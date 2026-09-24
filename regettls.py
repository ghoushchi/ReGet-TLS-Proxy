"""
ReGet TLS Proxy
===============

ReGet Deluxe 5.2 has an OpenSSL 0.9.6-era TLS record layer compiled into
ReGetDx.exe, so it cannot negotiate TLS 1.2/1.3 no matter what ReGetSSL.dll
provides. This proxy sidesteps that entirely:

    ReGetDx  --plain HTTP-->  this proxy  --modern TLS-->  origin server

ReGetDx sends "GET https://host/path HTTP/1.0" (absolute-URI proxy form).
We terminate that request, fetch upstream over TLS 1.2/1.3, and stream the
response back in the clear.

Range/If-Range headers pass through untouched, so ReGet's resume still works.

Usage:  python regettls.py [--port 8888] [--host 127.0.0.1] [--log-level INFO]
"""

import argparse
import logging
import selectors
import socket
import ssl
import sys
import threading
from urllib.parse import urlsplit

LOG = logging.getLogger("regettls")

# Headers that are hop-by-hop or proxy-specific: never forwarded upstream.
HOP_BY_HOP = {
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

CRLF = b"\r\n"
MAX_HEADER_BYTES = 64 * 1024
IO_CHUNK = 64 * 1024
CONNECT_TIMEOUT = 30
IO_TIMEOUT = 300


def _tls_context() -> ssl.SSLContext:
    """A modern client context: TLS 1.2+, system trust store, SNI on."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


TLS_CTX = _tls_context()
TLS_CTX_LOCK = threading.Lock()

TLS_CTX_INSECURE = ssl.create_default_context()
TLS_CTX_INSECURE.check_hostname = False
TLS_CTX_INSECURE.verify_mode = ssl.CERT_NONE


def refresh_tls_context() -> ssl.SSLContext:
    """
    Rebuild the verifying context so it re-reads the Windows certificate store.

    Windows fetches missing intermediate CAs on demand (via the AIA extension)
    and caches them. A context built before that fetch holds a stale CA set for
    the life of the process, which shows up as "unable to get local issuer
    certificate" on a site every other client can verify. Rebuilding picks up
    anything cached since startup.
    """
    global TLS_CTX
    with TLS_CTX_LOCK:
        TLS_CTX = _tls_context()
        return TLS_CTX


class RequestError(Exception):
    """Raised with an HTTP status we should report back to ReGetDx."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def recv_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read until the end of the header block. Returns (header_bytes, leftover_body)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER_BYTES:
            raise RequestError("431 Request Header Fields Too Large", "header block too large")
        chunk = sock.recv(IO_CHUNK)
        if not chunk:
            if not buf:
                raise RequestError("400 Bad Request", "client closed before sending a request")
            raise RequestError("400 Bad Request", "truncated header block")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def parse_request(head: bytes) -> tuple[str, str, str, list[tuple[str, str]]]:
    """Parse the request line + headers. Returns (method, target, version, headers)."""
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise RequestError("400 Bad Request", f"undecodable request: {exc}") from exc

    lines = text.split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise RequestError("400 Bad Request", f"malformed request line: {lines[0]!r}")
    method = parts[0].upper()
    target = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.0"

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and headers:  # obs-fold continuation
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip())
            continue
        name, sep, value = line.partition(":")
        if not sep:
            LOG.debug("skipping malformed header line: %r", line)
            continue
        headers.append((name.strip(), value.strip()))
    return method, target, version, headers


def build_upstream_request(
    method: str, path: str, headers: list[tuple[str, str]], host_header: str
) -> bytes:
    """Rebuild the request in origin form for the upstream server."""
    out = [f"{method} {path} HTTP/1.1"]
    seen_host = False
    for name, value in headers:
        lname = name.lower()
        if lname in HOP_BY_HOP:
            continue
        if lname == "host":
            seen_host = True
            out.append(f"Host: {host_header}")
            continue
        out.append(f"{name}: {value}")
    if not seen_host:
        out.insert(1, f"Host: {host_header}")
    # We stream the body back and close; no upstream keep-alive to manage.
    out.append("Connection: close")
    return ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1")


def connect_upstream(scheme: str, host: str, port: int, insecure: bool) -> socket.socket:
    try:
        raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        raise RequestError("502 Bad Gateway", f"cannot connect to {host}:{port} - {exc}") from exc

    raw.settimeout(IO_TIMEOUT)
    if scheme != "https":
        return raw

    ctx = TLS_CTX_INSECURE if insecure else TLS_CTX
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        raw.close()
        if insecure:
            raise RequestError(
                "526 Invalid SSL Certificate",
                f"certificate verification failed for {host} - {exc.verify_message or exc}",
            ) from exc

        # Most likely a stale CA set (see refresh_tls_context). Rebuild and retry
        # once before declaring the certificate bad.
        LOG.info("verify failed for %s; refreshing CA store and retrying once", host)
        retry_ctx = refresh_tls_context()
        try:
            raw = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            raw.settimeout(IO_TIMEOUT)
            tls = retry_ctx.wrap_socket(raw, server_hostname=host)
        except ssl.SSLCertVerificationError as exc2:
            try:
                raw.close()
            except OSError:
                pass
            raise RequestError(
                "526 Invalid SSL Certificate",
                f"certificate verification failed for {host} - {exc2.verify_message or exc2}. "
                f"If this host really does serve an incomplete chain, restart the proxy "
                f"with --insecure to bypass verification.",
            ) from exc2
        except (ssl.SSLError, OSError) as exc2:
            raise RequestError(
                "502 Bad Gateway", f"TLS handshake with {host} failed - {exc2}"
            ) from exc2
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        raise RequestError("502 Bad Gateway", f"TLS handshake with {host} failed - {exc}") from exc

    LOG.info("upstream %s:%d negotiated %s / %s", host, port, tls.version(), tls.cipher()[0])
    return tls


def send_error(sock: socket.socket, status: str, detail: str) -> None:
    body = (
        f"ReGet TLS Proxy could not complete the request.\r\n\r\n{detail}\r\n"
    ).encode("utf-8")
    resp = (
        f"HTTP/1.0 {status}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("iso-8859-1") + body
    try:
        sock.sendall(resp)
    except OSError:
        pass


def pump(src: socket.socket, dst: socket.socket) -> int:
    """Copy src -> dst until EOF. Returns bytes moved."""
    total = 0
    while True:
        try:
            chunk = src.recv(IO_CHUNK)
        except (socket.timeout, TimeoutError):
            LOG.warning("upstream read timed out after %d bytes", total)
            break
        except OSError as exc:
            LOG.debug("upstream read ended: %s", exc)
            break
        if not chunk:
            break
        try:
            dst.sendall(chunk)
        except OSError as exc:
            LOG.debug("client write ended: %s", exc)
            break
        total += len(chunk)
    return total


def tunnel(client: socket.socket, upstream: socket.socket) -> None:
    """Bidirectional relay for CONNECT."""
    sel = selectors.DefaultSelector()
    client.setblocking(False)
    upstream.setblocking(False)
    sel.register(client, selectors.EVENT_READ, upstream)
    sel.register(upstream, selectors.EVENT_READ, client)
    open_ends = 2
    try:
        while open_ends:
            for key, _ in sel.select(timeout=IO_TIMEOUT):
                src: socket.socket = key.fileobj  # type: ignore[assignment]
                dst: socket.socket = key.data
                try:
                    chunk = src.recv(IO_CHUNK)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(src)
                    open_ends -= 1
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(chunk)
                except OSError:
                    return
            else:
                if not sel.get_map():
                    break
    finally:
        sel.close()


def handle_connect(client: socket.socket, target: str, insecure: bool) -> None:
    """
    ReGetDx only issues CONNECT when it intends to run its own TLS stack, which
    is exactly the thing that is too old to work. We tunnel anyway so the failure
    is the client's and visible, rather than silently ours.
    """
    host, _, port_s = target.rpartition(":")
    if not host:
        raise RequestError("400 Bad Request", f"malformed CONNECT target {target!r}")
    try:
        port = int(port_s)
    except ValueError as exc:
        raise RequestError("400 Bad Request", f"bad CONNECT port in {target!r}") from exc

    LOG.warning(
        "CONNECT %s:%d - ReGetDx is trying to run its own (obsolete) TLS stack. "
        "Tunneling raw; this will likely fail at the handshake.",
        host,
        port,
    )
    upstream = connect_upstream("http", host, port, insecure)  # raw TCP, no TLS on our side
    try:
        client.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
        tunnel(client, upstream)
    finally:
        upstream.close()


def handle_absolute(
    client: socket.socket,
    method: str,
    target: str,
    headers: list[tuple[str, str]],
    leftover: bytes,
    insecure: bool,
) -> None:
    parts = urlsplit(target)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise RequestError("400 Bad Request", f"unsupported scheme {scheme!r} in {target!r}")
    if not parts.hostname:
        raise RequestError("400 Bad Request", f"no host in {target!r}")

    host = parts.hostname
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = host if parts.port in (None, 443 if scheme == "https" else 80) else f"{host}:{port}"

    rng = next((v for n, v in headers if n.lower() == "range"), None)
    LOG.info("%s %s://%s:%d%s%s", method, scheme, host, port, path, f"  Range: {rng}" if rng else "")

    upstream = connect_upstream(scheme, host, port, insecure)
    try:
        upstream.sendall(build_upstream_request(method, path, headers, host_header))
        if leftover:
            upstream.sendall(leftover)
        moved = pump(upstream, client)
        LOG.info("%s://%s%s - relayed %s bytes", scheme, host, path, f"{moved:,}")
    finally:
        upstream.close()


def handle_client(client: socket.socket, addr, insecure: bool) -> None:
    try:
        client.settimeout(IO_TIMEOUT)
        try:
            head, leftover = recv_headers(client)
            method, target, _version, headers = parse_request(head)
        except RequestError as exc:
            LOG.warning("%s:%d - %s", addr[0], addr[1], exc.detail)
            send_error(client, exc.status, exc.detail)
            return

        try:
            if method == "CONNECT":
                handle_connect(client, target, insecure)
            elif "://" in target:
                handle_absolute(client, method, target, headers, leftover, insecure)
            else:
                raise RequestError(
                    "400 Bad Request",
                    f"origin-form request {target!r} received. Configure ReGetDx to use this "
                    "as an HTTP proxy so it sends absolute URLs.",
                )
        except RequestError as exc:
            LOG.warning("%s - %s", exc.status, exc.detail)
            send_error(client, exc.status, exc.detail)
    except Exception:  # noqa: BLE001 - a dead connection must not kill the proxy
        LOG.exception("unhandled error serving %s:%d", addr[0], addr[1])
    finally:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client.close()


def serve(host: str, port: int, insecure: bool) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Deliberately NOT SO_REUSEADDR. On Windows that flag lets a second process
    # bind a port another process is already listening on; the two then split
    # incoming connections unpredictably, so a "restarted" proxy can silently
    # keep serving from the stale instance. SO_EXCLUSIVEADDRUSE makes a duplicate
    # bind fail loudly instead.
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)

    try:
        srv.bind((host, port))
    except OSError as exc:
        srv.close()
        LOG.error(
            "cannot bind %s:%d - %s. Another proxy instance is probably already "
            "running; stop it first.", host, port, exc,
        )
        raise SystemExit(1) from exc

    srv.listen(64)

    LOG.info("ReGet TLS Proxy listening on %s:%d", host, port)
    LOG.info("Point ReGetDx at this address as its HTTP proxy.")
    if insecure:
        LOG.warning("--insecure is set: upstream certificates are NOT verified.")

    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(
                target=handle_client, args=(client, addr, insecure), daemon=True
            ).start()
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        srv.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="TLS-terminating proxy for ReGet Deluxe 5.2")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8888, help="bind port (default: 8888)")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify upstream certificates (use only for self-signed hosts)",
    )
    ap.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING (default: INFO)")
    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    serve(args.host, args.port, args.insecure)
    return 0


if __name__ == "__main__":
    sys.exit(main())
