# ReGet TLS Proxy

Makes HTTPS downloads work in **ReGet Deluxe 5.2 build 320** on Windows 11 x64.

---

## Why the DLL approach cannot work

The obvious plan is to rebuild `ReGetSSL.dll` against a modern TLS stack. It does not work,
and the reason is structural.

`ReGetDx.exe` loads the add-on dynamically — the path comes from
`HKCU\Software\ReGet Software\SSL\DllPath` — and resolves **36 `Rg*` symbols by name**.
That list includes:

    Rgssl2_enc   Rgssl2_mac   Rgssl3_dispatch_alert
    Rgssl3_setup_buffers      Rgssl_free_wbio_buffer
    Rgssl3_renegotiate_check  RgSSLerr   Rgclear_sys_error

Those are **OpenSSL 0.9.6 internal symbols**, declared in `ssl_locl.h`. They are not a public
API and no application ever calls them. Equally telling: there is **no `SSL_read` or
`SSL_write`** anywhere in the contract.

That combination has only one explanation — ReGet took OpenSSL 0.9.6, prefixed every symbol
with `Rg`, and compiled the **record-layer sources into `ReGetDx.exe` itself**. The DLL exists
only to satisfy the leftover externs.

So the TLS engine lives in the 4 MB EXE, not in the DLL:

* record layer is SSLv3 / TLS 1.0 — MAC-then-encrypt CBC only
* no AEAD, so **AES-GCM is impossible**; every modern TLS 1.2 suite is AEAD
* no extensions, so no SNI — most shared hosts will not even serve the right certificate
* TLS 1.3 is a different handshake and record format entirely

A replacement DLL would additionally have to reproduce OpenSSL 0.9.6 `SSL` / `SSL3_STATE` /
`BIO` struct layouts byte-for-byte, because the EXE walks those structs at hardcoded offsets.

**Conclusion:** no `ReGetSSL.dll` — however modern, however correct — can give ReGetDx
TLS 1.2 or 1.3. The ceiling is inside the executable.

(For reference: `ReGetSSL_Modern-v9` also cannot load at all. It is built x64 against a 32-bit
host process, and four of its exports leak as decorated C++ names such as
`?RgSSL_read@@YAHPEAURgSSL_st@@PEAXH@Z` because they are missing from the `.def`.)

---

## What this does instead

`ReGetDx.exe` contains the format string `GET %s HTTP/1.0` — the **absolute-URI proxy form**.
Pointed at an HTTP proxy, ReGetDx hands over the whole `https://...` URL as plaintext and lets
the proxy do the TLS. Its obsolete crypto is never invoked.

    ReGetDx  ──plain HTTP──▶  regettls.py  ──TLS 1.2/1.3──▶  origin server

No DLL, no compiler, no reverse engineering, and you get the current TLS stack including SNI,
modern ciphers and the Windows trust store.

---

## Running it

```
C:\tools\ReGet_Deluxe_5.2_Build_320\reborn2026\ReGetTLSProxy\start-proxy.cmd
```

Leave the window open while using ReGet. Options:

| Flag | Meaning |
|---|---|
| `--port 8888` | listen port (default 8888) |
| `--host 127.0.0.1` | bind address; localhost only by default |
| `--insecure` | skip upstream certificate verification (self-signed hosts only) |
| `--log-level DEBUG` | verbose logging |

## Configuring ReGet Deluxe

In ReGetDx: **Tools → Options → Proxy** (or the Proxy tab of the download properties dialog)

* HTTP proxy: `127.0.0.1`
* Port: `8888`
* No proxy username/password
* Apply it to the HTTP protocol; leave FTP alone unless you want it proxied too

Then add an `https://` download as normal.

---

## Verified behaviour

| Test | Result |
|---|---|
| `GET https://www.example.com/` | 200, TLS 1.3 / `TLS_AES_256_GCM_SHA384` |
| `GET https://www.google.com/robots.txt` | 200, 7312 bytes |
| Single `Range: bytes=100-199` | **206 Partial Content**, exactly 100 bytes |
| 4 concurrent range segments | all four **206**, 50 bytes each |

Range and If-Range pass through untouched, so **resume and multi-segment downloading both
work** — which is the entire point of using ReGet.

---
## Load the extensions

**Chrome** — `chrome://extensions` → enable *Developer mode* → *Load unpacked* → pick
`dist\chrome`. (Chrome blocks `.crx` files from outside the Web Store, so unpacked is the
practical route.)

## Two failure modes worth knowing

**Only ever run one instance.** Earlier builds set `SO_REUSEADDR`, which on Windows lets a
second process bind a port the first is already listening on — the two then split incoming
connections unpredictably, so a "restarted" proxy can silently keep serving from the stale
copy. The socket now uses `SO_EXCLUSIVEADDRUSE`, so a duplicate bind fails loudly:

```
ERROR  cannot bind 127.0.0.1:8888 - [WinError 10048] Only one usage of each socket
       address (protocol/network address/port) is normally permitted.
```

That message means the proxy is *already running* — usually you can just use it. To restart
cleanly, run **`stop-proxy.cmd`** first, then `start-proxy.cmd`.

**`526 Invalid SSL Certificate` on a site that works everywhere else.** Windows fetches
missing intermediate CAs on demand and caches them; a context built before that fetch keeps
a stale CA set for the life of the process. The proxy now rebuilds its CA store and retries
once before reporting a bad certificate, which clears this automatically. If a host genuinely
serves a broken chain, run with `--insecure`.

## If it does not work

Watch the proxy console while ReGetDx runs.

* **You see `GET https://...`** — working as designed.
* **You see a `CONNECT host:443` warning** — ReGetDx decided to run its own TLS stack through
  the tunnel. That path cannot succeed (see above). The proxy tunnels it anyway so the failure
  is visible rather than silent. Report the log line and the approach needs adjusting.
* **You see nothing at all** — the proxy settings did not take effect, or ReGetDx refused the
  `https://` URL before reaching the network. ReGetDx gates HTTPS on the add-on being present;
  keep a valid **32-bit** `ReGetSSL.dll` at the registry `DllPath` so that check passes, even
  though its crypto is never used on the proxy path.

## Registry note

`HKCU\...\SSL\DllPath` correctly points at the original 32-bit DLL:

    C:\Program Files (x86)\Common Files\ReGet Shared\ReGetSSL.dll

`HKLM\...\SSL\DllPath` points at the x64 `ReGetSSL_Modern-v9\bin\Debug64\ReGetSSL.dll`, which
can never load into a 32-bit process. If ReGetDx ever falls back to the HKLM value it will
fail. Aligning HKLM with the HKCU path is the safe fix.
