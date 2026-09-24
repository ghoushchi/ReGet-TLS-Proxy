@echo off
REM Stops any running ReGet TLS Proxy instance, freeing port 8888.
REM Use this when start-proxy.cmd reports WinError 10048 (address already in use).
title Stop ReGet TLS Proxy

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p = Get-CimInstance Win32_Process -Filter \"Name like '%%python%%'\" | Where-Object { $_.CommandLine -like '*regettls.py*' };" ^
  "if (-not $p) { Write-Host 'No proxy instance is running.' -ForegroundColor Yellow }" ^
  "else { $p | ForEach-Object { Write-Host \"stopping PID $($_.ProcessId)\"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } };" ^
  "Start-Sleep -Seconds 1;" ^
  "$n = (Get-NetTCPConnection -LocalPort 8888 -State Listen -ErrorAction SilentlyContinue | Measure-Object).Count;" ^
  "if ($n -eq 0) { Write-Host 'Port 8888 is free.' -ForegroundColor Green } else { Write-Host \"Something is still listening on 8888.\" -ForegroundColor Red }"

echo.
pause
