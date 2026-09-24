@echo off
REM Starts the ReGet TLS Proxy on 127.0.0.1:8888.
REM Leave this window open while using ReGet Deluxe.
title ReGet TLS Proxy
set PY=C:\bin\dev\Python\Python312\python.exe
if not exist "%PY%" set PY=python
"%PY%" "%~dp0regettls.py" --port 8888 %*
echo.
echo Proxy stopped. Press any key to close.
pause >nul
