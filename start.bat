@echo off
title eNSP Topology Console
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
echo Starting eNSP console at http://127.0.0.1:8765
echo Keep this window open while using the console.
echo Browser will open automatically in a few seconds.
echo.
start "" powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://127.0.0.1:8765'"
"C:\Users\agnay\.venvs\ensp-mcp\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port 8765
echo.
echo Server stopped.
pause
