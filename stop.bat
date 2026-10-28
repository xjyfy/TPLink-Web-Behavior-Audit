@echo off
REM Stop the audit service (watchdog + app)
cd /d "%~dp0"
taskkill /F /IM pythonw.exe >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*app.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
echo [Done] Service stopped.
pause
