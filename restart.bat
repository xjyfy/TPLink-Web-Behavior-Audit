@echo off
REM Restart the audit service (v2, watchdog)
cd /d "%~dp0"
set "PYW="
for %%P in (
    "%LocalAppData%\Programs\Python\Python311\pythonw.exe"
    "%LocalAppData%\Programs\Python\Python312\pythonw.exe"
    "%LocalAppData%\Programs\Python\Python313\pythonw.exe"
    "%LocalAppData%\Programs\Python\Python310\pythonw.exe"
    "C:\Python311\pythonw.exe"
    "C:\Python312\pythonw.exe"
    "C:\Python313\pythonw.exe"
) do (
    if not defined PYW if exist %%P set "PYW=%%~P"
)
if not defined PYW set "PYW=pythonw.exe"
echo [Stop] Stopping...
taskkill /F /IM pythonw.exe >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*app.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
timeout /t 2 /nobreak >nul
echo [Start] Starting...
start "" "%PYW%" "%~dp0watchdog.py"
echo [Done] Service restarted.
timeout /t 2 /nobreak >nul
