@echo off
REM ============================================================
REM Uninstall + wipe database: stop service, remove auto-start, delete DB
REM Right-click: Run as Administrator
REM ============================================================
cd /d "%~dp0"

echo === 1/4 Stop service ===
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*app.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
timeout /t 1 /nobreak >nul

echo.
echo === 2/4 Remove auto-start ===
schtasks /Delete /TN "SyslogAuditServer" /F >nul 2>&1
echo   Done.

echo.
echo === 3/4 Delete database ===
set "DBDIR=%~dp0data"
if exist "%DBDIR%\syslog.db" del /f /q "%DBDIR%\syslog.db"
if exist "%DBDIR%\syslog.db-wal" del /f /q "%DBDIR%\syslog.db-wal"
if exist "%DBDIR%\syslog.db-shm" del /f /q "%DBDIR%\syslog.db-shm"
echo   Database cleared.

echo.
echo === 4/4 Done ===
echo   Service stopped, auto-start removed, database wiped.
echo.
pause
