@echo off
REM Remove auto-start and stop service
cd /d "%~dp0"
schtasks /Delete /TN "SyslogAuditServer" /F >nul 2>&1
taskkill /F /IM pythonw.exe >nul 2>&1
echo [Done] Auto-start removed and service stopped.
pause
