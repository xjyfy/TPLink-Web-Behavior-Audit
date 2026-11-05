@echo off
REM Restart the syslog service via restart.ps1 (does not touch site-name-service)
cd /d "%~dp0"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart.ps1"
