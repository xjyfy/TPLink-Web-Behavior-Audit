@echo off
REM Register service auto-start at boot (SYSTEM account, no login needed)
cd /d "%~dp0"

set "PYW="
if "%~1"=="" (
    where pythonw.exe >nul 2>&1 && for /f "delims=" %%i in ('where pythonw.exe') do if not defined PYW set "PYW=%%i"
) else (
    set "PYW=%~dp1pythonw.exe"
)
if not defined PYW (
    for %%P in (
        "%LocalAppData%\Programs\Python\Python311\pythonw.exe"
        "%LocalAppData%\Programs\Python\Python312\pythonw.exe"
        "%LocalAppData%\Programs\Python\Python313\pythonw.exe"
        "C:\Python311\pythonw.exe"
        "C:\Python312\pythonw.exe"
    ) do (
        if exist %%P set "PYW=%%~P"
    )
)
if not defined PYW (
    echo [ERROR] pythonw.exe not found. Run install.bat first.
    pause
    exit /b 1
)
echo [OK] pythonw: %PYW%

> "%~dp0_run_hidden.vbs" echo Set ws = CreateObject("Wscript.Shell")
>> "%~dp0_run_hidden.vbs" echo ws.CurrentDirectory = "%~dp0"
>> "%~dp0_run_hidden.vbs" echo ws.Run """%PYW%"" ""%~dp0watchdog.py""", 0, False

schtasks /Delete /TN "SyslogAuditServer" /F >nul 2>&1
schtasks /Create /TN "SyslogAuditServer" /TR "wscript.exe \"%~dp0_run_hidden.vbs\"" /SC ONSTART /RU SYSTEM /RL HIGHEST /F >nul
if errorlevel 1 ( echo [ERROR] schtasks failed & pause & exit /b 1 )
echo [OK] Auto-start registered (SYSTEM, boot-time)

start "" wscript.exe "%~dp0_run_hidden.vbs"
echo [OK] Service started
