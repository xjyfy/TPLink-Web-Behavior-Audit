@echo off
REM ============================================================
REM ????????? - One-click Install
REM Right-click: Run as Administrator
REM ============================================================
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please right-click and "Run as administrator"
    pause
    exit /b 1
)

echo === 0/6 Environment Check ===
set "PYEXE="
set "PYPATH="
REM Prefer a real installed Python from known paths (Store alias stub in WindowsApps is NOT a real Python)
for %%P in (
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python310\python.exe"
    "C:\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python313\python.exe"
) do (
    if not defined PYEXE if exist %%P set "PYEXE=%%~P"
)
REM Otherwise take `where python`, but reject the Store alias (it lives in WindowsApps and is not a real Python)
if not defined PYEXE (
    for /f "delims=" %%q in ('where python.exe 2^>nul') do if not defined PYPATH set "PYPATH=%%q"
)
if not defined PYEXE if defined PYPATH (
    echo %PYPATH% | findstr /I /C:"WindowsApps" >nul && set "PYPATH="
    if defined PYPATH set "PYEXE=%PYPATH%"
)
REM Still no usable Python: install via winget
if not defined PYEXE (
    echo [INFO] No usable Python found, installing via winget...
    where winget.exe >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] No Python and no winget. Install Python 3.10+ from python.org
        pause
        exit /b 1
    )
    winget install -e --id Python.Python.3.11 --scope user --silent --accept-package-agreements --accept-source-agreements
    set "PATH=%LocalAppData%\Programs\Python\Python311;%LocalAppData%\Programs\Python\Python311\Scripts;%PATH%"
    set "PYEXE=%LocalAppData%\Programs\Python\Python311\python.exe"
    if not exist "%PYEXE%" (
        echo [ERROR] winget installed Python, but python.exe not found at %PYEXE%
        pause
        exit /b 1
    )
)
echo [OK] Python: %PYEXE%
"%PYEXE%" --version
"%PYEXE%" -m pip --version >nul 2>&1
if errorlevel 1 ( "%PYEXE%" -m ensurepip --upgrade )

echo.
echo === 1/6 Install Dependencies ===
if exist "%~dp0packages\" (
    echo [OK] Installing from local packages...
    "%PYEXE%" -m pip install --no-index --find-links="%~dp0packages" flask psutil
    if errorlevel 1 (
        echo [WARN] Local packages incompatible with this Python, falling back to PyPI mirror...
        "%PYEXE%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    )
) else (
    echo [INFO] Installing from PyPI mirror...
    "%PYEXE%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
)
if errorlevel 1 ( echo [ERROR] pip install failed & pause & exit /b 1 )

echo.
echo === 2/6 Data Directory ===
if not exist "%~dp0data" mkdir "%~dp0data"
echo [OK] data/ ready

echo.
echo === 3/6 Firewall ===
netsh advfirewall firewall show rule name="SyslogAudit514" >nul 2>&1 || netsh advfirewall firewall add rule name="SyslogAudit514" dir=in action=allow protocol=UDP localport=514
netsh advfirewall firewall show rule name="SyslogAudit8080" >nul 2>&1 || netsh advfirewall firewall add rule name="SyslogAudit8080" dir=in action=allow protocol=TCP localport=8080
echo [OK] Firewall rules done

echo.
echo === 4/6 Port Check ===
netstat -ano | findstr ":514 " | findstr "LISTENING" >nul 2>&1 && echo [WARN] UDP 514 in use || echo [OK] UDP 514 free
netstat -ano | findstr ":8080 " | findstr "LISTENING" >nul 2>&1 && echo [WARN] TCP 8080 in use || echo [OK] TCP 8080 free

echo.
echo === 5/6 Register Auto-start ===
call "%~dp0install_service.bat" "%PYEXE%"

echo.
echo === 6/6 Verify ===
timeout /t 3 /nobreak >nul
powershell -NoProfile -Command "try { $r=(Invoke-WebRequest 'http://localhost:8080/login' -UseBasicParsing -TimeoutSec 5).StatusCode; if ($r -eq 200 -or $r -eq 302) { '[OK] Web service running' } else { '[WARN] Not responding' } } catch { '[WARN] Not responding' }"

echo.
echo ========================================
for /f "delims=" %%i in ('powershell -NoProfile -Command "$ip = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up'} | Select-Object -First 1).IPv4Address.IPAddress; if (-not $ip) { $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '169.254*'} | Select-Object -First 1).IPAddress }; $ip"') do set HOSTIP=%%i
echo   Web UI:  http://%HOSTIP%:8080/
echo   User:    admin   Pass: admin123
echo   Router syslog target: %HOSTIP% UDP 514
echo   IMPORTANT: Change password after login!
echo ========================================
pause
