# Restart the syslog service only. Does NOT touch site-name-service (-m app.main) on the same machine.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$py  = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'
$pyw = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\pythonw.exe'
if (-not (Test-Path -LiteralPath $py)) {
    $py  = Join-Path $dir 'python.exe'
    $pyw = Join-Path $dir 'pythonw.exe'
}
Write-Output '[Stop] Stopping syslog...'
& $py (Join-Path $dir 'stop_syslog.py')
Start-Sleep -Seconds 2
Write-Output '[Start] Starting watchdog...'
Start-Process -FilePath $pyw -ArgumentList (Join-Path $dir 'watchdog.py') -WindowStyle Hidden
Write-Output '[Done] syslog restarted.'
