@echo off
rem Start the read-only baby-virus-scanner dashboard on http://127.0.0.1:8777 and open it.
rem Arguments are passed through, e.g.:  start-dashboard.cmd -Scan 20260101-120000 -Rebuild
where pwsh >nul 2>nul
if %errorlevel%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\tools\windows\start-dashboard.ps1" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\tools\windows\start-dashboard.ps1" %*
)
