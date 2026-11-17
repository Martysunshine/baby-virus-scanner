# Fixture for src\tools\windows\check-collector.ps1 - must pass (exit 0). Read-only patterns only.
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
$iocs = @('rundll32.exe', 'mshta http', 'reg add', 'certutil -urlcache')   # strings are data, not commands
$run = Initialize-BvsRun -Module TEST -Area verify
Invoke-BvsCheck -Run $run -Id 'demo.reg' -Script { Get-BvsRegValues 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' }
git --no-optional-locks -C $env:USERPROFILE status --porcelain 2>$null
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[IO.File]::WriteAllText((Join-Path $run.OutDir 'x.txt'), 'ok')
Get-ChildItem $env:TEMP | Out-Null
