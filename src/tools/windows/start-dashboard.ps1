<#
.SYNOPSIS  Start the read-only dashboard (127.0.0.1 only) and open it in the browser.
.EXAMPLE   .\tools\windows\start-dashboard.ps1                 # latest scan, http://127.0.0.1:8777
.EXAMPLE   .\tools\windows\start-dashboard.ps1 -Scan <scanId> -Rebuild
#>
[CmdletBinding()]
param([string]$Scan, [switch]$Rebuild, [switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))

# Python 3: $env:BVS_PYTHON, else the py launcher, else python.exe (never the Microsoft Store alias).
$py = @()
if ($env:BVS_PYTHON -and (Test-Path -LiteralPath $env:BVS_PYTHON)) { $py = @($env:BVS_PYTHON) }
elseif (Get-Command py.exe -ErrorAction SilentlyContinue) { $py = @('py.exe', '-3') }
else {
    $cmd = Get-Command python.exe -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1
    if ($cmd) { $py = @($cmd.Source) }
}
if (-not $py) { throw 'Python 3 not found. Install it or set $env:BVS_PYTHON to python.exe.' }
$exe = $py[0]
$pre = @($py | Select-Object -Skip 1) + @('-I', '-B')

$scanArgs = @()
if ($Scan) { $scanArgs = @('--scan', $Scan) }
$latest = Join-Path $root 'data\latest.txt'
if (-not $Scan -and -not (Test-Path -LiteralPath $latest)) {
    Write-Host 'No scan yet. Run a scan first:   pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 scan'
    Write-Host 'Or look at the demo dashboard:   pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 demo'
    exit 1
}
$scanId = if ($Scan) { Split-Path -Leaf $Scan } else { (Get-Content -LiteralPath $latest -Raw).Trim() }
$manifest = Join-Path $root "data\$scanId\js\manifest.js"
if ($Rebuild -or -not (Test-Path -LiteralPath $manifest)) {
    & $exe @pre (Join-Path $root 'src\core\build_datajs.py') @scanArgs
    if ($LASTEXITCODE -ne 0) { throw "build_datajs.py failed ($LASTEXITCODE)" }
}
$serveArgs = @((Join-Path $root 'src\server\serve.py')) + $scanArgs
if (-not $NoBrowser) { $serveArgs += '--open' }
& $exe @pre @serveArgs
