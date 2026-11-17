#Requires -Version 7.2
<#
.SYNOPSIS
    Elevated launcher: verifies file hashes, runs admin-checks.ps1, then Microsoft Safety Scanner in
    REPORT-ONLY mode (/N). Started with ONE UAC prompt.
.DESCRIPTION
    Safety guarantees:
      * Refuses to run anything whose SHA-256 differs from the value given on the command line
        (protects against a file being swapped between review and the UAC click).
      * msert is ALWAYS run with /N (detect-only). It never removes or quarantines anything.
        Never /F:Y. Logs go to C:\Windows\debug\msert.log and are copied into data\<scan>\admin\.
      * Writes only to data\<scan>\admin\ (plus msert's own log/temp files).
    Progress: data\<scan>\admin\elevated-status.json
.EXAMPLE
    Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',
        '<root>\admin\windows\launch-elevated.ps1','-AdminScriptSha256','<sha>','-MsertSha256','<sha>'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AdminScriptSha256,
    [Parameter(Mandatory)][string]$MsertSha256,
    [switch]$SkipAdminChecks,
    [switch]$SkipQuickScan,
    [switch]$SkipFullScan
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scanId = (Get-Content -LiteralPath (Join-Path $root 'data\latest.txt') -Raw).Trim()
$outDir = Join-Path $root "data\$scanId\admin"
[void][IO.Directory]::CreateDirectory($outDir)
$adminScript = Join-Path $root 'admin\windows\admin-checks.ps1'
$msert = Join-Path $root 'intel\msert\msert.exe'
$msertLog = Join-Path $env:SystemRoot 'debug\msert.log'
$utf8 = [Text.UTF8Encoding]::new($false)
$history = [System.Collections.Generic.List[object]]::new()

function Set-Stage([string]$Stage, [string]$Detail = '') {
    $history.Add([ordered]@{ stage = $Stage; detail = $Detail; at = [datetime]::UtcNow.ToString('o') })
    [IO.File]::WriteAllText((Join-Path $outDir 'elevated-status.json'), (@{ scanId = $scanId; current = $Stage; history = $history } | ConvertTo-Json -Depth 5), $utf8)
    Write-Host ("[{0:HH:mm:ss}] {1} {2}" -f (Get-Date), $Stage, $Detail)
}

function Copy-MsertLog([string]$Name, [long]$StartOffset) {
    if (-not (Test-Path -LiteralPath $msertLog)) { return 'msert.log not found' }
    $bytes = [IO.File]::ReadAllBytes($msertLog)
    $slice = if ($StartOffset -gt 0 -and $StartOffset -lt $bytes.Length) { $bytes[$StartOffset..($bytes.Length - 1)] } else { $bytes }
    [IO.File]::WriteAllBytes((Join-Path $outDir $Name), [byte[]]$slice)
    "copied $($slice.Length) bytes"
}

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Set-Stage 'aborted' 'not elevated'; exit 2 }
    Set-Stage 'verifying' 'checking SHA-256 of admin-checks.ps1 and msert.exe'

    $aHash = (Get-FileHash -LiteralPath $adminScript -Algorithm SHA256).Hash
    if ($aHash -ne $AdminScriptSha256.ToUpperInvariant()) { Set-Stage 'aborted' "admin-checks.ps1 hash mismatch ($aHash)"; exit 3 }
    $mHash = (Get-FileHash -LiteralPath $msert -Algorithm SHA256).Hash
    if ($mHash -ne $MsertSha256.ToUpperInvariant()) { Set-Stage 'aborted' "msert.exe hash mismatch ($mHash)"; exit 3 }
    $sig = Get-AuthenticodeSignature -LiteralPath $msert
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { Set-Stage 'aborted' "msert signature not valid Microsoft ($($sig.Status))"; exit 4 }
    Set-Stage 'verified' 'hashes and Microsoft signature OK'

    if (-not $SkipAdminChecks) {
        Set-Stage 'admin-checks' 'running read-only admin checks (5-25 min)'
        & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -ExecutionPolicy Bypass -File $adminScript
        Set-Stage 'admin-checks-done' "exit code $LASTEXITCODE"
    }

    if (-not $SkipQuickScan) {
        $offset = if (Test-Path -LiteralPath $msertLog) { (Get-Item -LiteralPath $msertLog).Length } else { 0 }
        Set-Stage 'msert-quick' 'Microsoft Safety Scanner quick scan, detect-only (/Q /N)'
        $p = Start-Process -FilePath $msert -ArgumentList '/Q', '/N' -Wait -PassThru
        Set-Stage 'msert-quick-done' ("exit code {0}; {1}" -f $p.ExitCode, (Copy-MsertLog 'msert-quick.log' $offset))
    }

    if (-not $SkipFullScan) {
        $offset = if (Test-Path -LiteralPath $msertLog) { (Get-Item -LiteralPath $msertLog).Length } else { 0 }
        Set-Stage 'msert-full' 'Microsoft Safety Scanner FULL scan, detect-only (/Q /N /F) - can take hours'
        $p = Start-Process -FilePath $msert -ArgumentList '/Q', '/N', '/F' -Wait -PassThru
        Set-Stage 'msert-full-done' ("exit code {0}; {1}" -f $p.ExitCode, (Copy-MsertLog 'msert-full.log' $offset))
    }
    Set-Stage 'finished' 'all elevated steps done - you can close this window'
}
catch {
    Set-Stage 'error' $_.Exception.Message
    exit 1
}
