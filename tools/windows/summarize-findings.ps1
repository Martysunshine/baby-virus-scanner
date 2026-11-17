#Requires -Version 7.2
<#
.SYNOPSIS  Compact console summary of module envelopes (counts, coverage, and findings at/above a severity).
.EXAMPLE   pwsh -File tools\windows\summarize-findings.ps1 -Modules S02,S04 -MinSeverity medium
#>
[CmdletBinding()]
param(
    [string[]]$Modules,
    [ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$MinSeverity = 'medium',
    [string]$Area = 'security',
    [int]$MaxPerModule = 25,
    [int]$EvidenceChars = 160
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scanDir = Join-Path $root ('data\' + (Get-Content -LiteralPath (Join-Path $root 'data\latest.txt') -Raw).Trim())
$rank = @{ critical = 4; high = 3; medium = 2; low = 1; info = 0 }
$files = Get-ChildItem -LiteralPath (Join-Path $scanDir $Area) -Filter '*.json' -File | Where-Object { $_.Name -notmatch '\.tmp-' }
if ($Modules) { $Modules = @($Modules -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }); $files = $files | Where-Object { $Modules -contains $_.BaseName } }   # pwsh -File passes "a,b" as one string
foreach ($f in ($files | Sort-Object Name)) {
    $e = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -Depth 64
    $fs = @($e.findings)
    $sev = ($fs | Group-Object severity | Sort-Object { - $rank[$_.Name] } | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
    $chk = (@($e.checks) | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
    "==== {0}  findings: {1}  | checks: {2}  | errors: {3}" -f $e.module, $sev, $chk, @($e.errors).Count
    $bad = @($e.checks | Where-Object { $_.status -in 'error', 'needs_admin', 'partial' }) | Select-Object -First 8
    foreach ($c in $bad) { "   [check {0}] {1}: {2}" -f $c.status, $c.id, ("$($c.reason)" -replace '\s+', ' ').Substring(0, [Math]::Min(120, "$($c.reason)".Length)) }
    $sel = $fs | Where-Object { $rank[$_.severity] -ge $rank[$MinSeverity] } | Sort-Object { - $rank[$_.severity] }, class | Select-Object -First $MaxPerModule
    foreach ($x in $sel) {
        $ev = if ($x.evidence) { ($x.evidence | Select-Object -First 1 | ConvertTo-Json -Compress -Depth 6) } else { '' }
        if ($ev.Length -gt $EvidenceChars) { $ev = $ev.Substring(0, $EvidenceChars) + '…' }
        "   {0} {1}/{2}/{3} {4}" -f $x.id, $x.severity.ToUpper(), $x.class, $x.confidence, $x.title
        if ($ev) { "        ev: $ev" }
    }
}
