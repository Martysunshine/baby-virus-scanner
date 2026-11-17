#Requires -Version 7.2
<#
.SYNOPSIS
    Dashboard signal watcher for the Claude session (docs/ui-contract-v3.md section 1).
.DESCRIPTION
    Run by Claude in the background. Writes data\session\heartbeat.json every 5 s (the dashboard
    shows "Claude connected" while it is fresh), and waits for the OLDEST file in
    data\signals\inbox. When one arrives it moves the file to data\signals\archive, writes status
    "picked-up", prints one masked line

        SIGNAL <id> <type> <short summary>

    plus a NEXT: hint, and EXITS 0. That exit is what wakes Claude. Claude handles the signal and
    starts the watcher again. Signals older than 60 minutes are archived as "expired" without
    waking Claude. After -TimeoutMinutes (default 600) it prints NO-SIGNAL and exits 0.

    It never acts on a signal itself: it only moves the file and reports it.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File tools\windows\watch-signals.ps1
#>
[CmdletBinding()]
param(
    [ValidateRange(0.01, 1440)][double]$TimeoutMinutes = 600,
    [string]$StateRoot,
    [ValidateRange(0.2, 10)][double]$PollSeconds = 1
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'BVS.Signals.psm1') -Force

$ctx = Get-BvsSignalContext -StateRoot $StateRoot
foreach ($d in $ctx.Inbox, $ctx.Archive, $ctx.Status) { [void][IO.Directory]::CreateDirectory($d) }
$startedAt = Get-BvsUtcStamp
$deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
$nextBeat = [datetime]::MinValue

function Write-Heartbeat {
    $beat = [ordered]@{ pid = $PID; startedAt = $startedAt; beatAt = (Get-BvsUtcStamp) }
    try { Write-BvsStateFile -Ctx $ctx -Path $ctx.Heartbeat -Text (ConvertTo-Json $beat -Compress) } catch { Write-Verbose "heartbeat failed: $($_.Exception.Message)" }
}

function Move-ToArchive([string]$From, [string]$Id) {
    $to = Join-Path $ctx.Archive "$Id.json"
    try { [IO.File]::Move($From, $to, $false); $true } catch { $false }   # false: another watcher took it (or a duplicate)
}

while ($true) {
    $now = [datetime]::UtcNow
    if ($now -ge $nextBeat) { Write-Heartbeat; $nextBeat = $now.AddSeconds(5) }

    $files = @([IO.Directory]::GetFiles($ctx.Inbox, '*.json') | Where-Object { Test-BvsSignalId ([IO.Path]::GetFileNameWithoutExtension($_)) } | Sort-Object)
    foreach ($file in $files) {
        $id = [IO.Path]::GetFileNameWithoutExtension($file)
        $sig = Read-BvsSignal -Ctx $ctx -Id $id -From inbox
        if ($null -eq $sig) {
            if (Move-ToArchive $file $id) { Set-BvsSignalStatus -Ctx $ctx -Id $id -State error -Message 'Invalid signal file: ignored.' }
            continue
        }
        if ((Get-BvsSignalAgeMinutes $sig) -gt 60) {
            if (Move-ToArchive $file $id) {
                Set-BvsSignalStatus -Ctx $ctx -Id $id -State expired -Message 'Nobody picked this up within 60 minutes. Send it again while Claude is listening.'
            }
            continue
        }
        if (-not (Move-ToArchive $file $id)) { continue }
        Set-BvsSignalStatus -Ctx $ctx -Id $id -State 'picked-up' -Message 'Claude picked this up.'
        Write-Heartbeat
        "SIGNAL $id $($sig.type) $(Get-BvsSignalSummary $sig)"
        if ($sig.type -eq 'delete-request') {
            "NEXT: pwsh -NoProfile -ExecutionPolicy Bypass -File tools\windows\validate-delete.ps1 -SignalId $id   (then post the table and wait for the user to type: I confirm <CODE>)"
        }
        else {
            "NEXT: handle it as in docs\playbooks\K-signals.md, report with tools\windows\signal-status.ps1 -Id $id -State <running|done|error> -Message '...', then restart this watcher"
        }
        exit 0
    }

    if ([datetime]::UtcNow -ge $deadline) { 'NO-SIGNAL'; exit 0 }
    Start-Sleep -Milliseconds ([int]($PollSeconds * 1000))
}
