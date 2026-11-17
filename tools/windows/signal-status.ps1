#Requires -Version 7.2
<#
.SYNOPSIS
    Update a signal's status so the dashboard shows progress (docs/ui-contract-v3.md section 1).
.DESCRIPTION
    Writes data\signals\status\<id>.json = {id, state, message, updatedAt}. The message is cleaned
    (control characters removed, secrets masked, at most 500 characters). For delete-request
    signals the states "running" and "done" are reserved for execute-delete.ps1, so the dashboard
    can never show a deletion as done that did not run through the double confirmation.
.EXAMPLE
    pwsh -NoProfile -File tools\windows\signal-status.ps1 -Id 20260101-120000-rerun-module-a1b2c3 -State done -Message 'S07 re-ran: 2 findings'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][ValidateSet('queued', 'picked-up', 'awaiting-chat-confirmation', 'running', 'done', 'error', 'cancelled', 'expired')][string]$State,
    [string]$Message = '',
    [string]$StateRoot
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'BVS.Signals.psm1') -Force

$ctx = Get-BvsSignalContext -StateRoot $StateRoot
if (-not (Test-BvsSignalId $Id)) { Write-Error "Not a signal id: $Id"; exit 1 }
$sig = Read-BvsSignal -Ctx $ctx -Id $Id -From archive
if ($null -eq $sig) { $sig = Read-BvsSignal -Ctx $ctx -Id $Id -From inbox }
if ($null -eq $sig) { Write-Error "Signal not found: $Id"; exit 1 }
if ($sig.type -eq 'delete-request' -and $State -in 'running', 'done') {
    Write-Error "For delete requests only execute-delete.ps1 sets '$State' (after the user typed I confirm <CODE> in chat)."
    exit 1
}
Set-BvsSignalStatus -Ctx $ctx -Id $Id -State $State -Message $Message
"STATUS $Id $State"
