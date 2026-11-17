#Requires -Version 7.2
<#
.SYNOPSIS
    Step 4 of the double-confirmation deletion (docs/ui-contract-v3.md section 1). READ-ONLY.
.DESCRIPTION
    Loads a delete-request signal from data\signals\archive and re-checks every item LIVE:
    exists, size (folders summed), not a junction/symlink, not a cloud-only placeholder, not a
    running program or a folder holding one, no git work at risk (uncommitted/untracked files,
    unpushed commits, stashes), and the hard-refusal list (Windows, Program Files,
    ProgramData\Microsoft, WindowsApps, .ssh, credential files, profile and personal-folder roots,
    the scanner's data folder, anything outside %USERPROFILE%). Programs are matched to their
    registered uninstaller. Recycle Bin room is read per drive; what does not fit goes to
    holding\<id>\<n>\ on the same drive.

    Writes data\signals\tables\<id>.json ({tableHash, table}) where tableHash = sha256 of the
    canonical table JSON, valid for -TtlMinutes (default 60), prints a compact markdown table for
    Claude to post in chat, and sets the status to awaiting-chat-confirmation.
    It never deletes, moves or changes anything.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\validate-delete.ps1 -SignalId 20260101-120000-delete-request-a1b2c3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SignalId,
    [string]$StateRoot,
    [ValidateRange(0, 60)][int]$TtlMinutes = 60
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'BVS.Signals.psm1') -Force

function Stop-Refused([string]$Why, [string]$State) {
    "REFUSED $SignalId $Why"
    if ($State -and (Test-BvsSignalId $SignalId)) { try { Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State $State -Message "Validation refused: $Why" } catch { Write-Verbose $_ } }
    exit 1
}

$ctx = Get-BvsSignalContext -StateRoot $StateRoot
if (-not (Test-BvsSignalId $SignalId) -or $SignalId -notmatch '-delete-request-') { Stop-Refused 'not a delete-request signal id' }
$sig = Read-BvsSignal -Ctx $ctx -Id $SignalId -From archive
if ($null -eq $sig) {
    if (Read-BvsSignal -Ctx $ctx -Id $SignalId -From inbox) { Stop-Refused 'the signal is still in the inbox: run watch-signals.ps1 first so it is picked up' }
    Stop-Refused 'signal not found in data\signals\archive'
}
if ($sig.type -ne 'delete-request') { Stop-Refused 'not a delete-request signal' }
if ($sig.local.typedConfirmation -isnot [bool] -or -not $sig.local.typedConfirmation) { Stop-Refused 'the user did not type "I confirm" in the dashboard' 'error' }
if ($sig.codeSalt -notmatch '^[0-9a-f]{32}$' -or $sig.codeHash -notmatch '^[0-9a-f]{64}$') { Stop-Refused 'the signal has no valid confirmation code hash' 'error' }
$status = Get-BvsSignalStatus -Ctx $ctx -Id $SignalId
if ($status -and $status.state -in 'expired', 'cancelled', 'done', 'running') { Stop-Refused "the request is already $($status.state)" }
$guard = Get-BvsGuard -Ctx $ctx -Id $SignalId
if ($guard.executedAt) { Stop-Refused 'this request was already executed' }
if ($guard.failedAttempts -ge 5) { Stop-Refused 'locked after 5 wrong codes: ask the user to send a new request' }
if ((Get-BvsSignalAgeMinutes $sig) -gt 60) { Stop-Refused 'the request is older than 60 minutes: ask the user to send it again' 'expired' }

$items = @($sig.payload.items)
if ($items.Count -lt 1 -or $items.Count -gt 200) { Stop-Refused 'the request must have 1 to 200 items' 'error' }

$protected = Get-BvsProtectedSet -Ctx $ctx
$images = Get-BvsRunningImages
$git = Get-BvsGitExe
$results = [Collections.Generic.List[object]]::new()
$n = 0
foreach ($it in $items) {
    $n++
    $r = Test-BvsDeleteItem -Ctx $ctx -Item $it -Images $images -Protected $protected -Git $git
    $r.Insert(0, 'n', $n)
    $r.Remove('sizeChanged')
    $results.Add($r)
}
# an item inside another item of the same request would be removed twice: keep the outer one only
foreach ($inner in $results) {
    if ($inner.verdict -eq 'refused' -or $inner.kind -notin 'file', 'dir') { continue }
    $outer = $results | Where-Object { -not [object]::ReferenceEquals($_, $inner) -and $_.verdict -ne 'refused' -and $_.kind -eq 'dir' -and (Test-BvsUnder $inner.path $_.path -Strict) } | Select-Object -First 1
    if ($outer) { $inner.verdict = 'refused'; $inner.method = 'refused'; $inner.reasons = @("already included in item #$($outer.n)") + @($inner.reasons) }
}
$recycle = Set-BvsDeleteMethods -Ctx $ctx -Results $results

$now = [datetime]::UtcNow
$todo = @($results | Where-Object { $_.verdict -ne 'refused' })
$bytes = [long]0
foreach ($t in $todo) { if ($null -ne $t.bytes) { $bytes += [long]$t.bytes } }
$table = [ordered]@{
    schema      = 'bvs.deltable/1'
    signalId    = $SignalId
    scanId      = $sig.scanId
    createdAt   = Get-BvsUtcStamp $now
    expiresAt   = Get-BvsUtcStamp $now.AddMinutes($TtlMinutes)
    holdingRoot = $ctx.HoldingRoot
    sandbox     = [bool]$ctx.Sandbox
    recycleBin  = @($recycle)
    totals      = [ordered]@{
        items = $results.Count; ok = @($results | Where-Object { $_.verdict -eq 'ok' }).Count
        warn = @($results | Where-Object { $_.verdict -eq 'warn' }).Count
        refused = @($results | Where-Object { $_.verdict -eq 'refused' }).Count; bytes = $bytes
    }
    items       = @($results)
}
$hash = Write-BvsDeleteTable -Ctx $ctx -Id $SignalId -Table $table
$ref = $hash.Substring(0, 8)

$methodText = @{ recycle = 'Recycle Bin'; holding = 'holding folder'; uninstall = 'uninstaller'; refused = '-' }
"TABLE $SignalId to-remove=$($todo.Count) ($(Format-BvsBytes $bytes)) refused=$($table.totals.refused) ref=$ref expires=$($now.AddMinutes($TtlMinutes).ToLocalTime().ToString('HH:mm'))"
''
'| # | Item | Size | Method | Verdict | Notes |'
'|---|---|---|---|---|---|'
foreach ($r in $results) {
    $name = if ($r.kind -eq 'program') { ConvertTo-BvsCleanText $r.label 80 } else { Format-BvsShortPath $r.path }
    $notes = (@($r.reasons) | ForEach-Object { ConvertTo-BvsCleanText $_ 140 }) -join '; '
    "| $($r.n) | $($name.Replace('|', '\|')) | $(Format-BvsBytes $r.bytes) | $($methodText[$r.method]) | $($r.verdict) | $($notes.Replace('|', '\|')) |"
}
''
if ($todo.Count -eq 0) {
    Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State error -Message "Nothing can be removed: all $($results.Count) item(s) were refused. See the Claude chat for the reasons."
    'Nothing can be removed: every item was refused. Nothing will be deleted.'
    exit 2
}
$msg = "Final table is in the Claude chat (ref $ref): $($todo.Count) item(s), $(Format-BvsBytes $bytes)" +
$(if ($table.totals.refused) { ", $($table.totals.refused) refused" } else { '' }) +
". To go ahead, type I confirm <your code> in the Claude chat within $TtlMinutes minutes."
Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State 'awaiting-chat-confirmation' -Message $msg
"Table ref $ref (also shown in the dashboard). Nothing has been deleted."
'Ask the user to check this table and, to go ahead, type in this chat:  I confirm <CODE shown in the dashboard>'
"Only after they type it: pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\execute-delete.ps1 -SignalId $SignalId -Code <CODE exactly as the user typed it>"
'Never type, guess or reuse a code yourself.'
exit 0
