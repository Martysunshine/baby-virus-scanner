#Requires -Version 7.2
<#
.SYNOPSIS
    Step 5 of the double-confirmation deletion (docs/ui-contract-v3.md section 1).
    THIS IS THE ONLY SCRIPT IN THE PROJECT THAT DELETES ANYTHING.
.DESCRIPTION
    Claude runs it ONLY after the user typed "I confirm <CODE>" in the Claude chat, passing the
    code exactly as the user typed it. Claude never knows the code: the dashboard showed it to
    the user once and only its salted hash is on disk.

    It refuses (exit 1, nothing deleted) unless ALL of these hold:
      1. the signal is a delete-request from the dashboard with local typedConfirmation = true,
         not executed before and not locked;
      2. PBKDF2-SHA256(code, codeSalt, 600k) equals codeHash (constant-time compare). A wrong code exits 2;
         5 wrong codes lock the request for good;
      3. the final table from validate-delete.ps1 exists, is unchanged (re-hash of its canonical
         JSON) and has not expired;
      4. every item still validates live (same checks, same kind, same size, same uninstaller,
         and the Recycle Bin still has room).
    Then, for each ok/warn item, in table order:
      recycle   -> Microsoft.VisualBasic FileSystem DeleteFile/DeleteDirectory, SendToRecycleBin, OnlyErrorDialogs
      holding   -> Move-Item to holding\<id>\<n>\ on the same drive
      uninstall -> starts the program's registered UninstallString (interactive; it may ask for admin rights)
    Every action is appended to logs\deletions.jsonl {time, signalId, n, id, path, bytes, method, result,...}.
    Status becomes done (exit 0) or error (exit 3 when an action failed).
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File tools\windows\execute-delete.ps1 -SignalId 20260101-120000-delete-request-a1b2c3 -Code K7Q2-M9XP
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SignalId,
    [Parameter(Mandatory)][string]$Code,
    [string]$StateRoot
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\lib\windows\BVS.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'BVS.Signals.psm1') -Force

$MaxWrongCodes = 5
$Alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
$Utf8 = [Text.UTF8Encoding]::new($false)

function Stop-Refused([string]$Why, [int]$ExitCode = 1) {
    "REFUSED $SignalId $Why"
    'Nothing was deleted.'
    exit $ExitCode
}

function Split-BvsCommand([string]$Cmd) {
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -lt 1) { throw 'the uninstall command has unbalanced quotes' }
        $exe = $c.Substring(1, $end - 1); $rest = $c.Substring($end + 1).Trim()
    }
    elseif ($c -match '^(?<exe>.+?\.exe)(?:\s+(?<rest>.*))?$') { $exe = $Matches.exe; $rest = [string]$Matches.rest }
    else { $sp = $c.IndexOf(' '); if ($sp -lt 0) { $exe = $c; $rest = '' } else { $exe = $c.Substring(0, $sp); $rest = $c.Substring($sp + 1).Trim() } }
    @{ Exe = [Environment]::ExpandEnvironmentVariables($exe); Args = $rest }
}

# --- 1. the request ------------------------------------------------------------------------
$ctx = Get-BvsSignalContext -StateRoot $StateRoot
if (-not (Test-BvsSignalId $SignalId) -or $SignalId -notmatch '-delete-request-') { Stop-Refused 'not a delete-request signal id' }
$guard = Get-BvsGuard -Ctx $ctx -Id $SignalId
if ($guard.executedAt) { Stop-Refused "this request was already executed at $($guard.executedAt); a new deletion needs a new request and code" }
if ($guard.failedAttempts -ge $MaxWrongCodes) { Stop-Refused 'locked after 5 wrong codes: the user must send a new request from the dashboard' }
$sig = Read-BvsSignal -Ctx $ctx -Id $SignalId -From archive
if ($null -eq $sig -or $sig.type -ne 'delete-request') { Stop-Refused 'delete-request signal not found in data\signals\archive' }
if ($sig.local.typedConfirmation -isnot [bool] -or -not $sig.local.typedConfirmation) { Stop-Refused 'the user did not type "I confirm" in the dashboard' }
if ($sig.codeSalt -notmatch '^[0-9a-f]{32}$' -or $sig.codeHash -notmatch '^[0-9a-f]{64}$') { Stop-Refused 'the signal has no valid code hash' }
$status = Get-BvsSignalStatus -Ctx $ctx -Id $SignalId
if ($status -and $status.state -in 'expired', 'cancelled', 'done', 'running') { Stop-Refused "the request is $($status.state)" }

# --- 2. the code the user typed in chat ------------------------------------------------------
$typed = $Code.Trim()
if ($typed.StartsWith('I confirm', [StringComparison]::OrdinalIgnoreCase)) { $typed = $typed.Substring(9) }
$norm = ($typed -replace '[\s-]', '').ToUpperInvariant()
$formatOk = $norm.Length -eq 8 -and -not ($norm.ToCharArray() | Where-Object { $Alphabet.IndexOf($_) -lt 0 })
$expected = [Text.Encoding]::ASCII.GetBytes([string]$sig.codeHash)
# PBKDF2-HMAC-SHA256, 600k iterations (same as core/signals.py hash_code): slow on purpose so the
# one-time code cannot be brute-forced from the stored hash.
$actual = [Text.Encoding]::ASCII.GetBytes((Get-BvsCodeHash -Salt ([string]$sig.codeSalt) -Code $norm))
$codeOk = [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($expected, $actual) -and $formatOk
if (-not $codeOk) {
    $guard.failedAttempts = [int]$guard.failedAttempts + 1
    $guard.lastAttemptAt = Get-BvsUtcStamp
    Set-BvsGuard -Ctx $ctx -Id $SignalId -Guard $guard
    $left = $MaxWrongCodes - $guard.failedAttempts
    if ($left -le 0) { Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State cancelled -Message 'Locked: 5 wrong codes were entered in the Claude chat. Nothing was deleted. Send a new request.' }
    else { Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State 'awaiting-chat-confirmation' -Message "A wrong code was entered in the Claude chat ($left tries left). Nothing was deleted." }
    Stop-Refused "the code does not match the one shown in the dashboard ($left tries left). Ask the user to type it again; never guess." 2
}

# --- 3. the final table ----------------------------------------------------------------------
$t = Read-BvsDeleteTable -Ctx $ctx -Id $SignalId
if (-not $t.Valid) { Stop-Refused $t.Error }
$table = $t.Table
if ($table.signalId -cne $SignalId -or $table.schema -cne 'bvs.deltable/1') { Stop-Refused 'the table does not belong to this request' }
if ([bool]$table.sandbox -ne [bool]$ctx.Sandbox) { Stop-Refused 'the table was made for a different state folder' }
if ([datetime]::UtcNow -ge (ConvertTo-BvsUtcDate $table.expiresAt)) { Stop-Refused 'the final table has expired: run validate-delete.ps1 again and show the user the new table' }

# --- 4. live re-check of every item ------------------------------------------------------------
$protected = Get-BvsProtectedSet -Ctx $ctx
$images = Get-BvsRunningImages
$git = Get-BvsGitExe
$mismatch = [Collections.Generic.List[string]]::new()
$todo = [Collections.Generic.List[object]]::new()
$holdDrive = [IO.Path]::GetPathRoot($ctx.HoldingRoot)
foreach ($row in @($table.items)) {
    if ($row.verdict -eq 'refused') { continue }
    $item = [pscustomobject]@{ id = $row.id; path = $row.path; label = $row.label; method = $row.method; bytes = $row.bytes }
    $live = Test-BvsDeleteItem -Ctx $ctx -Item $item -Images $images -Protected $protected -Git $git
    $why = $null
    if ($live.verdict -eq 'refused') { $why = 'now refused: ' + (@($live.reasons) -join '; ') }
    elseif ($live.kind -ne $row.kind) { $why = "it changed from $($row.kind) to $($live.kind)" }
    elseif ($live.sizeChanged) { $why = "its size changed: $(Format-BvsBytes $row.bytes) in the table, $(Format-BvsBytes $live.bytes) now" }
    elseif ($row.method -eq 'uninstall' -and ($null -eq $live.uninstall -or $live.uninstall.key -cne $row.uninstall.key -or $live.uninstall.command -cne $row.uninstall.command)) { $why = 'its registered uninstaller changed' }
    elseif ($row.method -eq 'holding' -and -not ([IO.Path]::GetPathRoot($row.path)).Equals($holdDrive, [StringComparison]::OrdinalIgnoreCase)) { $why = 'the holding folder is on another drive' }
    if ($why) { $mismatch.Add("#$($row.n) $(Format-BvsShortPath $row.path): $why") } else { $todo.Add([pscustomobject]@{ Row = $row; Bytes = $live.bytes }) }
}
$need = @{}
foreach ($x in $todo) { if ($x.Row.method -eq 'recycle') { $d = [IO.Path]::GetPathRoot($x.Row.path); $need[$d] = [long]$need[$d] + [long]$x.Bytes } }
foreach ($d in $need.Keys) {
    $cap = Get-BvsRecycleCapacity -DriveRoot $d
    if (-not $cap.enabled -or $need[$d] -gt [long]($cap.freeBytes * 0.9)) { $mismatch.Add("the Recycle Bin on $($cap.drive) no longer has room for the planned items") }
}
if ($mismatch.Count) {
    Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State 'awaiting-chat-confirmation' -Message 'The live re-check found changes since the final table. Nothing was deleted; Claude has to validate again.'
    Stop-Refused ("the live state no longer matches the final table. Run validate-delete.ps1 again and show the new table:`n  " + ($mismatch -join "`n  "))
}
if ($todo.Count -eq 0) { Stop-Refused 'the table has no items to remove' }

# --- 5. execute (one run per request, even if an action fails) ---------------------------------
$guard.executedAt = Get-BvsUtcStamp
Set-BvsGuard -Ctx $ctx -Id $SignalId -Guard $guard
Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State running -Message "Removing $($todo.Count) item(s) after your chat confirmation..."
Add-Type -AssemblyName Microsoft.VisualBasic
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ctx.LogPath))
$ui = [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs
$toBin = [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin
$okCount = 0; $failCount = 0; $freed = [long]0; $started = 0
"EXECUTE $SignalId items=$($todo.Count) table-ref=$($t.Hash.Substring(0, 8))"
foreach ($x in $todo) {
    $row = $x.Row
    $entry = [ordered]@{ time = (Get-BvsUtcStamp); signalId = $SignalId; n = $row.n; id = $row.id; path = $row.path; bytes = $x.Bytes; method = $row.method; result = $null }
    try {
        switch ($row.method) {
            'recycle' {
                if ($row.kind -eq 'dir') { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($row.path, $ui, $toBin) }
                else { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($row.path, $ui, $toBin) }
                if ([IO.File]::Exists($row.path) -or [IO.Directory]::Exists($row.path)) { throw 'it is still there after sending it to the Recycle Bin' }
                $entry.result = 'recycled'
            }
            'holding' {
                $dest = Join-Path $ctx.HoldingRoot (Join-Path $SignalId ([string]$row.n))
                $target = Join-Path $dest ([IO.Path]::GetFileName($row.path))
                [void][IO.Directory]::CreateDirectory($dest)
                Move-Item -LiteralPath $row.path -Destination $target -ErrorAction Stop
                $entry['dest'] = $target
                $entry.result = 'moved'
            }
            'uninstall' {
                $cmd = Get-BvsUninstallCommand -Key $row.uninstall.key
                if ($cmd -cne $row.uninstall.command) { throw 'the registered uninstaller changed' }
                $parts = Split-BvsCommand $cmd
                $proc = if ($parts.Args) { Start-Process -FilePath $parts.Exe -ArgumentList $parts.Args -PassThru } else { Start-Process -FilePath $parts.Exe -PassThru }
                $entry['pid'] = $proc.Id
                $entry.result = 'started'
                $started++
            }
            default { throw "unknown method $($row.method)" }
        }
        $okCount++
        if ($row.method -ne 'uninstall' -and $x.Bytes) { $freed += [long]$x.Bytes }
    }
    catch {
        $failCount++
        $entry.result = 'error'
        $entry['error'] = ConvertTo-BvsCleanText $_.Exception.Message 300
    }
    [IO.File]::AppendAllText($ctx.LogPath, (ConvertTo-Json $entry -Compress) + "`n", $Utf8)
    "  #$($row.n) $($entry.result) $(Format-BvsShortPath $row.path)$(if ($entry['dest']) { ' -> ' + (Format-BvsShortPath $entry['dest']) })$(if ($entry['error']) { ' : ' + $entry['error'] })"
}

$hold = Join-Path $ctx.HoldingRoot $SignalId
$summary = "$okCount of $($todo.Count) item(s) handled, $(Format-BvsBytes $freed) freed" +
$(if ($started) { ", $started uninstaller window(s) opened" } else { '' }) +
'. Recycle Bin items can be restored from the Recycle Bin' + $(if ([IO.Directory]::Exists($hold)) { "; moved items are in $(Format-BvsShortPath $hold)" } else { '' }) + '.'
if ($failCount) {
    Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State error -Message "Finished with problems: $failCount item(s) failed. $summary"
    "DONE-WITH-ERRORS $SignalId ok=$okCount failed=$failCount freed=$(Format-BvsBytes $freed) log=$(Format-BvsShortPath $ctx.LogPath)"
    exit 3
}
Set-BvsSignalStatus -Ctx $ctx -Id $SignalId -State done -Message "Done. $summary"
"DONE $SignalId ok=$okCount freed=$(Format-BvsBytes $freed) log=$(Format-BvsShortPath $ctx.LogPath)"
exit 0
