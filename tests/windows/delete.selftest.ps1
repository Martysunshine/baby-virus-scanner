#Requires -Version 7.2
<#
.SYNOPSIS
    End-to-end self-test of the signal bus and the double-confirmation deletion pipeline.
.DESCRIPTION
    Creates its own run folder under tests\fixtures\delete-sandbox\ with small fixture files
    (bvs-selftest-*) and a sandbox state folder, then drives the real chain:
      own server instance (free port, --state-root = sandbox) -> POST /api/signal ->
      watch-signals.ps1 -> validate-delete.ps1 -> execute-delete.ps1
    Covers: wrong code refused, right code -> Recycle Bin, holding move, refused path under
    C:\Windows (never touched, only named), refused credential folder, expired table refused,
    tampered table refused, live size change refused, re-execution refused, missing browser
    confirmation refused, stale-signal expiry in the watcher, sandbox guard.

    It only touches files it created itself. The two recycled fixture items (a few KB) end up in
    your Recycle Bin; everything else is removed with the run folder at the end.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File tests\windows\delete.selftest.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'src\lib\windows\BVS.Common.psm1') -Force
Import-Module (Join-Path $root 'src\tools\windows\BVS.Signals.psm1') -Force
$pass = 0; $fail = 0
function Assert([string]$Name, [bool]$Cond, [string]$Detail = '') {
    if ($Cond) { $script:pass++; "  PASS $Name" } else { $script:fail++; "  FAIL $Name $Detail" }
}

$sandboxBase = Join-Path $root 'tests\fixtures\delete-sandbox'
$run = Join-Path $sandboxBase ('run-{0:yyyyMMdd-HHmmss}-{1}' -f (Get-Date), (Get-Random -Maximum 99999))
$files = Join-Path $run 'files'
$state = Join-Path $run 'state'
[void][IO.Directory]::CreateDirectory($files)
[void][IO.Directory]::CreateDirectory($state)
$tools = Join-Path $root 'src\tools\windows'
$server = $null

function Invoke-Tool([string]$Script, [string[]]$ToolArgs) {
    $out = & pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tools $Script) @ToolArgs 2>&1
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = (@($out) -join "`n") }
}

function New-Fixture([string]$Rel, [int]$Size) {
    $p = Join-Path $files $Rel
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
    [IO.File]::WriteAllBytes($p, [byte[]]::new($Size))
    $p
}

function New-TestSignal([object[]]$Items, [datetime]$Created = [datetime]::UtcNow, [bool]$Typed = $true, [string]$Folder = 'archive') {
    # Same format as src/core/signals.py. The code is returned to the TEST only (in real use only the browser sees it).
    $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
    $code = -join (1..8 | ForEach-Object { $alphabet[[Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)] })
    $salt = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16)).ToLowerInvariant()
    $rand = -join (1..6 | ForEach-Object { 'abcdefghijklmnopqrstuvwxyz0123456789'[[Security.Cryptography.RandomNumberGenerator]::GetInt32(36)] })
    $id = '{0:yyyyMMdd-HHmmss}-delete-request-{1}' -f $Created.ToLocalTime(), $rand
    $sig = [ordered]@{ schema = 'bvs.signal/1'; id = $id; type = 'delete-request'; createdAt = (Get-BvsUtcStamp $Created); scanId = 'selftest'
        payload = [ordered]@{ items = @($Items) }; local = [ordered]@{ typedConfirmation = $Typed; at = (Get-BvsUtcStamp $Created) }
        codeSalt = $salt; codeHash = (Get-BvsCodeHash -Salt $salt -Code $code); codeKdf = 'pbkdf2-sha256-600000'
    }
    $dir = Join-Path $state "signals\$Folder"
    [void][IO.Directory]::CreateDirectory($dir)
    [IO.File]::WriteAllText((Join-Path $dir "$id.json"), (ConvertTo-Json $sig -Depth 8), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ Id = $id; Code = $code.Substring(0, 4) + '-' + $code.Substring(4) }
}

function Get-Item1([string]$Path, [string]$Method = 'recycle', [string]$Id = ('t-' + (Get-Random -Maximum 999999))) {
    $b = if ([IO.File]::Exists($Path)) { [IO.FileInfo]::new($Path).Length } else { $null }
    [ordered]@{ id = $Id; path = $Path; bytes = $b; method = $Method; label = [IO.Path]::GetFileName($Path) }
}

try {
    # ---------------------------------------------------------------- fixtures
    $fRecycle = New-Fixture 'bvs-selftest-recycle.txt' 1024
    [void](New-Fixture 'bvs-selftest-dir\a.txt' 2048)
    [void](New-Fixture 'bvs-selftest-dir\sub\b.txt' 3072)
    $fDir = Join-Path $files 'bvs-selftest-dir'
    $fHold = New-Fixture 'bvs-selftest-hold.bin' 4096
    [void](New-Fixture 'bvs-selftest-keys\server.pem' 16)
    $fKeys = Join-Path $files 'bvs-selftest-keys'
    $winIni = Join-Path $env:SystemRoot 'win.ini'

    'sandbox guard'
    Assert 'StateRoot outside the sandbox is refused' ($(try { [void](Get-BvsSignalContext -StateRoot $env:TEMP); $false } catch { $true }))
    $r = Invoke-Tool 'validate-delete.ps1' @('-SignalId', '20261020-000000-delete-request-aaaaaa', '-StateRoot', $env:TEMP)
    Assert 'validate with a foreign StateRoot fails' ($r.Code -ne 0)

    'hash agreement with src/core/signals.py'
    $py = (Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if ($py) {
        $pyHash = & $py -I -B -c "import sys; sys.path.append(r'$root\core'); import signals; print(signals.hash_code('00ff', 'K7Q2M9XP'))"
        Assert 'PBKDF2 code hash identical in Python and PowerShell' ($pyHash -eq (Get-BvsCodeHash -Salt '00ff' -Code 'K7Q2M9XP'))
    }
    else { Assert 'python found for the end-to-end part' $false }

    # ---------------------------------------------------------------- 1. server -> inbox
    'server: POST /api/signal (own instance, free port, sandbox state)'
    $outFile = Join-Path $run 'server.out'
    $argv = @('-I', '-B', "`"$root\server\serve.py`"", '--scan', "`"$root\tests\fixtures\demo-scan`"", '--port', '0', '--no-ai', '--state-root', "`"$state`"")
    $server = Start-Process -FilePath $py -ArgumentList $argv -RedirectStandardOutput $outFile -NoNewWindow -PassThru
    $base = $null
    foreach ($i in 1..60) {
        Start-Sleep -Milliseconds 250
        if ([IO.File]::Exists($outFile)) {
            $m = [regex]::Match((Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue) + '', 'http://127\.0\.0\.1:(\d+)/')
            if ($m.Success) { $base = "http://127.0.0.1:$($m.Groups[1].Value)"; break }
        }
    }
    Assert 'test server started on a free port (not 8777)' ($base -and $base -notmatch ':8777$') "$base"
    $items = @(
        (Get-Item1 $fRecycle 'recycle' 'g1-00001'),
        [ordered]@{ id = 'g1-00002'; path = $fDir; bytes = 5120; method = 'recycle'; label = 'bvs-selftest-dir' },
        (Get-Item1 $fHold 'holding' 'g1-00003'),
        [ordered]@{ id = 'g1-00004'; path = $winIni; bytes = 92; method = 'recycle'; label = 'win.ini' },
        [ordered]@{ id = 'g1-00005'; path = $fKeys; bytes = 16; method = 'recycle'; label = 'bvs-selftest-keys' }
    )
    $tok = (Invoke-RestMethod -Uri "$base/api/status").token
    $hdr = @{ Origin = $base; 'X-BVS-Token' = $tok }
    $bad = try { Invoke-RestMethod -Method Post -Uri "$base/api/signal" -Headers $hdr -ContentType 'application/json' -Body (@{ type = 'delete-request'; typedConfirmation = 'i confirm'; payload = @{ items = $items } } | ConvertTo-Json -Depth 6); 'accepted' } catch { [int]$_.Exception.Response.StatusCode }
    Assert 'server refuses a wrong browser phrase (400)' ($bad -eq 400) "$bad"
    $resp = Invoke-RestMethod -Method Post -Uri "$base/api/signal" -Headers $hdr -ContentType 'application/json' -Body (@{ type = 'delete-request'; typedConfirmation = 'I confirm'; payload = @{ items = $items } } | ConvertTo-Json -Depth 6)
    $id = $resp.id; $code = $resp.code
    Assert 'server returned id + one-time code' (($id -match '-delete-request-') -and ($code -cmatch '^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$')) "$id $code"
    $inboxFile = Join-Path $state "signals\inbox\$id.json"
    $rawSig = Get-Content -LiteralPath $inboxFile -Raw
    Assert 'signal file in the inbox holds no code' ([IO.File]::Exists($inboxFile) -and -not $rawSig.Contains($code) -and -not $rawSig.Contains($code.Replace('-', '')))

    # ---------------------------------------------------------------- 2. watcher
    'watcher'
    $r = Invoke-Tool 'watch-signals.ps1' @('-StateRoot', $state, '-TimeoutMinutes', '0.5', '-PollSeconds', '0.2')
    Assert 'watcher printed SIGNAL line and exited 0' ($r.Code -eq 0 -and $r.Out -match "SIGNAL $id delete-request items=5") $r.Out
    Assert 'watcher moved the signal to the archive' ((-not [IO.File]::Exists($inboxFile)) -and [IO.File]::Exists((Join-Path $state "signals\archive\$id.json")))
    Assert 'status picked-up' ((Get-BvsSignalStatus -Ctx (Get-BvsSignalContext -StateRoot $state) -Id $id).state -eq 'picked-up')
    Assert 'heartbeat written' ([IO.File]::Exists((Join-Path $state 'session\heartbeat.json')))
    Assert 'watcher output does not contain the code' (-not $r.Out.Contains($code))
    $sess = Invoke-RestMethod -Uri "$base/api/session" -Headers @{ 'X-BVS-Token' = $tok }
    Assert '/api/session sees the fresh heartbeat' ($sess.connected -eq $true)

    # ---------------------------------------------------------------- 3. validate
    'validate'
    $ctx = Get-BvsSignalContext -StateRoot $state
    $r = Invoke-Tool 'validate-delete.ps1' @('-SignalId', $id, '-StateRoot', $state)
    Assert 'validate exit 0' ($r.Code -eq 0) $r.Out
    $t = Read-BvsDeleteTable -Ctx $ctx -Id $id
    Assert 'table written and hash valid' ($t.Valid) "$($t.Error)"
    $rows = @($t.Table.items)
    Assert '#1 file -> recycle' ($rows[0].verdict -ne 'refused' -and $rows[0].method -eq 'recycle') "$($rows[0].verdict) $($rows[0].method)"
    Assert '#2 folder -> recycle, size summed' ($rows[1].method -eq 'recycle' -and $rows[1].bytes -eq 5120 -and $rows[1].files -eq 2) "$($rows[1].method) $($rows[1].bytes)"
    Assert '#3 -> holding' ($rows[2].method -eq 'holding') "$($rows[2].method)"
    Assert '#4 C:\Windows refused' ($rows[3].verdict -eq 'refused' -and (@($rows[3].reasons) -join ' ') -match 'Windows') "$(@($rows[3].reasons) -join '; ')"
    Assert '#5 folder with a key file refused' ($rows[4].verdict -eq 'refused' -and (@($rows[4].reasons) -join ' ') -match 'credential') "$(@($rows[4].reasons) -join '; ')"
    Assert 'markdown table printed' ($r.Out -match '\| # \| Item \| Size \| Method \| Verdict \| Notes \|' -and $r.Out -match '\| 4 \|.*refused')
    Assert 'status awaiting-chat-confirmation' ((Get-BvsSignalStatus -Ctx $ctx -Id $id).state -eq 'awaiting-chat-confirmation')
    Assert 'signal-status cannot fake done for a delete' ((Invoke-Tool 'signal-status.ps1' @('-Id', $id, '-State', 'done', '-StateRoot', $state)).Code -ne 0)

    # ---------------------------------------------------------------- 4. wrong code
    'execute: wrong code'
    $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
    $wrong = -join ($code.Replace('-', '').ToCharArray() | ForEach-Object { $alphabet[($alphabet.IndexOf($_) + 1) % $alphabet.Length] })
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $id, '-Code', $wrong, '-StateRoot', $state)
    Assert 'wrong code -> exit 2, refused' ($r.Code -eq 2 -and $r.Out -match 'REFUSED') $r.Out
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $id, '-Code', 'I confirm', '-StateRoot', $state)
    Assert 'missing code -> exit 2' ($r.Code -eq 2)
    Assert 'nothing deleted after wrong codes' ([IO.File]::Exists($fRecycle) -and [IO.Directory]::Exists($fDir) -and [IO.File]::Exists($fHold))
    Assert 'wrong attempts counted' ((Get-BvsGuard -Ctx $ctx -Id $id).failedAttempts -eq 2)

    # ---------------------------------------------------------------- 5. right code
    'execute: right code'
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $id, '-Code', ('I confirm ' + $code.ToLowerInvariant()), '-StateRoot', $state)
    Assert 'right code -> exit 0' ($r.Code -eq 0) $r.Out
    Assert '#1 file recycled' (-not [IO.File]::Exists($fRecycle))
    Assert '#2 folder recycled' (-not [IO.Directory]::Exists($fDir))
    $held = Join-Path $state "holding\$id\3\bvs-selftest-hold.bin"
    Assert '#3 moved to holding\<id>\3\' ((-not [IO.File]::Exists($fHold)) -and [IO.File]::Exists($held))
    Assert '#4 C:\Windows untouched' ([IO.File]::Exists($winIni))
    Assert '#5 refused folder untouched' ([IO.Directory]::Exists($fKeys))
    $log = @(Get-Content -LiteralPath (Join-Path $state 'deletions.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert 'deletions.jsonl has 3 actions' ($log.Count -eq 3 -and ($log.result -join ',') -eq 'recycled,recycled,moved') "$($log.result -join ',')"
    Assert 'log entries have time/signalId/path/bytes/method' (@($log | Where-Object { $_.time -and $_.signalId -eq $id -and $_.path -and $null -ne $_.bytes -and $_.method }).Count -eq 3)
    Assert 'status done' ((Get-BvsSignalStatus -Ctx $ctx -Id $id).state -eq 'done')
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $id, '-Code', $code, '-StateRoot', $state)
    Assert 're-execution refused' ($r.Code -eq 1 -and $r.Out -match 'already executed')
    $list = Invoke-RestMethod -Uri "$base/api/signals" -Headers @{ 'X-BVS-Token' = $tok }
    $entry = @($list.items | Where-Object id -EQ $id)[0]
    Assert '/api/signals shows done, no code or hash' ($entry.state -eq 'done' -and -not (($list | ConvertTo-Json -Depth 6).Contains($code)) -and -not (($list | ConvertTo-Json -Depth 6) -match 'codeHash|codeSalt'))
    $allText = (Get-ChildItem -LiteralPath $state -Recurse -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
    Assert 'code appears in no state file' (-not $allText.Contains($code) -and -not $allText.Contains($code.Replace('-', '')))

    # ---------------------------------------------------------------- 6. expired table
    'expired table'
    $f6 = New-Fixture 'bvs-selftest-expired.txt' 512
    $s6 = New-TestSignal @((Get-Item1 $f6))
    $r = Invoke-Tool 'validate-delete.ps1' @('-SignalId', $s6.Id, '-StateRoot', $state, '-TtlMinutes', '0')
    Assert 'validate (TTL 0) exit 0' ($r.Code -eq 0) $r.Out
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $s6.Id, '-Code', $s6.Code, '-StateRoot', $state)
    Assert 'expired table refused' ($r.Code -eq 1 -and $r.Out -match 'expired') $r.Out
    Assert 'file kept' ([IO.File]::Exists($f6))

    # ---------------------------------------------------------------- 7. tampered table
    'tampered table'
    $f7 = New-Fixture 'bvs-selftest-tamper.txt' 512
    $s7 = New-TestSignal @((Get-Item1 $f7))
    [void](Invoke-Tool 'validate-delete.ps1' @('-SignalId', $s7.Id, '-StateRoot', $state))
    $tp = Join-Path $state "signals\tables\$($s7.Id).json"
    $txt = [IO.File]::ReadAllText($tp)
    [IO.File]::WriteAllText($tp, $txt.Replace('bvs-selftest-tamper.txt', 'bvs-selftest-tamper.TXT'), [Text.UTF8Encoding]::new($false))
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $s7.Id, '-Code', $s7.Code, '-StateRoot', $state)
    Assert 'tampered table refused' ($r.Code -eq 1 -and $r.Out -match 'hash mismatch') $r.Out
    Assert 'file kept' ([IO.File]::Exists($f7))

    # ---------------------------------------------------------------- 8. live change after the table
    'live change after validation'
    $f8 = New-Fixture 'bvs-selftest-grow.bin' 1024
    $s8 = New-TestSignal @((Get-Item1 $f8))
    [void](Invoke-Tool 'validate-delete.ps1' @('-SignalId', $s8.Id, '-StateRoot', $state))
    [IO.File]::WriteAllBytes($f8, [byte[]]::new(3MB))
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $s8.Id, '-Code', $s8.Code, '-StateRoot', $state)
    Assert 'size change refused' ($r.Code -eq 1 -and $r.Out -match 'size changed') $r.Out
    Assert 'file kept' ([IO.File]::Exists($f8))

    # ---------------------------------------------------------------- 9. no browser confirmation
    'no browser confirmation'
    $f9 = New-Fixture 'bvs-selftest-noconfirm.txt' 512
    $s9 = New-TestSignal @((Get-Item1 $f9)) -Typed $false
    $r = Invoke-Tool 'validate-delete.ps1' @('-SignalId', $s9.Id, '-StateRoot', $state)
    Assert 'validate refuses without "I confirm" in the browser' ($r.Code -eq 1)
    $r = Invoke-Tool 'execute-delete.ps1' @('-SignalId', $s9.Id, '-Code', $s9.Code, '-StateRoot', $state)
    Assert 'execute refuses without "I confirm" in the browser' ($r.Code -eq 1 -and [IO.File]::Exists($f9))

    # ---------------------------------------------------------------- 10. stale signal expiry
    'watcher expiry'
    $s10 = New-TestSignal @((Get-Item1 $f9)) -Created ([datetime]::UtcNow.AddHours(-2)) -Folder inbox
    $r = Invoke-Tool 'watch-signals.ps1' @('-StateRoot', $state, '-TimeoutMinutes', '0.05', '-PollSeconds', '0.2')
    Assert 'stale signal does not wake Claude (NO-SIGNAL)' ($r.Code -eq 0 -and $r.Out -match 'NO-SIGNAL' -and $r.Out -notmatch 'SIGNAL 2') $r.Out
    Assert 'stale signal archived as expired' ((Get-BvsSignalStatus -Ctx $ctx -Id $s10.Id).state -eq 'expired' -and [IO.File]::Exists((Join-Path $state "signals\archive\$($s10.Id).json")))
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }   # our own test server only
    Start-Sleep -Milliseconds 300
    # remove only this run's folder (fixtures, sandbox state, holding); refuse anything else
    if ((Test-BvsUnder $run $sandboxBase -Strict) -and [IO.Directory]::Exists($run)) { Remove-Item -LiteralPath $run -Recurse -Force -ErrorAction SilentlyContinue }
}
Assert 'run folder cleaned up' (-not [IO.Directory]::Exists($run))
''
"delete selftest: $pass passed, $fail failed"
if ($fail) { exit 1 }
exit 0
