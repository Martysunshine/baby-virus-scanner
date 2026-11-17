#Requires -Version 7.2
<#
.SYNOPSIS
    Shared helpers for the signal bus and the double-confirmation deletion pipeline (agent K).
.DESCRIPTION
    Used by watch-signals.ps1, signal-status.ps1, validate-delete.ps1 and execute-delete.ps1.
    Everything here is READ-ONLY towards the system. The only writes are small JSON files inside
    the state folder (signals\status, signals\tables, signals\guard, session\heartbeat.json) and
    the move of a picked-up signal from inbox to archive. Deleting happens ONLY in
    execute-delete.ps1.

    State folder: <project>\data (default) or, for the self-test only, a folder under
    tests\fixtures\delete-sandbox. In sandbox mode every file item must also be inside the
    sandbox, holding and the deletion log live inside the sandbox, and uninstalls are refused,
    so the test switches can never be pointed at real files.

    Contract: docs\ui-contract-v3.md section 1. Playbook: docs\playbooks\K-signals.md.
#>

$script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module (Join-Path $script:Root 'src\lib\windows\BVS.Common.psm1')   # Protect-BvsText, Test-BvsNeverRead, Test-BvsCloudOnly, ...
$script:SandboxRoot = Join-Path $script:Root 'tests\fixtures\delete-sandbox'
$script:SignalTypes = @('run-admin', 'run-github-check', 'rerun-module', 'fix-request', 'delete-request', 'refresh-report')
$script:States = @('queued', 'picked-up', 'awaiting-chat-confirmation', 'running', 'done', 'error', 'cancelled', 'expired')
$script:IdPattern = '^\d{8}-\d{6}-(run-admin|run-github-check|rerun-module|fix-request|delete-request|refresh-report)-[a-z0-9]{6}$'
$script:CodeAlphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
$script:ExpireMinutes = 60
$script:MaxTreeEntries = 1000000
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:BadChars = '[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]'

#region ---------- paths, context, state files ----------

function Test-BvsUnder {
    <# .SYNOPSIS True when Path equals Parent or lies inside it (case-insensitive, separator-aware). #>
    param([string]$Path, [string]$Parent, [switch]$Strict)
    if (-not $Path -or -not $Parent) { return $false }
    $p = $Path.TrimEnd('\'); $q = $Parent.TrimEnd('\')
    if (-not $Strict -and $p.Equals($q, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $p.StartsWith($q + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-BvsSignalContext {
    <# .SYNOPSIS Resolve and check the state folder. Throws for anything other than data\ or the self-test sandbox. #>
    param([string]$StateRoot)
    $default = Join-Path $script:Root 'data'
    $state = if ($StateRoot) { [IO.Path]::GetFullPath($StateRoot).TrimEnd('\') } else { $default }
    $sandbox = -not $state.Equals($default, [StringComparison]::OrdinalIgnoreCase)
    if ($sandbox -and -not (Test-BvsUnder $state $script:SandboxRoot -Strict)) {
        throw "StateRoot must be the project's data folder, or a folder under tests\fixtures\delete-sandbox (self-test only)."
    }
    $sig = Join-Path $state 'signals'
    [pscustomobject]@{
        Root        = $script:Root
        StateRoot   = $state
        Inbox       = Join-Path $sig 'inbox'
        Archive     = Join-Path $sig 'archive'
        Status      = Join-Path $sig 'status'
        Tables      = Join-Path $sig 'tables'
        Guard       = Join-Path $sig 'guard'
        Heartbeat   = Join-Path $state 'session\heartbeat.json'
        HoldingRoot = if ($sandbox) { Join-Path $state 'holding' } else { Join-Path $script:Root 'holding' }
        LogPath     = if ($sandbox) { Join-Path $state 'deletions.jsonl' } else { Join-Path $script:Root 'logs\deletions.jsonl' }
        Sandbox     = $sandbox
        AllowedArea = if ($sandbox) { $script:SandboxRoot } else { [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\') }
    }
}

function Test-BvsSignalId { param([string]$Id) [bool]($Id -cmatch $script:IdPattern) }

function Get-BvsSignalStates { $script:States }

function Get-BvsUtcStamp { param([datetime]$When = [datetime]::UtcNow) $When.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }

function Write-BvsStateFile {
    <# .SYNOPSIS Atomically write text inside the state folder (temp file + rename). #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-BvsUnder $full $Ctx.StateRoot -Strict)) { throw "Refusing to write outside the state folder: $full" }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
    $tmp = Join-Path ([IO.Path]::GetDirectoryName($full)) (".{0}.{1}.tmp" -f [IO.Path]::GetFileName($full), $PID)
    [IO.File]::WriteAllText($tmp, $Text, $script:Utf8NoBom)
    [IO.File]::Move($tmp, $full, $true)
}

function Read-BvsJsonFile {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return $null }
    try { [IO.File]::ReadAllText($Path, $script:Utf8NoBom) | ConvertFrom-Json -Depth 20 } catch { $null }
}

function ConvertTo-BvsCleanText {
    <# .SYNOPSIS Display-safe text: control/bidi characters removed, secrets masked, clipped. #>
    param([AllowNull()][string]$Text, [int]$Max = 500)
    $t = [regex]::Replace([string]$Text, $script:BadChars, ' ')
    $t = Protect-BvsText $t
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 1) + [char]0x2026 }
    $t
}

function Set-BvsSignalStatus {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$State, [string]$Message = '')
    if (-not (Test-BvsSignalId $Id)) { throw "Bad signal id: $Id" }
    if ($State -cnotin $script:States) { throw "Bad state: $State" }
    $obj = [ordered]@{ id = $Id; state = $State; message = (ConvertTo-BvsCleanText $Message 500); updatedAt = (Get-BvsUtcStamp) }
    Write-BvsStateFile -Ctx $Ctx -Path (Join-Path $Ctx.Status "$Id.json") -Text (ConvertTo-Json $obj -Compress)
}

function Get-BvsSignalStatus {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id)
    Read-BvsJsonFile (Join-Path $Ctx.Status "$Id.json")
}

function Read-BvsSignal {
    <# .SYNOPSIS Load and sanity-check a signal file from archive (default) or inbox. Returns $null when missing or invalid. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id, [ValidateSet('archive', 'inbox')][string]$From = 'archive')
    if (-not (Test-BvsSignalId $Id)) { return $null }
    $dir = if ($From -eq 'archive') { $Ctx.Archive } else { $Ctx.Inbox }
    $sig = Read-BvsJsonFile (Join-Path $dir "$Id.json")
    if ($null -eq $sig -or $sig.schema -cne 'bvs.signal/1' -or $sig.id -cne $Id -or $sig.type -cnotin $script:SignalTypes) { return $null }
    if (-not $Id.Contains("-$($sig.type)-")) { return $null }
    $sig
}

function Get-BvsSignalAgeMinutes {
    param($Signal)
    try { ([datetime]::UtcNow - (ConvertTo-BvsUtcDate $Signal.createdAt)).TotalMinutes } catch { [double]::MaxValue }
}

function Get-BvsGuard {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id)
    $g = Read-BvsJsonFile (Join-Path $Ctx.Guard "$Id.json")
    [ordered]@{
        failedAttempts = if ($g -and $g.failedAttempts) { [int]$g.failedAttempts } else { 0 }
        executedAt     = if ($g -and $g.executedAt) { [string]$g.executedAt } else { $null }
        lastAttemptAt  = if ($g -and $g.lastAttemptAt) { [string]$g.lastAttemptAt } else { $null }
    }
}

function Set-BvsGuard {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Guard)
    Write-BvsStateFile -Ctx $Ctx -Path (Join-Path $Ctx.Guard "$Id.json") -Text (ConvertTo-Json $Guard -Compress)
}

#endregion

#region ---------- formatting ----------

function Format-BvsBytes {
    param($Bytes)
    if ($null -eq $Bytes) { return '?' }
    $b = [double]$Bytes
    foreach ($u in 'B', 'KB', 'MB', 'GB') { if ($b -lt 1024) { return ('{0:0.#} {1}' -f $b, $u).Replace(',', '.') }; $b /= 1024 }
    ('{0:0.##} TB' -f $b).Replace(',', '.')
}

function Format-BvsShortPath {
    <# .SYNOPSIS Path for chat output: profile shortened to ~, secrets masked, table pipes escaped. #>
    param([string]$Path)
    $p = [string]$Path
    $prof = $env:USERPROFILE.TrimEnd('\')
    if ($p.StartsWith($prof, [StringComparison]::OrdinalIgnoreCase)) { $p = '~' + $p.Substring($prof.Length) }
    (ConvertTo-BvsCleanText $p 160).Replace('|', '\|')
}

function Get-BvsSignalSummary {
    <# .SYNOPSIS One short, masked line describing a signal (for the watcher's SIGNAL line). #>
    param($Signal)
    $p = $Signal.payload
    $text = switch ($Signal.type) {
        'run-admin' { 'run the elevated read-only admin checks' }
        'run-github-check' { 'run the authenticated GitHub check (S13)' }
        'refresh-report' { 'rebuild the report (aggregate + build_datajs)' }
        'rerun-module' { "re-run module $($p.module)" }
        'fix-request' { "explain the fix for finding $($p.findingId), then ask in chat" }
        'delete-request' {
            $items = @($p.items)
            $total = ($items | Where-Object { $null -ne $_.bytes } | Measure-Object -Property bytes -Sum).Sum
            $confirmed = if ($Signal.local.typedConfirmation -eq $true) { 'yes' } else { 'NO' }
            "items=$($items.Count) size=$(Format-BvsBytes $total) typed-in-browser=$confirmed"
        }
        default { '' }
    }
    ConvertTo-BvsCleanText $text 200
}

#endregion

#region ---------- live checks for one delete item ----------

function Get-BvsSha256Hex {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function Get-BvsCodeHash {
    <# .SYNOPSIS One-time delete code hash: PBKDF2-HMAC-SHA256(code, salt, 600k, 32 bytes) hex. Must match src/core/signals.py hash_code. #>
    param([Parameter(Mandatory)][string]$Salt, [Parameter(Mandatory)][AllowEmptyString()][string]$Code)
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2([Text.Encoding]::UTF8.GetBytes($Code), [Text.Encoding]::UTF8.GetBytes($Salt), 600000, [Security.Cryptography.HashAlgorithmName]::SHA256, 32)
    [Convert]::ToHexString($kdf).ToLowerInvariant()
}

function Get-BvsProtectedSet {
    <# .SYNOPSIS The hard-refusal list from docs\ui-contract-v3.md section 1, resolved for this PC. #>
    param([Parameter(Mandatory)]$Ctx)
    $prof = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
    $roots = [Collections.Generic.List[object]]::new()   # the folder itself, and anything that contains it
    $trees = [Collections.Generic.List[object]]::new()   # the folder and everything inside it
    function AddRoot([string]$p, [string]$why) { if ($p) { $roots.Add([pscustomobject]@{ Path = [IO.Path]::GetFullPath($p).TrimEnd('\'); Why = $why }) } }
    function AddTree([string]$p, [string]$why) { if ($p) { $trees.Add([pscustomobject]@{ Path = [IO.Path]::GetFullPath($p).TrimEnd('\'); Why = $why }) } }

    AddRoot $prof 'your user profile folder itself'
    foreach ($n in 'Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos', 'Music', 'OneDrive', 'AppData', 'AppData\Local', 'AppData\Roaming', 'AppData\LocalLow') {
        AddRoot (Join-Path $prof $n) "the $n folder itself"
    }
    foreach ($f in 'MyDocuments', 'Desktop', 'MyPictures', 'MyVideos', 'MyMusic') {
        $p = [Environment]::GetFolderPath($f); if ($p) { AddRoot $p 'a personal folder root (redirected)' }
    }
    $dl = (Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -ErrorAction SilentlyContinue).'{374DE290-123F-4565-9164-39C4925E467B}'
    if ($dl) { AddRoot $dl 'the Downloads folder itself' }
    foreach ($v in 'OneDrive', 'OneDriveConsumer', 'OneDriveCommercial') { $p = [Environment]::GetEnvironmentVariable($v); if ($p) { AddRoot $p 'the OneDrive folder itself' } }
    AddRoot $Ctx.Root "the scanner's own project folder"
    AddRoot $Ctx.HoldingRoot 'the holding folder itself'

    AddTree $env:SystemRoot 'the Windows system folder'
    AddTree $env:ProgramFiles "Program Files (use the program's own uninstaller)"
    AddTree ${env:ProgramFiles(x86)} "Program Files (x86) (use the program's own uninstaller)"
    AddTree $env:ProgramW6432 "Program Files (use the program's own uninstaller)"
    if ($env:ProgramData) { AddTree (Join-Path $env:ProgramData 'Microsoft') 'ProgramData\Microsoft (Windows data)' }
    if ($env:LOCALAPPDATA) { AddTree (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps') 'WindowsApps (Store apps)' }
    AddTree (Join-Path $prof '.ssh') 'the SSH keys folder'
    AddTree (Join-Path $Ctx.Root 'data') "the scanner's active data folder"
    AddTree $Ctx.StateRoot "the scanner's active data folder"
    AddTree (Join-Path $Ctx.Root 'logs') "the scanner's logs (deletion audit trail)"
    [pscustomobject]@{ Roots = $roots; Trees = $trees; OneDrive = @($roots | Where-Object { $_.Why -like '*OneDrive*' } | ForEach-Object Path) }
}

function Resolve-BvsItemPath {
    <# .SYNOPSIS Canonical absolute local path, or an error text. Refuses relative, UNC, \\?\, wildcards, ADS, 8.3 names, '..'. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return @{ Error = 'no path given' } }
    if ($Path -match $script:BadChars) { return @{ Error = 'the path contains control characters' } }
    if ($Path -notmatch '^[A-Za-z]:\\') { return @{ Error = 'not a local absolute path (C:\...)' } }
    if ($Path.IndexOfAny([char[]]'*?"<>|') -ge 0) { return @{ Error = 'the path contains wildcard or invalid characters' } }
    if ($Path.IndexOf(':', 2) -ge 0) { return @{ Error = 'alternate data stream syntax is not accepted' } }
    if ($Path -match '~\d') { return @{ Error = 'short 8.3 names (like PROGRA~1) are not accepted; use the full path' } }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return @{ Error = 'the path is not valid' } }
    if (-not $full.Equals($Path.TrimEnd('\'), [StringComparison]::Ordinal)) {
        return @{ Error = "the path is not in canonical form ('..', '.', doubled separators or trailing dots/spaces)" }
    }
    if ($full.Length -le 3) { return @{ Error = 'a whole drive cannot be deleted' } }
    @{ Path = $full }
}

function Get-BvsTreeStats {
    <#
    .SYNOPSIS Size and safety facts for a folder tree. Like Get-BvsFiles (no reparse traversal) but it also
              REPORTS what Get-BvsFiles silently skips (links, cloud placeholders, unreadable folders), which a
              deletion must know about. Reads names and sizes only, never file contents.
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxEntries = $script:MaxTreeEntries)
    $o = [IO.EnumerationOptions]::new()
    $o.AttributesToSkip = [IO.FileAttributes]0
    $o.IgnoreInaccessible = $false
    $o.RecurseSubdirectories = $false
    $o.ReturnSpecialDirectories = $false
    $s = [ordered]@{ bytes = [long]0; files = 0; dirs = 0; links = 0; cloud = 0; inaccessible = 0; neverRead = 0
        neverReadExample = $null; sshDirs = 0; repos = [Collections.Generic.List[string]]::new(); truncated = $false; entries = 0 }
    $stack = [Collections.Generic.Stack[string]]::new()
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($e in [IO.DirectoryInfo]::new($dir).EnumerateFileSystemInfos('*', $o)) {
                $s.entries++
                if ($s.entries -gt $MaxEntries) { $s.truncated = $true; return [pscustomobject]$s }
                $a = [int]$e.Attributes
                if ((($a -band 0x400000) -ne 0) -or (($a -band 0x40000) -ne 0) -or (($a -band 0x1000) -ne 0)) { $s.cloud++; continue }
                if (($a -band 0x400) -ne 0) { $s.links++; continue }
                if ($e -is [IO.DirectoryInfo]) {
                    $s.dirs++
                    if ($e.Name -eq '.git') { $s.repos.Add($dir) }
                    elseif ($e.Name -eq '.ssh') { $s.sshDirs++ }
                    $stack.Push($e.FullName)
                    continue
                }
                $s.files++
                $s.bytes += $e.Length
                if ($e.Name -eq '.git') { $s.repos.Add($dir) }   # worktree / submodule pointer file
                if (Test-BvsNeverRead $e.FullName) {
                    $s.neverRead++
                    if (-not $s.neverReadExample) { $s.neverReadExample = if ($e.Extension) { "*$($e.Extension)" } else { $e.Name.Substring(0, [Math]::Min(3, $e.Name.Length)) + '...' } }
                }
            }
        }
        catch { $s.inaccessible++ }
    }
    [pscustomobject]$s
}

function Get-BvsRunningImages {
    <# .SYNOPSIS Executable paths of running processes (read-only CIM query). #>
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath } |
            ForEach-Object { [pscustomobject]@{ Pid = [int]$_.ProcessId; Name = [string]$_.Name; Path = [string]$_.ExecutablePath } })
}

function Get-BvsGitExe {
    $g = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($g) { $g.Source } else { $null }
}

function Test-BvsGitWork {
    <#
    .SYNOPSIS Read-only git checks: uncommitted/untracked changes, unpushed commits, stashes.
              -SubPath limits the status check to one path inside an enclosing repo (commits are not at risk then).
              Returns a list of problems (empty = nothing at risk).
    #>
    param([Parameter(Mandatory)][string]$Git, [Parameter(Mandatory)][string]$Repo, [string]$SubPath)
    $problems = [Collections.Generic.List[string]]::new()
    $env:GIT_TERMINAL_PROMPT = '0'
    $short = "repo '" + (ConvertTo-BvsCleanText ([IO.Path]::GetFileName($Repo.TrimEnd('\'))) 60) + "'"
    $statusArgs = @('--no-pager', '--no-optional-locks', '-C', $Repo, 'status', '--porcelain')
    if ($SubPath) { $statusArgs += @('--', $SubPath) }
    $out = & $Git @statusArgs 2>$null
    if ($LASTEXITCODE -ne 0) { $problems.Add("git could not check the repository at $short (check it by hand)"); return $problems }
    if (@($out).Count -gt 0) { $problems.Add("uncommitted or untracked git changes in $short ($(@($out).Count) file(s))") }
    if (-not $SubPath) {
        $log = & $Git --no-pager --no-optional-locks -C $Repo log --branches --not --remotes --oneline -n 20 2>$null
        if ($LASTEXITCODE -ne 0) { $problems.Add("git could not list unpushed commits in $short") }
        elseif (@($log).Count -gt 0) { $problems.Add("unpushed git commits in $short ($(@($log).Count)$(if (@($log).Count -ge 20) { '+' }))") }
        & $Git --no-pager --no-optional-locks -C $Repo rev-parse --verify --quiet refs/stash *> $null
        if ($LASTEXITCODE -eq 0) { $problems.Add("git stash entries in $short") }
    }
    $problems
}

function Find-BvsUninstallEntry {
    <# .SYNOPSIS Installed-program registry entries whose DisplayName equals the label (read-only). #>
    param([Parameter(Mandatory)][string]$Label)
    $bases = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($b in $bases) {
        foreach ($k in @(Get-ChildItem -LiteralPath $b -ErrorAction SilentlyContinue)) {
            $name = [string]$k.GetValue('DisplayName')
            if ($name -and $name.Trim().Equals($Label.Trim(), [StringComparison]::OrdinalIgnoreCase)) {
                [pscustomobject]@{
                    Key             = "$b\$($k.PSChildName)"
                    UninstallString = [string]$k.GetValue('UninstallString')
                    InstallLocation = [string]$k.GetValue('InstallLocation')
                    SystemComponent = [int]($k.GetValue('SystemComponent', 0))
                }
            }
        }
    }
}

function Get-BvsUninstallCommand {
    <# .SYNOPSIS Re-read one UninstallString from its registry key (read-only). #>
    param([Parameter(Mandatory)][string]$Key)
    if ($Key -notmatch '^(HKLM|HKCU):\\(SOFTWARE|Software)\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$') { return $null }
    $p = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
    if ($p) { [string]$p.UninstallString } else { $null }
}

function Test-BvsDeleteItem {
    <#
    .SYNOPSIS Re-validate one delete item live. Returns an ordered hashtable:
              {id,label,path,kind,verdict(ok|warn|refused),method,bytes,files,reasons[],uninstall,sizeChanged}.
              Read-only: looks at names, sizes, attributes, running processes, git status and the registry.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$Item, [Parameter(Mandatory)][AllowEmptyCollection()]$Images,
        [Parameter(Mandatory)]$Protected, [string]$Git)
    $refusals = [Collections.Generic.List[string]]::new()
    $warnings = [Collections.Generic.List[string]]::new()
    $r = [ordered]@{ id = [string]$Item.id; label = [string]$Item.label; path = [string]$Item.path; kind = 'unknown'; verdict = 'ok'
        method = [string]$Item.method; bytes = $null; files = $null; reasons = @(); uninstall = $null; sizeChanged = $false
    }
    $requested = if ($null -ne $Item.bytes) { [long]$Item.bytes } else { $null }
    $finish = {
        $r.reasons = @(@($refusals) + @($warnings) | Select-Object -Unique)
        if ($refusals.Count) { $r.verdict = 'refused'; $r.method = 'refused' } elseif ($warnings.Count) { $r.verdict = 'warn' }
        $r
    }

    if ($r.method -in 'tool', 'setting') {
        $refusals.Add("this item is cleaned with the app's own tool or a setting, not by deleting files")
        return (& $finish)
    }
    if ($r.method -notin 'recycle', 'holding', 'uninstall') { $refusals.Add('unknown method'); return (& $finish) }

    # --- programs: the program's own uninstaller ---------------------------------------------
    if ($r.method -eq 'uninstall') {
        $r.kind = 'program'
        $r.bytes = $requested
        if ($Ctx.Sandbox) { $refusals.Add('uninstalling is not allowed in the self-test sandbox'); return (& $finish) }
        if (-not $r.label.Trim()) { $refusals.Add('no program name given'); return (& $finish) }
        $entries = @(Find-BvsUninstallEntry -Label $r.label)
        $distinct = @($entries | Where-Object { $_.UninstallString } | Sort-Object UninstallString -Unique)
        if ($entries.Count -eq 0) { $refusals.Add('this program is not in the installed-programs list any more'); return (& $finish) }
        if ($distinct.Count -eq 0) { $refusals.Add('the program has no uninstaller registered: use Settings > Apps'); return (& $finish) }
        if ($distinct.Count -gt 1) { $refusals.Add('several installed programs have this exact name: use Settings > Apps'); return (& $finish) }
        $e = $distinct[0]
        if ($e.SystemComponent -eq 1) { $refusals.Add('Windows marks this as a system component'); return (& $finish) }
        $r.uninstall = [ordered]@{ key = $e.Key; command = $e.UninstallString }
        $loc = if ($e.InstallLocation) { $e.InstallLocation.TrimEnd('\') } else { $r.path.TrimEnd('\') }
        if ($loc -and ($Images | Where-Object { Test-BvsUnder $_.Path $loc -Strict } | Select-Object -First 1)) {
            $warnings.Add('the program is running: close it before the uninstaller starts')
        }
        $warnings.Add('opens the program''s own uninstaller window: follow its steps (it may ask for administrator rights)')
        return (& $finish)
    }

    # --- files and folders ------------------------------------------------------------------
    $res = Resolve-BvsItemPath $r.path
    if ($res.Error) { $refusals.Add($res.Error); return (& $finish) }
    $full = $res.Path
    $r.path = $full
    foreach ($t in $Protected.Trees) { if (Test-BvsUnder $full $t.Path) { $refusals.Add("inside $($t.Why)") } elseif (Test-BvsUnder $t.Path $full -Strict) { $refusals.Add("contains $($t.Why)") } }
    foreach ($t in $Protected.Roots) { if (Test-BvsUnder $t.Path $full) { $refusals.Add($(if ($t.Path.Equals($full, [StringComparison]::OrdinalIgnoreCase)) { $t.Why } else { "contains $($t.Why -replace ' itself$', '')" })) } }
    if ($full -match '\\WindowsApps(\\|$)') { $refusals.Add('WindowsApps (Store apps)') }
    if ($full -match '\\\.ssh(\\|$)') { $refusals.Add('the SSH keys folder') }
    if (Test-BvsNeverRead $full) { $refusals.Add('a credential or key file (never-read list)') }
    if (-not (Test-BvsUnder $full $Ctx.AllowedArea -Strict)) {
        $refusals.Add($(if ($Ctx.Sandbox) { 'outside the self-test sandbox' } else { 'outside your user profile (%USERPROFILE%)' }))
    }
    if ($refusals.Count) { return (& $finish) }

    $isDir = [IO.Directory]::Exists($full)
    $isFile = -not $isDir -and [IO.File]::Exists($full)
    if (-not $isDir -and -not $isFile) { $refusals.Add('it no longer exists'); return (& $finish) }
    $r.kind = if ($isDir) { 'dir' } else { 'file' }
    $info = if ($isDir) { [IO.DirectoryInfo]::new($full) } else { [IO.FileInfo]::new($full) }
    if (([int]$info.Attributes -band 0x400) -ne 0) { $refusals.Add('it is a junction or symbolic link (reparse point)') }
    if (Test-BvsCloudOnly -Item $info) { $refusals.Add('it is a cloud-only placeholder (OneDrive): delete it in OneDrive instead') }
    $parent = [IO.Path]::GetDirectoryName($full)
    while ($parent -and $parent.Length -gt 3) {
        try { if (([int][IO.File]::GetAttributes($parent) -band 0x400) -ne 0) { $refusals.Add('the path goes through a junction or symbolic link'); break } } catch { break }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    if ($refusals.Count) { return (& $finish) }

    $repos = [Collections.Generic.List[string]]::new()
    if ($isFile) {
        $r.bytes = [long]$info.Length; $r.files = 1
    }
    else {
        $st = Get-BvsTreeStats -Path $full
        $r.bytes = [long]$st.bytes; $r.files = [int]$st.files
        if ($st.truncated) { $refusals.Add("more than $($script:MaxTreeEntries) entries: too large to verify safely, clean it in parts") }
        if ($st.cloud) { $refusals.Add("contains $($st.cloud) cloud-only OneDrive placeholder(s)") }
        if ($st.neverRead) { $refusals.Add("contains $($st.neverRead) credential or key file(s) (e.g. $($st.neverReadExample))") }
        if ($st.sshDirs) { $refusals.Add('contains an .ssh folder') }
        if ($st.links) { $warnings.Add("contains $($st.links) link(s) (junction/symlink): only the links move, never their targets") }
        if ($st.inaccessible) { $warnings.Add("$($st.inaccessible) subfolder(s) could not be read: size may be incomplete and removal may stop there") }
        foreach ($p in $st.repos) { if (-not $repos.Contains($p)) { $repos.Add($p) } }
    }

    $hit = $Images | Where-Object { $_.Path.Equals($full, [StringComparison]::OrdinalIgnoreCase) -or ($isDir -and (Test-BvsUnder $_.Path $full -Strict)) } | Select-Object -First 1
    if ($hit) { $refusals.Add("in use by the running program $($hit.Name) (PID $($hit.Pid)): close it first") }

    # git: repositories inside the item (whole repo at risk) and the repository around it (only this path)
    $enclosing = $null
    $up = [IO.Path]::GetDirectoryName($full)
    while ($up -and (Test-BvsUnder $up $Ctx.AllowedArea)) {
        if ([IO.Directory]::Exists((Join-Path $up '.git')) -or [IO.File]::Exists((Join-Path $up '.git'))) { $enclosing = $up; break }
        $up = [IO.Path]::GetDirectoryName($up)
    }
    if ($repos.Count -or $enclosing) {
        if (-not $Git) { $refusals.Add('git is not installed, so unsaved git work cannot be ruled out') }
        elseif ($repos.Count -gt 50) { $refusals.Add("contains $($repos.Count) git repositories: too many to verify, clean it in parts") }
        else {
            foreach ($repo in $repos) { foreach ($p in (Test-BvsGitWork -Git $Git -Repo $repo)) { $refusals.Add($p) } }
            if ($enclosing) { foreach ($p in (Test-BvsGitWork -Git $Git -Repo $enclosing -SubPath $full)) { $refusals.Add($p) } }
        }
    }

    if ($null -ne $requested -and $null -ne $r.bytes) {
        $diff = [Math]::Abs($r.bytes - $requested)
        if ($diff -gt [Math]::Max([double]1MB, [double](0.1 * $requested))) {
            $r.sizeChanged = $true
            $warnings.Add("size changed since the scan: was $(Format-BvsBytes $requested), now $(Format-BvsBytes $r.bytes)")
        }
    }
    foreach ($od in $Protected.OneDrive) { if (Test-BvsUnder $full $od -Strict) { $warnings.Add('inside OneDrive: the removal also syncs to your OneDrive cloud'); break } }
    & $finish
}

function Get-BvsRecycleCapacity {
    <#
    .SYNOPSIS Recycle Bin room on one drive for the current user: HKCU ...\BitBucket\Volume\{guid} MaxCapacity (MB)
              and NukeOnDelete, minus what the user's $Recycle.Bin\<SID> already holds. Read-only.
    #>
    param([Parameter(Mandatory)][string]$DriveRoot)
    $letter = $DriveRoot.Substring(0, 2).ToUpperInvariant()
    $out = [ordered]@{ drive = $letter; enabled = $true; maxBytes = $null; usedBytes = $null; freeBytes = [long]0; note = '' }
    $notes = [Collections.Generic.List[string]]::new()
    foreach ($pol in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') {
        if ((Get-ItemProperty -LiteralPath $pol -ErrorAction SilentlyContinue).NoRecycleFiles -eq 1) { $out.enabled = $false; $notes.Add('a policy switches the Recycle Bin off') }
    }
    $vol = Get-CimInstance Win32_Volume -Filter "DriveLetter='$letter'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $guid = if ($vol -and $vol.DeviceID -match '(\{[0-9A-Fa-f-]{36}\})') { $Matches[1] } else { $null }
    $props = if ($guid) { Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\$guid" -ErrorAction SilentlyContinue } else { $null }
    if ($props -and $props.NukeOnDelete -eq 1) { $out.enabled = $false; $notes.Add('the Recycle Bin is switched off on this drive (files would be deleted for good)') }
    $capacity = if ($vol -and $vol.Capacity) { [long]$vol.Capacity } else { try { [IO.DriveInfo]::new($letter).TotalSize } catch { 0 } }
    if ($props -and $null -ne $props.MaxCapacity) { $out.maxBytes = [long]$props.MaxCapacity * 1MB }
    else { $out.maxBytes = [long]($capacity * 0.05); $notes.Add('MaxCapacity not set: assuming the Windows default of about 5% of the drive') }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $bin = Join-Path $DriveRoot ('$Recycle.Bin\' + $sid)
    $out.usedBytes = if ([IO.Directory]::Exists($bin)) { [long](Get-BvsTreeStats -Path $bin).bytes } else { [long]0 }
    $out.freeBytes = [long][Math]::Max([long]0, [long]($out.maxBytes - $out.usedBytes))
    $out.note = $notes -join '; '
    $out
}

function Set-BvsDeleteMethods {
    <#
    .SYNOPSIS Decide recycle vs holding for every non-refused file item: an item goes to the Recycle Bin only while it
              fits into 90% of the free room on its drive; otherwise it is moved to holding\<id>\<n>\ on the same
              drive, or refused when holding is on another drive. Returns the capacity facts per drive.
    #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][AllowEmptyCollection()]$Results)
    $caps = [ordered]@{}
    $holdRoot = [IO.Path]::GetPathRoot($Ctx.HoldingRoot)
    foreach ($r in $Results) {
        if ($r.verdict -eq 'refused' -or $r.kind -notin 'file', 'dir') { continue }
        $drive = [IO.Path]::GetPathRoot($r.path)
        $sameDrive = $drive.Equals($holdRoot, [StringComparison]::OrdinalIgnoreCase)
        if ($r.method -eq 'recycle') {
            if (-not $caps.Contains($drive)) {
                $c = Get-BvsRecycleCapacity -DriveRoot $drive
                $c['remaining'] = [long]($c.freeBytes * 0.9)
                $caps[$drive] = $c
            }
            $c = $caps[$drive]
            if ($c.enabled -and $r.bytes -le $c.remaining) { $c.remaining -= $r.bytes; continue }
            $why = if ($c.enabled) { 'does not fit in the Recycle Bin' } else { 'the Recycle Bin is off on this drive' }
            if ($sameDrive) { $r.method = 'holding'; $r.reasons = @($r.reasons) + "$why`: it will be moved to the holding folder instead"; if ($r.verdict -eq 'ok') { $r.verdict = 'warn' } }
            else { $r.method = 'refused'; $r.verdict = 'refused'; $r.reasons = @("$why and the holding folder is on another drive") + @($r.reasons) }
        }
        elseif ($r.method -eq 'holding' -and -not $sameDrive) {
            $r.method = 'refused'; $r.verdict = 'refused'; $r.reasons = @('the holding folder is on another drive (moves stay on the same drive)') + @($r.reasons)
        }
    }
    @($caps.Values)
}

#endregion

#region ---------- delete table ----------

function Write-BvsDeleteTable {
    <# .SYNOPSIS Write {"tableHash":"<sha256 of the canonical table JSON>","table":<canonical table JSON>}. Returns the hash. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Table)
    $canon = ConvertTo-Json -InputObject $Table -Depth 10 -Compress
    $hash = Get-BvsSha256Hex $canon
    Write-BvsStateFile -Ctx $Ctx -Path (Join-Path $Ctx.Tables "$Id.json") -Text ('{"tableHash":"' + $hash + '","table":' + $canon + '}')
    $hash
}

function Read-BvsDeleteTable {
    <# .SYNOPSIS Read a table and re-hash its canonical JSON exactly as written. Returns {Table, Hash, Valid, Error}. #>
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$Id)
    $path = Join-Path $Ctx.Tables "$Id.json"
    if (-not [IO.File]::Exists($path)) { return [pscustomobject]@{ Valid = $false; Error = 'no final table: run validate-delete.ps1 first' } }
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $m = [regex]::Match($text, '^\{"tableHash":"([0-9a-f]{64})","table":(.*)\}$', 'Singleline')
    if (-not $m.Success) { return [pscustomobject]@{ Valid = $false; Error = 'the table file is not in the expected format' } }
    $stored = $m.Groups[1].Value
    $canon = $m.Groups[2].Value
    $actual = Get-BvsSha256Hex $canon
    $same = [Security.Cryptography.CryptographicOperations]::FixedTimeEquals([Text.Encoding]::ASCII.GetBytes($stored), [Text.Encoding]::ASCII.GetBytes($actual))
    if (-not $same) { return [pscustomobject]@{ Valid = $false; Error = 'the table was changed after it was shown (hash mismatch)' } }
    try { $table = $canon | ConvertFrom-Json -Depth 20 } catch { return [pscustomobject]@{ Valid = $false; Error = 'the table is not valid JSON' } }
    [pscustomobject]@{ Valid = $true; Error = $null; Table = $table; Hash = $stored }
}

#endregion

Export-ModuleMember -Function @(
    'Test-BvsUnder', 'Get-BvsSignalContext', 'Test-BvsSignalId', 'Get-BvsSignalStates', 'Get-BvsUtcStamp', 'Write-BvsStateFile',
    'Read-BvsJsonFile', 'ConvertTo-BvsCleanText', 'Set-BvsSignalStatus', 'Get-BvsSignalStatus', 'Read-BvsSignal', 'Get-BvsSignalAgeMinutes',
    'Get-BvsGuard', 'Set-BvsGuard', 'Format-BvsBytes', 'Format-BvsShortPath', 'Get-BvsSignalSummary', 'Get-BvsSha256Hex', 'Get-BvsCodeHash',
    'Get-BvsProtectedSet', 'Resolve-BvsItemPath', 'Get-BvsTreeStats', 'Get-BvsRunningImages', 'Get-BvsGitExe', 'Test-BvsGitWork',
    'Find-BvsUninstallEntry', 'Get-BvsUninstallCommand', 'Test-BvsDeleteItem', 'Get-BvsRecycleCapacity', 'Set-BvsDeleteMethods',
    'Write-BvsDeleteTable', 'Read-BvsDeleteTable'
)
