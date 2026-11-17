#Requires -Version 7.0
<#
.SYNOPSIS
    G2 duplicates: byte-identical files in your personal folders, and project/repo copies with their git risk.
.DESCRIPTION
    Read-only. Walks Documents, Desktop, Downloads, Pictures, Videos, Music and OneDrive (LOCAL files of 1 MB+;
    cloud-only placeholders are never opened; node_modules, .git, venvs and AppData are skipped).
    Duplicates: same size -> SHA-256 of first+last 64 KB -> full SHA-256 (Get-BvsHash). Every copy is 'review'.
    Project copies: candidates from G0 dirs.tsv (.git folders, .claude\worktrees, '- Copy'/'- kopie' folders,
    project folders directly under your personal folders), grouped by git remote, package name or copy name.
    git runs only as 'git --no-optional-locks' read commands (config --get, status, log, stash list, worktree list).
    Output: data\<scanId>\storage\G2.json (inventory keys duplicateGroups, projectCopies).
#>
[CmdletBinding()]
param([string]$ScanId, [long]$MinBytes = 1MB, [int]$TopGroups = 300)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = if ($ScanId) { Initialize-BvsRun -Module G2 -Area storage -ScanId $ScanId } else { Initialize-BvsRun -Module G2 -Area storage }
$S = @{ Dup = @(); Proj = @() }; $Cmp = [StringComparer]::OrdinalIgnoreCase
$self = $run.Root.TrimEnd('\')

function Get-DownloadsFolder {
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $v = (Get-ItemProperty -LiteralPath $k -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($v) { return [Environment]::ExpandEnvironmentVariables($v) }
    } catch { }
    Join-Path $env:USERPROFILE 'Downloads'
}
function ConvertTo-IsoZ([datetime]$D) { $D.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function ConvertFrom-Epoch($s) { $v = [long]$s; if ($v -le 0) { $null } else { [DateTimeOffset]::FromUnixTimeSeconds($v).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') } }
function Test-Link([IO.FileSystemInfo]$E) {
    if (-not ($E.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    try { [bool]$E.LinkTarget } catch { $true }   # junction/symlink: never follow; cloud placeholders have no LinkTarget
}
function Test-InSelf([string]$P) { $P -ieq $self -or $P.StartsWith($self + '\', 'OrdinalIgnoreCase') }

$named = [ordered]@{
    Documents = [Environment]::GetFolderPath('MyDocuments'); Desktop = [Environment]::GetFolderPath('Desktop'); Downloads = (Get-DownloadsFolder)
    Pictures = [Environment]::GetFolderPath('MyPictures'); Videos = [Environment]::GetFolderPath('MyVideos'); Music = [Environment]::GetFolderPath('MyMusic')
    OneDrive = $env:OneDrive; OneDriveCommercial = $env:OneDriveCommercial
}
$roots = [ordered]@{}
foreach ($k in $named.Keys) { $v = $named[$k]; if ($v -and (Test-Path -LiteralPath $v)) { $v = $v.TrimEnd('\'); if ($roots.Values -notcontains $v) { $roots[$k] = $v } } }
function Get-RootName([string]$P) {
    $best = $null
    foreach ($k in $roots.Keys) { if ($P.StartsWith($roots[$k] + '\', 'OrdinalIgnoreCase') -and (-not $best -or $roots[$k].Length -gt $roots[$best].Length)) { $best = $k } }
    $best
}
$skipNames = [Collections.Generic.HashSet[string]]::new([string[]]@('node_modules', '.git', '__pycache__', 'site-packages', '.venv', 'venv', '.tox',
        '.pnpm-store', '.next', '.nuxt', '.turbo', '.cache', 'AppData', '$RECYCLE.BIN', '.gradle', '.m2', '.cargo', '.rustup'), $Cmp)

function Get-HeadTailHash([IO.FileInfo]$F, $Sha) {
    if (Test-BvsNeverRead $F.FullName) { return $null }
    $fs = $null
    try {
        $fs = [IO.FileStream]::new($F.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        $n = [int][Math]::Min(65536, $fs.Length); $buf = [byte[]]::new(2 * $n)
        $got = $fs.Read($buf, 0, $n); [void]$fs.Seek(-$n, [IO.SeekOrigin]::End); $got += $fs.Read($buf, $n, $n)
        [Convert]::ToHexString($Sha.ComputeHash($buf, 0, $got))
    } catch { $null } finally { if ($fs) { $fs.Dispose() } }
}
function Get-PkgName([string]$Dir) {
    $pj = Join-Path $Dir 'package.json'
    if ((Test-Path -LiteralPath $pj -PathType Leaf) -and -not (Test-BvsNeverRead $pj) -and (Get-Item -LiteralPath $pj).Length -lt 1MB) {
        try { $n = (Get-Content -LiteralPath $pj -Raw | ConvertFrom-Json).name; if ($n -is [string] -and $n) { return $n } } catch { }
    }
    $pp = Join-Path $Dir 'pyproject.toml'
    if ((Test-Path -LiteralPath $pp -PathType Leaf) -and (Get-Item -LiteralPath $pp).Length -lt 1MB) {
        $m = Select-String -LiteralPath $pp -Pattern '^\s*name\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { return $m.Matches[0].Groups[1].Value }
    }
    $null
}
function Get-RemoteKey([string]$U) {
    # host/owner/repo, lower-case, credentials and scheme stripped (nothing secret is kept)
    ($U.Trim() -replace '^[a-z+]+://', '' -replace '^[^@/]+@', '' -replace ':(?!\d)', '/' -replace '\.git/?$', '' -replace '/+$', '').ToLowerInvariant()
}
function Get-GitRisk([string]$P) {
    $st = @(git --no-optional-locks -C $P status --porcelain 2>$null); $e1 = $LASTEXITCODE
    $lg = @(git --no-optional-locks -C $P log --branches --not --remotes --oneline 2>$null); $e2 = $LASTEXITCODE
    $sl = @(git --no-optional-locks -C $P stash list 2>$null); $e3 = $LASTEXITCODE
    if ($e1 -or $e2 -or $e3) { return $null }
    [ordered]@{ uncommitted = @($st | Where-Object { $_ }).Count; unpushed = @($lg | Where-Object { $_ }).Count; stashes = @($sl | Where-Object { $_ }).Count }
}
function Find-Root([hashtable]$M, [int]$I) { while ($M[$I] -ne $I) { $I = $M[$I] }; $I }

# ---------- 1. enumerate personal folders ----------
Invoke-BvsCheck -Run $run -Id 'G2.enumerate' -Description 'List local files of 1 MB+ in personal folders (cloud-only placeholders skipped, never opened)' -Script {
    $opt = [IO.EnumerationOptions]::new(); $opt.AttributesToSkip = [IO.FileAttributes]0; $opt.IgnoreInaccessible = $true; $opt.RecurseSubdirectories = $false
    $bySize = [Collections.Generic.Dictionary[long, Collections.Generic.List[IO.FileInfo]]]::new()
    $visited = [Collections.Generic.HashSet[string]]::new($Cmp); $st = @{ files = 0; dirs = 0; cloudSkipped = 0; cloudBytes = 0L; errors = 0 }
    foreach ($root in $roots.Values) {
        $stack = [Collections.Generic.Stack[string]]::new(); $stack.Push($root)
        while ($stack.Count) {
            $dir = $stack.Pop(); if (-not $visited.Add($dir)) { continue }; $st.dirs++
            try { $entries = @([IO.DirectoryInfo]::new($dir).EnumerateFileSystemInfos('*', $opt)) } catch { $st.errors++; continue }
            foreach ($e in $entries) {
                if ($e -is [IO.DirectoryInfo]) {
                    if ($skipNames.Contains($e.Name) -or $e.Name -like '*venv*' -or (Test-InSelf $e.FullName) -or (Test-Link $e)) { continue }
                    if ((Test-BvsCloudOnly $e) -or [IO.File]::Exists([IO.Path]::Combine($e.FullName, 'pyvenv.cfg'))) { continue }
                    $stack.Push($e.FullName)
                } elseif ($e.Length -ge $MinBytes) {
                    if (Test-BvsCloudOnly $e) { $st.cloudSkipped++; $st.cloudBytes += $e.Length; continue }
                    $st.files++
                    if (-not $bySize.ContainsKey($e.Length)) { $bySize[$e.Length] = [Collections.Generic.List[IO.FileInfo]]::new() }
                    $bySize[$e.Length].Add($e)
                }
            }
        }
    }
    $S.BySize = $bySize; $S.Enum = $st
    if ($st.errors) { Set-BvsCheckStatus -Id 'G2.enumerate' -Status partial -Reason "$($st.errors) folder(s) could not be listed" }
} | Out-Null

# ---------- 2. hash candidates ----------
Invoke-BvsCheck -Run $run -Id 'G2.hash' -Description 'Group by size, then head+tail 64 KB SHA-256, then full SHA-256' -Script {
    $sha = [Security.Cryptography.SHA256]::Create(); $groups = [Collections.Generic.List[object]]::new(); $st = @{ sizeGroups = 0; partial = 0; full = 0; unreadable = 0 }
    try {
        foreach ($kv in $S.BySize.GetEnumerator()) {
            if ($kv.Value.Count -lt 2) { continue }
            $st.sizeGroups++; $byPart = @{}
            foreach ($f in $kv.Value) {
                $h = Get-HeadTailHash $f $sha; if (-not $h) { $st.unreadable++; continue }
                $st.partial++; if (-not $byPart.ContainsKey($h)) { $byPart[$h] = [Collections.Generic.List[IO.FileInfo]]::new() }; $byPart[$h].Add($f)
            }
            foreach ($pl in $byPart.Values) {
                if ($pl.Count -lt 2) { continue }
                $byFull = @{}
                foreach ($f in $pl) {
                    $h = Get-BvsHash -Path $f.FullName -MaxBytes 64GB; if (-not $h) { $st.unreadable++; continue }
                    $st.full++; if (-not $byFull.ContainsKey($h)) { $byFull[$h] = [Collections.Generic.List[IO.FileInfo]]::new() }; $byFull[$h].Add($f)
                }
                foreach ($fl in $byFull.Values) { if ($fl.Count -ge 2) { $groups.Add([pscustomobject]@{ Size = $kv.Key; Files = $fl; Wasted = $kv.Key * ($fl.Count - 1) }) } }
            }
        }
    } finally { $sha.Dispose() }
    $S.Hash = $st; $S.GroupCount = $groups.Count; $tw = 0L; foreach ($g in $groups) { $tw += $g.Wasted }; $S.TotalWasted = $tw
    $n = 0
    $S.Dup = @(foreach ($g in ($groups | Sort-Object Wasted -Descending | Select-Object -First $TopGroups)) {
            $n++; $files = @($g.Files | Sort-Object LastWriteTimeUtc)
            $names = @($files | ForEach-Object { $_.Name } | Select-Object -Unique); $where = @($files | ForEach-Object { Get-RootName $_.FullName } | Select-Object -Unique)
            $flags = @(); if ($names.Count -gt 1) { $flags += 'different_names' }; if ($where.Count -gt 1) { $flags += 'cross_folder' }; if ($where -contains 'OneDrive') { $flags += 'onedrive_copy' }
            [ordered]@{ id = 'st-d{0:d5}' -f $n; path = $files[0].FullName; kind = 'file'; bytes = $g.Size * $files.Count; files = $files.Count
                newestUtc = ConvertTo-IsoZ $files[-1].LastWriteTimeUtc; oldestUtc = ConvertTo-IsoZ $files[0].LastWriteTimeUtc
                category = 'duplicate'; purpose = "{0} identical copies of '{1}' ({2:N1} MB each)" -f $files.Count, $files[0].Name, ($g.Size / 1MB)
                owner = 'you'; safety = 'review'; method = 'recycle'; reversible = $true; flags = $flags
                how = 'Byte-identical (same size, same head/tail and full SHA-256). The scanner never picks a copy: open them, keep the one in the right place, recycle the others.'
                sizeEach = $g.Size; wastedBytes = $g.Wasted
                copies = @(foreach ($f in $files) { [ordered]@{ path = $f.FullName; bytes = $f.Length; modifiedUtc = ConvertTo-IsoZ $f.LastWriteTimeUtc; folder = Get-RootName $f.FullName; safety = 'review'; method = 'recycle' } })
            }
        })
    if ($st.unreadable) { Set-BvsCheckStatus -Id 'G2.hash' -Status partial -Reason "$($st.unreadable) file(s) could not be read (locked or protected)" }
} | Out-Null

# ---------- 3. project copies ----------
Invoke-BvsCheck -Run $run -Id 'G2.projects' -Description 'Repo/project copies (same git remote, package name or copy name) with uncommitted, unpushed and stash counts' -Script {
    if (-not (Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue)) { Set-BvsCheckStatus -Id 'G2.projects' -Status skipped -Reason 'git is not installed'; return }
    $dirsTsv = Join-Path $run.ScanDir 'inventory\dirs.tsv'
    if (-not (Test-Path -LiteralPath $dirsTsv)) { Set-BvsCheckStatus -Id 'G2.projects' -Status skipped -Reason 'G0 dirs.tsv missing (run G0 first)'; return }
    $up = $env:USERPROFILE.TrimEnd('\'); $upL = $up.Length + 1
    $topSet = [Collections.Generic.HashSet[string]]::new($Cmp); [void]$topSet.Add($up)
    foreach ($v in $roots.Values) { [void]$topSet.Add($v) }
    foreach ($v in 'source\repos', 'repos', 'projects', 'dev', 'code', 'git', 'GitHub', 'src') { [void]$topSet.Add((Join-Path $up $v)) }
    $copyRx = [regex]::new(' - (copy|kopie)( \(\d+\))?$|-copy$', 'IgnoreCase')
    $stats = [Collections.Generic.Dictionary[string, long[]]]::new($Cmp); $cand = [Collections.Generic.HashSet[string]]::new($Cmp)
    foreach ($line in [IO.File]::ReadLines($dirsTsv)) {
        $c = $line.Split("`t"); if ($c.Count -lt 17) { continue }; $p = $c[3]
        if ($p.Length -le $upL -or -not $p.StartsWith($up + '\', 'OrdinalIgnoreCase')) { continue }
        if ($p[$upL] -eq [char]'.' -or $p.Contains('\node_modules\') -or $p.StartsWith("$up\AppData\", 'OrdinalIgnoreCase') -or (Test-InSelf $p)) { continue }
        $stats[$p] = [long[]]@($c[6], $c[7], $c[9], $c[10])
        $i = $p.LastIndexOf('\'); $leaf = $p.Substring($i + 1); $par = $p.Substring(0, $i)
        if ($leaf -eq '.git') { [void]$cand.Add($par) }
        elseif ($par.EndsWith('\.claude\worktrees', 'OrdinalIgnoreCase') -or $copyRx.IsMatch($leaf) -or $topSet.Contains($par)) { [void]$cand.Add($p) }
    }
    foreach ($p in @($cand)) {   # worktrees registered anywhere
        if (Test-Path -LiteralPath (Join-Path $p '.git\worktrees') -PathType Container) {
            foreach ($l in @(git --no-optional-locks -C $p worktree list --porcelain 2>$null)) {
                if ($l -like 'worktree *') { $w = $l.Substring(9).Replace('/', '\'); if ($w -ine $p -and (Test-Path -LiteralPath $w -PathType Container)) { [void]$cand.Add($w) } }
            }
        }
    }
    $bases = [Collections.Generic.HashSet[string]]::new($Cmp)
    foreach ($p in $cand) { $l = [IO.Path]::GetFileName($p); if ($copyRx.IsMatch($l)) { [void]$bases.Add($copyRx.Replace($l, '')) } }
    $stop = 'app', 'my-app', 'frontend', 'backend', 'web', 'client', 'server', 'api', 'project', 'test', 'demo', 'example', 'starter', 'root', 'workspace', 'monorepo'
    $info = [Collections.Generic.List[object]]::new()
    foreach ($p in $cand) {
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { continue }
        $gitP = Join-Path $p '.git'; $isRepo = Test-Path -LiteralPath $gitP; $isWt = $isRepo -and (Test-Path -LiteralPath $gitP -PathType Leaf)
        $leaf = [IO.Path]::GetFileName($p); $isCopy = $copyRx.IsMatch($leaf); $base = if ($isCopy) { $copyRx.Replace($leaf, '') } else { $leaf }
        $pkg = Get-PkgName $p
        if (-not ($isRepo -or $pkg -or $bases.Contains($base))) { continue }
        $remote = $null
        if ($isRepo) { $u = @(git --no-optional-locks -C $p config --get remote.origin.url 2>$null); if ($LASTEXITCODE -eq 0 -and $u.Count) { $remote = Get-RemoteKey $u[0] } }
        $keys = [Collections.Generic.List[string]]::new()
        if ($remote) { $keys.Add("remote:$remote") }
        if ($pkg -and $pkg.ToLowerInvariant() -notin $stop) { $keys.Add("package:$($pkg.ToLowerInvariant())") }
        if ($bases.Contains($base)) { $keys.Add("copy-name:$($base.ToLowerInvariant())") }
        $info.Add([pscustomobject]@{ Path = $p; Leaf = $leaf; Base = $base; IsRepo = $isRepo; IsWt = $isWt; Pkg = $pkg; Remote = $remote; MatchKeys = $keys })
    }
    $uf = @{}; for ($i = 0; $i -lt $info.Count; $i++) { $uf[$i] = $i }
    $owner = @{}
    for ($i = 0; $i -lt $info.Count; $i++) {
        foreach ($k in $info[$i].MatchKeys) {
            if ($owner.ContainsKey($k)) { $a = Find-Root $uf $owner[$k]; $b = Find-Root $uf $i; if ($a -ne $b) { $uf[$b] = $a } } else { $owner[$k] = $i }
        }
    }
    $groups = [ordered]@{}
    for ($i = 0; $i -lt $info.Count; $i++) { $r = "g$(Find-Root $uf $i)"; if (-not $groups.Contains($r)) { $groups[$r] = [Collections.Generic.List[object]]::new() }; $groups[$r].Add($info[$i]) }
    $out = [Collections.Generic.List[object]]::new(); $gi = 0; $n = 0
    foreach ($g in @($groups.Values | Where-Object { $_.Count -ge 2 })) {
        $gi++; $gid = 'pc-{0:d3}' -f $gi
        $label = @($g | Where-Object { $_.Pkg } | ForEach-Object { $_.Pkg })[0]
        if (-not $label) { $label = @($g | Where-Object { $_.Remote } | ForEach-Object { ($_.Remote -split '/')[-1] })[0] }
        if (-not $label) { $label = $g[0].Base }
        $why = (@($g | ForEach-Object { $_.MatchKeys } | Group-Object | Where-Object { $_.Count -ge 2 } | ForEach-Object { ($_.Name -split ':')[0] } | Select-Object -Unique) -join ', ')
        foreach ($m in $g) {
            $n++; $flags = [Collections.Generic.List[string]]::new(); $risk = $null
            if ($m.IsRepo) {
                $risk = Get-GitRisk $m.Path
                if (-not $risk) { $flags.Add('git_error') } elseif (($risk.uncommitted + $risk.unpushed + $risk.stashes) -gt 0) { $flags.Add('work_at_risk') }
            } else { $flags.Add('not_a_git_repo') }
            if ($m.IsWt) { $flags.Add('worktree'); $flags.Add('refs_shared_with_main_repo') }
            $st = $null; [void]$stats.TryGetValue($m.Path, [ref]$st); if (-not $st) { $flags.Add('size_unknown') }
            $how = if ($m.IsWt -and $flags.Contains('work_at_risk')) { "Has local-only work (see gitRisk): commit and push or merge it, then remove from the main repo with: git worktree remove `"$($m.Path)`"" }
            elseif ($m.IsWt) { "Nothing local-only found. Remove from the main repo with: git worktree remove `"$($m.Path)`" (history stays in the main repo)." }
            elseif (-not $m.IsRepo) { 'Not a git repo, so changes cannot be checked automatically: compare it with the other copies (e.g. WinMerge) before removing it.' }
            elseif ($flags.Contains('git_error')) { 'git could not read this repo (ownership or damage?): check it by hand before removing it.' }
            elseif ($flags.Contains('work_at_risk')) { 'Has local-only work (see gitRisk): commit and push it, or copy the changed files into the copy you keep, before removing this folder.' }
            else { 'Everything is committed and pushed. Compare with the other copies, then move this one to a holding folder or recycle it.' }
            $cat = if (-not $m.IsWt) { 'project-copy' } elseif ($m.Path -match '\\\.claude\\worktrees\\') { 'agent-worktree' } else { 'git-worktree' }
            $out.Add([ordered]@{ id = 'st-p{0:d5}' -f $n; group = $gid; groupSize = $g.Count; path = $m.Path; kind = 'dir'
                    bytes = $(if ($st) { $st[0] } else { 0 }); files = $(if ($st) { $st[1] } else { 0 })
                    newestUtc = $(if ($st) { ConvertFrom-Epoch $st[2] }); oldestUtc = $(if ($st) { ConvertFrom-Epoch $st[3] })
                    category = $cat; purpose = "One of $($g.Count) copies of project '$label' (matched by $why)."; owner = 'you'
                    safety = 'review'; method = $(if ($m.IsWt) { 'tool' } else { 'holding' }); how = $how; reversible = -not $m.IsWt
                    flags = @($flags); gitRisk = $risk; remote = $m.Remote; packageName = $m.Pkg
                })
        }
    }
    $S.Proj = @($out); $S.ProjGroups = $gi
} | Out-Null

Add-BvsInventory -Run $run -Name 'duplicateGroups' -Data @($S.Dup)
Add-BvsInventory -Run $run -Name 'projectCopies' -Data @($S.Proj)
Complete-BvsRun -Run $run | Out-Null

$e = $S.Enum; $listedWaste = 0L; foreach ($g in $S.Dup) { $listedWaste += $g.wastedBytes }
'G2 done. Local files >= 1 MB: {0} in {1} folders; cloud-only skipped: {2} ({3:N0} MB)' -f $e.files, $e.dirs, $e.cloudSkipped, ($e.cloudBytes / 1MB)
'Duplicate groups: {0} (listed {1}); wasted {2:N2} GB total, {3:N2} GB in listed groups' -f $S.GroupCount, @($S.Dup).Count, ($S.TotalWasted / 1GB), ($listedWaste / 1GB)
'Project copies: {0} folders in {1} groups; work_at_risk: {2}' -f @($S.Proj).Count, $S.ProjGroups, @($S.Proj | Where-Object { $_.flags -contains 'work_at_risk' }).Count
foreach ($p in @($S.Proj | Select-Object -First 20)) {
    $r = $p.gitRisk; '  {0} {1,-34} {2,7:N0} MB  unc={3} unp={4} st={5} {6}' -f $p.group, ([IO.Path]::GetFileName($p.path)), ($p.bytes / 1MB), $r.uncommitted, $r.unpushed, $r.stashes, ($p.flags -join ',')
}
