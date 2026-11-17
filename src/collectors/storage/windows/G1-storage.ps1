#Requires -Version 7.0
<#
.SYNOPSIS
    G1 storage map: junk/cache/leftover items, big files, old folders and a reclaimable-space summary.
.DESCRIPTION
    Read-only. Works from the G0 inventory (dirs.tsv, files.tsv, inventory-meta.json) and the editable
    rules in src\config\category-rules.json. The only live file-system access is: aging the files in %TEMP%,
    a few Test-Path checks (venv / project markers) and the node.exe version for the shadowed-install rule.
    Output: data\<scanId>\storage\G1.json (inventory keys junkItems, bigFiles, oldFolders, storageSummary).
#>
[CmdletBinding()]
param([string]$ScanId)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = if ($ScanId) { Initialize-BvsRun -Module G1 -Area storage -ScanId $ScanId } else { Initialize-BvsRun -Module G1 -Area storage }
$S = @{}   # state shared between checks

# ---------- path tokens (no hard-coded user paths) ----------
function Get-DownloadsFolder {
    try {
        $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $v = (Get-ItemProperty -LiteralPath $k -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($v) { return [Environment]::ExpandEnvironmentVariables($v) }
    } catch { }
    Join-Path $env:USERPROFILE 'Downloads'
}
$tmp = [IO.Path]::GetTempPath(); if ($tmp -match '~') { $tmp = Join-Path $env:LOCALAPPDATA 'Temp' }
$nvm = if ($env:NVM_HOME) { $env:NVM_HOME } else { [Environment]::GetEnvironmentVariable('NVM_HOME', 'User') }
$Tok = [ordered]@{
    '%USERPROFILE%' = $env:USERPROFILE; '%LOCALAPPDATA%' = $env:LOCALAPPDATA; '%APPDATA%' = $env:APPDATA
    '%ProgramData%' = $env:ProgramData; '%ProgramFiles%' = $env:ProgramFiles; '%ProgramFiles(x86)%' = ${env:ProgramFiles(x86)}
    '%SystemRoot%' = $env:SystemRoot; '%SystemDrive%' = $env:SystemDrive; '%TEMP%' = $tmp; '%NVM_HOME%' = $nvm
    '%DOCUMENTS%' = [Environment]::GetFolderPath('MyDocuments'); '%DESKTOP%' = [Environment]::GetFolderPath('Desktop')
    '%PICTURES%' = [Environment]::GetFolderPath('MyPictures'); '%VIDEOS%' = [Environment]::GetFolderPath('MyVideos')
    '%MUSIC%' = [Environment]::GetFolderPath('MyMusic'); '%DOWNLOADS%' = (Get-DownloadsFolder); '%ONEDRIVE%' = $env:OneDrive
}
function Expand-Tok([string]$s) {
    foreach ($k in $Tok.Keys) {
        if ($s.Contains($k)) { $v = $Tok[$k]; if ([string]::IsNullOrWhiteSpace($v)) { return $null }; $s = $s.Replace($k, $v.TrimEnd('\')) }
    }
    $s
}
$RxOpt = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
function ConvertTo-GlobRx([string]$Glob) {
    # '*' = part of one folder name, '**' = any number of folders
    $e = Expand-Tok $Glob; if (-not $e) { return $null }
    $r = [regex]::Escape($e).Replace('\\\*\*\\', '\\(?:.*\\)?').Replace('\*\*', '.*').Replace('\*', '[^\\]*')
    [pscustomobject]@{ Path = $e; Rx = [regex]::new("^$r$", $RxOpt) }
}
function Get-Rxs($Globs) { @(foreach ($g in @($Globs)) { if ($g) { $x = ConvertTo-GlobRx $g; if ($x) { $x.Rx } } }) }
function Test-AnyRx($Rxs, [string]$P) { foreach ($x in $Rxs) { if ($x.IsMatch($P)) { return $true } }; $false }
function Get-PathSet($List) {
    $h = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in @($List)) { $e = Expand-Tok $g; if ($e) { [void]$h.Add($e.TrimEnd('\')) } }
    , $h
}
function Test-Under([string]$P, $Set) {
    $a = $P.TrimEnd('\')
    while ($a) { if ($Set.Contains($a)) { return $true }; $k = $a.LastIndexOf('\'); if ($k -lt 0) { break }; $a = $a.Substring(0, $k) }
    $false
}
function Find-Ancestor([string]$P, [hashtable]$Map) {
    $a = $P
    while (($k = $a.LastIndexOf('\')) -gt 0) { $a = $a.Substring(0, $k); if ($Map.ContainsKey($a)) { return $Map[$a] } }
    $null
}
function ConvertFrom-Epoch($s) { $v = [long]$s; if ($v -le 0) { $null } else { [DateTimeOffset]::FromUnixTimeSeconds($v).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') } }
function ConvertFrom-Iso([string]$s) { [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') }
function Get-OwnerGuess([string]$P) {
    foreach ($b in $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData) {
        if ($b -and $P.StartsWith($b + '\', 'OrdinalIgnoreCase')) { return ($P.Substring($b.Length + 1) -split '\\')[0] }
    }
    if ($P.StartsWith($env:USERPROFILE + '\', 'OrdinalIgnoreCase')) { return 'you' }
    'unknown'
}
function ConvertTo-StItem([string]$Path, [string]$Kind, [long]$Bytes, [long]$Files, $Newest, $Oldest, $R, $Flags, [hashtable]$Extra) {
    $o = [ordered]@{ id = $null; path = $Path; kind = $Kind; bytes = $Bytes; files = $Files; newestUtc = $Newest; oldestUtc = $Oldest
        category = $R.category; purpose = $R.purpose; owner = $R.owner; safety = $R.safety; method = $R.method; how = $R.how
        reversible = [bool]$R.reversible; flags = @($Flags | Where-Object { $_ })
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    $o
}

function Use-FileRow([string[]]$C) {
    # First matching file rule wins for one files.tsv-style row. Uses $frs/$groups/$cand/$big/$d of the calling check.
    $size = [long]$C[1]
    if ($size -ge $bigMin -and $C[7] -ne 'probe') { $big.Add($C) }
    foreach ($f in $frs) {
        $r = $f.R; $pat = $null
        if ($r.reason) { if ($C[7] -ne $r.reason) { continue } }
        else { foreach ($x in $f.Pats) { if ($x.Rx.IsMatch($C[0])) { $pat = $x.Path; break } }; if (-not $pat) { continue } }
        if ($f.Ext.Count -and $C[6] -notin $f.Ext) { continue }
        $mod = ConvertFrom-Iso $C[4]; $cre = ConvertFrom-Iso $C[3]
        if ($r.olderThanDays) { $t = if ($cre -gt $mod) { $cre } else { $mod }; if ($t -gt $S.Ref.AddDays(-[int]$r.olderThanDays)) { return } }
        if ($r.group) {
            if (-not $groups.Contains($pat)) { $groups[$pat] = @{ R = $r; Bytes = 0L; Files = 0L; New = $mod; Old = $mod; Members = [Collections.Generic.List[string]]::new() } }
            $g = $groups[$pat]; $g.Bytes += $size; $g.Files++; $g.Members.Add($C[0])
            if ($mod -gt $g.New) { $g.New = $mod }; if ($mod -lt $g.Old) { $g.Old = $mod }
        } elseif ($size -ge [long]$d.minBytes) {
            $cand.Add((ConvertTo-StItem $C[0] 'file' $size 1 ($mod.ToString('yyyy-MM-ddTHH:mm:ssZ')) ($cre.ToString('yyyy-MM-ddTHH:mm:ssZ')) $r @() $null))
        }
        return
    }
}

# ---------- 1. inputs ----------
Invoke-BvsCheck -Run $run -Id 'G1.inputs' -Description 'Load G0 inventory and src\config\category-rules.json' -Script {
    $inv = Join-Path $run.ScanDir 'inventory'
    foreach ($f in 'dirs.tsv', 'files.tsv', 'inventory-meta.json') { if (-not (Test-Path -LiteralPath (Join-Path $inv $f))) { throw "G0 inventory file missing: $f (run G0 first)" } }
    $S.Inv = $inv
    $S.Meta = Get-Content -LiteralPath (Join-Path $inv 'inventory-meta.json') -Raw | ConvertFrom-Json
    $S.Cfg = Get-Content -LiteralPath (Join-Path $run.Root 'src\config\category-rules.json') -Raw | ConvertFrom-Json
    $ref = $S.Meta.referenceUtc; if ($ref -isnot [datetime]) { $ref = ConvertFrom-Iso $ref }
    $S.Ref = $ref.ToUniversalTime(); $S.RefEpoch = [DateTimeOffset]::new($S.Ref).ToUnixTimeSeconds()
} | Out-Null
if (-not $S.Cfg -or -not $S.Meta) { Complete-BvsRun -Run $run | Out-Null; Write-Output 'G1: inputs missing, see G1.json checks'; exit 1 }

# ---------- 2. one streaming pass over dirs.tsv ----------
Invoke-BvsCheck -Run $run -Id 'G1.dirscan' -Description 'Match every G0 folder against the category rules; collect cold-folder candidates' -Script {
    $cfg = $S.Cfg; $leafIdx = @{}; $parIdx = @{}; $sets = @{}; $order = 0; $skipped = 0
    foreach ($p in $cfg.excludeSets.PSObject.Properties) { $sets[$p.Name] = Get-Rxs $p.Value }
    foreach ($r in $cfg.dirRules) {
        $ex = @(); if ($r.excludeSet) { $ex += $sets[$r.excludeSet] }; if ($r.exclude) { $ex += Get-Rxs $r.exclude }
        foreach ($m in @($r.match)) {
            $g = ConvertTo-GlobRx $m; if (-not $g) { $skipped++; continue }   # token not present on this PC
            $i = $g.Path.LastIndexOf('\'); $leaf = $g.Path.Substring($i + 1); $par = $g.Path.Substring(0, $i)
            if ($leaf -notmatch '\*') { $idx = $leafIdx; $key = $leaf } elseif ($par -notmatch '\*') { $idx = $parIdx; $key = $par } else { $skipped++; continue }
            if (-not $idx.ContainsKey($key)) { $idx[$key] = [Collections.Generic.List[object]]::new() }
            $idx[$key].Add([pscustomobject]@{ Order = $order++; R = $r; Rx = $g.Rx; Ex = $ex })
        }
    }
    $newest = [Collections.Generic.Dictionary[int, long]]::new(600000)
    $hits = [Collections.Generic.List[object]]::new(); $cold = [Collections.Generic.List[object]]::new()
    $minOld = [long]$cfg.defaults.oldFolderMinBytes; $share = [double]$cfg.defaults.oldFolderColdShare; $rows = 0
    $rd = [IO.StreamReader]::new((Join-Path $S.Inv 'dirs.tsv'))
    try {
        [void]$rd.ReadLine()
        while ($null -ne ($line = $rd.ReadLine())) {
            $rows++; $c = $line.Split("`t")
            $newest[[int]$c[0]] = [long]$c[9]
            $p = $c[3]; $i = $p.LastIndexOf('\'); $hit = $null
            $list = $leafIdx[$p.Substring($i + 1)]
            if ($list) { foreach ($e in $list) { if ($e.Rx.IsMatch($p) -and -not (Test-AnyRx $e.Ex $p)) { $hit = $e; break } } }
            if (-not $hit) {
                $list = $parIdx[$p.Substring(0, $i)]
                if ($list) { foreach ($e in $list) { if ($e.Rx.IsMatch($p) -and -not (Test-AnyRx $e.Ex $p)) { $hit = $e; break } } }
            }
            if ($hit) { $hits.Add([pscustomobject]@{ E = $hit; C = $c }) }
            $tb = [long]$c[6]
            if ($tb -ge $minOld -and [long]$c[12] -ge $share * $tb) { $cold.Add($c) }
        }
    } finally { $rd.Dispose() }
    $S.Newest = $newest; $S.Hits = $hits; $S.Cold = $cold
    if ($skipped) { Set-BvsCheckStatus -Id 'G1.dirscan' -Status partial -Reason "$skipped rule pattern(s) not applicable on this PC (missing folder token)" }
} | Out-Null

# ---------- 3. junk items (dir rules + file rules, outermost wins) ----------
Invoke-BvsCheck -Run $run -Id 'G1.junk' -Description 'Build junk/cache/leftover items; nothing is counted twice' -Script {
    $cfg = $S.Cfg; $d = $cfg.defaults; $cand = [Collections.Generic.List[object]]::new()
    $userRoots = Get-PathSet $cfg.userRoots
    $S.NvmActive = $null
    $sym = if ($env:NVM_SYMLINK) { $env:NVM_SYMLINK } else { [Environment]::GetEnvironmentVariable('NVM_SYMLINK', 'User') }
    if ($sym) { try { $li = Get-Item -LiteralPath $sym -Force -ErrorAction Stop; if ($li.Target) { $S.NvmActive = ([string]@($li.Target)[0]).TrimEnd('\') } } catch { } }
    foreach ($h in $S.Hits) {
        $r = $h.E.R; $c = $h.C; $p = $c[3]; $bytes = [long]$c[6]; $files = [long]$c[7]
        $flags = [Collections.Generic.List[string]]::new(); $extra = @{}
        $inacc = $c[16] -match 'inaccessible'
        if ($c[16] -match 'hardlink-heavy') { $flags.Add('hardlinks_overcount') }
        if ($inacc) { $flags.Add('partly_inaccessible') }
        if ([long]$c[14] -gt 0) { $flags.Add('has_cloud_only_files') }
        $min = if ($null -ne $r.minBytes) { [long]$r.minBytes } else { [long]$d.minBytes }
        if ($bytes -lt $min -and -not $inacc -and -not $r.special) { continue }
        if ($r.idleDays) {
            $lim = $S.RefEpoch - [long]$r.idleDays * 86400; $par = $p.Substring(0, $p.LastIndexOf('\'))
            if ($userRoots.Contains($par)) { if ([long]$c[9] -gt $lim) { $flags.Add('recently_used') } }   # standalone item
            else {
                $pn = [long]0
                if (-not $S.Newest.TryGetValue([int]$c[1], [ref]$pn) -or $pn -gt $lim) { continue }
                $flags.Add("project_idle_$($r.idleDays)d")
            }
        }
        if ($r.requireChild -and -not (@($r.requireChild) | Where-Object { Test-Path -LiteralPath (Join-Path $p $_) })) { continue }
        if ($r.requireSibling) {
            $par = [IO.Path]::GetDirectoryName($p)
            if (-not (@($r.requireSibling) | Where-Object { Test-Path -LiteralPath (Join-Path $par $_) })) { continue }
        }
        $nw = ConvertFrom-Epoch $c[9]; $ol = ConvertFrom-Epoch $c[10]
        if ($r.special -eq 'temp-age') {
            $lim = $S.Ref.AddDays(-[int]$d.tempAgeDays); $bytes = 0L; $files = 0L; $tn = $null; $to = $null
            foreach ($f in (Get-BvsFiles -Path $p -NoPrune)) {
                $w = $f.LastWriteTimeUtc
                if ($w -lt $lim) { $bytes += $f.Length; $files++; if (-not $tn -or $w -gt $tn) { $tn = $w }; if (-not $to -or $w -lt $to) { $to = $w } }
            }
            if ($bytes -lt $min) { continue }
            $nw = if ($tn) { $tn.ToString('yyyy-MM-ddTHH:mm:ssZ') }; $ol = if ($to) { $to.ToString('yyyy-MM-ddTHH:mm:ssZ') }
            $extra.folderTotalBytes = [long]$c[6]; $flags.Add("only_files_older_than_$($d.tempAgeDays)d")
        } elseif ($r.special -eq 'nvm-inactive') {
            if ($p -notmatch '\\v\d+\.\d+\.\d+$') { continue }
            if ($S.NvmActive -and $p.TrimEnd('\') -ieq $S.NvmActive) { continue }
            if (-not $S.NvmActive) { $flags.Add('active_version_unknown') }
            $extra.how = $r.how.Replace('{version}', $p.Substring($p.LastIndexOf('\') + 2))
        } elseif ($r.special -eq 'node-shadowed') {
            $exe = Join-Path $p 'node.exe'
            if (-not (Test-Path -LiteralPath $exe) -or (Get-Item -LiteralPath $p -Force).LinkType) { continue }
            $first = @(Get-Command node.exe -CommandType Application -All -ErrorAction SilentlyContinue)[0]
            if (-not $first -or $first.Source.StartsWith($p + '\', 'OrdinalIgnoreCase')) { continue }
            $ver = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
            $extra.purpose = $r.purpose.Replace('{version}', "$ver"); $extra.activeNode = $first.Source; $flags.Add('shadowed_on_path')
        }
        $cand.Add((ConvertTo-StItem $p 'dir' $bytes $files $nw $ol $r $flags $extra))
    }
    # file rules over files.tsv rows (large / root-of-user-folder / partial-download); also keep big-file rows
    $frs = foreach ($fr in $cfg.fileRules) {
        $pats = @(foreach ($m in @($fr.match)) { if ($m) { ConvertTo-GlobRx $m } })
        [pscustomobject]@{ R = $fr; Pats = $pats; Ext = $(if ($fr.ext) { @($fr.ext) } else { @() }) }
    }
    $groups = [ordered]@{}; $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $big = [Collections.Generic.List[object]]::new(); $bigMin = [long]$d.bigFileMinBytes
    $rd = [IO.StreamReader]::new((Join-Path $S.Inv 'files.tsv'))
    try {
        [void]$rd.ReadLine()
        while ($null -ne ($line = $rd.ReadLine())) {
            $c = $line.Split("`t")
            if ($c[7] -notin 'large', 'root-of-user-folder', 'partial-download') { continue }
            if ($seen.Add($c[0])) { Use-FileRow $c }
        }
    } finally { $rd.Dispose() }
    # rules with probe=true: list that one folder live (small files G0 does not record, e.g. ~\.claude.json.tmp.*)
    foreach ($f in $frs) {
        if (-not $f.R.probe) { continue }
        foreach ($x in $f.Pats) {
            $dir = [IO.Path]::GetDirectoryName($x.Path); if (-not [IO.Directory]::Exists($dir)) { continue }
            foreach ($fi in [IO.DirectoryInfo]::new($dir).EnumerateFiles([IO.Path]::GetFileName($x.Path))) {
                if (-not $seen.Add($fi.FullName)) { continue }
                Use-FileRow ([string[]]@($fi.FullName, $fi.Length, $fi.Length, $fi.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'),
                        $fi.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'), ('0x{0:x}' -f [int]$fi.Attributes), $fi.Extension, 'probe'))
            }
        }
    }
    foreach ($k in $groups.Keys) {
        $g = $groups[$k]
        $cand.Add((ConvertTo-StItem $k 'file' $g.Bytes $g.Files ($g.New.ToString('yyyy-MM-ddTHH:mm:ssZ')) ($g.Old.ToString('yyyy-MM-ddTHH:mm:ssZ')) $g.R @('grouped') @{ members = @($g.Members | Select-Object -First 25) }))
    }
    $S.Big = $big
    # outermost match wins
    $claimed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $kept = [Collections.Generic.List[object]]::new()
    foreach ($it in ($cand | Sort-Object { $_.path.Length })) {
        $a = $it.path; $under = $false
        while (($k = $a.LastIndexOf('\')) -gt 0) { $a = $a.Substring(0, $k); if ($claimed.Contains($a)) { $under = $true; break } }
        if (-not $under) { [void]$claimed.Add($it.path); $kept.Add($it) }
    }
    $all = @($kept | Sort-Object { $_.bytes } -Descending); $n = 0
    foreach ($it in $all) { $n++; $it.id = 'st-j{0:d5}' -f $n }
    $S.JunkAll = $all; $S.Junk = @($all | Select-Object -First ([int]$d.maxJunkItems))
    if ($all.Count -gt $S.Junk.Count) { Set-BvsCheckStatus -Id 'G1.junk' -Status partial -Reason "listed top $($S.Junk.Count) of $($all.Count) items; summary counts all" }
} | Out-Null

# ---------- 4. big files ----------
Invoke-BvsCheck -Run $run -Id 'G1.bigfiles' -Description 'Top files of 100 MB or more (G0 large rows) with a category guess' -Script {
    $cfg = $S.Cfg; $d = $cfg.defaults
    $junkDirs = @{}; $junkFiles = @{}
    foreach ($j in $S.JunkAll) { if ($j.kind -eq 'dir') { $junkDirs[$j.path] = $j } else { $junkFiles[$j.path] = $j } }
    $extMap = @{}; foreach ($p in $cfg.extGuess.PSObject.Properties) { foreach ($e in $p.Value.ext) { $extMap[$e] = $p } }
    $def = $cfg.extGuessDefault; $n = 0
    $S.BigItems = @(foreach ($c in ($S.Big | Sort-Object { [long]$_[1] } -Descending | Select-Object -First ([int]$d.bigFileTop))) {
            $p = $c[0]; $n++; $flags = [Collections.Generic.List[string]]::new(); $extra = @{}
            $attr = [Convert]::ToInt64($c[5].Replace('0x', ''), 16)
            if (($attr -band 0x400000) -or ($attr -band 0x40000) -or ($attr -band 0x1000)) { $flags.Add('cloud_only') }
            $j = $junkFiles[$p]; if (-not $j) { $j = Find-Ancestor $p $junkDirs }
            if ($j) { $r = $j; $extra.junkItemId = $j.id }
            else {
                $m = $extMap[$c[6]]; $g = if ($m) { $m.Value } else { $def }
                $r = [pscustomobject]@{ category = $(if ($m) { $m.Name } else { 'large-file' }); owner = (Get-OwnerGuess $p)
                    purpose = '{0} in {1}' -f ($g.purpose ?? $def.purpose), [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($p))
                    safety = $g.safety ?? $def.safety; method = $g.method ?? $def.method; how = $g.how ?? $def.how; reversible = $true
                }
            }
            $it = ConvertTo-StItem $p 'file' ([long]$c[1]) 1 $c[4] $c[3] $r $flags $extra
            $it.id = 'st-b{0:d5}' -f $n; $it
        })
} | Out-Null

# ---------- 5. old folders ----------
Invoke-BvsCheck -Run $run -Id 'G1.oldfolders' -Description 'Folders of 200 MB+ where 80%+ of bytes are older than 2 years (outermost only)' -Script {
    $cfg = $S.Cfg; $d = $cfg.defaults
    $roots = Get-PathSet $cfg.userRoots; $excl = Get-PathSet $cfg.oldFolderExclude; $pers = Get-PathSet $cfg.personalRoots
    $junkDirs = @{}; foreach ($j in $S.JunkAll) { if ($j.kind -eq 'dir') { $junkDirs[$j.path] = $j } }
    $persR = [pscustomobject]@{ category = 'personal-data'; owner = 'you'; purpose = 'Your own files, not changed in 2+ years.'; safety = 'review'; method = 'holding'; reversible = $true
        how = 'Personal data: keep it, or archive it to an external drive/cloud and verify the copy before removing it here.' }
    $claimed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $kept = [Collections.Generic.List[object]]::new()
    foreach ($c in ($S.Cold | Sort-Object { $_[3].Length })) {
        $p = $c[3].TrimEnd('\'); if ($roots.Contains($p) -or (Test-Under $p $excl)) { continue }
        $a = $p; $under = $false
        while (($k = $a.LastIndexOf('\')) -gt 0) { $a = $a.Substring(0, $k); if ($claimed.Contains($a)) { $under = $true; break } }
        if (-not $under) { [void]$claimed.Add($p); $kept.Add($c) }
    }
    $n = 0
    $S.OldItems = @(foreach ($c in ($kept | Sort-Object { [long]$_[12] } -Descending | Select-Object -First ([int]$d.oldFolderTop))) {
            $p = $c[3]; $n++; $isPers = Test-Under $p $pers; $extra = @{ coldBytes = [long]$c[12]; coldShare = [math]::Round([long]$c[12] / [math]::Max(1, [long]$c[6]), 3) }
            $j = $junkDirs[$p]; if (-not $j) { $j = Find-Ancestor $p $junkDirs }
            if ($j) { $r = $j; $extra.junkItemId = $j.id }
            elseif ($isPers) { $r = $persR }
            else {
                $r = [pscustomobject]@{ category = 'cold-data'; owner = (Get-OwnerGuess $p); purpose = 'Folder where 80%+ of the data has not changed in 2+ years (may belong to an app you no longer use).'
                    safety = 'review'; method = 'holding'; reversible = $true; how = 'Open it and decide: keep, archive to external storage, or recycle. If it belongs to an installed app, uninstall or clean it from that app instead.' }
            }
            if ($isPers) { $extra.safety = 'review'; $extra.personal = $true }
            $it = ConvertTo-StItem $p 'dir' ([long]$c[6]) ([long]$c[7]) (ConvertFrom-Epoch $c[9]) (ConvertFrom-Epoch $c[10]) $r @() $extra
            $it.id = 'st-o{0:d5}' -f $n; $it
        })
} | Out-Null

# ---------- 6. summary ----------
Invoke-BvsCheck -Run $run -Id 'G1.summary' -Description 'Reclaimable bytes per safety level, cloud-only and unaccounted space' -Script {
    $t = $S.Meta.totals; $vol = @($S.Meta.volumes)[0]
    $by = [ordered]@{}; foreach ($lvl in 'safe', 'safe_after_check', 'use_tool', 'review', 'do_not_touch') { $by[$lvl] = [ordered]@{ bytes = 0L; items = 0 } }
    foreach ($j in $S.JunkAll) { $b = $by[$j.safety]; if ($b) { $b.bytes += $j.bytes; $b.items++ } }
    $cats = @($S.JunkAll | Group-Object { $_.category } | ForEach-Object {
            $sum = 0L; foreach ($x in $_.Group) { $sum += $x.bytes }
            [ordered]@{ category = $_.Name; bytes = $sum; items = $_.Count; safety = @($_.Group | ForEach-Object { $_.safety } | Select-Object -Unique) }
        } | Sort-Object { $_.bytes } -Descending)
    $bigB = 0L; foreach ($x in $S.BigItems) { $bigB += $x.bytes }
    $oldB = 0L; $oldC = 0L; foreach ($x in $S.OldItems) { $oldB += $x.bytes; $oldC += $x.coldBytes }
    $S.Summary = [ordered]@{
        volume           = [ordered]@{ root = $vol.name; sizeBytes = $vol.sizeBytes; freeBytes = $vol.freeBytes; usedBytes = $vol.usedBytes }
        scannedBytes     = $t.scannedBytes
        reclaimableBytes = $by.safe.bytes + $by.safe_after_check.bytes + $by.use_tool.bytes
        bySafety         = $by
        topCategories    = $cats
        cloudOnly        = [ordered]@{ bytes = $t.cloudOnlyBytes; files = $t.cloudOnlyFiles; note = 'Files that live only in the cloud (OneDrive placeholders); they use no local space.' }
        unaccounted      = [ordered]@{ bytes = $t.unaccountedBytes; note = "Used space the scan could not attribute: System Volume Information (restore points), NTFS metadata and $($t.inaccessibleDirs) access-denied folders. Restore points: System Properties > System Protection > Configure." }
        junkItems        = [ordered]@{ listed = @($S.Junk).Count; total = @($S.JunkAll).Count }
        bigFiles         = [ordered]@{ count = @($S.BigItems).Count; bytes = $bigB }
        oldFolders       = [ordered]@{ count = @($S.OldItems).Count; bytes = $oldB; coldBytes = $oldC }
        notes            = @('reclaimableBytes = safe + safe_after_check + use_tool junk items. review items need your decision; do_not_touch is listed only to explain where space goes.',
            'Sizes are logical bytes from G0. Hard-linked stores (WinSxS, pnpm) overstate real savings.', 'bigFiles and oldFolders overlap junkItems (see junkItemId); only junkItems are summed above.')
    }
} | Out-Null

Add-BvsInventory -Run $run -Name 'junkItems' -Data @($S.Junk)
Add-BvsInventory -Run $run -Name 'bigFiles' -Data @($S.BigItems)
Add-BvsInventory -Run $run -Name 'oldFolders' -Data @($S.OldItems)
Add-BvsInventory -Run $run -Name 'storageSummary' -Data $S.Summary
Complete-BvsRun -Run $run | Out-Null

$sm = $S.Summary
if ($sm) {
    'G1 done. Reclaimable {0:N1} GB; junk items {1}; big files {2}; old folders {3}' -f ($sm.reclaimableBytes / 1GB), $sm.junkItems.total, $sm.bigFiles.count, $sm.oldFolders.count
    foreach ($k in $sm.bySafety.Keys) { '  {0,-17} {1,8:N1} GB  {2,5} items' -f $k, ($sm.bySafety[$k].bytes / 1GB), $sm.bySafety[$k].items }
    foreach ($c in ($sm.topCategories | Select-Object -First 12)) { '  cat {0,-24} {1,8:N1} GB  {2,5}  {3}' -f $c.category, ($c.bytes / 1GB), $c.items, ($c.safety -join '/') }
}
