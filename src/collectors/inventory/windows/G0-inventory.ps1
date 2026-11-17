#Requires -Version 7.2
<#
.SYNOPSIS
    G0 - file-system inventory: one read-only, metadata-only pass over every fixed drive.
.DESCRIPTION
    Feeds the storage map (treemap), the old-files and large-files views and S02's cross-check.
    Contract: docs\schema.md, section "G0 inventory". Methodology: docs\playbooks\G0-inventory.md.

    Enumeration
      DirectoryInfo.EnumerateFileSystemInfos + EnumerationOptions, manual stack recursion, one directory
      at a time with IgnoreInaccessible = $false inside try/catch, so every directory that cannot be
      listed is counted. Pure PowerShell, no pipeline in the hot loop (measured at about 110k entries/s
      warm, 1.4x a compiled C# walker, so no Add-Type is needed).

      AttributesToSkip is None (NOT ReparsePoint) and reparse points are classified explicitly. On
      Windows 10/11 the OneDrive root, its folders and its files carry FILE_ATTRIBUTE_REPARSE_POINT
      (cloud tags 0x9000xx1A), so skipping ReparsePoint would hide the whole OneDrive tree and make
      cloud-only bytes unmeasurable. Hidden and System entries (all of AppData) are always included.
        * Name-surrogate reparse folders (junctions, symbolic links, volume mount points; detected with
          FileSystemInfo.LinkTarget, which reads the reparse point itself and never follows it) are
          never walked. They get a dirs.tsv row flagged 'reparse'.
        * Cloud-sync placeholder folders are walked unless they are cloud-only.
        * Any other non-link reparse folder outside a sync root is not walked (flag 'reparse').

    Safety
      * Never opens, reads or hashes file contents: every fact comes from directory listings.
      * Never enumerates or opens cloud-only placeholders (attributes 0x400000 / 0x40000 / 0x1000).
      * Writes only data\<scanId>\inventory\ (inventory\subset\ with -Path) and logs\G0.log.
      * Every string written to TSV/JSON is masked (path components through Protect-BvsText).
.PARAMETER Path
    Inventory only these folders (subset / test mode). Results go to data\<scanId>\inventory\subset\ so
    a test run never replaces the canonical full-scan outputs that other modules read.
.PARAMETER ScanId
    Scan to write into. Default: data\latest.txt.
.PARAMETER ProgressSeconds
    Interval of the progress lines in logs\G0.log. Default: 15.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\inventory\windows\G0-inventory.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\inventory\windows\G0-inventory.ps1 -Path "$env:USERPROFILE\Documents\GitHub"
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$ScanId,
    [ValidateRange(1, 3600)][int]$ProgressSeconds = 15
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$ScriptStart = [datetime]::UtcNow
$initArgs = @{ Module = 'G0'; Area = 'inventory' }
if ($ScanId) { $initArgs.ScanId = $ScanId }
# Workaround for a library bug (reported; lib\ is read-only for collectors): Initialize-BvsRun re-parses
# the DateTime that ConvertFrom-Json already produced as a culture-formatted string, which throws on
# day-first locales (en-GB, cs-CZ, ...). Run it under the invariant culture, then restore the exact UTC.
$prevCulture = [Globalization.CultureInfo]::CurrentCulture
try {
    [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
    $run = Initialize-BvsRun @initArgs
}
finally { [Globalization.CultureInfo]::CurrentCulture = $prevCulture }
$scanMetaPath = Join-Path $run.ScanDir 'scan-meta.json'
if (Test-Path -LiteralPath $scanMetaPath) {
    $scanMeta = Get-Content -LiteralPath $scanMetaPath -Raw | ConvertFrom-Json
    if ($scanMeta.auditStartUtc -is [datetime]) { $run.AuditStartUtc = $scanMeta.auditStartUtc.ToUniversalTime() }
}
$Subset = [bool]$Path
if ($Subset) {
    # test / subset runs never overwrite the canonical outputs other modules consume
    $run.OutDir = Join-Path $run.OutDir 'subset'
    [void][IO.Directory]::CreateDirectory($run.OutDir)
}
$outDir = $run.OutDir
$ProjectRoot = (Get-BvsRoot).TrimEnd('\')
if (-not ([IO.Path]::GetFullPath($outDir).TrimEnd('\') + '\').StartsWith($ProjectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "G0 refuses to write outside the project folder: $outDir"
}

#region ---------- constants ----------

# Selection / inheritance bits: the low 16 bits of the per-directory flags word.
$B_NM = 0x0001         # inside node_modules
$B_GIT = 0x0002        # inside .git
$B_PYPKG = 0x0004      # inside site-packages
$B_VENV = 0x0008       # inside a Python virtual environment (pyvenv.cfg, venv, .venv, virtualenv)
$B_WINAPPS = 0x0010    # inside WindowsApps
$B_PROJECT = 0x0020    # inside this project's folder
$B_EXECSCOPE = 0x0040  # under the profiles folder (C:\Users) or ProgramData
$B_DOWNLOADS = 0x0080  # inside a Downloads folder
$B_USERROOT = 0x0100   # this folder IS a Desktop / Downloads / Documents folder (not inherited)
$B_ONEDRIVE = 0x0200   # inside a OneDrive sync root                                 -> flag onedrive
$B_HARDLINK = 0x0400   # inside WinSxS, a pnpm store or node_modules\.pnpm           -> flag hardlink-heavy
$B_CLOUD = 0x0800      # inside any cloud-files sync root (OneDrive, Dropbox, Google Drive, iCloud, ...)
$INHERIT = 0xFFFF -bxor $B_USERROOT
$EXEC_EXCL = $B_NM -bor $B_GIT -bor $B_PYPKG -bor $B_VENV -bor $B_WINAPPS -bor $B_PROJECT
$ZERO_EXCL = $B_NM -bor $B_GIT
# Per-directory state: high bits, never inherited.
$F_INACCESSIBLE = 0x10000  # could not be listed (access denied, vanished during the scan, other error)
$F_REPARSE = 0x20000       # reparse point that was not walked (junction, symlink, mount point, unknown type)
$F_CLOUDONLY = 0x40000     # cloud-only placeholder folder: never opened (schema extension, see playbook)
$F_UWROOT = 0x80000        # top folder under the profiles folder / ProgramData writable by the current user
$DISPLAY = $F_INACCESSIBLE -bor $F_REPARSE -bor $F_CLOUDONLY -bor $F_UWROOT -bor $B_ONEDRIVE -bor $B_HARDLINK

$A_CLOUDONLY = 0x441000    # RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
$A_CLOUDHINT = 0x180000    # PINNED | UNPINNED (only cloud-files placeholders carry these)
$LARGE_BYTES = 10MB
$TMP_BYTES = 1MB
$MAX_DEPTH = 1000          # safety net only; real trees are far shallower
$EPOCH_TICKS = 621355968000000000

$ReasonBits = @(1, 2, 4, 8, 16)
$ReasonText = @('large', 'exec-recent', 'zero-byte', 'partial-download', 'root-of-user-folder')

$NameBits = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
$NameBits['node_modules'] = $B_NM
$NameBits['.git'] = $B_GIT
$NameBits['site-packages'] = $B_PYPKG
foreach ($v in 'venv', '.venv', 'virtualenv', '.virtualenvs') { $NameBits[$v] = $B_VENV }
$NameBits['WindowsApps'] = $B_WINAPPS
$NameBits['.pnpm-store'] = $B_HARDLINK

$ExecExt = [Collections.Generic.HashSet[string]]::new([string[]]@('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.msi', '.ps1', '.vbs', '.js', '.jse', '.wsf', '.hta', '.bat', '.cmd', '.lnk', '.jar', '.a3x'), [StringComparer]::OrdinalIgnoreCase)
$PartialExt = [Collections.Generic.HashSet[string]]::new([string[]]@('.crdownload', '.part', '.partial', '.download'), [StringComparer]::OrdinalIgnoreCase)

$EnumOpts = [IO.EnumerationOptions]::new()
$EnumOpts.AttributesToSkip = [IO.FileAttributes]0   # include Hidden/System; reparse points classified by hand
$EnumOpts.IgnoreInaccessible = $false               # an unlistable directory throws -> counted
$EnumOpts.RecurseSubdirectories = $false            # manual stack recursion
$EnumOpts.ReturnSpecialDirectories = $false
$EnumOpts.BufferSize = 65536                        # fewer NtQueryDirectoryFile round trips on big folders

$Utf8NoBom = [Text.UTF8Encoding]::new($false)
$BS = [char]92   # backslash; char overloads of EndsWith/IndexOf are ordinal (string overloads are culture-sensitive)
$RxCtl = [regex]::new('[\x00-\x1F\x7F]', [Text.RegularExpressions.RegexOptions]::Compiled)
$CtlRepl = [string][char]0xFFFD
$Inv = [Globalization.CultureInfo]::InvariantCulture
$IsoFmt = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"

#endregion

#region ---------- helpers ----------

function ConvertTo-G0Key {
    <# Normalised absolute path used as a dictionary key (no trailing backslash except for drive roots). #>
    param([AllowNull()][AllowEmptyString()][string]$P)
    if ([string]::IsNullOrWhiteSpace($P)) { return $null }
    try { $f = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($P.Trim().Trim('"'))) } catch { return $null }
    if ($f.Length -gt 3) { $f = $f.TrimEnd('\') }
    $f
}

function Add-G0PathBit {
    param([AllowNull()][AllowEmptyString()][string]$P, [int]$Bit)
    $k = ConvertTo-G0Key $P
    if (-not $k) { return }
    if ($script:PathBits.ContainsKey($k)) { $script:PathBits[$k] = $script:PathBits[$k] -bor $Bit } else { $script:PathBits[$k] = $Bit }
}

function Get-G0NameBit {
    param([string]$Name, [string]$ParentName)
    if ($script:NameBits.ContainsKey($Name)) { return $script:NameBits[$Name] }
    if ($Name -eq '.pnpm' -and $ParentName -eq 'node_modules') { return $script:B_HARDLINK }
    if ($Name -eq 'store' -and $ParentName -eq 'pnpm') { return $script:B_HARDLINK }
    0
}

function Get-G0RootBits {
    <# Bits for a walk root: inheritable bits of every ancestor (subset mode) plus the root's own bits. #>
    param([string]$Key)
    $parts = $Key.Split([char]'\', [StringSplitOptions]::RemoveEmptyEntries)
    $bits = 0
    if ($script:PathBits.ContainsKey($parts[0] + '\')) { $bits = $script:PathBits[$parts[0] + '\'] }
    $acc = $parts[0] + '\'
    $prev = ''
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $acc = if ($i -eq 1) { $acc + $parts[$i] } else { $acc + '\' + $parts[$i] }
        $own = Get-G0NameBit -Name $parts[$i] -ParentName $prev
        if ($script:PathBits.ContainsKey($acc)) { $own = $own -bor $script:PathBits[$acc] }
        if ($i -lt $parts.Count - 1) { $own = $own -band $script:INHERIT }
        $bits = $bits -bor $own
        $prev = $parts[$i]
    }
    $bits
}

function Add-G0Root {
    param([string]$Key)
    $id = $script:dParent.Count
    $script:dParent.Add(-1); $script:dDepth.Add(0); $script:dName.Add($Key); $script:dFlags.Add((Get-G0RootBits -Key $Key))
    $script:dOwnBytes.Add(0L); $script:dOwnFiles.Add(0); $script:dNewest.Add(0L); $script:dOldest.Add([long]::MaxValue)
    $script:dCold1.Add(0L); $script:dCold2.Add(0L); $script:dCold5.Add(0L); $script:dCloudB.Add(0L); $script:dCloudF.Add(0)
    if ($script:PathBits.ContainsKey($Key)) { $script:SpecialIds[$Key] = $id }
    $script:RootIds.Add($id)
    $id
}

function Get-G0FlagString {
    param([int]$F)
    $l = [Collections.Generic.List[string]]::new()
    if ($F -band $script:F_INACCESSIBLE) { $l.Add('inaccessible') }
    if ($F -band $script:F_REPARSE) { $l.Add('reparse') }
    if ($F -band $script:F_CLOUDONLY) { $l.Add('cloud-only') }
    if ($F -band $script:B_ONEDRIVE) { $l.Add('onedrive') }
    if ($F -band $script:B_HARDLINK) { $l.Add('hardlink-heavy') }
    if ($F -band $script:F_UWROOT) { $l.Add('user-writable-root') }
    $l -join ','
}

function Get-G0DirPath {
    <# Full path of a directory id, rebuilt from the (masked) names along the parent chain. Cached. #>
    param([int]$Id)
    $hit = $null
    if ($script:PathCache.TryGetValue($Id, [ref]$hit)) { return $hit }
    $chain = [Collections.Generic.List[int]]::new()
    $i = $Id
    while ($i -ge 0) { $chain.Add($i); $i = $script:dParent[$i] }
    $s = $script:dName[$chain[$chain.Count - 1]]
    for ($k = $chain.Count - 2; $k -ge 0; $k--) {
        if ($s.EndsWith($script:BS)) { $s += $script:dName[$chain[$k]] } else { $s += '\' + $script:dName[$chain[$k]] }
    }
    $script:PathCache[$Id] = $s
    $s
}

function Get-G0Children {
    param([int]$Id)
    $c = $script:ChildCount[$Id]
    if ($c -eq 0) { return , [int[]]@() }
    $f = $script:FirstChild[$Id]
    , [int[]]($f..($f + $c - 1))
}

function Protect-G0Names {
    <# Mask path components in place, in chunks (one Protect-BvsText call per ~20k names). Returns #changed. #>
    param([Collections.Generic.List[string]]$Names)
    $changed = 0
    $chunk = 20000
    for ($i = 0; $i -lt $Names.Count; $i += $chunk) {
        $cntN = [Math]::Min($chunk, $Names.Count - $i)
        $arr = $Names.GetRange($i, $cntN).ToArray()
        $joined = [string]::Join("`n", $arr)
        $masked = Protect-BvsText $joined
        if ([string]::Equals($masked, $joined, [StringComparison]::Ordinal)) { continue }
        $parts = $masked.Split([char]10)
        if ($parts.Length -ne $cntN) {
            # a rule spanned the separator or a name contains a newline: mask this chunk name by name
            $parts = [string[]]::new($cntN)
            for ($k = 0; $k -lt $cntN; $k++) { $parts[$k] = Protect-BvsText $arr[$k] }
        }
        for ($k = 0; $k -lt $cntN; $k++) {
            if (-not [string]::Equals($parts[$k], $arr[$k], [StringComparison]::Ordinal)) { $Names[$i + $k] = $parts[$k]; $changed++ }
        }
    }
    $changed
}

function New-G0DirItem {
    <# Compact folder summary (bytes are logical local bytes; cloud-only placeholders reported apart). #>
    param([int]$Id, [string]$Name)
    [ordered]@{
        name           = $Name
        path           = Get-G0DirPath $Id
        bytes          = $script:tBytes[$Id]
        files          = $script:tFiles[$Id]
        dirs           = $script:tDirs[$Id]
        cloudOnlyBytes = $script:dCloudB[$Id]
        newestWriteUtc = if ($script:dNewest[$Id] -gt 0) { [datetime]::new($script:dNewest[$Id], [DateTimeKind]::Utc).ToString($script:IsoFmt, $script:Inv) } else { $null }
        flags          = Get-G0FlagString ($script:dFlags[$Id] -band $script:DISPLAY)
    }
}

#endregion

#region ---------- the walk (hot loop) ----------

function Invoke-G0Walk {
    <#
    Walk one root with a manual stack. Directory ids are assigned when a folder is discovered, so all
    children of one folder get consecutive ids and every parent id is smaller than its children's ids.
    #>
    param([int]$RootId, [string]$RootPath, [long]$Cluster)

    # Plain locals are by far the fastest variables in PowerShell: copy everything the loop touches.
    $dParent = $script:dParent; $dDepth = $script:dDepth; $dName = $script:dName; $dFlags = $script:dFlags
    $dOwnBytes = $script:dOwnBytes; $dOwnFiles = $script:dOwnFiles; $dNewest = $script:dNewest; $dOldest = $script:dOldest
    $dCold1 = $script:dCold1; $dCold2 = $script:dCold2; $dCold5 = $script:dCold5; $dCloudB = $script:dCloudB; $dCloudF = $script:dCloudF
    $sDir = $script:sDir; $sName = $script:sName; $sSize = $script:sSize; $sAlloc = $script:sAlloc
    $sCt = $script:sCt; $sMt = $script:sMt; $sAttr = $script:sAttr; $sReason = $script:sReason
    $nameBits = $script:NameBits; $pathBits = $script:PathBits; $specialIds = $script:SpecialIds
    $execExt = $script:ExecExt; $partialExt = $script:PartialExt; $opts = $script:EnumOpts
    $errSamples = $script:ErrSamples; $inaccIds = $script:InaccIds; $oddIds = $script:OddReparseIds
    $cut1 = $script:Cut1; $cut2 = $script:Cut2; $cut5 = $script:Cut5; $cut90 = $script:Cut90
    $bVenv = $script:B_VENV; $bExecScope = $script:B_EXECSCOPE; $bDownloads = $script:B_DOWNLOADS
    $bUserRoot = $script:B_USERROOT; $bHardlink = $script:B_HARDLINK; $bCloud = $script:B_CLOUD
    $inherit = $script:INHERIT; $execExcl = $script:EXEC_EXCL; $zeroExcl = $script:ZERO_EXCL
    $fInaccessible = $script:F_INACCESSIBLE; $fReparse = $script:F_REPARSE; $fCloudOnly = $script:F_CLOUDONLY
    $aCloudOnly = $script:A_CLOUDONLY; $aCloudHint = $script:A_CLOUDHINT
    $largeBytes = [long]$script:LARGE_BYTES; $tmpBytes = [long]$script:TMP_BYTES; $maxDepth = $script:MAX_DEPTH
    $progressMs = [long]$script:ProgressSeconds * 1000
    $bs = $script:BS; $dot = [char]'.'; $space = [char]' '
    $clm1 = $Cluster - 1; $clmask = -$Cluster
    $maxLong = [long]::MaxValue
    $n = $dParent.Count

    $st = [ordered]@{
        root = $RootPath; dirsListed = 0L; dirRows = 0L; localFiles = 0L; localBytes = 0L; cloudOnlyFiles = 0L; cloudOnlyBytes = 0L
        allocEstimateBytes = 0L; sparseBytes = 0L; compressedBytes = 0L; reparseFileBytes = 0L
        denied = 0L; vanished = 0L; otherErrors = 0L; linkDirs = 0L; otherReparseDirs = 0L; cloudOnlyDirs = 0L
        linkTargetErrors = 0L; depthCapped = 0L; seconds = 0.0
    }
    $filesSeen = 0L; $localFiles = 0L; $localBytes = 0L; $cloudFiles = 0L; $cloudBytes = 0L; $allocEst = 0L
    $sparseBytes = 0L; $comprBytes = 0L; $rpFileBytes = 0L; $listed = 0L
    $denied = 0L; $vanished = 0L; $otherErr = 0L; $linkDirs = 0L; $oddReparse = 0L; $cloudOnlyDirs = 0L; $linkErrors = 0L; $depthCapped = 0L

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $stId = [Collections.Generic.Stack[int]]::new()
    $stPath = [Collections.Generic.Stack[string]]::new()

    $rootAttr = 0
    try { $rootAttr = [int][IO.File]::GetAttributes($RootPath) } catch { $rootAttr = 0 }
    if (($rootAttr -band $aCloudOnly) -ne 0) {
        $dFlags[$RootId] = $dFlags[$RootId] -bor $fCloudOnly   # never open a cloud-only placeholder
        $cloudOnlyDirs++
    }
    else {
        $stId.Push($RootId); $stPath.Push($RootPath)
    }
    $nextLog = $progressMs; $lastSeen = 0L; $lastMs = 0L

    try {
        while ($stId.Count -gt 0) {
            $id = $stId.Pop()
            $path = $stPath.Pop()
            $bits = $dFlags[$id]
            $p = $dParent[$id]
            if ($p -ge 0) { $bits = $bits -bor ($dFlags[$p] -band $inherit); $dFlags[$id] = $bits }
            $cDepth = $dDepth[$id] + 1
            $myName = $dName[$id]
            $inScope = (($bits -band $bExecScope) -ne 0) -and (($bits -band $execExcl) -eq 0)
            $zeroOk = ($bits -band $zeroExcl) -eq 0
            $inDl = ($bits -band $bDownloads) -ne 0
            $userRoot = ($bits -band $bUserRoot) -ne 0
            $inCloud = ($bits -band $bCloud) -ne 0
            $ob = 0L; $of = 0; $nw = 0L; $od = $maxLong; $c1 = 0L; $c2 = 0L; $c5 = 0L; $cb = 0L; $cf = 0
            try {
                foreach ($e in [IO.DirectoryInfo]::new($path).EnumerateFileSystemInfos('*', $opts)) {
                    $a = [int]$e.Attributes
                    if (($a -band 0x10) -ne 0) {
                        # ---- subdirectory: register it now (children of one folder get consecutive ids)
                        $nm = $e.Name
                        $full = $e.FullName
                        $own = 0
                        if ($nameBits.ContainsKey($nm)) { $own = $nameBits[$nm] }
                        elseif ($nm -eq '.pnpm') { if ($myName -eq 'node_modules') { $own = $bHardlink } }
                        elseif ($nm -eq 'store') { if ($myName -eq 'pnpm') { $own = $bHardlink } }
                        if ($pathBits.ContainsKey($full)) { $own = $own -bor $pathBits[$full]; $specialIds[$full] = $n }
                        $state = 0
                        if (($a -band $aCloudOnly) -ne 0) { $state = $fCloudOnly; $cloudOnlyDirs++ }
                        elseif (($a -band 0x400) -ne 0) {
                            # reparse folder: LinkTarget reads the reparse point itself (never follows it)
                            $isLink = $true
                            try { $isLink = $null -ne $e.LinkTarget } catch { $linkErrors++ }
                            if ($isLink) { $state = $fReparse; $linkDirs++ }
                            elseif (-not ($inCloud -or (($own -band $bCloud) -ne 0) -or (($a -band $aCloudHint) -ne 0))) {
                                $state = $fReparse; $oddReparse++
                                if ($oddIds.Count -lt 100) { $oddIds.Add($n) }
                            }
                        }
                        elseif ($cDepth -ge $maxDepth) { $state = $fInaccessible; $depthCapped++ }
                        $dParent.Add($id); $dDepth.Add($cDepth); $dName.Add($nm)
                        $dOwnBytes.Add(0L); $dOwnFiles.Add(0); $dNewest.Add(0L); $dOldest.Add($maxLong)
                        $dCold1.Add(0L); $dCold2.Add(0L); $dCold5.Add(0L); $dCloudB.Add(0L); $dCloudF.Add(0)
                        if ($state -eq 0) {
                            $dFlags.Add($own)
                            $stId.Push($n)
                            # names ending in '.' or ' ' are only reachable through the \\?\ namespace
                            if (($nm.EndsWith($dot) -or $nm.EndsWith($space)) -and -not $full.StartsWith('\\?\', [StringComparison]::Ordinal)) { $full = '\\?\' + $full }
                            $stPath.Push($full)
                        }
                        else {
                            $dFlags.Add(($own -bor ($bits -band $inherit)) -bor $state)
                        }
                        $n++
                        continue
                    }
                    # ---- file: metadata from the directory listing only (nothing is opened)
                    $len = $e.Length
                    $mt = $e.LastWriteTimeUtc.Ticks
                    $cloudOnly = ($a -band $aCloudOnly) -ne 0
                    if ($cloudOnly) { $cb += $len; $cf++ }
                    else {
                        $ob += $len; $of++
                        if ($mt -gt $nw) { $nw = $mt }
                        if ($mt -lt $od) { $od = $mt }
                        if ($mt -lt $cut1) { $c1 += $len; if ($mt -lt $cut2) { $c2 += $len; if ($mt -lt $cut5) { $c5 += $len } } }
                        if ($len -gt 0) { $allocEst += ($len + $clm1) -band $clmask }
                        if (($a -band 0xE00) -ne 0) {
                            if (($a -band 0x200) -ne 0) { $sparseBytes += $len }
                            if (($a -band 0x800) -ne 0) { $comprBytes += $len }
                            if (($a -band 0x400) -ne 0) { $rpFileBytes += $len }
                        }
                    }
                    $ext = $e.Extension
                    $rs = 0
                    if ($len -ge $largeBytes) { $rs = 1 }
                    if ($inScope) {
                        if ($execExt.Contains($ext)) { if ($mt -ge $cut90 -or $e.CreationTimeUtc.Ticks -ge $cut90) { $rs = $rs -bor 2 } }
                    }
                    if ($len -eq 0) {
                        if ($zeroOk -and $ext -ne '.lock') {
                            $fn = $e.Name
                            if ($fn -ne '__init__.py' -and $fn -ne '.gitkeep') {
                                # a zero-length reparse file outside a sync root is a link (symlink, App
                                # Execution Alias), not an empty file
                                if ((($a -band 0x400) -eq 0) -or $inCloud -or $cloudOnly) { $rs = $rs -bor 4 }
                            }
                        }
                    }
                    if ($partialExt.Contains($ext)) { $rs = $rs -bor 8 }
                    elseif ($inDl) { if ($len -ge $tmpBytes -and $ext -eq '.tmp') { $rs = $rs -bor 8 } }
                    if ($userRoot) { $rs = $rs -bor 16 }
                    if ($rs -ne 0) {
                        $sDir.Add($id); $sName.Add($e.Name); $sSize.Add($len)
                        if ($cloudOnly -or $len -eq 0) { $sAlloc.Add(0L) } else { $sAlloc.Add(($len + $clm1) -band $clmask) }
                        $sCt.Add($e.CreationTimeUtc.Ticks); $sMt.Add($mt); $sAttr.Add($a); $sReason.Add($rs)
                    }
                    if ($ext -eq '.cfg') {
                        # a virtualenv root: subfolders (already queued) inherit the exclusion when popped
                        if ($e.Name -eq 'pyvenv.cfg') { $bits = $bits -bor $bVenv; $dFlags[$id] = $bits; $inScope = $false }
                    }
                }
                $listed++
            }
            catch {
                $bx = $_.Exception.GetBaseException()
                $dFlags[$id] = $dFlags[$id] -bor $fInaccessible
                if ($bx -is [UnauthorizedAccessException]) { $denied++ }
                elseif ($bx -is [IO.DirectoryNotFoundException]) { $vanished++ }
                else {
                    $otherErr++
                    if ($errSamples.Count -lt 25) { $errSamples.Add(('{0}: {1}' -f $bx.GetType().Name, $bx.Message)) }
                }
                if ($inaccIds.Count -lt 200) { $inaccIds.Add($id) }
            }
            $dOwnBytes[$id] = $ob; $dOwnFiles[$id] = $of
            if ($of -gt 0) { $dNewest[$id] = $nw; $dOldest[$id] = $od; $dCold1[$id] = $c1; $dCold2[$id] = $c2; $dCold5[$id] = $c5 }
            if ($cf -gt 0) { $dCloudB[$id] = $cb; $dCloudF[$id] = $cf }
            $localFiles += $of; $localBytes += $ob; $cloudFiles += $cf; $cloudBytes += $cb; $filesSeen += $of + $cf

            if ($sw.ElapsedMilliseconds -ge $nextLog) {
                $ms = $sw.ElapsedMilliseconds
                $rate = [long](($filesSeen - $lastSeen) * 1000.0 / [Math]::Max(1, $ms - $lastMs))
                $avg = [long]($filesSeen * 1000.0 / [Math]::Max(1, $ms))
                $top = $path
                $i1 = $path.IndexOf($bs, 3)
                if ($i1 -gt 0) {
                    $i2 = $path.IndexOf($bs, $i1 + 1)
                    if ($i2 -gt 0) { $i3 = $path.IndexOf($bs, $i2 + 1); if ($i3 -gt 0) { $top = $path.Substring(0, $i3) } }
                }
                Write-BvsLog -Run $script:run -Message ('progress root={0} elapsed={1}s files={2} dirs={3} listed={4} localMB={5} rate={6} files/s avg={7} files/s pending={8} inaccessible={9} top={10}' -f $RootPath, [long]($ms / 1000), $filesSeen, ($n - $RootId), $listed, [long]($localBytes / 1MB), $rate, $avg, $stId.Count, ($denied + $vanished + $otherErr), $top)
                $lastSeen = $filesSeen; $lastMs = $ms; $nextLog = $ms + $progressMs
            }
        }
    }
    finally {
        $st.dirsListed = $listed; $st.dirRows = $n - $RootId; $st.localFiles = $localFiles; $st.localBytes = $localBytes
        $st.cloudOnlyFiles = $cloudFiles; $st.cloudOnlyBytes = $cloudBytes; $st.allocEstimateBytes = $allocEst
        $st.sparseBytes = $sparseBytes; $st.compressedBytes = $comprBytes; $st.reparseFileBytes = $rpFileBytes
        $st.denied = $denied; $st.vanished = $vanished; $st.otherErrors = $otherErr; $st.linkDirs = $linkDirs
        $st.otherReparseDirs = $oddReparse; $st.cloudOnlyDirs = $cloudOnlyDirs; $st.linkTargetErrors = $linkErrors
        $st.depthCapped = $depthCapped; $st.seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    }
    $inacc = $denied + $vanished + $otherErr + $depthCapped
    Write-BvsLog -Run $script:run -Message ('walk done root={0} {1}s files={2} localBytes={3} dirs={4} listed={5} inaccessible={6} (denied={7} vanished={8} other={9}) links={10} otherReparse={11} cloudOnlyFiles={12}' -f $RootPath, $st.seconds, $filesSeen, $localBytes, $st.dirRows, $listed, $inacc, $denied, $vanished, $otherErr, $linkDirs, $oddReparse, $cloudFiles)
    if ($inacc -gt 0) {
        $why = if ($script:run.Elevated) { 'elevated session' } else { 'not elevated' }
        Set-BvsCheckStatus -Id "inventory.walk.$($script:CurrentRootTag)" -Status partial -Reason ('{0} of {1} directories could not be listed ({2}): denied={3}, vanished={4}, other={5}, depth-capped={6}' -f $inacc, $st.dirRows, $why, $denied, $vanished, $otherErr, $depthCapped)
    }
    [pscustomobject]$st
}

#endregion

#region ---------- context: volumes, profiles, special folders ----------

$Unlettered = [Collections.Generic.List[object]]::new()
$Volumes = @(Invoke-BvsCheck -Run $run -Id 'inventory.volumes' -Description 'Fixed drives with a letter: size, free, used, file system, cluster size (letterless volumes listed, not walked)' -Script {
        $blk = @{}
        try {
            foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop)) {
                if ($v.DriveLetter) { $blk[$v.DriveLetter.ToUpperInvariant()] = [long]$v.BlockSize }
                else { $script:Unlettered.Add([ordered]@{ label = $v.Label; fileSystem = $v.FileSystem; sizeBytes = [long]$v.Capacity; freeBytes = [long]$v.FreeSpace }) }
            }
        }
        catch { Write-BvsLog -Run $run -Level WARN -Message "Win32_Volume unavailable, assuming 4096-byte clusters: $($_.Exception.Message)" }
        foreach ($d in [IO.DriveInfo]::GetDrives()) {
            if ($d.DriveType -ne [IO.DriveType]::Fixed -or -not $d.IsReady) { continue }
            $letter = $d.Name.Substring(0, 2).ToUpperInvariant()
            $cl = 4096L
            if ($blk.ContainsKey($letter) -and $blk[$letter] -gt 0) { $cl = $blk[$letter] }
            [pscustomobject][ordered]@{
                name = $d.Name; label = $d.VolumeLabel; fileSystem = $d.DriveFormat; clusterBytes = $cl
                sizeBytes = $d.TotalSize; freeBytes = $d.TotalFreeSpace; availableBytes = $d.AvailableFreeSpace
                usedBytes = $d.TotalSize - $d.TotalFreeSpace
            }
        }
    })

$PathBits = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
$SpecialIds = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
$Ctx = Invoke-BvsCheck -Run $run -Id 'inventory.context' -Description 'Resolve user profiles, known user folders, OneDrive and cloud sync roots, WinSxS and other special folders' -Script {
    $c = [ordered]@{
        profilesDir     = $null
        programData     = ConvertTo-G0Key $env:ProgramData
        systemRoot      = ConvertTo-G0Key $env:SystemRoot
        programFiles    = ConvertTo-G0Key $env:ProgramFiles
        programFilesX86 = ConvertTo-G0Key ${env:ProgramFiles(x86)}
        currentProfile  = ConvertTo-G0Key $env:USERPROFILE
        profiles        = [Collections.Generic.List[string]]::new()
        userFolders     = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        downloadFolders = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        oneDriveRoots   = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        syncRoots       = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $pl = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $pd = @(Get-BvsRegValues -Path $pl | Where-Object Name -EQ 'ProfilesDirectory')
    if ($pd.Count) { $c.profilesDir = ConvertTo-G0Key ([string]$pd[0].Value) }
    if (-not $c.profilesDir -and $c.currentProfile) { $c.profilesDir = Split-Path -Parent $c.currentProfile }

    $cand = [Collections.Generic.List[string]]::new()
    foreach ($sid in @(Get-BvsRegSubKeys -Path $pl)) {
        $ip = @(Get-BvsRegValues -Path "$pl\$sid" | Where-Object Name -EQ 'ProfileImagePath')
        if ($ip.Count) { $k = ConvertTo-G0Key ([string]$ip[0].Value); if ($k) { $cand.Add($k) } }
    }
    if ($c.profilesDir -and [IO.Directory]::Exists($c.profilesDir)) {
        $o = [IO.EnumerationOptions]::new(); $o.AttributesToSkip = [IO.FileAttributes]::ReparsePoint; $o.IgnoreInaccessible = $true
        foreach ($d in [IO.DirectoryInfo]::new($c.profilesDir).EnumerateDirectories('*', $o)) { $cand.Add($d.FullName) }
    }
    if ($c.currentProfile) { $cand.Add($c.currentProfile) }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $cand) {
        if (-not $seen.Add($p)) { continue }
        # real profiles only: under the profiles folder (service profiles live under System32) or the current user
        $under = $c.profilesDir -and $p.StartsWith($c.profilesDir + '\', [StringComparison]::OrdinalIgnoreCase)
        if ($under -or $p -eq $c.currentProfile) { $c.profiles.Add($p) }
    }
    foreach ($p in $c.profiles) {
        [void]$c.userFolders.Add((Join-Path $p 'Desktop'))
        [void]$c.userFolders.Add((Join-Path $p 'Documents'))
        [void]$c.downloadFolders.Add((Join-Path $p 'Downloads'))
    }
    # current user's known folders (may be redirected, e.g. into OneDrive by Known Folder Move)
    foreach ($v in @(Get-BvsRegValues -Path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')) {
        $k = ConvertTo-G0Key ([string]$v.Value)
        if (-not $k) { continue }
        if ($v.Name -in 'Desktop', 'Personal') { [void]$c.userFolders.Add($k) }
        elseif ($v.Name -eq '{374DE290-123F-4565-9164-39C4925E467B}') { [void]$c.downloadFolders.Add($k) }
    }
    foreach ($sf in 'Desktop', 'MyDocuments') { $k = ConvertTo-G0Key ([Environment]::GetFolderPath($sf)); if ($k) { [void]$c.userFolders.Add($k) } }
    # OneDrive and every other Cloud Files API sync root
    foreach ($ev in 'OneDrive', 'OneDriveConsumer', 'OneDriveCommercial') {
        $k = ConvertTo-G0Key ([Environment]::GetEnvironmentVariable($ev)); if ($k) { [void]$c.oneDriveRoots.Add($k) }
    }
    $acc = 'HKCU\Software\Microsoft\OneDrive\Accounts'
    foreach ($a in @(Get-BvsRegSubKeys -Path $acc)) {
        $uf = @(Get-BvsRegValues -Path "$acc\$a" | Where-Object Name -EQ 'UserFolder')
        if ($uf.Count) { $k = ConvertTo-G0Key ([string]$uf[0].Value); if ($k) { [void]$c.oneDriveRoots.Add($k) } }
    }
    $srm = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager'
    foreach ($sr in @(Get-BvsRegSubKeys -Path $srm)) {
        foreach ($v in @(Get-BvsRegValues -Path "$srm\$sr\UserSyncRoots")) {
            $k = ConvertTo-G0Key ([string]$v.Value)
            if (-not $k) { continue }
            [void]$c.syncRoots.Add($k)
            if ($sr -like 'OneDrive*') { [void]$c.oneDriveRoots.Add($k) }
        }
    }

    Add-G0PathBit $c.profilesDir $B_EXECSCOPE
    Add-G0PathBit $c.programData $B_EXECSCOPE
    Add-G0PathBit $ProjectRoot $B_PROJECT
    if ($c.systemRoot) { Add-G0PathBit (Join-Path $c.systemRoot 'WinSxS') $B_HARDLINK }
    foreach ($k in $c.oneDriveRoots) { Add-G0PathBit $k ($B_ONEDRIVE -bor $B_CLOUD) }
    foreach ($k in $c.syncRoots) { Add-G0PathBit $k $B_CLOUD }
    foreach ($k in $c.userFolders) { Add-G0PathBit $k $B_USERROOT }
    foreach ($k in $c.downloadFolders) { Add-G0PathBit $k ($B_USERROOT -bor $B_DOWNLOADS) }
    # folders whose ids the breakdowns need (bit 0 = just remember the id)
    foreach ($k in @($c.systemRoot, $c.programFiles, $c.programFilesX86, $c.programData, $c.profilesDir) + @($c.profiles)) { Add-G0PathBit $k 0 }
    [pscustomobject]$c
}
if (-not $Ctx) { throw 'inventory.context failed; see logs\G0.log' }

#endregion

#region ---------- roots ----------

$Roots = [Collections.Generic.List[object]]::new()
if ($Subset) {
    $keys = [Collections.Generic.List[string]]::new()
    foreach ($p in $Path) {
        $k = ConvertTo-G0Key $p
        if ($k -and [IO.Directory]::Exists($k)) { $keys.Add($k) } else { Write-BvsLog -Run $run -Level WARN -Message "-Path not found or not a folder, skipped: $p" }
    }
    # drop roots nested inside another root (they would be counted twice)
    foreach ($k in @($keys | Sort-Object Length)) {
        $nested = $false
        foreach ($r in $Roots) { $pre = if ($r.path.EndsWith($BS)) { $r.path } else { $r.path + '\' }; if ($k -eq $r.path -or $k.StartsWith($pre, [StringComparison]::OrdinalIgnoreCase)) { $nested = $true } }
        if ($nested) { continue }
        $vr = [IO.Path]::GetPathRoot($k)
        $vol = @($Volumes | Where-Object { $_.name -eq $vr })
        $Roots.Add([pscustomobject]@{ path = $k; volume = $vr; cluster = $(if ($vol.Count) { [long]$vol[0].clusterBytes } else { 4096L }) })
    }
    if ($Roots.Count -eq 0) { throw 'None of the -Path folders exists.' }
}
else {
    foreach ($v in $Volumes) { $Roots.Add([pscustomobject]@{ path = $v.name; volume = $v.name; cluster = [long]$v.clusterBytes }) }
}

#endregion

#region ---------- walk ----------

$cap = 1 -shl 18
$dParent = [Collections.Generic.List[int]]::new($cap)
$dDepth = [Collections.Generic.List[int]]::new($cap)
$dName = [Collections.Generic.List[string]]::new($cap)
$dFlags = [Collections.Generic.List[int]]::new($cap)
$dOwnBytes = [Collections.Generic.List[long]]::new($cap)
$dOwnFiles = [Collections.Generic.List[int]]::new($cap)
$dNewest = [Collections.Generic.List[long]]::new($cap)
$dOldest = [Collections.Generic.List[long]]::new($cap)
$dCold1 = [Collections.Generic.List[long]]::new($cap)
$dCold2 = [Collections.Generic.List[long]]::new($cap)
$dCold5 = [Collections.Generic.List[long]]::new($cap)
$dCloudB = [Collections.Generic.List[long]]::new($cap)
$dCloudF = [Collections.Generic.List[int]]::new($cap)
$sDir = [Collections.Generic.List[int]]::new()
$sName = [Collections.Generic.List[string]]::new()
$sSize = [Collections.Generic.List[long]]::new()
$sAlloc = [Collections.Generic.List[long]]::new()
$sCt = [Collections.Generic.List[long]]::new()
$sMt = [Collections.Generic.List[long]]::new()
$sAttr = [Collections.Generic.List[int]]::new()
$sReason = [Collections.Generic.List[int]]::new()
$ErrSamples = [Collections.Generic.List[string]]::new()
$InaccIds = [Collections.Generic.List[int]]::new()
$OddReparseIds = [Collections.Generic.List[int]]::new()
$RootIds = [Collections.Generic.List[int]]::new()
$PathCache = [Collections.Generic.Dictionary[int, string]]::new()

$RefUtc = [datetime]::UtcNow
$Cut1 = $RefUtc.AddYears(-1).Ticks
$Cut2 = $RefUtc.AddYears(-2).Ticks
$Cut5 = $RefUtc.AddYears(-5).Ticks
$Cut90 = $RefUtc.AddDays(-90).Ticks

$RootStats = [Collections.Generic.List[object]]::new()
$walkSw = [Diagnostics.Stopwatch]::StartNew()
foreach ($r in $Roots) {
    $rid = Add-G0Root -Key $r.path
    $CurrentRootTag = ($r.path -replace '[^A-Za-z0-9]+', '_').Trim('_')
    if (-not $CurrentRootTag) { $CurrentRootTag = "root$rid" }
    Write-BvsLog -Run $run -Message "walk start root=$($r.path) cluster=$($r.cluster)"
    $res = Invoke-BvsCheck -Run $run -Id "inventory.walk.$CurrentRootTag" -Description "Metadata walk of $($r.path) (directory listings only; links not followed; cloud-only placeholders not opened)" -Script {
        Invoke-G0Walk -RootId $rid -RootPath $r.path -Cluster $r.cluster
    }
    if ($res) {
        $res | Add-Member -NotePropertyName volume -NotePropertyValue $r.volume -Force
        $res | Add-Member -NotePropertyName rootId -NotePropertyValue $rid -Force
        $RootStats.Add($res)
    }
}
$walkSw.Stop()

# all per-directory lists must line up (they always do unless the walk died mid-row)
$DirCount = @($dParent.Count, $dDepth.Count, $dName.Count, $dFlags.Count, $dOwnBytes.Count, $dOwnFiles.Count, $dNewest.Count, $dOldest.Count,
    $dCold1.Count, $dCold2.Count, $dCold5.Count, $dCloudB.Count, $dCloudF.Count) | Measure-Object -Minimum | ForEach-Object { [int]$_.Minimum }
$SelCount = @($sDir.Count, $sName.Count, $sSize.Count, $sAlloc.Count, $sCt.Count, $sMt.Count, $sAttr.Count, $sReason.Count) | Measure-Object -Minimum | ForEach-Object { [int]$_.Minimum }

#endregion

#region ---------- bottom-up totals ----------

$tBytes = [long[]]::new($DirCount)
$tFiles = [long[]]::new($DirCount)
$tDirs = [long[]]::new($DirCount)
$FirstChild = [int[]]::new($DirCount)
$ChildCount = [int[]]::new($DirCount)
[void](Invoke-BvsCheck -Run $run -Id 'inventory.totals' -Description 'Bottom-up subtree totals (bytes, files, dirs, newest/oldest write, cold 1y/2y/5y, cloud-only)' -Script {
        for ($i = 0; $i -lt $DirCount; $i++) {
            $tBytes[$i] = $dOwnBytes[$i]; $tFiles[$i] = $dOwnFiles[$i]
            $p = $dParent[$i]
            if ($p -ge 0) { if ($ChildCount[$p] -eq 0) { $FirstChild[$p] = $i }; $ChildCount[$p]++ }
        }
        # parent id < child id, so one reverse pass accumulates every subtree
        for ($i = $DirCount - 1; $i -ge 0; $i--) {
            $p = $dParent[$i]
            if ($p -lt 0) { continue }
            $tBytes[$p] += $tBytes[$i]; $tFiles[$p] += $tFiles[$i]; $tDirs[$p] += $tDirs[$i] + 1
            $x = $dNewest[$i]; if ($x -gt $dNewest[$p]) { $dNewest[$p] = $x }
            $x = $dOldest[$i]; if ($x -lt $dOldest[$p]) { $dOldest[$p] = $x }
            $x = $dCold1[$i]; if ($x) { $dCold1[$p] += $x }
            $x = $dCold2[$i]; if ($x) { $dCold2[$p] += $x }
            $x = $dCold5[$i]; if ($x) { $dCold5[$p] += $x }
            $x = $dCloudB[$i]; if ($x) { $dCloudB[$p] += $x }
            $x = $dCloudF[$i]; if ($x) { $dCloudF[$p] += $x }
        }
        $DirCount
    })
Write-BvsLog -Run $run -Message "totals done dirs=$DirCount selectedFiles=$SelCount"

#endregion

#region ---------- user-writable top folders (real paths, before masking) ----------

$UwHits = @(Invoke-BvsCheck -Run $run -Id 'inventory.user_writable_roots' -Description 'Top folders under the profiles folder and ProgramData that the current user can write (flag user-writable-root)' -Script {
        $bases = @($Ctx.profilesDir, $Ctx.programData) | Where-Object { $_ -and $SpecialIds.ContainsKey($_) }
        if (-not $bases) { Set-BvsCheckStatus -Id 'inventory.user_writable_roots' -Status not_applicable -Reason 'profiles folder and ProgramData not inside the walked roots' }
        foreach ($base in $bases) {
            foreach ($k in (Get-G0Children $SpecialIds[$base])) {
                if (($dFlags[$k] -band ($F_REPARSE -bor $F_CLOUDONLY)) -ne 0) { continue }
                if (Test-BvsUserWritable -Path (Join-Path $base $dName[$k])) { $dFlags[$k] = $dFlags[$k] -bor $F_UWROOT; $k }
            }
        }
    })

#endregion

#region ---------- masking (every path component, once) ----------

$MaskStats = Invoke-BvsCheck -Run $run -Id 'inventory.mask' -Description 'Mask secrets in folder and file names (Protect-BvsText, chunked) before anything is written' -Script {
    [pscustomobject]@{ dirNames = (Protect-G0Names $dName); fileNames = (Protect-G0Names $sName) }
}

#endregion

#region ---------- dirs.tsv ----------

$DirRows = Invoke-BvsCheck -Run $run -Id 'inventory.write.dirs_tsv' -Description 'Write dirs.tsv: one row per directory, depth-first order (docs\schema.md)' -Script {
    $w = [IO.StreamWriter]::new((Join-Path $outDir "dirs.tsv.tmp-$PID"), $false, $Utf8NoBom, 1MB)
    $rows = 0L
    try {
        $w.WriteLine("id`tparent`tdepth`tpath`townBytes`townFiles`ttotalBytes`ttotalFiles`ttotalDirs`tnewestWriteUtc`toldestWriteUtc`tcold1yBytes`tcold2yBytes`tcold5yBytes`tcloudOnlyBytes`tcloudOnlyFiles`tflags")
        $stI = [Collections.Generic.Stack[int]]::new()
        $stP = [Collections.Generic.Stack[string]]::new()
        for ($r = $RootIds.Count - 1; $r -ge 0; $r--) { $stI.Push($RootIds[$r]); $stP.Push($dName[$RootIds[$r]]) }
        $flagCache = @{}
        while ($stI.Count -gt 0) {
            $id = $stI.Pop()
            $pth = $stP.Pop()
            $fk = $dFlags[$id] -band $DISPLAY
            $fs = $flagCache[$fk]
            if ($null -eq $fs) { $fs = Get-G0FlagString $fk; $flagCache[$fk] = $fs }
            $nws = ''; $ods = ''
            $nw = $dNewest[$id]
            if ($nw -gt 0) {
                # schema: epochs in seconds
                $nws = [long][Math]::Floor(($nw - $EPOCH_TICKS) / 1e7)
                $ods = [long][Math]::Floor(($dOldest[$id] - $EPOCH_TICKS) / 1e7)
            }
            $safe = $RxCtl.Replace($pth, $CtlRepl)
            $w.WriteLine("$id`t$($dParent[$id])`t$($dDepth[$id])`t$safe`t$($dOwnBytes[$id])`t$($dOwnFiles[$id])`t$($tBytes[$id])`t$($tFiles[$id])`t$($tDirs[$id])`t$nws`t$ods`t$($dCold1[$id])`t$($dCold2[$id])`t$($dCold5[$id])`t$($dCloudB[$id])`t$($dCloudF[$id])`t$fs")
            $rows++
            $c = $ChildCount[$id]
            if ($c -gt 0) {
                $f0 = $FirstChild[$id]
                $prefix = if ($pth.EndsWith($BS)) { $pth } else { $pth + '\' }
                for ($k = $f0 + $c - 1; $k -ge $f0; $k--) { $stI.Push($k); $stP.Push($prefix + $dName[$k]) }
            }
        }
    }
    finally { $w.Dispose() }
    [IO.File]::Move((Join-Path $outDir "dirs.tsv.tmp-$PID"), (Join-Path $outDir 'dirs.tsv'), $true)
    $rows
}

#endregion

#region ---------- files.tsv ----------

$FileRowCounts = [ordered]@{}
foreach ($t in $ReasonText) { $FileRowCounts[$t] = 0 }
$FileRows = Invoke-BvsCheck -Run $run -Id 'inventory.write.files_tsv' -Description 'Write files.tsv: selected files only, one row per (file, reason)' -Script {
    $w = [IO.StreamWriter]::new((Join-Path $outDir "files.tsv.tmp-$PID"), $false, $Utf8NoBom, 1MB)
    $rows = 0L
    try {
        $w.WriteLine("path`tsizeBytes`tallocBytes`tcreatedUtc`tmodifiedUtc`tattributes`text`treason")
        for ($ri = 0; $ri -lt $ReasonBits.Count; $ri++) {
            $bit = $ReasonBits[$ri]; $txt = $ReasonText[$ri]
            $idx = [Collections.Generic.List[int]]::new()
            $key = [Collections.Generic.List[long]]::new()
            for ($i = 0; $i -lt $SelCount; $i++) {
                if (($sReason[$i] -band $bit) -eq 0) { continue }
                $idx.Add($i)
                if ($bit -eq 1) { $key.Add(-$sSize[$i]) }                                  # large: biggest first
                elseif ($bit -eq 2) { $key.Add(-[Math]::Max($sCt[$i], $sMt[$i])) }         # exec-recent: newest first
                else { $key.Add($idx.Count) }                                               # walk order
            }
            $ia = $idx.ToArray(); $ka = $key.ToArray()
            [Array]::Sort($ka, $ia)
            foreach ($i in $ia) {
                $dp = Get-G0DirPath $sDir[$i]
                $fp = if ($dp.EndsWith($BS)) { $dp + $sName[$i] } else { $dp + '\' + $sName[$i] }
                $safe = $RxCtl.Replace($fp, $CtlRepl)
                $ext = $RxCtl.Replace([IO.Path]::GetExtension($sName[$i]).ToLowerInvariant(), $CtlRepl)
                $cs = [datetime]::new($sCt[$i], [DateTimeKind]::Utc).ToString($IsoFmt, $Inv)
                $ms = [datetime]::new($sMt[$i], [DateTimeKind]::Utc).ToString($IsoFmt, $Inv)
                $w.WriteLine("$safe`t$($sSize[$i])`t$($sAlloc[$i])`t$cs`t$ms`t0x$($sAttr[$i].ToString('X'))`t$ext`t$txt")
                $rows++
            }
            $FileRowCounts[$txt] = $ia.Length
        }
    }
    finally { $w.Dispose() }
    [IO.File]::Move((Join-Path $outDir "files.tsv.tmp-$PID"), (Join-Path $outDir 'files.tsv'), $true)
    $rows
}

#endregion

#region ---------- inventory-meta.json ----------

$Meta = Invoke-BvsCheck -Run $run -Id 'inventory.write.meta' -Description 'Write inventory-meta.json: volumes, totals, unaccounted bytes, top-level and per-profile breakdowns' -Script {
    # per-volume aggregation of the root walks
    $volOut = [Collections.Generic.List[object]]::new()
    $sum = @{}
    foreach ($k in 'localBytes', 'localFiles', 'dirRows', 'dirsListed', 'cloudOnlyBytes', 'cloudOnlyFiles', 'allocEstimateBytes', 'sparseBytes', 'compressedBytes', 'reparseFileBytes', 'denied', 'vanished', 'otherErrors', 'depthCapped', 'linkDirs', 'otherReparseDirs', 'cloudOnlyDirs', 'linkTargetErrors') { $sum[$k] = 0L }
    # hardlink-heavy subtrees (top-most flagged folders): their bytes are overstated (shared clusters)
    $hlByRoot = @{}
    for ($i = 0; $i -lt $DirCount; $i++) {
        if (($dFlags[$i] -band $B_HARDLINK) -eq 0) { continue }
        $p = $dParent[$i]
        if ($p -ge 0 -and ($dFlags[$p] -band $B_HARDLINK) -ne 0) { continue }
        $r = $i; while ($dParent[$r] -ge 0) { $r = $dParent[$r] }
        $hlByRoot[$r] = [long]$hlByRoot[$r] + $tBytes[$i]
    }
    $sumKeys = @($sum.Keys)
    foreach ($v in $Volumes) {
        $rs = @($RootStats | Where-Object { $_.volume -eq $v.name })
        if (-not $rs.Count) { continue }
        $agg = [ordered]@{}
        foreach ($k in $sumKeys) { $agg[$k] = [long](($rs | Measure-Object -Property $k -Sum).Sum); $sum[$k] += $agg[$k] }
        $hl = 0L; foreach ($x in $rs) { $hl += [long]$hlByRoot[[int]$x.rootId] }
        $inacc = $agg.denied + $agg.vanished + $agg.otherErrors + $agg.depthCapped
        $volOut.Add([ordered]@{
                name = $v.name; label = $v.label; fileSystem = $v.fileSystem; clusterBytes = $v.clusterBytes
                sizeBytes = $v.sizeBytes; freeBytes = $v.freeBytes; availableBytes = $v.availableBytes; usedBytes = $v.usedBytes
                scannedBytes = $agg.localBytes; scannedFiles = $agg.localFiles; scannedDirs = $agg.dirRows; listedDirs = $agg.dirsListed
                inaccessibleDirs = $inacc; cloudOnlyBytes = $agg.cloudOnlyBytes; cloudOnlyFiles = $agg.cloudOnlyFiles
                reparseDirs = $agg.linkDirs + $agg.otherReparseDirs
                unaccountedBytes = if ($Subset) { $null } else { $v.usedBytes - $agg.localBytes }
                allocEstimateBytes = $agg.allocEstimateBytes
                unaccountedVsAllocEstimateBytes = if ($Subset) { $null } else { $v.usedBytes - $agg.allocEstimateBytes }
                hardlinkHeavyBytes = $hl; sparseBytes = $agg.sparseBytes; compressedBytes = $agg.compressedBytes; reparseFileBytes = $agg.reparseFileBytes
                walkSeconds = [Math]::Round(($rs | Measure-Object -Property seconds -Sum).Sum, 1)
            })
    }
    $usedAll = [long](($volOut | ForEach-Object { $_.usedBytes } | Measure-Object -Sum).Sum)
    $inaccAll = $sum.denied + $sum.vanished + $sum.otherErrors + $sum.depthCapped

    # well-known top-level folders (labels by id; ids were recorded during the walk)
    $wk = @{}
    foreach ($pair in @(@($Ctx.profilesDir, 'Users'), @($Ctx.systemRoot, 'Windows'), @($Ctx.programFiles, 'Program Files'), @($Ctx.programFilesX86, 'Program Files (x86)'), @($Ctx.programData, 'ProgramData'))) {
        if ($pair[0] -and $SpecialIds.ContainsKey($pair[0])) { $wk[$SpecialIds[$pair[0]]] = $pair[1] }
    }
    $topLevel = [Collections.Generic.List[object]]::new()
    foreach ($rid in $RootIds) {
        $named = [Collections.Generic.List[object]]::new()
        $others = [Collections.Generic.List[object]]::new()
        $ob = 0L; $of = 0L; $od = 0L; $oc = 0L
        foreach ($c in (Get-G0Children $rid)) {
            if ($wk.ContainsKey($c)) { $named.Add((New-G0DirItem -Id $c -Name $wk[$c])) }
            else { $others.Add((New-G0DirItem -Id $c -Name $dName[$c])); $ob += $tBytes[$c]; $of += $tFiles[$c]; $od += $tDirs[$c] + 1; $oc += $dCloudB[$c] }
        }
        $others.Add([ordered]@{ name = '(files directly in the root)'; path = Get-G0DirPath $rid; bytes = $dOwnBytes[$rid]; files = $dOwnFiles[$rid]; dirs = 0; cloudOnlyBytes = 0L; newestWriteUtc = $null; flags = '' })
        $ob += $dOwnBytes[$rid]; $of += $dOwnFiles[$rid]
        $topLevel.Add([ordered]@{
                root   = Get-G0DirPath $rid
                bytes  = $tBytes[$rid]; files = $tFiles[$rid]; dirs = $tDirs[$rid]
                items  = @($named | Sort-Object { $_.bytes } -Descending)
                others = [ordered]@{ bytes = $ob; files = $of; dirs = $od; cloudOnlyBytes = $oc; top = @($others | Sort-Object { $_.bytes } -Descending | Select-Object -First 25) }
            })
    }

    # per user profile
    $profilesOut = [Collections.Generic.List[object]]::new()
    $appContainers = [Collections.Generic.List[int]]::new()   # for largestFolders
    if ($Ctx.profilesDir -and $SpecialIds.ContainsKey($Ctx.profilesDir)) {
        foreach ($u in (Get-G0Children $SpecialIds[$Ctx.profilesDir])) {
            if (($dFlags[$u] -band ($F_REPARSE -bor $F_CLOUDONLY)) -ne 0) { continue }
            $items = [Collections.Generic.List[object]]::new()
            foreach ($c in (Get-G0Children $u)) {
                if ($dName[$c] -eq 'AppData' -and $ChildCount[$c] -gt 0) {
                    foreach ($a in (Get-G0Children $c)) { $items.Add((New-G0DirItem -Id $a -Name ('AppData\' + $dName[$a]))); $appContainers.Add($a) }
                    if ($dOwnFiles[$c] -gt 0) { $items.Add([ordered]@{ name = 'AppData (files)'; path = Get-G0DirPath $c; bytes = $dOwnBytes[$c]; files = $dOwnFiles[$c]; dirs = 0; cloudOnlyBytes = 0L; newestWriteUtc = $null; flags = '' }) }
                }
                else { $items.Add((New-G0DirItem -Id $c -Name $dName[$c])) }
            }
            if ($dOwnFiles[$u] -gt 0) { $items.Add([ordered]@{ name = '(files directly in the profile)'; path = Get-G0DirPath $u; bytes = $dOwnBytes[$u]; files = $dOwnFiles[$u]; dirs = 0; cloudOnlyBytes = 0L; newestWriteUtc = $null; flags = '' }) }
            $pi = New-G0DirItem -Id $u -Name $dName[$u]
            $pi.accessible = (($dFlags[$u] -band $F_INACCESSIBLE) -eq 0)
            $pi.currentUser = ($Ctx.currentProfile -and $SpecialIds.ContainsKey($Ctx.currentProfile) -and $SpecialIds[$Ctx.currentProfile] -eq $u)
            $pi.items = @($items | Sort-Object { $_.bytes } -Descending)
            $profilesOut.Add($pi)
        }
    }

    # largest folders at "application / project" granularity: children of the drive roots, Windows,
    # Program Files (x86), ProgramData, each profile and each profile's AppData\Local|Roaming|LocalLow
    # (containers themselves are expanded, so the list never counts the same bytes twice)
    $expand = [Collections.Generic.HashSet[int]]::new()
    foreach ($rid in $RootIds) { [void]$expand.Add($rid) }
    foreach ($k in $wk.Keys) { [void]$expand.Add([int]$k) }
    if ($Ctx.profilesDir -and $SpecialIds.ContainsKey($Ctx.profilesDir)) {
        foreach ($u in (Get-G0Children $SpecialIds[$Ctx.profilesDir])) {
            [void]$expand.Add($u)
            foreach ($c in (Get-G0Children $u)) { if ($dName[$c] -eq 'AppData') { [void]$expand.Add($c) } }
        }
    }
    foreach ($a in $appContainers) { [void]$expand.Add($a) }
    $cands = [Collections.Generic.List[int]]::new()
    foreach ($x in $expand) { foreach ($c in (Get-G0Children $x)) { if (-not $expand.Contains($c)) { $cands.Add($c) } } }
    $largestFolders = @($cands | Sort-Object { $tBytes[$_] } -Descending | Select-Object -First 30 | ForEach-Object { New-G0DirItem -Id $_ -Name $dName[$_] })
    # folders holding the most bytes directly (non-overlapping by definition); array sort, no pipeline over all dirs
    $byOwn = [Collections.Generic.List[object]]::new()
    if ($DirCount -gt 0) {
        $ka = [long[]]::new($DirCount); $ia = [int[]]::new($DirCount)
        for ($i = 0; $i -lt $DirCount; $i++) { $ka[$i] = - $dOwnBytes[$i]; $ia[$i] = $i }
        [Array]::Sort($ka, $ia)
        for ($j = 0; $j -lt [Math]::Min(20, $DirCount); $j++) {
            $i = $ia[$j]
            if ($dOwnBytes[$i] -le 0) { break }
            $byOwn.Add([ordered]@{ path = Get-G0DirPath $i; ownBytes = $dOwnBytes[$i]; ownFiles = $dOwnFiles[$i] })
        }
    }
    $lf = [Collections.Generic.List[int]]::new(); $lk = [Collections.Generic.List[long]]::new()
    for ($i = 0; $i -lt $SelCount; $i++) { if (($sReason[$i] -band 1) -ne 0) { $lf.Add($i); $lk.Add(- $sSize[$i]) } }
    $lfa = $lf.ToArray(); $lka = $lk.ToArray()
    [Array]::Sort($lka, $lfa)
    $largestFiles = [Collections.Generic.List[object]]::new()
    for ($j = 0; $j -lt [Math]::Min(25, $lfa.Length); $j++) {
        $i = $lfa[$j]
        $dp = Get-G0DirPath $sDir[$i]
        $largestFiles.Add([ordered]@{ path = $(if ($dp.EndsWith($BS)) { $dp + $sName[$i] } else { $dp + '\' + $sName[$i] }); sizeBytes = $sSize[$i]; allocBytes = $sAlloc[$i]; attributes = '0x' + $sAttr[$i].ToString('X') })
    }
    $uniqueSel = $SelCount

    # OneDrive summary (top-most onedrive folders)
    $odLocal = 0L; $odCloudB = 0L; $odCloudF = 0L; $odRoots = [Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $DirCount; $i++) {
        if (($dFlags[$i] -band $B_ONEDRIVE) -eq 0) { continue }
        $p = $dParent[$i]
        if ($p -ge 0 -and ($dFlags[$p] -band $B_ONEDRIVE) -ne 0) { continue }
        $odLocal += $tBytes[$i]; $odCloudB += $dCloudB[$i]; $odCloudF += $dCloudF[$i]; $odRoots.Add((Get-G0DirPath $i))
    }

    $finished = [datetime]::UtcNow
    $m = [ordered]@{
        schema       = 'bvs.inventory-meta/1'
        module       = 'G0'
        scanId       = $run.ScanId
        host         = $env:COMPUTERNAME
        platform     = 'windows'
        elevated     = $run.Elevated
        scope        = if ($Subset) { 'subset' } else { 'full' }
        roots        = @($RootIds | ForEach-Object { Get-G0DirPath $_ })
        referenceUtc = $RefUtc.ToString('o')
        started      = $ScriptStart.ToString('o')
        finished     = $finished.ToString('o')
        durationSec  = [Math]::Round(($finished - $ScriptStart).TotalSeconds, 1)
        walkSec      = [Math]::Round($walkSw.Elapsed.TotalSeconds, 1)
        enumeration  = [ordered]@{
            api                = 'System.IO.DirectoryInfo.EnumerateFileSystemInfos (EnumerationOptions, manual stack)'
            attributesToSkip   = 'None: Hidden/System included; reparse points classified explicitly (OneDrive items carry the ReparsePoint attribute)'
            ignoreInaccessible = $false
            bufferSize         = $EnumOpts.BufferSize
            reparsePolicy      = 'junctions, symbolic links and mount points (LinkTarget not null) are never followed; cloud-sync placeholder folders are walked unless cloud-only; other non-link reparse folders outside a sync root are not walked'
            cloudPolicy        = 'cloud-only placeholders (0x400000/0x40000/0x1000) are never opened; their logical size is counted in cloudOnlyBytes, not in own/total bytes'
            contentRead        = $false
            hashing            = $false
            coldReference      = 'LastWriteTime (LastAccessTime is not used: Windows often does not update it)'
        }
        volumes      = @($volOut)
        unletteredVolumesNotScanned = @($Unlettered)
        totals       = [ordered]@{
            usedBytes          = $usedAll
            scannedBytes       = $sum.localBytes
            scannedFiles       = $sum.localFiles
            scannedDirs        = $sum.dirRows
            listedDirs         = $sum.dirsListed
            inaccessibleDirs   = $inaccAll
            inaccessibleDetail = [ordered]@{ accessDenied = $sum.denied; vanishedDuringScan = $sum.vanished; otherErrors = $sum.otherErrors; depthCapped = $sum.depthCapped }
            reparseDirs        = $sum.linkDirs + $sum.otherReparseDirs
            reparseDetail      = [ordered]@{ links = $sum.linkDirs; otherNonLink = $sum.otherReparseDirs; linkTargetErrors = $sum.linkTargetErrors }
            cloudOnlyBytes     = $sum.cloudOnlyBytes
            cloudOnlyFiles     = $sum.cloudOnlyFiles
            cloudOnlyDirs      = $sum.cloudOnlyDirs
            unaccountedBytes   = if ($Subset) { $null } else { $usedAll - $sum.localBytes }
            allocEstimateBytes = $sum.allocEstimateBytes
            selectedFiles      = $uniqueSel
            selectedFileRows   = $FileRows
        }
        oneDrive     = [ordered]@{ roots = @($odRoots); localBytes = $odLocal; cloudOnlyBytes = $odCloudB; cloudOnlyFiles = $odCloudF }
        topLevel     = @($topLevel)
        userProfiles = @($profilesOut)
        largestFolders        = $largestFolders
        largestDirsByOwnBytes = @($byOwn)
        largestFiles          = @($largestFiles)
        selectedFileRowsByReason = $FileRowCounts
        userWritableRoots     = @($UwHits | ForEach-Object { Get-G0DirPath $_ })
        inaccessibleSample    = @($InaccIds | Select-Object -First 60 | ForEach-Object { Get-G0DirPath $_ })
        otherReparseSample    = @($OddReparseIds | Select-Object -First 30 | ForEach-Object { Get-G0DirPath $_ })
        errorSample           = @($ErrSamples)
        masking               = $MaskStats
        outputs               = [ordered]@{ dirs = 'dirs.tsv'; files = 'files.tsv'; dirRows = $DirRows; fileRows = $FileRows }
        notes                 = @(
            'unaccountedBytes = usedBytes - scannedBytes. scannedBytes is the logical size of local files; it excludes cloud-only placeholders.'
            'Why it is not zero: folders that could not be listed (System Volume Information / VSS shadow copies, other profiles, protected system folders), NTFS metadata ($MFT, $LogFile, $UsnJrnl), cluster slack (see allocEstimateBytes) and files changed during the scan.'
            'It can even be negative: hard links are counted once per link (WinSxS / pnpm, see hardlinkHeavyBytes), and sparse/compressed files occupy fewer clusters than their logical size.'
            'allocEstimateBytes rounds every local file up to whole clusters; it ignores MFT-resident tiny files, compression and sparseness.'
            'Directory sizes come from directory-index entries (what Explorer shows); a hard-linked file can show a stale size on its other links.'
        )
    }
    $p = Write-BvsJson -InputObject $m -Path (Join-Path $outDir 'inventory-meta.json')
    Write-BvsLog -Run $run -Message "meta written: $p"
    $m
}

#endregion

#region ---------- envelope + console summary ----------

if ($Meta) {
    $sumVolumes = [Collections.Generic.List[object]]::new()
    foreach ($v in $Meta.volumes) {
        $sumVolumes.Add([ordered]@{ name = $v.name; sizeBytes = $v.sizeBytes; usedBytes = $v.usedBytes; freeBytes = $v.freeBytes; scannedBytes = $v.scannedBytes; unaccountedBytes = $v.unaccountedBytes; inaccessibleDirs = $v.inaccessibleDirs; cloudOnlyBytes = $v.cloudOnlyBytes })
    }
    $sumTop = [Collections.Generic.List[object]]::new()
    foreach ($tl in $Meta.topLevel) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($it in $tl.items) { $items.Add([ordered]@{ name = $it.name; path = $it.path; bytes = $it.bytes; files = $it.files }) }
        $sumTop.Add([ordered]@{ root = $tl.root; bytes = $tl.bytes; items = @($items); othersBytes = $tl.others.bytes })
    }
    $sumLargest = [Collections.Generic.List[object]]::new()
    foreach ($f in @($Meta.largestFolders | Select-Object -First 15)) { $sumLargest.Add([ordered]@{ path = $f.path; bytes = $f.bytes; files = $f.files }) }
    Add-BvsInventory -Run $run -Name 'summary' -Data ([ordered]@{
            scope            = $Meta.scope
            roots            = $Meta.roots
            durationSec      = $Meta.durationSec
            walkSec          = $Meta.walkSec
            totals           = $Meta.totals
            volumes          = @($sumVolumes)
            topLevel         = @($sumTop)
            largestFolders   = @($sumLargest)
            selectedFileRows = $Meta.selectedFileRowsByReason
            outputs          = [ordered]@{ dirs = (Join-Path $outDir 'dirs.tsv'); files = (Join-Path $outDir 'files.tsv'); meta = (Join-Path $outDir 'inventory-meta.json') }
        })
}
$done = Complete-BvsRun -Run $run

function Format-G0Size([long]$B) { if ($B -ge 1GB) { '{0} GB' -f [Math]::Round($B / 1GB, 1).ToString($Inv) } elseif ($B -ge 1MB) { '{0} MB' -f [Math]::Round($B / 1MB, 1).ToString($Inv) } else { "$B B" } }
$lines = [Collections.Generic.List[string]]::new()
$lines.Add("G0 inventory ($(if ($Subset) { 'subset' } else { 'full' })) -> $outDir")
if ($Meta) {
    $t = $Meta.totals
    $lines.Add(('duration {0}s (walk {1}s) | dirs {2} (listed {3}, inaccessible {4}, reparse {5}) | files {6}' -f $Meta.durationSec, $Meta.walkSec, $t.scannedDirs, $t.listedDirs, $t.inaccessibleDirs, $t.reparseDirs, $t.scannedFiles))
    foreach ($v in $Meta.volumes) {
        $lines.Add(('{0} size {1} used {2} free {3} | scanned {4} | unaccounted {5} | alloc-est {6} | hardlink-heavy {7}' -f $v.name, (Format-G0Size $v.sizeBytes), (Format-G0Size $v.usedBytes), (Format-G0Size $v.freeBytes), (Format-G0Size $v.scannedBytes), $(if ($null -ne $v.unaccountedBytes) { Format-G0Size $v.unaccountedBytes } else { 'n/a (subset)' }), (Format-G0Size $v.allocEstimateBytes), (Format-G0Size $v.hardlinkHeavyBytes)))
    }
    $lines.Add(('cloud-only {0} in {1} files | selected rows: {2}' -f (Format-G0Size $t.cloudOnlyBytes), $t.cloudOnlyFiles, (($Meta.selectedFileRowsByReason.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')))
    $lines.Add('largest folders:')
    foreach ($f in @($Meta.largestFolders | Select-Object -First 10)) { $lines.Add(('  {0,10}  {1}' -f (Format-G0Size $f.bytes), $f.path)) }
}
$lines.Add("envelope: $($done.Path) (checks=$($done.Checks), errors=$($done.Errors))")
foreach ($l in $lines) { Protect-BvsText $l }

#endregion
