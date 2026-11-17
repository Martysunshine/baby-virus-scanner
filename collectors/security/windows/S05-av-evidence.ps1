#Requires -Version 7.2
<#
.SYNOPSIS
    S05 - Antivirus evidence: what the installed security products have already seen.

.DESCRIPTION
    Read-only collector. It never runs a scanner, never opens quarantined files and never changes a
    setting. Sources:
      * Avast / AVG (same Gen Digital engine and on-disk layout)
          report\*.txt            shield reports: date, shield, detection, object (file/URL), action
          chest\index.xml         Virus Chest index (metadata only)
          log\detections.log      detection-UI events: user choices, rootkit/anti-exploit prompts
          Log.db                  scan sessions, scan results, infection statistics
                                  (built-in read-only SQLite reader, works on an in-memory copy)
          log\*.log               keyword grep: infection / threat / detection / blocked ...
          log\autosandbox.log     Auto-Sandbox decisions and exception-list hits
          log\aswAr*.log, UEFI    anti-rootkit and UEFI scan results
          registry properties\..  shields, passive/silent mode, exclusions, scan tasks; defs\aswdefs.ini
      * Microsoft Malicious Software Removal Tool   %windir%\debug\mrt.log
      * Microsoft Defender                          Get-MpThreatDetection / Get-MpThreat,
                                                    Operational log 1006-1008, 1015, 1116-1119
      * Microsoft Safety Scanner                    %windir%\debug\msert.log, data\<scan>\admin\msert-*.log
      * Windows Security Center                     root\SecurityCenter2 products, decoded productState
    Heuristics (type maps, false-positive hints, keyword lists) live in S05-av-heuristics.json.
    Re-runnable: run it again after msert has finished; the envelope is rewritten.

.NOTES
    Contract: docs\schema.md   Rules: docs\agent-rules.md   Playbook: docs\playbooks\S05-av-evidence.md
    Run:      pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S05-av-evidence.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$run = Initialize-BvsRun -Module S05 -Area security
$BvsRoot = Get-BvsRoot
$Inv = [Globalization.CultureInfo]::InvariantCulture
$SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

$S05 = @{
    Heur         = $null
    HeurError    = $null
    Gen          = [System.Collections.Generic.List[object]]::new()
    Detections   = [System.Collections.Generic.List[object]]::new()
    Chest        = [System.Collections.Generic.List[object]]::new()
    ReportFiles  = [System.Collections.Generic.List[object]]::new()
    DetLog       = [System.Collections.Generic.List[object]]::new()
    Sessions     = [System.Collections.Generic.List[object]]::new()
    InfectedHist = [System.Collections.Generic.List[object]]::new()
    LogDbResults = [System.Collections.Generic.List[object]]::new()
    LogDbInfo    = [System.Collections.Generic.List[object]]::new()
    Exclusions   = [System.Collections.Generic.List[object]]::new()
    Shields      = [System.Collections.Generic.List[object]]::new()
    Features     = [System.Collections.Generic.List[object]]::new()
    Tasks        = [System.Collections.Generic.List[object]]::new()
    TaskMap      = @{}
    Definitions  = [System.Collections.Generic.List[object]]::new()
    LogGrep      = [System.Collections.Generic.List[object]]::new()
    LogNotable   = [System.Collections.Generic.List[object]]::new()
    Autosandbox  = [System.Collections.Generic.List[object]]::new()
    AntiRootkit  = [System.Collections.Generic.List[object]]::new()
    Uefi         = [System.Collections.Generic.List[object]]::new()
    Removed      = [System.Collections.Generic.List[object]]::new()
    MsrtRuns     = [System.Collections.Generic.List[object]]::new()
    MsertRuns    = [System.Collections.Generic.List[object]]::new()
    MsertSources = [System.Collections.Generic.List[object]]::new()
    Defender     = [ordered]@{}
    Wsc          = [System.Collections.Generic.List[object]]::new()
    OwnPaths     = @()
    IntelHosts   = @()
}

#region ---------- generic helpers ----------

function Get-S05Heur {
    param([Parameter(Mandatory)][string]$Name)
    if ($null -ne $S05.Heur -and $S05.Heur.PSObject.Properties[$Name]) { return $S05.Heur.$Name }
    $null
}

function Format-S05Utc {
    param([AllowNull()][object]$Date)
    if ($null -eq $Date) { return $null }
    try { ([datetime]$Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $Inv) } catch { $null }
}

function ConvertFrom-S05Unix {
    param([object]$Seconds)
    try { [DateTimeOffset]::FromUnixTimeSeconds([long]$Seconds).UtcDateTime } catch { $null }
}

function ConvertFrom-S05UnixLocalWall {
    # Some Avast tables store local wall-clock time as "seconds since 1970".
    param([object]$Seconds)
    try { [datetime]::SpecifyKind([datetime]::new(1970, 1, 1).AddSeconds([long]$Seconds), [DateTimeKind]::Local).ToUniversalTime() } catch { $null }
}

function ConvertFrom-S05FileTime {
    param([object]$Value)
    try { $v = [long]$Value; if ($v -le 0) { return $null }; [datetime]::FromFileTimeUtc($v) } catch { $null }
}

function Get-S05Trunc {
    param([AllowNull()][string]$Text, [int]$Max = 240)
    if ($null -eq $Text) { return $null }
    $t = $Text.Trim()
    if ($t.Length -gt $Max) { $t.Substring(0, $Max) + [char]0x2026 } else { $t }
}

function Read-S05Bytes {
    # Shared read (the AV keeps its files open). Never used on quarantined content.
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 64MB)
    $info = [IO.FileInfo]::new($Path)
    if (-not $info.Exists) { return $null }
    if ($info.Length -gt $MaxBytes) { throw "file larger than $MaxBytes bytes: $Path" }
    $fs = [IO.FileStream]::new($info.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    try { $ms = [IO.MemoryStream]::new(); $fs.CopyTo($ms); , $ms.ToArray() } finally { $fs.Dispose() }
}

function ConvertFrom-S05Bytes {
    # BOM / UTF-16 / strict UTF-8 detection, then the given ANSI code page (Avast writes reports in the
    # code page of its UI language, which can differ from the system code page).
    param([AllowNull()][byte[]]$Bytes, [int]$CodePage = 0)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return [pscustomobject]@{ Text = ''; Encoding = 'empty' } }
    $n = $Bytes.Length
    if ($n -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [pscustomobject]@{ Text = [Text.Encoding]::Unicode.GetString($Bytes, 2, $n - 2); Encoding = 'utf-16le' } }
    if ($n -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { return [pscustomobject]@{ Text = [Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $n - 2); Encoding = 'utf-16be' } }
    if ($n -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [pscustomobject]@{ Text = [Text.Encoding]::UTF8.GetString($Bytes, 3, $n - 3); Encoding = 'utf-8-bom' } }
    if ($n -ge 4 -and $Bytes[0] -ne 0 -and $Bytes[1] -eq 0 -and $Bytes[2] -ne 0 -and $Bytes[3] -eq 0) { return [pscustomobject]@{ Text = [Text.Encoding]::Unicode.GetString($Bytes); Encoding = 'utf-16le-nobom' } }
    try { return [pscustomobject]@{ Text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes); Encoding = 'utf-8' } } catch { }
    $cp = if ($CodePage -gt 0) { $CodePage } else { Get-S05SystemCodePage }
    $enc = try { [Text.Encoding]::GetEncoding($cp) } catch { [Text.Encoding]::Latin1 }
    [pscustomobject]@{ Text = $enc.GetString($Bytes); Encoding = "cp$cp" }
}

function Read-S05Text {
    param([Parameter(Mandatory)][string]$Path, [int]$CodePage = 0, [long]$MaxBytes = 64MB)
    $b = Read-S05Bytes -Path $Path -MaxBytes $MaxBytes
    if ($null -eq $b) { return $null }
    ConvertFrom-S05Bytes -Bytes $b -CodePage $CodePage
}

function Get-S05RegMap {
    param([string]$Path)
    $m = @{}
    if (-not $Path) { return $m }
    try { foreach ($v in @(Get-BvsRegValues -Path $Path)) { $m[$v.Name] = $v.Value } } catch { }
    $m
}

$script:S05SystemCp = $null
function Get-S05SystemCodePage {
    if ($null -eq $script:S05SystemCp) {
        $acp = (Get-S05RegMap 'HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage')['ACP']
        $script:S05SystemCp = if ("$acp" -match '^\d+$') { [int]$acp } else { [Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage }
    }
    $script:S05SystemCp
}

function ConvertFrom-S05LocalStamp {
    # Avast report/autosandbox stamps: local time in the UI language's short format.
    param([string]$Text, [Globalization.CultureInfo]$Culture)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $s = ($Text -replace '\s+', ' ').Trim()
    $st = [Globalization.DateTimeStyles]::AllowWhiteSpaces
    $dt = [datetime]::MinValue
    $dayFirst = -not ($Culture -and $Culture.DateTimeFormat.ShortDatePattern -match '^\s*M')
    $fmts = [System.Collections.Generic.List[string]]::new()
    foreach ($f in 'd.M.yyyy H:mm:ss', 'd.M.yyyy. H:mm:ss', 'd. M. yyyy H:mm:ss', 'd. M. yyyy. H:mm:ss', 'yyyy-M-d H:mm:ss', 'yyyy.M.d. H:mm:ss', 'yyyy.M.d H:mm:ss', 'yyyy/M/d H:mm:ss', 'd.M.yyyy H:mm') { $fmts.Add($f) }
    if ($s -match '(?i)\b[AP]\.?\s?M\.?$') {
        $s = $s -replace '(?i)\b([AP])\.?\s?M\.?$', '$1M'
        foreach ($f in 'M/d/yyyy h:mm:ss tt', 'd/M/yyyy h:mm:ss tt', 'yyyy-M-d h:mm:ss tt') { $fmts.Add($f) }
    }
    elseif ($dayFirst) { foreach ($f in 'd/M/yyyy H:mm:ss', 'M/d/yyyy H:mm:ss', 'd-M-yyyy H:mm:ss') { $fmts.Add($f) } }
    else { foreach ($f in 'M/d/yyyy H:mm:ss', 'd/M/yyyy H:mm:ss', 'M-d-yyyy H:mm:ss') { $fmts.Add($f) } }
    if ([datetime]::TryParseExact($s, [string[]]$fmts, $Inv, $st, [ref]$dt)) { return [datetime]::SpecifyKind($dt, [DateTimeKind]::Local).ToUniversalTime() }
    foreach ($c in @($Culture, [Globalization.CultureInfo]::CurrentCulture)) {
        if ($c -and [datetime]::TryParse($s, $c, $st, [ref]$dt)) { return [datetime]::SpecifyKind($dt, [DateTimeKind]::Local).ToUniversalTime() }
    }
    $null
}

function ConvertFrom-S05EnglishStamp {
    # MSRT / msert: "Wed Nov 13 16:16:00 2024" (local time, invariant English names).
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(?<mon>[A-Za-z]{3})[a-z]*\s+(?<d>\d{1,2}),?\s+(?<t>\d{1,2}:\d{2}:\d{2})\s+(?<y>\d{4})')
    if (-not $m.Success) { return $null }
    $s = '{0} {1} {2} {3}' -f $m.Groups['mon'].Value, $m.Groups['d'].Value, $m.Groups['t'].Value, $m.Groups['y'].Value
    $dt = [datetime]::MinValue
    if ([datetime]::TryParseExact($s, 'MMM d H:mm:ss yyyy', $Inv, [Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$dt)) {
        return [datetime]::SpecifyKind($dt, [DateTimeKind]::Local).ToUniversalTime()
    }
    $null
}

function Test-S05UnderPath {
    param([string]$Path, [string[]]$Roots)
    if (-not $Path) { return $false }
    foreach ($r in $Roots) {
        if (-not $r) { continue }
        $root = $r.TrimEnd('\')
        if ($Path.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function Get-S05UrlHost {
    param([string]$Url)
    if (-not $Url) { return $null }
    $m = [regex]::Match($Url, '^(?i)[a-z][a-z0-9+.\-]*://(?:[^/@\s]*@)?(?<h>\[[^\]]+\]|[^/:?#\s]+)')
    if ($m.Success) { $m.Groups['h'].Value.ToLowerInvariant() } else { $null }
}

function Test-S05HostIn {
    param([string]$HostName, [object[]]$List)
    if (-not $HostName) { return $false }
    foreach ($h in $List) {
        if (-not $h) { continue }
        $x = ([string]$h).ToLowerInvariant()
        if ($HostName -eq $x -or $HostName.EndsWith('.' + $x)) { return $true }
    }
    $false
}

function Split-S05DetectionName {
    # "MacOS:Agent-BR [Trj]" -> name, type
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @('', $null) }
    $m = [regex]::Match($Raw.Trim(), '^(?<n>.+?)\s*\[(?<t>[^\]]{1,24})\]\s*$')
    if ($m.Success) { return @($m.Groups['n'].Value.Trim(), $m.Groups['t'].Value.Trim()) }
    @($Raw.Trim(), $null)
}

function Get-S05Category {
    param([string]$Name, [string]$Type, [ValidateSet('avast', 'microsoft')][string]$Vendor = 'avast')
    if (-not $Name) { return 'unknown' }
    if ($Name -match '^(?i)URL:') { return 'url' }
    if ($Vendor -eq 'microsoft') {
        $m = [regex]::Match($Name, '^(?<t>[A-Za-z]+):')
        if ($m.Success) {
            $map = Get-S05Heur 'msTypeMap'
            $t = $m.Groups['t'].Value
            if ($map -and $map.PSObject.Properties[$t]) { return [string]$map.$t }
        }
    }
    foreach ($r in @(Get-S05Heur 'nameCategoryRules')) { if ($r -and $Name -match $r.pattern) { return [string]$r.category } }
    if ($Type) {
        $map = Get-S05Heur 'avastTypeMap'
        if ($map -and $map.PSObject.Properties[$Type]) { return [string]$map.$Type }
    }
    'malware'
}

function Get-S05ActionFromText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    foreach ($a in @(Get-S05Heur 'avastActionPatterns')) { if ($a -and $Text -match $a.pattern) { return [string]$a.action } }
    'other'
}

function Get-S05NotableNotes {
    param([string[]]$Names)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @(Get-S05Heur 'notableFamilies')) {
        if (-not $f) { continue }
        $hit = @($Names | Where-Object { $_ -match $f.pattern } | Select-Object -Unique)
        if ($hit.Count) { $out.Add([ordered]@{ families = $hit; note = $f.note; check = $f.check }) }
    }
    $out
}

function Get-S05FpHints {
    param([string]$Path, [string]$Name, [string]$Url)
    $hints = [System.Collections.Generic.List[string]]::new()
    if ($Path) {
        $ext = ''
        try { $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant() } catch { }
        if (@(Get-S05Heur 'docExtensions') -contains $ext) { $hints.Add('doc_content') }
        foreach ($m in @(Get-S05Heur 'securityCorpusMarkers')) { if ($m -and $Path -match $m) { $hints.Add('security_corpus'); break } }
        foreach ($m in @(Get-S05Heur 'devCacheMarkers')) { if ($m -and $Path -match $m) { $hints.Add('dev_cache'); break } }
        foreach ($e in @(Get-BvsExpected -Category path)) {
            if ($e.id -eq 'this-project') { continue }
            $roots = @($e.match.paths | ForEach-Object { [Environment]::ExpandEnvironmentVariables([string]$_) })
            if (Test-S05UnderPath -Path $Path -Roots $roots) { $hints.Add("expected_path:$($e.id)"); break }
        }
    }
    if ($Name) { foreach ($g in @(Get-S05Heur 'genericHeuristicNames')) { if ($g -and $Name -match $g.pattern) { $hints.Add('generic_heuristic'); break } } }
    if ($Url) { if (Test-S05HostIn -HostName (Get-S05UrlHost $Url) -List @(Get-S05Heur 'contentPlatformHosts')) { $hints.Add('content_platform') } }
    , @($hints)
}

function New-S05Detection {
    # One row of the shared 'detections' inventory table (platform-neutral shape).
    param(
        [Parameter(Mandatory)][string]$Source, [string]$Product, [string]$Shield, [AllowNull()][object]$DateUtc,
        [string]$RawName, [string]$Vendor = 'avast', [string]$ObjectText, [string]$Path, [string]$Url,
        [string]$Inner, [string]$Action, [string]$ActionDetail, [string]$ActionSource
    )
    $split = Split-S05DetectionName $RawName
    $name = $split[0]; $type = $split[1]
    if ($Vendor -eq 'microsoft' -and -not $type -and $name -match '^(?<t>[A-Za-z]+):') { $type = $Matches.t }
    $kind = if ($Path) { 'file' } elseif ($Url) { 'url' } else { 'other' }
    $ext = $null
    if ($Path) { try { $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant() } catch { } }
    $hostName = Get-S05UrlHost $Url
    $own = $false
    if ($Path -and (Test-S05UnderPath -Path $Path -Roots $S05.OwnPaths)) { $own = $true }
    if ($Url -and $null -ne $DateUtc -and ([datetime]$DateUtc) -ge $run.AuditStartUtc -and (Test-S05HostIn -HostName $hostName -List $S05.IntelHosts)) { $own = $true }
    [ordered]@{
        source                  = $Source
        product                 = $Product
        shield                  = $Shield
        date                    = Format-S05Utc $DateUtc
        name                    = $name
        type                    = $type
        category                = Get-S05Category -Name $name -Type $type -Vendor $Vendor
        objectKind              = $kind
        path                    = $Path
        url                     = $Url
        host                    = $hostName
        object                  = if ($kind -eq 'other') { Get-S05Trunc (Protect-BvsText $ObjectText) 200 } else { $null }
        inner                   = $Inner
        extension               = $ext
        action                  = $Action
        actionDetail            = $ActionDetail
        actionSource            = $ActionSource
        stillPresent            = $null
        fileModifiedUtc         = $null
        recreatedAfterDetection = $null
        chestId                 = $null
        confirmedBy             = [System.Collections.Generic.List[string]]::new()
        fpHints                 = (Get-S05FpHints -Path $Path -Name $name -Url $Url)
        ownActivity             = $own
        assessment              = $null
        facts                   = $null
        _dt                     = if ($null -ne $DateUtc) { ([datetime]$DateUtc).ToUniversalTime() } else { $null }
    }
}

function ConvertTo-S05Public {
    # Drop internal keys (prefixed with '_') before a row goes into the envelope.
    param($Row)
    $o = [ordered]@{}
    foreach ($k in $Row.Keys) { if (-not "$k".StartsWith('_')) { $o[$k] = $Row[$k] } }
    $o
}

function Get-S05Range {
    param([object[]]$Rows)
    $d = @($Rows | Where-Object { $_.date } | ForEach-Object { $_.date } | Sort-Object)
    if (-not $d.Count) { return [ordered]@{ first = $null; last = $null } }
    [ordered]@{ first = $d[0]; last = $d[-1] }
}

function Get-S05DateOnly {
    param([string]$Iso)
    if ($Iso -and $Iso.Length -ge 10) { $Iso.Substring(0, 10) } else { $Iso }
}

function Get-S05NameSummary {
    param([object[]]$Rows, [int]$Top = 8)
    (@($Rows | Group-Object { $_.name } | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', ')
}

function Limit-S05Severity {
    param([string]$Severity, [string]$Cap)
    if ($Cap -and $SevRank.ContainsKey($Cap) -and $SevRank[$Severity] -gt $SevRank[$Cap]) { return $Cap }
    $Severity
}

function Get-S05MaxSeverity {
    param([string[]]$Severities)
    $best = 'info'
    foreach ($s in $Severities) { if ($s -and $SevRank[$s] -gt $SevRank[$best]) { $best = $s } }
    $best
}

#endregion

#region ---------- read-only SQLite reader (in-memory; no native code, no temp copies) ----------

function Get-S05BE {
    param([byte[]]$B, [int]$Pos, [int]$N)
    [long]$v = 0
    for ($i = 0; $i -lt $N; $i++) { $v = ($v -shl 8) -bor [long]$B[$Pos + $i] }
    $v
}

function Read-S05Varint {
    param([byte[]]$B, [int]$Pos)
    [long]$v = 0
    for ($i = 0; $i -lt 8; $i++) {
        $c = [long]$B[$Pos + $i]
        $v = ($v -shl 7) -bor ($c -band 0x7F)
        if (($c -band 0x80) -eq 0) { return , @($v, ($i + 1)) }
    }
    $v = ($v -shl 8) -bor [long]$B[$Pos + 8]
    , @($v, 9)
}

function ConvertFrom-S05SqliteRecord {
    param($Db, [byte[]]$P)
    $r = Read-S05Varint $P 0
    $hdrLen = [int]$r[0]; $pos = [int]$r[1]
    $types = [System.Collections.Generic.List[long]]::new()
    while ($pos -lt $hdrLen) { $t = Read-S05Varint $P $pos; $types.Add($t[0]); $pos += [int]$t[1] }
    $d = $hdrLen
    $vals = [object[]]::new($types.Count)
    for ($i = 0; $i -lt $types.Count; $i++) {
        $t = $types[$i]
        if ($t -eq 0) { $vals[$i] = $null }
        elseif ($t -ge 1 -and $t -le 6) {
            $len = (0, 1, 2, 3, 4, 6, 8)[[int]$t]
            $v = Get-S05BE $P $d $len
            if ($len -lt 8) { $bits = 8 * $len; if (($v -shr ($bits - 1)) -band 1) { $v -= ([long]1 -shl $bits) } }
            $vals[$i] = $v; $d += $len
        }
        elseif ($t -eq 7) { $tmp = [byte[]]::new(8); [Array]::Copy($P, $d, $tmp, 0, 8); [Array]::Reverse($tmp); $vals[$i] = [BitConverter]::ToDouble($tmp, 0); $d += 8 }
        elseif ($t -eq 8) { $vals[$i] = [long]0 }
        elseif ($t -eq 9) { $vals[$i] = [long]1 }
        elseif ($t -ge 12) {
            if (($t % 2) -eq 0) { $len = [int](($t - 12) / 2); $blob = [byte[]]::new($len); [Array]::Copy($P, $d, $blob, 0, $len); $vals[$i] = $blob }
            else { $len = [int](($t - 13) / 2); $vals[$i] = $Db.Encoding.GetString($P, $d, $len) }
            $d += $len
        }
    }
    , $vals
}

function Get-S05SqliteRecords {
    param($Db, [int]$RootPage)
    $b = $Db.Bytes; $ps = $Db.PageSize; $U = $Db.Usable
    $X = $U - 35
    $M = [int][Math]::Floor(($U - 12) * 32 / 255) - 23
    $visited = [System.Collections.Generic.HashSet[int]]::new()
    $stack = [System.Collections.Generic.Stack[int]]::new()
    $stack.Push($RootPage)
    while ($stack.Count -gt 0) {
        $pg = $stack.Pop()
        if ($pg -lt 1 -or $pg -gt $Db.PageCount -or -not $visited.Add($pg)) { continue }
        $off = ($pg - 1) * $ps
        $h = if ($pg -eq 1) { $off + 100 } else { $off }
        $kind = $b[$h]
        $n = [int](Get-S05BE $b ($h + 3) 2)
        if ($kind -eq 0x05) {
            $kids = [System.Collections.Generic.List[int]]::new()
            for ($i = 0; $i -lt $n; $i++) { $cp = $off + [int](Get-S05BE $b ($h + 12 + 2 * $i) 2); $kids.Add([int](Get-S05BE $b $cp 4)) }
            $kids.Add([int](Get-S05BE $b ($h + 8) 4))
            for ($i = $kids.Count - 1; $i -ge 0; $i--) { $stack.Push($kids[$i]) }
        }
        elseif ($kind -eq 0x0D) {
            for ($i = 0; $i -lt $n; $i++) {
                try {
                    $cp = $off + [int](Get-S05BE $b ($h + 8 + 2 * $i) 2)
                    $r1 = Read-S05Varint $b $cp; $plen = [long]$r1[0]; $cp += [int]$r1[1]
                    $r2 = Read-S05Varint $b $cp; $rowid = [long]$r2[0]; $cp += [int]$r2[1]
                    if ($plen -le $X) { $local = $plen; $ovf = 0 }
                    else {
                        $K = $M + (($plen - $M) % ($U - 4))
                        $local = if ($K -le $X) { $K } else { $M }
                        $ovf = [int](Get-S05BE $b ($cp + $local) 4)
                    }
                    $payload = [byte[]]::new($plen)
                    [Array]::Copy($b, $cp, $payload, 0, $local)
                    $got = [long]$local; $guard = 0
                    while ($ovf -ne 0 -and $got -lt $plen -and $guard -lt 1000000) {
                        $o = ($ovf - 1) * $ps
                        $next = [int](Get-S05BE $b $o 4)
                        $take = [Math]::Min($plen - $got, $U - 4)
                        [Array]::Copy($b, $o + 4, $payload, $got, $take)
                        $got += $take; $ovf = $next; $guard++
                    }
                    [pscustomobject]@{ RowId = $rowid; Values = (ConvertFrom-S05SqliteRecord -Db $Db -P $payload) }
                }
                catch { continue }
            }
        }
    }
}

function Open-S05Sqlite {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -lt 512 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 15) -ne 'SQLite format 3') { throw 'not a SQLite 3 database' }
    $ps = [int](Get-S05BE $Bytes 16 2); if ($ps -eq 1) { $ps = 65536 }
    if ($ps -lt 512 -or ($ps -band ($ps - 1)) -ne 0) { throw "invalid SQLite page size $ps" }
    $enc = switch ([int](Get-S05BE $Bytes 56 4)) { 2 { [Text.Encoding]::Unicode } 3 { [Text.Encoding]::BigEndianUnicode } default { [Text.Encoding]::UTF8 } }
    $db = [pscustomobject]@{ Bytes = $Bytes; PageSize = $ps; Usable = $ps - [int]$Bytes[20]; Encoding = $enc; PageCount = [int][Math]::Floor($Bytes.Length / $ps); Master = $null }
    $db.Master = @(Get-S05SqliteRecords -Db $db -RootPage 1)
    $db
}

function Get-S05SqliteColumns {
    param([string]$Sql)
    $i = $Sql.IndexOf('('); $j = $Sql.LastIndexOf(')')
    if ($i -lt 0 -or $j -le $i) { return }
    $body = $Sql.Substring($i + 1, $j - $i - 1)
    $parts = [System.Collections.Generic.List[string]]::new(); $depth = 0; $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $body.ToCharArray()) {
        if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')') { $depth-- }
        if ($ch -eq ',' -and $depth -eq 0) { $parts.Add($sb.ToString()); [void]$sb.Clear() } else { [void]$sb.Append($ch) }
    }
    $parts.Add($sb.ToString())
    foreach ($p in $parts) {
        $p = $p.Trim()
        if (-not $p -or $p -match '^(?i)(CONSTRAINT|PRIMARY\s+KEY|UNIQUE|CHECK|FOREIGN\s+KEY)\b') { continue }
        if ($p -match '^(?:"([^"]+)"|\[([^\]]+)\]|`([^`]+)`|(\S+))\s*(.*)$') {
            $name = @($Matches[1], $Matches[2], $Matches[3], $Matches[4]) | Where-Object { $_ } | Select-Object -First 1
            [pscustomobject]@{ Name = $name; IsRowIdAlias = ($Matches[5] -match '^(?i)INTEGER\s+PRIMARY\s+KEY\b') }
        }
    }
}

function Get-S05SqliteTable {
    param($Db, [string]$Table, [int]$MaxRows = 200000)
    $m = $Db.Master | Where-Object { $_.Values.Count -ge 5 -and $_.Values[0] -eq 'table' -and $_.Values[1] -eq $Table } | Select-Object -First 1
    if (-not $m) { return }
    $cols = @(Get-S05SqliteColumns -Sql ([string]$m.Values[4]))
    $count = 0
    foreach ($rec in (Get-S05SqliteRecords -Db $Db -RootPage ([int]$m.Values[3]))) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $v = if ($i -lt $rec.Values.Count) { $rec.Values[$i] } else { $null }
            if ($cols[$i].IsRowIdAlias -and $null -eq $v) { $v = $rec.RowId }
            $o[$cols[$i].Name] = $v
        }
        [pscustomobject]$o
        if (++$count -ge $MaxRows) { break }
    }
}

#endregion

#region ---------- expected items (config\local\expected.json) ----------

function Test-S05InvalidIf {
    # Evaluates the invalidIf phrases this module understands; everything else is reported as unevaluated.
    param($Item, [hashtable]$Context)
    $holds = [System.Collections.Generic.List[string]]::new()
    $unk = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @($Item.invalidIf)) {
        if (-not $c) { continue }
        if ($c -match "(?i)not 'on'|\bnot on\b") { if ($Context.ContainsKey('ProductOn')) { if (-not $Context.ProductOn) { $holds.Add($c) } } else { $unk.Add($c) } }
        elseif ($c -match '(?i)out of date') { if ($Context.ContainsKey('DefsUpToDate')) { if (-not $Context.DefsUpToDate) { $holds.Add($c) } } else { $unk.Add($c) } }
        elseif ($c -match '(?i)not installed') { if ($Context.ContainsKey('ProductInstalled')) { if (-not $Context.ProductInstalled) { $holds.Add($c) } } else { $unk.Add($c) } }
        else { $unk.Add($c) }
    }
    @{ Holds = @($holds); Unevaluated = @($unk) }
}

function New-S05ExpectedRef {
    param($Item, $Eval)
    $cap = if ($Item.PSObject.Properties['severityCap']) { $Item.severityCap } else { $null }
    $cls = if ($Item.PSObject.Properties['class']) { $Item.class } else { $null }
    $cwu = if ($Item.PSObject.Properties['confirmWithUser']) { [bool]$Item.confirmWithUser } else { $false }
    [ordered]@{
        id = $Item.id; reason = $Item.reason; severityCap = $cap; class = $cls; confirmWithUser = $cwu
        cancelled = (@($Eval.Holds).Count -gt 0); cancelledBy = @($Eval.Holds); unevaluated = @($Eval.Unevaluated)
    }
}

function Get-S05ExpectedAvDetection {
    # avDetection items: match.detectionTypes (e.g. HackTool, RiskWare, PUP) against type tag or name.
    param([object[]]$Rows)
    foreach ($e in @(Get-BvsExpected -Category avDetection)) {
        $types = @($e.match.detectionTypes)
        if (-not $types.Count) { continue }
        $hit = @($Rows | Where-Object {
                $r = $_
                @($types | Where-Object { ($r.type -and $r.type -ieq $_) -or ($r.name -match ('(?i)(^|[:/.\-])' + [regex]::Escape($_))) }).Count -gt 0
            })
        if ($hit.Count) { return (New-S05ExpectedRef -Item $e -Eval (Test-S05InvalidIf -Item $e -Context @{})) }
    }
    $null
}

#endregion

#region ---------- Avast / AVG discovery ----------

function Get-S05GenProducts {
    $defs = @(
        @{ Name = 'Avast'; Keys = @('HKLM\SOFTWARE\Avast Software\Avast', 'HKLM\SOFTWARE\WOW6432Node\Avast Software\Avast'); Data = 'Avast Software\Avast'; Prog = 'Avast Software\Avast' },
        @{ Name = 'AVG'; Keys = @('HKLM\SOFTWARE\AVG\Antivirus', 'HKLM\SOFTWARE\WOW6432Node\AVG\Antivirus'); Data = 'AVG\Antivirus'; Prog = 'AVG\Antivirus' }
    )
    $pd = if ($env:ProgramData) { $env:ProgramData } else { [Environment]::GetFolderPath('CommonApplicationData') }
    $pf = if ($env:ProgramFiles) { $env:ProgramFiles } else { [Environment]::GetFolderPath('ProgramFiles') }
    foreach ($d in $defs) {
        $key = $null; $vals = @{}
        foreach ($k in $d.Keys) {
            $m = Get-S05RegMap $k
            if ($m.Count) { $key = $k; $vals = $m; break }
        }
        $dataFolder = if ($vals['DataFolder']) { [Environment]::ExpandEnvironmentVariables([string]$vals['DataFolder']) } else { Join-Path $pd $d.Data }
        $progFolder = if ($vals['ProgramFolder']) { [Environment]::ExpandEnvironmentVariables([string]$vals['ProgramFolder']) } else { Join-Path $pf $d.Prog }
        if (-not $key -and -not [IO.Directory]::Exists($dataFolder)) { continue }
        $lcid = $null; $culture = $null
        if ($key) {
            $lang = Get-S05RegMap "$key\properties\settings\Languages"
            foreach ($n in 'Engine', 'UI', 'Language', 'Selected') { if ("$($lang[$n])" -match '^\d+$') { $lcid = [int]$lang[$n]; break } }
        }
        if ($lcid) { try { $culture = [Globalization.CultureInfo]::GetCultureInfo($lcid) } catch { $culture = $null } }
        $cp = if ($culture -and $culture.TextInfo.ANSICodePage -gt 0) { $culture.TextInfo.ANSICodePage } else { Get-S05SystemCodePage }
        $installed = if ("$($vals['TSS_InstallationDate'])" -match '^\d+$') { Format-S05Utc (ConvertFrom-S05Unix $vals['TSS_InstallationDate']) } else { $null }
        [pscustomobject]@{
            Name          = $d.Name
            RegKey        = $key
            PropsKey      = if ($key) { "$key\properties" } else { $null }
            DataFolder    = $dataFolder
            ProgramFolder = $progFolder
            Version       = $vals['Version']
            BuildVersion  = $vals['BuildVersion']
            SetupVersion  = $vals['SetupVersion']
            InstalledUtc  = $installed
            LanguageLcid  = $lcid
            Culture       = $culture
            CodePage      = $cp
            Services      = @()
        }
    }
}

#endregion

#region ---------- Avast parsers ----------

$S05RxReportFull = [regex]::new('^(?<stamp>\S.{4,40}?\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp]\.?\s?[Mm]\.?)?)\t(?<obj>.+?)\s\[(?<lvl>[^\]]{1,4})\]\s(?<name>.+?)(?:\s\[(?<typ>[^\]]{1,24})\])?\s\((?<code>-?\d+)\)\s*$')
$S05RxReportNoCode = [regex]::new('^(?<stamp>\S.{4,40}?\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp]\.?\s?[Mm]\.?)?)\t(?<obj>.+?)\s\[(?<lvl>[^\]]{1,4})\]\s(?<name>.+?)(?:\s\[(?<typ>[^\]]{1,24})\])?\s*$')
$S05RxStampTab = [regex]::new('^(?<stamp>\S.{4,40}?\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp]\.?\s?[Mm]\.?)?)\t(?<rest>.+)$')

function Read-S05AvastReports {
    param($P)
    $dir = Join-Path $P.DataFolder 'report'
    $res = [pscustomobject]@{ Exists = [IO.Directory]::Exists($dir); Denied = [System.Collections.Generic.List[string]]::new(); Unparsed = 0; Rows = [System.Collections.Generic.List[object]]::new() }
    if (-not $res.Exists) { return $res }
    foreach ($fp in [IO.Directory]::GetFiles($dir, '*.txt')) {
        $info = [IO.FileInfo]::new($fp)
        $shield = [IO.Path]::GetFileNameWithoutExtension($fp)
        $meta = [ordered]@{ product = $P.Name; shield = $shield; path = $fp; sizeBytes = $info.Length; lastWriteUtc = Format-S05Utc $info.LastWriteTimeUtc; encoding = $null; detections = 0; unparsedLines = 0; firstDetectionUtc = $null; lastDetectionUtc = $null; error = $null }
        try { $dec = Read-S05Text -Path $fp -CodePage $P.CodePage }
        catch {
            $meta.error = $_.Exception.Message
            if ($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)denied') { $res.Denied.Add($fp) }
            $S05.ReportFiles.Add($meta); continue
        }
        if ($null -eq $dec) { continue }
        $meta.encoding = $dec.Encoding
        $lines = $dec.Text -split "`r?`n"
        $fileRows = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if (-not $line -or $line.StartsWith('*')) { continue }
            $m = $S05RxReportFull.Match($line)
            if (-not $m.Success) { $m = $S05RxReportNoCode.Match($line) }
            if (-not $m.Success) {
                if ($S05RxStampTab.IsMatch($line)) { $meta.unparsedLines++; $res.Unparsed++ }
                continue
            }
            $actionText = $null
            if ($i + 1 -lt $lines.Count) {
                $nx = $lines[$i + 1]
                if ($nx -and -not $nx.StartsWith('*') -and -not $S05RxStampTab.IsMatch($nx)) { $actionText = $nx.Trim() }
            }
            $obj = $m.Groups['obj'].Value.Trim()
            $path = $null; $url = $null; $inner = $null
            if ($obj -match '^[A-Za-z][A-Za-z0-9+.\-]{1,15}://') { $url = Protect-BvsUrl $obj }
            elseif ($obj -match '^(?:[A-Za-z]:\\|\\\\)') {
                $k = $obj.IndexOf('|>')
                if ($k -gt 0) { $path = $obj.Substring(0, $k); $inner = $obj.Substring($k + 2) } else { $path = $obj }
            }
            $raw = $m.Groups['name'].Value.Trim()
            if ($m.Groups['typ'].Success -and $m.Groups['typ'].Value) { $raw = "$raw [$($m.Groups['typ'].Value)]" }
            $dt = ConvertFrom-S05LocalStamp -Text $m.Groups['stamp'].Value -Culture $P.Culture
            $action = Get-S05ActionFromText $actionText
            $row = New-S05Detection -Source 'avast.report' -Product $P.Name -Shield $shield -DateUtc $dt -RawName $raw -ObjectText $obj -Path $path -Url $url -Inner $inner `
                -Action $action -ActionDetail (Get-S05Trunc $actionText 160) -ActionSource $(if ($actionText) { 'report' } else { $null })
            $row['level'] = $m.Groups['lvl'].Value
            $row['code'] = if ($m.Groups['code'].Success) { $m.Groups['code'].Value } else { $null }
            $fileRows.Add($row)
        }
        $meta.detections = $fileRows.Count
        $rg = Get-S05Range -Rows $fileRows
        $meta.firstDetectionUtc = $rg.first; $meta.lastDetectionUtc = $rg.last
        $S05.ReportFiles.Add($meta)
        foreach ($r in $fileRows) { $res.Rows.Add($r) }
    }
    $res
}

function Read-S05AvastChest {
    param($P)
    $path = Join-Path $P.DataFolder 'chest\index.xml'
    if (-not [IO.File]::Exists($path)) { return $null }
    $bytes = Read-S05Bytes -Path $path -MaxBytes 128MB
    $ms = [IO.MemoryStream]::new($bytes)
    $set = [Xml.XmlReaderSettings]::new()
    $set.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $set.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($ms, $set)
    $xml = [xml]::new()
    $xml.XmlResolver = $null
    try { $xml.Load($reader) } finally { $reader.Dispose(); $ms.Dispose() }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($xml.SelectNodes('//ChestEntry'))) {
        $get = { param($n) $x = $e.SelectSingleNode($n); if ($x) { $x.InnerText } else { $null } }
        $folder = & $get 'OrigFolder'; $leaf = & $get 'OrigFileName'
        $orig = if ($folder -and $leaf) { (Join-Path $folder $leaf) } elseif ($leaf) { $leaf } else { $folder }
        $size = $null; $sizeRaw = & $get 'FileSize'
        if ("$sizeRaw" -match '^\d{1,19}$') { $sv = [decimal]$sizeRaw; if ($sv -le 1TB) { $size = [long]$sv } }
        $virusRaw = & $get 'Virus'
        $split = Split-S05DetectionName $virusRaw
        $out.Add([ordered]@{
                product        = $P.Name
                chestId        = & $get 'ChestId'
                dateUtc        = Format-S05Utc (ConvertFrom-S05Unix (& $get 'FileTime'))
                transferUtc    = Format-S05Utc (ConvertFrom-S05Unix (& $get 'TransferTime'))
                originalPath   = $orig
                detection      = $split[0]
                type           = $split[1]
                category       = & $get 'Category'
                restorable     = ((& $get 'Restore') -eq 'yes')
                size           = $size
                sizeNote       = if ($null -eq $size -and $sizeRaw) { 'index value implausible (Avast stores a non-size value); size unknown' } else { $null }
                sendToAnalysis = & $get 'SendToAnalysis'
                matchedReport  = $false
                _dt            = ConvertFrom-S05Unix (& $get 'FileTime')
                _raw           = $virusRaw
            })
    }
    $out
}

function Read-S05AvastDetectionsLog {
    param($P)
    $path = Join-Path $P.DataFolder 'log\detections.log'
    if (-not [IO.File]::Exists($path)) { return $null }
    $text = (Read-S05Text -Path $path).Text
    $rx = [regex]::new('(?m)^\W*\[(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\]\s*\[[^\]]*\]\s*\[(?<comp>[^\]]*)\]\s*\[[^\]]*\]\s*\[[^\]]*\]\s*(?<msg>[^\r\n]*)')
    $requests = [System.Collections.Generic.List[object]]::new()
    $choices = [System.Collections.Generic.List[object]]::new()
    $rootkit = [System.Collections.Generic.List[string]]::new()
    $silent = [ordered]@{}
    $counts = @{ handleVirusFound = 0; snxStarted = 0; snxFinished = 0; lines = 0 }
    $first = $null; $last = $null
    foreach ($m in $rx.Matches($text)) {
        $counts.lines++
        $ts = [datetime]::SpecifyKind([datetime]::ParseExact($m.Groups['ts'].Value, 'yyyy-MM-dd HH:mm:ss', $Inv), [DateTimeKind]::Utc)
        if ($null -eq $first) { $first = $ts }
        $last = $ts
        $msg = $m.Groups['msg'].Value
        $rq = [regex]::Match($msg, '^Detection request \| (?<mode>[^|]+?) \| Id: (?<id>[A-Za-z]+)_(?<hash>[0-9a-fA-F]+), Type: (?<type>\w+), wnd: (?<wnd>.*)$')
        if ($rq.Success) {
            $wm = [regex]::Match($rq.Groups['wnd'].Value, '"window_id"\s*:\s*"(?<w>[^"]+)"')
            $requests.Add([ordered]@{
                    tsUtc = Format-S05Utc $ts; mode = $(if ($rq.Groups['mode'].Value -match 'wait') { 'wait_for_user' } else { 'show_and_continue' })
                    type = $rq.Groups['type'].Value; windowId = $(if ($wm.Success) { $wm.Groups['w'].Value } else { $null })
                    id = $rq.Groups['hash'].Value.Substring(0, [Math]::Min(12, $rq.Groups['hash'].Value.Length)); choice = $null; choiceUtc = $null; _dt = $ts
                })
            continue
        }
        $ch = [regex]::Match($msg, '^Detection resolved \| User choice: (?<c>[^,]+)')
        if ($ch.Success) { $choices.Add(@{ dt = $ts; choice = $ch.Groups['c'].Value.Trim() }); continue }
        if ($msg -match '^handle_rootkit_detection') { $rootkit.Add((Format-S05Utc $ts)); continue }
        if ($msg -match '^handle_virus_found') { $counts.handleVirusFound++; continue }
        if ($msg -match 'detection ignored in SilentMode') { $k = $ts.ToString('yyyy-MM-dd', $Inv); if ($silent.Contains($k)) { $silent[$k]++ } else { $silent[$k] = 1 }; continue }
        if ($msg -match '^snx scan started') { $counts.snxStarted++; continue }
        if ($msg -match '^snx scan finished') { $counts.snxFinished++; continue }
    }
    foreach ($c in $choices) {
        $req = $requests | Where-Object { $_.mode -eq 'wait_for_user' -and -not $_.choice -and $_._dt -le $c.dt -and ($c.dt - $_._dt).TotalHours -le 2 } | Select-Object -Last 1
        if ($req) { $req.choice = $c.choice; $req.choiceUtc = Format-S05Utc $c.dt }
    }
    $byType = [ordered]@{}; foreach ($g in ($requests | Group-Object { $_.type })) { $byType[$g.Name] = $g.Count }
    $byWin = [ordered]@{}; foreach ($g in ($requests | Where-Object { $_.windowId } | Group-Object { $_.windowId })) { $byWin[$g.Name] = $g.Count }
    $cert = @($requests | Where-Object { $_.type -eq 'certificateDetection' })
    [pscustomobject]@{
        Product     = $P.Name
        Requests    = $requests
        Summary     = [ordered]@{
            product                = $P.Name
            lines                  = $counts.lines
            firstUtc               = Format-S05Utc $first
            lastUtc                = Format-S05Utc $last
            requestsByType         = $byType
            requestsByWindow       = $byWin
            userPrompts            = @($requests | Where-Object { $_.mode -eq 'wait_for_user' } | ForEach-Object { ConvertTo-S05Public $_ })
            rootkitHandlerEvents   = @($rootkit)
            specialDetections      = @($requests | Where-Object { $_.type -notin 'virusMultiDetection', 'virusDetection', 'certificateDetection' } | ForEach-Object { ConvertTo-S05Public $_ })
            certificateDetections  = [ordered]@{ count = $cert.Count; firstUtc = $(if ($cert.Count) { $cert[0].tsUtc } else { $null }); lastUtc = $(if ($cert.Count) { $cert[-1].tsUtc } else { $null }) }
            silentModeIgnoredByDay = $silent
            handleVirusFound       = $counts.handleVirusFound
            sandboxScansStarted    = $counts.snxStarted
            sandboxScansFinished   = $counts.snxFinished
        }
    }
}

function Read-S05AvastLogDb {
    param($P)
    $path = Join-Path $P.DataFolder 'Log.db'
    if (-not [IO.File]::Exists($path)) { return $null }
    $db = Open-S05Sqlite -Bytes (Read-S05Bytes -Path $path -MaxBytes 256MB)
    $walPath = "$path-wal"
    $wal = [IO.File]::Exists($walPath) -and ([IO.FileInfo]::new($walPath)).Length -gt 0
    $tables = @($db.Master | Where-Object { $_.Values[0] -eq 'table' } | ForEach-Object { [string]$_.Values[1] })
    $paths = @{}
    foreach ($r in (Get-S05SqliteTable -Db $db -Table 'Path')) { $paths[[long]$r.Id] = [string]$r.Name }
    $sessions = [System.Collections.Generic.List[object]]::new()
    $sessById = @{}
    foreach ($r in (Get-S05SqliteTable -Db $db -Table 'ScanSession')) {
        $name = [string]$r.TaskGuid
        $task = $S05.TaskMap["$($P.Name)|$name"]
        $kind = switch ([int]$r.Type) { 2 { 'shield' } 3 { 'scan_task' } default { "type$($r.Type)" } }
        $s = [ordered]@{
            product = $P.Name; id = $r.Id; kind = $kind; name = $name
            taskImage = $(if ($task) { $task.image } else { $null }); scanAreas = $(if ($task) { $task.scanAreas } else { $null })
            startedUtc = Format-S05Utc (ConvertFrom-S05Unix $r.Started); runtimeSec = $r.RunTime
            testedFiles = $r.TestedFiles; testedFolders = $r.TestedFolders; testedBytes = $r.TestedData; infectedFiles = $r.InfectedFiles
            status = $r.Status; error = $r.Error; percent = $r.Percent
        }
        $sessions.Add($s); $sessById[[long]$r.Id] = $s
    }
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (Get-S05SqliteTable -Db $db -Table 'ScanResult')) {
        $obj = if ($null -ne $r.PathId -and $paths.ContainsKey([long]$r.PathId)) { $paths[[long]$r.PathId] } else { $null }
        $url = $null; $fpath = $null
        if ($obj -and $obj.TrimStart().StartsWith('{')) { try { $j = $obj | ConvertFrom-Json; if ($j.url) { $url = Protect-BvsUrl ([string]$j.url) } } catch { } }
        elseif ($obj -match '^[A-Za-z][A-Za-z0-9+.\-]{1,15}://') { $url = Protect-BvsUrl $obj }
        elseif ($obj -match '^(?:[A-Za-z]:\\|\\\\)') { $fpath = $obj }
        $sess = $sessById[[long]$r.SessionId]
        $results.Add([ordered]@{
                product = $P.Name; id = $r.Id; timeUtc = Format-S05Utc (ConvertFrom-S05FileTime $r.Time); virus = $r.Virus
                session = $(if ($sess) { $sess.name } else { $r.SessionId }); path = $fpath; url = $url; chestId = $r.ChestId
                _dt = ConvertFrom-S05FileTime $r.Time
            })
    }
    $hist = [System.Collections.Generic.List[object]]::new()
    $minDaily = $null
    foreach ($spec in @(@{ T = 'YearlyResStat'; G = 'day' }, @{ T = 'DecennaryResStat'; G = 'week' })) {
        if ($tables -notcontains $spec.T) { continue }
        $rows = @(Get-S05SqliteTable -Db $db -Table $spec.T)
        if ($spec.G -eq 'day' -and $rows.Count) { $minDaily = ($rows | Measure-Object -Property Time -Minimum).Minimum }
        foreach ($r in $rows) {
            if ($spec.G -eq 'week' -and $null -ne $minDaily -and $r.Time -ge $minDaily) { continue }
            $inf = [ordered]@{}
            foreach ($pr in $r.PSObject.Properties) { if ($pr.Name -like '*_Infected' -and $null -ne $pr.Value -and [long]$pr.Value -gt 0) { $inf[$pr.Name -replace '_Infected$', ''] = [long]$pr.Value } }
            if ($inf.Count) {
                $start = ConvertFrom-S05UnixLocalWall $r.Time
                $hist.Add([ordered]@{ product = $P.Name; periodStartUtc = Format-S05Utc $start; granularity = $spec.G; infected = $inf })
            }
        }
    }
    [pscustomobject]@{ Sessions = $sessions; Results = $results; History = $hist; WalPresent = $wal; Tables = $tables; Path = $path; PageCount = $db.PageCount }
}

function ConvertFrom-S05ExclusionValue {
    param($Value)
    $s = if ($Value -is [array]) { ($Value | ForEach-Object { "$_" }) -join ';' } elseif ($Value -is [byte[]]) { '' } else { [string]$Value }
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    $hm = [regex]::Matches($s, '"(?<p>[^"]+)"\s*<sha256=(?<h>[0-9A-Fa-f]{64})>')
    if ($hm.Count -gt 0) {
        foreach ($m in $hm) { [pscustomobject]@{ Kind = 'hash'; Value = $m.Groups['p'].Value; Sha256 = $m.Groups['h'].Value.ToLowerInvariant() } }
        return
    }
    foreach ($part in ($s -split '[;|]')) {
        $x = $part.Trim().Trim('"')
        if (-not $x) { continue }
        $kind = if ($x -match '^(?i)[a-z][a-z0-9+.\-]*://' -or $x -match '^(?i)www\.') { 'url' } else { 'path' }
        [pscustomobject]@{ Kind = $kind; Value = $x; Sha256 = $null }
    }
}

function Get-S05AvastExclusions {
    param($P)
    $raw = [System.Collections.Generic.List[object]]::new()
    $namePat = Get-S05Heur 'exclusionValueNamePattern'
    if ($P.PropsKey) {
        $exKey = "$($P.PropsKey)\exclusions"
        foreach ($sub in @(Get-BvsRegSubKeys -Path $exKey)) {
            $k = "$exKey\$sub"
            $lw = Format-S05Utc (Get-BvsRegKeyLastWrite -Path $k)
            foreach ($v in @(Get-BvsRegValues -Path $k)) {
                foreach ($e in @(ConvertFrom-S05ExclusionValue -Value $v.Value)) { $raw.Add(@{ Source = 'registry'; Key = $k; List = $sub; ValueName = $v.Name; Entry = $e; LastWrite = $lw }) }
            }
        }
        $stack = [System.Collections.Generic.Stack[object]]::new()
        $stack.Push(@($P.PropsKey, 0))
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop(); $k = $cur[0]; $depth = $cur[1]
            if ($k -ieq $exKey) { continue }
            foreach ($v in @(try { Get-BvsRegValues -Path $k } catch { })) {
                if ($namePat -and $v.Name -match $namePat) {
                    foreach ($e in @(ConvertFrom-S05ExclusionValue -Value $v.Value)) { $raw.Add(@{ Source = 'registry'; Key = $k; List = (Split-Path $k -Leaf); ValueName = $v.Name; Entry = $e; LastWrite = (Format-S05Utc (Get-BvsRegKeyLastWrite -Path $k)) }) }
                }
            }
            if ($depth -lt 4) { foreach ($s in @(try { Get-BvsRegSubKeys -Path $k } catch { })) { $stack.Push(@("$k\$s", ($depth + 1))) } }
        }
    }
    $ini = Join-Path $P.DataFolder 'avast5.ini'
    if ([IO.File]::Exists($ini)) {
        $section = ''
        foreach ($line in ((Read-S05Text -Path $ini -CodePage $P.CodePage).Text -split "`r?`n")) {
            if ($line -match '^\s*\[(?<s>[^\]]+)\]') { $section = $Matches.s; continue }
            if ($line -match '^\s*(?<k>[^=;#\[]+?)\s*=\s*(?<v>.*)$') {
                $kn = $Matches.k; $kv = $Matches.v
                if ($namePat -and $kn -match $namePat) { foreach ($e in @(ConvertFrom-S05ExclusionValue -Value $kv)) { $raw.Add(@{ Source = 'avast5.ini'; Key = $ini; List = $section; ValueName = $kn; Entry = $e; LastWrite = (Format-S05Utc ([IO.File]::GetLastWriteTimeUtc($ini))) }) } }
            }
        }
    }
    $broad = @(Get-S05Heur 'broadExclusionPatterns')
    $devPat = Get-S05Heur 'devLauncherPattern'
    $hashed = 0
    foreach ($x in $raw) {
        $e = $x.Entry
        $val = [Environment]::ExpandEnvironmentVariables([string]$e.Value)
        $row = [ordered]@{
            product = $P.Name; source = $x.Source; key = $x.Key; list = $x.List; valueName = $x.ValueName; kind = $e.Kind; value = $e.Value; sha256 = $e.Sha256
            exists = $null; currentHashMatches = $null; signature = $null; signer = $null; devLauncher = $null; broad = $false; userWritable = $null; keyLastWriteUtc = $x.LastWrite
        }
        if ($e.Kind -eq 'path') {
            foreach ($b in $broad) { if ($b -and $val -match $b) { $row.broad = $true; break } }
            $prefix = ($val -split '[*?]')[0].TrimEnd('\')
            if ($prefix -match '^(?:[A-Za-z]:|\\\\)') { $row.exists = [IO.Directory]::Exists($prefix) -or [IO.File]::Exists($prefix); $row.userWritable = Test-BvsUserWritable -Path $prefix }
        }
        elseif ($e.Kind -eq 'hash') {
            $row.exists = [IO.File]::Exists($val)
            $row.devLauncher = [bool]($devPat -and $val -match $devPat)
            if ($row.exists -and $hashed -lt 60 -and -not (Test-BvsNeverRead $val)) {
                $hashed++
                $h = Get-BvsHash -Path $val -MaxBytes 256MB
                if ($h) { $row.currentHashMatches = ($h -eq $e.Sha256) }
                $sig = Get-BvsSignature -Path $val
                if ($sig) { $row.signature = $sig.Status; $row.signer = $sig.Signer }
            }
        }
        $row
    }
}

#endregion

#region ---------- Microsoft log parsers ----------

function Get-S05MsResourcePaths {
    param([string[]]$Resources)
    $rx = [regex]::new('(?i)(?:file|containerfile|webfile)(?::_|://|:)(?:\\\\\?\\)?(?<p>[A-Za-z]:\\[^|;\r\n]+?)(?=\s+SigSeq:|\s*\||\s*;|\s*$)')
    foreach ($r in $Resources) {
        if (-not $r) { continue }
        foreach ($m in $rx.Matches($r)) { $m.Groups['p'].Value.Trim() }
    }
}

function ConvertFrom-S05MsLog {
    # MSRT (mrt.log) and Microsoft Safety Scanner (msert.log) share one format.
    param([string]$Text, [string]$SourceFile)
    $codes = Get-S05Heur 'msrtReturnCodes'
    $nameRx = '(?<name>(?:[A-Za-z]+:)?[A-Za-z0-9]+/[A-Za-z0-9_.\-]+(?:![A-Za-z0-9.]+)?)'
    foreach ($b in [regex]::Split($Text, '(?m)^\s*-{20,}\s*$')) {
        $hm = [regex]::Match($b, '(?m)^\s*Microsoft (?<prod>Windows Malicious Software Removal Tool|Safety Scanner)\s+v(?<ver>[\d.]+)(?:,\s*\(build\s+(?<build>[\d.]+)\))?')
        if (-not $hm.Success) { continue }
        $field = { param($n) $m = [regex]::Match($b, "(?m)^\s*$n\s*:\s*(?<v>.+?)\s*$"); if ($m.Success) { $m.Groups['v'].Value } else { $null } }
        $started = ConvertFrom-S05EnglishStamp ([regex]::Match($b, '(?m)^\s*Started On\s+(?<v>.+?)\s*$').Groups['v'].Value)
        $finished = ConvertFrom-S05EnglishStamp ([regex]::Match($b, '(?m)Finished On\s+(?<v>.+?)\s*$').Groups['v'].Value)
        $rcm = [regex]::Match($b, '(?m)^\s*Return code:\s*(?<d>\d+)')
        $rc = if ($rcm.Success) { [int]$rcm.Groups['d'].Value } else { $null }
        $summary = [regex]::Match($b, '(?ms)^\s*Results Summary:\s*\r?\n\s*-+\s*\r?\n(?<s>.*?)(?=^\s*Microsoft (?:Windows Malicious Software Removal Tool|Safety Scanner) Finished On|^\s*Return code:|\z)').Groups['s'].Value
        $sumLines = @($summary -split '\r?\n' | ForEach-Object { $_.TrimEnd() } | Where-Object { $_.Trim() })
        $dets = [System.Collections.Generic.List[object]]::new()
        $cur = $null
        foreach ($line in ($b -split '\r?\n')) {
            $t = $line.Trim()
            $fm = [regex]::Match($t, "^(?i)(?:->\s*)?(?:Found|Threat detected:?|Detected:?)\s+$nameRx(?<rest>.*)$")
            if ($fm.Success) {
                $cur = [ordered]@{ name = $fm.Groups['name'].Value; actionText = $fm.Groups['rest'].Value.Trim(' ', ',', '.', '!'); resources = [System.Collections.Generic.List[string]]::new() }
                $dets.Add($cur); continue
            }
            if ($cur -and $t -match '(?i)\b(?:file|containerfile|regkey|process|service|startup|webfile|behavior|amsi)(?::_|://)') { $cur.resources.Add($t) }
        }
        if ($dets.Count -eq 0) {
            foreach ($l in $sumLines) {
                if ($l -match '(?i)No infection found|Successfully Submitted|Heartbeat') { continue }
                $nm = [regex]::Match($l, $nameRx)
                if ($nm.Success) { $dets.Add([ordered]@{ name = $nm.Groups['name'].Value; actionText = (Get-S05Trunc $l 120); resources = [System.Collections.Generic.List[string]]::new() }) }
            }
        }
        $filesScanned = $null
        $fsm = [regex]::Match($b, '(?im)(?:files?\s+scanned|scanned\s+files?|total\s+files(?:\s+scanned)?)\s*[:=]\s*(?<n>[\d,. ]+)')
        if ($fsm.Success) { $digits = $fsm.Groups['n'].Value -replace '[^\d]', ''; if ($digits) { $filesScanned = [long]$digits } }
        $runMode = & $field 'Run Mode'
        $scanType = & $field 'Scan (?:Type|Mode)'
        if (-not $scanType) { $scanType = $runMode }
        [ordered]@{
            product          = if ($hm.Groups['prod'].Value -match 'Safety') { 'msert' } else { 'msrt' }
            version          = $hm.Groups['ver'].Value
            build            = $hm.Groups['build'].Value
            startedUtc       = Format-S05Utc $started
            finishedUtc      = Format-S05Utc $finished
            engine           = & $field 'Engine'
            signatures       = & $field 'Signatures'
            mpGear           = & $field 'MpGear'
            runMode          = $runMode
            scanType         = $scanType
            returnCode       = $rc
            returnMeaning    = if ($null -ne $rc -and $codes -and $codes.PSObject.Properties["$rc"]) { [string]$codes."$rc" } else { $null }
            complete         = ($null -ne $rc -or $null -ne $finished)
            noInfectionFound = [bool]($summary -match '(?i)No infection found')
            summary          = @($sumLines | Select-Object -First 25 | ForEach-Object { Get-S05Trunc (Protect-BvsText $_) 240 })
            detections       = @($dets | ForEach-Object { [ordered]@{ name = $_.name; actionText = $_.actionText; paths = @(Get-S05MsResourcePaths -Resources @($_.resources)); resources = @($_.resources | Select-Object -First 20 | ForEach-Object { Get-S05Trunc (Protect-BvsText $_) 300 }) } })
            scanErrors       = ([regex]::Matches($b, '(?im)^\s*->\s*Scan ERROR')).Count
            filesScanned     = $filesScanned
            sourceFile       = $SourceFile
        }
    }
}

function Add-S05MsRunDetections {
    param($RunRec, [string]$Source, [string]$Product)
    $date = if ($RunRec.finishedUtc) { [datetime]::Parse($RunRec.finishedUtc, $Inv).ToUniversalTime() } elseif ($RunRec.startedUtc) { [datetime]::Parse($RunRec.startedUtc, $Inv).ToUniversalTime() } else { $null }
    foreach ($d in @($RunRec.detections)) {
        $act = if ($d.actionText -match '(?i)not removed|failed|\bbut\b|unable') { 'detected_only' } elseif ($d.actionText -match '(?i)removed|cleaned|quarantin') { 'removed' } else { 'detected' }
        $paths = @($d.paths)
        if (-not $paths.Count) { $paths = @($null) }
        foreach ($p in $paths) {
            $row = New-S05Detection -Source $Source -Product $Product -DateUtc $date -RawName $d.name -Vendor microsoft -Path $p -Action $act -ActionDetail (Get-S05Trunc $d.actionText 160) -ActionSource 'log'
            $S05.Detections.Add($row)
        }
    }
}

function ConvertFrom-S05ProductState {
    param([long]$State)
    $prov = ($State -shr 16) -band 0xFF
    $scan = ($State -shr 12) -band 0xF
    $owner = ($State -shr 8) -band 0xF
    $sig = ($State -shr 4) -band 0xF
    $flags = [System.Collections.Generic.List[string]]::new()
    foreach ($kv in @(@(0x01, 'firewall'), @(0x02, 'autoupdate'), @(0x04, 'antivirus'), @(0x08, 'antispyware'), @(0x10, 'internet_settings'), @(0x20, 'uac'), @(0x40, 'service'))) { if ($prov -band $kv[0]) { $flags.Add($kv[1]) } }
    [ordered]@{
        raw           = $State
        hex           = ('0x{0:X6}' -f $State)
        providerFlags = @($flags)
        state         = switch ($scan) { 0 { 'off' } 1 { 'on' } 2 { 'snoozed' } 3 { 'expired' } default { "unknown($scan)" } }
        enabled       = ($scan -eq 1)
        definitions   = switch ($sig) { 0 { 'up_to_date' } 1 { 'out_of_date' } default { "unknown($sig)" } }
        owner         = if ($owner -eq 1) { 'windows' } else { 'third_party' }
    }
}

#endregion

# ---------- configuration and context ----------
$heurPath = Join-Path $PSScriptRoot 'S05-av-heuristics.json'
try { $S05.Heur = Get-Content -LiteralPath $heurPath -Raw | ConvertFrom-Json }
catch { $S05.HeurError = "heuristics file unreadable ($heurPath): $($_.Exception.Message)"; $S05.Heur = $null }

$slug = ($BvsRoot -replace '[^A-Za-z0-9]', '-')
$own = [System.Collections.Generic.List[string]]::new()
$own.Add($BvsRoot)
$own.Add((Join-Path $env:USERPROFILE ".claude\projects\$slug"))
if ($env:TEMP) { $own.Add((Join-Path $env:TEMP "claude\$slug")) }
foreach ($e in @(Get-BvsExpected -Category path | Where-Object { $_.id -eq 'this-project' })) { foreach ($p in @($e.match.paths)) { $own.Add([Environment]::ExpandEnvironmentVariables([string]$p)) } }
$S05.OwnPaths = @($own | Select-Object -Unique)
try { $S05.IntelHosts = @((Get-BvsIntelHosts).hosts | ForEach-Object { $_.host }) } catch { $S05.IntelHosts = @() }

$null = Invoke-BvsCheck -Run $run -Id 's05.heuristics' -Description 'Load S05-av-heuristics.json (type maps, false-positive hints, keyword lists)' -Script {
    if ($S05.HeurError) { throw $S05.HeurError }
    @($S05.Heur.PSObject.Properties.Name)
}

#region ---------- checks: Avast / AVG ----------

$null = Invoke-BvsCheck -Run $run -Id 'avast.product' -Description 'Avast/AVG installation: version, folders, language, services' -Script {
    $found = @(Get-S05GenProducts)
    if (-not $found.Count) { Set-BvsCheckStatus -Id 'avast.product' -Status not_applicable -Reason 'No Avast or AVG antivirus installation found (registry and default folders)'; return }
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
    foreach ($p in $found) {
        $pf = $p.ProgramFolder
        $p.Services = @($svcs | Where-Object { $_.PathName -and $pf -and $_.PathName.IndexOf($pf, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
                ForEach-Object { [ordered]@{ name = $_.Name; displayName = $_.DisplayName; state = $_.State; startMode = $_.StartMode } })
        $S05.Gen.Add($p)
    }
    $found
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.settings' -Description 'Avast/AVG shields, features, passive/silent mode and scan tasks (registry properties)' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.settings' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $missing = @()
    foreach ($p in $S05.Gen) {
        if (-not $p.PropsKey -or -not (Open-BvsRegKey -Path $p.PropsKey)) { $missing += $p.Name; continue }
        foreach ($sub in @(Get-BvsRegSubKeys -Path $p.PropsKey)) {
            $ck = "$($p.PropsKey)\$sub\Common"
            $v = Get-S05RegMap $ck
            if (-not ($v.ContainsKey('ProviderEnabled') -or $v.ContainsKey('Enabled') -or $v.ContainsKey('TemporaryDisabled'))) { continue }
            $en = if ($v.ContainsKey('ProviderEnabled')) { [int]$v['ProviderEnabled'] -eq 1 } elseif ($v.ContainsKey('Enabled')) { [int]$v['Enabled'] -eq 1 } else { $null }
            $S05.Shields.Add([ordered]@{
                    product = $p.Name; shield = $(if ($sub -eq 'FwSettings') { 'Firewall' } else { $sub }); enabled = $en
                    temporarilyDisabled = $(if ($v.ContainsKey('TemporaryDisabled')) { [int]$v['TemporaryDisabled'] -eq 1 } else { $null })
                    unlicensed = $(if ($v.ContainsKey('Unlicensed')) { [int]$v['Unlicensed'] -eq 1 } else { $null })
                    keyLastWriteUtc = Format-S05Utc (Get-BvsRegKeyLastWrite -Path $ck)
                })
        }
        $set = "$($p.PropsKey)\settings"
        $feat = [ordered]@{ product = $p.Name }
        $ar = Get-S05RegMap "$set\AntiRootkit"; $ae = Get-S05RegMap "$set\AntiExploit"; $aavm = Get-S05RegMap "$set\AAVM"
        $idp = Get-S05RegMap "$($p.PropsKey)\IDP\Setting"; $com = Get-S05RegMap "$set\Common"; $pm = Get-S05RegMap "$set\PassiveMode"
        $feat.antiRootkitTemporarilyDisabled = if ($ar.ContainsKey('TemporaryDisabled')) { [int]$ar['TemporaryDisabled'] -eq 1 } else { $null }
        $feat.antiRootkitLastStartupScan = $ar['StartupScan']
        $feat.antiExploitTemporarilyDisabled = if ($ae.ContainsKey('TemporaryDisabled')) { [int]$ae['TemporaryDisabled'] -eq 1 } else { $null }
        $feat.antiExploitEnabled = if ($aavm.ContainsKey('AntiExploitEnabled')) { [int]$aavm['AntiExploitEnabled'] -eq 1 } else { $null }
        $feat.behaviorEngineEnabled = if ($idp.ContainsKey('enabled')) { [int]$idp['enabled'] -eq 1 } else { $null }
        $feat.ransomwareFolderProtection = if ($idp.ContainsKey('fileprotection.enabled')) { [int]$idp['fileprotection.enabled'] -eq 1 } else { $null }
        $feat.showDetectionsInSilentMode = $com['ShowDetectionsInSilent']
        $feat.silentModeLastReported = $com['LastSentSilentMode']
        $feat.firstVps = $com['FirstVPS']
        $pmFlags = @($pm.Keys | Where-Object { $_ -match '^(?i)(enabled|active|passive(mode)?|on)$' })
        $feat.passiveMode = if ($pmFlags.Count) { @($pmFlags | Where-Object { "$($pm[$_])" -eq '1' }).Count -gt 0 } else { $false }
        $feat.passiveModeProviders = if ($pm['DisabledProviders']) { [string]$pm['DisabledProviders'] } else { $null }
        $S05.Features.Add($feat)
        foreach ($sub in @(Get-BvsRegSubKeys -Path $set | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' })) {
            $t = Get-S05RegMap "$set\$sub"
            $task = [ordered]@{
                product = $p.Name; guid = $sub; image = $t['TaskImage']; job = $t['Job']; scanAreas = $t['ScanAreas']; scanPup = $t['ScanPUP']
                sensitivity = $t['TaskSensitivity']; lastRunUtc = $(if ("$($t['LastRun'])" -match '^\d+$') { Format-S05Utc (ConvertFrom-S05Unix $t['LastRun']) } else { $null })
                scanExclusions = $t['ScanExclusions']
            }
            $S05.Tasks.Add($task)
            $S05.TaskMap["$($p.Name)|$sub"] = $task
        }
    }
    if ($missing.Count) { Set-BvsCheckStatus -Id 'avast.settings' -Status partial -Reason ("settings registry not readable for: " + ($missing -join ', ')) }
    @($S05.Shields)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.exclusions' -Description 'Avast/AVG exclusions and exceptions (registry properties, avast5.ini)' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.exclusions' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    foreach ($p in $S05.Gen) { foreach ($x in @(Get-S05AvastExclusions -P $p)) { $S05.Exclusions.Add($x) } }
    @($S05.Exclusions)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.definitions' -Description 'Avast/AVG virus definitions (VPS) version, date and age; program version' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.definitions' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    foreach ($p in $S05.Gen) {
        $latest = $null; $src = $null; $folders = [System.Collections.Generic.List[string]]::new(); $root = $null
        foreach ($d in @((Join-Path $p.ProgramFolder 'defs'), (Join-Path $p.DataFolder 'defs')) | Select-Object -Unique) {
            if (-not [IO.Directory]::Exists($d)) { continue }
            if (-not $root) { $root = $d }
            $ini = Join-Path $d 'aswdefs.ini'
            if (-not $latest -and [IO.File]::Exists($ini)) {
                $t = (Read-S05Text -Path $ini).Text
                $mm = [regex]::Match($t, '(?im)^\s*Latest\s*=\s*(?<v>\d{8})')
                if ($mm.Success) { $latest = $mm.Groups['v'].Value; $src = $ini; $root = $d }
            }
            foreach ($sd in [IO.Directory]::GetDirectories($d)) { $folders.Add([IO.Path]::GetFileName($sd)) }
        }
        $plain = @($folders | Where-Object { $_ -match '^\d{8}$' } | Sort-Object -Descending)
        $streams = @($folders | Where-Object { $_ -match '^\d{8}_stream$' } | Sort-Object -Descending)
        if (-not $latest -and $plain.Count) { $latest = $plain[0]; $src = 'defs folder name' }
        $vpsDate = $null
        if ($latest) { $tmp = [datetime]::MinValue; if ([datetime]::TryParseExact('20' + $latest.Substring(0, 6), 'yyyyMMdd', $Inv, [Globalization.DateTimeStyles]::None, [ref]$tmp)) { $vpsDate = $tmp } }
        $updated = $null
        if ($latest -and $root -and [IO.Directory]::Exists((Join-Path $root $latest))) { $updated = [IO.Directory]::GetLastWriteTimeUtc((Join-Path $root $latest)) }
        $streamUpdated = $null
        if ($streams.Count -and $root) { $streamUpdated = [IO.Directory]::GetLastWriteTimeUtc((Join-Path $root $streams[0])) }
        $S05.Definitions.Add([ordered]@{
                product = $p.Name; programVersion = $p.Version; buildVersion = $p.BuildVersion; setupVersion = $p.SetupVersion
                vps = $latest; vpsSource = $src; vpsDate = $(if ($vpsDate) { $vpsDate.ToString('yyyy-MM-dd', $Inv) } else { $null })
                vpsAgeDays = $(if ($vpsDate) { [int][Math]::Floor(([datetime]::UtcNow.Date - $vpsDate.Date).TotalDays) } else { $null })
                vpsFolderWriteUtc = Format-S05Utc $updated
                latestStreamUpdate = $(if ($streams.Count) { $streams[0] } else { $null }); latestStreamUpdateUtc = Format-S05Utc $streamUpdated
                defsFolder = $root
            })
        if (-not $latest) { Set-BvsCheckStatus -Id 'avast.definitions' -Status partial -Reason "definitions version not found for $($p.Name)" }
    }
    @($S05.Definitions)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.reports' -Description 'Avast/AVG shield reports (report\*.txt): detections with date, shield, name, object, action' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.reports' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $denied = [System.Collections.Generic.List[string]]::new(); $missing = @(); $unparsed = 0; $n = 0
    foreach ($p in $S05.Gen) {
        $r = Read-S05AvastReports -P $p
        if (-not $r.Exists) { $missing += $p.Name; continue }
        foreach ($d in $r.Denied) { $denied.Add($d) }
        $unparsed += $r.Unparsed
        foreach ($row in $r.Rows) { $S05.Detections.Add($row); $n++ }
    }
    if ($denied.Count -and -not $n) { Set-BvsCheckStatus -Id 'avast.reports' -Status needs_admin -Reason ("report files not readable (Avast self-defense?): " + ($denied -join ', ')) }
    elseif ($denied.Count) { Set-BvsCheckStatus -Id 'avast.reports' -Status partial -Reason ("some report files not readable: " + ($denied -join ', ')) }
    elseif ($missing.Count -eq $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.reports' -Status partial -Reason 'report folder missing' }
    elseif ($unparsed) { Set-BvsCheckStatus -Id 'avast.reports' -Status partial -Reason "$unparsed dated report lines did not match the known detection format" }
    @($S05.Detections | Where-Object { $_.source -eq 'avast.report' })
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.chest' -Description 'Avast/AVG Virus Chest index (chest\index.xml, metadata only; quarantined files never opened)' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.chest' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $any = $false
    foreach ($p in $S05.Gen) {
        $c = Read-S05AvastChest -P $p
        if ($null -eq $c) { continue }
        $any = $true
        foreach ($x in $c) { $S05.Chest.Add($x) }
    }
    if (-not $any) { Set-BvsCheckStatus -Id 'avast.chest' -Status not_applicable -Reason 'no chest\index.xml (Virus Chest never used or folder missing)' }
    @($S05.Chest)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.removal_records' -Description 'Avast/AVG PUB-Detected / PUB-Removed registry records (removed detections)' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.removal_records' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    foreach ($p in $S05.Gen) {
        if (-not $p.RegKey) { continue }
        foreach ($kn in 'PUB-Detected', 'PUB-Removed') {
            $vals = @(try { Get-BvsRegValues -Path "$($p.RegKey)\$kn" } catch { })
            $entries = @($vals | ForEach-Object {
                    $t = $null
                    if ($_.Name -match '^[0-9A-Fa-f]{12,16}$') { $t = ConvertFrom-S05FileTime ([Convert]::ToInt64($_.Name, 16)) }
                    if ($t -and ($t.Year -lt 2000 -or $t -gt [datetime]::UtcNow.AddDays(2))) { $t = $null }
                    $v = [string]$_.Value
                    [ordered]@{ timeUtc = Format-S05Utc $t; path = ($v -split '\|' | Where-Object { $_ } | Select-Object -Last 1) }
                } | Sort-Object { $_.timeUtc })
            $S05.Removed.Add([ordered]@{ product = $p.Name; list = $kn; count = $entries.Count; firstUtc = $(if ($entries.Count) { $entries[0].timeUtc } else { $null }); lastUtc = $(if ($entries.Count) { $entries[-1].timeUtc } else { $null }); entries = @($entries | Select-Object -Last 200) })
        }
    }
    @($S05.Removed)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.detections_log' -Description 'Avast/AVG log\detections.log: detection prompts, user choices, rootkit/anti-exploit and certificate events' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.detections_log' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    foreach ($p in $S05.Gen) { $d = Read-S05AvastDetectionsLog -P $p; if ($d) { $S05.DetLog.Add($d) } }
    if (-not $S05.DetLog.Count) { Set-BvsCheckStatus -Id 'avast.detections_log' -Status not_applicable -Reason 'detections.log not present' }
    @($S05.DetLog | ForEach-Object { $_.Requests })
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.logdb' -Description 'Avast/AVG Log.db: scan sessions (last scan times), scan results, infection statistics' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.logdb' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $wal = @()
    foreach ($p in $S05.Gen) {
        $r = Read-S05AvastLogDb -P $p
        if ($null -eq $r) { continue }
        foreach ($s in $r.Sessions) { $S05.Sessions.Add($s) }
        foreach ($x in $r.Results) { $S05.LogDbResults.Add($x) }
        foreach ($h in $r.History) { $S05.InfectedHist.Add($h) }
        $S05.LogDbInfo.Add([ordered]@{ product = $p.Name; path = $r.Path; pages = $r.PageCount; tables = @($r.Tables); walPresent = $r.WalPresent; sessions = $r.Sessions.Count; results = $r.Results.Count; infectedPeriods = $r.History.Count })
        if ($r.WalPresent) { $wal += $p.Name }
    }
    if (-not $S05.LogDbInfo.Count) { Set-BvsCheckStatus -Id 'avast.logdb' -Status not_applicable -Reason 'Log.db not present' }
    elseif ($wal.Count) { Set-BvsCheckStatus -Id 'avast.logdb' -Status partial -Reason ("Log.db has an active -wal file (newest rows may be missing): " + ($wal -join ', ')) }
    @($S05.Sessions)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.correlation' -Description 'Correlate report rows with Virus Chest, detections.log user choices and Log.db results' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.correlation' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $byPath = @{}
    foreach ($c in $S05.Chest) {
        if (-not $c.originalPath) { continue }
        $k = $c.originalPath.ToLowerInvariant()
        if (-not $byPath.ContainsKey($k)) { $byPath[$k] = [System.Collections.Generic.List[object]]::new() }
        $byPath[$k].Add($c)
    }
    $matched = 0
    foreach ($r in @($S05.Detections | Where-Object { $_.source -eq 'avast.report' -and $_.objectKind -eq 'file' -and $_._dt })) {
        $cands = $byPath[$r.path.ToLowerInvariant()]
        if (-not $cands) { continue }
        $best = $null; $bestGap = [double]::MaxValue
        foreach ($c in $cands) {
            if ($c.matchedReport -or -not $c._dt) { continue }
            $gap = [Math]::Abs(($c._dt - $r._dt).TotalSeconds)
            if ($gap -le 180 -and $gap -lt $bestGap) { $best = $c; $bestGap = $gap }
        }
        if ($best) {
            $best.matchedReport = $true; $r.chestId = $best.chestId; $r.confirmedBy.Add('chest'); $matched++
            if ($r.action -ne 'failed') { $r.action = 'quarantined'; if (-not $r.actionSource) { $r.actionSource = 'chest' } }
        }
    }
    foreach ($c in @($S05.Chest | Where-Object { -not $_.matchedReport })) {
        $row = New-S05Detection -Source 'avast.chest' -Product $c.product -Shield $null -DateUtc $c._dt -RawName $c._raw -Path $c.originalPath -Action 'quarantined' -ActionDetail 'Virus Chest entry (no matching report line)' -ActionSource 'chest'
        $row.chestId = $c.chestId
        $S05.Detections.Add($row)
    }
    $prompts = @($S05.DetLog | ForEach-Object { $_.Requests } | Where-Object { $_.mode -eq 'wait_for_user' })
    $map = Get-S05Heur 'userChoiceMap'
    foreach ($r in @($S05.Detections | Where-Object { $_.source -eq 'avast.report' -and -not $_.action -and $_._dt -and $_.objectKind -eq 'file' })) {
        $q = $prompts | Where-Object { [Math]::Abs(($_._dt - $r._dt).TotalSeconds) -le 20 } | Select-Object -First 1
        if ($q) {
            $c = if ($q.choice) { $q.choice.ToLowerInvariant() } else { $null }
            $r.action = if ($c -and $map -and $map.PSObject.Properties[$c]) { [string]$map.$c } elseif ($c) { 'user_choice' } else { 'pending_or_unknown' }
            $r.actionDetail = if ($c) { "Avast asked the user; user choice '$c'" } else { 'Avast asked the user; no recorded choice' }
            $r.actionSource = 'detections.log'
            $r.confirmedBy.Add('detections.log')
        }
    }
    foreach ($x in $S05.LogDbResults) {
        $split = Split-S05DetectionName $x.virus
        $hit = $S05.Detections | Where-Object { $_._dt -and $x._dt -and $_.name -eq $split[0] -and [Math]::Abs(($_._dt - $x._dt).TotalSeconds) -le 5 -and (($x.path -and $_.path -ieq $x.path) -or ($x.url -and $_.url -eq $x.url)) } | Select-Object -First 1
        if ($hit) { $hit.confirmedBy.Add('logdb'); continue }
        $row = New-S05Detection -Source 'avast.logdb' -Product $x.product -Shield $x.session -DateUtc $x._dt -RawName $x.virus -Path $x.path -Url $x.url -ActionSource 'logdb'
        if ($x.chestId -and "$($x.chestId)" -ne '0') { $row.chestId = "$($x.chestId)"; $row.action = 'quarantined' }
        $S05.Detections.Add($row)
    }
    foreach ($r in $S05.Detections) {
        if ($r.product -notin 'Avast', 'AVG') { continue }
        if (-not $r.action -and $r.objectKind -eq 'url') { $r.action = 'blocked'; $r.actionSource = 'implied (Web Shield blocks by default)' }
        if (-not $r.action) { $r.action = 'unknown' }
    }
    $matched
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.log_grep' -Description 'Avast/AVG text logs: infection / threat / detection / blocked keyword summary' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.log_grep' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $kw = Get-S05Heur 'logKeywordPattern'
    if (-not $kw) { throw 'logKeywordPattern missing from heuristics' }
    $lineRx = [regex]::new('(?m)^[^\r\n]*?' + $kw + '[^\r\n]*', [Text.RegularExpressions.RegexOptions]::Compiled)
    $noise = @(Get-S05Heur 'logNoisePatterns')
    $noiseRx = if ($noise.Count) { [regex]::new('(?i)(?:' + ($noise -join '|') + ')', [Text.RegularExpressions.RegexOptions]::Compiled) } else { $null }
    $tsRx = [regex]::new('^\W*\[(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
    $skip = @(Get-S05Heur 'logSkipFiles')
    $problems = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $S05.Gen) {
        $dir = Join-Path $p.DataFolder 'log'
        if (-not [IO.Directory]::Exists($dir)) { continue }
        foreach ($fp in [IO.Directory]::GetFiles($dir)) {
            $leaf = [IO.Path]::GetFileName($fp)
            if ($leaf -notmatch '(?i)\.(log|old)$' -or $skip -contains $leaf) { continue }
            $info = [IO.FileInfo]::new($fp)
            $rec = [ordered]@{ product = $p.Name; file = $leaf; sizeBytes = $info.Length; lastWriteUtc = Format-S05Utc $info.LastWriteTimeUtc; encoding = $null; keywordHits = 0; notableHits = 0; firstNotableUtc = $null; lastNotableUtc = $null; topNotable = @(); error = $null }
            if ($info.Length -gt 48MB) { $rec.error = 'skipped: larger than 48 MB'; $problems.Add("$leaf (size)"); $S05.LogGrep.Add($rec); continue }
            try { $dec = Read-S05Text -Path $fp -CodePage $p.CodePage -MaxBytes 48MB }
            catch { $rec.error = $_.Exception.Message; $problems.Add("$leaf (read)"); $S05.LogGrep.Add($rec); continue }
            $rec.encoding = $dec.Encoding
            $notable = [System.Collections.Generic.List[string]]::new()
            foreach ($m in $lineRx.Matches($dec.Text)) {
                $rec.keywordHits++
                if ($noiseRx -and $noiseRx.IsMatch($m.Value)) { continue }
                $notable.Add($m.Value)
            }
            $rec.notableHits = $notable.Count
            if ($notable.Count) {
                $stamps = @($notable | ForEach-Object { $t = $tsRx.Match($_); if ($t.Success) { $t.Groups['ts'].Value } } | Sort-Object)
                if ($stamps.Count) { $rec.firstNotableUtc = ($stamps[0] -replace ' ', 'T') + 'Z'; $rec.lastNotableUtc = ($stamps[-1] -replace ' ', 'T') + 'Z' }
                $rec.topNotable = @($notable | Group-Object { ($_ -replace '^\W*\[[^\]]+\]\s*(\[[^\]]*\]\s*){0,4}', '' -replace '[0-9A-Fa-f]{12,}', 'H' -replace '\d+', 'N') -replace '^(.{0,100}).*$', '$1' } |
                        Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ count = $_.Count; sample = (Get-S05Trunc (Protect-BvsText $_.Group[-1]) 240) } })
                foreach ($l in ($notable | Select-Object -Last 5)) { $S05.LogNotable.Add([ordered]@{ product = $p.Name; file = $leaf; line = (Get-S05Trunc (Protect-BvsText $l) 240) }) }
            }
            $S05.LogGrep.Add($rec)
        }
    }
    if ($problems.Count) { Set-BvsCheckStatus -Id 'avast.log_grep' -Status partial -Reason ('not scanned: ' + ($problems -join ', ')) }
    @($S05.LogGrep)
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.autosandbox' -Description 'Avast/AVG Auto-Sandbox decisions (log\autosandbox.log): sandboxed files and exception-list hits' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.autosandbox' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    $recRx = [regex]::new('(?ms)^(?<stamp>\S[^\t\r\n]{4,40}?\d{1,2}:\d{2}:\d{2}(?:\s?[AaPp]\.?\s?[Mm]\.?)?)\t[^\r\n]*?:\s(?<path>[A-Za-z]:\\[^\r\n]+|\\\\[^\r\n]+)\r?\n(?<body>.*?)(?=^\S[^\t\r\n]{4,40}?\d{1,2}:\d{2}:\d{2}[^\t\r\n]{0,6}\t|\z)')
    $count = 0
    foreach ($p in $S05.Gen) {
        $fp = Join-Path $p.DataFolder 'log\autosandbox.log'
        if (-not [IO.File]::Exists($fp)) { continue }
        $text = (Read-S05Text -Path $fp -CodePage $p.CodePage).Text
        $rows = foreach ($m in $recRx.Matches($text)) {
            $body = $m.Groups['body'].Value
            [pscustomobject]@{
                dt = ConvertFrom-S05LocalStamp -Text $m.Groups['stamp'].Value -Culture $p.Culture
                path = $m.Groups['path'].Value.Trim()
                result = ([regex]::Match($body, '-->\s*[^:\r\n]+:\s*(?<r>[^\r\n]+)')).Groups['r'].Value.Trim()
            }
        }
        $rows = @($rows)
        $count += $rows.Count
        $byResult = @($rows | Group-Object result | Sort-Object Count -Descending | ForEach-Object {
                $g = @($_.Group | Sort-Object dt); [ordered]@{ result = $_.Name; count = $_.Count; firstUtc = Format-S05Utc $g[0].dt; lastUtc = Format-S05Utc $g[-1].dt } })
        $topBy = { param($filter) @($rows | Where-Object $filter | Group-Object path | Sort-Object Count -Descending | Select-Object -First 30 | ForEach-Object {
                    $g = @($_.Group | Sort-Object dt); [ordered]@{ path = $_.Name; count = $_.Count; lastUtc = Format-S05Utc $g[-1].dt } }) }
        $S05.Autosandbox.Add([ordered]@{
                product = $p.Name; file = $fp; records = $rows.Count; timesAssumed = 'local'
                byResult = $byResult
                exceptionListHits = (& $topBy { $_.result -match '(?i)exception' })
                sandboxed = (& $topBy { $_.result -match '(?i)^sandboxing' })
                custody = (& $topBy { $_.result -match '(?i)custody processed' })
            })
    }
    if (-not $S05.Autosandbox.Count) { Set-BvsCheckStatus -Id 'avast.autosandbox' -Status not_applicable -Reason 'autosandbox.log not present' }
    $count
}

$null = Invoke-BvsCheck -Run $run -Id 'avast.antirootkit_uefi' -Description 'Avast/AVG anti-rootkit (aswAr*.log) and UEFI scan results' -Script {
    if (-not $S05.Gen.Count) { Set-BvsCheckStatus -Id 'avast.antirootkit_uefi' -Status not_applicable -Reason 'Avast/AVG not installed'; return }
    foreach ($p in $S05.Gen) {
        foreach ($n in 'aswAr.log', 'aswArStartup.log') {
            $fp = Join-Path $p.DataFolder "log\$n"
            if (-not [IO.File]::Exists($fp)) { continue }
            $t = (Read-S05Text -Path $fp -CodePage $p.CodePage).Text
            $cnt = { param($what) $m = [regex]::Match($t, "(?im)^\s*Hidden $what found:\s*(?<n>\d+)"); if ($m.Success) { [int]$m.Groups['n'].Value } else { $null } }
            $S05.AntiRootkit.Add([ordered]@{
                    product = $p.Name; file = $n; kind = $(if ($n -match 'Startup') { 'startup scan' } else { 'on-demand / smart scan' })
                    scanFinishedUtc = Format-S05Utc ([IO.File]::GetLastWriteTimeUtc($fp))
                    version = ([regex]::Match($t, '(?im)Antirootkit, version\s+(?<v>[^\r\n]+)')).Groups['v'].Value.Trim()
                    hiddenFiles = (& $cnt 'files'); hiddenRegistryItems = (& $cnt 'registry items'); hiddenProcesses = (& $cnt 'processes')
                    hiddenServices = (& $cnt 'services'); hiddenBootSectors = (& $cnt 'boot sectors')
                    status = ([regex]::Match($t, '(?im)^\s*Status\s+(?<s>[^\r\n]+)')).Groups['s'].Value.Trim()
                    objectsListed = ([regex]::Matches($t, '(?im)^\s*(Process|Service|File|Driver|Module)\s')).Count
                })
        }
        $ini = Join-Path $p.DataFolder 'uefiscan.ini'
        $log = Join-Path $p.DataFolder 'log\uefiscan.log'
        if ([IO.File]::Exists($ini) -or [IO.File]::Exists($log)) {
            $last = $null; $mods = $null
            if ([IO.File]::Exists($ini)) { $m = [regex]::Match((Read-S05Text -Path $ini).Text, '(?ims)^\[UEFI\][^\[]*?^\s*LastScan\s*=\s*(?<v>\d+)'); if ($m.Success) { $last = ConvertFrom-S05Unix $m.Groups['v'].Value } }
            if ([IO.File]::Exists($log)) { $mods = ([regex]::Matches((Read-S05Text -Path $log).Text, '(?m)^\s*FILE\s*:')).Count }
            $S05.Uefi.Add([ordered]@{ product = $p.Name; lastScanUtc = Format-S05Utc $last; firmwareModulesListed = $mods; note = 'The UEFI log is a module inventory without a verdict; UEFI detections would appear as detection events.' })
        }
    }
    if (-not $S05.AntiRootkit.Count -and -not $S05.Uefi.Count) { Set-BvsCheckStatus -Id 'avast.antirootkit_uefi' -Status not_applicable -Reason 'no anti-rootkit or UEFI scan logs' }
    @($S05.AntiRootkit) + @($S05.Uefi)
}

#endregion

#region ---------- checks: Microsoft ----------

$null = Invoke-BvsCheck -Run $run -Id 'msrt.log' -Description 'Malicious Software Removal Tool runs (%windir%\debug\mrt.log): results summary per run' -Script {
    $fp = Join-Path $env:windir 'debug\mrt.log'
    if (-not [IO.File]::Exists($fp)) { Set-BvsCheckStatus -Id 'msrt.log' -Status not_applicable -Reason 'mrt.log not present (MSRT never ran or log cleaned)'; return }
    foreach ($r in @(ConvertFrom-S05MsLog -Text (Read-S05Text -Path $fp).Text -SourceFile $fp)) { if ($r.product -eq 'msrt') { $S05.MsrtRuns.Add($r) } }
    foreach ($r in $S05.MsrtRuns) { Add-S05MsRunDetections -RunRec $r -Source 'msrt' -Product 'MSRT' }
    if (-not $S05.MsrtRuns.Count) { Set-BvsCheckStatus -Id 'msrt.log' -Status partial -Reason 'mrt.log present but no run block could be parsed' }
    @($S05.MsrtRuns)
}

$null = Invoke-BvsCheck -Run $run -Id 'defender.threat_cmdlets' -Description 'Microsoft Defender Get-MpThreatDetection / Get-MpThreat history' -Script {
    if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) { Set-BvsCheckStatus -Id 'defender.threat_cmdlets' -Status not_applicable -Reason 'Defender PowerShell module not available'; return }
    $st = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { $S05.Defender.statusError = $_.Exception.Message }
    if ($st) {
        $S05.Defender.status = [ordered]@{
            amRunningMode = $st.AMRunningMode; amServiceEnabled = $st.AMServiceEnabled; antivirusEnabled = $st.AntivirusEnabled
            realTimeProtectionEnabled = $st.RealTimeProtectionEnabled; amProductVersion = $st.AMProductVersion; amEngineVersion = $st.AMEngineVersion
            signatureVersion = $st.AntivirusSignatureVersion; signatureLastUpdatedUtc = Format-S05Utc $st.AntivirusSignatureLastUpdated
            quickScanEndUtc = Format-S05Utc $st.QuickScanEndTime; fullScanEndUtc = Format-S05Utc $st.FullScanEndTime
        }
    }
    $errs = [System.Collections.Generic.List[string]]::new()
    $det = @(); $thr = @()
    try { $det = @(Get-MpThreatDetection -ErrorAction Stop) } catch { $errs.Add("Get-MpThreatDetection: $($_.Exception.Message)") }
    try { $thr = @(Get-MpThreat -ErrorAction Stop) } catch { $errs.Add("Get-MpThreat: $($_.Exception.Message)") }
    $names = @{}; foreach ($t in $thr) { $names["$($t.ThreatID)"] = $t.ThreatName }
    $statusMap = @{ 0 = 'unknown'; 1 = 'detected'; 2 = 'cleaned'; 3 = 'quarantined'; 4 = 'removed'; 5 = 'allowed'; 6 = 'blocked'; 102 = 'quarantine_failed'; 103 = 'remove_failed'; 104 = 'allow_failed'; 105 = 'abandoned'; 107 = 'block_failed' }
    foreach ($d in $det) {
        $nm = $names["$($d.ThreatID)"]; if (-not $nm) { $nm = "ThreatID $($d.ThreatID)" }
        $act = $statusMap[[int]$d.ThreatStatusID]; if (-not $act) { $act = "status_$($d.ThreatStatusID)" }
        $paths = @(Get-S05MsResourcePaths -Resources @($d.Resources))
        if (-not $paths.Count) { $paths = @($null) }
        foreach ($pp in $paths) {
            $S05.Detections.Add((New-S05Detection -Source 'defender.mp' -Product 'Defender' -DateUtc $d.InitialDetectionTime -RawName $nm -Vendor microsoft -Path $pp -Action $act -ActionDetail ("ActionSuccess=$($d.ActionSuccess); process=$($d.ProcessName)") -ActionSource 'Get-MpThreatDetection'))
        }
    }
    $S05.Defender.cmdletDetections = $det.Count
    $S05.Defender.cmdletThreats = $thr.Count
    if ($errs.Count -and -not $det.Count) { throw ($errs -join ' | ') }
    $notRunning = $st -and ($st.AMRunningMode -match '(?i)not running' -or -not $st.AMServiceEnabled)
    if ($notRunning) { Set-BvsCheckStatus -Id 'defender.threat_cmdlets' -Status partial -Reason "Defender is not running (AMRunningMode=$($st.AMRunningMode)); the cmdlets returned $($det.Count) detections / $($thr.Count) threats, which is not evidence of absence" }
    elseif ($errs.Count) { Set-BvsCheckStatus -Id 'defender.threat_cmdlets' -Status partial -Reason ($errs -join ' | ') }
    $det
}

$null = Invoke-BvsCheck -Run $run -Id 'defender.event_log' -Description 'Microsoft Defender Operational log detections (1006-1008, 1015, 1116-1119)' -Script {
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    $meta = $null
    try { $meta = Get-WinEvent -ListLog $log -ErrorAction Stop } catch { Set-BvsCheckStatus -Id 'defender.event_log' -Status not_applicable -Reason "event log '$log' not present"; return }
    $oldest = $null
    try { $o = Get-WinEvent -LogName $log -MaxEvents 1 -Oldest -ErrorAction Stop; $oldest = Format-S05Utc $o.TimeCreated } catch { }
    $S05.Defender.eventLog = [ordered]@{ records = $meta.RecordCount; oldestEventUtc = $oldest; enabled = $meta.IsEnabled; maxSizeBytes = $meta.MaximumSizeInBytes }
    $evs = @()
    try { $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119 } -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $evs = @() } else { throw } }
    $groups = @{}
    foreach ($e in $evs) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($dn in @($x.Event.EventData.Data)) { if ($dn.Name) { $data[$dn.Name] = $dn.'#text' } }
        $key = if ($data['Detection ID']) { $data['Detection ID'] } else { "rec$($e.RecordId)" }
        if (-not $groups.ContainsKey($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add(@{ Id = $e.Id; Time = $e.TimeCreated; Data = $data })
    }
    foreach ($k in $groups.Keys) {
        $g = @($groups[$k] | Sort-Object { $_.Time })
        $firstEv = $g[0]; $lastEv = $g[-1]
        $nm = @($g | ForEach-Object { $_.Data['Threat Name'] } | Where-Object { $_ })[0]
        $act = @($g | Where-Object { $_.Id -in 1117, 1007 } | ForEach-Object { $_.Data['Action Name'] } | Where-Object { $_ })[-1]
        $failed = @($g | Where-Object { $_.Id -in 1118, 1119, 1008 }).Count -gt 0
        $action = if ($failed) { 'action_failed' } elseif ($act) { ([string]$act).ToLowerInvariant() } elseif ($firstEv.Id -eq 1015) { 'behavior_reported' } else { 'detected' }
        $paths = @(Get-S05MsResourcePaths -Resources @($g | ForEach-Object { $_.Data['Path'] }))
        if (-not $paths.Count) { $paths = @($null) }
        foreach ($pp in ($paths | Select-Object -Unique)) {
            $S05.Detections.Add((New-S05Detection -Source 'defender.event' -Product 'Defender' -DateUtc $firstEv.Time -RawName $(if ($nm) { $nm } else { 'unknown' }) -Vendor microsoft -Path $pp -Action $action `
                        -ActionDetail ("events " + (($g | ForEach-Object { $_.Id }) -join ',') + "; severity=$($firstEv.Data['Severity Name']); category=$($firstEv.Data['Category Name']); user=$($firstEv.Data['Detection User'])") -ActionSource 'event log'))
        }
    }
    $S05.Defender.eventDetections = $groups.Count
    $evs
}

$null = Invoke-BvsCheck -Run $run -Id 'defender.detection_history' -Description 'Microsoft Defender DetectionHistory folder (Scans\History\Service\DetectionHistory)' -Script {
    $wd = Join-Path $env:ProgramData 'Microsoft\Windows Defender'
    if (-not [IO.Directory]::Exists($wd)) { Set-BvsCheckStatus -Id 'defender.detection_history' -Status not_applicable -Reason 'Windows Defender data folder not present'; return }
    $scans = Join-Path $wd 'Scans'
    $dh = Join-Path (Join-Path (Join-Path $scans 'History') 'Service') 'DetectionHistory'
    try { $items = @([IO.Directory]::EnumerateFileSystemEntries($dh, '*', [IO.SearchOption]::AllDirectories)) }
    catch [UnauthorizedAccessException] { Set-BvsCheckStatus -Id 'defender.detection_history' -Status needs_admin -Reason 'Defender Scans folder is readable only by administrators/SYSTEM'; return }
    catch [IO.DirectoryNotFoundException] {
        $denied = $false
        try { $null = [IO.Directory]::GetDirectories($scans) } catch [UnauthorizedAccessException] { $denied = $true } catch { }
        if ($denied) { Set-BvsCheckStatus -Id 'defender.detection_history' -Status needs_admin -Reason 'Defender Scans folder is readable only by administrators/SYSTEM (cannot tell whether DetectionHistory exists)' }
        else { Set-BvsCheckStatus -Id 'defender.detection_history' -Status ok -Reason 'DetectionHistory folder does not exist (no Defender detections recorded)' }
        return
    }
    $S05.Defender.detectionHistoryFiles = $items.Count
    $items
}

$null = Invoke-BvsCheck -Run $run -Id 'msert.results' -Description 'Microsoft Safety Scanner results (%windir%\debug\msert.log, data\<scan>\admin\msert-*.log)' -Script {
    $cands = [System.Collections.Generic.List[string]]::new()
    $m1 = Join-Path $env:windir 'debug\msert.log'
    if ([IO.File]::Exists($m1)) { $cands.Add($m1) }
    $adminDir = Join-Path $run.ScanDir 'admin'
    if ([IO.Directory]::Exists($adminDir)) { foreach ($f in [IO.Directory]::GetFiles($adminDir, 'msert*.log')) { $cands.Add($f) } }
    if (-not $cands.Count) { Set-BvsCheckStatus -Id 'msert.results' -Status skipped -Reason 'msert not run yet'; return }
    $seen = @{}
    $unreadable = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $cands) {
        $info = [IO.FileInfo]::new($f)
        $src = [ordered]@{ path = $f; sizeBytes = $info.Length; lastWriteUtc = Format-S05Utc $info.LastWriteTimeUtc; runs = 0; error = $null }
        try { $text = (Read-S05Text -Path $f).Text } catch { $src.error = $_.Exception.Message; $unreadable.Add($f); $S05.MsertSources.Add($src); continue }
        foreach ($r in @(ConvertFrom-S05MsLog -Text $text -SourceFile $f)) {
            if ($r.product -ne 'msert') { continue }
            $src.runs++
            $k = "$($r.version)|$($r.startedUtc)"
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            $S05.MsertRuns.Add($r)
        }
        $S05.MsertSources.Add($src)
    }
    foreach ($r in $S05.MsertRuns) { Add-S05MsRunDetections -RunRec $r -Source 'msert' -Product 'msert' }
    $latest = $S05.MsertRuns | Sort-Object { $_.startedUtc } | Select-Object -Last 1
    if (-not $S05.MsertRuns.Count) {
        if ($unreadable.Count -eq $cands.Count) { Set-BvsCheckStatus -Id 'msert.results' -Status needs_admin -Reason ('msert log(s) not readable: ' + ($unreadable -join ', ')) }
        else { Set-BvsCheckStatus -Id 'msert.results' -Status partial -Reason 'msert log present but no run block could be parsed' }
    }
    elseif (-not $latest.complete) { Set-BvsCheckStatus -Id 'msert.results' -Status partial -Reason "latest msert run ($($latest.startedUtc)) has no 'Finished On' or return code: still running or interrupted" }
    @($S05.MsertRuns)
}

#endregion

#region ---------- checks: presence, Security Center ----------

$null = Invoke-BvsCheck -Run $run -Id 'detections.presence' -Description 'For every file detection: does a file still exist at the original path? Facts for present files' -Script {
    $cache = @{}
    $factsDone = 0
    foreach ($r in $S05.Detections) {
        if ($r.objectKind -ne 'file' -or -not $r.path) { continue }
        $k = $r.path.ToLowerInvariant()
        if (-not $cache.ContainsKey($k)) {
            $st = @{ Exists = $null; Modified = $null }
            try {
                $info = [IO.FileInfo]::new($r.path)
                if ($info.Exists) { $st.Exists = $true; $st.Modified = $info.LastWriteTimeUtc }
                elseif ([IO.Directory]::Exists($r.path)) { $st.Exists = $true; $st.Modified = [IO.Directory]::GetLastWriteTimeUtc($r.path) }
                else { $st.Exists = $false }
            }
            catch { $st.Exists = $null }
            $cache[$k] = $st
        }
        $st = $cache[$k]
        $r.stillPresent = $st.Exists
        if ($st.Exists) {
            $r.fileModifiedUtc = Format-S05Utc $st.Modified
            if ($r._dt) { $r.recreatedAfterDetection = ($st.Modified -gt $r._dt.AddSeconds(2)) }
        }
    }
    $present = @($S05.Detections | Where-Object { $_.stillPresent -eq $true -and -not $_.ownActivity -and $_.category -in 'malware', 'pup', 'tool', 'suspicious' -and @($_.fpHints) -notcontains 'doc_content' })
    $factCache = @{}
    foreach ($r in $present) {
        $k = $r.path.ToLowerInvariant()
        if (-not $factCache.ContainsKey($k)) {
            if ($factsDone -ge 100 -or (Test-BvsNeverRead $r.path) -or -not [IO.File]::Exists($r.path)) { $factCache[$k] = $null }
            else {
                $factsDone++
                $info = [IO.FileInfo]::new($r.path)
                $sig = Get-BvsSignature -Path $r.path
                $motw = Get-BvsMotw -Path $r.path
                $mg = Get-BvsMagic -Path $r.path
                $factCache[$k] = [ordered]@{
                    size = $info.Length; createdUtc = Format-S05Utc $info.CreationTimeUtc; modifiedUtc = Format-S05Utc $info.LastWriteTimeUtc
                    sha256 = (Get-BvsHash -Path $r.path -MaxBytes 256MB); sigStatus = $(if ($sig) { $sig.Status } else { $null }); signer = $(if ($sig) { $sig.Signer } else { $null })
                    motwZone = $(if ($motw) { $motw.ZoneId } else { $null }); motwHost = $(if ($motw) { $motw.HostDomain } else { $null })
                    magic = $(if ($mg) { $mg.Type } else { $null }); userWritable = (Test-BvsUserWritable -Path $r.path)
                }
            }
        }
        $r.facts = $factCache[$k]
    }
    @($S05.Detections | Where-Object { $_.objectKind -eq 'file' })
}

$null = Invoke-BvsCheck -Run $run -Id 'wsc.products' -Description 'Windows Security Center antivirus/antispyware/firewall registrations with decoded productState' -Script {
    $classes = [ordered]@{ AntiVirusProduct = 'antivirus'; AntiSpywareProduct = 'antispyware'; FirewallProduct = 'firewall' }
    $na = $false
    foreach ($cls in $classes.Keys) {
        $items = @()
        try { $items = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $cls -ErrorAction Stop) }
        catch { if ($_.Exception.Message -match '(?i)invalid namespace|not found|0x8004100e') { $na = $true; continue } else { throw } }
        foreach ($i in $items) {
            $dec = ConvertFrom-S05ProductState -State ([long]$i.productState)
            $paths = [ordered]@{}
            foreach ($pn in 'pathToSignedProductExe', 'pathToSignedReportingExe') {
                $v = [string]$i.$pn
                if (-not $v -or $v -match '://') { continue }
                $x = [Environment]::ExpandEnvironmentVariables($v) -replace '^\\\\\?\\', ''
                $paths[$pn] = [ordered]@{ path = $x; exists = [IO.File]::Exists($x) }
            }
            $checkable = @($paths.Values)
            $ts = $null; $tmp = [datetime]::MinValue
            if ($i.timestamp -and [datetime]::TryParseExact([string]$i.timestamp, 'r', $Inv, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$tmp)) { $ts = $tmp }
            $S05.Wsc.Add([ordered]@{
                    productType = $classes[$cls]; displayName = $i.displayName; instanceGuid = $i.instanceGuid
                    productState = $dec; productExe = $i.pathToSignedProductExe; reportingExe = $i.pathToSignedReportingExe
                    exeChecks = $paths; stale = ($checkable.Count -gt 0 -and @($checkable | Where-Object { $_.exists }).Count -eq 0)
                    timestampUtc = Format-S05Utc $ts
                })
        }
    }
    if ($na -and -not $S05.Wsc.Count) { Set-BvsCheckStatus -Id 'wsc.products' -Status not_applicable -Reason 'root\SecurityCenter2 not available (Windows Server or WSC disabled)' }
    @($S05.Wsc)
}

#endregion

#region ---------- assessment: findings ----------

function Get-S05RowVerdict {
    param($R)
    $hints = @($R.fpHints)
    if ($R.ownActivity) { return @{ Bucket = 'own'; Severity = 'info' } }
    if ($R.objectKind -eq 'url') {
        if ($hints -contains 'content_platform' -and $R.category -ne 'url') { return @{ Bucket = 'web_platform'; Severity = 'info' } }
        return @{ Bucket = 'web_blocked'; Severity = 'low' }
    }
    if ($R.objectKind -ne 'file') { return @{ Bucket = 'other'; Severity = 'low' } }
    $expPath = @($hints | Where-Object { $_ -like 'expected_path:*' }).Count -gt 0
    $doc = $hints -contains 'doc_content'
    $generic = $hints -contains 'generic_heuristic'
    $devc = $hints -contains 'dev_cache'
    $exec = (@(Get-S05Heur 'executableExtensions') -contains $R.extension) -or ($R.facts -and $R.facts.magic -in 'pe', 'elf')
    $container = @(Get-S05Heur 'activeContainerExtensions') -contains $R.extension
    $present = ($R.stillPresent -eq $true)
    $recreated = ($R.recreatedAfterDetection -eq $true) -and ($R.action -in 'quarantined', 'deleted', 'removed')
    if ($expPath) { return @{ Bucket = 'expected_path'; Severity = 'low' } }
    if ($doc -and $R.category -in 'malware', 'pup', 'tool', 'suspicious') {
        return @{ Bucket = 'doc_content'; Severity = $(if ($present -and -not $recreated -and $R.category -eq 'malware') { 'medium' } else { 'low' }) }
    }
    switch ($R.category) {
        'malware' {
            if ($present -and -not $recreated) {
                if ($exec -and -not $generic -and -not $devc) { return @{ Bucket = 'live_malware'; Severity = 'critical'; Class = 'compromise' } }
                if ($generic -and $exec -and $devc -and $R.facts -and $null -eq $R.facts.motwZone) { return @{ Bucket = 'live_suspect'; Severity = 'medium' } }
                return @{ Bucket = 'live_suspect'; Severity = 'high' }
            }
            if ($present) { return @{ Bucket = 'recreated'; Severity = 'medium' } }
            $hr = (-not $generic) -and ($R.name -match (Get-S05Heur 'highRiskNamePattern')) -and ($exec -or $container -or -not $R.extension)
            return @{ Bucket = 'history_malware'; Severity = $(if ($hr) { 'high' } else { 'medium' }) }
        }
        { $_ -in 'pup', 'tool' } {
            if ($present -and -not $recreated) { return @{ Bucket = 'live_pup'; Severity = 'medium' } }
            return @{ Bucket = 'history_minor'; Severity = 'low' }
        }
        'suspicious' {
            if ($present -and -not $recreated -and ($exec -or $container)) { return @{ Bucket = 'live_heuristic'; Severity = 'medium' } }
            if ($present -and -not $recreated) { return @{ Bucket = 'live_heuristic'; Severity = 'low' } }
            return @{ Bucket = 'history_minor'; Severity = 'low' }
        }
        default { return @{ Bucket = 'history_minor'; Severity = 'low' } }
    }
}

function New-S05DetEvidence {
    param($R)
    $e = [ordered]@{ type = 'av_detection'; source = $R.source; product = $R.product; shield = $R.shield; date = $R.date; name = $R.name; detectionType = $R.type; action = $R.action; stillPresent = $R.stillPresent }
    if ($R.path) { $e.path = $R.path }
    if ($R.url) { $e.url = $R.url }
    if ($R.chestId) { $e.chestId = $R.chestId }
    $e
}

function New-S05FileEntity {
    param($R)
    $f = $R.facts
    if (-not $f) { return [ordered]@{ path = $R.path } }
    [ordered]@{
        path = $R.path; sha256 = $f.sha256; size = $f.size; sig = $f.sigStatus; signer = $f.signer; created = $f.createdUtc
        motw = $(if ($null -ne $f.motwZone) { [ordered]@{ zone = $f.motwZone; host = $f.motwHost } } else { $null })
    }
}

function Get-S05TopEvidence {
    param([object[]]$Rows, [int]$Max = 15)
    @($Rows | Sort-Object { $_.date } -Descending | Select-Object -First $Max | ForEach-Object { New-S05DetEvidence $_ })
}

$null = Invoke-BvsCheck -Run $run -Id 's05.assessment' -Description 'Judge detections and protection state, create calibrated findings' -Script {
    $rows = @($S05.Detections)
    foreach ($r in $rows) { $v = Get-S05RowVerdict $r; $r.assessment = $v.Bucket; $r['_sev'] = $v.Severity; $r['_class'] = $v.Class }
    $made = 0

    # --- live artifacts: one finding per path ---
    foreach ($g in @($rows | Where-Object { $_.assessment -in 'live_malware', 'live_suspect' } | Group-Object { $_.path.ToLowerInvariant() })) {
        $grp = @($g.Group | Sort-Object { $_.date })
        $r = $grp[-1]
        $sev = Get-S05MaxSeverity @($grp | ForEach-Object { $_._sev })
        $isCrit = $sev -eq 'critical'
        $reasons = [System.Collections.Generic.List[string]]::new()
        $reasons.Add($(if ($isCrit) { 'av_match' } else { 'av_detection_live' }))
        if ($r.facts) {
            if ($r.facts.userWritable) { $reasons.Add('user_writable') }
            if ($r.facts.sigStatus -eq 'NotSigned') { $reasons.Add('unsigned') }
            if ($r.facts.createdUtc -and ([datetime]::Parse($r.facts.createdUtc, $Inv).ToUniversalTime() -gt [datetime]::UtcNow.AddDays(-30))) { $reasons.Add('created_lt_30d') }
            if ($null -ne $r.facts.motwZone -and $r.facts.motwZone -ge 3) { $reasons.Add('downloaded') }
        }
        foreach ($h in @($r.fpHints)) { $reasons.Add($h) }
        $genericWhy = @((Get-S05Heur 'genericHeuristicNames') | Where-Object { $_ -and $r.name -match $_.pattern } | ForEach-Object { $_.why }) -join ' '
        $fp = 'AV names can be false positives, especially generic or reputation verdicts; the file may also have been restored from quarantine on purpose.'
        if ($genericWhy) { $fp += " $genericWhy" }
        if (@($r.fpHints) -contains 'dev_cache') { $fp += ' The file sits in a build/dependency cache, where bundlers regenerate files and generic script signatures misfire.' }
        $title = if ($isCrit) { "$($r.product) detected $($r.name) in a file that is still present ($([IO.Path]::GetFileName($r.path)), $(Get-S05DateOnly $r.date))" } else { "$($r.name) detection on a still-present file needs verification ($([IO.Path]::GetFileName($r.path)), $(Get-S05DateOnly $r.date))" }
        New-BvsFinding -Run $run -Check 's05.assessment' -Title $title -Severity $sev -Class $(if ($isCrit) { 'compromise' } else { 'suspicious' }) -Confidence 'medium' `
            -Reasons @($reasons | Select-Object -Unique) -Evidence (Get-S05TopEvidence $grp) -Entities @{ files = @(New-S05FileEntity $r) } `
            -FpNotes $fp `
            -Recommendation 'Do not open or run the file. Verify it with a second engine (Microsoft Safety Scanner report-only, or the hash on VirusTotal if you accept sharing the hash). If confirmed, quarantine it with the antivirus, then review persistence findings (Run keys, tasks, services) that reference this path and the download source (MOTW host).'
        $made++
    }

    # --- live PUP / tools / heuristic, re-created files: one finding per name ---
    foreach ($spec in @(
            @{ B = 'live_pup'; T = 'Potentially unwanted program or hacking tool still present'; F = 'PUP, HackTool and RiskWare names cover legitimate admin and security tools; they are expected on a PC used for security work and are not malware by themselves.'; R = 'Keep only tools you installed knowingly and still use; uninstall or delete the rest. Never run cracked or keygen tools.' },
            @{ B = 'live_heuristic'; T = 'Heuristic detection on a still-present file'; F = 'Heuristic/suspicious verdicts are probability calls and often hit self-built or rare binaries.'; R = 'Check the file origin (MOTW host, signer). If you built it yourself, no action; otherwise scan it with a second engine.' },
            @{ B = 'recreated'; T = 'Quarantined file re-created at the same path after detection'; F = 'Build tools and package managers regenerate files with the same name; the current version was not detected again after it was written.'; R = 'Re-scan the current file with the antivirus (right-click > Scan) and check the package/source that regenerates it.' })) {
        foreach ($g in @($rows | Where-Object { $_.assessment -eq $spec.B } | Group-Object { $_.name })) {
            $grp = @($g.Group); $rg = Get-S05Range $grp
            $sev = Limit-S05Severity -Severity (Get-S05MaxSeverity @($grp | ForEach-Object { $_._sev })) -Cap 'medium'
            $exp = if ($spec.B -eq 'live_pup') { Get-S05ExpectedAvDetection -Rows $grp } else { $null }
            if ($exp -and -not $exp.cancelled) { $sev = Limit-S05Severity -Severity $sev -Cap $exp.severityCap }
            $distinct = @($grp | ForEach-Object { $_.path } | Select-Object -Unique)
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0}: {1} ({2} file(s), {3}..{4})" -f $spec.T, $g.Name, $distinct.Count, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
                -Severity $sev -Class 'suspicious' -Confidence 'medium' -Reasons @('av_detection_live', $spec.B) -Evidence (Get-S05TopEvidence $grp) `
                -Entities @{ files = @($grp | Group-Object { $_.path } | ForEach-Object { New-S05FileEntity $_.Group[0] } | Select-Object -First 20) } -FpNotes $spec.F -Recommendation $spec.R -Expected $exp
            $made++
        }
    }

    # --- removed / quarantined malware: one finding per family ---
    foreach ($g in @($rows | Where-Object { $_.assessment -eq 'history_malware' } | Group-Object { $_.name })) {
        $grp = @($g.Group); $rg = Get-S05Range $grp
        $sev = Get-S05MaxSeverity @($grp | ForEach-Object { $_._sev })
        $acts = (@($grp | Group-Object { $_.action } | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ')
        $genericWhy = @((Get-S05Heur 'genericHeuristicNames') | Where-Object { $_ -and $g.Name -match $_.pattern } | ForEach-Object { $_.why }) -join ' '
        $fp = 'The antivirus already removed or quarantined these files and they are no longer at their original paths. A detection proves the file arrived, not that it ran.'
        if ($genericWhy) { $fp += " $genericWhy" }
        if (@($grp | Where-Object { @($_.fpHints) -contains 'dev_cache' }).Count) { $fp += ' The files were inside a build/dependency cache (node_modules, .vite, venv ...), where generic script signatures often misfire on minified bundles.' }
        $products = (@($grp | ForEach-Object { $_.product } | Select-Object -Unique) -join '/')
        New-BvsFinding -Run $run -Check 's05.assessment' `
            -Title ("{0} removed {1} ({2}x, {3}..{4}): files no longer present" -f $products, $g.Name, $grp.Count, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
            -Severity $sev -Class 'suspicious' -Confidence $(if ($genericWhy -or @($grp | Where-Object { @($_.fpHints) -contains 'dev_cache' }).Count) { 'low' } else { 'medium' }) `
            -Reasons @('av_detection_history', 'quarantined') -Evidence (Get-S05TopEvidence $grp) -FpNotes ($fp + " Actions: $acts.") `
            -Recommendation 'Correlate with persistence and execution findings from other modules around these dates. Find how the file arrived (download, archive, package install). Leave the Virus Chest entries quarantined unless you have confirmed a false positive. For files in a dependency cache, check the package version against advisories and reinstall from a clean lockfile.'
        $made++
    }

    # --- documentation / text content hits: one combined finding ---
    $doc = @($rows | Where-Object { $_.assessment -eq 'doc_content' })
    if ($doc.Count) {
        $rg = Get-S05Range $doc
        $distinct = @($doc | ForEach-Object { $_.path } | Select-Object -Unique)
        $presentN = @($doc | Where-Object { $_.stillPresent -eq $true } | ForEach-Object { $_.path } | Select-Object -Unique).Count
        $acts = (@($doc | Group-Object { $_.action } | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', ')
        $corpus = @($doc | Where-Object { @($_.fpHints) -contains 'security_corpus' }).Count
        $folders = @($distinct | ForEach-Object { $d = [IO.Path]::GetDirectoryName($_); if ($d) { $d } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ type = 'folder'; path = $_.Name; files = $_.Count } })
        $ev = @([ordered]@{ type = 'summary'; detections = $doc.Count; distinctFiles = $distinct.Count; stillPresentFiles = $presentN; names = (Get-S05NameSummary $doc 10); actions = $acts; securityCorpusRows = $corpus; first = $rg.first; last = $rg.last }) + $folders + (Get-S05TopEvidence $doc 8)
        New-BvsFinding -Run $run -Check 's05.assessment' `
            -Title ("Antivirus flagged {0} documentation/text files {1}x ({2}..{3}): attack-technique text, likely content false positives" -f $distinct.Count, $doc.Count, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
            -Severity (Get-S05MaxSeverity @($doc | ForEach-Object { $_._sev })) -Class 'suspicious' -Confidence 'high' -Reasons @('av_content_hit', 'doc_content') -Evidence $ev `
            -FpNotes ("Script-malware signatures match example code inside Markdown/YAML/text documentation (for example Atomic Red Team, GTFOBins, Sigma rules); {0} of these rows are in recognised public attack-technique corpora. Windows does not execute .md/.yml/.txt files, so these hits cannot infect the machine; the same signatures also fire on web pages that show this text. Actions: {1}." -f $corpus, $acts) `
            -Recommendation 'No security action needed. Confirm the folders are your own reference data or research copies. If quarantining breaks a project, re-clone the corpus from its official source instead of restoring blindly; if you add an antivirus exclusion, scope it to that single corpus folder, never to Documents, AppData or Temp.'
        $made++
    }

    # --- expected paths (machine-specific known security tooling) ---
    $ep = @($rows | Where-Object { $_.assessment -eq 'expected_path' })
    if ($ep.Count) {
        $rg = Get-S05Range $ep
        $ids = @($ep | ForEach-Object { @($_.fpHints) | Where-Object { $_ -like 'expected_path:*' } } | ForEach-Object { $_.Substring(14) } | Select-Object -Unique)
        $item = @(Get-BvsExpected -Category path | Where-Object { $_.id -in $ids })[0]
        $exp = if ($item) { New-S05ExpectedRef -Item $item -Eval (Test-S05InvalidIf -Item $item -Context @{}) } else { $null }
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} detections inside known security-tooling folders ({1})" -f $ep.Count, ($ids -join ', ')) -Severity 'low' -Class 'info' -Confidence 'high' `
            -Reasons @('av_detection', 'expected_match') -Evidence (Get-S05TopEvidence $ep) -Expected $exp `
            -FpNotes 'These folders are listed in config\local\expected.json as the user''s own security tools (rules, IoC strings, test data by design).' -Recommendation 'No action unless a detection names a real executable you did not put there.'
        $made++
    }

    # --- removed PUP / heuristic / other ---
    $minor = @($rows | Where-Object { $_.assessment -in 'history_minor', 'other' })
    if ($minor.Count) {
        $rg = Get-S05Range $minor
        $exp = Get-S05ExpectedAvDetection -Rows $minor
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} PUP/heuristic detections were removed or blocked ({1}..{2})" -f $minor.Count, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
            -Severity 'low' -Class 'suspicious' -Confidence 'medium' -Reasons @('av_detection_history') -Evidence ((@([ordered]@{ type = 'summary'; names = (Get-S05NameSummary $minor 12) })) + (Get-S05TopEvidence $minor 10)) -Expected $exp `
            -FpNotes 'Potentially unwanted, tool and heuristic verdicts that the antivirus already handled; the files are gone or were never written.' -Recommendation 'Review the names; if a tool was wanted, reinstall it from the official source.'
        $made++
    }

    # --- Web Shield blocks ---
    $web = @($rows | Where-Object { $_.assessment -eq 'web_blocked' })
    if ($web.Count) {
        $rg = Get-S05Range $web
        $hosts = @($web | Where-Object { $_.host } | Group-Object { $_.host } | Sort-Object Count -Descending)
        $notes = @(Get-S05NotableNotes -Names @($web | ForEach-Object { $_.name } | Select-Object -Unique))
        $ev = @([ordered]@{ type = 'summary'; blocks = $web.Count; domains = $hosts.Count; names = (Get-S05NameSummary $web 14); first = $rg.first; last = $rg.last }) +
              @($hosts | Select-Object -First 25 | ForEach-Object { $g = @($_.Group | Sort-Object { $_.date }); [ordered]@{ type = 'domain'; host = $_.Name; count = $_.Count; first = (Get-S05DateOnly $g[0].date); last = (Get-S05DateOnly $g[-1].date); names = (@($g.name | Select-Object -Unique) -join ', ') } }) +
              @($notes | ForEach-Object { [ordered]@{ type = 'notable_family'; families = ($_.families -join ', '); note = $_.note; check = $_.check } })
        $mitre = [System.Collections.Generic.List[string]]::new(); $mitre.Add('T1189')
        if (@($web | Where-Object { $_.name -match '(?i)phish' }).Count) { $mitre.Add('T1566.002') }
        if (@($notes | Where-Object { ($_.families -join ' ') -match '(?i)HelloTDS|ClickFix|Captcha' }).Count) { $mitre.Add('T1204.004') }
        $rec = 'No cleanup needed for blocked items. Avoid the listed sites; blocked sites are often malvertising, piracy or compromised pages.'
        foreach ($n in $notes) { $rec += " $($n.families -join '/'): $($n.check)" }
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("Web Shield blocked {0} malicious URLs/scripts on {1} domains ({2}..{3}): attempts stopped, no infection evidence" -f $web.Count, $hosts.Count, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
            -Severity 'low' -Class 'suspicious' -Confidence 'high' -Reasons @('av_url_block', 'public_network') -Evidence $ev -Mitre @($mitre) `
            -FpNotes 'A block means the connection or script was stopped before anything was saved or run. URL:Blacklist/URL:Phishing are reputation blocks; some hit legitimate but compromised sites.' -Recommendation $rec
        $made++
    }

    # --- content-platform hits (claude.ai, github.com ...) ---
    $plat = @($rows | Where-Object { $_.assessment -eq 'web_platform' })
    if ($plat.Count) {
        $rg = Get-S05Range $plat
        $hosts = (@($plat | Group-Object { $_.host } | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', ')
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("Web Shield flagged {0} pages on developer/AI platforms ({1}; {2}..{3}): page text, likely false positives" -f $plat.Count, $hosts, (Get-S05DateOnly $rg.first), (Get-S05DateOnly $rg.last)) `
            -Severity 'info' -Class 'info' -Confidence 'high' -Reasons @('av_content_hit', 'content_platform') -Evidence ((@([ordered]@{ type = 'summary'; names = (Get-S05NameSummary $plat) })) + (Get-S05TopEvidence $plat 10)) `
            -FpNotes 'The same script signatures that hit attack-technique documentation also fire on code-hosting and AI chat pages that display that text (for example a repository diff or a chat session stream).' `
            -Recommendation 'No security action. If the blocks break your work on these sites, report the false positive to the vendor rather than disabling Web Shield.'
        $made++
    }

    # --- anti-rootkit / anti-exploit prompts without details ---
    foreach ($dl in $S05.DetLog) {
        $special = @($dl.Requests | Where-Object { $_.type -match '(?i)rootkit|exploit' })
        if (-not $special.Count) { continue }
        $times = @($special | ForEach-Object { $_._dt } | Sort-Object)
        $sess = @($S05.Sessions | Where-Object { $_.product -eq $dl.Product -and $_.kind -eq 'shield' -and $_.name -match '(?i)exploit|rootkit' -and $_.startedUtc } |
                Where-Object { $s = [datetime]::Parse($_.startedUtc, $Inv).ToUniversalTime(); @($times | Where-Object { [Math]::Abs(($_ - $s).TotalMinutes) -le 5 }).Count -gt 0 })
        $later = @($S05.AntiRootkit | Where-Object { $_.product -eq $dl.Product })
        $clean = @($later | Where-Object { $_.hiddenFiles -eq 0 -and $_.hiddenRegistryItems -eq 0 -and $_.hiddenProcesses -eq 0 -and $_.hiddenServices -eq 0 -and $_.hiddenBootSectors -eq 0 })
        $ev = @($special | ForEach-Object { [ordered]@{ type = 'detection_prompt'; source = 'detections.log'; time = $_.tsUtc; detectionType = $_.type; mode = $_.mode; userChoice = $_.choice } }) +
              @($sess | ForEach-Object { [ordered]@{ type = 'log_db_session'; shield = $_.name; startedUtc = $_.startedUtc; infectedFiles = $_.infectedFiles } }) +
              @($later | ForEach-Object { [ordered]@{ type = 'later_antirootkit_scan'; file = $_.file; finishedUtc = $_.scanFinishedUtc; hiddenFiles = $_.hiddenFiles; hiddenRegistryItems = $_.hiddenRegistryItems; hiddenProcesses = $_.hiddenProcesses; hiddenServices = $_.hiddenServices; hiddenBootSectors = $_.hiddenBootSectors } })
        $sevA = if ($later.Count -and $clean.Count -eq $later.Count) { 'low' } else { 'medium' }
        $shieldTxt = if ($sess.Count) { " (Log.db: $(@($sess.name | Select-Object -Unique) -join ', ') session started at the same time)" } else { '' }
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} showed {1} anti-rootkit/anti-exploit prompt(s) on {2} with no recorded object or name{3}" -f $dl.Product, $special.Count, (@($times | ForEach-Object { $_.ToString('yyyy-MM-dd HH:mm', $Inv) } | Select-Object -Unique) -join ', '), $shieldTxt) `
            -Severity $sevA -Class 'suspicious' -Confidence 'low' -Reasons @('av_detection_history', 'details_missing') -Evidence $ev `
            -FpNotes ('Anti-exploit prompts often fire on legitimate software that injects into other processes (overlays, game tools, debuggers, screen recorders). ' + $(if ($clean.Count) { "The later anti-rootkit scans ($(@($clean | ForEach-Object { Get-S05DateOnly $_.scanFinishedUtc }) -join ', ')) found no hidden files, registry items, processes, services or boot sectors." } else { 'No later anti-rootkit result was found.' })) `
            -Recommendation 'Ask yourself what was running at that time (the user was asked to choose an action). The readable logs keep no object name; Avast binary logs (*.bxlog) may, but they are not parsed. If unsure, run a full scan (Avast full scan or Microsoft Safety Scanner /F /N) and review persistence findings from that period.'
        $made++
    }

    # --- exclusions ---
    foreach ($g in @($S05.Exclusions | Group-Object { "$($_.product)|$($_.kind)" })) {
        $grp = @($g.Group); $kind = $grp[0].kind; $prod = $grp[0].product
        $last = @($grp | ForEach-Object { $_.keyLastWriteUtc } | Where-Object { $_ } | Sort-Object)[-1]
        $ev = @($grp | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'av_exclusion'; source = $_.source; key = $_.key; list = $_.list; kind = $_.kind; value = $_.value; exists = $_.exists; currentHashMatches = $_.currentHashMatches; signature = $_.signature; devLauncher = $_.devLauncher; broad = $_.broad; userWritable = $_.userWritable } })
        $mitre = @('T1562.001')
        if ($kind -eq 'hash') {
            $nonDev = @($grp | Where-Object { -not $_.devLauncher })
            $sev = if ($nonDev.Count) { 'medium' } else { 'low' }
            $cls = if ($nonDev.Count) { 'suspicious' } else { 'hardening' }
            $lists = (@($grp | ForEach-Object { $_.list } | Select-Object -Unique) -join ', ')
            $leaves = (@($grp | ForEach-Object { [IO.Path]::GetFileName($_.value) } | Group-Object | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', ')
            $hits = @($S05.Autosandbox | Where-Object { $_.product -eq $prod } | ForEach-Object { @($_.byResult) } | Where-Object { $_.result -match '(?i)exception' })
            $hitTxt = if ($hits.Count) { " The Auto-Sandbox log shows $(($hits | Measure-Object -Property count -Sum).Sum) launches skipped because of this list ($(Get-S05DateOnly $hits[0].firstUtc)..$(Get-S05DateOnly $hits[0].lastUtc))." } else { '' }
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} {1} exceptions: {2} hash-pinned file(s) ({3}); last changed {4}" -f $prod, $lists, $grp.Count, $leaves, (Get-S05DateOnly $last)) `
                -Severity $sev -Class $cls -Confidence 'medium' -Reasons @('av_exclusion') -Evidence $ev -Mitre $mitre `
                -FpNotes ("Hash-pinned exceptions only cover the exact file content, so a changed or replaced file is scanned again. {0} of {1} entries are developer console-script launchers (pip, cython, meson, uvicorn ...), which are unsigned and regenerated often, so Avast keeps sandboxing them.{2}" -f ($grp.Count - $nonDev.Count), $grp.Count, $hitTxt) `
                -Recommendation $(if ($nonDev.Count) { 'Review the non-developer entries listed in the evidence: confirm you added each one. Remove any exception you do not recognise (Avast > Menu > Settings > General > Exceptions / Blocked & Allowed apps).' } else { 'Fine to keep if you added them while developing. Remove stale entries for virtual environments you deleted.' })
        }
        else {
            $broad = @($grp | Where-Object { $_.broad })
            $writable = @($grp | Where-Object { $_.userWritable })
            $sev = if ($broad.Count) { 'high' } elseif ($writable.Count) { 'medium' } else { 'low' }
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} has {1} {2} exclusion(s){3}; last changed {4}" -f $prod, $grp.Count, $kind, $(if ($broad.Count) { ", $($broad.Count) broad" } else { '' }), (Get-S05DateOnly $last)) `
                -Severity $sev -Class $(if ($broad.Count) { 'suspicious' } else { 'hardening' }) -Confidence 'medium' -Reasons (@('av_exclusion') + @(if ($writable.Count) { 'user_writable' })) -Evidence $ev -Mitre $mitre `
                -FpNotes 'Developers often exclude build folders for speed; every exclusion is still a blind spot, and adding exclusions is a common attacker step to hide payloads.' `
                -Recommendation 'Confirm you added every exclusion. Remove broad ones (whole drives, user folders, Temp/AppData/Downloads, *.exe) and keep only narrow, project-specific paths.'
        }
        $made++
    }

    # --- Avast/AVG health ---
    foreach ($p in $S05.Gen) {
        $sh = @($S05.Shields | Where-Object { $_.product -eq $p.Name })
        $off = @($sh | Where-Object { $_.enabled -eq $false -or $_.temporarilyDisabled -eq $true })
        $defs = @($S05.Definitions | Where-Object { $_.product -eq $p.Name })[0]
        $feat = @($S05.Features | Where-Object { $_.product -eq $p.Name })[0]
        $wscAv = @($S05.Wsc | Where-Object { $_.productType -eq 'antivirus' -and $_.displayName -match [regex]::Escape($p.Name) })[0]
        $core = @($off | Where-Object { $_.shield -match '(?i)^(FileSystemShield|BehaviorShield|WebShield)$' })
        if ($off.Count) {
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} protection components disabled: {1}" -f $p.Name, (@($off | ForEach-Object { '{0}{1}' -f $_.shield, $(if ($_.temporarilyDisabled) { ' (temporarily)' } else { '' }) }) -join ', ')) `
                -Severity $(if ($core.Count) { 'high' } else { 'medium' }) -Class $(if ($core.Count) { 'suspicious' } else { 'hardening' }) -Confidence 'high' -Reasons @('av_tampering') -Mitre @('T1562.001') `
                -Evidence @($off | ForEach-Object { [ordered]@{ type = 'registry'; path = "$($p.PropsKey)\$($_.shield)\Common"; enabled = $_.enabled; temporarilyDisabled = $_.temporarilyDisabled; keyLastWriteUtc = $_.keyLastWriteUtc } }) `
                -FpNotes 'Users sometimes switch a shield off for a game, an installer or a false positive and forget to switch it back on.' -Recommendation 'Turn the components back on in the antivirus UI. If you did not switch them off, treat it as tampering and check persistence and admin-account findings.'
            $made++
        }
        if ($feat -and $feat.passiveMode) {
            New-BvsFinding -Run $run -Check 's05.assessment' -Title "$($p.Name) runs in Passive Mode (real-time shields off)" -Severity 'high' -Class 'hardening' -Confidence 'medium' -Reasons @('av_passive') -Evidence @([ordered]@{ type = 'registry'; path = "$($p.PropsKey)\settings\PassiveMode" }) `
                -FpNotes 'Passive Mode is normal only when another real-time antivirus is active.' -Recommendation 'Make sure exactly one real-time antivirus is active.'
            $made++
        }
        if ($defs -and $null -ne $defs.vpsAgeDays -and $defs.vpsAgeDays -gt 7) {
            New-BvsFinding -Run $run -Check 's05.assessment' -Title "$($p.Name) virus definitions are $($defs.vpsAgeDays) days old ($($defs.vps))" -Severity $(if ($defs.vpsAgeDays -gt 30) { 'high' } else { 'medium' }) -Class 'hardening' -Confidence 'high' -Reasons @('av_outdated') `
                -Evidence @([ordered]@{ type = 'file'; path = $defs.vpsSource; vps = $defs.vps; vpsDate = $defs.vpsDate }) -FpNotes 'Streaming updates may still deliver new signatures between VPS builds.' -Recommendation 'Open the antivirus and run an update; check the internet connection and that the update service is not blocked.'
            $made++
        }
        if (-not $off.Count -and $defs -and $null -ne $defs.vpsAgeDays -and $defs.vpsAgeDays -le 7 -and (-not $wscAv -or $wscAv.productState.enabled)) {
            $lastTask = @($S05.Sessions | Where-Object { $_.product -eq $p.Name -and $_.kind -eq 'scan_task' } | Sort-Object { $_.startedUtc })[-1]
            $ev = @(
                [ordered]@{ type = 'av_state'; product = $p.Name; version = $p.Version; build = $p.BuildVersion; shieldsEnabled = @($sh | Where-Object { $_.enabled }).Count; shieldsTotal = $sh.Count; vps = $defs.vps; vpsDate = $defs.vpsDate; latestStreamUpdateUtc = $defs.latestStreamUpdateUtc; wscState = $(if ($wscAv) { $wscAv.productState.state } else { $null }); wscDefinitions = $(if ($wscAv) { $wscAv.productState.definitions } else { $null }) }
                [ordered]@{ type = 'last_scan'; source = 'Log.db'; name = $(if ($lastTask) { $lastTask.name } else { $null }); image = $(if ($lastTask) { $lastTask.taskImage } else { $null }); startedUtc = $(if ($lastTask) { $lastTask.startedUtc } else { $null }); testedFiles = $(if ($lastTask) { $lastTask.testedFiles } else { $null }); infectedFiles = $(if ($lastTask) { $lastTask.infectedFiles } else { $null }) }
            )
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("{0} real-time protection active: {1}/{2} components on, definitions {3} ({4} day(s) old)" -f $p.Name, @($sh | Where-Object { $_.enabled }).Count, $sh.Count, $defs.vps, $defs.vpsAgeDays) `
                -Severity 'info' -Class 'info' -Confidence 'high' -Reasons @('av_healthy') -Evidence $ev -FpNotes 'State is read from the registry and Security Center; a compromised machine could fake it, so other modules still matter.' -Recommendation 'None.'
            $made++
        }
    }

    # --- Security Center: stale registrations, no active AV, Defender off ---
    $avs = @($S05.Wsc | Where-Object { $_.productType -eq 'antivirus' })
    $thirdOn = @($avs | Where-Object { $_.productState.owner -eq 'third_party' -and $_.productState.enabled })
    foreach ($w in @($S05.Wsc | Where-Object { $_.stale })) {
        $missing = @($w.exeChecks.Values | Where-Object { -not $_.exists } | ForEach-Object { $_.path })
        $exp = $null
        foreach ($e in @(Get-BvsExpected -Category securityCenter)) {
            $mt = $e.match
            if (-not $mt.PSObject.Properties['displayName']) { continue }
            if ($w.displayName -notlike "*$($mt.displayName)*") { continue }
            if ($mt.PSObject.Properties['productType'] -and $mt.productType -ne $w.productType) { continue }
            if ($mt.PSObject.Properties['pathMissing'] -and -not (@($missing | Where-Object { $_ -ieq [string]$mt.pathMissing }).Count)) { continue }
            $exp = New-S05ExpectedRef -Item $e -Eval (Test-S05InvalidIf -Item $e -Context @{}); break
        }
        $sev = 'low'; if ($exp -and -not $exp.cancelled) { $sev = Limit-S05Severity -Severity $sev -Cap $exp.severityCap }
        New-BvsFinding -Run $run -Check 's05.assessment' -Title ("Stale Security Center {0} registration: {1} (program file missing)" -f $w.productType, $w.displayName) -Severity $sev -Class 'hygiene' -Confidence 'high' -Reasons @('stale_registration') -Expected $exp `
            -Evidence @([ordered]@{ type = 'wmi'; namespace = 'root\SecurityCenter2'; displayName = $w.displayName; productType = $w.productType; productState = $w.productState.hex; state = $w.productState.state; missing = $missing; timestampUtc = $w.timestampUtc }) `
            -FpNotes 'Uninstallers sometimes leave their Security Center entry behind. A stale entry can make Windows believe a firewall/antivirus is active when it is not.' `
            -Recommendation 'Run the vendor removal tool (for McAfee: MCPR) to remove the leftover registration; do not edit the WMI repository by hand.'
        $made++
    }
    if ($avs.Count -and -not @($avs | Where-Object { $_.productState.enabled }).Count) {
        New-BvsFinding -Run $run -Check 's05.assessment' -Title 'No antivirus is active according to Windows Security Center' -Severity 'high' -Class 'hardening' -Confidence 'high' -Reasons @('av_missing') -Mitre @('T1562.001') `
            -Evidence @($avs | ForEach-Object { [ordered]@{ type = 'wmi'; displayName = $_.displayName; state = $_.productState.state; definitions = $_.productState.definitions } }) `
            -FpNotes 'Security Center can lag a few minutes after an update or reboot.' -Recommendation 'Turn on Microsoft Defender or the installed antivirus.'
        $made++
    }
    $def = @($avs | Where-Object { $_.productState.owner -eq 'windows' -or $_.displayName -match '(?i)Defender' })[0]
    if ($def -and -not $def.productState.enabled) {
        $other = $thirdOn | Select-Object -First 1
        $exp = $null
        foreach ($e in @(Get-BvsExpected -Category securityCenter | Where-Object { $_.match.PSObject.Properties['defenderOffBecause'] })) {
            if ($other -and ([string]$e.match.defenderOffBecause) -match [regex]::Escape(($other.displayName -split ' ')[0])) {
                $ctx = @{ ProductOn = [bool]$other.productState.enabled; DefsUpToDate = ($other.productState.definitions -eq 'up_to_date'); ProductInstalled = $true }
                $exp = New-S05ExpectedRef -Item $e -Eval (Test-S05InvalidIf -Item $e -Context $ctx); break
            }
        }
        $healthyOther = $other -and $other.productState.definitions -eq 'up_to_date'
        $sev = if ($healthyOther -and (-not $exp -or -not $exp.cancelled)) { 'info' } elseif ($other) { 'medium' } else { 'high' }
        $st = $S05.Defender.status
        New-BvsFinding -Run $run -Check 's05.assessment' -Title $(if ($other) { "Microsoft Defender is off because $($other.displayName) is the registered antivirus" } else { 'Microsoft Defender is off and no other antivirus is active' }) `
            -Severity $sev -Class $(if ($sev -eq 'info') { 'info' } else { 'hardening' }) -Confidence 'high' -Reasons @('defender_off') -Expected $exp `
            -Evidence @([ordered]@{ type = 'wmi'; displayName = $def.displayName; state = $def.productState.state; productState = $def.productState.hex; amRunningMode = $(if ($st) { $st.amRunningMode } else { $null }); amEngineVersion = $(if ($st) { $st.amEngineVersion } else { $null }); otherAv = $(if ($other) { $other.displayName } else { $null }); otherAvState = $(if ($other) { $other.productState.state } else { $null }); otherAvDefinitions = $(if ($other) { $other.productState.definitions } else { $null }) }) `
            -FpNotes 'Windows turns Defender real-time protection off by design while a third-party antivirus is registered and healthy; Defender then also keeps no detection history (cmdlets return nothing).' `
            -Recommendation $(if ($sev -eq 'info') { 'None while the other antivirus stays on and up to date. Optionally enable Defender "Periodic scanning" for a second opinion.' } else { 'Turn on an antivirus; Defender takes over automatically if the third-party product is removed or expires.' })
        $made++
    }

    # --- MSRT / msert run summaries (detections themselves are handled above as rows) ---
    if ($S05.MsrtRuns.Count) {
        $runs = @($S05.MsrtRuns | Sort-Object { $_.startedUtc })
        $dirty = @($runs | Where-Object { -not $_.noInfectionFound -or @($_.detections).Count })
        if (-not $dirty.Count) {
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("MSRT found no infection in {0} runs ({1}..{2}, latest v{3})" -f $runs.Count, (Get-S05DateOnly $runs[0].startedUtc), (Get-S05DateOnly $runs[-1].startedUtc), $runs[-1].version) `
                -Severity 'info' -Class 'info' -Confidence 'high' -Reasons @('av_clean_scan') -Evidence @($runs | Select-Object -Last 6 | ForEach-Object { [ordered]@{ type = 'msrt_run'; version = $_.version; startedUtc = $_.startedUtc; signatures = $_.signatures; runMode = $_.runMode; returnCode = $_.returnCode; result = ($_.summary -join ' ') } }) `
                -FpNotes 'MSRT only looks for a short list of prevalent malware families; a clean MSRT run is weak evidence.' -Recommendation 'None.'
            $made++
        }
    }
    if ($S05.MsertRuns.Count) {
        $latest = @($S05.MsertRuns | Sort-Object { $_.startedUtc })[-1]
        if ($latest.complete -and $latest.noInfectionFound -and -not @($latest.detections).Count) {
            New-BvsFinding -Run $run -Check 's05.assessment' -Title ("Microsoft Safety Scanner {0} ({1}) found no infection" -f $latest.version, (Get-S05DateOnly $latest.startedUtc)) -Severity 'info' -Class 'info' -Confidence 'high' -Reasons @('av_clean_scan') `
                -Evidence @([ordered]@{ type = 'msert_run'; version = $latest.version; startedUtc = $latest.startedUtc; finishedUtc = $latest.finishedUtc; signatures = $latest.signatures; scanType = $latest.scanType; returnCode = $latest.returnCode; filesScanned = $latest.filesScanned; scanErrors = $latest.scanErrors; source = $latest.sourceFile }) `
                -FpNotes 'A clean result covers only what the chosen scan type looked at (quick scan = common locations).' -Recommendation 'None.'
            $made++
        }
    }
    $made
}

#endregion

#region ---------- inventory and envelope ----------

$det = @($S05.Detections | Sort-Object { $_.date } | ForEach-Object { ConvertTo-S05Public $_ })
Add-BvsInventory -Run $run -Name 'detections' -Data $det
Add-BvsInventory -Run $run -Name 'detectionSummary' -Data ([ordered]@{
        total        = $det.Count
        bySource     = & { $o = [ordered]@{}; foreach ($g in ($det | Group-Object { $_.source })) { $o[$g.Name] = $g.Count }; $o }
        byCategory   = & { $o = [ordered]@{}; foreach ($g in ($det | Group-Object { $_.category })) { $o[$g.Name] = $g.Count }; $o }
        byAction     = & { $o = [ordered]@{}; foreach ($g in ($det | Group-Object { $_.action })) { $o[$g.Name] = $g.Count }; $o }
        byAssessment = & { $o = [ordered]@{}; foreach ($g in ($det | Group-Object { $_.assessment })) { $o[$g.Name] = $g.Count }; $o }
        stillPresent = @($det | Where-Object { $_.stillPresent -eq $true }).Count
        ownActivity  = @($det | Where-Object { $_.ownActivity }).Count
    })
Add-BvsInventory -Run $run -Name 'avastProducts' -Data @($S05.Gen | ForEach-Object { [ordered]@{ product = $_.Name; registryKey = $_.RegKey; dataFolder = $_.DataFolder; programFolder = $_.ProgramFolder; version = $_.Version; buildVersion = $_.BuildVersion; setupVersion = $_.SetupVersion; installedUtc = $_.InstalledUtc; languageLcid = $_.LanguageLcid; reportCodePage = $_.CodePage; services = $_.Services } })
Add-BvsInventory -Run $run -Name 'avastShields' -Data @($S05.Shields)
Add-BvsInventory -Run $run -Name 'avastFeatures' -Data @($S05.Features)
Add-BvsInventory -Run $run -Name 'avastScanTasks' -Data @($S05.Tasks)
Add-BvsInventory -Run $run -Name 'avastDefinitions' -Data @($S05.Definitions)
Add-BvsInventory -Run $run -Name 'avastExclusions' -Data @($S05.Exclusions)
Add-BvsInventory -Run $run -Name 'avastReports' -Data @($S05.ReportFiles)
Add-BvsInventory -Run $run -Name 'avastChest' -Data @($S05.Chest | ForEach-Object { ConvertTo-S05Public $_ })
Add-BvsInventory -Run $run -Name 'avastRemovalRecords' -Data @($S05.Removed)
Add-BvsInventory -Run $run -Name 'avastDetectionsLog' -Data @($S05.DetLog | ForEach-Object { $_.Summary })
Add-BvsInventory -Run $run -Name 'avastLogDb' -Data @($S05.LogDbInfo)
Add-BvsInventory -Run $run -Name 'avastScanSessions' -Data @($S05.Sessions)
Add-BvsInventory -Run $run -Name 'avastInfectedHistory' -Data @($S05.InfectedHist)
Add-BvsInventory -Run $run -Name 'avastLogGrep' -Data @($S05.LogGrep)
Add-BvsInventory -Run $run -Name 'avastLogNotable' -Data @($S05.LogNotable | Select-Object -Last 60)
Add-BvsInventory -Run $run -Name 'avastAutosandbox' -Data @($S05.Autosandbox)
Add-BvsInventory -Run $run -Name 'avastAntiRootkit' -Data @($S05.AntiRootkit)
Add-BvsInventory -Run $run -Name 'avastUefiScan' -Data @($S05.Uefi)
Add-BvsInventory -Run $run -Name 'webShieldDomains' -Data @($det | Where-Object { $_.objectKind -eq 'url' -and $_.host } | Group-Object { $_.host } | Sort-Object Count -Descending | ForEach-Object {
        $g = @($_.Group | Sort-Object { $_.date }); [ordered]@{ host = $_.Name; count = $_.Count; firstUtc = $g[0].date; lastUtc = $g[-1].date; names = @($g.name | Select-Object -Unique); assessment = @($g.assessment | Select-Object -Unique) } })
Add-BvsInventory -Run $run -Name 'msrtRuns' -Data @($S05.MsrtRuns)
Add-BvsInventory -Run $run -Name 'msertRuns' -Data @($S05.MsertRuns)
Add-BvsInventory -Run $run -Name 'msertSources' -Data @($S05.MsertSources)
Add-BvsInventory -Run $run -Name 'defender' -Data $S05.Defender
Add-BvsInventory -Run $run -Name 'securityCenter' -Data @($S05.Wsc)

$summary = Complete-BvsRun -Run $run

"S05 av-evidence: findings=$($summary.Findings) [$($summary.BySeverity)] checks=$($summary.Checks) errors=$($summary.Errors)"
"checks: " + ((@($run.Checks) | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
foreach ($c in @($run.Checks | Where-Object { $_.status -ne 'ok' })) { "  {0,-26} {1,-14} {2}" -f $c.id, $c.status, (Get-S05Trunc (Protect-BvsText ([string]$c.reason)) 110) }
"detections: $($det.Count) (" + ((@($det) | Group-Object source | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ') + "), still present: " + @($det | Where-Object { $_.stillPresent -eq $true }).Count
foreach ($f in @($run.Findings | Sort-Object { $SevRank[$_.severity] } -Descending | Select-Object -First 16)) { "  [{0}/{1}] {2}" -f $f.severity, $f.class, (Get-S05Trunc (Protect-BvsText $f.title) 150) }
"output: $($summary.Path)"

#endregion
