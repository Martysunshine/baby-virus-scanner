#Requires -Version 7.2
<#
.SYNOPSIS
    S02 - Processes and suspicious files: read-only security collector (Windows 10/11).

.DESCRIPTION
    Part of baby-virus-scanner. Looks at what is running now and at recent risky files in the places
    malware usually lands, and writes findings into the shared bvs.module/1 envelope
    (data\<scanId>\security\S02.json).

    Processes   signer, user-writable image folder, deleted image, masquerading system names,
                look-alike names, parent anomalies (Office/browser -> shell, svchost not under
                services.exe), suspicious command lines, risky launch folders, sustained CPU from
                unsigned programs (two samples), inventory of unsigned / user-writable processes.
    Files       recent (created OR modified within -RecentDays) risky files in Downloads, Desktop,
                Public, %TEMP%, AppData / LocalAppData (depth 2), ProgramData (depth 2), Windows\Temp,
                Startup folders and the system-drive root (depth 1): signer, Mark-of-the-Web,
                header vs extension, double extension, RTLO, random names, LNK / URL abuse,
                DLL side-loading, AppData-root executables, script content indicators.
    Artifacts   Contagious Interview (BeaverTail / InvisibleFerret), Shai-Hulud 2.0, s1ngularity.
    Origins     Mark-of-the-Web host domains of executables and installers in Downloads.
    Cross-check G0 inventory\files.tsv 'exec-recent' rows that the targeted sweep missed (optional).

    Read-only: never modifies, moves, kills or executes anything. File contents are read only for
    headers, shortcut / URL parsing and script indicators (pattern ids are stored, never content).
    Tunable lists: S02-iocs.json (same folder). Known-good items: src\config\local\expected.json.
    Contract: docs\schema.md   Rules: docs\agent-rules.md   Playbook: docs\playbooks\S02-processes-files.md

.PARAMETER RecentDays
    File window in days (created OR modified). Default 90.
.PARAMETER CpuSampleSeconds
    Minimum gap between the two CPU samples. Default 10.
.PARAMETER CpuThresholdPct
    Sustained CPU, in percent of the whole machine, for the miner check. Default 25.
.PARAMETER MaxHashMB
    Largest file that gets a local SHA-256. Default 256.
.PARAMETER MaxFindingsPerCheck
    Individual findings per check before the rest are rolled into one summary finding. Default 40.

.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S02-processes-files.ps1
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$RecentDays = 90,
    [ValidateRange(1, 120)][int]$CpuSampleSeconds = 10,
    [ValidateRange(1, 100)][double]$CpuThresholdPct = 25,
    [ValidateRange(1, 4096)][int]$MaxHashMB = 256,
    [ValidateRange(5, 500)][int]$MaxFindingsPerCheck = 40
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
# Library workaround (reported to the lib owner): Initialize-BvsRun re-parses scan-meta auditStartUtc with
# [datetime]::Parse under the current culture, which throws on dd/MM cultures because ConvertFrom-Json
# already returned a DateTime. Run it under the invariant culture, then restore the exact UTC value.
$prevCulture = [Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
    $run = Initialize-BvsRun -Module S02 -Area security
}
finally { [Threading.Thread]::CurrentThread.CurrentCulture = $prevCulture }
$metaPath = Join-Path $run.ScanDir 'scan-meta.json'
if (Test-Path -LiteralPath $metaPath) {
    $metaRaw = Get-Content -LiteralPath $metaPath -Raw
    if ($metaRaw -match '"auditStartUtc"\s*:\s*"([^"]+)"') {
        $run.AuditStartUtc = [datetimeoffset]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
    }
}
$clock = [Diagnostics.Stopwatch]::StartNew()
$ioc = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S02-iocs.json') -Raw | ConvertFrom-Json
$nowUtc = [datetime]::UtcNow
$cutoffUtc = $nowUtc.AddDays(-$RecentDays)
$recent30Utc = $nowUtc.AddDays(-30)
$SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$coverageNotes = [System.Collections.Generic.List[string]]::new()

#region ---------- generic helpers ----------

function New-S02Set {
    param([object[]]$Items)
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in $Items) { if ($i) { [void]$set.Add([string]$i) } }
    , $set
}

function Out-S02Items {
    # Invoke-BvsCheck counts @($result); an empty array must be emitted as one object to count as 0.
    param($Items)
    if ($null -eq $Items -or @($Items).Count -eq 0) { return , @() }
    $Items
}

function Get-S02Short {
    param([AllowNull()][string]$Text, [int]$Max = 400)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = Protect-BvsText $Text
    if ($t.Length -gt $Max) { $t.Substring(0, $Max) + '...[truncated]' } else { $t }
}

function ConvertTo-S02Iso {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { ([datetime]$Value).ToUniversalTime().ToString('o') } catch { $null }
}

function Get-S02FullPath {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    elseif ($p.StartsWith('\\?\UNC\')) { $p = '\\' + $p.Substring(8) }
    elseif ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }
    elseif ($p -match '^(?i)\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
    try { [IO.Path]::GetFullPath($p) } catch { $p }
}

function Test-S02Under {
    param([AllowNull()][string]$Path, [AllowNull()][string]$Prefix)
    if ([string]::IsNullOrEmpty($Path) -or [string]::IsNullOrEmpty($Prefix)) { return $false }
    $pre = $Prefix.TrimEnd('\')
    if ($Path.Length -eq $pre.Length) { return $Path.Equals($pre, [StringComparison]::OrdinalIgnoreCase) }
    $Path.StartsWith($pre + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-S02Same {
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    if ([string]::IsNullOrEmpty($A) -or [string]::IsNullOrEmpty($B)) { return $false }
    $A.TrimEnd('\').Equals($B.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
}

function Test-S02Like {
    param([string]$Name, [object[]]$Patterns)
    foreach ($p in $Patterns) { if ($Name -like $p) { return $true } }
    $false
}

function Get-S02MaxSev {
    param([string[]]$Severities)
    $best = 'info'
    foreach ($s in $Severities) { if ($s -and $SevRank[$s] -gt $SevRank[$best]) { $best = $s } }
    $best
}

function Limit-S02Sev {
    param([string]$Severity, [string]$Cap)
    if (-not $Cap -or -not $SevRank.ContainsKey($Cap)) { return $Severity }
    if ($SevRank[$Severity] -gt $SevRank[$Cap]) { $Cap } else { $Severity }
}

function Get-S02Entropy {
    param([string]$Text)
    if (-not $Text) { return 0.0 }
    $h = @{}
    foreach ($c in $Text.ToCharArray()) { $h[[int]$c] = 1 + [int]$h[[int]$c] }
    $e = 0.0
    foreach ($v in $h.Values) { $p = $v / $Text.Length; $e -= $p * [Math]::Log($p, 2) }
    $e
}

function Test-S02RandomName {
    # Random-looking token (>= 8 chars) in the base name: high entropy plus unnatural composition.
    # GUIDs, pure hex / numbers (hash or content-addressed names) are not counted.
    param([string]$Name)
    $base = [IO.Path]::GetFileNameWithoutExtension($Name)
    if ($base -match '^\{?[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?$') { return $false }
    foreach ($t in ($base -split '[\s._\-()\[\]{}+,~]+')) {
        if ($t.Length -lt 8 -or $t -notmatch '^[A-Za-z0-9]+$') { continue }
        if ($t -match '^[0-9a-fA-F]+$' -or $t -match '^\d+$') { continue }
        $letters = ($t -replace '[^A-Za-z]', '').Length
        if ($letters -lt 3) { continue }
        $vowels = ($t -replace '[^aeiouyAEIOUY]', '').Length
        $alt = ([regex]::Matches($t, '(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])')).Count
        $maxCons = 0
        foreach ($m in [regex]::Matches($t, '[b-df-hj-np-tv-xzB-DF-HJ-NP-TV-XZ]+')) { if ($m.Length -gt $maxCons) { $maxCons = $m.Length } }
        $ent = Get-S02Entropy $t
        if ($ent -ge 3.0 -and ($alt -ge 4 -or $maxCons -ge 6 -or (($vowels / $letters) -lt 0.12 -and $letters -ge 6))) { return $true }
    }
    $false
}

function Get-S02Distance {
    # Damerau-Levenshtein (optimal string alignment); returns 99 when lengths differ by more than 2.
    param([string]$A, [string]$B)
    $la = $A.Length; $lb = $B.Length
    if ([Math]::Abs($la - $lb) -gt 2) { return 99 }
    $d = [int[, ]]::new($la + 1, $lb + 1)
    for ($i = 0; $i -le $la; $i++) { $d[$i, 0] = $i }
    for ($j = 0; $j -le $lb; $j++) { $d[0, $j] = $j }
    for ($i = 1; $i -le $la; $i++) {
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($A[$i - 1] -ceq $B[$j - 1]) { 0 } else { 1 }
            $v = [Math]::Min([Math]::Min($d[($i - 1), $j] + 1, $d[$i, ($j - 1)] + 1), $d[($i - 1), ($j - 1)] + $cost)
            if ($i -gt 1 -and $j -gt 1 -and $A[$i - 1] -ceq $B[$j - 2] -and $A[$i - 2] -ceq $B[$j - 1]) { $v = [Math]::Min($v, $d[($i - 2), ($j - 2)] + 1) }
            $d[$i, $j] = $v
        }
    }
    $d[$la, $lb]
}

$script:Homo = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
foreach ($h in $ioc.lookalike.homoglyphs.PSObject.Properties) { $script:Homo[$h.Name] = [string]$h.Value }
$script:Digraphs = @($ioc.lookalike.digraphs.PSObject.Properties | ForEach-Object { , @($_.Name, [string]$_.Value) })

function Get-S02Skeleton {
    # Homoglyph skeleton: digits/look-alike Unicode letters mapped to Latin, so 'svch0st' -> 'svchost'.
    param([string]$Name)
    $x = $Name.ToLowerInvariant()
    foreach ($dg in $script:Digraphs) { $x = $x -replace [regex]::Escape($dg[0]), $dg[1] }
    $sb = [Text.StringBuilder]::new($x.Length)
    foreach ($ch in $x.ToCharArray()) {
        $k = [string]$ch; $v = $null
        if ($script:Homo.TryGetValue($k, [ref]$v)) { [void]$sb.Append($v) } else { [void]$sb.Append($k) }
    }
    $sb.ToString()
}

$script:Ansi = try { [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage) } catch { [Text.Encoding]::Latin1 }

function Read-S02Bytes {
    # Read at most MaxBytes, sharing read/write/delete so other programs are never blocked.
    param([string]$Path, [int]$MaxBytes)
    $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    try {
        $len = [int][Math]::Min([long]$fs.Length, [long]$MaxBytes)
        $buf = [byte[]]::new($len)
        $got = 0
        while ($got -lt $len) { $n = $fs.Read($buf, $got, $len - $got); if ($n -le 0) { break }; $got += $n }
        if ($got -lt $len) { [Array]::Resize([ref]$buf, $got) }
        , $buf
    }
    finally { $fs.Dispose() }
}

function Read-S02Text {
    param([string]$Path, [int]$MaxBytes = 2MB)
    $b = Read-S02Bytes -Path $Path -MaxBytes $MaxBytes
    $n = $b.Length
    if ($n -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $n - 2) }
    if ($n -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($b, 2, $n - 2) }
    if ($n -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $n - 3) }
    $probe = [Math]::Min($n, 512); $zeros = 0
    for ($i = 1; $i -lt $probe; $i += 2) { if ($b[$i] -eq 0) { $zeros++ } }
    if ($probe -gt 16 -and $zeros -gt ($probe / 4)) { return [Text.Encoding]::Unicode.GetString($b, 0, $n - ($n % 2)) }
    [Text.Encoding]::UTF8.GetString($b, 0, $n)
}

function Get-S02CStr {
    param([byte[]]$B, [int]$Off, [bool]$Unicode, [int]$Max = 4096)
    if ($Off -lt 0 -or $Off -ge $B.Length) { return $null }
    $end = $Off
    if ($Unicode) {
        while ($end + 1 -lt $B.Length -and ($end - $Off) -lt ($Max * 2) -and -not ($B[$end] -eq 0 -and $B[$end + 1] -eq 0)) { $end += 2 }
        return [Text.Encoding]::Unicode.GetString($B, $Off, $end - $Off)
    }
    while ($end -lt $B.Length -and ($end - $Off) -lt $Max -and $B[$end] -ne 0) { $end++ }
    $script:Ansi.GetString($B, $Off, $end - $Off)
}

#endregion

#region ---------- native: image path by PID without opening the process (read-only) ----------

if (-not ('BvsS02.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace BvsS02 {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_ID_INFORMATION { public IntPtr ProcessId; public UNICODE_STRING ImageName; }
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, ref SYSTEM_PROCESS_ID_INFORMATION info, int length, out int returnLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);

        // SystemProcessIdInformation (88): the NT image path of any PID, no process handle required.
        public static string ImagePath(int pid) {
            ushort max = 1024;
            for (int attempt = 0; attempt < 3; attempt++) {
                IntPtr buf = Marshal.AllocHGlobal(max);
                try {
                    var info = new SYSTEM_PROCESS_ID_INFORMATION();
                    info.ProcessId = new IntPtr(pid);
                    info.ImageName.Length = 0;
                    info.ImageName.MaximumLength = max;
                    info.ImageName.Buffer = buf;
                    int ret;
                    int status = NtQuerySystemInformation(88, ref info, Marshal.SizeOf(typeof(SYSTEM_PROCESS_ID_INFORMATION)), out ret);
                    if (status == unchecked((int)0xC0000004)) {
                        if (info.ImageName.MaximumLength <= max) return null;
                        max = info.ImageName.MaximumLength;
                        continue;
                    }
                    if (status != 0 || info.ImageName.Length == 0) return null;
                    return Marshal.PtrToStringUni(buf, info.ImageName.Length / 2);
                } finally { Marshal.FreeHGlobal(buf); }
            }
            return null;
        }

        public static string DosDevice(string drive) {
            var sb = new StringBuilder(1024);
            return QueryDosDevice(drive, sb, sb.Capacity) == 0 ? null : sb.ToString();
        }
    }
}
'@
}

$script:DevMap = @{}
foreach ($drv in [IO.DriveInfo]::GetDrives()) {
    $letter = $drv.Name.Substring(0, 2)
    try { $dev = [BvsS02.Native]::DosDevice($letter); if ($dev) { $script:DevMap[$dev] = $letter } } catch { }
}

function Convert-S02NtPath {
    param([AllowNull()][string]$NtPath)
    if (-not $NtPath) { return $null }
    foreach ($k in $script:DevMap.Keys) {
        if ($NtPath.StartsWith($k + '\', [StringComparison]::OrdinalIgnoreCase)) { return $script:DevMap[$k] + $NtPath.Substring($k.Length) }
    }
    if ($NtPath -match '^[A-Za-z]:\\') { return $NtPath }
    $null
}

#endregion

#region ---------- locations, sets, expected items, exclusions ----------

$S = @{
    Risky        = New-S02Set $ioc.riskyExtensions
    Archive      = New-S02Set $ioc.archiveExtensions
    Installer    = New-S02Set $ioc.installerExtensions
    Pe           = New-S02Set $ioc.peExtensions
    Signable     = New-S02Set $ioc.signableExtensions
    Script       = New-S02Set $ioc.scriptExtensions
    Wsh          = New-S02Set $ioc.wshExtensions
    Decoy        = New-S02Set $ioc.decoyExtensions
    NeutralPe    = New-S02Set $ioc.neutralPeExtensions
    Office       = New-S02Set $ioc.officeProcesses
    Browser      = New-S02Set $ioc.browserProcesses
    SuspChild    = New-S02Set $ioc.suspiciousChildren
    ShellHosts   = New-S02Set $ioc.shellHosts
    Pseudo       = New-S02Set $ioc.pseudoProcesses
    LookAllow    = New-S02Set $ioc.lookalike.allow
    LnkLolbins   = New-S02Set $ioc.lnk.lolbins
    SearchTools  = New-S02Set @('rg.exe', 'grep.exe', 'egrep.exe', 'fgrep.exe', 'findstr.exe', 'ag.exe', 'ack.exe', 'git.exe')
}
$flaggedSources = New-S02Set $ioc.downloadSources.flagged

$usf = @(Get-BvsRegValues 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
$dlRaw = ($usf | Where-Object Name -eq '{374DE290-123F-4565-9164-39C4925E467B}' | Select-Object -First 1).Value
$appDataDir = Split-Path -Parent $env:APPDATA
$L = [ordered]@{
    SystemRoot      = Get-S02FullPath $env:SystemRoot
    System32        = Join-Path $env:SystemRoot 'System32'
    WinTemp         = Join-Path $env:SystemRoot 'Temp'
    Temp            = Get-S02FullPath $env:TEMP
    LocalTemp       = Join-Path $env:LOCALAPPDATA 'Temp'
    Downloads       = if ($dlRaw) { Get-S02FullPath $dlRaw } else { Join-Path $env:USERPROFILE 'Downloads' }
    Desktop         = [Environment]::GetFolderPath('Desktop')
    Public          = if ($env:PUBLIC) { $env:PUBLIC } else { Join-Path (Split-Path -Parent $env:USERPROFILE) 'Public' }
    PublicDesktop   = [Environment]::GetFolderPath('CommonDesktopDirectory')
    ProgramData     = $env:ProgramData
    AppData         = $env:APPDATA
    LocalAppData    = $env:LOCALAPPDATA
    LocalLow        = Join-Path $appDataDir 'LocalLow'
    AppDataDir      = $appDataDir
    Programs        = Join-Path $env:LOCALAPPDATA 'Programs'
    Profile         = $env:USERPROFILE
    UsersRoot       = Split-Path -Parent $env:USERPROFILE
    Startup         = [Environment]::GetFolderPath('Startup')
    CommonStartup   = [Environment]::GetFolderPath('CommonStartup')
    SystemDriveRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
    ProgramFiles    = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ } | Select-Object -Unique
}
$riskyProcLoc = @('temp', 'downloads', 'public', 'programdata_root', 'appdata_root', 'recycle_bin')
$unusualProcLoc = @('desktop', 'profile_root', 'drive_root', 'startup', 'other_profile')

function Get-S02Location {
    param([AllowNull()][string]$Path)
    if (-not $Path) { return 'unknown' }
    $parent = [IO.Path]::GetDirectoryName($Path)
    if ($Path -match '(?i)\\\$Recycle\.Bin\\') { return 'recycle_bin' }
    if ((Test-S02Under $Path $L.Startup) -or (Test-S02Under $Path $L.CommonStartup)) { return 'startup' }
    if ((Test-S02Under $Path $L.Temp) -or (Test-S02Under $Path $L.LocalTemp) -or (Test-S02Under $Path $L.WinTemp)) { return 'temp' }
    if (Test-S02Under $Path $L.Downloads) { return 'downloads' }
    if ((Test-S02Under $Path $L.Desktop) -or (Test-S02Under $Path $L.PublicDesktop)) { return 'desktop' }
    if (Test-S02Under $Path $L.Public) { return 'public' }
    foreach ($r in @($L.AppDataDir, $L.AppData, $L.LocalAppData, $L.LocalLow)) { if (Test-S02Same $parent $r) { return 'appdata_root' } }
    if (Test-S02Under $Path $L.Programs) { return 'appdata_programs' }
    if (Test-S02Under $Path $L.AppDataDir) { return 'appdata' }
    if (Test-S02Same $parent $L.ProgramData) { return 'programdata_root' }
    if (Test-S02Under $Path $L.ProgramData) { return 'programdata' }
    if (Test-S02Same $parent $L.Profile) { return 'profile_root' }
    if (Test-S02Under $Path $L.Profile) { return 'profile' }
    if (Test-S02Under $Path $L.SystemRoot) { return 'windows' }
    foreach ($pf in $L.ProgramFiles) { if (Test-S02Under $Path $pf) { return 'program_files' } }
    if (Test-S02Under $Path $L.UsersRoot) { return 'other_profile' }
    if (Test-S02Same $parent $L.SystemDriveRoot) { return 'drive_root' }
    'other'
}

# Our own activity (rules s7): this project, its Claude Code transcripts and its scratchpad.
$projRoot = (Get-BvsRoot).TrimEnd('\')
$slug = $projRoot -replace '[^A-Za-z0-9]', '-'
$script:Exclude = @($projRoot, (Join-Path $env:USERPROFILE ".claude\projects\$slug"), (Join-Path $L.Temp "claude\$slug"), (Join-Path $L.LocalTemp "claude\$slug")) | Select-Object -Unique
function Test-S02Excluded {
    param([string]$Path)
    foreach ($x in $script:Exclude) { if (Test-S02Under $Path $x) { return $true } }
    $false
}

# Machine-specific known-good paths (src\config\local\expected.json, any category with match.paths/path/targetPrefix).
$script:ExpectedPaths = [System.Collections.Generic.List[object]]::new()
foreach ($e in @(Get-BvsExpected)) {
    $m = $e.match
    if (-not $m) { continue }
    $cands = @()
    foreach ($prop in 'paths', 'path', 'targetPrefix') { if ($m.PSObject.Properties[$prop]) { $cands += @($m.$prop) } }
    foreach ($c in $cands) {
        if ($c -isnot [string] -or $c -notmatch '\\') { continue }
        $full = Get-S02FullPath $c
        if (-not $full -or (Test-S02Excluded $full)) { continue }
        $script:ExpectedPaths.Add([pscustomobject]@{
                Id              = $e.id
                Prefix          = $full.TrimEnd('\')
                Reason          = $e.reason
                Cap             = if ($e.PSObject.Properties['severityCap'] -and $e.severityCap) { [string]$e.severityCap } else { 'info' }
                Class           = if ($e.PSObject.Properties['class'] -and $e.class) { [string]$e.class } else { $null }
                InvalidIf       = @($e.invalidIf | Where-Object { $_ })
                ConfirmWithUser = [bool]($e.PSObject.Properties['confirmWithUser'] -and $e.confirmWithUser)
            })
    }
}

function Resolve-S02Expected {
    # A match caps severity; it is cancelled when an invalidIf condition about signing holds.
    param([AllowNull()][string]$Path, [string]$SigClass)
    if (-not $Path) { return $null }
    foreach ($x in $script:ExpectedPaths) {
        if (-not (Test-S02Under $Path $x.Prefix)) { continue }
        $cancel = $null
        foreach ($cond in $x.InvalidIf) {
            if ($cond -match '(?i)unsigned|signer|not signed' -and $SigClass -notin 'valid', 'na') { $cancel = $cond; break }
        }
        return [ordered]@{ id = $x.Id; reason = $x.Reason; severityCap = $x.Cap; class = $x.Class; applied = (-not $cancel); cancelledBy = $cancel; confirmWithUser = $x.ConfirmWithUser }
    }
    $null
}

#endregion

#region ---------- signatures, path facts, findings ----------

function Get-S02SigClass {
    param($Sig, [string]$Ext)
    if (-not $Sig) { return 'na' }
    switch ([string]$Sig.Status) {
        'Valid' { return 'valid' }
        'NotSigned' { return 'unsigned' }
        'HashMismatch' { return 'invalid' }
        'NotTrusted' { return 'untrusted' }
        'UnknownError' { if ($S.Pe.Contains($Ext) -or $Ext -in '.msi', '.msp') { return 'untrusted' } else { return 'na' } }
        'NotSupportedFileFormat' { return 'na' }
        'Incompatible' { return 'unsigned' }
        'Missing' { return 'missing' }
        'SkippedCloudOnly' { return 'cloud' }
        default { return 'error' }
    }
}

$script:PathFacts = @{}
function Get-S02PathFacts {
    # Cached facts for an executable path (processes, shortcut targets): signer, writability, location.
    param([string]$Path)
    $k = $Path.ToLowerInvariant()
    if ($script:PathFacts.ContainsKey($k)) { return $script:PathFacts[$k] }
    $exists = [IO.File]::Exists($Path)
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $sig = if ($exists -and -not (Test-BvsNeverRead $Path)) { Get-BvsSignature $Path } else { $null }
    $sigClass = if (-not $exists) { 'missing' } else { Get-S02SigClass $sig $ext }
    $folder = [IO.Path]::GetDirectoryName($Path)
    $uw = if ($folder) { Test-BvsUserWritable $folder } else { $null }
    $fw = if ($exists) { Test-BvsUserWritable $Path } else { $null }
    $f = [pscustomobject]@{
        Path         = $Path
        Exists       = $exists
        SigStatus    = if ($sig) { [string]$sig.Status } elseif ($exists) { 'NotChecked' } else { 'Missing' }
        SigClass     = $sigClass
        Signer       = if ($sig) { $sig.Signer } else { $null }
        IsMicrosoft  = [bool]($sig -and $sig.Status -eq 'Valid' -and ($sig.IsOSBinary -or "$($sig.Signer)" -match '^Microsoft '))
        UserWritable = [bool]($uw -or $fw)
        Location     = Get-S02Location $Path
        Expected     = Resolve-S02Expected $Path $sigClass
        Version      = if ($exists -and $sigClass -ne 'valid') { Get-BvsVersionInfo $Path } else { $null }
    }
    $script:PathFacts[$k] = $f
    $f
}

$script:FindingCount = @{}
$script:Overflow = @{}
function Add-S02Finding {
    param(
        [string]$Check, [string]$Title, [string]$Severity, [string]$Class, [string]$Confidence = 'medium',
        [string[]]$Reasons = @(), [object[]]$Evidence = @(), [hashtable]$Entities = @{},
        [string]$Recommendation = '', [string]$FpNotes = '', [string[]]$Mitre = @(), $Expected = $null
    )
    if ($Expected -and $Expected.applied) {
        $Severity = Limit-S02Sev $Severity $Expected.severityCap
        if ($Expected.class) { $Class = $Expected.class } elseif ($Severity -eq 'info') { $Class = 'info' }
        $Reasons = @($Reasons) + 'expected_match'
    }
    $n = [int]$script:FindingCount[$Check]
    if ($n -ge $MaxFindingsPerCheck) {
        if (-not $script:Overflow.ContainsKey($Check)) { $script:Overflow[$Check] = [System.Collections.Generic.List[object]]::new() }
        $script:Overflow[$Check].Add([ordered]@{ title = $Title; severity = $Severity })
        return
    }
    $script:FindingCount[$Check] = $n + 1
    $ent = @{ files = @(); processes = @(); network = @(); registry = @(); accounts = @() }
    foreach ($k in $Entities.Keys) { $ent[$k] = @($Entities[$k]) }
    $rs = [string[]]@($Reasons | Where-Object { $_ } | Select-Object -Unique)
    $mt = [string[]]@($Mitre | Where-Object { $_ } | Select-Object -Unique)
    New-BvsFinding -Run $run -Check $Check -Title $Title -Severity $Severity -Class $Class -Confidence $Confidence -Reasons $rs `
        -Evidence $Evidence -Entities $ent -Recommendation $Recommendation -FpNotes $FpNotes -Mitre $mt -Expected $Expected
}

#endregion

#region ---------- processes: helpers ----------

$procs = @()
$byPid = @{}
$ownPids = [System.Collections.Generic.HashSet[int]]::new()
$procFlags = @{}
$ownRootPid = $null

function Get-S02Parent {
    param($Proc)
    if (-not $Proc) { return $null }
    $par = $byPid[[int]$Proc.ParentPid]
    if (-not $par -or $par.Pid -eq $Proc.Pid) { return $null }
    if ($Proc.Started -and $par.Started -and $par.Started -gt $Proc.Started) { return $null }   # PID reused after the child started
    $par
}

function Add-S02ProcFlag {
    param($Proc, [string]$Check)
    $k = [int]$Proc.Pid
    if (-not $procFlags.ContainsKey($k)) { $procFlags[$k] = [System.Collections.Generic.List[string]]::new() }
    if (-not $procFlags[$k].Contains($Check)) { $procFlags[$k].Add($Check) }
}

function New-S02ProcEntity {
    param($Proc)
    $f = if ($Proc.Path) { Get-S02PathFacts $Proc.Path } else { $null }
    $par = Get-S02Parent $Proc
    [ordered]@{
        pid          = [int]$Proc.Pid
        ppid         = [int]$Proc.ParentPid
        parentName   = if ($par) { $par.Name } else { $null }
        name         = $Proc.Name
        path         = $Proc.Path
        pathSource   = $Proc.PathSource
        sig          = if ($f) { $f.SigStatus } else { $null }
        signer       = if ($f) { $f.Signer } else { $null }
        userWritable = if ($f) { $f.UserWritable } else { $null }
        location     = if ($f) { $f.Location } else { $null }
        started      = ConvertTo-S02Iso $Proc.Started
        commandLine  = Get-S02Short $Proc.CommandLine 600
    }
}

function New-S02ProcEvidence {
    param($Proc)
    $par = Get-S02Parent $Proc
    [ordered]@{
        type        = 'process'
        pid         = [int]$Proc.Pid
        name        = $Proc.Name
        path        = $Proc.Path
        parentPid   = [int]$Proc.ParentPid
        parentName  = if ($par) { $par.Name } else { $null }
        started     = ConvertTo-S02Iso $Proc.Started
        commandLine = Get-S02Short $Proc.CommandLine 600
    }
}

function New-S02SigEvidence {
    param($Facts)
    if (-not $Facts) { return $null }
    $o = [ordered]@{ type = 'signature'; path = $Facts.Path; status = $Facts.SigStatus; signer = $Facts.Signer; userWritable = $Facts.UserWritable; location = $Facts.Location }
    if ($Facts.Version) { $o.company = $Facts.Version.CompanyName; $o.product = $Facts.Version.ProductName; $o.originalName = $Facts.Version.OriginalFilename }
    $o
}

function Test-S02SignedHelper {
    # Unsigned image launched by a validly signed ancestor from inside that ancestor's folder (or an IDE extension folder).
    param($Proc)
    $a = Get-S02Parent $Proc; $hop = 0
    while ($a -and $hop -lt 6) {
        if ($a.Path) {
            $af = Get-S02PathFacts $a.Path
            if ($af.SigClass -eq 'valid') {
                if (Test-S02Under $Proc.Path ([IO.Path]::GetDirectoryName($a.Path))) { return "launched by signed $($a.Name) from inside its install folder" }
                foreach ($ide in @($ioc.ideExtensionDirs)) {
                    if (Test-S02Under $Proc.Path (Join-Path $env:USERPROFILE $ide)) { return "IDE extension helper launched by signed $($a.Name)" }
                }
            }
        }
        $a = Get-S02Parent $a; $hop++
    }
    $null
}

function Get-S02HeadlessPayload {
    # conhost/OpenConsole --headless is normal for ConPTY (only --width/--height/--signal/--server ...).
    # Anything left after the known ConPTY flags is a program run in a hidden console.
    param([string]$CommandLine)
    if ($CommandLine -notmatch '(?i)(?:^|\s)--headless\b') { return $null }
    $rest = $CommandLine.Trim()
    if ($rest.StartsWith('"')) { $q = $rest.IndexOf('"', 1); $rest = if ($q -gt 0) { $rest.Substring($q + 1) } else { '' } }
    else { $sp = $rest.IndexOf(' '); $rest = if ($sp -gt 0) { $rest.Substring($sp + 1) } else { '' } }
    $withValue = New-S02Set $ioc.conptyFlags.withValue
    $tokens = @([regex]::Matches($rest, '"[^"]*"|\S+') | ForEach-Object { $_.Value })
    $left = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i]
        if ($t -eq '--') { for ($j = $i + 1; $j -lt $tokens.Count; $j++) { $left.Add($tokens[$j]) }; break }
        if ($t -match '^--?([A-Za-z0-9_-]+)(=.*)?$') {
            if ($withValue.Contains($Matches[1]) -and -not $Matches[2]) { $i++ }
            continue
        }
        $left.Add($t)
    }
    if ($left.Count) { $left -join ' ' } else { $null }
}

function Get-S02CpuSample {
    $o = [pscustomobject]@{ At = [datetime]::UtcNow; Formatted = @{}; Raw = @{}; Names = @{}; RawTs = $null; Errors = [System.Collections.Generic.List[string]]::new() }
    try {
        foreach ($x in @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop)) {
            if ($x.Name -in '_Total', 'Idle') { continue }
            $o.Formatted[[int]$x.IDProcess] = [double]$x.PercentProcessorTime
            $o.Names[[int]$x.IDProcess] = ($x.Name -replace '#\d+$', '')
        }
    }
    catch { $o.Errors.Add("formatted: $($_.Exception.Message)") }
    try {
        foreach ($x in @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -ErrorAction Stop)) {
            if ($x.Name -eq '_Total') { $o.RawTs = [double]$x.Timestamp_Sys100NS; continue }
            if ($x.Name -eq 'Idle') { continue }
            $o.Raw[[int]$x.IDProcess] = [double]$x.PercentProcessorTime
            if (-not $o.Names.ContainsKey([int]$x.IDProcess)) { $o.Names[[int]$x.IDProcess] = ($x.Name -replace '#\d+$', '') }
        }
    }
    catch { $o.Errors.Add("raw: $($_.Exception.Message)") }
    $o.At = [datetime]::UtcNow
    $o
}

#endregion

#region ---------- processes: checks ----------

$cpu1 = Get-S02CpuSample   # first CPU sample; the second is taken in processes.cpu_miner (>= CpuSampleSeconds later)

$procs = @(Invoke-BvsCheck -Run $run -Id 'processes.table' -Description 'Process list (Win32_Process); image paths of SYSTEM processes via Win32_Service and a read-only NtQuerySystemInformation fallback when not elevated' -Script {
        $t = @(Get-BvsProcessTable)
        $missing = 0
        foreach ($p in $t) {
            if ($p.Path) { $p.Path = Get-S02FullPath $p.Path; continue }
            if ($S.Pseudo.Contains([string]$p.Name) -or [int]$p.Pid -le 4) { continue }
            $nt = $null
            try { $nt = Convert-S02NtPath ([BvsS02.Native]::ImagePath([int]$p.Pid)) } catch { $nt = $null }
            if ($nt) { $p.Path = $nt; $p.PathSource = 'ntquery' } else { $missing++ }
        }
        if ($missing -gt 0) { Set-BvsCheckStatus -Id 'processes.table' -Status partial -Reason "$missing process image path(s) unavailable (process exited or protected)" }
        Out-S02Items $t
    })
foreach ($p in $procs) { $byPid[[int]$p.Pid] = $p }

# Own activity: this collector's shell chain, processes that reference the project folder, and processes
# started after the audit began below the Claude Code instance that runs this scan.
try {
    $auditStartLocal = $run.AuditStartUtc.ToLocalTime()
    $cur = $byPid[[int]$PID]; $hop = 0
    while ($cur -and $hop -lt 40) { if ($cur.Name -match '^claude(\.exe)?$') { $ownRootPid = [int]$cur.Pid; break }; $cur = Get-S02Parent $cur; $hop++ }
    $cur = $byPid[[int]$PID]; $hop = 0
    while ($cur -and $hop -lt 40) {
        [void]$ownPids.Add([int]$cur.Pid)
        if ($cur.Name -notmatch '^(pwsh|powershell|cmd|conhost|bash|sh)\.exe$') { break }
        $cur = Get-S02Parent $cur; $hop++
    }
    foreach ($p in $procs) {
        if ($p.CommandLine -and $p.CommandLine.IndexOf($projRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) { [void]$ownPids.Add([int]$p.Pid); continue }
        if ($null -ne $ownRootPid -and $p.Started -and $p.Started -ge $auditStartLocal) {
            $a = Get-S02Parent $p; $hop = 0
            while ($a -and $hop -lt 40) { if ([int]$a.Pid -eq $ownRootPid) { [void]$ownPids.Add([int]$p.Pid); break }; $a = Get-S02Parent $a; $hop++ }
        }
    }
}
catch { $coverageNotes.Add("own-activity detection failed: $($_.Exception.Message)") }

$procWithPath = @($procs | Where-Object { $_.Path })

[void](Invoke-BvsCheck -Run $run -Id 'processes.signatures' -Description 'Authenticode signer, user-writable folder and image existence for every running image; invalid or untrusted signatures' -Script {
        $uniq = @($procWithPath | ForEach-Object { $_.Path } | Sort-Object -Unique)
        foreach ($u in $uniq) { [void](Get-S02PathFacts $u) }
        foreach ($g in ($procWithPath | Group-Object { $_.Path.ToLowerInvariant() })) {
            $p0 = $g.Group[0]
            $f = Get-S02PathFacts $p0.Path
            if ($f.SigClass -notin 'invalid', 'untrusted') { continue }
            $sev = if ($f.SigClass -eq 'invalid') { 'high' } else { 'medium' }
            $rs = @('invalid_signature'); if ($f.UserWritable) { $rs += 'user_writable' }
            foreach ($p in $g.Group) { Add-S02ProcFlag $p 'processes.signatures' }
            Add-S02Finding -Check 'processes.signatures' -Title "Running program has a broken or untrusted signature ($($f.SigStatus)): $($p0.Name)" `
                -Severity $sev -Class 'suspicious' -Confidence 'medium' -Reasons $rs `
                -Evidence @((New-S02SigEvidence $f), (New-S02ProcEvidence $p0)) -Entities @{ processes = @($g.Group | ForEach-Object { New-S02ProcEntity $_ }) } `
                -FpNotes 'HashMismatch can follow an in-place update or a damaged file; NotTrusted/UnknownError also appear with self-signed tools, expired chains without timestamps, or revocation-check failures when offline.' `
                -Recommendation 'Open the file Properties > Digital Signatures and compare with the vendor. If the vendor does not ship it this way, have your antivirus scan the file and reinstall the program from the official source.' `
                -Mitre @('T1036.001', 'T1553.002') -Expected $f.Expected
        }
        Out-S02Items $uniq
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.masquerading' -Description 'Windows system process names running outside their real folders' -Script {
        $sysBins = @{}
        foreach ($prop in $ioc.systemBinaries.PSObject.Properties) { $sysBins[$prop.Name.ToLowerInvariant()] = @($prop.Value | ForEach-Object { Get-S02FullPath $_ }) }
        $evaluated = [System.Collections.Generic.List[object]]::new()
        $noPath = 0
        $bad = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $procs) {
            $n = ([string]$p.Name).ToLowerInvariant()
            if (-not $sysBins.ContainsKey($n)) { continue }
            $evaluated.Add($p)
            if (-not $p.Path) { $noPath++; continue }
            $folder = [IO.Path]::GetDirectoryName($p.Path)
            $ok = $false
            foreach ($a in $sysBins[$n]) { if (Test-S02Same $folder $a) { $ok = $true; break } }
            if (-not $ok) { $bad.Add($p) }
        }
        foreach ($g in ($bad | Group-Object { $_.Path.ToLowerInvariant() })) {
            $p0 = $g.Group[0]
            $f = Get-S02PathFacts $p0.Path
            $sev = if ($f.IsMicrosoft) { 'medium' } else { 'high' }
            $rs = @('masquerading')
            if ($f.SigClass -eq 'unsigned') { $rs += 'unsigned' } elseif ($f.SigClass -in 'invalid', 'untrusted') { $rs += 'invalid_signature' }
            if ($f.UserWritable) { $rs += 'user_writable' }
            foreach ($p in $g.Group) { Add-S02ProcFlag $p 'processes.masquerading' }
            Add-S02Finding -Check 'processes.masquerading' -Title "System process name running outside its Windows folder: $($p0.Name) from $([IO.Path]::GetDirectoryName($p0.Path))" `
                -Severity $sev -Class 'suspicious' -Confidence $(if ($f.IsMicrosoft) { 'low' } else { 'high' }) -Reasons $rs `
                -Evidence @((New-S02ProcEvidence $p0), (New-S02SigEvidence $f), [ordered]@{ type = 'expected_folders'; folders = $sysBins[$p0.Name.ToLowerInvariant()] }) `
                -Entities @{ processes = @($g.Group | ForEach-Object { New-S02ProcEntity $_ }) } `
                -FpNotes 'A Microsoft-signed copy can run from a servicing, WinSxS or backup folder; anything unsigned or third-party under a Windows process name is almost never legitimate.' `
                -Recommendation 'Note the PID and path, check the signer in Properties, and run a full scan with your antivirus plus a second-opinion scanner. Do not kill it blindly: collect evidence first and verify the parent process.' `
                -Mitre @('T1036.005') -Expected $f.Expected
        }
        if ($noPath -gt 0) { Set-BvsCheckStatus -Id 'processes.masquerading' -Status partial -Reason "$noPath system-named process(es) without a readable image path" }
        Out-S02Items $evaluated
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.lookalike_names' -Description 'Process names that imitate Windows process names (homoglyph skeleton or one edit away)' -Script {
        $protected = @($ioc.lookalike.protected | ForEach-Object { $_.ToLowerInvariant() })
        $protSet = New-S02Set $protected
        $protSkel = @{}; foreach ($pn in $protected) { $protSkel[$pn] = Get-S02Skeleton $pn }
        $minLen = [int]$ioc.lookalike.minLength
        $names = @($procs | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension([string]$_.Name).ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
        foreach ($n in $names) {
            if ($protSet.Contains($n) -or $S.LookAllow.Contains($n)) { continue }
            $hit = $null; $how = $null
            $sk = Get-S02Skeleton $n
            foreach ($pn in $protected) { if ($sk -ceq $protSkel[$pn]) { $hit = $pn; $how = 'homoglyph'; break } }
            if (-not $hit -and $n.Length -ge $minLen) {
                foreach ($pn in $protected) {
                    if ($pn.Length -lt $minLen -or [Math]::Abs($pn.Length - $n.Length) -gt 1) { continue }
                    if ((Get-S02Distance $n $pn) -eq 1) { $hit = $pn; $how = 'one_edit'; break }
                }
            }
            if (-not $hit) { continue }
            $group = @($procs | Where-Object { [IO.Path]::GetFileNameWithoutExtension([string]$_.Name).ToLowerInvariant() -eq $n })
            $p0 = $group[0]
            $f = if ($p0.Path) { Get-S02PathFacts $p0.Path } else { $null }
            if ($f -and $f.IsMicrosoft) { continue }
            $sev = if ($f -and $f.SigClass -eq 'valid') { 'low' } else { 'high' }
            $rs = @('masquerading'); if ($f -and $f.SigClass -eq 'unsigned') { $rs += 'unsigned' }; if ($f -and $f.UserWritable) { $rs += 'user_writable' }
            foreach ($p in $group) { Add-S02ProcFlag $p 'processes.lookalike_names' }
            Add-S02Finding -Check 'processes.lookalike_names' -Title "Look-alike process name: $($p0.Name) imitates $hit.exe ($how)" `
                -Severity $sev -Class 'suspicious' -Confidence $(if ($how -eq 'homoglyph') { 'high' } else { 'medium' }) -Reasons $rs `
                -Evidence @((New-S02ProcEvidence $p0), (New-S02SigEvidence $f), [ordered]@{ type = 'lookalike'; imitates = "$hit.exe"; method = $how; skeleton = $sk }) `
                -Entities @{ processes = @($group | ForEach-Object { New-S02ProcEntity $_ }) } `
                -FpNotes 'Some vendors use names close to Windows binaries; a valid third-party signature makes this much less likely to be malicious (reported as low).' `
                -Recommendation 'Check the signer and the folder of this program. If it is not something you installed, run a full scan with your antivirus and investigate how it starts (S01 persistence report).' `
                -Mitre @('T1036.005') -Expected $(if ($f) { $f.Expected } else { $null })
        }
        Out-S02Items $names
    })

$nativeHosts = [System.Collections.Generic.List[object]]::new()
[void](Invoke-BvsCheck -Run $run -Id 'processes.parent_anomalies' -Description 'Office/browser spawning shells or script hosts; svchost/lsass/services/spoolsv with an unexpected parent' -Script {
        $rules = @{}
        foreach ($r in $ioc.parentRules) { $rules[$r.child.ToLowerInvariant()] = @($r.parents | ForEach-Object { $_.ToLowerInvariant() }) }
        $markers = @($ioc.nativeMessagingMarkers)
        $evaluated = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $procs) {
            $n = ([string]$p.Name).ToLowerInvariant()
            $par = Get-S02Parent $p
            if ($rules.ContainsKey($n)) {
                $evaluated.Add($p)
                $parName = if ($par) { ([string]$par.Name).ToLowerInvariant() } else { $null }
                if (-not $parName -or $rules[$n] -notcontains $parName) {
                    Add-S02ProcFlag $p 'processes.parent_anomalies'
                    $f = if ($p.Path) { Get-S02PathFacts $p.Path } else { $null }
                    $parDesc = if ($par) { "$($par.Name) (PID $($par.Pid))" } else { "an exited or unknown process (PID $($p.ParentPid))" }
                    Add-S02Finding -Check 'processes.parent_anomalies' -Title "$($p.Name) (PID $($p.Pid)) was not started by $($rules[$n] -join '/'): parent is $parDesc" `
                        -Severity 'high' -Class 'suspicious' -Confidence 'medium' -Reasons @('masquerading') `
                        -Evidence @((New-S02ProcEvidence $p), (New-S02SigEvidence $f), [ordered]@{ type = 'expected_parent'; expected = $rules[$n]; actual = $parDesc }) `
                        -Entities @{ processes = @((New-S02ProcEntity $p)) } `
                        -FpNotes 'Rare legitimate cases: a debugger or crash-handler restarting the process, or PID reuse right after the real parent exited (checked by start time).' `
                        -Recommendation 'Record the PID, path and parent. Compare the image path and signer with the real Windows binary; if they differ or the parent is unusual, run a full offline or boot-time antivirus scan (for example Microsoft Defender Offline).' `
                        -Mitre @('T1036.005', 'T1055') -Expected $(if ($f) { $f.Expected } else { $null })
                }
            }
            if ($S.SuspChild.Contains($n) -and $par -and ($S.Office.Contains([string]$par.Name) -or $S.Browser.Contains([string]$par.Name))) {
                $evaluated.Add($p)
                if ($ownPids.Contains([int]$p.Pid)) { continue }
                $cl = [string]$p.CommandLine
                $isNative = $false
                if ($S.Browser.Contains([string]$par.Name) -and $n -eq 'cmd.exe') { foreach ($mk in $markers) { if ($cl.IndexOf($mk, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $isNative = $true; break } } }
                if ($isNative) {
                    $hostPath = $null
                    if ($cl -match '(?i)/c\s+"*"([^"]+?\.(?:exe|bat|cmd|ps1|py|js))"') { $hostPath = Get-S02FullPath $Matches[1] }
                    $hf = if ($hostPath -and [IO.File]::Exists($hostPath)) { Get-S02PathFacts $hostPath } else { $null }
                    $nativeHosts.Add([ordered]@{ browser = $par.Name; pid = [int]$p.Pid; host = $hostPath; hostSig = if ($hf) { $hf.SigStatus } else { $null }; hostSigner = if ($hf) { $hf.Signer } else { $null }; commandLine = Get-S02Short $cl 300 })
                    continue
                }
                Add-S02ProcFlag $p 'processes.parent_anomalies'
                $kind = if ($S.Office.Contains([string]$par.Name)) { 'Office application' } else { 'web browser' }
                Add-S02Finding -Check 'processes.parent_anomalies' -Title "$kind $($par.Name) started $($p.Name) (PID $($p.Pid))" `
                    -Severity 'high' -Class 'suspicious' -Confidence 'medium' -Reasons @('lolbin') `
                    -Evidence @((New-S02ProcEvidence $p), (New-S02ProcEvidence $par)) -Entities @{ processes = @((New-S02ProcEntity $p), (New-S02ProcEntity $par)) } `
                    -FpNotes 'Some add-ins, mail macros you wrote yourself, or browser native-messaging hosts launch helpers; native messaging (chrome-extension:// in the command line) is excluded automatically.' `
                    -Recommendation 'Find which document or page was open at that time. Do not enable macros or content; close the parent application and have your antivirus scan the document and the Downloads folder.' `
                    -Mitre @('T1204.002', 'T1566.001', 'T1059')
            }
        }
        Out-S02Items $evaluated
    })

$ownCmdHits = 0
[void](Invoke-BvsCheck -Run $run -Id 'processes.command_lines' -Description 'Suspicious command lines: encoded/hidden PowerShell, download cradles, LOLBins (mshta, regsvr32, rundll32, certutil, bitsadmin), conhost --headless payloads, miner markers' -Script {
        $pats = foreach ($cp in $ioc.commandLinePatterns) {
            [pscustomobject]@{
                Id = $cp.id; Rx = [regex]::new($cp.regex); Hosts = (New-S02Set $cp.hosts); Any = (@($cp.hosts) -contains '*')
                Words = @($cp.hosts | Where-Object { $_ -ne '*' } | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) })
                Severity = $cp.severity; Reasons = @($cp.reasons); Mitre = @($cp.mitre)
            }
        }
        $withCmd = @($procs | Where-Object { $_.CommandLine })
        foreach ($p in $withCmd) {
            $n = ([string]$p.Name).ToLowerInvariant()
            $cl = [string]$p.CommandLine
            $hits = [System.Collections.Generic.List[object]]::new()
            foreach ($pt in $pats) {
                $applies = ($pt.Any -and -not $S.SearchTools.Contains($n)) -or $pt.Hosts.Contains($n)
                if (-not $applies -and $S.ShellHosts.Contains($n)) {
                    foreach ($w in $pt.Words) { if ($cl -match ('(?i)\b' + [regex]::Escape($w) + '\b')) { $applies = $true; break } }
                }
                if ($applies -and $pt.Rx.IsMatch($cl)) { $hits.Add($pt) }
            }
            if ($n -in 'conhost.exe', 'openconsole.exe') {
                $payload = Get-S02HeadlessPayload $cl
                if ($payload) { $hits.Add([pscustomobject]@{ Id = 'conhost_headless_payload'; Severity = 'high'; Reasons = @('hidden', 'lolbin'); Mitre = @('T1564.003', 'T1202') }) }
            }
            if ($hits.Count -eq 0) { continue }
            if ($ownPids.Contains([int]$p.Pid)) { $script:ownCmdHits++; continue }
            $sev = Get-S02MaxSev @($hits | ForEach-Object { $_.Severity })
            if ($hits.Count -ge 2 -and $sev -eq 'medium') { $sev = 'high' }
            $ids = @($hits | ForEach-Object { $_.Id })
            $rs = @($hits | ForEach-Object { $_.Reasons }); $mt = @($hits | ForEach-Object { $_.Mitre })
            $ev = [System.Collections.Generic.List[object]]::new()
            $ev.Add((New-S02ProcEvidence $p)); $ev.Add([ordered]@{ type = 'patterns'; ids = $ids })
            if ($ids -contains 'ps_encoded_command') {
                $r = Resolve-BvsCommandLine $cl
                if ($r -and $r.DecodedCommand) { $ev.Add([ordered]@{ type = 'decoded_command'; text = (Get-S02Short $r.DecodedCommand 400) }) }
            }
            $f = if ($p.Path) { Get-S02PathFacts $p.Path } else { $null }
            Add-S02ProcFlag $p 'processes.command_lines'
            Add-S02Finding -Check 'processes.command_lines' -Title "Suspicious command line ($($ids -join ', ')): $($p.Name) PID $($p.Pid)" `
                -Severity $sev -Class 'suspicious' -Confidence $(if ($sev -eq 'high') { 'medium' } else { 'low' }) -Reasons $rs `
                -Evidence @($ev) -Entities @{ processes = @((New-S02ProcEntity $p)) } `
                -FpNotes 'Installers and admin scripts sometimes use -WindowStyle Hidden, -EncodedCommand or "irm ... | iex" one-liners (for example official install scripts). Check who started it and when; processes started by this scan are excluded.' `
                -Recommendation 'Note the parent process and the decoded command (evidence). If you did not start it, disconnect from the network, run a full scan with your antivirus, and review persistence (S01) for whatever launches it.' `
                -Mitre $mt -Expected $(if ($f) { $f.Expected } else { $null })
        }
        Out-S02Items $withCmd
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.risky_locations' -Description 'Processes running from %TEMP%, Downloads, Public, ProgramData root, AppData root, Recycle Bin (plus Desktop, profile root, drive root, Startup)' -Script {
        $evaluated = [System.Collections.Generic.List[object]]::new()
        $signedLow = [System.Collections.Generic.List[object]]::new()
        foreach ($g in ($procWithPath | Group-Object { $_.Path.ToLowerInvariant() })) {
            $p0 = $g.Group[0]
            $f = Get-S02PathFacts $p0.Path
            $risky = $f.Location -in $riskyProcLoc
            if (-not $risky -and $f.Location -notin $unusualProcLoc) { continue }
            foreach ($p in $g.Group) { $evaluated.Add($p) }
            if ($f.SigClass -eq 'valid') { $signedLow.Add([ordered]@{ path = $p0.Path; name = $p0.Name; signer = $f.Signer; location = $f.Location; pids = @($g.Group | ForEach-Object { [int]$_.Pid }) }); continue }
            $sev = if ($risky) { 'high' } else { 'medium' }
            $rs = @('user_writable')
            if ($f.SigClass -eq 'unsigned') { $rs += 'unsigned' } elseif ($f.SigClass -in 'invalid', 'untrusted') { $rs += 'invalid_signature' }
            if (Test-S02RandomName $p0.Name) { $rs += 'random_name' }
            foreach ($p in $g.Group) { Add-S02ProcFlag $p 'processes.risky_locations' }
            $motw = if ($f.Exists) { Get-BvsMotw $p0.Path } else { $null }
            $ev = @((New-S02ProcEvidence $p0), (New-S02SigEvidence $f))
            if ($motw) { $ev += [ordered]@{ type = 'motw'; zone = $motw.ZoneId; host = $motw.HostDomain; hostUrl = $motw.HostUrl } }
            Add-S02Finding -Check 'processes.risky_locations' -Title "Unsigned program running from $($f.Location): $($p0.Name)" `
                -Severity $sev -Class 'suspicious' -Confidence 'medium' -Reasons $rs -Evidence $ev `
                -Entities @{ processes = @($g.Group | ForEach-Object { New-S02ProcEntity $_ }); files = @([ordered]@{ path = $p0.Path; sha256 = (Get-BvsHash -Path $p0.Path -MaxBytes ($MaxHashMB * 1MB)); sig = $f.SigStatus; signer = $f.Signer; motw = if ($motw) { [ordered]@{ zone = $motw.ZoneId; host = $motw.HostDomain } } else { $null } }) } `
                -FpNotes 'Portable tools, installers and self-extracting updaters run from Temp or Downloads; unsigned builds of developer tools are common for technical users.' `
                -Recommendation 'Identify the program (Properties > Details, where it was downloaded from). If unknown, check the hash on VirusTotal yourself and let your antivirus scan the folder; remove it only after confirming.' `
                -Mitre @('T1204.002') -Expected $f.Expected
        }
        if ($signedLow.Count) {
            Add-S02Finding -Check 'processes.risky_locations' -Title "$($signedLow.Count) signed program(s) running from Temp/Downloads/AppData root or similar folders" `
                -Severity 'low' -Class 'hygiene' -Confidence 'low' -Reasons @('user_writable') -Evidence @($signedLow | Select-Object -First 25) `
                -FpNotes 'Signed installers, updaters and portable apps commonly run from these folders.' `
                -Recommendation 'Glance over the list; anything you do not recognise deserves a look at its signer and origin.' -Mitre @('T1204.002')
        }
        Out-S02Items $evaluated
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.unsigned_user_writable' -Description 'Unsigned programs running from other user-writable folders (AppData vendor folders, LocalAppData\Programs, user profile)' -Script {
        $evaluated = [System.Collections.Generic.List[object]]::new()
        $helpers = [System.Collections.Generic.List[object]]::new()
        foreach ($g in ($procWithPath | Group-Object { $_.Path.ToLowerInvariant() })) {
            $p0 = $g.Group[0]
            $f = Get-S02PathFacts $p0.Path
            if (-not $f.UserWritable -or $f.SigClass -ne 'unsigned') { continue }
            if ($f.Location -in $riskyProcLoc -or $f.Location -in $unusualProcLoc) { continue }   # reported by processes.risky_locations
            foreach ($p in $g.Group) { $evaluated.Add($p) }
            $helper = Test-S02SignedHelper $p0
            if ($helper) { $helpers.Add([ordered]@{ path = $p0.Path; name = $p0.Name; reason = $helper; company = if ($f.Version) { $f.Version.CompanyName } else { $null }; pids = @($g.Group | ForEach-Object { [int]$_.Pid }) }); continue }
            $rs = @('unsigned', 'user_writable'); if (Test-S02RandomName $p0.Name) { $rs += 'random_name' }
            foreach ($p in $g.Group) { Add-S02ProcFlag $p 'processes.unsigned_user_writable' }
            Add-S02Finding -Check 'processes.unsigned_user_writable' -Title "Unsigned program running from a user-writable folder: $($p0.Name)" `
                -Severity 'medium' -Class 'suspicious' -Confidence 'low' -Reasons $rs `
                -Evidence @((New-S02ProcEvidence $p0), (New-S02SigEvidence $f)) -Entities @{ processes = @($g.Group | ForEach-Object { New-S02ProcEntity $_ }) } `
                -FpNotes 'Many open-source and developer tools (Go/Rust/Python builds, npm-installed binaries) ship unsigned and install per-user.' `
                -Recommendation 'Confirm you installed this program. Anything that writes itself into AppData and runs unsigned without you knowing should be scanned and its startup entry reviewed (S01).' `
                -Mitre @('T1204.002') -Expected $f.Expected
        }
        if ($helpers.Count) {
            Add-S02Finding -Check 'processes.unsigned_user_writable' -Title "$($helpers.Count) unsigned helper program(s) launched by signed applications from their own folders" `
                -Severity 'low' -Class 'hygiene' -Confidence 'low' -Reasons @('unsigned', 'user_writable') -Evidence @($helpers | Select-Object -First 30) `
                -FpNotes 'Editors and Electron apps start unsigned helpers (language servers, ripgrep, terminals) from their install or extension folders.' `
                -Recommendation 'No action needed unless a name looks unfamiliar; keep these apps updated.' -Mitre @()
        }
        Out-S02Items $evaluated
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.image_missing' -Description 'Running processes whose image file no longer exists on disk' -Script {
        $evaluated = [System.Collections.Generic.List[object]]::new()
        foreach ($g in ($procWithPath | Group-Object { $_.Path.ToLowerInvariant() })) {
            $p0 = $g.Group[0]
            foreach ($p in $g.Group) { $evaluated.Add($p) }
            $f = Get-S02PathFacts $p0.Path
            if ($f.Exists) { continue }
            $sev = if ($p0.PathSource -eq 'service') { 'low' } else { 'medium' }
            foreach ($p in $g.Group) { Add-S02ProcFlag $p 'processes.image_missing' }
            Add-S02Finding -Check 'processes.image_missing' -Title "Process image no longer on disk: $($p0.Name) ($($p0.Path))" `
                -Severity $sev -Class 'suspicious' -Confidence 'low' -Reasons @('hidden') `
                -Evidence @((New-S02ProcEvidence $p0), [ordered]@{ type = 'image'; path = $p0.Path; exists = $false; pathSource = $p0.PathSource }) `
                -Entities @{ processes = @($g.Group | ForEach-Object { New-S02ProcEntity $_ }) } `
                -FpNotes 'Applications that update themselves while running (browsers, editors, Squirrel/Electron apps) delete the old version folder; temporary installers also remove themselves.' `
                -Recommendation 'Restart the application and check whether the process comes back from a normal folder. A self-deleting unknown process is a strong malware sign: scan with your antivirus and review persistence.' `
                -Mitre @('T1070.004')
        }
        Out-S02Items $evaluated
    })

[void](Invoke-BvsCheck -Run $run -Id 'processes.cpu_miner' -Description "Sustained CPU (>= $CpuThresholdPct% of all cores) from unsigned or unknown programs; Win32_PerfFormattedData_PerfProc_Process sampled twice >= $CpuSampleSeconds s apart, plus raw-counter average" -Script {
        while (([datetime]::UtcNow - $cpu1.At).TotalSeconds -lt $CpuSampleSeconds) { Start-Sleep -Milliseconds 250 }
        $cpu2 = Get-S02CpuSample
        $ncpu = [Environment]::ProcessorCount
        $dt = if ($cpu1.RawTs -and $cpu2.RawTs) { $cpu2.RawTs - $cpu1.RawTs } else { 0 }
        $rows = [System.Collections.Generic.List[object]]::new()
        $ids = @($cpu2.Formatted.Keys) + @($cpu2.Raw.Keys) | Sort-Object -Unique
        foreach ($procId in $ids) {
            $nm = $cpu2.Names[$procId]
            if ($S.Pseudo.Contains([string]$nm) -or $procId -le 4) { continue }
            $raw = if ($dt -gt 0 -and $cpu1.Raw.ContainsKey($procId) -and $cpu2.Raw.ContainsKey($procId)) { [Math]::Round(100 * ($cpu2.Raw[$procId] - $cpu1.Raw[$procId]) / $dt / $ncpu, 1) } else { $null }
            $f1 = if ($cpu1.Formatted.ContainsKey($procId)) { [Math]::Round($cpu1.Formatted[$procId] / $ncpu, 1) } else { $null }
            $f2 = if ($cpu2.Formatted.ContainsKey($procId)) { [Math]::Round($cpu2.Formatted[$procId] / $ncpu, 1) } else { $null }
            $rows.Add([pscustomobject]@{ Pid = [int]$procId; Name = $nm; RawPct = $raw; F1 = $f1; F2 = $f2 })
        }
        $script:cpuMeta = [ordered]@{
            cores = $ncpu; thresholdPct = $CpuThresholdPct; sampleGapSeconds = [Math]::Round(($cpu2.At - $cpu1.At).TotalSeconds, 1)
            rawIntervalSeconds = if ($dt -gt 0) { [Math]::Round($dt / 1e7, 1) } else { $null }; errors = @($cpu1.Errors) + @($cpu2.Errors)
        }
        if ($cpu1.Errors.Count -and $cpu2.Errors.Count -and $rows.Count -eq 0) { Set-BvsCheckStatus -Id 'processes.cpu_miner' -Status error -Reason (($cpu1.Errors + $cpu2.Errors) -join '; ') }
        $top = @($rows | Sort-Object { if ($null -ne $_.RawPct) { $_.RawPct } else { [double]$_.F2 } } -Descending | Select-Object -First 15)
        $script:topCpu = foreach ($r in $top) {
            $p = $byPid[$r.Pid]
            $path = if ($p -and $p.Path) { $p.Path } else { Convert-S02NtPath ([BvsS02.Native]::ImagePath($r.Pid)) }
            $f = if ($path) { Get-S02PathFacts $path } else { $null }
            [ordered]@{ pid = $r.Pid; name = $r.Name; path = $path; avgPctOfMachine = $r.RawPct; sample1Pct = $r.F1; sample2Pct = $r.F2; sig = if ($f) { $f.SigStatus } else { 'unknown' }; signer = if ($f) { $f.Signer } else { $null } }
        }
        foreach ($r in $rows) {
            $sustained = ($null -ne $r.RawPct -and $r.RawPct -ge $CpuThresholdPct) -or ($null -ne $r.F1 -and $null -ne $r.F2 -and $r.F1 -ge $CpuThresholdPct -and $r.F2 -ge $CpuThresholdPct)
            if (-not $sustained) { continue }
            $p = $byPid[$r.Pid]
            $path = if ($p -and $p.Path) { $p.Path } else { Convert-S02NtPath ([BvsS02.Native]::ImagePath($r.Pid)) }
            $f = if ($path) { Get-S02PathFacts $path } else { $null }
            if ($f -and $f.SigClass -eq 'valid') { continue }
            $rs = @(); if ($f -and $f.SigClass -eq 'unsigned') { $rs += 'unsigned' }; if ($f -and $f.UserWritable) { $rs += 'user_writable' }
            if ($p) { Add-S02ProcFlag $p 'processes.cpu_miner' }
            Add-S02Finding -Check 'processes.cpu_miner' -Title "Sustained high CPU from an unsigned or unknown program: $($r.Name) (PID $($r.Pid), ~$($r.RawPct)% of all cores)" `
                -Severity 'high' -Class 'suspicious' -Confidence 'low' -Reasons $rs `
                -Evidence @([ordered]@{ type = 'cpu'; avgPctOfMachine = $r.RawPct; sample1Pct = $r.F1; sample2Pct = $r.F2; cores = $ncpu; thresholdPct = $CpuThresholdPct }, $(if ($p) { New-S02ProcEvidence $p }), (New-S02SigEvidence $f)) `
                -Entities @{ processes = @($(if ($p) { New-S02ProcEntity $p })) } `
                -FpNotes 'Compilers, video encoders, local AI models (Ollama), games and scientific tools legitimately use many cores; unsigned builds of such tools exist.' `
                -Recommendation 'Check what the program is and whether you started it. Coin miners often run from AppData or Temp with pool addresses in the command line; scan with your antivirus and look for its startup entry.' `
                -Mitre @('T1496') -Expected $(if ($f) { $f.Expected } else { $null })
        }
        Out-S02Items $rows
    })

#endregion

#region ---------- files: sweep ----------

$fileFacts = [System.Collections.Generic.List[object]]::new()
$factsByPath = @{}
$seenFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$magicCandidates = [System.Collections.Generic.List[object]]::new()
$downloadsAll = [System.Collections.Generic.List[object]]::new()
$sweepStats = [System.Collections.Generic.List[object]]::new()

function New-S02FileFacts {
    param([IO.FileInfo]$Item, [string]$Sweep, [int]$RelDepth)
    [pscustomobject][ordered]@{
        path = $Item.FullName; name = $Item.Name; ext = $Item.Extension.ToLowerInvariant(); size = $Item.Length
        created = $Item.CreationTimeUtc.ToString('o'); modified = $Item.LastWriteTimeUtc.ToString('o'); createdUtc = $Item.CreationTimeUtc
        sweep = $Sweep; relDepth = $RelDepth; location = (Get-S02Location $Item.FullName); userWritable = $null; cloudOnly = [bool](Test-BvsCloudOnly $Item)
        sigStatus = $null; sigClass = 'na'; signer = $null; isMicrosoft = $false
        motwZone = $null; motwHost = $null; motwHostUrl = $null; motwHostCategory = $null; motwReferrerHost = $null
        magic = $null; magicMismatch = $false; disguised = $false
        lnk = $null; lnkTargetSig = $null; url = $null; script = $null
        indicators = [System.Collections.Generic.List[string]]::new(); reasons = [System.Collections.Generic.List[string]]::new()
        severity = 'info'; primaryCheck = $null; sha256 = $null; expected = $null
    }
}

function Add-S02Facts {
    param($Facts)
    $fileFacts.Add($Facts)
    $factsByPath[$Facts.path.ToLowerInvariant()] = $Facts
}

function Set-S02FileSig {
    param($Facts)
    if ($Facts.cloudOnly -or (Test-BvsNeverRead $Facts.path)) { return }
    $sig = Get-BvsSignature $Facts.path
    $Facts.sigStatus = [string]$sig.Status
    $Facts.sigClass = Get-S02SigClass $sig $Facts.ext
    if ($Facts.magic -in 'pe', 'elf' -and $Facts.sigClass -eq 'na') { $Facts.sigClass = Get-S02SigClass $sig '.exe' }
    $Facts.signer = $sig.Signer
    $Facts.isMicrosoft = [bool]($sig.Status -eq 'Valid' -and ($sig.IsOSBinary -or "$($sig.Signer)" -match '^Microsoft '))
}

function Get-S02HostCategory {
    param([AllowNull()][string]$HostName)
    if (-not $HostName) { return $null }
    $h = $HostName.ToLowerInvariant().TrimEnd('.')
    $ip = $null
    if ([Net.IPAddress]::TryParse($h.Trim('[', ']'), [ref]$ip)) { return 'ip_address' }
    if ($h -match '(^|\.)xn--') { return 'punycode' }
    foreach ($cat in 'file_sharer', 'url_shortener', 'chat_cdn', 'raw_code', 'tunnel_dyndns', 'free_hosting', 'personal_cloud') {
        foreach ($entry in @($ioc.downloadSources.$cat)) {
            $en = ([string]$entry).ToLowerInvariant()
            if ($en.Contains('*')) { if ($h -like $en -or $h -like "*.$en") { return $cat } }
            elseif ($h -eq $en -or $h.EndsWith('.' + $en)) { return $cat }
        }
    }
    'normal'
}

function Set-S02FileMotw {
    param($Facts)
    if ($Facts.cloudOnly -or (Test-BvsNeverRead $Facts.path)) { return }
    $m = Get-BvsMotw $Facts.path
    if (-not $m) { return }
    $Facts.motwZone = $m.ZoneId
    $hn = $m.HostDomain
    if (-not $hn -and "$($m.HostUrl)" -match '^(?i)blob:(https?://[^/?#\s]+)') { try { $hn = ([uri]$Matches[1]).Host } catch { $hn = $null } }
    $Facts.motwHost = $hn
    $Facts.motwHostUrl = $m.HostUrl
    $Facts.motwHostCategory = Get-S02HostCategory $hn
    if ($m.ReferrerUrl) { try { $Facts.motwReferrerHost = ([uri]($m.ReferrerUrl -replace '\?\[query-removed\]$', '')).Host } catch { } }
}

$sweeps = @(
    @{ Id = 'startup_user'; Path = $L.Startup; Depth = 3; AllExt = $true; MagicDepth = 3; Desc = 'Current user Startup folder (all file types)' }
    @{ Id = 'startup_common'; Path = $L.CommonStartup; Depth = 3; AllExt = $true; MagicDepth = 3; Desc = 'All-users Startup folder (all file types)' }
    @{ Id = 'downloads'; Path = $L.Downloads; Depth = 6; Archives = 'all'; MagicDepth = 6; Desc = 'Downloads (depth 6, archives included)' }
    @{ Id = 'desktop'; Path = $L.Desktop; Depth = 6; Archives = 'all'; MagicDepth = 6; Desc = 'User Desktop (depth 6, archives included)' }
    @{ Id = 'public'; Path = $L.Public; Depth = 32; Archives = 'desktop'; MagicDepth = 32; Desc = 'C:\Users\Public (all depths; archives only on the Public Desktop)' }
    @{ Id = 'temp'; Path = $L.Temp; Depth = 5; MagicDepth = 1; Desc = '%TEMP% (depth 5)' }
    @{ Id = 'windows_temp'; Path = $L.WinTemp; Depth = 3; MagicDepth = 1; NeedsList = $true; Desc = 'Windows\Temp (depth 3, needs listing rights)' }
    @{ Id = 'appdata'; Path = $L.AppData; Depth = 2; MagicDepth = 0; Desc = '%APPDATA% (depth 2)' }
    @{ Id = 'localappdata'; Path = $L.LocalAppData; Depth = 2; MagicDepth = 0; Desc = '%LOCALAPPDATA% (depth 2)' }
    @{ Id = 'programdata'; Path = $L.ProgramData; Depth = 2; MagicDepth = 1; Desc = 'ProgramData (depth 2)' }
    @{ Id = 'drive_root'; Path = $L.SystemDriveRoot; Depth = 1; MagicDepth = 0; Desc = 'System drive root (depth 1)' }
)

foreach ($sw in $sweeps) {
    $chkId = "files.sweep.$($sw.Id)"
    [void](Invoke-BvsCheck -Run $run -Id $chkId -Description $sw.Desc -Script {
            if (-not $sw.Path -or -not [IO.Directory]::Exists($sw.Path)) { Set-BvsCheckStatus -Id $chkId -Status not_applicable -Reason 'folder not present'; return (, @()) }
            if ($sw.NeedsList) {
                try { $en = [IO.Directory]::EnumerateFileSystemEntries($sw.Path).GetEnumerator(); [void]$en.MoveNext() }
                catch {
                    Set-BvsCheckStatus -Id $chkId -Status needs_admin -Reason 'folder cannot be listed without elevation'
                    $coverageNotes.Add("$($sw.Path) could not be listed without elevation (run src\admin\windows checks).")
                    return (, @())
                }
            }
            $rootLen = $sw.Path.TrimEnd('\').Length
            $sel = [System.Collections.Generic.List[object]]::new()
            $total = 0; $recentN = 0; $magicN = 0; $excluded = 0
            $sws = [Diagnostics.Stopwatch]::StartNew()
            foreach ($item in (Get-BvsFiles -Path $sw.Path -MaxDepth $sw.Depth)) {
                $total++
                $full = $item.FullName
                if (Test-S02Excluded $full) { $excluded++; continue }
                $ext = $item.Extension.ToLowerInvariant()
                if ($sw.Id -eq 'downloads' -and ($S.Risky.Contains($ext) -or $S.Archive.Contains($ext) -or $S.Installer.Contains($ext))) { $downloadsAll.Add($item) }
                if (-not $seenFiles.Add($full)) { continue }
                if ($item.CreationTimeUtc -lt $cutoffUtc -and $item.LastWriteTimeUtc -lt $cutoffUtc) { continue }
                $recentN++
                $rest = if ($item.DirectoryName.Length -gt $rootLen) { $item.DirectoryName.Substring($rootLen).Trim('\') } else { '' }
                $relDepth = if ($rest) { ($rest -split '\\').Count } else { 0 }
                $archOk = $sw.Archives -eq 'all' -or ($sw.Archives -eq 'desktop' -and (Test-S02Under $full $L.PublicDesktop))
                $pick = $S.Risky.Contains($ext) -or ($archOk -and $S.Archive.Contains($ext)) -or ($sw.AllExt -and $item.Name -ne 'desktop.ini')
                if ($pick) { $ff = New-S02FileFacts $item $sw.Id $relDepth; Add-S02Facts $ff; $sel.Add($ff) }
                elseif ($relDepth -le $sw.MagicDepth -and $item.Length -ge 64) { $magicCandidates.Add([pscustomobject]@{ Item = $item; Sweep = $sw.Id; RelDepth = $relDepth }); $magicN++ }
            }
            $sweepStats.Add([ordered]@{ sweep = $sw.Id; path = $sw.Path; maxDepth = $sw.Depth; filesSeen = $total; excludedOwn = $excluded; recent = $recentN; riskyRecent = $sel.Count; headerChecks = $magicN; ms = $sws.ElapsedMilliseconds })
            Out-S02Items $sel
        })
}

#endregion

#region ---------- files: facts ----------

[void](Invoke-BvsCheck -Run $run -Id 'files.signatures' -Description 'Authenticode signer of recent signable files (PE, MSI, signable scripts)' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($ff in $fileFacts) { if ($S.Signable.Contains($ff.ext)) { Set-S02FileSig $ff; $done.Add($ff) } }
        Out-S02Items $done
    })

[void](Invoke-BvsCheck -Run $run -Id 'files.motw' -Description 'Mark-of-the-Web zone, host and referrer of recent risky files' -Script {
        foreach ($ff in $fileFacts) { Set-S02FileMotw $ff }
        Out-S02Items @($fileFacts | Where-Object { $null -ne $_.motwZone })
    })

[void](Invoke-BvsCheck -Run $run -Id 'files.header_vs_extension' -Description 'File header (magic bytes) compared with the extension of recent risky files' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($ff in $fileFacts) {
            if ($ff.cloudOnly -or $ff.size -lt 4 -or (Test-BvsNeverRead $ff.path)) { continue }
            $mm = Test-BvsMagicMismatch $ff.path
            if (-not $mm) { continue }
            $done.Add($ff)
            $ff.magic = $mm.Actual; $ff.magicMismatch = [bool]$mm.Mismatch; $ff.disguised = [bool]$mm.IsDisguisedExecutable
            if ($ff.disguised) {
                $ff.indicators.Add($(if ($S.Decoy.Contains($ff.ext) -or $S.Script.Contains($ff.ext) -or $ff.ext -in '.lnk', '.url', '.docm', '.xlsm', '.one', '.chm', '.iso', '.img', '.jar', '.reg', '.msc') { 'disguised_executable' } else { 'pe_unusual_extension' }))
                Set-S02FileSig $ff
            }
        }
        Out-S02Items $done
    })

[void](Invoke-BvsCheck -Run $run -Id 'files.disguised_executables' -Description 'Executable (PE/ELF) headers behind non-executable extensions among other recent files in the high-risk folders' -Script {
        foreach ($c in $magicCandidates) {
            $full = $c.Item.FullName
            if ((Test-BvsCloudOnly $c.Item) -or (Test-BvsNeverRead $full)) { continue }
            $mm = Test-BvsMagicMismatch $full
            if (-not $mm -or -not $mm.IsDisguisedExecutable) { continue }
            $ff = New-S02FileFacts $c.Item $c.Sweep $c.RelDepth
            $ff.magic = $mm.Actual; $ff.disguised = $true; $ff.magicMismatch = [bool]$mm.Mismatch
            $ff.indicators.Add($(if ($S.Decoy.Contains($ff.ext)) { 'disguised_executable' } elseif ($S.NeutralPe.Contains($ff.ext)) { 'pe_neutral_extension' } else { 'pe_unusual_extension' }))
            Set-S02FileSig $ff; Set-S02FileMotw $ff
            Add-S02Facts $ff
        }
        Out-S02Items $magicCandidates
    })

$bidiRx = [regex]::new('[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]')
$decoyAlt = (@($ioc.decoyExtensions) | ForEach-Object { [regex]::Escape($_.TrimStart('.')) }) -join '|'
$dblAlt = (@($ioc.doubleExtensionTargets) | ForEach-Object { [regex]::Escape($_.TrimStart('.')) }) -join '|'
$doubleRx = [regex]::new("(?i)\.($decoyAlt)[\s\u00A0_.\-]*\.($dblAlt)$")
$piNameRx = [regex]::new([string]$ioc.promptInjectionName)

[void](Invoke-BvsCheck -Run $run -Id 'files.name_tricks' -Description 'Double extensions, RTLO/bidi characters, random high-entropy names, instruction-like names' -Script {
        foreach ($ff in $fileFacts) {
            if ($bidiRx.IsMatch($ff.name)) { $ff.indicators.Add('rtlo') }
            $dm = $doubleRx.Match($ff.name)
            if ($dm.Success) { $ff.indicators.Add('double_extension'); $ff | Add-Member -NotePropertyName decoyExt -NotePropertyValue ('.' + $dm.Groups[1].Value.ToLowerInvariant()) -Force }
            if (Test-S02RandomName $ff.name) { $ff.indicators.Add('random_name') }
            if ($piNameRx.IsMatch($ff.name)) { $ff.indicators.Add('prompt_injection_name') }
        }
        Out-S02Items $fileFacts
    })

$script:SigBeef0004 = [uint32]3203334148   # 0xBEEF0004 file-entry extension block
$script:SigEnvBlock = [uint32]2684354561   # 0xA0000001 EnvironmentVariableDataBlock

function Read-S02IdList {
    param([byte[]]$B, [int]$Start, [int]$Size)
    $parts = [System.Collections.Generic.List[string]]::new()
    $p = $Start; $end = [Math]::Min($Start + $Size, $B.Length)
    while ($p + 2 -le $end) {
        $isz = [int][BitConverter]::ToUInt16($B, $p)
        if ($isz -lt 3 -or $p + $isz -gt $end) { break }
        $type = $B[$p + 2]
        $cls = $type -band 0x70
        if ($cls -eq 0x20) {
            $s = Get-S02CStr $B ($p + 3) $false 16
            if ($s -match '^[A-Za-z]:\\?$') { $parts.Clear(); $parts.Add($s.TrimEnd('\')) }
        }
        elseif ($cls -eq 0x30) {
            $name = $null
            $extOff = [int][BitConverter]::ToUInt16($B, $p + $isz - 2)
            $q = $p + $extOff
            if ($extOff -ge 4 -and $extOff -lt $isz - 8 -and [BitConverter]::ToUInt32($B, $q + 4) -eq $script:SigBeef0004) {
                $ver = [int][BitConverter]::ToUInt16($B, $q + 2)
                $off = if ($ver -ge 9) { 46 } elseif ($ver -ge 8) { 42 } elseif ($ver -ge 7) { 38 } elseif ($ver -ge 3) { 20 } else { 0 }
                if ($off -and $q + $off -lt $p + $isz) { $name = Get-S02CStr $B ($q + $off) $true 260 }
            }
            if (-not $name) { $name = Get-S02CStr $B ($p + 14) (($type -band 0x04) -ne 0) 260 }
            if ($name) { $parts.Add($name) }
        }
        $p += $isz
    }
    if ($parts.Count) { return ($parts -join '\') }
    $null
}

function Read-S02Lnk {
    # Minimal MS-SHLLINK parser: target (LinkInfo / environment block / IDList), arguments, working dir, icon, show command.
    param([string]$Path)
    $o = [ordered]@{ ok = $false; size = 0; target = $null; targetSource = $null; arguments = $null; workingDir = $null; relativePath = $null; iconLocation = $null; name = $null; showCommand = $null; error = $null }
    try {
        $b = Read-S02Bytes -Path $Path -MaxBytes ([int]$ioc.lnk.maxBytes)
        $o.size = (Get-Item -LiteralPath $Path -Force).Length
        if ($b.Length -lt 0x4C -or [BitConverter]::ToUInt32($b, 0) -ne 0x4C) { $o.error = 'not a shell link header'; return [pscustomobject]$o }
        $flags = [BitConverter]::ToUInt32($b, 0x14)
        $o.showCommand = [int][BitConverter]::ToUInt32($b, 0x3C)
        $pos = 0x4C
        $idTarget = $null
        if ($flags -band 0x1) {
            $idSize = [int][BitConverter]::ToUInt16($b, $pos)
            $idTarget = Read-S02IdList $b ($pos + 2) $idSize
            $pos += 2 + $idSize
        }
        if (($flags -band 0x2) -and -not ($flags -band 0x100) -and $pos + 28 -le $b.Length) {
            $li = $pos
            $liSize = [int][BitConverter]::ToUInt32($b, $li)
            $liHeader = [int][BitConverter]::ToUInt32($b, $li + 4)
            $liFlags = [int][BitConverter]::ToUInt32($b, $li + 8)
            $localOff = [int][BitConverter]::ToUInt32($b, $li + 16)
            $netOff = [int][BitConverter]::ToUInt32($b, $li + 20)
            $suffixOff = [int][BitConverter]::ToUInt32($b, $li + 24)
            $local = $null; $suffix = $null; $net = $null
            if ($liHeader -ge 0x24 -and $li + 36 -le $b.Length) {
                $localU = [int][BitConverter]::ToUInt32($b, $li + 28); $suffixU = [int][BitConverter]::ToUInt32($b, $li + 32)
                if (($liFlags -band 1) -and $localU) { $local = Get-S02CStr $b ($li + $localU) $true 1024 }
                if ($suffixU) { $suffix = Get-S02CStr $b ($li + $suffixU) $true 1024 }
            }
            if (-not $local -and ($liFlags -band 1) -and $localOff) { $local = Get-S02CStr $b ($li + $localOff) $false 1024 }
            if (-not $suffix -and $suffixOff) { $suffix = Get-S02CStr $b ($li + $suffixOff) $false 1024 }
            if (($liFlags -band 2) -and $netOff -and $li + $netOff + 12 -le $b.Length) {
                $cnr = $li + $netOff
                $netNameOff = [int][BitConverter]::ToUInt32($b, $cnr + 8)
                if ($netNameOff -gt 0x14 -and $cnr + 24 -le $b.Length) { $net = Get-S02CStr $b ($cnr + [int][BitConverter]::ToUInt32($b, $cnr + 20)) $true 1024 }
                else { $net = Get-S02CStr $b ($cnr + $netNameOff) $false 1024 }
            }
            if ($local) { $o.target = $local + $suffix; $o.targetSource = 'linkinfo' }
            elseif ($net) { $o.target = if ($suffix) { $net.TrimEnd('\') + '\' + $suffix } else { $net }; $o.targetSource = 'linkinfo-unc' }
            $pos = $li + $liSize
        }
        $unicode = ($flags -band 0x80) -ne 0
        foreach ($pair in @(@(0x4, 'name'), @(0x8, 'relativePath'), @(0x10, 'workingDir'), @(0x20, 'arguments'), @(0x40, 'iconLocation'))) {
            if (-not ($flags -band $pair[0])) { continue }
            if ($pos + 2 -gt $b.Length) { break }
            $count = [int][BitConverter]::ToUInt16($b, $pos); $pos += 2
            $nbytes = if ($unicode) { $count * 2 } else { $count }
            if ($pos + $nbytes -gt $b.Length) { $nbytes = $b.Length - $pos }
            $o[$pair[1]] = if ($unicode) { [Text.Encoding]::Unicode.GetString($b, $pos, $nbytes) } else { $script:Ansi.GetString($b, $pos, $nbytes) }
            $pos += $nbytes
        }
        $envTarget = $null
        while ($pos + 8 -le $b.Length) {
            $bs = [int][BitConverter]::ToUInt32($b, $pos)
            if ($bs -lt 8) { break }
            $sig = [BitConverter]::ToUInt32($b, $pos + 4)
            if ($sig -eq $script:SigEnvBlock -and $pos + 0x314 -le $b.Length) {
                $envTarget = ([Text.Encoding]::Unicode.GetString($b, $pos + 8 + 260, 520) -split [char]0)[0]
                if (-not $envTarget) { $envTarget = ($script:Ansi.GetString($b, $pos + 8, 260) -split [char]0)[0] }
            }
            $pos += $bs
        }
        if (-not $o.target -and $envTarget) { $o.target = $envTarget; $o.targetSource = 'envblock' }
        if (-not $o.target -and $idTarget) { $o.target = $idTarget; $o.targetSource = 'idlist' }
        if (-not $o.target -and $o.relativePath) { $o.target = $o.relativePath; $o.targetSource = 'relative' }
        $o.ok = $true
    }
    catch { $o.error = $_.Exception.Message }
    [pscustomobject]$o
}

$lolAlt = (@($ioc.lnk.lolbins) | ForEach-Object { [regex]::Escape($_) }) -join '|'
$lnkLolRx = [regex]::new("(?i)(?:^|[\s""'/\\&|(;])($lolAlt)(?:\.exe|\.com)?(?=$|[\s""'&|);])")
$argPatterns = @(@($ioc.commandLinePatterns | Where-Object { $_.id -ne 'bitsadmin_any' }) | ForEach-Object { [pscustomobject]@{ Id = $_.id; Rx = [regex]::new($_.regex) } })
$strongScript = @(@($ioc.scriptIndicators | Where-Object { $_.strong }) | ForEach-Object { [pscustomobject]@{ Id = $_.id; Rx = [regex]::new($_.regex) } })
$piContentRx = [regex]::new([string](@($ioc.scriptIndicators | Where-Object { $_.id -eq 'prompt_injection' })[0].regex))

[void](Invoke-BvsCheck -Run $run -Id 'files.lnk_abuse' -Description 'Shortcuts (.lnk) whose target/arguments call shells or LOLBins, carry long or padded arguments, point to UNC paths or unsigned user-writable programs' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($ff in @($fileFacts | Where-Object { $_.ext -eq '.lnk' })) {
            if ($ff.cloudOnly -or (Test-BvsNeverRead $ff.path)) { continue }
            $lnk = Read-S02Lnk $ff.path
            $ff.lnk = $lnk
            $done.Add($ff)
            if (-not $lnk.ok) { continue }
            $target = [string]$lnk.target
            $texp = if ($target) { [Environment]::ExpandEnvironmentVariables($target) } else { '' }
            $leaf = if ($texp) { [IO.Path]::GetFileNameWithoutExtension($texp).ToLowerInvariant() } else { '' }
            $largs = [string]$lnk.arguments
            if ($largs.Trim() -and $S.LnkLolbins.Contains($leaf)) { $ff.indicators.Add('lnk_lolbin_target') }
            if ($largs -and $lnkLolRx.IsMatch($largs)) { $ff.indicators.Add('lnk_lolbin_in_args') }
            if ($largs) {
                $ids = @($argPatterns | Where-Object { $_.Rx.IsMatch($largs) } | ForEach-Object { $_.Id }) + @($strongScript | Where-Object { $_.Rx.IsMatch($largs) } | ForEach-Object { $_.Id })
                if ($ids.Count) { $ff.indicators.Add('lnk_suspicious_args'); $ff | Add-Member -NotePropertyName lnkPatterns -NotePropertyValue @($ids | Select-Object -Unique) -Force }
                if ($largs.Length -gt [int]$ioc.lnk.longArgumentChars) { $ff.indicators.Add('lnk_long_args') }
                if ($largs -match ('\s{' + [int]$ioc.lnk.paddingRun + ',}')) { $ff.indicators.Add('lnk_padded_args') }
                if ($piContentRx.IsMatch($largs)) { $ff.indicators.Add('lnk_prompt_injection') }
            }
            if (($ff.indicators.Contains('lnk_lolbin_target') -or $ff.indicators.Contains('lnk_lolbin_in_args')) -and $lnk.showCommand -eq 7) { $ff.indicators.Add('lnk_minimized') }
            if ($texp -match '^(\\\\|(?i)https?:)') { $ff.indicators.Add('lnk_remote_target') }
            if ($lnk.size -gt [int]$ioc.lnk.largeLnkBytes) { $ff.indicators.Add('lnk_large') }
            if ($texp -and $texp -notmatch '^\\\\' -and [IO.File]::Exists($texp) -and $S.Pe.Contains([IO.Path]::GetExtension($texp).ToLowerInvariant())) {
                $tf = Get-S02PathFacts $texp
                $ff.lnkTargetSig = [ordered]@{ path = $texp; status = $tf.SigStatus; signer = $tf.Signer; userWritable = $tf.UserWritable }
                if ($tf.UserWritable -and $tf.SigClass -in 'unsigned', 'invalid', 'untrusted') { $ff.indicators.Add('lnk_target_unsigned_user_writable') }
            }
        }
        Out-S02Items $done
    })

[void](Invoke-BvsCheck -Run $run -Id 'files.url_abuse' -Description 'Internet shortcuts (.url) and .library-ms/.search-ms files pointing to file://, UNC, WebDAV or protocol-handler targets' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($ff in @($fileFacts | Where-Object { $_.ext -in '.url', '.library-ms', '.search-ms' })) {
            if ($ff.cloudOnly -or (Test-BvsNeverRead $ff.path)) { continue }
            $done.Add($ff)
            try { $txt = Read-S02Text $ff.path 262144 } catch { continue }
            if ($ff.ext -eq '.url') {
                $u = $null; $icon = $null; $wd = $null
                foreach ($line in ($txt -split "`r?`n")) {
                    if (-not $u -and $line -match '^\s*URL\s*=\s*(.+?)\s*$') { $u = $Matches[1] }
                    elseif ($line -match '^\s*IconFile\s*=\s*(.+?)\s*$') { $icon = $Matches[1] }
                    elseif ($line -match '^\s*WorkingDirectory\s*=\s*(.+?)\s*$') { $wd = $Matches[1] }
                }
                $ff.url = [ordered]@{ url = (Protect-BvsUrl $u); iconFile = (Protect-BvsUrl $icon); workingDirectory = $wd }
                if ($u) {
                    $ut = $u.Trim()
                    if ($ut -match '^\\\\' -or $ut -match '(?i)^file:/{2,}(?!/|localhost/)[^/]') { $ff.indicators.Add('url_unc') }
                    elseif ($ut -match '(?i)^file:') { $ff.indicators.Add('url_file_local') }
                    foreach ($mk in @($ioc.urlFile.webdavMarkers)) { if ($ut.IndexOf($mk, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ff.indicators.Add('url_webdav'); break } }
                    foreach ($sc in @($ioc.urlFile.badSchemes)) { if ($sc -ne 'file:' -and $ut.StartsWith($sc, [StringComparison]::OrdinalIgnoreCase)) { $ff.indicators.Add('url_bad_scheme'); break } }
                    if ($ut -match '(?i)^https?://([^/:?#]+)') { $cat = Get-S02HostCategory $Matches[1]; if ($flaggedSources.Contains([string]$cat)) { $ff.indicators.Add('url_unusual_host') } }
                    if ($piContentRx.IsMatch($ut)) { $ff.indicators.Add('url_prompt_injection') }
                }
                if ($icon -and $icon.Trim() -match '^(\\\\|(?i)https?://)') { $ff.indicators.Add('url_icon_remote') }
            }
            else {
                if ($txt -match '(?i)<url>\s*(?:\\\\|https?://|file://)' -or $txt -match '\\\\[A-Za-z0-9._-]+(?:@SSL)?(?:@\d+)?\\' -or $txt -match '(?i)crumb=location:\s*(?:\\\\|%5C%5C)') { $ff.indicators.Add('libms_remote') }
            }
        }
        Out-S02Items $done
    })

$scriptRx = @($ioc.scriptIndicators | ForEach-Object { [pscustomobject]@{ Id = $_.id; Strong = [bool]$_.strong; Rx = [regex]::new($_.regex) } })
[void](Invoke-BvsCheck -Run $run -Id 'files.script_content' -Description 'Recent scripts (PowerShell, WSH, HTA, batch, AutoIt): indicator patterns (download cradles, encoded commands, AMSI/Defender tampering, obfuscation)' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($ff in @($fileFacts | Where-Object { $S.Script.Contains($_.ext) })) {
            if ($ff.cloudOnly -or $ff.size -gt 2MB -or $ff.size -eq 0 -or (Test-BvsNeverRead $ff.path)) { continue }
            try { $txt = Read-S02Text $ff.path 2MB } catch { continue }
            $done.Add($ff)
            $ids = [System.Collections.Generic.List[string]]::new(); $strong = 0
            foreach ($r in $scriptRx) { if ($r.Rx.IsMatch($txt)) { $ids.Add($r.Id); if ($r.Strong) { $strong++ } } }
            $txt = $null
            $ff.script = [ordered]@{ indicators = @($ids); strong = $strong }
        }
        Out-S02Items $done
    })

$sideloadRows = [System.Collections.Generic.List[object]]::new()
[void](Invoke-BvsCheck -Run $run -Id 'files.sideloading' -Description 'Unsigned recent DLL next to a validly signed EXE in the same user-writable folder (DLL side-loading)' -Script {
        $allow = @($ioc.sideloading.allowDlls)
        $groups = @($fileFacts | Where-Object { $_.ext -eq '.dll' -and $_.sigClass -in 'unsigned', 'invalid', 'untrusted' } | Group-Object { [IO.Path]::GetDirectoryName($_.path) })
        $checked = 0
        foreach ($g in ($groups | Select-Object -First ([int]$ioc.sideloading.maxFolders))) {
            $folder = $g.Name
            if (-not (Test-BvsUserWritable $folder)) { continue }
            $checked++
            $signedExe = $null
            foreach ($x in @(Get-BvsFiles -Path $folder -MaxDepth 0 -Include '*.exe')) {
                if ((Test-BvsCloudOnly $x) -or (Test-BvsNeverRead $x.FullName)) { continue }
                $xs = Get-BvsSignature $x.FullName
                if ($xs.Status -eq 'Valid') { $signedExe = [ordered]@{ path = $x.FullName; signer = $xs.Signer; created = $x.CreationTimeUtc.ToString('o') }; break }
            }
            if (-not $signedExe) { continue }
            foreach ($dll in $g.Group) {
                $shadow = [IO.File]::Exists((Join-Path $L.System32 $dll.name)) -and -not (Test-S02Like $dll.name $allow)
                $riskyFolder = $dll.location -in 'downloads', 'desktop', 'temp', 'public', 'programdata_root', 'appdata_root', 'profile_root', 'drive_root'
                $level = if ($shadow) { 'high' } elseif ($riskyFolder) { 'medium' } else { 'low' }
                if ($shadow) { $dll.indicators.Add('sideload_system_dll_name') } elseif ($riskyFolder) { $dll.indicators.Add('sideload_risky_folder') }
                $dll | Add-Member -NotePropertyName sideloadExe -NotePropertyValue $signedExe -Force
                $sideloadRows.Add([ordered]@{ folder = $folder; dll = $dll.name; dllCreated = $dll.created; dllSig = $dll.sigStatus; shadowsSystem32 = $shadow; signedExe = $signedExe.path; exeSigner = $signedExe.signer; level = $level })
            }
        }
        Out-S02Items $groups
    })

[void](Invoke-BvsCheck -Run $run -Id 'files.appdata_root_executables' -Description 'Executables and scripts directly in the AppData, Roaming, Local or LocalLow root (any age)' -Script {
        $done = [System.Collections.Generic.List[object]]::new()
        foreach ($r in (@($L.AppDataDir, $L.AppData, $L.LocalAppData, $L.LocalLow) | Select-Object -Unique)) {
            foreach ($item in @(Get-BvsFiles -Path $r -MaxDepth 0)) {
                $ext = $item.Extension.ToLowerInvariant()
                if (-not ($S.Pe.Contains($ext) -or $S.Script.Contains($ext) -or $ext -in '.msi', '.jar', '.lnk', '.hta')) { continue }
                if (Test-S02Excluded $item.FullName) { continue }
                $ff = $factsByPath[$item.FullName.ToLowerInvariant()]
                if (-not $ff) {
                    $ff = New-S02FileFacts $item 'appdata_root' 0
                    if ($S.Signable.Contains($ext)) { Set-S02FileSig $ff }
                    Set-S02FileMotw $ff
                    $mm = if (-not $ff.cloudOnly -and -not (Test-BvsNeverRead $ff.path)) { Test-BvsMagicMismatch $ff.path } else { $null }
                    if ($mm) { $ff.magic = $mm.Actual; $ff.magicMismatch = [bool]$mm.Mismatch }
                    Add-S02Facts $ff
                }
                $ff.indicators.Add('appdata_root_executable')
                $done.Add($ff)
            }
        }
        Out-S02Items $done
    })

#endregion

#region ---------- files: scoring and findings ----------

function Set-S02Level {
    # Raise the severity recorded for one check (never lowers it).
    param([System.Collections.IDictionary]$Levels, [string]$Check, [string]$Severity)
    if (-not $Levels.Contains($Check) -or $SevRank[$Severity] -gt $SevRank[$Levels[$Check]]) { $Levels[$Check] = $Severity }
}

function Measure-S02File {
    # Turns collected facts and indicators into a severity per check. Returns $null when nothing stands out.
    param($ff)
    $lv = [ordered]@{}
    $rs = $ff.reasons; $ind = $ff.indicators
    $ext = $ff.ext; $loc = $ff.location
    $isPe = $S.Pe.Contains($ext) -or ($ff.magic -in 'pe', 'elf')
    $isMsi = $ext -in '.msi', '.msp'
    $isScript = $S.Script.Contains($ext)
    $isWsh = $S.Wsh.Contains($ext)
    $dl = ($null -ne $ff.motwZone) -and ($ff.motwZone -ge 3)
    $unusual = $ff.motwHostCategory -and $flaggedSources.Contains([string]$ff.motwHostCategory)
    $notValid = $ff.sigClass -in 'unsigned', 'invalid', 'untrusted'
    if ($unusual) { $rs.Add('motw_unknown_host'); $rs.Add("source_$($ff.motwHostCategory)") }

    # names and disguise
    if ($ind.Contains('rtlo')) { Set-S02Level $lv 'files.name_tricks' 'high'; $rs.Add('masquerading'); $rs.Add('obfuscation') }
    if ($ind.Contains('double_extension')) {
        $benignLnk = $false
        if ($ext -eq '.lnk' -and $ff.lnk -and $ff.lnk.target -and $ff.PSObject.Properties['decoyExt']) { $benignLnk = ([IO.Path]::GetExtension([string]$ff.lnk.target).ToLowerInvariant() -eq $ff.decoyExt) }
        if (-not $benignLnk) { Set-S02Level $lv 'files.name_tricks' 'high'; $rs.Add('masquerading') }
    }
    if ($ind.Contains('prompt_injection_name')) { Set-S02Level $lv 'files.name_tricks' 'medium'; $rs.Add('prompt_injection') }
    if ($ind.Contains('disguised_executable')) { Set-S02Level $lv 'files.disguised_executables' 'high'; $rs.Add('masquerading'); $rs.Add('obfuscation') }
    if ($ind.Contains('pe_unusual_extension') -and $ff.sigClass -ne 'valid') { Set-S02Level $lv 'files.disguised_executables' 'medium'; $rs.Add('masquerading') }
    if ($ind.Contains('pe_neutral_extension') -and $ff.sigClass -ne 'valid' -and $loc -in 'downloads', 'desktop', 'public', 'startup') { Set-S02Level $lv 'files.disguised_executables' 'low' }

    # signatures of executables and installers
    if ($isPe -or $isMsi) {
        $isLib = $ext -in '.dll', '.ocx', '.sys'
        switch ($ff.sigClass) {
            'invalid' { Set-S02Level $lv 'files.signatures' 'high'; $rs.Add('invalid_signature') }
            'untrusted' { Set-S02Level $lv 'files.signatures' 'medium'; $rs.Add('invalid_signature') }
            'unsigned' {
                $rs.Add('unsigned')
                if ($loc -eq 'startup') { Set-S02Level $lv 'files.signatures' 'high'; $rs.Add('persistence') }
                elseif ($loc -eq 'appdata_root') { Set-S02Level $lv 'files.appdata_root_executables' 'high' }
                elseif ($loc -in 'public', 'programdata_root', 'drive_root', 'profile_root', 'recycle_bin') { Set-S02Level $lv 'files.signatures' $(if ($isLib) { 'low' } else { 'medium' }) }
                elseif ($loc -eq 'temp') { Set-S02Level $lv 'files.signatures' $(if ($isLib) { if ($ff.relDepth -eq 0) { 'low' } else { 'info' } } elseif ($ff.relDepth -le 1 -or $ind.Contains('random_name')) { 'medium' } else { 'low' }) }
                elseif ($loc -in 'downloads', 'desktop') { Set-S02Level $lv 'files.signatures' $(if ($isLib) { 'info' } else { 'low' }) }
                elseif ($loc -eq 'windows') { Set-S02Level $lv 'files.signatures' 'medium' }
                else { Set-S02Level $lv 'files.signatures' $(if ($isLib) { 'info' } elseif ($ind.Contains('random_name')) { 'medium' } else { 'low' }) }
            }
        }
        if ($unusual) { Set-S02Level $lv 'downloads.origins' $(if ($notValid) { 'high' } else { 'medium' }) }
        if ($notValid -and $ext -in '.scr', '.pif', '.com' -and ($dl -or $loc -in 'downloads', 'desktop', 'temp')) { Set-S02Level $lv 'files.risky_types' 'high' }
        if ($notValid -and $ext -in '.cpl', '.xll') { Set-S02Level $lv 'files.risky_types' 'medium' }
    }

    # shortcuts
    if ($ext -eq '.lnk') {
        $lol = $ind.Contains('lnk_lolbin_target') -or $ind.Contains('lnk_lolbin_in_args')
        $susp = $ind.Contains('lnk_suspicious_args'); $long = $ind.Contains('lnk_long_args') -or $ind.Contains('lnk_padded_args')
        if ($ind.Contains('lnk_remote_target')) { Set-S02Level $lv 'files.lnk_abuse' 'high' }
        if ($lol -and ($susp -or $long -or $ind.Contains('lnk_minimized') -or $ind.Contains('lnk_large') -or $loc -in 'startup', 'downloads', 'temp', 'public')) { Set-S02Level $lv 'files.lnk_abuse' 'high'; $rs.Add('lolbin') }
        elseif ($lol) { Set-S02Level $lv 'files.lnk_abuse' 'medium'; $rs.Add('lolbin') }
        elseif ($susp -or $long) { Set-S02Level $lv 'files.lnk_abuse' 'medium' }
        if ($susp) { $rs.Add('obfuscation') }
        if ($ind.Contains('lnk_padded_args')) { $rs.Add('hidden') }
        if ($ind.Contains('lnk_target_unsigned_user_writable')) { Set-S02Level $lv 'files.lnk_abuse' $(if ($loc -eq 'startup') { 'high' } else { 'low' }); $rs.Add('unsigned'); $rs.Add('user_writable') }
        if ($ind.Contains('lnk_large') -and -not $lol) { Set-S02Level $lv 'files.lnk_abuse' 'low' }
        if ($ind.Contains('lnk_prompt_injection')) { Set-S02Level $lv 'files.lnk_abuse' 'medium'; $rs.Add('prompt_injection') }
        if ($loc -eq 'startup') { $rs.Add('persistence') }
    }

    # internet shortcuts and search/library descriptions
    if ($ext -eq '.url') {
        if ($ind.Contains('url_unc') -or $ind.Contains('url_webdav') -or $ind.Contains('url_bad_scheme')) { Set-S02Level $lv 'files.url_abuse' 'high' }
        if ($ind.Contains('url_file_local') -or $ind.Contains('url_icon_remote')) { Set-S02Level $lv 'files.url_abuse' 'medium' }
        if ($ind.Contains('url_unusual_host')) { Set-S02Level $lv 'files.url_abuse' 'low' }
        if ($ind.Contains('url_prompt_injection')) { Set-S02Level $lv 'files.url_abuse' 'medium'; $rs.Add('prompt_injection') }
        if ($loc -eq 'startup') { Set-S02Level $lv 'files.url_abuse' 'medium'; $rs.Add('persistence') }
    }
    if ($ext -in '.library-ms', '.search-ms') {
        if ($ind.Contains('libms_remote')) { Set-S02Level $lv 'files.url_abuse' 'high' }
        elseif ($dl -or $loc -in 'downloads', 'desktop', 'temp', 'startup') { Set-S02Level $lv 'files.url_abuse' 'medium' }
        else { Set-S02Level $lv 'files.url_abuse' 'low' }
    }

    # scripts
    if ($isScript) {
        if ($ff.script) {
            $strong = [int]$ff.script.strong; $anyN = @($ff.script.indicators).Count
            $hot = $isWsh -or $dl -or $loc -in 'temp', 'startup', 'public', 'appdata_root', 'programdata_root', 'downloads', 'drive_root', 'profile_root'
            if ($strong -gt 0 -and $hot) { Set-S02Level $lv 'files.script_content' 'high'; $rs.Add('obfuscation') }
            elseif ($strong -gt 0) { Set-S02Level $lv 'files.script_content' 'medium'; $rs.Add('obfuscation') }
            elseif ($anyN -gt 0 -and $isWsh -and ($dl -or $loc -in 'temp', 'startup', 'public', 'appdata_root', 'programdata_root')) { Set-S02Level $lv 'files.script_content' 'medium' }
            if (@($ff.script.indicators) -contains 'prompt_injection') { Set-S02Level $lv 'files.script_content' 'medium'; $rs.Add('prompt_injection') }
        }
        if ($ext -in '.a3x', '.au3') { Set-S02Level $lv 'files.risky_types' $(if ($dl) { 'high' } else { 'medium' }) }
        elseif ($ext -eq '.hta') { Set-S02Level $lv 'files.risky_types' $(if ($dl -or $loc -eq 'startup') { 'high' } else { 'medium' }) }
        elseif ($isWsh -and $dl) { Set-S02Level $lv 'files.risky_types' 'medium' }
        if ($loc -eq 'startup') { Set-S02Level $lv 'files.script_content' 'medium'; $rs.Add('persistence') }
        if ($loc -eq 'appdata_root') { Set-S02Level $lv 'files.appdata_root_executables' 'medium' }
        if ($unusual) { Set-S02Level $lv 'downloads.origins' 'high' }
    }

    # other risky types
    switch ($ext) {
        { $_ -in '.iso', '.img', '.vhd', '.vhdx' } { if ($unusual) { Set-S02Level $lv 'downloads.origins' 'high' } elseif ($dl -and $loc -eq 'temp') { Set-S02Level $lv 'files.risky_types' 'low' } }
        { $_ -in '.zip', '.rar', '.7z' } { if ($unusual) { Set-S02Level $lv 'downloads.origins' 'medium' } }
        { $_ -in '.jar', '.docm', '.xlsm' } { if ($unusual) { Set-S02Level $lv 'downloads.origins' 'high' } elseif ($dl) { Set-S02Level $lv 'files.risky_types' 'low' } }
        { $_ -in '.one', '.chm', '.msc', '.application' } { if ($unusual) { Set-S02Level $lv 'downloads.origins' 'high' } elseif ($dl) { Set-S02Level $lv 'files.risky_types' 'medium' } }
        '.reg' { if ($loc -in 'temp', 'startup') { Set-S02Level $lv 'files.risky_types' 'medium' } elseif ($dl) { Set-S02Level $lv 'files.risky_types' 'low' } }
    }

    # header mismatch, side-loading, AppData root
    if ($ff.magicMismatch -and -not $ff.disguised) { Set-S02Level $lv 'files.header_vs_extension' $(if ($ext -eq '.lnk') { 'medium' } else { 'low' }) }
    if ($ind.Contains('sideload_system_dll_name')) { Set-S02Level $lv 'files.sideloading' 'high'; $rs.Add('masquerading') }
    elseif ($ind.Contains('sideload_risky_folder')) { Set-S02Level $lv 'files.sideloading' 'medium' }
    if ($ind.Contains('appdata_root_executable') -and ($isPe -or $isMsi)) { Set-S02Level $lv 'files.appdata_root_executables' $(if ($notValid) { 'high' } else { 'low' }) }
    if ($loc -eq 'startup' -and $lv.Count -eq 0 -and $ff.name -ne 'desktop.ini') { Set-S02Level $lv 'files.risky_types' 'low'; $rs.Add('persistence') }

    if ($lv.Count -eq 0) { return $null }
    $sev = 'info'; $chk = $null
    foreach ($k in $lv.Keys) { if ($null -eq $chk -or $SevRank[$lv[$k]] -gt $SevRank[$sev]) { $sev = $lv[$k]; $chk = $k } }
    if ($SevRank[$sev] -ge 1) {
        if ($ff.createdUtc -ge $recent30Utc) { $rs.Add('created_lt_30d') }
        if ($ff.userWritable -and ($isPe -or $isScript -or $isMsi) -and $notValid) { $rs.Add('user_writable') }
        if ($ind.Contains('random_name')) { $rs.Add('random_name') }
    }
    [pscustomobject]@{ Severity = $sev; Check = $chk; Levels = $lv; Expected = (Resolve-S02Expected $ff.path $ff.sigClass) }
}

function New-S02FileEntity {
    param($ff)
    [ordered]@{
        path = $ff.path; sha256 = $ff.sha256; size = $ff.size; sig = $ff.sigStatus; signer = $ff.signer; created = $ff.created; modified = $ff.modified
        motw = if ($null -ne $ff.motwZone) { [ordered]@{ zone = $ff.motwZone; host = $ff.motwHost } } else { $null }
    }
}

function New-S02FileEvidence {
    param($ff)
    $ev = [System.Collections.Generic.List[object]]::new()
    $ev.Add([ordered]@{ type = 'file'; path = $ff.path; size = $ff.size; created = $ff.created; modified = $ff.modified; location = $ff.location; userWritable = $ff.userWritable; header = $ff.magic; extension = $ff.ext; indicators = @($ff.indicators | Select-Object -Unique) })
    if ($ff.sigStatus) { $ev.Add([ordered]@{ type = 'signature'; status = $ff.sigStatus; signer = $ff.signer }) }
    if ($null -ne $ff.motwZone) { $ev.Add([ordered]@{ type = 'motw'; zone = $ff.motwZone; host = $ff.motwHost; hostUrl = $ff.motwHostUrl; referrerHost = $ff.motwReferrerHost; category = $ff.motwHostCategory }) }
    if ($ff.lnk -and $ff.lnk.ok) {
        $ev.Add([ordered]@{ type = 'lnk'; target = $ff.lnk.target; targetSource = $ff.lnk.targetSource; arguments = (Get-S02Short $ff.lnk.arguments 500); argumentLength = ([string]$ff.lnk.arguments).Length; workingDir = $ff.lnk.workingDir; icon = $ff.lnk.iconLocation; showCommand = $ff.lnk.showCommand; patterns = if ($ff.PSObject.Properties['lnkPatterns']) { $ff.lnkPatterns } else { @() }; targetSignature = $ff.lnkTargetSig })
    }
    if ($ff.url) { $ev.Add([ordered]@{ type = 'url'; url = $ff.url.url; iconFile = $ff.url.iconFile; workingDirectory = $ff.url.workingDirectory }) }
    if ($ff.script) { $ev.Add([ordered]@{ type = 'script_indicators'; ids = $ff.script.indicators; strong = $ff.script.strong }) }
    if ($ff.PSObject.Properties['sideloadExe']) { $ev.Add([ordered]@{ type = 'signed_exe_same_folder'; path = $ff.sideloadExe.path; signer = $ff.sideloadExe.signer }) }
    @($ev)
}

$fileText = @{
    'files.name_tricks'              = @{ T = 'Deceptive file name'; M = @('T1036.002', 'T1036.007'); F = 'Double extensions occasionally come from tools that append an extension; right-to-left override characters have essentially no legitimate use in file names.'; R = 'Do not open it. Check Properties > Details / Digital Signatures and where it came from (MOTW host in evidence); delete or quarantine it with your antivirus if you do not recognise it.' }
    'files.disguised_executables'    = @{ T = 'Executable disguised behind another extension'; M = @('T1036.008'); F = 'Some programs store executable code in cache or data files with custom extensions; a PE header behind a document, image or script extension is a classic malware trick.'; R = 'Do not open or rename it. Let your antivirus scan the file and the folder; if it came from a download or e-mail, delete it.' }
    'files.signatures'               = @{ T = 'Unsigned or badly signed executable'; M = @('T1204.002', 'T1553.002'); F = 'Many legitimate open-source and developer tools are unsigned; installers extract unsigned helpers into Temp while they run.'; R = 'Confirm you know the program and where it came from. If not, check its hash on VirusTotal yourself and let your antivirus scan it before running.' }
    'files.appdata_root_executables' = @{ T = 'Executable directly in an AppData root folder'; M = @('T1204.002', 'T1036.005'); F = 'A few installers drop helpers in the AppData root, but normal programs live in vendor subfolders.'; R = 'Find out which program created it (creation time, MOTW, S01 startup entries). Quarantine it with your antivirus if you cannot identify it.' }
    'files.lnk_abuse'                = @{ T = 'Shortcut launches a shell or LOLBin'; M = @('T1204.002', 'T1547.009', 'T1059'); F = 'Shortcuts you create yourself (for example "cmd /k ..." helpers) and some admin tools use shell targets with arguments.'; R = 'Right-click > Properties and read the full Target and arguments (evidence). Delete the shortcut if you did not make it, and scan what it points to.' }
    'files.url_abuse'                = @{ T = 'Shortcut file points to a local, UNC, WebDAV or protocol-handler target'; M = @('T1187', 'T1204.001'); F = 'Internet shortcuts to intranet shares exist in some companies; on a home PC they are rare.'; R = 'Do not open it. Opening such shortcuts can leak your Windows password hash or run remote code; delete it if you did not create it.' }
    'files.script_content'           = @{ T = 'Script with suspicious content'; M = @('T1059.001', 'T1059.005', 'T1059.007', 'T1027'); F = 'Admin and installer scripts (and security tools) legitimately contain download or encoding code; only the pattern ids are recorded.'; R = 'Do not run it. Review it in a text editor (never double-click). If it arrived from the internet or e-mail and you do not know it, delete it and scan with your antivirus.' }
    'files.risky_types'              = @{ T = 'Risky file type in a high-risk folder'; M = @('T1204.002'); F = 'These file types have legitimate uses, but they are rarely needed by home users and are common malware carriers.'; R = 'Open only if you know exactly what it is and where it came from; otherwise delete it.' }
    'files.sideloading'              = @{ T = 'Possible DLL side-loading'; M = @('T1574.002'); F = 'Portable apps and games ship their own unsigned DLLs next to a signed launcher; a DLL named like a Windows system DLL is the stronger signal.'; R = 'Check whether the folder is a program you installed. If the signed EXE came with an unexpected DLL (typical in malicious ZIPs), delete the folder and scan with your antivirus.' }
    'files.header_vs_extension'      = @{ T = 'File header does not match its extension'; M = @('T1036.008'); F = 'Interrupted downloads, HTML error pages saved with the wrong extension, or renamed archives cause harmless mismatches.'; R = 'Check the file in a hex viewer or let your antivirus scan it; delete broken downloads.' }
    'downloads.origins'              = @{ T = 'Downloaded from an unusual source'; M = @('T1105', 'T1204.002'); F = 'File sharers and raw code hosts are also used for legitimate tools.'; R = 'See the downloads.origins finding for the full list.' }
}

$suspicious = [System.Collections.Generic.List[object]]::new()
[void](Invoke-BvsCheck -Run $run -Id 'files.findings' -Description 'Severity scoring of recent risky files; individual findings for medium and above, one summary per check for low' -Script {
        $lowByCheck = @{}
        foreach ($ff in $fileFacts) {
            $ff.userWritable = Test-BvsUserWritable ([IO.Path]::GetDirectoryName($ff.path))
            $m = Measure-S02File $ff
            if (-not $m) { continue }
            $sev = $m.Severity
            if ($m.Expected -and $m.Expected.applied) { $sev = Limit-S02Sev $sev $m.Expected.severityCap }
            $ff.severity = $sev; $ff.primaryCheck = $m.Check; $ff.expected = $m.Expected
            if ($SevRank[$sev] -ge 1 -and -not $ff.cloudOnly -and -not (Test-BvsNeverRead $ff.path)) { $ff.sha256 = Get-BvsHash -Path $ff.path -MaxBytes ($MaxHashMB * 1MB) }
            $suspicious.Add($ff)
            if ($m.Check -eq 'downloads.origins') { continue }
            $tx = $fileText[$m.Check]
            if ($SevRank[$sev] -ge 2) {
                $detail = @($ff.indicators | Select-Object -Unique) -join ', '
                Add-S02Finding -Check $m.Check -Title ("{0}: {1}{2}" -f $tx.T, $ff.name, $(if ($detail) { " ($detail)" } else { '' })) `
                    -Severity $sev -Class 'suspicious' -Confidence $(if ($sev -in 'high', 'critical' -and $m.Check -in 'files.name_tricks', 'files.disguised_executables', 'files.url_abuse') { 'high' } else { 'medium' }) `
                    -Reasons @($ff.reasons) -Evidence (New-S02FileEvidence $ff) -Entities @{ files = @((New-S02FileEntity $ff)) } `
                    -FpNotes $tx.F -Recommendation $tx.R -Mitre $tx.M -Expected $m.Expected
            }
            elseif ($sev -eq 'low') {
                if (-not $lowByCheck.ContainsKey($m.Check)) { $lowByCheck[$m.Check] = [System.Collections.Generic.List[object]]::new() }
                $lowByCheck[$m.Check].Add($ff)
            }
        }
        foreach ($chk in $lowByCheck.Keys) {
            $items = $lowByCheck[$chk]; $tx = $fileText[$chk]
            Add-S02Finding -Check $chk -Title "$($items.Count) lower-risk item(s): $($tx.T.ToLowerInvariant())" -Severity 'low' -Class 'hygiene' -Confidence 'low' `
                -Reasons @($items | ForEach-Object { $_.reasons } | Select-Object -Unique) `
                -Evidence @($items | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'file'; path = $_.path; created = $_.created; sig = $_.sigStatus; signer = $_.signer; motwHost = $_.motwHost; indicators = @($_.indicators | Select-Object -Unique) } }) `
                -Entities @{ files = @($items | Select-Object -First 30 | ForEach-Object { New-S02FileEntity $_ }) } -FpNotes $tx.F -Recommendation $tx.R -Mitre $tx.M
        }
        Out-S02Items $fileFacts
    })

#endregion

#region ---------- known dropper / worm artifacts ----------

$artifactRows = [System.Collections.Generic.List[object]]::new()
[void](Invoke-BvsCheck -Run $run -Id 'artifacts.droppers' -Description 'Known dropper/worm artifacts in the home folder and %TEMP% (existence and metadata only): Contagious Interview, Shai-Hulud 2.0, s1ngularity' -Script {
        foreach ($a in $ioc.dropperArtifacts) {
            $p = [Environment]::ExpandEnvironmentVariables([string]$a.path)
            $items = @()
            if ($a.glob) { $parentDir = Split-Path -Parent $p; $items = @(Get-BvsFiles -Path $parentDir -MaxDepth 0 -Include (Split-Path -Leaf $p)) }
            elseif (Test-Path -LiteralPath $p) { $items = @(Get-Item -LiteralPath $p -Force) }
            if ($items.Count -eq 0) { $artifactRows.Add([ordered]@{ path = $p; campaign = $a.campaign; family = $a.family; exists = $false }); continue }
            foreach ($it in $items) {
                if (Test-S02Excluded $it.FullName) { continue }
                $isDir = $it -is [IO.DirectoryInfo]
                $row = [ordered]@{ path = $it.FullName; campaign = $a.campaign; family = $a.family; exists = $true; type = if ($isDir) { 'dir' } else { 'file' }; size = if ($isDir) { $null } else { $it.Length }; created = $it.CreationTimeUtc.ToString('o'); modified = $it.LastWriteTimeUtc.ToString('o'); children = $null; markers = @(); mitre = @($a.mitre) }
                if ($isDir) {
                    $kids = @([IO.Directory]::EnumerateFileSystemEntries($it.FullName) | Select-Object -First 50 | ForEach-Object { [IO.Path]::GetFileName($_) })
                    $row.children = $kids
                    foreach ($mk in @($a.markers)) { if ($mk -and (Test-Path -LiteralPath (Join-Path $it.FullName $mk))) { $row.markers += $mk } }
                }
                $artifactRows.Add($row)
            }
        }
        $present = @($artifactRows | Where-Object { $_.exists })
        foreach ($g in ($present | Group-Object { $_.campaign })) {
            $rows = @($g.Group)
            $sev = 'high'; $cls = 'suspicious'; $conf = 'medium'
            if ($g.Name -eq 'contagious_interview' -and @($rows | ForEach-Object { [IO.Path]::GetFileName($_.path) } | Select-Object -Unique).Count -ge 2) { $sev = 'critical'; $cls = 'compromise'; $conf = 'high' }
            if ($g.Name -eq 'shai_hulud' -and @($rows | Where-Object { @($_.markers).Count -gt 0 }).Count -gt 0) { $sev = 'critical'; $cls = 'compromise'; $conf = 'high' }
            $exp = Resolve-S02Expected $rows[0].path 'na'
            Add-S02Finding -Check 'artifacts.droppers' -Title "Known malware artifact present ($($rows[0].family)): $(@($rows | ForEach-Object { $_.path }) -join ', ')" `
                -Severity $sev -Class $cls -Confidence $conf -Reasons @('intel_match', 'hidden') -Evidence @($rows | ForEach-Object { [ordered]@{ type = 'artifact' } + $_ }) `
                -Entities @{ files = @($rows | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $null; size = $_.size; sig = $null; signer = $null; created = $_.created; motw = $null } }) } `
                -FpNotes 'These exact names are used by the listed campaigns; a coincidental tool with the same dot-folder name is possible but rare. Contents were deliberately not read.' `
                -Recommendation 'Treat the machine as possibly compromised: disconnect from the network, do not delete anything yet, and from a clean device rotate passwords, GitHub/npm tokens, SSH keys and crypto wallets. Then collect the files for analysis and run a full offline antivirus scan (for example Microsoft Defender Offline).' `
                -Mitre @($rows | ForEach-Object { $_.mitre }) -Expected $exp
        }
        Out-S02Items $artifactRows
    })

$wormRows = [System.Collections.Generic.List[object]]::new()
[void](Invoke-BvsCheck -Run $run -Id 'artifacts.worm_files' -Description 'Shai-Hulud 2.0 files (setup_bun.js, bun_environment.js, truffleSecrets.json, actionsSecrets.json) outside node_modules in the profile and %TEMP%' -Script {
        $names = @($ioc.workerFileNames | ForEach-Object { $_.name })
        $meta = @{}; foreach ($w in $ioc.workerFileNames) { $meta[$w.name.ToLowerInvariant()] = $w }
        $roots = @($ioc.workerSearch.roots | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } | Where-Object { [IO.Directory]::Exists($_) } | Select-Object -Unique)
        $seen = New-S02Set @()
        foreach ($item in @(Get-BvsFiles -Path $roots -MaxDepth ([int]$ioc.workerSearch.maxDepth) -Include $names)) {
            if (-not $seen.Add($item.FullName) -or (Test-S02Excluded $item.FullName) -or $item.FullName -match '(?i)\\node_modules\\') { continue }
            $w = $meta[$item.Name.ToLowerInvariant()]
            $wormRows.Add([ordered]@{ path = $item.FullName; name = $item.Name; family = $w.family; size = $item.Length; created = $item.CreationTimeUtc.ToString('o'); modified = $item.LastWriteTimeUtc.ToString('o'); mitre = @($w.mitre) })
        }
        foreach ($g in ($wormRows | Group-Object { [IO.Path]::GetDirectoryName($_.path) })) {
            $rows = @($g.Group)
            $hasSecrets = @($rows | Where-Object { $_.name -match '(?i)secrets\.json$' }).Count -gt 0
            $pair = @($rows | Where-Object { $_.name -match '(?i)^(setup_bun|bun_environment)\.js$' }).Count -ge 2
            $sev = if ($hasSecrets -or $pair) { 'critical' } else { 'high' }
            $cls = if ($sev -eq 'critical') { 'compromise' } else { 'suspicious' }
            $exp = Resolve-S02Expected $rows[0].path 'na'
            Add-S02Finding -Check 'artifacts.worm_files' -Title "Shai-Hulud 2.0 file(s) outside node_modules: $(@($rows | ForEach-Object { $_.name }) -join ', ') in $($g.Name)" `
                -Severity $sev -Class $cls -Confidence $(if ($sev -eq 'critical') { 'high' } else { 'medium' }) -Reasons @('intel_match') `
                -Evidence @($rows | ForEach-Object { [ordered]@{ type = 'file' } + $_ }) -Entities @{ files = @($rows | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $null; size = $_.size; sig = $null; signer = $null; created = $_.created; motw = $null } }) } `
                -FpNotes 'Security research folders and IoC test fixtures can contain these names on purpose (security-tool folders can be listed in expected.json).' `
                -Recommendation 'If this is not your own research material: rotate npm, GitHub and cloud tokens from a clean device, check GitHub for unknown repositories/self-hosted runners, and rebuild node_modules from a clean lockfile.' `
                -Mitre @($rows | ForEach-Object { $_.mitre }) -Expected $exp
        }
        Out-S02Items $wormRows
    })

#endregion

#region ---------- download origins ----------

$originInventory = $null
[void](Invoke-BvsCheck -Run $run -Id 'downloads.origins' -Description 'Mark-of-the-Web host domains of executables, scripts, installers and archives in Downloads (any age); unusual sources flagged' -Script {
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $downloadsAll) {
            $ff = $factsByPath[$item.FullName.ToLowerInvariant()]
            if (-not $ff) { $ff = New-S02FileFacts $item 'downloads' 0; Set-S02FileMotw $ff }
            $rows.Add($ff)
        }
        $withMotw = @($rows | Where-Object { $null -ne $_.motwZone })
        $groups = @($rows | Group-Object { if ($_.motwHost) { $_.motwHost.ToLowerInvariant() } elseif ($null -ne $_.motwZone) { '(zone only, no host)' } else { '(no Mark-of-the-Web)' } })
        $top = foreach ($g in ($groups | Sort-Object Count -Descending | Select-Object -First 30)) {
            $cat = if ($g.Name -like '(*') { $null } else { Get-S02HostCategory $g.Name }
            [ordered]@{
                host = $g.Name; category = $cat; files = $g.Count
                executables = @($g.Group | Where-Object { $S.Pe.Contains($_.ext) -or $S.Script.Contains($_.ext) -or $_.ext -in '.msi', '.msp', '.msix', '.msixbundle', '.appx', '.appxbundle', '.jar', '.lnk', '.hta' }).Count
                bytes = [long](($g.Group | Measure-Object -Property size -Sum).Sum)
                newest = ($g.Group | Sort-Object createdUtc -Descending | Select-Object -First 1).created
                zones = @($g.Group | ForEach-Object { $_.motwZone } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
                sample = @($g.Group | Select-Object -First 3 | ForEach-Object { $_.name })
            }
        }
        $flagged = @($rows | Where-Object { $_.motwHostCategory -and $flaggedSources.Contains([string]$_.motwHostCategory) })
        foreach ($g in ($flagged | Group-Object motwHostCategory)) {
            $items = @($g.Group)
            foreach ($ff in $items) { if (-not $ff.sigStatus -and ($S.Signable.Contains($ff.ext))) { Set-S02FileSig $ff } }
            $execNotValid = @($items | Where-Object { ($S.Pe.Contains($_.ext) -or $S.Script.Contains($_.ext) -or $_.ext -in '.msi', '.msp', '.jar', '.lnk', '.hta') -and $_.sigClass -ne 'valid' })
            $sev = if ($execNotValid.Count) { 'high' } else { 'medium' }
            foreach ($ff in $items) { if ($SevRank[$sev] -ge 2 -and -not $ff.sha256 -and -not $ff.cloudOnly -and -not (Test-BvsNeverRead $ff.path)) { $ff.sha256 = Get-BvsHash -Path $ff.path -MaxBytes ($MaxHashMB * 1MB) } }
            Add-S02Finding -Check 'downloads.origins' -Title "$($items.Count) download(s) from unusual source type '$($g.Name)': $(@($items | ForEach-Object { $_.motwHost } | Select-Object -Unique | Select-Object -First 5) -join ', ')" `
                -Severity $sev -Class 'suspicious' -Confidence 'medium' -Reasons @('motw_unknown_host', "source_$($g.Name)") `
                -Evidence @($items | Select-Object -First 25 | ForEach-Object { [ordered]@{ type = 'download'; path = $_.path; created = $_.created; size = $_.size; host = $_.motwHost; hostUrl = $_.motwHostUrl; referrerHost = $_.motwReferrerHost; sig = $_.sigStatus; signer = $_.signer } }) `
                -Entities @{ files = @($items | Select-Object -First 25 | ForEach-Object { New-S02FileEntity $_ }) } `
                -FpNotes 'Legitimate tools are sometimes distributed through file sharers, Discord or raw GitHub links; raw IP addresses and URL shorteners are rarer for genuine software.' `
                -Recommendation 'For each file, confirm the project or person you got it from. Delete unknown executables; for anything you already ran, scan with your antivirus and review S01 persistence.' `
                -Mitre @('T1105', 'T1204.002')
        }
        $script:originInventory = [ordered]@{
            folder = $L.Downloads; files = $rows.Count; withMotw = $withMotw.Count; withoutMotw = $rows.Count - $withMotw.Count
            categories = [ordered]@{}; topHosts = @($top)
        }
        foreach ($g in ($withMotw | Group-Object { if ($_.motwHostCategory) { $_.motwHostCategory } else { 'none' } })) { $script:originInventory.categories[$g.Name] = $g.Count }
        Out-S02Items $rows
    })

#endregion

#region ---------- cross-check with the G0 inventory ----------

$g0Inventory = $null
[void](Invoke-BvsCheck -Run $run -Id 'crosscheck.g0_exec_recent' -Description "G0 inventory\files.tsv 'exec-recent' rows outside this sweep (optional; runs only when G0 has finished)" -Script {
        $tsv = Join-Path $run.ScanDir 'inventory\files.tsv'
        if (-not (Test-Path -LiteralPath $tsv)) {
            Set-BvsCheckStatus -Id 'crosscheck.g0_exec_recent' -Status skipped -Reason 'G0 inventory\files.tsv not available yet (re-run S02 after G0 finishes)'
            $coverageNotes.Add('G0 cross-check skipped: inventory\files.tsv did not exist at run time.')
            return (, @())
        }
        $rows = @(Import-Csv -LiteralPath $tsv -Delimiter "`t" | Where-Object { $_.reason -eq 'exec-recent' })
        $missed = [System.Collections.Generic.List[object]]::new()
        $skippedNm = 0
        foreach ($r in $rows) {
            $p = [string]$r.path
            if (-not $p -or $seenFiles.Contains($p) -or $factsByPath.ContainsKey($p.ToLowerInvariant()) -or (Test-S02Excluded $p)) { continue }
            if ($p -match '(?i)\\node_modules\\') { $skippedNm++; continue }
            if (-not [IO.File]::Exists($p)) { continue }
            $missed.Add($p)
        }
        $eval = [System.Collections.Generic.List[object]]::new()
        $flagRows = [System.Collections.Generic.List[object]]::new()
        $lowRows = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $missed) {
            $item = [IO.FileInfo]::new($p)
            $ff = New-S02FileFacts $item 'g0' 0
            if ($S.Signable.Contains($ff.ext)) { Set-S02FileSig $ff }
            Set-S02FileMotw $ff
            $ff.userWritable = Test-BvsUserWritable ([IO.Path]::GetDirectoryName($p))
            $exp = Resolve-S02Expected $p $ff.sigClass
            $eval.Add([ordered]@{ path = $p; ext = $ff.ext; size = $ff.size; created = $ff.created; sig = $ff.sigStatus; signer = $ff.signer; motwZone = $ff.motwZone; motwHost = $ff.motwHost; location = $ff.location; userWritable = $ff.userWritable; expected = if ($exp -and $exp.applied) { $exp.id } else { $null } })
            if ($exp -and $exp.applied) { continue }
            $isExe = $S.Pe.Contains($ff.ext) -or $ff.ext -in '.msi', '.msp'
            if ($isExe -and $ff.sigClass -in 'unsigned', 'invalid', 'untrusted' -and $ff.userWritable) {
                if (($null -ne $ff.motwZone -and $ff.motwZone -ge 3) -or $ff.location -in $riskyProcLoc -or $ff.location -in $unusualProcLoc) { $flagRows.Add($ff) } else { $lowRows.Add($ff) }
            }
        }
        foreach ($ff in $flagRows) {
            $ff.sha256 = Get-BvsHash -Path $ff.path -MaxBytes ($MaxHashMB * 1MB)
            $ff.severity = 'medium'; $ff.primaryCheck = 'crosscheck.g0_exec_recent'; $ff.reasons.Add('unsigned'); $ff.reasons.Add('user_writable')
            if ($null -ne $ff.motwZone -and $ff.motwZone -ge 3) { $ff.indicators.Add('downloaded') }
            $suspicious.Add($ff)
            Add-S02Finding -Check 'crosscheck.g0_exec_recent' -Title "Unsigned recent executable outside the targeted folders: $($ff.name)" -Severity 'medium' -Class 'suspicious' -Confidence 'low' `
                -Reasons @($ff.reasons) -Evidence (New-S02FileEvidence $ff) -Entities @{ files = @((New-S02FileEntity $ff)) } `
                -FpNotes 'Developer builds, portable tools and package-manager binaries are often unsigned.' `
                -Recommendation 'Confirm you know this program and where it came from; scan it with your antivirus if not.' -Mitre @('T1204.002')
        }
        if ($lowRows.Count) {
            Add-S02Finding -Check 'crosscheck.g0_exec_recent' -Title "$($lowRows.Count) unsigned recent executable(s) elsewhere in user folders (no download mark)" -Severity 'low' -Class 'hygiene' -Confidence 'low' `
                -Reasons @('unsigned', 'user_writable') -Evidence @($lowRows | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'file'; path = $_.path; created = $_.created; sig = $_.sigStatus } }) `
                -FpNotes 'Mostly local builds, virtual-environment launchers and portable tools.' -Recommendation 'Skim the list for names you do not recognise.' -Mitre @('T1204.002')
        }
        $script:g0Inventory = [ordered]@{ execRecentRows = $rows.Count; missedBySweep = $missed.Count; skippedNodeModules = $skippedNm; flagged = $flagRows.Count; lowUnsigned = $lowRows.Count; items = @($eval | Select-Object -First 300) }
        Out-S02Items $eval
    })

#endregion

#region ---------- inventory and envelope ----------

foreach ($chk in @($script:Overflow.Keys)) {
    $items = $script:Overflow[$chk]
    New-BvsFinding -Run $run -Check $chk -Title "$($items.Count) more '$chk' finding(s) not listed individually (cap $MaxFindingsPerCheck per check)" `
        -Severity (Get-S02MaxSev @($items | ForEach-Object { $_.severity })) -Class 'suspicious' -Confidence 'low' -Reasons @('overflow') `
        -Evidence @($items | Select-Object -First 100) -FpNotes 'Summary of additional findings beyond the per-check cap; see inventory tables for details.' `
        -Recommendation 'Review the listed titles; re-run with -MaxFindingsPerCheck to expand them.' -Mitre @()
}

$procInv = [System.Collections.Generic.List[object]]::new()
foreach ($p in $procs) {
    $f = if ($p.Path) { Get-S02PathFacts $p.Path } else { $null }
    $flagged = $procFlags.ContainsKey([int]$p.Pid)
    if (-not $flagged -and -not ($f -and ($f.SigClass -ne 'valid' -or $f.UserWritable))) { continue }
    $par = Get-S02Parent $p
    $motw = if ($f -and $f.Exists -and $f.UserWritable -and $f.SigClass -ne 'valid') { Get-BvsMotw $p.Path } else { $null }
    $procInv.Add([ordered]@{
            pid = [int]$p.Pid; ppid = [int]$p.ParentPid; parentName = if ($par) { $par.Name } else { $null }
            name = $p.Name; path = $p.Path; pathSource = $p.PathSource
            sig = if ($f) { $f.SigStatus } else { 'unknown' }; signer = if ($f) { $f.Signer } else { $null }
            company = if ($f -and $f.Version) { $f.Version.CompanyName } else { $null }
            userWritable = if ($f) { $f.UserWritable } else { $null }; location = if ($f) { $f.Location } else { $null }
            imageExists = if ($f) { $f.Exists } else { $null }
            motwZone = if ($motw) { $motw.ZoneId } else { $null }; motwHost = if ($motw) { $motw.HostDomain } else { $null }
            started = ConvertTo-S02Iso $p.Started
            expected = if ($f -and $f.Expected -and $f.Expected.applied) { $f.Expected.id } else { $null }
            ownActivity = $ownPids.Contains([int]$p.Pid)
            flags = @(if ($flagged) { $procFlags[[int]$p.Pid] })
            commandLine = Get-S02Short $p.CommandLine 300
        })
}

$facts = @($script:PathFacts.Values)
Add-BvsInventory -Run $run -Name 'processSummary' -Data ([ordered]@{
        total = $procs.Count; withPath = $procWithPath.Count
        pathFromService = @($procs | Where-Object PathSource -eq 'service').Count
        pathFromNtQuery = @($procs | Where-Object PathSource -eq 'ntquery').Count
        pathUnavailable = @($procs | Where-Object { -not $_.Path -and -not $S.Pseudo.Contains([string]$_.Name) -and [int]$_.Pid -gt 4 }).Count
        uniqueImages = $facts.Count
        unsignedImages = @($facts | Where-Object SigClass -eq 'unsigned').Count
        invalidOrUntrustedImages = @($facts | Where-Object { $_.SigClass -in 'invalid', 'untrusted' }).Count
        userWritableImages = @($facts | Where-Object UserWritable).Count
        ownActivityPids = $ownPids.Count; ownActivityRootPid = $ownRootPid; ownActivityCommandLineHits = $ownCmdHits
        elevated = $run.Elevated
    })
Add-BvsInventory -Run $run -Name 'processInventory' -Data @($procInv)
Add-BvsInventory -Run $run -Name 'topCpu' -Data @($script:topCpu)
Add-BvsInventory -Run $run -Name 'cpuSampling' -Data $script:cpuMeta
Add-BvsInventory -Run $run -Name 'nativeMessagingHosts' -Data @($nativeHosts)
Add-BvsInventory -Run $run -Name 'sweepStats' -Data @($sweepStats)

$recentRows = @($fileFacts | Select-Object -First 3000 | ForEach-Object {
        [ordered]@{ path = $_.path; ext = $_.ext; size = $_.size; created = $_.created; modified = $_.modified; location = $_.location; sig = $_.sigStatus; signer = $_.signer; motwZone = $_.motwZone; motwHost = $_.motwHost; header = $_.magic; severity = $_.severity; indicators = @($_.indicators | Select-Object -Unique) }
    })
Add-BvsInventory -Run $run -Name 'recentRiskyFiles' -Data ([ordered]@{ total = $fileFacts.Count; truncated = ($fileFacts.Count -gt 3000); rows = $recentRows })

$susRows = @($suspicious | Sort-Object { $SevRank[$_.severity] } -Descending | ForEach-Object {
        [ordered]@{
            path = $_.path; reasons = @(@($_.reasons) + @($_.indicators) | Where-Object { $_ } | Select-Object -Unique); signer = $_.signer; sig = $_.sigStatus
            motwHost = $_.motwHost; motwZone = $_.motwZone; sha256 = $_.sha256; created = $_.created; modified = $_.modified; size = $_.size
            severity = $_.severity; check = $_.primaryCheck; location = $_.location; expected = if ($_.expected -and $_.expected.applied) { $_.expected.id } else { $null }
        }
    })
Add-BvsInventory -Run $run -Name 'suspiciousFiles' -Data $susRows
Add-BvsInventory -Run $run -Name 'sideloadCandidates' -Data @($sideloadRows)
Add-BvsInventory -Run $run -Name 'downloadOrigins' -Data $script:originInventory
Add-BvsInventory -Run $run -Name 'dropperArtifacts' -Data @($artifactRows)
Add-BvsInventory -Run $run -Name 'wormFiles' -Data @($wormRows)
Add-BvsInventory -Run $run -Name 'g0CrossCheck' -Data $script:g0Inventory
Add-BvsInventory -Run $run -Name 'coverageNotes' -Data @($coverageNotes)
Add-BvsInventory -Run $run -Name 'parameters' -Data ([ordered]@{ recentDays = $RecentDays; cpuSampleSeconds = $CpuSampleSeconds; cpuThresholdPct = $CpuThresholdPct; maxHashMB = $MaxHashMB; maxFindingsPerCheck = $MaxFindingsPerCheck; iocFile = 'S02-iocs.json'; iocUpdated = $ioc.updated })

$summary = Complete-BvsRun -Run $run

# Console summary (masked, short).
"S02 finished in {0:n0} s -> {1}" -f $clock.Elapsed.TotalSeconds, $summary.Path
"findings: {0} [{1}]  checks: {2}  errors: {3}" -f $summary.Findings, $summary.BySeverity, $summary.Checks, $summary.Errors
$notOk = @($run.Checks | Where-Object { $_.status -ne 'ok' })
if ($notOk.Count) { 'checks not ok: ' + (($notOk | ForEach-Object { "$($_.id)=$($_.status)" }) -join ', ') }
foreach ($f in ($run.Findings | Sort-Object { $SevRank[$_.severity] } -Descending | Select-Object -First 15)) {
    '  [{0}] {1}' -f $f.severity, (Get-S02Short $f.title 150)
}

#endregion
