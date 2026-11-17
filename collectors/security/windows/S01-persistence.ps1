#Requires -Version 7.2
<#
.SYNOPSIS
    S01 Persistence & autostarts - read-only Windows collector for baby-virus-scanner.
.DESCRIPTION
    Enumerates autostart and execution-hijack points (Run keys + StartupApproved, Startup folders, Winlogon and
    logon hooks, Active Setup, BootExecute, AppInit/AppCert, LSA/SSP/network/credential providers, print monitors,
    NetSh helpers, time providers, IFEO/SilentProcessExit, UAC-bypass and file-association keys, accessibility
    binaries, HKCU COM hijacks, shell extensions, services, drivers + LOLDrivers (compared locally), scheduled tasks,
    WMI subscriptions, BITS jobs, environment hijacks, PowerShell/Git Bash/Terminal startup files and Claude Code
    shell snapshots). Every target is rated by signer, user-writable folder, recent change, LOLBin/URL/encoded
    arguments and masquerading. Generic lists live in S01-persistence-iocs.json; machine-specific known-good items
    come from config\local\expected.json. Writes only data\<scan>\security\S01.json (Complete-BvsRun), logs\S01.log
    and the LOLDrivers cache under intel\ (Invoke-BvsIntel). Playbook: docs\playbooks\S01-persistence.md
.PARAMETER NoIntel           Offline: do not download the LOLDrivers list (a cached copy under intel\ is still used).
.PARAMETER IntelMaxAgeHours  Reuse a cached LOLDrivers list younger than this (default 24).
.PARAMETER RecentDays        "Service changed recently" window (default 90).
.PARAMETER NewDays           "Created recently" window used for compromise corroboration (default 30).
#>
[CmdletBinding()]
param([switch]$NoIntel, [int]$IntelMaxAgeHours = 24, [int]$RecentDays = 90, [int]$NewDays = 30)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S01 -Area security
$ioc = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S01-persistence-iocs.json') -Raw | ConvertFrom-Json
$Now = [datetime]::UtcNow; $NewCut = $Now.AddDays(-$NewDays); $RecentCut = $Now.AddDays(-$RecentDays); $Timer = [Diagnostics.Stopwatch]::StartNew()
$SysRoot = $env:SystemRoot.TrimEnd('\'); $Sys32 = "$SysRoot\System32"; $SysWow = "$SysRoot\SysWOW64"
$Rank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }; $SevName = 'info', 'low', 'medium', 'high', 'critical'
$ClsRank = @{ info = 0; hygiene = 1; hardening = 2; suspicious = 3; compromise = 4 }
$Entries = [System.Collections.Generic.List[object]]::new(); $Facts = @{}; $Agg = [ordered]@{}; $script:DriverRows = @()
$Denied = [System.Collections.Generic.HashSet[string]]::new(); $Running = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$Rx = @{}; foreach ($r in $ioc.contentRules) { $Rx[$r.id] = [regex]::new($r.rx, 'IgnoreCase, CultureInvariant, Multiline', [TimeSpan]::FromSeconds(2)) }

#region ---------- generic helpers ----------
function Get-S01Vals([string]$p, [string]$v = '64') { try { @(Get-BvsRegValues -Path $p -View $v) } catch { [void]$Denied.Add($p); @() } }
function Get-S01Subs([string]$p, [string]$v = '64') { try { @(Get-BvsRegSubKeys -Path $p -View $v) } catch { [void]$Denied.Add($p); @() } }
function Get-S01Lw([string]$p, [string]$v = '64') { try { Get-BvsRegKeyLastWrite -Path $p -View $v } catch { [void]$Denied.Add($p); $null } }
function ConvertTo-S01Str($x) { if ($null -eq $x -or $x -is [byte[]]) { $null } elseif ($x -is [string]) { $x } elseif ($x -is [array]) { (@($x) | Where-Object { $_ }) -join ' ' } else { [string]$x } }
function Get-S01Val([string]$p, [string]$n, [string]$v = '64') { $x = Get-S01Vals $p $v | Where-Object Name -eq $n | Select-Object -First 1; if ($x) { ConvertTo-S01Str $x.Value } }
function Get-S01Phys([string]$p, [string]$v) {
    if ($v -eq '32' -and $p -match '^(?i)HKLM\\SOFTWARE\\(?!WOW6432Node)(.*)$') { return "HKLM\SOFTWARE\WOW6432Node\$($Matches[1])" }
    if ($v -eq '32' -and $p -match '^(?i)HKCU\\Software\\Classes\\(CLSID.*)$') { return "HKCU\Software\Classes\WOW6432Node\$($Matches[1])" }
    $p
}
function ConvertTo-S01Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } }
function Limit-S01([string]$t, [int]$n = 300) { if ($null -eq $t) { return $null }; $t = $t -replace '[\r\n]+', ' '; if ($t.Length -gt $n) { $t.Substring(0, $n) + '...' } else { $t } }
function Get-S01Norm([string]$p) { if ($p) { $p.TrimEnd('\').ToLowerInvariant() + '\' } }
$dl = Get-S01Val 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}'
$SuspDirs = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$SysRoot\Temp", $(if ($dl) { [Environment]::ExpandEnvironmentVariables($dl) } else { "$env:USERPROFILE\Downloads" }), [Environment]::GetFolderPath('Desktop'), $env:PUBLIC, "$env:SystemDrive\PerfLogs", "$SysRoot\Tasks", "$SysRoot\Tracing", "$SysRoot\debug", "$Sys32\Tasks", "$Sys32\spool\drivers\color", "$SysRoot\Fonts", "$env:LOCALAPPDATA\Microsoft\Windows\INetCache", "$env:SystemDrive\`$Recycle.Bin") | Where-Object { $_ } | ForEach-Object { Get-S01Norm $_ } | Select-Object -Unique
$RootDirs = @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:USERPROFILE, (Split-Path $env:USERPROFILE), "$env:SystemDrive\") | ForEach-Object { Get-S01Norm $_ }
$PfDirs = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { Get-S01Norm $_ }
function Get-S01FolderClass([string]$p) {
    if ($p -notmatch '^[A-Za-z]:\\') { return $(if ($p -match '^\\\\') { 'network' } else { 'unknown' }) }
    $l = $p.ToLowerInvariant()
    foreach ($d in $SuspDirs) { if ($l.StartsWith($d)) { return 'suspicious' } }
    if ((Get-S01Norm ([IO.Path]::GetDirectoryName($l))) -in $RootDirs) { return 'suspicious' }
    if ($l.StartsWith((Get-S01Norm "$env:ProgramFiles\WindowsApps"))) { return 'store-app' }
    if ($l.StartsWith((Get-S01Norm $SysRoot))) { return 'windows' }
    foreach ($d in $PfDirs) { if ($l.StartsWith($d)) { return 'programfiles' } }
    if ($l.StartsWith((Get-S01Norm $env:ProgramData))) { return 'programdata' }
    if ($l.StartsWith((Get-S01Norm $env:LOCALAPPDATA)) -or $l.StartsWith((Get-S01Norm $env:APPDATA))) { return 'user-appdata' }
    if ($l.StartsWith((Get-S01Norm $env:USERPROFILE))) { return 'user-profile' }
    'other'
}
function Resolve-S01Path([string]$p, [string]$ext = '.dll', [string]$v = '64', [string[]]$dirs = @()) {
    # Registry/driver/bare-name path -> full Win32 path, searched the way Windows loads it. Never executes anything.
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    $x = [Environment]::ExpandEnvironmentVariables($p.Trim()).Trim().Trim('"').Trim() -replace '^\\\?\?\\', '' -replace '^\\\\\?\\', ''
    if ($x -match '^(?i)\\SystemRoot\\(.+)') { $x = "$SysRoot\$($Matches[1])" } elseif ($x -match '^(?i)(system32|syswow64)\\') { $x = "$SysRoot\$x" }
    if ($x -match '^(?i)file:///?(.+)$') { $x = [uri]::UnescapeDataString($Matches[1]) -replace '/', '\' }
    if ($x -notmatch '^[A-Za-z]:\\|^\\\\') {
        if ($x -match '[\\/:]') { return $x }
        $leaf = if ([IO.Path]::HasExtension($x)) { $x } else { $x + $ext }; $sd = if ($v -eq '32') { $SysWow } else { $Sys32 }
        foreach ($d in @($dirs) + @($sd, $SysRoot)) { if ($d -and [IO.File]::Exists("$d\$leaf")) { return "$d\$leaf" } }
        $c = try { Get-Command $leaf -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { $null }
        if ($c) { return $c.Source }; return "$sd\$leaf"
    }
    if ($v -eq '32' -and $x.StartsWith("$Sys32\", 'OrdinalIgnoreCase')) { $x = $SysWow + $x.Substring($Sys32.Length) }
    $x
}
function Get-S01Facts([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    $k = $p.ToLowerInvariant(); if ($Facts.ContainsKey($k)) { return $Facts[$k] }
    $o = [ordered]@{ path = $p; resolved = ($p -match '^[A-Za-z]:\\|^\\\\'); exists = $false; isDir = $false; size = $null; created = $null; modified = $null; ext = ''; isPe = $false; isScript = $false
        sigStatus = $null; signer = $null; microsoft = $false; company = $null; originalFilename = $null; writable = $null; folderClass = 'unknown'; cloudOnly = $false; motwZone = $null; disguisedPe = $false; sha256 = $null }
    try { $o.ext = [IO.Path]::GetExtension($p).ToLowerInvariant() } catch { }
    $o.isPe = $o.ext -in $ioc.peExt; $o.isScript = $o.ext -in $ioc.scriptExt
    if ($o.resolved) {
        try {
            $fi = [IO.FileInfo]::new($p)
            if ($fi.Exists) { $o.exists = $true; $o.size = $fi.Length; $o.created = $fi.CreationTimeUtc; $o.modified = $fi.LastWriteTimeUtc; $o.cloudOnly = [bool](Test-BvsCloudOnly $fi) }
            elseif ([IO.Directory]::Exists($p)) { $o.exists = $true; $o.isDir = $true }
        } catch { }
        $o.folderClass = Get-S01FolderClass $p
        $parent = try { [IO.Path]::GetDirectoryName($p) } catch { $null }
        $o.writable = [bool]((Test-BvsUserWritable -Path $p) -or ($parent -and (Test-BvsUserWritable -Path $parent)))
        if ($o.exists -and -not $o.isDir -and -not $o.cloudOnly) {
            $s = Get-BvsSignature -Path $p; $o.sigStatus = $s.Status; $o.signer = $s.Signer
            $o.microsoft = $s.Status -eq 'Valid' -and "$($s.Signer)" -match '^Microsoft\b' -and "$($s.Signer)" -notmatch 'Hardware Compatibility|3rd Party|Third Party'
            $vi = Get-BvsVersionInfo -Path $p; if ($vi) { $o.company = $vi.CompanyName; $o.originalFilename = $vi.OriginalFilename }
            if (-not $o.isPe -and $o.ext -ne '.lnk') { $m = Get-BvsMagic -Path $p; if ($m -and $m.Type -eq 'pe') { $o.isPe = $true; $o.disguisedPe = $o.ext -in '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', '.csv', '.log', '.ini', '.xml', '.json', '.html' } }
            $mw = Get-BvsMotw -Path $p; if ($mw) { $o.motwZone = $mw.ZoneId }
        }
    }
    $f = [pscustomobject]$o; $Facts[$k] = $f; $f
}
function Get-S01Sig($f) { if (-not $f) { 'none' } elseif (-not $f.exists) { 'missing' } elseif ($f.isDir) { 'dir' } elseif ($f.cloudOnly) { 'cloud' } else { switch ($f.sigStatus) { 'Valid' { 'valid' } 'NotSigned' { 'unsigned' } 'HashMismatch' { 'invalid' } 'NotSupportedFileFormat' { 'n/a' } 'Error' { 'unreadable' } default { 'untrusted' } } } }
function Test-S01Vendor([string]$a, [string]$b) {
    # True when two publisher strings name the same vendor (token overlap or a known rebrand group).
    if (-not $a -or -not $b) { return $null }
    $la = $a.ToLowerInvariant(); $lb = $b.ToLowerInvariant()
    foreach ($g in $ioc.vendorAliases) { if (@($g | Where-Object { $la.Contains($_) }).Count -and @($g | Where-Object { $lb.Contains($_) }).Count) { return $true } }
    $ta = @([regex]::Matches($la, '[a-z0-9]{3,}').Value | Where-Object { $_ -notin $ioc.vendorStop }); $tb = @([regex]::Matches($lb, '[a-z0-9]{3,}').Value | Where-Object { $_ -notin $ioc.vendorStop })
    [bool](@($ta | Where-Object { $_ -in $tb }).Count)
}
function Test-S01SignerOk([string]$vendor, $f) { [bool]($f -and ((Test-S01Vendor $vendor "$($f.signer)") -or ("$($f.signer)" -match 'Hardware Compatibility Publisher' -and (Test-S01Vendor $vendor "$($f.company)")))) }  # WHQL-signed vendor binaries
function Get-S01Brand([string]$n) { if ($n) { foreach ($r in $ioc.brandRules) { if ($n -match $r.rx) { return $r.vendor } } } }
function Test-S01Random([string]$n) {
    if (-not $n) { return $false }
    $t = @(($n -replace '(?i)S-1-5-21(-\d+){3,4}|\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?|\d+(\.\d+){1,3}|\.(exe|dll|lnk|bat|cmd|ps1|vbs|js)$', ' ') -split '[\s_\-.,()\[\]{}\\]+' | Where-Object { $_ })
    $words = 0; $rand = 0; $hex = 0
    foreach ($x in $t) {
        if ($x -match '^[0-9A-Fa-f]{16,}$') { $hex++; continue }
        $letters = $x -replace '[^A-Za-z]'; $vow = ($letters -replace '[^AEIOUYaeiouy]').Length; $tr = 0
        for ($i = 1; $i -lt $x.Length; $i++) { if ([char]::IsDigit($x[$i]) -ne [char]::IsDigit($x[$i - 1]) -or [char]::IsUpper($x[$i]) -ne [char]::IsUpper($x[$i - 1])) { $tr++ } }
        if ($x.Length -ge 6 -and (($letters.Length -ge 6 -and $vow / $letters.Length -lt 0.12) -or ($x.Length -ge 8 -and $x -match '\d.*\d' -and $tr / $x.Length -gt 0.45))) { $rand++ } else { $words++ }
    }
    ($rand -gt 0 -and $words -eq 0) -or ($hex -gt 0 -and $words -eq 0)
}
function Resolve-S01Cmd([string]$cmd, [string]$v = '64') {
    if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
    $r = try { Resolve-BvsCommandLine $cmd } catch { $null }
    if (-not $r) { return [pscustomobject]@{ Executable = $null; Target = $null; Kind = 'unparsed'; DecodedCommand = $null } }
    [pscustomobject]@{ Executable = $(if ($r.Executable) { Resolve-S01Path $r.Executable '.exe' $v }); Target = $(if ($r.Target) { Resolve-S01Path $r.Target $(if ($r.Kind -like 'dll-*') { '.dll' } else { '.exe' }) $v }); Kind = $r.Kind; DecodedCommand = $r.DecodedCommand }
}
function New-S01Res([string]$target, [string]$kind) { [pscustomobject]@{ Executable = $null; Target = $target; Kind = $kind; DecodedCommand = $null } }
function Get-S01Ind([string]$cmd, $res) {
    # Command-line indicators: LOLBin class, URL, encoded/obfuscated payload, download+execute, script: protocols.
    $i = [ordered]@{ lolbin = $null; lolClass = $null; url = $false; encoded = $false; decoded = $null; obf = $false; hidden = $false; cradle = $false; exec = $false; benignUrl = $false; proto = $false; cred = $false; dropExec = $false }
    if ([string]::IsNullOrWhiteSpace($cmd)) { return [pscustomobject]$i }
    $leaf = if ($res -and $res.Executable) { [IO.Path]::GetFileNameWithoutExtension($res.Executable).ToLowerInvariant() } else { '' }
    foreach ($c in 'exec', 'download', 'shell') { if ($leaf -in $ioc.lolbins.$c) { $i.lolbin = $leaf; $i.lolClass = $c } }
    $all = $cmd; if ($res -and $res.DecodedCommand) { $i.encoded = $true; $i.decoded = Limit-S01 $res.DecodedCommand 300; $all += ' ' + $res.DecodedCommand }
    $i.url = $all -match '(?i)\b(https?|ftps?)://|\\\\\d{1,3}(\.\d{1,3}){3}\\|@ssl\\'
    if ($all -match '(?i)FromBase64String|base64\s+(-d|--decode)|certutil.{0,40}-decode') { $i.encoded = $true }
    $i.obf = ($all -match '[A-Za-z0-9+/]{120,}={0,2}') -or (($all -split '\^').Count -gt 5) -or ($all.Length -gt 1024 -and $all -match '\s{100,}')
    $i.hidden = $all -match '(?i)(^|\s)-w(indowstyle)?\s+(hidden|1)\b'
    $i.cradle = $Rx.download_cradle.IsMatch($all) -or $all -match '(?i)\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b'
    $i.exec = $all -match '(?i)\bIEX\b|Invoke-Expression|ScriptBlock\]::Create|Assembly\]::Load|\|\s*(ba)?sh\b'
    $i.proto = $all -match '(?i)\b(javascript|vbscript):'
    $i.cred = $all -match '(?i)comsvcs(\.dll)?.{0,40}minidump|sekurlsa|mimikatz'
    $i.benignUrl = ($all -match $ioc.urlOpenRegex) -or ($leaf -eq 'explorer' -and -not $i.cradle) -or ($leaf -eq 'cmd' -and $all -match '(?i)\bstart\s' -and -not $i.cradle)
    $i.dropExec = $all -match '(?i)(-o|--output|-OutFile|>)\s*["'']?[^\s"'']+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi)\b'
    [pscustomobject]$i
}
function Read-S01Text([string]$p, [int]$max = 1MB) {
    if (-not $p -or -not [IO.File]::Exists($p) -or (Test-BvsNeverRead $p)) { return $null }
    $fi = [IO.FileInfo]::new($p); if ((Test-BvsCloudOnly $fi) -or $fi.Length -gt $max) { return $null }
    try { [IO.File]::ReadAllText($p) } catch { $null }
}
function Get-S01TextHits([string]$text) {
    # Content rules (sidecar) per line; comment lines are skipped except for prompt-injection. Output is masked.
    if ([string]::IsNullOrEmpty($text)) { return }
    $lines = $text -split '\r?\n'
    foreach ($r in $ioc.contentRules) {
        $n = 0
        for ($li = 0; $li -lt $lines.Count -and $n -lt 3; $li++) {
            $ln = $lines[$li]; if (-not $r.inComments -and $ln -match '^\s*(#|//|::|rem\s|'')') { continue }
            $m = $false; try { $m = $Rx[$r.id].IsMatch($ln) } catch { }
            if ($m) { $n++; [pscustomobject]@{ rule = $r.id; sev = $r.sev; cls = $r.cls; reason = $r.reason; line = $li + 1; text = (Limit-S01 (Protect-BvsText $ln.Trim()) 160) } }
        }
    }
}
function Get-S01Top($hits) { $t = $null; foreach ($h in @($hits)) { if ($h -and (-not $t -or $Rank[$h.sev] -gt $Rank[$t.sev] -or ($Rank[$h.sev] -eq $Rank[$t.sev] -and $ClsRank[$h.cls] -gt $ClsRank[$t.cls]))) { $t = $h } }; $t }
function Test-S01Pattern($pats, [string[]]$names) { foreach ($pat in @($pats)) { if (-not $pat) { continue }; $w = [System.Management.Automation.WildcardPattern]::new([string]$pat, 'IgnoreCase'); foreach ($n in $names) { if ($n -and $w.IsMatch($n)) { return $n } } } }
function Find-S01Expected([string[]]$cats, [string[]]$names, $f, [string]$brand) {
    # Match config\local\expected.json; evaluate the machine-checkable invalidIf conditions against the target facts.
    foreach ($cat in $cats) { foreach ($it in @(Get-BvsExpected -Category $cat)) {
        $m = $it.match; $hit = Test-S01Pattern (@($m.names) + @($m.service) + @($m.process)) $names
        if (-not $hit -and $m.displayNameRegex) { $hit = $names | Where-Object { $_ -and $_ -match $m.displayNameRegex } | Select-Object -First 1 }
        if (-not $hit) { continue }
        $holds = [System.Collections.Generic.List[string]]::new(); $sig = Get-S01Sig $f
        foreach ($c in @($it.invalidIf)) {
            if ("$c" -match '(?i)not signed by\s+(\S+)') { if (-not ($f -and $f.signer -and (Test-S01Vendor $Matches[1] $f.signer))) { $holds.Add($c) } }
            elseif ("$c" -match '(?i)unsigned|unexpected signer') { if (-not $f -or ($f.isPe -and $sig -ne 'valid') -or ($f.company -and $f.signer -and -not (Test-S01SignerOk $f.company $f)) -or ($brand -and $f.signer -and -not (Test-S01SignerOk $brand $f))) { $holds.Add($c) } }
            elseif ("$c" -match '(?i)unexpected folder') { if ($f -and ($f.folderClass -in 'suspicious', 'network' -or ($f.folderClass -in 'other', 'user-profile', 'unknown' -and $f.writable))) { $holds.Add($c) } }
        }
        return [pscustomobject][ordered]@{ id = $it.id; category = $cat; matched = $hit; reason = $it.reason; invalidIf = @($it.invalidIf); invalidated = $holds.Count -gt 0; invalidReasons = @($holds); severityCap = $(if ($it.severityCap) { $it.severityCap } else { 'info' }) }
    } }
}
function Add-S01Entry([string]$cat, [string]$loc, [string]$name, [string]$cmd, $f, [string]$kind, $lw, $enabled = $true, [string]$scope = 'user', [string]$runAs, $exp, [hashtable]$extra) {
    $e = [ordered]@{ id = ('as-{0:00000}' -f ($Entries.Count + 1)); category = $cat; location = $loc; name = $name; command = (Limit-S01 $cmd 500); target = $f.path; targetKind = $kind
        exists = $f.exists; signer = $f.signer; sigStatus = $f.sigStatus; microsoft = [bool]$f.microsoft; company = $f.company; userWritable = $f.writable; folderClass = $f.folderClass
        lastWrite = (ConvertTo-S01Iso $lw); fileCreated = (ConvertTo-S01Iso $f.created); enabled = $enabled; scope = $scope; runAs = $runAs; running = [bool]($f.path -and $Running.Contains($f.path))
        expected = $exp.id; expectedInvalidated = $exp.invalidated; severity = 'none'; findingIds = [System.Collections.Generic.List[string]]::new() }
    if ($extra) { foreach ($k in $extra.Keys) { $e[$k] = $extra[$k] } }
    $o = [pscustomobject]$e; $Entries.Add($o); $o
}
function Add-S01Finding([string]$check, [string]$title, [string]$sev, [string]$cls, [string]$conf, [string[]]$reasons, [object[]]$ev, [object[]]$files, [string[]]$mitre, [string]$fp, [string]$rec, $exp, [object[]]$ents) {
    $fe = @(foreach ($f in @($files)) { if ($f -and $f.path) {
        if ($f.exists -and -not $f.isDir -and -not $f.cloudOnly -and -not $f.sha256 -and $f.size -lt 200MB) { $f.sha256 = Get-BvsHash -Path $f.path }
        [ordered]@{ path = $f.path; sha256 = $f.sha256; size = $f.size; sig = $f.sigStatus; signer = $f.signer; created = (ConvertTo-S01Iso $f.created); company = $f.company; userWritable = $f.writable; motw = $(if ($f.motwZone) { @{ zone = $f.motwZone } }) } } })
    if (-not $fp) { $fp = $ioc.defaultFp.$cls }; if (-not $rec) { $rec = $ioc.defaultRec.$cls }; if (-not $conf) { $conf = 'medium' }
    $fd = New-BvsFinding -Run $run -Check $check -Title $title -Severity $sev -Class $cls -Confidence $conf -Reasons @($reasons | Where-Object { $_ } | Select-Object -Unique) -Evidence @($ev | Where-Object { $_ }) `
        -Entities ([ordered]@{ files = $fe; processes = @(); network = @(); registry = @($ev | Where-Object { $_ -and $_.type -eq 'registry' }); accounts = @() }) -Recommendation $rec -FpNotes $fp -Mitre @($mitre) -Expected $exp -PassThru
    foreach ($e in @($ents)) { if ($e) { $e.findingIds.Add($fd.id); if (-not $Rank.ContainsKey($e.severity) -or $Rank[$sev] -gt $Rank[$e.severity]) { $e.severity = $sev } } }
    $fd.id
}
function Add-S01Agg([string]$key, [string]$check, [string]$title, [string]$sev, [string]$cls, [string[]]$mitre, $item, $entry) {
    if (-not $Agg.Contains($key)) { $Agg[$key] = [pscustomobject]@{ check = $check; title = $title; sev = $sev; cls = $cls; mitre = $mitre; items = [System.Collections.Generic.List[object]]::new(); ents = [System.Collections.Generic.List[object]]::new() } }
    $Agg[$key].items.Add($item); if ($entry) { $Agg[$key].ents.Add($entry) }
}
function Close-S01Agg { foreach ($k in @($Agg.Keys)) { $a = $Agg[$k]; [void](Add-S01Finding $a.check "$($a.title) [$($a.check -replace '^persistence\.')] ($($a.items.Count))" $a.sev $a.cls 'high' @('missing_target') @($a.items | Select-Object -First 50) @() $a.mitre $null $null $null @($a.ents)) }; $Agg.Clear() }
$ItemErrs = [System.Collections.Generic.List[string]]::new()
function Add-S01ItemErr([string]$check, [string]$item, $err) { $ItemErrs.Add($check); $run.Errors.Add([ordered]@{ check = $check; error = (Protect-BvsText (Limit-S01 "$item : $($err.Exception.Message)" 300)); at = [datetime]::UtcNow.ToString('o') }) }
function Get-S01RegEv([string]$path, [string]$name, $value, $lw) { [ordered]@{ type = 'registry'; path = $path; name = $name; value = (Limit-S01 (ConvertTo-S01Str $value) 400); lastWrite = (ConvertTo-S01Iso $lw) } }
#endregion

#region ---------- rating engine ----------
function Measure-S01 {
    # Rates one autostart target and emits at most one calibrated finding. Order: compromise indicators > unsigned in
    # user-writable folder > tampered signature > suspicious content > hardening (privileged + writable/missing) > floor.
    param($E, [string]$check, [string]$what, [string]$cmd, $res, $f, [string]$priv = 'user', [bool]$auto = $true, $enabled = $true, $changed, $exp,
        [string[]]$extra = @(), [object[]]$ev = @(), [string[]]$mitre = @(), [string]$brand, [hashtable]$floor, [string]$cap = 'critical', [string]$unsignedSev = 'medium', [string]$fp, [string]$rec)
    $R = [System.Collections.Generic.List[string]]::new(); $R.Add('persistence'); foreach ($x in $extra) { if ($x) { $R.Add($x) } }
    $ind = Get-S01Ind $cmd $res; $sig = Get-S01Sig $f; $isPe = $f -and $f.isPe; $w = [bool]($f -and $f.writable)
    $notValid = $isPe -and $sig -in 'unsigned', 'invalid', 'untrusted'
    $recent = ($changed -and $changed -gt $NewCut) -or ($f -and $f.created -and $f.created -gt $NewCut)
    $isScript = $f -and $f.exists -and $f.isScript
    $hits = @(Get-S01TextHits $cmd) + @(if ($isScript) { Get-S01TextHits (Read-S01Text $f.path) }); $top = Get-S01Top $hits
    if ($isPe -and $sig -eq 'unsigned') { $R.Add('unsigned') } elseif ($isPe -and $sig -eq 'invalid') { $R.Add('invalid_signature') } elseif ($notValid) { $R.Add('untrusted_signature') }
    if ($w) { $R.Add('user_writable') }; if ($recent) { $R.Add('created_lt_30d') }; if ($f -and $f.folderClass -eq 'suspicious') { $R.Add('suspicious_location') }; if ($f -and $f.motwZone -ge 3) { $R.Add('motw_internet') }
    foreach ($p in @(@('lolbin', $ind.lolbin), @('encoded_command', $ind.encoded), @('obfuscation', $ind.obf), @('hidden_window', $ind.hidden), @('url_in_command', $ind.url))) { if ($p[1]) { $R.Add($p[0]) } }
    foreach ($h in $hits) { $R.Add($h.reason) }
    $masq = $null
    if ($f -and $f.exists -and -not $f.microsoft) {
        $leaf = [IO.Path]::GetFileName($f.path).ToLowerInvariant()
        if ($leaf -in $ioc.systemBinaryNames -and $f.folderClass -ne 'windows') { $masq = "Windows binary name '$leaf' outside the Windows folder" }
        elseif ($leaf -match '\.(pdf|docx?|xlsx?|txt|jpe?g|png|mp4|zip)\.(exe|scr|com|pif|bat|cmd|vbs|js)$') { $masq = 'double file extension' }
        elseif ($f.disguisedPe) { $masq = 'executable hidden behind a non-executable extension' }
        elseif ($notValid -and $w -and "$($f.company)" -match '^Microsoft') { $masq = 'claims Microsoft in its version info but is not Microsoft-signed' }
        elseif ($brand -and $isPe -and -not (Test-S01SignerOk $brand $f)) { if ($notValid -and ($w -or $f.folderClass -eq 'suspicious')) { $masq = "name suggests $brand but the binary is not signed by $brand" } elseif ($sig -eq 'valid') { $R.Add('signer_mismatch') } }
    }
    if ($masq) { $R.Add('masquerading') }
    if ((Test-S01Random $E.name) -or ($f -and (Test-S01Random ([IO.Path]::GetFileNameWithoutExtension($f.path))))) { $R.Add('random_name') }
    $lolUrl = $ind.url -and -not $ind.benignUrl -and (($ind.lolClass -eq 'exec') -or ($ind.lolClass -eq 'download' -and ($ind.dropExec -or $ind.exec)) -or ($ind.lolClass -eq 'shell' -and ($ind.cradle -or $ind.exec -or $ind.encoded)))
    $encExec = $ind.encoded -and ($ind.lolbin -or $ind.exec)
    $sev = $null; $cls = $null; $conf = 'medium'; $core = $null
    if ($encExec -or $lolUrl -or $ind.proto -or $ind.cred -or $masq -or ($top -and $top.cls -eq 'compromise')) {
        $cls = 'compromise'; $sev = 'critical'; $conf = 'high'
        $core = if ($encExec) { 'runs an encoded command' } elseif ($lolUrl) { "runs $($ind.lolbin) with a URL" } elseif ($ind.proto) { 'runs a javascript:/vbscript: payload' } elseif ($ind.cred) { 'contains a credential-dumping command' } elseif ($masq) { $conf = 'medium'; "is masquerading ($masq)" } else { "matches '$($top.rule)' (line $($top.line))" }
    }
    elseif ($notValid -and $w) {
        $corr = $recent -and (-not $f.company -or $R.Contains('random_name') -or $R.Contains('motw_internet') -or $R.Contains('hidden') -or $f.folderClass -eq 'suspicious')
        $cls = $(if ($corr) { 'compromise' } else { 'suspicious' }); $sev = 'high'
        $core = if ($corr) { 'starts an unsigned, recently created binary from a user-writable folder' } else { "starts a binary that is not validly signed ($($f.sigStatus)) from a user-writable folder" }
    }
    elseif ($isPe -and $sig -eq 'invalid') { $cls = 'suspicious'; $sev = 'high'; $core = 'starts a binary whose signature does not match its content' }
    elseif ($notValid -and $f.folderClass -eq 'suspicious') { $cls = 'suspicious'; $sev = 'high'; $core = 'starts an unsigned binary from a temp/download folder' }
    elseif ($top -and $Rank[$top.sev] -ge 2) { $cls = $top.cls; $sev = $top.sev; $core = "has suspicious content ($($top.rule), line $($top.line))" }
    elseif ($ind.encoded -or $ind.obf) { $cls = 'suspicious'; $sev = 'high'; $core = 'has obfuscated or encoded arguments' }
    elseif ($ind.url) { $cls = 'suspicious'; $sev = 'medium'; $core = $(if ($ind.benignUrl) { 'opens a web page at startup' } else { 'passes a URL to the program it starts' }) }
    elseif ($isScript -and $w) { $cls = 'suspicious'; $sev = 'medium'; $core = 'runs a script from a user-writable folder' }
    elseif ($notValid -and $unsignedSev -ne 'none') { $cls = 'suspicious'; $sev = $unsignedSev; $core = "starts a binary that is not validly signed ($($f.sigStatus))" }
    elseif ($f -and $f.resolved -and -not $f.exists) {
        if ($w -and $priv -in 'system', 'admin', 'allusers') { $cls = 'hardening'; $sev = $(if ($priv -ne 'allusers' -and $auto) { 'high' } else { 'medium' }); $core = 'points to a missing file in a folder this user can write (hijackable)' }
        else { Add-S01Agg "$check.missing" $check 'Autostart entries pointing to missing files' 'low' 'hygiene' $mitre ([ordered]@{ what = $what; target = $f.path; command = (Limit-S01 $cmd 200) }) $E; return }
    }
    elseif ($w -and $priv -in 'system', 'admin') { $cls = 'hardening'; $sev = $(if ($auto) { 'high' } else { 'medium' }); $core = "runs with $priv rights from a folder this user can modify" }
    elseif ($w -and $priv -eq 'allusers' -and -not $f.microsoft) { $cls = 'hardening'; $sev = 'low'; $core = 'runs for every user from a folder this user can modify' }
    elseif ($R.Contains('signer_mismatch')) { $cls = 'suspicious'; $sev = 'medium'; $core = "is signed by '$($f.signer)', which does not match its name" }
    elseif ($sig -eq 'valid' -and $f.folderClass -eq 'suspicious') { $cls = 'suspicious'; $sev = 'medium'; $core = 'starts a program from a temp/download folder' }
    elseif ($top) { $cls = 'suspicious'; $sev = 'low'; $core = "has weak suspicious markers ($($top.rule))" }
    elseif (-not $f -and $cmd -and -not $floor) { Add-S01Agg "$check.unresolved" $check 'Autostart targets that could not be resolved' 'low' 'hygiene' $mitre ([ordered]@{ what = $what; command = (Limit-S01 $cmd 200) }) $E; return }
    if ($floor -and (-not $sev -or $Rank[$sev] -lt $Rank[$floor.sev])) { $sev = $floor.sev; if (-not $cls -or $ClsRank[$cls] -lt $ClsRank[$floor.cls]) { $cls = $floor.cls }; if (-not $core -or $floor.force) { $core = $floor.title } }
    if (-not $sev) { return }
    $notes = @()
    if ($enabled -eq $false -and $cls -ne 'compromise') { $sev = $SevName[[Math]::Max(0, $Rank[$sev] - 1)]; $notes += 'entry is disabled' }
    if ($cls -ne 'compromise' -and $Rank[$sev] -gt $Rank[$cap]) { $sev = $cap }
    if ($exp) { if ($exp.invalidated) { $notes += 'expected item, but: ' + ($exp.invalidReasons -join '; ') } elseif ($cls -ne 'compromise') { if ($Rank[$sev] -gt $Rank[$exp.severityCap]) { $sev = $exp.severityCap }; $R.Add('expected_match') } }
    $ev2 = @($ev); if ($f) { $ev2 += [ordered]@{ type = 'file'; path = $f.path; exists = $f.exists; signer = $f.signer; sigStatus = $f.sigStatus; company = $f.company; userWritable = $f.writable; folderClass = $f.folderClass; created = (ConvertTo-S01Iso $f.created) } }
    if ($ind.lolbin -or $ind.url -or $ind.encoded -or $ind.obf) { $ev2 += [ordered]@{ type = 'indicator'; lolbin = $ind.lolbin; url = $ind.url; encoded = $ind.encoded; decoded = $ind.decoded; obfuscation = $ind.obf; hiddenWindow = $ind.hidden } }
    foreach ($h in ($hits | Select-Object -First 6)) { $ev2 += [ordered]@{ type = 'content'; rule = $h.rule; line = $h.line; text = $h.text } }
    if ($notes) { $ev2 += [ordered]@{ type = 'note'; text = ($notes -join '; ') } }
    Add-S01Finding $check "$what $core" $sev $cls $conf @($R) $ev2 @($f) $mitre $fp $rec $exp @($E)
}
#endregion

#region ---------- checks ----------
$SA = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'; $Approved = @{}
foreach ($h in 'HKCU', 'HKLM') { foreach ($s in 'Run', 'Run32', 'StartupFolder') {
    $m = @{}; foreach ($v in (Get-S01Vals "$h\$SA\$s")) { $b = $v.Value -as [byte[]]; if ($b -and $b.Length) { $ft = if ($b.Length -ge 12) { [BitConverter]::ToInt64($b, 4) } else { 0 }
        $m[$v.Name.ToLowerInvariant()] = [pscustomobject]@{ key = "$h\$SA\$s"; name = $v.Name; raw = ('{0:X2}' -f $b[0]); enabled = (($b[0] -band 1) -eq 0); changed = $(if ($ft -gt 0) { [datetime]::FromFileTimeUtc($ft) }); used = $false } } }
    $Approved["$h|$s"] = $m } }

function Invoke-S01RunKeys {
    $seen = @{}
    foreach ($hive in 'HKLM', 'HKCU') { foreach ($d in $ioc.runKeys) { foreach ($v in '64', '32') {
        $key = "$hive\SOFTWARE\$($d.sub)"; $lw = Get-S01Lw $key $v; if (-not $lw) { continue }
        $phys = Get-S01Phys $key $v; $items = [System.Collections.Generic.List[object]]::new()
        if ($d.type -like '*RunOnceEx') { foreach ($sk in Get-S01Subs $key $v) { foreach ($sub in "$key\$sk", "$key\$sk\Depend") { foreach ($x in Get-S01Vals $sub $v) { $s = ConvertTo-S01Str $x.Value; if ($s) { $items.Add(@{ n = "$sk\$($x.Name)"; d = $s; dll = $s.Contains('|') }) } } } } }
        else { foreach ($x in Get-S01Vals $key $v) { if ($d.only -and $x.Name -notin $d.only) { continue }; $s = ConvertTo-S01Str $x.Value; if ($s) { $items.Add(@{ n = $x.Name; d = $s; dll = $false }) } } }
        foreach ($it in $items) {
            $dk = "$hive|$($d.sub)|$($it.n)|$($it.d)|$($lw.Ticks)"; if ($seen.ContainsKey($dk)) { continue }; $seen[$dk] = 1
            $name = $it.n.TrimStart('!', '*'); $st = $null
            if ($d.type -eq 'Run') { foreach ($s in $(if ($hive -eq 'HKLM' -and $v -eq '32') { 'Run32', 'Run' } else { 'Run', 'Run32' })) { $st = $Approved["$hive|$s"][$name.ToLowerInvariant()]; if ($st) { $st.used = $true; break } } }
            $enabled = if ($st) { $st.enabled } else { $true }
            $res = if ($it.dll) { New-S01Res (Resolve-S01Path ($it.d -split '\|')[0] '.dll' $v) 'dll-runonceex' } else { Resolve-S01Cmd $it.d $v }
            $f = Get-S01Facts $res.Target; $brand = Get-S01Brand $name; $exp = Find-S01Expected @('startup') @($name) $f $brand
            $e = Add-S01Entry 'run_key' $phys $name $it.d $f $res.Kind $lw $enabled $(if ($hive -eq 'HKLM') { 'machine' } else { 'user' }) $(if ($hive -eq 'HKLM') { 'every user' } else { 'current user' }) $exp @{ keyType = $d.type; view = $v; approvedRaw = $st.raw; disabledAt = (ConvertTo-S01Iso $st.changed) }
            $floor = if ($d.rare) { @{ sev = 'low'; cls = 'suspicious'; title = "uses a rarely used autostart key ($($d.type))" } }
            [void](Measure-S01 -E $e -check 'persistence.run_keys' -what "Run key '$name' ($hive $($d.type))" -cmd $it.d -res $res -f $f -priv $(if ($hive -eq 'HKLM') { 'allusers' } else { 'user' }) -enabled $enabled -changed $lw -exp $exp -ev @(Get-S01RegEv $phys $it.n $it.d $lw) -mitre 'T1547.001' -brand $brand -floor $floor)
            $e
        }
    } } }
}
function Invoke-S01StartupFolders {
    $sh = $null; try { $sh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($d in @(@{ h = 'HKCU'; scope = 'user'; dir = [Environment]::GetFolderPath('Startup'); def = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; usf = 'Startup' },
            @{ h = 'HKLM'; scope = 'machine'; dir = [Environment]::GetFolderPath('CommonStartup'); def = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"; usf = 'Common Startup' })) {
        $uk = "$($d.h)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"; $raw = Get-S01Val $uk $d.usf
        if ($raw -and [Environment]::ExpandEnvironmentVariables($raw).TrimEnd('\') -ne $d.def.TrimEnd('\')) { [void](Add-S01Finding 'persistence.startup_folders' "Startup folder location was changed ($($d.usf))" 'medium' 'suspicious' 'medium' @('persistence') @(Get-S01RegEv $uk $d.usf $raw $null) @() @('T1547.001') 'Folder-redirection tools can move Start Menu folders; rare for Startup.' $null $null $null) }
        if (-not $d.dir -or -not [IO.Directory]::Exists($d.dir)) { continue }
        foreach ($fi in @(Get-BvsFiles -Path $d.dir -MaxDepth 1 -NoPrune)) {
            if ($fi.Name -ieq 'desktop.ini' -and $fi.Length -lt 4KB) { continue }
            $top = [string]::Equals($fi.DirectoryName.TrimEnd('\'), $d.dir.TrimEnd('\'), 'OrdinalIgnoreCase')
            $st = $Approved["$($d.h)|StartupFolder"][$fi.Name.ToLowerInvariant()]; if ($st) { $st.used = $true }
            $enabled = $top -and (-not $st -or $st.enabled); $lf = Get-S01Facts $fi.FullName; $f = $lf; $cmd = $fi.FullName; $res = $null
            $x = @{ fileName = $fi.Name; inSubfolder = -not $top; approvedRaw = $st.raw; motwZone = $lf.motwZone }
            switch ($fi.Extension.ToLowerInvariant()) {
                '.lnk' { if ($sh -and -not $lf.cloudOnly) { try {
                            $sc = $sh.CreateShortcut($fi.FullName)   # read-only: properties only, never Save()
                            $la = [string]$sc.Arguments; $x.lnkTarget = [string]$sc.TargetPath; $x.lnkArgs = Limit-S01 $la 400; $x.lnkArgLength = $la.Length; $x.lnkWindowStyle = $sc.WindowStyle
                            if ($sc.TargetPath) { $cmd = ('"{0}" {1}' -f $sc.TargetPath, $la).Trim(); $res = Resolve-S01Cmd $cmd; $f = Get-S01Facts $res.Target } else { $x.note = 'advertised/shell-item shortcut (no TargetPath)'; $f = $null }
                        } catch { $x.lnkError = $_.Exception.Message } } }
                '.url' { $t = Read-S01Text $fi.FullName 64KB; if ($t -match '(?im)^URL=(.+)$') { $cmd = $Matches[1].Trim(); $x.url = Protect-BvsUrl $cmd; $f = $null } }
                default { $res = Resolve-S01Cmd ('"{0}"' -f $fi.FullName) }
            }
            $brand = Get-S01Brand $fi.BaseName; $exp = Find-S01Expected @('startup') @($fi.Name, $fi.BaseName) $f $brand
            $e = Add-S01Entry 'startup_folder' $d.dir $fi.Name $cmd $f $(if ($res) { $res.Kind } else { 'file' }) $fi.LastWriteTimeUtc $enabled $d.scope $null $exp $x
            $chg = if ($fi.CreationTimeUtc -gt $fi.LastWriteTimeUtc) { $fi.CreationTimeUtc } else { $fi.LastWriteTimeUtc }
            $floor = if ($fi.Extension -ieq '.url') { @{ sev = 'medium'; cls = 'suspicious'; title = 'is an Internet shortcut that opens a URL at logon' } }
            [void](Measure-S01 -E $e -check 'persistence.startup_folders' -what "Startup item '$($fi.Name)' ($($d.scope))" -cmd $cmd -res $res -f $f -priv $(if ($d.scope -eq 'machine') { 'allusers' } else { 'user' }) -enabled $enabled -changed $chg -exp $exp -ev @([ordered]@{ type = 'file'; path = $fi.FullName; created = (ConvertTo-S01Iso $fi.CreationTimeUtc); modified = (ConvertTo-S01Iso $fi.LastWriteTimeUtc); shortcut = $x }) -mitre 'T1547.001' -brand $brand -floor $floor)
            $e
        }
    }
    if ($sh) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
}
function Invoke-S01SingleValues([string]$group) {
    # Data-driven single registry values with Windows defaults (Winlogon, BootExecute, AutoRun, AppInit, AeDebug, ...).
    foreach ($d in @($ioc.singleValues | Where-Object group -eq $group)) { foreach ($v in @($(if ($d.views) { $d.views } else { '64' }))) {
        $rv = Get-S01Vals $d.key $v | Where-Object Name -eq $d.name | Select-Object -First 1; if (-not $rv -or $null -eq $rv.Value) { continue }
        $phys = Get-S01Phys $d.key $v; $lw = Get-S01Lw $d.key $v; $raw = $rv.Value
        $parts = if ($raw -is [array] -and $raw -isnot [byte[]]) { @($raw) } elseif ($d.multi) { @("$raw" -split ',') } else { @(ConvertTo-S01Str $raw) }
        $ok = @($d.ok | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).ToLowerInvariant() })
        $enabled = if ($d.enabledBy) { "$(Get-S01Val $d.key $d.enabledBy $v)" -eq '1' } else { $true }
        foreach ($p in $parts) {
            $p = "$p".Trim(); if (-not $p -or [Environment]::ExpandEnvironmentVariables($p).Trim('"').ToLowerInvariant() -in $ok) { continue }
            if ($d.native) { $tok = @($p -split '\s+'); $prog = if ($tok[0] -ieq 'autocheck' -and $tok.Count -gt 1) { $tok[1] } else { $tok[0] }; $res = New-S01Res (Resolve-S01Path $prog '.exe') 'native' }
            elseif ($d.dll) { $res = New-S01Res (Resolve-S01Path ($p -split '[\s,]+')[0] '.dll' $v) 'dll' } else { $res = Resolve-S01Cmd $p $v }
            $f = Get-S01Facts $res.Target; $label = "$($d.key -replace '^.*\\', '')\$($d.name)".TrimEnd('\')
            $e = Add-S01Entry $group $phys $label $p $f $res.Kind $lw $enabled $(if ($d.key -like 'HKCU*') { 'user' } else { 'machine' }) $d.priv $null @{ view = $v }
            if ($d.okIfMicrosoft -and $f.microsoft) { $e; continue }
            [void](Measure-S01 -E $e -check "persistence.$group" -what "Registry value $label ($(if ($v -eq '32') { '32-bit' } else { '64-bit' }))" -cmd $p -res $res -f $f -priv $d.priv -enabled $enabled -changed $lw -ev @(Get-S01RegEv $phys $d.name $raw $lw) -mitre $d.mitre -floor $(if ($d.native -and (Get-S01Sig $f) -eq 'valid' -and (Test-S01Vendor $f.company $f.signer) -ne $false) { @{ sev = 'info'; cls = 'info'; title = "runs a boot-time program signed by '$($f.signer)' (typical for antivirus or disk tools)"; force = $true } } else { @{ sev = $d.sev; cls = 'suspicious'; title = 'is set to a non-default value' } }))
            $e
        }
    } }
}
function Invoke-S01ActiveSetup {
    foreach ($b in @(@('HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components', '64'), @('HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components', '32'), @('HKCU\Software\Microsoft\Active Setup\Installed Components', '64'))) {
        foreach ($g in Get-S01Subs $b[0] $b[1]) {
            $k = "$($b[0])\$g"; $stub = Get-S01Val $k 'StubPath' $b[1]; if (-not $stub) { continue }
            $enabled = "$(Get-S01Val $k 'IsInstalled' $b[1])" -ne '0'; $lw = Get-S01Lw $k $b[1]; $phys = Get-S01Phys $k $b[1]; $res = Resolve-S01Cmd $stub $b[1]; $f = Get-S01Facts $res.Target
            $e = Add-S01Entry 'active_setup' $phys "$g $(Get-S01Val $k '' $b[1])".Trim() $stub $f $res.Kind $lw $enabled 'machine' 'each user at first logon' $null @{ view = $b[1] }
            $floor = if ($b[0] -like 'HKCU*') { @{ sev = 'medium'; cls = 'suspicious'; title = 'has a StubPath in HKCU (unusual)' } }
            [void](Measure-S01 -E $e -check 'persistence.active_setup' -what "Active Setup component $g" -cmd $stub -res $res -f $f -priv 'allusers' -enabled $enabled -changed $lw -ev @(Get-S01RegEv $phys 'StubPath' $stub $lw) -mitre 'T1547.014' -floor $floor)
            $e
        }
    }
}
function Get-S01Com([string]$clsid, [string]$v = '64', [string]$only) {
    # Resolve a CLSID the way COM does (HKCU before HKLM). Returns $null when unregistered.
    $c = $clsid.Trim(); if ($c -notmatch '^\{') { $c = "{$c}" }
    foreach ($src in 'HKCU\Software\Classes\CLSID', 'HKLM\SOFTWARE\Classes\CLSID') {
        if ($only -and -not $src.StartsWith($only)) { continue }
        $k = "$src\$c"; $lw = Get-S01Lw $k $v; if (-not $lw) { continue }
        $o = [ordered]@{ clsid = $c; source = $src.Substring(0, 4); key = (Get-S01Phys $k $v); name = (Get-S01Val $k '' $v); lastWrite = $lw; kind = $null; raw = $null; server = $null; treatAs = (Get-S01Val "$k\TreatAs" '' $v); scriptlet = (Get-S01Val "$k\ScriptletURL" '' $v) }
        $ip = Get-S01Val "$k\InprocServer32" '' $v; $ls = Get-S01Val "$k\LocalServer32" '' $v
        if ($ip) { $o.kind = 'inproc'; $o.raw = $ip; $cb = Get-S01Val "$k\InprocServer32" 'CodeBase' $v; $o.server = if ($ip -match '(?i)mscoree\.dll' -and $cb) { Resolve-S01Path $cb } else { Resolve-S01Path $ip '.dll' $v } }
        elseif ($ls) { $o.kind = 'local'; $o.raw = $ls; $o.server = (Resolve-S01Cmd $ls $v).Executable }
        return [pscustomobject]$o
    }
}
function Invoke-S01DllPoints {
    # Registrations that should only load Microsoft code (LSA, SSP, AppCert, providers, print, NetSh, time, GP, Notify).
    foreach ($d in $ioc.dllPoints) { foreach ($v in @($(if ($d.views) { $d.views } else { '64' }))) {
        $items = [System.Collections.Generic.List[object]]::new()
        if ($d.special -eq 'providerOrder') { foreach ($pn in @("$(Get-S01Val $d.key 'ProviderOrder')" -split ',' | Where-Object { $_ })) { $k = "HKLM\SYSTEM\CurrentControlSet\Services\$pn\NetworkProvider"; $s = Get-S01Val $k 'ProviderPath'; if ($s) { $items.Add(@{ n = $pn; d = $s; k = $k }) } } }
        elseif ($d.value) { foreach ($x in Get-S01Vals $d.key $v) { if ($d.value -ne '*' -and $x.Name -ne $d.value) { continue }
                $vals = if ($x.Value -is [array] -and $x.Value -isnot [byte[]]) { @($x.Value) } elseif ($d.comma) { @("$(ConvertTo-S01Str $x.Value)" -split ',') } else { @(ConvertTo-S01Str $x.Value) }
                foreach ($s in $vals) { $s = "$s".Trim().Trim('"'); if ($s) { $items.Add(@{ n = $(if ($d.value -eq '*') { $x.Name } else { $s }); d = $s; k = $d.key }) } } } }
        elseif ($d.sub) { foreach ($sk in Get-S01Subs $d.key $v) { $s = Get-S01Val "$($d.key)\$sk" $d.sub $v; if ($s) { $items.Add(@{ n = $sk; d = $s; k = "$($d.key)\$sk" }) } } }
        elseif ($d.clsidSub) { foreach ($sk in Get-S01Subs $d.key $v) { $srv = Get-S01Com $sk $v; $items.Add(@{ n = "$sk $($srv.name)".Trim(); d = $(if ($srv) { $srv.raw } else { "unregistered $sk" }); k = "$($d.key)\$sk"; path = $srv.server }) } }
        foreach ($it in $items) {
            $p = if ($it.ContainsKey('path')) { $it.path } else { Resolve-S01Path $it.d '.dll' $v @($(if ($d.dir) { [Environment]::ExpandEnvironmentVariables($d.dir) })) }
            $f = Get-S01Facts $p; $lw = Get-S01Lw $it.k $v; $phys = Get-S01Phys $it.k $v
            $e = Add-S01Entry $d.id $phys $it.n $it.d $f 'dll' $lw $true 'machine' 'SYSTEM process' $null @{ view = $v; label = $d.label }
            $floor = if ($d.floor) { @{ sev = $d.floor; cls = 'suspicious'; title = 'is configured (rarely legitimate)' } } elseif ($f -and $f.exists -and -not $f.microsoft -and (Get-S01Sig $f) -eq 'valid' -and $d.nonMs -ne 'info') { @{ sev = $d.nonMs; cls = 'suspicious'; title = "loads non-Microsoft code signed by '$($f.signer)'" } }
            [void](Measure-S01 -E $e -check 'persistence.dll_hooks' -what "$($d.label) '$($it.n)'" -f $f -priv 'system' -changed $lw -ev @(Get-S01RegEv $phys $it.n $it.d $lw) -mitre $d.mitre -floor $floor -unsignedSev 'high')
            $e
        }
    } }
}
function Invoke-S01Ifeo {
    $base = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; $spe = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    foreach ($v in '64', '32') { foreach ($exe in Get-S01Subs $base $v) {
        $k = "$base\$exe"; $m = @{}; foreach ($x in Get-S01Vals $k $v) { $m[$x.Name] = $x.Value }
        $gfs = "$($m['GlobalFlag'])"; $gf = 0; try { $gf = if ($gfs -match '^0x') { [Convert]::ToInt32($gfs.Substring(2), 16) } elseif ($gfs) { [int]$gfs } else { 0 } } catch { }
        $hooks = @(); if ($m['Debugger']) { $hooks += @{ n = 'Debugger'; d = (ConvertTo-S01Str $m['Debugger']); k = $k } }
        if ("$($m['UseFilter'])" -eq '1') { foreach ($sk in Get-S01Subs $k $v) { $dd = Get-S01Val "$k\$sk" 'Debugger' $v; if ($dd) { $hooks += @{ n = "Debugger (filter $sk)"; d = $dd; k = "$k\$sk" } } } }
        if ($gf -band 0x200) { $mp = Get-S01Val "$spe\$exe" 'MonitorProcess' $v; if ($mp) { $hooks += @{ n = 'SilentProcessExit MonitorProcess'; d = $mp; k = "$spe\$exe" } } }
        if (($gf -band 0x100) -and $m['VerifierDlls']) { foreach ($dll in ("$(ConvertTo-S01Str $m['VerifierDlls'])" -split '\s+' | Where-Object { $_ })) { $hooks += @{ n = 'VerifierDlls'; d = $dll; k = $k; dll = $true } } }
        foreach ($hk in $hooks) {
            $res = if ($hk.dll) { New-S01Res (Resolve-S01Path $hk.d '.dll' $v) 'dll' } else { Resolve-S01Cmd $hk.d $v }
            $f = Get-S01Facts $res.Target; $lw = Get-S01Lw $hk.k $v; $leaf = $exe.ToLowerInvariant(); $phys = Get-S01Phys $hk.k $v
            $e = Add-S01Entry 'ifeo' $phys "$exe $($hk.n)" $hk.d $f $res.Kind $lw $true 'machine' "whoever starts $exe" $null @{ view = $v; globalFlag = $gf }
            $floor = if ($leaf -in $ioc.accessibility.PSObject.Properties.Name) { @{ sev = 'critical'; cls = 'compromise'; title = 'hijacks an accessibility tool (Sticky-Keys style backdoor)'; force = $true } }
            elseif ($leaf -match $ioc.securityToolsRegex -and -not ($leaf -eq 'taskmgr.exe' -and (Get-S01Sig $f) -eq 'valid')) { @{ sev = 'high'; cls = 'suspicious'; title = "blocks or redirects the security/admin tool $exe"; force = $true } }
            else { @{ sev = 'low'; cls = 'suspicious'; title = 'redirects program start via Image File Execution Options' } }
            [void](Measure-S01 -E $e -check 'persistence.ifeo' -what "IFEO $($hk.n) for $exe" -cmd $hk.d -res $res -f $f -priv 'admin' -changed $lw -ev @(Get-S01RegEv $phys $hk.n $hk.d $lw) -mitre 'T1546.012' -floor $floor)
            $e
        }
    } }
}
function Invoke-S01ClassHijack {
    foreach ($p in $ioc.hkcuClassHijack) { foreach ($verb in 'open', 'runas') {
        $k = "HKCU\Software\Classes\$p\shell\$verb\command"; $vals = Get-S01Vals $k; if (-not $vals.Count) { continue }
        $cmd = ConvertTo-S01Str ($vals | Where-Object Name -eq '' | Select-Object -First 1).Value; $de = $vals | Where-Object Name -eq 'DelegateExecute' | Select-Object -First 1; $lw = Get-S01Lw $k
        $res = Resolve-S01Cmd $cmd; $f = Get-S01Facts $res.Target
        $e = Add-S01Entry 'class_hijack' $k "$p $verb" $cmd $f $res.Kind $lw $true 'user' 'auto-elevating Windows tools' $null @{ delegateExecute = $(if ($de) { "$($de.Value)" }) }
        [void](Measure-S01 -E $e -check 'persistence.class_hijack' -what "HKCU $p\shell\$verb\command" -cmd $cmd -res $res -f $f -priv 'admin' -changed $lw -extra @('uac_bypass_key', $(if ($de -and -not "$($de.Value)") { 'delegateexecute_empty' })) -ev @(Get-S01RegEv $k '(default)' $cmd $lw) -mitre @('T1548.002', 'T1546.001') -floor @{ sev = 'high'; cls = 'suspicious'; title = 'overrides a shell command used by auto-elevating Windows tools (UAC-bypass pattern)'; force = $true })
        $e
    } }
    foreach ($p in $ioc.hklmClassDefaults.PSObject.Properties) {
        $k = "HKLM\SOFTWARE\Classes\$($p.Name)\shell\open\command"; $cmd = Get-S01Val $k ''
        if ($cmd -and ($cmd -replace '\s+', ' ').Trim() -ne $p.Value) { $f = Get-S01Facts (Resolve-S01Cmd $cmd).Target; $e = Add-S01Entry 'class_hijack' $k "$($p.Name) open" $cmd $f 'association' (Get-S01Lw $k) $true 'machine' 'every user'
            [void](Measure-S01 -E $e -check 'persistence.class_hijack' -what "HKLM $($p.Name) open command" -cmd $cmd -f $f -priv 'allusers' -ev @(Get-S01RegEv $k '(default)' $cmd $null) -mitre 'T1546.001' -floor @{ sev = 'high'; cls = 'suspicious'; title = 'differs from the Windows default'; force = $true }); $e }
    }
    foreach ($x in '.exe', '.com', '.bat', '.cmd', '.scr', '.pif') { $val = Get-S01Val "HKCU\Software\Classes\$x" ''; if ($val) { [void](Add-S01Finding 'persistence.class_hijack' "HKCU redefines the $x file type as '$val'" 'high' 'suspicious' 'medium' @('persistence', 'file_association_hijack') @(Get-S01RegEv "HKCU\Software\Classes\$x" '(default)' $val $null) @() @('T1546.001') 'Almost never legitimate for executable types.' $null $null $null) } }
}
function Invoke-S01Accessibility {
    foreach ($p in $ioc.accessibility.PSObject.Properties) {
        $f = Get-S01Facts "$Sys32\$($p.Name)"; $orig = "$($f.originalFilename)" -replace '(?i)\.mui$', ''
        $e = Add-S01Entry 'accessibility' $Sys32 $p.Name $null $f 'exe' $f.modified $true 'machine' 'SYSTEM on the logon screen' $null @{ originalFilename = $orig }
        $bad = if (-not $f.exists) { $null } elseif ((Get-S01Sig $f) -ne 'valid' -or -not $f.microsoft) { "is not Microsoft-signed ($($f.sigStatus), '$($f.signer)')" } elseif ($orig.ToLowerInvariant() -notin @($p.Value)) { "has OriginalFilename '$orig' (expected $(@($p.Value) -join ' or '))" }
        if ($bad) { [void](Add-S01Finding 'persistence.accessibility' "Accessibility binary $($p.Name) $bad" 'critical' 'compromise' 'high' @('persistence', 'masquerading') @([ordered]@{ type = 'file'; path = $f.path; signer = $f.signer; sigStatus = $f.sigStatus; originalFilename = $orig }) @($f) @('T1546.008') 'A broken update could leave an unsigned file, but a replaced accessibility tool is a classic logon-screen backdoor.' $null $null @($e)) }
        $e
    }
    $ats = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
    foreach ($a in Get-S01Subs $ats) { $s = Get-S01Val "$ats\$a" 'StartExe'; if (-not $s) { $s = Get-S01Val "$ats\$a" 'ATExe' }; if ("$s" -notmatch '(?i)\.exe') { continue }
        $f = Get-S01Facts (Resolve-S01Cmd $s).Executable; if ($f.microsoft) { continue }
        $e = Add-S01Entry 'accessibility_at' "$ats\$a" $a $s $f 'exe' (Get-S01Lw "$ats\$a") $true 'machine' 'logon screen'
        [void](Measure-S01 -E $e -check 'persistence.accessibility' -what "Assistive technology '$a'" -cmd $s -f $f -priv 'system' -mitre 'T1546.008' -floor @{ sev = 'medium'; cls = 'suspicious'; title = 'registers a non-Microsoft assistive technology' }); $e }
}
function Invoke-S01ComHijack {
    foreach ($v in '64', '32') { foreach ($c in Get-S01Subs 'HKCU\Software\Classes\CLSID' $v) {
        $cu = Get-S01Com $c $v 'HKCU'; if (-not $cu) { continue }
        $lm = Get-S01Com $c $v 'HKLM'; $f = Get-S01Facts $cu.server; $known = $cu.clsid -in $ioc.knownHijackClsids
        $cmd = @($cu.raw, $cu.treatAs, $cu.scriptlet) | Where-Object { $_ } | Select-Object -First 1
        $e = Add-S01Entry 'com_hkcu' $cu.key "$($cu.clsid) $($cu.name)".Trim() $cmd $f $cu.kind $cu.lastWrite $true 'user' 'current user' $null @{ shadowsHklm = [bool]$lm; hklmServer = $lm.server; treatAs = $cu.treatAs; view = $v }
        $verified = $f -and (Get-S01Sig $f) -eq 'valid' -and (-not $f.company -or (Test-S01SignerOk $f.company $f))
        $floor = if ($cu.scriptlet) { $u = $cu.scriptlet -match '^(?i)https?:'; @{ sev = $(if ($u) { 'critical' } else { 'high' }); cls = $(if ($u) { 'compromise' } else { 'suspicious' }); title = 'registers a ScriptletURL COM object'; force = $true } }
        elseif ($lm -and $cu.treatAs) { @{ sev = 'medium'; cls = 'suspicious'; title = 'redirects an HKLM class with TreatAs' } }
        elseif ($lm -and $f -and $f.exists -and -not $verified) { @{ sev = $(if ($known) { 'high' } else { 'medium' }); cls = 'suspicious'; title = 'shadows an HKLM COM class with an unverified server' } }
        [void](Measure-S01 -E $e -check 'persistence.com_hijack' -what "HKCU COM class $($cu.clsid)$(if ($lm) { ' (shadows HKLM)' })" -f $f -changed $cu.lastWrite -extra @($(if ($lm) { 'com_shadow' }), $(if ($known) { 'known_hijack_clsid' })) -ev @(Get-S01RegEv $cu.key $cu.kind $cmd $cu.lastWrite) -mitre 'T1546.015' -floor $floor -cap $(if ($lm) { 'critical' } else { 'medium' }) -unsignedSev 'none')
        $e
    } }
}
function Invoke-S01ShellExt {
    $refs = @{}
    foreach ($h in 'HKLM', 'HKCU') { foreach ($s in $ioc.shellExtSources) {
        $k = "$h\$($s.key)"
        $ids = switch ($s.mode) { 'valueData' { Get-S01Vals $k | ForEach-Object { ConvertTo-S01Str $_.Value } } 'valueName' { Get-S01Vals $k | ForEach-Object Name } 'subkey' { Get-S01Subs $k }
            'subkeyDefault' { foreach ($sk in Get-S01Subs $k) { if ($sk -match '^\{[0-9A-Fa-f-]{36}\}$') { $sk } else { Get-S01Val "$k\$sk" '' } } } }
        foreach ($id in @($ids)) { if ("$id" -match '^\s*(\{[0-9A-Fa-f-]{36}\})\s*$') { $c = $Matches[1].ToUpperInvariant(); if (-not $refs.ContainsKey($c)) { $refs[$c] = [System.Collections.Generic.List[string]]::new() }; $refs[$c].Add("$k$(if ($s.startup) { ' [startup]' })") } }
    } }
    $stale = 0; $ms = 0
    foreach ($c in $refs.Keys) {
        $srv = Get-S01Com $c; if (-not $srv -or -not $srv.server) { $stale++; continue }
        $f = Get-S01Facts $srv.server; if ($f.microsoft) { $ms++; continue }
        $startup = [bool]($refs[$c] -match '\[startup\]')
        $e = Add-S01Entry 'shell_extension' ($refs[$c] -join '; ') "$c $($srv.name)".Trim() $srv.raw $f $srv.kind $srv.lastWrite $true $(if ($srv.source -eq 'HKCU') { 'user' } else { 'machine' }) 'Explorer' $null @{ registeredIn = $srv.source; loadsAtExplorerStart = $startup }
        [void](Measure-S01 -E $e -check 'persistence.shell_extensions' -what "Explorer extension $c ($($srv.name))" -f $f -changed $srv.lastWrite -ev @(Get-S01RegEv $srv.key $srv.kind $srv.raw $srv.lastWrite) -mitre 'T1546.015' -cap $(if ($startup) { 'high' } else { 'medium' }) -unsignedSev 'none')
        $e
    }
    Add-BvsInventory -Run $run -Name 'shellExtensionStats' -Data ([ordered]@{ referenced = $refs.Count; microsoft = $ms; unregistered = $stale })
}
function Invoke-S01Services {
    $unq = [System.Collections.Generic.List[object]]::new(); $odd = [System.Collections.Generic.List[object]]::new(); $rec = [System.Collections.Generic.List[object]]::new()
    $all = @(Get-CimInstance -ClassName Win32_Service); $names = [System.Collections.Generic.HashSet[string]]::new([string[]]@($all.Name), [StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $all) { try {
        $rk = "HKLM\SYSTEM\CurrentControlSet\Services\$($s.Name)"; $lw = Get-S01Lw $rk; $pn = if ($s.PathName) { $s.PathName } else { Get-S01Val $rk 'ImagePath' }
        $dllRaw = Get-S01Val "$rk\Parameters" 'ServiceDll'; if (-not $dllRaw) { $dllRaw = Get-S01Val $rk 'ServiceDll' }
        $res = Resolve-S01Cmd $pn; $xf = Get-S01Facts $res.Executable; $df = if ($dllRaw) { Get-S01Facts (Resolve-S01Path $dllRaw '.dll') }; $f = if ($df) { $df } else { $xf }
        $isMs = $xf.microsoft -and (-not $df -or $df.microsoft); $priv = if ("$($s.StartName)" -match '(?i)^(LocalSystem|NT AUTHORITY\\|$)') { 'system' } else { 'user' }
        $inst = $s.Name -match '^(.+)_[0-9a-f]{4,8}$' -and $names.Contains($Matches[1])
        $fc = Get-S01Val $rk 'FailureCommand'; $fa = (Get-S01Vals $rk | Where-Object Name -eq 'FailureActions').Value -as [byte[]]; $runCmd = $false
        if ($fa -and $fa.Length -ge 20) { $n = [BitConverter]::ToInt32($fa, 12); for ($i = 0; $i -lt $n -and (28 + 8 * $i) -le $fa.Length; $i++) { if ([BitConverter]::ToInt32($fa, 20 + 8 * $i) -eq 3) { $runCmd = $true } } }
        $isUnq = $pn -and $pn -notmatch '^\s*"' -and $res.Executable -and $res.Executable.Contains(' ') -and $pn.Trim().StartsWith($res.Executable, 'OrdinalIgnoreCase')
        $exp = Find-S01Expected @('listener', 'program') @($s.Name, $s.DisplayName, $(if ($xf) { [IO.Path]::GetFileName($xf.path) })) $f $null
        $e = Add-S01Entry 'service' $rk $s.Name $pn $f $(if ($df) { 'servicedll' } else { 'exe' }) $lw ($s.StartMode -ne 'Disabled') 'machine' $s.StartName $exp @{ displayName = $s.DisplayName; startMode = $s.StartMode; state = $s.State; binary = $xf.path; binarySigner = $xf.signer; serviceDll = $df.path; failureCommand = $fc; failureRunsCommand = $runCmd; unquoted = $isUnq; perUserInstance = $inst }
        if ($inst) { $e; continue }
        $ev0 = [ordered]@{ type = 'service'; name = $s.Name; pathName = $pn; serviceDll = $dllRaw; startMode = $s.StartMode; startName = $s.StartName; state = $s.State; keyLastWrite = (ConvertTo-S01Iso $lw) }
        [void](Measure-S01 -E $e -check 'persistence.services' -what "Service '$($s.Name)'" -cmd $pn -res $res -f $f -priv $priv -auto ($s.StartMode -eq 'Auto') -enabled ($s.StartMode -ne 'Disabled') -changed $lw -exp $exp -ev @($ev0) -mitre 'T1543.003' -unsignedSev 'low')
        if ($df -and $df.resolved -and -not ($df.path.StartsWith("$Sys32\", 'OrdinalIgnoreCase') -or $df.path.StartsWith("$SysWow\", 'OrdinalIgnoreCase'))) { [void](Add-S01Finding 'persistence.services' "Service '$($s.Name)' loads its ServiceDll from outside System32" $(if ($df.microsoft) { 'low' } else { 'medium' }) 'suspicious' 'medium' @('persistence', 'servicedll_outside_system32') @($ev0) @($df) @('T1543.003') 'Some vendors host DLL services from their own folder; verify the signer.' $null $null @($e)) }
        if ($isUnq) { $unq.Add([ordered]@{ service = $s.Name; pathName = $pn; startName = $s.StartName }) }
        if (-not $isMs -and $xf.exists -and $xf.folderClass -notin 'windows', 'programfiles') { $odd.Add([ordered]@{ service = $s.Name; binary = $xf.path; signer = $xf.signer; userWritable = $xf.writable }) }
        if (-not $isMs -and $lw -gt $RecentCut) { $rec.Add([ordered]@{ service = $s.Name; keyLastWrite = (ConvertTo-S01Iso $lw); binary = $f.path; signer = $f.signer }) }
        if ($fc -and $runCmd) { $fr = Resolve-S01Cmd $fc; $ff = Get-S01Facts $fr.Target; $e2 = Add-S01Entry 'service_failure_command' $rk "$($s.Name) FailureCommand" $fc $ff $fr.Kind $lw $true 'machine' $s.StartName
            [void](Measure-S01 -E $e2 -check 'persistence.services' -what "Service '$($s.Name)' failure action" -cmd $fc -res $fr -f $ff -priv $priv -changed $lw -ev @($ev0) -mitre 'T1543.003' -floor $(if (-not ($ff -and (Get-S01Sig $ff) -eq 'valid' -and (Test-S01Vendor $ff.signer $xf.signer))) { @{ sev = 'low'; cls = 'suspicious'; title = 'runs a command when the service fails' } })) }
        $e
    } catch { Add-S01ItemErr 'persistence.services' $s.Name $_ } }
    if ($unq.Count) { [void](Add-S01Finding 'persistence.services' "Unquoted service paths containing spaces ($($unq.Count))" 'low' 'hardening' 'high' @('unquoted_service_path') @($unq | Select-Object -First 40) @() @('T1574.009') 'Exploitable only if a standard user can write to a parent folder such as C:\ or C:\Program Files; normally they cannot.' 'Ask the vendor to quote the path, or add quotes to ImagePath in regedit after exporting a backup.' $null @()) }
    if ($odd.Count) { [void](Add-S01Finding 'persistence.services' "Non-Microsoft services running from outside Windows/Program Files ($($odd.Count))" 'info' 'info' 'high' @('nonstandard_location') @($odd | Select-Object -First 40) @() @('T1543.003') 'Context; each binary was rated individually.' 'Review the list.' $null @()) }
    if ($rec.Count) { [void](Add-S01Finding 'persistence.services' "Non-Microsoft services added or changed in the last $RecentDays days ($($rec.Count))" 'info' 'info' 'high' @('recently_changed') @($rec | Select-Object -First 40) @() @('T1543.003') 'Updates rewrite service keys; context for the timeline.' 'Review the list.' $null @()) }
}
function Invoke-S01Drivers {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @(Get-CimInstance -ClassName Win32_SystemDriver)) { try {
        $rk = "HKLM\SYSTEM\CurrentControlSet\Services\$($d.Name)"; $raw = if ($d.PathName) { $d.PathName } else { Get-S01Val $rk 'ImagePath' }
        $f = Get-S01Facts $(if ($raw) { Resolve-S01Path $raw '.sys' } else { "$Sys32\drivers\$($d.Name).sys" }); if ($f.exists -and -not $f.cloudOnly -and -not $f.sha256) { $f.sha256 = Get-BvsHash -Path $f.path }
        $lw = Get-S01Lw $rk
        $rows.Add([pscustomobject][ordered]@{ name = $d.Name; displayName = $d.DisplayName; path = $f.path; state = $d.State; startMode = $d.StartMode; exists = $f.exists; signer = $f.signer; sigStatus = $f.sigStatus; company = $f.company; sha256 = $f.sha256; lastWrite = (ConvertTo-S01Iso $lw); userWritable = $f.writable; folderClass = $f.folderClass; loldrivers = $null })
        if (-not $f.exists -or ($f.microsoft -and $f.signer -eq 'Microsoft Windows')) { continue }
        $e = Add-S01Entry 'driver' $rk $d.Name $raw $f 'driver' $lw ($d.StartMode -ne 'Disabled') 'machine' 'kernel' $null @{ state = $d.State; startMode = $d.StartMode; sha256 = $f.sha256 }
        $sig = Get-S01Sig $f; $t = if ($sig -in 'unsigned', 'invalid', 'untrusted') { "is not validly signed ($($f.sigStatus))" } elseif ($f.writable -or $f.folderClass -eq 'suspicious') { 'is loaded from a user-writable or temporary folder' }
        if ($t) { [void](Add-S01Finding 'persistence.drivers' "Driver '$($d.Name)' $t" $(if ($d.State -eq 'Running') { 'high' } else { 'medium' }) 'suspicious' 'medium' @('persistence', $(if ($sig -ne 'valid') { 'unsigned' }), $(if ($f.writable) { 'user_writable' })) @([ordered]@{ type = 'driver'; name = $d.Name; path = $f.path; state = $d.State; startMode = $d.StartMode; signer = $f.signer }) @($f) @('T1543.003', 'T1014') 'Hardware/monitoring tools (CPU-Z, HWiNFO, RGB utilities) drop signed drivers into Temp; lab test-signed drivers are unsigned.' $null $null @($e)) }
        $e
    } catch { Add-S01ItemErr 'persistence.drivers' $d.Name $_ } }
    $script:DriverRows = $rows
}
function Invoke-S01LolDrivers {
    $dir = Join-Path $run.Root 'intel\www.loldrivers.io'; $cache = @(if ([IO.Directory]::Exists($dir)) { Get-ChildItem -LiteralPath $dir -File -Filter '*-loldrivers.json' | Sort-Object LastWriteTimeUtc -Descending })
    $data = $null; $src = $null; $err = $null
    # The feed has keys that differ only by case, which ConvertFrom-Json rejects unless it builds hashtables.
    # The keys read below (KnownVulnerableSamples, SHA256, Category, Id) are used with their exact case.
    $parse = { param([string]$Text) $Text | ConvertFrom-Json -Depth 64 -AsHashtable }
    if ($cache.Count -and $cache[0].LastWriteTimeUtc -gt $Now.AddHours(-$IntelMaxAgeHours)) { $data = & $parse (Get-Content -LiteralPath $cache[0].FullName -Raw); $src = "cache $($cache[0].Name)" }
    if (-not $data -and -not $NoIntel) { try { $r = Invoke-BvsIntel -Uri 'https://www.loldrivers.io/api/drivers.json' -SaveName 'loldrivers.json' -TimeoutSec 180 -MaxBytes 200MB; if ($r.Status -eq 200) { $data = & $parse ([string]$r.Content); $src = 'download' } else { $err = "HTTP $($r.Status)" } } catch { $err = $_.Exception.Message } }
    if (-not $data -and $cache.Count) { $data = & $parse (Get-Content -LiteralPath $cache[0].FullName -Raw); $src = "stale cache $($cache[0].Name)" }
    if (-not $data) { Set-BvsCheckStatus -Id 'persistence.loldrivers' -Status skipped -Reason "LOLDrivers list unavailable ($err)"; return }
    $map = @{}; foreach ($x in @($data)) { foreach ($s in @($x.KnownVulnerableSamples)) { if ($s.SHA256) { $map["$($s.SHA256)".ToLowerInvariant()] = $x } } }
    $bl = Get-S01Val 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
    Add-BvsInventory -Run $run -Name 'loldriversIntel' -Data ([ordered]@{ source = $src; entries = @($data).Count; hashes = $map.Count; vulnerableDriverBlocklist = $bl; compared = @($script:DriverRows | Where-Object sha256).Count })
    foreach ($row in $script:DriverRows) {
        if (-not $row.sha256 -or -not $map.ContainsKey($row.sha256)) { continue }
        $x = $map[$row.sha256]; $mal = "$($x.Category)" -match '(?i)malicious'; $row.loldrivers = [ordered]@{ id = $x.Id; category = $x.Category }; $up = $row.state -eq 'Running'
        [void](Add-S01Finding 'persistence.loldrivers' "$(if ($mal) { 'Known malicious' } else { 'Known vulnerable' }) driver '$($row.name)' (LOLDrivers: $($x.Category))$(if ($up) { ' is loaded' } else { ' is installed' })" $(if ($mal) { 'critical' } elseif ($up) { 'high' } else { 'medium' }) $(if ($mal) { 'compromise' } else { 'hardening' }) 'high' @('intel_match', 'persistence') @([ordered]@{ type = 'driver'; name = $row.name; path = $row.path; state = $row.state; startMode = $row.startMode; signer = $row.signer; loldriversId = $x.Id; blocklistEnabled = $bl }) @(Get-S01Facts $row.path) @('T1068', 'T1543.003') 'Exact hash match against the public LOLDrivers list (compared locally). Vulnerable drivers ship with legitimate hardware, overclocking and anti-cheat tools; still a kernel attack surface while installed.' 'Identify the program that installed the driver (file Properties > Details), update or uninstall it, turn on Microsoft Vulnerable Driver Blocklist (Windows Security > Device security > Core isolation) and reboot.' $null $null)
        $row
    }
}
function Get-S01X($node, [string]$p) { if ($node) { $n = $node.SelectSingleNode('.//*[local-name()=''' + ($p -replace '/', ''']/*[local-name()=''') + ''']'); if ($n) { $n.InnerText } } }
function Invoke-S01Tasks {
    $root = [System.Collections.Generic.List[object]]::new()
    foreach ($t in @(Get-ScheduledTask)) { try {
        $full = "$($t.TaskPath)$($t.TaskName)"; $xml = $null; try { $xml = [xml](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath) } catch { }
        $hidden = (Get-S01X $xml 'Settings/Hidden') -eq 'true'; $rl = "$(Get-S01X $xml 'Principals/Principal/RunLevel')"; $uid = "$(Get-S01X $xml 'Principals/Principal/UserId')"; if (-not $uid) { $uid = "$($t.Principal.UserId)" }; $grp = "$($t.Principal.GroupId)"
        $regDate = $null; $rd = Get-S01X $xml 'RegistrationInfo/Date'; $dt = [datetime]::MinValue; if ($rd -and [datetime]::TryParse($rd, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$dt)) { $regDate = $dt.ToUniversalTime() }
        $priv = if ($uid -match '(?i)^(S-1-5-1[89]|S-1-5-20|SYSTEM|LOCAL ?SERVICE|NETWORK ?SERVICE)$|\\(SYSTEM|LOCAL ?SERVICE|NETWORK ?SERVICE)$') { 'system' } elseif ($rl -match 'Highest') { 'admin' } elseif ($grp) { 'allusers' } else { 'user' }
        $trig = @(if ($xml) { $xml.SelectNodes("//*[local-name()='Triggers']/*") | ForEach-Object LocalName }); $enabled = "$($t.State)" -ne 'Disabled'; $msFolder = $t.TaskPath -like '\Microsoft\*'
        $segs = @($t.TaskPath -split '\\' | Where-Object { $_ }); $brand = Get-S01Brand $t.TaskName; foreach ($sg in $segs) { if (-not $brand) { $brand = Get-S01Brand $sg } }; if (-not $brand -and $msFolder) { $brand = 'microsoft' }
        $acts = @($t.Actions); $i = 0
        foreach ($a in $acts) {
            $i++
            if ($a.CimClass.CimClassName -like '*ComHandler*') { $srv = Get-S01Com "$($a.ClassId)"; $f = Get-S01Facts $srv.server; $cmd = "ComHandler $($a.ClassId) $($srv.raw)".Trim(); $res = $null; $kind = 'comhandler' }
            else { $exe = [Environment]::ExpandEnvironmentVariables("$($a.Execute)".Trim().Trim('"')); $cmd = ('"{0}" {1}' -f $exe, $a.Arguments).Trim(); $res = Resolve-S01Cmd $cmd; $f = Get-S01Facts $res.Target; $kind = $res.Kind }
            $exp = Find-S01Expected @('task') (@($t.TaskName, $full) + $segs) $f $brand
            $x = @($(if ($hidden -and -not $f.microsoft) { 'hidden' }), $(if ($msFolder -and $f.exists -and -not $f.microsoft -and $f.isPe) { 'non_microsoft_in_microsoft_folder' }))
            $floor = if ($kind -eq 'comhandler' -and $f.writable -and -not $f.microsoft) { @{ sev = 'low'; cls = 'suspicious'; title = 'uses a COM handler DLL in a user-writable folder' } } elseif ($hidden -and $f -and -not $f.microsoft -and -not $exp) { @{ sev = 'low'; cls = 'suspicious'; title = 'is hidden and runs a non-Microsoft program' } }
            if ($t.TaskPath -eq '\' -and $f -and -not $f.microsoft -and -not $exp) { $root.Add([ordered]@{ task = $full; target = $f.path; signer = $f.signer }) }
            $e = Add-S01Entry 'scheduled_task' "Task Scheduler $($t.TaskPath)" $(if ($acts.Count -gt 1) { "$full [$i]" } else { $full }) $cmd $f $kind $regDate $enabled $(if ($priv -eq 'user') { 'user' } else { 'machine' }) $(if ($uid) { $uid } else { $grp }) $exp @{ hidden = $hidden; runLevel = $rl; triggers = $trig; author = (Limit-S01 "$($t.Author)" 120); state = "$($t.State)" }
            [void](Measure-S01 -E $e -check 'persistence.scheduled_tasks' -what "Scheduled task '$full'" -cmd $cmd -res $res -f $f -priv $priv -auto ([bool]($trig -match 'Logon|Boot|Idle|Session|Time|Calendar|Event|Registration')) -enabled $enabled -changed $regDate -exp $exp -extra $x -ev @([ordered]@{ type = 'task'; path = $full; action = (Limit-S01 $cmd 400); runAs = $uid; runLevel = $rl; hidden = $hidden; registered = (ConvertTo-S01Iso $regDate); triggers = ($trig -join ',') }) -mitre 'T1053.005' -brand $brand -floor $floor)
            $e
        }
    } catch { Add-S01ItemErr 'persistence.scheduled_tasks' $t.TaskName $_ } }
    if ($root.Count) { [void](Add-S01Finding 'persistence.scheduled_tasks' "Non-Microsoft tasks in the Task Scheduler root folder not on the known list ($($root.Count))" 'info' 'info' 'high' @('persistence') @($root) @() @('T1053.005') 'Most installers put their updater tasks in the root folder.' 'Review the list; each target was also rated individually.' $null @()) }
}
function Invoke-S01TaskCache {
    $t = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    try { $k = Open-BvsRegKey $t; if ($k) { $k.Dispose() } } catch { Set-BvsCheckStatus -Id 'persistence.task_sd_hidden' -Status needs_admin -Reason 'TaskCache\Tree is readable only when elevated (hidden-task SD-removal check)'; return }
    $stack = [System.Collections.Generic.Stack[string]]::new(); $stack.Push($t)
    while ($stack.Count) { $k = $stack.Pop(); foreach ($s in Get-S01Subs $k) { $stack.Push("$k\$s") }; $names = @(Get-S01Vals $k | ForEach-Object Name)
        if ('Id' -in $names -and 'SD' -notin $names) { [void](Add-S01Finding 'persistence.task_sd_hidden' "Scheduled task hidden by removing its security descriptor: $($k.Substring($t.Length))" 'high' 'suspicious' 'high' @('persistence', 'hidden') @(Get-S01RegEv $k 'SD' '(missing)' $null) @() @('T1053.005', 'T1564') 'Corrupted registrations can lose SD, but deliberate removal hides tasks from schtasks (Tarrask).' $null $null @()); $k } }
}
function Invoke-S01Wmi {
    foreach ($ns in 'root\subscription', 'root\default') {
        try { $fl = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter); $co = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer); $bi = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding) } catch { if ($ns -eq 'root\subscription') { throw }; continue }
        foreach ($c in $co) {
            $cls = $c.CimClass.CimClassName; $b = @($bi | Where-Object { $_.Consumer.Name -eq $c.Name }); $fn = @($b | ForEach-Object { $_.Filter.Name })
            $q = @($fl | Where-Object { $_.Name -in $fn } | ForEach-Object Query) -join ' | '; $default = $c.Name -eq 'SCM Event Log Consumer' -and $cls -eq 'NTEventLogEventConsumer'
            $cmd = switch ($cls) { 'CommandLineEventConsumer' { if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { $c.ExecutablePath } } 'ActiveScriptEventConsumer' { if ($c.ScriptText) { $c.ScriptText } else { $c.ScriptFileName } } default { $null } }
            $res = if ($cls -eq 'CommandLineEventConsumer') { Resolve-S01Cmd $cmd }; $f = if ($res) { Get-S01Facts $res.Target } elseif ($cls -eq 'ActiveScriptEventConsumer' -and $c.ScriptFileName) { Get-S01Facts $c.ScriptFileName }
            $e = Add-S01Entry 'wmi_subscription' "$ns $cls" $c.Name $cmd $f $cls $null $true 'machine' 'SYSTEM (WmiPrvSE)' $null @{ bindings = $b.Count; filterQuery = (Limit-S01 $q 300); default = $default }
            if (-not $default) { [void](Measure-S01 -E $e -check 'persistence.wmi_subscriptions' -what "WMI $cls '$($c.Name)'" -cmd $cmd -res $res -f $f -priv 'system' -ev @([ordered]@{ type = 'wmi'; namespace = $ns; class = $cls; name = $c.Name; command = (Limit-S01 $cmd 400); filter = (Limit-S01 $q 300) }) -mitre 'T1546.003' -floor @{ sev = $(if ($cls -match 'CommandLine|ActiveScript') { 'high' } else { 'medium' }); cls = 'suspicious'; title = 'is a permanent WMI event subscription (not the Windows default)' }) }
            $e
        }
        foreach ($x in $fl) { if (-not @($bi | Where-Object { $_.Filter.Name -eq $x.Name }).Count) { Add-S01Entry 'wmi_filter_unbound' "$ns __EventFilter" $x.Name (Limit-S01 $x.Query 300) $null 'filter' $null $false 'machine' $null $null $null } }
    }
}
function Invoke-S01Bits {
    try { Import-Module BitsTransfer -ErrorAction Stop } catch { Set-BvsCheckStatus -Id 'persistence.bits_jobs' -Status not_applicable -Reason 'BitsTransfer module unavailable'; return }
    Set-BvsCheckStatus -Id 'persistence.bits_jobs' -Status partial -Reason 'current user jobs only (other users need elevation)'
    foreach ($j in @(Get-BitsTransfer)) {
        $cmd = "$($j.NotifyCmdLine)".Trim(); $res = if ($cmd) { Resolve-S01Cmd $cmd }; $f = if ($res) { Get-S01Facts $res.Target }
        $e = Add-S01Entry 'bits_job' 'BITS (current user)' $j.DisplayName $cmd $f "$($j.TransferType)" $j.CreationTime $true 'user' $j.OwnerAccount $null @{ state = "$($j.JobState)"; files = @($j.FileList | ForEach-Object { [ordered]@{ remote = (Protect-BvsUrl $_.RemoteName); local = $_.LocalName } }) }
        if ($cmd) { [void](Measure-S01 -E $e -check 'persistence.bits_jobs' -what "BITS job '$($j.DisplayName)'" -cmd $cmd -res $res -f $f -ev @() -mitre 'T1197' -floor @{ sev = 'high'; cls = 'suspicious'; title = 'runs a command when the transfer completes (BITS persistence)' }) }
        $e
    }
}
function Invoke-S01Env {
    foreach ($src in @(@('HKCU\Environment', 'user'), @('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'machine'))) { foreach ($v in Get-S01Vals $src[0]) {
        $sev = $ioc.envWatch.($v.Name); if (-not $sev) { continue }
        $val = ConvertTo-S01Str $v.Value; $top = Get-S01Top @(Get-S01TextHits "$($v.Name)=$val"); if ($top -and $Rank[$top.sev] -gt $Rank[$sev]) { $sev = $top.sev }
        $ref = if ($v.Name -match 'PROFILER$') { (Get-S01Com $val).server } elseif ($v.Name -match 'PATH$|STARTUP$') { Resolve-S01Path $val } elseif ($val -match '(?i)(?:--require|-r|--import|-javaagent:)\s*["'']?([A-Za-z]:\\[^"''\s]+)') { $Matches[1] }
        $f = if ($ref) { Get-S01Facts $ref }; $e = Add-S01Entry 'environment' $src[0] $v.Name $val $f 'env' (Get-S01Lw $src[0]) $true $src[1] $null $null $null
        [void](Add-S01Finding 'persistence.env_hijack' "Environment variable $($v.Name) is set ($($src[1]))" $sev $(if ($v.Name -match 'TLS') { 'hardening' } else { 'suspicious' }) 'medium' @('execution_hijack') @(Get-S01RegEv $src[0] $v.Name $val $null) @($f) @('T1574.012', 'T1574') $ioc.envFp $null $null @($e)); $e
    } }
}
function Invoke-S01ShellFiles {
    $git = Get-S01Val 'HKLM\SOFTWARE\GitForWindows' 'InstallPath'; if (-not $git) { $git = "$env:ProgramFiles\Git" }; $list = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @([Environment]::GetFolderPath('MyDocuments'), "$env:USERPROFILE\Documents") | Select-Object -Unique) { foreach ($n in 'PowerShell\Microsoft.PowerShell_profile.ps1', 'PowerShell\profile.ps1', 'PowerShell\Microsoft.VSCode_profile.ps1', 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1', 'WindowsPowerShell\profile.ps1', 'WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1', 'WindowsPowerShell\Microsoft.VSCode_profile.ps1') { $list.Add(@("$d\$n", 'powershell_profile', 'user')) } }
    foreach ($h in @(@($PSHOME) + @(Get-ChildItem -LiteralPath "$env:ProgramFiles\PowerShell" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName) + @("$Sys32\WindowsPowerShell\v1.0", "$SysWow\WindowsPowerShell\v1.0") | Select-Object -Unique)) { foreach ($n in 'profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.PowerShellISE_profile.ps1', 'Microsoft.VSCode_profile.ps1') { $list.Add(@("$h\$n", 'powershell_profile', 'machine')) } }
    foreach ($n in '.bashrc', '.bash_profile', '.profile', '.bash_login', '.bash_logout', '.zshrc', '.zprofile', '.zshenv') { $list.Add(@("$env:USERPROFILE\$n", 'shell_rc', 'user')) }
    foreach ($n in 'etc\profile', 'etc\bash.bashrc', 'etc\bash.bash_logout') { $list.Add(@("$git\$n", 'shell_rc', 'machine')) }
    foreach ($fi in @(Get-BvsFiles -Path "$git\etc\profile.d" -MaxDepth 0)) { $list.Add(@($fi.FullName, 'shell_rc', 'machine')) }
    foreach ($fi in @(Get-BvsFiles -Path "$env:USERPROFILE\.claude\shell-snapshots" -MaxDepth 0 -Include '*.sh')) { $list.Add(@($fi.FullName, 'claude_snapshot', 'user')) }
    foreach ($w in 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState', 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState', 'Microsoft\Windows Terminal') { $list.Add(@("$env:LOCALAPPDATA\$w\settings.json", 'terminal_settings', 'user')) }
    $gitInstall = (Get-S01Facts "$git\bin\bash.exe").modified
    foreach ($it in $list) {
        $p = $it[0]; if (-not [IO.File]::Exists($p)) { continue }
        $f = Get-S01Facts $p; $text = Read-S01Text $p; $hits = @(if ($text -and $it[1] -ne 'terminal_settings') { Get-S01TextHits $text })
        $x = @{ readable = [bool]$text; size = $f.size; createdDuringScan = [bool]($f.created -gt $run.AuditStartUtc) }
        if ($it[1] -eq 'terminal_settings' -and $text) { try { $j = $text | ConvertFrom-Json; $x.startOnUserLogin = [bool]$j.startOnUserLogin; $cl = @($j.profiles.list | ForEach-Object commandline | Where-Object { $_ }); $x.profileCommands = @($cl | ForEach-Object { Limit-S01 $_ 200 })
                foreach ($c in $cl) { $ind = Get-S01Ind $c (Resolve-S01Cmd $c); if ($ind.encoded -or ($ind.url -and $ind.lolbin)) { $hits += [pscustomobject]@{ rule = 'terminal_profile_payload'; sev = 'critical'; cls = 'compromise'; reason = 'encoded_command'; line = 0; text = (Limit-S01 (Protect-BvsText $c) 160) } } } } catch { } }
        $mod = $it[2] -eq 'machine' -and $p.StartsWith($git, 'OrdinalIgnoreCase') -and $gitInstall -and $f.modified -gt $gitInstall.AddDays(1)
        $e = Add-S01Entry $it[1] (Split-Path $p) (Split-Path $p -Leaf) $null $f 'startup-file' $f.modified $true $it[2] $null $null $x
        $top = Get-S01Top $hits; $sev = if ($top) { $top.sev } elseif ($mod) { 'low' } elseif ($it[2] -eq 'machine' -and $f.writable) { 'medium' }
        if (-not $sev) { $e; continue }
        $why = if ($top) { "contains '$($top.rule)' (line $($top.line))" } elseif ($mod) { 'was modified after Git was installed' } else { 'is writable by a standard user but runs for all users' }
        [void](Add-S01Finding 'persistence.shell_startup_files' "Shell startup file $(Split-Path $p -Leaf) $why" $sev $(if ($top) { $top.cls } elseif ($mod) { 'suspicious' } else { 'hardening' }) 'medium' (@('persistence') + @($hits | ForEach-Object reason)) (@([ordered]@{ type = 'file'; path = $p; modified = (ConvertTo-S01Iso $f.modified); created = (ConvertTo-S01Iso $f.created) }) + @($hits | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'content'; rule = $_.rule; line = $_.line; text = $_.text } })) @($f) @('T1546.013', 'T1546.004') $ioc.shellFp $null $null @($e))
        $e
    }
}
#endregion

#region ---------- main ----------
function Invoke-S01Check([string]$id, [string]$desc, [scriptblock]$sb) {
    $d0 = $Denied.Count; $i0 = $ItemErrs.Count; $null = Invoke-BvsCheck -Run $run -Id $id -Description $desc -Script $sb
    $c = $run.Checks[$run.Checks.Count - 1]; if (($Denied.Count -gt $d0 -or $ItemErrs.Count -gt $i0) -and $c.status -eq 'ok') { $c.status = 'partial'; $c.reason = "$($Denied.Count - $d0) registry key(s) not readable without elevation; $($ItemErrs.Count - $i0) item error(s) in errors[]" }
}
Invoke-S01Check 'persistence.process_context' 'Running process paths (marks autostarts that run now)' { foreach ($p in @(Get-BvsProcessTable)) { if ($p.Path) { [void]$Running.Add($p.Path) } }; $Running }
Invoke-S01Check 'persistence.run_keys' 'Run/RunOnce/RunOnceEx/RunServices/Policies/TS-Install/Windows Load (HKLM+HKCU, 64+32) with StartupApproved state and key LastWrite' { Invoke-S01RunKeys }
Invoke-S01Check 'persistence.startup_folders' 'User and common Startup folders (.lnk via WScript.Shell read-only, .url, scripts, executables, folder redirection)' { Invoke-S01StartupFolders }
Invoke-S01Check 'persistence.winlogon' 'Winlogon Shell/Userinit/Taskman/AppSetup/GinaDLL/VmApplet (HKLM+HKCU), SafeBoot AlternateShell, RDP startup, BootExecute and other Session Manager execute values' { Invoke-S01SingleValues 'winlogon' }
Invoke-S01Check 'persistence.logon_hooks' 'Command Processor AutoRun, UserInitMprLogonScript, screensaver' { Invoke-S01SingleValues 'logon_hooks' }
Invoke-S01Check 'persistence.active_setup' 'Active Setup Installed Components StubPath (HKLM 64+32, HKCU)' { Invoke-S01ActiveSetup }
Invoke-S01Check 'persistence.injection' 'AppInit_DLLs (+LoadAppInit_DLLs), Office test DLL, AeDebug and .NET JIT debuggers' { Invoke-S01SingleValues 'injection' }
Invoke-S01Check 'persistence.dll_hooks' 'LSA auth/security/notification packages + OSConfig, SSPs, AppCertDlls, network and credential providers, print monitors/processors, NetSh helpers, time providers, GP extensions, Winlogon Notify' { Invoke-S01DllPoints }
Invoke-S01Check 'persistence.ifeo' 'Image File Execution Options Debugger/filters/GlobalFlag, SilentProcessExit MonitorProcess, VerifierDlls (64+32)' { Invoke-S01Ifeo }
Invoke-S01Check 'persistence.class_hijack' 'HKCU UAC-bypass class keys (incl. DelegateExecute), HKLM executable open-command defaults, HKCU executable extension overrides' { Invoke-S01ClassHijack }
Invoke-S01Check 'persistence.accessibility' 'sethc/utilman/osk/Magnify/Narrator/DisplaySwitch/AtBroker signer + OriginalFilename, registered assistive technologies' { Invoke-S01Accessibility }
Invoke-S01Check 'persistence.com_hijack' 'HKCU CLSID InprocServer32/LocalServer32/TreatAs/ScriptletURL (64+32) and HKLM shadowing' { Invoke-S01ComHijack }
Invoke-S01Check 'persistence.shell_extensions' 'ShellServiceObjectDelayLoad, SharedTaskScheduler, ShellServiceObjects, icon overlays, BHOs, Approved list and context-menu/copy-hook/drag-drop handlers' { Invoke-S01ShellExt }
Invoke-S01Check 'persistence.services' 'Win32_Service + registry: ImagePath, ServiceDll, FailureCommand, signer, user-writable, key LastWrite, unquoted paths' { Invoke-S01Services }
Invoke-S01Check 'persistence.drivers' 'Win32_SystemDriver: resolved path, signer, SHA-256 (local only)' { Invoke-S01Drivers }
Invoke-S01Check 'persistence.loldrivers' 'LOLDrivers list (downloaded via Invoke-BvsIntel, hashes compared locally, nothing sent)' { Invoke-S01LolDrivers }
Invoke-S01Check 'persistence.scheduled_tasks' 'Get-ScheduledTask + Export-ScheduledTask XML: actions, ComHandler DLLs, principal/RunLevel, hidden, triggers, registration date' { Invoke-S01Tasks }
Invoke-S01Check 'persistence.task_sd_hidden' 'TaskCache\Tree tasks without SD value (hidden-task technique)' { Invoke-S01TaskCache }
Invoke-S01Check 'persistence.wmi_subscriptions' 'WMI __EventFilter/__EventConsumer/__FilterToConsumerBinding in root\subscription and root\default' { Invoke-S01Wmi }
Invoke-S01Check 'persistence.bits_jobs' 'BITS jobs with notify command lines' { Invoke-S01Bits }
Invoke-S01Check 'persistence.env_hijack' 'COR_PROFILER, NODE_OPTIONS, JAVA_TOOL_OPTIONS, proxies, ANTHROPIC_BASE_URL and similar (HKCU + machine environment)' { Invoke-S01Env }
Invoke-S01Check 'persistence.shell_startup_files' 'PowerShell profiles (7 + 5.1 + PSHOME), Git Bash rc and etc files, Windows Terminal settings, Claude Code shell snapshots' { Invoke-S01ShellFiles }
Invoke-S01Check 'persistence.expected_verification' 'Known-good items (expected.json) verified by signer and folder; aggregated hygiene findings' {
    $ok = @($Entries | Where-Object { $_.expected } | ForEach-Object { [ordered]@{ expected = $_.expected; invalidated = $_.expectedInvalidated; category = $_.category; name = $_.name; target = $_.target; signer = $_.signer; folderClass = $_.folderClass; flagged = $_.severity } })
    if ($ok.Count) { [void](Add-S01Finding 'persistence.expected_verification' "Known startup entries, tasks and services checked against expected.json ($($ok.Count))" 'info' 'info' 'high' @('expected_match') @($ok | Select-Object -First 80) @() @() 'These match config\local\expected.json; each target was still checked for signer and folder.' 'No action needed unless an item shows invalidated=true.' $null @()) }
    Close-S01Agg; $ok
}
$stale = @(foreach ($m in $Approved.Values) { foreach ($s in $m.Values) { if (-not $s.used) { [ordered]@{ key = $s.key; name = $s.name; raw = $s.raw; enabled = $s.enabled; disabledAt = (ConvertTo-S01Iso $s.changed) } } } })
Add-BvsInventory -Run $run -Name 'autostarts' -Data @($Entries)
Add-BvsInventory -Run $run -Name 'drivers' -Data @($script:DriverRows)
Add-BvsInventory -Run $run -Name 'startupApprovedStale' -Data $stale
$byCat = [ordered]@{}; foreach ($g in ($Entries | Group-Object category)) { $byCat[$g.Name] = $g.Count }
Add-BvsInventory -Run $run -Name 'summary' -Data ([ordered]@{ entries = $Entries.Count; flagged = @($Entries | Where-Object severity -ne 'none').Count; byCategory = $byCat; deniedRegistryKeys = $Denied.Count; seconds = [int]$Timer.Elapsed.TotalSeconds })
$sum = Complete-BvsRun -Run $run
$up = [regex]::Escape($env:USERPROFILE)
"S01 done in $([int]$Timer.Elapsed.TotalSeconds)s: $($run.Checks.Count) checks, $($Entries.Count) autostart entries, findings $($sum.Findings) [$($sum.BySeverity)], errors $($sum.Errors)"
foreach ($c in $run.Checks) { '  {0,-34} {1,-11} {2,5} items {3,7} ms {4}' -f $c.id, $c.status, $c.items, $c.ms, (Limit-S01 "$($c.reason)" 70) }
foreach ($f in ($run.Findings | Where-Object severity -ne 'info' | Sort-Object { - $Rank[$_.severity] } | Select-Object -First 14)) { (Protect-BvsText ('  {0} {1}/{2}: {3}' -f $f.id, $f.severity, $f.class, (Limit-S01 $f.title 150))) -replace $up, '%USERPROFILE%' }
#endregion
