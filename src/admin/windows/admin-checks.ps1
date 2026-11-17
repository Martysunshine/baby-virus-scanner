#Requires -Version 7.2
<#
.SYNOPSIS
    Elevated, READ-ONLY checks for baby-virus-scanner (Windows). Standalone: does not import lib\.
.DESCRIPTION
    Runs once with admin rights (started by src\admin\windows\launch-elevated.ps1, hash-pinned).
    Reads what a normal user cannot: Security log, BAM, Prefetch, hidden scheduled tasks, full process
    command lines, Defender exclusions, SMB sessions, boot integrity, disk reliability, DISM/sfc VERIFY-only.
    Changes nothing. No network. Writes only to data\<scanId>\admin\ (one JSON per section + admin-meta.json).
.PARAMETER Quick   Skip the slow DISM /ScanHealth and sfc /verifyonly steps.
.PARAMETER DryRun  Write into <OutDir>\dryrun (for testing without elevation).
#>
[CmdletBinding()]
param([string]$ScanId, [string]$OutDir, [switch]$Quick, [switch]$DryRun)
$ErrorActionPreference = 'Stop'
$BvsRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
if (-not $ScanId) { $ScanId = (Get-Content -LiteralPath (Join-Path $BvsRoot 'data\latest.txt') -Raw).Trim() }
if (-not $OutDir) { $OutDir = Join-Path $BvsRoot "data\$ScanId\admin" }
if ($DryRun) { $OutDir = Join-Path $OutDir 'dryrun' }
[void][IO.Directory]::CreateDirectory($OutDir)
$utf8 = [Text.UTF8Encoding]::new($false)
$since = (Get-Date).AddDays(-90)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------- masking (same semantics as Protect-BvsSecret / Protect-BvsText) ----------
$rules = foreach ($r in (Get-Content -LiteralPath (Join-Path $BvsRoot 'src\config\secret-patterns.json') -Raw | ConvertFrom-Json).rules) {
    [pscustomobject]@{ Group = [int]$r.group; Rx = [regex]::new($r.regex, 'Compiled, CultureInvariant', [TimeSpan]::FromSeconds(5)) }
}
function Hide-Secret([string]$v) {
    if ([string]::IsNullOrEmpty($v)) { return $v }
    if ($v -match 'PRIVATE KEY|PuTTY-User-Key') { return '[PRIVATE KEY REDACTED]' }
    if ($v.Length -lt 20) { return "[REDACTED:$($v.Length)]" }
    $v.Substring(0, 4) + [char]0x2026 + $v.Substring($v.Length - 4)
}
function Hide-Text([string]$t) {
    if ([string]::IsNullOrEmpty($t)) { return $t }
    foreach ($r in $rules) {
        $ms = $r.Rx.Matches($t); if ($ms.Count -eq 0) { continue }
        $sb = [Text.StringBuilder]::new(); $last = 0
        foreach ($m in $ms) {
            $g = if ($r.Group -gt 0 -and $m.Groups[$r.Group].Success) { $m.Groups[$r.Group] } else { $m }
            if ($g.Index -lt $last) { continue }
            [void]$sb.Append($t, $last, $g.Index - $last).Append((Hide-Secret $g.Value)); $last = $g.Index + $g.Length
        }
        $t = $sb.Append($t, $last, $t.Length - $last).ToString()
    }
    $t
}

# ---------- section runner ----------
$meta = [ordered]@{ schema = 'bvs.admin/1'; scanId = $ScanId; host = $env:COMPUTERNAME; elevated = $isAdmin; quick = [bool]$Quick; started = (Get-Date).ToUniversalTime().ToString('o'); sections = [ordered]@{} }
function Save-Json([string]$Name, $Obj) {
    $json = Hide-Text ($Obj | ConvertTo-Json -Depth 12 -WarningAction SilentlyContinue)
    [IO.File]::WriteAllText((Join-Path $OutDir "$Name.json"), $json, $utf8)
}
function Invoke-Section([string]$Name, [scriptblock]$Body) {
    $sw = [Diagnostics.Stopwatch]::StartNew(); Write-Host ("[{0:HH:mm:ss}] {1} ..." -f (Get-Date), $Name)
    $status = 'ok'; $err = $null
    try { $data = & $Body; Save-Json $Name $data }
    catch {
        $err = $_.Exception.Message
        $status = if ($err -match '(?i)access|denied|privilege|elevat|unauthori[sz]ed|0x80070005') { 'needs_admin' } else { 'error' }
    }
    $meta.sections[$Name] = [ordered]@{ status = $status; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); error = (Hide-Text $err) }
    $meta.finished = (Get-Date).ToUniversalTime().ToString('o')
    [IO.File]::WriteAllText((Join-Path $OutDir 'admin-progress.json'), ($meta | ConvertTo-Json -Depth 6), $utf8)
}
function Get-EventData($e) { $d = [ordered]@{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }; $d }
function Get-Events([hashtable]$Filter, [int]$Max = 20000) { try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { if ($_.Exception.Message -match 'No events were found') { @() } else { throw } } }
function Get-LogWindow([string]$Log) {
    $first = Get-WinEvent -LogName $Log -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
    $last = Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction SilentlyContinue
    [ordered]@{ log = $Log; oldest = $first.TimeCreated; newest = $last.TimeCreated }
}
function Test-PrivateIp([string]$ip) { $ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|fe80:|-$)' -or [string]::IsNullOrEmpty($ip) }

# 1. Security log (90 days)
Invoke-Section 'security-log' {
    $logons = Get-Events @{ LogName = 'Security'; Id = 4624; StartTime = $since } 40000
    $byKey = @{}
    foreach ($e in $logons) {
        $d = Get-EventData $e
        $k = '{0}|{1}|{2}' -f $d.LogonType, $d.TargetUserName, $d.IpAddress
        if (-not $byKey[$k]) { $byKey[$k] = [ordered]@{ logonType = $d.LogonType; user = $d.TargetUserName; domain = $d.TargetDomainName; ip = $d.IpAddress; workstation = $d.WorkstationName; package = $d.AuthenticationPackageName; count = 0; first = $e.TimeCreated; last = $e.TimeCreated } }
        $byKey[$k].count++; if ($e.TimeCreated -lt $byKey[$k].first) { $byKey[$k].first = $e.TimeCreated }; if ($e.TimeCreated -gt $byKey[$k].last) { $byKey[$k].last = $e.TimeCreated }
    }
    $summary = @($byKey.Values | Sort-Object { - $_.count })
    $remote = @($summary | Where-Object { $_.logonType -in '3', '10' -and -not (Test-PrivateIp $_.ip) })
    $failed = Get-Events @{ LogName = 'Security'; Id = 4625; StartTime = $since } 20000
    $failSum = $failed | ForEach-Object { $d = Get-EventData $_; [pscustomobject]@{ user = $d.TargetUserName; ip = $d.IpAddress; type = $d.LogonType; status = $d.Status; t = $_.TimeCreated } } |
        Group-Object user, ip, type | ForEach-Object { [ordered]@{ key = $_.Name; count = $_.Count; last = ($_.Group | Sort-Object t | Select-Object -Last 1).t } } | Sort-Object { - $_.count } | Select-Object -First 50
    $acctIds = 4720, 4722, 4724, 4725, 4726, 4738, 4728, 4732, 4756, 4729, 4733, 1102, 4719, 4697, 4698, 4699, 4700, 4702, 4648
    $changes = foreach ($e in (Get-Events @{ LogName = 'Security'; Id = $acctIds; StartTime = $since } 5000)) {
        $d = Get-EventData $e
        [ordered]@{ id = $e.Id; time = $e.TimeCreated; subject = $d.SubjectUserName; target = $d.TargetUserName; member = $d.MemberName; group = $d.TargetUserName; task = $d.TaskName; service = $d.ServiceName; image = $d.ServiceFileName; process = $d.ProcessName; targetServer = $d.TargetServerName }
    }
    [ordered]@{ window = (Get-LogWindow 'Security'); logonSummary = $summary | Select-Object -First 200; remoteLogonsFromPublicIps = $remote; failedLogons = @($failSum); failedTotal = $failed.Count
        accountAndPolicyEvents = @($changes | Where-Object { $_.id -ne 4648 }); explicitCredentialUse = @($changes | Where-Object { $_.id -eq 4648 } | Select-Object -First 100); logCleared = @($changes | Where-Object { $_.id -eq 1102 }) }
}

# 2. Audit policy
Invoke-Section 'auditpol' { $raw = (& auditpol.exe /get /category:* /r) | ConvertFrom-Csv; @($raw | ForEach-Object { [ordered]@{ subcategory = $_.Subcategory; guid = $_.'Subcategory GUID'; setting = $_.'Inclusion Setting' } }) }

# 3. Boot / startup performance
Invoke-Section 'boot-performance' {
    $ev = Get-Events @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100, 101, 102, 103, 106, 109, 200, 203; StartTime = $since } 3000
    $boots = foreach ($e in ($ev | Where-Object Id -eq 100)) { $d = Get-EventData $e; [ordered]@{ time = $e.TimeCreated; bootMs = [int]$d.BootTime; mainPathMs = [int]$d.MainPathBootTime; postBootMs = [int]$d.BootPostBootTime } }
    $degraders = foreach ($e in ($ev | Where-Object Id -in 101, 102, 103, 106, 109)) { $d = Get-EventData $e; [ordered]@{ id = $e.Id; time = $e.TimeCreated; name = $(if ($d.FriendlyName) { $d.FriendlyName } else { $d.Name }); file = $d.FileName; totalMs = [int]$d.TotalTime; degradationMs = [int]$d.DegradationTime } }
    $startupInfo = @()
    $siDir = Join-Path $env:SystemRoot 'System32\wdi\LogFiles\StartupInfo'
    $latest = Get-ChildItem -LiteralPath $siDir -Filter '*.xml' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
    foreach ($x in $latest) {
        $doc = [xml](Get-Content -LiteralPath $x.FullName -Raw)
        foreach ($p in $doc.StartupData.Process) {
            # <CpuUsage Unit="ms">56</CpuUsage>: an element with an attribute comes back as an XmlElement, so read its text.
            $num = { param($v) $t = if ($v -is [System.Xml.XmlElement]) { $v.InnerText } else { "$v" }; $d = 0.0; if ([double]::TryParse($t, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $d } else { 0.0 } }
            $cpu = & $num $p.CpuUsage; $disk = & $num $p.DiskUsage
            $impact = if ($cpu -gt 1000 -or $disk -gt 3MB) { 'High' } elseif ($cpu -ge 300 -or $disk -ge 300KB) { 'Medium' } else { 'Low' }
            $startupInfo += [ordered]@{ file = $x.Name; process = $p.Name; commandLine = (Hide-Text $p.CommandLine); cpuMs = $cpu; diskBytes = $disk; impact = $impact }
        }
    }
    [ordered]@{ window = (Get-LogWindow 'Microsoft-Windows-Diagnostics-Performance/Operational'); boots = @($boots); degraders = @($degraders); startupInfo = $startupInfo }
}

# 4. BAM (last execution per program, per user)
Invoke-Section 'bam' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
    foreach ($sidKey in (Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
        foreach ($p in $sidKey.Property) {
            $v = $sidKey.GetValue($p)
            if ($v -is [byte[]] -and $v.Length -ge 8) { [ordered]@{ sid = $sidKey.PSChildName; path = $p; lastRunUtc = [datetime]::FromFileTimeUtc([BitConverter]::ToInt64($v, 0)) } }
        }
    }
}

# 5. Prefetch (names + first/last run times only)
Invoke-Section 'prefetch' {
    $flag = '(?i)^(PSEXEC|PAEXEC|MIMIKATZ|PROCDUMP|RCLONE|NGROK|CLOUDFLARED|ANYDESK|CLIENT32|NETSUPPORT|SCREENCONNECT|RUSTDESK|TEAMVIEWER|PLINK|CHISEL|FRPC|NC|NCAT|ADFIND|SHARPHOUND|LAZAGNE|WEBBROWSERPASSVIEW|NIRSOFT)'
    Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Prefetch') -Filter '*.pf' -ErrorAction Stop | ForEach-Object {
        $exe = ($_.BaseName -replace '-[0-9A-F]{8}$', '')
        [ordered]@{ exe = $exe; firstRun = $_.CreationTime; lastRun = $_.LastWriteTime; flagged = [bool]($exe -match $flag) }
    } | Sort-Object { $_.lastRun } -Descending
}

# 6. Hidden scheduled tasks (TaskCache entries without SD, or missing from Get-ScheduledTask)
Invoke-Section 'tasks-hidden' {
    $tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    $visible = @{}; foreach ($t in (Get-ScheduledTask)) { $visible[($t.TaskPath + $t.TaskName).TrimStart('\')] = $true }
    $rows = foreach ($k in (Get-ChildItem -LiteralPath $tree -Recurse -ErrorAction Stop)) {
        $props = $k.Property
        if ($props -notcontains 'Id') { continue }
        $rel = ($k.Name -replace '^.*\\TaskCache\\Tree\\', '')
        [ordered]@{ task = $rel; hasSD = ($props -contains 'SD'); index = $k.GetValue('Index'); visibleToTaskScheduler = [bool]$visible[$rel] }
    }
    $taskFiles = Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'System32\Tasks') -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ path = $_.FullName.Substring($env:SystemRoot.Length); size = $_.Length; modified = $_.LastWriteTime } }
    [ordered]@{ suspicious = @($rows | Where-Object { -not $_.hasSD -or $_.index -eq 0 -or -not $_.visibleToTaskScheduler }); total = @($rows).Count; taskFiles = @($taskFiles) }
}

# 7. Processes with full command lines, owners, signatures
Invoke-Section 'processes' {
    $owners = @{}; foreach ($p in (Get-Process -IncludeUserName -ErrorAction SilentlyContinue)) { $owners[$p.Id] = $p.UserName }
    $sigCache = @{}
    foreach ($p in (Get-CimInstance Win32_Process)) {
        $path = $p.ExecutablePath; $sig = $null
        if ($path) {
            if (-not $sigCache.ContainsKey($path)) { $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue; $sigCache[$path] = [ordered]@{ status = [string]$s.Status; signer = $s.SignerCertificate.Subject } }
            $sig = $sigCache[$path]
        }
        [ordered]@{ pid = $p.ProcessId; ppid = $p.ParentProcessId; name = $p.Name; path = $path; owner = $owners[[int]$p.ProcessId]; commandLine = (Hide-Text $p.CommandLine); started = $p.CreationDate; signature = $sig }
    }
}

# 8. Defender exclusions and detection history listing
Invoke-Section 'defender' {
    $ex = [ordered]@{}
    foreach ($kind in 'Paths', 'Processes', 'Extensions', 'IpAddresses', 'TemporaryPaths') {
        foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions') {
            $k = Join-Path $root $kind
            if (Test-Path -LiteralPath $k) { $ex["$root\$kind"] = @((Get-Item -LiteralPath $k).Property) }
        }
    }
    $pref = try { Get-MpPreference -ErrorAction Stop | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, DisableRealtimeMonitoring } catch { "Get-MpPreference failed: $($_.Exception.Message)" }
    $hist = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Scans\History\Service\DetectionHistory'
    $files = if (Test-Path -LiteralPath $hist) { @(Get-ChildItem -LiteralPath $hist -Recurse -File | ForEach-Object { [ordered]@{ name = $_.Name; modified = $_.LastWriteTime } }) } else { @() }
    [ordered]@{ registryExclusions = $ex; mpPreference = $pref; detectionHistoryFiles = $files }
}

# 9. SMB
Invoke-Section 'smb' {
    [ordered]@{
        shares   = @(Get-SmbShare | Select-Object Name, Path, Description, ShareType, Special, EncryptData, FolderEnumerationMode)
        access   = @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { Get-SmbShareAccess -Name $_.Name } | Select-Object Name, AccountName, AccessControlType, AccessRight)
        server   = (Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature, EncryptData)
        sessions = @(Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists, Dialect)
        openFiles = @(Get-SmbOpenFile).Count
    }
}

# 10. OpenSSH server
Invoke-Section 'openssh-server' {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object Name, State
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
    $ak = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $fps = if (Test-Path -LiteralPath $ak) { @(& ssh-keygen.exe -l -f $ak 2>&1 | ForEach-Object { "$_" }) } else { @() }
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    $cfgLines = if (Test-Path -LiteralPath $cfg) { @(Get-Content -LiteralPath $cfg | Where-Object { $_ -match '^\s*[^#\s]' }) } else { @() }
    [ordered]@{ capability = $cap; service = $svc; adminAuthorizedKeys = $fps; sshdConfigActiveLines = $cfgLines }
}

# 11. Boot integrity
Invoke-Section 'boot-integrity' {
    $bcd = @(& bcdedit.exe /enum '{current}' 2>&1 | ForEach-Object { "$_" })
    $sb = try { Confirm-SecureBootUEFI } catch { "unavailable: $($_.Exception.Message)" }
    $tpm = try { Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManufacturerIdTxt } catch { "unavailable: $($_.Exception.Message)" }
    $bl = try { @(Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod) } catch { @(& manage-bde.exe -status 2>&1 | ForEach-Object { "$_" }) }
    $dg = try { Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning, CodeIntegrityPolicyEnforcementStatus } catch { $null }
    [ordered]@{ bcdedit = $bcd; testSigningOrDebug = @($bcd | Where-Object { $_ -match '(?i)^(testsigning|nointegritychecks|debug|bootdebug)\s+(Yes|On)' }); secureBoot = $sb; tpm = $tpm; bitlocker = $bl; deviceGuard = $dg }
}

# 12. Logon sessions now
Invoke-Section 'logon-sessions' {
    $q = if (Get-Command quser.exe -ErrorAction SilentlyContinue) { @(& quser.exe 2>&1 | ForEach-Object { "$_" }) } else { @('quser not available on this Windows edition') }
    $types = @{ 2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Unlock'; 8 = 'NetworkCleartext'; 9 = 'NewCredentials'; 10 = 'RemoteInteractive'; 11 = 'CachedInteractive' }
    $users = @{}; foreach ($l in (Get-CimInstance Win32_LoggedOnUser)) { $users[$l.Dependent.LogonId] = "$($l.Antecedent.Domain)\$($l.Antecedent.Name)" }
    $sessions = Get-CimInstance Win32_LogonSession | Where-Object { $_.LogonType -in 2, 3, 7, 8, 9, 10, 11 } | ForEach-Object { [ordered]@{ logonId = $_.LogonId; type = $types[[int]$_.LogonType]; user = $users[$_.LogonId]; start = $_.StartTime; package = $_.AuthenticationPackage } }
    [ordered]@{ quser = $q; sessions = @($sessions) }
}

# 13. Firewall log (stats only)
Invoke-Section 'firewall-log' {
    $log = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    if (-not (Test-Path -LiteralPath $log)) { return [ordered]@{ enabled = $false } }
    $lines = Get-Content -LiteralPath $log -Tail 50000 | Where-Object { $_ -and $_ -notmatch '^#' }
    $drops = $lines | Where-Object { $_ -match ' DROP ' }
    [ordered]@{ enabled = $true; lines = @($lines).Count; drops = @($drops).Count; topDroppedSources = @($drops | ForEach-Object { ($_ -split ' ')[4] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Name) x$($_.Count)" }) }
}

# 14. Storage health (fast parts)
Invoke-Section 'disk-health' {
    $rel = Get-PhysicalDisk | ForEach-Object { $d = $_; $r = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        [ordered]@{ disk = $d.FriendlyName; media = [string]$d.MediaType; health = [string]$d.HealthStatus; temperatureC = $r.Temperature; temperatureMaxC = $r.TemperatureMax; wearPercent = $r.Wear; readErrorsTotal = $r.ReadErrorsTotal; readErrorsUncorrected = $r.ReadErrorsUncorrected; writeErrorsTotal = $r.WriteErrorsTotal; writeErrorsUncorrected = $r.WriteErrorsUncorrected; powerOnHours = $r.PowerOnHours; startStopCycles = $r.StartStopCycleCount } }
    $dirty = @(& fsutil.exe dirty query "$($env:SystemDrive)" 2>&1 | ForEach-Object { "$_" })
    $acs = @(& dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() })
    $shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Select-Object InstallDate, VolumeName, ClientAccessible)
    $rp = try { @(Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, CreationTime) } catch { @() }
    [ordered]@{ reliability = @($rel); dirtyBit = $dirty; componentStore = $acs; shadowCopies = $shadows; restorePoints = $rp }
}

# 15. System file integrity (VERIFY ONLY - never repairs)
if (-not $Quick) {
    Invoke-Section 'dism-scanhealth' { [ordered]@{ output = @(& dism.exe /Online /Cleanup-Image /ScanHealth 2>&1 | ForEach-Object { "$_" } | Where-Object { $_.Trim() }) } }
    Invoke-Section 'sfc-verifyonly' {
        $out = (& sfc.exe /verifyonly 2>&1 | ForEach-Object { "$_" }) -join "`n" -replace "`0", ''
        $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
        $sr = if (Test-Path -LiteralPath $cbs) { @(Get-Content -LiteralPath $cbs -Tail 4000 | Where-Object { $_ -match '\[SR\]' } | Select-Object -Last 60) } else { @() }
        [ordered]@{ output = @($out -split "`n" | Where-Object { $_.Trim() }); cbsSrLines = $sr }
    }
}

$meta.finished = (Get-Date).ToUniversalTime().ToString('o')
[IO.File]::WriteAllText((Join-Path $OutDir 'admin-meta.json'), ($meta | ConvertTo-Json -Depth 6), $utf8)
Write-Host "`nAdmin checks finished. Sections:"
$meta.sections.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-18} {1,-12} {2,6}s {3}" -f $_.Key, $_.Value.status, $_.Value.seconds, $_.Value.error) }
