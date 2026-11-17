#Requires -Version 7.2
<#
.SYNOPSIS
    S03 - Accounts, remote access and security posture (read-only Windows collector).
.DESCRIPTION
    Local accounts, privileged groups (by SID), hidden users, profiles; RDP/RDPWrap, Remote Assistance,
    OpenSSH, WinRM, Quick Assist; remote-control/RMM/tunnel inventory driven by S03-remote-tools.json;
    security posture; trusted roots vs Microsoft's AuthRoot CTL; hosts file and proxies.
    Writes only data\<scan>\security\S03.json, logs\S03.log and the CTL download/extraction under intel\.
    Methodology: docs\playbooks\S03-accounts-posture.md
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S03-accounts-posture.ps1 [-Offline]
#>
[CmdletBinding()]
param([switch]$Offline, [int]$RecentDays = 90, [int]$SweepDepth = 3)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S03 -Area security
$Now = [datetime]::UtcNow; $Recent = $Now.AddDays(-$RecentDays); $D30 = $Now.AddDays(-30)
$Rank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$Ref = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S03-reference.json') -Raw | ConvertFrom-Json
$Cat = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S03-remote-tools.json') -Raw | ConvertFrom-Json
$S = @{ Users = @(); Groups = @(); Hidden = @(); Profiles = @(); Svc = @{}; Services = @(); Procs = @(); Uninst = @(); Wsc = @()
    AdminSids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); Posture = [Collections.Generic.List[object]]::new()
    Remote = [ordered]@{}; Proxy = [ordered]@{}; AvastInstalled = $false; AvastOn = $null; AvastOld = $null; AvastRoots = $null; Fw3p = $false; Ctl = $null; IsHome = $false; Domain = $false }
$Hits = @{}

#region ---------- helpers ----------
function ConvertTo-Iso($v) {
    if ($null -eq $v -or "$v" -eq '') { return $null }
    try {
        if ($v -is [datetimeoffset]) { $v = $v.UtcDateTime }
        elseif ($v -isnot [datetime]) { $v = [datetimeoffset]::Parse([string]$v, [cultureinfo]::InvariantCulture).UtcDateTime }
        if ($v.Year -lt 1980) { return $null }
        if ($v.Kind -eq 'Unspecified') { $v = [datetime]::SpecifyKind($v, 'Local') }
        $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    } catch { $null }
}
function Get-RegV([string]$Path, [string]$Name, [string]$View = '64') {
    try { $k = Open-BvsRegKey -Path $Path -View $View; if (-not $k) { return $null }; try { $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') } finally { $k.Dispose() } } catch { $null }
}
function Get-RegMap([string]$Path, [string]$View = '64') { $m = [ordered]@{}; try { foreach ($v in @(Get-BvsRegValues -Path $Path -View $View)) { if ($v) { $m[$v.Name] = $v.Value } } } catch { }; $m }
function Get-RegTree([string]$Path, [int]$Depth = 0) {
    try { $vals = @(Get-BvsRegValues -Path $Path); $subs = @(Get-BvsRegSubKeys -Path $Path) } catch { return [pscustomobject]@{ Key = $Path; Name = $null; Value = $null; Denied = $true } }
    foreach ($v in $vals) { if ($v) { [pscustomobject]@{ Key = $Path; Name = $v.Name; Value = $v.Value; Denied = $false } } }
    if ($Depth -lt 4) { foreach ($sk in $subs) { if ($sk) { Get-RegTree "$Path\$sk" ($Depth + 1) } } }
}
function Ev([string]$Type, [string]$Path, [string]$Name, $Value, [string]$Note) {
    $e = [ordered]@{ type = $Type }; if ($Path) { $e.path = $Path }; if ($Name) { $e.name = $Name }
    if ($null -ne $Value) { $e.value = if ($Value -is [byte[]]) { "<binary $($Value.Length) bytes>" } else { $Value } }
    if ($Note) { $e.note = $Note }; $e
}
function Add-Posture([string]$Area, [string]$Setting, $Value, [string]$Expected, [string]$Status, [string]$Source) {
    $S.Posture.Add([ordered]@{ area = $Area; setting = $Setting; value = $Value; expected = $Expected; status = $Status; source = $Source })
}
function Test-Cond([string]$c, [hashtable]$Ctx) {
    if ($c -match '(?i)not signed by (.+)$') {
        if (-not $Ctx.ContainsKey('Signers')) { return $null }; $sg = @($Ctx.Signers); if (-not $sg.Count) { return $null }
        $w = [regex]::Escape($Matches[1].Trim()); return [bool]@($sg | Where-Object { "$_" -notmatch $w }).Count
    }
    if ($c -match '(?i)^Avast not installed') { return (-not $S.AvastInstalled) }
    if ($c -match '(?i)^Avast not .on') { if ($null -eq $S.AvastOn) { return $null }; return (-not $S.AvastOn) }
    if ($c -match '(?i)^Avast definitions out of date') { return $S.AvastOld }
    if ($c -match '(?i)several Avast-named roots') { if ($null -eq $S.AvastRoots) { return $null }; return ($S.AvastRoots -gt 1) }
    if ($c -match '(?i)^member of Administrators' -and $Ctx.ContainsKey('IsAdmin')) { return [bool]$Ctx.IsAdmin }
    $null
}
function Resolve-Exp($Item, [hashtable]$Ctx = @{}) {
    if (-not $Item) { return $null }
    $conds = @(foreach ($c in @($Item.invalidIf)) { if ($c) { [ordered]@{ condition = [string]$c; result = (Test-Cond ([string]$c) $Ctx) } } })
    [ordered]@{ id = $Item.id; reason = $Item.reason; cancelled = [bool]@($conds | Where-Object { $_.result -eq $true }).Count
        invalidIf = $conds; confirmWithUser = [bool]$Item.confirmWithUser; severityCap = $Item.severityCap; class = $Item.class }
}
function Add-Finding([string]$Check, [string]$Title, [string]$Sev, [string]$Class, [string]$Conf = 'medium', [string[]]$Reasons = @(),
    [object[]]$Evidence = @(), [hashtable]$Entities = @{}, [string]$Rec = '', [string]$Fp = '', [string[]]$Mitre = @(), $Exp = $null) {
    $rs = [Collections.Generic.List[string]]::new(); foreach ($r in $Reasons) { if ($r -and -not $rs.Contains($r)) { $rs.Add($r) } }
    if ($Exp) {
        if (-not $Exp.cancelled) {
            $cap = if ($Exp.severityCap) { [string]$Exp.severityCap } else { 'info' }
            if ($Rank[$Sev] -gt $Rank[$cap]) { $Sev = $cap }
            if ($Exp.class) { $Class = [string]$Exp.class } elseif ($Sev -eq 'info') { $Class = 'info' }
            $rs.Add('expected_match')
        } else { $rs.Add('expected_cancelled') }
    }
    $ent = [ordered]@{ files = @(); processes = @(); network = @(); registry = @(); accounts = @() }
    foreach ($k in $Entities.Keys) { $ent[$k] = @($Entities[$k]) }
    New-BvsFinding -Run $run -Check $Check -Title $Title -Severity $Sev -Class $Class -Confidence $Conf -Reasons @($rs) -Evidence $Evidence `
        -Entities $ent -Recommendation $Rec -FpNotes $Fp -Mitre $Mitre -Expected $Exp
}
function Get-FileFacts([string]$Path, [switch]$Hash) {
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim('"')); $o = [ordered]@{ path = $p; exists = $false }
    try {
        $fi = [IO.FileInfo]::new($p); if (-not $fi.Exists) { return $o }
        $sig = Get-BvsSignature -Path $fi.FullName
        $o.exists = $true; $o.size = $fi.Length; $o.created = ConvertTo-Iso $fi.CreationTimeUtc; $o.modified = ConvertTo-Iso $fi.LastWriteTimeUtc
        $o.sig = $sig.Status; $o.signer = $sig.Signer; $o.userWritable = Test-BvsUserWritable -Path $fi.DirectoryName
        if ($Hash) { $o.sha256 = Get-BvsHash -Path $fi.FullName -MaxBytes 200MB }
    } catch { }
    $o
}
function Get-ExePath([string]$Cmd) {
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = $Cmd.Trim(); while ($c.StartsWith('""')) { $c = $c.Substring(1) }; $c = $c -replace '^"([^"]+)""', '"$1"'
    try { $r = Resolve-BvsCommandLine $c; if ($r.Executable) { return $r } } catch { }; $null
}
function Get-Leaf([string]$p) { if ($p) { try { return [IO.Path]::GetFileName($p.Trim('"')).ToLowerInvariant() } catch { } }; $null }
function Test-Exe($t, [string]$leaf, [switch]$Files) {
    if (-not $leaf) { return $null }
    foreach ($p in $t.Exe) { if ($p.IsMatch($leaf)) { return 'exe' } }
    foreach ($p in $t.Client) { if ($p.IsMatch($leaf)) { return 'client' } }
    if ($Files) { foreach ($p in $t.Files) { if ($p.IsMatch($leaf)) { return 'file' } } }
    $null
}
function Test-PathSegs($t, [string]$path) {
    if (-not $t.Folder -or $t.Roots.Count -or -not $path) { return $false }
    foreach ($seg in ($path -split '\\')) { if ($seg -and $t.Folder.IsMatch($seg)) { return $true } }; $false
}
function Add-Hit($t, [string]$Source, [string]$Detail, [string]$Path, [hashtable]$X = @{}) {
    if (-not $Hits.ContainsKey($t.Id)) { $Hits[$t.Id] = [Collections.Generic.List[object]]::new() }
    if ($Hits[$t.Id] | Where-Object { $_.source -eq $Source -and $_.path -eq $Path -and $_.detail -eq $Detail }) { return }
    $h = [ordered]@{ source = $Source; detail = $Detail; path = $Path }; foreach ($k in $X.Keys) { $h[$k] = $X[$k] }; $Hits[$t.Id].Add($h)
}
function Get-KeysInfo([string]$Path) {
    $o = [ordered]@{ path = $Path; exists = $false }
    try { $fi = [IO.FileInfo]::new($Path); if (-not $fi.Exists) { return $o } } catch { $o.exists = $null; return $o }
    $o.exists = $true; $o.size = $fi.Length; $o.modified = ConvertTo-Iso $fi.LastWriteTimeUtc; $o.recent = $fi.LastWriteTimeUtc -gt $Recent
    if (Test-BvsNeverRead $Path) { $o.readable = $false; return $o }
    try { $lines = [IO.File]::ReadAllLines($fi.FullName); $o.readable = $true } catch { $o.readable = $false; return $o }
    $o.keys = @(foreach ($l in $lines) {
            if ($l -match '((?:ssh|ecdsa|sk)-[\w@.-]+)\s+([A-Za-z0-9+/=]{20,})(?:\s+(.*))?$') {
                $fp = try { 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String($Matches[2]))).TrimEnd('=') } catch { $null }
                [ordered]@{ type = $Matches[1]; fingerprint = $fp; comment = $Matches[3]; hasOptions = ($l.Trim() -notmatch '^(ssh|ecdsa|sk)-') }
            } })
    $o
}
function Test-Tag($r, [int]$n) { if (-not $r.HasData) { return $false }; $t = $r.PeekTag(); ($t.TagClass -eq [System.Formats.Asn1.TagClass]::Universal) -and ($t.TagValue -eq $n) }
function Read-Ctl([byte[]]$Bytes, [string]$Source) {
    # authroot.stl / EncodedCtl = PKCS#7 SignedData whose content is a CertificateTrustList (SHA-1 subject identifiers).
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(); $cms.Decode($Bytes)
    $ok = try { $cms.CheckSignature($true); $true } catch { $false }
    $c = [System.Formats.Asn1.AsnReader]::new($cms.ContentInfo.Content, [System.Formats.Asn1.AsnEncodingRules]::DER).ReadSequence()
    if (Test-Tag $c 2) { [void]$c.ReadInteger() }
    [void]$c.ReadSequence(); if (Test-Tag $c 4) { [void]$c.ReadOctetString() }
    $seq = if (Test-Tag $c 2) { $c.ReadInteger().ToString() } else { $null }
    $upd = if (Test-Tag $c 23) { $c.ReadUtcTime() } else { $c.ReadGeneralizedTime() }
    if (Test-Tag $c 23) { [void]$c.ReadUtcTime() } elseif (Test-Tag $c 24) { [void]$c.ReadGeneralizedTime() }
    [void]$c.ReadSequence(); $subj = @{}; $ts = $c.ReadSequence()
    while ($ts.HasData) {
        $one = $ts.ReadSequence(); $id = [Convert]::ToHexString($one.ReadOctetString()); $info = @{ name = $null; disallowedSince = $null }
        if ($one.HasData) {
            $as = $one.ReadSetOf()
            while ($as.HasData) {
                $a = $as.ReadSequence(); $oid = $a.ReadObjectIdentifier(); $vs = $a.ReadSetOf()
                if (-not (Test-Tag $vs 4)) { continue }
                $b = $vs.ReadOctetString()
                if ($oid -eq '1.3.6.1.4.1.311.10.11.11') { $info.name = [Text.Encoding]::Unicode.GetString($b).TrimEnd([char]0) }
                elseif ($oid -eq '1.3.6.1.4.1.311.10.11.104' -and $b.Length -ge 8) { $info.disallowedSince = ConvertTo-Iso ([datetime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 0))) }
            }
        }
        $subj[$id] = $info
    }
    [ordered]@{ source = $Source; signatureValid = $ok; signer = $cms.SignerInfos[0].Certificate.Subject; sequence = $seq; thisUpdate = (ConvertTo-Iso $upd); count = $subj.Count; subjects = $subj }
}
function Get-CertFromBlob([byte[]]$B) {
    $i = 0
    while ($i + 12 -le $B.Length) {
        $id = [BitConverter]::ToUInt32($B, $i); $len = [int][BitConverter]::ToUInt32($B, $i + 8)
        if ($id -eq 32) { $d = [byte[]]::new($len); [Buffer]::BlockCopy($B, $i + 12, $d, 0, $len); return [Security.Cryptography.X509Certificates.X509Certificate2]::new($d) }
        $i += 12 + $len
    }
    $null
}
function Read-ConnBlob([byte[]]$b) {
    $o = [ordered]@{ flags = $null; proxy = $null; bypass = $null; pac = $null }
    try {
        $o.flags = [BitConverter]::ToInt32($b, 8); $i = 12
        foreach ($f in 'proxy', 'bypass', 'pac') { $n = [BitConverter]::ToInt32($b, $i); $o[$f] = [Text.Encoding]::ASCII.GetString($b, $i + 4, $n); $i += 4 + $n }
    } catch { }
    $o.autoDetect = [bool]($o.flags -band 8); $o
}
function Get-ProxyWhy([string]$v) {
    try {
        if ($v -match '(?i)^(https?|file)://') { $u = [uri]$v; if ($u.IsFile) { if ($u.LocalPath -match $Ref.explainedPathRegex) { return 'PAC file inside the security-software folder' }; return $null }; $h = $u.Host; $port = $u.Port }
        else { $x = ($v -replace '^[a-z]+=', '' -replace ';.*$', '') -split ':'; $h = $x[0]; $port = $x[1] }
        if ($h -match $Ref.explainedPacHostRegex) { return "host $h belongs to Avast" }
        if ($h -in '127.0.0.1', 'localhost', '::1', '[::1]' -and $port) {
            $own = Get-NetTCPConnection -State Listen -LocalPort ([int]$port) -ErrorAction Stop | Select-Object -First 1
            $pp = ($S.Procs | Where-Object { $_.Pid -eq $own.OwningProcess } | Select-Object -First 1).Path
            $sig = Get-BvsSignature -Path $pp
            if ($sig.Signer -match $Ref.localProxyExplainedBySignerRegex) { return "loopback port $port is owned by $pp (signed by $($sig.Signer))" }
        }
    } catch { }
    $null
}
#endregion

#region ---------- shared context ----------
Invoke-BvsCheck -Run $run -Id 'context.system' -Description 'Edition, service table, process table and uninstall entries (HKLM 64/32, HKCU) shared by later checks' -Script {
    $cv = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $S.Edition = [string](Get-RegV $cv 'EditionID'); $S.IsHome = $S.Edition -match '^Core'
    try { $S.Domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { }
    $S.Services = @(Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId)
    foreach ($sv in $S.Services) { $S.Svc[$sv.Name] = $sv }   # never name a variable $s: PowerShell names are case-insensitive ($S)
    $S.Procs = @(Get-BvsProcessTable)
    $S.Uninst = @(foreach ($u in @(@('HKLM', '64'), @('HKLM', '32'), @('HKCU', '64'))) {
            $base = "$($u[0])\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            foreach ($sk in @(Get-BvsRegSubKeys -Path $base -View $u[1])) {
                if (-not $sk) { continue }; $m = Get-RegMap "$base\$sk" $u[1]
                if ($m['DisplayName']) { [pscustomobject]@{ key = "$base\$sk [$($u[1])]"; displayName = [string]$m['DisplayName']; publisher = [string]$m['Publisher']; version = [string]$m['DisplayVersion']; installDate = [string]$m['InstallDate']; installLocation = [string]$m['InstallLocation'] } }
            } })
    Add-Posture 'system' 'Windows edition' "$($S.Edition) $(Get-RegV $cv 'DisplayVersion') build $(Get-RegV $cv 'CurrentBuild').$(Get-RegV $cv 'UBR')" '' 'info' 'registry'
    $S.Services
} | Out-Null
#endregion

#region ---------- accounts ----------
$S.Users = @(Invoke-BvsCheck -Run $run -Id 'accounts.local_users' -Description 'Get-LocalUser: name, enabled, SID/RID role, last logon, password facts, description' -Script {
        try { $lu = @(Get-LocalUser) } catch { Set-BvsCheckStatus -Id 'accounts.local_users' -Status partial -Reason "Get-LocalUser failed ($($_.Exception.Message)); used Win32_UserAccount"; $lu = $null }
        if ($lu) { foreach ($u in $lu) { [ordered]@{ name = $u.Name; sid = $u.SID.Value; enabled = [bool]$u.Enabled; lastLogon = (ConvertTo-Iso $u.LastLogon); passwordLastSet = (ConvertTo-Iso $u.PasswordLastSet); passwordRequired = [bool]$u.PasswordRequired; principalSource = [string]$u.PrincipalSource; description = $u.Description } } }
        else { foreach ($u in @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True')) { [ordered]@{ name = $u.Name; sid = $u.SID; enabled = -not $u.Disabled; lastLogon = $null; passwordLastSet = $null; passwordRequired = [bool]$u.PasswordRequired; principalSource = 'Local'; description = $u.Description } } }
    })
foreach ($u in $S.Users) {
    $u.rid = [int]($u.sid -replace '^.*-', '')
    $u.role = switch ($u.rid) { 500 { 'builtin-administrator' } 501 { 'builtin-guest' } 503 { 'default-account' } 504 { 'wdag-utility' } default { if ($u.sid -eq $run.UserSid) { 'current-user' } else { 'local-user' } } }
}
$S.Groups = @(Invoke-BvsCheck -Run $run -Id 'accounts.privileged_groups' -Description 'Members of privileged builtin groups by SID: -544 Administrators, -555 Remote Desktop Users, -580 Remote Management Users, -551 Backup Operators, -578 Hyper-V Administrators, -585 OpenSSH Users' -Script {
        $present = @{}; foreach ($g in @(Get-CimInstance Win32_Group -Filter 'LocalAccount=True')) { $present[$g.SID] = $g.Name }
        foreach ($d in @(@('S-1-5-32-544', 'Administrators'), @('S-1-5-32-555', 'Remote Desktop Users'), @('S-1-5-32-580', 'Remote Management Users'), @('S-1-5-32-551', 'Backup Operators'), @('S-1-5-32-578', 'Hyper-V Administrators'), @('S-1-5-32-585', 'OpenSSH Users'))) {
            $row = [ordered]@{ sid = $d[0]; name = $d[1]; localName = $present[$d[0]]; present = $present.ContainsKey($d[0]); members = @(); source = $null }
            if ($row.present) {
                try { $row.members = @(Get-LocalGroupMember -SID $d[0] | ForEach-Object { [ordered]@{ name = $_.Name; sid = $_.SID.Value; objectClass = [string]$_.ObjectClass; principalSource = [string]$_.PrincipalSource } }); $row.source = 'Get-LocalGroupMember' }
                catch { $g = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='$($d[0])'"; $row.members = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser | ForEach-Object { [ordered]@{ name = "$($_.Domain)\$($_.Name)"; sid = $_.SID; objectClass = $_.CimClass.CimClassName } }); $row.source = 'Win32_GroupUser' }
            }
            $row
        }
    })
foreach ($m in @(($S.Groups | Where-Object { $_.sid -eq 'S-1-5-32-544' }).members)) { if ($m) { [void]$S.AdminSids.Add([string]$m.sid) } }
$S.Hidden = @(Invoke-BvsCheck -Run $run -Id 'accounts.hidden_users' -Description 'Winlogon SpecialAccounts\UserList: accounts hidden from the logon screen' -Script {
        $k = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'; $lw = ConvertTo-Iso (Get-BvsRegKeyLastWrite $k)
        foreach ($v in @(Get-BvsRegValues -Path $k)) { if ($v) { [ordered]@{ name = $v.Name; value = $v.Value; hidden = ($v.Value -eq 0); accountExists = [bool]($S.Users | Where-Object { $_.name -eq $v.Name }); keyLastWrite = $lw } } }
    })
$S.Profiles = @(Invoke-BvsCheck -Run $run -Id 'accounts.profiles' -Description "ProfileList SIDs, profile paths, folder creation dates (created in the last $RecentDays days flagged)" -Script {
        $base = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($sid in @(Get-BvsRegSubKeys -Path $base)) {
            if (-not $sid) { continue }
            $m = Get-RegMap "$base\$sid"; $path = [Environment]::ExpandEnvironmentVariables([string]$m['ProfileImagePath']); $created = $null; $exists = $null
            try { $di = [IO.DirectoryInfo]::new($path); $exists = $di.Exists; if ($exists) { $created = $di.CreationTimeUtc } } catch { }
            $last = $null
            try { $hi = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$m['LocalProfileLoadTimeHigh']), 0); $lo = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$m['LocalProfileLoadTimeLow']), 0); if ($hi) { $last = [datetime]::FromFileTimeUtc(([int64]$hi -shl 32) -bor [int64]$lo) } } catch { }
            $user = $S.Users | Where-Object { $_.sid -eq $sid } | Select-Object -First 1
            $name = if ($user) { $user.name } else { try { ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { $null } }
            $kind = if ($sid -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') { 'system' } elseif ($sid -like 'S-1-5-80-*') { 'service' } elseif ($sid -like '*.bak') { 'backup' } elseif ($user) { 'local-user' } elseif ($sid -like 'S-1-12-1-*') { 'azuread' } elseif (-not $name) { 'orphan' } else { 'other' }
            [ordered]@{ sid = $sid; name = $name; kind = $kind; path = $path; exists = $exists; created = (ConvertTo-Iso $created); recent = [bool]($created -and $created -gt $Recent); recent30 = [bool]($created -and $created -gt $D30); lastLoad = (ConvertTo-Iso $last); keyLastWrite = (ConvertTo-Iso (Get-BvsRegKeyLastWrite "$base\$sid")) }
        }
    })
Invoke-BvsCheck -Run $run -Id 'accounts.expected' -Description 'Evaluate users, privileged-group members, hidden users and profiles against built-in RID roles and expected.json' -Script {
    $exp = @(Get-BvsExpected -Category account); $okExp = @{}
    foreach ($u in $S.Users) {
        $isAdmin = $S.AdminSids.Contains($u.sid); $hidden = [bool]($S.Hidden | Where-Object { $_.hidden -and $_.name -eq $u.name })
        $prof = $S.Profiles | Where-Object { $_.sid -eq $u.sid } | Select-Object -First 1
        $e = Resolve-Exp ($exp | Where-Object { @($_.match.names) -contains $u.name } | Select-Object -First 1) @{ IsAdmin = $isAdmin }
        $u.isAdmin = $isAdmin; $u.hidden = $hidden; $u.profileCreated = $prof.created; $u.expected = $e.id; $u.expectedOk = [bool]($e -and -not $e.cancelled)
        $isNew = if ($prof) { $prof.recent } else { [bool]($u.passwordLastSet -and [datetime]$u.passwordLastSet -gt $Recent) }
        $ev = @(Ev 'account' $u.sid $u.name "enabled=$($u.enabled) admin=$isAdmin hidden=$hidden lastLogon=$($u.lastLogon) passwordLastSet=$($u.passwordLastSet) profileCreated=$($prof.created)")
        $ent = @{ accounts = @([ordered]@{ name = $u.name; sid = $u.sid; enabled = $u.enabled; admin = $isAdmin; hidden = $hidden }) }
        $rs = @(if ($isAdmin) { 'privileged_group' }; if ($hidden) { 'hidden' }; if ($isNew) { 'created_recent' })
        switch ($u.role) {
            'builtin-administrator' { if ($u.enabled) { Add-Finding 'accounts.expected' 'Built-in Administrator account (RID 500) is enabled' medium hardening -Reasons $rs -Evidence $ev -Entities $ent -Rec 'Disable it unless you deliberately use it (lusrmgr.msc or "net user Administrator /active:no" as admin): it is not subject to UAC prompts by default.' -Fp 'OEM/repair procedures sometimes enable it temporarily.' -Mitre 'T1078.003' } }
            'builtin-guest' { if ($u.enabled) { Add-Finding 'accounts.expected' 'Guest account is enabled' $(if ($isAdmin) { 'high' } else { 'medium' }) $(if ($isAdmin) { 'suspicious' } else { 'hardening' }) -Reasons $rs -Evidence $ev -Entities $ent -Rec 'Disable the Guest account; if it is in Administrators, treat the PC as possibly compromised.' -Fp 'Rarely enabled on purpose for shared PCs.' -Mitre 'T1078.001' } }
            'default-account' { if ($u.enabled) { Add-Finding 'accounts.expected' 'DefaultAccount (RID 503) is enabled' medium suspicious -Reasons $rs -Evidence $ev -Entities $ent -Rec 'This system-managed account should stay disabled; find out what enabled it.' -Fp 'Unusual configuration tools may enable it.' -Mitre 'T1078.001' } }
            'wdag-utility' { if ($u.enabled -or $isAdmin) { Add-Finding 'accounts.expected' 'WDAGUtilityAccount is enabled or privileged' $(if ($isAdmin) { 'high' } else { 'low' }) $(if ($isAdmin) { 'suspicious' } else { 'hardening' }) -Reasons $rs -Evidence $ev -Entities $ent -Rec 'Application Guard is deprecated; the account should be disabled and never an administrator.' -Fp 'Enabled automatically while Application Guard is in use.' -Mitre 'T1078.001' } }
            'local-user' {
                if ($e -and -not $e.cancelled) { if (-not $okExp.ContainsKey($e.id)) { $okExp[$e.id] = @{ exp = $e; users = [Collections.Generic.List[string]]::new() } }; $okExp[$e.id].users.Add($u.name) }
                elseif ($e) { Add-Finding 'accounts.expected' "Expected account '$($u.name)' is a member of Administrators" high suspicious -Reasons $rs -Evidence $ev -Entities $ent -Rec "Remove '$($u.name)' from Administrators unless you added it on purpose, then find out what added it." -Fp 'A tool update could change its sandbox design; verify with the vendor.' -Mitre @('T1098') -Exp $e }
                elseif ($u.enabled) { Add-Finding 'accounts.expected' "Unrecognised enabled local account: $($u.name)" $(if ($isAdmin -or $hidden) { 'high' } else { 'medium' }) suspicious -Reasons $rs -Evidence $ev -Entities $ent -Rec 'Confirm who created this account. If nobody did: disable it, check Administrators membership and recent logons, and change your passwords.' -Fp 'Second household users, software (Docker, sandboxes, ASUS tools) and old migrations create local accounts.' -Mitre @('T1136.001') }
                else { Add-Finding 'accounts.expected' "Disabled unrecognised local account: $($u.name)" low hygiene -Reasons $rs -Evidence $ev -Entities $ent -Rec 'Delete it if it is no longer needed.' -Fp 'Leftover from older software or users.' }
            }
        }
        if ($u.enabled -and -not $u.passwordRequired -and $u.role -ne 'current-user') { Add-Finding 'accounts.expected' "Enabled account may have an empty password (PASSWD_NOTREQD): $($u.name)" medium hardening -Evidence $ev -Entities $ent -Rec 'Set a password or disable the account.' -Fp 'The flag allows an empty password; it does not prove one is empty.' -Mitre 'T1078.003' }
    }
    foreach ($k in $okExp.Keys) { $o = $okExp[$k]; Add-Finding 'accounts.expected' "Expected accounts present: $($o.users -join ', ')" info info -Evidence @(Ev 'expected' $k ($o.users -join ', ') $o.exp.reason) -Fp 'Logon-type conditions (interactive/network logons) need the Security event log, which requires admin: not evaluated here.' -Rec 'None, unless you no longer use the tool that created them.' -Exp $o.exp }
    $machine = ($S.Users | Where-Object { $_.rid -eq 500 } | Select-Object -First 1).sid -replace '-500$', ''
    $rdpOn = (Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0
    foreach ($g in $S.Groups) {
        foreach ($m in @($g.members)) {
            if (-not $m) { continue }; $sid = [string]$m.sid; $leaf = $m.name -replace '^.*\\', ''; $isUser = [bool]($S.Users | Where-Object { $_.sid -eq $sid })
            $ev = @(Ev 'group' $g.sid $m.name $sid "objectClass=$($m.objectClass) source=$($m.principalSource)")
            if ($g.sid -eq 'S-1-5-32-544') {
                if ($sid -eq $run.UserSid -or $sid -eq "$machine-500" -or $sid -like 'S-1-12-1-*' -or ($S.Domain -and $sid -match '-512$')) { continue }
                if ($isUser -and ($exp | Where-Object { @($_.match.names) -contains $leaf })) { continue }
                Add-Finding 'accounts.privileged_groups' "Unexpected member of Administrators: $($m.name)" $(if ($isUser) { 'high' } else { 'medium' }) suspicious -Reasons @('privileged_group') -Evidence $ev -Rec 'Confirm who added this member (lusrmgr.msc > Groups > Administrators). Remove it if unknown and investigate.' -Fp 'A second household administrator account or an unresolvable SID left by a deleted account.' -Mitre @('T1098')
            }
            elseif ($g.sid -eq 'S-1-5-32-585') { Add-Finding 'accounts.privileged_groups' "OpenSSH Users group has a member: $($m.name)" low info -Evidence $ev -Fp 'Only matters if an SSH server is installed.' -Rec 'Remove members you do not use SSH with.' }
            else {
                $sev = switch ($g.sid) { 'S-1-5-32-551' { 'high' } 'S-1-5-32-555' { if ($rdpOn) { 'high' } else { 'medium' } } default { 'medium' } }
                Add-Finding 'accounts.privileged_groups' "Member of $($g.name): $($m.name)" $sev suspicious -Reasons @('privileged_group') -Evidence $ev -Rec "Remove the member from $($g.name) unless you configured remote management/backup on purpose." -Fp 'Admins sometimes grant these rights for remote support or backup tools.' -Mitre @('T1098')
            }
        }
    }
    foreach ($h in @($S.Hidden | Where-Object { $_.hidden })) {
        $u = $S.Users | Where-Object { $_.name -eq $h.name } | Select-Object -First 1
        if (-not $u -or $u.expectedOk -or -not $u.enabled) { continue }
        Add-Finding 'accounts.hidden_users' "Enabled local account hidden from the logon screen: $($h.name)" high suspicious -Reasons @('hidden') -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' $h.name 0 "key LastWrite $($h.keyLastWrite)") -Rec 'Hidden enabled accounts are a classic backdoor. Confirm which software created it; otherwise disable it and investigate.' -Fp 'Some sandboxes/OEM tools hide their service accounts.' -Mitre @('T1564.002')
    }
    foreach ($p in $S.Profiles) {
        if ($p.kind -eq 'system' -or $p.sid -eq $run.UserSid) { continue }
        $u = $S.Users | Where-Object { $_.sid -eq $p.sid } | Select-Object -First 1
        $ev = @(Ev 'registry' "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($p.sid)" $p.name $p.path "created=$($p.created) lastLoad=$($p.lastLoad)")
        if ($p.recent -and -not ($u -and $u.expectedOk)) {
            if ($p.kind -eq 'service') { Add-Finding 'accounts.profiles' "New service-account profile: $($p.name)" info info -Evidence $ev -Fp 'Created when a service running as a virtual account first starts.' -Rec 'Check that the service belongs to software you installed.' }
            else { Add-Finding 'accounts.profiles' "User profile created in the last $RecentDays days: $($p.name)" $(if ($u -and ($u.isAdmin -or $u.hidden)) { 'high' } else { 'medium' }) suspicious -Reasons @('created_recent', $(if ($p.recent30) { 'created_lt_30d' })) -Evidence $ev -Rec 'Confirm who signed in with this account.' -Fp 'New household user, sandbox or test account.' -Mitre @('T1136.001') }
        }
        if ($p.kind -in 'orphan', 'backup' -or $p.exists -eq $false) { Add-Finding 'accounts.profiles' "Orphaned or broken profile entry: $($p.sid)" low hygiene -Evidence $ev -Rec 'Remove stale profiles via System Properties > User Profiles once you have confirmed no data is needed.' -Fp 'Deleted accounts and failed profile loads leave such entries.' }
    }
    $S.Users
} | Out-Null
#endregion

#region ---------- remote access ----------
Invoke-BvsCheck -Run $run -Id 'remote.rdp' -Description 'RDP host (fDenyTSConnections + policy, NLA, port), TermService ServiceDll, termsrv.dll signature, RDP Wrapper artefacts, concurrent-session patch' -Script {
    $ts = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'; $pol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $deny = Get-RegV $ts 'fDenyTSConnections'; $pdeny = Get-RegV $pol 'fDenyTSConnections'
    $eff = if ($null -ne $pdeny) { $pdeny } elseif ($null -ne $deny) { $deny } else { 1 }
    $dllRaw = [string](Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters' 'ServiceDll'); $want = Join-Path $env:SystemRoot 'System32\termsrv.dll'
    $sig = Get-BvsSignature -Path $want
    $cand = @((Join-Path $env:ProgramFiles 'RDP Wrapper'), (Join-Path $env:SystemRoot 'System32\rdpwrap.dll'), (Join-Path $env:SystemRoot 'System32\rdpwrap.ini')); if (${env:ProgramFiles(x86)}) { $cand += Join-Path ${env:ProgramFiles(x86)} 'RDP Wrapper' }
    $wrap = @($cand | Where-Object { [IO.Directory]::Exists($_) -or [IO.File]::Exists($_) }) + @($S.Uninst | Where-Object { $_.displayName -match '^RDP Wrapper' } | ForEach-Object { $_.key })
    $r = [ordered]@{ enabled = ($eff -eq 0); fDenyTSConnections = $deny; policyDeny = $pdeny; port = (Get-RegV "$ts\WinStations\RDP-Tcp" 'PortNumber'); nla = (Get-RegV "$ts\WinStations\RDP-Tcp" 'UserAuthentication')
        termService = "$($S.Svc['TermService'].State)/$($S.Svc['TermService'].StartMode)"; serviceDll = $dllRaw; serviceDllOk = ([Environment]::ExpandEnvironmentVariables($dllRaw) -eq $want)
        termsrvSig = $sig.Status; termsrvSigner = $sig.Signer; rdpWrapArtifacts = $wrap; enableConcurrentSessions = (Get-RegV "$ts\Licensing Core" 'EnableConcurrentSessions'); edition = $S.Edition }
    $S.Remote.rdp = $r
    Add-Posture 'remote' 'RDP host enabled' $r.enabled 'False' $(if ($r.enabled) { 'risk' } else { 'ok' }) "$ts fDenyTSConnections=$eff"
    Add-Posture 'remote' 'TermService ServiceDll / termsrv.dll signature' "$dllRaw / $($sig.Status)" '%SystemRoot%\System32\termsrv.dll / Valid' $(if ($r.serviceDllOk -and $sig.Status -eq 'Valid') { 'ok' } else { 'risk' }) 'registry, Authenticode'
    $ev = @((Ev 'registry' $ts 'fDenyTSConnections' $deny), (Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters' 'ServiceDll' $dllRaw), (Ev 'file' $want 'signature' "$($sig.Status) $($sig.Signer)"))
    if ($r.enabled) { if ($S.IsHome) { Add-Finding 'remote.rdp' 'RDP host enabled on Windows Home (needs RDP Wrapper or a patched termsrv.dll)' high suspicious -Reasons @('exposed_service') -Evidence $ev -Rec 'Disable RDP and look for RDP Wrapper or other termsrv patches; find out who installed them.' -Fp 'A user may have installed RDP Wrapper deliberately for remote work.' -Mitre @('T1021.001', 'T1112') } else { Add-Finding 'remote.rdp' "Remote Desktop is enabled (NLA=$($r.nla), port $($r.port))" medium hardening -Reasons @('exposed_service') -Evidence $ev -Rec 'Disable Remote Desktop if unused; otherwise require NLA and restrict it to trusted networks.' -Fp 'Intentionally enabled for remote work.' -Mitre @('T1021.001') } }
    if (-not $r.serviceDllOk) { Add-Finding 'remote.rdp' 'TermService ServiceDll is not %SystemRoot%\System32\termsrv.dll' high suspicious -Reasons @('masquerading', 'persistence') -Evidence $ev -Rec 'Identify the DLL in the ServiceDll value (RDP Wrapper = rdpwrap.dll) and remove it if you did not install it.' -Fp 'RDP Wrapper installed on purpose.' -Mitre @('T1543.003', 'T1021.001') }
    if ($sig.Status -ne 'Valid') { Add-Finding 'remote.rdp' "termsrv.dll signature is not valid ($($sig.Status))" high suspicious -Reasons @('invalid_signature') -Evidence $ev -Rec 'Run "sfc /scannow" as admin to restore the original file and find the patcher that modified it.' -Fp 'Mid-update file replacement can briefly break catalog validation.' -Mitre @('T1112') }
    if ($wrap.Count -or $r.enableConcurrentSessions -eq 1) { Add-Finding 'remote.rdp' 'RDP Wrapper / concurrent-session artefacts present' $(if ($S.IsHome) { 'high' } else { 'medium' }) suspicious -Evidence @($wrap | ForEach-Object { Ev 'path' $_ }) -Rec 'Uninstall RDP Wrapper unless you installed it yourself.' -Fp 'Installed on purpose by the owner.' -Mitre @('T1021.001') }
    [pscustomobject]$r
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'remote.remote_assistance' -Description 'Remote Assistance fAllowToGetHelp / fAllowFullControl (+ policy)' -Script {
    $k = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; $pol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $help = Get-RegV $k 'fAllowToGetHelp'; $phelp = Get-RegV $pol 'fAllowToGetHelp'; $eff = if ($null -ne $phelp) { $phelp } else { $help }; $full = Get-RegV $k 'fAllowFullControl'
    $S.Remote.remoteAssistance = [ordered]@{ fAllowToGetHelp = $help; policy = $phelp; fAllowFullControl = $full; fAllowUnsolicited = (Get-RegV $pol 'fAllowUnsolicited') }
    Add-Posture 'remote' 'Remote Assistance (fAllowToGetHelp)' $eff '0' $(if ($eff -eq 1) { 'weak' } else { 'ok' }) $k
    if ($eff -eq 1) {
        $item = Get-BvsExpected -Category posture | Where-Object { $_.match.setting -eq "fAllowToGetHelp=$eff" } | Select-Object -First 1
        Add-Finding 'remote.remote_assistance' "Remote Assistance invitations allowed (fAllowFullControl=$full)" medium hardening -Evidence @((Ev 'registry' $k 'fAllowToGetHelp' $help), (Ev 'registry' $k 'fAllowFullControl' $full)) -Rec 'If unused: System Properties > Remote > untick "Allow Remote Assistance connections to this computer".' -Fp 'Default on many OEM images; a helper still needs an invitation.' -Mitre @('T1219') -Exp (Resolve-Exp $item)
    }
    $S.Remote.remoteAssistance
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'remote.openssh' -Description 'OpenSSH server: sshd service/binary, ProgramData\ssh\sshd_config, administrators_authorized_keys, per-profile authorized_keys' -Script {
    $svc = $S.Svc['sshd']; $exe = @("$env:SystemRoot\System32\OpenSSH\sshd.exe", "$env:ProgramFiles\OpenSSH\sshd.exe") | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
    $dir = Join-Path $env:ProgramData 'ssh'; $cfgPath = Join-Path $dir 'sshd_config'; $cfg = [ordered]@{}
    if ([IO.File]::Exists($cfgPath)) { try { foreach ($l in [IO.File]::ReadAllLines($cfgPath)) { if ($l -match '^\s*(Port|ListenAddress|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|AuthorizedKeysFile|AllowUsers|AllowGroups|Match)\s+(.+?)\s*$' -and -not $cfg.Contains($Matches[1])) { $cfg[$Matches[1]] = $Matches[2] } } } catch { $cfg.error = $_.Exception.Message } }
    $keys = @(@(Get-KeysInfo (Join-Path $dir 'administrators_authorized_keys')) + @($S.Profiles | Where-Object { $_.kind -eq 'local-user' -and $_.path } | ForEach-Object { Get-KeysInfo (Join-Path $_.path '.ssh\authorized_keys') }) | Where-Object { $_.exists -ne $false })
    $present = [bool]($svc -or $exe)
    $S.Remote.openssh = [ordered]@{ serverInstalled = $present; service = if ($svc) { "$($svc.State)/$($svc.StartMode)" } else { $null }; sshdExe = $exe; programDataSsh = [IO.Directory]::Exists($dir); sshdConfig = $cfg; authorizedKeys = $keys }
    Add-Posture 'remote' 'OpenSSH server' $(if ($present) { "installed ($($S.Remote.openssh.service))" } else { 'not installed' }) 'not installed' $(if ($svc -and $svc.State -eq 'Running') { 'weak' } else { 'ok' }) 'services, files'
    if ($svc -and ($svc.State -eq 'Running' -or $svc.StartMode -eq 'Auto')) { Add-Finding 'remote.openssh' "OpenSSH Server is enabled ($($svc.State)/$($svc.StartMode); PasswordAuthentication=$($cfg['PasswordAuthentication']))" medium hardening -Reasons @('exposed_service') -Evidence @(Ev 'service' $exe 'sshd' "$($svc.State)/$($svc.StartMode)") -Rec 'Disable sshd if unused; otherwise set PasswordAuthentication no and allow only known keys.' -Fp 'Developers enable it deliberately.' -Mitre @('T1021.004') }
    foreach ($k in $keys) { Add-Finding 'remote.openssh' "SSH authorized keys file present: $($k.path)" $(if (-not $present) { 'low' } elseif ($k.recent) { 'high' } else { 'medium' }) $(if ($present) { 'suspicious' } else { 'hygiene' }) -Reasons @(if ($k.recent) { 'created_recent' }) -Evidence @(Ev 'file' $k.path "$(@($k.keys).Count) key(s)" $k.modified) -Rec 'Verify every key fingerprint/comment belongs to you; delete unknown keys.' -Fp 'Your own keys for remote administration.' -Mitre @('T1098.004') }
    $S.Remote.openssh
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'remote.winrm_sshagent' -Description 'WinRM service, listeners and auth policy; ssh-agent service' -Script {
    $w = $S.Svc['WinRM']; $a = $S.Svc['ssh-agent']
    $lis = try { @(Get-BvsRegSubKeys -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener') } catch { Set-BvsCheckStatus -Id 'remote.winrm_sshagent' -Status partial -Reason 'WSMAN listener key needs admin; judged by the WinRM service state only'; @() }
    $wpol = Get-RegMap 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $S.Remote.winrm = [ordered]@{ state = $w.State; startMode = $w.StartMode; listeners = $lis; policy = $wpol }; $S.Remote.sshAgent = [ordered]@{ state = $a.State; startMode = $a.StartMode }
    Add-Posture 'remote' 'WinRM service' "$($w.State)/$($w.StartMode), listeners=$($lis.Count)" 'Stopped/Manual, 0' $(if ($lis.Count -or $w.State -eq 'Running') { 'weak' } else { 'ok' }) 'services, WSMAN registry'
    Add-Posture 'remote' 'ssh-agent service' "$($a.State)/$($a.StartMode)" '' 'info' 'services'
    if ($lis.Count -or ($w.State -eq 'Running' -and $w.StartMode -eq 'Auto')) { Add-Finding 'remote.winrm_sshagent' 'WinRM remoting is enabled' medium hardening -Reasons @('exposed_service') -Evidence @(Ev 'service' 'WinRM' "$($w.State)/$($w.StartMode)" ($lis -join ', ')) -Rec 'Run "Disable-PSRemoting" (admin) if you do not use remoting.' -Fp 'Enabled deliberately for automation.' -Mitre @('T1021.006') }
    if ($wpol['AllowUnencryptedTraffic'] -eq 1 -or $wpol['AllowBasic'] -eq 1) { Add-Finding 'remote.winrm_sshagent' 'WinRM allows unencrypted traffic or Basic auth' high hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') -Rec 'Remove AllowUnencryptedTraffic/AllowBasic policies.' -Fp 'Lab configurations.' -Mitre @('T1021.006') }
    $S.Remote.winrm
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'remote.quick_assist' -Description 'Quick Assist presence (info) and whether it is running now' -Script {
    $pk = @(Get-BvsRegSubKeys -Path 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages' | Where-Object { $_ -like 'MicrosoftCorporationII.QuickAssist_*' })
    $qa = @($S.Procs | Where-Object { $_.Name -eq 'QuickAssist.exe' })
    $S.Remote.quickAssist = [ordered]@{ packages = $pk; legacyExe = [IO.File]::Exists((Join-Path $env:SystemRoot 'System32\quickassist.exe')); running = [bool]$qa.Count }
    Add-Posture 'remote' 'Quick Assist' $(if ($pk.Count) { $pk[0] } else { 'not installed for this user' }) '' 'info' 'AppModel repository'
    if ($qa.Count) { Add-Finding 'remote.quick_assist' 'Quick Assist is running right now' medium suspicious -Reasons @('running') -Evidence @($qa | ForEach-Object { Ev 'process' $_.Path $_.Name $_.Pid }) -Rec 'If someone you did not contact yourself is connected, close Quick Assist immediately (tech-support scam pattern).' -Fp 'You may be helping or being helped by someone you know.' -Mitre @('T1219') }
    $S.Remote.quickAssist
} | Out-Null
#endregion

#region ---------- remote-control / RMM / tunnel inventory ----------
$Tools = @(foreach ($t in $Cat.tools) {
        $w = $t.windows; $mk = { param($a) @($a | Where-Object { $_ } | ForEach-Object { [WildcardPattern]::new([string]$_, 'IgnoreCase') }) }
        [pscustomobject]@{ Id = $t.id; Name = $t.name; Cat = $t.category; Note = $t.note; Exe = (& $mk $w.exe); Client = (& $mk $w.clientExe); Files = (& $mk $w.files)
            Names = @(@($w.exe) + @($w.clientExe) + @($w.files) | Where-Object { $_ }); Svc = $(if ($w.service) { [regex]::new($w.service, 'IgnoreCase') })
            Prod = $(if ($w.product) { [regex]::new($w.product, 'IgnoreCase') }); Pub = $(if ($w.publisher) { [regex]::new($w.publisher, 'IgnoreCase') })
            Folder = $(if ($w.folder) { [regex]::new($w.folder, 'IgnoreCase') }); Roots = @($w.folderRoots | Where-Object { $_ }); Level = $(if ($w.folderLevel) { [int]$w.folderLevel } else { 2 })
            Paths = @($w.paths | Where-Object { $_ }); Sweep = ($w.sweep -ne $false) } })
Invoke-BvsCheck -Run $run -Id 'rmm.inventory' -Description 'Remote-control/RMM/tunnel tools: services, processes, uninstall entries (HKLM, WOW6432Node, HKCU), folder names (Program Files, ProgramData, AppData; 2 levels), known paths, scheduled-task actions, Run keys, portable-binary sweep of user-writable folders' -Script {
    $failed = [Collections.Generic.List[string]]::new()
    foreach ($sv in $S.Services) {
        $r = Get-ExePath $sv.PathName; $leaf = Get-Leaf $r.Executable
        foreach ($t in $Tools) {
            if (($t.Svc -and ($t.Svc.IsMatch([string]$sv.Name) -or $t.Svc.IsMatch([string]$sv.DisplayName))) -or (Test-Exe $t $leaf) -or (Test-PathSegs $t $r.Executable)) {
                $x = @{ serviceName = $sv.Name; state = $sv.State; startMode = $sv.StartMode; account = $sv.StartName }; if ($sv.PathName -match '[?&]h=([^&"\s]+)') { $x.relayHost = $Matches[1] }
                Add-Hit $t 'service' "$($sv.Name) ($($sv.DisplayName)) $($sv.State)/$($sv.StartMode)" $r.Executable $x
            } } }
    foreach ($p in $S.Procs) {
        $leaf = if ($p.Path) { Get-Leaf $p.Path } else { ([string]$p.Name).ToLowerInvariant() }; $cmd = [string]$p.CommandLine
        foreach ($t in $Tools) { $k = Test-Exe $t $leaf; if ($k -or (Test-PathSegs $t $p.Path)) { Add-Hit $t 'process' "$($p.Name) pid $($p.Pid)" $p.Path @{ pid = $p.Pid; processName = $p.Name; kind = $k; cmd = $cmd.Substring(0, [Math]::Min(300, $cmd.Length)); tunnelArgs = ($t.Id -eq 'plink' -and $cmd -match '(^|\s)-[RLD]\s') } } } }
    foreach ($u in $S.Uninst) { foreach ($t in $Tools) { if (($t.Prod -and $t.Prod.IsMatch($u.displayName)) -or ($t.Pub -and $u.publisher -and $t.Pub.IsMatch($u.publisher))) { Add-Hit $t 'uninstall' "$($u.displayName) $($u.version) [$($u.publisher)]" $u.key @{ displayName = $u.displayName; installDate = $u.installDate; installLocation = $u.installLocation } } } }
    $ll = Join-Path (Split-Path $env:LOCALAPPDATA) 'LocalLow'
    $roots = @(@('ProgramFiles', $env:ProgramFiles), @('ProgramFiles', ${env:ProgramFiles(x86)}), @('ProgramData', $env:ProgramData), @('AppData', $env:APPDATA), @('AppData', $env:LOCALAPPDATA), @('AppData', $ll))
    $eo = [IO.EnumerationOptions]::new(); $eo.AttributesToSkip = [IO.FileAttributes]::ReparsePoint; $eo.IgnoreInaccessible = $true
    foreach ($rt in $roots) {
        if (-not $rt[1] -or -not [IO.Directory]::Exists($rt[1])) { continue }
        foreach ($d1 in [IO.DirectoryInfo]::new($rt[1]).EnumerateDirectories('*', $eo)) {
            $cands = [Collections.Generic.List[object]]::new(); $cands.Add(@($d1, 1)); try { foreach ($d2 in $d1.EnumerateDirectories('*', $eo)) { $cands.Add(@($d2, 2)) } } catch { }
            foreach ($c in $cands) { foreach ($t in $Tools) {
                    if ($t.Folder -and $c[1] -le $t.Level -and (-not $t.Roots.Count -or $t.Roots -contains $rt[0]) -and $t.Folder.IsMatch($c[0].Name)) {
                        $hasExe = [bool](Get-BvsFiles -Path $c[0].FullName -Include '*.exe' -MaxDepth 2 | Select-Object -First 1)
                        Add-Hit $t 'folder' "$($rt[0]) level $($c[1])" $c[0].FullName @{ root = $rt[0]; hasExe = $hasExe; created = (ConvertTo-Iso $c[0].CreationTimeUtc); modified = (ConvertTo-Iso $c[0].LastWriteTimeUtc) }
                    } } }
        } }
    foreach ($t in $Tools) { foreach ($p in $t.Paths) { $e = [Environment]::ExpandEnvironmentVariables($p); if ([IO.Directory]::Exists($e) -or [IO.File]::Exists($e)) { Add-Hit $t 'path' 'known location' $e @{} } } }
    try {
        foreach ($tk in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) { foreach ($a in @($tk.Actions)) {
                if (-not $a.Execute) { continue }
                $ex = [string]$a.Execute; $r = Get-ExePath $(if ($ex.Trim().StartsWith('"')) { "$ex $($a.Arguments)" } else { "`"$ex`" $($a.Arguments)" })
                foreach ($t in $Tools) { if ((Test-Exe $t (Get-Leaf $r.Executable)) -or (Test-Exe $t (Get-Leaf $r.Target)) -or (Test-PathSegs $t $r.Executable) -or (Test-PathSegs $t $r.Target)) { Add-Hit $t 'task' "$($tk.TaskPath)$($tk.TaskName) [$($tk.State)]" $r.Executable @{ state = [string]$tk.State; args = [string]$a.Arguments } } }
            } }
    } catch { $failed.Add("tasks: $($_.Exception.Message)") }
    foreach ($rk in @(@('HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '64'), @('HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce', '64'), @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', '64'), @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', '32'), @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', '64'), @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', '32'))) {
        foreach ($v in @(Get-BvsRegValues -Path $rk[0] -View $rk[1])) { if (-not $v) { continue }; $r = Get-ExePath ([string]$v.Value)
            foreach ($t in $Tools) { if ((Test-Exe $t (Get-Leaf $r.Executable)) -or (Test-Exe $t (Get-Leaf $r.Target)) -or (Test-PathSegs $t $r.Executable)) { Add-Hit $t 'runkey' "$($rk[0]) [$($rk[1])] $($v.Name)" $r.Executable @{ value = [string]$v.Value } } } } }
    try {
        $pats = @($Tools | Where-Object { $_.Sweep } | ForEach-Object { $_.Names } | Select-Object -Unique)
        $dl = [Environment]::ExpandEnvironmentVariables([string](Get-RegV 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}')); if (-not $dl) { $dl = Join-Path $env:USERPROFILE 'Downloads' }
        $desk = [Environment]::GetFolderPath('Desktop')
        $prune = @('node_modules', '.git', '__pycache__', '.venv', 'venv', 'site-packages', '.pnpm-store', 'npm-cache', 'pnpm-cache', 'pip', 'ms-playwright', 'User Data', 'Cache', 'Code Cache', 'GPUCache')
        $lad = @([IO.Directory]::GetDirectories($env:LOCALAPPDATA) | Where-Object { (Split-Path $_ -Leaf) -ne 'Packages' })
        $found = @(Get-BvsFiles -Path @(@($dl, $desk, $env:PUBLIC, $env:ProgramData, $env:APPDATA, $ll) | Where-Object { $_ }) -Include $pats -MaxDepth $SweepDepth -PruneDirNames $prune) + @(Get-BvsFiles -Path $lad -Include $pats -MaxDepth ([Math]::Max(0, $SweepDepth - 1)) -PruneDirNames $prune)
        foreach ($f in $found) {
            if ($f.FullName.StartsWith($run.Root, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $loc = switch -Wildcard ($f.FullName) { "$dl\*" { 'Downloads'; break } "$desk\*" { 'Desktop'; break } "$env:ProgramData\*" { 'ProgramData'; break } "$env:PUBLIC\*" { 'Public'; break } "$env:TEMP\*" { 'Temp'; break } default { 'AppData' } }
            foreach ($t in $Tools) { $k = Test-Exe $t $f.Name.ToLowerInvariant() -Files; if ($k) { Add-Hit $t 'file' $loc $f.FullName @{ kind = $k; location = $loc; size = $f.Length; created = (ConvertTo-Iso $f.CreationTimeUtc); motw = $(if ($loc -in 'Downloads', 'Desktop') { (Get-BvsMotw -Path $f.FullName).HostDomain }) } } }
        }
    } catch { $failed.Add("file sweep: $($_.Exception.Message)") }
    if ($failed.Count) { Set-BvsCheckStatus -Id 'rmm.inventory' -Status partial -Reason ($failed -join '; ') }
    @($Hits.Keys)
} | Out-Null
$RmmRows = @(Invoke-BvsCheck -Run $run -Id 'rmm.evaluate' -Description 'Per-tool facts (running, autostart, installed, signatures, user-writable paths), expected.json matching (with invalidIf) and calibrated severity' -Script {
        foreach ($id in @($Hits.Keys)) {
            $t = $Tools | Where-Object { $_.Id -eq $id }; $h = @($Hits[$id])
            $running = [bool]($h | Where-Object { $_.source -eq 'process' -or ($_.source -eq 'service' -and $_.state -eq 'Running') })
            $auto = [bool]($h | Where-Object { ($_.source -eq 'service' -and $_.startMode -in 'Auto', 'Boot', 'System') -or ($_.source -eq 'task' -and $_.state -ne 'Disabled') -or $_.source -eq 'runkey' })
            $installed = [bool]($h | Where-Object { $_.source -in 'uninstall', 'service' -or ($_.source -eq 'folder' -and $_.hasExe) })
            $folderOnly = -not ($h | Where-Object { -not ($_.source -in 'folder', 'path' -and -not $_.hasExe) })
            $dlOnly = -not ($h | Where-Object { -not ($_.source -eq 'file' -and $_.location -in 'Downloads', 'Desktop') })
            $clientOnly = [bool]($h | Where-Object { $_.kind -eq 'client' }) -and -not ($h | Where-Object { $_.source -in 'service', 'uninstall', 'runkey', 'task' -or ($_.kind -and $_.kind -ne 'client') })
            $facts = @($h | Where-Object { $_.path -match '\.(exe|dll)$' -and $_.source -ne 'uninstall' } | ForEach-Object { $_.path } | Select-Object -Unique -First 12 | ForEach-Object { Get-FileFacts $_ -Hash } | Where-Object { $_.exists })
            $unsigned = @($facts | Where-Object { $_.sig -ne 'Valid' }); $uw = @($facts | Where-Object { $_.userWritable -and $_.path -notlike '*\Program Files*' })
            $item = $null
            foreach ($it in @(Get-BvsExpected | Where-Object { $_.category -in 'network', 'listener', 'program', 'remoteTool', 'service' })) {
                $m = $it.match; if (-not $m) { continue }
                if (($m.service -and $t.Svc -and $t.Svc.IsMatch([string]$m.service)) -or ($m.process -and (Test-Exe $t (([string]$m.process).ToLowerInvariant() -replace '(?<!\.exe)$', '.exe'))) -or (@($m.names) -contains $t.Name)) { $item = $it; break }
            }
            $exp = Resolve-Exp $item @{ Signers = @($facts | ForEach-Object { [string]$_.signer }) }
            $rs = @(if ($running) { 'running' }; if ($auto) { 'persistence' }; if ($unsigned.Count) { 'unsigned' }; if ($uw.Count) { 'user_writable' }; if ($facts | Where-Object { $_.created -and [datetime]$_.created -gt $D30 }) { 'created_lt_30d' })
            $cls = 'suspicious'; $conf = 'medium'
            $sev = switch ($t.Cat) {
                'tunnel' { if ($t.Id -eq 'plink') { if ($h | Where-Object { $_.tunnelArgs }) { 'high' } elseif ($running -or ($h | Where-Object { $_.path -and $_.path -notmatch '\\PuTTY\\' })) { 'medium' } else { 'info' } } elseif ($running -or $auto) { 'high' } elseif ($folderOnly) { 'low' } else { 'medium' } }
                { $_ -in 'vpn-overlay', 'game-stream', 'oem-remote' } { if ($running -or $auto) { 'medium' } else { 'low' } }
                default { if ($running -or $auto) { 'high' } elseif ($folderOnly -or $dlOnly) { 'low' } else { 'medium' } }
            }
            if ($folderOnly -and $sev -ne 'high') { $cls = 'hygiene' }
            if ($clientOnly -and $Rank[$sev] -gt 1) { $sev = 'low'; $rs += 'viewer_only' }
            if ($t.Id -eq 'netsupport' -and ($h | Where-Object { $_.source -ne 'uninstall' -and $_.path -and $_.path -notlike '*\Program Files*' })) { $sev = 'high'; $rs += 'clickfix_pattern' }
            if ($unsigned.Count -and ($running -or $auto)) { $conf = 'high' }
            if ($sev -eq 'info') { $cls = 'info' }
            $state = @(if ($running) { 'running' }; if ($auto) { 'autostart' }; if ($installed) { 'installed' }; if ($folderOnly) { 'leftover folder/config only' }; if ($dlOnly) { 'downloaded file only' }) -join ', '
            $rec = if ($t.Cat -eq 'tunnel') { "Confirm you use $($t.Name) yourself. If not: stop it, remove the binary/service/task and review what it exposed." } else { "Confirm that you (or someone you trust) installed $($t.Name). If not: disconnect from the network, uninstall it (Settings > Apps), remove leftover services/tasks/Run entries, check the Administrators group and change passwords from a clean device." }
            Add-Finding 'rmm.evaluate' "Remote-access tool: $($t.Name) ($state)" $sev $cls -Conf $conf -Reasons $rs -Evidence @($h | Select-Object -First 15 | ForEach-Object { Ev $_.source $_.path $_.detail }) `
                -Entities @{ files = $facts; processes = @($h | Where-Object { $_.source -eq 'process' } | ForEach-Object { [ordered]@{ pid = $_.pid; name = $_.processName; path = $_.path; cmd = $_.cmd } }) } `
                -Rec $rec -Fp ('Legitimate remote-support/IT software; presence alone is not compromise.' + $(if ($t.Note) { " $($t.Note)" })) -Mitre @(if ($t.Cat -eq 'tunnel') { 'T1572' } else { 'T1219' }) -Exp $exp
            [ordered]@{ id = $t.Id; name = $t.Name; category = $t.Cat; running = $running; autostart = $auto; installed = $installed; folderOnly = $folderOnly; downloadOnly = $dlOnly; expected = $exp.id; expectedCancelled = $exp.cancelled; hits = $h; files = $facts }
        }
    })
#endregion

#region ---------- security posture ----------
Invoke-BvsCheck -Run $run -Id 'posture.uac' -Description 'UAC: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, LocalAccountTokenFilterPolicy' -Script {
    $k = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; $m = Get-RegMap $k
    $rows = @(@('EnableLUA', '1', ($m['EnableLUA'] -eq 0), 'high', 'UAC is disabled (EnableLUA=0)'), @('ConsentPromptBehaviorAdmin', '5', ($m['ConsentPromptBehaviorAdmin'] -eq 0), 'high', 'Administrators elevate without any prompt (ConsentPromptBehaviorAdmin=0)'),
        @('PromptOnSecureDesktop', '1', ($m['PromptOnSecureDesktop'] -eq 0), 'medium', 'UAC prompts are not on the secure desktop'), @('LocalAccountTokenFilterPolicy', 'unset/0', ($m['LocalAccountTokenFilterPolicy'] -eq 1), 'medium', 'Remote UAC token filtering disabled (LocalAccountTokenFilterPolicy=1)'))
    foreach ($r in $rows) {
        Add-Posture 'uac' $r[0] $m[$r[0]] $r[1] $(if ($r[2]) { 'risk' } else { 'ok' }) $k
        if ($r[2]) { Add-Finding 'posture.uac' $r[4] $r[3] hardening -Evidence @(Ev 'registry' $k $r[0] $m[$r[0]]) -Rec 'Restore the default in Settings > User Account Control (or the registry value) and find what changed it.' -Fp 'Some users or tweak tools lower UAC on purpose.' -Mitre @('T1548.002') }
    }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.smartscreen_sac' -Description 'SmartScreen (Explorer, policy, Edge policy, Store apps) and Smart App Control state' -Script {
    $ex = Get-RegV 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'; $pol = Get-RegV 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    $edge = @((Get-RegV 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'), (Get-RegV 'HKCU\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'))
    $app = Get-RegV 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation'; $sac = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
    $off = ($ex -eq 'Off') -or ($pol -eq 0)
    Add-Posture 'smartscreen' 'Check apps and files' $(if ($null -eq $ex -and $null -eq $pol) { 'default (on)' } else { "Explorer=$ex policy=$pol" }) 'on' $(if ($off) { 'weak' } else { 'ok' }) 'registry'
    Add-Posture 'smartscreen' 'Edge SmartScreen policy' ($edge -join '/') 'unset or 1' $(if ($edge -contains 0) { 'weak' } else { 'ok' }) 'registry'
    Add-Posture 'smartscreen' 'Smart App Control' $(switch ($sac) { 0 { 'off' } 1 { 'on' } 2 { 'evaluation' } default { "unknown ($sac)" } }) 'on (clean installs only)' 'info' 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy'
    if ($off) { Add-Finding 'posture.smartscreen_sac' 'Windows SmartScreen for apps and files is off' medium hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' $ex) -Rec 'Windows Security > App & browser control > Reputation-based protection: turn "Check apps and files" on.' -Fp 'Turned off deliberately by some users.' -Mitre @('T1562.001') }
    if ($edge -contains 0) { Add-Finding 'posture.smartscreen_sac' 'Edge SmartScreen disabled by policy' medium hardening -Evidence @(Ev 'registry' 'HKLM|HKCU\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 0) -Rec 'Remove the policy value unless an administrator set it.' -Fp 'Managed devices.' -Mitre @('T1562.001') }
    if ($app -eq 0) { Add-Finding 'posture.smartscreen_sac' 'SmartScreen for Microsoft Store apps is off' low hardening -Evidence @(Ev 'registry' 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation' 0) -Rec 'Turn it on in Reputation-based protection.' -Fp 'User preference.' }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.platform' -Description 'Secure Boot, VBS/HVCI (Win32_DeviceGuard), Credential Guard, vulnerable-driver blocklist, LSA RunAsPPL, WDigest, LimitBlankPasswordUse, NoLMHash' -Script {
    $sb = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    $dg = $null; try { $dg = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard } catch { }
    $run2 = @($dg.SecurityServicesRunning); $hvci = if ($dg) { $run2 -contains 2 } else { (Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled') -eq 1 }
    $bl = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'; $lsa = Get-RegMap 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    $wd = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    Add-Posture 'platform' 'Secure Boot' $sb '1' $(if ($sb -eq 1) { 'ok' } else { 'weak' }) 'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    Add-Posture 'platform' 'VBS status / HVCI running' "$($dg.VirtualizationBasedSecurityStatus) / $hvci" '2 / True' $(if ($hvci) { 'ok' } else { 'weak' }) $(if ($dg) { 'Win32_DeviceGuard' } else { 'registry' })
    Add-Posture 'platform' 'Credential Guard running' $(if ($dg) { $run2 -contains 1 } else { 'unknown' }) $(if ($S.IsHome) { 'n/a on Home' } else { 'True' }) 'info' 'Win32_DeviceGuard'
    Add-Posture 'platform' 'Vulnerable driver blocklist' $bl '1 (or unset = default on)' $(if ($bl -eq 0) { 'weak' } else { 'ok' }) 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config'
    Add-Posture 'platform' 'LSA RunAsPPL' $lsa['RunAsPPL'] '1 or 2' $(if ($lsa['RunAsPPL'] -in 1, 2) { 'ok' } else { 'weak' }) 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    Add-Posture 'platform' 'WDigest UseLogonCredential' $wd 'unset/0' $(if ($wd -eq 1) { 'risk' } else { 'ok' }) 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if ($sb -ne 1) { Add-Finding 'posture.platform' 'Secure Boot is off or unsupported' medium hardening -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled' $sb) -Rec 'Enable Secure Boot in UEFI setup.' -Fp 'Dual-boot or Linux setups sometimes need it off.' -Mitre @('T1542') }
    if (-not $hvci) { Add-Finding 'posture.platform' 'Memory integrity (HVCI) is not running' low hardening -Evidence @(Ev 'wmi' 'Win32_DeviceGuard' 'SecurityServicesRunning' ($run2 -join ',')) -Rec 'Windows Security > Device security > Core isolation: turn Memory integrity on.' -Fp 'Old drivers or hypervisor tools can block it.' }
    if ($bl -eq 0) { Add-Finding 'posture.platform' 'Microsoft vulnerable-driver blocklist is disabled' medium hardening -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable' 0) -Rec 'Turn the blocklist back on in Core isolation settings.' -Fp 'Disabled to run an old driver.' -Mitre @('T1562.001', 'T1068') }
    if ($lsa['RunAsPPL'] -notin 1, 2) { Add-Finding 'posture.platform' 'LSA protection (RunAsPPL) is off' low hardening -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' $lsa['RunAsPPL']) -Rec 'Core isolation > Local Security Authority protection: on.' -Fp 'Incompatible security plug-ins.' -Mitre @('T1003.001') }
    if ($wd -eq 1) { Add-Finding 'posture.platform' 'WDigest plaintext credential caching is enabled (UseLogonCredential=1)' high suspicious -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 1) -Rec 'Set UseLogonCredential to 0 and investigate: attackers enable this before dumping passwords.' -Fp 'Legacy application compatibility (rare at home).' -Mitre @('T1112', 'T1003.001') }
    foreach ($n in 'LimitBlankPasswordUse', 'NoLMHash') { if ($lsa[$n] -eq 0) { Add-Finding 'posture.platform' "LSA $n is 0 (weakened default)" medium hardening -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' $n 0) -Rec "Restore $n=1." -Fp 'Legacy compatibility tweak.' -Mitre @('T1112') } }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.windows_update' -Description 'Last hotfix (Win32_QuickFixEngineering) and last successful WU install (COM history), WU pause/disable/WSUS policies, wuauserv/UsoSvc start type' -Script {
    $qd = @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object { $raw = [string]$_.CimInstanceProperties['InstalledOn'].Value; $d = [datetime]::MinValue; if ([datetime]::TryParseExact($raw, [string[]]@('M/d/yyyy', 'yyyyMMdd', 'yyyy-MM-dd'), [cultureinfo]::InvariantCulture, 'AssumeLocal', [ref]$d)) { [pscustomobject]@{ id = $_.HotFixID; date = $d } } })
    $lastQfe = $qd | Sort-Object date -Descending | Select-Object -First 1; $lastWu = $null; $fails = $null
    try { $se = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $hist = @($se.QueryHistory(0, [Math]::Min($se.GetTotalHistoryCount(), 60))); $lastWu = $hist | Where-Object { $_.ResultCode -in 2, 3 -and $_.Operation -eq 1 } | Sort-Object Date -Descending | Select-Object -First 1; $fails = @($hist | Where-Object { $_.ResultCode -in 4, 5 -and $_.Date -gt $D30 }).Count } catch { }
    $last = @($lastQfe.date, $lastWu.Date) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $age = if ($last) { [int]($Now - $last.ToUniversalTime()).TotalDays } else { $null }
    $wp = Get-RegMap 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; $au = Get-RegMap 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; $ux = Get-RegMap 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $paused = @(foreach ($n in 'PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesEndTime') { $v = ConvertTo-Iso $ux[$n]; if ($v -and [datetime]$v -gt $Now) { "$n=$v" } })
    $svc = @('wuauserv', 'UsoSvc') | ForEach-Object { "$_=$($S.Svc[$_].StartMode)" }
    Add-Posture 'update' 'Last update installed' "$(ConvertTo-Iso $last) ($age days; QFE $($lastQfe.id); WU '$($lastWu.Title)')" '< 45 days' $(if ($null -eq $age) { 'unknown' } elseif ($age -gt 45) { 'weak' } else { 'ok' }) 'Win32_QuickFixEngineering + Microsoft.Update.Session'
    Add-Posture 'update' 'WU services / policies / pause' "$($svc -join ' '); policies=$($wp.Count + $au.Count); paused=$($paused -join ',') failures30d=$fails" 'Manual/Auto, none, none' $(if ($paused -or $wp.Count -or $au.Count) { 'weak' } else { 'ok' }) 'services, registry'
    if ($age -gt 45) { Add-Finding 'posture.windows_update' "No Windows update installed for $age days" $(if ($age -gt 120) { 'high' } else { 'medium' }) hardening -Evidence @(Ev 'wmi' 'Win32_QuickFixEngineering' $lastQfe.id (ConvertTo-Iso $last)) -Rec 'Settings > Windows Update > Check for updates.' -Fp 'Recently reinstalled or offline machine.' }
    if ($S.Svc['wuauserv'].StartMode -eq 'Disabled' -or $S.Svc['UsoSvc'].StartMode -eq 'Disabled' -or $au['NoAutoUpdate'] -eq 1 -or $wp['DisableWindowsUpdateAccess'] -eq 1) { Add-Finding 'posture.windows_update' 'Windows Update is disabled (service or policy)' medium hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' ($svc -join ' ')) -Rec 'Re-enable the Windows Update service and remove blocking policies.' -Fp 'Update-blocker tools used deliberately.' -Mitre @('T1562.001') }
    if ($wp['WUServer'] -and -not $S.Domain) { Add-Finding 'posture.windows_update' "Windows Update redirected to a WSUS server on a non-domain PC: $($wp['WUServer'])" high suspicious -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer' $wp['WUServer']) -Rec 'Remove WUServer/UseWUServer unless your employer manages this PC.' -Fp 'Former company-managed device.' -Mitre @('T1557') }
    if ($paused.Count) { Add-Finding 'posture.windows_update' 'Windows updates are paused' low hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' ($paused -join ', ')) -Rec 'Resume updates in Settings > Windows Update.' -Fp 'User paused updates temporarily.' }
} | Out-Null
$S.Wsc = @(Invoke-BvsCheck -Run $run -Id 'posture.security_center' -Description 'Security Center antivirus/antispyware/firewall products with decoded productState, product exe existence and signature' -Script {
        foreach ($c in @(@('AntiVirusProduct', 'antivirus'), @('AntiSpywareProduct', 'antispyware'), @('FirewallProduct', 'firewall'))) {
            foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName $c[0])) {
                $st = [int]$p.productState; $exe = ([string]$p.pathToSignedProductExe) -replace '^\\\\\?\\', ''
                $exists = if ($exe -and $exe -notmatch '^[a-z]+://') { [IO.File]::Exists([Environment]::ExpandEnvironmentVariables($exe)) } else { $null }; $sig = if ($exists) { Get-BvsSignature -Path $exe } else { $null }
                [ordered]@{ type = $c[1]; displayName = [string]$p.displayName; productState = ('0x{0:X6}' -f $st); state = @('off', 'on', 'snoozed', 'expired')[[Math]::Min((($st -shr 12) -band 0xF), 3)]
                    signatures = $(if ($c[1] -eq 'firewall') { $null } elseif ((($st -shr 4) -band 0xF) -eq 0) { 'up-to-date' } else { 'out-of-date' }); microsoft = ((($st -shr 8) -band 0xF) -eq 1)
                    productExe = $exe; exeExists = $exists; exeSig = $sig.Status; exeSigner = $sig.Signer; timestamp = (ConvertTo-Iso $p.timestamp) }
            } }
    })
Invoke-BvsCheck -Run $run -Id 'posture.security_center_eval' -Description 'Evaluate Security Center products: active AV, Defender off because of Avast (expected), stale or unsigned registrations' -Script {
    $av = @($S.Wsc | Where-Object { $_.type -eq 'antivirus' -and $_.displayName -match 'Avast' })
    $S.AvastInstalled = [bool]$av.Count -or [bool]($S.Uninst | Where-Object { $_.displayName -match '^Avast (Free|Premium|One|Antivirus|Business|Security)' }) -or $S.Svc.ContainsKey('avast! Antivirus')
    $S.AvastOn = [bool]($av | Where-Object { $_.state -eq 'on' }); $S.AvastOld = if ($av.Count) { [bool]($av | Where-Object { $_.signatures -eq 'out-of-date' }) } else { $null }
    $S.Fw3p = [bool]($S.Wsc | Where-Object { $_.type -eq 'firewall' -and -not $_.microsoft -and $_.state -eq 'on' -and $_.exeExists -ne $false })
    $onAv = @($S.Wsc | Where-Object { $_.type -eq 'antivirus' -and $_.state -eq 'on' -and $_.exeExists -ne $false })
    foreach ($p in $S.Wsc) { Add-Posture 'securityCenter' "$($p.type): $($p.displayName)" "$($p.state) $($p.productState) sig=$($p.signatures) exe=$($p.exeExists)" '' $(if ($p.exeExists -eq $false) { 'weak' } else { 'info' }) 'root/SecurityCenter2' }
    $ev = @($S.Wsc | ForEach-Object { Ev 'wmi' "root/SecurityCenter2 $($_.type)" $_.displayName "$($_.state) $($_.productState) $($_.signatures)" })
    if (-not $onAv.Count) { Add-Finding 'posture.security_center' 'No active antivirus registered in Security Center' high hardening -Evidence $ev -Rec 'Turn Microsoft Defender back on or repair your antivirus.' -Fp 'Security Center can lag right after an AV update.' -Mitre @('T1562.001') }
    foreach ($p in @($onAv | Where-Object { $_.signatures -eq 'out-of-date' })) { Add-Finding 'posture.security_center' "Antivirus definitions out of date: $($p.displayName)" medium hardening -Evidence $ev -Rec 'Update the antivirus definitions.' -Fp 'Machine was offline.' }
    foreach ($p in @($S.Wsc | Where-Object { $_.type -eq 'antivirus' -and $_.microsoft -and $_.state -ne 'on' })) {
        $item = Get-BvsExpected -Category securityCenter | Where-Object { $_.match.defenderOffBecause } | Select-Object -First 1
        Add-Finding 'posture.security_center' "Microsoft Defender antivirus is $($p.state)" high hardening -Evidence $ev -Rec 'Fine while another antivirus is on and current; otherwise re-enable Defender.' -Fp 'Defender switches itself off when a third-party AV registers.' -Mitre @('T1562.001') -Exp (Resolve-Exp $item)
    }
    foreach ($p in @($S.Wsc | Where-Object { $_.exeExists -eq $false })) {
        $item = Get-BvsExpected -Category securityCenter | Where-Object { $_.match.displayName -and $p.displayName -like "*$($_.match.displayName)*" -and $_.match.productType -eq $p.type -and (-not $_.match.pathMissing -or $_.match.pathMissing -eq $p.productExe) } | Select-Object -First 1
        Add-Finding 'posture.security_center' "Stale Security Center registration: $($p.displayName) ($($p.type)) claims '$($p.state)' but its executable is missing" medium hygiene -Evidence @(Ev 'wmi' "root/SecurityCenter2 $($p.type)" $p.displayName $p.productExe) -Rec "Run the vendor's removal tool (e.g. MCPR for McAfee) to clear the registration." -Fp 'Left behind by an incomplete uninstall.' -Exp (Resolve-Exp $item)
    }
    foreach ($p in @($S.Wsc | Where-Object { $_.exeExists -and $_.exeSig -ne 'Valid' })) { Add-Finding 'posture.security_center' "Security Center product executable is not validly signed: $($p.displayName)" high suspicious -Reasons @('unsigned') -Evidence @(Ev 'file' $p.productExe 'signature' "$($p.exeSig) $($p.exeSigner)") -Rec 'Verify the product; fake AV registrations hide malware.' -Fp 'Signature check failing during an update.' -Mitre @('T1036') }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.defender_policies' -Description 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (Disable*, exclusions, Spynet, threat overrides) + non-policy Defender state' -Script {
    $root = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; $all = @(Get-RegTree $root); $vals = @($all | Where-Object { -not $_.Denied })
    $denied = @($all | Where-Object { $_.Denied } | ForEach-Object { $_.Key })
    $bad = @($vals | Where-Object { ($_.Name -match '^Disable' -and $_.Value -eq 1) -or $_.Key -match '\\Exclusions\\' -or ($_.Name -eq 'SpynetReporting' -and $_.Value -eq 0) -or ($_.Name -eq 'SubmitSamplesConsent' -and $_.Value -eq 2) -or $_.Key -match '\\Threats\\ThreatIdDefaultAction' })
    $np = Get-RegMap 'HKLM\SOFTWARE\Microsoft\Windows Defender'
    $exState = try { $k = Open-BvsRegKey -Path 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions'; if ($k) { $k.Dispose(); 'readable' } else { 'absent' } } catch { 'denied' }
    if ($exState -eq 'denied' -or $denied.Count) { Set-BvsCheckStatus -Id 'posture.defender_policies' -Status partial -Reason "Need admin: local Defender exclusions ($exState) and policy subkeys [$($denied -join '; ')]; all other policy keys were read" }
    Add-Posture 'defender' 'Defender policy values' $vals.Count '0 disabling values' $(if ($bad.Count) { 'risk' } else { 'ok' }) $root
    Add-Posture 'defender' 'Defender DisableAntiSpyware/DisableAntiVirus (non-policy)' "$($np['DisableAntiSpyware'])/$($np['DisableAntiVirus'])" '1/1 is set by Defender itself while a third-party AV is active' 'info' 'HKLM\SOFTWARE\Microsoft\Windows Defender'
    if ($bad.Count) { Add-Finding 'posture.defender_policies' "Defender-disabling or exclusion policies present ($($bad.Count) values)" high suspicious -Conf high -Evidence @($bad | Select-Object -First 20 | ForEach-Object { Ev 'registry' $_.Key $_.Name $_.Value }) -Rec 'Delete these policy values unless your organisation set them, then run a full scan; malware sets them, Avast does not.' -Fp 'Corporate GPO or deliberate tweaking tools.' -Mitre @('T1562.001') }
    if ($np['DisableAntiSpyware'] -eq 1 -and -not $S.AvastOn -and -not ($S.Wsc | Where-Object { $_.type -eq 'antivirus' -and -not $_.microsoft -and $_.state -eq 'on' })) { Add-Finding 'posture.defender_policies' 'Defender is disabled although no third-party antivirus is active' high suspicious -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Microsoft\Windows Defender' 'DisableAntiSpyware' 1) -Rec 'Re-enable Defender and scan with an offline scanner.' -Fp 'Remnant of an uninstalled AV.' -Mitre @('T1562.001') }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.firewall' -Description 'Windows Firewall profiles (ActiveStore): enabled, default inbound/outbound action; active network categories' -Script {
    $fp = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{ profile = [string]$_.Name; enabled = [string]$_.Enabled; defaultInbound = [string]$_.DefaultInboundAction; defaultOutbound = [string]$_.DefaultOutboundAction; allowInboundRules = [string]$_.AllowInboundRules } })
    $nets = @(try { Get-NetConnectionProfile | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" } } catch { })
    $S.Remote.firewall = [ordered]@{ profiles = $fp; networks = $nets; thirdPartyFirewallOn = $S.Fw3p }
    foreach ($p in $fp) {
        $weak = $p.enabled -eq 'False' -or $p.defaultInbound -eq 'Allow'
        Add-Posture 'firewall' "$($p.profile) profile" "enabled=$($p.enabled) inbound=$($p.defaultInbound) outbound=$($p.defaultOutbound)" 'enabled=True inbound=Block' $(if ($weak -and -not $S.Fw3p) { 'risk' } else { 'ok' }) 'Get-NetFirewallProfile -PolicyStore ActiveStore'
        if ($weak -and -not $S.Fw3p) { Add-Finding 'posture.firewall' "Windows Firewall $($p.profile) profile is off or allows inbound by default" $(if ($p.profile -eq 'Public' -or $p.defaultInbound -eq 'Allow') { 'high' } else { 'medium' }) hardening -Evidence @(Ev 'firewall' $p.profile 'Enabled/DefaultInboundAction' "$($p.enabled)/$($p.defaultInbound)") -Rec 'Windows Security > Firewall & network protection: turn the profile on with inbound Block.' -Fp 'A third-party firewall not registered in Security Center.' -Mitre @('T1562.004') }
    }
    Add-Posture 'firewall' 'Active network categories' ($nets -join ', ') '' 'info' 'Get-NetConnectionProfile'
    $fp
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.powershell' -Description 'Execution policy for every scope (pwsh + Windows PowerShell registry), script-block logging policy' -Script {
    $eps = @(Get-ExecutionPolicy -List | ForEach-Object { [ordered]@{ engine = 'pwsh'; scope = [string]$_.Scope; policy = [string]$_.ExecutionPolicy } })
    foreach ($w in @(@('HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell', 'LocalMachine'), @('HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell', 'CurrentUser'), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'MachinePolicy'), @('HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'UserPolicy'))) { $eps += [ordered]@{ engine = 'WindowsPowerShell'; scope = $w[1]; policy = (Get-RegV $w[0] 'ExecutionPolicy') } }
    $sbl = @((Get-RegV 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'), (Get-RegV 'HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'EnableScriptBlockLogging')) -contains 1
    $loose = @($eps | Where-Object { $_.scope -ne 'Process' -and $_.policy -in 'Unrestricted', 'Bypass' })
    foreach ($e in $eps) { Add-Posture 'powershell' "$($e.engine) $($e.scope)" $e.policy 'Undefined/RemoteSigned/AllSigned' $(if ($e.scope -eq 'Process') { 'info' } elseif ($e.policy -in 'Unrestricted', 'Bypass') { 'weak' } else { 'ok' }) $(if ($e.scope -eq 'Process') { 'this collector runs with -ExecutionPolicy Bypass' } else { 'Get-ExecutionPolicy / registry' }) }
    Add-Posture 'powershell' 'Script block logging policy' $sbl 'True' $(if ($sbl) { 'ok' } else { 'weak' }) 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if ($loose.Count) { Add-Finding 'posture.powershell' "Persistent PowerShell execution policy is Unrestricted/Bypass ($(@($loose | ForEach-Object { "$($_.engine) $($_.scope)" }) -join ', '))" low hardening -Evidence @($loose | ForEach-Object { Ev 'policy' "$($_.engine) $($_.scope)" 'ExecutionPolicy' $_.policy }) -Rec 'Set-ExecutionPolicy RemoteSigned for that scope (not a security boundary, but limits accidental script runs).' -Fp 'Developers relax it on purpose.' }
    if (-not $sbl) { Add-Finding 'posture.powershell' 'PowerShell script block logging is not enabled by policy' low hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' $null) -Rec 'Enable "Turn on PowerShell Script Block Logging" (registry policy) for better forensics.' -Fp 'Windows still logs suspicious script blocks automatically.' }
    $eps
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.autorun_wsh_smb1' -Description 'AutoRun (NoDriveTypeAutoRun), Windows Script Host Enabled, SMB1 client (mrxsmb10 Start) and server' -Script {
    $ndt = @((Get-RegV 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'), (Get-RegV 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'))
    $wsh = @((Get-RegV 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'), (Get-RegV 'HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled'))
    $smb = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'; $smbS = Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    Add-Posture 'misc' 'NoDriveTypeAutoRun (HKLM/HKCU)' ($ndt -join '/') '0xFF (unset = Windows default 0x91)' $(if ($ndt -contains 0) { 'weak' } else { 'ok' }) 'registry'
    Add-Posture 'misc' 'Windows Script Host Enabled (HKLM/HKCU)' ($wsh -join '/') '0 if unused' $(if ($wsh -contains 0) { 'ok' } else { 'weak' }) 'registry'
    Add-Posture 'misc' 'SMB1 client mrxsmb10 Start / server SMB1' "$smb / $smbS" 'absent or 4 / unset or 0' $(if ($smb -in 2, 3 -or $smbS -eq 1) { 'risk' } else { 'ok' }) 'registry'
    if ($ndt -contains 0) { Add-Finding 'posture.autorun_wsh_smb1' 'AutoRun allowed on all drive types (NoDriveTypeAutoRun=0)' low hardening -Evidence @(Ev 'registry' 'HKLM|HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 0) -Rec 'Set NoDriveTypeAutoRun=0xFF.' -Fp 'Old tweak.' -Mitre @('T1091') }
    if (-not ($wsh -contains 0)) { Add-Finding 'posture.autorun_wsh_smb1' 'Windows Script Host is enabled (.js/.vbs run on double-click)' low hardening -Evidence @(Ev 'registry' 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' 'Enabled' $wsh[0]) -Rec 'If you never run .vbs/.js scripts, set Enabled=0 (DWORD) under HKLM and HKCU "Software\Microsoft\Windows Script Host\Settings"; blocks a common ClickFix/JS-dropper path.' -Fp 'Windows default; some installers and admin scripts need it.' -Mitre @('T1059.005', 'T1059.007') }
    if ($smb -in 2, 3 -or $smbS -eq 1) { Add-Finding 'posture.autorun_wsh_smb1' 'SMB1 is enabled' medium hardening -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' $smb) -Rec 'Remove the "SMB 1.0/CIFS File Sharing Support" Windows feature.' -Fp 'Very old NAS devices.' -Mitre @('T1210') }
} | Out-Null
Invoke-BvsCheck -Run $run -Id 'posture.bitlocker' -Description 'BitLocker / device encryption (Get-BitLockerVolume; Shell property fallback when not elevated)' -Script {
    $vols = $null
    try { $vols = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { [ordered]@{ drive = $_.MountPoint; protection = [string]$_.ProtectionStatus; status = [string]$_.VolumeStatus; method = [string]$_.EncryptionMethod; source = 'Get-BitLockerVolume' } }) }
    catch {
        $why = $_.Exception.Message; $map = @{ 1 = 'On'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On (locked)'; 8 = 'Waiting for activation' }
        try { $sh = New-Object -ComObject Shell.Application; $vols = @(foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) { $v = $sh.NameSpace("$($d.DeviceID)\").Self.ExtendedProperty('System.Volume.BitLockerProtection'); [ordered]@{ drive = $d.DeviceID; protection = $(if ($null -ne $v -and $map.ContainsKey([int]$v)) { $map[[int]$v] } else { "unknown ($v)" }); source = 'Shell System.Volume.BitLockerProtection' } })
            Set-BvsCheckStatus -Id 'posture.bitlocker' -Status partial -Reason "Get-BitLockerVolume needs admin ($why); protection state read from the Shell property (no method/percentage)" }
        catch { Set-BvsCheckStatus -Id 'posture.bitlocker' -Status needs_admin -Reason $why; return }
    }
    $S.Remote.bitlocker = $vols
    foreach ($v in $vols) {
        $on = $v.protection -in 'On', 'On (locked)', 'Encrypting'
        Add-Posture 'encryption' "BitLocker $($v.drive)" $v.protection 'On' $(if ($on) { 'ok' } else { 'weak' }) $v.source
        if (-not $on -and $v.drive -eq $env:SystemDrive) { Add-Finding 'posture.bitlocker' "System drive $($v.drive) is not protected by BitLocker/device encryption ($($v.protection))" medium hardening -Evidence @(Ev 'volume' $v.drive 'protection' $v.protection $v.source) -Rec 'Settings > Privacy & security > Device encryption (Home) or BitLocker: turn it on and back up the recovery key.' -Fp 'Desktop PCs that never leave home.' }
    }
    $vols
} | Out-Null
#endregion

#region ---------- root certificates ----------
Invoke-BvsCheck -Run $run -Id 'certs.ctl' -Description 'Microsoft AuthRoot CTL: authrootstl.cab via Invoke-BvsIntel (Authenticode-verified, extracted under intel\), fallback to the cached EncodedCtl' -Script {
    $o = [ordered]@{ fresh = $null; freshError = $null; cached = $null; cachedError = $null }
    if ($Offline) { $o.freshError = 'skipped (-Offline)' } else {
        try {
            $resp = Invoke-BvsIntel -Uri $Ref.ctl.url -SaveName 'authrootstl.cab' -TimeoutSec 45 -MaxBytes 10MB
            $head = try { [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($resp.File), 0, 4) } catch { '' }
            if ($resp.Status -ne 200 -or $head -ne 'MSCF') { throw "HTTP $($resp.Status): saved file is not a CAB (head '$head'; Invoke-BvsIntel saved binary content as text under this PowerShell version - library issue)" }
            $sig = Get-BvsSignature -Path $resp.File
            if ($sig.Status -ne 'Valid' -or $sig.Signer -notmatch $Ref.ctl.cabSignerRegex) { throw "CAB signature not trusted: $($sig.Status) $($sig.Signer)" }
            $dest = [IO.Directory]::CreateDirectory((Join-Path $run.Root ('intel\ctldl.windowsupdate.com\' + [IO.Path]::GetFileNameWithoutExtension($resp.File) + '-extract'))).FullName
            $expandExe = Join-Path $env:SystemRoot 'System32\expand.exe'
            $null = & $expandExe $resp.File '-F:authroot.stl' $dest 2>&1
            $o.fresh = Read-Ctl ([IO.File]::ReadAllBytes((Join-Path $dest 'authroot.stl'))) 'authrootstl.cab (downloaded)'; $o.fresh.cabSigner = $sig.Signer
        } catch { $o.freshError = $_.Exception.Message }
    }
    try { $o.cached = Read-Ctl ([byte[]](Get-RegV 'HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate' 'EncodedCtl')) 'EncodedCtl (registry cache)' } catch { $o.cachedError = $_.Exception.Message }
    $S.Ctl = if ($o.fresh -and $o.fresh.signatureValid) { $o.fresh } elseif ($o.cached -and $o.cached.signatureValid) { $o.cached } else { $null }
    if (-not $S.Ctl) { Set-BvsCheckStatus -Id 'certs.ctl' -Status partial -Reason "No verified CTL ($($o.freshError); $($o.cachedError)); roots judged by heuristics" }
    elseif ($o.freshError -and -not $Offline) { Set-BvsCheckStatus -Id 'certs.ctl' -Status partial -Reason "CTL download failed, used the cached CTL: $($o.freshError)" }
    $S.CtlMeta = [ordered]@{ used = $S.Ctl.source; freshError = $o.freshError; cachedError = $o.cachedError; disableRootAutoUpdate = (Get-RegV 'HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' 'DisableRootAutoUpdate') }
    foreach ($n in 'fresh', 'cached') { if ($o[$n]) { $S.CtlMeta[$n] = [ordered]@{ signatureValid = $o[$n].signatureValid; signer = $o[$n].signer; sequence = $o[$n].sequence; thisUpdate = $o[$n].thisUpdate; entries = $o[$n].count; cabSigner = $o[$n].cabSigner } } }
    $S.CtlMeta
} | Out-Null
$CertRows = @(Invoke-BvsCheck -Run $run -Id 'certs.roots' -Description 'Root/AuthRoot/SmartCardRoot/policy/enterprise roots, HKCU user-added roots, Disallowed, TrustedPublisher: Cert: objects, registry LastWrite, comparison with the CTL and expected.json' -Script {
        $stores = @(@('LM_ROOT', 'HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates', 'Cert:\LocalMachine\Root', 'root'), @('LM_AUTHROOT', 'HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates', 'Cert:\LocalMachine\AuthRoot', 'root'),
            @('LM_SMARTCARDROOT', 'HKLM\SOFTWARE\Microsoft\SystemCertificates\SmartCardRoot\Certificates', 'Cert:\LocalMachine\Root', 'root'), @('LM_POLICY_ROOT', 'HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates', 'Cert:\LocalMachine\Root', 'root'),
            @('LM_ENTERPRISE_ROOT', 'HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates', 'Cert:\LocalMachine\Root', 'root'), @('CU_ROOT', 'HKCU\Software\Microsoft\SystemCertificates\Root\Certificates', 'Cert:\CurrentUser\Root', 'root'),
            @('CU_POLICY_ROOT', 'HKCU\Software\Policies\Microsoft\SystemCertificates\Root\Certificates', 'Cert:\CurrentUser\Root', 'root'), @('LM_DISALLOWED', 'HKLM\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates', 'Cert:\LocalMachine\Disallowed', 'disallowed'),
            @('LM_TRUSTEDPUBLISHER', 'HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Certificates', 'Cert:\LocalMachine\TrustedPublisher', 'publisher'), @('LM_POLICY_TRUSTEDPUBLISHER', 'HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates', 'Cert:\LocalMachine\TrustedPublisher', 'publisher'),
            @('CU_TRUSTEDPUBLISHER', 'HKCU\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates', 'Cert:\CurrentUser\TrustedPublisher', 'publisher'))
        $rows = @(foreach ($sd in $stores) { foreach ($tp in @(Get-BvsRegSubKeys -Path $sd[1])) {
                    if (-not $tp) { continue }; $tpU = $tp.ToUpperInvariant(); $c = $null
                    try { $c = Get-Item -LiteralPath "$($sd[2])\$tpU" -ErrorAction Stop } catch { try { $c = Get-CertFromBlob ([byte[]](Get-RegV "$($sd[1])\$tp" 'Blob')) } catch { } }
                    $lw = Get-BvsRegKeyLastWrite "$($sd[1])\$tp"
                    [ordered]@{ store = $sd[0]; kind = $sd[3]; thumbprint = $tpU; subject = $c.Subject; issuer = $c.Issuer; notBefore = (ConvertTo-Iso $c.NotBefore); notAfter = (ConvertTo-Iso $c.NotAfter); hasPrivateKey = [bool]$c.HasPrivateKey
                        registryLastWrite = (ConvertTo-Iso $lw); recent = [bool]($lw -and $lw -gt $Recent); recent30 = [bool]($lw -and $lw -gt $D30); inCtl = $null; ctlName = $null; status = $null; registryKey = "$($sd[1])\$tp" }
                } })
        $ctl = $S.Ctl; $builtin = @($Ref.builtinRootsNotInCtl | ForEach-Object { $_.thumbprint })
        $S.AvastRoots = @($rows | Where-Object { $_.kind -eq 'root' -and $_.subject -match 'Avast' } | ForEach-Object { $_.thumbprint } | Select-Object -Unique).Count
        foreach ($r in @($rows | Where-Object { $_.kind -eq 'root' })) {
            if ($ctl) { $r.inCtl = $ctl.subjects.ContainsKey($r.thumbprint); if ($r.inCtl) { $r.ctlName = $ctl.subjects[$r.thumbprint].name } }
            $exp = Resolve-Exp (Get-BvsExpected -Category rootCert | Where-Object { $_.match.subjectContains -and $r.subject -and $r.subject.IndexOf([string]$_.match.subjectContains, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1)
            $msLike = $r.subject -and $r.subject -eq $r.issuer -and $r.subject -match 'O=Microsoft|Microsoft Root'
            $r.status = if ($r.inCtl) { 'microsoft-root-program' } elseif ($builtin -contains $r.thumbprint) { 'windows-builtin' } elseif ($exp) { if ($exp.cancelled) { 'expected-cancelled' } else { 'expected' } } elseif ($null -eq $r.inCtl) { if ($msLike) { 'microsoft-unverified' } else { 'unverified' } } else { 'unknown' }
            if ($r.status -in 'microsoft-root-program', 'windows-builtin', 'microsoft-unverified') { continue }
            $short = if ($r.subject) { $r.subject -replace ',.*$', '' } else { "(unreadable) $($r.thumbprint)" }; $user = $r.store -like 'CU_*'
            $ev = @(Ev 'registry' $r.registryKey $r.thumbprint "$($r.subject) | issuer: $($r.issuer) | valid $($r.notBefore)..$($r.notAfter) | key LastWrite $($r.registryLastWrite)")
            if ($r.status -eq 'expected') { Add-Finding 'certs.roots' "Expected HTTPS-scanning root present: $short" info info -Evidence $ev -Fp "$($exp.reason) Its registry LastWrite is refreshed whenever the product rewrites the key (e.g. at service start), so it is not an install date." -Rec 'Nothing to do while you use Avast Web Shield HTTPS scanning; the root goes away when Avast is uninstalled.' -Mitre @('T1553.004') -Exp $exp; continue }
            $sev = if ($r.status -eq 'unverified' -and -not $r.recent -and -not $user) { 'medium' } else { 'high' }
            $rs = @('not_in_ctl'; if ($user) { 'user_store' }; if ($r.recent30) { 'created_lt_30d' } elseif ($r.recent) { 'created_recent' }; if ($r.hasPrivateKey) { 'private_key_local' })
            Add-Finding 'certs.roots' "Trusted root CA not in Microsoft's root program ($($r.store)): $short" $sev suspicious -Conf $(if ($user -or $r.hasPrivateKey) { 'high' } else { 'medium' }) -Reasons $rs -Evidence $ev `
                -Rec "Open certlm.msc (machine) or certmgr.msc (user) > Trusted Root Certification Authorities and find thumbprint $($r.thumbprint). If no software you trust explains it (AV HTTPS scanning, corporate TLS inspection, VPN, Fiddler/Burp/mitmproxy), remove it and find what installed it around $($r.registryLastWrite)." `
                -Fp 'Antivirus HTTPS scanning, corporate TLS inspection, VPN clients and debugging proxies install private roots. Registry LastWrite is approximate.' -Mitre @('T1553.004', 'T1557') -Exp $exp
        }
        foreach ($r in @($rows | Where-Object { $_.kind -eq 'publisher' -and $_.recent })) { Add-Finding 'certs.roots' "Recently added Trusted Publisher: $($r.subject -replace ',.*$', '')" low suspicious -Evidence @(Ev 'registry' $r.registryKey $r.thumbprint $r.subject) -Rec 'certlm.msc > Trusted Publishers: remove it unless you recognise the publisher.' -Fp 'Driver installers (e.g. VirtualBox) add their publisher here.' -Mitre @('T1553') }
        $phys = @($rows | Where-Object { $_.kind -eq 'root' } | ForEach-Object { $_.thumbprint })
        foreach ($x in @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $phys -notcontains $_.Thumbprint } | Select-Object -Property Thumbprint, Subject -Unique)) {
            if ($ctl -and $ctl.subjects.ContainsKey($x.Thumbprint)) { continue }
            Add-Finding 'certs.roots' "Root visible in a logical store but in no registry store read: $($x.Subject -replace ',.*$', '')" high suspicious -Reasons @('not_in_ctl') -Evidence @(Ev 'certificate' 'Cert:\*\Root' $x.Thumbprint $x.Subject) -Rec 'Inspect it in certmgr.msc and find the physical store that provides it.' -Fp 'An unusual but legitimate physical store.' -Mitre @('T1553.004')
        }
        $rows
    })
#endregion

#region ---------- hosts and proxy ----------
$HostRows = @(Invoke-BvsCheck -Run $run -Id 'network.hosts' -Description 'hosts file (Tcpip DataBasePath aware): non-comment entries vs expected.json, Tailscale/Docker sections, sensitive domains, write permission' -Script {
        $dbRaw = [string](Get-RegV 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DataBasePath'); $db = [Environment]::ExpandEnvironmentVariables($dbRaw); $def = Join-Path $env:SystemRoot 'System32\drivers\etc'
        if ($db -and $db.TrimEnd('\') -ne $def) { Add-Finding 'network.hosts' "hosts file location redirected (DataBasePath=$dbRaw)" high suspicious -Evidence @(Ev 'registry' 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DataBasePath' $dbRaw) -Rec 'Restore DataBasePath to %SystemRoot%\System32\drivers\etc.' -Fp 'Almost never legitimate.' -Mitre @('T1565.001') }
        $hp = Join-Path $(if ($db) { $db } else { $def }) 'hosts'; $fi = [IO.FileInfo]::new($hp)
        $S.HostsMeta = [ordered]@{ path = $hp; dataBasePath = $dbRaw; size = $fi.Length; modified = (ConvertTo-Iso $fi.LastWriteTimeUtc); attributes = [string]$fi.Attributes; userWritable = (Test-BvsUserWritable -Path $hp) }
        if ($S.HostsMeta.userWritable) { Add-Finding 'network.hosts' 'hosts file is writable by the non-elevated user' high hardening -Evidence @(Ev 'file' $hp 'ACL' 'user-writable') -Rec 'Reset the hosts file ACL (Administrators/SYSTEM write only).' -Fp 'Some ad-blockers loosen it.' -Mitre @('T1565.001') }
        $exp = @(Get-BvsExpected -Category hosts); $section = $null; $rows = [Collections.Generic.List[object]]::new(); $self = $env:COMPUTERNAME.ToLowerInvariant()
        foreach ($line in [IO.File]::ReadLines($hp)) {
            if ($line -match '#\s*TailscaleHostsSectionStart') { $section = 'tailscale' } elseif ($line -match '#\s*TailscaleHostsSectionEnd') { $section = $null } elseif ($line -match '#\s*Added by Docker Desktop') { $section = 'docker' } elseif ($section -eq 'docker' -and $line -match '#\s*End of section') { $section = $null }
            $body = ($line -replace '#.*$', '').Trim(); if (-not $body) { continue }
            $parts = $body -split '\s+'; $ip = $parts[0]; $tsIp = $ip -match '^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.' -or $ip -like 'fd7a:115c:a1e0:*'
            foreach ($n in @($parts | Select-Object -Skip 1)) {
                $name = $n.TrimEnd('.').ToLowerInvariant(); $first = ($name -split '\.')[0]
                $item = $exp | Where-Object { $m = $_.match; ($m.hostname -and ($name -eq $m.hostname -or $name.EndsWith(".$($m.hostname)"))) -or ($m.hostnameRegex -and $name -match $m.hostnameRegex) -or ($m.hostnames -and (@($m.hostnames) -contains $name -or (@($m.hostnames) -contains $first -and ($section -eq 'tailscale' -or $name -like '*.ts.net')))) } | Select-Object -First 1
                $class = if ($section -eq 'tailscale' -and -not $tsIp) { 'tailscale-section-ip-outside-tailnet' } elseif ($item) { 'expected' } elseif ($section -eq 'tailscale' -and $first -eq $self) { 'self-tailscale' } elseif ($name -in 'localhost', 'localhost.localdomain' -and $ip -in '127.0.0.1', '::1') { 'localhost' } else { 'unexpected' }
                $rows.Add([ordered]@{ ip = $ip; name = $name; section = $section; class = $class; expected = $item.id; confirmWithUser = [bool]$item.confirmWithUser })
            } }
        $ok = @($rows | Where-Object { $_.class -in 'expected', 'self-tailscale', 'localhost' })
        if ($ok.Count) { Add-Finding 'network.hosts' "hosts entries explained ($($ok.Count)): $(@($ok | ForEach-Object { $_.expected } | Where-Object { $_ } | Select-Object -Unique) -join ', ')" info info -Evidence @($ok | Select-Object -First 25 | ForEach-Object { Ev 'hosts' $hp $_.name "$($_.ip) [$($_.class) $($_.expected)]" }) -Fp 'Matched expected.json or this machine''s own Tailscale MagicDNS name.' -Rec 'None.' }
        foreach ($g in @($rows | Where-Object { $_.confirmWithUser } | Group-Object { $_.expected })) { Add-Finding 'network.hosts' "Tailscale peer names in hosts need user confirmation: $(@($g.Group | ForEach-Object { $_.name }) -join ', ')" info info -Evidence @($g.Group | ForEach-Object { Ev 'hosts' $hp $_.name $_.ip }) -Rec 'Confirm each peer is your own device or one you shared on purpose (tailscale.com admin console > Machines).' -Fp 'MagicDNS writes peers here automatically.' -Exp (Resolve-Exp ($exp | Where-Object { $_.id -eq $g.Name } | Select-Object -First 1)) }
        $bad = @($rows | Where-Object { $_.class -notin 'expected', 'self-tailscale', 'localhost' })
        foreach ($r in $bad) {
            $sens = [bool]($Ref.sensitiveDomains | Where-Object { $r.name -eq $_ -or $r.name.EndsWith(".$_") }); $loop = $r.ip -match '^(127\.|0\.0\.0\.0$|::1?$)'
            $priv = $r.ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd)'; $local = [bool]($Ref.localNameSuffixes | Where-Object { $r.name.EndsWith($_) })
            $r.severity = if ($sens -or $r.class -ne 'unexpected' -or (-not $loop -and -not $priv)) { 'high' } elseif ($local -or $bad.Count -gt 50) { 'low' } else { 'medium' }
        }
        foreach ($r in @($bad | Where-Object { $_.severity -eq 'high' } | Select-Object -First 20)) { Add-Finding 'network.hosts' "hosts entry redirects or blocks $($r.name) -> $($r.ip)" high suspicious -Evidence @(Ev 'hosts' $hp $r.name $r.ip $r.class) -Rec 'Remove the line from the hosts file (admin editor) unless you added it, and look for the program that wrote it.' -Fp 'Developers map staging domains; ad-blockers null-route domains.' -Mitre @('T1565.001', 'T1562.001') }
        $rest = @($bad | Where-Object { $_.severity -ne 'high' })
        if ($rest.Count) { Add-Finding 'network.hosts' "Unexplained hosts entries ($($rest.Count))" $(if ($rest | Where-Object { $_.severity -eq 'medium' }) { 'medium' } else { 'low' }) suspicious -Evidence @($rest | Select-Object -First 25 | ForEach-Object { Ev 'hosts' $hp $_.name $_.ip }) -Rec 'Review and delete entries you did not add.' -Fp 'Local development names and ad-block lists.' -Mitre @('T1565.001') }
        $rows
    })
Invoke-BvsCheck -Run $run -Id 'network.proxy' -Description 'WinINET (HKCU/HKLM + policy + Connections blobs incl. WinHttpSettings), WinHTTP (netsh, read-only), proxy/TLS environment variables (User/Machine/Process), browser proxy policies' -Script {
    $items = [Collections.Generic.List[object]]::new()
    foreach ($k in 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings', 'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings', 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings') {
        $m = Get-RegMap $k; $S.Proxy[$k] = [ordered]@{ ProxyEnable = $m['ProxyEnable']; ProxyServer = (Protect-BvsUrl ([string]$m['ProxyServer'])); AutoConfigURL = (Protect-BvsUrl ([string]$m['AutoConfigURL'])); AutoDetect = $m['AutoDetect'] }
        if ($m['ProxyEnable'] -eq 1 -and $m['ProxyServer']) { $items.Add(@{ source = "$k ProxyServer"; value = [string]$m['ProxyServer'] }) }
        if ($m['AutoConfigURL']) { $items.Add(@{ source = "$k AutoConfigURL"; value = [string]$m['AutoConfigURL'] }) }
    }
    foreach ($k in 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections') {
        foreach ($v in @(Get-BvsRegValues -Path $k)) { if ($v -and $v.Value -is [byte[]]) { $d = Read-ConnBlob $v.Value; $S.Proxy["$k\$($v.Name)"] = $d
                if ($d.proxy -and ($d.flags -band 2)) { $items.Add(@{ source = "$k\$($v.Name) (proxy)"; value = $d.proxy }) }; if ($d.pac -and ($d.flags -band 4)) { $items.Add(@{ source = "$k\$($v.Name) (PAC)"; value = $d.pac }) } } } }
    $S.Proxy.winhttpNetsh = @(netsh winhttp show proxy 2>$null | Where-Object { $_ -match '\S' } | ForEach-Object { Protect-BvsText $_.Trim() })
    $envRows = @(foreach ($n in 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'GIT_SSL_NO_VERIFY') { foreach ($sc in 'User', 'Machine', 'Process') {
                $v = [Environment]::GetEnvironmentVariable($n, $sc)
                if ($v) { [ordered]@{ name = $n; scope = $sc; value = (Protect-BvsUrl $v); inheritedOnly = ($sc -eq 'Process' -and -not [Environment]::GetEnvironmentVariable($n, 'User') -and -not [Environment]::GetEnvironmentVariable($n, 'Machine')) } } } })
    $S.Proxy.environment = $envRows
    foreach ($e in @($envRows | Where-Object { $_.scope -ne 'Process' })) {
        $raw = [Environment]::GetEnvironmentVariable($e.name, $e.scope); $ev = @(Ev 'environment' $e.scope $e.name $e.value)
        if ($e.name -match 'PROXY$' -and $e.name -ne 'NO_PROXY') { $items.Add(@{ source = "environment $($e.scope) $($e.name)"; value = $raw }) }
        elseif ($e.name -eq 'NODE_OPTIONS' -and $raw -match '(^|\s)(--require|-r|--import|--loader|--experimental-loader)\b') { Add-Finding 'network.proxy' "NODE_OPTIONS preloads code into every Node.js process ($($e.scope))" high suspicious -Evidence $ev -Rec 'Remove the variable unless you set it; check the preloaded file.' -Fp 'APM/debug tooling.' -Mitre @('T1574') }
        elseif ($e.name -eq 'NODE_TLS_REJECT_UNAUTHORIZED' -and $raw -eq '0') { Add-Finding 'network.proxy' 'TLS certificate checks disabled for Node.js (NODE_TLS_REJECT_UNAUTHORIZED=0)' high hardening -Evidence $ev -Rec 'Delete the variable.' -Fp 'Left over from debugging.' -Mitre @('T1557') }
        elseif ($e.name -eq 'GIT_SSL_NO_VERIFY' -and $raw -match '^(1|true|yes)$') { Add-Finding 'network.proxy' 'Git TLS verification disabled (GIT_SSL_NO_VERIFY)' medium hardening -Evidence $ev -Rec 'Delete the variable.' -Fp 'Left over from debugging.' -Mitre @('T1557') }
        elseif ($e.name -in 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE' -and $raw -notmatch $Ref.explainedPathRegex) { Add-Finding 'network.proxy' "Extra CA bundle trusted via $($e.name) ($($e.scope))" medium suspicious -Evidence $ev -Rec 'Confirm the bundle belongs to software you trust (corporate proxy, AV); otherwise remove the variable.' -Fp 'Corporate TLS inspection or developer tooling.' -Mitre @('T1553.004') }
    }
    $inh = @($envRows | Where-Object { $_.inheritedOnly })
    if ($inh.Count) { Add-Finding 'network.proxy' "Process-only proxy/TLS variables inherited from the launching tool: $(@($inh | ForEach-Object { $_.name }) -join ', ')" info info -Evidence @($inh | ForEach-Object { Ev 'environment' 'Process' $_.name $_.value }) -Fp 'Not set in User or Machine scope: they come from the program that started this scan (e.g. the agent harness or Claude Code settings).' -Rec 'None for the system; review the launcher configuration if unexpected.' }
    foreach ($k in 'HKLM\SOFTWARE\Policies\Google\Chrome', 'HKCU\SOFTWARE\Policies\Google\Chrome', 'HKLM\SOFTWARE\Policies\Microsoft\Edge', 'HKCU\SOFTWARE\Policies\Microsoft\Edge') { $m = Get-RegMap $k; foreach ($n in 'ProxyServer', 'ProxyPacUrl', 'ProxySettings') { if ($m[$n]) { $items.Add(@{ source = "$k $n"; value = [string]$m[$n] }) } } }
    if (@(Get-BvsRegValues -Path 'HKLM\SOFTWARE\Policies\Mozilla\Firefox\Proxy').Count) { $items.Add(@{ source = 'HKLM\SOFTWARE\Policies\Mozilla\Firefox\Proxy'; value = 'policy set' }) }
    $S.Proxy.configured = @($items | ForEach-Object { [ordered]@{ source = $_.source; value = (Protect-BvsUrl $_.value) } })
    foreach ($it in $items) {
        $why = Get-ProxyWhy $it.value; $ev = @(Ev 'registry' $it.source $null (Protect-BvsUrl $it.value) $why)
        if ($why) { Add-Finding 'network.proxy' "Proxy/PAC explained by local security software: $($it.source)" info info -Evidence $ev -Fp $why -Rec 'None.' }
        else { Add-Finding 'network.proxy' "Proxy or PAC configured and not explained by Avast: $($it.source)" high suspicious -Reasons @('proxy') -Evidence $ev -Rec 'Settings > Network & internet > Proxy: turn it off if you did not set it and find the program that re-sets it.' -Fp 'Corporate proxies, VPN clients, Fiddler/Burp/mitmproxy and parental-control tools set proxies.' -Mitre @('T1090', 'T1557') }
    }
    $auto = @($S.Proxy.Values | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('autoDetect') -and $_.autoDetect }).Count
    Add-Posture 'proxy' 'Configured proxies/PAC (WinINET, WinHTTP, env, browser policy)' $items.Count '0' $(if ($items.Count) { 'risk' } else { 'ok' }) 'registry, netsh winhttp, environment'
    Add-Posture 'proxy' 'WPAD auto-detect (connection blobs with flag 0x08)' $auto 'Windows default on' 'info' 'Internet Settings\Connections'
    $S.Proxy
} | Out-Null
#endregion

Add-BvsInventory -Run $run -Name 'accounts' -Data ([ordered]@{ users = $S.Users; privilegedGroups = $S.Groups; hiddenUsers = $S.Hidden; profiles = $S.Profiles })
Add-BvsInventory -Run $run -Name 'remoteAccess' -Data $S.Remote
Add-BvsInventory -Run $run -Name 'remoteTools' -Data ([ordered]@{ catalog = 'src\collectors\security\windows\S03-remote-tools.json'; toolsInCatalog = $Tools.Count; detected = $RmmRows })
Add-BvsInventory -Run $run -Name 'posture' -Data $S.Posture
Add-BvsInventory -Run $run -Name 'securityCenter' -Data $S.Wsc
Add-BvsInventory -Run $run -Name 'rootCertificates' -Data ([ordered]@{ ctl = $S.CtlMeta; certificates = $CertRows })
Add-BvsInventory -Run $run -Name 'hosts' -Data ([ordered]@{ file = $S.HostsMeta; entries = $HostRows })
Add-BvsInventory -Run $run -Name 'proxy' -Data $S.Proxy
$sum = Complete-BvsRun -Run $run
Protect-BvsText "S03 done: $($sum.Findings) findings [$($sum.BySeverity)], $($sum.Checks) checks, $($sum.Errors) errors -> $($sum.Path)"
foreach ($c in @($run.Checks | Where-Object { $_.status -ne 'ok' })) { Protect-BvsText "  check $($c.id): $($c.status) $($c.reason)" }
foreach ($f in @($run.Findings | Where-Object { $_.severity -ne 'info' })) { Protect-BvsText "  [$($f.severity)/$($f.class)] $($f.title)" }
