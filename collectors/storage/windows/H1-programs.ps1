#Requires -Version 7.0
<#
.SYNOPSIS
  H1 - Programs, startup load, resource hogs, crashes, battery and power plan (Windows, read-only).
.DESCRIPTION
  Writes data\<scanId>\storage\H1.json (bvs.module/1). Inventory keys: programs, startupItems,
  resourceHogs, crashes, battery, powerPlan, summary. Items use the bvs.items/1 shape.
  Reuses G0 inventory\dirs.tsv (folder sizes) and S01 autostarts. Changes nothing.
  Admin-only sources (StartupInfo, BAM, Prefetch) are recorded as needs_admin.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$run     = Initialize-BvsRun -Module H1 -Area storage
$scanDir = Split-Path $run.OutDir -Parent
$script:seq = 0; $script:sigCache = @{}; $script:perf = @{}; $script:ua = @(); $script:procPaths = @()
$script:procTable = @(Get-BvsProcessTable)
$script:svcRaw = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)
$nowUtc = (Get-Date).ToUniversalTime()

function New-H1Item {
    param([string]$Prefix, [string]$Path, [string]$Kind, $Bytes, [string]$Category, [string]$Purpose, [string]$Owner,
          [string]$Safety = 'review', [string]$Method = 'none', [string]$How = '', [bool]$Reversible = $true,
          [string[]]$Flags = @(), [System.Collections.IDictionary]$Extra)
    $script:seq++
    $o = [ordered]@{ id = ('{0}-{1:d5}' -f $Prefix, $script:seq); path = $Path; kind = $Kind; bytes = $Bytes
        category = $Category; purpose = $Purpose; owner = $Owner; safety = $Safety; method = $Method; how = $How
        reversible = $Reversible; flags = @($Flags | Where-Object { $_ } | Select-Object -Unique) }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    [pscustomobject]$o
}
function Expand-H1([string]$s) { if ($s) { [Environment]::ExpandEnvironmentVariables($s.Trim().Trim('"')).TrimEnd('\') } }
function Get-H1RegMap([string]$Path, [string]$View) {
    $h = @{}
    $vals = if ($View) { Get-BvsRegValues -Path $Path -View $View } else { Get-BvsRegValues -Path $Path }
    foreach ($v in @($vals)) { if ($v) { $h[$v.Name] = $v.Value } }
    $h
}
function Get-H1Signer([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    if (-not $script:sigCache.ContainsKey($Path)) { $script:sigCache[$Path] = Get-BvsSignature -Path $Path }
    $script:sigCache[$Path]
}
function Get-H1Env([string]$Name) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if (-not $v) { $v = (Get-H1RegMap 'HKCU\Environment')[$Name] }
    if (-not $v) { $v = (Get-H1RegMap 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment')[$Name] }
    Expand-H1 $v
}
function ConvertFrom-H1Rot13([string]$s) {
    $sb = [System.Text.StringBuilder]::new($s.Length)
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { $c = 65 + (($c - 52) % 26) } elseif ($c -ge 97 -and $c -le 122) { $c = 97 + (($c - 84) % 26) }
        [void]$sb.Append([char]$c)
    }
    $sb.ToString()
}
# UserAssist: ROT13 names; Win10+ data is 72 bytes, run count at offset 4, last-run FILETIME at offset 60.
function Get-H1UserAssist {
    $kf = @{
        '{6D809377-6AF0-444B-8957-A3773F02200E}' = $env:ProgramW6432; '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = ${env:ProgramFiles(x86)}
        '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = [Environment]::GetFolderPath('System'); '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = [Environment]::GetFolderPath('SystemX86')
        '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $env:windir; '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = [Environment]::GetFolderPath('CommonPrograms')
        '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = [Environment]::GetFolderPath('Programs'); '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = $env:LOCALAPPDATA
        '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = $env:APPDATA; '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' = $env:ProgramData
        '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = (Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned')
    }
    $base = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    foreach ($g in @(Get-BvsRegSubKeys -Path $base)) {
        foreach ($v in @(Get-BvsRegValues -Path "$base\$g\Count")) {
            if ($null -eq $v -or $v.Value -isnot [byte[]] -or $v.Value.Length -lt 68) { continue }
            $name = ConvertFrom-H1Rot13 $v.Name
            if ($name -like 'UEME_*') { continue }
            $last = $null; try { $ft = [BitConverter]::ToInt64($v.Value, 60); if ($ft -gt 0) { $last = [DateTime]::FromFileTimeUtc($ft) } } catch { $last = $null }
            $p = $name
            if ($name -match '^(\{[0-9A-Fa-f-]{36}\})\\(.*)$' -and $kf[$Matches[1]]) { $p = Join-Path $kf[$Matches[1]] $Matches[2] }
            $lnk = if ($p -like '*.lnk') { [IO.Path]::GetFileNameWithoutExtension($p).ToLowerInvariant() -replace '[^a-z0-9]', '' } else { '' }
            [pscustomobject]@{ NameL = $name.ToLowerInvariant(); PathL = $p.ToLowerInvariant(); Count = [BitConverter]::ToInt32($v.Value, 4); Last = $last; LnkKey = $lnk }
        }
    }
}
function Find-H1Usage([string]$Loc, [string]$Exe, [string]$NameKey, [string]$Pfn) {
    $locL = if ($Loc) { $Loc.ToLowerInvariant() + '\' } else { $null }
    $exeL = if ($Exe) { $Exe.ToLowerInvariant() } else { $null }
    $pfnL = if ($Pfn) { $Pfn.ToLowerInvariant() + '!' } else { $null }
    if ($locL -and @($script:procPaths | Where-Object { $_.StartsWith($locL) }).Count) {
        return [pscustomobject]@{ Last = $nowUtc; Source = 'running now (a process from the install folder; may be a background service)'; Count = $null } }
    $last = $null; $count = 0; $hits = 0
    foreach ($u in $script:ua) {
        $hit = ($locL -and $u.PathL.StartsWith($locL)) -or ($exeL -and $u.PathL -eq $exeL) -or ($pfnL -and $u.NameL.StartsWith($pfnL)) -or
               ($u.LnkKey.Length -ge 5 -and $NameKey -and $NameKey.Contains($u.LnkKey) -and ($u.LnkKey.Length * 2) -ge $NameKey.Length)
        if (-not $hit) { continue }
        $hits++; $count += $u.Count
        if ($u.Last -and (-not $last -or $u.Last -gt $last)) { $last = $u.Last }
    }
    if ($hits) { return [pscustomobject]@{ Last = $last; Source = 'UserAssist (Explorer launches only)'; Count = $count } }
    [pscustomobject]@{ Last = $null; Source = 'unknown (UserAssist only sees Explorer launches)'; Count = $null }
}
function Get-H1DirSizes($Want) {
    $res = @{}; $f = Join-Path $scanDir 'inventory\dirs.tsv'
    if (-not (Test-Path -LiteralPath $f) -or $Want.Count -eq 0) { return $res }
    foreach ($line in [IO.File]::ReadLines($f)) {
        $i1 = $line.IndexOf("`t"); if ($i1 -lt 0) { continue }
        $i2 = $line.IndexOf("`t", $i1 + 1); $i3 = $line.IndexOf("`t", $i2 + 1); $i4 = $line.IndexOf("`t", $i3 + 1)
        if ($i4 -lt 0) { continue }
        $p = $line.Substring($i3 + 1, $i4 - $i3 - 1)
        if ($Want.Contains($p)) { $x = $line.Split("`t"); $res[$p] = [pscustomobject]@{ Bytes = [int64]$x[6]; Files = [int64]$x[7] } }
    }
    $res
}

function Get-H1PerfSample { @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop | Where-Object { $_.IDProcess -gt 0 -and $_.IDProcess -ne $PID -and $_.Name -notin '_Total', 'Idle' }) }
function ConvertTo-H1Number([string]$s) { $d = ($s -replace '[^\d]', ''); if ($d) { [int64]$d } else { $null } }

# Generic product knowledge (not machine-specific). Later rules override earlier safety.
$rules = @(
    @{ Re = '^McAfee|Norton|WildTangent|ExpressVPN|Booking\.com|Dropbox (Promotion|Offer)|ASUS GiftBox|CyberLink .*(Trial|Essential)|WPS Office|Candy Crush'; Flags = @('bloat_candidate', 'oem_trialware'); Safety = 'safe_after_check'; Note = 'Typical OEM pre-installed trial/promo software.' }
    @{ Re = 'WebAdvisor'; Flags = @('pup_candidate', 'bloat_candidate'); Safety = 'safe_after_check'; Note = 'Browser add-on bundled with other installers; redundant next to your antivirus and browser protection.' }
    @{ Re = 'CCleaner|Advanced SystemCare|Driver Booster|IObit|Reimage|Restoro|PC (Optimizer|Cleaner)|Segurazo|ByteFence|OneLaunch|Wave Browser|WebCompanion|Driver (Easy|Support|Updater)'; Flags = @('pup_candidate'); Safety = 'safe_after_check'; Note = 'Cleaner/optimizer/driver-updater class: commonly PUP, no real speed gain.' }
    @{ Re = '(Avast|AVG|Norton|CCleaner) (Secure )?Browser'; Flags = @('bundled_browser'); Safety = 'review'; Note = 'Browser bundled with an antivirus installer.' }
    @{ Re = 'Splunk|Elasticsearch|Kibana|Logstash|OpenSearch'; Flags = @('server_software'); Safety = 'review'; Note = 'Server software with background services; uninstall if you no longer use it.' }
)
$dnt = 'Visual C\+\+|\.NET (Runtime|Desktop Runtime|Framework)|Windows Desktop Runtime|ASP\.NET Core|Microsoft Edge|WebView2|Windows Software Development Kit|Driver|Chipset|Realtek|Intel\(R\)|NVIDIA|AMD Software|Update Health Tools|PC Health Check|Windows App Runtime'
$npmNotes = @{ 'supabase' = 'The Supabase CLI does not support global npm installs; use npx supabase, scoop or a project dev dependency.' }

$programs = Invoke-BvsCheck -Run $run -Id 'H1.programs' -Description 'Installed programs (uninstall keys + AppX) with real size, last use and flags' -Script {
    $script:ua = @(Get-H1UserAssist)
    $script:procPaths = @($script:procTable | Where-Object { $_.Path } | ForEach-Object { $_.Path.ToLowerInvariant() })
    $raw = [System.Collections.Generic.List[object]]::new(); $seen = @{}
    $roots = @(@{ P = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; V = ''; S = 'HKLM' },
               @{ P = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; V = '32'; S = 'HKLM-WOW64' },
               @{ P = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall'; V = ''; S = 'HKCU' })
    foreach ($root in $roots) {
        $subs = if ($root.V) { Get-BvsRegSubKeys -Path $root.P -View $root.V } else { Get-BvsRegSubKeys -Path $root.P }
        foreach ($sk in @($subs)) {
            if (-not $sk) { continue }
            $m = Get-H1RegMap "$($root.P)\$sk" $root.V
            $dn = [string]$m['DisplayName']
            if (-not $dn -or "$($m['SystemComponent'])" -eq '1' -or $m['ParentKeyName'] -or "$($m['ReleaseType'])" -match 'Update|Hotfix') { continue }
            $k = "$dn|$($m['DisplayVersion'])".ToLowerInvariant(); if ($seen[$k]) { continue }; $seen[$k] = 1
            $loc = Expand-H1 $m['InstallLocation']; $inferred = $false
            $icon = Expand-H1 (([string]$m['DisplayIcon']) -replace ',\s*-?\d+$', '')
            if (-not $loc -and $icon -match '\.exe$' -and $icon -notmatch '\\(Installer|Package Cache)\\' -and -not $icon.StartsWith($env:windir, 'OrdinalIgnoreCase') -and (Test-Path -LiteralPath $icon)) {
                $loc = Split-Path $icon -Parent; $inferred = $true }
            $raw.Add([pscustomobject]@{ Kind = 'arp'; Name = $dn; Publisher = [string]$m['Publisher']; Version = [string]$m['DisplayVersion']
                InstallDate = [string]$m['InstallDate']; EstKB = $m['EstimatedSize']; Loc = $loc; Inferred = $inferred; Icon = $icon
                Uninstall = [string]$m['UninstallString']; Key = "$($root.S)\...\Uninstall\$sk"; Pfn = $null; Flags = @(); Notes = @(); Safety = $null })
        }
    }
    # AppX: non-framework, removable, non-system, not provisioned for all users (= user-installed).
    $prov = @{}
    foreach ($pf in @(Get-BvsRegSubKeys -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications')) {
        if ($pf -match '^([^_]+)_[^_]*_[^_]*_[^_]*_([^_]+)$') { $prov["$($Matches[1])_$($Matches[2])"] = 1 } }
    $pk = @(); try { $pk = @(Get-AppxPackage -ErrorAction Stop) } catch { $pk = @() }
    if (-not $pk.Count) {
        $pk = @(& powershell.exe -NoProfile -NonInteractive -Command 'Get-AppxPackage | Select-Object Name,PackageFullName,PackageFamilyName,Publisher,Version,InstallLocation,IsFramework,NonRemovable,IsResourcePackage,SignatureKind | ConvertTo-Json -Depth 2' | ConvertFrom-Json) }
    foreach ($a in $pk) {
        if ($a.IsFramework -or $a.IsResourcePackage -or $a.NonRemovable -or "$($a.SignatureKind)" -in 'System', '4' -or $prov[$a.PackageFamilyName]) { continue }
        $pub = if ("$($a.Publisher)" -match 'CN=([^,]+)') { $Matches[1] } else { [string]$a.Publisher }
        $raw.Add([pscustomobject]@{ Kind = 'appx'; Name = $a.Name; Publisher = $pub; Version = [string]$a.Version; InstallDate = ''; EstKB = $null
            Loc = Expand-H1 $a.InstallLocation; Inferred = $false; Icon = $null; Uninstall = "Remove-AppxPackage $($a.PackageFullName)"
            Key = "AppX\$($a.PackageFullName)"; Pfn = $a.PackageFamilyName; Flags = @(); Notes = @(); Safety = $null })
    }
    # Node.js: MSI install vs nvm-windows; inactive nvm versions; npm globals whose bin target is missing.
    $nvmLink = Get-H1Env 'NVM_SYMLINK'; $nvmHome = Get-H1Env 'NVM_HOME'; $nvmActive = $null
    if ($nvmLink -and (Test-Path -LiteralPath $nvmLink)) { $tg = @((Get-Item -LiteralPath $nvmLink -Force).Target)[0]; if ($tg) { $nvmActive = Split-Path $tg -Leaf } }
    $nodeAll = @(Get-Command node.exe -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object Source); $nodeFirst = $nodeAll | Select-Object -First 1
    foreach ($n in @($raw | Where-Object { $_.Kind -eq 'arp' -and $_.Name -match '^Node\.js' -and -not $_.Loc })) {
        $c = @($nodeAll + (Join-Path $env:ProgramFiles 'nodejs\node.exe')) | Where-Object { $_ -and -not ($nvmLink -and $_.StartsWith($nvmLink + '\', 'OrdinalIgnoreCase')) -and (Test-Path -LiteralPath $_) -and (Get-Item -LiteralPath $_).VersionInfo.ProductVersion -eq $n.Version } | Select-Object -First 1
        if ($c) { $n.Loc = Split-Path $c -Parent; $n.Inferred = $true }
    }
    # Server software installed from an archive (service only, no uninstall entry).
    $srvRe = 'Splunk|Elasticsearch|Kibana|Logstash|OpenSearch'
    foreach ($s in @($script:svcRaw | Where-Object { "$($_.Name) $($_.DisplayName)" -match $srvRe })) {
        $word = [regex]::Match("$($s.Name) $($s.DisplayName)", $srvRe).Value
        if (@($raw | Where-Object { $_.Name -match $word }).Count) { continue }
        $exe = if ("$($s.PathName)" -match '^\s*"?([^"]+?\.exe)') { $Matches[1] } else { $null }
        $hdir = if ($exe) { $d = Split-Path $exe -Parent; if ((Split-Path $d -Leaf) -eq 'bin') { Split-Path $d -Parent } else { $d } } else { $null }
        $raw.Add([pscustomobject]@{ Kind = 'service'; Name = "$($s.DisplayName) (service-only install)"; Publisher = ''; Version = ''; InstallDate = ''; EstKB = $null
            Loc = $hdir; Inferred = $true; Icon = $exe; Uninstall = "remove the '$($s.Name)' service with the product's own tool (admin), then delete $hdir"; Key = "Service\$($s.Name)"
            Pfn = $null; Flags = @(); Notes = @('Installed from an archive, so there is no Settings -> Apps entry.'); Safety = $null })
    }
    if ($nvmActive) {
        foreach ($n in @($raw | Where-Object { $_.Kind -eq 'arp' -and $_.Name -match '^Node\.js' -and $_.Loc -and $_.Loc -ne $nvmLink })) {
            $wins = $nodeFirst -and $nodeFirst.StartsWith($n.Loc + '\', 'OrdinalIgnoreCase')
            $n.Flags += $(if ($wins) { 'shadows_nvm' } else { 'shadowed_duplicate' }); $n.Safety = 'safe_after_check'
            $n.Notes += $(if ($wins) { "This Node.js $($n.Version) comes first on PATH, so nvm's active $nvmActive is ignored." } else { "Duplicate: nvm-windows $nvmActive is active and first on PATH; this Node.js $($n.Version) install is shadowed." })
        }
    }
    if ($nvmHome -and (Test-Path -LiteralPath $nvmHome)) {
        foreach ($d in @(Get-ChildItem -LiteralPath $nvmHome -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^v?\d+\.\d+\.\d+$' -and $_.Name -ne $nvmActive })) {
            $raw.Add([pscustomobject]@{ Kind = 'nvm'; Name = "Node.js $($d.Name) (nvm, not active)"; Publisher = 'nvm-windows'; Version = $d.Name.TrimStart('v'); InstallDate = $d.CreationTimeUtc.ToString('yyyyMMdd')
                EstKB = $null; Loc = $d.FullName; Inferred = $false; Icon = $null; Uninstall = "nvm uninstall $($d.Name.TrimStart('v'))"; Key = "nvm\$($d.Name)"; Pfn = $null
                Flags = @('unused_version'); Notes = @("nvm-windows keeps this version but $nvmActive is active."); Safety = 'safe_after_check' })
        }
    }
    $npmRoots = @((Join-Path $env:APPDATA 'npm\node_modules')); if ($nvmLink) { $npmRoots += (Join-Path $nvmLink 'node_modules') }
    foreach ($nr in ($npmRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $nr)) { continue }
        $pkgs = Get-ChildItem -LiteralPath $nr -Directory -ErrorAction SilentlyContinue | ForEach-Object { if ($_.Name -like '@*') { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } else { $_ } }
        foreach ($d in @($pkgs)) {
            if ($d.Name -in 'npm', 'corepack') { continue }
            $pname = if ($d.Parent.Name -like '@*') { "$($d.Parent.Name)/$($d.Name)" } else { $d.Name }
            $j = $null; try { $j = Get-Content -LiteralPath (Join-Path $d.FullName 'package.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null }
            $bins = @(); if ($j -and $j.bin -is [string]) { $bins = @($j.bin) } elseif ($j -and $j.bin) { $bins = @($j.bin.PSObject.Properties.Value) }
            $miss = @($bins | Where-Object { -not (Test-Path -LiteralPath (Join-Path $d.FullName $_)) -and -not (Test-Path -LiteralPath (Join-Path $d.FullName "$_.exe")) })
            if ($j -and -not $miss.Count) { continue }
            $why = if (-not $j) { 'package.json missing or unreadable' } else { "bin target missing: $($miss -join ', ')" }
            $raw.Add([pscustomobject]@{ Kind = 'npm'; Name = "npm global: $pname"; Publisher = 'npm'; Version = [string]$j.version; InstallDate = $d.LastWriteTimeUtc.ToString('yyyyMMdd')
                EstKB = $null; Loc = $d.FullName; Inferred = $false; Icon = $null; Uninstall = "npm uninstall -g $pname"; Key = "npm\$pname"; Pfn = $null
                Flags = @('broken'); Notes = @("Broken global package ($why); its command will fail.", $npmNotes[$pname]); Safety = 'safe_after_check' })
        }
    }
    $want = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $raw) { if ($p.Loc -and ($p.Loc -split '\\').Count -ge 3) { [void]$want.Add($p.Loc) } }
    $sizes = Get-H1DirSizes $want; $counted = @{}
    foreach ($p in $raw) {
        $sz = if ($p.Loc) { $sizes[$p.Loc] } else { $null }
        if ($sz -and $sz.Bytes -le 0) { $sz = $null }   # 0 bytes = folder unreadable without admin; fall back to EstimatedSize
        $estB = if ($p.EstKB) { [int64]$p.EstKB * 1024 } else { $null }
        $shared = $null; if ($sz) { if ($counted[$p.Loc]) { $shared = $counted[$p.Loc] } else { $counted[$p.Loc] = $p.Name } }
        $bytes = if ($sz -and -not $shared) { $sz.Bytes } elseif ($sz) { $null } elseif ($estB) { $estB } else { $null }
        $src = if ($shared) { "shared folder (size counted under '$shared')" } elseif ($sz) { $(if ($p.Inferred) { 'dirs.tsv (inferred folder)' } else { 'dirs.tsv (InstallLocation)' }) } elseif ($estB) { 'EstimatedSize (registry)' } else { 'unknown' }
        $svcs = if ($p.Loc) { @($script:svcRaw | Where-Object { "$($_.PathName)".IndexOf($p.Loc + '\', [StringComparison]::OrdinalIgnoreCase) -ge 0 }) } else { @() }
        $svcRun = @($svcs | Where-Object { $_.State -eq 'Running' }).Count
        $use = Find-H1Usage $p.Loc $p.Icon ($p.Name.ToLowerInvariant() -replace '[^a-z0-9]', '') $p.Pfn
        $flags = [System.Collections.Generic.List[string]]::new(); foreach ($f in $p.Flags) { $flags.Add($f) }
        $notes = [System.Collections.Generic.List[string]]::new(); foreach ($n in $p.Notes) { if ($n) { $notes.Add($n) } }
        $safety = if ($p.Safety) { $p.Safety } else { 'review' }
        foreach ($r in $rules) { if ($p.Name -match $r.Re) { foreach ($f in $r.Flags) { $flags.Add($f) }; $safety = $r.Safety; $notes.Add($r.Note) } }
        if (-not $flags.Count -and $p.Name -match $dnt) { $safety = 'do_not_touch'; $notes.Add('Runtime, driver or platform component that other software depends on.') }
        if ($use.Last -and $use.Last -lt $nowUtc.AddDays(-180)) { $flags.Add('not_used_180d') }
        if ($p.Name -match $srvRe -and -not $flags.Contains('server_software')) { $flags.Add('server_software'); $safety = 'review'; $notes.Add('Server software with background services; uninstall if you no longer use it.') }
        if ($flags.Contains('server_software') -and -not $use.Last -and -not $svcRun) { $flags.Add('no_recent_use_evidence') }
        if ($svcs.Count) { $notes.Add('Services: ' + (($svcs | ForEach-Object { "$($_.Name) ($($_.State), $($_.StartMode))" }) -join ', ') + '.') }
        $method = if ($p.Kind -in 'nvm', 'npm', 'service') { 'tool' } else { 'uninstall' }
        $how = switch ($p.Kind) {
            'service' { "No Settings entry: back up its data, then $($p.Uninstall)." }
            'appx' { "Settings -> Apps -> Installed apps -> '$($p.Name)' -> Uninstall (PowerShell equivalent: $($p.Uninstall))" }
            'nvm'  { "Check no project pins this version (.nvmrc / engines), then run: $($p.Uninstall)" }
            'npm'  { "Run: $($p.Uninstall); reinstall only if you still need the command." }
            default { "Settings -> Apps -> Installed apps -> '$($p.Name)' -> ... -> Uninstall (vendor uninstaller: $($p.Uninstall))" }
        }
        $purpose = "$($p.Name) $($p.Version) by $(if ($p.Publisher) { $p.Publisher } else { 'unknown publisher' })" + $(if ($notes.Count) { '. ' + ($notes -join ' ') } else { '' })
        New-H1Item -Prefix 'h1p' -Path $(if ($p.Loc) { $p.Loc } else { $p.Key }) -Kind 'program' -Bytes $bytes -Category $(if ($p.Kind -in 'nvm', 'npm') { 'dev-runtime' } else { 'program' }) `
            -Purpose $purpose -Owner $p.Publisher -Safety $safety -Method $method -How $how -Reversible $false -Flags @($flags) -Extra ([ordered]@{
                name = $p.Name; publisher = $p.Publisher; version = $p.Version; installDate = $p.InstallDate; estimatedSize = $estB
                folderBytes = $(if ($sz) { $sz.Bytes } else { $null }); sizeSource = $src; lastUsed = $(if ($use.Last) { $use.Last.ToString('o') } else { 'unknown' })
                lastUsedSource = $use.Source; runCount = $use.Count; uninstallCommand = $p.Uninstall; source = $p.Kind; registryKey = $p.Key })
    }
}
$programs = @($programs | Where-Object { $_ } | Sort-Object { [int64]$_.bytes } -Descending)
Add-BvsInventory -Run $run -Name 'programs' -Data $programs

$hogs = Invoke-BvsCheck -Run $run -Id 'H1.resourceHogs' -Description 'Top 15 CPU and RAM processes (two perf samples 10 s apart) with signer' -Script {
    $ncpu = [Environment]::ProcessorCount
    $s1 = @{}; foreach ($x in (Get-H1PerfSample)) { $s1[[int]$x.IDProcess] = $x }
    Start-Sleep -Seconds 10
    $tbl = @{}; foreach ($x in $script:procTable) { $tbl[[int]$x.Pid] = $x }
    $rows = foreach ($x in (Get-H1PerfSample)) {
        $id = [int]$x.IDProcess; $first = if ($s1[$id]) { [math]::Round($s1[$id].PercentProcessorTime / $ncpu, 1) } else { $null }
        [pscustomobject]@{ Pid = $id; Name = $(if ($tbl[$id]) { $tbl[$id].Name } else { $x.Name -replace '#\d+$', '' }); Cpu = [math]::Round($x.PercentProcessorTime / $ncpu, 1)
            Cpu1 = $first; Ram = [int64]$x.WorkingSetPrivate; Path = $(if ($tbl[$id]) { $tbl[$id].Path } else { $null }) }
    }
    foreach ($r in $rows) { $script:perf[$r.Pid] = $r }
    $topCpu = @($rows | Sort-Object Cpu -Descending | Select-Object -First 15); $topRam = @($rows | Sort-Object Ram -Descending | Select-Object -First 15)
    foreach ($r in @($topCpu + $topRam | Sort-Object Pid -Unique)) {
        $sig = Get-H1Signer $r.Path; $rc = [array]::IndexOf($topCpu, $r); $rr = [array]::IndexOf($topRam, $r)
        $fl = @($(if ($rc -ge 0) { 'top_cpu' }), $(if ($rr -ge 0) { 'top_ram' }))
        New-H1Item -Prefix 'h1h' -Path $r.Path -Kind 'process' -Bytes 0 -Category 'resource-hog' -Owner $sig.Signer `
            -Purpose ("{0} (PID {1}): {2}% CPU over the 10-s window, {3:N0} MB private RAM" -f $r.Name, $r.Pid, $r.Cpu, ($r.Ram / 1MB)) `
            -Safety $(if ($sig.IsOSBinary) { 'do_not_touch' } else { 'review' }) -Method 'none' -Flags $fl `
            -How 'Informational. Close the app if you do not need it; if it starts with Windows see startupItems; a vendor tool that stays busy -> update or uninstall it.' `
            -Extra ([ordered]@{ pid = $r.Pid; name = $r.Name; cpuPct = $r.Cpu; cpuPctFirstSample = $r.Cpu1; ramBytes = $r.Ram; signer = $sig.Signer; sigStatus = $sig.Status
                rankCpu = $(if ($rc -ge 0) { $rc + 1 } else { $null }); rankRam = $(if ($rr -ge 0) { $rr + 1 } else { $null }) })
    }
}
Add-BvsInventory -Run $run -Name 'resourceHogs' -Data @($hogs | Where-Object { $_ })

$startup = Invoke-BvsCheck -Run $run -Id 'H1.startupItems' -Description 'Enabled startup entries (reused from S01) with current resource use' -Script {
    $s01f = Join-Path $scanDir 'security\S01.json'
    if (-not (Test-Path -LiteralPath $s01f)) { Set-BvsCheckStatus -Id 'H1.startupItems' -Status skipped -Reason 'S01.json not found; run S01 first'; return }
    $auto = @((Get-Content -LiteralPath $s01f -Raw | ConvertFrom-Json).inventory.autostarts)
    $svc = @{}; foreach ($s in $script:svcRaw) { $svc[$s.Name] = $s }
    $script:startupSkipped = @{}
    foreach ($e in $auto) {
        if (-not $e.enabled) { continue }
        $svcName = $null; $keep = $false
        switch ($e.category) {
            { $_ -in 'run_key', 'startup_folder' } { $keep = $true }
            'scheduled_task' { $keep = -not $e.microsoft }
            'service' { $svcName = Split-Path $e.location -Leaf; $s = $svc[$svcName]; $keep = (-not $e.microsoft) -and $s -and ($s.StartMode -eq 'Auto' -or $s.State -eq 'Running') }
        }
        if (-not $keep) { $script:startupSkipped[[string]$e.category]++; continue }
        $pids = if ($svcName -and $svc[$svcName].ProcessId) { @([int]$svc[$svcName].ProcessId) } elseif ($e.target) { @($script:procTable | Where-Object { $_.Path -and $_.Path -eq $e.target } | ForEach-Object { [int]$_.Pid }) } else { @() }
        $cpu = 0.0; $ram = [int64]0; foreach ($id in $pids) { $pr = $script:perf[$id]; if ($pr) { $cpu += $pr.Cpu; $ram += $pr.Ram } }
        $running = $pids.Count -gt 0
        $impact = if ($running) { "running now: {0:N1}% CPU, {1:N0} MB RAM; boot impact unknown (needs admin StartupInfo)" -f $cpu, ($ram / 1MB) } else { 'unknown (needs admin StartupInfo)' }
        $how = switch ($e.category) {
            'scheduled_task' { "Task Scheduler -> Task Scheduler Library -> '$($e.name)' -> right-click -> Disable" }
            'service' { "Task Manager -> Services -> Open Services -> '$($svc[$svcName].DisplayName)' -> Startup type: Manual (only if you do not need it)" }
            default { "Task Manager -> Startup apps -> '$($e.name)' -> Disable (or Settings -> Apps -> Startup)" }
        }
        $protect = "$($e.name) $($e.target)" -match 'SecurityHealth|Windows Defender' -or ($e.category -eq 'service' -and "$($e.signer)" -match 'Avast|AVG|ESET|Kaspersky|Bitdefender|Malwarebytes|Norton|Sophos')
        New-H1Item -Prefix 'h1s' -Path $e.target -Kind 'setting' -Bytes 0 -Category 'startup' -Owner $e.signer `
            -Purpose "$($e.category): $($e.name) starts automatically ($($e.scope); runs as $($e.runAs)). Impact: $impact" `
            -Safety $(if ($protect) { 'do_not_touch' } else { 'review' }) -Method 'setting' -How $how -Flags @($(if ($running) { 'running' }), $(if (-not $e.signer) { 'unsigned' })) `
            -Extra ([ordered]@{ name = $e.name; startupType = $e.category; command = $e.command; location = $e.location; signer = $e.signer; running = $running
                pids = $pids; cpuPct = $(if ($running) { [math]::Round($cpu, 1) } else { $null }); ramBytes = $(if ($running) { $ram } else { $null }); impact = $impact
                serviceStartMode = $(if ($svcName) { "$($svc[$svcName].StartMode)$(if ($svc[$svcName].DelayedAutoStart) { ' (delayed)' })" } else { $null }); s01Id = $e.id })
    }
}
Add-BvsInventory -Run $run -Name 'startupItems' -Data @($startup | Where-Object { $_ })

$null = Invoke-BvsCheck -Run $run -Id 'H1.startupImpact' -Description 'Measured boot impact per startup app (StartupInfo)' -Script {
    Set-BvsCheckStatus -Id 'H1.startupImpact' -Status needs_admin -Reason 'StartupInfo (System32\WDI\LogFiles\StartupInfo) is admin-only; pending the admin run' }
$null = Invoke-BvsCheck -Run $run -Id 'H1.lastUsedAdmin' -Description 'Last-run evidence beyond UserAssist (BAM, Prefetch)' -Script {
    Set-BvsCheckStatus -Id 'H1.lastUsedAdmin' -Status needs_admin -Reason 'BAM (HKLM\...\bam\State) and C:\Windows\Prefetch need elevation; pending the admin run' }

$crashes = Invoke-BvsCheck -Run $run -Id 'H1.crashes' -Description 'Application crashes (1000) and hangs (1002) per app, 90 days' -Script {
    $xp = "*[System[((Provider[@Name='Application Error'] and EventID=1000) or (Provider[@Name='Application Hang'] and EventID=1002)) and TimeCreated[timediff(@SystemTime) <= 7776000000]]]"
    $g = @{}
    foreach ($e in @(Get-WinEvent -LogName Application -FilterXPath $xp -ErrorAction SilentlyContinue)) {
        $p = $e.Properties; if ($p.Count -lt 4) { continue }
        $app = [string]$p[0].Value; if (-not $app) { continue }
        $t = $e.TimeCreated.ToUniversalTime()
        if ($t -ge $run.AuditStartUtc -and $app -match '^(pwsh|powershell)\.exe$') { continue }
        $hang = $e.Id -eq 1002
        $path = if ($hang -and $p.Count -gt 5) { [string]$p[5].Value } elseif (-not $hang -and $p.Count -gt 10) { [string]$p[10].Value } else { $null }
        $k = $app.ToLowerInvariant()
        if (-not $g[$k]) { $g[$k] = [pscustomobject]@{ App = $app; Path = $path; Crashes = 0; Hangs = 0; Latest = $t; First = $t; Versions = @{}; Modules = @{}; Codes = @{} } }
        $x = $g[$k]; if (-not $x.Path -and $path) { $x.Path = $path }
        if ($hang) { $x.Hangs++ } else { $x.Crashes++; $x.Modules[[string]$p[3].Value]++; if ($p.Count -gt 6) { $x.Codes[[string]$p[6].Value]++ } }
        $x.Versions[[string]$p[1].Value] = 1
        if ($t -gt $x.Latest) { $x.Latest = $t }; if ($t -lt $x.First) { $x.First = $t }
    }
    foreach ($x in @($g.Values | Sort-Object { $_.Crashes + $_.Hangs } -Descending)) {
        $mods = @($x.Modules.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Key) x$($_.Value)" })
        $top = if ($mods.Count) { ($mods[0] -split ' x')[0] } else { '' }
        $how = if ($x.Crashes -eq 0) { "It stops responding: update $($x.App); check its add-ins and whether antivirus scanning or a slow disk blocks it." }
            elseif ($x.App -ieq 'explorer.exe' -and $top -and $top -notmatch '^(ntdll|KERNELBASE|ucrtbase|msvcrt|shell32|windows\.storage|explorerframe)') { "A third-party DLL ($top) crashes Explorer: update or uninstall the program that installed it (usually a shell extension)." }
            elseif ($top -match '^(ntdll|KERNELBASE|ucrtbase|msvcrt|clr|coreclr)\.dll$') { "Generic runtime frame ($top): update $($x.App); if it continues, reinstall it and disable its plugins. Reliability Monitor (perfmon /rel) shows each crash." }
            else { "Update $($x.App); if it keeps crashing in $top, reinstall it. Reliability Monitor (perfmon /rel) shows each crash." }
        New-H1Item -Prefix 'h1c' -Path $x.Path -Kind 'program' -Bytes 0 -Category 'crash' -Owner (Get-H1Signer $x.Path).Signer -Safety 'review' -Method 'none' -How $how `
            -Purpose ("{0} crashed {1}x and hung {2}x in 90 days (latest {3:yyyy-MM-dd}){4}" -f $x.App, $x.Crashes, $x.Hangs, $x.Latest, $(if ($top) { "; top faulting module: $top" } else { '' })) `
            -Flags @($(if (($x.Crashes + $x.Hangs) -ge 10) { 'hot_spot' })) -Extra ([ordered]@{ app = $x.App; crashes = $x.Crashes; hangs = $x.Hangs; total = $x.Crashes + $x.Hangs
                latestUtc = $x.Latest.ToString('o'); firstUtc = $x.First.ToString('o'); versions = @($x.Versions.Keys); topModules = $mods
                exceptionCodes = @($x.Codes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Key) x$($_.Value)" }) })
    }
}
Add-BvsInventory -Run $run -Name 'crashes' -Data @($crashes | Where-Object { $_ })

$battery = Invoke-BvsCheck -Run $run -Id 'H1.battery' -Description 'Battery wear: design vs full-charge capacity (powercfg /batteryreport)' -Script {
    $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    if (-not $bat.Count) { Set-BvsCheckStatus -Id 'H1.battery' -Status not_applicable -Reason 'No battery present'; return }
    $out = Join-Path $run.OutDir 'H1-battery-report.html'
    $null = & powercfg.exe /batteryreport /output $out 2>&1
    if (-not (Test-Path -LiteralPath $out)) { Set-BvsCheckStatus -Id 'H1.battery' -Status partial -Reason 'powercfg produced no report'; return }
    $html = Get-Content -LiteralPath $out -Raw
    $rows = @([regex]::Matches($html, '<span class="label">\s*(.*?)\s*</span>\s*</td>\s*<td[^>]*>\s*(.*?)\s*</td>', 'Singleline') | ForEach-Object { [pscustomobject]@{ L = $_.Groups[1].Value; V = $_.Groups[2].Value } })
    $i = -1; for ($n = 0; $n -lt $rows.Count; $n++) { if ($rows[$n].V -match '\d\s*mWh') { $i = $n; break } }
    if ($i -ge 0 -and $i + 1 -lt $rows.Count) { $design = ConvertTo-H1Number $rows[$i].V; $full = ConvertTo-H1Number $rows[$i + 1].V; $cyc = if ($i + 2 -lt $rows.Count -and $rows[$i + 2].V -match '^\s*\d+\s*$') { [int]$rows[$i + 2].V } else { $null } }
    else { $mw = @([regex]::Matches($html, '>\s*([0-9][0-9\s\.,\u00a0\u202f]*)\s*mWh') | ForEach-Object { ConvertTo-H1Number $_.Groups[1].Value }); $design = $mw[0]; $full = $mw[1]; $cyc = $null }
    if (-not $design -or -not $full) { Set-BvsCheckStatus -Id 'H1.battery' -Status partial -Reason 'Could not parse capacities from the report'; return }
    $pct = [math]::Round(100.0 * $full / $design, 1)
    New-H1Item -Prefix 'h1b' -Path $out -Kind 'setting' -Bytes 0 -Category 'battery' -Owner 'Windows powercfg' -Safety 'safe' -Method 'none' `
        -Purpose ("Battery holds {0}% of its design capacity: full charge {1:N0} mWh vs design {2:N0} mWh{3}" -f $pct, $full, $design, $(if ($null -ne $cyc) { "; $cyc charge cycles" } else { '' })) `
        -How "Informational. Below ~80% runtime is noticeably shorter; consider a replacement through the vendor. If the laptop is mostly plugged in, enable the vendor's charge limit (e.g. 80%) to slow wear. Full report: $out" `
        -Flags @($(if ($pct -lt 80) { 'degraded' }), $(if ($pct -lt 60) { 'replace_soon' })) `
        -Extra ([ordered]@{ designMWh = $design; fullChargeMWh = $full; healthPct = $pct; cycleCount = $cyc; batteries = $bat.Count; chargePct = $bat[0].EstimatedChargeRemaining; reportPath = $out })
}
Add-BvsInventory -Run $run -Name 'battery' -Data @($battery | Where-Object { $_ })

$power = Invoke-BvsCheck -Run $run -Id 'H1.powerPlan' -Description 'Active power plan (powercfg /getactivescheme) and power-mode overlay' -Script {
    $txt = (& powercfg.exe /getactivescheme 2>&1) -join ' '
    $guid = [regex]::Match($txt, '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}').Value.ToLowerInvariant()
    $name = [regex]::Match($txt, '\(([^)]+)\)\s*$').Groups[1].Value
    $known = @{ '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'; '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'; 'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'; 'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Ultimate Performance' }
    $ovl = @{ '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'; '00000000-0000-0000-0000-000000000000' = 'Balanced'; '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Better performance'; 'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance' }
    $m = Get-H1RegMap 'HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
    $ac = $ovl["$($m['ActiveOverlayAcPowerScheme'])".ToLowerInvariant()]; $dc = $ovl["$($m['ActiveOverlayDcPowerScheme'])".ToLowerInvariant()]
    $plan = if ($known[$guid]) { $known[$guid] } else { 'custom/OEM plan' }
    New-H1Item -Prefix 'h1w' -Path 'powercfg /getactivescheme' -Kind 'setting' -Bytes 0 -Category 'power-plan' -Owner 'Windows' -Safety 'safe' -Method 'setting' `
        -Purpose "Active power plan: $name ($plan, $guid). Power mode plugged in: $(if ($ac) { $ac } else { 'n/a' }); on battery: $(if ($dc) { $dc } else { 'n/a' })." `
        -How "Settings -> System -> Power & battery -> Power mode. Balanced suits most use; Best performance trades battery and heat for speed." `
        -Flags @($(if ($plan -in 'High performance', 'Ultimate Performance' -or $dc -eq 'Best performance') { 'battery_drain' }), $(if ($plan -eq 'Power saver' -or $ac -eq 'Best power efficiency') { 'may_slow_pc' })) `
        -Extra ([ordered]@{ schemeGuid = $guid; schemeName = $name; knownPlan = $plan; overlayAc = $ac; overlayDc = $dc })
}
Add-BvsInventory -Run $run -Name 'powerPlan' -Data @($power | Where-Object { $_ })

$st = @($startup | Where-Object { $_ }); $cr = @($crashes | Where-Object { $_ })
$sized = @($programs | Where-Object { $_.folderBytes -and $_.bytes })
foreach ($x in $sized) { if (@($sized | Where-Object { $_ -ne $x -and $x.path.StartsWith($_.path + '\', 'OrdinalIgnoreCase') }).Count) { $x.flags = @($x.flags + 'nested_folder') } }
$summary = [ordered]@{
    programs = $programs.Count; programBytes = [int64](($programs | Where-Object { $_.flags -notcontains 'nested_folder' } | Measure-Object -Property bytes -Sum).Sum)
    unusedNvmVersions = @($programs | Where-Object { $_.flags -contains 'unused_version' }).Count
    likelyUnused = @($programs | Where-Object { $_.flags -contains 'not_used_180d' -or $_.flags -contains 'no_recent_use_evidence' } | ForEach-Object { "$($_.name) (last: $($_.lastUsed))" })
    biggest = @($programs | Select-Object -First 10 | ForEach-Object { '{0} ({1:N1} GB)' -f $_.name, ($_.bytes / 1GB) })
    flagged = @($programs | Where-Object { $_.flags.Count } | ForEach-Object { "$($_.name) [$($_.flags -join ',')]" })
    lastUsedKnown = @($programs | Where-Object { $_.lastUsed -ne 'unknown' }).Count
    startupItems = $st.Count; startupRunning = @($st | Where-Object running).Count
    startupRamMB = [math]::Round((($st | Where-Object running | Measure-Object -Property ramBytes -Sum).Sum) / 1MB)
    startupSkippedByCategory = $script:startupSkipped
    crashHotSpots = @($cr | Select-Object -First 5 | ForEach-Object { "$($_.app): $($_.crashes) crashes, $($_.hangs) hangs" })
    battery = @($battery | Where-Object { $_ } | ForEach-Object { "$($_.healthPct)% of design" })
    powerPlan = @($power | Where-Object { $_ } | ForEach-Object { $_.knownPlan })
    pendingAdmin = @('StartupInfo boot impact', 'BAM / Prefetch last-run')
}
Add-BvsInventory -Run $run -Name 'summary' -Data $summary
$res = Complete-BvsRun -Run $run
Protect-BvsText (($summary | ConvertTo-Json -Depth 3 -Compress))
Protect-BvsText ("H1 done: " + ($res | ConvertTo-Json -Depth 2 -Compress))
