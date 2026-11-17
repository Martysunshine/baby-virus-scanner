#Requires -Version 7.2
<#
.SYNOPSIS
    S10 Code editors & git (read-only): VS Code / Cursor / VS Code-fork extensions, editor settings traps,
    repository auto-run vectors, git config traps, hooks and worktrees, JetBrains / Visual Studio presence.
.DESCRIPTION
    Never runs editor CLIs or git; repo config is read from .git\config directly. Network only through
    Invoke-BvsIntel (extension IDs leave the machine, nothing else). Detection data: S10-editor-iocs.json.
    Output: data\<scanId>\security\S10.json. Playbook: docs\playbooks\S10-editors-git.md
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S10-editors-git.ps1 [-NoIntel]
#>
[CmdletBinding()]
param([ValidateRange(1, 8)][int]$RepoDepth = 5, [ValidateRange(1, 512)][int]$MaxJsMB = 30, [switch]$NoIntel)

Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$ErrorActionPreference = 'Stop'
$run = Initialize-BvsRun -Module S10 -Area security
$IOC = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S10-editor-iocs.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 32
$U = $env:USERPROFILE
$RootFull = $run.Root.TrimEnd('\')
$RxOpt = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
$Mitre = @{ ext = 'T1176.002'; exec = 'T1204.002'; obf = 'T1027'; dead = 'T1102.001'; hook = 'T1546'; mitm = 'T1557' }

#region helpers
function New-Rx([string]$P) { [regex]::new($P, $RxOpt, [TimeSpan]::FromSeconds(2)) }
function Test-Under([string]$Path, [string]$Root) { [bool]$Root -and ($Path.TrimEnd('\') + '\').StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }
function Read-Text([string]$Path, [long]$Max = 4MB) {
    try {
        if (Test-BvsNeverRead $Path) { return $null }
        $fi = [IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or $fi.Length -gt $Max -or (Test-BvsCloudOnly $fi)) { return $null }
        $fs = [IO.FileStream]::new($fi.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { ([IO.StreamReader]::new($fs, [Text.UTF8Encoding]::new($false), $true)).ReadToEnd() } finally { $fs.Dispose() }
    }
    catch { $null }
}
function Read-Json([string]$Path, [long]$Max = 4MB) {
    $t = Read-Text $Path $Max
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    try { , ($t.TrimStart([char]0xFEFF) | ConvertFrom-Json -AsHashtable -Depth 100 -NoEnumerate) } catch { $null }
}
function V($O, [string]$K) {
    if ($O -isnot [System.Collections.IDictionary]) { return $null }
    if ($O.Contains($K)) { return , $O[$K] }
    foreach ($x in @($O.Keys)) { if ("$x" -ieq $K) { return , $O[$x] } }
    $null
}
function Get-Items($X) { if ($null -eq $X) { return }; if ($X -is [string] -or $X -is [System.Collections.IDictionary]) { return , $X }; foreach ($i in $X) { $i } }
function Short($Val, [int]$N = 300) {
    if ($null -eq $Val) { return $null }
    $s = if ($Val -is [string]) { $Val } else { ConvertTo-Json -InputObject $Val -Compress -Depth 8 -WarningAction SilentlyContinue }
    if ($s.Length -gt $N) { $s = $s.Substring(0, $N) + '...' }
    Protect-BvsText $s
}
function Get-Sev([string]$S, [bool]$Cap) { if ($Cap) { 'info' } else { $S } }
$RiskRx = [ordered]@{}; foreach ($k in $IOC.commandPatterns.Keys) { $RiskRx[$k] = New-Rx $IOC.commandPatterns[$k] }
function Get-Risk([AllowNull()][string]$Text) {
    $t = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($Text)) { foreach ($k in $RiskRx.Keys) { try { if ($RiskRx[$k].IsMatch($Text)) { $t.Add($k) } } catch { $t.Add('regex_timeout') } } }
    $lvl = 'none'
    if ($t.Contains('pipe_shell') -or $t.Contains('reverse_shell') -or $t.Contains('encoded') -or $t.Contains('disguised_script') -or
        ($t.Contains('download') -and ($t.Contains('inline_exec') -or $t.Contains('eval') -or $t.Contains('paas_host') -or $t.Contains('ip_url')))) { $lvl = 'high' }
    elseif ($t.Contains('download') -or $t.Contains('paas_host') -or $t.Contains('evasion') -or $t.Contains('ip_url') -or ($t.Contains('inline_exec') -and $t.Contains('remote_url'))) { $lvl = 'medium' }
    elseif ($t.Contains('inline_exec') -or $t.Contains('eval') -or $t.Contains('remote_url') -or $t.Contains('base64_word')) { $lvl = 'low' }
    [pscustomobject]@{ Level = $lvl; Traits = @($t) }
}
function Add-F([hashtable]$P) { New-BvsFinding -Run $run @P }
$Pend = [ordered]@{}
function Add-Cand([string]$Key, [hashtable]$P, [string]$Path, $Ev) {
    if (-not $Pend.Contains($Key)) { $Pend[$Key] = @{ P = $P; Paths = [System.Collections.Generic.List[string]]::new(); Ev = [System.Collections.Generic.List[object]]::new() } }
    $c = $Pend[$Key]
    if (-not $c.Paths.Contains($Path)) { $c.Paths.Add($Path); if ($c.Ev.Count -lt 25) { $c.Ev.Add($Ev) } }
}
function Publish-Cands {
    foreach ($c in @($Pend.Values)) {
        $p = $c.P.Clone(); $p.Evidence = @($c.Ev)
        if ($c.Paths.Count -gt 1) { $p.Title = "$($p.Title) ($($c.Paths.Count) locations)" }
        New-BvsFinding -Run $run @p
    }
    $Pend.Clear()
}
$IntelLog = [System.Collections.Generic.List[object]]::new()
function Get-Intel([string]$Uri, [string]$Name, [string]$Method = 'GET', $Body = $null, [hashtable]$Headers = $null) {
    if ($NoIntel) { $IntelLog.Add([ordered]@{ name = $Name; url = $Uri; status = 'skipped' }); return $null }
    $err = $null
    for ($i = 1; $i -le 3; $i++) {
        try { $r = Invoke-BvsIntel -Uri $Uri -Method $Method -Body $Body -Headers $Headers -SaveName $Name; $IntelLog.Add([ordered]@{ name = $Name; url = $Uri; status = $r.Status }); return $r }
        catch { $err = $_.Exception.Message; Start-Sleep -Seconds (2 * $i) }
    }
    $IntelLog.Add([ordered]@{ name = $Name; url = $Uri; status = 'failed'; error = (Protect-BvsText $err) }); $null
}
function Get-IntelJson($R) { if (-not $R -or $null -eq $R.Content) { return $null }; try { , ("$($R.Content)" | ConvertFrom-Json -AsHashtable -Depth 64 -NoEnumerate) } catch { $null } }
function Protect-S10Url([string]$Url) {
    Protect-BvsUrl (($Url -replace '(?<=://)([^/@:\s]+):[^/@\s]+@', '$1:[REDACTED]@') -replace '(?<=://)(?:gh[pousr]_|github_pat_|glpat-)[^@/\s]+@', '[REDACTED]@')
}
function Get-RemoteInfo([string]$Url) {
    $u = "$Url".Trim(); $h = $null; $p = $null; $sch = 'local'
    if ($u -match '^(ext|fd)::') { $sch = $Matches[1] }
    elseif ($u -match '^[a-z][a-z0-9+.-]*://') { try { $x = [uri]$u; $h = $x.Host.ToLowerInvariant(); $p = $x.AbsolutePath; $sch = $x.Scheme } catch { } }
    elseif ($u -match '^(?:[^@/\s]+@)?([^:/\s]{2,}):(?!//)(.+)$') { $h = $Matches[1].ToLowerInvariant(); $p = $Matches[2]; $sch = 'ssh' }
    $key = if ($h) { "$h/" + (("$p").Trim('/') -replace '\.git$', '').ToLowerInvariant() } else { $u.ToLowerInvariant() }
    [pscustomobject]@{ Host = $h; Scheme = $sch; Key = $key
        Owner = $(if ($h -eq 'github.com' -and $p) { (("$p").Trim('/') -split '/')[0] } else { $null })
        Creds = ($u -match '://[^/@\s]+:[^/@\s]+@' -or $u -match '://(?:gh[pousr]_|github_pat_|glpat-)[^@/\s]+@') }
}
function Test-TrustedHost([string]$H) { ($H -in $IOC.git.trustedHosts) -or (@($IOC.git.trustedHostSuffixes | Where-Object { $H.EndsWith($_) }).Count -gt 0) }
function Convert-GitValue([string]$R) {
    $sb = [Text.StringBuilder]::new(); $q = $false
    for ($i = 0; $i -lt $R.Length; $i++) {
        $c = $R[$i]
        if ($c -eq [char]'\' -and $i + 1 -lt $R.Length) { $i++; $n = [string]$R[$i]; [void]$sb.Append($(switch -CaseSensitive ($n) { 'n' { "`n" } 't' { "`t" } default { $n } })); continue }
        if ($c -eq [char]'"') { $q = -not $q; continue }
        if (-not $q -and ($c -eq [char]'#' -or $c -eq [char]';')) { break }
        [void]$sb.Append($c)
    }
    $sb.ToString().Trim()
}
function Read-GitConfig([string]$Path, [string]$Scope, [int]$Depth = 0) {
    $out = [System.Collections.Generic.List[object]]::new()
    $t = Read-Text $Path 2MB
    if ($null -eq $t -or $Depth -gt 4) { return , $out }
    $sec = $null; $sub = $null; $ln = 0
    foreach ($line in ($t -split "`r?`n")) {
        $ln++; $s = $line.Trim()
        if (-not $s -or $s[0] -in [char]'#', [char]';') { continue }
        if ($s -match '^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\](.*)$') {
            $g1 = $Matches[1]; $g2 = $Matches[2]; $s = $Matches[3].Trim()
            $sub = $null; $sec = $g1.ToLowerInvariant()
            if ($null -ne $g2) { $sub = $g2 -replace '\\(.)', '$1' } elseif ($sec.Contains('.')) { $sub = $sec.Substring($sec.IndexOf('.') + 1); $sec = $sec.Substring(0, $sec.IndexOf('.')) }
            if (-not $s -or $s[0] -in [char]'#', [char]';') { continue }
        }
        if (-not $sec -or $s -notmatch '^([A-Za-z][\w-]*)\s*(?:=\s*(.*))?$') { continue }
        $key = $Matches[1].ToLowerInvariant(); $raw = $Matches[2]
        $val = if ($null -eq $raw) { 'true' } else { Convert-GitValue $raw }
        $name = if ($null -ne $sub) { "$sec.$sub.$key" } else { "$sec.$key" }
        $out.Add([pscustomobject]@{ Scope = $Scope; File = $Path; Line = $ln; Sec = $sec; Sub = $sub; Key = $key; Name = $name; Value = $val })
        if ($key -eq 'path' -and $sec -in 'include', 'includeif') {
            $ip = $val -replace '^~(?=[/\\])', $U
            if ($ip -and -not [IO.Path]::IsPathRooted($ip)) { $ip = Join-Path (Split-Path -Parent $Path) $ip }
            if ($ip -and [IO.File]::Exists($ip)) { foreach ($e in (Read-GitConfig $ip $Scope ($Depth + 1))) { $out.Add($e) } }
        }
    }
    , $out
}
function Resolve-Git($G) {
    if ($G -is [IO.DirectoryInfo]) { return [pscustomobject]@{ Work = $G.Parent.FullName; GitDir = $G.FullName; Common = $G.FullName; Kind = 'main' } }
    $t = Read-Text $G.FullName 8KB
    if ($t -notmatch '(?m)^\s*gitdir:\s*(.+?)\s*$') { return $null }
    $gd = $Matches[1] -replace '^/([a-zA-Z])/', '$1:/'
    if (-not [IO.Path]::IsPathRooted($gd)) { $gd = Join-Path $G.DirectoryName $gd }
    $gd = [IO.Path]::GetFullPath($gd); $cm = $gd; $cf = Join-Path $gd 'commondir'
    if ([IO.File]::Exists($cf)) { $c = "$(Read-Text $cf 4KB)".Trim(); if ($c) { if (-not [IO.Path]::IsPathRooted($c)) { $c = Join-Path $gd $c }; $cm = [IO.Path]::GetFullPath($c) } }
    [pscustomobject]@{ Work = $G.DirectoryName; GitDir = $gd; Common = $cm.TrimEnd('\'); Kind = $(if ($cm.TrimEnd('\') -ne $gd.TrimEnd('\')) { 'worktree' } elseif ($gd -match '\\modules\\') { 'submodule' } else { 'gitdir-link' }) }
}
#endregion

#region expected items
$ExpExt = @{}
foreach ($e in @(Get-BvsExpected -Category editorExtension) + @(Get-BvsExpected -Category program)) {
    foreach ($id in @($e.match.ids) + @($e.match.extensionIds)) { if ($id) { $ExpExt[$id.ToLowerInvariant()] = $e } }
}
#endregion

#region editors and extensions
$Editors = [System.Collections.Generic.List[object]]::new()
$null = Invoke-BvsCheck -Run $run -Id 'editors.discovery' -Description 'VS Code-family editors: uninstall registry, data folders, product.json (versioned layout), built-in trust/automatic-task defaults' -Script {
    $unins = foreach ($root in 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
        foreach ($view in '64', '32') { foreach ($sk in @(Get-BvsRegSubKeys -Path $root -View $view)) {
                $v = @(Get-BvsRegValues -Path "$root\$sk" -View $view)
                [pscustomobject]@{ Name = ($v | Where-Object Name -eq 'DisplayName').Value; Ver = ($v | Where-Object Name -eq 'DisplayVersion').Value; Loc = ($v | Where-Object Name -eq 'InstallLocation').Value } } }
    }
    foreach ($d in $IOC.editors) {
        $ext = [Environment]::ExpandEnvironmentVariables($d.extDir); $usr = [Environment]::ExpandEnvironmentVariables($d.userDir)
        if ($d.envExtDir) { $ov = [Environment]::GetEnvironmentVariable($d.envExtDir, 'User'); if ($ov) { $ext = $ov } }
        $u = $unins | Where-Object { $_.Name -and $_.Name -match $d.uninstallName } | Select-Object -First 1
        if (-not $u -and -not [IO.Directory]::Exists($ext) -and -not [IO.Directory]::Exists($usr)) { continue }
        $loc = if ($u.Loc) { "$($u.Loc)".TrimEnd('\') } else { $null }
        $pj = if ($loc) { @(Get-Item -Path (Join-Path $loc 'resources\app\product.json'), (Join-Path $loc '*\resources\app\product.json') -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)[0] } else { $null }
        $prod = if ($pj) { Read-Json $pj.FullName } else { $null }
        $trust = $d.defaults.trustEnabled; $tasks = $d.defaults.allowAutomaticTasks; $src = 'assumed'
        if ($pj) {
            $js = Read-Text (Join-Path $pj.Directory.FullName 'out\vs\workbench\workbench.desktop.main.js') 300MB
            if ($js) {
                $c = [regex]::Match($js, '([A-Za-z_$][\w$]*)="security\.workspace\.trust\.enabled"')
                if ($c.Success) { $m = [regex]::Match($js, '\[' + [regex]::Escape($c.Groups[1].Value) + '\]:\{type:"boolean",default:(!0|!1|true|false)'); if ($m.Success) { $trust = $m.Groups[1].Value -in '!0', 'true'; $src = 'bundle' } }
                $m2 = [regex]::Match($js, '"task\.allowAutomaticTasks":\{[^}]{0,300}?default:"(on|off|auto)"'); if ($m2.Success) { $tasks = $m2.Groups[1].Value; $src = 'bundle' }
            }
        }
        $Editors.Add([pscustomobject]@{ Key = $d.key; Name = $d.name; Version = $u.Ver; InstallDir = $loc; ProductJson = $pj.FullName; ControlUrl = (V (V $prod 'extensionsGallery') 'controlUrl')
                Gallery = $d.gallery; ExtDir = $ext; UserDir = $usr; TrustDefault = $trust; AutoTasksDefault = $tasks; DefaultsSource = $src; EffectiveTrust = $null; EffectiveAutoTasks = $null })
    }
    if ($Editors.Count -eq 0) { Set-BvsCheckStatus -Id 'editors.discovery' -Status not_applicable -Reason 'no VS Code-family editor found' }
    $Editors | ForEach-Object Name
}

$Ext = [System.Collections.Generic.List[object]]::new()
foreach ($ed in $Editors) {
    $cid = "extensions.$($ed.Key).inventory"
    $null = Invoke-BvsCheck -Run $run -Id $cid -Description "$($ed.Name): extensions.json (all profiles), .obsolete, package.json manifests, unregistered folders" -Script {
        if (-not [IO.Directory]::Exists($ed.ExtDir)) { Set-BvsCheckStatus -Id $cid -Status not_applicable -Reason 'no extensions folder'; return }
        $listed = @{}
        $lists = @(Join-Path $ed.ExtDir 'extensions.json') + @(Get-ChildItem -Path (Join-Path $ed.UserDir 'profiles\*\extensions.json') -ErrorAction SilentlyContinue | ForEach-Object FullName)
        foreach ($l in $lists) { foreach ($e in @(Get-Items (Read-Json $l))) {
                $rel = V $e 'relativeLocation'; if (-not $rel) { $lp = V (V $e 'location') 'path'; if ($lp) { $rel = Split-Path -Leaf $lp } }
                if ($rel) { $listed["$rel".ToLowerInvariant()] = $e } } }
        $obs = Read-Json (Join-Path $ed.ExtDir '.obsolete')
        $obsSet = @(if ($obs -is [System.Collections.IDictionary]) { $obs.Keys | ForEach-Object { "$_".ToLowerInvariant() } })
        foreach ($d in (Get-ChildItem -LiteralPath $ed.ExtDir -Directory -Force | Sort-Object Name)) {
            $e = $listed[$d.Name.ToLowerInvariant()]; $md = V $e 'metadata'
            $pkg = Read-Json (Join-Path $d.FullName 'package.json') 16MB
            $pub = V $pkg 'publisher'; $nm = V $pkg 'name'
            $eid = V (V $e 'identifier') 'id'; if (-not $eid) { $eid = if ($pub -and $nm) { "$pub.$nm" } else { $d.Name -replace '-\d+(\.\d+)+.*$', '' } }
            $ts = V $md 'installedTimestamp'; $contrib = V $pkg 'contributes'
            $ck = @(if ($contrib -is [System.Collections.IDictionary]) { $contrib.Keys })
            $act = @(Get-Items (V $pkg 'activationEvents') | Where-Object { $_ })
            $loc = V (V $e 'location') 'path'
            $Ext.Add([pscustomobject]@{
                    Editor = $ed.Name; EditorKey = $ed.Key; Gallery = $ed.Gallery; Id = "$eid"; Version = $(if ($pkg) { V $pkg 'version' } else { V $e 'version' })
                    Folder = $d.FullName; Listed = [bool]$e; Obsolete = ($obsSet -contains $d.Name.ToLowerInvariant()); Source = (V $md 'source')
                    Installed = $(if ($ts) { [DateTimeOffset]::FromUnixTimeMilliseconds([long]$ts).UtcDateTime.ToString('o') } else { $d.CreationTimeUtc.ToString('o') })
                    PublisherDisplayName = (V $md 'publisherDisplayName'); PreRelease = [bool]((V $md 'isPreReleaseVersion') -or (V $md 'preRelease')); TargetPlatform = (V $md 'targetPlatform')
                    PkgPublisher = $pub; PkgName = $nm; Main = (V $pkg 'main'); Browser = (V $pkg 'browser'); Activation = @($act | Select-Object -First 12)
                    StartupActivation = @($act | Where-Object { $_ -in '*', 'onStartupFinished' }); Dependencies = @(Get-Items (V $pkg 'extensionDependencies')) + @(Get-Items (V $pkg 'extensionPack'))
                    SignatureFile = [IO.File]::Exists((Join-Path $d.FullName '.signature.p7s')); ThemeOnly = ($ck.Count -gt 0 -and -not ($ck | Where-Object { $_ -notin $IOC.themeContributes }))
                    LocationOutside = [bool]($loc -and -not (Test-Under ((($loc -replace '^/([a-zA-Z]:)', '$1') -replace '/', '\')) $ed.ExtDir))
                    Marketplace = 'not_checked'; Verified = $null; OpenVsx = 'not_checked'; KillList = $null; Deprecated = $null; Removed = $null; Unicode = $null; C2 = @(); Capabilities = $null
                    Expected = $ExpExt["$eid".ToLowerInvariant()] })
        }
        @($Ext | Where-Object EditorKey -eq $ed.Key | ForEach-Object Id)
    }
}

$Mal = @{}; $Dep = @{}; $Removed = @{}
$null = Invoke-BvsCheck -Run $run -Id 'extensions.intel.killlist' -Description 'Kill lists from each editor product.json controlUrl (malicious/deprecated) + microsoft/vsmarketplace RemovedPackages.md' -Script {
    if ($Ext.Count -eq 0) { Set-BvsCheckStatus -Id 'extensions.intel.killlist' -Status not_applicable -Reason 'no extensions'; return }
    $urls = @($Editors | ForEach-Object { if ($_.ControlUrl) { $_.ControlUrl } elseif ($_.Gallery -eq 'vsmarketplace') { $IOC.intel.vscodeControlUrlFallback } elseif ($_.Key -eq 'cursor') { $IOC.intel.cursorControlUrlFallback } } | Select-Object -Unique)
    $ok = 0
    foreach ($u in $urls) {
        $j = Get-IntelJson (Get-Intel $u ('control-' + ([uri]$u).Host + '.json'))
        if ($j -isnot [System.Collections.IDictionary]) { continue }; $ok++
        foreach ($m in @(Get-Items (V $j 'malicious'))) { $mid = if ($m -is [string]) { $m } else { (V $m 'id') ?? (V $m 'extensionOrPublisher') }; if ($mid -is [string]) { $Mal[$mid.ToLowerInvariant()] = ([uri]$u).Host } }
        $d = V $j 'deprecated'; if ($d -is [System.Collections.IDictionary]) { foreach ($k in $d.Keys) { $Dep["$k".ToLowerInvariant()] = $d[$k] } }
    }
    $r = Get-Intel $IOC.intel.removedPackagesUrl 'RemovedPackages.md'
    if ($r -and $r.Status -eq 200) { foreach ($line in ("$($r.Content)" -split "`r?`n")) { if ($line -match '^\s*\|\s*([\w-]+\.[\w.-]+)\s*\|\s*([^|]*)\|\s*([^|]+)\|') { $Removed[$Matches[1].ToLowerInvariant()] = @{ date = $Matches[2].Trim(); type = $Matches[3].Trim() } } } } else { $ok-- }
    if ($ok -lt $urls.Count) { Set-BvsCheckStatus -Id 'extensions.intel.killlist' -Status partial -Reason 'one or more intel lists could not be fetched' }
    foreach ($x in $Ext) { $id = $x.Id.ToLowerInvariant(); $x.KillList = $Mal[$id] ?? $Mal[($id -split '\.')[0]]; $x.Deprecated = $Dep[$id]; $x.Removed = $Removed[$id] }
    @($Mal.Keys)
}

$null = Invoke-BvsCheck -Run $run -Id 'extensions.intel.gallery' -Description 'Gallery existence + verified publisher: VS Marketplace for non-gallery/unregistered VS Code extensions, Open VSX for Cursor/fork extensions' -Script {
    $q = @($Ext | Where-Object { $_.Gallery -eq 'vsmarketplace' -and ($_.Source -ne 'gallery' -or -not $_.Listed) } | ForEach-Object Id | Select-Object -Unique)
    $fail = 0
    for ($i = 0; $i -lt $q.Count; $i += 40) {
        $batch = @($q[$i..([Math]::Min($i + 39, $q.Count - 1))])
        $crit = @($batch | ForEach-Object { @{ filterType = 7; value = $_ } }) + @(@{ filterType = 8; value = 'Microsoft.VisualStudio.Code' })
        $body = @{ filters = @(@{ criteria = $crit; pageNumber = 1; pageSize = 100; sortBy = 0; sortOrder = 0 }); assetTypes = @(); flags = [int]$IOC.intel.vscodeMarketplaceFlags }
        $j = Get-IntelJson (Get-Intel $IOC.intel.vscodeMarketplaceQuery 'vsmarketplace-query.json' 'POST' $body @{ Accept = 'application/json;api-version=3.0-preview.1' })
        if (-not $j) { $fail++; continue }
        $found = @{}
        foreach ($e in @(Get-Items (V (@(Get-Items (V $j 'results')))[0] 'extensions'))) {
            $po = V $e 'publisher'
            $found[('{0}.{1}' -f (V $po 'publisherName'), (V $e 'extensionName')).ToLowerInvariant()] = (("$(V $po 'flags')" -match 'verified') -or [bool](V $po 'isDomainVerified'))
        }
        foreach ($x in ($Ext | Where-Object { $_.Gallery -eq 'vsmarketplace' -and $batch -contains $_.Id })) { $k = $x.Id.ToLowerInvariant(); if ($found.Contains($k)) { $x.Marketplace = 'found'; $x.Verified = $found[$k] } else { $x.Marketplace = 'not_found' } }
    }
    foreach ($x in ($Ext | Where-Object Gallery -eq 'openvsx')) {
        $ns, $nm = $x.Id -split '\.', 2
        $r = Get-Intel ('{0}/{1}/{2}' -f $IOC.intel.openVsxApi, $ns, $nm) "openvsx-$($x.Id).json"
        if (-not $r) { $fail++; continue }
        if ($r.Status -eq 200) { $x.OpenVsx = 'found'; $x.Verified = [bool](V (Get-IntelJson $r) 'verified') } elseif ($r.Status -eq 404) { $x.OpenVsx = 'not_found' } else { $fail++ }
    }
    if ($fail) { Set-BvsCheckStatus -Id 'extensions.intel.gallery' -Status partial -Reason "$fail gallery lookups failed" }
    @($Ext | Where-Object { $_.Marketplace -ne 'not_checked' -or $_.OpenVsx -ne 'not_checked' } | ForEach-Object Id)
}

$invChars = [char[]](@(0xFE00..0xFE0F) + @(0x200B..0x200F) + @(0x202A..0x202E) + @(0x2066..0x2069) + @(0xDB40))
$InvRx = New-Rx ('(?:' + $IOC.unicode.runRegex + '){' + $IOC.unicode.minRun + ',}')
$C2Rx = New-Rx ((@($IOC.glassworm.solanaRpcHosts | ForEach-Object { [regex]::Escape($_) }) + @($IOC.glassworm.solanaMarkers | ForEach-Object { [regex]::Escape($_) }) + @($IOC.glassworm.deadDrops | ForEach-Object { $_.regex })) -join '|')
$CapRx = @{}; foreach ($k in $IOC.codeCapabilities.Keys) { $CapRx[$k] = New-Rx $IOC.codeCapabilities[$k] }
function Get-RunInfo([string]$S) {
    $k = [ordered]@{ variationSelector = 0; tag = 0; zeroWidth = 0; bidi = 0 }; $cp = 0
    $uniq = [System.Collections.Generic.HashSet[int]]::new()
    for ($i = 0; $i -lt $S.Length; $i++) {
        $c = [int]$S[$i]; $cp++; [void]$uniq.Add($c)
        if ($c -eq 0xDB40 -and $i + 1 -lt $S.Length) { $i++; [void]$uniq.Add(0x10000 + [int]$S[$i]); if ([int]$S[$i] -ge 0xDD00) { $k['variationSelector']++ } else { $k['tag']++ } }
        elseif ($c -ge 0xFE00 -and $c -le 0xFE0F) { $k['variationSelector']++ } elseif ($c -ge 0x200B -and $c -le 0x200F) { $k['zeroWidth']++ } else { $k['bidi']++ }
    }
    [pscustomobject]@{ codepoints = $cp; kinds = $k; tableLike = ($cp -le 40 -and ($uniq.Count - @($uniq | Where-Object { $_ -eq 0xDB40 }).Count) -ge $cp) }
}
$null = Invoke-BvsCheck -Run $run -Id 'extensions.code_scan' -Description "Bounded JS scan per extension (entry points first, <= $MaxJsMB MB): invisible-Unicode runs, GlassWorm C2 strings, code in theme-only extensions" -Script {
    $trunc = 0
    foreach ($x in $Ext) {
        $files = @(Get-BvsFiles -Path $x.Folder -Include '*.js', '*.cjs', '*.mjs' -NoPrune)
        $entry = @(foreach ($m in @($x.Main, $x.Browser)) { if ($m -is [string]) { $p = [IO.Path]::GetFullPath((Join-Path $x.Folder $m)); foreach ($c in @($p, "$p.js", (Join-Path $p 'index.js'))) { if ([IO.File]::Exists($c)) { $c; break } } } })
        $read = 0L; $n = 0; $maxRun = 0; $runs = 0; $cut = $false
        $hits = [System.Collections.Generic.List[object]]::new(); $c2 = [System.Collections.Generic.List[object]]::new(); $cap = [ordered]@{ eval = $false; child_process = $false; network = $false }
        foreach ($f in ($files | Sort-Object @{ Expression = { if ($entry -contains $_.FullName) { 0 } elseif ($_.FullName -match '\\node_modules\\') { 2 } else { 1 } } }, Length)) {
            if ($entry -notcontains $f.FullName -and ($read + $f.Length) -gt ($MaxJsMB * 1MB)) { $cut = $true; continue }
            $t = Read-Text $f.FullName 128MB; if ($null -eq $t) { continue }
            $read += $f.Length; $n++; $rel = $f.FullName.Substring($x.Folder.Length).TrimStart('\')
            try {
                if ($t.IndexOfAny($invChars) -ge 0) { foreach ($m in $InvRx.Matches($t)) { $ri = Get-RunInfo $m.Value; $runs++; if ($ri.codepoints -gt $maxRun) { $maxRun = $ri.codepoints }; if ($hits.Count -lt 5) { $hits.Add([ordered]@{ file = $rel; offset = $m.Index; codepoints = $ri.codepoints; tableLike = $ri.tableLike; kinds = $ri.kinds }) } } }
                foreach ($m in $C2Rx.Matches($t)) { if ($c2.Count -lt 8) { $c2.Add([ordered]@{ file = $rel; match = $m.Value; library = ($f.FullName -match $IOC.glassworm.solanaLibraryPathHint) }) } }
                if ($x.ThemeOnly) { foreach ($k in @($CapRx.Keys)) { if (-not $cap[$k] -and $CapRx[$k].IsMatch($t)) { $cap[$k] = $true } } }
            }
            catch { $run.Errors.Add([ordered]@{ check = 'extensions.code_scan'; error = "regex timeout in $rel"; at = [datetime]::UtcNow.ToString('o') }) }
        }
        if ($cut) { $trunc++ }
        $x.Unicode = [ordered]@{ maxRun = $maxRun; runs = $runs; filesScanned = $n; filesTotal = $files.Count; bytesScanned = $read; truncated = $cut; hits = @($hits) }
        $x.C2 = @($c2); if ($x.ThemeOnly) { $x.Capabilities = $cap }
    }
    if ($trunc) { Set-BvsCheckStatus -Id 'extensions.code_scan' -Status partial -Reason "$trunc extension(s) above the $MaxJsMB MB budget were scanned partially (entry points always scanned)" }
    @($Ext | ForEach-Object Id)
}

$null = Invoke-BvsCheck -Run $run -Id 'extensions.evaluate' -Description 'Calibrated findings from inventory + intel + code scan (expected items cap heuristic findings only)' -Script {
    $minRun = [int]$IOC.unicode.minRun
    foreach ($x in $Ext) {
        $ev = @{ type = 'extension'; editor = $x.Editor; id = $x.Id; version = $x.Version; path = $x.Folder; source = $x.Source; installed = $x.Installed }
        $exp = $x.Expected
        $expOk = [bool]($exp -and $x.Source -eq 'gallery' -and -not $x.KillList -and -not $x.Removed -and $x.Marketplace -ne 'not_found' -and $x.OpenVsx -ne 'not_found')
        $expObj = if ($expOk) { @{ id = $exp.id; reason = $exp.reason } } else { $null }
        if ($x.KillList) { Add-F @{ Check = 'extensions.intel.killlist'; Title = "Installed extension is on the editor's malicious-extension kill list: $($x.Id)"; Severity = 'critical'; Class = 'compromise'; Confidence = 'high'; Reasons = @('intel_match', 'kill_list'); Evidence = @($ev, @{ type = 'intel'; source = $x.KillList; match = $x.Id }); Recommendation = 'Close the editor, uninstall the extension, rotate secrets reachable from this profile (tokens, SSH keys, browser sessions) and review recent activity.'; FpNotes = 'Vendor-curated list; publisher-level entries can also match other extensions of the same publisher.'; Mitre = @($Mitre.ext) } }
        if ($x.Removed) {
            $sev = $IOC.intel.removedPackageTypeSeverity[$x.Removed.type.ToLowerInvariant()] ?? 'info'
            Add-F @{ Check = 'extensions.intel.removed_packages'; Title = "Extension was removed from the VS Marketplace ($($x.Removed.type)): $($x.Id)"; Severity = $sev; Class = $(if ($sev -eq 'critical') { 'compromise' } elseif ($sev -eq 'high') { 'suspicious' } else { 'hygiene' }); Confidence = 'high'; Reasons = @('intel_match'); Evidence = @($ev, @{ type = 'intel'; source = 'microsoft/vsmarketplace RemovedPackages.md'; removed = $x.Removed }); Recommendation = 'Uninstall the extension and review what it could reach while installed.'; FpNotes = 'Reasons other than Malware/Impersonation/Typo-squatting/Untrustworthy are usually not security issues.'; Mitre = @($Mitre.ext) }
        }
        $nf = @(if ($x.Marketplace -eq 'not_found') { 'VS Marketplace' }) + @(if ($x.OpenVsx -eq 'not_found') { 'Open VSX' })
        if ($nf) { Add-F @{ Check = 'extensions.intel.gallery'; Title = "Extension not found in $($nf -join ' / '): $($x.Id)"; Severity = (Get-Sev 'high' $expOk); Class = 'suspicious'; Confidence = 'medium'; Reasons = @('not_in_marketplace'); Evidence = @($ev); Expected = $expObj; Recommendation = 'Verify where it came from (VSIX, private gallery, dev build); uninstall it if unknown.'; FpNotes = 'Private/enterprise or locally built extensions, owner-unpublished ones and extensions only listed in the other gallery are not found.'; Mitre = @($Mitre.ext) } }
        if (-not $x.Listed -and -not $x.Obsolete) { Add-F @{ Check = "extensions.$($x.EditorKey).inventory"; Title = "Extension folder not registered in extensions.json (sideloaded): $($x.Id)"; Severity = (Get-Sev $(if ($nf) { 'high' } else { 'medium' }) $expOk); Class = 'suspicious'; Confidence = 'medium'; Reasons = @('sideloaded', 'user_writable'); Evidence = @($ev); Expected = $expObj; Recommendation = 'Check how the folder got there; remove it if you did not install it.'; FpNotes = 'An interrupted install/update or a manual copy can leave an unregistered folder.'; Mitre = @($Mitre.ext) } }
        if ($x.Source -and $x.Source -ne 'gallery') { Add-F @{ Check = "extensions.$($x.EditorKey).inventory"; Title = "Extension installed from a $($x.Source) file instead of the gallery (review): $($x.Id)"; Severity = (Get-Sev $(if ($nf) { 'high' } else { 'medium' }) $expOk); Class = 'suspicious'; Confidence = 'low'; Reasons = @('sideloaded'); Evidence = @($ev); Recommendation = 'Confirm you installed this VSIX on purpose and know its origin.'; FpNotes = 'Developers install their own or beta VSIX builds.'; Mitre = @($Mitre.ext) } }
        if ($x.LocationOutside) { Add-F @{ Check = "extensions.$($x.EditorKey).inventory"; Title = "extensions.json loads an extension from outside the extensions folder: $($x.Id)"; Severity = 'medium'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @('masquerading'); Evidence = @($ev); Recommendation = 'Check the location path in extensions.json.'; FpNotes = 'Portable installs or moved profiles.'; Mitre = @($Mitre.ext) } }
        if ($x.Listed -and $x.PkgPublisher -and $x.PkgName -and ("$($x.PkgPublisher).$($x.PkgName)" -ine $x.Id)) { Add-F @{ Check = "extensions.$($x.EditorKey).inventory"; Title = "package.json identity ($($x.PkgPublisher).$($x.PkgName)) differs from the registered ID $($x.Id)"; Severity = 'high'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @('masquerading'); Evidence = @($ev); Recommendation = 'Compare the folder with a fresh copy from the gallery; reinstall or remove.'; FpNotes = 'Publisher renames can cause case/name drift.'; Mitre = @($Mitre.ext) } }
        if ($x.ThemeOnly -and ($x.Main -or $x.Browser -or $x.Unicode.filesTotal -gt 0)) {
            $all3 = [bool]($x.Capabilities -and $x.Capabilities.eval -and $x.Capabilities.child_process -and $x.Capabilities.network)
            Add-F @{ Check = 'extensions.code_scan'; Title = "Theme/icon-only extension ships executable code$(if ($all3) { ' with eval + child_process + network' }): $($x.Id)"; Severity = (Get-Sev $(if ($all3) { 'high' } else { 'medium' }) $expOk); Class = 'suspicious'; Confidence = $(if ($all3) { 'medium' } else { 'low' }); Reasons = @('theme_with_code'); Evidence = @($ev, @{ type = 'code'; capabilities = $x.Capabilities; main = $x.Main }); Expected = $expObj; Recommendation = 'Themes need no code; uninstall unless you can explain it.'; FpNotes = 'Some theme packs include a small activation script (e.g. to switch themes).'; Mitre = @($Mitre.ext) }
        }
        $u = $x.Unicode
        if ($u -and $u.maxRun -ge $minRun) {
            $real = @($u.hits | Where-Object { -not $_.tableLike })
            $vs = @($u.hits | Where-Object { ($_.kinds['variationSelector'] + $_.kinds['tag']) * 2 -gt $_.codepoints }).Count -gt 0
            Add-F @{ Check = 'extensions.code_scan'; Title = "Invisible-Unicode run of $($u.maxRun) characters in extension code: $($x.Id)"; Severity = (Get-Sev $(if ($real) { 'high' } else { 'low' }) $expOk); Class = 'suspicious'; Confidence = $(if ($real -and $vs -and $u.maxRun -ge 100) { 'high' } elseif ($real) { 'medium' } else { 'low' }); Reasons = @('obfuscation'); Evidence = @($ev) + @($u.hits); Expected = $expObj; Recommendation = 'Open the file at the offset in a hex/Unicode-aware viewer; GlassWorm hides its loader in variation-selector runs. Uninstall and rotate secrets if confirmed.'; FpNotes = 'Libraries listing zero-width/bidi characters in a literal table (tableLike=true) are benign.'; Mitre = @($Mitre.obf, $Mitre.ext) }
        }
        if ($x.C2.Count) {
            $lib = @($x.C2 | Where-Object { -not $_.library }).Count -eq 0
            Add-F @{ Check = 'extensions.code_scan'; Title = "GlassWorm-style C2 indicator (Solana RPC / calendar dead drop) in extension code: $($x.Id)"; Severity = (Get-Sev $(if ($lib) { 'medium' } else { 'high' }) $expOk); Class = 'suspicious'; Confidence = $(if ($lib) { 'low' } else { 'medium' }); Reasons = @('c2_indicator'); Evidence = @($ev) + @($x.C2); Expected = $expObj; Recommendation = 'Check why the extension talks to a blockchain RPC / calendar link; uninstall if it is not a crypto/calendar tool.'; FpNotes = 'Wallet/web3 or calendar extensions legitimately bundle these endpoints (library=true means inside node_modules\@solana).'; Mitre = @($Mitre.dead, $Mitre.ext) }
        }
    }
    $obs = @($Ext | Where-Object Obsolete)
    if ($obs) { Add-F @{ Check = 'extensions.evaluate'; Title = "$($obs.Count) old extension version folder(s) still on disk (marked obsolete, pending cleanup)"; Severity = 'low'; Class = 'hygiene'; Confidence = 'high'; Reasons = @('stale'); Evidence = @($obs | ForEach-Object { @{ type = 'extension'; editor = $_.Editor; id = $_.Id; version = $_.Version; path = $_.Folder } }); Recommendation = 'Restart the editor so it deletes them, or remove the folders listed in .obsolete manually.'; FpNotes = 'Normal after updates; not a security issue.' } }
    $dep = @($Ext | Where-Object Deprecated)
    if ($dep) { Add-F @{ Check = 'extensions.evaluate'; Title = "$($dep.Count) installed extension(s) are deprecated by the vendor"; Severity = 'low'; Class = 'hygiene'; Confidence = 'high'; Reasons = @('deprecated'); Evidence = @($dep | ForEach-Object { @{ type = 'extension'; id = $_.Id; replacement = (Short $_.Deprecated 200) } }); Recommendation = 'Replace with the suggested extension or uninstall.'; FpNotes = 'Deprecation is maintenance, not malice.' } }
    @($Ext | ForEach-Object Id)
}
#endregion

#region editor settings
$SettingRows = [System.Collections.Generic.List[object]]::new()
$EnvRules = @{}; foreach ($r in $IOC.terminalEnvRisk) { $EnvRules[$r.name.ToUpperInvariant()] = $r }
function Test-ShellPath([string]$P) {
    $e = [Environment]::ExpandEnvironmentVariables(($P -replace '\$\{env:([^}]+)\}', '%$1%'))
    [IO.Path]::IsPathRooted($e) -and [bool](Test-BvsUserWritable $e)
}
function Add-Setting($Ctx, [string]$Key, $Val, [string]$Sev, [string]$Class, [string]$Title, [string]$Rec, [string]$Fp, [string[]]$Reasons = @(), [string]$Mit) {
    $SettingRows.Add([ordered]@{ editor = $Ctx.Editor; scope = $(if ($Ctx.Ws) { 'workspace' } else { 'user' }); file = $Ctx.File; key = $Key; value = (Short $Val 200); severity = $Sev })
    if ($Sev -eq 'none') { return }
    $p = @{ Check = $(if ($Ctx.Ws) { 'repos.autorun' } else { 'editors.settings' }); Title = $Title; Severity = $Sev; Class = $Class; Confidence = 'medium'; Reasons = $Reasons; Recommendation = $Rec; FpNotes = $Fp; Mitre = @(if ($Mit) { $Mit }) }
    $e = @{ type = 'setting'; editor = $Ctx.Editor; file = $Ctx.File; key = $Key; value = (Short $Val 300) }
    if ($Ctx.Ws) { Add-Cand "ws|$Key|$(Short $Val 120)" $p $Ctx.File $e } else { $p.Evidence = @($e); Add-F $p }
}
function Test-Settings($S, $Ctx) {
    if ($S -isnot [System.Collections.IDictionary]) { return }
    $w = [bool]$Ctx.Ws; $where = if ($w) { 'Workspace settings' } else { "$($Ctx.Editor) user settings" }
    $v = V $S 'http.proxy'; if ($v) { Add-Setting $Ctx 'http.proxy' $v 'medium' 'suspicious' "$where route editor traffic through a proxy" 'Confirm the proxy is yours; remove it otherwise.' 'Corporate or local debugging proxies (Fiddler, mitmproxy) are legitimate.' @('proxy') $Mitre.mitm }
    if ((V $S 'http.proxyStrictSSL') -eq $false) { Add-Setting $Ctx 'http.proxyStrictSSL' $false 'medium' 'hardening' "$where disable proxy TLS certificate checks" 'Set http.proxyStrictSSL back to true.' 'Sometimes needed behind TLS-inspecting proxies/AV web shields.' @('tls_disabled') $Mitre.mitm }
    if (V $S 'http.proxyAuthorization') { Add-Setting $Ctx 'http.proxyAuthorization' '[set]' 'medium' 'hardening' "$where store a proxy credential in plain text" 'Remove it; use the OS credential prompt.' 'None (value masked).' @('plaintext_secret') }
    foreach ($os in 'windows', 'linux', 'osx') {
        $envD = V $S "terminal.integrated.env.$os"
        if ($envD -is [System.Collections.IDictionary]) {
            foreach ($k in @($envD.Keys)) {
                $val = "$($envD[$k])"; $r = $EnvRules["$k".ToUpperInvariant()]; $sev = 'none'
                if ($r) { $sev = $r.severity; if ($r.onlyIf -and $val -notmatch $r.onlyIf) { $sev = 'none' }; if ($r.highIf -and $val -match $r.highIf) { $sev = 'high' }; if ($r.lowIf -and $val -match $r.lowIf) { $sev = 'low' } }
                if ((Get-Risk $val).Level -in 'high', 'medium') { $sev = 'high' }
                if ($w -and $sev -eq 'none') { $sev = 'low' }
                Add-Setting $Ctx "terminal.integrated.env.$os.$k" $val $sev 'suspicious' "$where set terminal environment variable $k" 'Remove the variable unless you added it on purpose.' 'Developers set PATH/NODE_OPTIONS for tooling; check the value.' @('shell_override') $Mitre.exec
            }
        }
        foreach ($pk in "terminal.integrated.profiles.$os", "terminal.integrated.automationProfile.$os", "terminal.integrated.shell.$os", "terminal.integrated.automationShell.$os", "terminal.integrated.shellArgs.$os") {
            $pv = V $S $pk; if ($null -eq $pv) { continue }
            $profiles = if ($pk -like '*.profiles.*' -and $pv -is [System.Collections.IDictionary]) { @(foreach ($n in @($pv.Keys)) { , $pv[$n] }) } else { @(, $pv) }
            foreach ($pr in $profiles) {
                if ($null -eq $pr) { continue }
                $paths = @(if ($pr -is [string]) { $pr } elseif ($pr -is [System.Collections.IDictionary]) { Get-Items (V $pr 'path') })
                if ($pr -is [System.Collections.IDictionary] -and (V $pr 'source') -and -not $paths) { continue }
                $risk = Get-Risk (Short $pr 2000)
                $uw = @($paths | Where-Object { $_ -is [string] -and (Test-ShellPath $_) }).Count -gt 0
                $sev = if ($risk.Level -in 'high', 'medium') { 'high' } elseif ($uw -or $w) { 'medium' } else { 'none' }
                Add-Setting $Ctx $pk $pr $sev 'suspicious' "$where override the terminal/task shell ($pk)" 'Check the shell path and arguments; remove the override unless you set it.' 'Custom profiles for Git Bash, WSL or Developer PowerShell are common.' @('shell_override') $Mitre.exec
            }
        }
    }
    if ((V $S 'security.workspace.trust.enabled') -eq $false) { Add-Setting $Ctx 'security.workspace.trust.enabled' $false $(if ($w) { 'low' } else { 'medium' }) $(if ($w) { 'suspicious' } else { 'hardening' }) "$where turn Workspace Trust off" 'Set security.workspace.trust.enabled to true.' 'Convenience choice; it lets every opened folder run tasks/extensions without a prompt.' @('trust_disabled') }
    if ((V $S 'task.allowAutomaticTasks') -eq 'on') { Add-Setting $Ctx 'task.allowAutomaticTasks' 'on' 'medium' $(if ($w) { 'suspicious' } else { 'hardening' }) "$where allow folder-open tasks to run automatically" 'Set task.allowAutomaticTasks to "off".' 'Rarely needed; some templates ask for it.' @('autorun_on_open') $Mitre.exec }
    foreach ($k in $IOC.chatAutoApproveKeys) {
        $v = V $S $k
        if ($null -ne $v -and $v -ne $false -and -not ($v -is [System.Collections.IDictionary] -and $v.Count -eq 0)) { Add-Setting $Ctx $k $v $(if ($w) { 'high' } else { 'medium' }) $(if ($w) { 'suspicious' } else { 'hardening' }) "$where auto-approve AI agent tool calls ($k)" 'Remove the auto-approve setting so agent actions need confirmation.' $(if ($w) { 'A repo enabling agent auto-approval for itself is the CVE-2025-53773 prompt-injection pattern.' } else { 'Deliberate "YOLO mode" choice.' }) @('prompt_injection') $Mitre.exec }
    }
    if ((V $S 'extensions.verifySignature') -eq $false) { Add-Setting $Ctx 'extensions.verifySignature' $false 'medium' 'hardening' "$where disable extension signature verification" 'Remove extensions.verifySignature.' 'Sometimes set behind TLS-inspecting proxies.' @('signature_check_off') }
    foreach ($r in $IOC.autoRunOnOpenSettings) { if ((V $S $r.key) -eq $r.value) { Add-Setting $Ctx $r.key $r.value 'low' 'hardening' "$where let an extension run project code on folder open ($($r.key))" "Set $($r.key) to false." $r.note @('autorun_on_open') $Mitre.exec } }
    foreach ($k in $IOC.workspaceExecPathSettings) { $v = V $S $k; if ($null -ne $v) { Add-Setting $Ctx $k $v $(if ($w -and (Get-Risk (Short $v 2000)).Level -in 'high', 'medium') { 'medium' } else { 'none' }) 'suspicious' "$where point $k at a custom executable" 'Check the path.' 'Interpreter/tool paths are normal developer settings.' @('exec_path') } }
}

$AutoRows = [System.Collections.Generic.List[object]]::new()
$Opened = @{}
function Get-OpenedIn([string]$Dir) { $o = $Opened[$Dir.TrimEnd('\').ToLowerInvariant()]; if ($o) { @($o) } else { @() } }
function Get-CmdText($T) { (@('command', 'args', 'windows', 'linux', 'osx', 'options') | ForEach-Object { $x = V $T $_; if ($null -ne $x) { if ($x -is [string]) { $x } else { ConvertTo-Json -InputObject $x -Compress -Depth 8 -WarningAction SilentlyContinue } } }) -join ' ' }
function Test-Tasks($Obj, [string]$File, [string]$Where, [string]$Root) {
    $tasks = @(Get-Items (V $Obj 'tasks') | Where-Object { $_ -is [System.Collections.IDictionary] })
    $byLabel = @{}; foreach ($t in $tasks) { $l = V $t 'label'; if ($l) { $byLabel["$l"] = $t } }
    foreach ($t in $tasks) {
        $runOn = V (V $t 'runOptions') 'runOn'; $txt = Get-CmdText $t
        foreach ($d in @(Get-Items (V $t 'dependsOn'))) { if ($d -is [string] -and $byLabel[$d]) { $txt += ' ' + (Get-CmdText $byLabel[$d]) } }
        $risk = Get-Risk $txt; $pres = V $t 'presentation'
        $hidden = ((V $pres 'reveal') -in 'never', 'silent') -or ((V $pres 'echo') -eq $false) -or ((V $pres 'close') -eq $true)
        $opened = Get-OpenedIn $Root
        $AutoRows.Add([ordered]@{ kind = 'tasks'; file = $File; item = (V $t 'label'); runOn = $runOn; risk = $risk.Level; traits = $risk.Traits; hidden = $hidden; command = (Short $txt 300); openedIn = $opened })
        if ($runOn -eq 'folderOpen') {
            Add-Cand ('task|' + (Short $txt 200)) @{ Check = 'repos.autorun'; Title = "Task runs automatically when the folder opens (runOn: folderOpen): $Where"; Severity = 'high'; Class = 'suspicious'; Confidence = $(if ($risk.Level -in 'high', 'medium' -or $hidden) { 'high' } else { 'medium' }); Reasons = @('autorun_on_open') + @($risk.Traits | Where-Object { $_ -in 'download', 'encoded', 'pipe_shell', 'disguised_script' }); Recommendation = 'Do not open this folder in Cursor or with automatic tasks allowed. Read the command; delete the task (or repo) if you did not write it. If it already ran, treat the machine as possibly compromised (Contagious Interview pattern).'; FpNotes = 'Some developers auto-start watchers/dev servers on folder open; a plain local build command in your own repo is benign.'; Mitre = @($Mitre.exec, 'T1059') } $File @{ type = 'file'; path = $File; task = (V $t 'label'); command = (Short $txt 400); traits = $risk.Traits; hidden = $hidden; openedIn = $opened }
        }
        elseif ($risk.Level -eq 'high') { Add-Cand ('taskdl|' + (Short $txt 200)) @{ Check = 'repos.autorun'; Title = 'Task command downloads, decodes or pipes remote content into a shell'; Severity = 'medium'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @($risk.Traits); Recommendation = 'Read the task before running it.'; FpNotes = 'Installer/bootstrap tasks (curl ... | sh) exist in legitimate projects.'; Mitre = @($Mitre.exec) } $File @{ type = 'file'; path = $File; task = (V $t 'label'); command = (Short $txt 400) } }
    }
    , $byLabel
}
function Test-DevContainer($Obj, [string]$File) {
    foreach ($k in 'initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand') {
        $v = V $Obj $k; if ($null -eq $v) { continue }
        $risk = Get-Risk (Short $v 4000); $dl = $risk.Level -in 'high', 'medium'
        $AutoRows.Add([ordered]@{ kind = 'devcontainer'; file = $File; item = $k; risk = $risk.Level; traits = $risk.Traits; command = (Short $v 300) })
        if ($k -eq 'initializeCommand' -or $dl) {
            Add-Cand ("dc|$k|" + (Short $v 200)) @{ Check = 'repos.autorun'; Title = $(if ($k -eq 'initializeCommand') { 'Dev container initializeCommand runs on the HOST when the container is opened' } else { "Dev container $k downloads or decodes code" }); Severity = 'high'; Class = 'suspicious'; Confidence = $(if ($dl) { 'high' } else { 'low' }); Reasons = @('autorun_on_open') + @($risk.Traits | Where-Object { $_ -in 'download', 'encoded', 'pipe_shell' }); Recommendation = 'Read the command before "Reopen in Container"; remove it if you did not add it.'; FpNotes = 'initializeCommand is often benign host prep (docker network create, copying .env); in-container package installs are normal.'; Mitre = @($Mitre.exec) } $File @{ type = 'file'; path = $File; key = $k; command = (Short $v 400); traits = $risk.Traits }
        }
    }
    if (((V $Obj 'privileged') -eq $true) -or ("$(Short (V $Obj 'runArgs') 2000)" -match '--privileged') -or ("$(Short (V $Obj 'mounts') 4000)" -match 'docker\.sock|\.ssh|localEnv:(HOME|USERPROFILE)\}')) {
        Add-Cand "dcpriv|$File" @{ Check = 'repos.autorun'; Title = 'Dev container requests privileged mode or mounts host secrets / the Docker socket'; Severity = 'medium'; Class = 'hardening'; Confidence = 'medium'; Reasons = @('container_escape_risk'); Recommendation = 'Remove privileged/runArgs/mounts you do not need.'; FpNotes = 'Docker-in-docker and SSH-forwarding setups use these on purpose.'; Mitre = @('T1611') } $File @{ type = 'file'; path = $File }
    }
}

$null = Invoke-BvsCheck -Run $run -Id 'editors.settings' -Description 'User settings (all profiles) traps, effective Workspace Trust / automatic-task values, user-level tasks.json' -Script {
    if ($Editors.Count -eq 0) { Set-BvsCheckStatus -Id 'editors.settings' -Status not_applicable -Reason 'no editor'; return }
    foreach ($ed in $Editors) {
        $main = Join-Path $ed.UserDir 'settings.json'; $trust = $null; $tasks = $null
        foreach ($f in @($main) + @(Get-ChildItem -Path (Join-Path $ed.UserDir 'profiles\*\settings.json') -ErrorAction SilentlyContinue | ForEach-Object FullName)) {
            $s = Read-Json $f; if ($s -isnot [System.Collections.IDictionary]) { continue }
            Test-Settings $s @{ Editor = $ed.Name; File = $f; Ws = $false }
            if ($f -eq $main) { $trust = V $s 'security.workspace.trust.enabled'; $tasks = V $s 'task.allowAutomaticTasks' }
        }
        $ed.EffectiveTrust = if ($null -ne $trust) { [bool]$trust } else { $ed.TrustDefault }
        $ed.EffectiveAutoTasks = if ($tasks) { $tasks } else { $ed.AutoTasksDefault }
        if ($null -eq $trust -and $ed.EffectiveTrust -eq $false -and $ed.EffectiveAutoTasks -eq 'on') {
            Add-F @{ Check = 'editors.settings'; Title = "$($ed.Name): Workspace Trust is off and folder-open tasks run automatically (product defaults)"; Severity = 'medium'; Class = 'hardening'; Confidence = 'high'; Reasons = @('trust_disabled', 'autorun_on_open'); Evidence = @(@{ type = 'setting'; editor = $ed.Name; file = $main; trustDefault = $ed.TrustDefault; automaticTasksDefault = $ed.AutoTasksDefault; source = $ed.DefaultsSource }); Recommendation = "In $($ed.Name) settings.json set ""security.workspace.trust.enabled"": true and ""task.allowAutomaticTasks"": ""off"". Until then, never open untrusted repos in it."; FpNotes = 'Vendor default, not tampering; it becomes dangerous when a cloned repo contains a folderOpen task.'; Mitre = @($Mitre.exec) }
        }
        $ut = Join-Path $ed.UserDir 'tasks.json'; $uj = Read-Json $ut
        if ($uj) { $null = Test-Tasks $uj $ut "$($ed.Name) user tasks (apply to every folder)" $ed.UserDir }
    }
    @($SettingRows | ForEach-Object key)
}
$null = Invoke-BvsCheck -Run $run -Id 'editors.opened_folders' -Description 'Folders opened in each editor (workspaceStorage\*\workspace.json), used to tell whether an auto-run vector was exposed' -Script {
    foreach ($ed in $Editors) {
        foreach ($w in @(Get-ChildItem -Path (Join-Path $ed.UserDir 'workspaceStorage\*\workspace.json') -ErrorAction SilentlyContinue)) {
            $f = V (Read-Json $w.FullName) 'folder'
            if ($f -is [string] -and $f -like 'file:*') { try { $p = ([uri]$f).LocalPath.TrimEnd('\').ToLowerInvariant(); if (-not $Opened.Contains($p)) { $Opened[$p] = [System.Collections.Generic.List[string]]::new() }; if (-not $Opened[$p].Contains($ed.Name)) { $Opened[$p].Add($ed.Name) } } catch { } }
        }
    }
    @($Opened.Keys)
}
#endregion

#region repositories: discovery and auto-run vectors
$Sweep = @()
$null = Invoke-BvsCheck -Run $run -Id 'repos.discovery' -Description "Repos (.git dir/file), package.json projects and editor config folders under %USERPROFILE% (depth $RepoDepth; node_modules, editor extension folders and this project excluded)" -Script {
    $extDirs = @($Editors | ForEach-Object ExtDir)
    $script:Sweep = @(Get-BvsFiles -Path $U -MaxDepth $RepoDepth -Directories -Include '.git', '.devcontainer.json', '*.code-workspace', 'package.json' | Where-Object {
            $p = $_.FullName
            ($_.Name -in '.git', '.vscode', '.devcontainer', '.devcontainer.json', '.idea', 'package.json' -or $_.Name -like '*.code-workspace') -and -not (Test-Under $p $RootFull) -and -not ($extDirs | Where-Object { Test-Under $p $_ }) })
    @($script:Sweep | Where-Object Name -eq '.git' | ForEach-Object FullName)
}
$null = Invoke-BvsCheck -Run $run -Id 'repos.autorun' -Description 'tasks.json runOn folderOpen, launch.json preLaunchTask, .vscode\settings.json traps, *.code-workspace, devcontainer lifecycle commands, JetBrains startup tasks' -Script {
    foreach ($d in ($Sweep | Where-Object { $_ -is [IO.DirectoryInfo] -and $_.Name -eq '.vscode' })) {
        $root = $d.Parent.FullName; $tf = Join-Path $d.FullName 'tasks.json'; $byLabel = @{}
        $tj = Read-Json $tf; if ($tj) { $byLabel = Test-Tasks $tj $tf $root $root }
        $lf = Join-Path $d.FullName 'launch.json'; $lj = Read-Json $lf
        foreach ($c in @(Get-Items (V $lj 'configurations') | Where-Object { $_ -is [System.Collections.IDictionary] })) {
            $txt = ''; foreach ($k in 'preLaunchTask', 'postDebugTask') { $l = V $c $k; if ($l -is [string] -and $byLabel[$l]) { $txt += ' ' + (Get-CmdText $byLabel[$l]) } }
            $risk = Get-Risk ($txt + ' ' + (Short $c 4000))
            $AutoRows.Add([ordered]@{ kind = 'launch'; file = $lf; item = (V $c 'name'); preLaunchTask = (V $c 'preLaunchTask'); risk = $risk.Level; traits = $risk.Traits })
            if (@($risk.Traits | Where-Object { $_ -in 'download', 'pipe_shell', 'encoded' }).Count) { Add-Cand ('launch|' + (Short $txt 200)) @{ Check = 'repos.autorun'; Title = 'Debug launch configuration (or its preLaunchTask) downloads or decodes code'; Severity = 'medium'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @($risk.Traits); Recommendation = 'Read the launch config and its preLaunchTask before pressing F5.'; FpNotes = 'Some debug setups fetch tools on first run.'; Mitre = @($Mitre.exec) } $lf @{ type = 'file'; path = $lf; config = (V $c 'name'); traits = $risk.Traits } }
        }
        $sf = Join-Path $d.FullName 'settings.json'; $sj = Read-Json $sf; if ($sj) { Test-Settings $sj @{ Editor = 'workspace'; File = $sf; Ws = $true } }
    }
    foreach ($f in ($Sweep | Where-Object { $_ -is [IO.FileInfo] -and $_.Name -like '*.code-workspace' })) {
        $j = Read-Json $f.FullName
        if ($j) { if (V $j 'tasks') { $null = Test-Tasks (V $j 'tasks') $f.FullName $f.FullName $f.DirectoryName }; if (V $j 'settings') { Test-Settings (V $j 'settings') @{ Editor = 'workspace'; File = $f.FullName; Ws = $true } } }
    }
    $dcs = @($Sweep | Where-Object { $_ -is [IO.FileInfo] -and $_.Name -eq '.devcontainer.json' } | ForEach-Object FullName) +
    @($Sweep | Where-Object { $_ -is [IO.DirectoryInfo] -and $_.Name -eq '.devcontainer' } | ForEach-Object { Get-ChildItem -Path (Join-Path $_.FullName 'devcontainer.json'), (Join-Path $_.FullName '*\devcontainer.json') -ErrorAction SilentlyContinue | ForEach-Object FullName })
    foreach ($f in $dcs) { $j = Read-Json $f; if ($j) { Test-DevContainer $j $f } }
    foreach ($d in ($Sweep | Where-Object { $_ -is [IO.DirectoryInfo] -and $_.Name -eq '.idea' })) {
        foreach ($x in @(Get-ChildItem -LiteralPath $d.FullName -Filter *.xml -File -ErrorAction SilentlyContinue)) {
            $t = Read-Text $x.FullName 4MB
            if ($t -and $t -match $IOC.jetbrains.startupComponentRegex) { $AutoRows.Add([ordered]@{ kind = 'jetbrains-startup'; file = $x.FullName }); Add-Cand "idea|$($x.FullName)" @{ Check = 'repos.autorun'; Title = 'JetBrains project defines a startup task (runs when the project opens)'; Severity = 'high'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @('autorun_on_open'); Recommendation = 'Check Settings > Tools > Startup Tasks for this project; remove tasks you did not create.'; FpNotes = 'Teams share startup tasks (e.g. start a dev server); JetBrains Safe Mode blocks them for untrusted projects.'; Mitre = @($Mitre.exec) } $x.FullName @{ type = 'file'; path = $x.FullName } }
        }
    }
    @($AutoRows | ForEach-Object file)
}
#endregion

#region git
$GitRows = [System.Collections.Generic.List[object]]::new()
function Test-GitEntries($Entries, [string]$Mode, [string]$Anchor) {
    foreach ($e in $Entries) {
        $k = "$($e.Sec).$($e.Key)"; $v = "$($e.Value)"; $sev = 'none'; $cls = 'suspicious'; $title = $null; $rs = @('git_config'); $fp = 'Developer tooling sets git options; check that you recognise the value.'
        if (@($IOC.git.expectedValues | Where-Object { $_.key -eq $e.Name -and $v -match $_.regex }).Count) { continue }
        $bad = (Get-Risk $v).Level -in 'high', 'medium'; $hit = $true
        switch -Regex ($k) {
            '^core\.fsmonitor$' { if ($v -notmatch '^(true|false|yes|no|on|off|1|0)?$') { $sev = 'high'; $title = 'core.fsmonitor runs a program on every git status (also triggered by editor git refreshes)'; $rs = @('persistence') }; break }
            '^core\.hookspath$' { if ($v -notmatch $IOC.git.huskyHooksPath) { $sev = $(if ($Mode -eq 'repo') { 'low' } else { 'medium' }); $title = "core.hooksPath redirects git hooks ($($e.Scope))"; $rs = @('custom_hook') }; break }
            '^(core\.(sshcommand|pager|editor|askpass|gitproxy)|sequence\.editor|diff\.(external|textconv|command)|gpg\.program|merge\.driver|interactive\.difffilter|pager\..+)$' {
                if ($bad) { $sev = 'high' } elseif ($v -notmatch $IOC.git.benignExecValues) { $sev = 'low' }
                $title = "$($e.Name) runs an external program"; break }
            '^filter\.(clean|smudge|process)$' { $sev = $(if ($bad) { 'high' } else { 'medium' }); $title = "Git filter $($e.Name) runs a program on checkout/commit"; break }
            '^credential\.helper$' {
                if ($v -eq 'store') { $sev = 'medium'; $cls = 'hardening'; $rs = @('plaintext_secret'); $title = 'credential.helper=store keeps git passwords/tokens in plain text'; $fp = "Plaintext store file present: $([IO.File]::Exists((Join-Path $U '.git-credentials')))" }
                elseif ($v -notin $IOC.git.okCredentialHelpers -and $v -notmatch '^(manager|manager-core|wincred)(\.exe)?$|git-credential-manager') { $sev = $(if ($bad) { 'high' } else { 'medium' }); $title = "Custom git credential helper: $($e.Name)"; $rs = @('credential_access') }
                break }
            '^url\.(insteadof|pushinsteadof)$' { $a = (Get-RemoteInfo $e.Sub).Host; $b = (Get-RemoteInfo $v).Host; if ($a -ne $b) { $sev = 'high'; $title = "url.insteadOf rewrites $b URLs to another host ($a)"; $rs = @('remote_rewrite') }; break }
            '^alias\.' { if ($v.StartsWith('!') -and $bad) { $sev = 'high'; $title = "Git shell alias $($e.Name) downloads/decodes code" } elseif (-not $v.StartsWith('!')) { $hit = $false }; break }
            '^(remote\.(uploadpack|receivepack)|uploadpack\.packobjectshook)$' { $sev = 'high'; $title = "$($e.Name) makes git run a custom program"; break }
            '^submodule\.update$' { if ($v.StartsWith('!')) { $sev = 'high'; $title = "$($e.Name) runs a shell command on submodule update" } else { $hit = $false }; break }
            '^http\.sslverify$' { if ($v -match '^(false|no|off|0)$') { $sev = 'medium'; $cls = 'hardening'; $title = "TLS verification disabled ($($e.Name))"; $rs = @('tls_disabled') }; break }
            '^https?\.proxy$' { if ($v) { $sev = 'medium'; $title = "Git traffic goes through a proxy ($($e.Name))"; $rs = @('proxy') }; break }
            '^http\.extraheader$' { if ($v -match 'authorization') { $sev = 'medium'; $cls = 'hardening'; $title = "Credential header stored in git config ($($e.Name))"; $rs = @('plaintext_secret') }; break }
            '^protocol\.allow$' { if ($v -eq 'always' -and ($e.Sub -in 'ext', 'fd' -or $null -eq $e.Sub)) { $sev = $(if ($e.Sub) { 'high' } else { 'medium' }); $title = "$($e.Name)=always enables command-running transports" }; break }
            '^safe\.directory$' { if ($v -eq '*') { $sev = 'low'; $cls = 'hardening'; $title = 'safe.directory=* disables git repository-ownership protection' }; break }
            '^(include|includeif)\.path$' { break }
            default { $hit = $false }
        }
        if (-not $hit) { continue }
        $GitRows.Add([ordered]@{ scope = $e.Scope; file = $e.File; line = $e.Line; key = $e.Name; value = (Short $v 200); severity = $sev })
        if ($sev -eq 'none') { continue }
        $p = @{ Check = $(if ($Mode -eq 'repo') { 'git.repos' } else { 'git.global' }); Title = $title; Severity = $sev; Class = $cls; Confidence = 'medium'; Reasons = $rs; Recommendation = "Review $($e.Name) in $($e.File) (line $($e.Line)); remove it unless you configured it."; FpNotes = $fp; Mitre = @($Mitre.hook) }
        $ev = @{ type = 'git-config'; scope = $e.Scope; file = $e.File; line = $e.Line; key = $e.Name; value = (Short $v 300) }
        if ($Mode -eq 'repo') { Add-Cand "git|$($e.Name)|$(Short $v 150)" $p $Anchor $ev } else { $p.Evidence = @($ev); Add-F $p }
    }
}
function Test-HookDir([string]$Dir, [string]$Mode, [string]$Anchor) {
    foreach ($h in @(Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.sample' })) {
        $t = Read-Text $h.FullName 1MB
        $mgr = @($IOC.git.expectedHookSignatures | Where-Object { $t -and $t -match $_.regex } | ForEach-Object { $_.name })[0]
        $risk = Get-Risk $t
        $sev = if ($risk.Level -eq 'high') { 'high' } elseif ($risk.Level -eq 'medium') { 'medium' } elseif ($mgr) { 'none' } else { 'low' }
        if ($Mode -eq 'template' -and $sev -in 'none', 'low') { $sev = 'medium' }
        if ($sev -ne 'none') {
            $title = if ($Mode -eq 'template') { "Git template hook '$($h.Name)' is copied into every new repository" } elseif ($sev -eq 'low') { "Custom git hook '$($h.Name)' (review)" } else { "Git hook '$($h.Name)' downloads, decodes or runs inline code" }
            Add-Cand ("hook|$($h.Name)|" + (Get-BvsHash $h.FullName)) @{ Check = $(if ($Mode -eq 'template') { 'git.global' } else { 'git.repos' }); Title = $title; Severity = $sev; Class = 'suspicious'; Confidence = $(if ($sev -eq 'low') { 'low' } else { 'medium' }); Reasons = @('custom_hook') + @($risk.Traits | Where-Object { $_ -in 'download', 'encoded', 'inline_exec', 'pipe_shell', 'base64_word' }); Recommendation = 'Read the hook; delete it if you did not install it (hooks are not cloned, so something on this machine wrote it).'; FpNotes = 'Hook managers and personal automation write hooks; check the content.'; Mitre = @($Mitre.hook) } $Anchor @{ type = 'file'; path = $h.FullName; size = $h.Length; modified = $h.LastWriteTimeUtc.ToString('o'); traits = $risk.Traits; manager = $mgr }
        }
        [ordered]@{ name = $h.Name; size = $h.Length; manager = $mgr; risk = $risk.Level; traits = $risk.Traits }
    }
}
$null = Invoke-BvsCheck -Run $run -Id 'git.global' -Description 'System/portable/global/XDG/GitHub Desktop gitconfig traps (includes followed), persistent GIT_* variables, template hooks' -Script {
    $gitRoot = (Get-BvsRegValues -Path 'HKLM\SOFTWARE\GitForWindows' | Where-Object Name -eq 'InstallPath').Value
    if (-not $gitRoot) { $g = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($g) { $gitRoot = Split-Path -Parent (Split-Path -Parent $g.Source) } }
    $files = [ordered]@{}
    if ($gitRoot) { $files["$gitRoot\etc\gitconfig"] = 'system'; $files["$gitRoot\mingw64\etc\gitconfig"] = 'system' }
    $files["$env:ProgramData\Git\config"] = 'portable'; $files["$U\.gitconfig"] = 'global'
    $files["$(if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { "$U\.config" })\git\config"] = 'xdg'
    foreach ($f in @(Get-ChildItem -Path "$env:LOCALAPPDATA\GitHubDesktop\app-*\resources\app\git\etc\gitconfig", "$env:LOCALAPPDATA\GitHubDesktop\app-*\resources\app\git\mingw64\etc\gitconfig" -ErrorAction SilentlyContinue)) { $files[$f.FullName] = 'github-desktop' }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $files.Keys) { if ([IO.File]::Exists($p)) { foreach ($e in (Read-GitConfig $p $files[$p])) { $all.Add($e) } } }
    Test-GitEntries $all 'global' $null
    foreach ($sc in @(@('User', 'HKCU\Environment'), @('Machine', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'))) {
        foreach ($rv in @(Get-BvsRegValues -Path $sc[1] | Where-Object { $_.Name -in $IOC.git.envVars -or $_.Name -like 'GIT_CONFIG_KEY_*' })) {
            $GitRows.Add([ordered]@{ scope = "env-$($sc[0])"; key = $rv.Name; value = (Short "$($rv.Value)" 200) })
            Add-F @{ Check = 'git.global'; Title = "Persistent environment variable $($rv.Name) changes git behaviour ($($sc[0]))"; Severity = $(if ($rv.Name -match 'TRACE|VERBOSE') { 'low' } else { 'medium' }); Class = 'suspicious'; Confidence = 'medium'; Reasons = @('git_config'); Evidence = @(@{ type = 'registry'; path = $sc[1]; name = $rv.Name; value = (Short "$($rv.Value)" 300) }); Recommendation = 'Remove the variable unless you set it on purpose.'; FpNotes = 'Some tools set GIT_SSH or GIT_EDITOR globally.'; Mitre = @($Mitre.hook) }
        }
    }
    $tdirs = @(if ($gitRoot) { "$gitRoot\mingw64\share\git-core\templates\hooks" }) + @($all | Where-Object { $_.Sec -eq 'init' -and $_.Key -eq 'templatedir' } | ForEach-Object { Join-Path ($_.Value -replace '^~(?=[/\\])', $U) 'hooks' })
    $hp = @($all | Where-Object { $_.Sec -eq 'core' -and $_.Key -eq 'hookspath' } | ForEach-Object { $_.Value -replace '^~(?=[/\\])', $U } | Where-Object { [IO.Path]::IsPathRooted($_) })
    foreach ($td in $tdirs) { $null = Test-HookDir $td 'template' $td }
    foreach ($d in $hp) { $null = Test-HookDir $d 'global' $d }
    @($files.Keys | Where-Object { [IO.File]::Exists($_) })
}
$Repos = [System.Collections.Generic.List[object]]::new()
$null = Invoke-BvsCheck -Run $run -Id 'git.repos' -Description '.git\config per repo (remote/pushurl hosts, hooksPath, fsmonitor, insteadOf, aliases, helpers), non-sample hooks, worktree entries; copies grouped by remote' -Script {
    $res = @(foreach ($g in ($Sweep | Where-Object Name -eq '.git')) { Resolve-Git $g })
    $stale = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($res | Where-Object { $_ } | Group-Object Common)) {
        $common = $grp.Name; $works = @($grp.Group | ForEach-Object Work); $anchor = $works[0]
        $cfg = Read-GitConfig (Join-Path $common 'config') 'repo'
        Test-GitEntries @($cfg | Where-Object { -not ($_.Sec -eq 'remote' -and $_.Key -in 'url', 'pushurl', 'fetch') }) 'repo' $anchor
        $remotes = @($cfg | Where-Object { $_.Sec -eq 'remote' -and $_.Key -in 'url', 'pushurl' } | ForEach-Object { $ri = Get-RemoteInfo $_.Value; [pscustomobject]@{ Name = $_.Sub; Kind = $_.Key; Url = (Protect-S10Url $_.Value); Host = $ri.Host; Scheme = $ri.Scheme; Key = $ri.Key; Owner = $ri.Owner; Creds = $ri.Creds } })
        foreach ($r in $remotes) {
            $ev = @{ type = 'git-remote'; repo = $anchor; remote = $r.Name; kind = $r.Kind; url = $r.Url }
            if ($r.Scheme -in 'ext', 'fd') { Add-Cand "rem|$($r.Url)" @{ Check = 'git.repos'; Title = 'Git remote uses the ext::/fd:: transport (runs a local command)'; Severity = 'high'; Class = 'suspicious'; Confidence = 'high'; Reasons = @('remote_command'); Recommendation = 'Replace the remote with a normal https/ssh URL.'; FpNotes = 'Almost never legitimate.'; Mitre = @($Mitre.hook) } $anchor $ev }
            if ($r.Creds) { Add-Cand "cred|$($r.Key)" @{ Check = 'git.repos'; Title = 'Credential embedded in a git remote URL'; Severity = 'medium'; Class = 'hardening'; Confidence = 'high'; Reasons = @('plaintext_secret'); Recommendation = 'Remove the credential from the URL (git remote set-url) and revoke/rotate the token.'; FpNotes = 'None; value masked in this report.' } $anchor $ev }
            $ipv = $null
            if ($r.Host -and -not (Test-TrustedHost $r.Host)) { Add-Cand "host|$($r.Host)" @{ Check = 'git.repos'; Title = "Git remote on an unexpected host: $($r.Host)"; Severity = $(if ([Net.IPAddress]::TryParse($r.Host, [ref]$ipv)) { 'medium' } else { 'low' }); Class = 'suspicious'; Confidence = 'low'; Reasons = @('unexpected_host'); Recommendation = 'Confirm you know this git server.'; FpNotes = 'Self-hosted Gitea/GitLab or company servers are normal.' } $anchor $ev }
        }
        foreach ($p in @($remotes | Where-Object Kind -eq 'pushurl')) { $f = $remotes | Where-Object { $_.Name -eq $p.Name -and $_.Kind -eq 'url' } | Select-Object -First 1; if ($f -and $f.Host -ne $p.Host) { Add-Cand "push|$($p.Url)" @{ Check = 'git.repos'; Title = "pushurl sends pushes of remote '$($p.Name)' to a different host ($($p.Host))"; Severity = 'medium'; Class = 'suspicious'; Confidence = 'medium'; Reasons = @('remote_rewrite'); Recommendation = 'Check the pushurl; remove it if unknown.'; FpNotes = 'Mirrors or fork workflows can push elsewhere on purpose.' } $anchor @{ type = 'git-remote'; repo = $anchor; url = $f.Url; pushurl = $p.Url } } }
        $hp = (@($cfg | Where-Object { $_.Sec -eq 'core' -and $_.Key -eq 'hookspath' }) | Select-Object -Last 1).Value
        $hdir = if ($hp) { $x = $hp -replace '^~(?=[/\\])', $U; if (-not [IO.Path]::IsPathRooted($x)) { $x = Join-Path $anchor $x }; $x } else { Join-Path $common 'hooks' }
        $hooks = @(Test-HookDir $hdir 'repo' $anchor)
        $wts = @(foreach ($w in @(Get-ChildItem -LiteralPath (Join-Path $common 'worktrees') -Directory -Force -ErrorAction SilentlyContinue)) {
                $gd = "$(Read-Text (Join-Path $w.FullName 'gitdir') 8KB)".Trim()
                $o = [ordered]@{ name = $w.Name; target = $gd; exists = [bool]($gd -and [IO.File]::Exists($gd)); locked = [IO.File]::Exists((Join-Path $w.FullName 'locked')) }
                if (-not $o.exists) { $stale.Add(@{ type = 'git-worktree'; repo = $common; name = $w.Name; target = $gd }) }; $o })
        $origin = @($remotes | Where-Object { $_.Kind -eq 'url' } | Sort-Object { $_.Name -ne 'origin' })[0]
        $Repos.Add([pscustomobject]@{ Common = $common; GroupKey = $(if ($origin) { $origin.Key } else { $common.ToLowerInvariant() }); Owner = $origin.Owner
                Copies = @($grp.Group | ForEach-Object { [ordered]@{ path = $_.Work; kind = $_.Kind; branch = ("$(Read-Text (Join-Path $_.GitDir 'HEAD') 1KB)".Trim() -replace '^ref:\s*refs/heads/', '') } })
                Remotes = @($remotes | ForEach-Object { [ordered]@{ name = $_.Name; kind = $_.Kind; url = $_.Url; host = $_.Host } }); HooksDir = $hdir; Hooks = $hooks; Worktrees = $wts })
    }
    if ($stale.Count) { Add-F @{ Check = 'git.repos'; Title = "$($stale.Count) stale git worktree entr$(if ($stale.Count -eq 1) { 'y' } else { 'ies' }) (target folder gone)"; Severity = 'low'; Class = 'hygiene'; Confidence = 'high'; Reasons = @('stale'); Evidence = @($stale | Select-Object -First 30); Recommendation = 'Run "git worktree prune" in the affected repo when convenient.'; FpNotes = 'Left behind by deleted temp/agent worktrees; harmless.' } }
    $owners = @($Repos | Where-Object Owner | Group-Object GroupKey | ForEach-Object { $_.Group[0].Owner } | Group-Object | Sort-Object Count -Descending)
    $primary = if ($owners) { $owners[0].Name } else { $null }
    $foreign = @($Repos | Where-Object { $_.Owner -and $_.Owner -ne $primary })
    if ($foreign) { Add-F @{ Check = 'git.repos'; Title = "$($foreign.Count) repo(s) cloned from GitHub accounts other than the main one ($primary)"; Severity = 'info'; Class = 'info'; Confidence = 'high'; Reasons = @('third_party_repo'); Evidence = @($foreign | Select-Object -First 30 | ForEach-Object { @{ type = 'git-remote'; repo = $_.Copies[0].path; remote = $_.GroupKey } }); Recommendation = 'Confirm you know each source; open repos from recruiters/strangers only in a sandbox.'; FpNotes = 'Collaborators and upstream forks are normal.' } }
    @($Repos | ForEach-Object Common)
}
#endregion

#region other IDEs
$JB = @(Invoke-BvsCheck -Run $run -Id 'ide.jetbrains' -Description 'JetBrains IDEs: products, third-party plugins, trusted project paths' -Script {
        $prods = @(Get-ChildItem -Path "$env:APPDATA\JetBrains\*", "$env:APPDATA\Google\AndroidStudio*" -Directory -ErrorAction SilentlyContinue | Where-Object Name -match '^[A-Za-z]+\d{4}\.\d+$')
        if (-not $prods) { Set-BvsCheckStatus -Id 'ide.jetbrains' -Status not_applicable -Reason 'no JetBrains IDE configuration found'; return }
        $broad = @($U, [Environment]::GetFolderPath('MyDocuments'), [Environment]::GetFolderPath('Desktop')) | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() }
        foreach ($p in $prods) {
            $plugins = @(foreach ($pd in "$($p.FullName)\plugins", "$env:LOCALAPPDATA\JetBrains\$($p.Name)\plugins") { Get-ChildItem -LiteralPath $pd -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(meta|brokenPlugins\.json|pluginsXMLIds\.json)$|\.etag$' } | ForEach-Object Name })
            $tp = Read-Text "$($p.FullName)\options\trusted-paths.xml" 1MB
            $trusted = @(if ($tp) { [regex]::Matches($tp, '<entry key="([^"]+)" value="true"|<option value="([^"]+)"') | ForEach-Object { ($_.Groups[1].Value + $_.Groups[2].Value) -replace '\$USER_HOME\$', $U } })
            foreach ($t in $trusted) { $n = ($t -replace '/', '\').TrimEnd('\').ToLowerInvariant(); if ($n -in $broad -or $n -match '^[a-z]:$') { Add-F @{ Check = 'ide.jetbrains'; Title = "$($p.Name) trusts every project under $t"; Severity = 'medium'; Class = 'hardening'; Confidence = 'high'; Reasons = @('trust_disabled'); Evidence = @(@{ type = 'file'; path = "$($p.FullName)\options\trusted-paths.xml"; trusted = $t }); Recommendation = 'Remove the broad trusted location (Settings > Build > Trusted Locations).'; FpNotes = 'Convenience setting.' } } }
            [ordered]@{ product = $p.Name; plugins = $plugins; trustedPaths = $trusted }
        }
    })
$OtherIde = @(Invoke-BvsCheck -Run $run -Id 'ide.others' -Description 'Visual Studio instances, Sublime Text, Notepad++, Zed (presence only)' -Script {
        $o = @(foreach ($s in @(Get-ChildItem -Path "$env:ProgramData\Microsoft\VisualStudio\Packages\_Instances\*\state.json" -ErrorAction SilentlyContinue)) { $j = Read-Json $s.FullName; [ordered]@{ ide = 'Visual Studio'; product = (V (V $j 'product') 'id'); version = (V (V $j 'catalogInfo') 'productDisplayVersion'); path = (V $j 'installationPath') } })
        $o += @(foreach ($c in @(@('Sublime Text', "$env:APPDATA\Sublime Text"), @('Notepad++', "$env:APPDATA\Notepad++"), @('Zed', "$env:APPDATA\Zed"))) { if ([IO.Directory]::Exists($c[1])) { [ordered]@{ ide = $c[0]; path = $c[1] } } })
        if (-not $o) { Set-BvsCheckStatus -Id 'ide.others' -Status not_applicable -Reason 'none present' }
        $o
    })
#endregion

#region output
Publish-Cands
Add-BvsInventory -Run $run -Name 'editors' -Data @($Editors | ForEach-Object { [ordered]@{ editor = $_.Name; version = $_.Version; installDir = $_.InstallDir; productJson = $_.ProductJson; controlUrl = $_.ControlUrl; extDir = $_.ExtDir; userDir = $_.UserDir; trustDefault = $_.TrustDefault; autoTasksDefault = $_.AutoTasksDefault; defaultsSource = $_.DefaultsSource; effectiveTrust = $_.EffectiveTrust; effectiveAutoTasks = $_.EffectiveAutoTasks } })
Add-BvsInventory -Run $run -Name 'extensions' -Data @($Ext | ForEach-Object { [ordered]@{ editor = $_.Editor; id = $_.Id; version = $_.Version; source = $_.Source; installed = $_.Installed; publisherDisplayName = $_.PublisherDisplayName; publisherVerified = $_.Verified; marketplace = $_.Marketplace; openVsx = $_.OpenVsx; killList = [bool]$_.KillList; removed = $_.Removed; deprecated = [bool]$_.Deprecated; listed = $_.Listed; obsolete = $_.Obsolete; preRelease = $_.PreRelease; targetPlatform = $_.TargetPlatform; activation = $_.StartupActivation; activationEvents = $_.Activation; dependencies = $_.Dependencies; main = $_.Main; signatureFile = $_.SignatureFile; themeOnly = $_.ThemeOnly; unicodeFlag = [bool]($_.Unicode -and $_.Unicode.maxRun -ge [int]$IOC.unicode.minRun); unicode = $_.Unicode; c2 = $_.C2; expected = $_.Expected.id; path = $_.Folder } })
Add-BvsInventory -Run $run -Name 'editorSettings' -Data @($SettingRows)
Add-BvsInventory -Run $run -Name 'repoAutorun' -Data @($AutoRows)
Add-BvsInventory -Run $run -Name 'gitConfig' -Data @($GitRows)
Add-BvsInventory -Run $run -Name 'repoGroups' -Data @($Repos | Group-Object GroupKey | ForEach-Object { [ordered]@{ remote = $_.Name; copies = @($_.Group | ForEach-Object { $_.Copies }); remotes = @($_.Group[0].Remotes); hooks = @($_.Group | ForEach-Object { $_.Hooks }); worktrees = @($_.Group | ForEach-Object { $_.Worktrees }) } })
Add-BvsInventory -Run $run -Name 'openedFolders' -Data ([ordered]@{ count = $Opened.Count; folders = @($Opened.Keys | Sort-Object | Select-Object -First 200 | ForEach-Object { [ordered]@{ path = $_; editors = @($Opened[$_]) } }) })
Add-BvsInventory -Run $run -Name 'jetbrains' -Data $JB
Add-BvsInventory -Run $run -Name 'otherIdes' -Data $OtherIde
Add-BvsInventory -Run $run -Name 'intel' -Data @($IntelLog)
$sum = Complete-BvsRun -Run $run
"S10 -> $($sum.Path)"
"findings=$($sum.Findings) [$($sum.BySeverity)] checks=$($sum.Checks) errors=$($sum.Errors)"
$run.Checks | Where-Object status -ne 'ok' | ForEach-Object { Protect-BvsText "check $($_.id): $($_.status) $($_.reason)" }
$run.Findings | Select-Object -First 30 | ForEach-Object { Protect-BvsText ('{0} {1}/{2} {3}' -f $_.id, $_.severity, $_.class, $_.title) }
#endregion
