#Requires -Version 7.2
<#
.SYNOPSIS
    S06 Browsers - read-only audit of Chromium-family browsers: extensions (permissions, install source,
    intel match, store status), hijacks, flagged site permissions, launch flags, DevTools listeners,
    native messaging hosts, versions.
.DESCRIPTION
    Vendor-level reference data: S06-browsers-reference.json (next to this script).
    Machine-specific known-good items: config\local\expected.json (Get-BvsExpected).
    Safety: never opens the browser credential/cookie/history/web-data/storage/session files - every open
    goes through Test-BvsNeverRead; browser files are opened read-only with FileShare ReadWrite|Delete.
    Local State is parsed in memory and only profile names, DoH and flags are kept. Network only via
    Invoke-BvsIntel (extension IDs only). Playbook: docs\playbooks\S06-browsers.md
.PARAMETER Offline       No network (cached intel lists are still used).
.PARAMETER NoStoreCheck  Skip store lookups.
#>
[CmdletBinding()]
param([switch]$Offline, [switch]$NoStoreCheck, [int]$IntelMaxAgeHours = 12, [int]$StoreCheckMax = 40)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S06 -Area security
$Ref = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'S06-browsers-reference.json')) | ConvertFrom-Json -Depth 64
$SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
function ConvertTo-S06Map($o) { $h = @{}; if ($o) { foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } }; $h }
$WalletMap = ConvertTo-S06Map $Ref.walletExtensions
$LocNames = ConvertTo-S06Map $Ref.locationNames
$DrNames = ConvertTo-S06Map $Ref.disableReasonNames
$StoreHosts = ConvertTo-S06Map $Ref.storeUpdateHosts
$BrowserExe = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($bd in $Ref.chromiumBrowsers) { foreach ($e in @($bd.exe) + @($bd.proxyExe)) { if ($e) { [void]$BrowserExe.Add($e) } } }
foreach ($e in $Ref.extraBrowserExeNames) { [void]$BrowserExe.Add($e) }
$Ctx = [ordered]@{ Browsers = [Collections.Generic.List[object]]::new(); Ext = [Collections.Generic.List[object]]::new(); Stubs = [Collections.Generic.List[object]]::new()
    Odd = [Collections.Generic.List[object]]::new(); Intel = @{}; IntelSources = [Collections.Generic.List[object]]::new(); StoreFail = @{}; StoreWhy = @{}
    Hygiene = @{}; WalletApps = [Collections.Generic.List[string]]::new(); Notes = [Collections.Generic.List[string]]::new()
    Regs = @(); Pol = @(); Hijack = @(); Sites = $null; Shortcuts = @(); Procs = @(); PT = $null; Listeners = @(); Native = @() }

#region ---------- helpers ----------
function Add-S06Error([string]$Check, [string]$Msg) { $run.Errors.Add([ordered]@{ check = $Check; error = (Protect-BvsText $Msg); at = [datetime]::UtcNow.ToString('o') }) }
function Read-S06Text([string]$Path, [long]$Max = 32MB) {
    if (Test-BvsNeverRead $Path) { throw "never-read path refused: $Path" }
    $info = [IO.FileInfo]::new($Path)
    if (-not $info.Exists -or (Test-BvsCloudOnly $info)) { return $null }
    if ($info.Length -gt $Max) { throw "file too large: $Path" }
    $fs = [IO.FileStream]::new($info.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    try { $sr = [IO.StreamReader]::new($fs, [Text.UTF8Encoding]::new($false), $true); try { $sr.ReadToEnd() } finally { $sr.Dispose() } } finally { $fs.Dispose() }
}
function Read-S06Json([string]$Path, [long]$Max = 32MB) {
    $t = Read-S06Text $Path $Max
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    $t = $t.TrimStart([char]0xFEFF)
    try { $o = ConvertFrom-Json -InputObject $t -AsHashtable -Depth 512 }
    catch { $c = [regex]::Replace($t, '(?m)^\s*//[^\r\n]*', ''); $c = [regex]::Replace($c, ',(\s*[}\]])', '$1'); $o = ConvertFrom-Json -InputObject $c -AsHashtable -Depth 512 }
    , $o
}
function Get-S06Val($Obj, [string]$Path) { $cur = $Obj; foreach ($k in $Path.Split('.')) { if ($cur -isnot [Collections.IDictionary] -or -not $cur.Contains($k)) { return $null }; $cur = $cur[$k] }; , $cur }
function ConvertFrom-S06Time($v) {
    $n = 0L; if ($null -eq $v -or -not [long]::TryParse([string]$v, [ref]$n) -or $n -le 0) { return $null }
    try { if ($n -gt 1e16) { [datetime]::FromFileTimeUtc($n * 10).ToString('o') } elseif ($n -gt 1e11) { [DateTimeOffset]::FromUnixTimeMilliseconds($n).UtcDateTime.ToString('o') } else { $null } } catch { $null }
}
function Test-S06Recent([string]$Iso) { if (-not $Iso) { return $false }; [datetime]::Parse($Iso, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'RoundtripKind').ToUniversalTime() -gt $run.AuditStartUtc.AddDays(-30) }
function ConvertTo-S06Strings($v) { $o = [Collections.Generic.List[string]]::new(); foreach ($x in @($v)) { if ($null -eq $x) { continue }; if ($x -is [Collections.IDictionary]) { foreach ($k in $x.Keys) { $o.Add([string]$k) } } elseif ("$x") { $o.Add([string]$x) } }; $o }
function Get-S06Disable($v) {
    foreach ($x in @($v)) { $n = 0L; if ($null -eq $x -or -not [long]::TryParse([string]$x, [ref]$n)) { continue }
        for ($i = 0; $i -lt 62; $i++) { $bit = [long]1 -shl $i; if ($n -band $bit) { $nm = $DrNames["$bit"]; if ($nm) { $nm } else { "other_$bit" } } } }
}
function Get-S06VerKey([string]$n) { $v = ($n -split '_')[0]; if ($v -notmatch '\.') { $v += '.0' }; $p = $null; if ([version]::TryParse($v, [ref]$p)) { $p } else { [version]'0.0' } }
function Resolve-S06Msg([string]$Text, [string]$Dir, [string]$Loc) {
    if ($Text -notmatch '^__MSG_(.+)__$' -or -not $Dir) { return $Text }
    $key = $Matches[1]; $ld = Join-Path $Dir '_locales'
    if (-not [IO.Directory]::Exists($ld)) { return $Text }
    $cands = @(@($Loc, 'en', 'en_US', 'en_GB') + @([IO.Directory]::GetDirectories($ld) | ForEach-Object { [IO.Path]::GetFileName($_) }) | Where-Object { $_ } | Select-Object -Unique)
    foreach ($l in $cands) {
        try { $msgs = Read-S06Json (Join-Path $ld "$l\messages.json") 4MB } catch { continue }
        if ($msgs -isnot [Collections.IDictionary]) { continue }
        foreach ($k in $msgs.Keys) { if ([string]::Equals($k, $key, [StringComparison]::OrdinalIgnoreCase) -and $msgs[$k] -is [Collections.IDictionary] -and $msgs[$k]['message']) { return [string]$msgs[$k]['message'] } }
    }
    $Text
}
function Test-S06Host([string]$p) { $p -eq '<all_urls>' -or $p -match '^[a-z*][a-z0-9+.*-]*://' }
function Test-S06AllSites([string]$p) { $p -eq '<all_urls>' -or $p -match '^(\*|https?|wss?):\/\/\*\/' }
function Get-S06Tier($Apis, $Hosts, $Cs) {
    $Apis = @($Apis | Where-Object { $_ }); $Hosts = @($Hosts | Where-Object { $_ }); $Cs = @($Cs | Where-Object { $_ })
    $all = @($Hosts | Where-Object { Test-S06AllSites $_ }).Count -gt 0; $csAll = @($Cs | Where-Object { Test-S06AllSites $_ }).Count -gt 0
    $top = @($Ref.permissions.topTierWithAllSites | Where-Object { $Apis -contains $_ }); $high = @($Ref.permissions.highTier | Where-Object { $Apis -contains $_ })
    $med = @($Ref.permissions.mediumTier | Where-Object { $Apis -contains $_ })
    $tier = if (($all -and $top.Count) -or $csAll) { 'top' } elseif ($all -or $high.Count) { 'high' } elseif ($Hosts.Count -or $Cs.Count -or $med.Count) { 'medium' } else { 'low' }
    $sens = @(@($top) + @($high) | Select-Object -Unique)
    $sum = @(); if ($all) { $sum += 'ALL SITES' } elseif ($Hosts.Count) { $sum += "hosts:$($Hosts.Count)" }
    if ($csAll) { $sum += 'content scripts on all sites' } elseif ($Cs.Count) { $sum += "content-script patterns:$($Cs.Count)" }
    if ($sens.Count) { $sum += 'sensitive: ' + ($sens -join ',') }
    [pscustomobject]@{ Tier = $tier; AllSites = $all; CsAll = $csAll; Sensitive = $sens; Summary = ($sum -join '; ') }
}
function Get-S06Store([string]$UpdHost, $Loc, $FromWs) {
    if ($null -ne $Loc -and @($Ref.componentLocations) -contains [int]$Loc) { return 'component' }
    if ($Loc -eq 4) { return 'unpacked' }; if ($Loc -eq 8) { return 'command-line' }
    if ($UpdHost) { foreach ($k in $StoreHosts.Keys) { if (@($StoreHosts[$k]) -contains $UpdHost) { return $k } }; return 'self-hosted' }
    if ($FromWs) { 'chrome-web-store' } else { 'none' }
}
function Get-S06Url([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $u = ($Url.Trim() -replace '\{google:baseURL\}', 'https://www.google.com/') -replace '\{[^}]*\}', 'x'
    $p = $null
    if (-not [uri]::TryCreate($u, [UriKind]::Absolute, [ref]$p) -and -not [uri]::TryCreate("https://$u", [UriKind]::Absolute, [ref]$p)) { return [pscustomobject]@{ host = $null; display = (Protect-BvsUrl $Url) } }
    [pscustomobject]@{ host = $p.Host.ToLowerInvariant(); display = "$($p.Scheme)://$($p.Host)$($p.AbsolutePath)" }
}
function Test-S06KnownSearch([string]$h) {
    if (-not $h) { return $false }
    foreach ($k in $Ref.knownSearchHosts) { if ($k.EndsWith('.')) { if ($h -match ('(^|\.)' + [regex]::Escape($k) + '[a-z]{2,3}(\.[a-z]{2})?$')) { return $true } } elseif ($h -eq $k -or $h.EndsWith(".$k")) { return $true } }
    $false
}
function Get-S06Entropy([string]$s) { $c = @{}; foreach ($ch in $s.ToCharArray()) { $c[[string]$ch] = 1 + [int]$c[[string]$ch] }; $e = 0.0; foreach ($v in $c.Values) { $q = $v / $s.Length; $e -= $q * [Math]::Log($q, 2) }; $e }
function Test-S06Random([string]$l) {
    $l = $l.ToLowerInvariant(); if ($l.Length -lt 8 -or $l.StartsWith('xn--')) { return $false }
    $let = ($l -replace '[^a-z]', '').Length; $dig = ($l -replace '[^0-9]', '').Length; $vow = ($l -replace '[^aeiouy]', '').Length
    ($dig -ge 3 -and $let -ge 3 -and $l -notmatch '^[a-z-]+\d{2,4}$') -or ($let -ge 8 -and $vow / [double]$let -lt 0.15) -or ($l.Length -ge 12 -and (Get-S06Entropy $l) -ge 3.6)
}
function Get-S06SiteFlags([string]$h) {
    if (-not $h) { return }
    $h = $h.ToLowerInvariant().Trim('[', ']').TrimEnd('.')
    if ($h -match '^\d{1,3}(\.\d{1,3}){3}$' -or $h -match ':') { 'raw_ip'; return }
    if ($h -match $Ref.suspiciousSiteWordsRegex) { 'lure_word' }
    foreach ($t in $Ref.suspiciousTlds) { if ($h.EndsWith($t)) { "tld$t"; break } }
    $lab = $h.Split('.')
    if ($lab.Count -ge 2 -and ((Test-S06Random $lab[0]) -or ($lab.Count -ge 3 -and (Test-S06Random $lab[$lab.Count - 2])))) { 'random_label' }
}
function Get-S06PathTags([string]$Path) {
    if (-not $Path) { return }
    $low = $Path.ToLowerInvariant(); $tmp = [IO.Path]::GetTempPath().TrimEnd('\').ToLowerInvariant(); $t = @()
    if ($low.StartsWith($tmp) -or $low -match '\\(temp|tmp)\\') { $t += 'temp' }
    foreach ($pair in @(@($env:APPDATA, 'appdata'), @($env:LOCALAPPDATA, 'appdata'), @($env:ProgramData, 'programdata'), @($env:PUBLIC, 'public'))) { if ($pair[0] -and $low.StartsWith($pair[0].ToLowerInvariant())) { $t += $pair[1] } }
    if ($low -match '\\downloads\\') { $t += 'downloads' }
    $t | Select-Object -Unique
}
function Split-S06Args([string]$s) {
    $tok = [Collections.Generic.List[string]]::new(); $sb = [Text.StringBuilder]::new(); $q = $false
    foreach ($ch in ([string]$s).ToCharArray()) { if ($ch -eq '"') { $q = -not $q; continue }; if ([char]::IsWhiteSpace($ch) -and -not $q) { if ($sb.Length) { $tok.Add($sb.ToString()); [void]$sb.Clear() }; continue }; [void]$sb.Append($ch) }
    if ($sb.Length) { $tok.Add($sb.ToString()) }; $tok
}
function Get-S06Launch([string]$ArgText, [bool]$WebView) {
    $sw = [Collections.Generic.List[object]]::new(); $pos = [Collections.Generic.List[string]]::new(); $toks = @(Split-S06Args $ArgText)
    for ($i = 0; $i -lt $toks.Count; $i++) {
        $t = $toks[$i]
        if ($t -eq '--') { foreach ($r in @($toks | Select-Object -Skip ($i + 1))) { $pos.Add($r) }; break }
        if ($t -match '^(?:--|-|/)([A-Za-z0-9][A-Za-z0-9-]*)(?:=(.*))?$') {
            $n = $Matches[1].ToLowerInvariant(); $val = $Matches[2]
            if ($n -eq 'single-argument') { $pos.Add((@($toks | Select-Object -Skip ($i + 1)) -join ' ')); break }
            $sw.Add([pscustomobject]@{ name = $n; value = $val })
        } else { $pos.Add($t) }
    }
    $hits = [Collections.Generic.List[object]]::new()
    foreach ($r in $Ref.launchFlagRules) {
        if ($WebView -and -not $r.webview) { continue }
        foreach ($s in $sw) {
            if ($s.name -ne $r.switch) { continue }
            $val = [string]$s.value
            if ($r.condition -eq 'temp' -and @(Get-S06PathTags ($val.Trim('"'))) -notcontains 'temp') { continue }
            if ($r.valueRegex -and $val -notmatch $r.valueRegex) { continue }
            $hits.Add([pscustomobject]@{ switch = $s.name; severity = $r.severity; class = $r.class; reason = $r.reason; label = $r.label; mitre = @($r.mitre) })
        }
    }
    $known = @($Ref.benignSwitches) + @($Ref.launchFlagRules | ForEach-Object { $_.switch }) + @('app')
    [pscustomobject]@{ Switches = @($sw | ForEach-Object { $_.name }); Hits = $hits.ToArray(); Values = $sw.ToArray()
        Urls = @($pos | Where-Object { $_ -match '^(?i)(https?|ftp)://|^www\.' }); Unknown = @($sw | Where-Object { $known -notcontains $_.name } | ForEach-Object { $_.name }) }
}
function Format-S06Name([string]$n) { (($n -replace '[®™©]', '') -replace '\s+', ' ').Trim().ToLowerInvariant() }
function Get-S06Expected($x) {
    $res = $null; $norm = Format-S06Name $x.name
    foreach ($it in @(Get-BvsExpected -Category 'browserExtension')) {
        if (-not @($it.match.names | Where-Object { (Format-S06Name $_) -eq $norm }).Count) { continue }
        $cancel = @(foreach ($c in @($it.invalidIf)) {
                if ($c -match '(?i)official store' -and $x.store -notin 'chrome-web-store', 'edge-add-ons') { $c }
                elseif ($c -match '(?i)unexpected permission') { $bad = @($x.effectiveApis | Where-Object { @($Ref.permissions.unexpectedForExpected) -contains $_ }); if ($bad.Count) { "$c ($($bad -join ','))" } } })
        $res = [ordered]@{ id = $it.id; reason = $it.reason; severityCap = $(if ($it.severityCap) { $it.severityCap } else { 'info' }); class = $it.class; cancelled = ($cancel.Count -gt 0); cancelledBy = $cancel; hygiene = $false }
    }
    foreach ($it in @(Get-BvsExpected -Category 'program')) {
        if ($it.class -eq 'hygiene' -and $it.match.displayNameRegex -and (($x.name -replace '[®™©]', '') -match $it.match.displayNameRegex)) {
            if (-not $res) { $res = [ordered]@{ id = $it.id; reason = $it.reason; severityCap = $it.severityCap; class = 'hygiene'; cancelled = $false; cancelledBy = @(); hygiene = $true } }
            else { $res.hygiene = $true; $res.hygieneReason = $it.reason; if ($it.severityCap) { $res.severityCap = $it.severityCap } }
        }
    }
    $res
}
function Limit-S06Sev([string]$s, [string]$cap) { if ($cap -and $SevRank[$s] -gt $SevRank[$cap]) { $cap } else { $s } }
function Step-S06Down([string]$s) { @{ critical = 'high'; high = 'medium'; medium = 'low'; low = 'low'; info = 'info' }[$s] }
function Add-S06Finding {
    param([string]$Check, [string]$Title, [string]$Severity, [string]$Class, [string]$Confidence = 'medium', [string[]]$Reasons = @(), [object[]]$Evidence = @(),
        [hashtable]$Entities = @{}, [string]$Rec = '', [string]$Fp = '', [string[]]$Mitre = @(), $Expected = $null)
    New-BvsFinding -Run $run -Check $Check -Title $Title -Severity $Severity -Class $Class -Confidence $Confidence -Reasons $Reasons -Evidence $Evidence -Entities $Entities -Recommendation $Rec -FpNotes $Fp -Mitre $Mitre -Expected $Expected -PassThru
}
function New-S06ExtEv($x, [string]$Detail) { [ordered]@{ type = 'browser_extension'; browser = $x.browserLabel; profile = $x.profile; id = $x.id; name = $x.name; version = $x.version; enabled = $x.enabled; location = $x.locationName; store = $x.store; path = $x.prefsFile; value = $Detail } }
function Get-S06ExtEntity($xs) { @{ extensions = @($xs | ForEach-Object { [ordered]@{ browser = $_.browser; profile = $_.profile; id = $_.id; name = $_.name; version = $_.version; enabled = $_.enabled } }); files = @(); processes = @(); network = @(); registry = @(); accounts = @() } }
function Get-S06Bg($bg) {
    if ($bg -isnot [Collections.IDictionary]) { return 'none' }
    $s = if ($bg['service_worker']) { 'service_worker' } elseif ($bg['scripts']) { "scripts($(@($bg['scripts']).Count))" } elseif ($bg['page']) { 'page' } else { 'none' }
    if ($bg['persistent'] -eq $true) { $s += ',persistent' }; $s
}
function Format-S06Pref([string]$Name, $v) {
    if ($v -is [string]) { if ($v -match '^[a-z][a-z0-9+.-]*://') { return (Protect-BvsUrl $v) }; $s = Protect-BvsText $v; return $s.Substring(0, [Math]::Min(200, $s.Length)) }
    if ($v -is [Collections.IDictionary]) {
        if ($Name -eq 'proxy') { return [ordered]@{ mode = $v['mode']; server = $(if ($v['server']) { Protect-BvsUrl ([string]$v['server']) }); pac = $(if ($v['pac_url']) { Protect-BvsUrl ([string]$v['pac_url']) }) } }
        return '{' + (@($v.Keys) -join ',') + '}'
    }
    if ($v -is [Collections.IList]) { return "[list:$(@($v).Count)]" }
    $v
}
function Test-S06PrefIn([string]$Name, $List) { foreach ($p in @($List)) { if ($p.EndsWith('.')) { if ($Name.StartsWith($p)) { return $true } } elseif ($Name -eq $p -or $Name.StartsWith("$p.")) { return $true } }; $false }
function Get-S06Cached([string]$HostName, [string]$Save, [double]$MaxH) {
    $dp = Join-Path (Get-BvsRoot) ('intel\' + ($HostName -replace '[^A-Za-z0-9.-]', '_'))
    if (-not [IO.Directory]::Exists($dp)) { return $null }
    foreach ($c in @([IO.Directory]::GetFiles($dp) | Where-Object { $_.EndsWith("-$Save", [StringComparison]::OrdinalIgnoreCase) } | Sort-Object -Descending)) {
        try { $meta = Read-S06Json "$c.meta.json" 1MB } catch { continue }
        if (-not $meta -or [int]$meta['status'] -ne 200) { continue }
        $fa = $meta['fetchedAtUtc']
        $f = if ($fa -is [datetime]) { $fa.ToUniversalTime() } else { [datetime]::Parse([string]$fa, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'RoundtripKind').ToUniversalTime() }
        if (([datetime]::UtcNow - $f).TotalHours -gt $MaxH) { return $null }
        return [pscustomobject]@{ Text = (Read-S06Text $c 64MB); At = $f.ToString('o') }
    }
    $null
}
function Test-S06Store([string]$Store, [string]$Id) {
    $r = [ordered]@{ store = $Store; status = 'unknown'; detail = $null }
    if ([int]$Ctx.StoreFail[$Store] -ge 2) { $r.detail = 'skipped after repeated failures on this host'; return [pscustomobject]$r }
    $uri = if ($Store -eq 'edge-add-ons') { "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/$Id" } else { "https://chromewebstore.google.com/detail/$Id" }
    try {
        $resp = Invoke-BvsIntel -Uri $uri -NoSave -TimeoutSec 20 -Headers @{ 'Accept-Language' = 'en-US,en;q=0.8' }
        $Ctx.StoreFail[$Store] = 0; $body = [string]$resp.Content
        if ($resp.Status -in 204, 404, 410) { $r.status = 'not_listed'; $r.detail = "HTTP $($resp.Status)" }
        elseif ($resp.Status -eq 200 -and $body -match $Id -and $body -notmatch '(?i)this item is not available') { $r.status = 'listed'; $r.detail = 'page references the ID' }
        elseif ($resp.Status -eq 200) { $r.status = 'not_listed'; $r.detail = 'HTTP 200 without the ID (soft-404)' }
        else { $r.detail = "HTTP $($resp.Status)" }
    }
    catch {
        $Ctx.StoreFail[$Store] = 1 + [int]$Ctx.StoreFail[$Store]
        $msg = if ($_.Exception -is [InvalidOperationException]) { "redirect not followable by Invoke-BvsIntel (pwsh $($PSVersionTable.PSVersion))" } else { $_.Exception.Message }
        $Ctx.StoreWhy[$Store] = $msg; $r.detail = $msg
    }
    [pscustomobject]$r
}
function Get-S06RegTree([string]$Path, [string]$View, [int]$Depth, $Out) {
    foreach ($rv in @(Get-BvsRegValues -Path $Path -View $View)) { $Out.Add([pscustomobject]@{ key = $Path; name = $rv.Name; value = (Protect-BvsText ([string]($rv.Value -join ';'))) }) }
    if ($Depth -lt 3) { foreach ($s in @(Get-BvsRegSubKeys -Path $Path -View $View)) { Get-S06RegTree "$Path\$s" $View ($Depth + 1) $Out } }
}
function Get-S06ScriptExe([string]$Path) {
    $t = Read-S06Text $Path 256KB; if (-not $t) { return }
    $d = (Split-Path -Parent $Path).TrimEnd('\') + '\'
    foreach ($m in [regex]::Matches($t, '(?i)((?:[a-z]:\\|%~dp0|%[a-z_]+%\\)[^"\r\n<>|*?]*?\.exe)')) { [Environment]::ExpandEnvironmentVariables(($m.Groups[1].Value -replace '(?i)%~dp0', $d)) }
}
#endregion

#region ---------- per-profile extension import ----------
function Import-S06Profile($b, $pr) {
    $merged = @{}
    $srcs = [ordered]@{ 'Preferences' = (Get-S06Val $pr.P 'extensions.settings'); 'Secure Preferences' = (Get-S06Val $pr.S 'extensions.settings') }
    foreach ($sn in $srcs.Keys) {
        $dict = $srcs[$sn]; if ($dict -isnot [Collections.IDictionary]) { continue }
        foreach ($id in @($dict.Keys)) {
            $e = $dict[$id]; if ($e -isnot [Collections.IDictionary]) { continue }
            if (-not $merged.ContainsKey($id)) { $merged[$id] = [pscustomobject]@{ E = [ordered]@{}; Src = [Collections.Generic.List[string]]::new() } }
            foreach ($k in @($e.Keys)) { $merged[$id].E[$k] = $e[$k] }; $merged[$id].Src.Add($sn)
        }
    }
    $extRoot = Join-Path $pr.path 'Extensions'; $folders = @{}
    if ([IO.Directory]::Exists($extRoot)) {
        foreach ($d in [IO.Directory]::GetDirectories($extRoot)) { $n = [IO.Path]::GetFileName($d); if ($n -cmatch '^[a-p]{32}$') { $folders[$n] = $d } elseif ($n -ne 'Temp') { $Ctx.Odd.Add([pscustomobject]@{ browser = $b.id; profile = $pr.folder; folder = $n; path = $d }) } }
    }
    foreach ($id in @(@($merged.Keys) + @($folders.Keys) | Sort-Object -Unique)) {
        $m = $merged[$id]; $e = if ($m) { $m.E } else { $null }; $folder = $folders[$id]
        $dr = @(if ($e) { Get-S06Disable $e['disable_reasons'] })
        if ($e -and -not $e.Contains('location') -and -not $e.Contains('manifest') -and -not $folder) { $Ctx.Stubs.Add([pscustomobject]@{ browser = $b.id; profile = $pr.folder; id = $id; disableReasons = $dr }); continue }
        $pp = if ($e) { [string]$e['path'] } else { '' }; $vd = $null; $pk = 'none'
        if ($pp) { if ([IO.Path]::IsPathRooted($pp)) { $vd = $pp; $pk = 'absolute' } else { $vd = Join-Path $extRoot $pp; $pk = 'relative' } }
        if ((-not $vd -or -not [IO.Directory]::Exists($vd)) -and $folder) { $v = @([IO.Directory]::GetDirectories($folder) | Sort-Object { Get-S06VerKey ([IO.Path]::GetFileName($_)) } -Descending); if ($v.Count) { $vd = $v[0]; if ($pk -eq 'none') { $pk = 'folder' } } }
        $dx = [bool]($vd -and [IO.Directory]::Exists($vd)); $man = $null; $msrc = 'none'
        if ($dx) { try { $man = Read-S06Json (Join-Path $vd 'manifest.json') 4MB; if ($man) { $msrc = 'disk' } } catch { Add-S06Error 'browser.extensions.inventory' "manifest $id : $($_.Exception.Message)" } }
        if (-not $man -and $e -and $e['manifest'] -is [Collections.IDictionary]) { $man = $e['manifest']; $msrc = 'prefs' }
        if ($man -isnot [Collections.IDictionary]) { $man = @{} }
        $loc0 = [string]$man['default_locale']; $vdx = if ($dx) { $vd } else { $null }
        $name = Resolve-S06Msg ([string]$man['name']) $vdx $loc0; if (-not $name) { $name = "(unknown $id)" }
        $perm = @(ConvertTo-S06Strings $man['permissions'])
        $apis = @($perm | Where-Object { -not (Test-S06Host $_) })
        $hosts = @(@($perm | Where-Object { Test-S06Host $_ }) + @(ConvertTo-S06Strings $man['host_permissions']) | Select-Object -Unique)
        $cs = @(foreach ($c in @($man['content_scripts'])) { if ($c -is [Collections.IDictionary]) { ConvertTo-S06Strings $c['matches'] } }) | Select-Object -Unique
        $gA = [Collections.Generic.List[string]]::new(); $gH = [Collections.Generic.List[string]]::new()
        if ($e) {
            foreach ($gk in 'granted_permissions', 'active_permissions', 'runtime_granted_permissions') {
                $g = $e[$gk]; if ($g -isnot [Collections.IDictionary]) { continue }
                foreach ($a in @(ConvertTo-S06Strings $g['api']) + @(ConvertTo-S06Strings $g['manifest_permissions'])) { $gA.Add($a) }
                foreach ($h in @(ConvertTo-S06Strings $g['explicit_host']) + @(ConvertTo-S06Strings $g['scriptable_host'])) { $gH.Add($h) }
            }
        }
        $effA = @(@($apis) + @($gA) | Select-Object -Unique); $effH = @(@($hosts) + @($gH) | Select-Object -Unique)
        $loc = if ($e -and $e.Contains('location')) { [int]$e['location'] } else { $null }
        $upd = [string]$man['update_url']; $uh = $null; if ($upd) { try { $uh = ([uri]$upd).Host.ToLowerInvariant() } catch { $uh = '(unparsable)' } }
        $store = Get-S06Store $uh $loc ([bool]($e -and $e['from_webstore']))
        $state = if ($e) { $e['state'] } else { $null }
        $blk = $null; if ($e) { foreach ($bk in 'blacklist_state', 'blocklist_state') { if ($e.Contains($bk) -and [int]$e[$bk] -gt 0) { $blk = "$bk=$($e[$bk])" } } }
        $enabled = [bool]($e -and $dr.Count -eq 0 -and ($null -eq $state -or [int]$state -eq 1) -and -not $blk)
        $ci = if ($e) { $e['cws-info'] } else { $null }; $cws = $null
        if ($ci -is [Collections.IDictionary]) { $cws = [ordered]@{ isPresent = $ci['is-present']; isLive = $ci['is-live']; violation = @('none', 'malware', 'policy', 'minor_policy', 'unknown')[[Math]::Min(4, [Math]::Max(0, [int]$ci['violation-type']))]; unpublishedLongAgo = $ci['unpublished-long-ago']; lastUpdated = (ConvertFrom-S06Time $ci['last-updated-time-millis']) } }
        $ctrl = @(if ($e) { foreach ($pk2 in 'preferences', 'incognito_preferences', 'regular_only_preferences') { $d = $e[$pk2]; if ($d -is [Collections.IDictionary]) { foreach ($k in $d.Keys) { [pscustomobject]@{ scope = $pk2; pref = [string]$k; value = (Format-S06Pref $k $d[$k]) } } } } })
        $ovr = [Collections.Generic.List[string]]::new(); $so = $man['chrome_settings_overrides']
        if ($man['chrome_url_overrides'] -is [Collections.IDictionary]) { foreach ($k in $man['chrome_url_overrides'].Keys) { $ovr.Add("url_override:$k") } }
        if ($so -is [Collections.IDictionary]) {
            if ($so['search_provider'] -is [Collections.IDictionary]) { $ovr.Add("search_provider:$((Get-S06Url (Resolve-S06Msg ([string]$so['search_provider']['search_url']) $vdx $loc0)).host)") }
            if ($so['homepage']) { $ovr.Add("homepage:$((Get-S06Url (Resolve-S06Msg ([string]$so['homepage']) $vdx $loc0)).host)") }
            if ($so['startup_pages']) { $ovr.Add('startup_pages:' + ((@(ConvertTo-S06Strings $so['startup_pages']) | ForEach-Object { (Get-S06Url $_).host }) -join ',')) }
        }
        $tier = Get-S06Tier $effA $effH $cs
        $fit = if ($e) { ConvertFrom-S06Time $(if ($e['first_install_time']) { $e['first_install_time'] } else { $e['install_time'] }) } else { $null }
        $x = [pscustomobject][ordered]@{
            browser = $b.id; browserLabel = $b.label; profile = $pr.folder; id = $id; name = $name; version = [string]$man['version']; manifestVersion = $man['manifest_version']
            location = $loc; locationName = $(if ($null -ne $loc) { if ($LocNames["$loc"]) { $LocNames["$loc"] } else { "location_$loc" } } else { 'unregistered_folder' })
            enabled = $enabled; disableReasons = $dr; fromWebstore = $(if ($e) { $e['from_webstore'] }); store = $store; updateHost = $uh
            installTime = $fit; lastUpdateTime = $(if ($e) { ConvertFrom-S06Time $e['last_update_time'] }); byDefault = $(if ($e) { $e['was_installed_by_default'] }); byOem = $(if ($e) { $e['was_installed_by_oem'] })
            isComponent = ($store -eq 'component'); orphanFolder = (-not $e -and [bool]$folder); prefsEntry = $(if ($m) { $m.Src -join '+' } else { 'none' })
            prefsFile = $(if ($m) { Join-Path $pr.path $m.Src[$m.Src.Count - 1] } else { $folder }); pathKind = $pk; path = $(if ($pk -in 'absolute', 'folder') { $vd } else { $pp })
            pathTags = @(if ($pk -eq 'absolute' -and $store -ne 'component') { Get-S06PathTags $vd }); manifestSource = $msrc
            permissions = $apis; hostPermissions = $hosts; optionalPermissions = @(ConvertTo-S06Strings $man['optional_permissions']) + @(ConvertTo-S06Strings $man['optional_host_permissions'])
            contentScriptMatches = @($cs); background = (Get-S06Bg $man['background']); grantedHosts = @($gH | Select-Object -Unique); effectiveApis = $effA
            overrides = $ovr.ToArray(); controlledPrefs = $ctrl; riskTier = $tier.Tier; permissionsSummary = $tier.Summary
            cwsInfo = $cws; blocklist = $blk; storeStatus = $(if ($store -in 'chrome-web-store', 'edge-add-ons') { 'unchecked' } else { 'not_applicable' }); storeDetail = $null
            intel = $null; wallet = $WalletMap[$id]; expected = $null; devMode = $pr.devMode; recent = (Test-S06Recent $fit)
        }
        $x.expected = Get-S06Expected $x
        $Ctx.Ext.Add($x)
    }
}
#endregion

#region ---------- checks ----------
$null = Invoke-BvsCheck -Run $run -Id 'browser.discovery' -Description 'Chromium-family browsers and profiles (Local State profile.info_cache + profile folders), exe version and signature' -Script {
    foreach ($def in $Ref.chromiumBrowsers) {
        $ud = [Environment]::ExpandEnvironmentVariables($def.userData)
        if (-not [IO.Directory]::Exists($ud)) { continue }
        $b = [ordered]@{ id = $def.id; label = $def.label; userDataDir = $ud; profiles = [Collections.Generic.List[object]]::new(); doh = $null; labs = @(); exe = $null; version = $null; signer = $null; sigStatus = $null }
        $names = @{}; $folders = [Collections.Generic.List[string]]::new()
        if ($def.singleProfile) { if ([IO.File]::Exists((Join-Path $ud 'Preferences'))) { $folders.Add('.') } }
        else {
            $ls = $null; try { $ls = Read-S06Json (Join-Path $ud 'Local State') } catch { Add-S06Error 'browser.discovery' "$($def.id) Local State: $($_.Exception.Message)" }
            $ic = Get-S06Val $ls 'profile.info_cache'
            if ($ic -is [Collections.IDictionary]) { foreach ($k in $ic.Keys) { $names[$k] = $(if ($ic[$k] -is [Collections.IDictionary]) { [string]$ic[$k]['name'] }); $folders.Add($k) } }
            foreach ($d in [IO.Directory]::GetDirectories($ud)) { $n = [IO.Path]::GetFileName($d); if ([IO.File]::Exists((Join-Path $d 'Preferences')) -and -not $folders.Contains($n)) { $folders.Add($n) } }
            $b.doh = [ordered]@{ mode = (Get-S06Val $ls 'dns_over_https.mode'); templates = (Get-S06Val $ls 'dns_over_https.templates') }
            $b.labs = @(ConvertTo-S06Strings (Get-S06Val $ls 'browser.enabled_labs_experiments')); $ls = $null
        }
        foreach ($f in $folders) {
            $pth = if ($f -eq '.') { $ud } else { Join-Path $ud $f }
            if ([IO.Directory]::Exists($pth)) { $b.profiles.Add([ordered]@{ folder = $f; path = $pth; displayName = $names[$f]; inInfoCache = $names.ContainsKey($f); kind = $(if ($f -match '^(System|Guest) Profile$') { 'system' } else { 'user' }); P = $null; S = $null; devMode = $false }) }
        }
        foreach ($idir in @($def.installDirs)) { foreach ($xe in @($def.exe)) { $c = Join-Path ([Environment]::ExpandEnvironmentVariables($idir)) $xe; if (-not $b.exe -and [IO.File]::Exists($c)) { $b.exe = $c } } }
        if ($b.exe) { $b.version = (Get-BvsVersionInfo $b.exe).FileVersion; $sig = Get-BvsSignature $b.exe; $b.signer = $sig.Signer; $b.sigStatus = $sig.Status }
        $Ctx.Browsers.Add($b)
    }
    if (-not $Ctx.Browsers.Count) { Set-BvsCheckStatus -Id 'browser.discovery' -Status not_applicable -Reason 'no Chromium-family browser data found' }
    $v = @($Ctx.Browsers | Where-Object { $_.exe } | ForEach-Object { "$($_.label) $($_.version) ($($_.sigStatus), $($_.signer)); profiles: $(@($_.profiles | Where-Object { $_.kind -eq 'user' }).Count)" })
    if ($v.Count) { $null = Add-S06Finding -Check 'browser.discovery' -Title "Installed browsers: $($v -join ' | ')" -Severity info -Class info -Confidence high -Evidence @($Ctx.Browsers | Where-Object { $_.exe } | ForEach-Object { [ordered]@{ type = 'file'; path = $_.exe; name = $_.label; value = "$($_.version) $($_.sigStatus) $($_.signer)" } }) -Rec 'Keep browsers on automatic updates.' -Fp 'Context only.' }
    foreach ($b in @($Ctx.Browsers | Where-Object { $_.exe -and $_.sigStatus -ne 'Valid' })) { $null = Add-S06Finding -Check 'browser.discovery' -Title "$($b.label) executable signature is $($b.sigStatus)" -Severity high -Class suspicious -Reasons @('invalid_signature') -Evidence @([ordered]@{ type = 'file'; path = $b.exe; value = "$($b.sigStatus) $($b.signer)" }) -Rec 'Reinstall the browser from the vendor site and scan the machine.' -Fp 'An update in progress can briefly leave files unverifiable.' -Mitre @('T1036') }
    $Ctx.Browsers
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.inventory' -Description 'Extensions\<id>\<version>\manifest.json + Preferences/Secure Preferences extensions.settings (location, source, state, permissions)' -Script {
    $bad = [Collections.Generic.List[string]]::new()
    foreach ($b in $Ctx.Browsers) {
        foreach ($pr in $b.profiles) {
            try { $pr.P = Read-S06Json (Join-Path $pr.path 'Preferences'); $pr.S = Read-S06Json (Join-Path $pr.path 'Secure Preferences') } catch { $bad.Add("$($b.id)/$($pr.folder): $($_.Exception.Message)"); continue }
            $pr.devMode = [bool]((Get-S06Val $pr.S 'extensions.ui.developer_mode') -or (Get-S06Val $pr.P 'extensions.ui.developer_mode'))
            try { Import-S06Profile $b $pr } catch { $bad.Add("$($b.id)/$($pr.folder): $($_.Exception.Message) @ $($_.InvocationInfo.ScriptLineNumber)") }
        }
    }
    if ($bad.Count) { Set-BvsCheckStatus -Id 'browser.extensions.inventory' -Status partial -Reason ($bad -join '; ') }
    $Ctx.Ext
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.intel.sources' -Description 'Public known-malicious extension ID lists via Invoke-BvsIntel (cached in intel\)' -Script {
    $probs = [Collections.Generic.List[string]]::new()
    foreach ($src in $Ref.intelSources) {
        $r = [ordered]@{ name = $src.name; url = $src.url; status = $null; fetchedAtUtc = $null; ids = 0; newestEntry = $null; stale = $null; note = $src.note }
        $u = [uri]$src.url
        try { Assert-BvsIntelHost -Uri $u } catch { $r.status = 'blocked_by_allowlist'; $probs.Add("$($src.name): $($u.Host) not in config\intel-hosts.json"); $Ctx.IntelSources.Add($r); continue }
        $text = $null; $cache = Get-S06Cached $u.Host $src.saveName $(if ($Offline) { 1e6 } else { $IntelMaxAgeHours })
        if ($cache) { $text = $cache.Text; $r.status = 'cached'; $r.fetchedAtUtc = $cache.At }
        elseif ($Offline) { $r.status = 'offline_no_cache'; $probs.Add("$($src.name): offline, no cache"); $Ctx.IntelSources.Add($r); continue }
        else {
            try { $resp = Invoke-BvsIntel -Uri $src.url -SaveName $src.saveName -TimeoutSec 90; if ($resp.Status -ne 200) { throw "HTTP $($resp.Status)" }; $text = [string]$resp.Content; $r.status = 'fetched'; $r.fetchedAtUtc = [datetime]::UtcNow.ToString('o') }
            catch { $r.status = 'error'; $probs.Add("$($src.name): $($_.Exception.Message)"); $Ctx.IntelSources.Add($r); continue }
        }
        $text = $text.TrimStart([char]0xFEFF)
        if ($src.format -eq 'csv-detailed') {
            foreach ($row in ($text -split "`r?`n" | ConvertFrom-Csv)) {
                $id = [string]$row.extension_id; if ($id -notmatch '^[a-p]{32}$') { continue }
                if (-not $Ctx.Intel.ContainsKey($id)) { $Ctx.Intel[$id] = [Collections.Generic.List[object]]::new() }
                $Ctx.Intel[$id].Add([pscustomobject]@{ list = $src.name; name = $row.name; reason = $row.reason; origin = $row.source; date = $row.insert_date_fmt })
                $r.ids++; if ([string]$row.insert_date_fmt -gt [string]$r.newestEntry) { $r.newestEntry = [string]$row.insert_date_fmt }
            }
        }
        else {
            $sec = $null
            foreach ($line in $text -split "`r?`n") {
                $t = $line.Trim(); if ($t.StartsWith('#')) { $sec = $t.TrimStart('#').Trim(); continue }
                foreach ($mm in [regex]::Matches($t, '\b[a-p]{32}\b')) { if (-not $Ctx.Intel.ContainsKey($mm.Value)) { $Ctx.Intel[$mm.Value] = [Collections.Generic.List[object]]::new() }; $Ctx.Intel[$mm.Value].Add([pscustomobject]@{ list = $src.name; name = $t; reason = 'listed'; origin = $sec; date = $null }); $r.ids++ }
            }
        }
        if ($r.newestEntry -match '^\d{4}-\d{2}-\d{2}$') { $r.stale = ([datetime]::UtcNow - [datetime]::ParseExact($r.newestEntry, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).TotalDays -gt [int]$Ref.intelStaleDays }
        $Ctx.IntelSources.Add($r)
    }
    if (-not $Ctx.Intel.Count) { Set-BvsCheckStatus -Id 'browser.intel.sources' -Status error -Reason ('no intel list available: ' + ($probs -join '; ')) }
    elseif ($probs.Count) { Set-BvsCheckStatus -Id 'browser.intel.sources' -Status partial -Reason ($probs -join '; ') }
    $Ctx.IntelSources
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.intel' -Description 'Exact extension ID match against the intel lists (installed, settings stubs)' -Script {
    if (-not $Ctx.Intel.Count) { Set-BvsCheckStatus -Id 'browser.extensions.intel' -Status skipped -Reason 'no intel list loaded'; return }
    $hits = @($Ctx.Ext | Where-Object { $Ctx.Intel.ContainsKey($_.id) })
    foreach ($x in $hits) { $x.intel = (@($Ctx.Intel[$x.id] | ForEach-Object { "$($_.list): $($_.reason) ($($_.date))" }) -join ' | ') }
    foreach ($g in ($hits | Group-Object id)) {
        $xs = @($g.Group); $en = @($xs | Where-Object { $_.enabled }).Count -gt 0; $m = @($Ctx.Intel[$g.Name])
        $mal = @($m | Where-Object { @($Ref.intelMaliciousReasons) -contains $_.reason }).Count -gt 0
        $null = Add-S06Finding -Check 'browser.extensions.intel' -Title "Known-malicious browser extension installed: $($xs[0].name) ($($g.Name))" -Severity $(if ($en) { 'critical' } else { 'high' }) -Class $(if ($en -and $mal) { 'compromise' } else { 'suspicious' }) -Confidence $(if ($mal) { 'high' } else { 'medium' }) -Reasons @('intel_match') `
            -Evidence (@($xs | ForEach-Object { New-S06ExtEv $_ 'installed' }) + @($m | Select-Object -First 5 | ForEach-Object { [ordered]@{ type = 'intel'; name = $_.list; value = "$($_.reason); $($_.origin); listed $($_.date) as '$($_.name)'" } })) -Entities (Get-S06ExtEntity $xs) `
            -Rec 'Remove the extension from every listed profile, then sign out all sessions and change passwords for sites used in that browser (wallets and e-mail first).' -Fp "Lists also contain IDs removed for policy reasons and IDs whose earlier version was compromised; listed reason(s): $((@($m | ForEach-Object { $_.reason }) | Select-Object -Unique) -join ', ')." -Mitre @('T1176.001')
    }
    foreach ($s in @($Ctx.Stubs | Where-Object { $Ctx.Intel.ContainsKey($_.id) })) {
        $null = Add-S06Finding -Check 'browser.extensions.intel' -Title "Known-malicious extension ID referenced in browser settings (not installed): $($s.id)" -Severity medium -Class suspicious -Reasons @('intel_match') -Evidence @([ordered]@{ type = 'preference'; name = "$($s.browser)/$($s.profile)"; value = (@($Ctx.Intel[$s.id] | ForEach-Object { "$($_.list): $($_.reason)" }) -join ' | ') }) -Rec 'Confirm the browser extensions page shows nothing for this ID; remove software that registers it.' -Fp 'Settings stub only (external/sync registration); no extension code on disk.' -Mitre @('T1176.001')
    }
    $hits
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.store' -Description 'Store listing: Chrome cws-info (offline) + store lookups for enabled non-store or top-risk extensions without cws-info' -Script {
    $cwsById = @{}; foreach ($x in $Ctx.Ext) { if ($x.cwsInfo -and -not $cwsById.ContainsKey($x.id)) { $cwsById[$x.id] = $x.cwsInfo } }
    $net = @{}; $n = 0; $unk = 0
    $targets = @($Ctx.Ext | Where-Object { $_.enabled -and -not $_.isComponent -and ($_.store -in 'self-hosted', 'none' -or ($_.riskTier -eq 'top' -and $_.store -in 'chrome-web-store', 'edge-add-ons' -and -not $cwsById.ContainsKey($_.id))) } | Sort-Object id -Unique)
    foreach ($x in $targets) { if ($Offline -or $NoStoreCheck -or $n -ge $StoreCheckMax) { break }; $net[$x.id] = Test-S06Store $(if ($x.store -eq 'edge-add-ons') { 'edge-add-ons' } else { 'chrome-web-store' }) $x.id; $n++ }
    foreach ($x in $Ctx.Ext) {
        $c = $cwsById[$x.id]; $r = $net[$x.id]
        if ($r -and $r.status -ne 'unknown') { $x.storeStatus = $r.status; $x.storeDetail = "$($r.store): $($r.detail)" }
        elseif ($c -and $x.store -eq 'chrome-web-store') { $x.storeStatus = $(if ($c.violation -eq 'malware') { 'taken_down_malware' } elseif ($c.isPresent -eq $false) { 'not_listed' } elseif ($c.isLive -eq $false) { 'taken_down' } elseif ($c.unpublishedLongAgo) { 'unpublished' } else { 'listed' }); $x.storeDetail = "Chrome cws-info (violation=$($c.violation))" }
        elseif ($r) { $x.storeStatus = 'unknown'; $x.storeDetail = "$($r.store): $($r.detail)"; $unk++ }
    }
    foreach ($g in (@($Ctx.Ext | Where-Object { $_.storeStatus -in 'not_listed', 'taken_down', 'unpublished', 'taken_down_malware' }) | Group-Object id)) {
        $xs = @($g.Group); $x0 = $xs[0]; $en = @($xs | Where-Object { $_.enabled }).Count -gt 0; $mal = $x0.storeStatus -eq 'taken_down_malware'
        $sev = if ($mal) { if ($en) { 'critical' } else { 'high' } } else { 'medium' }
        if ($x0.expected -and -not $x0.expected.cancelled -and -not $mal) { $sev = Limit-S06Sev $sev $x0.expected.severityCap }
        $null = Add-S06Finding -Check 'browser.extensions.store' -Title $(if ($mal) { "Chrome Web Store flags extension as malware: $($x0.name)" } else { "Extension no longer listed in its store: $($x0.name) ($($x0.storeStatus))" }) -Severity $sev -Class $(if ($mal -and $en) { 'compromise' } else { 'suspicious' }) -Confidence $(if ($mal) { 'high' } else { 'medium' }) -Reasons @($(if ($mal) { 'av_match' } else { 'store_removed' })) `
            -Evidence @($xs | ForEach-Object { New-S06ExtEv $_ $_.storeDetail }) -Entities (Get-S06ExtEntity $xs) -Rec 'Remove the extension unless you still need it; then look for the official replacement in the store.' -Fp 'Developers unpublish (e.g. Manifest V2 retirement) and stores remove items for minor policy issues; removal alone is not proof of malice.' -Mitre @('T1176.001') -Expected $x0.expected
    }
    if ($unk) { Set-BvsCheckStatus -Id 'browser.extensions.store' -Status partial -Reason ("$unk lookup(s) inconclusive: " + (@($Ctx.StoreWhy.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; ')) }
    elseif ($Offline -or $NoStoreCheck) { Set-BvsCheckStatus -Id 'browser.extensions.store' -Status partial -Reason 'network lookups disabled; Chrome cws-info used where present' }
    @($Ctx.Ext | Where-Object { $_.storeStatus -ne 'not_applicable' })
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.risk' -Description 'Sideloading, orphan folders, self-hosted updates, blocklist, policy installs, permission tiers, developer mode, bundleware' -Script {
    $X = @($Ctx.Ext)
    foreach ($x in @($X | Where-Object { $_.store -in 'unpacked', 'command-line' })) {
        $sev = if (@($x.pathTags | Where-Object { $_ -in 'temp', 'appdata', 'programdata', 'public', 'downloads' }).Count -or $x.riskTier -eq 'top' -or ($x.enabled -and -not $x.devMode)) { 'high' } else { 'medium' }
        if (-not $x.enabled) { $sev = Step-S06Down $sev }
        $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Sideloaded ($($x.store)) extension loaded from outside the profile: $($x.name)" -Severity $sev -Class suspicious -Reasons (@('unpacked_extension') + @(if ($x.pathTags.Count) { 'user_writable' }) + @(if ($x.recent) { 'created_lt_30d' })) `
            -Evidence @(New-S06ExtEv $x "path=$($x.path); tags=$($x.pathTags -join ','); devMode=$($x.devMode); $($x.permissionsSummary)") -Entities (Get-S06ExtEntity @($x)) -Rec 'If you did not load it yourself, remove it on the extensions page, review its folder, and check shortcuts/Run keys for --load-extension.' -Fp 'Developers load their own unpacked extensions; check whether the folder is one of your projects.' -Mitre @('T1176.001')
    }
    foreach ($g in (@($X | Where-Object { $_.store -eq 'self-hosted' }) | Group-Object id)) {
        $xs = @($g.Group); $x0 = $xs[0]
        $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Extension updates from a non-store server: $($x0.name) ($($x0.updateHost))" -Severity $(if ($x0.riskTier -eq 'top' -and @($xs | Where-Object { $_.enabled }).Count) { 'high' } else { 'medium' }) -Class suspicious -Reasons @('non_store_update') -Evidence @($xs | ForEach-Object { New-S06ExtEv $_ "update host $($_.updateHost); $($_.permissionsSummary)" }) -Entities (Get-S06ExtEntity $xs) -Rec 'Confirm the vendor; remove it if unknown.' -Fp 'Enterprise and some AV extensions are self-hosted.' -Mitre @('T1176.001')
    }
    foreach ($x in @($X | Where-Object { $_.orphanFolder })) { $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Extension folder not registered in browser preferences: $($x.name) ($($x.id))" -Severity $(if ($x.riskTier -eq 'top') { 'medium' } else { 'low' }) -Class suspicious -Reasons @('orphan') -Evidence @(New-S06ExtEv $x "folder=$($x.path); $($x.permissionsSummary)") -Entities (Get-S06ExtEntity @($x)) -Rec 'Restart the browser; if the folder persists and the extension is not listed, review and remove the folder.' -Fp 'Leftover of an uninstall pending browser restart.' -Mitre @('T1176.001') }
    foreach ($o in $Ctx.Odd) { $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Unexpected folder in browser Extensions directory: $($o.folder)" -Severity low -Class suspicious -Reasons @('orphan') -Evidence @([ordered]@{ type = 'file'; path = $o.path; name = "$($o.browser)/$($o.profile)" }) -Rec 'Review the folder contents.' -Fp 'Browser temp/staging folders.' }
    foreach ($x in @($X | Where-Object { $_.blocklist })) { $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Browser blocklisted extension (Safe Browsing): $($x.name)" -Severity $(if ($x.enabled) { 'critical' } else { 'high' }) -Class suspicious -Confidence high -Reasons @('av_match') -Evidence @(New-S06ExtEv $x $x.blocklist) -Entities (Get-S06ExtEntity @($x)) -Rec 'Remove the extension and change passwords used in this profile.' -Fp 'Blocklist also covers potentially unwanted (not malicious) extensions.' -Mitre @('T1176.001') }
    foreach ($x in @($X | Where-Object { $_.location -in 7, 9 })) { $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Extension force-installed by policy: $($x.name)" -Severity medium -Class suspicious -Reasons @('policy') -Evidence @(New-S06ExtEv $x $x.permissionsSummary) -Entities (Get-S06ExtEntity @($x)) -Rec 'On a home PC no policy should install extensions; see browser.policies.' -Fp 'Work/school managed browsers.' -Mitre @('T1176.001') }
    $top = @($X | Where-Object { $_.enabled -and -not $_.isComponent -and $_.riskTier -eq 'top' })
    $topExp = @($top | Where-Object { $_.expected -and -not $_.expected.cancelled }); $topOther = @($top | Where-Object { -not ($_.expected -and -not $_.expected.cancelled) })
    if ($top.Count) {
        $ev = @($topOther | Group-Object id | ForEach-Object { New-S06ExtEv $_.Group[0] "$($_.Group[0].permissionsSummary); profiles: $((@($_.Group | ForEach-Object { "$($_.browser)/$($_.profile)" })) -join ', ')" }) + @($topExp | Group-Object id | ForEach-Object { New-S06ExtEv $_.Group[0] "expected ($($_.Group[0].expected.id)): $($_.Group[0].permissionsSummary)" })
        $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "$(@($topOther | Group-Object id).Count) enabled extension(s) can read and change data on all websites (top permission tier)" -Severity $(if ($topOther.Count) { 'low' } else { 'info' }) -Class hardening -Confidence high -Reasons @('all_sites_access', 'sensitive_api') -Evidence $ev -Entities (Get-S06ExtEntity $top) `
            -Rec 'Remove extensions you do not use; for the rest set Site access to "On click" or specific sites. Extensions with debugger/cookies/webRequest on all sites can read sessions and typed passwords.' -Fp 'Ad blockers, password managers, writing and AI assistants need all-site access by design; attack-surface hygiene, not compromise.' -Mitre @('T1176.001')
    }
    $dev = @(foreach ($b in $Ctx.Browsers) { foreach ($pr in $b.profiles) { if ($pr.devMode) { "$($b.id)/$($pr.folder)" } } })
    if ($dev.Count) { $null = Add-S06Finding -Check 'browser.extensions.risk' -Title "Extension developer mode is enabled ($($dev -join ', '))" -Severity low -Class hardening -Reasons @('developer_mode') -Evidence @($dev | ForEach-Object { [ordered]@{ type = 'preference'; name = $_; value = 'extensions.ui.developer_mode=true' } }) -Rec 'Turn Developer mode off on the extensions page unless you load your own unpacked extensions; current Chromium only runs unpacked extensions with it on, which sideloading malware abuses.' -Fp 'Normal on developer machines.' }
    foreach ($g in (@($X | Where-Object { $_.expected -and $_.expected.hygiene }) | Group-Object { $_.expected.id })) {
        $xs = @($g.Group); $x0 = $xs[0]
        $f = Add-S06Finding -Check 'browser.extensions.risk' -Title "Bundled extension present: $($x0.name) (unwanted bundleware)" -Severity $(if ($x0.expected.severityCap) { $x0.expected.severityCap } else { 'low' }) -Class hygiene -Confidence high -Reasons @('expected_match') -Evidence @($xs | ForEach-Object { New-S06ExtEv $_ "install location $($_.locationName); enabled=$($_.enabled); $($_.permissionsSummary)" }) -Entities (Get-S06ExtEntity $xs) -Rec 'Uninstall the bundled program (Settings > Apps), then remove the extension from each listed profile.' -Fp $(if ($x0.expected.hygieneReason) { $x0.expected.hygieneReason } else { $x0.expected.reason }) -Expected $x0.expected
        foreach ($x in $xs) { $Ctx.Hygiene[$x.id] = $f }
    }
    $top
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.external_registrations' -Description 'HKLM/HKCU\Software\(WOW6432Node\)<vendor>\Extensions registrations' -Script {
    $regs = [Collections.Generic.List[object]]::new()
    foreach ($v in $Ref.externalExtensionRegistryVendors) {
        foreach ($hv in @(@('HKLM', '64'), @('HKLM', '32'), @('HKCU', '64'))) {
            $base = "$($hv[0])\SOFTWARE\$v\Extensions"
            foreach ($id in @(Get-BvsRegSubKeys -Path $base -View $hv[1])) {
                $vals = @{}; foreach ($rv in @(Get-BvsRegValues -Path "$base\$id" -View $hv[1])) { $vals[$rv.Name] = $rv.Value }
                $uh = $null; if ($vals['update_url']) { try { $uh = ([uri][string]$vals['update_url']).Host.ToLowerInvariant() } catch { $uh = '(unparsable)' } }
                $regs.Add([pscustomobject]@{ key = $(if ($hv[1] -eq '32') { "$($hv[0])\SOFTWARE\WOW6432Node\$v\Extensions\$id" } else { "$base\$id" }); id = $id; updateHost = $uh; path = $vals['path']; version = $vals['version']; lastWrite = (Get-BvsRegKeyLastWrite -Path "$base\$id" -View $hv[1])
                        installed = @($Ctx.Ext | Where-Object { $_.id -eq $id } | ForEach-Object { "$($_.browser)/$($_.profile):$(if ($_.enabled) { 'enabled' } else { 'disabled' })" }) })
            }
        }
    }
    $Ctx.Regs = $regs.ToArray(); $storeH = @($StoreHosts.Values | ForEach-Object { $_ })
    foreach ($g in ($regs | Group-Object id)) {
        $rs = @($g.Group); $id = $g.Name; $x = @($Ctx.Ext | Where-Object { $_.id -eq $id }) | Select-Object -First 1
        $storeHosted = @($rs | Where-Object { $storeH -contains $_.updateHost }).Count -eq $rs.Count; $crx = @($rs | Where-Object { $_.path }).Count -gt 0; $intel = $Ctx.Intel.ContainsKey($id)
        $ev = @($rs | ForEach-Object { [ordered]@{ type = 'registry'; path = $_.key; name = 'update_url/path'; value = "update host=$($_.updateHost); crx path=$($_.path); version=$($_.version); key written $($_.lastWrite); installed in: $($_.installed -join ', ')" } })
        if ($Ctx.Hygiene.ContainsKey($id) -and -not $intel -and -not $crx) { $Ctx.Hygiene[$id].evidence = @($Ctx.Hygiene[$id].evidence) + $ev; continue }
        $sev = if ($intel -or $crx) { 'high' } elseif (-not $storeHosted) { 'medium' } else { 'low' }
        $null = Add-S06Finding -Check 'browser.extensions.external_registrations' -Title "Software registered a browser extension via the registry: $(if ($x) { $x.name } else { $id })" -Severity $sev -Class $(if ($sev -eq 'low') { 'hygiene' } else { 'suspicious' }) -Reasons (@('external_registration') + @(if ($intel) { 'intel_match' })) -Evidence $ev `
            -Entities @{ registry = @($rs | ForEach-Object { $_.key }); extensions = @(); files = @(); processes = @(); network = @(); accounts = @() } -Rec 'Identify the installer that created the key; if unwanted, uninstall it and remove the extension (HKLM keys need admin rights).' -Fp 'Adobe, AV vendors and other installers pre-register store-hosted extensions; the browser asks before enabling them.' -Mitre @('T1176.001')
    }
    $Ctx.Regs
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.policies' -Description 'HKLM/HKCU\Software\Policies\<vendor>: forcelist, ExtensionSettings, hijack/proxy/security/update policies' -Script {
    $pol = [Collections.Generic.List[object]]::new()
    foreach ($v in $Ref.policyRegistryVendors) { foreach ($hv in @(@('HKLM', '64'), @('HKLM', '32'), @('HKCU', '64'))) { Get-S06RegTree "$($hv[0])\SOFTWARE\Policies\$v" $hv[1] 0 $pol } }
    $Ctx.Pol = @($pol | Sort-Object key, name, value -Unique)
    if (-not $Ctx.Pol.Count) { return }
    $dom = $false; try { $dom = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { }
    $grp = [ordered]@{
        'force-installs extensions'      = @($Ctx.Pol | Where-Object { $_.key -match '\\ExtensionInstallForcelist' -or "$($_.key)\$($_.name)" -match 'ExtensionSettings' })
        'changes home/search/startup'    = @($Ctx.Pol | Where-Object { $_.name -match '^(HomepageLocation|HomepageIsNewTabPage|RestoreOnStartup|NewTabPageLocation|DefaultSearchProvider\w*|ShowHomeButton)$' -or $_.key -match '\\RestoreOnStartupURLs' })
        'sets a proxy or DNS'            = @($Ctx.Pol | Where-Object { $_.name -match '^(Proxy\w*|DnsOverHttps\w*)$' })
        'weakens browser security'       = @($Ctx.Pol | Where-Object { ($_.name -match '^(CommandLineFlagSecurityWarningsEnabled|SafeBrowsingEnabled|SafeBrowsingProtectionLevel)$' -and "$($_.value)" -eq '0') -or ($_.name -eq 'DeveloperToolsAvailability' -and "$($_.value)" -eq '2') -or $_.name -match '^(ExtensionInstallSources|ExtensionAllowedTypes|ExtensionDeveloperModeSettings)$' })
        'disables browser updates'       = @($Ctx.Pol | Where-Object { $_.key -match '\\(Google\\Update|Microsoft\\EdgeUpdate)' -and $_.name -match '^(UpdateDefault|Update\{|AutoUpdateCheckPeriodMinutes)' -and "$($_.value)" -eq '0' })
    }
    foreach ($k in $grp.Keys) {
        $items = $grp[$k]; if (-not $items.Count) { continue }; $upd = $k -eq 'disables browser updates'
        $null = Add-S06Finding -Check 'browser.policies' -Title "Browser policy $k" -Severity $(if ($upd -or $dom) { 'medium' } else { 'high' }) -Class $(if ($upd) { 'hardening' } else { 'suspicious' }) -Reasons @('policy') -Evidence @($items | Select-Object -First 25 | ForEach-Object { [ordered]@{ type = 'registry'; path = $_.key; name = $_.name; value = $_.value } }) `
            -Rec 'Review chrome://policy or edge://policy; identify the software that wrote the keys and remove it (needs admin rights).' -Fp $(if ($dom) { 'Domain-joined machine: policies may come from the organisation.' } else { 'Some security or parental-control products set browser policies.' }) -Mitre @('T1112', 'T1176.001')
    }
    $Ctx.Pol
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.hijack' -Description 'Search engine, homepage, startup pages, extension overrides and controlled settings, DNS-over-HTTPS, chrome://flags' -Script {
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($b in $Ctx.Browsers) {
        foreach ($pr in $b.profiles) {
            if (-not $pr.P -or $pr.kind -ne 'user') { continue }
            $PP = $pr.P; $SP = $pr.S; $sec = Join-Path $pr.path 'Secure Preferences'
            $dsp = @(foreach ($c in @(@($SP, 'default_search_provider_data.template_url_data'), @($PP, 'default_search_provider_data.template_url_data'), @($PP, 'default_search_provider_data.mirrored_template_url_data'))) {
                    $t = Get-S06Val $c[0] $c[1]
                    if ($t -is [Collections.IDictionary]) { $u = Get-S06Url ([string]$t['url']); [pscustomobject]@{ keyword = $t['keyword']; host = $u.host; url = $u.display; prepopulateId = $t['prepopulate_id']; policy = $t['enforced_by_policy']; known = (Test-S06KnownSearch $u.host); hijack = @($Ref.searchHijackPatterns | Where-Object { ([string]$t['url']) -match $_ }) } } }) | Sort-Object host -Unique
            $hp = if ($SP -and $SP.Contains('homepage')) { $SP['homepage'] } else { $PP['homepage'] }
            $hpNtp = if ($SP -and $SP.Contains('homepage_is_newtabpage')) { $SP['homepage_is_newtabpage'] } else { $PP['homepage_is_newtabpage'] }
            $ros = Get-S06Val $SP 'session.restore_on_startup'; if ($null -eq $ros) { $ros = Get-S06Val $PP 'session.restore_on_startup' }
            $su = @(@(ConvertTo-S06Strings (Get-S06Val $SP 'session.startup_urls')) + @(ConvertTo-S06Strings (Get-S06Val $PP 'session.startup_urls')) | Select-Object -Unique)
            $row = [ordered]@{ browser = $b.id; profile = $pr.folder; search = $dsp; homepage = $(if ($hp) { Protect-BvsUrl ([string]$hp) }); homepageIsNewTabPage = $hpNtp; restoreOnStartup = $ros; startupUrls = @($su | ForEach-Object { Protect-BvsUrl $_ }); preferenceResetTime = (ConvertFrom-S06Time (Get-S06Val $PP 'prefs.preference_reset_time')); extensionOverrides = @(); extensionSettings = @() }
            $ev = [Collections.Generic.List[object]]::new()
            foreach ($d in $dsp) { if ((-not $d.known -and [int]$d.prepopulateId -le 0) -or $d.hijack.Count) { $ev.Add([ordered]@{ type = 'preference'; path = $sec; name = 'default search engine'; value = "$($d.url) keyword=$($d.keyword) patterns=$($d.hijack -join ',')" }) } }
            foreach ($u in @(@(if ($hp -and -not $hpNtp) { [string]$hp }) + @(if ([int]$ros -eq 4) { $su }) | Where-Object { $_ })) { $fl = @(Get-S06SiteFlags (Get-S06Url $u).host) + @($Ref.searchHijackPatterns | Where-Object { $u -match $_ }); if ($fl.Count) { $ev.Add([ordered]@{ type = 'preference'; path = $sec; name = 'homepage/startup URL'; value = "$(Protect-BvsUrl $u) flags=$($fl -join ',')" }) } }
            foreach ($x in @($Ctx.Ext | Where-Object { $_.browser -eq $b.id -and $_.profile -eq $pr.folder -and $_.enabled -and -not $_.isComponent })) {
                foreach ($o in $x.overrides) { $row.extensionOverrides += "$($x.name): $o" }
                foreach ($c in @($x.controlledPrefs | Where-Object { Test-S06PrefIn $_.pref $Ref.extensionControlledPrefsHijack })) { $row.extensionSettings += "$($x.name): $($c.pref)=$($c.value | ConvertTo-Json -Compress -Depth 3)" }
            }
            $where = "$($b.label) / $($pr.folder)"
            if ($ev.Count) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Search/startup settings point to an unknown or suspicious site ($where)" -Severity medium -Class suspicious -Reasons @('search_hijack') -Evidence $ev.ToArray() -Rec 'Check Settings > Search engine / On start-up; reset settings if you did not choose this site, and look for the extension or program that set it.' -Fp 'Users may choose niche search engines or start pages.' -Mitre @('T1176.001') }
            $exH = @(@($row.extensionSettings) + @($row.extensionOverrides | Where-Object { $_ -match ': (search_provider|homepage|startup_pages)' }))
            if ($exH.Count) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Extension controls browser search/startup/proxy settings ($where)" -Severity $(if (@($row.extensionSettings | Where-Object { $_ -match ': (proxy|safebrowsing)' }).Count) { 'high' } else { 'medium' }) -Class suspicious -Reasons @('extension_controlled_setting') -Evidence @($exH | ForEach-Object { [ordered]@{ type = 'preference'; path = $sec; value = $_ } }) -Rec 'Disable the extension and confirm the setting returns to your choice; remove it if you did not install it for this purpose.' -Fp 'VPN/proxy and search-provider extensions change these settings by design.' -Mitre @('T1176.001') }
            $ntp = @($row.extensionOverrides | Where-Object { $_ -match 'url_override:newtab' })
            if ($ntp.Count) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Extension replaces the New Tab page ($where)" -Severity low -Class suspicious -Reasons @('extension_controlled_setting') -Evidence @($ntp | ForEach-Object { [ordered]@{ type = 'preference'; path = $sec; value = $_ } }) -Rec 'Keep only if you chose this new-tab extension.' -Fp 'Many legitimate new-tab extensions.' -Mitre @('T1176.001') }
            if ($row.preferenceResetTime) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Browser reset protected settings after an outside modification ($where)" -Severity low -Class suspicious -Reasons @('tracked_pref_reset') -Evidence @([ordered]@{ type = 'preference'; path = (Join-Path $pr.path 'Preferences'); name = 'prefs.preference_reset_time'; value = $row.preferenceResetTime }) -Rec 'Check whether software tried to change search/startup settings around that time.' -Fp 'Profile copies, sync or disk errors also trigger resets.' }
            $rows.Add($row)
        }
        $dohH = @(@(ConvertTo-S06Strings (([string]$b.doh.templates) -split '\s+')) | ForEach-Object { (Get-S06Url $_).host } | Where-Object { $_ })
        $custom = @($dohH | Where-Object { @($Ref.knownDohHosts) -notcontains $_ })
        if ($b.doh.mode -in 'secure', 'automatic' -and $custom.Count) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Custom DNS-over-HTTPS provider in $($b.label): $($custom -join ', ')" -Severity medium -Class suspicious -Reasons @('custom_doh') -Evidence @([ordered]@{ type = 'preference'; path = (Join-Path $b.userDataDir 'Local State'); name = 'dns_over_https'; value = "mode=$($b.doh.mode) hosts=$($dohH -join ',')" }) -Rec 'Confirm you configured this DNS provider (Settings > Privacy > Use secure DNS).' -Fp 'Privacy-minded users pick NextDNS/ISP resolvers not on the known list.' -Mitre @('T1557') }
        $badLabs = @($b.labs | Where-Object { $l = ($_ -split '@')[0]; @($Ref.labsInsecureExperiments | Where-Object { $l -like "$_*" }).Count })
        if ($badLabs.Count) { $null = Add-S06Finding -Check 'browser.hijack' -Title "Security-weakening flags enabled in $($b.label): $($badLabs -join ', ')" -Severity medium -Class hardening -Reasons @('insecure_flag') -Evidence @([ordered]@{ type = 'preference'; path = (Join-Path $b.userDataDir 'Local State'); name = 'browser.enabled_labs_experiments'; value = ($b.labs -join ',') }) -Rec 'Reset the listed flags on chrome://flags / edge://flags.' -Fp 'Developers enable these for local testing.' }
        $rows.Add([ordered]@{ browser = $b.id; localState = $true; dohMode = $b.doh.mode; dohHosts = $dohH; labs = $b.labs })
    }
    $Ctx.Hijack = $rows.ToArray(); $Ctx.Hijack
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.site_permissions' -Description 'notifications/popups/automatic_downloads allowed (setting=1); only flagged origins are output, totals for the rest' -Script {
    $tot = [Collections.Generic.List[object]]::new(); $flagged = [Collections.Generic.List[object]]::new()
    foreach ($b in $Ctx.Browsers) {
        foreach ($pr in $b.profiles) {
            if (-not $pr.P -or $pr.kind -ne 'user') { continue }
            $counts = [ordered]@{}
            foreach ($t in @($Ref.sitePermissionTypes) + @($Ref.chromeFlaggedSiteTypes)) {
                $d = Get-S06Val $pr.P "profile.content_settings.exceptions.$t"; if ($d -isnot [Collections.IDictionary]) { continue }
                $cf = @($Ref.chromeFlaggedSiteTypes) -contains $t; $n = 0
                foreach ($pat in $d.Keys) {
                    $e = $d[$pat]
                    if (-not $cf -and ($e -isnot [Collections.IDictionary] -or [string]$e['setting'] -ne '1')) { continue }
                    $n++; $h = if ($pat -match '^(?:[a-z*][a-z0-9+.*-]*://)?(?:\[\*\.\])?(\[[0-9a-f:]+\]|[^:/,\s]+)') { $Matches[1] } else { $null }
                    $fl = @(Get-S06SiteFlags $h); if ($cf) { $fl += 'chrome_flagged' }
                    if ($fl.Count) { $flagged.Add([pscustomobject]@{ browser = $b.id; profile = $pr.folder; type = $t; origin = ($pat -split ',')[0]; reasons = $fl; lastModified = $(if ($e -is [Collections.IDictionary]) { ConvertFrom-S06Time $e['last_modified'] }) }) }
                }
                $counts[$t] = $n
            }
            $tot.Add([ordered]@{ browser = $b.id; profile = $pr.folder; allowed = $counts })
        }
    }
    $Ctx.Sites = [ordered]@{ totals = $tot.ToArray(); flagged = $flagged.ToArray() }
    if ($flagged.Count) {
        $strong = @($flagged | Where-Object { $_.type -eq 'notifications' -and @($_.reasons | Where-Object { $_ -in 'lure_word', 'raw_ip', 'chrome_flagged' }).Count })
        $null = Add-S06Finding -Check 'browser.site_permissions' -Title "$($flagged.Count) suspicious site(s) allowed to send notifications / pop-ups / downloads" -Severity $(if ($strong.Count) { 'medium' } else { 'low' }) -Class suspicious -Reasons @('notification_spam') -Evidence @($flagged | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'preference'; name = "$($_.browser)/$($_.profile) $($_.type)"; value = "$($_.origin) [$($_.reasons -join ',')] since $($_.lastModified)" } }) `
            -Rec 'Settings > Privacy > Site settings > Notifications: remove these sites. "Click Allow to verify you are not a robot" pages push scam/phishing notifications.' -Fp 'Heuristic (TLD, random-looking label, lure words); legitimate shops on .shop/.online TLDs can match.' -Mitre @('T1204.001')
    }
    $flagged
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.launch.processes' -Description 'Running browser main processes (no --type=): dangerous switches' -Script {
    $pt = @(Get-BvsProcessTable); $Ctx.PT = $pt; $byPid = @{}; foreach ($p in $pt) { $byPid[[int]$p.Pid] = $p }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($p in @($pt | Where-Object { $_.Name -and $BrowserExe.Contains($_.Name) -and $_.CommandLine -and $_.CommandLine -notmatch '(^|\s)--type=' })) {
        $wv = @($Ref.webViewExeNames) -contains $p.Name.ToLowerInvariant()
        $argText = if ($p.CommandLine -match '^\s*"[^"]*"\s*(.*)$') { $Matches[1] } else { $p.CommandLine -replace '^\s*\S+\s*', '' }
        $a = Get-S06Launch $argText $wv; $par = $byPid[[int]$p.ParentPid]
        $rows.Add([pscustomobject]@{ pid = $p.Pid; name = $p.Name; path = $p.Path; switches = $a.Switches; unknownSwitches = $a.Unknown; flagged = @($a.Hits | ForEach-Object { $_.switch }); parent = $(if ($par) { "$($par.Name) ($($par.Pid))" }); started = $p.Started })
        foreach ($h in $a.Hits) {
            $null = Add-S06Finding -Check 'browser.launch.processes' -Title "Running $($p.Name) started with --$($h.switch): $($h.label)" -Severity $h.severity -Class $h.class -Reasons @($h.reason) -Evidence @([ordered]@{ type = 'process'; path = $p.Path; name = "$($p.Name) pid $($p.Pid)"; value = $p.CommandLine }, [ordered]@{ type = 'process'; name = 'parent'; value = $(if ($par) { "$($par.Name) $($par.Path)" } else { 'exited' }) }) `
                -Entities @{ processes = @([ordered]@{ pid = $p.Pid; name = $p.Name; path = $p.Path }); files = @(); network = @(); registry = @(); accounts = @(); extensions = @() } -Rec 'Find what launched it (parent, shortcut, task). If not your dev/automation tool, close the browser, sign out all sessions and change passwords.' -Fp 'Puppeteer/Playwright/Selenium and IDE debuggers start browsers with these switches.' -Mitre $h.mitre
        }
    }
    $Ctx.Procs = $rows.ToArray(); $Ctx.Procs
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.launch.shortcuts' -Description 'Browser shortcuts (Desktop, Public Desktop, Start Menus, Taskbar, Quick Launch) via WScript.Shell CreateShortcut (read only, never saved)' -Script {
    $ql = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch'
    $locs = @(@('desktop', [Environment]::GetFolderPath('DesktopDirectory'), 1), @('desktop', (Join-Path $env:USERPROFILE 'Desktop'), 1), @('public_desktop', [Environment]::GetFolderPath('CommonDesktopDirectory'), 1), @('start_menu', [Environment]::GetFolderPath('StartMenu'), 6),
        @('common_start_menu', [Environment]::GetFolderPath('CommonStartMenu'), 6), @('quick_launch', $ql, 0), @('taskbar', (Join-Path $ql 'User Pinned\TaskBar'), 0), @('taskbar_implicit', (Join-Path $ql 'User Pinned\ImplicitAppShortcuts'), 3))
    $signers = @($Ref.chromiumBrowsers | ForEach-Object { $_.signers } | Where-Object { $_ })
    $sh = New-Object -ComObject WScript.Shell
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $rows = [Collections.Generic.List[object]]::new(); $skipped = 0
    try {
        foreach ($l in $locs) {
            if (-not $l[1]) { continue }
            foreach ($f in @(Get-BvsFiles -Path $l[1] -Include '*.lnk' -MaxDepth $l[2] -NoPrune)) {
                if (-not $seen.Add($f.FullName)) { continue }
                if ((Test-BvsCloudOnly $f) -or (Test-BvsNeverRead $f.FullName)) { $skipped++; continue }
                try { $lnk = $sh.CreateShortcut($f.FullName) } catch { $skipped++; continue }
                $tp = [string]$lnk.TargetPath; $leaf = [IO.Path]::GetFileName($tp); $icon = [IO.Path]::GetFileName(([string]$lnk.IconLocation -replace ',\s*-?\d+$', ''))
                $isB = $leaf -and $BrowserExe.Contains($leaf) -and ($leaf -notin 'launcher.exe', 'browser.exe' -or $tp -match '\\(Opera|Yandex)')
                $nameB = $f.BaseName -match $Ref.shortcutBrowserNameRegex; $iconB = $icon -and $BrowserExe.Contains($icon) -and $icon -notin 'launcher.exe', 'browser.exe'
                if (-not ($isB -or $nameB -or $iconB)) { continue }
                $lArgs = [string]$lnk.Arguments; $a = Get-S06Launch $lArgs $false
                $appId = @($a.Values | Where-Object { $_.name -eq 'app-id' })[0].value; $appUrl = @($a.Values | Where-Object { $_.name -eq 'app-url' })[0].value
                $iss = [Collections.Generic.List[object]]::new(); foreach ($h in $a.Hits) { $iss.Add($h) }
                if (-not $isB -and $tp -and -not ($leaf -eq 'explorer.exe' -and $lArgs -match 'microsoft-edge:')) { $iss.Add([pscustomobject]@{ switch = 'target'; severity = 'high'; class = 'suspicious'; reason = 'masquerading'; label = "browser-named/iconed shortcut starts $leaf"; mitre = @('T1036', 'T1547.009') }) }
                elseif ($isB -and $leaf -notin 'firefox.exe', 'iexplore.exe') { $sig = Get-BvsSignature $tp; if (-not ($sig.Status -eq 'Valid' -and $signers -contains $sig.Signer)) { $iss.Add([pscustomobject]@{ switch = 'target'; severity = 'high'; class = 'suspicious'; reason = 'masquerading'; label = "browser executable not validly signed by its vendor ($($sig.Status), $($sig.Signer))"; mitre = @('T1036') }) } }
                foreach ($u in $a.Urls) { $fl = @(Get-S06SiteFlags (Get-S06Url $u).host); $iss.Add([pscustomobject]@{ switch = 'url'; severity = $(if ($fl.Count) { 'high' } else { 'medium' }); class = 'suspicious'; reason = 'shortcut_url'; label = "shortcut opens a fixed URL $(Protect-BvsUrl $u) $($fl -join ',')"; mitre = @('T1547.009') }) }
                $rows.Add([pscustomobject]@{ location = $l[0]; path = $f.FullName; name = $f.BaseName; target = $tp; switches = $a.Switches; unknownSwitches = $a.Unknown; appId = $appId; appUrlHost = $(if ($appUrl) { (Get-S06Url $appUrl).host }); issues = @($iss | ForEach-Object { "$($_.severity): $($_.label)" }) })
                foreach ($h in $iss) {
                    $null = Add-S06Finding -Check 'browser.launch.shortcuts' -Title "Browser shortcut '$($f.BaseName)': $($h.label)" -Severity $h.severity -Class $h.class -Reasons @($h.reason) -Evidence @([ordered]@{ type = 'shortcut'; path = $f.FullName; name = $tp; value = (Protect-BvsText $lArgs) }) `
                        -Entities @{ files = @([ordered]@{ path = $f.FullName }); processes = @(); network = @(); registry = @(); accounts = @(); extensions = @() } -Rec 'Open the shortcut Properties and compare Target/arguments with the real browser; if not yours, delete it and re-pin the browser.' -Fp 'Developers add debug/automation switches; some apps pin URL shortcuts on purpose.' -Mitre $h.mitre
                }
                if ($appId -and ($f.BaseName -match $Ref.walletNameRegex -or "$appUrl" -match '(?i)wallet')) { $Ctx.WalletApps.Add("$($f.BaseName) [$leaf, app-url host: $(if ($appUrl) { (Get-S06Url $appUrl).host } else { 'n/a' })]") }
            }
        }
    }
    finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh) }
    if ($skipped) { Set-BvsCheckStatus -Id 'browser.launch.shortcuts' -Status partial -Reason "$skipped shortcut(s) skipped (cloud-only or unreadable)" }
    $Ctx.Shortcuts = $rows.ToArray(); $Ctx.Shortcuts
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.launch.debug_listeners' -Description 'TCP listeners owned by browser processes or on 9222/9229 (Get-NetTCPConnection)' -Script {
    $pt = if ($Ctx.PT) { $Ctx.PT } else { @(Get-BvsProcessTable) }; $byPid = @{}; foreach ($p in $pt) { $byPid[[int]$p.Pid] = $p }
    $rows = @(foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $p = $byPid[[int]$c.OwningProcess]; $isB = [bool]($p -and $p.Name -and $BrowserExe.Contains($p.Name))
            if ($isB -or $c.LocalPort -in 9222, 9229) { [pscustomobject]@{ address = $c.LocalAddress; port = $c.LocalPort; pid = $c.OwningProcess; process = $(if ($p) { $p.Name }); path = $(if ($p) { $p.Path }); browser = $isB } } })
    foreach ($r in $rows) {
        $ev = @([ordered]@{ type = 'network'; name = "$($r.process) pid $($r.pid)"; path = $r.path; value = "listen $($r.address):$($r.port)" })
        if ($r.browser) { $null = Add-S06Finding -Check 'browser.launch.debug_listeners' -Title "Browser process $($r.process) listens on TCP $($r.address):$($r.port) (DevTools / remote debugging)" -Severity $(if ($r.port -in 9222, 9229) { 'critical' } else { 'high' }) -Class suspicious -Reasons @('remote_debugging', 'exposed_service') -Evidence $ev -Rec 'Identify who started the browser with remote debugging; if not you, close it, sign out all sessions and change passwords.' -Fp 'Automation/dev tools (Puppeteer, Playwright, VS Code) open DevTools ports.' -Mitre @('T1539', 'T1185') }
        elseif ($r.address -notin '127.0.0.1', '::1') { $null = Add-S06Finding -Check 'browser.launch.debug_listeners' -Title "Debugger port $($r.port) exposed on $($r.address) by $($r.process)" -Severity medium -Class hardening -Reasons @('exposed_service') -Evidence $ev -Rec 'Bind debuggers to 127.0.0.1 or stop them when not debugging.' -Fp 'Intentional remote debugging in a lab.' }
    }
    $Ctx.Listeners = $rows; $rows
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.native_messaging' -Description 'NativeMessagingHosts registrations: manifest, host binary signer, allowed extensions' -Script {
    $rows = [Collections.Generic.List[object]]::new(); $inst = @{}; foreach ($x in $Ctx.Ext) { $inst[$x.id] = $true }
    foreach ($v in $Ref.nativeMessagingRegistryVendors) {
        foreach ($hv in @(@('HKLM', '64'), @('HKLM', '32'), @('HKCU', '64'))) {
            $base = "$($hv[0])\SOFTWARE\$v\NativeMessagingHosts"
            foreach ($n in @(Get-BvsRegSubKeys -Path $base -View $hv[1])) {
                $mp = [Environment]::ExpandEnvironmentVariables(([string](@(Get-BvsRegValues -Path "$base\$n" -View $hv[1]) | Where-Object { $_.Name -eq '' } | Select-Object -First 1).Value).Trim('"'))
                $man = $null; try { if ($mp) { $man = Read-S06Json $mp 1MB } } catch { }
                $exe = $null; if ($man -is [Collections.IDictionary] -and $man['path']) { $exe = ([string]$man['path']) -replace '/', '\'; if (-not [IO.Path]::IsPathRooted($exe)) { $exe = Join-Path (Split-Path -Parent $mp) $exe } }
                $target = $exe; $script0 = $false
                if ($exe -and @($Ref.scriptHostExtensions) -contains [IO.Path]::GetExtension($exe).ToLowerInvariant() -and [IO.File]::Exists($exe)) { $script0 = $true; $target = @(Get-S06ScriptExe $exe | Where-Object { [IO.File]::Exists($_) })[0] }
                $sig = if ($target -and [IO.File]::Exists($target)) { Get-BvsSignature $target } else { $null }
                $ids = @(@(ConvertTo-S06Strings $(if ($man -is [Collections.IDictionary]) { if ($man['allowed_origins']) { $man['allowed_origins'] } else { $man['allowed_extensions'] } })) | ForEach-Object { if ($_ -match 'chrome-extension://([a-p]{32})') { $Matches[1] } })
                $known = @($Ref.knownNativeHosts | Where-Object { $n -match $_.namePattern })[0]
                $rows.Add([pscustomobject]@{ name = $n; key = $(if ($hv[1] -eq '32') { "$($hv[0])\SOFTWARE\WOW6432Node\$v\NativeMessagingHosts\$n" } else { "$base\$n" }); manifest = $mp; manifestFound = [bool]$man; host = $exe; scriptWrapper = $script0; target = $target
                        sigStatus = $(if ($sig) { $sig.Status } else { 'missing' }); signer = $(if ($sig) { $sig.Signer }); userWritable = $(if ($target) { Test-BvsUserWritable $target }); allowedExtensions = $ids; allowedInstalled = @($ids | Where-Object { $inst.ContainsKey($_) }); knownVendor = $(if ($known) { $known.label }); signerPattern = $(if ($known) { $known.signerPattern }) })
            }
        }
    }
    foreach ($g in ($rows | Group-Object { "$($_.name)|$($_.target)" })) {
        $r = $g.Group[0]
        $ev = @([ordered]@{ type = 'registry'; path = (@($g.Group | ForEach-Object { $_.key }) -join ' ; '); name = $r.name; value = "manifest=$($r.manifest); host=$($r.host); target=$($r.target); signature=$($r.sigStatus) $($r.signer); allowed=$($r.allowedExtensions -join ','); installed=$($r.allowedInstalled -join ',')" })
        $sev = $null; $cls = 'suspicious'; $rs = @(); $title = $null
        if (-not $r.manifestFound -or -not $r.target -or -not [IO.File]::Exists([string]$r.target)) {
            if ($r.scriptWrapper) { $sev = 'medium'; $title = "Native messaging host '$($r.name)' is a script wrapper without a resolvable signed binary"; $rs = @('unsigned') }
            else { $sev = 'low'; $cls = 'hygiene'; $title = "Dangling native messaging host registration: $($r.name)"; $rs = @('orphan') }
        }
        elseif ($r.knownVendor -and -not ($r.sigStatus -eq 'Valid' -and $r.signer -match $r.signerPattern)) { $sev = 'high'; $title = "Native messaging host '$($r.name)' is not signed by its expected vendor ($($r.knownVendor))"; $rs = @('masquerading') }
        elseif ($r.sigStatus -ne 'Valid') { $sev = $(if ($r.userWritable) { 'high' } else { 'medium' }); $title = "Native messaging host '$($r.name)' runs an unsigned or invalid binary"; $rs = @('unsigned') + @(if ($r.userWritable) { 'user_writable' }) }
        if ($sev) { $null = Add-S06Finding -Check 'browser.native_messaging' -Title $title -Severity $sev -Class $cls -Reasons $rs -Evidence $ev -Entities @{ files = @([ordered]@{ path = $r.target; sig = $r.sigStatus; signer = $r.signer }); registry = @($g.Group | ForEach-Object { $_.key }); processes = @(); network = @(); accounts = @(); extensions = @() } -Rec 'Identify the owning program; if unknown, remove the registration and the binary after review (HKLM needs admin).' -Fp 'Uninstalled software often leaves dangling registrations; small vendors ship unsigned hosts.' -Mitre @('T1176.001') }
    }
    $Ctx.Native = $rows.ToArray(); $Ctx.Native
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.extensions.wallets' -Description 'Crypto wallet extensions / web-wallet apps (high-value target) and wallet-name impersonation' -Script {
    $w = @($Ctx.Ext | Where-Object { $_.wallet }); $apps = @($Ctx.WalletApps | Select-Object -Unique)
    if ($w.Count -or $apps.Count) { $null = Add-S06Finding -Check 'browser.extensions.wallets' -Title "Crypto wallet present in the browser (high-value target): $((@($w | ForEach-Object { $_.wallet }) + $apps | Select-Object -Unique) -join '; ')" -Severity info -Class info -Confidence high -Reasons @('wallet_present') -Evidence (@($w | ForEach-Object { New-S06ExtEv $_ "wallet: $($_.wallet)" }) + @($apps | ForEach-Object { [ordered]@{ type = 'shortcut'; name = 'web wallet app'; value = $_ } })) -Rec 'Keep seed phrases offline, verify the wallet app URL/extension ID is the official one, and prefer a hardware wallet for large balances.' -Fp 'Context: infostealers and malicious extensions target wallets first.' }
    foreach ($x in @($Ctx.Ext | Where-Object { -not $_.wallet -and -not $_.isComponent -and $_.name -match $Ref.walletBrandRegex })) { $null = Add-S06Finding -Check 'browser.extensions.wallets' -Title "Extension name mimics a crypto wallet but its ID is not the official one: $($x.name)" -Severity $(if ($x.store -in 'chrome-web-store', 'edge-add-ons') { 'medium' } else { 'high' }) -Class suspicious -Reasons @('masquerading') -Evidence @(New-S06ExtEv $x $x.permissionsSummary) -Entities (Get-S06ExtEntity @($x)) -Rec 'Compare the ID with the vendor website; remove fakes and move funds if a seed was entered.' -Fp 'Vendors sometimes publish under other IDs on other stores.' -Mitre @('T1036', 'T1176.001') }
    @($w) + @($apps)
}

$null = Invoke-BvsCheck -Run $run -Id 'browser.firefox' -Description 'Firefox presence (not analysed in v1)' -Script {
    if (@($Ref.firefoxMarkers | Where-Object { [IO.File]::Exists([Environment]::ExpandEnvironmentVariables($_)) }).Count) { Set-BvsCheckStatus -Id 'browser.firefox' -Status skipped -Reason 'Firefox present: extension/hijack analysis not implemented in v1' }
    else { Set-BvsCheckStatus -Id 'browser.firefox' -Status not_applicable -Reason 'Firefox not installed' }
}
#endregion

#region ---------- inventory + envelope ----------
Add-BvsInventory -Run $run -Name 'browsers' -Data @($Ctx.Browsers | ForEach-Object { [ordered]@{ id = $_.id; label = $_.label; userDataDir = $_.userDataDir; exe = $_.exe; version = $_.version; signer = $_.signer; signature = $_.sigStatus } })
Add-BvsInventory -Run $run -Name 'profiles' -Data @(foreach ($b in $Ctx.Browsers) { foreach ($pr in $b.profiles) { [ordered]@{ browser = $b.id; profile = $pr.folder; displayName = $pr.displayName; inInfoCache = $pr.inInfoCache; kind = $pr.kind; developerMode = $pr.devMode; extensions = @($Ctx.Ext | Where-Object { $_.browser -eq $b.id -and $_.profile -eq $pr.folder }).Count; settingsStubs = @($Ctx.Stubs | Where-Object { $_.browser -eq $b.id -and $_.profile -eq $pr.folder }).Count } } })
Add-BvsInventory -Run $run -Name 'extensions' -Data @($Ctx.Ext | ForEach-Object { [ordered]@{ browser = $_.browser; profile = $_.profile; id = $_.id; name = $_.name; version = $_.version; manifestVersion = $_.manifestVersion; location = $_.locationName; store = $_.store; enabled = $_.enabled; disableReasons = $_.disableReasons; riskTier = $_.riskTier; permissionsSummary = $_.permissionsSummary; storeStatus = $_.storeStatus; storeDetail = $_.storeDetail; intelMatch = $_.intel; wallet = $_.wallet; expected = $(if ($_.expected) { $_.expected.id })
            permissions = $_.permissions; hostPermissions = $_.hostPermissions; optionalPermissions = $_.optionalPermissions; contentScriptMatches = $_.contentScriptMatches; grantedHosts = $_.grantedHosts; background = $_.background; updateHost = $_.updateHost; fromWebstore = $_.fromWebstore; installTime = $_.installTime; lastUpdateTime = $_.lastUpdateTime; byDefault = $_.byDefault; byOem = $_.byOem; prefsEntry = $_.prefsEntry; pathKind = $_.pathKind; path = $_.path; manifestSource = $_.manifestSource; overrides = $_.overrides; controlledPrefs = $_.controlledPrefs; cwsInfo = $_.cwsInfo } })
Add-BvsInventory -Run $run -Name 'extensionStubs' -Data @($Ctx.Stubs | Group-Object browser, profile | ForEach-Object { [ordered]@{ where = $_.Name; count = $_.Count; ids = @($_.Group | ForEach-Object { $_.id }) } })
Add-BvsInventory -Run $run -Name 'externalRegistrations' -Data $Ctx.Regs
Add-BvsInventory -Run $run -Name 'policies' -Data $Ctx.Pol
Add-BvsInventory -Run $run -Name 'hijack' -Data $Ctx.Hijack
Add-BvsInventory -Run $run -Name 'sitePermissions' -Data $Ctx.Sites
Add-BvsInventory -Run $run -Name 'shortcuts' -Data $Ctx.Shortcuts
Add-BvsInventory -Run $run -Name 'browserProcesses' -Data $Ctx.Procs
Add-BvsInventory -Run $run -Name 'debugListeners' -Data $Ctx.Listeners
Add-BvsInventory -Run $run -Name 'nativeMessagingHosts' -Data $Ctx.Native
Add-BvsInventory -Run $run -Name 'intelSources' -Data $Ctx.IntelSources
Add-BvsInventory -Run $run -Name 'notes' -Data $Ctx.Notes
foreach ($b in $Ctx.Browsers) { foreach ($pr in $b.profiles) { $pr.P = $null; $pr.S = $null } }
$sum = Complete-BvsRun -Run $run
"S06 done: $($sum.Path)"
"findings=$($sum.Findings) [$($sum.BySeverity)] checks=$($sum.Checks) errors=$($sum.Errors) extensions=$($Ctx.Ext.Count) stubs=$($Ctx.Stubs.Count) intelIds=$($Ctx.Intel.Count)"
$run.Findings | Sort-Object { $SevRank[$_.severity] } -Descending | Select-Object -First 18 | ForEach-Object { "  [$($_.severity)/$($_.class)] $(Protect-BvsText $_.title)" }
$run.Checks | Where-Object { $_.status -ne 'ok' } | ForEach-Object { "  check $($_.id): $($_.status) $(Protect-BvsText ([string]$_.reason))" }
$run.Errors | Select-Object -First 5 | ForEach-Object { "  error $($_.check): $($_.error)" }
#endregion
