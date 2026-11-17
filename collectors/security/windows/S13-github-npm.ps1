#Requires -Version 7.2
<#
.SYNOPSIS
    S13 - GitHub and npm account audit (read-only).

.DESCRIPTION
    Looks for signs of account takeover and supply-chain worms (Shai-Hulud 1.0/2.0, s1ngularity)
    on the user's GitHub account and published npm packages, and lists the manual account checks
    that have no API.

    A  Public GitHub   profile, owned repos, public events, public gists, SSH / signing / GPG keys
                       (api.github.com, github.com/<user>.keys|.gpg) and, for repos that publish an npm
                       package, the local clone against the remote.
    B  npm             packument (versions, publish times, publishers, maintainers, dist-tags, registry
                       signatures, provenance) compared with the local repo (tags, commits, package.json);
                       the newest tarballs are downloaded as bytes, listed with `tar -tzf` and read in
                       memory (never extracted to disk, never executed); read-only token calls (whoami,
                       profile/2FA, token list); maintainer search; local npm configuration.
    C  Authenticated   only when `gh auth status` succeeds (vendor\gh\bin\gh.exe with GH_CONFIG_DIR =
       GitHub          <root>\vendor\gh-config): user, keys, emails, all owned repos, installations, orgs,
                       codespaces, per-repo hooks / deploy keys / runners / secret names / collaborators /
                       invitations / branches / workflows / runs / environments / pages, private events.
                       Otherwise every C check is recorded as needs_consent ("waiting for gh login").
    D  Manual          inventory.manualChecks, built from S13-github-npm-manual.json.

    Safety
      * Every HTTP request goes through Invoke-BvsIntel (host allowlist). gh is used only for
        `gh auth status` and `gh api --method GET`. Never `gh auth token`; never the npm CLI.
      * The npm token is read from the user .npmrc in memory, sent only in an Authorization header
        (responses not saved) and never printed, logged or stored.
      * Indicators live in S13-github-npm-iocs.json (data, not logic).

    Contract: docs\schema.md   Rules: docs\agent-rules.md   Playbook: docs\playbooks\S13-github-npm.md

.PARAMETER Authenticated
    Declare that the authenticated GitHub part is expected (re-run after the user logged in with gh).
    Detection still decides: if `gh auth status` fails, the C checks are recorded as needs_consent.
.PARAMETER PublicOnly
    Never call gh; the C checks are recorded as skipped.
.PARAMETER GitHubUser
    GitHub login to audit. Default: environment BVS_GITHUB_USER, the gh account, then the github.com
    owner of local repos that matches git user.name, then the most common owner.
.PARAMETER NpmPackage
    npm package name(s) to audit. Default: non-private local packages with bin/publishConfig in the
    user's repos, plus packages returned by the npm maintainer search.
.PARAMETER RepoPath
    Extra local git repositories to consider besides the discovered ones.
.PARAMETER ReuseIntelMinutes
    Reuse saved intel responses younger than this (unauthenticated requests only). Rate-limited
    GitHub requests always fall back to a cached response younger than 24 hours.
.PARAMETER TarballCount
    Number of most recently published versions to download and list (default 2).
.PARAMETER MaxRepos
    Upper bound on repos examined by the authenticated per-repo checks.
.PARAMETER RecentDays
    Window for "recently created" repos, gists, keys and tokens (default 30).
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S13-github-npm.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S13-github-npm.ps1 -Authenticated
#>
[CmdletBinding()]
param(
    [switch]$Authenticated,
    [switch]$PublicOnly,
    [string]$GitHubUser,
    [string[]]$NpmPackage,
    [string[]]$RepoPath,
    [ValidateRange(0, 1440)][int]$ReuseIntelMinutes = 0,
    [ValidateRange(0, 5)][int]$TarballCount = 2,
    [ValidateRange(1, 500)][int]$MaxRepos = 200,
    [ValidateRange(1, 365)][int]$RecentDays = 30
)

Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$script:S13 = @{
    Root       = Get-BvsRoot
    Now        = [datetime]::UtcNow
    ReuseMin   = $ReuseIntelMinutes
    RecentDays = $RecentDays
    Requests   = [ordered]@{}
    GhCalls    = 0
    GhReady    = $false
    Run        = $null
}
$script:Ctx = @{
    Iocs           = $null
    GitHubUser     = $null
    GitHubUserFrom = $null
    GhAuth         = $null
    Repos          = @()
    Identity       = $null
    Baseline       = $null
    LocalSsh       = @()
    LocalPackages  = @()
    NpmUser        = $null
    NpmTokenState  = 'absent'
    NpmRcFacts     = @()
    Packuments     = @{}
    NpmTargets     = @()
    Owned          = @{}
    RepoSync       = @{}
    ReportedKeys   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    ReportedRepos  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    ReportedEvents = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    UnknownKeys    = @()
    Gateway        = $null
}
$script:SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$script:GhApiHeaders = @{ 'Accept' = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
$script:NpmToken = $null

#region ---------- generic helpers ----------

function ConvertFrom-S13Json {
    <# Parse JSON keeping arrays as arrays and dates as strings. Returns $null for non-JSON. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim().TrimStart([char]0xFEFF)
    if (-not ($t.StartsWith('{') -or $t.StartsWith('['))) { return $null }
    $obj = $null
    try { $obj = ConvertFrom-Json -InputObject $t -NoEnumerate -Depth 100 -DateKind String }
    catch [System.Management.Automation.ParameterBindingException] {
        try { $obj = ConvertFrom-Json -InputObject $t -NoEnumerate -Depth 100 } catch { return $null }
    }
    catch { return $null }
    , $obj
}

function ConvertTo-S13Array {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [array]) { return , $Value }
    , @($Value)
}

function ConvertTo-S13Date {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $dto.UtcDateTime }
    $null
}

function Format-S13Date {
    param([AllowNull()]$Value)
    $d = ConvertTo-S13Date $Value
    if ($null -eq $d) { return $null }
    $d.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-S13AgeDays {
    param([AllowNull()]$Value)
    $d = ConvertTo-S13Date $Value
    if ($null -eq $d) { return $null }
    [math]::Round(($script:S13.Now - $d).TotalDays, 1)
}

function Get-S13LocalHour {
    param([datetime]$Utc)
    [TimeZoneInfo]::ConvertTimeFromUtc([datetime]::SpecifyKind($Utc, [DateTimeKind]::Utc), [TimeZoneInfo]::Local).Hour
}

function Get-S13MaxSeverity {
    param([string[]]$Severities)
    $best = 'info'
    foreach ($s in $Severities) { if ($s -and $script:SevRank.ContainsKey($s) -and $script:SevRank[$s] -gt $script:SevRank[$best]) { $best = $s } }
    $best
}

function Limit-S13Severity {
    param([string]$Severity, [string]$Cap)
    if ($Cap -and $script:SevRank.ContainsKey($Cap) -and $script:SevRank[$Severity] -gt $script:SevRank[$Cap]) { return $Cap }
    $Severity
}

function ConvertTo-S13SemverKey {
    param([string]$Version)
    $m = [regex]::Match([string]$Version, '^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?')
    if (-not $m.Success) { return '0000000000.0000000000.0000000000.0' }
    $pre = if ($m.Groups[4].Success) { '0' + $m.Groups[4].Value } else { '1' }
    '{0:D10}.{1:D10}.{2:D10}.{3}' -f [long]$m.Groups[1].Value, [long]$m.Groups[2].Value, [long]$m.Groups[3].Value, $pre
}

function Get-S13SafeName {
    param([string]$Text)
    $s = ($Text -replace '[^A-Za-z0-9._-]', '_')
    # Windows limits a file name to 255 characters. A long name is cut and kept unique with a short hash.
    if ($s.Length -gt 120) {
        $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-', '').Substring(0, 12).ToLowerInvariant()
        $ext = if ($s -match '(\.[A-Za-z0-9]{1,5})$') { $Matches[1] } else { '' }
        $s = $s.Substring(0, 100) + '_' + $h + $ext
    }
    $s
}

function Find-S13Expected {
    <# Look up config\local\expected.json (category + value). Any string/array property of 'match' is a candidate; 'regex' is a pattern. #>
    param([Parameter(Mandatory)][string]$Category, [AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    foreach ($e in @(Get-BvsExpected -Category $Category)) {
        $m = $e.match
        if ($null -eq $m) { continue }
        foreach ($p in $m.PSObject.Properties) {
            if ($p.Name -match '(?i)regex$') {
                if ($Value -match [string]$p.Value) { return $e }
                continue
            }
            foreach ($v in @($p.Value)) {
                if ($v -isnot [string]) { continue }
                if ($v -ieq $Value -or ($v.Contains('*') -and $Value -like $v)) { return $e }
            }
        }
    }
    $null
}

function Add-S13Finding {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('critical', 'high', 'medium', 'low', 'info')][string]$Severity,
        [Parameter(Mandatory)][ValidateSet('compromise', 'suspicious', 'hardening', 'hygiene', 'info')][string]$Class,
        [ValidateSet('high', 'medium', 'low')][string]$Confidence = 'medium',
        [string[]]$Reasons = @(),
        [object[]]$Evidence = @(),
        [System.Collections.IDictionary]$Entities = @{},
        [string]$Recommendation = '',
        [string]$FpNotes = '',
        [string[]]$Mitre = @(),
        [AllowNull()]$ExpectedItem = $null
    )
    $exp = $null
    if ($ExpectedItem) {
        $cap = if ($ExpectedItem.severityCap) { [string]$ExpectedItem.severityCap } else { 'info' }
        $Severity = Limit-S13Severity -Severity $Severity -Cap $cap
        if ($ExpectedItem.class -and [string]$ExpectedItem.class -in 'compromise', 'suspicious', 'hardening', 'hygiene', 'info') { $Class = [string]$ExpectedItem.class }
        $Reasons = @($Reasons) + 'expected_match'
        $exp = [ordered]@{ id = $ExpectedItem.id; reason = $ExpectedItem.reason; invalidIf = @($ExpectedItem.invalidIf); confirmWithUser = [bool]$ExpectedItem.confirmWithUser }
    }
    New-BvsFinding -Run $script:S13.Run -Check $Check -Title $Title -Severity $Severity -Class $Class -Confidence $Confidence -Reasons $Reasons -Evidence $Evidence -Entities $Entities -Recommendation $Recommendation -FpNotes $FpNotes -Mitre $Mitre -Expected $exp
}

function Add-S13Error {
    param([string]$Check, [string]$Message)
    $script:S13.Run.Errors.Add([ordered]@{ check = $Check; error = (Protect-BvsText $Message); at = [datetime]::UtcNow.ToString('o') })
    Write-BvsLog -Run $script:S13.Run -Level WARN -Message "$Check : $Message"
}

#endregion

#region ---------- network helpers ----------

function Get-S13CachedIntel {
    param([string]$HostName, [string]$SafeName, [int]$MaxAgeMinutes, [switch]$Binary)
    if ($MaxAgeMinutes -le 0) { return $null }
    $folder = Join-Path $script:S13.Root ('intel\' + ($HostName -replace '[^A-Za-z0-9.-]', '_'))
    if (-not [IO.Directory]::Exists($folder)) { return $null }
    $cut = [datetime]::UtcNow.AddMinutes(-$MaxAgeMinutes)
    $cands = @(Get-ChildItem -LiteralPath $folder -File -Filter "*-$SafeName" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $cut } | Sort-Object LastWriteTimeUtc -Descending)
    foreach ($c in $cands) {
        $metaPath = $c.FullName + '.meta.json'
        if (-not [IO.File]::Exists($metaPath)) { continue }
        $meta = ConvertFrom-S13Json ([IO.File]::ReadAllText($metaPath))
        if ($null -eq $meta -or [int]$meta.status -ne 200) { continue }
        $text = $null; $bytes = $null; $data = $null
        if ($Binary) { $bytes = [IO.File]::ReadAllBytes($c.FullName) }
        else { $text = [IO.File]::ReadAllText($c.FullName); $data = ConvertFrom-S13Json $text }
        return [pscustomobject]@{ Status = 200; Text = $text; Bytes = $bytes; Data = $data; File = $c.FullName; FromCache = $true; Stale = $false; RateLimited = $false; CachedAt = (Format-S13Date $c.LastWriteTimeUtc) }
    }
    $null
}

function Invoke-S13Web {
    <# Invoke-BvsIntel plus an optional response cache (unauthenticated requests only) and rate-limit fallback. #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$SaveName,
        [hashtable]$Headers,
        [switch]$NoSave,
        [switch]$Binary,
        [int]$TimeoutSec = 30,
        [long]$MaxBytes = 50MB
    )
    $hostName = ([uri]$Uri).Host.ToLowerInvariant()
    $safe = Get-S13SafeName $SaveName
    $cacheable = (-not $NoSave) -and -not ($Headers -and $Headers.ContainsKey('Authorization'))
    if ($cacheable -and $script:S13.ReuseMin -gt 0) {
        $c = Get-S13CachedIntel -HostName $hostName -SafeName $safe -MaxAgeMinutes $script:S13.ReuseMin -Binary:$Binary
        if ($c) { return $c }
    }
    $r = $null
    try { $r = Invoke-BvsIntel -Uri $Uri -SaveName $safe -Headers $Headers -NoSave:$NoSave -TimeoutSec $TimeoutSec -MaxBytes $MaxBytes }
    catch {
        if ($cacheable) {
            $c = Get-S13CachedIntel -HostName $hostName -SafeName $safe -MaxAgeMinutes 1440 -Binary:$Binary
            if ($c) { $c.Stale = $true; return $c }
        }
        throw
    }
    if (-not $script:S13.Requests.Contains($hostName)) { $script:S13.Requests[$hostName] = 0 }
    $script:S13.Requests[$hostName] = $script:S13.Requests[$hostName] + 1
    $isBytes = $r.Content -is [byte[]]
    $text = if ($isBytes) { $null } else { [string]$r.Content }
    $bytes = if ($isBytes) { [byte[]]$r.Content } else { $null }
    $limited = ($r.Status -in 403, 429) -and ([string]$text -match '(?i)rate limit')
    if ($limited -and $cacheable) {
        $c = Get-S13CachedIntel -HostName $hostName -SafeName $safe -MaxAgeMinutes 1440 -Binary:$Binary
        if ($c) { $c.Stale = $true; $c.RateLimited = $true; return $c }
    }
    $data = $null
    if ($text) { $data = ConvertFrom-S13Json $text }
    [pscustomobject]@{ Status = [int]$r.Status; Text = $text; Bytes = $bytes; Data = $data; File = $r.File; FromCache = $false; Stale = $false; RateLimited = $limited; CachedAt = $null }
}

function Invoke-S13GitHubPublic {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$SaveName)
    Invoke-S13Web -Uri ('https://api.github.com/' + $Path.TrimStart('/')) -SaveName $SaveName -Headers $script:GhApiHeaders
}

function Get-S13GitHubPublicPaged {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$SaveBase, [int]$PerPage = 100, [int]$MaxPages = 3)
    $items = [System.Collections.Generic.List[object]]::new()
    $info = [ordered]@{ pages = 0; status = $null; fromCache = $false; stale = $false; rateLimited = $false; truncated = $false; error = $null }
    $sep = if ($Path.Contains('?')) { '&' } else { '?' }
    for ($p = 1; $p -le $MaxPages; $p++) {
        $r = Invoke-S13GitHubPublic -Path ('{0}{1}per_page={2}&page={3}' -f $Path, $sep, $PerPage, $p) -SaveName ('{0}-p{1}.json' -f $SaveBase, $p)
        $info.status = $r.Status
        if ($r.FromCache) { $info.fromCache = $true }
        if ($r.Stale) { $info.stale = $true }
        if ($r.RateLimited) {
            $info.rateLimited = $true
            if (-not $r.FromCache) { $info.error = 'GitHub API rate limit reached'; break }
        }
        if ($r.Status -eq 422 -and $p -gt 1) { break }
        if ($r.Status -ne 200) { $info.error = "HTTP $($r.Status)"; break }
        $page = ConvertTo-S13Array $r.Data
        $info.pages = $p
        foreach ($i in $page) { $items.Add($i) }
        if ($page.Count -lt $PerPage) { break }
        if ($p -eq $MaxPages) { $info.truncated = $true }
    }
    [pscustomobject]@{ Items = $items.ToArray(); Info = $info }
}

function Set-S13StatusFromWeb {
    <# Downgrade a check to partial when data came from cache or the API was rate limited. #>
    param([string]$Id, [object[]]$Infos)
    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($i in $Infos) {
        if ($null -eq $i) { continue }
        if ($i.rateLimited -and -not $i.fromCache) { $notes.Add('GitHub API rate limit reached (unauthenticated limit is 60 requests/hour)') }
        elseif ($i.stale) { $notes.Add('rate limited or offline: used a cached response younger than 24 h') }
        if ($i.truncated) { $notes.Add('result truncated at the page limit') }
        if ($i.error -and -not $i.rateLimited) { $notes.Add([string]$i.error) }
    }
    if ($notes.Count) { Set-BvsCheckStatus -Id $Id -Status partial -Reason (($notes | Select-Object -Unique) -join '; ') }
}

#endregion

#region ---------- GitHub CLI (read-only) ----------

function Initialize-S13Gh {
    $exe = Join-Path $script:S13.Root 'vendor\gh\bin\gh.exe'
    $info = [ordered]@{ path = $exe; present = $false; signature = $null; signer = $null; version = $null; configDir = (Join-Path (Get-BvsRoot) 'vendor\gh-config'); tokenEnvCleared = @(); usable = $false; reason = $null }
    if (-not [IO.File]::Exists($exe)) { $info.reason = 'GitHub CLI not found at vendor\gh\bin\gh.exe'; return [pscustomobject]$info }
    $info.present = $true
    $sig = Get-BvsSignature -Path $exe
    $info.signature = $sig.Status
    $info.signer = $sig.Signer
    if ($sig.Status -ne 'Valid' -or [string]$sig.Signer -notmatch '^GitHub, Inc\.?$') {
        $info.reason = "gh.exe signature not trusted (status $($sig.Status), signer '$($sig.Signer)'); not running it"
        return [pscustomobject]$info
    }
    # In-process only: use the project's gh config dir, keep gh quiet and offline apart from API calls.
    $env:GH_CONFIG_DIR = Join-Path (Get-BvsRoot) 'vendor\gh-config'
    $env:GH_NO_UPDATE_NOTIFIER = '1'
    $env:GH_NO_EXTENSION_UPDATE_NOTIFIER = '1'
    $env:GH_PROMPT_DISABLED = '1'
    $env:GH_SPINNER_DISABLED = '1'
    $env:GH_TELEMETRY = '0'
    $env:DO_NOT_TRACK = '1'
    $env:NO_COLOR = '1'
    $env:XDG_STATE_HOME = Join-Path $env:GH_CONFIG_DIR 'xdg-state'
    $env:XDG_CACHE_HOME = Join-Path $env:GH_CONFIG_DIR 'xdg-cache'
    foreach ($n in 'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN') {
        if ([Environment]::GetEnvironmentVariable($n, 'Process')) { $info.tokenEnvCleared += $n }
    }
    $env:GH_TOKEN = $null
    $env:GITHUB_TOKEN = $null
    $env:GH_ENTERPRISE_TOKEN = $null
    $env:GITHUB_ENTERPRISE_TOKEN = $null
    $env:GH_HOST = $null
    Set-Alias -Name gh -Value $exe -Scope Script
    $info.version = [string](@(gh --version 2>&1) | Select-Object -First 1)
    $info.usable = $true
    $script:S13.GhReady = $true
    [pscustomobject]$info
}

function Get-S13GhAuthStatus {
    $o = [ordered]@{ loggedIn = $false; account = $null; scopes = @(); tokenSource = $null; exitCode = $null; message = $null }
    $raw = @(gh auth status --hostname github.com 2>&1)
    $o.exitCode = $LASTEXITCODE
    $lines = @($raw | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $text = $lines -join "`n"
    if ($text -match '(?m)Logged in to github\.com (?:account|as) ([A-Za-z0-9-]+)(?:\s+\(([^)]*)\))?') {
        $o.account = $Matches[1]
        $src = [string]$Matches[2]
        $o.tokenSource = if (-not $src) { $null } elseif ($src -match '(?i)keyring') { 'keyring' } elseif ($src -match 'GH_TOKEN|GITHUB_TOKEN') { 'environment' } elseif ($src -match '(?i)hosts\.yml') { 'config-file' } else { 'other' }
    }
    if ($text -match "(?m)Token scopes:\s*(.+)$") { $o.scopes = @([regex]::Matches($Matches[1], "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }) }
    $o.loggedIn = ($o.exitCode -eq 0) -and [bool]$o.account
    $o.message = Protect-BvsText (($lines | Select-Object -First 1) -join ' ')
    [pscustomobject]$o
}

function Invoke-S13Gh {
    <# Read-only GitHub REST call through the vendored gh. GET only; the path must be a REST path (no GraphQL). #>
    param([Parameter(Mandatory)][string]$Path, [switch]$Paginate)
    if (-not $script:S13.GhReady) { throw 'GitHub CLI is not initialised' }
    if ($Path -match '(?i)graphql' -or $Path -notmatch '^(user|users|repos|orgs|gists|rate_limit)(/[A-Za-z0-9._%-]+)*/?(\?[A-Za-z0-9=&_.,:%+-]*)?$') {
        throw "Refusing gh api path '$Path' (not a read-only REST path)"
    }
    if ($Paginate) {
        $raw = @(gh api --method GET --paginate --slurp -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' $Path 2>&1)
    }
    else {
        $raw = @(gh api --method GET -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' $Path 2>&1)
    }
    $code = $LASTEXITCODE
    $script:S13.GhCalls++
    $out = [Text.StringBuilder]::new()
    $err = [Text.StringBuilder]::new()
    foreach ($line in $raw) {
        if ($line -is [System.Management.Automation.ErrorRecord]) { [void]$err.AppendLine([string]$line) } else { [void]$out.AppendLine([string]$line) }
    }
    $errText = $err.ToString()
    $status = if ($errText -match '\(HTTP (\d{3})\)') { [int]$Matches[1] } elseif ($code -eq 0) { 200 } else { 0 }
    $data = ConvertFrom-S13Json $out.ToString()
    if ($Paginate -and $code -eq 0 -and $null -ne $data) {
        $flat = [System.Collections.Generic.List[object]]::new()
        foreach ($pg in (ConvertTo-S13Array $data)) {
            if ($pg -is [array]) { foreach ($x in $pg) { $flat.Add($x) }; continue }
            $arrProp = $null
            foreach ($n in 'workflow_runs', 'runners', 'secrets', 'environments', 'installations', 'codespaces', 'artifacts', 'workflows', 'repositories') {
                if ($pg.PSObject.Properties[$n]) { $arrProp = $n; break }
            }
            if ($arrProp) { foreach ($x in @($pg.$arrProp)) { if ($null -ne $x) { $flat.Add($x) } } } else { $flat.Add($pg) }
        }
        $data = $flat.ToArray()
    }
    $msg = $null
    if ($code -ne 0) {
        $msg = (($errText.Trim() -split "`r?`n") | Select-Object -First 2) -join ' '
        if (-not $msg -and $null -ne $data -and $data -isnot [array] -and $data.message) { $msg = [string]$data.message }
        $msg = Protect-BvsText $msg
    }
    [pscustomobject]@{ Ok = ($code -eq 0); Status = $status; Data = $data; Error = $msg }
}

#endregion

#region ---------- local facts ----------

function Get-S13SshKeyFacts {
    param([AllowNull()][AllowEmptyString()][string]$Line, [string]$Source)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    $t = $Line.Trim()
    if ($t.StartsWith('#')) { return $null }
    $m = [regex]::Match($t, '(?<type>(?:sk-)?(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521))(?:@openssh\.com)?)\s+(?<b64>[A-Za-z0-9+/]{16,}={0,3})(?:\s+(?<comment>.*))?$')
    if (-not $m.Success) { return $null }
    $blob = $null
    try { $blob = [Convert]::FromBase64String($m.Groups['b64'].Value) } catch { return $null }
    $fp = 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($blob)).TrimEnd('=')
    [pscustomobject][ordered]@{ type = $m.Groups['type'].Value; fingerprint = $fp; comment = $m.Groups['comment'].Value.Trim(); source = $Source }
}

function Get-S13LocalSshKeys {
    $folder = Join-Path $env:USERPROFILE '.ssh'
    $list = [System.Collections.Generic.List[object]]::new()
    if (-not [IO.Directory]::Exists($folder)) { return , $list.ToArray() }
    foreach ($f in @(Get-ChildItem -LiteralPath $folder -File -Filter '*.pub' -Force -ErrorAction SilentlyContinue)) {
        if (Test-BvsNeverRead $f.FullName) { continue }
        foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
            $k = Get-S13SshKeyFacts -Line $line -Source $f.Name
            if ($null -eq $k) { continue }
            $k | Add-Member -NotePropertyName path -NotePropertyValue $f.FullName
            $k | Add-Member -NotePropertyName modified -NotePropertyValue (Format-S13Date $f.LastWriteTimeUtc)
            $list.Add($k)
        }
    }
    , $list.ToArray()
}

function Get-S13KnownHostNames {
    $p = Join-Path $env:USERPROFILE '.ssh\known_hosts'
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not [IO.File]::Exists($p) -or (Test-BvsNeverRead $p)) { return , @() }
    foreach ($line in [IO.File]::ReadAllLines($p)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#') -or $t.StartsWith('|') -or $t.StartsWith('@')) { continue }
        $hostField = ($t -split '\s+')[0]
        foreach ($h in $hostField.Split(',')) { [void]$names.Add(($h -replace '^\[([^\]]+)\](:\d+)?$', '$1')) }
    }
    , @($names)
}

function Get-S13GitHubRemote {
    param([string]$Url)
    if ($Url -match 'github\.com[:/]+(?<owner>[A-Za-z0-9-]+)/(?<name>[A-Za-z0-9._-]+?)(?:\.git)?/?$') { return [pscustomobject]@{ owner = $Matches['owner']; name = $Matches['name'] } }
    $null
}

function Find-S13LocalRepos {
    param([string[]]$Extra)
    $userHome = $env:USERPROFILE
    $roots = [System.Collections.Generic.List[string]]::new()
    $cands = @([Environment]::GetFolderPath('MyDocuments')) + @('Documents', 'source\repos', 'repos', 'projects', 'code', 'dev', 'src', 'git', 'GitHub', 'Desktop' | ForEach-Object { Join-Path $userHome $_ })
    foreach ($c in $cands) {
        if ($c -and [IO.Directory]::Exists($c) -and -not ($roots | Where-Object { $_ -ieq $c })) { $roots.Add($c) }
    }
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @($Extra)) {
        if ($x -and [IO.Directory]::Exists((Join-Path $x '.git'))) { [void]$set.Add([IO.Path]::GetFullPath($x).TrimEnd('\')) }
    }
    foreach ($r in $roots) {
        foreach ($d in (Get-BvsFiles -Path $r -Directories -MaxDepth 3)) {
            if ($d -is [IO.DirectoryInfo] -and $d.Name -eq '.git') { [void]$set.Add($d.Parent.FullName.TrimEnd('\')) }
        }
    }
    $own = $script:S13.Root.TrimEnd('\')
    $repos = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $set) {
        if ($p -ieq $own -or $p.StartsWith($own + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $remotes = [System.Collections.Generic.List[object]]::new()
        foreach ($line in @(git --no-optional-locks -C $p config --get-regexp '^remote\..*\.url$' 2>$null)) {
            if ([string]$line -match '^remote\.(?<r>.+?)\.url\s+(?<u>\S+)$') {
                $rn = $Matches['r']; $ru = $Matches['u']
                $g = Get-S13GitHubRemote $ru
                $remotes.Add([pscustomobject][ordered]@{ remote = $rn; url = (Protect-BvsUrl $ru); githubOwner = $g.owner; githubRepo = $g.name })
            }
        }
        $email = [string](@(git --no-optional-locks -C $p config --get user.email 2>$null) | Select-Object -First 1)
        $repos.Add([pscustomobject][ordered]@{ path = $p; remotes = $remotes.ToArray(); email = $email; owned = $false; packages = @() })
    }
    , $repos.ToArray()
}

function Get-S13RepoPackages {
    param([string]$Repo)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($f in (Get-BvsFiles -Path $Repo -Include 'package.json' -MaxDepth 3)) {
        if ($f -isnot [IO.FileInfo] -or (Test-BvsNeverRead $f.FullName)) { continue }
        $j = $null
        try { $j = ConvertFrom-S13Json ([IO.File]::ReadAllText($f.FullName)) } catch { $j = $null }
        if ($null -eq $j -or $j -is [array] -or -not $j.name) { continue }
        $rel = [IO.Path]::GetRelativePath($Repo, $f.FullName) -replace '\\', '/'
        $list.Add([pscustomobject][ordered]@{
                name                 = [string]$j.name
                version              = [string]$j.version
                private              = [bool]$j.private
                publishable          = (-not [bool]$j.private) -and (($null -ne $j.bin) -or ($null -ne $j.publishConfig))
                repo                 = $Repo
                relPath              = $rel
                folder               = $f.DirectoryName
                files                = @($j.files | Where-Object { $_ })
                scripts              = $j.scripts
                main                 = $j.main
                bin                  = $j.bin
                dependencies         = $j.dependencies
                optionalDependencies = $j.optionalDependencies
                history              = $null
            })
    }
    , $list.ToArray()
}

function Get-S13PackageHistory {
    <# package.json content at every commit that touched it (name, version, scripts, files). #>
    param([string]$Repo, [string]$RelPath, [int]$Max = 150)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($l in @(git --no-optional-locks -C $Repo log '--format=%H|%cI|%aI|%an' -n $Max -- $RelPath 2>$null)) {
        $p = ([string]$l).Split('|')
        if ($p.Count -lt 3) { continue }
        $raw = @(git --no-optional-locks -C $Repo show ($p[0] + ':' + $RelPath) 2>$null) -join "`n"
        $j = ConvertFrom-S13Json $raw
        if ($null -eq $j -or $j -is [array]) { continue }
        $list.Add([pscustomobject][ordered]@{
                commit = $p[0]; committed = (ConvertTo-S13Date $p[1]); authored = (ConvertTo-S13Date $p[2]); author = $(if ($p.Count -gt 3) { $p[3] } else { $null })
                name = [string]$j.name; version = [string]$j.version; scripts = $j.scripts; files = @($j.files | Where-Object { $_ })
                main = $j.main; bin = $j.bin; dependencies = $j.dependencies; optionalDependencies = $j.optionalDependencies
            })
    }
    , $list.ToArray()
}

function Get-S13RepoTags {
    param([string]$Repo)
    $names = @(git --no-optional-locks -C $Repo tag -l 2>$null | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $refs = [System.Collections.Generic.List[object]]::new()
    foreach ($l in @(git --no-optional-locks -C $Repo for-each-ref '--format=%(refname:short)|%(objecttype)|%(creatordate:iso-strict)|%(objectname)|%(*objectname)' refs/tags 2>$null)) {
        $p = ([string]$l).Split('|')
        if ($p.Count -lt 4) { continue }
        $refs.Add([pscustomobject][ordered]@{ tag = $p[0]; type = $p[1]; date = (Format-S13Date $p[2]); object = $p[3]; commit = $(if ($p.Count -gt 4 -and $p[4]) { $p[4] } else { $p[3] }) })
    }
    [pscustomobject]@{ names = $names; refs = $refs.ToArray() }
}

function Get-S13CommitBaseline {
    <# Hour-of-day histogram (local time) of the user's own commits across local repos: "usual working hours". #>
    param([object[]]$Repos, [string[]]$Names, [string[]]$Emails, [int]$Days = 365)
    $hist = [int[]]::new(24)
    $times = [System.Collections.Generic.List[datetime]]::new()
    $nameSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($Names)) { if ($n) { [void]$nameSet.Add($n) } }
    $mailSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @($Emails)) { if ($e) { [void]$mailSet.Add($e) } }
    foreach ($r in $Repos) {
        foreach ($l in @(git --no-optional-locks -C $r.path log --all "--since=$Days.days" '--format=%aI|%ae|%an' -n 3000 2>$null)) {
            $p = ([string]$l).Split('|')
            if ($p.Count -lt 3) { continue }
            if (-not ($mailSet.Contains($p[1]) -or $nameSet.Contains($p[2]))) { continue }
            $dto = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse($p[0], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dto)) { continue }
            $hist[[TimeZoneInfo]::ConvertTime($dto, [TimeZoneInfo]::Local).Hour]++
            $times.Add($dto.UtcDateTime)
        }
    }
    $times.Sort()
    [pscustomobject]@{ days = $Days; timeZone = [TimeZoneInfo]::Local.Id; total = $times.Count; hourHistogram = $hist; timesUtc = $times.ToArray() }
}

function Test-S13UsualHour {
    <# $true / $false, or $null when the baseline is too small (< 20 commits). Neighbouring hours count as usual. #>
    param($Baseline, [datetime]$Utc)
    if ($null -eq $Baseline -or $Baseline.total -lt 20) { return $null }
    $h = Get-S13LocalHour $Utc
    $s = $Baseline.hourHistogram[($h + 23) % 24] + $Baseline.hourHistogram[$h] + $Baseline.hourHistogram[($h + 1) % 24]
    $s -gt 0
}

function Get-S13NearestCommitHours {
    param($Baseline, [datetime]$Utc)
    if ($null -eq $Baseline -or $Baseline.total -eq 0) { return $null }
    $best = [double]::MaxValue
    foreach ($t in $Baseline.timesUtc) { $d = [math]::Abs(($t - $Utc).TotalHours); if ($d -lt $best) { $best = $d } }
    [math]::Round($best, 1)
}

function Get-S13NpmrcFacts {
    <# Key names, token classes (never values), strict-ssl, registry overrides of one npmrc file. #>
    param([string]$Path, [string]$Scope)
    $o = [ordered]@{ scope = $Scope; path = $Path; exists = $false; modified = $null; tokens = @(); strictSsl = $null; registry = $null; ignoreScripts = $null; scopedRegistries = @(); keys = @() }
    if (-not $Path -or -not [IO.File]::Exists($Path) -or (Test-BvsNeverRead $Path)) { return [pscustomobject]$o }
    $o.exists = $true
    $o.modified = Format-S13Date ([IO.File]::GetLastWriteTimeUtc($Path))
    $tokens = [System.Collections.Generic.List[object]]::new()
    $scoped = [System.Collections.Generic.List[object]]::new()
    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#') -or $l.StartsWith(';')) { continue }
        $eq = $l.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $l.Substring(0, $eq).Trim()
        $v = $l.Substring($eq + 1).Trim().Trim('"', "'")
        $keys.Add($k)
        $field = $null; $reg = $null
        if ($k -match '^(?<reg>//.+?):(?<field>_authToken|_auth|_password)$') { $field = $Matches['field']; $reg = $Matches['reg'] }
        elseif ($k -match '^(?<field>_authToken|_auth|_password)$') { $field = $Matches['field']; $reg = '(default registry)' }
        if ($field) {
            $cls = 'opaque'
            if ($v -match '^\$\{[A-Za-z0-9_]+\}$') { $cls = 'env-reference' }
            elseif ($v.StartsWith('npm_')) { $cls = 'npm_' }
            elseif ($v.StartsWith('github_pat_')) { $cls = 'github_pat_' }
            elseif ($v.StartsWith('ghp_')) { $cls = 'ghp_' }
            elseif ($v.StartsWith('gho_')) { $cls = 'gho_' }
            elseif ($v.StartsWith('glpat-')) { $cls = 'glpat-' }
            $tokens.Add([pscustomobject][ordered]@{ registry = $reg; field = $field; class = $cls; length = $v.Length; plaintext = ($cls -ne 'env-reference') })
            continue
        }
        switch -Regex ($k) {
            '^strict-ssl$' { $o.strictSsl = $v; break }
            '^registry$' { $o.registry = Protect-BvsUrl $v; break }
            '^ignore-scripts$' { $o.ignoreScripts = $v; break }
            '^@[^:]+:registry$' { $scoped.Add([pscustomobject]@{ scope = ($k -replace ':registry$', ''); registry = (Protect-BvsUrl $v) }); break }
        }
    }
    $v = $null
    $o.tokens = $tokens.ToArray()
    $o.scopedRegistries = $scoped.ToArray()
    $o.keys = @($keys | Select-Object -Unique)
    [pscustomobject]$o
}

function Get-S13NpmRegistryToken {
    <# The registry.npmjs.org token from one npmrc, in memory only. Never log or store the return value. #>
    param([string]$Path)
    if (-not $Path -or -not [IO.File]::Exists($Path) -or (Test-BvsNeverRead $Path)) { return $null }
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $l = $line.Trim()
        if (-not $l.StartsWith('//registry.npmjs.org/:_authToken', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $eq = $l.IndexOf('=')
        if ($eq -lt 0) { continue }
        $v = $l.Substring($eq + 1).Trim().Trim('"', "'")
        if ($v.StartsWith('${') -and $v.EndsWith('}')) { $v = [Environment]::GetEnvironmentVariable($v.Substring(2, $v.Length - 3), 'Process') }
        if ($v) { return $v }
    }
    $null
}

function Get-S13DefaultGateway {
    try {
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch '(?i)tailscale|virtualbox|vethernet|wsl|docker|loopback|vpn|zerotier|wireguard' } |
                Sort-Object RouteMetric)
        if ($routes.Count) { return [string]$routes[0].NextHop }
    }
    catch { }
    $null
}

function Get-S13GitBlobSha {
    param([string]$Path)
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $hdr = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
        $all = [byte[]]::new($hdr.Length + $bytes.Length)
        [Array]::Copy($hdr, 0, $all, 0, $hdr.Length)
        [Array]::Copy($bytes, 0, $all, $hdr.Length, $bytes.Length)
        [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($all)).ToLowerInvariant()
    }
    catch { $null }
}

#endregion

#region ---------- analysis helpers ----------

function Get-S13RepoFlags {
    param($Repo)
    $flags = [System.Collections.Generic.List[object]]::new()
    $iocs = $script:Ctx.Iocs
    $name = [string]$Repo.name
    $desc = ([string]$Repo.description).Trim()
    foreach ($i in @($iocs.repoNames)) {
        if ($name -match [string]$i.regex) { $flags.Add([pscustomobject]@{ kind = 'ioc_name'; severity = [string]$i.severity; family = [string]$i.family; detail = "name matches $($i.regex)" }) }
    }
    if ($desc) {
        $exact = $false
        foreach ($i in @($iocs.repoDescriptions | Where-Object { $_.equals })) {
            if ($desc -ieq [string]$i.equals) { $exact = $true; $flags.Add([pscustomobject]@{ kind = 'ioc_description'; severity = [string]$i.severity; family = [string]$i.family; detail = "description equals '$($i.equals)'" }) }
        }
        if (-not $exact) {
            foreach ($i in @($iocs.repoDescriptions | Where-Object { $_.contains })) {
                if ($desc.IndexOf([string]$i.contains, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $flags.Add([pscustomobject]@{ kind = 'description_mention'; severity = [string]$i.severity; family = [string]$i.family; detail = "description mentions '$($i.contains)'" }); break }
            }
        }
    }
    if ($iocs.migrationSuffixRegex -and $name -match [string]$iocs.migrationSuffixRegex) {
        $flags.Add([pscustomobject]@{ kind = 'migration_suffix'; severity = 'high'; family = 'Shai-Hulud 1.0 (private repo copied to public)'; detail = "name ends with '-migration'" })
    }
    $rr = $iocs.randomRepoName
    if ($rr -and $name -cmatch [string]$rr.regex) {
        $chars = $name.ToCharArray()
        $digits = @($chars | Where-Object { [char]::IsDigit($_) }).Count
        $letters = $name.Length - $digits
        $vowels = @($chars | Where-Object { 'aeiou'.Contains([string]$_) }).Count
        $ratio = if ($letters -gt 0) { $vowels / $letters } else { 1 }
        if ($digits -ge [int]$rr.minDigits -and $letters -ge [int]$rr.minLetters -and $ratio -le [double]$rr.maxVowelRatio) {
            $flags.Add([pscustomobject]@{ kind = 'random_name'; severity = 'high'; family = [string]$rr.family; detail = ("random-looking 18-character name ({0} digits, vowel ratio {1:N2})" -f $digits, $ratio) })
        }
    }
    $age = Get-S13AgeDays $Repo.created_at
    if ($null -ne $age -and $age -le $script:S13.RecentDays) { $flags.Add([pscustomobject]@{ kind = 'recent'; severity = 'low'; family = $null; detail = "created $age days ago" }) }
    , $flags.ToArray()
}

function Get-S13RepoRow {
    param($Repo, [object[]]$Flags)
    [ordered]@{
        name = [string]$Repo.full_name; private = [bool]$Repo.private; visibility = [string]$Repo.visibility; fork = [bool]$Repo.fork
        archived = [bool]$Repo.archived; created = (Format-S13Date $Repo.created_at); pushed = (Format-S13Date $Repo.pushed_at)
        description = [string]$Repo.description; defaultBranch = [string]$Repo.default_branch; sizeKb = $Repo.size; hasPages = [bool]$Repo.has_pages
        flags = @($Flags | ForEach-Object { $_.kind })
    }
}

function Add-S13RepoFindings {
    <# Findings for a list of GitHub repos (public or authenticated). Each repo is reported once per run. #>
    param([object[]]$Repos, [string]$Check)
    $rows = [System.Collections.Generic.List[object]]::new()
    $recent = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Repos) {
        $flags = Get-S13RepoFlags $r
        $rows.Add((Get-S13RepoRow -Repo $r -Flags $flags))
        $full = [string]$r.full_name
        if ($script:Ctx.ReportedRepos.Contains($full)) { continue }
        $kinds = @($flags | ForEach-Object { $_.kind })
        $ev = [ordered]@{ type = 'github_repo'; name = $full; url = [string]$r.html_url; private = [bool]$r.private; fork = [bool]$r.fork; created = (Format-S13Date $r.created_at); pushed = (Format-S13Date $r.pushed_at); description = [string]$r.description; details = @($flags | ForEach-Object { $_.detail }) }
        $exp = Find-S13Expected -Category 'githubRepo' -Value ([string]$r.name)
        if (-not $exp) { $exp = Find-S13Expected -Category 'githubRepo' -Value $full }
        $ent = @{ accounts = @([ordered]@{ type = 'github'; login = [string]$r.owner.login }) }
        if ($kinds -contains 'ioc_name' -or $kinds -contains 'ioc_description') {
            $fam = (@($flags | Where-Object { $_.kind -in 'ioc_name', 'ioc_description' } | ForEach-Object { $_.family }) | Select-Object -Unique) -join ', '
            [void]$script:Ctx.ReportedRepos.Add($full)
            Add-S13Finding -Check $Check -Title "GitHub repo '$full' matches worm exfiltration indicators ($fam)" -Severity critical -Class compromise -Confidence high `
                -Reasons @('intel_match', 'exfil_repo') -Evidence @($ev) -Entities $ent -ExpectedItem $exp -Mitre @('T1567.001', 'T1195.002') `
                -FpNotes 'Only exact campaign repo names/descriptions are matched. A security researcher could create such a repo deliberately (e.g. a lab copy); confirm you did not create it yourself.' `
                -Recommendation 'Treat as an active credential theft. Make the repo private at once (it may hold your secrets, base64-encoded), keep a copy for evidence, then rotate every credential reachable from this machine and CI: GitHub tokens/SSH keys, npm tokens, cloud keys, .env secrets. Review the GitHub security log (repo.create, oauth_authorization.create, public_key.create) and follow a current Shai-Hulud / s1ngularity incident guide. Do not reinstall dependencies with lifecycle scripts enabled until cleaned.'
            continue
        }
        if ($kinds -contains 'migration_suffix') {
            [void]$script:Ctx.ReportedRepos.Add($full)
            Add-S13Finding -Check $Check -Title "GitHub repo '$full' has a '-migration' name (Shai-Hulud 1.0 copied private repos to public '-migration' repos)" -Severity high -Class suspicious -Confidence medium `
                -Reasons @('exfil_repo_pattern') -Evidence @($ev) -Entities $ent -ExpectedItem $exp -Mitre @('T1567.001', 'T1213.003') `
                -FpNotes "You may have named a repo '-migration' yourself (for example during a platform move)." `
                -Recommendation 'Open the repo: if you did not create it (often description "Shai-Hulud Migration" and a copy of a private or organisation repo), make it private, rotate credentials and check the security log (repo.create, repo.access).'
            continue
        }
        if ($kinds -contains 'random_name') {
            $age = Get-S13AgeDays $r.created_at
            $sev = if ($null -ne $age -and $age -le 365) { 'high' } else { 'medium' }
            [void]$script:Ctx.ReportedRepos.Add($full)
            Add-S13Finding -Check $Check -Title "GitHub repo '$full' has a random 18-character name (Shai-Hulud 2.0 exfiltration repos use random names)" -Severity $sev -Class suspicious -Confidence low `
                -Reasons @('random_name') -Evidence @($ev) -Entities $ent -ExpectedItem $exp -Mitre @('T1567.001') `
                -FpNotes 'Some tools and templates create repos with generated names; the heuristic only looks at the name shape.' `
                -Recommendation 'Open the repo and look for files such as cloud.json, contents.json, environment.json, truffleSecrets.json or the description "Sha1-Hulud: The Second Coming.". If you did not create it, make it private and rotate credentials.'
            continue
        }
        if ($kinds -contains 'description_mention') {
            [void]$script:Ctx.ReportedRepos.Add($full)
            Add-S13Finding -Check $Check -Title "GitHub repo '$full' mentions Shai-Hulud in its description" -Severity medium -Class suspicious -Confidence low `
                -Reasons @('description_mention') -Evidence @($ev) -Entities $ent -ExpectedItem $exp -Mitre @('T1567.001') `
                -FpNotes 'A detection tool or research repo of your own would mention the campaign by name; the exact worm descriptions are matched separately.' `
                -Recommendation 'Confirm the repo is yours and intentional; otherwise treat it like a worm repo (make private, rotate credentials).'
            continue
        }
        if ($kinds -contains 'recent' -and -not [bool]$r.private) { $recent.Add($ev) }
    }
    , @($rows.ToArray(), $recent.ToArray())
}

function Measure-S13Events {
    param([object[]]$Events, [string]$Login, $Baseline, [string[]]$KnownEmails, [string[]]$KnownNames)
    $iocs = $script:Ctx.Iocs
    $res = [ordered]@{ count = 0; first = $null; last = $null; byType = [ordered]@{}; publicEvents = @(); repoCreates = @(); createBursts = @(); iocCreates = @(); iocBranches = @(); memberEvents = @(); unusualPushes = @(); foreignAuthors = @(); deletes = @(); baselineUsable = ($null -ne $Baseline -and $Baseline.total -ge 20) }
    $ev = @($Events | Where-Object { $null -ne $_ })
    $res.count = $ev.Count
    if (-not $ev.Count) { return [pscustomobject]$res }
    $dates = @($ev | ForEach-Object { ConvertTo-S13Date $_.created_at } | Where-Object { $_ } | Sort-Object)
    if ($dates.Count) { $res.first = Format-S13Date $dates[0]; $res.last = Format-S13Date $dates[-1] }
    foreach ($g in ($ev | Group-Object type | Sort-Object Count -Descending)) { $res.byType[[string]$g.Name] = $g.Count }
    $mail = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @($KnownEmails)) { if ($e) { [void]$mail.Add($e) } }
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($KnownNames)) { if ($n) { [void]$names.Add($n) } }
    $pub = [System.Collections.Generic.List[object]]::new(); $creates = [System.Collections.Generic.List[object]]::new(); $iocC = [System.Collections.Generic.List[object]]::new()
    $iocB = [System.Collections.Generic.List[object]]::new(); $mem = [System.Collections.Generic.List[object]]::new(); $odd = [System.Collections.Generic.List[object]]::new()
    $foreign = [System.Collections.Generic.List[object]]::new(); $del = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $ev) {
        $t = ConvertTo-S13Date $e.created_at
        $at = Format-S13Date $t
        $repo = [string]$e.repo.name
        $short = ($repo -split '/')[-1]
        $base = [ordered]@{ id = [string]$e.id; type = [string]$e.type; repo = $repo; at = $at; actor = [string]$e.actor.login }
        switch ([string]$e.type) {
            'PublicEvent' { $pub.Add([pscustomobject]$base) }
            'CreateEvent' {
                $rt = [string]$e.payload.ref_type
                if ($rt -eq 'repository') {
                    $creates.Add([pscustomobject]@{ id = $base.id; repo = $repo; at = $at; time = $t; description = [string]$e.payload.description })
                    $fake = [pscustomobject]@{ name = $short; full_name = $repo; description = [string]$e.payload.description; created_at = $at }
                    $hits = @((Get-S13RepoFlags $fake) | Where-Object { $_.kind -in 'ioc_name', 'ioc_description', 'migration_suffix', 'random_name' })
                    if ($hits.Count) { $iocC.Add([pscustomobject]@{ id = $base.id; repo = $repo; at = $at; indicators = @($hits | ForEach-Object { $_.detail }); severity = (Get-S13MaxSeverity @($hits | ForEach-Object { $_.severity })) }) }
                }
                elseif ($rt -eq 'branch') {
                    foreach ($b in @($iocs.branchNames)) {
                        if ([string]$e.payload.ref -match [string]$b.regex) { $iocB.Add([pscustomobject]@{ id = $base.id; repo = $repo; branch = [string]$e.payload.ref; at = $at; family = [string]$b.family; severity = [string]$b.severity }) }
                    }
                }
            }
            'MemberEvent' { $mem.Add([pscustomobject]@{ id = $base.id; repo = $repo; at = $at; action = [string]$e.payload.action; member = [string]$e.payload.member.login }) }
            'DeleteEvent' { $del.Add([pscustomobject]@{ id = $base.id; repo = $repo; at = $at; refType = [string]$e.payload.ref_type; ref = [string]$e.payload.ref }) }
            'PushEvent' {
                $ref = ([string]$e.payload.ref) -replace '^refs/heads/', ''
                foreach ($b in @($iocs.branchNames)) {
                    if ($ref -match [string]$b.regex) { $iocB.Add([pscustomobject]@{ id = $base.id; repo = $repo; branch = $ref; at = $at; family = [string]$b.family; severity = [string]$b.severity }) }
                }
                if ($t -and (Test-S13UsualHour -Baseline $Baseline -Utc $t) -eq $false) { $odd.Add([pscustomobject]@{ id = $base.id; repo = $repo; branch = $ref; at = $at; localHour = (Get-S13LocalHour $t) }) }
                foreach ($c in @($e.payload.commits)) {
                    if ($null -eq $c) { continue }
                    $am = [string]$c.author.email; $an = [string]$c.author.name
                    if (($am -and $mail.Contains($am)) -or ($an -and $names.Contains($an)) -or $am -match '(?i)^\d+\+[^@]+@users\.noreply\.github\.com$|noreply@github\.com$') { continue }
                    $foreign.Add([pscustomobject]@{ id = $base.id; repo = $repo; at = $at; authorName = $an; authorEmailDomain = $(if ($am -match '@(.+)$') { $Matches[1] } else { $null }) })
                }
            }
        }
    }
    # Bursts of repository creation: 4 or more within 60 minutes.
    $sorted = @($creates | Sort-Object time)
    $bursts = [System.Collections.Generic.List[object]]::new()
    $i = 0
    while ($i -lt $sorted.Count) {
        $j = $i
        while ($j + 1 -lt $sorted.Count -and ($sorted[$j + 1].time - $sorted[$i].time).TotalMinutes -le 60) { $j++ }
        $n = $j - $i + 1
        if ($n -ge 4) { $bursts.Add([pscustomobject]@{ start = $sorted[$i].at; end = $sorted[$j].at; count = $n; repos = @($sorted[$i..$j] | ForEach-Object { $_.repo }) }); $i = $j + 1 } else { $i++ }
    }
    $res.publicEvents = $pub.ToArray(); $res.repoCreates = @($creates | ForEach-Object { [ordered]@{ repo = $_.repo; at = $_.at; description = $_.description } }); $res.createBursts = $bursts.ToArray()
    $res.iocCreates = $iocC.ToArray(); $res.iocBranches = $iocB.ToArray(); $res.memberEvents = $mem.ToArray(); $res.unusualPushes = $odd.ToArray()
    $res.foreignAuthors = $foreign.ToArray(); $res.deletes = $del.ToArray()
    [pscustomobject]$res
}

function Add-S13EventFindings {
    param($Measure, [string]$Check, [string]$Scope)
    $ent = @{ accounts = @([ordered]@{ type = 'github'; login = [string]$script:Ctx.GitHubUser }) }
    $newOnly = { param($items) @($items | Where-Object { $_ -and $script:Ctx.ReportedEvents.Add("$Check|$($_.id)") -or ($_ -and -not $_.id) }) }
    $iocC = @(& $newOnly $Measure.iocCreates)
    foreach ($c in $iocC) {
        $sev = if ($c.severity -eq 'critical') { 'critical' } else { 'high' }
        $cls = if ($sev -eq 'critical') { 'compromise' } else { 'suspicious' }
        Add-S13Finding -Check $Check -Title "Repository created with worm indicators: $($c.repo)" -Severity $sev -Class $cls -Confidence $(if ($sev -eq 'critical') { 'high' } else { 'low' }) `
            -Reasons @('intel_match', 'exfil_repo') -Evidence @([ordered]@{ type = 'github_event'; event = 'CreateEvent'; scope = $Scope; repo = $c.repo; at = $c.at; indicators = $c.indicators }) -Entities $ent -Mitre @('T1567.001') `
            -FpNotes 'Matched on the name/description recorded in the creation event; the repo may since have been renamed or deleted.' `
            -Recommendation 'Check the repo (or the security log entry repo.create) and, if not yours, follow the worm incident steps: make private, rotate all credentials, review tokens and keys.'
    }
    foreach ($b in @(& $newOnly $Measure.iocBranches)) {
        Add-S13Finding -Check $Check -Title "Branch '$($b.branch)' created/pushed in $($b.repo) ($($b.family))" -Severity $(if ($b.severity -eq 'critical') { 'critical' } else { 'high' }) -Class $(if ($b.severity -eq 'critical') { 'compromise' } else { 'suspicious' }) -Confidence medium `
            -Reasons @('intel_match') -Evidence @([ordered]@{ type = 'github_event'; scope = $Scope; repo = $b.repo; branch = $b.branch; at = $b.at }) -Entities $ent -Mitre @('T1195.002', 'T1552') `
            -FpNotes 'Branch names are matched exactly against known worm branch names.' `
            -Recommendation 'Inspect the branch for an added workflow that sends secrets out (toJSON(secrets), webhook.site); delete the branch after preserving evidence and rotate the repository/organisation secrets.'
    }
    $pub = @(& $newOnly $Measure.publicEvents)
    if ($pub.Count) {
        $repos = @($pub | ForEach-Object { $_.repo } | Select-Object -Unique)
        $allExpected = $true
        foreach ($rn in $repos) { if (-not (Find-S13Expected -Category 'githubRepo' -Value (($rn -split '/')[-1]))) { $allExpected = $false } }
        Add-S13Finding -Check $Check -Title ("{0} private repo(s) made public in the event window: {1}" -f $repos.Count, ($repos -join ', ')) -Severity $(if ($allExpected) { 'info' } else { 'high' }) -Class suspicious -Confidence low `
            -Reasons @('visibility_change') -Evidence @($pub | ForEach-Object { [ordered]@{ type = 'github_event'; event = 'PublicEvent'; scope = $Scope; repo = $_.repo; at = $_.at } }) -Entities $ent -Mitre @('T1567.001', 'T1213.003') `
            -FpNotes 'Making your own repo public (e.g. to publish a project) produces the same event. Worms (Shai-Hulud migration, s1ngularity) flip private repos to public in bulk.' `
            -Recommendation 'Confirm you made each repo public yourself. If not: make it private again, check its contents for secrets, rotate them, and look for repo.access entries in the security log.'
    }
    foreach ($b in @($Measure.createBursts)) {
        $key = "$Check|burst|$($b.start)"
        if (-not $script:Ctx.ReportedEvents.Add($key)) { continue }
        Add-S13Finding -Check $Check -Title ("Burst of {0} repositories created within 60 minutes ({1})" -f $b.count, $b.start) -Severity high -Class suspicious -Confidence medium `
            -Reasons @('creation_burst') -Evidence @([ordered]@{ type = 'github_event'; event = 'CreateEvent'; scope = $Scope; start = $b.start; end = $b.end; repos = $b.repos }) -Entities $ent -Mitre @('T1567.001') `
            -FpNotes 'Scaffolding several projects at once, or a migration you ran, creates bursts too.' `
            -Recommendation 'Check each repo: worm migrations create many public copies of private/organisation repos at once.'
    }
    $mem = @(& $newOnly @($Measure.memberEvents | Where-Object { $_.action -ne 'removed' }))
    if ($mem.Count) {
        Add-S13Finding -Check $Check -Title ("Collaborator added to {0} repo(s): {1}" -f @($mem | ForEach-Object { $_.repo } | Select-Object -Unique).Count, (@($mem | ForEach-Object { "$($_.member)->$($_.repo)" }) -join ', ')) -Severity medium -Class suspicious -Confidence low `
            -Reasons @('access_grant') -Evidence @($mem | ForEach-Object { [ordered]@{ type = 'github_event'; event = 'MemberEvent'; scope = $Scope; repo = $_.repo; member = $_.member; action = $_.action; at = $_.at } }) -Entities $ent -Mitre @('T1098') `
            -FpNotes 'You may have invited a friend, colleague or bot account.' `
            -Recommendation 'Confirm each collaborator; remove unknown ones in the repo Settings > Collaborators and review what they pushed.'
    }
    $odd = @(& $newOnly $Measure.unusualPushes)
    if ($odd.Count) {
        Add-S13Finding -Check $Check -Title ("{0} push(es) at hours you never commit locally" -f $odd.Count) -Severity low -Class suspicious -Confidence low `
            -Reasons @('unusual_time') -Evidence @($odd | Select-Object -First 15 | ForEach-Object { [ordered]@{ type = 'github_event'; event = 'PushEvent'; scope = $Scope; repo = $_.repo; branch = $_.branch; at = $_.at; localHour = $_.localHour } }) -Entities $ent -Mitre @('T1078') `
            -FpNotes 'The baseline is your local git history only; pushes from another device, CI bots acting as you or travel across time zones look unusual too.' `
            -Recommendation 'Check that you recognise these pushes (repo, branch, time).'
    }
    $foreign = @(& $newOnly $Measure.foreignAuthors)
    if ($foreign.Count) {
        Add-S13Finding -Check $Check -Title ("{0} pushed commit(s) authored by identities not seen in local git config" -f $foreign.Count) -Severity low -Class suspicious -Confidence low `
            -Reasons @('foreign_author') -Evidence @($foreign | Select-Object -First 15 | ForEach-Object { [ordered]@{ type = 'github_event'; event = 'PushEvent'; scope = $Scope; repo = $_.repo; at = $_.at; authorName = $_.authorName; authorEmailDomain = $_.authorEmailDomain } }) -Entities $ent -Mitre @('T1078') `
            -FpNotes 'Merging other people''s pull requests, co-authored commits or commits made with another email on another machine all show up here.' `
            -Recommendation 'Confirm these commits are expected.'
    }
}

function ConvertTo-S13GlobRegex {
    param([string]$Glob)
    $g = (($Glob.Trim() -replace '\\', '/') -replace '^\./', '') -replace '^/', ''
    if ($g.EndsWith('/')) { $g = $g + '**' }
    $sb = [Text.StringBuilder]::new('^')
    $i = 0
    while ($i -lt $g.Length) {
        $ch = [string]$g[$i]
        if ($ch -eq '*') {
            if ($i + 1 -lt $g.Length -and [string]$g[$i + 1] -eq '*') {
                if ($i + 2 -lt $g.Length -and [string]$g[$i + 2] -eq '/') { [void]$sb.Append('(?:.*/)?'); $i += 3; continue }
                [void]$sb.Append('.*'); $i += 2; continue
            }
            [void]$sb.Append('[^/]*'); $i++; continue
        }
        if ($ch -eq '?') { [void]$sb.Append('[^/]'); $i++; continue }
        [void]$sb.Append([regex]::Escape($ch)); $i++
    }
    [void]$sb.Append('(?:/.*)?$')
    $sb.ToString()
}

function Read-S13Tarball {
    <# Read a .tgz in memory (no extraction to disk): entry names, sizes, modes, sha256, and text of small text files. #>
    param([Parameter(Mandatory)][string]$Path, [long]$MaxEntryBytes = 25MB)
    $entries = [System.Collections.Generic.List[object]]::new()
    $stream = [IO.File]::OpenRead($Path)
    try {
        $gz = [IO.Compression.GZipStream]::new($stream, [IO.Compression.CompressionMode]::Decompress)
        $reader = [System.Formats.Tar.TarReader]::new($gz, $false)
        while ($true) {
            $e = $reader.GetNextEntry($false)
            if ($null -eq $e) { break }
            $name = [string]$e.Name
            $rel = $name -replace '^[^/]+/', ''
            $rec = [ordered]@{ name = $name; rel = $rel; type = [string]$e.EntryType; size = [long]$e.Length; mode = [Convert]::ToString([int]$e.Mode, 8); mtime = (Format-S13Date $e.ModificationTime.UtcDateTime); sha256 = $null; text = $null }
            if ($null -ne $e.DataStream -and $e.Length -le $MaxEntryBytes) {
                $ms = [IO.MemoryStream]::new()
                $e.DataStream.CopyTo($ms)
                $bytes = $ms.ToArray()
                $ms.Dispose()
                $rec.sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                if ($rel -match '\.(json|js|cjs|mjs|ts|sh|ps1|cmd|bat|py|ya?ml|md)$' -or $rel -notmatch '\.') { $rec.text = [Text.Encoding]::UTF8.GetString($bytes) }
            }
            $entries.Add([pscustomobject]$rec)
        }
        $reader.Dispose()
        $gz.Dispose()
    }
    finally { $stream.Dispose() }
    , $entries.ToArray()
}

function Test-S13NpmSignature {
    <# Verify npm registry ECDSA signatures over "<name>@<version>:<integrity>" with the registry public keys. #>
    param([string]$Name, [string]$Version, [string]$Integrity, [object[]]$Signatures, [object[]]$Keys)
    if (-not $Signatures -or @($Signatures).Count -eq 0) { return 'missing' }
    if (-not $Keys -or @($Keys).Count -eq 0) { return 'no-keys' }
    $data = [Text.Encoding]::UTF8.GetBytes("$Name@${Version}:$Integrity")
    foreach ($s in @($Signatures)) {
        $k = @($Keys | Where-Object { $_.keyid -eq $s.keyid }) | Select-Object -First 1
        if (-not $k) { continue }
        $ec = [Security.Cryptography.ECDsa]::Create()
        try {
            $read = 0
            $ec.ImportSubjectPublicKeyInfo([Convert]::FromBase64String([string]$k.key), [ref]$read)
            $ok = $ec.VerifyData($data, [Convert]::FromBase64String([string]$s.sig), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
            if ($ok) { return 'valid' }
            return 'invalid'
        }
        finally { $ec.Dispose() }
    }
    'unknown-key'
}

function Get-S13Provenance {
    param([string]$Name, [string]$Version, $Dist)
    $url = [string]$Dist.attestations.url
    if (-not $url) { return $null }
    $r = Invoke-S13Web -Uri $url -SaveName ("npm-attest-{0}-{1}.json" -f (Get-S13SafeName $Name), $Version)
    $out = [ordered]@{ version = $Version; status = $null; predicateTypes = @(); repository = $null; workflow = $null; ref = $null; commit = $null; builder = $null; invocation = $null; commitInLocalRepo = $null }
    if ($r.Status -ne 200 -or $null -eq $r.Data) { $out.status = "HTTP $($r.Status)"; return [pscustomobject]$out }
    $out.status = 'ok'
    foreach ($a in @($r.Data.attestations)) {
        $out.predicateTypes += [string]$a.predicateType
        if ([string]$a.predicateType -notmatch 'slsa\.dev/provenance') { continue }
        $payload = [string]$a.bundle.dsseEnvelope.payload
        if (-not $payload) { continue }
        $stmt = $null
        try { $stmt = ConvertFrom-S13Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))) } catch { $stmt = $null }
        if ($null -eq $stmt) { continue }
        $bd = $stmt.predicate.buildDefinition
        $wf = $bd.externalParameters.workflow
        $out.repository = [string]$wf.repository
        $out.workflow = [string]$wf.path
        $out.ref = [string]$wf.ref
        $dep = @($bd.resolvedDependencies) | Select-Object -First 1
        if ($dep) { $out.commit = [string]$dep.digest.gitCommit }
        $out.builder = [string]$stmt.predicate.runDetails.builder.id
        $out.invocation = [string]$stmt.predicate.runDetails.metadata.invocationId
    }
    [pscustomobject]$out
}

#endregion

#region ---------- section 0: targets and gh ----------

function Invoke-S13Setup {
    $run = $script:S13.Run
    $iocPath = Join-Path $PSScriptRoot 'S13-github-npm-iocs.json'
    if ([IO.File]::Exists($iocPath)) { $script:Ctx.Iocs = ConvertFrom-S13Json ([IO.File]::ReadAllText($iocPath)) }
    if ($null -eq $script:Ctx.Iocs) {
        Add-S13Error -Check 's13.targets' -Message "IoC sidecar missing or invalid: $iocPath (indicator matching disabled)"
        $script:Ctx.Iocs = [pscustomobject]@{ repoNames = @(); repoDescriptions = @(); branchNames = @(); workflowFileNames = @(); workflowContentPatterns = @(); runnerNames = @(); exfilFileNames = @(); webhookHostRegexes = @(); npm = [pscustomobject]@{ installScripts = @('preinstall', 'install', 'postinstall'); lifecycleScriptsOfInterest = @(); maliciousFileNames = @(); contentIocStrings = @(); knownBadSha256 = @() }; githubSafeActors = @(); githubSafeRunEvents = @() }
    }

    Invoke-BvsCheck -Run $run -Id 'github.gh_auth' -Description 'GitHub CLI login state: vendor\gh\bin\gh.exe auth status with GH_CONFIG_DIR=<root>\vendor\gh-config (signature verified before use)' -Script {
        $auth = [ordered]@{ mode = $null; cli = $null; loggedIn = $false; account = $null; scopes = @(); tokenSource = $null; message = $null; loginHint = $null }
        $auth.loginHint = 'Run yourself (never by an agent), from the project folder: pwsh -NoProfile -File .\bvs.ps1 github-login'
        if ($PublicOnly) {
            $auth.mode = 'public-only'
            $script:Ctx.GhAuth = [pscustomobject]$auth
            Set-BvsCheckStatus -Id 'github.gh_auth' -Status skipped -Reason 'public-only mode (-PublicOnly)'
            Add-BvsInventory -Run $run -Name 'ghAuth' -Data $auth
            return
        }
        $cli = Initialize-S13Gh
        $auth.cli = $cli
        if (-not $cli.usable) {
            $auth.mode = 'public-only'
            $script:Ctx.GhAuth = [pscustomobject]$auth
            Set-BvsCheckStatus -Id 'github.gh_auth' -Status not_applicable -Reason $cli.reason
            Add-BvsInventory -Run $run -Name 'ghAuth' -Data $auth
            return
        }
        $st = Get-S13GhAuthStatus
        $auth.loggedIn = $st.loggedIn; $auth.account = $st.account; $auth.scopes = $st.scopes; $auth.tokenSource = $st.tokenSource; $auth.message = $st.message
        $auth.mode = if ($st.loggedIn) { 'authenticated' } else { 'public-only (gh not logged in)' }
        $script:Ctx.GhAuth = [pscustomobject]$auth
        Add-BvsInventory -Run $run -Name 'ghAuth' -Data $auth
        if (-not $st.loggedIn) {
            if ($Authenticated) { Write-BvsLog -Run $run -Level WARN -Message '-Authenticated was requested but gh auth status reports no login' }
            Set-BvsCheckStatus -Id 'github.gh_auth' -Status ok -Reason "gh not logged in (exit $($st.exitCode)): authenticated checks pending"
        }
        [pscustomobject]$auth
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 's13.targets' -Description 'Resolve audit targets: local git repos, GitHub user, npm packages, identity, local SSH keys, commit-time baseline' -Script {
        $repos = Find-S13LocalRepos -Extra $RepoPath
        $gName = [string](@(git --no-optional-locks config --global --get user.name 2>$null) | Select-Object -First 1)
        $gMail = [string](@(git --no-optional-locks config --global --get user.email 2>$null) | Select-Object -First 1)
        # GitHub user
        $user = $null; $from = $null
        if ($GitHubUser) { $user = $GitHubUser; $from = 'parameter' }
        elseif ($env:BVS_GITHUB_USER) { $user = $env:BVS_GITHUB_USER; $from = 'environment BVS_GITHUB_USER' }
        elseif ($script:Ctx.GhAuth -and $script:Ctx.GhAuth.loggedIn) { $user = $script:Ctx.GhAuth.account; $from = 'gh auth status' }
        else {
            $owners = @($repos | ForEach-Object { $_.remotes } | Where-Object { $_.githubOwner } | ForEach-Object { $_.githubOwner })
            if ($owners.Count) {
                $byName = @($owners | Where-Object { $gName -and $_ -ieq $gName })
                if ($byName.Count) { $user = $byName[0]; $from = 'local repo remote owner matching git user.name' }
                else { $user = ($owners | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name; $from = 'most common github.com owner of local repos' }
            }
        }
        $script:Ctx.GitHubUser = $user
        $script:Ctx.GitHubUserFrom = $from
        foreach ($r in $repos) { $r.owned = [bool]($user -and @($r.remotes | Where-Object { $_.githubOwner -ieq $user }).Count) }
        # Packages of owned repos (or of every repo when no user is known, or when -NpmPackage names a package)
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($r in $repos) {
            if ($r.owned -or -not $user -or $NpmPackage) {
                $pk = Get-S13RepoPackages -Repo $r.path
                if (-not $r.owned -and $user) { $pk = @($pk | Where-Object { $NpmPackage -contains $_.name }) }
                $r.packages = @($pk | ForEach-Object { $_.name })
                foreach ($x in $pk) { $all.Add($x) }
            }
        }
        $script:Ctx.Repos = $repos
        $script:Ctx.LocalPackages = $all.ToArray()
        foreach ($p in @($all | Where-Object { $_.publishable -or ($NpmPackage -contains $_.name) })) { $p.history = Get-S13PackageHistory -Repo $p.repo -RelPath $p.relPath }
        # Identity used to recognise the user's own commits
        $emails = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in @($gMail) + @($repos | ForEach-Object { $_.email })) { if ($m) { [void]$emails.Add($m) } }
        if ($user) { [void]$emails.Add("$user@users.noreply.github.com") }
        $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in @($gName, $user)) { if ($n) { [void]$names.Add($n) } }
        $script:Ctx.Identity = [pscustomobject]@{ names = @($names); emails = @($emails) }
        $script:Ctx.Baseline = Get-S13CommitBaseline -Repos @($repos) -Names @($names) -Emails @($emails)
        $script:Ctx.LocalSsh = Get-S13LocalSshKeys
        $inv = [ordered]@{
            githubUser = $user; githubUserSource = $from
            gitIdentity = [ordered]@{ name = $gName; emailDomain = $(if ($gMail -match '@(.+)$') { $Matches[1] } else { $null }) }
            repos = @($repos | ForEach-Object { [ordered]@{ path = $_.path; owned = $_.owned; remotes = $_.remotes; packages = $_.packages } })
            localPackages = @($all | ForEach-Object { [ordered]@{ name = $_.name; version = $_.version; private = $_.private; publishable = $_.publishable; repo = $_.repo; relPath = $_.relPath; files = $_.files; scripts = $(if ($_.scripts) { @($_.scripts.PSObject.Properties.Name) } else { @() }); historyCommits = @($_.history | Where-Object { $null -ne $_ }).Count } })
            localSshKeys = @($script:Ctx.LocalSsh | ForEach-Object { [ordered]@{ file = $_.source; type = $_.type; fingerprint = $_.fingerprint; comment = $_.comment; modified = $_.modified } })
            commitBaseline = [ordered]@{ days = $script:Ctx.Baseline.days; timeZone = $script:Ctx.Baseline.timeZone; commits = $script:Ctx.Baseline.total; hourHistogram = $script:Ctx.Baseline.hourHistogram }
        }
        Add-BvsInventory -Run $run -Name 'targets' -Data $inv
        if (-not $user) { Set-BvsCheckStatus -Id 's13.targets' -Status partial -Reason 'no GitHub user configured or discovered (pass -GitHubUser)' }
        $inv
    } | Out-Null
}

#endregion

#region ---------- section A: public GitHub ----------

function Invoke-S13PublicGitHub {
    $run = $script:S13.Run
    $u = $script:Ctx.GitHubUser
    $none = [string]::IsNullOrWhiteSpace($u)

    Invoke-BvsCheck -Run $run -Id 'github.profile' -Description 'Public profile of the audited GitHub user (api.github.com/users/<user>)' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.profile' -Status not_applicable -Reason 'no GitHub user'; return }
        $r = Invoke-S13GitHubPublic -Path "users/$u" -SaveName "gh-user-$u.json"
        if ($r.RateLimited -and -not $r.FromCache) { Set-BvsCheckStatus -Id 'github.profile' -Status partial -Reason 'GitHub API rate limit reached'; return }
        if ($r.Status -eq 404) {
            Add-S13Finding -Check 'github.profile' -Title "GitHub user '$u' not found" -Severity high -Class suspicious -Confidence low -Reasons @('account_missing') `
                -Evidence @([ordered]@{ type = 'http'; url = "https://api.github.com/users/$u"; status = 404 }) -Mitre @('T1531') `
                -FpNotes 'The configured or discovered user name may be wrong, or you renamed the account.' `
                -Recommendation 'Check that you can sign in to GitHub and that the account name is unchanged; contact GitHub Support if it was renamed or suspended without your action.'
            return
        }
        if ($r.Status -ne 200 -or $null -eq $r.Data) { throw "users/$u returned HTTP $($r.Status)" }
        $p = $r.Data
        if ($p.login -and [string]$p.login -cne $u) { $script:Ctx.GitHubUser = [string]$p.login }
        $prof = [ordered]@{ login = [string]$p.login; id = $p.id; type = [string]$p.type; name = [string]$p.name; company = [string]$p.company; blog = [string]$p.blog; location = [string]$p.location; bio = [string]$p.bio; twitter = [string]$p.twitter_username; publicRepos = $p.public_repos; publicGists = $p.public_gists; followers = $p.followers; following = $p.following; created = (Format-S13Date $p.created_at); updated = (Format-S13Date $p.updated_at); siteAdmin = [bool]$p.site_admin; source = $(if ($r.FromCache) { "cache $($r.CachedAt)" } else { 'live' }) }
        if ($p.name -and $script:Ctx.Identity) { $script:Ctx.Identity.names = @(@($script:Ctx.Identity.names) + [string]$p.name | Select-Object -Unique) }
        $script:Ctx.Profile = $prof
        Add-BvsInventory -Run $run -Name 'githubProfile' -Data $prof
        if ($r.Stale) { Set-BvsCheckStatus -Id 'github.profile' -Status partial -Reason 'used cached response (rate limited or offline)' }
        $prof
    } | Out-Null
    $u = $script:Ctx.GitHubUser

    Invoke-BvsCheck -Run $run -Id 'github.repos_public' -Description 'Owned public repos: worm repo names/descriptions, -migration copies, random 18-char names, recently created (users/<user>/repos?type=owner&sort=created)' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.repos_public' -Status not_applicable -Reason 'no GitHub user'; return }
        $pg = Get-S13GitHubPublicPaged -Path "users/$u/repos?type=owner&sort=created" -SaveBase "gh-repos-$u" -MaxPages 5
        Set-S13StatusFromWeb -Id 'github.repos_public' -Infos @($pg.Info)
        $res = Add-S13RepoFindings -Repos $pg.Items -Check 'github.repos_public'
        $rows = $res[0]; $recent = $res[1]
        if (@($recent).Count) {
            Add-S13Finding -Check 'github.repos_public' -Title ("{0} public repo(s) created in the last {1} days: confirm they are yours" -f @($recent).Count, $script:S13.RecentDays) -Severity low -Class suspicious -Confidence low `
                -Reasons @('created_lt_30d') -Evidence @($recent) -Entities @{ accounts = @([ordered]@{ type = 'github'; login = $u }) } -Mitre @('T1567.001') `
                -FpNotes 'New repos are normal for an active developer; this only asks you to recognise them.' `
                -Recommendation 'Open each listed repo; if you did not create it, make it private, inspect its files for leaked secrets and follow the worm incident steps.'
        }
        Add-BvsInventory -Run $run -Name 'githubReposPublic' -Data ([ordered]@{ fetched = @($pg.Items).Count; info = $pg.Info; repos = $rows })
        $script:Ctx.PublicRepos = $pg.Items
        $rows
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github.events_public' -Description 'Public event stream (up to 300 events): PublicEvent, CreateEvent bursts, MemberEvent, worm branches, pushes at unusual hours' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.events_public' -Status not_applicable -Reason 'no GitHub user'; return }
        $pg = Get-S13GitHubPublicPaged -Path "users/$u/events/public" -SaveBase "gh-events-$u" -MaxPages 3
        Set-S13StatusFromWeb -Id 'github.events_public' -Infos @($pg.Info)
        $m = Measure-S13Events -Events $pg.Items -Login $u -Baseline $script:Ctx.Baseline -KnownEmails $script:Ctx.Identity.emails -KnownNames $script:Ctx.Identity.names
        Add-S13EventFindings -Measure $m -Check 'github.events_public' -Scope 'public'
        Add-BvsInventory -Run $run -Name 'githubEventsPublic' -Data ([ordered]@{ info = $pg.Info; summary = $m })
        $script:Ctx.PublicEventIds = @($pg.Items | ForEach-Object { [string]$_.id })
        @($pg.Items)
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github.gists_public' -Description 'Public gists: exfiltration file names, worm markers, recently created' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.gists_public' -Status not_applicable -Reason 'no GitHub user'; return }
        $pg = Get-S13GitHubPublicPaged -Path "users/$u/gists" -SaveBase "gh-gists-$u" -MaxPages 3
        Set-S13StatusFromWeb -Id 'github.gists_public' -Infos @($pg.Info)
        $rows = Invoke-S13GistAnalysis -Gists $pg.Items -Check 'github.gists_public' -Scope 'public'
        Add-BvsInventory -Run $run -Name 'githubGistsPublic' -Data ([ordered]@{ info = $pg.Info; gists = $rows })
        $rows
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github.ssh_keys' -Description 'SSH authentication and signing keys on the account (github.com/<user>.keys, users/<user>/keys, users/<user>/ssh_signing_keys) vs local ~\.ssh\*.pub fingerprints' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.ssh_keys' -Status not_applicable -Reason 'no GitHub user'; return }
        $notes = [System.Collections.Generic.List[string]]::new()
        $kt = Invoke-S13Web -Uri "https://github.com/$u.keys" -SaveName "gh-$u.keys.txt"
        if ($kt.Status -ne 200) { $notes.Add("github.com/$u.keys HTTP $($kt.Status)") }
        $ghKeys = [System.Collections.Generic.List[object]]::new()
        foreach ($line in @(([string]$kt.Text) -split "`r?`n")) { $k = Get-S13SshKeyFacts -Line $line -Source "github.com/$u.keys"; if ($k) { $ghKeys.Add($k) } }
        $api = Invoke-S13GitHubPublic -Path "users/$u/keys" -SaveName "gh-keys-api-$u.json"
        $ids = @{}
        if ($api.Status -eq 200) { foreach ($a in (ConvertTo-S13Array $api.Data)) { $f = Get-S13SshKeyFacts -Line ([string]$a.key) -Source 'api'; if ($f) { $ids[$f.fingerprint] = $a.id } } }
        elseif ($api.RateLimited) { $notes.Add('users/<user>/keys rate limited (key ids unavailable)') }
        $sg = Invoke-S13GitHubPublic -Path "users/$u/ssh_signing_keys" -SaveName "gh-signkeys-$u.json"
        $signKeys = [System.Collections.Generic.List[object]]::new()
        if ($sg.Status -eq 200) {
            foreach ($a in (ConvertTo-S13Array $sg.Data)) { $f = Get-S13SshKeyFacts -Line ([string]$a.key) -Source 'ssh_signing_keys'; if ($f) { $f | Add-Member -NotePropertyName id -NotePropertyValue $a.id; $f | Add-Member -NotePropertyName created -NotePropertyValue (Format-S13Date $a.created_at); $f | Add-Member -NotePropertyName title -NotePropertyValue ([string]$a.title); $signKeys.Add($f) } }
        }
        else { $notes.Add("users/<user>/ssh_signing_keys HTTP $($sg.Status)") }
        $local = @{}
        foreach ($l in $script:Ctx.LocalSsh) { $local[$l.fingerprint] = $l }
        $rows = [System.Collections.Generic.List[object]]::new()
        $unknown = [System.Collections.Generic.List[object]]::new()
        foreach ($k in $ghKeys) {
            $match = $local[$k.fingerprint]
            $exp = Find-S13Expected -Category 'sshKey' -Value $k.fingerprint
            $row = [ordered]@{ kind = 'authentication'; type = $k.type; fingerprint = $k.fingerprint; githubKeyId = $ids[$k.fingerprint]; localFile = $(if ($match) { $match.source } else { $null }); expected = $(if ($exp) { $exp.id } else { $null }) }
            $rows.Add($row)
            if (-not $match) { $unknown.Add([pscustomobject]@{ row = $row; exp = $exp }) }
        }
        foreach ($k in $signKeys) {
            $match = $local[$k.fingerprint]
            $exp = Find-S13Expected -Category 'sshKey' -Value $k.fingerprint
            $row = [ordered]@{ kind = 'signing'; type = $k.type; fingerprint = $k.fingerprint; githubKeyId = $k.id; title = $k.title; created = $k.created; localFile = $(if ($match) { $match.source } else { $null }); expected = $(if ($exp) { $exp.id } else { $null }) }
            $rows.Add($row)
            if (-not $match) { $unknown.Add([pscustomobject]@{ row = $row; exp = $exp }) }
        }
        $script:Ctx.UnknownKeys = @($unknown | ForEach-Object { $_.row })
        foreach ($grp in @($unknown | Group-Object { $_.row.kind })) {
            $items = @($grp.Group)
            $allExp = @($items | Where-Object { $_.exp }).Count -eq $items.Count
            $newest = if ($ids.Count) { ($ids.Values | Measure-Object -Maximum).Maximum } else { $null }
            foreach ($i in $items) { [void]$script:Ctx.ReportedKeys.Add($i.row.fingerprint) }
            $kindText = if ($grp.Name -eq 'signing') { 'SSH signing key(s) (can make commits show as Verified)' } else { 'SSH authentication key(s) (push/pull access to all your repos)' }
            Add-S13Finding -Check 'github.ssh_keys' -Title ("GitHub account has {0} {1} not found on this machine" -f $items.Count, $kindText) -Severity $(if ($allExp) { 'info' } else { 'high' }) -Class suspicious -Confidence low `
                -Reasons @('unknown_key') -Evidence @($items | ForEach-Object { $e = [ordered]@{ type = 'ssh_key'; source = "github.com/$u"; isNewestGithubKeyId = ($null -ne $newest -and $_.row.githubKeyId -eq $newest) }; foreach ($kv in $_.row.GetEnumerator()) { $e[$kv.Key] = $kv.Value }; $e }) `
                -Entities @{ accounts = @([ordered]@{ type = 'github'; login = $u }) } -Mitre @('T1098.004', 'T1098') `
                -ExpectedItem $(if ($allExp) { $items[0].exp } else { $null }) `
                -FpNotes 'Keys of your other devices (another laptop, a VPS, a virtual machine, a phone Git client) are legitimately on GitHub but not in this machine''s ~\.ssh. Higher GitHub key ids were added more recently.' `
                -Recommendation 'For each fingerprint, find the device that holds the key (ssh-keygen -lf <key>.pub on that device). If no device matches, delete it at https://github.com/settings/keys and check the security log for public_key.create. Add known keys of other devices to config\local\expected.json (category sshKey, match.fingerprints) so future scans stay quiet.'
        }
        $localNotOn = @($script:Ctx.LocalSsh | Where-Object { $fp = $_.fingerprint; -not ($ghKeys | Where-Object { $_.fingerprint -eq $fp }) -and -not ($signKeys | Where-Object { $_.fingerprint -eq $fp }) } | ForEach-Object { [ordered]@{ file = $_.source; fingerprint = $_.fingerprint } })
        Add-BvsInventory -Run $run -Name 'githubSshKeys' -Data ([ordered]@{ githubAuthKeys = $ghKeys.Count; githubSigningKeys = $signKeys.Count; keys = $rows.ToArray(); localKeysNotOnGithub = $localNotOn; source = $(if ($kt.FromCache) { "cache $($kt.CachedAt)" } else { 'live' }) })
        if ($notes.Count) { Set-BvsCheckStatus -Id 'github.ssh_keys' -Status partial -Reason ($notes -join '; ') }
        $rows.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github.gpg_keys' -Description 'GPG keys on the account (github.com/<user>.gpg, users/<user>/gpg_keys) vs local signing configuration' -Script {
        if ($none) { Set-BvsCheckStatus -Id 'github.gpg_keys' -Status not_applicable -Reason 'no GitHub user'; return }
        $gt = Invoke-S13Web -Uri "https://github.com/$u.gpg" -SaveName "gh-$u.gpg.txt"
        $blocks = ([regex]::Matches([string]$gt.Text, '-----BEGIN PGP PUBLIC KEY BLOCK-----')).Count
        $api = Invoke-S13GitHubPublic -Path "users/$u/gpg_keys" -SaveName "gh-gpgkeys-$u.json"
        $keys = @()
        if ($api.Status -eq 200) {
            $keys = @((ConvertTo-S13Array $api.Data) | ForEach-Object { [ordered]@{ keyId = [string]$_.key_id; created = (Format-S13Date $_.created_at); expires = (Format-S13Date $_.expires_at); emails = @($_.emails | ForEach-Object { [string]$_.email }); canSign = [bool]$_.can_sign; subkeys = @($_.subkeys).Count; ageDays = (Get-S13AgeDays $_.created_at) } })
        }
        else { Set-BvsCheckStatus -Id 'github.gpg_keys' -Status partial -Reason "users/<user>/gpg_keys HTTP $($api.Status) (armored blocks seen: $blocks)" }
        $signingKey = [string](@(git --no-optional-locks config --global --get user.signingkey 2>$null) | Select-Object -First 1)
        $gpgFormat = [string](@(git --no-optional-locks config --global --get gpg.format 2>$null) | Select-Object -First 1)
        $localGpgSigning = [bool]$signingKey -and $gpgFormat -notin 'ssh', 'x509'
        $unknown = @($keys | Where-Object { -not (Find-S13Expected -Category 'gpgKey' -Value $_.keyId) })
        if ($unknown.Count -and -not $localGpgSigning) {
            $recent = @($unknown | Where-Object { $null -ne $_.ageDays -and $_.ageDays -le 90 })
            Add-S13Finding -Check 'github.gpg_keys' -Title ("GitHub account has {0} GPG key(s) but this machine has no GPG commit signing configured" -f $unknown.Count) -Severity $(if ($recent.Count) { 'high' } else { 'medium' }) -Class suspicious -Confidence low `
                -Reasons @('unknown_key') -Evidence @($unknown | ForEach-Object { $e = [ordered]@{ type = 'gpg_key'; source = "github.com/$u" }; foreach ($kv in $_.GetEnumerator()) { $e[$kv.Key] = $kv.Value }; $e }) `
                -Entities @{ accounts = @([ordered]@{ type = 'github'; login = $u }) } -Mitre @('T1098') `
                -FpNotes 'The key may belong to another machine of yours or an older setup. An attacker-added GPG key lets forged commits show as Verified.' `
                -Recommendation 'Confirm the key id and email belong to you (gpg --list-keys on the device that signs). Otherwise delete it at https://github.com/settings/keys and check the security log for gpg_key.create.'
        }
        Add-BvsInventory -Run $run -Name 'githubGpgKeys' -Data ([ordered]@{ armoredBlocks = $blocks; keys = $keys; localSigning = [ordered]@{ signingKeyConfigured = [bool]$signingKey; format = $gpgFormat } })
        $keys
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github.repo_sync' -Description 'For local repos that publish npm packages: remote default branch head and branch names vs the local clone' -Script {
        $targets = @($script:Ctx.LocalPackages | Where-Object { $_.publishable } | ForEach-Object { $_.repo } | Select-Object -Unique)
        if (-not $targets.Count) { Set-BvsCheckStatus -Id 'github.repo_sync' -Status not_applicable -Reason 'no local repo publishes an npm package'; return }
        $rows = [System.Collections.Generic.List[object]]::new()
        $infos = [System.Collections.Generic.List[object]]::new()
        foreach ($rp in $targets) {
            $repo = @($script:Ctx.Repos | Where-Object { $_.path -eq $rp }) | Select-Object -First 1
            $rem = @($repo.remotes | Where-Object { $_.githubOwner }) | Select-Object -First 1
            if (-not $rem) { continue }
            $full = "$($rem.githubOwner)/$($rem.githubRepo)"
            $row = [ordered]@{ repo = $full; localPath = $rp; visibility = $null; defaultBranch = $null; remoteHead = $null; remoteHeadDate = $null; localRemoteRef = $null; localHead = $null; remoteHeadInLocalClone = $null; remoteBranches = @(); branchesNotInLocalClone = @(); iocBranches = @() }
            $ri = Invoke-S13GitHubPublic -Path "repos/$full" -SaveName ("gh-repo-" + (Get-S13SafeName $full) + '.json')
            if ($ri.Status -ne 200) { $infos.Add([pscustomobject]@{ error = "repos/$full HTTP $($ri.Status)"; rateLimited = $ri.RateLimited; fromCache = $ri.FromCache }); $rows.Add($row); continue }
            $row.visibility = [string]$ri.Data.visibility
            $row.defaultBranch = [string]$ri.Data.default_branch
            $br = Get-S13GitHubPublicPaged -Path "repos/$full/branches" -SaveBase ("gh-branches-" + (Get-S13SafeName $full)) -MaxPages 2
            $infos.Add($br.Info)
            $row.remoteBranches = @($br.Items | ForEach-Object { [string]$_.name })
            $localBranches = @(git --no-optional-locks -C $rp for-each-ref '--format=%(refname:short)' "refs/remotes/$($rem.remote)" 2>$null | ForEach-Object { ([string]$_) -replace "^$([regex]::Escape($rem.remote))/", '' })
            $row.branchesNotInLocalClone = @($row.remoteBranches | Where-Object { $localBranches -notcontains $_ })
            foreach ($b in $row.remoteBranches) { foreach ($i in @($script:Ctx.Iocs.branchNames)) { if ($b -match [string]$i.regex) { $row.iocBranches += [ordered]@{ branch = $b; family = [string]$i.family; severity = [string]$i.severity } } } }
            $head = $br.Items | Where-Object { $_.name -eq $row.defaultBranch } | Select-Object -First 1
            if ($head) { $row.remoteHead = [string]$head.commit.sha }
            $row.localRemoteRef = [string](@(git --no-optional-locks -C $rp rev-parse --verify --quiet "refs/remotes/$($rem.remote)/$($row.defaultBranch)" 2>$null) | Select-Object -First 1)
            $row.localHead = [string](@(git --no-optional-locks -C $rp rev-parse --verify --quiet HEAD 2>$null) | Select-Object -First 1)
            if ($row.remoteHead) {
                $t = [string](@(git --no-optional-locks -C $rp cat-file -t $row.remoteHead 2>$null) | Select-Object -First 1)
                $row.remoteHeadInLocalClone = ($t -eq 'commit')
            }
            $script:Ctx.RepoSync[$rp] = $row
            $rows.Add($row)
            foreach ($ib in $row.iocBranches) {
                Add-S13Finding -Check 'github.repo_sync' -Title "Remote branch '$($ib.branch)' in $full matches a worm branch name ($($ib.family))" -Severity $(if ($ib.severity -eq 'critical') { 'critical' } else { 'high' }) -Class $(if ($ib.severity -eq 'critical') { 'compromise' } else { 'suspicious' }) -Confidence medium `
                    -Reasons @('intel_match') -Evidence @([ordered]@{ type = 'github_branch'; repo = $full; branch = $ib.branch }) -Mitre @('T1195.002', 'T1552') `
                    -FpNotes 'Exact branch-name match only.' -Recommendation 'Inspect the branch (added workflow that exfiltrates secrets), preserve evidence, delete it and rotate the repository secrets.'
            }
            if ($row.remoteHeadInLocalClone -eq $false) {
                Add-S13Finding -Check 'github.repo_sync' -Title "Remote default branch of $full has commits that are not in the local clone" -Severity medium -Class suspicious -Confidence low `
                    -Reasons @('remote_ahead') -Evidence @([ordered]@{ type = 'git'; repo = $full; localPath = $rp; branch = $row.defaultBranch; remoteHead = $row.remoteHead; localRemoteRef = $row.localRemoteRef }) -Mitre @('T1195.002') `
                    -FpNotes 'You may have pushed from another device or edited on github.com since the last fetch; this scan never fetches.' `
                    -Recommendation "Run 'git fetch' yourself and review the new commits (git log HEAD..origin/$($row.defaultBranch)) before building or publishing."
            }
        }
        Set-S13StatusFromWeb -Id 'github.repo_sync' -Infos $infos.ToArray()
        Add-BvsInventory -Run $run -Name 'githubRepoSync' -Data $rows.ToArray()
        $rows.ToArray()
    } | Out-Null
}

function Invoke-S13GistAnalysis {
    param([object[]]$Gists, [string]$Check, [string]$Scope)
    $iocs = $script:Ctx.Iocs
    $rows = [System.Collections.Generic.List[object]]::new()
    $recent = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $Gists) {
        $files = @($g.files.PSObject.Properties.Name)
        $hits = [System.Collections.Generic.List[object]]::new()
        foreach ($fn in $files) { foreach ($x in @($iocs.exfilFileNames)) { if ($fn -match [string]$x.regex) { $hits.Add([pscustomobject]@{ file = $fn; family = [string]$x.family; severity = [string]$x.severity }) } } }
        $desc = [string]$g.description
        $descHit = @($iocs.repoDescriptions | Where-Object { ($_.equals -and $desc -ieq [string]$_.equals) -or ($_.contains -and $desc.IndexOf([string]$_.contains, [StringComparison]::OrdinalIgnoreCase) -ge 0) }) | Select-Object -First 1
        $age = Get-S13AgeDays $g.created_at
        $row = [ordered]@{ id = [string]$g.id; public = [bool]$g.public; description = $desc; files = $files; created = (Format-S13Date $g.created_at); updated = (Format-S13Date $g.updated_at); ageDays = $age; indicators = @($hits | ForEach-Object { "$($_.file) ($($_.family))" }) }
        $rows.Add($row)
        $key = "gist|$($g.id)"
        $sevs = @($hits | ForEach-Object { $_.severity })
        if ($descHit) { $sevs += $(if ($descHit.equals) { 'critical' } else { 'medium' }) }
        $sev = Get-S13MaxSeverity $sevs
        if ($script:SevRank[$sev] -ge 2 -and $script:Ctx.ReportedEvents.Add($key)) {
            $exp = Find-S13Expected -Category 'gist' -Value ([string]$g.id)
            Add-S13Finding -Check $Check -Title "Gist $($g.id) looks like worm/stealer output ($(@($row.indicators) + @($(if ($descHit) { 'description marker' })) -join ', '))" -Severity $(if ($sev -eq 'critical') { 'critical' } else { 'high' }) -Class $(if ($sev -eq 'critical') { 'compromise' } else { 'suspicious' }) -Confidence low `
                -Reasons @('exfil_file_name') -Evidence @([ordered]@{ type = 'gist'; scope = $Scope; id = [string]$g.id; url = [string]$g.html_url; files = $files; created = $row.created; description = $desc }) -ExpectedItem $exp -Mitre @('T1567.001') `
                -FpNotes 'File names such as environment.json or data.json are also used by ordinary gists.' `
                -Recommendation 'Open the gist; if you did not create it, check whether it contains (encoded) secrets, delete it after preserving evidence and rotate those secrets.'
        }
        elseif ($null -ne $age -and $age -le $script:S13.RecentDays -and $script:Ctx.ReportedEvents.Add($key)) { $recent.Add([ordered]@{ type = 'gist'; scope = $Scope; id = [string]$g.id; files = $files; created = $row.created; public = [bool]$g.public }) }
    }
    if ($recent.Count) {
        Add-S13Finding -Check $Check -Title ("{0} gist(s) created in the last {1} days: confirm they are yours" -f $recent.Count, $script:S13.RecentDays) -Severity low -Class suspicious -Confidence low `
            -Reasons @('created_lt_30d') -Evidence $recent.ToArray() -Mitre @('T1567.001') `
            -FpNotes 'Creating gists is normal; this only asks you to recognise them.' -Recommendation 'Delete gists you do not recognise after checking them for secrets.'
    }
    , $rows.ToArray()
}

#endregion

#region ---------- section B: npm ----------

function Get-S13Packument {
    param([string]$Name)
    if ($script:Ctx.Packuments.ContainsKey($Name)) { return $script:Ctx.Packuments[$Name] }
    $enc = if ($Name.StartsWith('@')) { '@' + [uri]::EscapeDataString($Name.Substring(1)) } else { [uri]::EscapeDataString($Name) }
    $r = Invoke-S13Web -Uri "https://registry.npmjs.org/$enc" -SaveName ('npm-packument-' + (Get-S13SafeName $Name) + '.json') -Headers @{ Accept = 'application/json' }
    $script:Ctx.Packuments[$Name] = $r
    $r
}

function Get-S13PackumentVersions {
    param($Packument)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Packument -or $null -eq $Packument.versions) { return , $list.ToArray() }
    foreach ($p in $Packument.versions.PSObject.Properties) {
        $list.Add([pscustomobject]@{ version = $p.Name; manifest = $p.Value; published = (ConvertTo-S13Date $Packument.time.($p.Name)) })
    }
    , @($list | Sort-Object { ConvertTo-S13SemverKey $_.version })
}

function Get-S13LocalPackage {
    param([string]$Name)
    $c = @($script:Ctx.LocalPackages | Where-Object { $_.name -eq $Name })
    if (-not $c.Count) { return $null }
    $best = @($c | Where-Object { $_.publishable }) | Select-Object -First 1
    if (-not $best) { $best = $c[0] }
    if ($null -eq $best.history) { $best.history = Get-S13PackageHistory -Repo $best.repo -RelPath $best.relPath }
    $best
}

function Invoke-S13Npm {
    $run = $script:S13.Run
    $iocs = $script:Ctx.Iocs
    $userRc = if ($env:NPM_CONFIG_USERCONFIG) { $env:NPM_CONFIG_USERCONFIG } else { Join-Path $env:USERPROFILE '.npmrc' }
    $globalRc = Join-Path $env:APPDATA 'npm\etc\npmrc'
    $script:NpmToken = Get-S13NpmRegistryToken -Path $userRc
    $script:Ctx.NpmTokenState = if ($script:NpmToken) { 'present' } else { 'absent' }

    Invoke-BvsCheck -Run $run -Id 'npm.token_whoami' -Description 'Read-only: GET registry.npmjs.org/-/whoami with the token from the user .npmrc (in memory, response not saved)' -Script {
        if (-not $script:NpmToken) { Set-BvsCheckStatus -Id 'npm.token_whoami' -Status not_applicable -Reason 'no registry.npmjs.org token in the user .npmrc'; return }
        $r = Invoke-S13Web -Uri 'https://registry.npmjs.org/-/whoami' -SaveName 'npm-whoami.json' -Headers @{ Authorization = "Bearer $($script:NpmToken)" } -NoSave
        if ($r.Status -eq 200 -and $r.Data.username) {
            $script:Ctx.NpmUser = [string]$r.Data.username
            $script:Ctx.NpmTokenState = 'valid'
            Add-BvsInventory -Run $run -Name 'npmAccount' -Data ([ordered]@{ username = $script:Ctx.NpmUser; tokenState = 'valid' })
            return [pscustomobject]@{ username = $script:Ctx.NpmUser }
        }
        if ($r.Status -in 401, 403) {
            $script:Ctx.NpmTokenState = 'rejected'
            Add-BvsInventory -Run $run -Name 'npmAccount' -Data ([ordered]@{ username = $null; tokenState = "rejected (HTTP $($r.Status))" })
            Set-BvsCheckStatus -Id 'npm.token_whoami' -Status partial -Reason "token rejected by the registry (HTTP $($r.Status)): expired, revoked or not allowed to call whoami"
            return
        }
        throw "whoami returned HTTP $($r.Status)"
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.local_config' -Description 'npm configuration files: plaintext registry tokens (class only, never values), strict-ssl, registry overrides' -Script {
        $facts = [System.Collections.Generic.List[object]]::new()
        $facts.Add((Get-S13NpmrcFacts -Path $userRc -Scope 'user'))
        $facts.Add((Get-S13NpmrcFacts -Path $globalRc -Scope 'global'))
        foreach ($p in @($script:Ctx.LocalPackages | Where-Object { $_.publishable })) {
            foreach ($cand in @((Join-Path $p.repo '.npmrc'), (Join-Path $p.folder '.npmrc')) | Select-Object -Unique) { if ([IO.File]::Exists($cand)) { $facts.Add((Get-S13NpmrcFacts -Path $cand -Scope 'project')) } }
        }
        $script:Ctx.NpmRcFacts = $facts.ToArray()
        Add-BvsInventory -Run $run -Name 'npmConfig' -Data $facts.ToArray()
        $plain = @($facts | Where-Object { $_.exists } | ForEach-Object { $f = $_; @($f.tokens | Where-Object { $_.plaintext }) | ForEach-Object { [ordered]@{ type = 'file'; path = $f.path; scope = $f.scope; modified = $f.modified; registry = $_.registry; field = $_.field; tokenClass = $_.class; length = $_.length } } })
        if ($plain.Count) {
            $npmState = $script:Ctx.NpmTokenState
            $onlyRejected = ($npmState -eq 'rejected') -and -not @($plain | Where-Object { $_.registry -notmatch 'registry\.npmjs\.org' }).Count
            $classes = (@($plain | ForEach-Object { "$($_.tokenClass) for $($_.registry)" }) | Select-Object -Unique) -join '; '
            Add-S13Finding -Check 'npm.local_config' -Title ("Plaintext registry token(s) stored on disk ({0})" -f $classes) -Severity $(if ($onlyRejected) { 'low' } else { 'high' }) -Class hardening -Confidence high `
                -Reasons @('plaintext_secret') -Evidence $plain -Mitre @('T1552.001') `
                -FpNotes ("Normal for developers who publish from their workstation, and also reported by S12. npm token state: {0}." -f $npmState) `
                -Recommendation 'Any malware or worm that runs as you (an npm postinstall script, for example) can read these and publish under your name. Prefer npm trusted publishing (GitHub Actions OIDC) or a short-lived granular token that you add only when publishing; revoke the stored tokens at npmjs.com and github.com/settings/tokens after replacing them.'
        }
        foreach ($f in @($facts | Where-Object { $_.exists -and $_.strictSsl -match '^(false|0)$' })) {
            Add-S13Finding -Check 'npm.local_config' -Title "npm TLS certificate checking disabled (strict-ssl=false) in $($f.scope) npmrc" -Severity medium -Class hardening -Confidence high `
                -Reasons @('tls_verification_disabled') -Evidence @([ordered]@{ type = 'file'; path = $f.path; key = 'strict-ssl'; value = $f.strictSsl; modified = $f.modified }) -Mitre @('T1557') `
                -FpNotes 'Often set to get past HTTPS-scanning antivirus (Avast Web Shield re-signs TLS with its own root, which Node does not trust).' `
                -Recommendation 'Remove strict-ssl=false. If Avast HTTPS scanning breaks npm, export the Avast root certificate and point npm at it (cafile=<path>) or set NODE_EXTRA_CA_CERTS, instead of turning verification off.'
        }
        foreach ($f in @($facts | Where-Object { $_.exists -and $_.registry -and $_.registry -notmatch '^https://registry\.npmjs\.org/?' })) {
            Add-S13Finding -Check 'npm.local_config' -Title "Default npm registry overridden in $($f.scope) npmrc: $($f.registry)" -Severity high -Class suspicious -Confidence medium `
                -Reasons @('registry_override') -Evidence @([ordered]@{ type = 'file'; path = $f.path; key = 'registry'; value = $f.registry }) -Mitre @('T1195.002') `
                -FpNotes 'Company mirrors (Artifactory, Verdaccio) legitimately override the registry.' `
                -Recommendation 'Confirm you configured this registry; otherwise remove the line, since every install would come from it.'
        }
        $facts.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.maintainer_search' -Description 'Public npm search maintainer:<npm user>: packages under the account that do not exist in the local repos' -Script {
        $cands = [System.Collections.Generic.List[string]]::new()
        if ($script:Ctx.NpmUser) { $cands.Add($script:Ctx.NpmUser) }
        else {
            foreach ($p in @($script:Ctx.LocalPackages | Where-Object { $_.publishable })) {
                $pk = Get-S13Packument -Name $p.name
                if ($pk.Status -eq 200) { foreach ($m in @($pk.Data.maintainers)) { if ($m.name -and -not $cands.Contains([string]$m.name)) { $cands.Add([string]$m.name) } } }
            }
        }
        if (-not $cands.Count) { Set-BvsCheckStatus -Id 'npm.maintainer_search' -Status not_applicable -Reason 'npm user unknown (no valid token and no published local package)'; return }
        $expected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $script:Ctx.LocalPackages) { [void]$expected.Add($p.name); foreach ($h in @($p.history)) { if ($h.name) { [void]$expected.Add($h.name) } } }
        foreach ($n in @($NpmPackage)) { if ($n) { [void]$expected.Add($n) } }
        $found = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $cands) {
            $r = Invoke-S13Web -Uri ('https://registry.npmjs.org/-/v1/search?text=' + [uri]::EscapeDataString("maintainer:$c") + '&size=250') -SaveName ('npm-search-maintainer-' + (Get-S13SafeName $c) + '.json')
            if ($r.Status -ne 200) { Add-S13Error -Check 'npm.maintainer_search' -Message "search for maintainer:$c returned HTTP $($r.Status)"; continue }
            foreach ($o in @($r.Data.objects)) {
                $pkg = $o.package
                $name = [string]$pkg.name
                $isExp = $expected.Contains($name) -or [bool](Find-S13Expected -Category 'npmPackage' -Value $name)
                $found.Add([pscustomobject][ordered]@{ name = $name; version = [string]$pkg.version; date = (Format-S13Date $pkg.date); publisher = [string]$pkg.publisher.username; maintainers = @($pkg.maintainers | ForEach-Object { [string]$_.username }); searchedAs = $c; expected = $isExp })
            }
        }
        $script:Ctx.SearchResults = $found.ToArray()
        $unexpected = @($found | Where-Object { -not $_.expected })
        if ($unexpected.Count) {
            Add-S13Finding -Check 'npm.maintainer_search' -Title ("{0} npm package(s) under your account have no local source: {1}" -f $unexpected.Count, (@($unexpected | ForEach-Object { $_.name }) -join ', ')) -Severity high -Class suspicious -Confidence medium `
                -Reasons @('unknown_package') -Evidence @($unexpected | ForEach-Object { [ordered]@{ type = 'npm_package'; name = $_.name; version = $_.version; date = $_.date; publisher = $_.publisher; maintainers = $_.maintainers } }) -Mitre @('T1195.002') `
                -FpNotes 'Packages you published from another machine, co-maintain for someone else, or removed from disk show up here too.' `
                -Recommendation 'Confirm each package at https://www.npmjs.com/~<you>. For unknown ones check the versions/time tab and the publisher, then remove yourself as maintainer or deprecate/unpublish, and rotate npm tokens.'
        }
        Add-BvsInventory -Run $run -Name 'npmMaintainerSearch' -Data ([ordered]@{ searchedAs = $cands.ToArray(); results = $found.ToArray() })
        $found.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.packument' -Description 'Registry metadata per package: versions, publish times, publishers, maintainers, dist-tags, modification time' -Script {
        $names = [System.Collections.Generic.List[string]]::new()
        foreach ($n in @($NpmPackage) + @($script:Ctx.LocalPackages | Where-Object { -not $_.private } | ForEach-Object { $_.name }) + @($script:Ctx.SearchResults | ForEach-Object { $_.name })) {
            if ($n -and -not $names.Contains($n)) { $names.Add($n) }
        }
        if (-not $names.Count) { Set-BvsCheckStatus -Id 'npm.packument' -Status not_applicable -Reason 'no npm package to check'; return }
        $rows = [System.Collections.Generic.List[object]]::new()
        $owned = [System.Collections.Generic.List[string]]::new()
        foreach ($n in ($names | Select-Object -First 25)) {
            $r = Get-S13Packument -Name $n
            $local = @($script:Ctx.LocalPackages | Where-Object { $_.name -eq $n }) | Select-Object -First 1
            if ($r.Status -eq 404) { $rows.Add([ordered]@{ name = $n; onNpm = $false; owned = $false; local = [bool]$local }); continue }
            if ($r.Status -ne 200 -or $null -eq $r.Data) { Add-S13Error -Check 'npm.packument' -Message "packument $n HTTP $($r.Status)"; continue }
            $pk = $r.Data
            $maint = @($pk.maintainers | ForEach-Object { [string]$_.name })
            $repoUrl = [string]$pk.repository.url
            $gh = Get-S13GitHubRemote ($repoUrl -replace '^git\+', '')
            $isOwned = ($script:Ctx.NpmUser -and $maint -contains $script:Ctx.NpmUser) -or ($gh -and $script:Ctx.GitHubUser -and $gh.owner -ieq $script:Ctx.GitHubUser -and ($local -or @($script:Ctx.SearchResults | Where-Object { $_.name -eq $n }).Count)) -or ($NpmPackage -contains $n)
            $vers = Get-S13PackumentVersions $pk
            $tags = [ordered]@{}
            if ($pk.'dist-tags') { foreach ($t in $pk.'dist-tags'.PSObject.Properties) { $tags[$t.Name] = [string]$t.Value } }
            $row = [ordered]@{ name = $n; onNpm = $true; owned = [bool]$isOwned; local = [bool]$local; created = (Format-S13Date $pk.time.created); modified = (Format-S13Date $pk.time.modified); latest = $tags['latest']; distTags = $tags; versions = @($vers).Count; maintainers = $maint; repository = (Protect-BvsUrl $repoUrl); lastPublished = $(if (@($vers).Count) { Format-S13Date (@($vers | Sort-Object published)[-1].published) } else { $null }) }
            $rows.Add($row)
            if (-not $isOwned) {
                if ($local -and -not $local.private) {
                    Add-S13Finding -Check 'npm.packument' -Title "npm package '$n' (same name as a local workspace package) is published by someone else" -Severity low -Class suspicious -Confidence low `
                        -Reasons @('name_collision') -Evidence @([ordered]@{ type = 'npm_package'; name = $n; maintainers = $maint; localPath = $local.repo }) -Mitre @('T1195.002') `
                        -FpNotes 'Unrelated projects often share generic names; it only matters if something resolves this name from the registry instead of the workspace.' `
                        -Recommendation "Keep workspace dependencies on the workspace: protocol, or rename/scope the local package, so installs never pull the public '$n'."
                }
                continue
            }
            $owned.Add($n)
            $exp = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            if ($script:Ctx.NpmUser) { [void]$exp.Add($script:Ctx.NpmUser) }
            foreach ($m in $maint) { if (Find-S13Expected -Category 'npmMaintainer' -Value $m) { [void]$exp.Add($m) } }
            if (-not $script:Ctx.NpmUser -and $maint.Count -eq 1) { [void]$exp.Add($maint[0]) }
            $odd = @($maint | Where-Object { -not $exp.Contains($_) })
            if ($odd.Count -and ($script:Ctx.NpmUser -or $maint.Count -gt 1)) {
                Add-S13Finding -Check 'npm.packument' -Title ("npm package '$n' has maintainer(s) other than your account: {0}" -f ($odd -join ', ')) -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('unknown_maintainer') -Evidence @([ordered]@{ type = 'npm_package'; name = $n; maintainers = $maint; you = $script:Ctx.NpmUser }) -Mitre @('T1195.002', 'T1098') `
                    -FpNotes 'A co-maintainer you added deliberately looks the same.' `
                    -Recommendation "Check https://www.npmjs.com/package/$n/access; remove maintainers you did not add and rotate your npm tokens."
            }
            if ($tags['latest']) {
                $maxV = @($vers | Where-Object { $_.version -notmatch '-' })[-1].version
                if ($maxV -and $tags['latest'] -ne $maxV) {
                    Add-S13Finding -Check 'npm.packument' -Title "npm package '$n': dist-tag latest ($($tags['latest'])) is not the highest release ($maxV)" -Severity medium -Class suspicious -Confidence low `
                        -Reasons @('dist_tag_anomaly') -Evidence @([ordered]@{ type = 'npm_package'; name = $n; distTags = $tags; highest = $maxV }) -Mitre @('T1195.002') `
                        -FpNotes 'Deliberately moving latest back after a bad release produces the same picture.' -Recommendation 'Confirm you set the dist-tags (npm dist-tag ls is read-only, or check the package page).'
                }
            }
            $lastPub = @($vers | Sort-Object published)[-1].published
            $mod = ConvertTo-S13Date $pk.time.modified
            if ($lastPub -and $mod -and ($mod - $lastPub).TotalHours -gt 24) {
                Add-S13Finding -Check 'npm.packument' -Title "npm package '$n' metadata changed after the last publish ($(Format-S13Date $mod))" -Severity low -Class suspicious -Confidence low `
                    -Reasons @('metadata_changed') -Evidence @([ordered]@{ type = 'npm_package'; name = $n; lastPublish = (Format-S13Date $lastPub); modified = (Format-S13Date $mod) }) -Mitre @('T1195.002') `
                    -FpNotes 'Deprecating a version, changing dist-tags, maintainers or the readme also updates the modification time.' -Recommendation 'Confirm you changed the package settings at that time.'
            }
            $unpub = @($pk.time.PSObject.Properties.Name | Where-Object { $_ -notin 'created', 'modified', 'unpublished' -and -not ($pk.versions.PSObject.Properties[$_]) })
            if ($unpub.Count) { $row['unpublishedVersions'] = $unpub }
        }
        $script:Ctx.Owned = @{}
        foreach ($n in $owned) { $script:Ctx.Owned[$n] = $true }
        Add-BvsInventory -Run $run -Name 'npmPackages' -Data $rows.ToArray()
        $rows.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.versions_vs_local' -Description 'Every published version vs the local repo: matching tag or version-bump commit, publish time vs commit time and usual hours, publisher, install scripts in the published manifest' -Script {
        if (-not $script:Ctx.Owned.Count) { Set-BvsCheckStatus -Id 'npm.versions_vs_local' -Status not_applicable -Reason 'no npm package owned by the user'; return }
        $tables = [ordered]@{}
        $installNames = @($iocs.npm.installScripts)
        foreach ($n in @($script:Ctx.Owned.Keys)) {
            $pk = (Get-S13Packument -Name $n).Data
            $local = Get-S13LocalPackage -Name $n
            $tags = if ($local) { Get-S13RepoTags -Repo $local.repo } else { $null }
            $vers = Get-S13PackumentVersions $pk
            $publishers = @($vers | ForEach-Object { [string]$_.manifest._npmUser.name } | Where-Object { $_ })
            $expPub = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            if ($script:Ctx.NpmUser) { [void]$expPub.Add($script:Ctx.NpmUser) }
            elseif ($publishers.Count) { [void]$expPub.Add(($publishers | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name) }
            foreach ($p in ($publishers | Select-Object -Unique)) { if (Find-S13Expected -Category 'npmMaintainer' -Value $p) { [void]$expPub.Add($p) } }
            $rows = [System.Collections.Generic.List[object]]::new()
            $noRef = [System.Collections.Generic.List[object]]::new(); $oddT = [System.Collections.Generic.List[object]]::new(); $badPub = [System.Collections.Generic.List[object]]::new(); $newScripts = [System.Collections.Generic.List[object]]::new()
            foreach ($v in $vers) {
                $m = $v.manifest
                $commit = $null
                if ($local) { $commit = @($local.history | Where-Object { $_.version -eq $v.version -and $_.name -eq $n } | Sort-Object committed) | Select-Object -First 1 }
                $tag = $null
                if ($tags) {
                    $want = @("v$($v.version)", $v.version, "$n@$($v.version)", "$n@v$($v.version)", "$n-v$($v.version)", "$(($n -split '/')[-1])@$($v.version)")
                    $tag = @($tags.refs | Where-Object { $want -contains $_.tag }) | Select-Object -First 1
                }
                $pubT = $v.published
                $delta = if ($commit -and $pubT) { [math]::Round(($pubT - $commit.committed).TotalHours, 2) } else { $null }
                $usual = if ($pubT) { Test-S13UsualHour -Baseline $script:Ctx.Baseline -Utc $pubT } else { $null }
                $near = if ($pubT) { Get-S13NearestCommitHours -Baseline $script:Ctx.Baseline -Utc $pubT } else { $null }
                $publisher = [string]$m._npmUser.name
                $scriptNames = if ($m.scripts) { @($m.scripts.PSObject.Properties.Name) } else { @() }
                $inst = @($scriptNames | Where-Object { $installNames -contains $_ })
                $baseScripts = if ($commit) { $commit.scripts } elseif ($local) { $local.scripts } else { $null }
                $baseNames = if ($baseScripts) { @($baseScripts.PSObject.Properties.Name) } else { @() }
                $newInst = @($inst | Where-Object { $baseNames -notcontains $_ -or [string]$baseScripts.$_ -ne [string]$m.scripts.$_ })
                $flags = [System.Collections.Generic.List[string]]::new()
                if ($local -and -not $commit -and -not $tag) { $flags.Add('no_local_tag_or_commit'); $noRef.Add($v) }
                if ($usual -eq $false -and ($null -eq $near -or $near -gt 72)) { $flags.Add('odd_time'); $oddT.Add($v) }
                if ($publisher -and -not $expPub.Contains($publisher)) { $flags.Add('unknown_publisher'); $badPub.Add($v) }
                if ($newInst.Count -and ($local -or $inst.Count)) { $flags.Add('install_scripts'); $newScripts.Add([pscustomobject]@{ v = $v; names = $newInst }) }
                if ($m.deprecated) { $flags.Add('deprecated') }
                $rows.Add([ordered]@{
                        version = $v.version; published = (Format-S13Date $pubT); localHour = $(if ($pubT) { Get-S13LocalHour $pubT } else { $null }); publisher = $publisher
                        localCommit = $(if ($commit) { $commit.commit.Substring(0, 12) } else { $null }); commitTime = $(if ($commit) { Format-S13Date $commit.committed } else { $null }); hoursAfterCommit = $delta
                        localTag = $(if ($tag) { $tag.tag } else { $null }); usualHour = $usual; hoursToNearestLocalCommit = $near
                        installScripts = $inst; attestations = [bool]$m.dist.attestations; signatures = @($m.dist.signatures).Count; fileCount = $m.dist.fileCount; unpackedSize = $m.dist.unpackedSize
                        deprecated = [string]$m.deprecated; flags = $flags.ToArray()
                    })
            }
            $tables[$n] = [ordered]@{ localRepo = $(if ($local) { $local.repo } else { $null }); localVersion = $(if ($local) { $local.version } else { $null }); tags = $(if ($tags) { $tags.refs } else { @() }); expectedPublishers = @($expPub); versions = $rows.ToArray() }
            $ent = @{ accounts = @([ordered]@{ type = 'npm'; login = $script:Ctx.NpmUser }) }
            if ($noRef.Count) {
                $syncNote = ''
                if ($local -and $script:Ctx.RepoSync.ContainsKey($local.repo) -and $script:Ctx.RepoSync[$local.repo].remoteHeadInLocalClone -eq $false) { $syncNote = ' The remote has commits missing from the local clone, so a fetch may explain it.' }
                Add-S13Finding -Check 'npm.versions_vs_local' -Title ("npm '{0}': {1} published version(s) have no matching local tag or version commit: {2}" -f $n, $noRef.Count, (@($noRef | ForEach-Object { $_.version }) -join ', ')) -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('version_without_source') -Evidence @($noRef | ForEach-Object { [ordered]@{ type = 'npm_version'; package = $n; version = $_.version; published = (Format-S13Date $_.published); publisher = [string]$_.manifest._npmUser.name } }) -Entities $ent -Mitre @('T1195.002') `
                    -FpNotes ("Publishing without committing the version bump, or from another clone, produces this too.$syncNote") `
                    -Recommendation 'Compare the tarball of that version with your source (npm pack --dry-run is read-only, or check the files tab on npmjs.com). If you did not publish it: deprecate/unpublish it, rotate npm tokens and check your account for other packages.'
            }
            if ($badPub.Count) {
                Add-S13Finding -Check 'npm.versions_vs_local' -Title ("npm '{0}': version(s) published by an unexpected npm user: {1}" -f $n, (@($badPub | ForEach-Object { "$($_.version) by $($_.manifest._npmUser.name)" }) -join ', ')) -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('unknown_publisher') -Evidence @($badPub | ForEach-Object { [ordered]@{ type = 'npm_version'; package = $n; version = $_.version; published = (Format-S13Date $_.published); publisher = [string]$_.manifest._npmUser.name; expected = @($expPub) } }) -Entities $ent -Mitre @('T1195.002') `
                    -FpNotes 'Trusted publishing from CI shows a different publisher ("GitHub Actions"); a co-maintainer publishing also looks like this.' `
                    -Recommendation 'Confirm who published these versions; if unknown, deprecate them, remove the maintainer and rotate tokens.'
            }
            if ($oddT.Count) {
                Add-S13Finding -Check 'npm.versions_vs_local' -Title ("npm '{0}': version(s) published at an hour you never commit and far from any local commit: {1}" -f $n, (@($oddT | ForEach-Object { $_.version }) -join ', ')) -Severity high -Class suspicious -Confidence low `
                    -Reasons @('unusual_time') -Evidence @($oddT | ForEach-Object { [ordered]@{ type = 'npm_version'; package = $n; version = $_.version; published = (Format-S13Date $_.published); localHour = (Get-S13LocalHour $_.published); hoursToNearestLocalCommit = (Get-S13NearestCommitHours -Baseline $script:Ctx.Baseline -Utc $_.published) } }) -Entities $ent -Mitre @('T1195.002') `
                    -FpNotes 'The baseline is local git history of the last year only; publishing from another device or while travelling looks the same.' `
                    -Recommendation 'Check that you published these versions (npm account > Packages > versions).'
            }
            foreach ($ns in $newScripts) {
                $txt = (@($ns.names | ForEach-Object { "$_=$($ns.v.manifest.scripts.$_)" }) -join '; ')
                $ioc = $txt -match [string]$iocs.npm.installScriptIocRegex
                Add-S13Finding -Check 'npm.versions_vs_local' -Title ("npm '{0}@{1}': published manifest has install script(s) not in the local package.json: {2}" -f $n, $ns.v.version, ($ns.names -join ', ')) -Severity critical -Class $(if ($ioc) { 'compromise' } else { 'suspicious' }) -Confidence $(if ($ioc) { 'high' } else { 'medium' }) `
                    -Reasons @('install_script', $(if ($ioc) { 'intel_match' } else { 'unexpected_script' })) -Evidence @([ordered]@{ type = 'npm_version'; package = $n; version = $ns.v.version; published = (Format-S13Date $ns.v.published); scripts = $txt }) -Entities $ent -Mitre @('T1195.002', 'T1059.007') `
                    -FpNotes 'Only an uncommitted local change of your own that added the script would explain this benignly.' `
                    -Recommendation 'Do not install this version anywhere. Deprecate/unpublish it, rotate npm and GitHub tokens, and check every machine/CI that installed it for worm artefacts.'
            }
        }
        Add-BvsInventory -Run $run -Name 'npmVersions' -Data $tables
        @($tables.Keys)
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.registry_signatures' -Description 'npm registry ECDSA signatures (dist.signatures) verified against registry.npmjs.org/-/npm/v1/keys for every version' -Script {
        if (-not $script:Ctx.Owned.Count) { Set-BvsCheckStatus -Id 'npm.registry_signatures' -Status not_applicable -Reason 'no npm package owned by the user'; return }
        $kr = Invoke-S13Web -Uri 'https://registry.npmjs.org/-/npm/v1/keys' -SaveName 'npm-registry-keys.json'
        if ($kr.Status -ne 200) { throw "registry keys HTTP $($kr.Status)" }
        $keys = @($kr.Data.keys)
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($n in @($script:Ctx.Owned.Keys)) {
            foreach ($v in (Get-S13PackumentVersions (Get-S13Packument -Name $n).Data)) {
                $res = Test-S13NpmSignature -Name $n -Version $v.version -Integrity ([string]$v.manifest.dist.integrity) -Signatures @($v.manifest.dist.signatures) -Keys $keys
                $out.Add([pscustomobject]@{ package = $n; version = $v.version; result = $res })
            }
        }
        $bad = @($out | Where-Object { $_.result -in 'invalid', 'missing', 'unknown-key' })
        if ($bad.Count) {
            $inv = @($bad | Where-Object { $_.result -eq 'invalid' })
            Add-S13Finding -Check 'npm.registry_signatures' -Title ("{0} npm version(s) failed registry signature verification" -f $bad.Count) -Severity $(if ($inv.Count) { 'high' } else { 'medium' }) -Class suspicious -Confidence medium `
                -Reasons @('signature_failure') -Evidence @($bad | ForEach-Object { [ordered]@{ type = 'npm_version'; package = $_.package; version = $_.version; result = $_.result } }) -Mitre @('T1195.002', 'T1557') `
                -FpNotes 'Very old versions (before 2022) have no registry signatures; a TLS-intercepting proxy cannot forge valid signatures.' `
                -Recommendation 'Re-run on another network. A persistent invalid signature means the metadata was altered: report it to npm and do not install that version.'
        }
        Add-BvsInventory -Run $run -Name 'npmSignatures' -Data ([ordered]@{ keys = @($keys | ForEach-Object { [ordered]@{ keyid = [string]$_.keyid; expires = [string]$_.expires } }); results = $out.ToArray() })
        $out.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.provenance' -Description 'Provenance attestations (dist.attestations): source repository, workflow and commit vs the local repo' -Script {
        if (-not $script:Ctx.Owned.Count) { Set-BvsCheckStatus -Id 'npm.provenance' -Status not_applicable -Reason 'no npm package owned by the user'; return }
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($n in @($script:Ctx.Owned.Keys)) {
            $vers = Get-S13PackumentVersions (Get-S13Packument -Name $n).Data
            $withAtt = @($vers | Where-Object { $_.manifest.dist.attestations } | Sort-Object published -Descending | Select-Object -First 3)
            $local = Get-S13LocalPackage -Name $n
            foreach ($v in $withAtt) {
                $p = Get-S13Provenance -Name $n -Version $v.version -Dist $v.manifest.dist
                if ($null -eq $p) { continue }
                if ($p.commit -and $local) { $p.commitInLocalRepo = ([string](@(git --no-optional-locks -C $local.repo cat-file -t $p.commit 2>$null) | Select-Object -First 1) -eq 'commit') }
                $p | Add-Member -NotePropertyName package -NotePropertyValue $n
                $all.Add($p)
                $gh = Get-S13GitHubRemote ([string]$p.repository)
                if ($p.repository -and $script:Ctx.GitHubUser -and (-not $gh -or $gh.owner -ine $script:Ctx.GitHubUser)) {
                    Add-S13Finding -Check 'npm.provenance' -Title "npm '$n@$($v.version)' provenance points to a repository outside your account: $($p.repository)" -Severity high -Class suspicious -Confidence medium `
                        -Reasons @('provenance_mismatch') -Evidence @([ordered]@{ type = 'npm_provenance'; package = $n; version = $v.version; repository = $p.repository; workflow = $p.workflow; ref = $p.ref; commit = $p.commit }) -Mitre @('T1195.002') `
                        -FpNotes 'A package moved to an organisation repo, or a fork used for CI, looks the same. The attestation signature itself is not verified here (npm audit signatures does that).' `
                        -Recommendation 'Confirm the build came from your repository; otherwise deprecate the version and rotate tokens.'
                }
            }
            if (-not $withAtt.Count -and $vers.Count) {
                Add-S13Finding -Check 'npm.provenance' -Title "npm '$n': no version has a provenance attestation (all published manually with a token)" -Severity low -Class hardening -Confidence high `
                    -Reasons @('no_provenance') -Evidence @([ordered]@{ type = 'npm_package'; package = $n; versions = $vers.Count; latest = $vers[-1].version }) -Mitre @('T1195.002') `
                    -FpNotes 'Common for small packages; it is a hardening gap, not a sign of compromise.' `
                    -Recommendation 'Publish from GitHub Actions with npm trusted publishing (OIDC) and --provenance, then set the package to disallow token publishing. Consumers can then verify each version was built from your repo.'
            }
        }
        Add-BvsInventory -Run $run -Name 'npmProvenance' -Data $all.ToArray()
        $all.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.tarballs' -Description "Download the newest $TarballCount tarball(s) per owned package (bytes only), verify dist.integrity, list with tar -tzf, read package.json in memory; compare files and install scripts with the repo's publishing package.json" -Script {
        if (-not $script:Ctx.Owned.Count -or $TarballCount -le 0) { Set-BvsCheckStatus -Id 'npm.tarballs' -Status not_applicable -Reason 'no owned npm package (or -TarballCount 0)'; return }
        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($n in @($script:Ctx.Owned.Keys)) {
            $pk = (Get-S13Packument -Name $n).Data
            $local = Get-S13LocalPackage -Name $n
            $vers = @((Get-S13PackumentVersions $pk) | Where-Object { $_.published } | Sort-Object published -Descending | Select-Object -First $TarballCount)
            foreach ($v in $vers) {
                $results.Add((Invoke-S13TarballCheck -Name $n -Version $v -Local $local))
            }
        }
        Add-BvsInventory -Run $run -Name 'npmTarballs' -Data $results.ToArray()
        $results.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.token_profile' -Description 'Read-only: GET registry.npmjs.org/-/npm/v1/user (2FA mode) with the user .npmrc token (response not saved)' -Script {
        if ($script:Ctx.NpmTokenState -ne 'valid') { Set-BvsCheckStatus -Id 'npm.token_profile' -Status not_applicable -Reason "npm token $($script:Ctx.NpmTokenState)"; return }
        $r = Invoke-S13Web -Uri 'https://registry.npmjs.org/-/npm/v1/user' -SaveName 'npm-profile.json' -Headers @{ Authorization = "Bearer $($script:NpmToken)" } -NoSave
        if ($r.Status -in 401, 403) { Set-BvsCheckStatus -Id 'npm.token_profile' -Status partial -Reason "HTTP $($r.Status): token not allowed to read the profile (check 2FA manually)"; return }
        if ($r.Status -ne 200 -or $null -eq $r.Data) { throw "profile HTTP $($r.Status)" }
        $p = $r.Data
        $tfaMode = if ($p.tfa -is [bool] -or $null -eq $p.tfa) { if ($p.tfa) { 'enabled' } else { 'disabled' } } else { [string]$p.tfa.mode }
        $pending = if ($p.tfa -and $p.tfa -isnot [bool]) { [bool]$p.tfa.pending } else { $false }
        $prof = [ordered]@{ name = [string]$p.name; tfa = $tfaMode; tfaPending = $pending; emailVerified = $p.email_verified; emailDomain = $(if ([string]$p.email -match '@(.+)$') { $Matches[1] } else { $null }); created = (Format-S13Date $p.created); updated = (Format-S13Date $p.updated); cidrWhitelist = @($p.cidr_whitelist).Count }
        Add-BvsInventory -Run $run -Name 'npmProfile' -Data $prof
        if ($tfaMode -in 'disabled', '' -or $pending) {
            Add-S13Finding -Check 'npm.token_profile' -Title 'npm account has no active two-factor authentication' -Severity high -Class hardening -Confidence high -Reasons @('no_2fa') `
                -Evidence @([ordered]@{ type = 'npm_profile'; user = $prof.name; tfa = $tfaMode; pending = $pending }) -Mitre @('T1078') `
                -FpNotes 'None: the registry reports the account state directly.' -Recommendation "Enable 2FA (security key or authenticator) at https://www.npmjs.com/settings/$($prof.name)/profile with mode 'authorization and writes'."
        }
        elseif ($tfaMode -eq 'auth-only') {
            Add-S13Finding -Check 'npm.token_profile' -Title "npm 2FA protects logins only (mode auth-only), not publishing" -Severity medium -Class hardening -Confidence high -Reasons @('weak_2fa') `
                -Evidence @([ordered]@{ type = 'npm_profile'; user = $prof.name; tfa = $tfaMode }) -Mitre @('T1078') `
                -FpNotes 'Token-based publishing bypasses 2FA either way unless the package disallows tokens.' -Recommendation "Switch 2FA to 'authorization and writes' and set each package to require 2FA and disallow tokens (or use trusted publishing)."
        }
        $prof
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'npm.token_list' -Description 'Read-only: GET registry.npmjs.org/-/npm/v1/tokens (created, readonly, CIDR; identifiers masked) with the user .npmrc token' -Script {
        if ($script:Ctx.NpmTokenState -ne 'valid') { Set-BvsCheckStatus -Id 'npm.token_list' -Status not_applicable -Reason "npm token $($script:Ctx.NpmTokenState)"; return }
        $r = Invoke-S13Web -Uri 'https://registry.npmjs.org/-/npm/v1/tokens?perPage=100' -SaveName 'npm-tokens.json' -Headers @{ Authorization = "Bearer $($script:NpmToken)" } -NoSave
        if ($r.Status -in 401, 403) { Set-BvsCheckStatus -Id 'npm.token_list' -Status partial -Reason "HTTP $($r.Status): this token cannot list tokens (granular tokens usually cannot); check https://www.npmjs.com/settings/<user>/tokens manually"; return }
        if ($r.Status -ne 200 -or $null -eq $r.Data) { throw "tokens HTTP $($r.Status)" }
        $rows = [System.Collections.Generic.List[object]]::new()
        $i = 0
        foreach ($t in @($r.Data.objects)) {
            $i++
            $row = [ordered]@{ ref = "t$i"; created = (Format-S13Date $t.created); updated = (Format-S13Date $t.updated); readonly = [bool]$t.readonly; automation = [bool]$t.automation; cidrWhitelist = @($t.cidr_whitelist | Where-Object { $_ }).Count; ageDays = (Get-S13AgeDays $t.created) }
            foreach ($extra in 'name', 'type', 'expires', 'expiry') { if ($t.PSObject.Properties[$extra] -and $null -ne $t.$extra) { $row[$extra] = [string]$t.$extra } }
            $rows.Add([pscustomobject]$row)
        }
        Add-BvsInventory -Run $run -Name 'npmTokens' -Data ([ordered]@{ total = $rows.Count; tokens = $rows.ToArray(); note = 'token values and keys are never stored; ref is a positional label' })
        $write = @($rows | Where-Object { -not $_.readonly })
        $recentWrite = @($write | Where-Object { $null -ne $_.ageDays -and $_.ageDays -le $script:S13.RecentDays })
        if ($recentWrite.Count) {
            Add-S13Finding -Check 'npm.token_list' -Title ("{0} write-capable npm token(s) created in the last {1} days" -f $recentWrite.Count, $script:S13.RecentDays) -Severity high -Class suspicious -Confidence low `
                -Reasons @('recent_token') -Evidence @($recentWrite | ForEach-Object { [ordered]@{ type = 'npm_token'; ref = $_.ref; created = $_.created; readonly = $_.readonly; automation = $_.automation; cidrWhitelist = $_.cidrWhitelist } }) -Mitre @('T1528') `
                -FpNotes 'Rotating your own token (npm now limits write tokens to short lifetimes) creates new tokens regularly.' `
                -Recommendation 'Confirm you created each token at https://www.npmjs.com/settings/<user>/tokens; revoke unknown ones and check package versions published since.'
        }
        elseif ($write.Count -gt 1) {
            Add-S13Finding -Check 'npm.token_list' -Title ("{0} write-capable npm tokens exist" -f $write.Count) -Severity medium -Class hardening -Confidence medium `
                -Reasons @('excess_tokens') -Evidence @($write | ForEach-Object { [ordered]@{ type = 'npm_token'; ref = $_.ref; created = $_.created; automation = $_.automation; cidrWhitelist = $_.cidrWhitelist } }) -Mitre @('T1528') `
                -FpNotes 'Several machines or CI systems may each need one.' -Recommendation 'Keep one short-lived publish token (or none, with trusted publishing) and revoke the rest; restrict by CIDR where possible.'
        }
        $rows.ToArray()
    } | Out-Null

    $script:NpmToken = $null
}

function Invoke-S13TarballCheck {
    param([string]$Name, $Version, $Local)
    $iocs = $script:Ctx.Iocs
    $m = $Version.manifest
    $ver = $Version.version
    $res = [ordered]@{ package = $Name; version = $ver; published = (Format-S13Date $Version.published); tarball = (Protect-BvsUrl ([string]$m.dist.tarball)); savedAs = $null; bytes = $null; integrity = $null; shasum = $null; files = @(); listing = $null; scripts = @(); installScripts = @(); baseline = $null; issues = @(); mtimes = @(); error = $null }
    $issues = [System.Collections.Generic.List[object]]::new()
    $tgzUrl = [string]$m.dist.tarball
    if (-not $tgzUrl -or ([uri]$tgzUrl).Host -ne 'registry.npmjs.org') { $res.error = "tarball URL not on registry.npmjs.org: $tgzUrl"; Add-S13Error -Check 'npm.tarballs' -Message $res.error; return [pscustomobject]$res }
    $dl = Invoke-S13Web -Uri $tgzUrl -SaveName ("npm-tarball-{0}-{1}.tgz" -f (Get-S13SafeName $Name), $ver) -Binary -MaxBytes 200MB -TimeoutSec 120
    if ($dl.Status -ne 200 -or $null -eq $dl.Bytes) { $res.error = "download HTTP $($dl.Status)"; Add-S13Error -Check 'npm.tarballs' -Message "$Name@$ver $($res.error)"; return [pscustomobject]$res }
    $res.savedAs = $dl.File
    $res.bytes = $dl.Bytes.Length
    $sri = 'sha512-' + [Convert]::ToBase64String([Security.Cryptography.SHA512]::HashData($dl.Bytes))
    $res.integrity = if ($m.dist.integrity) { if ($sri -eq [string]$m.dist.integrity) { 'match' } else { 'MISMATCH' } } else { 'not published' }
    $sha1 = [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($dl.Bytes)).ToLowerInvariant()
    $res.shasum = if ($m.dist.shasum) { if ($sha1 -eq [string]$m.dist.shasum) { 'match' } else { 'MISMATCH' } } else { 'not published' }
    if ($res.integrity -eq 'MISMATCH' -or $res.shasum -eq 'MISMATCH') { $issues.Add([pscustomobject]@{ kind = 'integrity_mismatch'; severity = 'high'; class = 'suspicious'; detail = "integrity $($res.integrity), shasum $($res.shasum)" }) }
    # Listing with tar (list only) and an in-memory read with System.Formats.Tar.
    $tarOut = @(tar -tzf $dl.File 2>&1)
    $tarExit = $LASTEXITCODE
    $tarNames = @($tarOut | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $entries = Read-S13Tarball -Path $dl.File
    $fileEntries = @($entries | Where-Object { $_.type -match 'RegularFile' })
    $res.listing = [ordered]@{ tool = 'tar -tzf'; exitCode = $tarExit; entries = $tarNames.Count; readerEntries = $entries.Count }
    if ($tarExit -ne 0 -or $tarNames.Count -ne $entries.Count) { $issues.Add([pscustomobject]@{ kind = 'listing_mismatch'; severity = 'medium'; class = 'suspicious'; detail = "tar listed $($tarNames.Count) entries (exit $tarExit), reader saw $($entries.Count)" }) }
    foreach ($e in $entries) {
        if ($e.name -match '(^|/)\.\.(/|$)' -or $e.name -match '^(/|[A-Za-z]:)') { $issues.Add([pscustomobject]@{ kind = 'path_traversal'; severity = 'high'; class = 'suspicious'; detail = "entry '$($e.name)'" }) }
        if ($e.type -match 'Link') { $issues.Add([pscustomobject]@{ kind = 'link_entry'; severity = 'medium'; class = 'suspicious'; detail = "link entry '$($e.name)'" }) }
    }
    $res.mtimes = @($fileEntries | ForEach-Object { $_.mtime } | Select-Object -Unique)
    $pj = @($fileEntries | Where-Object { $_.rel -eq 'package.json' }) | Select-Object -First 1
    $tarPkg = if ($pj -and $pj.text) { ConvertFrom-S13Json $pj.text } else { $null }
    if ($null -eq $tarPkg) { $issues.Add([pscustomobject]@{ kind = 'no_package_json'; severity = 'medium'; class = 'suspicious'; detail = 'package/package.json missing or unreadable' }) }
    $tarScripts = if ($tarPkg -and $tarPkg.scripts) { $tarPkg.scripts } else { $null }
    $tarScriptNames = if ($tarScripts) { @($tarScripts.PSObject.Properties.Name) } else { @() }
    $res.scripts = @($tarScriptNames | ForEach-Object { [ordered]@{ name = $_; command = [string]$tarScripts.$_ } })
    $res.installScripts = @($tarScriptNames | Where-Object { @($iocs.npm.installScripts) -contains $_ })
    # Baseline: the repo's package.json at the commit that set this version, else the current file.
    $base = $null; $baseFrom = $null
    if ($Local) {
        $hc = @($Local.history | Where-Object { $_.version -eq $ver -and $_.name -eq $Name } | Sort-Object committed) | Select-Object -First 1
        if ($hc) { $base = $hc; $baseFrom = "commit $($hc.commit.Substring(0, 12))" } else { $base = $Local; $baseFrom = 'working tree package.json' }
    }
    $res.baseline = $baseFrom
    $include = @(); $exclude = @(); $always = @('package.json')
    if ($base) {
        foreach ($g in @($base.files)) { $gs = [string]$g; if ($gs.StartsWith('!')) { $exclude += ConvertTo-S13GlobRegex $gs.Substring(1) } elseif ($gs) { $include += ConvertTo-S13GlobRegex $gs } }
        if ($base.main) { $always += (([string]$base.main) -replace '^\./', '') }
        if ($base.bin -is [string]) { $always += (([string]$base.bin) -replace '^\./', '') }
        elseif ($base.bin) { foreach ($bp in $base.bin.PSObject.Properties) { $always += (([string]$bp.Value) -replace '^\./', '') } }
    }
    $sameVersionAsLocal = $Local -and $Local.version -eq $ver
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $fileEntries) {
        $rel = $e.rel
        $leaf = ($rel -split '/')[-1]
        $isRoot = $rel -notmatch '/'
        $expected = $null
        if ($always -contains $rel -or $rel -match '^(README|LICENSE|LICENCE|CHANGELOG|HISTORY|NOTICE)(\.[^/]*)?$') { $expected = $true }
        elseif ($include.Count) {
            $hit = $false
            foreach ($rx in $include) { if ($rel -match $rx) { $hit = $true; break } }
            if ($hit) { foreach ($rx in $exclude) { if ($rel -match $rx) { $hit = $false; break } } }
            $expected = $hit
        }
        $same = $null
        if ($sameVersionAsLocal -and $rel -ne 'package.json') {
            $lp = Join-Path $Local.folder ($rel -replace '/', '\')
            if ([IO.File]::Exists($lp)) { $same = ((Get-BvsHash -Path $lp) -eq $e.sha256) }
        }
        $rows.Add([ordered]@{ path = $rel; size = $e.size; mode = $e.mode; expected = $expected; sameAsLocalBuild = $same; sha256 = $e.sha256 })
        foreach ($mf in @($iocs.npm.maliciousFileNames)) {
            if ($leaf -match [string]$mf.regex -and (-not [bool]$mf.rootOnly -or $isRoot)) { $issues.Add([pscustomobject]@{ kind = 'malicious_file'; severity = [string]$mf.severity; class = $(if ($mf.severity -eq 'critical') { 'compromise' } else { 'suspicious' }); detail = "$rel ($($mf.family))" }) }
        }
        if (@($iocs.npm.knownBadSha256) -contains $e.sha256) { $issues.Add([pscustomobject]@{ kind = 'known_bad_hash'; severity = 'critical'; class = 'compromise'; detail = "$rel sha256 matches a known malicious file" }) }
        if ($iocs.npm.sensitiveFileRegex -and $rel -match [string]$iocs.npm.sensitiveFileRegex) { $issues.Add([pscustomobject]@{ kind = 'sensitive_file'; severity = 'high'; class = 'hardening'; detail = "$rel published in the tarball" }) }
        if ($expected -eq $false) {
            if ($rel -match '\.(js|cjs|mjs|sh|ps1|bat|cmd|exe|dll|node|py|vbs)$') { $issues.Add([pscustomobject]@{ kind = 'unexpected_executable'; severity = 'high'; class = 'suspicious'; detail = "$rel is outside the package.json files field" }) }
            else { $issues.Add([pscustomobject]@{ kind = 'unexpected_file'; severity = 'low'; class = 'hygiene'; detail = "$rel is outside the package.json files field" }) }
        }
        if ($e.text -and $rel -match '\.(js|cjs|mjs|json|sh)$') {
            foreach ($s in @($iocs.npm.contentIocStrings)) {
                if (-not $e.text.Contains([string]$s)) { continue }
                $localHas = $null
                if ($Local) {
                    $lp2 = Join-Path $Local.folder ($rel -replace '/', '\')
                    if ([IO.File]::Exists($lp2) -and (Get-Item -LiteralPath $lp2).Length -le 25MB) { $localHas = [IO.File]::ReadAllText($lp2).Contains([string]$s) }
                }
                if ($localHas -ne $true) { $issues.Add([pscustomobject]@{ kind = 'ioc_string'; severity = 'high'; class = 'suspicious'; detail = "$rel contains '$s' (not present in the local copy)" }) }
            }
        }
    }
    $res.files = $rows.ToArray()
    # Install scripts in the tarball package.json that the source package.json does not have.
    $baseScripts = if ($base) { $base.scripts } else { $null }
    $baseNames = if ($baseScripts) { @($baseScripts.PSObject.Properties.Name) } else { @() }
    foreach ($sn in $tarScriptNames) {
        $cmd = [string]$tarScripts.$sn
        $isInstall = @($iocs.npm.installScripts) -contains $sn
        $isLife = @($iocs.npm.lifecycleScriptsOfInterest) -contains $sn
        if (-not ($isInstall -or $isLife)) { continue }
        if ($base -and $baseNames -contains $sn -and [string]$baseScripts.$sn -eq $cmd) { continue }
        if (-not $base -and -not $isInstall) { continue }
        $ioc = $cmd -match [string]$iocs.npm.installScriptIocRegex
        if ($isInstall) { $issues.Add([pscustomobject]@{ kind = 'new_install_script'; severity = 'critical'; class = $(if ($ioc) { 'compromise' } else { 'suspicious' }); detail = "$sn = $cmd" }) }
        else { $issues.Add([pscustomobject]@{ kind = 'new_lifecycle_script'; severity = 'medium'; class = 'suspicious'; detail = "$sn = $cmd" }) }
    }
    # Manifest confusion: registry manifest vs the package.json inside the tarball.
    if ($tarPkg) {
        $diffs = [System.Collections.Generic.List[string]]::new()
        if ([string]$tarPkg.name -ne $Name) { $diffs.Add("name '$($tarPkg.name)'") }
        if ([string]$tarPkg.version -ne $ver) { $diffs.Add("version '$($tarPkg.version)'") }
        $regScripts = if ($m.scripts) { @($m.scripts.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) } else { @() }
        $tarScriptPairs = if ($tarScripts) { @($tarScripts.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) } else { @() }
        if ((@($regScripts | Sort-Object) -join "`n") -ne (@($tarScriptPairs | Sort-Object) -join "`n")) { $diffs.Add('scripts differ') }
        foreach ($dk in 'dependencies', 'optionalDependencies') {
            $a = if ($m.$dk) { @($m.$dk.PSObject.Properties | ForEach-Object { "$($_.Name)@$($_.Value)" }) } else { @() }
            $b = if ($tarPkg.$dk) { @($tarPkg.$dk.PSObject.Properties | ForEach-Object { "$($_.Name)@$($_.Value)" }) } else { @() }
            if ((@($a | Sort-Object) -join ',') -ne (@($b | Sort-Object) -join ',')) { $diffs.Add("$dk differ") }
        }
        if ($diffs.Count) { $issues.Add([pscustomobject]@{ kind = 'manifest_mismatch'; severity = 'high'; class = 'suspicious'; detail = 'registry manifest vs tarball package.json: ' + ($diffs -join ', ') }) }
        if ($base) {
            $baseDeps = @()
            foreach ($dk in 'dependencies', 'optionalDependencies') { if ($base.$dk) { $baseDeps += @($base.$dk.PSObject.Properties.Name) } }
            $newDeps = @()
            foreach ($dk in 'dependencies', 'optionalDependencies') { if ($tarPkg.$dk) { $newDeps += @($tarPkg.$dk.PSObject.Properties.Name | Where-Object { $baseDeps -notcontains $_ }) } }
            if ($newDeps.Count) { $issues.Add([pscustomobject]@{ kind = 'new_dependency'; severity = 'medium'; class = 'suspicious'; detail = 'runtime dependencies not in the source package.json: ' + ($newDeps -join ', ') }) }
        }
    }
    $res.issues = $issues.ToArray()
    # One finding per issue kind for this version.
    $ent = @{ files = @([ordered]@{ path = $dl.File; size = $dl.Bytes.Length }) }
    foreach ($grp in ($issues | Group-Object kind)) {
        $items = @($grp.Group)
        $sev = Get-S13MaxSeverity @($items | ForEach-Object { $_.severity })
        $cls = if (@($items | Where-Object { $_.class -eq 'compromise' }).Count) { 'compromise' } else { [string]$items[0].class }
        $detail = (@($items | ForEach-Object { $_.detail }) | Select-Object -First 10) -join '; '
        $titleMap = @{
            malicious_file = 'contains files named like worm payloads'; known_bad_hash = 'contains a file with a known malicious hash'; new_install_script = 'has install scripts that the source package.json does not have'
            new_lifecycle_script = 'has lifecycle scripts that the source package.json does not have'; sensitive_file = 'publishes sensitive files'; unexpected_executable = 'contains executable files outside the "files" field'
            unexpected_file = 'contains files outside the "files" field'; manifest_mismatch = 'registry manifest differs from the package.json inside the tarball'; new_dependency = 'declares runtime dependencies missing from the source package.json'
            path_traversal = 'contains path-traversal entries'; link_entry = 'contains link entries'; ioc_string = 'contains campaign marker strings not present in the local copy'
            integrity_mismatch = 'does not match its published integrity hash'; listing_mismatch = 'gives different listings with tar and the in-memory reader'; no_package_json = 'has no readable package.json'
        }
        $conf = if ($cls -eq 'compromise') { 'high' } elseif ($sev -in 'critical', 'high') { 'medium' } else { 'low' }
        Add-S13Finding -Check 'npm.tarballs' -Title ("npm tarball {0}@{1} {2}" -f $Name, $ver, $titleMap[[string]$grp.Name]) -Severity $sev -Class $cls -Confidence $conf `
            -Reasons @([string]$grp.Name) -Evidence @([ordered]@{ type = 'npm_tarball'; package = $Name; version = $ver; savedAs = $dl.File; baseline = $baseFrom; details = $detail }) -Entities $ent -Mitre @('T1195.002') `
            -FpNotes $(switch ([string]$grp.Name) { 'unexpected_file' { 'npm always adds some files (e.g. README/LICENSE variants); stale build output in dist can also land outside the pattern.' } 'new_dependency' { 'pnpm rewrites workspace: dependencies at publish time.' } 'manifest_mismatch' { 'Older npm clients normalised some fields differently.' } 'ioc_string' { 'Security tools (such as this scanner) contain these strings by design; only strings missing from the local copy are reported.' } default { 'Compare with your local build; a benign explanation needs an uncommitted change of your own at publish time.' } }) `
            -Recommendation $(if ($sev -eq 'critical') { 'Do not install this version. Deprecate/unpublish it, rotate npm and GitHub tokens, and check every machine and CI that installed it for worm artefacts.' } else { 'Inspect the listed entries (the tarball is saved under intel\registry.npmjs.org, never extract-and-run it) and republish a clean version if needed.' })
    }
    foreach ($e in $entries) { $e.text = $null }
    [pscustomobject]$res
}

#endregion

#region ---------- section C: authenticated GitHub ----------

$script:AuthChecks = [ordered]@{
    'github_auth.user'               = 'gh api user: 2FA, plan, private repo count, login matches the audited user'
    'github_auth.keys_emails'        = 'gh api user/keys, user/ssh_signing_keys, user/gpg_keys, user/emails (created dates, unknown emails)'
    'github_auth.repos'              = 'gh api user/repos?affiliation=owner (private repos included): worm names, -migration, random names'
    'github_auth.installations_orgs' = 'gh api user/installations and user/orgs'
    'github_auth.codespaces'         = 'gh api user/codespaces (skipped on 403/404: needs a scope we do not request)'
    'github_auth.repo_deep'          = 'Per owned non-fork repo: hooks, deploy keys, self-hosted runners, secret names, collaborators, invitations, branches, workflows, recent runs, environments, pages'
    'github_auth.events'             = 'gh api users/<user>/events (private events included)'
}

function Invoke-S13AuthSection {
    $run = $script:S13.Run
    $ga = $script:Ctx.GhAuth
    $ready = $ga -and $ga.loggedIn -and $script:S13.GhReady -and -not $PublicOnly
    if (-not $ready) {
        foreach ($id in $script:AuthChecks.Keys) {
            Invoke-BvsCheck -Run $run -Id $id -Description $script:AuthChecks[$id] -Script {
                if ($PublicOnly) { Set-BvsCheckStatus -Id $id -Status skipped -Reason 'public-only mode (-PublicOnly)' }
                elseif ($ga -and $ga.cli -and -not $ga.cli.usable) { Set-BvsCheckStatus -Id $id -Status not_applicable -Reason ([string]$ga.cli.reason) }
                else { Set-BvsCheckStatus -Id $id -Status needs_consent -Reason 'waiting for gh login' }
            } | Out-Null
        }
        return
    }
    $login = [string]$ga.account
    $iocs = $script:Ctx.Iocs

    Invoke-BvsCheck -Run $run -Id 'github_auth.user' -Description $script:AuthChecks['github_auth.user'] -Script {
        $r = Invoke-S13Gh -Path 'user'
        if (-not $r.Ok) { throw "gh api user failed: $($r.Status) $($r.Error)" }
        $p = $r.Data
        $u = [ordered]@{ login = [string]$p.login; twoFactor = $p.two_factor_authentication; plan = [string]$p.plan.name; ownedPrivateRepos = $p.owned_private_repos; totalPrivateRepos = $p.total_private_repos; privateGists = $p.private_gists; diskUsageKb = $p.disk_usage; created = (Format-S13Date $p.created_at); scopes = $ga.scopes }
        Add-BvsInventory -Run $run -Name 'githubAuthUser' -Data $u
        if ($script:Ctx.GitHubUser -and $u.login -and $u.login -ine $script:Ctx.GitHubUser) {
            Add-S13Finding -Check 'github_auth.user' -Title "gh is logged in as '$($u.login)' but the audited user is '$($script:Ctx.GitHubUser)'" -Severity medium -Class info -Confidence high -Reasons @('account_mismatch') `
                -Evidence @([ordered]@{ type = 'github_account'; ghLogin = $u.login; audited = $script:Ctx.GitHubUser }) -FpNotes 'You may own several accounts.' -Recommendation 'Re-run with -GitHubUser <login> or log gh into the audited account.'
        }
        if ($p.two_factor_authentication -eq $false) {
            Add-S13Finding -Check 'github_auth.user' -Title 'GitHub account has two-factor authentication disabled' -Severity high -Class hardening -Confidence high -Reasons @('no_2fa') `
                -Evidence @([ordered]@{ type = 'github_account'; login = $u.login; two_factor_authentication = $false }) -Mitre @('T1078') `
                -FpNotes 'None: GitHub reports the account state.' -Recommendation 'Enable 2FA (passkey/security key or authenticator app) at https://github.com/settings/security and store the recovery codes offline.'
        }
        $u
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.keys_emails' -Description $script:AuthChecks['github_auth.keys_emails'] -Script {
        $notes = [System.Collections.Generic.List[string]]::new()
        $local = @{}
        foreach ($l in $script:Ctx.LocalSsh) { $local[$l.fingerprint] = $l }
        $inv = [ordered]@{ keys = @(); signingKeys = @(); gpgKeys = @(); emails = @() }
        foreach ($spec in @(@{ path = 'user/keys'; kind = 'authentication'; slot = 'keys' }, @{ path = 'user/ssh_signing_keys'; kind = 'signing'; slot = 'signingKeys' })) {
            $r = Invoke-S13Gh -Path $spec.path -Paginate
            if (-not $r.Ok) { $notes.Add("$($spec.path): HTTP $($r.Status) (token scope read:public_key / read:ssh_signing_key not granted; public keys were compared in github.ssh_keys)"); continue }
            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($k in (ConvertTo-S13Array $r.Data)) {
                $f = Get-S13SshKeyFacts -Line ([string]$k.key) -Source $spec.path
                if (-not $f) { continue }
                $rows.Add([ordered]@{ kind = $spec.kind; id = $k.id; title = [string]$k.title; fingerprint = $f.fingerprint; type = $f.type; created = (Format-S13Date $k.created_at); lastUsed = (Format-S13Date $k.last_used); readOnly = $k.read_only; verified = $k.verified; localFile = $(if ($local[$f.fingerprint]) { $local[$f.fingerprint].source } else { $null }) })
            }
            $inv[$spec.slot] = $rows.ToArray()
            $unknown = @($rows | Where-Object { -not $_.localFile -and -not (Find-S13Expected -Category 'sshKey' -Value $_.fingerprint) -and -not $script:Ctx.ReportedKeys.Contains($_.fingerprint) })
            $recent = @($rows | Where-Object { -not $_.localFile -and $_.created -and (Get-S13AgeDays $_.created) -le $script:S13.RecentDays })
            if ($unknown.Count) {
                foreach ($x in $unknown) { [void]$script:Ctx.ReportedKeys.Add($x.fingerprint) }
                Add-S13Finding -Check 'github_auth.keys_emails' -Title ("GitHub account has {0} {1} key(s) not found on this machine" -f $unknown.Count, $spec.kind) -Severity high -Class suspicious -Confidence low `
                    -Reasons @('unknown_key') -Evidence @($unknown | ForEach-Object { $e = [ordered]@{ type = 'ssh_key' }; foreach ($kv in $_.GetEnumerator()) { $e[$kv.Key] = $kv.Value }; $e }) -Entities @{ accounts = @([ordered]@{ type = 'github'; login = $login }) } -Mitre @('T1098.004') `
                    -FpNotes 'Keys of your other devices are legitimately on GitHub; title and created date help identify them.' -Recommendation 'Identify the device for each key (title, created date); delete unknown keys at https://github.com/settings/keys and check the security log (public_key.create).'
            }
            if ($recent.Count) {
                Add-S13Finding -Check 'github_auth.keys_emails' -Title ("{0} {1} key(s) not on this machine were added in the last {2} days" -f $recent.Count, $spec.kind, $script:S13.RecentDays) -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('recent_key') -Evidence @($recent | ForEach-Object { [ordered]@{ type = 'ssh_key'; fingerprint = $_.fingerprint; title = $_.title; created = $_.created } }) -Mitre @('T1098.004') `
                    -FpNotes 'A key you added for a new device or VM in that period.' -Recommendation 'Confirm you added it; otherwise remove it and rotate your GitHub password and tokens.'
            }
        }
        $g = Invoke-S13Gh -Path 'user/gpg_keys' -Paginate
        if ($g.Ok) { $inv.gpgKeys = @((ConvertTo-S13Array $g.Data) | ForEach-Object { [ordered]@{ keyId = [string]$_.key_id; created = (Format-S13Date $_.created_at); expires = (Format-S13Date $_.expires_at); emails = @($_.emails | ForEach-Object { [string]$_.email }) } }) }
        else { $notes.Add("user/gpg_keys: HTTP $($g.Status) (scope read:gpg_key not granted)") }
        $em = Invoke-S13Gh -Path 'user/emails' -Paginate
        if ($em.Ok) {
            $rows = @((ConvertTo-S13Array $em.Data) | ForEach-Object { [ordered]@{ email = [string]$_.email; primary = [bool]$_.primary; verified = [bool]$_.verified; visibility = [string]$_.visibility } })
            $inv.emails = $rows
            $known = @($script:Ctx.Identity.emails)
            $unknownMail = @($rows | Where-Object { $known -notcontains $_.email -and $_.email -notmatch '@users\.noreply\.github\.com$' })
            if ($unknownMail.Count) {
                Add-S13Finding -Check 'github_auth.keys_emails' -Title ("GitHub account has {0} email address(es) not used in local git config" -f $unknownMail.Count) -Severity medium -Class suspicious -Confidence low `
                    -Reasons @('unknown_email') -Evidence @($unknownMail | ForEach-Object { [ordered]@{ type = 'github_email'; email = $_.email; primary = $_.primary; verified = $_.verified } }) -Mitre @('T1098') `
                    -FpNotes 'Old or secondary addresses of yours are normal.' -Recommendation 'Remove addresses you do not own at https://github.com/settings/emails: an attacker address can receive password resets.'
            }
        }
        else { $notes.Add("user/emails: HTTP $($em.Status) (scope user:email not granted)") }
        Add-BvsInventory -Run $run -Name 'githubAuthKeys' -Data $inv
        if ($notes.Count) { Set-BvsCheckStatus -Id 'github_auth.keys_emails' -Status partial -Reason ($notes -join '; ') }
        $inv
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.repos' -Description $script:AuthChecks['github_auth.repos'] -Script {
        $r = Invoke-S13Gh -Path 'user/repos?affiliation=owner&per_page=100' -Paginate
        if (-not $r.Ok) { throw "gh api user/repos failed: $($r.Status) $($r.Error)" }
        $repos = ConvertTo-S13Array $r.Data
        $script:Ctx.AuthRepos = $repos
        $res = Add-S13RepoFindings -Repos $repos -Check 'github_auth.repos'
        Add-BvsInventory -Run $run -Name 'githubReposAll' -Data ([ordered]@{ total = $repos.Count; private = @($repos | Where-Object { $_.private }).Count; repos = $res[0] })
        $res[0]
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.installations_orgs' -Description $script:AuthChecks['github_auth.installations_orgs'] -Script {
        $inv = [ordered]@{ installations = @(); orgs = @() }
        $notes = [System.Collections.Generic.List[string]]::new()
        $ins = Invoke-S13Gh -Path 'user/installations?per_page=100' -Paginate
        if ($ins.Ok) {
            $inv.installations = @((ConvertTo-S13Array $ins.Data) | ForEach-Object { [ordered]@{ app = [string]$_.app_slug; account = [string]$_.account.login; selection = [string]$_.repository_selection; created = (Format-S13Date $_.created_at); updated = (Format-S13Date $_.updated_at); permissions = $(if ($_.permissions) { @($_.permissions.PSObject.Properties | ForEach-Object { "$($_.Name):$($_.Value)" }) } else { @() }) } })
            $recent = @($inv.installations | Where-Object { $_.created -and (Get-S13AgeDays $_.created) -le $script:S13.RecentDays })
            if ($recent.Count) {
                Add-S13Finding -Check 'github_auth.installations_orgs' -Title ("{0} GitHub App installation(s) created in the last {1} days" -f $recent.Count, $script:S13.RecentDays) -Severity medium -Class suspicious -Confidence low `
                    -Reasons @('recent_app') -Evidence @($recent | ForEach-Object { [ordered]@{ type = 'github_app'; app = $_.app; account = $_.account; created = $_.created; permissions = $_.permissions } }) -Mitre @('T1528') `
                    -FpNotes 'Apps you installed yourself (CI, bots).' -Recommendation 'Review at https://github.com/settings/installations and uninstall unknown apps.'
            }
        }
        else { $notes.Add("user/installations: HTTP $($ins.Status) (OAuth tokens usually cannot list installations; see the manual check)") }
        $og = Invoke-S13Gh -Path 'user/orgs?per_page=100' -Paginate
        if ($og.Ok) { $inv.orgs = @((ConvertTo-S13Array $og.Data) | ForEach-Object { [string]$_.login }) } else { $notes.Add("user/orgs: HTTP $($og.Status)") }
        Add-BvsInventory -Run $run -Name 'githubInstallationsOrgs' -Data $inv
        if ($notes.Count) { Set-BvsCheckStatus -Id 'github_auth.installations_orgs' -Status partial -Reason ($notes -join '; ') }
        $inv
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.codespaces' -Description $script:AuthChecks['github_auth.codespaces'] -Script {
        $c = Invoke-S13Gh -Path 'user/codespaces' -Paginate
        if (-not $c.Ok) {
            if ($c.Status -in 401, 403, 404) { Set-BvsCheckStatus -Id 'github_auth.codespaces' -Status skipped -Reason "HTTP $($c.Status): needs the codespace scope, which this audit does not request"; return }
            throw "user/codespaces failed: $($c.Status) $($c.Error)"
        }
        $rows = @((ConvertTo-S13Array $c.Data) | ForEach-Object { [ordered]@{ name = [string]$_.name; repo = [string]$_.repository.full_name; state = [string]$_.state; created = (Format-S13Date $_.created_at); lastUsed = (Format-S13Date $_.last_used_at) } })
        Add-BvsInventory -Run $run -Name 'githubCodespaces' -Data $rows
        if ($rows.Count) {
            Add-S13Finding -Check 'github_auth.codespaces' -Title ("{0} codespace(s) exist on the account" -f $rows.Count) -Severity low -Class suspicious -Confidence low -Reasons @('codespaces') `
                -Evidence @($rows | ForEach-Object { [ordered]@{ type = 'codespace'; name = $_.name; repo = $_.repo; created = $_.created; lastUsed = $_.lastUsed } }) -Mitre @('T1578') `
                -FpNotes 'Codespaces you created yourself.' -Recommendation 'Delete codespaces you do not recognise at https://github.com/codespaces.'
        }
        $rows
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.repo_deep' -Description $script:AuthChecks['github_auth.repo_deep'] -Script {
        $repos = @((ConvertTo-S13Array $script:Ctx.AuthRepos) | Where-Object { -not $_.fork } | Select-Object -First $MaxRepos)
        if (-not $repos.Count) { Set-BvsCheckStatus -Id 'github_auth.repo_deep' -Status not_applicable -Reason 'no owned non-fork repos (or user/repos failed)'; return }
        $rows = [System.Collections.Generic.List[object]]::new()
        $errCount = 0
        foreach ($repo in $repos) {
            $row = Invoke-S13RepoDeep -Repo $repo -Login $login
            if (@($row.errors).Count) { $errCount++ }
            $rows.Add($row)
        }
        Add-BvsInventory -Run $run -Name 'githubRepoDeep' -Data $rows.ToArray()
        if ($errCount) { Set-BvsCheckStatus -Id 'github_auth.repo_deep' -Status partial -Reason "$errCount repo(s) had endpoint errors (see inventory.githubRepoDeep[].errors)" }
        $rows.ToArray()
    } | Out-Null

    Invoke-BvsCheck -Run $run -Id 'github_auth.events' -Description $script:AuthChecks['github_auth.events'] -Script {
        $u = if ($script:Ctx.GitHubUser) { $script:Ctx.GitHubUser } else { $login }
        $r = Invoke-S13Gh -Path "users/$u/events?per_page=100" -Paginate
        if (-not $r.Ok) { throw "users/$u/events failed: $($r.Status) $($r.Error)" }
        $events = @((ConvertTo-S13Array $r.Data) | Select-Object -First 300)
        $m = Measure-S13Events -Events $events -Login $u -Baseline $script:Ctx.Baseline -KnownEmails $script:Ctx.Identity.emails -KnownNames $script:Ctx.Identity.names
        # Events already analysed in the public stream are not reported twice.
        foreach ($id in @($script:Ctx.PublicEventIds)) { [void]$script:Ctx.ReportedEvents.Add("github_auth.events|$id") }
        Add-S13EventFindings -Measure $m -Check 'github_auth.events' -Scope 'authenticated'
        Add-BvsInventory -Run $run -Name 'githubEventsAll' -Data ([ordered]@{ fetched = $events.Count; privateEvents = @($events | Where-Object { $_.public -eq $false }).Count; summary = $m })
        $events
    } | Out-Null
}

function Invoke-S13RepoDeep {
    param($Repo, [string]$Login)
    $iocs = $script:Ctx.Iocs
    $full = [string]$Repo.full_name
    $owner = [string]$Repo.owner.login
    $row = [ordered]@{ repo = $full; private = [bool]$Repo.private; hooks = @(); deployKeys = @(); runners = @(); secrets = @(); collaborators = @(); invitations = @(); branches = @(); workflows = @(); runs = @(); environments = @(); pages = $null; errors = @() }
    $errs = [System.Collections.Generic.List[string]]::new()
    $localRepo = @($script:Ctx.Repos | Where-Object { @($_.remotes | Where-Object { "$($_.githubOwner)/$($_.githubRepo)" -ieq $full }).Count }) | Select-Object -First 1
    $ent = @{ accounts = @([ordered]@{ type = 'github'; login = $Login }) }
    $safeActors = @($iocs.githubSafeActors) + @($owner, $Login)
    try {
        # Webhooks
        $h = Invoke-S13Gh -Path "repos/$full/hooks" -Paginate
        if ($h.Ok) {
            $row.hooks = @((ConvertTo-S13Array $h.Data) | ForEach-Object {
                    $url = [string]$_.config.url
                    $hostName = try { ([uri]$url).Host } catch { $null }
                    [ordered]@{ id = $_.id; active = [bool]$_.active; events = @($_.events); host = $hostName; url = (Protect-BvsUrl $url); insecureSsl = [string]$_.config.insecure_ssl; created = (Format-S13Date $_.created_at); updated = (Format-S13Date $_.updated_at) }
                })
            foreach ($hk in $row.hooks) {
                $bad = @($iocs.webhookHostRegexes | Where-Object { $hk.host -and $hk.host -match [string]$_.regex }) | Select-Object -First 1
                $exp = Find-S13Expected -Category 'githubWebhook' -Value ([string]$hk.host)
                $sev = if ($bad) { [string]$bad.severity } else { 'medium' }
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("Webhook on {0} sends events to {1}" -f $full, $hk.host) -Severity $sev -Class $(if ($bad -and $sev -eq 'critical') { 'compromise' } else { 'suspicious' }) -Confidence $(if ($bad) { 'medium' } else { 'low' }) `
                    -Reasons @($(if ($bad) { 'exfil_host' } else { 'webhook' })) -Evidence @([ordered]@{ type = 'github_webhook'; repo = $full; host = $hk.host; url = $hk.url; events = $hk.events; created = $hk.created; active = $hk.active }) -Entities $ent -ExpectedItem $exp -Mitre @('T1567.004') `
                    -FpNotes 'CI/CD, chat and deployment integrations use webhooks legitimately.' -Recommendation "Confirm you added this webhook (Settings > Webhooks of $full); delete unknown ones and rotate repository secrets."
                if ($hk.insecureSsl -eq '1') {
                    Add-S13Finding -Check 'github_auth.repo_deep' -Title "Webhook on $full has TLS verification disabled" -Severity medium -Class hardening -Confidence high -Reasons @('tls_verification_disabled') `
                        -Evidence @([ordered]@{ type = 'github_webhook'; repo = $full; host = $hk.host; insecure_ssl = '1' }) -Mitre @('T1557') -FpNotes 'Self-signed internal endpoints.' -Recommendation 'Enable SSL verification on the webhook.'
                }
            }
        }
        elseif ($h.Status -ne 404) { $errs.Add("hooks: $($h.Status)") }
        # Deploy keys
        $k = Invoke-S13Gh -Path "repos/$full/keys" -Paginate
        if ($k.Ok) {
            $row.deployKeys = @((ConvertTo-S13Array $k.Data) | ForEach-Object {
                    $f = Get-S13SshKeyFacts -Line ([string]$_.key) -Source 'deploy'
                    [ordered]@{ id = $_.id; title = [string]$_.title; fingerprint = $f.fingerprint; readOnly = [bool]$_.read_only; created = (Format-S13Date $_.created_at); lastUsed = (Format-S13Date $_.last_used); addedBy = [string]$_.added_by; local = [bool]($f -and @($script:Ctx.LocalSsh | Where-Object { $_.fingerprint -eq $f.fingerprint }).Count) }
                })
            foreach ($dk in @($row.deployKeys | Where-Object { -not $_.local -and -not (Find-S13Expected -Category 'sshKey' -Value $_.fingerprint) })) {
                $recentKey = $dk.created -and (Get-S13AgeDays $dk.created) -le $script:S13.RecentDays
                $sev = if (-not $dk.readOnly -or $recentKey) { 'high' } else { 'medium' }
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("{0} deploy key '{1}' on {2}" -f $(if ($dk.readOnly) { 'Read-only' } else { 'Write-enabled' }), $dk.title, $full) -Severity $sev -Class suspicious -Confidence low `
                    -Reasons @('deploy_key') -Evidence @([ordered]@{ type = 'deploy_key'; repo = $full; title = $dk.title; fingerprint = $dk.fingerprint; readOnly = $dk.readOnly; created = $dk.created; lastUsed = $dk.lastUsed }) -Entities $ent -Mitre @('T1098.004') `
                    -FpNotes 'Deploy keys for servers/CI you set up (for example your own server) are normal.' -Recommendation "Confirm the key's server; remove unknown deploy keys at Settings > Deploy keys of $full."
            }
        }
        elseif ($k.Status -ne 404) { $errs.Add("keys: $($k.Status)") }
        # Self-hosted runners
        $rn = Invoke-S13Gh -Path "repos/$full/actions/runners" -Paginate
        if ($rn.Ok) {
            $row.runners = @((ConvertTo-S13Array $rn.Data) | ForEach-Object { [ordered]@{ id = $_.id; name = [string]$_.name; os = [string]$_.os; status = [string]$_.status; labels = @($_.labels | ForEach-Object { [string]$_.name }) } })
            foreach ($x in $row.runners) {
                $ioc = @($iocs.runnerNames | Where-Object { $x.name -match [string]$_.regex }) | Select-Object -First 1
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("Self-hosted runner '{0}' registered on {1}{2}" -f $x.name, $full, $(if ($ioc) { " ($($ioc.family))" } else { '' })) -Severity $(if ($ioc) { 'critical' } else { 'high' }) -Class $(if ($ioc) { 'compromise' } else { 'suspicious' }) -Confidence $(if ($ioc) { 'high' } else { 'low' }) `
                    -Reasons @($(if ($ioc) { 'intel_match' } else { 'self_hosted_runner' })) -Evidence @([ordered]@{ type = 'github_runner'; repo = $full; name = $x.name; os = $x.os; status = $x.status; labels = $x.labels }) -Entities $ent -Mitre @('T1072') `
                    -FpNotes $(if ($ioc) { 'Exact Shai-Hulud 2.0 runner name.' } else { 'A runner you registered for your own builds.' }) `
                    -Recommendation 'Remove unknown runners (Settings > Actions > Runners), find the machine that hosts them (Shai-Hulud installs one under ~/.dev-env on the infected host), and rotate all secrets.'
            }
        }
        elseif ($rn.Status -ne 404) { $errs.Add("runners: $($rn.Status)") }
        # Secret names and dates only
        $sc = Invoke-S13Gh -Path "repos/$full/actions/secrets" -Paginate
        if ($sc.Ok) { $row.secrets = @((ConvertTo-S13Array $sc.Data) | ForEach-Object { [ordered]@{ name = [string]$_.name; created = (Format-S13Date $_.created_at); updated = (Format-S13Date $_.updated_at) } }) }
        elseif ($sc.Status -ne 404) { $errs.Add("secrets: $($sc.Status)") }
        # Collaborators and invitations
        $co = Invoke-S13Gh -Path "repos/$full/collaborators?affiliation=direct&per_page=100" -Paginate
        if ($co.Ok) {
            $row.collaborators = @((ConvertTo-S13Array $co.Data) | Where-Object { [string]$_.login -ine $owner } | ForEach-Object { [ordered]@{ login = [string]$_.login; role = [string]$_.role_name; admin = [bool]$_.permissions.admin; push = [bool]$_.permissions.push } })
            foreach ($c in @($row.collaborators | Where-Object { -not (Find-S13Expected -Category 'githubCollaborator' -Value $_.login) })) {
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("Collaborator '{0}' has {1} access to {2}" -f $c.login, $(if ($c.admin) { 'admin' } elseif ($c.push) { 'write' } else { 'read' }), $full) -Severity $(if ($c.admin -or $c.push) { 'medium' } else { 'low' }) -Class suspicious -Confidence low `
                    -Reasons @('collaborator') -Evidence @([ordered]@{ type = 'github_collaborator'; repo = $full; login = $c.login; role = $c.role }) -Entities $ent -Mitre @('T1098') `
                    -FpNotes 'People you invited.' -Recommendation "Remove unknown collaborators at Settings > Collaborators of $full."
            }
        }
        elseif ($co.Status -ne 404) { $errs.Add("collaborators: $($co.Status)") }
        $iv = Invoke-S13Gh -Path "repos/$full/invitations" -Paginate
        if ($iv.Ok) {
            $row.invitations = @((ConvertTo-S13Array $iv.Data) | ForEach-Object { [ordered]@{ invitee = [string]$_.invitee.login; inviter = [string]$_.inviter.login; permissions = [string]$_.permissions; created = (Format-S13Date $_.created_at) } })
            if ($row.invitations.Count) {
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("{0} pending invitation(s) to {1}" -f $row.invitations.Count, $full) -Severity medium -Class suspicious -Confidence low -Reasons @('pending_invitation') `
                    -Evidence @($row.invitations | ForEach-Object { [ordered]@{ type = 'github_invitation'; repo = $full; invitee = $_.invitee; inviter = $_.inviter; permissions = $_.permissions; created = $_.created } }) -Entities $ent -Mitre @('T1098') `
                    -FpNotes 'Invitations you sent and that were not accepted yet.' -Recommendation "Cancel invitations you did not send (Settings > Collaborators of $full)."
            }
        }
        elseif ($iv.Status -ne 404) { $errs.Add("invitations: $($iv.Status)") }
        # Branches
        $br = Invoke-S13Gh -Path "repos/$full/branches?per_page=100" -Paginate
        if ($br.Ok) {
            $row.branches = @((ConvertTo-S13Array $br.Data) | ForEach-Object { [string]$_.name })
            foreach ($b in $row.branches) {
                foreach ($i in @($iocs.branchNames)) {
                    if ($b -match [string]$i.regex -and $script:Ctx.ReportedEvents.Add("branch|$full|$b")) {
                        Add-S13Finding -Check 'github_auth.repo_deep' -Title "Branch '$b' in $full matches a worm branch name ($($i.family))" -Severity $(if ($i.severity -eq 'critical') { 'critical' } else { 'high' }) -Class $(if ($i.severity -eq 'critical') { 'compromise' } else { 'suspicious' }) -Confidence medium `
                            -Reasons @('intel_match') -Evidence @([ordered]@{ type = 'github_branch'; repo = $full; branch = $b }) -Entities $ent -Mitre @('T1195.002', 'T1552') `
                            -FpNotes 'Exact branch-name match only.' -Recommendation 'Inspect the branch for an exfiltration workflow, preserve evidence, delete it and rotate repository secrets.'
                    }
                }
            }
        }
        elseif ($br.Status -ne 404) { $errs.Add("branches: $($br.Status)") }
        # Workflows on the default branch
        $wfNames = @()
        $wf = Invoke-S13Gh -Path "repos/$full/contents/.github/workflows"
        if ($wf.Ok) {
            $wfRows = [System.Collections.Generic.List[object]]::new()
            foreach ($f in (ConvertTo-S13Array $wf.Data)) {
                if ([string]$f.type -ne 'file') { continue }
                $wfNames += [string]$f.path
                $known = $false; $localSha = $null
                if ($localRepo) {
                    $localSha = [string](@(git --no-optional-locks -C $localRepo.path rev-parse --verify --quiet ("HEAD:" + [string]$f.path) 2>$null) | Select-Object -First 1)
                    $wtPath = Join-Path $localRepo.path (([string]$f.path) -replace '/', '\')
                    $wtSha = if ([IO.File]::Exists($wtPath)) { Get-S13GitBlobSha $wtPath } else { $null }
                    $known = ($localSha -and $localSha -eq [string]$f.sha) -or ($wtSha -and $wtSha -eq [string]$f.sha)
                }
                $nameIoc = @($iocs.workflowFileNames | Where-Object { [string]$f.name -match [string]$_.regex }) | Select-Object -First 1
                $hits = @()
                if (-not $known -or $nameIoc) {
                    $c = Invoke-S13Gh -Path ("repos/$full/contents/" + [string]$f.path)
                    if ($c.Ok -and $c.Data.content) {
                        $text = ''
                        try { $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((([string]$c.Data.content) -replace '\s', ''))) } catch { $text = '' }
                        $hits = @($iocs.workflowContentPatterns | Where-Object { $text -match [string]$_.regex } | ForEach-Object { [ordered]@{ id = [string]$_.id; severity = [string]$_.severity; note = [string]$_.note } })
                    }
                }
                $wfRows.Add([ordered]@{ path = [string]$f.path; sha = [string]$f.sha; size = $f.size; matchesLocalClone = [bool]$known; nameIndicator = $(if ($nameIoc) { $nameIoc.family } else { $null }); contentIndicators = @($hits | ForEach-Object { $_.id }) })
                if ($nameIoc -or $hits.Count -or -not $known) {
                    $sev = Get-S13MaxSeverity (@($hits | ForEach-Object { $_.severity }) + @($(if ($nameIoc) { [string]$nameIoc.severity } else { 'medium' })))
                    if (-not $nameIoc -and -not $hits.Count) { $sev = if ($localRepo) { 'medium' } else { 'low' } }
                    $cls = if ($sev -eq 'critical') { 'compromise' } else { 'suspicious' }
                    Add-S13Finding -Check 'github_auth.repo_deep' -Title ("Workflow {0} in {1} {2}" -f $f.path, $full, $(if ($hits.Count -or $nameIoc) { 'matches exfiltration indicators' } elseif ($localRepo) { 'differs from the local clone' } else { 'has no local copy to compare' })) -Severity $sev -Class $cls -Confidence $(if ($cls -eq 'compromise') { 'high' } elseif ($hits.Count) { 'medium' } else { 'low' }) `
                        -Reasons @($(if ($hits.Count -or $nameIoc) { 'intel_match' } else { 'unknown_workflow' })) -Evidence @([ordered]@{ type = 'github_workflow'; repo = $full; path = [string]$f.path; sha = [string]$f.sha; localBlob = $localSha; indicators = @($hits | ForEach-Object { "$($_.id): $($_.note)" }); nameIndicator = $(if ($nameIoc) { $nameIoc.family } else { $null }) }) -Entities $ent -Mitre @('T1552', 'T1195.002') `
                        -FpNotes 'A workflow changed on github.com or from another machine and not yet fetched locally; security workflows can mention these patterns.' `
                        -Recommendation "Read the workflow on github.com. If you did not write it: delete it, review recent runs and artefacts, and rotate all repository and organisation secrets."
                }
            }
            $row.workflows = $wfRows.ToArray()
        }
        elseif ($wf.Status -ne 404) { $errs.Add("workflows: $($wf.Status)") }
        # Recent workflow runs
        $ru = Invoke-S13Gh -Path "repos/$full/actions/runs?per_page=20"
        if ($ru.Ok) {
            $runs = @($ru.Data.workflow_runs)
            $row.runs = @($runs | ForEach-Object { [ordered]@{ id = $_.id; name = [string]$_.name; path = ([string]$_.path -replace '@.*$', ''); event = [string]$_.event; actor = [string]$_.actor.login; triggeringActor = [string]$_.triggering_actor.login; branch = [string]$_.head_branch; created = (Format-S13Date $_.created_at); conclusion = [string]$_.conclusion } })
            $odd = [System.Collections.Generic.List[object]]::new()
            foreach ($x in $row.runs) {
                $why = [System.Collections.Generic.List[string]]::new()
                if ($x.actor -and $safeActors -notcontains $x.actor) { $why.Add("actor $($x.actor)") }
                if ($x.triggeringActor -and $safeActors -notcontains $x.triggeringActor) { $why.Add("triggered by $($x.triggeringActor)") }
                if ($x.event -and @($iocs.githubSafeRunEvents) -notcontains $x.event) { $why.Add("event $($x.event)") }
                if ($x.path -and $wfNames -notcontains $x.path) {
                    $inHistory = $false
                    if ($localRepo) { $inHistory = [bool](@(git --no-optional-locks -C $localRepo.path log --all -1 '--format=%H' -- $x.path 2>$null) | Select-Object -First 1) }
                    if (-not $inHistory) { $why.Add("workflow file $($x.path) no longer exists and is not in local history") }
                }
                foreach ($i in @($iocs.branchNames)) { if ($x.branch -match [string]$i.regex) { $why.Add("branch $($x.branch) ($($i.family))") } }
                foreach ($i in @($iocs.workflowFileNames)) { if (($x.path -split '/')[-1] -match [string]$i.regex) { $why.Add("workflow name ($($i.family))") } }
                if ($why.Count) { $odd.Add([ordered]@{ type = 'github_run'; repo = $full; id = $x.id; workflow = $x.path; event = $x.event; actor = $x.actor; created = $x.created; why = $why.ToArray() }) }
            }
            if ($odd.Count) {
                $crit = @($odd | Where-Object { ($_.why -join ' ') -match 'Shai-Hulud|formatter_|discussion' }).Count
                Add-S13Finding -Check 'github_auth.repo_deep' -Title ("{0} unexpected workflow run(s) in {1}" -f $odd.Count, $full) -Severity $(if ($crit) { 'critical' } else { 'high' }) -Class $(if ($crit) { 'compromise' } else { 'suspicious' }) -Confidence $(if ($crit) { 'medium' } else { 'low' }) `
                    -Reasons @('unexpected_run') -Evidence @($odd | Select-Object -First 10) -Entities $ent -Mitre @('T1552', 'T1195.002') `
                    -FpNotes 'Workflows you deleted or renamed (for example when disabling Actions) and runs by bots you installed look similar.' `
                    -Recommendation "Open the runs (Actions tab of $full), check logs and artefacts for secret dumps, and rotate repository secrets if any run was not yours."
            }
        }
        elseif ($ru.Status -ne 404) { $errs.Add("runs: $($ru.Status)") }
        # Environments and Pages (inventory)
        $en = Invoke-S13Gh -Path "repos/$full/environments" -Paginate
        if ($en.Ok) { $row.environments = @((ConvertTo-S13Array $en.Data) | ForEach-Object { [ordered]@{ name = [string]$_.name; created = (Format-S13Date $_.created_at); protectionRules = @($_.protection_rules).Count } }) }
        elseif ($en.Status -ne 404) { $errs.Add("environments: $($en.Status)") }
        $pg = Invoke-S13Gh -Path "repos/$full/pages"
        if ($pg.Ok) { $row.pages = [ordered]@{ status = [string]$pg.Data.status; cname = [string]$pg.Data.cname; httpsEnforced = $pg.Data.https_enforced; buildType = [string]$pg.Data.build_type; source = $(if ($pg.Data.source) { "$($pg.Data.source.branch)$($pg.Data.source.path)" } else { $null }) } }
        elseif ($pg.Status -ne 404) { $errs.Add("pages: $($pg.Status)") }
    }
    catch { $errs.Add($_.Exception.Message) }
    $row.errors = $errs.ToArray()
    [pscustomobject]$row
}

#endregion

#region ---------- section D: manual checklist ----------

function Test-S13ManualCondition {
    param($When, $Facts)
    $ev = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $When -or $When.always) { return [pscustomobject]@{ ok = $true; evidence = @('always applicable') } }
    $conds = if ($When.anyOf) { @($When.anyOf) } else { @($When) }
    foreach ($c in $conds) {
        if ($c.always) { $ev.Add('always applicable') }
        if ($c.sshKeyNameRegex) { foreach ($k in $Facts.ssh) { if ($k.source -match [string]$c.sshKeyNameRegex -or $k.comment -match [string]$c.sshKeyNameRegex) { $ev.Add("local SSH key $($k.source) ($($k.fingerprint))") } } }
        if ($c.expectedId) { if (@(Get-BvsExpected | Where-Object { $_.id -eq [string]$c.expectedId }).Count) { $ev.Add("expected.json item '$($c.expectedId)'") } }
        if ($c.expectedHostRegex) { foreach ($h in $Facts.expectedHosts) { if ($h -match [string]$c.expectedHostRegex) { $ev.Add("expected.json host $h") } } }
        if ($c.knownHostsRegex) { foreach ($h in $Facts.knownHosts) { if ($h -match [string]$c.knownHostsRegex) { $ev.Add("known_hosts entry $h") } } }
        if ($c.pathExists) { foreach ($p in @($c.pathExists)) { $x = [Environment]::ExpandEnvironmentVariables([string]$p); if (Test-Path -LiteralPath $x) { $ev.Add("path exists: $x") } } }
        if ($c.gitEmailDomainRegex) { foreach ($d in $Facts.emailDomains) { if ($d -match [string]$c.gitEmailDomainRegex) { $ev.Add("git email domain $d") } } }
    }
    [pscustomobject]@{ ok = ($ev.Count -gt 0); evidence = @($ev | Select-Object -Unique) }
}

function Invoke-S13Manual {
    $run = $script:S13.Run
    Invoke-BvsCheck -Run $run -Id 'manual.checklist' -Description 'Manual account checks with no API (GitHub sessions/security log/apps/tokens/2FA, npm, Tailscale, Microsoft, Google, Anthropic, servers, cloud, mail, router)' -Script {
        $path = Join-Path $PSScriptRoot 'S13-github-npm-manual.json'
        if (-not [IO.File]::Exists($path)) { throw "manual checklist sidecar missing: $path" }
        $cat = ConvertFrom-S13Json ([IO.File]::ReadAllText($path))
        $expHosts = [System.Collections.Generic.List[string]]::new()
        foreach ($e in @(Get-BvsExpected)) { foreach ($p in 'hostname', 'hostnames') { if ($e.match -and $e.match.PSObject.Properties[$p]) { foreach ($h in @($e.match.$p)) { if ($h) { $expHosts.Add([string]$h) } } } } }
        $domains = @($script:Ctx.Identity.emails | Where-Object { $_ -match '@(.+)$' } | ForEach-Object { ($_ -split '@')[-1] } | Select-Object -Unique)
        $facts = [pscustomobject]@{ ssh = $script:Ctx.LocalSsh; expectedHosts = $expHosts.ToArray(); knownHosts = (Get-S13KnownHostNames); emailDomains = $domains }
        $gateway = Get-S13DefaultGateway
        $npmUser = if ($script:Ctx.NpmUser) { $script:Ctx.NpmUser } else { '<npm-user>' }
        $pkg = (@($script:Ctx.Owned.Keys) + @($script:Ctx.LocalPackages | Where-Object { $_.publishable } | ForEach-Object { $_.name }) | Select-Object -First 1)
        if (-not $pkg) { $pkg = '<package>' }
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($it in @($cat.items)) {
            $t = Test-S13ManualCondition -When $it.when -Facts $facts
            $hosts = @($t.evidence | Where-Object { $_ -match '^(expected\.json host|known_hosts entry) ' } | ForEach-Object { ($_ -split ' ')[-1] } | Select-Object -Unique)
            $fill = {
                param([string]$s)
                $s = $s.Replace('{githubUser}', [string]$script:Ctx.GitHubUser).Replace('{npmUser}', $npmUser).Replace('{npmPackage}', [string]$pkg)
                $s = $s.Replace('{gateway}', $(if ($gateway) { $gateway } else { '<router-ip>' })).Replace('{hosts}', $(if ($hosts.Count) { $hosts -join ', ' } else { 'your server' }))
                $s
            }
            $context = [System.Collections.Generic.List[string]]::new()
            switch ([string]$it.id) {
                'github-2fa' { foreach ($k in @($script:Ctx.UnknownKeys)) { $context.Add("GitHub key not on this machine: $($k.kind) $($k.fingerprint)") } }
                'github-pats' { foreach ($f in @($script:Ctx.NpmRcFacts | Where-Object { $_.exists })) { foreach ($tk in @($f.tokens | Where-Object { $_.class -match '^gh' })) { $context.Add("$($tk.class) token stored in $($f.scope) npmrc for $($tk.registry)") } } }
                'npm-tokens' { $context.Add("npm token on disk: $($script:Ctx.NpmTokenState)") }
                'vps-server' { foreach ($k in $script:Ctx.LocalSsh) { $context.Add("local key $($k.source): $($k.fingerprint)") } }
                'router-admin' { if ($gateway) { $context.Add("default gateway $gateway (physical adapter route)") } }
            }
            $items.Add([ordered]@{
                    id = [string]$it.id; area = [string]$it.area; title = (& $fill ([string]$it.title)); applicable = $t.ok; why = $t.evidence
                    urls = @($it.urls | ForEach-Object { & $fill ([string]$_) }); lookFor = @($it.lookFor | ForEach-Object { & $fill ([string]$_) }); context = $context.ToArray()
                })
        }
        $script:Ctx.Gateway = $gateway
        Add-BvsInventory -Run $run -Name 'manualChecks' -Data $items.ToArray()
        $items.ToArray()
    } | Out-Null
}

#endregion

#region ---------- main ----------

function Write-S13Summary {
    param($Summary)
    $run = $script:S13.Run
    "S13 github/npm: $($Summary.Path)"
    "findings: $($Summary.Findings) [$($Summary.BySeverity)]  checks: $($Summary.Checks)  errors: $($Summary.Errors)"
    "requests: " + ((@($script:S13.Requests.Keys | ForEach-Object { "$_=$($script:S13.Requests[$_])" })) -join ', ') + "  gh api calls: $($script:S13.GhCalls)"
    foreach ($c in $run.Checks) {
        $why = if ($c.reason) { Protect-BvsText ([string]$c.reason) } else { '' }
        if ($why.Length -gt 90) { $why = $why.Substring(0, 90) }
        "  {0,-32} {1,-14} {2}" -f $c.id, $c.status, $why
    }
    foreach ($f in ($run.Findings | Sort-Object { - $script:SevRank[$_.severity] } | Select-Object -First 12)) { "  [{0}/{1}] {2}" -f $f.severity, $f.class, (Protect-BvsText $f.title) }
}

# Dot-sourcing (tests) defines the functions without running the scan.
if ($MyInvocation.InvocationName -eq '.') { return }

$run = Initialize-BvsRun -Module S13 -Area security
$script:S13.Run = $run
$origOutEnc = [Console]::OutputEncoding
$summary = $null
try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    Invoke-S13Setup
    Invoke-S13PublicGitHub
    Invoke-S13Npm
    Invoke-S13AuthSection
    Invoke-S13Manual
    Add-BvsInventory -Run $run -Name 's13Meta' -Data ([ordered]@{
            mode = $(if ($script:Ctx.GhAuth) { $script:Ctx.GhAuth.mode } else { 'unknown' }); authenticatedRequested = [bool]$Authenticated
            githubUser = $script:Ctx.GitHubUser; npmUser = $script:Ctx.NpmUser; npmPackages = @($script:Ctx.Owned.Keys)
            requests = $script:S13.Requests; ghApiCalls = $script:S13.GhCalls; reuseIntelMinutes = $ReuseIntelMinutes; recentDays = $RecentDays
            iocSidecar = 'collectors\security\windows\S13-github-npm-iocs.json'; manualSidecar = 'collectors\security\windows\S13-github-npm-manual.json'
        })
}
catch {
    $run.Errors.Add([ordered]@{ check = 's13.main'; error = (Protect-BvsText $_.Exception.Message); at = [datetime]::UtcNow.ToString('o') })
    Write-BvsLog -Run $run -Level ERROR -Message ("fatal: {0} at line {1}" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber)
}
finally {
    $script:NpmToken = $null
    [Console]::OutputEncoding = $origOutEnc
    $summary = Complete-BvsRun -Run $run
}
Write-S13Summary -Summary $summary

#endregion
