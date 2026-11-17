#Requires -Version 7.2
<#
.SYNOPSIS
    S11 - Software supply chain (npm / PyPI malware). Read-only collector for baby-virus-scanner.

.DESCRIPTION
    Builds an inventory of every npm and PyPI package version on this machine that is
      - installed   (project node_modules, npm/pnpm/yarn/bun globals, venvs, global site-packages),
      - locked      (package-lock / npm-shrinkwrap v1-3, yarn.lock v1+berry, pnpm-lock v5/v6/v9,
                     bun.lock, poetry.lock, uv.lock, Pipfile.lock, pinned requirements*.txt),
      - downloaded  (npm cache index-v5: everything ever fetched), or
      - executed    (npm-cache\_npx one-off runs),
    and checks it against
      - OSV (api.osv.dev querybatch + vulns/<id>): MAL-* ids, "malicious" advisories, CWE-506;
        ordinary vulnerabilities are only counted per project (hygiene, not part of the verdict);
      - the local, NON-EXHAUSTIVE sidecar S11-iocs.json: known-compromised versions plus FILE
        indicators of the Shai-Hulud family (package-root loaders, repo backdoors in .github,
        .claude, .vscode, .cursor, .gemini, host persistence such as gh-token-monitor).
    It also flags suspicious npm lifecycle scripts (preinstall/install/postinstall, binding.gyp
    command expansion), Python .pth startup hooks, and registry overrides (.npmrc, .yarnrc*,
    bunfig.toml, pip.ini/pip.conf, uv.toml, pyproject/Pipfile sources, env vars).

    Safety: never runs npm/npx/pnpm/yarn/bun/pip/uv; every source is parsed as a file. Reads go
    through Test-BvsNeverRead / Test-BvsCloudOnly; this project and its transcript folder are
    excluded. Only package name@version leaves the machine (OSV via Invoke-BvsIntel). Tokens in
    .npmrc / .pypirc are never read into the output: only "a token exists for host X".

    Contract : docs\schema.md          Rules : docs\agent-rules.md
    Playbook : docs\playbooks\S11-supply-chain.md
    Output   : data\<scanId>\security\S11.json  (bvs.module/1)

.PARAMETER MaxDepth
    Project discovery depth below each root (user profile, Documents, Desktop). Default 6.
.PARAMETER Offline
    Skip OSV. Static IoC, lifecycle and registry checks still run (sidecar versions still match).
.PARAMETER OsvBatchSize
    Queries per OSV querybatch call (max 1000).
.PARAMETER OsvCacheDays
    Reuse OSV vulnerability details saved under intel\api.osv.dev for this many days.
.PARAMETER OsvMaxDetails
    Upper bound for vulns/<id> detail fetches per run (the rest are counted as unknown severity).
.PARAMETER OsvThrottle
    Parallel detail fetches.
.PARAMETER WalkMaxPackages
    Safety cap for one node_modules tree walk.

.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S11-supply-chain.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S11-supply-chain.ps1 -Offline
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 12)][int]$MaxDepth = 6,
    [switch]$Offline,
    [ValidateRange(1, 1000)][int]$OsvBatchSize = 1000,
    [ValidateRange(0, 60)][int]$OsvCacheDays = 3,
    [ValidateRange(0, 50000)][int]$OsvMaxDetails = 8000,
    [ValidateRange(1, 16)][int]$OsvThrottle = 6,
    [ValidateRange(100, 1000000)][int]$WalkMaxPackages = 60000
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S11 -Area security

#region ---------- state ----------

$script:Sw = [Diagnostics.Stopwatch]::StartNew()
$script:BvsRoot = (Get-BvsRoot).TrimEnd('\')
$script:LibPath = Join-Path $script:BvsRoot 'src\lib\windows\BVS.Common.psm1'
$script:UserHome = $env:USERPROFILE
$script:Ioc = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S11-iocs.json') -Raw | ConvertFrom-Json

$script:Pkgs = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:SetByProject = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:Groups = [System.Collections.Generic.List[object]]::new()
$script:GroupById = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:ParseCache = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:ProbeDirs = [System.Collections.Generic.List[object]]::new()
$script:ScriptPkgs = [System.Collections.Generic.List[object]]::new()
$script:NpxHistory = [System.Collections.Generic.List[object]]::new()
$script:GlobalsInv = [System.Collections.Generic.List[object]]::new()
$script:CacheInv = [System.Collections.Generic.List[object]]::new()
$script:PyEnvInv = [System.Collections.Generic.List[object]]::new()
$script:SitePackages = [System.Collections.Generic.List[object]]::new()
$script:RegistryInv = [System.Collections.Generic.List[object]]::new()
$script:LockHosts = [System.Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
$script:OsvHits = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:OsvVulns = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$script:OsvStats = [ordered]@{ queried = 0; batches = 0; packagesWithHits = 0; uniqueVulnIds = 0; detailsFromCache = 0; detailsFetched = 0; detailsFailed = 0; detailsSkipped = 0; maliciousIds = 0; withdrawn = 0; errors = 0; offline = [bool]$Offline }
$script:IocVersions = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
$script:IocCampaigns = @{}
$script:MalInv = [System.Collections.Generic.List[object]]::new()
$script:LifecycleInv = [System.Collections.Generic.List[object]]::new()
$script:LifecycleStats = [ordered]@{ packagesWithScripts = 0; scriptsAnalysed = 0; benign = 0; flagged = 0; bindingGyp = 0; unreadable = 0 }
$script:IocFileInv = [System.Collections.Generic.List[object]]::new()
$script:Coverage = [System.Collections.Generic.List[string]]::new()
$script:Discovery = $null
$script:LockStats = [ordered]@{ npmLockfiles = 0; parsed = 0; failed = 0; npm = 0; yarn = 0; pnpm = 0; bun = 0; bunLockbUnparsed = 0; pyLockfiles = 0; requirements = 0; pyFailed = 0 }
$script:InstalledStats = [ordered]@{ copiesWithNodeModules = 0; hiddenLockfile = 0; pnpmWalk = 0; fallbackWalk = 0; records = 0; walkCapped = 0 }
$script:InstalledKinds = [System.Collections.Generic.HashSet[string]]::new([string[]]@('installed', 'global', 'venv', 'site'), [StringComparer]::Ordinal)

$script:DirOpts = [IO.EnumerationOptions]::new()
$script:DirOpts.AttributesToSkip = [IO.FileAttributes]::ReparsePoint
$script:DirOpts.IgnoreInaccessible = $true
$script:DirOpts.RecurseSubdirectories = $false

$script:JsonOpts = [System.Text.Json.JsonDocumentOptions]::new()
$script:JsonOpts.AllowTrailingCommas = $true
$script:JsonOpts.CommentHandling = [System.Text.Json.JsonCommentHandling]::Skip
$script:JsonOpts.MaxDepth = 512
$script:JStr = [System.Text.Json.JsonValueKind]::String
$script:JObj = [System.Text.Json.JsonValueKind]::Object
$script:JArr = [System.Text.Json.JsonValueKind]::Array
$script:JTrue = [System.Text.Json.JsonValueKind]::True

$script:NpmLockNames = @('package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb')
$script:PyLockNames = @('poetry.lock', 'uv.lock', 'Pipfile.lock')
$script:ConfigNames = @('.npmrc', '.yarnrc', '.yarnrc.yml', 'bunfig.toml', 'pip.ini', 'pip.conf', '.pypirc', 'uv.toml', 'pyproject.toml', 'Pipfile')
$script:DiscoverPrune = @('node_modules', '.git', '__pycache__', '.venv', 'venv', 'site-packages', '.pnpm-store', '.pnpm', '.next', '.nuxt',
    '.svelte-kit', '.turbo', '.parcel-cache', '.angular', '.vercel', '.netlify', '.output', '.expo', '.cache', '.yarn', 'bower_components',
    'jspm_packages', '_cacache', '_npx', 'AppData', '.nuget', '.rustup', '.cargo', '.gradle', '.m2', 'Pods', '.tox', '.nox', '.mypy_cache',
    '.pytest_cache', '.ruff_cache', '.ipynb_checkpoints', '.vscode', '.vscode-insiders', '.vscode-server', '.cursor', '.cursor-server',
    '.windsurf', '.antigravity', '$Recycle.Bin', 'System Volume Information')

$script:SemverRx = [regex]::new('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$', 'Compiled')
$script:Pep440Rx = [regex]::new('^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$', 'Compiled, IgnoreCase')
$script:DistInfoRx = [regex]::new('^(?<n>.+?)-(?<v>\d[^-]*)\.dist-info$', 'Compiled, IgnoreCase')
$script:EggInfoRx = [regex]::new('^(?<n>.+?)-(?<v>\d[^-]*?)(?:-py\d+(?:\.\d+)*)?(?:-[^-]+)?\.egg-info$', 'Compiled, IgnoreCase')
$script:CacheKeyRx = [regex]::new('"key":"((?:[^"\\]|\\.)*)"', 'Compiled')
$script:CacheTimeRx = [regex]::new('"time":(\d+)', 'Compiled')
$script:TgzUrlRx = [regex]::new('^https?://(?<h>[^/]+)/(?<p>.+?)/-/(?<f>[^/?#]+)\.tgz(?:[?#].*)?$', 'Compiled')
$script:FixtureRx = [regex]::new('(?i)\\(tests?|__tests__|specs?|fixtures?|__fixtures__|samples?|examples?|testdata|test-data|corpus|iocs?|rules|yara|signatures|e2e|mocks?|__mocks__|vectors)\\', 'Compiled')
$script:SummaryMalRx = [regex]::new('(?i)\bmalicious (code|software|package|version|release|payload|dependency|script|update)|\bmalware\b|embedded malicious|crypto ?(currency )?min(er|ing)|\bbackdoor(ed)?\b|supply[- ]chain (attack|compromise)|compromised (version|release|package|maintainer|account|npm|pypi)|info-?stealer|wallet (drainer|stealer)|protestware|remote access trojan', 'Compiled')
$script:DetailsMalRx = [regex]::new('(?i)package was compromised|contain(s|ed)? malicious (code|software)|malicious code (was |has been )?(added|inserted|injected|introduced)|embedded malicious code|supply[- ]chain attack|should be considered fully compromised|crypto ?(currency )?min(er|ing) software|install(s|ed)? a (backdoor|remote access trojan)', 'Compiled')

$script:LcPatterns = @(foreach ($p in $script:Ioc.lifecycle.patterns) { [pscustomobject]@{ Id = $p.id; Weight = [int]$p.weight; Rx = [regex]::new($p.regex, 'Compiled') } })
$script:LcBenign = @(foreach ($b in $script:Ioc.lifecycle.benign) { [regex]::new($b, 'Compiled, IgnoreCase') })
$script:LcScripts = @($script:Ioc.lifecycle.scripts)
$script:ContentMarkers = @($script:Ioc.packageFileContentMarkers)
$script:PthSuspiciousRx = [regex]::new([string]$script:Ioc.pthSuspicious, 'Compiled')
$script:PthBenign = @($script:Ioc.pthKnownBenign)
foreach ($c in $script:Ioc.campaigns) { $script:IocCampaigns[$c.id] = $c }

$script:Excluded = [System.Collections.Generic.List[string]]::new()
$script:SecToolRoots = [System.Collections.Generic.List[object]]::new()

#endregion

#region ---------- helpers: paths, reading, json ----------

function Add-Excluded([string]$Path) { if ($Path) { $script:Excluded.Add($Path.TrimEnd('\') + '\') } }

function Test-Under([string]$Path, [string]$Prefix) {
    if (-not $Path -or -not $Prefix) { return $false }
    ($Path.TrimEnd('\') + '\').StartsWith($Prefix.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-Excluded([string]$Path) {
    if (-not $Path) { return $false }
    $p = $Path.TrimEnd('\') + '\'
    foreach ($x in $script:Excluded) { if ($p.StartsWith($x, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    $false
}

function Get-SecToolRoot([string]$Path) {
    foreach ($r in $script:SecToolRoots) { if (Test-Under $Path $r.Root) { return $r } }
    $null
}

function Get-ExpectedCap {
    <# Cap from expected.json 'security-tooling-repos': only fixture paths (or pure IoC strings) inside security-tool folders listed in expected.json. #>
    param([string]$Path, [switch]$StringMarker)
    $m = Get-SecToolRoot $Path
    if (-not $m) { return $null }
    $rel = $Path.Substring([Math]::Min($Path.Length, $m.Root.TrimEnd('\').Length)) + '\'
    if ($StringMarker -or $script:FixtureRx.IsMatch($rel)) {
        return [ordered]@{
            id = $m.Item.id; category = $m.Item.category; reason = $m.Item.reason
            scope = $(if ($StringMarker) { 'IoC string inside the user''s own security-tool repo' } else { 'test/fixture path inside the user''s own security-tool repo' })
        }
    }
    $null
}

function Test-Readable([string]$Path, [long]$MaxBytes = 64MB) {
    if (-not $Path) { return $false }
    try { $info = [IO.FileInfo]::new($Path) } catch { return $false }
    if (-not $info.Exists -or $info.Length -gt $MaxBytes) { return $false }
    if (Test-BvsCloudOnly $info) { return $false }
    if (Test-BvsNeverRead $info.FullName) { return $false }
    if (Test-Excluded $info.FullName) { return $false }
    $true
}

function Read-TextFile([string]$Path, [long]$MaxBytes = 32MB) {
    if (-not (Test-Readable $Path $MaxBytes)) { return $null }
    try { [IO.File]::ReadAllText($Path) } catch { $null }
}

function Read-TextHead([string]$Path, [int]$Bytes = 65536) {
    if (-not (Test-Readable $Path 8GB)) { return $null }
    try {
        $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try {
            $buf = [byte[]]::new([int][Math]::Min([long]$Bytes, $fs.Length))
            $n = $fs.Read($buf, 0, $buf.Length)
            [Text.Encoding]::UTF8.GetString($buf, 0, $n)
        }
        finally { $fs.Dispose() }
    }
    catch { $null }
}

function Open-JsonDoc([string]$Path, [long]$MaxBytes = 64MB) {
    if (-not (Test-Readable $Path $MaxBytes)) { return $null }
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $off = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $off = 3 }
        [System.Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($bytes, $off, $bytes.Length - $off), $script:JsonOpts)
    }
    catch { $null }
}

function Get-JStr([System.Text.Json.JsonElement]$El, [string]$Name) {
    if ($El.ValueKind -ne $script:JObj) { return $null }
    [System.Text.Json.JsonElement]$v = [System.Text.Json.JsonElement]::new()
    if ($El.TryGetProperty($Name, [ref]$v) -and $v.ValueKind -eq $script:JStr) { return $v.GetString() }
    $null
}

function Get-JEl([System.Text.Json.JsonElement]$El, [string]$Name) {
    if ($El.ValueKind -ne $script:JObj) { return $null }
    [System.Text.Json.JsonElement]$v = [System.Text.Json.JsonElement]::new()
    if ($El.TryGetProperty($Name, [ref]$v)) { return $v }
    $null
}

function Get-ShortHash([string]$Text) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).Substring(0, 16).ToLowerInvariant()
}

function Get-FileTimes([string]$Path) {
    try {
        $item = [IO.FileInfo]::new($Path)
        if (-not $item.Exists) { $item = [IO.DirectoryInfo]::new($Path) }
        [ordered]@{ created = $item.CreationTimeUtc.ToString('o'); modified = $item.LastWriteTimeUtc.ToString('o') }
    }
    catch { [ordered]@{ created = $null; modified = $null } }
}

function Get-MaskedUrl([string]$Value) {
    if (-not $Value) { return $Value }
    $v = $Value.Trim().Trim('"', "'")
    $v = $v -replace '(?i)^(https?://)[^/@\s]+@', '$1[credentials-removed]@'
    Protect-BvsUrl $v
}

function Get-UrlHost([string]$Value) {
    try { ([uri]($Value.Trim().Trim('"', "'"))).Host.ToLowerInvariant() } catch { $null }
}

function Test-Ver([string]$Eco, [string]$Version) {
    if (-not $Version) { return $false }
    if ($Eco -eq 'npm') { return $script:SemverRx.IsMatch($Version) }
    $script:Pep440Rx.IsMatch($Version)
}

function ConvertTo-Pep503([string]$Name) { ($Name -replace '[-_.]+', '-').ToLowerInvariant() }

function Limit-Text([string]$Text, [int]$Max = 300) {
    if (-not $Text) { return $Text }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + ' [truncated]' }
    Protect-BvsText $t
}

#endregion

#region ---------- package registry ----------

function Add-Pkg {
    param([string]$Eco, [string]$Name, [string]$Version, [string]$Kind, [string]$Path, [string]$Project, [string]$Detail)
    if (-not $Name -or -not (Test-Ver $Eco $Version)) { return $false }
    if ($Eco -eq 'PyPI') { $Name = ConvertTo-Pep503 $Name }
    $key = "$Eco|$Name|$Version"
    $p = $null
    if (-not $script:Pkgs.TryGetValue($key, [ref]$p)) {
        $p = [pscustomobject]@{
            Key = $key; Eco = $Eco; Name = $Name; Version = $Version
            Kinds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            Projects = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            Locs = [System.Collections.Generic.List[object]]::new()
            LocCount = 0
        }
        $script:Pkgs[$key] = $p
    }
    [void]$p.Kinds.Add($Kind)
    $p.LocCount++
    if ($Project) {
        [void]$p.Projects.Add($Project)
        $set = $null
        if (-not $script:SetByProject.TryGetValue($Project, [ref]$set)) {
            $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $script:SetByProject[$Project] = $set
        }
        [void]$set.Add($key)
    }
    $perKind = 0
    foreach ($l in $p.Locs) { if ($l.kind -eq $Kind) { $perKind++ } }
    if ($perKind -lt 8) { $p.Locs.Add([pscustomobject]@{ kind = $Kind; path = $Path; project = $Project; detail = $Detail }) }
    $true
}

function Get-PkgState($Kinds) {
    foreach ($k in $Kinds) { if ($script:InstalledKinds.Contains($k)) { return 'installed' } }
    if ($Kinds.Contains('lock')) { return 'lock' }
    if ($Kinds.Contains('npx')) { return 'npx' }
    if ($Kinds.Contains('cache')) { return 'cache' }
    'other'
}

#endregion

#region ---------- discovery ----------

function Get-PnpmStoreDirs {
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($base in @((Join-Path $env:LOCALAPPDATA 'pnpm\store'), $(if ($env:PNPM_HOME) { Join-Path $env:PNPM_HOME 'store' }))) {
        if (-not $base -or -not [IO.Directory]::Exists($base)) { continue }
        foreach ($v in [IO.Directory]::GetDirectories($base, 'v*', $script:DirOpts)) { if (-not $out.Contains($v)) { $out.Add($v) } }
    }
    $out
}

function Invoke-Discovery {
    $d = [pscustomobject]@{
        Roots       = [System.Collections.Generic.List[string]]::new()
        Files       = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
        NodeModules = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        RepoRoots   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Venvs       = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        NpxDirs     = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        CacheRoots  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Staging     = [System.Collections.Generic.List[string]]::new()
        DirCount    = 0
        FileCount   = 0
    }
    $d.Roots.Add($script:UserHome)
    foreach ($kf in 'MyDocuments', 'Desktop') {
        $p = [Environment]::GetFolderPath($kf)
        if ($p -and [IO.Directory]::Exists($p) -and -not (Test-Under $p $script:UserHome)) { $d.Roots.Add($p) }
    }
    foreach ($st in (Get-PnpmStoreDirs)) {
        $pd = Join-Path $st 'projects'
        if (-not [IO.Directory]::Exists($pd)) { continue }
        foreach ($j in [IO.DirectoryInfo]::new($pd).EnumerateDirectories()) {
            $t = $j.LinkTarget
            if (-not $t -or -not [IO.Directory]::Exists($t)) { continue }
            $inside = $false
            foreach ($r in $d.Roots) { if (Test-Under $t $r) { $inside = $true; break } }
            if (-not $inside) { $d.Roots.Add($t) }
        }
    }
    $stagingNames = @($script:Ioc.stagingFiles | ForEach-Object { $_.file })
    $include = @('package.json', '.git') + $script:NpmLockNames + $script:PyLockNames + @('requirements*.txt', 'pyvenv.cfg') + $script:ConfigNames + $stagingNames
    foreach ($e in (Get-BvsFiles -Path $d.Roots -MaxDepth $MaxDepth -Include $include -Directories -PruneDirNames $script:DiscoverPrune)) {
        if ($e -is [IO.DirectoryInfo]) {
            $d.DirCount++
            $n = $e.Name
            if ($n -eq 'node_modules') { [void]$d.NodeModules.Add($e.Parent.FullName) }
            elseif ($n -eq '.git' -or $n -eq '.github') { [void]$d.RepoRoots.Add($e.Parent.FullName) }
            elseif ($n -eq '.venv' -or $n -eq 'venv') { if ([IO.File]::Exists((Join-Path $e.FullName 'pyvenv.cfg'))) { [void]$d.Venvs.Add($e.FullName) } }
            elseif ($n -eq '_npx') { [void]$d.NpxDirs.Add($e.FullName) }
            elseif ($n -eq '_cacache') { [void]$d.CacheRoots.Add($e.Parent.FullName) }
            continue
        }
        $d.FileCount++
        if (Test-Excluded $e.FullName) { continue }
        $lname = $e.Name.ToLowerInvariant()
        if ($lname -eq 'pyvenv.cfg') { [void]$d.Venvs.Add($e.DirectoryName); continue }
        if ($lname -eq '.git') { [void]$d.RepoRoots.Add($e.DirectoryName); continue }
        if ($stagingNames -contains $e.Name) { $d.Staging.Add($e.FullName); continue }
        $bucket = $null
        if (-not $d.Files.TryGetValue($e.DirectoryName, [ref]$bucket)) {
            $bucket = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
            $d.Files[$e.DirectoryName] = $bucket
        }
        $bucket[$e.Name] = $e.FullName
    }
    foreach ($set in @($d.NodeModules, $d.RepoRoots, $d.Venvs, $d.NpxDirs, $d.CacheRoots)) {
        foreach ($x in @($set)) { if (Test-Excluded $x) { [void]$set.Remove($x) } }
    }
    $d
}

function Get-ProjectName([string]$Path, $Files) {
    $pj = $null
    if ($Files -and $Files.TryGetValue('package.json', [ref]$pj)) {
        $doc = Open-JsonDoc $pj 4MB
        if ($doc) { try { $n = Get-JStr $doc.RootElement 'name'; if ($n) { return $n } } finally { $doc.Dispose() } }
    }
    $pp = $null
    if ($Files -and $Files.TryGetValue('pyproject.toml', [ref]$pp)) {
        $t = Read-TextFile $pp 1MB
        if ($t -and $t -match '(?m)^\s*name\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    [IO.Path]::GetFileName($Path.TrimEnd('\'))
}

function Build-Projects($d) {
    $cands = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($kv in $d.Files.GetEnumerator()) {
        foreach ($n in $kv.Value.Keys) {
            if ($script:NpmLockNames -contains $n -or $script:PyLockNames -contains $n -or $n -like 'requirements*.txt') { [void]$cands.Add($kv.Key); break }
        }
    }
    foreach ($x in $d.NodeModules) { [void]$cands.Add($x) }
    $venvByParent = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($v in $d.Venvs) {
        $parent = [IO.Path]::GetDirectoryName($v)
        if (-not $parent) { continue }
        if (-not $venvByParent.ContainsKey($parent)) { $venvByParent[$parent] = [System.Collections.Generic.List[string]]::new() }
        $venvByParent[$parent].Add($v)
        if ($d.Files.ContainsKey($parent) -or $d.NodeModules.Contains($parent)) { [void]$cands.Add($parent) }
    }
    $byFp = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($pathItem in $cands) {
        $files = $null
        [void]$d.Files.TryGetValue($pathItem, [ref]$files)
        $npmLock = $null
        foreach ($ln in $script:NpmLockNames) { $f = $null; if ($files -and $files.TryGetValue($ln, [ref]$f)) { $npmLock = $f; break } }
        $pyLocks = [System.Collections.Generic.List[string]]::new()
        if ($files) {
            foreach ($ln in $script:PyLockNames) { $f = $null; if ($files.TryGetValue($ln, [ref]$f)) { $pyLocks.Add($f) } }
            foreach ($k in @($files.Keys | Where-Object { $_ -like 'requirements*.txt' } | Sort-Object)) { $pyLocks.Add($files[$k]) }
        }
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($f in @(@($npmLock) + @($pyLocks))) {
            if (-not $f) { continue }
            $h = Get-BvsHash -Path $f -MaxBytes 128MB
            $parts.Add(([IO.Path]::GetFileName($f)).ToLowerInvariant() + '=' + $h)
        }
        if ($parts.Count -eq 0) {
            $hl = Join-Path $pathItem 'node_modules\.package-lock.json'
            if ([IO.File]::Exists($hl)) { $parts.Add('nm=' + (Get-BvsHash -Path $hl -MaxBytes 128MB)) }
            elseif ($files -and $files.ContainsKey('package.json')) { $parts.Add('pkg=' + (Get-BvsHash -Path $files['package.json'])) }
            else { $parts.Add('dir=' + $pathItem.ToLowerInvariant()) }
        }
        $fp = Get-ShortHash ($parts -join '|')
        $g = $null
        if (-not $byFp.TryGetValue($fp, [ref]$g)) {
            $g = [pscustomobject]@{ Id = $null; Fingerprint = $fp; Name = $null; Copies = [System.Collections.Generic.List[object]]::new(); Ecosystems = [System.Collections.Generic.HashSet[string]]::new() }
            $byFp[$fp] = $g
        }
        $venvs = $null
        [void]$venvByParent.TryGetValue($pathItem, [ref]$venvs)
        $g.Copies.Add([pscustomobject]@{
                Path = $pathItem; Files = $files; NpmLock = $npmLock; PyLocks = $pyLocks
                HasNodeModules = $d.NodeModules.Contains($pathItem); Venvs = $(if ($venvs) { @($venvs) } else { @() })
            })
        if ($npmLock -or $d.NodeModules.Contains($pathItem)) { [void]$g.Ecosystems.Add('npm') }
        if ($pyLocks.Count -gt 0 -or $venvs) { [void]$g.Ecosystems.Add('PyPI') }
    }
    $i = 0
    foreach ($g in @($byFp.Values | Sort-Object { $_.Copies[0].Path })) {
        $i++
        $g.Id = 'P{0:000}' -f $i
        $g.Name = Get-ProjectName $g.Copies[0].Path $g.Copies[0].Files
        $script:Groups.Add($g)
        $script:GroupById[$g.Id] = $g
    }
    # Venvs whose parent is not a project become standalone environments (handled in python.environments).
    $script:Groups.Count
}

#endregion

#region ---------- npm parsers ----------

function Read-NpmPackageLock([string]$Path) {
    $out = [System.Collections.Generic.List[object]]::new()
    $doc = Open-JsonDoc $Path
    if (-not $doc) { return $null }
    try {
        $root = $doc.RootElement
        $pk = Get-JEl $root 'packages'
        if ($null -ne $pk -and $pk.ValueKind -eq $script:JObj) {
            foreach ($prop in $pk.EnumerateObject()) {
                $k = $prop.Name
                $i = $k.LastIndexOf('node_modules/')
                if ($i -lt 0 -or $prop.Value.ValueKind -ne $script:JObj) { continue }
                $name = $k.Substring($i + 13)
                $ver = $null; $real = $null; $link = $false; $scr = $false; $res = $null
                foreach ($f in $prop.Value.EnumerateObject()) {
                    $fn = $f.Name
                    if ($fn -eq 'version') { if ($f.Value.ValueKind -eq $script:JStr) { $ver = $f.Value.GetString() } }
                    elseif ($fn -eq 'name') { if ($f.Value.ValueKind -eq $script:JStr) { $real = $f.Value.GetString() } }
                    elseif ($fn -eq 'link') { $link = $f.Value.ValueKind -eq $script:JTrue }
                    elseif ($fn -eq 'hasInstallScript') { $scr = $f.Value.ValueKind -eq $script:JTrue }
                    elseif ($fn -eq 'resolved') { if ($f.Value.ValueKind -eq $script:JStr) { $res = $f.Value.GetString() } }
                }
                if ($link -or -not $ver) { continue }
                if ($real) { $name = $real }
                $out.Add([pscustomobject]@{ Name = $name; Version = $ver; Rel = $k; Script = $scr; Resolved = $res })
            }
            return , $out
        }
        $deps = Get-JEl $root 'dependencies'
        if ($null -ne $deps -and $deps.ValueKind -eq $script:JObj) {
            $stack = [System.Collections.Generic.Stack[object]]::new()
            $stack.Push(@($deps, ''))
            while ($stack.Count -gt 0) {
                $cur = $stack.Pop()
                $obj = [System.Text.Json.JsonElement]$cur[0]
                $prefix = [string]$cur[1]
                foreach ($prop in $obj.EnumerateObject()) {
                    if ($prop.Value.ValueKind -ne $script:JObj) { continue }
                    $name = $prop.Name
                    $rel = "${prefix}node_modules/$name"
                    $ver = $null; $res = $null; $sub = $null
                    foreach ($f in $prop.Value.EnumerateObject()) {
                        $fn = $f.Name
                        if ($fn -eq 'version') { if ($f.Value.ValueKind -eq $script:JStr) { $ver = $f.Value.GetString() } }
                        elseif ($fn -eq 'resolved') { if ($f.Value.ValueKind -eq $script:JStr) { $res = $f.Value.GetString() } }
                        elseif ($fn -eq 'dependencies') { if ($f.Value.ValueKind -eq $script:JObj) { $sub = $f.Value } }
                    }
                    if ($ver -and $ver.StartsWith('npm:')) {
                        $a = $ver.Substring(4); $at = $a.LastIndexOf('@')
                        if ($at -gt 0) { $name = $a.Substring(0, $at); $ver = $a.Substring($at + 1) }
                    }
                    if ($ver) { $out.Add([pscustomobject]@{ Name = $name; Version = $ver; Rel = $rel; Script = $false; Resolved = $res }) }
                    if ($null -ne $sub) { $stack.Push(@($sub, "$rel/")) }
                }
            }
        }
        , $out
    }
    catch { $null }
    finally { $doc.Dispose() }
}

function Get-YarnSpecName([string]$Spec) {
    $s = $Spec.Trim().Trim('"')
    $at = $s.IndexOf('@', 1)
    if ($at -lt 0) { return $s }
    $name = $s.Substring(0, $at)
    $range = $s.Substring($at + 1)
    if ($range.StartsWith('npm:')) {
        $r = $range.Substring(4)
        if ($r -match '^(@?[^@]+)@') { return $Matches[1] }
    }
    $name
}

function Read-YarnLock([string]$Path) {
    if (-not (Test-Readable $Path 128MB)) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    $berry = $false
    $cur = $null
    try {
        foreach ($line in [IO.File]::ReadLines($Path)) {
            if ($line.Length -eq 0 -or $line[0] -eq '#') { continue }
            if ($line.StartsWith('__metadata:')) { $berry = $true; $cur = $null; continue }
            if ($line[0] -ne ' ') {
                $hdr = $line.TrimEnd().TrimEnd(':')
                $cur = Get-YarnSpecName (($hdr -split ',\s*')[0])
                continue
            }
            if (-not $cur) { continue }
            if ($line -match '^\s{2}version:?\s+"?([^"\s]+)"?\s*$') {
                if (-not $berry) { $out.Add([pscustomobject]@{ Name = $cur; Version = $Matches[1]; Rel = $null; Script = $false; Resolved = $null }) }
                continue
            }
            if ($berry -and $line -match '^\s{2}resolution:\s*"?(.+?)"?\s*$') {
                $res = $Matches[1]
                if ($res -match '^(@?[^@]+)@npm:([^#]+)$') { $out.Add([pscustomobject]@{ Name = $Matches[1]; Version = $Matches[2]; Rel = $null; Script = $false; Resolved = $null }) }
                continue
            }
            if (-not $berry -and $line -match '^\s{2}resolved\s+"?(https?://[^/"]+)') {
                $h = Get-UrlHost $Matches[1]
                if ($h) { $script:LockHosts[$h] = 1 + $(if ($script:LockHosts.ContainsKey($h)) { $script:LockHosts[$h] } else { 0 }) }
            }
        }
    }
    catch { return $null }
    , $out
}

function Read-PnpmLock([string]$Path) {
    if (-not (Test-Readable $Path 128MB)) { return $null }
    $out = [System.Collections.Generic.List[object]]::new()
    $section = $null
    try {
        foreach ($line in [IO.File]::ReadLines($Path)) {
            if ($line.Length -eq 0) { continue }
            if ($line[0] -ne ' ') {
                $section = if ($line -match '^([A-Za-z][\w-]*):') { $Matches[1] } else { $null }
                continue
            }
            if ($section -ne 'packages' -and $section -ne 'snapshots') { continue }
            if ($line.Length -lt 4 -or $line[1] -ne ' ' -or $line[2] -eq ' ' -or -not $line.TrimEnd().EndsWith(':')) { continue }
            $t = $line.TrimEnd()
            $key = $t.Substring(2, $t.Length - 3).Trim().Trim("'", '"')
            $lead = $key.StartsWith('/')
            if ($lead) { $key = $key.Substring(1) }
            $k = $key -replace '\(.*$', ''
            $name = $null; $ver = $null
            if ($lead -and $k -notmatch '^(@[^/]+/)?[^@/]+@') {
                if ($k -match '^((?:@[^/]+/)?[^/]+)/([^/_]+)') { $name = $Matches[1]; $ver = $Matches[2] }
            }
            else {
                $at = $k.LastIndexOf('@')
                if ($at -gt 0) { $name = $k.Substring(0, $at); $ver = $k.Substring($at + 1) -replace '_.*$', '' }
            }
            if ($name -and $ver) { $out.Add([pscustomobject]@{ Name = $name; Version = $ver; Rel = $null; Script = $false; Resolved = $null }) }
        }
    }
    catch { return $null }
    , $out
}

function Read-BunLock([string]$Path) {
    $out = [System.Collections.Generic.List[object]]::new()
    $doc = Open-JsonDoc $Path 128MB
    if ($doc) {
        try {
            $pk = Get-JEl $doc.RootElement 'packages'
            if ($null -ne $pk -and $pk.ValueKind -eq $script:JObj) {
                foreach ($prop in $pk.EnumerateObject()) {
                    $arr = $prop.Value
                    if ($arr.ValueKind -ne $script:JArr -or $arr.GetArrayLength() -lt 1) { continue }
                    $first = $arr[0]
                    if ($first.ValueKind -ne $script:JStr) { continue }
                    $id = $first.GetString()
                    $at = $id.LastIndexOf('@')
                    if ($at -le 0) { continue }
                    $out.Add([pscustomobject]@{ Name = $id.Substring(0, $at); Version = $id.Substring($at + 1); Rel = $null; Script = $false; Resolved = $null })
                }
                return , $out
            }
        }
        catch { $out.Clear() }
        finally { $doc.Dispose() }
    }
    $text = Read-TextFile $Path 128MB
    if (-not $text) { return $null }
    foreach ($m in [regex]::Matches($text, '(?m)^\s{4}"[^"]+":\s*\["((?:@[^@"/]+/)?[^@"]+)@([^"]+)"')) {
        $out.Add([pscustomobject]@{ Name = $m.Groups[1].Value; Version = $m.Groups[2].Value; Rel = $null; Script = $false; Resolved = $null })
    }
    , $out
}

function Read-NpmLockAny([string]$Path) {
    $h = Get-BvsHash -Path $Path -MaxBytes 128MB
    if ($h -and $script:ParseCache.ContainsKey($h)) { return , $script:ParseCache[$h] }
    $leaf = [IO.Path]::GetFileName($Path).ToLowerInvariant()
    $recs = $null
    if ($leaf -in 'package-lock.json', 'npm-shrinkwrap.json', '.package-lock.json') { $recs = Read-NpmPackageLock $Path }
    elseif ($leaf -eq 'yarn.lock') { $recs = Read-YarnLock $Path }
    elseif ($leaf -in 'pnpm-lock.yaml', 'lock.yaml') { $recs = Read-PnpmLock $Path }
    elseif ($leaf -eq 'bun.lock') { $recs = Read-BunLock $Path }
    if ($null -ne $recs) {
        foreach ($r in $recs) {
            if ($r.Resolved -and $r.Resolved -match '^https?://([^/]+)/') {
                $hn = $Matches[1].ToLowerInvariant()
                $script:LockHosts[$hn] = 1 + $(if ($script:LockHosts.ContainsKey($hn)) { $script:LockHosts[$hn] } else { 0 })
            }
        }
        if ($h) { $script:ParseCache[$h] = $recs }
    }
    , $recs
}

function Read-PkgJson([string]$PkgDir, [int]$Depth = 0) {
    $doc = Open-JsonDoc (Join-Path $PkgDir 'package.json') 8MB
    if (-not $doc) { return $null }
    try {
        $r = $doc.RootElement
        if ($r.ValueKind -ne $script:JObj) { return $null }
        $scripts = [ordered]@{}
        $s = Get-JEl $r 'scripts'
        if ($null -ne $s -and $s.ValueKind -eq $script:JObj) {
            foreach ($sn in $script:LcScripts) { $v = Get-JStr $s $sn; if ($v) { $scripts[$sn] = $v } }
        }
        [pscustomobject]@{ Dir = $PkgDir; Name = (Get-JStr $r 'name'); Version = (Get-JStr $r 'version'); Scripts = $scripts; Main = (Get-JStr $r 'main'); Depth = $Depth; Broken = $false }
    }
    catch { $null }
    finally { $doc.Dispose() }
}

function Get-NodeModulesTree {
    param([string]$NodeModules, [int]$MaxTreeDepth = 12, [switch]$ReportBroken)
    $out = [System.Collections.Generic.List[object]]::new()
    if (-not [IO.Directory]::Exists($NodeModules)) { return , $out }
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@($NodeModules, 0))
    while ($stack.Count -gt 0) {
        if ($out.Count -ge $WalkMaxPackages) { $script:InstalledStats.walkCapped++; break }
        $cur = $stack.Pop()
        $nm = [string]$cur[0]; $depth = [int]$cur[1]
        $entries = $null
        try { $entries = [IO.Directory]::GetDirectories($nm, '*', $script:DirOpts) } catch { continue }
        foreach ($e in $entries) {
            $leaf = [IO.Path]::GetFileName($e)
            if ($leaf.StartsWith('.')) { continue }
            $pkgDirs = @($e)
            if ($leaf.StartsWith('@')) { try { $pkgDirs = [IO.Directory]::GetDirectories($e, '*', $script:DirOpts) } catch { $pkgDirs = @() } }
            foreach ($pd in $pkgDirs) {
                $info = Read-PkgJson $pd $depth
                if ($info) { $out.Add($info) }
                elseif ($ReportBroken -and $depth -eq 0) {
                    $bn = if ($leaf.StartsWith('@')) { $leaf + '/' + [IO.Path]::GetFileName($pd) } else { $leaf }
                    $out.Add([pscustomobject]@{ Dir = $pd; Name = $bn; Version = $null; Scripts = [ordered]@{}; Main = $null; Depth = 0; Broken = $true })
                }
                $sub = Join-Path $pd 'node_modules'
                if ($depth -lt $MaxTreeDepth -and [IO.Directory]::Exists($sub)) { $stack.Push(@($sub, ($depth + 1))) }
            }
        }
    }
    , $out
}

function Get-PnpmVirtualStore([string]$NodeModules) {
    <# Real package folders of a pnpm install: node_modules\.pnpm\<id>\node_modules\<name> (deps there are junctions and are skipped). #>
    $out = [System.Collections.Generic.List[object]]::new()
    $vs = Join-Path $NodeModules '.pnpm'
    if (-not [IO.Directory]::Exists($vs)) { return , $out }
    foreach ($id in [IO.Directory]::GetDirectories($vs, '*', $script:DirOpts)) {
        if ([IO.Path]::GetFileName($id) -eq 'node_modules') { continue }
        $inner = Join-Path $id 'node_modules'
        if (-not [IO.Directory]::Exists($inner)) { continue }
        foreach ($e in [IO.Directory]::GetDirectories($inner, '*', $script:DirOpts)) {
            $leaf = [IO.Path]::GetFileName($e)
            $pkgDirs = @($e)
            if ($leaf.StartsWith('@')) { $pkgDirs = [IO.Directory]::GetDirectories($e, '*', $script:DirOpts) }
            foreach ($pd in $pkgDirs) {
                $info = Read-PkgJson $pd 1
                if ($info) { $out.Add($info) }
                if ($out.Count -ge $WalkMaxPackages) { $script:InstalledStats.walkCapped++; return , $out }
            }
        }
    }
    , $out
}

function Add-WalkedPackages($Records, [string]$Kind, [string]$Project) {
    $n = 0
    foreach ($r in $Records) {
        if ($r.Broken) { continue }
        if (Add-Pkg -Eco npm -Name $r.Name -Version $r.Version -Kind $Kind -Path $r.Dir -Project $Project) { $n++ }
        $script:ProbeDirs.Add([pscustomobject]@{ Dir = $r.Dir; Name = $r.Name; Version = $r.Version; Kind = $Kind; Project = $Project; Scripts = $r.Scripts })
        if ($r.Scripts.Count -gt 0 -or [IO.File]::Exists((Join-Path $r.Dir 'binding.gyp'))) {
            $script:ScriptPkgs.Add([pscustomobject]@{ Dir = $r.Dir; Name = $r.Name; Version = $r.Version; Kind = $Kind; Project = $Project; Scripts = $r.Scripts })
        }
    }
    $n
}

function Add-LockRecordsInstalled($Records, [string]$BaseDir, [string]$Kind, [string]$Project) {
    $n = 0
    foreach ($r in $Records) {
        $pd = if ($r.Rel) { Join-Path $BaseDir ($r.Rel -replace '/', '\') } else { $BaseDir }
        if (Add-Pkg -Eco npm -Name $r.Name -Version $r.Version -Kind $Kind -Path $pd -Project $Project) { $n++ }
        if ($r.Rel) {
            $script:ProbeDirs.Add([pscustomobject]@{ Dir = $pd; Name = $r.Name; Version = $r.Version; Kind = $Kind; Project = $Project; Scripts = $null })
            if ($r.Script) { $script:ScriptPkgs.Add([pscustomobject]@{ Dir = $pd; Name = $r.Name; Version = $r.Version; Kind = $Kind; Project = $Project; Scripts = $null }) }
        }
    }
    $n
}

#endregion

#region ---------- npm sources: lockfiles, installed, globals, cache, npx ----------

function Invoke-NpmLockfiles {
    $done = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $script:Groups) {
        $copy = $g.Copies | Where-Object { $_.NpmLock } | Select-Object -First 1
        if (-not $copy) { continue }
        $script:LockStats.npmLockfiles++
        $leaf = [IO.Path]::GetFileName($copy.NpmLock).ToLowerInvariant()
        if ($leaf -eq 'bun.lockb') { $script:LockStats.bunLockbUnparsed++; continue }
        $recs = Read-NpmLockAny $copy.NpmLock
        if ($null -eq $recs) { $script:LockStats.failed++; Write-BvsLog -Run $run -Level WARN -Message "lockfile parse failed: $($copy.NpmLock)"; continue }
        $script:LockStats.parsed++
        switch ($leaf) { 'yarn.lock' { $script:LockStats.yarn++ } 'pnpm-lock.yaml' { $script:LockStats.pnpm++ } 'bun.lock' { $script:LockStats.bun++ } default { $script:LockStats.npm++ } }
        $n = 0
        foreach ($r in $recs) { if (Add-Pkg -Eco npm -Name $r.Name -Version $r.Version -Kind lock -Path $copy.NpmLock -Project $g.Id) { $n++ } }
        $done.Add([pscustomobject]@{ Group = $g.Id; File = $copy.NpmLock; Records = $n })
    }
    if ($script:LockStats.bunLockbUnparsed -gt 0) { $script:Coverage.Add("$($script:LockStats.bunLockbUnparsed) project(s) only have binary bun.lockb (not parsed); their installed node_modules are still walked.") }
    if ($script:LockStats.failed -gt 0) { Set-BvsCheckStatus -Id 'npm.lockfiles' -Status partial -Reason "$($script:LockStats.failed) lockfile(s) could not be parsed" }
    $done
}

function Invoke-NpmInstalled {
    $done = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $script:Groups) {
        foreach ($c in $g.Copies) {
            if (-not $c.HasNodeModules) { continue }
            $script:InstalledStats.copiesWithNodeModules++
            $nm = Join-Path $c.Path 'node_modules'
            $hidden = Join-Path $nm '.package-lock.json'
            $method = $null; $n = 0
            if ([IO.File]::Exists($hidden)) {
                $recs = Read-NpmLockAny $hidden
                if ($null -ne $recs) {
                    $method = 'hidden-lockfile'; $script:InstalledStats.hiddenLockfile++
                    $n = Add-LockRecordsInstalled $recs $c.Path 'installed' $g.Id
                }
            }
            if (-not $method -and [IO.Directory]::Exists((Join-Path $nm '.pnpm'))) {
                $method = 'pnpm-virtual-store'; $script:InstalledStats.pnpmWalk++
                $n = Add-WalkedPackages (Get-PnpmVirtualStore $nm) 'installed' $g.Id
            }
            if (-not $method) {
                $method = 'node_modules-walk'; $script:InstalledStats.fallbackWalk++
                $n = Add-WalkedPackages (Get-NodeModulesTree -NodeModules $nm -MaxTreeDepth 6) 'installed' $g.Id
            }
            $script:InstalledStats.records += $n
            $done.Add([pscustomobject]@{ Group = $g.Id; Path = $c.Path; Method = $method; Packages = $n })
        }
    }
    if ($script:InstalledStats.walkCapped -gt 0) { Set-BvsCheckStatus -Id 'npm.installed' -Status partial -Reason "walk cap ($WalkMaxPackages) reached $($script:InstalledStats.walkCapped) time(s)" }
    $done
}

function Get-NodeGlobalRoots {
    $list = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $activeNodeDir = $null
    foreach ($pe in ($env:PATH -split ';')) {
        if ($pe -and [IO.File]::Exists((Join-Path $pe 'node.exe'))) { $activeNodeDir = $pe; break }
    }
    $activeReal = $activeNodeDir
    if ($activeNodeDir) { try { $li = [IO.DirectoryInfo]::new($activeNodeDir); if ($li.LinkTarget) { $activeReal = $li.LinkTarget } } catch { } }
    $cands = [System.Collections.Generic.List[object]]::new()
    $nvmRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @($env:NVM_HOME, (Join-Path $env:LOCALAPPDATA 'nvm'), (Join-Path $env:APPDATA 'nvm'))) { if ($r -and [IO.Directory]::Exists($r) -and -not $nvmRoots.Contains($r)) { $nvmRoots.Add($r) } }
    foreach ($r in $nvmRoots) { foreach ($v in [IO.Directory]::GetDirectories($r, 'v*', $script:DirOpts)) { $cands.Add(@($v, "nvm $([IO.Path]::GetFileName($v))")) } }
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($pf) { $cands.Add(@((Join-Path $pf 'nodejs'), "Program Files nodejs ($pf)")) } }
    $cands.Add(@((Join-Path $env:APPDATA 'npm'), 'npm default prefix (%APPDATA%\npm)'))
    $userRc = Join-Path $script:UserHome '.npmrc'
    $rcText = Read-TextFile $userRc 1MB
    if ($rcText -and $rcText -match '(?m)^\s*prefix\s*=\s*(.+?)\s*$') { $cands.Add(@([Environment]::ExpandEnvironmentVariables($Matches[1].Trim('"')), 'custom npm prefix (.npmrc)')) }
    foreach ($pb in @((Join-Path $env:LOCALAPPDATA 'pnpm\global'), $(if ($env:PNPM_HOME) { Join-Path $env:PNPM_HOME 'global' }))) {
        if ($pb -and [IO.Directory]::Exists($pb)) { foreach ($v in [IO.Directory]::GetDirectories($pb, '*', $script:DirOpts)) { $cands.Add(@($v, 'pnpm global')) } }
    }
    $cands.Add(@((Join-Path $env:LOCALAPPDATA 'Yarn\Data\global'), 'yarn global'))
    $cands.Add(@((Join-Path $script:UserHome '.bun\install\global'), 'bun global'))
    $fnm = Join-Path $env:APPDATA 'fnm\node-versions'
    if ([IO.Directory]::Exists($fnm)) { foreach ($v in [IO.Directory]::GetDirectories($fnm, '*', $script:DirOpts)) { $cands.Add(@((Join-Path $v 'installation'), "fnm $([IO.Path]::GetFileName($v))")) } }
    foreach ($c in $cands) {
        $prefix = [string]$c[0]
        if (-not $prefix -or -not [IO.Directory]::Exists($prefix)) { continue }
        $real = $prefix
        try { $di = [IO.DirectoryInfo]::new($prefix); if ($di.LinkTarget) { $real = $di.LinkTarget } } catch { }
        $nm = Join-Path $real 'node_modules'
        if (-not [IO.Directory]::Exists($nm)) { continue }
        if (-not $seen.Add($nm)) { continue }
        $nodeExe = Join-Path $real 'node.exe'
        $nodeVer = if ([IO.File]::Exists($nodeExe)) { (Get-BvsVersionInfo -Path $nodeExe).FileVersion } else { $null }
        $list.Add([pscustomobject]@{ Prefix = $real; NodeModules = $nm; Label = [string]$c[1]; NodeVersion = $nodeVer; Active = [bool]($activeReal -and (Test-Under $real $activeReal) -and (Test-Under $activeReal $real)) })
    }
    if ($env:NVM_SYMLINK) { $script:Coverage.Add("nvm symlink $($env:NVM_SYMLINK) is a reparse point; globals were read through its real target.") }
    $list
}

function Invoke-NpmGlobals {
    $roots = Get-NodeGlobalRoots
    $higgs = @(Get-BvsExpected -Category 'claudeConfig' | Where-Object { $_.match.npmGlobal })
    foreach ($r in $roots) {
        $recs = Get-NodeModulesTree -NodeModules $r.NodeModules -MaxTreeDepth 12 -ReportBroken
        $proj = "G:$($r.Label)"
        $n = Add-WalkedPackages $recs 'global' $proj
        $top = @($recs | Where-Object { $_.Depth -eq 0 })
        $script:GlobalsInv.Add([ordered]@{
                label = $r.Label; prefix = $r.Prefix; nodeVersion = $r.NodeVersion; activeOnPath = $r.Active
                topLevel = @($top | Where-Object { -not $_.Broken } | ForEach-Object {
                        $exp = @($higgs | Where-Object { $_.match.npmGlobal -eq $_.Name }) | Select-Object -First 1
                        $nm = $_.Name
                        $e = @($higgs | Where-Object { $_.match.npmGlobal -eq $nm }) | Select-Object -First 1
                        [ordered]@{ name = $nm; version = $_.Version; expected = $(if ($e) { $e.id } else { $null }); installScripts = @($_.Scripts.Keys) }
                    })
                broken = @($top | Where-Object { $_.Broken } | ForEach-Object { [ordered]@{ name = $_.Name; path = $_.Dir; note = 'no readable package.json (broken or partial install)' } })
                packages = $n
            })
    }
    if ($roots.Count -eq 0) { Set-BvsCheckStatus -Id 'npm.globals' -Status not_applicable -Reason 'no Node.js global roots found' }
    $roots
}

function Get-NpmCacheRoots {
    $list = [System.Collections.Generic.List[string]]::new()
    $c = @((Join-Path $env:LOCALAPPDATA 'npm-cache'), (Join-Path $env:APPDATA 'npm-cache'), (Join-Path $script:UserHome 'npm-cache'), (Join-Path $script:UserHome '.npm'))
    if ($env:npm_config_cache) { $c += $env:npm_config_cache }
    if ($env:NPM_CONFIG_CACHE) { $c += $env:NPM_CONFIG_CACHE }
    $rcText = Read-TextFile (Join-Path $script:UserHome '.npmrc') 1MB
    if ($rcText -and $rcText -match '(?m)^\s*cache\s*=\s*(.+?)\s*$') { $c += [Environment]::ExpandEnvironmentVariables($Matches[1].Trim('"')) }
    if ($script:Discovery) { $c += @($script:Discovery.CacheRoots); $c += @($script:Discovery.NpxDirs | ForEach-Object { [IO.Path]::GetDirectoryName($_) }) }
    foreach ($x in $c) {
        if (-not $x) { continue }
        $full = $x.TrimEnd('\')
        if ([IO.Directory]::Exists($full) -and ([IO.Directory]::Exists((Join-Path $full '_cacache')) -or [IO.Directory]::Exists((Join-Path $full '_npx'))) -and -not ($list -contains $full) -and -not (Test-Excluded $full)) { $list.Add($full) }
    }
    $list
}

function Invoke-NpmCache {
    $roots = Get-NpmCacheRoots
    $total = 0
    foreach ($root in $roots) {
        $idx = Join-Path $root '_cacache\index-v5'
        if (-not [IO.Directory]::Exists($idx)) { continue }
        $stats = [ordered]@{ root = $root; bucketFiles = 0; entries = 0; tarballs = 0; uniquePackages = 0; deletedEntries = 0; oldestUtc = $null; newestUtc = $null; hosts = [ordered]@{} }
        $first = [System.Collections.Generic.Dictionary[string, long]]::new([StringComparer]::Ordinal)
        $hostCount = @{}
        $minT = [long]::MaxValue; $maxT = 0L
        foreach ($bf in [IO.Directory]::EnumerateFiles($idx, '*', [IO.SearchOption]::AllDirectories)) {
            $stats.bucketFiles++
            try { $lines = [IO.File]::ReadAllLines($bf) } catch { continue }
            foreach ($line in $lines) {
                if ($line.Length -lt 20) { continue }
                $tab = $line.IndexOf("`t")
                if ($tab -lt 0) { continue }
                $json = $line.Substring($tab + 1)
                $m = $script:CacheKeyRx.Match($json)
                if (-not $m.Success) { continue }
                $stats.entries++
                $key = $m.Groups[1].Value
                if (-not $key.StartsWith('make-fetch-happen:request-cache:')) { continue }
                $url = $key.Substring(32)
                $um = $script:TgzUrlRx.Match($url)
                if (-not $um.Success) { continue }
                if ($json.Contains('"integrity":null')) { $stats.deletedEntries++ }
                $hn = $um.Groups['h'].Value.ToLowerInvariant()
                $hostCount[$hn] = 1 + [int]$hostCount[$hn]
                $name = [uri]::UnescapeDataString($um.Groups['p'].Value)
                $base = if ($name.StartsWith('@') -and $name.Contains('/')) { $name.Substring($name.IndexOf('/') + 1) } else { $name }
                $fileBase = $um.Groups['f'].Value
                if (-not $fileBase.StartsWith("$base-")) { continue }
                $ver = $fileBase.Substring($base.Length + 1)
                $tm = $script:CacheTimeRx.Match($json)
                $t = if ($tm.Success) { [long]$tm.Groups[1].Value } else { 0L }
                $stats.tarballs++
                if ($t -gt 0) { if ($t -lt $minT) { $minT = $t }; if ($t -gt $maxT) { $maxT = $t } }
                $pk = "$name|$ver"
                $prev = 0L
                if (-not $first.TryGetValue($pk, [ref]$prev) -or ($t -gt 0 -and $t -lt $prev)) { $first[$pk] = $t }
            }
        }
        foreach ($kv in $first.GetEnumerator()) {
            $bar = $kv.Key.LastIndexOf('|')
            $when = if ($kv.Value -gt 0) { [DateTimeOffset]::FromUnixTimeMilliseconds($kv.Value).UtcDateTime.ToString('o') } else { $null }
            if (Add-Pkg -Eco npm -Name $kv.Key.Substring(0, $bar) -Version $kv.Key.Substring($bar + 1) -Kind cache -Path $root -Project $null -Detail $(if ($when) { "first cached $when" } else { $null })) { $stats.uniquePackages++ }
        }
        if ($minT -lt [long]::MaxValue) { $stats.oldestUtc = [DateTimeOffset]::FromUnixTimeMilliseconds($minT).UtcDateTime.ToString('o') }
        if ($maxT -gt 0) { $stats.newestUtc = [DateTimeOffset]::FromUnixTimeMilliseconds($maxT).UtcDateTime.ToString('o') }
        foreach ($k in @($hostCount.Keys | Sort-Object)) { $stats.hosts[$k] = $hostCount[$k] }
        $total += $stats.uniquePackages
        $script:CacheInv.Add($stats)
    }
    if ($script:CacheInv.Count -eq 0) { Set-BvsCheckStatus -Id 'npm.cache' -Status not_applicable -Reason 'no npm cache index found' }
    @($script:CacheInv)
}

function Invoke-NpxHistory {
    $dirs = [System.Collections.Generic.List[string]]::new()
    foreach ($root in (Get-NpmCacheRoots)) {
        $npx = Join-Path $root '_npx'
        if ([IO.Directory]::Exists($npx)) { foreach ($x in [IO.Directory]::GetDirectories($npx, '*', $script:DirOpts)) { if (-not $dirs.Contains($x)) { $dirs.Add($x) } } }
    }
    foreach ($nd in $dirs) {
        $hash = [IO.Path]::GetFileName($nd)
        $proj = "X:$hash"
        $requested = [System.Collections.Generic.List[object]]::new()
        $pjDoc = Open-JsonDoc (Join-Path $nd 'package.json') 1MB
        if ($pjDoc) {
            try {
                $deps = Get-JEl $pjDoc.RootElement 'dependencies'
                if ($null -ne $deps -and $deps.ValueKind -eq $script:JObj) {
                    foreach ($p in $deps.EnumerateObject()) { $requested.Add([ordered]@{ name = $p.Name; spec = $(if ($p.Value.ValueKind -eq $script:JStr) { Limit-Text $p.Value.GetString() 120 } else { $null }); resolved = $null }) }
                }
            }
            finally { $pjDoc.Dispose() }
        }
        $nm = Join-Path $nd 'node_modules'
        $hidden = Join-Path $nm '.package-lock.json'
        $n = 0; $recs = $null
        if ([IO.File]::Exists($hidden)) { $recs = Read-NpmLockAny $hidden }
        if ($null -ne $recs) {
            $n = Add-LockRecordsInstalled $recs $nd 'npx' $proj
            foreach ($rq in $requested) { $hit = @($recs | Where-Object { $_.Rel -eq "node_modules/$($rq.name)" }) | Select-Object -First 1; if ($hit) { $rq.resolved = $hit.Version } }
        }
        elseif ([IO.Directory]::Exists($nm)) {
            $walk = Get-NodeModulesTree -NodeModules $nm -MaxTreeDepth 8
            $n = Add-WalkedPackages $walk 'npx' $proj
            foreach ($rq in $requested) { $hit = @($walk | Where-Object { $_.Depth -eq 0 -and $_.Name -eq $rq.name }) | Select-Object -First 1; if ($hit) { $rq.resolved = $hit.Version } }
        }
        $times = Get-FileTimes $nd
        $script:NpxHistory.Add([ordered]@{ path = $nd; createdUtc = $times.created; modifiedUtc = $times.modified; requested = @($requested); packages = $n; malicious = 0 })
    }
    if ($dirs.Count -eq 0) { Set-BvsCheckStatus -Id 'npm.npx' -Status not_applicable -Reason 'no _npx folders found' }
    @($script:NpxHistory)
}

#endregion

#region ---------- python sources ----------

function Read-Requirements([string]$Path) {
    $pins = [System.Collections.Generic.List[object]]::new()
    $opts = [System.Collections.Generic.List[object]]::new()
    $t = Read-TextFile $Path 8MB
    if ($null -eq $t) { return $null }
    foreach ($raw in ($t -split "`r?`n")) {
        $line = ($raw -replace '(^|\s)#.*$', '').Trim()
        if (-not $line) { continue }
        $line = ($line -replace '\s+--hash[= ]\S+', '' -replace '\s*\\$', '').Trim()
        if ($line -match '^(-i|--index-url|--extra-index-url|--trusted-host|-f|--find-links)(?:\s*=\s*|\s+)(\S+)') { $opts.Add([pscustomobject]@{ Option = $Matches[1]; Value = $Matches[2] }); continue }
        if ($line.StartsWith('-')) { continue }
        if ($line -match '^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)\s*(?:;.*)?$') { $pins.Add([pscustomobject]@{ Name = $Matches[1]; Version = $Matches[2] }) }
    }
    [pscustomobject]@{ Pins = $pins; Options = $opts }
}

function Read-TomlLockPackages([string]$Path) {
    <# poetry.lock / uv.lock line parser: [[package]] name/version, plus source registry / [package.source] url. #>
    if (-not (Test-Readable $Path 128MB)) { return $null }
    $pkgs = [System.Collections.Generic.List[object]]::new()
    $sources = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $name = $null; $ver = $null; $src = $null; $inPkg = $false; $inSource = $false; $localish = $false
    $flush = {
        if ($inPkg -and $name -and $ver -and -not $localish) { $pkgs.Add([pscustomobject]@{ Name = $name; Version = $ver; Source = $src }) }
    }
    try {
        foreach ($line in [IO.File]::ReadLines($Path)) {
            if ($line -match '^\s*\[\[package\]\]\s*$') {
                . $flush
                $inPkg = $true; $inSource = $false; $name = $null; $ver = $null; $src = $null; $localish = $false
                continue
            }
            if ($line -match '^\s*\[') { $inSource = ($line -match '^\s*\[package\.source\]'); if (-not $inSource -and $line -notmatch '^\s*\[package\.') { . $flush; $inPkg = $false }; continue }
            if (-not $inPkg) { continue }
            if ($inSource) {
                if ($line -match '^\s*type\s*=\s*"(directory|file|git|url)"') { $localish = $true }
                if ($line -match '^\s*url\s*=\s*"([^"]+)"') { $src = $Matches[1]; if (-not $localish) { [void]$sources.Add($src) } }
                continue
            }
            if (-not $name -and $line -match '^name\s*=\s*"([^"]+)"') { $name = $Matches[1]; continue }
            if (-not $ver -and $line -match '^version\s*=\s*"([^"]+)"') { $ver = $Matches[1]; continue }
            if ($line -match '^source\s*=\s*\{([^}]*)\}') {
                $s = $Matches[1]
                if ($s -match 'registry\s*=\s*"([^"]+)"') { $src = $Matches[1]; [void]$sources.Add($src) }
                elseif ($s -match '(editable|virtual|directory|path|git|url)\s*=') { $localish = $true }
            }
        }
        . $flush
    }
    catch { return $null }
    [pscustomobject]@{ Packages = $pkgs; Sources = @($sources) }
}

function Read-PipfileLock([string]$Path) {
    $doc = Open-JsonDoc $Path 64MB
    if (-not $doc) { return $null }
    $pkgs = [System.Collections.Generic.List[object]]::new()
    $sources = [System.Collections.Generic.List[string]]::new()
    try {
        $root = $doc.RootElement
        foreach ($sec in 'default', 'develop') {
            $o = Get-JEl $root $sec
            if ($null -eq $o -or $o.ValueKind -ne $script:JObj) { continue }
            foreach ($p in $o.EnumerateObject()) {
                $v = Get-JStr $p.Value 'version'
                if ($v -and $v.StartsWith('==')) { $pkgs.Add([pscustomobject]@{ Name = $p.Name; Version = $v.TrimStart('=') }) }
            }
        }
        $meta = Get-JEl $root '_meta'
        if ($null -ne $meta) {
            $srcs = Get-JEl $meta 'sources'
            if ($null -ne $srcs -and $srcs.ValueKind -eq $script:JArr) { foreach ($s in $srcs.EnumerateArray()) { $u = Get-JStr $s 'url'; if ($u) { $sources.Add($u) } } }
        }
    }
    catch { return $null }
    finally { $doc.Dispose() }
    [pscustomobject]@{ Packages = $pkgs; Sources = @($sources) }
}

function Test-DefaultPyIndex([string]$Url) {
    $u = $Url.Trim().Trim('"', "'").TrimEnd('/').ToLowerInvariant()
    $u -in 'https://pypi.org/simple', 'https://pypi.python.org/simple', 'https://pypi.org/pypi', 'https://files.pythonhosted.org'
}

function Invoke-PythonLockfiles {
    $done = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $script:Groups) {
        $copy = $g.Copies | Where-Object { $_.PyLocks.Count -gt 0 } | Select-Object -First 1
        if (-not $copy) { continue }
        foreach ($f in $copy.PyLocks) {
            $leaf = [IO.Path]::GetFileName($f).ToLowerInvariant()
            $n = 0
            if ($leaf -like 'requirements*.txt') {
                $script:LockStats.requirements++
                $r = Read-Requirements $f
                if ($null -eq $r) { $script:LockStats.pyFailed++; continue }
                foreach ($p in $r.Pins) { if (Add-Pkg -Eco PyPI -Name $p.Name -Version $p.Version -Kind lock -Path $f -Project $g.Id) { $n++ } }
                foreach ($o in $r.Options) { Add-RegistryRecord -File $f -Scope 'project' -Tool 'pip' -Key $o.Option -Value $o.Value }
            }
            else {
                $script:LockStats.pyLockfiles++
                $r = if ($leaf -eq 'pipfile.lock') { Read-PipfileLock $f } else { Read-TomlLockPackages $f }
                if ($null -eq $r) { $script:LockStats.pyFailed++; continue }
                foreach ($p in $r.Packages) { if (Add-Pkg -Eco PyPI -Name $p.Name -Version $p.Version -Kind lock -Path $f -Project $g.Id) { $n++ } }
                foreach ($s in $r.Sources) { if (-not (Test-DefaultPyIndex $s)) { Add-RegistryRecord -File $f -Scope 'project' -Tool $leaf -Key 'source' -Value $s } }
            }
            $done.Add([pscustomobject]@{ Group = $g.Id; File = $f; Records = $n })
        }
    }
    if ($script:LockStats.pyFailed -gt 0) { Set-BvsCheckStatus -Id 'python.lockfiles' -Status partial -Reason "$($script:LockStats.pyFailed) file(s) unreadable" }
    $done
}

function Get-VenvSitePackages([string]$Root) {
    $list = [System.Collections.Generic.List[string]]::new()
    $w = Join-Path $Root 'Lib\site-packages'
    if ([IO.Directory]::Exists($w)) { $list.Add($w) }
    $lib = Join-Path $Root 'lib'
    if ([IO.Directory]::Exists($lib)) {
        foreach ($py in [IO.Directory]::GetDirectories($lib, 'python*', $script:DirOpts)) {
            $sp = Join-Path $py 'site-packages'
            if ([IO.Directory]::Exists($sp) -and -not $list.Contains($sp)) { $list.Add($sp) }
        }
    }
    $list
}

function Get-PythonEnvironments {
    $envs = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $projByVenv = @{}
    foreach ($g in $script:Groups) { foreach ($c in $g.Copies) { foreach ($v in $c.Venvs) { $projByVenv[$v] = $g.Id } } }
    $add = [System.Collections.Generic.List[object]]::new()
    foreach ($v in @($script:Discovery.Venvs)) { $add.Add(@($v, 'venv', $(if ($projByVenv.ContainsKey($v)) { $projByVenv[$v] } else { "E:$v" }), 'project/standalone venv')) }
    $pyRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($hive in 'HKCU', 'HKLM') {
        foreach ($view in '64', '32') {
            foreach ($ver in @(Get-BvsRegSubKeys -Path "$hive\Software\Python\PythonCore" -View $view)) {
                $ip = @(Get-BvsRegValues -Path "$hive\Software\Python\PythonCore\$ver\InstallPath" -View $view | Where-Object { $_.Name -eq '' }) | Select-Object -First 1
                if ($ip -and $ip.Value) { $r = ([string]$ip.Value).TrimEnd('\'); if (-not $pyRoots.Contains($r)) { $pyRoots.Add($r) } }
            }
        }
    }
    foreach ($pat in @((Join-Path $env:LOCALAPPDATA 'Programs\Python'), "$env:SystemDrive\", $env:ProgramFiles)) {
        if (-not $pat -or -not [IO.Directory]::Exists($pat)) { continue }
        foreach ($x in [IO.Directory]::GetDirectories($pat, 'Python3*', $script:DirOpts)) { if (-not $pyRoots.Contains($x)) { $pyRoots.Add($x) } }
    }
    foreach ($r in $pyRoots) { $add.Add(@($r, 'site', "E:$r", 'global Python install')) }
    $userBase = Join-Path $env:APPDATA 'Python'
    if ([IO.Directory]::Exists($userBase)) { foreach ($x in [IO.Directory]::GetDirectories($userBase, 'Python*', $script:DirOpts)) { $add.Add(@($x, 'site', "E:$x", 'per-user site-packages (pip --user)')) } }
    $store = Join-Path $env:LOCALAPPDATA 'Packages'
    if ([IO.Directory]::Exists($store)) {
        foreach ($x in [IO.Directory]::GetDirectories($store, 'PythonSoftwareFoundation.Python.*', $script:DirOpts)) {
            $lp = Join-Path $x 'LocalCache\local-packages'
            if ([IO.Directory]::Exists($lp)) { foreach ($y in [IO.Directory]::GetDirectories($lp, 'Python*', $script:DirOpts)) { $add.Add(@($y, 'site', "E:$y", 'Microsoft Store Python user site')) } }
        }
    }
    foreach ($base in @((Join-Path $script:UserHome 'pipx\venvs'), (Join-Path $env:LOCALAPPDATA 'pipx\pipx\venvs'), (Join-Path $script:UserHome '.local\pipx\venvs'), (Join-Path $env:APPDATA 'uv\tools'), (Join-Path $env:LOCALAPPDATA 'uv\tools'))) {
        if ([IO.Directory]::Exists($base)) { foreach ($x in [IO.Directory]::GetDirectories($base, '*', $script:DirOpts)) { $add.Add(@($x, 'venv', "E:$x", 'pipx/uv tool venv')) } }
    }
    foreach ($base in @((Join-Path $script:UserHome 'anaconda3'), (Join-Path $script:UserHome 'miniconda3'), (Join-Path $env:ProgramData 'anaconda3'), (Join-Path $env:ProgramData 'miniconda3'))) {
        if (-not [IO.Directory]::Exists($base)) { continue }
        $add.Add(@($base, 'site', "E:$base", 'conda base'))
        $ce = Join-Path $base 'envs'
        if ([IO.Directory]::Exists($ce)) { foreach ($x in [IO.Directory]::GetDirectories($ce, '*', $script:DirOpts)) { $add.Add(@($x, 'venv', "E:$x", 'conda env')) } }
    }
    foreach ($a in $add) {
        $root = [string]$a[0]
        if (-not $seen.Add($root) -or (Test-Excluded $root)) { continue }
        $sps = Get-VenvSitePackages $root
        if ($sps.Count -eq 0) { continue }
        $envs.Add([pscustomobject]@{ Root = $root; Kind = [string]$a[1]; Project = [string]$a[2]; Label = [string]$a[3]; SitePackages = $sps })
    }
    $envs
}

function Invoke-PythonEnvironments {
    $envs = Get-PythonEnvironments
    foreach ($e in $envs) {
        $n = 0
        foreach ($sp in $e.SitePackages) {
            $script:SitePackages.Add([pscustomobject]@{ Path = $sp; Kind = $e.Kind; Project = $e.Project; Root = $e.Root })
            try { $entries = [IO.Directory]::GetFileSystemEntries($sp, '*-info', $script:DirOpts) } catch { continue }
            foreach ($ent in $entries) {
                $leaf = [IO.Path]::GetFileName($ent)
                $m = $script:DistInfoRx.Match($leaf)
                if (-not $m.Success) { $m = $script:EggInfoRx.Match($leaf) }
                if (-not $m.Success) { continue }
                if (Add-Pkg -Eco PyPI -Name $m.Groups['n'].Value -Version $m.Groups['v'].Value -Kind $e.Kind -Path $ent -Project $e.Project) { $n++ }
            }
        }
        $script:PyEnvInv.Add([ordered]@{ root = $e.Root; kind = $e.Kind; label = $e.Label; project = $e.Project; sitePackages = @($e.SitePackages); packages = $n })
    }
    if ($envs.Count -eq 0) { Set-BvsCheckStatus -Id 'python.environments' -Status not_applicable -Reason 'no Python environments found' }
    $envs
}

#endregion

#region ---------- OSV ----------

function Invoke-OsvRequest {
    param([string]$Uri, [string]$Method = 'GET', $Body, [string]$SaveName = 'resp')
    $last = $null
    for ($try = 1; $try -le 3; $try++) {
        try {
            $last = Invoke-BvsIntel -Uri $Uri -Method $Method -Body $Body -SaveName $SaveName -TimeoutSec 90
            if ($last.Status -eq 200) { return $last }
            if ($last.Status -notin 429, 500, 502, 503, 504) { return $last }
        }
        catch { if ($try -eq 3) { throw } }
        Start-Sleep -Seconds (2 * $try)
    }
    $last
}

function Invoke-OsvQuery {
    $keys = [System.Collections.Generic.List[string]]::new($script:Pkgs.Keys)
    $script:OsvStats.queried = $keys.Count
    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) { $pending.Add([pscustomobject]@{ Key = $k; Token = $null }) }
    $round = 0
    while ($pending.Count -gt 0 -and $round -lt 5) {
        $round++
        $next = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $pending.Count; $i += $OsvBatchSize) {
            $chunk = $pending.GetRange($i, [Math]::Min($OsvBatchSize, $pending.Count - $i))
            $queries = [System.Collections.Generic.List[object]]::new()
            foreach ($c in $chunk) {
                $p = $script:Pkgs[$c.Key]
                $q = [ordered]@{ package = [ordered]@{ name = $p.Name; ecosystem = $p.Eco }; version = $p.Version }
                if ($c.Token) { $q.page_token = $c.Token }
                $queries.Add($q)
            }
            $script:OsvStats.batches++
            $r = Invoke-OsvRequest -Uri 'https://api.osv.dev/v1/querybatch' -Method POST -Body @{ queries = $queries } -SaveName "osv-querybatch-$($script:OsvStats.batches).json"
            if ($r.Status -ne 200 -or -not $r.Json) { $script:OsvStats.errors++; throw "OSV querybatch failed (HTTP $($r.Status))" }
            $results = @($r.Json.results)
            for ($j = 0; $j -lt $chunk.Count -and $j -lt $results.Count; $j++) {
                $res = $results[$j]
                if (-not $res) { continue }
                $ids = @($res.vulns | Where-Object { $_ -and $_.id } | ForEach-Object { $_.id })
                if ($ids.Count -gt 0) {
                    $key = $chunk[$j].Key
                    $lst = $null
                    if (-not $script:OsvHits.TryGetValue($key, [ref]$lst)) { $lst = [System.Collections.Generic.List[string]]::new(); $script:OsvHits[$key] = $lst }
                    foreach ($id in $ids) { if (-not $lst.Contains($id)) { $lst.Add($id) } }
                }
                if ($res.next_page_token) { $next.Add([pscustomobject]@{ Key = $chunk[$j].Key; Token = [string]$res.next_page_token }) }
            }
        }
        $pending = $next
    }
    $script:OsvStats.packagesWithHits = $script:OsvHits.Count
    $script:OsvHits.Count
}

function Get-Cvss3Score([string]$Vector) {
    if ($Vector -notmatch '^CVSS:3\.[01]/') { return $null }
    $m = @{}
    foreach ($part in ($Vector.Split('/') | Select-Object -Skip 1)) { $kv = $part.Split(':'); if ($kv.Count -eq 2) { $m[$kv[0]] = $kv[1] } }
    $AV = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.2 }[$m.AV]
    $AC = @{ L = 0.77; H = 0.44 }[$m.AC]
    $UI = @{ N = 0.85; R = 0.62 }[$m.UI]
    $sc = $m.S
    $PR = if ($sc -eq 'C') { @{ N = 0.85; L = 0.68; H = 0.5 }[$m.PR] } else { @{ N = 0.85; L = 0.62; H = 0.27 }[$m.PR] }
    $cia = @{ H = 0.56; L = 0.22; N = 0.0 }
    $C = $cia[$m.C]; $I = $cia[$m.I]; $A = $cia[$m.A]
    if ($null -in @($AV, $AC, $UI, $PR, $C, $I, $A)) { return $null }
    $iss = 1 - ((1 - $C) * (1 - $I) * (1 - $A))
    $impact = if ($sc -eq 'C') { 7.52 * ($iss - 0.029) - 3.25 * [Math]::Pow($iss - 0.02, 15) } else { 6.42 * $iss }
    if ($impact -le 0) { return 0.0 }
    $expl = 8.22 * $AV * $AC * $PR * $UI
    $raw = if ($sc -eq 'C') { [Math]::Min(1.08 * ($impact + $expl), 10) } else { [Math]::Min($impact + $expl, 10) }
    $int = [long][Math]::Round($raw * 100000)
    if ($int % 10000 -eq 0) { return $int / 100000.0 }
    ([Math]::Floor($int / 10000) + 1) / 10.0
}

function Get-SeverityBucket([string]$Text) {
    switch -regex ($Text) {
        '^(?i)critical' { return 'critical' }
        '^(?i)high' { return 'high' }
        '^(?i)(moderate|medium)' { return 'moderate' }
        '^(?i)low' { return 'low' }
    }
    $null
}

function ConvertTo-OsvInfo($V) {
    $id = [string]$V.id
    $summary = [string]$V.summary
    $details = [string]$V.details
    $cwes = [System.Collections.Generic.List[string]]::new()
    if ($V.database_specific -and $V.database_specific.cwe_ids) { foreach ($c in @($V.database_specific.cwe_ids)) { $cwes.Add([string]$c) } }
    foreach ($a in @($V.affected)) {
        if ($a.database_specific -and $a.database_specific.cwes) { foreach ($c in @($a.database_specific.cwes)) { if ($c.cweId) { $cwes.Add([string]$c.cweId) } } }
    }
    $aliases = @($V.aliases | Where-Object { $_ })
    $mal = $null
    if ($id -like 'MAL-*') { $mal = 'MAL id (OpenSSF malicious-packages)' }
    elseif (@($aliases | Where-Object { $_ -like 'MAL-*' }).Count -gt 0) { $mal = 'alias of a MAL id' }
    elseif ($cwes -contains 'CWE-506') { $mal = 'CWE-506 Embedded Malicious Code' }
    elseif ($script:SummaryMalRx.IsMatch($summary)) { $mal = 'summary describes malicious code' }
    elseif ($script:DetailsMalRx.IsMatch($details)) { $mal = 'details describe malicious code' }
    $sev = $null
    if ($V.database_specific -and $V.database_specific.severity) { $sev = Get-SeverityBucket ([string]$V.database_specific.severity) }
    if (-not $sev) {
        foreach ($s in @($V.severity)) {
            if ($s.type -eq 'CVSS_V3') {
                $score = Get-Cvss3Score ([string]$s.score)
                if ($null -ne $score) { $sev = if ($score -ge 9) { 'critical' } elseif ($score -ge 7) { 'high' } elseif ($score -ge 4) { 'moderate' } elseif ($score -gt 0) { 'low' } else { 'none' }; break }
            }
        }
    }
    if (-not $sev) {
        foreach ($a in @($V.affected)) {
            foreach ($src in @($a.ecosystem_specific, $a.database_specific)) { if ($src -and $src.severity -is [string]) { $sev = Get-SeverityBucket $src.severity; if ($sev) { break } } }
            if ($sev) { break }
        }
    }
    [pscustomobject]@{
        Id = $id; Malicious = [bool]$mal; MalReason = $mal; Severity = $(if ($sev) { $sev } else { 'unknown' })
        Summary = Limit-Text $summary 240; Aliases = $aliases; Published = [string]$V.published; Modified = [string]$V.modified
        Withdrawn = [string]$V.withdrawn
    }
}

function Invoke-OsvDetails {
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($l in $script:OsvHits.Values) { foreach ($id in $l) { [void]$ids.Add($id) } }
    $script:OsvStats.uniqueVulnIds = $ids.Count
    $cacheDir = Join-Path $script:BvsRoot 'intel\api.osv.dev'
    $cached = @{}
    if ([IO.Directory]::Exists($cacheDir) -and $OsvCacheDays -gt 0) {
        $cutoff = [datetime]::UtcNow.AddDays(-$OsvCacheDays)
        foreach ($f in [IO.Directory]::EnumerateFiles($cacheDir, '*-osv-vuln-*.json')) {
            $leaf = [IO.Path]::GetFileName($f)
            if ($leaf -notmatch '^(\d{8}-\d{9})-osv-vuln-(.+)\.json$') { continue }
            $stamp = [datetime]::ParseExact($Matches[1], 'yyyyMMdd-HHmmssfff', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
            if ($stamp -lt $cutoff) { continue }
            $vid = $Matches[2]
            if (-not $cached.ContainsKey($vid) -or $cached[$vid].Stamp -lt $stamp) { $cached[$vid] = [pscustomobject]@{ Stamp = $stamp; Path = $f } }
        }
    }
    $toFetch = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $ids) {
        $c = $cached[($id -replace '[^A-Za-z0-9._-]', '_')]
        if ($c) {
            try {
                $j = [IO.File]::ReadAllText($c.Path) | ConvertFrom-Json -Depth 64
                if ($j.id) { $script:OsvVulns[$id] = ConvertTo-OsvInfo $j; $script:OsvStats.detailsFromCache++; continue }
            }
            catch { }
        }
        $toFetch.Add($id)
    }
    if ($toFetch.Count -gt $OsvMaxDetails) {
        # Malicious-looking ids first, then the rest up to the cap.
        $ordered = @($toFetch | Sort-Object { if ($_ -like 'MAL-*') { 0 } elseif ($_ -like 'GHSA-*') { 1 } else { 2 } })
        $script:OsvStats.detailsSkipped = $toFetch.Count - $OsvMaxDetails
        $toFetch = [System.Collections.Generic.List[string]]::new([string[]]@($ordered | Select-Object -First $OsvMaxDetails))
        Set-BvsCheckStatus -Id 'osv.details' -Status partial -Reason "detail cap reached: $($script:OsvStats.detailsSkipped) vulnerability id(s) counted without severity"
    }
    if ($toFetch.Count -gt 0) {
        $lib = $script:LibPath
        $results = $toFetch | ForEach-Object -ThrottleLimit $OsvThrottle -Parallel {
            if (-not (Get-Module -Name 'BVS.Common')) { Import-Module $using:lib -Force }
            $vid = $_
            $out = [pscustomobject]@{ Id = $vid; Json = $null; Status = 0; Error = $null }
            for ($try = 1; $try -le 3; $try++) {
                try {
                    $r = Invoke-BvsIntel -Uri ('https://api.osv.dev/v1/vulns/' + [uri]::EscapeDataString($vid)) -SaveName ("osv-vuln-$vid.json") -TimeoutSec 60
                    $out.Status = $r.Status
                    if ($r.Status -eq 200 -and $r.Json) { $out.Json = $r.Json; break }
                    if ($r.Status -notin 429, 500, 502, 503, 504) { break }
                }
                catch { $out.Error = $_.Exception.Message }
                Start-Sleep -Seconds (2 * $try)
            }
            $out
        }
        foreach ($r in $results) {
            if ($r.Json) { $script:OsvVulns[$r.Id] = ConvertTo-OsvInfo $r.Json; $script:OsvStats.detailsFetched++ }
            else { $script:OsvStats.detailsFailed++; Write-BvsLog -Run $run -Level WARN -Message "OSV detail failed for $($r.Id): HTTP $($r.Status) $($r.Error)" }
        }
    }
    foreach ($id in $ids) {
        if (-not $script:OsvVulns.ContainsKey($id)) {
            $script:OsvVulns[$id] = [pscustomobject]@{ Id = $id; Malicious = ($id -like 'MAL-*'); MalReason = $(if ($id -like 'MAL-*') { 'MAL id (details unavailable)' } else { $null }); Severity = 'unknown'; Summary = $null; Aliases = @(); Published = $null; Modified = $null; Withdrawn = $null }
        }
    }
    foreach ($v in $script:OsvVulns.Values) {
        if ($v.Withdrawn) { $script:OsvStats.withdrawn++ }
        elseif ($v.Malicious) { $script:OsvStats.maliciousIds++ }
    }
    if ($script:OsvStats.detailsFailed -gt 0) { Set-BvsCheckStatus -Id 'osv.details' -Status partial -Reason "$($script:OsvStats.detailsFailed) detail fetch(es) failed (MAL- ids still count as malicious)" }
    $ids.Count
}

#endregion

#region ---------- findings: malicious packages ----------

function Get-LocationEvidence($P, [int]$Max = 12) {
    $ev = [System.Collections.Generic.List[object]]::new()
    foreach ($l in $P.Locs) {
        if ($ev.Count -ge $Max) { break }
        if ($l.kind -eq 'lock' -and $l.project -and $script:GroupById.ContainsKey($l.project)) {
            $g = $script:GroupById[$l.project]
            foreach ($c in $g.Copies) {
                if ($ev.Count -ge $Max) { break }
                $lf = @($c.NpmLock) + @($c.PyLocks) | Where-Object { $_ -and [IO.Path]::GetFileName($_) -eq [IO.Path]::GetFileName($l.path) } | Select-Object -First 1
                if ($lf) { $ev.Add([ordered]@{ type = 'file'; source = 'lockfile'; path = $lf; project = "$($g.Id) $($g.Name)" }) }
            }
            continue
        }
        $src = switch ($l.kind) { 'installed' { 'installed (project node_modules)' } 'global' { 'installed (global)' } 'venv' { 'installed (venv)' } 'site' { 'installed (global site-packages)' } 'npx' { 'npx run (executed)' } 'cache' { 'npm cache (downloaded)' } default { $l.kind } }
        $proj = if ($l.project -and $script:GroupById.ContainsKey($l.project)) { "$($l.project) $($script:GroupById[$l.project].Name)" } else { $l.project }
        $ev.Add([ordered]@{ type = 'file'; source = $src; path = $l.path; project = $proj; detail = $l.detail })
    }
    if ($P.LocCount -gt $ev.Count) { $ev.Add([ordered]@{ type = 'note'; detail = "$($P.LocCount) location record(s) in total; kinds: $(@($P.Kinds) -join ', ')" }) }
    $ev
}

function Add-MaliciousFindings {
    $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($kv in $script:OsvHits.GetEnumerator()) {
        foreach ($id in $kv.Value) { $v = $script:OsvVulns[$id]; if ($v -and $v.Malicious -and -not $v.Withdrawn) { [void]$keys.Add($kv.Key); break } }
    }
    foreach ($k in $script:Pkgs.Keys) { if ($script:IocVersions.ContainsKey($k)) { [void]$keys.Add($k) } }
    foreach ($key in $keys) {
        $p = $script:Pkgs[$key]
        $malIds = @()
        if ($script:OsvHits.ContainsKey($key)) { $malIds = @($script:OsvHits[$key] | Where-Object { $script:OsvVulns[$_].Malicious -and -not $script:OsvVulns[$_].Withdrawn }) }
        $camp = $null
        if ($script:IocVersions.ContainsKey($key)) { $camp = $script:IocCampaigns[$script:IocVersions[$key]] }
        $state = Get-PkgState $p.Kinds
        $isPlaceholder = $p.Version -match '-security$'
        $sev = 'high'; $cls = 'suspicious'; $conf = 'medium'
        switch ($state) {
            'installed' { $sev = 'critical'; $cls = 'compromise'; $conf = 'high' }
            'lock' { $sev = 'critical'; $cls = 'compromise'; $conf = 'medium' }
            'npx' { $sev = 'high'; $cls = 'suspicious'; $conf = 'high' }
            'cache' { $sev = 'high'; $cls = 'suspicious'; $conf = 'medium' }
        }
        if ($isPlaceholder) { $sev = 'medium'; $cls = 'suspicious'; $conf = 'medium' }
        $stateText = switch ($state) { 'installed' { 'installed' } 'lock' { 'in a lockfile' } 'npx' { 'executed via npx' } 'cache' { 'in the npm cache only' } default { 'present' } }
        $idText = if ($malIds.Count) { ($malIds | Select-Object -First 3) -join ', ' } elseif ($camp) { "IoC list: $($camp.id)" } else { 'IoC list' }
        $title = "Malicious $($p.Eco) package $($stateText): $($p.Name)@$($p.Version) ($idText)"
        if ($isPlaceholder) { $title = "npm security placeholder for a removed malicious package: $($p.Name)@$($p.Version)" }
        $evidence = [System.Collections.Generic.List[object]]::new()
        $evidence.Add([ordered]@{ type = 'package'; ecosystem = $p.Eco; name = $p.Name; version = $p.Version; state = $state; kinds = @($p.Kinds) })
        foreach ($id in $malIds) {
            $v = $script:OsvVulns[$id]
            $evidence.Add([ordered]@{ type = 'osv'; id = $id; url = "https://osv.dev/vulnerability/$id"; reason = $v.MalReason; summary = $v.Summary; published = $v.Published; aliases = @($v.Aliases | Select-Object -First 5) })
        }
        if ($camp) { $evidence.Add([ordered]@{ type = 'ioc'; list = 'S11-iocs.json'; campaign = $camp.id; title = $camp.title; date = $camp.date; source = $camp.source }) }
        foreach ($e in (Get-LocationEvidence $p)) { $evidence.Add($e) }
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($malIds.Count) { $reasons.Add('intel_match') }
        if ($camp) { $reasons.Add('ioc_list') }
        $reasons.Add("state_$state")
        if ($state -eq 'npx') { $reasons.Add('executed') }
        # Expected cap only when EVERY location is a fixture inside a security-tool folder listed in expected.json.
        $caps = @(foreach ($l in $p.Locs) { Get-ExpectedCap -Path ([string]$l.path) })
        $expected = $null
        if ($p.Locs.Count -gt 0 -and $caps.Count -eq $p.Locs.Count -and $p.LocCount -eq $p.Locs.Count) { $expected = $caps[0]; $sev = 'info'; $cls = 'info'; $reasons.Add('expected_match') }
        $fp = switch ($state) {
            'installed' { 'OSV MAL entries come from OpenSSF malicious-packages and GitHub malware advisories and are rarely wrong, but a few cover research/test packages or are later withdrawn: open the advisory. The version on disk was read from the hidden lockfile or package.json, so a stale node_modules can lag behind the lockfile.' }
            'lock' { 'Present in a lockfile but not found installed: it may be a platform-specific optional dependency that was never extracted here, or a stale lock. It will be installed by the next npm ci / pnpm install / uv sync unless the lock is changed.' }
            'npx' { 'npx folders survive for a long time; the run may be old. The package was executed at least once by the account (its install scripts and bin ran).' }
            'cache' { 'The npm cache records every tarball ever downloaded, including ones that were resolved but later replaced. It does not prove the code ran, only that it was fetched.' }
            default { 'Context only.' }
        }
        if ($isPlaceholder) { $fp = 'x.y.z-security is the harmless placeholder npm publishes after removing malware. It means a dependency still points at a known-malicious package name; the placeholder itself contains no code.' }
        if ($expected) { $fp = "All locations are test/fixture paths inside a security-tool folder listed in expected.json ($($expected.id)): planted by design. " + $fp }
        $rec = switch ($state) {
            'installed' { 'Treat the machine as possibly compromised until verified. 1) Do not run the project or any npm/pip command in it. 2) Check S11 host-path findings for gh-token-monitor or similar watchers and disable them FIRST (some 2026 worms wipe the home folder when their stolen token is revoked). 3) From a clean device, rotate npm, GitHub, cloud and AI-provider tokens reachable from this account; review GitHub for unknown repositories, workflows and self-hosted runners. 4) Then remove node_modules / the venv, pin a clean version in the lockfile and reinstall with --ignore-scripts. Manual steps only.' }
            'lock' { 'Change the lockfile to a clean version before the next install (check the advisory for the safe range), then check CI logs and other machines that may have installed it. Manual steps only.' }
            'npx' { 'It ran at least once. Find when (folder times), then rotate secrets that were reachable from that shell (npm/GitHub/cloud tokens, .env files) and check for persistence. Remove the npx folder only after the investigation. Manual steps only.' }
            'cache' { 'Find which project fetched it (search lockfiles and their git history for this version). If nothing installed it, it is a near-miss; clear the cache entry manually after the investigation (npm cache clean is a manual step).' }
            default { 'Review manually.' }
        }
        New-BvsFinding -Run $run -Check 'supply.malicious' -Title $title -Severity $sev -Class $cls -Confidence $conf -Reasons @($reasons) -Evidence @($evidence) `
            -Entities @{ files = @($p.Locs | Select-Object -First 10 | ForEach-Object { [ordered]@{ path = $_.path } }); processes = @(); network = @(); registry = @(); accounts = @() } `
            -Recommendation $rec -FpNotes $fp -Mitre @('T1195.002') -Expected $expected
        $script:MalInv.Add([ordered]@{
                ecosystem = $p.Eco; name = $p.Name; version = $p.Version; state = $state; severity = $sev
                osvIds = @($malIds); campaign = $(if ($camp) { $camp.id } else { $null })
                kinds = @($p.Kinds); projects = @($p.Projects | Select-Object -First 20); locations = $p.LocCount
                paths = @($p.Locs | Select-Object -First 8 | ForEach-Object { $_.path })
            })
        foreach ($h in $script:NpxHistory) { if ($p.Projects.Contains("X:$([IO.Path]::GetFileName($h.path))")) { $h.malicious++ } }
    }
    $keys.Count
}

#endregion

#region ---------- static IoCs: package files, repo files, host paths, staging ----------

function Test-ContentMarkers([string]$Text) {
    if (-not $Text) { return @() }
    @($script:ContentMarkers | Where-Object { $Text.Contains([string]$_) })
}

function Invoke-PackageFileProbe {
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $strong = @('setup_bun.js', 'bun_environment.js', 'Math_Symbol.js')
    $count = 0
    foreach ($pd in $script:ProbeDirs) {
        if (-not $seen.Add($pd.Dir)) { continue }
        $count++
        $found = [System.Collections.Generic.List[string]]::new()
        foreach ($n in $strong) { if ([IO.File]::Exists([IO.Path]::Combine($pd.Dir, $n))) { $found.Add($n) } }
        if ([IO.File]::Exists([IO.Path]::Combine($pd.Dir, 'lib', 'Math_Symbol.js'))) { $found.Add('lib/Math_Symbol.js') }
        $setupMjs = [IO.Path]::Combine($pd.Dir, 'setup.mjs')
        $hasSetup = [IO.File]::Exists($setupMjs) -or [IO.File]::Exists([IO.Path]::Combine($pd.Dir, 'lib', 'setup.mjs'))
        if ($found.Count -eq 0 -and -not $hasSetup) { continue }
        $scripts = $pd.Scripts
        if ($null -eq $scripts) { $info = Read-PkgJson $pd.Dir; $scripts = if ($info) { $info.Scripts } else { [ordered]@{} } }
        $scriptText = (@($scripts.Values) -join ' ; ')
        $runsSetup = $scriptText -match 'setup(_bun)?\.mjs|setup_bun\.js'
        $markers = [System.Collections.Generic.List[string]]::new()
        foreach ($cand in @($setupMjs, [IO.Path]::Combine($pd.Dir, 'setup_bun.js'), [IO.Path]::Combine($pd.Dir, 'lib', 'setup.mjs'))) {
            if ([IO.File]::Exists($cand)) { foreach ($mk in (Test-ContentMarkers (Read-TextHead $cand 262144))) { if (-not $markers.Contains($mk)) { $markers.Add($mk) } } }
        }
        if ($hasSetup) { $found.Add('setup.mjs') }
        $companions = @($found | Where-Object { $_ -in 'bun_environment.js', 'Math_Symbol.js', 'lib/Math_Symbol.js' }).Count -gt 0 -or [IO.File]::Exists([IO.Path]::Combine($pd.Dir, 'execution.js'))
        $strongHit = @($found | Where-Object { $_ -in $strong -or $_ -eq 'lib/Math_Symbol.js' }).Count -gt 0
        if (-not $strongHit -and -not $runsSetup -and $markers.Count -eq 0) { continue }   # a lone setup.mjs is normal
        $sev = 'high'; $cls = 'suspicious'; $conf = 'medium'
        if (($strongHit -and ($runsSetup -or $companions -or $markers.Count -gt 0)) -or ($runsSetup -and $markers.Count -gt 0)) { $sev = 'critical'; $cls = 'compromise'; $conf = 'high' }
        $cap = Get-ExpectedCap -Path $pd.Dir
        if ($cap) { $sev = 'info'; $cls = 'info' }
        $files = @($found | ForEach-Object {
                $fp = [IO.Path]::Combine($pd.Dir, ($_ -replace '/', '\'))
                $t = Get-FileTimes $fp
                $len = try { [IO.FileInfo]::new($fp).Length } catch { $null }
                [ordered]@{ path = $fp; size = $len; sha256 = (Get-BvsHash -Path $fp -MaxBytes 64MB); created = $t.created; modified = $t.modified }
            })
        $title = "Shai-Hulud-family loader in an installed package: $($pd.Name)@$($pd.Version) ($($found -join ', '))"
        New-BvsFinding -Run $run -Check 'ioc.package_files' -Title $title -Severity $sev -Class $cls -Confidence $conf `
            -Reasons @('ioc_file', $(if ($markers.Count) { 'content_marker' }), $(if ($runsSetup) { 'lifecycle_runs_loader' }), $(if ($cap) { 'expected_match' }) | Where-Object { $_ }) `
            -Evidence @([ordered]@{ type = 'package'; ecosystem = 'npm'; name = $pd.Name; version = $pd.Version; source = $pd.Kind; path = $pd.Dir },
                [ordered]@{ type = 'files'; found = @($found); lifecycle = (Limit-Text $scriptText 300); markers = @($markers) }) `
            -Entities @{ files = $files; processes = @(); network = @(); registry = @(); accounts = @() } `
            -FpNotes 'setup.mjs alone is a common file name, so it only counts together with a lifecycle hook that runs it, companion payload files or worm markers. setup_bun.js / bun_environment.js / Math_Symbol.js at a package root have no known legitimate use.' `
            -Recommendation 'Do not run npm in this project. Disable worm persistence first (see host-path findings: gh-token-monitor), then rotate npm/GitHub/cloud tokens from a clean device, delete node_modules and reinstall a clean version with --ignore-scripts. Keep a copy of the files (zipped, password-protected) for analysis. Manual steps only.' `
            -Mitre @('T1195.002', 'T1059.007') -Expected $cap
        $script:IocFileInv.Add([ordered]@{ check = 'ioc.package_files'; path = $pd.Dir; package = "$($pd.Name)@$($pd.Version)"; files = @($found); markers = @($markers); severity = $sev })
    }
    $count
}

function Get-RepoRootCandidates {
    $set = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $script:Discovery.RepoRoots) { [void]$set.Add($r) }
    foreach ($g in $script:Groups) { foreach ($c in $g.Copies) { [void]$set.Add($c.Path) } }
    foreach ($k in $script:Discovery.Files.Keys) { if ($script:Discovery.Files[$k].ContainsKey('package.json')) { [void]$set.Add($k) } }
    [void]$set.Add($script:UserHome)
    @($set | Where-Object { -not (Test-Excluded $_) })
}

function Invoke-RepoFileChecks {
    $roots = Get-RepoRootCandidates
    $wfMarkers = @(foreach ($w in $script:Ioc.workflowMarkers) { [pscustomobject]@{ Id = $w.id; Rx = [regex]::new($w.regex, 'IgnoreCase'); Severity = $w.severity; Note = $w.note } })
    $checked = 0
    foreach ($root in $roots) {
        $checked++
        foreach ($rf in $script:Ioc.repoFiles) {
            $paths = @()
            if ($rf.path) { $paths = @(Join-Path $root ($rf.path -replace '/', '\')) }
            elseif ($rf.glob) {
                $gd = Join-Path $root ([IO.Path]::GetDirectoryName(($rf.glob -replace '/', '\')))
                if ([IO.Directory]::Exists($gd)) { $paths = @([IO.Directory]::GetFiles($gd, [IO.Path]::GetFileName($rf.glob), $script:DirOpts)) }
            }
            foreach ($fpth in $paths) {
                if (-not [IO.File]::Exists($fpth) -or (Test-Excluded $fpth)) { continue }
                $text = Read-TextHead $fpth 524288
                $matched = $false
                if ($rf.contentRegex) { $matched = [bool]($text -and [regex]::IsMatch($text, $rf.contentRegex, 'IgnoreCase')) }
                if ($rf.strength -ne 'strong' -and -not $matched) { continue }
                $markers = Test-ContentMarkers $text
                $sev = 'high'; $cls = 'suspicious'; $conf = 'medium'
                if ($matched -or $markers.Count -gt 0 -or ($rf.strength -eq 'strong' -and $rf.id -like 'sh1-*')) { $sev = 'critical'; $cls = 'compromise'; $conf = 'high' }
                $cap = Get-ExpectedCap -Path $fpth
                if ($cap) { $sev = 'info'; $cls = 'info' }
                $camp = $script:IocCampaigns[$rf.campaign]
                $t = Get-FileTimes $fpth
                $snippet = $null
                if ($text -and $rf.contentRegex) { $mm = [regex]::Match($text, $rf.contentRegex, 'IgnoreCase'); if ($mm.Success) { $snippet = Limit-Text $mm.Value 240 } }
                New-BvsFinding -Run $run -Check 'ioc.repo_files' -Title "Worm repo artifact ($($camp.title.Split(':')[0])): $fpth" -Severity $sev -Class $cls -Confidence $conf `
                    -Reasons @('ioc_file', $(if ($matched) { 'content_match' }), $(if ($markers.Count) { 'content_marker' }), $(if ($cap) { 'expected_match' }) | Where-Object { $_ }) `
                    -Evidence @([ordered]@{ type = 'file'; path = $fpth; indicator = $rf.id; campaign = $rf.campaign; matched = $snippet; markers = @($markers); created = $t.created; modified = $t.modified; note = $rf.note }) `
                    -Entities @{ files = @([ordered]@{ path = $fpth; sha256 = (Get-BvsHash -Path $fpth -MaxBytes 64MB); created = $t.created; modified = $t.modified }); processes = @(); network = @(); registry = @(); accounts = @() } `
                    -FpNotes 'Matched by exact path and, where the name alone is ambiguous, by content. Legitimate .claude/settings.json, .vscode/tasks.json or format-check workflows only match when they run the worm loader (setup.mjs, math_init.js, router_runtime.js) or dump toJSON(secrets).' `
                    -Recommendation 'Do not open this folder in Claude Code, VS Code or Cursor (the hook/task runs on open) and do not push it. Check git log for the commit that added the file (often authored as claude@users.noreply.github.com or dependabot) and whether it reached GitHub; then follow the incident steps (disable gh-token-monitor first, rotate tokens from a clean device). Manual steps only.' `
                    -Mitre @('T1195.002', 'T1546') -Expected $cap
                $script:IocFileInv.Add([ordered]@{ check = 'ioc.repo_files'; path = $fpth; indicator = $rf.id; severity = $sev })
            }
        }
        $wf = Join-Path $root '.github\workflows'
        if (-not [IO.Directory]::Exists($wf)) { continue }
        foreach ($wfile in @([IO.Directory]::GetFiles($wf, '*.y*ml', $script:DirOpts))) {
            if (Test-Excluded $wfile) { continue }
            $leaf = [IO.Path]::GetFileName($wfile)
            if (@($script:IocFileInv | Where-Object { $_.path -eq $wfile }).Count) { continue }
            $text = Read-TextHead $wfile 524288
            if (-not $text) { continue }
            $hits = @($wfMarkers | Where-Object { $_.Rx.IsMatch($text) })
            if ($hits.Count -eq 0) { continue }
            $worst = if (@($hits | Where-Object { $_.Severity -eq 'critical' }).Count) { 'critical' } else { 'high' }
            $onlyStrings = @($hits | Where-Object { $_.Id -ne 'sha1hulud-runner' }).Count -eq 0
            $cap = if ($onlyStrings) { Get-ExpectedCap -Path $wfile -StringMarker } else { Get-ExpectedCap -Path $wfile }
            $sev = $worst; $cls = if ($worst -eq 'critical') { 'compromise' } else { 'suspicious' }
            if ($cap) { $sev = 'info'; $cls = 'info' }
            $t = Get-FileTimes $wfile
            New-BvsFinding -Run $run -Check 'ioc.repo_files' -Title "Suspicious GitHub workflow ($(@($hits.Id) -join ', ')): $wfile" -Severity $sev -Class $cls -Confidence 'medium' `
                -Reasons @('workflow_marker', $(if ($cap) { 'expected_match' }) | Where-Object { $_ }) `
                -Evidence @([ordered]@{ type = 'file'; path = $wfile; markers = @($hits | ForEach-Object { [ordered]@{ id = $_.Id; note = $_.Note } }); created = $t.created; modified = $t.modified }) `
                -FpNotes 'toJSON(secrets) is occasionally used in debugging workflows; worm workflows combine it with an artifact upload, webhook or self-hosted runner. Security-tool repositories can contain the strings by design.' `
                -Recommendation 'Read the workflow and its git history (who added it, when). If it was not written by you, disable Actions for the repository on GitHub, rotate every repository/organisation secret, and remove unknown self-hosted runners. Manual steps only.' `
                -Mitre @('T1195.002', 'T1552') -Expected $cap
            $script:IocFileInv.Add([ordered]@{ check = 'ioc.repo_files'; path = $wfile; indicator = @($hits.Id) -join ','; severity = $sev })
        }
    }
    $checked
}

function Invoke-HostPathChecks {
    $hits = 0
    foreach ($hp in $script:Ioc.hostPaths) {
        $cands = @()
        if ($hp.path) { $cands = @([Environment]::ExpandEnvironmentVariables([string]$hp.path)) }
        elseif ($hp.glob) {
            $gx = [Environment]::ExpandEnvironmentVariables([string]$hp.glob)
            $gd = [IO.Path]::GetDirectoryName($gx)
            if ([IO.Directory]::Exists($gd)) { $cands = @([IO.Directory]::GetFileSystemEntries($gd, [IO.Path]::GetFileName($gx), $script:DirOpts)) }
        }
        foreach ($c in $cands) {
            $isDir = [IO.Directory]::Exists($c)
            if (-not $isDir -and -not [IO.File]::Exists($c)) { continue }
            $detail = $null; $sev = 'critical'; $cls = 'compromise'; $conf = 'high'
            if ($hp.strength -eq 'needs-context') {
                $runner = @('config.sh', 'config.cmd', 'run.cmd', 'run.sh', '.runner', 'bin\Runner.Listener.exe') | Where-Object { Test-Path -LiteralPath (Join-Path $c $_) }
                if (-not $runner) { continue }
                $detail = "runner files: $($runner -join ', ')"; $sev = 'high'; $cls = 'suspicious'; $conf = 'medium'
            }
            elseif ($hp.strength -eq 'medium') { $sev = 'medium'; $cls = 'suspicious'; $conf = 'low' }
            $hits++
            $t = Get-FileTimes $c
            $camp = $script:IocCampaigns[$hp.campaign]
            New-BvsFinding -Run $run -Check 'ioc.host_paths' -Title "Supply-chain worm persistence/staging path present: $c" -Severity $sev -Class $cls -Confidence $conf `
                -Reasons @('ioc_path', 'persistence') `
                -Evidence @([ordered]@{ type = $(if ($isDir) { 'directory' } else { 'file' }); path = $c; indicator = $hp.id; campaign = $hp.campaign; campaignTitle = $camp.title; detail = $detail; created = $t.created; modified = $t.modified; warning = $hp.warning }) `
                -FpNotes 'Exact paths published for the Shai-Hulud family (gh-token-monitor, sysmon.py, .dev-env runner). A folder with the same name created by another tool is possible but unusual: check its contents and creation time.' `
                -Recommendation $(if ($hp.warning) { "$($hp.warning) Then look for the matching logon task (Task Scheduler, action monitor.ps1), stop it manually, and only then rotate GitHub/npm tokens from a clean device. Manual steps only." } else { 'Inspect the contents and creation time, find the installing package (npm cache / npx history around that time), then follow the incident steps. Manual steps only.' }) `
                -Mitre @('T1195.002', 'T1053.005')
            $script:IocFileInv.Add([ordered]@{ check = 'ioc.host_paths'; path = $c; indicator = $hp.id; severity = $sev })
        }
    }
    try {
        $markerRx = @(foreach ($m in $script:Ioc.scheduledTaskMarkers) { [pscustomobject]@{ Id = $m.id; Rx = [regex]::new($m.regex, 'IgnoreCase'); Campaign = $m.campaign } })
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            foreach ($a in @($task.Actions)) {
                $line = "$($a.Execute) $($a.Arguments)"
                foreach ($m in $markerRx) {
                    if (-not $m.Rx.IsMatch($line)) { continue }
                    $hits++
                    New-BvsFinding -Run $run -Check 'ioc.host_paths' -Title "Scheduled task matches worm watcher pattern: $($task.TaskPath)$($task.TaskName)" -Severity 'critical' -Class 'compromise' -Confidence 'medium' `
                        -Reasons @('ioc_task', 'persistence') -Evidence @([ordered]@{ type = 'task'; path = "$($task.TaskPath)$($task.TaskName)"; action = (Limit-Text $line 300); indicator = $m.Id; campaign = $m.Campaign }) `
                        -FpNotes 'Matched on the action command line (gh-token-monitor / monitor.ps1). A different script named monitor.ps1 is possible: read it before acting.' `
                        -Recommendation 'Disable (do not delete) the task manually, keep the script for analysis, then rotate GitHub/npm tokens from a clean device. Revoking tokens while the watcher runs can trigger its destructive cleanup. Manual steps only.' -Mitre @('T1053.005')
                }
            }
        }
    }
    catch { Write-BvsLog -Run $run -Level WARN -Message "scheduled task enumeration failed: $($_.Exception.Message)" }
    foreach ($s in $script:Discovery.Staging) {
        $hits++
        $cap = Get-ExpectedCap -Path $s
        $t = Get-FileTimes $s
        New-BvsFinding -Run $run -Check 'ioc.host_paths' -Title "Shai-Hulud 2.0 secret-staging file name found: $s" -Severity $(if ($cap) { 'info' } else { 'high' }) -Class $(if ($cap) { 'info' } else { 'suspicious' }) -Confidence 'medium' `
            -Reasons @('ioc_file') -Evidence @([ordered]@{ type = 'file'; path = $s; created = $t.created; modified = $t.modified; note = 'name only; content not read' }) `
            -FpNotes 'truffleSecrets.json / actionsSecrets.json are the file names Shai-Hulud 2.0 writes before exfiltration. A security tool or a TruffleHog user can create similar names.' `
            -Recommendation 'Check the creation time against npm installs in that folder; if it is not yours, treat every secret it lists as exposed. Manual steps only.' -Mitre @('T1552.001') -Expected $cap
    }
    $hits
}

#endregion

#region ---------- lifecycle scripts ----------

function Measure-LifecycleScript([string]$Value, [string]$PkgDir) {
    $hits = [System.Collections.Generic.List[string]]::new()
    $score = 0
    foreach ($p in $script:LcPatterns) { if ($p.Rx.IsMatch($Value)) { $hits.Add($p.Id); $score += $p.Weight } }
    $benign = $false
    $trim = $Value.Trim()
    foreach ($b in $script:LcBenign) { if ($b.IsMatch($trim)) { $benign = $true; break } }
    if ($trim -match '^\s*(?:node|bun)(?:\.exe)?\s+(?:--?[\w-]+\s+)*["'']?([^\s"''|&;]+\.(?:c?js|mjs))') {
        $target = [IO.Path]::GetFullPath([IO.Path]::Combine($PkgDir, ($Matches[1] -replace '/', '\')))
        if ((Test-Under $target $PkgDir) -and [IO.File]::Exists($target)) {
            $len = [IO.FileInfo]::new($target).Length
            if ($len -gt [long]$script:Ioc.lifecycle.oversizedScriptBytes) { $hits.Add("oversized-target:$len"); $score += 3 }
            $head = Read-TextHead $target 131072
            if ($head) {
                $obf = ([regex]::Matches($head, '_0x[0-9a-f]{4,6}')).Count
                if ($obf -ge 25 -or $head.Contains('eval(function(s,n){return s.replace(')) { $hits.Add('obfuscated-target'); $score += 3 }
                foreach ($mk in (Test-ContentMarkers $head)) { $hits.Add("marker:$mk"); $score += 6 }
            }
        }
    }
    if ($benign -and $score -lt 4) { $score = 0 }
    [pscustomobject]@{ Score = $score; Hits = $hits; Benign = $benign }
}

function Invoke-LifecycleAnalysis {
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $groups = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($sp in $script:ScriptPkgs) {
        if (-not $seen.Add($sp.Dir)) { continue }
        $scripts = $sp.Scripts
        $name = $sp.Name; $ver = $sp.Version
        if ($null -eq $scripts) {
            $info = Read-PkgJson $sp.Dir
            if (-not $info) { $script:LifecycleStats.unreadable++; continue }
            $scripts = $info.Scripts
            if ($info.Name) { $name = $info.Name }
            if ($info.Version) { $ver = $info.Version }
        }
        $gyp = Join-Path $sp.Dir 'binding.gyp'
        $hasGyp = [IO.File]::Exists($gyp)
        if ($scripts.Count -eq 0 -and -not $hasGyp) { continue }
        $script:LifecycleStats.packagesWithScripts++
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($sn in @($scripts.Keys)) { $items.Add(@($sn, [string]$scripts[$sn])) }
        if ($hasGyp) {
            $script:LifecycleStats.bindingGyp++
            $gt = Read-TextHead $gyp 65536
            if ($gt -and ($gt -match '<!\(\s*node\s+(index|setup|install)\.c?js' -or $gt.Contains('echo stub.c') -or ($gt -match '"target_name"\s*:\s*"Setup"' -and $gt -match '"type"\s*:\s*"none"'))) {
                $items.Add(@('binding.gyp', ('command expansion: ' + (Limit-Text (([regex]::Match($gt, '<!\([^)]*\)')).Value) 160))))
            }
        }
        foreach ($it in $items) {
            $sn = [string]$it[0]; $val = [string]$it[1]
            $script:LifecycleStats.scriptsAnalysed++
            $m = if ($sn -eq 'binding.gyp') { [pscustomobject]@{ Score = 8; Hits = [System.Collections.Generic.List[string]]@('binding-gyp-command-expansion'); Benign = $false } } else { Measure-LifecycleScript $val $sp.Dir }
            if ($m.Benign -and $m.Score -eq 0) { $script:LifecycleStats.benign++ }
            if ($m.Score -lt 2) { continue }
            $sig = "$name@$ver|$sn|$val"
            $g = $null
            if (-not $groups.TryGetValue($sig, [ref]$g)) {
                $g = [pscustomobject]@{ Name = $name; Version = $ver; Script = $sn; Value = $val; Score = $m.Score; Hits = $m.Hits; Dirs = [System.Collections.Generic.List[string]]::new(); Kinds = [System.Collections.Generic.HashSet[string]]::new() }
                $groups[$sig] = $g
            }
            if ($g.Dirs.Count -lt 15) { $g.Dirs.Add($sp.Dir) }
            [void]$g.Kinds.Add($sp.Kind)
        }
    }
    foreach ($g in $groups.Values) {
        $script:LifecycleStats.flagged++
        $iocHit = @($g.Hits | Where-Object { $_ -eq 'ioc-script' -or $_ -like 'marker:*' -or $_ -eq 'binding-gyp-command-expansion' }).Count -gt 0
        $sev = if ($g.Score -ge 5) { 'high' } else { 'medium' }
        $cls = 'suspicious'
        $caps = @(foreach ($d in $g.Dirs) { Get-ExpectedCap -Path $d })
        $cap = if ($caps.Count -eq $g.Dirs.Count -and $caps.Count -gt 0) { $caps[0] } else { $null }
        if ($cap) { $sev = 'info'; $cls = 'info' }
        $reasons = [System.Collections.Generic.List[string]]::new()
        $reasons.Add('lifecycle_script')
        if ($g.Hits -contains 'long-blob' -or $g.Hits -contains 'hex-escapes' -or $g.Hits -contains 'obfuscated-target') { $reasons.Add('obfuscation') }
        if ($g.Hits -contains 'encoded-command') { $reasons.Add('encoded_command') }
        if ($g.Hits -contains 'lolbin') { $reasons.Add('lolbin') }
        if ($iocHit) { $reasons.Add('ioc_match') }
        if ($cap) { $reasons.Add('expected_match') }
        $inv = [ordered]@{ name = $g.Name; version = $g.Version; script = $g.Script; value = (Limit-Text $g.Value 300); score = $g.Score; patterns = @($g.Hits); kinds = @($g.Kinds); locations = @($g.Dirs); severity = $sev }
        $script:LifecycleInv.Add($inv)
        New-BvsFinding -Run $run -Check 'npm.lifecycle' -Title "Suspicious npm $($g.Script) in $($g.Name)@$($g.Version): $(@($g.Hits | Select-Object -First 4) -join ', ')" -Severity $sev -Class $cls -Confidence $(if ($iocHit) { 'high' } else { 'medium' }) `
            -Reasons @($reasons) `
            -Evidence @([ordered]@{ type = 'lifecycle'; package = "$($g.Name)@$($g.Version)"; script = $g.Script; value = (Limit-Text $g.Value 300); score = $g.Score; patterns = @($g.Hits); installedAt = @($g.Dirs | Select-Object -First 8); sources = @($g.Kinds) }) `
            -FpNotes 'Install scripts legitimately download native binaries (often with curl/node fetch) or run small node -e snippets. Known build steps (node-gyp rebuild, prebuild-install, husky, node install.js) are not flagged. Read the script and the file it runs before deciding.' `
            -Recommendation 'Read the script and the file it runs. If it fetches or decodes code from the network, find who published that version (npm view is not allowed here: check the registry page), and consider npm config set ignore-scripts true with an allow-list (pnpm onlyBuiltDependencies). Manual steps only.' `
            -Mitre @('T1195.002', 'T1059') -Expected $cap
    }
    $script:LifecycleStats.packagesWithScripts
}

#endregion

#region ---------- python .pth and site-packages IoCs ----------

function Invoke-PthChecks {
    $n = 0
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sp in $script:SitePackages) {
        if (-not $seen.Add($sp.Path)) { continue }
        foreach ($sf in $script:Ioc.sitePackagesFiles) {
            $fpth = Join-Path $sp.Path ($sf.file -replace '/', '\')
            if (-not [IO.File]::Exists($fpth)) { continue }
            $t = Get-FileTimes $fpth
            New-BvsFinding -Run $run -Check 'python.pth' -Title "PyPI worm artifact in site-packages: $fpth" -Severity 'critical' -Class 'compromise' -Confidence 'high' `
                -Reasons @('ioc_file', 'persistence') -Evidence @([ordered]@{ type = 'file'; path = $fpth; indicator = $sf.id; campaign = $sf.campaign; created = $t.created; modified = $t.modified }) `
                -Entities @{ files = @([ordered]@{ path = $fpth; sha256 = (Get-BvsHash -Path $fpth); created = $t.created; modified = $t.modified }); processes = @(); network = @(); registry = @(); accounts = @() } `
                -FpNotes 'Exact file published for the litellm 1.82.8 / lightning 2.6.2-2.6.3 compromises; no legitimate package ships it.' `
                -Recommendation 'Stop using this Python environment, rotate cloud/GitHub/npm/AI tokens from a clean device, check ~/.config/sysmon and scheduled tasks, then rebuild the environment from a clean lockfile. Manual steps only.' -Mitre @('T1195.002', 'T1546')
        }
        try { $pths = [IO.Directory]::GetFiles($sp.Path, '*.pth', $script:DirOpts) } catch { continue }
        foreach ($pth in $pths) {
            $n++
            $leaf = [IO.Path]::GetFileName($pth)
            $text = Read-TextFile $pth 2MB
            if (-not $text) { continue }
            $execLines = @($text -split "`r?`n" | Where-Object { $_ -match '^\s*import[\s;]' })
            if ($execLines.Count -eq 0) { continue }
            $bad = @($execLines | Where-Object { $script:PthSuspiciousRx.IsMatch($_) })
            if ($bad.Count -eq 0) { continue }
            $knownName = @($script:PthBenign | Where-Object { $leaf.Contains([string]$_) }).Count -gt 0
            $strong = @($bad | Where-Object { $_ -match '(?i)exec\(' -and $_ -match '(?i)base64|b64decode|zlib|marshal|urlopen|requests\.' }).Count -gt 0
            if ($knownName -and -not $strong) { continue }
            $sev = if ($strong) { 'high' } else { 'medium' }
            $t = Get-FileTimes $pth
            New-BvsFinding -Run $run -Check 'python.pth' -Title "Python startup hook (.pth) runs suspicious code: $pth" -Severity $sev -Class 'suspicious' -Confidence 'medium' `
                -Reasons @('persistence', $(if ($strong) { 'obfuscation' }) | Where-Object { $_ }) `
                -Evidence @([ordered]@{ type = 'file'; path = $pth; lines = @($bad | Select-Object -First 3 | ForEach-Object { Limit-Text $_ 240 }); created = $t.created; modified = $t.modified; environment = $sp.Root }) `
                -FpNotes '.pth lines that start with "import" run at every interpreter start. Editable installs, namespace packages, setuptools and virtualenv use them legitimately; network, exec+base64 or subprocess calls there are not normal.' `
                -Recommendation 'Read the .pth file and find which package installed it (RECORD files in *.dist-info list it). If it is not explained, rebuild the environment and rotate secrets used from it. Manual steps only.' -Mitre @('T1546')
        }
    }
    $n
}

#endregion

#region ---------- registry overrides ----------

function Add-RegistryRecord {
    param([string]$File, [string]$Scope, [string]$Tool, [string]$Key, [string]$Value, [string]$Risk = $null, [string]$Note = $null)
    $script:RegistryInv.Add([pscustomobject]@{ file = $File; scope = $Scope; tool = $Tool; key = $Key; value = $(if ($Value) { Get-MaskedUrl $Value } else { $null }); host = $(if ($Value) { Get-UrlHost $Value } else { $null }); risk = $Risk; note = $Note })
}

function Test-DefaultNpmRegistry([string]$Url) {
    $u = $Url.Trim().Trim('"', "'").TrimEnd('/').ToLowerInvariant()
    $u -in 'https://registry.npmjs.org', 'https://registry.npmjs.com', 'https://registry.yarnpkg.com'
}

function Read-NpmrcFile([string]$Path, [string]$Scope) {
    $text = Read-TextFile $Path 2MB
    if ($null -eq $text) { return }
    foreach ($raw in ($text -split "`r?`n")) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith(';') -or $line.StartsWith('#')) { continue }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $line.Substring(0, $eq).Trim()
        $v = $line.Substring($eq + 1).Trim().Trim('"', "'")
        if ($k -match '^//([^/:]+)[^:]*:(_authToken|_auth|_password|password|username|certfile|keyfile)$') {
            $isRef = $v.StartsWith('${')
            $kind = $Matches[2]
            if ($kind -in '_authToken', '_auth', '_password', 'password') {
                Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key "//$($Matches[1])/:$kind" -Value $null -Risk $(if ($isRef) { 'none' } else { 'plaintext-credential' }) -Note $(if ($isRef) { 'credential taken from an environment variable' } else { "plaintext credential for $($Matches[1]) (value never read into output)" })
            }
            continue
        }
        if ($k -in '_authToken', '_auth', '_password') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $null -Risk 'plaintext-credential' -Note 'legacy global credential (value never read into output)'; continue }
        if ($k -eq 'registry') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $v -Risk $(if (Test-DefaultNpmRegistry $v) { 'none' } elseif ($v -match '^http://') { 'insecure-registry' } else { 'non-default-registry' }); continue }
        if ($k -match '^(@[^:]+):registry$') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $v -Risk $(if ($v -match '^http://') { 'insecure-registry' } else { 'scope-registry' }); continue }
        if ($k -eq 'strict-ssl' -and $v -match '^(false|0)$') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $null -Risk 'tls-verification-off' -Note 'strict-ssl=false'; continue }
        if ($k -in 'ca', 'cafile') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $null -Risk 'custom-ca' -Note 'custom CA configured (value not shown)'; continue }
        if ($k -eq 'ignore-scripts') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $null -Risk 'none' -Note "ignore-scripts=$v (protective when true)"; continue }
        if ($k -in 'node-options', 'script-shell') { Add-RegistryRecord -File $Path -Scope $Scope -Tool 'npm' -Key $k -Value $null -Risk $(if ($v -match '(^|\s)(--require|-r|--import|--loader)\b') { 'code-injection' } else { 'review' }) -Note (Limit-Text "$k=$v" 200); continue }
    }
}

function Read-IniIndexFile([string]$Path, [string]$Scope, [string]$Tool) {
    $text = Read-TextFile $Path 2MB
    if ($null -eq $text) { return }
    $lastKey = $null
    foreach ($raw in ($text -split "`r?`n")) {
        if ($raw -match '^\s*[#;]') { continue }
        if ($raw -match '^\s*([A-Za-z_-]+)\s*[=:]\s*(.*)$') {
            $k = $Matches[1].ToLowerInvariant(); $v = $Matches[2].Trim()
            $lastKey = $k
            if ($k -eq 'password') { Add-RegistryRecord -File $Path -Scope $Scope -Tool $Tool -Key $k -Value $null -Risk 'plaintext-credential' -Note 'password stored in plain text (value never read into output)'; continue }
            if ($k -in 'index-url', 'index_url', 'extra-index-url', 'extra_index_url', 'trusted-host', 'trusted_host', 'find-links', 'repository', 'allow-insecure-host', 'url') {
                foreach ($val in @($v -split '\s+' | Where-Object { $_ })) { Add-PyIndexRecord -File $Path -Scope $Scope -Tool $Tool -Key $k -Value $val }
            }
            continue
        }
        if ($raw -match '^\s+(\S+)\s*$' -and $lastKey -in 'extra-index-url', 'extra_index_url', 'trusted-host', 'find-links') { Add-PyIndexRecord -File $Path -Scope $Scope -Tool $Tool -Key $lastKey -Value $Matches[1] }
        elseif ($raw -match '^\s*\[') { $lastKey = $null }
    }
}

function Add-PyIndexRecord([string]$File, [string]$Scope, [string]$Tool, [string]$Key, [string]$Value) {
    $k = $Key.Replace('_', '-')
    $risk = switch ($k) {
        'index-url' { if (Test-DefaultPyIndex $Value) { 'none' } elseif ($Value -match '^http://') { 'insecure-index' } else { 'non-default-index' } }
        'extra-index-url' { 'extra-index-dependency-confusion' }
        'trusted-host' { 'tls-verification-off' }
        'allow-insecure-host' { 'tls-verification-off' }
        'find-links' { 'extra-package-source' }
        'repository' { 'upload-target' }
        default { if (Test-DefaultPyIndex $Value) { 'none' } else { 'non-default-index' } }
    }
    Add-RegistryRecord -File $File -Scope $Scope -Tool $Tool -Key $k -Value $Value -Risk $risk
}

function Invoke-RegistryChecks {
    $files = [System.Collections.Generic.List[object]]::new()
    $userRc = Join-Path $script:UserHome '.npmrc'
    if ([IO.File]::Exists($userRc)) { $files.Add(@($userRc, 'user', 'npmrc')) }
    foreach ($gr in (Get-NodeGlobalRoots)) {
        foreach ($c in @((Join-Path $gr.Prefix 'etc\npmrc'), (Join-Path $gr.NodeModules 'npm\npmrc'))) { if ([IO.File]::Exists($c)) { $files.Add(@($c, 'global', 'npmrc')) } }
    }
    foreach ($kv in $script:Discovery.Files.GetEnumerator()) {
        foreach ($n in $kv.Value.Keys) {
            $fp = $kv.Value[$n]
            if ($fp -eq $userRc) { continue }
            switch ($n.ToLowerInvariant()) {
                '.npmrc' { $files.Add(@($fp, 'project', 'npmrc')) }
                '.yarnrc' { $files.Add(@($fp, 'project', 'yarnrc')) }
                '.yarnrc.yml' { $files.Add(@($fp, 'project', 'yarnrc.yml')) }
                'bunfig.toml' { $files.Add(@($fp, 'project', 'bunfig')) }
                'pip.ini' { $files.Add(@($fp, 'project', 'pip')) }
                'pip.conf' { $files.Add(@($fp, 'project', 'pip')) }
                'uv.toml' { $files.Add(@($fp, 'project', 'uv')) }
                '.pypirc' { $files.Add(@($fp, 'user', 'pypirc')) }
                'pyproject.toml' { $files.Add(@($fp, 'project', 'pyproject')) }
                'pipfile' { $files.Add(@($fp, 'project', 'pipfile')) }
            }
        }
    }
    foreach ($c in @(
            @((Join-Path $env:APPDATA 'pip\pip.ini'), 'user', 'pip'), @((Join-Path $script:UserHome 'pip\pip.ini'), 'user', 'pip'),
            @((Join-Path $script:UserHome '.config\pip\pip.conf'), 'user', 'pip'), @((Join-Path $script:UserHome '.pip\pip.conf'), 'user', 'pip'),
            @((Join-Path $env:ProgramData 'pip\pip.ini'), 'global', 'pip'), @((Join-Path $env:APPDATA 'uv\uv.toml'), 'user', 'uv'),
            @((Join-Path $env:ProgramData 'uv\uv.toml'), 'global', 'uv'), @((Join-Path $script:UserHome '.config\uv\uv.toml'), 'user', 'uv'),
            @((Join-Path $script:UserHome '.pypirc'), 'user', 'pypirc'), @((Join-Path $script:UserHome '.yarnrc'), 'user', 'yarnrc'),
            @((Join-Path $script:UserHome '.yarnrc.yml'), 'user', 'yarnrc.yml'), @((Join-Path $script:UserHome '.bunfig.toml'), 'user', 'bunfig'))) {
        if ([IO.File]::Exists($c[0]) -and -not (@($files | Where-Object { $_[0] -eq $c[0] }).Count)) { $files.Add($c) }
    }
    foreach ($v in @($script:Discovery.Venvs)) { foreach ($n in 'pip.ini', 'pip.conf') { $c = Join-Path $v $n; if ([IO.File]::Exists($c)) { $files.Add(@($c, 'venv', 'pip')) } } }
    if ($env:PIP_CONFIG_FILE -and [IO.File]::Exists($env:PIP_CONFIG_FILE)) { $files.Add(@($env:PIP_CONFIG_FILE, 'env', 'pip')) }

    foreach ($f in $files) {
        $p = [string]$f[0]; $scope = [string]$f[1]; $kind = [string]$f[2]
        if (Test-Excluded $p) { continue }
        switch ($kind) {
            'npmrc' { Read-NpmrcFile $p $scope }
            'yarnrc' {
                $t = Read-TextFile $p 1MB
                if ($t) {
                    foreach ($m in [regex]::Matches($t, '(?m)^\s*"?(registry|@[^:"\s]+:registry)"?\s+"?([^"\s]+)"?')) { $val = $m.Groups[2].Value; Add-RegistryRecord -File $p -Scope $scope -Tool 'yarn1' -Key $m.Groups[1].Value -Value $val -Risk $(if ($m.Groups[1].Value -ne 'registry') { 'scope-registry' } elseif (Test-DefaultNpmRegistry $val) { 'none' } else { 'non-default-registry' }) }
                    if ($t -match '(?m)^\s*strict-ssl\s+false') { Add-RegistryRecord -File $p -Scope $scope -Tool 'yarn1' -Key 'strict-ssl' -Value $null -Risk 'tls-verification-off' }
                }
            }
            'yarnrc.yml' {
                $t = Read-TextFile $p 1MB
                if ($t) {
                    foreach ($m in [regex]::Matches($t, '(?m)^\s*npmRegistryServer:\s*"?([^"\s]+)"?')) { $val = $m.Groups[1].Value; Add-RegistryRecord -File $p -Scope $scope -Tool 'yarn' -Key 'npmRegistryServer' -Value $val -Risk $(if (Test-DefaultNpmRegistry $val) { 'none' } else { 'non-default-registry' }) }
                    if ($t -match '(?m)^\s*enableStrictSsl:\s*false') { Add-RegistryRecord -File $p -Scope $scope -Tool 'yarn' -Key 'enableStrictSsl' -Value $null -Risk 'tls-verification-off' }
                    if ($t -match '(?m)^\s*npmAuthToken:\s*(.+)$') { $isRef = $Matches[1].Trim().Trim('"').StartsWith('${'); Add-RegistryRecord -File $p -Scope $scope -Tool 'yarn' -Key 'npmAuthToken' -Value $null -Risk $(if ($isRef) { 'none' } else { 'plaintext-credential' }) -Note 'value never read into output' }
                }
            }
            'bunfig' {
                $t = Read-TextFile $p 1MB
                if ($t -and $t -match '(?m)^\s*registry\s*=\s*"([^"]+)"') { $val = $Matches[1]; Add-RegistryRecord -File $p -Scope $scope -Tool 'bun' -Key 'registry' -Value $val -Risk $(if (Test-DefaultNpmRegistry $val) { 'none' } else { 'non-default-registry' }) }
            }
            'pip' { Read-IniIndexFile $p $scope 'pip' }
            'uv' {
                $t = Read-TextFile $p 1MB
                if ($t) {
                    foreach ($m in [regex]::Matches($t, '(?m)^\s*(index-url|extra-index-url|default-index)\s*=\s*"([^"]+)"')) { Add-PyIndexRecord -File $p -Scope $scope -Tool 'uv' -Key $(if ($m.Groups[1].Value -eq 'default-index') { 'index-url' } else { $m.Groups[1].Value }) -Value $m.Groups[2].Value }
                    foreach ($m in [regex]::Matches($t, '(?ms)^\s*\[\[index\]\].*?^\s*url\s*=\s*"([^"]+)"')) { Add-PyIndexRecord -File $p -Scope $scope -Tool 'uv' -Key 'index' -Value $m.Groups[1].Value }
                    if ($t -match '(?m)^\s*allow-insecure-host\s*=') { Add-RegistryRecord -File $p -Scope $scope -Tool 'uv' -Key 'allow-insecure-host' -Value $null -Risk 'tls-verification-off' }
                }
            }
            'pypirc' { Read-IniIndexFile $p $scope 'pypirc' }
            'pyproject' {
                $t = Read-TextFile $p 2MB
                if ($t) {
                    foreach ($m in [regex]::Matches($t, '(?ms)^\s*\[\[tool\.(uv\.index|poetry\.source|pdm\.source)\]\](.*?)(?=^\s*\[|\z)')) {
                        if ($m.Groups[2].Value -match '(?m)^\s*url\s*=\s*"([^"]+)"') { $u = $Matches[1]; if (-not (Test-DefaultPyIndex $u)) { Add-PyIndexRecord -File $p -Scope $scope -Tool $m.Groups[1].Value -Key 'index' -Value $u } }
                    }
                    foreach ($m in [regex]::Matches($t, '(?m)^\s*(index-url|extra-index-url)\s*=\s*"([^"]+)"')) { Add-PyIndexRecord -File $p -Scope $scope -Tool 'pyproject' -Key $m.Groups[1].Value -Value $m.Groups[2].Value }
                }
            }
            'pipfile' {
                $t = Read-TextFile $p 1MB
                if ($t) { foreach ($m in [regex]::Matches($t, '(?ms)^\s*\[\[source\]\](.*?)(?=^\s*\[|\z)')) { if ($m.Groups[1].Value -match '(?m)^\s*url\s*=\s*"([^"]+)"') { $u = $Matches[1]; if (-not (Test-DefaultPyIndex $u)) { Add-PyIndexRecord -File $p -Scope $scope -Tool 'pipfile' -Key 'index' -Value $u } } } }
            }
        }
    }
    # Environment variables (process + user + machine). Values are URLs or flags; tokens are never printed.
    $envNames = @('NPM_CONFIG_REGISTRY', 'npm_config_registry', 'YARN_NPM_REGISTRY_SERVER', 'YARN_REGISTRY', 'BUN_CONFIG_REGISTRY', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_TRUSTED_HOST', 'PIP_FIND_LINKS', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_DEFAULT_INDEX', 'UV_INDEX', 'UV_INSECURE_HOST', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NPM_CONFIG_STRICT_SSL', 'npm_config_strict_ssl', 'NODE_OPTIONS', 'NPM_TOKEN', 'NODE_AUTH_TOKEN')
    foreach ($target in 'Process', 'User', 'Machine') {
        foreach ($n in $envNames) {
            $v = [Environment]::GetEnvironmentVariable($n, $target)
            if (-not $v) { continue }
            if (@($script:RegistryInv | Where-Object { $_.file -eq "env:$n" }).Count) { continue }
            $src = "env:$n"
            switch -regex ($n) {
                '^(NPM_CONFIG_REGISTRY|npm_config_registry|YARN_NPM_REGISTRY_SERVER|YARN_REGISTRY|BUN_CONFIG_REGISTRY)$' { Add-RegistryRecord -File $src -Scope $target -Tool 'npm' -Key 'registry' -Value $v -Risk $(if (Test-DefaultNpmRegistry $v) { 'none' } else { 'non-default-registry' }) }
                '^(PIP_INDEX_URL|UV_INDEX_URL|UV_DEFAULT_INDEX)$' { Add-PyIndexRecord -File $src -Scope $target -Tool 'env' -Key 'index-url' -Value $v }
                '^(PIP_EXTRA_INDEX_URL|UV_EXTRA_INDEX_URL|UV_INDEX)$' { foreach ($x in ($v -split '\s+')) { Add-PyIndexRecord -File $src -Scope $target -Tool 'env' -Key 'extra-index-url' -Value $x } }
                '^(PIP_TRUSTED_HOST|UV_INSECURE_HOST)$' { Add-RegistryRecord -File $src -Scope $target -Tool 'env' -Key 'trusted-host' -Value $null -Risk 'tls-verification-off' -Note $n }
                '^PIP_FIND_LINKS$' { Add-PyIndexRecord -File $src -Scope $target -Tool 'env' -Key 'find-links' -Value $v }
                '^NODE_TLS_REJECT_UNAUTHORIZED$' { if ($v -eq '0') { Add-RegistryRecord -File $src -Scope $target -Tool 'node' -Key $n -Value $null -Risk 'tls-verification-off' -Note "$n=0" } }
                '^(NPM_CONFIG_STRICT_SSL|npm_config_strict_ssl)$' { if ($v -match '^(false|0)$') { Add-RegistryRecord -File $src -Scope $target -Tool 'npm' -Key 'strict-ssl' -Value $null -Risk 'tls-verification-off' } }
                '^NODE_OPTIONS$' { Add-RegistryRecord -File $src -Scope $target -Tool 'node' -Key $n -Value $null -Risk $(if ($v -match '(^|\s)(--require|-r|--import|--loader)\b') { 'code-injection' } else { 'review' }) -Note (Limit-Text "NODE_OPTIONS=$v" 200) }
                '^(NPM_TOKEN|NODE_AUTH_TOKEN)$' { Add-RegistryRecord -File $src -Scope $target -Tool 'npm' -Key $n -Value $null -Risk 'credential-in-environment' -Note "$n is set in the $target environment (value never read into output)" }
            }
        }
    }
    Add-RegistryFindings
    $files.Count
}

function Add-RegistryFindings {
    $inv = @($script:RegistryInv)
    $byRisk = $inv | Group-Object risk
    foreach ($grp in $byRisk) {
        $risk = $grp.Name
        if ($risk -in 'none', 'scope-registry', 'upload-target', 'review', '') { continue }
        $items = @($grp.Group)
        $userLevel = @($items | Where-Object { $_.scope -in 'user', 'global', 'Process', 'User', 'Machine', 'env' })
        $projLevel = @($items | Where-Object { $_.scope -in 'project', 'venv' })
        $cap = $null
        if ($userLevel.Count -eq 0 -and $projLevel.Count -gt 0) {
            $caps = @(foreach ($i in $projLevel) { Get-ExpectedCap -Path $i.file })
            if ($caps.Count -eq $projLevel.Count) { $cap = $caps[0] }
        }
        $sev = 'medium'; $cls = 'hardening'
        $title = $null; $fp = $null; $rec = $null; $reasons = @('registry_config')
        switch ($risk) {
            'plaintext-credential' {
                $hosts = @($items | ForEach-Object { if ($_.key -match '^//([^/]+)/') { $Matches[1] } else { $_.tool } } | Select-Object -Unique)
                $title = "Plaintext package-registry credentials in config files ($($hosts -join ', '))"
                $fp = 'npm login and twine store tokens in these files by design. The risk depends on the token scope (read-only/granular vs publish-capable classic token). Supply-chain worms (Shai-Hulud family) harvest exactly ~/.npmrc and republish every package the token can reach. May overlap with the secrets module (S12).'
                $rec = 'Check each token on the registry website: prefer granular, short-lived tokens with 2FA or trusted publishing; for GitHub Packages use a fine-grained token with read:packages only; reference tokens via ${ENV_VAR} instead of literals; revoke unused tokens. If a worm finding exists, disable watchers before revoking. Manual steps only.'
                $reasons += 'plaintext_secret'
            }
            'tls-verification-off' {
                $title = "TLS certificate checks disabled for package downloads ($(@($items | ForEach-Object { $_.key } | Select-Object -Unique) -join ', '))"
                $fp = 'Often set to get past an HTTPS-inspecting proxy or an antivirus web shield that re-signs TLS. It still lets anyone on the network path swap packages during install.'
                $rec = 'Remove strict-ssl=false / trusted-host / NODE_TLS_REJECT_UNAUTHORIZED=0. If HTTPS inspection breaks npm or pip, point them at the inspection root instead (npm cafile=, pip cert=) or exclude the registries from scanning. Manual steps only.'
            }
            'extra-index-dependency-confusion' {
                $title = "pip/uv extra index configured: dependency-confusion risk ($(@($items | ForEach-Object { $_.host } | Select-Object -Unique) -join ', '))"
                $fp = 'Extra indexes are normal for private packages or PyTorch wheels. The risk is that pip picks the highest version from ANY index, so a public package with the same name as a private one wins.'
                $rec = 'Prefer a single index (a proxy that merges public+private) or uv index pinning ([tool.uv.sources] with explicit = true); pin hashes in requirements. Manual steps only.'
            }
            { $_ -in 'non-default-registry', 'non-default-index', 'insecure-registry', 'insecure-index', 'extra-package-source' } {
                $title = "Non-default package registry/index configured ($(@($items | ForEach-Object { "$($_.tool):$($_.host)" } | Select-Object -Unique) -join ', '))"
                $fp = 'Company registries and regional mirrors are legitimate. The question is whether you trust the operator of that registry with every install.'
                $rec = 'Confirm the registry is yours or a trusted mirror; use scoped registries (@scope:registry) for private packages and keep the default registry for the rest. Manual steps only.'
                if ($risk -like 'insecure-*') { $reasons += 'cleartext_registry' }
            }
            'code-injection' {
                $title = 'NODE_OPTIONS / node-options preloads code into every Node.js process'
                $sev = 'high'; $cls = 'suspicious'
                $fp = 'Some tools set NODE_OPTIONS=--require for instrumentation (APM agents, ts-node). It is also a known persistence trick.'
                $rec = 'Check what the preloaded file is and who set the variable. Manual steps only.'
                $reasons += 'persistence'
            }
            'credential-in-environment' {
                $title = 'npm token exposed in a persistent environment variable'
                $sev = 'low'
                $fp = 'CI-style setup on a workstation; any process (including install scripts) can read it.'
                $rec = 'Keep publish tokens out of the persistent environment; use npm login with 2FA or trusted publishing. Manual steps only.'
                $reasons += 'plaintext_secret'
            }
            'custom-ca' { $sev = 'low'; $title = 'Custom CA configured for npm'; $fp = 'Usually set for a company proxy or antivirus HTTPS inspection.'; $rec = 'Confirm the CA belongs to your proxy/AV. Manual steps only.' }
            default { $sev = 'low'; $title = "Registry configuration: $risk"; $fp = 'Context.'; $rec = 'Review manually.' }
        }
        if (-not $title) { continue }
        if ($cap) { $sev = 'info'; $cls = 'info' }
        New-BvsFinding -Run $run -Check 'registry.overrides' -Title $title -Severity $sev -Class $cls -Confidence 'high' -Reasons $reasons `
            -Evidence @($items | Select-Object -First 15 | ForEach-Object { [ordered]@{ type = 'config'; path = $_.file; scope = $_.scope; tool = $_.tool; key = $_.key; value = $_.value; host = $_.host; note = $_.note } }) `
            -FpNotes $fp -Recommendation $rec -Mitre @('T1195.001') -Expected $cap
    }
}

#endregion

#region ---------- hygiene (ordinary vulnerabilities) ----------

function Get-VulnCounts($Keys) {
    $c = [ordered]@{ critical = 0; high = 0; moderate = 0; low = 0; unknown = 0; packages = 0; malicious = 0 }
    $top = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $Keys) {
        $ids = $null
        if (-not $script:OsvHits.TryGetValue($k, [ref]$ids)) { continue }
        $counted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $pkgVulns = 0; $worst = $null; $isMal = $false
        foreach ($id in @($ids | Sort-Object { if ($_ -like 'GHSA-*') { 0 } else { 1 } })) {
            $v = $script:OsvVulns[$id]
            if (-not $v) { continue }
            if ($v.Malicious -and -not $v.Withdrawn) { $isMal = $true; continue }
            if ($v.Withdrawn -or $counted.Contains($id)) { continue }
            $dup = $false
            foreach ($a in $v.Aliases) { if ($counted.Contains($a)) { $dup = $true; break } }
            if ($dup) { continue }
            [void]$counted.Add($id)
            foreach ($a in $v.Aliases) { [void]$counted.Add($a) }
            $s = if ($v.Severity -in 'critical', 'high', 'moderate', 'low') { $v.Severity } else { 'unknown' }
            $c[$s]++
            $pkgVulns++
            if (-not $worst -or (@('critical', 'high', 'moderate', 'low', 'unknown').IndexOf($s) -lt @('critical', 'high', 'moderate', 'low', 'unknown').IndexOf($worst))) { $worst = $s }
        }
        if ($isMal) { $c.malicious++ }
        if ($pkgVulns -gt 0) {
            $c.packages++
            $p = $script:Pkgs[$k]
            $top.Add([pscustomobject]@{ pkg = "$($p.Name)@$($p.Version)"; vulns = $pkgVulns; worst = $worst })
        }
    }
    $c.top = @($top | Sort-Object @{ e = { @('critical', 'high', 'moderate', 'low', 'unknown').IndexOf($_.worst) } }, @{ e = { $_.vulns }; Descending = $true } | Select-Object -First 8 | ForEach-Object { "$($_.pkg) ($($_.vulns), worst $($_.worst))" })
    $c
}

function Invoke-Hygiene {
    $rows = [System.Collections.Generic.List[object]]::new()
    $tot = [ordered]@{ critical = 0; high = 0; moderate = 0; low = 0; unknown = 0; projectsWithCritical = 0; projectsWithVulns = 0 }
    foreach ($g in $script:Groups) {
        $set = $null
        $keys = if ($script:SetByProject.TryGetValue($g.Id, [ref]$set)) { $set } else { @() }
        $vc = Get-VulnCounts $keys
        $kinds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($k in $keys) { foreach ($x in $script:Pkgs[$k].Kinds) { [void]$kinds.Add($x) } }
        $row = [ordered]@{
            id = $g.Id; name = $g.Name; ecosystems = @($g.Ecosystems); copies = @($g.Copies | ForEach-Object { $_.Path }); copyCount = $g.Copies.Count
            lockfiles = @($g.Copies[0].NpmLock, @($g.Copies[0].PyLocks)) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFileName($_) }
            installedCopies = @($g.Copies | Where-Object { $_.HasNodeModules -or $_.Venvs.Count }).Count
            packages = @($keys).Count; maliciousHits = $vc.malicious
            vulns = [ordered]@{ critical = $vc.critical; high = $vc.high; moderate = $vc.moderate; low = $vc.low; unknown = $vc.unknown; vulnerablePackages = $vc.packages }
            topVulnerable = $vc.top; fingerprint = $g.Fingerprint
        }
        $rows.Add($row)
        foreach ($s in 'critical', 'high', 'moderate', 'low', 'unknown') { $tot[$s] += $vc[$s] }
        if ($vc.critical -gt 0) { $tot.projectsWithCritical++ }
        if ($vc.packages -gt 0) { $tot.projectsWithVulns++ }
    }
    $envRows = [System.Collections.Generic.List[object]]::new()
    foreach ($kv in $script:SetByProject.GetEnumerator()) {
        if ($kv.Key -like 'P*' -and $script:GroupById.ContainsKey($kv.Key)) { continue }
        $vc = Get-VulnCounts $kv.Value
        $envRows.Add([ordered]@{ id = $kv.Key; packages = $kv.Value.Count; maliciousHits = $vc.malicious; vulns = [ordered]@{ critical = $vc.critical; high = $vc.high; moderate = $vc.moderate; low = $vc.low; unknown = $vc.unknown; vulnerablePackages = $vc.packages }; topVulnerable = $vc.top })
    }
    Add-BvsInventory -Run $run -Name 'projects' -Data @($rows | Sort-Object { - ($_.vulns.critical * 1000 + $_.vulns.high) } | Select-Object -First 500)
    Add-BvsInventory -Run $run -Name 'environments' -Data @($envRows | Select-Object -First 300)
    if (-not $Offline -and ($tot.critical + $tot.high + $tot.moderate + $tot.low + $tot.unknown) -gt 0) {
        $worst = @($rows | Where-Object { $_.vulns.critical -gt 0 -or $_.vulns.high -gt 0 } | Sort-Object { - ($_.vulns.critical * 1000 + $_.vulns.high) } | Select-Object -First 10)
        New-BvsFinding -Run $run -Check 'osv.hygiene' -Title "Known vulnerabilities in project dependencies: $($tot.critical) critical, $($tot.high) high, $($tot.moderate) moderate across $($tot.projectsWithVulns) project(s)" `
            -Severity 'low' -Class 'hygiene' -Confidence 'high' -Reasons @('vulnerable_dependency') `
            -Evidence @($worst | ForEach-Object { [ordered]@{ type = 'project'; id = $_.id; name = $_.name; path = $_.copies[0]; copies = $_.copyCount; vulns = $_.vulns; top = $_.topVulnerable } }) `
            -FpNotes 'Counts are per unique advisory (aliases merged) for versions found in lockfiles or installed folders. Many apply only to specific APIs, server use or dev tooling; this is hygiene, not evidence of compromise, and is not part of the verdict.' `
            -Recommendation 'Update dependencies in active projects (npm audit / pip-audit in the project, run manually by you), starting with the projects listed. Archive or delete copies you no longer use. Manual steps only.' -Mitre @()
    }
    $rows.Count
}

#endregion

#region ---------- main ----------

# Exclusions and expected items (portable: from Get-BvsRoot and src\config\local\expected.json)
Add-Excluded $script:BvsRoot
Add-Excluded (Join-Path $script:UserHome ('.claude\projects\' + ($script:BvsRoot -replace '[^A-Za-z0-9]', '-')))
foreach ($e in @(Get-BvsExpected -Category 'path' | Where-Object { $_.id -eq 'this-project' })) { foreach ($p in @($e.match.paths)) { Add-Excluded ([Environment]::ExpandEnvironmentVariables([string]$p)) } }
foreach ($e in @(Get-BvsExpected -Category 'path' | Where-Object { $_.id -eq 'security-tooling-repos' })) {
    foreach ($p in @($e.match.paths)) { $script:SecToolRoots.Add([pscustomobject]@{ Root = ([Environment]::ExpandEnvironmentVariables([string]$p)).TrimEnd('\') + '\'; Item = $e }) }
}
foreach ($e in $script:Ioc.compromisedVersions) {
    $n = if ($e.ecosystem -eq 'PyPI') { ConvertTo-Pep503 $e.name } else { $e.name }
    foreach ($v in $e.versions) { $script:IocVersions["$($e.ecosystem)|$n|$v"] = $e.campaign }
}
Write-BvsLog -Run $run -Message "S11 start: maxDepth=$MaxDepth offline=$Offline iocVersions=$($script:IocVersions.Count)"

$null = Invoke-BvsCheck -Run $run -Id 'supply.discover' -Description 'Find lockfiles, manifests, node_modules, venvs, npm caches and repos under the user profile (depth-limited, no node_modules recursion); group copies by lockfile hash' -Script {
    $script:Discovery = Invoke-Discovery
    $null = Build-Projects $script:Discovery
    Write-BvsLog -Run $run -Message ("discovery: dirs={0} files={1} projects={2} nodeModules={3} venvs={4} repos={5} npx={6} caches={7}" -f $script:Discovery.DirCount, $script:Discovery.FileCount, $script:Groups.Count, $script:Discovery.NodeModules.Count, $script:Discovery.Venvs.Count, $script:Discovery.RepoRoots.Count, $script:Discovery.NpxDirs.Count, $script:Discovery.CacheRoots.Count)
    @($script:Groups)
}

$null = Invoke-BvsCheck -Run $run -Id 'npm.lockfiles' -Description 'Parse package-lock/npm-shrinkwrap (v1-3), yarn.lock (v1, berry), pnpm-lock.yaml (v5/v6/v9) and bun.lock once per unique lockfile' -Script { Invoke-NpmLockfiles }
$null = Invoke-BvsCheck -Run $run -Id 'npm.installed' -Description 'What is actually installed: node_modules\.package-lock.json, else pnpm virtual store, else node_modules walk' -Script { Invoke-NpmInstalled }
$null = Invoke-BvsCheck -Run $run -Id 'npm.globals' -Description 'Global packages for every nvm version, Program Files nodejs, %APPDATA%\npm, pnpm/yarn/bun/fnm globals' -Script { Invoke-NpmGlobals }
$null = Invoke-BvsCheck -Run $run -Id 'npm.cache' -Description 'npm cache index-v5: every tarball ever downloaded (name@version, first-seen time)' -Script { Invoke-NpmCache }
$null = Invoke-BvsCheck -Run $run -Id 'npm.npx' -Description 'npm-cache\_npx folders: history of npx one-off runs (executed code)' -Script { Invoke-NpxHistory }
$null = Invoke-BvsCheck -Run $run -Id 'python.lockfiles' -Description 'Pinned requirements*.txt, poetry.lock, uv.lock, Pipfile.lock' -Script { Invoke-PythonLockfiles }
$null = Invoke-BvsCheck -Run $run -Id 'python.environments' -Description 'dist-info / egg-info names in venvs, global and per-user site-packages, Store Python, pipx/uv tools, conda' -Script { Invoke-PythonEnvironments }

if ($Offline) {
    $null = Invoke-BvsCheck -Run $run -Id 'osv.query' -Description 'OSV querybatch for every unique name@version (npm, PyPI)' -Script { Set-BvsCheckStatus -Id 'osv.query' -Status skipped -Reason '-Offline'; @() }
    $null = Invoke-BvsCheck -Run $run -Id 'osv.details' -Description 'OSV vulnerability details (cached) and malicious classification' -Script { Set-BvsCheckStatus -Id 'osv.details' -Status skipped -Reason '-Offline'; @() }
    $script:Coverage.Add('OSV was skipped (-Offline): malicious detection relied on the local, non-exhaustive IoC list only.')
}
else {
    $null = Invoke-BvsCheck -Run $run -Id 'osv.query' -Description 'OSV querybatch for every unique name@version (npm, PyPI); only name@version leaves the machine' -Script { Invoke-OsvQuery }
    if ($script:OsvStats.batches -gt 0 -and $script:OsvStats.errors -eq 0) {
        $null = Invoke-BvsCheck -Run $run -Id 'osv.details' -Description 'OSV vulnerability details (cached under intel\api.osv.dev) and malicious classification: MAL- id, CWE-506, malicious wording' -Script { Invoke-OsvDetails }
    }
    else {
        $null = Invoke-BvsCheck -Run $run -Id 'osv.details' -Description 'OSV vulnerability details' -Script { Set-BvsCheckStatus -Id 'osv.details' -Status skipped -Reason 'querybatch failed'; @() }
        $script:Coverage.Add('OSV querybatch failed: malicious detection relied on the local IoC list only.')
    }
}

$null = Invoke-BvsCheck -Run $run -Id 'supply.malicious' -Description 'Malicious package versions (OSV + sidecar IoC list): critical if installed or locked, high if only cached or executed via npx' -Script { Add-MaliciousFindings }
$null = Invoke-BvsCheck -Run $run -Id 'ioc.package_files' -Description 'Shai-Hulud family loaders at installed package roots (setup_bun.js, bun_environment.js, Math_Symbol.js, setup.mjs + preinstall)' -Script { Invoke-PackageFileProbe }
$null = Invoke-BvsCheck -Run $run -Id 'ioc.repo_files' -Description 'Worm repo artifacts: shai-hulud workflows, formatter_*/discussion/format-check workflows, toJSON(secrets), .claude/.vscode/.cursor/.gemini backdoors (read only)' -Script { Invoke-RepoFileChecks }
$null = Invoke-BvsCheck -Run $run -Id 'ioc.host_paths' -Description 'Worm persistence/staging: gh-token-monitor, sysmon.py, .dev-env runner, bun-dl temp folders, watcher scheduled task, staging file names' -Script { Invoke-HostPathChecks }
$null = Invoke-BvsCheck -Run $run -Id 'npm.lifecycle' -Description 'preinstall/install/postinstall of installed packages (and binding.gyp command expansion): download/exec, encoded, obfuscated or oversized scripts' -Script { Invoke-LifecycleAnalysis }
$null = Invoke-BvsCheck -Run $run -Id 'python.pth' -Description 'Python .pth startup hooks with exec/network/decode code, plus PyPI worm files in site-packages' -Script { Invoke-PthChecks }
$null = Invoke-BvsCheck -Run $run -Id 'registry.overrides' -Description '.npmrc (user/global/project), .yarnrc*, bunfig.toml, pip.ini/pip.conf, uv.toml, .pypirc, pyproject/Pipfile sources and env vars: non-default registries, extra indexes, TLS off, plaintext credentials (never printed)' -Script { Invoke-RegistryChecks }
$null = Invoke-BvsCheck -Run $run -Id 'osv.hygiene' -Description 'Ordinary vulnerability counts per project group (hygiene, not part of the verdict)' -Script { Invoke-Hygiene }

# ---------- inventory ----------
$kindCounts = [ordered]@{}
foreach ($p in $script:Pkgs.Values) { foreach ($k in $p.Kinds) { $kindCounts[$k] = 1 + [int]$kindCounts[$k] } }
Add-BvsInventory -Run $run -Name 'summary' -Data ([ordered]@{
        projects = $script:Groups.Count; projectCopies = @($script:Groups | ForEach-Object { $_.Copies.Count } | Measure-Object -Sum).Sum
        uniquePackageVersions = $script:Pkgs.Count; npmPackageVersions = @($script:Pkgs.Values | Where-Object { $_.Eco -eq 'npm' }).Count; pypiPackageVersions = @($script:Pkgs.Values | Where-Object { $_.Eco -eq 'PyPI' }).Count
        byKind = $kindCounts; maliciousPackages = $script:MalInv.Count; iocFileHits = $script:IocFileInv.Count; lifecycleFlags = $script:LifecycleInv.Count
        registryRecords = $script:RegistryInv.Count; npxRuns = $script:NpxHistory.Count; runtimeSeconds = [Math]::Round($script:Sw.Elapsed.TotalSeconds, 1)
        lockStats = $script:LockStats; installedStats = $script:InstalledStats; lifecycleStats = $script:LifecycleStats
    })
Add-BvsInventory -Run $run -Name 'malicious' -Data @($script:MalInv)
Add-BvsInventory -Run $run -Name 'iocFileHits' -Data @($script:IocFileInv)
Add-BvsInventory -Run $run -Name 'npxHistory' -Data @($script:NpxHistory | Sort-Object { $_.createdUtc } -Descending | Select-Object -First 300)
Add-BvsInventory -Run $run -Name 'lifecycleFlags' -Data @($script:LifecycleInv | Sort-Object { - $_.score } | Select-Object -First 300)
Add-BvsInventory -Run $run -Name 'registryOverrides' -Data @($script:RegistryInv | Select-Object -First 400)
Add-BvsInventory -Run $run -Name 'lockfileRegistryHosts' -Data ([ordered]@{} + @{} | ForEach-Object { $h = [ordered]@{}; foreach ($k in @($script:LockHosts.Keys | Sort-Object)) { $h[$k] = $script:LockHosts[$k] }; $h })
Add-BvsInventory -Run $run -Name 'globals' -Data @($script:GlobalsInv)
Add-BvsInventory -Run $run -Name 'npmCache' -Data @($script:CacheInv)
Add-BvsInventory -Run $run -Name 'pythonEnvironments' -Data @($script:PyEnvInv | Select-Object -First 300)
Add-BvsInventory -Run $run -Name 'osv' -Data $script:OsvStats
Add-BvsInventory -Run $run -Name 'iocList' -Data ([ordered]@{ file = 'src\collectors\security\windows\S11-iocs.json'; updated = $script:Ioc.updated; campaigns = @($script:Ioc.campaigns).Count; versionEntries = $script:IocVersions.Count; packageFileIndicators = @($script:Ioc.packageFiles).Count; repoFileIndicators = @($script:Ioc.repoFiles).Count; hostPathIndicators = @($script:Ioc.hostPaths).Count; note = 'Non-exhaustive backstop; OSV is the primary source.' })
$script:Coverage.Add('pnpm 10+ store index is SQLite (index.db) and is not parsed; pnpm-installed projects are read from their node_modules\.pnpm folders instead.')
$script:Coverage.Add('VS Code / Cursor extension node_modules and Electron app bundles under AppData are out of scope here (editor-extension module).')
$script:Coverage.Add('Lockfile and node_modules contents are trusted as written; a package that rewrote its own package.json after install would only be caught by the file-indicator and lifecycle checks.')
Add-BvsInventory -Run $run -Name 'coverage' -Data @($script:Coverage)

$summary = Complete-BvsRun -Run $run

# ---------- short console summary (masked) ----------
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("S11 supply chain: $($summary.Findings) finding(s) [$($summary.BySeverity)] checks=$($summary.Checks) errors=$($summary.Errors) in $([Math]::Round($script:Sw.Elapsed.TotalSeconds))s")
$lines.Add("projects=$($script:Groups.Count) uniquePkgVersions=$($script:Pkgs.Count) kinds: " + (($kindCounts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '))
$lines.Add("OSV: queried=$($script:OsvStats.queried) batches=$($script:OsvStats.batches) pkgsWithHits=$($script:OsvStats.packagesWithHits) ids=$($script:OsvStats.uniqueVulnIds) cache=$($script:OsvStats.detailsFromCache) fetched=$($script:OsvStats.detailsFetched) failed=$($script:OsvStats.detailsFailed) malicious=$($script:OsvStats.maliciousIds)")
foreach ($f in @($run.Findings | Sort-Object @{ e = { @('critical', 'high', 'medium', 'low', 'info').IndexOf($_.severity) } } | Select-Object -First 25)) { $lines.Add("  [$($f.severity)/$($f.class)] $($f.title)") }
foreach ($c in @($run.Checks | Where-Object { $_.status -ne 'ok' })) { $lines.Add("  check $($c.id): $($c.status) $($c.reason)") }
$lines.Add("output: $($summary.Path)")
$lines | Select-Object -First 40 | ForEach-Object { Protect-BvsText $_ }

#endregion
