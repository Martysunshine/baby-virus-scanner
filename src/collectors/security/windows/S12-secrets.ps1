#Requires -Version 7.2
<#
.SYNOPSIS
    S12 - Secrets exposure: a masked inventory of where credentials sit in plaintext and whether they are exposed.
.DESCRIPTION
    Read-only collector for baby-virus-scanner (bvs.module/1, area "security").

    What it looks at:
      1. Home dotfiles and CLI token stores (catalog in S12-secret-stores.json), AI-agent configs,
         persistent environment variables and Windows Credential Manager target NAMES (cmdkey /list).
      2. Repository secret files (.env family, project .npmrc/.mcp.json/Claude settings): per-rule counts,
         git tracked / in history / pushed, .gitignore coverage, GitHub visibility of the user's own repos.
      3. Key-material files (existence and metadata only).
      4. Shell histories (PSReadLine, bash, python, node, ...).
      5. Claude Code storage (transcripts, file-history, prompt history), Codex sessions, editor local history.
      6. SSH: private-key protection (Get-BvsSshKeyInfo only), public-key fingerprints, ACLs, ssh config,
         known_hosts and authorized_keys.

    Safety contract (docs\agent-rules.md):
      * Never prints, logs or stores a raw secret. Output carries rule id, count, location, line numbers and
        the library's masked sample (Protect-BvsSecret). Cross-location correlation uses SHA-256 values that
        live only in memory; the output only has run-local reference ids (K001, K002, ...).
      * Files on the never-read list (Test-BvsNeverRead) and catalog entries with mode "exists" are reported
        by existence, size, timestamps and ACL only. SSH key protection comes only from Get-BvsSshKeyInfo.
      * git runs only as `git --no-optional-locks <read-only subcommand>`.
      * Network: only Invoke-BvsIntel to api.github.com, sending only the user's GitHub account name (and the
        names of that account's own repositories when the public list is unavailable).
.PARAMETER SearchRoots
    Folders swept for repository secret files and key-material files. Default: the user profile.
.PARAMETER GitHubUser
    GitHub account(s) whose public repositories are looked up. Default: git config github.user, else the
    owner of at least half of the local repositories' GitHub remotes.
.PARAMETER NoNetwork
    Skip the GitHub visibility lookup (public = null, check status "skipped").
.PARAMETER MaxScanMB
    Size cap for one non-transcript file. Larger files are skipped and listed under coverage.
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S12-secrets.ps1
.NOTES
    Data: S12-secret-stores.json. Contract: docs\schema.md. Playbook: docs\playbooks\S12-secrets.md.
#>
[CmdletBinding()]
param(
    [string[]]$SearchRoots,
    [string[]]$GitHubUser,
    [switch]$NoNetwork,
    [ValidateRange(1, 1024)][int]$MaxScanMB = 64
)

Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S12 -Area security
$swTotal = [Diagnostics.Stopwatch]::StartNew()

#region ---------- configuration and state ----------

$Cat = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S12-secret-stores.json') -Raw | ConvertFrom-Json
$UserHome = $env:USERPROFILE.TrimEnd('\')
$ProjectRoot = $run.Root.TrimEnd('\')
$NowUtc = [datetime]::UtcNow
$MaxScanBytes = [long]$MaxScanMB * 1MB
$ChunkChars = [int]$Cat.transcripts.chunkChars
$SshDir = Join-Path $UserHome '.ssh'
$Roots = @(if ($SearchRoots) { $SearchRoots | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') } } else { $UserHome })

$Rules = @(Get-BvsSecretRules)
$RulePrio = @{}
for ($i = 0; $i -lt $Rules.Count; $i++) { $RulePrio[$Rules[$i].Id] = $i }
$TierPrefixed = [Collections.Generic.HashSet[string]]::new([string[]]@($Cat.tiers.prefixed), [StringComparer]::OrdinalIgnoreCase)
$TierStructured = [Collections.Generic.HashSet[string]]::new([string[]]@($Cat.tiers.structured), [StringComparer]::OrdinalIgnoreCase)
$PublicRules = [Collections.Generic.HashSet[string]]::new([string[]]@('google-api-key', 'jwt', 'generic-assignment', 'env-assignment', 'json-field'), [StringComparer]::OrdinalIgnoreCase)
$PlaceholderWords = @($Cat.placeholderWords | ForEach-Object { ([string]$_).ToLowerInvariant() })
$ReferenceRx = [regex]::new([string]$Cat.referenceRegex, 'CultureInvariant')
$LocalHostRx = [regex]::new([string]$Cat.localHostRegex, 'CultureInvariant')
$TemplateRx = [regex]::new([string]$Cat.templateNameRegex, 'CultureInvariant')
$BackupNameRx = [regex]::new([string]$Cat.backupNameRegex, 'CultureInvariant')
$BenignKeyDirRx = [regex]::new([string]$Cat.keyFileBenignDirRegex, 'CultureInvariant')
$FixtureDirs = [Collections.Generic.HashSet[string]]::new([string[]]@($Cat.fixtureDirNames), [StringComparer]::OrdinalIgnoreCase)
$FixturePrefixes = @($Cat.fixtureDirPrefixes)
$EnvNameRx = [regex]'(?i)^(\.env(\..+)?|.+\.env|\.envrc|\.dev\.vars)$'
$SecretNameRx = [regex]'(?i)(SECRET|TOKEN|PASSWORD|PASSWD|PWD$|_PASS$|^PASS$|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH|CREDENTIAL|SIGNING|ENCRYPTION[_-]?KEY|MASTER[_-]?KEY|WEBHOOK|DSN$|_KEY$|^KEY$)'
$PublicNameRx = [regex]'(?i)(\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*|PUBLISHABLE[A-Z0-9_]*)["'']?\s*[:=]\s*["'']?$'
$JsonFieldRx = [regex]'(?i)(token|secret|passw(or)?d|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|refresh|credential|session[_-]?key|auth[_-]?key|bearer|cookie)'
$JsonFieldSkipRx = [regex]'(?i)(count|type|expir|_at$|At$|url$|uri$|endpoint|path$|file$|name$|limit|max|min|usage|tokens$|enabled|method|scope|scheme|kind|version|hint|header$|prefix|suffix|length|format|helper|storage|store$|provider$|source$|mode$)'
$BackupMapRx = [regex]'"((?:[^"\\]|\\.){1,600})":\{"backupFileName":"([0-9a-f]{8,64})@v\d+"'
$UrlHostRx = [regex]'\G@([^/:?#\s"''<>\\]+)'
$LiveRank = @{ 'configured' = 7; 'likely' = 6; 'historic' = 5; 'unknown' = 4; 'local' = 3; 'public' = 2; 'fixture' = 1; 'no' = 0 }
$LiveSet = @('configured', 'likely', 'historic')           # values that drive "live secret" findings
$ConfigTypes = @('cli-store', 'env-var', 'agent-config', 'repo-file', 'repo-config')
$AllowedAclSids = [Collections.Generic.HashSet[string]]::new([string[]]@($run.UserSid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-4'), [StringComparer]::OrdinalIgnoreCase)

$Locations = [Collections.Generic.List[object]]::new()
$SshKeys = [Collections.Generic.List[object]]::new()
$StoreRows = [Collections.Generic.List[object]]::new()
$Coverage = [Collections.Generic.List[object]]::new()
$BackupMap = @{}
$SessionProject = @{}
$RepoRootCache = @{}
$RepoFacts = [ordered]@{}
$Configured = [Collections.Generic.HashSet[string]]::new()
$ConfiguredAt = @{}
$FixtureHashes = [Collections.Generic.HashSet[string]]::new()
$RefIds = @{}
$RefInfo = [ordered]@{}
$GitHubVis = @{}
$GitHubMeta = [ordered]@{ users = @(); method = $null; listCalls = 0; perRepoCalls = 0; rateLimited = $false; errors = @() }

function Expand-S12Path([string]$Path) { [Environment]::ExpandEnvironmentVariables($Path).TrimEnd('\') }

function Get-S12Display([string]$Path) {
    if ($Path -and $Path.StartsWith($UserHome, [StringComparison]::OrdinalIgnoreCase)) { return '~' + $Path.Substring($UserHome.Length) }
    $Path
}

function Test-S12Under([string]$Path, [string[]]$Prefixes) {
    if (-not $Path) { return $false }
    foreach ($p in $Prefixes) {
        if (-not $p) { continue }
        $q = $p.TrimEnd('\')
        if ($Path.Equals($q, [StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($q + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $false
}

function ConvertTo-S12ProjectFolderName([string]$Path) { ($Path.TrimEnd('\') -replace '[^A-Za-z0-9]', '-') }

# Machine-specific context from src\config\local\expected.json (category "path"): the item whose paths contain
# this project is "self" (excluded everywhere); other info-class path items are known security-tooling repos
# whose test fixtures hold fake secrets by design.
$SelfPaths = [Collections.Generic.List[string]]::new()
$SelfPaths.Add($ProjectRoot)
$SecurityToolingPaths = [Collections.Generic.List[string]]::new()
$SecurityToolingItem = $null
foreach ($item in @(Get-BvsExpected -Category path)) {
    $paths = @($item.match.paths | Where-Object { $_ } | ForEach-Object { Expand-S12Path $_ })
    if (-not $paths) { continue }
    if (@($paths | Where-Object { $_.Equals($ProjectRoot, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { foreach ($p in $paths) { $SelfPaths.Add($p) } }
    elseif ($item.class -eq 'info') { foreach ($p in $paths) { $SecurityToolingPaths.Add($p) }; $SecurityToolingItem = $item }
}
$SelfTranscriptNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($p in $SelfPaths) {
    if ($p -match '\\\.claude\\projects\\([^\\]+)$') { [void]$SelfTranscriptNames.Add($Matches[1]) } else { [void]$SelfTranscriptNames.Add((ConvertTo-S12ProjectFolderName $p)) }
}
$ToolingTranscriptNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($p in $SecurityToolingPaths) { [void]$ToolingTranscriptNames.Add((ConvertTo-S12ProjectFolderName $p)) }

#endregion

#region ---------- value analysis (in memory only) ----------

function Get-S12Hash([string]$Value) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value)))
}

function Get-S12Entropy([string]$Value) {
    $s = if ($Value.Length -gt 256) { $Value.Substring(0, 256) } else { $Value }
    $d = [Collections.Generic.Dictionary[char, int]]::new()
    foreach ($c in $s.ToCharArray()) { if ($d.ContainsKey($c)) { $d[$c]++ } else { $d[$c] = 1 } }
    $h = 0.0
    $n = [double]$s.Length
    foreach ($k in $d.Values) { $p = $k / $n; $h -= $p * [Math]::Log($p, 2) }
    $h
}

function Test-S12Placeholder([string]$Value) {
    if ($Value.Length -lt 6) { return $true }
    $lv = $Value.ToLowerInvariant()
    foreach ($w in $PlaceholderWords) { if ($lv.Contains($w)) { return $true } }
    $core = $Value -creplace '^(?:[a-z]{1,8}[_-]){1,3}', ''
    foreach ($s in @($Value, $core)) {
        if ($s.Length -lt 6) { continue }
        if ($s -cmatch '(.)\1{5,}') { return $true }
        $set = [Collections.Generic.HashSet[char]]::new()
        foreach ($c in $s.ToCharArray()) { [void]$set.Add($c) }
        if ($set.Count -le 4) { return $true }
        $n = $s.Length
        $maxP = [Math]::Min(16, [Math]::Floor($n / 2))
        for ($p = 1; $p -le $maxP; $p++) {
            $periodic = $true
            for ($i = $p; $i -lt $n; $i++) { if ($s[$i] -cne $s[$i - $p]) { $periodic = $false; break } }
            if ($periodic) { return $true }
        }
    }
    if ($Value.Length -ge 16 -and (Get-S12Entropy $Value) -lt 2.5) { return $true }
    $false
}

function Read-S12UInt32([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) { return -1 }
    ([int]$Bytes[$Offset] -shl 24) -bor ([int]$Bytes[$Offset + 1] -shl 16) -bor ([int]$Bytes[$Offset + 2] -shl 8) -bor [int]$Bytes[$Offset + 3]
}

function Get-S12JwtInfo([string]$Token) {
    $parts = $Token.Split('.')
    if ($parts.Count -lt 3) { return $null }
    try {
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        $pad = $p.Length % 4
        if ($pad -eq 1) { return $null }
        if ($pad -gt 0) { $p = $p + ('=' * (4 - $pad)) }
        $o = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        $exp = $null
        $expRaw = $o['exp'] -as [long]
        if ($expRaw) { $exp = [DateTimeOffset]::FromUnixTimeSeconds($expRaw).UtcDateTime }
        $iss = $null
        if ($o['iss']) { $iss = [string]$o['iss']; try { $u = [uri]$iss; if ($u.IsAbsoluteUri) { $iss = $u.Host } } catch { $iss = $null } }
        [pscustomobject]@{ Role = [string]$o['role']; Expired = [bool]($exp -and $exp -lt $NowUtc); Iss = $iss }
    }
    catch { $null }
}

# OpenSSH private key text -> fingerprint of its embedded PUBLIC key (the public part is stored in clear even
# in encrypted keys). Used only on text found in transcripts/histories, never on key files.
function Get-S12PemPublicFingerprint([string]$Value) {
    if ($Value -notmatch 'BEGIN OPENSSH PRIVATE KEY') { return $null }
    try {
        $body = ($Value -replace '-----(BEGIN|END) OPENSSH PRIVATE KEY-----', '' -replace '\\[nrt]', '') -replace '[^A-Za-z0-9+/=]', ''
        $take = [Math]::Min($body.Length - ($body.Length % 4), 8192)
        if ($take -lt 64) { return $null }
        $bytes = [Convert]::FromBase64String($body.Substring(0, $take))
        try {
            if ([Text.Encoding]::ASCII.GetString($bytes, 0, 14) -ne 'openssh-key-v1') { return $null }
            $o = 15
            for ($k = 0; $k -lt 3; $k++) { $len = Read-S12UInt32 $bytes $o; if ($len -lt 0) { return $null }; $o += 4 + $len }
            $o += 4
            $len = Read-S12UInt32 $bytes $o
            if ($len -le 0 -or ($o + 4 + $len) -gt $bytes.Length) { return $null }
            $pub = [byte[]]$bytes[($o + 4)..($o + 3 + $len)]
            'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($pub)).TrimEnd('=')
        }
        finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    catch { $null }
}

function New-S12Hit {
    param(
        [Parameter(Mandatory)][string]$Rule,
        [string]$Kind = 'token',
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [string]$Masked,
        [int]$Line = 0,
        [string]$HostContext,
        [string]$LinePrefix
    )
    if (-not $Masked) { $Masked = Protect-BvsSecret $Value }
    $tier = if ($Kind -eq 'private-key') { 'private-key' } elseif ($TierPrefixed.Contains($Rule)) { 'prefixed' } elseif ($TierStructured.Contains($Rule)) { 'structured' } else { 'weak' }
    $placeholder = $false; $reference = $false; $note = $null; $keyFp = $null
    $jwtRole = $null; $jwtExpired = $null; $jwtIss = $null; $local = $false; $public = $false
    $norm = $Value.Trim().Trim('"', "'", '`')
    if ($tier -eq 'private-key') {
        $body = ($Value -replace '-----(BEGIN|END)[A-Z0-9 ]*-----', '' -replace '\\[nrt]', '') -replace '[^A-Za-z0-9+/=]', ''
        if ($body.Length -lt 64) { $placeholder = $true; $note = 'header-only' }
        else { $norm = $body; $keyFp = Get-S12PemPublicFingerprint $Value }
    }
    else {
        $reference = $ReferenceRx.IsMatch($norm)
        if (-not $reference) { $placeholder = Test-S12Placeholder $norm }
        if ($Rule -eq 'jwt') { $j = Get-S12JwtInfo $norm; if ($j) { $jwtRole = $j.Role; $jwtExpired = $j.Expired; $jwtIss = $j.Iss } }
        if ($HostContext) { $local = $LocalHostRx.IsMatch($HostContext) }
        if ($LinePrefix -and $PublicRules.Contains($Rule) -and $PublicNameRx.IsMatch($LinePrefix)) { $public = $true }
    }
    $hash = if ($placeholder -or $reference) { $null } else { Get-S12Hash $norm }
    [pscustomobject]@{
        Rule = $Rule; Kind = $Kind; Tier = $tier; Masked = $Masked; Line = $Line
        Placeholder = $placeholder; Reference = $reference; Note = $note
        JwtRole = $jwtRole; JwtExpired = $jwtExpired; JwtIss = $jwtIss
        LocalHost = $local; PublicByDesign = $public; KeyFingerprint = $keyFp
        Hash = $hash; Live = $null; Extra = $null
    }
}

function Get-S12LineStarts([string]$Text) {
    $l = [Collections.Generic.List[int]]::new()
    $l.Add(0)
    $i = $Text.IndexOf([char]10)
    while ($i -ge 0) { $l.Add($i + 1); $i = $Text.IndexOf([char]10, $i + 1) }
    , $l.ToArray()
}

# Find-BvsSecrets + overlap de-duplication (rule order = priority: private keys, prefixed tokens, context
# rules, generic) + line numbers + in-memory classification.
function Get-S12Hits {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [int]$FirstLine = 1)
    if ($Text.Length -eq 0) { return }
    $raw = @(Find-BvsSecrets $Text)
    if ($raw.Count -eq 0) { return }
    $covered = [Collections.BitArray]::new($Text.Length + 1)
    $starts = Get-S12LineStarts $Text
    $sorted = $raw | Sort-Object -Property @{ Expression = { $RulePrio[$_.Rule] } }, @{ Expression = { $_.Index } }
    foreach ($h in $sorted) {
        $start = [int]$h.Index
        $end = $start + [int]$h.Length
        if ($end -le $start) { continue }
        $overlap = $false
        for ($i = $start; $i -lt $end; $i++) { if ($covered[$i]) { $overlap = $true; break } }
        if ($overlap) { continue }
        for ($i = $start; $i -lt $end; $i++) { $covered[$i] = $true }
        $pos = [Array]::BinarySearch($starts, $start)
        if ($pos -lt 0) { $pos = (-bnot $pos) - 1 }
        $prefixStart = [Math]::Max($starts[$pos], $start - 96)
        $prefix = $Text.Substring($prefixStart, $start - $prefixStart)
        $hostCtx = $null
        if ($h.Rule -eq 'url-credentials' -and $end -lt $Text.Length) {
            $m = $UrlHostRx.Match($Text, $end)
            if ($m.Success) { $hostCtx = $m.Groups[1].Value }
        }
        New-S12Hit -Rule $h.Rule -Kind $h.Kind -Value $Text.Substring($start, $end - $start) -Masked $h.Masked -Line ($FirstLine + $pos) -HostContext $hostCtx -LinePrefix $prefix
    }
}

# JSON-escaped text (transcripts): undo one level of escaping, replacing \n \r \t with spaces so that line
# numbers (JSONL records) stay valid.
function ConvertFrom-S12JsonEscapes([string]$Text) {
    if ($Text.IndexOf([char]92) -lt 0) { return $Text }
    $one = [string][char]1
    $Text.Replace('\\', $one).Replace('\"', '"').Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' ').Replace('\/', '/').Replace($one, '\')
}

function Add-S12BackupMap([string]$Line) {
    foreach ($m in $BackupMapRx.Matches($Line)) {
        $k = $m.Groups[2].Value
        if (-not $BackupMap.ContainsKey($k)) { $BackupMap[$k] = $m.Groups[1].Value.Replace('\\', '\') }
    }
}

# Streams a text file in chunks (shared read, never locks the writer). Never opens never-read or cloud-only
# files. Returns hits plus line/byte counts.
function Invoke-S12ScanFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Json,
        [long]$MaxBytes = $MaxScanBytes,
        [switch]$CollectBackupMap,
        [scriptblock]$LineFilter
    )
    $res = [pscustomobject]@{ Hits = [Collections.Generic.List[object]]::new(); Lines = 0; Bytes = 0L; Skipped = $null; Error = $null }
    try {
        $info = [IO.FileInfo]::new($Path)
        if (-not $info.Exists) { $res.Skipped = 'missing'; return $res }
        if (Test-BvsCloudOnly $info) { $res.Skipped = 'cloud-only'; return $res }
        if (Test-BvsNeverRead $info.FullName) { $res.Skipped = 'never-read'; return $res }
        if ($info.Length -gt $MaxBytes) { $res.Skipped = "too-large ($($info.Length) bytes)"; return $res }
        $res.Bytes = $info.Length
        if ($info.Length -eq 0) { return $res }
        $fs = [IO.FileStream]::new($info.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete', 65536)
        try {
            $head = [byte[]]::new([int][Math]::Min(8192, $info.Length))
            $n = $fs.Read($head, 0, $head.Length)
            [void]$fs.Seek(0, [IO.SeekOrigin]::Begin)
            $bom16 = $n -ge 2 -and (($head[0] -eq 0xFF -and $head[1] -eq 0xFE) -or ($head[0] -eq 0xFE -and $head[1] -eq 0xFF))
            if (-not $bom16 -and [Array]::IndexOf($head, [byte]0, 0, $n) -ge 0) { $res.Skipped = 'binary'; return $res }
            $sr = [IO.StreamReader]::new($fs, [Text.UTF8Encoding]::new($false), $true, 65536)
            $sb = [Text.StringBuilder]::new()
            $lineNo = 0
            $first = 1
            while ($null -ne ($line = $sr.ReadLine())) {
                $lineNo++
                if ($CollectBackupMap -and $line.Contains('"backupFileName"')) { Add-S12BackupMap $line }
                if ($LineFilter -and (& $LineFilter $line)) { $line = '' }
                if ($sb.Length -gt 0 -and ($sb.Length + $line.Length) -ge $ChunkChars) {
                    Add-S12ChunkHits -Result $res -Text $sb.ToString() -FirstLine $first -Json:$Json
                    [void]$sb.Clear()
                    $first = $lineNo
                }
                [void]$sb.Append($line).Append([char]10)
            }
            if ($sb.Length -gt 0) { Add-S12ChunkHits -Result $res -Text $sb.ToString() -FirstLine $first -Json:$Json }
            $res.Lines = $lineNo
            $sr.Dispose()
        }
        finally { $fs.Dispose() }
    }
    catch { $res.Error = $_.Exception.Message }
    $res
}

function Add-S12ChunkHits($Result, [string]$Text, [int]$FirstLine, [switch]$Json) {
    if ($Json) { $Text = ConvertFrom-S12JsonEscapes $Text }
    try { foreach ($h in @(Get-S12Hits -Text $Text -FirstLine $FirstLine)) { $Result.Hits.Add($h) } }
    catch { $Result.Error = "partial scan (lines from $FirstLine): $($_.Exception.Message)" }
}

#endregion

#region ---------- locations, parsers, git, ACL ----------

function New-S12Location {
    param([string]$Type, [string]$Tool, [string]$Path, [string]$Display, [string]$StoreId, [string]$StoreKind, [switch]$ExistsOnly)
    $loc = [pscustomobject]@{
        Type = $Type; Tool = $Tool; Path = $Path; Display = $(if ($Display) { $Display } else { Get-S12Display $Path })
        StoreId = $StoreId; StoreKind = $StoreKind; ExistsOnly = [bool]$ExistsOnly
        Hits = [Collections.Generic.List[object]]::new(); HistoryHits = [Collections.Generic.List[object]]::new(); HistoryScope = $null
        Lines = 0; Bytes = 0L; Skipped = $null; Error = $null
        Repo = $null; RepoRel = $null; GitHub = @(); Tracked = $null; InHistory = $null; OnRemote = $null; Ignored = $null; Public = $null
        Fixture = $false; Template = $false; Backup = $false; SecurityTooling = $false; Project = $null
        Facts = [ordered]@{}
    }
    $Locations.Add($loc)
    $loc
}

function Get-S12Meta([string]$Path) {
    try { $it = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return $null }
    [ordered]@{
        path = $it.FullName; display = (Get-S12Display $it.FullName); isDir = [bool]$it.PSIsContainer
        size = $(if ($it.PSIsContainer) { $null } else { $it.Length })
        createdUtc = $it.CreationTimeUtc.ToString('o'); modifiedUtc = $it.LastWriteTimeUtc.ToString('o')
        cloudOnly = [bool](Test-BvsCloudOnly $it)
    }
}

# Principals other than the user, SYSTEM, Administrators (and OWNER RIGHTS) with read access.
function Get-S12AclExtras([string]$Path) {
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $null }
    $readMask = 0x1 -bor 0x10000000 -bor [int]::MinValue   # ReadData | GENERIC_ALL | GENERIC_READ
    $out = foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $sid = $ace.IdentityReference.Value
        if ($AllowedAclSids.Contains($sid)) { continue }
        if (([int]$ace.FileSystemRights -band $readMask) -eq 0) { continue }
        $name = try { $ace.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { $sid }
        [ordered]@{ sid = $sid; name = $name; rights = [string]$ace.FileSystemRights; inherited = [bool]$ace.IsInherited }
    }
    , @($out)
}

function Get-S12JsonFields($Node, [string]$Name, [int]$Depth) {
    if ($Depth -gt 16 -or $null -eq $Node) { return }
    if ($Node -is [Collections.IDictionary]) { foreach ($k in @($Node.Keys)) { Get-S12JsonFields $Node[$k] ([string]$k) ($Depth + 1) }; return }
    if ($Node -is [string]) {
        if ($Name -and $JsonFieldRx.IsMatch($Name) -and -not $JsonFieldSkipRx.IsMatch($Name) -and (Test-S12SecretValue $Node)) { [pscustomobject]@{ Field = $Name; Value = $Node } }
        return
    }
    if ($Node -is [Collections.IEnumerable]) { foreach ($x in $Node) { Get-S12JsonFields $x $Name ($Depth + 1) } }
}

function Test-S12SecretValue([string]$Value) {
    if ($Value.Length -lt 12 -or $Value.Length -gt 8192) { return $false }
    if ($Value -match '\s') { return $false }
    if ($Value -match '^(https?|file|wss?)://' -and $Value -notmatch '://[^/@\s]+:[^/@\s]+@') { return $false }
    if ($Value -match '^[A-Za-z]:\\' -or $Value[0] -in '/', '~', '.') { return $false }
    if ($Value -match '^\d+$' -or $Value -match '^\d{4}-\d{2}-\d{2}') { return $false }
    if ($Value -notmatch '\d' -and $Value.Length -lt 24) { return $false }
    $true
}

function Get-S12LocHashes($Loc) {
    $set = [Collections.Generic.HashSet[string]]::new()
    foreach ($h in $Loc.Hits) { if ($h.Hash) { [void]$set.Add($h.Hash) } }
    , $set
}

function Add-S12ParsedHit($Loc, $Hit, $Have, [hashtable]$Extra) {
    if ($Hit.Hash -and $Have.Contains($Hit.Hash)) { return }
    if ($Hit.Hash) { [void]$Have.Add($Hit.Hash) }
    if ($Extra) { $Hit.Extra = $Extra }
    $Loc.Hits.Add($Hit)
}

# Structure-aware detection on top of Find-BvsSecrets. Values stay in memory; only names, hosts and masks
# are kept.
function Invoke-S12Parser($Loc, [string]$Parser) {
    $path = $Loc.Path
    $have = Get-S12LocHashes $Loc
    switch ($Parser) {
        'npmrc' {
            $lines = [IO.File]::ReadAllLines($path)
            $regByLine = @{}
            $entries = [Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]
                if ($l -match '^\s*//([^/:\s]+)[^=]*?:(_authToken|_auth|_password|username|email|certfile|keyfile)\s*=') {
                    $regByLine[$i + 1] = $Matches[1]
                    $entries.Add([ordered]@{ registry = $Matches[1]; key = $Matches[2]; line = $i + 1 })
                }
                elseif ($l -match '^\s*(@[^:\s=]+:)?registry\s*=\s*(\S+)') { $Loc.Facts['registryOverride'] = Protect-BvsUrl $Matches[2] }
                elseif ($l -match '^\s*strict-ssl\s*=\s*false\b') { $Loc.Facts['strictSslFalse'] = $true; $Loc.Facts['strictSslLine'] = $i + 1 }
                elseif ($l -match '^\s*always-auth\s*=\s*true\b') { $Loc.Facts['alwaysAuth'] = $true }
                elseif ($l -match '^\s*(cafile|ca)\s*=') { $Loc.Facts['customCa'] = $true }
            }
            $Loc.Facts['authEntries'] = @($entries)
            foreach ($h in $Loc.Hits) { if ($regByLine.ContainsKey($h.Line)) { $h.Extra = @{ registry = $regByLine[$h.Line] } } }
        }
        'docker' {
            $j = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            $Loc.Facts['credsStore'] = $j['credsStore']
            $Loc.Facts['credHelpers'] = @(if ($j['credHelpers']) { $j['credHelpers'].Keys })
            $regs = [Collections.Generic.List[object]]::new()
            if ($j['auths']) {
                foreach ($r in @($j['auths'].Keys)) {
                    $e = $j['auths'][$r]
                    $plain = @()
                    foreach ($f in 'auth', 'identitytoken', 'registrytoken', 'password') {
                        if ($e -is [Collections.IDictionary] -and $e[$f]) {
                            $plain += $f
                            Add-S12ParsedHit $Loc (New-S12Hit -Rule 'docker-auth' -Kind 'token' -Value ([string]$e[$f])) $have @{ registry = $r; field = $f }
                        }
                    }
                    $regs.Add([ordered]@{ registry = $r; plaintextFields = $plain })
                }
            }
            $Loc.Facts['auths'] = @($regs)
        }
        'kube' {
            $lines = [IO.File]::ReadAllLines($path)
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*(client-key-data|token|password|id-token|refresh-token|access-token|client-secret)\s*:\s*["'']?([^"''\s#]+)') {
                    $kind = if ($Matches[1] -eq 'client-key-data') { 'private-key' } else { 'token' }
                    $v = $Matches[2]
                    Add-S12ParsedHit $Loc (New-S12Hit -Rule 'kube-embedded-credential' -Kind $kind -Value $v -Masked (Protect-BvsSecret $v) -Line ($i + 1)) $have @{ field = $Matches[1] }
                }
                elseif ($lines[$i] -match '^\s*exec\s*:') { $Loc.Facts['execAuth'] = $true }
            }
        }
        'netrc' {
            $t = [IO.File]::ReadAllText($path)
            $Loc.Facts['machines'] = @([regex]::Matches($t, '(?m)\bmachine\s+(\S+)') | ForEach-Object { $_.Groups[1].Value })
            foreach ($m in [regex]::Matches($t, '(?m)\bpassword\s+(\S+)')) {
                $lineNo = ([regex]::Matches($t.Substring(0, $m.Index), "`n")).Count + 1
                Add-S12ParsedHit $Loc (New-S12Hit -Rule 'netrc-password' -Kind 'password' -Value $m.Groups[1].Value -Line $lineNo) $have $null
            }
        }
        'json' {
            $obj = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -Depth 64 -ErrorAction Stop
            foreach ($fv in @(Get-S12JsonFields $obj '' 0)) {
                $hit = New-S12Hit -Rule 'json-field' -Kind 'token' -Value $fv.Value -LinePrefix "$($fv.Field)="
                if (-not $hit.Hash) { continue }
                Add-S12ParsedHit $Loc $hit $have @{ field = $fv.Field }
            }
        }
        'raw' {
            if (@($Loc.Hits | Where-Object { -not $_.Placeholder }).Count -gt 0) { return }
            $t = ([IO.File]::ReadAllText($path)).Trim()
            if ($t.Length -ge 16 -and $t.Length -le 1024 -and $t -notmatch '\s') { Add-S12ParsedHit $Loc (New-S12Hit -Rule 'raw-token-file' -Kind 'token' -Value $t -Line 1) $have $null }
        }
        'gitconfig' {
            $t = [IO.File]::ReadAllText($path)
            $helpers = @([regex]::Matches($t, '(?im)^\s*helper\s*=\s*(.+?)\s*$') | ForEach-Object { Protect-BvsText $_.Groups[1].Value })
            $Loc.Facts['credentialHelpers'] = $helpers
            $Loc.Facts['credentialHelperStore'] = [bool](@($helpers | Where-Object { $_ -match '^store\b' }).Count)
        }
        'env' {
            $lines = [IO.File]::ReadAllLines($path)
            $hitLines = [Collections.Generic.HashSet[int]]::new()
            foreach ($h in $Loc.Hits) { [void]$hitLines.Add($h.Line) }
            $varByLine = @{}
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -notmatch '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$') { continue }
                $name = $Matches[1]
                $val = $Matches[2]
                $varByLine[$i + 1] = $name
                if ($hitLines.Contains($i + 1) -or -not $SecretNameRx.IsMatch($name)) { continue }
                if ($val -match '^"(.*)"\s*(#.*)?$') { $val = $Matches[1] }
                elseif ($val -match "^'(.*)'\s*(#.*)?$") { $val = $Matches[1] }
                else { $val = $val -replace '\s+#.*$', '' }
                if ($val.Length -lt 6 -or $val -match '\s' -or $val -match '^(?i:true|false|null|none|yes|no|\d+)$') { continue }
                if ($val -match '^[a-z][a-z0-9+.\-]*://' -and $val -notmatch '://[^/@\s]+:[^/@\s]+@') { continue }
                if ($val -match '^[A-Za-z]:\\' -or $val[0] -in '/', '.') { continue }
                $hit = New-S12Hit -Rule 'env-assignment' -Kind 'generic' -Value $val -Line ($i + 1) -LinePrefix "$name="
                Add-S12ParsedHit $Loc $hit $have @{ variable = $name }
            }
            foreach ($h in $Loc.Hits) {
                if ($varByLine.ContainsKey($h.Line)) {
                    if ($null -eq $h.Extra) { $h.Extra = @{} }
                    if (-not $h.Extra.ContainsKey('variable')) { $h.Extra['variable'] = $varByLine[$h.Line] }
                }
            }
        }
    }
}

function Invoke-S12ScanInto {
    param([Parameter(Mandatory)]$Loc, [string]$Parser, [switch]$Json, [switch]$CollectBackupMap, [scriptblock]$LineFilter, [long]$MaxBytes = $MaxScanBytes)
    $isJson = $Json -or ($Loc.Path -match '(?i)\.(json|jsonl)$')
    $r = Invoke-S12ScanFile -Path $Loc.Path -Json:$isJson -MaxBytes $MaxBytes -CollectBackupMap:$CollectBackupMap -LineFilter $LineFilter
    $Loc.Lines = $r.Lines; $Loc.Bytes = $r.Bytes; $Loc.Skipped = $r.Skipped; $Loc.Error = $r.Error
    foreach ($h in $r.Hits) { $Loc.Hits.Add($h) }
    if ($r.Skipped) {
        if ($r.Skipped -eq 'never-read') { $Loc.ExistsOnly = $true }
        elseif ($r.Skipped -notin 'missing', 'binary') { $Coverage.Add([ordered]@{ path = $Loc.Display; skipped = $r.Skipped }) }
        return
    }
    if ($r.Error) { $Coverage.Add([ordered]@{ path = $Loc.Display; error = (Protect-BvsText $r.Error) }) }
    if (-not $Parser -and $EnvNameRx.IsMatch([IO.Path]::GetFileName($Loc.Path))) { $Parser = 'env' }
    if ($Parser -and $Parser -ne 'ini') {
        try { Invoke-S12Parser -Loc $Loc -Parser $Parser }
        catch { $Loc.Error = "parser ${Parser}: $($_.Exception.Message)"; $Coverage.Add([ordered]@{ path = $Loc.Display; error = (Protect-BvsText $Loc.Error) }) }
    }
}

function Get-S12RepoRoot([string]$Folder) {
    $d = $Folder
    $visited = [Collections.Generic.List[string]]::new()
    $found = $null
    while ($d) {
        if ($RepoRootCache.ContainsKey($d)) { $found = $RepoRootCache[$d]; break }
        $visited.Add($d)
        if (Test-Path -LiteralPath (Join-Path $d '.git')) { $found = $d; break }
        $parent = [IO.Path]::GetDirectoryName($d)
        if (-not $parent -or $parent -eq $d) { break }
        $d = $parent
    }
    foreach ($v in $visited) { $RepoRootCache[$v] = $found }
    $found
}

function Test-S12FixturePath([string]$Path, [string]$Base) {
    $rel = if ($Base -and $Path.StartsWith($Base, [StringComparison]::OrdinalIgnoreCase)) { $Path.Substring($Base.Length) } elseif ($Path.StartsWith($UserHome, [StringComparison]::OrdinalIgnoreCase)) { $Path.Substring($UserHome.Length) } else { $Path }
    $segs = @($rel.Trim('\').Split('\'))
    for ($i = 0; $i -lt $segs.Count - 1; $i++) {
        $s = $segs[$i]
        if ($FixtureDirs.Contains($s)) { return $true }
        foreach ($p in $FixturePrefixes) { if ($s.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    }
    $false
}

function ConvertTo-S12GitHubRepo([string]$Url) {
    if ($Url -match '(?i)github\.com[:/]+([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]+?)(?:\.git)?/?$') {
        [pscustomobject]@{ owner = $Matches[1]; name = $Matches[2]; key = ('{0}/{1}' -f $Matches[1], $Matches[2]).ToLowerInvariant() }
    }
}

function Get-S12RepoInfo([string]$Repo) {
    if ($RepoFacts.Contains($Repo)) { return $RepoFacts[$Repo] }
    $remotes = [Collections.Generic.List[object]]::new()
    foreach ($l in @(git --no-optional-locks -C $Repo config --get-regexp '^remote\..*\.url$' 2>$null)) {
        $parts = ([string]$l) -split '\s+', 2
        if ($parts.Count -ne 2) { continue }
        $credHits = @(Find-BvsSecrets $parts[1] | Where-Object { $_.Rule -in 'url-credentials', 'github-token', 'github-fine-grained-pat', 'gitlab-token' })
        $remotes.Add([pscustomobject]@{
                name = ($parts[0] -replace '^remote\.', '' -replace '\.url$', '')
                url = (Protect-BvsUrl $parts[1])
                github = (ConvertTo-S12GitHubRepo $parts[1])
                embeddedCredential = [bool]$credHits.Count
                credentialMasked = @($credHits | ForEach-Object Masked)
            })
    }
    $remoteRefs = @(git --no-optional-locks -C $Repo for-each-ref --count=1 --format=%(refname) refs/remotes 2>$null)
    git --no-optional-locks -C $Repo check-ignore --no-index -q -- .env 2>$null | Out-Null
    $dotEnvIgnored = switch ($LASTEXITCODE) { 0 { $true } 1 { $false } default { $null } }
    $info = [pscustomobject]@{
        path = $Repo; display = (Get-S12Display $Repo); remotes = @($remotes); hasRemoteRefs = [bool]$remoteRefs.Count
        gitignoreCoversDotEnv = $dotEnvIgnored; github = @($remotes | Where-Object { $_.github } | ForEach-Object { $_.github })
    }
    $RepoFacts[$Repo] = $info
    $info
}

# git status for a group of locations in one repository: tracked (ls-files --error-unmatch), ignored
# (check-ignore --no-index), present in any history / in remote-tracking history, and the secrets that were
# actually committed (added lines of the file's history, scanned in memory).
function Update-S12GitStatus([string]$Repo, [object[]]$Locs) {
    $info = Get-S12RepoInfo $Repo
    $ascii = @($Locs | Where-Object { $_.RepoRel -match '^[\x20-\x7E]+$' } | ForEach-Object RepoRel)
    $histAll = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $histRemote = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($ascii.Count -gt 0) {
        foreach ($l in @(git --no-optional-locks -C $Repo log --all --format= --name-only -- @ascii 2>$null)) { if ($l) { [void]$histAll.Add(([string]$l).Trim()) } }
        if ($info.hasRemoteRefs) { foreach ($l in @(git --no-optional-locks -C $Repo log --remotes --format= --name-only -- @ascii 2>$null)) { if ($l) { [void]$histRemote.Add(([string]$l).Trim()) } } }
    }
    foreach ($loc in $Locs) {
        $rel = $loc.RepoRel
        git --no-optional-locks -C $Repo ls-files --error-unmatch -- $rel 2>$null | Out-Null
        $loc.Tracked = ($LASTEXITCODE -eq 0)
        git --no-optional-locks -C $Repo check-ignore --no-index -q -- $rel 2>$null | Out-Null
        $loc.Ignored = switch ($LASTEXITCODE) { 0 { $true } 1 { $false } default { $null } }
        if ($rel -match '^[\x20-\x7E]+$') {
            $loc.InHistory = $loc.Tracked -or $histAll.Contains($rel)
            $loc.OnRemote = $histRemote.Contains($rel)
        }
        else {
            $loc.InHistory = $loc.Tracked -or [bool](@(git --no-optional-locks -C $Repo log --all --format=%h -n 1 -- $rel 2>$null).Count)
            $loc.OnRemote = $info.hasRemoteRefs -and [bool](@(git --no-optional-locks -C $Repo log --remotes --format=%h -n 1 -- $rel 2>$null).Count)
        }
        $loc.GitHub = @($info.github)
        if ($loc.ExistsOnly -or -not ($loc.InHistory -or $loc.OnRemote)) { continue }
        $out = if ($loc.OnRemote) { @(git --no-optional-locks -C $Repo log --remotes -p --no-color --no-ext-diff --format=commit:%h -- $rel 2>$null) }
        else { @(git --no-optional-locks -C $Repo log --all -p --no-color --no-ext-diff --format=commit:%h -- $rel 2>$null) }
        $loc.HistoryScope = if ($loc.OnRemote) { 'remote-tracking refs' } else { 'local refs only' }
        $loc.Facts['historyCommits'] = @($out | Where-Object { ([string]$_).StartsWith('commit:', [StringComparison]::Ordinal) }).Count
        $added = [Text.StringBuilder]::new()
        foreach ($l in $out) {
            $s = [string]$l
            if ($s.Length -gt 0 -and $s[0] -eq '+' -and -not $s.StartsWith('+++', [StringComparison]::Ordinal)) { [void]$added.Append($s, 1, $s.Length - 1).Append([char]10) }
            if ($added.Length -gt 16MB) { $loc.Facts['historyTruncated'] = $true; break }
        }
        if ($added.Length -gt 0) {
            try { foreach ($h in @(Get-S12Hits -Text $added.ToString() -FirstLine 0)) { $h.Line = 0; $loc.HistoryHits.Add($h) } }
            catch { $loc.Facts['historyScanError'] = Protect-BvsText $_.Exception.Message }
        }
    }
}

function ConvertFrom-S12PublicKeyLine([string]$Line) {
    $m = [regex]::Match($Line, '^(?:(.*?)\s+)??((?:sk-)?(?:ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+)(?:@openssh\.com)?)\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$')
    if (-not $m.Success) { return $null }
    try { $blob = [Convert]::FromBase64String($m.Groups[3].Value) } catch { return $null }
    $type = $m.Groups[2].Value
    $bits = $null
    switch -Regex ($type) {
        'ed25519' { $bits = 256; break }
        'nistp256' { $bits = 256; break }
        'nistp384' { $bits = 384; break }
        'nistp521' { $bits = 521; break }
        '^ssh-dss' { $bits = 1024; break }
        '^ssh-rsa' {
            $o = 0
            $len = Read-S12UInt32 $blob $o; $o += 4 + $len
            $len = Read-S12UInt32 $blob $o; $o += 4 + $len
            $len = Read-S12UInt32 $blob $o
            if ($len -gt 0) {
                $first = $o + 4
                while ($first -lt $o + 4 + $len -and $blob[$first] -eq 0) { $first++ }
                $nbytes = $o + 4 + $len - $first
                $top = [int]$blob[$first]; $tb = 0
                while ($top -gt 0) { $tb++; $top = $top -shr 1 }
                $bits = ($nbytes - 1) * 8 + $tb
            }
        }
    }
    [ordered]@{
        type = $type; bits = $bits
        fingerprint = 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData($blob)).TrimEnd('=')
        comment = $m.Groups[4].Value.Trim(); options = $(if ($m.Groups[1].Success) { Protect-BvsText $m.Groups[1].Value } else { $null })
    }
}

function Get-S12FirstLine([string]$Path) {
    try {
        $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $sr = [IO.StreamReader]::new($fs); $sr.ReadLine() } finally { $fs.Dispose() }
    }
    catch { $null }
}

function Get-S12Recommendation([string]$Rule, [string]$Kind) {
    $r = $Cat.recommendations.$Rule
    if (-not $r -and $Kind -eq 'private-key') { $r = $Cat.recommendations.'private-key' }
    if (-not $r) { $r = $Cat.recommendations.'generic-assignment' }
    $r
}

#endregion

#region ---------- 1. home dotfiles, CLI token stores, agent configs, env vars, Credential Manager ----------

$null = Invoke-BvsCheck -Run $run -Id 'dotfiles.credential_stores' -Description 'Known CLI credential stores in the profile (npm, PyPI, Docker, cloud CLIs, Vercel, Netlify, Supabase, configstore, Hugging Face, Higgsfield, gh, Ollama key, agent auth files): token counts with masked samples; never-read files by existence/metadata/ACL only' -Script {
    foreach ($st in $Cat.stores) {
        $path = Expand-S12Path $st.path
        $row = [ordered]@{ id = $st.id; tool = $st.tool; kind = $st.kind; path = $path; display = (Get-S12Display $path); mode = $st.mode; exists = $false; readMode = $null; meta = $null; aclExtra = @(); files = @(); hits = 0; note = $null }
        $StoreRows.Add($row)
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $row.exists = $true
        $row.meta = Get-S12Meta $path
        $row.aclExtra = Get-S12AclExtras $path
        if ($row.meta.isDir) {
            $depth = if ($st.maxDepth) { [int]$st.maxDepth } else { 2 }
            $children = @(Get-BvsFiles -Path $path -MaxDepth $depth -NoPrune | Select-Object -First 200)
            $row.files = @($children | ForEach-Object { [ordered]@{ name = $_.FullName.Substring($path.Length).TrimStart('\'); size = $_.Length; modifiedUtc = $_.LastWriteTimeUtc.ToString('o') } })
            $row.readMode = 'listed'
            if ($st.mode -eq 'dir-scan') {
                $pats = @($st.include | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
                foreach ($c in $children) {
                    if (@($pats | Where-Object { $_.IsMatch($c.Name) }).Count -eq 0) { continue }
                    $loc = New-S12Location -Type 'cli-store' -Tool $st.tool -Path $c.FullName -StoreId $st.id -StoreKind $st.kind
                    $loc.Facts['aclExtra'] = Get-S12AclExtras $c.FullName
                    Invoke-S12ScanInto $loc -Parser $st.parser
                    $row.hits += $loc.Hits.Count
                }
                $row.readMode = 'scanned'
            }
            else {
                $loc = New-S12Location -Type 'cli-store' -Tool $st.tool -Path $path -StoreId $st.id -StoreKind $st.kind -ExistsOnly
                $loc.Facts['plaintextByDesign'] = [bool]$st.plaintextByDesign
                $loc.Facts['aclExtra'] = $row.aclExtra
                $loc.Facts['files'] = $row.files
            }
            continue
        }
        $neverRead = Test-BvsNeverRead $path
        if ($st.mode -eq 'exists' -or $neverRead) {
            $row.readMode = if ($neverRead) { 'never-read (existence only)' } else { 'existence only (catalog)' }
            $loc = New-S12Location -Type 'cli-store' -Tool $st.tool -Path $path -StoreId $st.id -StoreKind $st.kind -ExistsOnly
            $loc.Facts['plaintextByDesign'] = [bool]$st.plaintextByDesign
            $loc.Facts['aclExtra'] = $row.aclExtra
            $loc.Facts['meta'] = $row.meta
            continue
        }
        $loc = New-S12Location -Type 'cli-store' -Tool $st.tool -Path $path -StoreId $st.id -StoreKind $st.kind
        $loc.Facts['aclExtra'] = $row.aclExtra
        Invoke-S12ScanInto $loc -Parser $st.parser
        $row.readMode = if ($loc.Skipped) { "skipped: $($loc.Skipped)" } else { 'scanned' }
        $row.hits = $loc.Hits.Count
        if ($loc.Facts.Count -gt 1) { $row.note = 'see facts' }
    }
    @($StoreRows | Where-Object { $_.exists })
}

$null = Invoke-BvsCheck -Run $run -Id 'dotfiles.agent_configs' -Description 'AI-agent and editor configuration files (Claude Code, Claude Desktop, Codex, VS Code, Cursor, Windsurf, Gemini): secrets in MCP env blocks, headers, settings' -Script {
    $found = 0
    foreach ($ac in $Cat.agentConfigs) {
        $path = Expand-S12Path $ac.path
        $targets = @()
        if ($ac.dir) {
            if (-not [IO.Directory]::Exists($path)) { continue }
            $pats = @($ac.include | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
            $targets = @(Get-BvsFiles -Path $path -MaxDepth 1 -NoPrune | Where-Object { $n = $_.Name; @($pats | Where-Object { $_.IsMatch($n) }).Count -gt 0 } | ForEach-Object FullName)
        }
        elseif ([IO.File]::Exists($path)) { $targets = @($path) }
        foreach ($t in $targets) {
            $found++
            $loc = New-S12Location -Type 'agent-config' -Tool $ac.tool -Path $t -StoreId $ac.id
            $loc.Facts['aclExtra'] = Get-S12AclExtras $t
            Invoke-S12ScanInto $loc -Parser $ac.parser
        }
    }
    if ($found -eq 0) { Set-BvsCheckStatus -Id 'dotfiles.agent_configs' -Status not_applicable -Reason 'no agent configuration files found' }
    @($Locations | Where-Object Type -eq 'agent-config')
}

$null = Invoke-BvsCheck -Run $run -Id 'env.persistent_variables' -Description 'Persistent user and machine environment variables (registry) holding secret-looking values; names and masked values only' -Script {
    $keys = @('HKCU\Environment', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
    $scanned = 0
    foreach ($k in $keys) {
        foreach ($v in @(Get-BvsRegValues -Path $k)) {
            $scanned++
            $val = [string]$v.Value
            if (-not $val -or $val.Length -lt 8) { continue }
            $hits = @(Get-S12Hits -Text "$($v.Name)=$val")
            if ($hits.Count -eq 0 -and $SecretNameRx.IsMatch($v.Name) -and (Test-S12SecretValue $val)) { $hits = @(New-S12Hit -Rule 'env-var' -Kind 'token' -Value $val -LinePrefix "$($v.Name)=") }
            $hits = @($hits | Where-Object { -not $_.Placeholder -and -not $_.Reference })
            if ($hits.Count -eq 0) { continue }
            $loc = New-S12Location -Type 'env-var' -Tool 'Environment variable' -Path ("{0}\{1}" -f $k, $v.Name) -Display ("{0} : {1}" -f $k, $v.Name)
            foreach ($h in $hits) { $h.Line = 0; $h.Extra = @{ variable = $v.Name }; $loc.Hits.Add($h) }
        }
    }
    if ($scanned -eq 0) { Set-BvsCheckStatus -Id 'env.persistent_variables' -Status partial -Reason 'no environment values could be read' }
    @($Locations | Where-Object Type -eq 'env-var')
}

$CredTargets = [Collections.Generic.List[object]]::new()
$null = Invoke-BvsCheck -Run $run -Id 'dotfiles.credential_manager' -Description 'Windows Credential Manager: target NAMES only (cmdkey /list); shows which tools keep secrets in the OS store' -Script {
    $out = @(cmdkey /list 2>$null)
    if ($LASTEXITCODE -ne 0 -and $out.Count -eq 0) { throw "cmdkey /list failed (exit $LASTEXITCODE)" }
    foreach ($l in $out) {
        if ([string]$l -notmatch '^\s*[^:]{1,40}:\s*(([A-Za-z]+):)?(target|interactive|batch|service|network|domain)=(.+?)\s*$') { continue }
        $ctype = $Matches[2]; $tkind = $Matches[3]; $tname = $Matches[4]
        $tool = 'other'
        foreach ($t in $Cat.credentialTargetTools) { if ($tname -match $t.regex -or ($ctype -and $ctype -match $t.regex)) { $tool = $t.tool; break } }
        $CredTargets.Add([ordered]@{ target = (Protect-BvsText $tname); credentialType = $ctype; targetKind = $tkind; tool = $tool })
    }
    @($CredTargets)
}

#endregion

#region ---------- 2. repository secret files + 3. key-material files ----------

$RepoSweep = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
$KeySweep = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
$null = Invoke-BvsCheck -Run $run -Id 'repos.secret_files' -Description 'Repository secret files (.env family, project .npmrc/.pypirc/.netrc, .mcp.json, Claude project settings) under the search roots, skipping node_modules and tool caches: per-rule masked counts, git tracked/history/pushed, .gitignore coverage' -Script {
    $repoPats = @($Cat.repoFileIncludes | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
    $keyPats = @($Cat.keyFileIncludes | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
    $include = @($Cat.repoFileIncludes) + @($Cat.keyFileIncludes)
    $existingRoots = @($Roots | Where-Object { [IO.Directory]::Exists($_) })
    if (-not $existingRoots) { Set-BvsCheckStatus -Id 'repos.secret_files' -Status not_applicable -Reason 'no search root exists'; return }
    foreach ($f in (Get-BvsFiles -Path $existingRoots -PruneDirNames $Cat.pruneDirNames -Include $include)) {
        if (Test-S12Under $f.FullName $SelfPaths) { continue }
        $n = $f.Name
        if (@($repoPats | Where-Object { $_.IsMatch($n) }).Count -gt 0) { $RepoSweep[$f.FullName] = $f }
        elseif (@($keyPats | Where-Object { $_.IsMatch($n) }).Count -gt 0) { $KeySweep[$f.FullName] = $f }
    }
    # project-level agent files (.claude folders are pruned in the sweep): repo roots + projects known to Claude Code
    $projDirs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @($RepoSweep.Values)) { $r = Get-S12RepoRoot $f.DirectoryName; if ($r) { [void]$projDirs.Add($r) } }
    $cj = $Cat.agentConfigs | Where-Object { $_.id -eq 'claude-json' } | Select-Object -First 1
    if ($cj) {
        $cjPath = Expand-S12Path $cj.path
        if ([IO.File]::Exists($cjPath)) {
            try { $j = Get-Content -LiteralPath $cjPath -Raw | ConvertFrom-Json -AsHashtable -Depth 64; foreach ($k in @($j['projects'].Keys)) { [void]$projDirs.Add(([string]$k).Replace('/', '\').TrimEnd('\')) } } catch { $Coverage.Add([ordered]@{ path = (Get-S12Display $cjPath); error = 'could not parse project list' }) }
        }
    }
    foreach ($d in $projDirs) {
        if (Test-S12Under $d $SelfPaths) { continue }
        foreach ($rel in $Cat.projectAgentFiles) {
            $fp = Join-Path $d $rel
            if (-not $RepoSweep.ContainsKey($fp) -and [IO.File]::Exists($fp)) { $RepoSweep[$fp] = [IO.FileInfo]::new($fp) }
        }
    }
    foreach ($f in @($RepoSweep.Values)) {
        $tool = switch -Regex ($f.Name) {
            '^\.npmrc$' { 'npm config (project)'; break }
            '^\.mcp\.json$|^mcp\.json$' { 'MCP server config (project)'; break }
            '^settings(\.local)?\.json$' { 'Claude Code project settings'; break }
            '^CLAUDE\.local\.md$' { 'Claude Code local memory'; break }
            '^\.pypirc$' { 'PyPI config (project)'; break }
            '^\.netrc$' { 'netrc (project)'; break }
            '^\.yarnrc' { 'yarn config (project)'; break }
            '^\.dev\.vars$' { 'Cloudflare wrangler dev vars'; break }
            '^\.envrc$' { 'direnv'; break }
            default { 'dotenv' }
        }
        $loc = New-S12Location -Type 'repo-file' -Tool $tool -Path $f.FullName
        $loc.Repo = Get-S12RepoRoot $f.DirectoryName
        if ($loc.Repo) { $loc.RepoRel = [IO.Path]::GetRelativePath($loc.Repo, $f.FullName).Replace('\', '/') }
        $loc.Template = $TemplateRx.IsMatch($f.Name)
        $loc.Backup = $BackupNameRx.IsMatch($f.Name)
        $loc.Fixture = Test-S12FixturePath $f.FullName $loc.Repo
        $loc.SecurityTooling = Test-S12Under $f.FullName $SecurityToolingPaths
        $loc.Facts['meta'] = Get-S12Meta $f.FullName
        if (Test-BvsCloudOnly $f) { $loc.Skipped = 'cloud-only'; $Coverage.Add([ordered]@{ path = $loc.Display; skipped = 'cloud-only' }); continue }
        if (Test-BvsNeverRead $f.FullName) { $loc.ExistsOnly = $true; $loc.Skipped = 'never-read'; continue }
        $parser = switch -Regex ($f.Name) { '^\.npmrc$' { 'npmrc'; break } '\.json$' { 'json'; break } '^\.netrc$' { 'netrc'; break } default { $null } }
        Invoke-S12ScanInto $loc -Parser $parser
    }
    foreach ($g in @($Locations | Where-Object { $_.Type -eq 'repo-file' -and $_.Repo } | Group-Object Repo)) {
        try { Update-S12GitStatus -Repo $g.Name -Locs $g.Group }
        catch { $Coverage.Add([ordered]@{ path = (Get-S12Display $g.Name); error = "git: $(Protect-BvsText $_.Exception.Message)" }) }
    }
    # embedded credentials in remote URLs (.git\config)
    foreach ($ri in @($RepoFacts.Values)) {
        foreach ($rm in @($ri.remotes | Where-Object embeddedCredential)) {
            $loc = New-S12Location -Type 'repo-config' -Tool 'git remote URL' -Path (Join-Path $ri.path '.git\config') -Display ("{0}\.git\config (remote {1})" -f $ri.display, $rm.name)
            $loc.Repo = $ri.path
            foreach ($mk in $rm.credentialMasked) { $loc.Hits.Add([pscustomobject]@{ Rule = 'url-credentials'; Kind = 'password'; Tier = 'structured'; Masked = $mk; Line = 0; Placeholder = $false; Reference = $false; Note = $null; JwtRole = $null; JwtExpired = $null; JwtIss = $null; LocalHost = $false; PublicByDesign = $false; KeyFingerprint = $null; Hash = $null; Live = 'configured'; Extra = @{ remote = $rm.name } }) }
        }
    }
    @($Locations | Where-Object Type -eq 'repo-file')
}

$null = Invoke-BvsCheck -Run $run -Id 'repos.github_visibility' -Description 'Public/private status of the user''s own GitHub repositories behind local secret files (api.github.com via Invoke-BvsIntel; 404 = private or absent)' -Script {
    $gitLocs = @($Locations | Where-Object { $_.Type -in 'repo-file', 'key-file' -and $_.GitHub.Count -gt 0 })
    $pairs = @($RepoFacts.Values | ForEach-Object { $_.github } | Where-Object { $_ } | Sort-Object key -Unique)
    if ($pairs.Count -eq 0) { Set-BvsCheckStatus -Id 'repos.github_visibility' -Status not_applicable -Reason 'no GitHub remotes behind secret files'; return }
    if ($NoNetwork) { Set-BvsCheckStatus -Id 'repos.github_visibility' -Status skipped -Reason 'NoNetwork switch'; return }
    $users = [Collections.Generic.List[string]]::new()
    if ($GitHubUser) { foreach ($u in $GitHubUser) { $users.Add($u) }; $GitHubMeta.method = 'parameter' }
    else {
        $gu = @(git --no-optional-locks config --global --get github.user 2>$null) | Select-Object -First 1
        if ($gu) { $users.Add(([string]$gu).Trim()); $GitHubMeta.method = 'git config github.user' }
        else {
            $top = $pairs | Group-Object { $_.owner.ToLowerInvariant() } | Sort-Object Count -Descending | Select-Object -First 1
            if ($top -and ($top.Count / $pairs.Count) -ge 0.5) { $users.Add($top.Group[0].owner); $GitHubMeta.method = "inferred: owner of $($top.Count) of $($pairs.Count) GitHub remotes" }
        }
    }
    $users = @($users | Where-Object { $_ -match '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$' } | Sort-Object -Unique)
    $GitHubMeta.users = $users
    if ($users.Count -eq 0) { Set-BvsCheckStatus -Id 'repos.github_visibility' -Status skipped -Reason 'GitHub account unknown (pass -GitHubUser)'; return }
    $hdr = @{ Accept = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
    $listed = @{}
    $listOk = @{}
    foreach ($u in $users) {
        $listOk[$u.ToLowerInvariant()] = $false
        for ($page = 1; $page -le 5; $page++) {
            try {
                $GitHubMeta.listCalls++
                $r = Invoke-BvsIntel -Uri "https://api.github.com/users/$u/repos?per_page=100&type=owner&sort=full_name&page=$page" -Headers $hdr -SaveName "S12-github-repos-$u-p$page.json"
            }
            catch { $GitHubMeta.errors += (Protect-BvsText $_.Exception.Message); break }
            if ($r.Status -in 403, 429) { $GitHubMeta.rateLimited = $true; break }
            if ($r.Status -ne 200) { $GitHubMeta.errors += "list $u page ${page}: HTTP $($r.Status)"; break }
            $arr = @($r.Json)
            foreach ($x in $arr) { if ($x.name) { $listed[('{0}/{1}' -f $u, $x.name).ToLowerInvariant()] = [ordered]@{ public = (-not $x.private); visibility = $x.visibility; fork = [bool]$x.fork; archived = [bool]$x.archived; method = 'users/<user>/repos list' } } }
            $listOk[$u.ToLowerInvariant()] = $true
            if ($arr.Count -lt 100) { break }
        }
    }
    $selfSet = [Collections.Generic.HashSet[string]]::new([string[]]@($users | ForEach-Object { $_.ToLowerInvariant() }))
    foreach ($p in $pairs) {
        $own = $p.owner.ToLowerInvariant()
        if (-not $selfSet.Contains($own)) { $GitHubVis[$p.key] = [ordered]@{ repo = "$($p.owner)/$($p.name)"; public = $null; method = 'not checked (not the user''s account)' }; continue }
        if ($listed.ContainsKey($p.key)) { $v = $listed[$p.key]; $v['repo'] = "$($p.owner)/$($p.name)"; $GitHubVis[$p.key] = $v; continue }
        $GitHubVis[$p.key] = [ordered]@{ repo = "$($p.owner)/$($p.name)"; public = $(if ($listOk[$own]) { $false } else { $null }); method = $(if ($listOk[$own]) { 'absent from public list (private or absent)' } else { 'unknown' }) }
    }
    # per-repo confirmation (follows renames) for repos whose secret files reached a remote, max 10 calls
    $needs = @($gitLocs | Where-Object { $_.OnRemote -or $_.Tracked } | ForEach-Object { $_.GitHub } | Where-Object { $selfSet.Contains($_.owner.ToLowerInvariant()) -and $GitHubVis[$_.key].public -ne $true } | Sort-Object key -Unique | Select-Object -First 10)
    foreach ($p in $needs) {
        if ($GitHubMeta.rateLimited) { break }
        try {
            $GitHubMeta.perRepoCalls++
            $r = Invoke-BvsIntel -Uri "https://api.github.com/repos/$($p.owner)/$($p.name)" -Headers $hdr -SaveName "S12-github-repo-$($p.owner)-$($p.name).json"
            if ($r.Status -eq 200 -and $r.Json) { $GitHubVis[$p.key] = [ordered]@{ repo = "$($p.owner)/$($p.name)"; public = (-not $r.Json.private); visibility = $r.Json.visibility; fork = [bool]$r.Json.fork; archived = [bool]$r.Json.archived; method = 'repos/<owner>/<name>' } }
            elseif ($r.Status -eq 404) { $GitHubVis[$p.key] = [ordered]@{ repo = "$($p.owner)/$($p.name)"; public = $false; method = 'repos/<owner>/<name>: 404 (private or absent)' } }
            elseif ($r.Status -in 403, 429) { $GitHubMeta.rateLimited = $true }
        }
        catch { $GitHubMeta.errors += (Protect-BvsText $_.Exception.Message) }
    }
    foreach ($loc in $gitLocs) {
        $vals = @($loc.GitHub | ForEach-Object { if ($GitHubVis.ContainsKey($_.key)) { $GitHubVis[$_.key].public } })
        $loc.Public = if ($vals -contains $true) { $true } elseif ($vals.Count -gt 0 -and @($vals | Where-Object { $_ -eq $false }).Count -eq $vals.Count) { $false } else { $null }
    }
    if ($GitHubMeta.rateLimited -or $GitHubMeta.errors.Count -gt 0) { Set-BvsCheckStatus -Id 'repos.github_visibility' -Status partial -Reason ('GitHub API: ' + $(if ($GitHubMeta.rateLimited) { 'rate limited' } else { $GitHubMeta.errors[0] })) }
    @($GitHubVis.Values)
}

$null = Invoke-BvsCheck -Run $run -Id 'files.key_material' -Description 'Key-material files (*.key, *.pem, *.pfx/*.p12, *.ppk, *.ovpn, keystores, *-key/*-token/*-secret, id_* outside ~\.ssh): existence, metadata, ACL and git status only, never content' -Script {
    foreach ($f in @($KeySweep.Values)) {
        if ($f.DirectoryName.Equals($SshDir, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $n = $f.Name
        $kind = switch -Regex ($n) {
            '\.ovpn$' { 'OpenVPN profile (often embeds a client private key)'; break }
            '\.pem$' { 'PEM key or certificate'; break }
            '\.key$' { 'key file'; break }
            '\.(pfx|p12)$' { 'PKCS#12 bundle (normally password-protected)'; break }
            '\.ppk$' { 'PuTTY private key'; break }
            '\.(kdbx|kdb)$' { 'KeePass database (encrypted by design)'; break }
            '\.(jks|keystore)$' { 'Java/Android keystore (password-protected)'; break }
            '^id_(rsa|dsa|ecdsa|ed25519)' { 'SSH private key outside ~\.ssh'; break }
            '^wallet\.dat$' { 'cryptocurrency wallet'; break }
            '^\.git-credentials$' { 'git credential store (plaintext by design)'; break }
            '(token)$' { 'token file (name match)'; break }
            '(secret|secrets)$' { 'secret file (name match)'; break }
            default { 'key file (name match)' }
        }
        $loc = New-S12Location -Type 'key-file' -Tool $kind -Path $f.FullName -ExistsOnly
        $loc.Repo = Get-S12RepoRoot $f.DirectoryName
        if ($loc.Repo) { $loc.RepoRel = [IO.Path]::GetRelativePath($loc.Repo, $f.FullName).Replace('\', '/') }
        $loc.Fixture = Test-S12FixturePath $f.FullName $loc.Repo
        $loc.SecurityTooling = Test-S12Under $f.FullName $SecurityToolingPaths
        $loc.Facts['meta'] = Get-S12Meta $f.FullName
        $loc.Facts['neverRead'] = [bool](Test-BvsNeverRead $f.FullName)
        $loc.Facts['likelyBenign'] = $BenignKeyDirRx.IsMatch($f.FullName)
        $loc.Facts['aclExtra'] = Get-S12AclExtras $f.FullName
        if ($n -match '^id_(rsa|dsa|ecdsa|ed25519)' -and $n -notlike '*.pub' -and $f.Length -le 64KB) {
            $ki = Get-BvsSshKeyInfo -Path $f.FullName
            $loc.Facts['sshKey'] = [ordered]@{ format = $ki.Format; encrypted = $ki.Encrypted; cipher = $ki.Cipher; kdf = $ki.Kdf }
        }
    }
    foreach ($g in @($Locations | Where-Object { $_.Type -eq 'key-file' -and $_.Repo } | Group-Object Repo)) {
        try { Update-S12GitStatus -Repo $g.Name -Locs $g.Group }
        catch { $Coverage.Add([ordered]@{ path = (Get-S12Display $g.Name); error = "git: $(Protect-BvsText $_.Exception.Message)" }) }
    }
    # GitHub visibility for repos that only hold key files
    foreach ($loc in @($Locations | Where-Object { $_.Type -eq 'key-file' -and $_.GitHub.Count -gt 0 })) {
        $vals = @($loc.GitHub | ForEach-Object { if ($GitHubVis.ContainsKey($_.key)) { $GitHubVis[$_.key].public } })
        $loc.Public = if ($vals -contains $true) { $true } elseif ($vals.Count -gt 0 -and @($vals | Where-Object { $_ -eq $false }).Count -eq $vals.Count) { $false } else { $null }
    }
    @($Locations | Where-Object Type -eq 'key-file')
}

#endregion

#region ---------- 4. shell histories ----------

$null = Invoke-BvsCheck -Run $run -Id 'history.shell' -Description 'Shell and REPL histories (PSReadLine, bash, zsh, python, node, psql, mysql, sqlite, redis, mongosh): secret hits per rule with masked samples and line numbers' -Script {
    $n = 0
    foreach ($hf in $Cat.historyFiles) {
        $p = Expand-S12Path $hf.path
        $files = @()
        if ($hf.dir) {
            if ([IO.Directory]::Exists($p)) {
                $pats = @($hf.include | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
                $files = @(Get-BvsFiles -Path $p -MaxDepth 0 -NoPrune | Where-Object { $nm = $_.Name; @($pats | Where-Object { $_.IsMatch($nm) }).Count -gt 0 } | ForEach-Object FullName)
            }
        }
        elseif ([IO.File]::Exists($p)) { $files = @($p) }
        foreach ($f in $files) {
            $n++
            $loc = New-S12Location -Type 'shell-history' -Tool $hf.tool -Path $f
            $loc.Facts['meta'] = Get-S12Meta $f
            Invoke-S12ScanInto $loc -MaxBytes 512MB
        }
    }
    if ($n -eq 0) { Set-BvsCheckStatus -Id 'history.shell' -Status not_applicable -Reason 'no history files found' }
    @($Locations | Where-Object Type -eq 'shell-history')
}

#endregion

#region ---------- 5. Claude Code storage, Codex sessions, editor local history ----------

$null = Invoke-BvsCheck -Run $run -Id 'claude.transcripts' -Description 'Claude Code transcripts (~\.claude\projects: *.jsonl incl. subagents, tool-results, memory), streamed; this project''s own folder excluded' -Script {
    $pj = Expand-S12Path $Cat.transcripts.claudeProjects
    if (-not [IO.Directory]::Exists($pj)) { Set-BvsCheckStatus -Id 'claude.transcripts' -Status not_applicable -Reason 'no ~\.claude\projects'; return }
    $count = 0
    foreach ($proj in [IO.DirectoryInfo]::new($pj).EnumerateDirectories()) {
        foreach ($s in $proj.EnumerateFiles('*.jsonl')) { $SessionProject[$s.BaseName] = $proj.Name }
        $isSelf = $SelfTranscriptNames.Contains($proj.Name) -or @($SelfTranscriptNames | Where-Object { $proj.Name.StartsWith($_ + '--claude-worktrees-', [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        if ($isSelf) { $Coverage.Add([ordered]@{ path = (Get-S12Display $proj.FullName); excluded = 'this project (own activity)' }); continue }
        $isTooling = $ToolingTranscriptNames.Contains($proj.Name)
        foreach ($f in @(Get-BvsFiles -Path $proj.FullName -Include $Cat.transcripts.claudeProjectIncludes -NoPrune)) {
            $count++
            $loc = New-S12Location -Type 'claude-transcript' -Tool 'Claude Code transcript' -Path $f.FullName
            $loc.Project = $proj.Name
            $loc.SecurityTooling = $isTooling
            $loc.Facts['modifiedUtc'] = $f.LastWriteTimeUtc.ToString('o')
            Invoke-S12ScanInto $loc -Json:($f.Extension -in '.jsonl', '.json') -CollectBackupMap:($f.Extension -eq '.jsonl') -MaxBytes 4GB
        }
    }
    if ($count -eq 0) { Set-BvsCheckStatus -Id 'claude.transcripts' -Status not_applicable -Reason 'no transcripts outside this project' }
    @($Locations | Where-Object Type -eq 'claude-transcript')
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.file_history' -Description 'Claude Code file-history backups (copies of files Claude edited), mapped to original paths via transcripts; this project''s sessions excluded' -Script {
    $fh = Expand-S12Path $Cat.transcripts.claudeFileHistory
    if (-not [IO.Directory]::Exists($fh)) { Set-BvsCheckStatus -Id 'claude.file_history' -Status not_applicable -Reason 'no file-history folder'; return }
    foreach ($sess in [IO.DirectoryInfo]::new($fh).EnumerateDirectories()) {
        $proj = $SessionProject[$sess.Name]
        if ($proj -and $SelfTranscriptNames.Contains($proj)) { continue }
        foreach ($f in @(Get-BvsFiles -Path $sess.FullName -NoPrune)) {
            $orig = $BackupMap[($f.Name -split '@')[0]]
            if ($orig -and (Test-S12Under $orig $SelfPaths)) { continue }
            $loc = New-S12Location -Type 'claude-file-history' -Tool 'Claude Code file-history' -Path $f.FullName
            $loc.Project = $proj
            $loc.Facts['originalPath'] = $orig
            if ($orig) {
                $loc.Fixture = Test-S12FixturePath $orig (Get-S12RepoRoot ([IO.Path]::GetDirectoryName($orig)))
                $loc.SecurityTooling = Test-S12Under $orig $SecurityToolingPaths
                if (Test-BvsNeverRead $orig) { $loc.ExistsOnly = $true; $loc.Skipped = 'never-read (original path)'; continue }
            }
            Invoke-S12ScanInto $loc -Json:([bool]($orig -match '(?i)\.(json|jsonl)$')) -Parser $(if ($orig -and $EnvNameRx.IsMatch([IO.Path]::GetFileName($orig))) { 'env' } else { $null })
        }
    }
    @($Locations | Where-Object Type -eq 'claude-file-history')
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.prompt_history' -Description 'Claude Code prompt history (~\.claude\history.jsonl, this project''s lines skipped) and other small Claude stores (shell snapshots, session env, debug logs, plans, todos)' -Script {
    $found = 0
    $ph = Expand-S12Path $Cat.transcripts.claudePromptHistory
    if ([IO.File]::Exists($ph)) {
        $found++
        $loc = New-S12Location -Type 'claude-prompt-history' -Tool 'Claude Code prompt history' -Path $ph
        $filter = {
            param($l)
            if ($l -match '"project"\s*:\s*"((?:[^"\\]|\\.)*)"') { return (Test-S12Under ($Matches[1].Replace('\\', '\').Replace('/', '\')) $SelfPaths) }
            $false
        }
        Invoke-S12ScanInto $loc -Json -LineFilter $filter
    }
    foreach ($o in $Cat.transcripts.claudeOther) {
        $p = Expand-S12Path $o.path
        if (-not [IO.Directory]::Exists($p)) { continue }
        $pats = @($o.include | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
        foreach ($f in @(Get-BvsFiles -Path $p -MaxDepth 3 -NoPrune)) {
            $nm = $f.Name
            if (@($pats | Where-Object { $_.IsMatch($nm) }).Count -eq 0) { continue }
            $found++
            $loc = New-S12Location -Type 'claude-other' -Tool 'Claude Code local store' -Path $f.FullName
            Invoke-S12ScanInto $loc
        }
    }
    if ($found -eq 0) { Set-BvsCheckStatus -Id 'claude.prompt_history' -Status not_applicable -Reason 'no Claude prompt history or other stores' }
    @($Locations | Where-Object { $_.Type -in 'claude-prompt-history', 'claude-other' })
}

$null = Invoke-BvsCheck -Run $run -Id 'agents.codex_sessions' -Description 'OpenAI Codex CLI session transcripts (~\.codex\sessions) and history; sessions whose cwd is this project excluded. auth.json is existence-only (catalog)' -Script {
    $cs = Expand-S12Path $Cat.transcripts.codexSessions
    $files = [Collections.Generic.List[string]]::new()
    if ([IO.Directory]::Exists($cs)) { foreach ($f in (Get-BvsFiles -Path $cs -Include '*.jsonl' -NoPrune)) { $files.Add($f.FullName) } }
    foreach ($p in $Cat.transcripts.codexFiles) { $q = Expand-S12Path $p; if ([IO.File]::Exists($q)) { $files.Add($q) } }
    if ($files.Count -eq 0) { Set-BvsCheckStatus -Id 'agents.codex_sessions' -Status not_applicable -Reason 'no Codex sessions'; return }
    foreach ($f in $files) {
        $first = Get-S12FirstLine $f
        if ($first -and $first -match '"cwd"\s*:\s*"((?:[^"\\]|\\.)*)"' -and (Test-S12Under ($Matches[1].Replace('\\', '\')) $SelfPaths)) { $Coverage.Add([ordered]@{ path = (Get-S12Display $f); excluded = 'Codex session in this project' }); continue }
        $loc = New-S12Location -Type 'codex-session' -Tool 'Codex CLI session' -Path $f
        Invoke-S12ScanInto $loc -Json -MaxBytes 4GB
    }
    @($Locations | Where-Object Type -eq 'codex-session')
}

$null = Invoke-BvsCheck -Run $run -Id 'editor.local_history' -Description 'Editor Local History (VS Code, Cursor, Windsurf): saved copies of secret-bearing files (.env family, credential configs), found via entries.json' -Script {
    $namePats = @(@($Cat.repoFileIncludes) + @($Cat.editorHistoryNames) | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') })
    $roots = 0
    foreach ($eh in $Cat.editorHistory) {
        $base = Expand-S12Path $eh.path
        if (-not [IO.Directory]::Exists($base)) { continue }
        $roots++
        foreach ($folder in [IO.DirectoryInfo]::new($base).EnumerateDirectories()) {
            $ej = Join-Path $folder.FullName 'entries.json'
            if (-not [IO.File]::Exists($ej)) { continue }
            try { $e = Get-Content -LiteralPath $ej -Raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ([string]$e.resource -notmatch '^file:///(.+)$') { continue }
            $orig = [uri]::UnescapeDataString($Matches[1]).Replace('/', '\')
            $leaf = [IO.Path]::GetFileName($orig)
            if (@($namePats | Where-Object { $_.IsMatch($leaf) }).Count -eq 0) { continue }
            if (Test-S12Under $orig $SelfPaths) { continue }
            foreach ($en in @($e.entries)) {
                $copy = Join-Path $folder.FullName ([string]$en.id)
                if (-not [IO.File]::Exists($copy)) { continue }
                $loc = New-S12Location -Type 'editor-history' -Tool $eh.tool -Path $copy
                $loc.Facts['originalPath'] = $orig
                if ($en.timestamp) { try { $loc.Facts['savedUtc'] = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$en.timestamp).UtcDateTime.ToString('o') } catch { $loc.Facts['savedUtc'] = $null } }
                $loc.Fixture = Test-S12FixturePath $orig (Get-S12RepoRoot ([IO.Path]::GetDirectoryName($orig)))
                if ((Test-BvsNeverRead $orig) -or (Test-BvsNeverRead $copy)) { $loc.ExistsOnly = $true; $loc.Skipped = 'never-read'; continue }
                Invoke-S12ScanInto $loc -Parser $(if ($EnvNameRx.IsMatch($leaf)) { 'env' } else { $null }) -Json:([bool]($leaf -match '(?i)\.json$'))
            }
        }
    }
    if ($roots -eq 0) { Set-BvsCheckStatus -Id 'editor.local_history' -Status not_applicable -Reason 'no editor Local History folders' }
    @($Locations | Where-Object Type -eq 'editor-history')
}

#endregion

#region ---------- 6. SSH ----------

$SshConfigBlocks = [Collections.Generic.List[object]]::new()
$SshConfigIssues = [Collections.Generic.List[object]]::new()
$KnownHosts = [Collections.Generic.List[object]]::new()
$AuthorizedKeys = [Collections.Generic.List[object]]::new()
$SshDirInfo = $null

$null = Invoke-BvsCheck -Run $run -Id 'ssh.private_keys' -Description 'SSH private keys in ~\.ssh: passphrase protection via Get-BvsSshKeyInfo (cipher field only), file ACL principals beyond user/SYSTEM/Administrators' -Script {
    if (-not [IO.Directory]::Exists($SshDir)) { Set-BvsCheckStatus -Id 'ssh.private_keys' -Status not_applicable -Reason 'no ~\.ssh folder'; return }
    $script:SshDirInfo = [ordered]@{ path = $SshDir; aclExtra = (Get-S12AclExtras $SshDir) }
    foreach ($f in @(Get-ChildItem -LiteralPath $SshDir -File -Force)) {
        $n = $f.Name
        if ($n -like '*.pub' -or $n -like 'known_hosts*' -or $n -eq 'config' -or $n -like 'authorized_keys*' -or $n -like '*.sock') { continue }
        $info = if ($f.Length -le 64KB) { Get-BvsSshKeyInfo -Path $f.FullName } else { $null }
        $isKey = $info -and $info.Format -notin 'unknown', 'unreadable'
        if (-not $isKey -and $n -notmatch '^id_') {
            $SshKeys.Add([ordered]@{ name = $n; path = $f.FullName; format = $(if ($info) { $info.Format } else { 'not inspected (size)' }); isPrivateKey = $false; size = $f.Length; modifiedUtc = $f.LastWriteTimeUtc.ToString('o') })
            continue
        }
        $SshKeys.Add([ordered]@{
                name = $n; path = $f.FullName; isPrivateKey = $true
                format = $(if ($info) { $info.Format } else { $null }); encrypted = $(if ($info) { $info.Encrypted } else { $null })
                cipher = $(if ($info) { $info.Cipher } else { $null }); kdf = $(if ($info) { $info.Kdf } else { $null })
                type = $null; bits = $null; fingerprint = $null; comment = $null; fingerprintCheck = $null
                publicKeyFile = $(if ([IO.File]::Exists("$($f.FullName).pub")) { "$n.pub" } else { $null })
                size = $f.Length; createdUtc = $f.CreationTimeUtc.ToString('o'); modifiedUtc = $f.LastWriteTimeUtc.ToString('o')
                aclExtra = (Get-S12AclExtras $f.FullName); aclInheritanceProtected = $(try { (Get-Acl -LiteralPath $f.FullName).AreAccessRulesProtected } catch { $null })
                referencedByHosts = @()
            })
    }
    @($SshKeys | Where-Object { $_.isPrivateKey })
}

$null = Invoke-BvsCheck -Run $run -Id 'ssh.public_keys' -Description 'SSH public keys (*.pub): type, bits, SHA256 fingerprint (computed natively, cross-checked with ssh-keygen -l -f) and comment; stored for comparison with GitHub-registered keys (S13)' -Script {
    if (-not [IO.Directory]::Exists($SshDir)) { Set-BvsCheckStatus -Id 'ssh.public_keys' -Status not_applicable -Reason 'no ~\.ssh folder'; return }
    $out = [Collections.Generic.List[object]]::new()
    foreach ($f in @(Get-ChildItem -LiteralPath $SshDir -Filter '*.pub' -File -Force)) {
        $line = @(Get-Content -LiteralPath $f.FullName -TotalCount 1)[0]
        $pk = ConvertFrom-S12PublicKeyLine ([string]$line)
        if (-not $pk) { $out.Add([ordered]@{ name = $f.Name; error = 'unrecognised public key format' }); continue }
        $kg = $null
        try {
            $o = @(ssh-keygen -l -f $f.FullName 2>$null)
            if ($LASTEXITCODE -eq 0 -and $o.Count -gt 0) { $kg = ([string]$o[0] -split '\s+')[1] }
        }
        catch { $kg = $null }
        $pk['fingerprintCheck'] = if (-not $kg) { 'ssh-keygen unavailable' } elseif ($kg -ceq $pk.fingerprint) { 'match' } else { 'mismatch' }
        $pk['name'] = $f.Name
        $out.Add($pk)
        $privName = $f.Name.Substring(0, $f.Name.Length - 4)
        $priv = $SshKeys | Where-Object { $_.name -eq $privName -and $_.isPrivateKey } | Select-Object -First 1
        if ($priv) { $priv.type = $pk.type; $priv.bits = $pk.bits; $priv.fingerprint = $pk.fingerprint; $priv.comment = $pk.comment; $priv.fingerprintCheck = $pk.fingerprintCheck }
        else { $SshKeys.Add([ordered]@{ name = $f.Name; path = $f.FullName; isPrivateKey = $false; publicOnly = $true; type = $pk.type; bits = $pk.bits; fingerprint = $pk.fingerprint; comment = $pk.comment; fingerprintCheck = $pk.fingerprintCheck }) }
    }
    @($out)
}

$null = Invoke-BvsCheck -Run $run -Id 'ssh.config' -Description '~\.ssh\config: Host blocks with HostName, User, IdentityFile, ProxyCommand/ProxyJump, Local/Remote/DynamicForward, ForwardAgent, StrictHostKeyChecking' -Script {
    $cfg = Join-Path $SshDir 'config'
    if (-not [IO.File]::Exists($cfg)) { Set-BvsCheckStatus -Id 'ssh.config' -Status not_applicable -Reason 'no ~\.ssh\config'; return }
    $keep = 'hostname', 'user', 'port', 'identityfile', 'identitiesonly', 'proxycommand', 'proxyjump', 'localforward', 'remoteforward', 'dynamicforward', 'forwardagent', 'forwardx11', 'stricthostkeychecking', 'userknownhostsfile', 'passwordauthentication', 'permitlocalcommand', 'localcommand', 'certificatefile', 'addkeystoagent', 'identityagent', 'include'
    $cur = [ordered]@{ host = '(global)'; line = 0; options = [ordered]@{} }
    $SshConfigBlocks.Add($cur)
    $ln = 0
    foreach ($raw in [IO.File]::ReadAllLines($cfg)) {
        $ln++
        $l = $raw.Trim()
        if (-not $l -or $l[0] -eq '#') { continue }
        if ($l -notmatch '^(\S+?)\s*(?:=|\s)\s*(.*)$') { continue }
        $k = $Matches[1].ToLowerInvariant()
        $v = $Matches[2].Trim().Trim('"')
        if ($k -in 'host', 'match') { $cur = [ordered]@{ host = "$k $v"; line = $ln; options = [ordered]@{} }; $SshConfigBlocks.Add($cur); continue }
        if ($k -notin $keep) { continue }
        if (-not $cur.options.Contains($k)) { $cur.options[$k] = [Collections.Generic.List[string]]::new() }
        $cur.options[$k].Add((Protect-BvsText $v))
        switch ($k) {
            'forwardagent' { if ($v -match '^(yes|true)$' -or $v -match '^[\$/~%]') { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = 'ForwardAgent enabled'; severity = 'low' }) } }
            'stricthostkeychecking' { if ($v -match '^(no|off)$') { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = "StrictHostKeyChecking $v"; severity = 'low' }) } }
            'userknownhostsfile' { if ($v -match '(?i)^(/dev/null|NUL)$') { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = 'UserKnownHostsFile disabled'; severity = 'low' }) } }
            'proxycommand' { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = 'ProxyCommand runs a local command on connect'; severity = 'info' }) }
            'localcommand' { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = 'LocalCommand configured'; severity = 'info' }) }
            'remoteforward' { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = 'RemoteForward exposes a local port on the remote host'; severity = 'info' }) }
        }
        if ($k -eq 'identityfile') {
            $leaf = [IO.Path]::GetFileName(($v -replace '/', '\'))
            $kref = $SshKeys | Where-Object { $_.name -eq $leaf } | Select-Object -First 1
            if ($kref -and $kref.Contains('referencedByHosts')) { $kref.referencedByHosts += $cur.host }
            elseif (-not $kref) { $SshConfigIssues.Add([ordered]@{ host = $cur.host; line = $ln; issue = "IdentityFile not found in ~\.ssh: $leaf"; severity = 'info' }) }
        }
    }
    @($SshConfigBlocks)
}

$null = Invoke-BvsCheck -Run $run -Id 'ssh.known_hosts' -Description 'known_hosts entry counts (hashed vs plain) and authorized_keys entries (fingerprints, comments, options) in ~\.ssh' -Script {
    if (-not [IO.Directory]::Exists($SshDir)) { Set-BvsCheckStatus -Id 'ssh.known_hosts' -Status not_applicable -Reason 'no ~\.ssh folder'; return }
    foreach ($f in @(Get-ChildItem -LiteralPath $SshDir -File -Force | Where-Object { $_.Name -like 'known_hosts*' })) {
        $entries = 0; $hashed = 0; $markers = 0
        $hostSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($l in [IO.File]::ReadLines($f.FullName)) {
            $t = $l.Trim()
            if (-not $t -or $t[0] -eq '#') { continue }
            $entries++
            if ($t[0] -eq '@') { $markers++; $t = ($t -split '\s+', 2)[1] }
            $firstField = ($t -split '\s+', 2)[0]
            if ($firstField.StartsWith('|1|', [StringComparison]::Ordinal)) { $hashed++ } else { foreach ($hn in $firstField.Split(',')) { [void]$hostSet.Add($hn) } }
        }
        $KnownHosts.Add([ordered]@{ file = $f.Name; entries = $entries; hashedEntries = $hashed; uniquePlainHosts = $hostSet.Count; markers = $markers; modifiedUtc = $f.LastWriteTimeUtc.ToString('o') })
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $SshDir -File -Force | Where-Object { $_.Name -like 'authorized_keys*' })) {
        foreach ($l in [IO.File]::ReadLines($f.FullName)) {
            $t = $l.Trim()
            if (-not $t -or $t[0] -eq '#') { continue }
            $pk = ConvertFrom-S12PublicKeyLine $t
            if ($pk) { $pk['file'] = $f.Name; $AuthorizedKeys.Add($pk) }
        }
    }
    @($KnownHosts) + @($AuthorizedKeys)
}

#endregion

#region ---------- correlation, classification, findings ----------

function Get-S12Live($H, $Loc) {
    if ($H.Live) { return $H.Live }
    if ($H.Placeholder -or $H.Reference) { return 'no' }
    if ($H.Rule -eq 'jwt' -and ($H.JwtExpired -or $H.JwtRole -eq 'anon')) { return 'no' }
    if ($H.PublicByDesign) { return 'public' }
    if ($Loc.Fixture) { return 'fixture' }
    $strong = $H.Tier -ne 'weak'
    switch ($Loc.Type) {
        { $_ -in 'cli-store', 'env-var', 'repo-config' } { return 'configured' }
        'agent-config' { if ($strong) { return 'configured' }; return 'unknown' }
        'repo-file' {
            if ($Loc.Template) { if ($strong) { return 'likely' }; return 'unknown' }
            if ($H.LocalHost) { return 'local' }
            return 'configured'
        }
    }
    if ($H.Hash -and $Configured.Contains($H.Hash)) { return 'configured' }
    if ($H.Hash -and $FixtureHashes.Contains($H.Hash)) { return 'fixture' }
    if ($H.LocalHost) { return 'local' }
    if ($strong) { return 'likely' }
    'unknown'
}

function Get-S12HistoryLive($H, $Loc) {
    if ($H.Placeholder -or $H.Reference) { return 'no' }
    if ($H.Rule -eq 'jwt' -and ($H.JwtExpired -or $H.JwtRole -eq 'anon')) { return 'no' }
    if ($H.PublicByDesign) { return 'public' }
    if ($Loc.Fixture) { return 'fixture' }
    if ($H.Hash -and $Configured.Contains($H.Hash)) { return 'configured' }
    if ($H.LocalHost) { return 'local' }
    if ($Loc.Template -and $H.Tier -eq 'weak') { return 'unknown' }
    'historic'
}

function Get-S12BestLive($Hits) {
    $best = 'no'
    foreach ($h in $Hits) { if ($LiveRank[$h.Live] -gt $LiveRank[$best]) { $best = $h.Live } }
    $best
}

function Get-S12Evidence($Loc, [object[]]$Hits, [int]$Max = 12) {
    $out = foreach ($g in @($Hits | Group-Object Rule)) {
        $hs = @($g.Group)
        $lv = @($hs | Where-Object { $_.Live -in $LiveSet -or $_.Live -eq 'unknown' })
        $src = if ($lv.Count) { $lv } else { $hs }
        $ev = [ordered]@{
            type = 'secret'; location = $Loc.Display; path = $Loc.Path; rule = $g.Name; count = $hs.Count
            masked = @($src | ForEach-Object Masked | Select-Object -Unique -First 3)
            lines = @($src | Where-Object { $_.Line -gt 0 } | ForEach-Object Line | Select-Object -First 8)
            live = (Get-S12BestLive $hs)
            refs = @($src | Where-Object Hash | ForEach-Object { $RefIds[$_.Hash] } | Where-Object { $_ } | Select-Object -Unique -First 5)
        }
        $names = @($src | Where-Object { $_.Extra } | ForEach-Object { foreach ($k in 'variable', 'field', 'registry') { if ($_.Extra[$k]) { $_.Extra[$k] } } } | Select-Object -Unique -First 5)
        if ($names) { $ev['names'] = $names }
        $ev
    }
    @($out | Select-Object -First $Max)
}

function Get-S12FileEntity($Loc) {
    $m = $Loc.Facts['meta']
    if (-not $m) { $m = Get-S12Meta $Loc.Path }
    if ($m) { [ordered]@{ path = $Loc.Path; size = $m.size; created = $m.createdUtc; modified = $m.modifiedUtc } } else { [ordered]@{ path = $Loc.Path } }
}

$SecretRows = [Collections.Generic.List[object]]::new()
$null = Invoke-BvsCheck -Run $run -Id 'secrets.correlate' -Description 'Classify hits (configured / likely / historic / unknown / local / public / fixture / placeholder), correlate identical values across locations with run-local ids, build the secrets table and findings' -Script {
    # pass 1: currently configured credentials (stores, agent configs, env vars, working-copy repo files)
    foreach ($loc in $Locations) {
        if ($loc.Type -notin $ConfigTypes) { continue }
        foreach ($h in $loc.Hits) {
            $h.Live = Get-S12Live $h $loc
            if ($h.Live -eq 'configured' -and $h.Hash) {
                [void]$Configured.Add($h.Hash)
                if (-not $ConfiguredAt.ContainsKey($h.Hash)) { $ConfiguredAt[$h.Hash] = [Collections.Generic.List[string]]::new() }
                if (-not $ConfiguredAt[$h.Hash].Contains($loc.Display)) { $ConfiguredAt[$h.Hash].Add($loc.Display) }
            }
            if ($h.Live -eq 'fixture' -and $h.Hash) { [void]$FixtureHashes.Add($h.Hash) }
        }
    }
    # pass 2: everything else (transcripts, histories, backups) + committed history of repo files
    foreach ($loc in $Locations) {
        if ($loc.Type -notin $ConfigTypes) { foreach ($h in $loc.Hits) { $h.Live = Get-S12Live $h $loc } }
        foreach ($h in $loc.HistoryHits) { $h.Live = Get-S12HistoryLive $h $loc }
    }
    # run-local reference ids for identical values seen in several places
    $n = 0
    foreach ($loc in $Locations) {
        foreach ($pair in @(@($loc.Hits | ForEach-Object { , @($_, $false) }) + @($loc.HistoryHits | ForEach-Object { , @($_, $true) }))) {
            $h = $pair[0]
            if (-not $h.Hash -or $h.Live -in 'no', 'public') { continue }
            if (-not $RefIds.ContainsKey($h.Hash)) {
                $n++
                $RefIds[$h.Hash] = 'K{0:000}' -f $n
                $RefInfo[$RefIds[$h.Hash]] = [ordered]@{ ref = $RefIds[$h.Hash]; rule = $h.Rule; masked = $h.Masked; live = $h.Live; configuredAt = @(); locations = [ordered]@{} }
            }
            $ri = $RefInfo[$RefIds[$h.Hash]]
            $key = if ($pair[1]) { "$($loc.Display) [git history]" } else { $loc.Display }
            if (-not $ri.locations.Contains($key)) { $ri.locations[$key] = [ordered]@{ location = $key; type = $loc.Type; count = 0 } }
            $ri.locations[$key].count++
            if ($LiveRank[$h.Live] -gt $LiveRank[$ri.live]) { $ri.live = $h.Live }
            if ($ConfiguredAt.ContainsKey($h.Hash)) { $ri.configuredAt = @($ConfiguredAt[$h.Hash]) }
        }
    }
    # secrets table
    $showTypes = 'cli-store', 'env-var', 'agent-config', 'repo-file', 'repo-config'
    foreach ($loc in $Locations) {
        if ($loc.Hits.Count -eq 0) { continue }
        foreach ($g in @($loc.Hits | Group-Object Rule)) {
            $hs = @($g.Group)
            $liveHits = @($hs | Where-Object { $_.Live -in $LiveSet -or $_.Live -eq 'unknown' -or $_.Live -eq 'local' })
            if ($loc.Type -notin $showTypes -and $liveHits.Count -eq 0) { continue }
            $src = if ($liveHits.Count) { $liveHits } else { $hs }
            $names = @($src | Where-Object { $_.Extra } | ForEach-Object { foreach ($k in 'variable', 'field', 'registry') { if ($_.Extra[$k]) { $_.Extra[$k] } } } | Select-Object -Unique -First 8)
            $SecretRows.Add([ordered]@{
                    location = $loc.Display; path = $loc.Path; locationType = $loc.Type; tool = $loc.Tool
                    rule = $g.Name; kind = $hs[0].Kind; tier = $hs[0].Tier
                    count = $hs.Count; distinct = @($hs | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique).Count
                    live = (Get-S12BestLive $hs); liveCount = @($hs | Where-Object { $_.Live -in $LiveSet }).Count
                    placeholders = @($hs | Where-Object Placeholder).Count; references = @($hs | Where-Object Reference).Count
                    maskedSample = $src[0].Masked; maskedSamples = @($src | ForEach-Object Masked | Select-Object -Unique -First 3)
                    lines = @($src | Where-Object { $_.Line -gt 0 } | ForEach-Object Line | Select-Object -First 10)
                    refs = @($src | Where-Object Hash | ForEach-Object { $RefIds[$_.Hash] } | Where-Object { $_ } | Select-Object -Unique -First 5)
                    names = $names
                    jwtRoles = @($hs | Where-Object JwtRole | ForEach-Object JwtRole | Select-Object -Unique)
                    keyFingerprints = @($hs | Where-Object KeyFingerprint | ForEach-Object KeyFingerprint | Select-Object -Unique)
                    committed = $loc.Tracked; inHistory = $loc.InHistory; onRemote = $loc.OnRemote; public = $loc.Public; ignored = $loc.Ignored
                    committedSecrets = @($loc.HistoryHits | Where-Object { $_.Live -in $LiveSet }).Count
                    fixture = $loc.Fixture; template = $loc.Template; backup = $loc.Backup
                    repo = $(if ($loc.Repo) { Get-S12Display $loc.Repo } else { $null }); project = $loc.Project
                    recommendation = (Get-S12Recommendation $g.Name $hs[0].Kind)
                })
        }
    }
    @($SecretRows)
}

$ExpectedTooling = if ($SecurityToolingItem) { [ordered]@{ id = $SecurityToolingItem.id; reason = $SecurityToolingItem.reason; effect = 'fixture context' } } else { $null }
$FindingCount0 = $run.Findings.Count

# ---- A. package-registry credentials (npm and friends) ----
$NpmrcLocs = @($Locations | Where-Object { $_.Type -eq 'cli-store' -and $_.StoreKind -eq 'package-registry' -and -not $_.ExistsOnly })
foreach ($loc in $NpmrcLocs) {
    $live = @($loc.Hits | Where-Object { $_.Live -eq 'configured' })
    foreach ($g in @($live | Group-Object { if ($_.Extra -and $_.Extra['registry']) { $_.Extra['registry'] } else { $_.Rule } })) {
        $hs = @($g.Group)
        $refs = @($hs | Where-Object Hash | ForEach-Object { $RefInfo[$RefIds[$_.Hash]] } | Where-Object { $_ })
        $elsewhere = @($refs | ForEach-Object { $_.locations.Values } | Where-Object { $_.location -ne $loc.Display })
        $isGitHub = @($hs | Where-Object { $_.Rule -like 'github*' }).Count -gt 0
        $what = if ($isGitHub) { 'GitHub personal access token' } elseif (@($hs | Where-Object { $_.Rule -in 'npm-token', 'npmrc-auth' }).Count) { 'npm token' } else { 'package registry credential' }
        $reasons = @('plaintext_secret', 'package_registry_credential')
        if (@($elsewhere | Where-Object { $_.type -in 'claude-transcript', 'claude-file-history', 'claude-prompt-history', 'codex-session' }).Count) { $reasons += 'sent_to_model' }
        if (@($elsewhere | Where-Object { $_.type -eq 'shell-history' }).Count) { $reasons += 'shell_history' }
        $ev = @(Get-S12Evidence $loc $hs)
        if ($elsewhere.Count) { $ev += [ordered]@{ type = 'correlation'; note = 'same value also found here'; locations = @($elsewhere | Select-Object -First 15) } }
        $rec = if ($isGitHub) { $Cat.recommendations.'github-token' } else { $Cat.recommendations.'npm-token' }
        $rec = "$rec Any npm install script (and any agent or tool running as you) can read ~\.npmrc; worms such as Shai-Hulud harvested exactly these tokens to republish packages."
        if ($elsewhere.Count) { $rec = "Rotate now: the same value also appears in $($elsewhere.Count) other location(s) listed in the evidence. $rec" }
        New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity high -Class hardening -Confidence high `
            -Title ("Plaintext {0} in {1} for {2}" -f $what, $loc.Display, $g.Name) `
            -Reasons $reasons -Evidence $ev -Entities @{ files = @(Get-S12FileEntity $loc) } `
            -Recommendation $rec `
            -FpNotes 'S12 never uses the token, so it cannot tell whether it is still valid or what it may do: it may be revoked, read-only, expiring or scoped to one package. Storing a token in .npmrc is npm''s default after `npm login`, so this is a weakness, not a sign of attack.' `
            -Mitre @('T1552.001')
    }
    if ($loc.Facts['strictSslFalse']) {
        New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity medium -Class hardening -Confidence high `
            -Title ("npm TLS certificate verification is disabled (strict-ssl=false) in {0}" -f $loc.Display) `
            -Reasons @('tls_verification_disabled', 'plaintext_secret') `
            -Evidence @([ordered]@{ type = 'config'; path = $loc.Path; line = $loc.Facts['strictSslLine']; setting = 'strict-ssl=false'; tokensConfigured = $live.Count }) `
            -Entities @{ files = @(Get-S12FileEntity $loc) } `
            -Recommendation 'Remove strict-ssl=false. If HTTPS scanning by the antivirus (for example Avast Web Shield) breaks npm, trust its root explicitly instead: export it and set `npm config set cafile <file>` or NODE_EXTRA_CA_CERTS, or use Node''s --use-system-ca. With verification off, anyone who can intercept traffic can serve modified packages and capture the auth tokens npm sends.' `
            -FpNotes 'Often set on purpose to work around antivirus or corporate TLS interception. It is still a man-in-the-middle exposure for every npm request, including authenticated publish requests.' `
            -Mitre @('T1557')
    }
}

# ---- B. other credential stores ----
$storeLocs = @($Locations | Where-Object { $_.Type -eq 'cli-store' -and $_.StoreKind -ne 'package-registry' })
$mediumRules = @('docker-auth', 'kube-embedded-credential', 'aws-access-key-id', 'netrc-password', 'url-credentials')
foreach ($loc in @($storeLocs | Where-Object { -not $_.ExistsOnly })) {
    $hs = @($loc.Hits | Where-Object { $_.Live -eq 'configured' -and $_.Rule -in $mediumRules })
    if ($hs.Count -eq 0) { continue }
    $rule = $hs[0].Rule
    New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity medium -Class hardening -Confidence high `
        -Title ("Plaintext {0} credential in {1}" -f $loc.Tool, $loc.Display) `
        -Reasons @('plaintext_secret') -Evidence @(Get-S12Evidence $loc $hs) -Entities @{ files = @(Get-S12FileEntity $loc) } `
        -Recommendation (Get-S12Recommendation $rule $hs[0].Kind) `
        -FpNotes 'The credential may be expired or revoked; S12 does not test it. The tool may require this file format.' -Mitre @('T1552.001')
}
$lowStores = @($storeLocs | Where-Object { -not $_.ExistsOnly } | Where-Object { @($_.Hits | Where-Object { $_.Live -eq 'configured' -and $_.Rule -notin $mediumRules }).Count -gt 0 })
if ($lowStores.Count) {
    $ev = @($lowStores | ForEach-Object { $l = $_; Get-S12Evidence $l @($l.Hits | Where-Object { $_.Live -eq 'configured' }) 3 })
    New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity low -Class hardening -Confidence medium `
        -Title ("CLI login tokens stored in plaintext files by their tools ({0}: {1})" -f $lowStores.Count, (($lowStores | ForEach-Object Tool | Select-Object -Unique) -join ', ')) `
        -Reasons @('plaintext_secret') -Evidence $ev -Entities @{ files = @($lowStores | ForEach-Object { Get-S12FileEntity $_ }) } `
        -Recommendation 'These CLIs keep their session token in a plaintext file by design (no keyring option). Sign out (for example `vercel logout`) or revoke the session at the provider when you no longer need it, prefer short-lived or scoped tokens, and keep the files readable only by your account.' `
        -FpNotes 'This is the normal storage of these tools. Any process running as you can read them; that is the weakness, not evidence of misuse.' -Mitre @('T1552.001')
}
$byDesign = @($storeLocs | Where-Object { $_.ExistsOnly -and $_.Facts['plaintextByDesign'] -and $_.StoreId -notlike 'git-credential-store*' })
if ($byDesign.Count) {
    New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity info -Class info -Confidence high `
        -Title ("Agent/CLI credential files present (existence only, not opened): {0}" -f (($byDesign | ForEach-Object Tool) -join '; ')) `
        -Reasons @('plaintext_secret') `
        -Evidence @($byDesign | ForEach-Object { [ordered]@{ type = 'file'; path = $_.Path; tool = $_.Tool; size = $_.Facts['meta'].size; modified = $_.Facts['meta'].modifiedUtc; aclExtra = $_.Facts['aclExtra'] } }) `
        -Entities @{ files = @($byDesign | ForEach-Object { Get-S12FileEntity $_ }) } `
        -Recommendation 'No action needed beyond normal hygiene: these tools store OAuth/session tokens in files protected only by NTFS permissions. Sign out of tools you no longer use, and never paste these files into chats.' `
        -FpNotes 'Contents were not read (never-read list); the files may hold only refresh metadata.' -Mitre @('T1552.001')
}
foreach ($loc in @($storeLocs | Where-Object { $_.ExistsOnly -and $_.StoreId -like 'git-credential-store*' })) {
    New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity medium -Class hardening -Confidence high `
        -Title ("git credential-store file present: {0} (plaintext by design, not opened)" -f $loc.Display) `
        -Reasons @('plaintext_secret') -Evidence @([ordered]@{ type = 'file'; path = $loc.Path; size = $loc.Facts['meta'].size; modified = $loc.Facts['meta'].modifiedUtc }) `
        -Entities @{ files = @(Get-S12FileEntity $loc) } `
        -Recommendation 'Switch to Git Credential Manager (credential.helper=manager), revoke the tokens stored in this file at their providers, then delete the file yourself.' `
        -FpNotes 'The file may be empty or stale; it was not opened.' -Mitre @('T1552.001')
}
$aclLocs = @($Locations | Where-Object { $_.Type -in 'cli-store', 'agent-config' -and @($_.Facts['aclExtra']).Count -gt 0 })
foreach ($loc in $aclLocs) {
    New-BvsFinding -Run $run -Check 'dotfiles.credential_stores' -Severity medium -Class hardening -Confidence high `
        -Title ("Credential file readable by other accounts: {0}" -f $loc.Display) `
        -Reasons @('weak_acl', 'plaintext_secret') -Evidence @([ordered]@{ type = 'acl'; path = $loc.Path; principals = @($loc.Facts['aclExtra']) }) `
        -Entities @{ files = @(Get-S12FileEntity $loc) } `
        -Recommendation 'Remove the extra principals from the file''s permissions (Properties > Security) so only your account, SYSTEM and Administrators can read it, then rotate the credential if other people use this PC.' `
        -FpNotes 'Sandbox or service accounts may have been granted access deliberately (for example by a coding agent sandbox).' -Mitre @('T1552.001')
}

# ---- C. agent configs and env vars ----
$agentLocs = @($Locations | Where-Object { $_.Type -eq 'agent-config' -and @($_.Hits | Where-Object { $_.Live -eq 'configured' }).Count -gt 0 })
if ($agentLocs.Count) {
    New-BvsFinding -Run $run -Check 'dotfiles.agent_configs' -Severity low -Class hardening -Confidence medium `
        -Title ("API keys stored in AI-agent/editor configuration files ({0} files)" -f $agentLocs.Count) `
        -Reasons @('plaintext_secret') `
        -Evidence @($agentLocs | ForEach-Object { $l = $_; Get-S12Evidence $l @($l.Hits | Where-Object { $_.Live -eq 'configured' }) 4 }) `
        -Entities @{ files = @($agentLocs | ForEach-Object { Get-S12FileEntity $_ }) } `
        -Recommendation 'Move MCP server keys out of JSON configs into environment variable references or the tool''s secret storage, scope them narrowly, and rotate any key that was ever shared or committed.' `
        -FpNotes 'Several tools only support keys in their config files; the values may be test keys.' -Mitre @('T1552.001')
}
$envLocs = @($Locations | Where-Object { $_.Type -eq 'env-var' -and @($_.Hits | Where-Object { $_.Live -eq 'configured' }).Count -gt 0 })
if ($envLocs.Count) {
    New-BvsFinding -Run $run -Check 'env.persistent_variables' -Severity medium -Class hardening -Confidence medium `
        -Title ("Secrets in persistent environment variables ({0})" -f (($envLocs | ForEach-Object { $_.Display.Split(':')[-1].Trim() }) -join ', ')) `
        -Reasons @('plaintext_secret') -Evidence @($envLocs | ForEach-Object { $l = $_; Get-S12Evidence $l @($l.Hits) 2 }) `
        -Recommendation $Cat.recommendations.'env-var' `
        -FpNotes 'Some tools document persistent variables as the way to configure keys; the value may be a test key.' -Mitre @('T1552.001')
}

# ---- D. repository secret files ----
$repoLocs = @($Locations | Where-Object { $_.Type -eq 'repo-file' -and -not $_.ExistsOnly })
foreach ($loc in @($repoLocs | Where-Object { -not $_.Fixture })) {
    $committed = @($loc.HistoryHits | Where-Object { $_.Live -in 'configured', 'historic' -or ($_.Live -eq 'unknown' -and $_.Tier -ne 'weak') })
    $working = @($loc.Hits | Where-Object { $_.Live -in 'configured', 'likely' })
    $repoName = (@($loc.GitHub | ForEach-Object { "$($_.owner)/$($_.name)" }) | Select-Object -Unique) -join ', '
    if (-not $repoName -and $loc.Repo) { $repoName = Get-S12Display $loc.Repo }
    $ent = @{ files = @(Get-S12FileEntity $loc) }
    if ($committed.Count -gt 0 -and $loc.OnRemote) {
        $stillUsed = @($committed | Where-Object { $_.Live -eq 'configured' })
        $ev = @(Get-S12Evidence $loc $committed)
        $ev += [ordered]@{ type = 'git'; repo = $repoName; file = $loc.RepoRel; tracked = $loc.Tracked; historyScope = $loc.HistoryScope; commitsTouchingFile = $loc.Facts['historyCommits']; public = $loc.Public; stillInUse = $stillUsed.Count }
        if ($loc.Public -eq $true) {
            New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity high -Class suspicious -Confidence $(if (@($committed | Where-Object { $_.Tier -ne 'weak' }).Count) { 'high' } else { 'medium' }) `
                -Title ("Secrets committed to public GitHub repo {0}: {1} ({2} values, {3} still in use)" -f $repoName, $loc.RepoRel, @($committed | ForEach-Object Hash | Select-Object -Unique).Count, @($stillUsed | ForEach-Object Hash | Select-Object -Unique).Count) `
                -Reasons @('plaintext_secret', 'public_repo', 'committed_secret') -Evidence $ev -Entities $ent `
                -Recommendation 'Rotate every listed secret now (assume it was scraped: bots harvest public GitHub commits within minutes), starting with values still in use. Then remove the file from the repository, add it to .gitignore, and purge it from history (git filter-repo or BFG) and ask GitHub support to clear cached views; rotation is what actually fixes the exposure.' `
                -FpNotes 'Values that look generic may be non-secret settings; the repo may have been public only briefly. GitHub visibility comes from the unauthenticated API at scan time.' -Mitre @('T1552.001', 'T1593.003')
        }
        else {
            $vis = if ($loc.Public -eq $false) { 'private (or absent) GitHub repo' } else { 'remote repo of unknown visibility' }
            New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity medium -Class hardening -Confidence medium `
                -Title ("Secrets committed and pushed to {0} {1}: {2}" -f $vis, $repoName, $loc.RepoRel) `
                -Reasons @('plaintext_secret', 'committed_secret') -Evidence $ev -Entities $ent `
                -Recommendation 'Rotate the values still in use, stop tracking the file (git rm --cached, add to .gitignore) and purge it from history before the repository is ever shared, forked or made public.' `
                -FpNotes 'Visibility is unknown or private; collaborators, forks and CI logs may still have copies. Some values may be non-secret settings.' -Mitre @('T1552.001')
        }
    }
    elseif ($committed.Count -gt 0) {
        New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity medium -Class hardening -Confidence medium `
            -Title ("Secrets committed locally (not found in remote-tracking history): {0}" -f $loc.Display) `
            -Reasons @('plaintext_secret', 'committed_secret') -Evidence @(Get-S12Evidence $loc $committed) -Entities $ent `
            -Recommendation 'Before pushing: remove the file from the commits (git rm --cached and rewrite the local commits), add it to .gitignore, and rotate the values if the branch was pushed elsewhere.' `
            -FpNotes 'Remote-tracking refs may be stale; the commits may already be pushed from another clone.' -Mitre @('T1552.001')
    }
    elseif ($working.Count -gt 0 -and $loc.Tracked) {
        New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity low -Class hardening -Confidence medium `
            -Title ("Tracked file now contains secrets (next commit would publish them): {0}" -f $loc.Display) `
            -Reasons @('plaintext_secret') -Evidence @(Get-S12Evidence $loc $working) -Entities $ent `
            -Recommendation 'Stop tracking the file (git rm --cached), add it to .gitignore, and keep only a placeholder template in the repository.' `
            -FpNotes 'The committed version did not contain these values; nothing has been published yet.' -Mitre @('T1552.001')
    }
    elseif ($working.Count -gt 0 -and $loc.Repo -and $loc.Ignored -eq $false) {
        New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity low -Class hardening -Confidence high `
            -Title ("Secret file not covered by .gitignore (one `git add .` from being committed): {0}" -f $loc.Display) `
            -Reasons @('plaintext_secret') -Evidence @(Get-S12Evidence $loc $working) -Entities $ent `
            -Recommendation ("Add a pattern to the repo's .gitignore that covers this file (for example `.env*` with `!.env.example`){0}." -f $(if ($loc.Backup) { '; delete stale backup copies once you no longer need them' } else { '' })) `
            -FpNotes 'The file is not tracked today; a global gitignore outside the repo may still exclude it on this machine.' -Mitre @('T1552.001')
    }
}
$ignoredLive = @($repoLocs | Where-Object { -not $_.Fixture -and -not $_.Tracked -and -not $_.InHistory -and ($_.Ignored -or -not $_.Repo) -and @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count -gt 0 })
if ($ignoredLive.Count) {
    New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity info -Class info -Confidence high `
        -Title ("{0} local secret files (gitignored or outside git) hold live-looking values" -f $ignoredLive.Count) `
        -Reasons @('plaintext_secret') `
        -Evidence @($ignoredLive | ForEach-Object { [ordered]@{ type = 'file'; location = $_.Display; repo = $(if ($_.Repo) { Get-S12Display $_.Repo } else { $null }); ignored = $_.Ignored; liveValues = @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count; rules = @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' } | ForEach-Object Rule | Select-Object -Unique) } }) `
        -Entities @{ files = @($ignoredLive | ForEach-Object { Get-S12FileEntity $_ }) } `
        -Recommendation 'Normal for local development. Keep them out of chats and backups, delete stale copies (.env.bak-*), and prefer a secret manager (for example 1Password CLI or Doppler) for production keys.' `
        -FpNotes 'Plaintext .env files are the standard local-development pattern; listed for inventory.' -Mitre @('T1552.001')
}
$fixtureLocs = @($Locations | Where-Object { $_.Type -in 'repo-file', 'key-file' -and $_.Fixture })
if ($fixtureLocs.Count) {
    New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity info -Class info -Confidence medium `
        -Title ("{0} test-fixture files with secret-like values (classified as fixtures)" -f $fixtureLocs.Count) `
        -Reasons @('fixture') -Expected $ExpectedTooling `
        -Evidence @($fixtureLocs | ForEach-Object { [ordered]@{ type = 'file'; location = $_.Display; hits = $_.Hits.Count; tracked = $_.Tracked; public = $_.Public } } | Select-Object -First 30) `
        -Recommendation 'None, provided the values are fake. Make sure no real key was ever pasted into a fixture.' `
        -FpNotes 'Classified by path (test/fixture/example folders, vulnerable demo apps). A real key placed in such a folder would be missed here.' -Mitre @()
}
foreach ($loc in @($Locations | Where-Object { $_.Type -eq 'repo-config' })) {
    New-BvsFinding -Run $run -Check 'repos.secret_files' -Severity medium -Class hardening -Confidence high `
        -Title ("Git remote URL embeds a credential: {0}" -f $loc.Display) `
        -Reasons @('plaintext_secret') -Evidence @(Get-S12Evidence $loc @($loc.Hits)) `
        -Recommendation 'Rotate the token, then set the remote back to a plain https URL (git remote set-url origin https://github.com/<owner>/<repo>.git) and let Git Credential Manager store the credential.' `
        -FpNotes 'The token may be expired.' -Mitre @('T1552.001')
}

# ---- E. key-material files ----
$keyLocs = @($Locations | Where-Object { $_.Type -eq 'key-file' -and -not $_.Fixture -and -not $_.Facts['likelyBenign'] })
foreach ($loc in @($keyLocs | Where-Object { $_.Tracked -or $_.InHistory })) {
    $pub = $loc.Public -eq $true -and $loc.OnRemote
    $repoName = (@($loc.GitHub | ForEach-Object { "$($_.owner)/$($_.name)" }) | Select-Object -Unique) -join ', '
    New-BvsFinding -Run $run -Check 'files.key_material' -Severity $(if ($pub) { 'high' } else { 'medium' }) -Class $(if ($pub) { 'suspicious' } else { 'hardening' }) -Confidence medium `
        -Title ("Key file committed to git{0}: {1}" -f $(if ($pub) { " and pushed to public repo $repoName" } elseif ($loc.OnRemote) { " and pushed ($repoName)" } else { ' (local history)' }), $loc.Display) `
        -Reasons @('committed_secret') + @(if ($pub) { 'public_repo' }) `
        -Evidence @([ordered]@{ type = 'file'; path = $loc.Path; kind = $loc.Tool; tracked = $loc.Tracked; inHistory = $loc.InHistory; onRemote = $loc.OnRemote; public = $loc.Public; size = $loc.Facts['meta'].size }) `
        -Entities @{ files = @(Get-S12FileEntity $loc) } `
        -Recommendation 'Treat the key as exposed: generate a new key (re-encrypt anything it protects), remove the file from the repository and its history, and add the pattern to .gitignore.' `
        -FpNotes 'Contents were not read (never-read list): it may be a public certificate, a dummy or an already-retired key.' -Mitre @('T1552.004')
}
$keyOnDisk = @($keyLocs | Where-Object { -not $_.Tracked -and -not $_.InHistory })
if ($keyOnDisk.Count) {
    New-BvsFinding -Run $run -Check 'files.key_material' -Severity info -Class info -Confidence medium `
        -Title ("{0} key-material files on disk (existence only): {1}" -f $keyOnDisk.Count, (($keyOnDisk | Group-Object Tool | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; ')) `
        -Reasons @('key_material') `
        -Evidence @($keyOnDisk | ForEach-Object { [ordered]@{ type = 'file'; path = $_.Path; kind = $_.Tool; size = $_.Facts['meta'].size; modified = $_.Facts['meta'].modifiedUtc; repo = $(if ($_.Repo) { Get-S12Display $_.Repo } else { $null }); ignored = $_.Ignored; aclExtra = $_.Facts['aclExtra'] } } | Select-Object -First 40) `
        -Entities @{ files = @($keyOnDisk | ForEach-Object { Get-S12FileEntity $_ } | Select-Object -First 40) } `
        -Recommendation 'Confirm each file is needed. Keep encryption keys apart from the data they protect (a backup key next to its backup protects nothing), store VPN profiles and signing keystores in a password manager or encrypted vault, and delete duplicates.' `
        -FpNotes 'Files were not opened; names can match by accident (certificates, public keys, tool scripts).' -Mitre @('T1552.004')
}

# ---- F. histories, transcripts, backups ----
function New-S12ExposureFinding([string]$Check, [object[]]$Locs, [string]$What, [string]$Recommendation, [string]$FpNotes, [string[]]$ExtraReasons, [string[]]$Mitre, [string]$LowClass = 'hardening', [string]$Severity = 'medium') {
    $withLive = @($Locs | Where-Object { @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count -gt 0 })
    $withUnknown = @($Locs | Where-Object { @($_.Hits | Where-Object { $_.Live -eq 'unknown' }).Count -gt 0 })
    if ($withLive.Count -eq 0 -and $withUnknown.Count -eq 0) { return }
    $liveHits = @($withLive | ForEach-Object { $_.Hits } | Where-Object { $_.Live -in 'configured', 'likely' })
    $cfg = @($liveHits | Where-Object { $_.Live -eq 'configured' })
    $sev = if ($withLive.Count) { $Severity } else { 'low' }
    $byRule = @($liveHits | Group-Object Rule | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ rule = $_.Name; occurrences = $_.Count; distinct = @($_.Group | ForEach-Object Hash | Select-Object -Unique).Count; masked = @($_.Group | ForEach-Object Masked | Select-Object -Unique -First 3) } })
    $topFiles = @($withLive | Sort-Object { @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count } -Descending | Select-Object -First 10 | ForEach-Object { $l = $_; [ordered]@{ location = $l.Display; liveHits = @($l.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count; rules = @($l.Hits | Where-Object { $_.Live -in 'configured', 'likely' } | ForEach-Object Rule | Select-Object -Unique); lines = @($l.Hits | Where-Object { $_.Live -in 'configured', 'likely' -and $_.Line -gt 0 } | ForEach-Object Line | Select-Object -First 5); project = $l.Project; original = $l.Facts['originalPath'] } })
    $cfgRefs = @($cfg | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique | ForEach-Object { $ri = $RefInfo[$RefIds[$_]]; if ($ri) { [ordered]@{ ref = $ri.ref; rule = $ri.rule; masked = $ri.masked; configuredAt = $ri.configuredAt; seenIn = @($ri.locations.Values | Where-Object { $_.type -notin $ConfigTypes }).Count } } } | Select-Object -First 20)
    $keys = @($liveHits | Where-Object KeyFingerprint | ForEach-Object KeyFingerprint | Select-Object -Unique)
    $localKeys = @($keys | ForEach-Object { $fp = $_; $SshKeys | Where-Object { $_.fingerprint -eq $fp } | ForEach-Object name })
    $ev = @([ordered]@{ type = 'summary'; files = $Locs.Count; filesWithLiveSecrets = $withLive.Count; liveOccurrences = $liveHits.Count; distinctLiveValues = @($liveHits | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique).Count; currentlyConfiguredValues = @($cfg | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique).Count; byRule = $byRule })
    if ($cfgRefs.Count) { $ev += [ordered]@{ type = 'configured-credentials'; note = 'values that are also stored in a current config (dotfile, CLI store, .env)'; refs = $cfgRefs } }
    if ($keys.Count) { $ev += [ordered]@{ type = 'private-keys'; fingerprints = $keys; matchesLocalKeys = $localKeys } }
    $ev += [ordered]@{ type = 'files'; top = $topFiles }
    $title = if ($withLive.Count) { "{0}: {1} live-looking secret occurrences ({2} distinct, {3} currently configured) in {4} files" -f $What, $liveHits.Count, @($liveHits | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique).Count, @($cfg | Where-Object Hash | ForEach-Object Hash | Select-Object -Unique).Count, $withLive.Count } else { "{0}: possible secrets (generic assignments only) in {1} files" -f $What, $withUnknown.Count }
    if ($localKeys.Count) { $title += " incl. private key(s) $($localKeys -join ', ')" }
    New-BvsFinding -Run $run -Check $Check -Severity $sev -Class $(if ($withLive.Count) { 'hardening' } else { $LowClass }) -Confidence $(if ($cfg.Count) { 'high' } elseif ($withLive.Count) { 'medium' } else { 'low' }) `
        -Title $title -Reasons (@('plaintext_secret') + $ExtraReasons) -Evidence $ev `
        -Entities @{ files = @($withLive | Select-Object -First 25 | ForEach-Object { [ordered]@{ path = $_.Path } }) } `
        -Recommendation $Recommendation -FpNotes $FpNotes -Mitre $Mitre
}

New-S12ExposureFinding -Check 'history.shell' -Locs @($Locations | Where-Object Type -eq 'shell-history') -What 'Shell history' `
    -Recommendation 'Rotate the live values listed (ref ids show where else they appear). Then remove those lines from the history file yourself (PSReadLine: edit or clear the file listed; `Set-PSReadLineOption -AddToHistoryHandler` can skip lines with secrets), and pass secrets through environment variables or prompts instead of command-line arguments.' `
    -FpNotes 'History keeps commands you typed, including test or already-rotated tokens. Masked samples and line numbers let you check each one.' -ExtraReasons @('shell_history') -Mitre @('T1552.003')
New-S12ExposureFinding -Check 'claude.transcripts' -Locs @($Locations | Where-Object Type -eq 'claude-transcript') -What 'Claude Code transcripts' `
    -Recommendation 'Rotate every currently configured value listed (they were sent to the model provider and are stored in plaintext under ~\.claude\projects). Delete transcripts you no longer need, lower cleanupPeriodDays in ~\.claude\settings.json, and add deny rules such as "Read(./.env*)" and "Read(~/.npmrc)" to permissions so agents stop reading secret files.' `
    -FpNotes 'Hits include test keys, examples Claude produced, and secrets already rotated. "Currently configured" means the same value is stored in a config file today, so those are almost certainly live.' -ExtraReasons @('sent_to_model') -Mitre @('T1552.001')
New-S12ExposureFinding -Check 'claude.file_history' -Locs @($Locations | Where-Object Type -eq 'claude-file-history') -What 'Claude Code file-history backups' `
    -Recommendation 'These are copies of files Claude edited (their content also went to the model). Rotate live values, and delete old session folders under ~\.claude\file-history once you no longer need rewind.' `
    -FpNotes 'Backups may hold old versions with values that were since rotated.' -ExtraReasons @('sent_to_model') -Mitre @('T1552.001')
New-S12ExposureFinding -Check 'claude.prompt_history' -Locs @($Locations | Where-Object { $_.Type -in 'claude-prompt-history', 'claude-other' }) -What 'Claude Code prompt history and local stores' `
    -Recommendation 'Rotate the values you typed into prompts and remove those lines from ~\.claude\history.jsonl (or the listed store).' `
    -FpNotes 'May include example values.' -ExtraReasons @('sent_to_model') -Mitre @('T1552.001')
New-S12ExposureFinding -Check 'agents.codex_sessions' -Locs @($Locations | Where-Object Type -eq 'codex-session') -What 'Codex CLI sessions' `
    -Recommendation 'Rotate currently configured values that appear in Codex sessions and delete old session files under ~\.codex\sessions.' `
    -FpNotes 'May include example values or values already rotated.' -ExtraReasons @('sent_to_model') -Mitre @('T1552.001')
New-S12ExposureFinding -Check 'editor.local_history' -Locs @($Locations | Where-Object Type -eq 'editor-history') -What 'Editor Local History copies of secret files' -Severity low -LowClass 'hygiene' `
    -Recommendation 'Editors keep a copy of every save; .gitignore does not apply. Clear Local History for these files (VS Code: Explorer > Timeline, or delete the folders under %APPDATA%\Code\User\History) and exclude .env files via "workbench.localHistory.exclude".' `
    -FpNotes 'Local-only copies; they matter mostly for backups, sync and shared machines.' -ExtraReasons @('local_copy') -Mitre @('T1552.001')

# ---- G. SSH ----
$vmKeyItem = @(Get-BvsExpected -Category claudeConfig) | Where-Object { @($_.match.permissionsAllowContains) | Where-Object { $_ -like 'id_*' } } | Select-Object -First 1
foreach ($k in @($SshKeys | Where-Object { $_.isPrivateKey -and $_.encrypted -eq $false })) {
    $ctx = $null
    if ($vmKeyItem -and @($vmKeyItem.match.permissionsAllowContains) -contains $k.name) { $ctx = [ordered]@{ id = $vmKeyItem.id; reason = $vmKeyItem.reason; effect = 'context only (key used by an automation workflow)' } }
    New-BvsFinding -Run $run -Check 'ssh.private_keys' -Severity medium -Class hardening -Confidence high `
        -Title ("SSH private key without passphrase: ~\.ssh\{0} ({1} {2}, {3})" -f $k.name, $k.type, $k.fingerprint, $k.comment) `
        -Reasons @('unencrypted_key') -Expected $ctx `
        -Evidence @([ordered]@{ type = 'ssh-key'; path = $k.path; format = $k.format; cipher = $k.cipher; kdf = $k.kdf; fingerprint = $k.fingerprint; comment = $k.comment; aclExtra = $k.aclExtra; referencedByHosts = $k.referencedByHosts; modified = $k.modifiedUtc }) `
        -Entities @{ files = @([ordered]@{ path = $k.path; size = $k.size; created = $k.createdUtc; modified = $k.modifiedUtc }) } `
        -Recommendation ("Add a passphrase (ssh-keygen -p -f ~\.ssh\{0}) and load it into the Windows ssh-agent service, or move it to a hardware/FIDO key (ed25519-sk). On every server that trusts it, restrict the key in authorized_keys (from=, no-agent-forwarding, command=) and remove it where unused.{1}" -f $k.name, $(if ($ctx) { ' For automation keys that must stay unattended, restrict them on the server side (from="127.0.0.1", command=) instead.' } else { '' })) `
        -FpNotes 'Unattended automation (CI, VM access by an agent) often needs keys without a passphrase. Any process running as you, or anyone with a copy of the file or a backup, can use it.' -Mitre @('T1552.004')
}
foreach ($k in @($SshKeys | Where-Object { $_.isPrivateKey -and @($_.aclExtra).Count -gt 0 })) {
    New-BvsFinding -Run $run -Check 'ssh.private_keys' -Severity medium -Class hardening -Confidence high `
        -Title ("SSH private key readable by other accounts: ~\.ssh\{0}" -f $k.name) -Reasons @('weak_acl') `
        -Evidence @([ordered]@{ type = 'acl'; path = $k.path; principals = $k.aclExtra }) `
        -Recommendation 'Remove inherited/extra permissions so only your account and SYSTEM can read the key (OpenSSH for Windows refuses keys with loose permissions), then rotate it if other accounts are used.' `
        -FpNotes 'Administrators-only additions are expected; this lists other principals.' -Mitre @('T1552.004')
}
if ($SshDirInfo -and @($SshDirInfo.aclExtra).Count -gt 0) {
    New-BvsFinding -Run $run -Check 'ssh.private_keys' -Severity medium -Class hardening -Confidence high -Title '~\.ssh folder readable by other accounts' -Reasons @('weak_acl') `
        -Evidence @([ordered]@{ type = 'acl'; path = $SshDir; principals = $SshDirInfo.aclExtra }) -Recommendation 'Restrict the folder to your account, SYSTEM and Administrators.' -FpNotes 'Inherited from a custom profile ACL.' -Mitre @('T1552.004')
}
$sshLow = @($SshConfigIssues | Where-Object { $_.severity -eq 'low' })
if ($sshLow.Count) {
    New-BvsFinding -Run $run -Check 'ssh.config' -Severity low -Class hardening -Confidence high -Title ("Weak options in ~\.ssh\config: {0}" -f (($sshLow | ForEach-Object issue | Select-Object -Unique) -join ', ')) -Reasons @('ssh_config') `
        -Evidence @($sshLow) -Recommendation 'Disable ForwardAgent except for hosts you fully trust (use ProxyJump instead) and keep host-key checking on.' -FpNotes 'Lab hosts and disposable VMs are often configured this way on purpose.' -Mitre @('T1563.001')
}

# ---- H. Credential Manager inventory ----
if ($CredTargets.Count) {
    New-BvsFinding -Run $run -Check 'dotfiles.credential_manager' -Severity info -Class info -Confidence high `
        -Title ("Windows Credential Manager holds {0} entries ({1})" -f $CredTargets.Count, (($CredTargets | Group-Object tool | Sort-Object Count -Descending | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join ', ')) `
        -Reasons @('inventory') -Evidence @([ordered]@{ type = 'credential-manager'; targets = @($CredTargets) }) `
        -Recommendation 'No action: this is the protected (DPAPI) store and the preferred place for CLI credentials. Remove entries for tools you no longer use (Control Panel > Credential Manager).' `
        -FpNotes 'Target names only; no secrets were read.' -Mitre @('T1555.004')
}

#endregion

#region ---------- inventory and output ----------

$typeOrder = 'shell-history', 'claude-transcript', 'claude-file-history', 'claude-prompt-history', 'claude-other', 'codex-session', 'editor-history'
$exposureSummary = foreach ($t in $typeOrder) {
    $ls = @($Locations | Where-Object Type -eq $t)
    if ($ls.Count -eq 0) { continue }
    $hits = @($ls | ForEach-Object { $_.Hits })
    $mods = @($ls | ForEach-Object { $_.Facts['modifiedUtc'] } | Where-Object { $_ } | Sort-Object)
    [ordered]@{
        source = $t; files = $ls.Count; bytes = [long](($ls | Measure-Object Bytes -Sum).Sum); lines = [long](($ls | Measure-Object Lines -Sum).Sum)
        hits = $hits.Count; liveHits = @($hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count; configuredHits = @($hits | Where-Object { $_.Live -eq 'configured' }).Count
        unknownHits = @($hits | Where-Object { $_.Live -eq 'unknown' }).Count; placeholderOrReference = @($hits | Where-Object { $_.Live -eq 'no' }).Count
        fixtureHits = @($hits | Where-Object { $_.Live -eq 'fixture' }).Count; publicByDesign = @($hits | Where-Object { $_.Live -eq 'public' }).Count
        filesWithLive = @($ls | Where-Object { @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' }).Count -gt 0 }).Count
        liveByRule = [ordered]@{} + (@($hits | Where-Object { $_.Live -in 'configured', 'likely' } | Group-Object Rule) | ForEach-Object -Begin { $d = [ordered]@{} } -Process { $d[$_.Name] = $_.Count } -End { $d })
        skipped = @($ls | Where-Object Skipped).Count; errors = @($ls | Where-Object Error).Count
        oldestModifiedUtc = $(if ($mods) { $mods[0] } else { $null }); newestModifiedUtc = $(if ($mods) { $mods[-1] } else { $null })
    }
}

$repoFileRows = @($Locations | Where-Object { $_.Type -in 'repo-file', 'key-file' } | ForEach-Object {
        [ordered]@{
            path = $_.Path; location = $_.Display; type = $_.Type; tool = $_.Tool; repo = $(if ($_.Repo) { Get-S12Display $_.Repo } else { $null }); file = $_.RepoRel
            github = @($_.GitHub | ForEach-Object { "$($_.owner)/$($_.name)" } | Select-Object -Unique)
            tracked = $_.Tracked; inHistory = $_.InHistory; onRemote = $_.OnRemote; public = $_.Public; ignored = $_.Ignored
            fixture = $_.Fixture; template = $_.Template; backup = $_.Backup; securityToolingRepo = $_.SecurityTooling; existsOnly = $_.ExistsOnly; skipped = $_.Skipped
            hits = $_.Hits.Count; liveValues = @($_.Hits | Where-Object { $_.Live -in 'configured', 'likely' } | ForEach-Object Hash | Select-Object -Unique).Count
            committedSecretValues = @($_.HistoryHits | Where-Object { $_.Live -in $LiveSet } | ForEach-Object Hash | Select-Object -Unique).Count
            committedRules = @($_.HistoryHits | Where-Object { $_.Live -in $LiveSet } | ForEach-Object Rule | Select-Object -Unique)
            historyScope = $_.HistoryScope; historyCommits = $_.Facts['historyCommits']; kind = $(if ($_.Type -eq 'key-file') { $_.Tool } else { $null })
            sshKey = $_.Facts['sshKey']; size = $_.Facts['meta'].size; modifiedUtc = $_.Facts['meta'].modifiedUtc
        }
    })

$storeFacts = @($Locations | Where-Object { $_.Type -in 'cli-store', 'agent-config' -and $_.Facts.Count -gt 0 } | ForEach-Object {
        $f = [ordered]@{}
        foreach ($k in $_.Facts.Keys) { if ($k -notin 'meta', 'files') { $f[$k] = $_.Facts[$k] } }
        [ordered]@{ location = $_.Display; tool = $_.Tool; facts = $f }
    })

Add-BvsInventory -Run $run -Name 'secrets' -Data @($SecretRows)
Add-BvsInventory -Run $run -Name 'secretRefs' -Data @($RefInfo.Values | Where-Object { $_.locations.Count -ge 2 -or $_.live -eq 'configured' } | ForEach-Object { [ordered]@{ ref = $_.ref; rule = $_.rule; masked = $_.masked; live = $_.live; configuredAt = $_.configuredAt; locationCount = $_.locations.Count; locations = @($_.locations.Values | Select-Object -First 25) } })
Add-BvsInventory -Run $run -Name 'sshKeys' -Data @($SshKeys)
Add-BvsInventory -Run $run -Name 'ssh' -Data ([ordered]@{ folder = $SshDirInfo; config = @($SshConfigBlocks); configIssues = @($SshConfigIssues); knownHosts = @($KnownHosts); authorizedKeys = @($AuthorizedKeys); agentService = $(try { $s = Get-Service -Name 'ssh-agent' -ErrorAction Stop; [ordered]@{ status = [string]$s.Status; startType = [string]$s.StartType } } catch { $null }) })
Add-BvsInventory -Run $run -Name 'credentialStores' -Data @($StoreRows | ForEach-Object { $r = $_; [ordered]@{ id = $r.id; tool = $r.tool; kind = $r.kind; path = $r.path; display = $r.display; mode = $r.mode; exists = $r.exists; readMode = $r.readMode; size = $(if ($r.meta) { $r.meta.size } else { $null }); modifiedUtc = $(if ($r.meta) { $r.meta.modifiedUtc } else { $null }); aclExtra = $r.aclExtra; files = $r.files; hits = $r.hits } })
Add-BvsInventory -Run $run -Name 'credentialStoreFacts' -Data $storeFacts
Add-BvsInventory -Run $run -Name 'credentialManagerTargets' -Data @($CredTargets)
Add-BvsInventory -Run $run -Name 'repoFiles' -Data $repoFileRows
Add-BvsInventory -Run $run -Name 'repos' -Data @($RepoFacts.Values | ForEach-Object { [ordered]@{ path = $_.path; display = $_.display; remotes = @($_.remotes | ForEach-Object { [ordered]@{ name = $_.name; url = $_.url; embeddedCredential = $_.embeddedCredential } }); hasRemoteRefs = $_.hasRemoteRefs; gitignoreCoversDotEnv = $_.gitignoreCoversDotEnv; github = @($_.github | ForEach-Object { $k = $_.key; [ordered]@{ repo = "$($_.owner)/$($_.name)"; public = $(if ($GitHubVis.ContainsKey($k)) { $GitHubVis[$k].public } else { $null }); method = $(if ($GitHubVis.ContainsKey($k)) { $GitHubVis[$k].method } else { 'not checked' }) } }) } })
Add-BvsInventory -Run $run -Name 'githubLookup' -Data $GitHubMeta
Add-BvsInventory -Run $run -Name 'exposureSummary' -Data @($exposureSummary)
Add-BvsInventory -Run $run -Name 'coverage' -Data ([ordered]@{
        searchRoots = $Roots; excludedPaths = @($SelfPaths); excludedTranscriptFolders = @($SelfTranscriptNames); securityToolingPaths = @($SecurityToolingPaths)
        notes = @($Coverage | Select-Object -First 200); locationsScanned = $Locations.Count
        backupMapEntries = $BackupMap.Count; fileHistoryMapped = @($Locations | Where-Object { $_.Type -eq 'claude-file-history' -and $_.Facts['originalPath'] }).Count
        fileHistoryUnmapped = @($Locations | Where-Object { $_.Type -eq 'claude-file-history' -and -not $_.Facts['originalPath'] }).Count
        notCovered = @('Browser password stores and cookies (never-read)', 'DPAPI/Credential Manager secrets (names only)', 'SQLite stores (Codex logs/state, VS Code state.vscdb, IPython history)', 'WSL distributions (\\wsl$ not touched to avoid starting them)', 'Other drives unless passed in -SearchRoots', 'git history of files that no longer exist in the working tree')
    })

$summary = Complete-BvsRun -Run $run
$swTotal.Stop()

# console summary (masked, short)
"S12 secrets: {0} findings [{1}] checks={2} errors={3} runtime={4:N0}s" -f $summary.Findings, $summary.BySeverity, $summary.Checks, $summary.Errors, $swTotal.Elapsed.TotalSeconds
foreach ($c in $run.Checks) { if ($c.status -ne 'ok') { "  check {0}: {1} {2}" -f $c.id, $c.status, $c.reason } }
$sevOrder = @{ critical = 0; high = 1; medium = 2; low = 3; info = 4 }
foreach ($f in @($run.Findings | Sort-Object { $sevOrder[$_.severity] } | Select-Object -First 24)) { Protect-BvsText ("  [{0}/{1}] {2}" -f $f.severity, $f.class, $f.title) }
"  output: $($summary.Path)"

#endregion
