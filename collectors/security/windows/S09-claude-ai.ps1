#Requires -Version 7.2
<#
.SYNOPSIS
    S09 - Claude Code & AI tools (read-only). Playbook: docs\playbooks\S09-claude-ai.md
.DESCRIPTION
    Install integrity, settings/hooks/env/permissions (user, project, managed), MCP servers (Claude, Codex, Cursor,
    VS Code, Claude Desktop, Gemini, Windsurf), plugins, skills, instruction/memory files, a streaming transcript
    IoC sweep, local state (IDE locks, Remote Control, hook endpoints) and the account-connector reminder.
    Safety: never opens credential stores (config\never-read.json + Claude session keys + Codex sandbox secrets);
    ~\.claude.json is parsed in-process and account identifiers are dropped before anything is stored; everything
    read is untrusted data; this project's folder, scratch dir and transcripts are excluded.
    IoC lists live in S09-claude-ai.iocs.json (shared with a future Linux collector).
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S09-claude-ai.ps1
#>
[CmdletBinding()]
param([int]$TranscriptBudgetSec = 900, [int]$MaxSamples = 8, [switch]$SkipTranscripts)
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$ErrorActionPreference = 'Continue'
$run = Initialize-BvsRun -Module S09 -Area security
$Ioc = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'S09-claude-ai.iocs.json') -Raw | ConvertFrom-Json
$UP = $env:USERPROFILE
$CD = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { Join-Path $UP '.claude' }
$CJ = if ($env:CLAUDE_CONFIG_DIR) { Join-Path $env:CLAUDE_CONFIG_DIR '.claude.json' } else { Join-Path $UP '.claude.json' }
$PD = Join-Path $CD 'projects'
$Root = (Get-BvsRoot).TrimEnd('\')
$OC = [StringComparison]::OrdinalIgnoreCase
$O = [Text.RegularExpressions.RegexOptions]'Compiled, IgnoreCase, CultureInvariant'
function New-Rx([object[]]$p) { [regex]::new(((@($p) | Where-Object { $_ }) -join '|'), $O, [TimeSpan]::FromSeconds(10)) }
$RX = @{
    Exfil = New-Rx $Ioc.exfilDomains; Skip = New-Rx $Ioc.skipPermissionFlags; Hunt = New-Rx $Ioc.fileHuntTerms
    Local = New-Rx $Ioc.localPathMarkers; Remote = New-Rx $Ioc.remoteContextMarkers; Cred = New-Rx $Ioc.credentialFiles
    Verb = New-Rx @($Ioc.readVerbs); Net = New-Rx $Ioc.networkVerbs; Post = New-Rx $Ioc.postVerbs
    Inject = New-Rx $Ioc.injectionPhrases; Hide = New-Rx $Ioc.hidePhrases; ExfilI = New-Rx $Ioc.exfilInstructionPhrases
    Def = New-Rx @($Ioc.defensiveContext); Exec = New-Rx $Ioc.execPatterns; Pipe = New-Rx $Ioc.pipeToShell; Enc = New-Rx $Ioc.encodedCommand
    Reserved = New-Rx $Ioc.reservedTestHosts
    Url = [regex]::new('\b(?:https?|wss?)://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-_]+)(?::[0-9]+|:\$\{[^}]+\})?[^\s"''`<>)\]]*', $O)
    B64 = [regex]::new('[A-Za-z0-9+/]{200,}={0,2}', 'Compiled')
    Inv = [regex]::new('(?:[​-‏‪-‮⁦-⁩︀-️]|\uDB40[\uDC00-\uDDEF])+', 'Compiled')
}
$RX.Strong = [regex]::new(($RX.Exfil.ToString(), $RX.Skip.ToString(), '"name":"mcp__') -join '|', $O)
$RX.Weak = [regex]::new(($RX.Net.ToString(), $RX.Cred.ToString()) -join '|', $O)

# ---------- own-activity exclusion and never-read ----------
$OwnSlug = $Root -replace '[^A-Za-z0-9]', '-'
$Own = [Collections.Generic.List[string]]::new()
foreach ($p in @($Root, (Join-Path $PD $OwnSlug), (Join-Path ([IO.Path]::GetTempPath()) "claude\$OwnSlug"))) { $Own.Add($p.TrimEnd('\')) }
foreach ($e in @(Get-BvsExpected -Category path)) {
    $ps = @($e.match.paths | Where-Object { $_ } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') })
    if ($ps -contains $Root) { foreach ($p in $ps) { $Own.Add($p) } }
}
function Test-Own([string]$p) { if (-not $p) { return $false }; foreach ($d in $Own) { if ($p.Equals($d, $OC) -or $p.StartsWith($d + '\', $OC)) { return $true } }; $false }
$DenyRx = [regex]::new('\\\.claude\\sessions\\[^\\]+\.key$|\\\.codex\\\.sandbox-secrets(\\|$)|\\\.codex\\cap_sid$', 'IgnoreCase')
function Test-NoRead([string]$p) { (Test-BvsNeverRead $p) -or $DenyRx.IsMatch($p) }

# ---------- helpers ----------
function Get-L($x) { if ($null -eq $x) { return }; if ($x -is [string] -or $x -is [Collections.IDictionary]) { return $x }; foreach ($y in $x) { if ($null -ne $y) { $y } } }
function Read-Text([string]$p, [long]$Max = 4MB) {
    if (-not $p -or (Test-NoRead $p)) { return $null }
    try {
        $f = [IO.FileInfo]::new($p); if (-not $f.Exists -or $f.Length -gt $Max -or (Test-BvsCloudOnly $f)) { return $null }
        $s = [IO.FileStream]::new($f.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        try { [IO.StreamReader]::new($s, $true).ReadToEnd() } finally { $s.Dispose() }
    } catch { $null }
}
function Read-Json([string]$p, [long]$Max = 16MB) {
    $t = Read-Text $p $Max; if ($null -eq $t) { return $null }
    try { $t | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop }
    catch { try { (($t -replace '(?m)^\s*//.*$', '') -replace ',(\s*[}\]])', '$1') | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop } catch { $null } }
}
$DropKeys = 'primaryApiKey', 'customApiKeyResponses', 'oauthAccount', 'userID', 'machineID', 'authToken', 'accessToken', 'refreshToken'
function Remove-Sens($o) {
    if ($o -is [Collections.IDictionary]) { foreach ($k in @($o.Keys)) { if ($k -in $DropKeys) { [void]$o.Remove($k) } else { Remove-Sens $o[$k] } } }
    elseif ($o -is [Collections.IList]) { foreach ($x in $o) { Remove-Sens $x } }
}
function Mask([AllowNull()][string]$t, [int]$Max = 200) {
    if ([string]::IsNullOrEmpty($t)) { return $t }
    $t = Protect-BvsText ($t -replace '\s+', ' ')
    $t = [regex]::Replace($t, '(?i)((?:authorization|x-api-key|api-key|apikey|cookie|private-token)["'']?\s*[:=]\s*["'']?(?:Bearer\s+)?)([^"''\s,;}{]{6,})', { param($m) $m.Groups[1].Value + (Protect-BvsSecret $m.Groups[2].Value) })
    $t = [regex]::Replace($t, '\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{32,}\b', { param($m) Protect-BvsSecret $m.Value })
    if ($t.Length -gt $Max) { $t.Substring(0, $Max - 1) + [char]0x2026 } else { $t }
}
function Snip([string]$t, [int]$i) {
    if (-not $t) { return '' }
    $s = [Math]::Max(0, [Math]::Min($i, $t.Length) - 80); $w = $t.Substring($s, [Math]::Min(420, $t.Length - $s))
    if ($s -gt 0) { $k = $w.IndexOfAny([char[]]" `t`r`n,;'`"(){}[]"); if ($k -ge 0 -and $k -lt 60) { $w = $w.Substring($k + 1) } }
    Mask $w 200
}
function Get-HostClass([string]$h) {
    $h = "$h".ToLowerInvariant().Trim('[', ']', '.'); if (-not $h) { return 'unknown' }
    $ip = $null
    if ([Net.IPAddress]::TryParse($h, [ref]$ip)) {
        if ([Net.IPAddress]::IsLoopback($ip)) { return 'local' }
        $b = $ip.GetAddressBytes()
        if ($b.Count -eq 4) {
            if ($b[0] -eq 10 -or $b[0] -eq 0 -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 169 -and $b[1] -eq 254)) { return 'local' }
            if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return 'tailnet' }
        }
        return 'other-ip'
    }
    if ($h -eq 'localhost' -or $h -match '\.(localhost|local|internal|lan|home\.arpa|ts\.net)$') { return 'local' }
    if ($RX.Exfil.IsMatch($h)) { return 'exfil-service' }
    if ($RX.Reserved.IsMatch($h)) { return 'reserved-test' }
    foreach ($s in @($Ioc.knownApiHostSuffixes) + @($Ioc.knownMcpHostSuffixes)) { if ($h -eq $s -or $h.EndsWith(".$s")) { return 'known-provider' } }
    foreach ($s in $Ioc.hostingPlatformSuffixes) { if ($h -eq $s -or $h.EndsWith(".$s")) { return 'user-content-hosting' } }
    'other'
}
function Get-Urls([string]$t) {
    if (-not $t) { return }
    foreach ($m in $RX.Url.Matches($t)) { $h = $m.Groups[1].Value.ToLowerInvariant(); [pscustomobject]@{ Host = $h; Class = $(if ($RX.Exfil.IsMatch($m.Value)) { 'exfil-service' } else { Get-HostClass $h }); Url = (Protect-BvsUrl $m.Value) } }
}
function Get-Flags([string]$c) {
    if (-not $c) { return @() }
    $f = @()
    if ($RX.Net.IsMatch($c)) { $f += 'network' }; if ($RX.Enc.IsMatch($c)) { $f += 'base64/encoded' }; if ($RX.Cred.IsMatch($c)) { $f += 'credential-file' }
    if ($RX.Pipe.IsMatch($c)) { $f += 'pipe-to-shell' }; if ($RX.Exfil.IsMatch($c)) { $f += 'exfil-endpoint' }
    if ($c -match '(?i)Invoke-Expression|(?<![\w-])iex\b|(?<![\w.])eval\(') { $f += 'dynamic-exec' }
    if ($c -match '(?i)permissionDecision|"behavior"|\bdecision\b') { $f += 'returns-permission-decision' }
    $f
}
function F([string]$Check, [string]$Sev, [string]$Cls, [string]$Title, [object[]]$Ev, [string]$Fp, [string]$Rec, [string[]]$Rs = @(), [string]$Conf = 'medium', $Exp = $null) {
    New-BvsFinding -Run $run -Check $Check -Title $Title -Severity $Sev -Class $Cls -Confidence $Conf -Reasons $Rs -Evidence $Ev -FpNotes $Fp -Recommendation $Rec -Expected $Exp
}
function Test-EmojiBase([int]$c) { ($c -ge 0x1F000 -and $c -le 0x1FAFF) -or ($c -ge 0x2190 -and $c -le 0x2BFF) -or ($c -in 0xA9, 0xAE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299, 0x23, 0x2A) -or ($c -ge 0x30 -and $c -le 0x39) }
function Find-Invisible([string]$t) {
    foreach ($m in $RX.Inv.Matches($t)) {
        $cps = [Collections.Generic.List[int]]::new()
        for ($i = 0; $i -lt $m.Length; $i++) { $cp = [char]::ConvertToUtf32($m.Value, $i); if ($cp -gt 0xFFFF) { $i++ }; $cps.Add($cp) }
        $prev = 0; if ($m.Index -ge 2 -and [char]::IsLowSurrogate($t[$m.Index - 1])) { $prev = [char]::ConvertToUtf32($t, $m.Index - 2) } elseif ($m.Index -ge 1) { $prev = [int]$t[$m.Index - 1] }
        $e = $m.Index + $m.Length; $nx = 0; if ($e -lt $t.Length) { $nx = if ([char]::IsHighSurrogate($t[$e]) -and $e + 1 -lt $t.Length) { [char]::ConvertToUtf32($t, $e) } else { [int]$t[$e] } }
        $emojiOnly = @($cps | Where-Object { $_ -notin 0xFE0E, 0xFE0F, 0x200D }).Count -eq 0
        $benign = ($emojiOnly -and (Test-EmojiBase $prev) -and ($cps[$cps.Count - 1] -ne 0x200D -or (Test-EmojiBase $nx))) -or
                  (@($cps | Where-Object { $_ -lt 0xE0020 -or $_ -gt 0xE007F }).Count -eq 0 -and $prev -eq 0x1F3F4) -or
                  ($cps.Count -eq 1 -and $cps[0] -in 0x200E, 0x200F -and (($prev -ge 0x590 -and $prev -le 0x6FF) -or ($nx -ge 0x590 -and $nx -le 0x6FF)))
        $tags = @($cps | Where-Object { $_ -ge 0xE0000 -and $_ -le 0xE007F })
        [pscustomobject]@{ Index = $m.Index; Codepoints = (($cps | Select-Object -First 12 | ForEach-Object { 'U+{0:X4}' -f $_ }) -join ' '); Count = $cps.Count; Benign = $benign; Hidden = $(if ($tags.Count -ge 2) { -join ($tags | ForEach-Object { [char]($_ - 0xE0000) }) }) }
    }
}
function Find-Hits([string]$t) {
    $o = [Collections.Generic.List[object]]::new(); $tn = $t -replace '\s+', ' '
    foreach ($p in @(@('exfil-domain', $RX.Exfil, $t), @('pipe-to-shell', $RX.Pipe, $t), @('encoded', $RX.Enc, $t), @('inject', $RX.Inject, $tn), @('hide', $RX.Hide, $tn), @('exfil-instruction', $RX.ExfilI, $tn))) {
        foreach ($m in $p[1].Matches($p[2])) {
            $typ = $p[0]; $src = $p[2]; $s = [Math]::Max(0, $m.Index - 250)
            if ($typ -ne 'pipe-to-shell' -and $typ -ne 'encoded' -and $RX.Def.IsMatch($src.Substring($s, [Math]::Min(500, $src.Length - $s)))) { $typ += '-defensive' }
            $o.Add([pscustomobject]@{ Type = $typ; Detail = $m.Value; Snippet = (Snip $src $m.Index) })
        }
    }
    $b = $RX.B64.Match($t); if ($b.Success) { $o.Add([pscustomobject]@{ Type = 'base64-blob'; Detail = "$($b.Length) chars"; Snippet = '' }) }
    foreach ($m in $RX.Cred.Matches($t)) {
        $ls = $t.LastIndexOf("`n", [Math]::Max(0, $m.Index - 1)) + 1; $le = $t.IndexOf("`n", $m.Index); if ($le -lt 0) { $le = $t.Length }
        $ln = $t.Substring($ls, $le - $ls); if ($RX.Verb.IsMatch($ln) -and $ln -notmatch '(?:^|\s)-i\s') { $o.Add([pscustomobject]@{ Type = 'credential-read'; Detail = $m.Value; Snippet = (Snip $t $m.Index) }) }
    }
    $x = $RX.Exec.Match($t); if ($x.Success) { $o.Add([pscustomobject]@{ Type = 'exec'; Detail = $x.Value; Snippet = '' }) }
    if ($RX.Net.IsMatch($t)) { $o.Add([pscustomobject]@{ Type = 'network'; Detail = ''; Snippet = '' }) }
    foreach ($v in @(Find-Invisible $t)) {
        if ($v.Benign) { $o.Add([pscustomobject]@{ Type = 'invisible-benign'; Detail = $v.Codepoints; Snippet = '' }) }
        else { $o.Add([pscustomobject]@{ Type = 'invisible'; Detail = "$($v.Codepoints)$(if ($v.Hidden) { ' hidden-text=' + (Mask $v.Hidden 80) })"; Snippet = ((Snip $t $v.Index) -replace '[​-‏‪-‮⁦-⁩︀-️]', '<INV>') }) }
    }
    , $o
}
$Sha1 = [Security.Cryptography.SHA1]::Create()
function Get-Blob([byte[]]$b) {
    $bin = $false; for ($i = 0; $i -lt [Math]::Min(8000, $b.Length); $i++) { if ($b[$i] -eq 0) { $bin = $true; break } }
    if (-not $bin) { $ms = [IO.MemoryStream]::new($b.Length); for ($i = 0; $i -lt $b.Length; $i++) { if (-not ($b[$i] -eq 13 -and $i + 1 -lt $b.Length -and $b[$i + 1] -eq 10)) { $ms.WriteByte($b[$i]) } }; $b = $ms.ToArray() }
    $Sha1.ComputeHash([byte[]]([Text.Encoding]::ASCII.GetBytes("blob $($b.Length)`0") + $b))
}
function Get-Tree([string]$d) {
    # git tree hash (LF-normalised, mode 100644) - matches skillFolderHash in ~\.agents\.skill-lock.json
    $es = @(foreach ($x in Get-ChildItem -LiteralPath $d -Force) { if ($x.PSIsContainer) { [pscustomobject]@{ K = $x.Name + '/'; M = '40000'; N = $x.Name; S = (Get-Tree $x.FullName) } } else { [pscustomobject]@{ K = $x.Name; M = '100644'; N = $x.Name; S = (Get-Blob ([IO.File]::ReadAllBytes($x.FullName))) } } })
    $ms = [IO.MemoryStream]::new()
    foreach ($e in [Linq.Enumerable]::OrderBy([object[]]$es, [Func[object, string]] { param($z) $z.K }, [StringComparer]::Ordinal)) { $h = [Text.Encoding]::UTF8.GetBytes("$($e.M) $($e.N)`0"); $ms.Write($h, 0, $h.Length); $ms.Write($e.S, 0, 20) }
    $body = $ms.ToArray(); $Sha1.ComputeHash([byte[]]([Text.Encoding]::ASCII.GetBytes("tree $($body.Length)`0") + $body))
}
function ConvertFrom-Toml([string]$s) {
    $root = [ordered]@{}; $cur = $root
    foreach ($l in ($s -split "`r?`n")) {
        $l = $l.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }
        if ($l -match '^\[\[?(.+?)\]\]?$') { $cur = $root; foreach ($p in [regex]::Matches($Matches[1], '"[^"]*"|''[^'']*''|[^.\s]+')) { $n = $p.Value.Trim('"', "'"); if (-not $cur.Contains($n)) { $cur[$n] = [ordered]@{} }; $cur = $cur[$n] }; continue }
        if ($l -match '^("[^"]*"|''[^'']*''|[\w.\-]+)\s*=\s*(.+)$') {
            $k = $Matches[1].Trim('"', "'"); $v = $Matches[2].Trim()
            $cur[$k] = if ($v -match '^"(.*)"$') { $Matches[1] } elseif ($v -match "^'(.*)'$") { $Matches[1] } elseif ($v -match '^\[(.*)\]$') { @([regex]::Matches($Matches[1], '"([^"]*)"|''([^'']*)''') | ForEach-Object { "$($_.Groups[1].Value)$($_.Groups[2].Value)" }) } elseif ($v -match '^(true|false)$') { $v -eq 'true' } else { $v }
        }
    }
    $root
}

# ---------- shared state ----------
$Inv = [ordered]@{}; $CJData = @{}; $SeenSha = @{}; $SeenMcp = @{}
$Proj = [ordered]@{}; $SetRecs = [Collections.Generic.List[object]]::new(); $McpRecs = [Collections.Generic.List[object]]::new()
$HookPorts = [Collections.Generic.List[object]]::new(); $DenyInfo = [Collections.Generic.List[object]]::new(); $RC = [Collections.Generic.List[string]]::new()
$SkUnits = [Collections.Generic.List[object]]::new(); $SkFiles = [Collections.Generic.List[object]]::new(); $Stubs = [Collections.Generic.List[string]]::new()
$ExpAllowTok = @(); $ExpAllowItem = $null
foreach ($e in @(Get-BvsExpected -Category claudeConfig)) { if ($e.match.permissionsAllowContains) { $ExpAllowTok += @($e.match.permissionsAllowContains); $ExpAllowItem = $e } }
$ExpSkill = @(Get-BvsExpected -Category claudeConfig | Where-Object { $_.match.skillPrefix }) | Select-Object -First 1
$ExpPathItems = @(Get-BvsExpected -Category path | Where-Object { $_.match.path })
$ExtRoots = @(@('VS Code', '.vscode\extensions'), @('VS Code Insiders', '.vscode-insiders\extensions'), @('Cursor', '.cursor\extensions'), @('Windsurf', '.windsurf\extensions'), @('VSCodium', '.vscode-oss\extensions'))
function Test-PkgEmbedded([string]$p) { foreach ($e in $ExtRoots) { if ($p.StartsWith((Join-Path $UP $e[1]) + '\', $OC)) { return $true } }; $false }
function Add-Proj([string]$p, [string]$src) {
    if (-not $p) { return }; try { $f = [IO.Path]::GetFullPath(($p -replace '/', '\')).TrimEnd('\') } catch { return }
    if ((Test-Own $f) -or (Test-PkgEmbedded $f) -or -not [IO.Directory]::Exists($f)) { return }
    $k = $f.ToLowerInvariant(); if (-not $Proj.Contains($k)) { $Proj[$k] = [ordered]@{ path = $f; sources = [Collections.Generic.List[string]]::new() } }
    if (-not $Proj[$k].sources.Contains($src)) { $Proj[$k].sources.Add($src) }
}

# ---------- MCP ----------
function Add-Mcp($S, [string]$src, [string]$scope, [string]$tool = 'claude-code', [switch]$FirstParty) {
    if ($S -isnot [Collections.IDictionary]) { return }
    foreach ($n in @($S.Keys)) {
        $d = $S[$n]; if ($d -isnot [Collections.IDictionary]) { continue }
        $cmd = [string]$d['command']; $al = @(Get-L $d['args'] | ForEach-Object { [string]$_ }); $url = [string]($d['url'] ?? $d['serverUrl'] ?? $d['httpUrl'])
        $type = [string]($d['type'] ?? $d['transport']); if (-not $type) { $type = if ($url) { 'http' } elseif ($cmd) { 'stdio' } else { '?' } }
        $full = "$cmd $($al -join ' ')".Trim(); $fl = @(); $pkg = $null; $h = $null; $cls = $null
        if ($full -match '(?i)(?:^|[\\/\s])(?:npx|bunx|uvx|pnpm\s+dlx|yarn\s+dlx|pipx\s+run)(?:\.cmd|\.exe)?\s+(.*)$') {
            $fl += 'auto-install-runner'; $pkg = @($Matches[1] -split '\s+' | Where-Object { $_ -and $_ -notmatch '^-' })[0]
            if ($pkg -and -not @($Ioc.knownMcpPackages | Where-Object { $pkg.StartsWith($_, $OC) }).Count) { $fl += 'unknown-package' }
            if ($pkg -notmatch '^(@[^/]+/)?[^@]+@\d') { $fl += 'unpinned' }
        }
        if ($url) {
            $u = $null; [void][uri]::TryCreate($url, 'Absolute', [ref]$u); $h = if ($u) { $u.Host } else { '' }
            $cls = if ($RX.Exfil.IsMatch($url)) { 'exfil-service' } else { Get-HostClass $h }
            if ($u -and $u.Scheme -eq 'http' -and $cls -notin 'local', 'tailnet') { $fl += 'plain-http-remote' }
            if ($h -match 'supabase' -and $url -notmatch '(?i)read_only(=|%3D)true') { $fl += 'supabase-not-read-only' }
        }
        $hd = if ($d['headers'] -is [Collections.IDictionary]) { $d['headers'] } else { @{} }
        foreach ($hn in @($hd.Keys)) { if ($hn -match '(?i)authorization|api[-_]?key|token|cookie' -and "$($hd[$hn])" -notmatch '^\$') { $fl += 'literal-auth-header' } }
        $McpRecs.Add([ordered]@{ tool = $tool; scope = $scope; source = $src; name = $n; transport = $type; command = (Mask $full 250); package = $pkg; url = (Protect-BvsUrl $url); host = $h; hostClass = $cls; headerNames = @($hd.Keys); envNames = @(if ($d['env'] -is [Collections.IDictionary]) { $d['env'].Keys }); flags = $fl; firstParty = [bool]$FirstParty })
        $ev = @([ordered]@{ type = 'config'; path = $src; server = $n; transport = $type; command = (Mask $full 200); url = (Protect-BvsUrl $url); flags = ($fl -join ',') })
        $mk = "$tool|$n|$h|$full"; if ($SeenMcp.Contains($mk)) { continue }; $SeenMcp[$mk] = 1
        if ($cls -eq 'exfil-service') { F 'mcp.servers' 'high' 'suspicious' "MCP server '$n' ($tool) points at an exfiltration-type service ($h)" $ev 'Could be a deliberate test endpoint.' 'Remove the server unless you created it; check what data it received.' @('intel_match') }
        elseif ($fl -contains 'auto-install-runner' -and $fl -contains 'unknown-package') { F 'mcp.servers' 'medium' 'hardening' "MCP server '$n' ($tool) auto-installs package '$pkg' at every start" $ev 'May be a well-known package missing from the list.' 'Pin an exact version or install it once; verify the publisher.' @('supply_chain') }
        elseif ($fl -contains 'plain-http-remote') { F 'mcp.servers' 'medium' 'hardening' "MCP server '$n' ($tool) uses plain HTTP to $h" $ev 'Internal test server?' 'Use HTTPS.' }
        elseif ($cls -in 'other', 'other-ip', 'user-content-hosting' -and -not $FirstParty) { F 'mcp.servers' 'low' 'suspicious' "MCP server '$n' ($tool) uses unrecognised host $h" $ev 'Likely your own or a vendor server not in the known list.' 'Confirm you added it and trust the operator.' }
        elseif ($fl -contains 'supabase-not-read-only') { F 'mcp.servers' 'low' 'hardening' "Supabase MCP '$n' ($tool) is not read-only" $ev 'Write access may be intended.' 'Add read_only=true (and project scoping) to the URL unless writes are needed.' }
    }
}

# ---------- hooks / settings ----------
function Invoke-Hooks($HookMap, [string]$src, [string]$scope, [string]$proj) {
    foreach ($ev in @($HookMap.Keys)) { foreach ($g in @(Get-L $HookMap[$ev] | Where-Object { $_ -is [Collections.IDictionary] })) { foreach ($h in (Get-L $g['hooks'])) {
        if ($h -isnot [Collections.IDictionary]) { continue }
        $cmd = ((@([string]$h['command']) + @(Get-L $h['args'] | ForEach-Object { [string]$_ })) -join ' ').Trim(); $url = [string]$h['url']
        $fl = @(Get-Flags "$cmd $url"); $hosts = @(Get-Urls "$cmd $url"); $scr = $null; $sf = @()
        $m = [regex]::Match($cmd, '(?i)"?([^"\s]+\.(?:js|cjs|mjs|ts|py|ps1|sh|bat|cmd|rb|pl))"?')
        if ($m.Success) {
            $sp = [Environment]::ExpandEnvironmentVariables(($m.Groups[1].Value -replace '^\$\{?CLAUDE_(PROJECT_DIR|PLUGIN_ROOT)\}?', "$proj"))
            $st = Read-Text $sp 1MB
            if ($st) { $sf = @(Get-Flags $st); $hosts += @(Get-Urls $st); if ($st -match '127\.0\.0\.1|localhost' -and $st -notmatch '(?i)authorization|x-api-key|\btoken\b|hmac|secret') { $sf += 'unauthenticated-local-endpoint' } }
            $scr = [ordered]@{ path = $sp; exists = [IO.File]::Exists($sp); sha256 = (Get-BvsHash -Path $sp); flags = $sf }
        }
        foreach ($pm in [regex]::Matches("$cmd $url", '(?:--port[ =]|localhost:|127\.0\.0\.1:)(\d{2,5})')) { $HookPorts.Add([ordered]@{ port = [int]$pm.Groups[1].Value; source = $src; event = $ev }) }
        $exe = if ($cmd.StartsWith('"')) { $cmd.Split('"')[1] } else { ($cmd -split '\s+')[0] }
        $expP = @($ExpPathItems | Where-Object { $exe -and $exe.StartsWith([Environment]::ExpandEnvironmentVariables($_.match.path), $OC) } | ForEach-Object id)
        $all = @($fl) + @($sf); $ext = @($hosts | Where-Object { $_.Class -notin 'local', 'tailnet', 'reserved-test' })
        $rec = [ordered]@{ event = $ev; matcher = $g['matcher']; type = $h['type']; command = (Mask $cmd 300); url = (Protect-BvsUrl $url); timeout = $h['timeout']; flags = $all; hosts = @($hosts | ForEach-Object { "$($_.Host) [$($_.Class)]" } | Select-Object -Unique); script = $scr; interpreterUnderExpectedPathItem = $expP }
        $bad = ($all -contains 'exfil-endpoint') -or ($all -contains 'pipe-to-shell') -or (($all -contains 'base64/encoded') -and ($all -contains 'network')) -or (($all -contains 'credential-file') -and $ext.Count)
        $sev, $cls = if ($scope -eq 'package-embedded') { 'info', 'info' } elseif ($bad) { 'high', 'suspicious' } elseif ($ev -eq 'PermissionRequest' -or $all -contains 'returns-permission-decision') { 'medium', 'hardening' } else { 'low', 'hardening' }
        $why = if ($ev -eq 'PermissionRequest' -or $all -contains 'returns-permission-decision') { ' - it can approve tool calls' } else { '' }
        F 'claude.settings.hooks' $sev $cls "Hook on $ev ($scope settings) runs a command$why" @([ordered]@{ type = 'config'; path = $src; hook = $rec }) 'Hooks you wrote yourself are legitimate automation; check the script still matches what you intended.' $(if ($all -contains 'unauthenticated-local-endpoint') { 'The hook trusts an unauthenticated 127.0.0.1 endpoint: any local process that binds that port can answer allow. Add a shared secret, remove the hook when unused, and keep the interpreter out of folders other users can write.' } else { 'Review the hook command and script; remove it if unknown.' }) $(if ($bad) { @('obfuscation') } elseif ($expP) { @('user_writable') } else { @() })
        $rec
    } } }
}
function Invoke-Perms($P, [string]$src, [string]$scope, [string]$sha) {
    $dup = $sha -and $SeenSha.Contains($sha); if ($sha) { $SeenSha[$sha] = $src }
    $allow = @(Get-L $P['allow'] | ForEach-Object { [string]$_ }); $deny = @(Get-L $P['deny']); $ask = @(Get-L $P['ask'])
    $broad = [Collections.Generic.List[object]]::new(); $expN = 0
    foreach ($a in $allow) {
        $rs = @($Ioc.broadAllow | Where-Object { $a -match $_.regex } | ForEach-Object reason)
        $isE = @($ExpAllowTok | Where-Object { $a.IndexOf($_, $OC) -ge 0 }).Count -gt 0; if ($isE) { $expN++ }
        if ($rs) { $broad.Add([ordered]@{ rule = (Mask $a 220); reasons = $rs; expected = $isE }) }
    }
    $DenyInfo.Add([ordered]@{ path = $src; scope = $scope; deny = $deny.Count; allow = $allow.Count })
    $mode = [string]$P['defaultMode']
    if ($mode -eq 'bypassPermissions') { F 'claude.settings.permissions' 'high' 'hardening' "defaultMode=bypassPermissions in $scope settings" @([ordered]@{ type = 'config'; path = $src; key = 'permissions.defaultMode'; value = $mode }) 'Only acceptable inside a disposable sandbox/VM.' 'Remove defaultMode or set it to default.' }
    $nb = @($broad | Where-Object { -not $_.expected })
    if ($nb.Count -and -not $dup) {
        $hi = @($nb | Where-Object { $_.reasons -contains 'tool-wide' }); $md = @($nb | Where-Object { @($_.reasons | Where-Object { $_ -in 'interpreter-wildcard', 'remote-shell', 'package-install-wildcard', 'network-wildcard', 'destructive' }).Count })
        $sev = if ($scope -eq 'package-embedded') { 'info' } elseif ($hi) { 'high' } elseif ($md) { 'medium' } else { 'low' }
        F 'claude.settings.permissions' $sev 'hardening' "Broad standing approvals in $scope settings ($($nb.Count) rules: $((@($nb | ForEach-Object { $_.reasons }) | Select-Object -Unique) -join ', '))" @([ordered]@{ type = 'config'; path = $src; rules = @($nb | Select-Object -First 15) }) 'Rules accumulate from "always allow" clicks; many are harmless one-offs. A committed settings.json applies to everyone who opens the repo.' 'Delete rules you no longer need; replace interpreter/ssh/package-install wildcards with exact commands; never commit broad rules to a shared repo.'
    }
    if ($expN -and $scope -eq 'user') { F 'claude.settings.permissions' 'info' 'hardening' "$expN of $($allow.Count) user allow rules match an expected item (config\local\expected.json)" @([ordered]@{ type = 'config'; path = $src; expectedTokens = $ExpAllowTok }) 'Expected per config\local\expected.json.' 'Keep these rules exact (no wildcards) and remove them when you no longer need them.' @('expected_match') 'high' ([ordered]@{ id = $ExpAllowItem.id; applied = $true; severityCap = $ExpAllowItem.severityCap }) }
    [ordered]@{ defaultMode = $mode; allow = $allow.Count; deny = $deny.Count; ask = $ask.Count; byTool = @($allow | Group-Object { if ($_ -match '^([A-Za-z_]+)') { $Matches[1] } else { '?' } } | ForEach-Object { "$($_.Name)=$($_.Count)" }); broad = $broad; expectedEntries = $expN; additionalDirectories = @(Get-L $P['additionalDirectories']) }
}
function Invoke-Settings([string]$Path, [string]$Scope, [string]$Project) {
    $j = Read-Json $Path; $i = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    $r = [ordered]@{ path = $Path; scope = $Scope; parsed = ($null -ne $j); sha256 = (Get-BvsHash -Path $Path); modified = $i.LastWriteTimeUtc.ToString('o'); topKeys = @(); hooks = @(); helpers = [ordered]@{}; env = [ordered]@{}; permissions = $null; other = [ordered]@{} }
    if ($null -eq $j) { $SetRecs.Add($r); return }
    $r.topKeys = @($j.Keys)
    if ($j['hooks'] -is [Collections.IDictionary]) { $r.hooks = @(Invoke-Hooks $j['hooks'] $Path $Scope $Project) }
    $hl = [ordered]@{}; foreach ($k in 'apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper') { if ($j[$k]) { $hl[$k] = [string]$j[$k] } }
    if ($j['statusLine'] -is [Collections.IDictionary] -and $j['statusLine']['command']) { $hl['statusLine.command'] = [string]$j['statusLine']['command'] }
    foreach ($k in @($hl.Keys)) {
        $fl = @(Get-Flags $hl[$k]); $r.helpers[$k] = [ordered]@{ command = (Mask $hl[$k] 300); flags = $fl }
        $bad = @($fl | Where-Object { $_ -in 'exfil-endpoint', 'pipe-to-shell', 'base64/encoded', 'dynamic-exec' }).Count -or ($fl -contains 'network' -and $fl -contains 'credential-file')
        if ($bad) { F 'claude.settings.helpers' 'high' 'suspicious' "$k in $Scope settings runs a suspicious command" @([ordered]@{ type = 'config'; path = $Path; key = $k; command = (Mask $hl[$k] 200); flags = ($fl -join ',') }) 'Enterprise helpers can look like this.' 'Verify you configured it; remove otherwise.' @('obfuscation') }
        elseif ($k -ne 'statusLine.command') { F 'claude.settings.helpers' 'low' 'hardening' "$k is configured in $Scope settings" @([ordered]@{ type = 'config'; path = $Path; key = $k; command = (Mask $hl[$k] 200) }) 'Normal for SSO/enterprise setups.' 'Confirm the command is yours.' }
    }
    if ($j['env'] -is [Collections.IDictionary]) {
        foreach ($k in @($j['env'].Keys)) {
            $v = [string]$j['env'][$k]
            $r.env[$k] = if ($k -match '(?i)KEY|TOKEN|SECRET|PASSWORD|HEADERS|AUTH') { "[set, $($v.Length) chars]" } elseif ($v -match '^(?i)(https?|socks5?h?)://') { Protect-BvsUrl $v } else { Mask $v 120 }
            $sev = $null; $why = $null; $cls = 'hardening'
            if ($k -match '^ANTHROPIC_(BASE_URL|API_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL)$') { $hh = try { ([uri]$v).Host } catch { $v }; if ($hh -notmatch 'anthropic\.com$') { $sev = if ((Get-HostClass $hh) -eq 'local') { 'medium' } else { 'high' }; $cls = 'suspicious'; $why = "API traffic redirected to $hh" } }
            elseif ($k -match '^(HTTPS?|ALL)_PROXY$') { $sev = 'medium'; $why = 'a proxy can read/modify API traffic' }
            elseif ($k -eq 'NODE_OPTIONS' -and $v -match '(?i)--(require|import|loader|experimental-loader|inspect)|(^|\s)-r\s') { $sev = 'high'; $cls = 'suspicious'; $why = 'code injected into the Node runtime' }
            elseif ($k -eq 'NODE_TLS_REJECT_UNAUTHORIZED' -and $v -eq '0') { $sev = 'high'; $why = 'TLS verification disabled' }
            elseif ($k -in 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE') { $sev = 'medium'; $why = 'extra CA trusted (TLS interception possible)' }
            elseif ($k -match '^OTEL_EXPORTER_OTLP_(ENDPOINT|HEADERS)$') { $sev = 'medium'; $why = 'telemetry exported to an external collector' }
            elseif ($k -in 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN') { $sev = 'low'; $cls = 'hygiene'; $why = 'plaintext API credential in a settings file' }
            if ($sev) { F 'claude.settings.env' $sev $cls "env.$k in $Scope settings: $why" @([ordered]@{ type = 'config'; path = $Path; key = "env.$k"; value = $r.env[$k] }) 'Corporate proxies/gateways set these legitimately.' 'Confirm you set it; remove it otherwise.' }
        }
    }
    if ($j['permissions'] -is [Collections.IDictionary]) { $r.permissions = Invoke-Perms $j['permissions'] $Path $Scope $r.sha256 }
    foreach ($k in 'enableAllProjectMcpServers', 'enabledMcpjsonServers', 'disabledMcpjsonServers', 'enabledPlugins', 'extraKnownMarketplaces', 'remoteControlAtStartup', 'agentPushNotifEnabled', 'cleanupPeriodDays', 'disableAllHooks', 'skipDangerousModePermissionPrompt', 'sandbox', 'model') { if ($j.Contains($k)) { $r.other[$k] = $j[$k] } }
    if ($j['enableAllProjectMcpServers'] -eq $true) { F 'claude.settings.mcp' 'medium' 'hardening' "enableAllProjectMcpServers=true in $Scope settings" @([ordered]@{ type = 'config'; path = $Path; key = 'enableAllProjectMcpServers'; value = $true }) 'Convenient for your own repos.' 'Turn it off: any cloned repo with a .mcp.json then starts servers without asking.' }
    if ($j['skipDangerousModePermissionPrompt'] -eq $true) { F 'claude.settings.permissions' 'low' 'hardening' "skipDangerousModePermissionPrompt=true in $Scope settings" @([ordered]@{ type = 'config'; path = $Path }) 'Personal preference.' 'Re-enable the warning.' }
    if ($j['extraKnownMarketplaces'] -is [Collections.IDictionary]) { foreach ($mk in @($j['extraKnownMarketplaces'].Keys)) { $s = $j['extraKnownMarketplaces'][$mk]['source']; $id = "$($s['repo'])$($s['url'])$($s['path'])"; if ($id -notin $Ioc.firstPartyMarketplaces) { F 'claude.plugins' 'medium' 'suspicious' "Settings add a non-official plugin marketplace '$mk' ($id)" @([ordered]@{ type = 'config'; path = $Path; marketplace = $mk; source = $id }) 'Team marketplaces are legitimate.' 'Verify the repo owner before installing plugins from it.' } } }
    if ($j['mcpServers'] -is [Collections.IDictionary]) { Add-Mcp $j['mcpServers'] $Path "settings:$Scope" }
    if ($j['remoteControlAtStartup'] -eq $true) { $RC.Add($Path) }
    $SetRecs.Add($r)
}

# ================= checks =================
$null = Invoke-BvsCheck -Run $run -Id 'claude.install' -Description 'claude.exe signer/version; Claude editor extensions (publisher, .signature.p7s, extensions.json source, bundled binaries); update state' -Script {
    $cli = [Collections.Generic.List[object]]::new(); $ext = [Collections.Generic.List[object]]::new()
    $c = @((Join-Path $UP '.local\bin\claude.exe')) + @(Get-ChildItem -LiteralPath (Join-Path $UP '.local\share\claude\versions') -File -ErrorAction SilentlyContinue | ForEach-Object FullName) + @(Get-Command claude -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object Source)
    foreach ($p in ($c | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)) {
        $pe = (Get-BvsMagic -Path $p).Type -eq 'pe'; $s = if ($pe) { Get-BvsSignature $p }; $v = if ($pe) { Get-BvsVersionInfo -Path $p }; $it = Get-Item -LiteralPath $p -Force
        $cli.Add([ordered]@{ path = $p; native = $pe; size = $it.Length; modified = $it.LastWriteTimeUtc.ToString('o'); sha256 = (Get-BvsHash -Path $p); sig = $s.Status; signer = $s.Signer; issuer = $s.Issuer; version = $v.FileVersion; product = $v.ProductName })
        if ($pe -and ($s.Status -ne 'Valid' -or $s.Signer -notmatch 'Anthropic')) { F 'claude.install' 'high' 'suspicious' "Claude binary not validly signed by Anthropic: $p" @([ordered]@{ type = 'file'; path = $p; sig = $s.Status; signer = $s.Signer }) 'A dev build could be unsigned.' 'Reinstall Claude Code from the official installer.' @('unsigned', 'user_writable', 'masquerading') }
    }
    $p7s = @()
    foreach ($ed in $ExtRoots) {
        $er = Join-Path $UP $ed[1]; if (-not (Test-Path -LiteralPath $er)) { continue }
        $ej = @(Read-Json (Join-Path $er 'extensions.json')); $all = @(Get-ChildItem -LiteralPath $er -Directory -Force -ErrorAction SilentlyContinue)
        $p7s += "$($ed[0]): $(@($all | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName '.signature.p7s') }).Count)/$($all.Count) extension folders keep .signature.p7s"
        foreach ($x in ($all | Where-Object Name -match '(?i)^anthropic\.|claude')) {
            $pk = Read-Json (Join-Path $x.FullName 'package.json'); $en = $ej | Where-Object { $_.relativeLocation -eq $x.Name } | Select-Object -First 1
            $bins = @(Get-BvsFiles -Path $x.FullName -NoPrune -Include *.exe | ForEach-Object { $sg = Get-BvsSignature $_.FullName; [ordered]@{ path = $_.FullName; sig = $sg.Status; signer = $sg.Signer } })
            $r = [ordered]@{ editor = $ed[0]; folder = $x.FullName; id = "$($pk.publisher).$($pk.name)"; publisher = $pk.publisher; version = $pk.version; signatureP7s = (Test-Path -LiteralPath (Join-Path $x.FullName '.signature.p7s')); listed = [bool]$en; source = $en.metadata.source; galleryId = $en.identifier.uuid; publisherId = $en.metadata.publisherId; publisherDisplayName = $en.metadata.publisherDisplayName; binaries = $bins }
            $ext.Add($r)
            $r.galleryId = $en.identifier.uuid ?? $en.metadata.id
            if ($x.Name -match '(?i)^anthropic\.claude-code') {
                $newer = @($ej | Where-Object { $_.identifier.id -eq 'anthropic.claude-code' -and $_.relativeLocation -ne $x.Name }).Count
                $prob = @(); if ($pk.publisher -ne 'Anthropic') { $prob += "publisher=$($pk.publisher)" }; if (-not $en -and -not $newer) { $prob += 'not listed in extensions.json' } elseif ($en -and $en.metadata.source -ne 'gallery') { $prob += "source=$($en.metadata.source)" }
                if (-not $en -and $newer) { $r.superseded = $true }
                foreach ($b in $bins) { if ($b.sig -ne 'Valid' -or $b.signer -notmatch 'Anthropic') { $prob += "bundled $([IO.Path]::GetFileName($b.path)) sig=$($b.sig)" } }
                if ($prob) { F 'claude.install' 'high' 'suspicious' "Claude Code extension in $($ed[0]) fails integrity checks: $($prob -join '; ')" @([ordered]@{ type = 'file'; path = $x.FullName; problems = $prob }) 'A VSIX installed manually from Anthropic would show source=vsix.' 'Uninstall and reinstall from the official marketplace.' @('masquerading') }
            } elseif ($pk.displayName -match '(?i)claude code' -and $pk.publisher -notmatch '(?i)^anthropic$') { F 'claude.install' 'medium' 'suspicious' "Extension '$($pk.displayName)' by $($pk.publisher) imitates Claude Code" @([ordered]@{ type = 'file'; path = $x.FullName }) 'Could be a legitimate community tool.' 'Verify the publisher; uninstall if unknown.' @('masquerading') }
        }
    }
    $ids = @($ext | Where-Object { $_.id -eq 'Anthropic.claude-code' -and $_.galleryId } | ForEach-Object galleryId | Select-Object -Unique)
    if ($ids.Count -gt 1) { F 'claude.install' 'medium' 'suspicious' 'Claude Code extension gallery IDs differ between editors' @([ordered]@{ type = 'config'; ids = $ids }) 'Marketplace migration could change IDs.' 'Reinstall from the official marketplace.' }
    if (@($ext | Where-Object { $_.signatureP7s }).Count -eq 0 -and $ext.Count) { Set-BvsCheckStatus -Id 'claude.install' -Status partial -Reason ('.signature.p7s is not kept after install by VS Code-family editors (' + ($p7s -join '; ') + '); used extensions.json source/publisherId and Authenticode of bundled binaries instead') }
    $lu = Read-Json (Join-Path $CD '.last-update-result.json')
    $Inv.install = [ordered]@{ cli = $cli; extensions = $ext; signatureFiles = $p7s; lastUpdate = $lu }
    @($cli) + @($ext)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.config.global' -Description '~\.claude.json parsed in-process (account identifiers dropped): MCP servers, projects, trust, allowedTools, connectors' -Script {
    if (-not (Test-Path -LiteralPath $CJ)) { Set-BvsCheckStatus -Id 'claude.config.global' -Status not_applicable -Reason 'no ~\.claude.json'; return }
    $j = Read-Json $CJ 64MB; if ($null -eq $j) { throw 'could not parse ~\.claude.json' }
    Remove-Sens $j; $script:CJData = $j
    Add-Mcp $j['mcpServers'] $CJ 'user (~\.claude.json)'
    $pl = foreach ($k in @(if ($j['projects'] -is [Collections.IDictionary]) { $j['projects'].Keys })) {
        $p = $j['projects'][$k]; Add-Mcp $p['mcpServers'] $CJ "project $k"; Add-Proj $k 'claude.json'
        $at = @(Get-L $p['allowedTools'] | ForEach-Object { [string]$_ })
        if ($at.Count) { [void](Invoke-Perms @{ allow = $at } "$CJ#projects[$k].allowedTools" 'project-allowedTools') }
        [ordered]@{ path = $k; exists = [IO.Directory]::Exists(($k -replace '/', '\')); trustAccepted = $p['hasTrustDialogAccepted']; allowedTools = @($at | ForEach-Object { Mask $_ 200 }); mcpServers = @(if ($p['mcpServers'] -is [Collections.IDictionary]) { $p['mcpServers'].Keys }); enabledMcpjsonServers = @(Get-L $p['enabledMcpjsonServers']); externalIncludesApproved = $p['hasClaudeMdExternalIncludesApproved'] }
    }
    if ($j['githubRepoPaths'] -is [Collections.IDictionary]) { foreach ($v in $j['githubRepoPaths'].Values) { foreach ($x in (Get-L $v)) { Add-Proj $x 'githubRepoPaths' } } }
    $Inv.claudeJson = [ordered]@{ path = $CJ; droppedKeys = $DropKeys; installMethod = $j['installMethod']; autoUpdates = $j['autoUpdates']; autoUpdatesProtectedForNative = $j['autoUpdatesProtectedForNative']; numStartups = $j['numStartups']; projects = @($pl); connectorsEverConnected = @(Get-L $j['claudeAiMcpEverConnected']); remoteControlSurfacesSeen = @(Get-L $j['remoteControlSurfacesSeen']); skillUsage = @(if ($j['skillUsage'] -is [Collections.IDictionary]) { $j['skillUsage'].Keys }); pluginUsage = @(if ($j['pluginUsage'] -is [Collections.IDictionary]) { $j['pluginUsage'].Keys }) }
    @($pl)
}

$Prune = @('node_modules', '.git', '__pycache__', '.venv', 'venv', 'site-packages', '.pnpm-store', '.next', '.turbo', 'AppData', 'dist', 'build', '.cache', 'worktrees')
$Found = @()
$null = Invoke-BvsCheck -Run $run -Id 'claude.projects.discover' -Description 'Project roots: ~\.claude.json keys, githubRepoPaths, history.jsonl, filesystem search under %USERPROFILE% (depth 4, node_modules etc. skipped), .claude\worktrees' -Script {
    $script:Found = @(Get-BvsFiles -Path $UP -MaxDepth 4 -PruneDirNames $Prune -Include (@($Ioc.instructionFileNames) + @($Ioc.mcpConfigFileNames) + @('settings.json', 'settings.local.json', '*.mdc')) | Where-Object { -not (Test-Own $_.FullName) })
    foreach ($f in $script:Found) {
        $d = $f.Directory
        if ($f.Name -like 'settings*.json') { if ($d.Name -eq '.claude') { Add-Proj $d.Parent.FullName 'fs:.claude' } }
        elseif ($f.Name -in $Ioc.instructionFileNames -or $f.Name -eq '.mcp.json') { Add-Proj $d.FullName "fs:$($f.Name)" }
    }
    $hj = Join-Path $CD 'history.jsonl'
    if (Test-Path -LiteralPath $hj) { foreach ($l in [IO.File]::ReadLines($hj)) { if ($l -match '"project":"((?:[^"\\]|\\.)*)"') { Add-Proj ([regex]::Unescape($Matches[1])) 'history.jsonl' } } }
    foreach ($pr in @($Proj.Values)) { $wt = Join-Path $pr.path '.claude\worktrees'; if (Test-Path -LiteralPath $wt) { foreach ($w in Get-ChildItem -LiteralPath $wt -Directory -Force) { Add-Proj $w.FullName 'worktree' } } }
    $Inv.projects = @($Proj.Values | ForEach-Object { [ordered]@{ path = $_.path; sources = @($_.sources) } })
    @($Proj.Values)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.settings' -Description 'User, project, worktree and package-embedded settings*.json: hooks, statusLine/helpers, env, permissions, MCP toggles, marketplaces' -Script {
    $userSet = @((Join-Path $CD 'settings.json'), (Join-Path $CD 'settings.local.json'))
    foreach ($p in $userSet) { if (Test-Path -LiteralPath $p) { Invoke-Settings $p 'user' $UP } }
    foreach ($pr in @($Proj.Values)) { foreach ($n in 'settings.json', 'settings.local.json') { $p = Join-Path $pr.path ".claude\$n"; if ((Test-Path -LiteralPath $p) -and $p -notin $userSet) { Invoke-Settings $p $(if ($pr.sources -contains 'worktree') { 'worktree' } elseif ($n -eq 'settings.json') { 'project-shared' } else { 'project-local' }) $pr.path } } }
    foreach ($f in $Found) { if ($f.Name -like 'settings*.json' -and $f.Directory.Name -eq '.claude' -and (Test-PkgEmbedded $f.FullName)) { Invoke-Settings $f.FullName 'package-embedded' $f.Directory.Parent.FullName } }
    $Inv.settings = @($SetRecs)
    @($SetRecs)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.settings.managed' -Description 'Managed policy: %ProgramFiles%/%ProgramData%\ClaudeCode\managed-settings.json, managed-mcp.json, HKLM/HKCU\SOFTWARE\Policies\ClaudeCode' -Script {
    $hits = @()
    foreach ($b in @($env:ProgramFiles, $env:ProgramData)) { foreach ($n in 'managed-settings.json', 'managed-mcp.json') {
        $p = Join-Path $b "ClaudeCode\$n"
        if (Test-Path -LiteralPath $p) { $hits += $p; if ($n -like '*mcp*') { $mj = Read-Json $p; if ($mj) { Add-Mcp $mj['mcpServers'] $p 'managed' } } else { Invoke-Settings $p 'managed' $null }; F 'claude.settings.managed' 'high' 'suspicious' "Managed Claude Code policy file present: $p" @([ordered]@{ type = 'file'; path = $p; sha256 = (Get-BvsHash -Path $p) }) 'Expected only on company-managed machines.' 'If you did not deploy it, inspect and remove it (admin needed); it overrides your own settings.' @('persistence') }
    } }
    foreach ($k in 'HKLM\SOFTWARE\Policies\ClaudeCode', 'HKCU\SOFTWARE\Policies\ClaudeCode') { $v = @(Get-BvsRegValues $k); $sk = @(Get-BvsRegSubKeys $k); if ($v.Count -or $sk.Count) { $hits += $k; F 'claude.settings.managed' 'high' 'suspicious' "Claude Code policy registry key present: $k" @([ordered]@{ type = 'registry'; path = $k; values = @($v | ForEach-Object { "$($_.Name)=" + (Mask "$($_.Value)" 120) }) }) 'Expected only on managed machines.' 'Inspect and remove if not deployed by you.' @('persistence') } }
    $Inv.managed = $hits
    $hits
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.mcp.files' -Description 'Every project .mcp.json plus MCP files found by the filesystem search' -Script {
    $seen = @{}
    foreach ($f in $Found) { if ($f.Name -in $Ioc.mcpConfigFileNames -and -not $seen[$f.FullName]) { $seen[$f.FullName] = 1; $m = Read-Json $f.FullName; if ($m) { Add-Mcp ($m['mcpServers'] ?? $m['servers']) $f.FullName 'mcp file' $(if ($f.FullName -like '*\agent-plugins\*') { 'vscode-agent' } else { 'claude-code' }) } } }
    foreach ($pr in @($Proj.Values)) { $p = Join-Path $pr.path '.mcp.json'; if ((Test-Path -LiteralPath $p) -and -not $seen[$p]) { $seen[$p] = 1; $m = Read-Json $p; if ($m) { Add-Mcp ($m['mcpServers'] ?? $m['servers']) $p 'project .mcp.json' } } }
    @($seen.Keys)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.plugins' -Description 'Plugins: installed_plugins.json, known_marketplaces.json, blocklist, account-synced plugins; hooks/.mcp.json/commands/agents/skills of each installed plugin' -Script {
    $pd = Join-Path $CD 'plugins'; if (-not (Test-Path -LiteralPath $pd)) { Set-BvsCheckStatus -Id 'claude.plugins' -Status not_applicable -Reason 'no plugins folder'; return }
    $km = Read-Json (Join-Path $pd 'known_marketplaces.json'); $ip = Read-Json (Join-Path $pd 'installed_plugins.json'); $bl = Read-Json (Join-Path $pd 'blocklist.json')
    $mk = @(foreach ($n in @(if ($km) { $km.Keys })) { $s = $km[$n]['source']; $id = "$($s['repo'])$($s['url'])$($s['path'])"; $fp = $id -in $Ioc.firstPartyMarketplaces
        if (-not $fp) { F 'claude.plugins' 'medium' 'suspicious' "Non-official plugin marketplace registered: $n ($id)" @([ordered]@{ type = 'config'; path = (Join-Path $pd 'known_marketplaces.json'); marketplace = $n; source = $id }) 'Team marketplaces are legitimate.' 'Verify the owner; remove it if unknown.' }
        [ordered]@{ name = $n; source = $s['source']; id = $id; firstParty = $fp; lastUpdated = $km[$n]['lastUpdated'] } })
    $dirs = [Collections.Generic.List[object]]::new()
    if ($ip -and $ip['plugins'] -is [Collections.IDictionary]) { foreach ($k in @($ip['plugins'].Keys)) { foreach ($e in (Get-L $ip['plugins'][$k])) { if ($e['installPath']) { $dirs.Add([ordered]@{ id = $k; dir = $e['installPath']; firstParty = [bool]@($mk | Where-Object { $_.name -eq ($k -split '@')[-1] -and $_.firstParty }).Count; synced = $false }) } } } }
    foreach ($b in @(Get-ChildItem -LiteralPath (Join-Path $pd 'synced') -Directory -Force -ErrorAction SilentlyContinue)) {
        $mf = Read-Json (Join-Path $b.FullName 'manifest.json')
        foreach ($p in (Get-L $mf['plugins'])) { $dir = Join-Path $b.FullName $p['name']; $pj = Read-Json (Join-Path $dir '.claude-plugin\plugin.json'); if (-not $pj) { $pj = @{} }; $dirs.Add([ordered]@{ id = "$(if ($pj['name']) { $pj['name'] } else { $p['name'] })@synced"; dir = $dir; firstParty = ($p['marketplaceName'] -in $Ioc.firstPartySyncedMarketplaces); synced = $true; marketplace = $p['marketplaceName']; version = $pj['version']; author = $(if ($pj['author'] -is [Collections.IDictionary]) { $pj['author']['name'] } else { $pj['author'] }) }) }
    }
    foreach ($x in $dirs) {
        if (-not (Test-Path -LiteralPath $x.dir)) { continue }
        $hj = Read-Json (Join-Path $x.dir 'hooks\hooks.json'); if ($hj -and $hj['hooks'] -is [Collections.IDictionary]) { $x.hooks = @(Invoke-Hooks $hj['hooks'] (Join-Path $x.dir 'hooks\hooks.json') "plugin $($x.id)" $x.dir) }
        $mj = Read-Json (Join-Path $x.dir '.mcp.json'); if ($mj) { Add-Mcp ($mj['mcpServers'] ?? $mj) (Join-Path $x.dir '.mcp.json') "plugin $($x.id)" 'claude-code' -FirstParty:$x.firstParty }
        $pj = Read-Json (Join-Path $x.dir '.claude-plugin\plugin.json'); if ($pj -and $pj['mcpServers'] -is [Collections.IDictionary]) { Add-Mcp $pj['mcpServers'] $x.dir "plugin $($x.id)" 'claude-code' -FirstParty:$x.firstParty }
        $SkUnits.Add([pscustomobject]@{ Name = $x.id; Dir = $x.dir; Kind = $(if ($x.synced) { 'plugin-synced' } else { 'plugin' }); FirstParty = $x.firstParty })
        if ($x.synced) { F 'claude.plugins' 'info' 'info' "Account-synced plugin $($x.id) from $($x.marketplace)" @([ordered]@{ type = 'file'; path = $x.dir; version = $x.version; author = $x.author; mcp = @($McpRecs | Where-Object { $_.scope -eq "plugin $($x.id)" } | ForEach-Object { "$($_.name) -> $($_.url)" }) }) 'Delivered by claude.ai account sync from the Anthropic directory.' 'Disable it in claude.ai if unused.' @() 'high' }
    }
    $Inv.plugins = [ordered]@{ marketplaces = $mk; installed = @($dirs); blocklist = @(if ($bl) { Get-L $bl['plugins'] | ForEach-Object { $_['plugin'] } }); installedPluginsJson = [bool]$ip }
    @($dirs)
}

function Add-Unit([string]$dir, [string]$kind, [bool]$fp) {
    $i = Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue; if (-not $i) { return }
    if ($i.LinkType -and $i.Target) { $t = @($i.Target)[0]; if (-not [IO.Path]::IsPathRooted($t)) { $t = Join-Path $i.Parent.FullName $t }; $i = Get-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue; if (-not $i) { return } }
    if (-not $i.PSIsContainer) { if ($i.Length -lt 300) { $Stubs.Add($i.FullName) }; return }
    if ((Test-Own $i.FullName) -or @($SkUnits | Where-Object { $_.Dir -eq $i.FullName }).Count) { return }
    $SkUnits.Add([pscustomobject]@{ Name = $i.Name; Dir = $i.FullName; Kind = $kind; FirstParty = $fp })
}
$null = Invoke-BvsCheck -Run $run -Id 'claude.skills' -Description 'Skills (user, account-synced, project .claude\skills + .agents\skills, plugins, Codex, VS Code agent plugins): SHA-256 of every file, content heuristics, invisible Unicode, allowed-tools, skills-CLI lock verification, provenance' -Script {
    foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $CD 'skills') -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name -eq 'synced') { foreach ($b in @(Get-ChildItem -LiteralPath $d.FullName -Directory -Force)) { foreach ($s in @(Get-ChildItem -LiteralPath $b.FullName -Directory -Force | Where-Object { -not $_.Name.StartsWith('.') })) { Add-Unit $s.FullName 'account-synced' $true } } }
        else { Add-Unit $d.FullName 'user' $false }
    }
    foreach ($base in @($Proj.Values | ForEach-Object path) + @($UP)) { foreach ($sd in '.claude\skills', '.agents\skills') { if ((Join-Path $base $sd) -eq (Join-Path $CD 'skills')) { continue }; foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $base $sd) -Force -ErrorAction SilentlyContinue)) { Add-Unit $s.FullName $(if ($sd -like '.agents*') { 'agents-standard' } else { 'project' }) $false } } }
    foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $UP '.codex\skills') -Directory -Force -ErrorAction SilentlyContinue)) { if ($s.Name -eq '.system') { foreach ($x in Get-ChildItem -LiteralPath $s.FullName -Directory -Force) { Add-Unit $x.FullName 'codex-system' $true } } else { Add-Unit $s.FullName 'codex' $false } }
    foreach ($s in @(Get-ChildItem -LiteralPath (Join-Path $UP '.vscode\agent-plugins') -Recurse -Directory -Filter skills -Force -ErrorAction SilentlyContinue)) { foreach ($x in Get-ChildItem -LiteralPath $s.FullName -Directory -Force) { Add-Unit $x.FullName 'vscode-agent' $true } }
    $lock = Read-Json (Join-Path $UP '.agents\.skill-lock.json')
    foreach ($u in $SkUnits) {
        $agg = [ordered]@{}; $smp = [ordered]@{}; $dom = @{}; $allowed = $null; $n = 0; $bytes = 0L; $newest = [datetime]::MinValue
        foreach ($f in @(Get-BvsFiles -Path $u.Dir -NoPrune)) {
            if (Test-NoRead $f.FullName) { continue }
            $n++; $bytes += $f.Length; if ($f.LastWriteTimeUtc -gt $newest) { $newest = $f.LastWriteTimeUtc }
            $SkFiles.Add([ordered]@{ unit = $u.Name; kind = $u.Kind; path = $f.FullName; size = $f.Length; modified = $f.LastWriteTimeUtc.ToString('o'); sha256 = (Get-BvsHash -Path $f.FullName -MaxBytes 64MB) })
            if ($f.Extension.ToLowerInvariant() -notin $Ioc.skillTextExtensions -or $f.Length -gt 2MB) { continue }
            $t = Read-Text $f.FullName 2MB; if (-not $t) { continue }
            foreach ($h in (Find-Hits $t)) { $k = $h.Type; if ($k -eq 'base64-blob' -and $f.Extension -notin '.md', '.txt', '.mdc') { $k = 'base64-blob-code' }; $agg[$k] = 1 + [int]$agg[$k]; if (-not $smp.Contains($k) -and $k -notmatch 'benign|^exec$|^network$') { $smp[$k] = [ordered]@{ file = $f.FullName; detail = (Mask $h.Detail 120); snippet = $h.Snippet } } }
            if ($f.Extension -in '.md', '.mdc', '.txt') { foreach ($m in $RX.Url.Matches($t)) { $hh = $m.Groups[1].Value.ToLowerInvariant(); $dom[$hh] = 1 + [int]$dom[$hh] } }
            if ($f.Name -eq 'SKILL.md' -and $t -match '(?s)\A---\s*\r?\n(.*?)\r?\n---' -and $Matches[1] -match '(?m)^allowed-tools\s*:\s*(.+)$') { $allowed = $Matches[1].Trim() }
        }
        $lm = $null; $le = $null
        if ($lock -and $u.Kind -eq 'user' -and $lock['skills'] -is [Collections.IDictionary] -and $lock['skills'].Contains($u.Name)) { $le = $lock['skills'][$u.Name]; try { $lm = ([Convert]::ToHexString((Get-Tree $u.Dir)).ToLowerInvariant() -eq $le['skillFolderHash']) } catch { $lm = $null } }
        $u | Add-Member -NotePropertyMembers @{ Files = $n; Bytes = $bytes; Newest = $(if ($n) { $newest.ToString('o') }); Hits = $agg; Samples = $smp; Domains = @($dom.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 | ForEach-Object { "$($_.Key)($($_.Value))" }); AllowedTools = $allowed; LockMatch = $lm; LockSource = $(if ($le) { $le['source'] }); LockInstalledAt = $(if ($le) { $le['installedAt'] }); ChangedDuringAudit = ($n -and $newest -gt $run.AuditStartUtc) }
    }
    $cliInfo = foreach ($e in @(Get-BvsExpected -Category claudeConfig | Where-Object { $_.match.npmGlobal })) { foreach ($pkgDir in @(Get-Item -Path (Join-Path $env:LOCALAPPDATA 'nvm\*\node_modules') -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName ($e.match.npmGlobal -replace '/', '\') }) + @(Join-Path $env:APPDATA ("npm\node_modules\" + ($e.match.npmGlobal -replace '/', '\')))) { if (Test-Path -LiteralPath $pkgDir) { $pj = Read-Json (Join-Path $pkgDir 'package.json'); [ordered]@{ package = $e.match.npmGlobal; version = $pj['version']; path = $pkgDir; dirCreatedUtc = (Get-Item -LiteralPath $pkgDir).CreationTimeUtc.ToString('o'); postinstall = $(if ($pj['scripts']) { $pj['scripts']['postinstall'] }) } } } }
    $sevMap = [ordered]@{ 'invisible' = @('high', 'suspicious', 'Invisible Unicode (prompt-injection technique) in skill files'); 'exfil-domain' = @('high', 'suspicious', 'Exfiltration-type endpoint referenced by skill files'); 'exfil-instruction' = @('high', 'suspicious', 'Skill text instructs sending secrets out'); 'inject' = @('medium', 'suspicious', 'Prompt-injection phrasing in skill files'); 'credential-read' = @('medium', 'suspicious', 'Skill files read credential files'); 'base64-blob' = @('medium', 'suspicious', 'Long base64 blob inside skill markdown'); 'encoded' = @('medium', 'suspicious', 'Encoded/obfuscated command in skill files'); 'hide' = @('low', 'suspicious', 'Skill tells the agent to keep actions from the user'); 'pipe-to-shell' = @('low', 'hardening', 'Skill tells the agent to pipe a downloaded script into a shell') }
    foreach ($k in $sevMap.Keys) {
        $us = @($SkUnits | Where-Object { $_.Hits[$k] }); if (-not $us.Count) { continue }; $s = $sevMap[$k]
        $exp = if ($ExpSkill -and @($us | Where-Object { $_.Name -like "$($ExpSkill.match.skillPrefix)*" }).Count) { [ordered]@{ id = $ExpSkill.id; applied = $false; note = 'presence is expected; content findings are not covered' } }
        $sev = if (@($us | Where-Object { -not $_.FirstParty }).Count) { $s[0] } else { 'info' }
        F 'claude.skills' $sev $s[1] "$($s[2]): $((@($us | ForEach-Object Name) | Select-Object -Unique) -join ', ')" @($us | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'file'; path = $_.Dir; kind = $_.Kind; count = $_.Hits[$k]; sample = $_.Samples[$k] } }) 'Vendor documentation sometimes contains such wording for UX or install reasons; first-party (Anthropic/OpenAI/Microsoft-synced) skills are capped at info.' 'Read the quoted lines; remove or pin the skill if the instruction is not acceptable to you.' @(if ($k -in 'invisible', 'inject', 'hide') { 'prompt_injection' } elseif ($k -in 'encoded', 'base64-blob') { 'obfuscation' }) 'medium' $exp
    }
    $at = @($SkUnits | Where-Object { $_.AllowedTools -match '^\s*(?:Bash|PowerShell|\*)(?:\(\s*\*\s*\))?\s*(?:,|$)' })
    if ($at.Count) { F 'claude.skills' $(if (@($at | Where-Object { -not $_.FirstParty }).Count) { 'medium' } else { 'info' }) 'hardening' "Skills pre-approve unrestricted shell access (allowed-tools: $(@($at | ForEach-Object AllowedTools | Select-Object -Unique) -join ', ')): $((@($at | ForEach-Object Name) | Select-Object -Unique) -join ', ')" @($at | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'file'; path = (Join-Path $_.Dir 'SKILL.md'); allowedTools = $_.AllowedTools; kind = $_.Kind } }) 'Claude Code treats allowed-tools as tools usable without a prompt while the skill is active; the vendor needs its CLI. Older versions used it only as a restriction list.' 'Narrow it to the vendor CLI, e.g. allowed-tools: Bash(higgsfield:*), or remove the line; keep skills updated from the vendor repo only.' @() 'medium' $(if ($ExpSkill) { [ordered]@{ id = $ExpSkill.id; applied = $false } }) }
    $mm = @($SkUnits | Where-Object { $_.LockMatch -eq $false }); if ($mm.Count) { F 'claude.skills' 'medium' 'suspicious' "Skill content changed after installation: $((@($mm | ForEach-Object Name)) -join ', ')" @($mm | ForEach-Object { [ordered]@{ type = 'file'; path = $_.Dir; lockSource = $_.LockSource; installedAt = $_.LockInstalledAt } }) 'You may have edited the skill yourself.' 'Diff against the vendor repo; reinstall if unexplained.' }
    $tp = @($SkUnits | Where-Object { -not $_.FirstParty -and $_.Kind -in 'user', 'project', 'agents-standard' })
    if ($tp.Count) { F 'claude.skills' 'info' 'info' "$((@($tp | ForEach-Object Name) | Select-Object -Unique).Count) third-party skills installed (lock-verified unchanged: $(@($tp | Where-Object LockMatch).Count))" @($tp | Select-Object -First 20 | ForEach-Object { [ordered]@{ type = 'file'; path = $_.Dir; kind = $_.Kind; files = $_.Files; lockMatch = $_.LockMatch; source = $_.LockSource; installedAt = $_.LockInstalledAt; domains = ($_.Domains -join ' ') } }) 'Expected per config\local\expected.json when they match the listed prefix.' 'Remove skills you no longer use.' @('expected_match') 'high' $(if ($ExpSkill) { [ordered]@{ id = $ExpSkill.id; applied = $true } }) }
    $Inv.skills = [ordered]@{ units = @($SkUnits | ForEach-Object { [ordered]@{ name = $_.Name; kind = $_.Kind; dir = $_.Dir; firstParty = $_.FirstParty; files = $_.Files; bytes = $_.Bytes; newest = $_.Newest; hits = $_.Hits; allowedTools = $_.AllowedTools; lockMatch = $_.LockMatch; lockSource = $_.LockSource; installedAt = $_.LockInstalledAt; changedDuringAudit = $_.ChangedDuringAudit; domains = $_.Domains } }); symlinkStubs = @($Stubs); npmGlobals = @($cliInfo) }
    $Inv.skillFiles = @($SkFiles)
    @($SkUnits)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.instructions' -Description 'CLAUDE.md / CLAUDE.local.md / .claude\rules / agents / commands, AGENTS.md, GEMINI.md, .cursorrules, .cursor\rules, copilot-instructions, .windsurfrules, Claude/Codex memory files' -Script {
    $in = [ordered]@{}
    $add = { param($p, $k) if ($p -and [IO.File]::Exists($p) -and -not (Test-Own $p) -and -not $in.Contains($p)) { $in[$p] = $k } }
    $add.Invoke((Join-Path $CD 'CLAUDE.md'), 'user-global')
    foreach ($f in @(Get-BvsFiles -Path (Join-Path $CD 'rules') -NoPrune -Include *.md)) { $add.Invoke($f.FullName, 'user-rules') }
    foreach ($pr in @($Proj.Values)) {
        foreach ($n in 'CLAUDE.md', 'CLAUDE.local.md', '.claude\CLAUDE.md', 'AGENTS.md', 'AGENTS.override.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules', '.github\copilot-instructions.md') { $add.Invoke((Join-Path $pr.path $n), 'project') }
        foreach ($sd in '.claude\rules', '.cursor\rules', '.claude\agents', '.claude\commands', '.github\instructions') { foreach ($f in @(Get-BvsFiles -Path (Join-Path $pr.path $sd) -NoPrune -Include *.md, *.mdc)) { $add.Invoke($f.FullName, 'project') } }
    }
    foreach ($f in $Found) { if ($f.Name -in $Ioc.instructionFileNames -or $f.Extension -eq '.mdc') { $add.Invoke($f.FullName, $(if (Test-PkgEmbedded $f.FullName) { 'package-embedded' } else { 'project' })) } }
    foreach ($f in @(Get-BvsFiles -Path $PD -NoPrune -Include *.md)) { if ($f.FullName -match '\\memory\\') { $add.Invoke($f.FullName, 'memory') } }
    $add.Invoke((Join-Path $UP '.codex\AGENTS.md'), 'codex'); $add.Invoke((Join-Path $UP '.gemini\GEMINI.md'), 'gemini')
    foreach ($f in @(Get-BvsFiles -Path (Join-Path $UP '.codex\memories') -NoPrune)) { $add.Invoke($f.FullName, 'codex-memory') }
    $recs = foreach ($p in @($in.Keys)) {
        $t = Read-Text $p 4MB; $hs = if ($t) { @(Find-Hits $t) } else { @() }
        [pscustomobject]@{ path = $p; kind = $in[$p]; size = (Get-Item -LiteralPath $p).Length; sha256 = (Get-BvsHash -Path $p); hits = @($hs | Group-Object Type | ForEach-Object { "$($_.Name)=$($_.Count)" }); H = $hs }
    }
    $rules = [ordered]@{ 'invisible' = @('high', 'suspicious', 'Invisible Unicode in instruction/memory files'); 'exfil-instruction' = @('high', 'suspicious', 'Instruction/memory file tells the agent to send secrets out'); 'inject' = @('high', 'suspicious', 'Prompt-injection phrasing in instruction/memory files'); 'hide' = @('medium', 'suspicious', 'Instruction/memory file tells the agent to hide actions from the user'); 'encoded' = @('medium', 'suspicious', 'Encoded command in instruction/memory files'); 'pipe-to-shell' = @('low', 'hardening', 'Instruction file pipes a downloaded script into a shell'); 'exfil-domain' = @('low', 'suspicious', 'Exfiltration-type endpoint named in instruction/memory files') }
    foreach ($k in $rules.Keys) {
        $hit = @($recs | Where-Object { @($_.H | Where-Object Type -eq $k).Count }); if (-not $hit.Count) { continue }
        $grp = @($hit | Group-Object sha256); $r = $rules[$k]; $sev = if (@($hit | Where-Object kind -ne 'package-embedded').Count) { $r[0] } else { 'info' }
        F 'claude.instructions' $sev $r[1] "$($r[2]) ($($grp.Count) distinct files)" @($grp | Select-Object -First 8 | ForEach-Object { $x = $_.Group[0]; $h = @($x.H | Where-Object Type -eq $k)[0]; [ordered]@{ type = 'file'; path = $x.path; copies = $_.Count; kind = $x.kind; detail = (Mask $h.Detail 100); snippet = $h.Snippet } }) 'Security notes and IoC lists can quote such strings.' 'Open the file at the quoted text; delete injected lines and check how they got there.' @('prompt_injection')
    }
    $Inv.instructions = @($recs | Select-Object path, kind, size, sha256, hits)
    @($recs)
}

# ---------- transcripts ----------
$TX = [ordered]@{ files = 0; bytes = 0L; lines = 0L; candidates = 0; parseErrors = 0; excluded = @($Own | Where-Object { $_.StartsWith($PD, $OC) }); partial = $false; elapsedSec = 0; hits = [ordered]@{}; samples = [ordered]@{}; entrypoints = @{}; permissionModes = @{}; bridgedSessions = 0; nodeModulesSessions = [Collections.Generic.List[object]]::new(); credReads = [Collections.Generic.List[object]]::new(); credThenNetwork = [Collections.Generic.List[object]]::new(); skipRuns = [Collections.Generic.List[object]]::new(); postHosts = @{}; mcpCalls = @{} }
function JP($e, [string]$n) { if ($null -eq $e -or $e.ValueKind -ne 'Object') { return $null }; $o = [System.Text.Json.JsonElement]::new(); if ($e.TryGetProperty($n, [ref]$o)) { return $o }; $null }
function JS($e) { if ($null -eq $e) { return $null }; if ($e.ValueKind -eq 'String') { return $e.GetString() }; $e.GetRawText() }
function Get-ToolKind([string]$n) { if ($n -in 'Bash', 'PowerShell', 'Monitor') { 'exec' } elseif ($n -in 'Write', 'Edit', 'MultiEdit', 'NotebookEdit') { 'write' } elseif ($n -in 'Read', 'Grep') { 'read' } elseif ($n -like 'mcp__*') { 'mcp' } elseif ($n -like 'Web*') { 'net-tool' } else { 'tool-other' } }
function Get-TxItems([string]$line, [string]$mode) {
    $L = [Collections.Generic.List[object]]::new()
    if ($mode -eq 'codex') { $k = if ($line -match '"type":"(?:function_call|local_shell_call|custom_tool_call)"') { 'exec' } elseif ($line.Contains('_output"')) { 'output' } elseif ($line.Contains('"role":"user"')) { 'user_text' } else { 'assistant_text' }; $L.Add([pscustomobject]@{ Kind = $k; Tool = 'codex'; Text = $line; Ts = $(if ($line -match '"timestamp":"([^"]+)"') { $Matches[1] }) }); return , $L }
    try { $d = [System.Text.Json.JsonDocument]::Parse($line) } catch { $TX.parseErrors++; return , $L }
    try {
        $r = $d.RootElement; $ts = JS (JP $r 'timestamp')
        if ($mode -eq 'history') { $L.Add([pscustomobject]@{ Kind = 'user_text'; Tool = $null; Text = (JS (JP $r 'display')); Ts = $ts }); return , $L }
        $type = JS (JP $r 'type'); $m = JP $r 'message'
        if ($null -eq $m) { $L.Add([pscustomobject]@{ Kind = 'record'; Tool = $type; Text = $r.GetRawText(); Ts = $ts }); return , $L }
        $c = JP $m 'content'; if ($null -eq $c) { return , $L }
        if ($c.ValueKind -eq 'String') { $L.Add([pscustomobject]@{ Kind = "$($type)_text"; Tool = $null; Text = $c.GetString(); Ts = $ts }); return , $L }
        if ($c.ValueKind -ne 'Array') { return , $L }
        foreach ($it in $c.EnumerateArray()) {
            $t = JS (JP $it 'type')
            if ($t -eq 'tool_use') {
                $n = JS (JP $it 'name'); $in = JP $it 'input'; $k = Get-ToolKind $n
                $tx = if ($null -eq $in) { '' } elseif ($k -eq 'exec' -and $null -ne (JP $in 'command')) { JS (JP $in 'command') } elseif ($k -eq 'read') { "$(JS (JP $in 'file_path'))$(JS (JP $in 'path'))" } else { $in.GetRawText() }
                $L.Add([pscustomobject]@{ Kind = $k; Tool = $n; Text = $tx; Ts = $ts })
            }
            elseif ($t -eq 'tool_result') { $L.Add([pscustomobject]@{ Kind = 'output'; Tool = $null; Text = (JS (JP $it 'content')); Ts = $ts }) }
            elseif ($t -in 'text', 'thinking') { $L.Add([pscustomobject]@{ Kind = $(if ($t -eq 'text') { "$($type)_text" } else { 'thinking' }); Tool = $null; Text = (JS (JP $it $t)); Ts = $ts }) }
        }
    } finally { $d.Dispose() }
    , $L
}
function Add-TxHit([string]$cat, [string]$k, [string]$rel, [int]$ln, [string]$ts, [string]$snip) {
    if (-not $TX.hits.Contains($cat)) { $TX.hits[$cat] = [ordered]@{} }; $TX.hits[$cat][$k] = 1 + [int]$TX.hits[$cat][$k]
    $sk = "$cat|$k"; if (-not $TX.samples.Contains($sk)) { $TX.samples[$sk] = [Collections.Generic.List[object]]::new() }
    if ($TX.samples[$sk].Count -lt $MaxSamples) { $TX.samples[$sk].Add([ordered]@{ file = $rel; line = $ln; ts = $ts; snippet = $snip }) }
}
function Find-CredRead([string]$t, [string]$k) {
    foreach ($m in $RX.Cred.Matches($t)) {
        $ok = $k -eq 'read'
        if (-not $ok) {
            $s = [Math]::Max(0, $m.Index - 200); $seg = @($t.Substring($s, $m.Index - $s) -split '[|;&\r\n]')[-1]
            if ($seg -notmatch '(?:^|\s)(?:-i|--identity-file|-o\s*IdentityFile=?)\s*["'']?\S*$' -and $seg -notmatch '(?i)ssh-(?:keygen|add)\b') { $ok = $RX.Verb.IsMatch($seg) -or ($t.Substring($m.Index, [Math]::Min(120, $t.Length - $m.Index)) -match '^[^|;&\r\n]{0,100}?(?:\.read_text\(|\.read\(\)|ReadAllText)') }
        }
        if ($ok) { $lab = @($Ioc.credentialIssuers | Where-Object { $m.Value -match $_.file })[0]; [pscustomobject]@{ Index = $m.Index; Label = $lab.label; Issuers = @($lab.issuers) } }
    }
}
$null = Invoke-BvsCheck -Run $run -Id 'claude.transcripts' -Description 'Streaming sweep of ~\.claude\projects\**\*.jsonl (this project excluded), history.jsonl and Codex sessions: exfil endpoints, approval-bypass runs, credential reads followed by network calls, POST destinations, MCP/connector calls' -Script {
    if ($SkipTranscripts) { Set-BvsCheckStatus -Id 'claude.transcripts' -Status skipped -Reason '-SkipTranscripts'; return }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $files = @(Get-BvsFiles -Path $PD -NoPrune -Include *.jsonl | Where-Object { -not (Test-Own $_.FullName) } | ForEach-Object { , @($_, 'claude') })
    $hf = Join-Path $CD 'history.jsonl'; if (Test-Path -LiteralPath $hf) { $files += , @((Get-Item -LiteralPath $hf), 'history') }
    $files += @(Get-BvsFiles -Path (Join-Path $UP '.codex\sessions') -NoPrune -Include *.jsonl | ForEach-Object { , @($_, 'codex') })
    $rxCwd = [regex]'"cwd":"((?:[^"\\]|\\.)*)"'; $rxEp = [regex]'"entrypoint":"([\w\-]+)"'; $rxPm = [regex]'"permissionMode":"(\w+)"'
    foreach ($x in $files) {
        if ($sw.Elapsed.TotalSeconds -gt $TranscriptBudgetSec) { $TX.partial = $true; break }
        $f = $x[0]; $mode = $x[1]; $TX.files++; $TX.bytes += $f.Length
        $rel = if ($f.FullName.StartsWith($PD, $OC)) { $f.FullName.Substring($PD.Length + 1) } else { $f.FullName -replace [regex]::Escape($UP), '~' }
        $creds = [Collections.Generic.List[object]]::new(); $nets = [Collections.Generic.List[object]]::new(); $ln = 0; $cwd = $null; $ep = $null; $br = $false
        $fs = [IO.FileStream]::new($f.FullName, 'Open', 'Read', 'ReadWrite, Delete'); $sr = [IO.StreamReader]::new($fs)
        try {
            while ($null -ne ($line = $sr.ReadLine())) {
                $ln++; $TX.lines++
                if ($mode -eq 'claude') {
                    if (-not $cwd) { $cm = $rxCwd.Match($line); if ($cm.Success) { $cwd = [regex]::Unescape($cm.Groups[1].Value); if ($cwd -match '[\\/]node_modules[\\/]') { $TX.nodeModulesSessions.Add([ordered]@{ file = $rel; cwd = $cwd }) } } }
                    if (-not $ep) { $em = $rxEp.Match($line); if ($em.Success) { $ep = $em.Groups[1].Value } }
                    if (-not $br -and $line.Contains('"type":"bridge-session"')) { $br = $true }
                    $pm = $rxPm.Match($line); if ($pm.Success) { $TX.permissionModes[$pm.Groups[1].Value] = 1 + [int]$TX.permissionModes[$pm.Groups[1].Value] }
                }
                if (-not ($RX.Strong.IsMatch($line) -or ($line.Contains('tool_use"') -and $RX.Weak.IsMatch($line)) -or ($mode -eq 'codex' -and $RX.Weak.IsMatch($line)))) { continue }
                $TX.candidates++
                foreach ($it in (Get-TxItems $line $mode)) {
                    $t = [string]$it.Text; if (-not $t) { continue }; if ($t.Length -gt 400000) { $t = $t.Substring(0, 400000) }; $k = $it.Kind
                    $m = $RX.Exfil.Match($t); if ($m.Success) { Add-TxHit 'exfil-endpoint' $k $rel $ln $it.Ts (Snip $t $m.Index) }
                    $m = $RX.Skip.Match($t); if ($m.Success) { Add-TxHit 'approval-bypass' $k $rel $ln $it.Ts (Snip $t $m.Index); if ($k -eq 'exec') { $TX.skipRuns.Add([ordered]@{ file = $rel; line = $ln; ts = $it.Ts; huntTerms = $RX.Hunt.IsMatch($t); localPaths = $RX.Local.IsMatch($t); remote = $RX.Remote.IsMatch($t); snippet = (Snip $t $m.Index) }) } }
                    if ($k -eq 'mcp') { $TX.mcpCalls[$it.Tool] = 1 + [int]$TX.mcpCalls[$it.Tool] }
                    if ($k -in 'exec', 'read') {
                        foreach ($c in @(Find-CredRead $t $k)) { $evr = [ordered]@{ file = $rel; line = $ln; ts = $it.Ts; tool = $it.Tool; credential = $c.Label; issuers = $c.Issuers; snippet = (Snip $t $c.Index) }; $creds.Add($evr); Add-TxHit 'credential-read' $k $rel $ln $it.Ts $evr.snippet }
                        if ($k -eq 'exec' -and $RX.Net.IsMatch($t)) {
                            $us = @(Get-Urls $t); $isPost = $RX.Post.IsMatch($t)
                            $nets.Add([ordered]@{ line = $ln; ts = $it.Ts; hosts = $us; post = $isPost; snippet = (Snip $t $RX.Net.Match($t).Index) })
                            if ($isPost) { foreach ($u in $us) { $key = "$($u.Host)|$($u.Class)"; if (-not $TX.postHosts.Contains($key)) { $TX.postHosts[$key] = [ordered]@{ host = $u.Host; class = $u.Class; n = 0; first = $it.Ts; last = $it.Ts; sample = (Snip $t ([Math]::Max(0, $t.IndexOf($u.Host)))) } }; $TX.postHosts[$key].n++; $TX.postHosts[$key].last = $it.Ts } }
                        }
                    }
                }
            }
        } finally { $sr.Dispose(); $fs.Dispose() }
        foreach ($c in $creds) { $TX.credReads.Add($c); $n = @($nets | Where-Object { $_.line -ge $c.line -and $_.line -le $c.line + 60 })[0]; if ($n) { $TX.credThenNetwork.Add([ordered]@{ read = $c; network = [ordered]@{ line = $n.line; ts = $n.ts; post = $n.post; hosts = @($n.hosts | ForEach-Object { "$($_.Host) [$($_.Class)]" }); snippet = $n.snippet }; sameCommand = ($n.line -eq $c.line); classes = @($n.hosts | ForEach-Object Class); hostNames = @($n.hosts | ForEach-Object Host) }) } }
        if ($ep) { $TX.entrypoints[$ep] = 1 + [int]$TX.entrypoints[$ep] }; if ($br) { $TX.bridgedSessions++ }
    }
    $TX.elapsedSec = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($TX.partial) { Set-BvsCheckStatus -Id 'claude.transcripts' -Status partial -Reason "time budget $TranscriptBudgetSec s reached" }
    # ---- triage ----
    $pairs = @(foreach ($p in $TX.credThenNetwork) { $ext = @($p.hostNames | Where-Object { (Get-HostClass $_) -notin 'local', 'tailnet', 'reserved-test' }); $iss = @($ext | Where-Object { $h = $_; @($p.read.issuers | Where-Object { $h -eq $_ -or $h.EndsWith(".$_") }).Count }); $p.severity = if (-not $ext.Count) { 'low' } elseif ($iss.Count -eq $ext.Count) { 'medium' } elseif ($p.sameCommand) { 'high' } else { 'medium' }; $p })
    foreach ($sv in 'high', 'medium', 'low') {
        $g = @($pairs | Where-Object severity -eq $sv); if (-not $g.Count) { continue }
        F 'claude.transcripts' $sv $(if ($sv -eq 'high') { 'suspicious' } else { 'hardening' }) "Agent session read a credential file and then made a network call ($($g.Count) events; destinations: $((@($g | ForEach-Object hostNames) | Select-Object -Unique) -join ', '))" @($g | Select-Object -First 6 | ForEach-Object { [ordered]@{ type = 'transcript'; file = $_.read.file; line = $_.read.line; ts = $_.read.ts; credential = $_.read.credential; readSnippet = $_.read.snippet; network = $_.network } }) $(if ($sv -eq 'high') { 'Destination is not the credential issuer; could still be your own debugging - check the session.' } else { 'Destination is the issuing service (or local) - typical of user-requested debugging, not exfiltration; the token still passed through a shell and the transcript.' }) 'Open the session at the line shown; if the token value was printed, rotate it (Claude: /logout then /login). Add deny rules for credential files (see posture finding).' @() 'high'
    }
    $plain = @($TX.credReads | Where-Object { $r = $_; -not @($pairs | Where-Object { $_.read -eq $r }).Count })
    if ($plain.Count) { F 'claude.transcripts' 'low' 'hardening' "Agent sessions read credential files $($plain.Count) times without a following network call" @($plain | Select-Object -First 6 | ForEach-Object { [ordered]@{ type = 'transcript'; file = $_.file; line = $_.line; ts = $_.ts; credential = $_.credential; snippet = $_.snippet } }) 'Often legitimate troubleshooting the user asked for.' 'Add permissions.deny Read rules for credential files.' }
    $bad = @($TX.skipRuns | Where-Object { $_.huntTerms -and $_.localPaths -and -not $_.remote })
    if ($bad.Count) { F 'claude.transcripts' 'high' 'suspicious' "AI CLI run with approvals disabled while hunting local secrets ($($bad.Count)) - s1ngularity pattern" @($bad | Select-Object -First 6 | ForEach-Object { [ordered]@{ type = 'transcript'; file = $_.file; line = $_.line; ts = $_.ts; snippet = $_.snippet } }) 'Secret-scanner tests can look like this.' 'Identify what launched it (npm postinstall?); rotate any secrets it could read.' @('prompt_injection') 'medium' }
    $rest = @($TX.skipRuns | Where-Object { $_ -notin $bad })
    if ($rest.Count) { F 'claude.transcripts' 'low' 'hardening' "Agent runs with approvals disabled (--yolo / skip-permissions) executed $($rest.Count) times ($(@($rest | Where-Object remote).Count) inside a remote/VM shell)" @($rest | Select-Object -First 5 | ForEach-Object { [ordered]@{ type = 'transcript'; file = $_.file; line = $_.line; ts = $_.ts; remote = $_.remote; snippet = $_.snippet } }) 'Agent runs the user started on purpose inside a VM or sandbox are expected.' 'Keep approval-bypass runs inside the VM/sandbox only.' }
    if ($TX.permissionModes['bypassPermissions']) { F 'claude.transcripts' 'medium' 'hardening' "Sessions ran in bypassPermissions mode ($($TX.permissionModes['bypassPermissions']) records)" @([ordered]@{ type = 'transcript'; permissionModes = $TX.permissionModes }) 'May be your own sandboxed runs.' 'Use bypass only in disposable sandboxes.' }
    if ($TX.nodeModulesSessions.Count) { F 'claude.transcripts' 'high' 'suspicious' "Claude sessions started inside node_modules ($($TX.nodeModulesSessions.Count)) - typical of a malicious package abusing AI CLIs" @($TX.nodeModulesSessions | Select-Object -First 5) 'A package author testing locally?' 'Identify the package; rotate secrets.' @('persistence') }
    $ph = @($TX.postHosts.Values)
    $ex = @($ph | Where-Object class -eq 'exfil-service'); if ($ex.Count) { F 'claude.transcripts' 'high' 'suspicious' "Executed POST requests to exfiltration-type services: $(($ex | ForEach-Object host) -join ', ')" @($ex | Select-Object -First 6 | ForEach-Object { [ordered]@{ type = 'transcript'; host = $_.host; posts = $_.n; first = $_.first; last = $_.last; sample = $_.sample } }) 'Canary/webhook tests you ran yourself.' 'Check what was sent; rotate exposed secrets.' @('intel_match') }
    $oth = @($ph | Where-Object { $_.class -in 'other', 'other-ip', 'user-content-hosting' } | Sort-Object { $_.n } -Descending)
    if ($oth.Count) { F 'claude.transcripts' 'info' 'info' "Executed POST requests to $($oth.Count) hosts outside the known-provider list (confirm they are yours): $((@($oth | Select-Object -First 12 | ForEach-Object { "$($_.host)($($_.n))" })) -join ', ')" @($oth | Select-Object -First 12 | ForEach-Object { [ordered]@{ type = 'transcript'; host = $_.host; class = $_.class; posts = $_.n; last = $_.last; sample = $_.sample } }) 'Often your own domains, previews and test hosts.' 'Tell us if any host is not yours.' }
    F 'claude.transcripts' 'info' 'info' "Transcript sweep: $($TX.files) files, $([Math]::Round($TX.bytes / 1MB)) MB, $($TX.lines) lines in $($TX.elapsedSec) s; IoC hit contexts: $((@($TX.hits.Keys | ForEach-Object { $c = $_; "$c[" + ((@($TX.hits[$c].Keys | ForEach-Object { "$($_)=$($TX.hits[$c][$_])" })) -join ' ') + ']' })) -join '; ')" @([ordered]@{ type = 'transcript'; excluded = $TX.excluded; permissionModes = $TX.permissionModes; bridgedSessions = $TX.bridgedSessions }) 'Text/output hits are discussion or tool output (security projects), not executed actions.' 'None.'
    $Inv.transcripts = $TX
    $TX.files
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.state' -Description 'Remote Control, IDE lock files (authToken dropped), session key files (counted, never opened), hook endpoint listeners' -Script {
    $locks = @(foreach ($l in @(Get-ChildItem -LiteralPath (Join-Path $CD 'ide') -Filter *.lock -File -ErrorAction SilentlyContinue)) { $o = Read-Json $l.FullName; Remove-Sens $o; [ordered]@{ file = $l.Name; pid = $o['pid']; alive = [bool](Get-Process -Id ([int]$o['pid']) -ErrorAction SilentlyContinue); ideName = $o['ideName']; transport = $o['transport']; workspaceFolders = @(Get-L $o['workspaceFolders']).Count; modified = $l.LastWriteTimeUtc.ToString('o') } })
    $keys = @(Get-ChildItem -LiteralPath (Join-Path $CD 'sessions') -Filter *.key -File -ErrorAction SilentlyContinue).Count
    if ($RC.Count) { F 'claude.state' 'low' 'hardening' "Remote Control starts with every session (remoteControlAtStartup=true; $($TX.bridgedSessions) bridged transcripts)" @([ordered]@{ type = 'config'; path = ($RC -join '; '); key = 'remoteControlAtStartup'; surfaces = @($script:CJData['remoteControlSurfacesSeen']) }) 'Convenient phone/web control you chose.' 'Anyone who gets into your claude.ai account can drive local sessions; enable it per session instead and protect the account with 2FA.' }
    $ports = foreach ($hp in @($HookPorts | Group-Object port)) {
        $p = [int]$hp.Name; $c = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
        $own = foreach ($x in $c) { $pr = Get-Process -Id $x.OwningProcess -ErrorAction SilentlyContinue; [ordered]@{ address = $x.LocalAddress; pid = $x.OwningProcess; process = $pr.ProcessName; path = $pr.Path; signer = (Get-BvsSignature $pr.Path).Signer } }
        [ordered]@{ port = $p; usedBy = @($hp.Group | ForEach-Object { "$($_.event) in $($_.source)" }); listening = @($own); note = $(if (-not $c.Count) { 'nothing listening now: any local process could bind this port and answer the hook' }) }
    }
    $Inv.state = [ordered]@{ ideLocks = $locks; staleIdeLocks = @($locks | Where-Object { -not $_.alive }).Count; sessionKeyFiles = $keys; remoteControlSettings = @($RC); hookEndpoints = @($ports) }
    @($locks)
}

$null = Invoke-BvsCheck -Run $run -Id 'ai.other_tools' -Description 'Codex config.toml (approval/sandbox/MCP; auth file never opened), Cursor/VS Code/Claude Desktop/Gemini/Windsurf MCP configs, Ollama models, AI-related environment variables' -Script {
    $o = [ordered]@{}
    $ct = Read-Text (Join-Path $UP '.codex\config.toml')
    if ($ct) {
        $c = ConvertFrom-Toml $ct; Add-Mcp $c['mcp_servers'] (Join-Path $UP '.codex\config.toml') 'codex config.toml' 'codex'
        $o.codex = [ordered]@{ model = $c['model']; approval_policy = $c['approval_policy']; sandbox_mode = $c['sandbox_mode']; windowsSandbox = $(if ($c['windows']) { $c['windows']['sandbox'] }); mcpServers = @(if ($c['mcp_servers']) { $c['mcp_servers'].Keys }); trustedProjects = @(if ($c['projects']) { $c['projects'].Keys | Where-Object { $c['projects'][$_]['trust_level'] -eq 'trusted' } }); plugins = @(if ($c['plugins']) { $c['plugins'].Keys }) }
        if ($c['approval_policy'] -eq 'never' -and $c['sandbox_mode'] -eq 'danger-full-access') { F 'ai.codex' 'high' 'hardening' 'Codex runs with approval_policy=never and sandbox_mode=danger-full-access' @([ordered]@{ type = 'config'; path = (Join-Path $UP '.codex\config.toml') }) 'Only acceptable in a disposable VM.' 'Use on-request approvals and workspace-write.' }
        elseif ($c['sandbox_mode'] -eq 'danger-full-access') { F 'ai.codex' 'medium' 'hardening' 'Codex sandbox_mode=danger-full-access' @([ordered]@{ type = 'config'; path = (Join-Path $UP '.codex\config.toml') }) 'Deliberate choice?' 'Use workspace-write.' }
    }
    foreach ($m in @(@('cursor', (Join-Path $UP '.cursor\mcp.json')), @('vscode', (Join-Path $env:APPDATA 'Code\User\mcp.json')), @('vscode-insiders', (Join-Path $env:APPDATA 'Code - Insiders\User\mcp.json')), @('claude-desktop', (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json')), @('gemini', (Join-Path $UP '.gemini\settings.json')), @('windsurf', (Join-Path $UP '.codeium\windsurf\mcp_config.json')))) {
        $j = Read-Json $m[1]; if ($j) { Add-Mcp ($j['mcpServers'] ?? $j['servers']) $m[1] "$($m[0]) config" $m[0]; $o[$m[0]] = 'present' }
    }
    foreach ($s in @((Join-Path $env:APPDATA 'Code\User\settings.json'), (Join-Path $env:APPDATA 'Cursor\User\settings.json'))) { $j = Read-Json $s; if ($j -and $j['mcp'] -is [Collections.IDictionary]) { Add-Mcp $j['mcp']['servers'] $s 'editor settings.json' 'editor' } }
    $mdir = if ($env:OLLAMA_MODELS) { $env:OLLAMA_MODELS } else { Join-Path $UP '.ollama\models' }
    $o.ollamaModels = @(Get-ChildItem -LiteralPath (Join-Path $mdir 'manifests') -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { ($_.FullName.Substring($mdir.Length) -split '\\')[-2..-1] -join ':' })
    $o.env = @(foreach ($sc in 'Process', 'User', 'Machine') { foreach ($kv in [Environment]::GetEnvironmentVariables($sc).GetEnumerator()) { $k = [string]$kv.Key; if ($k -in $Ioc.envKeysOfInterest -or @($Ioc.envKeyPrefixesOfInterest | Where-Object { $k.StartsWith($_, $OC) }).Count) { [ordered]@{ scope = $sc; name = $k; value = $(if ($k -match '(?i)KEY|TOKEN|SECRET|PASSWORD|HEADERS|AUTH') { '[set]' } elseif ("$($kv.Value)" -match '^(?i)https?://') { Protect-BvsUrl "$($kv.Value)" } else { Mask "$($kv.Value)" 80 }) } } } })
    $Inv.otherTools = $o
    @($o.Keys)
}

$null = Invoke-BvsCheck -Run $run -Id 'ai.connectors' -Description 'Account-level claude.ai connectors (cloud-side, never called): least-privilege reminder from local evidence' -Script {
    $names = [ordered]@{}
    foreach ($n in @(Get-L $script:CJData['connectorsEverConnected']) + @(Get-L $script:CJData['claudeAiMcpEverConnected'])) { foreach ($nn in ([string]$n -split '\s*claude\.ai\s+')) { if ($nn.Trim()) { $names[$nn.Trim()] = 0 } } }
    $na =Read-Json (Join-Path $CD 'mcp-needs-auth-cache.json'); foreach ($n in @(if ($na) { $na.Keys })) { $names[($n -replace '^claude\.ai\s+', '')] = 0 }
    $calls = @{}; foreach ($k in @($TX.mcpCalls.Keys)) { if ($k -match '^mcp__claude_ai_(.+?)__(.+)$') { $cn = $Matches[1] -replace '_', ' '; $tl = $Matches[2]; if (-not $calls.Contains($cn)) { $calls[$cn] = [ordered]@{ total = 0; writeLike = [ordered]@{} } }; $calls[$cn].total += $TX.mcpCalls[$k]; if ($tl -match $Ioc.writeCapableToolVerbs) { $calls[$cn].writeLike[$tl] = $TX.mcpCalls[$k] } } }
    $list = foreach ($n in @($names.Keys) + @($calls.Keys | Where-Object { -not $names.Contains($_) })) {
        $hint = @($Ioc.connectorCapabilityHints | Where-Object { $n -match $_.regex } | ForEach-Object hint) -join '; '
        $cc = @($calls.Keys | Where-Object { $_ -ieq $n -or $_ -ieq ($n -replace '\s', ' ') })[0]
        [ordered]@{ connector = $n; capabilityHint = $hint; transcriptCalls = $(if ($cc) { $calls[$cc].total } else { 0 }); writeLikeCalls = $(if ($cc) { $calls[$cc].writeLike } else { $null }) }
    }
    if (@($list).Count) { F 'ai.connectors' 'info' 'hardening' "Account connectors to review for least privilege: $((@($list | ForEach-Object connector)) -join ', ')" @($list) 'They live in your claude.ai account, not on this PC; listed from local traces only and never called.' 'In claude.ai > Settings > Connectors, disconnect unused ones; give mail connectors read-only scope where possible; custom connectors (e.g. one that can send, forward and delete mail) deserve the strictest review.' @() 'medium' }
    $Inv.connectors = @($list)
    @($list)
}

$null = Invoke-BvsCheck -Run $run -Id 'claude.permissions.posture' -Description 'Deny-list posture and CLI update hygiene' -Script {
    $u = @($DenyInfo | Where-Object { $_.scope -eq 'user' }); $ud = 0; $ua = 0; foreach ($x in $u) { $ud += [int]$x.deny; $ua += [int]$x.allow }
    if ($u.Count -and -not $ud) { F 'claude.permissions.posture' $(if ($TX.credReads.Count) { 'medium' } else { 'low' }) 'hardening' "No permissions.deny rules in user settings ($ua allow rules)$(if ($TX.credReads.Count) { "; agents read credential files $($TX.credReads.Count) times" })" @($u | ForEach-Object { [ordered]@{ type = 'config'; path = $_.path; allow = $_.allow; deny = 0 } }) 'Many users run without deny rules; risk depends on what agents are asked to do.' 'Add deny rules such as Read(~/.claude/.credentials.json), Read(~/.ssh/**), Read(~/.codex/auth.json), Read(**/.env), Bash(curl:*) for untrusted repos.' }
    $cv = @($Inv.install.cli | Where-Object native | ForEach-Object { try { [version]($_.version -replace '[^\d.]', '') } catch { } }) | Sort-Object -Descending | Select-Object -First 1
    $ev = @($Inv.install.extensions | Where-Object { $_.id -eq 'Anthropic.claude-code' } | ForEach-Object { try { [version]$_.version } catch { } }) | Sort-Object -Descending | Select-Object -First 1
    if ($cv -and $ev -and $cv -lt $ev -and $script:CJData['autoUpdates'] -eq $false) { F 'claude.permissions.posture' 'low' 'hygiene' "Claude Code CLI $cv is older than the editor extension $ev and auto-updates are off" @([ordered]@{ type = 'config'; path = $CJ; key = 'autoUpdates'; value = $false; lastUpdate = $Inv.install.lastUpdate }) 'Pinning a version can be deliberate.' 'Run claude update (or re-enable auto-updates) to get security fixes.' }
    @($u)
}

$Inv.mcpServers = @($McpRecs)
foreach ($k in $Inv.Keys) { Add-BvsInventory -Run $run -Name $k -Data $Inv[$k] }
$sum = Complete-BvsRun -Run $run
"S09 done: $($sum.Findings) findings [$($sum.BySeverity)] checks=$($sum.Checks) errors=$($sum.Errors) -> $($sum.Path)"
foreach ($f in ($run.Findings | Sort-Object { @{ critical = 0; high = 1; medium = 2; low = 3; info = 4 }[$_.severity] } | Select-Object -First 25)) { '  {0,-6} {1,-10} {2}' -f $f.severity, $f.class, (Mask $f.title 150) }
