#Requires -Version 7.2
<#
.SYNOPSIS
    Privacy check before you commit or publish. Exit 0 = nothing found, 1 = at least one hit.
.DESCRIPTION
    This project sits next to private scan output, and collectors are written while looking at a real
    machine. It is easy to leave a host name, a home network, a user folder or a token in code, docs,
    fixtures or screenshots. This script reads every file git would publish and fails on:

      path      a file under a folder that must never be committed (data\, intel\, logs\, vendor\, ...)
      size      a file larger than -MaxFileMB
      secret    anything the project's own masking engine recognises (config\secret-patterns.json)
      userpath  a user-profile path whose user name is not a known placeholder (demo, tester, <user>, ...)
      ipv4      a private (RFC 1918 / CGNAT) address that is not a well-known example
      mac       a MAC address that is not a well-known example
      email     an e-mail address outside the example domains
      sid       a full Windows account SID
      host      a default Windows computer name (DESKTOP-XXXXXXX, LAPTOP-XXXXXXXX)
      machine   this PC's own computer name, user name, SID or git e-mail
      denylist  a term from config\local\publish-denylist.txt (private, optional, one term per line;
                a line starting with ! marks a term that is public on purpose)
      metadata  a PNG text / EXIF / provenance chunk, or JPEG EXIF (can carry tool and account ids)

    It never prints a secret, a denylist term or a machine identifier in full: those are masked.
    Nothing is changed and nothing leaves the PC.
.PARAMETER Staged
    Check what is staged for the next commit (used by tools\git-hooks\pre-commit).
.PARAMETER Commit
    Check the files of one commit, for example HEAD. Use this on the commit you are about to push.
.PARAMETER MaxFileMB
    Size limit per file.
.EXAMPLE
    pwsh -NoProfile -File tools\windows\check-publish.ps1
.EXAMPLE
    pwsh -NoProfile -File tools\windows\check-publish.ps1 -Commit HEAD
#>
[CmdletBinding(DefaultParameterSetName = 'Tree')]
param(
    [Parameter(ParameterSetName = 'Staged')][switch]$Staged,
    [Parameter(ParameterSetName = 'Commit')][string]$Commit,
    [double]$MaxFileMB = 1.5,
    [int]$MaxHitsPerRule = 40
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'lib\windows\BVS.Common.psm1') -Force
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

#region ---------- what counts as a harmless example ----------
$forbiddenPath = '^(data|intel|logs|holding|backups|vendor|design)/|^config/local/|^tests/ui/shots/|(^|/)__pycache__/|\.pyc$'
$placeholderUsers = @('demo', 'tester', 'jdoe', 'x', 'you', 'user', 'username', 'name', 'alice', 'bob', 'public', 'default', 'all users',
    'defaultuser0', '<user>', '<name>', '<username>', '%username%', '$env:username', '...', '*', '{user}', 'me', 'someone', 'victim')
$exampleIpv4 = @('192.168.0.1', '192.168.1.1', '192.168.1.0', '192.168.0.0', '192.168.56.1', '10.0.0.1', '10.0.0.0', '10.0.2.2', '10.0.2.15',
    '172.16.0.0', '172.16.0.1', '100.64.0.0', '100.64.0.1', '100.64.0.2', '100.100.100.100', '100.101.1.2', '100.101.1.3', '100.101.1.4',
    '192.168.1.10', '192.168.1.20', '192.168.1.50', '192.168.1.100', '192.168.1.255', '10.255.255.255', '172.31.255.255', '192.168.255.255',
    '100.127.255.255')
$exampleMac = @('000000000000', 'ffffffffffff', '001122334455', 'aabbccddeeff', '0123456789ab', 'deadbeef0001', '020000000001', '112233445566')
$exampleMailDomain = '(?i)(^|\.)(example\.(com|org|net)|users\.noreply\.github\.com|invalid|test|localhost)$'
$textExt = '\.(ps1|psm1|psd1|py|js|mjs|cjs|ts|json|md|txt|html|htm|css|svg|tsv|csv|yml|yaml|xml|cmd|bat|sh|toml|ini|cfg)$|(^|/)(LICENSE|NOTICE|\.gitignore|\.gitattributes|pre-commit)$'

# Per-file exemptions for the pattern rules, each with the reason it is safe. Keep this list short.
$exempt = @(
    @{ Path = '^tools/windows/check-publish\.ps1$'; Rules = @('ipv4', 'mac', 'userpath', 'email', 'host'); Why = 'this file lists the example values' }
    @{ Path = '^tests/windows/lib\.selftest\.ps1$'; Rules = @('secret', 'email', 'userpath'); Why = 'synthetic secrets that test the masking engine' }
    @{ Path = '^tests/test_server\.py$'; Rules = @('secret', 'userpath'); Why = 'synthetic secrets and paths that test redaction' }
    @{ Path = '^tests/fixtures/'; Rules = @('secret', 'sid'); Why = 'synthetic demo scan (masked samples, made-up SID) and linter fixtures' }
    @{ Path = '^config/secret-patterns\.json$'; Rules = @('secret'); Why = 'the masking rules themselves' }
    @{ Path = '^lib/windows/BVS\.Common\.psm1$'; Rules = @('secret'); Why = 'code that recognises private-key headers' }
    @{ Path = '^collectors/security/windows/S13-github-npm\.ps1$'; Rules = @('secret'); Why = 'variables named token that hold function results, not literals' }
    @{ Path = '^server/serve\.py$'; Rules = @('secret'); Why = 'a per-start token generated with secrets.token_urlsafe' }
)
#endregion

#region ---------- file list ----------
function Invoke-Git { param([string[]]$GitArgs) $o = & git -C $root @GitArgs 2>$null; if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs -join ' ') failed ($LASTEXITCODE)" }; , @($o) }
$mode = $PSCmdlet.ParameterSetName
$files = switch ($mode) {
    'Staged' { Invoke-Git @('diff', '--cached', '--name-only', '--diff-filter=ACMR') }
    'Commit' { Invoke-Git @('ls-tree', '-r', '--name-only', $Commit) }
    default { Invoke-Git @('ls-files', '--cached', '--others', '--exclude-standard') }
}
$files = @($files | Where-Object { $_ } | Sort-Object -Unique)

function Get-Text([string]$Rel) {
    switch ($mode) {
        'Staged' { return ((& git -C $root show ":$Rel" 2>$null) -join "`n") }
        'Commit' { return ((& git -C $root show "${Commit}:$Rel" 2>$null) -join "`n") }
        default { $p = Join-Path $root $Rel; if (Test-Path -LiteralPath $p -PathType Leaf) { return [IO.File]::ReadAllText($p) } else { return '' } }
    }
}
function Get-SizeBytes([string]$Rel) {
    switch ($mode) {
        'Staged' { return [long]((& git -C $root cat-file -s ":$Rel" 2>$null) | Select-Object -First 1) }
        'Commit' { return [long]((& git -C $root cat-file -s "${Commit}:$Rel" 2>$null) | Select-Object -First 1) }
        default { $p = Join-Path $root $Rel; if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Item -LiteralPath $p).Length } else { return 0 } }
    }
}
#endregion

#region ---------- private terms ----------
$allowTerms = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$deny = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$denyFile = Join-Path $root 'config\local\publish-denylist.txt'
if (Test-Path -LiteralPath $denyFile) {
    foreach ($l in [IO.File]::ReadAllLines($denyFile)) {
        $t = $l.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        if ($t.StartsWith('!')) { [void]$allowTerms.Add($t.Substring(1).Trim()) } else { [void]$deny.Add($t) }
    }
}
$machine = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($v in @($env:COMPUTERNAME, $env:USERNAME, (Split-Path -Leaf $env:USERPROFILE), [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        (& git config --global --get user.email 2>$null))) {
    if ($v -and $v.Length -ge 4 -and $placeholderUsers -notcontains $v.ToLowerInvariant() -and -not $allowTerms.Contains($v)) { [void]$machine.Add($v) }
}
foreach ($a in $allowTerms) { [void]$deny.Remove($a); [void]$machine.Remove($a) }
function New-TermRegex($Set) {
    if (-not $Set.Count) { return $null }
    $alts = @($Set | Sort-Object { - $_.Length } | ForEach-Object { [regex]::Escape($_) }) -join '|'
    [regex]::new("(?<![A-Za-z0-9])(?:$alts)(?![A-Za-z0-9])", 'IgnoreCase, CultureInvariant')
}
$denyRx = New-TermRegex $deny
$machineRx = New-TermRegex $machine
function Hide([string]$s) { if ($s.Length -le 3) { '***' } else { '{0}…({1} chars)' -f $s.Substring(0, 2), $s.Length } }
#endregion

#region ---------- pattern rules ----------
$rxUserPath = [regex]::new('(?i)(?:\b[A-Z]:|/[a-z])(?:[\\/]+)Users(?:[\\/]+)([^\\/\s"''<>|*?:`,;)\]}]+)|(?<![A-Za-z0-9])/(?:home|Users)/([A-Za-z0-9._-]+)|(?<![A-Za-z0-9])[A-Za-z]--Users-([A-Za-z0-9]+)-')
$rxIpv4 = [regex]::new('(?<![0-9.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})(?![0-9.])')
$rxMac = [regex]::new('(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])|(?<![0-9A-Fa-f.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f.])')
$rxMail = [regex]::new('(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![A-Za-z0-9-])')
$rxSid = [regex]::new('S-1-5-21-\d{6,}-\d{6,}-\d{6,}(?:-\d+)?')
$rxHost = [regex]::new('(?<![A-Za-z0-9])(?:DESKTOP|LAPTOP)-[A-Z0-9]{7,8}(?![A-Za-z0-9])')
#endregion

$hits = [System.Collections.Generic.List[object]]::new()
function Add-Hit([string]$Rule, [string]$File, [int]$Line, [string]$What) { $hits.Add([pscustomobject]@{ Rule = $Rule; File = $File; Line = $Line; What = $What }) }
function Test-Exempt([string]$Rel, [string]$Rule) { foreach ($e in $exempt) { if ($Rel -match $e.Path -and $e.Rules -contains $Rule) { return $true } }; $false }
function Get-LineNo([string]$Text, [int]$Index) { $n = 1; for ($i = 0; $i -lt $Index -and $i -lt $Text.Length; $i++) { if ($Text[$i] -eq "`n") { $n++ } }; $n }

function Test-PngMetadata([string]$Rel) {
    $p = Join-Path $root $Rel
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $b = [IO.File]::ReadAllBytes($p)
    if ($b.Length -lt 16 -or $b[0] -ne 0x89 -or $b[1] -ne 0x50) { return }
    $i = 8; $found = [System.Collections.Generic.List[string]]::new()
    while ($i + 12 -le $b.Length) {
        $len = ([int]$b[$i] -shl 24) -bor ([int]$b[$i + 1] -shl 16) -bor ([int]$b[$i + 2] -shl 8) -bor [int]$b[$i + 3]
        $type = [Text.Encoding]::ASCII.GetString($b, $i + 4, 4)
        if ($type -in 'tEXt', 'iTXt', 'zTXt', 'eXIf', 'caBX') { if (-not $found.Contains($type)) { $found.Add($type) } }
        if ($type -eq 'IEND' -or $len -lt 0) { break }
        $i += 12 + $len
    }
    if ($found.Count) { Add-Hit 'metadata' $Rel 0 ("PNG chunks: " + ($found -join ', ')) }
}
function Test-JpegMetadata([string]$Rel) {
    $p = Join-Path $root $Rel
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }
    $b = [IO.File]::ReadAllBytes($p); $n = [Math]::Min($b.Length, 65536)
    $s = [Text.Encoding]::ASCII.GetString($b, 0, $n)
    if ($s.Contains('Exif') -or $s.Contains('http://ns.adobe.com/xap')) { Add-Hit 'metadata' $Rel 0 'JPEG EXIF/XMP block' }
}

foreach ($rel in $files) {
    if ($rel -match $forbiddenPath) { Add-Hit 'path' $rel 0 'file is under a folder that must never be committed'; continue }
    $size = Get-SizeBytes $rel
    if ($size -gt $MaxFileMB * 1MB) { Add-Hit 'size' $rel 0 ('{0:N2} MB' -f ($size / 1MB)) }
    if ($rel -match '\.png$') { Test-PngMetadata $rel; continue }
    if ($rel -match '\.(jpg|jpeg)$') { Test-JpegMetadata $rel; continue }
    if ($rel -notmatch $textExt) { continue }
    $text = Get-Text $rel
    if (-not $text) { continue }

    if (-not (Test-Exempt $rel 'secret')) {
        foreach ($s in @(Find-BvsSecrets $text)) { Add-Hit 'secret' $rel (Get-LineNo $text $s.Index) ("$($s.Rule): $($s.Masked)") }
    }
    if (-not (Test-Exempt $rel 'userpath')) {
        foreach ($m in $rxUserPath.Matches($text)) {
            $u = @($m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value | Where-Object { $_ })[0]
            if (-not $u) { continue }
            $u = $u.Trim('\', '/', '.')
            if ($placeholderUsers -contains $u.ToLowerInvariant() -or $u -match '^[<%$\[{(]' -or $u -match '^\\*$') { continue }
            Add-Hit 'userpath' $rel (Get-LineNo $text $m.Index) (Hide $u)
        }
    }
    if (-not (Test-Exempt $rel 'ipv4')) {
        foreach ($m in $rxIpv4.Matches($text)) { if ($exampleIpv4 -notcontains $m.Value) { Add-Hit 'ipv4' $rel (Get-LineNo $text $m.Index) $m.Value } }
    }
    if (-not (Test-Exempt $rel 'mac')) {
        foreach ($m in $rxMac.Matches($text)) {
            $hex = ($m.Value -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
            if ($hex -notmatch '[a-f]' -and $m.Value -match '\.') { continue }   # 1234.5678.9012 is a number, not a MAC
            if ($exampleMac -notcontains $hex) { Add-Hit 'mac' $rel (Get-LineNo $text $m.Index) $m.Value }
        }
    }
    if (-not (Test-Exempt $rel 'email')) {
        foreach ($m in $rxMail.Matches($text)) {
            if ($m.Groups[1].Value -match $exampleMailDomain) { continue }
            if ($m.Value -match '\.(png|jpg|svg|js|css|json|md|ps1|py)$') { continue }   # asset@2x.png and similar
            Add-Hit 'email' $rel (Get-LineNo $text $m.Index) $m.Value
        }
    }
    if (-not (Test-Exempt $rel 'sid')) { foreach ($m in $rxSid.Matches($text)) { Add-Hit 'sid' $rel (Get-LineNo $text $m.Index) (Hide $m.Value) } }
    if (-not (Test-Exempt $rel 'host')) { foreach ($m in $rxHost.Matches($text)) { Add-Hit 'host' $rel (Get-LineNo $text $m.Index) $m.Value } }
    if ($machineRx) { foreach ($m in $machineRx.Matches($text)) { Add-Hit 'machine' $rel (Get-LineNo $text $m.Index) (Hide $m.Value) } }
    if ($denyRx) { foreach ($m in $denyRx.Matches($text)) { Add-Hit 'denylist' $rel (Get-LineNo $text $m.Index) (Hide $m.Value) } }
}

$label = switch ($mode) { 'Staged' { 'staged files' } 'Commit' { "commit $Commit" } default { 'working tree (tracked + untracked, not ignored)' } }
"check-publish: $($files.Count) files, $label; private terms: $($deny.Count) denylist + $($machine.Count) machine"
if (-not $hits.Count) { 'OK: nothing found.'; exit 0 }
foreach ($g in ($hits | Group-Object Rule | Sort-Object Name)) {
    "[{0}] {1} hit(s)" -f $g.Name, $g.Count
    $g.Group | Select-Object -First $MaxHitsPerRule | ForEach-Object { '   {0}{1}  {2}' -f $_.File, $(if ($_.Line) { ":$($_.Line)" } else { '' }), $_.What }
    if ($g.Count -gt $MaxHitsPerRule) { "   ... and $($g.Count - $MaxHitsPerRule) more" }
}
"FAILED: $($hits.Count) hit(s). Fix each one, or (for a deliberate example) add it to the example lists at the top of this script."
exit 1
