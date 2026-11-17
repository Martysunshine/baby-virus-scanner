#Requires -Version 7.2
<#
.SYNOPSIS
    Shared helpers for baby-virus-scanner Windows collectors.
.DESCRIPTION
    Everything in this module is READ-ONLY towards the system. The only writes it performs are
    inside the project folder (data\, logs\, intel\), and every JSON document it writes passes
    through secret masking first (fail-closed: masking config missing = error).

    Contract : docs\schema.md
    Rules    : docs\agent-rules.md
#>

$script:Root          = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:ConfigDir     = Join-Path $script:Root 'config'
$script:SigCache      = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$script:WritableCache = @{}
$script:SecretRules   = $null
$script:IntelHosts    = $null
$script:NeverRead     = $null
$script:IdentityInfo  = $null
$script:Expected      = $null
$script:PendingStatus = @{}
$script:Utf8NoBom     = [System.Text.UTF8Encoding]::new($false)
$script:Ellipsis      = [string][char]0x2026

#region ---------- paths and run lifecycle ----------

function Get-BvsRoot { $script:Root }

function Get-BvsScanId {
    $p = Join-Path $script:Root 'data\latest.txt'
    if (-not (Test-Path -LiteralPath $p)) {
        throw 'No active scan: data\latest.txt is missing. Run tools\windows\new-scan.ps1 first.'
    }
    (Get-Content -LiteralPath $p -Raw).Trim()
}

function Get-BvsScanDir {
    param([string]$ScanId)
    if (-not $ScanId) { $ScanId = Get-BvsScanId }
    Join-Path $script:Root "data\$ScanId"
}

function ConvertTo-BvsUtcDate {
    <# .SYNOPSIS Culture-independent UTC date: accepts DateTime (ConvertFrom-Json auto-converts ISO strings) or ISO-8601 text. #>
    param([Parameter(Position = 0)][AllowNull()]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return [datetime]::UtcNow }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

function Initialize-BvsRun {
    <#
    .SYNOPSIS Start a collector run. Returns the $run object every other helper takes.
    .EXAMPLE  $run = Initialize-BvsRun -Module S01 -Area security
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{1,40}$')][string]$Module,
        [ValidateSet('security', 'storage', 'inventory', 'verify', 'admin')][string]$Area = 'security',
        [string]$ScanId
    )
    if (-not $ScanId) { $ScanId = Get-BvsScanId }
    $scanDir = Get-BvsScanDir -ScanId $ScanId
    $outDir = Join-Path $scanDir $Area
    [void][IO.Directory]::CreateDirectory($outDir)
    [void][IO.Directory]::CreateDirectory((Join-Path $script:Root 'logs'))

    $meta = $null
    $metaPath = Join-Path $scanDir 'scan-meta.json'
    if (Test-Path -LiteralPath $metaPath) { $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json }

    $ident = Get-BvsIdentity
    $run = [pscustomobject]@{
        Module        = $Module
        Area          = $Area
        ScanId        = $ScanId
        Root          = $script:Root
        ScanDir       = $scanDir
        OutDir        = $outDir
        LogFile       = Join-Path $script:Root "logs\$Module.log"
        Elevated      = $ident.Elevated
        UserSid       = $ident.User
        AuditStartUtc = ConvertTo-BvsUtcDate $(if ($meta) { $meta.auditStartUtc } else { $null })
        Started       = [datetime]::UtcNow
        Checks        = [System.Collections.Generic.List[object]]::new()
        Findings      = [System.Collections.Generic.List[object]]::new()
        Inventory     = [ordered]@{}
        Errors        = [System.Collections.Generic.List[object]]::new()
        NextFindingNo = 1
    }
    Write-BvsLog -Run $run -Message "start module=$Module area=$Area scan=$ScanId elevated=$($ident.Elevated)"
    $run
}

function Write-BvsLog {
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0:o} [{1}] {2}' -f [datetime]::UtcNow, $Level, (Protect-BvsText $Message)
    [IO.File]::AppendAllText($Run.LogFile, $line + [Environment]::NewLine, $script:Utf8NoBom)
}

function Complete-BvsRun {
    <#
    .SYNOPSIS Write the module envelope data\<scan>\<area>\<Module>.json (masked) and return a summary.
    #>
    param([Parameter(Mandatory)]$Run, [switch]$NoMask)
    $envelope = [ordered]@{
        schema    = 'bvs.module/1'
        module    = $Run.Module
        area      = $Run.Area
        scanId    = $Run.ScanId
        host      = $env:COMPUTERNAME
        platform  = 'windows'
        elevated  = $Run.Elevated
        started   = $Run.Started.ToString('o')
        finished  = [datetime]::UtcNow.ToString('o')
        checks    = @($Run.Checks)
        findings  = @($Run.Findings)
        inventory = $Run.Inventory
        errors    = @($Run.Errors)
    }
    $path = Join-Path $Run.OutDir "$($Run.Module).json"
    [void](Write-BvsJson -InputObject $envelope -Path $path -NoMask:$NoMask)
    $bySev = ($Run.Findings | Group-Object severity | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Write-BvsLog -Run $Run -Message "complete: findings=$($Run.Findings.Count) [$bySev] checks=$($Run.Checks.Count) errors=$($Run.Errors.Count)"
    [pscustomobject]@{ Path = $path; Findings = $Run.Findings.Count; BySeverity = $bySev; Checks = $Run.Checks.Count; Errors = $Run.Errors.Count }
}

#endregion

#region ---------- masking ----------

function Get-BvsSecretRules {
    if ($null -eq $script:SecretRules) {
        $cfgPath = Join-Path $script:ConfigDir 'secret-patterns.json'
        if (-not (Test-Path -LiteralPath $cfgPath)) { throw "Masking config missing: $cfgPath (fail-closed)" }
        $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($r in $cfg.rules) {
            $opts = [Text.RegularExpressions.RegexOptions]::Compiled -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
            $list.Add([pscustomobject]@{
                    Id    = $r.id
                    Kind  = $r.kind
                    Group = [int]$r.group
                    Regex = [regex]::new($r.regex, $opts, [TimeSpan]::FromSeconds(5))
                })
        }
        $script:SecretRules = $list
    }
    $script:SecretRules
}

function Protect-BvsSecret {
    <# .SYNOPSIS Mask one secret value: PEM -> [PRIVATE KEY REDACTED], JWT -> header.[REDACTED].[REDACTED], <20 chars -> [REDACTED:n], else first4…last4. #>
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value -match '-----BEGIN [A-Z0-9 ]*PRIVATE KEY') { return '[PRIVATE KEY REDACTED]' }
    if ($Value -match 'PuTTY-User-Key-File') { return '[PRIVATE KEY REDACTED]' }
    if ($Value -match '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') { return ($Value.Split('.')[0] + '.[REDACTED].[REDACTED]') }
    if ($Value.Length -lt 20) { return "[REDACTED:$($Value.Length)]" }
    $Value.Substring(0, 4) + $script:Ellipsis + $Value.Substring($Value.Length - 4)
}

function Protect-BvsText {
    <# .SYNOPSIS Mask every secret-looking substring in free text using config\secret-patterns.json. #>
    param([Parameter(Position = 0, ValueFromPipeline)][AllowNull()][AllowEmptyString()][string]$Text)
    process {
        if ([string]::IsNullOrEmpty($Text)) { return $Text }
        $out = $Text
        foreach ($rule in (Get-BvsSecretRules)) {
            try { $ms = $rule.Regex.Matches($out) }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return '[REDACTED:mask-timeout]' }
            if ($ms.Count -eq 0) { continue }
            $sb = [System.Text.StringBuilder]::new($out.Length)
            $last = 0
            foreach ($m in $ms) {
                $g = if ($rule.Group -gt 0 -and $m.Groups[$rule.Group].Success) { $m.Groups[$rule.Group] } else { $m }
                if ($g.Index -lt $last) { continue }
                [void]$sb.Append($out, $last, $g.Index - $last)
                [void]$sb.Append((Protect-BvsSecret $g.Value))
                $last = $g.Index + $g.Length
            }
            [void]$sb.Append($out, $last, $out.Length - $last)
            $out = $sb.ToString()
        }
        $out
    }
}

function Find-BvsSecrets {
    <# .SYNOPSIS Return secret hits (rule, kind, offset, masked value) without exposing values. #>
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return }
    foreach ($rule in (Get-BvsSecretRules)) {
        try { $ms = $rule.Regex.Matches($Text) } catch { continue }
        foreach ($m in $ms) {
            $g = if ($rule.Group -gt 0 -and $m.Groups[$rule.Group].Success) { $m.Groups[$rule.Group] } else { $m }
            [pscustomobject]@{ Rule = $rule.Id; Kind = $rule.Kind; Index = $g.Index; Length = $g.Length; Masked = (Protect-BvsSecret $g.Value) }
        }
    }
}

function Protect-BvsUrl {
    <# .SYNOPSIS Drop query string/fragment from a URL and mask credentials. #>
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Url)
    if ([string]::IsNullOrEmpty($Url)) { return $Url }
    $u = $Url -replace '\?.*$', '?[query-removed]' -replace '#.*$', ''
    Protect-BvsText $u
}

#endregion

#region ---------- JSON output ----------

function Write-BvsJson {
    <# .SYNOPSIS Atomically write JSON inside the project folder. Masks secrets unless -NoMask. #>
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Compress,
        [switch]$NoMask,
        [int]$Depth = 32
    )
    $full = [IO.Path]::GetFullPath($Path)
    $rootPrefix = $script:Root.TrimEnd('\') + '\'
    if (-not $full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Write-BvsJson refuses to write outside the project folder: $full"
    }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
    $json = ConvertTo-Json -InputObject $InputObject -Depth $Depth -Compress:$Compress -WarningAction SilentlyContinue
    if (-not $NoMask) { $json = Protect-BvsText $json }
    $tmp = "$full.tmp-$PID"
    [IO.File]::WriteAllText($tmp, $json, $script:Utf8NoBom)
    [IO.File]::Move($tmp, $full, $true)
    $full
}

#endregion

#region ---------- checks, findings, inventory ----------

function Invoke-BvsCheck {
    <#
    .SYNOPSIS Run one check, record its status/timing for the coverage report, return its output.
    .DESCRIPTION Access-denied style errors become 'needs_admin'; other errors 'error'. A check can
                 override its own status from inside the script block with Set-BvsCheckStatus.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][scriptblock]$Script,
        [string]$Description = ''
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rec = [ordered]@{ id = $Id; description = $Description; status = 'ok'; reason = $null; items = 0; ms = 0 }
    $result = $null
    try {
        $result = & $Script
        $rec.items = @($result).Count
    }
    catch {
        $msg = $_.Exception.Message
        $isDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
                    ($_.Exception -is [System.Security.SecurityException]) -or
                    ($msg -match '(?i)access (is )?denied|requires elevation|administrator|privilege|0x80070005')
        $rec.status = if ($isDenied) { 'needs_admin' } else { 'error' }
        $rec.reason = Protect-BvsText $msg
        $Run.Errors.Add([ordered]@{ check = $Id; error = (Protect-BvsText $msg); at = [datetime]::UtcNow.ToString('o') })
    }
    $sw.Stop()
    $rec.ms = $sw.ElapsedMilliseconds
    if ($script:PendingStatus.ContainsKey($Id)) {
        $o = $script:PendingStatus[$Id]
        $rec.status = $o.Status
        if ($o.Reason) { $rec.reason = Protect-BvsText $o.Reason }
        $script:PendingStatus.Remove($Id)
    }
    $Run.Checks.Add([pscustomobject]$rec)
    $suffix = if ($rec.reason) { " : $($rec.reason)" } else { '' }
    Write-BvsLog -Run $Run -Message ("check {0} -> {1} ({2} items, {3} ms){4}" -f $Id, $rec.status, $rec.items, $rec.ms, $suffix)
    $result
}

function Set-BvsCheckStatus {
    <# .SYNOPSIS Called inside an Invoke-BvsCheck script block to set the check's final status. #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('ok', 'partial', 'skipped', 'needs_admin', 'needs_consent', 'not_applicable', 'error')][string]$Status,
        [string]$Reason
    )
    $script:PendingStatus[$Id] = @{ Status = $Status; Reason = $Reason }
}

function New-BvsFinding {
    <# .SYNOPSIS Add a finding (bvs.finding/1) to the run. Evidence is masked when written. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Run,
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
        [object]$Expected = $null,
        [switch]$PassThru
    )
    $id = '{0}-{1:0000}' -f $Run.Module, $Run.NextFindingNo
    $Run.NextFindingNo++
    $f = [pscustomobject][ordered]@{
        id             = $id
        module         = $Run.Module
        check          = $Check
        title          = (Protect-BvsText $Title)
        severity       = $Severity
        class          = $Class
        confidence     = $Confidence
        reasons        = @($Reasons)
        evidence       = @($Evidence)
        entities       = $Entities
        expected       = $Expected
        fp_notes       = (Protect-BvsText $FpNotes)
        recommendation = (Protect-BvsText $Recommendation)
        mitre          = @($Mitre)
        collected_at   = [datetime]::UtcNow.ToString('o')
        collector      = $Run.Module
        verification   = $null
    }
    $Run.Findings.Add($f)
    if ($PassThru) { $f }
}

function Add-BvsInventory {
    <# .SYNOPSIS Store structured data for the dashboard under envelope.inventory.<Name>. #>
    param([Parameter(Mandatory)]$Run, [Parameter(Mandatory)][string]$Name, [AllowNull()]$Data)
    $Run.Inventory[$Name] = $Data
}

function Get-BvsExpected {
    <# .SYNOPSIS Machine-specific known-good items from config\local\expected.json (optionally one category). #>
    param([string]$Category)
    if ($null -eq $script:Expected) {
        $p = Join-Path $script:ConfigDir 'local\expected.json'
        $script:Expected = if (Test-Path -LiteralPath $p) { @((Get-Content -LiteralPath $p -Raw | ConvertFrom-Json).items) } else { @() }
    }
    if ($Category) { @($script:Expected | Where-Object { $_.category -eq $Category }) } else { $script:Expected }
}

#endregion

#region ---------- identity, permissions ----------

function Get-BvsIdentity {
    if ($null -eq $script:IdentityInfo) {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $elev = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $sids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$sids.Add($id.User.Value)
        # .NET's WindowsIdentity.Groups only returns enabled groups (deny-only and logon SIDs excluded).
        foreach ($g in $id.Groups) { [void]$sids.Add($g.Value) }
        if (-not $elev) { [void]$sids.Remove('S-1-5-32-544') }   # belt and braces: filtered admin token
        $script:IdentityInfo = [pscustomobject]@{ User = $id.User.Value; Name = $id.Name; Sids = $sids; Elevated = $elev }
    }
    $script:IdentityInfo
}

function Test-BvsUserWritable {
    <#
    .SYNOPSIS True if the current (non-elevated) user can write/create/delete/re-ACL the path.
    .DESCRIPTION Evaluates the DACL against the user's enabled SIDs, maps generic rights, ignores
                 inherit-only ACEs, applies deny ACEs, and treats ownership as writable (WRITE_DAC).
                 Non-existent paths are evaluated on their nearest existing parent.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try { $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)) } catch { return $null }
    if ($script:WritableCache.ContainsKey($full)) { return $script:WritableCache[$full] }
    $target = $full
    while ($target -and -not (Test-Path -LiteralPath $target)) { $target = [IO.Path]::GetDirectoryName($target) }
    if (-not $target) { return $null }
    $ident = Get-BvsIdentity
    try { $acl = Get-Acl -LiteralPath $target -ErrorAction Stop } catch { $script:WritableCache[$full] = $null; return $null }
    # WriteData|AppendData|WriteEA|WriteAttributes|Delete|WRITE_DAC|WRITE_OWNER|GENERIC_ALL|GENERIC_WRITE
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $allow = 0; $deny = 0
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if (($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (-not $ident.Sids.Contains($ace.IdentityReference.Value)) { continue }
        $rights = [int]$ace.FileSystemRights
        if ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) { $allow = $allow -bor $rights } else { $deny = $deny -bor $rights }
    }
    $owner = try { $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $null }
    $effective = $allow -band (-bnot $deny)
    $writable = (($effective -band $writeMask) -ne 0) -or ($owner -and $owner -ne 'S-1-5-32-544' -and $ident.Sids.Contains($owner))
    $script:WritableCache[$full] = [bool]$writable
    [bool]$writable
}

#endregion

#region ---------- files ----------

function Test-BvsCloudOnly {
    <# .SYNOPSIS True for OneDrive/cloud placeholders (RecallOnDataAccess / RecallOnOpen / Offline). Never open those. #>
    param([Parameter(Mandatory)][IO.FileSystemInfo]$Item)
    $a = [int]$Item.Attributes
    (($a -band 0x400000) -ne 0) -or (($a -band 0x40000) -ne 0) -or (($a -band 0x1000) -ne 0)
}

function Test-BvsNeverRead {
    <# .SYNOPSIS True if the path is on the never-open list (config\never-read.json). #>
    param([Parameter(Mandatory)][string]$Path)
    if ($null -eq $script:NeverRead) {
        $cfg = Get-Content -LiteralPath (Join-Path $script:ConfigDir 'never-read.json') -Raw | ConvertFrom-Json
        $script:NeverRead = @($cfg.patterns | ForEach-Object { [regex]::new($_, 'IgnoreCase, CultureInvariant') })
    }
    foreach ($r in $script:NeverRead) { if ($r.IsMatch($Path)) { return $true } }
    $false
}

function Get-BvsFiles {
    <#
    .SYNOPSIS Fast, safe recursive enumeration (no reparse-point traversal, inaccessible dirs skipped).
    .DESCRIPTION Emits FileInfo (and DirectoryInfo with -Directories). Prunes noisy dirs by name unless -NoPrune.
                 AttributesToSkip is ReparsePoint ONLY (the .NET default would also skip Hidden/System = all of AppData).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [int]$MaxDepth = 32,
        [string[]]$PruneDirNames = @('node_modules', '.git', '__pycache__', '.venv', 'venv', 'site-packages', '.pnpm-store', '.next', '.turbo'),
        [string[]]$Include,
        [Nullable[datetime]]$ModifiedAfter,
        [switch]$Directories,
        [switch]$NoPrune
    )
    $opts = [IO.EnumerationOptions]::new()
    $opts.AttributesToSkip = [IO.FileAttributes]::ReparsePoint
    $opts.IgnoreInaccessible = $true
    $opts.RecurseSubdirectories = $false
    $opts.ReturnSpecialDirectories = $false
    $prune = [System.Collections.Generic.HashSet[string]]::new([string[]]$PruneDirNames, [StringComparer]::OrdinalIgnoreCase)
    $patterns = if ($Include) { @($Include | ForEach-Object { [Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') }) } else { $null }
    $cutoff = if ($ModifiedAfter) { $ModifiedAfter.Value.ToUniversalTime() } else { $null }
    $stack = [System.Collections.Generic.Stack[object]]::new()
    foreach ($p in $Path) {
        $ep = [Environment]::ExpandEnvironmentVariables($p)
        if ([IO.Directory]::Exists($ep)) { $stack.Push(@([IO.DirectoryInfo]::new($ep), 0)) }
    }
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $dir = $cur[0]; $depth = $cur[1]
        try { $entries = $dir.EnumerateFileSystemInfos('*', $opts) } catch { continue }
        try {
            foreach ($e in $entries) {
                if ($e -is [IO.DirectoryInfo]) {
                    if ($Directories) { $e }
                    if ($depth -lt $MaxDepth -and ($NoPrune -or -not $prune.Contains($e.Name))) { $stack.Push(@($e, ($depth + 1))) }
                    continue
                }
                if ($cutoff -and $e.LastWriteTimeUtc -lt $cutoff -and $e.CreationTimeUtc -lt $cutoff) { continue }
                if ($patterns) {
                    $ok = $false
                    foreach ($w in $patterns) { if ($w.IsMatch($e.Name)) { $ok = $true; break } }
                    if (-not $ok) { continue }
                }
                $e
            }
        }
        catch { continue }
    }
}

function Get-BvsSignature {
    <# .SYNOPSIS Authenticode/catalog signature info, cached by path|length|mtime. Skips cloud-only files. #>
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Path)
    process {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        $blank = [ordered]@{ Path = $Path; Exists = $false; Status = 'Missing'; Type = $null; Signer = $null; Issuer = $null; Thumbprint = $null; IsOSBinary = $false; Error = $null }
        try {
            $fi = [IO.FileInfo]::new([Environment]::ExpandEnvironmentVariables($Path))
            if (-not $fi.Exists) { return [pscustomobject]$blank }
            $blank.Path = $fi.FullName; $blank.Exists = $true
            if (Test-BvsCloudOnly $fi) { $blank.Status = 'SkippedCloudOnly'; return [pscustomobject]$blank }
            $key = '{0}|{1}|{2}' -f $fi.FullName.ToLowerInvariant(), $fi.Length, $fi.LastWriteTimeUtc.Ticks
            $cached = $null
            if ($script:SigCache.TryGetValue($key, [ref]$cached)) { return $cached }
            $s = Get-AuthenticodeSignature -LiteralPath $fi.FullName -ErrorAction Stop
            $cert = $s.SignerCertificate
            $r = [pscustomobject][ordered]@{
                Path       = $fi.FullName
                Exists     = $true
                Status     = [string]$s.Status
                Type       = if ($s.PSObject.Properties['SignatureType']) { [string]$s.SignatureType } else { $null }
                Signer     = if ($cert) { $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { $null }
                Issuer     = if ($cert) { $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true) } else { $null }
                Thumbprint = if ($cert) { $cert.Thumbprint } else { $null }
                IsOSBinary = if ($s.PSObject.Properties['IsOSBinary']) { [bool]$s.IsOSBinary } else { $false }
                Error      = $null
            }
            [void]$script:SigCache.TryAdd($key, $r)
            $r
        }
        catch { $blank.Status = 'Error'; $blank.Error = $_.Exception.Message; [pscustomobject]$blank }
    }
}

function Get-BvsHash {
    <# .SYNOPSIS Streaming SHA-256 (shares read/write/delete so it never blocks other programs). Skips cloud-only/oversize. #>
    param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 1GB)
    try {
        $fi = [IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or (Test-BvsCloudOnly $fi) -or $fi.Length -gt $MaxBytes) { return $null }
        $fs = [IO.FileStream]::new($fi.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try { [Convert]::ToHexString($sha.ComputeHash($fs)).ToLowerInvariant() } finally { $sha.Dispose() }
        }
        finally { $fs.Dispose() }
    }
    catch { $null }
}

function Get-BvsVersionInfo {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $v = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        [pscustomobject]@{ CompanyName = $v.CompanyName; ProductName = $v.ProductName; FileDescription = $v.FileDescription; OriginalFilename = $v.OriginalFilename; FileVersion = $v.FileVersion }
    }
    catch { $null }
}

function Get-BvsMotw {
    <# .SYNOPSIS Mark-of-the-Web (Zone.Identifier stream): ZoneId, HostUrl, ReferrerUrl (query strings removed). #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fi = [IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or (Test-BvsCloudOnly $fi)) { return $null }
        $raw = Get-Content -LiteralPath $fi.FullName -Stream 'Zone.Identifier' -Raw -ErrorAction Stop
    }
    catch { return $null }
    $o = [ordered]@{ ZoneId = $null; HostUrl = $null; ReferrerUrl = $null; HostDomain = $null }
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^ZoneId=(\d+)') { $o.ZoneId = [int]$Matches[1] }
        elseif ($line -match '^HostUrl=(.+)$') { $o.HostUrl = Protect-BvsUrl $Matches[1].Trim() }
        elseif ($line -match '^ReferrerUrl=(.+)$') { $o.ReferrerUrl = Protect-BvsUrl $Matches[1].Trim() }
    }
    if ($o.HostUrl) { try { $o.HostDomain = ([uri]($o.HostUrl -replace '\?\[query-removed\]$', '')).Host } catch { } }
    [pscustomobject]$o
}

$script:MagicTable = @(
    @('4D5A', 'pe'), @('7F454C46', 'elf'), @('25504446', 'pdf'), @('504B0304', 'zip'), @('504B0506', 'zip'), @('504B0708', 'zip'),
    @('526172211A07', 'rar'), @('377ABCAF271C', '7z'), @('1F8B', 'gzip'), @('425A68', 'bzip2'), @('FD377A585A00', 'xz'),
    @('D0CF11E0A1B11AE1', 'ole-cfb'), @('4D534346', 'cab'), @('4C0000000114020000000000C000000000000046', 'lnk'),
    @('89504E470D0A1A0A', 'png'), @('FFD8FF', 'jpeg'), @('47494638', 'gif'), @('424D', 'bmp'), @('49492A00', 'tiff'), @('4D4D002A', 'tiff'),
    @('52494646', 'riff'), @('494433', 'mp3'), @('FFFB', 'mp3'), @('FFF3', 'mp3'), @('4F676753', 'ogg'), @('664C6143', 'flac'), @('1A45DFA3', 'mkv'),
    @('3026B2758E66CF11', 'asf'), @('49545346', 'chm'), @('7B5C727466', 'rtf'), @('CAFEBABE', 'java-class'), @('53514C69746520666F726D6174', 'sqlite'),
    @('774F4646', 'woff'), @('774F4632', 'woff2'), @('00010000', 'ttf'), @('4F54544F', 'otf'), @('2321', 'script-shebang'),
    @('3C3F786D6C', 'xml'), @('EFBBBF', 'text-bom'), @('FFFE', 'text-utf16'), @('FEFF', 'text-utf16'), @('0061736D', 'wasm'), @('4D5A9000', 'pe')
)

function Get-BvsMagic {
    <# .SYNOPSIS Identify file type from its first bytes (never opens cloud-only files). Returns Type + Hex. #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fi = [IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or $fi.Length -eq 0 -or (Test-BvsCloudOnly $fi)) { return $null }
        $buf = [byte[]]::new(16)
        $fs = [IO.FileStream]::new($fi.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $n = $fs.Read($buf, 0, 16) } finally { $fs.Dispose() }
    }
    catch { return [pscustomobject]@{ Type = 'unreadable'; Hex = $null } }
    $hex = [Convert]::ToHexString($buf, 0, $n)
    $type = 'unknown'
    if ($hex.Length -ge 16 -and $hex.Substring(8, 8) -eq '66747970') { $type = 'iso-bmff' }
    else {
        foreach ($m in $script:MagicTable) { if ($hex.StartsWith($m[0])) { $type = $m[1]; break } }
        if ($type -eq 'unknown' -and $hex -match '^(3C21|3C68|3C48)') { $type = 'html' }
    }
    [pscustomobject]@{ Type = $type; Hex = $hex }
}

$script:ExtMagic = @{
    '.exe' = 'pe'; '.dll' = 'pe'; '.sys' = 'pe'; '.scr' = 'pe'; '.cpl' = 'pe'; '.ocx' = 'pe'; '.efi' = 'pe'; '.mui' = 'pe'
    '.pdf' = 'pdf'; '.zip' = 'zip'; '.docx' = 'zip'; '.xlsx' = 'zip'; '.pptx' = 'zip'; '.jar' = 'zip'; '.apk' = 'zip'; '.vsix' = 'zip'; '.nupkg' = 'zip'; '.whl' = 'zip'; '.odt' = 'zip'; '.epub' = 'zip'; '.crx' = 'crx'
    '.doc' = 'ole-cfb'; '.xls' = 'ole-cfb'; '.ppt' = 'ole-cfb'; '.msi' = 'ole-cfb'; '.msg' = 'ole-cfb'
    '.rar' = 'rar'; '.7z' = '7z'; '.gz' = 'gzip'; '.tgz' = 'gzip'; '.cab' = 'cab'; '.lnk' = 'lnk'
    '.png' = 'png'; '.jpg' = 'jpeg'; '.jpeg' = 'jpeg'; '.gif' = 'gif'; '.bmp' = 'bmp'; '.tif' = 'tiff'; '.tiff' = 'tiff'
    '.mp4' = 'iso-bmff'; '.m4a' = 'iso-bmff'; '.mov' = 'iso-bmff'; '.heic' = 'iso-bmff'; '.avif' = 'iso-bmff'; '.3gp' = 'iso-bmff'
    '.wav' = 'riff'; '.avi' = 'riff'; '.webp' = 'riff'; '.mp3' = 'mp3'; '.ogg' = 'ogg'; '.flac' = 'flac'; '.mkv' = 'mkv'; '.webm' = 'mkv'; '.wmv' = 'asf'
    '.chm' = 'chm'; '.rtf' = 'rtf'; '.sqlite' = 'sqlite'; '.db' = $null
}

function Test-BvsMagicMismatch {
    <# .SYNOPSIS Compare extension with real header. IsDisguisedExecutable = PE/ELF header behind a non-executable extension (security signal). #>
    param([Parameter(Mandatory)][string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $magic = Get-BvsMagic -Path $Path
    if (-not $magic) { return $null }
    $expected = $script:ExtMagic[$ext]
    $isExecExt = $ext -in '.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.efi', '.mui', '.com', '.pif', '.node', '.pyd', '.so', '.bin', '.dat', ''
    $mismatch = $false
    if ($expected -and $magic.Type -notin 'unknown', 'unreadable') {
        $mismatch = $magic.Type -ne $expected -and -not ($expected -eq 'mp3' -and $magic.Type -eq 'mp3')
    }
    [pscustomobject]@{
        Extension             = $ext
        Expected              = $expected
        Actual                = $magic.Type
        Hex                   = $magic.Hex
        Mismatch              = $mismatch
        IsDisguisedExecutable = ($magic.Type -in 'pe', 'elf') -and -not $isExecExt
    }
}

function Get-BvsSshKeyInfo {
    <#
    .SYNOPSIS Report whether a private key file is passphrase-protected WITHOUT exposing key material.
    .DESCRIPTION Reads the file in memory, inspects only the header / OpenSSH cipher-name field, then discards it.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $info = [ordered]@{ Path = $Path; Format = 'unknown'; Encrypted = $null; Cipher = $null; Kdf = $null }
    try { $text = [IO.File]::ReadAllText($Path) } catch { $info.Format = 'unreadable'; return [pscustomobject]$info }
    try {
        if ($text -match '-----BEGIN OPENSSH PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)-----END') {
            $info.Format = 'openssh'
            $b64 = ($Matches[1] -replace '\s', '')
            $take = [Math]::Min($b64.Length - ($b64.Length % 4), 256)
            $bytes = [Convert]::FromBase64String($b64.Substring(0, $take))
            $magic = [Text.Encoding]::ASCII.GetString($bytes, 0, 14)
            if ($magic -eq 'openssh-key-v1') {
                $o = 15
                $len = ([int]$bytes[$o] -shl 24) -bor ([int]$bytes[$o + 1] -shl 16) -bor ([int]$bytes[$o + 2] -shl 8) -bor [int]$bytes[$o + 3]
                $info.Cipher = [Text.Encoding]::ASCII.GetString($bytes, $o + 4, $len)
                $o = $o + 4 + $len
                $len2 = ([int]$bytes[$o] -shl 24) -bor ([int]$bytes[$o + 1] -shl 16) -bor ([int]$bytes[$o + 2] -shl 8) -bor [int]$bytes[$o + 3]
                $info.Kdf = [Text.Encoding]::ASCII.GetString($bytes, $o + 4, $len2)
                $info.Encrypted = $info.Cipher -ne 'none'
            }
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        elseif ($text -match '-----BEGIN ENCRYPTED PRIVATE KEY-----') { $info.Format = 'pkcs8'; $info.Encrypted = $true }
        elseif ($text -match '-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----') {
            $info.Format = "pem-$($Matches[1].ToLowerInvariant())"
            $info.Encrypted = [bool]($text -match 'Proc-Type:\s*4,ENCRYPTED')
            if ($text -match 'DEK-Info:\s*([A-Z0-9-]+)') { $info.Cipher = $Matches[1] }
        }
        elseif ($text -match '-----BEGIN PRIVATE KEY-----') { $info.Format = 'pkcs8'; $info.Encrypted = $false }
        elseif ($text -match 'PuTTY-User-Key-File-\d') {
            $info.Format = 'ppk'
            if ($text -match 'Encryption:\s*(\S+)') { $info.Cipher = $Matches[1]; $info.Encrypted = $Matches[1] -ne 'none' }
        }
    }
    finally { $text = $null }
    [pscustomobject]$info
}

#endregion

#region ---------- registry ----------

function Split-BvsRegPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKU|HKEY_USERS|HKCR|HKEY_CLASSES_ROOT):?\\?(.*)$') { throw "Bad registry path: $Path" }
    $hiveName = $Matches[1].ToUpperInvariant(); $sub = $Matches[2]
    $hive = switch ($hiveName) {
        { $_ -in 'HKLM', 'HKEY_LOCAL_MACHINE' } { [Microsoft.Win32.RegistryHive]::LocalMachine; break }
        { $_ -in 'HKCU', 'HKEY_CURRENT_USER' } { [Microsoft.Win32.RegistryHive]::CurrentUser; break }
        { $_ -in 'HKU', 'HKEY_USERS' } { [Microsoft.Win32.RegistryHive]::Users; break }
        default { [Microsoft.Win32.RegistryHive]::ClassesRoot }
    }
    , @($hive, $sub)
}

function Open-BvsRegKey {
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('64', '32')][string]$View = '64')
    $parts = Split-BvsRegPath $Path
    $rv = if ($View -eq '32') { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($parts[0], $rv)
    try { $base.OpenSubKey($parts[1], $false) } finally { $base.Dispose() }
}

function Get-BvsRegValues {
    <# .SYNOPSIS Raw registry values (REG_EXPAND_SZ NOT expanded). Returns nothing if the key is missing. #>
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('64', '32')][string]$View = '64')
    $k = Open-BvsRegKey -Path $Path -View $View
    if (-not $k) { return }
    try {
        foreach ($n in $k.GetValueNames()) {
            [pscustomobject]@{
                Key   = $Path
                Name  = $n
                Kind  = [string]$k.GetValueKind($n)
                Value = $k.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
    }
    finally { $k.Dispose() }
}

function Get-BvsRegSubKeys {
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('64', '32')][string]$View = '64')
    $k = Open-BvsRegKey -Path $Path -View $View
    if (-not $k) { return }
    try { $k.GetSubKeyNames() } finally { $k.Dispose() }
}

if (-not ('BvsNative.Reg' -as [type])) {
    Add-Type -Namespace BvsNative -Name Reg -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
public static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, System.IntPtr lpClass,
    System.IntPtr lpcchClass, System.IntPtr lpReserved, System.IntPtr lpcSubKeys, System.IntPtr lpcbMaxSubKeyLen,
    System.IntPtr lpcbMaxClassLen, System.IntPtr lpcValues, System.IntPtr lpcbMaxValueNameLen, System.IntPtr lpcbMaxValueLen,
    System.IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
}

function Get-BvsRegKeyLastWrite {
    <# .SYNOPSIS Key LastWriteTime (UTC) - an approximate "added/changed" time for Run keys, CLSIDs, services, roots. #>
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('64', '32')][string]$View = '64')
    $k = Open-BvsRegKey -Path $Path -View $View
    if (-not $k) { return $null }
    try {
        $ft = 0L
        $z = [IntPtr]::Zero
        $rc = [BvsNative.Reg]::RegQueryInfoKey($k.Handle, $z, $z, $z, $z, $z, $z, $z, $z, $z, $z, [ref]$ft)
        if ($rc -ne 0) { return $null }
        [datetime]::FromFileTimeUtc($ft)
    }
    finally { $k.Dispose() }
}

#endregion

#region ---------- command lines and processes ----------

function Resolve-BvsCommandLine {
    <#
    .SYNOPSIS Split a command line into executable + effective target (DLL for rundll32, script for wscript/powershell -File, ...).
    .DESCRIPTION Also decodes PowerShell -EncodedCommand (masked). Never executes anything.
    #>
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $exe = $null; $argText = ''
    if ($expanded.StartsWith('"')) {
        $end = $expanded.IndexOf('"', 1)
        if ($end -gt 0) { $exe = $expanded.Substring(1, $end - 1); $argText = $expanded.Substring($end + 1).Trim() }
    }
    if (-not $exe) {
        $parts = $expanded -split ' '
        for ($i = 1; $i -le $parts.Count; $i++) {
            $cand = ($parts[0..($i - 1)] -join ' ')
            $rest = if ($i -lt $parts.Count) { ($parts[$i..($parts.Count - 1)] -join ' ') } else { '' }
            if ([IO.File]::Exists($cand)) { $exe = $cand; $argText = $rest; break }
            if ([IO.File]::Exists("$cand.exe")) { $exe = "$cand.exe"; $argText = $rest; break }
        }
        if (-not $exe) { $exe = $parts[0]; $argText = (($parts | Select-Object -Skip 1) -join ' ') }
    }
    if ($exe -and -not [IO.Path]::IsPathRooted($exe)) {
        $c = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $exe = $c.Source }
    }
    $target = $exe; $kind = 'exe'
    $leaf = if ($exe) { [IO.Path]::GetFileName($exe).ToLowerInvariant() } else { '' }
    switch ($leaf) {
        'rundll32.exe' { if ($argText -match '^\s*"?([^",]+)') { $target = $Matches[1].Trim(); $kind = 'dll-via-rundll32' } }
        'regsvr32.exe' { if ($argText -match '"?([^"\s]+\.(?:dll|ocx|sct|ax))') { $target = $Matches[1]; $kind = 'dll-via-regsvr32' } }
        { $_ -in 'wscript.exe', 'cscript.exe' } { if ($argText -match '"?([^"]+?\.(?:vbs|vbe|js|jse|wsf|wsh))') { $target = $Matches[1].Trim(); $kind = 'script-host' } }
        { $_ -in 'powershell.exe', 'pwsh.exe' } { $kind = 'powershell'; if ($argText -match '(?i)-(?:f|file)\s+"?([^"]+?\.ps1)') { $target = $Matches[1].Trim() } }
        'cmd.exe' { $kind = 'cmd'; if ($argText -match '"?([^"\s]+\.(?:bat|cmd))') { $target = $Matches[1] } }
        'mshta.exe' { $kind = 'mshta' }
        'msiexec.exe' { $kind = 'msiexec' }
        'conhost.exe' { $kind = 'conhost' }
    }
    $decoded = $null
    if ($argText -match '(?i)(?:^|\s)-e[a-z]*\s+([A-Za-z0-9+/=]{20,})') {
        try { $decoded = Protect-BvsText ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))) } catch { }
    }
    [pscustomobject]@{
        Raw            = (Protect-BvsText $CommandLine)
        Executable     = $exe
        Target         = $target
        Kind           = $kind
        Arguments      = (Protect-BvsText $argText)
        DecodedCommand = $decoded
    }
}

function Get-BvsProcessTable {
    <# .SYNOPSIS All processes with PID, parent, path (filled from Win32_Service for SYSTEM processes when not elevated), masked command line. #>
    $svcByPid = @{}
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        if ($s.ProcessId) {
            $k = [int]$s.ProcessId
            if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = [System.Collections.Generic.List[object]]::new() }
            $svcByPid[$k].Add($s)
        }
    }
    foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $procId = [int]$p.ProcessId
        $path = $p.ExecutablePath
        $src = 'process'
        $svcs = $svcByPid[$procId]
        if (-not $path -and $svcs) {
            $r = Resolve-BvsCommandLine $svcs[0].PathName
            if ($r) { $path = $r.Executable; $src = 'service' }
        }
        [pscustomobject]@{
            Pid         = $procId
            ParentPid   = [int]$p.ParentProcessId
            Name        = $p.Name
            Path        = $path
            PathSource  = if ($path) { $src } else { 'unavailable' }
            CommandLine = (Protect-BvsText $p.CommandLine)
            Services    = @($svcs | ForEach-Object { $_.Name })
            Started     = $p.CreationDate
            SessionId   = $p.SessionId
        }
    }
}

#endregion

#region ---------- network (threat intel) ----------

function Get-BvsIntelHosts {
    if ($null -eq $script:IntelHosts) { $script:IntelHosts = Get-Content -LiteralPath (Join-Path $script:ConfigDir 'intel-hosts.json') -Raw | ConvertFrom-Json }
    $script:IntelHosts
}

function Assert-BvsIntelHost {
    param([Parameter(Mandatory)][uri]$Uri, [switch]$AllowLan)
    $h = $Uri.Host.ToLowerInvariant()
    if ($AllowLan) {
        $ip = $null
        if ([Net.IPAddress]::TryParse($h, [ref]$ip) -and $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            $b = $ip.GetAddressBytes()
            $lan = ($b[0] -eq 10) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 169 -and $b[1] -eq 254)
            if ($lan -and $Uri.Scheme -in 'http', 'https') { return }
        }
    }
    $entry = @((Get-BvsIntelHosts).hosts) | Where-Object { $_.host -eq $h } | Select-Object -First 1
    if (-not $entry) { throw "Host not in intel allowlist (config\intel-hosts.json): $h" }
    if ($Uri.Scheme -ne 'https' -and -not $entry.allowHttp) { throw "HTTPS required for $h" }
}

function Invoke-BvsIntel {
    <#
    .SYNOPSIS The ONLY way collectors talk to the internet: allowlisted hosts, manual redirect checks, size cap.
    .DESCRIPTION Saves the (masked) response under intel\<host>\ with a .meta.json (url, status, sha256, time).
                 Request headers (e.g. Authorization) are never logged or saved. Returns Status/Content/Json/File.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST', 'HEAD')][string]$Method = 'GET',
        [object]$Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers,
        [string]$SaveName = 'resp',
        [int]$TimeoutSec = 30,
        [long]$MaxBytes = 50MB,
        [switch]$AllowLan,
        [switch]$NoSave
    )
    # HttpClient with auto-redirect OFF: every hop is re-checked against the allowlist.
    # (Invoke-WebRequest -MaximumRedirection 0 throws on 3xx in pwsh 7.6, so it is not used.)
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::All
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $bodyText = if ($null -eq $Body) { $null } elseif ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 -Compress }
    $current = [uri]$Uri
    try {
    for ($hop = 0; $hop -le 3; $hop++) {
        Assert-BvsIntelHost -Uri $current -AllowLan:$AllowLan
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $current)
        [void]$req.Headers.TryAddWithoutValidation('User-Agent', 'baby-virus-scanner/0.1 (local read-only security audit)')
        if ($Headers) { foreach ($k in $Headers.Keys) { if ($k -ne 'Content-Type') { [void]$req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k]) } } }
        if ($null -ne $bodyText) {
            $req.Content = [System.Net.Http.ByteArrayContent]::new([Text.Encoding]::UTF8.GetBytes($bodyText))
            [void]$req.Content.Headers.TryAddWithoutValidation('Content-Type', $ContentType)
        }
        $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $code = [int]$resp.StatusCode
        if ($code -in 301, 302, 303, 307, 308) {
            $loc = $resp.Headers.Location
            $resp.Dispose(); $req.Dispose()
            if (-not $loc) { throw "Redirect without Location from $($current.Host)" }
            $current = if ($loc.IsAbsoluteUri) { $loc } else { [uri]::new($current, $loc) }
            if ($code -eq 303) { $Method = 'GET'; $bodyText = $null }
            continue
        }
        $ms = [IO.MemoryStream]::new()
        $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buf = [byte[]]::new(81920)
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $ms.Write($buf, 0, $n)
            if ($ms.Length -gt $MaxBytes) { $stream.Dispose(); $resp.Dispose(); throw "Response from $($current.Host) exceeds $MaxBytes bytes" }
        }
        $stream.Dispose()
        $bytes = $ms.ToArray()
        $ctype = "$($resp.Content.Headers.ContentType)"
        $resp.Dispose(); $req.Dispose()
        $isText = $ctype -match '(?i)json|text|xml|javascript|html|csv|yaml' -or ($ctype -eq '' -and $bytes.Length -gt 0 -and $bytes -notcontains 0)
        # assign inside the branches: "$x = if (...) { $bytes }" would unroll the byte[] into object[]
        if ($isText) { $content = [Text.Encoding]::UTF8.GetString($bytes) } else { $content = $bytes }
        $len = $bytes.Length
        $file = $null
        if (-not $NoSave) {
            $dir = Join-Path $script:Root ('intel\' + ($current.Host -replace '[^A-Za-z0-9.-]', '_'))
            [void][IO.Directory]::CreateDirectory($dir)
            $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')
            $file = Join-Path $dir ("$stamp-" + ($SaveName -replace '[^A-Za-z0-9._-]', '_'))
            if ($content -is [byte[]]) { [IO.File]::WriteAllBytes($file, $content) }
            else { [IO.File]::WriteAllText($file, (Protect-BvsText ([string]$content)), $script:Utf8NoBom) }
            $meta = [ordered]@{
                url = (Protect-BvsUrl $current.AbsoluteUri); method = $Method; status = $code
                fetchedAtUtc = [datetime]::UtcNow.ToString('o'); bytes = $len
                sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            [IO.File]::WriteAllText("$file.meta.json", ($meta | ConvertTo-Json), $script:Utf8NoBom)
        }
        $json = $null
        if ($content -isnot [byte[]] -and ($ctype -match 'json' -or "$content".TrimStart().StartsWith('{') -or "$content".TrimStart().StartsWith('['))) {
            try { $json = $content | ConvertFrom-Json -Depth 64 } catch { }
        }
        return [pscustomobject]@{ Status = $code; Content = $content; Json = $json; File = $file; Url = $current.AbsoluteUri; ContentType = $ctype }
    }
    throw "Too many redirects for $Uri"
    }
    finally { $client.Dispose() }
}

#endregion

Export-ModuleMember -Function @(
    'Get-BvsRoot', 'Get-BvsScanId', 'Get-BvsScanDir', 'ConvertTo-BvsUtcDate', 'Initialize-BvsRun', 'Write-BvsLog', 'Complete-BvsRun',
    'Get-BvsSecretRules', 'Protect-BvsSecret', 'Protect-BvsText', 'Find-BvsSecrets', 'Protect-BvsUrl',
    'Write-BvsJson',
    'Invoke-BvsCheck', 'Set-BvsCheckStatus', 'New-BvsFinding', 'Add-BvsInventory', 'Get-BvsExpected',
    'Get-BvsIdentity', 'Test-BvsUserWritable',
    'Test-BvsCloudOnly', 'Test-BvsNeverRead', 'Get-BvsFiles', 'Get-BvsSignature', 'Get-BvsHash', 'Get-BvsVersionInfo',
    'Get-BvsMotw', 'Get-BvsMagic', 'Test-BvsMagicMismatch', 'Get-BvsSshKeyInfo',
    'Split-BvsRegPath', 'Open-BvsRegKey', 'Get-BvsRegValues', 'Get-BvsRegSubKeys', 'Get-BvsRegKeyLastWrite',
    'Resolve-BvsCommandLine', 'Get-BvsProcessTable',
    'Get-BvsIntelHosts', 'Assert-BvsIntelHost', 'Invoke-BvsIntel'
)
