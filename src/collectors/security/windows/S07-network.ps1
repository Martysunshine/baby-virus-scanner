#Requires -Version 7.2
<#
.SYNOPSIS
    S07 Network: live connections, listeners and LAN/tailnet exposure, Windows Firewall, DNS
    integrity (hijack / MITM / WPAD / ARP / IPv6 RA), Wi-Fi security, SMB/NetBIOS and Tailscale.
    Strictly read-only.

.DESCRIPTION
    Part of baby-virus-scanner (contract: docs\schema.md, rules: docs\agent-rules.md).
    Writes only data\<scanId>\security\S07.json (masked, via Complete-BvsRun), logs\S07.log and
    intel\<host>\ (via Invoke-BvsIntel).

    Connection sampling (Get-NetTCPConnection Established/SynSent + Get-NetUDPEndpoint) runs in a
    background thread job: -Samples snapshots, -IntervalSec apart (default 10 x 30 s). All other
    checks run in the foreground meanwhile, so the total runtime is roughly the sampling time.

    Firewall exposure is computed offline: enabled inbound rules (ActiveStore) are joined with their
    application/service/port/address filters on InstanceID and evaluated for every non-loopback
    listener against every active interface (LAN, tailnet, virtual) and its network profile.

    Methodology, heuristics, false positives and coverage gaps: docs\playbooks\S07-network.md.

.PARAMETER Samples
    Number of connection snapshots (default 10).
.PARAMETER IntervalSec
    Seconds between snapshots (default 30).
.PARAMETER NoIntel
    Skip all internet lookups (Tor exit list, Feodo C2 list, DoH reference answers).
.PARAMETER NoTlsProbe
    Skip the TLS issuer probe against router-resolved addresses.
.PARAMETER MaxReverseDns
    Cap on PTR lookups for public remote IPs (default 250, 0 = none).
.PARAMETER ScanId
    Override data\latest.txt.

.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S07-network.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S07-network.ps1 -Samples 2 -IntervalSec 5
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 60)][int]$Samples = 10,
    [ValidateRange(1, 600)][int]$IntervalSec = 30,
    [switch]$NoIntel,
    [switch]$NoTlsProbe,
    [ValidateRange(0, 1000)][int]$MaxReverseDns = 250,
    [string]$ScanId
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force

$initArgs = @{ Module = 'S07'; Area = 'security' }
if ($ScanId) { $initArgs['ScanId'] = $ScanId }
$run = Initialize-BvsRun @initArgs

# Shared state between checks. A hashtable is a reference type, so check script blocks can fill it.
$ctx = @{
    Procs = $null; ProcsAt = [datetime]::MinValue; Interfaces = @(); Columns = @(); OnLink = @(); IpToIf = @{}
    Gateway = $null; GatewayIf = $null; Listeners = @(); Fw = $null; Tor = $null; Feodo = $null
    Ts = $null; TsCancel = @(); TsOtherUserPeers = 0; DiscordInstalled = $false; AvastInstalled = $false
}
$questions = [System.Collections.Generic.List[string]]::new()

#region ---------- constants (generic knowledge, never machine-specific) ----------

$S07 = @{
    SuspiciousPorts   = @{
        4444 = 'Metasploit default handler'; 1337 = 'common backdoor/RAT port'; 31337 = 'Back Orifice / "elite" backdoor'
        5555 = 'ADB / common RAT port'; 6666 = 'IRC botnet'; 6667 = 'IRC botnet'; 6668 = 'IRC botnet'; 6669 = 'IRC botnet'
        9001 = 'Tor ORPort'; 9030 = 'Tor DirPort'; 9050 = 'Tor SOCKS'; 9150 = 'Tor Browser SOCKS'
        3333 = 'mining stratum'; 14444 = 'mining stratum (Monero)'; 5730 = 'mining stratum'; 7777 = 'mining stratum'; 45700 = 'mining stratum (Monero)'
    }
    TorPorts          = @(9001, 9030, 9050, 9150)
    MiningPorts       = @(3333, 14444, 5730, 7777, 45700)
    DiscoveryUdpPorts = @(137, 138, 1900, 3702, 5353, 5355)
    WindowsPorts      = @(135, 139, 445, 5040, 5357, 7680)
    KernelNames       = @('System', 'Idle', 'System Idle Process', 'Registry', 'Memory Compression', 'MemCompression', 'Secure System')
    # Names that must live under %SystemRoot%; elsewhere = masquerading.
    OsNames           = @('svchost.exe', 'lsass.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'spoolsv.exe', 'lsaiso.exe', 'fontdrvhost.exe', 'dwm.exe', 'taskhostw.exe', 'explorer.exe', 'dllhost.exe', 'sihost.exe', 'ctfmon.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'searchindexer.exe', 'wmiprvse.exe')
    # Core OS processes whose path is hidden from a non-elevated token.
    CoreOsNoPath      = @('wininit.exe', 'services.exe', 'lsass.exe', 'csrss.exe', 'smss.exe', 'svchost.exe', 'spoolsv.exe', 'lsaiso.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe')
    TestNames         = @('github.com', 'www.microsoft.com', 'registry.npmjs.org', 'api.anthropic.com', 'www.google.com', 'www.cloudflare.com')
    PublicResolvers   = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15', '2606:4700:4700::1111', '2606:4700:4700::1001', '2001:4860:4860::8888', '2001:4860:4860::8844', '2620:fe::fe', '2620:fe::9')
    TailscaleDns      = @('100.100.100.100', 'fd7a:115c:a1e0::53')
    PlaceholderDns    = @('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
    DefaultControlUrl = 'https://controlplane.tailscale.com'
    PublicCaVendors   = 'DigiCert|GlobalSign|Sectigo|COMODO|USERTrust|ISRG|Let''s Encrypt|Google Trust Services|GTS Root|Amazon|Baltimore|Entrust|GoDaddy|Go Daddy|Starfield|IdenTrust|VeriSign|Thawte|QuoVadis|SSL\.com|Certum|Buypass|HARICA|Actalis|T-TeleSec|SwissSign|Microsoft (RSA|ECC) Root|Microsoft Root Certificate Authority|Certainly|Telia|D-TRUST'
    DnsRules          = @(
        @{ Cat = 'tunnel'; Mitre = 'T1572'; Suffixes = @('ngrok.io', 'ngrok.app', 'ngrok.dev', 'ngrok-free.app', 'ngrok-free.dev', 'trycloudflare.com', 'duckdns.org', 'no-ip.com', 'no-ip.org', 'no-ip.biz', 'no-ip.info', 'noip.com', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net', 'serveftp.com', 'servebeer.com', 'myftp.org', 'redirectme.net', 'loca.lt', 'localtunnel.me', 'serveo.net', 'localhost.run', 'lhr.life', 'pagekite.me', 'bore.pub') }
        @{ Cat = 'request-catcher'; Mitre = 'T1567'; Suffixes = @('webhook.site', 'requestbin.com', 'requestbin.net', 'pipedream.net', 'pipedream.com', 'requestcatcher.com', 'beeceptor.com', 'interact.sh', 'oast.fun', 'oast.live', 'oast.me', 'oast.online', 'oast.pro', 'oast.site', 'oastify.com', 'burpcollaborator.net', 'canarytokens.com') }
        @{ Cat = 'paste-transfer'; Mitre = 'T1567'; Suffixes = @('pastebin.com', 'paste.ee', 'hastebin.com', 'ghostbin.com', 'rentry.co', 'rentry.org', 'paste.rs', 'dpaste.com', 'dpaste.org', 'justpaste.it', 'controlc.com', 'privatebin.net', '0bin.net', 'termbin.com', 'ix.io', 'sprunge.us', 'transfer.sh', 'file.io', 'gofile.io', 'anonfiles.com', 'temp.sh', 'catbox.moe', 'bashupload.com', 'oshi.at', 'filebin.net', 'tmpfiles.org', 'pixeldrain.com') }
        @{ Cat = 'telegram-api'; Mitre = 'T1102'; Suffixes = @('api.telegram.org') }
        @{ Cat = 'discord-webhook-cdn'; Mitre = 'T1102'; Suffixes = @('cdn.discordapp.com', 'media.discordapp.net', 'discordapp.com') }
    )
    BadTlds           = @('top', 'xyz', 'click', 'zip', 'mov', 'icu', 'cyou', 'rest')
    TwoLevelSuffixes  = @('co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.cn', 'com.tw', 'com.hk', 'co.kr', 'co.in', 'co.za', 'com.mx', 'com.tr', 'co.nz', 'com.sg', 'com.ar', 'com.ua', 'co.il', 'com.pl', 'co.id', 'com.my', 'com.vn')
    # Firewall rules of these common apps are expected on developer machines (still signature-checked).
    KnownFirewallApps = @(
        @{ App = 'node'; Rx = '\\node\.exe$' }
        @{ App = 'python'; Rx = '\\pythonw?[\d.]*\.exe$' }
        @{ App = 'virtualbox'; Rx = '\\Oracle\\VirtualBox\\|\\VirtualBox[^\\]*\.exe$|\\VBox[^\\]*\.exe$' }
        @{ App = 'spotify'; Rx = '\\Spotify[^\\]*\.exe$' }
        @{ App = 'discord'; Rx = '\\Discord[^\\]*\\.*\.exe$|\\Discord\.exe$' }
        @{ App = 'docker'; Rx = '\\Docker\\|\\com\.docker\.[^\\]+\.exe$|\\vpnkit[^\\]*\.exe$' }
        @{ App = 'tailscale'; Rx = '\\Tailscale\\' }
    )
    # tailscale debug prefs: ONLY these keys are kept. Everything else (Persist, Config = node keys) is dropped.
    TsPrefsKeep       = @('ControlURL', 'RouteAll', 'ExitNodeID', 'ExitNodeIP', 'ExitNodeAllowLANAccess', 'CorpDNS', 'RunSSH', 'RunWebClient', 'WantRunning', 'LoggedOut', 'ShieldsUp', 'AdvertiseTags', 'Hostname', 'AdvertiseRoutes', 'AdvertiseServices', 'NoSNAT', 'NoStatefulFiltering', 'NetfilterMode', 'AutoUpdate', 'AppConnector', 'PostureChecking', 'OperatorUser', 'RemoteConfig')
    ProfileBits       = @{ Domain = 1; Private = 2; Public = 4 }
}

#endregion

#region ---------- helpers: generic ----------

$script:SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function Limit-S07Severity {
    param([string]$Severity, [string]$Cap)
    if (-not $Cap -or -not $script:SevRank.ContainsKey($Cap)) { return $Severity }
    if ($script:SevRank[$Severity] -gt $script:SevRank[$Cap]) { $Cap } else { $Severity }
}

function Step-S07Severity {
    param([string]$Severity)
    switch ($Severity) { 'info' { 'low' } 'low' { 'medium' } 'medium' { 'high' } default { $Severity } }
}

function ConvertTo-S07Iso {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Year -le 1) { return $null }
        return $Value.ToUniversalTime().ToString('o')
    }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
        if ($d.Year -le 1) { return $null }
        return $d.ToString('o')
    }
    [string]$Value
}

function Get-S07Expected {
    <# First expected.json item of a category for which the predicate returns true. #>
    param([string]$Category, [scriptblock]$Where)
    foreach ($e in @(Get-BvsExpected -Category $Category)) { if (& $Where $e) { return $e } }
    $null
}

function New-S07ExpectedRef {
    param($Item, [string[]]$Cancel = @())
    if (-not $Item) { return $null }
    $c = @($Cancel | Where-Object { $_ })
    [ordered]@{
        id = $Item.id; reason = $Item.reason; severityCap = $Item.severityCap; class = $Item.class
        confirmWithUser = [bool]$Item.confirmWithUser; cancelled = ($c.Count -gt 0); cancelledBecause = $c
    }
}

function Resolve-S07Expected {
    <# A live (not cancelled) expected match caps severity at severityCap (default info) and may set the class. #>
    param([string]$Severity, [string]$Class, $Ref)
    if (-not $Ref -or $Ref.cancelled) { return @($Severity, $Class) }
    $cap = if ($Ref.severityCap) { $Ref.severityCap } else { 'info' }
    $cls = if ($Ref.class) { $Ref.class } else { $Class }
    @((Limit-S07Severity $Severity $cap), $cls)
}

function Add-S07Question {
    param([string]$Text)
    if ($Text -and -not $questions.Contains($Text)) { $questions.Add($Text) }
}

#endregion

#region ---------- helpers: IP math and classification ----------

function ConvertTo-S07Ip {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    $pct = $t.IndexOf('%')
    if ($pct -gt 0) { $t = $t.Substring(0, $pct) }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($t, [ref]$ip)) { return $null }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $ip
}

function Get-S07PrefixBits {
    param([string]$Spec, [int]$Max)
    if ($Spec -match '^\d+$') { return [Math]::Min([int]$Spec, $Max) }
    $m = ConvertTo-S07Ip $Spec
    if (-not $m) { return -1 }
    $bits = 0
    foreach ($b in $m.GetAddressBytes()) { $x = [int]$b; while ($x -band 0x80) { $bits++; $x = ($x -shl 1) -band 0xFF } }
    $bits
}

function Test-S07InPrefix {
    param([Net.IPAddress]$Ip, [Net.IPAddress]$Network, [int]$Bits)
    if (-not $Ip -or -not $Network -or $Ip.AddressFamily -ne $Network.AddressFamily) { return $false }
    $a = $Ip.GetAddressBytes(); $b = $Network.GetAddressBytes()
    for ($i = 0; $i -lt $a.Length -and $Bits -gt 0; $i++) {
        $mask = if ($Bits -ge 8) { 0xFF } else { (0xFF -shl (8 - $Bits)) -band 0xFF }
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
        $Bits -= 8
    }
    $true
}

function Compare-S07IpBytes {
    param([byte[]]$A, [byte[]]$B)
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return ([int]$A[$i] - [int]$B[$i]) } }
    0
}

function Test-S07IpSpec {
    <# Firewall address token: single IP, a.b.c.d/nn, a.b.c.d/255.255.255.0, x::/nn or lo-hi range. #>
    param([Net.IPAddress]$Ip, [string]$Spec)
    if (-not $Ip -or [string]::IsNullOrWhiteSpace($Spec)) { return $false }
    if ($Spec -match '^([^/]+)/(.+)$') {
        $net = ConvertTo-S07Ip $Matches[1]
        if (-not $net) { return $false }
        $max = if ($net.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        $bits = Get-S07PrefixBits -Spec $Matches[2] -Max $max
        if ($bits -lt 0) { return $false }
        return (Test-S07InPrefix -Ip $Ip -Network $net -Bits $bits)
    }
    if ($Spec.Contains('-')) {
        $p = $Spec -split '-', 2
        $lo = ConvertTo-S07Ip $p[0]; $hi = ConvertTo-S07Ip $p[1]
        if (-not $lo -or -not $hi -or $lo.AddressFamily -ne $Ip.AddressFamily) { return $false }
        $x = $Ip.GetAddressBytes()
        return ((Compare-S07IpBytes $x $lo.GetAddressBytes()) -ge 0 -and (Compare-S07IpBytes $x $hi.GetAddressBytes()) -le 0)
    }
    $one = ConvertTo-S07Ip $Spec
    [bool]($one -and $one.Equals($Ip))
}

$script:HasTailscale = $false
$script:IpClassCache = @{}

function Get-S07IpClass {
    <# loopback | rfc1918 | tailscale (100.64/10 when Tailscale present, else cgnat) | linklocal | multicast | ula | public | ... #>
    param([string]$Address)
    if ($script:IpClassCache.ContainsKey($Address)) { return $script:IpClassCache[$Address] }
    $cls = 'invalid'
    $ip = ConvertTo-S07Ip $Address
    if ($ip) {
        $b = $ip.GetAddressBytes()
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            if ($b[0] -eq 0) { $cls = if ($b[1] -eq 0 -and $b[2] -eq 0 -and $b[3] -eq 0) { 'unspecified' } else { 'reserved' } }
            elseif ($b[0] -eq 127) { $cls = 'loopback' }
            elseif ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { $cls = 'rfc1918' }
            elseif ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { $cls = if ($script:HasTailscale) { 'tailscale' } else { 'cgnat' } }
            elseif ($b[0] -eq 169 -and $b[1] -eq 254) { $cls = 'linklocal' }
            elseif ($b[0] -ge 224 -and $b[0] -le 239) { $cls = 'multicast' }
            elseif ($b[0] -eq 255 -and $b[1] -eq 255 -and $b[2] -eq 255 -and $b[3] -eq 255) { $cls = 'broadcast' }
            elseif ($b[0] -ge 240) { $cls = 'reserved' }
            else { $cls = 'public' }
        }
        else {
            if ($ip.Equals([Net.IPAddress]::IPv6Loopback)) { $cls = 'loopback' }
            elseif ($ip.Equals([Net.IPAddress]::IPv6Any)) { $cls = 'unspecified' }
            elseif ($ip.IsIPv6LinkLocal) { $cls = 'linklocal' }
            elseif ($ip.IsIPv6Multicast) { $cls = 'multicast' }
            elseif ($b[0] -eq 0xfd -and $b[1] -eq 0x7a -and $b[2] -eq 0x11 -and $b[3] -eq 0x5c -and $b[4] -eq 0xa1 -and $b[5] -eq 0xe0) { $cls = 'tailscale' }
            elseif (($b[0] -band 0xFE) -eq 0xFC) { $cls = 'ula' }
            elseif ($ip.IsIPv6SiteLocal) { $cls = 'sitelocal' }
            elseif (($b[0] -band 0xE0) -eq 0x20) { $cls = 'public' }
            else { $cls = 'reserved' }
        }
    }
    $script:IpClassCache[$Address] = $cls
    $cls
}

function Test-S07OnLink {
    <# Windows Firewall "LocalSubnet": the address is inside a prefix of a local interface address. #>
    param([Net.IPAddress]$Ip)
    foreach ($o in $ctx.OnLink) { if (Test-S07InPrefix -Ip $Ip -Network $o.Net -Bits $o.Bits) { return $true } }
    $false
}

function Get-S07HostInSubnet {
    <# A representative peer address inside ip/prefix that is neither us nor the gateway. #>
    param([string]$Ip, [int]$Prefix, [string[]]$Avoid)
    $a = ConvertTo-S07Ip $Ip
    if (-not $a -or $Prefix -ge 31) { return $null }
    $bytes = $a.GetAddressBytes()
    $bits = $Prefix
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $mask = if ($bits -ge 8) { 0xFF } elseif ($bits -le 0) { 0 } else { (0xFF -shl (8 - $bits)) -band 0xFF }
        $bytes[$i] = $bytes[$i] -band $mask
        $bits -= 8
    }
    foreach ($add in 2, 3, 4, 5) {
        $c = [byte[]]$bytes.Clone()
        $c[$c.Length - 1] = [byte](($c[$c.Length - 1] + $add) -band 0xFF)
        $cand = [Net.IPAddress]::new($c).ToString()
        if ($Avoid -notcontains $cand) { return $cand }
    }
    $null
}

#endregion

#region ---------- helpers: processes and trust ----------

function Update-S07ProcTable {
    $t = @{}
    foreach ($p in @(Get-BvsProcessTable)) { $t[[int]$p.Pid] = $p }
    $ctx.Procs = $t
    $ctx.ProcsAt = [datetime]::UtcNow
}

function Get-S07Proc {
    param([int]$ProcId)
    if (-not $ctx.Procs) { Update-S07ProcTable }
    $p = $ctx.Procs[$ProcId]
    if (-not $p -and ([datetime]::UtcNow - $ctx.ProcsAt).TotalSeconds -gt 5) { Update-S07ProcTable; $p = $ctx.Procs[$ProcId] }
    $p
}

$script:TrustCache = @{}

function Get-S07Trust {
    <#
    Label: os | signed | unsigned | invalid | missing | unknown (path hidden when not elevated).
    UserWritable: the binary or its folder can be modified by the current non-elevated user.
    #>
    param([string]$Path, [string]$Name, [int]$ProcId = -1)
    if ($ProcId -eq 4 -or $S07.KernelNames -contains $Name) {
        return [pscustomobject]@{ Path = $null; Label = 'os'; SigStatus = 'Kernel'; Signer = 'Microsoft Windows (kernel)'; IsOs = $true; UserWritable = $false; Exists = $true; Masquerading = $false }
    }
    if (-not $Path) {
        $osGuess = $S07.CoreOsNoPath -contains $Name
        return [pscustomobject]@{ Path = $null; Label = 'unknown'; SigStatus = 'PathUnavailable'; Signer = $null; IsOs = $osGuess; UserWritable = $null; Exists = $null; Masquerading = $false }
    }
    $key = $Path.ToLowerInvariant()
    if ($script:TrustCache.ContainsKey($key)) { return $script:TrustCache[$key] }
    $sig = Get-BvsSignature -Path $Path
    $fileW = Test-BvsUserWritable -Path $Path
    $dirW = Test-BvsUserWritable -Path ([IO.Path]::GetDirectoryName($Path))
    $sysRoot = $env:SystemRoot.TrimEnd('\') + '\'
    $inWin = $Path.StartsWith($sysRoot, [StringComparison]::OrdinalIgnoreCase)
    $isOs = ($sig.Status -eq 'Valid') -and ($sig.IsOSBinary -or ($inWin -and "$($sig.Signer)" -match '^Microsoft Windows'))
    $label = switch ($sig.Status) {
        'Valid' { if ($isOs) { 'os' } else { 'signed' } }
        'NotSigned' { 'unsigned' }
        'Missing' { 'missing' }
        'SkippedCloudOnly' { 'unknown' }
        'Error' { 'unknown' }
        default { 'invalid' }
    }
    $leaf = [IO.Path]::GetFileName($Path).ToLowerInvariant()
    $t = [pscustomobject]@{
        Path = $sig.Path; Label = $label; SigStatus = $sig.Status; Signer = $sig.Signer; IsOs = $isOs
        UserWritable = [bool]($fileW -or $dirW); Exists = $sig.Exists
        Masquerading = ($S07.OsNames -contains $leaf) -and -not $inWin
    }
    $script:TrustCache[$key] = $t
    $t
}

function Test-S07Untrusted {
    param($Trust)
    $Trust.Label -in 'unsigned', 'invalid' -or $Trust.Masquerading
}

function New-S07ProcEntity {
    param([int]$ProcId, [string]$Name, [string]$Path, $Trust, [string[]]$Services = @())
    [ordered]@{ pid = $ProcId; name = $Name; path = $Path; services = @($Services); sig = $Trust.SigStatus; signer = $Trust.Signer; userWritable = $Trust.UserWritable }
}

function Get-S07ProcessExpected {
    <# expected.json: category program (exact paths) or editorExtension (binary inside that extension folder). #>
    param([string]$Path)
    if (-not $Path) { return $null }
    foreach ($e in @(Get-BvsExpected -Category 'program')) {
        foreach ($p in @($e.match.paths)) {
            if ($p -and [string]::Equals([Environment]::ExpandEnvironmentVariables($p), $Path, [StringComparison]::OrdinalIgnoreCase)) { return $e }
        }
    }
    foreach ($e in @(Get-BvsExpected -Category 'editorExtension')) {
        foreach ($id in @($e.match.ids)) {
            if ($id -and $Path -match ('(?i)\\extensions\\' + [regex]::Escape($id) + '-[^\\]+\\')) { return $e }
        }
    }
    $null
}

#endregion

#region ---------- helpers: DNS name heuristics ----------

function Get-S07RegLabel {
    <# Registrable label (eTLD+1 without the suffix), with a small two-level public-suffix list. #>
    param([string]$Name)
    $l = $Name.TrimEnd('.').ToLowerInvariant() -split '\.'
    if ($l.Count -lt 2) { return $l[0] }
    $last2 = '{0}.{1}' -f $l[-2], $l[-1]
    if ($l.Count -ge 3 -and $S07.TwoLevelSuffixes -contains $last2) { return $l[-3] }
    $l[-2]
}

function Test-S07Dga {
    <#
    DGA-like registrable label: >= 10 chars of [a-z0-9] and at least 3 of: length >= 14, entropy >= 3.4,
    vowel ratio < 0.22, consonant run >= 5, letters and digits interleaved. Only the registrable label is
    scored, so CDN host names (random subdomains under cloudfront.net, akamaiedge.net, ...) do not trigger.
    #>
    param([string]$Label)
    if (-not $Label -or $Label.Length -lt 10 -or $Label -notmatch '^[a-z0-9]+$') { return $false }
    $freq = @{}
    foreach ($ch in $Label.ToCharArray()) { $freq[$ch] = 1 + [int]$freq[$ch] }
    $h = 0.0
    foreach ($v in $freq.Values) { $p = $v / $Label.Length; $h -= $p * [Math]::Log($p, 2) }
    $vowels = 0; $digits = 0; $run = 0; $maxRun = 0
    foreach ($ch in $Label.ToCharArray()) {
        if ([char]::IsDigit($ch)) { $digits++; $run = 0; continue }
        if ('aeiouy'.IndexOf($ch) -ge 0) { $vowels++; $run = 0 } else { $run++; if ($run -gt $maxRun) { $maxRun = $run } }
    }
    $letters = $Label.Length - $digits
    $score = 0
    if ($Label.Length -ge 14) { $score++ }
    if ($h -ge 3.4) { $score++ }
    if ($letters -gt 0 -and ($vowels / $letters) -lt 0.22) { $score++ }
    if ($maxRun -ge 5) { $score++ }
    if ($digits -ge 2 -and $letters -ge 4 -and $Label -match '[a-z]\d+[a-z]') { $score++ }
    $score -ge 3
}

function Get-S07DnsFlags {
    <# Categories for a DNS name: tunnel, request-catcher, paste-transfer, telegram-api, discord-webhook-cdn, abused-tld, dga-like. #>
    param([string]$Name, [switch]$ServicesOnly)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    $n = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if ($n -match '\.(in-addr|ip6)\.arpa$' -or $n -notmatch '\.') { return }
    foreach ($r in $S07.DnsRules) {
        foreach ($s in $r.Suffixes) {
            if ($n -eq $s -or $n.EndsWith(".$s")) { [pscustomobject]@{ Cat = $r.Cat; Match = $s; Mitre = $r.Mitre }; break }
        }
    }
    if ($ServicesOnly) { return }
    $tld = ($n -split '\.')[-1]
    if ($S07.BadTlds -contains $tld) { [pscustomobject]@{ Cat = 'abused-tld'; Match = ".$tld"; Mitre = $null } }
    $label = Get-S07RegLabel $n
    if (Test-S07Dga $label) { [pscustomobject]@{ Cat = 'dga-like'; Match = $label; Mitre = 'T1568.002' } }
}

#endregion

#region ---------- helpers: netsh parsing (English + Czech labels, value fallbacks) ----------

$S07Wlan = @{
    Name    = '^(Name|Název)$'
    Auth    = '^(Authentication|Ověřování|Ověření)$'
    Cipher  = '^(Cipher|Šifra|Šifrování)$'
    Mode    = '^(Connection mode|Režim připojení)$'
    Ssid    = '^(SSID|SSID name|Název SSID)$'
    Profile = '^(Profile|Profil)$'
    State   = '^(State|Stav)$'
    Radio   = '^(Radio type|Typ rádia|Typ radiového rozhraní)$'
    Band    = '^(Band|Pásmo)$'
    Key     = '^(Security key|Klíč zabezpečení)$'
    Bcast   = '^(Network broadcast|Vysílání sítě)$'
    MacRand = '^(MAC Randomization|Náhodné adresy MAC|Randomizace adresy MAC)$'
}

function ConvertFrom-S07Netsh {
    param([string[]]$Lines)
    foreach ($l in $Lines) {
        if ($l -match '^\s+([^:]+?)\s+:\s?(.*)$') { [pscustomobject]@{ L = $Matches[1].Trim(); V = $Matches[2].Trim() } }
    }
}

function Get-S07WifiSecurity {
    <# Classify auth/cipher lists (one profile may list several pairs). #>
    param([string[]]$Auths, [string[]]$Ciphers)
    $a = @($Auths | Where-Object { $_ }); $c = @($Ciphers | Where-Object { $_ })
    $hasWep = (@($c | Where-Object { $_ -match '(?i)^WEP' }).Count -gt 0) -or (@($a | Where-Object { $_ -match '(?i)^(Shared|Sdílen)' }).Count -gt 0)
    $openish = @($a | Where-Object { $_ -match '(?i)^(Open|Otev)' })
    $allOpen = ($a.Count -gt 0) -and ($openish.Count -eq $a.Count) -and -not $hasWep
    $best = 'unknown'
    if (@($a | Where-Object { $_ -match '(?i)WPA3' }).Count) { $best = 'WPA3' }
    elseif (@($a | Where-Object { $_ -match '(?i)WPA2' }).Count) { $best = 'WPA2' }
    elseif (@($a | Where-Object { $_ -match '(?i)^WPA' }).Count) { $best = 'WPA' }
    elseif (@($a | Where-Object { $_ -match '(?i)OWE' }).Count) { $best = 'OWE' }
    elseif ($hasWep) { $best = 'WEP' }
    elseif ($allOpen) { $best = 'Open' }
    [pscustomobject]@{
        Best       = $best
        Open       = $allOpen
        Wep        = $hasWep
        Tkip       = (@($c | Where-Object { $_ -match '(?i)TKIP' }).Count -gt 0)
        Transition = ((@($a | Where-Object { $_ -match '(?i)WPA3' }).Count -gt 0) -and (@($a | Where-Object { $_ -match '(?i)WPA2' }).Count -gt 0))
        Enterprise = (@($a | Where-Object { $_ -match '(?i)Enterprise|802\.1X' }).Count -gt 0)
    }
}

#endregion

#region ---------- helpers: firewall model and offline rule evaluation ----------

function ConvertTo-S07ProfileMask {
    param($Profile)
    $v = 0L
    try { $v = [long]$Profile } catch { $v = 0L }
    $m = [int]($v -band 7)
    if ($m -eq 0) { 7 } else { $m }
}

function Get-S07FirewallModel {
    <# Bulk read of rules + filters (ActiveStore = effective policy), joined on InstanceID. #>
    $errs = [System.Collections.Generic.List[string]]::new()
    $ev = $null
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev)
    if (@($ev).Count) { $errs.Add("rules: $(@($ev).Count) error(s): $(@($ev)[0].Exception.Message)") }
    $maps = @{}
    foreach ($kind in 'Application', 'Service', 'Port', 'Address', 'InterfaceType', 'Interface') {
        $ev = $null
        $items = switch ($kind) {
            'Application' { @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
            'Service' { @(Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
            'Port' { @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
            'Address' { @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
            'InterfaceType' { @(Get-NetFirewallInterfaceTypeFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
            'Interface' { @(Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable ev) }
        }
        $m = @{}
        foreach ($x in $items) { if ($x) { $m[[string]$x.InstanceID] = $x } }
        $maps[$kind] = $m
        if (@($ev).Count) { $errs.Add("$kind filters: $(@($ev).Count) unreadable ($(@($ev)[0].Exception.Message.Trim()))") }
    }
    $model = foreach ($r in $rules) {
        $id = [string]$r.InstanceID
        $a = $maps['Application'][$id]; $s = $maps['Service'][$id]; $p = $maps['Port'][$id]
        $d = $maps['Address'][$id]; $it = $maps['InterfaceType'][$id]; $if = $maps['Interface'][$id]
        $prog = if ($a) { [string]$a.Program } else { $null }
        $progExp = if ($prog -and $prog -notin 'Any', 'System') { [Environment]::ExpandEnvironmentVariables($prog) } else { $prog }
        $group = [string]$r.Group
        [pscustomobject]@{
            Id = $id; Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; Group = $group
            Enabled = ([string]$r.Enabled -eq 'True'); Direction = [string]$r.Direction; Action = [string]$r.Action
            ProfileMask = (ConvertTo-S07ProfileMask $r.Profile); ProfileText = [string]$r.Profile
            Program = $prog; ProgramExpanded = $progExp
            Package = if ($a) { [string]$a.Package } else { $null }
            Service = if ($s) { [string]$s.Service } else { 'Any' }
            Protocol = if ($p) { [string]$p.Protocol } else { $null }
            LocalPorts = if ($p) { @($p.LocalPort | ForEach-Object { [string]$_ }) } else { $null }
            RemoteAddress = if ($d) { @($d.RemoteAddress | ForEach-Object { [string]$_ }) } else { $null }
            LocalAddress = if ($d) { @($d.LocalAddress | ForEach-Object { [string]$_ }) } else { $null }
            InterfaceType = if ($it) { [string]$it.InterfaceType } else { $null }
            Interfaces = if ($if) { @($if.InterfaceAlias | ForEach-Object { [string]$_ }) } else { $null }
            Owner = [string]$r.Owner; Source = [string]$r.PolicyStoreSourceType; Edge = [string]$r.EdgeTraversalPolicy
            Builtin = (-not $r.Owner) -and ($group -match '^@(?i)(%SystemRoot%|%windir%|FirewallAPI\.dll|[A-Za-z]:\\Windows\\|[A-Za-z0-9_]+\.dll)')
        }
    }
    $profiles = @{}
    foreach ($fp in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
        $dia = [string]$fp.DefaultInboundAction
        $profiles[[string]$fp.Name] = [pscustomobject]@{
            Name = [string]$fp.Name
            Enabled = ([string]$fp.Enabled -ne 'False')
            DefaultInboundAction = if ($dia -eq 'NotConfigured') { 'Block' } else { $dia }
            DefaultOutboundAction = [string]$fp.DefaultOutboundAction
            NotifyOnListen = [string]$fp.NotifyOnListen
            AllowInboundRules = ([string]$fp.AllowInboundRules -ne 'False')
            AllowLocalFirewallRules = [string]$fp.AllowLocalFirewallRules
            LogBlocked = [string]$fp.LogBlocked; LogAllowed = [string]$fp.LogAllowed
        }
    }
    $all = @($model)
    [pscustomobject]@{
        Rules = $all
        Inbound = @($all | Where-Object { $_.Enabled -and $_.Direction -eq 'Inbound' -and $_.Action -in 'Allow', 'Block' -and ($null -eq $_.Protocol -or $_.Protocol -in 'Any', 'TCP', 'UDP', '6', '17') })
        Profiles = $profiles
        Errors = @($errs)
        Coverage = [ordered]@{
            rules = $all.Count; applicationFilters = $maps['Application'].Count; serviceFilters = $maps['Service'].Count
            portFilters = $maps['Port'].Count; addressFilters = $maps['Address'].Count
            interfaceTypeFilters = $maps['InterfaceType'].Count; interfaceFilters = $maps['Interface'].Count
        }
    }
}

function Test-S07PortTokens {
    param([string[]]$Tokens, [int]$Port)
    foreach ($t in $Tokens) {
        if ($t -eq 'Any') { return $true }
        if ($t -match '^\d+$') { if ([int]$t -eq $Port) { return $true }; continue }
        if ($t -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }; continue }
        if ($t -eq 'RPCEPMap' -and $Port -eq 135) { return $true }
        if ($t -eq 'RPC' -and $Port -ge 1024) { return $true }      # dynamic RPC endpoints of the rule's program/service
        if ($t -eq 'IPHTTPSIn' -and $Port -eq 443) { return $true }
        if ($t -match '^(?i)mdns$' -and $Port -eq 5353) { return $true }
    }
    $false
}

function Test-S07AddrTokens {
    param([string[]]$Tokens, [Net.IPAddress]$Ip)
    if (-not $Ip) { return $false }
    foreach ($t in $Tokens) {
        if ($t -eq 'Any' -or $t -eq '*') { return $true }
        if ($t -match '^(?i)LocalSubnet([46]?)$') {
            $fam = $Matches[1]
            if ($fam -eq '4' -and $Ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            if ($fam -eq '6' -and $Ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) { continue }
            if (Test-S07OnLink -Ip $Ip) { return $true }
            continue
        }
        if ($t -match '^(?i)(Internet|Intranet|IntranetRemoteAccess|PlayToDevice|Ply2Renders|DNS|DHCP|WINS|DefaultGateway|CaptivePortal\w*)$') {
            if ($t -ieq 'Internet' -and -not (Test-S07OnLink -Ip $Ip)) { return $true }   # approximation
            continue
        }
        if (Test-S07IpSpec -Ip $Ip -Spec $t) { return $true }
    }
    $false
}

function Test-S07RuleForListener {
    <# Column-independent part of a rule match: protocol, program, package, service, local port. yes|no|unknown #>
    param($Rule, $L)
    $unknown = $false
    if ($null -eq $Rule.Protocol) { $unknown = $true }
    elseif ($Rule.Protocol -ne 'Any') {
        $want = if ($L.Proto -eq 'TCP') { @('TCP', '6') } else { @('UDP', '17') }
        if ($want -notcontains $Rule.Protocol) { return 'no' }
    }
    if ($null -eq $Rule.Program) { $unknown = $true }
    elseif ($Rule.Program -ne 'Any') {
        if ($Rule.Program -eq 'System') { if ($L.Pid -ne 4) { return 'no' } }
        elseif ($L.Path) { if (-not [string]::Equals($Rule.ProgramExpanded, $L.Path, [StringComparison]::OrdinalIgnoreCase)) { return 'no' } }
        elseif ([IO.Path]::GetFileName($Rule.ProgramExpanded) -ieq $L.Name) { $unknown = $true }
        else { return 'no' }
    }
    if ($Rule.Package -match '^S-1-15-') {
        if (-not $L.Path -or $L.Path -notmatch '\\WindowsApps\\') { return 'no' }
        $unknown = $true
    }
    if ($Rule.Service -and $Rule.Service -ne 'Any') {
        if ($Rule.Service -eq '*') { if (@($L.Services).Count -eq 0) { return 'no' } }
        elseif (@($L.Services) -notcontains $Rule.Service) { return 'no' }
    }
    if ($null -eq $Rule.LocalPorts) { $unknown = $true }
    elseif (-not (Test-S07PortTokens -Tokens $Rule.LocalPorts -Port $L.Port)) { return 'no' }
    if ($unknown) { 'unknown' } else { 'yes' }
}

function Test-S07RuleForColumn {
    <# Column-dependent part: profile, remote/local address, interface type, interface. yes|no|unknown #>
    param($Rule, $Col, [string]$Family)
    if (($Rule.ProfileMask -band $Col.ProfileBit) -eq 0) { return 'no' }
    $rep = if ($Family -eq 'v4') { $Col.RepV4Ip } else { $Col.RepV6Ip }
    $loc = if ($Family -eq 'v4') { $Col.LocalV4Ip } else { $Col.LocalV6Ip }
    $unknown = $false
    if ($null -eq $Rule.RemoteAddress) { $unknown = $true }
    elseif (-not (Test-S07AddrTokens -Tokens $Rule.RemoteAddress -Ip $rep)) { return 'no' }
    if ($null -ne $Rule.LocalAddress -and -not (Test-S07AddrTokens -Tokens $Rule.LocalAddress -Ip $loc)) { return 'no' }
    if ($Rule.InterfaceType -and $Rule.InterfaceType -ne 'Any' -and $Rule.InterfaceType -notmatch $Col.IfTypeBucket) { return 'no' }
    if ($Rule.Interfaces -and $Rule.Interfaces -notcontains 'Any' -and $Rule.Interfaces -notcontains $Col.Alias) { return 'no' }
    if ($unknown) { 'unknown' } else { 'yes' }
}

function Get-S07Reach {
    <# Effective inbound verdict for one listener on one interface/family. Block rules win over allow rules. #>
    param($L, $Col, [string]$Family, $Cands)
    $fp = $ctx.Fw.Profiles[$Col.Profile]
    if ($fp -and -not $fp.Enabled) { return [pscustomobject]@{ R = 'yes'; Via = @(); Reason = "firewall-off($($Col.Profile))" } }
    $ay = [System.Collections.Generic.List[string]]::new(); $au = [System.Collections.Generic.List[string]]::new()
    $by = [System.Collections.Generic.List[string]]::new(); $bu = [System.Collections.Generic.List[string]]::new()
    foreach ($c in $Cands) {
        $m = Test-S07RuleForColumn -Rule $c.Rule -Col $Col -Family $Family
        if ($m -eq 'no') { continue }
        if ($c.Match -eq 'unknown') { $m = 'unknown' }
        if ($c.Rule.Action -eq 'Block') { if ($m -eq 'yes') { $by.Add($c.Rule.Name) } else { $bu.Add($c.Rule.Name) } }
        else { if ($m -eq 'yes') { $ay.Add($c.Rule.Name) } else { $au.Add($c.Rule.Name) } }
    }
    if ($by.Count) { return [pscustomobject]@{ R = 'no'; Via = @($by); Reason = 'blocked-by-rule' } }
    if ($fp -and -not $fp.AllowInboundRules) { return [pscustomobject]@{ R = 'no'; Via = @(); Reason = 'block-all-incoming' } }
    if ($ay.Count) { return [pscustomobject]@{ R = $(if ($bu.Count) { 'unknown' } else { 'yes' }); Via = @($ay); Reason = 'allow-rule' } }
    if ($au.Count) { return [pscustomobject]@{ R = 'unknown'; Via = @($au); Reason = 'allow-rule-partly-unreadable' } }
    if ($fp -and $fp.DefaultInboundAction -eq 'Allow') { return [pscustomobject]@{ R = 'yes'; Via = @(); Reason = 'default-allow' } }
    [pscustomobject]@{ R = 'no'; Via = @(); Reason = 'default-block' }
}

#endregion

#region ---------- helpers: TLS probe, DoH, intel cache ----------

$script:RootStores = $null

function Get-S07RootStores {
    if (-not $script:RootStores) {
        $mk = { param($p) [System.Collections.Generic.HashSet[string]]::new([string[]]@(Get-ChildItem -Path $p -ErrorAction SilentlyContinue | ForEach-Object { $_.Thumbprint }), [StringComparer]::OrdinalIgnoreCase) }
        $script:RootStores = @{
            AuthRoot = (& $mk 'Cert:\LocalMachine\AuthRoot')
            LmRoot   = (& $mk 'Cert:\LocalMachine\Root')
            CuRoot   = (& $mk 'Cert:\CurrentUser\Root')
        }
    }
    $script:RootStores
}

function Test-S07Tls {
    <#
    TCP connect to Ip:443, TLS handshake with SNI = Name and NORMAL certificate validation. The
    callback only records the chain the platform built and returns the platform's own verdict
    (SslPolicyErrors -eq None): validation is never bypassed.
    #>
    param([string]$Ip, [string]$Name, [int]$TimeoutMs = 5000)
    $cap = @{ Errors = $null; Chain = @() }
    $cb = {
        param($s, $cert, $chain, $errs)
        $cap.Errors = [string]$errs
        $cap.Chain = @(foreach ($el in $chain.ChainElements) {
                [pscustomobject]@{ Subject = $el.Certificate.Subject; Issuer = $el.Certificate.Issuer; Thumbprint = $el.Certificate.Thumbprint; NotAfter = $el.Certificate.NotAfter.ToUniversalTime().ToString('o') }
            })
        return ($errs -eq [System.Net.Security.SslPolicyErrors]::None)
    }.GetNewClosure()
    $out = [ordered]@{ ip = $Ip; sni = $Name; connected = $false; handshake = $false; protocol = $null; policyErrors = $null; chain = @(); leafSubject = $null; leafIssuer = $null; rootSubject = $null; rootThumbprint = $null; rootStore = $null; classification = $null; error = $null }
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        $tcp.ReceiveTimeout = $TimeoutMs; $tcp.SendTimeout = $TimeoutMs
        $task = $tcp.ConnectAsync($Ip, 443)
        if (-not $task.Wait($TimeoutMs)) { throw 'TCP connect timeout' }
        $out.connected = $true
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, [System.Net.Security.RemoteCertificateValidationCallback]$cb)
        try {
            $ssl.ReadTimeout = $TimeoutMs; $ssl.WriteTimeout = $TimeoutMs
            $ssl.AuthenticateAsClient($Name)
            $out.handshake = $true
            $out.protocol = [string]$ssl.SslProtocol
        }
        catch {
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            $out.error = $ex.Message
        }
        finally { $ssl.Dispose() }
    }
    catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        if (-not $out.error) { $out.error = $ex.Message }
    }
    finally { $tcp.Dispose() }
    $out.policyErrors = $cap.Errors
    $out.chain = @($cap.Chain | ForEach-Object { $_.Subject })
    if (@($cap.Chain).Count) {
        $leaf = @($cap.Chain)[0]; $root = @($cap.Chain)[-1]
        $out.leafSubject = $leaf.Subject; $out.leafIssuer = $leaf.Issuer
        $out.rootSubject = $root.Subject; $out.rootThumbprint = $root.Thumbprint
        $st = Get-S07RootStores
        $out.rootStore = if ($st.AuthRoot.Contains($root.Thumbprint)) { 'LocalMachine\AuthRoot' } elseif ($st.LmRoot.Contains($root.Thumbprint)) { 'LocalMachine\Root' } elseif ($st.CuRoot.Contains($root.Thumbprint)) { 'CurrentUser\Root' } else { 'not-in-root-stores' }
    }
    $out
}

function Get-S07TlsClass {
    <# public | public-preinstalled | avast-intercept | avast-intercept-unverified | validation-failed | unknown-root | no-handshake #>
    param($Tls, $AvastRef)
    if ($Tls.policyErrors -and $Tls.policyErrors -ne 'None') { return 'validation-failed' }
    if (-not $Tls.handshake -or -not $Tls.rootThumbprint) { return 'no-handshake' }
    if ($Tls.rootStore -eq 'LocalMachine\AuthRoot') { return 'public' }
    if ($AvastRef -and $Tls.rootSubject -like "*$($AvastRef.match.subjectContains)*") {
        if ($ctx.AvastCancel.Count) { return 'avast-intercept-unverified' } else { return 'avast-intercept' }
    }
    if ($Tls.rootStore -in 'LocalMachine\Root', 'CurrentUser\Root' -and $Tls.rootSubject -match $S07.PublicCaVendors) { return 'public-preinstalled' }
    'unknown-root'
}

function Get-S07DohA {
    <# Reference A records via DNS-over-HTTPS (cloudflare-dns.com, fallback dns.google) through Invoke-BvsIntel. #>
    param([string]$Name)
    $q = [uri]::EscapeDataString($Name)
    $tries = @(
        @{ Uri = "https://cloudflare-dns.com/dns-query?name=$q&type=A"; Src = 'cloudflare-dns.com'; Headers = @{ Accept = 'application/dns-json' } }
        @{ Uri = "https://dns.google/resolve?name=$q&type=A"; Src = 'dns.google'; Headers = @{ Accept = 'application/json' } }
    )
    $lastErr = $null
    foreach ($t in $tries) {
        try {
            $r = Invoke-BvsIntel -Uri $t.Uri -Headers $t.Headers -SaveName "doh-$Name-A.json" -TimeoutSec 10
            $j = $r.Json
            if (-not $j) {
                $txt = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
                $j = $txt | ConvertFrom-Json -ErrorAction Stop
            }
            if ($r.Status -eq 200 -and $null -ne $j.Status) {
                return [pscustomobject]@{ Ok = ($j.Status -eq 0); Source = $t.Src; Rcode = $j.Status; Ips = @($j.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { [string]$_.data }); Error = $null }
            }
            $lastErr = "HTTP $($r.Status) from $($t.Src)"
        }
        catch { $lastErr = $_.Exception.Message }
    }
    [pscustomobject]@{ Ok = $false; Source = $null; Rcode = $null; Ips = @(); Error = $lastErr }
}

function Get-S07IntelText {
    <# Fetch an intel list through Invoke-BvsIntel, reusing a successful copy under intel\<host>\ younger than MaxAgeHours. #>
    param([string]$Uri, [string]$SaveName, [double]$MaxAgeHours = 12)
    $hostDir = Join-Path $run.Root ('intel\' + (([uri]$Uri).Host -replace '[^A-Za-z0-9.-]', '_'))
    if (Test-Path -LiteralPath $hostDir) {
        $cands = Get-ChildItem -LiteralPath $hostDir -Filter "*-$SaveName" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -gt [datetime]::UtcNow.AddHours(-$MaxAgeHours) } | Sort-Object LastWriteTimeUtc -Descending
        foreach ($c in $cands) {
            $metaPath = "$($c.FullName).meta.json"
            if (-not (Test-Path -LiteralPath $metaPath)) { continue }
            $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
            if ([int]$meta.status -eq 200) {
                return [pscustomobject]@{ Status = 200; Text = [IO.File]::ReadAllText($c.FullName); Source = 'cache'; FetchedAt = $meta.fetchedAtUtc }
            }
        }
    }
    $r = Invoke-BvsIntel -Uri $Uri -SaveName $SaveName -TimeoutSec 30
    $text = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { [string]$r.Content }
    [pscustomobject]@{ Status = $r.Status; Text = $text; Source = 'fetched'; FetchedAt = [datetime]::UtcNow.ToString('o') }
}

#endregion

#region ---------- background connection sampler ----------

# Self-contained: runs in its own runspace (thread job). Records raw snapshots only; analysis happens later.
$samplerScript = {
    param([int]$Count, [int]$Interval, [int]$SelfPid, [string]$RootRx)
    for ($i = 0; $i -lt $Count; $i++) {
        $t0 = [datetime]::UtcNow
        $pids = [System.Collections.Generic.HashSet[int]]::new()
        $tcp = [System.Collections.Generic.List[object]]::new()
        foreach ($c in @(Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue)) {
            $p = [int]$c.OwningProcess
            if ($p -eq $SelfPid) { continue }
            [void]$pids.Add($p)
            $ct = $null
            try { $ct = [datetime]$c.CreationTime } catch { $ct = $null }
            $tcp.Add([pscustomobject]@{ L = [string]$c.LocalAddress; LP = [int]$c.LocalPort; R = [string]$c.RemoteAddress; RP = [int]$c.RemotePort; S = [string]$c.State; P = $p; C = $ct })
        }
        $udp = [System.Collections.Generic.List[object]]::new()
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            $p = [int]$u.OwningProcess
            if ($p -eq $SelfPid) { continue }
            [void]$pids.Add($p)
            $udp.Add([pscustomobject]@{ L = [string]$u.LocalAddress; LP = [int]$u.LocalPort; P = $p })
        }
        $procs = @{}
        foreach ($w in @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath, CreationDate, ParentProcessId, CommandLine -ErrorAction SilentlyContinue)) {
            $p = [int]$w.ProcessId
            if (-not $pids.Contains($p)) { continue }
            # Only a boolean leaves this runspace: "is this one of the scanner's own collectors?"
            $procs[$p] = [pscustomobject]@{ Pid = $p; Name = [string]$w.Name; Path = [string]$w.ExecutablePath; ParentPid = [int]$w.ParentProcessId; Started = $w.CreationDate; Scanner = ([string]$w.CommandLine -match $RootRx) }
        }
        [pscustomobject]@{ Index = $i; AtUtc = $t0; Tcp = $tcp.ToArray(); Udp = $udp.ToArray(); Procs = $procs }
        if ($i -lt $Count - 1) {
            $wait = $Interval * 1000 - [int]([datetime]::UtcNow - $t0).TotalMilliseconds
            if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
        }
    }
}

$rootRx = [regex]::Escape($run.Root)
$samplerJob = $null
$samplerStarted = [datetime]::UtcNow
if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
    $samplerJob = Start-ThreadJob -Name 'S07-sampler' -ScriptBlock $samplerScript -ArgumentList $Samples, $IntervalSec, $PID, $rootRx
}
Write-BvsLog -Run $run -Message "sampler started: $Samples x $IntervalSec s (threadjob=$([bool]$samplerJob))"
"S07: connection sampling started ($Samples x $IntervalSec s, background); running other checks..."

#endregion

#region ---------- 0. context: interfaces, profiles, gateway, processes ----------

[void](Invoke-BvsCheck -Run $run -Id 'net.context' -Description 'Interfaces, IP addresses, network profiles, default gateways and process table' -Script {
        Update-S07ProcTable
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
        $ipsAll = @(Get-NetIPAddress -ErrorAction SilentlyContinue)
        $profs = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue)
        foreach ($ip in $ipsAll) { $ctx.IpToIf[(([string]$ip.IPAddress) -replace '%.*$', '')] = [int]$ip.InterfaceIndex }
        $onlink = [System.Collections.Generic.List[object]]::new()
        $ifs = foreach ($a in @($adapters | Where-Object { [string]$_.Status -eq 'Up' })) {
            $idx = [int]$a.ifIndex
            $v4 = @($ipsAll | Where-Object { $_.InterfaceIndex -eq $idx -and [string]$_.AddressFamily -eq 'IPv4' -and [string]$_.IPAddress -notlike '169.254.*' })
            $v6 = @($ipsAll | Where-Object { $_.InterfaceIndex -eq $idx -and [string]$_.AddressFamily -eq 'IPv6' })
            foreach ($x in @($v4) + @($v6)) {
                $net = ConvertTo-S07Ip ([string]$x.IPAddress)
                $max = if ([string]$x.AddressFamily -eq 'IPv4') { 32 } else { 128 }
                if ($net -and [int]$x.PrefixLength -lt $max) { $onlink.Add([pscustomobject]@{ Net = $net; Bits = [int]$x.PrefixLength }) }
            }
            $prof = $profs | Where-Object { $_.InterfaceIndex -eq $idx } | Select-Object -First 1
            $gw4 = ($routes | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1)
            $gw6 = ($routes | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '::/0' -and $_.NextHop -ne '::' } | Sort-Object RouteMetric | Select-Object -First 1)
            $desc = [string]$a.InterfaceDescription
            $isTs = ($desc -match 'Tailscale') -or (([int]$a.InterfaceType -eq 53) -and @($v4 | Where-Object { (Get-S07IpClass ([string]$_.IPAddress)) -in 'tailscale', 'cgnat' }).Count -gt 0)
            $kind = if ($isTs) { 'tailnet' } elseif ($gw4 -or $gw6) { 'lan' } elseif ($a.Virtual -or $desc -match 'VirtualBox|Hyper-V|VMware|vEthernet|WSL|Docker') { 'virtual' } else { 'other' }
            if ($isTs) { $script:HasTailscale = $true }
            $cat = if ($prof) { switch ([string]$prof.NetworkCategory) { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } } } else { 'Public' }
            [pscustomobject]@{
                Alias = [string]$a.Name; Index = $idx; Description = $desc; Guid = [string]$a.InterfaceGuid; IfType = [int]$a.InterfaceType
                Virtual = [bool]$a.Virtual; Kind = $kind; Profile = $cat; ProfileAssumed = (-not $prof); NetworkName = if ($prof) { [string]$prof.Name } else { $null }
                IPv4 = @($v4 | ForEach-Object { '{0}/{1}' -f $_.IPAddress, $_.PrefixLength }); IPv6 = @($v6 | ForEach-Object { '{0}/{1}' -f ($_.IPAddress -replace '%.*$', ''), $_.PrefixLength })
                V4Objs = $v4; V6Objs = $v6
                Gateway4 = if ($gw4) { [string]$gw4.NextHop } else { $null }; Gateway6 = if ($gw6) { [string]$gw6.NextHop } else { $null }
                Gateway4Metric = if ($gw4) { [int]$gw4.RouteMetric } else { $null }
            }
        }
        $ctx.Interfaces = @($ifs)
        $ctx.OnLink = @($onlink)
        $primary = $ctx.Interfaces | Where-Object { $_.Gateway4 } | Sort-Object Gateway4Metric | Select-Object -First 1
        if ($primary) { $ctx.Gateway = $primary.Gateway4; $ctx.GatewayIf = $primary }
        $ctx.DiscordInstalled = [bool](Get-Process -Name 'Discord' -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Discord'))
        $avastSvc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { [string]$_.PathName -match '\\Avast Software\\' })
        $ctx.AvastInstalled = $avastSvc.Count -gt 0
        Add-BvsInventory -Run $run -Name 'networks' -Data ([ordered]@{
                interfaces = @($ctx.Interfaces | ForEach-Object { [ordered]@{ alias = $_.Alias; index = $_.Index; description = $_.Description; kind = $_.Kind; profile = $_.Profile; profileAssumed = $_.ProfileAssumed; networkName = $_.NetworkName; ifType = $_.IfType; virtual = $_.Virtual; ipv4 = $_.IPv4; ipv6 = $_.IPv6; gateway4 = $_.Gateway4; gateway6 = $_.Gateway6 } })
                primaryGateway = $ctx.Gateway
                primaryInterface = if ($primary) { $primary.Alias } else { $null }
                tailscalePresent = $script:HasTailscale
            })
        $ctx.Interfaces
    })

#endregion

#region ---------- 1. intel lists (context only) ----------

[void](Invoke-BvsCheck -Run $run -Id 'intel.tor_exits' -Description 'Tor bulk exit list (check.torproject.org) for connection context' -Script {
        if ($NoIntel) { Set-BvsCheckStatus -Id 'intel.tor_exits' -Status skipped -Reason '-NoIntel'; return @() }
        $r = Get-S07IntelText -Uri 'https://check.torproject.org/torbulkexitlist' -SaveName 'torbulkexitlist.txt'
        if ($r.Status -ne 200) { Set-BvsCheckStatus -Id 'intel.tor_exits' -Status skipped -Reason "HTTP $($r.Status)"; return @() }
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($line in ($r.Text -split "`r?`n")) { $t = $line.Trim(); if ($t -and -not $t.StartsWith('#') -and (ConvertTo-S07Ip $t)) { [void]$set.Add($t) } }
        $ctx.Tor = [pscustomobject]@{ Set = $set; Source = $r.Source; FetchedAt = $r.FetchedAt }
        @($set)
    })

[void](Invoke-BvsCheck -Run $run -Id 'intel.feodo' -Description 'abuse.ch Feodo Tracker botnet C2 IP list (public download, no key)' -Script {
        if ($NoIntel) { Set-BvsCheckStatus -Id 'intel.feodo' -Status skipped -Reason '-NoIntel'; return @() }
        $r = Get-S07IntelText -Uri 'https://feodotracker.abuse.ch/downloads/ipblocklist.json' -SaveName 'feodo-ipblocklist.json'
        if ($r.Status -in 401, 403) { Set-BvsCheckStatus -Id 'intel.feodo' -Status skipped -Reason "HTTP $($r.Status): list requires a key now - skipped per brief"; return @() }
        if ($r.Status -ne 200) { Set-BvsCheckStatus -Id 'intel.feodo' -Status skipped -Reason "HTTP $($r.Status)"; return @() }
        $map = @{}
        foreach ($e in @($r.Text | ConvertFrom-Json -ErrorAction Stop)) {
            if ($e.ip_address) { $map[[string]$e.ip_address] = [pscustomobject]@{ Port = $e.port; Malware = $e.malware; Status = $e.status; LastOnline = $e.last_online } }
        }
        $ctx.Feodo = [pscustomobject]@{ Map = $map; Source = $r.Source; FetchedAt = $r.FetchedAt }
        @($map.Keys)
    })

#endregion

#region ---------- 2. Tailscale ----------

$tsExe = $null
foreach ($cand in @(
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe' }),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe' }),
        $((Get-Command tailscale.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source))) {
    if ($cand -and [IO.File]::Exists($cand)) { $tsExe = $cand; break }
}
$tsExpected = Get-S07Expected -Category 'network' -Where { param($e) $e.match.adapter -eq 'Tailscale' -or $e.id -eq 'tailscale' }

[void](Invoke-BvsCheck -Run $run -Id 'ts.status' -Description 'tailscale status --json: peers, owners (shared-in), exit node, tags, last seen' -Script {
        if (-not $tsExe) { Set-BvsCheckStatus -Id 'ts.status' -Status not_applicable -Reason 'Tailscale CLI not installed'; return @() }
        $raw = (& $tsExe status --json 2>$null) -join "`n"
        if (-not $raw) { Set-BvsCheckStatus -Id 'ts.status' -Status error -Reason 'no output from tailscale status --json'; return @() }
        $j = $raw | ConvertFrom-Json -ErrorAction Stop
        $raw = $null
        $selfUser = [string]$j.Self.UserID
        $users = @{}
        foreach ($u in @($j.User.PSObject.Properties)) { $users[[string]$u.Name] = $u.Value }
        $knownNames = @(foreach ($e in @(Get-BvsExpected -Category 'hosts')) { foreach ($h in @($e.match.hostnames)) { if ($h) { ([string]$h).ToLowerInvariant() } } })
        $peerExp = Get-S07Expected -Category 'hosts' -Where { param($e) @($e.match.hostnames).Count -gt 0 }
        $peers = foreach ($p in @($j.Peer.PSObject.Properties | ForEach-Object { $_.Value })) {
            $dns = ([string]$p.DNSName).TrimEnd('.')
            $short = (($dns -split '\.')[0]).ToLowerInvariant()
            $tags = @($p.Tags | Where-Object { $_ })
            $owner = [string]$p.UserID
            $otherUser = ($owner -ne $selfUser) -and ($tags.Count -eq 0)
            [pscustomobject][ordered]@{
                name = $short; hostName = [string]$p.HostName; dnsName = $dns; os = [string]$p.OS; online = [bool]$p.Online
                lastSeen = ConvertTo-S07Iso $p.LastSeen; created = ConvertTo-S07Iso $p.Created
                tailscaleIPs = @($p.TailscaleIPs); userId = $owner; userLogin = if ($users[$owner]) { [string]$users[$owner].LoginName } else { $null }
                sameUserAsSelf = ($owner -eq $selfUser); sharedIn = ($otherUser -or [bool]$p.ShareeNode); tags = $tags
                exitNode = [bool]$p.ExitNode; exitNodeOption = [bool]$p.ExitNodeOption; active = [bool]$p.Active; relay = [string]$p.Relay
                keyExpiry = ConvertTo-S07Iso $p.KeyExpiry; knownName = ($knownNames -contains $short -or $knownNames -contains ([string]$p.HostName).ToLowerInvariant())
            }
        }
        $peers = @($peers)
        $self = $j.Self
        $ctx.Ts = [pscustomobject]@{
            Backend = [string]$j.BackendState; Version = [string]$j.Version; Tailnet = [string]$j.CurrentTailnet.Name
            MagicDnsSuffix = [string]$j.MagicDNSSuffix; MagicDnsEnabled = [bool]$j.CurrentTailnet.MagicDNSEnabled
            Self = [ordered]@{ name = ((([string]$self.DNSName).TrimEnd('.') -split '\.')[0]).ToLowerInvariant(); hostName = [string]$self.HostName; os = [string]$self.OS; tailscaleIPs = @($self.TailscaleIPs); userId = $selfUser; userLogin = if ($users[$selfUser]) { [string]$users[$selfUser].LoginName } else { $null }; keyExpiry = ConvertTo-S07Iso $self.KeyExpiry; exitNodeOption = [bool]$self.ExitNodeOption }
            Health = @($j.Health | Where-Object { $_ })
            Peers = $peers; Prefs = $null; Serve = $null; Funnel = $null
        }
        $shared = @($peers | Where-Object { $_.sharedIn })
        $unknown = @($peers | Where-Object { -not $_.knownName -and -not $_.sharedIn })
        $ctx.TsOtherUserPeers = $shared.Count
        if ($shared.Count) { $ctx.TsCancel += 'shared-in or other-user peers present' }
        if ($unknown.Count) { $ctx.TsCancel += 'unknown peers present' }
        if ($ctx.Ts.Backend -ne 'Running') { Set-BvsCheckStatus -Id 'ts.status' -Status partial -Reason "BackendState=$($ctx.Ts.Backend)" }

        foreach ($p in $shared) {
            New-BvsFinding -Run $run -Check 'ts.status' -Title "Tailscale peer '$($p.name)' is owned by another user (shared-in node)" -Severity medium -Class suspicious -Confidence medium `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'tailscale-peer'; name = $p.name; os = $p.os; userLogin = $p.userLogin; online = $p.online; lastSeen = $p.lastSeen; tailscaleIPs = $p.tailscaleIPs }) `
                -Entities @{ network = @(@{ peer = $p.name; ips = $p.tailscaleIPs }) } `
                -FpNotes 'Node sharing is a normal Tailscale feature (a friend or colleague sharing a device). It only matters if you did not accept this share.' `
                -Recommendation 'Open https://login.tailscale.com/admin/machines and confirm the share. Remove it if unknown. Review the tailnet ACL so shared nodes cannot reach this PC.' -Mitre @('T1133')
        }
        foreach ($p in $unknown) {
            New-BvsFinding -Run $run -Check 'ts.status' -Title "Tailscale peer '$($p.name)' is not on the known-peer list" -Severity low -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'tailscale-peer'; name = $p.name; os = $p.os; online = $p.online; lastSeen = $p.lastSeen; created = $p.created }) `
                -FpNotes 'A device you added recently will show up here until src\config\local\expected.json lists it.' `
                -Recommendation 'Confirm the device in the Tailscale admin console; remove it (and expire its key) if you do not recognise it.'
        }
        $peerList = ($peers | ForEach-Object { '{0} ({1}, {2}, last seen {3})' -f $_.name, $_.os, $(if ($_.online) { 'online' } else { 'offline' }), $(if ($_.lastSeen) { $_.lastSeen } else { 'now' }) }) -join '; '
        $ref = New-S07ExpectedRef -Item $peerExp
        New-BvsFinding -Run $run -Check 'ts.status' -Title "Tailscale tailnet '$($ctx.Ts.Tailnet)' has $($peers.Count) peer(s) - please confirm each device" -Severity info -Class info -Confidence high `
            -Reasons @('expected_match') -Evidence @(@{ type = 'tailscale-peers'; peers = @($peers | ForEach-Object { [ordered]@{ name = $_.name; os = $_.os; online = $_.online; lastSeen = $_.lastSeen; sameUserAsSelf = $_.sameUserAsSelf; knownName = $_.knownName } }) }) `
            -Expected $ref -FpNotes 'Context finding for user confirmation (expected.json marks the peer list confirmWithUser).' `
            -Recommendation 'Confirm every peer is your own device. Remove unknown devices in the Tailscale admin console.'
        Add-S07Question "Tailscale peers: $peerList. Are all of these your own devices? Remove any you do not recognise in the Tailscale admin console."
        $peers
    })

[void](Invoke-BvsCheck -Run $run -Id 'ts.prefs' -Description 'tailscale debug prefs (Persist/Config node keys dropped): ControlURL, RunSSH, routes, exit node, ShieldsUp' -Script {
        if (-not $tsExe) { Set-BvsCheckStatus -Id 'ts.prefs' -Status not_applicable -Reason 'Tailscale CLI not installed'; return @() }
        $raw = (& $tsExe debug prefs 2>$null) -join "`n"
        if (-not $raw) { Set-BvsCheckStatus -Id 'ts.prefs' -Status error -Reason 'no output from tailscale debug prefs'; return @() }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $raw = $null
        # ALLOWLIST: only known non-secret keys survive. Persist and Config (node private keys) never leave this block.
        $prefs = [ordered]@{}
        foreach ($k in $S07.TsPrefsKeep) { if ($obj.PSObject.Properties[$k]) { $prefs[$k] = $obj.$k } }
        $driveShares = @($obj.DriveShares | Where-Object { $_ } | ForEach-Object { [string]$_.Name })
        $prefs['DriveShareNames'] = $driveShares
        $obj = $null
        $probe = ConvertTo-Json -InputObject $prefs -Depth 6 -Compress
        if ($probe -match '(?i)privkey:|nlpriv:|PrivateNodeKey|NetworkLockKey|OldPrivate') {
            Set-BvsCheckStatus -Id 'ts.prefs' -Status error -Reason 'secret material detected after filtering - prefs discarded (fail-closed)'
            return @()
        }
        $ctx.Ts.Prefs = $prefs
        $routes = @($prefs['AdvertiseRoutes'] | Where-Object { $_ })
        $control = [string]$prefs['ControlURL']
        if ($control -and $control.TrimEnd('/') -ne $S07.DefaultControlUrl) {
            $ctx.TsCancel += 'ControlURL not the Tailscale default'
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title "Tailscale uses a non-default control server ($control)" -Severity high -Class suspicious -Confidence medium `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'ControlURL'; value = $control; default = $S07.DefaultControlUrl }) `
                -FpNotes 'A self-hosted Headscale server or a company control plane sets this deliberately.' `
                -Recommendation 'If you did not set up Headscale or a company tailnet, log out of Tailscale and log in again with the default control server.' -Mitre @('T1133')
        }
        if ([bool]$prefs['RunSSH']) {
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title 'Tailscale SSH server is enabled (RunSSH)' -Severity medium -Class hardening -Confidence high -Reasons @('exposed_service') `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'RunSSH'; value = $true }) -FpNotes 'Intentional if you use Tailscale SSH to reach this PC.' `
                -Recommendation 'If not needed: Tailscale menu > Preferences, or run "tailscale set --ssh=false" yourself.' -Mitre @('T1021.004')
        }
        if ($routes.Count) {
            $exitAdv = @($routes | Where-Object { $_ -in '0.0.0.0/0', '::/0' }).Count -gt 0
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title $(if ($exitAdv) { 'This PC advertises itself as a Tailscale exit node' } else { "This PC advertises subnet routes to the tailnet: $($routes -join ', ')" }) -Severity medium -Class hardening -Confidence high -Reasons @('exposed_service') `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'AdvertiseRoutes'; value = $routes }) -FpNotes 'Intentional for a home subnet router or exit node.' `
                -Recommendation 'If not intended, stop advertising routes ("tailscale set --advertise-routes=" / --advertise-exit-node=false) and disable the routes in the admin console.'
        }
        if ([bool]$prefs['RunWebClient']) {
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title 'Tailscale web client is enabled on the tailnet (port 5252)' -Severity medium -Class hardening -Confidence high -Reasons @('exposed_service') `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'RunWebClient'; value = $true }) -FpNotes 'Intentional if you manage this node from the browser.' `
                -Recommendation 'Disable it if unused ("tailscale set --webclient=false").'
        }
        if ($driveShares.Count) {
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title "Taildrive shares folders with the tailnet: $($driveShares -join ', ')" -Severity medium -Class hardening -Confidence high -Reasons @('exposed_service') `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'DriveShares'; value = $driveShares }) -FpNotes 'Intentional if you share these folders with your own devices.' `
                -Recommendation 'Remove shares you do not need and restrict Taildrive in the tailnet ACL.'
        }
        if ($prefs['ExitNodeID']) {
            $en = @($ctx.Ts.Peers | Where-Object { $_.exitNode }) | Select-Object -First 1
            New-BvsFinding -Run $run -Check 'ts.prefs' -Title "All internet traffic goes through Tailscale exit node $(if ($en) { "'$($en.name)'" } else { $prefs['ExitNodeID'] })" -Severity info -Class info -Confidence high `
                -Evidence @(@{ type = 'tailscale-pref'; name = 'ExitNodeID'; value = [string]$prefs['ExitNodeID']; peer = if ($en) { $en.name } else { $null } }) -FpNotes 'Intentional VPN use.' `
                -Recommendation 'Make sure the exit node is your own device.'
        }
        @($prefs.Keys)
    })

[void](Invoke-BvsCheck -Run $run -Id 'ts.serve_funnel' -Description 'tailscale serve status / funnel status (Funnel = internet exposure)' -Script {
        if (-not $tsExe) { Set-BvsCheckStatus -Id 'ts.serve_funnel' -Status not_applicable -Reason 'Tailscale CLI not installed'; return @() }
        $serveRaw = (& $tsExe serve status --json 2>$null) -join "`n"
        $funnelRaw = (& $tsExe funnel status --json 2>$null) -join "`n"
        $serve = $null; $funnel = $null
        try { if ($serveRaw) { $serve = $serveRaw | ConvertFrom-Json -ErrorAction Stop } } catch { $serve = $null }
        try { if ($funnelRaw) { $funnel = $funnelRaw | ConvertFrom-Json -ErrorAction Stop } } catch { $funnel = $null }
        if ($null -eq $serve -and $null -eq $funnel) {
            # Older CLIs without --json: plain text
            $serveRaw = (& $tsExe serve status 2>$null) -join "`n"
            $funnelRaw = (& $tsExe funnel status 2>$null) -join "`n"
        }
        $serveOn = ($serve -and @($serve.PSObject.Properties).Count -gt 0) -or ($serveRaw -and $serveRaw -notmatch '(?i)no serve config|^\s*\{\s*\}\s*$')
        $funnelOn = ($funnel -and ((ConvertTo-Json -InputObject $funnel -Depth 8 -Compress) -match '"AllowFunnel":\{[^}]*true')) -or ($funnelRaw -match '(?i)funnel on|\(Funnel on\)')
        if (-not $funnelOn -and $serve) { $funnelOn = (ConvertTo-Json -InputObject $serve -Depth 8 -Compress) -match '"AllowFunnel":\{[^}]*true' }
        $ctx.Ts.Serve = [bool]$serveOn
        $ctx.Ts.Funnel = [bool]$funnelOn
        if ($funnelOn) {
            $ctx.TsCancel += 'Funnel enabled'
            New-BvsFinding -Run $run -Check 'ts.serve_funnel' -Title 'Tailscale Funnel is ON: a local service is published to the public internet' -Severity high -Class hardening -Confidence high -Reasons @('exposed_service', 'public_network') `
                -Evidence @(@{ type = 'command'; command = 'tailscale funnel status --json'; summary = 'AllowFunnel true' }) -FpNotes 'Intentional if you are deliberately sharing a site or webhook endpoint.' `
                -Recommendation 'Run "tailscale funnel status" to see what is published and turn it off ("tailscale funnel reset") if it is not meant to be public.' -Mitre @('T1133')
        }
        elseif ($serveOn) {
            New-BvsFinding -Run $run -Check 'ts.serve_funnel' -Title 'Tailscale Serve publishes a local service to the tailnet' -Severity medium -Class hardening -Confidence high -Reasons @('exposed_service') `
                -Evidence @(@{ type = 'command'; command = 'tailscale serve status'; summary = 'serve config present' }) -FpNotes 'Intentional for sharing a dev server with your own devices.' `
                -Recommendation 'Run "tailscale serve status" and remove entries you do not need ("tailscale serve reset").'
        }
        Add-BvsInventory -Run $run -Name 'tailscale' -Data ([ordered]@{
                cli = $tsExe; backend = $ctx.Ts.Backend; version = $ctx.Ts.Version; tailnet = $ctx.Ts.Tailnet; magicDnsSuffix = $ctx.Ts.MagicDnsSuffix
                magicDnsEnabled = $ctx.Ts.MagicDnsEnabled; self = $ctx.Ts.Self; health = $ctx.Ts.Health; prefs = $ctx.Ts.Prefs
                serve = $ctx.Ts.Serve; funnel = $ctx.Ts.Funnel; peers = $ctx.Ts.Peers
                expected = (New-S07ExpectedRef -Item $tsExpected -Cancel $ctx.TsCancel)
                note = 'Tailnet reachability below also depends on the tailnet ACL, which is not visible locally.'
            })
        @([int]$serveOn, [int]$funnelOn)
    })

#endregion

#region ---------- 3. firewall model and profiles ----------

[void](Invoke-BvsCheck -Run $run -Id 'fw.profiles' -Description 'Windows Firewall profiles (effective): Enabled, DefaultInboundAction, NotifyOnListen; Security Center firewall products' -Script {
        $ctx.Fw = Get-S07FirewallModel
        $wsc = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction SilentlyContinue | ForEach-Object {
                $st = [int]$_.productState
                $exe = [string]$_.pathToSignedProductExe -replace '^\\\\\?\\', ''
                [ordered]@{ name = [string]$_.displayName; productState = ('0x{0:X}' -f $st); enabled = ((($st -shr 12) -band 0xF) -eq 1); exe = $exe; exeExists = [bool]($exe -and (Test-Path -LiteralPath $exe)) }
            })
        $ctx.ThirdPartyFw = @($wsc | Where-Object { $_.enabled -and $_.exeExists })
        foreach ($p in $ctx.Fw.Profiles.Values) {
            if (-not $p.Enabled) {
                New-BvsFinding -Run $run -Check 'fw.profiles' -Title "Windows Firewall is OFF for the $($p.Name) profile" -Severity $(if ($p.Name -eq 'Public') { 'high' } else { 'medium' }) -Class hardening -Confidence high `
                    -Reasons @('exposed_service') -Evidence @(@{ type = 'firewall-profile'; profile = $p.Name; enabled = $false }) `
                    -FpNotes $(if ($ctx.ThirdPartyFw.Count) { "A third-party firewall is registered: $(($ctx.ThirdPartyFw | ForEach-Object { $_.name }) -join ', ')." } else { 'None: no other firewall is registered in Security Center.' }) `
                    -Recommendation 'Turn Windows Defender Firewall back on for this profile (Windows Security > Firewall & network protection).' -Mitre @('T1562.004')
            }
            elseif ($p.DefaultInboundAction -eq 'Allow') {
                New-BvsFinding -Run $run -Check 'fw.profiles' -Title "Windows Firewall allows all unsolicited inbound traffic on the $($p.Name) profile" -Severity high -Class hardening -Confidence high `
                    -Reasons @('exposed_service') -Evidence @(@{ type = 'firewall-profile'; profile = $p.Name; defaultInboundAction = 'Allow' }) `
                    -FpNotes 'Never a sane default on a laptop.' -Recommendation 'Set the default inbound action back to Block (wf.msc > Windows Defender Firewall Properties).' -Mitre @('T1562.004')
            }
        }
        if ($ctx.Fw.Errors.Count) { Set-BvsCheckStatus -Id 'fw.profiles' -Status partial -Reason ("not elevated: " + ($ctx.Fw.Errors -join '; ')) }
        Add-BvsInventory -Run $run -Name 'firewall' -Data ([ordered]@{
                profiles = @($ctx.Fw.Profiles.Values)
                securityCenterFirewalls = $wsc
                coverage = $ctx.Fw.Coverage
                readErrors = $ctx.Fw.Errors
                rulesOfInterest = @()
            })
        @($ctx.Fw.Profiles.Values)
    })

#endregion

#region ---------- 4. listeners and exposure matrix ----------

[void](Invoke-BvsCheck -Run $run -Id 'net.listeners' -Description 'All TCP listeners and UDP endpoints mapped to process, service, path and signer' -Script {
        $raw = [System.Collections.Generic.List[object]]::new()
        foreach ($t in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) { $raw.Add([pscustomobject]@{ Proto = 'TCP'; Address = [string]$t.LocalAddress; Port = [int]$t.LocalPort; Pid = [int]$t.OwningProcess }) }
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) { $raw.Add([pscustomobject]@{ Proto = 'UDP'; Address = [string]$u.LocalAddress; Port = [int]$u.LocalPort; Pid = [int]$u.OwningProcess }) }
        $any4 = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($r in $raw) { if ($r.Address -eq '0.0.0.0') { [void]$any4.Add("$($r.Proto)|$($r.Port)|$($r.Pid)") } }
        $ls = foreach ($r in $raw) {
            if ($r.Pid -eq $PID) { continue }
            $cls = Get-S07IpClass $r.Address
            $scope = switch ($r.Address) { '0.0.0.0' { 'any4' } '::' { 'any6' } default { 'specific' } }
            $ip = ConvertTo-S07Ip $r.Address
            $fam = if ($ip -and $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { 'v6' } else { 'v4' }
            $p = Get-S07Proc -ProcId $r.Pid
            $name = if ($p) { [string]$p.Name } elseif ($r.Pid -eq 4) { 'System' } else { "pid-$($r.Pid)" }
            $path = if ($p) { [string]$p.Path } else { $null }
            $svcs = if ($p) { @($p.Services) } else { @() }
            $trust = Get-S07Trust -Path $path -Name $name -ProcId $r.Pid
            [pscustomobject]@{
                Proto = $r.Proto; Address = $r.Address; Port = $r.Port; Pid = $r.Pid; Name = $name; Path = $path
                PathSource = if ($p) { $p.PathSource } else { 'unavailable' }; Services = $svcs; Trust = $trust
                Loopback = ($cls -eq 'loopback'); Scope = $scope; Family = $fam
                IfIndex = if ($scope -eq 'specific' -and $ip) { $ctx.IpToIf[$ip.ToString()] } else { $null }
                DualMode = ($scope -eq 'any6' -and -not $any4.Contains("$($r.Proto)|$($r.Port)|$($r.Pid)"))
                Expected = $null; Category = $null; Reach = [ordered]@{}; Via = [ordered]@{}; Why = [ordered]@{}; ReachLan = 'no'; ReachTailnet = 'no'
            }
        }
        $ctx.Listeners = @($ls)
        # Listener categories
        $tsCancel = @($ctx.TsCancel)
        foreach ($l in $ctx.Listeners) {
            $exp = Get-S07Expected -Category 'listener' -Where {
                param($e)
                $m = $e.match
                $ok = $true
                if ($m.process) { $pn = ([string]$m.process) -replace '\.exe$', ''; if ((($l.Name) -replace '\.exe$', '') -notlike "$pn*") { $ok = $false } }
                elseif ($m.service) { if (@($l.Services) -notcontains $m.service) { $ok = $false } }
                if ($ok -and $m.port -and [int]$m.port -ne $l.Port) { $ok = $false }
                $ok
            }
            $cancel = @()
            if ($exp) {
                if ($exp.id -eq 'asus-glidex' -and "$($l.Trust.Signer)" -notmatch 'ASUSTeK') { $cancel += 'binary not signed by ASUSTeK' }
                if ($exp.match.address -and -not $l.Loopback -and $l.Address -ne $exp.match.address) { $cancel += 'bound to 0.0.0.0 or a LAN/Tailscale address' }
            }
            elseif (($l.Name -ieq 'tailscaled.exe' -or @($l.Services) -contains 'Tailscale') -and $tsExpected) { $exp = $tsExpected; $cancel = $tsCancel }
            $l.Expected = New-S07ExpectedRef -Item $exp -Cancel $cancel
            $isWin = $l.Trust.IsOs
            $l.Category = if ($isWin) { 'windows' } elseif ($l.Expected -and -not $l.Expected.cancelled) { 'expected' } elseif ($l.Proto -eq 'UDP' -and $S07.DiscoveryUdpPorts -contains $l.Port) { 'discovery' } else { 'third-party' }
        }
        # Suspicious ports on any listener (loopback included)
        foreach ($g in @($ctx.Listeners | Where-Object { $S07.SuspiciousPorts.ContainsKey($_.Port) } | Group-Object Pid, Port)) {
            $l = $g.Group[0]
            $onlyLoop = @($g.Group | Where-Object { -not $_.Loopback }).Count -eq 0
            $sev = if ($onlyLoop) { 'low' } elseif (Test-S07Untrusted $l.Trust) { 'high' } else { 'medium' }
            New-BvsFinding -Run $run -Check 'net.listeners' -Title "$($l.Name) listens on port $($l.Port) ($($S07.SuspiciousPorts[$l.Port]))$(if ($onlyLoop) { ' on loopback only' })" -Severity $sev -Class suspicious -Confidence low `
                -Reasons @(@('exposed_service') + $(if ($l.Trust.Label -eq 'unsigned') { 'unsigned' }) + $(if ($l.Trust.UserWritable) { 'user_writable' }) | Where-Object { $_ }) `
                -Evidence @($g.Group | ForEach-Object { @{ type = 'listener'; proto = $_.Proto; address = $_.Address; port = $_.Port; pid = $_.Pid } }) `
                -Entities @{ processes = @(New-S07ProcEntity -ProcId $l.Pid -Name $l.Name -Path $l.Path -Trust $l.Trust -Services $l.Services) } `
                -FpNotes 'These ports are also used by legitimate tools: Tor Browser (9050/9150), Android adb (5555), game servers and dev tools (7777, 9001).' `
                -Recommendation 'Identify the program; if you do not use it, uninstall it or stop it.' -Mitre @('T1571')
        }
        @($ctx.Listeners)
    })

[void](Invoke-BvsCheck -Run $run -Id 'net.exposure' -Description 'Exposure matrix: every non-loopback listener x active interface (LAN, tailnet, virtual) through Windows Firewall rules' -Script {
        if (-not $ctx.Fw) { Set-BvsCheckStatus -Id 'net.exposure' -Status error -Reason 'firewall model unavailable'; return @() }
        # Columns = active interfaces with addresses
        $peerV4 = $null; $peerV6 = $null
        if ($ctx.Ts -and $ctx.Ts.Peers) {
            $peerV4 = @($ctx.Ts.Peers.tailscaleIPs | Where-Object { $_ -match '^\d+\.' }) | Select-Object -First 1
            $peerV6 = @($ctx.Ts.Peers.tailscaleIPs | Where-Object { $_ -match ':' }) | Select-Object -First 1
        }
        $cols = foreach ($i in $ctx.Interfaces) {
            $v4 = @($i.V4Objs) | Select-Object -First 1
            $v6 = @($i.V6Objs | Sort-Object { if ([string]$_.IPAddress -like 'fe80*') { 1 } else { 0 } }) | Select-Object -First 1
            if (-not $v4 -and -not $v6) { continue }
            $avoid = @($(if ($v4) { [string]$v4.IPAddress }), $i.Gateway4) | Where-Object { $_ }
            $rep4 = if ($i.Kind -eq 'tailnet') { if ($peerV4) { $peerV4 } else { '100.64.0.2' } } elseif ($v4) { Get-S07HostInSubnet -Ip ([string]$v4.IPAddress) -Prefix ([int]$v4.PrefixLength) -Avoid $avoid } else { $null }
            $rep6 = if ($i.Kind -eq 'tailnet') { if ($peerV6) { $peerV6 } else { 'fd7a:115c:a1e0::2' } } else { 'fe80::2' }
            [pscustomobject]@{
                Alias = $i.Alias; Index = $i.Index; Kind = $i.Kind; Profile = $i.Profile; ProfileAssumed = $i.ProfileAssumed
                ProfileBit = $S07.ProfileBits[$i.Profile]
                IfTypeBucket = if ($i.IfType -eq 71) { 'Wireless' } elseif ($i.IfType -in 23, 131) { 'RemoteAccess' } else { 'Wired' }
                LocalV4 = if ($v4) { [string]$v4.IPAddress } else { $null }; LocalV6 = if ($v6) { ([string]$v6.IPAddress) -replace '%.*$', '' } else { $null }
                LocalV4Ip = if ($v4) { ConvertTo-S07Ip ([string]$v4.IPAddress) } else { $null }; LocalV6Ip = if ($v6) { ConvertTo-S07Ip ([string]$v6.IPAddress) } else { $null }
                RepV4 = $rep4; RepV6 = $rep6; RepV4Ip = ConvertTo-S07Ip $rep4; RepV6Ip = ConvertTo-S07Ip $rep6
            }
        }
        $ctx.Columns = @($cols)
        $rank = @{ 'yes' = 3; 'unknown' = 2; 'no' = 1; 'not-bound' = 0 }
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($l in @($ctx.Listeners | Where-Object { -not $_.Loopback -and $_.Address -notmatch '^(fe80|169\.254\.)' -or (-not $_.Loopback -and $_.Scope -eq 'specific') })) {
            # Column-independent pre-filter
            $cands = foreach ($r in $ctx.Fw.Inbound) {
                $m = Test-S07RuleForListener -Rule $r -L $l
                if ($m -ne 'no') { [pscustomobject]@{ Rule = $r; Match = $m } }
            }
            $cands = @($cands)
            foreach ($c in $ctx.Columns) {
                $fams = @()
                switch ($l.Scope) {
                    'any4' { if ($c.LocalV4) { $fams += 'v4' } }
                    'any6' { if ($c.LocalV6) { $fams += 'v6' }; if ($l.DualMode -and $c.LocalV4) { $fams += 'v4' } }
                    default { if ($l.IfIndex -eq $c.Index) { $fams += $l.Family } }
                }
                $best = [pscustomobject]@{ R = 'not-bound'; Via = @(); Reason = 'not bound to this interface' }
                foreach ($f in $fams) {
                    $res = Get-S07Reach -L $l -Col $c -Family $f -Cands $cands
                    if ($rank[$res.R] -gt $rank[$best.R]) { $best = $res }
                }
                $l.Reach[$c.Alias] = $best.R
                $l.Via[$c.Alias] = @($best.Via | Select-Object -First 6)
                $l.Why[$c.Alias] = $best.Reason
            }
            $lanCols = @($ctx.Columns | Where-Object { $_.Kind -eq 'lan' })
            $tsCols = @($ctx.Columns | Where-Object { $_.Kind -eq 'tailnet' })
            $pick = { param($cs) $b = 'no'; foreach ($c in $cs) { $v = $l.Reach[$c.Alias]; if ($rank[$v] -gt $rank[$b]) { $b = $v } }; if ($b -eq 'not-bound') { 'no' } else { $b } }
            $l.ReachLan = & $pick $lanCols
            $l.ReachTailnet = & $pick $tsCols
            $rows.Add($l)
        }
        $unknownRows = @($rows | Where-Object { $_.ReachLan -eq 'unknown' -or $_.ReachTailnet -eq 'unknown' })
        $caveats = [System.Collections.Generic.List[string]]::new()
        if ($ctx.Fw.Errors.Count) { $caveats.Add('Some firewall filters are unreadable without elevation (interface/interface-type filters assumed Any; rules without readable port/address filters give "unknown").') }
        if ($ctx.ThirdPartyFw.Count) { $caveats.Add("Third-party firewall registered in Security Center: $(($ctx.ThirdPartyFw | ForEach-Object { $_.name }) -join ', '). Its own rules are not visible here; the matrix reflects Windows Defender Firewall only.") }
        foreach ($c in @($ctx.Columns | Where-Object { $_.ProfileAssumed })) { $caveats.Add("Interface '$($c.Alias)' has no network profile; the Public profile is assumed for it.") }
        if (@($ctx.Columns | Where-Object { $_.Kind -eq 'tailnet' }).Count) { $caveats.Add('Tailnet reachability = Windows Firewall allows it AND the tailnet ACL allows it. The ACL is not visible locally.') }
        $caveats.Add('"::" listeners without an IPv4 twin are treated as dual-stack (they also accept IPv4).')
        if ($unknownRows.Count) { Set-BvsCheckStatus -Id 'net.exposure' -Status partial -Reason "$($unknownRows.Count) listener(s) with unknown reachability (filters unreadable without elevation)" }

        $matrix = [ordered]@{
            networks = @($ctx.Columns | ForEach-Object { [ordered]@{ alias = $_.Alias; kind = $_.Kind; profile = $_.Profile; profileAssumed = $_.ProfileAssumed; localV4 = $_.LocalV4; localV6 = $_.LocalV6; representativePeerV4 = $_.RepV4; representativePeerV6 = $_.RepV6 } })
            rows     = @($rows | Sort-Object Proto, Port | Select-Object -First 500 | ForEach-Object {
                    [ordered]@{
                        proto = $_.Proto; address = $_.Address; port = $_.Port; pid = $_.Pid; process = $_.Name; path = $_.Path; services = @($_.Services)
                        signer = $_.Trust.Signer; sig = $_.Trust.SigStatus; userWritable = $_.Trust.UserWritable; category = $_.Category
                        expected = if ($_.Expected) { $_.Expected.id } else { $null }; reachLan = $_.ReachLan; reachTailnet = $_.ReachTailnet
                        reach = $_.Reach; via = $_.Via; why = $_.Why
                    } })
            loopbackListeners = @($ctx.Listeners | Where-Object { $_.Loopback -and $_.Proto -eq 'TCP' } | Sort-Object Port | Select-Object -First 200 | ForEach-Object { [ordered]@{ address = $_.Address; port = $_.Port; pid = $_.Pid; process = $_.Name; signer = $_.Trust.Signer } })
            summary  = [ordered]@{
                reachableFromLan     = @($rows | Where-Object { $_.ReachLan -eq 'yes' } | ForEach-Object { '{0} {1}/{2}' -f $_.Name, $_.Proto, $_.Port } | Sort-Object -Unique)
                reachableFromTailnet = @($rows | Where-Object { $_.ReachTailnet -eq 'yes' } | ForEach-Object { '{0} {1}/{2}' -f $_.Name, $_.Proto, $_.Port } | Sort-Object -Unique)
                unknown              = @($unknownRows | ForEach-Object { '{0} {1}/{2}' -f $_.Name, $_.Proto, $_.Port } | Sort-Object -Unique)
            }
            caveats  = @($caveats)
        }
        Add-BvsInventory -Run $run -Name 'exposureMatrix' -Data $matrix

        # Findings: GlideX (expected, hardening) and unexpected third-party listeners reachable from LAN/tailnet.
        $tsBoost = $ctx.TsOtherUserPeers -gt 0
        $glide = @($rows | Where-Object { $_.Expected -and $_.Expected.id -eq 'asus-glidex' })
        if ($glide.Count) {
            $g0 = $glide[0]
            $lan = @($glide | Where-Object { $_.ReachLan -eq 'yes' }).Count -gt 0
            $tsn = @($glide | Where-Object { $_.ReachTailnet -eq 'yes' }).Count -gt 0
            $ports = @($glide | ForEach-Object { "$($_.Proto)/$($_.Port)" } | Sort-Object -Unique)
            if ($g0.Expected.cancelled) {
                New-BvsFinding -Run $run -Check 'net.exposure' -Title "GlideXService listens on $($ports.Count) ports but is NOT signed by ASUSTeK (signer: $($g0.Trust.Signer))" -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('exposed_service', 'masquerading') -Evidence @(@{ type = 'listener'; process = $g0.Name; path = $g0.Path; ports = $ports; signer = $g0.Trust.Signer; sig = $g0.Trust.SigStatus }) `
                    -Entities @{ processes = @(New-S07ProcEntity -ProcId $g0.Pid -Name $g0.Name -Path $g0.Path -Trust $g0.Trust -Services $g0.Services) } -Expected $g0.Expected `
                    -FpNotes 'An ASUS update may have changed the signing certificate name.' -Recommendation 'Check the file signature in Explorer (Properties > Digital Signatures) and the install folder. Reinstall GlideX from ASUS if in doubt.' -Mitre @('T1036')
            }
            else {
                $sev = if ($lan -or $tsn) { if ($tsn -and $tsBoost) { 'medium' } else { 'low' } } else { 'info' }
                $where = @($(if ($lan) { 'LAN' }), $(if ($tsn) { 'tailnet' })) | Where-Object { $_ }
                New-BvsFinding -Run $run -Check 'net.exposure' -Title "ASUS GlideX (screen sharing) listens on all interfaces on $($ports.Count) ports$(if ($where) { " - reachable from $($where -join ' and ')" } else { ' - blocked by the firewall' })" -Severity $sev -Class hardening -Confidence high `
                    -Reasons @('exposed_service', 'expected_match') -Evidence @(@{ type = 'listener'; process = $g0.Name; path = $g0.Path; addresses = @($glide.Address | Sort-Object -Unique); ports = $ports; signer = $g0.Trust.Signer; reachLan = $lan; reachTailnet = $tsn; allowRules = @($glide | ForEach-Object { $_.Via.Values } | ForEach-Object { $_ } | Sort-Object -Unique | Select-Object -First 10) }) `
                    -Entities @{ processes = @(New-S07ProcEntity -ProcId $g0.Pid -Name $g0.Name -Path $g0.Path -Trust $g0.Trust -Services $g0.Services) } -Expected $g0.Expected `
                    -FpNotes 'Legitimate ASUSTeK-signed software (expected.json: asus-glidex). The issue is only the exposure: a screen-sharing/control service listening on 0.0.0.0, reachable by every device on the same Wi-Fi and every tailnet peer the firewall admits.' `
                    -Recommendation 'If you do not use GlideX: uninstall it, or set the GlideXService service to Manual. If you use it: restrict its firewall rules to the Private profile and LocalSubnet, or block it on the Tailscale interface.' -Mitre @('T1021')
            }
        }
        $third = @($rows | Where-Object { $_.Category -eq 'third-party' -and ($_.ReachLan -eq 'yes' -or $_.ReachTailnet -eq 'yes') })
        foreach ($g in @($third | Group-Object Pid)) {
            $l = $g.Group[0]
            $lan = @($g.Group | Where-Object { $_.ReachLan -eq 'yes' }).Count -gt 0
            $tsn = @($g.Group | Where-Object { $_.ReachTailnet -eq 'yes' }).Count -gt 0
            $untrusted = Test-S07Untrusted $l.Trust
            $sev = if ($untrusted) { 'medium' } elseif ($l.Trust.Label -eq 'unknown') { 'low' } else { 'low' }
            if ($tsn -and $tsBoost) { $sev = Step-S07Severity $sev }
            $cls = if ($untrusted) { 'suspicious' } else { 'hardening' }
            $ref = $l.Expected
            $res = Resolve-S07Expected -Severity $sev -Class $cls -Ref $ref
            $ports = @($g.Group | ForEach-Object { "$($_.Proto)/$($_.Port)" } | Sort-Object -Unique)
            $where = @($(if ($lan) { 'LAN' }), $(if ($tsn) { 'tailnet' })) | Where-Object { $_ }
            $reasons = @('exposed_service') + @($(if ($l.Trust.Label -eq 'unsigned') { 'unsigned' }), $(if ($l.Trust.Label -eq 'invalid') { 'invalid_signature' }), $(if ($l.Trust.UserWritable) { 'user_writable' }), $(if ($ref -and -not $ref.cancelled) { 'expected_match' }) | Where-Object { $_ })
            New-BvsFinding -Run $run -Check 'net.exposure' -Title "$($l.Name) accepts inbound connections from the $($where -join ' and ') ($($ports -join ', '))" -Severity $res[0] -Class $res[1] -Confidence medium `
                -Reasons $reasons -Evidence @($g.Group | Select-Object -First 8 | ForEach-Object { @{ type = 'listener'; proto = $_.Proto; address = $_.Address; port = $_.Port; reachLan = $_.ReachLan; reachTailnet = $_.ReachTailnet; allowRules = @($_.Via.Values | ForEach-Object { $_ } | Sort-Object -Unique | Select-Object -First 6) } }) `
                -Entities @{ processes = @(New-S07ProcEntity -ProcId $l.Pid -Name $l.Name -Path $l.Path -Trust $l.Trust -Services $l.Services) } -Expected $ref `
                -FpNotes "Signer: $($l.Trust.Signer) ($($l.Trust.SigStatus)). Many apps open LAN ports for casting, sync or device discovery. Reachability is computed from Windows Firewall rules only (tailnet ACLs and third-party firewalls can still block it)." `
                -Recommendation 'If you do not need other devices to reach this program, remove or narrow its inbound firewall rules (wf.msc > Inbound Rules), or quit the program.' -Mitre @('T1133')
        }
        @($rows)
    })

#endregion

#region ---------- 5. firewall rules of interest ----------

[void](Invoke-BvsCheck -Run $run -Id 'fw.rules_of_interest' -Description 'Inbound allow rules for user-writable or missing programs; any-program rules on all profiles; known app and expected rules' -Script {
        if (-not $ctx.Fw) { Set-BvsCheckStatus -Id 'fw.rules_of_interest' -Status error -Reason 'firewall model unavailable'; return @() }
        $progInfo = @{}
        $interest = [System.Collections.Generic.List[object]]::new()
        $expRx = @(Get-BvsExpected -Category 'firewallRule' | Where-Object { $_.match.nameRegex })
        foreach ($r in $ctx.Fw.Rules) {
            $isInAllow = $r.Enabled -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow'
            $exp = $expRx | Where-Object { $r.Name -match $_.match.nameRegex } | Select-Object -First 1
            $knownApp = $null
            if ($r.ProgramExpanded -and $r.ProgramExpanded -notin 'Any', 'System') {
                foreach ($k in $S07.KnownFirewallApps) { if ($r.ProgramExpanded -match $k.Rx) { $knownApp = $k.App; break } }
            }
            $isFps = $r.Name -like 'FPS-*'
            if (-not $isInAllow -and -not $exp -and -not ($isFps -and $r.Enabled)) { continue }
            $flags = [System.Collections.Generic.List[string]]::new()
            $trust = $null
            if ($isInAllow -and $r.ProgramExpanded -and $r.ProgramExpanded -notin 'Any', 'System') {
                $p = $r.ProgramExpanded
                if (-not $progInfo.ContainsKey($p)) {
                    $exists = [IO.File]::Exists($p)
                    $fw = Test-BvsUserWritable -Path $p
                    $dw = Test-BvsUserWritable -Path ([IO.Path]::GetDirectoryName($p))
                    $progInfo[$p] = [pscustomobject]@{ Exists = $exists; UserWritable = [bool]($fw -or $dw); Trust = $null }
                    if ($exists -and $progInfo[$p].UserWritable) { $progInfo[$p].Trust = Get-S07Trust -Path $p -Name ([IO.Path]::GetFileName($p)) }
                }
                $pi = $progInfo[$p]
                if (-not $pi.Exists) { $flags.Add('program-missing') }
                if ($pi.UserWritable) { $flags.Add('user-writable') }
                $trust = $pi.Trust
            }
            $anyProg = $r.Program -eq 'Any' -and ($r.Service -in 'Any', '', $null) -and -not ($r.Package -match '^S-1-15-')
            if ($isInAllow -and $anyProg -and $r.ProfileMask -eq 7 -and -not $r.Builtin) { $flags.Add('any-program-all-profiles') }
            if ($isInAllow -and -not $r.Builtin -and ($r.ProfileMask -band 4) -and @($r.RemoteAddress) -contains 'Any' -and $r.Program -ne 'Any' -and $flags.Count -eq 0 -and -not $knownApp) { $flags.Add('public-profile-any-remote') }
            if ($knownApp) { $flags.Add("known-app:$knownApp") }
            if ($exp) { $flags.Add("expected:$($exp.id)") }
            if ($isFps -and $r.Enabled) { $flags.Add('file-printer-sharing') }
            if ($flags.Count -eq 0) { continue }
            $interest.Add([pscustomobject]@{ Rule = $r; Flags = @($flags); Trust = $trust; Expected = $exp })
        }
        $ctx.FwInterest = @($interest)
        $view = { param($x) [ordered]@{ name = $x.Rule.Name; displayName = $x.Rule.DisplayName; group = $x.Rule.Group; enabled = $x.Rule.Enabled; direction = $x.Rule.Direction; action = $x.Rule.Action; profile = $x.Rule.ProfileText; program = $x.Rule.ProgramExpanded; service = $x.Rule.Service; protocol = $x.Rule.Protocol; localPorts = $x.Rule.LocalPorts; remoteAddress = $x.Rule.RemoteAddress; flags = $x.Flags; signer = if ($x.Trust) { $x.Trust.Signer } else { $null }; sig = if ($x.Trust) { $x.Trust.SigStatus } else { $null } } }
        $inv = (Get-Variable -Name run -ValueOnly).Inventory['firewall']
        if ($inv) { $inv['rulesOfInterest'] = @($interest | Select-Object -First 300 | ForEach-Object { & $view $_ }) }

        $uwMissing = @($interest | Where-Object { $_.Flags -contains 'user-writable' -and $_.Flags -contains 'program-missing' })
        $uwUnsigned = @($interest | Where-Object { $_.Flags -contains 'user-writable' -and $_.Flags -notcontains 'program-missing' -and $_.Trust -and (Test-S07Untrusted $_.Trust) })
        $uwSigned = @($interest | Where-Object { $_.Flags -contains 'user-writable' -and $_.Flags -notcontains 'program-missing' -and -not ($_.Trust -and (Test-S07Untrusted $_.Trust)) })
        $stale = @($interest | Where-Object { $_.Flags -contains 'program-missing' -and $_.Flags -notcontains 'user-writable' })
        $anyAll = @($interest | Where-Object { $_.Flags -contains 'any-program-all-profiles' })

        foreach ($g in @($uwUnsigned | Group-Object { $_.Rule.ProgramExpanded })) {
            $x = $g.Group[0]
            New-BvsFinding -Run $run -Check 'fw.rules_of_interest' -Title "Inbound firewall allow rule for an unsigned program in a user-writable folder: $([IO.Path]::GetFileName($x.Rule.ProgramExpanded))" -Severity medium -Class suspicious -Confidence medium `
                -Reasons @('unsigned', 'user_writable', 'exposed_service') -Evidence @($g.Group | Select-Object -First 6 | ForEach-Object { @{ type = 'firewall-rule'; name = $_.Rule.Name; profile = $_.Rule.ProfileText; protocol = $_.Rule.Protocol; localPorts = $_.Rule.LocalPorts; remoteAddress = $_.Rule.RemoteAddress } }) `
                -Entities @{ files = @(@{ path = $x.Rule.ProgramExpanded; sig = $x.Trust.SigStatus; signer = $x.Trust.Signer }) } `
                -FpNotes 'Self-built dev servers and many open-source tools are unsigned. The rule was usually created when you clicked "Allow" in a firewall prompt.' `
                -Recommendation 'If you do not recognise the program, delete the rule (wf.msc > Inbound Rules) and scan the file. Otherwise narrow it to the Private profile.' -Mitre @('T1562.004')
        }
        if ($uwMissing.Count) {
            New-BvsFinding -Run $run -Check 'fw.rules_of_interest' -Title "$($uwMissing.Count) inbound allow rule(s) point to missing programs in user-writable folders (any file dropped there inherits the rule)" -Severity medium -Class hardening -Confidence high `
                -Reasons @('user_writable', 'exposed_service') -Evidence @($uwMissing | Select-Object -First 12 | ForEach-Object { @{ type = 'firewall-rule'; name = $_.Rule.Name; program = $_.Rule.ProgramExpanded; profile = $_.Rule.ProfileText; localPorts = $_.Rule.LocalPorts } }) `
                -FpNotes 'Usually leftovers of uninstalled or auto-updated apps (old version folders).' `
                -Recommendation 'Delete these stale rules in wf.msc > Inbound Rules (sort by Program).' -Mitre @('T1562.004')
        }
        if ($uwSigned.Count) {
            New-BvsFinding -Run $run -Check 'fw.rules_of_interest' -Title "$(@($uwSigned | ForEach-Object { $_.Rule.ProgramExpanded } | Sort-Object -Unique).Count) signed program(s) in user-writable folders have inbound allow rules" -Severity low -Class hardening -Confidence high `
                -Reasons @('user_writable', 'exposed_service') -Evidence @($uwSigned | Group-Object { $_.Rule.ProgramExpanded } | Select-Object -First 15 | ForEach-Object { @{ type = 'firewall-rule'; program = $_.Name; signer = $_.Group[0].Trust.Signer; rules = @($_.Group | ForEach-Object { '{0} [{1}] {2}/{3}' -f $_.Rule.Name, $_.Rule.ProfileText, $_.Rule.Protocol, (@($_.Rule.LocalPorts) -join ',') }) } }) `
                -FpNotes 'Normal for per-user installs (VS Code, Zoom, Discord, node via nvm, Python). Rules are path-based, so whatever replaces the file at that path inherits the access.' `
                -Recommendation 'Keep only rules you need; prefer the Private profile over Public; remove rules for apps you no longer use.' -Mitre @('T1562.004')
        }
        if ($stale.Count) {
            New-BvsFinding -Run $run -Check 'fw.rules_of_interest' -Title "$($stale.Count) inbound allow rule(s) point to programs that no longer exist" -Severity low -Class hygiene -Confidence high `
                -Evidence @($stale | Select-Object -First 15 | ForEach-Object { @{ type = 'firewall-rule'; name = $_.Rule.Name; program = $_.Rule.ProgramExpanded } }) `
                -FpNotes 'Typical after app updates (old WebView2/Teams version folders). The folders are admin-only, so this is cleanup, not exposure.' `
                -Recommendation 'Optional cleanup in wf.msc > Inbound Rules.'
        }
        foreach ($x in $anyAll) {
            $allPorts = @($x.Rule.LocalPorts) -contains 'Any'
            New-BvsFinding -Run $run -Check 'fw.rules_of_interest' -Title "Firewall rule '$($x.Rule.DisplayName)' allows any program on all profiles ($($x.Rule.Protocol) $(@($x.Rule.LocalPorts) -join ','))" -Severity $(if ($allPorts) { 'high' } else { 'medium' }) -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'firewall-rule'; name = $x.Rule.Name; group = $x.Rule.Group; protocol = $x.Rule.Protocol; localPorts = $x.Rule.LocalPorts; remoteAddress = $x.Rule.RemoteAddress; profile = $x.Rule.ProfileText }) `
                -FpNotes 'Some installers add port rules without a program; still applies on public Wi-Fi.' `
                -Recommendation 'Scope the rule to a program and the Private profile, or delete it.' -Mitre @('T1562.004')
        }
        @($interest)
    })

#endregion

#region ---------- 6. SMB / NetBIOS ----------

[void](Invoke-BvsCheck -Run $run -Id 'smb.shares' -Description 'SMB shares (Get-SmbShare, fallback net share) and share permissions' -Script {
        $shares = $null
        try { $shares = @(Get-SmbShare -ErrorAction Stop) } catch { $shares = $null }
        $list = @()
        if ($null -ne $shares) {
            $list = @($shares | ForEach-Object {
                    $acc = $null
                    if (-not $_.Special -and [string]$_.ShareType -ne 'PrintQueue') {
                        try { $acc = @(Get-SmbShareAccess -Name $_.Name -ErrorAction Stop | ForEach-Object { '{0}:{1}:{2}' -f $_.AccountName, $_.AccessControlType, $_.AccessRight }) } catch { $acc = @('unreadable') }
                    }
                    [ordered]@{ name = [string]$_.Name; path = [string]$_.Path; type = [string]$_.ShareType; special = [bool]$_.Special; encrypt = [bool]$_.EncryptData; access = $acc }
                })
        }
        else {
            Set-BvsCheckStatus -Id 'smb.shares' -Status partial -Reason 'Get-SmbShare failed; parsed "net share"'
            $out = @(net share 2>$null)
            $list = @($out | Where-Object { $_ -match '^(\S[^\s]*)\s{2,}' -and $_ -notmatch '^-{5}' } | Select-Object -Skip 1 | ForEach-Object { $n = ($_ -split '\s{2,}')[0]; [ordered]@{ name = $n; path = $null; type = $null; special = $n.EndsWith('$'); encrypt = $null; access = $null } })
        }
        $ctx.Shares = $list
        foreach ($s in @($list | Where-Object { -not $_.special -and $_.type -ne 'PrintQueue' -and $_.name -ne 'print$' })) {
            $everyone = @($s.access | Where-Object { $_ -match '(?i)^(Everyone|Všichni|Guest|Host)' -and $_ -match '(?i)Allow' -and $_ -match '(?i)Full|Change' })
            New-BvsFinding -Run $run -Check 'smb.shares' -Title "Folder '$($s.path)' is shared over SMB as '$($s.name)'$(if ($everyone.Count) { ' with write access for Everyone' })" -Severity $(if ($everyone.Count) { 'medium' } else { 'low' }) -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'smb-share'; name = $s.name; path = $s.path; access = $s.access }) `
                -FpNotes 'Intentional file sharing at home. Reachability depends on the File and Printer Sharing rules (see smb.fps_rules).' `
                -Recommendation 'Stop sharing folders you do not need (Computer Management > Shared Folders), and give access to named users only.' -Mitre @('T1021.002')
        }
        $list
    })

[void](Invoke-BvsCheck -Run $run -Id 'smb.connections' -Description 'Outgoing SMB sessions (Get-SmbConnection, fallback net use)' -Script {
        $conns = $null
        try { $conns = @(Get-SmbConnection -ErrorAction Stop | ForEach-Object { [ordered]@{ server = [string]$_.ServerName; share = [string]$_.ShareName; dialect = [string]$_.Dialect; user = [string]$_.UserName } }) } catch { $conns = $null }
        if ($null -eq $conns) {
            Set-BvsCheckStatus -Id 'smb.connections' -Status partial -Reason 'Get-SmbConnection needs elevation; listed "net use" (current user only)'
            $conns = @(net use 2>$null | Where-Object { $_ -match '\\\\' } | ForEach-Object { $m = [regex]::Match($_, '(\\\\[^\s]+)'); [ordered]@{ server = $m.Groups[1].Value; share = $null; dialect = $null; user = $null; status = (($_ -split '\s+')[0]) } })
        }
        $ctx.SmbConnections = $conns
        $conns
    })

[void](Invoke-BvsCheck -Run $run -Id 'smb.config' -Description 'SMB1 server/client, signing and insecure guest logons (registry)' -Script {
        $srv = @{}; foreach ($v in @(Get-BvsRegValues 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters')) { $srv[$v.Name] = $v.Value }
        $wks = @{}; foreach ($v in @(Get-BvsRegValues 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters')) { $wks[$v.Name] = $v.Value }
        $mrx10 = @{}; foreach ($v in @(Get-BvsRegValues 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10')) { $mrx10[$v.Name] = $v.Value }
        $polWks = @{}; foreach ($v in @(Get-BvsRegValues 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation')) { $polWks[$v.Name] = $v.Value }
        $smb1Server = if ($srv.ContainsKey('SMB1')) { [int]$srv['SMB1'] -ne 0 } else { $null }
        $smb1Client = ($mrx10.Count -gt 0) -and ([int]$mrx10['Start'] -ne 4)
        $guest = ($wks.ContainsKey('AllowInsecureGuestAuth') -and [int]$wks['AllowInsecureGuestAuth'] -eq 1) -or ($polWks.ContainsKey('AllowInsecureGuestAuth') -and [int]$polWks['AllowInsecureGuestAuth'] -eq 1)
        $cfg = [ordered]@{
            smb1ServerValue = if ($srv.ContainsKey('SMB1')) { [int]$srv['SMB1'] } else { 'absent (feature default: not installed on Windows 11)' }
            smb1ClientDriverPresent = ($mrx10.Count -gt 0); smb1ClientEnabled = $smb1Client
            serverRequireSigning = if ($srv.ContainsKey('RequireSecuritySignature')) { [int]$srv['RequireSecuritySignature'] } else { $null }
            clientRequireSigning = if ($wks.ContainsKey('RequireSecuritySignature')) { [int]$wks['RequireSecuritySignature'] } else { $null }
            insecureGuestAuth = $guest
            restrictNullSessAccess = if ($srv.ContainsKey('RestrictNullSessAccess')) { [int]$srv['RestrictNullSessAccess'] } else { $null }
        }
        $ctx.SmbConfig = $cfg
        if ($smb1Server -or $smb1Client) {
            New-BvsFinding -Run $run -Check 'smb.config' -Title "SMB1 is enabled ($(@($(if ($smb1Server) { 'server' }), $(if ($smb1Client) { 'client' })) -join ' + '))" -Severity medium -Class hardening -Confidence high `
                -Evidence @(@{ type = 'registry'; path = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; name = 'SMB1'; value = $cfg.smb1ServerValue }, @{ type = 'registry'; path = 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10'; name = 'Start'; value = $mrx10['Start'] }) `
                -FpNotes 'Old NAS boxes or printers sometimes need SMB1.' -Recommendation 'Remove "SMB 1.0/CIFS File Sharing Support" in Windows Features unless an old device needs it.' -Mitre @('T1210')
        }
        if ($guest) {
            New-BvsFinding -Run $run -Check 'smb.config' -Title 'Insecure SMB guest logons are allowed (AllowInsecureGuestAuth=1)' -Severity low -Class hardening -Confidence high `
                -Evidence @(@{ type = 'registry'; path = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; name = 'AllowInsecureGuestAuth'; value = 1 }) `
                -FpNotes 'Some cheap NAS devices only offer guest access.' -Recommendation 'Set a username/password on the NAS and remove AllowInsecureGuestAuth.' -Mitre @('T1557')
        }
        @($cfg)
    })

[void](Invoke-BvsCheck -Run $run -Id 'smb.netbios' -Description 'NetBIOS over TCP/IP per interface, LLMNR and mDNS policy' -Script {
        $rows = foreach ($c in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction SilentlyContinue)) {
            $idx = [int]$c.InterfaceIndex
            $if = $ctx.Interfaces | Where-Object { $_.Index -eq $idx } | Select-Object -First 1
            $opt = [int]$c.TcpipNetbiosOptions
            $v4 = @($c.IPAddress | Where-Object { $_ -match '^\d+\.' })
            $l139 = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -eq 139 -and $v4 -contains $_.Address })
            [pscustomobject][ordered]@{
                interface = if ($if) { $if.Alias } else { [string]$c.Description }; index = $idx; kind = if ($if) { $if.Kind } else { $null }
                netbiosOption = $opt; netbiosMeaning = switch ($opt) { 0 { 'default (DHCP decides; enabled when DHCP sends nothing)' } 1 { 'enabled' } 2 { 'disabled' } default { "unknown($opt)" } }
                dhcp = [bool]$c.DHCPEnabled; effectiveEnabled = ($opt -eq 1) -or ($opt -eq 0); listening139 = ($l139.Count -gt 0); addresses = $v4
                reach139Lan = if ($l139) { $l139[0].ReachLan } else { $null }; reach139Tailnet = if ($l139) { $l139[0].ReachTailnet } else { $null }
            }
        }
        $rows = @($rows)
        $llmnrPol = (Get-BvsRegValues 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' | Where-Object Name -eq 'EnableMulticast' | Select-Object -First 1).Value
        $mdns = (Get-BvsRegValues 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' | Where-Object Name -eq 'EnableMDNS' | Select-Object -First 1).Value
        $ctx.NetBios = [ordered]@{ interfaces = $rows; llmnrEnabled = ($null -eq $llmnrPol -or [int]$llmnrPol -ne 0); mdnsEnabled = ($null -eq $mdns -or [int]$mdns -ne 0) }
        foreach ($r in @($rows | Where-Object { $_.kind -eq 'tailnet' -and $_.effectiveEnabled })) {
            $reach = ($r.reach139Tailnet -eq 'yes')
            New-BvsFinding -Run $run -Check 'smb.netbios' -Title "NetBIOS over TCP/IP is enabled on the Tailscale adapter (port 139 $(if ($r.listening139) { 'listens on the tailnet IP' } else { 'may listen' }); firewall: $(if ($reach) { 'reachable' } else { 'blocked' }))" -Severity $(if ($reach) { 'medium' } else { 'low' }) -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'netbios'; interface = $r.interface; tcpipNetbiosOptions = $r.netbiosOption; listening139 = $r.listening139; addresses = $r.addresses; reachTailnet = $r.reach139Tailnet }) `
                -FpNotes 'Windows default (option 0) on adapters without DHCP. Nothing needs NetBIOS over a WireGuard tunnel; SMB works over 445 directly.' `
                -Recommendation 'Tailscale adapter > Properties > IPv4 > Advanced > WINS > "Disable NetBIOS over TCP/IP".' -Mitre @('T1557.001')
        }
        if ($ctx.NetBios.llmnrEnabled -and @($rows | Where-Object { $_.kind -eq 'lan' -and $_.effectiveEnabled }).Count) {
            New-BvsFinding -Run $run -Check 'smb.netbios' -Title 'LLMNR and NetBIOS name resolution are enabled on the LAN adapter (name-poisoning surface on untrusted Wi-Fi)' -Severity info -Class hardening -Confidence high `
                -Evidence @(@{ type = 'registry'; path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; name = 'EnableMulticast'; value = $llmnrPol }) `
                -FpNotes 'Windows default; only a concern on hostile networks (Responder-style attacks).' -Recommendation 'Optional: disable LLMNR (policy "Turn off multicast name resolution") and NetBIOS on the Wi-Fi adapter.' -Mitre @('T1557.001')
        }
        $rows
    })

[void](Invoke-BvsCheck -Run $run -Id 'smb.fps_rules' -Description 'File and Printer Sharing rules by profile; what 445/139/135 expose to the LAN and the tailnet' -Script {
        if (-not $ctx.Fw) { Set-BvsCheckStatus -Id 'smb.fps_rules' -Status error -Reason 'firewall model unavailable'; return @() }
        $fps = @($ctx.Fw.Rules | Where-Object { $_.Name -like 'FPS-*' -and $_.Direction -eq 'Inbound' })
        $enabled = @($fps | Where-Object { $_.Enabled })
        $byProfile = [ordered]@{}
        foreach ($pn in 'Domain', 'Private', 'Public') {
            $bit = $S07.ProfileBits[$pn]
            $byProfile[$pn] = @($enabled | Where-Object { $_.ProfileMask -band $bit } | ForEach-Object { '{0} ({1}/{2} from {3})' -f $_.Name, $_.Protocol, (@($_.LocalPorts) -join ','), (@($_.RemoteAddress) -join ',') })
        }
        $smbRows = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -in 445, 139, 135 -and -not $_.Loopback })
        $lan = @($smbRows | Where-Object { $_.ReachLan -eq 'yes' } | ForEach-Object { $_.Port } | Sort-Object -Unique)
        $tsn = @($smbRows | Where-Object { $_.ReachTailnet -eq 'yes' } | ForEach-Object { $_.Port } | Sort-Object -Unique)
        $publicAny = @($enabled | Where-Object { ($_.ProfileMask -band 4) -and @($_.RemoteAddress) -contains 'Any' -and (@($_.LocalPorts) -contains '445' -or @($_.LocalPorts) -contains 'RPCEPMap' -or @($_.LocalPorts) -contains '139') })
        $privOn = @($enabled | Where-Object { ($_.ProfileMask -band 2) -and @($_.LocalPorts) -contains '445' })
        $ctx.Fps = [ordered]@{ enabledByProfile = $byProfile; reachableFromLan = $lan; reachableFromTailnet = $tsn; privateSmbRuleEnabled = ($privOn.Count -gt 0) }
        $sharesNonDefault = @($ctx.Shares | Where-Object { -not $_.special -and $_.name -ne 'print$' } | ForEach-Object { $_.name })
        if ($lan.Count -or $tsn.Count) {
            $sev = if ($tsn.Count) { if ($ctx.TsOtherUserPeers -gt 0) { 'medium' } else { 'low' } } else { 'low' }
            New-BvsFinding -Run $run -Check 'smb.fps_rules' -Title "SMB/RPC ports reachable from the $(@($(if ($lan.Count) { "LAN ($($lan -join ','))" }), $(if ($tsn.Count) { "tailnet ($($tsn -join ','))" })) -join ' and ')" -Severity $sev -Class hardening -Confidence medium `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'firewall'; enabledFpsRulesByProfile = $byProfile; reachableFromLan = $lan; reachableFromTailnet = $tsn; shares = $sharesNonDefault }) `
                -FpNotes 'Intentional if you share files or a printer with other devices at home. Tailnet peers are admitted when a rule uses RemoteAddress Any; LocalSubnet rules do not cover tailnet /32 addresses.' `
                -Recommendation 'If you do not share files from this PC, turn off File and Printer Sharing for Private networks (Settings > Network > Advanced sharing settings).' -Mitre @('T1021.002')
        }
        if ($publicAny.Count) {
            New-BvsFinding -Run $run -Check 'smb.fps_rules' -Title "File and Printer Sharing (Restrictive) is enabled on the PUBLIC profile from any address ($(@($publicAny | ForEach-Object { $_.Name }) -join ', '))" -Severity medium -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @($publicAny | ForEach-Object { @{ type = 'firewall-rule'; name = $_.Name; group = $_.Group; profile = $_.ProfileText; protocol = $_.Protocol; localPorts = $_.LocalPorts; remoteAddress = $_.RemoteAddress; program = $_.Program } }) `
                -FpNotes "Windows 11 enables this group when a printer or folder is shared while connected to a network marked Public. Currently shared: $(if ($sharesNonDefault.Count) { $sharesNonDefault -join ', ' } else { 'nothing beyond defaults' }). None of the active networks is Public right now$(if (@($ctx.Columns | Where-Object { $_.Profile -eq 'Public' }).Count) { ' except: ' + ((@($ctx.Columns | Where-Object { $_.Profile -eq 'Public' }) | ForEach-Object { $_.Alias }) -join ', ') })." `
                -Recommendation 'Settings > Network & internet > Advanced network settings > Advanced sharing settings > Public networks: turn File and printer sharing Off. Unshare the printer if other devices do not print through this PC.' -Mitre @('T1021.002')
        }
        Add-BvsInventory -Run $run -Name 'smb' -Data ([ordered]@{ shares = $ctx.Shares; connections = $ctx.SmbConnections; config = $ctx.SmbConfig; netbios = $ctx.NetBios; fileAndPrinterSharing = $ctx.Fps })
        $enabled
    })

#endregion

#region ---------- 7. configuration checks: Ollama, VirtualBox, Docker, IDE locks, debug ports ----------

$cfgInv = [ordered]@{}

[void](Invoke-BvsCheck -Run $run -Id 'cfg.ollama' -Description 'Ollama: OLLAMA_HOST/OLLAMA_ORIGINS (User/Machine) and the API listener address' -Script {
        $envs = [ordered]@{}
        foreach ($n in 'OLLAMA_HOST', 'OLLAMA_ORIGINS') { foreach ($scope in 'User', 'Machine') { $envs["$n($scope)"] = [Environment]::GetEnvironmentVariable($n, $scope) } }
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'ollama*' } | ForEach-Object { [ordered]@{ pid = $_.Id; name = $_.ProcessName } })
        $ls = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and ($_.Name -like 'ollama*' -or $_.Port -eq 11434) })
        $installed = $procs.Count -or $ls.Count -or (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Programs\Ollama')) -or @($envs.Values | Where-Object { $_ }).Count
        $cfgInv['ollama'] = [ordered]@{ env = $envs; processes = $procs; listeners = @($ls | ForEach-Object { [ordered]@{ address = $_.Address; port = $_.Port; process = $_.Name; reachLan = $_.ReachLan; reachTailnet = $_.ReachTailnet } }) }
        if (-not $installed) { Set-BvsCheckStatus -Id 'cfg.ollama' -Status not_applicable -Reason 'Ollama not found'; return @() }
        $exp = Get-S07Expected -Category 'listener' -Where { param($e) $e.id -eq 'ollama-loopback' -or $e.match.process -like 'ollama*' }
        $hostVals = @($envs['OLLAMA_HOST(User)'], $envs['OLLAMA_HOST(Machine)'] | Where-Object { $_ })
        $wideEnv = @($hostVals | Where-Object { $_ -match '^(https?://)?(0\.0\.0\.0|\[?::\]?|\*)(:|$)' -or (($_ -replace '^(https?://)?', '' -replace ':\d+$', '') -notmatch '^(127\.|localhost$|\[?::1\]?$)' -and $_ -notmatch '^:\d+$') })
        $wideLs = @($ls | Where-Object { -not $_.Loopback })
        if ($wideEnv.Count -or $wideLs.Count) {
            $reach = @($wideLs | Where-Object { $_.ReachLan -eq 'yes' -or $_.ReachTailnet -eq 'yes' }).Count -gt 0
            $ref = New-S07ExpectedRef -Item $exp -Cancel @('bound to 0.0.0.0 or a LAN/Tailscale address')
            New-BvsFinding -Run $run -Check 'cfg.ollama' -Title "Ollama API is (or will be) bound beyond loopback$(if ($reach) { ' and is reachable from LAN/tailnet' })" -Severity $(if ($reach) { 'high' } else { 'medium' }) -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'config'; env = $envs; listeners = @($wideLs | ForEach-Object { "$($_.Address):$($_.Port)" }) }) -Expected $ref `
                -FpNotes 'Sometimes set on purpose to use Ollama from another device. The Ollama API has no authentication.' `
                -Recommendation 'Remove OLLAMA_HOST (or set it to 127.0.0.1:11434) unless another device must use this Ollama; then restrict it with firewall rules.' -Mitre @('T1133')
        }
        if (@($envs['OLLAMA_ORIGINS(User)'], $envs['OLLAMA_ORIGINS(Machine)'] | Where-Object { $_ -match '\*' }).Count) {
            New-BvsFinding -Run $run -Check 'cfg.ollama' -Title 'OLLAMA_ORIGINS allows any website (*) to call the local Ollama API' -Severity low -Class hardening -Confidence high `
                -Evidence @(@{ type = 'config'; env = $envs }) -FpNotes 'Set for browser extensions or web UIs.' -Recommendation 'List only the origins you use instead of *.'
        }
        @($ls)
    })

[void](Invoke-BvsCheck -Run $run -Id 'cfg.virtualbox' -Description 'VirtualBox: VMs, NAT port forwards (host IP must be 127.0.0.1), NAT networks, VRDE, bridged NICs' -Script {
        $vbm = $null
        $inst = (Get-BvsRegValues 'HKLM\SOFTWARE\Oracle\VirtualBox' | Where-Object Name -eq 'InstallDir' | Select-Object -First 1).Value
        foreach ($cand in @($(if ($inst) { Join-Path $inst 'VBoxManage.exe' }), $(if ($env:VBOX_MSI_INSTALL_PATH) { Join-Path $env:VBOX_MSI_INSTALL_PATH 'VBoxManage.exe' }), $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe' }))) {
            if ($cand -and [IO.File]::Exists($cand)) { $vbm = $cand; break }
        }
        if (-not $vbm) { Set-BvsCheckStatus -Id 'cfg.virtualbox' -Status not_applicable -Reason 'VBoxManage not found'; return @() }
        $vmLines = @(& $vbm list vms 2>$null)
        $fwdExp = @(Get-BvsExpected -Category 'network' | Where-Object { $_.match.vm -and $_.match.rule })
        $vms = foreach ($line in $vmLines) {
            if ($line -notmatch '^"(.+)"\s+\{([0-9a-fA-F-]+)\}') { continue }
            $vmName = $Matches[1]; $uuid = $Matches[2]
            $info = @{}
            $fwds = [System.Collections.Generic.List[object]]::new()
            foreach ($kv in @(& $vbm showvminfo $uuid --machinereadable 2>$null)) {
                if ($kv -match '^Forwarding\((\d+)\)="(.*)"$') {
                    $spec = $Matches[2]; $f = $spec -split ','
                    $fwds.Add([pscustomobject]@{ Spec = $spec; Name = $f[0]; Proto = $f[1]; HostIp = $f[2]; HostPort = $f[3]; GuestIp = $f[4]; GuestPort = $f[5] })
                }
                elseif ($kv -match '^"?([^"=]+)"?="?(.*?)"?$') { $info[$Matches[1]] = $Matches[2] }
            }
            $nics = @(1..8 | ForEach-Object { $t = $info["nic$_"]; if ($t -and $t -ne 'none') { [ordered]@{ nic = $_; type = $t; bridge = $info["bridgeadapter$_"]; hostonly = $info["hostonlyadapter$_"] } } })
            [pscustomobject]@{ Name = $vmName; Uuid = $uuid; State = $info['VMState']; Vrde = $info['vrde']; VrdePort = $info['vrdeport']; Nics = $nics; Forwards = @($fwds) }
        }
        $vms = @($vms)
        $natnets = [System.Collections.Generic.List[object]]::new()
        $curNet = $null
        foreach ($l in @(& $vbm list natnets 2>$null)) {
            if ($l -match '^(NetworkName|Name):\s+(.+)$') { $curNet = $Matches[2].Trim() }
            elseif ($l -match '^\s+([^:]+):(tcp|udp):\[([^\]]*)\]:(\d+):\[([^\]]*)\]:(\d+)') { $natnets.Add([pscustomobject]@{ Network = $curNet; Name = $Matches[1]; Proto = $Matches[2]; HostIp = $Matches[3]; HostPort = $Matches[4]; GuestIp = $Matches[5]; GuestPort = $Matches[6] }) }
        }
        foreach ($vm in $vms) {
            foreach ($f in $vm.Forwards) {
                $exp = $fwdExp | Where-Object { $_.match.vm -eq $vm.Name -and $_.match.rule -eq $f.Spec } | Select-Object -First 1
                if ($f.HostIp -notin '127.0.0.1', '::1') {
                    $ref = New-S07ExpectedRef -Item $exp -Cancel @('host IP not 127.0.0.1')
                    New-BvsFinding -Run $run -Check 'cfg.virtualbox' -Title "VM '$($vm.Name)' forwards host port $($f.HostPort) on $(if ($f.HostIp) { $f.HostIp } else { 'ALL interfaces' }) to guest port $($f.GuestPort)" -Severity medium -Class hardening -Confidence high `
                        -Reasons @('exposed_service') -Evidence @(@{ type = 'vbox-forward'; vm = $vm.Name; rule = $f.Spec; vmState = $vm.State }) -Expected $ref `
                        -FpNotes 'An empty host IP makes VirtualBox listen on every interface (LAN and tailnet) while the VM runs.' `
                        -Recommendation "VirtualBox > $($vm.Name) > Settings > Network > Port Forwarding: set Host IP to 127.0.0.1." -Mitre @('T1133')
                }
            }
            if ($vm.Vrde -eq 'on') {
                New-BvsFinding -Run $run -Check 'cfg.virtualbox' -Title "VM '$($vm.Name)' has VirtualBox Remote Display (VRDE) enabled (port $($vm.VrdePort))" -Severity medium -Class hardening -Confidence high `
                    -Reasons @('exposed_service') -Evidence @(@{ type = 'vbox-config'; vm = $vm.Name; vrde = $vm.Vrde; port = $vm.VrdePort }) -FpNotes 'Intentional for headless VMs.' `
                    -Recommendation 'Disable Remote Display or bind it to 127.0.0.1.' -Mitre @('T1021.001')
            }
        }
        foreach ($n in @($natnets | Where-Object { $_.HostIp -notin '127.0.0.1', '::1' })) {
            New-BvsFinding -Run $run -Check 'cfg.virtualbox' -Title "NAT network '$($n.Network)' forwards host port $($n.HostPort) on $(if ($n.HostIp) { $n.HostIp } else { 'ALL interfaces' })" -Severity medium -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'vbox-natnet-forward'; network = $n.Network; rule = "$($n.Name):$($n.Proto):[$($n.HostIp)]:$($n.HostPort):[$($n.GuestIp)]:$($n.GuestPort)" }) `
                -FpNotes 'Intentional only if other devices must reach the VM.' -Recommendation 'Set the host IP of the rule to 127.0.0.1 (File > Tools > Network Manager > NAT Networks).' -Mitre @('T1133')
        }
        $cfgInv['virtualbox'] = [ordered]@{
            vboxmanage = $vbm
            vms = @($vms | ForEach-Object { [ordered]@{ name = $_.Name; state = $_.State; vrde = $_.Vrde; nics = $_.Nics; forwards = @($_.Forwards | ForEach-Object { [ordered]@{ rule = $_.Spec; hostIp = $_.HostIp; loopbackOnly = ($_.HostIp -in '127.0.0.1', '::1'); expected = @($fwdExp | Where-Object { $_.match.rule -eq $_.Spec }).Count -gt 0 } }) } })
            natNetworkForwards = @($natnets)
            expectedForwards = @($fwdExp | ForEach-Object { [ordered]@{ id = $_.id; vm = $_.match.vm; rule = $_.match.rule } })
        }
        $vms
    })

[void](Invoke-BvsCheck -Run $run -Id 'cfg.docker' -Description 'Docker Desktop: exposeDockerAPIOnTCP2375 must be false; listeners on 2375/2376' -Script {
        $files = @('settings-store.json', 'settings.json') | ForEach-Object { Join-Path $env:APPDATA "Docker\$_" } | Where-Object { Test-Path -LiteralPath $_ }
        $installed = $files.Count -or ($env:ProgramFiles -and (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')))
        $ls = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -in 2375, 2376 })
        if (-not $installed -and -not $ls.Count) { Set-BvsCheckStatus -Id 'cfg.docker' -Status not_applicable -Reason 'Docker Desktop not found'; return @() }
        $vals = foreach ($f in $files) {
            $o = $null
            try { $o = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
            $prop = if ($o) { $o.PSObject.Properties | Where-Object { $_.Name -ieq 'exposeDockerAPIOnTCP2375' } | Select-Object -First 1 } else { $null }
            [ordered]@{ file = $f; parsed = [bool]$o; exposeDockerAPIOnTCP2375 = if ($prop) { [bool]$prop.Value } else { $null }; note = if ($prop) { $null } else { 'key absent = default false' } }
        }
        $vals = @($vals)
        $cfgInv['docker'] = [ordered]@{ settings = $vals; listeners2375 = @($ls | ForEach-Object { "$($_.Address):$($_.Port) ($($_.Name))" }); running = [bool](Get-Process -Name 'Docker Desktop', 'com.docker.backend' -ErrorAction SilentlyContinue) }
        if (@($vals | Where-Object { $_.exposeDockerAPIOnTCP2375 -eq $true }).Count -or @($ls | Where-Object { $_.Port -eq 2375 }).Count) {
            New-BvsFinding -Run $run -Check 'cfg.docker' -Title 'Docker Engine API is exposed on tcp://localhost:2375 without TLS' -Severity high -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'config'; settings = $vals; listeners = @($ls | ForEach-Object { "$($_.Address):$($_.Port)" }) }) `
                -FpNotes 'Some old tools required it. Any local process or website (via DNS rebinding) can then run containers with full host access.' `
                -Recommendation 'Docker Desktop > Settings > General: untick "Expose daemon on tcp://localhost:2375 without TLS".' -Mitre @('T1610')
        }
        $vals
    })

[void](Invoke-BvsCheck -Run $run -Id 'cfg.claude_ide_locks' -Description '~\.claude\ide\*.lock: port and pid only (authToken never read into output); listener must be loopback' -Script {
        $dirPath = Join-Path $env:USERPROFILE '.claude\ide'
        if (-not (Test-Path -LiteralPath $dirPath)) { Set-BvsCheckStatus -Id 'cfg.claude_ide_locks' -Status not_applicable -Reason 'no ~\.claude\ide folder'; return @() }
        $locks = foreach ($f in @(Get-ChildItem -LiteralPath $dirPath -Filter '*.lock' -File -ErrorAction SilentlyContinue)) {
            if (Test-BvsNeverRead $f.FullName) { continue }
            $port = if ($f.BaseName -match '^\d+$') { [int]$f.BaseName } else { $null }
            $text = [IO.File]::ReadAllText($f.FullName)
            $lockPid = if ($text -match '"pid"\s*:\s*(\d+)') { [int]$Matches[1] } else { $null }
            $text = $null
            $alive = if ($lockPid) { [bool](Get-Process -Id $lockPid -ErrorAction SilentlyContinue) } else { $false }
            $ls = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -eq $port })
            [pscustomobject][ordered]@{ port = $port; pid = $lockPid; pidAlive = $alive; listening = ($ls.Count -gt 0); addresses = @($ls | ForEach-Object { if ($_.PSObject.Properties['Address']) { [string]$_.Address } elseif ($_.PSObject.Properties['LocalAddress']) { [string]$_.LocalAddress } } | Sort-Object -Unique); listenerPid = @($ls.Pid) | Select-Object -First 1; listenerProcess = @($ls.Name) | Select-Object -First 1; lastWriteUtc = $f.LastWriteTimeUtc.ToString('o'); stale = (-not $ls.Count) }
        }
        $locks = @($locks)
        $cfgInv['claudeIdeLocks'] = $locks
        foreach ($k in @($locks | Where-Object { $_.listening -and @($_.addresses | Where-Object { $_ -notin '127.0.0.1', '::1' }).Count })) {
            New-BvsFinding -Run $run -Check 'cfg.claude_ide_locks' -Title "Claude Code IDE bridge on port $($k.port) listens beyond loopback ($($k.addresses -join ', '))" -Severity high -Class hardening -Confidence high `
                -Reasons @('exposed_service') -Evidence @(@{ type = 'listener'; port = $k.port; addresses = $k.addresses; pid = $k.listenerPid; process = $k.listenerProcess }) `
                -FpNotes 'The bridge is token-protected, but it is designed for loopback only.' -Recommendation 'Restart the IDE; if it persists, update the Claude Code extension and report it.'
        }
        $stale = @($locks | Where-Object { $_.stale })
        if ($stale.Count) {
            New-BvsFinding -Run $run -Check 'cfg.claude_ide_locks' -Title "$($stale.Count) stale Claude Code IDE lock file(s) (no listener on their port)" -Severity info -Class hygiene -Confidence high `
                -Evidence @(@{ type = 'files'; folder = $dirPath; stalePorts = @($stale.port) }) -FpNotes 'Left behind when an IDE window closes uncleanly. Harmless.' `
                -Recommendation 'Optional: delete the stale .lock files while no IDE is open.'
        }
        $locks
    })

[void](Invoke-BvsCheck -Run $run -Id 'cfg.debug_ports' -Description 'Listeners on 9222 (Chromium DevTools) and 9229 (Node inspector)' -Script {
        $ls = @($ctx.Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -in 9222, 9229 })
        $cfgInv['debugPorts'] = @($ls | ForEach-Object { [ordered]@{ address = $_.Address; port = $_.Port; pid = $_.Pid; process = $_.Name; path = $_.Path; reachLan = $_.ReachLan; reachTailnet = $_.ReachTailnet } })
        foreach ($g in @($ls | Group-Object Pid, Port)) {
            $l = $g.Group[0]
            $wide = @($g.Group | Where-Object { -not $_.Loopback }).Count -gt 0
            $sev = if ($wide) { 'high' } elseif ($l.Port -eq 9222) { 'medium' } else { 'low' }
            New-BvsFinding -Run $run -Check 'cfg.debug_ports' -Title "$(if ($l.Port -eq 9222) { 'Chromium DevTools' } else { 'Node.js inspector' }) port $($l.Port) is open ($($l.Name) on $(@($g.Group.Address) -join ', '))" -Severity $sev -Class suspicious -Confidence medium `
                -Reasons @(@('exposed_service') + $(if ($wide) { 'public_network' }) | Where-Object { $_ }) -Evidence @($g.Group | ForEach-Object { @{ type = 'listener'; address = $_.Address; port = $_.Port; pid = $_.Pid } }) `
                -Entities @{ processes = @(New-S07ProcEntity -ProcId $l.Pid -Name $l.Name -Path $l.Path -Trust $l.Trust -Services $l.Services) } `
                -FpNotes 'Developers open these on purpose (node --inspect, Playwright/Puppeteer, browser automation). A DevTools port gives full control of the browser profile (cookies, sessions) to any local process.' `
                -Recommendation 'Close the program that opened it when you are not debugging. Never expose these ports beyond 127.0.0.1.' -Mitre @('T1185')
        }
        $ls
    })

Add-BvsInventory -Run $run -Name 'configChecks' -Data $cfgInv

#endregion

#region ---------- 8. DNS ----------

$dnsInv = [ordered]@{}
$avastExp = Get-S07Expected -Category 'rootCert' -Where { param($e) $e.match.subjectContains -like '*Avast*' }
$ctx.AvastCancel = @()
if ($avastExp) {
    if (-not $ctx.AvastInstalled) { $ctx.AvastCancel += 'Avast not installed' }
    $avRoots = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\AuthRoot' -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'Avast' } | ForEach-Object { $_.Thumbprint } | Sort-Object -Unique)
    if ($avRoots.Count -gt 1) { $ctx.AvastCancel += 'several Avast-named roots with different thumbprints' }
}

[void](Invoke-BvsCheck -Run $run -Id 'dns.servers' -Description 'DNS servers per interface (static vs DHCP) classified: router, tailscale, known public, unknown' -Script {
        $v6Router = @{}
        foreach ($i in $ctx.Interfaces) { if ($i.Gateway6) { $v6Router[$i.Index] = $i.Gateway6 } }
        $rows = foreach ($s in @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) {
            $if = $ctx.Interfaces | Where-Object { $_.Index -eq [int]$s.InterfaceIndex } | Select-Object -First 1
            if (-not $if) { continue }
            $reg4 = @{}; if ($if.Guid) { foreach ($v in @(Get-BvsRegValues "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($if.Guid)")) { $reg4[$v.Name] = $v.Value } }
            $reg6 = @{}; if ($if.Guid) { foreach ($v in @(Get-BvsRegValues "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($if.Guid)")) { $reg6[$v.Name] = $v.Value } }
            $static = if ([string]$s.AddressFamily -match '23|IPv6') { [string]$reg6['NameServer'] } else { [string]$reg4['NameServer'] }
            foreach ($srvAddr in @($s.ServerAddresses)) {
                $cls = Get-S07IpClass $srvAddr
                $kind = if ($S07.PlaceholderDns -contains $srvAddr) { 'placeholder' }
                elseif ($S07.TailscaleDns -contains $srvAddr) { 'tailscale' }
                elseif ($srvAddr -eq $if.Gateway4 -or $srvAddr -eq $if.Gateway6) { 'router' }
                elseif ($v6Router[$if.Index] -and $srvAddr -match ':' -and (($srvAddr -split ':')[-4..-1] -join ':') -eq ((([string]$v6Router[$if.Index]) -split ':')[-4..-1] -join ':')) { 'router' }
                elseif ($cls -in 'rfc1918', 'linklocal', 'ula', 'loopback') { 'lan' }
                elseif ($S07.PublicResolvers -contains $srvAddr) { 'public-known' }
                elseif ($cls -eq 'public') { 'public-unknown' }
                else { $cls }
                [pscustomobject][ordered]@{ interface = $if.Alias; kind = $if.Kind; family = if ($srvAddr -match ':') { 'IPv6' } else { 'IPv4' }; server = $srvAddr; classification = $kind; staticConfigured = [bool]($static -and $static -match [regex]::Escape($srvAddr)) }
            }
        }
        $rows = @($rows)
        $dnsInv['servers'] = $rows
        foreach ($r in @($rows | Where-Object { $_.classification -eq 'public-unknown' })) {
            New-BvsFinding -Run $run -Check 'dns.servers' -Title "Interface '$($r.interface)' uses an unrecognised public DNS server $($r.server)$(if ($r.staticConfigured) { ' (set manually)' } else { ' (from DHCP)' })" -Severity $(if ($r.staticConfigured) { 'medium' } else { 'low' }) -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'dns-server'; interface = $r.interface; server = $r.server; static = $r.staticConfigured }) `
                -FpNotes 'ISP resolvers handed out by the router, or a resolver you chose yourself, are common. DNS-changer malware sets unknown public resolvers.' `
                -Recommendation 'Confirm the server belongs to your ISP or a resolver you chose; otherwise reset the adapter DNS to automatic.' -Mitre @('T1557')
        }
        $rows
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.doh' -Description 'DNS-over-HTTPS server table (Get-DnsClientDohServerAddress)' -Script {
        $doh = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ server = [string]$_.ServerAddress; template = [string]$_.DohTemplate; autoUpgrade = [bool]$_.AutoUpgrade; allowFallbackToUdp = [bool]$_.AllowFallbackToUdp } })
        $dnsInv['doh'] = $doh
        $known = '(?i)^https://(dns\.quad9\.net|dns\.google|cloudflare-dns\.com|one\.one\.one\.one|doh\.opendns\.com|dns\.adguard(-dns)?\.com|dns\.nextdns\.io|doh\.cleanbrowsing\.org)/'
        foreach ($d in @($doh | Where-Object { $_.template -and $_.template -notmatch $known })) {
            New-BvsFinding -Run $run -Check 'dns.doh' -Title "Custom DNS-over-HTTPS template for $($d.server): $($d.template)" -Severity low -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'doh'; server = $d.server; template = $d.template; autoUpgrade = $d.autoUpgrade }) -FpNotes 'NextDNS/ControlD or company resolvers add their own templates.' `
                -Recommendation 'Confirm you added this DoH provider; remove it in Settings > Network > DNS settings if not.' -Mitre @('T1557')
        }
        $doh
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.nrpt' -Description 'Name Resolution Policy Table (effective), e.g. Tailscale MagicDNS' -Script {
        $pol = @(Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue)
        $groups = @($pol | Group-Object { (@($_.NameServers) -join ',') } | ForEach-Object {
                $names = @($_.Group | ForEach-Object { $_.Namespace } | ForEach-Object { $_ })
                [ordered]@{ nameServers = $_.Name; namespaces = $names.Count; reverseZones = @($names | Where-Object { $_ -match '\.arpa$' }).Count; forwardNamespaces = @($names | Where-Object { $_ -notmatch '\.arpa$' } | Select-Object -First 20) }
            })
        $dnsInv['nrpt'] = $groups
        foreach ($g in @($groups | Where-Object { $_.nameServers -and (@($_.nameServers -split ',' | Where-Object { $S07.TailscaleDns -notcontains $_ }).Count) })) {
            $catchAll = @($g.forwardNamespaces | Where-Object { $_ -eq '.' }).Count -gt 0
            New-BvsFinding -Run $run -Check 'dns.nrpt' -Title "NRPT sends $(if ($catchAll) { 'ALL names' } else { ($g.forwardNamespaces -join ', ') }) to $($g.nameServers)" -Severity $(if ($catchAll) { 'medium' } else { 'low' }) -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'nrpt'; nameServers = $g.nameServers; namespaces = $g.forwardNamespaces }) -FpNotes 'Corporate VPNs and DirectAccess use NRPT rules.' `
                -Recommendation 'Confirm the VPN/software that owns these rules; remove them via its settings if unknown.' -Mitre @('T1557')
        }
        $groups
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.cache' -Description 'DNS client cache: total count and ONLY flagged entries (tunnels, request catchers, paste/transfer, Telegram API, Discord CDN, abused TLDs, DGA-like)' -Script {
        $cache = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
        if ($cache.Count -eq 0 -and -not $run.Elevated) {
            Set-BvsCheckStatus -Id 'dns.cache' -Status needs_admin -Reason 'This Windows build only exposes the DNS client cache to elevated callers (Get-DnsClientCache returns nothing, ipconfig /displaydns requires elevation)'
            $dnsInv['cache'] = [ordered]@{ total = $null; readable = $false; flagged = @() }
            return @()
        }
        $flagged = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $cache) {
            foreach ($n in @([string]$e.Entry, [string]$e.Name, $(if ([string]$e.Type -eq '5' -or [string]$e.Type -eq 'CNAME') { [string]$e.Data }))) {
                if (-not $n -or -not $seen.Add($n)) { continue }
                if ($n -match '^bvsnx[a-z]{15}\.com$') { continue }      # this collector's own NXDOMAIN probe
                foreach ($f in @(Get-S07DnsFlags -Name $n)) { $flagged.Add([pscustomobject]@{ Name = $n; Cat = $f.Cat; Match = $f.Match; Mitre = $f.Mitre }) }
            }
        }
        $dnsInv['cache'] = [ordered]@{ total = $cache.Count; readable = $true; flagged = @($flagged | Select-Object -First 200 | ForEach-Object { [ordered]@{ name = $_.Name; category = $_.Cat; match = $_.Match } }) }
        foreach ($g in @($flagged | Group-Object Cat)) {
            $cat = $g.Name
            $sev = switch ($cat) { 'discord-webhook-cdn' { if ($ctx.DiscordInstalled) { 'info' } else { 'low' } } 'dga-like' { 'low' } 'abused-tld' { 'low' } default { 'low' } }
            New-BvsFinding -Run $run -Check 'dns.cache' -Title "DNS cache contains $($g.Count) $cat name(s): $(@($g.Group.Name | Select-Object -First 5) -join ', ')" -Severity $sev -Class suspicious -Confidence low `
                -Reasons @($(if ($cat -eq 'dga-like') { 'random_name' }) | Where-Object { $_ }) -Evidence @(@{ type = 'dns-cache'; category = $cat; names = @($g.Group.Name | Select-Object -First 25); totalCacheEntries = $cache.Count }) `
                -FpNotes $(switch ($cat) { 'tunnel' { 'Developers use ngrok/cloudflared/duckdns themselves.' } 'request-catcher' { 'Webhook testing and security work (interactsh/Burp) produce these.' } 'paste-transfer' { 'Opening a paste link in the browser is enough.' } 'telegram-api' { 'Telegram bots/apps you run.' } 'discord-webhook-cdn' { "Discord installed: $($ctx.DiscordInstalled). Discord's CDN is also abused to host malware." } 'dga-like' { 'Random-looking names are also used by CDNs, trackers and ad networks.' } default { 'Cheap TLDs host plenty of legitimate sites.' } }) `
                -Recommendation 'Check which program resolved these names (browser history, running tools). Investigate unknown ones.' -Mitre @($(if ($g.Group[0].Mitre) { $g.Group[0].Mitre }) | Where-Object { $_ })
        }
        @($flagged)
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.hijack' -Description 'Router vs DoH answers for 6 well-known names; TLS issuer of router answers with normal validation' -Script {
        $gw = $ctx.Gateway
        if (-not $gw) { Set-BvsCheckStatus -Id 'dns.hijack' -Status not_applicable -Reason 'no IPv4 default gateway'; return @() }
        $results = foreach ($n in $S07.TestNames) {
            $row = [ordered]@{ name = $n; router = $gw; routerIps = @(); routerError = $null; dohSource = $null; dohIps = @(); dohError = $null; overlap = $null; routerBogon = $false; tls = $null; verdict = $null }
            try { $row.routerIps = @(Resolve-DnsName -Name $n -Type A -Server $gw -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress }) }
            catch { $row.routerError = $_.Exception.Message }
            if (-not $NoIntel) { $d = Get-S07DohA -Name $n; $row.dohSource = $d.Source; $row.dohIps = @($d.Ips); $row.dohError = $d.Error }
            if ($row.routerIps.Count -and $row.dohIps.Count) { $row.overlap = @($row.routerIps | Where-Object { $row.dohIps -contains $_ }).Count }
            $row.routerBogon = @($row.routerIps | Where-Object { (Get-S07IpClass $_) -ne 'public' }).Count -gt 0
            if (-not $NoTlsProbe -and $row.routerIps.Count) {
                $t = Test-S07Tls -Ip $row.routerIps[0] -Name $n
                $t.classification = Get-S07TlsClass -Tls $t -AvastRef $avastExp
                $row.tls = $t
            }
            $row.verdict = if ($row.routerBogon) { 'hijack-suspected (private/bogon answer)' }
            elseif ($row.tls -and $row.tls.classification -in 'validation-failed', 'unknown-root', 'avast-intercept-unverified') { "mitm-suspected ($($row.tls.classification))" }
            elseif ($row.tls -and $row.tls.classification -eq 'avast-intercept') { 'ok (Avast Web Shield TLS interception)' }
            elseif ($row.tls -and $row.tls.classification -in 'public', 'public-preinstalled') { 'ok' }
            elseif ($row.routerError) { 'inconclusive (router did not answer)' }
            else { 'inconclusive' }
            [pscustomobject]$row
        }
        $results = @($results)
        $dnsInv['hijackTest'] = $results
        foreach ($r in @($results | Where-Object { $_.verdict -like 'hijack*' -or $_.verdict -like 'mitm*' })) {
            New-BvsFinding -Run $run -Check 'dns.hijack' -Title "DNS/TLS integrity failure for $($r.name): $($r.verdict)" -Severity high -Class suspicious -Confidence medium `
                -Evidence @(@{ type = 'dns'; name = $r.name; router = $r.router; routerIps = $r.routerIps; dohIps = $r.dohIps; dohSource = $r.dohSource }, @{ type = 'tls'; ip = $r.tls.ip; policyErrors = $r.tls.policyErrors; leafIssuer = $r.tls.leafIssuer; rootSubject = $r.tls.rootSubject; rootStore = $r.tls.rootStore; error = $r.tls.error }) `
                -FpNotes 'Captive portals, parental-control routers and corporate TLS inspection produce the same picture. CDN address differences alone are normal and are not flagged.' `
                -Recommendation 'Check the router DNS settings and firmware, compare with a different network (phone hotspot), and inspect the certificate in a browser.' -Mitre @('T1557')
        }
        $av = @($results | Where-Object { $_.tls -and $_.tls.classification -eq 'avast-intercept' })
        if ($av.Count) {
            New-BvsFinding -Run $run -Check 'dns.hijack' -Title "Avast Web Shield intercepts TLS for $($av.Count) of $($results.Count) test sites ($(@($av.name) -join ', '))" -Severity info -Class info -Confidence high `
                -Reasons @('expected_match') -Evidence @($av | ForEach-Object { @{ type = 'tls'; name = $_.name; leafIssuer = $_.tls.leafIssuer; rootStore = $_.tls.rootStore } }) -Expected (New-S07ExpectedRef -Item $avastExp -Cancel $ctx.AvastCancel) `
                -FpNotes 'Expected (expected.json: avast-webshield-root). Certificate-based checks by other modules will see the Avast root instead of the real issuer for these sites.' `
                -Recommendation 'None required. To see real certificates, temporarily disable HTTPS scanning in Avast > Settings > Protection > Core Shields.'
        }
        $results
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.nxdomain' -Description 'NXDOMAIN probe: a random 20-character .com name sent to the router must fail' -Script {
        $gw = $ctx.Gateway
        if (-not $gw) { Set-BvsCheckStatus -Id 'dns.nxdomain' -Status not_applicable -Reason 'no IPv4 default gateway'; return @() }
        $rand = -join (1..15 | ForEach-Object { [char](97 + [Security.Cryptography.RandomNumberGenerator]::GetInt32(26)) })
        $name = "bvsnx$rand.com"      # 20 characters before .com; recognisable as our own probe
        $res = [ordered]@{ name = $name; server = $gw; answered = $false; answers = @(); errorCode = $null; error = $null; verdict = $null }
        try {
            $res.answers = @(Resolve-DnsName -Name $name -Type A -Server $gw -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
            $res.answered = $res.answers.Count -gt 0
        }
        catch {
            $res.errorCode = $_.Exception.NativeErrorCode
            $res.error = $_.Exception.Message
        }
        $res.verdict = if ($res.answered) { 'NXDOMAIN rewritten (hijacked)' } elseif ($res.errorCode -eq 9003) { 'ok (NXDOMAIN)' } else { 'inconclusive' }
        $dnsInv['nxdomainProbe'] = $res
        if ($res.verdict -eq 'inconclusive') { Set-BvsCheckStatus -Id 'dns.nxdomain' -Status partial -Reason "router reply: $($res.error)" }
        if ($res.answered) {
            New-BvsFinding -Run $run -Check 'dns.nxdomain' -Title "Router DNS answers non-existent names ($name -> $($res.answers -join ', '))" -Severity high -Class suspicious -Confidence high `
                -Evidence @(@{ type = 'dns'; name = $name; server = $gw; answers = $res.answers }) `
                -FpNotes 'Some ISPs rewrite NXDOMAIN to an ad/search page; a compromised router does the same to phish.' `
                -Recommendation 'Check router DNS settings and firmware; switch the router to a trusted resolver; ask the ISP to disable NXDOMAIN redirection.' -Mitre @('T1557')
        }
        @($res)
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.wpad' -Description 'WPAD: wpad.<suffix> (DNS) and wpad (LLMNR/NetBIOS) must not resolve' -Script {
        $suffixes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($c in @(Get-DnsClient -ErrorAction SilentlyContinue)) {
            foreach ($s in @($c.ConnectionSpecificSuffix) + @($c.ConnectionSpecificSuffixSearchList)) { if ($s) { [void]$suffixes.Add($s.Trim('.')) } }
        }
        foreach ($s in @((Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue).SuffixSearchList)) { if ($s) { [void]$suffixes.Add($s.Trim('.')) } }
        foreach ($v in @(Get-BvsRegValues 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' | Where-Object { $_.Name -in 'Domain', 'NV Domain' })) { if ($v.Value) { [void]$suffixes.Add(([string]$v.Value).Trim('.')) } }
        $tests = foreach ($s in $suffixes) {
            $n = "wpad.$s"
            $r = [ordered]@{ name = $n; method = 'DNS'; resolved = $false; answers = @(); errorCode = $null }
            try { $r.answers = @(Resolve-DnsName -Name $n -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress }); $r.resolved = $r.answers.Count -gt 0 }
            catch { $r.errorCode = $_.Exception.NativeErrorCode }
            [pscustomobject]$r
        }
        $l = [ordered]@{ name = 'wpad'; method = 'LLMNR/NetBIOS'; resolved = $false; answers = @(); errorCode = $null }
        try { $l.answers = @(Resolve-DnsName -Name 'wpad' -LlmnrNetbiosOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { [string]$_.IPAddress }); $l.resolved = $l.answers.Count -gt 0 }
        catch { $l.errorCode = $_.Exception.NativeErrorCode }
        $all = @($tests) + @([pscustomobject]$l)
        $dnsInv['wpad'] = $all
        foreach ($t in @($all | Where-Object { $_.resolved })) {
            New-BvsFinding -Run $run -Check 'dns.wpad' -Title "WPAD name '$($t.name)' resolves via $($t.method) to $($t.answers -join ', ')" -Severity $(if ($t.method -ne 'DNS') { 'high' } else { 'medium' }) -Class suspicious -Confidence medium `
                -Evidence @(@{ type = 'dns'; name = $t.name; method = $t.method; answers = $t.answers }) `
                -FpNotes 'Company networks publish WPAD on purpose. On a home network an answer is unexpected; an LLMNR/NetBIOS answer is the Responder attack pattern.' `
                -Recommendation 'Turn off "Automatically detect settings" (Settings > Network > Proxy) and find the device that answers.' -Mitre @('T1557.001')
        }
        $all
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.gateway_arp' -Description 'Gateway MAC must be unique in the IPv4 neighbor (ARP) table' -Script {
        $gw = $ctx.Gateway
        if (-not $gw) { Set-BvsCheckStatus -Id 'dns.gateway_arp' -Status not_applicable -Reason 'no IPv4 default gateway'; return @() }
        $nb = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E-.*)$' -and [string]$_.State -notin 'Unreachable', 'Incomplete' })
        $g = $nb | Where-Object { $_.IPAddress -eq $gw } | Select-Object -First 1
        $res = [ordered]@{ gateway = $gw; gatewayMac = if ($g) { [string]$g.LinkLayerAddress } else { $null }; state = if ($g) { [string]$g.State } else { $null }; sameMacOtherIps = @(); neighbors = $nb.Count }
        if ($g) { $res.sameMacOtherIps = @($nb | Where-Object { $_.LinkLayerAddress -eq $g.LinkLayerAddress -and $_.IPAddress -ne $gw } | ForEach-Object { '{0} ({1})' -f $_.IPAddress, $_.State }) }
        else { Set-BvsCheckStatus -Id 'dns.gateway_arp' -Status partial -Reason 'gateway not in the neighbor table yet' }
        $dnsInv['gatewayArp'] = $res
        if ($res.sameMacOtherIps.Count) {
            New-BvsFinding -Run $run -Check 'dns.gateway_arp' -Title "Gateway MAC $($res.gatewayMac) is also used by $($res.sameMacOtherIps.Count) other IPv4 address(es)" -Severity medium -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'arp'; gateway = $gw; mac = $res.gatewayMac; otherIps = $res.sameMacOtherIps }) `
                -FpNotes 'Wi-Fi repeaters/mesh nodes in MAC-NAT mode and routers with several IPs show one MAC for many IPs. ARP spoofing looks the same.' `
                -Recommendation 'Compare with the MAC printed on the router; let S08 (LAN discovery) identify the devices.' -Mitre @('T1557.002')
        }
        if ($g -and [string]$g.State -eq 'Permanent') { $res['note'] = 'static ARP entry for the gateway' }
        @($res)
    })

[void](Invoke-BvsCheck -Run $run -Id 'dns.ipv6_routers' -Description 'IPv6 default-route router advertisements per interface' -Script {
        $routes = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -and $_.NextHop -ne '::' })
        $gwMac = if ($dnsInv['gatewayArp']) { $dnsInv['gatewayArp'].gatewayMac } else { $null }
        $rows = foreach ($r in $routes) {
            $nb = Get-NetNeighbor -IPAddress $r.NextHop -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
            [pscustomobject][ordered]@{ interface = [string]$r.InterfaceAlias; router = [string]$r.NextHop; metric = [int]$r.RouteMetric; mac = if ($nb) { [string]$nb.LinkLayerAddress } else { $null }; sameMacAsIPv4Gateway = if ($nb -and $gwMac) { [string]$nb.LinkLayerAddress -eq $gwMac } else { $null } }
        }
        $rows = @($rows)
        $prefixes = @(Get-NetIPAddress -AddressFamily IPv6 -PrefixOrigin RouterAdvertisement -ErrorAction SilentlyContinue | ForEach-Object { '{0} {1}/{2}' -f $_.InterfaceAlias, ((([string]$_.IPAddress) -split ':')[0..3] -join ':'), $_.PrefixLength } | Sort-Object -Unique)
        $dnsInv['ipv6Routers'] = [ordered]@{ defaultRoutes = $rows; raPrefixes = $prefixes }
        foreach ($g in @($rows | Group-Object interface | Where-Object { @($_.Group.mac | Sort-Object -Unique).Count -gt 1 })) {
            New-BvsFinding -Run $run -Check 'dns.ipv6_routers' -Title "Several IPv6 routers advertise a default route on '$($g.Name)' ($(@($g.Group.router) -join ', '))" -Severity low -Class suspicious -Confidence low `
                -Evidence @(@{ type = 'ipv6-ra'; interface = $g.Name; routers = @($g.Group | ForEach-Object { "$($_.router) [$($_.mac)]" }) }) `
                -FpNotes 'Mesh Wi-Fi systems and ISP modems plus a second router legitimately both advertise. A rogue RA (IPv6 MITM) looks the same.' `
                -Recommendation 'Identify each router MAC; disable router advertisements on devices that should not send them.' -Mitre @('T1557')
        }
        $rows
    })

Add-BvsInventory -Run $run -Name 'dns' -Data $dnsInv

#endregion

#region ---------- 9. Wi-Fi ----------

$wifiInv = [ordered]@{}

[void](Invoke-BvsCheck -Run $run -Id 'wifi.interfaces' -Description 'netsh wlan show interfaces: SSID, authentication, cipher, connection mode' -Script {
        $out = @(netsh wlan show interfaces 2>$null)
        $pairs = @(ConvertFrom-S07Netsh -Lines $out)
        if (-not $pairs.Count) { Set-BvsCheckStatus -Id 'wifi.interfaces' -Status not_applicable -Reason 'no wireless interface or WLAN service not running'; return @() }
        $blocks = [System.Collections.Generic.List[object]]::new()
        $cur = $null
        foreach ($p in $pairs) {
            if ($p.L -match $S07Wlan.Name) { $cur = [ordered]@{ name = $p.V }; $blocks.Add($cur); continue }
            if (-not $cur) { continue }
            if ($p.L -match $S07Wlan.Ssid -and -not $cur.Contains('ssid')) { $cur['ssid'] = $p.V }
            elseif ($p.L -match $S07Wlan.Auth -or ($p.V -match '^(WPA|WEP|Open|Otev|OWE)' -and -not $cur.Contains('authentication'))) { if (-not $cur.Contains('authentication')) { $cur['authentication'] = $p.V } }
            elseif ($p.L -match $S07Wlan.Cipher) { $cur['cipher'] = $p.V }
            elseif ($p.L -match $S07Wlan.Mode) { $cur['connectionMode'] = $p.V }
            elseif ($p.L -match $S07Wlan.Profile) { $cur['profile'] = $p.V }
            elseif ($p.L -match $S07Wlan.State) { $cur['state'] = $p.V }
            elseif ($p.L -match $S07Wlan.Radio) { $cur['radioType'] = $p.V }
            elseif ($p.L -match $S07Wlan.Band) { $cur['band'] = $p.V }
        }
        $ifs = foreach ($b in $blocks) {
            $sec = Get-S07WifiSecurity -Auths @($b['authentication']) -Ciphers @($b['cipher'])
            $b['security'] = $sec.Best
            $b
        }
        $ifs = @($ifs)
        $wifiInv['interfaces'] = $ifs
        foreach ($b in @($ifs | Where-Object { $_['ssid'] })) {
            $sec = Get-S07WifiSecurity -Auths @($b['authentication']) -Ciphers @($b['cipher'])
            if ($sec.Open -or $sec.Wep -or $sec.Best -eq 'WPA') {
                New-BvsFinding -Run $run -Check 'wifi.interfaces' -Title "Connected Wi-Fi '$($b['ssid'])' uses weak security ($($b['authentication']) / $($b['cipher']))" -Severity $(if ($sec.Open -or $sec.Wep) { 'high' } else { 'medium' }) -Class hardening -Confidence high `
                    -Evidence @(@{ type = 'wifi'; ssid = $b['ssid']; authentication = $b['authentication']; cipher = $b['cipher'] }) -FpNotes 'Hotel/café networks are often open; use a VPN there.' `
                    -Recommendation 'Use WPA2/WPA3 on your own router; on open networks keep Tailscale exit node or another VPN on.' -Mitre @('T1557')
            }
        }
        $ifs
    })

[void](Invoke-BvsCheck -Run $run -Id 'wifi.profiles' -Description 'Saved Wi-Fi profiles (no key material): authentication, cipher, connection mode; open/WEP auto-connect' -Script {
        $out = @(netsh wlan show profiles 2>$null)
        $names = @($out | ForEach-Object { if ($_ -match '^\s{2,}[^:]*\S\s+:\s(.+)$') { $v = $Matches[1].Trim(); if ($v -and $v -notmatch '^<.*>$') { $v } } } | Select-Object -Unique)
        if (-not $names.Count) { Set-BvsCheckStatus -Id 'wifi.profiles' -Status not_applicable -Reason 'no saved Wi-Fi profiles'; return @() }
        $skipped = 0
        $profiles = foreach ($n in $names) {
            if ($n.Contains('"')) { $skipped++; continue }
            $det = @(netsh wlan show profile name="$n" 2>$null)
            $pairs = @(ConvertFrom-S07Netsh -Lines $det)
            $auths = @($pairs | Where-Object { $_.L -match $S07Wlan.Auth } | ForEach-Object { $_.V })
            $ciphers = @($pairs | Where-Object { $_.L -match $S07Wlan.Cipher } | ForEach-Object { $_.V })
            $mode = ($pairs | Where-Object { $_.L -match $S07Wlan.Mode } | Select-Object -First 1).V
            $key = ($pairs | Where-Object { $_.L -match $S07Wlan.Key } | Select-Object -First 1).V
            $bcast = ($pairs | Where-Object { $_.L -match $S07Wlan.Bcast } | Select-Object -First 1).V
            $mac = ($pairs | Where-Object { $_.L -match $S07Wlan.MacRand } | Select-Object -First 1).V
            $sec = Get-S07WifiSecurity -Auths $auths -Ciphers $ciphers
            [pscustomobject][ordered]@{
                name = $n; authentication = @($auths | Sort-Object -Unique); cipher = @($ciphers | Sort-Object -Unique); security = $sec.Best
                open = $sec.Open; wep = $sec.Wep; tkip = $sec.Tkip; wpa3Transition = $sec.Transition; enterprise = $sec.Enterprise
                connectionMode = $mode; autoConnect = [bool]($mode -match '(?i)auto|automati'); securityKey = $key
                connectEvenIfHidden = [bool]($bcast -match '(?i)even if|i když|i kdyz'); macRandomization = $mac
            }
        }
        $profiles = @($profiles)
        $wifiInv['profiles'] = $profiles
        $wifiInv['summary'] = [ordered]@{ total = $profiles.Count; skipped = $skipped; wpa3 = @($profiles | Where-Object { $_.security -eq 'WPA3' }).Count; wpa2 = @($profiles | Where-Object { $_.security -eq 'WPA2' }).Count; wpa = @($profiles | Where-Object { $_.security -eq 'WPA' }).Count; open = @($profiles | Where-Object { $_.open }).Count; wep = @($profiles | Where-Object { $_.wep }).Count; enterprise = @($profiles | Where-Object { $_.enterprise }).Count }
        if ($skipped) { Set-BvsCheckStatus -Id 'wifi.profiles' -Status partial -Reason "$skipped profile name(s) with quotes skipped" }
        $openAuto = @($profiles | Where-Object { ($_.open -or $_.wep) -and $_.autoConnect })
        if ($openAuto.Count) {
            New-BvsFinding -Run $run -Check 'wifi.profiles' -Title "$($openAuto.Count) saved open/WEP Wi-Fi network(s) auto-connect: $(@($openAuto.name | Select-Object -First 6) -join ', ')" -Severity medium -Class hardening -Confidence high `
                -Evidence @($openAuto | Select-Object -First 15 | ForEach-Object { @{ type = 'wifi-profile'; name = $_.name; security = $_.security; connectionMode = $_.connectionMode } }) `
                -FpNotes 'Saved from a hotel/café/train. Anyone can create a fake hotspot with the same name and the laptop joins it automatically (evil twin).' `
                -Recommendation 'Forget these networks or switch them to "Connect manually" (Settings > Wi-Fi > Manage known networks).' -Mitre @('T1557')
        }
        $weak = @($profiles | Where-Object { -not $_.open -and -not $_.wep -and ($_.security -eq 'WPA' -or ($_.tkip -and $_.security -ne 'WPA3')) })
        if ($weak.Count) {
            New-BvsFinding -Run $run -Check 'wifi.profiles' -Title "$($weak.Count) saved Wi-Fi network(s) still allow WPA1/TKIP: $(@($weak.name | Select-Object -First 6) -join ', ')" -Severity low -Class hardening -Confidence high `
                -Evidence @($weak | Select-Object -First 15 | ForEach-Object { @{ type = 'wifi-profile'; name = $_.name; authentication = $_.authentication; cipher = $_.cipher } }) -FpNotes 'Old routers.' `
                -Recommendation 'Switch those routers to WPA2-AES or WPA3, or forget the networks.'
        }
        $hidden = @($profiles | Where-Object { $_.connectEvenIfHidden })
        if ($hidden.Count) {
            New-BvsFinding -Run $run -Check 'wifi.profiles' -Title "$($hidden.Count) saved Wi-Fi profile(s) probe for hidden networks (SSID broadcast in every probe)" -Severity info -Class hygiene -Confidence high `
                -Evidence @(@{ type = 'wifi-profile'; names = @($hidden.name | Select-Object -First 10) }) -FpNotes 'Needed only for genuinely hidden networks.' `
                -Recommendation 'Untick "Connect even if the network is not broadcasting" where not needed.'
        }
        $cur = @($wifiInv['interfaces'] | Where-Object { $_['ssid'] }) | Select-Object -First 1
        if ($cur -and $cur['security'] -eq 'WPA2') {
            New-BvsFinding -Run $run -Check 'wifi.profiles' -Title "Current Wi-Fi '$($cur['ssid'])' uses WPA2-Personal (WPA3 not in use); $($wifiInv['summary'].wpa3) saved profile(s) use WPA3" -Severity info -Class info -Confidence high `
                -Evidence @(@{ type = 'wifi'; ssid = $cur['ssid']; authentication = $cur['authentication']; cipher = $cur['cipher'] }) -FpNotes 'WPA2-AES with a strong passphrase is still fine.' `
                -Recommendation 'Optional: enable WPA2/WPA3 transition or WPA3 in the router if all devices support it.'
        }
        $profiles
    })

Add-BvsInventory -Run $run -Name 'wifi' -Data $wifiInv

#endregion

#region ---------- 10. connections: wait for the sampler, then analyse ----------

"S07: other checks done; waiting for the connection sampler..."
$samplesTaken = @()
[void](Invoke-BvsCheck -Run $run -Id 'conn.sampling' -Description "Get-NetTCPConnection (Established, SynSent) + Get-NetUDPEndpoint, $Samples samples $IntervalSec s apart (own PID excluded)" -Script {
        $got = @()
        if ($samplerJob) {
            $timeout = [int]($Samples * $IntervalSec + 240 - ([datetime]::UtcNow - $samplerStarted).TotalSeconds)
            if ($timeout -lt 30) { $timeout = 30 }
            [void](Wait-Job -Job $samplerJob -Timeout $timeout)
            if ($samplerJob.State -eq 'Running') { Stop-Job -Job $samplerJob }
            $jobErr = $null
            $got = @(Receive-Job -Job $samplerJob -ErrorAction SilentlyContinue -ErrorVariable jobErr)
            Remove-Job -Job $samplerJob -Force
            if (@($jobErr).Count) { Write-BvsLog -Run $run -Level WARN -Message "sampler errors: $(@($jobErr).Count) ($(@($jobErr)[0]))" }
        }
        else {
            $got = @(& $samplerScript $Samples $IntervalSec $PID $rootRx)
        }
        $script:samplesTaken = @($got | Where-Object { $_ -and $_.PSObject.Properties['Tcp'] } | Sort-Object Index)
        if ($script:samplesTaken.Count -lt $Samples) { Set-BvsCheckStatus -Id 'conn.sampling' -Status partial -Reason "$($script:samplesTaken.Count) of $Samples samples collected" }
        $script:samplesTaken
    })
$samplesTaken = $script:samplesTaken

# Merge process info from samples with the (refreshed) process table
$sampleProcs = @{}
foreach ($s in $samplesTaken) { foreach ($kv in $s.Procs.GetEnumerator()) { if (-not $sampleProcs.ContainsKey([int]$kv.Key)) { $sampleProcs[[int]$kv.Key] = $kv.Value } } }
Update-S07ProcTable
$connProc = @{}
function Get-S07ConnProc {
    param([int]$ProcId)
    if ($connProc.ContainsKey($ProcId)) { return $connProc[$ProcId] }
    $sp = $sampleProcs[$ProcId]; $tp = $ctx.Procs[$ProcId]
    $name = if ($sp -and $sp.Name) { $sp.Name } elseif ($tp) { [string]$tp.Name } elseif ($ProcId -eq 4) { 'System' } else { "pid-$ProcId" }
    $path = if ($sp -and $sp.Path) { $sp.Path } elseif ($tp -and $tp.Path -and $tp.Name -eq $name) { [string]$tp.Path } else { $null }
    $svcs = if ($tp -and $tp.Name -eq $name) { @($tp.Services) } else { @() }
    $trust = Get-S07Trust -Path $path -Name $name -ProcId $ProcId
    $exp = Get-S07ProcessExpected -Path $path
    $o = [pscustomobject]@{ Pid = $ProcId; Name = $name; Path = $path; Services = $svcs; Trust = $trust; Scanner = [bool]($sp -and $sp.Scanner); Expected = (New-S07ExpectedRef -Item $exp) }
    $connProc[$ProcId] = $o
    $o
}

$epAgg = @{}
$classTotals = @{}; $stateTotals = @{}
$tcpObs = 0; $scannerObs = 0
foreach ($s in $samplesTaken) {
    foreach ($c in $s.Tcp) {
        $tcpObs++
        $sp = $sampleProcs[$c.P]
        if ($sp -and $sp.Scanner) { $scannerObs++; continue }
        $cls = Get-S07IpClass $c.R
        $classTotals[$cls] = 1 + [int]$classTotals[$cls]
        $stateTotals[$c.S] = 1 + [int]$stateTotals[$c.S]
        $k = '{0}|{1}|{2}' -f $c.P, $c.R, $c.RP
        $e = $epAgg[$k]
        if (-not $e) {
            $e = [pscustomobject]@{ Pid = $c.P; Remote = $c.R; RemotePort = $c.RP; Class = $cls; Samples = [System.Collections.Generic.SortedSet[int]]::new(); Conns = @{}; States = [System.Collections.Generic.HashSet[string]]::new(); First = $s.AtUtc; Last = $s.AtUtc }
            $epAgg[$k] = $e
        }
        [void]$e.Samples.Add($s.Index); [void]$e.States.Add($c.S); $e.Last = $s.AtUtc
        $ck = '{0}|{1}' -f $c.LP, $(if ($c.C) { $c.C.Ticks } else { 0 })
        if (-not $e.Conns.ContainsKey($ck)) { $e.Conns[$ck] = [System.Collections.Generic.List[int]]::new() }
        $e.Conns[$ck].Add($s.Index)
    }
}
$ptr = @{}

[void](Invoke-BvsCheck -Run $run -Id 'conn.rdns' -Description 'Reverse DNS (PTR) for public remote IPs: cached, short timeout, capped' -Script {
        $ips = @($epAgg.Values | Where-Object { $_.Class -eq 'public' } | ForEach-Object { $_.Remote } | Sort-Object -Unique)
        if ($MaxReverseDns -eq 0 -or -not $ips.Count) { Set-BvsCheckStatus -Id 'conn.rdns' -Status skipped -Reason $(if ($MaxReverseDns -eq 0) { '-MaxReverseDns 0' } else { 'no public remote IPs' }); return @() }
        $take = @($ips | Select-Object -First $MaxReverseDns)
        $res = @($take | ForEach-Object -ThrottleLimit 16 -Parallel {
                $ipAddr = $_
                $nm = $null
                try { $rec = Resolve-DnsName -Name $ipAddr -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'PTR' } | Select-Object -First 1; if ($rec) { $nm = [string]$rec.NameHost } } catch { $nm = $null }
                [pscustomobject]@{ Ip = $ipAddr; Name = $nm }
            })
        foreach ($r in $res) { $ptr[$r.Ip] = $r.Name }
        if ($ips.Count -gt $take.Count) { Set-BvsCheckStatus -Id 'conn.rdns' -Status partial -Reason "capped at $MaxReverseDns of $($ips.Count) IPs" }
        $res
    })

[void](Invoke-BvsCheck -Run $run -Id 'conn.analysis' -Description 'Classify remote ends (loopback, RFC1918, tailscale, link-local, multicast, public) and map to process/path/signer' -Script {
        if (-not $samplesTaken.Count) { Set-BvsCheckStatus -Id 'conn.analysis' -Status error -Reason 'no samples'; return @() }
        $byProc = @{}
        foreach ($e in $epAgg.Values) {
            $p = Get-S07ConnProc -ProcId $e.Pid
            $key = $e.Pid
            if (-not $byProc.ContainsKey($key)) { $byProc[$key] = [pscustomobject]@{ Proc = $p; Endpoints = [System.Collections.Generic.List[object]]::new(); Classes = @{} } }
            $byProc[$key].Endpoints.Add($e)
            $byProc[$key].Classes[$e.Class] = 1 + [int]$byProc[$key].Classes[$e.Class]
        }
        $ctx.ConnByProc = $byProc
        $procRows = @($byProc.Values | ForEach-Object {
                $p = $_.Proc
                $pub = @($_.Endpoints | Where-Object { $_.Class -eq 'public' })
                [ordered]@{
                    pid = $p.Pid; name = $p.Name; path = $p.Path; signer = $p.Trust.Signer; sig = $p.Trust.SigStatus; userWritable = $p.Trust.UserWritable
                    expected = if ($p.Expected) { $p.Expected.id } else { $null }; endpoints = $_.Endpoints.Count; publicEndpoints = $pub.Count
                    publicRemoteIps = @($pub.Remote | Sort-Object -Unique).Count; classes = $_.Classes
                    remotePorts = @($_.Endpoints.RemotePort | Sort-Object -Unique | Select-Object -First 15)
                }
            } | Sort-Object { $_.publicEndpoints } -Descending)
        $pubRows = @($epAgg.Values | Where-Object { $_.Class -eq 'public' } | Sort-Object { $_.Samples.Count } -Descending | Select-Object -First 300 | ForEach-Object {
                $p = Get-S07ConnProc -ProcId $_.Pid
                $intel = @($(if ($ctx.Tor -and $ctx.Tor.Set.Contains($_.Remote)) { 'tor-exit' }), $(if ($ctx.Feodo -and $ctx.Feodo.Map.ContainsKey($_.Remote)) { 'feodo-c2' })) | Where-Object { $_ }
                [ordered]@{ process = $p.Name; pid = $_.Pid; remote = $_.Remote; port = $_.RemotePort; ptr = $ptr[$_.Remote]; samplesSeen = $_.Samples.Count; distinctConnections = $_.Conns.Count; states = @($_.States); firstSeenUtc = $_.First.ToString('o'); lastSeenUtc = $_.Last.ToString('o'); intel = @($intel) }
            })
        $udpByProc = @{}
        foreach ($s in $samplesTaken) {
            foreach ($g in @($s.Udp | Where-Object { (Get-S07IpClass $_.L) -ne 'loopback' } | Group-Object P)) {
                $n = $g.Count
                if (-not $udpByProc.ContainsKey($g.Name) -or $udpByProc[$g.Name].max -lt $n) { $udpByProc[$g.Name] = @{ max = $n; ports = @($g.Group.LP | Sort-Object -Unique | Select-Object -First 12) } }
            }
        }
        Add-BvsInventory -Run $run -Name 'connections' -Data ([ordered]@{
                samplesRequested = $Samples; samplesTaken = $samplesTaken.Count; intervalSec = $IntervalSec
                firstSampleUtc = if ($samplesTaken.Count) { $samplesTaken[0].AtUtc.ToString('o') } else { $null }
                lastSampleUtc = if ($samplesTaken.Count) { $samplesTaken[-1].AtUtc.ToString('o') } else { $null }
                excluded = [ordered]@{ ownPid = $PID; scannerObservations = $scannerObs; note = 'Connections of this collector and of other baby-virus-scanner collectors (command line inside the project folder) are excluded from flagging.' }
                totals = [ordered]@{ tcpObservations = $tcpObs; uniqueEndpoints = $epAgg.Count; uniqueRemoteIps = @($epAgg.Values.Remote | Sort-Object -Unique).Count; byClass = $classTotals; byState = $stateTotals }
                processes = @($procRows | Select-Object -First 150)
                publicEndpoints = $pubRows
                udpNonLoopbackByProcess = @($udpByProc.GetEnumerator() | ForEach-Object { $p = Get-S07ConnProc -ProcId ([int]$_.Key); [ordered]@{ pid = [int]$_.Key; process = $p.Name; maxEndpoints = $_.Value.max; ports = $_.Value.ports } } | Sort-Object { $_.maxEndpoints } -Descending | Select-Object -First 60)
                intelLists = [ordered]@{ torExits = if ($ctx.Tor) { [ordered]@{ entries = $ctx.Tor.Set.Count; source = $ctx.Tor.Source; fetchedAt = $ctx.Tor.FetchedAt } } else { $null }; feodo = if ($ctx.Feodo) { [ordered]@{ entries = $ctx.Feodo.Map.Count; source = $ctx.Feodo.Source; fetchedAt = $ctx.Feodo.FetchedAt } } else { $null } }
            })
        $procRows
    })

[void](Invoke-BvsCheck -Run $run -Id 'conn.untrusted_public' -Description 'Unsigned, invalid-signature, masquerading or user-writable processes with public connections' -Script {
        if (-not $ctx.ConnByProc) { return @() }
        $hits = [System.Collections.Generic.List[object]]::new()
        $signedUw = [System.Collections.Generic.List[object]]::new()
        $hidden = [System.Collections.Generic.List[object]]::new()
        foreach ($b in $ctx.ConnByProc.Values) {
            $p = $b.Proc
            $pub = @($b.Endpoints | Where-Object { $_.Class -eq 'public' })
            if (-not $pub.Count) { continue }
            $t = $p.Trust
            $ev = @($pub | Sort-Object { $_.Samples.Count } -Descending | Select-Object -First 8 | ForEach-Object { @{ type = 'connection'; remote = $_.Remote; port = $_.RemotePort; ptr = $ptr[$_.Remote]; samplesSeen = $_.Samples.Count; states = @($_.States) } })
            $ent = @{ processes = @(New-S07ProcEntity -ProcId $p.Pid -Name $p.Name -Path $p.Path -Trust $t -Services $p.Services); network = @($pub | Select-Object -First 20 | ForEach-Object { @{ remote = $_.Remote; port = $_.RemotePort; ptr = $ptr[$_.Remote] } }) }
            if ($t.Masquerading -or $t.Label -eq 'invalid' -or $t.Label -eq 'unsigned') {
                $reasons = @('public_network') + @($(if ($t.Label -eq 'unsigned') { 'unsigned' }), $(if ($t.Label -eq 'invalid') { 'invalid_signature' }), $(if ($t.UserWritable) { 'user_writable' }), $(if ($t.Masquerading) { 'masquerading' }) | Where-Object { $_ })
                $sev = if ($t.Masquerading -or $t.Label -eq 'invalid' -or $t.UserWritable) { 'high' } else { 'medium' }
                $res = Resolve-S07Expected -Severity $sev -Class 'suspicious' -Ref $p.Expected
                if ($p.Expected -and -not $p.Expected.cancelled) { $reasons += 'expected_match' }
                New-BvsFinding -Run $run -Check 'conn.untrusted_public' -Title "$($t.Label -replace 'invalid', 'Invalid-signature' -replace 'unsigned', 'Unsigned') process $($p.Name)$(if ($t.UserWritable) { ' in a user-writable folder' }) talks to $(@($pub.Remote | Sort-Object -Unique).Count) public IP(s)" -Severity $res[0] -Class $res[1] -Confidence medium `
                    -Reasons $reasons -Evidence $ev -Entities $ent -Expected $p.Expected `
                    -FpNotes 'Developer tools, game launchers and open-source utilities are often unsigned and live in AppData. Check the remote names (PTR) and the program origin.' `
                    -Recommendation 'Identify the program (path, publisher, when it was installed). If unknown: disconnect, upload the file hash to VirusTotal manually, and remove it.' -Mitre @('T1071')
                $hits.Add($p)
            }
            elseif ($t.UserWritable) { $signedUw.Add([pscustomobject]@{ P = $p; Pub = $pub }) }
            elseif ($t.Label -eq 'unknown' -and -not $t.IsOs) { $hidden.Add([pscustomobject]@{ P = $p; Pub = $pub }) }
        }
        if ($signedUw.Count) {
            New-BvsFinding -Run $run -Check 'conn.untrusted_public' -Title "$($signedUw.Count) validly signed program(s) running from user-writable folders talk to the internet" -Severity low -Class info -Confidence high `
                -Reasons @('user_writable', 'public_network') -Evidence @($signedUw | Select-Object -First 25 | ForEach-Object { @{ type = 'process'; name = $_.P.Name; path = $_.P.Path; signer = $_.P.Trust.Signer; publicRemoteIps = @($_.Pub.Remote | Sort-Object -Unique).Count; expected = if ($_.P.Expected) { $_.P.Expected.id } else { $null } } }) `
                -FpNotes 'Normal for per-user installs (Claude Code, VS Code, Discord, Spotify, OneDrive, Zoom). Listed so verifiers can confirm each signer.' `
                -Recommendation 'Confirm every signer is the vendor you expect.'
        }
        if ($hidden.Count) {
            New-BvsFinding -Run $run -Check 'conn.untrusted_public' -Title "$($hidden.Count) process(es) with public connections could not be mapped to a file (needs elevation)" -Severity info -Class info -Confidence low `
                -Evidence @($hidden | Select-Object -First 20 | ForEach-Object { @{ type = 'process'; name = $_.P.Name; pid = $_.P.Pid; publicRemoteIps = @($_.Pub.Remote | Sort-Object -Unique).Count } }) `
                -FpNotes 'Processes of other accounts (e.g. sandbox users) or protected processes hide their path from a non-elevated token.' `
                -Recommendation 'Re-run S07 elevated to resolve their paths and signers.'
            Set-BvsCheckStatus -Id 'conn.untrusted_public' -Status partial -Reason "$($hidden.Count) process path(s) hidden without elevation"
        }
        @($hits)
    })

[void](Invoke-BvsCheck -Run $run -Id 'conn.suspicious_ports' -Description 'Connections to backdoor / Tor / mining ports' -Script {
        $hits = @($epAgg.Values | Where-Object { $S07.SuspiciousPorts.ContainsKey($_.RemotePort) -and $_.Class -notin 'loopback', 'unspecified' })
        foreach ($g in @($hits | Group-Object Pid, RemotePort)) {
            $e0 = $g.Group[0]
            $p = Get-S07ConnProc -ProcId $e0.Pid
            $isPublic = @($g.Group | Where-Object { $_.Class -eq 'public' }).Count -gt 0
            $sev = if (-not $isPublic) { 'low' } elseif (Test-S07Untrusted $p.Trust) { 'high' } else { 'medium' }
            $mitre = if ($S07.TorPorts -contains $e0.RemotePort) { @('T1090.003') } elseif ($S07.MiningPorts -contains $e0.RemotePort) { @('T1496') } else { @('T1571') }
            New-BvsFinding -Run $run -Check 'conn.suspicious_ports' -Title "$($p.Name) connects to port $($e0.RemotePort) ($($S07.SuspiciousPorts[$e0.RemotePort])) on $(@($g.Group.Remote | Sort-Object -Unique).Count) $(if ($isPublic) { 'public' } else { 'private' }) host(s)" -Severity $sev -Class suspicious -Confidence low `
                -Reasons @(@($(if ($isPublic) { 'public_network' }), $(if ($p.Trust.Label -eq 'unsigned') { 'unsigned' }), $(if ($p.Trust.UserWritable) { 'user_writable' })) | Where-Object { $_ }) `
                -Evidence @($g.Group | Select-Object -First 8 | ForEach-Object { @{ type = 'connection'; remote = $_.Remote; port = $_.RemotePort; ptr = $ptr[$_.Remote]; class = $_.Class; samplesSeen = $_.Samples.Count } }) `
                -Entities @{ processes = @(New-S07ProcEntity -ProcId $p.Pid -Name $p.Name -Path $p.Path -Trust $p.Trust -Services $p.Services) } `
                -FpNotes 'Games, dev servers and some apps use these ports too (7777 game servers, 9001 dev consoles, 5555 adb to a phone).' `
                -Recommendation 'Identify the remote host (PTR, owner) and the program; stop it if you do not recognise it.' -Mitre $mitre
        }
        $hits
    })

[void](Invoke-BvsCheck -Run $run -Id 'conn.beaconing' -Description 'Repeated short-lived connections (new local port each time) to the same remote across samples; repeated SYN_SENT' -Script {
        if ($samplesTaken.Count -lt 4) { Set-BvsCheckStatus -Id 'conn.beaconing' -Status skipped -Reason "needs at least 4 samples (got $($samplesTaken.Count))"; return @() }
        $minSeen = [Math]::Max(3, [int][Math]::Ceiling($samplesTaken.Count * 0.3))
        $cands = foreach ($e in $epAgg.Values) {
            if ($e.Class -in 'loopback', 'unspecified', 'multicast') { continue }
            $seen = $e.Samples.Count
            $conns = $e.Conns.Count
            $short = @($e.Conns.Values | Where-Object { $_.Count -eq 1 }).Count
            $synOnly = ($e.States.Count -eq 1 -and $e.States.Contains('SynSent'))
            $isBeacon = ($seen -ge $minSeen -and $conns -ge 3 -and $short -ge 3 -and ($short / $conns) -ge 0.75)
            $isSyn = ($synOnly -and $seen -ge 3)
            if (-not $isBeacon -and -not $isSyn) { continue }
            $ticks = @($e.Conns.Keys | ForEach-Object { [long](($_ -split '\|')[1]) } | Where-Object { $_ -gt 0 } | Sort-Object)
            $deltas = @(for ($i = 1; $i -lt $ticks.Count; $i++) { ($ticks[$i] - $ticks[$i - 1]) / 1e7 })
            $mean = if ($deltas.Count) { ($deltas | Measure-Object -Average).Average } else { $null }
            $cv = $null
            if ($deltas.Count -ge 2 -and $mean -gt 0) { $sd = [Math]::Sqrt((($deltas | ForEach-Object { ($_ - $mean) * ($_ - $mean) }) | Measure-Object -Sum).Sum / $deltas.Count); $cv = [Math]::Round($sd / $mean, 2) }
            $p = Get-S07ConnProc -ProcId $e.Pid
            [pscustomobject]@{ E = $e; P = $p; Kind = $(if ($isSyn) { 'syn-repeated' } else { 'short-repeated' }); Seen = $seen; Conns = $conns; MeanInterval = $(if ($null -ne $mean) { [Math]::Round($mean, 1) } else { $null }); Cv = $cv }
        }
        $cands = @($cands)
        $inv = (Get-Variable -Name run -ValueOnly).Inventory['connections']
        if ($inv) {
            $inv['beaconCandidates'] = @($cands | Select-Object -First 100 | ForEach-Object { [ordered]@{ kind = $_.Kind; process = $_.P.Name; pid = $_.P.Pid; signer = $_.P.Trust.Signer; sig = $_.P.Trust.SigStatus; remote = $_.E.Remote; port = $_.E.RemotePort; class = $_.E.Class; ptr = $ptr[$_.E.Remote]; samplesSeen = $_.Seen; distinctConnections = $_.Conns; meanIntervalSec = $_.MeanInterval; intervalCv = $_.Cv } })
        }
        foreach ($c in @($cands | Where-Object { (Test-S07Untrusted $_.P.Trust) -or ($_.P.Trust.UserWritable -and -not ($_.P.Expected -and -not $_.P.Expected.cancelled)) -or $_.P.Trust.Label -eq 'unknown' })) {
            $sev = if (Test-S07Untrusted $c.P.Trust) { 'medium' } else { 'low' }
            if ($c.E.Class -ne 'public') { $sev = 'low' }
            New-BvsFinding -Run $run -Check 'conn.beaconing' -Title "$($c.P.Name) makes repeated $(if ($c.Kind -eq 'syn-repeated') { 'failing (SYN_SENT)' } else { 'short' }) connections to $($c.E.Remote):$($c.E.RemotePort)$(if ($ptr[$c.E.Remote]) { " ($($ptr[$c.E.Remote]))" })" -Severity $sev -Class suspicious -Confidence low `
                -Reasons @(@($(if ($c.E.Class -eq 'public') { 'public_network' }), $(if ($c.P.Trust.Label -eq 'unsigned') { 'unsigned' }), $(if ($c.P.Trust.UserWritable) { 'user_writable' })) | Where-Object { $_ }) `
                -Evidence @(@{ type = 'connection-pattern'; kind = $c.Kind; remote = $c.E.Remote; port = $c.E.RemotePort; ptr = $ptr[$c.E.Remote]; samplesSeen = $c.Seen; of = $samplesTaken.Count; distinctConnections = $c.Conns; meanIntervalSec = $c.MeanInterval; intervalCv = $c.Cv }) `
                -Entities @{ processes = @(New-S07ProcEntity -ProcId $c.P.Pid -Name $c.P.Name -Path $c.P.Path -Trust $c.P.Trust -Services $c.P.Services) } `
                -FpNotes 'Update checkers, telemetry, sync clients and dev tools poll on timers too. 30-second sampling only sees connections alive at sample time.' `
                -Recommendation 'Identify the remote (PTR, ASN) and what the program is; investigate further only if both are unknown.' -Mitre @('T1071')
        }
        $cands
    })

[void](Invoke-BvsCheck -Run $run -Id 'conn.intel_match' -Description 'Remote IPs on the Tor exit list or the Feodo Tracker C2 list; flagged PTR names (tunnels, paste, webhooks)' -Script {
        if (-not $ctx.Tor -and -not $ctx.Feodo) { Set-BvsCheckStatus -Id 'conn.intel_match' -Status partial -Reason 'no intel lists loaded; PTR name check only' }
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @($epAgg.Values | Where-Object { $_.Class -eq 'public' })) {
            $p = Get-S07ConnProc -ProcId $e.Pid
            if ($ctx.Feodo -and $ctx.Feodo.Map.ContainsKey($e.Remote)) {
                $f = $ctx.Feodo.Map[$e.Remote]
                New-BvsFinding -Run $run -Check 'conn.intel_match' -Title "$($p.Name) connected to a Feodo Tracker botnet C2 address $($e.Remote):$($e.RemotePort) ($($f.Malware))" -Severity high -Class suspicious -Confidence medium `
                    -Reasons @('intel_match', 'public_network') -Evidence @(@{ type = 'connection'; remote = $e.Remote; port = $e.RemotePort; ptr = $ptr[$e.Remote]; samplesSeen = $e.Samples.Count }, @{ type = 'intel'; source = 'feodotracker.abuse.ch'; malware = $f.Malware; status = $f.Status; lastOnline = $f.LastOnline }) `
                    -Entities @{ processes = @(New-S07ProcEntity -ProcId $p.Pid -Name $p.Name -Path $p.Path -Trust $p.Trust -Services $p.Services) } `
                    -FpNotes 'C2 IPs on shared hosting are sometimes reused by legitimate sites after takedown.' `
                    -Recommendation 'Disconnect from the network, identify the process and its file, and run a full offline AV scan.' -Mitre @('T1071.001')
                $out.Add($e)
            }
            if ($ctx.Tor -and $ctx.Tor.Set.Contains($e.Remote)) {
                New-BvsFinding -Run $run -Check 'conn.intel_match' -Title "$($p.Name) connected to Tor exit relay $($e.Remote):$($e.RemotePort)" -Severity medium -Class suspicious -Confidence low `
                    -Reasons @('intel_match', 'public_network') -Evidence @(@{ type = 'connection'; remote = $e.Remote; port = $e.RemotePort; ptr = $ptr[$e.Remote] }, @{ type = 'intel'; source = 'check.torproject.org/torbulkexitlist' }) `
                    -Entities @{ processes = @(New-S07ProcEntity -ProcId $p.Pid -Name $p.Name -Path $p.Path -Trust $p.Trust -Services $p.Services) } `
                    -FpNotes 'Tor Browser or Tor-routed tools you run yourself; relays also host normal services.' `
                    -Recommendation 'If you do not use Tor, identify and remove the program.' -Mitre @('T1090.003')
                $out.Add($e)
            }
        }
        $ptrFlags = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @($epAgg.Values | Where-Object { $_.Class -eq 'public' -and $ptr[$_.Remote] })) {
            foreach ($f in @(Get-S07DnsFlags -Name $ptr[$e.Remote] -ServicesOnly)) { $ptrFlags.Add([pscustomobject]@{ E = $e; F = $f }) }
        }
        foreach ($g in @($ptrFlags | Group-Object { $_.F.Cat })) {
            $first = $g.Group[0]
            $p = Get-S07ConnProc -ProcId $first.E.Pid
            New-BvsFinding -Run $run -Check 'conn.intel_match' -Title "Live connection(s) to $($g.Name) infrastructure (by reverse DNS): $(@($g.Group | ForEach-Object { $ptr[$_.E.Remote] } | Sort-Object -Unique | Select-Object -First 4) -join ', ')" -Severity $(if (Test-S07Untrusted $p.Trust) { 'medium' } else { 'low' }) -Class suspicious -Confidence low `
                -Evidence @($g.Group | Select-Object -First 8 | ForEach-Object { $pp = Get-S07ConnProc -ProcId $_.E.Pid; @{ type = 'connection'; process = $pp.Name; remote = $_.E.Remote; port = $_.E.RemotePort; ptr = $ptr[$_.E.Remote] } }) `
                -FpNotes 'You may be using these services yourself (ngrok agent, a paste link in the browser).' `
                -Recommendation 'Confirm which program holds the connection and that you started it.' -Mitre @($(if ($first.F.Mitre) { $first.F.Mitre }) | Where-Object { $_ })
            $out.Add($g)
        }
        @($out)
    })

#endregion

#region ---------- finish ----------

Add-BvsInventory -Run $run -Name 'questionsForUser' -Data @($questions)
$sum = Complete-BvsRun -Run $run

$statusCounts = ($run.Checks | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("S07 network: $($sum.Path)")
$lines.Add("findings: $($sum.Findings) [$($sum.BySeverity)] | checks: $($sum.Checks) [$statusCounts] | errors: $($sum.Errors)")
foreach ($f in @($run.Findings | Sort-Object { $script:SevRank[$_.severity] } -Descending | Select-Object -First 18)) { $lines.Add(('  [{0}/{1}] {2}' -f $f.severity, $f.class, $f.title)) }
foreach ($c in @($run.Checks | Where-Object { $_.status -notin 'ok' } | Select-Object -First 12)) { $lines.Add(('  check {0}: {1}{2}' -f $c.id, $c.status, $(if ($c.reason) { " - $($c.reason)" } else { '' }))) }
$lines | ForEach-Object { Protect-BvsText $_ }

#endregion
