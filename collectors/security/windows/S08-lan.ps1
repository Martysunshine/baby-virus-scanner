#Requires -Version 7.2
<#
.SYNOPSIS
    S08 - LAN device discovery: which devices share this PC's network, and which ports the router
    forwards to them. Read-only and consent-gated.

.DESCRIPTION
    Area     : security (module S08). Contract: docs\schema.md. Rules: docs\agent-rules.md.
    Playbook : docs\playbooks\S08-lan.md (methodology, heuristics, false positives, Linux equivalent).

    Order of work (each step is one Invoke-BvsCheck, so coverage is reported per step)
      1. lan.interface        pick the adapter holding the IPv4 default route (VPN/virtual adapters
                              excluded), derive the subnet, apply the consent gates
      2. lan.arp_passive      read the ARP cache before sending anything
      3. lan.ping_sweep       ICMP echo to every host address (System.Net.NetworkInformation.Ping,
                              ForEach-Object -Parallel)
      4. lan.arp_after_sweep  re-read the ARP cache: MACs, plus hosts that drop ICMP
      5. lan.ssdp             SSDP M-SEARCH (IGD:1 and ssdp:all) -> responders and LOCATION URLs
      6. lan.upnp_stack       SSDP SERVER banners vs known-vulnerable libupnp / MiniUPnPd releases
      7. lan.names_mdns       mDNS legacy-unicast queries: reverse PTR per host + DNS-SD service list
      8. lan.late_ping        one ping to hosts first seen via SSDP/mDNS (so ARP learns their MAC)
      9. lan.names_ptr        reverse DNS asked to the router (Resolve-DnsName -Server <gateway>)
     10. lan.names_netbios    NetBIOS node status (nbtstat -A <ip>)
     11. lan.vendor_oui       IEEE MA-L vendor list (cached under intel\), randomized-MAC detection
     12. lan.router_http      one GET of http://<gateway>/ : the <title> only
     13. lan.upnp_igd         IGD description XML, then GetGenericPortMappingEntry 0..n (read-only SOAP)
     14. lan.upnp_com         fallback: HNetCfg.NATUPnP StaticPortMappingCollection (enumeration only)
     15. lan.device_identify  merge all sources, guess each device type, census finding
     16. lan.upnp_assess      rate every port-forward (sensitive port on this PC = high, ...)
     17. lan.arp_anomalies    one MAC on several IPs (gateway involved = possible ARP spoofing)
     18. lan.untrusted_text   prompt-injection screen of every string read from other devices

    Passive by default. Without -Active nothing is sent to the network: only this PC's ARP cache is
    read and the active steps are recorded as skipped. Pass -Active only after the user has agreed to
    device discovery on the network they are connected to (bvs.ps1 scan -Lan does this).

    Network gates for -Active. All must hold, otherwise only passive steps run and active steps are
    recorded as skipped with the reason: IPv4 default route on a non-virtual adapter; RFC1918 address
    and gateway; prefix /22 or longer; network profile Private (Public and DomainAuthenticated are
    refused).

    Never: port scans, logins, form posts, state-changing UPnP actions (AddPortMapping,
    DeletePortMapping, ...), ARP cache changes, configuration changes of any kind.

    Output : data\<scanId>\security\S08.json (bvs.module/1, masked by Complete-BvsRun)
    Cache  : intel\standards-oui.ieee.org\*-oui.csv (refreshed after -OuiMaxAgeDays)
    Evidence: intel\<gateway-ip>\* (router start page, UPnP description, SOAP answers)

.PARAMETER Active
    Run the active steps too: ping sweep of the local subnet, name lookups, one GET of the router's
    start page, SSDP discovery and read-only UPnP queries. Requires the user's consent.
.PARAMETER PassiveOnly
    Send nothing to the LAN. Only the ARP cache is read (plus the IEEE vendor list download). This is
    the default; the switch is kept so existing commands still work, and it wins over -Active.
.PARAMETER OuiMaxAgeDays
    Re-download the IEEE OUI list when the cached copy is older than this.
.PARAMETER PingTimeoutMs
    ICMP echo timeout per attempt.
.PARAMETER PingAttempts
    Echo attempts per address (the next attempt is only sent if the previous one failed).
.PARAMETER ThrottleLimit
    Parallel pings.

.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S08-lan.ps1
.EXAMPLE
    pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S08-lan.ps1 -Active
#>
[CmdletBinding()]
param(
    # Named AllowActive internally because the script keeps its own $script:Active state.
    [Alias('Active')][switch]$AllowActive,
    [switch]$PassiveOnly,
    [ValidateRange(1, 365)][int]$OuiMaxAgeDays = 30,
    [ValidateRange(200, 3000)][int]$PingTimeoutMs = 1000,
    [ValidateRange(1, 3)][int]$PingAttempts = 2,
    [ValidateRange(1, 128)][int]$ThrottleLimit = 64
)

$ErrorActionPreference = 'Stop'
# Passive unless the caller asks for active discovery. Everything below keys on $PassiveOnly.
if (-not $AllowActive) { $PassiveOnly = $true }
# Process-local, no system change: invariant culture keeps this collector's own date and number
# formatting independent of the Windows display language.
[System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
Import-Module (Join-Path $PSScriptRoot '..\..\..\lib\windows\BVS.Common.psm1') -Force
$run = Initialize-BvsRun -Module S08 -Area security

#region ---------- generic knowledge (not machine-specific) ----------

# Ports that should never be reachable from the internet through a UPnP forward to this PC.
$script:SensitivePorts = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'; 80 = 'HTTP'; 110 = 'POP3'; 135 = 'MS-RPC'
    137 = 'NetBIOS-NS'; 138 = 'NetBIOS-DGM'; 139 = 'NetBIOS-SSN'; 143 = 'IMAP'; 443 = 'HTTPS'; 445 = 'SMB'
    1433 = 'MS-SQL'; 1900 = 'SSDP'; 2375 = 'Docker API'; 2376 = 'Docker API (TLS)'; 3306 = 'MySQL'; 3389 = 'RDP'
    5000 = 'dev HTTP'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5901 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM (TLS)'
    6379 = 'Redis'; 8000 = 'dev HTTP'; 8080 = 'HTTP-alt'; 8443 = 'HTTPS-alt'; 8888 = 'dev HTTP/Jupyter'
    9200 = 'Elasticsearch'; 11434 = 'Ollama API'; 27017 = 'MongoDB'
}
# Remote-admin, file-sharing and database ports: high on ANY device when forwarded.
$script:CriticalPorts = @(22, 23, 135, 139, 445, 1433, 2375, 2376, 3306, 3389, 5432, 5900, 5901, 5985, 5986, 6379, 9200, 11434, 27017)

# Applications known to request UPnP forwards for legitimate reasons.
$script:KnownApps = @(
    [pscustomobject]@{ Name = 'Tailscale direct connections'; Proto = 'UDP'; Ports = @(41641); Rx = '(?i)tailscale'; ConsoleOnly = $false }
    [pscustomobject]@{ Name = 'Xbox network'; Proto = 'ANY'; Ports = @(3074); Rx = '(?i)xbox|teredo'; ConsoleOnly = $true }
    [pscustomobject]@{ Name = 'PlayStation Network'; Proto = 'ANY'; Ports = @(3478, 3479, 3480, 3658) + (9295..9304); Rx = '(?i)playstation|\bps[345]\b|\bpsn\b'; ConsoleOnly = $true }
    [pscustomobject]@{ Name = 'Nintendo Switch'; Proto = 'ANY'; Ports = @(); Rx = '(?i)nintendo'; ConsoleOnly = $true }
    [pscustomobject]@{ Name = 'Steam'; Proto = 'ANY'; Ports = (27015..27030) + @(27036, 27037); Rx = '(?i)\bsteam\b'; ConsoleOnly = $false }
)
$script:ConsoleVendorRx = '(?i)sony interactive|nintendo|microsoft'

# Device type signals: source (vendor | name | mdns | ssdp), type, points, regex. Best score >= 3 wins.
$script:TypeSignals = @(
    @('vendor', 'router', 3, '(?i)\b(askey|arcadyan|sagemcom|technicolor|vantiva|avm|sercomm|mitrastar|compal broadband|ubiquiti|mikrotik|routerboard|netgear|zyxel|d-link|linksys|eero|plume design|tenda|mercusys|fiberhome|nokia shanghai bell|ruckus|aruba|draytek|lancom|devolo)\b'),
    @('vendor', 'router', 1, '(?i)\b(tp-link|huawei technologies|zte|asustek|cisco)\b'),
    @('vendor', 'printer', 5, '(?i)\b(seiko epson|epson|canon|brother industries|kyocera|lexmark|xerox|ricoh|konica minolta|oki electric|pantum)\b'),
    @('vendor', 'printer', 2, '(?i)\b(hewlett|hp inc)\b'),
    @('vendor', 'TV/streamer', 3, '(?i)\b(lg electronics|lg innotek|tcl|hisense|roku|vestel|tp vision|vizio|skyworth|sony interactive|nintendo|nvidia)\b'),
    @('vendor', 'TV/streamer', 1, '(?i)\b(samsung electronics|sony|panasonic|sharp|philips|amazon technologies|google|apple|xiaomi)\b'),
    @('vendor', 'IoT', 4, '(?i)\b(espressif|tuya|shelly|allterco|itead|signify|philips lighting|lifi labs|sonos|ecovacs|roborock|dreame|ezviz|hikvision|dahua|reolink|wyze|ring llc|nest labs|lumi united|aqara|netatmo|tado|eq-3|govee|meross|leedarson|bouffalo|beken|wiz connected|ikea)\b'),
    @('vendor', 'IoT', 1, '(?i)\b(amazon technologies|xiaomi|murata|silicon lab|texas instruments|nordic semiconductor|raspberry pi|azurewave|universal global scientific)\b'),
    @('vendor', 'phone/tablet', 2, '(?i)\b(oneplus|oppo|vivo mobile|realme|motorola mobility|hmd global|fairphone|honor device|huawei device)\b'),
    @('vendor', 'phone/tablet', 1, '(?i)\b(apple|samsung electronics|xiaomi|google|huawei)\b'),
    @('vendor', 'laptop/PC', 3, '(?i)\b(intel corporate|liteon|lite-on|hon hai|cloud network technology|dell|micro-star|gigabyte|chicony|quanta|wistron|pegatron|compal information|framework computer|razer|clevo)\b'),
    @('vendor', 'laptop/PC', 1, '(?i)\b(asustek|lenovo|hewlett|acer|realtek|azurewave|microsoft|apple|toshiba|dynabook|fujitsu)\b'),
    @('name', 'router', 5, '(?i)router|gateway|homebox|fritz|speedport|repeater|extender|access-?point|\bdeco\b|\borbi\b|\beero\b|\bmesh\b'),
    @('name', 'printer', 6, '(?i)epson|^hp[0-9a-f]{6}|officejet|deskjet|laserjet|^brn|^brw|canon|printer|\bmfc-|ecotank|xerox|kyocera'),
    @('name', 'TV/streamer', 5, '(?i)\btv\b|[-_]tv|tv[-_]|chromecast|\broku|fire-?tv|apple-?tv|bravia|webos|tizen|android-?tv|\bshield\b|smart-?tv|\bkodi\b|playstation|\bps[345]\b|xbox|nintendo'),
    @('name', 'IoT', 4, '(?i)\besp[-_]|espressif|tasmota|shelly|sonoff|tuya|smart-?plug|\bplug\b|\bbulb\b|\bhue\b|\becho\b|alexa|\bnest\b|google-?home|\bring\b|camera|ipcam|doorbell|vacuum|roborock|roomba|thermostat|sonos|speaker|homepod|\bwled\b|zigbee'),
    @('name', 'phone/tablet', 5, '(?i)iphone|ipad|android|galaxy|\bsm-[a-z]\d|pixel|redmi|xiaomi|\bpoco|huawei|honor|oneplus|oppo|vivo|realme|\bmoto|nokia|phone|tablet'),
    @('name', 'laptop/PC', 5, '(?i)desktop-|laptop-|macbook|imac|mac-?mini|mac-?pro|\bmac\b|\bpc\b|-pc\b|^pc-|thinkpad|surface|notebook|workstation|ubuntu|debian|fedora|\bkali\b|archlinux'),
    @('mdns', 'printer', 6, '(?i)_(ipp|ipps|printer|pdl-datastream|scanner|uscan|uscans|privet|fax-ipp)\._tcp'),
    @('mdns', 'TV/streamer', 5, '(?i)_(googlecast|androidtvremote2?|amzn-wplay|nvstream|roku|mediaremotetv|viziocast|dial)\._tcp'),
    @('mdns', 'TV/streamer', 2, '(?i)_(airplay|raop|spotify-connect)\._tcp'),
    @('mdns', 'IoT', 5, '(?i)_(hap|hue|esphomelib|shelly|sonos|miio|aqara|elg|matter)\._(tcp|udp)|_matterc\._udp'),
    @('mdns', 'phone/tablet', 5, '(?i)_apple-mobdev2\._tcp'),
    @('mdns', 'phone/tablet', 1, '(?i)_companion-link\._tcp'),
    @('mdns', 'laptop/PC', 4, '(?i)_(workstation|smb|adisk|afpovertcp|rdlink)\._tcp'),
    @('mdns', 'laptop/PC', 2, '(?i)_(ssh|sftp-ssh|rfb)\._tcp'),
    @('ssdp', 'router', 6, '(?i)InternetGatewayDevice|WANDevice|WANConnectionDevice|WANIPConnection|WANPPPConnection'),
    @('ssdp', 'TV/streamer', 5, '(?i)dial-multiscreen-org|roku|tizen|webos|bravia|chromecast|android ?tv|fire ?os|smart ?tv'),
    @('ssdp', 'TV/streamer', 3, '(?i)MediaRenderer'),
    @('ssdp', 'printer', 5, '(?i)device:Printer|PrintBasic|device:Scanner|epson|brother|canon|hewlett|officejet|deskjet|laserjet'),
    @('ssdp', 'IoT', 4, '(?i)philips-hue|IpBridge|hue bridge|sonos|ZonePlayer|belkin|wemo|yeelight|shelly|hikvision|dahua|ezviz|miio|ecovacs|roborock|tuya'),
    @('ssdp', 'laptop/PC', 4, '(?i)Microsoft-Windows|Windows NT|Windows/\d')
)

# Text read from other devices is data. Instructions inside it are recorded, never followed.
$script:InjectionRx = [regex]::new('(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)|disregard\s+(all\s+|the\s+)?(previous|above|prior)|system\s+prompt|you\s+are\s+now\b|\bassistant\s*:|\b(run|execute)\s+(this|the\s+following)\b|powershell(\.exe)?\s+-|\b(curl|wget)\s+https?://|<script\b|rm\s+-rf\b|send\s+.{0,40}\s+to\s+https?://')

#endregion

#region ---------- helpers ----------

function ConvertTo-S08UInt32([Net.IPAddress]$Ip) {
    $b = $Ip.GetAddressBytes()
    [BitConverter]::ToUInt32([byte[]]@($b[3], $b[2], $b[1], $b[0]), 0)
}

function ConvertFrom-S08UInt32([uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Net.IPAddress]::new([byte[]]@($b[3], $b[2], $b[1], $b[0]))
}

function Test-S08Rfc1918([Net.IPAddress]$Ip) {
    if (-not $Ip -or $Ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $Ip.GetAddressBytes()
    ($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)
}

function Test-S08InLan([AllowNull()][string]$Ip) {
    # True for a host address (not network/broadcast) inside the selected LAN subnet.
    $obj = $null
    if (-not $script:Net -or -not $Ip -or -not [Net.IPAddress]::TryParse($Ip, [ref]$obj)) { return $false }
    if ($obj.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $u = ConvertTo-S08UInt32 $obj
    (($u -band $script:Net.MaskU32) -eq $script:Net.NetworkU32) -and $u -ne $script:Net.NetworkU32 -and $u -ne $script:Net.BroadcastU32
}

function Format-S08Mac([AllowNull()][string]$Mac) {
    if ([string]::IsNullOrWhiteSpace($Mac)) { return $null }
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12 -or $hex -eq '000000000000' -or $hex -eq 'FFFFFFFFFFFF') { return $null }
    [regex]::Replace($hex, '(..)(?!$)', '$1:')
}

function Test-S08RandomMac([AllowNull()][string]$Mac) {
    # Locally administered bit (0x02 of the first octet): second hex digit 2, 6, A or E.
    [bool]($Mac -and $Mac.Length -ge 2 -and '26AE'.Contains($Mac.Substring(1, 1).ToUpperInvariant()))
}

function Get-S08Text([AllowNull()][object]$Value, [int]$Max = 160) {
    # Untrusted text: strip control characters, collapse whitespace, cap the length.
    if ($null -eq $Value) { return $null }
    $t = [string]$Value
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    $t = [regex]::Replace($t, '[\x00-\x1F\x7F]+', ' ')
    $t = [regex]::Replace($t, '\s{2,}', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + [char]0x2026 }
    $t
}

function Get-S08ContentText($Response) {
    if ($null -eq $Response -or $null -eq $Response.Content) { return '' }
    if ($Response.Content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($Response.Content) }
    [string]$Response.Content
}

$script:Untrusted = [System.Collections.Generic.List[object]]::new()
function Add-S08Untrusted([string]$Source, [AllowNull()][string]$Ip, [AllowNull()][string]$Text) {
    if ($Text) { $script:Untrusted.Add([pscustomobject]@{ Source = $Source; Ip = $Ip; Text = $Text }) }
}

function ConvertTo-S08Xml([AllowNull()][string]$Text) {
    # Hardened XML parse for device-supplied documents: no DTD, no external resolution, size cap.
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 4000000
    $settings.IgnoreComments = $true
    $reader = [System.IO.StringReader]::new($Text.Trim().TrimStart([char]0xFEFF))
    try {
        $xr = [System.Xml.XmlReader]::Create($reader, $settings)
        try {
            $doc = [System.Xml.XmlDocument]::new()
            $doc.XmlResolver = $null
            $doc.Load($xr)
            , $doc
        }
        finally { $xr.Dispose() }
    }
    finally { $reader.Dispose() }
}

function Get-S08XmlValue($Node, [string]$Name, [switch]$Child) {
    # $Name is always a constant from this script (never device data), so the XPath is fixed.
    if ($null -eq $Node) { return $null }
    $xp = if ($Child) { "./*[local-name()='$Name']" } else { ".//*[local-name()='$Name']" }
    $n = $Node.SelectSingleNode($xp)
    if ($n) { $n.InnerText.Trim() }
}

function Test-S08LanUrl([AllowNull()][string]$Url, [string]$ExpectHost) {
    # Only http(s) URLs whose host is a LAN host address (and, if given, the expected responder).
    $u = $null
    if (-not $Url -or -not [uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $null }
    if ($u.Scheme -notin 'http', 'https') { return $null }
    if ($ExpectHost -and $u.Host -ne $ExpectHost) { return $null }
    if (-not (Test-S08InLan $u.Host)) { return $null }
    $u
}

function New-S08DnsQuery([int]$Id, [string]$Name, [int]$QType = 12) {
    # Plain DNS query packet (one question, class IN). Sent from an ephemeral port, an mDNS
    # responder answers it as a legacy unicast query (RFC 6762 6.7) straight back to us.
    $b = [System.Collections.Generic.List[byte]]::new()
    foreach ($v in @((($Id -shr 8) -band 0xFF), ($Id -band 0xFF), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)) { $b.Add([byte]$v) }
    foreach ($label in $Name.TrimEnd('.').Split('.')) {
        $lb = [Text.Encoding]::UTF8.GetBytes($label)
        if ($lb.Length -lt 1 -or $lb.Length -gt 63) { throw "bad DNS label in $Name" }
        $b.Add([byte]$lb.Length)
        $b.AddRange($lb)
    }
    $b.Add([byte]0)
    foreach ($v in @((($QType -shr 8) -band 0xFF), ($QType -band 0xFF), 0, 1)) { $b.Add([byte]$v) }
    , $b.ToArray()
}

function Read-S08DnsName([byte[]]$Packet, [int]$Offset) {
    # Bounds-checked DNS name decoder with compression pointers and a loop guard.
    $labels = [System.Collections.Generic.List[string]]::new()
    $pos = $Offset; $next = -1; $hops = 0
    while ($true) {
        if ($pos -ge $Packet.Length) { throw 'dns name out of range' }
        $len = [int]$Packet[$pos]
        if ($len -eq 0) { if ($next -lt 0) { $next = $pos + 1 }; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($pos + 1 -ge $Packet.Length) { throw 'dns pointer out of range' }
            if ($next -lt 0) { $next = $pos + 2 }
            $pos = (($len -band 0x3F) * 256) + [int]$Packet[$pos + 1]
            if (++$hops -gt 32) { throw 'dns pointer loop' }
            continue
        }
        if (($len -band 0xC0) -ne 0 -or ($pos + 1 + $len) -gt $Packet.Length) { throw 'dns bad label' }
        $labels.Add([Text.Encoding]::UTF8.GetString($Packet, $pos + 1, $len))
        if ($labels.Count -gt 40) { throw 'dns name too long' }
        $pos += 1 + $len
    }
    [pscustomobject]@{ Name = ($labels -join '.'); Next = $next }
}

function Read-S08DnsMessage([byte[]]$Packet) {
    # Returns A, PTR and SRV records (Name, Type, Data) from answer/authority/additional sections.
    if ($Packet.Length -lt 12) { return }
    $qd = [int]$Packet[4] * 256 + $Packet[5]
    $rr = ([int]$Packet[6] * 256 + $Packet[7]) + ([int]$Packet[8] * 256 + $Packet[9]) + ([int]$Packet[10] * 256 + $Packet[11])
    $pos = 12
    for ($i = 0; $i -lt [Math]::Min($qd, 64); $i++) { $pos = (Read-S08DnsName $Packet $pos).Next + 4 }
    for ($i = 0; $i -lt [Math]::Min($rr, 256); $i++) {
        $n = Read-S08DnsName $Packet $pos
        $pos = $n.Next
        if ($pos + 10 -gt $Packet.Length) { break }
        $type = [int]$Packet[$pos] * 256 + $Packet[$pos + 1]
        $rdLen = [int]$Packet[$pos + 8] * 256 + $Packet[$pos + 9]
        $rd = $pos + 10
        if ($rd + $rdLen -gt $Packet.Length) { break }
        $value = $null
        switch ($type) {
            1 { if ($rdLen -eq 4) { $value = '{0}.{1}.{2}.{3}' -f $Packet[$rd], $Packet[$rd + 1], $Packet[$rd + 2], $Packet[$rd + 3] } }
            12 { $value = (Read-S08DnsName $Packet $rd).Name }
            33 { if ($rdLen -gt 6) { $value = (Read-S08DnsName $Packet ($rd + 6)).Name } }
        }
        if ($null -ne $value) { [pscustomobject]@{ Name = $n.Name; Type = $type; Data = $value } }
        $pos = $rd + $rdLen
    }
}

function Get-S08Neighbors {
    # ARP cache of the LAN adapter: unicast entries inside the subnet that hold a MAC.
    try { $all = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $script:Net.IfIndex -ErrorAction Stop) }
    catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return }; throw }
    foreach ($n in $all) {
        if ([string]$n.State -in 'Unreachable', 'Incomplete') { continue }
        $mac = Format-S08Mac ([string]$n.LinkLayerAddress)
        if (-not $mac -or $mac.StartsWith('01:00:5E')) { continue }
        $ip = [string]$n.IPAddress
        if (-not (Test-S08InLan $ip)) { continue }
        [pscustomobject]@{ Ip = $ip; Mac = $mac; State = [string]$n.State }
    }
}

function Test-S08NbGroup($Entry, [AllowNull()][string]$GroupWord) {
    # NetBIOS GROUP vs UNIQUE without trusting the (possibly localized) type word alone.
    if ($GroupWord) { return $Entry.Type -eq $GroupWord }
    $Entry.Type -match '(?i)^GROUP'
}

function Get-S08PortOwner([int]$Port, [string]$Protocol) {
    # Local, read-only: which process on THIS PC holds the port a router forward points to.
    if ($Port -le 0) { return }
    $owners = if ($Protocol -eq 'UDP') {
        @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue | ForEach-Object OwningProcess)
    }
    else {
        @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | ForEach-Object OwningProcess)
    }
    foreach ($procId in @($owners | Select-Object -Unique)) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        [pscustomobject][ordered]@{ pid = [int]$procId; name = if ($p) { $p.ProcessName } else { $null } }
    }
}

$script:Devices = [ordered]@{}
function Get-S08Device([string]$Ip) {
    if (-not $script:Devices.Contains($Ip)) {
        $script:Devices[$Ip] = [pscustomobject][ordered]@{
            ip = $Ip; mac = $null; vendor = $null; randomizedMac = $false; hostname = $null
            ptr = [System.Collections.Generic.List[string]]::new(); netbios = $null; netbiosGroup = $null; netbiosServer = $false
            mdnsNames = [System.Collections.Generic.List[string]]::new(); mdnsServices = [System.Collections.Generic.List[string]]::new()
            mdnsInstances = [System.Collections.Generic.List[string]]::new()
            typeGuess = 'unknown'; typeConfidence = 'low'; typeReason = @()
            seenBy = [System.Collections.Generic.List[string]]::new(); answered = $false
            isGateway = $false; isThisPc = $false; arpState = $null; rttMs = $null; ttl = $null
            ssdp = $null; upnpMappings = 0
        }
    }
    $script:Devices[$Ip]
}

function Add-S08Unique($List, [AllowNull()][string]$Value, [int]$Max = 40) {
    if ($Value -and -not $List.Contains($Value) -and $List.Count -lt $Max) { $List.Add($Value) }
}

function Skip-S08Active([string]$Id) {
    # 'skipped' in both cases: across the product, needs_consent means "waiting for a sign-in" (dashboard wording).
    $status = if (-not $script:Net) { 'not_applicable' } else { 'skipped' }
    Set-BvsCheckStatus -Id $Id -Status $status -Reason $script:Refusal
}

function Get-S08TypeGuess($Device) {
    if ($Device.isThisPc) { return [pscustomobject]@{ Type = 'laptop/PC'; Confidence = 'high'; Reason = @('this PC') } }
    $score = [ordered]@{ 'router' = 0; 'printer' = 0; 'TV/streamer' = 0; 'IoT' = 0; 'phone/tablet' = 0; 'laptop/PC' = 0 }
    $why = @{}
    foreach ($k in @($score.Keys)) { $why[$k] = [System.Collections.Generic.List[string]]::new() }
    $ssdpText = ''
    if ($Device.ssdp) { $ssdpText = (@($Device.ssdp.servers) + @($Device.ssdp.searchTargets) + @($Device.ssdp.friendlyName, $Device.ssdp.manufacturer, $Device.ssdp.modelName)) -join ' ' }
    $text = @{
        vendor = [string]$Device.vendor
        name   = (@($Device.hostname, $Device.netbios) + @($Device.ptr) + @($Device.mdnsNames) + @($Device.mdnsInstances) | Where-Object { $_ }) -join ' '
        mdns   = (@($Device.mdnsServices) -join ' ')
        ssdp   = $ssdpText
    }
    foreach ($s in $script:TypeSignals) {
        $src = [string]$s[0]
        if ($text[$src] -and ([string]$text[$src] -match $s[3])) {
            $score[$s[1]] += [int]$s[2]
            $why[$s[1]].Add("$src '$($Matches[0])'")
        }
    }
    if ($Device.isGateway) { $score['router'] += 10; $why['router'].Add('default gateway') }
    if ($Device.randomizedMac) { $score['phone/tablet'] += 3; $why['phone/tablet'].Add('randomized MAC') }
    if ($Device.ttl -eq 128) { $score['laptop/PC'] += 2; $why['laptop/PC'].Add('ICMP TTL 128 (Windows)') }
    if ($Device.netbios) { $score['laptop/PC'] += 2; $why['laptop/PC'].Add('answers NetBIOS') }
    if ($Device.netbiosServer) { $score['laptop/PC'] += 2; $why['laptop/PC'].Add('NetBIOS file-server name <20>') }
    $best = @($score.GetEnumerator()) | Sort-Object -Property Value -Descending -Stable | Select-Object -First 1
    if ($best.Value -lt 3) {
        $hints = @($score.GetEnumerator() | Where-Object Value -gt 0 | ForEach-Object { $why[$_.Key] } | Select-Object -First 3)
        return [pscustomobject]@{ Type = 'unknown'; Confidence = 'low'; Reason = if ($hints) { @('weak signals only:') + $hints } else { @('no identifying signal') } }
    }
    $conf = if ($best.Value -ge 8) { 'high' } elseif ($best.Value -ge 5) { 'medium' } else { 'low' }
    [pscustomobject]@{ Type = $best.Key; Confidence = $conf; Reason = @($why[$best.Key] | Select-Object -First 4) }
}

function Get-S08ExpectedForHost($Device) {
    # Machine-specific known names (config\local\expected.json, category hosts), e.g. Tailscale peers.
    $full = @(@($Device.hostname, $Device.netbios) + @($Device.ptr) + @($Device.mdnsNames) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    if (-not $full.Count) { return $null }
    $short = @($full | ForEach-Object { ($_ -split '\.')[0] } | Select-Object -Unique)
    foreach ($e in @(Get-BvsExpected -Category 'hosts')) {
        $list = @(@($e.match.hostnames) + @($e.match.hostname) | Where-Object { $_ } | ForEach-Object { (([string]$_) -split '\.')[0].ToLowerInvariant() })
        $rx = [string]$e.match.hostnameRegex
        $hit = @($short | Where-Object { $list -contains $_ }) + @($full | Where-Object { $rx -and $_ -match $rx }) | Select-Object -First 1
        if ($hit) { return [ordered]@{ id = $e.id; matched = $hit; reason = $e.reason; confirmWithUser = [bool]$e.confirmWithUser } }
    }
    $null
}

function Get-S08KnownApp($Mapping, $Device) {
    foreach ($a in $script:KnownApps) {
        if ($Mapping.description -and $Mapping.description -match $a.Rx) { return $a.Name }
        $protoOk = $a.Proto -eq 'ANY' -or $a.Proto -eq $Mapping.protocol
        $portOk = $protoOk -and (($a.Ports -contains $Mapping.internalPort) -or ($a.Ports -contains $Mapping.externalPort))
        if (-not $portOk) { continue }
        if (-not $a.ConsoleOnly) { return $a.Name }
        if ($Device -and (([string]$Device.vendor -match $script:ConsoleVendorRx) -or $Device.typeGuess -eq 'TV/streamer')) { return $a.Name }
    }
    $null
}

function Get-S08ExpectedForMapping($Mapping, $Owners) {
    # Machine-specific known-good items (config\local\expected.json, category network): a forward
    # to this PC matches when the item's service owns the port or the item's name is in the description.
    foreach ($e in @(Get-BvsExpected -Category 'network')) {
        $svcName = [string]$e.match.service
        $label = if ($e.match.adapter) { [string]$e.match.adapter } elseif ($svcName) { $svcName } else { $null }
        $hit = $false
        if ($svcName -match '^[A-Za-z0-9_.-]{1,64}$' -and @($Owners).Count) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
            if ($svc -and $svc.ProcessId -and (@($Owners | ForEach-Object pid) -contains [int]$svc.ProcessId)) { $hit = $true }
        }
        if (-not $hit -and $label -and $Mapping.description -and $Mapping.description -match [regex]::Escape($label)) { $hit = $true }
        if ($hit) { return [ordered]@{ id = $e.id; reason = $e.reason; invalidIf = @($e.invalidIf) } }
    }
    $null
}

#endregion

#region ---------- 1. interface and consent gates ----------

$script:Net = $null
$script:Active = $false
$script:Refusal = $null

$script:Net = Invoke-BvsCheck -Run $run -Id 'lan.interface' -Description 'Adapter holding the IPv4 default route (VPN/virtual excluded); subnet; consent gates (RFC1918, prefix >= /22, profile Private)' -Script {
    $virtual = '(?i)tailscale|virtualbox|vmware|hyper-v|vethernet|\bwsl\b|wintun|wireguard|tap-windows|\btap\b|openvpn|zerotier|npcap|loopback|anyconnect|fortinet|forticlient|globalprotect|pangp|nordlynx|mullvad|proton|warp|docker'
    $cands = foreach ($r in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        $ad = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
        if (-not $ad -or [string]$ad.Status -ne 'Up') { continue }
        if ("$($ad.Name) $($ad.InterfaceDescription)" -match $virtual) { continue }
        $addr = @(Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.PrefixOrigin -ne 'WellKnown' -and [string]$_.AddressState -eq 'Preferred' }) | Select-Object -First 1
        if (-not $addr) { continue }
        $ifMetric = (Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
        [pscustomobject]@{ Route = $r; Adapter = $ad; Addr = $addr; Metric = [int]$r.RouteMetric + [int]$ifMetric }
    }
    $pick = @($cands) | Sort-Object Metric | Select-Object -First 1
    if (-not $pick) {
        Set-BvsCheckStatus -Id 'lan.interface' -Status 'not_applicable' -Reason 'No physical adapter holds an IPv4 default route (offline or VPN-only).'
        return
    }
    $ip = [Net.IPAddress]::Parse([string]$pick.Addr.IPAddress)
    $prefix = [int]$pick.Addr.PrefixLength
    $size = [uint64]1 -shl (32 - [Math]::Min([Math]::Max($prefix, 0), 32))
    $mask = [uint32]([uint64]4294967296 - $size)
    $ipU = ConvertTo-S08UInt32 $ip
    $netU = [uint32]($ipU -band $mask)
    $bcU = [uint32]([uint64]$netU + $size - 1)
    $gwText = [string]$pick.Route.NextHop
    $gw = $null
    [void][Net.IPAddress]::TryParse($gwText, [ref]$gw)
    $prof = Get-NetConnectionProfile -InterfaceIndex $pick.Adapter.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
    $category = if ($prof) { [string]$prof.NetworkCategory } else { 'Unknown' }

    $refuse = [System.Collections.Generic.List[string]]::new()
    if ($prefix -lt 22) { $refuse.Add("prefix /$prefix is broader than /22") }
    if ($prefix -gt 30) { $refuse.Add("prefix /$prefix leaves no other hosts") }
    if ($category -eq 'Public') { $refuse.Add('network profile is Public') }
    elseif ($category -eq 'DomainAuthenticated') { $refuse.Add('network profile is DomainAuthenticated (managed network)') }
    elseif ($category -ne 'Private') { $refuse.Add("network profile is $category") }
    if (-not (Test-S08Rfc1918 $ip)) { $refuse.Add('local address is not RFC1918') }
    if (-not $gw -or -not (Test-S08Rfc1918 $gw)) { $refuse.Add('gateway is not an RFC1918 address') }

    [pscustomobject][ordered]@{
        IfIndex      = [int]$pick.Adapter.ifIndex
        Alias        = [string]$pick.Adapter.Name
        Description  = [string]$pick.Adapter.InterfaceDescription
        MediaType    = [string]$pick.Adapter.PhysicalMediaType
        Mac          = Format-S08Mac ([string]$pick.Adapter.MacAddress)
        LocalIp      = $ip.ToString()
        Prefix       = $prefix
        Subnet       = "$(ConvertFrom-S08UInt32 $netU)/$prefix"
        Gateway      = $gwText
        ProfileName  = if ($prof) { [string]$prof.Name } else { $null }
        Category     = $category
        NetworkU32   = $netU
        MaskU32      = $mask
        BroadcastU32 = $bcU
        LocalU32     = $ipU
        HostCount    = [int][Math]::Max([double]$size - 2, 0)
        SweepAllowed = ($refuse.Count -eq 0)
        Refusal      = ($refuse -join '; ')
    }
}

if ($script:Net) {
    $script:Active = $script:Net.SweepAllowed -and -not $PassiveOnly
    $script:Refusal = if ($PassiveOnly) { 'passive mode: nothing is sent to the LAN. Active discovery needs the user''s consent (-Active, or bvs.ps1 scan -Lan)' }
    elseif (-not $script:Net.SweepAllowed) { "consent gate refused active discovery: $($script:Net.Refusal)" }
    else { $null }
    Write-BvsLog -Run $run -Message ("lan: if={0} ip={1} subnet={2} gw={3} profile={4} active={5} {6}" -f $script:Net.Alias, $script:Net.LocalIp, $script:Net.Subnet, $script:Net.Gateway, $script:Net.Category, $script:Active, $script:Refusal)
    $me = Get-S08Device $script:Net.LocalIp
    $me.isThisPc = $true; $me.mac = $script:Net.Mac; $me.hostname = $env:COMPUTERNAME; $me.answered = $true
    $me.seenBy.Add('self')
    if (Test-S08InLan $script:Net.Gateway) { (Get-S08Device $script:Net.Gateway).isGateway = $true }
}
else {
    $script:Refusal = 'no LAN adapter with an IPv4 default route'
}

#endregion

#region ---------- 2-4. ARP cache, ping sweep, ARP re-read ----------

$arpBefore = @(Invoke-BvsCheck -Run $run -Id 'lan.arp_passive' -Description 'IPv4 neighbour (ARP) cache of the LAN adapter, read before any probe' -Script {
        if (-not $script:Net) { Set-BvsCheckStatus -Id 'lan.arp_passive' -Status 'not_applicable' -Reason $script:Refusal; return }
        Get-S08Neighbors
    }).Where({ $null -ne $_ })
foreach ($n in $arpBefore) {
    $d = Get-S08Device $n.Ip
    $d.mac = $n.Mac; $d.arpState = $n.State
    Add-S08Unique $d.seenBy 'arp'
}
$gwMacBefore = if ($script:Net -and $script:Devices.Contains($script:Net.Gateway)) { $script:Devices[$script:Net.Gateway].mac } else { $null }

$pingAlive = @(Invoke-BvsCheck -Run $run -Id 'lan.ping_sweep' -Description "ICMP echo to every host address of the LAN subnet ($PingTimeoutMs ms timeout, up to $PingAttempts attempts, $ThrottleLimit parallel)" -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.ping_sweep'; return }
        $targets = [System.Collections.Generic.List[string]]::new()
        for ($u = [uint64]$script:Net.NetworkU32 + 1; $u -lt [uint64]$script:Net.BroadcastU32; $u++) {
            if ($u -ne [uint64]$script:Net.LocalU32) { $targets.Add((ConvertFrom-S08UInt32 ([uint32]$u)).ToString()) }
        }
        $timeout = $PingTimeoutMs
        $attempts = $PingAttempts
        $targets | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $pinger = [System.Net.NetworkInformation.Ping]::new()
            try {
                for ($i = 1; $i -le $using:attempts; $i++) {
                    try {
                        $reply = $pinger.Send($_, $using:timeout)
                        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                            [pscustomobject]@{ Ip = $_; RttMs = [int]$reply.RoundtripTime; Ttl = if ($reply.Options) { [int]$reply.Options.Ttl } else { $null }; Attempt = $i }
                            break
                        }
                    }
                    catch { }
                }
            }
            finally { $pinger.Dispose() }
        }
    }).Where({ $null -ne $_ })
foreach ($p in $pingAlive) {
    $d = Get-S08Device $p.Ip
    $d.rttMs = $p.RttMs; $d.ttl = $p.Ttl; $d.answered = $true
    Add-S08Unique $d.seenBy 'ping'
}

$arpAfter = @(Invoke-BvsCheck -Run $run -Id 'lan.arp_after_sweep' -Description 'ARP cache re-read after the sweep: MACs, plus hosts that answer ARP but drop ICMP' -Script {
        if (-not $script:Net) { Set-BvsCheckStatus -Id 'lan.arp_after_sweep' -Status 'not_applicable' -Reason $script:Refusal; return }
        if (-not $script:Active) { Set-BvsCheckStatus -Id 'lan.arp_after_sweep' -Status 'skipped' -Reason 'no sweep was sent; the passive read is the only ARP view'; return }
        Get-S08Neighbors
    }).Where({ $null -ne $_ })
foreach ($n in $arpAfter) {
    $d = Get-S08Device $n.Ip
    $d.mac = $n.Mac; $d.arpState = $n.State
    if ($n.State -in 'Reachable', 'Delay', 'Probe', 'Permanent') { $d.answered = $true }
    Add-S08Unique $d.seenBy 'arp'
}
Write-BvsLog -Run $run -Message "sweep: arpBefore=$($arpBefore.Count) pingAlive=$($pingAlive.Count) arpAfter=$($arpAfter.Count)"

#endregion

#region ---------- 5. SSDP ----------

$ssdpRaw = @(Invoke-BvsCheck -Run $run -Id 'lan.ssdp' -Description 'SSDP M-SEARCH to 239.255.255.250:1900 (ST InternetGatewayDevice:1 and ssdp:all, sent twice), ~3 s listen' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.ssdp'; return }
        $local = [Net.IPAddress]::Parse($script:Net.LocalIp)
        $udp = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new($local, 0))
        try {
            $udp.MulticastLoopback = $false
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $local.GetAddressBytes())
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 2)
            $udp.Client.ReceiveTimeout = 200
            $dest = [System.Net.IPEndPoint]::new([Net.IPAddress]::Parse('239.255.255.250'), 1900)
            foreach ($round in 1..2) {
                foreach ($st in 'urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'ssdp:all') {
                    $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: $st`r`nUSER-AGENT: Windows/10.0 UPnP/1.1 baby-virus-scanner/0.1`r`n`r`n"
                    $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
                    [void]$udp.Send($bytes, $bytes.Length, $dest)
                }
                Start-Sleep -Milliseconds 100
            }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($sw.ElapsedMilliseconds -lt 3200) {
                $remote = [System.Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
                try { $packet = $udp.Receive([ref]$remote) } catch { continue }
                if ($packet.Length -gt 8192) { continue }
                $text = [Text.Encoding]::UTF8.GetString($packet)
                if ($text -notmatch '^HTTP/1\.[01]\s+200') { continue }
                $h = @{}
                foreach ($line in ($text -split "`r?`n")) {
                    $i = $line.IndexOf(':')
                    if ($i -gt 0) {
                        $k = $line.Substring(0, $i).Trim().ToUpperInvariant()
                        if (-not $h.ContainsKey($k)) { $h[$k] = $line.Substring($i + 1).Trim() }
                    }
                }
                [pscustomobject]@{ Ip = $remote.Address.ToString(); St = $h['ST']; Usn = $h['USN']; Location = $h['LOCATION']; Server = $h['SERVER'] }
            }
        }
        finally { $udp.Dispose() }
    }).Where({ $null -ne $_ })

$script:SsdpByIp = [ordered]@{}
foreach ($r in $ssdpRaw) {
    if (-not $script:SsdpByIp.Contains($r.Ip)) {
        $script:SsdpByIp[$r.Ip] = [pscustomobject][ordered]@{
            ip = $r.Ip; inLan = (Test-S08InLan $r.Ip)
            servers = [System.Collections.Generic.List[string]]::new(); searchTargets = [System.Collections.Generic.List[string]]::new()
            usns = [System.Collections.Generic.List[string]]::new(); locations = [System.Collections.Generic.List[string]]::new()
            described = $false; friendlyName = $null; manufacturer = $null; modelName = $null; modelNumber = $null; deviceType = $null
        }
    }
    $g = $script:SsdpByIp[$r.Ip]
    $server = Get-S08Text $r.Server 200
    Add-S08Unique $g.servers $server 5
    Add-S08Unique $g.searchTargets (Get-S08Text $r.St 160) 40
    if ($r.Usn) { Add-S08Unique $g.usns (Get-S08Text (($r.Usn -split '::')[0]) 80) 10 }
    if ($r.Location) { Add-S08Unique $g.locations (Get-S08Text $r.Location 300) 10 }
    Add-S08Untrusted 'ssdp.server' $r.Ip $server
}
foreach ($g in $script:SsdpByIp.Values) {
    if (-not $g.inLan) { continue }
    $d = Get-S08Device $g.ip
    $d.ssdp = $g; $d.answered = $true
    Add-S08Unique $d.seenBy 'ssdp'
}
Write-BvsLog -Run $run -Message "ssdp: responses=$($ssdpRaw.Count) responders=$($script:SsdpByIp.Count)"

$stackRows = @(Invoke-BvsCheck -Run $run -Id 'lan.upnp_stack' -Description 'UPnP stack versions from SSDP SERVER banners vs well-known vulnerable releases (libupnp < 1.6.18 and < 1.6.21, MiniUPnPd < 1.4)' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.upnp_stack'; return }
        if ($script:SsdpByIp.Count -eq 0) { Set-BvsCheckStatus -Id 'lan.upnp_stack' -Status 'not_applicable' -Reason 'no SSDP responders'; return }
        foreach ($g in $script:SsdpByIp.Values) {
            foreach ($srv in $g.servers) {
                $product = $null; $ver = $null; $cves = $null; $impact = $null; $rce = $false
                if ($srv -match '(?i)(?:Portable SDK for UPnP devices|libupnp)/(\d+)\.(\d+)\.(\d+)') {
                    $product = 'libupnp'; $ver = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
                    if ($ver -lt [version]'1.6.18') { $cves = 'CVE-2012-5958 to CVE-2012-5965'; $impact = 'stack overflows in the SSDP parser: remote code execution with one UDP packet to port 1900'; $rce = $true }
                    elseif ($ver -lt [version]'1.6.21') { $cves = 'CVE-2016-6255, CVE-2016-8863'; $impact = 'unauthenticated file write into the UPnP web root; heap overflow (crash) via SUBSCRIBE' }
                }
                elseif ($srv -match '(?i)miniupnpd/(\d+)\.(\d+)') {
                    $product = 'MiniUPnPd'; $ver = [version]"$($Matches[1]).$($Matches[2])"
                    if ($ver -lt [version]'1.4') { $cves = 'CVE-2013-0229, CVE-2013-0230'; $impact = 'SOAP stack overflow (remote code execution) and SSDP denial of service'; $rce = $true }
                }
                if ($product) {
                    [pscustomobject][ordered]@{
                        ip = $g.ip; isGateway = ($g.ip -eq $script:Net.Gateway); banner = $srv; product = $product; version = $ver.ToString()
                        vulnerable = [bool]$cves; cves = $cves; impact = $impact; rce = $rce
                    }
                }
            }
        }
    }).Where({ $null -ne $_ })
foreach ($grp in @($stackRows | Where-Object vulnerable | Group-Object ip)) {
    $worst = $grp.Group | Sort-Object { -not $_.rce } | Select-Object -First 1
    $isGw = [bool]$worst.isGateway
    $sev = if ($worst.rce) { if ($isGw) { 'medium' } else { 'low' } } elseif ($isGw) { 'low' } else { 'info' }
    $who = if ($isGw) { "The router ($($grp.Name))" } else { "Device $($grp.Name)" }
    New-BvsFinding -Run $run -Check 'lan.upnp_stack' -Title "$who announces an outdated UPnP stack: $(@($grp.Group | ForEach-Object { "$($_.product) $($_.version)" } | Select-Object -Unique) -join ', ')" `
        -Severity $sev -Class 'hardening' -Confidence 'low' -Reasons @('outdated_component', 'banner_version') `
        -Evidence @($grp.Group | ForEach-Object { [ordered]@{ type = 'ssdp_banner'; ip = $_.ip; banner = $_.banner; product = $_.product; version = $_.version; cves = $_.cves; impact = $_.impact } }) `
        -FpNotes 'Based only on the version string the device announces over SSDP; vendors sometimes back-port fixes without changing it. UPnP normally listens on the LAN side only, so exploiting it needs a device that is already inside the network (or a router that wrongly exposes UPnP to the internet).' `
        -Recommendation 'Check the firmware version and date in the router admin page and install updates (provider-managed routers are usually updated remotely; ask the provider if the firmware looks old). If nothing at home needs UPnP, switch it off: that also takes this code off the network. UPnP must never be reachable from the internet.'
}

$script:LiveIps = @($script:Devices.Values | Where-Object { -not $_.isThisPc -and $_.answered } | ForEach-Object ip)

#endregion

#region ---------- 6-8. names: mDNS, reverse DNS via the router, NetBIOS ----------

$mdnsRaw = @(Invoke-BvsCheck -Run $run -Id 'lan.names_mdns' -Description 'mDNS legacy-unicast queries to 224.0.0.251:5353: reverse PTR for each live host + one DNS-SD service enumeration' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.names_mdns'; return }
        $local = [Net.IPAddress]::Parse($script:Net.LocalIp)
        $udp = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new($local, 0))
        try {
            $udp.MulticastLoopback = $false
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastInterface, $local.GetAddressBytes())
            $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::IP, [System.Net.Sockets.SocketOptionName]::MulticastTimeToLive, 255)
            $udp.Client.ReceiveTimeout = 200
            $dest = [System.Net.IPEndPoint]::new([Net.IPAddress]::Parse('224.0.0.251'), 5353)
            $queries = [System.Collections.Generic.List[byte[]]]::new()
            $queries.Add((New-S08DnsQuery -Id 0x5308 -Name '_services._dns-sd._udp.local'))
            $qid = 0x5400
            foreach ($ip in $script:LiveIps) {
                $o = $ip.Split('.')
                $queries.Add((New-S08DnsQuery -Id ($qid++) -Name "$($o[3]).$($o[2]).$($o[1]).$($o[0]).in-addr.arpa"))
            }
            $queries.Add((New-S08DnsQuery -Id 0x5309 -Name '_services._dns-sd._udp.local'))
            foreach ($q in $queries) { [void]$udp.Send($q, $q.Length, $dest) }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($sw.ElapsedMilliseconds -lt 2600) {
                $remote = [System.Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
                try { $packet = $udp.Receive([ref]$remote) } catch { continue }
                $src = $remote.Address.ToString()
                if (-not (Test-S08InLan $src)) { continue }
                $recs = @()
                try { $recs = @(Read-S08DnsMessage $packet) } catch { continue }
                foreach ($rec in $recs) { [pscustomobject]@{ Src = $src; Name = $rec.Name; Type = $rec.Type; Data = $rec.Data } }
            }
        }
        finally { $udp.Dispose() }
    }).Where({ $null -ne $_ })
foreach ($m in $mdnsRaw) {
    $d = Get-S08Device $m.Src
    $d.answered = $true
    Add-S08Unique $d.seenBy 'mdns'
    $name = Get-S08Text $m.Name 120
    $data = Get-S08Text $m.Data 120
    if ($m.Type -eq 12 -and $name -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa$') {
        $rev = "$($Matches[4]).$($Matches[3]).$($Matches[2]).$($Matches[1])"
        if (Test-S08InLan $rev) { Add-S08Unique (Get-S08Device $rev).mdnsNames ($data -replace '\.$', '') 5; Add-S08Untrusted 'mdns.name' $rev $data }
    }
    elseif ($m.Type -eq 12 -and $name -eq '_services._dns-sd._udp.local') {
        # Sub-types (e.g. Matter _I<fabric-id>._sub._matter._tcp) are identifiers, not service types.
        if ($data -notmatch '\._sub\.') { Add-S08Unique $d.mdnsServices ($data -replace '\.local\.?$', '') 40 }
    }
    elseif ($m.Type -eq 12 -and $name -match '^_[^.]+\._(tcp|udp)\.local$' -and $data -and $data.EndsWith(".$name")) {
        $inst = $data.Substring(0, $data.Length - $name.Length - 1)
        Add-S08Unique $d.mdnsInstances $inst 10
        Add-S08Unique $d.mdnsServices ($name -replace '\.local$', '') 40
        Add-S08Untrusted 'mdns.instance' $m.Src $inst
    }
    elseif ($m.Type -in 1, 33 -and $name -match '\.local$') {
        $host1 = if ($m.Type -eq 1) { $(if ($data -eq $m.Src) { $name } else { $null }) } else { $data }
        if ($host1) { Add-S08Unique $d.mdnsNames ($host1 -replace '\.$', '') 5; Add-S08Untrusted 'mdns.name' $m.Src $host1 }
    }
}

$lateIps = @($script:Devices.Values | Where-Object { -not $_.isThisPc -and $_.answered -and -not $_.mac } | ForEach-Object ip)
$latePing = @(Invoke-BvsCheck -Run $run -Id 'lan.late_ping' -Description 'One ping to hosts first seen via SSDP/mDNS, so the ARP cache learns their MAC' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.late_ping'; return }
        if ($lateIps.Count -eq 0) { Set-BvsCheckStatus -Id 'lan.late_ping' -Status 'not_applicable' -Reason 'every live host already has a MAC'; return }
        $timeout = $PingTimeoutMs
        $lateIps | ForEach-Object -ThrottleLimit 16 -Parallel {
            $pinger = [System.Net.NetworkInformation.Ping]::new()
            try {
                $reply = $pinger.Send($_, $using:timeout)
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    [pscustomobject]@{ Ip = $_; RttMs = [int]$reply.RoundtripTime; Ttl = if ($reply.Options) { [int]$reply.Options.Ttl } else { $null } }
                }
            }
            catch { }
            finally { $pinger.Dispose() }
        }
    }).Where({ $null -ne $_ })
foreach ($p in $latePing) { $d = Get-S08Device $p.Ip; $d.rttMs = $p.RttMs; $d.ttl = $p.Ttl; Add-S08Unique $d.seenBy 'ping' }
if ($script:Active -and $lateIps.Count) {
    foreach ($n in @(Get-S08Neighbors)) { $d = Get-S08Device $n.Ip; if (-not $d.mac) { $d.mac = $n.Mac; $d.arpState = $n.State; Add-S08Unique $d.seenBy 'arp' } }
}
# Names are asked for every host that answered anything (ping, ARP, SSDP or mDNS).
$script:LiveIps = @($script:Devices.Values | Where-Object { -not $_.isThisPc -and $_.answered } | ForEach-Object ip)

$ptrRaw = @(Invoke-BvsCheck -Run $run -Id 'lan.names_ptr' -Description 'Reverse DNS (PTR) for each live host, asked to the gateway DNS server' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.names_ptr'; return }
        if ($script:LiveIps.Count -eq 0) { Set-BvsCheckStatus -Id 'lan.names_ptr' -Status 'not_applicable' -Reason 'no live hosts'; return }
        $server = $script:Net.Gateway
        $script:LiveIps | ForEach-Object -ThrottleLimit 16 -Parallel {
            try {
                $ans = @(Resolve-DnsName -Name $_ -Type PTR -Server $using:server -DnsOnly -QuickTimeout -NoHostsFile -ErrorAction Stop)
                $names = @($ans | Where-Object { [string]$_.Type -eq 'PTR' -and $_.NameHost } | ForEach-Object { [string]$_.NameHost } | Select-Object -Unique)
                if ($names.Count) { [pscustomobject]@{ Ip = $_; Names = $names } }
            }
            catch { }
        }
    }).Where({ $null -ne $_ })
foreach ($p in $ptrRaw) {
    $d = Get-S08Device $p.Ip
    foreach ($n in $p.Names) { $t = Get-S08Text ($n -replace '\.$', '') 120; Add-S08Unique $d.ptr $t 5; Add-S08Untrusted 'dns.ptr' $p.Ip $t }
}

$nbtRaw = @(Invoke-BvsCheck -Run $run -Id 'lan.names_netbios' -Description 'NetBIOS node status (nbtstat -A <ip>) for each live host' -Script {
        if (-not $script:Active) { Skip-S08Active 'lan.names_netbios'; return }
        if ($script:LiveIps.Count -eq 0) { Set-BvsCheckStatus -Id 'lan.names_netbios' -Status 'not_applicable' -Reason 'no live hosts'; return }
        if (-not (Get-Command nbtstat.exe -ErrorAction SilentlyContinue)) { Set-BvsCheckStatus -Id 'lan.names_netbios' -Status 'not_applicable' -Reason 'nbtstat.exe not found'; return }
        $script:LiveIps | ForEach-Object -ThrottleLimit 16 -Parallel {
            $ip = $_
            $lines = @(nbtstat.exe -A $ip 2>$null)
            $names = @(foreach ($l in $lines) {
                    if ([string]$l -match '^\s*(\S.{0,15}?)\s*<([0-9A-Fa-f]{2})>\s+(\S+)') {
                        [pscustomobject]@{ Name = $Matches[1].Trim(); Suffix = $Matches[2].ToUpperInvariant(); Type = $Matches[3] }
                    }
                })
            if ($names.Count) { [pscustomobject]@{ Ip = $ip; Names = $names } }
        }
    }).Where({ $null -ne $_ })
foreach ($r in $nbtRaw) {
    $d = Get-S08Device $r.Ip
    # Locale-independent: <1E>/<1C> entries are always GROUP, so their type word is the local "GROUP".
    $groupWord = ($r.Names | Where-Object { $_.Suffix -in '1E', '1C' } | Select-Object -First 1).Type
    $n00 = @($r.Names | Where-Object { $_.Suffix -eq '00' -and $_.Name -notmatch '__MSBROWSE__' })
    $comp = $n00 | Where-Object { -not (Test-S08NbGroup $_ $groupWord) } | Select-Object -First 1
    $grp = $n00 | Where-Object { Test-S08NbGroup $_ $groupWord } | Select-Object -First 1
    if (-not $comp) { $comp = $r.Names | Where-Object { $_.Suffix -eq '20' } | Select-Object -First 1 }
    if ($comp) { $d.netbios = Get-S08Text $comp.Name 32; Add-S08Untrusted 'netbios.name' $r.Ip $d.netbios }
    if ($grp) { $d.netbiosGroup = Get-S08Text $grp.Name 32 }
    $d.netbiosServer = [bool]($r.Names | Where-Object Suffix -eq '20')
    Add-S08Unique $d.seenBy 'netbios'
}
Write-BvsLog -Run $run -Message "names: live=$($script:LiveIps.Count) mdnsRecords=$($mdnsRaw.Count) ptr=$($ptrRaw.Count) netbios=$($nbtRaw.Count)"

#endregion

#region ---------- 9. vendor (IEEE OUI) and randomized MACs ----------

$ouiResult = Invoke-BvsCheck -Run $run -Id 'lan.vendor_oui' -Description 'MAC vendor from the IEEE MA-L list (standards-oui.ieee.org, cached under intel\); locally administered = randomized MAC' -Script {
    if (-not $script:Net) { Set-BvsCheckStatus -Id 'lan.vendor_oui' -Status 'not_applicable' -Reason $script:Refusal; return }
    # Final passive ARP read: fills MACs of hosts first seen via SSDP/mDNS (nothing is sent).
    foreach ($n in @(Get-S08Neighbors)) { $d = Get-S08Device $n.Ip; if (-not $d.mac) { $d.mac = $n.Mac; $d.arpState = $n.State; Add-S08Unique $d.seenBy 'arp' } }
    $need = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $script:Devices.Values) {
        if (-not $d.mac) { continue }
        $d.randomizedMac = Test-S08RandomMac $d.mac
        if (-not $d.randomizedMac) { [void]$need.Add(($d.mac -replace ':', '').Substring(0, 6)) }
    }
    if ($need.Count -eq 0) { Set-BvsCheckStatus -Id 'lan.vendor_oui' -Status 'ok' -Reason 'no globally administered MACs to look up'; return }

    $cacheDir = Join-Path (Get-BvsRoot) 'intel\standards-oui.ieee.org'
    $cached = @(Get-ChildItem -LiteralPath $cacheDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*-oui.csv' -and $_.Length -gt 1000000 } | Sort-Object LastWriteTimeUtc -Descending) | Select-Object -First 1
    $source = $null; $reader = $null; $note = $null
    if ($cached -and $cached.LastWriteTimeUtc -gt [datetime]::UtcNow.AddDays(-$OuiMaxAgeDays)) {
        $reader = [IO.File]::OpenText($cached.FullName); $source = "cache $($cached.Name)"
    }
    else {
        try {
            $resp = Invoke-BvsIntel -Uri 'https://standards-oui.ieee.org/oui/oui.csv' -SaveName 'oui.csv' -TimeoutSec 120
            $body = (Get-S08ContentText $resp).TrimStart([char]0xFEFF)
            if ($resp.Status -eq 200 -and $body.StartsWith('Registry,Assignment') -and $body.Length -gt 1000000) {
                $reader = [IO.StringReader]::new($body); $source = 'downloaded'
            }
            else { $note = "IEEE answered HTTP $($resp.Status) ($($body.Length) chars)" }
        }
        catch { $note = "IEEE download failed: $($_.Exception.Message)" }
        if (-not $reader -and $cached) { $reader = [IO.File]::OpenText($cached.FullName); $source = "stale cache $($cached.Name)" }
    }
    if (-not $reader) { Set-BvsCheckStatus -Id 'lan.vendor_oui' -Status 'partial' -Reason "$note; no cached list - vendors unknown"; return }

    $map = @{}
    $rx = [regex]::new('^MA-L,([0-9A-Fa-f]{6}),(?:"((?:[^"]|"")*)"|([^,]*))')
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Length -lt 12 -or -not $need.Contains($line.Substring(5, 6))) { continue }
            $m = $rx.Match($line)
            if ($m.Success) { $map[$m.Groups[1].Value.ToUpperInvariant()] = if ($m.Groups[2].Success) { $m.Groups[2].Value.Replace('""', '"') } else { $m.Groups[3].Value } }
        }
    }
    finally { $reader.Dispose() }
    foreach ($d in $script:Devices.Values) {
        if ($d.mac -and -not $d.randomizedMac) {
            $oui = ($d.mac -replace ':', '').Substring(0, 6).ToUpperInvariant()
            if ($map.ContainsKey($oui)) { $d.vendor = Get-S08Text $map[$oui] 80 }
        }
    }
    if ($note) { Set-BvsCheckStatus -Id 'lan.vendor_oui' -Status 'partial' -Reason "$note; used $source" }
    [pscustomobject]@{ Source = $source; Needed = $need.Count; Resolved = $map.Count }
}

#endregion

#region ---------- 10. router start page ----------

$script:Router = [ordered]@{
    ip = if ($script:Net) { $script:Net.Gateway } else { $null }
    mac = $null; vendor = $null
    httpUrl = $null; httpStatus = $null; httpFinalUrl = $null; httpTitle = $null
    httpServer = $null
    httpServerNote = 'not collected: Invoke-BvsIntel does not return response headers (library change requested)'
    plainHttp = $null; plainHttpBasis = $null; httpsRedirect = $null; httpError = $null; httpNote = $null
    presentationUrl = $null; ssdpServer = $null; ssdpServers = @(); tr064Advertised = $null; upnpStacks = @()
    upnp = $null
}

Invoke-BvsCheck -Run $run -Id 'lan.router_http' -Description 'One HTTP GET of http://<gateway>/ (Invoke-BvsIntel -AllowLan): page <title> only, no login, no forms' -Script {
    if (-not $script:Active) { Skip-S08Active 'lan.router_http'; return }
    $url = "http://$($script:Net.Gateway)/"
    $script:Router.httpUrl = $url
    try { $resp = Invoke-BvsIntel -Uri $url -AllowLan -TimeoutSec 8 -MaxBytes 2MB -SaveName 'router-start.html' }
    catch {
        $ex = $_.Exception
        $msg = Get-S08Text $ex.Message 200
        $script:Router.httpError = $msg
        if ($ex -is [System.InvalidOperationException] -and $PSVersionTable.PSVersion -ge [version]'7.4') {
            $script:Router.httpNote = 'The router answered, most likely with an HTTP redirect (3xx). On PowerShell 7.4+ Invoke-WebRequest -MaximumRedirection 0 -SkipHttpErrorCheck throws InvalidOperationException for 3xx, so Invoke-BvsIntel cannot follow it (library change requested). Title and scheme of the final page are unknown.'
            Set-BvsCheckStatus -Id 'lan.router_http' -Status 'partial' -Reason 'router answered with a redirect that Invoke-BvsIntel cannot follow on this PowerShell version (library change requested)'
            return
        }
        if ($msg -match '(?i)ssl|tls|certificate') { $script:Router.httpsRedirect = $true; $script:Router.plainHttp = $false }
        Set-BvsCheckStatus -Id 'lan.router_http' -Status 'partial' -Reason "GET failed: $msg"
        return
    }
    $html = Get-S08ContentText $resp
    $title = $null
    if ($html -match '(?is)<title[^>]*>(.*?)</title>') { $title = Get-S08Text ([System.Net.WebUtility]::HtmlDecode($Matches[1])) 120 }
    $final = [uri]$resp.Url
    $script:Router.httpStatus = [int]$resp.Status
    $script:Router.httpFinalUrl = Protect-BvsUrl $resp.Url
    $script:Router.httpTitle = $title
    $script:Router.httpsRedirect = ($final.Scheme -eq 'https')
    $script:Router.plainHttp = ($final.Scheme -eq 'http' -and [int]$resp.Status -in 200, 401, 403)
    Add-S08Untrusted 'router.title' $script:Net.Gateway $title
    [int]$resp.Status
} | Out-Null

#endregion

#region ---------- 11-12. UPnP IGD port-forwards ----------

$script:Mappings = [System.Collections.Generic.List[object]]::new()
$script:Upnp = [ordered]@{
    igdFound = $false; source = $null; descriptions = [System.Collections.Generic.List[object]]::new()
    wanServices = [System.Collections.Generic.List[string]]::new(); enumeration = 'not_attempted'; stopCode = $null; stopReason = $null
}

Invoke-BvsCheck -Run $run -Id 'lan.upnp_igd' -Description 'UPnP IGD: GET the router description XML, then GetGenericPortMappingEntry index 0..n until the router reports the end (read-only SOAP)' -Script {
    if (-not $script:Active) { Skip-S08Active 'lan.upnp_igd'; return }
    $igdRx = '(?i)InternetGatewayDevice|WANDevice|WANConnectionDevice|WANIPConnection|WANPPPConnection'
    $cands = [System.Collections.Generic.List[object]]::new()
    $seenLoc = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($pass in 1, 2) {
        foreach ($r in $ssdpRaw) {
            $isIgd = "$($r.St) $($r.Usn)" -match $igdRx
            if (($pass -eq 1 -and -not $isIgd) -or ($pass -eq 2 -and ($cands.Count -gt 0 -or $r.Ip -ne $script:Net.Gateway))) { continue }
            $u = Test-S08LanUrl $r.Location $r.Ip
            if ($u -and $seenLoc.Add($u.AbsoluteUri) -and $cands.Count -lt 3) { $cands.Add([pscustomobject]@{ Ip = $r.Ip; Uri = $u }) }
        }
    }
    if ($cands.Count -eq 0) {
        $script:Upnp.stopReason = 'no Internet Gateway Device answered SSDP (UPnP disabled or filtered)'
        Set-BvsCheckStatus -Id 'lan.upnp_igd' -Status 'ok' -Reason $script:Upnp.stopReason
        return
    }
    $wan = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $cands) {
        try { $resp = Invoke-BvsIntel -Uri $c.Uri.AbsoluteUri -AllowLan -TimeoutSec 6 -MaxBytes 1MB -SaveName 'upnp-description.xml' }
        catch { $script:Upnp.stopReason = "description GET failed: $(Get-S08Text $_.Exception.Message 160)"; continue }
        if ([int]$resp.Status -ne 200) { continue }
        $xml = $null
        try { $xml = ConvertTo-S08Xml (Get-S08ContentText $resp) } catch { continue }
        if (-not $xml) { continue }
        $root = $xml.SelectSingleNode("/*[local-name()='root']")
        $dev = if ($root) { $root.SelectSingleNode("./*[local-name()='device']") } else { $null }
        $desc = [ordered]@{
            location         = Protect-BvsUrl $c.Uri.AbsoluteUri
            ip               = $c.Ip
            deviceType       = Get-S08Text (Get-S08XmlValue $dev 'deviceType' -Child) 120
            friendlyName     = Get-S08Text (Get-S08XmlValue $dev 'friendlyName' -Child) 120
            manufacturer     = Get-S08Text (Get-S08XmlValue $dev 'manufacturer' -Child) 120
            modelName        = Get-S08Text (Get-S08XmlValue $dev 'modelName' -Child) 120
            modelNumber      = Get-S08Text (Get-S08XmlValue $dev 'modelNumber' -Child) 60
            modelDescription = Get-S08Text (Get-S08XmlValue $dev 'modelDescription' -Child) 160
            presentationUrl  = Protect-BvsUrl (Get-S08Text (Get-S08XmlValue $dev 'presentationURL' -Child) 200)
            services         = @($xml.SelectNodes("//*[local-name()='service']/*[local-name()='serviceType']") | ForEach-Object { Get-S08Text $_.InnerText 120 } | Select-Object -Unique -First 30)
        }
        $script:Upnp.descriptions.Add($desc)
        foreach ($k in 'friendlyName', 'manufacturer', 'modelName', 'modelDescription') { Add-S08Untrusted "upnp.$k" $c.Ip $desc[$k] }
        if ($script:SsdpByIp.Contains($c.Ip)) {
            $g = $script:SsdpByIp[$c.Ip]
            $g.described = $true
            foreach ($k in 'friendlyName', 'manufacturer', 'modelName', 'modelNumber', 'deviceType') { if (-not $g.$k) { $g.$k = $desc[$k] } }
        }
        $baseText = Get-S08XmlValue $root 'URLBase' -Child
        $base = $c.Uri
        if ($baseText) { $bu = Test-S08LanUrl $baseText $c.Uri.Host; if ($bu) { $base = $bu } }
        foreach ($svc in @($xml.SelectNodes("//*[local-name()='service']"))) {
            $type = Get-S08XmlValue $svc 'serviceType' -Child
            $ctl = Get-S08XmlValue $svc 'controlURL' -Child
            if (-not $ctl -or $type -notmatch '^urn:schemas-upnp-org:service:WAN(IP|PPP)Connection:[12]$') { continue }
            $abs = $null
            try { $abs = [uri]::new($base, $ctl) } catch { continue }
            # Only ever POST to the device that served the description.
            if ($abs.Host -ne $c.Uri.Host -or $abs.Scheme -notin 'http', 'https') { continue }
            if (-not ($wan | Where-Object { $_.Control.AbsoluteUri -eq $abs.AbsoluteUri -and $_.Type -eq $type })) {
                $wan.Add([pscustomobject]@{ Type = $type; Control = $abs; Ip = $c.Ip })
            }
        }
    }
    $script:Upnp.igdFound = ($wan.Count -gt 0) -or [bool]($ssdpRaw | Where-Object { "$($_.St) $($_.Usn)" -match $igdRx })
    if ($wan.Count -eq 0) {
        $script:Upnp.stopReason = 'IGD answered SSDP but no WANIPConnection/WANPPPConnection control URL was usable'
        Set-BvsCheckStatus -Id 'lan.upnp_igd' -Status 'partial' -Reason $script:Upnp.stopReason
        return
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $results = [System.Collections.Generic.List[string]]::new()
    foreach ($w in $wan) {
        $short = ($w.Type -split ':')[-2] + ':' + ($w.Type -split ':')[-1]
        $script:Upnp.wanServices.Add("$short $(Protect-BvsUrl $w.Control.AbsoluteUri)")
        $result = 'truncated at 256 entries'
        for ($i = 0; $i -lt 256; $i++) {
            $body = '<?xml version="1.0" encoding="utf-8"?>' +
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>' +
            "<u:GetGenericPortMappingEntry xmlns:u=`"$($w.Type)`"><NewPortMappingIndex>$i</NewPortMappingIndex></u:GetGenericPortMappingEntry>" +
            '</s:Body></s:Envelope>'
            try {
                $resp = Invoke-BvsIntel -Uri $w.Control.AbsoluteUri -Method POST -Body $body -ContentType 'text/xml; charset=utf-8' `
                    -Headers @{ SOAPAction = "`"$($w.Type)#GetGenericPortMappingEntry`"" } -AllowLan -TimeoutSec 6 -MaxBytes 256KB `
                    -SaveName "upnp-GetGenericPortMappingEntry-$i.xml"
            }
            catch { $result = "error: request failed at index ${i}: $(Get-S08Text $_.Exception.Message 160)"; break }
            $x = $null
            try { $x = ConvertTo-S08Xml (Get-S08ContentText $resp) } catch { }
            $code = if ($x) { Get-S08XmlValue $x.DocumentElement 'errorCode' } else { $null }
            if ($code -or [int]$resp.Status -ne 200 -or -not $x) {
                $script:Upnp.stopCode = $code
                $errDesc = if ($x) { Get-S08Text (Get-S08XmlValue $x.DocumentElement 'errorDescription') 80 } else { $null }
                $result = switch ($code) {
                    { $_ -in '713', '714' } { "complete ($i entries; end signalled with UPnP error $code)"; break }
                    '606' { "denied: UPnP error 606 Action not authorized (router restricts reading)"; break }
                    default { "error: HTTP $([int]$resp.Status) UPnP error $code $errDesc at index $i" }
                }
                break
            }
            $ext = Get-S08XmlValue $x.DocumentElement 'NewExternalPort'
            if (-not $ext) { $result = "error: index $i answered without NewExternalPort"; break }
            $enabledText = Get-S08XmlValue $x.DocumentElement 'NewEnabled'
            $m = [pscustomobject][ordered]@{
                index          = $i
                service        = $short
                remoteHost     = Get-S08Text (Get-S08XmlValue $x.DocumentElement 'NewRemoteHost') 64
                externalPort   = [int](Get-S08XmlValue $x.DocumentElement 'NewExternalPort')
                protocol       = ([string](Get-S08XmlValue $x.DocumentElement 'NewProtocol')).ToUpperInvariant()
                internalClient = Get-S08Text (Get-S08XmlValue $x.DocumentElement 'NewInternalClient') 64
                internalPort   = [int](Get-S08XmlValue $x.DocumentElement 'NewInternalPort')
                description    = Get-S08Text (Get-S08XmlValue $x.DocumentElement 'NewPortMappingDescription') 120
                enabled        = $enabledText -in '1', 'true', 'yes'
                leaseSeconds   = [int](Get-S08XmlValue $x.DocumentElement 'NewLeaseDuration')
                source         = 'soap'
            }
            $key = "$($m.remoteHost)|$($m.externalPort)|$($m.protocol)"
            if (-not $seen.Add($key)) { $result = "complete ($i entries; router repeated an entry, stopped)"; break }
            $script:Mappings.Add($m)
            Add-S08Untrusted 'upnp.mapping.description' $m.internalClient $m.description
        }
        $results.Add("$short`: $result")
    }
    $script:Upnp.source = 'soap'
    $script:Upnp.enumeration = if (@($results | Where-Object { $_ -notmatch ': complete' }).Count -eq 0) { 'complete' } elseif (@($results | Where-Object { $_ -match ': denied' }).Count) { 'denied' } else { 'error' }
    $script:Upnp.stopReason = $results -join ' | '
    if ($script:Upnp.enumeration -ne 'complete') { Set-BvsCheckStatus -Id 'lan.upnp_igd' -Status 'partial' -Reason $script:Upnp.stopReason }
    @($script:Mappings)
} | Out-Null

Invoke-BvsCheck -Run $run -Id 'lan.upnp_com' -Description 'Fallback: HNetCfg.NATUPnP StaticPortMappingCollection, read-only enumeration (only when SOAP did not complete)' -Script {
    if (-not $script:Active) { Skip-S08Active 'lan.upnp_com'; return }
    if ($script:Upnp.enumeration -eq 'complete') { Set-BvsCheckStatus -Id 'lan.upnp_com' -Status 'skipped' -Reason 'SOAP enumeration already complete'; return }
    try {
        $rows = @(1 | ForEach-Object -TimeoutSeconds 30 -Parallel {
                $nat = New-Object -ComObject HNetCfg.NATUPnP
                $col = $nat.StaticPortMappingCollection
                if ($null -eq $col) { [pscustomobject]@{ Missing = $true }; return }
                foreach ($e in $col) {
                    [pscustomobject]@{
                        Missing = $false; ExternalPort = [int]$e.ExternalPort; Protocol = [string]$e.Protocol; InternalPort = [int]$e.InternalPort
                        InternalClient = [string]$e.InternalClient; Enabled = [bool]$e.Enabled; Description = [string]$e.Description
                    }
                }
            })
    }
    catch { Set-BvsCheckStatus -Id 'lan.upnp_com' -Status 'partial' -Reason "NATUPnP failed or timed out: $(Get-S08Text $_.Exception.Message 160)"; return }
    if ($rows.Count -eq 0 -or ($rows | Where-Object Missing)) {
        Set-BvsCheckStatus -Id 'lan.upnp_com' -Status 'ok' -Reason 'NATUPnP found no IGD port-mapping collection (UPnP disabled, filtered, or Windows discovery off)'
        return
    }
    $known = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in $script:Mappings) { [void]$known.Add("$($m.externalPort)|$($m.protocol)") }
    $added = 0
    foreach ($r in $rows) {
        if (-not $known.Add("$($r.ExternalPort)|$($r.Protocol.ToUpperInvariant())")) { continue }
        $m = [pscustomobject][ordered]@{
            index = $null; service = 'NATUPnP'; remoteHost = $null; externalPort = $r.ExternalPort; protocol = $r.Protocol.ToUpperInvariant()
            internalClient = Get-S08Text $r.InternalClient 64; internalPort = $r.InternalPort; description = Get-S08Text $r.Description 120
            enabled = $r.Enabled; leaseSeconds = $null; source = 'com'
        }
        $script:Mappings.Add($m); $added++
        Add-S08Untrusted 'upnp.mapping.description' $m.internalClient $m.description
    }
    $script:Upnp.igdFound = $true
    if (-not $script:Upnp.source) { $script:Upnp.source = 'com' }
    $script:Upnp.enumeration = 'complete'
    $script:Upnp.stopReason = (@($script:Upnp.stopReason, "NATUPnP listed $($rows.Count) mapping(s), $added new") | Where-Object { $_ }) -join ' | '
    $rows
} | Out-Null
Write-BvsLog -Run $run -Message "upnp: igd=$($script:Upnp.igdFound) mappings=$($script:Mappings.Count) enumeration=$($script:Upnp.enumeration) $($script:Upnp.stopReason)"

#endregion

#region ---------- 13. merge, identify, census ----------

$devList = @(Invoke-BvsCheck -Run $run -Id 'lan.device_identify' -Description 'Merge ARP/ping/SSDP/mDNS/PTR/NetBIOS/OUI per IP; best name; device-type guess with reasons' -Script {
        if (-not $script:Net) { Set-BvsCheckStatus -Id 'lan.device_identify' -Status 'not_applicable' -Reason $script:Refusal; return }
        foreach ($d in $script:Devices.Values) {
            if ($d.isThisPc) { continue }
            $d.hostname = @($d.mdnsNames | Select-Object -First 1) + @($d.netbios) + @($d.ptr | Select-Object -First 1) | Where-Object { $_ } | Select-Object -First 1
            $g = Get-S08TypeGuess $d
            $d.typeGuess = $g.Type; $d.typeConfidence = $g.Confidence; $d.typeReason = @($g.Reason)
        }
        $me = $script:Devices[$script:Net.LocalIp]
        $g = Get-S08TypeGuess $me
        $me.typeGuess = $g.Type; $me.typeConfidence = $g.Confidence; $me.typeReason = @($g.Reason)
        foreach ($d in ($script:Devices.Values | Sort-Object { [version]$_.ip })) {
            [pscustomobject][ordered]@{
                ip = $d.ip; mac = $d.mac; vendor = $d.vendor; randomizedMac = $d.randomizedMac
                hostname = $d.hostname; ptr = @($d.ptr); netbios = $d.netbios; netbiosGroup = $d.netbiosGroup
                mdnsNames = @($d.mdnsNames); mdnsInstances = @($d.mdnsInstances); mdnsServices = @($d.mdnsServices)
                ssdpServer = if ($d.ssdp) { @($d.ssdp.servers) | Select-Object -First 1 } else { $null }
                ssdpFriendlyName = if ($d.ssdp) { $d.ssdp.friendlyName } else { $null }
                typeGuess = $d.typeGuess; typeConfidence = $d.typeConfidence; typeReason = @($d.typeReason)
                seenBy = @($d.seenBy); answeredThisScan = $d.answered; arpState = $d.arpState; rttMs = $d.rttMs; ttl = $d.ttl
                isGateway = $d.isGateway; isThisPc = $d.isThisPc; upnpMappings = 0
                expected = if ($d.isThisPc) { $null } else { Get-S08ExpectedForHost $d }
                needsUserConfirmation = -not ($d.isThisPc -or $d.isGateway)
            }
        }
    }).Where({ $null -ne $_ })

#endregion

#region ---------- 14. port-forward assessment ----------

$mapRows = @(Invoke-BvsCheck -Run $run -Id 'lan.upnp_assess' -Description 'Rate each UPnP port-forward: sensitive port to this PC = high, remote-admin/database port to any device = high, other device = medium, known app/console = expected' -Script {
        if ($script:Mappings.Count -eq 0) {
            $why = if (-not $script:Active) { $script:Refusal } else { 'no port-forwards were listed' }
            Set-BvsCheckStatus -Id 'lan.upnp_assess' -Status $(if ($script:Active) { 'ok' } else { 'not_applicable' }) -Reason $why
            return
        }
        foreach ($m in $script:Mappings) {
            $isPc = $m.internalClient -eq $script:Net.LocalIp
            $devRow = $devList | Where-Object { $_.ip -eq $m.internalClient } | Select-Object -First 1
            if ($devRow) { $devRow.upnpMappings++ }
            $ports = @($m.internalPort, $m.externalPort) | Where-Object { $_ -gt 0 } | Select-Object -Unique
            $sens = @($ports | Where-Object { $script:SensitivePorts.ContainsKey([int]$_) })
            $crit = @($ports | Where-Object { [int]$_ -in $script:CriticalPorts })
            $owners = if ($isPc) { @(Get-S08PortOwner $m.internalPort $m.protocol) } else { @() }
            $app = Get-S08KnownApp $m $devRow
            $exp = if ($isPc) { Get-S08ExpectedForMapping $m $owners } else { $null }
            $inLan = Test-S08InLan $m.internalClient
            $svcName = if ($sens) { ($sens | ForEach-Object { $script:SensitivePorts[[int]$_] } | Select-Object -Unique) -join '/' } else { $null }
            $target = if ($isPc) { 'this PC' } elseif ($devRow) { "$($m.internalClient) ($($devRow.typeGuess)$(if ($devRow.vendor) { ", $($devRow.vendor)" }))" } else { "$($m.internalClient) (not seen in this scan)" }

            $sev = 'info'; $class = 'info'; $assess = $null
            if ($isPc -and $sens) { $sev = 'high'; $class = 'suspicious'; $assess = "risky: $svcName port on this PC reachable from the internet" }
            elseif (-not $isPc -and $crit) { $sev = 'high'; $class = 'suspicious'; $assess = "risky: $svcName port on another device reachable from the internet" }
            elseif ($exp) { $assess = "expected: $($exp.id) ($app)" }
            elseif ($app) { $assess = "expected: $app" }
            elseif (-not $isPc -and -not $inLan) { $sev = 'medium'; $class = 'hardening'; $assess = 'forward to an address outside the LAN subnet' }
            elseif (-not $isPc -and $sens) { $sev = 'medium'; $class = 'hardening'; $assess = "$svcName port on another device reachable from the internet" }
            elseif (-not $isPc) { $sev = 'medium'; $class = 'hardening'; $assess = 'forward to a device the user has not confirmed' }
            else { $sev = 'low'; $class = 'hardening'; $assess = 'an application on this PC opened an inbound port' }
            if (-not $m.enabled -and $sev -in 'high', 'medium') { $sev = 'low'; $assess += ' (mapping disabled)' }

            $row = [pscustomobject][ordered]@{
                externalPort = $m.externalPort; protocol = $m.protocol; internalClient = $m.internalClient; internalPort = $m.internalPort
                description = $m.description; enabled = $m.enabled; leaseSeconds = $m.leaseSeconds
                permanent = ($m.leaseSeconds -eq 0); remoteHost = $m.remoteHost; source = $m.source; service = $m.service
                targetIsThisPc = $isPc; target = $target; sensitive = [bool]$sens; localProcess = @($owners)
                knownApp = $app; expected = $exp; severity = $sev; assessment = $assess
            }
            if ($sev -ne 'info') {
                $proto = $m.protocol
                $title = if ($isPc -and $sens) { "UPnP port-forward exposes $svcName ($proto $($m.internalPort)) on this PC to the internet" }
                elseif ($crit) { "UPnP port-forward exposes $svcName ($proto $($m.internalPort)) on $($m.internalClient) to the internet" }
                elseif ($isPc) { "An application on this PC opened inbound $proto $($m.externalPort) via UPnP" }
                else { "UPnP port-forward $proto $($m.externalPort) -> $($m.internalClient):$($m.internalPort) points to an unconfirmed device" }
                $ev = @([ordered]@{ type = 'upnp_mapping'; router = $script:Net.Gateway; externalPort = $m.externalPort; protocol = $proto; internalClient = $m.internalClient; internalPort = $m.internalPort; description = $m.description; enabled = $m.enabled; leaseSeconds = $m.leaseSeconds; remoteHost = $m.remoteHost; source = $m.source })
                foreach ($o in $owners) { $ev += [ordered]@{ type = 'process'; pid = $o.pid; name = $o.name; note = 'owns the internal port on this PC' } }
                if ($devRow) { $ev += [ordered]@{ type = 'device'; ip = $devRow.ip; mac = $devRow.mac; vendor = $devRow.vendor; hostname = $devRow.hostname; typeGuess = $devRow.typeGuess } }
                $reasons = @('exposed_service', 'upnp')
                if ($m.leaseSeconds -eq 0) { $reasons += 'permanent_mapping' }
                $mitre = if ($crit) { @('T1133') } else { @() }
                New-BvsFinding -Run $run -Check 'lan.upnp_assess' -Title $title -Severity $sev -Class $class -Confidence 'high' `
                    -Reasons $reasons -Evidence $ev -Mitre $mitre `
                    -Entities @{ network = @([ordered]@{ ip = $m.internalClient; port = $m.internalPort; protocol = $proto; externalPort = $m.externalPort; direction = 'inbound from internet via router' }); processes = @($owners) } `
                    -FpNotes 'The forward may be intentional (remote access you set up yourself, a game, a media server) or requested automatically by an application through UPnP. Entries created manually in the router UI can also be listed here.' `
                    -Recommendation "Open the router admin page (http://$($script:Net.Gateway)/), review the UPnP / port-forwarding table and delete this entry if you did not create it on purpose. Identify the program behind it (on this PC: Resource Monitor > Network > Listening Ports; on another device: its app settings). If nothing at home needs UPnP, disable it in the router. For remote access, prefer a VPN such as Tailscale over forwarded ports."
            }
            $row
        }
    }).Where({ $null -ne $_ })

#endregion

#region ---------- 15. ARP anomalies ----------

$arpAnomalies = @(Invoke-BvsCheck -Run $run -Id 'lan.arp_anomalies' -Description 'One MAC answering for several IPs (gateway involved = possible ARP spoofing); gateway MAC changed during the scan' -Script {
        if (-not $script:Net) { Set-BvsCheckStatus -Id 'lan.arp_anomalies' -Status 'not_applicable' -Reason $script:Refusal; return }
        $gwRow = $devList | Where-Object isGateway | Select-Object -First 1
        foreach ($grp in @($devList | Where-Object { $_.mac -and -not $_.isThisPc } | Group-Object mac | Where-Object Count -gt 1)) {
            $withGw = [bool]($grp.Group | Where-Object isGateway)
            [pscustomobject][ordered]@{ kind = 'shared_mac'; mac = $grp.Name; ips = @($grp.Group.ip); includesGateway = $withGw }
            if ($withGw) {
                New-BvsFinding -Run $run -Check 'lan.arp_anomalies' -Title "The gateway's MAC address also answers for $(@($grp.Group.ip | Where-Object { $_ -ne $script:Net.Gateway }) -join ', ')" `
                    -Severity 'medium' -Class 'suspicious' -Confidence 'low' -Reasons @('arp_anomaly') -Mitre @('T1557.002') `
                    -Evidence @([ordered]@{ type = 'arp'; mac = $grp.Name; ips = @($grp.Group.ip); gateway = $script:Net.Gateway }) `
                    -FpNotes 'Some routers answer for a second LAN address, and repeaters or mesh nodes in proxy-ARP/bridge mode reuse one MAC. ARP spoofing (a device pretending to be the router) looks the same.' `
                    -Recommendation 'Compare the MAC with the one printed on the router label or shown in its admin page. If another device holds the router MAC, disconnect unknown devices, change the Wi-Fi password and re-run this check.'
            }
        }
        if ($gwMacBefore -and $gwRow -and $gwRow.mac -and $gwRow.mac -ne $gwMacBefore) {
            [pscustomobject][ordered]@{ kind = 'gateway_mac_changed'; mac = $gwRow.mac; previous = $gwMacBefore; ips = @($script:Net.Gateway); includesGateway = $true }
            New-BvsFinding -Run $run -Check 'lan.arp_anomalies' -Title 'The gateway MAC address changed during the scan' -Severity 'medium' -Class 'suspicious' -Confidence 'low' `
                -Reasons @('arp_anomaly') -Mitre @('T1557.002') `
                -Evidence @([ordered]@{ type = 'arp'; before = $gwMacBefore; after = $gwRow.mac; gateway = $script:Net.Gateway }) `
                -FpNotes 'A router replaced or rebooted into a different interface, or a failover between two gateways, also changes the MAC.' `
                -Recommendation 'Check which device now holds the gateway address (router label/admin page). Re-run the scan; a MAC that keeps flipping is a strong ARP-spoofing sign.'
        }
    }).Where({ $null -ne $_ })

#endregion

#region ---------- 16. untrusted text screen ----------

$injHits = @(Invoke-BvsCheck -Run $run -Id 'lan.untrusted_text' -Description 'Screen every name/title/description read from other devices for embedded instructions (prompt injection)' -Script {
        foreach ($u in $script:Untrusted) { if ($script:InjectionRx.IsMatch($u.Text)) { $u } }
    }).Where({ $null -ne $_ })
if ($injHits.Count) {
    New-BvsFinding -Run $run -Check 'lan.untrusted_text' -Title "Text read from $(@($injHits.Ip | Select-Object -Unique).Count) LAN device(s) contains instruction-like content" `
        -Severity 'medium' -Class 'suspicious' -Confidence 'medium' -Reasons @('prompt_injection') `
        -Evidence @($injHits | Select-Object -First 10 | ForEach-Object { [ordered]@{ type = 'text'; source = $_.Source; ip = $_.Ip; text = (Get-S08Text $_.Text 160) } }) `
        -FpNotes 'Device names and UPnP descriptions are free text set by apps or users; an odd wording can match by accident.' `
        -Recommendation 'Treat the text as hostile data. Find the device and the app that set it (router UPnP table, device settings) and remove it. Do not paste it into AI tools.'
}

#endregion

#region ---------- posture findings, router summary, inventory ----------

$gwRow = $devList | Where-Object isGateway | Select-Object -First 1
if ($gwRow) {
    $script:Router.mac = $gwRow.mac; $script:Router.vendor = $gwRow.vendor
    $script:Router.ssdpServer = $gwRow.ssdpServer
}
$mainDesc = $script:Upnp.descriptions | Where-Object { $_.deviceType -match '^urn:schemas-upnp-org:device:InternetGatewayDevice' } | Select-Object -First 1
if (-not $mainDesc) { $mainDesc = $script:Upnp.descriptions | Select-Object -First 1 }
if ($script:Net -and $script:SsdpByIp.Contains($script:Net.Gateway)) {
    $gs = $script:SsdpByIp[$script:Net.Gateway]
    $script:Router.ssdpServers = @($gs.servers)
    # TR-064 (dslforum-org) is the router's LAN-side management protocol (settings, Wi-Fi, hosts list).
    $script:Router.tr064Advertised = [bool]($gs.searchTargets | Where-Object { $_ -match '^urn:dslforum-org:' })
}
$script:Router.upnpStacks = @($stackRows | Where-Object isGateway)
$script:Router.presentationUrl = $mainDesc.presentationUrl
$script:Router.upnp = [ordered]@{
    enabled = $script:Upnp.igdFound; source = $script:Upnp.source; enumeration = $script:Upnp.enumeration; stopCode = $script:Upnp.stopCode
    detail = $script:Upnp.stopReason; mappingCount = $script:Mappings.Count; wanServices = @($script:Upnp.wanServices)
    friendlyName = $mainDesc.friendlyName; manufacturer = $mainDesc.manufacturer; modelName = $mainDesc.modelName; modelNumber = $mainDesc.modelNumber
    descriptions = @($script:Upnp.descriptions)
}

if ($script:Upnp.igdFound) {
    $modelNo = if ($mainDesc.modelNumber -and [string]$mainDesc.modelName -notmatch [regex]::Escape([string]$mainDesc.modelNumber)) { $mainDesc.modelNumber } else { $null }
    $model = (@($mainDesc.manufacturer, $mainDesc.modelName, $modelNo) | Where-Object { $_ }) -join ' '
    $listText = if ($script:Upnp.enumeration -eq 'complete') { "$($script:Mappings.Count) port-forward(s) listed" } else { "port-forward list incomplete ($($script:Upnp.enumeration))" }
    New-BvsFinding -Run $run -Check 'lan.upnp_igd' -Title ("UPnP is enabled on the router{0}: {1}" -f $(if ($model) { " ($model)" } else { '' }), $listText) `
        -Severity 'info' -Class 'hardening' -Confidence 'high' -Reasons @('upnp') `
        -Evidence @([ordered]@{ type = 'upnp_igd'; router = $script:Net.Gateway; friendlyName = $mainDesc.friendlyName; manufacturer = $mainDesc.manufacturer; modelName = $mainDesc.modelName; wanServices = @($script:Upnp.wanServices); mappings = $script:Mappings.Count; enumeration = $script:Upnp.enumeration; detail = $script:Upnp.stopReason; tr064Advertised = $script:Router.tr064Advertised; ssdpServers = @($script:Router.ssdpServers) }) `
        -FpNotes 'UPnP is on by default on most ISP routers and some things need it: game consoles (open NAT type), Tailscale direct connections, some video-call and media-server apps.' `
        -Recommendation 'UPnP lets any program on any LAN device open inbound ports without a password. If nothing at home needs it, switch it off in the router admin page; otherwise keep it, and review the port-forward list in this report after each scan.'
}

$plainBasis = $null
if ($script:Router.plainHttp) { $plainBasis = "the start page answered over plain HTTP (status $($script:Router.httpStatus))" }
elseif ($null -eq $script:Router.plainHttp -and $script:Router.httpNote -and [string]$script:Router.presentationUrl -match '^http://') {
    $plainBasis = "the GET of http://$($script:Net.Gateway)/ was redirected (target unknown) and the router's UPnP description advertises its admin page as $($script:Router.presentationUrl)"
}
$script:Router.plainHttpBasis = $plainBasis
if ($plainBasis) {
    $adminUrl = if ($script:Router.plainHttp) { $script:Router.httpFinalUrl } else { $script:Router.presentationUrl }
    New-BvsFinding -Run $run -Check 'lan.router_http' -Title "Router admin page is served over plain HTTP ($adminUrl)" `
        -Severity 'info' -Class 'hardening' -Confidence $(if ($script:Router.plainHttp) { 'high' } else { 'low' }) -Reasons @('plaintext_http') `
        -Evidence @([ordered]@{ type = 'http'; url = $adminUrl; status = $script:Router.httpStatus; title = $script:Router.httpTitle; basis = $plainBasis; presentationUrl = $script:Router.presentationUrl }) `
        -FpNotes 'Normal for home routers. The page is only reachable from inside the network and Wi-Fi traffic is encrypted (WPA2/WPA3), so the risk is limited to someone already on the LAN.' `
        -Recommendation 'Use a long, unique router admin password (not the one printed on the label), keep remote/WAN administration disabled, and switch the admin page to HTTPS if the router offers it.'
}

$others = @($devList | Where-Object { -not $_.isThisPc -and -not $_.isGateway })
$unknownDevs = @($others | Where-Object { $_.typeGuess -eq 'unknown' })
$randomDevs = @($others | Where-Object randomizedMac)
if ($others.Count) {
    $many = ($unknownDevs.Count + $randomDevs.Count) -ge 5
    New-BvsFinding -Run $run -Check 'lan.device_identify' -Title ("{0}{1} other device(s) on the LAN: {2} not identified, {3} with randomized MACs - please confirm you recognise them" -f $(if ($many) { 'Many devices: ' } else { '' }), $others.Count, $unknownDevs.Count, $randomDevs.Count) `
        -Severity 'info' -Class 'info' -Confidence 'medium' -Reasons @('unknown_device_census') `
        -Evidence @($others | Select-Object -First 25 | ForEach-Object { [ordered]@{ type = 'device'; ip = $_.ip; mac = $_.mac; vendor = $_.vendor; randomizedMac = $_.randomizedMac; hostname = $_.hostname; typeGuess = $_.typeGuess; expected = $_.expected.id } }) `
        -FpNotes 'Unidentified devices are usually phones/tablets using private (randomized) Wi-Fi addresses, smart-home gadgets or guests. Not being able to name a device is not evidence of an intrusion.' `
        -Recommendation "Compare the device table with what you own (the router's connected-devices page shows DHCP names). If a device stays unexplained, change the Wi-Fi password (WPA2/WPA3), which disconnects everything, and reconnect your own devices."
}

$questions = [System.Collections.Generic.List[string]]::new()
if ($others.Count) {
    $list = ($others | ForEach-Object {
            $v = if ($_.vendor) { $_.vendor } elseif ($_.randomizedMac) { 'randomized MAC' } else { 'vendor unknown' }
            $h = if ($_.hostname) { $_.hostname } else { 'no name' }
            $e = if ($_.expected) { "; matches expected '$($_.expected.id)'" } else { '' }
            "$($_.ip) [$($_.typeGuess); $v; $h$e]"
        }) -join ', '
    $questions.Add("Do you recognise these $($others.Count) devices? $list")
}
foreach ($r in @($mapRows | Where-Object { $_.severity -in 'high', 'medium' })) {
    $questions.Add("Do you know why the router forwards $($r.protocol) $($r.externalPort) to $($r.target) port $($r.internalPort)$(if ($r.description) { " ('$($r.description)')" })?")
}
if ($script:Upnp.igdFound) { $questions.Add('Does anything at home need UPnP (game console, Tailscale direct connections, media server)? If not, consider switching it off in the router.') }
if ($plainBasis) { $questions.Add('Have you changed the router admin password from the default printed on the router label?') }

$summary = [ordered]@{
    active          = $script:Active
    refusal         = $script:Refusal
    devices         = $devList.Count
    others          = $others.Count
    unidentified    = $unknownDevs.Count
    randomizedMacs  = $randomDevs.Count
    byType          = [ordered]@{}
    upnpEnabled     = $script:Upnp.igdFound
    upnpMappings    = $script:Mappings.Count
    riskyMappings   = @($mapRows | Where-Object { $_.severity -in 'high', 'medium' }).Count
    ssdpResponders  = $script:SsdpByIp.Count
    routerPlainHttp = $script:Router.plainHttp
}
foreach ($grp in @($devList | Group-Object typeGuess | Sort-Object Count -Descending)) { $summary.byType[$grp.Name] = $grp.Count }

$netInfo = if ($script:Net) {
    [ordered]@{
        interfaceAlias = $script:Net.Alias; interfaceDescription = $script:Net.Description; mediaType = $script:Net.MediaType
        ifIndex = $script:Net.IfIndex; localIp = $script:Net.LocalIp; mac = $script:Net.Mac; prefixLength = $script:Net.Prefix
        subnet = $script:Net.Subnet; gateway = $script:Net.Gateway; profileName = $script:Net.ProfileName
        networkCategory = $script:Net.Category; hostAddresses = $script:Net.HostCount
        sweepAllowed = $script:Net.SweepAllowed; passiveOnly = [bool]$PassiveOnly; refusal = $script:Refusal
        probe = [ordered]@{ pingTimeoutMs = $PingTimeoutMs; pingAttempts = $PingAttempts; throttle = $ThrottleLimit }
    }
}
else { [ordered]@{ refusal = $script:Refusal } }

$ssdpList = @($script:SsdpByIp.Values | ForEach-Object {
        [ordered]@{
            ip = $_.ip; inLan = $_.inLan; servers = @($_.servers); searchTargets = @($_.searchTargets); usns = @($_.usns)
            locations = @($_.locations | ForEach-Object { Protect-BvsUrl $_ }); described = $_.described
            friendlyName = $_.friendlyName; manufacturer = $_.manufacturer; modelName = $_.modelName; modelNumber = $_.modelNumber; deviceType = $_.deviceType
            typeGuess = $null
        }
    })
foreach ($s in $ssdpList) { $s.typeGuess = ($devList | Where-Object ip -eq $s.ip | Select-Object -First 1).typeGuess }

Add-BvsInventory -Run $run -Name 'summary' -Data $summary
Add-BvsInventory -Run $run -Name 'network' -Data $netInfo
Add-BvsInventory -Run $run -Name 'devices' -Data @($devList)
Add-BvsInventory -Run $run -Name 'router' -Data $script:Router
Add-BvsInventory -Run $run -Name 'upnpMappings' -Data @($mapRows)
Add-BvsInventory -Run $run -Name 'ssdpResponders' -Data $ssdpList
Add-BvsInventory -Run $run -Name 'upnpStacks' -Data @($stackRows)
Add-BvsInventory -Run $run -Name 'arpAnomalies' -Data @($arpAnomalies)
Add-BvsInventory -Run $run -Name 'vendorLookup' -Data $ouiResult
Add-BvsInventory -Run $run -Name 'questions' -Data @($questions)

$done = Complete-BvsRun -Run $run

#endregion

#region ---------- short console summary (masked, ~30 lines) ----------

$out = [System.Collections.Generic.List[string]]::new()
if ($script:Net) {
    $out.Add(("S08 LAN: {0} {1} gw {2} profile '{3}' ({4}) active={5}" -f $script:Net.Alias, "$($script:Net.LocalIp)/$($script:Net.Prefix)", $script:Net.Gateway, $script:Net.ProfileName, $script:Net.Category, $script:Active))
}
if ($script:Refusal) { $out.Add("  note: $($script:Refusal)") }
$out.Add(("devices: {0} total, {1} others ({2} unidentified, {3} randomized MAC); types: {4}" -f $devList.Count, $others.Count, $unknownDevs.Count, $randomDevs.Count, (($summary.byType.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')))
foreach ($d in ($devList | Select-Object -First 24)) {
    $flags = @($(if ($d.isThisPc) { 'this-PC' }), $(if ($d.isGateway) { 'gateway' }), $(if ($d.randomizedMac) { 'randomMAC' })) | Where-Object { $_ }
    $out.Add(("  {0,-15} {1,-17} {2,-12} {3,-26} {4,-28} [{5}] {6}" -f $d.ip, $d.mac, $d.typeGuess, (Get-S08Text $d.vendor 26), (Get-S08Text $d.hostname 28), ($d.seenBy -join ','), ($flags -join ',')))
}
$out.Add(("router: {0} title='{1}' plainHttp={2} upnp={3} ({4}) mappings={5} tr064={6} stacks={7}" -f $script:Router.upnp.modelName, $script:Router.httpTitle, $script:Router.plainHttp, $script:Upnp.igdFound, $script:Upnp.enumeration, $script:Mappings.Count, $script:Router.tr064Advertised, (($script:Router.upnpStacks | ForEach-Object { "$($_.product) $($_.version)$(if ($_.vulnerable) { '!' })" }) -join ', ')))
foreach ($r in ($mapRows | Select-Object -First 8)) { $out.Add(("  map {0} {1} -> {2}:{3} '{4}' => {5} ({6})" -f $r.protocol, $r.externalPort, $r.internalClient, $r.internalPort, $r.description, $r.severity, $r.assessment)) }
$out.Add(("ssdp responders: {0}" -f (($ssdpList | ForEach-Object { "$($_.ip)=$(Get-S08Text (@($_.servers) | Select-Object -First 1) 50)" }) -join '; ')))
$out.Add(("findings: {0} [{1}] checks={2} errors={3}" -f $done.Findings, $done.BySeverity, $done.Checks, $done.Errors))
foreach ($c in ($run.Checks | Where-Object { $_.status -ne 'ok' })) { $out.Add(("  check {0}: {1} {2}" -f $c.id, $c.status, (Get-S08Text $c.reason 110))) }
$out.Add("output: $($done.Path)")
$out | ForEach-Object { Protect-BvsText $_ }

#endregion
