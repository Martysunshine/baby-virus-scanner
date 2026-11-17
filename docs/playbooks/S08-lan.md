# S08 - LAN device discovery

Collector: `src\collectors\security\windows\S08-lan.ps1` - Output: `data\<scanId>\security\S08.json` (`bvs.module/1`)

## (a) Brief

Build and run the LAN discovery module: which devices share this PC's network, and which ports
the router forwards to them. Read-only, and passive unless the user agreed to active discovery.

1. **Passive first:** read this PC's ARP cache for the LAN adapter (the one holding the IPv4
   default route). VPN and virtual adapters are ignored.
2. **Active steps, only with `-Active`** and only when the network gates hold (Private profile,
   RFC 1918 addressing, prefix /22 or longer):
   - ping sweep of the subnet, then re-read the ARP cache for MAC addresses;
   - names: reverse DNS through the router, NetBIOS (`nbtstat -A`), mDNS;
   - vendor from the IEEE OUI list (downloaded once through `Invoke-BvsIntel`, cached under `intel\`);
   - one HTTP GET of the router's start page (title only; no logins, no forms);
   - SSDP discovery, the router's UPnP description, and the read-only SOAP action
     `GetGenericPortMappingEntry` to list port-forwards.
3. **Never:** port scans of other devices, logins, brute force, state-changing UPnP actions,
   ARP cache changes.
4. **Findings:** unknown devices are not findings by themselves; they go into the device table
   with a question for the user. Risky port-forwards are rated (a sensitive port on this PC is
   high). UPnP enabled and an admin page on plain HTTP are hardening information.
5. **Deliverables:** the collector, `data\<scanId>\security\S08.json`, this playbook, and a short
   final message (device summary, risky port-forwards, coverage gaps, questions for the user).


## (b) Implementation

### Safety design

Discovery is passive by default. It becomes *active* only when the user agreed (`-Active`, which
`bvs.ps1 scan -Lan` passes) **and** every network gate holds. The gates are evaluated on the
adapter that carries the IPv4 default route. VPN and virtual adapters (Tailscale, VirtualBox,
Hyper-V, WSL, WireGuard, OpenVPN, ZeroTier and others) are excluded by name/description.

| Gate | Refuses when |
|---|---|
| Prefix | shorter than /22 (more than 1022 hosts), or /31 and longer (no other hosts) |
| Network profile | `Public`, `DomainAuthenticated` (managed or corporate network) or unknown. Only `Private` passes. |
| Addressing | local address or gateway outside RFC1918 |

Without `-Active`, or if a gate fails, only the ARP cache is read and the IEEE vendor list is
used. Every active check is then recorded as `skipped`, with the reason.

**What is sent on the LAN (active mode only):**
- ICMP echo to every host address;
- reverse-DNS queries to the gateway;
- `nbtstat -A` node-status queries to hosts that answered;
- mDNS legacy-unicast queries: one reverse PTR per live host, plus one DNS-SD `_services._dns-sd._udp.local` query (sent twice);
- SSDP M-SEARCH, 2 search targets, each sent twice;
- one ping to hosts first seen through SSDP/mDNS, so the ARP cache learns their MAC;
- one GET of `http://<gateway>/`;
- a GET of the IGD description XML from the router;
- the read-only SOAP action `GetGenericPortMappingEntry`, index 0..n.

**What is never sent:**
- port scans;
- logins or form posts;
- state-changing UPnP actions (`AddPortMapping`, `DeletePortMapping`, ...);
- ARP changes;
- TR-064 actions;
- anything to the internet except the IEEE list download.

**Defensive parsing of device data:**
- Description XML is parsed with `DtdProcessing=Prohibit`, no resolver and a size cap.
- The DNS decoder is bounds-checked and guarded against pointer loops.
- SOAP is only POSTed to the host that served the description, and that host must be inside the LAN subnet.
- `LOCATION` URLs must name the responder's own IP.
- Every device string is stripped of control characters, length-capped and screened for prompt
  injection (rule §4).

### Checks

| Check | Source | What it does |
|---|---|---|
| `lan.interface` | `Get-NetRoute 0.0.0.0/0`, `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetConnectionProfile` | Picks the adapter, derives the subnet, applies the gates |
| `lan.arp_passive` | `Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex` | Reads unicast entries with a MAC inside the subnet (Unreachable/Incomplete and multicast dropped) |
| `lan.ping_sweep` | `System.Net.NetworkInformation.Ping`, `ForEach-Object -Parallel -ThrottleLimit 64` | 1000 ms timeout, second attempt only after a failure; records RTT and TTL |
| `lan.arp_after_sweep` | `Get-NetNeighbor` | MACs, plus hosts that answer ARP but drop ICMP (state Reachable/Delay/Probe = answered) |
| `lan.ssdp` | `UdpClient` bound to the LAN IP, `IP_MULTICAST_IF`, TTL 2, loopback off | M-SEARCH (IGD:1 and `ssdp:all`, MX 2), 3.2 s listen; records SERVER, ST, USN and LOCATION per responder |
| `lan.upnp_stack` | SSDP `SERVER` banners | libupnp < 1.6.18 (CVE-2012-5958 to 5965, SSDP remote code execution); libupnp < 1.6.21 (CVE-2016-6255, CVE-2016-8863); MiniUPnPd < 1.4 (CVE-2013-0229/0230) |
| `lan.names_mdns` | `UdpClient` to 224.0.0.251:5353 from an ephemeral port, so responders answer by unicast (RFC 6762 §6.7) | Reverse PTR, DNS-SD service types, instance names, A/SRV host names |
| `lan.late_ping` | `Ping` | One echo to hosts first seen through SSDP/mDNS, then an ARP re-read |
| `lan.names_ptr` | `Resolve-DnsName -Type PTR -Server <gateway> -DnsOnly -QuickTimeout` | The router's DHCP names (for example `router.home` or a PC's computer name) |
| `lan.names_netbios` | `nbtstat -A <ip>`, 16 parallel | Computer name, workgroup and `<20>` server flag. GROUP/UNIQUE is decided by the type word of the `<1E>`/`<1C>` entries, so a localized `nbtstat` still parses. |
| `lan.vendor_oui` | `Invoke-BvsIntel https://standards-oui.ieee.org/oui/oui.csv` | Cached as `intel\standards-oui.ieee.org\<stamp>-oui.csv` and refreshed after 30 days (`-OuiMaxAgeDays`). A stale cache is used if the download fails. Only the needed OUIs are extracted, by streaming. |
| `lan.router_http` | `Invoke-BvsIntel -AllowLan http://<gateway>/` | `<title>` only, with HTML entities decoded. Plain HTTP when the final URL is `http` and the status is 200/401/403. |
| `lan.upnp_igd` | `Invoke-BvsIntel -AllowLan` | Up to 3 description documents (IGD-typed responses first, gateway otherwise); `URLBase`/`controlURL` resolution; SOAP loop up to 256 entries. Stops on UPnP error 713/714 (normal end), 606 (denied), a repeated entry or an HTTP error. |
| `lan.upnp_com` | `HNetCfg.NATUPnP.StaticPortMappingCollection` | Only runs if SOAP did not complete. Executed in a `-Parallel` runspace with a 30 s timeout, so a hanging COM call cannot block the run. |
| `lan.device_identify` | All of the above | Best name (mDNS, then NetBIOS, then PTR), type guess with reasons, `expected.json` host match, census finding |
| `lan.upnp_assess` | Mappings plus devices; `Get-NetTCPConnection`/`Get-NetUDPEndpoint` for this PC only | Rates each port-forward (table below) and names the local process that owns the port |
| `lan.arp_anomalies` | Device table | One MAC answering for several IPs; gateway MAC changed during the scan (possible ARP spoofing, T1557.002) |
| `lan.untrusted_text` | Every string read from devices | Prompt-injection screen (`ignore previous instructions`, `<script`, `curl http…`, ...) |

### Heuristics

**Randomized MAC.** The locally administered bit (0x02 of the first octet, so the second hex digit
is 2, 6, A or E) is set. Such MACs have no meaningful OUI, so no vendor lookup is attempted.

**Type guess.** Each device collects points from four sources:
- the IEEE organisation name;
- host names (PTR, NetBIOS, mDNS, mDNS instance names);
- mDNS service types (`_ipp`, `_googlecast`, `_hap`, `_matter`, `_apple-mobdev2`, `_smb`, ...);
- SSDP search targets, SERVER banners and description fields.

Fixed bonuses are added: default gateway +10 router; randomized MAC +3 phone/tablet; ICMP TTL 128
+2 laptop/PC; NetBIOS answer +2 laptop/PC; NetBIOS `<20>` +2 laptop/PC. The best score of 3 or more
wins; confidence is high at 8 or more, medium at 5 or more, low otherwise. Ambiguous vendors
(Samsung, Apple, Google, Amazon, Xiaomi, Huawei, TP-Link) give only 1 point, so they rarely decide
alone. The winning reasons are stored in `typeReason`. The signal table lives in the collector
(`$script:TypeSignals`); extend it there.

**Port-forward rating** (`lan.upnp_assess`):

| Condition | Severity / class |
|---|---|
| Internal client is this PC and the internal or external port is in `$script:SensitivePorts` (21, 22, 23, 80, 135-139, 443, 445, 1433, 2375/6, 3306, 3389, 5432, 5900/1, 5985/6, 6379, 8000, 8080, 8443, 8888, 9200, 11434, 27017 …) | **high / suspicious** |
| Any other device with a remote-admin, file-sharing or database port (`$script:CriticalPorts`) | **high / suspicious** |
| Matches `expected.json` category `network`: the item's service owns the port, or the item's name appears in the description | expected (no finding) |
| Known application: Tailscale (UDP 41641 or "tailscale" in the description), Steam ports, consoles (Xbox, PSN, Nintendo) by description, or by port when the device looks like a console | expected (no finding) |
| Other device whose client address is outside the LAN subnet | medium / hardening |
| Other device on another sensitive port | medium / hardening |
| Other device, anything else (unconfirmed device) | medium / hardening |
| This PC, non-sensitive port, unknown application | low / hardening (with the owning process) |
| Mapping disabled | high and medium are capped at low |

**Machine-specific items** come only from `src\config\local\expected.json`, through `Get-BvsExpected`:
- category `hosts` annotates devices whose name matches, for example the Tailscale peer list
  (`confirmWithUser` is kept, so the user is still asked);
- category `network` can mark a port-forward to this PC as expected.

### Findings produced

| Check | Finding | Severity / class |
|---|---|---|
| `lan.upnp_assess` | Risky or unconfirmed port-forward | see table above |
| `lan.upnp_stack` | Outdated UPnP stack banner | medium (RCE-class on the gateway), low (other cases on the gateway, or RCE-class on other devices), info; hardening, confidence low |
| `lan.upnp_igd` | UPnP IGD enabled (model, mapping count, TR-064 advertised) | info / hardening |
| `lan.router_http` | Admin page on plain HTTP. Confidence high from the GET; low when only inferred from the description's `presentationURL` because the GET hit an unfollowable redirect. | info / hardening |
| `lan.device_identify` | LAN census and "please confirm you recognise them" (prefixed "Many devices" at 5 or more unknown/randomized) | info / info |
| `lan.arp_anomalies` | Gateway MAC shared or changed | medium / suspicious, confidence low |
| `lan.untrusted_text` | Instruction-like text in device data | medium / suspicious |

Unknown devices alone never create a finding above info. They go into `devices` and `questions`.

### Inventory (`envelope.inventory`)

| Key | Content |
|---|---|
| `summary` | Counts, by type, UPnP state, risky mappings |
| `network` | Adapter, subnet, gateway, profile name/category, gate result, probe settings |
| `devices` | `ip`, `mac`, `vendor`, `randomizedMac`, `hostname`, `ptr[]`, `netbios`, `netbiosGroup`, `mdnsNames[]`, `mdnsInstances[]`, `mdnsServices[]`, `ssdpServer`, `ssdpFriendlyName`, `typeGuess`, `typeConfidence`, `typeReason[]`, `seenBy[]` (self, arp, ping, ssdp, mdns, netbios), `answeredThisScan`, `arpState`, `rttMs`, `ttl`, `isGateway`, `isThisPc`, `upnpMappings`, `expected`, `needsUserConfirmation` |
| `router` | IP, MAC, vendor, HTTP status/final URL/title, `httpServer` (null, see gaps), `httpNote`, `plainHttp` plus `plainHttpBasis`, `presentationUrl`, SSDP banners, `tr064Advertised`, `upnpStacks`, `upnp` (enabled, enumeration, stop code, WAN services, model, descriptions) |
| `upnpMappings` | One row per mapping: external port, protocol, internal client, internal port, description, enabled, lease (0 = permanent), remote host, target, sensitive, local process, known app, expected, severity, assessment |
| `ssdpResponders` | Per IP: SERVER banners, search targets, USN UUIDs, LOCATIONs (query strings removed), description fields when fetched, type guess |
| `upnpStacks` | Parsed banner versions and vulnerability verdicts |
| `arpAnomalies`, `vendorLookup`, `questions` | As named |

### Expected false positives

- **Randomized MACs on computers.** Windows "random hardware addresses" and macOS private Wi-Fi
  addresses look like phones; a host name usually corrects this (for example a randomized-MAC
  host whose DHCP name says it is a computer).
- **Module vendors.** The OUI owner is often the Wi-Fi chip or module maker, not the device brand
  (for example a cellular-module maker on a laptop, or Tuya, Espressif, AzureWave and Murata on
  smart-home devices).
- **Sleepy devices.** Power-saving IoT devices and phones answer in one run and not the next.
  Treat a missing device as "not seen", not "gone".
- **Banner-only versions.** Vendors back-port fixes without changing the libupnp version string.
- **Shared MACs.** Routers with several LAN addresses, or repeaters in proxy-ARP mode, share a MAC
  without any ARP spoofing.
- **Inferred plain HTTP.** When only `presentationURL` is available, the admin page could still
  redirect to HTTPS.

### Coverage gaps

- **Router `Server` header not collected.** `Invoke-BvsIntel` does not return response headers.
- **Router page title may be missing.** Some routers answer `/` with a redirect to a login page;
  the title is only collected when the final page is reached without a login.
- **Manual port-forwards and DMZ are not listed.** IGD `GetGenericPortMappingEntry` usually lists
  only UPnP-created entries. Forwards configured in the router UI need a router login, which is
  outside consent; ask the user.
- **TR-064 is not queried.** Many routers advertise TR-064 (`urn:dslforum-org`: hosts list, Wi-Fi
  configuration, ...). Querying it needs authentication and is outside consent.
- **Hidden devices.** Not seen: devices that ignore ICMP and are asleep at ARP time, devices on
  guest/isolated SSIDs or other VLANs, and IPv6-only devices (there is no IPv6 neighbour sweep).
- **NetBIOS is slow** (`nbtstat` takes about 13 s waiting for silent hosts). LLMNR is not implemented.
- **mDNS is partial:** only reverse PTR and the service list; no per-service instance or TXT
  browsing.
- **SSDP descriptions** are fetched only from IGD responders or the gateway. Other responders are
  listed from their SSDP headers only (consent boundary).
- **OUI lookup** uses the MA-L list only; MA-M, MA-S and IAB blocks are unresolved.
- **The NATUPnP fallback** returns nothing when the Windows UPnP framework or network discovery
  is off.
- **Snapshot only:** devices that join later are not seen.

### Ideas for v2

- Baseline and diff between scans ("new device since last scan"), plus user-confirmed devices kept
  in `src\config\local\expected.json` (category `lanDevice`, keyed by MAC) so that questions are not
  repeated.
- Native NBSTAT over UDP 137 (one packet, short timeout) to replace `nbtstat`.
- IPv6 neighbour discovery (`Get-NetNeighbor -AddressFamily IPv6`, an echo to ff02::1).
- NAT-PMP/PCP mapping listing (UDP 5351).
- mDNS `_device-info` TXT (model) and instance browsing for printers and TVs.
- MA-M/MA-S lists, plus Wireshark `manuf` as a fallback (needs an allowlist entry).
- An optional, consented TR-064 `Hosts`/`GetGenericHostEntry` read for the router's DHCP list.
- An external check that UPnP and the router admin page are not exposed on the WAN side.

### Linux equivalent

The Linux collector should emit the same `bvs.module/1` shapes, check IDs and inventory keys.

| Step | Linux |
|---|---|
| Adapter, subnet, gateway | `ip -4 route show default` (dev + via), `ip -4 -o addr show dev <if>` (address/prefix) |
| Profile gate | No "Public" profile on Linux. Use the NetworkManager connection zone (`nmcli -g connection.zone con show <name>`) or the firewalld zone (`firewall-cmd --get-zone-of-interface=<if>`) and treat `public`/`external`/`block`/`drop` as Public. Same prefix and RFC1918 gates. Network name: `nmcli -t -f NAME,DEVICE con show --active` or `iwgetid -r`. |
| Passive ARP | `ip -4 neigh show dev <if>` (states REACHABLE/STALE/DELAY/PROBE/FAILED; skip FAILED/INCOMPLETE) |
| Ping sweep | `fping -a -q -r 1 -t 1000 -g <net>/<prefix>`, or `seq 1 254 \| xargs -P 64 -I{} ping -c1 -W1 <net>.{}`, then `ip neigh` again. `arp-scan` needs root and is not required. |
| Vendor | `/usr/share/ieee-data/oui.csv` (package `ieee-data`) or the same IEEE download into `intel/`; identical locally administered bit test |
| Reverse DNS | `dig -x <ip> @<gateway> +short +time=1 +tries=1` (or `host <ip> <gateway>`) |
| NetBIOS | `nmblookup -A <ip>` (Samba client) |
| mDNS | `avahi-browse -a -r -t -p` (services, instances, addresses); `avahi-resolve -a <ip>` (reverse name) |
| SSDP | `gssdp-discover -t ssdp:all -n 3 -i <if>` (gupnp-tools), or a small socket script sending the same M-SEARCH |
| UPnP port-forwards | `upnpc -l` (miniupnpc) prints the IGD, its control URL and every `GetGenericPortMappingEntry` row, read-only. Never call `upnpc -a`/`-d`/`-r`, which change mappings. |
| Router title | `curl -s -m 8 --max-redirs 3 http://<gateway>/` (title only; `-I` for the Server header) via the Linux intel wrapper |
| Port owner (this PC) | `ss -lntup 'sport = :<port>'` |
| ARP anomaly | `ip neigh` grouped by `lladdr` |

## (c) Run

| | |
|---|---|
| Lint | `pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S08-lan.ps1`: OK (0 fail, 1 warn: COM object `HNetCfg.NATUPnP`, read-only enumeration only) |
| Command (passive, the default) | `pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S08-lan.ps1` |
| Command (active, after the user agreed) | the same with `-Active`, or `pwsh -File .\bvs.ps1 scan -Lan` |
| Other options | `-OuiMaxAgeDays`, `-PingTimeoutMs`, `-PingAttempts`, `-ThrottleLimit`; `-PassiveOnly` is kept for older commands |
| Runtime | About 6 s passive. About 35 s active on a /24 network (ping sweep, NetBIOS, SSDP, mDNS, and a one-time download of the IEEE list). |
| Output | `data\<scanId>\security\S08.json` |
| Log | `logs\S08.log` |
| Intel cache and evidence | `intel\standards-oui.ieee.org\<stamp>-oui.csv`; in active mode also `intel\<gateway-ip>\<stamp>-upnp-description.xml` and `intel\<gateway-ip>\<stamp>-upnp-GetGenericPortMappingEntry-<n>.xml` (each with `.meta.json`) |

**Known library limitation.** `Invoke-BvsIntel` does not return response headers, so the router's
`Server` header is not collected.
