# S07-network

> Generated from the collector's own code by `src/tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File src\tools\windows\gen-playbook.ps1 -Path src\collectors\security\windows\S07-network.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S07 Network: live connections, listeners and LAN/tailnet exposure, Windows Firewall, DNS
integrity (hijack / MITM / WPAD / ARP / IPv6 RA), Wi-Fi security, SMB/NetBIOS and Tailscale.
Strictly read-only.

```text
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
```

## (b) Implementation

Collector: `src\collectors\security\windows\S07-network.ps1`. Library: `src\lib\windows\BVS.Common.psm1`.

| Check | What it does |
|---|---|
| `net.context` | Interfaces, IP addresses, network profiles, default gateways and process table |
| `intel.tor_exits` | Tor bulk exit list (check.torproject.org) for connection context |
| `intel.feodo` | abuse.ch Feodo Tracker botnet C2 IP list (public download, no key) |
| `ts.status` | tailscale status --json: peers, owners (shared-in), exit node, tags, last seen |
| `ts.prefs` | tailscale debug prefs (Persist/Config node keys dropped): ControlURL, RunSSH, routes, exit node, ShieldsUp |
| `ts.serve_funnel` | tailscale serve status / funnel status (Funnel = internet exposure) |
| `fw.profiles` | Windows Firewall profiles (effective): Enabled, DefaultInboundAction, NotifyOnListen; Security Center firewall products |
| `net.listeners` | All TCP listeners and UDP endpoints mapped to process, service, path and signer |
| `net.exposure` | Exposure matrix: every non-loopback listener x active interface (LAN, tailnet, virtual) through Windows Firewall rules |
| `fw.rules_of_interest` | Inbound allow rules for user-writable or missing programs; any-program rules on all profiles; known app and expected rules |
| `smb.shares` | SMB shares (Get-SmbShare, fallback net share) and share permissions |
| `smb.connections` | Outgoing SMB sessions (Get-SmbConnection, fallback net use) |
| `smb.config` | SMB1 server/client, signing and insecure guest logons (registry) |
| `smb.netbios` | NetBIOS over TCP/IP per interface, LLMNR and mDNS policy |
| `smb.fps_rules` | File and Printer Sharing rules by profile; what 445/139/135 expose to the LAN and the tailnet |
| `cfg.ollama` | Ollama: OLLAMA_HOST/OLLAMA_ORIGINS (User/Machine) and the API listener address |
| `cfg.virtualbox` | VirtualBox: VMs, NAT port forwards (host IP must be 127.0.0.1), NAT networks, VRDE, bridged NICs |
| `cfg.docker` | Docker Desktop: exposeDockerAPIOnTCP2375 must be false; listeners on 2375/2376 |
| `cfg.claude_ide_locks` | ~\.claude\ide\*.lock: port and pid only (authToken never read into output); listener must be loopback |
| `cfg.debug_ports` | Listeners on 9222 (Chromium DevTools) and 9229 (Node inspector) |
| `dns.servers` | DNS servers per interface (static vs DHCP) classified: router, tailscale, known public, unknown |
| `dns.doh` | DNS-over-HTTPS server table (Get-DnsClientDohServerAddress) |
| `dns.nrpt` | Name Resolution Policy Table (effective), e.g. Tailscale MagicDNS |
| `dns.cache` | DNS client cache: total count and ONLY flagged entries (tunnels, request catchers, paste/transfer, Telegram API, Discord CDN, abused TLDs, DGA-like) |
| `dns.hijack` | Router vs DoH answers for 6 well-known names; TLS issuer of router answers with normal validation |
| `dns.nxdomain` | NXDOMAIN probe: a random 20-character .com name sent to the router must fail |
| `dns.wpad` | WPAD: wpad.<suffix> (DNS) and wpad (LLMNR/NetBIOS) must not resolve |
| `dns.gateway_arp` | Gateway MAC must be unique in the IPv4 neighbor (ARP) table |
| `dns.ipv6_routers` | IPv6 default-route router advertisements per interface |
| `wifi.interfaces` | netsh wlan show interfaces: SSID, authentication, cipher, connection mode |
| `wifi.profiles` | Saved Wi-Fi profiles (no key material): authentication, cipher, connection mode; open/WEP auto-connect |
| `conn.sampling` | Get-NetTCPConnection (Established, SynSent) + Get-NetUDPEndpoint, $Samples samples $IntervalSec s apart (own PID excluded) |
| `conn.rdns` | Reverse DNS (PTR) for public remote IPs: cached, short timeout, capped |
| `conn.analysis` | Classify remote ends (loopback, RFC1918, tailscale, link-local, multicast, public) and map to process/path/signer |
| `conn.untrusted_public` | Unsigned, invalid-signature, masquerading or user-writable processes with public connections |
| `conn.suspicious_ports` | Connections to backdoor / Tor / mining ports |
| `conn.beaconing` | Repeated short-lived connections (new local port each time) to the same remote across samples; repeated SYN_SENT |
| `conn.intel_match` | Remote IPs on the Tor exit list or the Feodo Tracker C2 list; flagged PTR names (tunnels, paste, webhooks) |

Parameters: `-Samples`, `-IntervalSec`, `-NoIntel`, `-NoTlsProbe`, `-MaxReverseDns`, `-ScanId`.

## (c) Run

```powershell
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S07-network.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S07-network.ps1
```

Output: `data\<scanId>\security\S07.json` (`bvs.module/1`). Log: `logs\S07.log`.
