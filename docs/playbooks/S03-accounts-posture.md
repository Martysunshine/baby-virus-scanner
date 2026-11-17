# S03 - Accounts, remote access & security posture

## (a) Brief (condensed)
Build `src\collectors\security\windows\S03-accounts-posture.ps1` (read-only, `BVS.Common.psm1`, lint before run).
1. **Accounts**: Get-LocalUser (Name, Enabled, SID, LastLogon, PasswordLastSet, PasswordRequired, Description);
   group members by SID (Administrators -544, Remote Desktop Users -555, Remote Management Users -580,
   Backup Operators -551, Hyper-V Administrators -578); hidden users (Winlogon\SpecialAccounts\UserList);
   ProfileList SIDs/paths/folder creation dates, flag profiles created in the last 90 days; expected accounts
   (Administrator/Guest disabled, owner, DefaultAccount, WDAGUtilityAccount, and non-admin sandbox accounts of
   developer tools when `expected.json` lists them).
2. **Remote access**: RDP fDenyTSConnections; TermService ServiceDll = %SystemRoot%\System32\termsrv.dll, RDPWrap;
   Remote Assistance fAllowToGetHelp; OpenSSH server (sshd, ProgramData\ssh, administrators_authorized_keys,
   ~\.ssh\authorized_keys); ssh-agent; WinRM; Quick Assist (info).
3. **Remote-control/RMM/RAT/tunnel inventory** from services, processes, uninstall entries (HKLM, WOW6432Node,
   HKCU), folder names (Program Files, ProgramData, AppData) and scheduled-task actions; ~45 named tools incl.
   NetSupport client32 (ClickFix), tunnels (ngrok, cloudflared, frpc, chisel, plink, ligolo), VPN overlays and
   game-stream hosts (Sunshine). A VPN the user installed on purpose is marked expected through `expected.json`.
4. **Posture**: UAC, SmartScreen, Smart App Control, Secure Boot, VBS/HVCI, driver blocklist, LSA RunAsPPL,
   Credential Guard, Windows Update (last hotfix, pause/disable policies, service), Security Center AV/firewall
   (decoded productState), Defender-disabling policies, firewall profiles, PowerShell execution policy (all scopes)
   and script-block logging, AutoRun, WSH, SMB1, BitLocker (needs_admin if required).
5. **Root certificates** (MITM): HKLM ROOT/AuthRoot/Disallowed/TrustedPublisher, HKCU Root (user-added), policy and
   enterprise stores; Cert: objects; compare with Microsoft's authroot.stl (signed CAB via Invoke-BvsIntel, fallback
   cached EncodedCtl); unexplained root = high (an antivirus HTTPS-scanning root, such as Avast Web/Mail Shield Root,
   is expected while that product is installed); registry LastWrite ~ added date.
6. **Hosts & proxy**: hosts entries vs expected.json (Docker, antivirus local-server entries, VPN peer names - confirm);
   WinINET (incl. AutoConfigURL), WinHTTP, *_PROXY env vars, NODE_OPTIONS/NODE_EXTRA_CA_CERTS; unexplained proxy = high.
Inventory: accounts, posture table, RMM inventory, roots, hosts/proxy. Output `data\<scan>\security\S03.json`.

## (b) Implementation
- **Files**: collector + sidecars `S03-remote-tools.json` (55 tools: exe/client/file names, service/product/publisher/
  folder regexes, known paths, Linux process/service/path hints - reusable by a Linux collector) and
  `S03-reference.json` (Windows built-in roots outside the CTL, CTL URL, sensitive domains, Avast explainers).
- **Expected logic**: `Resolve-Exp` evaluates each `invalidIf` it understands (signer, Avast installed/on/current,
  Avast-root count, admin membership); unknown conditions are recorded as `result: null` (not evaluated). A valid
  match caps severity at info/`severityCap`; a cancelled match adds `expected_cancelled` and keeps full severity.
- **Accounts**: RID roles (500/501/503/504), current user from the run SID; unknown enabled account = medium
  (high if admin/hidden); extra Administrators member = high; hidden enabled non-expected account = high (T1564.002);
  new profile (<90 d) = medium/high; Backup Operators member = high; PASSWD_NOTREQD on enabled account = medium.
- **Remote**: RDP enabled on Home = high (only possible via RDPWrap/patched termsrv); ServiceDll mismatch or invalid
  termsrv.dll signature = high; Remote Assistance = medium hardening (capped low by expected.json); WinRM/sshd = medium.
- **RMM**: every source records hits; per tool: running, autostart (service Auto, enabled task, Run key), installed,
  folder-only, download-only, viewer-only, signatures/hashes of matched binaries. Remote tool running/autostart = high,
  installed = medium, leftover/downloaded = low; tunnels likewise; VPN/game-stream/OEM = medium/low; NetSupport outside
  Program Files = high (clickfix_pattern). Process matching uses executable names only, never command lines.
- **Roots**: registry physical stores give membership + LastWrite; Cert: drive (blob fallback) gives the object; CTL
  parsed in-process (SignedCms + AsnReader, signature checked). Not in CTL, not built-in, not expected = high (medium
  if no CTL and old). Logical-store roots missing from every physical store = high.
- **Hosts/proxy**: DataBasePath redirection, hosts ACL, sections (Docker/Tailscale), own MagicDNS name, sensitive-domain
  and public-IP redirects = high; loopback proxies explained only if the listening process is Avast/Gen-signed.
- **Expected false positives**: second household accounts, developer tunnels (ngrok/cloudflared), corporate TLS
  inspection/debug proxies, OEM remote features, Avast rewriting its root key at boot (LastWrite is not an install date).
- **Coverage gaps**: Security log logon types (admin) for account `invalidIf` conditions; Defender local exclusions,
  Defender "Policy Manager" subkey, WSMAN listeners and BitLocker details need admin; other users' AppData not swept;
  ClickOnce (Apps\2.0) and deep (>3 levels) portable binaries not swept. If the fresh authroot CAB cannot be
  downloaded, the cached EncodedCtl from the registry is used instead.
- **v2 ideas**: LOLRMM intel feed; ScreenConnect/AnyDesk config relay IDs; per-user hive sweep when elevated;
  WinGet/npm shims for tunnels. **Linux equivalent**: `getent passwd/group` (sudo/wheel), `/etc/sudoers*`,
  sshd_config + authorized_keys, `systemctl`/`ps` against the same catalog `linux` hints, `/etc/hosts`,
  `*_proxy` env + `/etc/environment`, `/usr/local/share/ca-certificates` vs distro CA bundle, UFW/nftables, Secure Boot
  via `mokutil --sb-state`, unattended-upgrades.

## (c) Run
```
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S03-accounts-posture.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S03-accounts-posture.ps1 [-Offline] [-RecentDays 90] [-SweepDepth 3]
```
- Lint: 0 fail, 6 warn (read-only COM: Microsoft.Update.Session, Shell.Application; `expand.exe`; catalog helper).
- Runtime about 30 s to 1.5 minutes, non-elevated. Output `data\<scanId>\security\S03.json`, log `logs\S03.log`,
  CTL download under `intel\ctldl.windowsupdate.com\`.
