# S06 Browsers - playbook

## (a) Brief (condensed)

- Build `src\collectors\security\windows\S06-browsers.ps1` (read-only; follow `docs\agent-rules.md`; never open Login Data,
  Cookies, History, Web Data, Local Storage, IndexedDB, Local Extension Settings or Sessions; use Test-BvsNeverRead).
- Discover Chrome/Edge profiles dynamically (Local State `profile.info_cache` + folders); open prefs files with sharing.
- **Extensions** per profile: manifest name (resolve `__MSG_x__`), version, manifest_version, permissions,
  host/optional permissions, content-script matches, background, update_url; from Preferences/Secure Preferences:
  location (1 store, 4 unpacked, 8 command line, 2/3/6 external, 7/9 policy, 5/10 component), from_webstore,
  install time (us since 1601), state/disable_reasons, granted permissions, by-default/OEM.
- Flag non-store update_url, folders without prefs entry, unpacked paths outside the profile, registry external
  registrations (HKLM/HKCU, WOW6432Node), ExtensionInstallForcelist / ExtensionSettings policies.
- Risk tiers; top = all sites + webRequest/DNR/scripting/cookies/debugger/proxy/nativeMessaging/management/
  clipboardRead/history/downloads, or content scripts on every site.
- Intel: public malicious-ID lists via Invoke-BvsIntel (palant, toborrm9); exact match enabled = critical,
  disabled = high. Store existence with soft-404 check; removed from store = medium.
- Wallet extensions = info (high-value target). Expected items from `src\config\local\expected.json`.
- **Hijacks**: search provider, homepage, startup pages, extension URL/settings overrides, DoH, chrome://flags.
- **Site permissions**: notifications/popups/automatic_downloads allowed; output only flagged origins (raw IP,
  captcha/verify/allow/robot/human words, random labels, .top/.xyz/.click/.online/.icu/.cyou/.rest/.shop) + totals.
- **Launch args**: shortcuts (Desktop, Public, Start Menus, Taskbar, Quick Launch; WScript.Shell, never Save) and
  running main processes: remote debugging (critical candidate), load-extension, Temp user-data-dir,
  disable-web-security, no-sandbox, appended URL, non-browser target. Browser listener on 9222/9229 = critical candidate.
- **Native messaging hosts**: manifest, host exe + signer, allowed_origins, installed?  **Versions** (info).
- Deliverables: collector, `data\<scan>\security\S06.json`, this playbook, short final report.

## (b) Implementation

| Check id | Source | Heuristic / severity |
|---|---|---|
| browser.discovery | Local State + folders, exe version/signature | info; invalid signature = high |
| browser.extensions.inventory | Secure Preferences + Preferences `extensions.settings` merged (secure wins), `Extensions\<id>\<ver>\manifest.json` (prefs `manifest` fallback), `_locales` | inventory only; settings-only stubs (no location/manifest/folder) listed separately |
| browser.intel.sources / extensions.intel | toborrm9 `malicious_extensions_detailed.csv` (cached 12 h in `intel\`), palant list (Codeberg) | enabled = critical (compromise if reason Malware/Spyware...), disabled = high, stub = medium |
| browser.extensions.store | Chrome `cws-info` (is-present, is-live, violation-type) offline; lookups only for enabled non-store or top-tier extensions without cws-info | removed = medium; store malware violation = critical/high; circuit breaker after 2 host failures |
| browser.extensions.risk | location, path tags, update host, blocklist state, tiers, developer mode, expected hygiene | sideload high/medium; self-hosted medium/high; orphan low/medium; top-tier aggregate = low hardening; dev mode low; bundleware = expected cap |
| browser.extensions.external_registrations | HKLM 64/32 + HKCU `<vendor>\Extensions` | store-hosted = low hygiene (folded into bundleware finding), off-store medium, local CRX/intel high |
| browser.policies | `Software\Policies\<vendor>` (+ Google/Edge Update) | forcelist/hijack/proxy/security = high (medium if domain-joined); updates off = medium |
| browser.hijack | template_url_data + mirrored, homepage, session.*, extension overrides + controlled prefs, Local State DoH + labs | unknown engine / flagged start URL = medium; extension proxy/SafeBrowsing = high; NTP override low; custom DoH medium |
| browser.site_permissions | `profile.content_settings.exceptions.*` (setting=1) + Chrome abuse lists | lure word/IP/Chrome-flagged notifications = medium, else low |
| browser.launch.processes / shortcuts / debug_listeners | Get-BvsProcessTable (no `--type=`), .lnk via COM, Get-NetTCPConnection | rules in reference JSON (`--`, `-`, `/` prefixes); WebView2 only remote-debugging rules |
| browser.native_messaging | `<vendor>\NativeMessagingHosts`, manifest, script wrappers resolved to exe, Get-BvsSignature | known vendor name + wrong signer = high; unsigned = medium/high; dangling = low hygiene |
| browser.extensions.wallets | wallet ID map, wallet-named PWA shortcuts, brand-name impersonation | presence = info; impersonation medium/high |

- Vendor knowledge (browser paths, wallet IDs, store hosts, enum maps, flag rules, known hosts, intel sources) lives in
  `src\collectors\security\windows\S06-browsers-reference.json`; machine-specific items only in expected.json.
- Privacy: Local State `os_crypt` and Preferences account fields are never copied; URLs lose query strings.
- Expected false positives: AV/password-manager/AI extensions in the top tier; dev tools (Puppeteer, VS Code) using
  remote debugging; legitimate .shop/.online sites; bundled Adobe/McAfee registrations.
- Coverage gaps: store lookups are best effort (a store may answer with a consent or region redirect, and the Edge
  add-ons host sometimes resets the connection; the check then reports partial); Chrome PWA start URLs not resolved;
  Firefox only detected; Secure Preferences MACs not verified.
- v2: verify Secure Preferences HMACs, Firefox `extensions.json`/policies, extension code heuristics (eval/remote
  code), PWA origins.
- Linux equivalent: same logic on `~/.config/google-chrome`, `~/.config/microsoft-edge`, `.desktop` files,
  `/etc/opt/chrome/policies`, `~/.config/google-chrome/NativeMessagingHosts`, `ss -ltnp`.

## (c) Run

```
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S06-browsers.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S06-browsers.ps1 [-Offline] [-NoStoreCheck]
```

- Runtime about 10 to 30 s, depending on the number of browser profiles and extensions.
- Outputs: `data\<scanId>\security\S06.json`, `logs\S06.log`, intel cache under `intel\raw.githubusercontent.com\`.
