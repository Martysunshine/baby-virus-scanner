# S01 - Persistence & autostarts

## (a) Brief (condensed)
Scan agent S01 for baby-virus-scanner (read-only audit, future Windows + Linux AV). Follow `docs\agent-rules.md`,
`docs\schema.md`, `config\local\expected.json`; use `lib\windows\BVS.Common.psm1`; lint must pass before running.
Build `collectors\security\windows\S01-persistence.ps1` covering every way code starts automatically or hijacks
execution, one `Invoke-BvsCheck` per area, HKLM + HKCU, 64- and 32-bit views:
1. Run keys (Run, RunOnce(Ex), RunServices(Once), Policies\Explorer\Run, TS Install), StartupApproved (02 on / 03 off),
   key LastWriteTime, resolved command, target signer / user-writable / exists.
2. Startup folders: .lnk via WScript.Shell CreateShortcut (never Save()), scripts and executables.
3. Winlogon Shell/Userinit/Taskman/AppSetup/Notify, Command Processor AutoRun, UserInitMprLogonScript, Active Setup
   StubPath, BootExecute (default `autocheck autochk *`).
4. AppInit/AppCertDlls, LSA packages + OSConfig, print monitors, NetSh helpers, time providers, IFEO Debugger/GlobalFlag,
   SilentProcessExit, HKCU UAC-bypass class keys (+DelegateExecute), accessibility binaries (Microsoft-signed and
   OriginalFilename matches).
5. HKCU COM hijacks shadowing HKLM (user-writable/unsigned server); shell extensions, SSODL, icon overlays.
6. Services: path, StartMode, account, ServiceDll, FailureCommand, signers, LastWrite; unquoted paths = hardening-low.
7. Drivers: resolve paths, signer, SHA-256; LOLDrivers via Invoke-BvsIntel, compared locally (malicious = critical,
   vulnerable + loaded = hardening-high). Never send hashes.
8. Scheduled tasks (+XML): user-writable actions, LOLBin/script host with URL or encoded args, hidden, random names,
   unsigned, non-Microsoft in root, ComHandler DLLs.
9. WMI permanent subscriptions (only "SCM Event Log" expected).
10. Shell startup files: PowerShell profiles, Git Bash rc/profile.d, Claude Code shell-snapshots (curl|sh, base64, eval,
    NODE_OPTIONS / ANTHROPIC_BASE_URL / proxy exports).
`compromise` only for encoded payload, LOLBin+URL, masquerading, or unsigned + user-writable + persistence + recent.
expected.json matches: set `-Expected`, cap at info unless an invalidIf holds. Full inventory via Add-BvsInventory.

## (b) Implementation
- **Files**: `S01-persistence.ps1` (logic) + `S01-persistence-iocs.json` (generic lists: LOLBins, Windows defaults, registry
  locations, content rules, vendor aliases, brand rules, default FP/recommendation texts). Machine-specific items stay in expected.json.
- **Checks (23)**: process_context, run_keys, startup_folders, winlogon, logon_hooks, active_setup, injection,
  dll_hooks, ifeo, class_hijack, accessibility, com_hijack, shell_extensions, services, drivers, loldrivers,
  scheduled_tasks, task_sd_hidden (TaskCache SD removal, needs admin), wmi_subscriptions, bits_jobs, env_hijack
  (COR_PROFILER, NODE_OPTIONS, JAVA_TOOL_OPTIONS, proxies, ANTHROPIC_BASE_URL), shell_startup_files (+ Windows
  Terminal), expected_verification.
- **Facts per target** (cached): signature (catalog aware), Microsoft-authored (WHQL "Hardware Compatibility
  Publisher" is not Microsoft-authored), version info, user-writable (file or parent, via Test-BvsUserWritable),
  folder class (windows / programfiles / programdata / user-appdata / user-profile / suspicious = temp, downloads,
  desktop, public, AppData root ...), MOTW, PE magic.
- **Rating engine (`Measure-S01`)**, in order: compromise (encoded command executed, exec-LOLBin + URL, downloader
  writing executables, javascript:/vbscript:, credential dumping, masquerading, malicious content rule) > unsigned in a
  user-writable folder (high suspicious; compromise only if also recent AND no version info / random name / MOTW /
  temp folder) > tampered signature > content rules > obfuscation / URL > script in a user-writable folder >
  unsigned elsewhere > missing target (hardening when hijackable from a privileged context, else aggregated
  hygiene) > privileged + user-writable (hardening) > signer/brand mismatch > per-check floor. Disabled entries drop
  one level; expected matches cap at the item's severityCap unless invalidIf holds (unsigned/unexpected signer,
  unexpected folder, "not signed by X" are machine-checked).
- **Expected false positives**: per-user apps in AppData (for example OneDrive or Discord; signed, so no finding); vendor
  AV boot programs in BootExecute (reported as info); WHQL-signed driver-package tools (accepted when the company
  matches); Squirrel `Update.exe` company/signer mismatch can invalidate an expected match without creating a finding.
- **Inventory**: `autostarts` (one row per entry: category, location, name, command, target, signer, userWritable,
  lastWrite, enabled, runAs, running, expected, severity, findingIds), `drivers` (all, with SHA-256), `startupApprovedStale`,
  `shellExtensionStats`, `loldriversIntel`, `summary`.
- **Gaps / v2**: when the LOLDrivers list cannot be downloaded and no cached copy exists, the driver comparison is
  reported as partial. TaskCache SD check, other users' BITS jobs, and some service keys need elevation. Authentihash matching, service DACLs,
  Office add-ins and XLSTART, browser extensions (other agents), and git hooks are not covered. Linux v2: systemd units/timers, cron, /etc/rc*,
  ~/.config/autostart, shell rc files, LD_PRELOAD, kernel modules (same engine, same shapes).

## (c) Run
`pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S01-persistence.ps1 [-NoIntel] [-IntelMaxAgeHours 24]`
- Lint first: `pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S01-persistence.ps1` (1 expected WARN: read-only WScript.Shell).
- Runtime about 45 s to 2 minutes, not elevated (drivers, services and tasks take the longest).
- Outputs: `data\<scanId>\security\S01.json`, `logs\S01.log`, LOLDrivers cache `intel\www.loldrivers.io\*-loldrivers.json`.
