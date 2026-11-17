# S04-history-logs

> Generated from the collector's own code by `tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File tools\windows\gen-playbook.ps1 -Path collectors\security\windows\S04-history-logs.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S04 - Command history & event logs: ClickFix/FileFix traces, PowerShell logs, BITS, System log
(services, start types, log clears, shutdowns), MSI installs timeline, Defender, remote sessions,
firewall rule changes, Shell-Core Run executions, WMI activity, CodeIntegrity, log coverage.

```text
READ-ONLY. Reads registry values, history files and event logs; writes only the module envelope
data\<scanId>\security\S04.json (masked by Complete-BvsRun) and logs\S04.log.

- History files are never dumped: only suspicious lines (masked, with line number) and counts are kept.
- Events are parsed by EventData/UserData field NAME from ([xml]$e.ToXml()), never by localized
  message text (the OS may be localized).
- Our own activity is excluded: only events strictly before AuditStartUtc (scan-meta.json) are used,
  and history lines that reference this project are ignored.
- Missing or disabled logs become not_applicable (with the reason) rather than errors.
- Patterns, installer allowlist and vendor update hosts live in S04-history-iocs.json (sidecar).
- Machine-specific known-good items come from config\local\expected.json via Get-BvsExpected.

Contract: docs\schema.md  Rules: docs\agent-rules.md  Playbook: docs\playbooks\S04-history-logs.md
```

## (b) Implementation

Collector: `collectors\security\windows\S04-history-logs.ps1`. Library: `lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S04-history-iocs.json`.

| Check | What it does |
|---|---|
| `history.runmru` | Win+R history (Explorer\RunMRU) in MRUList order, scanned for ClickFix commands |
| `history.typedpaths` | Explorer address-bar history (TypedPaths): FileFix pastes a command disguised as a path |
| `history.files` | PSReadLine *_history.txt, ~\.bash_history, ~\.python_history, ~\.node_repl_history scanned line by line (only suspicious lines kept, masked) |
| `pslog.classic` | Windows PowerShell log 400/403/600: unique HostApplication command lines, flagged for cradles/encoding/obfuscation |
| `bits.jobs` | Bits-Client/Operational 3/59/60/61/16403: BITS job URLs, creators; non-vendor hosts flagged |
| `system.services_new` | System 7045: services installed in the last $Days days (name, image path, account), signature and folder checks |
| `system.service_starttype` | System 7040: service start-type changes (WinDefend, wuauserv, Avast and other security services highlighted) |
| `system.log_cleared` | System 104 (Microsoft-Windows-Eventlog): event logs cleared |
| `system.shutdowns` | System 1074 (planned shutdown/restart), 6008 (unexpected shutdown), 41 (Kernel-Power) for timeline context |
| `installs.msi` | Application log MsiInstaller 11707/1033/1034/11724: MSI installs/removals in the last $Days days (product, version, date) |
| `defender.operational` | Defender/Operational 1116-1119 detections, 5001 RTP off, 5007 config changes (exclusions), 5010/5012 (whole log: it is small and old exclusions stay active) |
| `remote.sessions` | TerminalServices LocalSessionManager 21/22/24/25 (logon/reconnect with source address) and RemoteConnectionManager 1149; non-local sources flagged |
| `firewall.rule_changes` | Windows Firewall With Advanced Security/Firewall: rule add/modify/delete events matched by provider + RuleName/ModifyingApplication fields; non-system modifiers flagged |
| `shellcore.run_exec` | Shell-Core/Operational 9707/9708: Run/RunOnce commands executed at logon, compared with the current Run keys |
| `wmi.activity` | WMI-Activity/Operational 5857-5861 (5861 = permanent event subscription bound; 5860 = temporary subscription; 5857 = provider loaded) |
| `codeintegrity.events` | CodeIntegrity/Operational 3033/3063: images that did not meet the signing level (info) |
| `taskscheduler.operational` | TaskScheduler/Operational availability (task execution history; often disabled by default) |
| `logs.security` | Security log access (1102 clears, 4624/4688 etc. need elevation; covered by admin\windows\admin-checks.ps1) |
| `logs.coverage` | Record count, size, oldest/newest event, enabled state and window coverage for every log queried |

Plus 1 check(s) whose ID is built at run time (see the script).

Parameters: `-Days`, `-MaxEvents`, `-SelfTest`.

## (c) Run

```powershell
pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S04-history-logs.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S04-history-logs.ps1
```

Output: `data\<scanId>\security\S04.json` (`bvs.module/1`). Log: `logs\S04.log`.
