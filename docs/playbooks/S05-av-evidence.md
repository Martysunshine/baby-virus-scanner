# S05-av-evidence

> Generated from the collector's own code by `src/tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File src\tools\windows\gen-playbook.ps1 -Path src\collectors\security\windows\S05-av-evidence.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S05 - Antivirus evidence: what the installed security products have already seen.

```text
Read-only collector. It never runs a scanner, never opens quarantined files and never changes a
setting. Sources:
  * Avast / AVG (same Gen Digital engine and on-disk layout)
      report\*.txt            shield reports: date, shield, detection, object (file/URL), action
      chest\index.xml         Virus Chest index (metadata only)
      log\detections.log      detection-UI events: user choices, rootkit/anti-exploit prompts
      Log.db                  scan sessions, scan results, infection statistics
                              (built-in read-only SQLite reader, works on an in-memory copy)
      log\*.log               keyword grep: infection / threat / detection / blocked ...
      log\autosandbox.log     Auto-Sandbox decisions and exception-list hits
      log\aswAr*.log, UEFI    anti-rootkit and UEFI scan results
      registry properties\..  shields, passive/silent mode, exclusions, scan tasks; defs\aswdefs.ini
  * Microsoft Malicious Software Removal Tool   %windir%\debug\mrt.log
  * Microsoft Defender                          Get-MpThreatDetection / Get-MpThreat,
                                                Operational log 1006-1008, 1015, 1116-1119
  * Microsoft Safety Scanner                    %windir%\debug\msert.log, data\<scan>\admin\msert-*.log
  * Windows Security Center                     root\SecurityCenter2 products, decoded productState
Heuristics (type maps, false-positive hints, keyword lists) live in S05-av-heuristics.json.
Re-runnable: run it again after msert has finished; the envelope is rewritten.
```

## (b) Implementation

Collector: `src\collectors\security\windows\S05-av-evidence.ps1`. Library: `src\lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S05-av-heuristics.json`.

| Check | What it does |
|---|---|
| `s05.heuristics` | Load S05-av-heuristics.json (type maps, false-positive hints, keyword lists) |
| `avast.product` | Avast/AVG installation: version, folders, language, services |
| `avast.settings` | Avast/AVG shields, features, passive/silent mode and scan tasks (registry properties) |
| `avast.exclusions` | Avast/AVG exclusions and exceptions (registry properties, avast5.ini) |
| `avast.definitions` | Avast/AVG virus definitions (VPS) version, date and age; program version |
| `avast.reports` | Avast/AVG shield reports (report\*.txt): detections with date, shield, name, object, action |
| `avast.chest` | Avast/AVG Virus Chest index (chest\index.xml, metadata only; quarantined files never opened) |
| `avast.removal_records` | Avast/AVG PUB-Detected / PUB-Removed registry records (removed detections) |
| `avast.detections_log` | Avast/AVG log\detections.log: detection prompts, user choices, rootkit/anti-exploit and certificate events |
| `avast.logdb` | Avast/AVG Log.db: scan sessions (last scan times), scan results, infection statistics |
| `avast.correlation` | Correlate report rows with Virus Chest, detections.log user choices and Log.db results |
| `avast.log_grep` | Avast/AVG text logs: infection / threat / detection / blocked keyword summary |
| `avast.autosandbox` | Avast/AVG Auto-Sandbox decisions (log\autosandbox.log): sandboxed files and exception-list hits |
| `avast.antirootkit_uefi` | Avast/AVG anti-rootkit (aswAr*.log) and UEFI scan results |
| `msrt.log` | Malicious Software Removal Tool runs (%windir%\debug\mrt.log): results summary per run |
| `defender.threat_cmdlets` | Microsoft Defender Get-MpThreatDetection / Get-MpThreat history |
| `defender.event_log` | Microsoft Defender Operational log detections (1006-1008, 1015, 1116-1119) |
| `defender.detection_history` | Microsoft Defender DetectionHistory folder (Scans\History\Service\DetectionHistory) |
| `msert.results` | Microsoft Safety Scanner results (%windir%\debug\msert.log, data\<scan>\admin\msert-*.log) |
| `detections.presence` | For every file detection: does a file still exist at the original path? Facts for present files |
| `wsc.products` | Windows Security Center antivirus/antispyware/firewall registrations with decoded productState |
| `s05.assessment` | Judge detections and protection state, create calibrated findings |

## (c) Run

```powershell
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S05-av-evidence.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S05-av-evidence.ps1
```

Output: `data\<scanId>\security\S05.json` (`bvs.module/1`). Log: `logs\S05.log`.
