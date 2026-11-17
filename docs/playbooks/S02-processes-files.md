# S02-processes-files

> Generated from the collector's own code by `src/tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File src\tools\windows\gen-playbook.ps1 -Path src\collectors\security\windows\S02-processes-files.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S02 - Processes and suspicious files: read-only security collector (Windows 10/11).

```text
Part of baby-virus-scanner. Looks at what is running now and at recent risky files in the places
malware usually lands, and writes findings into the shared bvs.module/1 envelope
(data\<scanId>\security\S02.json).

Processes   signer, user-writable image folder, deleted image, masquerading system names,
            look-alike names, parent anomalies (Office/browser -> shell, svchost not under
            services.exe), suspicious command lines, risky launch folders, sustained CPU from
            unsigned programs (two samples), inventory of unsigned / user-writable processes.
Files       recent (created OR modified within -RecentDays) risky files in Downloads, Desktop,
            Public, %TEMP%, AppData / LocalAppData (depth 2), ProgramData (depth 2), Windows\Temp,
            Startup folders and the system-drive root (depth 1): signer, Mark-of-the-Web,
            header vs extension, double extension, RTLO, random names, LNK / URL abuse,
            DLL side-loading, AppData-root executables, script content indicators.
Artifacts   Contagious Interview (BeaverTail / InvisibleFerret), Shai-Hulud 2.0, s1ngularity.
Origins     Mark-of-the-Web host domains of executables and installers in Downloads.
Cross-check G0 inventory\files.tsv 'exec-recent' rows that the targeted sweep missed (optional).

Read-only: never modifies, moves, kills or executes anything. File contents are read only for
headers, shortcut / URL parsing and script indicators (pattern ids are stored, never content).
Tunable lists: S02-iocs.json (same folder). Known-good items: src\config\local\expected.json.
Contract: docs\schema.md   Rules: docs\agent-rules.md   Playbook: docs\playbooks\S02-processes-files.md
```

## (b) Implementation

Collector: `src\collectors\security\windows\S02-processes-files.ps1`. Library: `src\lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S02-iocs.json`.

| Check | What it does |
|---|---|
| `processes.table` | Process list (Win32_Process); image paths of SYSTEM processes via Win32_Service and a read-only NtQuerySystemInformation fallback when not elevated |
| `processes.signatures` | Authenticode signer, user-writable folder and image existence for every running image; invalid or untrusted signatures |
| `processes.masquerading` | Windows system process names running outside their real folders |
| `processes.lookalike_names` | Process names that imitate Windows process names (homoglyph skeleton or one edit away) |
| `processes.parent_anomalies` | Office/browser spawning shells or script hosts; svchost/lsass/services/spoolsv with an unexpected parent |
| `processes.command_lines` | Suspicious command lines: encoded/hidden PowerShell, download cradles, LOLBins (mshta, regsvr32, rundll32, certutil, bitsadmin), conhost --headless payloads, miner markers |
| `processes.risky_locations` | Processes running from %TEMP%, Downloads, Public, ProgramData root, AppData root, Recycle Bin (plus Desktop, profile root, drive root, Startup) |
| `processes.unsigned_user_writable` | Unsigned programs running from other user-writable folders (AppData vendor folders, LocalAppData\Programs, user profile) |
| `processes.image_missing` | Running processes whose image file no longer exists on disk |
| `processes.cpu_miner` | Sustained CPU (>= $CpuThresholdPct% of all cores) from unsigned or unknown programs; Win32_PerfFormattedData_PerfProc_Process sampled twice >= $CpuSampleSeconds s apart, plus raw-counter average |
| `files.signatures` | Authenticode signer of recent signable files (PE, MSI, signable scripts) |
| `files.motw` | Mark-of-the-Web zone, host and referrer of recent risky files |
| `files.header_vs_extension` | File header (magic bytes) compared with the extension of recent risky files |
| `files.disguised_executables` | Executable (PE/ELF) headers behind non-executable extensions among other recent files in the high-risk folders |
| `files.name_tricks` | Double extensions, RTLO/bidi characters, random high-entropy names, instruction-like names |
| `files.lnk_abuse` | Shortcuts (.lnk) whose target/arguments call shells or LOLBins, carry long or padded arguments, point to UNC paths or unsigned user-writable programs |
| `files.url_abuse` | Internet shortcuts (.url) and .library-ms/.search-ms files pointing to file://, UNC, WebDAV or protocol-handler targets |
| `files.script_content` | Recent scripts (PowerShell, WSH, HTA, batch, AutoIt): indicator patterns (download cradles, encoded commands, AMSI/Defender tampering, obfuscation) |
| `files.sideloading` | Unsigned recent DLL next to a validly signed EXE in the same user-writable folder (DLL side-loading) |
| `files.appdata_root_executables` | Executables and scripts directly in the AppData, Roaming, Local or LocalLow root (any age) |
| `files.findings` | Severity scoring of recent risky files; individual findings for medium and above, one summary per check for low |
| `artifacts.droppers` | Known dropper/worm artifacts in the home folder and %TEMP% (existence and metadata only): Contagious Interview, Shai-Hulud 2.0, s1ngularity |
| `artifacts.worm_files` | Shai-Hulud 2.0 files (setup_bun.js, bun_environment.js, truffleSecrets.json, actionsSecrets.json) outside node_modules in the profile and %TEMP% |
| `downloads.origins` | Mark-of-the-Web host domains of executables, scripts, installers and archives in Downloads (any age); unusual sources flagged |
| `crosscheck.g0_exec_recent` | G0 inventory\files.tsv 'exec-recent' rows outside this sweep (optional; runs only when G0 has finished) |

Plus 1 check(s) whose ID is built at run time (see the script).

Parameters: `-RecentDays`, `-CpuSampleSeconds`, `-CpuThresholdPct`, `-MaxHashMB`, `-MaxFindingsPerCheck`.

## (c) Run

```powershell
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S02-processes-files.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S02-processes-files.ps1
```

Output: `data\<scanId>\security\S02.json` (`bvs.module/1`). Log: `logs\S02.log`.
