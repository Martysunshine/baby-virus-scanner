# H1 - Programs, speed and startup load (Windows)

## (a) Brief, condensed
Read-only inventory for the storage dashboard: what is installed, how big it is, whether it is still used,
what starts with Windows, what is using CPU/RAM now, which apps crash, battery wear and the power plan.
Output `data\<scanId>\storage\H1.json`. Inventory keys, unchanged: `programs`, `startupItems`, `resourceHogs`,
`crashes`, `battery`, `powerPlan` (+ `summary`). Items use the `bvs.items/1` shape from `docs\schema.md`.
Admin-only sources (StartupInfo, BAM, Prefetch) are `needs_admin`, pending the elevated run.

## (b) Implementation (`src\collectors\storage\windows\H1-programs.ps1`)
- **programs** (`H1.programs`): uninstall keys from HKLM, HKLM WOW64 (`-View 32`) and HKCU, skipping
  `SystemComponent`, updates and duplicates, plus `Get-AppxPackage`. The AppX list drops framework, resource,
  non-removable and System-signed packages, and anything provisioned for all users (`AppxAllUserStore`).
  - **Size:** the real folder size from G0 `dirs.tsv`, streamed once with a HashSet of InstallLocations. A
    folder shared by several products is counted once. A 0-byte (unreadable) folder falls back to `EstimatedSize`.
  - **lastUsed:** a process running from the install folder, or else UserAssist. UserAssist names are ROT13
    and the data is 72 bytes: run count at offset 4, FILETIME at offset 60. Known-folder GUIDs are resolved,
    and Start Menu `.lnk` names are matched to DisplayName. Otherwise `unknown`, because UserAssist only sees Explorer launches.
  - **Flags** come from generic rules: OEM trialware, the WebAdvisor PUP, cleaners/optimizers, bundled browsers,
    server software (Splunk, Elasticsearch...) with `no_recent_use_evidence`, and `not_used_180d`.
    Runtimes and drivers are `do_not_touch`.
  - **Node.js checks:** an MSI Node.js shadowed by (or shadowing) nvm-windows (PATH order through
    `Get-Command -All`), inactive nvm versions (`nvm uninstall`), and npm globals whose `bin` target is missing (`broken`).
  - **Service-only installs**, such as an Elasticsearch zip, are added from `Win32_Service`.
- **resourceHogs:** two `Win32_PerfFormattedData_PerfProc_Process` samples 10 s apart. CPU is divided by the
  number of logical CPUs and RAM is the private working set. Top 15 by CPU and top 15 by RAM, with `Get-BvsSignature`.
  The collector's own PID is excluded.
- **startupItems:** S01 `autostarts` with `enabled`. All Run-key and Startup-folder entries are included,
  plus non-Microsoft tasks and non-Microsoft Auto/running services (start mode from `Win32_Service`).
  Running entries get CPU/RAM from the perf sample. Otherwise the impact is `unknown (needs admin StartupInfo)`.
  The `how` field says where to disable the entry (Task Manager -> Startup apps / Services / Task Scheduler).
- **crashes:** Application log events 1000 (`Application Error`) and 1002 (`Application Hang`) through XPath,
  90 days. They are parsed from EventData by index, so the Windows display language does not matter. Grouped per app:
  versions, top faulting modules and exception codes.
- **battery:** `powercfg /batteryreport /output <OutDir>\H1-battery-report.html`. The design and full-charge
  values are the first two `mWh` rows, so the parsing works in any language. Cycle count is read too.
- **powerPlan:** `powercfg /getactivescheme` (GUID mapped to a known plan) plus the power-mode overlay from
  `HKLM\...\Power\User\PowerSchemes`.

## (c) How to run
```powershell
pwsh -NoProfile -File <root>\src\tools\windows\check-collector.ps1 -Path <root>\src\collectors\storage\windows\H1-programs.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File <root>\src\collectors\storage\windows\H1-programs.ps1
```
Needs S01 (`security\S01.json`) and G0 (`inventory\dirs.tsv`) from the same scan. It takes about 30 s
(10 s of that is the perf window). Run it elevated later to fill in StartupInfo, BAM and Prefetch.
