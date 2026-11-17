# H2 - System health: broken references, disk health, clutter (Windows)

## (a) Brief, condensed
Read-only health view. Output `data\<scanId>\storage\H2.json`. Inventory keys, unchanged: `registryRefs`,
`diskHealth`, `brokenShortcuts`, `zeroByteFiles`, `incompleteDownloads`, `typeMismatches` (+ `summary`).
Registry cleaners don't speed Windows up, so H2 lists only broken references that have a visible effect.
Each one gives the impact, the fix (vendor uninstaller or Windows UI first), the risk, `backup_required`, and
method `setting`/`tool`. H2 never suggests a registry cleaner. A disguised executable also gets a security
finding (high, suspicious). Reliability counters and sfc/DISM are `needs_admin`, pending.

## (b) Implementation (`collectors\storage\windows\H2-health.ps1`)
- **registryRefs** (`H2.registryRefs`):
  - **Ghost uninstall entries:** InstallLocation is missing, or the non-MSI uninstaller `.exe` is missing.
    Skipped when a DisplayIcon outside `%windir%` still exists, because the app is probably still there.
  - **Missing startup, task and service targets** (S01 `exists=false`), re-verified against the real command
    (Active Setup `StubPath`, task actions through `Get-ScheduledTask`, service `ImagePath`), including DLL
    arguments. S01 parse artefacts are counted as `s01FalsePositives`. Orphaned StartupApproved flags have no
    effect, so they are only counted.
  - **App Paths** (64-bit view, which is what Win+R uses) pointing to a missing exe.
  - **Default open command** for 28 common file types (`UserChoiceLatest` -> `UserChoice` -> HKCR) whose
    program is missing.
  - **Context-menu handlers:** `*`, AllFilesystemObjects, Directory, Background, Folder and Drive handlers whose
    InprocServer32 DLL is missing.
  - **Security Center:** stale `root\SecurityCenter2` AV/AS/firewall registrations whose exe is gone
    (`\\?\` prefix stripped).
  - **Dead PATH entries** (User and Machine). A Machine entry whose nearest existing parent is user-writable
    gets `planting_risk`.
- **diskHealth:**
  - `Get-PhysicalDisk` health.
  - System log for 90 days, one XPath query per provider: disk 7/11/51/153, stornvme 129, Ntfs 55/98/137
    (98 only at warning level or worse), volmgr 161, WHEA 17/18/19/47, Kernel-Power 41 and BugCheck 1001.
    Stop codes come from EventData.
  - Ntfs/Operational warnings and errors, labelled with a sample message.
  - Two `pending-admin` items.
- **brokenShortcuts:** `.lnk` files on the user and Public Desktop, both Start Menus (recursive) and taskbar pins.
  Each target is read with `WScript.Shell.CreateShortcut().TargetPath` and `Save()` is never called.
  Cloud-only files are skipped. A target on a missing drive is marked `review`.
- **zeroByteFiles / incompleteDownloads:** G0 `files.tsv` rows `zero-byte` / `partial-download`, skipping our own
  folder. Zero-byte files in user-visible folders are listed one by one (up to 300). The rest are grouped per
  folder as `do_not_touch`: they are app markers and free 0 bytes.
- **typeMismatches:** `root-of-user-folder` rows directly in Desktop, Downloads and Documents. Each file goes
  through `Test-BvsNeverRead`, then `Test-BvsCloudOnly`, then `Test-BvsMagicMismatch`. A disguised executable
  also gets `New-BvsFinding` (high, suspicious, T1036.008).

## (c) How to run
```powershell
pwsh -NoProfile -File <root>\tools\windows\check-collector.ps1 -Path <root>\collectors\storage\windows\H2-health.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File <root>\collectors\storage\windows\H2-health.ps1
```
Needs S01 and G0 from the same scan. It takes about 15 s. A later elevated run adds reliability counters and sfc/DISM.
