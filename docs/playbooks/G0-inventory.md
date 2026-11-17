# G0-inventory

> Generated from the collector's own code by `tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File tools\windows\gen-playbook.ps1 -Path collectors\inventory\windows\G0-inventory.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

G0 - file-system inventory: one read-only, metadata-only pass over every fixed drive.

```text
Feeds the storage map (treemap), the old-files and large-files views and S02's cross-check.
Contract: docs\schema.md, section "G0 inventory". Methodology: docs\playbooks\G0-inventory.md.

Enumeration
  DirectoryInfo.EnumerateFileSystemInfos + EnumerationOptions, manual stack recursion, one directory
  at a time with IgnoreInaccessible = $false inside try/catch, so every directory that cannot be
  listed is counted. Pure PowerShell, no pipeline in the hot loop (measured at about 110k entries/s
  warm, 1.4x a compiled C# walker, so no Add-Type is needed).

  AttributesToSkip is None (NOT ReparsePoint) and reparse points are classified explicitly. On
  Windows 10/11 the OneDrive root, its folders and its files carry FILE_ATTRIBUTE_REPARSE_POINT
  (cloud tags 0x9000xx1A), so skipping ReparsePoint would hide the whole OneDrive tree and make
  cloud-only bytes unmeasurable. Hidden and System entries (all of AppData) are always included.
    * Name-surrogate reparse folders (junctions, symbolic links, volume mount points; detected with
      FileSystemInfo.LinkTarget, which reads the reparse point itself and never follows it) are
      never walked. They get a dirs.tsv row flagged 'reparse'.
    * Cloud-sync placeholder folders are walked unless they are cloud-only.
    * Any other non-link reparse folder outside a sync root is not walked (flag 'reparse').

Safety
  * Never opens, reads or hashes file contents: every fact comes from directory listings.
  * Never enumerates or opens cloud-only placeholders (attributes 0x400000 / 0x40000 / 0x1000).
  * Writes only data\<scanId>\inventory\ (inventory\subset\ with -Path) and logs\G0.log.
  * Every string written to TSV/JSON is masked (path components through Protect-BvsText).
```

## (b) Implementation

Collector: `collectors\inventory\windows\G0-inventory.ps1`. Library: `lib\windows\BVS.Common.psm1`.

| Check | What it does |
|---|---|
| `inventory.volumes` | Fixed drives with a letter: size, free, used, file system, cluster size (letterless volumes listed, not walked) |
| `inventory.context` | Resolve user profiles, known user folders, OneDrive and cloud sync roots, WinSxS and other special folders |
| `inventory.totals` | Bottom-up subtree totals (bytes, files, dirs, newest/oldest write, cold 1y/2y/5y, cloud-only) |
| `inventory.user_writable_roots` | Top folders under the profiles folder and ProgramData that the current user can write (flag user-writable-root) |
| `inventory.mask` | Mask secrets in folder and file names (Protect-BvsText, chunked) before anything is written |
| `inventory.write.dirs_tsv` | Write dirs.tsv: one row per directory, depth-first order (docs\schema.md) |
| `inventory.write.files_tsv` | Write files.tsv: selected files only, one row per (file, reason) |
| `inventory.write.meta` | Write inventory-meta.json: volumes, totals, unaccounted bytes, top-level and per-profile breakdowns |

Plus 1 check(s) whose ID is built at run time (see the script).

Parameters: `-Path`, `-ScanId`, `-ProgressSeconds`.

## (c) Run

```powershell
pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\inventory\windows\G0-inventory.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\inventory\windows\G0-inventory.ps1
```

Output: `data\<scanId>\inventory\G0.json` (`bvs.module/1`). Log: `logs\G0.log`.
