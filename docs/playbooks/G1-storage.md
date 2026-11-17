# G1 - Storage map (junk, big files, old folders)

## (a) Brief (condensed)
- Read-only. Use G0 aggregates (`inventory\dirs.tsv`, `files.tsv`, `inventory-meta.json`); never re-walk the disk (small targeted folders only).
- Output `data\<scanId>\storage\G1.json`, inventory keys `junkItems`, `bigFiles`, `oldFolders`, `storageSummary` (bvs.items/1, ids `st-...`).
- `junkItems` from `config\category-rules.json`: temp (%TEMP% older than 7 d, Windows\Temp: use_tool); browser caches (use_tool, clear in browser); editor caches; package caches (npm, pip, pnpm, NuGet, gradle, cargo, HuggingFace); node_modules/venv/.next/dist/build/__pycache__ in projects idle >90 d (safe_after_check); crash dumps/WER; Windows.old, SoftwareDistribution\Download, DeliveryOptimization (use_tool); WinSxS/Installer/pagefile/hiberfil (do_not_touch); Docker/WSL vhdx and Ollama (use_tool); Downloads installers older than 30 d; inactive nvm versions and the shadowed Program Files\nodejs; remnants of uninstalled antivirus products; PC-maker folders such as C:\eSupport, C:\Intel, C:\Drivers (review). Also: project copies (`*-copy`, `* - Copy`, `*-merge`) and `.claude\worktrees` (review), standalone venv (safe_after_check), `~\.claude.json.tmp.*`, Desktop `~$` lock files.
- `bigFiles`: top 200 files of 100 MB+ with a category guess. `oldFolders`: 200 MB+ with 80%+ of bytes cold for 2 years; personal data always review. `storageSummary`: reclaimable bytes per safety level, cloud-only bytes, unaccounted bytes.

## (b) Implementation
- **Rules live in config** (`dirRules`, `fileRules`, `extGuess`, `excludeSets`, `userRoots`, `personalRoots`, `oldFolderExclude`). Path tokens such as %DOCUMENTS%, %DOWNLOADS% (registry known folder) and %NVM_HOME% keep it portable. A rule whose token is missing is skipped and the check is marked partial.
- **One streaming pass over dirs.tsv** (hundreds of thousands of rows in a few seconds). Rules are indexed by literal leaf name or literal parent path, so the regex runs only on candidates. The first matching rule wins per folder; across folders the outermost match wins, so nothing is counted twice.
- **Filters**:
  - `minBytes`.
  - `idleDays`: the parent folder's newest write is older than N days. Items directly under a user root are always listed, flagged `recently_used` if newer.
  - `requireChild` (pyvenv.cfg) and `requireSibling` (package.json, pyproject.toml...): checked with Test-Path.
- **Special rules**:
  - `temp-age`: lists %TEMP% with Get-BvsFiles and counts files older than 7 days.
  - `nvm-inactive`: the active version is the NVM_SYMLINK target.
  - `node-shadowed`: a real Program Files\nodejs whose node.exe is not first on PATH.
- **File rules** apply to files.tsv rows (`large`, `root-of-user-folder`, `partial-download`). `probe: true` lists one folder live (`~\.claude.json.tmp.*`, which G0 does not record). `group: true` rules aggregate many small files into one item.
- **bigFiles** take their category from, in order: a file-rule item, the enclosing junk folder (`junkItemId`), or an `extGuess` extension match.
- **oldFolders** keep only the outermost qualifying folders outside Windows, Program Files and ProgramData. User roots are never reported as a whole.
- **Expected false positives**:
  - Idle is based on write times, so a project that is opened but never edited looks idle.
  - The `app-cache` rule is generic.
  - Hard links (WinSxS, pnpm) overstate the savings.
  - `-merge`/`-iso` copy names are config heuristics.
- **Gaps / v2**:
  - Installers under 10 MB in Downloads subfolders are missed (G0 does not list them).
  - System Volume Information and other access-denied folders appear only as "unaccounted".
  - No per-file aging inside caches.
- **Linux**: the same rules file with Linux tokens (~/.cache, ~/.npm, /var/tmp, journald, snap/flatpak, docker overlay2).

## (c) Run
```
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\storage\windows\G1-storage.ps1 [-ScanId <id>]
```
- Needs G0 first; runtime about 8 s. Output: `data\<scanId>\storage\G1.json`.
