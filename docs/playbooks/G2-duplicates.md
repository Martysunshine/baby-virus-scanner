# G2 - Duplicate files and project copies

## (a) Brief (condensed)
- **`duplicateGroups`**:
  - Scope: files of 1 MB+ under Documents, Desktop, Downloads, Pictures, Videos, Music and OneDrive. Local files only: cloud-only placeholders are never opened (Test-BvsCloudOnly).
  - Skip node_modules, .git, venvs and AppData.
  - Group by size, then a hash of the first and last 64 KB, then full SHA-256 (Get-BvsHash). Keep the top 300 groups by wasted bytes.
  - Never pick a copy: every copy is `review`.
- **`projectCopies`**:
  - Repos that are copies of each other (same git remote or same package.json name): agent worktrees (`.claude\worktrees`), "- Copy" folders, renamed clones.
  - gitRisk = {uncommitted, unpushed, stashes} from `git --no-optional-locks -C <dir>` with `status --porcelain`, `log --branches --not --remotes --oneline` and `stash list`. Flag `work_at_risk` if any count is above 0.
- Read-only. Output `data\<scanId>\storage\G2.json`.

## (b) Implementation
- **Roots**: known folders (Downloads read from the registry), de-duplicated; this project's own folder is skipped.
- **Walk**: manual stack with EnumerationOptions (AttributesToSkip=0, so local OneDrive files are seen). Junctions and symlinks are never followed. Cloud-only folders and files are skipped and counted. Skipped folders: node_modules, .git, venv, .venv, *venv*, site-packages, AppData, .cache..., and any folder containing pyvenv.cfg.
- **Hashing**: the head/tail hash opens the file read-only with FileShare ReadWrite|Delete after Test-BvsNeverRead. The full hash uses Get-BvsHash -MaxBytes 64GB. Hashes are never written to the output.
- **Group item** `st-d...`: bytes (all copies), wastedBytes, sizeEach; flags `different_names`, `cross_folder`, `onedrive_copy`; `copies[]` each with path, bytes, modifiedUtc, folder, safety `review`.
- **Project candidates** come from G0 dirs.tsv, with no disk walk:
  - parents of .git folders and children of `.claude\worktrees`;
  - "- Copy" (and localized Explorer variants such as "- kopie") / "-copy" folders;
  - folders directly under personal roots, ~\source\repos and similar;
  - worktrees reported by `git worktree list --porcelain`.

  Top-level dot-folders, AppData and node_modules are excluded.
- **Match keys**: `remote:<host/owner/repo>` (credentials stripped), `package:<name>` (package.json or pyproject.toml; generic names such as "app" ignored), `copy-name:<base>`. Union-find on shared keys; groups of 2 or more are reported.
- **Copy item** `st-p...`: group, groupSize, gitRisk, remote, packageName. Flags: `work_at_risk`, `worktree`, `refs_shared_with_main_repo`, `not_a_git_repo`, `git_error`, `size_unknown`. Always `review`; `how` says to push or merge first, then use `git worktree remove` or a holding folder.
- **Expected false positives**: forks and tutorial clones of the same remote group together. Worktrees share branches and stashes with the main repo, so unpushed/stash counts repeat across them. Hard links look like duplicates.
- **Gaps / v2**: no hard-link detection (needs file IDs); `log --branches` misses detached-HEAD commits; non-git copies cannot be diffed, only flagged.
- **Linux**: the same walk over XDG user dirs and the same git commands.

## (c) Run
```
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\storage\windows\G2-duplicates.ps1 [-ScanId <id>] [-MinBytes 1MB] [-TopGroups 300]
```
- Runtime about 20 s to a few minutes (it hashes candidate files); needs G0 dirs.tsv for projectCopies. Output: `data\<scanId>\storage\G2.json`.
