# S10: Code editors & git

## (a) Brief (condensed)

Build `collectors\security\windows\S10-editors-git.ps1`. Read-only; git only as `git --no-optional-locks <read>`
(read `.git\config` directly); never run the `code`/`cursor` CLIs; network only via `Invoke-BvsIntel`.
1. **VS Code/Cursor extensions**: from extensions.json read id, version, source (gallery/vsix), installedTimestamp,
   publisherDisplayName, pre-release and targetPlatform. Also read `.obsolete`, package.json (publisher, main,
   activationEvents `*`/onStartupFinished, extensionDependencies) and check whether `.signature.p7s` exists.
   Flag sideloaded folders and vsix installs.
   Intel: Marketplace existence and verified publisher (extensionquery, filterType 7; missing = high); the kill list
   from product.json `extensionsGallery.controlUrl` (a malicious match = critical); RemovedPackages.md
   (Malware/Impersonation/Typo-squatting).
   Code (at most ~30 MB of JS per extension): invisible-Unicode runs of 10 or more (FE00-FE0F, E0100-E01EF,
   E0000-E007F, 200B-200F, 202A-202E, 2066-2069) = high; eval/new Function + child_process + network in theme/icon
   extensions = high; GlassWorm C2 strings (Solana RPC, Google Calendar dead drops) = high.
2. **Editor settings** (Code + Cursor settings.json): http.proxy / proxyStrictSSL=false, terminal env,
   custom profile/automationProfile shells, trust disabled, task.allowAutomaticTasks "on",
   python.defaultInterpreterPath, git.path. Check Cursor extensions on Open VSX; read the Cursor extensions-control
   list and tolerate unknown formats.
3. **Repo auto-run vectors** (repos via .git/package.json under %USERPROFILE%, depth 5, skipping node_modules):
   tasks.json `runOn: folderOpen` = high; launch.json preLaunchTask that downloads; .vscode\settings.json shell/env
   overrides; devcontainer initializeCommand (runs on the host) or a postCreate/postStart command that downloads = high.
4. **Git**: global/system/XDG config (hooksPath, fsmonitor, sshCommand, pager, editor, credential.helper,
   insteadOf, include/includeIf, `!` aliases, filter.lfs expected). Per repo: remotes/pushurl hosts, hooksPath,
   fsmonitor, non-.sample hooks (scan for curl/iwr/base64/-enc/node -e), and .git\worktrees. Group copies by remote.
5. **JetBrains and others**: record not_applicable when absent.
Deliverables: the collector, `data\<scan>\security\S10.json`, this playbook and a short report.

## (b) Implementation

- **Data**: all detection data (editor list, regexes, IoCs, severity maps, git expectations) lives in
  `collectors\security\windows\S10-editor-iocs.json`. Nothing machine-specific is in the code. Expected items come
  from `Get-BvsExpected` (categories editorExtension and program). An expected match caps only heuristic findings,
  and only while the extension is gallery-sourced, absent from the kill list and RemovedPackages, and found in its
  gallery. Intel matches are never capped.
- **Editors**: found through the uninstall registry plus data folders. product.json is located in both layouts:
  `<install>\resources\app` and the versioned `<install>\<commit>\resources\app`. The built-in defaults for
  `security.workspace.trust.enabled` and `task.allowAutomaticTasks` are extracted from
  `workbench.desktop.main.js`, with the sidecar values as fallback (Cursor 1.0: trust=false, tasks=on; VS Code 1.142:
  true/off). Forks (Insiders, VSCodium, Windsurf, Kiro, Trae, Antigravity, Positron) get the same treatment when present.
- **Extensions**: the "registered" set is the union of extensions.json across all profiles. A folder that is neither
  registered nor in `.obsolete` is sideloaded (medium; high if also missing from its gallery). Obsolete folders are
  low/hygiene. Other checks: package.json identity vs registered ID (masquerading, high), and an extensions.json
  location outside the extensions folder (medium).
- **Intel**: Invoke-BvsIntel with 3 retries, because HTTPS-scanning antivirus products sometimes reset connections.
  Sources: the kill list
  from every controlUrl (main.vscode-cdn.net, api2.cursor.sh), RemovedPackages.md (type → severity map), a Marketplace
  batch query (40 IDs per call, flags 789) for non-gallery or unregistered VS Code extensions, and Open VSX per
  Cursor/fork extension.
- **Code scan**: entry points (main/browser) are always scanned, then other files in this order: outside
  node_modules, inside node_modules, smallest first, up to `-MaxJsMB` (30). The check is `partial` when the cap is
  hit. Invisible runs are classified (variation selector / tag / zero-width / bidi); `tableLike` (short, all-distinct
  runs) drops to low. A C2 hit only inside `node_modules\@solana` drops to medium. Capability regexes run only for
  theme-only extensions (contributes ⊆ themes/iconThemes/productIconThemes).
- **Settings traps**: proxy (medium), proxyStrictSSL=false (medium), proxyAuthorization (medium), terminal env
  (per-variable rules: NODE_OPTIONS --require = high), shell/automation profiles (user-writable path or risky args),
  trust off, automatic tasks on, `chat.tools.*autoApprove` (workspace = high, CVE-2025-53773 pattern),
  `extensions.verifySignature=false`, configure-on-open settings (makefile/cmake, low), and exec-path settings
  (inventory). When effective trust is off and tasks are on from defaults: medium hardening.
- **Repos**: one `Get-BvsFiles` sweep (depth 5) for `.git` dirs/files, `.vscode`, `.devcontainer(.json)`, `.idea`,
  `*.code-workspace` and package.json, excluding this project and the editor extension folders. Commands are graded
  by `Get-Risk` (download, pipe_shell, encoded, inline_exec, eval, reverse_shell, evasion, disguised_script,
  paas_host, ip_url). Findings for identical content are merged across copies/worktrees ("N locations"). Folders
  opened in each editor (workspaceStorage) are attached as `openedIn`.
- **Git**: a custom config parser (quoted subsections, escapes, inline comments; include/includeIf are followed,
  conditions ignored). Locations: Git for Windows (registry InstallPath), %ProgramData%, the global and XDG configs,
  GitHub Desktop's embedded configs, and persistent `GIT_*` environment variables. Template hooks and global
  hooksPath directories are checked too. Per unique common dir: config traps, remotes (ext::/fd:: = high, embedded
  credentials = medium, untrusted host = low/medium, pushurl on another host = medium), hooks (git-lfs, husky,
  pre-commit and similar are expected; risk high/medium → finding; an unknown benign hook = low), stale worktrees
  (low), and repos owned by accounts other than the primary GitHub owner (info).
- **Expected false positives**: corporate proxies, Git Bash/WSL profiles, deliberate YOLO-mode, legitimate dev-server
  folderOpen tasks, devcontainer host prep, hook managers, crypto/calendar extensions.
- **Gaps / v2**: the VS Code trusted-folder list (state.vscdb SQLite) is not parsed. No Authenticode check of native
  binaries in extensions. JS beyond the cap is not scanned. Repos deeper than 5 levels or on other drives are not
  covered. There is no JetBrains plugin intel (host not allowlisted). WSL/remote/container extension hosts are not
  scanned. Git line continuations are not parsed. MCP configs (mcp.json) are left to S09.
- **Linux v2**: same shapes from `~/.vscode/extensions`, `~/.cursor/extensions`, `~/.config/{Code,Cursor}/User`,
  `/etc/gitconfig`, `~/.gitconfig`, `~/.config/git/config`, `~/.config/JetBrains`; reuse the sidecar unchanged.

## (c) Run

```
pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S10-editors-git.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S10-editors-git.ps1 [-NoIntel] [-RepoDepth 5] [-MaxJsMB 30]
```
- Runtime about 35 s; about 25 s of that is the JS scan.
- Outputs: `data\<scanId>\security\S10.json`, `logs\S10.log`, and intel copies under `intel\<host>\`.
- `extensions.code_scan` is `partial` when an extension's JavaScript exceeds `-MaxJsMB`; large AI and
  language-server extensions do.
