# S12-secrets

> Generated from the collector's own code by `src/tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File src\tools\windows\gen-playbook.ps1 -Path src\collectors\security\windows\S12-secrets.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S12 - Secrets exposure: a masked inventory of where credentials sit in plaintext and whether they are exposed.

```text
Read-only collector for baby-virus-scanner (bvs.module/1, area "security").

What it looks at:
  1. Home dotfiles and CLI token stores (catalog in S12-secret-stores.json), AI-agent configs,
     persistent environment variables and Windows Credential Manager target NAMES (cmdkey /list).
  2. Repository secret files (.env family, project .npmrc/.mcp.json/Claude settings): per-rule counts,
     git tracked / in history / pushed, .gitignore coverage, GitHub visibility of the user's own repos.
  3. Key-material files (existence and metadata only).
  4. Shell histories (PSReadLine, bash, python, node, ...).
  5. Claude Code storage (transcripts, file-history, prompt history), Codex sessions, editor local history.
  6. SSH: private-key protection (Get-BvsSshKeyInfo only), public-key fingerprints, ACLs, ssh config,
     known_hosts and authorized_keys.

Safety contract (docs\agent-rules.md):
  * Never prints, logs or stores a raw secret. Output carries rule id, count, location, line numbers and
    the library's masked sample (Protect-BvsSecret). Cross-location correlation uses SHA-256 values that
    live only in memory; the output only has run-local reference ids (K001, K002, ...).
  * Files on the never-read list (Test-BvsNeverRead) and catalog entries with mode "exists" are reported
    by existence, size, timestamps and ACL only. SSH key protection comes only from Get-BvsSshKeyInfo.
  * git runs only as `git --no-optional-locks <read-only subcommand>`.
  * Network: only Invoke-BvsIntel to api.github.com, sending only the user's GitHub account name (and the
    names of that account's own repositories when the public list is unavailable).
```

## (b) Implementation

Collector: `src\collectors\security\windows\S12-secrets.ps1`. Library: `src\lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S12-secret-stores.json`.

| Check | What it does |
|---|---|
| `dotfiles.credential_stores` | Known CLI credential stores in the profile (npm, PyPI, Docker, cloud CLIs, Vercel, Netlify, Supabase, configstore, Hugging Face, Higgsfield, gh, Ollama key, agent auth files): token counts with masked samples; never-read files by existence/metadata/ACL only |
| `dotfiles.agent_configs` | AI-agent and editor configuration files (Claude Code, Claude Desktop, Codex, VS Code, Cursor, Windsurf, Gemini): secrets in MCP env blocks, headers, settings |
| `env.persistent_variables` | Persistent user and machine environment variables (registry) holding secret-looking values; names and masked values only |
| `dotfiles.credential_manager` | Windows Credential Manager: target NAMES only (cmdkey /list); shows which tools keep secrets in the OS store |
| `repos.secret_files` | Repository secret files (.env family, project .npmrc/.pypirc/.netrc, .mcp.json, Claude project settings) under the search roots, skipping node_modules and tool caches: per-rule masked counts, git tracked/history/pushed, .gitignore coverage |
| `repos.github_visibility` | Public/private status of the user's own GitHub repositories behind local secret files (api.github.com via Invoke-BvsIntel; 404 = private or absent) |
| `files.key_material` | Key-material files (*.key, *.pem, *.pfx/*.p12, *.ppk, *.ovpn, keystores, *-key/*-token/*-secret, id_* outside ~\.ssh): existence, metadata, ACL and git status only, never content |
| `history.shell` | Shell and REPL histories (PSReadLine, bash, zsh, python, node, psql, mysql, sqlite, redis, mongosh): secret hits per rule with masked samples and line numbers |
| `claude.transcripts` | Claude Code transcripts (~\.claude\projects: *.jsonl incl. subagents, tool-results, memory), streamed; this project's own folder excluded |
| `claude.file_history` | Claude Code file-history backups (copies of files Claude edited), mapped to original paths via transcripts; this project's sessions excluded |
| `claude.prompt_history` | Claude Code prompt history (~\.claude\history.jsonl, this project's lines skipped) and other small Claude stores (shell snapshots, session env, debug logs, plans, todos) |
| `agents.codex_sessions` | OpenAI Codex CLI session transcripts (~\.codex\sessions) and history; sessions whose cwd is this project excluded. auth.json is existence-only (catalog) |
| `editor.local_history` | Editor Local History (VS Code, Cursor, Windsurf): saved copies of secret-bearing files (.env family, credential configs), found via entries.json |
| `ssh.private_keys` | SSH private keys in ~\.ssh: passphrase protection via Get-BvsSshKeyInfo (cipher field only), file ACL principals beyond user/SYSTEM/Administrators |
| `ssh.public_keys` | SSH public keys (*.pub): type, bits, SHA256 fingerprint (computed natively, cross-checked with ssh-keygen -l -f) and comment; stored for comparison with GitHub-registered keys (S13) |
| `ssh.config` | ~\.ssh\config: Host blocks with HostName, User, IdentityFile, ProxyCommand/ProxyJump, Local/Remote/DynamicForward, ForwardAgent, StrictHostKeyChecking |
| `ssh.known_hosts` | known_hosts entry counts (hashed vs plain) and authorized_keys entries (fingerprints, comments, options) in ~\.ssh |
| `secrets.correlate` | Classify hits (configured / likely / historic / unknown / local / public / fixture / placeholder), correlate identical values across locations with run-local ids, build the secrets table and findings |

Parameters: `-SearchRoots`, `-GitHubUser`, `-NoNetwork`, `-MaxScanMB`.

## (c) Run

```powershell
pwsh -NoProfile -File src\tools\windows\check-collector.ps1 -Path src\collectors\security\windows\S12-secrets.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File src\collectors\security\windows\S12-secrets.ps1
```

Output: `data\<scanId>\security\S12.json` (`bvs.module/1`). Log: `logs\S12.log`.
