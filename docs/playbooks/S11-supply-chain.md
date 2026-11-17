# S11-supply-chain

> Generated from the collector's own code by `tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File tools\windows\gen-playbook.ps1 -Path collectors\security\windows\S11-supply-chain.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S11 - Software supply chain (npm / PyPI malware). Read-only collector for baby-virus-scanner.

```text
Builds an inventory of every npm and PyPI package version on this machine that is
  - installed   (project node_modules, npm/pnpm/yarn/bun globals, venvs, global site-packages),
  - locked      (package-lock / npm-shrinkwrap v1-3, yarn.lock v1+berry, pnpm-lock v5/v6/v9,
                 bun.lock, poetry.lock, uv.lock, Pipfile.lock, pinned requirements*.txt),
  - downloaded  (npm cache index-v5: everything ever fetched), or
  - executed    (npm-cache\_npx one-off runs),
and checks it against
  - OSV (api.osv.dev querybatch + vulns/<id>): MAL-* ids, "malicious" advisories, CWE-506;
    ordinary vulnerabilities are only counted per project (hygiene, not part of the verdict);
  - the local, NON-EXHAUSTIVE sidecar S11-iocs.json: known-compromised versions plus FILE
    indicators of the Shai-Hulud family (package-root loaders, repo backdoors in .github,
    .claude, .vscode, .cursor, .gemini, host persistence such as gh-token-monitor).
It also flags suspicious npm lifecycle scripts (preinstall/install/postinstall, binding.gyp
command expansion), Python .pth startup hooks, and registry overrides (.npmrc, .yarnrc*,
bunfig.toml, pip.ini/pip.conf, uv.toml, pyproject/Pipfile sources, env vars).

Safety: never runs npm/npx/pnpm/yarn/bun/pip/uv; every source is parsed as a file. Reads go
through Test-BvsNeverRead / Test-BvsCloudOnly; this project and its transcript folder are
excluded. Only package name@version leaves the machine (OSV via Invoke-BvsIntel). Tokens in
.npmrc / .pypirc are never read into the output: only "a token exists for host X".

Contract : docs\schema.md          Rules : docs\agent-rules.md
Playbook : docs\playbooks\S11-supply-chain.md
Output   : data\<scanId>\security\S11.json  (bvs.module/1)
```

## (b) Implementation

Collector: `collectors\security\windows\S11-supply-chain.ps1`. Library: `lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S11-iocs.json`.

| Check | What it does |
|---|---|
| `supply.discover` | Find lockfiles, manifests, node_modules, venvs, npm caches and repos under the user profile (depth-limited, no node_modules recursion); group copies by lockfile hash |
| `npm.lockfiles` | Parse package-lock/npm-shrinkwrap (v1-3), yarn.lock (v1, berry), pnpm-lock.yaml (v5/v6/v9) and bun.lock once per unique lockfile |
| `npm.installed` | What is actually installed: node_modules\.package-lock.json, else pnpm virtual store, else node_modules walk |
| `npm.globals` | Global packages for every nvm version, Program Files nodejs, %APPDATA%\npm, pnpm/yarn/bun/fnm globals |
| `npm.cache` | npm cache index-v5: every tarball ever downloaded (name@version, first-seen time) |
| `npm.npx` | npm-cache\_npx folders: history of npx one-off runs (executed code) |
| `python.lockfiles` | Pinned requirements*.txt, poetry.lock, uv.lock, Pipfile.lock |
| `python.environments` | dist-info / egg-info names in venvs, global and per-user site-packages, Store Python, pipx/uv tools, conda |
| `osv.query` | OSV querybatch for every unique name@version (npm, PyPI) |
| `osv.details` | OSV vulnerability details (cached) and malicious classification |
| `supply.malicious` | Malicious package versions (OSV + sidecar IoC list): critical if installed or locked, high if only cached or executed via npx |
| `ioc.package_files` | Shai-Hulud family loaders at installed package roots (setup_bun.js, bun_environment.js, Math_Symbol.js, setup.mjs + preinstall) |
| `ioc.repo_files` | Worm repo artifacts: shai-hulud workflows, formatter_*/discussion/format-check workflows, toJSON(secrets), .claude/.vscode/.cursor/.gemini backdoors (read only) |
| `ioc.host_paths` | Worm persistence/staging: gh-token-monitor, sysmon.py, .dev-env runner, bun-dl temp folders, watcher scheduled task, staging file names |
| `npm.lifecycle` | preinstall/install/postinstall of installed packages (and binding.gyp command expansion): download/exec, encoded, obfuscated or oversized scripts |
| `python.pth` | Python .pth startup hooks with exec/network/decode code, plus PyPI worm files in site-packages |
| `registry.overrides` | .npmrc (user/global/project), .yarnrc*, bunfig.toml, pip.ini/pip.conf, uv.toml, .pypirc, pyproject/Pipfile sources and env vars: non-default registries, extra indexes, TLS off, plaintext credentials (never printed) |
| `osv.hygiene` | Ordinary vulnerability counts per project group (hygiene, not part of the verdict) |

Parameters: `-MaxDepth`, `-Offline`, `-OsvBatchSize`, `-OsvCacheDays`, `-OsvMaxDetails`, `-OsvThrottle`, `-WalkMaxPackages`.

## (c) Run

```powershell
pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S11-supply-chain.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S11-supply-chain.ps1
```

Output: `data\<scanId>\security\S11.json` (`bvs.module/1`). Log: `logs\S11.log`.
