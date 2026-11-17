# S13-github-npm

> Generated from the collector's own code by `tools/windows/gen-playbook.ps1`. After changing the collector,
> regenerate it: `pwsh -File tools\windows\gen-playbook.ps1 -Path collectors\security\windows\S13-github-npm.ps1 -Force`. See `docs/METHODOLOGY.md` for the overall method.

## (a) Purpose

S13 - GitHub and npm account audit (read-only).

```text
Looks for signs of account takeover and supply-chain worms (Shai-Hulud 1.0/2.0, s1ngularity)
on the user's GitHub account and published npm packages, and lists the manual account checks
that have no API.

A  Public GitHub   profile, owned repos, public events, public gists, SSH / signing / GPG keys
                   (api.github.com, github.com/<user>.keys|.gpg) and, for repos that publish an npm
                   package, the local clone against the remote.
B  npm             packument (versions, publish times, publishers, maintainers, dist-tags, registry
                   signatures, provenance) compared with the local repo (tags, commits, package.json);
                   the newest tarballs are downloaded as bytes, listed with `tar -tzf` and read in
                   memory (never extracted to disk, never executed); read-only token calls (whoami,
                   profile/2FA, token list); maintainer search; local npm configuration.
C  Authenticated   only when `gh auth status` succeeds (vendor\gh\bin\gh.exe with GH_CONFIG_DIR =
   GitHub          <root>\vendor\gh-config): user, keys, emails, all owned repos, installations, orgs,
                   codespaces, per-repo hooks / deploy keys / runners / secret names / collaborators /
                   invitations / branches / workflows / runs / environments / pages, private events.
                   Otherwise every C check is recorded as needs_consent ("waiting for gh login").
D  Manual          inventory.manualChecks, built from S13-github-npm-manual.json.

Safety
  * Every HTTP request goes through Invoke-BvsIntel (host allowlist). gh is used only for
    `gh auth status` and `gh api --method GET`. Never `gh auth token`; never the npm CLI.
  * The npm token is read from the user .npmrc in memory, sent only in an Authorization header
    (responses not saved) and never printed, logged or stored.
  * Indicators live in S13-github-npm-iocs.json (data, not logic).

Contract: docs\schema.md   Rules: docs\agent-rules.md   Playbook: docs\playbooks\S13-github-npm.md
```

## (b) Implementation

Collector: `collectors\security\windows\S13-github-npm.ps1`. Library: `lib\windows\BVS.Common.psm1`.

Sidecar data (IoC lists and reference tables): `S13-github-npm-iocs.json`, `S13-github-npm-manual.json`.

| Check | What it does |
|---|---|
| `github.gh_auth` | GitHub CLI login state: vendor\gh\bin\gh.exe auth status with GH_CONFIG_DIR=<root>\vendor\gh-config (signature verified before use) |
| `s13.targets` | Resolve audit targets: local git repos, GitHub user, npm packages, identity, local SSH keys, commit-time baseline |
| `github.profile` | Public profile of the audited GitHub user (api.github.com/users/<user>) |
| `github.repos_public` | Owned public repos: worm repo names/descriptions, -migration copies, random 18-char names, recently created (users/<user>/repos?type=owner&sort=created) |
| `github.events_public` | Public event stream (up to 300 events): PublicEvent, CreateEvent bursts, MemberEvent, worm branches, pushes at unusual hours |
| `github.gists_public` | Public gists: exfiltration file names, worm markers, recently created |
| `github.ssh_keys` | SSH authentication and signing keys on the account (github.com/<user>.keys, users/<user>/keys, users/<user>/ssh_signing_keys) vs local ~\.ssh\*.pub fingerprints |
| `github.gpg_keys` | GPG keys on the account (github.com/<user>.gpg, users/<user>/gpg_keys) vs local signing configuration |
| `github.repo_sync` | For local repos that publish npm packages: remote default branch head and branch names vs the local clone |
| `npm.token_whoami` | Read-only: GET registry.npmjs.org/-/whoami with the token from the user .npmrc (in memory, response not saved) |
| `npm.local_config` | npm configuration files: plaintext registry tokens (class only, never values), strict-ssl, registry overrides |
| `npm.maintainer_search` | Public npm search maintainer:<npm user>: packages under the account that do not exist in the local repos |
| `npm.packument` | Registry metadata per package: versions, publish times, publishers, maintainers, dist-tags, modification time |
| `npm.versions_vs_local` | Every published version vs the local repo: matching tag or version-bump commit, publish time vs commit time and usual hours, publisher, install scripts in the published manifest |
| `npm.registry_signatures` | npm registry ECDSA signatures (dist.signatures) verified against registry.npmjs.org/-/npm/v1/keys for every version |
| `npm.provenance` | Provenance attestations (dist.attestations): source repository, workflow and commit vs the local repo |
| `npm.tarballs` | Download the newest $TarballCount tarball(s) per owned package (bytes only), verify dist.integrity, list with tar -tzf, read package.json in memory; compare files and install scripts with the repo's publishing package.json |
| `npm.token_profile` | Read-only: GET registry.npmjs.org/-/npm/v1/user (2FA mode) with the user .npmrc token (response not saved) |
| `npm.token_list` | Read-only: GET registry.npmjs.org/-/npm/v1/tokens (created, readonly, CIDR; identifiers masked) with the user .npmrc token |
| `github_auth.user` | (description is built at run time; see the script) |
| `github_auth.keys_emails` | (description is built at run time; see the script) |
| `github_auth.repos` | (description is built at run time; see the script) |
| `github_auth.installations_orgs` | (description is built at run time; see the script) |
| `github_auth.codespaces` | (description is built at run time; see the script) |
| `github_auth.repo_deep` | (description is built at run time; see the script) |
| `github_auth.events` | (description is built at run time; see the script) |
| `manual.checklist` | Manual account checks with no API (GitHub sessions/security log/apps/tokens/2FA, npm, Tailscale, Microsoft, Google, Anthropic, servers, cloud, mail, router) |

Plus 1 check(s) whose ID is built at run time (see the script).

Parameters: `-Authenticated`, `-PublicOnly`, `-GitHubUser`, `-NpmPackage`, `-RepoPath`, `-ReuseIntelMinutes`, `-TarballCount`, `-MaxRepos`, `-RecentDays`.

## (c) Run

```powershell
pwsh -NoProfile -File tools\windows\check-collector.ps1 -Path collectors\security\windows\S13-github-npm.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File collectors\security\windows\S13-github-npm.ps1
```

Output: `data\<scanId>\security\S13.json` (`bvs.module/1`). Log: `logs\S13.log`.
