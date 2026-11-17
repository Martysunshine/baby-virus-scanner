# Changelog

## 0.1.0

First public release.

### Scanner
- 13 read-only security modules (S01 to S13): persistence, processes and files, accounts and
  posture, history and logs, antivirus evidence, browsers, network, LAN, AI tools, editors and
  git, supply chain, secrets exposure, GitHub and npm.
- File-system inventory (G0) and storage, duplicates, programs and health modules
  (G1, G2, H1, H2).
- Shared library with fail-closed secret masking, a never-read list, an AST safety linter for
  collectors and a host allowlist for threat-intelligence lookups.
- Aggregator with a fixed verdict rubric, verification records and coverage reporting.
- Local dashboard (127.0.0.1 only): verdict, findings, storage map, checks, an optional AI
  explainer, and a delete-request basket with double confirmation.

### Command line
- `bvs.ps1 doctor`, `scan` (one command, resumable, optional background mode), `status`,
  `report`, `dashboard`, `demo`.
- `get-tools` (verified downloads of the two optional external tools), `github-login`,
  `github-logout`, `check-publish`.
- LAN discovery is passive unless `-Lan` is given.
- Comma lists (`-Only S01,S02`) work through `pwsh -File`.

### For AI agents
- `AGENTS.md` runbook with consent steps that default to "no", a Claude Code `/scan` skill and
  verifier subagent, and task briefs under `docs\agent\`.

### Optional extras
- Elevated admin checks with a report-only Microsoft Safety Scanner pass, and signed-in GitHub
  checks. Both are off by default, and both were run end to end before release.

### Fixed before release
- Driver blocklist (LOLDrivers) feed with keys that differ only by case.
- Boot-performance admin section on Windows' StartupInfo XML.
- A false "Defender disable commands" alarm caused by Microsoft's own Defender module code in the
  PowerShell log.
- Detections of a detect-only scan were summarised as "removed or blocked"; they are now reported
  as still present.
