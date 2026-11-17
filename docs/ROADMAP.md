# Roadmap

## 0.1 (current): agent-operated scan on Windows

- [x] Shared Windows library, AST safety linter, masking, never-read list, intel allowlist
- [x] Scan sessions, before/after state snapshots
- [x] 13 security modules, inventory, storage, duplicates, programs and health modules
- [x] Aggregator, verdict rubric, verification records, localhost dashboard
- [x] Delete-request basket with validated, logged, double-confirmed deletion
- [x] One-command scan (`bvs.ps1 scan`), preflight (`doctor`), demo mode
- [x] Agent runbook (`AGENTS.md`) and task briefs
- [ ] Elevated admin checks and signed-in GitHub checks verified end to end (experimental today)

## Next

- **Scan diffing:** "what is new since the last scan" (new autostarts, extensions, listeners,
  packages).
- **Stable finding fingerprints:** a hash of module, check and key evidence. Verification
  records and diffs should key on fingerprints, not on sequential IDs (`S07-0022`), which shift
  when a collector is re-run.
- **Verification as code:** automatic second-method re-checks for high and critical findings.
- **Admin findings as code:** today the elevated run gets coverage automatically and findings
  only from a reviewer.
- **Agent-neutral dashboard wording** (it says "Claude" for the connected agent) and an
  explainer that can use other local or hosted models.
- **Reuse an existing GitHub CLI sign-in** for the account checks.
- **A global offline switch** that skips every threat-intelligence lookup.
- **Signed release archive.** No installer, no services, no background agents.

## Linux

- Python collectors producing identical envelopes (see `src/collectors/security/linux/README.md`).
- Shared modules reused as they are: browsers, editors, supply chain, secrets, accounts.
- ClamAV, rkhunter and chkrootkit as optional report-only engines.

## Later

- Rule packs as data (IoCs, expected-item templates per vendor) with freshness checks.
- Test corpus: synthetic, harmless "infected" fixtures for every detection.
- Localization of the dashboard.
- Opt-in scheduled local re-scans (Windows Task Scheduler, systemd timer).
- Real-time monitoring (ETW, auditd). A large step; to be evaluated separately.
- HTTPS and authentication for the dashboard, only if it ever becomes reachable from other
  devices. While it is loopback-only it stays on HTTP: a self-signed certificate means constant
  warnings and a local root CA is a forgery risk.

## Non-goals

- Automatic deletion or quarantine without a typed human confirmation.
- Uploading files or hashes to third-party services by default.
- Kernel drivers.
- Cloud CI or scheduled automation in this repository without the maintainer's explicit approval.
