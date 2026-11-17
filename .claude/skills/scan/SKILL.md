---
name: scan
description: Run baby-virus-scanner on this Windows PC - preflight, consent questions, the read-only security and storage scan, a plain-language report and the local dashboard. Use when the user asks to scan, check or audit this PC, asks whether they have been hacked or compromised, or wants to know what fills the disk.
argument-hint: "[lan] [deep]"
---

Follow `AGENTS.md` in the project root. It is the single source of truth for this workflow:
sections 1 to 5 are the standard scan, in that order (preflight, then the questions, then the
scan, the report, the dashboard). Sections 6, 9 and 10 apply when their situation comes up. Obey
its "Rules that never bend" throughout. Do not add, skip or reorder steps.

Notes for Claude Code:

- **Consent:** after `doctor`, ask the questions of AGENTS.md section 2 in one question dialog.
  If `$ARGUMENTS` contains `lan`, the user has already asked for network discovery; still
  confirm that this is their own home network.
- **Running:** start `pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 scan -Parallel 4`
  as a background command. Check `status` when you are notified or the user asks; do not poll
  in a tight loop.
- **Report:** AGENTS.md section 4. Keep it short and calibrated, most important first.
- **Dashboard:** offer to open it (section 5).
- **Deep review** (AGENTS.md section 7): offer it after the report, or do it when `$ARGUMENTS`
  contains `deep`. For verification, give each high or critical finding to the `bvs-verifier`
  subagent, several in parallel, and write their records yourself into
  `data\<scanId>\verify\V1.json`. Then run the `report` command.
