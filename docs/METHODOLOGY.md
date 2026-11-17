# Methodology: how a scan is carried out and judged

The same method works by hand, through the command line, or with an AI agent as the operator.
The agent's step-by-step runbook is [AGENTS.md](../AGENTS.md); this page explains the reasoning.

## Phase 0: preparation

1. **Preflight:** `bvs.ps1 doctor` checks PowerShell, Python and write access. It changes nothing.
2. **Consent, asked once and up front.** Each defaults to "no":
   - start the read-only scan;
   - active discovery on the local network (`-Lan`), only on the user's own home network;
   - whether a cloud-hosted agent may read the findings.

   The optional extras (one elevated run, a report-only antivirus engine pass, a GitHub sign-in)
   are asked separately, when the user wants them.
3. **Start a session:** `tools/windows/new-scan.ps1` creates `data/<scanId>/` and records
   `auditStartUtc`. Log entries after that time are the scan's own activity and are excluded.
4. **Before snapshot:** `tools/windows/snapshot-state.ps1 -Label before`.

## Phase 1: collection

`bvs.ps1 scan` runs the modules in this order:

1. **Inventory (G0):** file-system metadata. It comes first because the process-and-files module
   cross-checks it and the storage modules need it.
2. **Security modules S01 to S13.** Each one:
   - passes the safety linter before it runs;
   - reads only, and writes one masked `bvs.module/1` envelope;
   - records every check with a status, so coverage is known;
   - turns what it found into calibrated findings with evidence, the reasons it might be
     harmless (`fp_notes`) and manual recommendations.

The modules are independent, so they can run in parallel (`-Parallel N`).

## Phase 1b: independent verification (optional, recommended)

Every **high or critical** finding should be looked at a second time, by a verifier that tries
to *disprove* it using a **different method** than the collector:

| Collector source | Verifier cross-check |
|---|---|
| PowerShell registry provider | `reg.exe query` |
| `Get-NetTCPConnection` | `netstat -ano` |
| batch package lookup | the single package's advisory |
| antivirus report | quarantine list vs. whether the file still exists |
| public account events | the account's own security log |

The verifier writes a record (`confirmed`, `refuted` or `inconclusive`) into
`data/<scanId>/verify/`. Brief: [docs/agent/verify.md](agent/verify.md). Verification can be done
by a person or by a capable AI agent; it is not done by the scanner itself yet.

## Phase 1c: verdict

`core/aggregate.py` merges everything and applies a fixed rubric. The first matching row wins:

| Verdict | Rule | What happens |
|---|---|---|
| **COMPROMISED** | A critical *compromise* finding confirmed by a verifier | Stop. No clean-up. Incident steps (AGENTS.md, section 10). `bvs.ps1 scan` skips the storage phase. |
| **SUSPICIOUS** | A high or critical *compromise* or *suspicious* finding that is neither refuted nor explained | Questions for the user. No clean-up until it is resolved. |
| **HARDENING_NEEDED** | Medium findings, or serious weaknesses that are not signs of intrusion | A hardening list. |
| **OK** | Nothing above low severity | |

Refuted findings, informational findings and storage clean-up items never count. A finding is
"explained" when it matches a known-good item of this PC that the user confirmed
(`config/local/expected.json`), unless one of that item's cancel conditions holds.

The report always states its confidence and coverage (including log time windows), what could
not be checked, and the honest limits: no guarantee against kernel rootkits or firmware implants,
the router is not inspected, and a missing event is not proof.

## Phase 2: storage, speed and health

| Module | Covers |
|---|---|
| G1 | Treemap, big files, cold folders, junk and cache categories (purpose, safety, how to clean) |
| G2 | Duplicate files, and copies of code projects with a "work at risk" check |
| H1 | Programs (size, last used), startup impact, resource use, crashes |
| H2 | Broken references that have a real effect, disk and file health |

These are read-only too. Results go to the dashboard (`bvs.ps1 dashboard`).

## Phase 3: after snapshot

`snapshot-state.ps1 -Label after -CompareTo before`. The comparison is saved as
`data/<scanId>/snapshot-diff.txt`. Background activity of Windows and apps shows up there; a
change made by the scanner would too, which is the point.

## Phase 4: deletion (only when the user asks)

1. In the dashboard's Basket the user requests deletion and types `I confirm`. The server issues
   a one-time code, shown only in the browser.
2. `validate-delete.ps1` re-checks every item live. It refuses system folders, credentials,
   profile roots and anything outside the user's profile.
3. The final table is shown in the agent chat: method, reversibility, warnings.
4. The user types `I confirm <CODE>` in the chat. That covers only that table.
5. `execute-delete.ps1` sends items to the Recycle Bin when they fit, otherwise moves them to a
   `holding/` folder on the same drive; for a program it starts the program's own uninstaller.
   Everything is logged to `logs/deletions.jsonl`.

The scanner never empties the Recycle Bin, never runs third-party cleaners and never edits the
registry. Details: [docs/playbooks/K-signals.md](playbooks/K-signals.md).

## Evidence standards

- A finding without evidence is not a finding.
- Every finding states why it might be benign.
- Known-good items come from the machine profile, never from collector code, and each match is
  cancelled by its `invalidIf` conditions (for example "signature invalid" or "path changed").
- Scores come from reasons: persistence, obfuscation, masquerading, unsigned, user-writable,
  public network, recency, an intel or antivirus match.
