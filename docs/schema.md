# Data contracts

Every collector produces the same shapes on every platform. All of this data is consumed by the
aggregator (`src\core\aggregate.py`) and the dashboard.

**Conventions**
- Timestamps are ISO-8601 UTC (`2026-01-01T10:11:12.123Z`).
- Sizes are in bytes.
- Paths are absolute.
- Text is UTF-8 without BOM.
- Every string is already masked when written.

## Scan layout

```
data\latest.txt                 current scanId (yyyyMMdd-HHmmss)
data\<scanId>\scan-meta.json    bvs.scan/1: scanId, auditStartUtc, host, user, userSid, os, elevated
data\<scanId>\security\<ID>.json   security module envelopes (S01..S13)
data\<scanId>\admin\*.json         elevated read-only checks: raw sections (src\admin\windows\admin-checks.ps1) + X1.json (see below)
data\<scanId>\inventory\...        G0 file-system metadata (see below)
data\<scanId>\verify\*.json        verification records (see below)
data\<scanId>\storage\<ID>.json    storage/performance/health envelopes (G1, G2, H1, H2)
data\<scanId>\summary.json         aggregate + verdict (src\core\aggregate.py)
data\<scanId>\js\*.js              dashboard data (src\core\build_datajs.py)
data\<scanId>\scan-status.json     progress of `bvs.ps1 scan` (state, step, verdict, failed collectors)
data\<scanId>\snapshot-*.json      system state before/after; snapshot-diff.txt is the comparison
data\<scanId>\requests\            delete requests / confirmed tables
```

## Module envelope: `bvs.module/1`

```json
{
  "schema": "bvs.module/1", "module": "S01", "area": "security", "scanId": "20260101-101112",
  "host": "DEMO-PC", "platform": "windows", "elevated": false,
  "started": "...", "finished": "...",
  "checks":   [ { "id": "persistence.run_keys", "description": "...", "status": "ok|partial|skipped|needs_admin|needs_consent|not_applicable|error", "reason": null, "items": 14, "ms": 120 } ],
  "findings": [ <bvs.finding/1> ],
  "inventory": { "<name>": <any structured data for dashboard tables> },
  "errors":   [ { "check": "...", "error": "...", "at": "..." } ]
}
```

## Finding: `bvs.finding/1`

```json
{
  "id": "S01-0007", "module": "S01", "check": "persistence.run_keys",
  "title": "Run key starts unsigned EXE from AppData",
  "severity": "critical|high|medium|low|info",
  "class": "compromise|suspicious|hardening|hygiene|info",
  "confidence": "high|medium|low",
  "reasons": ["persistence", "user_writable", "unsigned", "created_lt_30d"],
  "evidence": [ { "type": "registry", "path": "HKCU\\...\\Run", "name": "Updater", "value": "C:\\Users\\...\\u.exe" } ],
  "entities": { "files": [ { "path": "...", "sha256": "...", "size": 0, "sig": "NotSigned", "signer": null, "created": "...", "motw": { "zone": 3, "host": "..." } } ],
                "processes": [], "network": [], "registry": [], "accounts": [] },
  "expected": null,
  "fp_notes": "why this could be benign",
  "recommendation": "manual steps only",
  "mitre": ["T1547.001"],
  "collected_at": "...", "collector": "S01",
  "verification": null
}
```

**`verification`** is filled by the aggregator from the verification records (next section):
`{ "result": "confirmed|refuted|inconclusive", "method": "...", "by": "V1", "at": "..." }`.

**Reason vocabulary** (use these where they fit, add new ones freely):
`persistence`, `obfuscation`, `masquerading`, `unsigned`, `invalid_signature`, `user_writable`,
`public_network`, `created_lt_30d`, `motw_unknown_host`, `random_name`, `intel_match`, `av_match`,
`lolbin`, `encoded_command`, `hidden`, `exposed_service`, `plaintext_secret`, `prompt_injection`,
`expected_match`.

**Score**, computed by the aggregator from the reasons; collectors still choose their own severity:

| Reason | Points |
|---|---|
| `persistence` | +3 |
| `obfuscation` | +3 |
| `masquerading` | +4 |
| `invalid_signature` | +4 |
| `unsigned` | +2 |
| `user_writable` | +2 |
| `public_network` | +2 |
| `created_lt_30d` | +1 |
| `motw_unknown_host` | +1 |
| `random_name` | +1 |

`intel_match` or `av_match` on a live artifact means critical. Score bands: 8 or more is critical,
5–7 high, 3–4 medium, 1–2 low.

## Verdict (`summary.json`)

Computed by `src\core\aggregate.py` (`compute_verdict`). The first matching row wins.

| Verdict | Condition |
|---|---|
| `COMPROMISED` | At least one critical `compromise` finding with `verification.result = confirmed` |
| `SUSPICIOUS` | At least one high or critical finding of class `compromise` or `suspicious` that is neither refuted nor explained |
| `HARDENING_NEEDED` | At least one medium finding, or a high/critical `hardening` or `hygiene` finding, that is neither refuted nor explained |
| `OK` | Nothing above low severity is left |

What never counts: `info` findings, refuted findings, and storage clean-up (`hygiene`) items.
A finding is **explained** when it carries a valid `expected` match (not cancelled by an
`invalidIf` condition, not marked `confirmWithUser`).

`summary.json` also carries:
- `verdictSource` (`computed` or `override`) and `computedVerdict`. A `verdict-override.json` in
  the scan folder (`{verdict, rationale, by, at}`) replaces the displayed verdict; the computed one
  stays visible, and `bvs.ps1 report` prints a warning. **Agents must not write this file**: see
  `AGENTS.md`.
- `confidence`: high when at least 90% of applicable checks are ok, every high/critical finding
  is verified and no security module is missing; medium from 70% with at most two modules
  missing; otherwise low.
- `coverage`: every check status, log windows, missing modules, and what the aggregator could not
  use (`unrecognizedFiles`, `parseErrors`, `orphanVerifications`).
- the honest limits of the scan.

## Verification records (`data\<scanId>\verify\*.json`)

A verifier re-checks a finding **by a different method** than the collector and records the
result. Any JSON file in `verify\` is read. The simplest accepted shape is a list:

```json
[
  { "findingId": "S07-0003", "result": "refuted", "method": "netstat -ano shows the port is owned by the signed vendor service",
    "by": "V1", "at": "2026-01-01T10:15:00Z", "notes": "one or two sentences" }
]
```

- `findingId` must be the exact `id` of a finding in this scan. A record that matches nothing is
  listed under `coverage.orphanVerifications` and has no effect.
- `result` is `confirmed`, `refuted` or `inconclusive`. When records disagree, confirmed wins over
  refuted, and refuted over inconclusive.
- Effects: a `refuted` finding no longer counts toward the verdict. A `confirmed` critical
  `compromise` finding makes the verdict `COMPROMISED`. `inconclusive` changes nothing except
  that the finding counts as looked at.
- Finding IDs are assigned per run. **Re-running a collector renumbers its findings**, so write
  records last and redo them for any module you re-run.
- Do not add `explained` or `benign` to a record. The aggregator honours them (they take a
  finding out of the verdict), so they are reserved for a known-good item the user confirmed; use
  `src\config\local\expected.json` for that.

## Admin summary (`data\<scanId>\admin\X1.json`)

`src\admin\windows\admin-checks.ps1` writes raw section files (`bvs.admin/1`), which the aggregator
does not read. The admin area counts as covered once `admin\X1.json` exists: a normal
`bvs.module/1` envelope with `"module": "X1"`, `"area": "admin"`, one check per section and any
findings. Every check needs an explicit `status` (a missing one is read as `ok`). Brief:
`docs\agent\admin-triage.md`.

## Machine profile (`src\config\local\expected.json`)

Known-good items of one PC. Git-ignored. Template: `src\config\expected.example.json`. Without the
file the scanner works and simply explains nothing away.

```json
{ "schema": "bvs.expected/1", "host": "DEMO-PC",
  "items": [
    { "id": "docker-hosts-entries", "category": "hosts",
      "match": { "hostnameRegex": "^(host|gateway|kubernetes)\\.docker\\.internal$" },
      "reason": "Docker Desktop.", "invalidIf": ["Docker Desktop not installed"],
      "severityCap": "info", "confirmWithUser": false }
  ] }
```

- `category` is one of: `path`, `hosts`, `network`, `listener`, `program`, `service`, `remoteTool`,
  `account`, `startup`, `task`, `firewallRule`, `rootCert`, `policy`, `securityCenter`, `posture`,
  `browserExtension`, `editorExtension`, `claudeConfig`, `avDetection`.
- `match` holds the fields the collector for that category reads (see the template).
- A match caps the finding at `severityCap` (default `info`) and marks it explained, unless an
  `invalidIf` condition holds. `confirmWithUser: true` keeps the question open.
- Every item hides something from the verdict. Add one only after the user confirmed that exact
  item. Brief: `docs\agent\calibrate.md`.

## G0 inventory (`data\<scanId>\inventory\`)

**`dirs.tsv`**: one row per directory, with a header row. Columns:
`id  parent  depth  path  ownBytes  ownFiles  totalBytes  totalFiles  totalDirs  newestWriteUtc  oldestWriteUtc  cold1yBytes  cold2yBytes  cold5yBytes  cloudOnlyBytes  cloudOnlyFiles  flags`
- `flags` is a comma-separated list: `inaccessible`, `reparse`, `onedrive`, `hardlink-heavy`
  (WinSxS, pnpm store), `user-writable-root`.
- Epochs are in seconds.

**`files.tsv`**: selected files only. Columns:
`path  sizeBytes  allocBytes  createdUtc  modifiedUtc  attributes  ext  reason`
- `reason` is one of: `large` (10 MB or more), `exec-recent` (executable/script in `C:\Users` or
  `C:\ProgramData`, changed in the last 90 days), `zero-byte`, `partial-download`, `root-of-user-folder`.

**`inventory-meta.json`**:
- volume size/free, scanned bytes/files/dirs;
- inaccessible dir count;
- cloud-only bytes;
- duration;
- `unaccountedBytes`, computed as used minus scanned.

## Storage item: `bvs.items/1`

Used by the G1/G2/H1/H2 envelopes under `inventory`.

```json
{ "id": "st-000123", "path": "...", "kind": "file|dir|program|registry|setting", "bytes": 0, "files": 0,
  "newestUtc": "...", "oldestUtc": "...", "category": "temp|browser-cache|dev-deps|...", "purpose": "plain-English what it is",
  "owner": "app/vendor", "safety": "safe|safe_after_check|review|use_tool|do_not_touch",
  "method": "recycle|holding|tool|uninstall|setting|none", "how": "exact cleaning instruction", "reversible": true,
  "flags": ["work_at_risk", "cloud_only"], "gitRisk": { "uncommitted": 0, "unpushed": 0, "stashes": 0 } }
```

## Collector API (`src\lib\windows\BVS.Common.psm1`)

| Function | Purpose |
|---|---|
| `Initialize-BvsRun -Module S01 -Area security` | Start a run; returns `$run` (`ScanId`, `OutDir`, `AuditStartUtc`, `Elevated`, `UserSid`) |
| `Invoke-BvsCheck -Run $run -Id x -Description d -Script { … }` | Run a check and record its status/timing; returns the script's output |
| `Set-BvsCheckStatus -Id x -Status partial -Reason r` | Override a check's status from inside its script |
| `New-BvsFinding -Run $run -Check -Title -Severity -Class [-Confidence -Reasons -Evidence -Entities -Recommendation -FpNotes -Mitre -Expected]` | Add a finding |
| `Add-BvsInventory -Run $run -Name n -Data d` | Add dashboard data |
| `Complete-BvsRun -Run $run` | Write the masked envelope; returns a summary |
| `Get-BvsExpected [-Category c]` | Machine-specific known-good items |
| `Protect-BvsText`, `Protect-BvsSecret`, `Protect-BvsUrl`, `Find-BvsSecrets` | Masking and secret detection |
| `Write-BvsJson -InputObject o -Path p` | Atomic JSON write inside the project only (masked) |
| `Get-BvsFiles -Path … [-Include *.exe] [-ModifiedAfter d] [-MaxDepth n] [-Directories] [-NoPrune]` | Safe enumeration |
| `Test-BvsCloudOnly`, `Test-BvsNeverRead`, `Test-BvsUserWritable` | Safety and permission tests |
| `Get-BvsSignature`, `Get-BvsHash`, `Get-BvsVersionInfo`, `Get-BvsMotw`, `Get-BvsMagic`, `Test-BvsMagicMismatch`, `Get-BvsSshKeyInfo` | File facts |
| `Get-BvsRegValues`, `Get-BvsRegSubKeys`, `Get-BvsRegKeyLastWrite`, `Open-BvsRegKey` | Registry reads (raw, unexpanded; `-View 32` for WOW64) |
| `Resolve-BvsCommandLine`, `Get-BvsProcessTable` | Command-line parsing and the process list |
| `Invoke-BvsIntel -Uri … [-Method POST -Body …] [-Headers …] [-AllowLan]` | The only way to reach the network; returns `Status`, `Content`, `Json`, `File` |
