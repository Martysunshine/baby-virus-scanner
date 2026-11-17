# Architecture

```
            ┌─────────────────────── platform layer ────────────────────────┐
            │ Windows: PowerShell 7 collectors + lib/windows/BVS.Common.psm1 │
            │ Linux (planned): Python 3 collectors, same output contract     │
            └───────────────┬───────────────────────────────┬───────────────┘
                            │ bvs.module/1 envelopes         │ inventory TSV
                            ▼ (findings, checks, inventory)  ▼ (dirs/files)
   data/<scanId>/{security,admin,verify,storage,inventory}/  ─────────────────┐
                            │                                                 │
                            ▼                                                 │
               core/aggregate.py  (cross-platform, stdlib)                    │
               merge · verification · score · coverage · verdict              │
                            │ summary.json                                     │
                            ▼                                                 │
               core/build_datajs.py  ◄────────────────────────────────────────┘
               window.BVS.register(...) data files, lazy treemap subtrees
                            │
                            ▼
   server/serve.py (127.0.0.1 only, Host/Origin/token checks, CSP)  →  dashboard/ (static UI, cannot delete)
                            │
                            ▼
   Basket → request + "I confirm" in the dashboard → validate-delete → "I confirm <CODE>" in the agent chat
          → execute-delete (Recycle Bin / holding folder / the program's own uninstaller)
```

## Design decisions

1. **The schema is the product's spine.** Every platform and every module emits
   `bvs.module/1` / `bvs.finding/1` (see `docs/schema.md`). Adding Linux, or a new check, never
   touches the aggregator or the UI.
2. **Collectors are dumb and safe. Judgement happens with evidence.** A collector records facts,
   with masking and coverage status, plus calibrated findings that carry `fp_notes`. The verdict
   needs a *verified* compromise finding. Verification uses a different method than the collector.
3. **Safety is enforced in code, not just in prose:**
   - the AST linter for collectors;
   - the never-read list;
   - masking that fails closed;
   - the intel host allowlist;
   - a project-folder write guard;
   - before/after state snapshots.
4. **Machine profiles are separate from logic.** Known-good items live in
   `config/local/expected.json`, each with `invalidIf` conditions. Collectors stay portable.
5. **Zero third-party runtime dependencies.** PowerShell 7 and the Python standard library only.
   No CDN scripts in the UI. A security tool should have a tiny supply chain itself.
6. **Humans own destructive actions.** The UI can only *compose* a delete request. Execution is a
   separate, validated, logged step that needs a typed confirmation.

## Components

| Component | Language | Notes |
|---|---|---|
| `lib/windows/BVS.Common.psm1` | PowerShell 7 | run lifecycle, masking, safe enumeration (reparse points skipped, cloud-only never opened), Authenticode, MOTW, magic bytes, ACL writability, registry (raw + LastWrite), command-line resolution, intel fetch |
| `collectors/*/windows/*.ps1` | PowerShell 7 | one module per file, re-runnable, documented in a playbook |
| `admin/windows/admin-checks.ps1` | PowerShell 7 | standalone; run elevated through `launch-elevated.ps1` (hash-pinned) |
| `core/*.py` | Python 3 stdlib | aggregation, verdict, dashboard data. Cross-platform. |
| `server/serve.py` | Python 3 stdlib | hardened localhost server: static files plus a small token-protected API (AI explainer, signals, saved chats) |
| `core/ai_bridge.py`, `core/signals.py`, `core/chat_store.py` | Python 3 stdlib | opt-in AI explainer with redaction; dashboard-to-agent signals and the delete-code check; saved chats |
| `dashboard/` | HTML/CSS/vanilla JS | `textContent`-only rendering, CSP-compatible (no inline code) |
| `tools/windows/` | PowerShell 7 | linter, scan sessions, snapshots, privacy check, verified tool downloads, delete validation/execution |

## Who does what: code and agents

Detection and judgement are code. The collectors apply fixed rules, and the verdict comes from a
fixed rubric in `core/aggregate.py`. `bvs.ps1 scan` runs all of it without any AI.

An AI agent is the *operator*: it runs the commands in [AGENTS.md](../AGENTS.md), asks for
consent, explains the result, and can add two kinds of evidence that the rubric then uses:
verification records (a second look at a finding by a different method) and known-good items the
user confirmed. It cannot set the verdict.

The project itself was built the same way it is meant to be extended: an AI coding agent
orchestrated parallel subagents, each of which wrote, linted, ran and documented one module
against the shared rules ([docs/agent-rules.md](agent-rules.md)) and data contract
([docs/schema.md](schema.md)). A human directed the work and decided what counts as acceptable.
