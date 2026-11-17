# Dashboard v3 contract: signals, agent map, privacy (agents K, L, M)

> Design contract used while these features were built. Kept as contributor documentation. The wording says
> "Claude" because the dashboard labels the connected agent that way; any agent that runs the listener in
> `docs/playbooks/K-signals.md` takes the same role.

Extends `docs/ui-contract.md` (still binding). **Goal:** the localhost dashboard becomes the user's remote
control for the Claude session. Buttons send **signals**, Claude picks them up and acts, and anything
destructive needs **two confirmations typed by the user**: one in the browser and one in the Claude
chat. Claude never types either.

## 1. Signal bus (owner K: server + session tools)

**Files (project-relative)**
| Path | Contents |
|---|---|
| `data/signals/inbox/<id>.json` | new signal, written by the server |
| `data/signals/status/<id>.json` | status updates, written by session tools / Claude: `{id, state, message, updatedAt}` |
| `data/signals/archive/<id>.json` | handled signals (moved by the watcher) |
| `data/session/heartbeat.json` | `{pid, startedAt, beatAt}`, written every 5 s by `tools/windows/watch-signals.ps1` while a Claude session listens |

`<id>` is `yyyyMMdd-HHmmss-<type>-<6 random>`.

**Signal JSON:** `{schema:'bvs.signal/1', id, type, createdAt, scanId, payload, local: {typedConfirmation:true|false, at}, codeHash?, codeSalt?}`

**States:** `queued` → `picked-up` → `awaiting-chat-confirmation` (delete/fix) → `running` → `done` | `error` | `cancelled` | `expired` (after 60 min).

**Signal types (allowlist; anything else → 400)**
| type | payload | What Claude does |
|---|---|---|
| `run-admin` | `{}` | Shows the admin script hash in chat and launches the elevated read-only run (one Windows UAC prompt the user clicks) |
| `run-github-check` | `{}` | If gh is signed in, re-runs S13 authenticated; otherwise posts the sign-in instructions |
| `rerun-module` | `{module:'S01'..'S13'\|'G0'\|'G1'\|'G2'\|'H1'\|'H2'}` | Re-runs that collector, then aggregate + build_datajs |
| `fix-request` | `{findingId}` | Explains the fix in chat and asks for chat confirmation before changing anything |
| `delete-request` | `{items:[{id, path, bytes, method, label}]}` (at most 200 items) | Validates live, shows the final table, then waits for the user to type `I confirm <CODE>` in chat |
| `refresh-report` | `{}` | Runs aggregate + build_datajs |

**Delete-request double confirmation**
1. In the Basket the user clicks "Request deletion". A modal shows the exact list. The user must type exactly `I confirm` (case-sensitive) before the Send button enables.
2. `POST /api/signal` with `{type:'delete-request', payload, typedConfirmation:'I confirm'}`. The server re-checks the phrase (400 otherwise) and generates an 8-character code (alphabet `ABCDEFGHJKMNPQRSTUVWXYZ23456789`). It stores ONLY `codeSalt` + `codeHash` = PBKDF2-HMAC-SHA256(code, salt, 600,000 iterations) in the signal file and returns `{id, code}` to the browser **once**. The code is never logged or written.
3. The dashboard shows big: **"Now type this in your Claude chat: I confirm K7Q2-M9XP"**, with a copy button and a warning ("Claude will never type this for you").
4. Claude runs `tools/windows/validate-delete.ps1 -SignalId <id>`. This re-validates every item live and writes `data/signals/tables/<id>.json` with a `tableHash`. Claude then posts the final table in chat and waits.
5. The user types `I confirm <CODE>` in chat. Claude runs `tools/windows/execute-delete.ps1 -SignalId <id> -Code <CODE as typed>`. The script verifies codeHash, the local confirmation, tableHash and expiry (60 min), then executes. It uses the Recycle Bin when the item fits; otherwise it moves items to the same-drive `holding/<id>/`. Program items run the program's own interactive uninstaller. It logs every action to `logs/deletions.jsonl` and updates the status.

**Hard refusals** (validate and execute both): `C:\Windows`, Program Files (both), `ProgramData\Microsoft`, WindowsApps, `\.ssh\`, credential files (never-read list), the profile root, the roots of Documents/Desktop/Downloads/OneDrive, the project's active `data\` folder, reparse points, cloud-only placeholders, and anything outside `%USERPROFILE%` for file operations.

**Server API (K)** — the same protections as `/api/ask`: Host allowlist, exact Origin, `X-BVS-Token`, JSON only, at most 64 KB, a rate limit.
| Route | Returns |
|---|---|
| `POST /api/signal` | `{id, state:'queued', code?}` |
| `GET /api/signals` | the 30 most recent signals with state/message (never codes or hashes) |
| `GET /api/session` | `{connected: beatAt < 15 s ago, beatAt, pid}` |
| `GET /api/agents/live` | running agentic tools on this PC, read-only: claude, codex, gemini, aider, cursor-agent, Cursor, Windsurf, Copilot CLI. Fields: name, pid, started, kind, masked short command, never full command lines with secrets. |

**Session watcher (K):** `tools/windows/watch-signals.ps1` is run by Claude in the background. It writes a heartbeat every 5 s, and when a new inbox file appears it prints a one-line masked summary (`SIGNAL <id> <type> ...`), moves the file to archive, writes status `picked-up` and EXITS. That exit is what wakes Claude. Claude handles the signal, then restarts the watcher. Re-running is safe: queued signals are picked up oldest first.

## 2. Security tab additions (owner L: `app.js` / `style.css` / `index.html` / `basket.js` / `infosec.js`)
- **New "Checks" section/page (`#/checks`, also reachable from Security).** It groups every check from the `coverage` dataset into: **Ran fully** (ok), **Partly** (partial), **Needs your admin rights** (needs_admin), **Needs your login** (needs_consent, e.g. GitHub), **Not applicable**, **Skipped/errors**. Each group shows counts and plain names by module, and every check is clickable (panel: what it checks, status, reason).
- **Permission buttons:**
  - "Run the admin checks now (1 Windows prompt)" → signal `run-admin`.
  - "Run the GitHub deep check" → shows the sign-in command with a copy button, then signal `run-github-check`.
  - Each module gets "Re-run" → `rerun-module`.

  Show the signal state live (poll `/api/signals` every 4 s while visible) and the **session status pill**: "Claude connected" (green) or "Claude not listening: open the Claude session and ask it to start the dashboard listener" (grey). Show it in the top bar too.
- **Finding panel:** "Ask Claude to fix this" → `fix-request` (explain that Claude will ask in chat before changing anything).
- **Basket:** "Request deletion" modal, as in §1 (local typed "I confirm" + one-time code display). Show the request's progress. Never a direct delete.
- **Privacy & AI page (`#/privacy`, sidebar item "Privacy & AI"):** what is scanned and what is NEVER read, where data is stored, retention, what goes to the AI and when, the AI disclosure (EU AI Act Art. 50), user rights. Content comes from `docs/PRIVACY.md` (main agent), summarised in UI text.
- **AI consent gate (in `infosec.js` + `scanner.js`):** before the first AI request, a modal: "INFOSEC sends the question, the text you selected and the related findings to Claude (Anthropic) using your Claude Code login. Personal file names are hidden first. Allow?" with Allow / Only offline answers. Store the choice in localStorage. Send the header `X-BVS-AI-Consent: yes` (server K requires it). Every AI answer gets the badge "AI-generated (Claude) — check important steps".
- **Privacy mode toggle** (top bar, default ON): file names inside personal folders (Documents, Desktop, Downloads, Pictures, Videos, Music, OneDrive) show as `[personal file · .ext]` and folder names under them as `[personal folder]`. Show the real name only after a click in the side panel. Expose it as `BVSApp.privacy.label(path, name)` and `BVSApp.privacy.on`. Apply it in your views and in `storage-view.js`, a minimal edit: route displayed names through the helper.

## 3. Agent map (owner M: `dashboard/agents-view.js`, `dashboard/agents.css`, `core/build_agents.py`)
- **Data:** `core/build_agents.py --scan <dir>` reads `data/agents-ledger.json` (main agent seed: every agent with role, module, tokens, tool uses, duration, status, notes) plus the collectors (line counts) plus the module envelopes (run time from started/finished, findings, check counts). It writes `<scan>/agents.json`; `core/build_datajs.py` exports it as dataset `agents` (main agent wires this).
- **Difficulty scale** (show the legend everywhere):
  | Grade | Colour | Rule |
  |---|---|---|
  | easy | green | tokens < 150k and duration < 10 min |
  | medium | yellow | tokens < 350k |
  | hard | red | tokens < 450k |
  | extra high | dark purple `#4B1D6B` | tokens ≥ 450k or duration ≥ 45 min |

  Without token data, estimate from the collector's lines: < 500 easy, < 1500 medium, < 3000 hard, ≥ 3000 extra high. Show an "estimated" badge.
- **View (`#/agents`, sidebar item "Agent map"):**
  - A visual map. Orchestrator (this Claude session) at the centre, phases as rings or columns (Recon → Security scan → Verify → Storage → Dashboard v1 → Dashboard v2), agents as nodes coloured by difficulty, edges to the modules and files they produced.
  - Per-agent cards: tokens, tool calls, duration, script length, run time, status (done / stopped by usage limit / resumed), findings produced.
  - Totals: tokens per phase, heaviest agents.
  - A "Live agentic tools on this PC" section from `GET /api/agents/live`, polled every 10 s when visible: Claude/Codex/Cursor sessions that are running.
  - Clicking anything opens a side panel. Data attributes are present for the scanner.

## 4. Privacy guarantees (all agents)
- Never add new reading of personal content.
- AI context: replace the Windows username with `<user>`, personal file names with `[personal file .ext]`, and drop evidence fields that aren't needed (K implements this in `core/ai_bridge.py`).
- No signal can trigger deletion, fixes or network calls without the user's chat confirmation.
