# M: Agent map tab (docs/ui-contract-v3.md section 3)

## What it is
`#/agents`, sidebar "Agent map" (Tools). Shows every AI helper that worked on the scan, how heavy its job was
(green E Easy, yellow M Medium, red H Hard, dark purple `#4B1D6B` X Extra high, grey ? not measured), how long
its scripts are, and which AI tools run on this PC right now. Read-only; never invents a number (null = "not measured").

## Files
| File | Role |
|---|---|
| `src/core/build_agents.py` | `python -I -B src/core/build_agents.py --scan <dir> [--js <file>]` -> `<scan>/agents.json` (`bvs.agents/1`) |
| `dashboard/agents-view.js` | `BVSApp.registerView('agents', ...)`, data from `BVSApp.data.get('agents')` |
| `dashboard/agents.css` | styles, all scoped under `.agents-view` (view root, tooltip, panel content) |

## Data flow
The tab is optional. It needs a ledger that the orchestrating agent writes by hand; without one the
tab shows an empty state and nothing else is affected.

`data/agents-ledger.json` (main agent: tokens, tool calls, duration, status, produced files) + line counts of the
produced files (scripts/code only; `(v1)`/`(input)` entries, docs and configs are listed but not counted) + module
envelopes `<scan>/{security,storage,inventory,admin}/<module>.json` (run time = finished - started, findings,
checks) + `<scan>/verify/*.json` record counts -> `agents.json` -> `src/core/build_datajs.py` exports dataset `agents`.

## Ledger format (`data/agents-ledger.json`)
```json
{ "schema": "bvs.agents-ledger/1", "project": "baby-virus-scanner",
  "orchestrator": { "name": "...", "model": "...", "role": "...", "tokens": 0, "durationSec": 0 },
  "notes": [], "phases": [ { "id": "p1", "label": "Security collection", "order": 1 } ],
  "agents": [ { "id": "S07", "name": "Network", "kind": "collector", "phase": "p1", "module": "S07",
               "status": "finished", "tokens": null, "toolUses": null, "durationSec": null,
               "produced": [ "src/collectors/security/windows/S07-network.ps1" ], "notes": "" } ] }
```
Use `null` for anything that was not measured. Keep notes free of machine and account details: the
ledger is copied into the dashboard data.

## Grading (contract rules)
Measured: extra-high if tokens >= 450k or duration >= 45 min; easy if tokens < 150k and < 10 min; medium < 350k;
hard < 450k. Without tokens: estimated from script lines (< 500 / < 1500 / < 3000 / more), shown dashed with an
"estimated" badge. Neither: ungraded grey "?". Each agent carries `difficultyReason` in plain words.

## View
Header + 4 tiles (helpers, tokens, helper time, longest scan script) -> sticky legend (click a grade = list) ->
Map | Cards | Table toggle (remembered in localStorage) -> tokens-per-round stacked bars + heaviest jobs ->
script-length bars with the typical (median) scan script line -> live tools -> "Where these numbers come from".
Map: radial tree, the main agent in the centre, numbered round hubs clockwise, nodes sized by tokens (area), letter inside,
status badge (finished / resumed / usage limit / replaced), outer bars = produced files (length = lines).
Hover/focus = tooltip; click/Enter = side panel. Deep link `#/agents?agent=S07&view=table`.
Live: `GET /api/agents/live` with `X-BVS-Token` from `/api/status`, every 10 s while visible; friendly notes on
file://, a missing route (404) or errors. Shell/test pages may set `BVSApp.fetchAgentsLive()` instead.

## Safety & accessibility
textContent only, SVG via createElementNS, no inline styles in markup; traversal/absolute produced paths are never
read; files > 8 MB not counted. Never colour alone (letters, icons, dashes); light/dark; reduced motion honoured.
Re-run after new agents: update the ledger, then `build_agents.py` and `build_datajs.py`.
