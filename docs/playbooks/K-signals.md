# K: signal bus and double-confirmation deletion

**Brief:** dashboard buttons send signals to the AI agent's session (the dashboard calls it "Claude"; any agent
that runs the listener below works the same). Deletion needs TWO confirmations typed by the user: `I confirm` in
the dashboard, then `I confirm <CODE>` in the agent chat. The agent must never complete a deletion on its own.
Contract: `docs/ui-contract-v3.md` sections 1 and 4.

**Files:** `src/core/signals.py` (schema, code, store), `src/core/agents_live.py`, `src/core/ai_bridge.py` (Redactor),
`src/server/serve.py` (routes), `src/tools/windows/BVS.Signals.psm1` (read-only helpers), `watch-signals.ps1`,
`signal-status.ps1`, `validate-delete.ps1`, `execute-delete.ps1` (the ONLY script that deletes).

## The agent's loop
1. Start the listener in the background (it wakes you by exiting):
   `pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\watch-signals.ps1`
2. On `SIGNAL <id> <type> <summary>`: handle it, report progress with
   `pwsh -NoProfile -File src\tools\windows\signal-status.ps1 -Id <id> -State running|done|error -Message "..."`, then
   start the watcher again. `NO-SIGNAL` = timeout (600 min): just restart it.
   - `run-admin`: if the Safety Scanner is missing or older than 10 days, ask the user, then
     `bvs.ps1 get-tools -Msert`. Show the admin script hash and launch `bvs.ps1 admin` (one Windows admin prompt
     the user clicks).
   - `run-github-check`: if the scanner is signed in (`bvs.ps1 doctor` says so) re-run S13, else post the sign-in
     steps (`bvs.ps1 get-tools -Gh`, then the user runs `bvs.ps1 github-login`).
   - `rerun-module`: re-run that collector (`bvs.ps1 security -Only <ID>`), then `bvs.ps1 report`. For S08, ask
     before adding `-Lan`. Re-running a collector renumbers its findings, so verification records for that
     module must be redone.
   - `refresh-report`: `bvs.ps1 report`.
   - `fix-request`: explain the fix in chat as steps the user carries out. The agent does not change the system.
3. `delete-request`:
   - `pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\validate-delete.ps1 -SignalId <id>`
     (read-only), then post the printed table + its `ref` and WAIT.
   - Only after the user types `I confirm <CODE>`:
     `pwsh -NoProfile -ExecutionPolicy Bypass -File src\tools\windows\execute-delete.ps1 -SignalId <id> -Code <CODE as typed>`
   - Exit 0 done, 1 refused (nothing deleted), 2 wrong code (5 wrong = locked), 3 some actions failed.
     Never type, guess or reuse a code.

## Safety design
- **Server:** POST `/api/signal` has the `/api/ask` guards (Host, exact Origin, Sec-Fetch-Site, `X-BVS-Token`,
  JSON, 64 KB) plus 20 signals and 120 attempts per minute. Strict schema: type allowlist, exact payload keys,
  module allowlist, at most 200 items, paths at most 1024 chars, no control/bidi characters. delete-request needs
  `typedConfirmation === "I confirm"`. The code (8 characters, `secrets`) is returned once as `XXXX-XXXX`; only
  `codeSalt` + `codeHash` = PBKDF2-HMAC-SHA256(code, salt, 600,000 iterations) are stored. It is never logged
  or listed.
- **Validate:** live checks for exists, size (folders summed), reparse point, cloud-only, running image, git work
  (status, unpushed, stash), nested items and the hard-refusal list. Recycle Bin room per drive (BitBucket
  MaxCapacity/NukeOnDelete minus `$Recycle.Bin\<SID>`, 90% margin); the rest goes to holding on the same drive.
  Programs are matched to one registered UninstallString. Table = `{tableHash, table}`, valid for 60 minutes.
- **Execute:** checks the browser confirmation, the code (constant time), the table hash and expiry, and re-checks
  every item live (same kind, size, uninstaller, Recycle Bin room). One run per request. Logs to `logs\deletions.jsonl`.
- `signal-status.ps1` cannot set `running`/`done` on a delete. `-StateRoot` only accepts `data\` or
  `tests\fixtures\delete-sandbox\`, and in the sandbox every item must be inside it (no uninstall).
- **Limit (honest):** this is a process guard. An agent that ignores the rules and has shell access could delete
  files directly, so nothing here can stop that. The code has about 40 bits; PBKDF2 makes guessing it offline
  slow, not impossible.
- **AI privacy (`/api/ask` needs `X-BVS-AI-Consent: yes`):** user name to `<user>`; names under personal folders become
  `[personal file .ext]`/`[personal folder]` unless the user typed them; sha256 dropped, command lines cut to the
  exe name, URL queries removed.

## API shapes
`POST /api/signal {type, payload, typedConfirmation?, scanId?}` returns `{id, state:'queued', code?}`.
`GET /api/signals` returns `{items:[{id,type,createdAt,state,message,updatedAt,confirmedInBrowser,summary}], count}`.
`GET /api/session` returns `{connected, beatAt, pid, startedAt}`. `GET /api/agents/live` returns
`{items:[{name,kind,pid,started,exe,command,commandAvailable}], count, source, cachedAt}`. All GETs need `X-BVS-Token`.

## Run / tests
`python -I -B tests/test_server.py` (own server, port 0, temporary state root).
`pwsh -NoProfile -ExecutionPolicy Bypass -File tests\windows\delete.selftest.ps1` (own server and sandbox).
It sends its own small fixture files (`bvs-selftest-*`, a few KB) to the Recycle Bin, where they remain.
