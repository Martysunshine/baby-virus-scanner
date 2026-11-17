# I: INFOSEC copilot, streamed answers, saved chats

## Goal
- Answers arrive quickly and visibly: streamed, with a progress line.
- "Scan and explain" hands its question over to INFOSEC.
- INFOSEC is also a copilot window that stays beside any page.
- Chats are saved on this PC only, and the INFOSEC page lists saved chats and past questions.

## What was wrong (measured)
- Answers took 35-60 s with no sign of progress: `claude -p` started fresh for every question (~10 s
  start-up), extended thinking added ~8 s before the first word, and the bridge returned only the
  finished answer (`--output-format json`).
- The scanner answered inside its own floating card, separate from the INFOSEC chat; nothing was saved
  (`sessionStorage`, lost with the tab).

## What changed
- **src/core/ai_bridge.py**
  - `ask_stream()` runs the same locked-down CLI in streaming mode (`--input-format stream-json
    --output-format stream-json --include-partial-messages`).
  - `WarmClaude` keeps one process started ahead of time. It waits idle (no API call) until a question
    arrives, answers that one question and exits. The next spare starts as soon as a question begins.
    A spare older than 30 minutes is replaced.
  - Extended thinking is off (`--settings {"alwaysThinkingEnabled":false}`, `MAX_THINKING_TOKENS=0`).
  - Secrets are masked on the whole answer so far. While streaming, text is released only up to the last
    space or line break, so a token is never sent half-written.
  - Measured: first words in about 1 s and a short answer in about 2 s. A question asked while the next
    spare is still booting waits up to ~10 s.
- **src/server/serve.py**
  - `POST /api/ask` with `Accept: application/x-ndjson` streams one JSON event per line: `status`
    (asking / thinking / writing), `delta`, `reset`, then `done` or `error`. Busy, rate limit and AI off
    still return normal JSON errors before the stream starts.
  - The bridge is pre-warmed at start and closed on shutdown.
- **src/core/chat_store.py** with `POST /api/chats`, `GET /api/chats` and `GET /api/chats/<id>`
  - Chats are stored as `<state-root>/infosec/chats/<id>.json` with a strict schema and masked secrets.
  - Limits: 5 MB body, 120 saves per minute, no delete route.
- **dashboard/infosec.js**
  - Streamed answers appear in place with a live stage line ("Reading your scan… 2 s") and a Stop button.
  - A failed live answer offers "Try the live answer again".
  - Chats save automatically: on the server, else in localStorage. The old sessionStorage chat is
    imported once.
  - **Copilot:** a panel docked beside the page from 1100 px wide, which makes room instead of covering
    the page.
    - It stays open across tabs, steps aside on `#/infosec` and comes back afterwards.
    - It is resizable (340-720 px) and remembers whether it was open.
    - A yellow INFOSEC launcher sits at the bottom right of every page.
    - The header has saved chats, new chat, full page and close.
  - **INFOSEC page:** "Saved chats" (search, click to continue) and "Questions you asked" (newest first
    across all chats, click to open, "Ask again").
- **dashboard/scanner.js**
  - The scan card keeps the quick questions and the typed question.
  - Asking hands over to INFOSEC (`openInfosec({where: 'auto'})`): the copilot when it is open, else the
    INFOSEC page.
  - The question is tagged "from the scanner", carries the scanned area as context and is saved with the
    chats.
- **app.js**: `App.ask` forwards `onEvent` and `signal`. The item details drawer sits left of the docked
  copilot.

## Follow-up: a small floating window
- The copilot now opens as a **floating window** at the bottom right: width 28% of the screen (360-520 px)
  and height 60% (420-700 px). That is about a quarter of a laptop screen, and the page underneath is not
  squeezed.
- **Resize** from all 4 sides and 4 corners (minimum 320x300 px, always kept inside the browser window).
  **Move** it by the title bar; a double-click on the title bar restores the default size.
- The **dock** button in the header pins it beside the page as before (default width 380 px, left edge
  resizable); the float button returns to the window.
- Mode, size and position are remembered (localStorage `bvs.infosec.mode`, `bvs.infosec.geom`).

## Checks
- `tests/test_server.py` covers:
  - Streaming: streaming events and the locked-down command, a secret never streamed unmasked, errors after
    start, a process that dies, busy before start returning JSON, warm spare reuse.
  - Chat routes: round trip, masking, bad input, guards, no DELETE.
- The browser side (copilot window, hand-over from the scanner, saved-chat lists) has no automated
  test in this repository. Check it by hand with `bvs.ps1 demo` after changing `infosec.js` or `scanner.js`.

## Operating notes
- INFOSEC uses the Claude Code CLI when it is installed and the user opted in. Without it, or with the
  server's `--no-ai` switch, every answer comes from the built-in glossary and guide.
- The server starts one idle CLI process ahead of time so the first answer is fast. It makes no API call
  until a question arrives, and it is closed when the server stops.
- The CLI runs with tools, slash commands, MCP servers and session persistence switched off, from an empty
  folder. The user's own user-level Claude Code settings still load (`--setting-sources user`).
- If you ever clean up leftover processes, stop only those whose command line contains the INFOSEC system
  prompt. The VS Code Claude extension also runs `claude.exe ... --input-format stream-json`, and that is
  the user's own Claude Code session.
