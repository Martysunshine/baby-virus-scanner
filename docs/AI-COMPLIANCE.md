# AI use and the EU AI Act (Regulation (EU) 2024/1689)

How baby-virus-scanner uses AI, and how the design lines up with the AI Act's obligations. This is
a design note, not a legal certification.

## Where AI is used
| Part | AI? | Role |
|---|---|---|
| Collectors S01–S13, G0–H2 | No | Deterministic PowerShell rules. Same input, same output. |
| Verdict (`core/aggregate.py`) | No | A fixed rubric: COMPROMISED only with a verified critical finding. |
| Building the scanner | Yes, at development time (AI coding agents) | Agents wrote collectors and documentation against fixed rules. A human directed the work. |
| Operating a scan (`AGENTS.md`) | Yes, if the user chooses an AI agent as operator | The agent runs fixed commands, explains the result, and may add verification records and user-confirmed known-good items. It cannot set the verdict, and it must ask before it reads findings. |
| INFOSEC assistant + scanner copilot | Yes (Claude via the user's Claude Code login), only after opt-in | Explains findings and suggests steps. It **cannot act**: no tools, no commands, no deletion. |

## Classification
- **Not a prohibited practice (Art. 5) and not high-risk (Annex III):** no biometrics, employment
  decisions, credit scoring or critical-infrastructure control. It is a personal security and
  maintenance assistant.
- **INFOSEC interacts with people,** so the **transparency obligation of Art. 50(1)** applies:
  - the dashboard says clearly that INFOSEC is an AI system (Claude by Anthropic);
  - every answer carries the badge "AI-generated (Claude) — double-check important steps".
- **The general-purpose AI model obligations** (Art. 53–55) fall on the model provider (Anthropic).
  This project is a *deployer/integrator* of that model.

## Safeguards built in
1. **Human oversight (cf. Art. 14 spirit):**
   - AI output is advice only.
   - Any change to the system needs the user's explicit chat confirmation.
   - Deletion needs **two confirmations typed by the user**: in the dashboard, then `I confirm <code>` in the agent chat. The code is shown only to the user, and only its hash is stored, so the AI cannot confirm on the user's behalf.
2. **Informed consent before first use:** a dialog explains what is sent and to whom. The user can
   choose "Only offline answers" and withdraw at any time.
3. **Data minimisation for AI calls:**
   - the username is pseudonymised;
   - personal file names are hidden;
   - hashes and raw command lines are dropped;
   - token-like strings are masked;
   - the request is capped at about 30k characters.
4. **Locked-down model execution:** `claude -p --tools "" --disable-slash-commands --strict-mcp-config
   --no-session-persistence`, run from an empty sandbox folder, with input on stdin only. The
   user's own user-level Claude Code settings still load (`--setting-sources user`).
5. **Robustness:**
   - scan data is treated as untrusted input; the system prompt tells the model to ignore instructions found inside it;
   - verifier records separate AI-suggested from verified conclusions.
6. **Logging:** the server keeps metadata only (time, size, duration, status). It never stores prompt
   or answer text.
7. **AI literacy (Art. 4):** a plain-English guide, a glossary, "explain like I'm in high school"
   buttons, and a Privacy & AI page.

## Limits
- AI explanations can be wrong. The verdict and findings come from deterministic checks, not from the model.
- Offline mode (`file://` or `--no-ai`) gives glossary/guide-based answers without any AI.
