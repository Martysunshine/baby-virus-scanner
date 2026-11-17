# Privacy: what baby-virus-scanner reads, keeps and shares

**Principle: scan the technical depths, not people's private lives.** The tool looks at settings,
programs, file *metadata* and security logs. It does not look at what you write, watch or browse.
This page also documents how the tool is designed to line up with the GDPR (EU 2016/679). It is
not legal advice.

## 1. What is never read
- **Browsers:** history, cookies, saved passwords, autofill, Local Storage/IndexedDB, extension data
  (`config/never-read.json` is enforced by the collector linter and the library).
- **Contents of your documents, photos, videos, music or e-mails.** File names and sizes are used for
  the storage map. Privacy mode hides them on screen and from the AI.
- **Credential stores and secret material:**
  - `~/.claude/.credentials.json`, `~/.codex/auth.json`, `.git-credentials`, gh `hosts.yml`;
  - Windows Credential/Vault/DPAPI folders;
  - wallet folders, messenger session data;
  - private key bodies (only an SSH key's "is it encrypted?" header field is read).
- **Wi-Fi passwords:** `key=clear` is blocked.

## 2. Content that IS read, for security only, and always masked
| Module | Reads | Why | What is kept |
|---|---|---|---|
| S02 | script files in high-risk folders (Downloads, Temp, …) | to spot malicious scripts | file metadata + reasons; no file text |
| S04 | command histories (PowerShell, bash, python) | to spot "paste this command" scams and attack commands | only suspicious lines, secrets masked; counts |
| S09 | Claude Code settings, skills, instruction files, chat transcripts | to spot hijacked AI tools and data theft patterns | counts + short masked snippets |
| S10 | code of installed editor extensions | to spot hidden malicious code | flags only |
| S12 | dotfiles, `.env` files, histories, transcripts | to find secrets lying around in plain text | location, type, count, masked sample (`npm_…a1b2`), never the value |
| G2 | hashes of your own files ≥ 1 MB in personal folders | to find duplicates | hashes stay on this PC |
| H1, admin | program launch history (UserAssist, BAM, Prefetch), Windows Security log | to find unused programs and suspicious logins | program names/times, logon summaries |

Every JSON file is passed through secret masking before it is written. Masking fails closed: if the
masking rules are missing, nothing is written.

## 3. Where data lives, and for how long
- **Location:** only on this PC, in `baby-virus-scanner\data\<scanId>\`. Nothing is uploaded by default.
- **No telemetry and no accounts.**
- **The dashboard** is served only on `127.0.0.1`. No other computer can open it.
- **Retention:** you decide. Old scans can be removed through the Basket, using the double
  confirmation (first in the dashboard, then in the agent chat). Recommendation: keep the latest
  2–3 scans.
- **INFOSEC chats:** every conversation (copilot, INFOSEC page, scanner questions) is saved on this
  PC as `data\infosec\chats\<id>.json` so it can be reopened from the INFOSEC page. Token-like
  strings are masked before writing. The server has no delete route; to remove saved chats, delete
  the files yourself or use the Basket (same rule as every other deletion). If the server cannot store a chat, the
  browser keeps it in its local storage instead.

## 4. What leaves the PC, and only when
| When | Sent to | What |
|---|---|---|
| Threat-intel checks during a scan | OSV, GitHub/npm registries, browser and editor marketplaces, IEEE, DNS-over-HTTPS | package `name@version`, extension IDs, your GitHub username / npm package name, test domain names. Never file contents, paths or hashes. |
| You let your AI agent read the findings (it asks first) | the provider of the model your agent runs on; nobody, if the model runs on your own PC | whatever the agent reads from `data\<scanId>\`: program names, paths, settings and findings of this PC, with secrets already masked. Without your yes, the agent works from the verdict and the counts only. |
| You ask INFOSEC or use the scanner (opt-in consent dialog) | Claude (Anthropic) through your own Claude Code login | your question, the text you selected, the related findings. Your Windows username becomes `<user>`; personal file and folder names become `[personal file .ext]`; hashes and raw command lines are removed. |
| GitHub deep check (only after you sign in) | GitHub API | read-only requests under your account |
| You ask for an optional tool (`bvs.ps1 get-tools`) | Microsoft download servers, GitHub release assets | an ordinary download request. Nothing about this PC is sent. |

## 5. Your control (GDPR rights, applied to a local tool)
- **Access/portability:** everything is plain JSON in `data\` (scan results and INFOSEC chats).
- **Erasure:** delete scan data through the Basket, with the double confirmation.
- **Objection/withdrawal:** switch AI off in Privacy & AI, or start the server with `--no-ai`.
- **Data minimisation:** privacy mode is on by default; collectors keep summaries, not dumps.
- **Security of processing:** read-only scanning, an AST linter on every collector, loopback-only
  server with Host/Origin/token checks, and append-only logs that contain no prompt text.

## 6. Legal notes
- **Personal use** of the tool on your own PC falls under GDPR's household exemption (Art. 2(2)(c)).
- **Using it in an organisation:**
  - The organisation is the controller.
  - The likely lawful basis is legitimate interest in network and information security (Art. 6(1)(f), Recital 49).
  - Tell users, do a DPIA if it monitors staff devices, and keep retention short.
- **Using INFOSEC transfers data to Anthropic (USA)** under Anthropic's terms for your account.
