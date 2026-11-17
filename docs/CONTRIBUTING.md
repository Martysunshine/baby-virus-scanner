# Contributing

Thanks for helping. This is a security tool that people run on their own PCs, so a few rules are
strict. They are short.

## Before every commit: the privacy check

You develop collectors while looking at a real machine, usually your own. It is easy to leave a
host name, a home network, a user folder or a token in code, docs or fixtures.

```powershell
pwsh -NoProfile -File .\bvs.ps1 check-publish
```

It reads every file git would publish and fails on secrets, real user paths, private addresses,
e-mail addresses, machine identifiers and image metadata. Make it pass before you commit.

- Optional: list your own private terms (host names, project names, account names), one per
  line, in `src\config\local\publish-denylist.txt`. That folder is git-ignored.
- Optional: run the check automatically with the provided hook:
  `git config core.hooksPath src/tools/git-hooks`
- Never commit `data\`, `intel\`, `logs\`, `vendor\` or `src\config\local\`. The `.gitignore` is an
  allowlist: a new top-level file or folder is ignored until you add it there on purpose.
- Screenshots and examples come from the synthetic demo scan only: `.\bvs.ps1 demo`.

## Rules for collectors

The binding contract is [docs/agent-rules.md](agent-rules.md). In short:

- **Read-only.** A collector never changes the system. The linter enforces it and must pass:
  `pwsh -NoProfile -File .\bvs.ps1 lint`. Fix the script; never work around the linter.
- **Never open** credential stores, private keys or private browser data
  (`src\config\never-read.json`).
- **Everything written is masked** (`Complete-BvsRun`, `Write-BvsJson`).
- **Network only through `Invoke-BvsIntel`** and the host allowlist.
- **Portable.** No user names, machine paths or machine-specific "known good" items in code.
  Those belong in the user's own `src\config\local\expected.json`.
- **Calibrated findings.** Every finding has evidence, says why it might be harmless, and gives
  manual steps. `compromise` is for concrete evidence of malicious activity only.

## Adding or changing a collector

1. One module per file: `collectors\<area>\windows\<ID>-<name>.ps1`, with detection data in a
   sidecar `<ID>-*.json`. Wrap every check in `Invoke-BvsCheck`.
2. Output is a `bvs.module/1` envelope ([docs/schema.md](schema.md)).
3. Document it in `docs\playbooks\<ID>-<name>.md`: purpose, implementation, how to run. Either
   write it by hand or generate it:
   `pwsh -File src\tools\windows\gen-playbook.ps1 -Path <collector> -Force`.
   A playbook describes the method. Results of a scan never go into it.
4. Run it on a real PC and on the checks below.

## Tests

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 selftest     # library: masking, signatures, enumeration
pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 lint         # every collector
python -I -B tests\test_server.py                                    # dashboard server, on synthetic data
pwsh -NoProfile -ExecutionPolicy Bypass -File .\bvs.ps1 demo         # look at the dashboard
```

`tests\windows\delete.selftest.ps1` tests the deletion protocol in a sandbox folder; it sends its
own small fixture files to the Recycle Bin.

## No automation without the maintainer's approval

Do not add CI workflows, scheduled jobs, release automation or anything else under `.github\`.
Suggest it in an issue instead.

## Pull requests

Keep them small and say what you ran. Attach check IDs and error messages, never scan output.
By contributing you agree that your contribution is licensed under the Apache License 2.0.
