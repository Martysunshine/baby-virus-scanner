# Start here: prompt for any AI agent

Most coding agents read `AGENTS.md` from the project folder by themselves. If yours does not, or
you are not sure, open this folder in the agent and paste the prompt below.

```text
You are operating baby-virus-scanner, a read-only security and storage scanner, in this folder
on my Windows PC.

1. Read the file AGENTS.md in this folder completely before you do anything else.
2. Follow it exactly, starting at section 1. Obey its "Rules that never bend".
3. Ask me the questions in its section 2 before you start the scan.
4. Do not change, delete or install anything on this PC. Do not edit the scanner's code.
5. When the scan is done, give me the report described in its section 4 and offer to open the
   dashboard.
```

## What the agent needs

- A way to run commands on this PC (a terminal tool). An agent that can only chat cannot run
  the scan; use the manual quick start in `README.md` instead and paste the verdict lines to it.
- PowerShell 7 and Python 3.9 or newer. `bvs.ps1 doctor` checks both.
- If its commands time out after a few minutes, it uses `scan -Background` and polls `status`.
  That path is described in `AGENTS.md` section 3.

## Small or local models

The standard scan (sections 1 to 5 of `AGENTS.md`) is a handful of fixed commands, and the
verdict comes from the scanner's own rubric, so a small model can run it. The deep review in
section 7 asks the model to judge evidence and to write files that change the verdict. Skip it
unless the model is reliably careful; nothing is lost by skipping it.
