# Security policy

baby-virus-scanner is a security tool that runs on people's own PCs, so problems in it matter.

## Reporting a vulnerability

Please report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for it.

Useful to include: what you ran, what you expected, what happened, and the smallest way to
reproduce it. **Never attach your scan output** (`data\`, `intel\`, `logs\`): it describes your
PC. A check ID and an error message are enough.

## What counts

- A collector or tool that changes the system, or can be made to (the scanner must be read-only).
- A secret, token or credential that reaches a JSON file, a log, the dashboard or an AI request
  unmasked.
- A file on the never-read list being opened (`config\never-read.json`).
- A network request to a host outside `config\intel-hosts.json`, other than the two documented
  downloads in `tools\windows\get-tools.ps1`.
- The local dashboard server being reachable from another machine or another website, or its
  deletion protocol being completed without both confirmations typed by the user.
- Text from scanned files, logs or web pages being treated as instructions by the tooling.

## What does not

- A missed detection or a false positive. Those are ordinary issues and very welcome.
- The honest limits listed in the README (kernel rootkits, firmware, a compromised router).

## Supported versions

The latest release on the default branch.
