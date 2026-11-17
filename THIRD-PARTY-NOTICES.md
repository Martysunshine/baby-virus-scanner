# Third-party notices

baby-virus-scanner has no third-party runtime dependencies: PowerShell 7 and the Python standard
library only, and no external scripts or fonts in the dashboard. This file lists the outside
data and programs it relies on.

## Programs downloaded at the user's request

Neither is part of this repository. `tools\windows\get-tools.ps1` downloads them only when the
user asks, and keeps a download only after verifying its signature.

| Program | Publisher | Used for | License |
|---|---|---|---|
| Microsoft Safety Scanner (`msert.exe`) | Microsoft Corporation | A report-only (`/N`) malware scan during the optional admin step | Microsoft's own terms |
| GitHub CLI (`gh.exe`) | GitHub, Inc. | Read-only API calls for the optional signed-in GitHub checks | MIT License |

## Threat-intelligence data fetched at scan time

Collectors query these public sources through the host allowlist in `config\intel-hosts.json`.
The data is cached under `intel\` on the user's PC and is never committed. It stays under each
source's own terms.

| Source | Used by | For |
|---|---|---|
| OSV (osv.dev), including OpenSSF malicious-packages | S11 | malicious and vulnerable npm / PyPI packages |
| GitHub Advisory Database, GitHub public API | S11, S13 | advisories; account and repository checks |
| npm registry, PyPI | S11, S13 | package metadata |
| Visual Studio Marketplace, VS Code extension control list, Microsoft `vsmarketplace` removed-packages list, Open VSX, Cursor extension control list | S10 | editor extension checks |
| Chrome Web Store, Microsoft Edge Add-ons | S06 | whether an extension is still listed |
| `toborrm9/malicious_extension_sentry`, `palant/malicious-extensions-list` | S06 | known malicious browser extension IDs |
| LOLDrivers (loldrivers.io) | S01 | known vulnerable and malicious drivers |
| Microsoft AuthRoot certificate trust list | S03 | trusted root certificates |
| IEEE OUI registry | S08 | network adapter vendors |
| Tor exit list, abuse.ch Feodo Tracker | S07 | known bad network endpoints |
| Public DNS-over-HTTPS resolvers | S07 | DNS hijack test |

## Reference data inside this repository

The sidecar JSON files next to the collectors (`collectors\security\windows\*.json`) hold
indicators and reference lists written for this project: tool names, registry locations, file
patterns, package names and version ranges. They are facts gathered from public advisories and
vendor documentation; where an entry comes from a specific advisory, its `source` field names it
(for example OSV and GHSA identifiers, CVE numbers, and vendor write-ups). Technique numbers
refer to MITRE ATT&CK. The remote-access tool catalogue was informed by the LOLRMM project.

Product and company names are used only to identify the software being detected. They belong to
their owners.

## Artwork

The logo, the dashboard illustrations (`dashboard\assets\`) and the README banner
(`docs\assets\`) were generated for this project with an AI image tool. The screenshots in
`docs\assets\screenshots\` show the dashboard on the synthetic demo scan.
