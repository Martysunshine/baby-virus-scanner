# J: dashboard, local server and aggregator

## (a) Brief (condensed)
Build a cross-platform (Python 3 stdlib + vanilla HTML/CSS/JS, no external scripts or fonts), read-only
dashboard for baby-virus-scanner. `core/aggregate.py` merges all envelopes into `summary.json`: findings,
verification records (verify files or on the finding), reason scores, per-module/severity counts, coverage
(every check + `logCoverage`), the schema.md verdict rubric, `verdict-override.json` and the honest limits.
`core/build_datajs.py` writes `js/*.js` as `window.BVS.register(name, json)` (escape `<`, U+2028/2029),
a manifest and a pruned treemap (>=0.1% of used bytes, top 200 children, rest collapsed) split per
top-level folder. `server/serve.py`: 127.0.0.1:8777 (fallback 8778-8800), BaseHTTPRequestHandler, static routes
GET/HEAD only, Host must be 127.0.0.1/localhost:<port> (else 403), fixed whitelisted routes, realpath
containment, no symlinks, strict CSP and hardening headers, no CORS, logs/server.log. UI tabs: Verdict,
Security, Storage map, Big/Old files, Duplicates, Junk & caches, Programs, Startup & speed, Registry &
health, Basket (DELETE REQUEST text, never deletes). textContent only, no inline JS/CSS, light/dark.
Fixture with every envelope type and a hostile name; `tests/test_server.py`.

## (b) Architecture and data flow
```
data/<scan>/{security,admin,verify,storage}/*.json + inventory/{dirs.tsv,files.tsv,inventory-meta.json}
  -> core/aggregate.py   -> summary.json  (merge, verification, score, coverage, verdict, limits)
  -> core/build_datajs.py -> js/{manifest,summary,findings,coverage,storage,duplicates,programs,
                             startup,registry,health,treemap,treemap-NNNN}.js  + data/latest.js
  -> server/serve.py (or file://) -> dashboard/index.html + loader/util/vtable/treemap/basket/app.js
```
- **Verdict**: COMPROMISED = confirmed critical compromise; SUSPICIOUS = unrefuted, unexplained high/critical
  compromise/suspicious finding; high hardening/hygiene or medium -> HARDENING_NEEDED; else OK. Refuted,
  info and storage-hygiene findings never count. Conflicting verifiers: confirmed > refuted > inconclusive.
  "Explained" = known-good `expected` match (not cancelled, not confirmWithUser).
- **Storage tabs**: storage inventory keys are routed to tabs by name tokens (big/old/junk/dup/...).
  Until G1 runs, big/old/junk fall back to unclassified items from `files.tsv` (safety review).
- **Treemap**: dirs.tsv in compact arrays; folders >=0.1% of used bytes are expanded with their top 200
  children, the rest becomes "(n smaller items)", loose files "(files in this folder)". One chunk per
  top-level folder (deeper chunks above 20k nodes), loaded by script tag on drill-down. Colours are chosen
  for accessibility: cleanability and age are one-hue ordinal ramps, category uses three categorical
  slots (in a treemap every colour touches every other). Labels only on rects >= 60x18 px, <=400 divs/level.
- **Safety**: every value enters the DOM as text; bidi/control characters are shown as `⟦U+202E⟧`;
  links only to an allowlist of account-security pages. The basket refuses use_tool/do_not_touch items,
  persists in localStorage (try/catch) and outputs exactly the DELETE REQUEST format.
- **Server**: no percent-decoding, regex routes, Windows device names refused, SO_EXCLUSIVEADDRUSE,
  CSP/nosniff/no-referrer/no-store/COOP/CORP/Permissions-Policy/X-Frame-Options on every response.
  The token-protected `/api/*` routes added later are described in `K-signals.md` and `I-infosec-copilot.md`.

## (c) Run
```
python -I -B core/aggregate.py   --scan data/<scanId>     # summary.json only
python -I -B core/build_datajs.py --scan data/<scanId>    # also re-aggregates
start-dashboard.cmd   [-Scan <id>] [-Rebuild] [-NoBrowser]       # build if needed, serve, open browser
python -I -B server/serve.py [--scan <id|dir>] [--port 8777] [--open]
python -I -B tests/test_server.py                                # own server on a free port, synthetic data
python -I -B tests/fixtures/make_demo_scan.py                    # regenerate the synthetic fixture
```
A disk with about half a million folders becomes roughly 15,000 treemap nodes (about 1.4 MB of data
files); aggregate + build take a few seconds. `dashboard/index.html` also works from file:// via `data/latest.js`.
