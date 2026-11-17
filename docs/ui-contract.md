# Dashboard v2: UI contract (shared by agents UI-A, UI-B, UI-C)

> Design contract used while the dashboard was built by three parallel agents. It is kept as contributor
> documentation: it explains who owns which file, the data sets, the routes and the shared wording.

**Goal:** a dashboard in the style of a consumer antivirus app, but *much easier to understand*. Every number, tile and label is
**clickable** and leads somewhere: a filtered list, a side panel, or the storage map. Plain English
always comes first; technical detail goes in the side panel.

**Hard rules**
- Vanilla JS/CSS only. No CDN, no external fonts.
- The CSP forbids inline `<script>`/`<style>`/`on*=` attributes. Setting `element.style.x` from JS is fine.
- Render data ONLY with `textContent` / `createElement` (`util.js` `el()`), never `innerHTML`.
- The dashboard must still work over `file://`. AI features then fall back to offline explanations.
- No delete buttons anywhere. Deletion only goes through the Basket and the double confirmation described in
  `docs/ui-contract-v3.md` (typed once in the dashboard, once in the agent chat).

## Files and owners
| Owner | Files |
|---|---|
| **UI-A** (shell + views) | `dashboard/index.html`, `dashboard/style.css`, `dashboard/app.js` (rewrite; reuse `util.js`, `vtable.js`, `basket.js`, `loader.js` unchanged) |
| **UI-B** (storage map) | `dashboard/storage-view.js`, `dashboard/storage.css` (may reuse/extend `treemap.js` via its own copy `storage-treemap.js` if needed) |
| **UI-C** (intelligence) | `dashboard/infosec.js`, `dashboard/infosec.css`, `dashboard/scanner.js`, `dashboard/scanner.css`, `dashboard/glossary.js`, `src/core/ai_bridge.py`, AI routes in `src/server/serve.py`, `tests/test_server.py` (extend) |
| **main agent** | `data/<scan>/guide.json` (curated plain-English content), `src/core/build_datajs.py` (exports `guide` dataset) |

`index.html` (UI-A) MUST include, in this order:
1. `loader.js`, `util.js`, `vtable.js`, `treemap.js`, `basket.js`;
2. `app.js`;
3. `storage-view.js`, `glossary.js`, `infosec.js`, `scanner.js`;
4. CSS: `style.css`, `storage.css`, `infosec.css`, `scanner.css`.

Data scripts are loaded by the existing loader mechanism.

## Datasets (`window.BVS.get(name)`, already built by `src/core/build_datajs.py`)
`summary`, `findings`, `coverage`, `storage`, `duplicates`, `programs`, `startup`, `registry`, `health`,
`treemap` (+ lazy chunks), `manifest`, and NEW: `guide`. Shapes are in `docs/schema.md`. For examples, run
`pwsh -File .\bvs.ps1 demo` and inspect `data/demo-scan/js/*.js` (synthetic data).

**Key fields:**
- **`summary`:** verdict, verdictMeaning, verdictReasons[], verdictDrivers[], counts{bySeverity, bySeverityActive, byClass, byVerification, byModule}, confidence{level,…}, suspiciousFiles[], hardening[], questions[], honestLimits[], coverage{gaps, logWindows, modules…}, score.
- **`findings.items[]`:** id, module, check, title, severity, class, confidence, reasons[], evidence[], fp_notes, recommendation, verification{result,…}, score.
- **storage-like datasets `.items[]`:** id, label, path, kind, bytes, files, newest, oldest, category, purpose, owner, safety (safe | safe_after_check | review | use_tool | do_not_touch), method, how, reversible, flags[], gitRisk, group, groupSize, module, list, tabs[].
- **`treemap`:** meta{…, cats[], catFamily[], families[], ageBuckets[], safetyLevels[]}, root{n,b,f,d,t,a,k3,cl,x[],k,pv}. See `treemap.js` for how nodes and lazy chunks work.
- **`guide`** (main agent, may be absent, so render a graceful fallback):
  ```json
  { "headline": "...", "subhead": "...", "status": "safe|warning|danger",
    "health": [ {"area":"Security|Storage|Stability|Privacy|Updates", "grade":"good|ok|attention|bad", "text":"...", "link":"#/..."} ],
    "verdictPlain": { "summary":"...", "whatItMeans":"...", "whyNotCompromised":["..."], "confidenceText":"...", "notChecked":["..."] },
    "topFixes": [ {"id":"fix-1", "title":"...", "plain":"...", "why":"...", "effort":"5 min", "priority":1, "steps":["..."], "related":["S12-0001"], "link":"#/finding/S12-0001"} ],
    "questions": [ {"id":"q-1", "question":"...", "plain":"...", "found":["..."], "whyItMatters":"...", "ifYes":"...", "ifNo":"...", "related":["S07-0019"], "link":"#/..."} ],
    "stability": { "title":"...", "plain":"...", "facts":["..."], "steps":["..."] },
    "storageHighlights": [ {"title":"...", "bytes":0, "plain":"...", "link":"#/storage/..."} ],
    "glossaryExtra": [ {"term":"...", "plain":"..."} ] }
  ```

## Routes (hash router in app.js)
| Route | Shows |
|---|---|
| `#/overview` (default) | Merged verdict + "at a glance" |
| `#/security?sev=high&class=hardening&verify=refuted&module=S07&q=text` | Findings list (all filters optional) |
| `#/finding/<id>` | Security list with that finding's side panel open |
| `#/questions` | Questions for you |
| `#/suspicious` | Suspicious files |
| `#/why` | Why this verdict (page + panel) |
| `#/fixes` | Top fixes walkthroughs |
| `#/storage`, `#/storage/<section>` | Storage map (UI-B). Sections: `map`, `junk`, `big`, `old`, `duplicates`, `projects`. `#/storage/map?path=<urlencoded>` drills to a folder. |
| `#/performance` | Programs / startup / resource hogs |
| `#/health` | Stability (BSODs), disk, registry refs, broken shortcuts |
| `#/coverage` | What was / wasn't checked |
| `#/basket` | Basket |
| `#/infosec` | INFOSEC assistant (UI-C) |

## `window.BVSApp` API (UI-A creates it synchronously at the top of app.js; B/C attach to it)
```js
BVSApp.registerView(id, { title, icon /* svg path d */, group: 'main'|'tools', accent /* optional css color */, mount(rootEl, params) , unmount() })
BVSApp.navigate(hashRoute)                 // e.g. '#/security?sev=high'
BVSApp.openPanel(spec)                     // right side drawer. spec = { title, subtitle?, kind: 'finding'|'storageItem'|'file'|'question'|'fix'|'text'|'custom', id?, item?, render?(bodyEl), actions?: [{label, onClick, primary?}] }
BVSApp.closePanel()
BVSApp.findingById(id) ; BVSApp.itemById(id)   // item from any storage-like dataset
BVSApp.basket                               // the Basket instance (add/has/count) from basket.js
BVSApp.ask(question, context) -> Promise<{ text, source: 'ai'|'offline', error? }>   // implemented by UI-C (infosec.js sets BVSApp.askImpl); UI-A calls BVSApp.ask
BVSApp.openInfosec({ prefill, context })    // implemented by UI-C; UI-A shows "Ask INFOSEC" buttons in panels that call it
BVSApp.friendly = { severity(sev) -> {label, plain, color}, safety(s) -> {...}, verdict(v) -> {...} }   // UI-A, shared wording
```
- **Panel content:** UI-A renders panels for kinds finding/question/fix/file/text. UI-B renders its own storage panels through `render(bodyEl)`.
- **Every panel** gets these buttons automatically: "Ask INFOSEC about this" (calls openInfosec with the entity context) and "Close". Storage items that may be deleted also get "Add to basket" (only if `basket.js` `canAdd` allows it).

## Scanner hooks (UI-A and UI-B MUST add these attributes)
Any element representing an entity gets `data-bvs-type="finding|storageItem|question|fix|file|tile|section"`
and `data-bvs-id="<id>"`, plus `data-bvs-label="<short human label>"` where useful. Section containers
get `data-bvs-section="<name>"`. `scanner.js` reads these plus the visible text inside the selected
rectangle, so the explanation knows exactly what the user pointed at.

## Friendly wording (UI-A defines it in `BVSApp.friendly`; everyone uses the same words)
| Severity | Label | Plain meaning |
|---|---|---|
| critical | Act now | likely an active threat |
| high | Important | fix soon |
| medium | Worth fixing | a weakness |
| low | Minor | small tidy-up |
| info | FYI | for your information |

| Class | Label |
|---|---|
| compromise | Sign of attack |
| suspicious | Needs a look |
| hardening | Security setting to tighten |
| hygiene | Clean-up |

| Verification | Label |
|---|---|
| refuted | Checked: false alarm |
| confirmed | Checked: real |
| inconclusive | Checked: unclear |
| unverified | Not double-checked |

| Safety | Label |
|---|---|
| safe | Safe to remove |
| safe_after_check | Safe after a quick check |
| review | Look before deleting |
| use_tool | Clean with the app's own tool |
| do_not_touch | System: leave alone |

## Visual language
- Like a consumer antivirus app: left icon sidebar, big status hero with a shield/ring, cards with a clear call to action.
- Light and dark themes via `prefers-color-scheme` plus a toggle.
- Colourful but accessible: each section has its own accent; status uses green/amber/red with icons + text, never colour alone.
- **INFOSEC accent is yellow** (`#F5C518`-ish, dark text on it).
- Big readable type (16px base). Generous spacing. Smooth transitions. `prefers-reduced-motion` respected.
