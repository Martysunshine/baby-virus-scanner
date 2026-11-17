# D: visual design (3D shape system, motion, asset slots)

Code comments mark the dashboard's build passes: UI-A shell and views, UI-B storage map, UI-C
INFOSEC and scanner (see `docs/ui-contract.md`), UI-D this visual design, UI-E the frame-timing
probe (`tests/ui/perf-probe.mjs`), UI-F the Overview orb and smoothness pass below.

The look changed; markup hooks (`data-bvs-*`), routes, wording, data flow and colours did not. CSS lives in the
"UI-D" blocks at the end of `style.css`, `storage.css` and `agents.css`; JS additions are marked `UI-D`.

## Shape system (CSS `corner-shape`, so borders, shadows and focus rings follow the shape)
- **Chamfer** (panels, cards, tiles): `border-radius: var(--bv) var(--bv-r); corner-shape: bevel round`.
- **Hexagon** (severity tiles, icon medallions, legend chips, number badges): `border-radius: <point> / 50%; corner-shape: bevel`.
- **Pill rail** (sub-nav, colour-by, Map/Cards/Table, chips): `border-radius: 999px` with a lit active pill.
- **Ring / sphere**: hero core, disk gauge, win medallions, agent nodes (radial gradients + specular).
- Without `corner-shape` (old browsers) the same boxes are rounded: nothing is clipped, nothing is lost.
- **Depth** = rim lit from above (`--rim`, border-box) + panel fill (`--panel`, padding-box) + `--e1`/`--e2` shadows
  (+ `--well` for recessed tubes). Every token has light and dark values (3 theme blocks, as in the rest of the CSS).

## Motion rules
- Transform/opacity only, 150-600 ms (loops are slow and decorative). Paint-only motion (stroke-dash streams on
  the agent map, the ring's leader spark) runs only while the user points at something, never at rest.
- **Idle loops must run on the compositor** (UI-F, measured; see below). In Chromium that means: transform or
  opacity, on an HTML-level box (an `<svg>` element counts; SVG *children* do not), with literal keyframe values.
  These all fall back to the main thread on every frame and made the Overview drop to ~30 fps at rest:
  animating SVG children (`<g>`, `<circle>`, `<path>`: transform, opacity, stroke-dashoffset), `box-shadow`,
  `background-position`, `left`/`width`, registered custom properties, and CSS `@keyframes` that use `var()`.
  When a loop needs per-element values, build it with `element.animate()` and literal keyframes (`fxGroup()` in
  `app.js` also pauses it off screen and skips it under reduced motion).
- No `backdrop-filter` on sticky or large areas (top bar, agent legend, drawer backdrop): it re-blurs per scroll frame.
- `prefers-reduced-motion`: the global rule in `style.css` stops every animation and transition; the JS layer
  (end of `app.js`) skips count-up, stagger and tilt.
- Entrance stagger (`.fx-rise`, fill-mode backwards, max 30 elements, never treemap tiles); count-up always
  ends on the exact original text; pointer tilt max 6 deg (mouse only); `.fx-paused` stops loops off screen.
- Treemap: static bevel shading per tile, ONE zoom animation on `.svm-box` per drill level (`fxZoom`).

## Asset slots (`dashboard/assets/`, served by the strict `/dashboard/assets/<name>.(svg|png|webp|jpg)` route)
| Slot (base name) | Where | Fallback |
|---|---|---|
| `logo-mark` | sidebar brand (`<img>` src swap) | `logo-mark.svg` |
| `hero-shield` | floating art at the hero's top right, only when orb and text sit side by side | none needed (core rings stay) |
| `storage-core` | storage sub-sidebar header | hexagon disk icon |
| `agent-core` | behind the main-agent core on the agent map (HTML layer `.ag-orch-layer`) | code-built reactor rings (HTML) |
| `bg-nebula` | page backdrop, dark themes only, under a contrast overlay | glow + grid |
- The loader tries `<name>.png`, then `<name>.webp`, once per page load; a 404 keeps the fallback.
- Views that re-render call `window.BVSFx.slots(scope)`. Only names from the fixed list are ever requested.
- Logo files: `logo.svg` (full, dark UI), `logo-light.svg` (full, light UI), `logo-mark.svg`; `favicon.svg` = mark.
- Screenshots: headless Edge needs `--run-all-compositor-stages-before-draw` or CSS animations stall mid-way.

## UI-F: Overview orb, circuit current, smoothness pass
Goal: the Overview ring's coloured segments stand out in 3D, each with a label that leads somewhere; no recurring
scan sweep; a slow, calm current running along circuit lines in place of the hero grid; smooth scrolling,
responses and fallbacks everywhere.
- **Orb** (`app.js` heroOrb, 620 x 310 design box): raised segments (gradient face, darker side, gloss edge), each
  its own SVG layer; slow outward wave via `element.animate()`, hover pop via `translate`; one spec chip per area
  (a real link, keyboard path) joined by a circuit leader line; the segment itself is a mouse shortcut; the verdict
  button stays in the centre. Container queries: side by side from a 1120 px hero, stacked below, chips become a
  2-column grid under 610 px.
- **Current** (`app.js` heroCurrentFx): static trace lines + pads near the hero edges (one SVG, painted once);
  three sparks (head + 2 trailing dots) and 16 pad flashes are HTML spans animated by transform/opacity, about
  70 px/s, rebuilt on resize. The old `.hero::before` grid and `.hero::after` scan sweep are gone, as is the
  top-bar scan light.
- **Agent map**: no idle sphere float and no idle edge flow (both only on hover/selection); the reactor rings,
  bloom and `agent-core` art moved to an HTML layer (`.ag-orch-layer`) under the map inside `.ag-map-box`
  (same aspect ratio as the viewBox), so the large map SVG is painted once.
- **Shell**: connected-dot pulse, agent live dot and INFOSEC send pulse are scaling rings (no animated box-shadow);
  thinking bars and the INFOSEC header band move by transform; art images fade in on load.
- **Measuring** (`tests/ui/perf-probe.mjs`: headless Edge on the real GPU, its own server, idle 3 s after a
  settle): before this pass the Overview spent ~650-960 main-thread ms per second at rest (~30 fps) and the Agent
  map ~900. Compare before and after any motion change with `--out` and `--compare`. Notes: a rAF loop in the probe forces main-thread frames and makes composited animations look busy;
  measure without one. Animations on `display:none` elements are never composited, so ablate by cancelling
  animations, not by hiding elements. Measure after the entrance animations have finished.
