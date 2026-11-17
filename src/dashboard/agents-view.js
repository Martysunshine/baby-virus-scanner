/* baby-virus-scanner dashboard v3: "Agent map" view (agent M, docs/ui-contract-v3.md section 3).
 *
 * Shows which AI helpers (agents) worked on the scan, how heavy each job was (green Easy, yellow
 * Medium, red Hard, dark purple Extra high), how long the scripts they wrote are, and which AI tools
 * are running on this PC right now (GET /api/agents/live, polled every 10 s while visible).
 *
 * - Data: dataset "agents" (src/core/build_agents.py -> <scan>/agents.json -> src/core/build_datajs.py).
 *   null means "not measured": the view says so and never fills in a number.
 * - CSP-safe: no innerHTML, no inline style attributes in markup; SVG is built with createElementNS
 *   and every piece of data enters the DOM as text (util.js el() / textContent).
 * - Colour is never alone: every grade also shows its letter (E, M, H, X, ?), every status an icon.
 * - Read-only: the only request is the GET to the local dashboard server for the live list. */
(function () {
  'use strict';
  var U = window.BVSUI && window.BVSUI.util;
  if (!U) { return; }
  var el = U.el;
  var SVGNS = 'http://www.w3.org/2000/svg';
  var MODE_KEY = 'bvs.agents.mode';
  var POLL_MS = 10000;
  var MODES = ['map', 'cards', 'table'];

  // ------------------------------------------------------------------ wording (shared with the legend)
  var GRADE_ORDER = ['easy', 'medium', 'hard', 'extra-high'];
  var GRADES = {
    easy: { key: 'easy', cls: 'g-easy', label: 'Easy', letter: 'E', rank: 0,
      rule: 'under 150,000 tokens and under 10 minutes', est: 'script under 500 lines',
      plain: 'A light job: quick, with little reading or writing for the AI.' },
    medium: { key: 'medium', cls: 'g-medium', label: 'Medium', letter: 'M', rank: 1,
      rule: 'under 350,000 tokens', est: 'script of 500 to 1,499 lines',
      plain: 'A normal job: some research and one solid script.' },
    hard: { key: 'hard', cls: 'g-hard', label: 'Hard', letter: 'H', rank: 2,
      rule: 'under 450,000 tokens', est: 'script of 1,500 to 2,999 lines',
      plain: 'A heavy job: lots of reading, testing and fixing.' },
    'extra-high': { key: 'extra-high', cls: 'g-xhigh', label: 'Extra high', letter: 'X', rank: 3,
      rule: '450,000 tokens or more, or 45 minutes or longer', est: 'script of 3,000 lines or more',
      plain: 'The heaviest jobs: close to what one AI session can hold at once.' },
    none: { key: 'none', cls: 'g-none', label: 'Not measured', letter: '?', rank: -1,
      rule: 'no usage and no script recorded', est: '',
      plain: 'Its usage was not recorded, so it is not graded. The dashboard never guesses a number.' }
  };
  var STATUS = {
    'done': { label: 'Finished', short: 'Finished', icon: 'check', plain: 'It did its job and reported back.' },
    'resumed-done': { label: 'Resumed, then finished', short: 'Resumed', icon: 'resume', plain: 'The account usage limit stopped it; it was resumed later and finished.' },
    'stopped-limit': { label: 'Stopped by the usage limit', short: 'Usage limit', icon: 'pause', plain: 'The account usage limit stopped it. The main session finished or ran its work.' },
    'replaced': { label: 'Replaced', short: 'Replaced', icon: 'swap', plain: 'It got stuck, so the main session did this job itself.' }
  };
  var ICON = {
    check: 'M5 12.5l4.5 4.5L19 7.5',
    resume: 'M19 12a7 7 0 1 1-2.05-4.95M19 4v4h-4',
    pause: 'M9 6v12M15 6v12',
    swap: 'M5 9h13l-3.5-3.5M19 15H6l3.5 3.5',
    unknown: 'M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.6M12 17h.01',
    agents: 'M12 8.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM5 21.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM19 21.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM12 8.5v4M12 12.5l-5.5 4.5M12 12.5l5.5 4.5',
    map: 'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.9 2.9M15.5 15.5l2.9 2.9M5.6 18.4l2.9-2.9M15.5 8.5l2.9-2.9',
    cards: 'M3 4h8v7H3zM13 4h8v7h-8zM3 13h8v7H3zM13 13h8v7h-8z',
    table: 'M3 5h18M3 12h18M3 19h18M8 5v14',
    live: 'M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8',
    file: 'M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8zM14 3v5h5',
    info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 16v-5M12 8h.01',
    chart: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
    ruler: 'M3 17 17 3l4 4L7 21zM7 13l2 2M10 10l2 2M13 7l2 2'
  };
  var PHASE_PLAIN = {
    recon: 'Looked around the PC and made the plan.',
    security: 'Wrote and ran the security check scripts.',
    verify: 'Double-checked the alarms to weed out false ones.',
    storage: 'Mapped disk space, programs and PC health.',
    dashboard1: 'Built the first dashboard, the local server and the report builder.',
    dashboard2: 'Built this dashboard: the pages, the storage map and INFOSEC.'
  };
  var SHORT_RULE = { easy: 'under 150,000 tokens and under 10 min', medium: 'under 350,000 tokens', hard: 'under 450,000 tokens',
    'extra-high': '450,000+ tokens or 45+ min', none: 'usage not recorded' };
  // kinds from src/core/agents_live.py (GET /api/agents/live) -> plain words
  var LIVE_KIND = {
    'claude-code': 'AI in a terminal (Anthropic)', codex: 'AI in a terminal (OpenAI)', gemini: 'AI in a terminal (Google)',
    aider: 'AI in a terminal', 'cursor-agent': 'AI in a terminal (Cursor)', copilot: 'AI in a terminal (GitHub)',
    cursor: 'AI code editor', windsurf: 'AI code editor', cli: 'AI in a terminal', editor: 'AI code editor'
  };

  var S = {
    root: null, data: null, mode: 'map', sort: { key: 'tokens', dir: -1 }, tip: null, body: null,
    byId: null, phaseById: null, selected: null,
    live: { timer: null, inflight: false, state: 'idle', items: [], at: null, error: null, token: null, tokenAt: 0, body: null, onVis: null }
  };

  // ------------------------------------------------------------------ small helpers
  function num(v) { return typeof v === 'number' && isFinite(v) && v >= 0 ? v : null; }
  function str(v) { return v === null || v === undefined ? '' : U.safeText(String(v)); }
  function plural(n, one, many) { return n === 1 ? one : (many || one + 's'); }
  function fmtInt(n) { return num(n) === null ? '—' : U.fmtNum(Math.round(n)); }
  function fmtTokens(n, long) {
    n = num(n);
    if (n === null) { return 'not measured'; }
    if (long) { return U.fmtNum(n) + ' tokens'; }
    if (n >= 1e6) { return (n / 1e6).toFixed(2) + ' M'; }
    if (n >= 1e3) { return Math.round(n / 1e3) + 'k'; }
    return String(n);
  }
  function fmtDur(sec) {
    sec = num(sec);
    if (sec === null) { return 'not measured'; }
    if (sec < 90) { return Math.round(sec) + ' s'; }
    var m = Math.round(sec / 60);
    return m >= 60 ? Math.floor(m / 60) + ' h ' + (m % 60) + ' min' : m + ' min';
  }
  function fmtRun(sec) {
    sec = num(sec);
    if (sec === null) { return '—'; }
    if (sec < 90) { return (sec < 10 ? sec.toFixed(1) : Math.round(sec)) + ' s'; }
    var m = Math.floor(sec / 60), s = Math.round(sec % 60);
    return m + ' min ' + (s ? s + ' s' : '');
  }
  function fmtLines(n) { return num(n) === null ? '—' : U.fmtNum(n) + ' ' + plural(n, 'line'); }
  function gradeOf(a) { return (a && GRADES[a.difficulty]) || GRADES.none; }
  function isEstimated(a) { return !!a && a.difficultyBasis === 'estimated'; }
  function phaseLabel(id) { var p = S.phaseById && S.phaseById[id]; return p ? p.label : str(id); }
  function phaseNo(id) { var p = S.phaseById && S.phaseById[id]; return p ? p.order : ''; }
  function bvs(type, id, label, extra) {
    var a = { 'data-bvs-type': type };
    if (id !== undefined && id !== null && id !== '') { a['data-bvs-id'] = String(id); }
    if (label) { a['data-bvs-label'] = str(label).slice(0, 120); }
    if (extra) { Object.keys(extra).forEach(function (k) { a[k] = extra[k]; }); }
    return a;
  }
  function reducedMotion() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
  function storeGet(k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } }
  function storeSet(k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function app() { return window.BVSApp || {}; }

  function svg(tag, attrs, kids) {
    var n = document.createElementNS(SVGNS, tag);
    if (attrs) { Object.keys(attrs).forEach(function (k) { if (attrs[k] !== null && attrs[k] !== undefined) { n.setAttribute(k, String(attrs[k])); } }); }
    (kids || []).forEach(function (c) { if (c) { n.appendChild(c); } });
    return n;
  }
  function svgText(x, y, text, cls, anchor) {
    var t = svg('text', { x: r1(x), y: r1(y), 'class': cls || null, 'text-anchor': anchor || null });
    t.textContent = str(text);
    return t;
  }
  function icon(name, cls) {
    var s = svg('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false', 'class': 'ag-ico' + (cls ? ' ' + cls : '') });
    s.appendChild(svg('path', { d: ICON[name] || ICON.info }));
    return s;
  }
  function r1(v) { return Math.round(v * 10) / 10; }

  // A grade disc: colour + letter (never colour alone). Dashed edge = estimated.
  function disc(a, size) {
    var g = a && a.key ? a : gradeOf(a);
    var est = a && !a.key && isEstimated(a);
    return el('span', { cls: 'ag-disc ' + g.cls + (est ? ' is-est' : '') + (size ? ' ' + size : ''), text: g.letter, attrs: { 'aria-hidden': 'true' } });
  }
  // withBasis: true = show 'measured' or 'estimated'; 'est' = only the 'estimated' badge (compact places)
  function gradeChip(a, withBasis) {
    var g = gradeOf(a);
    var basis = a.difficultyBasis === 'estimated' ? 'estimated' : a.difficultyBasis === 'measured' && withBasis !== 'est' ? 'measured' : '';
    return el('span', { cls: 'ag-chip ' + g.cls, attrs: { 'data-grade': g.key } }, [
      disc(a), el('span', { cls: 'ag-chip-label', text: g.label }),
      withBasis && basis && a.difficulty ? el('span', { cls: 'ag-basis is-' + basis, text: basis }) : null
    ]);
  }
  // withText: true = full label, 'short' = short label (table; full label in the tooltip), false = icon only
  function statusBadge(status, withText) {
    var m = STATUS[status] || { label: str(status) || 'Unknown', short: str(status) || 'Unknown', icon: 'unknown' };
    return el('span', { cls: 'ag-status st-' + (STATUS[status] ? status : 'unknown'), title: withText === true ? null : m.label }, [
      icon(m.icon), withText ? el('span', { text: withText === 'short' ? m.short : m.label }) : el('span', { cls: 'ag-sr', text: m.label })
    ]);
  }

  // ------------------------------------------------------------------ data
  function getData() {
    var d = null;
    try {
      var A = app();
      d = A.data && typeof A.data.get === 'function' ? A.data.get('agents') : null;
      if (!d && window.BVS && typeof window.BVS.get === 'function') { d = window.BVS.get('agents'); }
    } catch (e) { d = null; }
    if (!d || typeof d !== 'object' || !Array.isArray(d.agents) || !Array.isArray(d.phases)) { return null; }
    return d;
  }
  function index(d) {
    S.byId = Object.create(null);
    S.phaseById = Object.create(null);
    d.agents.forEach(function (a) { if (a && typeof a.id === 'string') { S.byId[a.id] = a; } });
    d.phases.slice().sort(function (a, b) { return (a.order || 0) - (b.order || 0); }).forEach(function (p, i) {
      if (p && typeof p.id === 'string') { S.phaseById[p.id] = { id: p.id, label: str(p.label || p.id), order: num(p.order) || i + 1, raw: p }; }
    });
  }
  function phases() {
    return Object.keys(S.phaseById).map(function (k) { return S.phaseById[k]; }).sort(function (a, b) { return a.order - b.order; });
  }
  function agentsIn(pid) { return S.data.agents.filter(function (a) { return a.phase === pid; }); }

  // ------------------------------------------------------------------ tooltip (hover / focus)
  function tipShow(target, lines) {
    if (!S.tip) { return; }
    U.clear(S.tip);
    lines.forEach(function (l, i) {
      if (!l) { return; }
      S.tip.appendChild(typeof l === 'string' ? el('div', { cls: i === 0 ? 'ag-tip-title' : 'ag-tip-row', text: l }) : l);
    });
    S.tip.hidden = false;
    var b = target.getBoundingClientRect();
    var tw = S.tip.offsetWidth, th = S.tip.offsetHeight;
    var x = b.left + b.width / 2 - tw / 2, y = b.top - th - 10;
    if (y < 8) { y = b.bottom + 10; }
    x = Math.max(8, Math.min(window.innerWidth - tw - 8, x));
    S.tip.style.left = Math.round(x) + 'px';
    S.tip.style.top = Math.round(y) + 'px';
  }
  function tipHide() { if (S.tip) { S.tip.hidden = true; } }
  function agentTip(a) {
    var g = gradeOf(a);
    return [
      a.name,
      el('div', { cls: 'ag-tip-grade' }, [gradeChip(a, true)]),
      'Tokens: ' + fmtTokens(a.tokens, true).replace(' tokens', ''),
      'Working time: ' + fmtDur(a.durationSec),
      num(a.scriptLines) !== null ? 'Script: ' + fmtLines(a.scriptLines) : null,
      num(a.runSec) !== null ? 'Scan run time: ' + fmtRun(a.runSec) : null,
      'Status: ' + ((STATUS[a.status] || {}).label || str(a.status)),
      el('div', { cls: 'ag-tip-hint', text: g.key === 'none' ? 'Click for details' : 'Click for details and why it is ' + g.label })
    ];
  }

  // ------------------------------------------------------------------ side panels
  function panelWrap(body, fill) {
    var w = el('div', { cls: 'agents-view ag-panel' });
    body.appendChild(w);
    fill(w);
  }
  function fact(label, value, sub, cls) {
    return el('div', { cls: 'ag-fact' + (cls ? ' ' + cls : '') }, [
      el('dt', { text: label }),
      el('dd', null, [el('span', { cls: 'ag-fact-v' + (/not measured|—/.test(value) ? ' is-none' : ''), text: value }), sub ? el('span', { cls: 'ag-fact-sub', text: sub }) : null])
    ]);
  }
  function openPanel(spec) {
    var A = app();
    if (typeof A.openPanel !== 'function') { return; }
    tipHide();
    A.openPanel(spec);
  }

  function openAgent(id) {
    var a = S.byId && S.byId[id];
    if (!a) { return; }
    markSelected(id);
    var g = gradeOf(a);
    openPanel({
      kind: 'custom', kicker: 'AI helper', id: a.id, item: a, title: a.name,
      subtitle: 'Round ' + phaseNo(a.phase) + ' · ' + phaseLabel(a.phase) + ' · ' + str(a.kindLabel || a.kind),
      render: function (body) {
        panelWrap(body, function (w) {
          // grade banner
          w.appendChild(el('section', { cls: 'ag-pbanner ' + g.cls, attrs: bvs('agent', a.id, a.name) }, [
            disc(a, 'big'),
            el('div', { cls: 'ag-pbanner-text' }, [
              el('div', { cls: 'ag-pbanner-title' }, [el('span', { text: g.label + (g.key === 'none' ? '' : ' job') }),
                a.difficulty ? el('span', { cls: 'ag-basis is-' + (isEstimated(a) ? 'estimated' : 'measured'), text: isEstimated(a) ? 'estimated' : 'measured' }) : null]),
              el('p', { text: str(a.difficultyReason) || g.plain })
            ])
          ]));
          // what it did
          w.appendChild(el('h3', { cls: 'ag-ph', text: 'What this helper did' }));
          w.appendChild(el('p', { cls: 'ag-p', text: str(a.kindLabel) + ': ' + str(a.role || '') }));
          var st = STATUS[a.status];
          w.appendChild(el('div', { cls: 'ag-pstatus' }, [statusBadge(a.status, true), st ? el('span', { cls: 'ag-muted', text: st.plain }) : null]));
          // facts
          w.appendChild(el('h3', { cls: 'ag-ph', text: 'How heavy the job was' }));
          var checks = a.checkStatus ? Object.keys(a.checkStatus).map(function (k) { return a.checkStatus[k] + ' ' + k.replace(/_/g, ' '); }).join(', ') : '';
          w.appendChild(el('dl', { cls: 'ag-facts' }, [
            fact('Tokens', fmtTokens(a.tokens, true), 'text the AI read and wrote'),
            fact('Tool calls', num(a.toolUses) === null ? 'not measured' : fmtInt(a.toolUses), 'commands, file reads and edits'),
            fact('Working time', fmtDur(a.durationSec), 'how long the helper worked'),
            fact('Script length', num(a.scriptLines) === null ? '—' : fmtLines(a.scriptLines), a.longestFile ? 'longest file: ' + str(a.longestFile.path).split('/').pop() : 'no script written'),
            fact('Scan run time', fmtRun(a.runSec), num(a.runSec) !== null ? 'how long its script took to run on your PC' : 'no scan module of its own'),
            fact('Findings', num(a.findings) === null ? '—' : fmtInt(a.findings), num(a.findings) !== null ? 'problems or notes it reported' : null),
            num(a.checks) !== null ? fact('Checks', fmtInt(a.checks), checks) : null,
            a.kind === 'storage' && num(a.itemsListed) ? fact('Items listed', fmtInt(a.itemsListed), 'folders, files and programs it listed for you') : null,
            a.module ? fact('Module', str(a.module), null) : null
          ]));
          if (a.verification && num(a.verification.records) !== null) {
            var vr = a.verification.results || {};
            w.appendChild(el('p', { cls: 'ag-p' }, [el('strong', { text: 'Double-checks written: ' + fmtInt(a.verification.records) + '. ' }),
              Object.keys(vr).map(function (k) { return vr[k] + ' ' + (k === 'refuted' ? 'false alarms' : k); }).join(', ') + '.']));
          }
          // produced files
          var files = Array.isArray(a.files) ? a.files : [];
          w.appendChild(el('h3', { cls: 'ag-ph', text: files.length ? 'What it produced' : 'What it produced: nothing saved as a file' }));
          if (files.length) {
            w.appendChild(el('ul', { cls: 'ag-files' }, files.map(function (f, i) {
              return el('li', null, [el('button', {
                cls: 'ag-file', attrs: bvs('file', f.path, f.path, { type: 'button' }),
                on: { click: function () { openFile(a.id, i); } }
              }, [icon('file'), el('span', { cls: 'ag-file-path', text: f.path }),
                el('span', { cls: 'ag-file-lines', text: num(f.lines) === null ? 'not found' : fmtLines(f.lines) + (f.counted ? '' : ' (not counted)') })])]);
            })));
          }
          if (a.notes) { w.appendChild(el('h3', { cls: 'ag-ph', text: 'Notes' })); w.appendChild(el('p', { cls: 'ag-p', text: a.notes })); }
          if (Array.isArray(a.envelopes) && a.envelopes.length) {
            w.appendChild(el('h3', { cls: 'ag-ph', text: 'When its scan ran' }));
            w.appendChild(el('ul', { cls: 'ag-plain-list' }, a.envelopes.map(function (m) {
              return el('li', { text: str(m.module) + ': ' + U.fmtDate(m.started, true) + ', ran ' + fmtRun(m.runSec) + ', ' + fmtInt(m.checks) + ' checks, ' + fmtInt(m.findings) + ' findings' + (m.elevated ? ' (as admin)' : '') }); })));
          }
          w.appendChild(basisBox(a));
        });
      }
    });
  }
  function basisBox(a) {
    var kids;
    if (a && a.difficultyBasis === 'measured') {
      kids = 'Measured: this grade comes from the AI\'s own usage meter (tokens and working time).';
    } else if (a && a.difficultyBasis === 'estimated') {
      kids = 'Estimated: this helper\'s usage was not recorded (it was stopped at the usage limit or ran before the meter was shown), so the length of the script it wrote is used instead.';
    } else {
      kids = 'Not graded: there is no usage meter reading and no script to measure, so no grade is shown. Nothing is guessed.';
    }
    return el('div', { cls: 'ag-note' }, [icon('info'), el('div', null, [el('strong', { text: 'Estimated or measured? ' }), kids,
      el('div', { cls: 'ag-muted', text: 'Rule: Easy = ' + GRADES.easy.rule + '; Medium = ' + GRADES.medium.rule + '; Hard = ' + GRADES.hard.rule + '; Extra high = ' + GRADES['extra-high'].rule + '. Without usage data: Easy = ' + GRADES.easy.est + ', Medium = ' + GRADES.medium.est + ', Hard = ' + GRADES.hard.est + ', Extra high = ' + GRADES['extra-high'].est + '.' })])]);
  }

  function openFile(agentId, i) {
    var a = S.byId[agentId], f = a && a.files && a.files[i];
    if (!f) { return; }
    openPanel({
      kind: 'custom', kicker: 'File a helper made', id: f.path, title: str(f.path).split('/').pop(), subtitle: f.path,
      render: function (body) {
        panelWrap(body, function (w) {
          w.appendChild(el('dl', { cls: 'ag-facts' }, [
            fact('Length', num(f.lines) === null ? 'not found' : fmtLines(f.lines), f.counted ? 'counted as this helper\'s script' : 'not counted as script length'),
            fact('Type', { script: 'Script (a program)', code: 'Page code', doc: 'Written guide', config: 'Settings file', data: 'Results file' }[f.kind] || 'Other', null),
            fact('Made by', a.name, phaseLabel(a.phase))
          ]));
          if (f.note) { w.appendChild(el('div', { cls: 'ag-note' }, [icon('info'), el('div', { text: f.note })])); }
          w.appendChild(el('p', { cls: 'ag-p ag-muted', text: 'Line counts are the file\'s current length. Other helpers may have edited it later.' }));
        });
      },
      actions: [{ label: 'Show the helper', primary: true, onClick: function () { openAgent(a.id); } }]
    });
  }

  function openPhase(pid) {
    var p = S.phaseById[pid];
    if (!p) { return; }
    var list = agentsIn(pid), raw = p.raw || {};
    openPanel({
      kind: 'custom', kicker: 'Round ' + p.order, id: 'phase-' + pid, title: p.label, subtitle: PHASE_PLAIN[pid] || null,
      render: function (body) {
        panelWrap(body, function (w) {
          w.appendChild(el('dl', { cls: 'ag-facts' }, [
            fact('Helpers', fmtInt(list.length), num(raw.measuredAgents) !== null ? raw.measuredAgents + ' with measured usage' : null),
            fact('Tokens', fmtTokens(raw.tokens, true), num(raw.tokens) !== null ? 'for the measured helpers only' : null),
            fact('Working time', fmtDur(raw.durationSec), 'added up'),
            fact('Script lines', num(raw.scriptLines) === null ? '—' : fmtLines(raw.scriptLines), null),
            num(raw.findings) !== null ? fact('Findings', fmtInt(raw.findings), null) : null
          ]));
          w.appendChild(el('h3', { cls: 'ag-ph', text: 'Helpers in this round' }));
          w.appendChild(agentList(list));
        });
      }
    });
  }

  function openOrchestrator() {
    var o = S.data.orchestrator || {};
    openPanel({
      kind: 'custom', kicker: 'The main session', id: 'orchestrator', title: str(o.name || 'Claude main session'), subtitle: o.model ? 'Model: ' + o.model : null,
      render: function (body) {
        panelWrap(body, function (w) {
          w.appendChild(el('p', { cls: 'ag-p', text: 'This is the Claude session you talk to. ' + str(o.role || '') + '.' }));
          w.appendChild(el('dl', { cls: 'ag-facts' }, [
            fact('Helpers it started', fmtInt(S.data.agents.length), null),
            fact('Its own tokens', fmtTokens(o.tokens, true), num(o.tokens) === null ? 'the main session\'s own usage is not in the record' : null),
            fact('Rounds', fmtInt(phases().length), null)
          ]));
          (S.data.notes || []).forEach(function (n) { w.appendChild(el('div', { cls: 'ag-note' }, [icon('info'), el('div', { text: n })])); });
        });
      }
    });
  }

  function openGrade(key) {
    var g = GRADES[key] || GRADES.none;
    var list = S.data.agents.filter(function (a) { return gradeOf(a).key === g.key; });
    openPanel({
      kind: 'custom', kicker: 'Difficulty', id: 'grade-' + g.key, title: g.label + ' (' + g.letter + ')', subtitle: g.plain,
      render: function (body) {
        panelWrap(body, function (w) {
          w.appendChild(el('div', { cls: 'ag-pbanner ' + g.cls }, [disc(g, 'big'), el('div', { cls: 'ag-pbanner-text' }, [
            el('div', { cls: 'ag-pbanner-title', text: g.label }),
            el('p', { text: g.key === 'none' ? 'Helpers without a usage reading and without a script.' : 'Measured: ' + g.rule + '. Estimated when usage is missing: ' + g.est + '.' })])]));
          w.appendChild(el('h3', { cls: 'ag-ph', text: list.length + ' ' + plural(list.length, 'helper') + ' with this grade' }));
          w.appendChild(list.length ? agentList(list) : el('p', { cls: 'ag-p ag-muted', text: 'None in this scan.' }));
        });
      }
    });
  }

  function openExplainer(kind) {
    var t = S.data.totals || {};
    var spec = {
      tokens: { title: 'What are tokens?', text: [
        'Tokens are small pieces of text. Every word the AI reads (files, command output, instructions) and every word it writes counts.',
        'More tokens means a heavier job: more to read, more to think about, more to write. A single AI session can hold only so many before it has to stop.',
        'The ' + fmtInt(t.measuredAgents) + ' helpers whose meter was recorded used ' + fmtTokens(t.tokens, true) + ' together. ' + fmtInt(t.unmeasuredAgents) + ' helpers were not measured, so the real total is higher.'] },
      time: { title: 'Helper working time', text: [
        'This is how long each helper worked, added up: ' + fmtDur(t.durationSec) + ' for the ' + fmtInt(t.measuredAgents) + ' measured helpers.',
        'Many helpers worked at the same time, so the scan did not take this long on the clock.',
        'Scan run time is different: it is how long a finished script takes to run on your PC. A typical scan script runs in about ' + fmtRun(t.typicalRunSec) + '; the slowest took ' + fmtRun(t.longestRunSec) + '.'] }
    }[kind];
    if (!spec) { return; }
    openPanel({
      kind: 'custom', kicker: 'Explanation', id: 'explain-' + kind, title: spec.title,
      render: function (body) {
        panelWrap(body, function (w) {
          spec.text.forEach(function (p) { w.appendChild(el('p', { cls: 'ag-p', text: p })); });
          w.appendChild(el('h3', { cls: 'ag-ph', text: 'Per round' }));
          w.appendChild(el('ul', { cls: 'ag-plain-list' }, phases().map(function (p) {
            var raw = p.raw || {};
            return el('li', { text: p.order + '. ' + p.label + ': ' + (kind === 'tokens' ? fmtTokens(raw.tokens, true) : fmtDur(raw.durationSec)) + ' (' + fmtInt(raw.measuredAgents) + ' of ' + fmtInt(raw.agents) + ' measured)' });
          })));
        });
      }
    });
  }

  function agentList(list) {
    return el('ul', { cls: 'ag-alist' }, list.map(function (a) {
      return el('li', null, [el('button', {
        cls: 'ag-arow', attrs: bvs('agent', a.id, a.name, { type: 'button' }), on: { click: function () { openAgent(a.id); } }
      }, [disc(a), el('span', { cls: 'ag-arow-name', text: a.name }), el('span', { cls: 'ag-arow-val', text: num(a.tokens) !== null ? fmtTokens(a.tokens) + ' tokens' : num(a.scriptLines) !== null ? fmtLines(a.scriptLines) : 'not measured' }), statusBadge(a.status)])]);
    }));
  }

  function markSelected(id) {
    S.selected = id;
    if (!S.root) { return; }
    Array.prototype.forEach.call(S.root.querySelectorAll('.is-selected'), function (n) { n.classList.remove('is-selected'); });
    Array.prototype.forEach.call(S.root.querySelectorAll('[data-bvs-type="agent"]'), function (n) {
      if (n.getAttribute('data-bvs-id') === id) { n.classList.add('is-selected'); }
    });
  }

  // ------------------------------------------------------------------ header, tiles, legend
  function renderHead(root) {
    root.appendChild(el('header', { cls: 'ag-head', attrs: { 'data-bvs-section': 'agents-head' } }, [
      el('div', { cls: 'ag-head-icon' }, icon('agents')),
      el('div', { cls: 'ag-head-text' }, [
        el('h1', { text: 'Agent map' }),
        el('p', { cls: 'ag-intro', text: 'Many AI helpers worked on your scan. Each circle is one helper; its colour shows how heavy its job was.' }),
        el('p', { cls: 'ag-intro2', text: 'Claude (the main session) is in the middle. It planned the work and sent helpers out in ' + phases().length + ' rounds, clockwise from the top.' })
      ])
    ]));
  }

  function renderTiles(root) {
    var t = S.data.totals || {};
    var ls = t.longestScript || null, lsA = ls && S.byId[ls.agent];
    var tiles = [
      { id: 'helpers', value: fmtInt(t.agents), label: 'AI helpers', sub: 'plus the main Claude session · usage measured for ' + fmtInt(t.measuredAgents), go: function () { setMode('cards'); } },
      { id: 'tokens', value: num(t.tokens) === null ? 'not measured' : fmtTokens(t.tokens), label: 'tokens used', sub: 'text the ' + fmtInt(t.measuredAgents) + ' measured helpers read and wrote', go: function () { openExplainer('tokens'); } },
      { id: 'time', value: fmtDur(t.durationSec), label: 'helper working time', sub: 'added up; many worked at the same time', go: function () { openExplainer('time'); } },
      { id: 'longest', value: ls ? fmtInt(ls.lines) : '—', unit: ls ? 'lines' : '', label: 'longest scan script', sub: ls ? (lsA ? lsA.name : str(ls.agent)) + (num(t.typicalScanScriptLines) !== null ? ' · a typical one has about ' + fmtInt(t.typicalScanScriptLines) : '') : 'no scripts recorded', go: function () { if (ls) { openAgent(ls.agent); } } }
    ];
    root.appendChild(el('div', { cls: 'ag-tiles', attrs: { 'data-bvs-section': 'agents-totals' } }, tiles.map(function (x) {
      return el('button', { cls: 'ag-tile', attrs: bvs('tile', 'agents-' + x.id, x.label + ': ' + x.value, { type: 'button' }), on: { click: x.go } }, [
        el('span', { cls: 'ag-tile-value' }, [x.value, x.unit ? el('span', { cls: 'ag-tile-unit', text: ' ' + x.unit }) : null]),
        el('span', { cls: 'ag-tile-label', text: x.label }),
        el('span', { cls: 'ag-tile-sub', text: x.sub })
      ]);
    })));
  }

  function renderLegend(root) {
    var counts = {};
    S.data.agents.forEach(function (a) { var k = gradeOf(a).key; counts[k] = (counts[k] || 0) + 1; });
    var chips = GRADE_ORDER.concat(['none']).map(function (k) {
      var g = GRADES[k];
      return el('button', { cls: 'ag-lchip ' + g.cls, attrs: bvs('section', 'grade-' + k, g.label, { type: 'button', 'aria-label': g.label + ' (' + g.letter + '): ' + (k === 'none' ? g.rule : g.rule) + '. ' + (counts[k] || 0) + ' helpers. Show them.' }), on: { click: function () { openGrade(k); } } }, [
        disc(g), el('span', { cls: 'ag-lchip-text' }, [el('strong', { text: g.label }), el('span', { text: SHORT_RULE[k] })]),
        el('span', { cls: 'ag-lchip-n', text: String(counts[k] || 0) })
      ]);
    });
    root.appendChild(el('div', { cls: 'ag-legend', attrs: { 'data-bvs-section': 'agents-legend', role: 'group', 'aria-label': 'Difficulty legend' } }, [
      el('div', { cls: 'ag-legend-chips' }, chips),
      el('p', { cls: 'ag-legend-rule' }, [
        el('strong', { text: 'How the colour is chosen: ' }),
        'by tokens (how much text the AI read and wrote) and working time. If those were not measured, the length of the script it wrote decides: under 500 lines Easy, under 1,500 Medium, under 3,000 Hard, more is Extra high. ',
        el('span', { cls: 'ag-dash-key', attrs: { 'aria-hidden': 'true' } }), ' A dashed edge means "estimated".'
      ])
    ]));
  }

  function renderToggle(root) {
    var labels = { map: 'Map', cards: 'Cards', table: 'Table' };
    var bar = el('div', { cls: 'ag-toggle', attrs: { role: 'tablist', 'aria-label': 'How to show the helpers' } }, MODES.map(function (m) {
      return el('button', { cls: 'ag-tbtn' + (S.mode === m ? ' is-on' : ''), attrs: { type: 'button', role: 'tab', 'aria-selected': S.mode === m ? 'true' : 'false', 'data-mode': m },
        on: { click: function () { setMode(m); } } }, [icon(m), el('span', { text: labels[m] })]);
    }));
    root.appendChild(el('div', { cls: 'ag-toolbar' }, [bar, el('span', { cls: 'ag-toolbar-hint', text: S.mode === 'map' ? 'Hover a circle for a quick look; click it for everything.' : S.mode === 'table' ? 'Click a column title to sort; click a row for details.' : 'Click a card for details.' })]));
  }

  function setMode(m) {
    if (MODES.indexOf(m) < 0 || !S.root) { return; }
    S.mode = m;
    storeSet(MODE_KEY, m);
    renderBody();
    var tb = S.root.querySelector('.ag-toolbar');
    if (tb) { tb.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' }); }
  }

  // ------------------------------------------------------------------ the map (radial tree, SVG)
  var GEO = { W: 1340, H: 1060, CX: 670, CY: 530, R0: 64, R1: 162, R2: 318, RB: 376, BAR: 70, RL: 470 };
  function polar(r, deg) { var a = deg * Math.PI / 180; return { x: GEO.CX + r * Math.cos(a), y: GEO.CY + r * Math.sin(a) }; }
  function wedgePath(r0, rr, a0, a1) {
    var p0 = polar(rr, a0), p1 = polar(rr, a1), p2 = polar(r0, a1), p3 = polar(r0, a0), large = a1 - a0 > 180 ? 1 : 0;
    return 'M' + r1(p0.x) + ' ' + r1(p0.y) + 'A' + rr + ' ' + rr + ' 0 ' + large + ' 1 ' + r1(p1.x) + ' ' + r1(p1.y) +
      'L' + r1(p2.x) + ' ' + r1(p2.y) + 'A' + r0 + ' ' + r0 + ' 0 ' + large + ' 0 ' + r1(p3.x) + ' ' + r1(p3.y) + 'Z';
  }
  function layout() {
    var list = phases(), MIN = 2, GAP = 1, total = 0;
    var slots = {};
    list.forEach(function (p) { var n = agentsIn(p.id).length; slots[p.id] = Math.max(n, MIN); total += slots[p.id] + GAP; });
    var step = 360 / Math.max(total, 1), ang = -90 + GAP * step / 2, pos = {}, ph = {};
    list.forEach(function (p) {
      var members = agentsIn(p.id), k = slots[p.id], off = (k - members.length) / 2;
      ph[p.id] = { a0: ang, a1: ang + k * step, mid: ang + k * step / 2 };
      members.forEach(function (a, i) { pos[a.id] = ang + (off + i + 0.5) * step; });
      ang += (k + GAP) * step;
    });
    return { step: step, pos: pos, ph: ph };
  }
  function nodeRadius(a, maxT) {
    var t = num(a.tokens);
    return t === null || !maxT ? 16 : Math.max(14, 27 * Math.sqrt(t / maxT));
  }
  function anchorFor(deg) {
    var c = Math.cos(deg * Math.PI / 180);
    return c > 0.3 ? 'start' : c < -0.3 ? 'end' : 'middle';
  }
  // UI-D (decorative): paint servers for the glossy 3D spheres, their bloom, the specular highlight and the
  // reactor core. Stop colours come from agents.css (grade variables), so the fixed grade palette and the
  // light/dark themes still decide every colour.
  function fxDefs() {
    function stops(n) { var out = []; for (var i = 0; i < n; i++) { out.push(svg('stop', { offset: String(i / (n - 1)) })); } return out; }
    var defs = svg('defs', null);
    ['easy', 'medium', 'hard', 'xhigh', 'none'].forEach(function (k) {
      defs.appendChild(svg('radialGradient', { id: 'agfx-sph-' + k, 'class': 'agfx-sph g-' + k, cx: '0.38', cy: '0.32', r: '0.72' }, stops(3)));
      defs.appendChild(svg('radialGradient', { id: 'agfx-bloom-' + k, 'class': 'agfx-bloom g-' + k }, stops(2)));
    });
    defs.appendChild(svg('radialGradient', { id: 'agfx-spec', 'class': 'agfx-spec' }, stops(2)));
    defs.appendChild(svg('radialGradient', { id: 'agfx-orch', 'class': 'agfx-orch', cx: '0.36', cy: '0.3', r: '0.78' }, stops(3)));
    return defs;
  }
  // UI-D (decorative): an orbit ellipse split in a back half (drawn behind the sphere) and a front half.
  function orbitHalf(cx, cy, rx, ry, front) {
    var d = front ? 'M' + r1(cx + rx) + ' ' + r1(cy) + 'A' + r1(rx) + ' ' + r1(ry) + ' 0 0 1 ' + r1(cx - rx) + ' ' + r1(cy)
      : 'M' + r1(cx - rx) + ' ' + r1(cy) + 'A' + r1(rx) + ' ' + r1(ry) + ' 0 0 1 ' + r1(cx + rx) + ' ' + r1(cy);
    return svg('path', { d: d, transform: 'rotate(-22 ' + r1(cx) + ' ' + r1(cy) + ')', 'class': 'ag-node-orbit ' + (front ? 'is-front' : 'is-back') });
  }

  function renderMap(host) {
    var d = S.data, L = layout(), list = phases();
    var maxT = 0, maxLines = 0;
    d.agents.forEach(function (a) {
      if (num(a.tokens) !== null) { maxT = Math.max(maxT, a.tokens); }
      (a.files || []).forEach(function (f) { if (f.counted && num(f.lines) !== null) { maxLines = Math.max(maxLines, f.lines); } });
    });
    var root = svg('svg', { viewBox: '0 0 ' + GEO.W + ' ' + GEO.H, 'class': 'ag-map', role: 'group', 'aria-label': 'Map of the AI helpers: the main session in the centre, ' + list.length + ' rounds around it, every helper as a circle coloured by difficulty' });
    root.appendChild(fxDefs()); // UI-D: decorative gradients only
    var gW = svg('g', { 'class': 'ag-l-wedges' }), gE = svg('g', { 'class': 'ag-l-edges' }), gF = svg('g', { 'class': 'ag-l-files' });
    var gP = svg('g', { 'class': 'ag-l-phases' }), gN = svg('g', { 'class': 'ag-l-nodes' }), gT = svg('g', { 'class': 'ag-l-labels' });

    // rounds: background wedge, spoke from the centre, numbered hub, outer label
    list.forEach(function (p, i) {
      var g = L.ph[p.id], raw = p.raw || {}, n = agentsIn(p.id).length;
      gW.appendChild(svg('path', { d: wedgePath(GEO.R1 + 28, GEO.RB - 10, g.a0 + 0.6, g.a1 - 0.6), 'class': 'ag-wedge ' + (i % 2 ? 'w-b' : 'w-a') }));
      var s0 = polar(GEO.R0 + 6, g.mid), s1 = polar(GEO.R1 - 20, g.mid);
      gE.appendChild(svg('line', { x1: r1(s0.x), y1: r1(s0.y), x2: r1(s1.x), y2: r1(s1.y), 'class': 'ag-spoke' }));
      var hub = polar(GEO.R1, g.mid);
      var hubG = svg('g', bvsSvg('section', 'phase-' + p.id, 'Round ' + p.order + ': ' + p.label, { 'class': 'ag-hub', tabindex: 0, role: 'button', 'data-ag': 'phase', 'data-ag-id': p.id,
        'aria-label': 'Round ' + p.order + ', ' + p.label + ': ' + n + ' ' + plural(n, 'helper') + '. Open details.' }), [
        svg('circle', { cx: r1(hub.x), cy: r1(hub.y), r: 20, 'class': 'ag-hub-c' }),
        svgText(hub.x, hub.y + 6, String(p.order), 'ag-hub-t', 'middle')
      ]);
      gP.appendChild(hubG);
      // outer label
      var lp = polar(GEO.RL, g.mid), anc = anchorFor(g.mid), sin = Math.sin(g.mid * Math.PI / 180);
      var y0 = anc === 'middle' ? (sin < 0 ? lp.y - 22 : lp.y + 8) : lp.y - 4;
      var stats = n + ' ' + plural(n, 'helper') + ' · ' + (num(raw.tokens) !== null ? fmtTokens(raw.tokens) + ' tokens' : 'usage not measured');
      var lab = svg('g', bvsSvg('section', 'phase-' + p.id, p.label, { 'class': 'ag-plabel', 'data-ag': 'phase', 'data-ag-id': p.id }), [
        svgText(lp.x, y0, p.order + '  ' + p.label, 'ag-plabel-t', anc),
        svgText(lp.x, y0 + 21, stats, 'ag-plabel-s', anc)
      ]);
      gT.appendChild(lab);
    });

    // orchestrator (its moving reactor lives in reactorLayer() below the map, so the map SVG itself never animates)
    var o = d.orchestrator || {};
    gN.appendChild(svg('g', bvsSvg('section', 'orchestrator', str(o.name || 'Claude main session'), { 'class': 'ag-orch', tabindex: 0, role: 'button', 'data-ag': 'orch',
      'aria-label': str(o.name || 'Claude main session') + ': plans the work and starts every helper. Open details.' }), [
      svg('circle', { cx: GEO.CX, cy: GEO.CY, r: GEO.R0 + 10, 'class': 'ag-orch-halo' }),
      svg('circle', { cx: GEO.CX, cy: GEO.CY, r: GEO.R0, 'class': 'ag-orch-c' }),
      svg('ellipse', { cx: r1(GEO.CX - GEO.R0 * 0.26), cy: r1(GEO.CY - GEO.R0 * 0.44), rx: r1(GEO.R0 * 0.5), ry: r1(GEO.R0 * 0.28), 'class': 'ag-orch-spec', 'aria-hidden': 'true' }),
      svgText(GEO.CX, GEO.CY - 2, 'Claude', 'ag-orch-t', 'middle'),
      svgText(GEO.CX, GEO.CY + 20, 'main session', 'ag-orch-s', 'middle')
    ]));

    // helpers: edge from their round's hub, the node, files as radial bars
    d.agents.forEach(function (a) {
      var ang = L.pos[a.id];
      if (ang === undefined) { return; }
      var g = gradeOf(a), est = isEstimated(a), r = nodeRadius(a, maxT), c = polar(GEO.R2, ang);
      var ph = L.ph[a.phase], hub = polar(GEO.R1 + 20, ph.mid), c1 = polar(GEO.R1 + 80, ph.mid), c2 = polar(GEO.R2 - 80, ang), end = polar(GEO.R2 - r - 1, ang);
      var edgeD = 'M' + r1(hub.x) + ' ' + r1(hub.y) + 'C' + r1(c1.x) + ' ' + r1(c1.y) + ' ' + r1(c2.x) + ' ' + r1(c2.y) + ' ' + r1(end.x) + ' ' + r1(end.y);
      gE.appendChild(svg('path', { d: edgeD, 'class': 'ag-edge', 'data-for': a.id }));
      gE.appendChild(svg('path', { d: edgeD, 'class': 'ag-edge-flow', 'data-for': a.id, 'aria-hidden': 'true' })); // UI-D: data stream

      var files = Array.isArray(a.files) ? a.files : [];
      var spread = Math.min(2.4, (L.step * 0.8) / Math.max(files.length, 1));
      files.forEach(function (f, i) {
        var fa = ang + (i - (files.length - 1) / 2) * spread;
        var e0 = polar(GEO.R2 + r + 2, ang), e1 = polar(GEO.RB - 3, fa);
        gE.appendChild(svg('line', { x1: r1(e0.x), y1: r1(e0.y), x2: r1(e1.x), y2: r1(e1.y), 'class': 'ag-fedge', 'data-for': a.id }));
        var counted = f.counted && num(f.lines) !== null;
        var len = counted && maxLines ? 6 + GEO.BAR * f.lines / maxLines : 7;
        var tr = 'translate(' + GEO.CX + ' ' + GEO.CY + ') rotate(' + r1(fa) + ')';
        var label = str(f.path).split('/').pop() + ': ' + (num(f.lines) === null ? 'file not found' : fmtLines(f.lines));
        gF.appendChild(svg('rect', bvsSvg('file', f.path, label, {
          x: GEO.RB, y: counted ? -3.5 : -3.5, width: r1(len), height: 7, rx: counted ? 2 : 1, transform: tr,
          'class': 'ag-fbar ' + (counted ? g.cls : 'is-other') + (num(f.lines) === null ? ' is-missing' : ''), tabindex: -1,
          'data-ag': 'file', 'data-ag-id': a.id, 'data-ag-i': i
        })));
      });

      var nodeG = svg('g', bvsSvg('agent', a.id, a.name, {
        'class': 'ag-node ' + g.cls + (est ? ' is-est' : '') + (num(a.tokens) === null ? ' is-unmeasured' : '') + (S.selected === a.id ? ' is-selected' : ''),
        tabindex: 0, role: 'button', 'data-ag': 'agent', 'data-ag-id': a.id,
        'aria-label': a.name + ': ' + g.label + (a.difficulty ? (est ? ' (estimated)' : ' (measured)') : '') + '. ' + fmtTokens(a.tokens, true) + '. ' + ((STATUS[a.status] || {}).label || '') + '. Open details.'
      }), [
        svg('circle', { cx: r1(c.x), cy: r1(c.y), r: r1(r * 1.9), 'class': 'ag-node-bloom', 'aria-hidden': 'true' }), // UI-D
        orbitHalf(c.x, c.y, r + 8, (r + 8) * 0.34, false), // UI-D: orbit, back half
        svg('circle', { cx: r1(c.x), cy: r1(c.y), r: r1(r + 5), 'class': 'ag-node-ring' }),
        svg('circle', { cx: r1(c.x), cy: r1(c.y), r: r1(r), 'class': 'ag-node-c' }),
        svg('ellipse', { cx: r1(c.x - r * 0.3), cy: r1(c.y - r * 0.4), rx: r1(r * 0.5), ry: r1(r * 0.3), 'class': 'ag-node-spec', 'aria-hidden': 'true' }), // UI-D
        orbitHalf(c.x, c.y, r + 8, (r + 8) * 0.34, true), // UI-D: orbit, front half
        svgText(c.x, c.y + 6, g.letter, 'ag-node-t', 'middle'),
        statusMark(a.status, c.x + (r + 1) * Math.cos((ang - 58) * Math.PI / 180), c.y + (r + 1) * Math.sin((ang - 58) * Math.PI / 180))
      ]);
      gN.appendChild(nodeG);

      // label inside the ring, running along the radius towards the centre (never upside down), on a
      // halo so it stays readable over its own edge; neighbours never collide because each has its slot
      var lp = polar(GEO.R2 - r - 9, ang), right = Math.cos(ang * Math.PI / 180) >= 0;
      var lab = svgText(lp.x, lp.y, a.short || a.id, 'ag-nlabel', right ? 'end' : 'start');
      lab.setAttribute('dy', '0.35em');
      lab.setAttribute('transform', 'rotate(' + r1(right ? ang : ang + 180) + ' ' + r1(lp.x) + ' ' + r1(lp.y) + ')');
      gT.appendChild(lab);
    });

    [gW, gE, gF, gP, gN, gT].forEach(function (g) { root.appendChild(g); });

    var wrap = el('div', { cls: 'ag-map-wrap', attrs: { 'data-bvs-section': 'agents-map' } });
    wrap.appendChild(el('div', { cls: 'ag-map-box' }, [reactorLayer(), root]));
    host.appendChild(el('section', { cls: 'ag-card ag-map-card', attrs: { 'data-bvs-section': 'agents-map-card' } }, [
      wrap,
      mapKey()
    ]));
    wireMap(root);
    if (window.BVSFx && typeof window.BVSFx.slots === 'function') { window.BVSFx.slots(wrap); } // UI-D: optional agent-core art (.png/.webp)
  }
  // UI-F: the main session's reactor (optional agent-core art, else bloom, counter-rotating rings and a sweep
  // arc) as HTML layers under the map, centred on the orchestrator by percentages of the map's viewBox (the
  // .ag-map-box keeps the same aspect ratio). Their spin and breathing are transform/opacity animations the
  // compositor runs, so the large map SVG is painted once instead of on every frame.
  function reactorLayer() {
    var size = 300, lay = el('div', { cls: 'ag-orch-layer', attrs: { 'aria-hidden': 'true' } }, [
      el('span', { cls: 'fx-slot ag-orch-art', attrs: { 'data-fx-slot': 'agent-core' } }),
      el('span', { cls: 'fx-fallback ag-orch-deco' }, ['ag-orch-bloom', 'ag-orch-ring2', 'ag-orch-ring1', 'ag-orch-arc'].map(function (c) { return el('span', { cls: c }); }))
    ]);
    lay.style.left = ((GEO.CX - size / 2) / GEO.W * 100).toFixed(3) + '%';
    lay.style.top = ((GEO.CY - size / 2) / GEO.H * 100).toFixed(3) + '%';
    lay.style.width = (size / GEO.W * 100).toFixed(3) + '%';
    return lay;
  }
  function bvsSvg(type, id, label, extra) {
    var a = bvs(type, id, label);
    Object.keys(extra || {}).forEach(function (k) { a[k] = extra[k]; });
    return a;
  }
  function statusMark(status, x, y) {
    var m = STATUS[status] || { icon: 'unknown', label: 'Unknown' };
    var g = svg('g', { 'class': 'ag-smark st-' + (STATUS[status] ? status : 'unknown'), 'aria-hidden': 'true' });
    g.appendChild(svg('circle', { cx: r1(x), cy: r1(y), r: 8.5 }));
    g.appendChild(svg('path', { d: ICON[m.icon], transform: 'translate(' + r1(x - 6.5) + ' ' + r1(y - 6.5) + ') scale(0.5417)' }));
    return g;
  }
  function mapKey() {
    function k(svgKids, text) { return el('li', null, [svgKids, el('span', { text: text })]); }
    function mini(kids) { return svg('svg', { viewBox: '0 0 24 24', 'class': 'ag-key-svg', 'aria-hidden': 'true' }, kids); }
    function smark(name) { var g = svg('g', { 'class': 'ag-smark st-' + name }); g.appendChild(svg('circle', { cx: 12, cy: 12, r: 10 })); g.appendChild(svg('path', { d: ICON[STATUS[name].icon], transform: 'translate(4 4) scale(0.6667)' })); return mini([g]); }
    return el('ul', { cls: 'ag-key', attrs: { 'aria-label': 'How to read the map' } }, [
      k(mini([svg('circle', { cx: 8, cy: 12, r: 4, 'class': 'ag-key-dot' }), svg('circle', { cx: 17, cy: 12, r: 6.5, 'class': 'ag-key-dot' })]), 'Bigger circle = more tokens used'),
      k(mini([svg('circle', { cx: 12, cy: 12, r: 8, 'class': 'ag-key-dash' })]), 'Dashed edge = usage not measured (grade estimated)'),
      k(mini([svg('rect', { x: 2, y: 9, width: 20, height: 6, rx: 2, 'class': 'ag-key-bar' })]), 'Outer bars = files it wrote; longer bar = longer script'),
      k(smark('done'), 'Finished'),
      k(smark('resumed-done'), 'Stopped at the usage limit, resumed, finished'),
      k(smark('stopped-limit'), 'Stopped by the usage limit'),
      k(smark('replaced'), 'Replaced by the main session')
    ]);
  }
  function wireMap(root) {
    function target(ev) { var t = ev.target; return t && t.closest ? t.closest('[data-ag]') : null; }
    function tipFor(t) {
      var kind = t.getAttribute('data-ag'), id = t.getAttribute('data-ag-id');
      if (kind === 'agent') { var a = S.byId[id]; if (a) { tipShow(t, agentTip(a)); highlight(id, true); } }
      else if (kind === 'phase') {
        var p = S.phaseById[id], raw = (p && p.raw) || {};
        if (p) { tipShow(t, ['Round ' + p.order + ': ' + p.label, PHASE_PLAIN[id] || '', agentsIn(id).length + ' helpers · ' + (num(raw.tokens) !== null ? fmtTokens(raw.tokens, true) : 'usage not measured'), el('div', { cls: 'ag-tip-hint', text: 'Click for the list' })]); }
      } else if (kind === 'orch') {
        tipShow(t, ['Claude main session', 'Plans the work, starts every helper, checks their results and talks to you.', el('div', { cls: 'ag-tip-hint', text: 'Click for details' })]);
      } else if (kind === 'file') {
        var ag = S.byId[id], f = ag && ag.files && ag.files[Number(t.getAttribute('data-ag-i'))];
        if (f) { tipShow(t, [str(f.path).split('/').pop(), num(f.lines) === null ? 'File not found' : fmtLines(f.lines) + (f.counted ? '' : ' (not counted as script length)'), 'Made by ' + ag.name]); highlight(id, true); }
      }
    }
    function activate(t) {
      var kind = t.getAttribute('data-ag'), id = t.getAttribute('data-ag-id');
      if (kind === 'agent') { openAgent(id); } else if (kind === 'phase') { openPhase(id); } else if (kind === 'orch') { openOrchestrator(); }
      else if (kind === 'file') { openFile(id, Number(t.getAttribute('data-ag-i'))); }
    }
    root.addEventListener('pointerover', function (ev) { var t = target(ev); if (t) { tipFor(t); } });
    root.addEventListener('pointerout', function (ev) { var t = target(ev); if (t && !(ev.relatedTarget && t.contains(ev.relatedTarget))) { tipHide(); highlight(null, false); } });
    root.addEventListener('focusin', function (ev) { var t = target(ev); if (t) { tipFor(t); } });
    root.addEventListener('focusout', function () { tipHide(); highlight(null, false); });
    root.addEventListener('click', function (ev) { var t = target(ev); if (t) { activate(t); } });
    root.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Enter' && ev.key !== ' ') { return; }
      var t = target(ev); if (t) { ev.preventDefault(); activate(t); }
    });
  }
  function highlight(id, on) {
    if (!S.root) { return; }
    var svgRoot = S.root.querySelector('.ag-map');
    if (!svgRoot) { return; }
    svgRoot.classList.toggle('has-focus', !!on);
    Array.prototype.forEach.call(svgRoot.querySelectorAll('.is-hot'), function (n) { n.classList.remove('is-hot'); });
    if (!on || !id) { return; }
    Array.prototype.forEach.call(svgRoot.querySelectorAll('[data-for="' + id.replace(/"/g, '') + '"], [data-ag-id="' + id.replace(/"/g, '') + '"]'), function (n) { n.classList.add('is-hot'); });
  }

  // ------------------------------------------------------------------ cards view
  function renderCards(host) {
    var wrap = el('div', { cls: 'ag-cards-wrap', attrs: { 'data-bvs-section': 'agents-cards' } });
    phases().forEach(function (p) {
      var list = agentsIn(p.id);
      if (!list.length) { return; }
      wrap.appendChild(el('h2', { cls: 'ag-round-h' }, [el('span', { cls: 'ag-round-n', text: String(p.order) }), el('span', { text: p.label }),
        el('span', { cls: 'ag-round-sub', text: list.length + ' ' + plural(list.length, 'helper') + ' · ' + (PHASE_PLAIN[p.id] || '') })]));
      wrap.appendChild(el('div', { cls: 'ag-cards' }, list.map(agentCard)));
    });
    host.appendChild(wrap);
  }
  function agentCard(a) {
    var g = gradeOf(a);
    function m(label, value) { return el('div', { cls: 'ag-m' }, [el('span', { cls: 'ag-m-l', text: label }), el('span', { cls: 'ag-m-v' + (/not measured|—/.test(value) ? ' is-none' : ''), text: value })]); }
    return el('button', { cls: 'ag-acard ' + g.cls + (isEstimated(a) ? ' is-est' : '') + (S.selected === a.id ? ' is-selected' : ''), attrs: bvs('agent', a.id, a.name, { type: 'button' }), on: { click: function () { openAgent(a.id); } } }, [
      el('span', { cls: 'ag-acard-top' }, [disc(a), el('span', { cls: 'ag-acard-name', text: a.name }), statusBadge(a.status)]),
      el('span', { cls: 'ag-acard-grade' }, [gradeChip(a, 'est')]),
      el('span', { cls: 'ag-acard-grid' }, [
        m('Tokens', fmtTokens(a.tokens)), m('Tool calls', num(a.toolUses) === null ? 'not measured' : fmtInt(a.toolUses)),
        m('Working time', fmtDur(a.durationSec)), m('Script', num(a.scriptLines) === null ? '—' : fmtLines(a.scriptLines)),
        m('Run time', fmtRun(a.runSec)), m('Findings', num(a.findings) === null ? '—' : fmtInt(a.findings))
      ]),
      el('span', { cls: 'ag-acard-status', text: (STATUS[a.status] || {}).label || str(a.status) })
    ]);
  }

  // ------------------------------------------------------------------ table view
  var COLS = [
    { key: 'name', label: 'Helper', get: function (a) { return str(a.name).toLowerCase(); } },
    { key: 'phase', label: 'Round', get: function (a) { return phaseNo(a.phase); } },
    { key: 'difficulty', label: 'Difficulty', get: function (a) { return gradeOf(a).rank < 0 ? null : gradeOf(a).rank; } },
    { key: 'tokens', label: 'Tokens', num: true, get: function (a) { return num(a.tokens); } },
    { key: 'durationSec', label: 'Working time', num: true, get: function (a) { return num(a.durationSec); } },
    { key: 'scriptLines', label: 'Script lines', num: true, get: function (a) { return num(a.scriptLines); } },
    { key: 'runSec', label: 'Scan run time', num: true, get: function (a) { return num(a.runSec); } },
    { key: 'status', label: 'Status', get: function (a) { return (STATUS[a.status] || {}).label || str(a.status); } }
  ];
  function renderTable(host) {
    var col = COLS.filter(function (c) { return c.key === S.sort.key; })[0] || COLS[3];  // default: tokens
    var rows = S.data.agents.slice().sort(function (x, y) {
      var a = col.get(x), b = col.get(y);
      if (a === null || a === undefined || a === '') { return b === null || b === undefined || b === '' ? 0 : 1; }
      if (b === null || b === undefined || b === '') { return -1; }
      return (a < b ? -1 : a > b ? 1 : 0) * S.sort.dir;
    });
    var thead = el('thead', null, el('tr', null, COLS.map(function (c) {
      var on = c.key === S.sort.key;
      return el('th', { cls: c.num ? 'is-num' : '', attrs: { scope: 'col', 'aria-sort': on ? (S.sort.dir > 0 ? 'ascending' : 'descending') : 'none' } }, el('button', {
        cls: 'ag-sort' + (on ? ' is-on' : ''), attrs: { type: 'button' },
        on: { click: function () { S.sort = { key: c.key, dir: on ? -S.sort.dir : (c.num || c.key === 'difficulty' ? -1 : 1) }; renderBody(); } }
      }, [c.label, el('span', { cls: 'ag-sort-ar', text: on ? (S.sort.dir > 0 ? ' ▲' : ' ▼') : '', attrs: { 'aria-hidden': 'true' } })]));
    })));
    var tbody = el('tbody', null, rows.map(function (a) {
      function td(v, isNum) { return el('td', { cls: (isNum ? 'is-num' : '') + (/not measured|^—$/.test(v) ? ' is-none' : ''), text: v }); }
      return el('tr', { cls: S.selected === a.id ? 'is-selected' : '', attrs: bvs('agent', a.id, a.name, { tabindex: 0 }), on: {
        click: function () { openAgent(a.id); },
        keydown: function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openAgent(a.id); } }
      } }, [
        el('td', { cls: 'ag-td-name' }, el('span', { cls: 'ag-td-name-in' }, [disc(a), el('span', { text: a.name })])),
        el('td', { cls: 'ag-td-round' }, el('span', { cls: 'ag-td-round-in' }, [el('span', { cls: 'ag-round-n sm', text: String(phaseNo(a.phase)) }), el('span', { text: phaseLabel(a.phase) })])),
        el('td', null, gradeChip(a, 'est')),
        td(num(a.tokens) === null ? 'not measured' : fmtInt(a.tokens), true),
        td(fmtDur(a.durationSec), true),
        td(num(a.scriptLines) === null ? '—' : fmtInt(a.scriptLines), true),
        td(fmtRun(a.runSec), true),
        el('td', null, statusBadge(a.status, 'short'))
      ]);
    }));
    host.appendChild(el('section', { cls: 'ag-card ag-table-card', attrs: { 'data-bvs-section': 'agents-table' } }, [
      el('div', { cls: 'ag-table-scroll' }, el('table', { cls: 'ag-table' }, [el('caption', { cls: 'ag-sr', text: 'All AI helpers, sortable' }), thead, tbody]))
    ]));
  }

  // ------------------------------------------------------------------ charts
  function chartCard(title, sub, iconName, section, kids) {
    return el('section', { cls: 'ag-card ag-chart', attrs: { 'data-bvs-section': section } }, [
      el('div', { cls: 'ag-card-head' }, [el('span', { cls: 'ag-card-ico' }, icon(iconName)), el('div', null, [el('h2', { cls: 'ag-card-title', text: title }), sub ? el('p', { cls: 'ag-card-sub', text: sub }) : null])])
    ].concat(kids));
  }
  function segTip(node, a) { node.addEventListener('pointerenter', function () { tipShow(node, agentTip(a)); }); node.addEventListener('pointerleave', tipHide); node.addEventListener('focus', function () { tipShow(node, agentTip(a)); }); node.addEventListener('blur', tipHide); }

  function renderCharts(host) {
    var list = phases();
    var maxPhase = 0;
    list.forEach(function (p) { maxPhase = Math.max(maxPhase, num(p.raw.tokens) || 0); });
    var rows = list.map(function (p) {
      var raw = p.raw || {}, members = agentsIn(p.id).filter(function (a) { return num(a.tokens) !== null; }).sort(function (a, b) { return b.tokens - a.tokens; });
      var bar = el('div', { cls: 'ag-stack' });
      if (members.length && maxPhase) {
        bar.style.width = (100 * (raw.tokens || 0) / maxPhase).toFixed(2) + '%';
        members.forEach(function (a) {
          var seg = el('button', { cls: 'ag-seg ' + gradeOf(a).cls, attrs: bvs('agent', a.id, a.name, { type: 'button', 'aria-label': a.name + ': ' + fmtTokens(a.tokens, true) }), on: { click: function () { openAgent(a.id); } } });
          seg.style.flexGrow = String(a.tokens / 1000);
          segTip(seg, a);
          bar.appendChild(seg);
        });
      }
      var unmeasured = (raw.agents || 0) - members.length;
      return el('div', { cls: 'ag-hrow' }, [
        el('button', { cls: 'ag-hrow-label', attrs: bvs('section', 'phase-' + p.id, p.label, { type: 'button' }), on: { click: function () { openPhase(p.id); } } }, [el('span', { cls: 'ag-round-n sm', text: String(p.order) }), el('span', { text: p.label })]),
        el('div', { cls: 'ag-track' }, members.length ? bar : el('span', { cls: 'ag-track-none', text: 'not measured' })),
        el('div', { cls: 'ag-hrow-val' }, [el('strong', { text: members.length ? fmtTokens(raw.tokens) : '—' }),
          el('span', { text: members.length ? (unmeasured ? ' · ' + unmeasured + ' not measured' : ' · all measured') : ' · ' + (raw.agents || 0) + ' ' + plural(raw.agents || 0, 'helper') })])
      ]);
    });
    var tokCard = chartCard('Tokens per round', 'How much text the helpers of each round read and wrote. Each coloured piece is one helper; only measured helpers can be shown.', 'chart', 'agents-chart-tokens', [el('div', { cls: 'ag-hbars' }, rows)]);

    // script lengths
    var t = S.data.totals || {};
    var withLines = S.data.agents.filter(function (a) { return num(a.scriptLines); });
    var scan = withLines.filter(function (a) { return a.kind === 'collector' || a.kind === 'storage'; }).sort(function (a, b) { return b.scriptLines - a.scriptLines; });
    var other = withLines.filter(function (a) { return scan.indexOf(a) < 0; }).sort(function (a, b) { return b.scriptLines - a.scriptLines; });
    var maxL = 0;
    withLines.forEach(function (a) { maxL = Math.max(maxL, a.scriptLines); });
    function lineRow(a) {
      var b = el('span', { cls: 'ag-lbar ' + gradeOf(a).cls + (isEstimated(a) ? ' is-est' : '') });
      b.style.width = (100 * a.scriptLines / (maxL || 1)).toFixed(2) + '%';
      var row = el('button', { cls: 'ag-lrow', attrs: bvs('agent', a.id, a.name, { type: 'button', 'aria-label': a.name + ': ' + fmtLines(a.scriptLines) + ', ' + gradeOf(a).label }), on: { click: function () { openAgent(a.id); } } }, [
        el('span', { cls: 'ag-lrow-label' }, [disc(a), el('span', { text: a.name })]),
        el('span', { cls: 'ag-ltrack' }, [b]),
        el('span', { cls: 'ag-lrow-val', text: fmtInt(a.scriptLines) })
      ]);
      segTip(row, a);
      return row;
    }
    var typical = num(t.typicalScanScriptLines);
    var groups = [];
    if (scan.length) {
      var g1 = el('div', { cls: 'ag-lgroup' }, [el('h3', { cls: 'ag-lgroup-h', text: 'Scan scripts (they run on your PC)' })].concat(scan.map(lineRow)));
      if (typical && maxL) {
        var mk = el('span', { cls: 'ag-typical', attrs: { 'aria-hidden': 'true' } }, el('span', { cls: 'ag-typical-l', text: 'typical: ' + fmtInt(typical) }));
        mk.style.setProperty('--pos-n', (typical / maxL).toFixed(4));
        g1.appendChild(mk);
      }
      groups.push(g1);
    }
    if (other.length) { groups.push(el('div', { cls: 'ag-lgroup' }, [el('h3', { cls: 'ag-lgroup-h', text: 'Dashboard and report code' })].concat(other.map(lineRow)))); }
    var linesCard = chartCard('How long are the scripts?', typical ? 'Lines of code each helper wrote. A typical scan script has about ' + fmtInt(typical) + ' lines and runs in about ' + fmtRun(t.typicalRunSec) + '.' : 'Lines of code each helper wrote.', 'ruler', 'agents-chart-lines',
      groups.length ? groups : [el('p', { cls: 'ag-p ag-muted', text: 'No script lengths recorded.' })]);

    host.appendChild(el('div', { cls: 'ag-two' }, [tokCard, renderHeaviest()]));
    host.appendChild(linesCard);
  }

  function renderHeaviest() {
    var top = (S.data.heaviest || []).map(function (h) { return S.byId[h.id]; }).filter(Boolean);
    var maxT = top.length ? num(top[0].tokens) || 1 : 1;
    return chartCard('Heaviest jobs', 'The helpers that used the most tokens (measured only).', 'chart', 'agents-heaviest', [
      top.length ? el('ol', { cls: 'ag-heavy' }, top.map(function (a, i) {
        var b = el('span', { cls: 'ag-heavy-bar ' + gradeOf(a).cls });
        b.style.width = (100 * a.tokens / maxT).toFixed(2) + '%';
        return el('li', null, el('button', { cls: 'ag-heavy-row', attrs: bvs('agent', a.id, a.name, { type: 'button' }), on: { click: function () { openAgent(a.id); } } }, [
          el('span', { cls: 'ag-heavy-rank', text: String(i + 1) }), disc(a),
          el('span', { cls: 'ag-heavy-main' }, [el('span', { cls: 'ag-heavy-name', text: a.name }), el('span', { cls: 'ag-heavy-track' }, b)]),
          el('span', { cls: 'ag-heavy-val' }, [el('strong', { text: fmtTokens(a.tokens) }), el('span', { text: fmtDur(a.durationSec) })])
        ]));
      })) : el('p', { cls: 'ag-p ag-muted', text: 'No helper usage was measured.' })
    ]);
  }

  // ------------------------------------------------------------------ live section
  function isHttp() { return (location.protocol === 'http:' || location.protocol === 'https:') && typeof fetch === 'function'; }
  function getToken(force) {
    var L = S.live;
    if (!force && L.token && Date.now() - L.tokenAt < 60000) { return Promise.resolve(L.token); }
    return fetch('/api/status', { cache: 'no-store', credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : {}; }).then(function (j) {
      L.token = j && typeof j.token === 'string' ? j.token : null; L.tokenAt = Date.now(); return L.token;
    }, function () { return null; });
  }
  function fetchLive(retried) {
    var A = app();
    if (typeof A.fetchAgentsLive === 'function') { return Promise.resolve(A.fetchAgentsLive()); }  // shell or test page may provide it
    return getToken(retried).then(function (token) {
      var h = { Accept: 'application/json' };
      if (token) { h['X-BVS-Token'] = token; }
      return fetch('/api/agents/live', { cache: 'no-store', credentials: 'same-origin', headers: h });
    }).then(function (r) {
      if ((r.status === 401 || r.status === 403) && !retried) { return fetchLive(true); }
      if (r.status === 404 || r.status === 405) { var e = new Error('missing'); e.code = 'missing'; throw e; }
      if (!r.ok) { var e2 = new Error('HTTP ' + r.status); e2.code = 'http'; throw e2; }
      return r.json();
    });
  }
  function liveItems(j) {
    var arr = Array.isArray(j) ? j : j && typeof j === 'object' ? (j.items || j.agents || j.tools || j.processes || j.running || []) : [];
    return Array.isArray(arr) ? arr.filter(function (x) { return x && typeof x === 'object'; }).slice(0, 100) : [];
  }
  function poll() {
    var L = S.live;
    if (!S.root || L.inflight) { return; }
    if (document.hidden) { return; }
    if (!isHttp() && typeof app().fetchAgentsLive !== 'function') { L.state = 'file'; renderLiveBody(); return; }
    L.inflight = true;
    fetchLive(false).then(function (j) {
      L.items = liveItems(j); L.state = 'ok'; L.at = new Date(); L.error = null;
    }, function (err) {
      L.state = err && err.code === 'missing' ? 'missing' : 'error'; L.error = err && err.message; L.at = new Date();
    }).then(function () { L.inflight = false; renderLiveBody(); });
  }
  function startLive() {
    stopLive();
    poll();
    S.live.timer = setInterval(poll, POLL_MS);
    S.live.onVis = function () { if (!document.hidden) { poll(); } };
    document.addEventListener('visibilitychange', S.live.onVis);
  }
  function stopLive() {
    if (S.live.timer) { clearInterval(S.live.timer); S.live.timer = null; }
    if (S.live.onVis) { document.removeEventListener('visibilitychange', S.live.onVis); S.live.onVis = null; }
  }
  function sinceText(v) {
    var d = U.toDate(v);
    if (!d) { return ''; }
    var mins = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
    var dur = mins < 1 ? 'just started' : mins < 60 ? mins + ' min' : Math.floor(mins / 60) + ' h' + (mins % 60 ? ' ' + (mins % 60) + ' min' : '');
    var hh = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
    var sameDay = new Date().toDateString() === d.toDateString();
    return 'since ' + (sameDay ? hh : U.fmtDate(d, true)) + ' (' + dur + ')';
  }
  function renderLive(host) {
    S.live.body = el('div', { cls: 'ag-live-body', attrs: { 'aria-live': 'polite' } });
    host.appendChild(el('section', { cls: 'ag-card ag-live', attrs: { 'data-bvs-section': 'agents-live' } }, [
      el('div', { cls: 'ag-card-head' }, [el('span', { cls: 'ag-card-ico live' }, icon('live')), el('div', null, [
        el('h2', { cls: 'ag-card-title', text: 'AI tools running on this PC right now' }),
        el('p', { cls: 'ag-card-sub', text: 'Claude, Codex, Cursor and other AI coding tools that are open at the moment. Read-only: the dashboard only looks, it never stops anything.' })])]),
      S.live.body
    ]));
    renderLiveBody();
  }
  function renderLiveBody() {
    var L = S.live, b = L.body;
    if (!b) { return; }
    U.clear(b);
    if (L.state === 'file') {
      b.appendChild(el('div', { cls: 'ag-note' }, [icon('info'), el('div', null, [el('strong', { text: 'Live view needs the dashboard server. ' }),
        'You opened the dashboard as a file. Start it with start-dashboard.cmd (it runs at http://127.0.0.1:8777) to see which AI tools are running right now.'])]));
      return;
    }
    if (L.state === 'missing') {
      b.appendChild(el('div', { cls: 'ag-note' }, [icon('info'), el('div', null, [el('strong', { text: 'This dashboard server cannot list live AI tools yet. ' }),
        'Restart the dashboard after updating it, then this list fills in by itself.'])]));
      return;
    }
    if (L.state === 'idle') { b.appendChild(el('p', { cls: 'ag-p ag-muted', text: 'Checking…' })); return; }
    if (L.state === 'error') {
      b.appendChild(el('div', { cls: 'ag-note warn' }, [icon('info'), el('div', null, [el('strong', { text: 'Could not ask the dashboard server just now. ' }), 'Trying again in 10 seconds.'])]));
    } else if (!L.items.length) {
      b.appendChild(el('p', { cls: 'ag-live-empty' }, [statusIconOnly('check'), ' No AI coding tools are running right now.']));
    } else {
      b.appendChild(el('ul', { cls: 'ag-live-list' }, L.items.map(function (x, i) {
        var name = str(x.name || x.tool || x.process || 'AI tool'), kind = str(x.kind || x.type || '');
        var cmd = str(x.command || x.cmd || x.shortCommand || x.commandMasked || '');
        var pid = num(x.pid);
        var item = el('li', null, el('button', { cls: 'ag-live-item', attrs: bvs('agent', 'live-' + (pid !== null ? pid : i), name + (kind ? ' (' + kind + ')' : ''), { type: 'button' }),
          on: { click: function () { openLive(x); } } }, [
          el('span', { cls: 'ag-live-dot', attrs: { 'aria-hidden': 'true' } }),
          el('span', { cls: 'ag-live-main' }, [el('span', { cls: 'ag-live-name', text: name }),
            el('span', { cls: 'ag-live-meta', text: [LIVE_KIND[kind.toLowerCase()] || kind, sinceText(x.started || x.startedAt || x.since)].filter(Boolean).join(' · ') }),
            cmd ? el('code', { cls: 'ag-live-cmd', text: cmd.length > 120 ? cmd.slice(0, 119) + '…' : cmd }) : null]),
          pid !== null ? el('span', { cls: 'ag-live-pid', text: 'process ' + pid }) : null
        ]));
        return item;
      })));
    }
    if (L.at) {
      b.appendChild(el('p', { cls: 'ag-live-foot', text: 'Last checked ' + ('0' + L.at.getHours()).slice(-2) + ':' + ('0' + L.at.getMinutes()).slice(-2) + ':' + ('0' + L.at.getSeconds()).slice(-2) + ' · checks again every 10 seconds while this page is open.' }));
    }
  }
  function statusIconOnly(name) { return el('span', { cls: 'ag-status st-done' }, icon(name)); }
  function openLive(x) {
    var name = str(x.name || x.tool || 'AI tool');
    openPanel({
      kind: 'custom', kicker: 'Running now', id: 'live-' + (num(x.pid) !== null ? x.pid : name), title: name, subtitle: str(x.kind || x.type || ''),
      render: function (body) {
        panelWrap(body, function (w) {
          w.appendChild(el('dl', { cls: 'ag-facts' }, [
            fact('Running', sinceText(x.started || x.startedAt || x.since) || 'start time unknown', null),
            num(x.pid) !== null ? fact('Process number', String(x.pid), 'Windows process ID') : null,
            fact('Kind', LIVE_KIND[str(x.kind || '').toLowerCase()] || str(x.kind || 'unknown'), null)
          ]));
          var cmd = str(x.command || x.cmd || x.shortCommand || x.commandMasked || '');
          if (cmd) { w.appendChild(el('h3', { cls: 'ag-ph', text: 'Command (shortened, secrets hidden)' })); w.appendChild(el('code', { cls: 'ag-live-cmd block', text: cmd })); }
          w.appendChild(el('p', { cls: 'ag-p ag-muted', text: 'The dashboard only lists these tools. It cannot stop, start or change them.' }));
        });
      }
    });
  }

  // ------------------------------------------------------------------ notes, empty state
  function renderNotes(host) {
    var d = S.data, items = [];
    if (d.rules) { ['measured', 'estimated', 'unknown'].forEach(function (k) { if (d.rules[k]) { items.push(d.rules[k]); } }); }
    (d.notes || []).forEach(function (n) { items.push(n); });
    items.push('Script lines are the current length of the files each helper wrote. Files that were rewritten later, or that a helper only gave input to, are not counted.');
    items.push('Scan run time comes from each scan module\'s own start and finish time.');
    host.appendChild(el('details', { cls: 'ag-card ag-notes', attrs: { 'data-bvs-section': 'agents-notes' } }, [
      el('summary', { text: 'Where these numbers come from' }),
      el('ul', { cls: 'ag-plain-list' }, items.map(function (t) { return el('li', { text: t }); })),
      el('p', { cls: 'ag-muted ag-p', text: 'Built ' + U.fmtDate(d.generatedAt, true) + ' from ' + str((d.source && d.source.ledger) || 'data/agents-ledger.json') + '.' })
    ]));
  }
  function renderEmpty(root) {
    var scan = typeof window.BVS_LATEST === 'string' && /^[A-Za-z0-9_-]+$/.test(window.BVS_LATEST) ? window.BVS_LATEST : '<scan folder>';
    var cmd1 = 'python -I -B core\\build_agents.py --scan data\\' + scan;
    var cmd2 = 'python -I -B core\\build_datajs.py --scan data\\' + scan;
    root.appendChild(el('section', { cls: 'ag-card ag-empty', attrs: { 'data-bvs-section': 'agents-empty' } }, [
      el('h2', { cls: 'ag-card-title', text: 'The agent map has not been built for this scan yet' }),
      el('p', { cls: 'ag-p', text: 'It needs a small data file made from the record of AI helpers (data\\agents-ledger.json). Ask Claude to build it, or run these two commands in the project folder, then reload this page:' }),
      el('pre', { cls: 'ag-code' }, [el('code', { text: cmd1 }), el('code', { text: cmd2 })])
    ]));
  }

  // ------------------------------------------------------------------ mount / unmount
  function renderBody() {
    if (!S.body) { return; }
    tipHide();
    U.clear(S.body);
    renderToggle(S.body);
    if (S.mode === 'table') { renderTable(S.body); } else if (S.mode === 'cards') { renderCards(S.body); } else { renderMap(S.body); }
  }

  function mount(root, params) {
    unmount();
    S.root = root;
    root.classList.add('agents-view');
    S.tip = el('div', { cls: 'agents-view ag-tip', attrs: { role: 'tooltip' }, hidden: true });
    document.body.appendChild(S.tip);
    S.data = getData();
    var q = (params && params.query) || {};
    if (!S.data) {
      root.appendChild(el('header', { cls: 'ag-head' }, [el('div', { cls: 'ag-head-icon' }, icon('agents')), el('div', { cls: 'ag-head-text' }, [el('h1', { text: 'Agent map' }),
        el('p', { cls: 'ag-intro', text: 'Many AI helpers worked on your scan. This page shows each one and how heavy its job was.' })])]));
      renderEmpty(root);
      renderLive(root);
      startLive();
      return;
    }
    index(S.data);
    var saved = storeGet(MODE_KEY);
    S.mode = MODES.indexOf(q.view) >= 0 ? q.view : MODES.indexOf(saved) >= 0 ? saved : 'map';
    renderHead(root);
    renderTiles(root);
    renderLegend(root);
    S.body = el('div', { cls: 'ag-body' });
    root.appendChild(S.body);
    renderBody();
    renderCharts(root);
    renderLive(root);
    renderNotes(root);
    startLive();
    if (typeof q.agent === 'string' && S.byId[q.agent]) { setTimeout(function () { openAgent(q.agent); }, 0); }
  }

  function unmount() {
    stopLive();
    tipHide();
    if (S.tip && S.tip.parentNode) { S.tip.parentNode.removeChild(S.tip); }
    S.tip = null; S.root = null; S.body = null; S.live.body = null; S.live.state = 'idle'; S.live.items = []; S.live.at = null;
  }

  var VIEW = { title: 'Agent map', group: 'tools', icon: ICON.agents, accent: '#7c4ddb', mount: mount, unmount: unmount };
  window.BVSUI.agentsView = VIEW;
  function register() {
    var A = window.BVSApp;
    if (A && typeof A.registerView === 'function') { A.registerView('agents', VIEW); return true; }
    return false;
  }
  if (!register()) { document.addEventListener('DOMContentLoaded', register); }
})();
