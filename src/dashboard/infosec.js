/* baby-virus-scanner dashboard: INFOSEC, the yellow security explainer (agent UI-C, reworked by UI-G).
 *
 *  - BVSApp.askImpl(question, context, onEvent, signal): POST /api/ask (token from /api/status) asking
 *    for a streamed answer (NDJSON): onEvent gets status / delta / reset events while Claude writes,
 *    signal (AbortController) stops it. Without a server (file://), with AI switched off, or on an
 *    error it falls back to the offline explainer (glossary.js + the curated guide + the scan's fields).
 *  - Chats are saved on this PC: POST /api/chats (data/infosec/chats/<id>.json, src/core/chat_store.py),
 *    with localStorage as the fallback when the server cannot store them. The INFOSEC page lists the
 *    saved chats and every question asked; any of them reopens.
 *  - BVSApp.openInfosec({prefill, context, send, preset, via, where, transcript}): the INFOSEC copilot,
 *    a panel docked beside the current page (on wide screens the page makes room for it) that stays
 *    open while you switch tabs; where: 'page' opens the full page, 'auto' (scanner) uses the copilot
 *    when it is open and the full page otherwise.
 *  - BVSApp.registerView('infosec', ...): the full-page INFOSEC view (#/infosec).
 *
 * SAFETY: every answer is rendered by a small markdown-lite renderer that only creates elements
 * and text nodes (no innerHTML). Links are only created for internal dashboard routes (#/...). */
(function () {
  'use strict';

  var U = window.BVSUI && window.BVSUI.util;
  if (!U) { return; }
  var el = U.el, clear = U.clear;
  var App = window.BVSApp = window.BVSApp || {};

  var ACCENT = '#F5C518';
  var OLD_SESSION_KEY = 'bvs.infosec.chat.v1';   // sessionStorage, from before chats were saved
  var CURRENT_KEY = 'bvs.infosec.current.v2';    // localStorage: the open chat (instant restore)
  var LOCAL_CHATS_KEY = 'bvs.infosec.chats.v2';  // localStorage: chats the server could not store
  var DOCK_KEY = 'bvs.infosec.dock';
  var DOCK_W_KEY = 'bvs.infosec.dockw';
  var CHAT_ID_RE = /^c[0-9a-z]{8,40}$/;
  var PRIVACY = 'With your OK, answers come from Claude via your Claude Code login: your question and the text you ask about are sent, with personal names hidden. Chats are saved only on this PC.';
  var OFFLINE_HINT = 'Live INFOSEC answers need the dashboard opened via start-dashboard.';
  var MAX_MESSAGES = 200;
  var AI_BADGE = 'AI-generated (Claude) — double-check important steps';
  var ENTITY_TYPES = ['finding', 'storageItem', 'question', 'fix', 'file', 'tile', 'section'];
  var ROUTE_RE = /^#\/[A-Za-z][A-Za-z0-9\/_.%-]*(\?[A-Za-z0-9=&%_.,+-]*)?$/;

  var PRESETS = [
    { id: 'eli5', label: "Explain my result like I'm in high school", icon: 'spark' },
    { id: 'fix-first', label: 'What should I fix first? Walk me through it', icon: 'wrench' },
    { id: 'connect-dots', label: 'Connect the dots: what does all this mean together?', icon: 'dots' },
    { id: 'bsod', label: 'Why did my PC blue-screen?', icon: 'bolt' },
    { id: 'danger', label: 'Is anything here dangerous right now?', icon: 'alert' },
    { id: 'how-to-use', label: 'How do I use this dashboard?', icon: 'compass' }
  ];

  // ------------------------------------------------------------------------------ icons
  var ICONS = {
    shield: ['M12 2.5l7.5 3v5.7c0 4.9-3.2 9.1-7.5 10.3-4.3-1.2-7.5-5.4-7.5-10.3V5.5z', 'M8.6 12.2l2.4 2.4 4.4-4.6'],
    send: ['M4 12l16-8-6 16-2.5-6.5z', 'M11.5 13.5L20 4'],
    copy: ['M9 9h10v11H9z', 'M5 15V4h10'],
    close: ['M6 6l12 12', 'M18 6L6 18'],
    expand: ['M14 4h6v6', 'M20 4l-7 7', 'M10 20H4v-6', 'M4 20l7-7'],
    trash: ['M5 7h14', 'M9 7V4h6v3', 'M7 7l1 13h8l1-13'],
    spark: ['M12 3v4', 'M12 17v4', 'M3 12h4', 'M17 12h4', 'M6 6l2.5 2.5', 'M15.5 15.5L18 18', 'M18 6l-2.5 2.5', 'M8.5 15.5L6 18'],
    wrench: ['M14.5 5.5a4 4 0 00-5 5L4 16l4 4 5.5-5.5a4 4 0 005-5l-2.5 2.5-3-3z'],
    dots: ['M6 6h.01', 'M18 7h.01', 'M12 18h.01', 'M6 6l12 1', 'M18 7l-6 11', 'M12 18L6 6'],
    bolt: ['M13 2L5 14h6l-1 8 8-12h-6z'],
    alert: ['M12 3l9.5 17h-19z', 'M12 10v4', 'M12 17h.01'],
    compass: ['M12 3a9 9 0 100 18 9 9 0 000-18z', 'M15.5 8.5l-2 5-5 2 2-5z'],
    scan: ['M4 8V4h4', 'M16 4h4v4', 'M20 16v4h-4', 'M8 20H4v-4', 'M3 12h18'],
    book: ['M5 4h9a3 3 0 013 3v13H8a3 3 0 01-3-3z', 'M5 17a3 3 0 013-3h9'],
    stop: ['M7 7h10v10H7z'],
    history: ['M3.5 12a8.5 8.5 0 108.5-8.5A8.6 8.6 0 005 7', 'M4 3v4h4', 'M12 8v4l3 2'],
    plus: ['M12 5v14', 'M5 12h14'],
    chat: ['M4 5h16v11H9l-5 4z'],
    retry: ['M4 12a8 8 0 0113.7-5.6L20 9', 'M20 4v5h-5', 'M20 12a8 8 0 01-13.7 5.6L4 15', 'M4 20v-5h5'],
    question: ['M12 21a9 9 0 100-18 9 9 0 000 18z', 'M9.5 9.5a2.5 2.5 0 114 2c-.9.6-1.5 1.1-1.5 2.2', 'M12 17h.01'],
    dock: ['M3 5h18v14H3z', 'M15 5v14'],
    float: ['M3 5h18v14H3z', 'M11 11h7v5h-7z']
  };
  var SVGNS = 'http://www.w3.org/2000/svg';
  function icon(name, size) {
    var svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', String(size || 18));
    svg.setAttribute('height', String(size || 18));
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    (ICONS[name] || ICONS.shield).forEach(function (d) {
      var p = document.createElementNS(SVGNS, 'path');
      p.setAttribute('d', d);
      svg.appendChild(p);
    });
    return svg;
  }

  // ------------------------------------------------------------------------------ helpers
  function clip(s, n) { s = s === null || s === undefined ? '' : String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function get(name) { try { return window.BVS && window.BVS.get ? window.BVS.get(name) : undefined; } catch (e) { return undefined; } }
  function items(name) { var d = get(name); return d && Array.isArray(d.items) ? d.items : []; }
  function guide() { var g = get('guide'); return g && typeof g === 'object' ? g : null; }
  function summary() { var s = get('summary'); return s && typeof s === 'object' ? s : null; }
  function currentRoute() { return (location.hash && location.hash.length > 1 ? location.hash : '#/overview').slice(0, 200); }
  function hhmm(ts) { var d = new Date(ts || Date.now()); return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2); }

  function findingById(id) {
    if (typeof App.findingById === 'function') { try { var f = App.findingById(id); if (f) { return f; } } catch (e) { /* ignore */ } }
    var list = items('findings');
    for (var i = 0; i < list.length; i++) { if (list[i] && list[i].id === id) { return list[i]; } }
    return null;
  }
  function itemById(id) {
    if (typeof App.itemById === 'function') { try { var it = App.itemById(id); if (it) { return it; } } catch (e) { /* ignore */ } }
    var sets = ['storage', 'duplicates', 'programs', 'startup', 'registry', 'health'];
    for (var s = 0; s < sets.length; s++) {
      var list = items(sets[s]);
      for (var i = 0; i < list.length; i++) { if (list[i] && list[i].id === id) { return list[i]; } }
    }
    return null;
  }

  var SEV = {
    critical: ['Act now', 'likely an active threat'], high: ['Important', 'fix soon'],
    medium: ['Worth fixing', 'a weakness'], low: ['Minor', 'small tidy-up'], info: ['FYI', 'for your information']
  };
  var CLS = { compromise: 'Sign of attack', suspicious: 'Needs a look', hardening: 'Security setting to tighten', hygiene: 'Clean-up', info: 'Information' };
  var VER = { refuted: 'Checked: false alarm', confirmed: 'Checked: real', inconclusive: 'Checked: unclear', unverified: 'Not double-checked' };
  var SAFE = { safe: 'Safe to remove', safe_after_check: 'Safe after a quick check', review: 'Look before deleting', use_tool: "Clean with the app's own tool", do_not_touch: 'System: leave alone' };
  function sevWords(sev) {
    if (App.friendly && typeof App.friendly.severity === 'function') {
      try { var f = App.friendly.severity(sev); if (f && f.label) { return [f.label, f.plain || '']; } } catch (e) { /* ignore */ }
    }
    return SEV[sev] || SEV.info;
  }

  function copyToClipboard(text) {
    return U.copyText(text).then(function (ok) {
      if (ok) { return true; }
      try {
        var ta = el('textarea', { attrs: { readonly: true, 'aria-hidden': 'true' } });
        ta.value = text;
        ta.className = 'ix-offscreen';
        document.body.appendChild(ta);
        ta.select();
        var done = document.execCommand && document.execCommand('copy');
        document.body.removeChild(ta);
        return !!done;
      } catch (e) { return false; }
    });
  }

  // ------------------------------------------------------------------------------ markdown-lite
  var INLINE_RE = /(`+)([^`]+?)\1|\*\*([^*]+?)\*\*|\[([^\]]{1,200})\]\(([^)\s]{1,300})\)|(#\/[A-Za-z][A-Za-z0-9\/_.%-]*(?:\?[A-Za-z0-9=&%_.,+-]*)?)|\*([^*\s][^*]{0,300}?)\*/g;

  function routeLink(route, label) {
    var a = document.createElement('a');
    a.setAttribute('href', route);
    a.className = 'ix-route';
    a.appendChild(U.text(label || route));
    a.addEventListener('click', function (ev) {
      if (typeof App.navigate === 'function') { ev.preventDefault(); App.navigate(route); }
    });
    return a;
  }

  function inline(parent, s, depth) {
    s = String(s);
    depth = depth || 0;
    var last = 0, m;
    INLINE_RE.lastIndex = 0;
    var re = new RegExp(INLINE_RE.source, 'g');
    while ((m = re.exec(s)) !== null) {
      if (m.index > last) { parent.appendChild(U.text(s.slice(last, m.index))); }
      var trailing = '';
      if (m[2] !== undefined) {
        parent.appendChild(el('code', { text: m[2] }));
      } else if (m[3] !== undefined) {
        var strong = el('strong');
        if (depth < 2) { inline(strong, m[3], depth + 1); } else { strong.appendChild(U.text(m[3])); }
        parent.appendChild(strong);
      } else if (m[4] !== undefined) {
        if (ROUTE_RE.test(m[5])) { parent.appendChild(routeLink(m[5], m[4])); }
        else { parent.appendChild(U.text(m[4] + ' (' + m[5] + ')')); }
      } else if (m[6] !== undefined) {
        var route = m[6];
        while (/[.,;:)]$/.test(route)) { trailing = route.slice(-1) + trailing; route = route.slice(0, -1); }
        if (ROUTE_RE.test(route) && route.length > 2) { parent.appendChild(routeLink(route)); }
        else { parent.appendChild(U.text(route)); }
        if (trailing) { parent.appendChild(U.text(trailing)); }
      } else if (m[7] !== undefined) {
        parent.appendChild(el('em', { text: m[7] }));
      }
      last = re.lastIndex;
    }
    if (last < s.length) { parent.appendChild(U.text(s.slice(last))); }
    return parent;
  }

  var RE_HEAD = /^\s{0,3}(#{1,6})\s+(.*)$/;
  var RE_UL = /^(\s*)[-*•+]\s+(.*)$/;
  var RE_OL = /^(\s*)(\d{1,3})[.)]\s+(.*)$/;
  var RE_QUOTE = /^\s*>\s?(.*)$/;
  var RE_HR = /^\s*([-*_])(\s*\1){2,}\s*$/;
  var RE_FENCE = /^\s*```/;

  function renderMarkdown(text) {
    var root = el('div', { cls: 'ix-md' });
    var lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    var i = 0, para = [];

    function flushPara() {
      if (!para.length) { return; }
      var isTable = para.every(function (l) { return /^\s*\|/.test(l); });
      if (isTable) {
        root.appendChild(el('div', { cls: 'ix-pre', text: para.join('\n') }));
      } else {
        var p = el('p');
        para.forEach(function (l, idx) { if (idx) { p.appendChild(document.createElement('br')); } inline(p, l.trim()); });
        root.appendChild(p);
      }
      para = [];
    }

    while (i < lines.length) {
      var line = lines[i];
      if (RE_FENCE.test(line)) {
        flushPara();
        var code = [];
        i++;
        while (i < lines.length && !RE_FENCE.test(lines[i])) { code.push(lines[i]); i++; }
        i++;
        root.appendChild(el('pre', { cls: 'ix-code' }, el('code', { text: code.join('\n') })));
        continue;
      }
      if (!line.trim()) { flushPara(); i++; continue; }
      var h = RE_HEAD.exec(line);
      if (h) {
        flushPara();
        var lvl = h[1].length <= 2 ? 'h3' : h[1].length === 3 ? 'h4' : 'h5';
        root.appendChild(inline(el(lvl, { cls: 'ix-h' }), h[2].replace(/#+\s*$/, '').trim()));
        i++;
        continue;
      }
      if (RE_HR.test(line)) { flushPara(); root.appendChild(el('hr')); i++; continue; }
      if (RE_UL.test(line) || RE_OL.test(line)) {
        flushPara();
        var ordered = !RE_UL.test(line);
        var list = el(ordered ? 'ol' : 'ul');
        if (ordered) { var start = parseInt(RE_OL.exec(line)[2], 10); if (start > 1) { list.start = start; } }
        var li = null;
        while (i < lines.length) {
          var l = lines[i];
          var mu = RE_UL.exec(l), mo = RE_OL.exec(l);
          var match = ordered ? mo : mu;
          if (match) {
            li = el('li');
            inline(li, ordered ? match[3] : match[2]);
            list.appendChild(li);
            i++;
          } else if ((mu || mo) && li) {
            // a nested item of the other kind: render it inside the current item as a sub-line
            var sub = el('div', { cls: 'ix-sub' });
            inline(sub, (mu ? '• ' + mu[2] : mo[2] + '. ' + mo[3]));
            li.appendChild(sub);
            i++;
          } else if (l.trim() && /^\s{2,}\S/.test(l) && li) {
            li.appendChild(U.text(' '));
            inline(li, l.trim());
            i++;
          } else {
            break;
          }
        }
        root.appendChild(list);
        continue;
      }
      var q = RE_QUOTE.exec(line);
      if (q) {
        flushPara();
        var bq = el('blockquote');
        while (i < lines.length && RE_QUOTE.test(lines[i])) {
          var qt = RE_QUOTE.exec(lines[i])[1];
          if (bq.childNodes.length) { bq.appendChild(document.createElement('br')); }
          inline(bq, qt);
          i++;
        }
        root.appendChild(bq);
        continue;
      }
      para.push(line);
      i++;
    }
    flushPara();
    return root;
  }

  // ------------------------------------------------------------------------------ glossary
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  var glossaryIndex = null;
  function buildGlossaryIndex() {
    var list = Array.isArray(window.BVS_GLOSSARY) ? window.BVS_GLOSSARY.slice() : [];
    var g = guide();
    if (g && Array.isArray(g.glossaryExtra)) {
      g.glossaryExtra.forEach(function (x) { if (x && x.term && x.plain) { list.push({ term: String(x.term), aliases: [], plain: String(x.plain) }); } });
    }
    glossaryIndex = list.filter(function (e) { return e && e.term && e.plain; }).map(function (e) {
      var names = [e.term].concat(Array.isArray(e.aliases) ? e.aliases : []).filter(Boolean);
      var res = names.map(function (n) {
        n = String(n);
        var short = n.length < 3;
        return new RegExp('(^|[^A-Za-z0-9_])' + escapeRe(n) + '(?=$|[^A-Za-z0-9_])', short ? '' : 'i');
      });
      return { entry: e, res: res };
    });
    return glossaryIndex;
  }
  function glossaryLookup(text, limit) {
    var idx = glossaryIndex || buildGlossaryIndex();
    var hits = [];
    var s = String(text || '');
    if (!s) { return hits; }
    idx.forEach(function (g) {
      var best = -1;
      g.res.forEach(function (re) { var m = re.exec(s); if (m && (best < 0 || m.index < best)) { best = m.index; } });
      if (best >= 0) { hits.push({ entry: g.entry, at: best }); }
    });
    hits.sort(function (a, b) { return a.at - b.at; });
    return hits.slice(0, limit || 6).map(function (h) { return h.entry; });
  }

  // ------------------------------------------------------------------------------ offline explainer
  var TOUR = [
    '## How to use this dashboard',
    '1. **Start at the overview** (#/overview): the big ring shows the verdict, with the most important things to know below it.',
    '2. **Click anything.** Every number, tile and label opens a list or a side panel with the details in plain English.',
    '3. **Fix things in order** on #/fixes: each fix has a short walkthrough.',
    '4. **Answer the questions** on #/questions: only you know if you installed something.',
    '5. **Free up space** on #/storage: the map shows what fills your disk and how safe each item is to remove.',
    '6. **Ask INFOSEC** about anything: use the Ask INFOSEC button in a side panel, or press **S** (the glowing scan button) and drag over any part of the screen.',
    '7. **Deleting is never automatic.** Add items to the Basket (#/basket), paste the DELETE REQUEST into Claude Code and type "I confirm".'
  ].join('\n');

  function entityExplain(ent) {
    var out = [];
    if (!ent || !ent.type) { return out; }
    if (ent.type === 'finding') {
      var f = findingById(ent.id);
      if (!f) { return out; }
      var sw = sevWords(f.severity);
      var ver = (f.verification && f.verification.result) || 'unverified';
      out.push('## ' + clip(f.title || f.id, 200));
      out.push('- **How serious:** ' + sw[0] + (sw[1] ? ' (' + sw[1] + ')' : ''));
      out.push('- **Kind:** ' + (CLS[f['class']] || f['class'] || 'unknown'));
      out.push('- **Double-checked:** ' + (VER[ver] || ver));
      if (f.recommendation) { out.push('', '**What to do:** ' + clip(f.recommendation, 900)); }
      if (f.fp_notes) { out.push('', '**Could it be harmless?** ' + clip(f.fp_notes, 600)); }
      if (f.verification && f.verification.notes) { out.push('', '**Checker\'s note:** ' + clip(f.verification.notes, 300)); }
      out.push('', 'Details: #/finding/' + f.id);
    } else if (ent.type === 'storageItem') {
      var it = itemById(ent.id);
      if (!it) { return out; }
      out.push('## ' + clip(it.label || it.path || it.id, 200));
      if (it.purpose) { out.push(clip(it.purpose, 600)); }
      if (it.bytes) { out.push('- **Size:** ' + U.fmtBytes(it.bytes)); }
      if (it.safety) { out.push('- **Safe to delete?** ' + (SAFE[it.safety] || it.safety)); }
      if (it.how) { out.push('- **How:** ' + clip(it.how, 500)); }
    } else if (ent.type === 'question' || ent.type === 'fix') {
      var g = guide();
      var pool = g ? (ent.type === 'question' ? g.questions : g.topFixes) : null;
      var found = Array.isArray(pool) ? pool.filter(function (x) { return x && x.id === ent.id; })[0] : null;
      if (found) {
        out.push('## ' + clip(found.title || found.question, 200));
        if (found.plain) { out.push(clip(found.plain, 800)); }
        if (found.why) { out.push('', '**Why it matters:** ' + clip(found.why, 500)); }
        if (found.whyItMatters) { out.push('', '**Why it matters:** ' + clip(found.whyItMatters, 500)); }
        if (Array.isArray(found.steps) && found.steps.length) {
          out.push('', '**Steps:**');
          found.steps.slice(0, 8).forEach(function (st, n) { out.push((n + 1) + '. ' + clip(st, 400)); });
        }
        if (found.ifYes) { out.push('', '**If yes:** ' + clip(found.ifYes, 400)); }
        if (found.ifNo) { out.push('**If no:** ' + clip(found.ifNo, 400)); }
      }
    }
    return out;
  }

  function verdictExplain(withReasons) {
    var out = [];
    var g = guide();
    var s = summary();
    if (g && g.verdictPlain) {
      if (g.headline) { out.push('## ' + clip(g.headline, 200)); }
      if (g.verdictPlain.summary) { out.push(clip(g.verdictPlain.summary, 800)); }
      if (g.verdictPlain.whatItMeans) { out.push('', '**What it means:** ' + clip(g.verdictPlain.whatItMeans, 800)); }
      if (withReasons && Array.isArray(g.verdictPlain.whyNotCompromised) && g.verdictPlain.whyNotCompromised.length) {
        out.push('', '**Why this is not an active attack:**');
        g.verdictPlain.whyNotCompromised.slice(0, 5).forEach(function (r) { out.push('- ' + clip(r, 300)); });
      }
    } else if (s) {
      var v = (App.friendly && typeof App.friendly.verdict === 'function') ? (function () { try { return App.friendly.verdict(s.verdict); } catch (e) { return null; } })() : null;
      out.push('## Your result: ' + ((v && v.label) || String(s.verdict || 'unknown').replace(/_/g, ' ').toLowerCase()));
      if (s.verdictMeaning) { out.push(clip(s.verdictMeaning, 800)); }
      if (withReasons && Array.isArray(s.verdictReasons)) { s.verdictReasons.slice(0, 3).forEach(function (r) { out.push('- ' + clip(r, 300)); }); }
    }
    return out;
  }

  function fixesExplain() {
    var out = [];
    var g = guide();
    var fixes = g && Array.isArray(g.topFixes) ? g.topFixes.slice() : [];
    if (fixes.length) {
      fixes.sort(function (a, b) { return (a.priority || 99) - (b.priority || 99); });
      out.push('## Fix these first');
      fixes.slice(0, 3).forEach(function (fx, n) {
        out.push((n + 1) + '. **' + clip(fx.title, 160) + '**' + (fx.effort ? ' (' + fx.effort + ')' : '') + ': ' + clip(fx.plain, 300)
          + (fx.link && ROUTE_RE.test(fx.link) ? ' ' + fx.link : ''));
      });
      out.push('', 'Every fix has a step-by-step walkthrough on #/fixes.');
    } else {
      var s = summary();
      var hard = s && Array.isArray(s.hardening) ? s.hardening : [];
      if (hard.length) {
        out.push('## Fix these first');
        hard.slice(0, 3).forEach(function (h, n) { out.push((n + 1) + '. **' + clip(h.title, 160) + '**: ' + clip(h.recommendation, 300)); });
      }
    }
    return out;
  }

  function stabilityExplain() {
    var out = [];
    var g = guide();
    var st = g && g.stability;
    if (st) {
      out.push('## ' + clip(st.title || 'Blue screens and crashes', 160));
      if (st.plain) { out.push(clip(st.plain, 800)); }
      if (Array.isArray(st.facts) && st.facts.length) { out.push('', '**What the scan saw:**'); st.facts.slice(0, 6).forEach(function (f) { out.push('- ' + clip(f, 300)); }); }
      if (Array.isArray(st.steps) && st.steps.length) { out.push('', '**What to try, easiest first:**'); st.steps.slice(0, 8).forEach(function (f, n) { out.push((n + 1) + '. ' + clip(f, 300)); }); }
    } else {
      out.push('## Blue screens and crashes', 'The stability page (#/health) lists unexpected restarts and their stop codes. A code like DRIVER_POWER_STATE_FAILURE (0x9F) usually points to a driver that fails during sleep or wake-up, so updating BIOS, chipset, Wi-Fi and graphics drivers is the first thing to try.');
    }
    out.push('', 'More on #/health.');
    return out;
  }

  function explainOffline(question, context) {
    context = context || {};
    var preset = context.preset || null;
    var out = [];
    var ents = Array.isArray(context.entities) ? context.entities : [];
    ents.slice(0, 3).forEach(function (e) { var part = entityExplain(e); if (part.length) { if (out.length) { out.push(''); } out = out.concat(part); } });

    var q = String(question || '').toLowerCase();
    var topic = preset;
    if (!topic) {
      if (/blue.?screen|bsod|crash|restart|bugcheck|freez/.test(q)) { topic = 'bsod'; }
      else if (/fix first|what should i (do|fix)|walk me|priorit/.test(q)) { topic = 'fix-first'; }
      else if (/dangerous|hacked|virus|safe\b|attack|compromis/.test(q)) { topic = 'danger'; }
      else if (/how (do i|to) use|dashboard|where (do|can) i|navigate/.test(q)) { topic = 'how-to-use'; }
      else if (/verdict|result|mean|summary|overall/.test(q) && !ents.length) { topic = 'eli5'; }
    }
    var add = [];
    if (topic === 'eli5' || topic === 'connect-dots') { add = verdictExplain(false); }
    else if (topic === 'danger') { add = verdictExplain(true); }
    else if (topic === 'fix-first' || (topic === 'what-do' && !ents.length)) { add = fixesExplain(); }
    else if (topic === 'bsod') { add = stabilityExplain(); }
    else if (topic === 'how-to-use' || (topic === 'how-use-part' && !ents.length)) { add = TOUR.split('\n'); }
    if (topic === 'connect-dots') {
      var g = guide();
      if (g && Array.isArray(g.health) && g.health.length) {
        add.push('', '**Area by area:**');
        g.health.slice(0, 6).forEach(function (h) { add.push('- **' + clip(h.area, 40) + '** (' + clip(h.grade, 20) + '): ' + clip(h.text, 260)); });
      }
    }
    if (!out.length && !add.length) {
      // nothing specific matched: say what was pointed at and give the overall picture around it
      var what = context.selectionText ? clip(String(context.selectionText).replace(/\s+/g, ' '), 220)
        : ents.map(function (e) { return e.label || e.id; }).filter(Boolean).slice(0, 3).join(', ');
      if (what) { out.push('## What you pointed at', '> ' + what); }
      add = verdictExplain(false);
      if (add.length) { add[0] = add[0].replace(/^## /, '**The big picture:** '); }
    }
    if (add.length) { if (out.length) { out.push(''); } out = out.concat(add); }

    var labels = ents.map(function (e) { return (e.label || '') + ' ' + (e.section || ''); }).join(' ');
    var words = glossaryLookup(String(question || '') + '\n' + labels + '\n' + (context.selectionText || ''), out.length ? 5 : 7);
    if (words.length) {
      out.push('', '## Words in plain English');
      words.forEach(function (w) { out.push('- **' + w.term + '**: ' + w.plain); });
    }
    if (!out.length) {
      out.push('I could not find a ready-made explanation for that without the live assistant.',
        '', 'Try one of the quick questions, select part of the screen with the scan button, or look the word up in the glossary on #/infosec.');
    }
    return out.join('\n');
  }

  // ------------------------------------------------------------------------------ transport
  var statusPromise = null, statusAt = 0;
  function isHttp() { return (location.protocol === 'http:' || location.protocol === 'https:') && typeof fetch === 'function'; }
  function getStatus(force) {
    if (!isHttp()) { return Promise.resolve({ ai: false, reason: 'file' }); }
    if (!force && statusPromise && Date.now() - statusAt < 60000) { return statusPromise; }
    statusAt = Date.now();
    statusPromise = fetch('/api/status', { cache: 'no-store', credentials: 'same-origin' }).then(function (r) {
      if (!r.ok) { return { ai: false, reason: 'no-server' }; }
      return r.json().then(function (j) { return j && typeof j === 'object' ? j : { ai: false, reason: 'no-server' }; },
        function () { return { ai: false, reason: 'no-server' }; });
    }, function () { return { ai: false, reason: 'no-server' }; });
    return statusPromise;
  }
  function reasonText(st) {
    var r = st && st.reason;
    if (r === 'file') { return 'This is the offline explainer: the dashboard was opened as a file.'; }
    if (r === 'disabled') { return 'This is the offline explainer: live answers are switched off on this server.'; }
    if (r === 'claude-not-found') { return 'This is the offline explainer: Claude Code was not found on this PC.'; }
    return 'This is the offline explainer: the dashboard server did not answer.';
  }

  // Accept both the contract shape {view, selectionText, entities, history} and the shell's panel
  // shape {kind, id, title, data, text} (app.js "Ask INFOSEC about this").
  function normalizeContext(ctx) {
    if (!ctx || typeof ctx !== 'object') { return {}; }
    var out = {};
    Object.keys(ctx).forEach(function (k) { out[k] = ctx[k]; });
    out.entities = Array.isArray(ctx.entities) ? ctx.entities.slice() : [];
    if (ctx.kind && typeof ctx.kind === 'string') {
      var type = ENTITY_TYPES.indexOf(ctx.kind) >= 0 ? ctx.kind : null;
      if (type && ctx.id !== undefined && ctx.id !== null && ctx.id !== '') {
        var dup = out.entities.some(function (e) { return e && e.type === type && String(e.id) === String(ctx.id); });
        if (!dup) { out.entities.unshift({ type: type, id: String(ctx.id), label: ctx.title ? clip(ctx.title, 120) : '' }); }
      } else if (ctx.data && !out.selectionText) {
        try { out.selectionText = clip(JSON.stringify(ctx.data), 3000); } catch (e) { /* ignore */ }
      }
      if (ctx.text && !out.selectionText) { out.selectionText = clip(ctx.text, 3000); }
      if (!out.label && ctx.title) { out.label = clip(ctx.title, 80); }
    }
    return out;
  }

  function cleanContext(ctx) {
    ctx = normalizeContext(ctx);
    var out = { view: clip(ctx.view || currentRoute(), 200) };
    if (ctx.selectionText) { out.selectionText = clip(ctx.selectionText, 4000); }
    if (Array.isArray(ctx.entities) && ctx.entities.length) {
      out.entities = ctx.entities.filter(function (e) { return e && ENTITY_TYPES.indexOf(e.type) >= 0; }).slice(0, 12).map(function (e) {
        var o = { type: e.type };
        if (e.id !== undefined && e.id !== null && e.id !== '') { o.id = clip(e.id, 300); }
        if (e.label) { o.label = clip(e.label, 200); }
        if (e.section) { o.section = clip(e.section, 80); }
        return o;
      });
    }
    if (Array.isArray(ctx.history) && ctx.history.length) {
      out.history = ctx.history.filter(function (h) { return h && (h.role === 'user' || h.role === 'assistant') && h.text; })
        .slice(-6).map(function (h) { return { role: h.role, text: clip(h.text, 1200) }; });
    }
    return out;
  }

  // A streamed answer arrives as NDJSON: one JSON event per line. onLine gets every parsed event.
  function readNdjson(resp, onLine) {
    function each(text) {
      text.split('\n').forEach(function (line) {
        if (!line.trim()) { return; }
        var obj = null;
        try { obj = JSON.parse(line); } catch (e) { return; }
        onLine(obj);
      });
    }
    if (!resp.body || typeof resp.body.getReader !== 'function' || typeof TextDecoder !== 'function') {
      return resp.text().then(each);
    }
    var reader = resp.body.getReader(), dec = new TextDecoder('utf-8'), buf = '';
    function pump() {
      return reader.read().then(function (r) {
        if (r.done) { buf += dec.decode(); each(buf); buf = ''; return; }
        buf += dec.decode(r.value, { stream: true });
        var cut = buf.lastIndexOf('\n');
        if (cut >= 0) { each(buf.slice(0, cut)); buf = buf.slice(cut + 1); }
        return pump();
      });
    }
    return pump();
  }

  function post(token, question, preset, context, onEvent, signal) {
    var body = { question: clip(question, 4000), context: cleanContext(context) };
    if (preset) { body.preset = preset; }
    var init = {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      // v3: the server (agent K) requires the user's recorded AI consent on every live question.
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/x-ndjson, application/json', 'X-BVS-Token': token, 'X-BVS-AI-Consent': 'yes' },
      body: JSON.stringify(body)
    };
    if (signal) { init.signal = signal; }
    return fetch('/api/ask', init).then(function (r) {
      var ctype = String(r.headers.get('Content-Type') || '').toLowerCase();
      if (r.ok && ctype.indexOf('application/x-ndjson') === 0) {
        var done = null, failure = null;
        return readNdjson(r, function (ev) {
          if (!ev || typeof ev !== 'object') { return; }
          if (ev.type === 'done') { done = ev; } else if (ev.type === 'error') { failure = ev; } else if (onEvent) { onEvent(ev); }
        }).then(function () {
          if (done && typeof done.text === 'string') { return { text: done.text, source: 'ai', costUsd: done.costUsd, model: done.model }; }
          var e = new Error((failure && failure.message) || 'the answer stopped before it was finished');
          e.status = 502;
          e.code = failure && failure.error;
          throw e;
        });
      }
      return r.json().then(null, function () { return {}; }).then(function (obj) {
        if (r.ok && obj && typeof obj.text === 'string') {
          return { text: obj.text, source: 'ai', costUsd: obj.costUsd, model: obj.model };
        }
        var e = new Error((obj && obj.message) || ('HTTP ' + r.status));
        e.status = r.status;
        e.code = obj && obj.error;
        throw e;
      });
    });
  }

  var queue = Promise.resolve();
  function askImpl(question, context, onEvent, signal) {
    var job = queue.then(function () { return doAsk(question, context || {}, onEvent, signal); });
    queue = job.then(null, function () { /* keep the queue alive */ });
    return job;
  }
  function offline(question, context, reason) {
    var text = explainOffline(question, context);
    return { text: text + '\n\n---\n*' + reason + ' ' + OFFLINE_HINT + '*', source: 'offline', error: reason };
  }
  function doAsk(question, context, onEvent, signal) {
    context = normalizeContext(context);
    var preset = context.preset || null;
    if (context.forceOffline) { return Promise.resolve(offline(question, context, 'Demo mode: offline explanation.')); }
    return getStatus().then(function (st) {
      if (!st || !st.ai || !st.token) { return offline(question, context, reasonText(st)); }
      return consentGate().then(function (choice) {
        if (choice !== 'yes') {
          return offline(question, context, choice === 'no' ? 'You chose offline answers only, so nothing was sent to Claude (change it on the Privacy & AI page).'
            : 'Nothing was sent to Claude: live answers need your OK first (Privacy & AI page).');
        }
        return askLive(st, question, preset, context, onEvent, signal);
      });
    });
  }
  // v3 AI consent gate (docs/ui-contract-v3.md §2): the modal lives in app.js (BVSApp.aiConsent). Without
  // it nothing is sent.
  function consentGate() {
    try { if (App.aiConsent && typeof App.aiConsent.request === 'function') { return Promise.resolve(App.aiConsent.request()); } } catch (e) { /* fall through */ }
    return Promise.resolve('no');
  }
  function isAbort(err) { return !!err && (err.name === 'AbortError' || err.code === 20); }
  function askLive(st, question, preset, context, onEvent, signal) {
    return post(st.token, question, preset, context, onEvent, signal).then(null, function (err) {
      if (err && err.status === 403 && err.code !== 'consent_required') { // token from an older server run: refresh once
        return getStatus(true).then(function (st2) {
          if (!st2 || !st2.ai || !st2.token) { throw err; }
          return post(st2.token, question, preset, context, onEvent, signal);
        });
      }
      throw err;
    }).then(null, function (err) {
      if (isAbort(err)) { return { text: '', source: 'ai', aborted: true }; }
      var msg = err && err.message ? String(err.message) : 'the live assistant failed';
      if (err && err.status === 503) { statusPromise = null; }
      var res = offline(question, context, 'Live answer unavailable (' + clip(msg, 160) + '), so here is the offline explanation.');
      res.failed = true;
      return res;
    });
  }

  // ------------------------------------------------------------------------------ saved chats
  function newChatId() { return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  function blankChat() { var now = Date.now(); return { id: newChatId(), title: '', created: now, updated: now, messages: [] }; }
  function titleOf(msgs) {
    var first = (msgs || []).filter(function (m) { return m.role === 'user'; })[0];
    return first ? clip(String(first.text).replace(/\s+/g, ' ').trim(), 80) : '';
  }
  function cleanMessages(arr) {
    return (Array.isArray(arr) ? arr : []).filter(function (m) {
      return m && (m.role === 'user' || m.role === 'assistant') && typeof m.text === 'string' && m.text;
    }).slice(-MAX_MESSAGES).map(function (m) {
      var o = { role: m.role, text: m.text.slice(0, 20000), ts: typeof m.ts === 'number' ? m.ts : Date.now() };
      if (m.source === 'ai' || m.source === 'offline') { o.source = m.source; }
      if (m.model) { o.model = clip(m.model, 200); }
      if (typeof m.costUsd === 'number' && isFinite(m.costUsd) && m.costUsd >= 0) { o.costUsd = m.costUsd; }
      if (m.about) { o.about = clip(m.about, 200); }
      if (m.via) { o.via = clip(m.via, 200); }
      if (m.error === true) { o.error = true; }
      return o;
    });
  }
  function fromSaved(c) {
    if (!c || typeof c.id !== 'string' || !CHAT_ID_RE.test(c.id) || !Array.isArray(c.messages)) { return null; }
    var msgs = cleanMessages(c.messages);
    return { id: c.id, title: clip(c.title || titleOf(msgs), 120), created: c.created || Date.now(), updated: c.updated || Date.now(), messages: msgs };
  }
  function toSaved(c) {
    var msgs = cleanMessages(c.messages);
    return { id: c.id, title: clip(c.title || titleOf(msgs) || 'Chat', 120), created: c.created, updated: c.updated, messages: msgs };
  }
  function rowOf(c) {
    return {
      id: c.id, title: c.title || titleOf(c.messages) || 'Chat', created: c.created, updated: c.updated, count: c.messages.length,
      questions: c.messages.filter(function (m) { return m.role === 'user'; }).slice(-30).map(function (m) {
        return { text: clip(String(m.text).replace(/\s+/g, ' '), 200), ts: m.ts, about: m.about || '' };
      })
    };
  }

  // JSON API of the dashboard server, with the per-start token (refreshed once when it is stale).
  function api(method, path, body) {
    function call(token, retried) {
      var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: { 'X-BVS-Token': token, 'Accept': 'application/json' } };
      if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
      return fetch(path, init).then(function (r) {
        if (r.status === 403 && !retried) {
          return getStatus(true).then(function (st) { if (!st || !st.token) { throw new Error('no server'); } return call(st.token, true); });
        }
        return r.json().then(null, function () { return {}; }).then(function (obj) {
          if (!r.ok) { var e = new Error((obj && obj.message) || ('HTTP ' + r.status)); e.status = r.status; throw e; }
          return obj;
        });
      });
    }
    return getStatus().then(function (st) {
      if (!st || !st.token) { throw new Error('no server'); }
      return call(st.token, false);
    });
  }

  // Chats live on the dashboard server (data/infosec/chats). When it cannot store them (file:// copy,
  // server stopped) they are kept in this browser instead, and still listed.
  var Store = {
    local: function () {
      try {
        var raw = window.localStorage.getItem(LOCAL_CHATS_KEY);
        var arr = raw ? JSON.parse(raw) : [];
        return Array.isArray(arr) ? arr.map(fromSaved).filter(Boolean) : [];
      } catch (e) { return []; }
    },
    writeLocal: function (arr) {
      try { window.localStorage.setItem(LOCAL_CHATS_KEY, JSON.stringify(arr.slice(0, 30))); } catch (e) { /* storage off or full */ }
    },
    list: function () {
      var local = this.local().map(rowOf);
      return api('GET', '/api/chats').then(function (obj) {
        var rows = Array.isArray(obj.items) ? obj.items.filter(function (r) { return r && typeof r.id === 'string'; }) : [];
        var seen = {};
        rows.forEach(function (r) { seen[r.id] = true; });
        local.forEach(function (r) { if (!seen[r.id]) { rows.push(r); } });
        rows.sort(function (a, b) { return (b.updated || 0) - (a.updated || 0); });
        return rows;
      }, function () { return local; });
    },
    get: function (id) {
      var self = this;
      return api('GET', '/api/chats/' + id).then(fromSaved, function () { return null; }).then(function (chat) {
        if (chat) { return chat; }
        var hit = self.local().filter(function (c) { return c.id === id; })[0];
        if (hit) { return hit; }
        throw new Error('This chat could not be found.');
      });
    },
    save: function (chat) {
      var self = this;
      return api('POST', '/api/chats', chat).then(function () {
        var local = self.local();
        if (local.some(function (c) { return c.id === chat.id; })) { self.writeLocal(local.filter(function (c) { return c.id !== chat.id; })); }
        return true;
      }, function () {
        self.writeLocal([chat].concat(self.local().filter(function (c) { return c.id !== chat.id; })));
        return false;
      });
    }
  };

  // ------------------------------------------------------------------------------ chat state
  // Events: 'change' (messages, busy state, context or chat switched: views re-render), 'live' (the
  // answer being written grew: views update only that bubble), 'list' (saved chats changed).
  var Chat = {
    current: blankChat(),
    messages: [],
    busy: false,
    live: null,
    context: null,
    list: [],
    listState: 'idle',
    hub: {},
    ctrl: null,
    saveTimer: null,
    on: function (kind, fn) {
      var self = this;
      (this.hub[kind] = this.hub[kind] || []).push(fn);
      return function () { self.hub[kind] = (self.hub[kind] || []).filter(function (f) { return f !== fn; }); };
    },
    emit: function (kind) { (this.hub[kind] || []).slice().forEach(function (fn) { try { fn(); } catch (e) { if (window.console) { console.warn('infosec:', e); } } }); },
    subscribe: function (fn) { return this.on('change', fn); },
    notify: function () { this.emit('change'); },
    init: function () {
      var cur = null;
      try { var raw = window.localStorage.getItem(CURRENT_KEY); cur = raw ? fromSaved(JSON.parse(raw)) : null; } catch (e) { cur = null; }
      this.use(cur || blankChat());
      this.migrate();
      this.refreshList();
    },
    migrate: function () { // the chat from before saving existed lived in sessionStorage only: keep it
      var arr = null;
      try {
        var raw = window.sessionStorage.getItem(OLD_SESSION_KEY);
        if (!raw) { return; }
        arr = JSON.parse(raw);
        window.sessionStorage.removeItem(OLD_SESSION_KEY);
      } catch (e) { return; }
      var msgs = cleanMessages(arr);
      if (msgs.length && !this.current.messages.length) { this.current.messages = msgs; this.messages = msgs; this.persist(true); }
    },
    use: function (chat) { this.current = chat; this.messages = chat.messages; this.cache(); },
    cache: function () {
      try { window.localStorage.setItem(CURRENT_KEY, JSON.stringify(toSaved(this.current))); } catch (e) { /* storage off or full */ }
    },
    persist: function (now) {
      var self = this;
      this.current.updated = Date.now();
      if (!this.current.title) { this.current.title = titleOf(this.current.messages); }
      this.cache();
      if (!this.current.messages.length) { return Promise.resolve(false); }
      clearTimeout(this.saveTimer);
      var snapshot = toSaved(this.current);
      if (now) { return Store.save(snapshot).then(function (ok) { self.refreshList(); return ok; }); }
      this.saveTimer = setTimeout(function () { Store.save(snapshot).then(function () { self.refreshList(); }); }, 400);
      return Promise.resolve(true);
    },
    refreshList: function () {
      var self = this;
      if (this.listState === 'idle') { this.listState = 'loading'; this.emit('list'); }
      return Store.list().then(function (rows) { self.list = rows; self.listState = 'ok'; self.emit('list'); });
    },
    setContext: function (ctx) {
      if (!ctx || typeof ctx !== 'object') { this.context = null; this.notify(); return; }
      ctx = normalizeContext(ctx);
      var ents = Array.isArray(ctx.entities) ? ctx.entities.filter(function (e) { return e && e.type; }) : [];
      if (!ents.length && !ctx.selectionText) { this.context = null; this.notify(); return; }
      this.context = { entities: ents, selectionText: ctx.selectionText || '', view: ctx.view || '', label: ctx.label || contextLabel(ents, ctx.selectionText) };
      this.notify();
    },
    append: function (msgs) {
      var add = cleanMessages(msgs);
      if (!add.length) { return; }
      this.current.messages.push.apply(this.current.messages, add);
      if (this.current.messages.length > MAX_MESSAGES) { this.current.messages.splice(0, this.current.messages.length - MAX_MESSAGES); }
      this.persist(true);
      this.notify();
    },
    startNew: function () {
      if (this.busy) { return; }
      clearTimeout(this.saveTimer);
      if (this.current.messages.length) { Store.save(toSaved(this.current)); }
      this.context = null;
      this.use(blankChat());
      this.notify();
      this.refreshList();
    },
    clear: function () { this.startNew(); },
    open: function (id) {
      var self = this;
      if (this.busy || !id) { return Promise.resolve(false); }
      if (id === this.current.id) { return Promise.resolve(true); }
      clearTimeout(this.saveTimer);
      if (this.current.messages.length) { Store.save(toSaved(this.current)); }
      return Store.get(id).then(function (chat) {
        self.context = null;
        self.use(chat);
        self.notify();
        self.emit('list');
        return true;
      }, function () { return false; });
    },
    send: function (question, preset, opts) {
      var self = this;
      opts = opts || {};
      question = String(question || '').trim();
      if (!question || this.busy) { return Promise.resolve(null); }
      var history = this.current.messages.filter(function (m) { return !m.error; }).slice(-6).map(function (m) { return { role: m.role, text: m.text }; });
      var ctx = { view: currentRoute(), history: history, preset: preset || null };
      if (this.context) {
        ctx.entities = this.context.entities;
        if (this.context.selectionText) { ctx.selectionText = this.context.selectionText; }
      }
      this.current.messages.push({ role: 'user', text: question, ts: Date.now(), about: this.context ? this.context.label : '', via: opts.via || '' });
      this.busy = true;
      this.live = { text: '', stage: 'connecting', started: Date.now(), warm: null };
      this.ctrl = typeof AbortController === 'function' ? new AbortController() : null;
      this.persist(false);
      this.notify();
      var ask = typeof App.ask === 'function' ? App.ask : askImpl;
      var p;
      try { p = Promise.resolve(ask.call(App, question, ctx, function (ev) { self.onLive(ev); }, this.ctrl ? this.ctrl.signal : undefined)); } catch (e) { p = Promise.reject(e); }
      return p.then(null, function (err) {
        var res = offline(question, ctx, 'Something went wrong (' + clip(err && err.message, 120) + ').');
        res.failed = true;
        return res;
      }).then(function (res) {
        res = res || {};
        var partial = self.live && self.live.text ? self.live.text : '';
        var msg = { role: 'assistant', text: String(res.text || ''), source: res.source || 'offline', model: res.model, costUsd: res.costUsd, ts: Date.now() };
        if (res.aborted) {
          msg.text = (partial ? partial + '\n\n' : '') + '*You stopped this answer.*';
          msg.source = partial ? 'ai' : 'offline';
        }
        if (res.failed) { msg.error = true; }
        self.current.messages.push(msg);
        if (self.current.messages.length > MAX_MESSAGES) { self.current.messages.splice(0, self.current.messages.length - MAX_MESSAGES); }
        self.busy = false;
        self.live = null;
        self.ctrl = null;
        self.persist(true);
        self.notify();
        return res;
      });
    },
    onLive: function (ev) {
      if (!this.live || !ev || typeof ev !== 'object') { return; }
      if (ev.type === 'status' && typeof ev.stage === 'string') {
        this.live.stage = ev.stage;
        if (typeof ev.warm === 'boolean') { this.live.warm = ev.warm; }
      } else if (ev.type === 'delta' && typeof ev.text === 'string') {
        this.live.text += ev.text;
        this.live.stage = 'writing';
      } else if (ev.type === 'reset' && typeof ev.text === 'string') {
        this.live.text = ev.text;
      }
      this.emit('live');
    },
    stop: function () { if (this.ctrl) { try { this.ctrl.abort(); } catch (e) { /* ignore */ } } },
    retry: function () { // ask the last question again after a failed live answer
      if (this.busy) { return; }
      var msgs = this.current.messages, last = msgs[msgs.length - 1], q = null, at = -1;
      if (!last || last.role !== 'assistant' || !last.error) { return; }
      for (var i = msgs.length - 2; i >= 0; i--) { if (msgs[i].role === 'user') { q = msgs[i]; at = i; break; } }
      if (!q) { return; }
      msgs.splice(at, msgs.length - at);
      this.send(q.text, null, { via: q.via });
    }
  };

  function typeLabel(t) {
    return { finding: 'Finding', storageItem: 'Storage item', question: 'Question', fix: 'Fix', file: 'File', tile: 'Tile', section: 'Section' }[t] || 'Item';
  }
  function contextLabel(ents, sel) {
    var parts = (ents || []).slice(0, 3).map(function (e) { return clip(e.label || (typeLabel(e.type) + (e.id ? ' ' + e.id : '')), 60); });
    if ((ents || []).length > 3) { parts.push('+' + (ents.length - 3) + ' more'); }
    if (!parts.length && sel) { parts.push('Selected text'); }
    return parts.join(', ');
  }
  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function when(ts) {
    if (!ts) { return ''; }
    var d = new Date(ts), now = new Date();
    if (d.toDateString() === now.toDateString()) { return 'today ' + hhmm(ts); }
    return d.getDate() + ' ' + MONTHS[d.getMonth()] + (d.getFullYear() !== now.getFullYear() ? ' ' + d.getFullYear() : '') + ', ' + hhmm(ts);
  }

  // ------------------------------------------------------------------------------ chat view
  function statusPill() {
    var pill = el('span', { cls: 'ix-pill ix-pill-wait', text: 'Checking live answers…' });
    getStatus().then(function (st) {
      if (st && st.ai && App.aiConsent && App.aiConsent.get && App.aiConsent.get() === 'no') {
        pill.className = 'ix-pill ix-pill-off';
        pill.textContent = 'Offline answers (your choice)';
        pill.title = 'You chose offline answers only: nothing is sent to Claude. Change it on the Privacy & AI page.';
      } else if (st && st.ai) {
        pill.className = 'ix-pill ix-pill-on';
        pill.textContent = 'Live · Claude ' + (st.model || '');
        pill.title = PRIVACY;
      } else {
        pill.className = 'ix-pill ix-pill-off';
        pill.textContent = 'Offline explainer';
        pill.title = reasonText(st) + ' ' + OFFLINE_HINT;
      }
    });
    return pill;
  }

  function messageNode(m, isLast) {
    if (m.role === 'user') {
      return el('div', { cls: 'ix-msg ix-msg-user', attrs: { 'data-ts': String(m.ts || '') } }, [
        m.about ? el('div', { cls: 'ix-about', text: 'About: ' + m.about }) : null,
        el('div', { cls: 'ix-bubble', text: m.text }),
        el('div', { cls: 'ix-meta', text: hhmm(m.ts) + (m.via ? ' · ' + m.via : '') })
      ]);
    }
    var copyBtn = el('button', { cls: 'ix-mini', attrs: { type: 'button', 'aria-label': 'Copy this answer' } }, [icon('copy', 14), el('span', { text: 'Copy' })]);
    copyBtn.addEventListener('click', function () {
      copyToClipboard(m.text).then(function (ok) {
        copyBtn.lastChild.textContent = ok ? 'Copied' : 'Copy failed';
        setTimeout(function () { copyBtn.lastChild.textContent = 'Copy'; }, 1600);
      });
    });
    var retryBtn = null;
    if (m.error && isLast) {
      retryBtn = el('button', { cls: 'ix-mini ix-retry', attrs: { type: 'button' } }, [icon('retry', 14), el('span', { text: 'Try the live answer again' })]);
      retryBtn.addEventListener('click', function () { Chat.retry(); });
    }
    var src = m.source === 'ai' ? 'Live answer · Claude' + (m.model ? ' ' + m.model : '') : 'Offline explanation';
    if (m.source === 'ai' && typeof m.costUsd === 'number') { src += ' · $' + (m.costUsd < 0.01 ? m.costUsd.toFixed(4) : m.costUsd.toFixed(3)); }
    return el('div', { cls: 'ix-msg ix-msg-ai' + (m.source === 'ai' ? '' : ' ix-offline') }, [
      el('div', { cls: 'ix-avatar', attrs: { 'aria-hidden': 'true' } }, icon('shield', 18)),
      el('div', { cls: 'ix-bubble' }, [
        m.source === 'ai' ? el('div', { cls: 'ai-badge', attrs: { role: 'note' }, text: AI_BADGE }) : null,
        renderMarkdown(m.text),
        el('div', { cls: 'ix-msg-foot' }, [
          el('span', { cls: 'ix-src', text: src + ' · ' + hhmm(m.ts) }),
          el('span', { cls: 'ix-foot-btns' }, [retryBtn, copyBtn])
        ])
      ])
    ]);
  }

  function stageText(live) {
    if (!live) { return ''; }
    if (live.stage === 'writing') { return 'Writing the answer'; }
    if (live.stage === 'thinking') { return 'Thinking it through'; }
    if (live.stage === 'asking') { return live.warm === false ? 'Starting Claude (about 10 seconds the first time)' : 'Reading your scan'; }
    return 'Connecting to INFOSEC';
  }

  function welcomeNode(compact) {
    var g = guide();
    return el('div', { cls: 'ix-welcome' }, [
      el('div', { cls: 'ix-welcome-badge', attrs: { 'aria-hidden': 'true' } }, icon('shield', compact ? 26 : 34)),
      el('h3', { text: "Hi, I'm INFOSEC." }),
      el('p', { text: 'I read this scan, explain it in plain English, connect the dots between findings and walk you through fixes step by step.' }),
      g && g.headline ? el('p', { cls: 'ix-welcome-head', text: 'Your scan in one line: ' + g.headline }) : null,
      el('p', { cls: 'ix-muted', text: 'Tap a question below or type your own. Tip: press S to scan any part of the screen. Every chat is saved on this PC.' })
    ]);
  }

  function createChatView(opts) {
    opts = opts || {};
    var log = el('div', { cls: 'ix-log', attrs: { role: 'log', 'aria-live': 'polite', 'aria-label': 'INFOSEC conversation' } });
    var input = el('textarea', { cls: 'ix-input', attrs: { rows: 2, placeholder: 'Ask INFOSEC anything about your scan…', 'aria-label': 'Your question for INFOSEC', spellcheck: 'true' } });
    var sendIcon = el('span', { cls: 'ix-send-ico', attrs: { 'aria-hidden': 'true' } }, icon('send', 18));
    var sendLabel = el('span', { text: 'Ask' });
    var sendBtn = el('button', { cls: 'ix-send', attrs: { type: 'submit', 'aria-label': 'Send question' } }, [sendIcon, sendLabel]);
    var ctxBox = el('div', { cls: 'ix-ctx', hidden: true });
    var presets = null;
    if (opts.presets !== false) {
      presets = el('div', { cls: 'ix-presets', attrs: { role: 'group', 'aria-label': 'Quick questions' } });
      PRESETS.forEach(function (p) {
        presets.appendChild(el('button', { cls: 'ix-chip', attrs: { type: 'button' }, on: { click: function () { Chat.send(p.label, p.id); } } }, [icon(p.icon, 14), el('span', { text: p.label })]));
      });
    }
    var form = el('form', { cls: 'ix-composer', attrs: { autocomplete: 'off' } }, [input, sendBtn]);
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (Chat.busy) { Chat.stop(); return; }
      var q = input.value.trim();
      if (!q) { input.focus(); return; }
      input.value = '';
      sendBtn.classList.remove('ix-pulse');
      Chat.send(q, null);
    });
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) {
        ev.preventDefault();
        if (!Chat.busy) { if (form.requestSubmit) { form.requestSubmit(); } else { form.dispatchEvent(new Event('submit', { cancelable: true })); } }
      }
      ev.stopPropagation(); // typing "s" here must not start the scanner
    });
    var newBtn = el('button', { cls: 'ix-mini ix-clear', attrs: { type: 'button' } }, [icon('plus', 14), el('span', { text: 'New chat' })]);
    newBtn.addEventListener('click', function () { Chat.startNew(); input.focus(); });

    var root = el('div', { cls: 'ix-chat' + (opts.compact ? ' ix-compact' : '') }, [
      log,
      presets,
      ctxBox,
      form,
      el('div', { cls: 'ix-foot' }, [el('span', { cls: 'ix-privacy', title: PRIVACY, text: opts.compact ? 'AI answers by Claude, with your OK · chats saved only on this PC' : PRIVACY }), newBtn])
    ]);

    // the answer being written: one node, updated in place (no full re-render per piece of text)
    var live = { node: null, stage: null, body: null, shown: null, timer: 0, pending: 0 };
    var stick = true;
    log.addEventListener('scroll', function () { stick = log.scrollHeight - log.scrollTop - log.clientHeight < 48; }, { passive: true });
    function liveNode() {
      live.stage = el('span', { cls: 'ix-typing-text' });
      live.body = el('div', { cls: 'ix-live-body' });
      live.shown = null;
      live.node = el('div', { cls: 'ix-msg ix-msg-ai ix-live' }, [
        el('div', { cls: 'ix-avatar', attrs: { 'aria-hidden': 'true' } }, icon('shield', 18)),
        el('div', { cls: 'ix-bubble' }, [
          el('div', { cls: 'ix-scanbar', attrs: { 'aria-hidden': 'true' } }, el('span')),
          el('div', { cls: 'ix-live-head', attrs: { role: 'status' } }, [el('span', { cls: 'ix-dots', attrs: { 'aria-hidden': 'true' } }, [el('i'), el('i'), el('i')]), live.stage]),
          live.body
        ])
      ]);
      return live.node;
    }
    function updateLive() {
      live.pending = 0;
      if (!live.node || !Chat.live) { return; }
      var secs = Math.max(0, Math.round((Date.now() - Chat.live.started) / 1000));
      live.stage.textContent = stageText(Chat.live) + '… ' + secs + ' s';
      if (Chat.live.text !== live.shown) {
        live.shown = Chat.live.text;
        clear(live.body);
        if (live.shown) { live.body.appendChild(renderMarkdown(live.shown)); }
        live.node.classList.toggle('ix-has-text', !!live.shown);
      }
      if (stick) { log.scrollTop = log.scrollHeight; }
    }
    function scheduleLive() { if (!live.pending) { live.pending = setTimeout(updateLive, 90); } }
    function setSendMode(busy) {
      clear(sendIcon);
      sendIcon.appendChild(icon(busy ? 'stop' : 'send', 18));
      sendLabel.textContent = busy ? 'Stop' : 'Ask';
      sendBtn.setAttribute('aria-label', busy ? 'Stop the answer' : 'Send question');
      sendBtn.classList.toggle('ix-stop', busy);
    }

    var lastKey = '';
    function render() {
      clear(log);
      live.node = null;
      if (!Chat.messages.length && !Chat.busy) { log.appendChild(welcomeNode(opts.compact)); }
      Chat.messages.forEach(function (m, i) { log.appendChild(messageNode(m, i === Chat.messages.length - 1)); });
      if (Chat.busy) {
        log.appendChild(liveNode());
        updateLive();
        if (!live.timer) { live.timer = setInterval(updateLive, 1000); }
      } else if (live.timer) {
        clearInterval(live.timer);
        live.timer = 0;
      }
      log.setAttribute('aria-busy', Chat.busy ? 'true' : 'false');
      setSendMode(Chat.busy);
      newBtn.disabled = Chat.busy;
      if (presets) { Array.prototype.forEach.call(presets.children, function (b) { b.disabled = Chat.busy; }); }
      clear(ctxBox);
      if (Chat.context) {
        ctxBox.hidden = false;
        var x = el('button', { cls: 'ix-ctx-x', attrs: { type: 'button', 'aria-label': 'Stop asking about this' } }, icon('close', 12));
        x.addEventListener('click', function () { Chat.setContext(null); });
        ctxBox.appendChild(el('span', { cls: 'ix-ctx-label', text: 'Asking about: ' + Chat.context.label }));
        ctxBox.appendChild(x);
      } else {
        ctxBox.hidden = true;
      }
      var key = Chat.current.id + ':' + Chat.messages.length + ':' + (Chat.busy ? 1 : 0);
      if (key !== lastKey) {
        var switched = lastKey.split(':')[0] !== Chat.current.id;
        lastKey = key;
        var lastMsg = log.lastElementChild;
        // keep the start of a finished long answer in view; follow a new question and the answer being written
        if (!switched && lastMsg && lastMsg.classList.contains('ix-msg-ai') && !Chat.busy && lastMsg.offsetHeight > log.clientHeight) {
          log.scrollTop = lastMsg.offsetTop - log.offsetTop - 8;
        } else {
          log.scrollTop = log.scrollHeight;
        }
        stick = true;
      }
    }
    var offs = [Chat.on('change', render), Chat.on('live', scheduleLive)];
    render();
    return {
      root: root,
      input: input,
      focus: function () { try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); } },
      setPrefill: function (text) {
        if (text) { input.value = String(text); sendBtn.classList.add('ix-pulse'); }
      },
      scrollToQuestion: function (ts) {
        var hit = log.querySelector('.ix-msg-user[data-ts="' + String(ts).replace(/[^0-9]/g, '') + '"]');
        if (!hit) { return; }
        log.scrollTop = hit.offsetTop - log.offsetTop - 12;
        hit.classList.add('ix-flash');
        setTimeout(function () { hit.classList.remove('ix-flash'); }, 1600);
      },
      destroy: function () {
        offs.forEach(function (off) { off(); });
        if (live.timer) { clearInterval(live.timer); }
        if (live.pending) { clearTimeout(live.pending); }
      }
    };
  }

  // saved chats: the list on the INFOSEC page and in the copilot's history menu
  function chatList(opts) {
    opts = opts || {};
    var list = el('div', { cls: 'ix-hist-list', attrs: { role: 'list' } });
    var filter = '';
    function render() {
      clear(list);
      var q = filter.trim().toLowerCase();
      var rows = Chat.list.filter(function (r) {
        if (!q) { return true; }
        return String(r.title || '').toLowerCase().indexOf(q) >= 0 || (r.questions || []).some(function (x) { return String(x.text).toLowerCase().indexOf(q) >= 0; });
      });
      if (!rows.length) {
        list.appendChild(el('p', { cls: 'ix-muted ix-hist-empty', text: Chat.listState !== 'ok' ? 'Loading your saved chats…'
          : q ? 'No saved chat matches.' : 'No saved chats yet. Everything you ask INFOSEC is saved here automatically.' }));
        return;
      }
      rows.slice(0, opts.limit || 80).forEach(function (r) {
        var active = r.id === Chat.current.id;
        var b = el('button', { cls: 'ix-hist-item' + (active ? ' is-active' : ''), attrs: { type: 'button', role: 'listitem', 'aria-current': active ? 'true' : null } }, [
          el('span', { cls: 'ix-hist-ico', attrs: { 'aria-hidden': 'true' } }, icon('chat', 15)),
          el('span', { cls: 'ix-hist-text' }, [
            el('span', { cls: 'ix-hist-title', text: r.title || 'Chat' }),
            el('span', { cls: 'ix-hist-meta', text: plural(r.count || 0, 'message') + ' · ' + when(r.updated) + (active ? ' · open now' : '') })
          ])
        ]);
        b.disabled = Chat.busy && !active;
        b.addEventListener('click', function () {
          Chat.open(r.id).then(function (ok) { if (ok && opts.onOpen) { opts.onOpen(r.id); } });
        });
        list.appendChild(b);
      });
    }
    var offs = [Chat.on('list', render), Chat.on('change', render)];
    render();
    return { root: list, filter: function (s) { filter = s || ''; render(); }, destroy: function () { offs.forEach(function (o) { o(); }); } };
  }

  function questionList(onPick) {
    var list = el('div', { cls: 'ix-hist-list', attrs: { role: 'list' } });
    var filter = '';
    function render() {
      clear(list);
      var q = filter.trim().toLowerCase(), all = [];
      Chat.list.forEach(function (r) {
        (r.questions || []).forEach(function (x) { if (x && x.text) { all.push({ text: x.text, ts: x.ts, about: x.about, chat: r }); } });
      });
      all.sort(function (a, b) { return (b.ts || 0) - (a.ts || 0); });
      if (q) { all = all.filter(function (x) { return x.text.toLowerCase().indexOf(q) >= 0 || String(x.about || '').toLowerCase().indexOf(q) >= 0; }); }
      if (!all.length) {
        list.appendChild(el('p', { cls: 'ix-muted ix-hist-empty', text: Chat.listState !== 'ok' ? 'Loading…' : q ? 'No question matches.' : 'Your questions will appear here.' }));
        return;
      }
      all.slice(0, 120).forEach(function (x) {
        var open = el('button', { cls: 'ix-q-item', attrs: { type: 'button', role: 'listitem' } }, [
          el('span', { cls: 'ix-q-text', text: x.text }),
          el('span', { cls: 'ix-hist-meta', text: (x.about ? 'About ' + clip(x.about, 40) + ' · ' : '') + when(x.ts) })
        ]);
        open.title = 'Open the chat with this question';
        open.addEventListener('click', function () { onPick(x, false); });
        var again = el('button', { cls: 'ix-mini ix-q-again', attrs: { type: 'button', 'aria-label': 'Ask this again in the current chat' } }, [icon('retry', 13), el('span', { text: 'Ask again' })]);
        again.disabled = Chat.busy;
        again.addEventListener('click', function () { onPick(x, true); });
        list.appendChild(el('div', { cls: 'ix-q-row' }, [open, again]));
      });
    }
    var offs = [Chat.on('list', render), Chat.on('change', render)];
    render();
    return { root: list, filter: function (s) { filter = s || ''; render(); }, destroy: function () { offs.forEach(function (o) { o(); }); } };
  }

  function searchBox(placeholder, onInput) {
    var s = el('input', { cls: 'ix-gloss-search', attrs: { type: 'search', placeholder: placeholder, 'aria-label': placeholder } });
    s.addEventListener('input', function () { onInput(s.value); });
    s.addEventListener('keydown', function (ev) { ev.stopPropagation(); });
    return s;
  }

  // ------------------------------------------------------------------------------ copilot (floating window or docked panel)
  // The copilot opens as a small floating window (about a quarter of the screen, bottom right). It moves by
  // its title bar, resizes from every side and corner, and a double-click on the title bar brings back the
  // default size. The dock button pins it beside the page instead (on wide screens the page then makes room
  // for it). Mode, size and position are remembered in this browser.
  var drawer = null, drawerView = null, drawerHist = null, histPanel = null, launcher = null, pageView = null, dockBtn = null;
  var dockWanted = false;
  var mqWide = window.matchMedia ? window.matchMedia('(min-width: 1100px)') : null;
  var MODE_KEY = 'bvs.infosec.mode', GEOM_KEY = 'bvs.infosec.geom';
  var MIN_W = 320, MIN_H = 300, EDGE = 8;
  var RZ_DIRS = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];
  var RZ_CURSOR = { n: 'ns-resize', s: 'ns-resize', e: 'ew-resize', w: 'ew-resize', ne: 'nesw-resize', sw: 'nesw-resize', nw: 'nwse-resize', se: 'nwse-resize', move: 'move' };
  function onInfosecPage() { return /^#\/infosec(?:[?/]|$)/.test(location.hash || ''); }
  function drawerOpen() { return !!(drawer && drawer.classList.contains('ix-open')); }
  function remember(key, value) { try { window.localStorage.setItem(key, value); } catch (e) { /* storage off */ } }
  function recall(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } }
  var mode = recall(MODE_KEY) === 'dock' ? 'dock' : 'float';
  var geom = null;

  function defaultGeom() {
    var vw = window.innerWidth, vh = window.innerHeight;
    var w = Math.min(Math.max(360, vw * 0.28), 520), h = Math.min(Math.max(420, vh * 0.6), 700);
    return { x: vw - w - 20, y: vh - h - 20, w: w, h: h };
  }
  function clampGeom(g) {
    var vw = window.innerWidth, vh = window.innerHeight;
    var w = Math.min(Math.max(g.w, Math.min(MIN_W, vw - 2 * EDGE)), vw - 2 * EDGE);
    var h = Math.min(Math.max(g.h, Math.min(MIN_H, vh - 2 * EDGE)), vh - 2 * EDGE);
    var x = Math.min(Math.max(g.x, EDGE), vw - w - EDGE), y = Math.min(Math.max(g.y, EDGE), vh - h - EDGE);
    return { x: Math.round(x), y: Math.round(y), w: Math.round(w), h: Math.round(h) };
  }
  function savedGeom() {
    try {
      var g = JSON.parse(recall(GEOM_KEY) || 'null');
      if (g && [g.x, g.y, g.w, g.h].every(function (n) { return typeof n === 'number' && isFinite(n); })) { return clampGeom(g); }
    } catch (e) { /* ignore */ }
    return clampGeom(defaultGeom());
  }
  function applyGeom() {
    if (!drawer) { return; }
    var st = drawer.style;
    if (mode === 'float') {
      geom = clampGeom(geom || savedGeom());
      st.left = geom.x + 'px'; st.top = geom.y + 'px'; st.width = geom.w + 'px'; st.height = geom.h + 'px';
    } else {
      st.left = ''; st.top = ''; st.width = ''; st.height = '';
    }
  }
  function syncDock() {
    var open = drawerOpen();
    if (drawer) {
      drawer.classList.toggle('ix-float', mode === 'float');
      drawer.classList.toggle('ix-pinned', mode === 'dock');
    }
    document.documentElement.classList.toggle('ix-docked', open && mode === 'dock' && (!mqWide || mqWide.matches));
    document.documentElement.classList.toggle('ix-drawer-open', open);
    if (dockBtn) {
      clear(dockBtn);
      dockBtn.appendChild(icon(mode === 'dock' ? 'float' : 'dock', 18));
      dockBtn.title = mode === 'dock' ? 'Make it a small floating window' : 'Dock beside the page';
      dockBtn.setAttribute('aria-label', dockBtn.title);
      dockBtn.setAttribute('aria-pressed', mode === 'dock' ? 'true' : 'false');
    }
    if (launcher) { launcher.hidden = open || onInfosecPage(); }
  }
  function setMode(m) {
    mode = m === 'dock' ? 'dock' : 'float';
    remember(MODE_KEY, mode);
    applyGeom();
    syncDock();
  }
  function setDockWidth(px) {
    var w = Math.round(Math.max(320, Math.min(720, px, window.innerWidth - 420)));
    document.documentElement.style.setProperty('--ix-dock-w', w + 'px');
    return w;
  }

  // dragging: the title bar moves the floating window; the edge and corner handles resize it; in docked mode
  // the left edge handle sets the panel width
  var drag = null;
  function startDrag(ev, dir, target) {
    if (ev.button !== 0) { return; }
    if (dir === 'dock') {
      if (mode !== 'dock') { return; }
    } else {
      if (mode !== 'float') { return; }
      if (dir === 'move' && ev.target.closest && ev.target.closest('button, a, input, textarea')) { return; }
      geom = clampGeom(geom || savedGeom());
    }
    drag = { dir: dir, id: ev.pointerId, sx: ev.clientX, sy: ev.clientY, g: geom ? { x: geom.x, y: geom.y, w: geom.w, h: geom.h } : null };
    try { target.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
    document.documentElement.style.setProperty('--ix-cursor', dir === 'dock' ? 'ew-resize' : RZ_CURSOR[dir]);
    document.documentElement.classList.add('ix-resizing');
    ev.preventDefault();
  }
  function onDragMove(ev) {
    if (!drag || ev.pointerId !== drag.id) { return; }
    if (drag.dir === 'dock') { drag.w = setDockWidth(window.innerWidth - ev.clientX); return; }
    var vw = window.innerWidth, vh = window.innerHeight, d = drag.dir, g = drag.g;
    var dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
    var minW = Math.min(MIN_W, vw - 2 * EDGE), minH = Math.min(MIN_H, vh - 2 * EDGE);
    var left = g.x, top = g.y, right = g.x + g.w, bottom = g.y + g.h;
    if (d === 'move') {
      geom = clampGeom({ x: g.x + dx, y: g.y + dy, w: g.w, h: g.h });
    } else {
      // move only the edges being dragged; the opposite edges stay put
      if (d.indexOf('w') >= 0) { left = Math.min(Math.max(EDGE, g.x + dx), right - minW); }
      if (d.indexOf('e') >= 0) { right = Math.max(Math.min(vw - EDGE, right + dx), left + minW); }
      if (d.indexOf('n') >= 0) { top = Math.min(Math.max(EDGE, g.y + dy), bottom - minH); }
      if (d.indexOf('s') >= 0) { bottom = Math.max(Math.min(vh - EDGE, bottom + dy), top + minH); }
      geom = { x: Math.round(left), y: Math.round(top), w: Math.round(right - left), h: Math.round(bottom - top) };
    }
    applyGeom();
  }
  function endDrag(ev) {
    if (!drag || (ev && ev.pointerId !== drag.id)) { return; }
    if (drag.dir === 'dock') { if (drag.w) { remember(DOCK_W_KEY, String(drag.w)); } } else if (geom) { remember(GEOM_KEY, JSON.stringify(geom)); }
    drag = null;
    document.documentElement.classList.remove('ix-resizing');
    document.documentElement.style.removeProperty('--ix-cursor');
  }

  function buildDrawer() {
    drawerView = createChatView({ compact: true });
    var closeBtn = el('button', { cls: 'ix-icon-btn', attrs: { type: 'button', 'aria-label': 'Close the INFOSEC copilot' } }, icon('close', 18));
    closeBtn.title = 'Close';
    closeBtn.addEventListener('click', function () { closeDrawer(); });
    var fullBtn = el('button', { cls: 'ix-icon-btn', attrs: { type: 'button', 'aria-label': 'Open INFOSEC full page with all saved chats' } }, icon('expand', 18));
    fullBtn.title = 'Full page: all saved chats and questions';
    fullBtn.addEventListener('click', function () { go('#/infosec'); });
    var newBtn = el('button', { cls: 'ix-icon-btn', attrs: { type: 'button', 'aria-label': 'Start a new chat' } }, icon('plus', 18));
    newBtn.title = 'New chat (the current one stays saved)';
    newBtn.addEventListener('click', function () { Chat.startNew(); drawerView.focus(); });
    var histBtn = el('button', { cls: 'ix-icon-btn', attrs: { type: 'button', 'aria-label': 'Saved chats', 'aria-expanded': 'false' } }, icon('history', 18));
    histBtn.title = 'Saved chats';
    dockBtn = el('button', { cls: 'ix-icon-btn', attrs: { type: 'button' } });
    dockBtn.addEventListener('click', function () { setMode(mode === 'dock' ? 'float' : 'dock'); });
    drawerHist = chatList({ limit: 12, onOpen: function () { toggleHist(false); drawerView.focus(); } });
    histPanel = el('div', { cls: 'ix-dock-hist', hidden: true }, [
      el('div', { cls: 'ix-dock-hist-head' }, [el('b', { text: 'Saved chats' }), routeLink('#/infosec', 'All chats & questions')]),
      drawerHist.root
    ]);
    function toggleHist(show) {
      var open = typeof show === 'boolean' ? show : histPanel.hidden;
      histPanel.hidden = !open;
      histBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      histBtn.classList.toggle('is-on', open);
      if (open) { Chat.refreshList(); }
    }
    histBtn.addEventListener('click', function () { toggleHist(); });
    Chat.on('change', function () { newBtn.disabled = Chat.busy; });

    var dockHandle = el('div', { cls: 'ix-dock-resize', title: 'Drag to resize', attrs: { 'aria-hidden': 'true' } });
    dockHandle.addEventListener('pointerdown', function (ev) { startDrag(ev, 'dock', dockHandle); });
    var handles = RZ_DIRS.map(function (dir) {
      var h = el('div', { cls: 'ix-rz ix-rz-' + dir, attrs: { 'aria-hidden': 'true' } });
      h.addEventListener('pointerdown', function (ev) { startDrag(ev, dir, h); });
      return h;
    });
    var head = el('header', { cls: 'ix-drawer-head' }, [
      el('div', { cls: 'ix-brand' }, [
        el('span', { cls: 'ix-brand-icon', attrs: { 'aria-hidden': 'true' } }, icon('shield', 22)),
        el('div', null, [el('div', { cls: 'ix-brand-name', text: 'INFOSEC' }), el('div', { cls: 'ix-brand-sub' }, [statusPill()])])
      ]),
      el('div', { cls: 'ix-head-actions' }, [histBtn, newBtn, dockBtn, fullBtn, closeBtn])
    ]);
    head.addEventListener('pointerdown', function (ev) { startDrag(ev, 'move', head); });
    head.addEventListener('dblclick', function (ev) {
      if (mode !== 'float' || (ev.target.closest && ev.target.closest('button, a'))) { return; }
      geom = clampGeom(defaultGeom());
      applyGeom();
      remember(GEOM_KEY, JSON.stringify(geom));
    });

    drawer = el('aside', { cls: 'ix-drawer', attrs: { id: 'bvs-infosec-drawer', role: 'complementary', 'aria-label': 'INFOSEC copilot', 'aria-hidden': 'true' } },
      [dockHandle].concat(handles, [head, histPanel, drawerView.root]));
    drawer.addEventListener('pointermove', onDragMove);
    drawer.addEventListener('pointerup', endDrag);
    drawer.addEventListener('pointercancel', endDrag);
    drawer.addEventListener('lostpointercapture', endDrag);
    drawer.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') {
        ev.stopPropagation();
        if (!histPanel.hidden) { toggleHist(false); } else { closeDrawer(); }
      }
    });
    document.body.appendChild(drawer);
    var w = parseInt(recall(DOCK_W_KEY) || '', 10);
    if (w) { setDockWidth(w); }
    applyGeom();
  }
  window.addEventListener('resize', function () {
    if (drawer && mode === 'float' && geom) { geom = clampGeom(geom); applyGeom(); }
  });

  function openDrawer() {
    if (!drawer) { buildDrawer(); }
    applyGeom();
    drawer.classList.add('ix-open');
    drawer.setAttribute('aria-hidden', 'false');
    remember(DOCK_KEY, '1');
    syncDock();
  }
  function closeDrawer(opts) {
    if (!drawer) { return; }
    var hadFocus = drawer.contains(document.activeElement);
    drawer.classList.remove('ix-open');
    drawer.setAttribute('aria-hidden', 'true');
    if (!(opts && opts.keepWanted)) { remember(DOCK_KEY, '0'); dockWanted = false; }
    syncDock();
    if (hadFocus && launcher && !launcher.hidden) { try { launcher.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  function buildLauncher() {
    launcher = el('button', { cls: 'ix-launch', attrs: { type: 'button', 'aria-label': 'Open the INFOSEC copilot' } }, [
      el('span', { cls: 'ix-launch-ico', attrs: { 'aria-hidden': 'true' } }, icon('shield', 18)),
      el('span', { text: 'INFOSEC' }),
      el('span', { cls: 'ix-launch-dot', attrs: { 'aria-hidden': 'true' } })
    ]);
    launcher.title = 'INFOSEC copilot: ask about anything while you browse the tabs';
    launcher.addEventListener('click', function () { openDrawer(); setTimeout(function () { drawerView.focus(); }, 60); });
    Chat.on('change', function () { launcher.classList.toggle('ix-busy', Chat.busy); });
    document.body.appendChild(launcher);
    syncDock();
  }

  function go(route) {
    if (typeof App.navigate === 'function') { App.navigate(route); } else { location.hash = route; }
  }

  // where: undefined/'copilot' -> the copilot window (or the page when it is showing),
  //        'page' -> the INFOSEC page, 'auto' -> the copilot when it is open, else the page
  function openInfosec(opts) {
    opts = opts || {};
    var onPage = !!(pageView && document.contains(pageView.root));
    if (!onPage && (opts.where === 'page' || (opts.where === 'auto' && !drawerOpen()))) {
      App.pendingInfosec = opts;
      go('#/infosec');
      return null;
    }
    if (opts.context) { Chat.setContext(opts.context); }
    if (Array.isArray(opts.transcript) && opts.transcript.length) { Chat.append(opts.transcript); }
    var view = onPage ? pageView : null;
    if (!view) { openDrawer(); view = drawerView; }
    var prefill = opts.prefill;
    var hasEntities = opts.context && Array.isArray(opts.context.entities) && opts.context.entities.length;
    if (!prefill && hasEntities && !opts.transcript) { prefill = 'Explain this to me: what is it, does it matter, and what should I do?'; }
    if (opts.send && prefill && !Chat.busy) { Chat.send(prefill, opts.preset || null, { via: opts.via }); }
    else if (prefill) { view.setPrefill(prefill); }
    setTimeout(function () { view.focus(); }, 60);
    return view;
  }

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape' && drawerOpen() && drawer.contains(document.activeElement) && !(window.BVSScanner && window.BVSScanner.active())) {
      closeDrawer();
    }
  });
  window.addEventListener('hashchange', function () {
    if (onInfosecPage()) {
      if (drawerOpen()) { dockWanted = true; closeDrawer({ keepWanted: true }); }
    } else if (dockWanted) {
      dockWanted = false;
      openDrawer();
    }
    syncDock();
  });
  if (mqWide) {
    if (mqWide.addEventListener) { mqWide.addEventListener('change', syncDock); } else if (mqWide.addListener) { mqWide.addListener(syncDock); }
  }

  // ------------------------------------------------------------------------------ full page view
  function glossaryCard() {
    var list = el('dl', { cls: 'ix-gloss-list' });
    var search = el('input', { cls: 'ix-gloss-search', attrs: { type: 'search', placeholder: 'Look up a word (e.g. token, NetBIOS)…', 'aria-label': 'Search the glossary' } });
    var more = el('button', { cls: 'ix-mini', attrs: { type: 'button' }, text: 'Show all' });
    var showAll = false;
    function render() {
      clear(list);
      var q = search.value.trim().toLowerCase();
      var all = Array.isArray(window.BVS_GLOSSARY) ? window.BVS_GLOSSARY : [];
      var hits = all.filter(function (e) {
        if (!q) { return true; }
        return [e.term].concat(e.aliases || []).some(function (n) { return String(n).toLowerCase().indexOf(q) >= 0; }) || String(e.plain).toLowerCase().indexOf(q) >= 0;
      });
      var shown = showAll || q ? hits : hits.slice(0, 8);
      shown.forEach(function (e) {
        list.appendChild(el('dt', { text: e.term }));
        list.appendChild(el('dd', null, [el('span', { text: e.plain }), e.example ? el('span', { cls: 'ix-gloss-ex', text: ' Example: ' + e.example }) : null]));
      });
      if (!hits.length) { list.appendChild(el('dd', { cls: 'ix-muted', text: 'No match. Ask INFOSEC instead: it can explain any word in context.' })); }
      more.hidden = !!q || showAll || hits.length <= 8;
    }
    search.addEventListener('input', render);
    search.addEventListener('keydown', function (ev) { ev.stopPropagation(); });
    more.addEventListener('click', function () { showAll = true; render(); });
    render();
    return el('section', { cls: 'ix-card', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-glossary', 'data-bvs-label': 'Glossary' } }, [
      el('h2', { cls: 'ix-card-title' }, [icon('book', 18), el('span', { text: 'Glossary: plain-English words' })]),
      search, list, more
    ]);
  }

  var pageParts = [];
  function mountPage(rootEl, params) {
    clear(rootEl);
    unmountPage();
    if (drawerOpen()) { dockWanted = true; closeDrawer({ keepWanted: true }); }
    syncDock();
    pageView = createChatView({ presets: false });

    var chats = chatList({ onOpen: function () { if (pageView) { pageView.focus(); } } });
    var questions = questionList(function (x, again) {
      if (again) { Chat.send(x.text, null); return; }
      Chat.open(x.chat.id).then(function () { if (pageView) { setTimeout(function () { pageView.scrollToQuestion(x.ts); }, 30); } });
    });
    pageParts = [chats, questions];
    var newChat = el('button', { cls: 'ix-mini', attrs: { type: 'button' } }, [icon('plus', 14), el('span', { text: 'New chat' })]);
    newChat.addEventListener('click', function () { Chat.startNew(); if (pageView) { pageView.focus(); } });
    var chatsCard = el('section', { cls: 'ix-card ix-card-hist', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-saved-chats', 'data-bvs-label': 'Saved chats' } }, [
      el('div', { cls: 'ix-card-head' }, [el('h2', { cls: 'ix-card-title' }, [icon('history', 18), el('span', { text: 'Saved chats' })]), newChat]),
      el('p', { cls: 'ix-card-sub', text: 'Every conversation is saved on this PC. Click one to continue it.' }),
      searchBox('Search saved chats…', chats.filter),
      chats.root
    ]);
    var questionsCard = el('section', { cls: 'ix-card ix-card-hist', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-questions', 'data-bvs-label': 'Questions you asked' } }, [
      el('h2', { cls: 'ix-card-title' }, [icon('question', 18), el('span', { text: 'Questions you asked' })]),
      el('p', { cls: 'ix-card-sub', text: 'Newest first, from every chat, including the ones asked from the scanner.' }),
      searchBox('Search your questions…', questions.filter),
      questions.root
    ]);

    var presetCard = el('section', { cls: 'ix-card', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-presets', 'data-bvs-label': 'Quick questions' } }, [
      el('h2', { cls: 'ix-card-title' }, [icon('spark', 18), el('span', { text: 'Quick questions' })])
    ]);
    var grid = el('div', { cls: 'ix-preset-grid' });
    PRESETS.forEach(function (p) {
      var b = el('button', { cls: 'ix-preset', attrs: { type: 'button' }, on: { click: function () { Chat.send(p.label, p.id); } } }, [
        el('span', { cls: 'ix-preset-icon', attrs: { 'aria-hidden': 'true' } }, icon(p.icon, 18)), el('span', { text: p.label })
      ]);
      grid.appendChild(b);
    });
    var offPresets = Chat.on('change', function () { Array.prototype.forEach.call(grid.children, function (b) { b.disabled = Chat.busy; }); });
    pageParts.push({ destroy: offPresets });
    presetCard.appendChild(grid);

    var scanCard = el('section', { cls: 'ix-card ix-card-scan' }, [
      el('h2', { cls: 'ix-card-title' }, [icon('scan', 18), el('span', { text: 'Scan & explain anything' })]),
      el('p', { text: 'Press S (or the glowing round button at the top) and drag over any part of the dashboard, then pick a question. It opens here in INFOSEC (or in the copilot, if it is open) and is saved with your chats.' }),
      el('p', { cls: 'ix-muted', text: 'No screenshot is taken: it reads the page\'s own text, so it needs no permissions.' })
    ]);
    var copilotCard = el('section', { cls: 'ix-card ix-card-scan' }, [
      el('h2', { cls: 'ix-card-title' }, [icon('chat', 18), el('span', { text: 'INFOSEC copilot' })]),
      el('p', { text: 'Want INFOSEC next to the Overview, Storage or any other tab? Click the yellow INFOSEC button at the bottom right of any page: the copilot opens beside it, keeps this same chat and stays open while you switch tabs.' })
    ]);

    var hero = el('header', { cls: 'ix-hero', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-hero', 'data-bvs-label': 'INFOSEC' } }, [
      el('div', { cls: 'ix-hero-icon', attrs: { 'aria-hidden': 'true' } }, icon('shield', 40)),
      el('div', { cls: 'ix-hero-text' }, [
        el('h1', { text: 'INFOSEC' }),
        el('p', { text: 'Your built-in security explainer. Ask what anything means, why it matters and what to do: INFOSEC reads this scan, puts the dots together and walks you through it.' }),
        el('div', { cls: 'ix-hero-meta' }, [statusPill(), el('span', { cls: 'ix-hero-privacy', text: PRIVACY })])
      ])
    ]);

    rootEl.appendChild(el('div', { cls: 'ix-page' }, [
      hero,
      el('div', { cls: 'ix-grid' }, [
        el('section', { cls: 'ix-card ix-card-chat', attrs: { 'data-bvs-type': 'section', 'data-bvs-section': 'infosec-chat', 'data-bvs-label': 'INFOSEC chat' } }, pageView.root),
        el('div', { cls: 'ix-side' }, [chatsCard, questionsCard, presetCard, scanCard, copilotCard, glossaryCard()])
      ])
    ]));
    Chat.refreshList();
    var q = params && (params.q || (params.query && params.query.q));
    if (q && typeof q === 'string') { pageView.setPrefill(q.slice(0, 500)); }
    if (App.pendingInfosec) {
      var pend = App.pendingInfosec;
      App.pendingInfosec = null;
      if (pend.context) { Chat.setContext(pend.context); }
      if (Array.isArray(pend.transcript) && pend.transcript.length) { Chat.append(pend.transcript); }
      if (pend.send && pend.prefill && !Chat.busy) { Chat.send(String(pend.prefill).slice(0, 4000), pend.preset || null, { via: pend.via }); }
      else if (pend.prefill) { pageView.setPrefill(String(pend.prefill).slice(0, 2000)); }
    }
    setTimeout(function () { if (pageView) { pageView.focus(); } }, 80);
  }

  function unmountPage() {
    pageParts.forEach(function (p) { if (p && typeof p.destroy === 'function') { p.destroy(); } });
    pageParts = [];
    if (pageView) { pageView.destroy(); pageView = null; }
    syncDock();
  }

  // ------------------------------------------------------------------------------ wire up
  Chat.init();
  App.askImpl = askImpl;
  if (typeof App.ask !== 'function') { App.ask = function (question, context, onEvent, signal) { return askImpl(question, context, onEvent, signal); }; }
  App.openInfosec = openInfosec;
  App.closeInfosec = closeDrawer;

  window.BVSInfosec = {
    ACCENT: ACCENT, PRIVACY: PRIVACY, OFFLINE_HINT: OFFLINE_HINT, PRESETS: PRESETS,
    renderMarkdown: renderMarkdown, explainOffline: explainOffline, glossaryLookup: glossaryLookup,
    askImpl: askImpl, getStatus: getStatus, copy: copyToClipboard, icon: icon, open: openInfosec, close: closeDrawer,
    openCopilot: function () { openDrawer(); }, copilotOpen: drawerOpen,
    chat: Chat
  };

  if (typeof App.registerView === 'function') {
    App.registerView('infosec', {
      title: 'INFOSEC', group: 'tools', accent: ACCENT,
      icon: App.icons && App.icons.infosec ? 'infosec' : 'M12 2.5l7.5 3v5.7c0 4.9-3.2 9.1-7.5 10.3-4.3-1.2-7.5-5.4-7.5-10.3V5.5z M8.6 12.2l2.4 2.4 4.4-4.6',
      mount: mountPage,
      unmount: unmountPage
    });
  }

  function startUi() {
    buildLauncher();
    if (recall(DOCK_KEY) === '1') {
      if (onInfosecPage()) { dockWanted = true; } else { openDrawer(); }
    }
  }
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', startUi); } else { startUi(); }
})();
