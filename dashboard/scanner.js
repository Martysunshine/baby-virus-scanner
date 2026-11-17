/* baby-virus-scanner dashboard: "Scan & explain" scanner + INFOSEC copilot (agent UI-C).
 *
 * Press S (or the glowing round button in #bvs-scanner-slot) and drag over any part of the page.
 * The scanner reads the page's OWN visible text inside the frame plus the data-bvs-type/id/label/
 * section hooks of the elements there (no screen capture, no permissions), plays a scan-line sweep,
 * and opens a card with quick questions. Asking hands the question plus that part over to INFOSEC
 * (BVSApp.openInfosec, where: 'auto'): the copilot when it is open, else the INFOSEC page.
 *
 * SAFETY: text only (createElement/textContent). The overlay is removed from the DOM on Esc, close,
 * route change or any error, so it can never keep blocking the page. */
(function () {
  'use strict';

  var U = window.BVSUI && window.BVSUI.util;
  if (!U) { return; }
  var el = U.el, clear = U.clear;
  var App = window.BVSApp = window.BVSApp || {};

  var MAX_TEXT = 4000;
  var MAX_ENTITIES = 12;
  var ENTITY_TYPES = ['finding', 'storageItem', 'question', 'fix', 'file', 'tile', 'section'];
  var OURS = '.sx-overlay, .sx-copilot, .sx-frame, .sx-btn, .ix-drawer, .ix-launch';
  var CHIPS = [
    { id: 'explain', label: 'What does this mean?' },
    { id: 'eli5', label: "Explain like I'm a high-schooler" },
    { id: 'danger', label: 'Is this dangerous?' },
    { id: 'what-do', label: 'What should I do?' },
    { id: 'how-use-part', label: 'How do I use this part?' },
    { id: 'connect-dots', label: 'Connect the dots' }
  ];
  var PRIVATE_NOTE = "Private by design: no screenshot is taken. The scanner reads the page's own text, so it needs no permissions. Nothing is sent until you ask.";

  function IX() { return window.BVSInfosec || null; }
  function reducedMotion() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
  function clip(s, n) { s = s === null || s === undefined ? '' : String(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function route() { return (location.hash && location.hash.length > 1 ? location.hash : '#/overview').slice(0, 200); }

  var SVGNS = 'http://www.w3.org/2000/svg';
  function svg(paths, size, cls) {
    var s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('width', String(size));
    s.setAttribute('height', String(size));
    s.setAttribute('fill', 'none');
    s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '2');
    s.setAttribute('stroke-linecap', 'round');
    s.setAttribute('stroke-linejoin', 'round');
    s.setAttribute('aria-hidden', 'true');
    s.setAttribute('focusable', 'false');
    if (cls) { s.setAttribute('class', cls); }
    paths.forEach(function (d) { var p = document.createElementNS(SVGNS, 'path'); p.setAttribute('d', d); s.appendChild(p); });
    return s;
  }
  var P_SCAN = ['M4 8V4h4', 'M16 4h4v4', 'M20 16v4h-4', 'M8 20H4v-4', 'M3 12h18'];
  var P_CLOSE = ['M6 6l12 12', 'M18 6L6 18'];
  var P_SEND = ['M4 12l16-8-6 16-2.5-6.5z', 'M11.5 13.5L20 4'];
  var P_SHIELD = ['M12 2.5l7.5 3v5.7c0 4.9-3.2 9.1-7.5 10.3-4.3-1.2-7.5-5.4-7.5-10.3V5.5z', 'M8.6 12.2l2.4 2.4 4.4-4.6'];
  var P_COPY = ['M9 9h10v11H9z', 'M5 15V4h10'];
  var P_ARROW = ['M5 12h14', 'M13 6l6 6-6 6'];

  // ------------------------------------------------------------------------------ state
  var S = {
    mode: 'idle',        // idle | scanning | copilot
    overlay: null, selBox: null, sizeLabel: null, hint: null,
    start: null, dragging: false, pointerId: null,
    frame: null, copilot: null, capture: null, demo: false
  };
  var btn = null;

  // ------------------------------------------------------------------------------ button
  function makeButton() {
    var b = el('button', { cls: 'sx-btn', attrs: { type: 'button', 'aria-label': 'Scan & explain (S)', 'aria-keyshortcuts': 'S', 'aria-pressed': 'false' } }, [
      el('span', { cls: 'sx-btn-ring', attrs: { 'aria-hidden': 'true' } }),
      el('span', { cls: 'sx-btn-core', attrs: { 'aria-hidden': 'true' } }, svg(P_SCAN, 20)),
      el('span', { cls: 'sx-tip', attrs: { role: 'tooltip' } }, ['Scan & explain ', el('kbd', { text: 'S' })])
    ]);
    b.addEventListener('click', function (ev) { ev.preventDefault(); toggle(); });
    return b;
  }

  function placeButton() {
    var slot = document.getElementById('bvs-scanner-slot');
    if (slot) {
      if (btn.parentNode !== slot) { slot.appendChild(btn); }
      btn.classList.remove('sx-floating');
      return true;
    }
    return false;
  }

  function mountButton() {
    btn = makeButton();
    if (placeButton()) { return; }
    var placedFloating = false;
    var obs = null;
    if (typeof MutationObserver === 'function') {
      obs = new MutationObserver(function () { if (placeButton() && obs) { obs.disconnect(); obs = null; } });
      obs.observe(document.body, { childList: true, subtree: true });
    }
    setTimeout(function () {
      if (!btn.parentNode) { btn.classList.add('sx-floating'); document.body.appendChild(btn); placedFloating = true; }
    }, 2500);
    setTimeout(function () { if (obs) { obs.disconnect(); obs = null; } }, 20000);
    return placedFloating;
  }

  // ------------------------------------------------------------------------------ scan mode
  function toggle() {
    if (S.mode === 'scanning') { cancelScan(); } else { startScan(); }
  }

  function startScan() {
    closeCopilot(true);
    removeOverlay();
    S.mode = 'scanning';
    S.selBox = el('div', { cls: 'sx-sel', hidden: true }, [
      el('span', { cls: 'sx-c sx-c-tl' }), el('span', { cls: 'sx-c sx-c-tr' }),
      el('span', { cls: 'sx-c sx-c-bl' }), el('span', { cls: 'sx-c sx-c-br' }),
      S.sizeLabel = el('span', { cls: 'sx-size', text: '0 × 0' })
    ]);
    S.hint = el('div', { cls: 'sx-hint', attrs: { role: 'status' } }, [
      el('span', { cls: 'sx-hint-icon', attrs: { 'aria-hidden': 'true' } }, svg(P_SCAN, 16)),
      el('span', { text: 'Drag over anything you want explained' }),
      el('span', { cls: 'sx-hint-keys' }, [el('kbd', { text: 'Esc' }), ' to cancel'])
    ]);
    S.overlay = el('div', { cls: 'sx-overlay', attrs: { tabindex: '-1', role: 'application', 'aria-label': 'Scan mode: drag over the part of the page you want explained. Press Escape to cancel.' } }, [
      el('div', { cls: 'sx-grid', attrs: { 'aria-hidden': 'true' } }),
      el('div', { cls: 'sx-scanline-idle', attrs: { 'aria-hidden': 'true' } }),
      S.hint,
      S.selBox,
      el('div', { cls: 'sx-note', text: PRIVATE_NOTE })
    ]);
    S.overlay.addEventListener('pointerdown', onDown);
    S.overlay.addEventListener('pointermove', onMove);
    S.overlay.addEventListener('pointerup', onUp);
    S.overlay.addEventListener('pointercancel', onCancelPointer);
    S.overlay.addEventListener('contextmenu', function (ev) { ev.preventDefault(); cancelScan(); });
    document.body.appendChild(S.overlay);
    document.documentElement.classList.add('sx-scanning');
    if (btn) { btn.setAttribute('aria-pressed', 'true'); btn.classList.add('sx-active'); }
    try { S.overlay.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
  }

  function removeOverlay() {
    if (S.overlay && S.overlay.parentNode) { S.overlay.parentNode.removeChild(S.overlay); }
    S.overlay = null; S.selBox = null; S.sizeLabel = null; S.hint = null;
    S.dragging = false; S.start = null; S.pointerId = null;
    document.documentElement.classList.remove('sx-scanning');
    if (btn) { btn.setAttribute('aria-pressed', 'false'); btn.classList.remove('sx-active'); }
  }

  function cancelScan() {
    removeOverlay();
    if (S.mode === 'scanning') { S.mode = 'idle'; }
    if (btn && document.contains(btn)) { try { btn.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  function normRect(a, b) {
    var x = Math.max(0, Math.min(a.x, b.x)), y = Math.max(0, Math.min(a.y, b.y));
    var r = Math.min(window.innerWidth, Math.max(a.x, b.x)), btm = Math.min(window.innerHeight, Math.max(a.y, b.y));
    return { x: x, y: y, w: Math.max(0, r - x), h: Math.max(0, btm - y) };
  }

  function drawSel(r) {
    if (!S.selBox) { return; }
    S.selBox.hidden = false;
    S.selBox.style.left = r.x + 'px';
    S.selBox.style.top = r.y + 'px';
    S.selBox.style.width = r.w + 'px';
    S.selBox.style.height = r.h + 'px';
    S.sizeLabel.textContent = Math.round(r.w) + ' × ' + Math.round(r.h);
    S.selBox.classList.toggle('sx-size-below', r.y < 40);
  }

  function onDown(ev) {
    if (ev.button !== 0) { return; }
    ev.preventDefault();
    S.dragging = true;
    S.pointerId = ev.pointerId;
    S.start = { x: ev.clientX, y: ev.clientY };
    try { S.overlay.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
    if (S.hint) { S.hint.classList.add('sx-hint-dim'); }
    drawSel({ x: ev.clientX, y: ev.clientY, w: 0, h: 0 });
  }
  function onMove(ev) {
    if (!S.dragging || ev.pointerId !== S.pointerId) { return; }
    drawSel(normRect(S.start, { x: ev.clientX, y: ev.clientY }));
  }
  function onCancelPointer() {
    S.dragging = false;
    if (S.selBox) { S.selBox.hidden = true; }
    if (S.hint) { S.hint.classList.remove('sx-hint-dim'); }
  }
  function onUp(ev) {
    if (!S.dragging || ev.pointerId !== S.pointerId) { return; }
    S.dragging = false;
    var r = normRect(S.start, { x: ev.clientX, y: ev.clientY });
    if (r.w < 12 && r.h < 12) { r = pickAt(ev.clientX, ev.clientY); }
    if (!r || r.w < 4 || r.h < 4) { onCancelPointer(); return; }
    finish(r);
  }

  // A click (no drag) scans the item under the pointer.
  function pickAt(x, y) {
    var target = null;
    if (S.overlay) { S.overlay.style.pointerEvents = 'none'; }
    try { target = document.elementFromPoint(x, y); } finally { if (S.overlay) { S.overlay.style.pointerEvents = ''; } }
    if (!target || target === document.body || target === document.documentElement || target.closest(OURS)) { return null; }
    var pick = target.closest('[data-bvs-type]') || target;
    var r = pick.getBoundingClientRect();
    if (r.width * r.height > window.innerWidth * window.innerHeight * 0.6) { r = target.getBoundingClientRect(); }
    return normRect({ x: r.left - 4, y: r.top - 4 }, { x: r.right + 4, y: r.bottom + 4 });
  }

  // ------------------------------------------------------------------------------ capture
  function inter(a, b) {
    var w = Math.min(a.right, b.right) - Math.max(a.left, b.left);
    var h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    return w > 0 && h > 0 ? w * h : 0;
  }

  function extract(r) {
    var sel = { left: r.x, top: r.y, right: r.x + r.w, bottom: r.y + r.h };
    var visCache = new Map();
    function visible(elm) {
      if (visCache.has(elm)) { return visCache.get(elm); }
      var ok = true;
      try {
        var cs = window.getComputedStyle(elm);
        ok = cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity || '1') > 0.05;
      } catch (e) { ok = true; }
      visCache.set(elm, ok);
      return ok;
    }
    var pieces = [];
    var seen = new Set();
    var total = 0, visited = 0, truncated = false;
    var range = document.createRange();
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode: function (n) {
        if (!n.nodeValue || !/\S/.test(n.nodeValue)) { return NodeFilter.FILTER_REJECT; }
        var p = n.parentElement;
        if (!p || /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|TEXTAREA|OPTION|TITLE)$/.test(p.tagName)) { return NodeFilter.FILTER_REJECT; }
        if (p.closest(OURS + ', [aria-hidden="true"], [hidden]')) { return NodeFilter.FILTER_REJECT; }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var lastTop = null, lastRight = null, lastParent = null, node;
    while ((node = walker.nextNode())) {
      if (++visited > 40000) { truncated = true; break; }
      range.selectNodeContents(node);
      var rects = range.getClientRects();
      var hit = null;
      for (var i = 0; i < rects.length; i++) {
        var rc = rects[i];
        if (rc.width < 1 || rc.height < 1) { continue; }
        var area = inter(rc, sel);
        if (area > 0 && area >= rc.width * rc.height * 0.25) { hit = rc; break; }
        if (area > 0 && rc.height > 0 && (Math.min(rc.bottom, sel.bottom) - Math.max(rc.top, sel.top)) >= rc.height * 0.5 && rc.width > r.w) { hit = rc; break; }
      }
      if (!hit || !visible(node.parentElement)) { continue; }
      var txt = node.nodeValue.replace(/\s+/g, ' ').trim();
      if (!txt) { continue; }
      if (txt.length > 12 && seen.has(txt)) { continue; }
      seen.add(txt);
      var sep = '';
      if (pieces.length) {
        var sameLine = lastTop !== null && Math.abs(hit.top - lastTop) < 6;
        sep = sameLine ? (node.parentElement === lastParent || hit.left - lastRight < 24 ? ' ' : '  ·  ') : '\n';
      }
      if (pieces.length && pieces[pieces.length - 1] === txt && sep !== '\n') { continue; }
      if (total + sep.length + txt.length > MAX_TEXT) {
        var room = MAX_TEXT - total - sep.length;
        if (room > 20) { pieces.push(sep + txt.slice(0, room - 1) + '…'); }
        truncated = true;
        break;
      }
      pieces.push(sep + txt);
      total += sep.length + txt.length;
      lastTop = hit.top; lastRight = hit.right; lastParent = node.parentElement;
    }
    var text = pieces.join('').replace(/\n{3,}/g, '\n\n').trim();

    // entities: hooks on elements inside the frame, then the containers around it
    var inside = [], around = [], keys = new Set();
    function entityOf(node) {
      var type = node.getAttribute('data-bvs-type');
      var sectionName = node.getAttribute('data-bvs-section');
      if (!type && !sectionName) { return null; }
      if (type && ENTITY_TYPES.indexOf(type) < 0) { type = 'tile'; }
      var secNode = node.closest('[data-bvs-section]');
      var ent = {
        type: type || 'section',
        id: node.getAttribute('data-bvs-id') || (!type ? sectionName : '') || '',
        label: node.getAttribute('data-bvs-label') || clip((node.textContent || '').replace(/\s+/g, ' ').trim(), 70),
        section: (secNode && secNode.getAttribute('data-bvs-section')) || sectionName || ''
      };
      return ent;
    }
    function addEnt(list, ent) {
      if (!ent) { return; }
      var key = ent.type + '|' + (ent.id || ent.label);
      if (keys.has(key)) { return; }
      keys.add(key);
      list.push(ent);
    }
    var hooks = document.querySelectorAll('[data-bvs-type], [data-bvs-section]');
    for (var h = 0; h < hooks.length && inside.length < 40; h++) {
      var hn = hooks[h];
      if (hn.closest(OURS)) { continue; }
      var hr = hn.getBoundingClientRect();
      if (hr.width < 1 || hr.height < 1) { continue; }
      var a = inter(hr, sel);
      if (a > 0 && a >= hr.width * hr.height * 0.4 && visible(hn)) { addEnt(inside, entityOf(hn)); }
    }
    // containers around the centre of the frame
    var centre = null;
    if (S.overlay) { S.overlay.style.pointerEvents = 'none'; }
    try { centre = document.elementFromPoint(r.x + r.w / 2, r.y + r.h / 2); } finally { if (S.overlay) { S.overlay.style.pointerEvents = ''; } }
    var cur = centre && !centre.closest(OURS) ? centre : null;
    while (cur && cur !== document.body) {
      if (cur.hasAttribute && (cur.hasAttribute('data-bvs-type') || cur.hasAttribute('data-bvs-section'))) { addEnt(around, entityOf(cur)); }
      cur = cur.parentElement;
    }
    // specific items first (findings, files...), then tiles, then sections
    var rank = { finding: 0, storageItem: 0, file: 0, question: 1, fix: 1, tile: 2, section: 3 };
    var entities = inside.concat(around).sort(function (x, y) { return (rank[x.type] || 2) - (rank[y.type] || 2); }).slice(0, MAX_ENTITIES);

    // v3 privacy mode: the visible text is already redacted by the views; hook attributes (labels, ids such
    // as file paths) go through the same helper so nothing hidden on screen leaks into a question.
    var pv = App.privacy;
    if (pv && pv.on && typeof pv.text === 'function') {
      text = pv.text(text);
      entities = entities.map(function (e) { return { type: e.type, id: e.id ? pv.text(e.id) : e.id, label: e.label ? pv.text(e.label) : e.label, section: e.section }; });
    }
    var words = text ? text.split(/\s+/).length : 0;
    return { text: text, entities: entities, route: route(), rect: r, words: words, chars: text.length, truncated: truncated };
  }

  // ------------------------------------------------------------------------------ sweep + copilot
  function finish(r) {
    var capture;
    try {
      capture = extract(r);
    } catch (e) {
      capture = { text: '', entities: [], route: route(), rect: r, words: 0, chars: 0 };
    } finally {
      removeOverlay();
    }
    S.mode = 'copilot';
    S.capture = capture;
    showFrame(r, capture);
    var delay = reducedMotion() ? 180 : 950;
    setTimeout(function () {
      if (S.capture !== capture) { return; }
      if (S.frame) { S.frame.classList.remove('sx-sweeping'); S.frame.classList.add('sx-locked'); }
      openCopilot(capture);
    }, delay);
  }

  function showFrame(r, capture) {
    removeFrame();
    S.frame = el('div', { cls: 'sx-frame sx-sweeping' + (reducedMotion() ? ' sx-reduced' : ''), attrs: { 'aria-hidden': 'true' } }, [
      el('span', { cls: 'sx-c sx-c-tl' }), el('span', { cls: 'sx-c sx-c-tr' }),
      el('span', { cls: 'sx-c sx-c-bl' }), el('span', { cls: 'sx-c sx-c-br' }),
      el('div', { cls: 'sx-sweep' }),
      el('div', { cls: 'sx-frame-grid' }),
      el('span', { cls: 'sx-frame-tag', text: 'SCANNED · ' + plural(capture.words, 'word') + (capture.entities.length ? ' · ' + plural(capture.entities.length, 'item') : '') })
    ]);
    S.frame.style.left = r.x + 'px';
    S.frame.style.top = r.y + 'px';
    S.frame.style.width = r.w + 'px';
    S.frame.style.height = r.h + 'px';
    document.body.appendChild(S.frame);
  }

  function removeFrame() {
    if (S.frame && S.frame.parentNode) { S.frame.parentNode.removeChild(S.frame); }
    S.frame = null;
  }

  function plural(n, word) { return n + ' ' + word + (n === 1 ? '' : 's'); }

  function typeName(t) {
    return { finding: 'Finding', storageItem: 'Storage', question: 'Question', fix: 'Fix', file: 'File', tile: 'Tile', section: 'Section' }[t] || 'Item';
  }

  // After a scan the card offers quick questions and a box to type one. Asking hands the question and what
  // was scanned over to INFOSEC (the copilot when it is open, else the INFOSEC page), where the answer
  // streams in and the chat is saved with all the others.
  function openCopilot(capture) {
    closeCopilot(true, true);
    var ix = IX();
    var input = el('input', { cls: 'sx-cp-input', attrs: { type: 'text', placeholder: 'Ask about this… e.g. what does this mean?', 'aria-label': 'Ask INFOSEC about the scanned area', autocomplete: 'off', spellcheck: 'true' } });
    var askBtn = el('button', { cls: 'sx-cp-ask', attrs: { type: 'submit', 'aria-label': 'Ask INFOSEC' } }, [svg(P_SEND, 16), el('span', { text: 'Ask' })]);
    var form = el('form', { cls: 'sx-cp-form', attrs: { autocomplete: 'off' } }, [input, askBtn]);
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      handoff(input.value, null);
    });
    input.addEventListener('keydown', function (ev) { if (ev.key !== 'Escape') { ev.stopPropagation(); } });

    var chips = el('div', { cls: 'sx-cp-chips', attrs: { role: 'group', 'aria-label': 'Quick questions about this' } });
    CHIPS.forEach(function (c) {
      chips.appendChild(el('button', { cls: 'sx-chip', attrs: { type: 'button' }, text: c.label, on: { click: function () { handoff(c.label, c.id); } } }));
    });

    // what was captured
    var entChips = el('div', { cls: 'sx-ent-chips' });
    capture.entities.forEach(function (e) {
      entChips.appendChild(el('span', { cls: 'sx-ent sx-ent-' + e.type, title: (e.id ? e.id + ' · ' : '') + (e.label || '') }, [
        el('b', { text: typeName(e.type) }), el('span', { text: clip(e.label || e.id || '', 48) })
      ]));
    });
    var preview = el('div', { cls: 'sx-preview', text: capture.text ? clip(capture.text, 700) : '(No readable text here: INFOSEC will use the items and the page you are on.)' });
    var details = el('details', { cls: 'sx-cp-details' }, [
      el('summary', null, [
        el('span', { cls: 'sx-sum-label', text: 'What I captured' }),
        el('span', { cls: 'sx-sum-meta', text: plural(capture.words, 'word') + (capture.entities.length ? ' · ' + plural(capture.entities.length, 'item') + ' detected' : '') + (capture.truncated ? ' · trimmed' : '') })
      ]),
      capture.entities.length ? entChips : null,
      preview
    ]);

    var copyBtn = el('button', { cls: 'sx-cp-btn', attrs: { type: 'button' } }, [svg(P_COPY, 15), el('span', { text: 'Copy text' })]);
    copyBtn.addEventListener('click', function () {
      var copier = ix && ix.copy ? ix.copy : U.copyText;
      copier(capture.text || '').then(function (ok) {
        copyBtn.lastChild.textContent = ok ? 'Text copied' : 'Copy failed';
        setTimeout(function () { copyBtn.lastChild.textContent = 'Copy text'; }, 1600);
      });
    });
    var inCopilot = !!(ix && ix.copilotOpen && ix.copilotOpen());
    var contBtn = el('button', { cls: 'sx-cp-btn sx-cp-primary', attrs: { type: 'button' } }, [svg(P_SHIELD, 15), el('span', { text: inCopilot ? 'Ask in the copilot' : 'Ask in INFOSEC' }), svg(P_ARROW, 15)]);
    contBtn.addEventListener('click', function () { handoff(input.value, null); });
    var closeBtn = el('button', { cls: 'sx-cp-x', attrs: { type: 'button', 'aria-label': 'Close' } }, svg(P_CLOSE, 16));
    closeBtn.addEventListener('click', function () { closeCopilot(); });

    var head = el('header', { cls: 'sx-cp-head' }, [
      el('span', { cls: 'sx-cp-badge' }, [svg(P_SCAN, 14), el('span', { text: 'SCAN COMPLETE' })]),
      el('span', { cls: 'sx-cp-title' }, [el('b', { text: 'Ask INFOSEC' }), el('span', { text: ' about this' })]),
      closeBtn
    ]);
    var note = (inCopilot ? 'Your question goes to the INFOSEC copilot' : 'Your question opens in INFOSEC') +
      ', where the answer appears as it is written and the chat is saved. No screenshot: it reads the page’s own text.';
    var card = el('div', { cls: 'sx-copilot', attrs: { role: 'dialog', 'aria-label': 'Ask INFOSEC about the scanned area' } }, [
      head,
      el('div', { cls: 'sx-cp-body' }, [chips, form, details]),
      el('footer', { cls: 'sx-cp-foot' }, [
        el('div', { cls: 'sx-cp-actions' }, [contBtn, copyBtn]),
        el('div', { cls: 'sx-cp-note', text: note })
      ])
    ]);
    card.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); closeCopilot(); } });
    makeDraggable(card, head);
    S.copilot = { card: card, input: input };
    document.body.appendChild(card);
    positionCopilot(card, capture.rect);
    S.mode = 'copilot';
    setTimeout(function () { try { input.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }, 30);
  }

  function positionCopilot(card, r) {
    var vw = window.innerWidth, vh = window.innerHeight, m = 12, gap = 16;
    var w = Math.min(420, vw - 2 * m);
    card.style.width = w + 'px';
    card.style.maxHeight = (vh - 2 * m) + 'px';
    var h = Math.min(card.offsetHeight || 420, vh - 2 * m);
    var x, y;
    if (r.x + r.w + gap + w <= vw - m) { x = r.x + r.w + gap; y = r.y; }
    else if (r.x - gap - w >= m) { x = r.x - gap - w; y = r.y; }
    else if (r.y + r.h + gap + h <= vh - m) { x = r.x; y = r.y + r.h + gap; }
    else if (r.y - gap - h >= m) { x = r.x; y = r.y - gap - h; }
    else { x = vw - w - m; y = vh - h - m; }
    x = Math.max(m, Math.min(x, vw - w - m));
    y = Math.max(m, Math.min(y, vh - h - m));
    card.style.left = Math.round(x) + 'px';
    card.style.top = Math.round(y) + 'px';
  }

  function makeDraggable(card, handle) {
    var start = null;
    handle.addEventListener('pointerdown', function (ev) {
      if (ev.button !== 0 || ev.target.closest('button')) { return; }
      start = { x: ev.clientX, y: ev.clientY, left: card.offsetLeft, top: card.offsetTop, id: ev.pointerId };
      try { handle.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
      card.classList.add('sx-dragging');
    });
    handle.addEventListener('pointermove', function (ev) {
      if (!start || ev.pointerId !== start.id) { return; }
      var x = Math.max(0, Math.min(window.innerWidth - 60, start.left + ev.clientX - start.x));
      var y = Math.max(0, Math.min(window.innerHeight - 40, start.top + ev.clientY - start.y));
      card.style.left = x + 'px';
      card.style.top = y + 'px';
    });
    function end() { start = null; card.classList.remove('sx-dragging'); }
    handle.addEventListener('pointerup', end);
    handle.addEventListener('pointercancel', end);
  }

  // keep the card inside the viewport
  function positionKeep() {
    var card = S.copilot && S.copilot.card;
    if (!card) { return; }
    var vh = window.innerHeight, m = 12;
    var rect = card.getBoundingClientRect();
    if (rect.bottom > vh - m) { card.style.top = Math.max(m, vh - m - rect.height) + 'px'; }
  }

  // Hand the question and the scanned area to INFOSEC; the AI consent dialog (if still needed) is shown there.
  function handoff(question, preset) {
    var capture = S.capture;
    if (!capture) { return; }
    question = String(question || '').trim() || 'What does this part of the dashboard mean?';
    var lead = capture.entities[0];
    var ctx = {
      entities: capture.entities, selectionText: capture.text, view: capture.route,
      label: 'Scanned area' + (lead ? ' (' + clip(lead.label || lead.id, 40) + ')' : '')
    };
    closeCopilot(true);
    if (typeof App.openInfosec === 'function') {
      App.openInfosec({ context: ctx, prefill: question, preset: preset || null, send: !S.demo, via: 'from the scanner', where: 'auto' });
    }
  }

  function closeCopilot(silent, keepFrame) {
    if (S.copilot && S.copilot.card.parentNode) { S.copilot.card.parentNode.removeChild(S.copilot.card); }
    S.copilot = null;
    if (!keepFrame) { removeFrame(); S.capture = null; }
    if (S.mode === 'copilot') { S.mode = 'idle'; }
    if (!silent && btn && document.contains(btn)) { try { btn.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  // ------------------------------------------------------------------------------ global keys & safety nets
  function isTyping(t) {
    return !!(t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)));
  }
  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') {
      if (S.mode === 'scanning') { ev.preventDefault(); ev.stopImmediatePropagation(); cancelScan(); return; }
      if (S.copilot) { ev.preventDefault(); ev.stopImmediatePropagation(); closeCopilot(); return; }
      return;
    }
    if ((ev.key === 's' || ev.key === 'S') && !ev.ctrlKey && !ev.metaKey && !ev.altKey && !ev.repeat && !isTyping(ev.target)) {
      ev.preventDefault();
      toggle();
    }
  }, true);
  window.addEventListener('hashchange', function () {
    if (S.mode === 'scanning') { cancelScan(); }
    removeFrame();
  });
  // The scanned frame is fixed to the viewport, so it is dropped when the page under it moves.
  window.addEventListener('scroll', function (ev) {
    if (S.demo || !S.frame || !S.frame.classList.contains('sx-locked')) { return; }
    if (ev.target && ev.target.nodeType === 1 && ev.target.closest && ev.target.closest('.sx-copilot, .ix-drawer')) { return; }
    removeFrame();
  }, true);
  window.addEventListener('resize', function () {
    if (S.dragging) { onCancelPointer(); }
    if (!S.demo && S.frame && S.frame.classList.contains('sx-locked')) { removeFrame(); }
    positionKeep();
  });
  window.addEventListener('blur', function () { if (S.dragging) { onCancelPointer(); } });

  // ------------------------------------------------------------------------------ demo (headless screenshots only)
  function demoParam() {
    var m = /[?&]demo-scan=(\d)/.exec(location.hash || '') || /[?&]demo-scan=(\d)/.exec(location.search || '');
    return m ? parseInt(m[1], 10) : 0;
  }
  function demoRect() {
    var vw = window.innerWidth, vh = window.innerHeight;
    var cands = document.querySelectorAll('[data-bvs-demo-target], [data-bvs-type="tile"], [data-bvs-type="finding"], [data-bvs-type]');
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i];
      if (c.closest(OURS)) { continue; }
      var r = c.getBoundingClientRect();
      if (r.width > 120 && r.height > 40 && r.width < vw * 0.7 && r.height < vh * 0.6 && r.top >= 0 && r.bottom <= vh) {
        return normRect({ x: r.left - 10, y: r.top - 10 }, { x: r.right + 10, y: r.bottom + 10 });
      }
    }
    return { x: Math.round(vw * 0.22), y: Math.round(vh * 0.25), w: Math.round(vw * 0.36), h: Math.round(vh * 0.3) };
  }
  function runDemo(level) {
    S.demo = true;
    var r = demoRect();
    startScan();
    if (S.overlay) { S.overlay.classList.add('sx-demo'); }
    if (level === 1) {
      drawSel(r);
      return;
    }
    finish(r);
  }

  // ------------------------------------------------------------------------------ init
  function init() {
    mountButton();
    var level = demoParam();
    if (level) { setTimeout(function () { runDemo(level); }, 1400); }
  }
  window.BVSScanner = {
    active: function () { return S.mode === 'scanning'; },
    start: startScan, cancel: cancelScan, close: function () { closeCopilot(); },
    extract: extract
  };
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', init); } else { init(); }
})();
