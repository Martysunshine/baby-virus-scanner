/* baby-virus-scanner dashboard: shared helpers.
 * SAFETY: every piece of scan data reaches the DOM through text nodes (textContent /
 * createTextNode). Nothing here ever assigns innerHTML/outerHTML or builds markup strings. */
(function () {
  'use strict';

  var SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
  var SEV_META = {
    critical: { label: 'Critical', glyph: '◆', cls: 'st-critical' },
    high: { label: 'High', glyph: '▲', cls: 'st-serious' },
    medium: { label: 'Medium', glyph: '■', cls: 'st-warning' },
    low: { label: 'Low', glyph: '●', cls: 'st-neutral' },
    info: { label: 'Info', glyph: '○', cls: 'st-neutral' }
  };
  var SAFETY = ['safe', 'safe_after_check', 'review', 'use_tool', 'do_not_touch'];
  var SAFETY_LABEL = {
    safe: 'Safe', safe_after_check: 'Safe after check', review: 'Review', use_tool: 'Use tool',
    do_not_touch: 'Do not touch'
  };
  var VERIFY_META = {
    confirmed: { label: 'Confirmed', glyph: '◉' },
    refuted: { label: 'Refuted', glyph: '⊘' },
    inconclusive: { label: 'Inconclusive', glyph: '◐' },
    unverified: { label: 'Unverified', glyph: '○' }
  };
  var VERDICT_META = {
    COMPROMISED: { label: 'Compromised', glyph: '✖', tone: 'critical' },
    SUSPICIOUS: { label: 'Suspicious', glyph: '▲', tone: 'serious' },
    HARDENING_NEEDED: { label: 'Hardening needed', glyph: '■', tone: 'warning' },
    OK: { label: 'OK', glyph: '✔', tone: 'good' }
  };

  // Make invisible / control / bidi-override characters visible so a hostile file name cannot
  // hide part of itself (for example "invoice‮fdp.exe" displaying as "invoiceexe.pdf").
  var INVISIBLE_RE = /[\u0000-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
  function safeText(value) {
    if (value === null || value === undefined) { return ''; }
    var s = typeof value === 'string' ? value : String(value);
    return s.replace(INVISIBLE_RE, function (ch) {
      var code = ch.charCodeAt(0).toString(16).toUpperCase();
      while (code.length < 4) { code = '0' + code; }
      return '⟦U+' + code + '⟧';
    });
  }

  function text(value) { return document.createTextNode(safeText(value)); }

  // el('div', {cls: 'a b', text: 'x', title: 't', attrs: {role: 'row'}, on: {click: fn}}, [children])
  var SAFE_ATTRS = /^(role|aria-[a-z-]+|tabindex|type|id|for|name|value|placeholder|data-[a-z0-9-]+|colspan|rowspan|scope|width|height|alt|min|max|step|readonly|spellcheck|autocomplete|rows|cols)$/;
  function el(tag, opts, children) {
    var node = document.createElement(tag);
    opts = opts || {};
    if (opts.cls) { node.className = opts.cls; }
    if (opts.text !== undefined && opts.text !== null) { node.textContent = safeText(opts.text); }
    if (opts.title) { node.title = safeText(opts.title); }
    if (opts.attrs) {
      Object.keys(opts.attrs).forEach(function (k) {
        var v = opts.attrs[k];
        if (v === null || v === undefined || v === false) { return; }
        if (!SAFE_ATTRS.test(k)) { throw new Error('attribute not allowed: ' + k); }
        node.setAttribute(k, v === true ? '' : String(v));
      });
    }
    if (opts.hidden) { node.hidden = true; }
    if (opts.disabled) { node.disabled = true; }
    if (opts.on) {
      Object.keys(opts.on).forEach(function (ev) { node.addEventListener(ev, opts.on[ev]); });
    }
    append(node, children);
    return node;
  }

  function append(parent, children) {
    if (children === null || children === undefined) { return parent; }
    if (!Array.isArray(children)) { children = [children]; }
    children.forEach(function (c) {
      if (c === null || c === undefined || c === false) { return; }
      parent.appendChild(typeof c === 'string' || typeof c === 'number' ? text(c) : c);
    });
    return parent;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } return node; }

  // --- formatting ---------------------------------------------------------------------------
  function fmtBytes(n) {
    if (n === null || n === undefined || n === '' || isNaN(n)) { return '—'; }
    n = Number(n);
    if (n < 1024) { return n + ' B'; }
    var units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    var v = n, i = -1;
    do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
    var digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
    return v.toFixed(digits) + ' ' + units[i];
  }

  function fmtNum(n) {
    if (n === null || n === undefined || n === '' || isNaN(n)) { return '—'; }
    return Number(n).toLocaleString('en-US');
  }

  function toDate(value) {
    if (value === null || value === undefined || value === '') { return null; }
    var d;
    if (typeof value === 'number') { d = new Date(value > 1e11 ? value : value * 1000); }
    else {
      var s = String(value);
      var ms = /^\/Date\((-?\d+)/.exec(s);
      d = ms ? new Date(Number(ms[1])) : new Date(s);
    }
    return isNaN(d.getTime()) ? null : d;
  }

  function pad(n) { return n < 10 ? '0' + n : String(n); }
  function fmtDate(value, withTime) {
    var d = toDate(value);
    if (!d) { return '—'; }
    var s = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
    if (withTime) { s += ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
    return s;
  }

  function fmtAge(value, refEpoch) {
    var d = toDate(value);
    if (!d) { return ''; }
    var ref = refEpoch ? refEpoch * 1000 : Date.now();
    var days = Math.max(0, (ref - d.getTime()) / 86400000);
    if (days < 1) { return 'today'; }
    if (days < 60) { return Math.round(days) + ' d ago'; }
    if (days < 730) { return Math.round(days / 30.4) + ' mo ago'; }
    return (days / 365.25).toFixed(1) + ' y ago';
  }

  function pct(part, whole) {
    if (!whole) { return ''; }
    var p = part / whole * 100;
    return (p >= 10 ? p.toFixed(0) : p >= 1 ? p.toFixed(1) : p > 0 ? '<1' : '0') + '%';
  }

  function debounce(fn, ms) {
    var t = null;
    return function () {
      var args = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(self, args); }, ms);
    };
  }

  // --- small components ---------------------------------------------------------------------
  function sevBadge(sev) {
    var m = SEV_META[sev] || SEV_META.info;
    return el('span', { cls: 'sev', title: 'Severity: ' + m.label }, [
      el('span', { cls: 'glyph ' + m.cls, text: m.glyph, attrs: { 'aria-hidden': 'true' } }),
      el('span', { cls: 'label', text: m.label })
    ]);
  }

  function verifyBadge(result) {
    var key = result || 'unverified';
    var m = VERIFY_META[key] || VERIFY_META.unverified;
    return el('span', { cls: 'chip', title: 'Verification: ' + m.label }, [
      el('span', { cls: 'glyph', text: m.glyph, attrs: { 'aria-hidden': 'true' } }), m.label
    ]);
  }

  function safetyBadge(safety) {
    var idx = SAFETY.indexOf(safety);
    if (idx < 0) { idx = 2; safety = 'review'; }
    return el('span', { cls: 'safety', title: 'Safety: ' + SAFETY_LABEL[safety] }, [
      el('span', { cls: 'swatch sw-s' + idx, attrs: { 'aria-hidden': 'true' } }), SAFETY_LABEL[safety]
    ]);
  }

  function flagChips(flags) {
    var wrap = el('span');
    (flags || []).forEach(function (f) {
      var risky = /work_at_risk|unpushed|uncommitted/.test(f);
      wrap.appendChild(el('span', { cls: 'flag' + (risky ? ' risk' : ''), text: risky ? 'work at risk' : String(f).replace(/_/g, ' ') }));
    });
    return wrap;
  }

  // Render any JSON-ish value as a definition list / text, depth-limited. Text only.
  function renderValue(value, depth) {
    depth = depth || 0;
    if (value === null || value === undefined) { return el('span', { cls: 'muted', text: '—' }); }
    if (typeof value !== 'object') { return el('span', { cls: 'break', text: String(value) }); }
    if (depth >= 3) {
      var s;
      try { s = JSON.stringify(value); } catch (e) { s = String(value); }
      return el('code', { cls: 'break', text: s.length > 2000 ? s.slice(0, 2000) + '…' : s });
    }
    if (Array.isArray(value)) {
      if (!value.length) { return el('span', { cls: 'muted', text: '(none)' }); }
      if (value.every(function (v) { return v === null || typeof v !== 'object'; })) {
        return el('span', { cls: 'break', text: value.join(', ') });
      }
      var ul = el('ul', { cls: 'list' });
      value.slice(0, 200).forEach(function (v) { ul.appendChild(el('li', null, renderValue(v, depth + 1))); });
      if (value.length > 200) { ul.appendChild(el('li', { cls: 'muted', text: '… ' + (value.length - 200) + ' more' })); }
      return ul;
    }
    var keys = Object.keys(value);
    if (!keys.length) { return el('span', { cls: 'muted', text: '(empty)' }); }
    var dl = el('dl', { cls: 'kv' });
    keys.slice(0, 200).forEach(function (k) {
      dl.appendChild(el('dt', { text: k }));
      dl.appendChild(el('dd', null, renderValue(value[k], depth + 1)));
    });
    return dl;
  }

  // --- persistence and clipboard ------------------------------------------------------------
  var storage = {
    get: function (key, fallback) {
      try {
        var raw = window.localStorage.getItem(key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch (e) { return fallback; }
    },
    set: function (key, value) {
      try { window.localStorage.setItem(key, JSON.stringify(value)); return true; } catch (e) { return false; }
    },
    remove: function (key) {
      try { window.localStorage.removeItem(key); } catch (e) { /* ignore */ }
    }
  };

  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value).then(function () { return true; }, function () { return false; });
    }
    return Promise.resolve(false);
  }

  window.BVSUI.util = {
    SEVERITIES: SEVERITIES, SEV_META: SEV_META, SAFETY: SAFETY, SAFETY_LABEL: SAFETY_LABEL,
    VERIFY_META: VERIFY_META, VERDICT_META: VERDICT_META,
    safeText: safeText, text: text, el: el, append: append, clear: clear,
    fmtBytes: fmtBytes, fmtNum: fmtNum, fmtDate: fmtDate, fmtAge: fmtAge, toDate: toDate, pct: pct,
    debounce: debounce, sevBadge: sevBadge, verifyBadge: verifyBadge, safetyBadge: safetyBadge,
    flagChips: flagChips, renderValue: renderValue, storage: storage, copyText: copyText
  };
})();
