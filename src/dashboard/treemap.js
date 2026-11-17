/* baby-virus-scanner dashboard: storage treemap.
 * Squarified layout (Bruls, Huizing & van Wijk, 2000) in vanilla JS. Two levels are drawn:
 * the children of the current folder and, inside the larger ones, their children - at most
 * about 400 positioned divs per level. Click to drill down; the breadcrumb goes back up.
 * Subtrees live in separate data files (one per top-level folder) and load on demand.
 * Colour = cleanability (safety), age of the median byte, or category family.
 * All labels are text nodes; nothing is parsed as HTML. */
(function () {
  'use strict';
  var U = window.BVSUI.util;
  var el = U.el;
  var MAX_PER_LEVEL = 400;
  var LABEL_MIN_W = 60, LABEL_MIN_H = 18;
  var MODES = [['safety', 'Cleanability'], ['age', 'Age'], ['category', 'Category']];
  var FLAG_TEXT = {
    'hardlink-heavy': 'Hard-link heavy: sizes count shared files more than once, so real disk use is lower.',
    'onedrive': 'OneDrive folder: online-only files use no local space.',
    'inaccessible': 'Could not be read (access denied); its size is unknown.',
    'reparse': 'Junction or symbolic link: not followed, so its target is not counted here.',
    'user-writable-root': 'Writable by every user.'
  };

  // ---------------------------------------------------------------- squarify
  // values: positive numbers sorted descending. Returns rects in the same order.
  function squarify(values, x, y, w, h) {
    var n = values.length, out = new Array(n);
    if (!n || w <= 0 || h <= 0) { return out; }
    var total = 0;
    for (var t = 0; t < n; t++) { total += values[t]; }
    if (total <= 0) { return out; }
    var scale = (w * h) / total;
    var areas = values.map(function (v) { return v * scale; });
    var i = 0, rx = x, ry = y, rw = w, rh = h;
    function worst(sum, min, max, side) {
      var s2 = sum * sum, w2 = side * side;
      return Math.max((w2 * max) / s2, s2 / (w2 * min));
    }
    while (i < n) {
      var side = Math.min(rw, rh);
      if (side <= 0) {
        for (; i < n; i++) { out[i] = { x: rx, y: ry, w: 0, h: 0 }; }
        break;
      }
      var sum = areas[i], min = areas[i], max = areas[i];
      var best = worst(sum, min, max, side);
      var j = i + 1;
      while (j < n) {
        var a = areas[j];
        var s2 = sum + a, mn = Math.min(min, a), mx = Math.max(max, a);
        var wst = worst(s2, mn, mx, side);
        if (wst > best) { break; }
        sum = s2; min = mn; max = mx; best = wst; j++;
      }
      var k;
      if (rw >= rh) {  // lay the row out as a vertical strip on the left
        var stripW = sum / rh, cy = ry;
        for (k = i; k < j; k++) {
          var hh = areas[k] / stripW;
          out[k] = { x: rx, y: cy, w: stripW, h: hh };
          cy += hh;
        }
        rx += stripW; rw -= stripW;
      } else {          // horizontal strip on top
        var stripH = sum / rw, cx = rx;
        for (k = i; k < j; k++) {
          var ww = areas[k] / stripH;
          out[k] = { x: cx, y: ry, w: ww, h: stripH };
          cx += ww;
        }
        ry += stripH; rh -= stripH;
      }
      i = j;
    }
    return out;
  }

  function joinPath(base, name, sep) {
    if (!base) { return name; }
    return base.charAt(base.length - 1) === sep ? base + name : base + sep + name;
  }

  // ---------------------------------------------------------------- component
  /**
   * opts: {data: treemap dataset, loadChunk(name) -> Promise, items: [storage items],
   *        basket, onItem(item), tooltip: element}
   */
  function Treemap(panel, opts) {
    this.opts = opts;
    this.meta = opts.data.meta || {};
    this.root = opts.data.root;
    this.sep = this.meta.sep || '\\';
    this.stack = [this.root];
    this.mode = U.storage.get('bvs.treemap.mode', 'safety');
    if (!MODES.some(function (m) { return m[0] === this.mode; }, this)) { this.mode = 'safety'; }
    this.nodeInfo = new WeakMap();
    this.items = (opts.items || []).filter(function (it) { return it.path; }).map(function (it) {
      return { item: it, key: this._key(it.path) };
    }, this);
    this._build(panel);
    this.renderAll();
  }

  Treemap.prototype._key = function (p) {
    var s = String(p || '').replace(/[\\/]+$/, '');
    return this.meta.caseInsensitive === false ? s : s.toLowerCase();
  };

  Treemap.prototype._build = function (panel) {
    var self = this;
    var toolbar = el('div', { cls: 'map-toolbar' });
    this.modeGroup = el('div', { cls: 'segmented', attrs: { role: 'group', 'aria-label': 'Colour by' } });
    MODES.forEach(function (m) {
      var b = el('button', { text: m[1], attrs: { type: 'button', 'aria-pressed': String(self.mode === m[0]) } });
      b.addEventListener('click', function () {
        self.mode = m[0];
        U.storage.set('bvs.treemap.mode', self.mode);
        Array.prototype.forEach.call(self.modeGroup.children, function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        self.renderAll();
      });
      self.modeGroup.appendChild(b);
    });
    this.upBtn = el('button', { cls: 'btn small', text: '↑ Up', attrs: { type: 'button' } });
    this.upBtn.addEventListener('click', function () { self.up(); });
    this.crumbs = el('nav', { cls: 'breadcrumb', attrs: { 'aria-label': 'Folder path' } });
    toolbar.appendChild(el('span', { cls: 'muted', text: 'Colour by' }));
    toolbar.appendChild(this.modeGroup);
    toolbar.appendChild(this.upBtn);
    toolbar.appendChild(this.crumbs);
    this.legend = el('div', { cls: 'legend', attrs: { 'aria-label': 'Legend' } });
    var layout = el('div', { cls: 'map-layout' });
    var left = el('div', { cls: 'side' });
    var wrap = el('div', { cls: 'tm-wrap' });
    this.tm = el('div', { cls: 'tm', attrs: { role: 'img' } });
    wrap.appendChild(this.tm);
    left.appendChild(wrap);
    this.note = el('p', { cls: 'muted' });
    left.appendChild(this.note);
    this.side = el('div', { cls: 'side' });
    layout.appendChild(left);
    layout.appendChild(this.side);
    panel.appendChild(toolbar);
    panel.appendChild(this.legend);
    panel.appendChild(layout);

    this.tm.addEventListener('pointermove', function (ev) { self._hover(ev); });
    this.tm.addEventListener('pointerleave', function () { self._hideTip(); });
    this.tm.addEventListener('click', function (ev) {
      var div = ev.target.closest('.tm-node');
      if (!div) { return; }
      var info = self.nodeInfo.get(div);
      if (!info) { return; }
      self._hideTip();
      if (info.level === 2) { self.drill([info.parent, info.node]); } else { self.drill([info.node]); }
    });
    if (window.ResizeObserver) {
      var lastW = 0, lastH = 0;
      var onResize = U.debounce(function () {
        var w = self.tm.clientWidth, h = self.tm.clientHeight;
        if (w !== lastW || h !== lastH) { lastW = w; lastH = h; self.renderMap(); }
      }, 120);
      new ResizeObserver(onResize).observe(this.tm);
    }
  };

  Treemap.prototype.current = function () { return this.stack[this.stack.length - 1]; };

  Treemap.prototype.pathAt = function (index) {
    var p = this.meta.rootPath || '';
    for (var i = 1; i <= index; i++) { p = joinPath(p, this.stack[i].n, this.sep); }
    return p || this.root.n;
  };

  Treemap.prototype.inherited = function () {
    var s = null, c = null, sFrom = null, cFrom = null;
    for (var i = 0; i < this.stack.length; i++) {
      var n = this.stack[i];
      if (n.s !== undefined && n.s !== null) { s = n.s; sFrom = i; }
      if (n.c !== undefined && n.c !== null) { c = n.c; cFrom = i; }
    }
    return { s: s, c: c, sFrom: sFrom, cFrom: cFrom };
  };

  function childInherit(node, inh) {
    return {
      s: node.s !== undefined && node.s !== null ? node.s : inh.s,
      c: node.c !== undefined && node.c !== null ? node.c : inh.c
    };
  }

  Treemap.prototype.colorClass = function (node, inh) {
    var pseudo = !!node.y;
    var eff = childInherit(node, inh);
    if (this.mode === 'safety') {
      if (eff.s === null || eff.s === undefined) { return pseudo ? 'tm-more' : 'tm-un'; }
      return 'tm-s' + eff.s;
    }
    if (this.mode === 'age') {
      if (pseudo || node.a === undefined || node.a === null || node.a < 0) { return pseudo ? 'tm-more' : 'tm-un'; }
      return 'tm-a' + node.a;
    }
    if (eff.c === null || eff.c === undefined) { return pseudo ? 'tm-more' : 'tm-un'; }
    var fam = (this.meta.catFamily || [])[eff.c];
    return fam === 0 || fam === 1 || fam === 2 ? 'tm-c' + fam : 'tm-co';
  };

  Treemap.prototype.classLabel = function (node, inh) {
    var eff = childInherit(node, inh);
    if (this.mode === 'safety') {
      return eff.s === null || eff.s === undefined ? 'Unclassified' : U.SAFETY_LABEL[U.SAFETY[eff.s]];
    }
    if (this.mode === 'age') {
      var buckets = this.meta.ageBuckets || [];
      return node.a >= 0 ? 'Median byte ' + (buckets[node.a] || '?') + ' old' : 'Age unknown';
    }
    if (eff.c === null || eff.c === undefined) { return 'Unclassified'; }
    var cat = (this.meta.cats || [])[eff.c];
    var fam = (this.meta.families || [])[(this.meta.catFamily || [])[eff.c]];
    return (cat || '?') + (fam ? ' (' + fam.label + ')' : '');
  };

  function drillable(node) { return !node.y && ((node.x && node.x.length > 0) || !!node.k || !!node.e); }

  function displayName(node) {
    if (node.y === 'f') { return '(' + U.fmtNum(node.f || 0) + ' files directly in this folder)'; }
    return node.n;
  }

  // ---------------------------------------------------------------- rendering
  Treemap.prototype.renderAll = function () {
    this.renderCrumbs();
    this.renderLegend();
    this.renderMap();
    this.renderSide();
  };

  Treemap.prototype.renderCrumbs = function () {
    var self = this;
    U.clear(this.crumbs);
    this.stack.forEach(function (node, i) {
      if (i > 0) { self.crumbs.appendChild(el('span', { cls: 'sep', text: '›', attrs: { 'aria-hidden': 'true' } })); }
      var last = i === self.stack.length - 1;
      var label = i === 0 ? (self.meta.rootPath || node.n) : node.n;
      var b = el('button', { text: label, attrs: { type: 'button', 'aria-current': last ? 'page' : null } });
      if (!last) { b.addEventListener('click', function () { self.stack.length = i + 1; self.renderAll(); }); }
      self.crumbs.appendChild(b);
    });
    this.upBtn.disabled = this.stack.length <= 1;
  };

  Treemap.prototype.renderLegend = function () {
    U.clear(this.legend);
    var entries = [];
    var meta = this.meta;
    if (this.mode === 'safety') {
      U.SAFETY.forEach(function (s, i) { entries.push(['sw-s' + i, U.SAFETY_LABEL[s]]); });
      entries.push(['sw-un', 'Unclassified']);
    } else if (this.mode === 'age') {
      (meta.ageBuckets || []).forEach(function (b, i) { entries.push(['sw-a' + i, b]); });
      entries.push(['sw-un', 'Unknown']);
    } else {
      (meta.families || []).forEach(function (f, i) { entries.push([i < 3 ? 'sw-c' + i : 'sw-co', f.label]); });
      entries.push(['sw-un', 'Unclassified']);
    }
    entries.push(['sw-more', 'Loose files / collapsed small items']);
    var self = this;
    entries.forEach(function (e) {
      self.legend.appendChild(el('span', { cls: 'item' }, [el('span', { cls: 'swatch ' + e[0], attrs: { 'aria-hidden': 'true' } }), e[1]]));
    });
    var hint = this.mode === 'safety' ? 'Darker = more cleanable. A folder takes the class of its nearest classified folder.'
      : this.mode === 'age' ? 'Darker = older: the bucket that holds the median byte (from last-write times).'
        : 'Three category families; everything else classified is "Other".';
    this.legend.appendChild(el('span', { cls: 'item muted', text: hint }));
  };

  Treemap.prototype.renderMap = function () {
    var box = this.tm, node = this.current();
    var W = box.clientWidth, H = box.clientHeight;
    U.clear(box);
    this.nodeInfo = new WeakMap();
    var kids = (node.x || []).filter(function (c) { return c.b > 0; });
    box.setAttribute('aria-label', 'Treemap of ' + U.safeText(this.pathAt(this.stack.length - 1)) + ': ' + kids.length +
      ' items. The Contents list next to it has the same data.');
    if (!W || !H) { return; }
    if (!kids.length) {
      box.appendChild(el('div', { cls: 'empty', text: 'Nothing below this folder is large enough to be shown.' }));
      return;
    }
    var rects = squarify(kids.map(function (c) { return c.b; }), 0, 0, W, H);
    var inh = this.inherited();
    var l1 = 0, l2 = 0, hiddenL1 = 0;
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i], r = rects[i];
      if (!r || r.w < 3 || r.h < 3 || l1 >= MAX_PER_LEVEL) { hiddenL1++; continue; }
      var nested = c.x && c.x.length && r.w >= 90 && r.h >= 60 && l2 < MAX_PER_LEVEL;
      var div = this.makeRect(c, r, 1, inh, null, nested);
      box.appendChild(div);
      l1++;
      if (nested) {
        var cin = childInherit(c, inh);
        var gk = c.x.filter(function (g) { return g.b > 0; });
        var innerW = r.w - 2 - 6, innerH = r.h - 2 - LABEL_MIN_H - 4;
        if (innerW > 12 && innerH > 12) {
          var grs = squarify(gk.map(function (g) { return g.b; }), 3, LABEL_MIN_H + 1, innerW, innerH);
          for (var j = 0; j < gk.length && l2 < MAX_PER_LEVEL; j++) {
            var gr = grs[j];
            if (!gr || gr.w < 4 || gr.h < 4) { continue; }
            div.appendChild(this.makeRect(gk[j], gr, 2, cin, c, false));
            l2++;
          }
        }
      }
    }
    this.note.textContent = hiddenL1 ? (hiddenL1 + ' items are too small to draw; they are listed under Contents.') : '';
  };

  Treemap.prototype.makeRect = function (node, r, level, inh, parent, nested) {
    var div = el('div', { cls: 'tm-node l' + level + ' ' + this.colorClass(node, inh) + (node.y ? ' pseudo' : '') });
    var w = Math.max(0, r.w - 2), h = Math.max(0, r.h - 2);  // 2px surface gap between neighbours
    div.style.left = (r.x + 1) + 'px';
    div.style.top = (r.y + 1) + 'px';
    div.style.width = w + 'px';
    div.style.height = h + 'px';
    if (w >= LABEL_MIN_W && h >= LABEL_MIN_H) {
      var label = el('div', { cls: 'tm-label', attrs: { 'aria-hidden': 'true' } });
      label.appendChild(el('span', { cls: 'tm-name', text: displayName(node) }));
      if (nested) {
        label.appendChild(U.text('  ' + U.fmtBytes(node.b)));
      } else if (h >= 34) {
        label.appendChild(el('span', { cls: 'tm-size', text: U.fmtBytes(node.b) }));
      }
      div.appendChild(label);
    }
    if (!drillable(node) && !(level === 2 && parent && drillable(parent))) { div.classList.add('pseudo'); }
    this.nodeInfo.set(div, { node: node, level: level, parent: parent, inh: inh });
    return div;
  };

  Treemap.prototype._hover = function (ev) {
    var tip = this.opts.tooltip;
    var div = ev.target.closest('.tm-node');
    if (!div || !tip) { this._hideTip(); return; }
    var info = this.nodeInfo.get(div);
    if (!info) { this._hideTip(); return; }
    var node = info.node, cur = this.current();
    var whole = info.level === 2 && info.parent ? info.parent.b : cur.b;
    U.clear(tip);
    tip.appendChild(el('div', { cls: 'tt-value', text: U.fmtBytes(node.b) }));
    tip.appendChild(el('div', { cls: 'tt-name', text: displayName(node) }));
    tip.appendChild(el('div', { cls: 'tt-row', text: U.pct(node.b, whole) + ' of ' + (info.level === 2 ? info.parent.n : (cur === this.root ? (this.meta.rootPath || cur.n) : cur.n)) }));
    if (node.f !== undefined) { tip.appendChild(el('div', { cls: 'tt-row', text: U.fmtNum(node.f) + ' files' + (node.d ? ', ' + U.fmtNum(node.d) + ' folders' : '') })); }
    if (node.t) { tip.appendChild(el('div', { cls: 'tt-row', text: 'Newest change ' + U.fmtDate(node.t) + ' (' + U.fmtAge(node.t, this.meta.ageRef) + ')' })); }
    if (node.y === 'm') { tip.appendChild(el('div', { cls: 'tt-row', text: 'Collapsed: below the display threshold' })); }
    var inh = info.inh;
    tip.appendChild(el('div', { cls: 'tt-row', text: MODES.filter(function (m) { return m[0] === this.mode; }, this)[0][1] + ': ' + this.classLabel(node, inh) }));
    if (drillable(node) || (info.level === 2 && drillable(info.parent))) { tip.appendChild(el('div', { cls: 'tt-row muted', text: 'Click to open' })); }
    tip.hidden = false;
    var pad = 14, vw = window.innerWidth, vh = window.innerHeight;
    var rect = tip.getBoundingClientRect();
    var x = ev.clientX + pad, y = ev.clientY + pad;
    if (x + rect.width > vw - 8) { x = ev.clientX - rect.width - pad; }
    if (y + rect.height > vh - 8) { y = ev.clientY - rect.height - pad; }
    tip.style.left = Math.max(8, x) + 'px';
    tip.style.top = Math.max(8, y) + 'px';
  };

  Treemap.prototype._hideTip = function () { if (this.opts.tooltip) { this.opts.tooltip.hidden = true; } };

  // ---------------------------------------------------------------- navigation
  Treemap.prototype.ensureLoaded = function (node) {
    if (!node.pv || !node.k) { return Promise.resolve(node); }
    var self = this;
    var existing = window.BVS.get(node.k);
    var p = existing ? Promise.resolve() : this.opts.loadChunk(node.k);
    this.tm.classList.add('loading');
    return p.then(function () {
      var chunk = window.BVS.get(node.k);
      if (chunk && Array.isArray(chunk.x)) { node.x = chunk.x; delete node.pv; }
      self.tm.classList.remove('loading');
      return node;
    }, function (err) {
      self.tm.classList.remove('loading');
      self.note.textContent = 'Could not load this part of the map: ' + U.safeText(err && err.message);
      throw err;
    });
  };

  // path: nodes to descend into from the current folder (a preview child is resolved after loading)
  Treemap.prototype.drill = function (path) {
    var self = this;
    var chain = Promise.resolve();
    var pushed = 0;
    var stop = false;
    path.forEach(function (target) {
      chain = chain.then(function () {
        if (stop || !target) { return; }
        var parent = self.current();
        var real = target;
        if (target !== self.root && parent.x && parent.x.indexOf(target) === -1) {
          real = null;
          for (var i = 0; i < parent.x.length; i++) {
            if (parent.x[i].n === target.n && parent.x[i].b === target.b) { real = parent.x[i]; break; }
          }
        }
        if (!real || !drillable(real)) { stop = true; return; }
        return self.ensureLoaded(real).then(function (n) {
          if (n.x && n.x.length) { self.stack.push(n); pushed++; } else { stop = true; }
        });
      });
    });
    return chain.then(function () { if (pushed) { self.renderAll(); } }, function () { self.renderAll(); });
  };

  Treemap.prototype.up = function () {
    if (this.stack.length > 1) { this.stack.pop(); this.renderAll(); }
  };

  // ---------------------------------------------------------------- side panel (also the table view)
  Treemap.prototype.renderSide = function () {
    var self = this, node = this.current(), meta = this.meta;
    var idx = this.stack.length - 1;
    var path = this.pathAt(idx);
    var inh = this.inherited();
    U.clear(this.side);

    var info = el('div', { cls: 'card' });
    info.appendChild(el('div', { cls: 'side-path', text: path }));
    var dl = el('dl', { cls: 'kv' });
    function row(k, v) { if (v !== null && v !== undefined && v !== '') { dl.appendChild(el('dt', { text: k })); dl.appendChild(el('dd', null, v)); } }
    row('Size', U.fmtBytes(node.b) + (meta.usedBytes ? '  (' + U.pct(node.b, meta.usedBytes) + ' of used space)' : ''));
    row('Files', node.f !== undefined ? U.fmtNum(node.f) : null);
    row('Folders', node.d !== undefined ? U.fmtNum(node.d) : null);
    row('Newest change', node.t ? U.fmtDate(node.t) + ' (' + U.fmtAge(node.t, meta.ageRef) + ')' : null);
    row('Oldest change', node.o ? U.fmtDate(node.o) : null);
    if (node.k3 && node.b) {
      row('Not changed for', '> 1 y: ' + U.fmtBytes(node.k3[0]) + ' (' + U.pct(node.k3[0], node.b) + ') · > 2 y: ' +
        U.fmtBytes(node.k3[1]) + ' · > 5 y: ' + U.fmtBytes(node.k3[2]));
    }
    row('Online-only (cloud)', node.cl ? U.fmtBytes(node.cl) + ' (uses no local space)' : null);
    var sLabel = inh.s === null ? 'Unclassified' : U.SAFETY_LABEL[U.SAFETY[inh.s]] +
      (inh.sFrom !== null && inh.sFrom < idx ? ' (from ' + this.stack[inh.sFrom].n + ')' : '');
    row('Cleanability', sLabel);
    if (inh.c !== null) { row('Category', (meta.cats || [])[inh.c] || '?'); }
    info.appendChild(dl);
    if (node.fl) {
      String(node.fl).split(',').forEach(function (f) {
        f = f.trim();
        if (f) { info.appendChild(el('p', { cls: 'notice warn', text: FLAG_TEXT[f] || ('Flag: ' + f) })); }
      });
    }
    if (idx === 0) {
      var tot = el('dl', { cls: 'kv' });
      var trow = function (k, v) {
        if (v !== null && v !== undefined) { tot.appendChild(el('dt', { text: k })); tot.appendChild(el('dd', { text: v })); }
      };
      trow('Used space', meta.usedBytes ? U.fmtBytes(meta.usedBytes) : null);
      trow('Treemap total', U.fmtBytes(meta.treemapBytes) + (meta.scannedBytes !== null && meta.scannedBytes !== undefined
        ? (meta.totalMatchesScanned ? ' = scanned bytes ✔' : ' ≠ scanned ' + U.fmtBytes(meta.scannedBytes)) : ''));
      trow('Unaccounted', meta.unaccountedBytes !== null && meta.unaccountedBytes !== undefined ? U.fmtBytes(meta.unaccountedBytes) + ' (system files, inaccessible folders, metadata)' : null);
      trow('Folders in inventory', U.fmtNum(meta.rows) + ' (' + U.fmtNum(meta.nodes) + ' in this map)');
      trow('Display rule', meta.thresholdRule || null);
      info.appendChild(el('h3', { text: 'Totals', attrs: { 'aria-level': '3' } }));
      info.appendChild(tot);
    }
    this.side.appendChild(info);

    // Contents list: the accessible equivalent of the drawing.
    var kids = (node.x || []).slice();
    var list = el('div', { cls: 'card' });
    list.appendChild(el('h3', { text: 'Contents (' + kids.length + ')' }));
    if (node.h && !kids.length) {
      list.appendChild(el('p', { cls: 'muted', text: 'This folder has ' + node.h + ' sub-folders, but it is below the display threshold, so they are not broken down.' }));
    }
    var box = el('div', { cls: 'child-list' });
    var max = kids.length ? Math.max.apply(null, kids.map(function (k) { return k.b; })) : 0;
    kids.slice(0, 80).forEach(function (k) {
      var can = drillable(k);
      var rowEl = el(can ? 'button' : 'div', { cls: 'child-row' + (can ? '' : ' static'), attrs: can ? { type: 'button' } : null, title: displayName(k) });
      rowEl.appendChild(el('span', { cls: 'name', text: displayName(k) }));
      rowEl.appendChild(el('span', { cls: 'size', text: U.fmtBytes(k.b) + '  ' + U.pct(k.b, node.b) }));
      var bar = el('span', { cls: 'bar', attrs: { 'aria-hidden': 'true' } });
      var fill = el('span');
      fill.style.width = (max ? Math.max(1, k.b / max * 100) : 0) + '%';
      bar.appendChild(fill);
      rowEl.appendChild(bar);
      if (can) { rowEl.addEventListener('click', function () { self.drill([k]); }); }
      box.appendChild(rowEl);
    });
    if (kids.length > 80) { box.appendChild(el('p', { cls: 'muted', text: '… and ' + (kids.length - 80) + ' smaller items' })); }
    list.appendChild(box);
    this.side.appendChild(list);

    // Clean-up items located inside this folder (from the storage tables).
    var key = this._key(path);
    var sepKey = key + (this.sep === '/' ? '/' : '\\');
    var inside = idx === 0 && !meta.rootPath ? this.items : this.items.filter(function (e) {
      return e.key === key || e.key.indexOf(sepKey) === 0 || (key.charAt(key.length - 1) === self.sep.toLowerCase() && e.key.indexOf(key) === 0);
    });
    if (inside.length) {
      inside.sort(function (a, b) { return (b.item.bytes || 0) - (a.item.bytes || 0); });
      var card = el('div', { cls: 'card' });
      card.appendChild(el('h3', { text: 'Clean-up items here (' + inside.length + ')' }));
      var cl = el('div', { cls: 'child-list' });
      inside.slice(0, 40).forEach(function (e) {
        var it = e.item;
        var b = el('button', { cls: 'child-row', attrs: { type: 'button' }, title: it.path });
        b.appendChild(el('span', { cls: 'name', text: it.label }));
        b.appendChild(el('span', { cls: 'size', text: U.fmtBytes(it.bytes) }));
        var meta2 = el('span', { cls: 'muted' }, [U.safetyBadge(it.safety)]);
        meta2.style.gridColumn = '1 / -1';
        b.appendChild(meta2);
        b.addEventListener('click', function () { if (self.opts.onItem) { self.opts.onItem(it); } });
        cl.appendChild(b);
      });
      card.appendChild(cl);
      this.side.appendChild(card);
    }
  };

  window.BVSUI.Treemap = Treemap;
  window.BVSUI.squarify = squarify;
})();
