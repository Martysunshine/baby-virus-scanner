/* baby-virus-scanner dashboard: the clean-up basket.
 * The basket never deletes or moves anything. v3: "Request deletion" hands the list to app.js, which
 * shows the double-confirmation dialog (the user types "I confirm" here, then "I confirm <CODE>" in the
 * Claude chat; docs/ui-contract-v3.md). requestText() is kept for the older copy/paste flow.
 * Items whose safety is use_tool or do_not_touch can never be added. */
(function () {
  'use strict';
  var U = window.BVSUI.util;
  var el = U.el;
  var BLOCKED = { use_tool: true, do_not_touch: true };

  function canAdd(item) {
    return !!item && typeof item.id === 'string' && item.id.length > 0 && !BLOCKED[item.safety] && item.method !== 'none';
  }

  function snapshot(item) {
    return {
      id: String(item.id),
      method: String(item.method || 'recycle'),
      bytes: typeof item.bytes === 'number' ? item.bytes : null,
      path: String(item.path || ''),
      label: String(item.label || ''),
      safety: String(item.safety || 'review'),
      flags: Array.isArray(item.flags) ? item.flags.map(String) : []
    };
  }

  function Basket(scanKey) {
    this.key = 'bvs.basket.v1.' + scanKey;
    this.map = new Map();
    this.listeners = [];
    var saved = U.storage.get(this.key, []);
    var self = this;
    if (Array.isArray(saved)) {
      saved.forEach(function (e) {
        if (e && typeof e.id === 'string' && canAdd(e)) { self.map.set(e.id, snapshot(e)); }
      });
    }
  }

  Basket.prototype.canAdd = canAdd;
  Basket.prototype.has = function (id) { return this.map.has(id); };
  Basket.prototype.list = function () { return Array.from(this.map.values()); };
  Basket.prototype.count = function () { return this.map.size; };
  Basket.prototype.totalBytes = function () {
    return this.list().reduce(function (sum, it) { return sum + (it.bytes || 0); }, 0);
  };
  Basket.prototype.onChange = function (fn) { this.listeners.push(fn); };
  Basket.prototype._changed = function () {
    this.saved = U.storage.set(this.key, this.list());
    var self = this;
    this.listeners.forEach(function (fn) { fn(self); });
  };
  Basket.prototype.add = function (item) {
    if (!canAdd(item)) { return false; }
    this.map.set(item.id, snapshot(item));
    this._changed();
    return true;
  };
  Basket.prototype.remove = function (id) {
    if (this.map.delete(id)) { this._changed(); }
  };
  Basket.prototype.toggle = function (item) {
    if (this.has(item.id)) { this.remove(item.id); return false; }
    return this.add(item);
  };
  Basket.prototype.clear = function () { this.map.clear(); this._changed(); };

  // Exactly:  DELETE REQUEST — scan <scanId> — <n> items — <total size>
  //           <id> | <method> | <size> | <path>      (one line per item)
  //           Paste this into Claude. Nothing is deleted until you reply exactly: I confirm
  // Control and bidi characters are made visible so no field can inject an extra line.
  Basket.prototype.requestText = function (scanId) {
    var items = this.list();
    var lines = ['DELETE REQUEST — scan ' + U.safeText(scanId) + ' — ' + items.length + ' items — ' + U.fmtBytes(this.totalBytes())];
    items.forEach(function (it) {
      lines.push([it.id, it.method, U.fmtBytes(it.bytes), it.path || it.label].map(U.safeText).join(' | '));
    });
    lines.push('Paste this into Claude. Nothing is deleted until you reply exactly: I confirm');
    return lines.join('\n');
  };

  // ---------------------------------------------------------------- view
  function BasketView(panel, basket, opts) {
    this.panel = panel;
    this.basket = basket;
    this.opts = opts;  // {scanId, findItem(id), onOpen(item)}
    var self = this;
    basket.onChange(function () { self.render(); });
    this.render();
  }

  // v3 (docs/ui-contract-v3.md §1-2): "Request deletion" opens app.js's double-confirmation dialog
  // (typed "I confirm" here, then "I confirm <CODE>" typed by the user in the Claude chat). This view
  // never deletes anything and never sends anything by itself.
  BasketView.prototype.render = function () {
    var b = this.basket, panel = this.panel, o = this.opts;
    var pv = o.privacy || null;
    var live = typeof o.live === 'function' ? !!o.live() : false;
    var max = o.maxItems || 200;
    this.renderedLive = typeof o.live === 'function' ? o.live() : null;
    function shownLabel(it) { return pv ? pv.label(it.path, it.label || it.path) : (it.label || it.path); }
    function shownPath(it) { return pv ? pv.path(it.path) : it.path; }
    U.clear(panel);
    var items = b.list();
    var risky = items.filter(function (it) { return it.flags.some(function (f) { return /work_at_risk/.test(f); }); });

    var summary = el('div', { cls: 'card basket-summary', attrs: { 'data-bvs-section': 'basket-summary' } });
    summary.appendChild(el('h2', { text: 'Remove these items safely' }));
    summary.appendChild(el('div', { cls: 'stat-line' }, [
      el('span', null, [el('strong', { text: U.fmtNum(items.length) }), ' items']),
      el('span', null, [el('strong', { text: U.fmtBytes(b.totalBytes()) }), ' in total']),
      el('span', { cls: 'muted', text: 'Saved in this browser only' + (b.saved === false ? ' (storage unavailable: the basket resets on reload)' : '') })
    ]));
    var how = el('ol', { cls: 'basket-how' }, [
      el('li', null, [el('strong', { text: 'Here: ' }), 'press "Request deletion", check the exact list and type I confirm.']),
      el('li', null, [el('strong', { text: 'In your Claude chat: ' }), 'Claude re-checks every item live and shows the final list. Only when you type "I confirm" plus the code you got does anything happen.'])
    ]);
    summary.appendChild(how);
    if (risky.length) {
      summary.appendChild(el('p', { cls: 'notice warn', text: risky.length + ' item(s) have uncommitted or unpushed git work. Save that work first; the check will refuse them otherwise.' }));
    }
    var actions = el('div', { cls: 'basket-actions' });
    var reqBtn = el('button', { cls: 'btn primary big', attrs: { type: 'button', 'data-bvs-type': 'tile', 'data-bvs-id': 'basket-request-deletion', 'data-bvs-label': 'Request deletion' }, disabled: !items.length || !live || items.length > max, text: 'Request deletion' });
    var clearBtn = el('button', { cls: 'btn', text: 'Clear basket', attrs: { type: 'button' }, disabled: !items.length });
    var status = el('span', { cls: 'basket-hint', attrs: { 'aria-live': 'polite' } });
    if (!items.length) { status.textContent = 'Add items first: tick them in the storage lists.'; }
    else if (!live) { status.textContent = typeof o.liveHint === 'function' ? o.liveHint() : 'Needs the live dashboard (start-dashboard).'; }
    else if (items.length > max) { status.textContent = 'At most ' + max + ' items per request: remove ' + (items.length - max) + '.'; }
    actions.appendChild(reqBtn);
    actions.appendChild(clearBtn);
    actions.appendChild(status);
    summary.appendChild(actions);
    reqBtn.addEventListener('click', function () {
      if (reqBtn.disabled || typeof o.onRequestDeletion !== 'function') { return; }
      o.onRequestDeletion(b.list());
    });
    clearBtn.addEventListener('click', function () { b.clear(); });
    summary.appendChild(el('p', { cls: 'intro', text: 'Items marked "Use tool" or "Do not touch" cannot be added; their tables show how to handle them instead.' }));
    panel.appendChild(summary);

    var listCard = el('div', { cls: 'card' });
    listCard.appendChild(el('h3', { text: 'Items' }));
    if (!items.length) {
      listCard.appendChild(el('p', { cls: 'empty', text: 'The basket is empty.' }));
    } else {
      var wrap = el('div', { cls: 'table-wrap' });
      var table = el('table', { cls: 'simple' });
      var thead = el('thead', null, el('tr', null, ['Name / path', 'Method', 'Size', 'Safety', ''].map(function (h, i) {
        return el('th', { text: h, cls: i === 2 ? 'num' : '', attrs: { scope: 'col' } });
      })));
      var tbody = el('tbody');
      items.forEach(function (it) {
        var tr = el('tr', { attrs: { 'data-bvs-type': 'storageItem', 'data-bvs-id': it.id, 'data-bvs-label': U.safeText(shownLabel(it)).slice(0, 120) } });
        tr.appendChild(el('td', null, [el('div', { text: shownLabel(it) }), el('div', { cls: 'muted break', text: shownPath(it) })]));
        tr.appendChild(el('td', { text: it.method }));
        tr.appendChild(el('td', { cls: 'num nowrap', text: U.fmtBytes(it.bytes) }));
        tr.appendChild(el('td', null, U.safetyBadge(it.safety)));
        var actionsTd = el('td', { cls: 'nowrap' });
        var full = o.findItem ? o.findItem(it.id) : null;
        if (full && o.onOpen) {
          actionsTd.appendChild(el('button', { cls: 'btn small ghost', text: 'Details', attrs: { type: 'button' }, on: { click: function () { o.onOpen(full); } } }));
        }
        actionsTd.appendChild(el('button', { cls: 'btn small', text: 'Remove', attrs: { type: 'button' }, on: { click: function () { b.remove(it.id); } } }));
        tr.appendChild(actionsTd);
        tbody.appendChild(tr);
      });
      table.appendChild(thead);
      table.appendChild(tbody);
      wrap.appendChild(table);
      listCard.appendChild(wrap);
    }
    panel.appendChild(listCard);
  };

  window.BVSUI.Basket = Basket;
  window.BVSUI.BasketView = BasketView;
})();
