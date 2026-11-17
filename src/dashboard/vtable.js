/* baby-virus-scanner dashboard: virtualized, sortable, searchable table.
 * Only the rows in view (plus a small buffer) exist in the DOM, so lists with tens of
 * thousands of items stay fast. Cells are built with createElement/textContent only. */
(function () {
  'use strict';
  var U = window.BVSUI.util;
  var el = U.el;

  /**
   * opts.columns: [{key, label, width, sortValue(row), render(row) -> Node|string, align, cls, title(row)}]
   * opts.rowHeight (px), opts.height (CSS length), opts.minWidth (px), opts.searchText(row),
   * opts.onActivate(row), opts.getId(row), opts.initialSort {key, dir}, opts.emptyText, opts.label
   */
  function VTable(container, opts) {
    this.opts = opts;
    this.rowHeight = opts.rowHeight || 44;
    this.rows = [];
    this.view = [];
    this.query = '';
    this.filter = null;
    this.activeId = null;
    this.sortKey = opts.initialSort ? opts.initialSort.key : null;
    this.sortDir = opts.initialSort ? opts.initialSort.dir : 'desc';
    this._raf = 0;
    this._build(container);
  }

  VTable.prototype._build = function (container) {
    var self = this, o = this.opts;
    this.root = el('div', { cls: 'vt', attrs: { role: 'table', 'aria-label': o.label || 'table' } });
    this.root.style.setProperty('--vt-cols', o.columns.map(function (c) { return c.width || '1fr'; }).join(' '));
    if (o.minWidth) { this.root.style.setProperty('--vt-min', o.minWidth + 'px'); }
    if (o.height) { this.root.style.setProperty('--vt-height', o.height); }
    var inner = el('div', { cls: 'vt-inner' });
    this.head = el('div', { cls: 'vt-head', attrs: { role: 'row' } });
    o.columns.forEach(function (col) {
      var th = el('div', { cls: 'vt-th' + (col.align === 'right' ? ' right' : ''), attrs: { role: 'columnheader' } });
      if (col.sortValue) {
        var btn = el('button', { attrs: { type: 'button' }, title: 'Sort by ' + col.label }, [col.label, el('span', { cls: 'sort-ind', attrs: { 'aria-hidden': 'true' } })]);
        btn.addEventListener('click', function () { self.sortBy(col.key); });
        th.appendChild(btn);
      } else if (col.label) {
        th.appendChild(U.text(col.label));
      } else if (col.ariaLabel) {
        th.appendChild(el('span', { cls: 'sr-only', text: col.ariaLabel }));
      }
      th.dataset.key = col.key;
      self.head.appendChild(th);
    });
    this.viewport = el('div', { cls: 'vt-viewport' });
    this.spacer = el('div', { cls: 'vt-spacer' });
    this.rowsEl = el('div', { cls: 'vt-rows', attrs: { role: 'rowgroup' } });
    this.emptyEl = el('div', { cls: 'vt-empty', text: o.emptyText || 'Nothing to show.', hidden: true });
    this.viewport.appendChild(this.spacer);
    this.viewport.appendChild(this.rowsEl);
    this.viewport.appendChild(this.emptyEl);
    inner.appendChild(this.head);
    inner.appendChild(this.viewport);
    this.root.appendChild(inner);
    container.appendChild(this.root);
    this.viewport.addEventListener('scroll', function () { self._schedule(); }, { passive: true });
    if (window.ResizeObserver) {
      new ResizeObserver(function () { self._schedule(); }).observe(this.viewport);
    }
    this.rowsEl.addEventListener('click', function (ev) {
      if (ev.target.closest('input, button')) { return; }
      var rowEl = ev.target.closest('.vt-row');
      if (rowEl) { self._activate(Number(rowEl.dataset.index)); }
    });
    this.rowsEl.addEventListener('keydown', function (ev) {
      var rowEl = ev.target.closest('.vt-row');
      if (!rowEl || ev.target !== rowEl) { return; }
      var idx = Number(rowEl.dataset.index);
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); self._activate(idx); }
      else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        ev.preventDefault();
        self.focusIndex(idx + (ev.key === 'ArrowDown' ? 1 : -1));
      }
    });
    this._updateSortIndicators();
  };

  VTable.prototype._activate = function (idx) {
    var row = this.view[idx];
    if (!row) { return; }
    this.activeId = this.opts.getId ? this.opts.getId(row) : idx;
    this.refresh();
    if (this.opts.onActivate) { this.opts.onActivate(row); }
  };

  VTable.prototype.focusIndex = function (idx) {
    if (idx < 0 || idx >= this.view.length) { return; }
    var rh = this.rowHeight, vp = this.viewport;
    if (idx * rh < vp.scrollTop) { vp.scrollTop = idx * rh; }
    else if ((idx + 1) * rh > vp.scrollTop + vp.clientHeight) { vp.scrollTop = (idx + 1) * rh - vp.clientHeight; }
    this.render();
    var target = this.rowsEl.querySelector('.vt-row[data-index="' + idx + '"]');
    if (target) { target.focus(); }
  };

  VTable.prototype.setRows = function (rows) { this.rows = rows || []; this._recompute(); };
  VTable.prototype.setQuery = function (q) { this.query = (q || '').trim().toLowerCase(); this._recompute(); };
  VTable.prototype.setFilter = function (fn) { this.filter = fn; this._recompute(); };

  VTable.prototype.sortBy = function (key) {
    if (this.sortKey === key) { this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc'; }
    else {
      this.sortKey = key;
      var col = this._col(key);
      this.sortDir = col && col.defaultDir ? col.defaultDir : 'asc';
    }
    this._updateSortIndicators();
    this._recompute();
  };

  VTable.prototype._col = function (key) {
    for (var i = 0; i < this.opts.columns.length; i++) { if (this.opts.columns[i].key === key) { return this.opts.columns[i]; } }
    return null;
  };

  VTable.prototype._updateSortIndicators = function () {
    var self = this;
    Array.prototype.forEach.call(this.head.children, function (th) {
      var key = th.dataset.key;
      var ind = th.querySelector('.sort-ind');
      if (key === self.sortKey) {
        th.setAttribute('aria-sort', self.sortDir === 'asc' ? 'ascending' : 'descending');
        if (ind) { ind.textContent = self.sortDir === 'asc' ? '▴' : '▾'; }
      } else {
        th.removeAttribute('aria-sort');
        if (ind) { ind.textContent = ''; }
      }
    });
  };

  VTable.prototype._recompute = function () {
    var self = this, q = this.query, o = this.opts;
    var out = this.rows.filter(function (r) {
      if (self.filter && !self.filter(r)) { return false; }
      if (!q) { return true; }
      if (r.__search === undefined) { r.__search = (o.searchText ? o.searchText(r) : JSON.stringify(r)).toLowerCase(); }
      return r.__search.indexOf(q) !== -1;
    });
    var col = this.sortKey ? this._col(this.sortKey) : null;
    if (col && col.sortValue) {
      var dir = this.sortDir === 'asc' ? 1 : -1;
      out.sort(function (a, b) {
        var va = col.sortValue(a), vb = col.sortValue(b);
        var na = va === null || va === undefined || va === '', nb = vb === null || vb === undefined || vb === '';
        if (na || nb) { return na === nb ? 0 : na ? 1 : -1; }  // empty values always last
        if (typeof va === 'number' && typeof vb === 'number') { return (va - vb) * dir; }
        return String(va).localeCompare(String(vb), 'en', { numeric: true, sensitivity: 'base' }) * dir;
      });
    }
    this.view = out;
    this.root.setAttribute('aria-rowcount', String(out.length + 1));
    this.spacer.style.height = (out.length * this.rowHeight) + 'px';
    this.emptyEl.hidden = out.length > 0;
    if (this.opts.onView) { this.opts.onView(out); }
    this.render();
  };

  VTable.prototype._schedule = function () {
    var self = this;
    if (this._raf) { return; }
    this._raf = requestAnimationFrame(function () { self._raf = 0; self.render(); });
  };

  VTable.prototype.refresh = function () { this.render(); };

  VTable.prototype.render = function () {
    var rh = this.rowHeight, vp = this.viewport, o = this.opts;
    var top = vp.scrollTop, height = vp.clientHeight || 500;
    var start = Math.max(0, Math.floor(top / rh) - 6);
    var end = Math.min(this.view.length, Math.ceil((top + height) / rh) + 6);
    var focusedIndex = null;
    if (document.activeElement && this.rowsEl.contains(document.activeElement)) {
      var fr = document.activeElement.closest('.vt-row');
      if (fr) { focusedIndex = fr.dataset.index; }
    }
    U.clear(this.rowsEl);
    for (var i = start; i < end; i++) {
      var row = this.view[i];
      var id = o.getId ? o.getId(row) : i;
      var rowEl = el('div', {
        cls: 'vt-row' + (id === this.activeId ? ' active' : ''),
        attrs: { role: 'row', tabindex: '0', 'aria-rowindex': String(i + 2), 'data-index': String(i) }
      });
      rowEl.style.transform = 'translateY(' + (i * rh) + 'px)';
      rowEl.style.height = rh + 'px';
      for (var c = 0; c < o.columns.length; c++) {
        var col = o.columns[c];
        var cell = el('div', { cls: 'vt-cell' + (col.align === 'right' ? ' right' : '') + (col.cls ? ' ' + col.cls : ''), attrs: { role: 'cell' } });
        var content = col.render ? col.render(row) : row[col.key];
        U.append(cell, content === undefined ? null : content);
        if (col.title) { var t = col.title(row); if (t) { cell.title = U.safeText(t); } }
        rowEl.appendChild(cell);
      }
      this.rowsEl.appendChild(rowEl);
    }
    if (focusedIndex !== null) {
      var again = this.rowsEl.querySelector('.vt-row[data-index="' + focusedIndex + '"]');
      if (again) { again.focus({ preventScroll: true }); }
    }
  };

  window.BVSUI.VTable = VTable;
})();
