/* baby-virus-scanner dashboard: data registry.
 * Every data file is a classic script of the form  window.BVS.register("<name>", <json>);
 * Loading data with <script> tags (not fetch) lets index.html work from file:// too.
 * The registry is frozen so a data file cannot replace these functions. */
(function () {
  'use strict';
  var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  var store = new Map();

  function register(name, value) {
    if (typeof name !== 'string' || !NAME_RE.test(name)) { return; }
    store.set(name, value);
  }

  function get(name) { return store.get(name); }
  function has(name) { return store.has(name); }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.onload = function () { resolve(src); };
      s.onerror = function () { s.remove(); reject(new Error('could not load ' + src)); };
      document.head.appendChild(s);
    });
  }

  window.BVS = Object.freeze({ register: register, get: get, has: has, loadScript: loadScript });
  window.BVSUI = {};
})();
