#!/usr/bin/env node
// baby-virus-scanner: frame-timing probe for the dashboard (agent UI-E, docs/playbooks/D-visual-design.md).
//
// Plain Node 22 ESM, no packages. It starts its OWN dashboard server (never the user's live one on 8777),
// launches headless Edge with a throw-away profile, drives it over the DevTools protocol (built-in
// WebSocket) and prints, per route:
//   idle   frame deltas for --idle-ms (default 3 s) from an injected requestAnimationFrame loop
//   scroll frame deltas while the page scrolls 40 px per frame to the bottom and back up
//   inner  the same for the first virtual table (.vt-viewport), when the route has one
//   trace  main-thread Paint / style / layout events per second while idle (separate 2 s trace)
//   Performance.getMetrics deltas (layout/style counts and durations, script and task time)
// Headless timing is indicative only: compare before/after runs on the same machine (--out, --compare).
//
// Usage (from the project folder):
//   node tests/ui/perf-probe.mjs [--port 8790] [--scan data/<scanId>] [--routes "#/overview,#/storage"]
//        [--repeat 1] [--idle-ms 3000] [--settle-ms 2500] [--scheme dark|light] [--reduced-motion]
//        [--profile-root <folder>] [--out result.json] [--compare before.json] [--no-trace]
//   node tests/ui/perf-probe.mjs --no-server --url http://127.0.0.1:8777/   (measure a server you started)
// Network: Edge resolves nothing but 127.0.0.1 (--host-resolver-rules); the probe talks to 127.0.0.1 only.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_ROUTES = '#/overview,#/storage,#/storage/map,#/agents,#/security';
const EDGE_CANDIDATES = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable'
];

// ------------------------------------------------------------------ arguments
function parseArgs(argv) {
  const o = {
    url: 'http://127.0.0.1:8777/', port: 8790, server: true, scan: null, routes: DEFAULT_ROUTES, repeat: 1,
    idleMs: 3000, settleMs: 2500, scheme: 'dark', reduced: false, profileRoot: null, out: null, compare: null,
    trace: true, python: process.env.BVS_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'), edge: null, urlGiven: false
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => { if (i + 1 >= argv.length) { throw new Error('missing value for ' + a); } return argv[++i]; };
    switch (a) {
      case '--url': o.url = v(); o.urlGiven = true; break;
      case '--port': o.port = Number(v()); break;
      case '--no-server': o.server = false; break;
      case '--scan': o.scan = v(); break;
      case '--routes': o.routes = v(); break;
      case '--repeat': o.repeat = Math.max(1, Number(v()) || 1); break;
      case '--idle-ms': o.idleMs = Number(v()); break;
      case '--settle-ms': o.settleMs = Number(v()); break;
      case '--scheme': o.scheme = v() === 'light' ? 'light' : 'dark'; break;
      case '--reduced-motion': o.reduced = true; break;
      case '--profile-root': o.profileRoot = v(); break;
      case '--out': o.out = v(); break;
      case '--compare': o.compare = v(); break;
      case '--no-trace': o.trace = false; break;
      case '--python': o.python = v(); break;
      case '--edge': o.edge = v(); break;
      case '-h': case '--help': console.log(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 20).join('\n')); process.exit(0); break;
      default: throw new Error('unknown argument ' + a);
    }
  }
  if (o.urlGiven && !argv.includes('--no-server')) { o.server = false; } // an explicit --url means "measure that server"
  if (!Number.isInteger(o.port) || o.port < 1024 || o.port > 65535) { throw new Error('--port must be 1024-65535'); }
  if (o.server && o.port === 8777) { throw new Error('refusing port 8777: that is the live dashboard; pick another --port'); }
  if (o.server) { o.url = 'http://127.0.0.1:' + o.port + '/'; }
  const u = new URL(o.url);
  if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') { throw new Error('--url must point at 127.0.0.1'); }
  o.routes = o.routes.split(',').map((r) => r.trim()).filter(Boolean);
  return o;
}

// ------------------------------------------------------------------ helpers
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}
async function waitHttp(url, timeoutMs) {
  const end = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < end) {
    try { const r = await fetch(url, { redirect: 'manual' }); if (r.status < 500) { return r; } last = new Error('HTTP ' + r.status); } catch (e) { last = e; }
    await sleep(150);
  }
  throw new Error('timed out waiting for ' + url + (last ? ': ' + last.message : ''));
}
function killTree(child) {
  if (!child || child.exitCode !== null) { return; }
  try {
    if (process.platform === 'win32') { spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true }); }
    else { child.kill('SIGKILL'); }
  } catch (e) { /* already gone */ }
}
function pct(arr, p) {
  if (!arr.length) { return NaN; }
  const s = arr.slice().sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p / 100 * s.length) - 1))];
}
function median(arr) { const a = arr.filter((x) => Number.isFinite(x)); return a.length ? pct(a, 50) : NaN; }
function summarize(deltas) {
  return { n: deltas.length, p50: pct(deltas, 50), p95: pct(deltas, 95), max: deltas.length ? Math.max(...deltas) : NaN, over25: deltas.filter((d) => d > 25).length };
}

// ------------------------------------------------------------------ a minimal CDP client (flat sessions)
class CDP {
  constructor(wsUrl) { this.wsUrl = wsUrl; this.id = 0; this.pending = new Map(); this.listeners = []; }
  open() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.wsUrl);
      this.ws = ws;
      ws.onopen = () => resolve();
      ws.onerror = (e) => reject(new Error('CDP socket error ' + (e && e.message ? e.message : '')));
      ws.onclose = () => { for (const p of this.pending.values()) { p.reject(new Error('CDP socket closed')); } this.pending.clear(); };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
        if (msg.id && this.pending.has(msg.id)) {
          const p = this.pending.get(msg.id); this.pending.delete(msg.id);
          if (msg.error) { p.reject(new Error(p.method + ': ' + msg.error.message)); } else { p.resolve(msg.result); }
        } else if (msg.method) {
          for (const l of this.listeners.slice()) { l(msg); }
        }
      };
    });
  }
  send(method, params = {}, sessionId = undefined, timeoutMs = 60000) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) { payload.sessionId = sessionId; }
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(method + ' timed out')); }, timeoutMs);
      this.pending.set(id, { method, resolve: (r) => { clearTimeout(t); resolve(r); }, reject: (e) => { clearTimeout(t); reject(e); } });
      this.ws.send(JSON.stringify(payload));
    });
  }
  waitFor(method, sessionId, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      const l = (msg) => { if (msg.method === method && (!sessionId || msg.sessionId === sessionId)) { done(); resolve(msg.params); } };
      const t = setTimeout(() => { done(); reject(new Error('timed out waiting for ' + method)); }, timeoutMs);
      const done = () => { clearTimeout(t); this.listeners = this.listeners.filter((x) => x !== l); };
      this.listeners.push(l);
    });
  }
  on(fn) { this.listeners.push(fn); return () => { this.listeners = this.listeners.filter((x) => x !== fn); }; }
  close() { try { this.ws.close(); } catch (e) { /* ignore */ } }
}

// ------------------------------------------------------------------ in-page measurement scripts
const IDLE_JS = (ms) => `new Promise(function (res) {
  var d = [], last = 0, end = performance.now() + ${ms};
  function f(t) { if (last) { d.push(t - last); } last = t; if (t < end) { requestAnimationFrame(f); } else { res(d); } }
  requestAnimationFrame(f);
})`;
// Scrolls 40 px per frame to the bottom and back up (instant steps, never smooth), max 900 frames.
const SCROLL_JS = `new Promise(function (res) {
  var se = document.scrollingElement || document.documentElement;
  var max = Math.max(0, se.scrollHeight - window.innerHeight);
  if (max < 80) { res({ d: [], max: max }); return; }
  window.scrollTo({ top: 0, behavior: 'instant' });
  var d = [], last = 0, dir = 1, n = 0;
  function f(t) {
    if (last) { d.push(t - last); } last = t;
    if (++n > 900) { res({ d: d, max: max, capped: true }); return; }
    if (dir === 1) { window.scrollBy({ top: 40, behavior: 'instant' }); if (se.scrollTop >= max - 1) { dir = -1; } }
    else { window.scrollBy({ top: -40, behavior: 'instant' }); if (se.scrollTop <= 0) { res({ d: d, max: max }); return; } }
    requestAnimationFrame(f);
  }
  requestAnimationFrame(f);
})`;
const INNER_JS = `new Promise(function (res) {
  var vp = document.querySelector('.vt-viewport');
  if (!vp || vp.scrollHeight - vp.clientHeight < 80) { res(null); return; }
  vp.scrollIntoView({ block: 'center', behavior: 'instant' });
  var max = Math.min(4000, vp.scrollHeight - vp.clientHeight), d = [], last = 0, dir = 1, n = 0;
  vp.scrollTop = 0;
  function f(t) {
    if (last) { d.push(t - last); } last = t;
    if (++n > 400) { res({ d: d, max: max }); return; }
    if (dir === 1) { vp.scrollTop += 40; if (vp.scrollTop >= max - 1) { dir = -1; } }
    else { vp.scrollTop -= 40; if (vp.scrollTop <= 0) { res({ d: d, max: max }); return; } }
    requestAnimationFrame(f);
  }
  requestAnimationFrame(f);
})`;
// running CSS animations / transitions right now, grouped by name (what keeps the page busy while idle)
const ANIMS_JS = `(function () {
  if (!document.getAnimations) { return []; }
  var out = {};
  document.getAnimations().forEach(function (a) {
    if (a.playState !== 'running') { return; }
    var t = a.effect && a.effect.target, name = a.animationName || a.transitionProperty || a.id || 'waapi';
    var tag = t ? (t.tagName || '').toLowerCase() : '?';
    var svgChild = !!(t && t.ownerSVGElement);
    var key = name + (svgChild ? ' [svg]' : '');
    out[key] = (out[key] || 0) + 1;
  });
  return Object.keys(out).sort(function (a, b) { return out[b] - out[a]; }).map(function (k) { return k + ' x' + out[k]; });
})()`;
const METRIC_KEYS = ['LayoutCount', 'RecalcStyleCount', 'LayoutDuration', 'RecalcStyleDuration', 'ScriptDuration', 'TaskDuration'];

async function metrics(cdp, sid) {
  const r = await cdp.send('Performance.getMetrics', {}, sid);
  const m = {};
  for (const x of r.metrics) { if (METRIC_KEYS.includes(x.name)) { m[x.name] = x.value; } }
  return m;
}
function diff(a, b) {
  const o = {};
  for (const k of METRIC_KEYS) { o[k] = (b[k] || 0) - (a[k] || 0); }
  // durations come in seconds: report milliseconds
  for (const k of ['LayoutDuration', 'RecalcStyleDuration', 'ScriptDuration', 'TaskDuration']) { o[k] = o[k] * 1000; }
  return o;
}
async function evalAwait(cdp, sid, expr, timeoutMs = 60000) {
  const r = await cdp.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true }, sid, timeoutMs);
  if (r.exceptionDetails) { throw new Error('page script failed: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text)); }
  return r.result.value;
}

// main-thread paint/style/layout events while idle, from a short devtools.timeline trace
async function traceIdle(cdp, sid, ms) {
  const events = [];
  const off = cdp.on((msg) => { if (msg.method === 'Tracing.dataCollected' && msg.sessionId === sid) { events.push(...msg.params.value); } });
  await cdp.send('Tracing.start', { categories: 'devtools.timeline,disabled-by-default-devtools.timeline', transferMode: 'ReportEvents' }, sid);
  await sleep(ms);
  const done = cdp.waitFor('Tracing.tracingComplete', sid, 30000);
  await cdp.send('Tracing.end', {}, sid);
  await done;
  off();
  const sec = ms / 1000, out = { paints: 0, paintMs: 0, styles: 0, layouts: 0, rasterMs: 0, animFrames: 0 };
  for (const e of events) {
    const dur = (e.dur || 0) / 1000;
    if (e.name === 'Paint' && e.ph === 'X') { out.paints++; out.paintMs += dur; }
    else if (e.name === 'UpdateLayoutTree' && e.ph === 'X') { out.styles++; }
    else if (e.name === 'Layout' && e.ph === 'X') { out.layouts++; }
    else if (e.name === 'RasterTask' && e.ph === 'X') { out.rasterMs += dur; }
    else if (e.name === 'BeginMainThreadFrame' || e.name === 'BeginFrame') { out.animFrames++; }
  }
  return { paintsPerS: out.paints / sec, paintMsPerS: out.paintMs / sec, stylesPerS: out.styles / sec, layoutsPerS: out.layouts / sec, rasterMsPerS: out.rasterMs / sec };
}

async function measureRoute(cdp, sid, base, route, o) {
  await cdp.send('Page.navigate', { url: 'about:blank' }, sid);
  await sleep(150);
  const loaded = cdp.waitFor('Page.loadEventFired', sid, 30000);
  await cdp.send('Page.navigate', { url: base + route }, sid);
  await loaded;
  await sleep(o.settleMs);
  const anims = (await cdp.send('Runtime.evaluate', { expression: ANIMS_JS, returnByValue: true }, sid)).result.value || [];
  const m0 = await metrics(cdp, sid);
  const idle = await evalAwait(cdp, sid, IDLE_JS(o.idleMs), o.idleMs + 20000);
  const m1 = await metrics(cdp, sid);
  const sc = await evalAwait(cdp, sid, SCROLL_JS, 60000);
  const m2 = await metrics(cdp, sid);
  const inner = await evalAwait(cdp, sid, INNER_JS, 60000);
  await evalAwait(cdp, sid, 'new Promise(function (r) { window.scrollTo({ top: 0, behavior: "instant" }); setTimeout(r, 400); })');
  const tr = o.trace ? await traceIdle(cdp, sid, 2000) : null;
  return {
    route, idle: summarize(idle), scroll: summarize(sc.d), scrollMax: sc.max, capped: !!sc.capped,
    inner: inner ? summarize(inner.d) : null, idleMetrics: diff(m0, m1), scrollMetrics: diff(m1, m2), trace: tr, anims
  };
}

function combine(runs) { // median across repeats, per numeric leaf
  const first = runs[0];
  function walk(objs) {
    if (objs[0] === null || objs[0] === undefined) { return objs[0]; }
    if (typeof objs[0] === 'number') { return median(objs); }
    if (typeof objs[0] !== 'object' || Array.isArray(objs[0])) { return objs[0]; }
    const o = {};
    for (const k of Object.keys(objs[0])) { o[k] = walk(objs.map((x) => (x ? x[k] : undefined))); }
    return o;
  }
  return Object.assign(walk(runs), { route: first.route, repeats: runs.length });
}

// ------------------------------------------------------------------ output
const f0 = (x) => (Number.isFinite(x) ? x.toFixed(0) : '-');
const f1 = (x) => (Number.isFinite(x) ? x.toFixed(1) : '-');
function printTable(results, title) {
  console.log('\n' + title);
  const head = ['route', 'idle p50/p95/max', 'scroll p50/p95/max', '>25ms i/s', 'layouts i/s', 'styles i/s', 'layout ms', 'style ms', 'script ms', 'task ms i/s', 'paint/s', 'paint ms/s', 'raster ms/s'];
  const rows = results.map((r) => [
    r.route,
    f1(r.idle.p50) + '/' + f1(r.idle.p95) + '/' + f0(r.idle.max),
    r.scroll.n ? f1(r.scroll.p50) + '/' + f1(r.scroll.p95) + '/' + f0(r.scroll.max) : 'no scroll',
    f0(r.idle.over25) + '/' + f0(r.scroll.over25),
    f0(r.idleMetrics.LayoutCount) + '/' + f0(r.scrollMetrics.LayoutCount),
    f0(r.idleMetrics.RecalcStyleCount) + '/' + f0(r.scrollMetrics.RecalcStyleCount),
    f1(r.idleMetrics.LayoutDuration + r.scrollMetrics.LayoutDuration),
    f1(r.idleMetrics.RecalcStyleDuration + r.scrollMetrics.RecalcStyleDuration),
    f1(r.idleMetrics.ScriptDuration + r.scrollMetrics.ScriptDuration),
    f0(r.idleMetrics.TaskDuration) + '/' + f0(r.scrollMetrics.TaskDuration),
    r.trace ? f1(r.trace.paintsPerS) : '-', r.trace ? f1(r.trace.paintMsPerS) : '-', r.trace ? f1(r.trace.rasterMsPerS) : '-'
  ]);
  const w = head.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i]).length)));
  const line = (cells) => cells.map((c, i) => String(c).padEnd(w[i])).join('  ');
  console.log(line(head));
  console.log(w.map((n) => '-'.repeat(n)).join('  '));
  for (const r of rows) { console.log(line(r)); }
  for (const r of results) {
    if (r.inner) { console.log('  inner table scroll on ' + r.route + ': p50/p95/max ' + f1(r.inner.p50) + '/' + f1(r.inner.p95) + '/' + f0(r.inner.max) + ' ms, >25ms ' + f0(r.inner.over25)); }
    if (r.capped) { console.log('  note: ' + r.route + ' scroll capped at 900 frames (page ' + f0(r.scrollMax) + ' px)'); }
    if (r.anims && r.anims.length) { console.log('  running animations on ' + r.route + ': ' + r.anims.join(', ')); }
  }
  console.log('Columns: frame deltas in ms (60 Hz = 16.7); i/s = idle phase / scroll phase; durations are main-thread ms summed over both phases;');
  console.log('paint/s, paint ms/s, raster ms/s come from a separate 2 s idle trace (0 when nothing animates on the main thread).');
}
function printCompare(before, after) {
  console.log('\nBefore -> after (idle p95, scroll p95, >25ms idle/scroll, idle task ms, idle styles, paint/s, paint ms/s)');
  for (const a of after) {
    const b = before.find((x) => x.route === a.route);
    if (!b) { continue; }
    const pair = (x, y, f) => f(x) + ' -> ' + f(y);
    console.log('  ' + a.route.padEnd(16) + '  idle p95 ' + pair(b.idle.p95, a.idle.p95, f1) + ' | scroll p95 ' + pair(b.scroll.p95, a.scroll.p95, f1) +
      ' | >25 ' + pair(b.idle.over25 + b.scroll.over25, a.idle.over25 + a.scroll.over25, f0) + ' | task ' + pair(b.idleMetrics.TaskDuration, a.idleMetrics.TaskDuration, f0) +
      ' | styles ' + pair(b.idleMetrics.RecalcStyleCount, a.idleMetrics.RecalcStyleCount, f0) +
      (a.trace && b.trace ? ' | paint/s ' + pair(b.trace.paintsPerS, a.trace.paintsPerS, f1) + ' | paint ms/s ' + pair(b.trace.paintMsPerS, a.trace.paintMsPerS, f1) : ''));
  }
}

// ------------------------------------------------------------------ main
async function main() {
  const o = parseArgs(process.argv.slice(2));
  let server = null, edge = null, cdp = null, profileDir = null;
  const cleanup = () => { if (cdp) { cdp.close(); } killTree(edge); killTree(server); };
  process.on('SIGINT', () => { cleanup(); process.exit(130); });
  try {
    if (o.server) {
      let scan = o.scan;
      if (!scan) {
        // Default: the latest scan, or the synthetic demo scan on a fresh clone (build it first with
        // `python -I -B core/build_datajs.py --scan tests/fixtures/demo-scan`).
        const latest = path.join(ROOT, 'data', 'latest.txt');
        scan = fs.existsSync(latest) ? fs.readFileSync(latest, 'utf8').trim() : path.join('tests', 'fixtures', 'demo-scan');
      }
      const stateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bvs-perf-state-'));
      const args = ['-I', '-B', path.join(ROOT, 'server', 'serve.py'), '--port', String(o.port), '--no-ai', '--state-root', stateRoot];
      if (scan) { args.push('--scan', scan); }
      server = spawn(o.python, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let serr = '';
      server.stderr.on('data', (b) => { serr += b; });
      server.stdout.on('data', () => { /* drain */ });
      server.on('exit', (c) => { if (c && c !== 0 && serr) { console.error('server exited ' + c + ': ' + serr.slice(-400)); } });
      await waitHttp(o.url, 20000);
      console.log('server: ' + o.url + ' (scan ' + (scan || 'latest') + ', state ' + stateRoot + ')');
    } else {
      await waitHttp(o.url, 5000);
      console.log('using existing server: ' + o.url);
    }

    const edgePath = o.edge || EDGE_CANDIDATES.find((p) => fs.existsSync(p));
    if (!edgePath) { throw new Error('Microsoft Edge not found; pass --edge <path>'); }
    const profileRoot = o.profileRoot || path.join(os.tmpdir(), 'bvs-perf-profile');
    fs.mkdirSync(profileRoot, { recursive: true });
    profileDir = path.join(profileRoot, 'run-' + new Date().toISOString().replace(/[:.]/g, '-') + '-' + process.pid);
    fs.mkdirSync(profileDir);
    const dport = await freePort();
    edge = spawn(edgePath, [
      '--headless=new', '--remote-debugging-port=' + dport, '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + profileDir,
      '--window-size=1600,1000', '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
      '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-domain-reliability',
      '--disable-client-side-phishing-detection', '--no-pings', '--disable-breakpad', '--mute-audio', '--hide-scrollbars',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost', 'about:blank'
    ], { stdio: 'ignore', windowsHide: true });
    const ver = await (await waitHttp('http://127.0.0.1:' + dport + '/json/version', 20000)).json();
    cdp = new CDP(ver.webSocketDebuggerUrl);
    await cdp.open();
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId: sid } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Page.enable', {}, sid);
    await cdp.send('Runtime.enable', {}, sid);
    await cdp.send('Performance.enable', { timeDomain: 'timeTicks' }, sid);
    await cdp.send('Emulation.setEmulatedMedia', { features: [
      { name: 'prefers-color-scheme', value: o.scheme },
      { name: 'prefers-reduced-motion', value: o.reduced ? 'reduce' : 'no-preference' }
    ] }, sid);
    console.log('edge: ' + ver.Browser + ' (headless, profile ' + profileDir + ')' + (o.reduced ? ' [reduced motion]' : '') + ' [' + o.scheme + ']');

    const base = o.url.replace(/#.*$/, '');
    const results = [];
    for (const route of o.routes) {
      const runs = [];
      for (let k = 0; k < o.repeat; k++) {
        process.stdout.write('  measuring ' + route + (o.repeat > 1 ? ' (' + (k + 1) + '/' + o.repeat + ')' : '') + ' ...\n');
        runs.push(await measureRoute(cdp, sid, base, route, o));
      }
      results.push(o.repeat > 1 ? combine(runs) : runs[0]);
    }
    printTable(results, 'Frame timing (headless Edge, 1600x1000, ' + o.scheme + (o.reduced ? ', reduced motion' : '') + (o.repeat > 1 ? ', median of ' + o.repeat : '') + ')');
    if (o.compare) {
      try { printCompare(JSON.parse(fs.readFileSync(o.compare, 'utf8')).results, results); } catch (e) { console.error('compare failed: ' + e.message); }
    }
    if (o.out) { fs.writeFileSync(o.out, JSON.stringify({ at: new Date().toISOString(), url: o.url, scheme: o.scheme, reduced: o.reduced, results }, null, 2)); console.log('saved ' + o.out); }
    try { await cdp.send('Browser.close', {}, undefined, 3000); } catch (e) { /* killed below */ }
    await sleep(500);
  } finally {
    cleanup();
  }
}

main().catch((e) => { console.error('perf-probe: ' + (e && e.stack || e)); process.exitCode = 1; });
