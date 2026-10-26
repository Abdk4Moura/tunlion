// Peer detection must not wait on a fixed bound, against the REAL app + relay.
//
// Guards two measured delays (evidence: pairing-ux/evidence/fast-detect):
//   1. A held websocket upgrade (a middlebox that never completes it) cost
//      every page load the fixed 4 s connect bound plus a reconnect delay
//      before the page could see any peer. The websocket attempt is now hedged
//      by the measured API round trip, so the page falls back to polling and
//      sees its peer well inside that old bound.
//   2. A reload (a page that already holds a session token) sent its sync and
//      its join together; both ran the room join, so every other peer saw the
//      reloaded device leave and come back (peer-left + peer-joined for the
//      same sid) and tore down its link. The other peer must see the new sid
//      arrive exactly once and never leave.
//
//   node frontend/tests/fast-detect.spec.cjs        (from the repo root; needs frontend/dist)
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const PORT = 8273;
const BASE = `http://127.0.0.1:${PORT}`;
const OLD_BOUND_MS = 4000; // SOCKET_TIMEOUT_MS: the earliest the old code could fall back
const LOG_FILE = path.join(os.tmpdir(), 'tunlion-fast-detect.log');

let backend = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
function fail(msg) { console.error('[fast-detect] FAIL:', msg); cleanup(); process.exit(1); }
const ok = (msg) => console.log('[fast-detect] OK:', msg);

async function waitHealth(ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const up = await new Promise((res) => {
      const req = http.get(`${BASE}/api/health`, (r) => { r.resume(); res(r.statusCode === 200); });
      req.on('error', () => res(false));
      req.setTimeout(1000, () => { req.destroy(); res(false); });
    });
    if (up) return true;
    await sleep(200);
  }
  return false;
}

// Records socket.io events (in-page clock) and peer-tile count changes. With
// hold=true the websocket is one a middlebox holds: it never opens or errors.
function instrument({ hold }) {
  const fd = (window.__fd = { ev: [], tiles: [], tile1: null });
  const now = () => Math.round(performance.now());
  const W = window.WebSocket;
  window.WebSocket = function (...a) {
    if (hold) {
      fd.ev.push({ t: now(), e: 'ws-held' });
      const fake = new EventTarget();
      Object.assign(fake, { readyState: 0, url: a[0], protocol: '', extensions: '', bufferedAmount: 0, binaryType: 'blob', send() {}, close() { fake.readyState = 3 } });
      return fake;
    }
    const ws = new W(...a);
    ws.addEventListener('message', (m) => {
      const s = typeof m.data === 'string' ? m.data : '';
      const mm = /^42(\[.*)$/s.exec(s);
      if (!mm) return;
      try { const [name, p] = JSON.parse(mm[1]); fd.ev.push({ t: now(), e: name, id: p && p.id }); } catch {}
    });
    return ws;
  };
  window.WebSocket.prototype = W.prototype;
  Object.assign(window.WebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
  let last = -1;
  new MutationObserver(() => {
    const n = document.querySelectorAll('[data-testid="peer-tile"]').length;
    if (n !== last) { last = n; fd.tiles.push({ t: now(), n }); }
    if (n && fd.tile1 == null) fd.tile1 = now();
  }).observe(document, { subtree: true, childList: true });
}

async function page(browser, hold) {
  const ctx = await browser.newContext();
  await ctx.addInitScript(instrument, { hold });
  return { ctx, page: await ctx.newPage() };
}
const fdOf = (p) => p.evaluate(() => window.__fd);

(async () => {
  if (!fs.existsSync(path.join(ROOT, 'frontend', 'dist', 'index.html'))) fail('build the web app first: (cd frontend && VITE_TUNLION_API= npm run build)');
  const logFd = fs.openSync(LOG_FILE, 'w');
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: { ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading', FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25', FIL_SECRET: 'fast-detect-test-secret' },
    stdio: ['ignore', logFd, logFd],
  });
  if (!(await waitHealth(30000))) fail('relay did not come up; log: ' + LOG_FILE);
  const browser = await playwright.chromium.launch();
  try {
    // 1. Held websocket: the page must still see its peer inside the old bound.
    const a = await page(browser, false);
    await a.page.goto(BASE + '/?test=1');
    await a.page.waitForFunction(() => /online/i.test(document.body.innerText), null, { timeout: 20000 });
    const b = await page(browser, true);
    await b.page.goto(BASE + '/?test=1');
    await b.page.waitForFunction(() => window.__fd.tile1 != null, null, { timeout: 20000 }).catch(() => {});
    const fb = await fdOf(b.page);
    if (fb.tile1 == null) fail('the page behind a held websocket never saw its peer');
    if (!fb.ev.some((e) => e.e === 'ws-held')) fail('the websocket was not held (the scenario did not run)');
    if (fb.tile1 >= OLD_BOUND_MS) fail(`the page behind a held websocket saw its peer only at ${fb.tile1} ms (old bound ${OLD_BOUND_MS} ms)`);
    ok(`held websocket: peer visible at ${fb.tile1} ms after navigation (old code: >= ${OLD_BOUND_MS} ms)`);
    await b.ctx.close();

    // 2. Reload churn: c holds a token, reloads; a must see the new sid join
    //    once and never leave.
    const c = await page(browser, false);
    await c.page.goto(BASE + '/?test=1');
    await a.page.waitForFunction(() => document.querySelectorAll('[data-testid="peer-tile"]').length >= 1, null, { timeout: 20000 });
    await c.page.waitForFunction(() => !!localStorage.getItem('tunlion.ownerToken'), null, { timeout: 20000 });
    const mark = (await fdOf(a.page)).ev.length;
    await c.page.reload();
    await c.page.waitForFunction(() => window.__fd.ev.some((e) => e.e === 'welcome'), null, { timeout: 20000 });
    await sleep(2500);
    const newSid = (await fdOf(c.page)).ev.filter((e) => e.e === 'welcome').at(-1).id;
    const after = (await fdOf(a.page)).ev.slice(mark).filter((e) => e.id === newSid);
    const left = after.filter((e) => e.e === 'peer-left').length;
    const joined = after.filter((e) => e.e === 'peer-joined').length;
    if (left !== 0) fail(`the other peer was told the reloaded device left ${left} time(s): ${JSON.stringify(after)}`);
    if (joined !== 1) fail(`the other peer saw the reloaded device join ${joined} times (want 1): ${JSON.stringify(after)}`);
    ok('reload: the other peer saw the new session join once and never leave');
  } finally {
    await browser.close().catch(() => {});
    cleanup();
  }
  console.log('[fast-detect] PASSED');
})().catch((e) => fail(e && e.stack || String(e)));
