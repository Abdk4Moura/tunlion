// A page that goes away must leave the other peers' rosters at once, and a
// page that comes back from bfcache must rejoin, against the REAL app + relay,
// on both socket.io transports.
//
//   1. polling: a page behind a held websocket (so on long-polling) is closed;
//      the other peer drops its tile within DEPART_MS, through the page's own
//      pagehide close (the relay applies a session-close), not the backstop.
//   2. websocket: the same, for a page whose websocket opened.
//   3. bfcache: pagehide(persisted) then pageshow(persisted), three rounds per
//      transport. The restored page must be back on the other peer, hear the
//      other peer itself, and not call itself superseded. Two defects failed
//      this: the relay's echo of the page's own close (session-superseded,
//      reason page-closed) was read as another tab taking over, so the page
//      suspended for good; and engine.io-client drops its in-flight long-poll
//      requests on pagehide without settling them, so a polling page came back
//      with a transport that sent and received nothing until a ping timeout.
//
// The relay runs with a long ping timeout (as the other browser gates do), so
// the backstop cannot pass this gate: only an explicit departure can. A page
// that dies without running pagehide at all (a killed renderer) is outside
// what any explicit signal can cover; there the relay's polling liveness rule
// (polling, polling-liveness.spec.cjs) or the TCP close (websocket) decides.
//
//   node frontend/tests/closed-tab.spec.cjs        (from the repo root; needs frontend/dist)
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
const PORT = 8274;
const BASE = `http://127.0.0.1:${PORT}`;
const DEPART_MS = 1500;
const LOG_FILE = path.join(os.tmpdir(), 'tunlion-closed-tab.log');

let backend = null;
// Every scenario runs, so one run reports both transports' numbers.
const failures = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
function fail(msg) { console.error('[closed-tab] FAIL:', msg); cleanup(); process.exit(1); }
const ok = (msg) => console.log('[closed-tab] OK:', msg);

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

function telEvents() {
  let raw = '';
  try { raw = fs.readFileSync(LOG_FILE, 'utf8'); } catch {}
  const out = [];
  for (const line of raw.split('\n')) {
    const i = line.indexOf('TEL {');
    if (i < 0) continue;
    try { out.push(JSON.parse(line.slice(i + 4))); } catch {}
  }
  return out;
}

// hold=true: a websocket that a middlebox holds (never opens, never errors),
// so socket.io falls back to long-polling. Records which transports opened.
function instrument({ hold }) {
  const fd = (window.__fd = { held: 0, wsOpen: 0 });
  const W = window.WebSocket;
  window.WebSocket = function (...a) {
    if (hold) {
      fd.held += 1;
      const fake = new EventTarget();
      Object.assign(fake, { readyState: 0, url: a[0], protocol: '', extensions: '', bufferedAmount: 0, binaryType: 'blob', send() {}, close() { fake.readyState = 3 } });
      return fake;
    }
    const ws = new W(...a);
    ws.addEventListener('open', () => { fd.wsOpen += 1 });
    return ws;
  };
  window.WebSocket.prototype = W.prototype;
  Object.assign(window.WebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
}

async function open(browser, hold) {
  const ctx = await browser.newContext();
  // The page's socket.io and close requests (the context outlives the page),
  // printed when a bfcache round fails.
  const sent = [];
  const t00 = Date.now();
  const note = (r, how) => { if (/\/api\/session\/close|socket\.io/.test(r.url())) sent.push(`${Date.now() - t00}:${how} ${r.method()} ${r.url().replace(BASE, '').replace(/[?].*/, '')}${/close/.test(r.url()) ? '' : /transport=(\w+)/.exec(r.url())?.[1] || ''}`); };
  ctx.on('request', (r) => note(r, 'start'));
  ctx.on('requestfinished', (r) => note(r, 'ok'));
  ctx.on('requestfailed', (r) => note(r, 'failed'));
  await ctx.addInitScript(instrument, { hold });
  const page = await ctx.newPage();
  // A throw inside a socket.io handler would stop a polling transport too
  // (the next long-poll is never issued), so page errors go in that log.
  page.on('pageerror', (e) => sent.push(`${Date.now() - t00}:pageerror ${String(e && e.message || e).slice(0, 200)}`));
  page.on('console', (m) => { if (m.type() === 'error') sent.push(`${Date.now() - t00}:console ${m.text().slice(0, 200)}`); });
  await page.goto(BASE + '/?test=1');
  await page.waitForFunction(() => /online/i.test(document.body.innerText), null, { timeout: 20000 });
  return { ctx, page, sent };
}

const deviceName = (page) => page.evaluate(() => document.querySelector('[data-testid="device-name-input"]')?.value || document.documentElement.getAttribute('data-device-name') || '');
const tilesFor = (page, name) => page.evaluate((n) => [...document.querySelectorAll('[data-testid="peer-tile"]')]
  .filter((el) => (el.getAttribute('aria-label') || '').startsWith(n + ',')).length, name);

async function waitTile(page, name, want, ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (((await tilesFor(page, name)) > 0) === want) return Date.now() - t0;
    await sleep(25);
  }
  return null;
}

// Close `leaving` and time how long `observer` keeps its tile.
async function closeAndTime(tag, observer, leaving, { polling }) {
  const name = await deviceName(leaving.page);
  if (!name) fail(`${tag}: the leaving page has no device name`);
  if ((await waitTile(observer, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
  const fd = await leaving.page.evaluate(() => window.__fd);
  if (polling && !(fd.held > 0 && fd.wsOpen === 0)) fail(`${tag}: the leaving page was not on polling (${JSON.stringify(fd)})`);
  if (!polling && !(fd.wsOpen > 0)) fail(`${tag}: the leaving page never opened its websocket (${JSON.stringify(fd)})`);
  // Let the room settle, so a late roster refresh cannot mask the departure.
  await sleep(1000);
  const before = telEvents().length;
  const t0 = Date.now();
  // A real tab close: the renderer runs pagehide/unload, then the target goes.
  await leaving.page.close({ runBeforeUnload: true });
  let gone = null;
  while (Date.now() - t0 < DEPART_MS + 8000) {
    if ((await tilesFor(observer, name)) === 0) { gone = Date.now() - t0; break; }
    await sleep(25);
  }
  await leaving.ctx.close().catch(() => {});
  const ev = telEvents().slice(before).map((e) => e.ev).filter((e) => /close|leave|disconnect/.test(e));
  console.log(`[closed-tab] ${tag}: tile gone after ${gone == null ? '>' + (DEPART_MS + 8000) : gone} ms; relay saw [${ev.join(', ')}]`);
  if (!ev.includes('session-close')) failures.push(`${tag}: the relay never applied the page's own close (saw [${ev.join(', ')}])`);
  if (gone == null || gone > DEPART_MS) {
    failures.push(`${tag}: the closed page stayed on the other peer for ${gone == null ? 'over ' + (DEPART_MS + 8000) : gone} ms (want <= ${DEPART_MS} ms)`);
    // The tile may still be up: wait it out so the next scenario starts clean.
    await waitTile(observer, name, false, 180000);
  } else ok(`${tag}: the closed page left the other peer's roster in ${gone} ms`);
  return gone;
}

(async () => {
  if (!fs.existsSync(path.join(ROOT, 'frontend', 'dist', 'index.html'))) fail('build the web app first: (cd frontend && VITE_TUNLION_API= npm run build)');
  const logFd = fs.openSync(LOG_FILE, 'w');
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    // The long ping timeout keeps the backstop out of reach: only an explicit
    // departure can remove the tile inside DEPART_MS.
    env: { ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading', FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25', FIL_SECRET: 'closed-tab-test-secret' },
    stdio: ['ignore', logFd, logFd],
  });
  if (!(await waitHealth(30000))) fail('relay did not come up; log: ' + LOG_FILE);
  const browser = await playwright.chromium.launch();
  try {
    const a = await open(browser, false);
    const aName = await deviceName(a.page);

    // 1. Polling transport.
    const p = await open(browser, true);
    await closeAndTime('polling', a.page, p, { polling: true });

    // 2. Websocket transport.
    const w = await open(browser, false);
    await closeAndTime('websocket', a.page, w, { polling: false });

    // 3. bfcache: pagehide(persisted) then pageshow(persisted) is a page that
    //    comes back, not a departure. Three rounds each: the relay's echo of
    //    the page's own close races the restore.
    for (const hold of [true, false, true, false, true, false]) {
      const tag = hold ? 'bfcache/polling' : 'bfcache/websocket';
      const b = await open(browser, hold);
      const name = await deviceName(b.page);
      if ((await waitTile(a.page, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
      const mark = telEvents().length;
      const sentMark = b.sent.length;
      await b.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
      await sleep(300);
      await b.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
      // Stable presence after the restore: seen now, and still there later.
      const sockAt = async () => b.page.evaluate(() => window.__tunlionTestSocket && window.__tunlionTestSocket());
      const sock1 = await sockAt();
      const back = await waitTile(a.page, name, true, 10000);
      const sock2 = await sockAt();
      await sleep(3000);
      // Both directions: a wedged long-poll can still deliver an earlier
      // join while the restored page itself hears nothing.
      const sees = await waitTile(b.page, aName, true, 10000);
      const why = back == null ? 'the restored page never came back on the other peer'
        : sees == null ? 'the restored page never saw the other peer again'
        : (await tilesFor(a.page, name)) === 0 ? 'the restored page dropped off the other peer again'
          : /took over/i.test(await b.page.evaluate(() => document.body.innerText)) ? 'the restored page shows itself superseded' : null;
      const seen = telEvents().slice(mark).filter((e) => !/^web:(vis|net|conn|link|ice|tile|cfg)/.test(e.ev))
        .map((e) => e.ev + (e.reason ? '(' + e.reason + ')' : '') + (e.status ? '(' + e.status + ')' : ''));
      if (why) {
        // What a failure needs to be read: the relay's view, the page's
        // socket transport state, and its socket.io requests around the trip.
        console.log(`[closed-tab] ${tag}: relay saw [${seen.slice(0, 40).join(', ')}]`);
        console.log(`[closed-tab] ${tag}: socket after restore ${JSON.stringify(sock1)} later ${JSON.stringify(sock2)}`);
        console.log(`[closed-tab] ${tag}: page requests [${b.sent.slice(Math.max(0, sentMark - 4), sentMark + 40).join(', ')}]`);
        failures.push(`${tag}: ${why}`);
      } else ok(`${tag}: a restored page comes back and stays on the other peer`);
      await b.ctx.close();
    }
    await a.ctx.close();
  } finally {
    await browser.close().catch(() => {});
    cleanup();
  }
  if (failures.length) fail(failures.join('; '));
  console.log('[closed-tab] PASSED');
})().catch((e) => fail(e && e.stack || String(e)));
