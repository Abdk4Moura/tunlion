// A closed tab must leave the other peers' rosters at once, against the REAL
// app + relay, on both socket.io transports.
//
// Guards the "connecting ghost": a page on the polling transport (a network
// that holds the websocket upgrade) was closed, and every other peer kept its
// tile for the lease TTL plus the engine.io ping timeout (about a minute in
// production). A websocket page went at once only because its TCP close
// reached the relay. The page now announces its own departure on pagehide, and
// the relay drops a closed session from the room at once on either transport.
//
//   1. polling: a page behind a held websocket is closed; the other peer drops
//      its tile within DEPART_MS.
//   2. websocket: the same, for a page whose websocket opened.
//   3. bfcache: a pagehide with persisted=true followed by a pageshow restore
//      must come back; the other peer sees the device again.
//
// The relay runs with a long ping timeout (as the other browser gates do), so
// the backstop cannot pass this gate: only an explicit departure can.
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
  // What the page sent on its way out (the context outlives the page).
  const sent = [];
  const note = (r, how) => { if (/\/api\/session\/close|transport=polling.*POST/.test(r.url() + ' ' + r.method())) sent.push(`${how} ${r.method()} ${r.url().replace(BASE, '').slice(0, 60)}`); };
  ctx.on('requestfinished', (r) => note(r, 'ok'));
  ctx.on('requestfailed', (r) => note(r, 'failed'));
  await ctx.addInitScript(instrument, { hold });
  const page = await ctx.newPage();
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
  const sentBefore = leaving.sent.length;
  const t0 = Date.now();
  // A real tab close: the renderer runs pagehide/unload, then the target goes.
  await leaving.page.close({ runBeforeUnload: true });
  let gone = null;
  while (Date.now() - t0 < DEPART_MS + 8000) {
    if ((await tilesFor(observer, name)) === 0) { gone = Date.now() - t0; break; }
    await sleep(25);
  }
  const ev = telEvents().slice(before).map((e) => e.ev).filter((e) => /close|leave|disconnect/.test(e));
  const out = leaving.sent.slice(sentBefore).filter((x) => /session\/close/.test(x));
  console.log(`[closed-tab] ${tag}: tile gone after ${gone == null ? '>' + (DEPART_MS + 8000) : gone} ms; page sent [${out.join(', ')}]; relay saw [${ev.join(', ')}]`);
  await leaving.ctx.close().catch(() => {});
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

    // 1. Polling transport.
    const p = await open(browser, true);
    await closeAndTime('polling', a.page, p, { polling: true });

    // 2. Websocket transport.
    const w = await open(browser, false);
    await closeAndTime('websocket', a.page, w, { polling: false });

    // 3. bfcache: pagehide(persisted) then pageshow(persisted) is a page that
    //    comes back, not a departure. It must end up on the other peer again.
    for (const hold of [true, false]) {
      const tag = hold ? 'bfcache/polling' : 'bfcache/websocket';
      const b = await open(browser, hold);
      const name = await deviceName(b.page);
      if ((await waitTile(a.page, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
      await b.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
      await sleep(300);
      await b.page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
      // Stable presence after the restore: seen now, and still there later.
      const back = await waitTile(a.page, name, true, 10000);
      await sleep(3000);
      const why = back == null ? 'the restored page never came back on the other peer'
        : (await tilesFor(a.page, name)) === 0 ? 'the restored page dropped off the other peer again'
          : /took over/i.test(await b.page.evaluate(() => document.body.innerText)) ? 'the restored page shows itself superseded' : null;
      if (why) failures.push(`${tag}: ${why}`);
      else ok(`${tag}: a restored page comes back and stays on the other peer`);
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
