// A page on the socket.io POLLING transport that dies without pagehide must
// leave the other peers' rosters within seconds, and a polling page that is
// only slow (throttled CPU, a high round trip, a background tab) must not.
//
// Real app + relay. The relay runs with production's engine.io ping (25 s
// interval, 60 s timeout), so the ping timeout cannot pass the first part: on
// it alone a killed polling page stays a "connecting" ghost for about 85 s.
// The relay's polling liveness rule (backend/signaling.py PollWatch) is what
// has to remove it.
//
//   1. crash:    the polling page's renderer is crashed (CDP Page.crash), so
//                no pagehide, no beacon, no close; then its context is closed.
//   2. ctx-close: the context is closed with the close beacon blocked, so the
//                relay hears nothing from the page itself.
//      Both: the tile drops within KILL_BOUND_MS, through the polling rule
//      (TEL poll-lapsed), never through a session-close.
//   3. slow:     a polling page with 20x CPU throttling, 2.5 s added latency,
//                hidden (visibilityState, visibilitychange, Chrome-style 1 s
//                timer alignment) stays on the other peer for SLOW_HOLD_MS
//                without one gap, and the relay never lapses it.
//   4. flaps:    three 3 s offline flaps of a polling page; the page must be
//                back on the other peer within FLAP_BACK_MS of each.
//
//   node frontend/tests/polling-liveness.spec.cjs   (from the repo root; needs frontend/dist)
//   PL_ONLY=crash,slow  runs a subset;  PL_OUT=file.json  writes the numbers.
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
const PORT = +(process.env.PL_PORT || 8275);
const BASE = `http://127.0.0.1:${PORT}`;
// FIL_POLL_HOLD_S 2 + FIL_POLL_GRACE_S 7 + two 1 s ticks, plus the observer's
// own reaction. The ping timeout alone is 85 s.
const KILL_BOUND_MS = 13000;
const SLOW_HOLD_MS = +(process.env.PL_SLOW_MS || 60000);
const FLAP_BACK_MS = 15000;
// The slow page: added latency per request (ms) and CPU slowdown.
const SLOW_LAT_MS = +(process.env.PL_LAT || 2500);
const SLOW_CPU = +(process.env.PL_CPU || 20);
const LOG_FILE = path.join(os.tmpdir(), `tunlion-polling-liveness-${PORT}.log`);
const ONLY = (process.env.PL_ONLY || 'crash,ctx-close,slow,flaps').split(',');

let backend = null;
const failures = [];
const results = {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
function fail(msg) { console.error('[polling-liveness] FAIL:', msg); cleanup(); process.exit(1); }
const ok = (msg) => console.log('[polling-liveness] OK:', msg);

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
// so socket.io stays on long-polling.
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

// A hidden tab as Chrome treats one: visibilityState hidden (and the event,
// which the app listens to), and timers aligned to whole seconds with a 1 s
// floor (Chrome's background budget; intensive throttling is per minute and
// stricter, and is covered by the length of the hold).
function backgroundTab() {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' });
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
  document.dispatchEvent(new Event('visibilitychange'));
  const st = window.setTimeout.bind(window), si = window.setInterval.bind(window);
  const align = (ms) => { const due = Date.now() + Math.max(1000, +ms || 0); return Math.ceil(due / 1000) * 1000 - Date.now(); };
  window.setTimeout = (fn, ms, ...a) => st(fn, align(ms), ...a);
  window.setInterval = (fn, ms, ...a) => si(fn, Math.max(1000, +ms || 0), ...a);
  window.__bgAt = Date.now();
}

async function open(browser, hold) {
  const ctx = await browser.newContext();
  await ctx.addInitScript(instrument, { hold });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e && e.message || e).slice(0, 200)));
  await page.goto(BASE + '/?test=1');
  await page.waitForFunction(() => /online/i.test(document.body.innerText), null, { timeout: 20000 });
  return { ctx, page, errors };
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

async function onPolling(tag, p) {
  const fd = await p.page.evaluate(() => window.__fd);
  if (!(fd.held > 0 && fd.wsOpen === 0)) fail(`${tag}: the page was not on polling (${JSON.stringify(fd)})`);
}

async function kill(tag, observer, how) {
  const p = await open(observer.browser, true);
  const name = await deviceName(p.page);
  if ((await waitTile(observer.page, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
  await onPolling(tag, p);
  await sleep(4000); // past one NOOP cycle, so the page is in steady polling
  const before = telEvents().length;
  const t0 = Date.now();
  if (how === 'crash') {
    // A killed renderer: no pagehide, no beacon, no transport close frame.
    // Page.crash never answers (the target it would answer from is gone), so
    // wait for the page's crash event instead of the command.
    const cdp = await p.ctx.newCDPSession(p.page);
    const crashed = new Promise((r) => p.page.once('crash', () => r(true)));
    cdp.send('Page.crash').catch(() => {});
    const how = await Promise.race([crashed, sleep(5000).then(() => false)]);
    if (!how) failures.push(`${tag}: the renderer did not crash`);
    Promise.race([p.ctx.close(), sleep(5000)]).catch(() => {});
  } else {
    // A context that goes away with its close beacon refused: the relay hears
    // nothing from the page.
    await p.ctx.route('**/api/session/close', (r) => r.abort());
    await Promise.race([p.ctx.close(), sleep(5000)]).catch(() => {});
  }
  let gone = null;
  const limit = +(process.env.PL_KILL_WAIT_MS || KILL_BOUND_MS + 5000);
  while (Date.now() - t0 < limit) {
    if ((await tilesFor(observer.page, name)) === 0) { gone = Date.now() - t0; break; }
    await sleep(25);
  }
  const ev = telEvents().slice(before).map((e) => e.ev).filter((e) => /close|leave|disconnect|lapsed/.test(e));
  console.log(`[polling-liveness] ${tag}: tile gone after ${gone == null ? '>' + limit : gone} ms; relay saw [${ev.join(', ')}]`);
  results[tag] = { goneMs: gone, relay: ev };
  if (ev.includes('session-close')) failures.push(`${tag}: the relay applied a session-close, so this did not test a silent death`);
  if (!ev.includes('poll-lapsed')) failures.push(`${tag}: the relay never lapsed the polling socket (saw [${ev.join(', ')}])`);
  if (gone == null || gone > KILL_BOUND_MS) {
    failures.push(`${tag}: the dead polling page stayed on the other peer for ${gone == null ? 'over ' + limit : gone} ms (want <= ${KILL_BOUND_MS} ms)`);
    await waitTile(observer.page, name, false, 120000);
  } else ok(`${tag}: a silently dead polling page left the other peer in ${gone} ms`);
}

async function slow(observer) {
  const tag = 'slow';
  const p = await open(observer.browser, true);
  const name = await deviceName(p.page);
  if ((await waitTile(observer.page, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
  await onPolling(tag, p);
  const cdp = await p.ctx.newCDPSession(p.page);
  await cdp.send('Network.enable');
  await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: SLOW_LAT_MS, downloadThroughput: 64 * 1024, uploadThroughput: 32 * 1024 });
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: SLOW_CPU });
  await p.page.evaluate(backgroundTab);
  // A second tab in front as well, for whatever real background handling the
  // headless browser applies.
  const front = await p.ctx.newPage();
  await front.goto('about:blank');
  await front.bringToFront();
  const vis = await p.page.evaluate(() => document.visibilityState);
  const before = telEvents().length;
  const t0 = Date.now();
  let gaps = 0, gapStart = null, longest = 0;
  while (Date.now() - t0 < SLOW_HOLD_MS) {
    const n = await tilesFor(observer.page, name);
    if (n === 0 && gapStart == null) { gapStart = Date.now(); gaps += 1; }
    if (n > 0 && gapStart != null) { longest = Math.max(longest, Date.now() - gapStart); gapStart = null; }
    await sleep(100);
  }
  if (gapStart != null) longest = Math.max(longest, Date.now() - gapStart);
  const ev = telEvents().slice(before);
  const lapsed = ev.filter((e) => e.ev === 'poll-lapsed').length;
  const disc = ev.filter((e) => e.ev === 'disconnect').length;
  // The slow page still hears the room (both directions).
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 1 });
  await cdp.send('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  const sees = await waitTile(p.page, observer.name, true, 15000);
  console.log(`[polling-liveness] ${tag}: ${SLOW_HOLD_MS} ms hidden (${vis}) at ${SLOW_CPU}x CPU + ${SLOW_LAT_MS} ms latency: ${gaps} gap(s), longest ${longest} ms; relay poll-lapsed ${lapsed}, disconnect ${disc}; page sees observer: ${sees != null}`);
  results[tag] = { holdMs: SLOW_HOLD_MS, latencyMs: SLOW_LAT_MS, cpu: SLOW_CPU, visibility: vis, gaps, longestGapMs: longest, pollLapsed: lapsed, disconnects: disc, seesObserver: sees != null };
  if (gaps || lapsed || disc) failures.push(`${tag}: a slow, hidden polling page dropped (${gaps} gap(s), longest ${longest} ms, poll-lapsed ${lapsed}, disconnect ${disc})`);
  else if (sees == null) failures.push(`${tag}: the slow page no longer sees the other peer`);
  else ok(`${tag}: a throttled, hidden, high-latency polling page stayed on the other peer for ${SLOW_HOLD_MS} ms`);
  await p.ctx.close();
}

async function flaps(observer) {
  const tag = 'flaps';
  const p = await open(observer.browser, true);
  const name = await deviceName(p.page);
  if ((await waitTile(observer.page, name, true, 20000)) == null) fail(`${tag}: the observer never saw ${name}`);
  await onPolling(tag, p);
  const rounds = [];
  for (let i = 0; i < 3; i++) {
    const before = telEvents().length;
    await p.ctx.setOffline(true);
    const t0 = Date.now();
    let gone = null;
    while (Date.now() - t0 < 3000) {
      if (gone == null && (await tilesFor(observer.page, name)) === 0) gone = Date.now() - t0;
      await sleep(50);
    }
    await p.ctx.setOffline(false);
    const t1 = Date.now();
    const back = await waitTile(observer.page, name, true, FLAP_BACK_MS);
    // Settled: still there a few seconds later.
    await sleep(4000);
    const stays = (await tilesFor(observer.page, name)) > 0;
    const ev = telEvents().slice(before).map((e) => e.ev).filter((e) => /lapsed|disconnect|connect$|superseded/.test(e));
    rounds.push({ goneDuringOfflineMs: gone, backAfterOnlineMs: back, stays, relay: ev });
    console.log(`[polling-liveness] ${tag} ${i + 1}: gone while offline ${gone == null ? 'no' : 'at ' + gone + ' ms'}; back ${back} ms after online; stays ${stays}; relay [${ev.join(', ')}]`);
    if (back == null || !stays) failures.push(`${tag} ${i + 1}: the page was not back on the other peer within ${FLAP_BACK_MS} ms of coming online`);
    await sleep(2000);
  }
  results[tag] = rounds;
  await p.ctx.close();
}

(async () => {
  if (!fs.existsSync(path.join(ROOT, 'frontend', 'dist', 'index.html'))) fail('build the web app first: (cd frontend && VITE_TUNLION_API= npm run build)');
  const logFd = fs.openSync(LOG_FILE, 'w');
  const eventlet = (process.env.PL_ASYNC || 'eventlet') === 'eventlet';
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    // Production's engine.io ping, and production's async server.
    env: { ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: eventlet ? 'eventlet' : 'threading', ...(eventlet ? { FIL_SELF_MONKEYPATCH: '1' } : {}), FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '60', FIL_PING_INTERVAL: '25', FIL_SECRET: 'polling-liveness-test-secret' },
    stdio: ['ignore', logFd, logFd],
  });
  if (!(await waitHealth(30000))) fail('relay did not come up; log: ' + LOG_FILE);
  const browser = await playwright.chromium.launch();
  try {
    const a = await open(browser, false);
    const observer = { browser, page: a.page, name: await deviceName(a.page) };
    if (ONLY.includes('crash')) await kill('crash', observer, 'crash');
    if (ONLY.includes('ctx-close')) await kill('ctx-close', observer, 'ctx-close');
    if (ONLY.includes('slow')) await slow(observer);
    if (ONLY.includes('flaps')) await flaps(observer);
    await a.ctx.close();
  } finally {
    await browser.close().catch(() => {});
    cleanup();
  }
  if (process.env.PL_OUT) fs.writeFileSync(process.env.PL_OUT, JSON.stringify(results, null, 1));
  if (failures.length) fail(failures.join('; '));
  console.log('[polling-liveness] PASSED');
})().catch((e) => fail(e && e.stack || String(e)));
