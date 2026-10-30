// Browser <-> browser pairing with human names, against the REAL built app and
// the real Flask relay. Two Chromium contexts (two devices):
//
//   A = "Abdul's iPad"   creates a code
//   B = "Kabir Laptop"   enters it with "Remember a device"
//
// Both choose Remember. The gate then watches each side's Devices row for the
// other device and the live peer tile for 40 s, and FAILS if the remembered
// device is ever not online, or the tile disappears, after it first came up.
// Then: a local petname rename on A ("iPad"), and a self rename on B
// ("Kabir's Laptop"); each must keep the link online.
//
//   node frontend/tests/browser-pair-names.spec.cjs   (dist built same-origin)

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));
const { chromium } = playwright;

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(ROOT, 'frontend', 'dist');
const PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const PORT = Number(process.env.BPN_PORT || 8297);
const BASE = process.env.BPN_BASE || `http://127.0.0.1:${PORT}`;
const WATCH_MS = Number(process.env.BPN_WATCH_MS || 40000);

let backend = null;
let backendLog = '';
function fail(msg) { console.error('[pair-names] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[pair-names] OK:', msg); }
function note(msg) { console.log('[pair-names]', msg); }
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startBackend() {
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: {
      ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading',
      FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25',
      FIL_SECRET: 'pair-names-test-secret',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backend.stdout.on('data', (d) => { backendLog += d; });
  backend.stderr.on('data', (d) => { backendLog += d; });
}

async function waitHealth(timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const up = await new Promise((res) => {
      const req = http.get(`${BASE}/api/health`, (r) => { r.resume(); res(r.statusCode === 200); });
      req.on('error', () => res(false));
      req.setTimeout(1000, () => { req.destroy(); res(false); });
    });
    if (up) return true;
    await sleep(300);
  }
  return false;
}

async function device(browser, label, name, route = '/') {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 } });
  await ctx.addInitScript((n) => {
    try { if (!localStorage.getItem('tunlion.deviceName')) localStorage.setItem('tunlion.deviceName', n) } catch {}
    try { localStorage.setItem('tunlionLog', 'debug') } catch {}
  }, name);
  const page = await ctx.newPage();
  const logs = [];
  page.on('console', (m) => logs.push(`${Date.now()} ${m.type()} ${m.text()}`));
  await page.goto(`${BASE}${route}`, { waitUntil: 'domcontentloaded' });
  return { ctx, page, logs, label, name };
}

// What this page shows right now about remembered devices and live peers.
async function snapshot(page) {
  return page.evaluate(() => {
    const rows = [...document.querySelectorAll('[data-testid="device-row"]')].map((r) => r.getAttribute('aria-label'));
    const tiles = [...document.querySelectorAll('[data-testid="peer-tile"]')].map((t) => t.getAttribute('aria-label'));
    let known = []
    try { known = JSON.parse(localStorage.getItem('filament-known-devices') || '[]').map((d) => d.name) } catch {}
    return { rows, tiles, known };
  });
}

async function gotoTab(page, tab) {
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: new RegExp('^' + tab) }).click();
}

(async () => {
  if (process.env.BPN_BASE) {
    ok('using ' + BASE + ' (no local relay)');
  } else {
    if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built: VITE_TUNLION_API= npm run build');
    startBackend();
    if (!(await waitHealth(20000))) fail('backend never healthy:\n' + backendLog.slice(-2000));
    ok('relay up');
  }

  const browser = await chromium.launch({ headless: true });
  const A = await device(browser, 'A', "Abdul's iPad");
  // BPN_SAME_ROOM=1 keeps both in the one auto room (same network), the
  // common home case; otherwise B starts in a room of its own.
  const B = await device(browser, 'B', 'Kabir Laptop', process.env.BPN_SAME_ROOM === '1' ? '/' : '/rooms/bpn-' + Date.now());

  // A creates a code; B enters it in remember mode.
  await A.page.getByTestId('create-code').click();
  const codeEl = A.page.getByTestId('room-code');
  await codeEl.waitFor({ timeout: 40000 }).catch(async () => fail('no code shown; A text: ' + (await A.page.evaluate(() => document.body.innerText)).slice(0, 1500) + '\nA logs:\n' + A.logs.slice(-30).join('\n')));
  const code = (await codeEl.innerText()).trim();
  note('code ' + code);
  await B.page.getByRole('radio', { name: 'Remember a device' }).first().click();
  const input = B.page.locator('#tl-code-w');
  await input.fill(code);
  await B.page.getByTestId('code-connect').first().click();

  // Both see the consent banner; both Remember under the suggested name.
  for (const d of [A, B]) {
    const banner = d.page.getByRole('region', { name: 'Remember this device?' }).first();
    await banner.waitFor({ timeout: 45000 }).catch(async () => {
      const txt = async (x) => (await x.page.evaluate(() => document.body.innerText)).slice(0, 1500);
      fail(`${d.label}: no Remember banner; snapshot ${JSON.stringify(await snapshot(d.page))}\nA logs:\n${A.logs.filter((x) => /pake|pair|known|rtc|link/i.test(x)).slice(-60).join('\n')}\nB logs:\n${B.logs.filter((x) => /pake|pair|known|rtc|link/i.test(x)).slice(-60).join('\n')}\nrelay:\n${backendLog.split('\n').filter((x) => /pake|pair|claim|signal-refused|join/i.test(x)).slice(-60).join('\n')}`);
    });
    const suggested = await banner.locator('input').inputValue().catch(() => '(no input)');
    note(`${d.label} banner suggests name: ${JSON.stringify(suggested)}`);
  }
  for (const d of [A, B]) {
    await d.page.getByRole('region', { name: 'Remember this device?' }).first().getByRole('button', { name: 'Remember' }).click();
    if (d === A && process.env.BPN_STAGGER_MS) {
      await gotoTab(A.page, 'Devices');
      const t0 = Date.now();
      while (Date.now() - t0 < Number(process.env.BPN_STAGGER_MS)) { note('stagger A ' + JSON.stringify(await snapshot(A.page))); await sleep(2000); }
      await gotoTab(A.page, 'Home');
    }
  }
  ok('both chose Remember');

  for (const d of [A, B]) await gotoTab(d.page, 'Devices');

  // Watch both sides. Record every distinct state; the device must come
  // online and STAY online.
  const watch = async (phase, ms) => {
    const t0 = Date.now();
    const seen = { A: [], B: [] };
    const cameUp = { A: false, B: false };
    const dropped = { A: null, B: null };
    while (Date.now() - t0 < ms) {
      for (const d of [A, B]) {
        const s = await snapshot(d.page);
        const key = JSON.stringify(s);
        const last = seen[d.label][seen[d.label].length - 1];
        if (!last || last.key !== key) {
          seen[d.label].push({ t: Date.now() - t0, key });
          note(`${phase} ${d.label} +${Date.now() - t0}ms ${key}`);
        }
        const online = s.rows.some((r) => /, online$/.test(r));
        if (online) cameUp[d.label] = true;
        else if (cameUp[d.label] && !dropped[d.label]) dropped[d.label] = { t: Date.now() - t0, s };
      }
      await sleep(500);
    }
    return { cameUp, dropped };
  };

  const r1 = await watch('paired', WATCH_MS);
  const problems = [];
  for (const l of ['A', 'B']) {
    if (!r1.cameUp[l]) problems.push(`${l}: the remembered device never showed online`);
    if (r1.dropped[l]) problems.push(`${l}: the remembered device went offline at +${r1.dropped[l].t}ms: ${JSON.stringify(r1.dropped[l].s)}`);
  }
  if (problems.length) {
    for (const d of [A, B]) note(`${d.label} console tail:\n` + d.logs.filter((x) => /known|proof|digest|peer|left|stale|tel/i.test(x)).slice(-60).join('\n'));
    note('backend tail:\n' + backendLog.split('\n').filter((x) => /known|sync|join|leave|disconnect|room/i.test(x)).slice(-60).join('\n'));
    fail(problems.join('\n'));
  }
  ok('both remembered devices came online and stayed online for ' + WATCH_MS + 'ms');

  // Each phase: act, then watch. A phase passes when both rows are online at
  // the end; any offline sample is reported with its time.
  const PHASE_MS = Number(process.env.BPN_PHASE_MS || 30000);
  const results = [];
  const phase = async (label, act) => {
    note('=== phase: ' + label);
    await act();
    const t0 = Date.now();
    const offline = { A: [], B: [] };
    let end = null;
    while (Date.now() - t0 < PHASE_MS) {
      end = {};
      for (const d of [A, B]) {
        const s = await snapshot(d.page);
        const on = s.rows.some((r) => /, online$/.test(r));
        end[d.label] = { on, s };
        if (!on) offline[d.label].push(Date.now() - t0);
      }
      await sleep(500);
    }
    const r = { label, endA: end.A, endB: end.B,
      offA: offline.A.length ? `${offline.A[0]}..${offline.A[offline.A.length - 1]}ms (${offline.A.length} samples)` : 'never',
      offB: offline.B.length ? `${offline.B[0]}..${offline.B[offline.B.length - 1]}ms (${offline.B.length} samples)` : 'never' };
    note(JSON.stringify(r));
    results.push(r);
  };

  await phase('B: Back to people near you', async () => {
    await gotoTab(B.page, 'Home');
    await B.page.getByRole('button', { name: 'Back to people near you' }).click();
    await gotoTab(B.page, 'Devices');
  });
  await phase('B: reload', async () => {
    await B.page.reload({ waitUntil: 'domcontentloaded' });
    await gotoTab(B.page, 'Devices');
  });
  await phase('B: rename A locally to "iPad"', async () => {
    await B.page.getByTestId('device-row').first().click();
    await B.page.getByRole('button', { name: /rename/i }).first().click();
    const inp = B.page.getByLabel('device name', { exact: true });
    await inp.fill('iPad');
    await inp.press('Enter');
    await B.page.keyboard.press('Escape');
    note('B known after rename: ' + JSON.stringify((await snapshot(B.page)).known));
  });
  await phase('A: rename itself to "Abdul iPad Pro"', async () => {
    await gotoTab(A.page, 'Home');
    const inp = A.page.getByTestId('device-name-input');
    await inp.fill('Abdul iPad Pro');
    await inp.press('Enter');
    await gotoTab(A.page, 'Devices');
  });
  await phase('A: network drops for 15 s', async () => {
    await A.ctx.setOffline(true);
    await sleep(15000);
    await A.ctx.setOffline(false);
  });
  await phase('B: network drops for 40 s', async () => {
    await B.ctx.setOffline(true);
    await sleep(40000);
    await B.ctx.setOffline(false);
  });
  await phase('A: close tab, open a new tab', async () => {
    const p2 = await A.ctx.newPage();
    p2.on('console', (m) => A.logs.push(`${Date.now()} ${m.type()} ${m.text()}`));
    await A.page.close();
    A.page = p2;
    await p2.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
    await gotoTab(p2, 'Devices');
  });

  const bad = results.filter((r) => !r.endA.on || !r.endB.on);
  if (bad.length) {
    for (const d of [A, B]) note(`${d.label} console tail:\n` + d.logs.slice(-80).join('\n'));
    fail('phases ending offline: ' + bad.map((r) => r.label).join('; '));
  }
  ok('every phase ended with both devices online');

  await browser.close();
  cleanup();
  process.exit(0);
})().catch((e) => fail(String(e && e.stack || e)));
