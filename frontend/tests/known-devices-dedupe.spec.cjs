// Browser gate: duplicate known-device records migrate to one row and the
// surviving (newest) secret actually reconnects, against the REAL app + relay.
//
// Seeds localStorage with two records for the same local petname, exactly the
// state left by the re-pairing bug. On load devicesLoad must keep the newest
// record, write the clean list back, render ONE Devices row, light it online
// from the real known-peer/WebRTC path, and let Forget remove only that peer.
//
// Runs Chromium and WebKit iPad. No Rust build needed.
//
//   node frontend/tests/known-devices-dedupe.spec.cjs

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));
const { chromium, webkit, devices } = playwright;

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(ROOT, 'frontend', 'dist');
const PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const PORT = Number(process.env.KDD_PORT || 8291);
const BASE = `http://127.0.0.1:${PORT}`;
const KEY = 'filament-known-devices';

let backend = null;
function fail(msg) { console.error('[known-dedupe] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[known-dedupe] OK:', msg); }
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startBackend() {
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: {
      ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading',
      FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25',
      FIL_SECRET: 'known-dedupe-test-secret',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backend.stdout.on('data', () => {});
  backend.stderr.on('data', () => {});
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

async function waitFor(fn, timeoutMs, label) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await fn()) return true;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function nav(page) {
  await page.goto(`${BASE}/?test=1`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.waitForFunction(() => !!document.querySelector('[data-testid="device-name-input"]'), null, { timeout: 60000 });
  await page.locator('[data-testid="device-name-input"]').waitFor({ state: 'visible', timeout: 15000 });
}

async function identity(page) {
  return page.evaluate(() => ({
    name: document.querySelector('[data-testid="device-name-input"]')?.value || '',
    uid: sessionStorage.getItem('tunlion.uid') || '',
    gen: document.documentElement.getAttribute('data-session-generation') || '',
    online: /online/i.test(document.body.innerText),
  }));
}

function exactText(name) {
  return new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
}

function peerRows(page, name) {
  return page.locator('[data-testid="peer-tile"]', {
    has: page.locator('b', { hasText: exactText(name) }),
  });
}

function deviceRows(page, name) {
  return page.locator('[data-testid="device-row"]', {
    has: page.locator('b', { hasText: exactText(name) }),
  });
}

async function waitOnline(page, timeout = 30000) {
  await waitFor(async () => (await identity(page)).online, timeout, 'page online');
}

async function waitPeerReady(page, name, timeout = 60000) {
  await waitFor(async () => {
    const row = peerRows(page, name).first();
    if ((await row.count()) !== 1) return false;
    if (!/\bready\b/i.test(await row.innerText().catch(() => ''))) return false;
    // The real PeerLink map (?test=1), not a rendered-only claim.
    return page.evaluate((wanted) => {
      const links = window.__tunlionTestLinks;
      if (!links) return false;
      for (const link of links.values()) {
        if (link?.name === wanted && link?.channel?.readyState === 'open') return true;
      }
      return false;
    }, name);
  }, timeout, `peer ${name} ready with an OPEN data channel`);
}

async function seed(page, records) {
  await page.evaluate(({ key, records }) => {
    localStorage.setItem(key, JSON.stringify(records));
  }, { key: KEY, records });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => !!document.querySelector('[data-testid="device-name-input"]'), null, { timeout: 60000 });
}

async function runEngine(engine, browser, contextOptions) {
  const tag = `[${engine}]`;
  const peerCtx = await browser.newContext({ ...contextOptions, serviceWorkers: 'block' });
  const devCtx = await browser.newContext({ ...contextOptions, serviceWorkers: 'block' });
  const peer = await peerCtx.newPage();
  const dev = await devCtx.newPage();
  for (const [label, page] of [['peer', peer], ['dev', dev]]) {
    page.on('pageerror', (e) => console.log(tag, `[${label} page-error]`, String(e).slice(0, 300)));
    page.on('console', (m) => { if (m.type() === 'error') console.log(tag, `[${label} console]`, m.text().slice(0, 300)); });
  }

  await nav(peer);
  await nav(dev);
  await waitOnline(peer);
  await waitOnline(dev);
  const peerName = (await identity(peer)).name;
  const devName = (await identity(dev)).name;
  if (!peerName || !devName) fail(`${tag} both devices need names (peer=${peerName}, dev=${devName})`);

  // The pairing must be mutual: each side stores the other's local petname.
  // The dev side carries an OLD duplicate first, exactly the broken state.
  const oldSecret = 'a'.repeat(64);
  const newest = crypto.randomBytes(32).toString('hex');
  const spare = crypto.randomBytes(32).toString('hex');
  const spareName = 'spare-' + engine;
  await seed(peer, [{ name: devName, secret: newest, addedAt: 3000 }]);
  await seed(dev, [
    { name: peerName, secret: oldSecret, addedAt: 1000 },
    { name: peerName, secret: newest, addedAt: 2000 },
    { name: spareName, secret: spare, addedAt: 2500 },
  ]);

  const migrated = await dev.evaluate(({ key, name }) => {
    const all = JSON.parse(localStorage.getItem(key) || '[]');
    return { all, same: all.filter((d) => d.name === name) };
  }, { key: KEY, name: peerName });
  if (migrated.same.length !== 1) fail(`${tag} storage still has ${migrated.same.length} records for ${peerName}`);
  if (migrated.same[0].secret !== newest) fail(`${tag} storage kept the wrong (older) secret`);
  if (!migrated.all.some((d) => d.name === spareName)) fail(`${tag} migration dropped a distinct device`);
  ok(`${tag} load migrated duplicate "${peerName}" records to one, keeping the newest secret`);

  await waitOnline(peer);
  await waitOnline(dev);
  await waitPeerReady(peer, devName);
  await waitPeerReady(dev, peerName);
  ok(`${tag} real ready peer with an open data channel: ${peerName} <-> ${devName}`);

  await dev.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: /^Devices/ }).click();
  await waitFor(async () => {
    const n = await deviceRows(dev, peerName).count();
    if (n !== 1) return false;
    return /online/i.test(await deviceRows(dev, peerName).getAttribute('aria-label').catch(() => ''));
  }, 60000, `one online Devices row for ${peerName}`);
  if ((await deviceRows(dev, peerName).count()) !== 1) fail(`${tag} expected exactly one row, got ${await deviceRows(dev, peerName).count()}`);
  if ((await deviceRows(dev, spareName).count()) !== 1) fail(`${tag} distinct remembered device is missing`);
  ok(`${tag} seeded duplicates render ONE online row; the distinct device remains`);

  await deviceRows(dev, peerName).click();
  const dialog = dev.getByRole('dialog');
  await dialog.waitFor({ timeout: 5000 }).catch(() => fail(`${tag} device row did not open its sheet`));
  if (!(await dialog.innerText()).includes('Send files')) fail(`${tag} ready device sheet has no Send files action`);
  if ((await dialog.innerText()).includes("isn't reachable")) fail(`${tag} ready device sheet says it is unreachable`);
  if (!(await dialog.innerText()).includes('Forget device')) fail(`${tag} remembered device sheet has no Forget action`);
  const html = await dev.locator('body').innerHTML();
  if (html.includes(newest) || html.includes(oldSecret)) fail(`${tag} the secret leaked into the DOM`);
  ok(`${tag} online row opens a working sheet; no secret in the DOM`);

  await dialog.getByText('Forget device', { exact: true }).click();
  await waitFor(async () => (await deviceRows(dev, peerName).count()) === 0, 10000, 'the forgotten row to disappear');
  if ((await deviceRows(dev, spareName).count()) !== 1) fail(`${tag} Forget removed a different device`);
  const afterForget = await dev.evaluate(({ key, name }) => JSON.parse(localStorage.getItem(key) || '[]').filter((d) => d.name === name), { key: KEY, name: peerName });
  if (afterForget.length !== 0) fail(`${tag} Forget left ${afterForget.length} records for the peer`);
  ok(`${tag} Forget removed only that peer; the other remembered device remains`);

  await dev.close();
  await peer.close();
  await devCtx.close();
  await peerCtx.close();
}

const IPAD = devices['iPad (gen 7)'] || {
  viewport: { width: 810, height: 1080 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
  userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
};

async function runOne(engine) {
  if (engine === 'chromium') {
    const b = await chromium.launch({ headless: true });
    try { await runEngine('chromium', b, { viewport: { width: 1200, height: 900 } }); }
    finally { await b.close(); }
  } else {
    const b = await webkit.launch({ headless: true });
    try { await runEngine('webkit-ipad', b, { ...IPAD }); }
    finally { await b.close(); }
  }
}

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built — run `VITE_TUNLION_API= npm run build` in frontend/');

  if (process.env.KDD_CHILD) {
    await runOne(process.env.KDD_CHILD);
    console.log(`\n[known-dedupe] ${process.env.KDD_CHILD} PASSED`);
    process.exit(0);
  }

  startBackend();
  if (!await waitHealth(30000)) fail('backend did not come up at ' + BASE);

  const only = (process.env.KDD_ENGINES || 'chromium,webkit-ipad').split(',').map((s) => s.trim());
  for (const engine of only) {
    const r = spawnSync(process.execPath, [__filename], {
      env: { ...process.env, KDD_CHILD: engine, KDD_ENGINES: '' },
      stdio: 'inherit',
      timeout: 9 * 60 * 1000,
    });
    if (r.status !== 0) fail(`${engine} child exited with ${r.status === null ? `signal ${r.signal}` : `code ${r.status}`}`);
  }

  cleanup();
  console.log('\n[known-dedupe] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[known-dedupe] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
