// Browser gate: a remembered device's identity is its pairing SECRET, never
// its name, against the REAL built app and the real Flask relay. Chromium and
// WebKit (iPad).
//
//   A = "Abdul's iPad"   already remembers a DIFFERENT, offline device that
//                        is also called "Kabir Laptop"
//   B = "Kabir Laptop"   pairs with A by code ("Remember a device")
//
// Checks, in order:
//   1. A's Remember banner suggests "Kabir Laptop 2", never the taken name.
//   2. A remembers first, B has not answered yet: A's row for B reads ONLINE
//      with the quiet "not remembered on their side" note (it used to read
//      offline: the live peer was matched by name and only via the channel).
//   3. A still holds BOTH "Kabir Laptop" secrets (the old one was deleted).
//   4. B remembers: the note clears, the row stays online.
//   5. On A, renaming "Kabir Laptop 2" onto "Kabir Laptop" is refused with a
//      clear message and storage is unchanged.
//   6. On A, renaming the old device away and then B's row to "Kabir Laptop"
//      works, and B's row stays online under the new name.
//   7. No secret ever reaches the DOM.
//
//   node frontend/tests/pair-identity.spec.cjs   (dist built same-origin)

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
const PORT = Number(process.env.PID_PORT || 8305);
const BASE = `http://127.0.0.1:${PORT}`;
const KEY = 'filament-known-devices';

let backend = null;
let backendLog = '';
function fail(msg) { console.error('[pair-identity] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[pair-identity] OK:', msg); }
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startBackend() {
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: {
      ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading',
      FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25',
      FIL_SECRET: 'pair-identity-test-secret',
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

async function waitFor(fn, timeoutMs, label) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await fn()) return true;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const exactText = (name) => new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
const row = (page, name) => page.locator('[data-testid="device-row"]', { has: page.locator('b', { hasText: exactText(name) }) });
const stored = (page) => page.evaluate((k) => JSON.parse(localStorage.getItem(k) || '[]'), KEY);
const gotoTab = (page, tab) => page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: new RegExp('^' + tab) }).click();
const rowState = async (page, name) => {
  const r = row(page, name);
  if ((await r.count()) !== 1) return null;
  return { label: await r.getAttribute('aria-label'), note: (await r.getByTestId('one-sided-note').count()) > 0 };
};

async function device(browser, ctxOpts, name, route, seedRecords) {
  const ctx = await browser.newContext({ ...ctxOpts, serviceWorkers: 'block' });
  await ctx.addInitScript(([n, key, recs]) => {
    try { if (!localStorage.getItem('tunlion.deviceName')) localStorage.setItem('tunlion.deviceName', n) } catch {}
    try { if (recs && !localStorage.getItem(key)) localStorage.setItem(key, JSON.stringify(recs)) } catch {}
  }, [name, KEY, seedRecords || null]);
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log(`[${name} page-error]`, String(e).slice(0, 300)));
  await page.goto(`${BASE}${route}`, { waitUntil: 'domcontentloaded' });
  return { ctx, page };
}

async function runEngine(engine, browser, ctxOpts) {
  const tag = `[${engine}]`;
  const narrow = (ctxOpts.viewport && ctxOpts.viewport.width < 720);
  const oldLaptop = crypto.randomBytes(32).toString('hex');
  const A = await device(browser, ctxOpts, "Abdul's iPad", '/', [{ name: 'Kabir Laptop', secret: oldLaptop, addedAt: 1000 }]);
  const B = await device(browser, ctxOpts, 'Kabir Laptop', '/rooms/pid-' + engine + '-' + Date.now());
  const codeInputSel = narrow ? '#tl-code-n' : '#tl-code-w';

  await A.page.getByTestId('create-code').click();
  const codeEl = A.page.getByTestId('room-code');
  await codeEl.waitFor({ timeout: 40000 });
  const code = (await codeEl.innerText()).trim();
  await B.page.getByRole('radio', { name: 'Remember a device' }).first().click();
  await B.page.locator(codeInputSel).fill(code);
  await B.page.getByTestId('code-connect').first().click();

  const banner = (p) => p.getByRole('region', { name: 'Remember this device?' }).first();
  await banner(A.page).waitFor({ timeout: 45000 });
  await banner(B.page).waitFor({ timeout: 45000 });
  const suggested = await banner(A.page).locator('input').inputValue();
  if (suggested !== 'Kabir Laptop 2') fail(`${tag} A's banner suggests ${JSON.stringify(suggested)} (a different device already has "Kabir Laptop")`);
  ok(`${tag} the new pairing suggests "Kabir Laptop 2", not the taken name`);

  // 2. One-sided: A remembers, B has not answered.
  await banner(A.page).getByRole('button', { name: 'Remember' }).click();
  await gotoTab(A.page, 'Devices');
  await waitFor(async () => {
    const s = await rowState(A.page, 'Kabir Laptop 2');
    return s && /, online$/.test(s.label) && s.note;
  }, 20000, 'A: "Kabir Laptop 2" online with the one-sided note').catch(async (e) => fail(`${tag} ${e.message}; got ${JSON.stringify(await rowState(A.page, 'Kabir Laptop 2'))}`));
  // and it STAYS online while B has not answered
  for (let i = 0; i < 12; i++) {
    const s = await rowState(A.page, 'Kabir Laptop 2');
    if (!s || !/, online$/.test(s.label)) fail(`${tag} one-sided row went offline: ${JSON.stringify(s)}`);
    await sleep(500);
  }
  const old = await rowState(A.page, 'Kabir Laptop');
  if (!old || !/, offline$/.test(old.label)) fail(`${tag} the other "Kabir Laptop" device row is missing or not offline: ${JSON.stringify(old)}`);
  ok(`${tag} one-sided: the row reads online with "not remembered on their side"; the other device is its own offline row`);

  // 3. Both secrets kept.
  const sA = await stored(A.page);
  if (!sA.some((d) => d.secret === oldLaptop && d.name === 'Kabir Laptop')) fail(`${tag} the old "Kabir Laptop" record was lost: ${JSON.stringify(sA.map((d) => d.name))}`);
  if (sA.length !== 2) fail(`${tag} A should hold 2 records, holds ${sA.length}`);
  ok(`${tag} A holds both devices' secrets`);

  // 4. B remembers: mutual, the note clears.
  await banner(B.page).getByRole('button', { name: 'Remember' }).click();
  await waitFor(async () => {
    const s = await rowState(A.page, 'Kabir Laptop 2');
    return s && /, online$/.test(s.label) && !s.note;
  }, 30000, 'A: note clears once B remembers').catch(async (e) => fail(`${tag} ${e.message}; got ${JSON.stringify(await rowState(A.page, 'Kabir Laptop 2'))}`));
  await gotoTab(B.page, 'Devices');
  await waitFor(async () => {
    const s = await rowState(B.page, "Abdul's iPad");
    return s && /, online$/.test(s.label) && !s.note;
  }, 30000, "B: Abdul's iPad online").catch((e) => fail(`${tag} ${e.message}`));
  ok(`${tag} once both remember, both rows are online and the note is gone`);

  // 5. Rename onto a taken name: refused.
  const renameTo = async (page, from, to) => {
    await row(page, from).click();
    const sheet = page.getByRole('dialog');
    await sheet.waitFor({ timeout: 5000 });
    await sheet.getByText('Rename', { exact: true }).click();
    const inp = page.getByLabel('device name', { exact: true });
    await inp.fill(to);
    await inp.press('Enter');
    await sleep(400);
    const refused = (await page.getByTestId('rename-error').count()) > 0 ? await page.getByTestId('rename-error').innerText() : null;
    if (refused) await inp.press('Escape');
    await page.keyboard.press('Escape');
    await waitFor(async () => (await page.getByRole('dialog').count()) === 0, 5000, 'sheet closed');
    return refused;
  };
  const before = JSON.stringify(await stored(A.page));
  const refused = await renameTo(A.page, 'Kabir Laptop 2', 'Kabir Laptop');
  if (!refused || !/already called "Kabir Laptop"/.test(refused)) fail(`${tag} rename onto a taken name was not refused clearly: ${JSON.stringify(refused)}`);
  if (JSON.stringify(await stored(A.page)) !== before) fail(`${tag} a refused rename changed storage`);
  ok(`${tag} rename onto a taken name refused: "${refused}"`);

  // 6. Free the name, then take it.
  if (await renameTo(A.page, 'Kabir Laptop', 'Old Laptop')) fail(`${tag} renaming the old device to a free name was refused`);
  if (await renameTo(A.page, 'Kabir Laptop 2', 'Kabir Laptop')) fail(`${tag} renaming onto the freed name was refused`);
  await waitFor(async () => {
    const s = await rowState(A.page, 'Kabir Laptop');
    return s && /, online$/.test(s.label);
  }, 15000, 'renamed row online').catch((e) => fail(`${tag} ${e.message}`));
  const oldRow = await rowState(A.page, 'Old Laptop');
  if (!oldRow || !/, offline$/.test(oldRow.label)) fail(`${tag} the old device row after rename: ${JSON.stringify(oldRow)}`);
  const sA2 = await stored(A.page);
  if (sA2.length !== 2 || !sA2.some((d) => d.secret === oldLaptop && d.name === 'Old Laptop')) fail(`${tag} storage after renames: ${JSON.stringify(sA2.map((d) => d.name))}`);
  ok(`${tag} renames by record: the live device is "Kabir Laptop" and online, the old one "Old Laptop" offline`);

  // 7. No secret in either DOM.
  for (const [p, l] of [[A.page, 'A'], [B.page, 'B']]) {
    const html = await p.locator('body').innerHTML();
    for (const d of await stored(p)) if (html.includes(d.secret)) fail(`${tag} ${l}: a secret leaked into the DOM`);
  }
  ok(`${tag} no secret in the DOM`);
  await A.ctx.close();
  await B.ctx.close();
}

const IPAD = devices['iPad (gen 7)'] || {
  viewport: { width: 810, height: 1080 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
  userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
};

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built: VITE_TUNLION_API= npm run build');
  if (process.env.PID_CHILD) {
    const engine = process.env.PID_CHILD;
    const b = engine === 'chromium' ? await chromium.launch({ headless: true }) : await webkit.launch({ headless: true });
    try { await runEngine(engine, b, engine === 'chromium' ? { viewport: { width: 1200, height: 900 } } : { ...IPAD }); }
    finally { await b.close(); }
    console.log(`[pair-identity] ${engine} PASSED`);
    process.exit(0);
  }
  startBackend();
  if (!(await waitHealth(30000))) fail('backend never healthy:\n' + backendLog.slice(-2000));
  for (const engine of (process.env.PID_ENGINES || 'chromium,webkit-ipad').split(',').map((s) => s.trim())) {
    const r = spawnSync(process.execPath, [__filename], { env: { ...process.env, PID_CHILD: engine }, stdio: 'inherit', timeout: 9 * 60 * 1000 });
    if (r.status !== 0) fail(`${engine} child exited with ${r.status === null ? `signal ${r.signal}` : `code ${r.status}`}`);
  }
  cleanup();
  console.log('[pair-identity] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => fail(String(e && e.stack || e)));
