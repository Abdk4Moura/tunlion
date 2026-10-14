// Browser UI gate: the new screens (one code box, rows, devices, phone shell).
// Drives a real Chromium against the REAL Tunlion component (focused render
// harness, as relay-honesty does) and, for the link fragment, the REAL built app
// served by the local backend (as pake-ux does). It FAILS when:
//   1. the code input has no label, or the box does not default to "Receive a
//      file", or Connect reaches the wrong hook action for the chosen mode;
//   2. a row shows a button for access this browser does not hold (Shell on a
//      device that is not remembered or offers no shell, any button on an
//      unreachable device, Send files on an unreachable device's sheet);
//   3. the drop zone or a row cannot be reached with Tab, or a focused control
//      shows no visible focus ring, or Enter on a row does nothing;
//   4. on a phone, the shell does not cover the whole screen (header and bottom
//      nav must be underneath it), its one-line bar does not expand, or a key in
//      its key bar is under 44 px tall;
//   5. a code in the link's #fragment is not put in the code box on load, or the
//      fragment is left in the address bar.
//
//   node frontend/tests/browser-ui.spec.cjs        (from the repo root)

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const { chromium } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(FRONT, 'dist');
const VENV_PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const HARNESS_PORT = 8252;
const BACK_PORT = 8253;
const BACK_URL = `http://127.0.0.1:${BACK_PORT}`;
const SHOT_DIR = path.join(__dirname, '.browser-ui-shots');

let harnessServer = null;
let backendProc = null;
function fail(msg) { console.error('[browser-ui] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[browser-ui] OK:', msg); }
function cleanup() {
  try { harnessServer && harnessServer.close(); } catch (e) {}
  try { backendProc && backendProc.kill('SIGKILL'); } catch (e) {}
}

function buildHarness() {
  const out = path.join(__dirname, '.browser-ui-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'browser-ui-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--loader:.css=text',
      '--define:import.meta.env={"VITE_TUNLION_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startHarnessServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  harnessServer = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else if (req.url.endsWith('.wasm')) { res.statusCode = 404; res.end(); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => harnessServer.listen(HARNESS_PORT, '127.0.0.1', resolve));
}

async function waitHealth(timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const up = await new Promise((res) => {
      const req = http.get(`${BACK_URL}/api/health`, (r) => { r.resume(); res(r.statusCode === 200); });
      req.on('error', () => res(false));
      req.setTimeout(1000, () => { req.destroy(); res(false); });
    });
    if (up) return true;
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

// The row (data-testid=peer-tile) whose visible name is `name`.
function row(page, name) {
  return page.locator('[data-testid="peer-tile"]', { has: page.locator('b', { hasText: new RegExp('^' + name + '$') }) }).first();
}

async function focusRing(page) {
  return page.evaluate(() => {
    const e = document.activeElement;
    const cs = getComputedStyle(e);
    return { tag: e.tagName, label: (e.getAttribute('aria-label') || e.innerText || '').slice(0, 40).replace(/\n/g, ' '), style: cs.outlineStyle, width: parseFloat(cs.outlineWidth) };
  });
}

(async () => {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const bundle = buildHarness();
  await startHarnessServer(bundle);
  ok('harness bundled + served');
  const browser = await chromium.launch({ headless: true });

  for (const theme of ['light', 'dark']) {
    // ---- desktop: code box, rows, keyboard, devices ------------------------
    const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
    page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));
    await page.goto(`http://127.0.0.1:${HARNESS_PORT}/?theme=${theme}`, { waitUntil: 'networkidle' });

    // 1. labelled code input; receive is the default; Connect follows the mode.
    const input = page.getByLabel('Enter a code', { exact: true });
    if ((await input.count()) !== 1) fail(`[${theme}] expected exactly one input labelled "Enter a code", got ${await input.count()}`);
    if ((await input.evaluate((e) => e.tagName)) !== 'INPUT') fail(`[${theme}] "Enter a code" label is not on an input`);
    const recv = page.getByRole('radio', { name: 'Receive a file' });
    const pair = page.getByRole('radio', { name: 'Remember a device' });
    if ((await recv.getAttribute('aria-checked')) !== 'true') fail(`[${theme}] "Receive a file" is not the default mode`);
    if ((await pair.getAttribute('aria-checked')) !== 'false') fail(`[${theme}] "Remember a device" should start unchecked`);
    await input.click();
    await page.keyboard.type('brave otter 3141');
    if ((await input.inputValue()) !== 'BRAVE-OTTER-3141') fail(`[${theme}] code box auto-dash gave "${await input.inputValue()}"`);
    await page.getByRole('button', { name: 'Connect' }).click();
    let calls = await page.evaluate(() => window.__calls.splice(0));
    if (!calls.some((c) => c.name === 'receiveWithCode' && c.args[0] === 'BRAVE-OTTER-3141') || calls.some((c) => c.name === 'pairWithCode'))
      fail(`[${theme}] default Connect should call receiveWithCode only; got ${JSON.stringify(calls)}`);
    ok(`[${theme}] one code box: labelled input, Receive first, Connect -> receiveWithCode`);
    await pair.click();
    if ((await pair.getAttribute('aria-checked')) !== 'true') fail(`[${theme}] "Remember a device" did not select`);
    await input.press('Enter');
    calls = await page.evaluate(() => window.__calls.splice(0));
    if (!calls.some((c) => c.name === 'pairWithCode' && c.args[0] === 'BRAVE-OTTER-3141') || calls.some((c) => c.name === 'receiveWithCode'))
      fail(`[${theme}] remember-mode Enter should call pairWithCode only; got ${JSON.stringify(calls)}`);
    ok(`[${theme}] Remember a device -> pairWithCode`);

    // 2. buttons only for access held.
    const btnNames = async (loc) => (await loc.getByRole('button').allInnerTexts()).map((t) => t.trim()).filter(Boolean);
    const vps = await btnNames(row(page, 'web-vps'));
    if (!vps.includes('Shell') || !vps.includes('Send files')) fail(`[${theme}] web-vps (remembered, offers shell) should show Shell + Send files; got ${vps}`);
    const laptop = await btnNames(row(page, 'laptop'));
    if (laptop.includes('Shell') || !laptop.includes('Send files')) fail(`[${theme}] laptop (no shell) should show Send files only; got ${laptop}`);
    const stranger = await btnNames(row(page, 'pixel'));
    if (stranger.includes('Shell') || !stranger.includes('Send files')) fail(`[${theme}] a stranger must never get a Shell button; got ${stranger}`);
    const off = await btnNames(row(page, 'nas'));
    if (off.length) fail(`[${theme}] an unreachable device must show no buttons; got ${off}`);
    ok(`[${theme}] rows show buttons only for access held`);

    // 3. keyboard: drop zone and rows are reachable, focus is visible, Enter acts.
    await input.focus();
    const seen = [];
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Tab');
      const f = await focusRing(page);
      if (f.tag === 'BODY') break; // walked off the end of the page
      seen.push(f);
      if (f.style !== 'solid' || f.width < 2) fail(`[${theme}] focused ${f.tag} "${f.label}" has no visible focus ring (${f.style} ${f.width}px)`);
    }
    const labels = seen.map((f) => f.label);
    if (!labels.some((l) => /^Drop a file to send/.test(l))) fail(`[${theme}] Tab never reached the drop zone: ${labels.join(' | ')}`);
    const dropTag = seen.find((f) => /^Drop a file to send/.test(f.label)).tag;
    if (dropTag !== 'BUTTON') fail(`[${theme}] the drop zone should be a button, is ${dropTag}`);
    if (!labels.some((l) => /^web-vps, ready/.test(l))) fail(`[${theme}] Tab never reached the web-vps row: ${labels.join(' | ')}`);
    ok(`[${theme}] Tab reaches the drop zone (a button) and the rows, every stop shows a 2 px ring`);
    await row(page, 'web-vps').focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog');
    await dialog.waitFor({ timeout: 5000 }).catch(() => fail(`[${theme}] Enter on a remembered row did not open its device sheet`));
    ok(`[${theme}] Enter on a remembered row opens its device sheet`);
    await page.keyboard.press('Escape');

    // Devices: an unreachable remembered device has no Shell, and its sheet
    // offers no Send files but says it is not reachable.
    await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: /^Devices/ }).click();
    const oldPhone = page.locator('[data-testid="device-row"]', { hasText: 'old-phone' });
    if ((await oldPhone.getByRole('button', { name: /shell/i }).count()) !== 0) fail(`[${theme}] offline old-phone shows a Shell button`);
    const vpsDev = page.locator('[data-testid="device-row"]', { hasText: 'web-vps' });
    if ((await vpsDev.getByRole('button', { name: /^open a shell on web-vps$/ }).count()) !== 1) fail(`[${theme}] online web-vps should show its Shell button on Devices`);
    await oldPhone.focus();
    await page.keyboard.press('Enter');
    await dialog.waitFor({ timeout: 5000 }).catch(() => fail(`[${theme}] Enter on a device row did not open its sheet`));
    if (await dialog.getByRole('button', { name: /Send files/ }).count()) fail(`[${theme}] an unreachable device's sheet offers Send files`);
    if (!(await dialog.innerText()).includes("isn't reachable")) fail(`[${theme}] an unreachable device's sheet does not say so`);
    ok(`[${theme}] Devices: buttons only for access held, offline sheet says so`);
    await page.screenshot({ path: path.join(SHOT_DIR, `devices-sheet-${theme}.png`) });
    await page.keyboard.press('Escape');
    await page.close();

    // ---- phone: full-bleed shell ------------------------------------------
    const ph = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
    ph.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));
    await ph.goto(`http://127.0.0.1:${HARNESS_PORT}/?theme=${theme}&phone=1`, { waitUntil: 'networkidle' });
    const nav = ph.getByRole('navigation', { name: 'Main' });
    if (!(await nav.count())) fail(`[${theme}] phone layout has no bottom navigation`);
    const navBox = await nav.boundingBox();
    const headBox = await ph.locator('header').boundingBox();
    await ph.screenshot({ path: path.join(SHOT_DIR, `phone-home-${theme}.png`) });
    await row(ph, 'web-vps').getByRole('button', { name: 'open a shell on web-vps' }).click();
    const overlay = ph.locator('[data-testid="terminal-overlay"]');
    await overlay.waitFor({ timeout: 5000 });
    await ph.waitForTimeout(400);
    const ob = await overlay.boundingBox();
    if (!ob || ob.x > 1 || ob.y > 1 || Math.abs(ob.width - 390) > 1 || Math.abs(ob.height - 844) > 1)
      fail(`[${theme}] phone shell is not full screen: ${JSON.stringify(ob)}`);
    const covered = await ph.evaluate(([h, n]) => {
      const inOverlay = (x, y) => !!document.elementFromPoint(x, y)?.closest('[data-testid="terminal-overlay"]');
      return { header: inOverlay(h.x + h.width / 2, h.y + h.height / 2), nav: inOverlay(n.x + n.width / 2, n.y + n.height / 2) };
    }, [headBox, navBox]);
    if (!covered.header || !covered.nav) fail(`[${theme}] the phone shell leaves the header or nav on top: ${JSON.stringify(covered)}`);
    const bar = overlay.getByRole('button', { expanded: false }).filter({ hasText: 'web-vps' });
    const barText = (await bar.innerText()).replace(/\s+/g, ' ');
    if (!/web-vps · remembered · /.test(barText)) fail(`[${theme}] shell bar should read "web-vps · remembered · <route>", got "${barText}"`);
    await bar.click();
    if (!(await overlay.getByRole('button', { expanded: true }).count())) fail(`[${theme}] shell bar did not expand`);
    if (!(await overlay.innerText()).includes('shell on web-vps')) fail(`[${theme}] expanded bar is missing the full line`);
    const keys = await overlay.locator('button[data-key]').evaluateAll((els) => els.map((e) => ({ k: e.dataset.key, h: e.getBoundingClientRect().height })));
    if (keys.length < 10) fail(`[${theme}] key bar has only ${keys.length} keys`);
    const smallKeys = keys.filter((k) => k.h < 44);
    if (smallKeys.length) fail(`[${theme}] key bar keys under 44 px: ${JSON.stringify(smallKeys)}`);
    for (const name of ['End', 'Hide']) {
      const b = await overlay.getByRole('button', { name: new RegExp('^' + name) }).first().boundingBox();
      if (!b || b.height < 44) fail(`[${theme}] shell "${name}" button under 44 px: ${JSON.stringify(b)}`);
    }
    ok(`[${theme}] phone shell covers the screen, bar expands, keys and buttons are 44 px`);
    await ph.screenshot({ path: path.join(SHOT_DIR, `phone-shell-${theme}.png`) });
    await ph.close();
  }

  // ---- 5. real built app: code from the #fragment on load -------------------
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built: run `VITE_TUNLION_API= npm run build` in frontend/');
  backendProc = spawn(VENV_PY, ['app.py'], {
    cwd: BACKEND,
    env: { ...process.env, PORT: String(BACK_PORT), FIL_ASYNC_MODE: 'eventlet', FIL_SELF_MONKEYPATCH: '1', FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backendProc.stdout.on('data', () => {});
  backendProc.stderr.on('data', () => {});
  if (!await waitHealth(30000)) fail('backend did not come up at ' + BACK_URL);
  const app = await browser.newPage();
  app.on('pageerror', (e) => console.log('[app-page-error]', String(e).slice(0, 300)));
  await app.goto(`${BACK_URL}/#brave-otter-3141`, { waitUntil: 'networkidle' });
  const box = app.getByLabel('Enter a code', { exact: true });
  await box.waitFor({ timeout: 30000 });
  const v = await box.inputValue();
  if (v !== 'BRAVE-OTTER-3141') fail(`code from #fragment not put in the box: got "${v}"`);
  const hash = await app.evaluate(() => window.location.hash);
  if (hash) fail(`the #fragment was left in the address bar: "${hash}"`);
  // Not a code: the fragment is left alone and the box stays empty.
  const app2 = await browser.newPage();
  await app2.goto(`${BACK_URL}/#about`, { waitUntil: 'networkidle' });
  const box2 = app2.getByLabel('Enter a code', { exact: true });
  await box2.waitFor({ timeout: 30000 });
  if ((await box2.inputValue()) !== '') fail('a non-code fragment was put in the code box');
  if ((await app2.evaluate(() => window.location.hash)) !== '#about') fail('a non-code fragment was removed');
  ok('real app: a code in the #fragment fills the box and the fragment is cleared; other fragments are left alone');

  await browser.close();
  cleanup();
  console.log('\n[browser-ui] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[browser-ui] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
