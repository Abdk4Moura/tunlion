// Peer identity gate: the local device name and the connected peer name are
// visible, a chosen name replaces the generated default on the SAME device,
// and a superseded tab explains itself without offering a reset/clear-data.
//
// Drives the REAL Tunlion component in Chromium and in WebKit with an iPad
// touch viewport/user-agent. WebKit is Safari's engine, not a physical iPad;
// the boundary is stated rather than papered over.
//
//   node frontend/tests/peer-identity.spec.cjs       (from the repo root)

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const Module = require('module');

const CLI_TESTS_NM = path.resolve(__dirname, '..', '..', 'cli', 'tests', 'node_modules');
if (fs.existsSync(CLI_TESTS_NM) && !Module.globalPaths.includes(CLI_TESTS_NM)) {
  Module.globalPaths.push(CLI_TESTS_NM);
  process.env.NODE_PATH = (process.env.NODE_PATH ? process.env.NODE_PATH + path.delimiter : '') + CLI_TESTS_NM;
  Module._initPaths();
}
const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));
const { chromium, webkit, devices } = playwright;

const FRONT = path.resolve(__dirname, '..');
const PORT = 8266;

let server = null;
function fail(msg) { console.error('[peer-identity] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[peer-identity] OK:', msg); }
function cleanup() { try { server && server.close(); } catch {} }

function buildHarness() {
  const out = path.join(__dirname, '.peer-identity-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'peer-identity-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--define:import.meta.env={"VITE_TUNLION_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));
}

async function run(browserName, browser, contextOptions) {
  const tag = `[${browserName}]`;
  const context = await browser.newContext(contextOptions);
  const page = await context.newPage();
  page.on('pageerror', (e) => console.log(tag, '[page-error]', String(e).slice(0, 300)));
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'networkidle' });

  // 1. Local device name and connected peer name are both explicit.
  const input = page.getByLabel("This device's name", { exact: true });
  if ((await input.count()) !== 1) fail(`${tag} expected exactly one device-name field, got ${await input.count()}`);
  if ((await input.inputValue()) !== 'silken-chickadee') fail(`${tag} generated/stored local name not shown: "${await input.inputValue()}"`);
  const connected = page.locator('[data-testid="connected-peer-name"]');
  if (!(await connected.isVisible())) fail(`${tag} connected peer name is not visible`);
  if (!/leafy-bronco/.test(await connected.innerText())) fail(`${tag} connected peer name did not say leafy-bronco: ${await connected.innerText()}`);
  const tile = page.locator('[data-testid="peer-tile"]', { has: page.locator('b', { hasText: /^leafy-bronco$/ }) }).first();
  if (!(await tile.isVisible())) fail(`${tag} the connected peer has no named row`);
  ok(`${tag} local name "silken-chickadee" and connected peer "leafy-bronco" are visible`);

  // 2. A chosen name replaces the default and reaches the hook callback.
  await input.fill('studio-ipad');
  await input.press('Enter');
  await page.waitForTimeout(100);
  let renames = await page.evaluate(() => window.__renames.splice(0));
  if (!renames.includes('studio-ipad')) fail(`${tag} chosen name did not reach the rename callback: ${JSON.stringify(renames)}`);
  if ((await input.inputValue()) !== 'studio-ipad') fail(`${tag} chosen name did not stay in the field: "${await input.inputValue()}"`);
  ok(`${tag} a chosen name replaces the generated default on the same device`);

  // 3. Blank is not allowed to erase the identity; the current name stays.
  await input.fill('');
  await input.press('Enter');
  await page.waitForTimeout(100);
  renames = await page.evaluate(() => window.__renames.splice(0));
  const afterBlank = await input.inputValue();
  if (!afterBlank) fail(`${tag} a blank commit left the device with no name`);
  if (!renames.includes('studio-ipad')) fail(`${tag} blank commit did not fall back to the current name: ${JSON.stringify(renames)}`);
  ok(`${tag} a blank name falls back to the current identity (${afterBlank})`);

  // 4. "Random" gives a generated, visible default.
  await page.getByRole('button', { name: 'Use a random device name' }).click();
  await page.waitForTimeout(100);
  const random = await input.inputValue();
  if (!/^[a-z]+-[a-z]+$/.test(random)) fail(`${tag} Random produced a non-generated name: "${random}"`);
  ok(`${tag} Random produces a generated name (${random})`);

  // 5. A superseded tab explains the takeover and offers reload only. It must
  //    never send people to reset/clear site data (that forgets the pairing).
  const body = (await page.locator('body').innerText()).toLowerCase();
  if (/clear (site )?data|reset (the )?browser|delete site data/.test(body)) fail(`${tag} UI offers a clear-data/reset path`);
  await page.close();

  const supersededPage = await context.newPage();
  await supersededPage.goto(`http://127.0.0.1:${PORT}/?superseded=1`, { waitUntil: 'networkidle' });
  const banner = supersededPage.locator('[data-testid="superseded-banner"]');
  if (!(await banner.isVisible())) fail(`${tag} superseded state has no explanation`);
  const bannerText = await banner.innerText();
  if (!/reload this tab/i.test(bannerText)) fail(`${tag} superseded state has no reload action: ${bannerText}`);
  if (/clear (site )?data|reset/i.test(bannerText)) fail(`${tag} superseded state offers a reset: ${bannerText}`);
  await supersededPage.getByRole('button', { name: 'Reload this tab' }).click();
  if ((await supersededPage.evaluate(() => window.__reloads)) !== 1) fail(`${tag} Reload this tab did not invoke the reload action`);
  ok(`${tag} a superseded tab explains the takeover, offers reload, and never offers reset/clear-data`);
  await context.close();
}

(async () => {
  const bundle = buildHarness();
  await startServer(bundle);
  ok('harness bundled + served');

  // Chromium: the desktop/Android engine.
  const chromiumBrowser = await chromium.launch({ headless: true });
  await run('chromium', chromiumBrowser, { viewport: { width: 1200, height: 900 } });
  await chromiumBrowser.close();

  // WebKit with an iPad touch viewport/user-agent: Safari's engine. This is a
  // rendering/interaction proxy, not a claim about a physical iPad.
  const ipad = devices['iPad (gen 7)'] || {
    viewport: { width: 810, height: 1080 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
    userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  };
  const webkitBrowser = await webkit.launch({ headless: true });
  await run('webkit-ipad', webkitBrowser, { ...ipad });
  await webkitBrowser.close();

  cleanup();
  console.log('\n[peer-identity] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[peer-identity] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
