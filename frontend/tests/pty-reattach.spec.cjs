// Browser shell reattach gate. Drives the REAL WebTerminal in Chromium against
// a fake device session that replays like the CLI acceptor (see the harness).
// It FAILS when:
//   1. the first pty-open carries resume_from (a fresh shell must look as before);
//   2. the shell bar does not say "reconnecting" while the link is down;
//   3. the reattach's resume_from is not exactly the bytes the terminal showed;
//   4. any line reaches the terminal twice, or a line produced while the link
//      was down never arrives;
//   5. the bar still says "reconnecting" once the shell is back;
//   6. an ICE drop on the live link (channel still open) is not shown, or the
//      recovered link is not reattached with the exact count.
//
//   node frontend/tests/pty-reattach.spec.cjs        (from the repo root)

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const { chromium } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const FRONT = path.resolve(__dirname, '..');
const PORT = 8256;
let server = null;
function fail(msg) { console.error('[pty-reattach] FAIL:', msg); try { server && server.close(); } catch (e) {} process.exit(1); }
function ok(msg) { console.log('[pty-reattach] OK:', msg); }

function build() {
  const out = path.join(__dirname, '.pty-reattach-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'pty-reattach-harness.jsx'), '--bundle', '--format=iife', `--outfile=${out}`,
      '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--loader:.css=text', '--define:import.meta.env={"VITE_TUNLION_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild failed: ' + (r.stderr || r.stdout));
  return fs.readFileSync(out);
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const bundle = build();
  const html = '<!doctype html><html><head><meta charset=utf-8></head><body style="margin:0"><div id="root" style="position:fixed;inset:0"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 900, height: 700 } });
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 300)));
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.__h && window.__h.opens().length === 1, null, { timeout: 10000 }).catch(() => fail('the terminal never opened a shell'));
  await wait(200);

  const opens0 = await page.evaluate(() => window.__h.opens());
  if (opens0[0].resumeFrom !== 'absent') fail(`the first open carried resume_from=${opens0[0].resumeFrom}`);
  ok('first open: no resume_from');

  for (let i = 0; i < 5; i++) await page.evaluate(() => window.__h.tick());
  await wait(200);
  const shownBefore = await page.evaluate(() => window.__delivered.length);

  // The link dies under the live shell; output keeps coming on the device.
  await page.evaluate(() => window.__h.dropChannel());
  await page.waitForFunction(() => /reconnecting/.test(window.__h.bar()), null, { timeout: 4000 })
    .catch(async () => fail(`the bar did not say reconnecting while the link was down: "${await page.evaluate(() => window.__h.bar())}"`));
  ok('link down: the bar says reconnecting');
  for (let i = 0; i < 3; i++) await page.evaluate(() => window.__h.tick());

  await page.evaluate(() => window.__h.newLink('B'));
  await page.waitForFunction(() => window.__h.opens().length === 2, null, { timeout: 5000 }).catch(() => fail('no reattach after the new link'));
  await wait(300);
  const opens = await page.evaluate(() => window.__h.opens());
  if (opens[1].session !== opens[0].session) fail('the reattach used a different session id');
  if (opens[1].resumeFrom !== shownBefore) fail(`resume_from=${opens[1].resumeFrom}, but the terminal had shown ${shownBefore} bytes`);
  ok(`reattach: same session, resume_from=${shownBefore} (exactly what was shown)`);

  for (let i = 0; i < 2; i++) await page.evaluate(() => window.__h.tick());
  await wait(200);
  const text = await page.evaluate(() => window.__h.delivered());
  const lines = (text.match(/LINE-\d+/g) || []).map((l) => +l.slice(5));
  const want = Array.from({ length: 10 }, (_, i) => i + 1);
  if (JSON.stringify(lines) !== JSON.stringify(want)) fail(`terminal got ${JSON.stringify(lines)}, want each of 1..10 once, in order`);
  ok('output intact across the drop: LINE-1..LINE-10, each once');

  // Same link, ICE blip: the bar must say reconnecting, then the terminal must
  // reattach over the recovered link with the exact count, losing nothing.
  const shownMid = await page.evaluate(() => window.__delivered.length);
  await page.evaluate(() => window.__h.pcDown());
  await page.waitForFunction(() => /reconnecting/.test(window.__h.bar()), null, { timeout: 4000 })
    .catch(() => fail('an ICE drop on the live link did not show reconnecting'));
  await page.evaluate(() => { window.__h.tick(); window.__h.tick() });
  await page.evaluate(() => window.__h.pcUp());
  await page.waitForFunction(() => window.__h.opens().length === 3, null, { timeout: 5000 })
    .catch(() => fail('no reattach after the same link recovered'));
  await wait(300);
  const o3 = (await page.evaluate(() => window.__h.opens()))[2];
  if (o3.resumeFrom !== shownMid) fail(`recovered-link reattach resume_from=${o3.resumeFrom}, shown ${shownMid}`);
  const lines2 = ((await page.evaluate(() => window.__h.delivered())).match(/LINE-\d+/g) || []).map((l) => +l.slice(5));
  if (JSON.stringify(lines2) !== JSON.stringify(Array.from({ length: 12 }, (_, i) => i + 1))) fail(`after the ICE blip the terminal got ${JSON.stringify(lines2)}`);
  ok(`same link recovered: reattached with resume_from=${shownMid}, LINE-1..LINE-12 each once`);

  const bar = await page.evaluate(() => window.__h.bar());
  if (/reconnecting/.test(bar)) fail(`the bar still says reconnecting after the reattach: "${bar}"`);
  if (!/direct/.test(bar)) fail(`the bar does not show the route again: "${bar}"`);
  ok(`shell back: the bar reads "${bar.replace(/\s+/g, ' ').trim()}"`);

  await browser.close();
  server.close();
  console.log('[pty-reattach] PASS');
})().catch((e) => fail(String(e && e.stack || e)));
