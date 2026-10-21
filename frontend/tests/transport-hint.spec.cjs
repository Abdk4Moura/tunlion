// Browser gate: the web client's transport hint is the FIRST signal and is
// emitted synchronously, before any SDP.
//
// Why this is load-bearing: a direct-first CLI arms a QUIC attempt and refuses
// to build the WebRTC responder until that attempt's budget expires. A browser
// can never answer the QUIC transport-offer, so without this hint every web
// shell connection spends the direct budget on "connecting" for nothing. The
// Rust side has a deterministic unit test for the budget cancel; this test
// pins the wire half (browser actually sends the hint, first, immediately).
//
//   node frontend/tests/transport-hint.spec.cjs

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PW = require.resolve('playwright', {
  paths: [path.join(__dirname, '..')],
});
const { chromium } = require(PW);

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const HARNESS_PORT = 8245;

let server = null;
function fail(msg) { console.error('[hint] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[hint] OK:', msg); }
function cleanup() { try { server && server.close(); } catch (e) {} }

function buildHarness() {
  const out = path.join(__dirname, '.transport-hint-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'transport-hint-harness.jsx'), '--bundle', '--format=iife',
      `--outfile=${out}`, '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--define:import.meta.env={"VITE_FILAMENT_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild harness bundle failed: ' + (r.stderr || r.stdout));
  return out;
}

function startServer(bundlePath) {
  const bundle = fs.readFileSync(bundlePath);
  const html = '<!doctype html><html><head><meta charset=utf-8></head><body><div id="root"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  return new Promise((resolve) => server.listen(HARNESS_PORT, '127.0.0.1', resolve));
}

(async () => {
  const bundle = buildHarness();
  await startServer(bundle);
  ok('harness bundled + served');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 400)));
  await page.goto(`http://127.0.0.1:${HARNESS_PORT}/`, { waitUntil: 'load' });
  await page.waitForFunction(() => !!window.__HINT, null, { timeout: 15000 });
  const out = await page.evaluate(() => window.__HINT);
  await page.waitForFunction(() => !!window.__READY, null, { timeout: 1000 }).catch(() => {});
  const ready = await page.evaluate(() => window.__READY);
  await browser.close();
  cleanup();

  if (!out || !Array.isArray(out.sent) || out.sent.length === 0) fail('PeerLink emitted no signals');
  const first = out.first || {};
  if (first.type !== 'transport-hint') fail(`first signal was ${JSON.stringify(first.type)}, expected transport-hint`);
  if (first.direct !== false) fail(`transport hint did not say direct:false (got ${JSON.stringify(first.direct)})`);
  if (first.uid !== 'browser-uid') fail(`transport hint uid was ${JSON.stringify(first.uid)}`);
  // PeerLink.name is the REMOTE peer; it must never travel as our name, and an
  // unauthenticated hint must not be able to set a display name.
  if ('name' in first) fail(`transport hint carried a name (${JSON.stringify(first.name)})`);
  if (out.firstDescription !== -1 && out.sent.findIndex((x) => x.data && x.data.type === 'transport-hint') > out.firstDescription)
    fail('a description was emitted before the transport hint');
  if (!(out.sent[0].at < 50)) fail(`transport hint took ${out.sent[0].at}ms; it must be synchronous`);
  if (!(out.elapsed < 100)) fail(`PeerLink construction took ${out.elapsed}ms before emitting the hint`);
  ok(`first signal is transport-hint{direct:false} at ${out.sent[0].at.toFixed(1)}ms`);
  ok('no SDP precedes the hint');

  // Real WebRTC: a CLI that honors the hint must reach ready without waiting
  // the modelled fixed budget. The control (hint ignored) must pay it, which
  // also proves the measurement is sensitive rather than trivially fast.
  if (!ready) fail('ready-time harness returned nothing');
  if (ready.fast.error) fail(`hint-honoring link never became ready: ${ready.fast.error}`);
  if (ready.slow.error) fail(`control link never became ready: ${ready.slow.error}`);
  if (!(ready.fast.readyMs < 2000))
    fail(`hint-honoring connecting->ready took ${ready.fast.readyMs.toFixed(0)}ms; it waited for the fixed budget`);
  if (!(ready.slow.readyMs >= 2800))
    fail(`control connecting->ready was ${ready.slow.readyMs.toFixed(0)}ms; the budget model did not run`);
  ok(`connecting->ready with hint ${ready.fast.readyMs.toFixed(0)}ms (control ${ready.slow.readyMs.toFixed(0)}ms)`);

  console.log('\n[hint] PASS');
  process.exit(0);
})().catch((e) => { console.error('[hint] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
