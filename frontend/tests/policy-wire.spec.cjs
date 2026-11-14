// Browser gate: the browser's auto-accept decision is the SHARED core.
//
// It drives the real built app (frontend/dist, same-origin) and its ?test=1
// policy surface, so the code under test is the committed wasm plus the real
// adapter, not a copy in this spec:
//   1. replays every shared vector from
//      crates/tunlion-policy-wasm/testdata/transfer_vectors.json through the
//      actual wasm admitTransfer;
//   2. an anonymous code transfer is allowed only when the core allows it (a
//      core revocation and the core's own consent check still win);
//   3. a stored cap with an unresolved identity is blocked;
//   4. no facts, and no explicit now, never auto-accept.
//
// If frontend/src/policy has not been committed yet, this gate FAILS with the
// workflow to run. It never skips: a missing decision core must not look like
// a passing gate.
//
//   VITE_TUNLION_API= npm run build   (in frontend/)
//   node frontend/tests/policy-wire.spec.cjs

const { spawn } = require('child_process');
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const { chromium } = require(require.resolve('playwright', {
  paths: [path.join(__dirname, '..')],
}));

const ROOT = path.resolve(__dirname, '..', '..');
const FRONT = path.join(ROOT, 'frontend');
const DIST = path.join(FRONT, 'dist');
const VENV_PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python'))
    ? path.join(ROOT, '.venv', 'bin', 'python')
    : 'python3');
const BACK_PORT = 8264;
const BACK_URL = `http://127.0.0.1:${BACK_PORT}`;
const VECTORS = path.join(ROOT, 'crates', 'tunlion-policy-wasm', 'testdata', 'transfer_vectors.json');

let backendProc = null;

function fail(msg) { console.error('[policy-wire] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[policy-wire] OK:', msg); }
function cleanup() { try { backendProc && backendProc.kill('SIGKILL'); } catch (e) {} }

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

function startBackend() {
  backendProc = spawn(VENV_PY, ['app.py'], {
    cwd: path.join(ROOT, 'backend'),
    env: {
      ...process.env,
      PORT: String(BACK_PORT),
      FIL_ASYNC_MODE: 'eventlet',
      FIL_SELF_MONKEYPATCH: '1',
      FIL_CLAIM_LIMIT: '1000000',
      FIL_PING_TIMEOUT: '120',
      FIL_PING_INTERVAL: '25',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  backendProc.stdout.on('data', () => {});
  backendProc.stderr.on('data', () => {});
}

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) {
    fail('frontend/dist not built; run `VITE_TUNLION_API= npm run build` in frontend/');
  }
  // A prod-pointing dist makes every Playwright nav time out.
  for (const f of fs.readdirSync(path.join(DIST, 'assets')).filter((x) => x.endsWith('.js'))) {
    if (fs.readFileSync(path.join(DIST, 'assets', f), 'utf8').includes('api.tunlion.autumated.com')) {
      fail('dist is prod-pointing; rebuild SAME-ORIGIN: `VITE_TUNLION_API= npm run build`');
    }
  }
  ok('dist present and same-origin');

  startBackend();
  if (!await waitHealth(30000)) fail('backend did not come up at ' + BACK_URL);
  ok('backend up');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 400)));
  await page.goto(`${BACK_URL}/rooms/policy-${Date.now()}?test=1`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => !!window.__tunlionTestPolicy, null, { timeout: 30000 });
  ok('real app exposed the policy surface');

  const callAdmit = (input) => page.evaluate(async (json) => {
    try { return { ok: true, value: await window.__tunlionTestPolicy.admit(json) }; }
    catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
  }, input);
  const decide = (facts) => page.evaluate((f) => window.__tunlionTestPolicy.decide(f), facts);
  const autoAccept = (facts) => page.evaluate((f) => window.__tunlionTestPolicy.autoAccept(f), facts);

  // ---- 1. the shared vectors, through the committed wasm ---------------------
  const vectors = JSON.parse(fs.readFileSync(VECTORS, 'utf8'));
  for (const c of vectors.cases) {
    const got = await callAdmit(JSON.stringify(c.input));
    if (!got.ok) {
      fail(`shared vector '${c.name}' could not reach the policy core: ${got.error}. `
        + 'Run the Browser policy wasm workflow and commit its artifact under frontend/src/policy/ '
        + '(see frontend/src/policy/README.md).');
    }
    try {
      assert.deepStrictEqual(got.value, c.expected);
    } catch (e) {
      fail(`shared vector '${c.name}' differed: ${e.message}`);
    }
  }
  ok(`replayed ${vectors.cases.length} shared vectors through the committed wasm`);

  // ---- 2. the two browser consent paths: the core decides --------------------
  const codeOffer = { direction: 'receive', status: 'offered', byCode: true, consent: true, now: 1000 };
  const allowed = await decide(codeOffer);
  if (!allowed || allowed.allowed !== true) fail(`anonymous code transfer was not allowed by the core: ${JSON.stringify(allowed)}`);
  ok('anonymous code transfer: consented, in-bounds offer allowed by the core');

  const revoked = await decide({ ...codeOffer, revoked: true });
  if (!revoked || revoked.allowed !== false || !revoked.deny || revoked.deny.kind !== 'revoked') {
    fail(`a revoked anonymous code transfer was not denied by the core: ${JSON.stringify(revoked)}`);
  }
  ok('anonymous code transfer: a core revocation still wins');

  const noConsent = await decide({ ...codeOffer, consent: false });
  if (!noConsent || noConsent.allowed !== false || !noConsent.deny || noConsent.deny.kind !== 'anonymousNoConsent') {
    fail(`a code transfer without consent was not denied by the core: ${JSON.stringify(noConsent)}`);
  }
  ok("anonymous code transfer: the core's own consent check is load-bearing");

  // The other consent path the old boolean covered: a remembered device that
  // proved its secret on this link. The shared core must still allow it.
  const provenOffer = {
    direction: 'receive', status: 'offered',
    relationship: 'remembered', caps: ['transfer'], proven: true,
    consent: true, now: 1000,
  };
  const proven = await decide(provenOffer);
  if (!proven || proven.allowed !== true) fail(`a proven remembered device was not allowed by the core: ${JSON.stringify(proven)}`);
  ok('remembered device that proved its secret: allowed by the core');

  // ---- 3. a stored cap with an unresolved identity is blocked ----------------
  const storedCap = {
    direction: 'receive', status: 'offered',
    relationship: 'remembered', caps: ['transfer'], proven: false,
    consent: true, now: 1000,
  };
  const held = await decide(storedCap);
  if (!held || held.allowed !== false) fail(`stored cap with an unresolved identity was allowed: ${JSON.stringify(held)}`);
  if (!held.deny || held.deny.kind !== 'shadowLegacy') fail(`stored cap block had the wrong deny: ${JSON.stringify(held)}`);
  ok('stored cap but unresolved identity: blocked by the core');

  // The cap is a real core input, not a label: a stored record that does not
  // include "transfer" must be denied by the core's ceiling check even though
  // the human remembered it.
  const heldNoTransfer = await decide({ ...storedCap, caps: ['mount'] });
  if (!heldNoTransfer || heldNoTransfer.allowed !== false || !heldNoTransfer.deny || heldNoTransfer.deny.kind !== 'ceiling') {
    fail(`a stored record without the transfer cap was not denied by the ceiling: ${JSON.stringify(heldNoTransfer)}`);
  }
  ok('stored record without the transfer cap: denied by the core ceiling');

  // ---- 4. no facts and no now never auto-accept -----------------------------
  const nothing = await decide({ now: 1000 });
  if (!nothing || nothing.allowed !== false) fail(`no facts were allowed: ${JSON.stringify(nothing)}`);
  ok('no facts: denied by the core');

  const noNow = await decide({ direction: 'receive', status: 'offered', byCode: true, consent: true });
  if (!noNow || noNow.allowed !== false || !noNow.deny || noNow.deny.kind !== 'unsupported') {
    fail(`a decision without an explicit now was not unsupported: ${JSON.stringify(noNow)}`);
  }
  ok('no explicit now: unsupported, not allowed');

  // ---- 5. shouldAutoAccept follows the core and only applies to offers ------
  if (!await autoAccept(codeOffer)) fail('shouldAutoAccept did not accept the core-allowed code offer');
  if (!await autoAccept(provenOffer)) fail('shouldAutoAccept did not accept the core-allowed remembered device');
  if (await autoAccept({ ...codeOffer, revoked: true })) fail('shouldAutoAccept overrode a core denial');
  if (await autoAccept(storedCap)) fail('shouldAutoAccept accepted a stored cap without identity');
  if (await autoAccept({ ...codeOffer, direction: 'send' })) fail('shouldAutoAccept accepted our own send');
  if (await autoAccept({ ...codeOffer, status: 'transferring' })) fail('shouldAutoAccept accepted a running transfer');
  ok('shouldAutoAccept follows the core and only applies to incoming offers');

  await browser.close();
  cleanup();
  console.log('\n[policy-wire] PASS');
  process.exit(0);
})().catch((e) => { console.error('[policy-wire] ERROR:', (e && e.stack) || String(e)); cleanup(); process.exit(1); });
