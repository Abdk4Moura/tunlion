// Browser gate: pairing two browsers that are ALREADY in the same room (the
// same network, the common home case) must never abort.
//
// The defect this pins: the claimer's pair-matched handler left and re-joined
// the room it was already in, and the creator's peer-left handler failed the
// running ceremony 2 ms later (relay: web:pake-failed why=peer-left), in 3 of
// 4 runs. Either half of the fix alone is enough: the claimer skips a no-op
// rejoin, and the creator tolerates a prompt rejoin of the same peer.
//
// Each run: fresh contexts A and B at "/" (one auto room, one IP), A creates a
// code, B enters it in "Remember a device" mode right away. Two entry paths:
//   typed     B types the code into the box
//   fragment  B opens /#CODE (a shared code link) and connects
// A run passes only when BOTH sides reach the Remember banner and neither
// side ever showed a pairing failure. Any failure fails the gate.
//
//   PSR_RUNS=10 PSR_ENGINES=chromium,webkit node frontend/tests/pair-same-room.spec.cjs

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));
const { chromium, webkit } = playwright;

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(ROOT, 'frontend', 'dist');
const PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const PORT = Number(process.env.PSR_PORT || 8303);
const BASE = `http://127.0.0.1:${PORT}`;
const RUNS = Number(process.env.PSR_RUNS || 10);

let backend = null;
let backendLog = '';
function fail(msg) { console.error('[same-room] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[same-room] OK:', msg); }
function note(msg) { console.log('[same-room]', msg); }
function cleanup() { try { backend && backend.kill('SIGKILL'); } catch {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startBackend() {
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: {
      ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading',
      FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25',
      FIL_SECRET: 'same-room-test-secret',
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

async function device(browser, name) {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 }, serviceWorkers: 'block' });
  await ctx.addInitScript((n) => {
    try { if (!localStorage.getItem('tunlion.deviceName')) localStorage.setItem('tunlion.deviceName', n) } catch {}
    try { localStorage.setItem('tunlionLog', 'debug') } catch {}
  }, name);
  const page = await ctx.newPage();
  const logs = [];
  page.on('console', (m) => logs.push(`${Date.now()} ${m.type()} ${m.text()}`));
  return { ctx, page, logs, name };
}

// A pairing failure this side showed (the CodeBox alert or the status line).
async function pairError(page) {
  return page.evaluate(() => {
    const e = document.querySelector('[data-testid="pair-error"]');
    if (e && e.textContent.trim()) return e.textContent.trim();
    const t = document.body.innerText;
    const m = /(the other device ended the pairing[^\n]*|pairing refused[^\n]*|the other device did not finish pairing[^\n]*)/.exec(t);
    return m ? m[1] : null;
  });
}

async function oneRun(browser, engine, mode, i) {
  const A = await device(browser, "Abdul's iPad");
  const B = await device(browser, 'Kabir Laptop');
  const tag = `[${engine} ${mode} #${i}]`;
  try {
    await A.page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
    // In typed mode B is already in the room when the code exists (the
    // person has the page open). In fragment mode B opens the link fresh.
    if (mode === 'typed') await B.page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' });
    await A.page.getByTestId('create-code').click();
    const codeEl = A.page.getByTestId('room-code');
    await codeEl.waitFor({ timeout: 40000 });
    const code = (await codeEl.innerText()).trim();
    if (mode === 'typed') {
      // Wait until B sees A in the room: the same-room precondition.
      await B.page.locator('[data-testid="peer-tile"]').first().waitFor({ timeout: 30000 });
      await B.page.getByRole('radio', { name: 'Remember a device' }).first().click();
      await B.page.locator('#tl-code-w').fill(code);
    } else {
      await B.page.goto(`${BASE}/#${code.toLowerCase()}`, { waitUntil: 'domcontentloaded' });
      await B.page.getByRole('radio', { name: 'Remember a device' }).first().click();
      const v = await B.page.locator('#tl-code-w').inputValue();
      if (v.toUpperCase() !== code.toUpperCase()) throw new Error(`fragment did not prefill the code (box: ${JSON.stringify(v)})`);
    }
    await B.page.getByTestId('code-connect').first().click();

    const t0 = Date.now();
    const got = { A: false, B: false };
    while (Date.now() - t0 < 45000) {
      for (const d of [['A', A], ['B', B]]) {
        const err = await pairError(d[1].page);
        if (err) throw new Error(`${d[0]} showed a pairing failure: ${err}`);
        if (!got[d[0]] && (await d[1].page.getByRole('region', { name: 'Remember this device?' }).count()) > 0) got[d[0]] = true;
      }
      if (got.A && got.B) break;
      await sleep(150);
    }
    if (!got.A || !got.B) throw new Error(`no Remember banner within 45 s (A=${got.A} B=${got.B})`);
    // Hold a moment: a late peer-left must not turn a success into a failure.
    await sleep(1500);
    for (const d of [['A', A], ['B', B]]) {
      const err = await pairError(d[1].page);
      if (err) throw new Error(`${d[0]} showed a pairing failure after pairing: ${err}`);
    }
    note(`${tag} paired in ${Date.now() - t0} ms`);
    return null;
  } catch (e) {
    const tail = (d) => d.logs.filter((x) => /pake|pair|peer-left|rejoin|leave/i.test(x)).slice(-25).join('\n');
    return `${tag} ${e.message}\nA:\n${tail(A)}\nB:\n${tail(B)}`;
  } finally {
    await A.ctx.close().catch(() => {});
    await B.ctx.close().catch(() => {});
  }
}

async function runEngine(engine) {
  const browser = engine === 'webkit' ? await webkit.launch({ headless: true }) : await chromium.launch({ headless: true });
  const failures = [];
  try {
    for (const mode of (process.env.PSR_MODES || 'typed,fragment').split(',')) {
      for (let i = 1; i <= RUNS; i++) {
        const f = await oneRun(browser, engine, mode, i);
        if (f) { console.log('[same-room] RUN FAILED:', f); failures.push(f.split('\n')[0]); }
      }
    }
  } finally {
    await browser.close();
  }
  return failures;
}

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built: VITE_TUNLION_API= npm run build');
  if (process.env.PSR_CHILD) {
    const failures = await runEngine(process.env.PSR_CHILD);
    if (failures.length) { console.error(`[same-room] ${process.env.PSR_CHILD}: ${failures.length} failed run(s):\n` + failures.join('\n')); process.exit(1); }
    console.log(`[same-room] ${process.env.PSR_CHILD} PASSED`);
    process.exit(0);
  }
  startBackend();
  if (!(await waitHealth(30000))) fail('backend never healthy:\n' + backendLog.slice(-2000));
  ok('relay up');
  let bad = 0;
  for (const engine of (process.env.PSR_ENGINES || 'chromium,webkit').split(',').map((s) => s.trim())) {
    const r = spawnSync(process.execPath, [__filename], { env: { ...process.env, PSR_CHILD: engine }, stdio: 'inherit', timeout: 30 * 60 * 1000 });
    if (r.status !== 0) bad++;
  }
  const relayFails = backendLog.split('\n').filter((l) => /pake-failed/.test(l));
  if (relayFails.length) console.log('[same-room] relay saw:\n' + relayFails.slice(-20).join('\n'));
  if (bad) fail(`${bad} engine(s) had failed runs`);
  if (relayFails.length) fail(`relay logged ${relayFails.length} pake-failed event(s)`);
  cleanup();
  ok(`ALL RUNS PASSED (${RUNS} per mode, per engine)`);
  process.exit(0);
})().catch((e) => fail(String(e && e.stack || e)));
