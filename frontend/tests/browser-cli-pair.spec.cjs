// Browser <-> CLI pairing with human names, against the REAL built app, the
// real Flask relay and a real `tunlion` binary (TUNLION_BIN), driven in a pty.
//
//   CLI  : `tunlion add` (interactive, "Another device I own"), then `tunlion up`
//   tab  : "Abdul's iPad" enters the code with Remember a device, chooses Remember
//
// Then it watches the tab's Devices row for the CLI device and the CLI's
// `devices` view, and reports every offline sample after first online.
//
//   TUNLION_BIN=... node frontend/tests/browser-cli-pair.spec.cjs

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const playwright = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));
const { chromium } = playwright;

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const PY = process.env.TUNLION_TEST_VENV || 'python3';
const BIN = process.env.TUNLION_BIN || 'tunlion';
const PORT = Number(process.env.BCP_PORT || 8296);
const BASE = `http://127.0.0.1:${PORT}`;
const WATCH_MS = Number(process.env.BCP_WATCH_MS || 60000);
const MENU_KEY = process.env.BCP_MENU_KEY || '1';
const W = fs.mkdtempSync(path.join(os.tmpdir(), 'bcp-'));
const CLI_ENV = { ...process.env, HOME: path.join(W, 'home'), TUNLION_CONFIG_DIR: path.join(W, 'cfg'), PTY_MENU_KEY: MENU_KEY };
fs.mkdirSync(CLI_ENV.HOME, { recursive: true });

const procs = [];
let backendLog = '';
function note(m) { console.log('[cli-pair]', m); }
function cleanup() { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } }
function fail(m) { console.error('[cli-pair] FAIL:', m); dump(); cleanup(); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readOr = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
function dump() {
  note('add.log:\n' + readOr(path.join(W, 'add.log')).replace(/\r/g, '\n').replace(/\n\s*\n+/g, '\n').slice(-3000));
  note('up.log tail:\n' + readOr(path.join(W, 'up.log')).split('\n').slice(-60).join('\n'));
}
function cli(args, extra = {}) {
  const r = spawnSync(BIN, args, { env: { ...CLI_ENV, ...extra }, encoding: 'utf8', timeout: 25000 });
  return (r.stdout || '') + (r.stderr || '');
}

async function waitHealth(ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const up = await new Promise((res) => {
      const q = http.get(`${BASE}/api/health`, (r) => { r.resume(); res(r.statusCode === 200); });
      q.on('error', () => res(false));
      q.setTimeout(1000, () => { q.destroy(); res(false); });
    });
    if (up) return true;
    await sleep(300);
  }
  return false;
}

async function rows(page) {
  return page.evaluate(() => ({
    rows: [...document.querySelectorAll('[data-testid="device-row"]')].map((r) => r.getAttribute('aria-label')),
    tiles: [...document.querySelectorAll('[data-testid="peer-tile"]')].map((t) => t.getAttribute('aria-label')),
    known: (() => { try { return JSON.parse(localStorage.getItem('filament-known-devices') || '[]').map((d) => d.name) } catch { return [] } })(),
  }));
}

(async () => {
  const be = spawn(PY, ['app.py'], { cwd: BACKEND, env: { ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading', FIL_CLAIM_LIMIT: '1000000', FIL_SECRET: 'bcp', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25' }, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(be);
  be.stdout.on('data', (d) => { backendLog += d; });
  be.stderr.on('data', (d) => { backendLog += d; });
  if (!(await waitHealth(20000))) fail('relay never healthy\n' + backendLog.slice(-1500));
  note('relay up; ' + cli(['--version']).trim());

  const add = spawn(PY, [path.join(__dirname, 'ptydrive.py'), path.join(W, 'add.log'), path.join(W, 'code'), '--', BIN, 'add', '--server', BASE], { env: CLI_ENV, stdio: 'ignore' });
  procs.push(add);
  let addExit = null;
  add.on('exit', (c) => { addExit = c; });
  let code = '';
  for (let i = 0; i < 100 && !code; i++) { code = readOr(path.join(W, 'code')).trim(); await sleep(200); }
  if (!code) fail('the CLI never printed a code');
  note('CLI code ' + code);

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 } });
  await ctx.addInitScript(() => {
    try { if (!localStorage.getItem('tunlion.deviceName')) localStorage.setItem('tunlion.deviceName', "Abdul's iPad") } catch {}
    try { localStorage.setItem('tunlionLog', 'debug') } catch {}
  });
  const page = await ctx.newPage();
  const logs = [];
  page.on('console', (m) => logs.push(`${Date.now()} ${m.type()} ${m.text()}`));
  await page.goto(`${BASE}/rooms/bcp-${Date.now()}`, { waitUntil: 'domcontentloaded' });
  await page.getByRole('radio', { name: 'Remember a device' }).first().click();
  await page.locator('#tl-code-w').fill(code);
  await page.getByTestId('code-connect').first().click();
  const banner = page.getByRole('region', { name: 'Remember this device?' }).first();
  await banner.waitFor({ timeout: 60000 }).catch(async () => fail('no Remember banner; ' + JSON.stringify(await rows(page)) + '\n' + (await page.evaluate(() => document.body.innerText)).slice(0, 1200)));
  note('banner suggests: ' + JSON.stringify(await banner.locator('input').inputValue()));
  await banner.getByRole('button', { name: 'Remember' }).click();
  note('tab chose Remember');

  for (let i = 0; i < 150 && addExit === null; i++) await sleep(200);
  note('add exited ' + addExit);
  note('CLI devices after add:\n' + cli(['devices']));

  // The machine then runs its daemon, as a person would.
  const up = spawn(BIN, ['up', '--server', BASE, '--dir', path.join(W, 'drop'), '--no-interactive'], { env: { ...CLI_ENV, TUNLION_LOG: 'debug' }, stdio: ['ignore', fs.openSync(path.join(W, 'up.log'), 'w'), fs.openSync(path.join(W, 'up.log'), 'a')] });
  procs.push(up);

  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: /^Devices/ }).click();
  let cameUp = false, last = '';
  const off = [];
  const watch = async (label, ms) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      const s = await rows(page);
      const k = JSON.stringify(s);
      if (k !== last) { note(`${label} +${Date.now() - t0}ms ${k}`); last = k; }
      const on = s.rows.some((r) => /, online$/.test(r));
      if (on) cameUp = true; else if (cameUp) off.push(`${label}+${Date.now() - t0}`);
      await sleep(500);
    }
  };
  await watch('idle', WATCH_MS);
  note('CLI devices (1):\n' + cli(['devices']));
  await watch('after-devices', 30000);
  note('CLI devices --json:\n' + cli(['devices', '--json']).slice(0, 1500));
  await watch('after-devices-json', 30000);
  fs.writeFileSync(path.join(W, 'before.txt'), 'before');
  note('relay mark before-send ' + backendLog.split('\n').length);
  note("CLI send --to Abdul's iPad (before rename):\n" + cli(['send', path.join(W, 'before.txt'), '--to', "Abdul's iPad", '--server', BASE, '--timeout', '15']).split('\n').slice(-8).join('\n'));
  await watch('after-send-before', 10000);
  const NO_RENAME = process.env.BCP_NO_RENAME === '1';
  if (!NO_RENAME) note('CLI rename:\n' + cli(['devices', 'rename', "Abdul's iPad", 'iPad']));
  note('CLI devices after rename:\n' + cli(['devices']));
  await watch('after-cli-rename', 45000);
  fs.writeFileSync(path.join(W, 'hello.txt'), 'hello');
  const afterSend = cli(['send', path.join(W, 'hello.txt'), '--to', NO_RENAME ? "Abdul's iPad" : 'iPad', '--server', BASE, '--timeout', '15'], { TUNLION_LOG: 'debug' });
  fs.writeFileSync(path.join(W, 'send-after.log'), afterSend);
  note('CLI send --to iPad (debug log at ' + path.join(W, 'send-after.log') + '):\n' + afterSend.split('\n').slice(-8).join('\n'));
  note('tab console during send:\n' + logs.slice(-40).join('\n'));
  note('relay tel tail:\n' + backendLog.split('\n').filter((x) => x.startsWith('TEL') && !/web:/.test(x)).slice(-40).join('\n'));
  await watch('after-send', 20000);
  note(`result: cameUp=${cameUp} offlineAfterUp=${off.length ? off[0] + '..' + off[off.length - 1] + ' (' + off.length + ')' : 'never'}`);
  if (!cameUp || off.length) {
    note('tab console tail:\n' + logs.filter((x) => /known|proof|peer|left|digest|rtc/i.test(x)).slice(-80).join('\n'));
    fail('the remembered CLI device was not steadily online in the tab');
  }
  note('OK: remembered CLI device online and stayed online');
  dump();
  await browser.close();
  cleanup();
  process.exit(0);
})().catch((e) => fail(String((e && e.stack) || e)));
