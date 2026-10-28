// Two real browsers pair by code and transfer a file through a given
// signaling backend (the staging Durable Object), on a forced transport.
//
//   API=https://tunlion-signal-staging.<sub>.workers.dev DIST=frontend/dist \
//   MODE=websocket|polling OUT=evidence/dir PLAYWRIGHT=/path/to/playwright \
//     node edge/signal/test/browser-transfer.cjs
//
// DIST must be a frontend build made with VITE_TUNLION_API=$API, served here
// on a local origin. MODE=polling replaces the page's WebSocket for socket.io
// URLs with one that fails at once, so engine.io falls back to long-polling
// and can never upgrade; the run then asserts no socket.io websocket opened.
// SCENARIO=cli-to-browser instead runs `tunlion send --code` (TUNLION_BIN,
// an isolated TUNLION_CONFIG_DIR, TUNLION_SERVER=$API) and has ONE browser
// enter the code and receive.
// The helpers mirror lab/matrix/browser/cells.cjs (BB1, B01), by visible label.
'use strict';
const fs = require('fs'), path = require('path'), http = require('http'), crypto = require('crypto'), cp = require('child_process');
const SCENARIO = process.env.SCENARIO || 'browser-to-browser';
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');

const API = (process.env.API || '').replace(/\/$/, '');
const DIST = process.env.DIST;
const MODE = process.env.MODE || 'websocket';
const OUT = process.env.OUT || 'browser-transfer-out';
fs.mkdirSync(OUT, { recursive: true });
const TAG = SCENARIO === 'cli-to-browser' ? `cli-${MODE}` : MODE;
const LOG = path.join(OUT, `browser-${TAG}.log`);
fs.writeFileSync(LOG, '');
const say = (...a) => { const s = `${new Date().toISOString()} ${a.join(' ')}`; fs.appendFileSync(LOG, s + '\n'); console.log(s); };
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const CODE = /\b[a-z]+-[a-z]+(?:-[a-z]+)?-\d{2,5}\b/;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.wasm': 'application/wasm', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

function serve() {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    let f = path.join(DIST, decodeURIComponent(u.pathname));
    if (!f.startsWith(path.resolve(DIST)) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(DIST, 'index.html');
    res.writeHead(200, { 'content-type': types[path.extname(f)] || 'application/octet-stream' });
    res.end(fs.readFileSync(f));
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}

const body = (p) => p.innerText('body');
async function waitText(p, re, ms) { const t = Date.now(); while (Date.now() - t < ms) { if (re.test(await body(p))) return true; await p.waitForTimeout(500); } return false; }
async function enterCode(p, code) {
  await p.getByRole('radio', { name: 'Receive a file' }).click();
  await p.getByLabel('Enter a code').fill(code);
  await p.getByRole('button', { name: 'Connect', exact: true }).click();
}
async function createCode(p) {
  await p.getByRole('radio', { name: 'Receive a file' }).click();
  const before = new Set((await body(p)).match(new RegExp(CODE.source, 'g')) || []);
  await p.getByRole('button', { name: 'Create a code' }).click();
  const t = Date.now();
  while (Date.now() - t < 30000) {
    const found = ((await body(p)).match(new RegExp(CODE.source, 'g')) || []).find((c) => !before.has(c));
    if (found) return found;
    await p.waitForTimeout(250);
  }
  return undefined;
}
async function pickFile(p, opener, file) {
  const [fc] = await Promise.all([p.waitForEvent('filechooser', { timeout: 15000 }), opener.click({ timeout: 15000 })]);
  await fc.setFiles(file);
}
async function saveDownload(p, to) {
  const dl = p.waitForEvent('download', { timeout: 15000 });
  await p.getByRole('button', { name: /^Save$/ }).last().click();
  const d = await dl; await d.saveAs(to); return to;
}
const sendTo = (p, peerName) => p.getByRole('button', { name: `send files to ${peerName}`, exact: true }).first();
const selfName = (p) => p.evaluate(() => sessionStorage.getItem('tunlion.name'));

async function open(origin, label) {
  const b = await chromium.launch({ args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
  const ctx = await b.newContext({ viewport: { width: 1280, height: 860 }, acceptDownloads: true, serviceWorkers: 'block' });
  if (MODE === 'polling') {
    await ctx.addInitScript(() => {
      const Real = window.WebSocket;
      // Fail socket.io websockets at once; leave any other websocket alone.
      window.WebSocket = function (url, protocols) {
        if (String(url).includes('/socket.io/')) throw new Error('websocket blocked for the polling run');
        return new Real(url, protocols);
      };
      Object.assign(window.WebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
      window.WebSocket.prototype = Real.prototype;
    });
  }
  const p = await ctx.newPage();
  const t = { websockets: [], polls: 0, backends: new Set() };
  p.on('websocket', (ws) => { if (ws.url().includes('/socket.io/')) t.websockets.push(ws.url()); });
  p.on('request', (r) => { if (r.url().includes('/socket.io/') && r.url().includes('transport=polling')) t.polls += 1; });
  p.on('response', (r) => { const h = r.headers()['x-tunlion-backend']; if (h && r.url().startsWith(API)) t.backends.add(h); });
  p.on('pageerror', (e) => say(label, 'pageerror', e.message));
  await p.goto(origin + '/', { waitUntil: 'commit' }).catch(() => {});
  await p.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
  await p.waitForTimeout(2500);
  return { b, p, t };
}

async function cliToBrowser(origin) {
  const t0 = Date.now();
  const dir = fs.mkdtempSync(path.join(OUT, 'cli-'));
  const f = path.join(dir, `${TAG}-sent.bin`);
  fs.writeFileSync(f, crypto.randomBytes(400000));
  const out = path.join(OUT, `${TAG}-cli-send.out`);
  const fd = fs.openSync(out, 'w');
  const tx = cp.spawn(process.env.TUNLION_BIN || 'tunlion', ['send', f, '--code', '--no-interactive'], {
    env: { ...process.env, TUNLION_SERVER: API, TUNLION_CONFIG_DIR: path.join(dir, 'cfg'), HOME: dir, TUNLION_NONINTERACTIVE: '1' },
    stdio: ['ignore', fd, fd],
  });
  let exit = null; tx.on('exit', (c) => { exit = c; });
  let code;
  for (let i = 0; i < 60 && !code; i++) { code = (fs.readFileSync(out, 'utf8').match(CODE) || [])[0]; if (!code) await new Promise((r) => setTimeout(r, 500)); }
  say('cli code', code);
  if (!code) throw new Error('CLI printed no code');
  const B = await open(origin, 'B');
  try {
    await enterCode(B.p, code);
    if (!(await waitText(B.p, new RegExp(`${TAG}-sent\\.bin[\\s\\S]*(done|complete)`, 'i'), 60000))) throw new Error('browser never showed done');
    const g = await saveDownload(B.p, path.join(OUT, `${TAG}-got.bin`));
    await B.p.screenshot({ path: path.join(OUT, `${TAG}-B-done.png`) });
    for (let i = 0; i < 30 && exit === null; i++) await new Promise((r) => setTimeout(r, 500));
    const same = sha(g) === sha(f);
    say('sha256 sent', sha(f), 'got', sha(g), same ? 'MATCH' : 'MISMATCH', 'cli exit', exit);
    say('B socket.io websockets', B.t.websockets.length, 'polling requests', B.t.polls);
    const transportOk = MODE === 'polling' ? B.t.websockets.length === 0 && B.t.polls > 2 : B.t.websockets.length > 0;
    say('transport assertion', transportOk ? 'ok' : 'FAILED');
    return same && exit === 0 && transportOk;
  } finally {
    await B.b.close();
    try { tx.kill('SIGKILL'); } catch {}
  }
}

(async () => {
  if (!API || !DIST) throw new Error('API and DIST are required');
  const srv = await serve();
  if (SCENARIO === 'cli-to-browser') {
    const origin = `http://127.0.0.1:${srv.address().port}`;
    say('scenario cli-to-browser mode', MODE, 'api', API);
    let pass = false;
    try { pass = await cliToBrowser(origin); } catch (e) { say('error', e.stack || e); }
    srv.close();
    say(pass ? 'PASS' : 'FAIL', TAG);
    process.exit(pass ? 0 : 1);
  }
  const origin = `http://127.0.0.1:${srv.address().port}`;
  say('mode', MODE, 'api', API, 'page origin', origin);
  const t0 = Date.now();
  const A = await open(origin, 'A'), B = await open(origin, 'B');
  let pass = false;
  try {
    const code = await createCode(A.p);
    say('code', code);
    if (!code) throw new Error('page A minted no code');
    await enterCode(B.p, code);
    const paired = await waitText(A.p, /Paired|Code accepted/, 30000);
    await A.p.screenshot({ path: path.join(OUT, `${MODE}-A-paired.png`) });
    await B.p.screenshot({ path: path.join(OUT, `${MODE}-B-paired.png`) });
    if (!paired) throw new Error('A never showed paired');
    say('paired after', Date.now() - t0, 'ms');
    const f = path.join(OUT, `${MODE}-sent.bin`);
    fs.writeFileSync(f, crypto.randomBytes(350000));
    await pickFile(A.p, sendTo(A.p, await selfName(B.p)), f);
    if (!(await waitText(B.p, new RegExp(`${MODE}-sent\\.bin[\\s\\S]*(done|complete)`, 'i'), 40000))) throw new Error('B never showed done');
    const g = await saveDownload(B.p, path.join(OUT, `${MODE}-got.bin`));
    await B.p.screenshot({ path: path.join(OUT, `${MODE}-B-done.png`) });
    const same = sha(g) === sha(f);
    say('sha256 sent', sha(f), 'got', sha(g), same ? 'MATCH' : 'MISMATCH');
    for (const [n, x] of [['A', A], ['B', B]]) {
      say(n, 'socket.io websockets', x.t.websockets.length, 'polling requests', x.t.polls, 'backends', [...x.t.backends].join(','));
    }
    const transportOk = MODE === 'polling'
      ? A.t.websockets.length === 0 && B.t.websockets.length === 0 && A.t.polls > 2 && B.t.polls > 2
      : A.t.websockets.length > 0 && B.t.websockets.length > 0 && A.t.websockets.every((u) => u.startsWith(API.replace(/^http/, 'ws')));
    say('transport assertion', transportOk ? 'ok' : 'FAILED');
    pass = same && transportOk;
  } catch (e) {
    say('error', e.stack || e);
  } finally {
    await A.b.close(); await B.b.close(); srv.close();
  }
  say(pass ? 'PASS' : 'FAIL', MODE, 'in', Date.now() - t0, 'ms');
  process.exit(pass ? 0 : 1);
})();
