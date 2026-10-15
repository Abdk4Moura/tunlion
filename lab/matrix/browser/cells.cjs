// Browser cells of the launch matrix: browser-CLI and browser-browser.
//
//   node browser/cells.cjs <outdir> [cell-regex]
//
// Env:
//   LAB_HOST        command that runs a shell command on the lab host (docker + tmux)
//   PLAYWRIGHT      path to the playwright package (CommonJS require)
//   FRONTEND_DIST   the built frontend (vite dist) served under the real origin
//   MX_ORIGIN       instead: the origin of a local backend that serves its own
//                   same-origin build (backend/app.py); no interception then
//
// The page is served under https://tunlion.autumated.com (the production API
// refuses other origins) from FRONTEND_DIST, and talks to the production API.
// The CLI peer is a fresh container on the lab host built by box.sh.
'use strict';
const fs = require('fs'), path = require('path'), cp = require('child_process'), crypto = require('crypto');
const { chromium, devices } = require(process.env.PLAYWRIGHT || 'playwright');
const OUT = process.argv[2], FILTER = new RegExp(process.argv[3] || '.');
const DIST = process.env.FRONTEND_DIST;
const PROD_ORIGIN = 'https://tunlion.autumated.com';
const ORIGIN = process.env.MX_ORIGIN || PROD_ORIGIN;
const VPS = 'mx-bvps';
fs.mkdirSync(path.join(OUT, 'ev'), { recursive: true });
const RES = path.join(OUT, 'browser.jsonl'); fs.writeFileSync(RES, '');

const lab = (cmd, opt = {}) => cp.execSync(`${process.env.LAB_HOST} ${JSON.stringify(cmd)}`, { encoding: 'utf8', timeout: opt.timeout || 180000 });
// Scripts go over stdin: a quoted multi-line command does not survive the lab-host hop.
const vps = (script, opt = {}) => cp.execSync(`${process.env.LAB_HOST} "docker exec -i ${VPS} bash -l -s"`, { input: script + '\n', encoding: 'utf8', timeout: opt.timeout || 180000 });
// The async form keeps node's event loop running while a long CLI command runs:
// with execSync the Playwright connection is not serviced, so the page's CDP
// traffic (console events, intercepted requests) backs up for the whole command.
const vpsAsync = (script, opt = {}) => new Promise(res => {
  const ch = cp.spawn('bash', ['-c', `${process.env.LAB_HOST} "docker exec -i ${VPS} bash -l -s"`]);
  let out = ''; ch.stdout.on('data', d => out += d); ch.stderr.on('data', d => out += d);
  const t = setTimeout(() => ch.kill('SIGKILL'), opt.timeout || 180000);
  ch.on('close', code => { clearTimeout(t); res({ out, rc: code }); });
  ch.stdin.end(script + '\n');
});
const tryVps = (script, opt) => { try { return { out: vps(script, opt), rc: 0 }; } catch (e) { return { out: (e.stdout || '') + (e.stderr || ''), rc: e.status }; } };
const sha = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const CODE = /\b[a-z]+-[a-z]+(?:-[a-z]+)?-\d{2,5}\b/;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.wasm': 'application/wasm', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

async function browser(kind = 'desktop') {
  const b = await chromium.launch({ args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
  const opts = kind === 'phone' ? { ...devices['Pixel 7'] } : { viewport: { width: 1280, height: 860 } };
  // serviceWorkers: 'block'. The app installs a service worker, and requests a
  // worker makes are not seen by context.route: after the first load every
  // reload would be served from PRODUCTION, not the build under test.
  const ctx = await b.newContext({ ...opts, acceptDownloads: true, serviceWorkers: 'block' });
  if (ORIGIN === PROD_ORIGIN) await ctx.route(`${ORIGIN}/**`, async r => {
    const u = new URL(r.request().url()); let f = path.join(DIST, decodeURIComponent(u.pathname));
    if (!fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(DIST, 'index.html');
    await r.fulfill({ status: 200, body: fs.readFileSync(f), contentType: types[path.extname(f)] || 'application/octet-stream' });
  });
  if (process.env.MX_DEBUG) await ctx.addInitScript(() => { try { localStorage.setItem('tunlionLog', 'trace'); } catch {} });
  const p = await ctx.newPage();
  const log = [];
  if (process.env.MX_DEBUG) p.on('console', m => log.push(`${new Date().toISOString().slice(11, 23)} ${m.type()}: ${m.text().slice(0, 400)}`));
  p.on('pageerror', e => log.push('pageerror: ' + e.message));
  p.on('console', m => { if (m.type() === 'error') log.push('console: ' + m.text().slice(0, 200)); });
  await home(p); await p.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {}); await p.waitForTimeout(2500);
  return { b, ctx, p, log, kind };
}
const body = p => p.innerText('body');
// Reload the app. A navigation the app itself starts (a first service-worker
// install used to reload the page) aborts Playwright's goto; that is not a test
// failure, so wait for the page to settle instead.
async function home(p) {
  await p.goto(ORIGIN + '/', { waitUntil: 'commit' }).catch(() => {});
  await p.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
}
async function waitText(p, re, ms) { const t = Date.now(); while (Date.now() - t < ms) { if (re.test(await body(p))) return true; await p.waitForTimeout(500); } return false; }
const term = p => p.evaluate(() => [...document.querySelectorAll('.xterm-rows')].map(e => e.innerText).join('\n'));

// UI verbs, by visible label (the code box is a two-mode toggle).
async function enterCode(p, code, mode = 'Receive a file') {
  await p.getByRole('radio', { name: mode }).click();
  await p.getByLabel('Enter a code').fill(code);
  await p.getByRole('button', { name: 'Connect' }).click();
}
async function createCode(p, mode = 'Receive a file') {
  await p.getByRole('radio', { name: mode }).click();
  // Codes already on the page (a sample, an older code) are not the answer:
  // wait for a code that was not there before the click.
  const before = new Set((await body(p)).match(new RegExp(CODE.source, 'g')) || []);
  await p.getByRole('button', { name: 'Create a code' }).click();
  const t = Date.now();
  while (Date.now() - t < 30000) {
    const found = ((await body(p)).match(new RegExp(CODE.source, 'g')) || []).find(c => !before.has(c));
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
// The Send files button on the row of the peer that came in on `code`. Other
// browsers on the same public IP (other test runs) also appear under "near you",
// so a bare "Drop a file to send" could go to the wrong peer.
function sendTo(p, peerName) {
  return p.getByRole('button', { name: `send files to ${peerName}`, exact: true }).first();
}
// The name this browser goes by (what the other side's row is labelled).
const selfName = p => p.evaluate(() => sessionStorage.getItem('tunlion.name'));
// Click the Remember button of the "Paired. Remember this device?" prompt. Wait
// for the BUTTON: the text "Remember" is always on the page (the "Remember a
// device" mode), so waiting for the text clicked nothing and stored nothing.
async function remember(p) {
  const r = p.getByRole('button', { name: 'Remember', exact: true }).first();
  await r.waitFor({ state: 'visible', timeout: 30000 });
  await r.click(); await p.waitForTimeout(2500);
  return true;
}

let ev; const say = (...a) => { const s = a.join(' '); fs.appendFileSync(ev, s + '\n'); };
async function shot(p, name) { const f = path.join(OUT, 'ev', name + '.png'); await p.screenshot({ path: f }); say('screenshot', 'ev/' + name + '.png'); }
function assert(c, what) { say((c ? 'ok   ' : 'FAIL ') + what); if (!c) throw new Error(what); }
function na(why) { const e = new Error(why); e.na = true; throw e; }

async function cell(id, pair, feature, fn) {
  if (!FILTER.test(id)) return;
  ev = path.join(OUT, 'ev', id + '.log'); fs.writeFileSync(ev, '');
  const t0 = Date.now(); let result = 'pass';
  try { await fn(); } catch (e) { result = e.na ? 'n/a' : 'fail'; say('error:', e.stack || e); }
  const row = { cell: id, pair, feature, result, seconds: Math.round((Date.now() - t0) / 1000), evidence: `ev/${id}.log` };
  fs.appendFileSync(RES, JSON.stringify(row) + '\n');
  console.log(result.padEnd(5), id.padEnd(8), feature);
}

async function receiveFromCli(kind) {
  vps(`head -c 400000 /dev/urandom > b.bin; sha256sum b.bin | cut -c1-64 > b.sha; (tunlion send b.bin --code > b.out 2>&1; echo "EXIT=$?" >> b.out) & sleep 5`);
  // A cold machine can take longer than the 5 s above to reach the server: poll for the code.
  let code; for (let i = 0; i < 25 && !code; i++) { code = (vps('cat b.out').match(CODE) || [])[0]; if (!code) cp.execSync('sleep 1'); }
  say('code', code); assert(code, 'CLI printed a code');
  const x = await browser(kind);
  try {
    await enterCode(x.p, code);
    assert(await waitText(x.p, /b\.bin[\s\S]*(done|complete)/i, 40000), 'transfer shows done in the page');
    await shot(x.p, `rx-${kind}`);
    const f = await saveDownload(x.p, path.join(OUT, 'ev', `rx-${kind}.bin`));
    assert(sha(f) === vps('cat b.sha').trim(), 'downloaded file matches the sender sha256');
    await x.p.waitForTimeout(2000);
    assert(/EXIT=0/.test(vps('cat b.out')), 'CLI send exited 0 (receiver verified)');
    await x.p.waitForTimeout(8000); const after = await body(x.p); await shot(x.p, `rx-${kind}-after`);
    assert(!/Waiting for the file/i.test(after), 'the code box no longer says it is waiting for the file');
    assert(!/\bvps\b[\s\S]{0,80}?connecting/i.test(after), 'the finished sender is not shown as still connecting');
    say(x.log.join('\n'));
  } finally { await x.b.close(); }
}

// A browser remembered by the vps, kept open across the paired cells.
async function pairWithVps(kind, via) {
  const x = await browser(kind);
  try { return await pairWithVpsIn(x, via); } catch (e) { await x.b.close(); throw e; }
}
async function pairWithVpsIn(x, via) {
  if (via === 'cli-add') {
    // CLI offers at a TTY; the browser claims in "Remember a device" mode.
    lab(`tmux kill-session -t bxa 2>/dev/null; tmux new-session -d -s bxa -x 160 -y 50 "docker exec -it ${VPS} bash -l"; sleep 2; tmux send-keys -t bxa 'tunlion add' Enter; sleep 4; tmux send-keys -t bxa Enter; sleep 4`);
    const pane = lab(`tmux capture-pane -p -J -t bxa`); const code = (pane.match(CODE) || [])[0]; say('code', code); assert(code, 'CLI add showed a code');
    await enterCode(x.p, code, 'Remember a device');
    assert(await remember(x.p), 'page offers Remember and it was chosen');
    let pane2 = ''; for (let i = 0; i < 25 && !/remembered|verified end-to-end/.test(pane2); i++) { await x.p.waitForTimeout(1000); pane2 = lab(`tmux capture-pane -p -J -t bxa`); }
    say(pane2); assert(/remembered|verified end-to-end/.test(pane2), 'CLI reports the browser remembered');
  } else {
    // The browser creates the code in "Remember a device" mode; the CLI joins it.
    const code = await createCode(x.p, 'Remember a device'); say('code', code); assert(code, 'page shows a code');
    vps(`(timeout 90 tunlion join ${process.env.MX_DEBUG ? '-vv ' : ''}${code} > join.out 2>&1; echo "EXIT=$?" >> join.out) & sleep 1`);
    const offered = await remember(x.p).catch(() => false);
    if (!offered) { await shot(x.p, `no-remember-${x.kind}`); say('join.out:', vps('sleep 5; cat join.out')); if (process.env.MX_DEBUG) fs.writeFileSync(path.join(OUT, 'ev', `nopair-${x.kind}-console.txt`), x.log.join('\n')); }
    assert(offered, 'page offers Remember and it was chosen');
    let out = ''; for (let i = 0; i < 60 && !/EXIT=/.test(out); i++) { await x.p.waitForTimeout(1000); out = vps('cat join.out'); }
    say(out); assert(/EXIT=0/.test(out), 'CLI `join <browser code>` exited 0');
  }
  await shot(x.p, `paired-${via}`);
  const devs = vps('tunlion devices --json'); say(devs);
  const names = [...devs.matchAll(/"name":"([^"]+)"/g)].map(m => m[1]);
  const name = names[names.length - 1]; assert(name, 'browser is in the CLI device list');
  return { ...x, name };
}

(async () => {
  lab(`~/matrix/box.sh up ${VPS}`);
  vps(`tunlion init --name vps --no-background --recovery-file ~/.recovery -y >/dev/null && tunlion up --detach >/dev/null && echo ok`);
  let paired = null;
  // A device paired by a separate CLI process is picked up by the running
  // daemon on its next tick (about 20 s), so a fresh pairing reads OFFLINE
  // until then. Wait for ONLINE (bounded) before using it.
  const waitOnline = async (p, name, ms = 60000) => {
    await p.getByRole('button', { name: /^Devices/ }).first().click();
    const t = Date.now();
    while (Date.now() - t < ms) {
      // The row's online chip names the route: ONLINE, LAN (a direct link on the
      // local network) or RELAY. OFFLINE is the only offline state.
      if (new RegExp(`${name}[\\s\\S]{0,120}?\\b(ONLINE|LAN|RELAY)\\b`).test(await body(p))) return true;
      await p.waitForTimeout(2000);
    }
    return false;
  };

  await cell('B01', 'browser-cli', 'receive by code (desktop)', () => receiveFromCli('desktop'));
  await cell('B02', 'browser-cli', 'receive by code (phone)', () => receiveFromCli('phone'));

  await cell('B03', 'browser-cli', 'browser code, CLI receive, browser sends', async () => {
    const x = await browser();
    try {
      const code = await createCode(x.p); say('code', code); assert(code, 'page shows a code');
      vps(`mkdir -p fromweb; (timeout 90 tunlion receive ${code} --dir fromweb > fw.out 2>&1; echo "EXIT=$?" >> fw.out) & sleep 1`);
      const pairedUp = await waitText(x.p, /Paired|Code accepted/, 30000);
      if (!pairedUp) { say('CLI receiver said:', tryVps('cat fw.out').out); await shot(x.p, 'b03-not-paired'); if (process.env.MX_DEBUG) fs.writeFileSync(path.join(OUT, 'ev', 'B03-console.txt'), x.log.join('\n')); }
      assert(pairedUp, 'page pairs with the CLI receiver');
      const f = path.join(OUT, 'ev', 'web-sent.bin'); fs.writeFileSync(f, crypto.randomBytes(250000));
      // The CLI receiver's row is labelled with its display name.
      const rows = x.p.getByRole('button', { name: /^send files to /i });
      const names = await rows.evaluateAll(els => els.map(e => e.getAttribute('aria-label')));
      say('rows:', JSON.stringify(names));
      const cliRow = names.find(n => /vps/.test(n));
      assert(cliRow, 'the CLI receiver has a row on the page');
      await pickFile(x.p, x.p.getByRole('button', { name: cliRow, exact: true }), f);
      let out = ''; for (let i = 0; i < 60 && !/EXIT=/.test(out); i++) { await x.p.waitForTimeout(1000); out = vps('cat fw.out'); }
      say(out); await shot(x.p, 'b03');
      assert(/EXIT=0/.test(out), 'CLI receive exited 0');
      assert(vps('sha256sum fromweb/web-sent.bin | cut -c1-64').trim() === sha(f), 'CLI got the exact bytes');
    } finally { await x.b.close(); }
  });

  await cell('B04', 'browser-cli', 'CLI joins a browser "Remember a device" code', async () => {
    const x = await pairWithVps('desktop', 'browser-code');
    await x.b.close();
    vps(`tunlion devices forget '${x.name}' -y >/dev/null 2>&1; true`);
  });

  await cell('B05', 'browser-cli', 'browser claims a CLI `add` code, both remember', async () => {
    paired = await pairWithVps('desktop', 'cli-add');
  });

  await cell('B06', 'browser-cli', 'browser sends to the remembered vps after reload', async () => {
    assert(paired, 'B05 paired a browser'); const { p } = paired;
    await home(p); await p.waitForTimeout(6000);
    await p.getByRole('button', { name: 'Devices' }).click(); await p.waitForTimeout(3000);
    await shot(p, 'b06-devices');
    assert(/vps/.test(await body(p)), 'vps is listed under Devices after reload');
    assert(await waitOnline(p, 'vps'), 'vps comes ONLINE after reload');
    const f = path.join(OUT, 'ev', 'to-vps.bin'); fs.writeFileSync(f, crypto.randomBytes(300000));
    await p.getByRole('button', { name: 'Home', exact: true }).click(); await p.waitForTimeout(1500);
    await pickFile(p, p.getByRole('button', { name: /^send files to vps$/i }).first(), f);
    let got = ''; for (let i = 0; i < 40 && !got; i++) { await p.waitForTimeout(1000); got = tryVps('sha256sum Tunlion/to-vps.bin 2>/dev/null | cut -c1-64').out.trim(); }
    assert(got === sha(f), 'vps inbox has the exact bytes');
  });

  const openShell = async (p, ms = 45000) => {
    await waitOnline(p, 'vps', 60000);
    const btn = p.getByRole('button', { name: /open a shell on/i });
    const t = Date.now();
    while (!(await btn.count()) && Date.now() - t < ms) await p.waitForTimeout(2000);
    if (!(await btn.count())) return false;
    await btn.first().click();
    // Wait for the prompt, not a fixed time.
    for (let i = 0; i < 20 && !/\$\s*$/m.test(await term(p)); i++) await p.waitForTimeout(1000);
    return true;
  };

  await cell('B07', 'browser-cli', 'shell: refused before grant, works after (desktop)', async () => {
    assert(paired, 'B05 paired a browser'); const { p, name } = paired;
    if (await openShell(p)) {
      await shot(p, 'b07-before');
      assert(/not granted|refused/i.test(await body(p) + await term(p)), 'shell before grant is refused with a reason');
      await home(p); await p.waitForTimeout(4000);
    } else say('no Shell button before grant (buttons only for access held)');
    await waitOnline(p, 'vps', 60000);
    say(vps(`tunlion grant '${name}' shell; echo GRANT=$?`));
    // The open page learns of the grant on its live link: no reload.
    const shellBtn = p.getByRole('button', { name: /open a shell on/i });
    let live = false; for (let i = 0; i < 10 && !live; i++) { await p.waitForTimeout(2000); live = (await shellBtn.count()) > 0; }
    await shot(p, 'b07-after-grant');
    assert(live, 'the Shell button appears after the grant without a reload');
    assert(await openShell(p), 'Shell button present after grant');
    await p.keyboard.type('echo WEB-$((40+2)); hostname\n'); await p.waitForTimeout(4000);
    const t = await term(p); say(t); await shot(p, 'b07-shell');
    assert(/WEB-42/.test(t) && /mx-bvps/.test(t), 'command ran on the vps');
  });

  await cell('B08', 'browser-cli', 'shell on a phone viewport against the vps', async () => {
    // A second browser (phone) pairs and is granted shell, then runs a command.
    const ph = await pairWithVps('phone', 'browser-code');
    try {
      say(vps(`tunlion grant '${ph.name}' shell; echo GRANT=$?`));
      await home(ph.p); await ph.p.waitForTimeout(7000);
      // The phone layout may put Devices in a bottom bar; same label.
      assert(await openShell(ph.p), 'Shell button present on the phone');
      await shot(ph.p, 'b08-phone-shell-open');
      await ph.p.keyboard.type('echo PHONE-$((40+2)); hostname\n'); await ph.p.waitForTimeout(4000);
      const t = await term(ph.p); say(t); await shot(ph.p, 'b08-phone-shell');
      assert(/PHONE-42/.test(t) && /mx-bvps/.test(t), 'command ran on the vps from the phone');
      const vp = ph.p.viewportSize(); const box = await ph.p.locator('.xterm').first().boundingBox();
      say('terminal box', JSON.stringify(box), 'viewport', JSON.stringify(vp));
      assert(box && box.height > vp.height * 0.6, 'terminal takes most of the phone screen');
    } finally { await ph.b.close(); }
  });

  await cell('B11', 'browser-cli', 'browser shell survives a 10 s network cut', async () => {
    assert(paired, 'B05 paired a browser'); const { p, ctx } = paired;
    await home(p); await p.waitForTimeout(5000);
    assert(await openShell(p), 'Shell button present');
    await p.keyboard.type('export MXW=kept; echo START-$MXW\n'); await p.waitForTimeout(3000);
    assert(/START-kept/.test(await term(p)), 'shell answered before the cut');
    await ctx.setOffline(true);
    let sawReconnecting = false;
    for (let i = 0; i < 10; i++) { await p.waitForTimeout(1000); if (/reconnect/i.test(await body(p) + await term(p))) sawReconnecting = true; }
    await shot(p, 'b11-cut');
    await ctx.setOffline(false);
    assert(sawReconnecting, 'page shows it is reconnecting during the cut');
    let resumed = false;
    for (let i = 0; i < 60 && !resumed; i++) {
      await p.waitForTimeout(1000);
      if (i % 5 === 0) await p.keyboard.type('echo BACK-$MXW-$((40+2))\n');
      resumed = /BACK-kept-42/.test(await term(p));
    }
    await shot(p, 'b11-resumed'); say(await term(p));
    assert(resumed, 'the same shell (its variable kept) answers after the network returns');
  });

  await cell('B09', 'browser-cli', 'revoke shell cuts the browser off', async () => {
    assert(paired, 'B05 paired a browser'); const { p, name } = paired;
    say(vps(`tunlion revoke '${name}' shell -y; echo REVOKE=$?`));
    await home(p); await p.waitForTimeout(7000);
    if (await openShell(p)) {
      await p.keyboard.type('echo NOPE-$((1+1))\n'); await p.waitForTimeout(3000);
      const t = await body(p) + '\n' + await term(p); await shot(p, 'b09');
      assert(!/NOPE-2/.test(t), 'no command runs after revoke');
      assert(/not granted|refused/i.test(t), 'refusal names the reason');
    } else say('Shell button gone after revoke');
  });

  await cell('B10', 'browser-cli', 'CLI sends --to the remembered browser', async () => {
    assert(paired, 'B05 paired a browser'); const { p, name } = paired;
    // The transfer list is on Home; the cells before may have left the page on the shell.
    await p.getByRole('button', { name: 'Home', exact: true }).click().catch(() => {}); await p.waitForTimeout(1000);
    vps(`head -c 200000 /dev/urandom > tob.bin; sha256sum tob.bin | cut -c1-64 > tob.sha`);
    const r = await vpsAsync(`timeout 60 tunlion send ${process.env.MX_DEBUG ? '-vv' : ''} tob.bin --to '${name}'`, { timeout: 90000 }); say(r.out, 'rc', r.rc);
    if (process.env.MX_DEBUG) { const alive = await Promise.race([p.evaluate(() => 'alive'), new Promise(r => setTimeout(() => r('HUNG'), 5000))]); paired.log.push('PAGE ' + alive); await shot(p, 'b10-after'); fs.writeFileSync(path.join(OUT, 'ev', 'B10-console.txt'), paired.log.join('\n')); }
    assert(r.rc === 0, 'CLI send --to browser exited 0');
    assert(await waitText(p, /tob\.bin[\s\S]*(done|complete)/i, 20000), 'page shows the file done');
    const f = await saveDownload(p, path.join(OUT, 'ev', 'tob.bin'));
    assert(sha(f) === vps('cat tob.sha').trim(), 'browser got the exact bytes');
  });
  await cell('B12', 'browser-cli', 'pairing with a bystander browser on the same network, 3 times', async () => {
    // The browser paired in B05 is still open on this network: it shares the
    // room every new page joins. A pairing must run with the creator of the
    // code, never with a bystander that happened to connect first.
    assert(paired, 'B05 left a browser open as the bystander');
    for (let i = 1; i <= 3; i++) {
      const x = await browser('phone');
      try { await pairWithVpsIn(x, 'browser-code'); say(`round ${i} paired`); } finally { await x.b.close(); }
    }
  });
  if (paired) await paired.b.close();

  await cell('BB1', 'browser-browser', 'code, then send (desktop to phone)', async () => {
    const A = await browser('desktop'), B = await browser('phone');
    try {
      const code = await createCode(A.p); say('code', code); assert(code, 'page A shows a code');
      await enterCode(B.p, code);
      const ok = await waitText(A.p, /Paired|Code accepted/, 30000);
      await shot(A.p, 'bb1-A'); await shot(B.p, 'bb1-B');
      assert(ok, 'A shows paired');
      const f = path.join(OUT, 'ev', 'bb.bin'); fs.writeFileSync(f, crypto.randomBytes(350000));
      await pickFile(A.p, sendTo(A.p, await selfName(B.p)), f);
      assert(await waitText(B.p, /bb\.bin[\s\S]*(done|complete)/i, 40000), 'B shows done');
      const g = await saveDownload(B.p, path.join(OUT, 'ev', 'bb-got.bin'));
      await shot(B.p, 'bb1'); assert(sha(g) === sha(f), 'B got the exact bytes');
    } finally { await A.b.close(); await B.b.close(); }
  });

  await cell('BB2', 'browser-browser', 'remember each other, reload, send', async () => {
    const A = await browser('desktop'), B = await browser('desktop');
    try {
      const code = await createCode(A.p, 'Remember a device'); assert(code, 'page A shows a code');
      await enterCode(B.p, code, 'Remember a device');
      assert(await remember(A.p), 'A offers Remember and it was chosen');
      await remember(B.p);
      await home(A.p); await home(B.p); await A.p.waitForTimeout(8000);
      const bname = await selfName(B.p);
      const up = await waitOnline(A.p, bname);
      await shot(A.p, 'bb2-devices-after-reload'); say('B is', bname);
      assert(up, 'B comes ONLINE on A after both reload');
      const f = path.join(OUT, 'ev', 'bb2.bin'); fs.writeFileSync(f, crypto.randomBytes(120000));
      await A.p.getByRole('button', { name: 'Home', exact: true }).click(); await A.p.waitForTimeout(1500); // the send button is on Home's rows
      await pickFile(A.p, sendTo(A.p, await selfName(B.p)), f);
      assert(await waitText(B.p, /bb2\.bin[\s\S]*(done|complete)/i, 40000), 'B shows done after reload');
    } finally {
      if (process.env.MX_DEBUG) { fs.writeFileSync(path.join(OUT, 'ev', 'BB2-A.txt'), A.log.join('\n')); fs.writeFileSync(path.join(OUT, 'ev', 'BB2-B.txt'), B.log.join('\n')); }
      await A.b.close(); await B.b.close();
    }
  });

  lab(`tmux kill-session -t bxa 2>/dev/null; ~/matrix/box.sh down ${VPS}`);
})().catch(e => { console.error(e); process.exit(1); });
