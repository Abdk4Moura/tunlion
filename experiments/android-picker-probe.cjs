// Real Android Chrome (emulator) behind a real system file picker, on the
// polling transport, against a local relay. Measures what the other peer sees
// while the picker is up, and whether a file sends afterwards.
//   node android-picker-probe.cjs <label> <freezes csv> <hold 1|0>
const { spawn, execSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const pw = require(require.resolve('playwright', { paths: [path.join(process.cwd(), 'frontend')] }));
const ROOT = process.cwd();
const PORT = 8275, BASE = `http://localhost:${PORT}`;
const [label, freezesCsv, holdArg] = process.argv.slice(2);
const HOLD = holdArg !== '0';
const LOG = `/tmp/probe-relay-${label}.log`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (c) => { try { return execSync(`adb shell ${c}`, { encoding: 'utf8', timeout: 20000 }); } catch (e) { return String(e.stdout || e); } };
const pollGets = () => (fs.readFileSync(LOG, 'utf8').match(/GET \/socket\.io\/\?EIO=4&transport=polling&t=[^ ]*&sid=/g) || []).length;
const tel = () => fs.readFileSync(LOG, 'utf8').split('\n').filter((l) => l.includes('TEL {')).map((l) => { try { return JSON.parse(l.slice(l.indexOf('TEL {') + 4)); } catch { return {}; } });
function shim(hold) {
  window.__fd = { held: 0, wsOpen: 0, leaves: 0 };
  const W = window.WebSocket;
  window.WebSocket = function (...a) {
    if (hold) { window.__fd.held++; const f = new EventTarget(); Object.assign(f, { readyState: 0, url: a[0], protocol: '', extensions: '', bufferedAmount: 0, binaryType: 'blob', send() {}, close() { f.readyState = 3 } }); return f; }
    const ws = new W(...a); ws.addEventListener('open', () => window.__fd.wsOpen++);
    const s = ws.send.bind(ws); ws.send = (d) => { if (typeof d === 'string' && /^42\d*\["leave"/.test(d)) window.__fd.leaves++; return s(d); }; return ws;
  };
  window.WebSocket.prototype = W.prototype; Object.assign(window.WebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
}
const tiles = (page, n) => page.evaluate((x) => [...document.querySelectorAll('[data-testid="peer-tile"]')].filter((el) => (el.getAttribute('aria-label') || '').startsWith(x + ',')).map((el) => el.getAttribute('aria-label')), n);
const nameOf = (page) => page.evaluate(() => document.querySelector('[data-testid="device-name-input"]')?.value || document.documentElement.getAttribute('data-device-name') || '');
const up = (page) => page.waitForFunction(() => !!(window.__tunlionTestSocket && window.__tunlionTestSocket().connected), null, { timeout: 30000 });
async function waitReady(page, n, ms = 40000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if ((await tiles(page, n)).some((l) => l.startsWith(n + ', ready'))) return true; await sleep(200); } return false; }
(async () => {
  const relay = spawn(process.env.PY || 'python3', ['app.py'], { cwd: path.join(ROOT, 'backend'), env: { ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'eventlet', FIL_SELF_MONKEYPATCH: '1', FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '60', FIL_PING_INTERVAL: '25', FIL_SECRET: 'probe' }, stdio: ['ignore', fs.openSync(LOG, 'w'), fs.openSync(LOG, 'a')] });
  for (let i = 0; i < 100; i++) { const ok = await new Promise((r) => http.get(BASE + '/api/health', (x) => { x.resume(); r(x.statusCode === 200); }).on('error', () => r(false))); if (ok) break; await sleep(300); }
  execSync(`adb reverse tcp:${PORT} tcp:${PORT}`);
  const host = await pw.chromium.launch();
  const obsCtx = await host.newContext();
  const obs = await obsCtx.newPage();
  await obs.goto(BASE + '/?test=1'); await up(obs);
  const obsName = await nameOf(obs);
  const [device] = await pw._android.devices();
  console.log(`[probe ${label}] device ${device.model()} ${device.serial()}; chrome ${adb('dumpsys package com.android.chrome | grep versionName | head -1').trim()}`);
  await device.shell('am force-stop com.android.chrome');
  for (const perm of ['READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO', 'READ_MEDIA_VISUAL_USER_SELECTED', 'READ_EXTERNAL_STORAGE', 'POST_NOTIFICATIONS', 'CAMERA']) adb(`pm grant com.android.chrome android.permission.${perm}`);
  const ctx = await device.launchBrowser();
  const departures = [];
  ctx.on('request', (r) => { const u = r.url(); if (/session\/close/.test(u)) departures.push('session-close'); else if (/socket\.io/.test(u) && r.method() === 'POST' && /\["leave"/.test(r.postData() || '')) departures.push('leave(polling)'); });
  await ctx.addInitScript(shim, HOLD);
  let page = ctx.pages()[0];
  try { page = await ctx.newPage(); } catch (e) { console.log(`[probe ${label}] newPage: ${String(e).slice(0, 100)}; using the open tab`); }
  if (!page) throw new Error('no page');
  await page.goto(BASE + '/?test=1'); await up(page);
  const phone = await nameOf(page);
  if (!(await waitReady(obs, phone, 60000)) || !(await waitReady(page, obsName, 60000))) { await page.reload(); await up(page); }
  if (!(await waitReady(obs, phone, 60000)) || !(await waitReady(page, obsName, 60000))) { console.log(`[probe ${label}] FAIL: never paired; obs sees ${JSON.stringify(await tiles(obs, phone))}`); process.exit(1); }
  console.log(`[probe ${label}] phone ${phone} transport ${JSON.stringify(await page.evaluate(() => [window.__fd, window.__tunlionTestSocket()]))}`);
  const rows = [];
  for (const f of freezesCsv.split(',').map(Number)) {
    await sleep(3000);
    const before = tel().length;
    // The real system picker: no filechooser interception.
    await page.locator(`[data-testid="peer-tile"][aria-label^="${obsName},"] button[aria-label^="send files to"]`).first().click();
    await sleep(1500);
    const top = adb('dumpsys activity activities | grep -E "mResumedActivity|topResumedActivity" | head -2').trim();
    const g0 = pollGets();
    const t0 = Date.now(); let gaps = 0, gapAt = null, longest = 0, firstGap = null;
    while (Date.now() - t0 < f * 1000) {
      const n = (await tiles(obs, phone)).length;
      if (!n && gapAt == null) { gapAt = Date.now(); gaps++; if (firstGap == null) firstGap = gapAt - t0; }
      if (n && gapAt != null) { longest = Math.max(longest, Date.now() - gapAt); gapAt = null; }
      await sleep(250);
    }
    const getsDuring = pollGets() - g0;
    const topEnd = adb('dumpsys activity activities | grep -E "topResumedActivity" | head -1').trim();
    adb('input keyevent KEYCODE_BACK');
    const tBack = Date.now();
    await sleep(1000);
    // Back in Chrome: send a file through an intercepted chooser.
    const backReady = await waitReady(obs, phone, 30000) ? Date.now() - tBack : null;
    const chooserP = page.waitForEvent('filechooser', { timeout: 20000 });
    await page.locator(`[data-testid="peer-tile"][aria-label^="${obsName},"] button[aria-label^="send files to"]`).first().click({ timeout: 20000 }).catch(() => {});
    let sendMs = null;
    try {
      const ch = await chooserP; const ts = Date.now();
      await ch.setFiles({ name: `p${f}.bin`, mimeType: 'application/octet-stream', buffer: require('crypto').randomBytes(128 * 1024) });
      while (Date.now() - ts < 60000) {
        const acc = obs.locator('button', { hasText: /^Accept$/ }); if (await acc.count()) await acc.first().click().catch(() => {});
        if (await obs.evaluate((n) => [...document.querySelectorAll('button')].some((b) => b.textContent === 'Save' && (b.closest('div')?.parentElement?.innerText || '').includes(n)), `p${f}.bin`)) { sendMs = Date.now() - ts; break; }
        await sleep(150);
      }
    } catch (e) { console.log(`[probe ${label}] chooser: ${String(e).slice(0, 120)}`); }
    if (gapAt != null) longest = Math.max(longest, Date.now() - gapAt);
    const ev = tel().slice(before).map((e) => e.ev);
    const fd = await page.evaluate(() => window.__fd).catch(() => ({}));
    const r = { label, freezeS: f, transport: HOLD ? 'polling' : 'websocket', pickerTop: !/com\.android\.chrome\//.test(top) ? top.replace(/.*ActivityRecord\{\S+ \S+ /, '').slice(0, 80) : 'CHROME', topAtEnd: topEnd.replace(/.*ActivityRecord\{\S+ \S+ /, '').slice(0, 80), pollGetsDuringPicker: getsDuring, gaps, firstGapMs: firstGap, longestGapMs: longest, pollLapsed: ev.filter((e) => e === 'poll-lapsed').length, disconnects: ev.filter((e) => e === 'disconnect').length, away: ev.filter((e) => e === 'poll-away').length, readyAfterBackMs: backReady, sendMs, departures: departures.splice(0), wsLeaves: fd.leaves };
    rows.push(r);
    console.log(`[probe ${label}] ${JSON.stringify(r)}`);
  }
  fs.writeFileSync(`/tmp/probe-${label}.json`, JSON.stringify(rows, null, 1));
  await ctx.close().catch(() => {}); await host.close(); relay.kill('SIGKILL'); execSync(`adb reverse --remove tcp:${PORT}`);
  process.exit(0);
})().catch((e) => { console.error(`[probe ${label}] ERROR`, e); process.exit(1); });
