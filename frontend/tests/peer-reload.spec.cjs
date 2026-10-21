// Generation-safe reload / reconnect gate, against the REAL app + relay.
//
// The bug being guarded: a normal tab reload could leave a stale signaling
// session behind, and the new page then failed to connect until the tab was
// closed entirely. The fix is generation ownership on the relay:
//   * every page load has a new session generation;
//   * a new generation for the same device uid supersedes the old one at once;
//   * a late pagehide close from the old generation is ignored;
//   * pagehide closes local PeerConnections synchronously, pageshow revalidates.
//
// This spec drives two browser engines (Chromium and WebKit with an iPad touch
// context) plus the real Flask/Socket.IO relay. It does not need a Rust build.
//
//   node frontend/tests/peer-reload.spec.cjs        (from the repo root)

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const os = require('os');
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

const ROOT = path.resolve(__dirname, '..', '..');
const BACKEND = path.join(ROOT, 'backend');
const DIST = path.join(ROOT, 'frontend', 'dist');
const PY = process.env.TUNLION_TEST_VENV
  || (fs.existsSync(path.join(ROOT, '.venv', 'bin', 'python')) ? path.join(ROOT, '.venv', 'bin', 'python') : 'python3');
const PORT = 8271;
const BASE = `http://127.0.0.1:${PORT}`;

let backend = null;
let backendLogFd = null;
let logs = '';
const LOG_FILE = process.env.PEER_RELOAD_LOG_FILE || path.join(os.tmpdir(), 'tunlion-peer-reload.log');
function fail(msg) { console.error('[peer-reload] FAIL:', msg); cleanup(); process.exit(1); }
function ok(msg) { console.log('[peer-reload] OK:', msg); }
function cleanup() {
  try { backend && backend.kill('SIGKILL'); } catch {}
  try { if (backendLogFd != null) fs.closeSync(backendLogFd); } catch {}
  backendLogFd = null;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startBackend() {
  try { fs.writeFileSync(LOG_FILE, ''); } catch {}
  // Write straight to a file, not a pipe: the parent blocks in spawnSync while
  // the engine child runs, so a piped relay log would never reach the reader.
  backendLogFd = fs.openSync(LOG_FILE, 'a');
  backend = spawn(PY, ['app.py'], {
    cwd: BACKEND,
    env: {
      ...process.env, PORT: String(PORT), FIL_ASYNC_MODE: 'threading',
      FIL_CLAIM_LIMIT: '1000000', FIL_PING_TIMEOUT: '120', FIL_PING_INTERVAL: '25',
      FIL_SECRET: 'peer-reload-test-secret',
      // Same-origin only for the close beacon; the cross-origin test below
      // proves the endpoint refuses an otherwise-valid token from elsewhere.
      FIL_CORS_ORIGINS: BASE,
    },
    stdio: ['ignore', backendLogFd, backendLogFd],
  });
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

function telEvents() {
  // The engine runs in a child process; read the relay log the parent tees to
  // a file so both processes see the same TEL stream.
  let src = logs;
  try { if (fs.existsSync(LOG_FILE)) src = fs.readFileSync(LOG_FILE, 'utf8'); } catch {}
  return src.split(/\r?\n/).filter((l) => l.startsWith('TEL ')).map((l) => {
    try { return JSON.parse(l.slice(4)); } catch { return null; }
  }).filter(Boolean);
}

async function waitFor(fn, timeoutMs, label) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await fn()) return true;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${label}`);
}

// WebKit counts the signaling websocket as an open request, so networkidle
// never fires for the real app; wait for the rendered identity field instead.
async function nav(page, url) {
  const target = new URL(url);
  target.searchParams.set('test', '1'); // expose real link/timer diagnostics
  await page.goto(target.toString(), { waitUntil: 'domcontentloaded', timeout: 60000 });
  try {
    // waitForFunction is deliberate: a continuously-updating React root can
    // make Playwright's selector wait chase a replaced node, while "does the
    // identity field exist" is the actual condition this gate needs.
    await page.waitForFunction(
      () => !!document.querySelector('[data-testid="device-name-input"]'),
      null, { timeout: 60000 },
    );
    await page.locator('[data-testid="device-name-input"]').waitFor({ state: 'visible', timeout: 15000 });
  } catch (e) {
    const body = await page.locator('body').innerText().catch(() => '<no body>');
    console.log('[nav] app did not render at', url, 'body:', body.slice(0, 500));
    throw e;
  }
}

async function identity(page) {
  return page.evaluate(() => ({
    name: document.querySelector('[data-testid="device-name-input"]')?.value || '',
    uid: sessionStorage.getItem('tunlion.uid') || '',
    gen: document.documentElement.getAttribute('data-session-generation') || '',
    online: /online/i.test(document.body.innerText),
  }));
}

function peerRows(page, name) {
  return page.locator('[data-testid="peer-tile"]', {
    has: page.locator('b', { hasText: new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') }),
  });
}

async function waitPeerVisible(page, name, timeout = 25000) {
  await waitFor(async () => (await peerRows(page, name).count()) === 1, timeout, `peer ${name} visible`);
}

// A row saying "ready" means the real PeerLink reached connectionState
// connected; this is the live WebRTC assertion, not just "a name rendered".
async function waitPeerReady(page, name, timeout = 30000) {
  await waitFor(async () => {
    const row = peerRows(page, name).first();
    if ((await row.count()) !== 1) return false;
    if (!/\bready\b/i.test(await row.innerText().catch(() => ''))) return false;
    // `ready` is set from pc.connectionState too; prove a real DataChannel is
    // open. The ?test=1 hook exposes the live PeerLink map, not a mock.
    return page.evaluate((wanted) => {
      const links = window.__tunlionTestLinks;
      if (!links) return false;
      for (const link of links.values()) {
        if (link?.name === wanted && link?.channel?.readyState === 'open') return true;
      }
      return false;
    }, name);
  }, timeout, `peer ${name} ready with an OPEN data channel`);
}

async function ownerToken(page) {
  return page.evaluate(() => localStorage.getItem('tunlion.ownerToken') || '');
}

function closeCount(uid, gen) {
  return telEvents().filter((e) => e.ev === 'session-close' && e.uid === uid && e.gen === gen.slice(0, 8)).length;
}

async function postClose(ctx, body, headers = {}) {
  return ctx.request.post(`${BASE}/api/session/close`, { data: body, headers });
}

async function waitOnlineAndPeer(page, peerName, timeout = 30000) {
  await waitFor(async () => {
    const id = await identity(page);
    return id.online && (await peerRows(page, peerName).count()) >= 1;
  }, timeout, `page online with ${peerName}`);
}

async function waitOnline(page, timeout = 30000) {
  await waitFor(async () => (await identity(page)).online, timeout, 'page online');
}

async function runEngine(engine, browser, contextOptions) {
  const tag = `[${engine}]`;
  // Both engines take the FULL path: real peer row + ready WebRTC data
  // channel, not just "the page says online". Each engine runs in its own
  // child process so one engine's renderer memory cannot starve the other.
  const full = true;
  const trackPageshow = () => {
    window.__pageshowPersisted = false;
    window.addEventListener('pageshow', (e) => { if (e.persisted) window.__pageshowPersisted = true; });
  };
  let peerCtx = null;
  let peer = null;
  let peerName = null;
  if (full) {
    // A stand-in second device, in its own context so it has its own uid/name.
    peerCtx = await browser.newContext({ ...contextOptions, serviceWorkers: 'block' });
    await peerCtx.addInitScript(trackPageshow);
    peer = await peerCtx.newPage();
    peer.on('pageerror', (e) => console.log(tag, '[peer page-error]', String(e).slice(0, 300)));
    peer.on('console', (m) => { if (m.type() === 'error') console.log(tag, '[peer console]', m.text().slice(0, 300)); });
    await nav(peer, BASE);
    await waitOnline(peer);
    peerName = (await identity(peer)).name;
    if (!peerName) fail(`${tag} peer has no local device name`);
  }

  // The device under test. Its page load is generation 1.
  // Service-worker caching is orthogonal to session/reload correctness, and a
  // stale SW would make this gate flaky for the wrong reason.
  const devCtx = await browser.newContext({ ...contextOptions, serviceWorkers: 'block' });
  await devCtx.addInitScript(trackPageshow);
  const dev = await devCtx.newPage();
  dev.on('pageerror', (e) => console.log(tag, '[dev page-error]', String(e).slice(0, 300)));
  dev.on('console', (m) => { if (m.type() === 'error') console.log(tag, '[dev console]', m.text().slice(0, 300)); });
  await nav(dev, BASE);
  const devName = (await identity(dev)).name;
  if (!devName) fail(`${tag} device has no local device name`);
  if (full) {
    await waitOnlineAndPeer(dev, peerName);
    await waitPeerVisible(peer, devName);
    // Prove a REAL WebRTC data channel, not merely a rendered row.
    await waitPeerReady(dev, peerName);
    await waitPeerReady(peer, devName);
  } else {
    await waitOnline(dev);
  }
  const g1 = await identity(dev);
  if (!g1.gen) fail(`${tag} page has no session generation marker`);
  ok(`${tag} local name visible "${devName}"${peerName ? `, connected peer "${peerName}"` : ' and relay online'} (gen ${g1.gen.slice(0, 8)})`);

  // 1. A normal reload reconnects by itself and keeps the SAME device name/uid.
  await dev.reload({ waitUntil: 'domcontentloaded' });
  await dev.waitForSelector('[data-testid="device-name-input"]', { timeout: 60000 });
  if (full) { await waitOnlineAndPeer(dev, peerName); await waitPeerReady(dev, peerName); } else await waitOnline(dev);
  const g2 = await identity(dev);
  if (g2.uid !== g1.uid) fail(`${tag} reload changed the device uid (${g1.uid} -> ${g2.uid})`);
  if (g2.name !== devName) fail(`${tag} reload lost the device name (${devName} -> ${g2.name})`);
  if (g2.gen === g1.gen) fail(`${tag} reload reused the old session generation`);
  await sleep(1200);
  if (full) {
    const afterReloadRows = await peerRows(peer, devName).count();
    if (afterReloadRows !== 1) fail(`${tag} peer shows ${afterReloadRows} rows for the reloaded device, want 1`);
  }
  ok(`${tag} normal reload reconnects itself, same uid/name, new generation ${g2.gen.slice(0, 8)}${full ? ', no duplicate row' : ''}`);

  // 2. Two tabs for the same device: the new generation takes over at once and
  //    the old tab is told, instead of both sitting on a stale session.
  // Duplicate-tab case: the same per-tab uid (as a browser "Duplicate Tab"
  // does), while the shared device name already lives in localStorage.
  await devCtx.addInitScript(({ uid }) => {
    try { sessionStorage.setItem('tunlion.uid', uid); } catch {}
  }, { uid: g2.uid });
  const second = await devCtx.newPage();
  second.on('pageerror', (e) => console.log(tag, '[second page-error]', String(e).slice(0, 300)));
  second.on('console', (m) => { if (m.type() === 'error') console.log(tag, '[second console]', m.text().slice(0, 300)); });
  await nav(second, BASE);
  if (full) { await waitOnlineAndPeer(second, peerName, 45000); await waitPeerReady(second, peerName, 120000); } else await waitOnline(second);
  const g3 = await identity(second);
  if (g3.uid !== g2.uid) fail(`${tag} second tab did not carry the same device uid`);
  if (g3.gen === g2.gen) fail(`${tag} second tab reused the old generation`);
  await waitFor(async () => (await dev.locator('[data-testid="superseded-banner"]').count()) === 1, 15000,
    'old tab to show the superseded explanation');
  const oldBody = (await dev.locator('body').innerText()).toLowerCase();
  if (/clear (site )?data|reset (the )?browser/.test(oldBody)) fail(`${tag} superseded tab offers clear-data/reset`);
  await sleep(1000);
  if (full && (await peerRows(peer, devName).count()) !== 1) fail(`${tag} the peer shows a duplicate row after takeover`);
  const supersede = telEvents().filter((e) => e.ev === 'session-supersede' && e.uid === g2.uid);
  if (!supersede.length) fail(`${tag} relay did not log the generation supersede`);
  ok(`${tag} second tab took over (gen ${g3.gen.slice(0, 8)}); old tab explained${full ? ', peer still has one row' : ''}`);

  // 2b. A BFCache restore / token storage event must NOT resume the superseded
  //     tab. Only an explicit full reload may take over again.
  const oldGen8 = g2.gen.slice(0, 8);
  const oldJoinsBefore = telEvents().filter((e) => e.ev === 'join' && e.uid === g2.uid && e.gen === oldGen8).length;
  await dev.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await dev.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'tunlion.ownerToken', newValue: 'attacker-token' })));
  await sleep(1200);
  if ((await dev.locator('[data-testid="superseded-banner"]').count()) !== 1) fail(`${tag} a pageshow/storage event cleared the superseded banner`);
  const oldIdentity = await identity(dev);
  if (oldIdentity.online) fail(`${tag} a superseded tab came back online on pageshow/storage`);
  const oldJoinsAfter = telEvents().filter((e) => e.ev === 'join' && e.uid === g2.uid && e.gen === oldGen8).length;
  if (oldJoinsAfter !== oldJoinsBefore) fail(`${tag} a superseded tab replayed its retired generation (${oldJoinsBefore} -> ${oldJoinsAfter})`);
  if (full) { await waitOnlineAndPeer(second, peerName); await waitPeerReady(second, peerName); }
  ok(`${tag} pageshow/storage events leave the superseded tab suspended; the active tab stays owner`);

  // 3. A LATE close from the superseded generation must not drop the new link.
  const staleClose = await devCtx.request.post(`${BASE}/api/session/close`, { data: { uid: g2.uid, gen: g2.gen } });
  if (staleClose.status() !== 204) fail(`${tag} stale close endpoint returned ${staleClose.status()}`);
  await sleep(2500);
  if (full) await waitOnlineAndPeer(second, peerName, 10000); else await waitOnline(second, 10000);
  if (full && (await peerRows(peer, devName).count()) !== 1) fail(`${tag} stale close removed the replacement link`);
  // The normal reload's own pagehide can legitimately close generation 1; this
  // assertion is specifically that OUR late beacon for the superseded
  // generation 2 was refused.
  const closeEvents = telEvents().filter((e) => e.ev === 'session-close' && e.uid === g2.uid && e.gen === g2.gen.slice(0, 8));
  if (closeEvents.length) fail(`${tag} stale close was accepted by the relay: ${JSON.stringify(closeEvents)}`);
  ok(`${tag} a late close from the old generation is ignored; the new link stays up`);

  // 3b. The close endpoint is authenticated: no token, a wrong token, and a
  //     cross-origin request with the right token must all leave the session
  //     online. (The endpoint returns 204 either way, so the proof is state.)
  const owner = await ownerToken(second);
  if (!owner) fail(`${tag} the relay did not mint an ownership token for the browser`);
  const live = await identity(second);
  const closesBefore = closeCount(live.uid, live.gen);
  const attempts = [
    { data: { uid: live.uid, gen: live.gen } },
    { data: { uid: live.uid, gen: live.gen, token: 'attacker-token' } },
    { data: { uid: live.uid, gen: live.gen, token: owner }, headers: { Origin: 'https://evil.example' } },
  ];
  for (const a of attempts) {
    const r = await postClose(second.context(), a.data, a.headers);
    if (r.status() !== 204) fail(`${tag} close endpoint did not hide the refusal as 204: ${r.status()}`);
  }
  await sleep(1200);
  if (closeCount(live.uid, live.gen) !== closesBefore) fail(`${tag} an unauthenticated/wrong/cross-origin close was accepted`);
  if (full) await waitOnlineAndPeer(second, peerName, 10000); else await waitOnline(second, 10000);
  ok(`${tag} close endpoint refuses no-token, wrong-token and cross-origin calls; the live session stays up`);

  // 4. Renaming updates the SAME device (uid+generation), and the peer's row is
  //    relabeled in place — never a second pairing/row.
  const chosen = 'studio-ipad-' + engine.replace(/[^a-z]/g, '').slice(0, 6);
  const nameInput = second.getByLabel("This device's name", { exact: true });
  await nameInput.fill(chosen);
  await nameInput.press('Enter');
  if (full) {
    await waitFor(async () => (await peerRows(peer, chosen).count()) === 1, 15000, `peer to relabel the device to ${chosen}`);
  } else {
    await waitFor(() => telEvents().some((e) => e.ev === 'rename' && e.uid === g3.uid), 15000,
      'relay to log the in-place rename');
  }
  const g4 = await identity(second);
  if (g4.name !== chosen) fail(`${tag} chosen name not shown locally after rename`);
  if (g4.uid !== g3.uid || g4.gen !== g3.gen) fail(`${tag} rename changed the device identity or generation`);
  if (full) {
    if ((await peerRows(peer, chosen).count()) !== 1) fail(`${tag} rename created a duplicate peer row`);
    if ((await peerRows(peer, devName).count()) !== 0) fail(`${tag} old name still has a peer row after rename`);
  }
  // The other open tab shares localStorage but has a different uid; the
  // storage event must relabel it in place too.
  const devNameField = dev.getByLabel("This device's name", { exact: true });
  await waitFor(async () => (await devNameField.inputValue()) === chosen, 15000,
    'the other open tab to receive the rename storage event');
  ok(`${tag} rename relabeled the same device (${chosen}); other open tab updated${full ? ', one row' : ''}`);

  // 4b. A socket disconnect/reconnect must replay the CURRENT generation/name
  //     from the signaling cache. A stale cached gen would be retired and the
  //     open tab would be marked superseded.
  const beforeReconnect = await identity(second);
  const gen8 = beforeReconnect.gen.slice(0, 8);
  const retiredBefore = telEvents().filter((e) => e.ev === 'session-retired' && e.uid === g3.uid && e.gen === gen8).length;
  const joinsBefore = telEvents().filter((e) => e.ev === 'join' && e.uid === g3.uid && e.gen === gen8).length;
  // Drop only the signaling socket; the WebRTC links stay up, so a `ready`
  // assertion here measures the reconnect cache, not ICE/network emulation.
  await second.evaluate(() => window.__tunlionTestReconnect && window.__tunlionTestReconnect());
  await peer.evaluate(() => window.__tunlionTestReconnect && window.__tunlionTestReconnect());
  await sleep(500);
  if (full) {
    await waitOnlineAndPeer(second, peerName, 45000);
    await waitPeerReady(second, peerName, 120000);
    await waitFor(async () => {
      const now = await peerRows(peer, chosen).count();
      const old = await peerRows(peer, devName).count();
      return now === 1 && old === 0;
    }, 15000, 'the peer to relabel the reconnected device');
    await waitPeerReady(peer, chosen, 120000);
  } else {
    await waitOnline(second, 30000);
  }
  const afterReconnect = await identity(second);
  if (afterReconnect.gen !== beforeReconnect.gen) fail(`${tag} a socket reconnect changed the page generation`);
  if (afterReconnect.name !== chosen) fail(`${tag} a socket reconnect lost the chosen name`);
  const retiredAfter = telEvents().filter((e) => e.ev === 'session-retired' && e.uid === g3.uid && e.gen === gen8).length;
  const joinsAfter = telEvents().filter((e) => e.ev === 'join' && e.uid === g3.uid && e.gen === gen8).length;
  if (retiredAfter !== retiredBefore) fail(`${tag} reconnect retired the current generation (${retiredBefore} -> ${retiredAfter})`);
  if (joinsAfter <= joinsBefore) fail(`${tag} reconnect did not rejoin with the current generation (${joinsBefore} -> ${joinsAfter})`);
  ok(`${tag} socket reconnect after rename replays the current generation/name, not a retired one`);

  // 5. Reload the (renamed) current tab. Still one row, still connected.
  await second.reload({ waitUntil: 'domcontentloaded' });
  await second.waitForSelector('[data-testid="device-name-input"]', { timeout: 60000 });
  if (full) await waitOnlineAndPeer(second, peerName); else await waitOnline(second);
  const g5 = await identity(second);
  if (g5.name !== chosen) fail(`${tag} reload after rename lost the chosen name (${g5.name})`);
  if (g5.gen === g4.gen) fail(`${tag} reload after rename reused the generation`);
  await sleep(800);
  if (full && (await peerRows(peer, chosen).count()) !== 1) fail(`${tag} reload after rename produced duplicate rows`);
  ok(`${tag} reload after rename keeps the chosen name, new generation ${g5.gen.slice(0, 8)}${full ? ', one row' : ''}`);

  // 6a. The BFCache restore path itself, independent of whether this headless
  //     engine actually caches history entries: a persisted pageshow must
  //     rotate generation and revalidate, not replay the retired generation.
  const beforeBf = await identity(second);
  await second.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await waitFor(async () => (await identity(second)).gen !== beforeBf.gen, 15000, 'pageshow(persisted) to rotate generation');
  if (full) { await waitOnlineAndPeer(second, peerName, 45000); await waitPeerReady(second, peerName, 120000); } else await waitOnline(second);
  ok(`${tag} persisted pageshow rotates the session generation and revalidates`);

  // 6a-b. Force a real socket disconnect/reconnect AFTER that rotation. The
  //       reconnect cache must carry the rotated gen; replaying the retired one
  //       would be refused as superseded.
  const bf = await identity(second);
  const bfGen = bf.gen.slice(0, 8);
  const bfRetiredBefore = telEvents().filter((e) => e.ev === 'session-retired' && e.uid === bf.uid && e.gen === bfGen).length;
  const bfJoinsBefore = telEvents().filter((e) => e.ev === 'join' && e.uid === bf.uid && e.gen === bfGen).length;
  await second.evaluate(() => window.__tunlionTestReconnect && window.__tunlionTestReconnect());
  await peer.evaluate(() => window.__tunlionTestReconnect && window.__tunlionTestReconnect());
  await sleep(500);
  if (full) { await waitOnlineAndPeer(second, peerName, 45000); await waitPeerReady(second, peerName, 120000); } else await waitOnline(second, 45000);
  const bfRetiredAfter = telEvents().filter((e) => e.ev === 'session-retired' && e.uid === bf.uid && e.gen === bfGen).length;
  const bfJoinsAfter = telEvents().filter((e) => e.ev === 'join' && e.uid === bf.uid && e.gen === bfGen).length;
  if (bfRetiredAfter !== bfRetiredBefore) fail(`${tag} post-pageshow reconnect retired the current generation`);
  if (bfJoinsAfter <= bfJoinsBefore) fail(`${tag} post-pageshow reconnect did not rejoin with the current generation`);
  ok(`${tag} socket reconnect after pageshow rotation replays the new generation`);

  // 6b. Back/forward. If this engine uses BFCache we get pageshow(persisted) and
  //    the page rotates generation; if not, it is an ordinary fresh load. Both
  //    must come back connected, and neither may reuse a retired generation.
  await nav(second, `${BASE}/?nav=1`);
  await waitFor(async () => /online/i.test(await second.locator('body').innerText()), 20000, 'nav page online');
  const gNav = await identity(second);
  await second.goBack({ waitUntil: 'domcontentloaded' });
  await second.waitForSelector('[data-testid="device-name-input"]', { timeout: 60000 });
  if (full) await waitOnlineAndPeer(second, peerName); else await waitOnline(second);
  const gBack = await identity(second);
  if (gBack.gen === gNav.gen || gBack.gen === g5.gen) fail(`${tag} back/forward reused a retired generation`);
  const persisted = await second.evaluate(() => window.__pageshowPersisted || false);
  ok(`${tag} back/forward returned connected with a fresh generation (${persisted ? 'bfcache pageshow' : 'full load'})`);

  const finalBody = (await second.locator('body').innerText()).toLowerCase();
  if (/clear (site )?data|reset (the )?browser/.test(finalBody)) fail(`${tag} UI offers a clear-data/reset path`);

  // 7. The authenticated close path still works for the live generation.
  const finalId = await identity(second);
  const finalToken = await ownerToken(second);
  const beforeAuthClose = closeCount(finalId.uid, finalId.gen);
  const okClose = await postClose(second.context(), { uid: finalId.uid, gen: finalId.gen, token: finalToken },
    { Origin: BASE });
  if (okClose.status() !== 204) fail(`${tag} authenticated close returned ${okClose.status()}`);
  await waitFor(() => closeCount(finalId.uid, finalId.gen) === beforeAuthClose + 1, 10000,
    'the authenticated close to be applied');
  ok(`${tag} the owner's authenticated close is applied`);

  // 8. pagehide clears page-owned timers (config refresh + pairing/waitUp/
  //    second-wind/helper slots), not only PeerLink timers.
  const timersBefore = await second.evaluate(() => {
    window.__tunlionArmTimers?.();
    return window.__tunlionTimerStats && window.__tunlionTimerStats();
  });
  if (!timersBefore) fail(`${tag} timer inventory missing`);
  for (const [name, on] of Object.entries(timersBefore)) {
    if (!on) fail(`${tag} timer ${name} was not running before pagehide`);
  }
  await second.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
  await sleep(250);
  const timersAfter = await second.evaluate(() => ({
    stats: window.__tunlionTimerStats && window.__tunlionTimerStats(),
    released: window.__tunlionTimersReleased,
  }));
  for (const [name, on] of Object.entries(timersAfter.stats || {})) {
    if (on) fail(`${tag} pagehide left a page timer running: ${name}`);
  }
  if (!timersAfter.released?.waitUp || !timersAfter.released?.pairCreate) {
    fail(`${tag} pagehide did not resolve the waitUp/pair-create promises`);
  }
  ok(`${tag} pagehide clears and resolves all page-owned timers`);

  await second.close();
  await dev.close();
  if (peer) await peer.close();
  await devCtx.close();
  if (peerCtx) await peerCtx.close();
  return { name: devName };
}

const IPAD = devices['iPad (gen 7)'] || {
  viewport: { width: 810, height: 1080 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
  userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
};

async function runOne(engine) {
  if (engine === 'chromium') {
    const b = await chromium.launch({ headless: true });
    try { await runEngine('chromium', b, { viewport: { width: 1200, height: 900 } }); }
    finally { await b.close(); }
    return;
  }
  const b = await webkit.launch({ headless: true });
  try { await runEngine('webkit-ipad', b, { ...IPAD }); }
  finally { await b.close(); }
}

(async () => {
  if (!fs.existsSync(path.join(DIST, 'index.html'))) fail('frontend/dist not built — run `VITE_TUNLION_API= npm run build` in frontend/');

  // Each engine runs in its own Node process. A single process that has already
  // launched Chromium leaves its renderer memory around, which makes the WebKit
  // iPad pass fail for an environmental reason (OOM/slow first paint) rather
  // than a product one. The parent owns the relay; the children only browse.
  if (process.env.PEER_RELOAD_CHILD) {
    await runOne(process.env.PEER_RELOAD_CHILD);
    console.log(`\n[peer-reload] ${process.env.PEER_RELOAD_CHILD} PASSED`);
    process.exit(0);
  }

  startBackend();
  if (!await waitHealth(30000)) fail('backend did not come up at ' + BASE);

  // PEER_RELOAD_ENGINES=chromium|webkit runs one engine while debugging.
  const only = (process.env.PEER_RELOAD_ENGINES || 'chromium,webkit').split(',').map((s) => s.trim());
  for (const engine of only) {
    const r = spawnSync(process.execPath, [__filename], {
      env: { ...process.env, PEER_RELOAD_CHILD: engine, PEER_RELOAD_ENGINES: '', PEER_RELOAD_LOG_FILE: LOG_FILE },
      stdio: 'inherit',
      timeout: 9 * 60 * 1000,
    });
    if (r.status !== 0) fail(`${engine} child exited with ${r.status === null ? `signal ${r.signal}` : `code ${r.status}`}`);
  }

  cleanup();
  console.log('\n[peer-reload] ALL CHECKS PASSED');
  process.exit(0);
})().catch((e) => { console.error('[peer-reload] ERROR:', e && e.stack || String(e)); cleanup(); process.exit(1); });
