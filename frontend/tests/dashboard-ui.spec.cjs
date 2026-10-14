// Dashboard UI gate: the BUILT dashboard bundle (cli/dashboard-dist, the exact
// bytes `tunlion dashboard` serves) in a real Chromium, against a stand-in API
// that keeps the daemon's rules (one-time secret traded for a session cookie).
// It FAILS when:
//   1. the secret in the #fragment does not sign in, or is left in the address
//      bar, or works a second time;
//   2. an ask's Accept does not send approve with the request's id, capability
//      and a duration;
//   3. Allow shell takes effect on the first click (it must confirm), or a
//      narrowing (Remove) does not say it applied;
//   4. Cut off on an online device does not confirm first;
//   5. Exposure does not list a high-risk item first;
//   6. a made invitation stays readable after "Copy and hide";
//   7. a nav control cannot be reached with Tab or shows no focus ring;
//   8. on a phone, the bottom nav targets are under 44 px;
//   9. any screen shows an em dash.
//
//   node frontend/tests/dashboard-ui.spec.cjs        (from the repo root)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const ROOT = path.resolve(__dirname, '..', '..');
const DIST = path.join(ROOT, 'cli', 'dashboard-dist');
const SHOT_DIR = path.join(__dirname, '.relay-shots');
const SECRET = 'ab'.repeat(32);
const NOW = 1792000000;

function fail(msg) { console.error('[dashboard-ui] FAIL:', msg); process.exit(1); }
function ok(msg) { console.log('[dashboard-ui] ok:', msg); }

function seed() {
  return {
    ok: true, now: NOW,
    me: { name: 'laptop', owner: true, identity: true },
    daemon: { running: true, answering: true },
    devices: [
      { name: 'web-vps', state: 'active', online: true, status: 'online', lastSeen: NOW - 5, caps: ['shell', 'transfer'] },
      { name: 'jane-phone', state: 'active', online: false, status: 'idle', lastSeen: NOW - 3600, caps: ['transfer'] },
      { name: 'old-phone', state: 'revoked', online: false, status: 'idle', lastSeen: NOW - 40 * 86400, caps: [] },
    ],
    perms: [
      { name: 'web-vps', tier: 'FLEET', caveats: [], caps: [
        { action: 'shell', resource: 'self', source: 'grant', valid_until: null, effective: true },
        { action: 'transfer', resource: 'self', source: 'fleet default', valid_until: null, effective: true }] },
      { name: 'jane-phone', tier: 'EXTERNAL', caveats: [], caps: [
        { action: 'transfer', resource: 'self', source: 'enrolment ceiling', valid_until: NOW + 2 * 86400, effective: true }] },
      { name: 'old-phone', tier: 'EXTERNAL', caveats: [], caps: [] },
    ],
    requests: [{ id: 7, peer: 'jane-phone', capability: 'shell', ago: '3m ago' }],
    history: ['2026-10-14 07:13:37 web-vps opened a shell', '2026-10-14 08:15:02 received notes.txt from jane-phone'],
  };
}

function startServer() {
  const state = { used: false, token: 'tok' + Math.random().toString(36).slice(2), data: seed(), acts: [] };
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
  const srv = http.createServer((req, res) => {
    const send = (code, body, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...extra }); res.end(JSON.stringify(body)); };
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const url = req.url.split('?')[0];
      if (req.method === 'GET' && !url.startsWith('/api/')) {
        const f = url === '/' ? 'dashboard.html' : url.slice(1);
        const p = path.join(DIST, path.basename(f));
        if (!fs.existsSync(p)) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { 'Content-Type': types[path.extname(p)] || 'application/octet-stream' });
        return res.end(fs.readFileSync(p));
      }
      if (url === '/api/session') {
        const s = (JSON.parse(body || '{}').secret) || '';
        if (state.used || s !== SECRET) return send(401, { ok: false, error: 'This link was already used. Run tunlion dashboard again for a new one.' });
        state.used = true;
        return send(200, { ok: true }, { 'Set-Cookie': `tl_dash=${state.token}; HttpOnly; SameSite=Strict; Path=/` });
      }
      const cookie = (req.headers.cookie || '').includes(`tl_dash=${state.token}`);
      if (!cookie) return send(401, { ok: false, error: 'Not signed in.' });
      if (url === '/api/state') return send(200, state.data);
      if (url === '/api/act') { const a = JSON.parse(body); state.acts.push(a); return send(200, { ok: true, exit: 0, message: '' }); }
      if (url === '/api/invite') { state.acts.push({ verb: 'invite', ...JSON.parse(body) }); return send(200, { ok: true, invitation: 'TUNLION-INVITATION-v1:SECRETMATERIALXYZ' }); }
      send(404, { ok: false });
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ srv, state, port: srv.address().port })));
}

(async () => {
  for (const f of ['dashboard.html', 'dashboard.js', 'dashboard.css']) if (!fs.existsSync(path.join(DIST, f))) fail(`cli/dashboard-dist/${f} missing`);
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const { srv, state, port } = await startServer();
  const base = `http://127.0.0.1:${port}`;
  const browser = await chromium.launch({ headless: true, ...(process.env.TUNLION_CHROMIUM ? { executablePath: process.env.TUNLION_CHROMIUM } : {}) });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, colorScheme: 'light' });
  const p = await ctx.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(String(e)));
  const shot = (n) => p.screenshot({ path: path.join(SHOT_DIR, `dashboard-${n}.png`), fullPage: false });
  const noEmDash = async (where) => { const t = await p.evaluate(() => document.body.innerText); if (/[—–]/.test(t)) fail(`em or en dash on ${where}`); };

  // 1. sign in, fragment cleared
  await p.goto(`${base}/#k=${SECRET}`);
  await p.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 15000 });
  if (p.url().includes('#')) fail(`the secret is still in the address bar: ${p.url()}`);
  ok('signed in with the fragment secret; address bar cleared');
  await shot('overview'); await noEmDash('overview');

  // 2. accept an ask
  await p.getByTestId('ask-accept').first().click();
  await p.waitForTimeout(300);
  const ap = state.acts.find((a) => a.verb === 'approve');
  if (!ap || ap.id !== 7 || ap.cap !== 'shell' || ap.for !== '1d') fail(`approve sent ${JSON.stringify(ap)}`);
  ok('Accept sends approve with id, capability and duration');

  // 3. device page: Allow shell confirms; Remove says applied
  await p.getByRole('button', { name: 'Devices and people', exact: true }).click();
  await p.getByRole('button', { name: /jane-phone/ }).first().click();
  await p.getByRole('heading', { name: 'jane-phone', exact: true }).waitFor();
  const before = state.acts.length;
  await p.getByRole('button', { name: 'Allow shell' }).first().click();
  await p.waitForTimeout(200);
  if (state.acts.length !== before) fail('Allow shell took effect without a confirm');
  if (!(await p.getByText(/A shell lets jane-phone do anything you can/).count())) fail('no shell warning before granting');
  await p.getByRole('button', { name: 'Allow shell' }).last().click();
  await p.waitForTimeout(300);
  const g = state.acts[state.acts.length - 1];
  if (!(g.verb === 'grant' && g.device === 'jane-phone' && g.cap === 'shell')) fail(`grant sent ${JSON.stringify(g)}`);
  if (!(await p.getByText(/Applied on laptop/).count())) fail('a grant did not say it applied on this device');
  ok('Allow shell confirms first, then applies on this device');
  await shot('device'); await noEmDash('device page');

  // 4. cut off an online device confirms
  await p.getByRole('button', { name: 'Devices and people', exact: true }).click();
  await p.getByRole('button', { name: /web-vps/ }).first().click();
  await p.getByRole('heading', { name: 'web-vps', exact: true }).waitFor();
  const n4 = state.acts.length;
  await p.getByTestId('cut').click();
  await p.waitForTimeout(200);
  if (state.acts.length !== n4) fail('Cut off on an online device took effect without a confirm');
  if (!(await p.getByText(/is online now/).count())) fail('Cut off on an online device does not say it is online');
  await p.getByRole('button', { name: 'Cut off and close' }).click();
  await p.waitForTimeout(300);
  if (state.acts[state.acts.length - 1].verb !== 'cut') fail('confirmed cut off was not sent');
  ok('Cut off on an online device confirms first');

  // 5. exposure riskiest first
  await p.locator('nav[aria-label=Dashboard]').getByRole('button', { name: /^Exposure/ }).click();
  await p.getByRole('heading', { name: 'Exposure', exact: true }).waitFor();
  const risks = await p.$$eval('[data-testid=exposure-item]', (xs) => xs.map((x) => x.dataset.risk));
  if (!risks.length || risks[0] !== 'high') fail(`exposure order ${risks}`);
  ok(`exposure lists high first (${risks.join(',')})`);
  await shot('exposure'); await noEmDash('exposure');

  // 6. invitation shown once
  await p.getByRole('button', { name: 'Codes and invitations', exact: true }).click();
  await p.getByTestId('make-invite').click();
  await p.getByTestId('secret').waitFor();
  await shot('invitation');
  await p.getByRole('button', { name: 'Copy and hide' }).click();
  await p.waitForTimeout(200);
  if (await p.getByTestId('secret').count()) fail('the invitation is still shown after Copy and hide');
  if ((await p.evaluate(() => document.body.innerText)).includes('SECRETMATERIALXYZ')) fail('the invitation text is still in the page');
  ok('an invitation is shown once and hidden after copying');

  // 7. keyboard reach and focus ring
  await p.getByRole('button', { name: 'Overview', exact: true }).focus();
  await p.keyboard.press('Tab');
  const ring = await p.evaluate(() => { const e = document.activeElement; const s = getComputedStyle(e); return { tag: e.tagName, text: e.innerText, outline: s.outlineStyle, w: s.outlineWidth }; });
  if (ring.tag !== 'BUTTON' || ring.outline === 'none' || ring.w === '0px') fail(`focus after Tab: ${JSON.stringify(ring)}`);
  ok(`Tab moves to "${ring.text.split('\n')[0]}" with a visible ring`);

  // 1b. the secret works once
  const ctx2 = await browser.newContext();
  const p2 = await ctx2.newPage();
  await p2.goto(`${base}/#k=${SECRET}`);
  await p2.getByText('This link did not open the dashboard').waitFor({ timeout: 10000 });
  ok('a second use of the same link is refused');
  await ctx2.close();

  // 8. phone nav targets
  const ph = await browser.newContext({ viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
  const pp = await ph.newPage();
  await pp.addInitScript(() => {});
  await ph.addCookies([{ name: 'tl_dash', value: state.token, domain: '127.0.0.1', path: '/', httpOnly: true, sameSite: 'Strict' }]);
  await pp.goto(`${base}/`);
  await pp.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 15000 });
  const heights = await pp.$$eval('nav[aria-label=Dashboard] button', (bs) => bs.map((b) => b.getBoundingClientRect().height));
  if (!heights.length || heights.some((h) => h < 44)) fail(`phone nav heights ${heights}`);
  ok(`phone nav targets ${heights.map(Math.round).join(',')} px`);
  await pp.screenshot({ path: path.join(SHOT_DIR, 'dashboard-phone-dark.png') });
  await ph.close();

  if (errs.length) fail('page errors: ' + errs.join(' | '));
  await browser.close();
  srv.close();
  console.log('[dashboard-ui] PASS');
})().catch((e) => fail(e.stack || String(e)));
