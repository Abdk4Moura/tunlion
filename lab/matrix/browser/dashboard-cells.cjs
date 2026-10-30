// Dashboard cells of the launch matrix: the real `tunlion dashboard` served by
// a real daemon, driven in real Chromium.
//
//   node browser/dashboard-cells.cjs <outdir> [cell-regex]
//
// Env: LAB_HOST, CODESPACE, PLAYWRIGHT (as browser/cells.cjs).
//
// The dashboard listens on 127.0.0.1 inside a lab container and checks Host,
// Origin and (on Linux) the connecting user. To reach it from here with all of
// those intact, the SAME port is forwarded twice: here -> lab host (gh codespace
// ssh -L) and lab host -> the container's loopback (ssh to an sshd running as
// the same user, so the connection the dashboard sees comes from that user).
'use strict';
const fs = require('fs'), path = require('path'), cp = require('child_process');
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const OUT = process.argv[2], FILTER = new RegExp(process.argv[3] || '.');
const PORT = 17420, DASH = 'mx-dash', INV = 'mx-dinv', CODE_BOX = 'mx-dcode';
fs.mkdirSync(path.join(OUT, 'ev'), { recursive: true });
const RES = path.join(OUT, 'dashboard.jsonl'); fs.writeFileSync(RES, '');
const lab = (cmd, opt = {}) => cp.execSync(`${process.env.LAB_HOST} ${JSON.stringify(cmd)}`, { encoding: 'utf8', timeout: opt.timeout || 180000 });
const on = (c) => (script, opt = {}) => cp.execSync(`${process.env.LAB_HOST} "docker exec -i ${c} bash -l -s"`, { input: script + '\n', encoding: 'utf8', timeout: opt.timeout || 180000 });
const tryOn = (c) => (script, opt) => { try { return { out: on(c)(script, opt), rc: 0 }; } catch (e) { return { out: (e.stdout || '') + (e.stderr || ''), rc: e.status }; } };
const dash = on(DASH), inv = on(INV), dc = on(CODE_BOX), tryDc = tryOn(CODE_BOX);
const CODE = /\b[a-z]+-[a-z]+(?:-[a-z]+)?-\d{2,5}\b/;

let ev; const say = (...a) => fs.appendFileSync(ev, a.join(' ') + '\n');
function assert(c, what) { say((c ? 'ok   ' : 'FAIL ') + what); if (!c) throw new Error(what); }
async function shot(p, name) { await p.screenshot({ path: path.join(OUT, 'ev', name + '.png') }); say('screenshot ev/' + name + '.png'); }
async function cell(id, feature, fn) {
  if (!FILTER.test(id)) return;
  ev = path.join(OUT, 'ev', id + '.log'); fs.writeFileSync(ev, '');
  const t0 = Date.now(); let result = 'pass';
  try { await fn(); } catch (e) { result = 'fail'; say('error:', e.stack || e); }
  fs.appendFileSync(RES, JSON.stringify({ cell: id, pair: 'dashboard', feature, result, seconds: Math.round((Date.now() - t0) / 1000), evidence: `ev/${id}.log` }) + '\n');
  console.log(result.padEnd(5), id.padEnd(8), feature);
}
const caps = (name) => dash(`tunlion devices --caps ${name} 2>&1`);
// The owner's record of a device, parsed (null when there is none).
const recordOf = (name) => {
  let j; try { j = JSON.parse(dash('tunlion devices --json')); } catch { return null; }
  const list = Array.isArray(j) ? j : ((j.data && j.data.devices) || j.devices || []);
  return list.find((d) => d.name === name) || null;
};
// Debug logging on the dashboard (inherited by its `add` children) and on the
// claiming terminal, always: a pairing that ends without the peer's certificate
// says why only at debug level ("pair: identity-expose ... refused: <check>",
// "pair: completing without the peer's certificate"), and the 0.9.2 run that
// hit it once had no such evidence to read. It lands in the cell evidence only.
const DEBUG = 'TUNLION_LOG=debug ';
const stateOf = (name) => { const m = dash('tunlion devices --json').match(new RegExp(`"name":"${name}"[^}]*?"state":"([a-z]+)"|"state":"([a-z]+)"[^}]*?"name":"${name}"`)); return m && (m[1] || m[2]); };

(async () => {
  // Machines: the owner serving the dashboard, and two that will join it.
  for (const c of [DASH, INV, CODE_BOX]) lab(`~/matrix/box.sh up ${c}`);
  dash(`tunlion init --name dash --no-background --recovery-file ~/.r -y >/dev/null && tunlion up --detach >/dev/null && echo ok`);
  dc(`tunlion init --name dcode --no-background --recovery-file ~/.r -y >/dev/null && tunlion up --detach >/dev/null && echo ok`);
  // sshd as sam inside the owner container, keyed from the lab host.
  lab(`docker exec -u0 ${DASH} mkdir -p /run/sshd; test -f ~/.ssh/mxdash || ssh-keygen -q -t ed25519 -f ~/.ssh/mxdash -N ''`);
  const pub = lab('cat ~/.ssh/mxdash.pub').trim();
  dash(`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${pub}' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys; test -f hk || ssh-keygen -q -t ed25519 -f hk -N ''; /usr/sbin/sshd -p 2222 -h $PWD/hk -o PidFile=$PWD/sshd.pid 2>/dev/null; echo sshd`);
  const ip = lab(`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${DASH}`).trim();
  // A control socket, so the tunnel is closed by name of socket, never by pkill.
  lab(`ssh -S ~/.ssh/mxdash.sock -O exit x 2>/dev/null; ssh -M -S ~/.ssh/mxdash.sock -i ~/.ssh/mxdash -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -fN -L 127.0.0.1:${PORT}:127.0.0.1:${PORT} -p 2222 sam@${ip} && echo tunnel`);
  // A Codespace lab host needs a second hop to this workstation; a local lab
  // host (a CI runner) already has the tunnel's port.
  const fwd = process.env.CODESPACE
    ? cp.spawn('gh', ['codespace', 'ssh', '-c', process.env.CODESPACE, '--', '-N', '-o', 'ExitOnForwardFailure=yes', '-L', `${PORT}:127.0.0.1:${PORT}`], { stdio: 'ignore' })
    : null;
  await new Promise(r => setTimeout(r, fwd ? 8000 : 1000));
  dash(`(${DEBUG}nohup tunlion dashboard --no-open --port ${PORT} > dash.out 2>&1 &) ; sleep 3; cat dash.out`);
  const url = (dash('cat dash.out').match(/http:\/\/127\.0\.0\.1:\d+\/#k=[0-9a-f]+/) || [])[0];
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1280, height: 860 } });
  const p = await ctx.newPage();
  const errs = []; p.on('pageerror', e => errs.push(String(e)));
  // Nav buttons carry a count badge ("Asks 1"), so match the label at the start.
  const nav = (name) => p.getByRole('button', { name: new RegExp(`^${name}\\b`) }).first().click();

  await cell('D01', 'sign in once with the printed link; a second use is refused', async () => {
    say('url', url ? url.replace(/k=[0-9a-f]+/, 'k=<secret>') : 'none'); assert(url, 'dashboard printed a link');
    await p.goto(url);
    await p.getByRole('heading', { name: 'Overview', exact: true }).waitFor({ timeout: 20000 });
    assert(!p.url().includes('#k='), 'the secret is cleared from the address bar');
    await shot(p, 'd01-overview');
    const c2 = await b.newContext(); const p2 = await c2.newPage();
    await p2.goto(url); const refused = await p2.getByText('This link did not open the dashboard').waitFor({ timeout: 10000 }).then(() => true, () => false);
    await c2.close(); assert(refused, 'a second use of the same link is refused');
  });

  await cell('D02', 'make an invitation, another machine joins it', async () => {
    await nav('Codes and invitations');
    await p.getByLabel('Name').first().fill('dinv');
    await p.getByTestId('make-invite').click();
    await p.getByTestId('secret').waitFor({ timeout: 20000 });
    const text = (await p.getByTestId('secret').innerText()).trim();
    assert(text.length > 40, 'the invitation is shown');
    await shot(p, 'd02-invitation');
    on(INV)(`umask 077; cat > inv.txt <<'EOF'\n${text}\nEOF\necho saved`);
    const r = tryOn(INV)(`tunlion join inv.txt -y && tunlion up --detach >/dev/null; echo JOIN=$?`); say(r.out);
    assert(/JOIN=0/.test(r.out), 'the other machine joined with it');
    await nav('Devices and people'); await p.waitForTimeout(3000);
    assert(await p.getByRole('button', { name: /dinv/ }).count() > 0, 'the new device is listed in the dashboard');
  });

  await cell('D04', 'cut off, then restore', async () => {
    await nav('Devices and people');
    await p.getByRole('button', { name: /dinv/ }).first().click();
    await p.getByTestId('cut').click();
    // The confirm appears only while the device is online, and it renders after
    // the click: waiting for it (or the cut taking effect) instead of counting
    // once, which raced the render and skipped the confirm.
    const confirm = p.getByRole('button', { name: /^Cut off/ }).last();
    let st = stateOf('dinv');
    for (let i = 0; i < 30 && st !== 'revoked'; i++) {
      if (await confirm.count() && await confirm.isVisible().catch(() => false)) await confirm.click().catch(() => {});
      await p.waitForTimeout(500);
      st = stateOf('dinv');
    }
    say('state', st); assert(st === 'revoked', 'the CLI shows dinv revoked');
    await shot(p, 'd04-cut');
    await p.getByRole('button', { name: 'Restore' }).first().click();
    st = stateOf('dinv');
    for (let i = 0; i < 30 && st !== 'active'; i++) { await p.waitForTimeout(500); st = stateOf('dinv'); }
    say('state', st); assert(st === 'active', 'the CLI shows dinv active again');
  });

  // One dashboard code, claimed by `tunlion join` on box `c` (which holds its
  // own identity, so the owner must end up holding its certificate: EXTERNAL
  // with a cert, never NEEDS REVIEW / no certificate).
  const dashCode = async (name, c, shotName) => {
    await nav('Codes and invitations');
    await p.getByLabel('Name').last().fill(name);
    await p.getByTestId('show-code').click();
    await p.getByTestId('code').waitFor({ timeout: 20000 });
    const code = ((await p.getByTestId('code').innerText()).match(CODE) || [])[0]; say('code', code); assert(code, 'a code is shown');
    if (shotName) await shot(p, shotName);
    const t0 = Date.now();
    const r = tryOn(c)(`${DEBUG}timeout 90 tunlion join ${code} 2>&1; echo JOIN=$?`, { timeout: 120000 }); say(r.out);
    say(`join took ${((Date.now() - t0) / 1000).toFixed(1)} s`);
    assert(/JOIN=0/.test(r.out), 'the terminal joined with the code');
    const inNow = await p.getByText(new RegExp(`${name} is in`)).waitFor({ timeout: 20000 }).then(() => true, () => false);
    // What the dashboard's own `add` said: the owner half of the ceremony.
    const st = await p.evaluate(async () => (await (await fetch('/api/code')).json()));
    say('owner side said:', (st && st.done && st.done.message) || JSON.stringify(st).slice(0, 400));
    assert(inNow, 'the dashboard says it is in');
    const rec = recordOf(name); say('owner record:', JSON.stringify(rec));
    assert(rec && rec.certExpires, `the owner holds ${name}'s certificate (not "no certificate")`);
    const again = p.getByRole('button', { name: 'Another code' });
    if (await again.count()) await again.first().click();
  };

  await cell('D05', 'a pairing code from the dashboard, joined from a terminal', async () => {
    await dashCode('dcode', CODE_BOX, 'd05-code');
  });

  // MX_DASH_REPEATS=N: N more dashboard codes, each claimed by a fresh box
  // with its own identity. The cell fails if any claim leaves the owner
  // without that box's certificate.
  const repeats = Number(process.env.MX_DASH_REPEATS || 0);
  if (repeats > 0) await cell('D05r', `${repeats} more dashboard codes, each claimed by a fresh machine`, async () => {
    const box = 'mx-dcode-r'; let bad = 0;
    for (let i = 1; i <= repeats; i++) {
      say(`--- round ${i}`);
      lab(`~/matrix/box.sh up ${box}`);
      on(box)(`tunlion init --name dr${i} --no-background --recovery-file ~/.r -y >/dev/null && tunlion up --detach >/dev/null && echo ok`);
      // MX_DASH_NETEM (e.g. "delay 200ms 150ms loss 8%"): impair the claimer's
      // link (its host-side veth, so signaling and WebRTC both) to reach the
      // slow-ceremony timings a busy production run sees. Needs sudo on the lab host.
      if (process.env.MX_DASH_NETEM) {
        const idx = lab(`docker exec ${box} cat /sys/class/net/eth0/iflink`).trim();
        const veth = (lab('ip -o link').split('\n').find((l) => l.startsWith(idx + ': ')) || '').split(': ')[1].split('@')[0];
        say('netem on', veth, lab(`sudo tc qdisc replace dev ${veth} root netem ${process.env.MX_DASH_NETEM} && tc qdisc show dev ${veth}`).trim());
      }
      try { await dashCode(`dr${i}`, box); say(`round ${i} pass`); }
      catch (e) { bad++; say(`round ${i} FAIL ${e.message}`); const again = p.getByRole('button', { name: /Another code|Cancel this code/ }); if (await again.count()) await again.first().click().catch(() => {}); }
      if (process.env.MX_DASH_SPACING) await p.waitForTimeout(Number(process.env.MX_DASH_SPACING) * 1000);
    }
    lab(`~/matrix/box.sh down ${box}`);
    say(`${repeats - bad}/${repeats} rounds left the owner holding the certificate`);
    assert(bad === 0, 'every round left the owner holding the claimer\'s certificate');
  });

  await cell('D03', 'grant shell (confirmed), then remove it (device paired by code)', async () => {
    await nav('Devices and people');
    await p.getByRole('button', { name: /dcode/ }).first().click();
    await p.getByRole('heading', { name: 'dcode', exact: true }).waitFor();
    await p.getByRole('button', { name: 'Allow shell' }).first().click();
    assert(await p.getByText(/A shell lets dcode do anything you can/).count() > 0, 'a warning comes before granting shell');
    await p.getByRole('button', { name: 'Allow shell' }).last().click();
    await p.getByText(/Applied on dash/).first().waitFor({ timeout: 15000 });
    let c = caps('dcode'); say(c); assert(/shell\s+self\s+\S.*yes/.test(c), 'the CLI shows shell granted to dcode');
    await shot(p, 'd03-granted');
    await p.getByRole('button', { name: 'Remove shell' }).first().click();
    await p.waitForTimeout(3000);
    c = caps('dcode'); say(c); assert(!/shell\s+self\s+\S.*yes/.test(c), 'the CLI shows shell removed');
  });

  await cell('D06', 'approve an ask from the Asks screen', async () => {
    // A paired device without shell asks by being refused.
    const r = tryDc(`tunlion exec dash -- true; echo EXIT=$?`); say(r.out);
    assert(/EXIT=4/.test(r.out), 'exec without shell is refused (exit 4)');
    say('requests on dash:', dash('tunlion requests 2>&1'));
    await nav('Asks'); await p.waitForTimeout(3000);
    await p.reload(); await p.waitForTimeout(3000); await nav('Asks');
    const st = await p.evaluate(async () => { const r = await fetch('/api/state'); const j = await r.json(); return JSON.stringify({ requests: j.requests, asks: j.asks, daemon: j.daemon }).slice(0, 600); });
    say('state:', st); await shot(p, 'd06-asks');
    const ask = p.getByTestId('ask-accept').first();
    await ask.waitFor({ timeout: 20000 });
    await shot(p, 'd06-ask');
    await ask.click();
    await p.getByText(/Applied on dash/).first().waitFor({ timeout: 15000 });
    const r2 = tryDc(`tunlion exec dash -- echo APPROVED-$((40+2)); echo EXIT=$?`); say(r2.out);
    assert(/APPROVED-42/.test(r2.out), 'after Accept, the device runs a command');
  });

  await cell('D07', 'the dashboard closes when the background service stops', async () => {
    dash('tunlion down -y >/dev/null');
    let out = ''; for (let i = 0; i < 20 && !/dashboard closed/.test(out); i++) { await p.waitForTimeout(1000); out = dash('cat dash.out'); }
    say(out); assert(/the background service stopped, so the dashboard closed/.test(out), 'the dashboard says it closed');
    const alive = dash(`ss -ltn | grep -c ':${PORT} ' || true`).trim(); say('listening', alive);
    assert(alive === '0', 'nothing listens on the dashboard port any more');
  });

  if (errs.length) console.log('page errors:', errs.join(' | '));
  await b.close(); if (fwd) fwd.kill();
  lab(`ssh -S ~/.ssh/mxdash.sock -O exit x 2>/dev/null; ~/matrix/box.sh down ${DASH} ${INV} ${CODE_BOX}`);
})().catch(e => { console.error(e); process.exit(1); });
