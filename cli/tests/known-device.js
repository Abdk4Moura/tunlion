// Gate 16: known-device rendezvous, the browser half of C12/C20/C27.
//
// Phase 1: a real Chromium tab receives a `send --word --remember` sender's
// code in the "Receive a file" box. C27: remembering needs HUMAN consent. The
// "asks to be remembered" banner appears, nothing may be stored before its
// Remember button is clicked, and the secret must be stored after it.
//
// Phase 2: a brand-new CLI session runs `send --to <name> --room <isolated>`,
// with NO shared room and NO code. The only way it can find this tab is the
// secret-derived presence channel. The offer arriving here proves the whole
// chain: consent -> store -> subscribe -> known-peer -> link -> proof. The
// known device is recognised, not added twice: one stored record, one row.
//
// Phase 3 (decline): a third sender offers to be remembered and we click
// "Not now". The pair-keep-ack{ok:false} must make THAT sender discard its
// half (gates.sh asserts its log and the device store), and the browser must
// store nothing for it.
//
// Usage: node known-device.js <app-url> <code> <decline-code-or-@logfile>
//
// L1-a: a `send --word` mints its OWN numeric nameplate, so the browser must
// claim the FULL minted `word-word-NNNN` code (not the spoken phrase). <code> is
// that minted phase-1 code. The phase-3 decline sender is started AFTER this
// harness launches, so its code is not known up front: pass `@<logfile>` and we
// poll that sender's log for the minted code right before phase 3.
const { chromium } = require('playwright');
const fs = require('node:fs');

const KNOWN = 'filament-known-devices';
let failDump = async () => {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function resolveDeclineCode(arg) {
  if (!arg) return undefined;
  if (!arg.startsWith('@')) return arg; // a literal code
  const logPath = arg.slice(1);
  // Poll the decline sender's log for its minted `word-word-NNNN` code.
  for (let i = 0; i < 100; i++) {
    try {
      const txt = fs.readFileSync(logPath, 'utf8');
      const m = txt.match(/[a-z]+-[a-z]+-[0-9]{3,5}/i);
      if (m) return m[0].toLowerCase();
    } catch { /* not created yet */ }
    await sleep(300);
  }
  throw new Error('decline sender never minted a code');
}

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:8077/';
  const code = process.argv[3];
  const declineArg = process.argv[4];
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  // KD_DEBUG=1: the app's own trace log, printed if the gate fails.
  if (process.env.KD_DEBUG) await ctx.addInitScript(() => { try { localStorage.setItem('tunlionLog', 'trace'); } catch {} });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  const trace = [];
  page.on('console', (m) => trace.push(`${new Date().toISOString().slice(11, 23)} ${m.type()}: ${m.text().slice(0, 300)}`));
  failDump = async () => {
    console.log('[pw] page text at failure:\n' + (await page.innerText('body').catch(() => '')).slice(0, 1500));
    console.log('[pw] last console lines:\n' + trace.slice(-120).join('\n'));
  };
  const known = () => page.evaluate((k) => { try { return JSON.parse(localStorage.getItem(k) || '[]') } catch { return [] } }, KNOWN);
  const names = async () => (await known()).map((d) => d.name);

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  // The one code box on Home (Tunlion.jsx): a two-mode toggle, a labelled
  // input and Connect. Matched by role and exact label, as a person sees it.
  const enterCode = async (c) => {
    await page.getByRole('radio', { name: 'Receive a file' }).click();
    await page.getByLabel('Enter a code').fill(c);
    await page.getByRole('button', { name: 'Connect', exact: true }).click();
  };
  // The "asks to be remembered" banner (role=region, "Remember this device?").
  const banner = page.getByRole('region', { name: 'Remember this device?' }).first();
  const accept = page.getByRole('button', { name: 'Accept', exact: true });
  const save = page.getByRole('button', { name: 'Save', exact: true });
  // Wait until `n` transfers are complete (a Save button each). A file sent to
  // the code this tab typed arrives without asking; an offer from a known
  // device shows Accept first. Click Accept whenever it is there.
  const completed = async (n, ms) => {
    const t = Date.now();
    while (Date.now() - t < ms) {
      if (await save.count() >= n) return;
      if (await accept.count()) await accept.first().click().catch(() => {});
      await sleep(300);
    }
    throw new Error(`transfer ${n} did not complete within ${ms / 1000} s`);
  };

  // ---- phase 1: claim, consent to remember, accept, complete --------------
  await enterCode(code);
  console.log('[pw] code submitted');

  await banner.waitFor({ timeout: 60000 });
  if ((await known()).length > 0) throw new Error('secret stored BEFORE consent');
  await banner.getByRole('button', { name: 'Remember', exact: true }).click();
  console.log('[pw] consent given');

  await page.waitForFunction((k) => {
    try { return JSON.parse(localStorage.getItem(k) || '[]').length > 0 } catch { return false }
  }, KNOWN, { timeout: 15000 });
  console.log('[pw] SECRET STORED', JSON.stringify(await names()));

  await completed(1, 60000);
  console.log('[pw] PHASE1 COMPLETE');
  // The claim parked this tab in the code's private room. Leave it, as a
  // person does once the file is in (and as this gate did before the redesign,
  // via "back to nearby"): the rendezvous below must find the tab by its
  // remembered secret alone, not through any room the two ever shared.
  const back = page.getByRole('button', { name: 'Back to people near you' });
  if (await back.count()) await back.first().click();

  // ---- phase 2: a fresh CLI session must find us with no room, no code ----
  // A SECOND completed transfer is a second Save button.
  await completed(2, 120000);
  // Recognised, not re-added: the sender that found us is the one record
  // phase 1 stored, and the page asked nothing about it this time.
  const after2 = await names();
  if (after2.length !== 1) throw new Error(`expected one remembered device after the rendezvous, found ${JSON.stringify(after2)}`);
  if (await banner.count()) throw new Error('the known device was asked to be remembered a second time');
  console.log('[pw] PHASE2 COMPLETE (channel rendezvous, no code)', JSON.stringify(after2));

  // ---- phase 3: decline a remember offer; the sender must discard ---------
  if (declineArg) {
    await sleep(6000); // let gates.sh start the decline sender (it mints its code)
    const declineCode = await resolveDeclineCode(declineArg);
    await enterCode(declineCode);
    await banner.waitFor({ timeout: 60000 });
    await banner.getByRole('button', { name: 'Not now', exact: true }).click();
    await sleep(2500); // let the ack reach the sender
    const after3 = await names();
    if (after3.length !== 1) throw new Error(`a declined sender was stored: ${JSON.stringify(after3)}`);
    console.log('[pw] PHASE3 DECLINED');
  }

  await browser.close();
  process.exit(0);
})().catch(async (e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  await failDump();
  process.exit(1);
});
