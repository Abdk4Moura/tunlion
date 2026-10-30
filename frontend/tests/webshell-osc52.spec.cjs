// OSC 52 browser shell gate (tmux/vim yank -> device clipboard).
// Drives the REAL WebTerminal + xterm 6 + @xterm/addon-clipboard through the
// same fake PeerLink harness as webshell-scroll, and asserts the exact sequence
// a PTY would deliver. Device profiles per engine:
//   chromium: Android phone (touch, 412x915) and desktop (1280x800)
//   webkit:   iPad (touch, 1024x768), iPhone (touch, 390x844), desktop Safari
//
// It FAILS when:
//   1. a normal OSC 52 write (BEL or ST terminated, 'c' or the empty default
//      selection) does not reach the device clipboard;
//   2. a refused write does not show the tap prompt, or the trusted tap does
//      not perform the write, or success is claimed without it;
//   3. a refused tap is reported as success, or the prompt disappears silently;
//   4. an OSC 52 query ('?') reads the clipboard, sends any response to the
//      PTY, or otherwise exposes clipboard data;
//   5. PRIMARY ('p') or malformed/empty payloads overwrite or clear the device
//      clipboard;
//   6. an oversized payload is copied, or a large permitted payload is
//      truncated instead of waiting for a tap;
//   7. control characters from the remote are planted on the clipboard;
//   8. a later yank does not replace an earlier pending prompt.
//
//   node frontend/tests/webshell-osc52.spec.cjs
//   WEBSHELL_BROWSER=webkit node frontend/tests/webshell-osc52.spec.cjs
//
// Boundary: this is Safari's engine, not a physical iPad/iPhone. Playwright
// cannot reproduce iOS's real gesture policy or the system clipboard UI; the
// Clipboard API outcome is scripted. A real device check is still required.

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const { chromium, webkit } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const FRONT = path.resolve(__dirname, '..');
const PORT = 8264;
const BROWSER = (process.env.WEBSHELL_BROWSER || 'chromium').trim().toLowerCase();
if (BROWSER !== 'chromium' && BROWSER !== 'webkit') { console.error('unknown WEBSHELL_BROWSER=' + BROWSER); process.exit(1); }
let server = null;
const pageErrors = [];
let profile = '';

const IPAD_UA = 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const IPHONE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';
const PROFILES = BROWSER === 'webkit'
  ? [
      { name: 'ipad', width: 1024, height: 768, touch: true, ua: IPAD_UA },
      { name: 'iphone', width: 390, height: 844, touch: true, ua: IPHONE_UA },
      { name: 'desktop-safari', width: 1280, height: 800, touch: false },
    ]
  : [
      { name: 'android', width: 412, height: 915, touch: true, ua: ANDROID_UA },
      { name: 'desktop', width: 1280, height: 800, touch: false },
    ];

function fail(msg) { console.error(`[webshell-osc52] FAIL (${BROWSER}/${profile}):`, msg); try { server && server.close(); } catch (e) {} process.exit(1); }
function ok(msg) { console.log(`[webshell-osc52] OK (${profile}):`, msg); }
function eq(actual, expected, msg) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${msg}: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function build() {
  const out = path.join(__dirname, '.webshell-osc52-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'webshell-scroll-harness.jsx'), '--bundle', '--format=iife', `--outfile=${out}`,
      '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--loader:.css=text', '--define:import.meta.env={"VITE_TUNLION_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild failed: ' + (r.stderr || r.stdout));
  const b = fs.readFileSync(out);
  try { fs.unlinkSync(out); } catch (e) {}
  return b;
}

async function openPage(browser, p) {
  const page = await browser.newPage({
    viewport: { width: p.width, height: p.height },
    hasTouch: p.touch,
    ...(p.touch ? { isMobile: true, deviceScaleFactor: 2, userAgent: p.ua } : {}),
  });
  page.on('pageerror', (e) => { pageErrors.push(String(e)); console.log('[page-error]', String(e).slice(0, 400)); });
  await page.goto(`http://127.0.0.1:${PORT}/?preview=webshell-scroll&touch=${p.touch ? 1 : 0}`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.__webterm && window.__scroll, null, { timeout: 10000 })
    .catch(() => fail('WebTerminal / xterm never mounted'));
  await page.waitForFunction(() => {
    const ta = document.querySelector('.xterm-helper-textarea');
    return !!ta && document.activeElement === ta;
  }, null, { timeout: 5000 }).catch(() => fail('terminal helper textarea did not receive initial focus'));
  await page.waitForFunction(() => typeof window.__webtermRemoteQueries === 'function', null, { timeout: 5000 })
    .catch(() => fail('OSC 52 guard hook is missing'));
  return page;
}

// Scripted device clipboard. denyRemaining lets the automatic write fail and
// the later trusted tap succeed, which is exactly the iOS refusal path.
async function stubClipboard(page, { denyRemaining = 0, denyAll = false } = {}) {
  await page.evaluate(({ denyRemaining, denyAll }) => {
    window.__writes = [];
    window.__reads = 0;
    window.__copied = null;
    window.__denyRemaining = denyRemaining;
    window.__denyAll = !!denyAll;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: (text) => {
          let active = false;
          try { active = !!(navigator.userActivation && navigator.userActivation.isActive); } catch (e) {}
          window.__writes.push({ text, active });
          if (window.__denyAll || window.__denyRemaining > 0) {
            if (window.__denyRemaining > 0) window.__denyRemaining--;
            const err = new Error('denied');
            err.name = 'NotAllowedError';
            return Promise.reject(err);
          }
          window.__copied = text;
          return Promise.resolve();
        },
        readText: () => { window.__reads++; return Promise.resolve('DEVICE-SECRET'); },
      },
    });
  }, { denyRemaining, denyAll });
}

const writes = (page) => page.evaluate(() => window.__writes.map((w) => ({ text: w.text, active: w.active })));
const feed = (page, text) => page.evaluate((t) => window.__scroll.feedLink(t), text);
const sent = async (page) => (await page.evaluate(() => window.__scroll.inputs())).join('');

function b64(text) { return Buffer.from(text, 'utf8').toString('base64'); }
// tmux and vim both emit plain OSC 52 (tmux when set-clipboard is on/external).
// BEL is the common xterm terminator; ST is also accepted. '' is the default
// system selection, 'c' the explicit one, 'p' X11 PRIMARY.
function osc52(text, { sel = 'c', st = 'bel', raw = null } = {}) {
  const payload = raw === null ? b64(text) : raw;
  return `\x1b]52;${sel};${payload}` + (st === 'st' ? '\x1b\\' : '\x07');
}
// tmux allow-passthrough wraps an inner escape in DCS and doubles every ESC.
function tmuxPassthrough(seq) {
  return '\x1bPtmux;' + seq.replace(/\x1b/g, '\x1b\x1b') + '\x1b\\';
}
async function waitCopied(page, want, msg) {
  try {
    await page.waitForFunction((want) => window.__copied === want, want, { timeout: 4000 });
  } catch (e) { eq(await page.evaluate(() => window.__copied), want, msg); }
}
async function press(page, p, sel) {
  const loc = page.locator(sel);
  if (p.touch) await loc.tap(); else await loc.click();
}
async function promptVisible(page) {
  return page.locator('[data-testid="remote-copy-prompt"]').isVisible().catch(() => false);
}
async function toastText(page) {
  const loc = page.locator('[data-testid="term-toast"]');
  if (!(await loc.isVisible().catch(() => false))) return '';
  return (await loc.innerText()).trim();
}

async function runProfile(browser, p) {
  profile = p.name;
  const page = await openPage(browser, p);
  console.log(`[webshell-osc52] engine=${BROWSER} profile=${p.name} viewport=${p.width}x${p.height} touch=${p.touch}`);

  // 1. Direct copy: vim BEL form, explicit system selection.
  await stubClipboard(page, {});
  await feed(page, osc52('vim yank\nsecond line'));
  await waitCopied(page, 'vim yank\nsecond line', 'a normal OSC 52 yank must land on the device clipboard');
  const directWrites = await writes(page);
  eq(directWrites.length, 1, 'one automatic write');
  eq(directWrites[0].text, 'vim yank\nsecond line', 'the automatic write carries the yank');
  eq(await toastText(page), 'copied from remote', 'success is reported honestly');
  eq(await promptVisible(page), false, 'a successful copy needs no prompt');
  ok('copy: vim-style OSC 52 BEL reaches the clipboard');

  // 2. tmux ST form.
  await stubClipboard(page, {});
  await feed(page, osc52('tmux yank', { st: 'st' }));
  await waitCopied(page, 'tmux yank', 'an ST-terminated OSC 52 must land');
  ok('copy: tmux-style ST terminator reaches the clipboard');

  // 3. Empty selection means the default clipboard (same target as 'c').
  await stubClipboard(page, {});
  await feed(page, osc52('default selection', { sel: '' }));
  await waitCopied(page, 'default selection', 'an empty selection must use the default clipboard');
  ok('copy: empty selection is the default clipboard');

  // 4. PRIMARY and any other selection are not device clipboard targets.
  await stubClipboard(page, {});
  await feed(page, osc52('primary yank', { sel: 'p' }));
  await feed(page, osc52('clipboard yank', { sel: 's0' }));
  await wait(200);
  eq(await writes(page), [], 'PRIMARY/other selections must not touch the device clipboard');
  ok('copy: p and other selections are ignored');

  // 5. Query suppression: no read, no OSC 52 response on the PTY.
  await stubClipboard(page, {});
  const beforeQueries = await page.evaluate(() => window.__webtermRemoteQueries());
  await feed(page, osc52('', { raw: '?' }));
  await feed(page, osc52('', { raw: '?', st: 'st' }));
  await feed(page, tmuxPassthrough(osc52('', { raw: '?' })));
  await wait(300);
  eq(await page.evaluate(() => window.__reads), 0, 'an OSC 52 query must never read the device clipboard');
  eq(await page.evaluate(() => window.__webtermRemoteQueries()), beforeQueries + 3, 'all queries, including a tmux-wrapped one, must be consumed by the guard');
  eq(await sent(page), '', 'no OSC 52 query response may be sent to the PTY');
  eq(await writes(page), [], 'a query must not write either');
  ok('query: consumed, no read, no PTY response');

  // 6. Malformed and empty payloads never clear or corrupt the clipboard.
  await stubClipboard(page, {});
  await feed(page, osc52('', { raw: '!!!!' }));
  await feed(page, osc52('', { raw: '' }));
  await feed(page, '\x1b]52;c\x07'); // no Pd at all
  await wait(250);
  eq(await writes(page), [], 'malformed/empty Pd must not write or clear the clipboard');
  eq(await promptVisible(page), false, 'malformed input must not raise a prompt');
  ok('malformed: no junk write, no clipboard clear');

  // 6b. tmux allow-passthrough wraps the inner escape in a DCS and doubles its
  // ESC. xterm surfaces the inner OSC, so the same guard applies: this is the
  // real passthrough path, and it must still copy only the expected text.
  await stubClipboard(page, {});
  await feed(page, tmuxPassthrough(osc52('wrapped yank')));
  await waitCopied(page, 'wrapped yank', 'a tmux passthrough yank must reach the clipboard');
  eq((await writes(page)).length, 1, 'a tmux passthrough yank writes exactly once');
  ok('tmux passthrough: inner OSC 52 is unwrapped and handled by the same guard');

  // 7. Control characters are untrusted: refuse, do not plant them.
  await stubClipboard(page, {});
  await feed(page, osc52('safe\x1b[31mred'));
  await wait(250);
  eq(await writes(page), [], 'ESC in remote text must not reach the clipboard');
  eq(await toastText(page), 'remote copy blocked: control characters', 'control characters are reported honestly');
  ok('untrusted content: control characters are refused');

  // 8. Oversized wire payload is refused before decoding.
  await stubClipboard(page, {});
  await feed(page, osc52('x'.repeat(70 * 1024)));
  await wait(250);
  eq(await writes(page), [], 'a payload over the base64 wire cap must not be copied');
  eq(await toastText(page), 'remote copy too large', 'an oversized yank is reported honestly');
  eq(await promptVisible(page), false, 'an oversized yank gets no prompt');
  ok('bounds: oversized base64 payload is refused');

  // 9. Large permitted yank waits for a tap and is never truncated.
  const large = 'L'.repeat(9 * 1024);
  await stubClipboard(page, {});
  await feed(page, osc52(large));
  await page.locator('[data-testid="remote-copy-prompt"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('a large permitted yank did not open the tap prompt'));
  eq(await writes(page), [], 'a large yank must not auto-write');
  eq((await page.locator('[data-testid="remote-copy-prompt"]').innerText()).includes('Copied from the remote, tap to copy'), true,
    'the prompt uses the exact tap wording');
  await press(page, p, '[data-testid="remote-copy-now"]');
  await waitCopied(page, large, 'the tap must copy the whole large yank, not a truncated one');
  eq((await page.evaluate(() => window.__copied)).length, large.length, 'large yank length is preserved');
  eq(await promptVisible(page), false, 'prompt closes after the trusted tap succeeds');
  ok('bounds: 9 KiB yank prompts and copies in full on tap');

  // 10. Refused automatic write -> prompt -> trusted tap (the iOS path).
  await stubClipboard(page, { denyRemaining: 1 });
  await page.evaluate(() => {
    window.__trustedClick = null;
    document.addEventListener('click', (e) => {
      const b = e.target && e.target.closest && e.target.closest('[data-testid="remote-copy-now"]');
      if (b && window.__trustedClick === null) window.__trustedClick = e.isTrusted;
    }, true);
  });
  await feed(page, osc52('after gesture'));
  await page.locator('[data-testid="remote-copy-prompt"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('a refused automatic write did not show the tap prompt'));
  eq(await page.evaluate(() => window.__copied), null, 'a refused write must not claim a copy');
  eq((await page.locator('[data-testid="remote-copy-prompt"]').innerText()).includes('Copied from the remote, tap to copy'), true,
    'the refusal prompt uses the exact wording');
  await press(page, p, '[data-testid="remote-copy-now"]');
  await waitCopied(page, 'after gesture', 'the trusted tap must perform the clipboard write');
  eq(await page.evaluate(() => window.__trustedClick), true, 'the fallback write ran from a trusted click');
  eq(await promptVisible(page), false, 'the prompt closes after the write lands');
  eq(await toastText(page), 'copied from remote', 'the fallback reports success only after the write');
  const gestureWrites = await writes(page);
  eq(gestureWrites.length, 2, 'one automatic attempt plus one tap write');
  eq(gestureWrites[1].text, 'after gesture', 'the tap writes the pending yank');
  if (await page.evaluate(() => typeof navigator.userActivation !== 'undefined')) {
    eq(gestureWrites[1].active, true, 'writeText ran while the trusted click was active');
  }
  ok('fallback: refusal -> tap prompt -> trusted write -> honest success');

  // 11. A refused tap is an honest error, not a false success.
  // Let the prior success toast expire so this case cannot inherit it.
  await page.waitForFunction(() => !document.querySelector('[data-testid="term-toast"]'), null, { timeout: 3000 }).catch(() => {});
  await stubClipboard(page, { denyAll: true });
  await feed(page, osc52('never lands'));
  await page.locator('[data-testid="remote-copy-prompt"]').waitFor({ state: 'visible', timeout: 4000 });
  await press(page, p, '[data-testid="remote-copy-now"]');
  await page.locator('[data-testid="remote-copy-error"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('a refused tap did not show the real error'));
  const errText = await page.locator('[data-testid="remote-copy-error"]').innerText();
  if (!errText.includes('NotAllowedError')) fail(`error must name the real refusal: ${errText}`);
  eq(await page.evaluate(() => window.__copied), null, 'a refused tap must not claim success');
  eq(await promptVisible(page), true, 'the prompt stays up after a refused tap');
  eq(await toastText(page), '', 'no success toast after a refused tap');
  await press(page, p, '[data-testid="remote-copy-dismiss"]');
  await page.locator('[data-testid="remote-copy-prompt"]').waitFor({ state: 'detached', timeout: 3000 })
    .catch(() => fail('dismiss did not clear the pending remote copy'));
  ok('error: refused tap stays honest, dismiss discards');

  // 12. A later yank replaces the pending text safely.
  await stubClipboard(page, { denyRemaining: 2 });
  await feed(page, osc52('first yank'));
  await page.locator('[data-testid="remote-copy-prompt"]').waitFor({ state: 'visible', timeout: 4000 });
  await feed(page, osc52('second yank'));
  await page.waitForFunction(() => window.__writes.length === 2, null, { timeout: 4000 })
    .catch(() => fail('the second refused yank was not attempted'));
  await press(page, p, '[data-testid="remote-copy-now"]');
  await waitCopied(page, 'second yank', 'the prompt must hold the newest yank, not a stale one');
  ok('replacement: a later yank replaces the pending prompt');

  // 13. No OSC path read the clipboard and none echoed a query.
  eq(await page.evaluate(() => window.__reads), 0, 'the OSC 52 path must never read the device clipboard');
  const pty = await sent(page);
  if (pty.includes(']52;')) fail(`OSC 52 bytes leaked to the PTY: ${JSON.stringify(pty)}`);

  await page.close();
}

(async () => {
  const bundle = build();
  const html = '<!doctype html><html><head><meta charset=utf-8><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0"><div id="root" style="position:fixed;inset:0"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
  const browser = await (BROWSER === 'webkit' ? webkit : chromium).launch({ headless: true });
  for (const p of PROFILES) await runProfile(browser, p);
  await browser.close();
  server.close();
  profile = 'all';
  if (pageErrors.length) fail(`page errors: ${pageErrors.join(' | ')}`);
  console.log(`[webshell-osc52] PASS (${BROWSER}: ${PROFILES.map((p) => p.name).join(', ')})`);
})().catch((e) => fail(String((e && e.stack) || e)));
