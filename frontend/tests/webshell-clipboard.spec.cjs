// Browser shell clipboard gate. Drives the REAL WebTerminal + xterm 6 (the
// same harness as webshell-scroll) and asserts the exact bytes that would go
// to the PTY. Device profiles per engine:
//   chromium: Android phone (touch, 412x915) and desktop (1280x800)
//   webkit:   iPad (touch, 1024x768), iPhone (touch, 390x844), desktop Safari
// It FAILS when:
//   1. Paste or Select is not on screen without scrolling the key bar;
//   2. a paste skips xterm's paste semantics (newline -> CR, bracketed paste
//      when the app enabled mode 2004);
//   3. pasted text can close the bracket early (embedded ESC[201~);
//   4. multi-line text goes straight into a shell without bracketed paste, or
//      a large paste is not reviewed first, or review Send/Cancel misbehave;
//   5. a refused clipboard read dead-ends instead of opening the paste sheet,
//      or a system paste into that sheet does not go straight in;
//   6. a native paste event on the terminal is lost, doubled, or bypasses
//      the review rules; an armed sticky Alt prefixes a paste;
//   7. Cmd+V on a touch device with the soft keyboard hidden does not lift
//      the helper textarea's readonly for that keystroke (iPad hardware keyboard);
//   8. Select mode does not expose the buffer as selectable text at the
//      on-screen lines, does not copy a selection / the screen, or does not
//      join soft-wrapped rows.
//
//   node frontend/tests/webshell-clipboard.spec.cjs
//   WEBSHELL_BROWSER=webkit node frontend/tests/webshell-clipboard.spec.cjs
//
// Boundary: this is Safari's engine, not a physical iPad. Playwright cannot
// show the iOS "Paste" bubble that readText() raises, the press-and-hold edit
// menu, or route a hardware Cmd+V through UIKit. Those are stubbed (Clipboard
// API) or dispatched as real DOM events (paste, keydown); the iOS UI layer
// itself needs a device check.

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const { chromium, webkit } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const FRONT = path.resolve(__dirname, '..');
const PORT = 8263;
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

function fail(msg) { console.error(`[webshell-clipboard] FAIL (${BROWSER}/${profile}):`, msg); try { server && server.close(); } catch (e) {} process.exit(1); }
function ok(msg) { console.log(`[webshell-clipboard] OK (${profile}):`, msg); }
function eq(actual, expected, msg) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(`${msg}: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function build() {
  const out = path.join(__dirname, '.webshell-clipboard-bundle.js');
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
  return page;
}

// Clipboard API stub: Playwright cannot raise the iOS Paste bubble, so the
// read outcome is scripted. read === null means the browser refused.
async function stubClipboard(page, { read = '' } = {}) {
  await page.evaluate(({ read }) => {
    window.__copied = null;
    window.__reads = 0;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text) => { window.__copied = text; return true; },
        readText: async () => {
          window.__reads++;
          if (read === null) { const e = new Error('denied'); e.name = 'NotAllowedError'; throw e; }
          return read;
        },
      },
    });
  }, { read });
}
const feed = (page, text) => page.evaluate((t) => window.__scroll.feed(t), text);
const inputs = (page) => page.evaluate(() => window.__scroll.inputs());
const clearInputs = (page) => page.evaluate(() => window.__scroll.clearInputs());
const sent = async (page) => (await inputs(page)).join('');
async function waitSent(page, want, msg) {
  try {
    await page.waitForFunction((want) => window.__scroll.inputs().join('') === want, want, { timeout: 4000 });
  } catch (e) { eq(await sent(page), want, msg); }
}
async function press(page, p, sel) {
  const loc = page.locator(sel);
  if (p.touch) await loc.tap(); else await loc.click();
}
async function sheet(page) {
  return page.evaluate(() => {
    const s = document.querySelector('[data-testid="paste-sheet"]');
    if (!s) return null;
    return { mode: s.getAttribute('data-mode'), draft: document.querySelector('[data-testid="paste-input"]').value };
  });
}
// A real ClipboardEvent carrying a DataTransfer, dispatched where the
// platform would deliver a system paste.
async function nativePaste(page, selector, text) {
  return page.evaluate(({ selector, text }) => {
    const el = document.querySelector(selector);
    const dt = new DataTransfer();
    dt.setData('text/plain', text);
    const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true, composed: true });
    el.dispatchEvent(ev);
    return ev.defaultPrevented;
  }, { selector, text });
}
async function resetModes(page) {
  await feed(page, '\x1b[?2004l');
  await clearInputs(page);
}

const HISTORY = Array.from({ length: 140 }, (_, i) => `history line ${String(i + 1).padStart(3, '0')}`).join('\r\n') + '\r\n';

async function runProfile(browser, p) {
  profile = p.name;
  const page = await openPage(browser, p);
  console.log(`[webshell-clipboard] engine=${BROWSER} profile=${p.name} viewport=${p.width}x${p.height} touch=${p.touch}`);

  // 1. Paste and Select are on screen without scrolling the bar.
  for (const key of ['Paste', 'Select']) {
    const box = await page.locator(`[data-key="${key}"]`).boundingBox();
    if (!box) fail(`${key} button is not rendered`);
    if (box.x < 0 || box.x + box.width > p.width || box.y + box.height > p.height) {
      fail(`${key} button is off screen: ${JSON.stringify(box)} in ${p.width}x${p.height}`);
    }
    if (p.touch && (box.width < 44 || box.height < 44)) fail(`${key} touch target below 44px: ${JSON.stringify(box)}`);
  }
  ok('Paste and Select are pinned on screen');

  // 2. Direct read: one command, newline becomes Enter (CR), sent once.
  await resetModes(page);
  await stubClipboard(page, { read: 'echo hi\n' });
  await press(page, p, '[data-key="Paste"]');
  await waitSent(page, 'echo hi\r', 'single-line paste must arrive as typed text + CR');
  eq(await sheet(page), null, 'a single-line paste must not open the sheet');
  ok('paste: single line goes straight in with CR');

  // 2b. Bracketed paste: an app that enabled mode 2004 gets one bracketed
  // paste, multi-line included, no review.
  await clearInputs(page);
  await feed(page, '\x1b[?2004h');
  await stubClipboard(page, { read: 'line one\nline two' });
  await press(page, p, '[data-key="Paste"]');
  await waitSent(page, '\x1b[200~line one\rline two\x1b[201~', 'bracketed multi-line paste');
  eq(await sheet(page), null, 'bracketed multi-line paste must not need review');
  ok('paste: bracketed mode wraps the paste once, no review');

  // 3. Paste injection: an embedded end-bracket must not survive.
  await clearInputs(page);
  await stubClipboard(page, { read: 'safe\x1b[201~rm -rf ~\n' });
  await press(page, p, '[data-key="Paste"]');
  await waitSent(page, '\x1b[200~saferm -rf ~\r\x1b[201~', 'embedded bracket markers must be stripped');
  ok('paste: embedded ESC[201~ is stripped, the bracket cannot be closed early');

  // 4. Multi-line into a plain (non-bracketed) shell: review first.
  await resetModes(page);
  await stubClipboard(page, { read: 'ls\npwd\n' });
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="review"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('multi-line paste without bracketed mode did not open review'));
  eq(await sent(page), '', 'review must not send anything before Send');
  eq((await sheet(page)).draft, 'ls\npwd\n', 'review shows the exact text');
  const title = await page.locator('[data-testid="paste-sheet"]').getAttribute('aria-label');
  eq(title, 'Paste 2 lines?', 'review states the line count');
  await press(page, p, '[data-testid="paste-insert"]');
  await waitSent(page, 'ls\rpwd\r', 'review Send must deliver the lines');
  eq(await sheet(page), null, 'sheet closes after Send');
  await stubClipboard(page, { read: 'a\nb' });
  await clearInputs(page);
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="review"]').waitFor({ state: 'visible', timeout: 4000 });
  await press(page, p, '[data-testid="paste-cancel"]');
  await wait(150);
  eq(await sent(page), '', 'review Cancel sends nothing');
  eq(await sheet(page), null, 'review Cancel closes the sheet');
  ok('paste: multi-line into a plain shell is reviewed; Send sends, Cancel does not');

  // 4b. Large single-line paste is reviewed even when bracketed.
  await feed(page, '\x1b[?2004h');
  await clearInputs(page);
  await stubClipboard(page, { read: 'x'.repeat(5000) });
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="review"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('a 5000-char paste was not reviewed'));
  await press(page, p, '[data-testid="paste-cancel"]');
  ok('paste: a large paste is reviewed first');

  // 5. Refused read -> fallback sheet; a system paste into it goes straight in.
  await resetModes(page);
  await stubClipboard(page, { read: null });
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="fallback"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('refused clipboard read did not open the fallback sheet'));
  eq(await page.evaluate(() => window.__reads), 1, 'Paste must try a direct read first');
  const prevented = await nativePaste(page, '[data-testid="paste-input"]', 'uname -a');
  if (!prevented) fail('fallback sheet did not take the system paste');
  await waitSent(page, 'uname -a', 'system paste into the fallback sheet must send at once');
  eq(await sheet(page), null, 'fallback sheet closes after the paste lands');
  // Typed (no clipboardData) text still goes through Insert.
  await clearInputs(page);
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="fallback"]').waitFor({ state: 'visible', timeout: 4000 });
  await page.locator('[data-testid="paste-input"]').fill('typed');
  await press(page, p, '[data-testid="paste-insert"]');
  await waitSent(page, 'typed', 'Insert sends the box contents');
  // Multi-line system paste into the fallback sheet becomes a review.
  await clearInputs(page);
  await press(page, p, '[data-key="Paste"]');
  await page.locator('[data-testid="paste-sheet"][data-mode="fallback"]').waitFor({ state: 'visible', timeout: 4000 });
  await nativePaste(page, '[data-testid="paste-input"]', 'one\ntwo');
  await page.locator('[data-testid="paste-sheet"][data-mode="review"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('multi-line paste into the fallback sheet skipped review'));
  eq(await sent(page), '', 'review from the fallback sheet sends nothing yet');
  await press(page, p, '[data-testid="paste-cancel"]');
  ok('paste: refused read opens the sheet; a system paste there goes straight in');

  // 6. Native paste on the terminal (Cmd/Ctrl+V, Edit menu, long-press Paste).
  await resetModes(page);
  const termPrevented = await nativePaste(page, '.xterm-helper-textarea', 'cd /tmp');
  if (!termPrevented) fail('native terminal paste was not taken by the paste pipeline');
  await waitSent(page, 'cd /tmp', 'native paste on the terminal');
  await wait(100);
  eq(await inputs(page), ['cd /tmp'], 'native paste must arrive exactly once (not also via xterm)');
  await clearInputs(page);
  await nativePaste(page, '.xterm', 'a\nb\nc');
  await page.locator('[data-testid="paste-sheet"][data-mode="review"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('native multi-line paste skipped review'));
  eq(await sent(page), '', 'native multi-line paste waits for review');
  await press(page, p, '[data-testid="paste-cancel"]');
  // Sticky Alt must not prefix a paste (and stays armed for the next key).
  await clearInputs(page);
  await press(page, p, '[data-key="alt"]');
  await nativePaste(page, '.xterm-helper-textarea', 'q');
  await waitSent(page, 'q', 'armed Alt must not prefix a paste');
  eq(await page.locator('[data-key="alt"]').getAttribute('aria-pressed'), 'true', 'a paste must not consume armed Alt');
  await press(page, p, '[data-key="alt"]');
  ok('paste: native terminal paste takes the same path, once; sticky Alt untouched');

  // 7. iPad hardware keyboard: Cmd+V while the soft keyboard is hidden.
  if (p.touch) {
    await clearInputs(page);
    const before = await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      window.__roAtKey = null;
      // Bubble phase on document: after xterm's keydown handler, before the
      // browser's default (paste) action for the keystroke.
      document.addEventListener('keydown', (e) => {
        if (e.key === 'v' && e.metaKey && window.__roAtKey === null) window.__roAtKey = ta.readOnly;
      });
      ta.focus();
      return { readOnly: ta.readOnly, inputMode: ta.getAttribute('inputmode') };
    });
    eq(before, { readOnly: true, inputMode: 'none' }, 'touch viewing mode starts readonly with no soft keyboard');
    await page.keyboard.down('Meta');
    await page.keyboard.press('v');
    await page.keyboard.up('Meta');
    eq(await page.evaluate(() => window.__roAtKey), false, 'Cmd+V keydown must make the helper editable before the paste action');
    eq(await page.evaluate(() => document.querySelector('.xterm-helper-textarea').getAttribute('inputmode')), 'none', 'lifting readonly must not request a soft keyboard');
    await nativePaste(page, '.xterm-helper-textarea', 'from-hw-keyboard');
    await waitSent(page, 'from-hw-keyboard', 'hardware Cmd+V paste');
    eq(await page.evaluate(() => document.querySelector('.xterm-helper-textarea').readOnly), true, 'readonly is restored once the paste lands');
    // And it restores on its own when no paste follows.
    await page.keyboard.down('Meta'); await page.keyboard.press('v'); await page.keyboard.up('Meta');
    await page.waitForFunction(() => document.querySelector('.xterm-helper-textarea').readOnly === true, null, { timeout: 2500 })
      .catch(() => fail('readonly was not restored after a Cmd+V with no paste'));
    ok('hardware Cmd+V on touch: readonly lifted for the keystroke, restored after');
  }

  // 8. Select mode.
  await resetModes(page);
  await feed(page, '\x1b[2J\x1b[H');
  await feed(page, HISTORY);
  const cols = await page.evaluate(() => window.__webterm.cols);
  const longLine = 'W'.repeat(cols + 17);
  await feed(page, longLine + '\r\n');
  await page.evaluate(() => window.__webterm.scrollLines(-10));
  const firstVisible = await page.evaluate(() => {
    const b = window.__webterm.buffer.active;
    return b.getLine(b.viewportY).translateToString(true);
  });
  await stubClipboard(page, {});
  await press(page, p, '[data-key="Select"]');
  await page.locator('[data-testid="select-layer"]').waitFor({ state: 'visible', timeout: 4000 })
    .catch(() => fail('Select did not open the selectable text layer'));
  const layer = await page.evaluate(() => {
    const pre = document.querySelector('[data-testid="select-text"]');
    const cs = getComputedStyle(pre);
    return {
      text: pre.textContent,
      userSelect: cs.userSelect || cs.webkitUserSelect,
      anchorTop: pre.querySelector('[data-select-anchor]').getBoundingClientRect().top - pre.getBoundingClientRect().top,
      height: pre.clientHeight,
      scrollTop: pre.scrollTop,
    };
  });
  if (layer.userSelect !== 'text') fail(`select layer is not user-selectable: ${layer.userSelect}`);
  if (!layer.text.includes('history line 001') || !layer.text.includes('history line 140')) fail('select layer is missing scrollback or the tail');
  if (!layer.text.includes(longLine)) fail('a soft-wrapped row was not joined into one line');
  if (!(layer.scrollTop > 0) || layer.anchorTop < -4 || layer.anchorTop > 40) {
    fail(`select layer did not land on the on-screen lines (scrollTop=${layer.scrollTop}, anchorTop=${layer.anchorTop})`);
  }
  const anchorText = await page.evaluate(() => document.querySelector('[data-select-anchor]').textContent.split('\n')[0]);
  eq(anchorText, firstVisible, 'the layer starts at the first line that was on screen');
  // Select one line with a real DOM range, then Copy.
  await page.evaluate(() => {
    const pre = document.querySelector('[data-testid="select-text"]');
    const walker = document.createTreeWalker(pre, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      const i = n.data.indexOf('history line 120');
      if (i >= 0) {
        const r = document.createRange();
        r.setStart(n, i); r.setEnd(n, i + 'history line 120'.length);
        const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
        return;
      }
    }
  });
  await press(page, p, '[data-testid="select-copy"]');
  await page.waitForFunction(() => window.__copied != null, null, { timeout: 4000 })
    .catch(() => fail('Copy in Select mode did not write the clipboard'));
  eq(await page.evaluate(() => window.__copied), 'history line 120', 'Copy copies exactly the selection');
  await page.locator('[data-testid="select-layer"]').waitFor({ state: 'detached', timeout: 3000 })
    .catch(() => fail('Select layer did not close after a successful copy'));
  // Nothing selected: copies the visible screen.
  await stubClipboard(page, {});
  await press(page, p, '[data-key="Select"]');
  await page.locator('[data-testid="select-layer"]').waitFor({ state: 'visible', timeout: 4000 });
  await page.evaluate(() => window.getSelection().removeAllRanges());
  await press(page, p, '[data-testid="select-copy"]');
  await page.waitForFunction(() => window.__copied != null, null, { timeout: 4000 });
  const screenCopy = await page.evaluate(() => window.__copied);
  if (!screenCopy.startsWith(firstVisible)) fail(`no-selection Copy did not copy the screen: ${JSON.stringify(screenCopy.slice(0, 60))}`);
  // Done closes without copying.
  await press(page, p, '[data-key="Select"]');
  await page.locator('[data-testid="select-layer"]').waitFor({ state: 'visible', timeout: 4000 });
  await press(page, p, '[data-testid="select-done"]');
  await page.locator('[data-testid="select-layer"]').waitFor({ state: 'detached', timeout: 3000 })
    .catch(() => fail('Done did not close the Select layer'));
  eq(await sent(page), '', 'Select mode must never send input to the PTY');
  ok('select: buffer as selectable text at the on-screen lines; Copy selection / screen; Done');

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
  console.log(`[webshell-clipboard] PASS (${BROWSER}: ${PROFILES.map((p) => p.name).join(', ')})`);
})().catch((e) => fail(String((e && e.stack) || e)));
