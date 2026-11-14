// Browser shell scroll ergonomics gate. Drives the REAL WebTerminal + xterm 6
// in Chromium, and in Playwright WebKit (Safari's engine) with an iPad touch
// viewport/user-agent when WEBSHELL_BROWSER=webkit. It asserts the bytes that
// would have gone to the PTY. It FAILS when:
//   1. an ordinary normal-buffer shell stops scrolling local history, or a
//      touch scroll leaks wheel/cursor bytes into its PTY;
//   2. a partial TUI in the NORMAL buffer with mouse reporting does not receive
//      a wheel report at the touched cell (the original iPad bug);
//   3. an alternate-screen TUI with mouse reporting does not receive wheel, or
//      an alternate screen without it does not get xterm's Up/Down fallback
//      (including DECCKM application cursor keys);
//   4. a gesture is routed twice (local scroll + report), or horizontal,
//      multi-touch and tap gestures scroll or type;
//   5. accessory page buttons move history under a TUI instead of paging the
//      app, or lose local-history paging in an ordinary shell;
//   6. X10 (click-only, no wheel in xterm) is dishonestly treated as wheel;
//   7. the mobile textarea hardening / IME commit path regressed.
//
//   node frontend/tests/webshell-scroll.spec.cjs        (from the repo root)
//   WEBSHELL_BROWSER=webkit node frontend/tests/webshell-scroll.spec.cjs
//
// Boundary: Playwright WebKit is Safari's engine, not a physical iPad. It does
// not expose a `Touch` constructor (Safari's real construction API is
// `document.createTouch`/`createTouchList`), and on Linux it reports
// navigator.maxTouchPoints=0 even with hasTouch. The gate uses the engine's
// real Touch/TouchEvent API and the app's existing `?touch=1` preview hook; it
// does not claim iOS Safari UI, virtual-keyboard, or hardware-touch coverage.

const { spawnSync } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const { chromium, webkit } = require(require.resolve('playwright', { paths: [path.join(__dirname, '..')] }));

const FRONT = path.resolve(__dirname, '..');
const PORT = 8261;
// `chromium` is the default so the existing command keeps its old cost.
// `WEBSHELL_BROWSER=webkit` runs the same gate in Playwright's WebKit engine
// (Safari's engine) with an iPad touch context. It is not a physical iPad; see
// the boundary note in `openPage`.
let server = null;
const pageErrors = [];
const BROWSER = (process.env.WEBSHELL_BROWSER || 'chromium').trim().toLowerCase();
if (BROWSER !== 'chromium' && BROWSER !== 'webkit') fail(`unknown WEBSHELL_BROWSER=${BROWSER}`);
let loggedContext = false;
const IPAD_UA = 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
function fail(msg) { console.error('[webshell-scroll] FAIL:', msg); try { server && server.close(); } catch (e) {} process.exit(1); }
function ok(msg) { console.log('[webshell-scroll] OK:', msg); }
function eq(actual, expected, msg) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${msg}: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
  }
}
// Touch taps are real input events; React state and xterm focus settle after
// the event task. Poll instead of reading immediately (WebKit order differs).
async function waitPolicy(page, want, msg) {
  try {
    await page.waitForFunction((want) => {
      const ta = document.querySelector('.xterm-helper-textarea');
      return !!ta
        && ta.readOnly === want.readOnly
        && (want.inputMode === undefined || ta.getAttribute('inputmode') === want.inputMode)
        && (document.activeElement === ta) === want.focused;
    }, want, { timeout: 5000 });
  } catch (e) {
    fail(`${msg}: ${e && e.message ? e.message : e}`);
  }
}
async function waitPressed(page, want, msg) {
  try {
    await page.waitForFunction((want) => {
      const b = document.querySelector('[data-testid="term-keyboard"]');
      return !!b && b.getAttribute('aria-pressed') === want;
    }, want, { timeout: 5000 });
  } catch (e) {
    fail(`${msg}: ${e && e.message ? e.message : e}`);
  }
}
async function waitInputs(page, n, msg) {
  try {
    await page.waitForFunction((n) => window.__scroll.inputs().length >= n, n, { timeout: 5000 });
  } catch (e) {
    fail(`${msg}: ${e && e.message ? e.message : e}`);
  }
}
async function tapHostAt(page, x, y) {
  const host = page.locator('[data-testid="term-host"]');
  const box = await host.boundingBox();
  if (!box) fail('term-host has no bounding box');
  await host.tap({ position: { x: Math.max(0, x - box.x), y: Math.max(0, y - box.y) } });
}

function build() {
  const out = path.join(__dirname, '.webshell-scroll-bundle.js');
  const r = spawnSync(path.join(FRONT, 'node_modules', '.bin', 'esbuild'),
    [path.join(__dirname, 'webshell-scroll-harness.jsx'), '--bundle', '--format=iife', `--outfile=${out}`,
      '--loader:.js=jsx', '--jsx=automatic', '--define:process.env.NODE_ENV="production"',
      '--loader:.wasm=file', '--loader:.css=text', '--define:import.meta.env={"VITE_TUNLION_API":""}'],
    { cwd: FRONT, encoding: 'utf8' });
  if (r.status !== 0) fail('esbuild failed: ' + (r.stderr || r.stdout));
  return fs.readFileSync(out);
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function openPage(browser, { width = BROWSER === 'webkit' ? 1024 : 900, height = BROWSER === 'webkit' ? 768 : 700, touch = true } = {}) {
  const page = await browser.newPage({
    viewport: { width, height },
    hasTouch: touch,
    ...(BROWSER === 'webkit' && touch ? { isMobile: true, deviceScaleFactor: 2, userAgent: IPAD_UA } : {}),
  });
  page.on('pageerror', (e) => { pageErrors.push(String(e)); console.log('[page-error]', String(e).slice(0, 400)); });
  page.on('console', (m) => { if (m.type() === 'error') console.log('[console-error]', m.text().slice(0, 400)); });
  await page.goto(`http://127.0.0.1:${PORT}/?preview=webshell-scroll&touch=${touch ? 1 : 0}`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.__webterm && window.__scroll, null, { timeout: 10000 })
    .catch(async () => {
      const d = await page.evaluate(() => ({
        webterm: !!window.__webterm, scroll: !!window.__scroll,
        root: (document.getElementById('root') || {}).innerHTML,
        body: document.body.innerHTML.slice(0, 200),
      })).catch((e) => ({ evalError: String(e) }));
      console.log('[mount-debug]', JSON.stringify(d).slice(0, 1200));
      fail('WebTerminal / xterm never mounted');
    });
  // The component focuses the helper textarea on mount (readonly on touch).
  // Wait for that real state instead of calling term.focus() from the harness,
  // which would mask a missing mount-focus regression.
  await page.waitForFunction(() => {
    const ta = document.querySelector('.xterm-helper-textarea');
    return !!ta && document.activeElement === ta;
  }, null, { timeout: 5000 }).catch(() => fail('terminal helper textarea did not receive initial focus'));
  // TouchEvent construction is engine-specific. WebKit exposes `Touch` but its
  // constructor is an illegal constructor (Safari's real API is the legacy
  // `document.createTouch` + `createTouchList` pair). Do not paper over that:
  // detect the API actually present and fail if neither exists, rather than
  // silently turning a touch gesture into a mouse/key gesture.
  page.__touchMode = await page.evaluate(() => {
    try { new Touch({ identifier: 1, target: document.body, clientX: 1, clientY: 1, pageX: 1, pageY: 1, screenX: 1, screenY: 1, radiusX: 1, radiusY: 1, force: 1 }); return 'constructor'; } catch (e) {}
    if (typeof document.createTouch === 'function' && typeof document.createTouchList === 'function') return 'createTouchList';
    return 'unsupported';
  });
  if (page.__touchMode === 'unsupported') fail('this browser exposes no synthetic Touch/TouchEvent construction API');
  if (!loggedContext) {
    loggedContext = true;
    const ua = await page.evaluate(() => navigator.userAgent);
    console.log(`[webshell-scroll] engine=${BROWSER} viewport=${width}x${height} touchMode=${page.__touchMode} ua=${ua}`);
  }
  return page;
}

const feed = (page, text) => page.evaluate((t) => window.__scroll.feed(t), text);
const state = (page) => page.evaluate(() => window.__scroll.state());
const inputs = (page) => page.evaluate(() => window.__scroll.inputs());
const inputBytes = (page) => page.evaluate(() => window.__scroll.inputBytes());
const clearInputs = (page) => page.evaluate(() => window.__scroll.clearInputs());

const HISTORY = Array.from({ length: 140 }, (_, i) => `history line ${String(i + 1).padStart(3, '0')}`).join('\r\n') + '\r\n';

async function cellPoint(page, col, row) {
  const s = await state(page);
  return {
    x: s.screen.left + (col + 0.5) * s.cell.width,
    y: s.screen.top + (row + 0.5) * s.cell.height,
  };
}

// Synthetic TouchEvent sequence over the real host. `steps` touchmove events;
// steps=0 is a tap. `fingers=2` starts a two-finger gesture and then moves one
// finger, which must leave tActive false in WebTerminal.
async function swipe(page, { x0, y0, x1 = x0, y1, steps = 1, fingers = 1 }) {
  return page.evaluate(({ x0, y0, x1, y1, steps, fingers, mode }) => {
    const host = document.querySelector('[data-testid="term-host"]');
    // Chromium exposes `new Touch(...)`. WebKit (Safari's engine) exposes
    // `Touch` but its constructor is illegal; the API that actually works there
    // is Safari's legacy `document.createTouch` / `createTouchList`. Use the
    // engine's real API rather than a JS object that only looks like a Touch.
    const mk = (x, y, id) => mode === 'createTouchList'
      ? document.createTouch(window, host, id, x, y, x, y, 1, 1, 1, 1)
      : new Touch({
          identifier: id, target: host,
          clientX: x, clientY: y, pageX: x, pageY: y, screenX: x, screenY: y,
          radiusX: 1, radiusY: 1, force: 1,
        });
    const list = (xs) => mode === 'createTouchList' ? document.createTouchList(...xs) : xs;
    const fire = (type, touches, changed) => host.dispatchEvent(new TouchEvent(type, {
      bubbles: true, cancelable: true, composed: true,
      touches: list(touches), targetTouches: list(touches), changedTouches: list(changed || touches),
    }));
    if (fingers === 2) {
      const a = mk(x0, y0, 1), b = mk(x0, y0 + 24, 2);
      fire('touchstart', [a, b]);
      fire('touchmove', [a], [a]);
      fire('touchend', [], [a, b]);
      return true;
    }
    fire('touchstart', [mk(x0, y0, 1)]);
    for (let i = 1; i <= steps; i++) {
      fire('touchmove', [mk(x0 + (x1 - x0) * i / steps, y0 + (y1 - y0) * i / steps, 1)]);
    }
    fire('touchend', []);
    return true;
  }, { x0, y0, x1, y1, steps, fingers, mode: page.__touchMode });
}

// Split gesture primitives, so a spec can change the app's mode/buffer between
// touchstart and touchmove (the stale-route abort case).
async function touchStart(page, x, y) {
  await page.evaluate(({ x, y, mode }) => {
    const host = document.querySelector('[data-testid="term-host"]');
    const t = mode === 'createTouchList'
      ? document.createTouch(window, host, 1, x, y, x, y, 1, 1, 1, 1)
      : new Touch({ identifier: 1, target: host, clientX: x, clientY: y, pageX: x, pageY: y, screenX: x, screenY: y });
    const l = mode === 'createTouchList' ? document.createTouchList(t) : [t];
    host.dispatchEvent(new TouchEvent('touchstart', { bubbles: true, cancelable: true, composed: true, touches: l, targetTouches: l, changedTouches: l }));
  }, { x, y, mode: page.__touchMode });
}
async function touchMove(page, x, y) {
  await page.evaluate(({ x, y, mode }) => {
    const host = document.querySelector('[data-testid="term-host"]');
    const t = mode === 'createTouchList'
      ? document.createTouch(window, host, 1, x, y, x, y, 1, 1, 1, 1)
      : new Touch({ identifier: 1, target: host, clientX: x, clientY: y, pageX: x, pageY: y, screenX: x, screenY: y });
    const l = mode === 'createTouchList' ? document.createTouchList(t) : [t];
    host.dispatchEvent(new TouchEvent('touchmove', { bubbles: true, cancelable: true, composed: true, touches: l, targetTouches: l, changedTouches: l }));
  }, { x, y, mode: page.__touchMode });
}
async function touchEnd(page) {
  await page.evaluate(({ mode }) => {
    const host = document.querySelector('[data-testid="term-host"]');
    const empty = mode === 'createTouchList' ? document.createTouchList() : [];
    host.dispatchEvent(new TouchEvent('touchend', { bubbles: true, cancelable: true, composed: true, touches: empty, targetTouches: empty, changedTouches: empty }));
  }, { mode: page.__touchMode });
}

// Report xterm itself would encode for the ORIGINAL touch cell. We compute the
// expectation from the same screen rect/cell size the event carries, never by
// hardcoding a protocol in the component.
function sgrWheel(button, col, row) {
  return `\x1b[<${button};${col + 1};${row + 1}M`; // 64 = wheel up, 65 = wheel down
}

// Legacy DEFAULT encoding: CSI M, then event-code/col/row each +32, one byte.
// Wheel up = 64+32 = 96, wheel down = 65+32 = 97.
function legacyWheel(code, col, row) {
  return [27, 91, 77, code, col + 1 + 32, row + 1 + 32];
}

(async () => {
  const bundle = build();
  const html = '<!doctype html><html><head><meta charset=utf-8><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0"><div id="root" style="position:fixed;inset:0"></div><script src="/bundle.js"></script></body></html>';
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/bundle.js')) { res.setHeader('content-type', 'text/javascript'); res.end(bundle); }
    else { res.setHeader('content-type', 'text/html'); res.end(html); }
  });
  await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
  const engine = BROWSER === 'webkit' ? webkit : chromium;
  const browser = await engine.launch({ headless: true });

  // Touch viewing does not ask the OS for a keyboard. Only the explicit button
  // makes xterm editable/focuses it in the user's click stack. Browsers here do
  // not display an iOS/Gboard IME; assert the DOM/focus contract, not fake pixels.
  {
    const page = await openPage(browser);
    const keyboard = page.locator('[data-testid="term-keyboard"]');
    const policy = () => page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      return { readOnly: ta.readOnly, inputMode: ta.getAttribute('inputmode'), focused: document.activeElement === ta };
    });
    await waitPressed(page, 'false', 'touch must start with keyboard off');
    eq((await policy()).readOnly, true, 'touch viewing must not expose an editable field');
    eq((await policy()).inputMode, 'none', 'touch viewing must suppress the IME hint');
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: true }, 'touch mount must focus the readonly helper for hardware keyboards');

    // Physical keyboard input works from the initial readonly focus. Do this
    // before any tap so the mount-focus contract is what is exercised.
    await clearInputs(page);
    await page.keyboard.type('hardware');
    await waitInputs(page, 'hardware'.length, 'physical keys did not reach the PTY from initial focus');
    eq((await inputs(page)).join(''), 'hardware', 'focused readonly terminal still accepts physical keys with the software keyboard off');
    eq((await policy()).readOnly, true, 'physical typing must not make the field editable');

    // A real touch tap on the terminal must neither enable editing nor hide the
    // hardware focus/typing path.
    await clearInputs(page);
    const p = await cellPoint(page, 4, 4);
    await tapHostAt(page, p.x, p.y);
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: true }, 'terminal touch tap must leave the readonly policy intact');
    await page.keyboard.type('tap');
    await waitInputs(page, 'tap'.length, 'physical keys did not reach the PTY after a terminal tap');
    eq((await inputs(page)).join(''), 'tap', 'terminal touch tap must not block physical keys');

    // A real touch tap (not a mouse click) on the button is the Safari path.
    // The textarea is ALREADY focused while readonly. iOS will not raise the
    // soft keyboard if show merely flips readOnly on that same focus, so the
    // show action must blur and focus again inside the tap.
    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      window.__kbdFocusLog = [];
      ta.addEventListener('blur', () => window.__kbdFocusLog.push('blur'));
      ta.addEventListener('focus', () => window.__kbdFocusLog.push('focus'));
    });
    await keyboard.tap();
    await waitPressed(page, 'true', 'Keyboard touch tap did not enable typing');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'show keyboard synchronously enables and focuses input');
    eq(await page.evaluate(() => window.__kbdFocusLog.slice(0, 2)), ['blur', 'focus'],
      'show keyboard must start a fresh editable focus, not just drop readOnly');
    await clearInputs(page);
    await page.keyboard.type('hello');
    await waitInputs(page, 'hello'.length, 'explicit keyboard typing did not reach the PTY');
    eq((await inputs(page)).join(''), 'hello', 'explicit keyboard typing reaches PTY');
    await keyboard.tap();
    await waitPressed(page, 'false', 'Keyboard touch tap did not hide the keyboard');
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: false }, 'hide keyboard disables editing and blurs input');
    await clearInputs(page);
    await page.locator('[data-key="Esc"]').tap();
    await waitInputs(page, 1, 'accessory Esc did not reach the PTY');
    eq(await inputBytes(page), [[27]], 'accessory keys still work with keyboard hidden');
    await page.locator('[data-key="Redraw"]').tap();
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: false }, 'redraw must not enable typing or steal focus');
    await keyboard.tap();
    await waitPressed(page, 'true', 'Keyboard did not reopen after accessory actions');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'keyboard can reopen after accessory actions');
    ok('touch keyboard: real taps show/hide; taps, redraw and accessory keys keep readonly policy');
    await page.close();
  }

  // Hidden means the SOFT keyboard is hidden. Hardware keyboards (including
  // their IME) stay live: composition must commit once and reopening must not
  // duplicate or lose it.
  {
    const page = await openPage(browser);
    const keyboard = page.locator('[data-testid="term-keyboard"]');
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: true }, 'hidden hardware composition fixture is not focused/readonly');
    await clearInputs(page);
    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      ta.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true, data: 'ni' }));
      ta.dispatchEvent(new CompositionEvent('compositionupdate', { bubbles: true, data: '你' }));
      ta.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: '你' }));
    });
    await waitInputs(page, 1, 'hidden hardware composition did not commit');
    eq(await inputs(page), ['你'], 'hidden hardware composition must commit exactly once');
    eq((await page.evaluate(() => document.querySelector('.xterm-helper-textarea').readOnly)), true, 'composition must not reveal an editable field');

    await keyboard.tap();
    await waitPressed(page, 'true', 'Keyboard did not reopen after hidden composition');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'keyboard did not focus after hidden composition');
    await clearInputs(page);
    await page.keyboard.type('x');
    await waitInputs(page, 1, 'typing after hidden composition did not reach the PTY');
    eq(await inputs(page), ['x'], 'reopening after hidden composition must not duplicate the prior commit');
    ok('hidden hardware composition/reopen: one commit, one later key, no duplicate');
    await page.close();
  }

  // Hiding while a composition is in flight: the final compositionend must
  // commit once after hide, and reopening must not duplicate it.
  {
    const page = await openPage(browser);
    const keyboard = page.locator('[data-testid="term-keyboard"]');
    await keyboard.tap();
    await waitPressed(page, 'true', 'Keyboard did not enable for hide-mid-composition fixture');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'hide-mid-composition fixture did not focus');
    await clearInputs(page);
    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      ta.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true, data: 'ni' }));
      ta.dispatchEvent(new CompositionEvent('compositionupdate', { bubbles: true, data: '你' }));
    });
    await keyboard.tap();
    await waitPressed(page, 'false', 'hide-mid-composition did not hide the keyboard');
    await waitPolicy(page, { readOnly: true, inputMode: 'none', focused: false }, 'hide-mid-composition did not blur');
    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      ta.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: '你' }));
    });
    await waitInputs(page, 1, 'composition ending after hide was silently dropped');
    eq(await inputs(page), ['你'], 'composition ending after hide must commit exactly once');
    await clearInputs(page);
    await keyboard.tap();
    await waitPressed(page, 'true', 'Keyboard did not reopen after hide-mid-composition');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'keyboard did not focus after hide-mid-composition');
    await page.keyboard.type('q');
    await waitInputs(page, 1, 'typing after hide-mid-composition did not reach the PTY');
    eq(await inputs(page), ['q'], 'reopen after hide-mid-composition must not duplicate the commit');
    ok('hide mid-composition: final commit lands once; reopen commits later text only');
    await page.close();
  }
  {
    const page = await openPage(browser, { touch: false });
    await waitPolicy(page, { readOnly: false, focused: true }, 'desktop helper is not editable/focused on mount');
    eq(await page.locator('[data-testid="term-keyboard"]').count(), 0, 'desktop has no touch keyboard toggle');
    await clearInputs(page);
    await page.keyboard.type('desktop');
    await waitInputs(page, 'desktop'.length, 'desktop typing did not reach the PTY');
    eq((await inputs(page)).join(''), 'desktop', 'desktop auto-focused typing remains unchanged');
    ok('desktop retains normal focus and typing without a keyboard toggle');
    await page.close();
  }

  // Clipboard (copy, paste, Select mode) lives in webshell-clipboard.spec.cjs.

  // 12. Local recovery must not consume server stream slots. A healthy link
  // with an acked PTY gets repaints only; repeated Redraw/watchdog recovery
  // keeps openPty at one. A real link swap reattaches exactly once with the
  // same session id and resume_from.
  {
    const page = await openPage(browser);
    await page.waitForFunction(() => window.__scroll.openPtyCalls().length === 1, null, { timeout: 5000 });
    await page.waitForFunction(() => typeof window.__webtermRecover === 'function', null, { timeout: 5000 });
    await page.evaluate(() => { window.__savedTerm = window.__webterm });
    await feed(page, HISTORY);
    const before = await page.evaluate(() => {
      const b = window.__webterm.buffer.active;
      return { baseY: b.baseY, length: b.length, line: b.getLine(Math.max(0, b.baseY - 1)).translateToString(true) };
    });
    await page.evaluate(() => { for (let i = 0; i < 12; i++) window.__webtermRecover(); });
    await wait(120);
    const afterCalls = await page.evaluate(() => window.__scroll.openPtyCalls());
    eq(afterCalls.length, 1, '12 local Redraw recoveries must keep openPty at one');
    const after = await page.evaluate(() => {
      const b = window.__webterm.buffer.active;
      return { baseY: b.baseY, length: b.length, line: b.getLine(Math.max(0, b.baseY - 1)).translateToString(true) };
    });
    eq(after, before, 'local Redraw changed scrollback/buffer content');
    eq(await page.evaluate(() => window.__savedTerm === window.__webterm), true, 'local Redraw replaced the terminal identity');

    // Partial/alternate TUI repaint: still local, still the same terminal.
    await feed(page, '\x1b[?1049h');
    await feed(page, '\x1b[?1002h\x1b[?1006h');
    await feed(page, 'alt marker\r\n');
    const altBefore = await state(page);
    eq(altBefore.bufferType, 'alternate', 'alt repaint fixture did not enter alternate screen');
    await page.evaluate(() => { for (let i = 0; i < 12; i++) window.__webtermRecover(); });
    await wait(120);
    const altAfter = await state(page);
    eq(altAfter.bufferType, 'alternate', 'local Redraw lost the alternate screen');
    eq(await page.evaluate(() => window.__scroll.openPtyCalls().length), 1, 'alt-screen repaint opened another PTY stream');

    // Watchdog path: fake a stale render with new bytes and let the 1s tick run
    // redrawRecover. It must recover the renderer locally, not re-open the PTY.
    await page.evaluate(() => {
      const w = window.__webtermWatchdog;
      const b = window.__webterm.buffer.active;
      w.lastSig = b.length + ':' + b.baseY + ':' + b.cursorY + ':' + b.cursorX;
      w.renderAt = Date.now() - 5000;
      w.bytesAt = Date.now() - 5000;
      w.lastByteCount = w.byteCount;
      w.byteCount += 17;
      w.recoverAt = 0;
    });
    await page.waitForFunction(() => window.__webtermWatchdog.recoverAt > 0, null, { timeout: 5000 });
    eq(await page.evaluate(() => window.__scroll.openPtyCalls().length), 1, 'watchdog recovery opened another PTY stream');
    ok('local Redraw/watchdog: 12x + alt screen + watchdog, one PTY open, terminal/scrollback preserved');

    // Real link replacement: one fresh binding/open, same PTY session, resume_from.
    const resumeText = 'resume-me';
    await page.evaluate((t) => window.__scroll.feedLink(t), resumeText);
    await page.evaluate(() => window.__scroll.swapLink());
    await page.waitForFunction(() => window.__scroll.openPtyCalls().length === 2, null, { timeout: 5000 });
    const calls = await page.evaluate(() => window.__scroll.openPtyCalls());
    eq(calls.length, 2, 'link swap must reattach exactly once');
    eq(calls[1].link !== calls[0].link, true, 'link swap did not use a replacement link');
    eq(calls[1].session, calls[0].session, 'reattach changed the stable PTY session id');
    eq(calls[1].resumeFrom, Buffer.byteLength(resumeText), 'reattach did not resume from the bytes already shown');
    eq(await page.evaluate(() => window.__savedTerm === window.__webterm), true, 'link swap replaced the terminal identity');
    await page.evaluate(() => { for (let i = 0; i < 12; i++) window.__webtermRecover(); });
    await wait(120);
    eq(await page.evaluate(() => window.__scroll.openPtyCalls().length), 2, 'post-reattach Redraw opened another PTY stream');
    ok('link swap: one reattach, same session, resume_from preserved; later Redraw stays local');
    await page.close();
  }

  // 1. Ordinary normal-buffer terminal: local history, never PTY data.
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    const s0 = await state(page);
    if (s0.bufferType !== 'normal' || s0.mouseTrackingMode !== 'none') fail(`history fixture is not a plain normal terminal: ${JSON.stringify(s0)}`);
    if (!(s0.baseY > 0) || s0.viewportY !== s0.baseY) fail(`history fixture did not fill scrollback at the live tail: baseY=${s0.baseY} viewportY=${s0.viewportY}`);
    await page.waitForSelector('[data-testid="term-scrollbar"]', { state: 'visible', timeout: 4000 })
      .catch(() => fail('ordinary history terminal has no scrollbar'));
    eq(await page.getAttribute('[data-key="ScrollUp"]', 'aria-label'), 'scroll terminal history up', 'history page-up label');
    eq(await page.getAttribute('[data-key="ScrollUp"]', 'title'), 'scroll terminal history up', 'history page-up title');
    eq(await page.getAttribute('[data-key="ScrollDn"]', 'aria-label'), 'scroll terminal history down', 'history page-down label');
    const p = await cellPoint(page, 8, 4);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 8, steps: 1 });
    const s1 = await state(page);
    if (!(s1.viewportY < s0.viewportY)) fail(`swipe down did not scroll local history: ${s0.viewportY} -> ${s1.viewportY}`);
    eq(await inputs(page), [], 'a plain-shell touch scroll must send no PTY bytes');
    ok(`normal buffer: local history ${s0.viewportY} -> ${s1.viewportY}, zero PTY bytes`);

    // Under-threshold movement and a tap are not scrolls.
    await clearInputs(page);
    const at = s1.viewportY;
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + 3, steps: 1 });
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y, steps: 0 });
    const s2 = await state(page);
    if (s2.viewportY !== at) fail(`tap / sub-threshold drag moved history: ${at} -> ${s2.viewportY}`);
    eq(await inputs(page), [], 'tap / sub-threshold drag must send no PTY bytes');
    ok('normal buffer: tap and <6px drag do not scroll or type');
    await page.close();
  }

  // 2. Partial TUI in the NORMAL buffer with mouse reporting: xterm must encode
  //    a wheel at the touched cell, and history must not move underneath it.
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    const before = await state(page);
    const pOff = await cellPoint(page, 8, 4);
    // The reader is off the live tail when a partial TUI takes the wheel. That
    // must not strand them: the scroll-to-bottom escape hatch stays reachable.
    await swipe(page, { x0: pOff.x, y0: pOff.y, y1: pOff.y + before.cell.height * 8, steps: 1 });
    const off = await state(page);
    if (!(off.viewportY < off.baseY)) fail('could not scroll history off-tail before entering the partial TUI');
    await clearInputs(page);
    await feed(page, '\x1b[?1000h\x1b[?1006h'); // VT200 + SGR
    const s0 = await state(page);
    if (s0.bufferType !== 'normal' || s0.mouseTrackingMode !== 'vt200') fail(`partial-TUI fixture is not normal+vt200: ${JSON.stringify(s0)}`);
    if (!(s0.baseY > 0)) fail('partial-TUI fixture lost its normal-buffer scrollback');
    await page.waitForFunction(() => !document.querySelector('[data-testid="term-scrollbar"]'), null, { timeout: 4000 })
      .catch(() => fail('the history scrollbar stayed visible while the app owns the wheel'));
    eq(await page.getAttribute('[data-key="ScrollUp"]', 'aria-label'), 'scroll the running app up', 'app page-up label');
    eq(await page.getAttribute('[data-key="ScrollDn"]', 'title'), 'scroll the running app down', 'app page-down title');
    const jump = page.locator('[data-testid="scroll-to-bottom"]');
    if (await jump.count() !== 1) fail('off-tail reader was stranded: no scroll-to-bottom while the app owns the wheel');
    await jump.click();
    const back = await state(page);
    eq(back.viewportY, back.baseY, 'scroll-to-bottom did not return to the live tail');
    eq(await inputs(page), [], 'scroll-to-bottom must not send PTY bytes');
    ok('partial TUI: off-tail history kept a reachable scroll-to-bottom escape hatch');

    await clearInputs(page);
    const col = 12, row = 7;
    const p = await cellPoint(page, col, row);
    // Three rows of scroll: three application wheel reports, all at the cell
    // where the finger landed (not the cell it ended over).
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 3, steps: 1 });
    const got = await inputs(page);
    eq(got, [sgrWheel(64, col, row), sgrWheel(64, col, row), sgrWheel(64, col, row)], 'partial TUI should get 3 SGR wheel-up reports at the touched cell');
    const s1 = await state(page);
    eq(s1.viewportY, back.viewportY, 'partial TUI: touch wheel must not also scroll local history');
    ok(`partial normal-buffer TUI: 3 wheel-up reports at cell ${col + 1},${row + 1}, history untouched`);

    // Accessory page button is app paging, not history paging.
    await clearInputs(page);
    await page.click('[data-key="ScrollDn"]');
    const down = await inputs(page);
    if (down.length !== Math.max(1, s1.rows - 1)) fail(`page-down sent ${down.length} wheel reports, want rows-1=${Math.max(1, s1.rows - 1)}`);
    if (!down.every((d) => d === down[0] && /^\x1b\[<65;\d+;\d+M$/.test(d))) fail(`page-down did not encode wheel-down reports: ${JSON.stringify(down.slice(0, 3))}`);
    const s2 = await state(page);
    eq(s2.viewportY, back.viewportY, 'partial TUI page button must not move local history');
    ok(`partial TUI: page-down = ${down.length} app wheel-down reports at the terminal centre`);
    await page.close();
  }

  // 3. Alternate-screen TUI with mouse reporting: wheel goes to the app.
  {
    const page = await openPage(browser);
    await feed(page, '\x1b[?1049h');
    await feed(page, '\x1b[?1002h\x1b[?1006h'); // DRAG + SGR (tmux/vim style)
    const s0 = await state(page);
    if (s0.bufferType !== 'alternate' || s0.mouseTrackingMode !== 'drag') fail(`alt-mouse fixture is not alt+drag: ${JSON.stringify(s0)}`);
    await clearInputs(page);
    const col = 4, row = 3;
    const p = await cellPoint(page, col, row);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 2, steps: 1 });
    eq(await inputs(page), [sgrWheel(64, col, row), sgrWheel(64, col, row)], 'alternate mouse TUI should get 2 wheel-up reports');
    ok(`alt buffer + mouse: 2 wheel reports at cell ${col + 1},${row + 1}`);
    await page.close();
  }

  // 4. Alternate screen without mouse reporting: xterm's standard wheel ->
  //    Up/Down fallback, respecting DECCKM.
  {
    const page = await openPage(browser);
    await feed(page, '\x1b[?1049h');
    let s0 = await state(page);
    if (s0.bufferType !== 'alternate' || s0.mouseTrackingMode !== 'none') fail(`alt fallback fixture is not alt+none: ${JSON.stringify(s0)}`);
    eq(await page.getAttribute('[data-key="ScrollUp"]', 'aria-label'), 'send cursor-key up to the alternate-screen app', 'cursor-fallback page-up label');
    eq(await page.getAttribute('[data-key="ScrollDn"]', 'title'), 'send cursor-key down to the alternate-screen app', 'cursor-fallback page-down title');
    const p = await cellPoint(page, 6, 4);
    await clearInputs(page);
    // Finger down = reveal older = wheel up = Up.
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 2, steps: 1 });
    eq(await inputs(page), ['\x1b[A', '\x1b[A'], 'alt screen without mouse should get xterm cursor-key fallback (normal DECCKM)');

    await clearInputs(page);
    await feed(page, '\x1b[?1h'); // application cursor keys
    s0 = await state(page);
    if (!s0.applicationCursorKeys) fail('DECCKM did not turn on applicationCursorKeysMode');
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height, steps: 1 });
    eq(await inputs(page), ['\x1bOA'], 'DECCKM fallback should use SS3 Up (ESC O A)');
    await clearInputs(page);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y - s0.cell.height, steps: 1 });
    eq(await inputs(page), ['\x1bOB'], 'finger up should send the Down fallback (ESC O B)');
    ok('alt buffer + no mouse: xterm Up/Down fallback, both DECCKM modes and directions');

    await clearInputs(page);
    await page.click('[data-key="ScrollUp"]');
    const up = await inputs(page);
    eq(up.length, Math.max(1, s0.rows - 1), 'alt page-up should send rows-1 cursor keys');
    if (!up.every((d) => d === '\x1bOA')) fail(`alt page-up used the wrong cursor mode: ${JSON.stringify(up.slice(0, 3))}`);
    ok(`alt buffer: page-up = ${up.length} application-cursor Up keys`);
    await page.close();
  }

  // 5. X10 is click-only in xterm: normal buffer keeps history; alt falls back.
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    await feed(page, '\x1b[?9h');
    const s0 = await state(page);
    if (s0.mouseTrackingMode !== 'x10' || s0.bufferType !== 'normal') fail(`X10 fixture is not normal+x10: ${JSON.stringify(s0)}`);
    const p = await cellPoint(page, 5, 5);
    await clearInputs(page);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 4, steps: 1 });
    const s1 = await state(page);
    if (!(s1.viewportY < s0.viewportY)) fail('X10 normal buffer did not fall back to local history');
    eq(await inputs(page), [], 'X10 must not emit wheel reports');
    ok('X10 normal buffer: local history (xterm cannot report wheel for X10)');

    await feed(page, '\x1b[?1049h');
    const s2 = await state(page);
    await clearInputs(page);
    const q = await cellPoint(page, 5, 5);
    await swipe(page, { x0: q.x, y0: q.y, y1: q.y + s2.cell.height * 2, steps: 1 });
    eq(await inputs(page), ['\x1b[A', '\x1b[A'], 'X10 alternate screen should use the standard cursor-key fallback');
    ok('X10 alternate screen: cursor-key fallback, still no fake wheel reports');
    await page.close();
  }

  // 6. Horizontal drag, multi-touch and taps never scroll or type.
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    const s0 = await state(page);
    const p = await cellPoint(page, 7, 5);
    await clearInputs(page);
    await swipe(page, { x0: p.x, y0: p.y, x1: p.x + 120, y1: p.y + 8, steps: 4 });
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 6, steps: 3, fingers: 2 });
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y, steps: 0 });
    const s1 = await state(page);
    eq(s1.viewportY, s0.viewportY, 'horizontal / multi-touch / tap changed history');
    eq(await inputs(page), [], 'horizontal / multi-touch / tap sent PTY bytes');
    ok('horizontal drag, two-finger gesture and tap are inert');
    await page.close();
  }

  // 7. Mobile keyboard / IME behavior is untouched: same textarea hardening,
  //    plain typing still reaches the PTY, and a composition commits once.
  {
    const page = await openPage(browser);
    await page.locator('[data-testid="term-keyboard"]').tap();
    await waitPressed(page, 'true', 'IME fixture did not enable the keyboard');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'IME fixture did not focus after tap');
    const s = await state(page);
    eq(s.textarea, {
      autocorrect: 'off', autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false',
      enterkeyhint: 'send', ariaAutocomplete: 'none',
    }, 'mobile textarea hardening changed');
    await clearInputs(page);
    await page.evaluate(() => window.__webterm.focus());
    await page.keyboard.type('abc');
    await wait(100);
    eq((await inputs(page)).join(''), 'abc', 'plain typing no longer reaches the PTY');

    await clearInputs(page);
    await page.evaluate(() => {
      const ta = document.querySelector('.xterm-helper-textarea');
      ta.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true, data: 'ni' }));
      ta.dispatchEvent(new CompositionEvent('compositionupdate', { bubbles: true, data: '你' }));
      ta.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: '你' }));
    });
    await wait(150);
    eq(await inputs(page), ['你'], 'IME composition must commit exactly once');
    ok('mobile textarea hardening preserved; typing and one-shot IME commit intact');
    await page.close();
  }

  // 8. Legacy mouse encoding (DECSET 1000 without 1006/1016) is emitted on
  //    xterm's BINARY path. It must reach the PTY as exact raw bytes, including
  //    a coordinate above 127, which UTF-8 encoding would corrupt.
  {
    const page = await openPage(browser, { width: 1800, height: 700 });
    await feed(page, HISTORY);
    await feed(page, '\x1b[?1000h'); // VT200, DEFAULT (legacy) encoding
    const s0 = await state(page);
    if (s0.mouseTrackingMode !== 'vt200' || s0.bufferType !== 'normal') fail(`legacy normal fixture is not normal+vt200: ${JSON.stringify(s0)}`);
    if (!(s0.cols > 152)) fail(`legacy report needs columns >152 to exercise a byte >127, got ${s0.cols}`);
    await clearInputs(page);
    const col = 150, row = 6;
    const p = await cellPoint(page, col, row);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + s0.cell.height * 2, steps: 1 });
    const bytes = await inputBytes(page);
    eq(bytes, [legacyWheel(96, col, row), legacyWheel(96, col, row)], '1000-only normal TUI should get exact legacy ESC[M wheel bytes');
    const s1 = await state(page);
    eq(s1.viewportY, s0.viewportY, 'legacy normal TUI: history moved underneath the app');
    if (bytes.some((b) => b.length !== 6)) fail(`legacy report was re-encoded to ${JSON.stringify(bytes)} (want 6 bytes each)`);
    ok(`legacy normal TUI: 2 raw ESC[M reports, column byte ${col + 1 + 32} (>127), no history move`);

    await clearInputs(page);
    await feed(page, '\x1b[?1049h');
    await feed(page, '\x1b[?1000h'); // still no SGR encoding
    const s2 = await state(page);
    const q = await cellPoint(page, col, 4);
    await swipe(page, { x0: q.x, y0: q.y, y1: q.y + s2.cell.height, steps: 1 });
    eq(await inputBytes(page), [legacyWheel(96, col, 4)], '1000-only alternate TUI should get one exact legacy ESC[M wheel report');
    ok('legacy alternate TUI: raw ESC[M bytes, no duplicates');
    await page.close();
  }

  // 9. Sticky Alt/Ctrl is for text, not generated mouse input. A swipe must
  //    keep the modifier armed for the next real key, for both mouse encodings.
  {
    const page = await openPage(browser);
    await feed(page, '\x1b[?1000h\x1b[?1006h'); // SGR
    await page.click('[data-key="alt"]');
    eq(await page.getAttribute('[data-key="alt"]', 'aria-pressed'), 'true', 'sticky alt did not arm');
    await clearInputs(page);
    const p = await cellPoint(page, 10, 5);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + (await state(page)).cell.height, steps: 1 });
    eq(await inputs(page), [sgrWheel(64, 10, 5)], 'sticky Alt corrupted an SGR wheel report');
    eq(await page.getAttribute('[data-key="alt"]', 'aria-pressed'), 'true', 'SGR wheel consumed sticky Alt');
    await clearInputs(page);
    await page.locator('[data-testid="term-keyboard"]').tap();
    await waitPressed(page, 'true', 'sticky Alt fixture did not enable the keyboard');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'sticky Alt fixture did not focus after tap');
    await page.keyboard.type('a');
    await wait(100);
    eq(await inputBytes(page), [[27, 97]], 'sticky Alt no longer prefixes real text');
    eq(await page.getAttribute('[data-key="alt"]', 'aria-pressed'), 'false', 'sticky Alt did not disarm after real text');
    ok('sticky Alt: SGR wheel stays exact and armed; next real key is ESC+a and disarms');
    await page.close();
  }
  {
    const page = await openPage(browser, { width: 1800, height: 700 });
    await feed(page, '\x1b[?1000h'); // legacy binary path
    await page.click('[data-key="alt"]');
    await clearInputs(page);
    const p = await cellPoint(page, 150, 5);
    await swipe(page, { x0: p.x, y0: p.y, y1: p.y + (await state(page)).cell.height, steps: 1 });
    eq(await inputBytes(page), [legacyWheel(96, 150, 5)], 'sticky Alt corrupted a legacy wheel report');
    eq(await page.getAttribute('[data-key="alt"]', 'aria-pressed'), 'true', 'legacy wheel consumed sticky Alt');
    await clearInputs(page);
    await page.locator('[data-testid="term-keyboard"]').tap();
    await waitPressed(page, 'true', 'sticky Alt fixture did not enable the keyboard');
    await waitPolicy(page, { readOnly: false, inputMode: 'text', focused: true }, 'sticky Alt fixture did not focus after tap');
    await page.keyboard.type('a');
    await wait(100);
    eq(await inputBytes(page), [[27, 97]], 'sticky Alt no longer prefixes real text after a legacy report');
    eq(await page.getAttribute('[data-key="alt"]', 'aria-pressed'), 'false', 'sticky Alt did not disarm after real text');
    ok('sticky Alt: legacy wheel stays exact and armed; next real key is ESC+a and disarms');
    await page.close();
  }

  // 10. A mode or active-buffer change mid-gesture aborts it, instead of
  //     delivering the captured route to the new app.
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    const s0 = await state(page);
    const p = await cellPoint(page, 8, 5);
    await clearInputs(page);
    await touchStart(page, p.x, p.y);
    await feed(page, '\x1b[?1000h'); // history -> application wheel mid-gesture
    await touchMove(page, p.x, p.y + s0.cell.height * 5);
    await touchEnd(page);
    const s1 = await state(page);
    eq(s1.viewportY, s0.viewportY, 'mode change mid-gesture still scrolled history');
    eq(await inputs(page), [], 'mode change mid-gesture delivered a stale wheel route');
    ok('gesture aborted on mouse-mode change: no scroll, no report');
    await page.close();
  }
  {
    const page = await openPage(browser);
    await feed(page, HISTORY);
    const s0 = await state(page);
    const p = await cellPoint(page, 8, 5);
    await clearInputs(page);
    await touchStart(page, p.x, p.y);
    await feed(page, '\x1b[?1049h'); // normal buffer -> alternate mid-gesture
    await touchMove(page, p.x, p.y + s0.cell.height * 5);
    await touchEnd(page);
    const s1 = await state(page);
    if (s1.bufferType !== 'alternate') fail('buffer-flip fixture did not enter the alternate screen');
    eq(await inputs(page), [], 'buffer change mid-gesture delivered a stale cursor-key route');
    ok('gesture aborted on active-buffer change: no cursor keys, no report');
    await page.close();
  }

  await browser.close();
  server.close();
  if (pageErrors.length) fail(`page errors: ${pageErrors.join(' | ')}`);
  console.log(`[webshell-scroll] PASS (${BROWSER}${BROWSER === 'webkit' ? ', iPad touch context' : ''})`);
})().catch((e) => fail(String((e && e.stack) || e)));
