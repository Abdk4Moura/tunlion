// Replay actual PTY bytes and resize events through browser xterm.js. These are
// real widget pixels, not an HTML approximation. Keep full screenshots as well
// as focused crops of the current owned region (resize preserves old history).
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

async function fragmentedPaintCheck(browser, root) {
  const page = await browser.newPage({ viewport: { width: 500, height: 140 } });
  try {
    await page.setContent('<body style="margin:10px;background:#141412"><div id="terminal"></div></body>');
    await page.addStyleTag({ path: require.resolve('@xterm/xterm/css/xterm.css') });
    await page.addScriptTag({ path: require.resolve('@xterm/xterm') });
    await page.evaluate(async () => {
      const terminal = window.flickerTerminal = new Terminal({ cols: 40, rows: 3,
        cursorBlink: false, cursorStyle: 'bar', theme: { background: '#141412', foreground: '#deded5' } });
      terminal.open(document.querySelector('#terminal'));
      terminal.focus();
      await new Promise(resolve => terminal.write('  add / choose words\r\n  abalaka-world\r\n  Enter creates abalaka-world-1740\x1b[1A\r\x1b[15C', resolve));
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    const screen = page.locator('.xterm-screen');
    const before = await screen.screenshot({ path: path.join(root, 'atomic-before.png') });
    const holding = await page.evaluate(async () => {
      const terminal = window.flickerTerminal;
      // Deliberately split a transaction across animation frames, like a slow
      // SSH/network delivery. Even a clear must not become a visible blank.
      await new Promise(resolve => terminal.write('\x1b[?2026h\x1b[2;1H\x1b[2K', resolve));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      return terminal.modes.synchronizedOutputMode;
    });
    if (!holding) throw new Error('xterm did not enable synchronized output');
    const during = await screen.screenshot({ path: path.join(root, 'atomic-during.png') });
    if (!before.equals(during)) throw new Error('A partial transaction became visible (flicker)');
    await page.evaluate(async () => {
      await new Promise(resolve => window.flickerTerminal.write('  abalaka-worldx\x1b[?2026l', resolve));
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    const after = await screen.screenshot({ path: path.join(root, 'atomic-after.png') });
    if (before.equals(after)) throw new Error('Completed transaction did not become visible');
    console.log('PASS: fragmented paint stayed pixel-identical until commit; no intermediate blank frame');
  } finally { await page.close(); }
}

(async () => {
  const root = process.argv[2];
  const browser = await chromium.launch({ headless: true,
    ...(process.env.CHROME_BIN ? { executablePath: process.env.CHROME_BIN } : {}),
    args: ['--no-sandbox'] });
  try {
    for (const file of fs.readdirSync(root).filter(name => name.endsWith('.json'))) {
      const sample = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
      if (!sample.events || !sample.frame) continue;
      for (const light of [false, true]) {
        const page = await browser.newPage({ viewport: { width: 1100, height: 720 }, deviceScaleFactor: 1 });
        const background = light ? '#f7f6f2' : '#141412';
        await page.setContent(`<body style="margin:20px;background:${background}"><div id="terminal"></div></body>`);
        await page.addStyleTag({ path: require.resolve('@xterm/xterm/css/xterm.css') });
        await page.addScriptTag({ path: require.resolve('@xterm/xterm') });
        const geometry = await page.evaluate(async ({ sample, light, background }) => {
          const terminal = new Terminal({ cols: sample.initial[0], rows: sample.initial[1],
            fontSize: 15, fontFamily: '"DejaVu Sans Mono", monospace', cursorBlink: false,
            theme: { background, foreground: light ? '#24241f' : '#deded5',
              yellow: light ? '#8b6500' : '#e6b450' } });
          terminal.open(document.querySelector('#terminal'));
          for (const event of sample.events) {
            if (event.resize) terminal.resize(...event.resize);
            if (event.data) {
              const bytes = Uint8Array.from(atob(event.data), c => c.charCodeAt(0));
              await new Promise(resolve => terminal.write(bytes, resolve));
            }
          }
          terminal.focus();
          await document.fonts.ready;
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          const bounds = document.querySelector('.xterm-screen').getBoundingClientRect();
          const height = bounds.height / terminal.rows;
          const ownedRows = sample.frame.lines.some(line => line.includes('choose words')) ? 3 : 10;
          return { x: bounds.x, y: bounds.y + Math.max(0, terminal.rows - ownedRows) * height,
            width: bounds.width, height: Math.min(terminal.rows, ownedRows) * height };
        }, { sample, light, background });
        const name = file.slice(0, -5) + (light ? '-light' : '-dark');
        await page.screenshot({ path: path.join(root, name + '-full.png') });
        await page.screenshot({ path: path.join(root, name + '.png'), clip: geometry });
        await page.close();
      }
    }
    await fragmentedPaintCheck(browser, root);
  } finally {
    await browser.close();
  }
  console.log('PASS: actual terminal visual-review screenshots rendered in light/dark themes');
})().catch(error => { console.error(error); process.exit(1); });
