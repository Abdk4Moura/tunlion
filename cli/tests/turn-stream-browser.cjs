// turn-stream-gates.sh helper: a real headless Chromium on the production
// frontend receives the CLI's offer in a room, saves it, and reports the
// sha256 of the saved bytes and whether the UI showed the relay route badge.
//   node turn-stream-browser.cjs <room-url> <download-path>
// Prints one line: RESULT sha256=<hex> bytes=<n> relay_badge=<bool>
const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');

(async () => {
  const [url, out] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ acceptDownloads: true });
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  console.log('[pw] app loaded', url);

  const accept = page.getByRole('button', { name: /^accept$/i }).first();
  await accept.waitFor({ timeout: 120000 });
  console.log('[pw] offer visible, accepting');
  await accept.click();

  const save = page.getByRole('button', { name: /^save$/i }).first();
  await save.waitFor({ timeout: 150000 });
  console.log('[pw] transfer complete');

  let relayBadge = false;
  try {
    await page.getByTestId('route-relay').first().waitFor({ timeout: 10000 });
    relayBadge = true;
  } catch (_) {
    relayBadge = false;
  }

  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 30000 }), save.click()]);
  await dl.saveAs(out);
  const buf = fs.readFileSync(out);
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  console.log(`RESULT sha256=${sha} bytes=${buf.length} relay_badge=${relayBadge}`);
  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 400));
  process.exit(1);
});
