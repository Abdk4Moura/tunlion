// Gate: CLI -> browser. A real (headless) Chromium tab running the production
// frontend receives a file offered by the CLI. Usage:
//   node browser-receiver.js <app-url>
const { chromium } = require('playwright');

(async () => {
  const url = process.argv[2] || 'http://127.0.0.1:8077/';
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));

  await page.goto(url, { waitUntil: 'networkidle' });
  console.log('[pw] app loaded');

  // The offer row's buttons (TransferRow in frontend/src/ui/Tunlion.jsx).
  // Match them by role and their exact, capitalized label: Playwright's
  // `exact: true` is case-sensitive, so a lowercase 'accept' never matched the
  // real 'Accept' button and this gate could only time out.
  const accept = page.getByRole('button', { name: 'Accept', exact: true }).first();
  await accept.waitFor({ timeout: 90000 });
  console.log('[pw] offer visible, clicking Accept');
  await accept.click();

  // Save appears only once the row reaches 'complete' (all bytes in).
  await page.getByRole('button', { name: 'Save', exact: true }).first().waitFor({ timeout: 120000 });
  console.log('[pw] RECEIVE COMPLETE in browser');

  await browser.close();
  process.exit(0);
})().catch((e) => {
  console.error('[pw] FAILED:', String(e).slice(0, 300));
  process.exit(1);
});
