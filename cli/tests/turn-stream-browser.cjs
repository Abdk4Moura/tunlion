// turn-stream-gates.sh helper: a real headless Chromium on the production
// frontend receives the CLI's offer in a room, saves it, and reports the
// sha256 of the saved bytes and whether the UI showed the relay route badge.
//   node turn-stream-browser.cjs <room-url> <download-path>
// Prints one line: RESULT sha256=<hex> bytes=<n> relay_badge=<bool>
const { chromium } = require('playwright');
const crypto = require('crypto');
const fs = require('fs');

// Failure-only evidence for a receive that never completes: every
// RTCPeerConnection the page makes, and its data channels, are recorded by a
// test-only init script that passes every call straight through. Nothing here
// changes what the page does or what this helper asserts.
function recordPeerConnections() {
  const Native = window.RTCPeerConnection;
  if (!Native) return;
  window.__diagPcs = [];
  function Recorded(...args) {
    const pc = new Native(...args);
    const entry = { pc, chans: [] };
    window.__diagPcs.push(entry);
    pc.addEventListener('datachannel', (ev) => entry.chans.push(ev.channel));
    const create = pc.createDataChannel.bind(pc);
    pc.createDataChannel = (...a) => { const c = create(...a); entry.chans.push(c); return c; };
    return pc;
  }
  Recorded.prototype = Native.prototype;
  Object.setPrototypeOf(Recorded, Native);
  window.RTCPeerConnection = Recorded;
}

function bounded(promise, ms, fallback) {
  return Promise.race([promise.catch(() => fallback), new Promise((r) => setTimeout(() => r(fallback), ms))]);
}

async function dumpReceiveState(page) {
  const state = await bounded(page.evaluate(async () => {
    const out = [];
    for (const { pc, chans } of window.__diagPcs || []) {
      const row = {
        conn: pc.connectionState, ice: pc.iceConnectionState, sig: pc.signalingState,
        chans: chans.map((c) => ({ label: c.label, state: c.readyState, buffered: c.bufferedAmount })),
      };
      try {
        const stats = await pc.getStats();
        const byId = new Map();
        stats.forEach((r) => byId.set(r.id, r));
        stats.forEach((r) => {
          if (r.type === 'transport' && r.selectedCandidatePairId) row.pairId = r.selectedCandidatePairId;
        });
        let pair = row.pairId && byId.get(row.pairId);
        if (!pair) stats.forEach((r) => { if (r.type === 'candidate-pair' && r.nominated && r.state === 'succeeded') pair = r; });
        if (pair) {
          const l = byId.get(pair.localCandidateId) || {};
          const rm = byId.get(pair.remoteCandidateId) || {};
          row.pair = {
            state: pair.state, bytesReceived: pair.bytesReceived, bytesSent: pair.bytesSent,
            local: `${l.candidateType}/${l.protocol}/${l.relayProtocol || ''}`,
            remote: `${rm.candidateType}/${rm.protocol}`,
          };
        }
        stats.forEach((r) => {
          if (r.type === 'data-channel') (row.dc = row.dc || []).push({ label: r.label, state: r.state, bytesReceived: r.bytesReceived, messagesReceived: r.messagesReceived });
        });
      } catch (e) { row.statsError = String(e).slice(0, 120); }
      out.push(row);
    }
    return out;
  }), 5000, [{ error: 'page did not answer within 5s' }]);
  const rows = await bounded(page.locator('body').innerText(), 3000, '');
  const progress = (rows.match(/[^\n]*\d+\s?%[^\n]*/g) || []).slice(0, 5);
  console.log('[pw] DIAG peer-connections', JSON.stringify(state));
  console.log('[pw] DIAG progress-lines', JSON.stringify(progress));
}

(async () => {
  const [url, out] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ acceptDownloads: true });
  await page.addInitScript(recordPeerConnections);
  page.on('pageerror', (e) => console.log('[page-error]', String(e).slice(0, 200)));
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  console.log('[pw] app loaded', url);

  // The RELAY badge belongs to the live peer row and goes when the sender
  // disconnects, so watch for it from the start instead of after completion.
  let relayBadge = false;
  const badgeSeen = page
    .getByTestId('route-relay')
    .first()
    .waitFor({ timeout: 300000 })
    .then(() => { relayBadge = true; console.log('[pw] relay badge visible'); })
    .catch(() => {});

  const accept = page.getByRole('button', { name: /^accept$/i }).first();
  await accept.waitFor({ timeout: 120000 });
  console.log('[pw] offer visible, accepting');
  await accept.click();

  const save = page.getByRole('button', { name: /^save$/i }).first();
  try {
    await save.waitFor({ timeout: 150000 });
  } catch (e) {
    // The wait's own error is what fails the cell, whatever the dump does.
    await bounded(dumpReceiveState(page), 15000, undefined).catch(() => {});
    throw e;
  }
  console.log('[pw] transfer complete');

  // Still connected a moment after completion if it was not seen yet.
  await Promise.race([badgeSeen, new Promise((r) => setTimeout(r, 5000))]);

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
