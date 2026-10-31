// Raw RTCPeerConnection offer-first harness. No PeerLink, no transport-hint.
// Signaling stays in Node (socket.io-client); the browser only owns the real
// RTCPeerConnection. The daemon must answer the FIRST SDP and open the channel.
//
//   RAW_SERVER=http://127.0.0.1:8145 RAW_CHANNEL=<hex> \
//     node frontend/tests/raw-offer-first.spec.cjs
const path = require('path');
const { chromium } = require(require.resolve('playwright', {
  paths: [path.join(__dirname, '..')],
}));
const io = require(require.resolve('socket.io-client', {
  paths: [path.join(__dirname, '..')],
}));

const SERVER = process.env.RAW_SERVER || 'http://127.0.0.1:8145';
const CHANNEL = process.env.RAW_CHANNEL || '';
const UID = process.env.RAW_UID || 'raw-browser-uid';
const CHROME = process.env.RAW_CHROME || '/usr/bin/chromium';
const TIMEOUT = Number(process.env.RAW_TIMEOUT_MS || 12000);

(async () => {
  if (!CHANNEL) throw new Error('RAW_CHANNEL is required');
  const socket = io(SERVER, { transports: ['websocket'], forceNew: true, reconnection: false });
  await new Promise((resolve, reject) => {
    socket.on('connect', resolve);
    socket.on('connect_error', reject);
    setTimeout(() => reject(new Error('socket connect timeout')), 5000);
  });
  socket.emit('join', { room: `raw-${crypto.randomUUID()}`, name: 'raw', uid: UID });
  socket.emit('subscribe', { channels: [CHANNEL] });
  const daemon = await new Promise((resolve, reject) => {
    socket.on('known-peer', (p) => {
      if (p.channel === CHANNEL && p.id !== socket.id) resolve(p);
    });
    setTimeout(() => reject(new Error('no daemon known-peer on channel')), 5000);
  });

  const browser = await chromium.launch({ headless: true, executablePath: CHROME });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.error('[page-error]', String(e).slice(0, 300)));
  await page.setContent('<!doctype html><html><body></body></html>');
  await page.exposeFunction('__rawSend', (data) => {
    socket.emit('signal', { to: daemon.id, data });
  });
  const inbox = [];
  let recvReady = false;
  socket.on('signal', async ({ from, data }) => {
    console.log('[raw-recv]', from, data && data.type, data && data.description && data.description.type);
    if (!recvReady) { inbox.push(data); return; }
    try { await page.evaluate((d) => window.__rawRecv(d), data); } catch (e) { console.log('[raw-recv-error]', String(e).slice(0,200)); }
  });

  // Build the peer and define the receiver first; only then send the offer.
  await page.evaluate(({ UID, TIMEOUT }) => {
    const pc = new RTCPeerConnection({ iceServers: [] });
    const dc = pc.createDataChannel('filament');
    const t0 = performance.now();
    const sent = [];
    let descriptionSent = false;
    const pendingCandidates = [];
    const opened = new Promise((resolve, reject) => {
      dc.onopen = () => resolve(performance.now() - t0);
      setTimeout(() => reject(new Error('data channel did not open')), TIMEOUT);
    });
    pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      const candidate = e.candidate.toJSON ? e.candidate.toJSON() : e.candidate;
      if (!descriptionSent) { pendingCandidates.push(candidate); return; }
      sent.push('candidate');
      window.__rawSend({ type: 'candidate', uid: UID, candidate });
    };
    window.__rawRecv = async (data) => {
      if (!data) return;
      if (data.description) await pc.setRemoteDescription(data.description);
      if (data.candidate) {
        try { await pc.addIceCandidate(data.candidate); } catch (_) {}
      }
    };
    window.__rawOffer = async () => {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      descriptionSent = true;
      sent.push('description');
      console.log('[raw-send] description');
      window.__rawSend({ type: 'description', uid: UID, description: pc.localDescription });
      for (const candidate of pendingCandidates.splice(0)) {
        sent.push('candidate');
        window.__rawSend({ type: 'candidate', uid: UID, candidate });
      }
      const readyMs = await opened;
      return { readyMs, sent, first: sent[0], hint: sent.includes('transport-hint') };
    };
    window.__rawRecvReady = true;
  }, { UID, TIMEOUT });
  recvReady = true;
  for (const data of inbox.splice(0)) {
    await page.evaluate((d) => window.__rawRecv(d), data);
  }
  const ready = page.evaluate(() => window.__rawOffer());

  const result = await ready;
  await browser.close();
  socket.close();
  console.log(JSON.stringify({ daemonId: daemon.id, ...result }));
  if (result.hint) throw new Error('a transport-hint was sent; this is not an offer-first run');
  if (result.first !== 'description') throw new Error(`first signal was ${result.first}, expected description`);
  if (!(result.readyMs < TIMEOUT)) throw new Error(`ready ${result.readyMs}ms`);
  console.log('[raw-offer-first] PASS');
})().catch((e) => {
  console.error('[raw-offer-first] FAIL:', e && e.stack || String(e));
  process.exit(1);
});
