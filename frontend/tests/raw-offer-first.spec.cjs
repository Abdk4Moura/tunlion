// Raw RTCPeerConnection offer-first harness. No PeerLink, no transport-hint.
// A real browser joins the fixture's fleet channel, learns the daemon sid from
// the server's known-peer push, and sends the FIRST SDP offer. The daemon must
// start its responder from that offer, answer it, and open the data channel.
//
//   RAW_SERVER=http://127.0.0.1:8145 RAW_CHANNEL=<hex> \
//     node frontend/tests/raw-offer-first.spec.cjs
const path = require('path');
const { chromium } = require(require.resolve('playwright', {
  paths: [path.join(__dirname, '..')],
}));

const SERVER = process.env.RAW_SERVER || 'http://127.0.0.1:8145';
const CHANNEL = process.env.RAW_CHANNEL || '';
const UID = process.env.RAW_UID || 'raw-browser-uid';
const CHROME = process.env.RAW_CHROME || '/usr/bin/chromium';
const TIMEOUT = Number(process.env.RAW_TIMEOUT_MS || 12000);

(async () => {
  if (!CHANNEL) throw new Error('RAW_CHANNEL is required');
  const browser = await chromium.launch({ headless: true, executablePath: CHROME });
  const page = await browser.newPage();
  page.on('pageerror', (e) => console.error('[page-error]', String(e).slice(0, 300)));
  await page.goto(`${SERVER}/`, { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.addScriptTag({ url: `${SERVER}/socket.io/socket.io.js` });
  const result = await page.evaluate(
    async ({ SERVER, CHANNEL, UID, TIMEOUT }) => {
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

      const pc = new RTCPeerConnection({ iceServers: [] });
      const dc = pc.createDataChannel('filament');
      const sent = [];
      const t0 = performance.now();
      pc.onicecandidate = (e) => {
        if (!e.candidate) return;
        const candidate = e.candidate.toJSON ? e.candidate.toJSON() : e.candidate;
        sent.push('candidate');
        socket.emit('signal', { to: daemon.id, data: { type: 'candidate', uid: UID, candidate } });
      };
      socket.on('signal', async ({ data }) => {
        if (!data) return;
        if (data.description) {
          await pc.setRemoteDescription(data.description);
        }
        if (data.candidate) {
          try { await pc.addIceCandidate(data.candidate); } catch (_) {}
        }
      });

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      sent.push('description');
      socket.emit('signal', {
        to: daemon.id,
        data: { type: 'description', uid: UID, description: pc.localDescription },
      });
      const readyMs = await new Promise((resolve, reject) => {
        dc.onopen = () => resolve(performance.now() - t0);
        setTimeout(() => reject(new Error('data channel did not open')), TIMEOUT);
      });
      const out = { daemonId: daemon.id, sent, readyMs, first: sent[0], hint: sent.includes('transport-hint') };
      try { dc.close(); } catch (_) {}
      try { pc.close(); } catch (_) {}
      try { socket.close(); } catch (_) {}
      return out;
    },
    { SERVER, CHANNEL, UID, TIMEOUT },
  );
  await browser.close();
  console.log(JSON.stringify(result));
  if (result.hint) throw new Error('a transport-hint was sent; this is not an offer-first run');
  if (result.first !== 'description') throw new Error(`first signal was ${result.first}, expected description`);
  if (!(result.readyMs < TIMEOUT)) throw new Error(`ready ${result.readyMs}ms`);
  console.log('[raw-offer-first] PASS');
})().catch((e) => {
  console.error('[raw-offer-first] FAIL:', e && e.stack || String(e));
  process.exit(1);
});
