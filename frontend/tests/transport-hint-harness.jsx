// Harness: construct the REAL PeerLink in Chromium and capture every signal it
// emits. The point is ordering and immediacy, not a network path: the browser
// must announce `direct:false` synchronously, before any SDP, so a direct-first
// CLI never waits out its QUIC budget for a peer that cannot speak QUIC. The
// hint also names the device kind (`client:"browser"`) so the CLI can explain a
// completed browser pairing without treating it as a failed fleet enrolment.
//
// It also runs a real two-peer WebRTC negotiation against a "CLI" that models
// the direct-first wait: without the hint it waits DELAY_MS before creating its
// link; with the hint it starts at once. That measures connecting -> ready and
// proves the ready path is not gated on an unrelated fixed budget.
import { PeerLink, transportHint } from '../src/lib/webrtc.js'

function captureHint() {
  const sent = []
  const t0 = performance.now()
  const link = new PeerLink({
    id: 'peer-sid',
    name: 'web-shell',
    iceServers: [],
    chunkSize: 16 * 1024,
    polite: true,
    myUid: 'browser-uid',
    peerUid: 'cli-uid',
    stores: { partials: new Map(), outgoing: new Map() },
    sendSignal: (data) => sent.push({ data, at: performance.now() - t0 }),
    onStatus: () => {},
  })
  const elapsed = performance.now() - t0
  try { link.close() } catch {}
  return {
    hint: transportHint('browser-uid'),
    sent,
    elapsed,
    first: sent[0] ? sent[0].data : null,
    firstDescription: sent.findIndex((x) => x.data && x.data.type === 'description'),
  }
}

// A miniature "CLI": impolite, creates the data channel + offer. `honorHint`
// models a fixed CLIENT that applies transport-hint; otherwise it waits
// DELAY_MS first, which is exactly what the direct-QUIC budget did to a browser.
function measureReady({ honorHint, delayMs }) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now()
    let browser = null
    let cli = null
    const toBrowser = []
    const toCli = []
    let done = false

    const finish = (result) => {
      if (done) return
      done = true
      try { browser && browser.close() } catch (e) {}
      try { cli && cli.close() } catch (e) {}
      resolve(result)
    }

    const route = (to, data) => {
      if (to === 'cli') {
        if (!cli) { toCli.push(data); return }
        cli.enqueueSignal(data)
      } else {
        if (!browser) { toBrowser.push(data); return }
        browser.enqueueSignal(data)
      }
    }

    const ensureCli = () => {
      if (cli) return
      cli = new PeerLink({
        id: 'browser-sid',
        name: 'web-shell',
        iceServers: [],
        chunkSize: 16 * 1024,
        polite: false,
        myUid: 'cli-uid',
        peerUid: 'browser-uid',
        stores: { partials: new Map(), outgoing: new Map() },
        sendSignal: (data) => route('browser', data),
        onStatus: () => {},
      })
      while (toCli.length) cli.enqueueSignal(toCli.shift())
    }

    browser = new PeerLink({
      id: 'cli-sid',
      name: 'cli',
      iceServers: [],
      chunkSize: 16 * 1024,
      polite: true,
      myUid: 'browser-uid',
      peerUid: 'cli-uid',
      stores: { partials: new Map(), outgoing: new Map() },
      sendSignal: (data) => {
        route('cli', data)
        // A fixed CLI applies the hint at once; the old/broken one ignores it
        // and only starts after its direct budget.
        if (honorHint && data.type === 'transport-hint') ensureCli()
      },
      onStatus: (status) => {
        if (status === 'ready') finish({ readyMs: performance.now() - t0 })
        if (status === 'failed') finish({ error: 'browser link failed' })
      },
    })
    while (toBrowser.length) browser.enqueueSignal(toBrowser.shift())

    if (!honorHint) setTimeout(ensureCli, delayMs)
    setTimeout(() => finish({ error: 'ready timeout' }), 12000)
  })
}

window.__HINT = captureHint()
window.__READY = (async () => {
  const fast = await measureReady({ honorHint: true, delayMs: 3000 })
  const slow = await measureReady({ honorHint: false, delayMs: 3000 })
  return { fast, slow }
})()
