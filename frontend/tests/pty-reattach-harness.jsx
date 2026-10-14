// Focused harness for the browser shell reattach (pty-reattach.spec.cjs).
// Mounts the REAL WebTerminal against fake links backed by ONE fake device-side
// session that behaves like the CLI acceptor: it numbers its output, keeps a
// bounded replay ring, and on a reattach replays from `resume_from` exactly as
// the CLI's replay_skip does (whole ring when the client says nothing). The spec
// drives link drops through window.__h and reads what reached the terminal.
import React, { useState } from 'react'
import ReactDOM from 'react-dom/client'
import WebTerminal from '../src/ui/WebTerminal.jsx'

const enc = new TextEncoder()
const dec = new TextDecoder()
const T = {
  mode: 'dark', bg: '#0A0B0C', panel: '#0F1113', panel2: '#0C0E10', line: '#1E2227', lineSoft: '#15181C', grid: '#121417',
  text: '#D9DEE3', sub: '#9AA1A8', dim: '#666C73', faint: '#3C424A', ok: '#7CF6C8', warn: '#FFC857', bad: '#E5484D', recv: '#5B9DFF', onAccent: '#06120D',
}

// The device side: one persistent session that outlives every link.
const RING_CAP = 4096
const dev = { out: [], total: 0, ring: [], bound: null, opens: [], n: 0 }
function produce(text) {
  const b = Array.from(enc.encode(text))
  dev.total += b.length
  dev.ring.push(...b)
  if (dev.ring.length > RING_CAP) dev.ring.splice(0, dev.ring.length - RING_CAP)
  if (dev.bound) dev.bound.deliver(new Uint8Array(b))
}
function replaySkip(total, ringLen, from) {
  const start = Math.max(0, total - ringLen)
  return Number.isFinite(from) && from >= start && from <= total ? from - start : 0
}
// Every link-visible byte the terminal was handed, in order.
window.__delivered = []

function fakeLink(id) {
  const link = {
    id,
    channel: { readyState: 'open', send: () => {} },
    pc: { connectionState: 'connected' },
    _ptySid: null,
    onPtyData: () => {}, onPtyClose: () => {}, onPtyReady: () => {},
    deliver(u8) { window.__delivered.push(...u8); link.onPtyData(u8) },
    openPty(cols, rows, session, resumeFrom) {
      dev.opens.push({ link: id, session, resumeFrom: resumeFrom === undefined ? 'absent' : resumeFrom })
      link._ptySid = 1
      setTimeout(() => {
        dev.bound = link
        link.onPtyReady()
        const skip = replaySkip(dev.total, dev.ring.length, resumeFrom)
        const replay = dev.ring.slice(skip)
        if (replay.length) link.deliver(new Uint8Array(replay))
      }, 30)
    },
    resizePty() {},
    closePty() {},
    sendPtyInput() {},
  }
  return link
}

let setLinkOuter = null
function App() {
  const [link, setLink] = useState(() => fakeLink('A'))
  setLinkOuter = setLink
  return <WebTerminal link={link} peerName="web-vps" relation="one-time" route="direct" T={T} font="monospace" instanceId="harness-1" viewportPinned onClose={() => {}} />
}

window.__h = {
  produce,
  tick() { dev.n += 1; produce(`LINE-${dev.n}\r\n`) },
  // The channel dies under the live shell; the app has not swapped links yet.
  dropChannel() { if (dev.bound) { dev.bound.channel.readyState = 'closed'; dev.bound = null } },
  // ICE loses the path on the CURRENT link (channel still "open"), then the
  // same link recovers. The device detached the shell meanwhile.
  pcDown() { const l = dev.bound; if (l) { l.pc.connectionState = 'disconnected'; dev.bound = null; window.__downLink = l } },
  pcUp() { if (window.__downLink) window.__downLink.pc.connectionState = 'connected' },
  // The app hands the terminal a fresh link (the reconnect).
  newLink(id) { setLinkOuter(fakeLink(id)) },
  opens: () => dev.opens,
  delivered: () => dec.decode(new Uint8Array(window.__delivered)),
  bar: () => (document.querySelector('[aria-expanded]') || {}).innerText || '',
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />)
