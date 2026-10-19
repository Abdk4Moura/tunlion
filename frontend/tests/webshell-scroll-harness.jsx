// Focused harness for mode-aware touch scrolling (webshell-scroll.spec.cjs).
// Mounts the REAL WebTerminal against a fake PeerLink, so the spec drives the
// real xterm 6 instance: output, buffer type, DEC mouse modes, and the exact
// bytes the terminal would have sent to the PTY over the data channel.
import React from 'react'
import ReactDOM from 'react-dom/client'
import WebTerminal from '../src/ui/WebTerminal.jsx'

const enc = new TextEncoder()
const dec = new TextDecoder()
const T = {
  mode: 'dark', bg: '#0A0B0C', panel: '#0F1113', panel2: '#0C0E10', line: '#1E2227', lineSoft: '#15181C', grid: '#121417',
  text: '#D9DEE3', sub: '#9AA1A8', dim: '#666C73', faint: '#3C424A', ok: '#7CF6C8', warn: '#FFC857', bad: '#E5484D', recv: '#5B9DFF', onAccent: '#06120D',
}

const inputs = []
let active = null

function fakeLink() {
  return {
    channel: { readyState: 'open', send: () => {} },
    pc: { connectionState: 'connected' },
    _ptySid: null,
    onPtyData: () => {}, onPtyClose: () => {}, onPtyReady: () => {},
    openPty() {
      this._ptySid = 1
      active = this
      setTimeout(() => { this.onPtyReady() }, 0)
    },
    resizePty() {},
    closePty() { this._ptySid = null },
    sendPtyInput(u8) { inputs.push(dec.decode(u8)) },
  }
}

const link = fakeLink()

function state() {
  const t = window.__webterm
  if (!t) return null
  const b = t.buffer.active
  const screen = document.querySelector('[data-testid="term-host"] .xterm-screen')
  const rect = screen ? screen.getBoundingClientRect() : { left: 0, top: 0, width: 0, height: 0 }
  const ta = document.querySelector('.xterm-helper-textarea')
  return {
    bufferType: b.type,
    baseY: b.baseY,
    viewportY: b.viewportY,
    rows: t.rows,
    cols: t.cols,
    mouseTrackingMode: t.modes.mouseTrackingMode,
    applicationCursorKeys: t.modes.applicationCursorKeysMode,
    screen: { left: rect.left, top: rect.top, width: rect.width, height: rect.height },
    cell: { width: rect.width / (t.cols || 1), height: rect.height / (t.rows || 1) },
    textarea: ta ? {
      autocorrect: ta.getAttribute('autocorrect'),
      autocapitalize: ta.getAttribute('autocapitalize'),
      autocomplete: ta.getAttribute('autocomplete'),
      spellcheck: ta.getAttribute('spellcheck'),
      enterkeyhint: ta.getAttribute('enterkeyhint'),
      ariaAutocomplete: ta.getAttribute('aria-autocomplete'),
    } : null,
  }
}

window.__scroll = {
  // Write output exactly as a PTY chunk would arrive, and resolve after xterm
  // has parsed it (so buffer/mode assertions are not racing the parser).
  feed(text) {
    return new Promise((resolve) => {
      const t = window.__webterm
      if (!t) { resolve(false); return }
      t.write(text, () => resolve(true))
    })
  },
  // Push a raw PTY chunk through WebTerminal's own onPtyData path (predictor,
  // syncBar, write queue). Returns after the write callback has run.
  feedLink(text) {
    return new Promise((resolve) => {
      if (!active) { resolve(false); return }
      const t = window.__webterm
      let done = false
      const finish = () => { if (!done) { done = true; resolve(true) } }
      active.onPtyData(enc.encode(text))
      // onPtyData's completion callback is internal; parsing a second no-op
      // write with a callback orders us after the first chunk.
      t.write('', finish)
      setTimeout(finish, 250)
    })
  },
  inputs: () => inputs.slice(),
  takeInputs() { return inputs.splice(0, inputs.length) },
  clearInputs() { inputs.length = 0 },
  state,
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <WebTerminal
    link={link}
    peerName="scroll-vps"
    relation="remembered"
    route="direct"
    T={T}
    accent="#7CF6C8"
    font="monospace"
    instanceId="scroll-harness"
    viewportPinned
    onClose={() => {}}
  />,
)
