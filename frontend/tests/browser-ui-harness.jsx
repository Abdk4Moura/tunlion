// Focused render harness for the new browser UI (browser-ui.spec.cjs).
// Mounts the REAL Tunlion component with an injected state, exactly as the
// relay-honesty and pakekeep harnesses do, so the gate can drive the screens
// without a live peer. Every callback records its arguments on window.__calls
// so the spec can assert which hook action a click reached.
//
//   ?theme=light|dark   palette
//   ?phone=1            force the phone layout (bottom nav, full-bleed shell)
import React from 'react'
import ReactDOM from 'react-dom/client'
import Tunlion from '../src/ui/Tunlion.jsx'
// The real global stylesheet (focus rings, mark animations), loaded as text by
// the spec's esbuild call and injected, so the gate sees what the app ships.
import css from '../src/index.css'

const styleEl = document.createElement('style')
styleEl.textContent = css
document.head.appendChild(styleEl)

const params = new URLSearchParams(window.location.search)
const theme = params.get('theme') === 'light' ? 'light' : 'dark'
const phone = params.get('phone') === '1'

window.__calls = []
const rec = (name) => (...args) => {
  window.__calls.push({ name, args: args.map((a) => (a && typeof a === 'object' && 'length' in a ? Array.from(a).map((f) => f.name || String(f)) : a)) })
}

// A mock PeerLink: answers openPty and echoes input, so the real WebTerminal
// mounts and draws its bar and key row.
const enc = new TextEncoder()
function mockLink() {
  return {
    channel: { readyState: 'open', send: () => {} },
    _ptySid: null,
    onPtyData: () => {}, onPtyClose: () => {}, onPtyReady: () => {},
    openPty() {
      this._ptySid = 1
      setTimeout(() => { this.onPtyReady(); this.onPtyData(enc.encode('sam@web-vps:~$ ')) }, 30)
    },
    resizePty() {},
    closePty() { this._ptySid = null },
    sendPtyInput(u8) { this.onPtyData(u8) },
  }
}
const links = {}

const state = {
  roomScope: 'auto',
  roomId: 'ui-demo',
  roomUrl: 'http://127.0.0.1/rooms/ui-demo',
  roomCode: '',
  network: 'Wi-Fi',
  localHelper: null,
  connected: true,
  signalingKind: 'ws',
  me: { name: 'me', uid: 'meuid' },
  peers: [
    // remembered, online, offers a shell: Shell + Send files
    { id: 'p-vps', uid: 'u-vps', name: 'root@vps', known: 'web-vps', status: 'ready', route: 'direct', lastSeen: 'now', shell: true },
    // remembered, online, no shell: Send files only
    { id: 'p-laptop', uid: 'u-laptop', name: 'laptop', known: 'laptop', status: 'ready', route: 'local', lastSeen: 'now', shell: false },
    // a stranger nearby that advertises a shell: never a Shell button (not remembered)
    { id: 'p-stranger', uid: 'u-stranger', name: 'pixel', status: 'ready', route: 'direct', lastSeen: 'now', shell: true },
    // remembered but not reachable: no buttons at all
    { id: 'p-off', uid: 'u-off', name: 'nas', known: 'nas', status: 'failed', route: null, lastSeen: '3 h ago', shell: true },
  ],
  knownDevices: [
    { name: 'web-vps', caps: ['transfer'], addedAt: Date.UTC(2026, 9, 1) },
    { name: 'laptop', caps: ['transfer'], addedAt: Date.UTC(2026, 9, 2) },
    { name: 'nas', caps: ['transfer'], addedAt: Date.UTC(2026, 9, 3) },
    // remembered but not in the room at all
    { name: 'old-phone', caps: ['transfer'], addedAt: Date.UTC(2026, 8, 1) },
  ],
  transfers: [],
  pendingKeeps: [],
  pendingPakeKeep: [],
  pairStatus: null,
  getLink: (pid) => (links[pid] = links[pid] || mockLink()),
  getLinkByUid: (uid) => {
    const p = state.peers.find((x) => x.uid === uid)
    return p ? state.getLink(p.id) : null
  },
}

function Harness() {
  return React.createElement(Tunlion, {
    state,
    ui: { theme, forceMobile: phone, onToggleTheme: rec('toggleTheme') },
    onSendFiles: rec('sendFiles'), onAccept: rec('accept'), onDecline: rec('decline'), onSave: rec('save'), onClear: rec('clear'),
    onCopyRoomLink: rec('copyRoomLink'), onPairWithCode: rec('pairWithCode'), onReceiveWithCode: rec('receiveWithCode'),
    onGenerateCode: rec('generateCode'), onUseAutoRoom: rec('useAutoRoom'),
    onAcceptKeep: rec('acceptKeep'), onDeclineKeep: rec('declineKeep'), onAcceptPakeKeep: rec('acceptPakeKeep'), onDeclinePakeKeep: rec('declinePakeKeep'),
    onForgetDevice: rec('forgetDevice'), onRenameDevice: rec('renameDevice'),
  })
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Harness))
