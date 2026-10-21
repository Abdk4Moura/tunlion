// Focused render harness for the local device identity / name UI.
//
// Mounts the REAL Tunlion component with a small local state, so editing the
// name field exercises the same presentation path the app uses. The spec reads
// window.__renames to prove a chosen name reaches the hook callback; the hook's
// own persistence/relay behavior is covered by peer-reload.spec.cjs.
//
//   ?superseded=1  render the "another tab took over" state
//   ?phone=1       force the narrow layout
import React from 'react'
import ReactDOM from 'react-dom/client'
import Tunlion from '../src/ui/Tunlion.jsx'

const params = new URLSearchParams(window.location.search)
const phone = params.get('phone') === '1'
const superseded = params.get('superseded') === '1'
const initialName = 'silken-chickadee'

window.__renames = []
window.__reloads = 0

function Harness() {
  const [state, setState] = React.useState({
    roomScope: 'auto',
    roomId: 'ui-demo',
    roomUrl: 'http://127.0.0.1/rooms/ui-demo',
    roomCode: '',
    network: 'Wi-Fi',
    localHelper: null,
    connected: true,
    signalingKind: 'ws',
    deviceName: initialName,
    // Before the first welcome `me` is null; the local name must still show.
    me: null,
    peers: [
      { id: 'p-peer', uid: 'u-peer', name: 'leafy-bronco', status: 'ready', route: 'direct', lastSeen: 'now', shell: false },
      { id: 'p-other', uid: 'u-other', name: 'pixel', status: 'connecting', route: null, lastSeen: 'now', shell: false },
    ],
    knownDevices: [],
    transfers: [],
    pendingKeeps: [],
    pendingPakeKeep: [],
    pairStatus: null,
    superseded: superseded ? 'A newer tab or reload for this device took over the session.' : null,
  })

  const onRenameSelf = (raw) => {
    const next = String(raw == null ? '' : raw).trim() || state.deviceName
    window.__renames.push(next)
    setState((s) => ({ ...s, deviceName: next, me: { ...s.me, name: next } }))
    return next
  }

  return React.createElement(Tunlion, {
    state,
    ui: { theme: 'dark', forceMobile: phone },
    onRenameSelf,
    onReloadTab: () => { window.__reloads += 1 },
    onSendFiles: () => {}, onAccept: () => {}, onDecline: () => {}, onSave: () => {}, onClear: () => {},
    onCopyRoomLink: () => {}, onPairWithCode: () => {}, onReceiveWithCode: () => {},
    onGenerateCode: () => {}, onUseAutoRoom: () => {},
    onAcceptKeep: () => {}, onDeclineKeep: () => {},
    onAcceptPakeKeep: () => {}, onDeclinePakeKeep: () => {},
    onForgetDevice: () => {}, onRenameDevice: () => {},
  })
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Harness))
