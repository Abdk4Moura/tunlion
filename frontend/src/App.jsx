// App: wires the real useTunlion() networking to the Tunlion UI.
// The presentation lives in ui/Tunlion.jsx (ported from the Claude Design
// handoff); here we map its callback props to the hook's actions and carry a
// small, persisted `ui` preference set (theme/accent/density/columns/font).

import { useCallback, useEffect, useState } from 'react'
import Tunlion from './ui/Tunlion.jsx'
import { useTunlion } from './lib/useTunlion.js'

const UI_DEFAULTS = { theme: 'dark', accent: 'green', density: 'airy', columns: 'auto', font: 'jetbrains' }

function loadUiPrefs() {
  try {
    return { ...UI_DEFAULTS, ...JSON.parse(localStorage.getItem('tunlion.ui') || '{}') }
  } catch {
    return { ...UI_DEFAULTS }
  }
}

export default function App() {
  const qs = useTunlion()
  const [prefs, setPrefs] = useState(loadUiPrefs)

  useEffect(() => {
    try {
      localStorage.setItem('tunlion.ui', JSON.stringify(prefs))
    } catch {}
  }, [prefs])

  const ui = {
    ...prefs,
    onToggleTheme: () => setPrefs((p) => ({ ...p, theme: p.theme === 'light' ? 'dark' : 'light' })),
  }

  const onCopyRoomLink = useCallback(() => {
    if (qs.roomUrl) navigator.clipboard.writeText(qs.roomUrl).catch(() => {})
  }, [qs.roomUrl])

  return (
    <Tunlion
      state={qs}
      ui={ui}
      onSendFiles={qs.sendFiles}
      onAccept={qs.acceptTransfer}
      onDecline={qs.declineTransfer}
      onSave={qs.saveTransfer}
      onClear={qs.clearTransfer}
      onCopyRoomLink={onCopyRoomLink}
      onPairWithCode={qs.pairWithCode}
      onReceiveWithCode={qs.receiveWithCode}
      onGenerateCode={qs.generateCode}
      onUseAutoRoom={qs.useAutoRoom}
      onAcceptKeep={qs.acceptKeep}
      onDeclineKeep={qs.declineKeep}
      onAcceptPakeKeep={qs.acceptPakeKeep}
      onDeclinePakeKeep={qs.declinePakeKeep}
      onForgetDevice={qs.forgetDevice}
      onRenameDevice={qs.renameDevice}
    />
  )
}
