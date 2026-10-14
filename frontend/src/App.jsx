// App: wires the real useTunlion() networking to the Tunlion UI.
// The presentation lives in ui/Tunlion.jsx; here we map its callback props to
// the hook's actions and keep one persisted preference: the theme. With no
// choice saved, the theme follows the system setting and tracks it live.

import { useCallback, useEffect, useState } from 'react'
import Tunlion from './ui/Tunlion.jsx'
import { useTunlion } from './lib/useTunlion.js'
import { makeTheme, systemMode } from './ui/theme.js'

const CODE_IN_LINK = /^[a-z]+(?:-[a-z]+)*-[0-9]{3,5}$/i

function loadTheme() {
  try {
    const p = JSON.parse(localStorage.getItem('tunlion.ui') || '{}')
    return p.theme === 'light' || p.theme === 'dark' ? p.theme : null
  } catch {
    return null
  }
}

// A shared link carries the code after the #, so it never reaches a server or a
// referrer. Read it once, then clear it from the address bar so a reload or a
// copied URL does not carry a spent code around.
function takeCodeFromLink() {
  try {
    const h = decodeURIComponent((window.location.hash || '').slice(1)).trim()
    if (!h || !CODE_IN_LINK.test(h)) return ''
    window.history.replaceState(null, '', window.location.pathname + window.location.search)
    return h.toUpperCase()
  } catch {
    return ''
  }
}

export default function App() {
  const qs = useTunlion()
  const [chosen, setChosen] = useState(loadTheme)
  const [sys, setSys] = useState(systemMode)
  const [initialCode, setInitialCode] = useState(takeCodeFromLink)
  const theme = chosen || sys

  useEffect(() => {
    let mq
    try { mq = window.matchMedia('(prefers-color-scheme: light)') } catch { return }
    const on = () => setSys(mq.matches ? 'light' : 'dark')
    mq.addEventListener ? mq.addEventListener('change', on) : mq.addListener(on)
    return () => { mq.removeEventListener ? mq.removeEventListener('change', on) : mq.removeListener(on) }
  }, [])

  // A code link pasted into this same tab changes only the fragment (no reload).
  useEffect(() => {
    const on = () => { const c = takeCodeFromLink(); if (c) setInitialCode(c) }
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])

  useEffect(() => {
    try {
      localStorage.setItem('tunlion.ui', JSON.stringify(chosen ? { theme: chosen } : {}))
    } catch {}
  }, [chosen])

  // Paint the page behind the app in the same colour, so overscroll and the
  // area under the phone's bars never flash the other theme.
  useEffect(() => {
    const T = makeTheme(theme)
    document.documentElement.style.background = T.bg
    document.documentElement.style.colorScheme = theme
    const meta = document.querySelector('meta[name=theme-color]')
    if (meta) meta.setAttribute('content', T.bg)
  }, [theme])

  const ui = {
    theme,
    onToggleTheme: () => setChosen(theme === 'light' ? 'dark' : 'light'),
  }

  const onCopyRoomLink = useCallback(() => {
    if (qs.roomUrl) navigator.clipboard.writeText(qs.roomUrl).catch(() => {})
  }, [qs.roomUrl])

  return (
    <Tunlion
      state={qs}
      ui={ui}
      initialCode={initialCode}
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
