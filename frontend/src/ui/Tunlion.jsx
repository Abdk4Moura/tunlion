/* Tunlion: the browser UI.
   Presentation only: driven by `state` + callbacks whose names match
   useTunlion(). An optional `ui` prop carries the theme ('light' | 'dark') and
   the theme toggle; with no theme given it follows the system setting.

   Layout follows the "tunlion browser" design: a header with Home and Devices,
   one code box, a drop zone, the people and devices here now, transfers, and a
   device list. Only what today's protocol does is shown. Nothing here fakes the
   redesign's later pieces (one-time shell, asks, end times, cut off). */

import { useState, useRef, useCallback, useEffect, useLayoutEffect } from 'react'
import { createPortal } from 'react-dom'
import WebTerminal from './WebTerminal.jsx'
import DeviceSheet from './DeviceSheet.jsx'
import CommandPalette from './CommandPalette.jsx'
import DiagPanel from './DiagPanel.jsx'
import { makeTheme, terminalTheme, systemMode, FONT_SANS, FONT_MONO } from './theme.js'
import { pakeReady, previewCustomCode } from '../lib/pairing.js'
import { mintNameplate } from '../lib/words.js'

// Relay honesty (transport-resilience P1, §3.5). Relay (TURN) is still
// end-to-end encrypted but is NOT a direct link; the "no middleman on the wire"
// property is gone, so it must be LOUD and HONEST wherever it appears. The exact
// words are chosen to neither over-claim ("insecure/exposed", false, it's
// encrypted) nor under-claim ("direct/private", false, there IS a middleman on
// the wire). Single source of truth so the row, sheet and header all agree.
const RELAY_EXPLAINER =
  'On relay: routed through a TURN server, not a direct link. Still end-to-end encrypted; the relay forwards bytes it can’t read.'

// ---- data helpers -----------------------------------------------------------
function formatBytes(n) {
  if (n == null) return '-'
  if (n < 1024) return n + ' B'
  const u = ['KB', 'MB', 'GB', 'TB']
  let i = -1
  do {
    n /= 1024
    i++
  } while (n >= 1024 && i < u.length - 1)
  return (n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i]
}

function fileTag(t) {
  const ext = (t.name.split('.').pop() || '').toUpperCase()
  return ext.length <= 4 ? ext : ((t.mime || '').split('/').pop() || 'FILE').toUpperCase()
}

const STATUS_LABEL = {
  offered: 'offered',
  transferring: 'sending',
  paused: 'paused',
  complete: 'done',
  declined: 'declined',
  failed: 'failed',
}
const PEER_STATUS_LABEL = { ready: 'ready', connecting: 'connecting', failed: 'unreachable', away: 'away, back soon' }

function peerName(p) {
  return p.known || p.verified || p.name
}

// Turn the hook's pairStatus into the design's failure text (B7): what happened,
// then one next action. Anything not recognised is shown as the hook wrote it.
function codeFeedback(ps) {
  if (!ps) return null
  if (ps === 'pairing') return { tone: 'wait', text: 'Checking the code…' }
  if (ps === 'paired') return { tone: 'ok', text: 'Code accepted. Both sides proved they hold the same code.' }
  if (ps === 'connected') return { tone: 'ok', text: 'Code accepted. Waiting for the file.' }
  const s = String(ps)
  if (/key confirmation failed/i.test(s)) return { tone: 'bad', text: "That code didn't match. Check the words and try again.", action: 'Try again' }
  if (/did not work|expired|already used/i.test(s)) return { tone: 'bad', text: "That code didn't work. It may be mistyped, already used (codes work once), or expired. Ask for a new one.", action: 'Enter another code' }
  if (/left before/i.test(s)) return { tone: 'bad', text: 'The other device left before you connected. Ask for a new code.', action: 'Enter another code' }
  if (/did not finish/i.test(s)) return { tone: 'bad', text: "The other device didn't finish. Nothing was kept. Ask for a new code.", action: 'Enter another code' }
  if (/too many attempts/i.test(s)) return { tone: 'bad', text: 'Too many tries. Wait a moment, then try again.', action: 'Try again' }
  if (/missing its number|full code|not valid/i.test(s)) return { tone: 'bad', text: 'That is not a full code. A code is words and a number, like brave-otter-3141.', action: 'Try again' }
  if (/older version/i.test(s)) return { tone: 'bad', text: 'The other device runs an older tunlion and cannot connect securely. Update it. Nothing was kept.' }
  return { tone: 'bad', text: s.charAt(0).toUpperCase() + s.slice(1) }
}

function useCopied() {
  const [hit, setHit] = useState(false)
  const fire = useCallback((fn) => {
    try {
      fn && fn()
    } catch (e) {}
    setHit(true)
    setTimeout(() => setHit(false), 1300)
  }, [])
  return [hit, fire]
}

// ---- atoms ------------------------------------------------------------------

// The tunlion mark: an arch with the accent block inside. anim 'pulse' means
// waiting on the other side; 'knock' means something waits on you. Both stop
// under prefers-reduced-motion (index.css).
function Mark({ T, size = 24, anim }) {
  const small = size < 24
  const cls = anim === 'knock' ? 'tl-knock' : anim === 'pulse' ? 'tl-pulse' : undefined
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" style={{ display: 'block', flexShrink: 0 }} aria-hidden="true">
      {small
        ? <path d="M10 80 V26 Q10 8 28 8 H52 Q70 8 70 26 V80" fill="none" stroke={T.ink} strokeWidth="16" />
        : <path d="M12 74 V24 Q12 10 26 10 H54 Q68 10 68 24 V74" fill="none" stroke={T.ink} strokeWidth="10" />}
      {small
        ? <rect className={cls} x="31" y="42" width="18" height="38" fill={T.acc} />
        : <rect className={cls} x="33" y="46" width="14" height="28" fill={T.acc} />}
    </svg>
  )
}

function Btn({ children, kind = 'sec', onClick, small, full, disabled, T, narrow, title, ariaLabel, testid, type }) {
  const base = {
    font: '600 14px ' + FONT_SANS, minHeight: small && !narrow ? 36 : 44, padding: small ? '0 12px' : '0 18px',
    borderRadius: 7, cursor: disabled ? 'default' : 'pointer', display: 'inline-flex', alignItems: 'center',
    justifyContent: 'center', gap: 8, width: full ? '100%' : 'auto', opacity: disabled ? 0.45 : 1, whiteSpace: 'nowrap',
  }
  const k = {
    pri: { background: T.ink, color: T.inv, border: '1.5px solid ' + T.ink },
    sec: { background: 'transparent', color: T.ink, border: '1.5px solid ' + T.ink },
    ghost: { background: 'transparent', color: T.sub, border: '1.5px solid transparent' },
    dan: { background: 'transparent', color: T.bad, border: '1.5px solid ' + T.bad },
  }[kind]
  return (
    <button type={type || 'button'} onClick={disabled ? undefined : onClick} disabled={disabled} title={title} aria-label={ariaLabel}
      data-testid={testid} className="tl-focus" style={{ ...base, ...k }}>{children}</button>
  )
}

function Tag({ children, tone = 'n', T }) {
  const c = { n: [T.soft, T.sub], ok: [T.okBg, T.ok], bad: [T.badBg, T.bad] }[tone]
  return (
    <span style={{ font: "600 10.5px/1 " + FONT_MONO, letterSpacing: '.06em', textTransform: 'uppercase', padding: '5px 7px', borderRadius: 4, background: c[0], color: c[1], whiteSpace: 'nowrap' }}>{children}</span>
  )
}

function Section({ children, T, right }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, margin: '6px 0 2px' }}>
      <h2 style={{ margin: 0, font: '600 11px ' + FONT_MONO, letterSpacing: '.1em', textTransform: 'uppercase', color: T.sub }}>{children}</h2>
      {right}
    </div>
  )
}

function Notice({ children, action, onAction, tone = 'bad', T, narrow }) {
  return (
    <div role={tone === 'bad' ? 'alert' : 'status'} style={{
      display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', padding: '12px 14px', borderRadius: 7,
      border: '1.5px solid ' + (tone === 'bad' ? T.bad : T.rule), color: tone === 'bad' ? T.bad : T.ink, fontSize: 14.5, background: T.surf,
    }}>
      <span style={{ flex: 1, minWidth: 200, lineHeight: 1.45 }}>{children}</span>
      {action && <Btn small T={T} narrow={narrow} onClick={onAction}>{action}</Btn>}
    </div>
  )
}

function routeMeta(route, T) {
  if (route === 'local') return { label: 'LAN', tone: 'ok', tip: 'Direct link on your network: bytes go straight between you, no middleman.' }
  if (route === 'direct') return { label: 'direct', tone: 'ok', tip: 'Direct link: bytes go straight between you, no middleman.' }
  // relayed is the ONLY route with a middleman on the wire; it gets the loud
  // amber ⚠ treatment + the honest explainer (it is still E2E-encrypted).
  if (route === 'relayed') return { label: 'RELAY', relay: true, tip: RELAY_EXPLAINER }
  return null
}

function RouteBadge({ route, T }) {
  const m = routeMeta(route, T)
  if (!m) return null
  // Relay: LOUD. Amber ⚠ chip with an amber border, never calm. The honest
  // explainer rides in the title (hover/tap) and is repeated in the device sheet.
  if (m.relay) {
    return (
      <span data-testid="route-relay" title={m.tip} style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, font: '700 11px/1 ' + FONT_MONO, letterSpacing: '.06em',
        padding: '5px 7px', borderRadius: 4, border: '1.5px solid ' + T.warn, background: T.warnBg,
        color: T.warn, cursor: 'help', whiteSpace: 'nowrap',
      }}>
        <span aria-hidden="true">⚠</span>{m.label}
      </span>
    )
  }
  return <span title={m.tip}><Tag tone={m.tone} T={T}>{m.label}</Tag></span>
}

// Global relay-honesty indicator (transport-resilience P1, §3.3). Appears ONLY
// when ≥1 connected peer is on relay, so the user is never unaware even if the
// relayed row is scrolled off. Hidden entirely when everything is direct.
function RelayBanner({ peers, T }) {
  const relayed = (peers || []).filter((p) => p.route === 'relayed')
  const n = relayed.length
  if (n === 0) return null
  const names = relayed.map(peerName).join(', ')
  return (
    <span
      data-testid="relay-banner"
      title={RELAY_EXPLAINER + (names ? '\n\nOn relay: ' + names : '')}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6, font: '700 12px ' + FONT_SANS,
        padding: '6px 10px', borderRadius: 6, border: '1.5px solid ' + T.warn, color: T.warn, background: T.warnBg,
        cursor: 'help', whiteSpace: 'nowrap',
      }}
    >
      <span aria-hidden="true">⚠</span>
      <span>{n} on relay</span>
    </span>
  )
}

function LanChip({ localHelper, T }) {
  if (!localHelper || !localHelper.available) return null
  const n = (localHelper.peers || []).length
  const names = (localHelper.peers || []).map((p) => p.name + ' · ' + p.addr).join('\n')
  return (
    <span title={names} style={{ fontSize: 13, color: T.sub, whiteSpace: 'nowrap' }}>
      {n} on your network · works offline
    </span>
  )
}

// Cursor-safe auto-dash code field. The prior regression reformatted the whole
// string on every keystroke and let React reset the caret to the END, so any
// mid-string edit jumped to the tail. Here we (1) count the ALPHANUMERIC chars
// before the caret in the raw input, (2) format, (3) re-find that same Nth
// alphanumeric in the formatted string, and (4) restore the caret there in a
// layout effect (before paint). Counting alphanumerics, not raw offset, makes
// collapse/strip/paste/backspace all caret-stable regardless of length change.
function CodeInput({ id, value, onChange, format, onSubmit, onCancel, autoFocus, placeholder, invalid, describedBy, inputRef, T, big }) {
  const own = useRef(null)
  const ref = inputRef || own
  const caretRef = useRef(null)

  // Restore the caret AFTER React commits the new (formatted) value but BEFORE
  // the browser paints, so the user never sees it flicker to the end.
  useLayoutEffect(() => {
    if (caretRef.current != null && ref.current) {
      const pos = caretRef.current
      caretRef.current = null
      try { ref.current.setSelectionRange(pos, pos) } catch (e) {}
    }
  })

  const handleChange = (e) => {
    const el = e.target
    const raw = el.value
    const sel = el.selectionStart ?? raw.length
    // How many real (alphanumeric) chars sit before the caret in the raw text?
    const before = (raw.slice(0, sel).match(/[A-Za-z0-9]/g) || []).length
    const formatted = format(raw)
    // Walk the formatted string to just past the `before`-th alphanumeric.
    let seen = 0
    let pos = formatted.length
    if (before === 0) {
      pos = 0
    } else {
      for (let i = 0; i < formatted.length; i++) {
        if (/[A-Za-z0-9]/.test(formatted[i])) {
          seen++
          if (seen === before) { pos = i + 1; break }
        }
      }
    }
    // If the char just before the raw caret was a separator (the user just typed
    // a space/dash to end a word), step PAST the dash it became, so the next
    // word starts after the dash, not before it (which would shove the dash to
    // the tail). Conditional on the separator: a normal mid-word edit must NOT
    // skip, or the caret would jump over a real dash.
    if (sel > 0 && /[\s-]/.test(raw[sel - 1]) && formatted[pos] === '-') pos++
    caretRef.current = pos
    onChange(formatted)
  }

  return (
    <input ref={ref} id={id} autoFocus={autoFocus} value={value} onChange={handleChange}
      onKeyDown={(e) => { if (e.key === 'Enter') onSubmit(); if (e.key === 'Escape' && onCancel) onCancel() }}
      placeholder={placeholder} spellCheck="false" autoComplete="off" autoCapitalize="characters"
      aria-invalid={invalid ? 'true' : undefined} aria-describedby={describedBy}
      className="tl-input"
      style={{
        flex: 1, minWidth: 0, minHeight: big ? 54 : 46, borderRadius: 7, padding: '0 14px',
        font: (big ? '500 18px ' : '500 15px ') + FONT_MONO, letterSpacing: '.04em', textTransform: 'uppercase',
        background: T.surf, color: T.ink, border: '1.5px solid ' + (invalid ? T.bad : T.ink),
      }} />
  )
}

// "Choose your own code" entry. The user types words (and optionally a
// number); we show a LIVE normalized preview (the shared WASM normCode/splitCode,
// so it matches what SPAKE2 hashes), auto-append a dimmed connect number when
// they typed none, and gate Create on the >= 2-word strength floor, a gentle
// nudge, never a hard block on typing. On Create we hand the RAW typed string to
// onGenerateCode (the hook re-parses it with the same shared split).
function CustomCodeEntry({ onCreate, onCancel, T, narrow }) {
  const [typed, setTyped] = useState('')
  const [ready, setReady] = useState(false)
  // A stable machine-assigned number for the preview (so it doesn't reshuffle on
  // every keystroke); the hook mints the real one at create time.
  const autoNpRef = useRef(null)
  if (autoNpRef.current == null) { try { autoNpRef.current = mintNameplate() } catch { autoNpRef.current = '0000' } }

  useEffect(() => { pakeReady().then(() => setReady(true)).catch(() => setReady(true)) }, [])

  const format = (raw) => raw.toUpperCase().replace(/[\s-]+/g, '-').replace(/^-+/, '')
  let pv = null
  if (ready && typed.trim()) {
    try { pv = previewCustomCode(typed, autoNpRef.current) } catch { pv = null }
  }
  const canCreate = !!(pv && pv.strongEnough && pv.full)
  const doCreate = () => { if (canCreate) onCreate(typed) }

  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <label htmlFor="tl-custom-code" style={{ fontWeight: 600, fontSize: 15 }}>Choose your own words</label>
      <div style={{ display: 'flex', gap: 10, flexDirection: narrow ? 'column' : 'row' }}>
        <CodeInput id="tl-custom-code" autoFocus value={typed} onChange={setTyped} format={format}
          onSubmit={doCreate} onCancel={onCancel} placeholder="TWO WORDS OR MORE" T={T} describedBy="tl-custom-help" />
        <span style={{ display: 'flex', gap: 8 }}>
          <Btn kind="pri" T={T} narrow={narrow} onClick={doCreate} disabled={!canCreate} testid="custom-create">Create</Btn>
          <Btn T={T} narrow={narrow} onClick={onCancel}>Cancel</Btn>
        </span>
      </div>
      {pv && pv.full && (
        <div data-testid="custom-preview" style={{ font: '500 15px ' + FONT_MONO, letterSpacing: '.04em', color: T.ink }}>
          {pv.password}
          <span style={{ color: pv.autoAssigned ? T.sub : T.ink }}>-{pv.nameplate}</span>
          {pv.autoAssigned && <span style={{ fontSize: 13, color: T.sub, fontFamily: FONT_SANS }}>  (number added for you)</span>}
        </div>
      )}
      <div id="tl-custom-help" data-testid={pv && typed.trim() && !pv.strongEnough ? 'custom-nudge' : undefined}
        style={{ fontSize: 13, lineHeight: 1.45, color: pv && typed.trim() && !pv.strongEnough ? T.bad : T.sub }}>
        {pv && typed.trim() && !pv.strongEnough
          ? (pv.blockedReason || 'Use at least two words, like gigantic-element. Easier to say, harder to guess.')
          : 'Two words or more. A number is added if you leave it out.'}
      </div>
    </div>
  )
}

// The one code box. Today's protocol cannot tell from a code what it offers
// (that is the redesign's offer-in-code), and claiming a code burns it, so the
// box asks once what the code is for instead of guessing: receive a file, or
// remember a device. Receive is the default, since most codes people are handed
// are file codes.
function CodeBox({ state, onPairWithCode, onReceiveWithCode, initialCode, openEntryNonce, T, narrow }) {
  const [code, setCode] = useState(initialCode || '')
  const [mode, setMode] = useState('receive')
  const [submitted, setSubmitted] = useState(false)
  const inputRef = useRef(null)
  const id = 'tl-code-' + (narrow ? 'n' : 'w')

  // The command palette's "Pair with code" raises this nonce: focus the box in
  // remember mode (skip the initial 0 so we don't steal focus on mount).
  useEffect(() => {
    if (!openEntryNonce) return
    setMode('pair')
    try { inputRef.current && inputRef.current.focus() } catch (e) {}
  }, [openEntryNonce])

  useEffect(() => { if (initialCode) setCode(initialCode) }, [initialCode])

  // Auto-dash: the user types/pastes "grand hawk ruby 8045" or "GRANDHAWKRUBY8045"
  // and sees dashes either way. Uppercase, collapse any run of spaces/dashes to a
  // single dash, and drop a leading dash. Safe because the submit path still
  // canonicalizes via normCode (WASM) before SPAKE2.
  const formatCode = (raw) => raw.toUpperCase().replace(/[\s-]+/g, '-').replace(/^-+/, '')

  // Keep the box filled after submitting so the person sees the result and can
  // fix a mistyped code in place.
  const submit = () => {
    const c = code.trim()
    if (!c) { try { inputRef.current && inputRef.current.focus() } catch (e) {} ; return }
    setSubmitted(true)
    if (mode === 'receive') onReceiveWithCode(c)
    else onPairWithCode(c)
  }

  // Show the hook's status when this box started the attempt, or when it is an
  // outcome worth seeing anyway. A 'pairing' left over from an earlier minted
  // code (the person pressed Done) is not news, so it stays hidden.
  const ps = state.pairStatus
  const fb = ps && (submitted || ps !== 'pairing') ? codeFeedback(ps) : null
  const invalid = fb && fb.tone === 'bad'
  const retry = () => {
    if (fb && fb.action === 'Enter another code') setCode('')
    setSubmitted(false)
    try { inputRef.current && inputRef.current.focus() } catch (e) {}
  }

  const modeBtn = (k, label) => (
    <button type="button" role="radio" aria-checked={mode === k} onClick={() => setMode(k)} className="tl-focus"
      style={{
        flex: 1, minHeight: 44, font: '500 14px ' + FONT_SANS, border: 0, borderLeft: k === 'pair' ? '1px solid ' + T.ink : 0,
        background: mode === k ? T.ink : 'transparent', color: mode === k ? T.inv : T.ink, cursor: 'pointer', padding: '0 10px',
      }}>{label}</button>
  )

  return (
    <div style={{ display: 'grid', gap: 10 }} data-testid={`code-entry-${mode}`}>
      <label htmlFor={id} style={{ fontWeight: 600, fontSize: 15 }}>Enter a code</label>
      <div style={{ display: 'flex', gap: 10, flexDirection: narrow ? 'column' : 'row' }}>
        <CodeInput id={id} inputRef={inputRef} value={code} onChange={(v) => { setCode(v); if (submitted) setSubmitted(false) }} format={formatCode}
          onSubmit={submit} placeholder="WORDS-AND-NUMBER" invalid={invalid} describedBy={id + '-help'} T={T} big />
        <Btn kind="pri" T={T} narrow={narrow} onClick={submit} testid="code-connect">Connect</Btn>
      </div>
      <div role="radiogroup" aria-label="What is the code for?" style={{ display: 'flex', border: '1.5px solid ' + T.ink, borderRadius: 7, overflow: 'hidden', maxWidth: narrow ? 'none' : 420 }}>
        {modeBtn('receive', 'Receive a file')}
        {modeBtn('pair', 'Remember a device')}
      </div>
      <div id={id + '-help'} aria-live="polite">
        {fb ? (
          fb.tone === 'bad'
            ? (
              <div role="alert" style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', fontSize: 14, color: T.bad, lineHeight: 1.45 }}>
                <span data-testid="pair-error" style={{ flex: 1, minWidth: 200 }}>{fb.text}</span>
                {fb.action && <Btn small T={T} narrow={narrow} onClick={retry}>{fb.action}</Btn>}
              </div>
            )
            : (
              <div data-testid="pair-state" style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 14, color: fb.tone === 'ok' ? T.ok : T.ink }}>
                {fb.tone === 'wait' && <Mark T={T} size={20} anim="pulse" />}
                <span>{fb.text}</span>
              </div>
            )
        ) : (
          <span style={{ fontSize: 13, color: T.sub, lineHeight: 1.45 }}>
            {mode === 'receive'
              ? 'For a code from tunlion send, or from someone sending you a file here.'
              : 'For a code from tunlion add on one of your computers. You choose whether to remember it.'}
          </span>
        )}
      </div>
    </div>
  )
}

// The minted code, shown big while it waits to be claimed.
function CodeCard({ code, onDone, T, narrow, toast }) {
  const lower = String(code || '').toLowerCase()
  const link = (typeof window !== 'undefined' ? window.location.origin : 'https://tunlion.autumated.com') + '/#' + lower
  const copy = (text, msg) => {
    try {
      navigator.clipboard.writeText(text).then(() => toast(msg), () => toast('Copy did not work here. Select the code and copy it.'))
    } catch (e) { toast('Copy did not work here. Select the code and copy it.') }
  }
  return (
    <div style={{ display: 'grid', gap: 12, padding: 16, borderRadius: 9, border: '1.5px solid ' + T.ink, background: T.surf }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Mark T={T} size={22} anim="pulse" />
        <span style={{ fontWeight: 600, fontSize: 15 }}>Waiting for the other device</span>
      </div>
      <span data-testid="room-code" style={{ font: '600 ' + (narrow ? 22 : 28) + 'px ' + FONT_MONO, letterSpacing: '.02em', wordBreak: 'break-all', userSelect: 'all' }}>{lower}</span>
      <span style={{ fontSize: 13.5, color: T.sub, lineHeight: 1.45 }}>
        Say it aloud or send the link. They enter it on tunlion.autumated.com, then you can swap files. The code works once.
      </span>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <Btn small T={T} narrow={narrow} onClick={() => copy(lower, 'Code copied')}>Copy code</Btn>
        <Btn small T={T} narrow={narrow} onClick={() => copy(link, 'Link copied. The code is after the #, so it never reaches a server.')}>Copy link</Btn>
        <Btn small kind="ghost" T={T} narrow={narrow} onClick={onDone}>Done</Btn>
      </div>
    </div>
  )
}

// One person or device in the room. A row, not a tile: name, status, route, and
// buttons only for what this browser can do with it now.
function PeerRow({ peer, onSendFiles, onOpenSheet, onOpenTerminal, staged, onSendStaged, T, narrow }) {
  const ready = peer.status === 'ready'
  const [over, setOver] = useState(false)
  const inp = useRef(null)
  const rowRef = useRef(null)
  const known = !!peer.known
  const displayName = peerName(peer)
  const canSheet = ready && known && onOpenSheet
  const canTerminal = ready && known && !!peer.shell && onOpenTerminal
  const statusColor = ready ? T.ok : peer.status === 'connecting' || peer.status === 'away' ? T.warn : T.bad
  const openSheet = () => onOpenSheet && onOpenSheet(peer, rowRef.current ? rowRef.current.getBoundingClientRect() : null)
  const primary = () => {
    if (!ready) return
    if (canSheet) { openSheet(); return }
    if (inp.current) inp.current.click()
  }
  return (
    <div
      ref={rowRef}
      data-testid="peer-tile"
      data-route={peer.route || ''}
      role="button"
      tabIndex={0}
      aria-label={`${displayName}, ${PEER_STATUS_LABEL[peer.status] || peer.status}${peer.route === 'relayed' ? ', on relay' : ''}`}
      className="tl-focus"
      onClick={primary}
      onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) { e.preventDefault(); primary() } }}
      onContextMenu={(e) => { if (canSheet) { e.preventDefault(); openSheet() } }}
      onDragOver={(e) => { if (ready) { e.preventDefault(); setOver(true) } }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); if (ready && e.dataTransfer.files.length) onSendFiles(peer.id, e.dataTransfer.files) }}
      title={known ? 'Remembered: you two reconnect automatically, in any room, with no code.' : undefined}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '12px 14px', minHeight: 56,
        borderRadius: 8, border: '1.5px solid ' + (over ? T.ink : T.rule), background: over ? T.soft : T.surf,
        cursor: ready ? 'pointer' : 'default', opacity: ready ? 1 : 0.6, flexWrap: narrow ? 'wrap' : 'nowrap',
      }}
    >
      <input ref={inp} type="file" multiple style={{ display: 'none' }} tabIndex={-1} aria-hidden="true"
        onClick={(e) => e.stopPropagation()}
        onChange={(e) => { if (e.target.files.length) onSendFiles(peer.id, e.target.files); e.target.value = '' }} />
      <span style={{ display: 'grid', gap: 3, minWidth: 0, flex: 1 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flexWrap: 'wrap' }}>
          <b style={{ fontSize: 15, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '100%' }}>{displayName}</b>
          {/* Relay honesty: when a peer is on relay its ⚠ chip is the most
              important marker, so it comes first and never shrinks away. */}
          {peer.route === 'relayed' && <RouteBadge route="relayed" T={T} />}
          {known && <Tag T={T}>remembered</Tag>}
          {peer.route && peer.route !== 'relayed' && <RouteBadge route={peer.route} T={T} />}
        </span>
        <span style={{ fontSize: 13, color: T.sub, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          <span style={{ color: statusColor }}>{PEER_STATUS_LABEL[peer.status] || peer.status}</span>
          {/* the status line ALSO says "· via relay", so the warning survives
              even if the chip is scrolled past or cut off */}
          {peer.route === 'relayed' && <span style={{ color: T.warn }}> · via relay</span>}
          {peer.lastSeen ? <span> · {peer.lastSeen}</span> : null}
        </span>
      </span>
      {ready && (
        <span style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
          {staged && staged.length > 0 && (
            <Btn small kind="pri" T={T} narrow={narrow} onClick={() => onSendStaged(peer.id)} ariaLabel={`send the picked file to ${displayName}`}>Send here</Btn>
          )}
          {canTerminal && (
            <Btn small T={T} narrow={narrow} onClick={() => onOpenTerminal(peer)} ariaLabel={`open a shell on ${displayName}`} title={`open a shell on ${displayName}`}>Shell</Btn>
          )}
          {!(staged && staged.length) && (
            <Btn small T={T} narrow={narrow} onClick={() => inp.current && inp.current.click()} ariaLabel={`send files to ${displayName}`}>Send files</Btn>
          )}
        </span>
      )}
    </div>
  )
}

function Bar({ p, color, T }) {
  return (
    <div style={{ height: 8, borderRadius: 4, background: T.soft, overflow: 'hidden' }}>
      <div style={{ width: Math.max(0, Math.min(1, p)) * 100 + '%', height: '100%', background: color, transition: 'width .3s linear' }} />
    </div>
  )
}

function TransferRow({ t, onAccept, onDecline, onSave, onClear, T, narrow }) {
  const recv = t.direction === 'receive'
  const sc = t.status === 'complete' ? T.ok : t.status === 'failed' ? T.bad : T.sub
  const active = t.status === 'transferring'
  return (
    <div style={{ padding: '13px 0', borderBottom: '1px solid ' + T.rule, display: 'grid', gap: 8 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
        <span aria-hidden="true" style={{ color: T.sub, width: 14 }}>{recv ? '↓' : '↑'}</span>
        <span style={{ flex: 1, fontSize: 15, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{t.name}</span>
        <span style={{ fontSize: 13, color: T.sub, whiteSpace: 'nowrap' }}>{formatBytes(t.size)}</span>
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, color: T.sub }}>
        <Tag T={T}>{fileTag(t)}</Tag>
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{recv ? 'from ' : 'to '}{t.peerName}</span>
        <span style={{ marginLeft: 'auto', color: sc, whiteSpace: 'nowrap' }}>{STATUS_LABEL[t.status] || t.status}{active ? ' ' + Math.round(t.progress * 100) + '%' : ''}</span>
      </div>
      {(active || t.status === 'failed' || t.status === 'paused') && <Bar p={t.progress} color={t.status === 'failed' ? T.bad : T.ink} T={T} />}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {recv && t.status === 'offered' && (<><Btn small kind="pri" T={T} narrow={narrow} onClick={() => onAccept(t.id)}>Accept</Btn><Btn small T={T} narrow={narrow} onClick={() => onDecline(t.id)}>Decline</Btn></>)}
        {recv && t.status === 'complete' && <Btn small kind="pri" T={T} narrow={narrow} onClick={() => onSave(t.id)}>Save</Btn>}
        {!recv && t.status === 'offered' && <span style={{ fontSize: 13, color: T.sub }}>Waiting for them to accept…</span>}
        {t.status === 'paused' && <span style={{ fontSize: 13, color: T.sub }}>Paused. It resumes when you reconnect.</span>}
        {(t.status === 'complete' || t.status === 'declined' || t.status === 'failed' || t.status === 'paused') && <Btn small kind="ghost" T={T} narrow={narrow} onClick={() => onClear(t.id)}>Clear</Btn>}
      </div>
    </div>
  )
}

// L1-a (PAKE v2): after a code pairing, ask before remembering, with the name
// editable. Holds the draft name in its own state, seeded from the peer's
// display name. Accept stores under the chosen name (local-only, no wire ack).
function PakeKeepBanner({ k, onAcceptPakeKeep, onDeclinePakeKeep, T, narrow }) {
  const [name, setName] = useState(k.name || 'device')
  const accept = () => onAcceptPakeKeep?.(k.peerId, name)
  const id = 'tl-keep-' + k.peerId
  return (
    <div role="region" aria-label="Remember this device?" style={{ display: 'grid', gap: 10, padding: '14px 16px', borderRadius: 8, background: T.soft, border: '1.5px solid ' + T.ink }}>
      <span style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 15 }}>
        <Mark T={T} size={20} anim="knock" />
        <span><b>Paired.</b> Remember this device? You would reconnect automatically, with no code.</span>
      </span>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <label htmlFor={id} style={{ fontSize: 14, color: T.sub }}>Name</label>
        <input id={id} value={name} onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') accept() }}
          placeholder="device" className="tl-input"
          style={{ font: '500 15px ' + FONT_SANS, minHeight: 44, padding: '0 12px', flex: 1, minWidth: 140, borderRadius: 7, background: T.surf, color: T.ink, border: '1.5px solid ' + T.ink }} />
        <span style={{ display: 'flex', gap: 8 }}>
          <Btn kind="pri" small T={T} narrow={narrow} onClick={accept}>Remember</Btn>
          <Btn small T={T} narrow={narrow} onClick={() => onDeclinePakeKeep?.(k.peerId)}>Not now</Btn>
        </span>
      </div>
    </div>
  )
}

// Shell sessions: a slim row that only renders when ≥1 terminal is open or
// backgrounded. One chip per session: click to switch back, ✕ to close (which
// tears down its PTY).
function SessionsStrip({ sessions, activeId, onSwitch, onClose, T, narrow }) {
  if (!sessions.length) return null
  return (
    <div data-testid="sessions-strip" style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', WebkitOverflowScrolling: 'touch', paddingBottom: 2 }}>
      <span style={{ font: '600 11px ' + FONT_MONO, letterSpacing: '.1em', textTransform: 'uppercase', color: T.sub, flexShrink: 0 }}>Open shells</span>
      {sessions.map((s) => {
        const active = s.id === activeId
        const name = peerName(s.peer)
        return (
          <span key={s.id} data-testid="session-chip" data-session-active={active ? '1' : '0'}
            style={{ flexShrink: 0, display: 'inline-flex', alignItems: 'center', borderRadius: 7, border: '1.5px solid ' + T.ink, background: active ? T.ink : T.surf, color: active ? T.inv : T.ink }}>
            <button type="button" onClick={() => onSwitch(s.id)} className="tl-focus" title={`show the shell on ${name}`}
              style={{ font: '600 14px ' + FONT_SANS, minHeight: narrow ? 44 : 36, padding: '0 6px 0 12px', border: 0, background: 'none', color: 'inherit', cursor: 'pointer', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</button>
            <button type="button" data-testid="session-close" onClick={() => onClose(s.id)} className="tl-focus"
              aria-label={`close the shell on ${name}`} title={`close the shell on ${name}`}
              style={{ minWidth: narrow ? 44 : 32, minHeight: narrow ? 44 : 36, border: 0, background: 'none', color: 'inherit', cursor: 'pointer', fontSize: 15 }}>✕</button>
          </span>
        )
      })}
    </div>
  )
}

// Track the VISUAL viewport (the actually-visible region), not the layout
// viewport. On mobile the layout viewport is taller than what is on screen
// whenever the URL bar is showing or the soft keyboard is up, so a fixed inset:0
// box hangs below the fold and can be panned. Pinning the terminal overlay to
// these numbers makes it exactly fill what is visible, so nothing pans, and the
// key bar at its bottom sits right above the keyboard.
function useVisualViewport() {
  const read = () => {
    const vv = (typeof window !== 'undefined') && window.visualViewport
    if (vv) return { width: vv.width, height: vv.height, left: vv.offsetLeft, top: vv.offsetTop }
    if (typeof window !== 'undefined') return { width: window.innerWidth, height: window.innerHeight, left: 0, top: 0 }
    return { width: 0, height: 0, left: 0, top: 0 }
  }
  const [vp, setVp] = useState(read)
  useEffect(() => {
    const vv = window.visualViewport
    const onChange = () => setVp(read())
    if (vv) {
      vv.addEventListener('resize', onChange)
      vv.addEventListener('scroll', onChange)
    }
    window.addEventListener('resize', onChange)
    onChange()
    return () => {
      if (vv) { vv.removeEventListener('resize', onChange); vv.removeEventListener('scroll', onChange) }
      window.removeEventListener('resize', onChange)
    }
  }, [])
  return vp
}

// Suppress pinch-zoom only while a shell is on screen (so a pinch cannot turn
// the terminal into a pannable image), and restore the page's viewport meta on
// close so accessibility zoom elsewhere is never broken.
function useLockZoomWhile(active) {
  useEffect(() => {
    if (!active) return
    const meta = document.querySelector('meta[name=viewport]')
    if (!meta) return
    const prev = meta.getAttribute('content')
    meta.setAttribute('content', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover')
    return () => { if (prev != null) meta.setAttribute('content', prev) }
  }, [active])
}

// One toast at a time: a new one replaces the old. On phones it sits above the
// bottom nav so it never covers the nav or the button that raised it.
function useToast() {
  const [toast, setToast] = useState(null)
  const timer = useRef(null)
  const show = useCallback((msg) => {
    if (timer.current) clearTimeout(timer.current)
    const id = Date.now() + Math.random()
    setToast({ msg, id })
    timer.current = setTimeout(() => setToast((t) => (t && t.id === id ? null : t)), 3200)
  }, [])
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])
  return [toast, show]
}

export default function Tunlion(props) {
  const { state, onSendFiles, onAccept, onDecline, onSave, onClear, onCopyRoomLink,
    onPairWithCode, onReceiveWithCode, onGenerateCode, onUseAutoRoom, onAcceptKeep, onDeclineKeep,
    onAcceptPakeKeep, onDeclinePakeKeep, onForgetDevice, onRenameDevice, initialCode, ui = {} } = props
  const mode = ui.theme === 'light' || ui.theme === 'dark' ? ui.theme : systemMode()
  const T = makeTheme(mode)
  const TT = terminalTheme()
  const peers = state.peers || []
  const transfers = state.transfers || []
  const knownDevices = state.knownDevices || []
  const onToggleTheme = ui.onToggleTheme

  const [toast, showToast] = useToast()
  const [screen, setScreen] = useState('home')

  // Responsive: measure our own width so the same component works on desktop
  // and inside a phone frame. ui.forceMobile lets a host pin the phone layout.
  const rootRef = useRef(null)
  const [narrow, setNarrow] = useState(!!ui.forceMobile)
  useEffect(() => {
    if (ui.forceMobile) { setNarrow(true); return }
    const el = rootRef.current
    if (!el) return
    const measure = () => setNarrow(el.clientWidth < 720)
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [ui.forceMobile])

  // Shell sessions: a LIST of open terminals. Each session's WebTerminal stays
  // MOUNTED for its lifetime; hiding only hides the overlay (activeSessionId =
  // null), it does NOT unmount (unmount → link.closePty() kills the PTY). Only an
  // explicit close unmounts a session. Scrollback survives hiding.
  const [sessions, setSessions] = useState([]) // [{ id, peer }]
  // Sessions that have had a live link at least once (see the terminal overlay).
  const linkedSessions = useRef(new Set())
  const [activeSessionId, setActiveSessionId] = useState(null)
  const sessionSeq = useRef(0)
  const openSession = useCallback((peer) => {
    setSessions((prev) => {
      const existing = prev.find((s) => s.peer.id === peer.id)
      if (existing) { setActiveSessionId(existing.id); return prev }
      const id = 'sess-' + (++sessionSeq.current)
      setActiveSessionId(id)
      return [...prev, { id, peer }]
    })
  }, [])
  const backgroundSession = useCallback(() => setActiveSessionId(null), [])
  const switchSession = useCallback((id) => setActiveSessionId(id), [])
  const closeSession = useCallback((id) => {
    linkedSessions.current.delete(id)
    setSessions((prev) => prev.filter((s) => s.id !== id))
    setActiveSessionId((cur) => (cur === id ? null : cur))
  }, [])
  const activeSession = sessions.find((s) => s.id === activeSessionId) || null
  const vp = useVisualViewport()
  useLockZoomWhile(!!activeSession)

  // The per-device sheet. { peer, rect }: rect anchors the desktop popover.
  const [sheet, setSheet] = useState(null)
  const openSheet = useCallback((peer, rect) => setSheet({ peer, rect }), [])
  const closeSheet = useCallback(() => setSheet(null), [])

  // ⌘K / Ctrl+K command palette. Opening it dismisses the sheet.
  const [paletteOpen, setPaletteOpen] = useState(false)
  const openPalette = useCallback(() => { setSheet(null); setPaletteOpen(true) }, [])
  const closePalette = useCallback(() => setPaletteOpen(false), [])
  // The palette's "Pair with code" asks the code box to focus in remember mode.
  const [pairEntryNonce, setPairEntryNonce] = useState(0)
  const requestPairEntry = useCallback(() => { closePalette(); setScreen('home'); setPairEntryNonce((n) => n + 1) }, [closePalette])
  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        setPaletteOpen((v) => { if (!v) setSheet(null); return !v })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])
  // Keep the open sheet's peer fresh as the roster updates (status/route/shell).
  const sheetPeer = sheet ? (peers.find((p) => p.id === sheet.peer.id) || sheet.peer) : null

  // Files picked from the drop zone before choosing who gets them.
  const [staged, setStaged] = useState([])
  const pickRef = useRef(null)
  const [dropOver, setDropOver] = useState(false)
  const readyPeers = peers.filter((p) => p.status === 'ready')
  const stageFiles = (files) => {
    const list = Array.from(files || [])
    if (!list.length) return
    if (readyPeers.length === 1) {
      onSendFiles(readyPeers[0].id, list)
      showToast(`Sending to ${peerName(readyPeers[0])}`)
      return
    }
    setStaged(list)
  }
  const sendStaged = (peerId) => {
    if (!staged.length) return
    onSendFiles(peerId, staged)
    const p = peers.find((x) => x.id === peerId)
    showToast(p ? `Sending to ${peerName(p)}` : 'Sending')
    setStaged([])
  }

  const [customizing, setCustomizing] = useState(false)
  const createCustom = (typed) => { setCustomizing(false); onGenerateCode && onGenerateCode(typed) }

  const scope = state.roomScope || 'auto'
  const waiting = scope === 'code' || state.pairStatus === 'pairing' || peers.some((p) => p.status === 'connecting')
  const asks = (state.pendingKeeps || []).length + (state.pendingPakeKeep || []).length

  // ---- header ---------------------------------------------------------------
  const navItems = [['home', 'Home'], ['devices', 'Devices']]
  const navBtn = ([k, label]) => {
    const cur = screen === k
    return (
      <button key={k} type="button" onClick={() => setScreen(k)} aria-current={cur ? 'page' : undefined} className="tl-focus"
        style={{
          border: 0, background: 'none', cursor: 'pointer', font: (cur ? '600 ' : '500 ') + (narrow ? 13 : 14) + 'px ' + FONT_SANS,
          color: cur ? T.ink : T.sub, padding: narrow ? '4px 0' : '8px 10px', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', gap: 3, flex: narrow ? 1 : 'none', minHeight: 44, borderRadius: 6,
        }}>
        {narrow && <span aria-hidden="true" style={{ width: 22, height: 3, borderRadius: 2, background: cur ? T.ink : 'transparent' }} />}
        <span>{label}{k === 'devices' && knownDevices.length > 0 && <span style={{ marginLeft: 6, font: '600 11px ' + FONT_MONO, color: T.sub }}>{knownDevices.length}</span>}</span>
      </button>
    )
  }
  const header = (
    <header style={{ display: 'flex', alignItems: 'center', gap: narrow ? 10 : 16, padding: narrow ? '8px 16px' : '12px 24px', borderBottom: '1px solid ' + T.rule, flexShrink: 0, background: T.bg }}>
      <button type="button" onClick={() => setScreen('home')} aria-label="tunlion home" className="tl-focus"
        style={{ display: 'flex', alignItems: 'center', gap: 9, border: 0, background: 'none', cursor: 'pointer', padding: 0, color: T.ink, minHeight: 44 }}>
        <Mark T={T} size={narrow ? 24 : 26} anim={waiting ? 'pulse' : undefined} />
        <span style={{ font: '600 20px/1 ' + FONT_SANS, letterSpacing: '-.025em' }}>tunlion</span>
      </button>
      {!narrow && <nav aria-label="Main" style={{ display: 'flex', gap: 4, marginLeft: 12 }}>{navItems.map(navBtn)}</nav>}
      <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
        <RelayBanner peers={peers} T={T} />
        {!narrow && (
          <span role="status" style={{ fontSize: 13, color: state.connected ? T.sub : T.bad, whiteSpace: 'nowrap' }}>
            {state.connected ? 'online' : 'offline, reconnecting'}
          </span>
        )}
        <button type="button" onClick={openPalette} data-testid="cmd-open" title="Quick launcher (Ctrl+K)" aria-label="Open the quick launcher" className="tl-focus"
          style={{ minHeight: 44, minWidth: 44, border: '1px solid ' + T.rule, background: 'none', color: T.sub, borderRadius: 6, padding: '0 10px', font: '500 13px ' + FONT_MONO, cursor: 'pointer' }}>⌘K</button>
        {onToggleTheme && (
          <button type="button" onClick={onToggleTheme} className="tl-focus" aria-label={mode === 'light' ? 'Switch to dark theme' : 'Switch to light theme'}
            style={{ minHeight: 44, minWidth: 44, border: '1px solid ' + T.rule, background: 'none', color: T.sub, borderRadius: 6, padding: '0 10px', font: '500 13px ' + FONT_MONO, cursor: 'pointer' }}>
            {mode === 'light' ? 'Dark' : 'Light'}
          </button>
        )}
      </span>
    </header>
  )

  // ---- pieces of Home -------------------------------------------------------
  const keepBanners = (state.pendingKeeps || []).map((k) => (
    <div key={k.peerId} role="region" aria-label="Remember this device?" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 14px', borderRadius: 8, background: T.soft, border: '1.5px solid ' + T.ink, flexWrap: 'wrap' }}>
      <Mark T={T} size={20} anim="knock" />
      <span style={{ flex: 1, minWidth: 200, fontSize: 15 }}><b>{k.name}</b> asks to be remembered on this browser. You would reconnect automatically, with no code.</span>
      <span style={{ display: 'flex', gap: 8 }}>
        <Btn kind="pri" small T={T} narrow={narrow} onClick={() => onAcceptKeep?.(k.peerId)}>Remember</Btn>
        <Btn small T={T} narrow={narrow} onClick={() => onDeclineKeep?.(k.peerId)}>Not now</Btn>
      </span>
    </div>
  ))
  const pakeKeepBanners = (state.pendingPakeKeep || []).map((k) => (
    <PakeKeepBanner key={k.peerId} k={k} onAcceptPakeKeep={onAcceptPakeKeep} onDeclinePakeKeep={onDeclinePakeKeep} T={T} narrow={narrow} />
  ))

  const sessionChips = sessions.map((s) => ({
    id: s.id,
    peer:
      (s.peer.uid && peers.find((p) => p.uid && p.uid === s.peer.uid)) ||
      peers.find((p) => p.id === s.peer.id) ||
      s.peer,
  }))

  const dropZone = (
    <button type="button" onClick={() => pickRef.current && pickRef.current.click()} className="tl-focus"
      onDragOver={(e) => { e.preventDefault(); setDropOver(true) }}
      onDragLeave={() => setDropOver(false)}
      onDrop={(e) => { e.preventDefault(); setDropOver(false); stageFiles(e.dataTransfer.files) }}
      style={{
        font: 'inherit', background: dropOver ? T.soft : 'transparent', width: '100%', border: '1.5px dashed ' + (dropOver ? T.ink : T.sub), borderRadius: 9,
        minHeight: narrow ? 96 : 116, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4,
        cursor: 'pointer', color: T.sub, fontSize: 14, textAlign: 'center', padding: 12,
      }}>
      <span style={{ color: T.ink, fontWeight: 600, fontSize: 15 }}>Drop a file to send</span>
      <span>or {narrow ? 'tap' : 'click'} to pick one</span>
    </button>
  )

  const stagedCard = staged.length > 0 && (
    <div role="status" style={{ display: 'grid', gap: 10, padding: '12px 14px', borderRadius: 8, border: '1.5px solid ' + T.ink, background: T.surf }}>
      <span style={{ fontSize: 15 }}>
        <b>{staged.length === 1 ? staged[0].name : staged.length + ' files'}</b>
        <span style={{ color: T.sub }}> · {formatBytes(staged.reduce((n, f) => n + (f.size || 0), 0))} ready to send</span>
      </span>
      <span style={{ fontSize: 14, color: T.sub, lineHeight: 1.45 }}>
        {readyPeers.length
          ? 'Choose who gets it below: Send here.'
          : 'Nobody is here yet. Create a code, give it to the other person, and send once they appear below.'}
      </span>
      <span style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {!readyPeers.length && scope !== 'code' && <Btn small kind="pri" T={T} narrow={narrow} onClick={() => onGenerateCode && onGenerateCode()}>Create a code</Btn>}
        <Btn small kind="ghost" T={T} narrow={narrow} onClick={() => setStaged([])}>Clear</Btn>
      </span>
    </div>
  )

  // Where this browser is: the room it joined, and how others reach it.
  const roomLine = (() => {
    if (scope === 'pair') {
      const ps = state.pairStatus
      const done = ps === 'paired' || ps === 'connected'
      return done ? 'Connected privately with a one-time code. The code is used up.' : 'Private room for a one-time code.'
    }
    if (scope === 'link') return 'Anyone who opens this room link joins you here.'
    return state.network ? `People near you on the same network (${state.network}) show up here.` : 'People near you show up here.'
  })()

  const roomBlock = (
    <div style={{ display: 'grid', gap: 10 }}>
      <Section T={T} right={<LanChip localHelper={state.localHelper} T={T} />}>Here now · {peers.length}</Section>
      <span style={{ fontSize: 13.5, color: T.sub, lineHeight: 1.45 }}>{roomLine}</span>
      {scope === 'link' && state.roomUrl && (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ flex: 1, minWidth: 180, font: '500 13px ' + FONT_MONO, color: T.ink, border: '1px solid ' + T.rule, borderRadius: 6, padding: '10px 12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', background: T.surf }}>{state.roomUrl}</span>
          <Btn small T={T} narrow={narrow} onClick={() => { onCopyRoomLink && onCopyRoomLink(); showToast('Room link copied') }}>Copy room link</Btn>
        </div>
      )}
      {(scope === 'pair' || scope === 'link') && onUseAutoRoom && (
        <div><Btn small kind="ghost" T={T} narrow={narrow} onClick={onUseAutoRoom}>Back to people near you</Btn></div>
      )}
      {peers.length ? (
        <div style={{ display: 'grid', gap: 8 }}>
          {peers.map((p) => (
            <PeerRow key={p.id} peer={p} onSendFiles={onSendFiles} onOpenSheet={openSheet} onOpenTerminal={openSession}
              staged={staged} onSendStaged={sendStaged} T={T} narrow={narrow} />
          ))}
        </div>
      ) : (
        <div style={{ fontSize: 14, color: T.sub, padding: '14px 16px', borderRadius: 8, border: '1px dashed ' + T.rule }}>
          Nobody here yet. Enter a code above, create one, or open tunlion on another device on this network.
        </div>
      )}
    </div>
  )

  const transfersBlock = transfers.length > 0 && (
    <div>
      <Section T={T}>Transfers · {transfers.length}</Section>
      {transfers.map((t) => <TransferRow key={t.id} t={t} onAccept={onAccept} onDecline={onDecline} onSave={onSave} onClear={onClear} T={T} narrow={narrow} />)}
    </div>
  )

  const page = (children) => (
    <div style={{ padding: narrow ? '18px 16px 28px' : '32px 40px 40px', maxWidth: 720, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18 }}>{children}</div>
  )

  const home = page(
    <>
      <div style={{ display: 'grid', gap: 6 }}>
        <h1 style={{ margin: 0, fontSize: narrow ? 24 : 30, lineHeight: 1.15, letterSpacing: '-.015em', fontWeight: 600, textWrap: 'balance' }}>
          {knownDevices.length ? 'Welcome back' : 'Connect to a device'}
        </h1>
        <p style={{ margin: 0, fontSize: 15, lineHeight: 1.5, color: T.sub }}>Enter a code from another device, or drop a file to send. Nothing to install, nothing uploaded.</p>
      </div>
      {keepBanners}
      {pakeKeepBanners}
      <SessionsStrip sessions={sessionChips} activeId={activeSessionId} onSwitch={switchSession} onClose={closeSession} T={T} narrow={narrow} />
      {scope === 'code' && state.roomCode
        ? <CodeCard code={state.roomCode} onDone={onUseAutoRoom || (() => {})} T={T} narrow={narrow} toast={showToast} />
        : <CodeBox state={state} onPairWithCode={onPairWithCode || (() => {})} onReceiveWithCode={onReceiveWithCode || (() => {})}
            initialCode={initialCode} openEntryNonce={pairEntryNonce} T={T} narrow={narrow} />}
      <input ref={pickRef} type="file" multiple style={{ display: 'none' }} tabIndex={-1} aria-hidden="true"
        onChange={(e) => { stageFiles(e.target.files); e.target.value = '' }} />
      {dropZone}
      {stagedCard}
      {scope !== 'code' && !(staged.length > 0 && !readyPeers.length) && (customizing
        ? <CustomCodeEntry onCreate={createCustom} onCancel={() => setCustomizing(false)} T={T} narrow={narrow} />
        : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <Btn T={T} narrow={narrow} onClick={() => onGenerateCode && onGenerateCode()} testid="create-code">Create a code</Btn>
            <Btn kind="ghost" T={T} narrow={narrow} onClick={() => setCustomizing(true)}>Choose your own words</Btn>
            <span style={{ fontSize: 13.5, color: T.sub, flexBasis: narrow ? '100%' : 'auto' }}>so someone in another browser can connect to this one and swap files</span>
          </div>
        ))}
      {roomBlock}
      {transfersBlock}
    </>,
  )

  // ---- Devices --------------------------------------------------------------
  const deviceRows = knownDevices.map((d) => {
    const live = peers.find((p) => p.known === d.name)
    const online = !!live && live.status === 'ready'
    const peerForSheet = live || { id: 'known:' + d.name, name: d.name, known: d.name, status: 'failed' }
    const caps = Array.isArray(d.caps) ? d.caps : ['transfer']
    const what = caps.map((c) => (c === 'transfer' ? 'files' : c)).join(', ')
    return (
      <div key={d.name} data-testid="device-row" role="button" tabIndex={0} className="tl-focus"
        aria-label={`${d.name}, ${online ? 'online' : 'offline'}`}
        onClick={() => openSheet(peerForSheet, null)}
        onKeyDown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) { e.preventDefault(); openSheet(peerForSheet, null) } }}
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '13px 0', minHeight: 56, borderBottom: '1px solid ' + T.rule, cursor: 'pointer' }}>
        <span style={{ display: 'grid', gap: 3, minWidth: 0 }}>
          <b style={{ fontSize: 15, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</b>
          <span style={{ fontSize: 13, color: T.sub }}>remembered · {what}{d.addedAt ? ' · since ' + new Date(d.addedAt).toLocaleDateString() : ''}</span>
        </span>
        <span style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }} onClick={(e) => e.stopPropagation()}>
          {online && live.shell && <Btn small T={T} narrow={narrow} onClick={() => openSession(live)} ariaLabel={`open a shell on ${d.name}`}>Shell</Btn>}
          {online ? (live.route === 'relayed' ? <RouteBadge route="relayed" T={T} /> : <Tag tone="ok" T={T}>{live.route === 'local' ? 'LAN' : 'online'}</Tag>) : <Tag T={T}>offline</Tag>}
        </span>
      </div>
    )
  })
  const devices = page(
    <>
      <h1 style={{ margin: 0, fontSize: narrow ? 24 : 30, lineHeight: 1.15, letterSpacing: '-.015em', fontWeight: 600 }}>Devices</h1>
      {knownDevices.length ? (
        <div>
          <Section T={T}>Remembered on this browser</Section>
          {deviceRows}
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          <p style={{ margin: 0, fontSize: 15, lineHeight: 1.5, color: T.sub }}>No devices yet. On one of your computers run <code style={{ fontFamily: FONT_MONO }}>tunlion add</code>, enter the code it shows on Home with Remember a device, then choose Remember.</p>
          <div><Btn T={T} narrow={narrow} onClick={() => setScreen('home')}>Enter a code</Btn></div>
        </div>
      )}
      <p style={{ margin: 0, fontSize: 13, lineHeight: 1.5, color: T.sub }}>
        Remembered devices are stored only in this browser. Clearing site data forgets them. What each device lets this browser do is decided on that device.
      </p>
    </>,
  )

  // ---- overlays -------------------------------------------------------------
  // Terminals render as a full-window overlay (portal to body) pinned to the
  // visual viewport, so on a phone the shell takes the whole screen (no header,
  // no nav) and its key bar sits right above the soft keyboard. EVERY open
  // session's WebTerminal is mounted at once; only the active one is visible.
  // Keeping a hidden session mounted preserves its live PTY and scrollback.
  const terminalOverlay = sessions.length
    ? createPortal(
        <div data-testid="terminal-overlay" style={{
          position: 'fixed', zIndex: 4000, background: TT.bg,
          left: vp.left, top: vp.top, width: vp.width, height: vp.height,
          overflow: 'hidden', touchAction: 'none', overscrollBehavior: 'none',
          display: activeSession ? 'block' : 'none',
        }}>
          {sessions.map((s) => {
            const visible = s.id === activeSessionId
            const peer =
              (s.peer.uid && peers.find((p) => p.uid === s.peer.uid)) ||
              peers.find((p) => p.id === s.peer.id) ||
              s.peer
            // Resolve the CURRENT link by stable uid so a reconnect (new sid)
            // still hands WebTerminal a live link to reattach over.
            const link =
              (peer.uid && state.getLinkByUid && state.getLinkByUid(peer.uid)) ||
              (state.getLink && state.getLink(peer.id)) ||
              null
            // A session that has had a link keeps its terminal mounted while the
            // device is briefly unreachable: the remote shell is still running,
            // the terminal says "reconnecting", and the next link reattaches with
            // nothing lost. Only a session that never connected gets the
            // "isn't reachable" panel.
            if (link) linkedSessions.current.add(s.id)
            const keepMounted = !!link || linkedSessions.current.has(s.id)
            return (
              <div key={s.id} data-testid="session-pane" data-session-pane-id={s.id}
                style={{ position: 'absolute', inset: 0, display: visible ? 'block' : 'none' }}>
                {keepMounted
                  ? <WebTerminal link={link} peerName={peerName(peer)} route={peer.route} relation={peer.known ? 'remembered' : 'this session'}
                      relayExplainer={RELAY_EXPLAINER}
                      T={TT} accent={TT.acc} font={FONT_MONO} uiFont={FONT_SANS} instanceId={s.id} hidden={!visible}
                      viewportPinned narrow={narrow}
                      onBackground={backgroundSession} onClose={() => closeSession(s.id)} />
                  : (
                    <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', color: TT.ink, fontFamily: FONT_SANS, padding: 20 }}>
                      <div style={{ textAlign: 'center', display: 'grid', gap: 14 }}>
                        <div style={{ fontSize: 15 }}>{peerName(peer)} isn't reachable. It may be off, or tunlion isn't running there.</div>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                          <Btn T={TT} narrow={narrow} onClick={backgroundSession}>Hide</Btn>
                          <Btn T={TT} narrow={narrow} onClick={() => closeSession(s.id)}>Close</Btn>
                        </div>
                      </div>
                    </div>
                  )}
              </div>
            )
          })}
        </div>,
        document.body,
      )
    : null

  const deviceSheet = sheetPeer ? (
    <DeviceSheet
      peer={sheetPeer}
      anchorRect={sheet.rect}
      narrow={narrow}
      sendFirst={narrow}
      T={T}
      D={{ dispName: 17 }}
      accent={T.ink}
      font={FONT_SANS}
      onOpenShell={openSession}
      onSendFiles={onSendFiles}
      onForget={onForgetDevice}
      onRename={onRenameDevice}
      onClose={closeSheet}
    />
  ) : null

  const commandPalette = (
    <CommandPalette
      open={paletteOpen}
      onClose={closePalette}
      peers={peers}
      T={T}
      D={{ pad: 18, gap: 12, tilePad: 13, rowPad: 12, name: 14, dispName: 15 }}
      accent={T.ink}
      font={FONT_SANS}
      narrow={narrow}
      onOpenShell={openSession}
      onSendFiles={onSendFiles}
      onOpenSheet={openSheet}
      onPairWithCode={onPairWithCode ? requestPairEntry : null}
      onGenerateCode={onGenerateCode || null}
    />
  )

  // Link-diagnostics export (telemetry capture); renders nothing when off.
  const diagPanel = <DiagPanel T={T} accent={T.ink} font={FONT_MONO} />

  const toastEl = toast && (
    <div role="status" aria-live="polite" style={{
      position: 'absolute', left: '50%', bottom: narrow ? 84 : 24, transform: 'translateX(-50%)', zIndex: 50,
      background: T.ink, color: T.inv, padding: '11px 16px', borderRadius: 8, fontSize: 14, maxWidth: '88%',
      boxShadow: '0 10px 30px -10px rgba(0,0,0,.4)', textAlign: 'center', pointerEvents: 'none',
    }}>{toast.msg}</div>
  )

  return (
    <div ref={rootRef} data-theme={mode} style={{
      position: 'absolute', inset: 0, background: T.bg, color: T.ink, font: '15px/1.45 ' + FONT_SANS,
      display: 'flex', flexDirection: 'column', overflow: 'hidden', ['--tl-ring']: T.ink,
    }}>
      {terminalOverlay}
      {deviceSheet}
      {commandPalette}
      {diagPanel}
      {header}
      <main style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
        {screen === 'devices' ? devices : home}
      </main>
      {narrow && (
        <nav aria-label="Main" style={{ display: 'flex', borderTop: '1px solid ' + T.rule, padding: '2px 8px', paddingBottom: 'max(8px, env(safe-area-inset-bottom))', flexShrink: 0, background: T.bg }}>
          {navItems.map(navBtn)}
        </nav>
      )}
      {toastEl}
      {asks > 0 && screen !== 'home' && (
        <button type="button" onClick={() => setScreen('home')} className="tl-focus"
          style={{ position: 'absolute', right: 16, top: narrow ? 64 : 76, zIndex: 40, display: 'flex', alignItems: 'center', gap: 8, minHeight: 44, padding: '0 12px', borderRadius: 8, border: '1.5px solid ' + T.ink, background: T.surf, color: T.ink, font: '600 14px ' + FONT_SANS, cursor: 'pointer' }}>
          <Mark T={T} size={18} anim="knock" />{asks === 1 ? 'A device asks to be remembered' : asks + ' devices ask to be remembered'}
        </button>
      )}
    </div>
  )
}
