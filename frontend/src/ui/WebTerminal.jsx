// WebTerminal: a real browser shell wired to a peer's PTY over the data channel.
// Given a live PeerLink, it opens a pty (pty-open), bridges xterm <-> the PTY
// byte stream, handles resize, and provides a mobile accessory key bar (the
// missing-special-keys fix) with a sticky-toggle modifier model + an escape-
// sequence map, plus visualViewport keyboard avoidance. Per docs/mobile-terminal-
// ergonomics.md.
//
// Persistence (issue #4): the PTY session id is owned HERE and is STABLE across a
// reconnect. When the `link` prop changes (a dropped data channel superseded by a
// fresh one) we re-open with the SAME session id, so the CLI reattaches us to the
// still-running PTY and replays the buffered output, instead of spawning a fresh
// shell. The session id is derived from `instanceId` so it survives a re-render
// and a link swap, but a brand-new WebTerminal (new tab/session) gets a new one.
import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { PredictiveEcho } from '../lib/predict.js'
import { log } from '../lib/log.js'
import {
  SCROLL_APPLICATION, SCROLL_CURSOR_KEYS, SCROLL_HISTORY, applicationWheelActive,
  isMouseReport, latin1Bytes, pageLines, scrollModeKey, scrollRoute, wheelDeltaForDirection,
} from '../lib/tui-scroll.js'
import '@xterm/xterm/css/xterm.css'

const enc = new TextEncoder()

// Run a render-helper / per-write callback so NOTHING it throws can escape into
// xterm's internal write loop (a throw in a term.write completion callback jams
// xterm's write queue and freezes the terminal while the link/PTY stay alive,
// the confirmed root cause of the freeze bug). A helper error is swallowed here
// (logged at debug), never propagated. `tag` is just for the log line.
function guarded(tag, fn) {
  try { fn() } catch (e) { try { log.debug('webterm: render helper threw (' + tag + ')', e && (e.message || e)) } catch (_) {} }
}

// label -> exact bytes sent to the PTY (xterm/ANSI). From the research doc.
const KEYS = {
  Esc: '\x1b', Tab: '\x09', Enter: '\r',
  Up: '\x1b[A', Down: '\x1b[B', Right: '\x1b[C', Left: '\x1b[D',
  Home: '\x1b[H', End: '\x1b[F', PgUp: '\x1b[5~', PgDn: '\x1b[6~',
  Del: '\x1b[3~', '|': '|', '/': '/', '~': '~', '-': '-',
}
// Coarse pointer => treat as touch (mobile). The ?preview=...&touch=1 query is a
// dev-only override so the touch input/scroll path can be exercised on a desktop
// browser in the harness; it is inert in the real app (no preview query).
const forceTouch = (() => {
  try { const q = new URLSearchParams(window.location.search); return !!q.get('preview') && q.get('touch') === '1' } catch (e) { return false }
})()
const isTouch = forceTouch || (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(pointer: coarse)').matches)

function xtermTheme(T, accent) {
  return {
    background: T.bg, foreground: T.text, cursor: accent, cursorAccent: T.bg,
    selectionBackground: accent + '40',
    black: T.mode === 'light' ? '#C9C4B5' : '#15181C', red: T.bad, green: T.ok,
    yellow: T.warn, blue: T.recv, magenta: '#FF8AD6', cyan: '#5BE7FF', white: T.sub,
    brightBlack: T.dim, brightRed: T.bad, brightGreen: T.ok, brightYellow: T.warn,
    brightBlue: T.recv, brightMagenta: '#FF8AD6', brightCyan: '#5BE7FF', brightWhite: T.text,
  }
}
const haptic = (ms = 8) => { try { navigator.vibrate && navigator.vibrate(ms) } catch (e) {} } // Android only

// A WebTerminal instance keeps ONE stable PTY session id for its whole lifetime,
// across any number of link swaps (reconnects). Derived from instanceId so two
// renders of the same session agree; a fallback random id covers the preview.
function makeSessionId(instanceId) {
  const base = instanceId || ('s' + Math.random().toString(36).slice(2, 10))
  return 'pty-' + base
}

// viewportPinned: the host (the terminal overlay in Tunlion.jsx, and the
// preview wrapper) already sizes itself to the VISUAL viewport, so the visible
// box already excludes the soft keyboard. In that case we must NOT also lift the
// accessory bar by kbInset (that would double-count the keyboard, leaving a gap
// and shrinking the terminal). We still listen to visualViewport so a keyboard
// open/close triggers a refit, we just keep the bar margin at 0.
export default function WebTerminal({ link, peerName, route, relation, relayExplainer, T, accent, font, uiFont, narrow, onClose, onBackground, hidden, instanceId, viewportPinned }) {
  const hostRef = useRef(null)
  const termRef = useRef(null)
  const fitRef = useRef(null)
  // The CURRENT link, always live. The terminal is created ONCE (mount-once
  // effect) and never recreated on a reconnect; its persistent handlers
  // (onData, IME commit, the redraw recovery) read linkRef.current so they
  // always reach the freshest PeerLink instead of a stale closure over the
  // link that was current when the terminal was built. The link-binding
  // effect keeps this in sync.
  const linkRef = useRef(link)
  const ctrl = useRef(false) // 'armed' modifiers, read inside onData
  const alt = useRef(false)
  const [ctrlOn, setCtrlOn] = useState(false) // mirror for the UI
  const [altOn, setAltOn] = useState(false)
  const [status, setStatus] = useState('connecting')
  const [barOpen, setBarOpen] = useState(false) // the one-line bar, expanded to the full line
  const [kbInset, setKbInset] = useState(0) // visualViewport keyboard height
  // Touch starts in viewing mode. An explicit, synchronous user gesture opts
  // into typing; scrolling/reconnecting/repainting must never summon the IME.
  const [keyboardOpen, setKeyboardOpen] = useState(!isTouch)
  const keyboardOpenRef = useRef(!isTouch)
  const focusTerminal = useCallback(() => {
    if (!isTouch || keyboardOpenRef.current) termRef.current?.focus()
  }, [])
  const setKeyboard = useCallback((open) => {
    const enabled = !isTouch || open
    keyboardOpenRef.current = enabled
    setKeyboardOpen(enabled)
    const ta = hostRef.current?.querySelector('textarea')
    if (ta) {
      // inputmode is a hint, not a guarantee on Safari. readOnly prevents an
      // incidental xterm focus from bringing up its editable keyboard as well.
      ta.readOnly = !enabled
      if (enabled) ta.removeAttribute('readonly')
      else ta.setAttribute('readonly', '')
      ta.setAttribute('inputmode', enabled ? 'text' : 'none')
      ta.setAttribute('virtualkeyboardpolicy', enabled ? 'auto' : 'manual')
      // iOS only raises the keyboard for a TRUSTED focus of an editable field.
      // A focus() called inside this click handler is not enough: the other
      // controls on the screen can take focus back. The visible control is a
      // <label for=textarea> instead, so the browser itself focuses the now
      // editable textarea as the label's default activation (a fresh focus
      // after this blur). Programs that call setKeyboard directly still get the
      // correct editable state; the user's next terminal tap opens the IME.
      try { ta.blur() } catch (e) {}
      void ta.offsetHeight
      if (!enabled) {
        // Hidden means the SOFT keyboard is hidden: physical keyboards and
        // their IME must keep working. blur() normally delivers the final
        // compositionend (which commits exactly once); clear the shared flag
        // after it so a browser that does not deliver that event cannot leave
        // the next composition marked as still in progress. Do not clear the
        // textarea here: the compositionend handler owns that, and clearing it
        // early would lose an in-flight commit.
        ta.blur()
        composingRef.current = false
      }
    }
    // Everything above runs synchronously in the button's click stack. iOS
    // rejects a delayed focus, so there is deliberately no setTimeout here.
  }, [])
  const [atBottom, setAtBottom] = useState(true) // false => show scroll-to-bottom
  const [wheelRoute, setWheelRoute] = useState(SCROLL_HISTORY) // who owns a vertical wheel
  const [toast, setToast] = useState('') // brief copy/paste feedback
  const toastTimer = useRef(0)
  const sessionIdRef = useRef(makeSessionId(instanceId))
  // The hidden xterm textarea is the only editable target the soft keyboard can
  // attach to. A <label for=this-id> lets the browser focus it as the label's
  // own activation, which iOS accepts as trusted; programmatic focus from a
  // button handler is not reliable there.
  const inputIdRef = useRef('term-input-' + (instanceId || Math.random().toString(36).slice(2, 10)))
  // Session resume: bytes of this session's output written to the terminal,
  // across every link. A reattach sends it as resume_from so the device replays
  // only what this screen missed, never what it already shows.
  const recvRef = useRef(0)
  const openedRef = useRef(false) // an open went out before: the next is a reattach
  const wasReadyRef = useRef(false) // the shell was live once: a drop is "reconnecting"
  // Which link owns the current PTY attachment. A local repaint must not call
  // openPty() again while this link still has an open channel and an acked PTY:
  // every open consumes a server stream slot. These refs are cleared when the
  // channel goes down, the PTY closes, or a different link replaces it, so a
  // genuine reconnect still reattaches with resume_from.
  const ptyOpenLinkRef = useRef(null)
  const ptyReadyLinkRef = useRef(null)
  const statusRef = useRef('connecting')
  useEffect(() => { statusRef.current = status }, [status])
  // Predictive / local echo (mosh-style): paints keystrokes instantly, styled,
  // then reconciles to the server's authoritative bytes. Created per-terminal in
  // the mount effect. composingRef is shared with the IME path so we never both
  // predict a char AND let the composition commit insert it (double insert).
  const predictRef = useRef(null)
  const composingRef = useRef(false)
  // --- render watchdog (self-heal a wedge without reload) -------------------
  // The freeze symptom is: PTY bytes keep arriving but xterm stops painting (a
  // thrown write-completion callback jammed the write queue, or the renderer
  // paused). We track WHEN bytes last arrived (bytesAt / byteCount) and the last
  // time the rendered buffer actually ADVANCED (renderAt, sampled from a parse
  // tick AND from the buffer's own length/cursor so we are not fooled by a
  // handler that itself stopped firing). If bytes arrived recently but the
  // render has not advanced for the stall window, we auto-run redrawRecover.
  // Only fires when bytes-arrived-but-render-stuck, so a legitimately idle
  // terminal (no bytes) never triggers it (no false positives).
  const wd = useRef({ bytesAt: 0, byteCount: 0, renderAt: 0, lastByteCount: 0, lastSig: '', recoverAt: 0 })
  // --- custom scrollbar (the reliable mobile scroll, issue #5) -------------
  // A plain DOM track+thumb pinned to the right edge. Unlike the swipe handler
  // (which never fired reliably on real iPad/Android), a dragged DOM element
  // behaves identically on touch, pen, and mouse via pointer events, so this is
  // the dependable way to move through scrollback on a phone/tablet.
  const trackRef = useRef(null)
  // {visible, thumbTop, thumbH} as percentages of the track height. visible is
  // false when everything fits (no scrollback) or a TUI owns the alt screen.
  const [bar, setBar] = useState({ visible: false, top: 0, height: 100 })
  const dragRef = useRef(null) // { startY, startTop } while dragging the thumb

  // brief, self-clearing status note (copy/paste feedback so a silent clipboard
  // rejection on mobile is visible).
  const showToast = useCallback((msg) => {
    setToast(msg)
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(''), 1400)
  }, [])
  useEffect(() => () => { if (toastTimer.current) clearTimeout(toastTimer.current) }, [])

  // Always send to the CURRENT link (linkRef), never a captured one, so a
  // reconnect (new link, same terminal) keeps input flowing without rebuilding
  // any of the persistent handlers that call write.
  const write = useCallback((s) => { const l = linkRef.current; return l && l.sendPtyInput(enc.encode(s)) }, [])
  // Raw-byte input path for xterm's binary events (legacy mouse reports). Never
  // run these through TextEncoder: byte values >127 are Latin-1 code units in
  // xterm's report string, and UTF-8 encoding would expand/corrupt them.
  const writeBytes = useCallback((u8) => {
    const l = linkRef.current
    return l && u8 && l.sendPtyInput(u8)
  }, [])

  // apply sticky Ctrl/Alt to a single typed char, then disarm (unless locked)
  const applyMods = useCallback((data) => {
    let out = data
    if (ctrl.current && data.length === 1) {
      const c = data.toLowerCase().charCodeAt(0)
      if (c >= 97 && c <= 122) out = String.fromCharCode(c - 96) // Ctrl-A..Z
      else if (data === ' ') out = '\x00'
      else if (data === '[') out = '\x1b'
      ctrl.current = false; setCtrlOn(false)
    }
    if (alt.current) { out = '\x1b' + out; alt.current = false; setAltOn(false) }
    return out
  }, [])

  // --- scrollback helpers (mobile scroll, issue #5) -----------------------
  // "At the bottom" means the viewport top equals the buffer base (the live
  // prompt is visible). We track this to (a) show/hide the scroll-to-bottom
  // affordance and (b) decide whether a resize should auto-stick to bottom or
  // preserve the reader's position. In the alternate screen (a full-screen TUI)
  // there is no scrollback, so we always treat it as "at bottom" and hide the
  // button: the TUI owns the viewport (issue #1, correct xterm behavior).
  const computeAtBottom = useCallback(() => {
    const term = termRef.current
    if (!term || !term.buffer || !term.buffer.active) return true
    if (term.buffer.active.type === 'alternate') return true
    return term.buffer.active.viewportY >= term.buffer.active.baseY
  }, [])
  // What owns a vertical wheel/touch scroll right now? Read only PUBLIC xterm
  // state: the active buffer type and the application's mouse tracking mode.
  // A partial TUI can keep the normal buffer while asking for mouse reports, so
  // "alternate screen?" alone is not enough (the old bug: those apps got local
  // history scrolling and never saw the gesture).
  const routeForTerm = useCallback((term) => {
    try {
      return scrollRoute(term.buffer.active.type, term.modes.mouseTrackingMode)
    } catch (e) {
      return SCROLL_HISTORY
    }
  }, [])
  // Turn a touch/page step into real WheelEvents on xterm's screen element.
  // xterm's own wheel listeners then do the encoding: SGR/legacy/pixel mouse
  // reports for a mouse-tracking app, or Up/Down cursor keys when an alternate
  // screen has no scrollback (honouring applicationCursorKeys). We never touch
  // xterm internals or hardcode a mouse protocol here.
  //
  // Exactly-once routing: xterm binds its wheel listeners on the `.xterm`
  // element (the screen element is a child), and its mouse-reporting listener
  // and its no-scrollback fallback are mutually exclusive (`requestedEvents.wheel`
  // makes the fallback return immediately). Dispatching on `.xterm-screen`
  // therefore reaches one handler, once, and the touch handler returns without
  // also calling scrollLines() for the same gesture.
  const dispatchWheel = useCallback((clientX, clientY, lines, dir) => {
    const host = hostRef.current
    const screen = host && host.querySelector('.xterm-screen')
    const n = Math.max(0, Math.min(200, Math.abs(Math.trunc(lines)) || 0))
    if (!screen || !n) return 0
    const deltaY = wheelDeltaForDirection(dir)
    let sent = 0
    for (let i = 0; i < n; i++) {
      const ev = new WheelEvent('wheel', {
        bubbles: true, cancelable: true, composed: true,
        clientX, clientY, deltaX: 0, deltaY,
        deltaMode: WheelEvent.DOM_DELTA_LINE,
      })
      // Marks the event as ours for debugging / harness assertions only; xterm
      // does not need (or read) it.
      try { ev.__tunlionTouchWheel = true } catch (e) {}
      screen.dispatchEvent(ev)
      sent++
    }
    return sent
  }, [])
  const scrollToBottom = useCallback(() => {
    const term = termRef.current
    if (!term) return
    // Explicit escape hatch, not a wheel route: a partial TUI that started while
    // the reader was off-tail must not strand them in hidden history. The
    // per-finger wheel still belongs to the app; this button deliberately jumps
    // the local viewport back to the live tail.
    term.scrollToBottom()
    setAtBottom(true)
    haptic()
    try { focusTerminal() } catch (e) {}
  }, [focusTerminal])
  // Page up/down for the accessory bar (a touch-friendly chunk scroll). A near-
  // full-page step (rows - 1) keeps a line of context, like a pager. In local
  // history this moves xterm's scrollback; when the app owns the wheel the same
  // step is delivered as wheel reports at the terminal centre, so a TUI pages
  // itself instead of the shell's history moving underneath it. There is no
  // blind PgUp/PgDn key injection: an app that does not report wheel keeps the
  // standard xterm behaviour (cursor keys in the alternate screen).
  const scrollPage = useCallback((dir) => {
    const term = termRef.current
    if (!term) return
    const n = pageLines(term.rows)
    if (routeForTerm(term) === SCROLL_HISTORY) {
      term.scrollLines(dir * n)
    } else {
      const host = hostRef.current
      const screen = host && host.querySelector('.xterm-screen')
      if (!screen) return
      const rect = screen.getBoundingClientRect()
      dispatchWheel(rect.left + rect.width / 2, rect.top + rect.height / 2, n, dir)
    }
    haptic()
  }, [dispatchWheel, routeForTerm])

  // Recompute the thumb size + position from xterm's buffer geometry. The total
  // scrollable height is (baseY + rows) lines: baseY is the topmost viewport
  // line of the live tail, so the whole document is baseY + rows lines and the
  // viewport shows `rows` of them starting at viewportY. The thumb height is the
  // visible fraction (rows / total) and its top is viewportY / total. Hidden
  // when everything fits (baseY === 0) or a TUI owns the alternate screen.
  // Dev-only fault injection (preview harness): set window.__webtermThrowSyncBar
  // to make the NEXT syncBar() throw once, to prove the guarded callbacks swallow
  // it and the terminal keeps rendering (no wedge). Inert in the real app: the
  // ref is only ever set by the preview hook below.
  const throwSyncBarRef = useRef(false)
  const syncBar = useCallback(() => {
    if (throwSyncBarRef.current) { throwSyncBarRef.current = false; throw new Error('injected syncBar fault (dev)') }
    const term = termRef.current
    const b = term && term.buffer && term.buffer.active
    if (!term || !b) { setBar((p) => (p.visible ? { ...p, visible: false } : p)); return }
    // History-only chrome: never offer a dragbar for a TUI's wheel, and the
    // alternate screen has no scrollback at all. A partial TUI in the normal
    // buffer still counts as app-owned (mouse reporting), so its scrollbar is
    // hidden too even though xterm has history behind it.
    const route = routeForTerm(term)
    setWheelRoute((prev) => (prev === route ? prev : route))
    const appOwnsWheel = applicationWheelActive(route)
    if (b.type === 'alternate' || appOwnsWheel || b.baseY <= 0) {
      setBar((p) => (p.visible ? { ...p, visible: false } : p)); return
    }
    const rows = term.rows || 24
    const total = b.baseY + rows
    const h = Math.max(8, (rows / total) * 100) // % of track, floored so it stays grabbable
    const maxTop = 100 - h
    const top = total > rows ? (b.viewportY / b.baseY) * maxTop : 0
    setBar({ visible: true, top: Math.max(0, Math.min(maxTop, top)), height: h })
  }, [routeForTerm])

  // Map a fractional position along the track (0 = top, 1 = bottom) to a buffer
  // line and scroll there. Used by both the thumb drag and a track tap-to-page
  // would use scrollLines instead; here we jump precisely.
  const scrollToFraction = useCallback((frac) => {
    const term = termRef.current
    const b = term && term.buffer && term.buffer.active
    if (!term || !b || b.type === 'alternate') return
    if (applicationWheelActive(routeForTerm(term))) return // history-only control
    const f = Math.max(0, Math.min(1, frac))
    term.scrollToLine(Math.round(f * b.baseY))
  }, [routeForTerm])

  // Thumb drag: pointer events cover mouse + touch + pen identically, so a synth
  // drag in the harness exercises the exact code a real finger does. We capture
  // the pointer so the drag survives the finger sliding off the thin thumb, and
  // map the thumb's center under the pointer to a scroll fraction.
  const onThumbDown = useCallback((e) => {
    const term = termRef.current
    const track = trackRef.current
    if (!term || !track) return
    e.preventDefault(); e.stopPropagation() // never let it reach xterm (no typing/selection)
    const rect = track.getBoundingClientRect()
    // Measure the rendered thumb (its height can exceed bar.height% via minHeight)
    // so the pixel<->line mapping is exact. grab is where within the thumb we
    // grabbed, so the thumb does not snap its top to the pointer.
    const thumbRect = e.currentTarget.getBoundingClientRect()
    const thumbPx = thumbRect.height
    const grab = e.clientY - thumbRect.top
    dragRef.current = { rect, thumbPx, grab }
    try { e.target.setPointerCapture(e.pointerId) } catch (err) {}
  }, [])
  const onThumbMove = useCallback((e) => {
    const d = dragRef.current
    if (!d) return
    e.preventDefault()
    const travel = d.rect.height - d.thumbPx // px of track the thumb top can span
    if (travel <= 0) return
    const topPx = (e.clientY - d.rect.top - d.grab)
    scrollToFraction(topPx / travel)
  }, [scrollToFraction])
  const onThumbUp = useCallback((e) => {
    if (!dragRef.current) return
    dragRef.current = null
    try { e.target.releasePointerCapture(e.pointerId) } catch (err) {}
  }, [])

  // Tap the track above/below the thumb: page toward the tap, like a native
  // scrollbar gutter click. Ignore taps that land on the thumb (those start a
  // drag instead). Direction: tap above the thumb scrolls up, below scrolls down.
  const onTrackDown = useCallback((e) => {
    const term = termRef.current
    const track = trackRef.current
    if (!term || !track) return
    e.preventDefault()
    const rect = track.getBoundingClientRect()
    const y = e.clientY - rect.top
    const thumbTop = (bar.top / 100) * rect.height
    const thumbBot = thumbTop + (bar.height / 100) * rect.height
    if (y < thumbTop) scrollPage(-1)
    else if (y > thumbBot) scrollPage(1)
  }, [bar, scrollPage])

  // --- resize hardening (issue #2) ----------------------------------------
  // The Android soft keyboard fires a burst of visualViewport resizes; the
  // ResizeObserver fires its own. ALL of them funnel through this one
  // rAF-coalesced, guarded path so we never refit twice in a frame, never refit
  // a hidden or zero-size element (which makes the FitAddon throw / compute a
  // bogus 0x0 and wedge the renderer), and the IO loop is never blocked.
  const fitRaf = useRef(0)
  const safeFit = useCallback(() => {
    if (fitRaf.current) return // already scheduled this frame
    fitRaf.current = requestAnimationFrame(() => {
      fitRaf.current = 0
      const host = hostRef.current
      const fit = fitRef.current
      const term = termRef.current
      if (!host || !fit || !term) return
      // Never fit a hidden / un-laid-out / zero-size element: offsetParent is
      // null when display:none (backgrounded session), and a 0 width/height
      // makes the fit dims NaN/0 and corrupts the buffer.
      if (host.offsetParent === null) return
      if (host.clientWidth < 2 || host.clientHeight < 2) return
      let dims
      try { dims = fit.proposeDimensions() } catch (e) { return }
      if (!dims || !dims.cols || !dims.rows || !isFinite(dims.cols) || !isFinite(dims.rows)) return
      if (dims.cols === term.cols && dims.rows === term.rows) return // no-op, skip churn
      // Soft-keyboard open/close must NOT yank the reader away from scrollback.
      // Remember where we were (and how far from the live tail) BEFORE the fit,
      // then: if we were at the bottom, stick to the bottom (the common case, so
      // the prompt stays visible); otherwise restore the same distance-from-tail
      // so the lines being read stay put (issue #4 / #5).
      const wasBottom = computeAtBottom()
      const b = term.buffer && term.buffer.active
      const fromTail = b ? (b.baseY - b.viewportY) : 0
      try { fit.fit() } catch (e) {}
      try {
        if (wasBottom) term.scrollToBottom()
        else if (fromTail > 0) {
          const nb = term.buffer && term.buffer.active
          if (nb) term.scrollToLine(Math.max(0, nb.baseY - fromTail))
        }
      } catch (e) {}
      guarded('safeFit.atBottom', () => setAtBottom(computeAtBottom()))
      guarded('safeFit.syncBar', () => syncBar())
    })
  }, [computeAtBottom, syncBar])

  // Bind a link's PTY callbacks to the EXISTING terminal and (re)open/reattach
  // the PTY with our stable session id. Stored in a ref so BOTH the link-binding
  // effect and the no-reload redraw recovery can call the exact same logic. It
  // reads termRef/predictRef/linkRef (all live), never closes over a stale link,
  // and returns a cleanup that only UNBINDS handlers (never disposes the
  // terminal, never closePty), so a link swap leaves the remote PTY running.
  const bindLinkRef = useRef(() => () => {})
  // The active unbind for the current link binding. The link-binding effect and
  // the redraw recovery both go through rebindLink() so there is ever only ONE
  // live binding (and one reattach poll): rebinding always unbinds first.
  const unbindRef = useRef(null)
  const rebindLink = useCallback(() => {
    try { if (unbindRef.current) unbindRef.current() } catch (e) {}
    unbindRef.current = bindLinkRef.current()
  }, [])
  // No-reload recovery: if the screen ever gets stuck (a paused DOM renderer
  // after a flaky reconnect / a hidden then re-shown host), this re-fits and
  // forces a FULL repaint of every row. A repaint is LOCAL: when the current
  // link still has an open channel and its PTY is ready, it must NOT call
  // openPty() again. Every open consumes a server stream slot, and repeated
  // Redraw/watchdog recovery was leaking one per click. Only rebind/reattach
  // when the link is actually down/replaced or the PTY is not ready. Safe to
  // call anytime (no link / no terminal yet => no-ops), and it never tears down
  // the terminal, so scrollback survives.
  const redrawRecover = useCallback(() => {
    const term = termRef.current
    safeFit()
    if (term) { try { term.refresh(0, Math.max(0, (term.rows || 1) - 1)) } catch (e) {} }
    const l = linkRef.current
    const ptyLive = !!(
      l
      && (ptyReadyLinkRef.current === l || ptyOpenLinkRef.current === l)
      && l.channel
      && l.channel.readyState === 'open'
      && (!l.pc || l.pc.connectionState === 'connected')
    )
    // Rebind + reattach only when the current link is gone/replaced or its PTY
    // is not owned at all. An open already in flight counts as owned: rebinding
    // would unbind the handler that receives its pty-ready ack. rebindLink
    // unbinds first, so a genuine reconnect still creates exactly one new
    // binding/poll and no duplicate handlers.
    if (l && !ptyLive) { try { rebindLink() } catch (e) {} }
    if (term) { try { focusTerminal() } catch (e) {} }
    haptic()
  }, [safeFit, rebindLink, focusTerminal])

  // mount xterm ONCE. This is the ONLY place the Terminal is created/opened and
  // (on final unmount) disposed. It is decoupled from `link`: a reconnect swaps
  // the link via the link-binding effect below and REBINDS callbacks to this same
  // terminal, so the screen never gets torn down and rebuilt (the freeze bug).
  useEffect(() => {
    const term = new Terminal({
      fontFamily: font, fontSize: isTouch ? 13 : 13.5, lineHeight: 1.3, letterSpacing: 0.2,
      cursorBlink: true, cursorStyle: 'bar', cursorWidth: 2, scrollback: 5000,
      theme: xtermTheme(T, accent), allowProposedApi: true,
      // A full-screen TUI (vim/htop/opencode) drives the alternate screen buffer
      // and expects unmodified passthrough: convertEol off (the PTY already sends
      // CRLF), the alt buffer scrollback clamped so the TUI owns the viewport.
      convertEol: false, altClickMovesCursor: false,
      // mobile: stop the OS keyboard from "helping"
      ...(isTouch ? { screenReaderMode: false } : {}),
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(hostRef.current)
    termRef.current = term; fitRef.current = fit
    // Predictive local echo. A pure overlay: the real key is still sent to the
    // PTY below; this only paints it a few ms sooner and self-corrects. Starts
    // OFF and turns on only after it observes the server echoing our input.
    const predict = new PredictiveEcho(term)
    predictRef.current = predict
    try {
      if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('preview')) {
        window.__webtermPredict = predict // dev harness assertion hook
      }
    } catch (e) {}
    // Dev-only: expose the live Terminal for the ?preview= harness so Playwright
    // can assert alt-screen state / dimensions. Inert in the real app (no query).
    try {
      if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('preview')) {
        window.__webterm = term
      }
    } catch (e) {}
    // Initial fit MUST land before we report a size to the PTY, otherwise the
    // shell allocates 80x24 while xterm shows a different geometry and a TUI
    // draws into the wrong region (issue #1).
    try { fit.fit() } catch (e) {}

    // harden the hidden textarea for mobile. The Android soft keyboard (Gboard)
    // does TWO destructive things to a terminal:
    //   1. predictive text / autocomplete: it COMPOSES a word in the textarea and
    //      replaces it on accept, so a single typed word arrives garbled.
    //   2. xterm's IME path re-reads the textarea value and, when composition
    //      never cleanly finalizes (Gboard's keyCode 229 stream), it re-emits the
    //      whole growing buffer on every keystroke ("I cant say... I cant say t
    //      ... I cant say th..." repeating). See xterm CompositionHelper.
    // The fix has two parts. (a) Tell the IME to stop predicting/correcting and
    // mark the field non-autofillable so Gboard sends discrete keys. (b) Strip
    // composition-based input events ourselves and forward only the inserted
    // delta to the PTY, so a replay of the accumulated value can never reach the
    // shell. We also keep the textarea cleared so there is no buffer to replay.
    const ta = hostRef.current.querySelector('textarea')
    if (ta) {
      ta.id = inputIdRef.current
      ta.setAttribute('aria-label', 'terminal input')
      ta.setAttribute('autocorrect', 'off'); ta.setAttribute('autocapitalize', 'off')
      ta.setAttribute('autocomplete', 'off'); ta.setAttribute('spellcheck', 'false')
      // Hints that suppress Gboard predictive text / suggestions strip on many
      // keyboards. Touch typing is explicitly enabled by the Keyboard button;
      // the enterkeyhint keeps Enter sane. data-gramm disables Grammarly overlays.
      ta.setAttribute('enterkeyhint', 'send'); ta.setAttribute('data-gramm', 'false')
      ta.setAttribute('aria-autocomplete', 'none')
      if (isTouch) {
        ta.readOnly = !keyboardOpenRef.current
        ta.setAttribute('inputmode', keyboardOpenRef.current ? 'text' : 'none')
        ta.setAttribute('virtualkeyboardpolicy', keyboardOpenRef.current ? 'auto' : 'manual')
      }
      // (b) On touch keyboards, neutralize the IME composition path WITHOUT
      // touching normal typing. Plain (non-composed) keys still flow through
      // xterm's own input handler, which is correct. The corruption is purely
      // the COMPOSITION path: xterm's CompositionHelper slices the textarea value
      // on a delayed timer and, with Gboard's predictive stream, re-emits the
      // whole growing buffer. We defang it by keeping the textarea EMPTY for the
      // duration of a composition (so the slice yields nothing) and committing
      // the resolved word ourselves, exactly once, on compositionend.
      if (isTouch) {
        let composing = false
        const onCompStart = () => { composing = true; composingRef.current = true; ta.value = '' }
        const onCompUpdate = () => { ta.value = '' } // never let it accumulate
        const onCompEnd = (e) => {
          composing = false; composingRef.current = false
          // Commit the resolved/autocompleted word ONCE.
          const data = e && e.data ? e.data : ''
          // Soft-keyboard visibility must not gate input: hardware keyboards
          // (including their IME composition) stay live while the software
          // keyboard is hidden. Commit once, whatever opened the keyboard.
          if (data) {
            write(applyMods(data))
            // Predict the committed text now (NOT during composition, so we never
            // double-insert): mirrors typing the resolved chars.
            if (!ctrl.current && !alt.current) {
              try { predictRef.current && predictRef.current.onUserText(data) } catch (err) {}
            }
          }
          // Blank on the next tick too: xterm's _finalizeComposition reads the
          // value from a setTimeout, so clearing now AND async keeps it empty.
          ta.value = ''
          setTimeout(() => { ta.value = '' }, 0)
        }
        // During composition, swallow the IME's interim insert events so neither
        // xterm nor the textarea accumulates a replayable buffer. Plain keys
        // (no composition active) are left entirely to xterm.
        const onBeforeInput = (e) => {
          const it = e.inputType || ''
          if (composing || it === 'insertCompositionText' || it === 'insertFromComposition') {
            if (e.cancelable) e.preventDefault()
            ta.value = ''
          }
        }
        // Capture phase: run before xterm's (capture-registered) input handler.
        ta.addEventListener('compositionstart', onCompStart, true)
        ta.addEventListener('compositionupdate', onCompUpdate, true)
        ta.addEventListener('compositionend', onCompEnd, true)
        ta.addEventListener('beforeinput', onBeforeInput, true)
      } else {
        // Desktop IME (no Gboard interception): xterm finalizes the composition
        // itself and emits the resolved text through term.onData. We only need to
        // suppress prediction WHILE composing so a half-formed candidate is not
        // painted; the committed text is predicted via onData like normal typing.
        ta.addEventListener('compositionstart', () => { composingRef.current = true }, true)
        ta.addEventListener('compositionend', () => { composingRef.current = false }, true)
      }
    }

    // The per-link binding (PTY callbacks + reattach) lives in bindLinkRef so the
    // link-binding effect and the redraw recovery share ONE implementation. It is
    // defined here, in the mount-once effect, so it closes over the persistent
    // `term`/`predict`/`fit` (which never change) and reads `linkRef.current` for
    // the link (which does). Returns an unbind cleanup.
    bindLinkRef.current = () => {
      const l = linkRef.current
      if (!l) return () => {}
      // bridge: PTY -> xterm. Raw bytes, written through unmodified so alternate
      // screen / cursor-addressing escapes reach the parser intact (issue #1).
      // Server bytes are authoritative. Let the predictor reconcile its pending
      // predictions against them FIRST (confirm matches / erase divergences), then
      // write the real bytes (which overwrite any confirmed styled cells with the
      // truth), then resync the predictor's view of the buffer (e.g. a flip into a
      // TUI's alternate screen drops prediction).
      l.onPtyData = (u8) => {
        // Watchdog signal: PTY bytes have arrived (timestamp + running byte
        // count). The watchdog compares this against whether the rendered buffer
        // actually advanced, to self-heal a wedged screen without a reload.
        try { wd.current.bytesAt = Date.now(); wd.current.byteCount += (u8 && u8.length) || 0 } catch (e) {}
        recvRef.current += (u8 && u8.length) || 0
        // predict.onServerData is itself fail-safe (wrapped in predict.js); the
        // extra guard here is belt-and-suspenders so the write still happens.
        try { predict.onServerData(u8) } catch (e) {}
        // The write-COMPLETION callback runs inside xterm's write loop: if it
        // throws, it jams the write queue and freezes rendering. Every bit of
        // work in here is therefore guarded so nothing can escape (the bug was
        // an UNGUARDED syncBar() here). predict.syncBuffer is also fail-safe.
        term.write(u8, () => {
          guarded('onPtyData.predict.syncBuffer', () => predict.syncBuffer())
          guarded('onPtyData.syncBar', () => syncBar())
        })
      }
      l.onPtyClose = (refusal) => {
        if (linkRef.current !== l) return
        wasReadyRef.current = false
        ptyReadyLinkRef.current = null
        ptyOpenLinkRef.current = null
        setStatus('closed')
        if (!refusal) { term.write('\r\n\x1b[90m( session ended )\x1b[0m\r\n'); return }
        // Refused by the device: say why, and the one command that fixes it
        // when it is a missing grant (the CLI's remedy for the same codes).
        const where = peerName ? `'${peerName}'` : 'that device'
        const me = refusal.as || 'this-browser'
        const grant = { 'shell-off': 1, 'not-granted': 1, 'tunnel-off': 1, revoked: 1 }[refusal.code]
        term.write(`\r\n\x1b[31mshell refused: ${refusal.err}\x1b[0m\r\n`)
        if (grant) term.write(`\x1b[90mto allow it, run this on ${where}:\x1b[0m\r\n  tunlion grant ${me} shell\r\n`)
      }
      l.onPtyReady = () => {
        if (linkRef.current !== l) return
        wasReadyRef.current = true
        ptyReadyLinkRef.current = l
        setStatus('ready')
        // The PTY is live (fresh or reattached): make sure its window size matches
        // what we actually render, then nudge a SIGWINCH so a TUI redraws to fit.
        safeFit()
        const t = termRef.current
        const cur = linkRef.current
        if (t && cur) cur.resizePty(t.cols || 80, t.rows || 24)
      }
      // open (or reattach to) the shell once the channel is up, carrying our
      // stable session id so the CLI can rebind a surviving PTY (issue #4). On a
      // link swap the SAME session id makes this a reattach, not a fresh shell, so
      // the still-running remote PTY replays into this SAME terminal.
      const begin = () => {
        const channelUp = !!(l.channel && l.channel.readyState === 'open')
        const pcUp = !l.pc || l.pc.connectionState === 'connected'
        if (!channelUp || !pcUp) {
          // The channel/PC is down: the PTY attachment is no longer usable.
          // Clear the ownership refs so the next open on this same link is a
          // genuine reattach, not a skipped duplicate. (Do this before the
          // pty-open guard; otherwise a Redraw racing the down detector can
          // unbind the ack handler and then skip the replacement open.)
          ptyReadyLinkRef.current = null
          ptyOpenLinkRef.current = null
          return false
        }
        // Already attached on this link, or an open is in flight: a local
        // repaint/rebind must not consume another server stream slot.
        if (ptyReadyLinkRef.current === l || ptyOpenLinkRef.current === l) return true
        const cols = term.cols || 80
        const rows = term.rows || 24
        // A reattach says how much it already has (resume_from); the first
        // open says nothing, so it looks exactly as it always did.
        l.openPty(cols, rows, sessionIdRef.current, openedRef.current ? recvRef.current : undefined)
        ptyOpenLinkRef.current = l
        openedRef.current = true
        setStatus(wasReadyRef.current ? 'reconnecting' : 'connecting')
        return true
      }
      let poll = null
      if (!begin()) poll = setInterval(() => { if (begin()) clearInterval(poll) }, 200)
      // Cleanup: ONLY unbind this link's handlers (no-op them) and stop the poll.
      // Never dispose the terminal and never closePty: a link swap must leave the
      // remote PTY running so the next link reattaches to it.
      return () => {
        if (poll) clearInterval(poll)
        l.onPtyData = () => {}; l.onPtyClose = () => {}; l.onPtyReady = () => {}
      }
    }

    // bridge: xterm -> PTY (with sticky modifiers). Prediction is attempted on
    // the RAW key first (cosmetic only; the real key is always sent), but only
    // when no sticky modifier is armed: Ctrl/Alt turn a printable into a control
    // sequence (applyMods), which the server will not echo as that char, so
    // predicting it would be wrong. We also never predict mid-IME-composition;
    // the resolved text is predicted on compositionend instead. write() targets
    // linkRef.current, so this sub stays correct across reconnects.
    // onData is user input (not inside xterm's write loop), but still fully
    // guarded so a predict/write throw can never wedge typing. predict.onUserKey
    // is itself fail-safe; this is belt-and-suspenders and protects write().
    const dataSub = term.onData((d) => {
      // SGR/SGR-pixel mouse reports arrive on onData, but they are generated
      // application input: sticky Ctrl/Alt must not prefix them or be consumed.
      // Ordinary typed/accessory input keeps the existing modifier semantics.
      // Only an exact SGR report shapes while a mouse protocol is live can be
      // generated input; the same bytes pasted into a plain shell are text.
      let mouseTracking = 'none'
      try { mouseTracking = term.modes.mouseTrackingMode } catch (e) {}
      const mouseReport = mouseTracking !== 'none' && isMouseReport(d)
      if (!mouseReport && !ctrl.current && !alt.current) {
        guarded('onData.predict', () => predict.onUserKey(d, composingRef.current))
      }
      guarded('onData.write', () => {
        if (mouseReport) write(d)
        else write(applyMods(d))
      })
    })
    // Legacy (X10/VT200/DRAG/ANY without an SGR encoding) mouse reports are
    // emitted on xterm's BINARY path. Their JS string code units are the wire
    // bytes; forward them raw as Uint8Array, never TextEncoder (UTF-8 would
    // corrupt coordinates/modifiers >127). Guarded + disposed with the terminal.
    const binarySub = term.onBinary((d) => {
      guarded('onBinary.write', () => writeBytes(latin1Bytes(d)))
    })
    // Resize -> PTY: route through linkRef.current so a reconnect keeps SIGWINCH
    // flowing to the new link without rebuilding this subscription. Guarded: a
    // resize handler runs on xterm's path and must never throw back into it.
    const sizeSub = term.onResize(({ cols, rows }) => {
      guarded('onResize.pty', () => { const l = linkRef.current; if (l) l.resizePty(cols, rows) })
    })
    // Track scroll position so the scroll-to-bottom affordance shows only when
    // the reader has scrolled up off the live tail. Fires on wheel, touch swipe,
    // and programmatic scrolls alike. Guarded so a thrown helper cannot wedge.
    const scrollSub = term.onScroll(() => {
      guarded('onScroll', () => { setAtBottom(computeAtBottom()); syncBar() })
    })
    // Keep the thumb in sync as output arrives and as the alt screen toggles.
    // onWriteParsed fires after each parsed chunk (covers TUI enter/exit and the
    // alternate-screen flip), INSIDE xterm's write loop, so guarding it is
    // essential; onLineFeed covers plain line growth. The watchdog also samples
    // a render tick here so it can tell the buffer actually advanced.
    const writeSub = term.onWriteParsed(() => guarded('onWriteParsed', () => { wd.current.renderAt = Date.now(); syncBar() }))
    const lineSub = term.onLineFeed(() => guarded('onLineFeed', () => { wd.current.renderAt = Date.now(); syncBar() }))
    const resizeBarSub = term.onResize(() => guarded('onResize.bar', () => syncBar()))

    // --- touch scrolling (issue #5) -----------------------------------------
    // On mobile a one-finger swipe over the terminal must scroll the right
    // context, not type into the PTY and not start a text selection. There are
    // three contexts (see lib/tui-scroll.js):
    //   history      normal buffer, no wheel-capable mouse mode -> scrollLines
    //   application  mouse reporting (even a partial TUI in normal buffer) ->
    //                synthetic wheel at the ORIGINAL touch cell; xterm encodes
    //                the selected protocol itself (SGR/legacy/pixels)
    //   cursor-keys  alternate screen with no wheel reporting -> synthetic
    //                wheel; xterm turns it into Up/Down respecting DECCKM
    // We never preventDefault on a clear horizontal move (allow selection/bar),
    // and a swipe under a small threshold stays a tap. The explicit keyboard
    // policy above decides whether that focus may open the soft keyboard.
    const host = hostRef.current
    let tY = 0, tX = 0, tStartX = 0, tStartY = 0, tAccum = 0, tMoved = false, tActive = false
    let tRoute = SCROLL_HISTORY
    let tModeKey = ''
    const cellH = () => {
      const t = termRef.current
      // Measure the rendered screen, not .xterm-viewport: in xterm 6 the
      // viewport element can report clientHeight 0 (the renderer owns the
      // canvas), which used to make this fall back to 8px and move ~2.4 rows
      // per finger row. The screen rect is exactly rows * cell height.
      const screen = host && host.querySelector('.xterm-screen')
      if (screen && t && t.rows) {
        const h = screen.getBoundingClientRect().height
        if (h > 0) return Math.max(8, h / t.rows)
      }
      return 18
    }
    const onTouchStart = (e) => {
      if (e.touches.length !== 1) { tActive = false; return }
      const t = termRef.current
      if (!t) { tActive = false; return }
      // Capture the context once per gesture. A TUI entering/exiting mouse mode
      // or flipping buffers mid-swipe aborts below instead of delivering the
      // captured route to whatever app arrived next.
      tRoute = routeForTerm(t)
      try { tModeKey = scrollModeKey(t.buffer.active.type, t.modes.mouseTrackingMode) } catch (e) { tModeKey = '' }
      tActive = true; tMoved = false; tAccum = 0
      tY = e.touches[0].clientY; tX = e.touches[0].clientX
      tStartY = tY; tStartX = tX
    }
    const onTouchMove = (e) => {
      if (!tActive || e.touches.length !== 1) return
      const t = termRef.current
      if (!t) { tActive = false; return }
      let nowKey = ''
      try { nowKey = scrollModeKey(t.buffer.active.type, t.modes.mouseTrackingMode) } catch (err) { nowKey = '' }
      if (tModeKey && nowKey !== tModeKey) {
        // The app changed scroll context under the finger. Drop the rest of this
        // gesture rather than scrolling/reporting into the new one.
        tActive = false; tMoved = false; tAccum = 0
        return
      }
      const y = e.touches[0].clientY, x = e.touches[0].clientX
      const dy = y - tY, dx = x - tX
      // Ignore a mostly-horizontal drag (let it be / allow text selection drag).
      if (!tMoved && Math.abs(dx) > Math.abs(dy)) { tActive = false; return }
      if (!tMoved && Math.abs(dy) < 6) return // below the tap threshold, keep watching
      tMoved = true
      // Swiping the content DOWN (finger moves down, dy>0) reveals older lines:
      // scroll up. Accumulate sub-cell motion so slow drags still move.
      tAccum += dy
      const h = cellH()
      const lines = Math.trunc(tAccum / h)
      if (lines !== 0) {
        tAccum -= lines * h
        if (tRoute === SCROLL_HISTORY) {
          const t = termRef.current
          if (t) t.scrollLines(-lines)
        } else {
          // Original touch position, not the finger's current cell: xterm
          // reports the cell the user grabbed, and every line of the swipe
          // rides the same application protocol handler exactly once.
          // Finger down (lines > 0) reveals older content = wheel up (-1).
          dispatchWheel(tStartX, tStartY, Math.abs(lines), lines > 0 ? -1 : 1)
        }
      }
      tY = y; tX = x
      if (e.cancelable) e.preventDefault() // stop selection + PTY input on a scroll
    }
    const onTouchEnd = () => {
      // A genuine tap falls through to xterm (including TUI mouse reporting),
      // but its textarea stays non-editable until Keyboard is explicitly on.
      tActive = false
    }
    host.addEventListener('touchstart', onTouchStart, { passive: true })
    host.addEventListener('touchmove', onTouchMove, { passive: false })
    host.addEventListener('touchend', onTouchEnd, { passive: true })
    host.addEventListener('touchcancel', onTouchEnd, { passive: true })

    const ro = new ResizeObserver(() => safeFit())
    ro.observe(hostRef.current)
    // Focus the helper textarea on mount even in touch/browse mode so a
    // hardware keyboard has a target immediately. On touch it is readOnly with
    // inputmode=none, which is what keeps the SOFTWARE keyboard closed; do not
    // replace this with focusTerminal() (that intentionally skips hidden mode
    // for accessory/scroll/reconnect paths).
    try { term.focus() } catch (e) {}

    // Final-unmount cleanup ONLY. This effect has deps [] so it runs exactly
    // once on mount and its cleanup runs exactly once on unmount: the ONLY place
    // the terminal/predictor/terminal-level subs are disposed. A reconnect does
    // NOT come through here (it is the [link] effect), so the terminal survives a
    // link swap, preserving scrollback and never blanking the screen.
    return () => {
      if (fitRaf.current) { cancelAnimationFrame(fitRaf.current); fitRaf.current = 0 }
      dataSub.dispose(); binarySub.dispose(); sizeSub.dispose(); scrollSub.dispose(); ro.disconnect()
      try { writeSub.dispose(); lineSub.dispose(); resizeBarSub.dispose() } catch (e) {}
      host.removeEventListener('touchstart', onTouchStart)
      host.removeEventListener('touchmove', onTouchMove)
      host.removeEventListener('touchend', onTouchEnd)
      host.removeEventListener('touchcancel', onTouchEnd)
      try { predict.dispose() } catch (e) {}
      predictRef.current = null
      term.dispose()
      termRef.current = null; fitRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Link-binding effect: when `link` changes (a reconnect hands us a fresh
  // PeerLink), point linkRef at it and REBIND its PTY callbacks to the EXISTING
  // terminal, then re-open/reattach the PTY with the stable session id. Cleanup
  // only unbinds the old link's handlers (set to no-ops) and stops its poll; it
  // does NOT dispose or recreate the terminal and does NOT closePty, so the
  // remote PTY keeps running across the swap.
  useEffect(() => {
    linkRef.current = link
    if (!link) {
      // The link went away under a live shell: the remote PTY keeps running and
      // the next link reattaches to it, so say so instead of "connecting".
      ptyReadyLinkRef.current = null
      ptyOpenLinkRef.current = null
      if (wasReadyRef.current) setStatus('reconnecting')
      return
    }
    rebindLink()
    return () => { try { if (unbindRef.current) unbindRef.current() } catch (e) {}; unbindRef.current = null }
  }, [link, rebindLink])

  // A link can die before the app hands over a new one (the channel closes, the
  // PeerLink object stays). Watch the live shell's channel and show
  // "reconnecting" the moment it is gone, so the bar never claims a live route.
  // The same link can also come back (ICE recovers after a network blip). The
  // device may have detached the shell meanwhile, so reattach over it; the
  // resume_from count keeps that from repeating anything.
  const rebindRef = useRef(rebindLink)
  rebindRef.current = rebindLink
  const downLinkRef = useRef(null)
  useEffect(() => {
    const t = setInterval(() => {
      const l = linkRef.current
      const ch = l && l.channel
      const pcs = l && l.pc && l.pc.connectionState
      const down = !ch || ch.readyState !== 'open' || (!!pcs && pcs !== 'connected')
      if (statusRef.current === 'ready' && down) {
        downLinkRef.current = l
        // The attachment cannot survive a dead channel: allow exactly one
        // reattach when this link (or its replacement) comes back.
        ptyReadyLinkRef.current = null
        ptyOpenLinkRef.current = null
        setStatus('reconnecting')
      } else if (statusRef.current === 'reconnecting' && !down && l && l === downLinkRef.current) {
        downLinkRef.current = null
        try { rebindRef.current() } catch (e) {}
      }
    }, 1000)
    return () => clearInterval(t)
  }, [])

  // Explicit teardown: closing the session (the ✕) must end the remote PTY.
  // Kept separate from the link-swap unbind above so a reconnect never kills it.
  const endSession = useCallback(() => {
    try { const l = linkRef.current; l && l.closePty() } catch (e) {}
    onClose && onClose()
  }, [onClose])

  // Dev-only: expose the no-reload recovery to the ?preview= harness so Playwright
  // can trigger it without a synthetic tap. Inert in the real app (no query).
  useEffect(() => {
    try {
      if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('preview')) {
        window.__webtermRecover = redrawRecover
        // Fault-injection hooks for the harness to prove the guards work:
        //  __webtermThrowSyncBar(): next syncBar() throws once (must be swallowed).
        //  __webtermWatchdog: live watchdog state (so a "stuck" state can be faked
        //  by freezing the render signature while bumping byteCount).
        window.__webtermThrowSyncBar = () => { throwSyncBarRef.current = true }
        window.__webtermWatchdog = wd.current
      }
    } catch (e) {}
  }, [redrawRecover])

  // Render watchdog: a cheap 1s poll that self-heals a wedged screen with no
  // reload. A render "signature" captures whether the terminal actually advanced
  // (buffer length + cursor); if it is unchanged WHILE new PTY bytes have arrived
  // since the last advance, the screen is stuck (bytes in, nothing painted), so
  // we run the existing redrawRecover() once. Guards against false positives:
  //   - only acts when byteCount grew since we last saw the render advance, so an
  //     idle terminal (no incoming bytes) is never touched;
  //   - requires the stall to persist (bytes arrived >= STALL_MS ago and render
  //     still has not moved), so a single slow frame does not trip it;
  //   - rate-limited (one recover per RECOVER_COOLDOWN) so it cannot thrash.
  useEffect(() => {
    const STALL_MS = 3500   // bytes arrived but render frozen this long => wedged
    const COOLDOWN = 8000   // do not re-recover more often than this
    const tick = () => {
      const term = termRef.current
      const s = wd.current
      if (!term) return
      // Current render signature: total buffer length + cursor position. Any real
      // paint advances at least one of these; reading it is cheap.
      let sig = ''
      try {
        const b = term.buffer && term.buffer.active
        if (b) sig = b.length + ':' + b.baseY + ':' + b.cursorY + ':' + b.cursorX
      } catch (e) { return }
      const now = Date.now()
      // If the signature changed, the terminal advanced: record it and clear the
      // "bytes since last advance" baseline (we are caught up to the render).
      if (sig !== s.lastSig) {
        s.lastSig = sig
        s.renderAt = now
        s.lastByteCount = s.byteCount
        return
      }
      // Signature unchanged. Only a wedge if NEW bytes arrived since the last
      // advance AND those bytes are old enough to have rendered by now.
      const bytesSinceAdvance = s.byteCount - s.lastByteCount
      const bytesAreStale = s.bytesAt && (now - s.bytesAt) >= STALL_MS
      const renderStale = s.renderAt && (now - s.renderAt) >= STALL_MS
      if (bytesSinceAdvance > 0 && bytesAreStale && renderStale) {
        if (now - s.recoverAt < COOLDOWN) return
        s.recoverAt = now
        // Reset the baseline so a successful recover does not immediately re-trip.
        s.lastByteCount = s.byteCount
        s.renderAt = now
        try { log.warn('webterm: render wedge detected, auto-recovering', { bytesSinceAdvance }) } catch (e) {}
        guarded('watchdog.redrawRecover', () => redrawRecover())
      }
    }
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [redrawRecover])

  // live theme
  useEffect(() => { if (termRef.current) termRef.current.options.theme = xtermTheme(T, accent) }, [T, accent])

  // Sessions dock: when this instance is un-hidden (reopened from the background)
  // its host had display:none, so xterm couldn't measure: refit + force a full
  // repaint + refocus now that it's visible again. A renderer that paused while
  // the host was hidden / zero-size (mobile keyboard, backgrounded session) needs
  // the explicit term.refresh to resume painting, otherwise the first frame back
  // can stay blank. The terminal was NEVER unmounted, so scrollback and the live
  // PTY are intact. requestAnimationFrame waits for the layout to apply.
  useEffect(() => {
    if (hidden) {
      if (isTouch) setKeyboard(false)
      return
    }
    const raf = requestAnimationFrame(() => {
      safeFit()
      const term = termRef.current
      if (term) { try { term.refresh(0, Math.max(0, (term.rows || 1) - 1)) } catch (e) {} }
      try { term && focusTerminal() } catch (e) {}
    })
    return () => cancelAnimationFrame(raf)
  }, [hidden, safeFit, focusTerminal, setKeyboard])

  // visualViewport keyboard avoidance: lift the bar above the soft keyboard.
  // The inset state-set is cheap; the refit is the guarded, coalesced safeFit so
  // a keyboard-open/close burst can never wedge the terminal (issue #2).
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const onVV = () => {
      // When the host is pinned to the visual viewport the visible box already
      // excludes the keyboard, so the bar needs no extra lift (kbInset stays 0).
      // Otherwise (e.g. a host pinned to the layout viewport) lift it ourselves.
      const inset = viewportPinned ? 0 : Math.max(0, window.innerHeight - vv.height - vv.offsetTop)
      setKbInset(inset)
      safeFit()
    }
    onVV()
    vv.addEventListener('resize', onVV); vv.addEventListener('scroll', onVV)
    return () => { vv.removeEventListener('resize', onVV); vv.removeEventListener('scroll', onVV) }
  }, [safeFit, viewportPinned])

  // --- copy / paste (issue #3) --------------------------------------------
  // Desktop: select-to-copy (auto-copies the current selection) + Ctrl/Cmd+V
  // paste. Mobile: explicit Copy/Paste accessory buttons, since selection + the
  // OS clipboard are awkward on touch. A tiny toast confirms success/failure so
  // a silent clipboard rejection (common on Android) is no longer invisible.

  // robust clipboard write: the async Clipboard API first, then a hidden
  // textarea + execCommand('copy') fallback for browsers/contexts that block it.
  const writeClipboard = useCallback(async (text) => {
    if (!text) return false
    try { await navigator.clipboard.writeText(text); return true } catch (e) {}
    try {
      const tmp = document.createElement('textarea')
      tmp.value = text
      tmp.readOnly = true
      tmp.setAttribute('inputmode', 'none')
      tmp.style.position = 'fixed'; tmp.style.opacity = '0'; tmp.style.top = '0'
      document.body.appendChild(tmp); tmp.focus(); tmp.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(tmp)
      return ok
    } catch (e) { return false }
  }, [])

  // Copy: the current selection if there is one; on touch (where making a
  // precise selection is hard) fall back to copying the VISIBLE viewport, so
  // "grab that output" works with a single tap.
  const copySelection = useCallback(async () => {
    const term = termRef.current
    if (!term) return false
    let text = term.getSelection()
    if ((!text || !text.length) && isTouch) {
      try {
        const b = term.buffer.active
        const lines = []
        for (let i = 0; i < term.rows; i++) {
          const ln = b.getLine(b.viewportY + i)
          if (ln) lines.push(ln.translateToString(true))
        }
        text = lines.join('\n').replace(/\n+$/, '')
      } catch (e) {}
    }
    if (!text || !text.length) { showToast('nothing to copy'); return false }
    const ok = await writeClipboard(text)
    haptic(); showToast(ok ? 'copied' : 'copy blocked')
    return ok
  }, [writeClipboard, showToast])

  const pasteClipboard = useCallback(async () => {
    let text = ''
    try { text = await navigator.clipboard.readText() } catch (e) {
      showToast('paste blocked: allow clipboard'); return false
    }
    if (!text) { showToast('clipboard empty'); return false }
    write(text) // bracketed-paste-safe: the PTY/app decides how to treat it
    haptic(); showToast('pasted')
    focusTerminal()
    return true
  }, [write, showToast, focusTerminal])

  // Auto-copy on selection (desktop): mirrors a normal terminal's behavior and
  // gives mobile a no-op-safe path. Wired once per mounted terminal.
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    const sub = term.onSelectionChange(() => {
      if (isTouch) return // touch selection is too jumpy to auto-copy
      const sel = term.getSelection()
      if (sel && sel.length) navigator.clipboard && navigator.clipboard.writeText(sel).catch(() => {})
    })
    // Ctrl/Cmd+Shift+C copy, Ctrl/Cmd+Shift+V / Ctrl+Cmd+V paste. We attach a
    // key handler that returns false to let xterm forward keys we don't claim.
    const keySub = term.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true
      const mod = e.ctrlKey || e.metaKey
      if (mod && e.shiftKey && (e.key === 'C' || e.key === 'c')) { copySelection(); return false }
      if (mod && e.shiftKey && (e.key === 'V' || e.key === 'v')) { pasteClipboard(); return false }
      return true
    })
    return () => { try { sub.dispose() } catch (e) {} }
    // attachCustomKeyEventHandler has no disposer; replaced on remount. keySub unused.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [copySelection, pasteClipboard])

  const sendKey = (label) => {
    haptic()
    const base = KEYS[label]
    if (base == null) return
    write(applyMods(base))
    focusTerminal()
  }
  const toggleCtrl = () => { ctrl.current = !ctrl.current; setCtrlOn(ctrl.current); haptic(); focusTerminal() }
  const toggleAlt = () => { alt.current = !alt.current; setAltOn(alt.current); haptic(); focusTerminal() }

  const dot = status === 'ready' ? T.ok : status === 'closed' ? T.bad : T.warn
  // Say what the page buttons actually do in the current context.
  const pageHint = (verb) => {
    if (wheelRoute === SCROLL_APPLICATION) return `scroll the running app ${verb}`
    if (wheelRoute === SCROLL_CURSOR_KEYS) return `send cursor-key ${verb} to the alternate-screen app`
    return `scroll terminal history ${verb}`
  }

  // accessory bar key spec (default row). Copy/Paste live at the end so they are
  // always reachable on touch (issue #3).
  const ROW = [
    { l: 'Esc' }, { l: 'Tab' }, { l: 'ctrl', on: ctrlOn, fn: toggleCtrl }, { l: 'alt', on: altOn, fn: toggleAlt },
    { l: 'Up', g: '↑' }, { l: 'Down', g: '↓' }, { l: 'Left', g: '←' }, { l: 'Right', g: '→' },
    { l: '|' }, { l: '/' }, { l: '~' }, { l: '-' }, { l: 'Home', g: '⤒' }, { l: 'End', g: '⤓' }, { l: 'Del' },
    // Page controls are mode-aware: local history in an ordinary shell, wheel
    // reports (or xterm's cursor-key fallback) when an app owns the alternate
    // screen / mouse wheel. Never a blind PgUp/PgDn into the shell's input.
    { l: 'ScrollUp', g: '⇞', fn: () => scrollPage(-1), title: pageHint('up'), label: pageHint('up') },
    { l: 'ScrollDn', g: '⇟', fn: () => scrollPage(1), title: pageHint('down'), label: pageHint('down') },
    // No-reload recovery: repaint + reattach if the screen ever freezes after a
    // flaky reconnect, so the user never has to reload the page.
    { l: 'Redraw', g: '⟳', fn: redrawRecover },
    { l: 'Copy', g: 'copy', fn: copySelection }, { l: 'Paste', g: 'paste', fn: pasteClipboard },
  ]

  return (
    <div data-session-id={instanceId} style={{ position: 'absolute', inset: 0, background: T.bg, color: T.text, fontFamily: font, display: 'flex', flexDirection: 'column' }}>
      {/* header: one line, "name · relation · route". Tap it for the full
          line and the route explainer. Hide keeps the shell running (reachable
          from Open shells on Home); End closes it. 44 px targets on phones. */}
      {(() => {
        const sans = uiFont || font
        const routeWord = route === 'relayed' ? 'relay' : route === 'local' ? 'on your network' : (route || 'direct')
        const stateWord = status === 'connecting' ? 'connecting' : status === 'reconnecting' ? 'reconnecting' : status === 'closed' ? 'ended' : routeWord
        const tgt = narrow || isTouch ? 44 : 36
        const hb = { minHeight: tgt, minWidth: tgt, padding: '0 12px', borderRadius: 7, cursor: 'pointer', font: `600 14px ${sans}`, background: 'transparent', color: T.text, border: `1.5px solid ${T.line}` }
        return (
          <div style={{ flex: '0 0 auto', borderBottom: `1px solid ${T.line}`, background: T.panel || T.bg }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px' }}>
              <button type="button" onClick={endSession} title="end the shell" aria-label={`end the shell on ${peerName || 'this device'}`} style={hb}>End</button>
              <button type="button" onClick={() => setBarOpen((v) => !v)} aria-expanded={barOpen}
                style={{ flex: 1, minWidth: 0, minHeight: tgt, border: 0, background: 'none', color: T.text, textAlign: 'left', cursor: 'pointer', font: `600 14px ${sans}`, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: 8, flexShrink: 0, background: dot }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {peerName || 'shell'} · {relation || 'remembered'} · <span style={{ color: route === 'relayed' ? T.warn : T.text }}>{stateWord}</span>
                </span>
                <span aria-hidden="true" style={{ color: T.sub }}>{barOpen ? '\u25b4' : '\u25be'}</span>
              </button>
              {isTouch && (
                // A label, not a button, and it STAYS MOUNTED in both states:
                // its default activation focuses the xterm textarea after
                // setKeyboard has made it editable, which is the trusted gesture
                // iOS needs to raise the soft keyboard. Replacing the element
                // during the click would cancel that default action. On hide we
                // prevent the default so the label does not refocus the input.
                <label htmlFor={inputIdRef.current} data-testid="term-keyboard"
                  role="button" tabIndex={0}
                  aria-label={keyboardOpen ? 'hide terminal keyboard' : 'show terminal keyboard'}
                  aria-pressed={keyboardOpen}
                  title={keyboardOpen ? 'hide keyboard; keep viewing' : 'show keyboard to type'}
                  onClick={(e) => {
                    const open = !keyboardOpenRef.current
                    if (!open) e.preventDefault()
                    setKeyboard(open)
                    haptic()
                  }}
                  onKeyDown={(e) => {
                    if (e.key !== 'Enter' && e.key !== ' ') return
                    e.preventDefault()
                    const open = !keyboardOpenRef.current
                    setKeyboard(open)
                    haptic()
                    if (open) { try { hostRef.current?.querySelector('textarea')?.focus() } catch (err) {} }
                  }}
                  style={{
                    ...hb, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    userSelect: 'none', color: keyboardOpen ? T.onAccent : T.text,
                    background: keyboardOpen ? accent : 'transparent',
                  }}
                >Keyboard</label>
              )}
              {onBackground && <button type="button" onClick={onBackground} title="hide (keeps running)" style={hb}>Hide</button>}
            </div>
            {barOpen && (
              <div style={{ padding: '4px 12px 10px', display: 'grid', gap: 6, font: `13px/1.45 ${sans}`, color: T.sub }}>
                <span style={{ font: `500 12.5px/1.45 ${font}`, color: T.text }}>
                  shell on {peerName || 'this device'} · {relation || 'remembered'} · {route === 'relayed' ? 'via relay' : routeWord}
                </span>
                <span style={{ color: route === 'relayed' ? T.warn : T.sub }}>
                  {route === 'relayed' ? (relayExplainer || 'On relay: not a direct link. Still end-to-end encrypted.') : 'Direct link: bytes go straight between the two devices.'}
                </span>
                <span>Whether this browser may open a shell is decided on {peerName || 'that device'}. Hide keeps it running; End closes it.</span>
              </div>
            )}
          </div>
        )
      })()}
      {/* terminal (position:relative anchors the scroll-to-bottom affordance) */}
      <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        <div ref={hostRef} data-testid="term-host" style={{ position: 'absolute', inset: 0, padding: '8px 10px', touchAction: 'none' }} />
        {/* Custom scrollbar: a track + draggable thumb pinned to the right edge,
            ABOVE the xterm canvas (zIndex 4, under the modal-level toast/button).
            The track is a wide (28px) touch target so a finger can land it; the
            visible rail inside is slimmer. Hidden when everything fits or a TUI
            owns the alt screen. It does NOT use touch-action/swipe: a dragged DOM
            element with pointer capture works the same on iPad, Android, desktop. */}
        {bar.visible && (
          <div ref={trackRef} data-testid="term-scrollbar" onPointerDown={onTrackDown}
            style={{
              position: 'absolute', top: 6, bottom: 6, right: 0, width: 28,
              zIndex: 4, cursor: 'pointer', touchAction: 'none',
              display: 'flex', justifyContent: 'center',
            }}>
            {/* rail (visual) */}
            <div style={{ position: 'absolute', top: 0, bottom: 0, right: 9, width: 6, borderRadius: 3, background: T.lineSoft, opacity: 0.5 }} />
            {/* thumb (the grab target). It is wider than the rail so it is easy to
                hit; pointer events here scroll, never reach xterm. */}
            <button data-testid="term-scrollbar-thumb" aria-label="scroll terminal"
              onPointerDown={onThumbDown} onPointerMove={onThumbMove}
              onPointerUp={onThumbUp} onPointerCancel={onThumbUp}
              style={{
                position: 'absolute', right: 5, width: 14, padding: 0, margin: 0,
                top: `${bar.top}%`, height: `${bar.height}%`, minHeight: 28,
                borderRadius: 7, border: `1px solid ${accent}66`, background: accent,
                opacity: 0.9, cursor: 'grab', touchAction: 'none',
                boxShadow: '0 1px 4px rgba(0,0,0,.4)',
              }} />
          </div>
        )}
        {/* scroll-to-bottom: appears only when scrolled up off the live tail.
            Touch-sized (44px), unobtrusive, jumps back to the prompt. */}
        {!atBottom && (
          <button data-testid="scroll-to-bottom" aria-label="scroll to bottom"
            onClick={scrollToBottom}
            style={{
              position: 'absolute', right: 14, bottom: 14, width: 44, height: 44,
              borderRadius: 22, cursor: 'pointer', zIndex: 5,
              display: 'grid', placeItems: 'center', fontSize: 18, lineHeight: 1,
              border: `1px solid ${accent}66`, color: T.onAccent, background: accent,
              boxShadow: '0 2px 10px rgba(0,0,0,.45)', opacity: 0.92,
            }}>↓</button>
        )}
        {/* copy/paste feedback toast: makes a silent clipboard rejection visible */}
        {toast && (
          <div data-testid="term-toast" style={{
            position: 'absolute', left: '50%', bottom: 14, transform: 'translateX(-50%)',
            zIndex: 6, pointerEvents: 'none', fontSize: 12, padding: '6px 12px',
            borderRadius: 8, color: T.text, background: T.panel2,
            border: `1px solid ${T.line}`, boxShadow: '0 2px 10px rgba(0,0,0,.45)',
            whiteSpace: 'nowrap',
          }}>{toast}</div>
        )}
      </div>
      {/* accessory key bar (always on touch; handy on desktop too) */}
      <div style={{
        flex: '0 0 auto', display: 'flex', gap: 6, padding: '7px 10px', borderTop: `1px solid ${T.line}`,
        overflowX: 'auto', background: T.panel2, marginBottom: kbInset, WebkitOverflowScrolling: 'touch',
      }}>
        {ROW.map((k, i) => {
          const active = k.on
          return (
            <button key={i} data-key={k.l} aria-label={k.label || k.l} title={k.title} aria-pressed={k.on === undefined ? undefined : !!k.on} onClick={k.fn || (() => sendKey(k.l))} style={{
              flex: '0 0 auto', minWidth: narrow || isTouch ? 44 : 38, minHeight: narrow || isTouch ? 44 : 34, padding: '0 11px', fontFamily: font, fontSize: 13, borderRadius: 7,
              cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all .1s',
              border: `1px solid ${active ? accent : T.line}`, color: active ? T.onAccent : T.text,
              background: active ? accent : 'transparent',
            }}>{k.g || k.l}</button>
          )
        })}
      </div>
    </div>
  )
}
