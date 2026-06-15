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

// viewportPinned: the host (the terminal overlay in Filament.jsx, and the
// preview wrapper) already sizes itself to the VISUAL viewport, so the visible
// box already excludes the soft keyboard. In that case we must NOT also lift the
// accessory bar by kbInset (that would double-count the keyboard, leaving a gap
// and shrinking the terminal). We still listen to visualViewport so a keyboard
// open/close triggers a refit, we just keep the bar margin at 0.
export default function WebTerminal({ link, peerName, route, T, accent, font, onClose, onBackground, hidden, instanceId, viewportPinned }) {
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
  const [kbInset, setKbInset] = useState(0) // visualViewport keyboard height
  const [atBottom, setAtBottom] = useState(true) // false => show scroll-to-bottom
  const [toast, setToast] = useState('') // brief copy/paste feedback
  const toastTimer = useRef(0)
  const sessionIdRef = useRef(makeSessionId(instanceId))
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
  const scrollToBottom = useCallback(() => {
    const term = termRef.current
    if (!term) return
    term.scrollToBottom()
    setAtBottom(true)
    haptic()
    try { term.focus() } catch (e) {}
  }, [])
  // Page up/down for the accessory bar (a touch-friendly chunk scroll). A near-
  // full-page step (rows - 1) keeps a line of context, like a pager.
  const scrollPage = useCallback((dir) => {
    const term = termRef.current
    if (!term) return
    if (term.buffer && term.buffer.active && term.buffer.active.type === 'alternate') return
    term.scrollLines(dir * Math.max(1, (term.rows || 24) - 1))
    haptic()
  }, [])

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
    if (b.type === 'alternate' || b.baseY <= 0) {
      setBar((p) => (p.visible ? { ...p, visible: false } : p)); return
    }
    const rows = term.rows || 24
    const total = b.baseY + rows
    const h = Math.max(8, (rows / total) * 100) // % of track, floored so it stays grabbable
    const maxTop = 100 - h
    const top = total > rows ? (b.viewportY / b.baseY) * maxTop : 0
    setBar({ visible: true, top: Math.max(0, Math.min(maxTop, top)), height: h })
  }, [])

  // Map a fractional position along the track (0 = top, 1 = bottom) to a buffer
  // line and scroll there. Used by both the thumb drag and a track tap-to-page
  // would use scrollLines instead; here we jump precisely.
  const scrollToFraction = useCallback((frac) => {
    const term = termRef.current
    const b = term && term.buffer && term.buffer.active
    if (!term || !b || b.type === 'alternate') return
    const f = Math.max(0, Math.min(1, frac))
    term.scrollToLine(Math.round(f * b.baseY))
  }, [])

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
  // after a flaky reconnect / a hidden then re-shown host), this re-fits, forces
  // a FULL repaint of every row, rebinds the current link's PTY callbacks, and
  // re-opens/reattaches the PTY with our stable session id. Safe to call anytime
  // (no link / no terminal yet => no-ops), and it never tears down the terminal,
  // so scrollback survives. Wired to a button near the scroll-to-bottom control.
  const redrawRecover = useCallback(() => {
    const term = termRef.current
    safeFit()
    if (term) { try { term.refresh(0, Math.max(0, (term.rows || 1) - 1)) } catch (e) {} }
    // Rebind + reattach the CURRENT link (rebindLink unbinds the old binding
    // first, so there is no duplicate handler or leaked poll).
    if (linkRef.current) { try { rebindLink() } catch (e) {} }
    if (term) { try { term.focus() } catch (e) {} }
    haptic()
  }, [safeFit, rebindLink])

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
      ta.setAttribute('autocorrect', 'off'); ta.setAttribute('autocapitalize', 'off')
      ta.setAttribute('autocomplete', 'off'); ta.setAttribute('spellcheck', 'false')
      // Hints that suppress Gboard predictive text / suggestions strip on many
      // keyboards. inputmode stays 'text' (we still want the keyboard); the
      // enterkeyhint keeps Enter sane. data-gramm disables Grammarly overlays.
      ta.setAttribute('enterkeyhint', 'send'); ta.setAttribute('data-gramm', 'false')
      ta.setAttribute('aria-autocomplete', 'none')
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
      l.onPtyClose = () => { setStatus('closed'); term.write('\r\n\x1b[90m( session ended )\x1b[0m\r\n') }
      l.onPtyReady = () => {
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
        if (l.channel && l.channel.readyState === 'open') {
          const cols = term.cols || 80
          const rows = term.rows || 24
          l.openPty(cols, rows, sessionIdRef.current)
          setStatus('connecting')
          return true
        }
        return false
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
      if (!ctrl.current && !alt.current) {
        guarded('onData.predict', () => predict.onUserKey(d, composingRef.current))
      }
      guarded('onData.write', () => write(applyMods(d)))
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
    // On mobile a one-finger swipe over the terminal must scroll the SCROLLBACK,
    // not type into the PTY and not start a text selection. xterm's own viewport
    // is touch-finicky, so we translate vertical swipe delta into scrollLines on
    // the host element directly. We never preventDefault on a clear horizontal
    // move (let the accessory bar / page scroll), and we skip the alternate
    // screen (a TUI owns touch there, e.g. scrolling a list). A swipe under a
    // small threshold is treated as a tap so the keyboard/selection still work.
    const host = hostRef.current
    let tY = 0, tX = 0, tAccum = 0, tMoved = false, tActive = false
    const cellH = () => {
      const t = termRef.current
      // approximate row height in px from the viewport; fall back to font-based.
      const vp = host && host.querySelector('.xterm-viewport')
      if (vp && t && t.rows) return Math.max(8, vp.clientHeight / t.rows)
      return 18
    }
    const onTouchStart = (e) => {
      if (e.touches.length !== 1) { tActive = false; return }
      const t = termRef.current
      if (t && t.buffer && t.buffer.active && t.buffer.active.type === 'alternate') { tActive = false; return }
      tActive = true; tMoved = false; tAccum = 0
      tY = e.touches[0].clientY; tX = e.touches[0].clientX
    }
    const onTouchMove = (e) => {
      if (!tActive || e.touches.length !== 1) return
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
        const t = termRef.current
        if (t) t.scrollLines(-lines)
      }
      tY = y; tX = x
      if (e.cancelable) e.preventDefault() // stop selection + PTY input on a scroll
    }
    const onTouchEnd = () => {
      // A genuine tap (no scroll) falls through so xterm focuses + the soft
      // keyboard opens; a scroll swallowed its motion above. Nothing to do here
      // beyond resetting; focus on tap is xterm's own job.
      tActive = false
    }
    host.addEventListener('touchstart', onTouchStart, { passive: true })
    host.addEventListener('touchmove', onTouchMove, { passive: false })
    host.addEventListener('touchend', onTouchEnd, { passive: true })
    host.addEventListener('touchcancel', onTouchEnd, { passive: true })

    const ro = new ResizeObserver(() => safeFit())
    ro.observe(hostRef.current)
    term.focus()

    // Final-unmount cleanup ONLY. This effect has deps [] so it runs exactly
    // once on mount and its cleanup runs exactly once on unmount: the ONLY place
    // the terminal/predictor/terminal-level subs are disposed. A reconnect does
    // NOT come through here (it is the [link] effect), so the terminal survives a
    // link swap, preserving scrollback and never blanking the screen.
    return () => {
      if (fitRaf.current) { cancelAnimationFrame(fitRaf.current); fitRaf.current = 0 }
      dataSub.dispose(); sizeSub.dispose(); scrollSub.dispose(); ro.disconnect()
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
    if (!link) return
    rebindLink()
    return () => { try { if (unbindRef.current) unbindRef.current() } catch (e) {}; unbindRef.current = null }
  }, [link, rebindLink])

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
    if (hidden) return
    const raf = requestAnimationFrame(() => {
      safeFit()
      const term = termRef.current
      if (term) { try { term.refresh(0, Math.max(0, (term.rows || 1) - 1)) } catch (e) {} }
      try { term && term.focus() } catch (e) {}
    })
    return () => cancelAnimationFrame(raf)
  }, [hidden, safeFit])

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
    termRef.current && termRef.current.focus()
    return true
  }, [write, showToast])

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
    termRef.current && termRef.current.focus()
  }
  const toggleCtrl = () => { ctrl.current = !ctrl.current; setCtrlOn(ctrl.current); haptic(); termRef.current?.focus() }
  const toggleAlt = () => { alt.current = !alt.current; setAltOn(alt.current); haptic(); termRef.current?.focus() }

  const dot = status === 'ready' ? T.ok : status === 'closed' ? T.bad : T.warn

  // accessory bar key spec (default row). Copy/Paste live at the end so they are
  // always reachable on touch (issue #3).
  const ROW = [
    { l: 'Esc' }, { l: 'Tab' }, { l: 'ctrl', on: ctrlOn, fn: toggleCtrl }, { l: 'alt', on: altOn, fn: toggleAlt },
    { l: 'Up', g: '↑' }, { l: 'Down', g: '↓' }, { l: 'Left', g: '←' }, { l: 'Right', g: '→' },
    { l: '|' }, { l: '/' }, { l: '~' }, { l: '-' }, { l: 'Home', g: '⤒' }, { l: 'End', g: '⤓' }, { l: 'Del' },
    // Scrollback page controls (scroll the xterm buffer, NOT PgUp/PgDn to the
    // PTY): a touch-friendly way to move through history a page at a time.
    { l: 'ScrollUp', g: '⇞', fn: () => scrollPage(-1) }, { l: 'ScrollDn', g: '⇟', fn: () => scrollPage(1) },
    // No-reload recovery: repaint + reattach if the screen ever freezes after a
    // flaky reconnect, so the user never has to reload the page.
    { l: 'Redraw', g: '⟳', fn: redrawRecover },
    { l: 'Copy', g: 'copy', fn: copySelection }, { l: 'Paste', g: 'paste', fn: pasteClipboard },
  ]

  return (
    <div data-session-id={instanceId} style={{ position: 'absolute', inset: 0, background: T.bg, color: T.text, fontFamily: font, display: 'flex', flexDirection: 'column' }}>
      {/* header */}
      <div style={{ height: 40, flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 10, padding: '0 14px', borderBottom: `1px solid ${T.line}` }}>
        <span style={{ width: 8, height: 8, borderRadius: 8, background: dot, boxShadow: `0 0 8px ${dot}` }} />
        <span style={{ fontSize: 13 }}>{peerName || 'shell'}</span>
        <span style={{ fontSize: 10.5, color: accent, border: `1px solid ${accent}55`, padding: '2px 6px', background: accent + '14' }}>
          {route || 'direct'}{status === 'connecting' ? ' · connecting…' : ''}
        </span>
        <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 14, color: T.dim, fontSize: 13 }}>
          {/* Background: hide the overlay WITHOUT tearing down the PTY (the
              instance stays mounted, reachable from the SESSIONS strip). */}
          {onBackground && (
            <span title="background (keep running)" onClick={onBackground}
              style={{ cursor: 'pointer', fontSize: 12, letterSpacing: '.04em' }}>hide</span>
          )}
          <span title="close (end session)" onClick={endSession} style={{ cursor: 'pointer', fontSize: 15 }}>✕</span>
        </span>
      </div>
      {/* terminal (position:relative anchors the scroll-to-bottom affordance) */}
      <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        {/* Let the xterm viewport own vertical panning; our touch handler does the
            actual scroll, this just stops the browser from rubber-banding the page
            or zooming on a swipe over the terminal. */}
        <style>{`[data-testid="term-host"] .xterm-viewport{touch-action:pan-y}`}</style>
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
            <button key={i} data-key={k.l} onClick={k.fn || (() => sendKey(k.l))} style={{
              flex: '0 0 auto', minWidth: 38, padding: '9px 11px', fontFamily: font, fontSize: 12,
              cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all .1s',
              border: `1px solid ${active ? accent : T.lineSoft}`, color: active ? T.onAccent : T.sub,
              background: active ? accent : 'transparent',
            }}>{k.g || k.l}</button>
          )
        })}
      </div>
    </div>
  )
}
