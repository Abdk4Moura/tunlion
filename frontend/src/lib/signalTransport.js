// What the signaling socket should try next when it is still down.
//
// WebSocket first is the fast path (one handshake, no long-poll). A websocket
// that never completes burns the engine.io timeout before polling is tried,
// and each reconnect starts that list over. Against a tunnel that sometimes
// holds the upgrade, the page stays "offline, reconnecting" for the whole
// timeout, twice. Polling to the same API answers immediately. After one
// failed attempt, or a few seconds still down, lead with polling. Websocket
// stays in the list so a later upgrade can still take it.
//
// "A few seconds" used to be the only bound: a held websocket cost every page
// load about 5 s before it could see a single peer (measured: 4.9 to 6.7 s to
// the first peer tile, against 0.6 to 0.9 s when the websocket opens). The
// hedge below bounds the websocket attempt by what this network has already
// shown it needs, not by a fixed constant.

export const SOCKET_TIMEOUT_MS = 4000
export const POLL_AFTER_MS = 4000

// Hedge bounds. A websocket open is a fresh TCP + TLS + HTTP upgrade, about
// three round trips; past that plus a margin it is held, not slow. The floor
// keeps a jittery fast network from hedging on noise; the ceiling is the old
// fixed bound, so the hedge can only make the fallback earlier, never later.
export const HEDGE_RTTS = 3
export const HEDGE_MARGIN_MS = 300
export const HEDGE_MIN_MS = 800
export const HEDGE_UNKNOWN_MS = 1500

export function hedgeDelayMs(rttMs) {
  if (!(rttMs > 0) || !Number.isFinite(rttMs)) return HEDGE_UNKNOWN_MS
  const ms = Math.round(HEDGE_RTTS * rttMs + HEDGE_MARGIN_MS)
  return Math.min(POLL_AFTER_MS, Math.max(HEDGE_MIN_MS, ms))
}

// The fastest completed request this page made to the API: the page fetches
// /api/config and /api/room just before it opens the socket, so this is a
// measured round trip to the same origin (duration also covers a cold
// connection's setup, which only makes the estimate, and the hedge, larger).
export function apiRttFromEntries(entries, apiBase) {
  let best = Infinity
  for (const e of entries || []) {
    const name = String(e && e.name || '')
    if (!name.includes('/api/')) continue
    if (apiBase && !name.startsWith(apiBase)) continue
    const d = Number(e.duration)
    if (d > 0 && d < best) best = d
  }
  return Number.isFinite(best) ? best : null
}

export function transportsAfterFailure(current, { attempts = 0, downMs = 0, pollAfterMs = POLL_AFTER_MS } = {}) {
  const cur = current && current.length ? current.slice() : ['websocket', 'polling']
  if (cur[0] === 'polling') return cur
  if (attempts >= 1 || downMs >= pollAfterMs) return ['polling', 'websocket']
  return cur
}
