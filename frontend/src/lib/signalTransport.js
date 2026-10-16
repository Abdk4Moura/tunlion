// What the signaling socket should try next when it is still down.
//
// WebSocket first is the fast path (one handshake, no long-poll). A websocket
// that never completes burns the engine.io timeout before polling is tried,
// and each reconnect starts that list over. Against a tunnel that sometimes
// holds the upgrade, the page stays "offline, reconnecting" for the whole
// timeout, twice. Polling to the same API answers immediately. After one
// failed attempt, or a few seconds still down, lead with polling. Websocket
// stays in the list so a later upgrade can still take it.

export const SOCKET_TIMEOUT_MS = 4000
export const POLL_AFTER_MS = 4000

export function transportsAfterFailure(current, { attempts = 0, downMs = 0 } = {}) {
  const cur = current && current.length ? current.slice() : ['websocket', 'polling']
  if (cur[0] === 'polling') return cur
  if (attempts >= 1 || downMs >= POLL_AFTER_MS) return ['polling', 'websocket']
  return cur
}
