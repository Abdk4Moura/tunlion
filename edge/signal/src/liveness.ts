// Liveness predicates, pure so the authority rules are testable without
// workerd.
//
// The hub has two transports and one rule: a session is live only while its
// transport is actually open and its socket.io namespace is connected. The
// stored `last_seen` in SQLite is a refresh hint, not the authority: after a
// hibernation or eviction it can be an hour stale while the websocket is
// still open. Polling is memory-only, so its freshness deadline is the
// engine.io dead window (ping interval plus timeout); a namespace flag left
// behind by a frozen page is not enough.

/** A websocket is live only while OPEN, accepted, past the upgrade probe and
 *  connected to the default namespace. `attached` is false when the runtime
 *  restored a socket without its attachment. */
export function wsAlive(open: boolean, attached: boolean, probing: boolean, ns: boolean): boolean {
  return open && attached && !probing && ns;
}

/** Polling has no transport object to ask: the last request is the only
 *  freshness signal, and it must be inside the engine.io dead window. */
export function pollAlive(ns: boolean, lastSeen: number, now: number, deadAfterMs: number): boolean {
  return ns && Number.isFinite(lastSeen) && now - lastSeen <= deadAfterMs;
}

/** The registry's capacity rule: a token record is live only while its sid is
 *  a live transport and the record itself is unexpired. */
export function sessionAlive(
  sid: string | null,
  exp: number,
  now: number,
  alive: (sid: string) => boolean,
): boolean {
  return !!sid && exp > now && alive(sid);
}
