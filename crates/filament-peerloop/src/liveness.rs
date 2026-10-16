//! Link liveness and route predicates.
//!
//! Pure over booleans the caller has already read off a peer or a transport: this
//! module never touches a `Transport`, a socket or a terminal, so each decision is
//! one expression, unit-testable, and identical at every call site. Before these
//! were named functions the same expressions were retyped per call site, and a
//! transcription error in one of them is exactly how #246's livelock survived.

/// #246: a link is dead only when nothing is serving AND its WebRTC peer is
/// not still making progress. `peer_live` is `Peer::is_live` (anything but
/// Failed/Closed); `transport_dead` and `workers_all_dead` describe the direct
/// transports. A WebRTC link that just finished `establish` is
/// (peer_live=true, transport dead, workers empty) and therefore alive: it has
/// no transport or workers YET, but its ICE agent is working. Named as a
/// function so the decision is one expression, unit-testable, and stable
/// across call sites.
pub fn link_dead_for(peer_live: bool, transport_dead: bool, workers_all_dead: bool) -> bool {
    !peer_live && transport_dead && workers_all_dead
}

/// #246: a link counts as live when any transport serves, any worker serves,
/// or the WebRTC peer is still making progress. The peer clause is what lets a
/// Normal re-dial yield to an establish that is still underway instead of
/// arming a fresh direct attempt (whose fallback timer would then tear the
/// establish down).
pub fn link_has_live_for(peer_live: bool, primary_ok: bool, workers_ok: bool) -> bool {
    peer_live || primary_ok || workers_ok
}

/// Whether an establish may proceed on STUN alone when the config API is slow.
/// Not under a forced relay, which needs the TURN credentials only the API has.
pub fn ice_fallback_allowed(relay_only: bool) -> bool {
    !relay_only
}

/// `--relay` promises to hide this machine's address from the peer. Direct
/// transport cannot keep that promise: its `transport-offer` carries our host
/// and public candidates, and dialing the peer's candidates hands it our source
/// address. So a relay-mode session never takes direct, whatever else asked for
/// it (env gate, L2 acceptor, daemon anti-glare). Decided here once, at Conn
/// construction, and `direct_ok` is never widened afterwards, so send, receive,
/// pair and the `up` daemon all inherit it. Runtime escalation to relay
/// (`relay_only` set later) is a different thing and is not this flag.
pub fn direct_permitted(relay_only: bool, direct_ok: bool) -> bool {
    direct_ok && !relay_only
}
