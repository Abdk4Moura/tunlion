//! Warm `send`: carry a one-shot file transfer over a link the daemon ALREADY
//! holds to the target device.
//!
//! A `tunlion send --to <device>` used to build its own link to the target
//! every time, even when the local `up` daemon held a live, identity-proven
//! direct QUIC link to it. On a slow, lossy path that own build is the weak
//! step: its direct dial can miss its budget and fall back to a WebRTC data
//! channel that moves a few hundred bytes a second, while the daemon's link,
//! built earlier, carries traffic fine (chaos finding 83e2d5588e, PR #752).
//!
//! WHAT IS REUSED: the daemon's transport to the peer. The CLI keeps the whole
//! send protocol (offers, resume, delivery-ack, every message and exit code);
//! this module turns the control socket into a pipe for exactly the transport
//! calls that protocol makes: control frames and data frames out, `flush` with
//! an answer, and the peer's answers to THIS send's offers back in. The peer
//! sees the same `file-offer` a cold sender sends, from the same device, so it
//! runs the same admission at offer time. Nothing here grants anything.
//!
//! WHAT IS NOT REUSED: the transport's lifecycle. The CLI never finishes or
//! closes the shared link; `drain_finish` becomes a flush. When the link dies
//! the session ends with a `warm-error`, and the CLI falls back to building its
//! own link and re-offers with resume, exactly as it does when its own link
//! dies. A session that ends with transfers unfinished on a link that is still
//! up tells the peer to park them (`file-park`), so the resume on the CLI's own
//! link is not refused as a duplicate of a stream that will never move again.
//!
//! ROUTING: the receiver answers on the daemon's link, so the daemon's receive
//! loop hands every answer that names one of this send's transfer ids
//! (`file-accept`, `file-decline`, `file-pending`, `delivery-ack`) to the
//! session ([`route_answer`]) and does not act on it itself. Link-wide frames a
//! sender reads (`state`, `link-revoked`, `brb`, `back`) are copied to every
//! session on that link ([`copy_link_frame`]) and still handled by the daemon.
//!
//! SIDS: two sends on one link must not share a file stream id (the receiver
//! keys streams by link and sid), so the daemon hands each session its own
//! range from the low (file) half of the sid space.
//!
//! PLATFORM: the session handler needs the Unix control socket. The routing
//! table is platform-neutral (it is empty where no session can start).

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use tokio::sync::mpsc;

/// Client -> daemon: one control frame (JSON) for the peer.
pub const WS_CONTROL: u8 = 0x21;
/// Client -> daemon: one data frame, `u32 BE sid | u64 BE offset | payload`.
pub const WS_DATA: u8 = 0x22;
/// Client -> daemon: flush the link; payload is a `u64 BE` token to answer.
pub const WS_FLUSH: u8 = 0x23;
/// Daemon -> client: one control frame (JSON) the peer sent this send.
pub const WS_INBOUND: u8 = 0x31;
/// Daemon -> client: a flush finished; `u64 BE token | u8 ok`.
pub const WS_FLUSHED: u8 = 0x32;
/// Daemon -> client: the link's health, JSON, about once a second.
pub const WS_HEALTH: u8 = 0x33;
/// Daemon -> client: the session ended; JSON `{"type":"warm-error","err":..}`.
pub const WS_CLOSE: u8 = 0x34;

/// The answers a receiver sends about ONE transfer. Each carries its `id`.
const ANSWERS: [&str; 4] = ["file-accept", "file-decline", "file-pending", "delivery-ack"];
/// The answers after which nothing more is owed for that transfer.
const SETTLING: [&str; 2] = ["file-decline", "delivery-ack"];
/// Link-wide frames a sender reads. Copied, never consumed.
const LINK_FRAMES: [&str; 4] = ["state", "link-revoked", "brb", "back"];

/// The first sid a warm send may use, and the bound of the range. The low half
/// of the sid space is file streams (`l2::is_l2_sid` is the high bit); a cold
/// sender numbers its files from 1, and `limits::VERIFY_PROBE_SID` sits at the
/// very top of the low half, so warm ranges live well clear of both.
const SID_FIRST: u32 = 0x4000_0000;
const SID_LIMIT: u32 = 0x7000_0000;

/// Hand out `n` consecutive file sids no other warm session on this daemon is
/// using. Wraps far below the limit; a wrap can only meet a range of a session
/// that ended long ago.
pub fn alloc_sids(n: u32) -> u32 {
    static NEXT: Mutex<u32> = Mutex::new(SID_FIRST);
    let mut next = NEXT.lock().unwrap_or_else(|e| e.into_inner());
    let n = n.max(1);
    if next.saturating_add(n) >= SID_LIMIT {
        *next = SID_FIRST;
    }
    let base = *next;
    *next = base + n;
    base
}

struct Session {
    pid: String,
    ids: HashSet<String>,
    settled: HashSet<String>,
    tx: mpsc::UnboundedSender<Value>,
}

fn sessions() -> &'static Mutex<HashMap<u64, Session>> {
    static S: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One registered session. Dropping it removes the route, so a session that
/// ends any way at all stops receiving answers.
pub struct Route {
    key: u64,
}

impl Route {
    /// The transfers of this session nothing more is owed for.
    pub fn unsettled(&self) -> Vec<String> {
        let map = sessions().lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&self.key) {
            Some(s) => s.ids.difference(&s.settled).cloned().collect(),
            None => Vec::new(),
        }
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        sessions()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

/// Register a session's transfer ids on link `pid`. Answers for those ids on
/// that link go to `tx` from now on.
pub fn register(pid: &str, ids: &[String], tx: mpsc::UnboundedSender<Value>) -> Route {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let key = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    sessions().lock().unwrap_or_else(|e| e.into_inner()).insert(
        key,
        Session {
            pid: pid.to_string(),
            ids: ids.iter().cloned().collect(),
            settled: HashSet::new(),
            tx,
        },
    );
    Route { key }
}

/// The daemon's receive loop calls this for every control frame. Returns true
/// when the frame is an answer to a warm send's offer on that link: it went to
/// that send, and the loop must not act on it. A frame for no live session is
/// left to the loop (which ignores transfer answers it did not ask for).
pub fn route_answer(pid: &str, v: &Value) -> bool {
    let Some(kind) = v["type"].as_str() else {
        return false;
    };
    if !ANSWERS.contains(&kind) {
        return false;
    }
    let Some(id) = v["id"].as_str() else {
        return false;
    };
    let mut map = sessions().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = map.values_mut().find(|s| s.pid == pid && s.ids.contains(id)) else {
        return false;
    };
    if SETTLING.contains(&kind) {
        s.settled.insert(id.to_string());
    }
    // A closed receiver means the session is ending; the answer is still
    // consumed so the daemon never acts on another sender's transfer.
    let _ = s.tx.send(v.clone());
    true
}

/// Copy a link-wide frame a sender reads to every warm send on that link. The
/// daemon still handles it itself.
pub fn copy_link_frame(pid: &str, v: &Value) {
    let Some(kind) = v["type"].as_str() else {
        return;
    };
    if !LINK_FRAMES.contains(&kind) {
        return;
    }
    let map = sessions().lock().unwrap_or_else(|e| e.into_inner());
    for s in map.values().filter(|s| s.pid == pid) {
        let _ = s.tx.send(v.clone());
    }
}

/// Tell the receiver this sender stopped streaming `id` on this link and will
/// resume it elsewhere: keep the partial, release the stream.
pub fn park_msg(id: &str) -> Value {
    serde_json::json!({ "type": "file-park", "id": id })
}

/// Encode a data frame payload: `u32 BE sid | u64 BE offset | bytes`.
pub fn encode_data(sid: u32, offset: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + payload.len());
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(&offset.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Decode a data frame payload. `None` for one too short to hold the header.
pub fn decode_data(b: &[u8]) -> Option<(u32, u64, &[u8])> {
    if b.len() < 12 {
        return None;
    }
    let sid = u32::from_be_bytes(b[0..4].try_into().ok()?);
    let off = u64::from_be_bytes(b[4..12].try_into().ok()?);
    Some((sid, off, &b[12..]))
}

/// The control frames a warm-send client may put on the daemon's link: the
/// sender's own vocabulary, naming one of its own transfers and sids. Anything
/// else is dropped, so the pipe can carry a send and nothing more.
pub fn client_control_allowed(v: &Value, ids: &[String], base: u32, n: u32) -> bool {
    let own_id = || v["id"].as_str().is_some_and(|id| ids.iter().any(|i| i == id));
    let own_sid = || {
        v["sid"]
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .is_some_and(|s| in_range(s, base, n))
    };
    match v["type"].as_str() {
        Some("file-offer" | "file-end" | "file-cancel") => own_id() && own_sid(),
        // The send loop's bounded liveness probe on a stalled transfer.
        Some("ping") => true,
        _ => false,
    }
}

/// Is `sid` one of the `n` sids starting at `base`?
pub fn in_range(sid: u32, base: u32, n: u32) -> bool {
    sid >= base && sid - base < n.max(1)
}

#[cfg(unix)]
pub use imp::handle_warm_send;

#[cfg(unix)]
mod imp {
    use super::*;
    use crate::conn::{warm_link_for, Conn};
    use crate::control;
    use crate::exec_frame::{read_frame, write_frame};
    use filament_transport::net::Transport;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::BufWriter;

    /// How often the session reports the link's health to the client.
    const HEALTH_EVERY: Duration = Duration::from_secs(1);
    /// The longest a session waits to tell the peer to park its streams.
    const PARK_BUDGET: Duration = Duration::from_secs(3);

    /// The bound on the preflight ping. Generous on purpose: a miss sends the
    /// client to build its own link, which on the slow, lossy path this exists
    /// for costs tens of seconds and often fails, while a live link there may
    /// need a retransmission or two (and quinn's RTT estimate can still be the
    /// one from before the path degraded). At least `PREFLIGHT_MIN`, four
    /// round trips on a slower link, never more than `PREFLIGHT_MAX`. Only a
    /// link that is truly gone pays it, once.
    fn preflight_window(t: &Arc<dyn Transport>) -> Duration {
        let base = crate::daemon_ctl::liveness_window().max(PREFLIGHT_MIN);
        let rtt = t.rtt_ms().map(|ms| Duration::from_millis(ms.saturating_mul(4)));
        rtt.map_or(base, |r| base.max(r)).min(PREFLIGHT_MAX)
    }
    const PREFLIGHT_MIN: Duration = Duration::from_secs(5);
    const PREFLIGHT_MAX: Duration = Duration::from_secs(8);

    /// Handle one `send-link` control request. Resolves the warm link inline
    /// (cheap) and spawns the session, so nothing here blocks the receive loop.
    pub async fn handle_warm_send(
        conn: &Conn,
        probes: &crate::daemon_ctl::LivenessProbes,
        req: control::Req,
    ) {
        let control::ReqKind::SendLink { peer, ids } = req.kind.clone() else {
            return;
        };
        let Some((pid, t)) = warm_link_for(conn, &peer) else {
            crate::daemon_ctl::log_warm_miss(conn, &peer);
            req.reject("no warm path: no live link to that peer").await;
            return;
        };
        let Some(link) = conn.link(&pid) else {
            req.reject("no warm path: no live link to that peer").await;
            return;
        };
        // Direct QUIC only: a relayed or data-channel link is the slow path
        // this exists to avoid, and the CLI's own build may do better.
        if !link.direct || t.is_dead() || !t.is_alive() {
            req.reject("no warm path: the held link is not a live direct link")
                .await;
            return;
        }
        let route = link.direct_route;
        let log = conn.log.clone();
        let probes = probes.clone();
        conn.log.debug(&format!(
            "warm-send: riding the daemon's link to '{peer}' (pid={pid})"
        ));
        tokio::spawn(async move {
            // PREFLIGHT: a held link can be up at the QUIC layer and still
            // black-hole frames. Nothing has been offered yet, so a miss is a
            // clean "no warm path"; the link itself is left to its own
            // keepalive (a slow answer is not proof it is dead).
            let window = preflight_window(&t);
            let answered = link_answers(&t, &probes, &peer, &pid, window).await;
            if !answered {
                log.debug(&format!(
                    "warm-send: link to '{peer}' did not answer a preflight ping in {}ms; cold fallback",
                    window.as_millis()
                ));
                req.reject("no warm path: the held link did not answer a preflight ping")
                    .await;
                return;
            }
            run(t, pid, peer, ids, route, log, req).await;
        });
    }

    /// Datagrams this end has received on the link's QUIC connection, when it
    /// has one. Any increase is the peer's QUIC stack answering.
    fn rx_datagrams(t: &Arc<dyn Transport>) -> Option<u64> {
        t.quic_connection().map(|c| c.stats().udp_rx.datagrams)
    }

    /// Does the peer answer on this link within `window`? Its daemon's pong
    /// says so, and so does any datagram its QUIC stack sends back (the ack of
    /// the ping, a keepalive): those are answered below the application, so a
    /// ping queued behind a large frame on a slow link still counts as heard.
    /// A peer whose process is gone sends neither.
    async fn link_answers(
        t: &Arc<dyn Transport>,
        probes: &crate::daemon_ctl::LivenessProbes,
        peer: &str,
        pid: &str,
        window: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + window;
        let rx0 = rx_datagrams(t);
        let mut probe = probes.register(peer, pid);
        let ping = crate::daemon_ctl::liveness_ping(probe.nonce());
        let sent = tokio::time::timeout_at(deadline, t.send_control(&ping)).await;
        if matches!(sent, Ok(Err(_))) {
            return false;
        }
        let heard = || match (rx0, rx_datagrams(t)) {
            (Some(a), Some(b)) => b > a,
            _ => false,
        };
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let answered = {
            let pong = probe.answered();
            tokio::pin!(pong);
            loop {
                tokio::select! {
                    ok = &mut pong => break ok,
                    _ = tick.tick() => {
                        if heard() {
                            break true;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            break false;
                        }
                    }
                }
            }
        };
        drop(probe);
        answered
    }

    /// The largest data frame the session puts on the link. On a link with a
    /// real round trip, a client chunk is split into frames a receiver sees
    /// arrive steadily: it judges a transfer stalled by the time between whole
    /// frames, and the daemon's own control frames wait behind whichever frame
    /// is being written. A local link takes the client's chunk as it is.
    fn data_piece(t: &Arc<dyn Transport>) -> usize {
        match t.rtt_ms() {
            Some(ms) if ms > 20 => SLOW_LINK_PIECE.min(t.max_payload()),
            _ => t.max_payload(),
        }
        .max(1)
    }
    const SLOW_LINK_PIECE: usize = 64 * 1024;

    enum Out {
        Frame(u8, Vec<u8>),
        Close(Value),
    }

    async fn run(
        t: Arc<dyn Transport>,
        pid: String,
        peer: String,
        ids: Vec<String>,
        route: &'static str,
        log: Arc<dyn crate::host::LogSink>,
        req: control::Req,
    ) {
        // Keeps the receive loop on its fast tick while this send runs: the
        // answers it routes here are handled once per loop turn.
        let _live = crate::l2::mux::WarmExecLive::enter();
        let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Value>();
        let reg = register(&pid, &ids, in_tx);
        let n_sids = ids.len() as u32;
        let base = alloc_sids(n_sids);
        let mut sock = req.sock;
        let mut reply = json!({
            "ok": true,
            "sid_base": base,
            "max_payload": t.max_payload(),
            "route": route,
            "link": pid,
        });
        if let Some(addr) = t.remote_addr() {
            reply["remote"] = json!(addr.to_string());
        }
        control::send_reply(&mut sock, &reply).await;
        let (read_half, write_half) = sock.into_split();

        // One writer owns the write half, so frames never interleave.
        let (out_tx, mut out_rx) = mpsc::channel::<Out>(64);
        let writer = tokio::spawn(async move {
            let mut w = BufWriter::new(write_half);
            while let Some(msg) = out_rx.recv().await {
                let res = match msg {
                    Out::Frame(kind, payload) => write_frame(&mut w, kind, &payload).await,
                    Out::Close(v) => {
                        let _ = write_frame(&mut w, WS_CLOSE, v.to_string().as_bytes()).await;
                        return;
                    }
                };
                if res.is_err() {
                    return;
                }
            }
        });

        // CLIENT -> LINK: one task, in order, so a data frame and the
        // `file-end` after it reach the peer in the order the client sent them.
        let pump = {
            let t = t.clone();
            let out_tx = out_tx.clone();
            let ids = ids.clone();
            tokio::spawn(async move {
                let mut r = tokio::io::BufReader::new(read_half);
                loop {
                    let frame = match read_frame(&mut r).await {
                        Ok(Some(f)) => f,
                        // The client went away (finished, fell back, or died).
                        Ok(None) | Err(_) => return "the client closed",
                    };
                    match frame {
                        (WS_CONTROL, payload) => {
                            let Ok(v) = serde_json::from_slice::<Value>(&payload) else {
                                continue;
                            };
                            // A sender's vocabulary only, about this send's
                            // own transfers: the pipe carries a send, not
                            // arbitrary frames on the daemon's link.
                            if !client_control_allowed(&v, &ids, base, n_sids) {
                                continue;
                            }
                            if t.send_control(&v).await.is_err() {
                                return "the warm link died";
                            }
                        }
                        (WS_DATA, payload) => {
                            let Some((sid, off, bytes)) = decode_data(&payload) else {
                                continue;
                            };
                            // Only file sids: the high half is the L2 streams
                            // the daemon's own mux owns on this link.
                            if crate::l2::is_l2_sid(sid) || !in_range(sid, base, n_sids) {
                                continue;
                            }
                            let piece = data_piece(&t);
                            let mut at = off;
                            for chunk in bytes.chunks(piece) {
                                if t.send_frame(sid, at, chunk).await.is_err() {
                                    return "the warm link died";
                                }
                                at += chunk.len() as u64;
                            }
                        }
                        (WS_FLUSH, payload) => {
                            let ok = t.flush().await.is_ok();
                            let mut ans = payload.get(..8).unwrap_or(&[0; 8]).to_vec();
                            ans.push(u8::from(ok));
                            if out_tx.send(Out::Frame(WS_FLUSHED, ans)).await.is_err() {
                                return "the client closed";
                            }
                            if !ok {
                                return "the warm link died";
                            }
                        }
                        _ => {}
                    }
                }
            })
        };

        let mut health = tokio::time::interval(HEALTH_EVERY);
        let why: String = {
            let mut pump = pump;
            loop {
                tokio::select! {
                    r = &mut pump => {
                        break r.unwrap_or("the warm send session failed").to_string();
                    }
                    Some(v) = in_rx.recv() => {
                        if out_tx.send(Out::Frame(WS_INBOUND, v.to_string().into_bytes())).await.is_err() {
                            pump.abort();
                            break "the client closed".to_string();
                        }
                    }
                    _ = health.tick() => {
                        let dead = t.is_dead() || !t.is_alive();
                        let mut h = json!({ "alive": !dead });
                        if let Some(ms) = t.heard_ms() {
                            h["heard_ms"] = json!(ms);
                        }
                        if let Some(ms) = t.keepalive_silence_ms() {
                            h["silence_ms"] = json!(ms);
                        }
                        let _ = out_tx.send(Out::Frame(WS_HEALTH, h.to_string().into_bytes())).await;
                        if dead {
                            pump.abort();
                            break "the warm link died".to_string();
                        }
                    }
                }
            }
        };
        // Answers already routed to this session are passed on before the
        // close, so a `delivery-ack` that arrived with the link's last breath
        // is not lost.
        while let Ok(v) = in_rx.try_recv() {
            let _ = out_tx
                .send(Out::Frame(WS_INBOUND, v.to_string().into_bytes()))
                .await;
        }
        let _ = out_tx
            .send(Out::Close(json!({ "type": "warm-error", "err": why })))
            .await;
        drop(out_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
        // Whatever is still owed was abandoned on this link. On a link that is
        // still up, the receiver would otherwise hold those streams open and
        // refuse the resume from the client's own link as a duplicate.
        let unsettled = reg.unsettled();
        drop(reg);
        if !unsettled.is_empty() && !t.is_dead() && t.is_alive() {
            let _ = tokio::time::timeout(PARK_BUDGET, async {
                for id in &unsettled {
                    if t.send_control(&park_msg(id)).await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
        log.debug(&format!(
            "warm-send to '{peer}' ended ({why}); {} transfer(s) left for the client to finish",
            unsettled.len()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn answers_route_only_to_the_session_that_offered_them_on_that_link() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let route = register("link-a", &["s-1-1".to_string()], tx);
        let accept = json!({ "type": "file-accept", "id": "s-1-1", "offset": 0 });
        // Another link, or another transfer id: left to the daemon.
        assert!(!route_answer("link-b", &accept));
        assert!(!route_answer(
            "link-a",
            &json!({ "type": "file-accept", "id": "s-9-1", "offset": 0 })
        ));
        assert!(rx.try_recv().is_err());
        // Its own answer on its own link: consumed and delivered.
        assert!(route_answer("link-a", &accept));
        assert_eq!(rx.try_recv().unwrap(), accept);
        // A non-answer is never consumed, even with a matching id.
        assert!(!route_answer("link-a", &json!({ "type": "file-end", "id": "s-1-1" })));
        drop(route);
        // A finished session routes nothing.
        assert!(!route_answer("link-a", &accept));
    }

    #[test]
    fn a_settled_transfer_is_not_parked_and_an_open_one_is() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let ids = vec!["s-2-1".to_string(), "s-2-2".to_string(), "s-2-3".to_string()];
        let route = register("link-c", &ids, tx);
        assert!(route_answer("link-c", &json!({ "type": "delivery-ack", "id": "s-2-1" })));
        assert!(route_answer("link-c", &json!({ "type": "file-decline", "id": "s-2-2" })));
        // An accept alone settles nothing: the bytes are still owed.
        assert!(route_answer("link-c", &json!({ "type": "file-accept", "id": "s-2-3" })));
        assert_eq!(route.unsettled(), vec!["s-2-3".to_string()]);
    }

    #[test]
    fn link_frames_are_copied_to_every_session_on_the_link_and_never_consumed() {
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let (tx3, mut rx3) = mpsc::unbounded_channel();
        let _a = register("link-d", &["s-3-1".to_string()], tx1);
        let _b = register("link-d", &["s-4-1".to_string()], tx2);
        let _c = register("link-e", &["s-5-1".to_string()], tx3);
        let revoked = json!({ "type": "link-revoked", "reason": "x" });
        copy_link_frame("link-d", &revoked);
        assert_eq!(rx1.try_recv().unwrap(), revoked);
        assert_eq!(rx2.try_recv().unwrap(), revoked);
        assert!(rx3.try_recv().is_err());
        // Not a link-wide frame: nothing copied.
        copy_link_frame("link-d", &json!({ "type": "ping" }));
        assert!(rx1.try_recv().is_err());
    }

    #[test]
    fn sid_ranges_never_overlap_and_stay_in_the_file_half() {
        let a = alloc_sids(3);
        let b = alloc_sids(1);
        assert!(b >= a + 3 || b == SID_FIRST, "{a:#x} {b:#x}");
        for s in [a, a + 2, b] {
            assert!(!crate::l2::is_l2_sid(s));
            assert!(s >= SID_FIRST && s < SID_LIMIT);
        }
    }

    #[test]
    fn the_client_may_only_speak_about_its_own_transfers() {
        let ids = vec!["s-7-1".to_string(), "s-7-2".to_string()];
        let base = 0x4000_0100;
        let offer = |id: &str, sid: u32| json!({ "type": "file-offer", "id": id, "sid": sid });
        assert!(client_control_allowed(&offer("s-7-1", base), &ids, base, 2));
        assert!(client_control_allowed(&json!({ "type": "file-end", "id": "s-7-2", "sid": base + 1 }), &ids, base, 2));
        assert!(client_control_allowed(&json!({ "type": "ping", "v": 1 }), &ids, base, 2));
        // Another send's transfer, or a sid outside this session's range.
        assert!(!client_control_allowed(&offer("s-8-1", base), &ids, base, 2));
        assert!(!client_control_allowed(&offer("s-7-1", base + 2), &ids, base, 2));
        assert!(!client_control_allowed(&offer("s-7-1", 1), &ids, base, 2));
        // Anything that is not a sender's own vocabulary.
        for kind in ["pair-proof", "link-revoked", "l2-open", "exec-open", "state", "pair-keep"] {
            assert!(!client_control_allowed(&json!({ "type": kind, "id": "s-7-1", "sid": base }), &ids, base, 2), "{kind}");
        }
    }

    #[test]
    fn data_frames_round_trip() {
        let enc = encode_data(0x4000_0001, 1 << 40, b"\x00\xffbytes");
        assert_eq!(decode_data(&enc), Some((0x4000_0001, 1 << 40, &b"\x00\xffbytes"[..])));
        assert_eq!(decode_data(&enc[..11]), None);
    }
}
