//! L2 WIRE + MUX: the stream-id vocabulary and the multiplexer that routes
//! inbound control and data frames to per-stream pipes.
//!
//! This is the host-free core of `cli/src/l2.rs`: it decides what a stream id
//! means, allocates them, registers pipes, enforces the per-link cap and the
//! localhost-only acceptor rule, and pumps bytes between the transport and a
//! local socket. It owns no terminal, reads no settings, and does not build or
//! close links.
//!
//! The two host edges go through `host::HostServices`, never through the CLI:
//!   * `connect_local_stream` is the acceptor's dial. A peer asks for a local
//!     target; only the host can open a socket here, and its inert default
//!     REFUSES. The loopback check and the operator allowlist stay in
//!     `accept_control` and its caller, respectively.
//!   * `live_session_cut` is the mid-session revocation/expiry re-check a
//!     served stream runs. The host names the cut and its exact reason; an inert
//!     host has no opinion, and an unidentified peer (`idev == None`) is never
//!     cut here.
//!
//! Everything else is pure policy over the `Transport` trait. Nothing in this
//! file calls back into the CLI.

use anyhow::Result;
use bytes::Bytes;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::host::{HostServices, LiveCutCause};
use filament_transport::hooks;
use filament_transport::net::Transport;

/// L2 stream ids live in the HIGH half of the u32 sid space (`sid | 0x8000_0000`)
/// so they can NEVER collide with file-transfer sids (which start at 0 and count
/// up). A single link can therefore carry file transfers (low sids) and L2
/// streams (high sids) at once; the read loop in net.rs hands both to `Ev::Chunk`
/// and the dispatcher splits on this bit.
pub const L2_SID_BASE: u32 = 0x8000_0000;

/// Is this a high-half (L2) stream id? The hot-path discriminator the recv loop
/// uses to route an `Ev::Chunk` to the mux vs. the file-transfer logic.
#[inline]
pub fn is_l2_sid(sid: u32) -> bool {
    sid & L2_SID_BASE != 0
}

/// The honest refusal sent for an inbound `l2-open` when this build has no
/// inbound forward server compiled (`forward-server` off). It is a named
/// protocol refusal, not a silent accept or a bare drop.
pub const FORWARD_SERVER_UNAVAILABLE: &str = "forward server is not available in this build";

/// Parse a stream id from an inbound control message's `sid` field, REFUSING a
/// value that does not fit in u32 instead of silently truncating it. A bare
/// `as_u64().unwrap_or(0) as u32` cast both defaults a MISSING sid to 0 and
/// WRAPS an oversized one (e.g. `0x1_8000_0000 as u32 == 0x8000_0000`), which
/// would let a peer forge a value that passes `is_l2_sid` yet aliases a live
/// sid. Returns `None` for a missing field OR an out-of-range value; every
/// caller must deny/ignore the open in that case, never default to 0.
pub fn wire_sid(v: &Value) -> Option<u32> {
    u32::try_from(v["sid"].as_u64()?).ok()
}

/// Per-stream pipe item: `Some(bytes)` = data; `None` = clean half-close/EOF
/// (an empty 4-byte data frame). A RST/abort is signalled out-of-band by
/// dropping the whole stream entry (writer wakes on a closed channel), distinct
/// from `None` so a reset is never mistaken for an orderly EOF.
pub type PipeItem = Option<Bytes>;
type StreamTx = mpsc::Sender<PipeItem>;

/// Liveness handle for one stream's two pumps. Holding the read-pump's
/// `AbortHandle` is what makes teardown actually work: `socket_to_dc` parks in
/// `rd.read()` and will NOT wake just because we drop its peer channel, so on
/// data-channel death / l2-close we must abort it explicitly (design §3.5).
struct StreamHandle {
    tx: StreamTx,
    read_pump: Option<AbortHandle>,
    /// Monotonic identity for THIS registration. A sid can be reused after its
    /// stream is torn down; a detached session's late cleanup must only free
    /// the stream it actually owned, never a newer generation that reused the
    /// same sid.
    generation: u64,
}

/// H-1 (DoS): per-link cap on concurrently live streams (file + L2 + PTY share
/// the `streams` table). Beyond this an `l2-open`/`pty-open` is refused. A
/// generous bound, interactive use needs only a handful, that still stops a
/// flaky/hostile paired device from spawning unbounded threads/sockets.
pub const MAX_STREAMS_PER_LINK: usize = 8;

/// What the acceptor answered to an initiator's open (mount-open / pty-open).
/// One channel per stream id, shared by every verb, so a new open kind inherits
/// the denial path instead of silently starting without one (the lesson of the
/// mount-only `mount_ack_tx`, which left pty with no way to learn why it was
/// refused).
pub enum OpenOutcome {
    /// The acceptor acked the open. The carried control JSON is the verb's ack
    /// payload (mount-open-ack carries `caps`; pty-open-ack carries nothing).
    Opened(serde_json::Value),
    /// The acceptor closed the stream with an explicit reason (a real refusal).
    Refused(String),
    /// The stream closed with no ack and no reason: we never established that
    /// the peer opened anything.
    ClosedWithoutAck,
}

/// The multiplexer: routes inbound control/data frames to per-stream pipes and
/// owns stream-id allocation. Transport-agnostic, it rides above the trait.
pub struct Mux {
    transport: Arc<dyn Transport>,
    /// The host this mux asks for its two edges: the acceptor's local dial and
    /// the live-session cut. Owned by this instance and supplied by its caller.
    host: Arc<dyn HostServices>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
    next_sid: AtomicU32,
    /// Identity source for [`StreamHandle::generation`]. Never reset.
    next_generation: std::sync::atomic::AtomicU64,
    /// Acceptor only: sids we have seen `l2-open` for and accepted, so a late
    /// duplicate open is ignored. (Initiator allocates, so it can't double-open.)
    accepted: Mutex<HashMap<u32, ()>>,
    /// web-shell: per-sid PTY resize senders. H-1: owning these HERE (rather than
    /// in the main event loop) guarantees they are dropped on EVERY teardown path:
    /// inbound `l2-close` (`on_close`), the session task exit (`drop_pty`), and
    /// link/mux death (`shutdown_all`), closing the resizer-map leak.
    resizers: Mutex<HashMap<u32, mpsc::UnboundedSender<(u16, u16)>>>,
    /// per-sid oneshot senders delivering the acceptor's answer to an open back
    /// to the caller that issued it (mount-open via `open_mount_stream`, pty-open
    /// via `pty_attach_once`). pump_initiator receives the ack control message
    /// (mount-open-ack / pty-open-ack), resolves the sid, and sends `Opened`;
    /// an inbound l2-close (`on_close`) sends `Refused`/`ClosedWithoutAck`. The
    /// caller awaits the receiver. Shared across verbs and keyed by stream id, so
    /// a denial carries a reason for every open kind instead of just mount.
    open_ack_tx: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<OpenOutcome>>>,
    /// A reason an inbound `l2-close` carried for a stream whose open waiter was
    /// already consumed (i.e. a mid-session close). A revoked peer loses a live
    /// shell/stream this way; the reason must reach the caller as a denial, not
    /// be swallowed into a clean close. Entries for streams that never read them
    /// linger only until link death (`shutdown_all`), bounded and harmless.
    close_err: Mutex<HashMap<u32, String>>,
    /// Acceptor only: per-sid control channel into a served exec session
    /// (`exec-alive` heartbeats, `exec-signal` from the initiator). Keyed by
    /// the sid on THIS peer's mux, so one peer can never reach another's
    /// session. Bounded: a peer that floods heartbeats loses the extras, never
    /// the daemon's memory. Dropped with the stream on every teardown path.
    exec_ctl: Mutex<HashMap<u32, mpsc::Sender<ExecCtl>>>,
}

impl Mux {
    /// A mux over `t` with an explicitly owned host. When attached to a `Conn`,
    /// pass that connection's host. For inert behavior, explicitly pass
    /// `Arc::new(NoHost)`; there is no process-wide host or implicit fallback.
    ///
    /// ```compile_fail
    /// use filament_peerloop::l2::mux::Mux;
    /// use filament_transport::net::Transport;
    /// use std::sync::Arc;
    /// fn missing_host(transport: Arc<dyn Transport>) {
    ///     let _ = Mux::new(transport);
    /// }
    /// ```
    pub fn new(t: Arc<dyn Transport>, host: Arc<dyn HostServices>) -> Arc<Self> {
        Self::with_host(t, host)
    }

    /// A mux with a host chosen by the caller, for an embedder that carries one
    /// per session. Equivalent to [`Self::new`].
    pub fn with_host(t: Arc<dyn Transport>, host: Arc<dyn HostServices>) -> Arc<Self> {
        Arc::new(Mux {
            transport: t,
            host,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            next_generation: std::sync::atomic::AtomicU64::new(0),
            accepted: Mutex::new(HashMap::new()),
            resizers: Mutex::new(HashMap::new()),
            open_ack_tx: Mutex::new(HashMap::new()),
            close_err: Mutex::new(HashMap::new()),
            exec_ctl: Mutex::new(HashMap::new()),
        })
    }

    pub fn transport(&self) -> Arc<dyn Transport> {
        self.transport.clone()
    }

    pub fn alloc_sid(&self) -> u32 {
        // Mask the counter to the low 30 bits so a long-lived link never escapes
        // into the L2 flag (0x80000000) OR the answerer-role bit (0x40000000).
        // The role bit keeps the two ends' sid spaces DISJOINT: each end allocates
        // with its own bit (opposite the peer's, via the deterministic `polite`
        // role), so a sid this end allocates can never equal one the peer
        // allocated - preventing cross-tunnel frame collisions when both ends open
        // L2 streams on one link (pty + warm-reuse forward, etc.).
        let n = self.next_sid.fetch_add(1, Ordering::Relaxed) & 0x3FFF_FFFF;
        let role = if self.transport.sid_answerer() {
            0x4000_0000
        } else {
            0
        };
        n | L2_SID_BASE | role
    }

    /// Register a stream's inbound pipe and return the receiver the socket-writer
    /// task drains. The read-pump handle is attached later via `set_read_pump`.
    ///
    /// COLLISION-SAFE: the sid is chosen by the PEER, so it can name a sid that
    /// is ALREADY live (its own earlier forward, a pty, a mount, ...). A bare
    /// `insert` would silently DISPLACE the existing `StreamHandle` and drop it;
    /// dropping is NOT closing (the orphaned `read_pump` is dropped WITHOUT
    /// `abort()`, so `socket_to_dc` stays parked in `rd.read()` leaking a
    /// pump+socket, while `streams.len()` stays flat and defeats the H-1 stream
    /// cap, and inbound frames for the sid are redirected to the new stream).
    /// So this REFUSES a sid that is already present and returns `None`; a peer
    /// reusing a live sid is a protocol error and the caller must deny the open.
    /// This is the single structural chokepoint every stream type inherits.
    pub async fn register(&self, sid: u32) -> Option<mpsc::Receiver<PipeItem>> {
        let mut streams = self.streams.lock().await;
        if streams.contains_key(&sid) {
            return None; // sid already live: refuse, do NOT overwrite/drop
        }
        let (tx, rx) = mpsc::channel::<PipeItem>(256);
        let generation = self
            .next_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        streams.insert(
            sid,
            StreamHandle {
                tx,
                read_pump: None,
                generation,
            },
        );
        Some(rx)
    }

    async fn set_read_pump(&self, sid: u32, h: AbortHandle) {
        if let Some(s) = self.streams.lock().await.get_mut(&sid) {
            s.read_pump = Some(h);
        } else {
            // Stream already gone (raced with teardown), kill the orphan pump.
            h.abort();
        }
    }

    /// Register a stream's inbound pipe (public, for the PTY/mount acceptors which
    /// register BEFORE spawning the server, same pre-registration race fix as
    /// l2-open's dial path). Returns `None` if the sid is already live (see
    /// `register`): the caller MUST deny the open and must NOT proceed to set up
    /// the stream, or the collision hole re-opens.
    pub async fn register_stream(&self, sid: u32) -> Option<mpsc::Receiver<PipeItem>> {
        self.register(sid).await
    }

    /// Number of currently live streams on this link (file + L2 + PTY share the
    /// table). H-1: the acceptor checks this against `MAX_STREAMS_PER_LINK`
    /// before accepting a new `l2-open`/`pty-open`.
    pub async fn live_streams(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// The sids currently registered on this link. The warm-verify paths use it
    /// to observe the stream they just opened; no caller may assume the order.
    pub async fn live_sids(&self) -> Vec<u32> {
        self.streams.lock().await.keys().copied().collect()
    }

    /// Number of live PTY resize senders. A resize sender is owned by the mux so
    /// it cannot outlive its stream; this exposes that bookkeeping to the
    /// teardown tests without handing out the map.
    pub async fn live_resizers(&self) -> usize {
        self.resizers.lock().await.len()
    }

    /// Arm the open waiter for `sid` and return the receiver. The caller does
    /// this BEFORE sending the open so an ack or close that races back cannot
    /// land in the gap; `take_open_ack` removes the sender when the ack arrives.
    pub async fn arm_open_ack(&self, sid: u32) -> oneshot::Receiver<OpenOutcome> {
        let (tx, rx) = oneshot::channel();
        self.open_ack_tx.lock().await.insert(sid, tx);
        rx
    }

    /// Take the open waiter for `sid`, if one is still armed, so the caller can
    /// deliver the ack payload to it.
    pub async fn take_open_ack(&self, sid: u32) -> Option<oneshot::Sender<OpenOutcome>> {
        self.open_ack_tx.lock().await.remove(&sid)
    }

    /// True if accepting one more stream would exceed `MAX_STREAMS_PER_LINK`.
    pub async fn at_stream_cap(&self) -> bool {
        self.live_streams().await >= MAX_STREAMS_PER_LINK
    }

    /// Drop a stream and abort its read pump. Idempotent. Also drops any PTY
    /// resize sender for this sid (H-1: no resizer outlives its stream).
    pub async fn drop_stream(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        self.open_ack_tx.lock().await.remove(&sid);
        self.exec_ctl.lock().await.remove(&sid);
        if let Some(s) = self.streams.lock().await.remove(&sid) {
            if let Some(h) = s.read_pump {
                h.abort();
            }
            // Dropping `s.tx` closes the pipe; the writer pump (dc_to_socket)
            // sees `recv()` return None and shuts the socket down.
        }
    }

    /// Is `sid` currently registered on this link? The PTY open path uses this
    /// to refuse a sid owned by a forward/mount/other stream BEFORE it drops
    /// anything for a superseded attachment.
    pub async fn has_stream(&self, sid: u32) -> bool {
        self.streams.lock().await.contains_key(&sid)
    }

    /// The identity of the registration currently holding `sid`, if any. A
    /// cleanup task records this and later calls [`Self::drop_stream_if`] so a
    /// sid reused by a newer attachment is never torn down by an older
    /// generation's exit.
    pub async fn stream_generation(&self, sid: u32) -> Option<u64> {
        self.streams.lock().await.get(&sid).map(|s| s.generation)
    }

    /// Drop `sid` only if it is still the SAME registration as `generation`.
    /// Unlike [`Self::drop_stream`], this is safe to call from a detached
    /// session's asynchronous teardown: a newer stream that reused the sid has
    /// a different generation and is left alone.
    pub async fn drop_stream_if(&self, sid: u32, generation: u64) {
        let removed = {
            let mut streams = self.streams.lock().await;
            match streams.get(&sid) {
                Some(s) if s.generation == generation => streams.remove(&sid),
                _ => None,
            }
        };
        let Some(s) = removed else { return };
        // Same cleanup set as `drop_stream`, but the stream was already removed
        // under the identity check above.
        self.resizers.lock().await.remove(&sid);
        self.open_ack_tx.lock().await.remove(&sid);
        self.exec_ctl.lock().await.remove(&sid);
        if let Some(h) = s.read_pump {
            h.abort();
        }
        // Dropping `s.tx` closes the pipe; the host's input pump exits.
    }

    /// Register a PTY's resize sender (acceptor). Stored in the mux so it is freed
    /// on every teardown path with the stream, see `resizers`.
    pub async fn register_resizer(&self, sid: u32, tx: mpsc::UnboundedSender<(u16, u16)>) {
        self.resizers.lock().await.insert(sid, tx);
    }

    /// Deliver a `pty-resize` to the PTY task for `sid`, if it is still live.
    pub async fn resize_pty(&self, sid: u32, cols: u16, rows: u16) {
        if let Some(tx) = self.resizers.lock().await.get(&sid) {
            let _ = tx.send((cols, rows));
        }
    }

    /// Free a PTY's stream + resize sender on a session task exit (the teardown path
    /// that does NOT come from an inbound `l2-close`). Idempotent.
    pub async fn drop_pty(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        self.streams.lock().await.remove(&sid);
    }

    /// Route an inbound data frame to its stream. Empty payload = clean EOF/FIN.
    /// Never parks: the send is try_send, so a stalled consumer cannot freeze
    /// the daemon recv loop that calls this (bulk stdin vs a non-reading
    /// child filled the 256-slot pipe and wedged every stream behind it).
    /// A full pipe resets the stream LOUDLY -- l2-close with an explicit
    /// reason, entry dropped -- so the initiator fails fast with a reason
    /// instead of hanging on silently lost bytes or wedging the daemon.
    /// Steady consumers never trip it (they drain continuously); only a
    /// genuinely stalled consumer with a full buffer does.
    pub async fn on_frame(&self, sid: u32, payload: Bytes) {
        let tx = match self.streams.lock().await.get(&sid) {
            Some(s) => s.tx.clone(),
            None => {
                // A frame for a sid this mux no longer holds: the session was torn down before
                // it arrived, so a close can be DELIVERED and still unactionable. To the caller
                // whose stream this was that is indistinguishable from never-delivered, and it
                // used to be silent. Behaviour is unchanged (the frame is dropped); what changes
                // is that a future occurrence leaves a trace instead of nothing.
                hooks::debug(&format!(
                    "l2: frame for unknown sid {sid} ({} bytes) dropped",
                    payload.len()
                ));
                return;
            }
        };
        let msg = if payload.is_empty() {
            None
        } else {
            Some(payload)
        };
        match tx.try_send(msg) {
            Ok(()) => {}
            // receiver gone => stream already torn down (same as before).
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                let _ = self
                    .transport
                    .send_control(&json!({
                        "type": "l2-close",
                        "sid": sid,
                        "err": "stream input flooded (consumer stalled)",
                    }))
                    .await;
                self.drop_stream(sid).await;
            }
        }
    }

    /// Deliver a liveness marker for `sid` when the acceptor's `l2-open-ack` lands.
    /// Warm-reuse verification (`verify_first_frame`) needs proof the held link still
    /// delivers BEFORE it commits the client. A server-speaks-first protocol supplies
    /// that proof itself (sshd's banner), but a CLIENT-speaks-first one (HTTP, most DB
    /// clients) sends no app bytes until the client does - so without this the verify
    /// window expired and a HEALTHY link was wrongly dropped as a zombie, making every
    /// `forward` connection fall to a fresh cold link (the "no extra presence" promise
    /// broke). The ack is an empty `Some`: `on_frame` maps real empty payloads to
    /// `None`/EOF, so `Some(empty)` never occurs organically and is an unambiguous
    /// marker; replaying it writes zero bytes to the client.
    pub async fn on_open_ack(&self, sid: u32) {
        let tx = self.streams.lock().await.get(&sid).map(|s| s.tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send(Some(Bytes::new())).await;
        }
    }

    /// Inbound l2-close. `err` set = RST/abort (drop, do NOT deliver clean EOF);
    /// no `err` = the peer is done, also a drop (its data direction already
    /// EOF'd via the empty frame). Either way: abort pumps, close the socket.
    pub async fn on_close(&self, sid: u32, err: Option<&str>) {
        // Deliver any pending open waiter its answer: an l2-close is the peer
        // saying NO (authorization, ceiling, stream cap, acceptor off), and the
        // reason it carries must reach the caller as a denial, not as a mystery
        // timeout. #206: the acceptor sends `l2-close{err: ...}` on a refusal;
        // before this, the reason was dropped here and the initiator read a
        // generic channel-closed. A close WITHOUT an err is a different fact
        // (we never established the peer opened anything) and is delivered as
        // `ClosedWithoutAck` so the caller can say that instead of inventing a
        // cause.
        if let Some(tx) = self.open_ack_tx.lock().await.remove(&sid) {
            let outcome = match err {
                Some(reason) => OpenOutcome::Refused(reason.to_string()),
                None => OpenOutcome::ClosedWithoutAck,
            };
            let _ = tx.send(outcome);
        } else if let Some(reason) = err {
            // Mid-session close: the open waiter is already consumed, so record
            // the reason where the caller (the pty IO loop) can read it. A revoked
            // peer loses a live session this way; the reason must surface as a
            // denial, never a clean exit.
            //
            // Why this needs no buffer: this insert happens BEFORE drop_stream,
            // and dropping the stream is what closes the pipe the consumer awaits,
            // so the write happens-before the close the reader keys on, in program
            // order. Do NOT "simplify" this by re-arming the open_ack_tx one-shot
            // here: a one-shot slot can be empty at the instant on_close fires, and
            // a denial delivered into that gap is silently lost. The always-present
            // map, written before the close, cannot lose it.
            self.close_err.lock().await.insert(sid, reason.to_string());
        }
        self.drop_stream(sid).await;
    }

    /// Acceptor: open the control channel for the exec session on `sid`.
    pub async fn register_exec_ctl(&self, sid: u32) -> mpsc::Receiver<ExecCtl> {
        let (tx, rx) = mpsc::channel(16);
        self.exec_ctl.lock().await.insert(sid, tx);
        rx
    }

    /// Acceptor: deliver an initiator's `exec-alive`/`exec-signal` to the
    /// session on `sid`. A frame for no live session is dropped, as is one
    /// that finds the session's small queue full (heartbeats are idempotent,
    /// and a signal is followed by the initiator's l2-close anyway). Returns
    /// whether a live session holds `sid`, so a heartbeat is answered only for
    /// a command that is still running here.
    pub async fn exec_control(&self, sid: u32, msg: ExecCtl) -> bool {
        match self.exec_ctl.lock().await.get(&sid) {
            Some(tx) if !tx.is_closed() => {
                let _ = tx.try_send(msg);
                true
            }
            _ => false,
        }
    }

    /// Take the mid-session close reason for a stream, if one was recorded, so the
    /// caller can distinguish "the peer revoked us" from "the shell exited".
    pub async fn take_close_err(&self, sid: u32) -> Option<String> {
        self.close_err.lock().await.remove(&sid)
    }

    /// Data-channel died (or a send errored): tear down EVERY live stream so no
    /// pump hangs forever waiting on a peer that will never speak again.
    pub async fn shutdown_all(&self) {
        self.resizers.lock().await.clear(); // H-1: no resizer outlives the mux
        self.open_ack_tx.lock().await.clear();
        self.exec_ctl.lock().await.clear();
        self.close_err.lock().await.clear();
        let mut map = self.streams.lock().await;
        for (_, s) in map.drain() {
            if let Some(h) = s.read_pump {
                h.abort();
            }
        }
    }
}

// ----------------------------------------------------------- stream plumbing --

/// Pump local TCP reads -> data-channel frames. On local EOF, send a 4-byte
/// empty frame (clean half-close / FIN). `send_frame` carries the per-link
/// aggregate backpressure, so a slow peer naturally stalls us here. Returns the
/// kind of ending so the caller can pick FIN vs. RST in the trailing l2-close.
///
/// TODO(credits): single-stream only relies on send_frame's per-link
/// backpressure. With >1 concurrent heavy stream this needs a per-stream credit
/// window (design §4) or one slow stream head-of-line-blocks the others.
async fn socket_to_dc<R: AsyncRead + Unpin>(
    transport: Arc<dyn Transport>,
    sid: u32,
    mut rd: R,
) -> Result<()> {
    let cap = transport.max_payload();
    let mut buf = vec![0u8; cap];
    loop {
        let n = rd.read(&mut buf).await?;
        if n == 0 {
            transport.send_frame(sid, 0, &[]).await?; // local FIN -> empty frame
            return Ok(());
        }
        transport.send_frame(sid, 0, &buf[..n]).await?;
    }
}

/// Pump data-channel frames -> local TCP writes. `None` = peer FIN: shutdown the
/// write half so the local app sees a clean EOF, then end. A dropped pipe
/// (channel closed without a `None`) = abort: shutdown anyway and end.
async fn dc_to_socket<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<PipeItem>,
    mut wr: W,
    first: Option<PipeItem>,
) -> Result<()> {
    // A warm-reuse verify already pulled the FIRST inbound frame off the wire to
    // confirm the link is live; replay it here so no peer bytes are lost.
    if let Some(item) = first {
        match item {
            Some(bytes) => wr.write_all(&bytes).await?,
            None => {
                let _ = wr.shutdown().await;
                return Ok(());
            }
        }
    }
    while let Some(item) = rx.recv().await {
        match item {
            Some(bytes) => wr.write_all(&bytes).await?,
            None => {
                let _ = wr.shutdown().await; // clean half-close to local app
                return Ok(());
            }
        }
    }
    let _ = wr.shutdown().await; // pipe dropped (teardown/abort)
    Ok(())
}

/// Wire a connected socket to stream `sid` whose inbound pipe (`rx`) is already
/// registered. Spawns the write pump, stores the read pump's abort handle so
/// teardown can wake it, and runs the read pump to completion. On exit, drops
/// the stream and (optionally) sends a trailing l2-close (FIN or, on read error,
/// RST with `err`).
pub async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    sock: S,
    rx: mpsc::Receiver<PipeItem>,
    send_close: bool,
    first: Option<PipeItem>,
    // The peer's device key, for the acceptor's live-stream revocation re-check.
    // `None` for the warm/initiator bridges, which do not gate the peer's
    // liveness.
    idev: Option<[u8; 32]>,
) {
    // Caller sets TCP_NODELAY where applicable (a unix socket has none); split
    // generically so the same plumbing serves a TcpStream OR a local UnixStream
    // (the warm-link reuse path bridges a unix socket to an L2 stream).
    let (rd, wr) = tokio::io::split(sock);
    // `first`: a warm-reuse verify already pulled the first inbound frame off the
    // wire to PROVE the link is live before the client was committed; replay it
    // here so no peer bytes are lost.
    let mut writer = tokio::spawn(dc_to_socket(rx, wr, first));
    let reader_task = tokio::spawn(socket_to_dc(mux.transport.clone(), sid, rd));
    mux.set_read_pump(sid, reader_task.abort_handle()).await;
    let mut reader = Some(reader_task);

    // Half-close semantics: reader-done (client stdin-EOF) is NON-TERMINAL.
    // The reader finishing means the client closed its write-half (stdin-EOF /
    // socket write-half closed). On a Unix socket, closing the write-half sends
    // EOF to the reader (socket_to_dc sees it and sends FIN to daemon transport),
    // but the read-half stays open. The daemon keeps the pty open until the
    // command exits, then dc_to_socket finishes and the socket closes.
    //
    // Writer-done (dc_to_socket done = remote command exited / pty output pipe
    // closed) IS terminal: this is when the command has finished and all output
    // has been delivered. Only then do we send l2-close and tear down.
    //
    // Ticker+transport-dead is also terminal: a dead peer must not hang the
    // bridge. The 2s poll tears down in ~2s (kept short so a dead peer doesn't
    // leave the warm pty hung).
    //
    // read_result: Some = reader finished (Ok=FIN sent); None = we tore down
    // because the peer/link ended (writer-done or transport-dead).
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await; // consume the immediate tick
    let mut reader_done = false;
    let mut read_result = None;
    // #235-shape: a dedicated recheck ticker at the shared interval, so the
    // revoke bound is not floored by the 2s liveness tick. The tick IS the
    // cadence; the verdict is re-asked directly.
    let mut revoke_ticker = tokio::time::interval(mux.host.revoke_recheck_interval());
    revoke_ticker.tick().await; // consume the immediate first tick
    let mut revoked_reason: Option<String> = None;
    loop {
        tokio::select! {
            r = async { reader.as_mut().unwrap().await }, if !reader_done => {
                // Client-side finished: record result, disarm the arm, but DO
                // NOT break. The writer (dc_to_socket) is still waiting for the
                // remote command to exit. l2-close is sent only after the writer
                // finishes (command exit), not here.
                read_result = Some(r);
                reader = None;   // disarm - must not re-poll a resolved future
                reader_done = true;
            }
            _ = &mut writer => {
                // Terminal: remote command exited / pty output pipe closed.
                // All output delivered; safe to tear down.
                if let Some(r) = reader.take() { r.abort(); }
                read_result = None;
                break;
            }
            _ = ticker.tick() => {
                if !mux.transport.is_alive() {
                    // Terminal: transport dead. Abort both directions.
                    if let Some(r) = reader.take() { r.abort(); }
                    writer.abort();
                    read_result = None;
                    break;
                }
            }
            _ = revoke_ticker.tick() => {
                // Re-ask the gate. A revoked peer loses the live forward; the
                // denial is a close-with-reason so the client's connection breaks
                // instead of hanging.
                // Revocation AND the delegated deadline: a forward opened while
                // an invitation was live is cut when it ends, exactly as a
                // revocation cuts it (it used to check revocation only, so a
                // stream opened before expiry ran on indefinitely).
                if let Some(cut) = mux.host.live_session_cut(idev.as_ref()) {
                    match cut.cause {
                        LiveCutCause::Revoked => {
                            hooks::critical("l2: peer revoked, closing the live stream")
                        }
                        LiveCutCause::Expired => {
                            hooks::critical("l2: peer access expired, closing the live stream")
                        }
                    }
                    revoked_reason = Some(cut.reason);
                    if let Some(r) = reader.take() { r.abort(); }
                    writer.abort();
                    read_result = None;
                    break;
                }
            }
        }
    }
    // The stream may already be gone (teardown). Remove if still present.
    mux.streams.lock().await.remove(&sid);
    if send_close {
        let close = if let Some(reason) = revoked_reason {
            json!({ "type": "l2-close", "sid": sid, "err": reason })
        } else {
            match read_result {
                Some(Ok(Ok(()))) => json!({ "type": "l2-close", "sid": sid }), // clean FIN
                Some(Ok(Err(e))) => json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }),
                Some(Err(_aborted)) => return, // teardown owns the close; don't double-send
                // Peer FIN or link death: ack a close so the peer reaps its half (a
                // no-op if the transport is already gone).
                None => json!({ "type": "l2-close", "sid": sid }),
            }
        };
        let _ = mux.transport.send_control(&close).await;
    }
}

// ------------------------------------------------------------- ACCEPTOR side --

/// Decision for an inbound `l2-open`, made synchronously in the event loop
/// BEFORE any await, so the pipe is registered before a data frame for this sid
/// can be processed (closes the early-frame-drop race, design §3.4).
pub enum OpenVerdict {
    /// Accepted: dial this localhost target and relay. Carries the pre-registered
    /// inbound pipe.
    Accept {
        sid: u32,
        host: String,
        port: u16,
        rx: mpsc::Receiver<PipeItem>,
    },
    /// Refused: send l2-close{err} and forget it.
    Deny { sid: u32, err: &'static str },
    /// Not an l2-open / malformed, ignore.
    Ignore,
}

impl Mux {
    /// Handle an inbound L2 *control* message on the acceptor side. `trusted` is
    /// the proof-verified capability flag for this link (the placeholder gate).
    /// Registers the pipe synchronously for an accepted open, then returns the
    /// verdict for the caller to act on (the dial is async and must NOT block the
    /// event loop). Returns `Ignore` for non-l2 control.
    /// `allow_nonloopback`: the caller (main.rs, where the peer's device name is
    /// known) decided this specific non-loopback target is permitted by the
    /// operator's opt-in `l2-allow.json` allowlist. Loopback is always allowed; a
    /// non-loopback host is refused UNLESS this is set, keeping the SSRF default.
    pub async fn accept_control(
        &self,
        v: &Value,
        trusted: bool,
        allow_nonloopback: bool,
    ) -> OpenVerdict {
        // With `forward-server` off, the `l2-open` arm is compiled out and these
        // two inputs are unused; keep the signature stable and silence the lint.
        #[cfg(not(feature = "forward-server"))]
        let _ = (trusted, allow_nonloopback);
        match v["type"].as_str() {
            #[cfg(feature = "forward-server")]
            Some("l2-open") => {
                // Reject a missing OR out-of-range sid (wire_sid never truncates)
                // rather than defaulting/wrapping into a forged is_l2_sid value.
                let Some(sid) = wire_sid(v) else {
                    return OpenVerdict::Ignore;
                };
                if !is_l2_sid(sid) {
                    return OpenVerdict::Ignore; // not in the high half, not ours
                }
                // Idempotency: a duplicate open for a live sid is ignored.
                {
                    let mut acc = self.accepted.lock().await;
                    if acc.contains_key(&sid) {
                        return OpenVerdict::Ignore;
                    }
                    acc.insert(sid, ());
                }
                // ---- CAPABILITY GATE (placeholder; see TODO below) ----
                // Today: the peer must be a remembered/trusted device (its
                // pair-proof verified on this link, main.rs ~3111). That is the
                // coarse stand-in for L1-a's per-cap model.
                if !trusted {
                    return OpenVerdict::Deny { sid, err: "denied" };
                }
                // TODO(L1-a caps): replace the bare `trusted` check above with the
                // real capability decision once l1-a-pake merges. L1-a gives each
                // device a record {name, secret, caps[]}; here we must require the
                // `forward` cap (and `shell` for port 22) carried/proved in
                // `v["cap"]` and bound to the DTLS fingerprints, deny-by-default.
                // The whole L2 acceptor stays OFF unless TUNLION_L2=1 (opt-in).

                let host = v["host"].as_str().unwrap_or("127.0.0.1").to_string();
                let port = v["rport"]
                    .as_u64()
                    .or_else(|| v["port"].as_u64())
                    .unwrap_or(0) as u16;
                if port == 0 {
                    return OpenVerdict::Deny {
                        sid,
                        err: "bad port",
                    };
                }
                // ---- SSRF defense: localhost-only by default ----
                // Stricter than is_private_addr (which ALLOWS LAN/RFC1918): the
                // dial target must resolve to loopback. A non-loopback host is
                // refused UNLESS the caller's opt-in per-device allowlist
                // (l2-allow.json) authorized this exact target (`allow_nonloopback`).
                if !host_is_loopback(&host) && !allow_nonloopback {
                    return OpenVerdict::Deny {
                        sid,
                        err: "non-loopback denied (not in l2-allow.json)",
                    };
                }
                // H-1 (DoS): cap concurrent streams per link. A flaky/hostile
                // paired device can otherwise flood `l2-open` and exhaust
                // sockets/threads. We drop the `accepted` marker so the same sid
                // can be retried once others free up.
                if self.at_stream_cap().await {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny {
                        sid,
                        err: "too many streams",
                    };
                }
                // Collision-safe register: if the peer named a sid already live
                // on this link (its own forward/pty/mount), REFUSE rather than
                // overwrite. Drop the `accepted` marker so the sid isn't wedged.
                let Some(rx) = self.register(sid).await else {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny {
                        sid,
                        err: "sid in use",
                    };
                };
                OpenVerdict::Accept {
                    sid,
                    host,
                    port,
                    rx,
                }
            }
            // Without `forward-server` there is no inbound dial implementation
            // compiled, so an open is refused by name: never registered on the
            // mux, never dialled. `l2-close` stays common because a node that
            // serves no inbound opens still OPENS outbound ones, and the peer's
            // answer to those must not be discarded.
            #[cfg(not(feature = "forward-server"))]
            Some("l2-open") => match wire_sid(v) {
                Some(sid) if is_l2_sid(sid) => OpenVerdict::Deny {
                    sid,
                    err: FORWARD_SERVER_UNAVAILABLE,
                },
                _ => OpenVerdict::Ignore,
            },
            Some("l2-close") => {
                // wire_sid (not `as u32`): a wrapped/oversized close sid must not
                // be truncated into a live sid and tear down the wrong stream.
                if let Some(sid) = wire_sid(v) {
                    self.on_close(sid, v["err"].as_str()).await;
                }
                OpenVerdict::Ignore
            }
            _ => OpenVerdict::Ignore,
        }
    }

    /// Acceptor: dial the localhost target for an accepted open and relay. Sends
    /// l2-open-ack on success, l2-close{err} on dial failure. Runs as its own
    /// task (the event loop spawns it) so the dial never blocks routing.
    ///
    /// The dial itself is the host's: a peer asked for a local socket, and only
    /// the host may open one. Its inert default refuses, so a library consumer
    /// that installs no host cannot be tricked into dialling by a peer. The
    /// loopback check and the operator allowlist already ran in
    /// `accept_control`.
    pub async fn dial_and_serve(
        self: Arc<Self>,
        sid: u32,
        host: String,
        port: u16,
        rx: mpsc::Receiver<PipeItem>,
        idev: Option<[u8; 32]>,
    ) {
        // The dial itself is the host's: a peer asked for a local socket, and
        // only the host may open one. With `forward-server` off, no dial
        // implementation is compiled anywhere; the open is answered with an
        // explicit named refusal instead of an ack, so the peer never hangs.
        #[cfg(feature = "forward-server")]
        let dialed = self.host.connect_local_stream(host.as_str(), port).await;
        #[cfg(not(feature = "forward-server"))]
        let dialed: std::io::Result<tokio::net::TcpStream> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            FORWARD_SERVER_UNAVAILABLE,
        ));
        #[cfg(not(feature = "forward-server"))]
        let _ = (&host, &port);
        match dialed {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                // l2-open-ack is mandatory (design §3.4/O2): it tells the
                // initiator the stream is live. credit-in-ack is the follow-up
                // (TODO(credits)); 0 here means "no per-stream window yet".
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-open-ack", "sid": sid, "credit": 0 }))
                    .await;
                serve_stream(self.clone(), sid, sock, rx, true, None, idev).await;
                self.accepted.lock().await.remove(&sid);
            }
            Err(e) => {
                self.drop_stream(sid).await;
                self.accepted.lock().await.remove(&sid);
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }))
                    .await;
            }
        }
    }
}

/// True if `host` is a loopback address/name. We accept the literal "localhost"
/// and any address that parses to a loopback IP. (DNS for arbitrary names is
/// deliberately NOT performed here, the default contract is localhost-only and
/// a name that isn't "localhost" is treated as non-loopback.)
fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// The signals a served remote command can be sent as a whole tree.
///
/// Moved with `Mux`, whose `exec_ctl` channel carries it. The wire names are
/// frozen: `HUP`/`INT`/`TERM`/`KILL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeSignal {
    /// The terminal went away (the initiator is gone).
    Hangup,
    /// The initiator's user pressed Ctrl-C.
    Interrupt,
    /// Asked to stop.
    Terminate,
    /// Ended now; cannot be caught.
    Kill,
}

impl TreeSignal {
    /// The wire name (`exec-signal`'s `signal`), shared by both ends.
    pub fn wire(self) -> &'static str {
        match self {
            TreeSignal::Hangup => "HUP",
            TreeSignal::Interrupt => "INT",
            TreeSignal::Terminate => "TERM",
            TreeSignal::Kill => "KILL",
        }
    }

    pub fn from_wire(s: &str) -> Option<TreeSignal> {
        Some(match s {
            "HUP" => TreeSignal::Hangup,
            "INT" => TreeSignal::Interrupt,
            "TERM" => TreeSignal::Terminate,
            "KILL" => TreeSignal::Kill,
            _ => return None,
        })
    }
}

/// Initiator -> acceptor control for one served exec, routed by sid through
/// the peer's own mux (`Mux::exec_control`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCtl {
    /// `exec-alive`: the initiator is still there.
    Alive,
    /// `exec-signal`: deliver this signal to the remote tree.
    Signal(TreeSignal),
}

impl ExecCtl {
    /// Parse `{type:"exec-alive"}` or `{type:"exec-signal", signal:"INT"}`.
    /// An unknown signal name is ignored rather than guessed at.
    pub fn from_frame(v: &Value) -> Option<ExecCtl> {
        match v.get("type")?.as_str()? {
            "exec-alive" => Some(ExecCtl::Alive),
            "exec-signal" => TreeSignal::from_wire(v.get("signal")?.as_str()?).map(ExecCtl::Signal),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::NoHost;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    /// Minimal in-memory Transport: records control messages, discards frames.
    struct MockTransport {
        controls: StdMutex<Vec<Value>>,
        alive: bool,
    }
    impl MockTransport {
        fn new() -> Arc<Self> {
            Self::new_with_alive(true)
        }
        fn new_with_alive(alive: bool) -> Arc<Self> {
            Arc::new(MockTransport {
                controls: StdMutex::new(Vec::new()),
                alive,
            })
        }
    }
    #[async_trait]
    impl Transport for MockTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn is_dead(&self) -> bool {
            !self.alive
        }
        fn is_alive(&self) -> bool {
            self.alive
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn open_msg(sid: u32) -> Value {
        json!({ "type": "l2-open", "sid": sid, "host": "127.0.0.1", "rport": 9 })
    }

    /// Distinct host answers must survive simultaneous mux ownership, including
    /// constructing a later inert mux. No process install or test serialization.
    struct NamedHost(&'static str);

    #[async_trait]
    impl HostServices for NamedHost {
        fn settings_get_str(&self, key: &str) -> Option<String> {
            NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            NoHost.devices_load()
        }
        fn is_self_uid(&self, my_uid: &str, peer_uid: Option<&str>) -> bool {
            NoHost.is_self_uid(my_uid, peer_uid)
        }
        fn rejoin_unwarned(&self) -> Duration {
            NoHost.rejoin_unwarned()
        }
        fn relay_banner(&self) -> String {
            NoHost.relay_banner()
        }
        fn relay_forbidden(&self) -> bool {
            NoHost.relay_forbidden()
        }
        fn channel_of(&self, secret: &str) -> String {
            NoHost.channel_of(secret)
        }
        fn roster_snapshot_json(&self) -> Option<String> {
            NoHost.roster_snapshot_json()
        }
        fn fleet_rv_present(&self) -> bool {
            NoHost.fleet_rv_present()
        }
        async fn connect_local_stream(
            &self,
            _host: &str,
            _port: u16,
        ) -> std::io::Result<tokio::net::TcpStream> {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, self.0))
        }
        fn live_session_cut(&self, idev: Option<&[u8; 32]>) -> Option<crate::host::LiveCut> {
            idev.map(|_| crate::host::LiveCut {
                cause: LiveCutCause::Revoked,
                expires_at: None,
                reason: self.0.to_string(),
            })
        }
        fn revoke_recheck_interval(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    #[cfg(feature = "forward-server")]
    #[tokio::test]
    async fn simultaneous_muxes_dial_through_their_own_hosts_without_fallback() {
        let ta = MockTransport::new();
        let tb = MockTransport::new();
        let inert_transport = MockTransport::new();
        let a = Mux::new(ta.clone(), Arc::new(NamedHost("host-a")));
        let b = Mux::with_host(tb.clone(), Arc::new(NamedHost("host-b")));
        let inert = Mux::new(inert_transport.clone(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 12;
        let ra = a.register(sid).await.unwrap();
        let rb = b.register(sid).await.unwrap();
        let ri = inert.register(sid).await.unwrap();
        tokio::join!(
            a.clone().dial_and_serve(sid, "127.0.0.1".into(), 9, ra, None),
            b.clone().dial_and_serve(sid, "127.0.0.1".into(), 9, rb, None),
            inert.clone().dial_and_serve(sid, "127.0.0.1".into(), 9, ri, None),
        );
        for (mux, transport, reason) in [
            (a, ta, "host-a"),
            (b, tb, "host-b"),
            (inert, inert_transport, "does not open local sockets"),
        ] {
            assert_eq!(mux.live_streams().await, 0);
            let controls = transport.controls.lock().unwrap();
            assert_eq!(controls.len(), 1, "failed dial must close, never ack");
            assert_eq!(controls[0]["type"], "l2-close");
            assert!(controls[0]["err"].as_str().unwrap().contains(reason));
        }
    }

    #[tokio::test]
    async fn simultaneous_muxes_recheck_live_sessions_with_their_own_hosts() {
        let ta = MockTransport::new();
        let tb = MockTransport::new();
        let a = Mux::new(ta.clone(), Arc::new(NamedHost("cut-a")));
        let b = Mux::new(tb.clone(), Arc::new(NamedHost("cut-b")));
        let sid = L2_SID_BASE | 13;
        let ra = a.register(sid).await.unwrap();
        let rb = b.register(sid).await.unwrap();
        let (_client_a, socket_a) = tokio::io::duplex(64);
        let (_client_b, socket_b) = tokio::io::duplex(64);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                serve_stream(a.clone(), sid, socket_a, ra, true, None, Some([1; 32])),
                serve_stream(b.clone(), sid, socket_b, rb, true, None, Some([1; 32])),
            );
        })
        .await
        .expect("both hosts must independently terminate their live streams");
        for (mux, transport, reason) in [(a, ta, "cut-a"), (b, tb, "cut-b")] {
            assert_eq!(mux.live_streams().await, 0);
            let controls = transport.controls.lock().unwrap();
            assert!(controls.iter().any(|v| v["type"] == "l2-close" && v["err"] == reason));
        }
    }
    #[tokio::test]
    async fn on_frame_resets_full_pipe_instead_of_parking() {
        let t = MockTransport::new();
        let mux = Mux::new(t.clone(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 77;
        let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
        // Fill the 256-slot pipe with NOBODY reading (stalled consumer).
        for _ in 0..256 {
            mux.on_frame(sid, bytes::Bytes::from_static(b"x")).await;
        }
        assert!(
            mux.streams.lock().await.contains_key(&sid),
            "a full-but-live pipe stays registered"
        );
        // The 257th frame must reset promptly, never park the caller.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mux.on_frame(sid, bytes::Bytes::from_static(b"y")),
        )
        .await
        .expect("on_frame never parks, even on a full pipe");
        assert!(
            !mux.streams.lock().await.contains_key(&sid),
            "full pipe resets (drops) the stream"
        );
        let controls = t.controls.lock().unwrap();
        assert!(
            controls.iter().any(
                |v| v.get("type").and_then(|x| x.as_str()) == Some("l2-close")
                    && v.get("sid").and_then(|x| x.as_u64()) == Some(sid as u64)
                    && v.get("err")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .contains("flooded")
            ),
            "reset carries an l2-close naming the flood, got: {controls:?}"
        );
    }

    /// H-1: the per-link stream cap refuses opens beyond MAX_STREAMS_PER_LINK with
    /// an `l2-close{err:"too many streams"}`, and does NOT register the stream.
    #[cfg(feature = "forward-server")]
    #[tokio::test]
    async fn per_link_stream_cap_refuses_over_limit() {
        let mux = Mux::new(MockTransport::new(), Arc::new(NoHost));
        // Fill to the cap with accepted opens (they register pipes).
        for i in 0..MAX_STREAMS_PER_LINK as u32 {
            let sid = L2_SID_BASE | (i + 1);
            match mux.accept_control(&open_msg(sid), true, false).await {
                OpenVerdict::Accept { .. } => {}
                other => panic!(
                    "expected Accept under cap, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        }
        assert_eq!(mux.live_streams().await, MAX_STREAMS_PER_LINK);
        // One more must be denied with the cap error, leaving the table unchanged.
        let over = L2_SID_BASE | 9999;
        match mux.accept_control(&open_msg(over), true, false).await {
            OpenVerdict::Deny { sid, err } => {
                assert_eq!(sid, over);
                assert_eq!(err, "too many streams");
            }
            other => panic!(
                "expected Deny over cap, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert_eq!(
            mux.live_streams().await,
            MAX_STREAMS_PER_LINK,
            "over-cap open must not register"
        );
        // The denied sid is not stuck in `accepted` (can retry once room frees).
        assert!(!mux.accepted.lock().await.contains_key(&over));
    }

    /// SECURITY (sid collision): a second `register` for an ALREADY-LIVE sid must
    /// be REFUSED (return None), NOT silently overwrite the existing StreamHandle.
    /// An overwrite drops the first handle's read pump WITHOUT abort() (leaking a
    /// parked socket) while `streams.len()` stays flat (defeating the H-1 cap) and
    /// redirects the sid's inbound frames to the new stream. The peer chooses the
    /// sid, so this is a peer-triggerable protocol error, and `register` is the
    /// single structural chokepoint that refuses it.
    #[tokio::test]
    async fn register_refuses_duplicate_live_sid() {
        let mux = Mux::new(MockTransport::new(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 42;
        let mut rx1 = mux.register(sid).await.expect("first register succeeds");
        assert_eq!(mux.live_streams().await, 1);

        // Second register for the SAME live sid is refused (no new channel).
        assert!(
            mux.register(sid).await.is_none(),
            "duplicate register on a live sid must be refused, not overwrite"
        );
        // Table unchanged: still exactly one stream for S.
        assert_eq!(
            mux.live_streams().await,
            1,
            "refused register must not change the table"
        );

        // The ORIGINAL handle is intact: an inbound frame for S still reaches rx1,
        // proving its tx was NOT replaced by a second register's fresh channel.
        mux.on_frame(sid, Bytes::from_static(b"hello")).await;
        match rx1.recv().await {
            Some(Some(bytes)) => assert_eq!(&bytes[..], b"hello"),
            other => panic!("original stream channel broken after refused register: {other:?}"),
        }
    }

    /// A detached session's late cleanup must not free a NEWER stream that
    /// reused the same sid. Generations make the release conditional.
    #[tokio::test]
    async fn drop_stream_if_spares_a_new_generation_on_the_same_sid() {
        let mux = Mux::new(MockTransport::new(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 55;
        let _old = mux.register_stream(sid).await.expect("first generation");
        let old = mux.stream_generation(sid).await.expect("generation recorded");
        mux.drop_stream(sid).await;
        let _new = mux.register_stream(sid).await.expect("sid reused");
        let new = mux.stream_generation(sid).await.expect("new generation");
        assert_ne!(old, new, "a reused sid gets a fresh identity");

        // The OLD generation's cleanup is a no-op against the new stream.
        mux.drop_stream_if(sid, old).await;
        assert!(mux.has_stream(sid).await, "old cleanup must not free the new stream");
        // The CURRENT generation releases it.
        mux.drop_stream_if(sid, new).await;
        assert!(!mux.has_stream(sid).await);
        assert_eq!(mux.live_resizers().await, 0);
    }

    /// SECURITY (cross-stream collision): the exact shipped bug. A pty/mount open
    /// registers a stream at sid S through the bare insert (bypassing the l2-open
    /// `accepted` guard); a later `l2-open` naming the SAME S must be DENIED
    /// ("sid in use") rather than displace the pre-existing stream. `register` is
    /// now the chokepoint so every stream type inherits the protection.
    #[cfg(feature = "forward-server")]
    #[tokio::test]
    async fn accept_control_denies_open_on_live_foreign_sid() {
        let mux = Mux::new(MockTransport::new(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 7;
        // A pty/mount claims S via register_stream (a path that never touches the
        // `accepted` map, so the l2-open acceptor cannot see it there).
        let mut rx_orig = mux
            .register_stream(sid)
            .await
            .expect("first claim succeeds");
        assert_eq!(mux.live_streams().await, 1);

        // A peer now opens an l2 forward naming the SAME sid.
        match mux.accept_control(&open_msg(sid), true, false).await {
            OpenVerdict::Deny { sid: dsid, err } => {
                assert_eq!(dsid, sid);
                assert_eq!(err, "sid in use");
            }
            other => panic!(
                "expected Deny on live-sid reuse, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        // Still exactly one stream, and the colliding open left no `accepted` wedge.
        assert_eq!(
            mux.live_streams().await,
            1,
            "collision must not add or replace a stream"
        );
        assert!(
            !mux.accepted.lock().await.contains_key(&sid),
            "denied open must not wedge `accepted`"
        );
        // The surviving stream is the ORIGINAL: an inbound frame still reaches rx_orig.
        mux.on_frame(sid, Bytes::from_static(b"orig")).await;
        match rx_orig.recv().await {
            Some(Some(b)) => assert_eq!(&b[..], b"orig"),
            other => panic!("original stream displaced by colliding open: {other:?}"),
        }
    }

    /// SECURITY (sid truncation): a wire `sid` that does not fit in u32 must be
    /// REJECTED by `wire_sid`, never truncated. `0x1_8000_0000 as u32 ==
    /// 0x8000_0000` would otherwise pass `is_l2_sid` and alias a legit high-half
    /// sid; a missing sid must be rejected too, never defaulted to 0.
    #[test]
    fn wire_sid_rejects_out_of_range_and_missing() {
        // In range: parsed exactly.
        assert_eq!(
            wire_sid(&json!({ "sid": 0x8000_0000u64 })),
            Some(0x8000_0000)
        );
        assert_eq!(wire_sid(&json!({ "sid": 0u64 })), Some(0));
        assert_eq!(wire_sid(&json!({ "sid": u32::MAX as u64 })), Some(u32::MAX));
        // The aliasing attack value: 0x1_8000_0000 must NOT become 0x8000_0000.
        let attack = 0x1_8000_0000u64;
        assert_eq!(
            attack as u32, 0x8000_0000,
            "precondition: a bare cast truncates"
        );
        assert_eq!(
            wire_sid(&json!({ "sid": attack })),
            None,
            "oversized sid must be refused, not wrapped"
        );
        // Just past the boundary is rejected, not wrapped to 0.
        assert_eq!(wire_sid(&json!({ "sid": (u32::MAX as u64) + 1 })), None);
        // Missing sid: rejected, NOT defaulted to 0.
        assert_eq!(wire_sid(&json!({ "type": "l2-open" })), None);
    }

    /// The seam's inert semantics: an explicitly inert host cannot be made
    /// to dial a peer-named target. The refusal takes the same `l2-close` path a
    /// failed dial always took, and the open is never acked.
    #[cfg(feature = "forward-server")]
    #[tokio::test]
    async fn inert_host_refuses_a_peer_requested_dial() {
        let t = MockTransport::new();
        let mux = Mux::with_host(t.clone(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 11;
        let rx = mux.register(sid).await.expect("fresh sid registers");
        mux.clone()
            .dial_and_serve(sid, "127.0.0.1".to_string(), 9, rx, None)
            .await;
        {
            let controls = t.controls.lock().unwrap();
            assert!(
                !controls.iter().any(|v| v["type"] == "l2-open-ack"),
                "an inert host must not ack an open it did not dial: {controls:?}"
            );
            assert!(
                controls.iter().any(|v| v["type"] == "l2-close"
                    && v["sid"].as_u64() == Some(sid as u64)
                    && v["err"]
                        .as_str()
                        .unwrap_or("")
                        .contains("does not open local sockets")),
                "the refusal must ride the usual l2-close: {controls:?}"
            );
        }
        assert_eq!(
            mux.live_streams().await,
            0,
            "a refused dial must drop its stream"
        );
    }

    /// A transport whose liveness we can flip, to prove the daemon bridge tears
    /// down on transport death (not just on a clean FIN) even with an IDLE client.
    struct KillableTransport {
        alive: std::sync::atomic::AtomicBool,
    }
    impl KillableTransport {
        fn new() -> Arc<Self> {
            Arc::new(KillableTransport {
                alive: std::sync::atomic::AtomicBool::new(true),
            })
        }
        fn kill(&self) {
            self.alive.store(false, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl Transport for KillableTransport {
        async fn send_control(&self, _msg: &Value) -> Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
        fn is_dead(&self) -> bool {
            !self.alive.load(Ordering::SeqCst)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Regression for the warm-pty deadlock: the daemon bridge (`serve_stream`) must
    /// tear down when the PEER TRANSPORT dies even while the local client is IDLE.
    /// The client->peer reader parks on the silent client socket and never notices
    /// the death; awaiting only that reader (the old code) hung the warm bridge - and
    /// the user's warm pty - until they happened to type. The liveness ticker now
    /// catches it: with an idle client and a killed transport, this returns instead
    /// of blocking forever.
    #[tokio::test]
    async fn serve_stream_tears_down_on_transport_death_with_idle_client() {
        let t = KillableTransport::new();
        let mux = Mux::new(t.clone(), Arc::new(NoHost));
        let sid = L2_SID_BASE | 7;
        let rx = mux.register(sid).await.expect("fresh sid registers");
        // A duplex pair: one half is the bridge's "client socket", the other we keep
        // and NEVER write to, so the reader stays parked (the deadlock precondition).
        let (client, server_side) = tokio::io::duplex(1024);
        let bridge = tokio::spawn(serve_stream(
            mux.clone(),
            sid,
            server_side,
            rx,
            true,
            None,
            None,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await; // let the reader park
        t.kill(); // transport dies with no clean FIN and no client input
        let r = tokio::time::timeout(Duration::from_secs(4), bridge).await;
        assert!(
            r.is_ok(),
            "serve_stream deadlocked on an idle client after transport death"
        );
        drop(client);
    }
}
