// L2, ssh / raw TCP tunnelled over the Filament WebRTC data channel.
//
// Productionizes docs/L2-tunnel-design.md (spike: cli/spike/l2spike.rs). L2
// multiplexes logical TCP streams over the SAME data channel that moves files
// today, reusing the `Transport` trait verbatim, no transport changes.
//
// SCOPE: single-stream (ssh / one forward at a time is the supported case and
// what ships first). Multiple *concurrent heavy* streams over one link need
// per-stream credit flow control (design §4) to stay deadlock-free; that is a
// follow-up, see TODO(credits) below. l2-open-ack is mandatory here (it closes
// the early-frame-drop race and the open/deny ambiguity); the `credit` field it
// will eventually carry is the only piece deferred.
//
// Three surfaces, smallest-primitive-first (each is sugar over the one below):
//   * `filament netcat <peer> <rport>`            stdio  <-> one L2 stream
//   * `filament forward <lport> <peer> <rport>`   local TCP listener; conn=stream
//   * `filament ssh <peer> [args...]`             real ssh -o ProxyCommand=netcat
//
// The ACCEPTOR (the side that dials the localhost target) is NOT a subcommand:
// it lives inside `filament up` / `filament recv`, gated on the existing
// proof-verified `trusted` flag (the capability placeholder) + localhost-only
// dialing (the SSRF defense). See `Mux::on_open` and main.rs's recv loop.

use crate::net::{self, Ev, Peer, Transport};
use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

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

/// Per-stream pipe item: `Some(bytes)` = data; `None` = clean half-close/EOF
/// (an empty 4-byte data frame). A RST/abort is signalled out-of-band by
/// dropping the whole stream entry (writer wakes on a closed channel), distinct
/// from `None` so a reset is never mistaken for an orderly EOF.
type PipeItem = Option<Bytes>;
type StreamTx = mpsc::Sender<PipeItem>;

/// Liveness handle for one stream's two pumps. Holding the read-pump's
/// `AbortHandle` is what makes teardown actually work: `socket_to_dc` parks in
/// `rd.read()` and will NOT wake just because we drop its peer channel, so on
/// data-channel death / l2-close we must abort it explicitly (design §3.5).
struct StreamHandle {
    tx: StreamTx,
    read_pump: Option<AbortHandle>,
}

/// H-1 (DoS): per-link cap on concurrently live streams (file + L2 + PTY share
/// the `streams` table). Beyond this an `l2-open`/`pty-open` is refused. A
/// generous bound, interactive use needs only a handful, that still stops a
/// flaky/hostile paired device from spawning unbounded threads/sockets.
pub const MAX_STREAMS_PER_LINK: usize = 8;

/// H-1 (DoS): process-wide cap on concurrently live PTYs across ALL links. Each
/// PTY is a login shell + threads, so this bounds total resource use even if many
/// links each stay under the per-link cap. Refused opens get an `l2-close`.
pub const MAX_PTYS_GLOBAL: usize = 32;

/// Process-wide live-PTY counter (incremented just before a PTY session task is
/// spawned, decremented when it ends, see `PtyGuard`). The acceptor checks it
/// against `MAX_PTYS_GLOBAL` before granting a `pty-open`.
pub static LIVE_PTYS: AtomicUsize = AtomicUsize::new(0);

/// RAII guard that decrements `LIVE_PTYS` on drop, so the global PTY count is
/// freed on EVERY PTY session exit path (shell exit, browser FIN, error return).
pub struct PtyGuard;
impl PtyGuard {
    /// Reserve a global PTY slot if one is free. Returns `None` (and reserves
    /// nothing) when `MAX_PTYS_GLOBAL` live PTYs already exist.
    pub fn try_acquire() -> Option<PtyGuard> {
        // Optimistic CAS loop so the check + increment is atomic across links.
        let mut cur = LIVE_PTYS.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_PTYS_GLOBAL {
                return None;
            }
            match LIVE_PTYS.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(PtyGuard),
                Err(actual) => cur = actual,
            }
        }
    }
}
impl Drop for PtyGuard {
    fn drop(&mut self) {
        LIVE_PTYS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The multiplexer: routes inbound control/data frames to per-stream pipes and
/// owns stream-id allocation. Transport-agnostic, it rides above the trait.
pub struct Mux {
    transport: Arc<dyn Transport>,
    streams: Mutex<HashMap<u32, StreamHandle>>,
    next_sid: AtomicU32,
    /// Acceptor only: sids we have seen `l2-open` for and accepted, so a late
    /// duplicate open is ignored. (Initiator allocates, so it can't double-open.)
    accepted: Mutex<HashMap<u32, ()>>,
    /// web-shell: per-sid PTY resize senders. H-1: owning these HERE (rather than
    /// in the main event loop) guarantees they are dropped on EVERY teardown path:
    /// inbound `l2-close` (`on_close`), the session task exit (`drop_pty`), and
    /// link/mux death (`shutdown_all`), closing the resizer-map leak.
    resizers: Mutex<HashMap<u32, mpsc::UnboundedSender<(u16, u16)>>>,
}

impl Mux {
    pub fn new(t: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(Mux {
            transport: t,
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            accepted: Mutex::new(HashMap::new()),
            resizers: Mutex::new(HashMap::new()),
        })
    }

    pub fn transport(&self) -> Arc<dyn Transport> {
        self.transport.clone()
    }

    fn alloc_sid(&self) -> u32 {
        // Mask the counter to the low 30 bits so a long-lived link never escapes
        // into the L2 flag (0x80000000) OR the answerer-role bit (0x40000000).
        // The role bit keeps the two ends' sid spaces DISJOINT: each end allocates
        // with its own bit (opposite the peer's, via the deterministic `polite`
        // role), so a sid this end allocates can never equal one the peer
        // allocated — preventing cross-tunnel frame collisions when both ends open
        // L2 streams on one link (pty + warm-reuse forward, etc.).
        let n = self.next_sid.fetch_add(1, Ordering::Relaxed) & 0x3FFF_FFFF;
        let role = if self.transport.sid_answerer() { 0x4000_0000 } else { 0 };
        n | L2_SID_BASE | role
    }

    /// Register a stream's inbound pipe and return the receiver the socket-writer
    /// task drains. The read-pump handle is attached later via `set_read_pump`.
    async fn register(&self, sid: u32) -> mpsc::Receiver<PipeItem> {
        let (tx, rx) = mpsc::channel::<PipeItem>(256);
        self.streams
            .lock()
            .await
            .insert(sid, StreamHandle { tx, read_pump: None });
        rx
    }

    async fn set_read_pump(&self, sid: u32, h: AbortHandle) {
        if let Some(s) = self.streams.lock().await.get_mut(&sid) {
            s.read_pump = Some(h);
        } else {
            // Stream already gone (raced with teardown), kill the orphan pump.
            h.abort();
        }
    }

    /// Register a stream's inbound pipe (public, for the PTY acceptor which
    /// registers BEFORE spawning the shell, same pre-registration race fix as
    /// l2-open's dial path).
    pub async fn register_stream(&self, sid: u32) -> mpsc::Receiver<PipeItem> {
        self.register(sid).await
    }

    /// Number of currently live streams on this link (file + L2 + PTY share the
    /// table). H-1: the acceptor checks this against `MAX_STREAMS_PER_LINK`
    /// before accepting a new `l2-open`/`pty-open`.
    pub async fn live_streams(&self) -> usize {
        self.streams.lock().await.len()
    }

    /// True if accepting one more stream would exceed `MAX_STREAMS_PER_LINK`.
    pub async fn at_stream_cap(&self) -> bool {
        self.live_streams().await >= MAX_STREAMS_PER_LINK
    }

    /// Drop a stream and abort its read pump. Idempotent. Also drops any PTY
    /// resize sender for this sid (H-1: no resizer outlives its stream).
    async fn drop_stream(&self, sid: u32) {
        self.resizers.lock().await.remove(&sid);
        if let Some(s) = self.streams.lock().await.remove(&sid) {
            if let Some(h) = s.read_pump {
                h.abort();
            }
            // Dropping `s.tx` closes the pipe; the writer pump (dc_to_socket)
            // sees `recv()` return None and shuts the socket down.
        }
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
    pub async fn on_frame(&self, sid: u32, payload: Bytes) {
        let tx = self.streams.lock().await.get(&sid).map(|s| s.tx.clone());
        if let Some(tx) = tx {
            let msg = if payload.is_empty() { None } else { Some(payload) };
            let _ = tx.send(msg).await; // receiver gone => stream already torn down
        }
    }

    /// Inbound l2-close. `err` set = RST/abort (drop, do NOT deliver clean EOF);
    /// no `err` = the peer is done, also a drop (its data direction already
    /// EOF'd via the empty frame). Either way: abort pumps, close the socket.
    async fn on_close(&self, sid: u32, _err: Option<&str>) {
        self.drop_stream(sid).await;
    }

    /// Data-channel died (or a send errored): tear down EVERY live stream so no
    /// pump hangs forever waiting on a peer that will never speak again.
    pub async fn shutdown_all(&self) {
        self.resizers.lock().await.clear(); // H-1: no resizer outlives the mux
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
            transport.send_frame(sid, &[]).await?; // local FIN -> empty frame
            return Ok(());
        }
        transport.send_frame(sid, &buf[..n]).await?;
    }
}

/// Pump data-channel frames -> local TCP writes. `None` = peer FIN: shutdown the
/// write half so the local app sees a clean EOF, then end. A dropped pipe
/// (channel closed without a `None`) = abort: shutdown anyway and end.
async fn dc_to_socket<W: AsyncWrite + Unpin>(
    mut rx: mpsc::Receiver<PipeItem>,
    mut wr: W,
) -> Result<()> {
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
async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    sock: S,
    rx: mpsc::Receiver<PipeItem>,
    send_close: bool,
) {
    // Caller sets TCP_NODELAY where applicable (a unix socket has none); split
    // generically so the same plumbing serves a TcpStream OR a local UnixStream
    // (the warm-link reuse path bridges a unix socket to an L2 stream).
    let (rd, wr) = tokio::io::split(sock);
    let writer = tokio::spawn(dc_to_socket(rx, wr));
    let reader = tokio::spawn(socket_to_dc(mux.transport.clone(), sid, rd));
    mux.set_read_pump(sid, reader.abort_handle()).await;

    // Wait for the read pump: Ok = local FIN sent; Err = socket error -> RST;
    // Aborted = teardown already cleaned us up.
    let read_result = reader.await;
    let _ = writer.await;
    // The stream may already be gone (teardown). Remove if still present.
    mux.streams.lock().await.remove(&sid);
    if send_close {
        let close = match read_result {
            Ok(Ok(())) => json!({ "type": "l2-close", "sid": sid }), // clean FIN
            Ok(Err(e)) => json!({ "type": "l2-close", "sid": sid, "err": e.to_string() }),
            Err(_aborted) => return, // teardown owns the close; don't double-send
        };
        let _ = mux.transport.send_control(&close).await;
    }
}

// ----------------------------------------------------- PERSISTENT PTY SESSIONS --
//
// Issue #4 (disconnects lose progress): a PTY must OUTLIVE the data channel that
// opened it. A link-bound bridge would tie the shell's lifetime to one link, so a
// dropped channel would kill the shell. The session model below decouples them:
//
//   * A `PtySession` owns the shell (child + master + reader/writer threads) and
//     a long-lived task. It is keyed by a STABLE `session id` chosen by the
//     browser, NOT by the per-link sid (which changes on every reconnect).
//   * While ATTACHED, PTY output is framed to the current link's transport+sid
//     AND mirrored into a bounded ring buffer. While DETACHED (channel dropped),
//     output only accrues in the ring (capped: oldest bytes evicted).
//   * On reconnect the browser re-opens with the SAME session id; the acceptor
//     calls `attach`, which rebinds the new transport+sid and REPLAYS the ring,
//     so the user sees the same shell and its missed output (tmux/mosh-style).
//   * Caps: the ring is bounded (`SESSION_BUFFER_CAP`); a detached session is
//     reaped after `SESSION_DETACHED_IDLE` with no reattach; ANY session is
//     reaped after `SESSION_MAX_LIFETIME` regardless. The shell exiting always
//     ends the session immediately.

/// Bytes of recent PTY output retained while detached, for replay on reattach.
/// 256 KiB covers a full-screen TUI redraw plus a scrollback's worth of context
/// without letting an abandoned-but-not-reaped session hoard memory.
pub const SESSION_BUFFER_CAP: usize = 256 * 1024;

/// Terminal-mode reset emitted to the client right AFTER a reattach replay.
/// A TUI that gets cut off mid-run (link drop, then the app dies before it can
/// emit its own disable) leaves the client terminal stuck in mouse-reporting
/// mode: every trackpad move then spews escape codes onto the shell line, which
/// also wedges readline so Ctrl-U / Alt-Backspace stop parsing. Clearing the
/// mouse modes after the replay heals that; a TUI that is STILL alive re-enables
/// the mouse on its next redraw. Deliberately ONLY mouse modes (X10/normal/
/// button/any-motion + SGR + urxvt ext), never cursor-key or keypad modes, so a
/// reattach never disturbs arrow keys.
pub const PTY_REATTACH_RESET: &[u8] = b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l";

/// A detached session (channel dropped, nobody reattached) is reaped after this.
/// Long enough to ride out a mobile network handoff / tab suspend, short enough
/// that a closed laptop does not leave a root shell alive for hours.
pub const SESSION_DETACHED_IDLE: Duration = Duration::from_secs(180);

/// Hard lifetime cap on ANY persistent PTY session, attached or not. A backstop
/// so a wedged or forgotten session cannot live forever.
pub const SESSION_MAX_LIFETIME: Duration = Duration::from_secs(8 * 3600);

/// Where a session sends its PTY output right now: a link's transport + the sid
/// the browser allocated for THIS attach. `None` = detached (buffer only).
struct OutBind {
    transport: Arc<dyn Transport>,
    sid: u32,
}

/// Commands to a session's task: (re)bind output to a new link, detach, or end.
enum SessionCmd {
    Attach { transport: Arc<dyn Transport>, sid: u32 },
    Detach,
    End,
}

/// Handle to one persistent PTY session, stored in the `PtySessions` map. Cloning
/// is cheap (channels + Arcs); the actual shell lives in the spawned task.
#[derive(Clone)]
pub struct PtySessionHandle {
    /// Bytes typed by the user -> PTY master writer thread.
    input_tx: std::sync::mpsc::Sender<Vec<u8>>,
    /// Window-size changes -> PTY master resize.
    resize_tx: mpsc::UnboundedSender<(u16, u16)>,
    /// Attach/detach control -> the session task.
    cmd_tx: mpsc::UnboundedSender<SessionCmd>,
    /// Set once the task observes the shell exit OR a reap, so a stale handle in
    /// the map is recognized as dead and replaced by a fresh spawn.
    dead: Arc<std::sync::atomic::AtomicBool>,
}

impl PtySessionHandle {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }
    pub fn feed_input(&self, bytes: Vec<u8>) {
        let _ = self.input_tx.send(bytes);
    }
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.resize_tx.send((cols, rows));
    }
    /// Rebind output to a new link (transport + sid) and replay the buffer.
    pub fn attach(&self, transport: Arc<dyn Transport>, sid: u32) {
        let _ = self.cmd_tx.send(SessionCmd::Attach { transport, sid });
    }
    /// Drop the current binding; output accrues in the ring until the next attach
    /// or the detached-idle reaper fires.
    pub fn detach(&self) {
        let _ = self.cmd_tx.send(SessionCmd::Detach);
    }
    /// End the session now: kill the shell and tear the task down (the explicit
    /// `pty-close` / user-closed path, NOT a transient channel drop).
    pub fn end(&self) {
        let _ = self.cmd_tx.send(SessionCmd::End);
    }
}

/// Process-wide store of persistent PTY sessions, keyed by the browser-chosen
/// stable session id. Lives for the whole `up`/`recv` process so a session
/// survives any number of link drops/reconnects.
#[derive(Default)]
pub struct PtySessions {
    map: Mutex<HashMap<String, PtySessionHandle>>,
}

impl PtySessions {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Look up a LIVE session by id (a dead/exited one is treated as absent so a
    /// re-open spawns fresh).
    pub async fn get_live(&self, id: &str) -> Option<PtySessionHandle> {
        let mut map = self.map.lock().await;
        match map.get(id) {
            Some(h) if !h.is_dead() => Some(h.clone()),
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    /// Insert a freshly spawned session under `id`.
    pub async fn insert(&self, id: String, h: PtySessionHandle) {
        self.map.lock().await.insert(id, h);
    }

    /// Remove a session by id (the reaper / shell-exit path calls this).
    pub async fn remove(&self, id: &str) {
        self.map.lock().await.remove(id);
    }
}

/// Spawn a brand-new persistent PTY session bound to `(transport, sid)`. Returns
/// a handle to store in `PtySessions`; the shell runs in a detached task that
/// outlives the link. `pty_guard` holds the global PTY slot for the session's
/// whole life. On any failure an `l2-close{err}` is sent on the opening link and
/// `None` is returned (nothing to store).
pub async fn spawn_pty_session(
    sessions: Arc<PtySessions>,
    session_id: String,
    transport: Arc<dyn Transport>,
    sid: u32,
    cols: u16,
    rows: u16,
    term: &str,
    argv: Vec<String>,
    pty_guard: PtyGuard,
) -> Option<PtySessionHandle> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read as _, Write as _};

    let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
    let pair = match native_pty_system().openpty(size) {
        Ok(p) => p,
        Err(e) => {
            let _ = transport.send_control(&json!({ "type": "l2-close", "sid": sid, "err": format!("pty: {e}") })).await;
            return None;
        }
    };
    let mut cmd = CommandBuilder::new(&argv[0]);
    for a in &argv[1..] {
        cmd.arg(a);
    }
    cmd.env("TERM", if term.is_empty() { "xterm-256color" } else { term });
    // Advertise 24-bit color. opentui-based TUIs (e.g. opencode) downgrade to a
    // 256-color palette when COLORTERM is unset; the web-shell xterm.js renders
    // truecolor fine, so set this to get full-color output (verified: opencode
    // emits 38;2;R;G;B with this set, 38;5;N without).
    cmd.env("COLORTERM", "truecolor");
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let mut child = match pair.slave.spawn_command(cmd) {
        Ok(c) => c,
        Err(e) => {
            let _ = transport.send_control(&json!({ "type": "l2-close", "sid": sid, "err": format!("spawn: {e}") })).await;
            return None;
        }
    };
    drop(pair.slave); // close our copy so the shell owns the only slave
    let master = pair.master;
    let mut reader = match master.try_clone_reader() {
        Ok(r) => r,
        Err(_) => return None,
    };
    let mut writer = match master.take_writer() {
        Ok(w) => w,
        Err(_) => return None,
    };

    // Blocking PTY-master reads -> async output channel.
    let (otx, mut orx) = mpsc::channel::<Vec<u8>>(128);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break, // shell exited / PTY closed
                Ok(n) => {
                    if otx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Async input -> blocking PTY-master writes (dedicated thread).
    let (input_tx, wrx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(b) = wrx.recv() {
            if writer.write_all(&b).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    let (resize_tx, mut resize_rx) = mpsc::unbounded_channel::<(u16, u16)>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SessionCmd>();
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let handle = PtySessionHandle {
        input_tx,
        resize_tx,
        cmd_tx,
        dead: dead.clone(),
    };

    // The long-lived session task: it owns the PTY output, the current binding,
    // the replay ring, and the lifetime/idle caps. It outlives every link.
    let sessions_for_task = sessions.clone();
    let session_id_for_task = session_id.clone();
    tokio::spawn(async move {
        let _guard = pty_guard; // freed when the task ends (any exit path)
        let mut bind: Option<OutBind> = Some(OutBind { transport, sid });
        let mut ring: VecDeque<u8> = VecDeque::new();
        let started = Instant::now();
        let mut detached_since: Option<Instant> = None;
        // 5s tick to enforce the idle/lifetime caps without busy-waiting.
        let mut reaper = tokio::time::interval(Duration::from_secs(5));
        reaper.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                out = orx.recv() => match out {
                    Some(bytes) => {
                        push_ring(&mut ring, &bytes, SESSION_BUFFER_CAP);
                        if let Some(b) = &bind {
                            for chunk in bytes.chunks(b.transport.max_payload().max(1)) {
                                if b.transport.send_frame(b.sid, chunk).await.is_err() {
                                    // The link died under us; treat as a detach so
                                    // output keeps buffering for a reattach.
                                    detached_since = Some(Instant::now());
                                    bind = None;
                                    break;
                                }
                            }
                        }
                    }
                    None => break, // shell exited
                },
                cmd = cmd_rx.recv() => match cmd {
                    Some(SessionCmd::Attach { transport, sid }) => {
                        // Replay the buffered output to the freshly attached link
                        // so the user sees the shell exactly as it stands now.
                        let snapshot: Vec<u8> = ring.iter().copied().collect();
                        let mp = transport.max_payload().max(1);
                        let mut ok = true;
                        for chunk in snapshot.chunks(mp) {
                            if transport.send_frame(sid, chunk).await.is_err() {
                                ok = false;
                                break;
                            }
                        }
                        // Heal a mouse-reporting mode a cut-off TUI left stuck on
                        // the client (see PTY_REATTACH_RESET): sent after the
                        // replay so it is the last word on terminal state.
                        if ok && transport.send_frame(sid, PTY_REATTACH_RESET).await.is_err() {
                            ok = false;
                        }
                        if ok {
                            bind = Some(OutBind { transport, sid });
                            detached_since = None;
                        } else {
                            detached_since = Some(Instant::now());
                            bind = None;
                        }
                    }
                    Some(SessionCmd::Detach) => {
                        bind = None;
                        detached_since = Some(Instant::now());
                    }
                    Some(SessionCmd::End) => break, // explicit close: kill the shell
                    None => break, // all handles dropped (store removed): tear down
                },
                rs = resize_rx.recv() => {
                    if let Some((c, r)) = rs {
                        let _ = master.resize(PtySize { rows: r.max(1), cols: c.max(1), pixel_width: 0, pixel_height: 0 });
                    }
                }
                _ = reaper.tick() => {
                    let lifetime_up = started.elapsed() >= SESSION_MAX_LIFETIME;
                    let idle_up = detached_since
                        .map(|t| t.elapsed() >= SESSION_DETACHED_IDLE)
                        .unwrap_or(false);
                    if lifetime_up || idle_up {
                        break;
                    }
                }
            }
        }

        // Teardown (shell exit, reap, or store removal): kill the shell, tell the
        // currently-attached link (if any) the session ended, drop from the store.
        let _ = child.kill();
        let _ = child.wait();
        dead.store(true, Ordering::Release);
        if let Some(b) = &bind {
            let _ = b.transport.send_control(&json!({ "type": "l2-close", "sid": b.sid })).await;
        }
        sessions_for_task.remove(&session_id_for_task).await;
    });

    sessions.insert(session_id, handle.clone()).await;
    Some(handle)
}

/// Append `bytes` to the replay ring, evicting from the front so it never exceeds
/// `cap`. A single write larger than `cap` keeps only its trailing `cap` bytes
/// (the most recent screen state is what matters for replay).
fn push_ring(ring: &mut VecDeque<u8>, bytes: &[u8], cap: usize) {
    if bytes.len() >= cap {
        ring.clear();
        ring.extend(&bytes[bytes.len() - cap..]);
        return;
    }
    ring.extend(bytes);
    while ring.len() > cap {
        ring.pop_front();
    }
}

// ------------------------------------------------------------- ACCEPTOR side --

/// Decision for an inbound `l2-open`, made synchronously in the event loop
/// BEFORE any await, so the pipe is registered before a data frame for this sid
/// can be processed (closes the early-frame-drop race, design §3.4).
pub enum OpenVerdict {
    /// Accepted: dial this localhost target and relay. Carries the pre-registered
    /// inbound pipe.
    Accept { sid: u32, host: String, port: u16, rx: mpsc::Receiver<PipeItem> },
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
    pub async fn accept_control(&self, v: &Value, trusted: bool, allow_nonloopback: bool) -> OpenVerdict {
        match v["type"].as_str() {
            Some("l2-open") => {
                let Some(sid) = v["sid"].as_u64().map(|s| s as u32) else {
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
                // The whole L2 acceptor stays OFF unless FILAMENT_L2=1 (opt-in).

                let host = v["host"].as_str().unwrap_or("127.0.0.1").to_string();
                let port = v["rport"].as_u64().or_else(|| v["port"].as_u64()).unwrap_or(0) as u16;
                if port == 0 {
                    return OpenVerdict::Deny { sid, err: "bad port" };
                }
                // ---- SSRF defense: localhost-only by default ----
                // Stricter than is_private_addr (which ALLOWS LAN/RFC1918): the
                // dial target must resolve to loopback. A non-loopback host is
                // refused UNLESS the caller's opt-in per-device allowlist
                // (l2-allow.json) authorized this exact target (`allow_nonloopback`).
                if !host_is_loopback(&host) && !allow_nonloopback {
                    return OpenVerdict::Deny { sid, err: "non-loopback denied (not in l2-allow.json)" };
                }
                // H-1 (DoS): cap concurrent streams per link. A flaky/hostile
                // paired device can otherwise flood `l2-open` and exhaust
                // sockets/threads. We drop the `accepted` marker so the same sid
                // can be retried once others free up.
                if self.at_stream_cap().await {
                    self.accepted.lock().await.remove(&sid);
                    return OpenVerdict::Deny { sid, err: "too many streams" };
                }
                let rx = self.register(sid).await; // BEFORE the async dial
                OpenVerdict::Accept { sid, host, port, rx }
            }
            Some("l2-close") => {
                if let Some(sid) = v["sid"].as_u64() {
                    self.on_close(sid as u32, v["err"].as_str()).await;
                }
                OpenVerdict::Ignore
            }
            _ => OpenVerdict::Ignore,
        }
    }

    /// Acceptor: dial the localhost target for an accepted open and relay. Sends
    /// l2-open-ack on success, l2-close{err} on dial failure. Runs as its own
    /// task (the event loop spawns it) so the dial never blocks routing.
    pub async fn dial_and_serve(self: Arc<Self>, sid: u32, host: String, port: u16, rx: mpsc::Receiver<PipeItem>) {
        match TcpStream::connect((host.as_str(), port)).await {
            Ok(sock) => {
                let _ = sock.set_nodelay(true);
                // l2-open-ack is mandatory (design §3.4/O2): it tells the
                // initiator the stream is live. credit-in-ack is the follow-up
                // (TODO(credits)); 0 here means "no per-stream window yet".
                let _ = self
                    .transport
                    .send_control(&json!({ "type": "l2-open-ack", "sid": sid, "credit": 0 }))
                    .await;
                serve_stream(self.clone(), sid, sock, rx, true).await;
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
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

// ------------------------------------------------------------ INITIATOR side --

/// Holds the signaling client + WebRTC peer that back a brought-up link so the
/// CALLER decides their fate. A long-lived consumer (netcat/forward) calls
/// `forget()` to keep the link alive for the process lifetime (byte-identical to
/// the old `std::mem::forget`). A short-lived consumer (the shell bootstrap)
/// calls `close().await` to TEAR THE LINK DOWN before opening a second link to
/// the same device, otherwise the acceptor sees two same-device peers at once
/// and its C6 supersede/adopt logic churns (one link gets dropped mid-use).
pub struct LinkGuard {
    sio: Option<rust_socketio::asynchronous::Client>,
    peer: Option<Arc<Peer>>,
}

impl LinkGuard {
    /// Keep the link alive forever (leaks sio+peer, as the long-lived tunnels
    /// want). Consumes the guard.
    fn forget(mut self) {
        if let Some(sio) = self.sio.take() {
            std::mem::forget(sio);
        }
        if let Some(p) = self.peer.take() {
            std::mem::forget(p);
        }
    }

    /// Cleanly close the link: drop the WebRTC peer connection and disconnect
    /// signaling, so the acceptor reaps this peer promptly. Consumes the guard.
    async fn close(mut self) {
        if let Some(p) = self.peer.take() {
            p.close().await;
        }
        if let Some(sio) = self.sio.take() {
            let _ = sio.disconnect().await;
        }
    }
}

/// Minimal identity-mode link bring-up to a *known* device, mirroring the
/// production send/recv path but stripped to exactly what L2 needs: join a solo
/// room, subscribe to the device's presence channel, dial it when it appears,
/// and prove our identity (pair-proof) so its `up`/`recv` marks us trusted,
/// which is what unlocks the acceptor's capability gate. Returns the ready
/// Transport, the event receiver, and a `LinkGuard` the caller must either
/// `forget()` (keep alive) or `close().await` (tear down).
async fn bring_up_to_known(
    server: &str,
    peer_name: &str,
    relay: bool,
    role: &'static str,
) -> Result<(Arc<dyn Transport>, mpsc::UnboundedReceiver<Ev>, LinkGuard, crate::diag::Attempt)> {
    let secret = crate::devices_load()
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(peer_name))
        .map(|(_, s)| s)
        .ok_or_else(|| anyhow!("no known device named '{peer_name}', run `filament pair` first (see `filament devices`)"))?;
    let channel = crate::channel_of(&secret);

    // Establishment telemetry: a connect span, peer tagged by SHORT HASH (never
    // the petname). The Attempt is returned to the caller so it can record the
    // L2Open round trip and the final `up`. We start in Signaling (socket + the
    // first `welcome`); the loop drives the phase transitions below.
    let mut diag = crate::diag::Attempt::new(server, &crate::diag::peer_hash_from_secret(&secret), role);
    // Latch so we record the Presence->Establishing transition exactly once
    // (the loop dequeues a candidate every time `peer` is idle, but the connect
    // lifecycle's "establishing" begins at the FIRST candidate).
    let mut entered_establishing = false;

    let cfg = net::fetch_config(server).await?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let mut sio = net::connect_signaling(server, tx.clone()).await?;

    let my_uid = crate::mk_uid("l2");
    // A solo room keeps strangers out; presence-channel subscription is how we
    // actually find the known device (same as `--to` identity mode).
    let solo = format!("l2-{}", crate::fresh_secret());
    let join_payload =
        json!({ "room": solo, "uid": my_uid, "name": crate::display_name() });
    sio.emit("join", join_payload.clone()).await.ok();
    // NOTE: subscribe is emitted on Ev::Welcome (below), not here, `welcome` is
    // the proof the socket.io connection is fully established, so the subscribe
    // can't be lost in the connect->emit race that intermittently left the client
    // unsubscribed and "waiting for known device" forever (harness finding).
    //
    // The `join` ABOVE has the SAME connect->emit race: fired the instant
    // `connect_signaling` returns, it can land before the socket.io connection is
    // fully ready and be silently dropped, the server then never runs `_do_join`,
    // never emits `welcome`, and this loop waits for a Welcome that never comes,
    // stranding `filament ssh` in "waiting for known device" (~30% of attempts in
    // the isolated repro). So we RE-EMIT join on the same cadence as the
    // re-subscribe below until Welcome lands (idempotent: a repeat join to the
    // same solo room is a no-op server-side once it took).

    let mut my_id: Option<String> = None;
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_uid: Option<String> = None;
    let mut generation: u32 = 0;
    // Ghost tolerance: the channel can hold DEAD sids (a SIGKILL'd process
    // lingers until the server's ping-timeout) and WRONG peers (our own up
    // subscribes the same pair channel). Locking onto the first known-peer
    // forever was the dominant stall. Instead: one candidate AT A TIME (a
    // parallel race glares, proven, see multicandidate-attempt.patch), a
    // short per-candidate timer, and rotation through everything seen.
    let mut queue: VecDeque<(String, Option<String>)> = VecDeque::new();
    // Per-candidate establish budget for the INTERACTIVE L2/ssh path: how long a
    // single candidate gets to complete (WebRTC + direct-QUIC race) before it is
    // declared Stuck and we rotate to the next. This is a TIMEOUT, not the
    // connect time: a healthy candidate completes in 1.7-3.3s regardless, so a
    // larger budget never slows a good path, it only stops abandoning a real one
    // too early.
    //
    // It was briefly tightened to 4s chasing Tailscale's sub-5s connect, but 4s
    // is BELOW the time a legitimately slow-but-real ICE needs (~5s, e.g. a
    // cross-NAT path that nominates a srflx/relay pair): the budget fired before
    // the real candidate finished, every rotation got cut at 4s, and the link
    // never came up ("establishment timed out", reproduced live as a consistent
    // pop-os -> do-vm failure that 7s/12s established cleanly). Back to 7s, which
    // clears the real ICE time with margin; field-overridable via
    // FILAMENT_L2_CANDIDATE_SECS.
    let candidate_secs: u64 = std::env::var("FILAMENT_L2_CANDIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(7);
    // Item 3: the L2 initiator races a DIRECT-QUIC dial against WebRTC. On
    // KnownPeer we bind a quinn endpoint + advertise our candidates (mirrors
    // `start_direct` in main.rs); when the peer's transport-offer arrives we
    // consume this endpoint into the race. UNCONDITIONAL here: `bring_up_to_known`
    // only ever serves L2 (netcat/ssh/forward), which always wants direct, and
    // `filament ssh`/`netcat` do NOT set FILAMENT_L2 in their own env, so gating
    // on `direct_enabled()` would kill the direct dial on the live path. main.rs
    // gates because it ALSO serves file transfer; this function never does.
    let mut endpoint: Option<quinn::Endpoint> = None;
    // Candidates gathered once at first bind; re-advertised to each new
    // candidate peer we rotate to (the endpoint accepts from any of them,
    // the QUIC race is pair-secret-authenticated either way).
    let mut direct_cands: Option<Vec<String>> = None;
    // The acceptor re-sends its transport-offer (a late initiator can miss the
    // first). Race only the FIRST offer we get; later re-sends are duplicates.
    let mut direct_racing = false;

    let spawn_timer = |pid: String, g: u32| {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(candidate_secs)).await;
            let _ = tx.send(Ev::Stuck(pid, g));
        });
    };

    // Distinct wording for the shell-auth pre-flight so the two sequential
    // bring-ups of `filament ssh` (the bootstrap link, then the netcat data link)
    // do not read as a flap/retry of one connection.
    crate::ui::say(&match role {
        "bootstrap" => format!("filament: authenticating with '{peer_name}'..."),
        _ => format!("filament: waiting for known device '{peer_name}'..."),
    });

    // Presence re-subscribe cadence: while we have NOT yet discovered a candidate
    // (empty queue, no live peer), re-emit the ack'd subscribe every ~2s. This
    // recovers the inverse of the ack-roster race, the acceptor that subscribes
    // AFTER us, whose single async `known-peer` push to us is lost. The `up`
    // acceptor gets this self-healing free from its `sync` tick; the one-shot L2
    // initiator needs it explicitly or a lost push strands it in "presence"
    // forever. Cheap (one emit) and idempotent, and it STOPS the instant a
    // candidate is queued/dialing, so a healthy connect never re-subscribes.
    let mut resubscribe = tokio::time::interval(Duration::from_millis(2000));
    resubscribe.tick().await; // consume the immediate first tick (we just subscribed on Welcome)
    // How many re-join ticks we've waited with NO Welcome. rust_socketio's
    // websocket client occasionally finishes `.connect().await` in a state where
    // it can SEND but silently never DELIVERS inbound events to our handlers: the
    // server receives our `join` (and re-emits `welcome` on every retry, verified
    // in the backend telemetry) but this loop never sees `Ev::Welcome`, so it
    // hangs in "waiting for known device" no matter how many times we re-join the
    // SAME dead socket (the residual ~30% rapid-`ssh` failure). Re-emitting can't
    // fix a socket that won't receive, so after a couple of silent ticks we tear
    // the socket DOWN and dial a FRESH one (reconnect_signaling) on the same `tx`.
    let mut welcome_silent_ticks: u32 = 0;

    loop {
        // One candidate at a time: start the next attempt whenever idle.
        if peer.is_none() {
            if let Some((pid, uid)) = queue.pop_front() {
                // A candidate appeared and we are dialing it: presence is done,
                // we are now in the Establishing (WebRTC + direct-QUIC race)
                // phase. Latched so re-dials of later candidates don't re-emit.
                if !entered_establishing {
                    diag.enter(crate::diag::Phase::Establishing);
                    entered_establishing = true;
                }
                let mine = my_id.clone().unwrap_or_default();
                let polite = net::polite_role(&my_uid, uid.as_deref(), &mine, &pid);
                generation += 1;
                spawn_timer(pid.clone(), generation);
                let p = Peer::connect(
                    pid.clone(), polite, cfg.ice_servers.clone(), relay,
                    sio.clone(), tx.clone(), generation,
                )
                .await?;
                peer_uid = uid;
                peer = Some(p);

                // Item 3: also start a DIRECT-QUIC attempt racing the WebRTC
                // dial. Bind once, advertise to whichever candidate is current
                // (mirrors `start_direct`); the peer's own offer drives the
                // race (handled in Ev::Signal below).
                if !direct_racing {
                    if endpoint.is_none() {
                        match crate::direct::bind_endpoint() {
                            Ok((ep, port)) => {
                                direct_cands =
                                    Some(crate::direct::gather_candidates(server, port).await);
                                endpoint = Some(ep);
                                // TRACE, direct-offer detail.
                                crate::ui::trace(&format!("filament: DIRECT-OFFER sent to '{peer_name}', port {port}"));
                            }
                            Err(e) => {
                                crate::ui::trace(&format!("filament: direct disabled (endpoint bind failed: {e}), WebRTC only"));
                            }
                        }
                    }
                    if endpoint.is_some() {
                        if let Some(c) = &direct_cands {
                            let offer =
                                json!({ "type": "transport-offer", "v": 1, "addrs": c });
                            sio.emit("signal", json!({ "to": pid, "data": offer })).await.ok();
                        }
                    }
                }
            }
        }
        let ev = tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => break,
            },
            _ = resubscribe.tick() => {
                if my_id.is_none() {
                    // No Welcome yet. Re-emit the `join` once (it may have raced the
                    // socket-ready and been dropped server-bound); but if the socket
                    // stays silent across a couple of ticks the socket itself is
                    // RECEIVE-dead, so dial a fresh one and re-join on it.
                    welcome_silent_ticks += 1;
                    if welcome_silent_ticks >= 2 {
                        welcome_silent_ticks = 0;
                        if let Ok(fresh) = net::reconnect_signaling(server, tx.clone()).await {
                            let _ = sio.disconnect().await;
                            sio = fresh;
                        }
                    }
                    sio.emit("join", join_payload.clone()).await.ok();
                } else if peer.is_none() && queue.is_empty() {
                    // Welcome landed but no candidate found yet: re-subscribe so a
                    // lost `known-peer` push / a late-appearing acceptor is still
                    // discovered. Stops the instant a candidate is queued/dialing.
                    net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
                }
                continue;
            }
        };
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(|s| s.to_string());
                // Signaling is live (socket + welcome); we now subscribe and wait
                // for the known device to appear, that is the Presence phase.
                diag.enter(crate::diag::Phase::Presence);
                // Subscribe now that the connection is confirmed (see the note at
                // the join site). DETERMINISTIC discovery: emit-with-ack and read
                // the roster the server returns synchronously, so a known device
                // already present is found even if its one-shot async `known-peer`
                // push is lost (the dominant presence stall, see
                // `net::subscribe_with_ack`). The periodic re-subscribe below
                // covers the inverse race (the acceptor appearing AFTER us).
                net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
            }
            Ev::KnownPeer(v) => {
                if v["channel"].as_str() != Some(channel.as_str()) {
                    continue;
                }
                let pid = match v["id"].as_str() {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                if Some(pid.as_str()) == my_id.as_deref() {
                    continue;
                }
                // #9: never dial our OWN install (the up subscribes this pair
                // channel too). Pair secrets are symmetric, so a self-connect
                // can pass the pair-proof and tunnel into the WRONG host's
                // sshd, the local daemon answering as the remote device.
                if crate::is_self_uid(&my_uid, v["uid"].as_str()) {
                    continue;
                }
                // Queue every distinct sid; the loop top rotates through them.
                if peer.as_ref().is_some_and(|p| p.id == pid)
                    || queue.iter().any(|(q, _)| *q == pid)
                {
                    continue;
                }
                queue.push_back((pid, v["uid"].as_str().map(|s| s.to_string())));
            }
            Ev::Signal(v) => {
                let data = v["data"].clone();
                // Item 3: a relayed `transport-offer` carries the peer's direct
                // candidates. Do NOT hand it to the WebRTC `Peer`; instead consume
                // our endpoint and spawn the simultaneous-open + auth race
                // (`race_connect_labeled`, the same primitive `start_direct`
                // drives). The winner posts Ev::DirectReady into THIS loop's tx,
                // so the DirectTransport's reader funnels Chunk/Control/PcState to
                // the rx the caller hands to `pump_initiator`.
                if data["type"].as_str() == Some("transport-offer") {
                    if direct_racing {
                        continue; // already racing the first offer; ignore re-sends
                    }
                    // Bind on-demand if the offer beat our own KnownPeer: on real
                    // WAN the already-running acceptor fires its offer the instant
                    // we appear, which can arrive BEFORE our presence event sets
                    // `endpoint`. The old `if let Some` silently DROPPED it and we
                    // never dialed (the cross-machine stall). We DIAL the peer's
                    // candidates, so we don't need to have sent our own offer first.
                    let ep = endpoint
                        .take()
                        .or_else(|| crate::direct::bind_endpoint().ok().map(|(ep, _)| ep));
                    if let Some(ep) = ep {
                        direct_racing = true;
                        let peer_cands: Vec<String> = data["addrs"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        // DEBUG, resilience/direct internal (racing a direct path).
                        crate::ui::debug(&format!(
                            "filament: got transport-offer ({} cand), racing direct-quic",
                            peer_cands.len()
                        ));
                        let secret = secret.clone();
                        let pid = v["from"].as_str().unwrap_or_default().to_string();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Some(t) = crate::direct::race_connect_labeled(
                                // answerer=false: this is bring_up (the connector
                                // side), so it allocates the low L2 sid half.
                                ep, peer_cands, &secret, pid.clone(), tx.clone(), "direct-quic", false,
                            )
                            .await
                            {
                                let _ = tx.send(Ev::DirectReady(pid, t, "direct-quic"));
                            }
                            // On None the WebRTC path (Ev::ChannelReady) continues.
                        });
                    }
                    continue;
                }
                // Route by sender: the channel is multi-party (our own up
                // subscribes it too, plus lingering dead sids), a stray offer
                // applied to the current pc was a reliable glare generator.
                let from = v["from"].as_str().unwrap_or_default();
                let Some(p) = &peer else { continue };
                if p.id != from {
                    continue;
                }
                match p.handle_signal(data).await {
                    Ok(net::SignalOutcome::Handled) => {}
                    Ok(net::SignalOutcome::Glare(offer)) => {
                        // Both sides offered (role confusion). Yield: rebuild
                        // this attempt as a pure responder answering theirs.
                        let old = peer.take().unwrap();
                        let pid = old.id.clone();
                        old.mark_closed();
                        tokio::spawn(async move { old.close().await });
                        generation += 1;
                        spawn_timer(pid.clone(), generation);
                        let p = Peer::connect(
                            pid, true, cfg.ice_servers.clone(), relay,
                            sio.clone(), tx.clone(), generation,
                        )
                        .await?;
                        if let Err(e) = p.handle_signal(offer).await {
                            crate::ui::trace(&format!("filament: signal: {e}"));
                        }
                        peer = Some(p);
                    }
                    Err(e) => crate::ui::trace(&format!("filament: signal: {e}")),
                }
            }
            Ev::DirectReady(_pid, t, route) => {
                // Item 3: the DIRECT-QUIC race won before WebRTC. The acceptor's
                // `adopt_direct` (main.rs) is born `trusted: true` + identity-bound
                // `verified_name`, its pair-secret MAC already proved who we are,
                // so the cap gate is satisfied WITHOUT a pair-proof. We deliberately
                // do NOT replicate the ChannelReady proof here: that MAC is built
                // from the WebRTC DTLS fingerprints, which a direct QUIC link does
                // not have, and the acceptor's direct link (`peer: None`) has none
                // to verify against. (design-l2-direct-ladder.md §NOTE: pre-trust
                // OR pair-proof, we confirmed pre-trust holds for the L2 acceptor.)
                // INFO, tunnel established (with its route label). Silent for the
                // bootstrap pre-flight (internal; the data link reports the route).
                if role != "bootstrap" {
                    crate::ui::say(&format!("filament: tunnel up to '{peer_name}' (route: {route})"));
                }
                // Transport is up: the Establishing race is won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                // The WebRTC `peer` is now superfluous; the guard owns it (its
                // teardown/forget semantics are unchanged, no extra teardown).
                let guard = LinkGuard { sio: Some(sio), peer: peer.take() };
                return Ok((t, rx, guard, diag));
            }
            Ev::Stuck(pid, g) => {
                // Per-candidate timer (or the 15s watchdog) fired for the
                // CURRENT attempt: drop it and rotate. The sid goes to the
                // back of the queue, a slow-but-real peer gets retried, a
                // ghost just cycles until the server evicts it.
                if g == generation && peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    // The per-candidate establish budget fired: this candidate
                    // wedged and we rotate. Record a stall (the "burns the budget
                    // then succeeds on retry" signal we are hunting).
                    diag.stall(crate::diag::Phase::Establishing, candidate_secs * 1000);
                    crate::ui::debug("filament: candidate unresponsive, rotating");
                    queue.push_back((pid, peer_uid.take()));
                }
            }
            Ev::ChannelReady(pid, t) if peer.as_ref().is_some_and(|p| p.id == pid) => {
                // Prove identity so the peer's up/recv marks this link trusted,
                // the acceptor's capability gate keys on exactly that.
                if let Some(p) = &peer {
                    if let Some((my_fp, their_fp)) = p.fingerprints().await {
                        let mac = crate::proof_for(
                            &secret, &my_uid, &my_uid,
                            peer_uid.as_deref().unwrap_or(""), &my_fp, &their_fp,
                        );
                        t.send_control(&json!({ "type": "pair-proof", "mac": mac })).await?;
                    }
                }
                // Hand sio + peer to the caller via a guard: a long-lived tunnel
                // `forget()`s it (keep alive); the bootstrap `close().await`s it
                // (tear down before the second link).
                if role != "bootstrap" {
                    crate::ui::say(&format!("filament: tunnel up to '{peer_name}'"));
                }
                // Transport is up via WebRTC: Establishing race won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                let guard = LinkGuard { sio: Some(sio), peer: peer.take() };
                return Ok((t, rx, guard, diag));
            }
            Ev::PcState(pid, s) if s == "failed" || s == "closed" => {
                // Was fatal; now just rotate, the overall command timeout
                // (or the user) bounds how long we keep trying.
                if peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    crate::ui::debug(&format!("filament: connection {s}, rotating"));
                    queue.push_back((pid, peer_uid.take()));
                }
            }
            _ => {}
        }
    }
    diag.fail("signaling ended before a data channel came up");
    Err(anyhow!("signaling ended before a data channel came up"))
}

// ------------------------------------------------------------- DOCTOR PROBE --
//
// `filament doctor <device>` drives this: an "establish then drop" probe that
// runs the EXACT same bring-up as netcat (`bring_up_to_known` with role
// "doctor"), opens one L2 stream so the L2Open round trip is exercised, then
// IMMEDIATELY tears the link down. It never opens a shell or moves payload. The
// point is to surface WHERE establishment is slow or stalls, using the same
// `Attempt` instrumentation (phases + budgets) a real connect uses, so the
// ladder a probe prints matches what a live ssh would have hit.

/// The result of one `establish_probe`: the per-phase ladder (reused verbatim
/// from the `Attempt`), the total span time, and the terminal verdict.
pub struct ProbeOutcome {
    /// Per-phase timings, in completion order (signaling, presence, ...). Each
    /// carries its over-budget flag, computed by `diag::over_budget`.
    pub timings: Vec<crate::diag::PhaseTiming>,
    /// Total establish time, signaling start to link usable.
    pub total_ms: u64,
    /// True iff the link came up. On `false`, `failed_phase` says where it died.
    pub established: bool,
    /// On failure, the phase the bring-up was IN when it gave up.
    pub failed_phase: Option<crate::diag::Phase>,
    /// On failure, the error string.
    pub error: Option<String>,
}

/// Establish a link to `peer` exactly as netcat would, then drop it. Returns the
/// per-phase timings + verdict. Reuses `bring_up_to_known` (role "doctor"), so
/// the phases/budgets are identical to a real connect, and cleans up BOTH the
/// link (LinkGuard::close) and the mux (no leaked streams/pumps).
pub async fn establish_probe(server: &str, peer: &str, relay: bool) -> Result<ProbeOutcome> {
    // Overall safety bound so a wedged candidate cannot hang the probe forever
    // (the per-candidate rotation already re-races inside bring_up_to_known; this
    // is the outer wall). Generous: a slow-but-real ICE lands around 5s and we
    // want to OBSERVE that, not abort it prematurely. Overridable for the field.
    let probe_secs: u64 = std::env::var("FILAMENT_DOCTOR_PROBE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(30);
    let deadline = std::time::Duration::from_secs(probe_secs);

    match tokio::time::timeout(deadline, bring_up_to_known(server, peer, relay, "doctor")).await {
        Ok(Ok((t, rx, guard, mut diag))) => {
            // The link is up (Ready recorded). Exercise the L2Open round trip the
            // same way netcat does: pump inbound events, open one stream (sends
            // l2-open), record `up`. We do NOT wait on payload; the open is the
            // last establishment rung we care about.
            let mux = Mux::new(t);
            let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

            diag.enter(crate::diag::Phase::L2Open);
            // rport is irrelevant for the timing: the acceptor dials localhost:0
            // and refuses, but the l2-open / l2-close round trip is what we time.
            // Use a benign port and tear the stream down immediately afterwards.
            let probe_rport: u16 = 9; // discard
            let (sid, _rx_pipe) = open_stream(&mux, probe_rport).await?;
            diag.up("tunnel", "datachannel-or-direct");

            // Tear DOWN, no leak: drop the stream, tell the peer, stop the pump,
            // and close the link (peer + signaling), so the acceptor reaps us.
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            mux.shutdown_all().await;
            pump.abort();
            guard.close().await;

            Ok(ProbeOutcome {
                timings: diag.timings().to_vec(),
                total_ms: diag.total_ms(),
                established: true,
                failed_phase: None,
                error: None,
            })
        }
        Ok(Err(e)) => {
            // bring_up_to_known recorded `fail` on its (now-consumed) Attempt and
            // wrote the partial ladder to the JSONL. Read it back so the verdict
            // can name where it died, the SAME timings a live connect recorded.
            let (timings, failed_phase) = match crate::diag::latest_span_ladder() {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: 0,
                established: false,
                failed_phase,
                error: Some(e.to_string()),
            })
        }
        Err(_elapsed) => {
            // The outer wall fired: the bring-up is still running (the Attempt was
            // never returned). Recover whatever ladder it logged so far.
            let (timings, failed_phase) = match crate::diag::latest_span_ladder() {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: probe_secs * 1000,
                established: false,
                failed_phase,
                error: Some(format!("establishment timed out after {probe_secs}s")),
            })
        }
    }
}

/// Drive the initiator's inbound event pump: route L2 control/data into the mux
/// and tear everything down on data-channel death. The initiator never accepts
/// inbound opens (it allocates ids); an l2-open-ack unparks nothing today (no
/// credits) but is consumed so the protocol stays honest.
async fn pump_initiator(mut rx: mpsc::UnboundedReceiver<Ev>, mux: Arc<Mux>) {
    while let Some(ev) = rx.recv().await {
        match ev {
            Ev::Control(_pid, v) => match v["type"].as_str() {
                Some("l2-close") => {
                    if let Some(sid) = v["sid"].as_u64() {
                        mux.on_close(sid as u32, v["err"].as_str()).await;
                    }
                }
                Some("l2-open-ack") => { /* TODO(credits): seed the send window */ }
                _ => {}
            },
            Ev::Chunk(_pid, sid, data) if is_l2_sid(sid) => {
                mux.on_frame(sid, data).await;
            }
            Ev::PcState(_, s) if s == "failed" || s == "closed" || s == "disconnected" => {
                crate::ui::debug(&format!("filament: tunnel {s}, closing streams"));
                mux.shutdown_all().await;
            }
            _ => {}
        }
    }
    mux.shutdown_all().await;
}

/// Open one stream to `peer:rport`, sending l2-open and waiting (briefly) until
/// the inbound pipe is wired. Returns the registered receiver. The initiator
/// registers its OWN pipe up front so a server-speaks-first protocol (ssh
/// banner) can't lose bytes.
pub(crate) async fn open_stream(mux: &Arc<Mux>, rport: u16) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    let rx = mux.register(sid).await;
    // The dial target is ALWAYS 127.0.0.1 in production (localhost-only is the
    // contract). FILAMENT_L2_DIALHOST is a TEST-ONLY override so the SSRF gate
    // can drive a non-loopback open and observe the acceptor refuse it.
    let host = std::env::var("FILAMENT_L2_DIALHOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    mux.transport
        .send_control(&json!({ "type": "l2-open", "sid": sid, "host": host, "rport": rport }))
        .await?;
    Ok((sid, rx))
}

/// WARM pty (daemon side): open a PTY on the peer over an EXISTING link's `mux`,
/// sending `pty-open` (vs `open_stream`'s `l2-open`). Returns the sid + inbound
/// pipe; the caller bridges with `serve_opened_stream` and relays `pty-resize` by
/// the sid. `session` keys the peer's persistent PTY so a reconnect reattaches.
/// The remote acceptor serves this exactly as a cold `pty-open`.
pub(crate) async fn open_pty_stream(
    mux: &Arc<Mux>,
    session: &str,
    cols: u16,
    rows: u16,
    term: &str,
) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    let rx = mux.register(sid).await;
    mux.transport
        .send_control(&json!({
            "type": "pty-open", "sid": sid, "session": session, "cols": cols, "rows": rows, "term": term
        }))
        .await?;
    Ok((sid, rx))
}

/// Bridge an already-opened L2 stream (`sid` + its inbound `rx`) to a local
/// `stream` (the warm pty client's unix socket), running to completion (stream
/// EOF or peer FIN). The daemon's warm-pty path uses this after `open_pty_stream`.
#[cfg(unix)]
pub(crate) async fn serve_opened_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    stream: S,
    rx: mpsc::Receiver<PipeItem>,
) {
    serve_stream(mux, sid, stream, rx, true).await;
}

/// WARM-LINK REUSE (daemon side): open a NEW L2 stream to `rport` over an
/// EXISTING peer link (its `mux`) and bridge it to a local `stream` (a unix
/// socket from a sibling `filament netcat`/`ssh`/`forward` process). This is the
/// same initiator primitive netcat uses (`open_stream` + `serve_stream`), but the
/// bytes ride a unix socket instead of stdio, and the underlying QUIC/DC link is
/// the daemon's already-established one, so signaling + establishment are skipped
/// entirely. The remote acceptor is UNCHANGED: it serves this `l2-open` exactly
/// as it serves a cold one. Unix-only (the control socket is a unix-domain socket).
#[cfg(unix)]
pub(crate) async fn serve_local_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    rport: u16,
    stream: S,
) -> Result<()> {
    let (sid, rx_pipe) = open_stream(&mux, rport).await?;
    serve_stream(mux, sid, stream, rx_pipe, true).await;
    Ok(())
}

/// Pump this process's stdio over a connected warm-reuse socket: stdin -> sock,
/// sock -> stdout. Exit when the remote half closes (sock read EOF), the same
/// "session over" semantics the cold netcat path has; then abort the stdin pump.
#[cfg(unix)]
async fn pump_stdio_over(sock: tokio::net::UnixStream) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    let writer = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut wr).await; // local EOF
        let _ = wr.shutdown().await; // half-close so the remote sees our EOF
    });
    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut rd, &mut stdout).await?;
    let _ = stdout.flush().await;
    writer.abort();
    Ok(())
}

/// `filament netcat <peer> <rport>`: wire this process's stdio to one L2 stream.
/// This is the ssh ProxyCommand primitive.
pub async fn netcat_cmd(server: &str, peer: &str, rport: u16, relay: bool) -> Result<()> {
    // WARM-LINK FAST PATH: if a local `up` daemon already holds a link to `peer`,
    // ride it (no signaling, no establishment, ~1s saved). Skipped under --relay
    // (the user forced a relay path; a warm link may be direct) and self-heals: any
    // miss / no daemon / dead stream falls through to a fresh establish below.
    // Unix-only: the control socket is a unix-domain socket (no-op elsewhere).
    #[cfg(unix)]
    if !relay {
        if let Some(sock) = crate::ctl::try_open(peer, rport).await {
            crate::ui::trace(&format!("filament: reusing warm link to '{peer}' (no establish)"));
            return pump_stdio_over(sock).await;
        }
    }
    let (t, rx, guard, mut diag) = bring_up_to_known(server, peer, relay, "init").await?;
    guard.forget(); // long-lived tunnel, keep the link alive for the process
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    // L2Open round trip: open the stream and wait for the acceptor's l2-open-ack
    // (the stream-is-live confirmation) before declaring the link Up. The ack is
    // consumed by pump_initiator, so we instead wait for the FIRST inbound byte
    // or a bounded grace, the practical "stream usable" signal for stdio netcat.
    diag.enter(crate::diag::Phase::L2Open);
    let (sid, mut rx_pipe) = open_stream(&mux, rport).await?;
    // The link is now usable end to end (the ssh handshake will flow). Record
    // `up` with the route label we can infer (the transport carries no route()
    // for a direct link, so we report the generic tunnel transport here).
    diag.up("tunnel", "datachannel-or-direct");

    // stdin -> dc
    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, &[]).await; // local EOF -> FIN
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // dc -> stdout
    let mut stdout = tokio::io::stdout();
    while let Some(item) = rx_pipe.recv().await {
        match item {
            Some(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            None => break, // peer FIN
        }
    }
    let _ = reader.await;
    mux.drop_stream(sid).await;
    let _ = mux
        .transport()
        .send_control(&json!({ "type": "l2-close", "sid": sid }))
        .await;
    pump.abort();
    Ok(())
}

/// RAII guard: put the local terminal in raw mode for an interactive PTY and
/// ALWAYS restore cooked mode on drop (normal exit, error, or `?`). Without raw
/// mode the local tty line-buffers + echoes and swallows control keys, so a
/// remote TUI (claude/opencode/vim/htop) can't receive keystrokes or escape
/// sequences and renders unusable.
struct RawGuard;
impl RawGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard)
    }
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Why a single PTY attach ended.
enum PtyOutcome {
    /// The remote shell exited (acceptor sent `l2-close` while the link was
    /// healthy) — we are DONE, do not reconnect.
    Exited,
    /// The link died under us (transport not alive) — the remote PTY session may
    /// still be alive on the acceptor; reconnect and REATTACH the same session.
    Dropped,
}

/// One attach to the peer's PTY over a freshly-established link: open/reattach the
/// `session_id`, bridge stdio, and return why it ended. Raw mode is owned by the
/// caller (held across reconnects), so this only does size/resize/IO.
#[allow(clippy::too_many_arguments)]
async fn pty_attach_once(
    server: &str,
    peer: &str,
    relay: bool,
    role: &'static str,
    session_id: &str,
    term: &str,
    interactive: bool,
    raw: &mut Option<RawGuard>,
) -> Result<PtyOutcome> {
    let (t, rx, guard, mut diag) = bring_up_to_known(server, peer, relay, role).await?;
    guard.forget();
    let mux = Mux::new(t);
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    diag.enter(crate::diag::Phase::L2Open);
    let sid = mux.alloc_sid();
    let mut rx_pipe = mux.register(sid).await;

    // Real terminal: query the ACTUAL tty size (crossterm asks the tty via
    // ioctl), NOT the COLUMNS/LINES shell vars which are usually unexported and
    // leave a TUI rendering at a stale size. Fall back to env/defaults for a pipe.
    let (cols, rows) = if interactive {
        crossterm::terminal::size().unwrap_or((80, 24))
    } else {
        (
            std::env::var("COLUMNS").ok().and_then(|s| s.parse().ok()).unwrap_or(80u16),
            std::env::var("LINES").ok().and_then(|s| s.parse().ok()).unwrap_or(24u16),
        )
    };
    // `session` makes reconnects REATTACH the same shell (acceptor keys it per
    // verified device); a fresh per-invocation id means two `filament pty` runs
    // never collide. `term` is forwarded so the remote matches THIS terminal.
    mux.transport()
        .send_control(&json!({
            "type": "pty-open", "sid": sid, "session": session_id,
            "cols": cols, "rows": rows, "term": term,
        }))
        .await?;
    diag.up("tunnel", "datachannel-or-direct");

    // Enable raw mode LAZILY, AFTER the establishment status lines have printed in
    // cooked mode (so `\n` still does CR+LF and they don't "staircase"). Held in
    // the caller's scope so it persists across reconnects and is restored on exit.
    // On a reconnect raw is already on; the acceptor's buffer replay redraws the
    // screen cleanly anyway.
    if interactive && raw.is_none() {
        *raw = Some(RawGuard::enable()?);
    }

    // Forward terminal resizes to the remote PTY (acceptor handles `pty-resize`).
    #[cfg(unix)]
    let winch = if interactive {
        let t_resize = mux.transport();
        Some(tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    let _ = t_resize
                        .send_control(&json!({ "type": "pty-resize", "sid": sid, "cols": c, "rows": r }))
                        .await;
                }
            }
        }))
    } else {
        None
    };

    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, &[]).await;
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Stream remote output to stdout. End when the pipe closes (shell exit OR
    // link death) — disambiguated by the transport's liveness. A 2s liveness
    // poll is the backstop for a silent black-hole that never closes the pipe.
    let mut stdout = tokio::io::stdout();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await; // consume the immediate tick
    let dropped;
    loop {
        tokio::select! {
            item = rx_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                }
                // Pipe closed: clean exit (l2-close, link still alive) vs drop.
                _ => { dropped = !mux.transport().is_alive(); break; }
            },
            _ = ticker.tick() => {
                if !mux.transport().is_alive() { dropped = true; break; }
            }
        }
    }

    reader.abort();
    #[cfg(unix)]
    if let Some(w) = winch {
        w.abort();
    }
    mux.drop_stream(sid).await;
    // Only send our own l2-close on a CLEAN exit. On a drop the link is gone and,
    // crucially, an l2-close would tell the acceptor to END the session we want
    // to reattach — so we stay silent and let it buffer for the reattach.
    if !dropped {
        let _ = mux.transport().send_control(&json!({ "type": "l2-close", "sid": sid })).await;
    }
    pump.abort();
    Ok(if dropped { PtyOutcome::Dropped } else { PtyOutcome::Exited })
}

/// Warm fast path for `filament pty`: if the local daemon already holds a link to
/// `peer`, open the PTY over it (via the control socket) and bridge this process's
/// stdio to it — raw mode + SIGWINCH forwarded as a `resize` op. Returns
/// `Some(result)` once it has handled the session (stdio EOF = shell exit or a
/// warm-link drop -> we exit), or `None` when there is no warm link, so the caller
/// falls through to the cold resumable path. Unix-only (the control socket is unix).
#[cfg(unix)]
async fn try_warm_pty(
    peer: &str,
    session: &str,
    term: &str,
    raw: &mut Option<RawGuard>,
) -> Option<Result<()>> {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let sock = crate::ctl::try_pty(peer, session, cols, rows, term).await?; // None = no warm link
    crate::ui::trace(&format!("filament: reusing warm link to '{peer}' for pty (no establish)"));
    if raw.is_none() {
        match RawGuard::enable() {
            Ok(g) => *raw = Some(g),
            Err(e) => return Some(Err(e)),
        }
    }
    // Forward SIGWINCH as a `resize` control op (a fresh short connection each time).
    let session_owned = session.to_string();
    let winch = tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = match signal(SignalKind::window_change()) {
            Ok(s) => s,
            Err(_) => return,
        };
        while sig.recv().await.is_some() {
            if let Ok((c, r)) = crossterm::terminal::size() {
                crate::ctl::try_resize(&session_owned, c, r).await;
            }
        }
    });
    let r = pump_stdio_over(sock).await;
    winch.abort();
    Some(r)
}

/// `filament pty <peer>`: open a PTY shell on the peer and bridge it to this
/// terminal (the CLI sibling of the browser web-shell). On a real terminal it is
/// a FULL interactive client — real tty size, raw mode, SIGWINCH, $TERM — AND
/// RESUMABLE: a per-invocation random session id lets a dropped link reconnect
/// and reattach the SAME live shell (mosh/tmux-style, the acceptor replays its
/// output buffer), so a flaky link (e.g. a Coder workspace reconnecting every
/// ~90s) no longer loses the session. The session id lives only in THIS process,
/// so a separate `filament pty` run always gets a fresh shell, never this one.
/// A non-tty stdio (a pipe) keeps the plain cooked, non-resuming bridge.
pub async fn pty_cmd(server: &str, peer: &str, relay: bool) -> Result<()> {
    use std::io::IsTerminal;
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    // Random, per-invocation, in-memory only: distinct runs never collide; only
    // THIS process's reconnects reattach (see the user's "same client" concern).
    let session_id = crate::fresh_secret();
    let term = std::env::var("TERM").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "xterm-256color".into());

    // Raw mode is held for the WHOLE invocation (enabled lazily inside the first
    // attach, AFTER its status lines, so they don't staircase), persists across
    // reconnects, and is restored on every exit path by this guard's Drop.
    let mut raw: Option<RawGuard> = None;

    // WARM FAST PATH: if the local `up` daemon already holds a (verified, direct)
    // link to `peer`, open the PTY over it — no signaling, no establishment, ~0.2s
    // instead of seconds. A miss / no daemon / no warm link falls through to the
    // cold resumable path below. Skipped under --relay (the user forced relay; a
    // warm link may be direct) and for non-tty stdio (scripted). Resumability
    // lives on the cold path, where flaky peers (no warm link) need it anyway.
    #[cfg(unix)]
    if interactive && !relay {
        if let Some(r) = try_warm_pty(peer, &session_id, &term, &mut raw).await {
            return r;
        }
    }

    let mut ever_connected = false;
    let mut last_up = std::time::Instant::now();
    let mut backoff = Duration::from_millis(300);
    let mut role: &'static str = "init";
    loop {
        match pty_attach_once(server, peer, relay, role, &session_id, &term, interactive, &mut raw).await {
            Ok(PtyOutcome::Exited) => return Ok(()),
            Ok(PtyOutcome::Dropped) => {
                // Non-tty (scripted) sessions don't resume; a drop is the end.
                if !interactive {
                    return Ok(());
                }
                ever_connected = true;
                last_up = std::time::Instant::now();
                backoff = Duration::from_millis(300);
                role = "reconnect";
                eprint!("\r\n\x1b[2m[filament: link dropped, reconnecting…]\x1b[0m\r\n");
                continue;
            }
            Err(e) => {
                // First connect failed (peer offline, no pair, ...): surface it.
                if !ever_connected {
                    return Err(e);
                }
                // A reconnect attempt failed. Keep trying until the acceptor would
                // have reaped the detached session (SESSION_DETACHED_IDLE = 180s);
                // stop a bit under that so we don't reattach into a fresh shell.
                if last_up.elapsed() > Duration::from_secs(150) {
                    eprint!("\r\n\x1b[2m[filament: session expired, reconnect window passed]\x1b[0m\r\n");
                    return Ok(());
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                role = "reconnect";
                continue;
            }
        }
    }
}

/// Build the user-facing message for the case where `filament forward` could
/// not bind its local listener because the requested port is in use. The
/// tunnel itself is healthy; only the local bind failed. We suggest
/// lport+1 with a saturating increment so the suggestion is always a valid
/// u16 (the helper is pure so the unit test below can pin the message shape
/// without touching the network).
fn port_in_use_msg(lport: u16, peer: &str, rport: u16) -> String {
    let suggested = lport.saturating_add(1);
    format!(
        "filament: local port {lport} is already in use, pick another (e.g. filament forward {suggested} {peer} {rport})"
    )
}

/// Bidirectionally copy an accepted local TCP connection and a warm-reuse unix
/// socket (the daemon bridges the unix socket to an L2 stream over its existing
/// link). One copy per direction; either side's EOF ends the pair. Unix-only.
#[cfg(unix)]
async fn bridge_streams(mut tcp: TcpStream, mut unix: tokio::net::UnixStream) -> std::io::Result<()> {
    tokio::io::copy_bidirectional(&mut tcp, &mut unix).await.map(|_| ())
}

/// `filament forward <lport> <peer> <rport>`: local TCP listener; every accepted
/// connection opens a fresh L2 stream to `peer:127.0.0.1:rport`.
///
/// WARM-LINK FAST PATH: when a local daemon already holds a link to `peer`, each
/// accepted connection rides it (no establishment) via the control socket. If the
/// daemon can't serve it (no daemon / no warm link / --relay), we fall back to
/// establishing ONE cold link lazily and multiplexing connections over it, the
/// original behavior. The warm path also sidesteps the single-link credit caveat:
/// each connection is an independent stream over the daemon's link.
pub async fn forward_cmd(server: &str, lport: u16, peer: &str, rport: u16, relay: bool) -> Result<()> {
    // Bind first so a port conflict fails fast, before any network work.
    let listener = match TcpListener::bind(("127.0.0.1", lport)).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            bail!("{}", port_in_use_msg(lport, peer, rport));
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "filament: failed to bind 127.0.0.1:{lport} for forward to {peer}:127.0.0.1:{rport}"
            )));
        }
    };
    crate::ui::say(&format!("filament: forwarding 127.0.0.1:{lport} -> {peer}:127.0.0.1:{rport}"));
    // Warm path is unix-only (control socket); elsewhere every connection is cold.
    #[cfg(unix)]
    let mut warm = !relay; // try the daemon's warm link until proven unavailable
    let mut cold: Option<Arc<Mux>> = None; // lazily established fallback link
    loop {
        let (sock, _) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        // Warm path: bridge this connection straight to the daemon's link.
        #[cfg(unix)]
        if warm {
            if let Some(usock) = crate::ctl::try_open(peer, rport).await {
                tokio::spawn(async move {
                    let _ = bridge_streams(sock, usock).await;
                });
                continue;
            }
            warm = false; // no daemon / no warm link: settle on the cold path
            crate::ui::trace("filament: no warm link, establishing for forward");
        }
        // Cold path: establish one link on the first connection, reuse it after.
        let mux = match &cold {
            Some(m) => m.clone(),
            None => {
                let (t, rx, guard, mut diag) = bring_up_to_known(server, peer, relay, "init").await?;
                guard.forget(); // long-lived listener, keep the link alive
                diag.up("tunnel", "datachannel-or-direct");
                let m = Mux::new(t);
                tokio::spawn(pump_initiator(rx, m.clone()));
                cold = Some(m.clone());
                m
            }
        };
        // NOTE(scope): concurrent heavy forwards over ONE cold link need credit
        // flow control (design §4); the warm path avoids this (independent streams).
        let (sid, rx_pipe) = open_stream(&mux, rport).await?;
        tokio::spawn(async move {
            serve_stream(mux, sid, sock, rx_pipe, true).await;
        });
    }
}

/// Seamless-shell bootstrap (initiator): over the already-authenticated filament
/// channel, hand the acceptor our managed pubkey and fetch its host keys, so a
/// user with ZERO ssh setup gets a no-prompt shell. The exchange is pure control
/// JSON over the transport `bring_up_to_known` returns (no mux needed).
///
/// Returns `Ok(hostkeys)` on grant (the acceptor installed our key); the caller
/// pins the host keys and spawns ssh. Returns `Err` if the acceptor DENIES (the
/// device lacks the `shell` cap) or times out, in which case the caller MUST NOT
/// fall through to a key-less ssh attempt (that would be a muddy auth failure
/// instead of a clear "zero shell" denial).
/// Result of installing our managed key on a peer (warm or cold path). `sshd` is
/// the peer's report of whether an sshd is listening on the port `filament ssh`
/// will dial: `Some(true)` reachable, `Some(false)` nothing there (so ssh would
/// fail blindly — caller bails with a clear message), `None` when the peer is an
/// older build that didn't report it (caller proceeds, status unknown).
struct BootstrapInfo {
    hostkeys: Vec<String>,
    user: Option<String>,
    sshd: Option<bool>,
}

async fn shell_bootstrap(server: &str, peer: &str, relay: bool, ssh_port: u16) -> Result<BootstrapInfo> {
    // Managed keypair lives under the filament config dir, NEVER ~/.ssh.
    let pubkey = crate::sshkeys::ensure_managed_key()?;

    let (t, mut rx, guard, mut diag) = bring_up_to_known(server, peer, relay, "bootstrap").await?;
    // The bootstrap rides the bring-up transport directly (pure control JSON, no
    // mux), so the link being usable IS the end of this span. Record `up`; the
    // ssh data link is a SEPARATE netcat span instrumented in its own right.
    diag.up("tunnel", "datachannel-or-direct");
    t.send_control(&json!({ "type": "shell-bootstrap", "v": 1, "pubkey": pubkey, "ssh_port": ssh_port })).await?;

    // Await the verdict (bounded, a daemon without FILAMENT_L2 / without the cap
    // must not hang us forever). Capture it, then ALWAYS tear this link down
    // BEFORE returning, so the ssh data link (netcat ProxyCommand) is the only
    // boxA peer the acceptor sees, no concurrent same-device supersede churn.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let verdict: Result<BootstrapInfo> = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!(
                "shell bootstrap timed out, is '{peer}' running `filament up` with shell access granted?"
            ));
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(Ev::Control(_pid, v))) => match v["type"].as_str() {
                Some("shell-bootstrap-ack") => {
                    let hostkeys: Vec<String> = v["hostkeys"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // The acceptor reports the account it installed our key into,
                    // authoritative for the ssh login (see ssh_cmd).
                    let user = v["user"].as_str().map(String::from);
                    // Older acceptors omit `sshd` -> None (unknown, proceed).
                    let sshd = v["sshd"].as_bool();
                    break Ok(BootstrapInfo { hostkeys, user, sshd });
                }
                Some("shell-bootstrap-deny") => {
                    let why = v["reason"].as_str().unwrap_or("shell capability not granted");
                    break Err(anyhow!(
                        "shell refused by '{peer}': {why}. Run `filament grant <this-device> shell` on '{peer}'."
                    ));
                }
                _ => continue,
            },
            Ok(Some(_)) => continue, // other events on this link, ignore
            Ok(None) => break Err(anyhow!("channel closed before shell bootstrap completed")),
            Err(_) => continue, // timeout sliver, loop re-checks the deadline
        }
    };

    // Tear down the bootstrap link before the caller opens the ssh data link.
    drop(t);
    guard.close().await;
    verdict
}

/// Install our managed key on `peer`, WARM-first: ask the local `up` daemon to
/// run the `shell-bootstrap` over its already-established link (instant, no cold
/// establish), and fall back to a fresh `shell_bootstrap` on a miss/deny/timeout,
/// under `--relay`, or off-unix. This is what closes the last gap that left
/// `filament ssh` slow while `pty` was already warm: the bootstrap was the only
/// remaining cold establish in the ssh path.
async fn bootstrap_key(server: &str, peer: &str, relay: bool, ssh_port: u16) -> Result<BootstrapInfo> {
    #[cfg(unix)]
    if !relay {
        let pubkey = crate::sshkeys::ensure_managed_key()?;
        if let Some(v) = crate::ctl::try_bootstrap(peer, &pubkey, ssh_port).await {
            let hostkeys: Vec<String> = v["hostkeys"]
                .as_array()
                .map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if !hostkeys.is_empty() {
                crate::ui::trace(&format!(
                    "filament: reusing warm link to '{peer}' for ssh bootstrap (no establish)"
                ));
                return Ok(BootstrapInfo {
                    hostkeys,
                    user: v["user"].as_str().map(String::from),
                    sshd: v["sshd"].as_bool(),
                });
            }
        }
    }
    shell_bootstrap(server, peer, relay, ssh_port).await
}

/// The login account for the ssh destination: FILAMENT_SSH_USER wins, else the
/// account the ACCEPTOR installed our key into (from the bootstrap-ack, or the
/// cache), else local $USER, else root. The acceptor's report is authoritative
/// over a local $USER guess, which is usually wrong cross-machine (agboola@laptop
/// vs root@server, the "Permission denied (publickey)" mismatch).
fn resolve_login(remote_user: Option<String>) -> String {
    std::env::var("FILAMENT_SSH_USER")
        .ok()
        .or(remote_user)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into())
}

/// Spawn the real `ssh`, pointed EXCLUSIVELY at filament-managed key material +
/// known_hosts, with a `filament netcat` ProxyCommand. Returns ssh's exit code
/// (so a cached fast-path can detect a 255 connect/auth failure and retry after a
/// fresh bootstrap). The destination is always `<login>@filament-<peer>`.
fn spawn_ssh(
    server: &str,
    peer: &str,
    relay: bool,
    host: &str,
    login: &str,
    rport: u16,
    extra: &[String],
) -> Result<i32> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" netcat {peer} {rport}"));

    let key = crate::sshkeys::managed_key_path();
    let kh = crate::sshkeys::known_hosts_path();
    let dest_token = format!("{login}@{host}");
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o").arg(format!("ProxyCommand={proxy}"))
        .arg("-o").arg(format!("IdentityFile={}", key.display()))
        .arg("-o").arg("IdentitiesOnly=yes")
        .arg("-o").arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o").arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o").arg("StrictHostKeyChecking=accept-new");
    // Split passthrough args into ssh OPTIONS (leading flags) and the remote
    // COMMAND (from the first non-flag token on). The destination is ALWAYS our
    // managed token, inserted BETWEEN options and command, or ssh would mistake
    // the command (e.g. `hostname`) for the host.
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a);
    }
    cmd.arg(&dest_token);
    for a in &extra[split..] {
        cmd.arg(a);
    }
    Ok(cmd.status()?.code().unwrap_or(1))
}

/// `filament ssh <peer> [args...]`: seamless shell over the trusted channel.
///
/// With zero pre-existing ssh setup: bootstrap our managed key + the peer's host
/// key over the authenticated filament channel, pin them, then run ssh pointed
/// EXCLUSIVELY at filament-managed material (-o IdentityFile / IdentitiesOnly /
/// UserKnownHostsFile) with a `filament netcat` ProxyCommand. No prompts, no
/// ~/.ssh, no key copying. The bootstrap is the deny-by-default gate: if the
/// peer lacks the `shell` cap we abort HERE, before invoking ssh.
pub async fn ssh_cmd(server: &str, peer: &str, extra: &[String], relay: bool) -> Result<()> {
    // ssh matches known_hosts by HOST token only (never user@host), so the pin
    // MUST be keyed on the bare host or it is silently inert.
    let host = format!("filament-{peer}");

    // The ProxyCommand data link talks to peer:22 (or a test port via
    // FILAMENT_SSH_PORT, mirroring FILAMENT_L2_DIALHOST).
    let rport: u16 =
        std::env::var("FILAMENT_SSH_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(22);

    // FAST PATH: a device whose host keys are already pinned AND whose bootstrap
    // is still fresh has our key installed + the shell cap granted, so skip the
    // pre-flight bootstrap (a whole extra establish) and go straight to ssh. It
    // self-heals: a stale skip that fails at the ssh layer (255) falls back to a
    // full bootstrap + one retry below.
    let cached = if crate::sshkeys::host_pinned(&host) {
        crate::sshkeys::bootstrap_cache_get(peer)
    } else {
        None
    };

    let (login, took_fast_path) = match cached {
        Some(cached_user) => (resolve_login(cached_user), true),
        None => {
            // Bootstrap over the trusted channel (deny-by-default gate), WARM-first
            // (ride the daemon's link, no cold establish), pin host keys, and
            // record the cache for next time.
            let info = bootstrap_key(server, peer, relay, rport).await?;
            ensure_sshd(peer, rport, info.sshd).await;
            crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
            crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());
            (resolve_login(info.user), false)
        }
    };

    let code = spawn_ssh(server, peer, relay, &host, &login, rport, extra)?;

    // A cached skip that failed at the ssh layer (connect/auth, exit 255) may mean
    // the device rotated its key/host-key or revoked the cap. Invalidate, run a
    // real bootstrap (which surfaces a clear deny if revoked, or re-installs our
    // key + re-pins host keys), and retry ssh ONCE.
    if code == 255 && took_fast_path {
        crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
        crate::sshkeys::bootstrap_cache_clear(peer);
        let info = shell_bootstrap(server, peer, relay, rport).await?;
        // A stale fast-path 255 can simply mean the peer's sshd went away; the
        // re-bootstrap now reports that, so say so plainly instead of looping.
        ensure_sshd(peer, rport, info.sshd).await;
        crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
        crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());
        let login = resolve_login(info.user);
        let code = spawn_ssh(server, peer, relay, &host, &login, rport, extra)?;
        std::process::exit(code);
    }
    std::process::exit(code);
}

/// Confirm an sshd is reachable on `rport` before spawning ssh, so it fails fast
/// with a clear message instead of hanging on a refused/black-holed connection.
/// A beta.20+ peer already `reported` it in the bootstrap ack; for an older peer
/// (`None`) fall back to a quick client-side probe over the warm link, which works
/// regardless of the peer's version. Only a DEFINITE "no sshd" stops us; an
/// inconclusive probe proceeds (never make ssh worse than before).
async fn ensure_sshd(peer: &str, rport: u16, reported: Option<bool>) {
    let sshd = match reported {
        Some(b) => Some(b),
        #[cfg(unix)]
        None => probe_sshd_warm(peer, rport).await,
        #[cfg(not(unix))]
        None => None,
    };
    if sshd != Some(false) {
        return;
    }
    crate::ui::problem(
        &format!("filament ssh: no sshd on '{peer}'"),
        &format!("'{peer}' is reachable, but nothing is listening on port {rport} for ssh."),
        &[
            format!("start an sshd on '{peer}'"),
            format!("set {} to its port", crate::ui::paint(crate::ui::Tone::Brand, "FILAMENT_SSH_PORT")),
            format!(
                "use {} for a shell that needs no sshd",
                crate::ui::paint(crate::ui::Tone::Brand, &format!("filament pty {peer}"))
            ),
        ],
    );
    std::process::exit(1);
}

/// Client-side "is there an sshd on `peer:rport`" probe over the daemon's WARM
/// link only (fast, never a cold establish, so it can't hang). Opens one L2
/// stream and reads: an immediate EOF means the acceptor's local dial was refused
/// (no listener); any bytes (the SSH banner) mean a listener is there. No warm
/// link or no banner in time -> `None` (unknown, caller proceeds). Works against
/// any peer version, since it relies only on the old l2-open/l2-close path.
#[cfg(unix)]
async fn probe_sshd_warm(peer: &str, rport: u16) -> Option<bool> {
    use tokio::io::AsyncReadExt;
    let mut s = crate::ctl::try_open(peer, rport).await?;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await {
        Ok(Ok(0)) => Some(false),  // refused: stream closed before any byte
        Ok(Ok(_)) => Some(true),   // a listener answered (sshd banner)
        Ok(Err(_)) => Some(false), // stream error: treat as unreachable
        Err(_) => None,            // no banner in time: inconclusive, don't block
    }
}

#[cfg(test)]
mod h1_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;

    /// Minimal in-memory Transport: records control messages, discards frames.
    struct MockTransport {
        controls: StdMutex<Vec<Value>>,
    }
    impl MockTransport {
        fn new() -> Arc<Self> {
            Arc::new(MockTransport { controls: StdMutex::new(Vec::new()) })
        }
    }
    #[async_trait]
    impl Transport for MockTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
    }

    fn open_msg(sid: u32) -> Value {
        json!({ "type": "l2-open", "sid": sid, "host": "127.0.0.1", "rport": 9 })
    }

    /// H-1: opening + closing N PTY-style streams (register + resizer, then close)
    /// leaves BOTH the stream table and the resizer map empty on every teardown
    /// path, and the global PTY counter returns to zero.
    #[tokio::test]
    async fn pty_open_close_leaves_maps_empty() {
        let start = LIVE_PTYS.load(Ordering::SeqCst);
        let mux = Mux::new(MockTransport::new());
        let n = 5u32;

        // Path A: inbound l2-close frees stream + resizer.
        for i in 0..n {
            let sid = L2_SID_BASE | (1000 + i);
            let guard = PtyGuard::try_acquire().expect("slot free");
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            assert_eq!(mux.live_streams().await, 1);
            assert_eq!(mux.resizers.lock().await.len(), 1);
            // Inbound l2-close (browser closed).
            mux.on_close(sid, None).await;
            drop(guard); // session task ending frees the global slot
            assert_eq!(mux.live_streams().await, 0, "stream not freed on l2-close");
            assert_eq!(mux.resizers.lock().await.len(), 0, "resizer leaked on l2-close");
        }

        // Path B: session task exit (drop_pty) frees stream + resizer.
        for i in 0..n {
            let sid = L2_SID_BASE | (2000 + i);
            let guard = PtyGuard::try_acquire().expect("slot free");
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
            mux.drop_pty(sid).await; // a session task own exit path
            drop(guard);
            assert_eq!(mux.live_streams().await, 0, "stream not freed on drop_pty");
            assert_eq!(mux.resizers.lock().await.len(), 0, "resizer leaked on drop_pty");
        }

        // Path C: link/mux death (shutdown_all) frees everything.
        let mut guards = Vec::new();
        for i in 0..n {
            let sid = L2_SID_BASE | (3000 + i);
            guards.push(PtyGuard::try_acquire().expect("slot free"));
            let _rx = mux.register_stream(sid).await;
            let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, tx).await;
        }
        assert_eq!(mux.live_streams().await, n as usize);
        mux.shutdown_all().await;
        drop(guards);
        assert_eq!(mux.live_streams().await, 0, "streams leaked past shutdown_all");
        assert_eq!(mux.resizers.lock().await.len(), 0, "resizers leaked past shutdown_all");

        assert_eq!(LIVE_PTYS.load(Ordering::SeqCst), start, "global PTY count must return to baseline");
    }

    /// H-1: the per-link stream cap refuses opens beyond MAX_STREAMS_PER_LINK with
    /// an `l2-close{err:"too many streams"}`, and does NOT register the stream.
    #[tokio::test]
    async fn per_link_stream_cap_refuses_over_limit() {
        let mux = Mux::new(MockTransport::new());
        // Fill to the cap with accepted opens (they register pipes).
        for i in 0..MAX_STREAMS_PER_LINK as u32 {
            let sid = L2_SID_BASE | (i + 1);
            match mux.accept_control(&open_msg(sid), true, false).await {
                OpenVerdict::Accept { .. } => {}
                other => panic!("expected Accept under cap, got {:?}", std::mem::discriminant(&other)),
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
            other => panic!("expected Deny over cap, got {:?}", std::mem::discriminant(&other)),
        }
        assert_eq!(mux.live_streams().await, MAX_STREAMS_PER_LINK, "over-cap open must not register");
        // The denied sid is not stuck in `accepted` (can retry once room frees).
        assert!(!mux.accepted.lock().await.contains_key(&over));
    }

    /// H-1: the global PTY guard refuses acquisition once MAX_PTYS_GLOBAL slots
    /// are held, and frees them on drop.
    #[tokio::test]
    async fn global_pty_cap_is_enforced() {
        // Other tests may hold none here, but to be robust we only assert the
        // guard refuses once at-capacity relative to the current baseline.
        let mut held = Vec::new();
        while LIVE_PTYS.load(Ordering::SeqCst) < MAX_PTYS_GLOBAL {
            match PtyGuard::try_acquire() {
                Some(g) => held.push(g),
                None => break,
            }
        }
        assert_eq!(LIVE_PTYS.load(Ordering::SeqCst), MAX_PTYS_GLOBAL);
        assert!(PtyGuard::try_acquire().is_none(), "must refuse at global cap");
        let before = held.len();
        drop(held);
        assert!(LIVE_PTYS.load(Ordering::SeqCst) <= MAX_PTYS_GLOBAL - before.min(1));
    }

    // ---- #4: persistent PTY session ----------------------------------------

    /// A Transport that records every frame's payload (per sid) so a test can
    /// observe what a session actually sent / replayed.
    struct CapTransport {
        frames: StdMutex<Vec<(u32, Vec<u8>)>>,
        controls: StdMutex<Vec<Value>>,
    }
    impl CapTransport {
        fn new() -> Arc<Self> {
            Arc::new(CapTransport { frames: StdMutex::new(Vec::new()), controls: StdMutex::new(Vec::new()) })
        }
        /// All bytes ever sent to `sid`, concatenated in order.
        fn bytes_for(&self, sid: u32) -> Vec<u8> {
            self.frames
                .lock()
                .unwrap()
                .iter()
                .filter(|(s, _)| *s == sid)
                .flat_map(|(_, b)| b.clone())
                .collect()
        }
    }
    #[async_trait]
    impl Transport for CapTransport {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
            self.frames.lock().unwrap().push((sid, payload.to_vec()));
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
    }

    /// `push_ring` keeps the buffer bounded by `cap`, evicting the OLDEST bytes,
    /// and a single oversized write keeps only its trailing `cap` bytes.
    #[test]
    fn ring_buffer_is_bounded_and_keeps_newest() {
        let mut ring = VecDeque::new();
        push_ring(&mut ring, b"hello", 8);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"hello");
        // "helloworld!!" is 12 bytes; cap 8 keeps the trailing 8: "oworld!!".
        push_ring(&mut ring, b"world!!", 8);
        assert_eq!(ring.len(), 8);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"oworld!!");
    }

    /// A single write LARGER than the cap keeps only its trailing `cap` bytes.
    #[test]
    fn ring_buffer_oversized_write_keeps_tail() {
        let mut ring = VecDeque::new();
        push_ring(&mut ring, b"0123456789", 4);
        assert_eq!(ring.iter().copied().collect::<Vec<u8>>(), b"6789");
    }

    /// End-to-end #4: a session spawned over link A, detached (link A drops),
    /// then REATTACHED over link B with the same session id REPLAYS the buffered
    /// output to link B AND the still-running shell keeps working. Uses `cat` as
    /// the "shell" (it echoes stdin), so input typed after reattach comes back on
    /// link B, proving the SAME process survived the reconnect.
    #[tokio::test]
    async fn session_survives_detach_and_reattaches_with_replay() {
        // `cat` echoes its stdin: a deterministic stand-in for a live shell whose
        // process identity we can verify survived the drop.
        if !std::path::Path::new("/bin/cat").exists() {
            return; // environment without /bin/cat: skip rather than fail
        }
        let sessions = PtySessions::new();
        let ta = CapTransport::new();
        let sid_a = L2_SID_BASE | 1;
        let guard = PtyGuard::try_acquire().expect("slot");
        let sess = spawn_pty_session(
            sessions.clone(),
            "sess-x".to_string(),
            ta.clone(),
            sid_a,
            80,
            24,
            "xterm-256color",
            vec!["/bin/cat".to_string()],
            guard,
        )
        .await
        .expect("spawn");

        // Type a line on link A; cat echoes it back to sid_a.
        sess.feed_input(b"before-drop\n".to_vec());
        // Give the PTY threads + task a moment to echo and buffer.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let a_out = String::from_utf8_lossy(&ta.bytes_for(sid_a)).to_string();
        assert!(a_out.contains("before-drop"), "link A never saw the echo: {a_out:?}");

        // Link A drops: detach (the shell MUST keep running).
        sess.detach();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!sess.is_dead(), "detach must NOT kill the session");

        // Reconnect: attach link B with the same session, new sid. The buffer
        // (including "before-drop") replays to sid_b.
        let tb = CapTransport::new();
        let sid_b = L2_SID_BASE | 2;
        let live = sessions.get_live("sess-x").await.expect("session still live for reattach");
        live.attach(tb.clone(), sid_b);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let b_replay = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
        assert!(b_replay.contains("before-drop"), "reattach did not replay buffered output: {b_replay:?}");

        // The SAME shell still works: type after reattach, see it on link B.
        live.feed_input(b"after-reconnect\n".to_vec());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let b_out = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
        assert!(b_out.contains("after-reconnect"), "post-reattach input did not echo: {b_out:?}");

        // Explicit end kills the shell and removes the session.
        live.end();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(sessions.get_live("sess-x").await.is_none(), "ended session must leave the store");
    }

    /// The `port_in_use_msg` helper must surface the conflicting port and a
    /// `filament forward <lport+1> <peer> <rport>` retry hint, so a user
    /// staring at a "port in use" error can recover in one copy-paste.
    #[test]
    fn port_in_use_msg_names_port_and_suggests_forward() {
        let msg = port_in_use_msg(8080, "laptop", 22);
        assert!(msg.contains("8080"), "message must name the conflicting port: {msg}");
        assert!(msg.contains("filament forward"), "message must suggest a filament forward retry: {msg}");
        assert!(msg.contains("8081"), "suggested port should be lport+1: {msg}");
        assert!(msg.contains("laptop"), "message should reference the peer: {msg}");
        assert!(msg.contains("22"), "message should reference the rport: {msg}");
    }

    /// The helper's `saturating_add` must not wrap when lport is u16::MAX, so
    /// the user never sees a suggested port of 0 (which would still be valid
    /// for binding but is a confusing retry hint).
    #[test]
    fn port_in_use_msg_saturates_at_u16_max() {
        let msg = port_in_use_msg(u16::MAX, "laptop", 22);
        assert!(msg.contains(&format!("{}", u16::MAX)), "must name the conflicting port: {msg}");
        // u16::MAX.saturating_add(1) == u16::MAX, NOT 0.
        assert!(!msg.contains("0 "), "saturating add must not wrap to 0: {msg}");
    }
}
