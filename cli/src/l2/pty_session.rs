//! Persistent acceptor-side PTY session table, ring buffer, and global slot cap.

use crate::net::Transport;
use bytes::Bytes;
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};

/// H-1 (DoS): process-wide cap on concurrently live PTYs across ALL links. Each
/// PTY is a login shell + threads, so this bounds total resource use even if many
/// links each stay under the per-link cap. Refused opens get an `l2-close`.
///
/// Re-exported from the library, which also names the figure in its refusal
/// log: one definition, so the check and the message cannot drift apart.
pub use filament_peerloop::l2::MAX_PTYS_GLOBAL;

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
            match LIVE_PTYS.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
            {
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

/// The TERM the remote shell actually gets.
///
/// The client sends ITS terminal's name, and forwarding it verbatim is right only
/// when this machine has a terminfo entry for it. Modern terminals (kitty,
/// ghostty, wezterm, ...) use names most servers have never heard of, and then
/// every curses program degrades or refuses outright -- tmux exits with
/// "missing or unsuitable terminal: xterm-kitty", so a remote tmux never starts
/// and mouse events land on the shell prompt as `64;20;10M`. `ssh` appears not
/// to have this problem only because those terminals' ssh integrations copy
/// their terminfo to the remote first; this path has no such step. Fall back to
/// xterm-256color, which every system ships and which supports 256 colours and
/// mouse tracking.
///
/// THE VALUE COMES FROM THE PEER and is used to build a filesystem path below,
/// so anything that is not a plausible terminal name is replaced before it is
/// ever joined onto a directory (`../../etc/passwd` must not become a probe).
/// The TERM a shell session gets. The Windows relay sets TERM/COLORTERM on the
/// ConPTY itself and ignores it (see `platform::pty::spawn_shell`).
pub(crate) fn effective_term(requested: &str) -> String {
    const FALLBACK: &str = "xterm-256color";
    let plausible = !requested.is_empty()
        && requested.len() <= 64
        && requested
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
        && !requested.starts_with('.');
    if !plausible {
        return FALLBACK.to_string();
    }
    if crate::platform::terminfo_exists(requested) {
        requested.to_string()
    } else {
        FALLBACK.to_string()
    }
}

/// A detached session (channel dropped, nobody reattached) is reaped after this.
/// Long enough to ride out a mobile network handoff, a tab suspend or a laptop
/// lid closed for a coffee, short enough that a closed laptop does not leave a
/// shell alive for hours. It never outlives the peer's access: the revocation
/// ticker below ends a detached session the moment its access expires or is
/// cut, whatever is left of this window.
pub const SESSION_DETACHED_IDLE: Duration = Duration::from_secs(600);

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
    Attach {
        transport: Arc<dyn Transport>,
        sid: u32,
        /// How many bytes of this session's output the client already has. The
        /// replay starts there, so a reattach shows only what was missed instead
        /// of the whole buffer again. `None` (a client that does not count, or a
        /// first attach) replays the whole buffer, as before.
        resume_from: Option<u64>,
    },
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
    /// Library-installed teardown for the current attachment. The session task
    /// invokes it on every exit that never returns through the receive loop
    /// (natural exit, idle/lifetime reap, revocation), so that path also
    /// releases its mux stream/resizer. A newer attachment replaces the slot;
    /// only the newest sid is ever released.
    end_cleanup: Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>,
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
    /// Rebind output to a new link (transport + sid) and replay what the client
    /// missed: everything after `resume_from` bytes, or the whole buffer when the
    /// client did not say.
    pub fn attach(&self, transport: Arc<dyn Transport>, sid: u32, resume_from: Option<u64>) {
        let _ = self.cmd_tx.send(SessionCmd::Attach { transport, sid, resume_from });
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
    /// Install the release for the CURRENT attachment. Returns false when the
    /// session has already ended, in which case the caller must release its
    /// registrations itself.
    pub fn set_end_cleanup(&self, cleanup: Box<dyn FnOnce() + Send>) -> bool {
        let mut slot = self
            .end_cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_dead() {
            return false;
        }
        *slot = Some(cleanup);
        true
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
    // The peer's device key, for the live session's revocation re-check. `None`
    // (no resolved identity) is treated as not-revoked by `cert_revoked_for`.
    idev: Option<[u8; 32]>,
    // True when this session was admitted via its enrolment ceiling rather
    // than an explicit grant: a narrowed ceiling must end it on the next
    // tick, exactly like a revocation. Grant-admitted sessions ignore the
    // ceiling (the grant authorizes); uncovered sessions never set this.
    admitted_via_ceiling: bool,
    terminal_scope: Option<filament_peerloop::shell_gate::TerminalSessionScope>,
) -> Option<PtySessionHandle> {
    use std::io::{Read as _, Write as _};
    // The backend (portable-pty, or the Windows token relay) is chosen in the
    // platform adapter; this loop only reads, writes, resizes and ends it.
    let (mut reader, mut writer, mut control) =
        match crate::platform::pty::spawn_shell(&argv, cols, rows, &effective_term(term)) {
            Ok(shell) => shell,
            Err(e) => {
                let _ = transport
                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": e }))
                    .await;
                return None;
            }
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
    let end_cleanup = Arc::new(std::sync::Mutex::new(None));

    let handle = PtySessionHandle {
        input_tx,
        resize_tx,
        cmd_tx,
        dead: dead.clone(),
        end_cleanup: end_cleanup.clone(),
    };

    // The long-lived session task: it owns the PTY output, the current binding,
    // the replay ring, and the lifetime/idle caps. It outlives every link.
    let sessions_for_task = sessions.clone();
    let session_id_for_task = session_id.clone();
    tokio::spawn(async move {
        let _guard = pty_guard; // freed when the task ends (any exit path)
        let mut bind: Option<OutBind> = Some(OutBind { transport, sid });
        let mut ring: VecDeque<u8> = VecDeque::new();
        // Total bytes of output this session has produced (everything that went
        // through the ring). The ring holds
        // the last `ring.len()` of them, so it starts at `out_total - ring.len()`.
        let mut out_total: u64 = 0;
        let started = Instant::now();
        let mut detached_since: Option<Instant> = None;
        // 5s tick to enforce the idle/lifetime caps without busy-waiting.
        let mut reaper = tokio::time::interval(Duration::from_secs(5));
        reaper.tick().await; // consume the immediate first tick
        // #235-shape: a dedicated recheck ticker at the shared interval, so the
        // revoke bound is NOT floored by the 5s reaper. The tick IS the cadence;
        // the verdict is re-asked directly. The denial must reach the initiator
        // as a denial (a reason + nonzero exit), never as a clean shell exit.
        let mut revoke_ticker = tokio::time::interval(crate::revoke_recheck_interval());
        revoke_ticker.tick().await; // consume the immediate first tick
        let mut revoked_reason: Option<String> = None;

        loop {
            tokio::select! {
                out = orx.recv() => match out {
                    Some(bytes) => {
                        push_ring(&mut ring, &bytes, SESSION_BUFFER_CAP);
                        out_total += bytes.len() as u64;
                        if let Some(b) = &bind {
                            for chunk in bytes.chunks(b.transport.max_payload().max(1)) {
                                if b.transport.send_frame(b.sid, 0, chunk).await.is_err() {
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
                    Some(SessionCmd::Attach { transport, sid, resume_from }) => {
                        // Replay the buffered output the client has not seen to
                        // the freshly attached link, so the user sees the shell
                        // exactly as it stands now without repeating anything.
                        let skip = replay_skip(out_total, ring.len(), resume_from);
                        let snapshot: Vec<u8> = ring.iter().skip(skip).copied().collect();
                        let mp = transport.max_payload().max(1);
                        let mut ok = true;
                        for chunk in snapshot.chunks(mp) {
                            if transport.send_frame(sid, 0, chunk).await.is_err() {
                                ok = false;
                                break;
                            }
                        }
                        // Reattach is a byte-stream continuation, not a terminal
                        // reset. The client retains its terminal across a drop;
                        // only the remote app owns its modes. Injecting a reset
                        // here disables live TUI mouse tracking (PTY reads can
                        // split a mode sequence), or even splices an escape into
                        // an unfinished CSI/OSC. Replay and future output must
                        // join exactly, without synthetic bytes in between.
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
                        control.resize(c, r);
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
                _ = revoke_ticker.tick() => {
                    // Re-ask the gate. A revoked peer loses the live shell: tell
                    // the terminal, then close with a reason so the initiator
                    // surfaces a nonzero exit rather than a clean one (#223).
                    // A ceiling narrowed under a ceiling-admitted session ends
                    // it the same way (re-read fresh; never cached at open).
                    let ceiling_gone = admitted_via_ceiling
                        && !crate::identity_state::ceiling_covers_action(
                            idev.as_ref(),
                            crate::capability::CAP_SHELL,
                        );
                    // A lapsed deadline ends it too; unresolvable is no opinion.
                    let lapsed =
                        matches!(crate::identity_state::peer_liveness_alive(idev.as_ref()), Some(false));
                    let cut = crate::identity_state::live_session_cut(idev.as_ref());
                    let grant_gone = terminal_scope.as_ref().is_some_and(|scope| {
                        scope.withdrawn(&crate::host_impl::CliHost)
                    });
                    if cut.is_some() || ceiling_gone || lapsed || grant_gone {
                        let reason = match cut {
                            Some(c) => c.reason_for(idev.as_ref()),
                            None => crate::capability::REVOKED_REASON.to_string(),
                        };
                        if matches!(cut, Some(crate::identity_state::LiveCut::Expired(_))) {
                            crate::ui::critical("pty: peer access expired, closing the live session");
                        } else if matches!(cut, Some(crate::identity_state::LiveCut::Forgotten)) {
                            crate::ui::critical("pty: peer forgotten, closing the live session");
                        } else {
                            crate::ui::critical("pty: peer revoked, closing the live session");
                        }
                        revoked_reason = Some(reason.clone());
                        if let Some(b) = &bind {
                            let msg = format!("\r\n[tunlion: {}]\r\n", reason);
                            let _ = b.transport.send_frame(b.sid, 0, msg.as_bytes()).await;
                        }
                        break;
                    }
                }
            }
        }

        // Teardown (shell exit, reap, revoke, or store removal): kill the shell,
        // tell the currently-attached link (if any) the session ended, drop from
        // the store.
        control.end();
        dead.store(true, Ordering::Release);
        // Publish "ended" BEFORE taking the slot. A concurrent attach that
        // loses the race then sees `is_dead()` and releases its own stream,
        // instead of storing a cleanup this task has already passed.
        let cleanup = end_cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(cleanup) = cleanup {
            cleanup();
        }
        if let Some(b) = &bind {
            let close = match revoked_reason {
                Some(reason) => json!({ "type": "l2-close", "sid": b.sid, "err": reason }),
                None => json!({ "type": "l2-close", "sid": b.sid }),
            };
            let _ = b.transport.send_control(&close).await;
        }
        sessions_for_task.remove(&session_id_for_task).await;
    });

    sessions.insert(session_id, handle.clone()).await;
    Some(handle)
}

/// How many bytes at the front of the replay ring a reattach skips. The ring
/// holds the last `ring_len` of `out_total` bytes produced. A client that says it
/// already has `resume_from` bytes gets only what follows; a client that says
/// nothing, claims bytes that were never produced, or has fallen behind what the
/// ring still holds gets the whole ring (the old behaviour: some repetition is
/// better than a gap). Pure.
pub(crate) fn replay_skip(out_total: u64, ring_len: usize, resume_from: Option<u64>) -> usize {
    let ring_start = out_total.saturating_sub(ring_len as u64);
    match resume_from {
        Some(n) if n >= ring_start && n <= out_total => (n - ring_start) as usize,
        _ => 0,
    }
}

/// Append `bytes` to the replay ring, evicting from the front so it never exceeds
/// `cap`. A single write larger than `cap` keeps only its trailing `cap` bytes
/// (the most recent screen state is what matters for replay).
pub(super) fn push_ring(ring: &mut VecDeque<u8>, bytes: &[u8], cap: usize) {
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

#[cfg(test)]
mod term_tests {
    use super::effective_term;

    #[test]
    fn a_term_with_no_terminfo_falls_back_instead_of_breaking_curses_apps() {
        // Reproduced: TERM=xterm-kitty on a server without that entry made a
        // remote `tmux` exit with "missing or unsuitable terminal".
        //
        // The contract, portably: effective_term keeps a name exactly when the
        // platform says it has terminfo for it, and otherwise falls back. On
        // unix an invented name has none (pinned in platform/'s own tests); on
        // Windows there is no terminfo and every name is kept by design. The
        // first version asserted the unix outcome everywhere and failed on the
        // Windows runner, which was the test being wrong, not the code.
        let name = "definitely-not-a-real-terminal-x9";
        let want = if crate::platform::terminfo_exists(name) { name } else { "xterm-256color" };
        assert_eq!(effective_term(name), want);
        assert_eq!(effective_term(""), "xterm-256color");
    }

    #[test]
    fn a_term_this_machine_knows_is_kept() {
        // Every Linux and macOS CI image ships xterm-256color, and on Windows
        // (no terminfo) the requested name is always kept.
        assert_eq!(effective_term("xterm-256color"), "xterm-256color");
    }

    #[test]
    fn a_peer_supplied_term_cannot_become_a_path_probe() {
        // TERM is chosen by the PEER and joined onto terminfo directories, so
        // anything that is not a plain terminal name is replaced before use.
        let too_long = "z".repeat(65);
        let hostile_names: [&str; 8] = [
            "../../etc/passwd",
            "..",
            ".hidden",
            "a/b",
            "x\\y",
            "term\0nul",
            "has space",
            too_long.as_str(),
        ];
        for hostile in hostile_names {
            assert_eq!(effective_term(hostile), "xterm-256color", "{hostile:?}");
        }
    }
}

