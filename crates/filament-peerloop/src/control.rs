//! The local control socket's request/reply surface: the TYPES, not the server.
//!
//! `ReqKind` is what a warm-reuse client asks the daemon to do over its warm
//! link; `Req` is one parsed request, the kind plus the client's socket. They
//! moved here from `cli/src/ctl.rs` (issue #465) so the daemon receive loop can
//! name its own request type without reaching into a CLI module. The Unix-socket
//! server (`serve_at`), the client probes (`try_open`, `try_pty`, ...) and every
//! handler body stay in the CLI.
//!
//! WHAT IS NOT HERE: nothing. Every `ReqKind` payload is plain data (`String`,
//! `u16`, `u64`, `bool`), so no CLI type (`Conn`, `Link`, `DaemonMounts`, a path
//! type) crosses the crate boundary. `Req` holds only the kind and a
//! `tokio::net::UnixStream`.
//!
//! WIRE SHAPE: these types are NOT serialized. There is no serde derive here and
//! there never was; the control protocol is one hand-written JSON request line
//! and one hand-written JSON reply line. The client builds the request line with
//! `json!` and the daemon's `serve_at` parses it field by field, both in
//! `cli/src/ctl.rs`; the reply writers below emit exactly the bytes they emitted
//! before the move. Moving a type that never touches the wire cannot change it.

use serde_json::Value;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;

/// What a warm-reuse client is asking the daemon to do over its warm link.
#[derive(Clone)]
pub enum ReqKind {
    /// Open one raw L2 stream to `peer`'s localhost:`rport` (netcat/ssh/forward).
    Open { peer: String, rport: u16 },
    /// Dial `peer`'s OVERLAY address:`port` over L3 (reaches an `expose`d overlay
    /// service; the daemon resolves the peer to its verified overlay addr). The
    /// proxy `.mesh` path uses this as a FALLBACK after the L2 `Open`.
    Dial { peer: String, port: u16 },
    /// Open a PTY shell on `peer` (the warm pty fast path). `session` keys the
    /// peer's persistent PTY so a later reconnect reattaches the same shell.
    /// `cmd` is non-empty for one-shot exec (mirrors the cold pty-open cmd field).
    Pty { peer: String, session: String, cols: u16, rows: u16, term: String, cmd: String },
    /// Relay a window-size change to an already-open warm PTY (by `session`).
    Resize { session: String, cols: u16, rows: u16 },
    /// Run a ONE-SHOT command over the daemon's existing warm link to `peer`.
    /// The daemon sends the same `exec-open` a cold initiator would (so the
    /// peer's serving/capability/revocation checks run at request time), then
    /// bridges stdin/stdout/stderr/exit over the control socket with the binary
    /// framing in `exec_frame`. A daemon with no live, identity-proven link
    /// answers `no warm path`, which is the client's signal to cold-establish;
    /// once the open is sent there is NO retry (a non-idempotent command must
    /// never run twice). `argv` is final (shell wrapping already applied) and
    /// `env` is `KEY=VALUE`, exactly as the cold exec frame carries them.
    Exec {
        peer: String,
        argv: Vec<String>,
        cwd: Option<String>,
        env: Vec<String>,
        tty: bool,
    },
    /// Run the ssh `shell-bootstrap` over the daemon's warm link instead of a
    /// fresh cold establish: install our managed `pubkey` on `peer` and return
    /// the peer's host keys + login. The reply is deferred (it awaits the
    /// peer's ack via the event loop), so the daemon stashes the socket rather
    /// than answering inline. `ssh_port` is the port `tunlion ssh` will dial
    /// on the peer's loopback, so the peer can report whether an sshd is
    /// actually listening there (else ssh would fail blindly).
    Bootstrap { peer: String, pubkey: String, ssh_port: u16 },
    /// Report the daemon's live link to `peer` for `tunlion ping`: route,
    /// remote address, RTT, verified name. Answered INLINE (synchronous): all
    /// the facts are local to the daemon (quinn's RTT/addr, the link table), so
    /// unlike Bootstrap there is nothing to await from the peer.
    Ping { peer: String },
    /// Tell the running daemon a setting changed (`tunlion set`). The daemon
    /// re-reads its prefs and applies `key` to its live state where it safely
    /// can (drop-dir, shell policy/user, name, auto-extract), replying
    /// `{"ok":true,"live":<bool>}`: `live:true` = applied without a restart;
    /// `live:false` = the key is woven into startup (relay/server, or arming
    /// the L2 acceptor from cold) and needs `tunlion up`. Answered INLINE.
    Reconfigure { key: String },
    /// Tell the daemon to re-read `expose.json` and reconcile its overlay
    /// listeners (`tunlion expose`/`unexpose`). Answered INLINE with
    /// `{"ok":true,"live":true,"count":<n>}` where `n` is the number of ports
    /// now bound; `live:false` if L3 is not up in the daemon.
    ReloadExpose,
    /// A no-op that exists to WAKE the daemon loop. The mint sends it right
    /// after writing armed.json so the per-iteration arm gate subscribes the
    /// enrollment channel NOW, instead of on the loop's next idle tick. That
    /// tick cost a joiner up to a second whenever it arrived fast (a phone
    /// scanning the QR code, or a scripted add | join): it reached the empty
    /// channel first and waited. armed.json stays the source of truth -- this
    /// carries no state, so a platform without a control socket loses nothing
    /// but the speed-up. Answered INLINE with `{"ok":true}`.
    Wake,
    /// A forget or revoke changed the device store: re-read it now, close
    /// the links it ends, and reply `{"ok":true,"closed":<n>}` once done
    /// (see revocation_live.rs). Handled inline in the daemon loop.
    RevocationSync,
    /// Gracefully restart to pick up an updated binary (`tunlion update`).
    /// Handled INLINE: if supervised (systemd), reply then self-SIGTERM so the
    /// supervisor restarts us cleanly; otherwise decline (don't exit into down).
    Reload,
    /// Mount a remote directory via sshfs through the daemon. The daemon
    /// spawns sshfs, tracks the mount, and monitors its health centrally.
    Mount { peer: String, remote: String, local: String, read_only: bool, auto_restore: bool, port: u16 },
    /// Unmount a tunlion mount point by local path.
    Unmount { target: String },
    /// List all daemon-managed mounts and their health status.
    ListMounts,
    /// Check health of a specific mount by local path or mount ID.
    MountHealth { target: String },
    /// Return the daemon's live capability shadow counters (synchronous).
    CapStatus,
    /// Snapshot already-held warm links without probing peers.
    ListWarm,
    /// Broker a one-time private rendezvous with a fleet sibling.
    ///
    /// The daemon already holds a certificate-verified link to that sibling.
    /// It mints a single-use secret, hands it over THAT link, and returns it
    /// here. Both ends then meet on `channel_of(secret)`, where exactly two
    /// parties exist, instead of the fleet channel where every sibling does.
    FleetRendezvous { name: String },
    /// List pending consent requests.
    ListPending,
    /// Approve a pending request by id.
    ApproveRequest { id: u64, allow: String, expires: u64 },
    /// Deny a pending request by id.
    DenyRequest { id: u64 },
}

/// A parsed request handed to the daemon's event loop, which owns the link
/// table and the per-peer muxes. The loop dispatches on `kind` and then
/// `accept()`s (bridging `sock`) or `reject()`s.
#[cfg(unix)]
pub struct Req {
    pub kind: ReqKind,
    pub sock: tokio::net::UnixStream,
}

#[cfg(unix)]
impl Req {
    /// Confirm the stream is opening; returns the socket for the bridge.
    pub async fn accept(mut self) -> tokio::net::UnixStream {
        let _ = self.sock.write_all(b"{\"ok\":true}\n").await;
        let _ = self.sock.flush().await;
        self.sock
    }

    /// Decline (no warm link / not permitted); the client falls back to a
    /// fresh establish. Best-effort; the socket drops on return.
    pub async fn reject(mut self, err: &str) {
        let line = serde_json::json!({ "ok": false, "err": err }).to_string();
        let _ = self.sock.write_all(line.as_bytes()).await;
        let _ = self.sock.write_all(b"\n").await;
        let _ = self.sock.flush().await;
    }

    /// Answer a synchronous request (Ping) with one JSON line, then drop the
    /// socket. For requests that report facts rather than handing off a stream.
    pub async fn reply(mut self, v: &Value) {
        send_reply(&mut self.sock, v).await;
    }
}

/// Write one JSON reply line to a DEFERRED-reply socket (a `Bootstrap` request
/// whose `sock` the daemon stashed until the peer's ack arrived). Best-effort.
#[cfg(unix)]
pub async fn send_reply(sock: &mut tokio::net::UnixStream, v: &Value) {
    if let Ok(mut line) = serde_json::to_vec(v) {
        line.push(b'\n');
        let _ = sock.write_all(&line).await;
        let _ = sock.flush().await;
    }
}

/// Warm-link reuse needs a unix-domain socket, which this platform lacks, so
/// `Req` is uninhabited: the daemon never spawns `serve`, the channel never
/// receives, and the fast paths (gated on `cfg(unix)`) never call `try_open`.
/// Keeping the type lets the daemon loop and handler compile unchanged.
#[cfg(not(unix))]
pub enum Req {}

#[cfg(not(unix))]
impl Req {
    /// Uninhabited here, so this is never called; it exists so the daemon
    /// loop's reply to a parked revocation-sync compiles on every target.
    pub async fn reply(self, _v: &Value) {
        match self {}
    }

    /// Uninhabited here, so this is never called; the control loop still names
    /// the refusal path on every target.
    pub async fn reject(self, _err: &str) {
        match self {}
    }
}
