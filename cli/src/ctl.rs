// Local control socket: warm-link reuse between sibling filament processes.
//
// WHY: a one-shot `filament ssh`/`netcat`/`forward` normally establishes a FRESH
// link to the peer (signaling + presence + the direct-QUIC race, ~1s). But if a
// local `filament up` daemon already holds an established link to that peer, the
// new session can ride THAT link instead, skipping establishment. The daemon
// exposes a unix-domain socket; a sibling process connects, names a peer and a
// remote port, and on success the socket becomes a raw byte pipe for one L2
// stream the daemon opens over its warm link.
//
// PLATFORM: this rides a unix-domain socket, so it is a UNIX-ONLY feature. On
// other platforms (Windows) the control socket is absent and every command falls
// back to a fresh establish; `Req` is an uninhabited type so the daemon loop and
// the netcat/forward fast paths compile unchanged.
//
// The wire protocol is one request line and one reply line, then raw bytes:
//   client -> daemon:  {"op":"open","peer":"<name>","rport":<u16>}\n
//   daemon -> client:  {"ok":true}\n            (then both sides pipe raw bytes)
//                  or:  {"ok":false,"err":"..."}\n  (daemon closes; client falls back)
//
// SECURITY: the socket is created 0600 under the user's config dir, so only the
// user who runs the daemon can talk to it. That is the same authority boundary as
// the daemon itself (it already acts on behalf of the local user); a peer is only
// reachable if it was paired AND its acceptor grants L2, exactly as for a cold
// `filament ssh`. The remote side is UNCHANGED and re-verifies trust per link.

use std::path::PathBuf;

/// `{config_dir}/control.sock`, honoring FILAMENT_CONFIG_DIR (hermetic tests),
/// else `~/.config/filament`. Mirrors `devices_path()` / `pidfile()`. Portable
/// (just path math); only used on unix where the socket is actually bound.
pub fn control_sock_path() -> PathBuf {
    crate::platform::Paths::config_path("control.sock")
}

/// True if the warm-reuse fast path is disabled by the operator. An escape hatch
/// so a user can force every session back onto a fresh establish for debugging.
pub fn reuse_disabled() -> bool {
    std::env::var("FILAMENT_NO_WARM_REUSE").map(|v| v == "1").unwrap_or(false)
}

#[cfg(unix)]
    pub use imp::{
        daemon_present, send_reply, serve, serve_at, try_approve_request, try_bootstrap,
        try_cap_status, try_deny_request, try_dial, try_list_mounts, try_list_pending, try_mount,
        try_mount_health, try_open, try_open_at, try_ping, try_pty, try_reconfigure, try_reload,
        try_reload_expose, try_resize, try_unmount, Req, ReqKind,
    };

#[cfg(not(unix))]
pub use stub::{try_ping, Req};

// --------------------------------------------------------------- unix impl ----
#[cfg(unix)]
mod imp {
    use super::{control_sock_path, reuse_disabled};
    use anyhow::{anyhow, Result};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    /// Read a single newline-terminated line, byte at a time, so we never consume
    /// the raw stream bytes that follow the JSON line. Lines are tiny, so cheap.
    async fn read_line(s: &mut UnixStream, max: usize) -> Result<String> {
        let mut buf = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        loop {
            let n = s.read(&mut byte).await?;
            if n == 0 {
                return Err(anyhow!("control socket closed before newline"));
            }
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
            if buf.len() > max {
                return Err(anyhow!("control line too long"));
            }
        }
        Ok(String::from_utf8(buf)?)
    }

    // ----------------------------------------------------------------- client -

    /// Cheap probe: is a local `up` daemon listening on the control socket? Lets
    /// callers (e.g. `forward`) tell "ride the warm link" from "cold-establish as
    /// a new identity" UP FRONT, so they can report the right ready-state and not
    /// surprise the user with a second presence on the peer. A bare connect the
    /// daemon accepts then drops on our disconnect (harmless: its reader just sees
    /// EOF). Honors the warm-reuse opt-out.
    pub async fn daemon_present() -> bool {
        if reuse_disabled() {
            return false;
        }
        UnixStream::connect(control_sock_path()).await.is_ok()
    }

    /// Try to DIAL `peer`'s OVERLAY address:`port` through the daemon's L3 plane
    /// (an `expose`d overlay service, which an L2 loopback open cannot reach), and
    /// on a userspace node the only way to reach `<peer>.mesh:port` at all. The
    /// daemon resolves `peer` to its verified overlay address itself (never client-
    /// asserted). Returns the bridged socket, or `None` if there is no daemon / the
    /// peer is unknown / L3 is down, so the caller can report a clean failure.
    pub async fn try_dial(peer: &str, port: u16) -> Option<UnixStream> {
        if reuse_disabled() {
            return None;
        }
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "dial", "peer": peer, "port": port });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = read_line(&mut s, 4096).await.ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(s)
    }

    /// Try to open an L2 stream to `peer:rport` THROUGH a local daemon's warm
    /// link. Returns the connected socket (positioned for raw bytes) on success,
    /// or `None` if there is no daemon, no warm link, or any protocol error, so
    /// the caller falls back to a fresh establish. Never errors: a miss is `None`.
    pub async fn try_open(peer: &str, rport: u16) -> Option<UnixStream> {
        if reuse_disabled() {
            return None;
        }
        try_open_at(&control_sock_path(), peer, rport).await
    }

    /// `try_open` against an explicit socket path (the live path comes from
    /// `control_sock_path()`; tests pass a hermetic path with no global env).
    pub async fn try_open_at(path: &Path, peer: &str, rport: u16) -> Option<UnixStream> {
        let mut s = UnixStream::connect(path).await.ok()?;
        let req = json!({ "op": "open", "peer": peer, "rport": rport });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = read_line(&mut s, 4096).await.ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        if v["ok"].as_bool() == Some(true) {
            Some(s)
        } else {
            None
        }
    }

    /// Try to open a PTY shell on `peer` THROUGH a local daemon's warm link.
    /// On success returns the socket bridging this process's stdio to the warm
    /// PTY stream; `None` (no daemon / no warm link) means fall back to a fresh
    /// establish. `session` keys the peer's persistent PTY for reattach.
    /// `cmd` is non-empty for one-shot exec (mirrors the cold pty-open cmd field).
    pub async fn try_pty(peer: &str, session: &str, cols: u16, rows: u16, term: &str, cmd: &str) -> Option<UnixStream> {
        if reuse_disabled() {
            return None;
        }
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let mut req = json!({ "op": "pty", "peer": peer, "session": session, "cols": cols, "rows": rows, "term": term });
        if !cmd.is_empty() {
            req["cmd"] = json!(cmd);
        }
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = read_line(&mut s, 4096).await.ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(s)
    }

    /// Relay a window-size change to an already-open warm PTY (by `session`),
    /// over a fresh short control connection. Best-effort and fire-and-forget.
    pub async fn try_resize(session: &str, cols: u16, rows: u16) {
        if reuse_disabled() {
            return;
        }
        let Ok(mut s) = UnixStream::connect(control_sock_path()).await else { return };
        let req = json!({ "op": "resize", "session": session, "cols": cols, "rows": rows });
        if let Ok(mut line) = serde_json::to_vec(&req) {
            line.push(b'\n');
            let _ = s.write_all(&line).await;
            let _ = s.flush().await;
        }
    }

    /// Run the ssh `shell-bootstrap` THROUGH a local daemon's warm link: the
    /// daemon installs our `pubkey` on `peer` over its existing link (no cold
    /// establish) and relays the peer's verdict. Returns the ack JSON
    /// (`{"ok":true,"hostkeys":[...],"user":...}`) on success, or `None` (no
    /// daemon / no warm link / deny / timeout / protocol error) so the caller
    /// falls back to the cold `shell_bootstrap`. The reply is deferred on the
    /// daemon side (it awaits the peer), so we bound our own wait too.
    pub async fn try_bootstrap(peer: &str, pubkey: &str, ssh_port: u16) -> Option<Value> {
        if reuse_disabled() {
            return None;
        }
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "bootstrap", "peer": peer, "pubkey": pubkey, "ssh_port": ssh_port });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        // Bound the wait: the daemon relays the peer's ack, which can take a beat,
        // but a hung/denying peer must not stall ssh. On timeout, fall back to cold.
        let reply = tokio::time::timeout(std::time::Duration::from_secs(15), read_line(&mut s, 8192))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask a local daemon what its warm link to `peer` looks like (for
    /// `filament ping`): returns the facts JSON (`{"ok":true,"warm":true,"route":…,
    /// "remote_addr":…,"rtt_ms":…,"direct":…,"verified":…}`) when the daemon holds
    /// a live link, or `None` (no daemon / no warm link) so the caller falls back
    /// to a cold establish-probe. Bounded so a wedged daemon can't hang ping.
    pub async fn try_ping(peer: &str) -> Option<Value> {
        if reuse_disabled() {
            return None;
        }
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "ping", "peer": peer });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Tell a running `up` daemon that setting `key` changed, so it re-reads its
    /// prefs and applies the change to its live state (the `filament set` live
    /// path). Returns the daemon's reply (`{"ok":true,"live":<bool>}`) or `None`
    /// when there is no daemon / it did not answer, so the caller can fall back to
    /// the "takes effect on next up" message. Bounded so a wedged daemon can't
    /// hang `filament set`.
    pub async fn try_reconfigure(key: &str) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "reconfigure", "key": key });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the running daemon to re-read `expose.json` and reconcile its overlay
    /// listeners (used by `filament expose`/`unexpose`). Returns the daemon reply
    /// (`{"ok":true,"live":<bool>,"count":<n>}`) or `None` if no daemon answered.
    pub async fn try_reload_expose() -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "reload-expose" });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask a running `up` daemon to RELOAD onto a freshly `filament update`d binary
    /// with no manual restart and no sudo. The daemon gracefully shuts down (the
    /// same path a `systemctl restart` / SIGTERM takes, which cleanly closes the
    /// QUIC links so peers re-establish and L3 recovers) and its supervisor
    /// (systemd `Restart=always`) starts it again on the new binary with fresh
    /// AmbientCapabilities. Reply `{"ok":true,"reloading":true}` when it will do
    /// so, `{"ok":true,"reloading":false,...}` when it is NOT under a supervisor
    /// (exiting would leave it down, so it declines), or `None` if no daemon answered.
    pub async fn try_reload() -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "reload" });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to mount a remote directory via sshfs. The daemon spawns
    /// sshfs, tracks the mount, and monitors its health centrally. Returns the
    /// daemon's reply (`{"ok":true}`) or `None` if no daemon answered, so the
    /// caller can fall back to a direct sshfs spawn.
    pub async fn try_mount(peer: &str, remote: &str, local: &str, read_only: bool, auto_restore: bool, port: u16) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "mount", "peer": peer, "remote": remote, "local": local, "read_only": read_only, "auto_restore": auto_restore, "port": port });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(15), read_line(&mut s, 8192))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to unmount a filament mount point. Returns the daemon's
    /// reply (`{"ok":true}`) or `None` if no daemon answered.
    pub async fn try_unmount(target: &str) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "unmount", "target": target });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(15), read_line(&mut s, 8192))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to list all tracked mounts and their health. Returns the
    /// daemon's reply (`{"ok":true,"mounts":[...]}`) or `None` if no daemon.
    pub async fn try_list_mounts() -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "list-mounts" });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 16384))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to check health of a specific mount. Returns the daemon's
    /// reply (`{"ok":true,"status":"healthy"}`) or `None` if no daemon.
    pub async fn try_mount_health(target: &str) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "mount-health", "target": target });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon for its live capability shadow counters (synchronous).
    /// Returns the daemon's reply (`{"ok":true,"counts":{...}}`) or `None` if
    /// no daemon answered. A fresh process has zero counters; only the running
    /// daemon (`filament up`) accumulates them across live opens.
    pub async fn try_cap_status() -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "cap-status" });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon for the list of pending consent requests.
    pub async fn try_list_pending() -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "list-pending" });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 8192))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to approve a pending request by id.
    pub async fn try_approve_request(id: u64) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "approve-request", "id": id });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    /// Ask the daemon to deny a pending request by id.
    pub async fn try_deny_request(id: u64) -> Option<Value> {
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "deny-request", "id": id });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(4), read_line(&mut s, 4096))
            .await
            .ok()?
            .ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        (v["ok"].as_bool() == Some(true)).then_some(v)
    }

    // ----------------------------------------------------------------- daemon -

    /// What a warm-reuse client is asking the daemon to do over its warm link.
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
        /// Run the ssh `shell-bootstrap` over the daemon's warm link instead of a
        /// fresh cold establish: install our managed `pubkey` on `peer` and return
        /// the peer's host keys + login. The reply is deferred (it awaits the
        /// peer's ack via the event loop), so the daemon stashes the socket rather
        /// than answering inline. `ssh_port` is the port `filament ssh` will dial
        /// on the peer's loopback, so the peer can report whether an sshd is
        /// actually listening there (else ssh would fail blindly).
        Bootstrap { peer: String, pubkey: String, ssh_port: u16 },
        /// Report the daemon's live link to `peer` for `filament ping`: route,
        /// remote address, RTT, verified name. Answered INLINE (synchronous): all
        /// the facts are local to the daemon (quinn's RTT/addr, the link table), so
        /// unlike Bootstrap there is nothing to await from the peer.
        Ping { peer: String },
        /// Tell the running daemon a setting changed (`filament set`). The daemon
        /// re-reads its prefs and applies `key` to its live state where it safely
        /// can (drop-dir, shell policy/user, name, auto-extract), replying
        /// `{"ok":true,"live":<bool>}`: `live:true` = applied without a restart;
        /// `live:false` = the key is woven into startup (relay/server, or arming
        /// the L2 acceptor from cold) and needs `filament up`. Answered INLINE.
        Reconfigure { key: String },
        /// Tell the daemon to re-read `expose.json` and reconcile its overlay
        /// listeners (`filament expose`/`unexpose`). Answered INLINE with
        /// `{"ok":true,"live":true,"count":<n>}` where `n` is the number of ports
        /// now bound; `live:false` if L3 is not up in the daemon.
        ReloadExpose,
        /// Gracefully restart to pick up an updated binary (`filament update`).
        /// Handled INLINE: if supervised (systemd), reply then self-SIGTERM so the
        /// supervisor restarts us cleanly; otherwise decline (don't exit into down).
        Reload,
        /// Mount a remote directory via sshfs through the daemon. The daemon
        /// spawns sshfs, tracks the mount, and monitors its health centrally.
        Mount { peer: String, remote: String, local: String, read_only: bool, auto_restore: bool, port: u16 },
        /// Unmount a filament mount point by local path.
        Unmount { target: String },
        /// List all daemon-managed mounts and their health status.
        ListMounts,
        /// Check health of a specific mount by local path or mount ID.
        MountHealth { target: String },
        /// Return the daemon's live capability shadow counters (synchronous).
        CapStatus,
        /// List pending consent requests.
        ListPending,
        /// Approve a pending request by id.
        ApproveRequest { id: u64 },
        /// Deny a pending request by id.
        DenyRequest { id: u64 },
    }

    /// A parsed request handed to the daemon's event loop, which owns the link
    /// table and the per-peer muxes. The loop dispatches on `kind` and then
    /// `accept()`s (bridging `sock`) or `reject()`s.
    pub struct Req {
        pub kind: ReqKind,
        pub sock: UnixStream,
    }

    impl Req {
        /// Confirm the stream is opening; returns the socket for the bridge.
        pub async fn accept(mut self) -> UnixStream {
            let _ = self.sock.write_all(b"{\"ok\":true}\n").await;
            let _ = self.sock.flush().await;
            self.sock
        }

        /// Decline (no warm link / not permitted); the client falls back to a
        /// fresh establish. Best-effort; the socket drops on return.
        pub async fn reject(mut self, err: &str) {
            let line = json!({ "ok": false, "err": err }).to_string();
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
    pub async fn send_reply(sock: &mut UnixStream, v: &Value) {
        if let Ok(mut line) = serde_json::to_vec(v) {
            line.push(b'\n');
            let _ = sock.write_all(&line).await;
            let _ = sock.flush().await;
        }
    }

    /// Bind the control socket and forward each parsed request to `tx` (the
    /// daemon event loop). Removes a stale socket file first; `daemon_alive()`
    /// already guards against two live daemons. Sets mode 0600.
    pub async fn serve(tx: mpsc::UnboundedSender<Req>) -> Result<()> {
        serve_at(control_sock_path(), tx).await
    }

    /// `serve` against an explicit socket path (tests pass a hermetic path).
    pub async fn serve_at(path: PathBuf, tx: mpsc::UnboundedSender<Req>) -> Result<()> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path); // clear a stale leftover
        let listener = UnixListener::bind(&path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        crate::ui::trace(&format!("filament: control socket at {}", path.display()));
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let tx = tx.clone();
            // Read the request off the loop so a slow/garbage client cannot stall
            // the daemon; only a well-formed request reaches the event loop.
            tokio::spawn(async move {
                let line = match read_line(&mut sock, 4096).await {
                    Ok(l) => l,
                    Err(_) => return,
                };
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let kind = match v["op"].as_str() {
                    Some("open") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(rport) = v["rport"].as_u64().and_then(|n| u16::try_from(n).ok()) else { return };
                        ReqKind::Open { peer, rport }
                    }
                    Some("dial") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(port) = v["port"].as_u64().and_then(|n| u16::try_from(n).ok()) else { return };
                        ReqKind::Dial { peer, port }
                    }
                    Some("pty") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(session) = v["session"].as_str().filter(|s| !s.is_empty() && s.len() <= 128).map(str::to_string) else { return };
                        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        let term = v["term"].as_str().filter(|s| !s.is_empty() && s.len() <= 64).unwrap_or("xterm-256color").to_string();
                        let cmd = v["cmd"].as_str().unwrap_or("").to_string();
                        ReqKind::Pty { peer, session, cols, rows, term, cmd }
                    }
                    Some("resize") => {
                        let Some(session) = v["session"].as_str().map(str::to_string) else { return };
                        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        ReqKind::Resize { session, cols, rows }
                    }
                    Some("bootstrap") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(pubkey) = v["pubkey"].as_str().filter(|s| !s.is_empty() && s.len() <= 4096).map(str::to_string) else { return };
                        let ssh_port = v["ssh_port"].as_u64().and_then(|n| u16::try_from(n).ok()).unwrap_or(22);
                        ReqKind::Bootstrap { peer, pubkey, ssh_port }
                    }
                    Some("ping") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        ReqKind::Ping { peer }
                    }
                    Some("reconfigure") => {
                        let Some(key) = v["key"].as_str().filter(|s| !s.is_empty() && s.len() <= 64).map(str::to_string) else { return };
                        ReqKind::Reconfigure { key }
                    }
                    Some("reload-expose") => ReqKind::ReloadExpose,
                    Some("reload") => ReqKind::Reload,
                    Some("mount") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(remote) = v["remote"].as_str().map(str::to_string) else { return };
                        let Some(local) = v["local"].as_str().map(str::to_string) else { return };
                        let read_only = v["read_only"].as_bool().unwrap_or(false);
                        let auto_restore = v["auto_restore"].as_bool().unwrap_or(false);
                        let port = v["port"].as_u64().unwrap_or(22) as u16;
                        ReqKind::Mount { peer, remote, local, read_only, auto_restore, port }
                    }
                    Some("unmount") => {
                        let Some(target) = v["target"].as_str().map(str::to_string) else { return };
                        ReqKind::Unmount { target }
                    }
                    Some("list-mounts") => ReqKind::ListMounts,
                    Some("mount-health") => {
                        let Some(target) = v["target"].as_str().map(str::to_string) else { return };
                        ReqKind::MountHealth { target }
                    }
                    Some("cap-status") => ReqKind::CapStatus,
                    Some("list-pending") => ReqKind::ListPending,
                    Some("approve-request") => {
                        let Some(id) = v["id"].as_u64() else { return };
                        ReqKind::ApproveRequest { id }
                    }
                    Some("deny-request") => {
                        let Some(id) = v["id"].as_u64() else { return };
                        ReqKind::DenyRequest { id }
                    }
                    _ => return,
                };
                let _ = tx.send(Req { kind, sock });
            });
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn control_sock_path_ends_with_socket_name() {
            assert!(control_sock_path().ends_with("control.sock"));
        }

        #[tokio::test]
        async fn request_line_round_trips_and_pipes_raw_bytes() {
            let dir = format!("/tmp/filament-ctl-{}", std::process::id());
            std::fs::create_dir_all(&dir).unwrap();
            let path = PathBuf::from(&dir).join("control.sock");
            let (tx, mut rx) = mpsc::unbounded_channel::<Req>();
            let server = tokio::spawn(serve_at(path.clone(), tx));

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let p = path.clone();
            let client = tokio::spawn(async move { try_open_at(&p, "popos", 22).await });

            let req = rx.recv().await.expect("request reached the loop");
            match &req.kind {
                ReqKind::Open { peer, rport } => {
                    assert_eq!(peer, "popos");
                    assert_eq!(*rport, 22);
                }
                _ => panic!("expected an Open request"),
            }
            let mut daemon_side = req.accept().await;

            let mut client_side = client.await.unwrap().expect("client got ok");
            client_side.write_all(b"ping").await.unwrap();
            client_side.flush().await.unwrap();
            let mut got = [0u8; 4];
            daemon_side.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ping");
            daemon_side.write_all(b"pong").await.unwrap();
            daemon_side.flush().await.unwrap();
            let mut back = [0u8; 4];
            client_side.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"pong");

            server.abort();
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[tokio::test]
        async fn reject_makes_client_fall_back() {
            let dir = format!("/tmp/filament-ctl-rej-{}", std::process::id());
            std::fs::create_dir_all(&dir).unwrap();
            let path = PathBuf::from(&dir).join("control.sock");
            let (tx, mut rx) = mpsc::unbounded_channel::<Req>();
            let server = tokio::spawn(serve_at(path.clone(), tx));
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let p = path.clone();
            let client = tokio::spawn(async move { try_open_at(&p, "nope", 22).await });
            let req = rx.recv().await.unwrap();
            req.reject("no warm link").await;
            let res = client.await.unwrap();
            assert!(res.is_none(), "a reject yields None so the caller falls back");
            server.abort();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

// -------------------------------------------------------- non-unix fallback ----
#[cfg(not(unix))]
mod stub {
    use serde_json::Value;
    /// Warm-link reuse needs a unix-domain socket, which this platform lacks, so
    /// `Req` is uninhabited: the daemon never spawns `serve`, the channel never
    /// receives, and the fast paths (gated on `cfg(unix)`) never call `try_open`.
    /// Keeping the type lets the daemon loop and handler compile unchanged.
    pub enum Req {}

    /// No control socket on this platform, so there is never a warm daemon link
    /// to ping. Callers (`ping`, `forward`) treat `None` as "no daemon" and fall
    /// back to a fresh establish. Present so the `via_daemon`-gated call sites —
    /// dead here, since `via_daemon` is always false on non-unix — still compile.
    pub async fn try_ping(_peer: &str) -> Option<Value> {
        None
    }
}
