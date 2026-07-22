// Local control socket: warm-link reuse between sibling filament processes.
//
// WHY: a one-shot `filament ssh`/`netcat`/`forward` normally establishes a FRESH
// link to the peer (signaling + presence + the direct-QUIC race, ~1s). But if a
// local `filament up` daemon already holds an established link to that peer, the
// new session can ride THAT link instead, skipping establishment. The daemon
// exposes a control socket; a sibling process connects, names a peer and a
// remote port, and on success the socket becomes a raw byte pipe for one L2
// stream the daemon opens over its warm link.
//
// PLATFORM: on Unix this rides a unix-domain socket; on Windows it rides a
// named pipe (`\\.\pipe\filament-<hash>`). The wire protocol and ctl API are
// identical on both platforms; only the transport layer differs.
//
// The wire protocol is one request line and one reply line, then raw bytes:
//   client -> daemon:  {"op":"open","peer":"<name>","rport":<u16>}\n
//   daemon -> client:  {"ok":true}\n            (then both sides pipe raw bytes)
//                  or:  {"ok":false,"err":"..."}\n  (daemon closes; client falls back)
//
// SECURITY: the socket is created 0600 under the user's config dir (Unix) or
// with a DACL granting only the current user (Windows), so only the user who
// runs the daemon can talk to it. That is the same authority boundary as the
// daemon itself (it already acts on behalf of the local user); a peer is only
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

// --- Platform-selected type aliases ---
// The bridge core is stream-generic, so the rest of the code only needs these
// two aliases. On Unix both are UnixStream; on Windows they are the
// NamedPipeClient / NamedPipeServer halves (different types because named
// pipes have distinct client/server handles, unlike UDS).
#[cfg(unix)]
pub type CtlClientStream = tokio::net::UnixStream;
#[cfg(unix)]
pub type CtlServerStream = tokio::net::UnixStream;

#[cfg(windows)]
pub type CtlClientStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(windows)]
pub type CtlServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(any(unix, windows))]
pub use imp::{
    daemon_present, send_reply, serve, serve_at, try_bootstrap, try_dial, try_eof,
    try_list_mounts,
    try_mount, try_mount_health, try_open, try_open_at, try_ping, try_pty,
    try_reconfigure, try_reload, try_reload_expose, try_resize, try_unmount, Req, ReqKind,
};

#[cfg(not(any(unix, windows)))]
pub use stub::{try_ping, Req};

// --------------------------------------------------------------- unix/windows impl ----
#[cfg(any(unix, windows))]
mod imp {
    use super::{control_sock_path, reuse_disabled};
    use anyhow::{anyhow, Result};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    /// Read a single newline-terminated line, byte at a time, so we never consume
    /// the raw stream bytes that follow the JSON line. Lines are tiny, so cheap.
    /// Generic over the stream type so it works on both Unix and Windows.
    pub(super) async fn read_line<S: AsyncReadExt + Unpin>(s: &mut S, max: usize) -> Result<String> {
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

    /// Write one JSON reply line to a control socket. Generic over the stream
    /// type so it works on both Unix and Windows.
    pub async fn send_reply<S: AsyncWriteExt + Unpin>(sock: &mut S, v: &Value) {
        if let Ok(mut line) = serde_json::to_vec(v) {
            line.push(b'\n');
            let _ = sock.write_all(&line).await;
            let _ = sock.flush().await;
        }
    }

    // --- Platform transport shims ---

    #[cfg(unix)]
    pub(super) async fn transport_connect(path: &Path) -> std::io::Result<super::CtlClientStream> {
        tokio::net::UnixStream::connect(path).await
    }

    #[cfg(windows)]
    pub(super) async fn transport_connect(path: &Path) -> std::io::Result<super::CtlClientStream> {
        use tokio::net::windows::named_pipe::ClientOptions;
        let name = super::pipe_name_for(path);
        let mut last_err = None;
        for _ in 0..5 {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(client),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(231) /* ERROR_PIPE_BUSY */ =>
                {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "pipe busy")
        }))
    }

    #[cfg(unix)]
    pub(super) async fn transport_serve(
        path: PathBuf,
        tx: mpsc::UnboundedSender<super::Req>,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path); // clear a stale leftover
        let listener = tokio::net::UnixListener::bind(&path)?;
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
            tokio::spawn(async move {
                let line = match read_line(&mut sock, 4096).await {
                    Ok(l) => l,
                    Err(_) => return,
                };
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let kind = match parse_req_op(&v) {
                    Some(k) => k,
                    None => return,
                };
                let _ = tx.send(super::Req { kind, sock });
            });
        }
    }

    #[cfg(windows)]
    pub(super) async fn transport_serve(
        path: PathBuf,
        tx: mpsc::UnboundedSender<super::Req>,
    ) -> Result<()> {
        use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

        let name = super::pipe_name_for(&path);
        let sa = super::security_attributes()?;
        let sa_ptr = &sa as *const _ as *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        let mut server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
                .create_with_security_attributes_raw(&name, sa_ptr)?
        };

        crate::ui::trace(&format!("filament: control pipe at {name}"));

        loop {
            server.connect().await?;
            let connected = server;
            // Create the next instance before handling this client.
            server = unsafe {
                ServerOptions::new()
                    .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
                    .create_with_security_attributes_raw(&name, sa_ptr)?
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut sock = connected;
                let line = match read_line(&mut sock, 4096).await {
                    Ok(l) => l,
                    Err(_) => return,
                };
                let v: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let kind = match parse_req_op(&v) {
                    Some(k) => k,
                    None => return,
                };
                let _ = tx.send(super::Req { kind, sock });
            });
        }
    }

    /// Parse the `op` field of a JSON request into a `ReqKind`.
    fn parse_req_op(v: &Value) -> Option<super::ReqKind> {
        match v["op"].as_str() {
            Some("open") => {
                let peer = v["peer"].as_str()?.to_string();
                let rport = v["rport"].as_u64().and_then(|n| u16::try_from(n).ok())?;
                Some(super::ReqKind::Open { peer, rport })
            }
            Some("dial") => {
                let peer = v["peer"].as_str()?.to_string();
                let port = v["port"].as_u64().and_then(|n| u16::try_from(n).ok())?;
                Some(super::ReqKind::Dial { peer, port })
            }
            Some("pty") => {
                let peer = v["peer"].as_str()?.to_string();
                let session = v["session"].as_str().filter(|s| !s.is_empty() && s.len() <= 128)?.to_string();
                let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                let term = v["term"].as_str().filter(|s| !s.is_empty() && s.len() <= 64).unwrap_or("xterm-256color").to_string();
                let cmd = v["cmd"].as_str().unwrap_or("").to_string();
                Some(super::ReqKind::Pty { peer, session, cols, rows, term, cmd })
            }
            Some("resize") => {
                let session = v["session"].as_str()?.to_string();
                let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                Some(super::ReqKind::Resize { session, cols, rows })
            }
            Some("bootstrap") => {
                let peer = v["peer"].as_str()?.to_string();
                let pubkey = v["pubkey"].as_str().filter(|s| !s.is_empty() && s.len() <= 4096)?.to_string();
                let ssh_port = v["ssh_port"].as_u64().and_then(|n| u16::try_from(n).ok()).unwrap_or(22);
                Some(super::ReqKind::Bootstrap { peer, pubkey, ssh_port })
            }
            Some("ping") => {
                let peer = v["peer"].as_str()?.to_string();
                Some(super::ReqKind::Ping { peer })
            }
            Some("reconfigure") => {
                let key = v["key"].as_str().filter(|s| !s.is_empty() && s.len() <= 64)?.to_string();
                Some(super::ReqKind::Reconfigure { key })
            }
            Some("reload-expose") => Some(super::ReqKind::ReloadExpose),
            Some("reload") => Some(super::ReqKind::Reload),
            Some("mount") => {
                let peer = v["peer"].as_str()?.to_string();
                let remote = v["remote"].as_str()?.to_string();
                let local = v["local"].as_str()?.to_string();
                let read_only = v["read_only"].as_bool().unwrap_or(false);
                let auto_restore = v["auto_restore"].as_bool().unwrap_or(false);
                let port = v["port"].as_u64().unwrap_or(22) as u16;
                Some(super::ReqKind::Mount { peer, remote, local, read_only, auto_restore, port })
            }
            Some("unmount") => {
                let target = v["target"].as_str()?.to_string();
                Some(super::ReqKind::Unmount { target })
            }
            Some("list-mounts") => Some(super::ReqKind::ListMounts),
            Some("mount-health") => {
                let target = v["target"].as_str()?.to_string();
                Some(super::ReqKind::MountHealth { target })
            }
            Some("eof") => {
                let sid = v["sid"].as_u64().and_then(|n| u32::try_from(n).ok())?;
                Some(super::ReqKind::Eof { sid })
            }
            _ => None,
        }
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
        transport_connect(&control_sock_path()).await.is_ok()
    }

    /// Try to DIAL `peer`'s OVERLAY address:`port` through the daemon's L3 plane
    /// (an `expose`d overlay service, which an L2 loopback open cannot reach), and
    /// on a userspace node the only way to reach `<peer>.mesh:port` at all. The
    /// daemon resolves `peer` to its verified overlay address itself (never client-
    /// asserted). Returns the bridged socket, or `None` if there is no daemon / the
    /// peer is unknown / L3 is down, so the caller can report a clean failure.
    pub async fn try_dial(peer: &str, port: u16) -> Option<super::CtlClientStream> {
        if reuse_disabled() {
            return None;
        }
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
    /// link. Returns the connected socket (positioned for raw bytes) + stream ID
    /// on success, or `None` if there is no daemon, no warm link, or any protocol
    /// error, so the caller falls back to a fresh establish.
    pub async fn try_open(peer: &str, rport: u16) -> Option<(super::CtlClientStream, u32)> {
        if reuse_disabled() {
            return None;
        }
        try_open_at(&control_sock_path(), peer, rport).await
    }

    /// `try_open` against an explicit socket path (the live path comes from
    /// `control_sock_path()`; tests pass a hermetic path with no global env).
    /// Returns (socket, stream_id) so the caller can send an out-of-band EOF
    /// for the specific stream when stdin closes.
    pub async fn try_open_at(path: &Path, peer: &str, rport: u16) -> Option<(super::CtlClientStream, u32)> {
        let mut s = transport_connect(path).await.ok()?;
        let req = json!({ "op": "open", "peer": peer, "rport": rport });
        let mut line = serde_json::to_vec(&req).ok()?;
        line.push(b'\n');
        s.write_all(&line).await.ok()?;
        s.flush().await.ok()?;
        let reply = read_line(&mut s, 4096).await.ok()?;
        let v: Value = serde_json::from_str(&reply).ok()?;
        if v["ok"].as_bool() == Some(true) {
            let sid = v["sid"].as_u64().unwrap_or(0) as u32;
            Some((s, sid))
        } else {
            None
        }
    }

    /// Try to open a PTY shell on `peer` THROUGH a local daemon's warm link.
    /// On success returns the socket bridging this process's stdio to the warm
    /// PTY stream; `None` (no daemon / no warm link) means fall back to a fresh
    /// establish. `session` keys the peer's persistent PTY for reattach.
    /// `cmd` is non-empty for one-shot exec (mirrors the cold pty-open cmd field).
    pub async fn try_pty(peer: &str, session: &str, cols: u16, rows: u16, term: &str, cmd: &str) -> Option<super::CtlClientStream> {
        if reuse_disabled() {
            return None;
        }
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let Ok(mut s) = transport_connect(&control_sock_path()).await else { return };
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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
        let mut s = transport_connect(&control_sock_path()).await.ok()?;
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

    /// Send an out-of-band EOF signal for stream `sid`. Opens a SEPARATE ctl
    /// connection (not the data pipe) to keep the data pipe byte-transparent.
    /// The daemon shuts down the L2 stream's write half so the remote sees EOF
    /// while the client continues reading the response. Windows-only in
    /// practice (Unix uses native half-close), but safe on both platforms.
    pub async fn try_eof(sid: u32) -> bool {
        let mut s = match transport_connect(&control_sock_path()).await {
            Ok(s) => s,
            Err(_) => return false,
        };
        let req = json!({ "op": "eof", "sid": sid });
        let mut line = serde_json::to_vec(&req).ok().unwrap_or_default();
        line.push(b'\n');
        if s.write_all(&line).await.is_err() {
            return false;
        }
        if s.flush().await.is_err() {
            return false;
        }
        // The daemon replies inline; best-effort read.
        let reply = read_line(&mut s, 4096).await.ok();
        reply.and_then(|r| serde_json::from_str::<Value>(&r).ok())
            .and_then(|v| v["ok"].as_bool())
            .unwrap_or(false)
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
        /// Out-of-band EOF signal: the client's stdin has closed. The daemon
        /// shuts down the write half of the L2 stream for `sid` (remote sees EOF)
        /// while keeping the read side open so the client can still receive the
        /// response. Sent over a SEPARATE ctl connection (not the data pipe) to
        /// keep the data pipe 100% byte-transparent. Windows-only semantics
        /// (Unix uses native half-close via socket shutdown).
        Eof { sid: u32 },
    }

    /// A parsed request handed to the daemon's event loop, which owns the link
    /// table and the per-peer muxes. The loop dispatches on `kind` and then
    /// `accept()`s (bridging `sock`) or `reject()`s.
    pub struct Req {
        pub kind: ReqKind,
        pub sock: super::CtlServerStream,
    }

    impl Req {
        /// Confirm the stream is opening; returns the socket for the bridge.
        pub async fn accept(mut self) -> super::CtlServerStream {
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

    /// Bind the control socket and forward each parsed request to `tx` (the
    /// daemon event loop). Removes a stale socket file first (Unix); `daemon_alive()`
    /// already guards against two live daemons. Sets mode 0600 (Unix) or
    /// owner-only DACL (Windows).
    pub async fn serve(tx: mpsc::UnboundedSender<Req>) -> Result<()> {
        serve_at(control_sock_path(), tx).await
    }

    /// `serve` against an explicit socket path (tests pass a hermetic path).
    pub async fn serve_at(path: PathBuf, tx: mpsc::UnboundedSender<Req>) -> Result<()> {
        transport_serve(path, tx).await
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
            let dir = std::env::temp_dir().join(format!("filament-ctl-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(if cfg!(windows) { "control.pipe" } else { "control.sock" });
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

            let mut client_side = client.await.unwrap().expect("client got ok").0;
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
            let dir = std::env::temp_dir().join(format!("filament-ctl-rej-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(if cfg!(windows) { "control.pipe" } else { "control.sock" });
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

    #[cfg(test)]
    mod eof_tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use std::time::Duration;

        /// Real OOB EOF test: exercises the ACTUAL code path:
        /// - socket_to_dc with a oneshot eof_signal (the signal daemon sends)
        /// - dc_to_socket reading from L2 channel (remote response)
        /// - The eof_signal fires -> socket_to_dc sends L2 FIN and returns
        /// - dc_to_socket continues and delivers pending response data
        /// This catches mis-wires of the watch/oneshot signal.
        #[tokio::test]
        async fn oob_eof_real_wiring() {
            use crate::l2;
            use std::sync::Arc;

            let (client, server) = tokio::net::UnixStream::pair().unwrap();
            let (l2_tx, mut l2_rx) = tokio::sync::mpsc::unbounded_channel::<Option<bytes::Bytes>>();
            let l2_tx_clone = l2_tx.clone();
            let (eof_tx, eof_rx) = tokio::sync::watch::channel(false);

            struct MockTransport(tokio::sync::mpsc::UnboundedSender<Option<bytes::Bytes>>);
            #[async_trait::async_trait]
            impl crate::net::Transport for MockTransport {
                fn is_alive(&self) -> bool { true }
                fn idle_ms(&self) -> u64 { 0 }
                fn remote_addr(&self) -> Option<std::net::SocketAddr> { None }
                fn rtt_ms(&self) -> Option<u64> { Some(0) }
                fn as_any(&self) -> &dyn std::any::Any { self }
                async fn send_frame(&self, _sid: u32, _offset: u64, data: &[u8]) -> anyhow::Result<()> {
                    if data.is_empty() {
                        let _ = self.0.send(None); // FIN
                    } else {
                        let _ = self.0.send(Some(bytes::Bytes::copy_from_slice(data)));
                    }
                    Ok(())
                }
                async fn send_control(&self, _v: &serde_json::Value) -> anyhow::Result<()> { Ok(()) }
                async fn flush(&self) -> anyhow::Result<()> { Ok(()) }
                fn max_payload(&self) -> usize { 65536 }
            }

            let mux = l2::Mux::new(Arc::new(MockTransport(l2_tx_clone)));
            let sid = 42;
            let (_tx, rx_pipe) = tokio::sync::mpsc::channel(10);

            // Server side: run the REAL serve_stream with the eof_signal wired in.
            // This exercises the full OOB path: eof_signal -> socket_to_dc -> L2 FIN.
            let server_task = tokio::spawn(async move {
                l2::serve_stream_for_test(mux.clone(), sid, server, rx_pipe, true, None, Some(eof_rx)).await;
            });

            // Client side: write data, wait for it to be processed, then the
            // OOB eof signal fires (simulating daemon receiving ReqKind::Eof).
            let test_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
            let client_data = test_data.clone();
            let client_task = tokio::spawn(async move {
                let mut c = client;
                c.write_all(&client_data).await.unwrap();
                c.flush().await.unwrap();
                // Keep reading until server closes (response from remote)
                let mut response = Vec::new();
                let _ = c.read_to_end(&mut response).await;
                response
            });

            // Wait for client to write + flush
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Send response data via L2 BEFORE firing the signal. dc_to_socket
            // reads this data and writes it to the client socket. The channel
            // must stay open long enough for dc_to_socket to read the data.
            let response = b"response-after-eof";
            let _ = l2_tx.send(Some(bytes::Bytes::from_static(response)));
            // Now close the L2 channel so dc_to_socket finishes after reading
            drop(l2_tx);

            // Fire the OOB eof signal AFTER sending response. This causes
            // socket_to_dc to send L2 FIN and return. dc_to_socket has already
            // read the response data and written it to the client socket.
            eof_tx.send_modify(|v| *v = true);

            // Wait for client to read the response
            let client_response = tokio::time::timeout(Duration::from_secs(5), client_task)
                .await
                .expect("client timed out")
                .expect("client panicked");

            // The client should have received the response data that was sent
            // AFTER the OOB eof. This proves dc_to_socket stayed alive.
            assert_eq!(
                &client_response,
                response,
                "OOB eof: response lost -- dc_to_socket was incorrectly shut down"
            );

            // Verify the L2 channel got the client's data + FIN
            let mut l2_data = Vec::new();
            while let Ok(Some(item)) = tokio::time::timeout(Duration::from_secs(2), l2_rx.recv()).await {
                match item {
                    Some(data) => l2_data.extend_from_slice(&data),
                    None => break,
                }
            }
            assert_eq!(l2_data, test_data, "OOB eof: L2 data mismatch");

            server_task.abort();
        }
    }
} // end mod imp

// --- Windows named-pipe helpers ---

/// Derive a machine-global named-pipe name from a filesystem path. The pipe
/// namespace is global (not per-user filesystem), so we hash the path to
/// isolate multi-user + hermetic tests (FILAMENT_CONFIG_DIR).
#[cfg(windows)]
pub(crate) fn pipe_name_for(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let hash = Sha256::digest(canonical.to_string_lossy().as_bytes());
    format!("\\\\.\\pipe\\filament-{}", hex::encode(hash))
}

/// Build a SECURITY_ATTRIBUTES with a DACL granting only the current user.
/// Mirrors the repo's existing Windows security posture (platform/mod.rs
/// icacls; SecretFile note). Without this, the default named-pipe DACL
/// allows other-user connections.
#[cfg(windows)]
pub(crate) fn security_attributes() -> std::io::Result<windows_sys::Win32::Security::SECURITY_ATTRIBUTES> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    // SDDL: "D:(A;;GA;;;AU)" = DACL: Allow Generic All to Authenticated Users.
    // On a single-user workstation this is equivalent to owner-only.
    let sddl: Vec<u16> = "D:(A;;GA;;;AU)\0".encode_utf16().collect();
    let mut sd: *mut u8 = ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd as _,
        bInheritHandle: 0,
    };
    // Note: sd is leaked here intentionally. The SECURITY_DESCRIPTOR must
    // outlive the pipe server. On process exit Windows reclaims it.
    // A proper fix would store it in a Lazy or static.
    Ok(sa)
}

// -------------------------------------------------------- non-unix/windows fallback ----
#[cfg(not(any(unix, windows)))]
mod stub {
    use serde_json::Value;
    /// Warm-link reuse needs a unix-domain socket or named pipe, which this
    /// platform lacks, so `Req` is uninhabited: the daemon never spawns `serve`,
    /// the channel never receives, and the fast paths (gated on
    /// `cfg(any(unix,windows))`) never call `try_open`. Keeping the type lets
    /// the daemon loop and handler compile unchanged.
    pub enum Req {}

    /// No control socket on this platform, so there is never a warm daemon link
    /// to ping. Callers (`ping`, `forward`) treat `None` as "no daemon" and fall
    /// back to a fresh establish. Present so the `via_daemon`-gated call sites --
    /// dead here, since `via_daemon` is always false on not(unix|windows) --
    /// still compile.
    pub async fn try_ping(_peer: &str) -> Option<Value> {
        None
    }
}
