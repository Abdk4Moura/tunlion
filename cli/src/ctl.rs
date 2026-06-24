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
    let base = if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        PathBuf::from(d)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".config/filament")
    };
    base.join("control.sock")
}

/// True if the warm-reuse fast path is disabled by the operator. An escape hatch
/// so a user can force every session back onto a fresh establish for debugging.
pub fn reuse_disabled() -> bool {
    std::env::var("FILAMENT_NO_WARM_REUSE").map(|v| v == "1").unwrap_or(false)
}

#[cfg(unix)]
pub use imp::{serve, serve_at, try_open, try_open_at, try_pty, try_resize, Req, ReqKind};

#[cfg(not(unix))]
pub use stub::Req;

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
    pub async fn try_pty(peer: &str, session: &str, cols: u16, rows: u16, term: &str) -> Option<UnixStream> {
        if reuse_disabled() {
            return None;
        }
        let mut s = UnixStream::connect(control_sock_path()).await.ok()?;
        let req = json!({ "op": "pty", "peer": peer, "session": session, "cols": cols, "rows": rows, "term": term });
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

    // ----------------------------------------------------------------- daemon -

    /// What a warm-reuse client is asking the daemon to do over its warm link.
    pub enum ReqKind {
        /// Open one raw L2 stream to `peer`'s localhost:`rport` (netcat/ssh/forward).
        Open { peer: String, rport: u16 },
        /// Open a PTY shell on `peer` (the warm pty fast path). `session` keys the
        /// peer's persistent PTY so a later reconnect reattaches the same shell.
        Pty { peer: String, session: String, cols: u16, rows: u16, term: String },
        /// Relay a window-size change to an already-open warm PTY (by `session`).
        Resize { session: String, cols: u16, rows: u16 },
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
                    Some("pty") => {
                        let Some(peer) = v["peer"].as_str().map(str::to_string) else { return };
                        let Some(session) = v["session"].as_str().filter(|s| !s.is_empty() && s.len() <= 128).map(str::to_string) else { return };
                        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        let term = v["term"].as_str().filter(|s| !s.is_empty() && s.len() <= 64).unwrap_or("xterm-256color").to_string();
                        ReqKind::Pty { peer, session, cols, rows, term }
                    }
                    Some("resize") => {
                        let Some(session) = v["session"].as_str().map(str::to_string) else { return };
                        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        ReqKind::Resize { session, cols, rows }
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
    /// Warm-link reuse needs a unix-domain socket, which this platform lacks, so
    /// `Req` is uninhabited: the daemon never spawns `serve`, the channel never
    /// receives, and the fast paths (gated on `cfg(unix)`) never call `try_open`.
    /// Keeping the type lets the daemon loop and handler compile unchanged.
    pub enum Req {}
}
