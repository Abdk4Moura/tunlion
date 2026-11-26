#![cfg_attr(not(unix), allow(dead_code))]
//! `tunlion send --to <device>` warm reuse: ride the local daemon's live
//! direct link to that device instead of building one.
//!
//! The daemon half is `filament_peerloop::l2::warm_send`. This half asks the
//! local control socket for a `send-link` and, when the daemon has one, wraps
//! the session in a [`Transport`] the send loop adopts as an ordinary
//! pre-authenticated direct link. Everything the send does over a link (offer,
//! stream from the receiver's offset, `file-end`, wait for the whole-file
//! `delivery-ack`, every message, exit code and `--json` field) is the same
//! code on the same trait; only the bytes travel through the daemon.
//!
//! FALLBACK: no daemon, no live direct link, a daemon from before this op, or
//! any failure before the daemon's reply is `None`, and the send builds its own
//! link as it always did. Nothing is offered before that reply, so a miss can
//! never leave anything half-sent. A warm link that dies (or stalls) mid-send
//! is dropped by the send loop, which then builds its own link and re-offers
//! everything unfinished with resume, the path it already takes when its own
//! link dies. The receiver verifies the whole file against the sender's digest
//! before it acknowledges, whichever links the bytes came over.
//!
//! The transport never finishes or closes the shared link: `drain_finish` is a
//! flush, and dropping it only closes this process's control connection.

use anyhow::{Result, bail};
use async_trait::async_trait;
use filament_transport::net::{Ev, SourceId, Transport};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

/// A daemon link a send may ride.
pub(crate) struct WarmSendLink {
    /// The key the send loop files this link under. Never a signaling id, so
    /// presence events for the device can never be mistaken for this link.
    pub(crate) pid: String,
    pub(crate) transport: Arc<WarmSendTransport>,
    /// The first of the file sids the daemon reserved for this send.
    pub(crate) sid_base: u32,
    pub(crate) route: &'static str,
}

#[derive(Default)]
struct Health {
    alive: bool,
    heard: Option<(u64, Instant)>,
    silence: Option<(u64, Instant)>,
}

/// The daemon's link, seen through the control socket.
pub(crate) struct WarmSendTransport {
    #[cfg(unix)]
    writer: tokio::sync::Mutex<Option<tokio::net::unix::OwnedWriteHalf>>,
    #[cfg(unix)]
    reader: Mutex<Option<tokio::net::unix::OwnedReadHalf>>,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dead: AtomicBool,
    why: Mutex<Option<String>>,
    health: Mutex<Health>,
    last_data: Mutex<Instant>,
    flushes: Mutex<HashMap<u64, oneshot::Sender<bool>>>,
    next_flush: AtomicU64,
    max_payload: usize,
    source: SourceId,
    remote: Option<std::net::SocketAddr>,
    wake: OnceLock<mpsc::UnboundedSender<Ev>>,
}

impl WarmSendTransport {
    /// Why the daemon ended the session, when it said.
    pub(crate) fn end_reason(&self) -> Option<String> {
        self.why.lock().ok().and_then(|g| g.clone())
    }

    fn mark_dead(&self, why: &str) {
        if let Ok(mut g) = self.why.lock() {
            g.get_or_insert_with(|| why.to_string());
        }
        if self.dead.swap(true, Ordering::SeqCst) {
            return;
        }
        // Every flush still waiting fails now; nothing will answer it.
        if let Ok(mut f) = self.flushes.lock() {
            f.clear();
        }
        // Wake the send loop so it sees the dead link at once instead of at
        // its next idle tick.
        if let Some(tx) = self.wake.get() {
            let _ = tx.send(Ev::BuildWake);
        }
    }

    fn on_health(&self, v: &Value) {
        let now = Instant::now();
        if let Ok(mut h) = self.health.lock() {
            h.alive = v["alive"].as_bool().unwrap_or(false);
            h.heard = v["heard_ms"].as_u64().map(|ms| (ms, now));
            h.silence = v["silence_ms"].as_u64().map(|ms| (ms, now));
        }
        if v["alive"].as_bool() == Some(false) {
            self.mark_dead("the warm link died");
        }
    }

    #[cfg(unix)]
    async fn write(&self, kind: u8, payload: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::SeqCst) {
            bail!("the warm link to the daemon is closed");
        }
        let mut w = self.writer.lock().await;
        let Some(w) = w.as_mut() else {
            bail!("the warm link to the daemon is closed");
        };
        if let Err(e) = filament_peerloop::exec_frame::write_frame(w, kind, payload).await {
            self.mark_dead("the daemon's control connection closed");
            return Err(anyhow::anyhow!("the warm link to the daemon closed: {e}"));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    async fn write(&self, _kind: u8, _payload: &[u8]) -> Result<()> {
        bail!("no warm link on this platform")
    }

    /// Start delivering the daemon's frames to the send loop as events of link
    /// `pid`. Called once, after the loop has adopted the link, so no answer
    /// can arrive for a link the loop does not know yet.
    #[cfg(unix)]
    pub(crate) fn start(self: &Arc<Self>, pid: String, tx: mpsc::UnboundedSender<Ev>) {
        use filament_peerloop::l2::warm_send::{WS_CLOSE, WS_FLUSHED, WS_HEALTH, WS_INBOUND};
        let _ = self.wake.set(tx.clone());
        let Some(read_half) = self.reader.lock().ok().and_then(|mut g| g.take()) else {
            return;
        };
        let me = Arc::downgrade(self);
        let source = self.source;
        let task = tokio::spawn(async move {
            let mut r = tokio::io::BufReader::new(read_half);
            loop {
                let frame = filament_peerloop::exec_frame::read_frame(&mut r).await;
                let Some(t) = me.upgrade() else { return };
                let (kind, payload) = match frame {
                    Ok(Some(f)) => f,
                    Ok(None) | Err(_) => {
                        t.mark_dead("the daemon's control connection closed");
                        return;
                    }
                };
                match kind {
                    WS_INBOUND => {
                        if let Ok(v) = serde_json::from_slice::<Value>(&payload) {
                            let _ = tx.send(Ev::Sourced {
                                pid: pid.clone(),
                                source,
                                inner: Box::new(Ev::Control(pid.clone(), v)),
                            });
                        }
                    }
                    WS_FLUSHED => {
                        if payload.len() >= 9 {
                            let token = u64::from_be_bytes(payload[..8].try_into().unwrap_or([0; 8]));
                            let ok = payload[8] == 1;
                            if let Some(w) = t.flushes.lock().ok().and_then(|mut f| f.remove(&token)) {
                                let _ = w.send(ok);
                            }
                        }
                    }
                    WS_HEALTH => {
                        if let Ok(v) = serde_json::from_slice::<Value>(&payload) {
                            t.on_health(&v);
                        }
                    }
                    WS_CLOSE => {
                        let why = serde_json::from_slice::<Value>(&payload)
                            .ok()
                            .and_then(|v| v["err"].as_str().map(str::to_string))
                            .unwrap_or_else(|| "the daemon ended the warm send".to_string());
                        t.mark_dead(&why);
                        return;
                    }
                    _ => {}
                }
            }
        });
        if let Ok(mut g) = self.reader_task.lock() {
            *g = Some(task);
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn start(self: &Arc<Self>, _pid: String, _tx: mpsc::UnboundedSender<Ev>) {}
}

#[async_trait]
impl Transport for WarmSendTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(msg)?;
        self.write(filament_peerloop::l2::warm_send::WS_CONTROL, &bytes).await
    }

    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        let frame = filament_peerloop::l2::warm_send::encode_data(sid, offset, payload);
        self.write(filament_peerloop::l2::warm_send::WS_DATA, &frame).await?;
        if let Ok(mut g) = self.last_data.lock() {
            *g = Instant::now();
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let token = self.next_flush.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut f) = self.flushes.lock() {
            f.insert(token, tx);
        }
        if let Err(e) = self
            .write(filament_peerloop::l2::warm_send::WS_FLUSH, &token.to_be_bytes())
            .await
        {
            if let Ok(mut f) = self.flushes.lock() {
                f.remove(&token);
            }
            return Err(e);
        }
        // A death after the write drops every waiter, so this never parks on
        // a link that cannot answer.
        if self.dead.load(Ordering::SeqCst) {
            bail!("the warm link died before the flush finished");
        }
        match rx.await {
            Ok(true) => Ok(()),
            Ok(false) => bail!("the warm link could not flush"),
            Err(_) => bail!("the warm link died before the flush finished"),
        }
    }

    /// Never finish the shared link: other users ride it. Everything this send
    /// wrote is on its way once the daemon's flush returns.
    async fn drain_finish(&self) -> Result<()> {
        self.flush().await
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn idle_ms(&self) -> u64 {
        if self.is_dead() {
            return u64::MAX;
        }
        self.last_data
            .lock()
            .map(|g| u64::try_from(g.elapsed().as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX)
    }

    fn idle_ms_tracked(&self) -> Option<u64> {
        Some(self.idle_ms())
    }

    fn heard_ms(&self) -> Option<u64> {
        let h = self.health.lock().ok()?;
        h.heard
            .map(|(ms, at)| ms.saturating_add(u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)))
    }

    fn keepalive_silence_ms(&self) -> Option<u64> {
        let h = self.health.lock().ok()?;
        h.silence
            .map(|(ms, at)| ms.saturating_add(u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)))
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::SeqCst) && self.health.lock().map(|h| h.alive).unwrap_or(false)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn sever(&self) {
        self.mark_dead("the send loop judged the warm link unusable");
    }

    fn force_close(&self) {
        self.mark_dead("the send loop dropped the warm link");
        if let Ok(mut g) = self.reader_task.lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
        #[cfg(unix)]
        if let Ok(mut w) = self.writer.try_lock() {
            // Dropping the write half closes this process's side of the
            // control connection; the daemon ends the session and parks what
            // is unfinished. The link itself stays the daemon's.
            w.take();
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn source_id(&self) -> Option<SourceId> {
        Some(self.source)
    }

    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.remote
    }
}

/// The reply bound: the daemon pings the link once before it answers, and on
/// a slow link that ping may take a few round trips.
#[cfg(unix)]
const REPLY_WAIT: std::time::Duration = std::time::Duration::from_secs(12);

/// Ask the local daemon for a warm link to `peer` for a send that will offer
/// `ids`. `None` means build the send's own link.
#[cfg(unix)]
pub(crate) async fn try_send_link(peer: &str, ids: &[String]) -> Option<WarmSendLink> {
    if crate::ctl::reuse_disabled() {
        return None;
    }
    try_send_link_at(&crate::ctl::control_sock_path(), peer, ids).await
}

#[cfg(not(unix))]
pub(crate) async fn try_send_link(_peer: &str, _ids: &[String]) -> Option<WarmSendLink> {
    // Windows has no control socket yet: every send builds its own link.
    None
}

/// Read the one JSON reply line, byte at a time, so the binary frames that
/// follow stay unread.
#[cfg(unix)]
async fn read_line(s: &mut tokio::net::UnixStream, max: usize) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if s.read(&mut byte).await? == 0 {
            bail!("the local daemon closed before answering");
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > max {
            bail!("the local daemon's reply is too long");
        }
    }
    Ok(String::from_utf8(buf)?)
}

/// `try_send_link` against an explicit socket path, so tests can drive a fake
/// daemon.
#[cfg(unix)]
pub(crate) async fn try_send_link_at(
    path: &std::path::Path,
    peer: &str,
    ids: &[String],
) -> Option<WarmSendLink> {
    use tokio::io::AsyncWriteExt;
    let mut sock = tokio::net::UnixStream::connect(path).await.ok()?;
    let req = serde_json::json!({ "op": "send-link", "peer": peer, "ids": ids });
    let mut line = serde_json::to_vec(&req).ok()?;
    line.push(b'\n');
    if line.len() > 1024 * 1024 {
        return None;
    }
    sock.write_all(&line).await.ok()?;
    sock.flush().await.ok()?;
    // A daemon from before this op closes without a reply: that is a miss,
    // and so is any refusal or a reply that does not arrive in time.
    let reply = tokio::time::timeout(REPLY_WAIT, read_line(&mut sock, 64 * 1024))
        .await
        .ok()?
        .ok()?;
    let v: Value = serde_json::from_str(&reply).ok()?;
    if v["ok"].as_bool() != Some(true) {
        crate::ui::debug(&format!(
            "send: no warm link to '{peer}' ({})",
            v["err"].as_str().unwrap_or("refused")
        ));
        return None;
    }
    let sid_base = u32::try_from(v["sid_base"].as_u64()?).ok()?;
    if filament_peerloop::l2::is_l2_sid(sid_base)
        || filament_peerloop::l2::is_l2_sid(sid_base.checked_add(u32::try_from(ids.len()).ok()?)?)
    {
        return None;
    }
    let max_payload = usize::try_from(v["max_payload"].as_u64()?)
        .ok()?
        .min(filament_peerloop::exec_frame::MAX_FRAME - 12);
    if max_payload == 0 {
        return None;
    }
    let route = match v["route"].as_str() {
        Some(filament_transport::lan::ROUTE_LAN) => filament_transport::lan::ROUTE_LAN,
        _ => "direct-quic",
    };
    let link = v["link"].as_str().unwrap_or("link");
    let (read_half, write_half) = sock.into_split();
    let transport = Arc::new(WarmSendTransport {
        writer: tokio::sync::Mutex::new(Some(write_half)),
        reader: Mutex::new(Some(read_half)),
        reader_task: Mutex::new(None),
        dead: AtomicBool::new(false),
        why: Mutex::new(None),
        // The daemon checked the link before it answered.
        health: Mutex::new(Health { alive: true, heard: None, silence: None }),
        last_data: Mutex::new(Instant::now()),
        flushes: Mutex::new(HashMap::new()),
        next_flush: AtomicU64::new(1),
        max_payload,
        source: SourceId::next(),
        remote: v["remote"].as_str().and_then(|s| s.parse().ok()),
        wake: OnceLock::new(),
    });
    Some(WarmSendLink {
        pid: format!("warm:{link}"),
        transport,
        sid_base,
        route,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use filament_peerloop::exec_frame::{read_frame, write_frame};
    use filament_peerloop::l2::warm_send::*;
    use serde_json::json;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{UnixListener, UnixStream};

    fn sock_dir(tag: &str) -> std::path::PathBuf {
        // Short: unix socket paths are capped near 108 bytes.
        let dir = std::path::PathBuf::from("/tmp").join(format!(
            "ws{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn read_req(s: &mut UnixStream) -> Value {
        serde_json::from_str(&read_line(s, 1 << 20).await.unwrap()).unwrap()
    }

    /// No daemon at all, a daemon that refuses, and a daemon from before this
    /// op (closes without a word) are all a plain miss: the send builds its
    /// own link and nothing was offered anywhere.
    #[tokio::test]
    async fn no_daemon_a_refusal_or_a_stale_daemon_falls_back() {
        let dir = sock_dir("a");
        let path = dir.join("control.sock");
        let ids = vec!["s-1-1".to_string()];
        assert!(try_send_link_at(&path, "box", &ids).await.is_none());

        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // A refusal.
            let (mut s, _) = listener.accept().await.unwrap();
            let v = read_req(&mut s).await;
            assert_eq!(v["op"], "send-link");
            assert_eq!(v["peer"], "box");
            assert_eq!(v["ids"], json!(["s-1-1"]));
            s.write_all(b"{\"ok\":false,\"err\":\"no warm path: no live link to that peer\"}\n")
                .await
                .unwrap();
            // A stale daemon: reads the line, closes.
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_req(&mut s).await;
            drop(s);
        });
        assert!(try_send_link_at(&path, "box", &ids).await.is_none());
        assert!(try_send_link_at(&path, "box", &ids).await.is_none());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A live session: control and data reach the daemon in order, the
    /// peer's answers come back as events of the adopted link, a flush is
    /// answered, and a daemon that reports the link dead ends the transport
    /// (so the send loop falls back) without anything claiming success.
    #[tokio::test]
    async fn a_live_session_carries_the_send_and_reports_link_death() {
        let dir = sock_dir("b");
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (seen_tx, mut seen) = mpsc::unbounded_channel::<(u8, Vec<u8>)>();
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_req(&mut s).await;
            s.write_all(
                format!(
                    "{}\n",
                    json!({"ok": true, "sid_base": 0x4000_0010u32, "max_payload": 1 << 20,
                           "route": "direct-quic", "link": "abc", "remote": "10.0.0.2:5000"})
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let (mut r, mut w) = s.into_split();
            // The receiver's accept arrives as soon as the offer does.
            let (kind, payload) = read_frame(&mut r).await.unwrap().unwrap();
            assert_eq!(kind, WS_CONTROL);
            let offer: Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(offer["type"], "file-offer");
            write_frame(&mut w, WS_INBOUND, json!({"type":"file-accept","id":"s-1-1","offset":0}).to_string().as_bytes())
                .await
                .unwrap();
            for _ in 0..3 {
                let f = read_frame(&mut r).await.unwrap().unwrap();
                if f.0 == WS_FLUSH {
                    let mut ans = f.1.clone();
                    ans.push(1);
                    write_frame(&mut w, WS_FLUSHED, &ans).await.unwrap();
                }
                let _ = seen_tx.send(f);
            }
            let _ = kill_rx.await;
            write_frame(&mut w, WS_HEALTH, b"{\"alive\":false}").await.unwrap();
            // Hold the socket open: death comes from the health report alone.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let link = try_send_link_at(&path, "box", &["s-1-1".to_string()]).await.expect("warm link");
        assert_eq!(link.pid, "warm:abc");
        assert_eq!(link.sid_base, 0x4000_0010);
        let t = link.transport.clone();
        assert_eq!(t.remote_addr().unwrap().to_string(), "10.0.0.2:5000");
        assert!(t.is_alive() && !t.is_dead());
        let (tx, mut rx) = mpsc::unbounded_channel();
        t.start(link.pid.clone(), tx);
        t.send_control(&json!({"type":"file-offer","id":"s-1-1","sid":0x4000_0010u32})).await.unwrap();
        match rx.recv().await.unwrap() {
            Ev::Sourced { pid, source, inner } => {
                assert_eq!(pid, "warm:abc");
                assert_eq!(Some(source), t.source_id());
                match *inner {
                    Ev::Control(p, v) => {
                        assert_eq!(p, "warm:abc");
                        assert_eq!(v["type"], "file-accept");
                    }
                    _ => panic!("expected a control event"),
                }
            }
            _ => panic!("expected a sourced event"),
        }
        t.send_frame(0x4000_0010, 0, b"hello").await.unwrap();
        t.send_control(&json!({"type":"file-end","id":"s-1-1","sid":0x4000_0010u32})).await.unwrap();
        t.flush().await.unwrap();
        let (k, p) = seen.recv().await.unwrap();
        assert_eq!(k, WS_DATA);
        assert_eq!(decode_data(&p), Some((0x4000_0010, 0, &b"hello"[..])));
        let (k, p) = seen.recv().await.unwrap();
        assert_eq!(k, WS_CONTROL);
        assert_eq!(serde_json::from_slice::<Value>(&p).unwrap()["type"], "file-end");
        assert_eq!(seen.recv().await.unwrap().0, WS_FLUSH);
        // The daemon reports the link dead: the transport goes dead, the loop
        // is woken, and further writes fail instead of vanishing.
        kill_tx.send(()).unwrap();
        loop {
            match rx.recv().await.unwrap() {
                Ev::BuildWake => break,
                _ => continue,
            }
        }
        assert!(t.is_dead() && !t.is_alive());
        assert_eq!(t.idle_ms(), u64::MAX);
        assert!(t.send_frame(0x4000_0010, 5, b"x").await.is_err());
        assert!(t.flush().await.is_err());
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The daemon process going away mid-send (EOF, no close frame) is a dead
    /// link too, and a pending flush fails rather than waiting forever.
    #[tokio::test]
    async fn a_daemon_that_vanishes_mid_flush_fails_the_flush() {
        let dir = sock_dir("c");
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_req(&mut s).await;
            s.write_all(
                format!("{}\n", json!({"ok": true, "sid_base": 0x4000_0100u32, "max_payload": 65536, "link": "x"}))
                    .as_bytes(),
            )
            .await
            .unwrap();
            let (mut r, _w) = s.into_split();
            // Read the flush request, then vanish without answering it.
            let _ = read_frame(&mut r).await;
        });
        let link = try_send_link_at(&path, "box", &["s-2-1".to_string()]).await.expect("warm link");
        let t = link.transport.clone();
        let (tx, _rx) = mpsc::unbounded_channel();
        t.start(link.pid.clone(), tx);
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), t.flush()).await;
        assert!(matches!(r, Ok(Err(_))), "a flush on a vanished daemon must fail, not hang");
        assert!(t.is_dead());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reply naming a sid range that reaches into the L2 half is refused:
    /// file frames must never collide with the daemon's tunnel streams.
    #[tokio::test]
    async fn a_sid_range_in_the_l2_half_is_refused() {
        let dir = sock_dir("d");
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_req(&mut s).await;
            s.write_all(
                format!("{}\n", json!({"ok": true, "sid_base": 0x7FFF_FFFFu32, "max_payload": 65536}))
                    .as_bytes(),
            )
            .await
            .unwrap();
        });
        let ids = vec!["a".to_string(), "b".to_string()];
        assert!(try_send_link_at(&path, "box", &ids).await.is_none());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
