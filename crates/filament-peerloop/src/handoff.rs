//! Make-before-break promotion of a serving WebRTC link to direct QUIC.
//!
//! After a one-time code's PAKE confirms, both ends hold an authenticated
//! WebRTC link and race direct QUIC keyed by the ceremony secret. The link that
//! is already up carries the transfer at once; the direct link, when it wins,
//! takes over at a clean boundary instead of the WebRTC link being torn down
//! first and the transfer waiting for QUIC (the old "Option A", which cost
//! 1.35 to 1.5 s between `authenticated` and the first byte on every
//! cross-network code transfer, and a rebuild when QUIC never came up).
//!
//! The boundary is a round trip on the serving channel, led by the end that
//! sends the data:
//!
//! ```text
//! sender                                      receiver
//!   frames ... (WebRTC)
//!   [gate closed: no frame in flight]
//!   path-promote (WebRTC, after every frame) ->
//!                                             processes every frame first
//!                                             (one ordered channel), moves
//!                                 <- path-promoted (WebRTC)
//!   [gate opens on QUIC]
//!   frames ..., file-end (QUIC)  ->
//! ```
//!
//! Nothing is resent and nothing is renegotiated: the stream keeps its offsets
//! and continues on the new path from the next chunk. The receiver writes every
//! chunk at its absolute offset, so the only property the barrier has to buy is
//! ordering, and it buys exactly that: no byte, and no `file-end`, can reach the
//! receiver on the direct link before every byte the old link carried has been
//! dispatched. A receiver that has no verified direct link answers
//! `path-declined` and the transfer never leaves WebRTC.
//!
//! This module is the sender's half of the barrier: a [`Transport`] that
//! forwards to whichever path currently serves, and closes its frame gate for
//! the length of the round trip. Control messages are never gated, so the event
//! loop that sends them can never be parked on the peer's answer; until the
//! answer they keep riding the old path, which the receiver keeps reading for a
//! grace after it moves.

use anyhow::Result;
use filament_transport::net::Transport;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::oneshot;

/// The sender asks to move (sent on the serving channel, after its last frame).
pub const PATH_PROMOTE: &str = "path-promote";
/// The receiver moved; every frame sent before the ask was processed first.
pub const PATH_PROMOTED: &str = "path-promoted";
/// The receiver has no verified direct link; stay on the serving one.
pub const PATH_DECLINED: &str = "path-declined";
/// The sender stopped waiting for an answer; the receiver must not move.
pub const PATH_STAY: &str = "path-stay";

pub fn message(kind: &str) -> Value {
    serde_json::json!({ "type": kind, "v": 1 })
}

/// How a handoff ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    /// Frames now ride the new path.
    Moved,
    /// The ask could not be written (the old path is dead): nothing changed.
    AskFailed,
    /// The peer declined, or the promotion was abandoned: the old path serves.
    Declined,
    /// No answer within the backstop; `path-stay` was sent and the old path
    /// serves.
    TimedOut,
}

/// A transport whose underlying path can be replaced at a frame boundary.
pub struct HandoffTransport {
    current: RwLock<Arc<dyn Transport>>,
    /// Every `send_frame` holds this for reading while its frame is written; a
    /// handoff holds it for writing from before the ask until the answer. tokio's
    /// lock is fair, so once a handoff is waiting no new frame starts, and the
    /// ask is written only after the frames already started have finished.
    frames: tokio::sync::RwLock<()>,
    /// The ask is on the wire. An answer that arrives before it cannot be an
    /// answer to it, and must not open the gate.
    asked: AtomicBool,
}

impl HandoffTransport {
    pub fn wrap(inner: Arc<dyn Transport>) -> Arc<Self> {
        Arc::new(HandoffTransport {
            current: RwLock::new(inner),
            frames: tokio::sync::RwLock::new(()),
            asked: AtomicBool::new(false),
        })
    }

    /// The path frames and control go to right now.
    pub fn current(&self) -> Arc<dyn Transport> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set(&self, next: Arc<dyn Transport>) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    }

    /// Has the ask been written? Only then can the peer's answer be one.
    pub fn asked(&self) -> bool {
        self.asked.load(Ordering::SeqCst)
    }

    /// Is `t` this wrapper's current path?
    pub fn serves_on(&self, t: &Arc<dyn Transport>) -> bool {
        Arc::ptr_eq(&self.current(), t)
    }

    /// Run the barrier. Waits for any frame already being written, sends `ask`
    /// on the current path, then holds new frames until `answer` resolves:
    /// `Some(next)` moves every later frame and control message to `next`;
    /// `None` or a dropped sender leaves the current path serving. With no
    /// answer within `backstop` it sends `stay` (still behind the gate, so it is
    /// ordered after the ask and before any later frame) and stays.
    pub async fn hand_off(
        &self,
        ask: &Value,
        stay: &Value,
        answer: oneshot::Receiver<Option<Arc<dyn Transport>>>,
        backstop: Duration,
    ) -> Handoff {
        let _no_frames = self.frames.write().await;
        let serving = self.current();
        if serving.send_control(ask).await.is_err() {
            return Handoff::AskFailed;
        }
        self.asked.store(true, Ordering::SeqCst);
        match tokio::time::timeout(backstop, answer).await {
            Ok(Ok(Some(next))) => {
                self.set(next);
                Handoff::Moved
            }
            Ok(Ok(None)) | Ok(Err(_)) => Handoff::Declined,
            Err(_) => {
                let _ = serving.send_control(stay).await;
                Handoff::TimedOut
            }
        }
    }

    /// The peer moved without our barrier completing (its answer crossed our
    /// `path-stay`). Follow it: the old path is about to close.
    pub fn force_switch(&self, next: Arc<dyn Transport>) {
        self.set(next);
    }
}

#[async_trait::async_trait]
impl Transport for HandoffTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        self.current().send_control(msg).await
    }
    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        let _frame = self.frames.read().await;
        self.current().send_frame(sid, offset, payload).await
    }
    async fn flush(&self) -> Result<()> {
        self.current().flush().await
    }
    async fn drain_finish(&self) -> Result<()> {
        self.current().drain_finish().await
    }
    fn max_payload(&self) -> usize {
        self.current().max_payload()
    }
    fn sid_answerer(&self) -> bool {
        self.current().sid_answerer()
    }
    fn idle_ms(&self) -> u64 {
        self.current().idle_ms()
    }
    fn idle_ms_tracked(&self) -> Option<u64> {
        self.current().idle_ms_tracked()
    }
    fn heard_ms(&self) -> Option<u64> {
        self.current().heard_ms()
    }
    fn is_alive(&self) -> bool {
        self.current().is_alive()
    }
    fn supports_datagrams(&self) -> bool {
        self.current().supports_datagrams()
    }
    fn is_dead(&self) -> bool {
        self.current().is_dead()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn force_close(&self) {
        self.current().force_close()
    }
    async fn open_stream(
        &self,
    ) -> Option<(quinn::SendStream, quinn::RecvStream, quinn::Connection)> {
        self.current().open_stream().await
    }
    fn send_datagram(&self, packet: &[u8]) -> Result<()> {
        self.current().send_datagram(packet)
    }
    async fn recv_datagram(&self) -> Result<bytes::Bytes> {
        self.current().recv_datagram().await
    }
    fn max_datagram_size(&self) -> Option<usize> {
        self.current().max_datagram_size()
    }
    fn channel_binding(&self) -> Option<Vec<u8>> {
        self.current().channel_binding()
    }
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.current().remote_addr()
    }
    fn quic_connection(&self) -> Option<quinn::Connection> {
        self.current().quic_connection()
    }
    fn rtt_ms(&self) -> Option<u64> {
        self.current().rtt_ms()
    }
    fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.current().local_ip()
    }
    fn has_flowed(&self) -> bool {
        self.current().has_flowed()
    }
}

/// `t` is a handoff wrapper.
pub fn as_handoff(t: &Arc<dyn Transport>) -> Option<&HandoffTransport> {
    t.as_any().downcast_ref::<HandoffTransport>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every frame offset and control type, in order, per path. A frame
    /// write can be held open to model a chunk still in flight on the old path.
    struct Path {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        hold: Option<Arc<tokio::sync::Notify>>,
    }

    #[async_trait::async_trait]
    impl Transport for Path {
        async fn send_control(&self, msg: &Value) -> Result<()> {
            let kind = msg["type"].as_str().unwrap_or("?").to_string();
            self.log.lock().unwrap().push(format!("{}:{kind}", self.name));
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, offset: u64, _payload: &[u8]) -> Result<()> {
            if let Some(h) = &self.hold {
                h.notified().await;
            }
            self.log.lock().unwrap().push(format!("{}:{offset}", self.name));
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            4
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn path(name: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Arc<dyn Transport> {
        Arc::new(Path { name, log: log.clone(), hold: None })
    }

    fn entries(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    /// The ordering the receiver depends on: every frame before the ask rides
    /// the old path, the ask follows them there, and no frame reaches the new
    /// path until the peer has answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn frames_move_only_after_the_answer_and_never_overtake_the_ask() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let old = path("old", &log);
        let new = path("new", &log);
        let h = HandoffTransport::wrap(old);
        let ht: Arc<dyn Transport> = h.clone();
        ht.send_frame(1, 0, b"aaaa").await.unwrap();
        let (answer, rx) = oneshot::channel();
        let hc = h.clone();
        let barrier = tokio::spawn(async move {
            hc.hand_off(&message(PATH_PROMOTE), &message(PATH_STAY), rx, Duration::from_secs(5))
                .await
        });
        // Let the handoff take the gate, then start a frame: it must wait.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sender = {
            let ht = ht.clone();
            tokio::spawn(async move { ht.send_frame(1, 4, b"bbbb").await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(entries(&log), vec!["old:0", "old:path-promote"], "a frame went out during the barrier");
        answer.send(Some(new.clone())).unwrap();
        assert_eq!(barrier.await.unwrap(), Handoff::Moved);
        sender.await.unwrap().unwrap();
        ht.send_control(&message("file-end")).await.unwrap();
        assert_eq!(
            entries(&log),
            vec!["old:0", "old:path-promote", "new:4", "new:file-end"]
        );
        assert!(h.serves_on(&new));
    }

    /// A frame already being written when the handoff starts finishes on the
    /// old path BEFORE the ask is written there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_ask_waits_for_a_frame_already_in_flight() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(tokio::sync::Notify::new());
        let old: Arc<dyn Transport> = Arc::new(Path {
            name: "old",
            log: log.clone(),
            hold: Some(release.clone()),
        });
        let h = HandoffTransport::wrap(old);
        let ht: Arc<dyn Transport> = h.clone();
        let inflight = {
            let ht = ht.clone();
            tokio::spawn(async move { ht.send_frame(1, 0, b"aaaa").await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (answer, rx) = oneshot::channel::<Option<Arc<dyn Transport>>>();
        let hc = h.clone();
        let barrier = tokio::spawn(async move {
            hc.hand_off(&message(PATH_PROMOTE), &message(PATH_STAY), rx, Duration::from_secs(5))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(entries(&log).is_empty(), "the ask overtook a frame in flight: {:?}", entries(&log));
        release.notify_one();
        inflight.await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(entries(&log), vec!["old:0", "old:path-promote"]);
        drop(answer);
        assert_eq!(barrier.await.unwrap(), Handoff::Declined);
    }

    /// A decline, and a promotion abandoned before it was answered, both leave
    /// the old path serving, with later frames on it.
    #[tokio::test]
    async fn a_decline_keeps_the_old_path() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let h = HandoffTransport::wrap(path("old", &log));
        let (answer, rx) = oneshot::channel();
        answer.send(None).unwrap();
        let got = h
            .hand_off(&message(PATH_PROMOTE), &message(PATH_STAY), rx, Duration::from_secs(5))
            .await;
        assert_eq!(got, Handoff::Declined);
        let ht: Arc<dyn Transport> = h.clone();
        ht.send_frame(1, 8, b"cccc").await.unwrap();
        assert_eq!(entries(&log), vec!["old:path-promote", "old:8"]);
    }

    /// No answer: `path-stay` follows the ask on the old path, before any later
    /// frame, so the peer can never move after we decided not to.
    #[tokio::test]
    async fn an_unanswered_ask_is_withdrawn_before_the_next_frame() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let h = HandoffTransport::wrap(path("old", &log));
        let (_answer, rx) = oneshot::channel::<Option<Arc<dyn Transport>>>();
        let got = h
            .hand_off(&message(PATH_PROMOTE), &message(PATH_STAY), rx, Duration::from_millis(50))
            .await;
        assert_eq!(got, Handoff::TimedOut);
        let ht: Arc<dyn Transport> = h.clone();
        ht.send_frame(1, 0, b"aaaa").await.unwrap();
        assert_eq!(entries(&log), vec!["old:path-promote", "old:path-stay", "old:0"]);
    }

    /// Control is never gated: the event loop that sends it must not wait on
    /// the peer's answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn control_is_not_held_by_the_barrier() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let h = HandoffTransport::wrap(path("old", &log));
        let (_answer, rx) = oneshot::channel::<Option<Arc<dyn Transport>>>();
        let hc = h.clone();
        let _barrier = tokio::spawn(async move {
            hc.hand_off(&message(PATH_PROMOTE), &message(PATH_STAY), rx, Duration::from_secs(30))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ht: Arc<dyn Transport> = h.clone();
        tokio::time::timeout(Duration::from_millis(500), ht.send_control(&message("pair-keep")))
            .await
            .expect("control waited on the barrier")
            .unwrap();
        assert_eq!(entries(&log), vec!["old:path-promote", "old:pair-keep"]);
    }
}
