use super::*;
use super::pty_session::push_ring;
use super::terminal::{LocalTerminalReset, write_local_terminal_reset};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Mutex as StdMutex;

/// HARNESS-LEVEL SERIALIZATION for the three tests that acquire a GLOBAL PTY
/// slot. The slot pool and `LIVE_PTYS` are process-global, and these tests
/// assert against a PER-TEST baseline, so a slot held by a sibling test makes
/// the count 1 where the baseline was 0 (#330: 3 failures in 20 runs at
/// --test-threads=16).
///
/// Taken ONCE per test, at the top, and NEVER by the code under test -- so
/// there is no reentrancy and it cannot deadlock. That is the difference from
/// the #322 failure mode, which added a SECOND acquisition of a non-reentrant
/// mutex to a test that already held it.
static PTY_SLOT_TEST_LOCK: StdMutex<()> = StdMutex::new(());

/// Minimal in-memory Transport: records control messages, discards frames.
struct MockTransport {
    controls: StdMutex<Vec<Value>>,
    alive: bool,
    idle: u64,
    alive_checks: std::sync::atomic::AtomicUsize,
}
impl MockTransport {
    fn new() -> Arc<Self> {
        Self::new_with_alive(true)
    }
    fn new_with_alive(alive: bool) -> Arc<Self> {
        Self::new_with_state(alive, u64::MAX)
    }
    fn new_with_state(alive: bool, idle: u64) -> Arc<Self> {
        Arc::new(MockTransport {
            controls: StdMutex::new(Vec::new()),
            alive,
            idle,
            alive_checks: std::sync::atomic::AtomicUsize::new(0),
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
    fn idle_ms(&self) -> u64 {
        self.idle
    }
    fn is_dead(&self) -> bool {
        !self.alive
    }
    fn is_alive(&self) -> bool {
        self.alive_checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.alive
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// A PcState event can come from a losing WebRTC candidate after the direct
/// transport has won. It must not tear down streams on the selected mux;
/// the same event must tear them down once that selected transport is dead.
#[tokio::test]
async fn losing_pc_state_does_not_shutdown_live_selected_mux() {
    let selected = MockTransport::new_with_alive(true);
    let mux = Mux::new(selected.clone(), Arc::new(filament_peerloop::host::NoHost));
    let sid = L2_SID_BASE | 0x123;
    let mut stream = mux.register_stream(sid).await.expect("register stream");
    let (tx, rx) = mpsc::unbounded_channel();
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    // This candidate is not the selected transport represented by `mux`.
    tx.send(Ev::PcState("losing-candidate".into(), "disconnected".into()))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while selected.alive_checks.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pump did not process losing candidate state");
    assert_eq!(mux.live_streams().await, 1, "losing candidate tore down selected mux");
    mux.on_frame(sid, Bytes::from_static(b"still-live")).await;
    assert_eq!(
        stream.recv().await,
        Some(Some(Bytes::from_static(b"still-live"))),
        "stream remains usable after losing candidate state"
    );

    // A PcState notification while the selected transport is dead does
    // retire the mux, even though its event pid is another candidate.
    let dead_transport = MockTransport::new_with_alive(false);
    let dead_selected = Mux::new(dead_transport.clone(), Arc::new(filament_peerloop::host::NoHost));
    let _dead_stream = dead_selected
        .register_stream(sid + 1)
        .await
        .expect("register dead-link stream");
    let (dead_tx, dead_rx) = mpsc::unbounded_channel();
    let dead_pump = tokio::spawn(pump_initiator(dead_rx, dead_selected.clone()));
    dead_tx
        .send(Ev::PcState("candidate".into(), "failed".into()))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while dead_transport
            .alive_checks
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pump did not process dead selected transport state");
    assert_eq!(dead_selected.live_streams().await, 0, "dead selected transport retained streams");

    drop(tx);
    drop(dead_tx);
    let _ = pump.await;
    let _ = dead_pump.await;
}

#[test]
fn stall_observation_reports_dead_transport_down() {
    let dead = MockTransport::new_with_alive(false);
    let (transport_up, _flowed, idle_ms) =
        crate::Conn::stall_observation(Some(dead.as_ref()), &[]);
    assert!(!transport_up, "a dead transport must not be observed as up");
    assert_eq!(
        idle_ms,
        u64::MAX,
        "dead transport must not contribute activity"
    );
}

#[test]
fn stall_observation_uses_oldest_live_activity() {
    let primary = MockTransport::new_with_state(true, 9_000);
    let worker = MockTransport::new_with_state(true, 10);
    let workers: Vec<Arc<dyn Transport>> = vec![worker];
    let (transport_up, flowed, idle_ms) =
        crate::Conn::stall_observation(Some(primary.as_ref()), &workers);
    assert!(transport_up);
    assert!(flowed);
    assert_eq!(
        idle_ms, 9_000,
        "a recently active worker must not mask a stalled primary"
    );
}

/// H-1: opening + closing N PTY-style streams (register + resizer, then close)
/// leaves BOTH the stream table and the resizer map empty on every teardown
/// path, and the global PTY counter returns to zero.
#[tokio::test]
async fn pty_open_close_leaves_maps_empty() {
    let _slot_guard = PTY_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let start = LIVE_PTYS.load(Ordering::SeqCst);
    let mux = Mux::new(MockTransport::new(), Arc::new(filament_peerloop::host::NoHost));
    let n = 5u32;

    // Path A: inbound l2-close frees stream + resizer.
    for i in 0..n {
        let sid = L2_SID_BASE | (1000 + i);
        let guard = PtyGuard::try_acquire().expect("slot free");
        let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
        let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
        mux.register_resizer(sid, tx).await;
        assert_eq!(mux.live_streams().await, 1);
        assert_eq!(mux.live_resizers().await, 1);
        // Inbound l2-close (browser closed).
        mux.on_close(sid, None).await;
        drop(guard); // session task ending frees the global slot
        assert_eq!(mux.live_streams().await, 0, "stream not freed on l2-close");
        assert_eq!(
            mux.live_resizers().await,
            0,
            "resizer leaked on l2-close"
        );
    }

    // Path B: session task exit (drop_pty) frees stream + resizer.
    for i in 0..n {
        let sid = L2_SID_BASE | (2000 + i);
        let guard = PtyGuard::try_acquire().expect("slot free");
        let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
        let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
        mux.register_resizer(sid, tx).await;
        mux.drop_pty(sid).await; // a session task own exit path
        drop(guard);
        assert_eq!(mux.live_streams().await, 0, "stream not freed on drop_pty");
        assert_eq!(
            mux.live_resizers().await,
            0,
            "resizer leaked on drop_pty"
        );
    }

    // Path C: link/mux death (shutdown_all) frees everything.
    let mut guards = Vec::new();
    for i in 0..n {
        let sid = L2_SID_BASE | (3000 + i);
        guards.push(PtyGuard::try_acquire().expect("slot free"));
        let _rx = mux.register_stream(sid).await.expect("fresh sid registers");
        let (tx, _rrx) = mpsc::unbounded_channel::<(u16, u16)>();
        mux.register_resizer(sid, tx).await;
    }
    assert_eq!(mux.live_streams().await, n as usize);
    mux.shutdown_all().await;
    drop(guards);
    assert_eq!(
        mux.live_streams().await,
        0,
        "streams leaked past shutdown_all"
    );
    assert_eq!(
        mux.live_resizers().await,
        0,
        "resizers leaked past shutdown_all"
    );

    assert_eq!(
        LIVE_PTYS.load(Ordering::SeqCst),
        start,
        "global PTY count must return to baseline"
    );
}

/// H-1: the global PTY guard refuses acquisition once MAX_PTYS_GLOBAL slots
/// are held, and frees them on drop.
#[tokio::test]
async fn global_pty_cap_is_enforced() {
    let _slot_guard = PTY_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // With the lock held no sibling test is in the pool, and the baseline
    // logic below stays anyway: it makes the assertion robust rather than
    // dependent on how many slots this test could take.
    let mut held = Vec::new();
    while LIVE_PTYS.load(Ordering::SeqCst) < MAX_PTYS_GLOBAL {
        match PtyGuard::try_acquire() {
            Some(g) => held.push(g),
            None => break,
        }
    }
    assert_eq!(LIVE_PTYS.load(Ordering::SeqCst), MAX_PTYS_GLOBAL);
    assert!(
        PtyGuard::try_acquire().is_none(),
        "must refuse at global cap"
    );
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
        Arc::new(CapTransport {
            frames: StdMutex::new(Vec::new()),
            controls: StdMutex::new(Vec::new()),
        })
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
    async fn send_frame(&self, sid: u32, _offset: u64, payload: &[u8]) -> Result<()> {
        self.frames.lock().unwrap().push((sid, payload.to_vec()));
        Ok(())
    }
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn max_payload(&self) -> usize {
        1024
    }
    fn is_dead(&self) -> bool {
        false
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The owner-reported failure: `tunlion shell <sibling>` over the fleet
/// channel (no daemon broker, as on Windows) died as "can't reach" whenever
/// another fleet device's offer or answer came first. The dial must hold an
/// offer from a device it is not dialing, replay it when that device's turn
/// comes, and after a candidate proves to be someone else, skip it and its
/// offers instead of ending the connect.
#[test]
fn fleet_dial_holds_other_offers_and_skips_a_rejected_candidate() {
    let mut f = FleetDial::default();
    let offer = |from: &str| json!({ "from": from, "data": { "type": "transport-offer" } });

    // Ordering only: the device calling itself the target goes first.
    assert_eq!(f.presence("sid-charlie", Some("Charlie"), "charlie"), Some(true));
    assert_eq!(f.presence("sid-alpha", Some("alpha"), "charlie"), Some(false));
    assert_eq!(f.presence("sid-anon", None, "charlie"), Some(false));

    // Dialing alpha: charlie's offer is held, not raced against alpha.
    assert!(f.offer(&offer("sid-alpha"), Some("sid-alpha")));
    assert!(!f.offer(&offer("sid-charlie"), Some("sid-alpha")));
    assert!(!f.offer(&offer("sid-charlie"), None));

    // alpha proved a different identity: rejected, never queued or raced again.
    f.reject("sid-alpha");
    assert_eq!(f.presence("sid-alpha", Some("charlie"), "charlie"), None);
    assert!(!f.offer(&offer("sid-alpha"), Some("sid-alpha")));
    assert_eq!(f.on_dial("sid-alpha"), None);

    // charlie's turn: its held offer comes back exactly once.
    assert_eq!(f.on_dial("sid-charlie"), Some(offer("sid-charlie")));
    assert_eq!(f.on_dial("sid-charlie"), None);
}

/// The one-shot fleet exec path: the target answers the hello on the direct
/// QUIC connection, whose reader tags the frame with the transport's
/// `SourceId`. Verification must read that shape; it used to see only the
/// untagged one and wait out its deadline while the peer had already
/// answered.
#[test]
fn fleet_verify_reads_a_source_attributed_direct_control() {
    let pid = "sid-direct";
    let source = net::SourceId::next();
    let other = net::SourceId::next();
    let hello = json!({ "type": crate::fleet::HELLO, "name": "charlie" });
    let ev = Ev::Sourced {
        pid: pid.to_string(),
        source,
        inner: Box::new(Ev::Control(pid.to_string(), hello.clone())),
    };

    assert_eq!(control_for_link(&ev, pid, Some(source)), Some(&hello));
    // A control from another candidate is not this link's certificate.
    assert_eq!(control_for_link(&ev, "sid-other", Some(source)), None);
    // A lost connection with the same signaling id is not this link either:
    // its hello was bound to different keying material.
    assert_eq!(control_for_link(&ev, pid, Some(other)), None);
    // The untagged WebRTC/LAN shape keeps working.
    let plain = Ev::Control(pid.to_string(), hello.clone());
    assert_eq!(control_for_link(&plain, pid, None), Some(&hello));

    // The dial loop itself must see the event, not leave it in `Sourced`.
    match unsource_event(ev) {
        Ev::Control(from, v) => {
            assert_eq!(from, pid);
            assert_eq!(v, hello);
        }
        other => panic!("sourced control was not unwrapped: {other:?}"),
    }
}

/// After the link is selected, a late callback from a losing transport must
/// not reach the mux: an old `l2-close` would end a stream on the live link.
#[test]
fn the_selected_pump_reads_only_the_selected_transports_source() {
    let pid = "sid-direct";
    let selected = net::SourceId::next();
    let stale = net::SourceId::next();
    let tagged = |source| Ev::Sourced {
        pid: pid.to_string(),
        source,
        inner: Box::new(Ev::Control(
            pid.to_string(),
            json!({ "type": "l2-open-ack" }),
        )),
    };

    assert!(matches!(
        selected_event(tagged(selected), Some(selected)),
        Some(Ev::Control(..))
    ));
    let chunk = |source, inner: &str| Ev::Sourced {
        pid: pid.into(), source,
        inner: Box::new(Ev::Chunk(inner.into(), 42, Some(0), bytes::Bytes::from_static(b"data"))),
    };
    assert!(matches!(selected_event(chunk(selected, pid), Some(selected)), Some(Ev::Chunk(..))));
    assert!(selected_event(chunk(stale, pid), Some(selected)).is_none());
    assert!(selected_event(chunk(selected, "other"), Some(selected)).is_none());
    assert!(selected_event(Ev::Chunk(pid.into(), 42, Some(0), bytes::Bytes::new()), Some(selected)).is_none());
    // The source-tagged departure barrier is admitted on the source match.
    let departure = Ev::Sourced {
        pid: pid.into(), source: selected,
        inner: Box::new(Ev::PeerLeft(json!({ "id": pid }))),
    };
    assert!(matches!(selected_event(departure, Some(selected)), Some(Ev::PeerLeft(..))));
    let stale_departure = Ev::Sourced {
        pid: pid.into(), source: stale,
        inner: Box::new(Ev::PeerLeft(json!({ "id": pid }))),
    };
    assert!(selected_event(stale_departure, Some(selected)).is_none());
    assert!(
        selected_event(tagged(stale), Some(selected)).is_none(),
        "a stale transport's control reached the selected link's pump"
    );
    // Untagged events keep the pre-attribution behaviour.
    assert!(matches!(
        selected_event(
            Ev::Control(pid.to_string(), json!({ "type": "l2-open-ack" })),
            None
        ),
        Some(Ev::Control(..))
    ));
}

#[tokio::test]
async fn selected_reply_reader_accepts_exec_and_bootstrap_replies_not_stale_closes() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let selected = net::SourceId::next();
    let stale = net::SourceId::next();
    for kind in ["exec-open-ack", "shell-bootstrap-ack", "exec-close", "ssh-sign-response", "l2-close"] {
        tx.send(Ev::Sourced {
            pid: "peer".into(),
            source: stale,
            inner: Box::new(Ev::Control("peer".into(), json!({"type": "l2-close"}))),
        }).unwrap();
        tx.send(Ev::Sourced {
            pid: "peer".into(),
            source: selected,
            inner: Box::new(Ev::Control("peer".into(), json!({"type": kind}))),
        }).unwrap();
        match recv_selected_event(&mut rx, Some(selected)).await {
            Some(Ev::Control(_, value)) => assert_eq!(value["type"], kind),
            other => panic!("selected reply was not delivered: {other:?}"),
        }
    }
    drop(tx);
    assert!(recv_selected_event(&mut rx, Some(selected)).await.is_none());
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
    let _slot_guard = PTY_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
        None,
        false,
        None,
    )
    .await
    .expect("spawn");

    // Type a line on link A; cat echoes it back to sid_a.
    sess.feed_input(b"before-drop\n".to_vec());
    // Give the PTY threads + task a moment to echo and buffer.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let a_out = String::from_utf8_lossy(&ta.bytes_for(sid_a)).to_string();
    assert!(
        a_out.contains("before-drop"),
        "link A never saw the echo: {a_out:?}"
    );

    // Link A drops: detach (the shell MUST keep running).
    sess.detach();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!sess.is_dead(), "detach must NOT kill the session");

    // Reconnect: attach link B with the same session, new sid. The buffer
    // (including "before-drop") replays to sid_b.
    let tb = CapTransport::new();
    let sid_b = L2_SID_BASE | 2;
    let live = sessions
        .get_live("sess-x")
        .await
        .expect("session still live for reattach");
    live.attach(tb.clone(), sid_b, None);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let b_replay = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
    assert!(
        b_replay.contains("before-drop"),
        "reattach did not replay buffered output: {b_replay:?}"
    );

    // The SAME shell still works: type after reattach, see it on link B.
    live.feed_input(b"after-reconnect\n".to_vec());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b_out = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
    assert!(
        b_out.contains("after-reconnect"),
        "post-reattach input did not echo: {b_out:?}"
    );

    // Explicit end kills the shell and removes the session.
    live.end();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        sessions.get_live("sess-x").await.is_none(),
        "ended session must leave the store"
    );
}

/// A session that ends on its own runs the attachment release the library
/// installed. This is the path no receive-loop event reaches: the mux
/// stream/resizer must still be freed (regression: natural shell exit left
/// the sid registered until link death).
#[tokio::test]
async fn natural_session_exit_runs_the_installed_end_cleanup_once() {
    let _slot_guard = PTY_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !std::path::Path::new("/bin/sh").exists() {
        return; // environment without /bin/sh: skip rather than fail
    }
    let sessions = PtySessions::new();
    let t = CapTransport::new();
    let guard = PtyGuard::try_acquire().expect("slot");
    let sess = spawn_pty_session(
        sessions.clone(),
        "sess-natural-end".to_string(),
        t,
        L2_SID_BASE | 21,
        80,
        24,
        "xterm-256color",
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 0.2".to_string(),
        ],
        guard,
        None,
        false,
        None,
    )
    .await
    .expect("spawn");

    let cleaned = Arc::new(AtomicBool::new(false));
    let seen = cleaned.clone();
    assert!(
        sess.set_end_cleanup(Box::new(move || seen.store(true, Ordering::SeqCst))),
        "a live session accepts its release"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        cleaned.load(Ordering::SeqCst),
        "natural exit did not run the installed release"
    );
    assert!(
        sessions.get_live("sess-natural-end").await.is_none(),
        "ended session must leave the store"
    );
    assert!(
        !sess.set_end_cleanup(Box::new(|| {})),
        "an already-ended session tells the caller to release its own stream"
    );
}

/// A reattach that says how much output it already has gets only what it
/// missed: nothing it already showed comes back a second time, and output
/// produced while detached is not lost.
#[tokio::test]
async fn reattach_with_resume_from_replays_only_what_was_missed() {
    let _slot_guard = PTY_SLOT_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !std::path::Path::new("/bin/cat").exists() {
        return;
    }
    let sessions = PtySessions::new();
    let ta = CapTransport::new();
    let sid_a = L2_SID_BASE | 11;
    let guard = PtyGuard::try_acquire().expect("slot");
    let sess = spawn_pty_session(
        sessions.clone(),
        "sess-resume".to_string(),
        ta.clone(),
        sid_a,
        80,
        24,
        "xterm-256color",
        vec!["/bin/cat".to_string()],
        guard,
        None,
        false,
        None,
    )
    .await
    .expect("spawn");

    sess.feed_input(b"seen-on-a\n".to_vec());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = ta.bytes_for(sid_a);
    assert!(String::from_utf8_lossy(&seen).contains("seen-on-a"));

    // Drop, then produce output nobody is attached to see.
    sess.detach();
    tokio::time::sleep(Duration::from_millis(50)).await;
    sess.feed_input(b"while-away\n".to_vec());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Reattach saying "I have everything link A showed".
    let tb = CapTransport::new();
    let sid_b = L2_SID_BASE | 12;
    let live = sessions.get_live("sess-resume").await.expect("live");
    live.attach(tb.clone(), sid_b, Some(seen.len() as u64));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let b = String::from_utf8_lossy(&tb.bytes_for(sid_b)).to_string();
    assert!(!b.contains("seen-on-a"), "already-shown output was replayed again: {b:?}");
    assert!(b.contains("while-away"), "output produced while detached was lost: {b:?}");

    live.end();
    tokio::time::sleep(Duration::from_millis(150)).await;
}

#[test]
fn replay_skip_resumes_exactly_or_falls_back_to_the_whole_ring() {
    // 100 bytes produced, the ring holds the last 40 (bytes 60..100).
    assert_eq!(replay_skip(100, 40, Some(100)), 40, "up to date: replay nothing");
    assert_eq!(replay_skip(100, 40, Some(75)), 15, "replay bytes 75..100");
    assert_eq!(replay_skip(100, 40, Some(60)), 0, "exactly the ring start");
    assert_eq!(replay_skip(100, 40, Some(59)), 0, "behind the ring: whole ring");
    assert_eq!(replay_skip(100, 40, Some(101)), 0, "claims unproduced bytes: whole ring");
    assert_eq!(replay_skip(100, 40, None), 0, "client did not say: whole ring");
    assert_eq!(replay_skip(10, 10, Some(4)), 4, "ring holds everything");
}

/// A reconnect must not guess terminal state from PTY read boundaries.
/// In particular an unfinished CSI/OSC must join its continuation exactly,
/// and a disable followed by an enable must not be reordered by a "heal".
#[tokio::test]
async fn reattach_preserves_terminal_mode_bytes_without_injecting_resets() {
    let _slot_guard = PTY_SLOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for (index, (before, after)) in [
        ("\x1b[?1000l\x1b[?1000h\x1b[?1006h", "READY"),
        ("\x1b[?1000h\x1b[?1006", "hREADY"),
        ("\x1b]0;partial title", "\x07READY"),
        ("\x1b[?9h\x1b[?1005h", "READY"),
    ].into_iter().enumerate() {
        let Some(argv) = crate::platform::pty_mode_test_argv(before, after) else {
            return; // This fixture does not exercise interactive Windows consoles.
        };
        let sessions = PtySessions::new();
        let ta = CapTransport::new();
        // Exercise local lifecycle cleanup alongside a real session. Its
        // sink is deliberately separate from every transport/replay byte.
        let mut local_stdout = Vec::new();
        write_local_terminal_reset(&mut local_stdout, true, LocalTerminalReset::Entry).unwrap();
        assert!(ta.frames.lock().unwrap().is_empty());
        assert!(ta.controls.lock().unwrap().is_empty());
        let sid_a = L2_SID_BASE | 21;
        let id = format!("mode-continuation-{index}");
        let sess = spawn_pty_session(
            sessions.clone(), id.clone(), ta.clone(), sid_a, 80, 24,
            "xterm-256color",
            argv,
            PtyGuard::try_acquire().expect("slot"), None, false, None,
        ).await.expect("spawn");
        tokio::time::timeout(Duration::from_secs(5), async {
            while ta.bytes_for(sid_a).len() < before.len() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("initial output");
        let seen = ta.bytes_for(sid_a);
        assert_eq!(seen, before.as_bytes());

        // Both commands use one FIFO. No sleep is needed to ensure detach
        // precedes attach; the shell blocks until we send the continuation.
        sess.detach();
        let tb = CapTransport::new();
        let sid_b = L2_SID_BASE | 22;
        sess.attach(tb.clone(), sid_b, Some(seen.len() as u64));
        sess.feed_input(b"continue\n".to_vec());
        tokio::time::timeout(Duration::from_secs(5), async {
            while !tb.bytes_for(sid_b).ends_with(b"READY") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("continued output");
        assert_eq!(tb.bytes_for(sid_b), after.as_bytes(), "case {index}: synthetic bytes on reattach");

        // A second reconnect uses the same byte offsets and must not have
        // any synthetic output in its replay ring either.
        let tc = CapTransport::new();
        let sid_c = L2_SID_BASE | 23;
        sess.attach(tc.clone(), sid_c, Some(seen.len() as u64));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !tc.bytes_for(sid_c).ends_with(b"READY") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("second replay");
        assert_eq!(tc.bytes_for(sid_c), after.as_bytes(), "case {index}: replay ring changed");
        sess.end();
        tokio::time::timeout(Duration::from_secs(5), async {
            while sessions.get_live(&id).await.is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("session cleanup");
        write_local_terminal_reset(&mut local_stdout, true, LocalTerminalReset::Exit).unwrap();
        assert!(!local_stdout.is_empty());
        assert_eq!(ta.bytes_for(sid_a), before.as_bytes(), "local cleanup reached initial transport");
        assert_eq!(tb.bytes_for(sid_b), after.as_bytes(), "local cleanup reached resumed transport");
        assert_eq!(tc.bytes_for(sid_c), after.as_bytes(), "local cleanup reached replay transport");
    }
}

/// The retry hint must be a command the CLI ACCEPTS, not just one containing
/// the right words. The substring test below passed for months while the
/// hint printed `tunlion forward 8081 laptop 22`, which clap rejects; a
/// first-time user copied it and got "unexpected argument". Same parse
/// check fleet_ui/pair_ui uses for its suggestions.
#[test]
fn a_suggested_forward_command_parses() {
    use clap::Parser;
    let msg = port_in_use_msg(8080, "laptop", 22);
    let start = msg.find("e.g. ").expect("the message offers an example") + "e.g. ".len();
    let cmd = msg[start..].trim_end_matches(')').trim();
    let argv: Vec<&str> = cmd.split_whitespace().collect();
    assert!(
        crate::Cli::try_parse_from(&argv).is_ok(),
        "suggested command does not parse: {cmd}"
    );
    assert!(cmd.contains("--lport 8081"), "{cmd}");
}

/// The `port_in_use_msg` helper must surface the conflicting port and a
/// `tunlion forward <lport+1> <peer> <rport>` retry hint, so a user
/// staring at a "port in use" error can recover in one copy-paste.
#[test]
fn port_in_use_msg_names_port_and_suggests_forward() {
    let msg = port_in_use_msg(8080, "laptop", 22);
    assert!(
        msg.contains("8080"),
        "message must name the conflicting port: {msg}"
    );
    assert!(
        msg.contains("tunlion forward"),
        "message must suggest a tunlion forward retry: {msg}"
    );
    assert!(
        msg.contains("8081"),
        "suggested port should be lport+1: {msg}"
    );
    assert!(
        msg.contains("laptop"),
        "message should reference the peer: {msg}"
    );
    assert!(
        msg.contains("22"),
        "message should reference the rport: {msg}"
    );
}

/// The helper's `saturating_add` must not wrap when lport is u16::MAX, so
/// the user never sees a suggested port of 0 (which would still be valid
/// for binding but is a confusing retry hint).
#[test]
fn port_in_use_msg_saturates_at_u16_max() {
    let msg = port_in_use_msg(u16::MAX, "laptop", 22);
    assert!(
        msg.contains(&format!("{}", u16::MAX)),
        "must name the conflicting port: {msg}"
    );
    // u16::MAX.saturating_add(1) == u16::MAX, NOT 0.
    assert!(
        !msg.contains("0 "),
        "saturating add must not wrap to 0: {msg}"
    );
}

// ---- warm-reuse zombie self-heal (the popos pty/ssh hang) ----------------

/// THE proof for "tunlion definitively works no matter what": warm-reuse over
/// a ZOMBIE held link (alive at QUIC, black-holing new streams: NOTHING ever
/// arrives inbound) must NOT hang. `open_stream_verified` bails within the
/// window with an `Err`, removes the half-open stream, and sends an `l2-close`
/// so the peer reaps its half. The caller (handle_warm_open) then drops the
/// link and rejects, so the client falls through to a fresh establish.
/// Crucially it verifies BEFORE the client is committed, so the fallback is
/// instant - never the 25s ssh-ConnectTimeout stall an accepted-then-dead
/// connection would cause.
#[cfg(unix)]
#[tokio::test]
async fn warm_reuse_zombie_link_self_heals_instead_of_hanging() {
    let t = CapTransport::new();
    let mux = Mux::new(t.clone(), Arc::new(filament_peerloop::host::NoHost));

    let verdict = open_stream_verified(&mux, 22, std::time::Duration::from_millis(50)).await;

    assert!(
        verdict.is_err(),
        "a link that delivers no inbound frame must be a zombie Err"
    );
    assert_eq!(
        mux.live_streams().await,
        0,
        "zombie stream must be removed, not leaked"
    );
    let ctrls = t.controls.lock().unwrap();
    assert!(
        ctrls.iter().any(|c| c["type"] == "l2-open"),
        "must have attempted the open"
    );
    assert!(
        ctrls.iter().any(|c| c["type"] == "l2-close"),
        "must send l2-close so the peer reaps its half of the zombie stream"
    );
}

/// The flip side, proving the verify costs the happy path NOTHING and never
/// false-flags a live link: a HEALTHY link that delivers a first frame within
/// the window returns `Ok` with that frame preserved, and `serve_verified_stream`
/// replays it to the client byte-for-byte (no peer bytes lost to the probe).
#[cfg(unix)]
#[tokio::test]
async fn warm_reuse_healthy_link_passes_and_replays_first_frame() {
    let t = CapTransport::new();
    let mux = Mux::new(t.clone(), Arc::new(filament_peerloop::host::NoHost));

    // Drive open_stream_verified concurrently; as soon as it registers its
    // stream, deliver the peer's first frame (sshd banner / shell prompt).
    let mux2 = mux.clone();
    let h = tokio::spawn(async move {
        open_stream_verified(&mux2, 22, std::time::Duration::from_secs(5)).await
    });
    let sid = loop {
        if let Some(&sid) = mux.live_sids().await.first() {
            break sid;
        }
        tokio::task::yield_now().await;
    };
    mux.on_frame(sid, Bytes::from_static(b"BANNER")).await;

    let (got_sid, first, rx) = h
        .await
        .expect("task panicked")
        .expect("healthy link must be Ok");
    assert_eq!(got_sid, sid);
    assert_eq!(
        first,
        Some(Bytes::from_static(b"BANNER")),
        "first frame must be preserved for replay"
    );

    // serve_verified_stream replays `first` to the client verbatim.
    let (mut client, srv) = tokio::io::duplex(1024);
    let mux3 = mux.clone();
    let s = tokio::spawn(async move { serve_verified_stream(mux3, sid, srv, first, rx).await });
    let mut buf = [0u8; 6];
    client
        .read_exact(&mut buf)
        .await
        .expect("replayed frame must reach the client");
    assert_eq!(
        &buf, b"BANNER",
        "the verified first frame must be replayed verbatim"
    );

    mux.on_frame(sid, Bytes::new()).await; // peer FIN closes the writer pump
    drop(client); // client EOF closes the reader pump
    s.await.expect("serve task panicked");
}

/// The client-speaks-first case (HTTP, most DB clients): the peer sends NO app
/// bytes until we do, only the `l2-open-ack` confirming its local connect. Warm
/// verify must pass on that ack - not hang until the window expires and wrongly
/// drop a healthy link (the bug that sent every warm `forward` to a cold link) -
/// and replay it as ZERO bytes so the client sees no spurious data before its own
/// exchange.
#[cfg(unix)]
#[tokio::test]
async fn warm_reuse_client_first_link_passes_on_open_ack() {
    let t = CapTransport::new();
    let mux = Mux::new(t.clone(), Arc::new(filament_peerloop::host::NoHost));

    let mux2 = mux.clone();
    let h = tokio::spawn(async move {
        open_stream_verified(&mux2, 80, std::time::Duration::from_secs(5)).await
    });
    let sid = loop {
        if let Some(&sid) = mux.live_sids().await.first() {
            break sid;
        }
        tokio::task::yield_now().await;
    };
    // Only the acceptor's connect confirmation arrives - no app data yet.
    mux.on_open_ack(sid).await;

    let (got_sid, first, rx) = h
        .await
        .expect("task panicked")
        .expect("open-ack must prove the link live");
    assert_eq!(got_sid, sid);
    assert_eq!(
        first,
        Some(Bytes::new()),
        "the ack is an empty liveness marker"
    );

    // Replaying the empty ack writes nothing; real app data (sent only after the
    // client would have spoken) still reaches the client intact.
    let (mut client, srv) = tokio::io::duplex(1024);
    let mux3 = mux.clone();
    let s = tokio::spawn(async move { serve_verified_stream(mux3, sid, srv, first, rx).await });
    mux.on_frame(sid, Bytes::from_static(b"HTTP/1.1 200 OK"))
        .await;
    let mut buf = [0u8; 15];
    client
        .read_exact(&mut buf)
        .await
        .expect("real data must reach the client after the empty ack");
    assert_eq!(
        &buf, b"HTTP/1.1 200 OK",
        "the empty ack must not corrupt the stream"
    );

    mux.on_frame(sid, Bytes::new()).await;
    drop(client);
    s.await.expect("serve task panicked");
}
