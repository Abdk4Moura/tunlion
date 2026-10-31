//! Fault-injection tests for the serverless plain-pair carrier.
//!
//! Each test drives the shipping functions (`persist_plain`,
//! `persist_then_ack`, `stored_ack_within`, `start_signaling_claim`,
//! `store_after_signaling_claim`, `HostHandle::shutdown`) rather than a
//! parallel model. Only the timing seam in `test_seams` and the short ack
//! budget are test-only; both are compiled out of every production build.

use super::*;

use crate::pair_code::Carrier;
use crate::pair_cmd::{
    SignalingClaimStart, start_signaling_claim, store_after_signaling_claim,
};
use crate::tests::lock_test_config;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Barrier;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// A per-test `TUNLION_CONFIG_DIR`. The env var is process-global, so every
/// test in this file holds `TEST_CONFIG_LOCK` for its whole body, exactly as
/// the crate's existing isolated-store tests do.
struct ConfigDir {
    path: PathBuf,
    previous: Option<OsString>,
}

impl ConfigDir {
    fn new(tag: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tunlion-lan-fault-{tag}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let previous = std::env::var_os("TUNLION_CONFIG_DIR");
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &path) };
        Self { path, previous }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_devices(&self, records: &Value) {
        std::fs::write(
            self.path.join("devices.json"),
            serde_json::to_string_pretty(records).unwrap(),
        )
        .unwrap();
    }

    fn devices(&self) -> Vec<Value> {
        let raw = std::fs::read_to_string(self.path.join("devices.json")).unwrap_or_else(|_| "[]".into());
        serde_json::from_str(&raw).expect("devices.json stays a JSON list")
    }

    fn record<'a>(&self, records: &'a [Value], name: &str) -> Option<&'a Value> {
        records.iter().find(|d| d["name"].as_str() == Some(name))
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => unsafe { std::env::set_var("TUNLION_CONFIG_DIR", value) },
            None => unsafe { std::env::remove_var("TUNLION_CONFIG_DIR") },
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn valid_cert() -> crate::identity::DeviceCert {
    let key = crate::identity::UserKey::generate(&crate::platform::PlatformKeyStore)
        .expect("a fresh test identity key");
    crate::identity::DeviceCert::certify(&key, [0x11; 32], crate::identity::now_secs(), 3_600)
        .expect("a valid test certificate")
}

fn unique_dir(tag: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "tunlion-lan-link-{tag}-{}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A real loopback `filament-pair/1` session: the host side has a live
/// pairing listener and both sides hold the QUIC streams the production frame
/// helpers use.
struct LinkedPair {
    host: PairLink,
    peer: PairLink,
    _host_service: LanService,
    _peer_service: LanService,
    _host_dir: PathBuf,
    _peer_dir: PathBuf,
}

async fn connected_pair() -> LinkedPair {
    let host_dir = unique_dir("host");
    let peer_dir = unique_dir("peer");
    let (host_ev_tx, _host_ev_rx) = mpsc::unbounded_channel();
    let (pair_tx, mut pair_rx) = mpsc::channel(2);
    let host_service = LanService::start(
        &host_dir,
        Options { serve: true, pairing: Some([5; 16]), ..Default::default() },
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        Some(pair_tx),
        None,
        host_ev_tx,
    )
    .await
    .expect("host pairing service starts");
    let port = host_service.hello_json()["port"]
        .as_u64()
        .expect("host advertises its bound pairing port") as u16;
    let (peer_ev_tx, _peer_ev_rx) = mpsc::unbounded_channel();
    let peer_service = LanService::start(
        &peer_dir,
        Options::default(),
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        None,
        None,
        peer_ev_tx,
    )
    .await
    .expect("peer dial service starts");
    let mut peer = peer_service
        .pair_dial(vec![(Ipv4Addr::LOCALHOST, port).into()])
        .await
        .expect("pair dial completes");
    // QUIC `open_bi` is local until the first byte reaches the wire, so the
    // host's accept_bi cannot see the stream until this frame is written.
    pair_write(&mut peer.send, &json!({"type": "pake-msg", "v": 2}))
        .await
        .expect("the first frame opens the pairing stream");
    let host = tokio::time::timeout(Duration::from_secs(10), pair_rx.recv())
        .await
        .expect("host accepted the pair link")
        .expect("pair link channel is open");
    LinkedPair {
        host,
        peer,
        _host_service: host_service,
        _peer_service: peer_service,
        _host_dir: host_dir,
        _peer_dir: peer_dir,
    }
}

async fn dial_pair(port: u16) -> (PairLink, LanService, PathBuf) {
    let dir = unique_dir("dial");
    let (ev_tx, _ev_rx) = mpsc::unbounded_channel();
    let service = LanService::start(
        &dir,
        Options::default(),
        Arc::new(Vec::<filament_transport::lan::LanKey>::new),
        None,
        None,
        ev_tx,
    )
    .await
    .expect("dial service starts");
    let link = service
        .pair_dial(vec![(Ipv4Addr::LOCALHOST, port).into()])
        .await
        .expect("pair dial completes");
    (link, service, dir)
}

/// Wait until a UDP port that was bound by the service is free again.
async fn wait_for_port_free(port: u16) -> bool {
    for _ in 0..60 {
        if std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// 1. Durable store succeeded, provisional store failed, with a pre-existing
//    same-pair record and a real concurrent writer.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provisional_failure_keeps_the_durable_record_and_sends_no_ack() {
    let _guard = lock_test_config();
    let cfg = ConfigDir::new("provisional");
    let cert = valid_cert();
    let cert_pub = hex::encode(cert.device_pub);
    let secret = "same-pair-secret";
    cfg.write_devices(&json!([
        {
            "name": "laptop",
            "secret": secret,
            "deviceCert": cert.to_json(),
            "caps": ["transfer"],
            "v": 2
        },
        {"name": "phone", "secret": "phone-secret", "caps": ["transfer"], "v": 2}
    ]));

    // A real filesystem failure at the provisional path, not a mock: the
    // sidecar path is a directory, so SecretFile's atomic write must fail.
    std::fs::create_dir(cfg.path().join("provisional_laptop.json")).unwrap();

    let linked = connected_pair().await;
    let mut host = linked.host;
    let mut peer = linked.peer;

    // Hold the writer after the durable upsert and before the provisional
    // write, so the concurrent legitimate writer is guaranteed to run inside
    // that window rather than racing it by luck.
    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    test_seams::set_persist_pause(test_seams::PersistPause {
        reached: reached.clone(),
        release: release.clone(),
    });

    let outcome = Outcome {
        token: 1,
        peer_name: "laptop".into(),
        secret: secret.into(),
        cert: Some(cert.clone()),
        hello: json!({}),
    };
    let persist = tokio::spawn(async move {
        let result = persist_then_ack(&mut host, &outcome).await;
        (result, host)
    });

    // The writer is another real store operation in the same locked file. It
    // targets a different device so a rollback-by-name could only be caught
    // by the laptop record disappearing, never masked by this write.
    let (writer_done_tx, writer_done_rx) = tokio::sync::oneshot::channel();
    let writer = tokio::task::spawn_blocking(move || {
        reached.wait();
        crate::devices_store::devices_upsert_atomic(
            "phone",
            Some("phone-secret"),
            None,
            Some(&["transfer".to_string(), "mount".to_string()]),
            Some(crate::identity::IntroScope::Device.to_byte()),
            None,
            None,
            false,
        )
        .expect("the legitimate concurrent writer succeeds");
        let _ = writer_done_tx.send(());
    });
    writer_done_rx.await.expect("the concurrent writer completed");
    // Let the persisted side continue into the forced provisional failure,
    // only after the concurrent legitimate write has landed.
    release.wait();
    writer.await.unwrap();

    let (result, _host) = persist.await.expect("the persist task does not panic");
    let error = result.expect_err("a missing provisional identity must not report success");
    let message = format!("{error:#}");
    assert!(message.contains("durable record was kept"), "got: {message}");
    assert!(message.contains("no success is claimed"), "got: {message}");

    // No post-store frame reached the peer: `persist_then_ack` returns before
    // `stored_ack`, so there is no pair-stored nonce or acknowledgement.
    let peer_frame = tokio::time::timeout(Duration::from_millis(750), pair_read(&mut peer.recv)).await;
    match peer_frame {
        Err(_) => {}
        Ok(Ok(frame)) => panic!("the peer received a post-store frame after a failed persist: {frame}"),
        // A closed stream is also an honest non-ack; only a frame is a false ack.
        Ok(Err(_)) => {}
    }

    let records = cfg.devices();
    let laptop = cfg
        .record(&records, "laptop")
        .expect("the durable same-pair record was not deleted");
    assert_eq!(laptop["secret"].as_str(), Some(secret));
    assert_eq!(laptop["deviceCert"]["devicePub"].as_str(), Some(cert_pub.as_str()));
    let phone = cfg
        .record(&records, "phone")
        .expect("the concurrent legitimate writer's record survived");
    let phone_caps = phone["caps"].as_array().expect("caps array");
    assert!(phone_caps.iter().any(|c| c == "mount"), "the concurrent write landed");
    assert!(
        cfg.record(&records, "laptop-2").is_none(),
        "a same-pair record must not be renamed into a duplicate"
    );
    assert!(
        !cfg.path().join("provisional_laptop.json").is_file(),
        "the forced provisional failure stays failed"
    );
}

// ---------------------------------------------------------------------------
// 2. Post-store acknowledgement: loss, a wrong session, and a frame queued
//    before the exchange. Only a nonce-bound match is a mutual success.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_or_wrong_session_ack_is_local_unknown_not_mutual_success() {
    let linked = connected_pair().await;
    let mut host = linked.host;
    let mut peer = linked.peer;

    // The peer queues an ack for a DIFFERENT session before it has seen this
    // one's nonce, then reads the host nonce and stays silent.
    let peer_task = tokio::spawn(async move {
        pair_write(
            &mut peer.send,
            &json!({"type": "pair-stored", "v": 1, "ack_of": "another-session"}),
        )
        .await
        .expect("pre-queued wrong-session ack");
        let host_nonce = pair_read(&mut peer.recv)
            .await
            .expect("the host asked this session to acknowledge");
        host_nonce
    });

    let acked = stored_ack_within(&mut host, Duration::from_millis(800)).await;
    assert!(!acked, "a pre-queued wrong-session ack is not this session's success");
    assert_eq!(
        saved_claim(acked),
        "  saved here; the other device has not confirmed it saved"
    );
    assert!(!saved_claim(acked).contains("says it saved"));
    let host_nonce = peer_task.await.expect("peer task");
    assert!(host_nonce["nonce"].is_string(), "the host did send its own nonce");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nonce_bound_peer_ack_is_the_only_reason_to_say_it_saved() {
    let linked = connected_pair().await;
    let mut host = linked.host;
    let mut peer = linked.peer;

    let peer_task = tokio::spawn(async move {
        // Two adversarial frames first: one for another session, one with no
        // nonce at all. Neither may be read as this session's success.
        pair_write(
            &mut peer.send,
            &json!({"type": "pair-stored", "v": 1, "ack_of": "stale-session"}),
        )
        .await
        .expect("pre-queued stale ack");
        pair_write(&mut peer.send, &json!({"type": "pair-stored", "v": 1}))
            .await
            .expect("pre-queued nonce-less ack");
        let host_nonce = pair_read(&mut peer.recv)
            .await
            .expect("the host asked this session to acknowledge");
        let nonce = host_nonce["nonce"].as_str().expect("host nonce").to_string();
        // A stale ack still does not match; only the nonce-bound reply does.
        pair_write(
            &mut peer.send,
            &json!({"type": "pair-stored", "v": 1, "ack_of": "stale-session"}),
        )
        .await
        .expect("stale ack");
        pair_write(
            &mut peer.send,
            &json!({"type": "pair-stored", "v": 1, "ack_of": nonce}),
        )
        .await
        .expect("the matching ack");
        // Keep the link open until the host has had time to read the frame;
        // dropping it at once can turn a valid ack into a stream-closed race.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    let acked = stored_ack_within(&mut host, Duration::from_secs(2)).await;
    peer_task.await.expect("peer task");
    assert!(acked, "a nonce-bound acknowledgement is the only mutual success");
    assert_eq!(saved_claim(acked), "  the other device says it saved this pairing");
    assert!(saved_claim(true).contains("says it saved"));
}

// ---------------------------------------------------------------------------
// 3. The real pair_cmd coordinator seam: a delayed or missing PairUsed leaves
//    no token, and no token means no store. One carrier wins; a stale loser
//    still stores nothing.
// ---------------------------------------------------------------------------

#[test]
fn a_missing_pair_used_token_cannot_reach_the_real_store() {
    let _guard = lock_test_config();
    let cfg = ConfigDir::new("missing-used");
    let code = PairCode::new([3; 16], Instant::now());
    let now = Instant::now();
    let mut token = None;

    let error = store_after_signaling_claim(Some(&code), token, now, || {
        crate::devices_store::devices_upsert_atomic(
            "late",
            Some("late-secret"),
            None,
            Some(&["transfer".to_string()]),
            Some(crate::identity::IntroScope::Device.to_byte()),
            None,
            None,
            false,
        )
    })
    .expect_err("a host without a claim token must not store");
    assert!(
        error.to_string().contains("without a signaling claim token"),
        "got: {error}"
    );
    assert!(
        !cfg.path().join("devices.json").exists(),
        "the store closure must not have run"
    );

    // The delayed PairUsed finally arrives: the same seam acquires the token,
    // and only then does the real store run.
    assert_eq!(
        start_signaling_claim(&code, &mut token, now + Duration::from_secs(1)),
        SignalingClaimStart::Started
    );
    let name = store_after_signaling_claim(
        Some(&code),
        token,
        now + Duration::from_secs(2),
        || {
            crate::devices_store::devices_upsert_atomic(
                "late",
                Some("late-secret"),
                None,
                Some(&["transfer".to_string()]),
                Some(crate::identity::IntroScope::Device.to_byte()),
                None,
                None,
                false,
            )
        },
    )
    .expect("the delayed claim stores");
    assert_eq!(name, "late");
    assert!(
        cfg.device_exists("late"),
        "the delayed token reached the real store"
    );
}

impl ConfigDir {
    fn device_exists(&self, name: &str) -> bool {
        self.devices().iter().any(|d| d["name"].as_str() == Some(name))
    }
}

#[test]
fn one_carrier_wins_and_a_stale_loser_stores_nothing() {
    let _guard = lock_test_config();
    let cfg = ConfigDir::new("stale-loser");
    let now = Instant::now();

    // A LAN carrier wins the code while the signaling carrier is still busy.
    let code = PairCode::new([4; 16], now);
    let lan_token = match code.begin(Carrier::Lan, now) {
        Begin::Started(t) => t,
        other => panic!("LAN carrier starts: {other:?}"),
    };
    assert!(code.confirm(lan_token, now + Duration::from_secs(1)));
    let mut signaling_token = None;
    assert_eq!(
        start_signaling_claim(&code, &mut signaling_token, now + Duration::from_secs(2)),
        SignalingClaimStart::Blocked
    );
    assert!(signaling_token.is_none(), "a consumed code hands out no token");
    let error = store_after_signaling_claim(Some(&code), signaling_token, now + Duration::from_secs(2), || {
        crate::devices_store::devices_upsert_atomic(
            "loser",
            Some("loser-secret"),
            None,
            Some(&["transfer".to_string()]),
            Some(crate::identity::IntroScope::Device.to_byte()),
            None,
            None,
            false,
        )
    })
    .expect_err("the losing carrier stores nothing");
    assert!(error.to_string().contains("without a signaling claim token"), "got: {error}");
    assert!(!cfg.device_exists("loser"), "the loser's closure never ran");

    // A stale signaling token (released by a failed attempt, then superseded
    // by a LAN winner) is just as unable to store.
    let code = PairCode::new([6; 16], now);
    let mut token = None;
    assert_eq!(
        start_signaling_claim(&code, &mut token, now),
        SignalingClaimStart::Started
    );
    let stale = token.expect("signaling token");
    code.fail(stale, now);
    let lan_token = match code.begin(Carrier::Lan, now + Duration::from_secs(10)) {
        Begin::Started(t) => t,
        other => panic!("LAN carrier starts after backoff: {other:?}"),
    };
    assert!(code.confirm(lan_token, now + Duration::from_secs(11)));
    let error = store_after_signaling_claim(Some(&code), Some(stale), now + Duration::from_secs(12), || {
        crate::devices_store::devices_upsert_atomic(
            "stale",
            Some("stale-secret"),
            None,
            Some(&["transfer".to_string()]),
            Some(crate::identity::IntroScope::Device.to_byte()),
            None,
            None,
            false,
        )
    })
    .expect_err("a stale token must not store");
    assert!(
        error.to_string().contains("already used by a nearby device"),
        "got: {error}"
    );
    assert!(!cfg.device_exists("stale"), "the stale closure never ran");
}

// ---------------------------------------------------------------------------
// 4. Forced host cancel after a real ceremony failure: the listener, service
//    tasks and ceremony task are all closed or joined, leaving no orphan pair
//    service.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_host_closes_its_listener_and_joins_its_ceremony_task() {
    let _guard = lock_test_config();
    let cfg = ConfigDir::new("host-cancel");
    let code = PairCode::new([9; 16], Instant::now());
    let mut host = spawn_host(code.clone(), "brave otter".into(), "3141".into())
        .await
        .expect("the host starts on the real LanService");
    let port = host.svc.hello_json()["port"]
        .as_u64()
        .expect("the host advertises its listener") as u16;
    assert_ne!(port, 0);

    // Force a real ceremony failure on a real QUIC link: an identity-expose
    // before key confirmation is refused by `run_ceremony`.
    let (mut peer, _peer_service, _peer_dir) = dial_pair(port).await;
    pair_write(&mut peer.send, &json!({"type": "identity-expose", "v": 2}))
        .await
        .expect("send the out-of-phase frame");
    let event = tokio::time::timeout(Duration::from_secs(10), host.events.recv())
        .await
        .expect("the host reports the failed ceremony")
        .expect("the host event channel is open");
    match event {
        HostEvent::Failed { why, .. } => {
            assert!(why.contains("before key confirmation"), "got: {why}");
        }
        other => panic!("expected a failed ceremony, got {other:?}"),
    }

    // The production cancellation path (`pair_cmd`'s finally block) calls this.
    host.shutdown().await;

    assert!(host.task.is_finished(), "the ceremony task was joined");
    assert!(
        wait_for_port_free(port).await,
        "the pairing listener port {port} stayed bound after cancel"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), host.events.recv())
            .await
            .expect("the event channel closes promptly")
            .is_none(),
        "the host event channel must close, not stay open"
    );
    assert!(code.winner().is_none(), "a failed ceremony must not claim a winner");
    let _ = cfg;
}
