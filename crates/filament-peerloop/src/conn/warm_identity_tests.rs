use super::*;
use std::sync::atomic::AtomicUsize;

/// A direct-QUIC-shaped transport whose liveness, activity and close are
/// observable. `idle_ms`/`heard_ms` let a test model a link that is quiet
/// but alive (an idle shell) without pretending it is dead.
struct FakeQuic {
    alive: AtomicBool,
    closes: AtomicUsize,
    /// `u64::MAX` = never moved a byte (the Transport default).
    idle_ms: u64,
    /// `None` = transport does not track peer-originated traffic (direct
    /// QUIC); `Some` = relay/DataChannel-style `heard_ms`.
    heard: Option<u64>,
    /// The explicit `dead` flag, separate from `alive`: a QUIC connection
    /// can report closed (`is_alive` false) before that flag latches.
    dead_flag: bool,
    /// True for the fixture where `is_alive` is false but the transport has
    /// not reported `is_dead` yet (a QUIC close before the flag latches).
    closed_not_dead: bool,
}
impl FakeQuic {
    fn with(
        idle_ms: u64,
        heard: Option<u64>,
        alive: bool,
        dead_flag: bool,
        closed_not_dead: bool,
    ) -> Arc<Self> {
        Arc::new(FakeQuic {
            alive: AtomicBool::new(alive),
            closes: AtomicUsize::new(0),
            idle_ms,
            heard,
            dead_flag,
            closed_not_dead,
        })
    }
    fn live() -> Arc<Self> {
        Self::with(u64::MAX, None, true, false, false)
    }
    fn idle(idle_ms: u64) -> Arc<Self> {
        Self::with(idle_ms, None, true, false, false)
    }
    fn relay(idle_ms: u64, heard_ms: u64) -> Arc<Self> {
        Self::with(idle_ms, Some(heard_ms), true, false, false)
    }
    fn with_activity(idle_ms: u64, heard_ms: Option<u64>) -> Arc<Self> {
        Self::with(idle_ms, heard_ms, true, false, false)
    }
    /// A transport that is actively moving bytes (idle 0ms).
    fn flowing() -> Arc<Self> {
        Self::with(0, None, true, false, false)
    }
    /// A relay link whose OWN keepalive writes keep `idle_ms` near zero
    /// while the peer has sent nothing (`heard_ms` is old).
    fn relay_writes_only() -> Arc<Self> {
        Self::with(0, Some(u64::MAX), true, false, false)
    }
    /// A relay link whose peer-originated `heard_ms` is fresh.
    fn relay_heard(heard_ms: u64) -> Arc<Self> {
        Self::with(u64::MAX, Some(heard_ms), true, false, false)
    }
    fn dead() -> Arc<Self> {
        Self::with(u64::MAX, Some(u64::MAX), false, true, false)
    }
    /// A WebRTC data channel that latched dead, as the trait sees it:
    /// dead, not alive, heard never.
    fn dead_data_channel() -> Arc<Self> {
        Self::with(u64::MAX, Some(u64::MAX), false, true, false)
    }
    /// QUIC has closed the connection (`is_alive` false) but the `dead`
    /// flag has not latched yet (`is_dead` false).
    fn closed_not_dead() -> Arc<Self> {
        Self::with(u64::MAX, None, false, false, true)
    }
}
#[async_trait::async_trait]
impl Transport for FakeQuic {
    async fn send_control(&self, _msg: &Value) -> Result<()> {
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
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
    fn is_dead(&self) -> bool {
        self.dead_flag || (!self.alive.load(Ordering::Relaxed) && !self.closed_not_dead)
    }
    fn idle_ms(&self) -> u64 {
        if self.is_dead() {
            return u64::MAX;
        }
        self.idle_ms
    }
    fn heard_ms(&self) -> Option<u64> {
        self.heard
    }
    fn force_close(&self) {
        self.closes.fetch_add(1, Ordering::Relaxed);
        self.alive.store(false, Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The link `adopt_direct` builds on the dialer: named by PETNAME, while
/// the roster entry for the same sid carries the DISPLAY name.
fn direct_link(pid: &str, petname: &str, display: &str, t: Arc<dyn Transport>) -> Link {
    let source = t.source_id().unwrap_or(net::SourceId::UNASSIGNED);
    let attempt = t.attempt_id();
    Link {
        peer: None,
        info: json!({ "id": pid, "name": display }),
        name: petname.to_string(),
        uid: None,
        transport: Some(t),
        workers: vec![],
        generation: 7,
        source,
        attempt,
        worker_sources: SimHashSet::default(),
        attempts: 0,
        trusted: true,
        expected_secret: Some((petname.to_string(), "s3cret".to_string())),
        lan_binding: None,
        verified_name: Some(petname.to_string()),
        presence: Presence::Ready,
        direct: true,
        direct_route: "direct-quic",
        established_at: Some(Instant::now()),
        identity_device_pub: None,
        identity_user_pub: None,
        identity_binding: BindingStrength::None,
        identity_state: IdentityState::Pending,
        identity_cert_expires: None,
        principal_kind: PrincipalKind::OwnerDevice,
        host: Arc::new(crate::host::NoHost),
    }
}

/// The same link record on a non-direct (WebRTC/DataChannel/relay)
/// transport. `digest_link_active` keys the transport-bounded direct rule
/// on `direct`, so a relay fixture must not be built by `direct_link`.
fn relay_link(pid: &str, petname: &str, display: &str, t: Arc<dyn Transport>) -> Link {
    let mut l = direct_link(pid, petname, display, t);
    l.direct = false;
    l.direct_route = "relay";
    l
}

/// A direct link carrying the uid a same-device reconnect is matched on.
fn linked_direct(pid: &str, petname: &str, uid: &str, t: Arc<dyn Transport>) -> Link {
    let mut l = direct_link(pid, petname, &format!("user@{petname}"), t);
    l.uid = Some(uid.to_string());
    l
}

/// The host facts these tests need: the devices a warm-hold tick would dial.
/// Everything else is the host-free default. This replaces the old
/// `TUNLION_CONFIG_DIR` + `devices.json` setup, so the tests need no process
/// global and can run in parallel.
#[derive(Default)]
struct TestHost {
    devices: Vec<(String, String)>,
    fleet_rv: bool,
    /// Records the store still carries with their pair secret but which are
    /// REVOKED (`certRevoked` / terminal `principalState`).
    revoked_records: Vec<String>,
    /// Devices whose record denies the L0 transfer capability.
    denied_transfer: Vec<String>,
    /// Mirror the CLI host's baseline: `device_allows(_, "transfer")` is true
    /// for every live record. Off by default so pre-existing tests keep the
    /// inert-host answer.
    transfer_allowed: bool,
    /// The live store record's capability ceiling for `device_ceiling`.
    ceilings: Vec<(String, Vec<String>)>,
    /// Delegated (invited) records' ceilings for `principal_ceiling_for`.
    principal_ceilings: Vec<(String, Vec<String>)>,
}

#[async_trait::async_trait]
impl HostServices for TestHost {
    fn settings_get_str(&self, _key: &str) -> Option<String> {
        None
    }
    fn devices_load(&self) -> Vec<(String, String)> {
        self.devices.clone()
    }
    fn device_record_revoked(&self, name: &str) -> bool {
        self.revoked_records
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
    }
    fn device_capability_denied(&self, name: &str, capability: &str) -> bool {
        capability == "transfer"
            && self.denied_transfer.iter().any(|n| n.eq_ignore_ascii_case(name))
    }
    fn device_allows(&self, _name: &str, capability: &str) -> bool {
        self.transfer_allowed && capability == "transfer"
    }
    fn device_ceiling(&self, name: &str) -> Vec<String> {
        self.ceilings
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, caps)| caps.clone())
            .unwrap_or_default()
    }
    fn principal_ceiling_for(&self, name: &str) -> Option<Vec<String>> {
        self.principal_ceilings
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, caps)| caps.clone())
    }
    fn is_self_uid(&self, _my_uid: &str, _peer_uid: Option<&str>) -> bool {
        false
    }
    fn rejoin_unwarned(&self) -> Duration {
        Duration::from_secs(25)
    }
    fn relay_banner(&self) -> String {
        String::new()
    }
    fn relay_forbidden(&self) -> bool {
        false
    }
    fn channel_of(&self, secret: &str) -> String {
        format!("channel-of-{secret}")
    }
    fn roster_snapshot_json(&self) -> Option<String> {
        None
    }
    fn fleet_rv_present(&self) -> bool {
        self.fleet_rv
    }
    fn now_secs(&self) -> u64 {
        filament_id::now_secs()
    }
}

/// A `Conn` on a loopback signaling client, with a fresh ICE config cached
/// so no establish ever reaches for the network. Keep the returned socket
/// alive for the duration of the test.
async fn test_conn() -> (Conn, tokio::net::TcpStream, mpsc::UnboundedReceiver<Ev>) {
    test_conn_with_host(Arc::new(TestHost::default())).await
}

/// A `Conn` on a loopback signaling client over an explicit host, with a
/// fresh ICE config cached so no establish ever reaches for the network.
async fn test_conn_with_host(
    host: Arc<dyn HostServices>,
) -> (Conn, tokio::net::TcpStream, mpsc::UnboundedReceiver<Ev>) {
    let (sio, far) = filament_signal::Client::loopback()
        .await
        .expect("loopback client");
    let (tx, rx) = mpsc::unbounded_channel();
    // Port 9 (discard) on loopback: a config GET that does escape the cache
    // fails fast instead of hanging.
    let conn = Conn::for_command(
        filament_transport::TransportContext::default(),
        "http://127.0.0.1:9",
        sio,
        tx,
        "zz-me".to_string(),
        false,
        None,
        false,
        false,
        Arc::new(crate::host::NoLog),
        host,
    );
    lock_ice(&conn.ice_cache).cfg = Some((
        Instant::now(),
        net::ServerConfig {
            ice_servers: vec![],
            chunk_size: 16 * 1024,
        },
    ));
    (conn, far, rx)
}

/// Chaos finding 83681ee4ef: a daemon restarted under 20% loss met a
/// known peer before its `/api/whoami` answer was cached, and the
/// KnownPeer handler awaited candidate gathering inline (1224 ms against
/// the loop's 1000 ms budget). Gathering must never hold the caller; the
/// attempt is armed at once and a peer offer that arrives while we gather
/// is raced as soon as our candidates are in.
#[tokio::test]
async fn a_known_peer_dial_never_waits_for_candidate_gathering() {
    // A server that accepts and never answers: whoami waits out its timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut socks = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            socks.push(sock);
        }
    });
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    conn.server = format!("http://{addr}");
    let pid = "sid-alpha";
    conn.roster
        .insert(pid.into(), json!({ "id": pid, "uid": "uid-alpha" }));

    let started = Instant::now();
    conn.start_direct(pid, "alpha", "pair-secret").await;
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_millis(200),
        "arming a direct attempt waited {waited:?} for candidate gathering"
    );
    assert!(conn.direct_pending.contains_key(pid), "no direct attempt was armed");
    assert!(conn.direct_gathering_for(pid), "the attempt is not marked as gathering");
    // Still idempotent while gathering: a repeat KnownPeer arms nothing new.
    let attempt = conn.direct_pending[pid].attempt;
    conn.start_direct(pid, "alpha", "pair-secret").await;
    assert_eq!(conn.direct_pending[pid].attempt, attempt, "a repeat contact re-armed");

    // The peer's offer lands before our candidates: it waits for them.
    conn.on_transport_offer(pid, vec!["127.0.0.1:9".into()], None, None, 2);
    assert!(!conn.direct_pending[pid].racing, "raced before our candidates were gathered");

    // Gathering ends; the loop's pump hands it over and races the held offer.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            conn.pump_builds();
            if !conn.direct_gathering_for(pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("candidate gathering never reported back");
    let pending = &conn.direct_pending[pid];
    assert_eq!(pending.attempt, attempt);
    assert!(pending.racing, "the offer that arrived while gathering was not raced");
    assert!(
        pending.deadline <= Instant::now() + direct_ladder_budget(),
        "the ladder budget did not restart when gathering ended"
    );
    held.abort();
}

/// A gathering report for an attempt that was replaced or retired changes
/// nothing, and the peer offer it was holding is kept for the next
/// attempt, as an offer that finds no pending always is.
#[tokio::test]
async fn a_stale_gathering_report_touches_no_newer_attempt() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-bravo";
    let stale = net::AttemptId::next();
    conn.direct_gathering.insert(
        pid.into(),
        DirectGathering {
            attempt: stale,
            offer: Some((vec!["127.0.0.1:9".into()], None, None, 2, None)),
        },
    );
    conn.apply_direct_gathered(DirectGathered {
        pid: pid.into(),
        attempt: stale,
        punch_sock: None,
        my_srflx: None,
    });
    assert!(!conn.direct_gathering.contains_key(pid), "the stale gathering lingered");
    assert!(!conn.direct_pending.contains_key(pid), "a stale report armed an attempt");
    assert_eq!(
        conn.buffered_offers.get(pid).map(|s| s.offer.0.clone()),
        Some(vec!["127.0.0.1:9".to_string()]),
        "the held peer offer was lost"
    );
}

/// The live LAN regression: an exact authenticated DEVICE reservation that
/// is still the current store's binding must resolve for reach/send routing
/// even though the link stays untrusted and un-Proven. A revoked record
/// (which the store keeps, WITH its pair secret) must resolve nothing even
/// before the next sweep, and its LAN MAC key must not be offered.
#[tokio::test]
async fn an_exact_lan_device_binding_resolves_for_reach_and_send_without_trust() {
    fn lan_link(pid: &str) -> Link {
        let mut link = direct_link(pid, "boxb", "boxb", FakeQuic::flowing());
        link.trusted = false;
        link.verified_name = None;
        link.expected_secret = None;
        link.direct_route = filament_transport::lan::ROUTE_LAN;
        link.lan_binding = Some(LanBinding {
            name: "boxb".to_string(),
            device: Some(("boxb".to_string(), "s1".to_string())),
        });
        link
    }

    let host = Arc::new(TestHost {
        devices: vec![("boxb".to_string(), "s1".to_string())],
        transfer_allowed: true,
        ceilings: vec![("boxb".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let pid = "lan-live";
    conn.links.insert(pid.to_string(), lan_link(pid));

    assert!(
        warm_link_for(&conn, "boxb").is_some(),
        "reach could not route a live LAN device link"
    );
    assert!(
        conn.link_matches_device(pid, "boxb", "s1"),
        "send could not select the LAN target"
    );
    assert_eq!(conn.authenticated_lan_peer(pid).as_deref(), Some("boxb"));
    assert_eq!(
        conn.link_peer_name(pid).as_deref(),
        Some("boxb"),
        "reach-pong could not key a LAN link by its exact device binding"
    );
    assert!(!conn.link(pid).unwrap().trusted, "routing must not mint trust");
    assert!(
        conn.link(pid).unwrap().verified_name.is_none(),
        "routing must not mint a verified name"
    );

    // A re-pair (different secret) resolves nothing.
    assert!(!conn.link_matches_device(pid, "boxb", "other"));
    // A session-revoked binding resolves nothing.
    conn.revoked_bindings.insert("s1".to_string());
    assert!(warm_link_for(&conn, "boxb").is_none());
    assert_eq!(conn.authenticated_lan_peer(pid), None);

    // A record revoked on disk RETAINS its pair secret. With no sweep yet
    // (revoked_bindings empty) it must still never route, be selected, be
    // consented to, or yield a LAN MAC key.
    let revoked_host = Arc::new(TestHost {
        devices: vec![("boxb".to_string(), "s1".to_string())],
        revoked_records: vec!["boxb".to_string()],
        transfer_allowed: true,
        ceilings: vec![("boxb".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut revoked_conn, _far, _rx) = test_conn_with_host(revoked_host.clone()).await;
    revoked_conn.links.insert(pid.to_string(), lan_link(pid));
    assert!(revoked_conn.revoked_bindings.is_empty(), "no sweep has run yet");
    assert!(
        warm_link_for(&revoked_conn, "boxb").is_none(),
        "a revoked record with a retained secret routed reach"
    );
    assert!(!revoked_conn.link_matches_device(pid, "boxb", "s1"));
    assert_eq!(revoked_conn.authenticated_lan_peer(pid), None);
    assert!(revoked_conn.link_peer_name(pid).is_none());
    assert!(
        crate::lan_glue::keys(&*revoked_host).is_empty(),
        "a revoked record's retained secret was offered as a LAN MAC key"
    );

    // A REMOVED record (forgotten) has no live row, so it must also keep the
    // empty ceiling and never answer the pong registry.
    let removed_host = Arc::new(TestHost {
        devices: vec![],
        transfer_allowed: true,
        ceilings: vec![("boxb".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut removed_conn, _far, _rx) = test_conn_with_host(removed_host).await;
    removed_conn.links.insert(pid.to_string(), lan_link(pid));
    assert!(removed_conn.link_peer_name(pid).is_none());

    // A live record that DENIES transfer still routes (routing is not
    // permission) but must not earn the daemon's baseline auto-consent or a
    // ceiling from the record.
    let denied_host = Arc::new(TestHost {
        devices: vec![("boxb".to_string(), "s1".to_string())],
        denied_transfer: vec!["boxb".to_string()],
        transfer_allowed: true,
        ceilings: vec![("boxb".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut denied_conn, _far, _rx) = test_conn_with_host(denied_host).await;
    denied_conn.links.insert(pid.to_string(), lan_link(pid));
    assert!(warm_link_for(&denied_conn, "boxb").is_some());
    assert_eq!(denied_conn.authenticated_lan_peer(pid), None);
}

/// Re-adopting an EXISTING link over LAN starts its identity over. A link
/// that had proven a device key, or held sibling or owner standing, keeps
/// none of it when the LAN binding no longer resolves, and a LAN pair is
/// re-resolved from the record rather than inheriting the old key.
#[tokio::test]
async fn an_existing_link_adopted_over_lan_keeps_no_stale_identity() {
    fn stale(pid: &str, log: &Arc<std::sync::Mutex<Vec<String>>>) -> Link {
        let dead: Arc<dyn Transport> = Rec::new("dead-serving", log);
        dead.force_close();
        let mut link = relay_link(pid, "boxb", "boxb", dead);
        link.trusted = true;
        link.verified_name = Some("boxb".into());
        link.identity_device_pub = Some([7; 32]);
        link.identity_user_pub = Some([8; 32]);
        link.identity_binding = BindingStrength::Proven;
        link.identity_state = IdentityState::Resolved;
        link.identity_cert_expires = Some(u64::MAX);
        link.principal_kind = PrincipalKind::FleetSibling;
        link
    }
    for (what, host) in [
        (
            "revoked record",
            TestHost {
                devices: vec![("boxb".to_string(), "s1".to_string())],
                revoked_records: vec!["boxb".to_string()],
                ..Default::default()
            },
        ),
        ("forgotten record", TestHost::default()),
    ] {
        let (mut conn, _far, _rx) = test_conn_with_host(Arc::new(host)).await;
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pid = "sid-lan-stale";
        conn.links.insert(pid.into(), stale(pid, &log));
        let t: Arc<dyn Transport> = Rec::with_attempt("lan", &log, net::AttemptId::next());
        conn.seed_lan(pid, "boxb", "s1", false, t.attempt_id().unwrap());
        assert!(matches!(
            conn.adopt_direct(pid, t, filament_transport::lan::ROUTE_LAN),
            DirectAdoption::Adopted { tkey: None, .. }
        ));
        let link = &conn.links[pid];
        assert!(!link.trusted, "{what}: stale trust survived");
        assert!(link.verified_name.is_none(), "{what}: stale name survived");
        assert!(link.identity_device_pub.is_none(), "{what}: stale device key survived");
        assert!(link.identity_user_pub.is_none(), "{what}: stale user key survived");
        assert_eq!(link.identity_binding, BindingStrength::None, "{what}");
        assert!(link.identity_cert_expires.is_none(), "{what}");
        assert!(!matches!(link.identity_state, IdentityState::Resolved), "{what}");
        assert!(!link.fleet_proven(), "{what}: sibling standing survived");
        assert!(
            matches!(&link.principal_kind, PrincipalKind::Delegated { caps } if caps.is_empty()),
            "{what}: stale principal survived"
        );
        assert!(link.expected_secret.is_none(), "{what}: a worker key survived");
    }

    // A live binding: the pair, re-resolved, with no inherited key.
    let host = TestHost {
        devices: vec![("boxb".to_string(), "s1".to_string())],
        ..Default::default()
    };
    let (mut conn, _far, _rx) = test_conn_with_host(Arc::new(host)).await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lan-stale";
    conn.links.insert(pid.into(), stale(pid, &log));
    let t: Arc<dyn Transport> = Rec::with_attempt("lan", &log, net::AttemptId::next());
    conn.seed_lan(pid, "boxb", "s1", false, t.attempt_id().unwrap());
    assert!(matches!(
        conn.adopt_direct(pid, t, filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { tkey: None, .. }
    ));
    let link = &conn.links[pid];
    assert!(link.trusted);
    assert_eq!(link.verified_name.as_deref(), Some("boxb"));
    assert!(link.identity_device_pub.is_none(), "the old device key was inherited");
    assert!(matches!(link.principal_kind, PrincipalKind::OwnerDevice));
}

/// A LAN DEVICE link is the pair only while its exact binding is live. A
/// record revoked on disk (secret retained, no sweep yet) or a forgotten
/// record adopts untrusted, unnamed and with the empty ceiling, exactly
/// what the old blanket LAN rule gave every link. A session-revoked
/// binding is refused before adoption and installs no link at all.
#[tokio::test]
async fn a_lan_link_is_the_pair_only_while_its_binding_is_live() {
    async fn try_adopt(host: TestHost, session_revoked: bool) -> Option<Link> {
        let (mut conn, _far, _rx) = test_conn_with_host(Arc::new(host)).await;
        if session_revoked {
            conn.revoked_bindings.insert("s1".to_string());
        }
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pid = "sid-lan-binding";
        let t: Arc<dyn Transport> = Rec::with_attempt("lan", &log, net::AttemptId::next());
        let attempt = t.attempt_id().unwrap();
        conn.seed_lan(pid, "boxb", "s1", false, attempt);
        match conn.adopt_direct(pid, t, filament_transport::lan::ROUTE_LAN) {
            DirectAdoption::Adopted { tkey, .. } => {
                assert!(tkey.is_none(), "a LAN adoption minted a worker key");
                Some(conn.links.remove(pid).unwrap())
            }
            DirectAdoption::Rejected => {
                assert!(!conn.links.contains_key(pid));
                None
            }
            _ => panic!("unexpected LAN adoption outcome"),
        }
    }
    async fn adopt(host: TestHost) -> Link {
        try_adopt(host, false).await.expect("LAN adoption was refused")
    }
    fn live() -> TestHost {
        TestHost {
            devices: vec![("BoxB".to_string(), "s1".to_string())],
            transfer_allowed: true,
            ..Default::default()
        }
    }
    let pair = adopt(live()).await;
    assert!(pair.trusted);
    assert_eq!(
        pair.verified_name.as_deref(),
        Some("BoxB"),
        "the LAN pair must be named by the canonical stored petname"
    );
    assert!(matches!(pair.principal_kind, PrincipalKind::OwnerDevice));
    assert!(pair.expected_secret.is_none(), "a LAN link minted a worker key");

    // An invited (delegated) record is resolved at adoption like any pair
    // link: with no live certificate it is pinned to the empty ceiling,
    // never left owner-equivalent by the LAN route.
    let invited = TestHost {
        principal_ceilings: vec![("boxb".to_string(), vec!["transfer".to_string()])],
        ..live()
    };
    let invited = adopt(invited).await;
    assert!(
        matches!(&invited.principal_kind, PrincipalKind::Delegated { caps } if caps.is_empty()),
        "a delegated record over LAN was not resolved from its record"
    );

    let revoked = TestHost { revoked_records: vec!["boxb".to_string()], ..live() };
    let forgotten = TestHost { devices: vec![], ..live() };
    assert!(
        try_adopt(live(), true).await.is_none(),
        "a session-revoked LAN binding installed a link"
    );
    for (what, link) in [
        ("revoked record", adopt(revoked).await),
        ("forgotten record", adopt(forgotten).await),
    ] {
        assert!(!link.trusted, "{what}: LAN link was trusted");
        assert!(link.verified_name.is_none(), "{what}: LAN link was named");
        assert!(
            matches!(&link.principal_kind, PrincipalKind::Delegated { caps } if caps.is_empty()),
            "{what}: LAN link carried authority"
        );
    }
}

// --- the pure decision ------------------------------------------------

const CH: &str = "chan-of-x";

#[test]
fn display_name_roster_and_petname_direct_link_is_a_skip() {
    // THE defect: roster says `user@x`, the live direct link is named `x`.
    let roster = [WarmRosterView {
        pid: "sid-1",
        name: Some("user@x"),
        channel: Some(CH),
    }];
    let links = [WarmLinkView {
        pid: "sid-1",
        petname: Some("x"),
        name: "x",
        live: true,
    }];
    assert_eq!(
        warm_decide("x", Some(CH), &links, &roster, 0),
        WarmDecision::Skip {
            pid: "sid-1".into()
        }
    );
    // The pre-fix key (the display name) must not establish either: it is
    // not a paired-device key, but the sid is the live link's sid.
    assert_eq!(
        warm_decide("user@x", None, &links, &roster, 0),
        WarmDecision::Skip {
            pid: "sid-1".into()
        }
    );
}

#[test]
fn a_live_link_to_the_device_under_any_sid_or_name_is_a_skip() {
    // The device reconnected signaling (new sid) and an old daemon instance
    // left a ghost entry; the live link still runs on the original sid,
    // which is no longer in the roster at all. Petname identity carries it.
    let roster = [
        WarmRosterView {
            pid: "sid-ghost",
            name: Some("user@x"),
            channel: Some(CH),
        },
        WarmRosterView {
            pid: "sid-new",
            name: Some("user@x"),
            channel: Some(CH),
        },
    ];
    let links = [WarmLinkView {
        pid: "sid-old",
        petname: Some("x"),
        name: "x",
        live: true,
    }];
    for rotation in 0..4 {
        assert_eq!(
            warm_decide("x", Some(CH), &links, &roster, rotation),
            WarmDecision::Skip {
                pid: "sid-old".into()
            }
        );
    }
}

#[test]
fn no_live_link_dials_only_present_sids_of_the_device_and_rotates() {
    let roster = [
        WarmRosterView {
            pid: "sid-b",
            name: Some("user@x"),
            channel: Some(CH),
        },
        WarmRosterView {
            pid: "sid-a",
            name: Some("user@x"),
            channel: Some(CH),
        },
        // Same display name, different device: never this device's sid.
        WarmRosterView {
            pid: "sid-stranger",
            name: Some("user@x"),
            channel: Some("someone-elses-channel"),
        },
    ];
    // A dead link to the device does not count.
    let links = [WarmLinkView {
        pid: "sid-a",
        petname: Some("x"),
        name: "x",
        live: false,
    }];
    let pick = |r| match warm_decide("x", Some(CH), &links, &roster, r) {
        WarmDecision::Establish { pid } => pid,
        other => panic!("expected an establish, got {other:?}"),
    };
    assert_eq!(pick(0), "sid-a");
    assert_eq!(pick(1), "sid-b");
    assert_eq!(pick(2), "sid-a");
}

#[test]
fn an_absent_device_is_not_dialled() {
    let roster = [WarmRosterView {
        pid: "sid-other",
        name: Some("user@y"),
        channel: Some("chan-of-y"),
    }];
    assert_eq!(
        warm_decide("x", Some(CH), &[], &roster, 0),
        WarmDecision::Absent
    );
}

// --- the Conn paths ---------------------------------------------------

/// The required unit gate: warm_hold_tick with the roster entry `user@x`
/// and a live direct link named by petname `x` neither establishes nor
/// drops anything.
#[tokio::test]
async fn warm_hold_tick_keeps_a_live_direct_link_named_by_petname() {
    let host = Arc::new(TestHost {
        devices: vec![("x".to_string(), "s3cret".to_string())],
        ..Default::default()
    });
    let channel = host.channel_of("s3cret");

    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let t = FakeQuic::live();
    conn.links
        .insert("sid-1".into(), direct_link("sid-1", "x", "user@x", t.clone()));
    conn.roster.insert(
        "sid-1".into(),
        json!({ "id": "sid-1", "name": "user@x", "uid": "uid-x", "channel": channel }),
    );
    // A ghost from an earlier instance of the same device.
    conn.roster.insert(
        "sid-ghost".into(),
        json!({ "id": "sid-ghost", "name": "user@x", "uid": "uid-x", "channel": channel }),
    );

    for _ in 0..3 {
        let dialled = conn.warm_hold_tick(true).await;
        assert!(dialled.is_empty(), "warm-hold dialled {dialled:?} over a live link");
    }
    let l = conn.links.get("sid-1").expect("the live direct link must survive");
    assert_eq!(l.generation, 7, "the live direct link was replaced");
    assert!(l.direct);
    assert_eq!(t.closes.load(Ordering::Relaxed), 0, "the live transport was closed");
    assert!(conn.direct_pending.is_empty(), "a re-dial was armed");
    assert!(!conn.links.contains_key("sid-ghost"), "a ghost sid was dialled");
    assert!(conn.warm_hold.auto.contains("x"), "the device is warm-held by petname");
}

/// A live, certificate-admitted fleet sibling with no device record (no
/// pair secret, so the auto tier never holds it): the shape gate T2b reads.
fn cert_only_sibling(pid: &str, name: &str, t: Arc<dyn Transport>) -> Link {
    let mut l = direct_link(pid, name, &format!("user@{name}"), t);
    l.trusted = false;
    l.expected_secret = None;
    l.verified_name = Some(name.to_string());
    l.admit_fleet([1u8; 32], [2u8; 32], u64::MAX);
    l
}

/// The pair-link rule as every fleet arm site reads it, on real links: a
/// pair link whose secret the store still holds blocks the arm; the same
/// link after the device was forgotten (secret no longer held) does not;
/// a fleet-shaped link (untrusted, no pair secret) does not.
#[cfg(feature = "dispatch")]
#[tokio::test]
async fn a_fleet_arm_is_blocked_only_by_a_held_pair_link() {
    use crate::recv::dispatch::fleet_arm_blocked_by_pair_link as blocked;
    let (mut conn, _far, _rx) = test_conn().await;
    let held = vec![("dev".to_string(), "s3cret".to_string())];
    conn.links.insert("sid-p".into(), direct_link("sid-p", "dev", "user@dev", FakeQuic::live()));
    assert!(blocked(&conn, "sid-p", &held), "a fleet arm may take over a held pair link");
    assert!(!blocked(&conn, "sid-p", &[]), "a forgotten device's stale link blocked the arm");
    conn.links.insert("sid-f".into(), cert_only_sibling("sid-f", "sib", FakeQuic::live()));
    assert!(!blocked(&conn, "sid-f", &held), "a fleet link blocked the fleet arm");
    assert!(!blocked(&conn, "sid-none", &held), "a peer with no link blocked the arm");
}

/// One completed receive from a certificate-only sibling, with no other
/// stream in flight, leaves that sender warm, and the next warm tick
/// reports its live link as a FleetSibling without dialling. Before, the
/// warm tier was fed from the streams still in flight once something had
/// completed; the finished stream was already gone, so this sender was
/// never recorded and the tick never named it.
#[tokio::test]
async fn a_completed_receive_warms_its_certificate_only_sender() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(crate::host::VecLog::new());
    conn.log = log.clone() as Arc<dyn LogSink>;
    conn.links.insert(
        "sid-c".into(),
        cert_only_sibling("sid-c", "charlie", FakeQuic::live()),
    );

    // Nothing completed yet: not warm, and the tick says nothing of it.
    assert!(!conn.warm_hold.peers_to_connect().iter().any(|p| p == "charlie"));
    assert!(conn.warm_hold_tick(true).await.is_empty());
    assert!(
        !log.take().iter().any(|(_, l)| l.contains("warm-hold: skip 'charlie'")),
        "the tick named a sender before any transfer completed"
    );

    conn.note_completed_transfer("sid-c", Some("charlie"));
    assert!(
        conn.warm_hold.peers_to_connect().iter().any(|p| p == "charlie"),
        "the completed sender is not warm"
    );
    let dialled = conn.warm_hold_tick(true).await;
    assert!(dialled.is_empty(), "warm-hold dialled {dialled:?} over a live link");
    let lines = log.take();
    assert!(
        lines.iter().any(|(_, l)| l.contains("warm-hold: skip 'charlie'")
            && l.contains("principal=FleetSibling sibling=true")),
        "the tick did not report the live sibling link: {lines:?}"
    );
}

/// Two senders, one completes while the other is still in flight: the
/// one that COMPLETED is recorded, and only that one.
#[tokio::test]
async fn the_completed_sender_is_the_one_recorded() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.links.insert("sid-a".into(), cert_only_sibling("sid-a", "alpha", FakeQuic::live()));
    conn.links.insert("sid-b".into(), cert_only_sibling("sid-b", "bravo", FakeQuic::live()));
    conn.note_completed_transfer("sid-a", Some("alpha"));
    let warm = conn.warm_hold.peers_to_connect();
    assert!(warm.iter().any(|p| p == "alpha"), "the completed sender was not recorded");
    assert!(!warm.iter().any(|p| p == "bravo"), "the in-flight sender was recorded instead");
}

/// Only a PROVEN name is recorded. The live link's verified name wins;
/// with the link gone (the sender left before file-end) the name captured
/// when the stream was accepted is used; a link with no proven name and
/// nothing captured records nothing, whatever name the peer claimed.
#[tokio::test]
async fn a_completed_transfer_records_only_a_proven_name() {
    let (mut conn, _far, _rx) = test_conn().await;
    // The link is gone: the captured name stands in.
    conn.note_completed_transfer("sid-gone", Some("delta"));
    assert!(conn.warm_hold.peers_to_connect().iter().any(|p| p == "delta"));
    // An unproven link: its claimed petname is never recorded.
    let mut l = direct_link("sid-u", "mallory", "user@mallory", FakeQuic::live());
    l.verified_name = None;
    conn.links.insert("sid-u".into(), l);
    conn.note_completed_transfer("sid-u", None);
    assert!(
        !conn.warm_hold.peers_to_connect().iter().any(|p| p == "mallory"),
        "a claimed name was recorded as warm"
    );
}

#[tokio::test]
async fn establish_refuses_to_replace_a_live_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::live();
    conn.links
        .insert("sid-1".into(), direct_link("sid-1", "x", "user@x", t.clone()));
    conn.establish_as(json!({ "id": "sid-1", "name": "user@x", "uid": "uid-x" }), None)
        .await
        .expect("a refusal is not an error: the caller's link exists");
    let l = conn.links.get("sid-1").expect("the live link must survive");
    assert_eq!(l.generation, 7);
    assert!(l.direct && l.peer.is_none(), "replaced by a WebRTC link");
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);

    // Once its transport is dead the same call does replace it, closing it.
    t.alive.store(false, Ordering::Relaxed);
    conn.establish_as(json!({ "id": "sid-1", "name": "user@x", "uid": "uid-x" }), Some(true))
        .await
        .expect("rebuild a dead link");
    let l = conn.links.get("sid-1").expect("rebuilt");
    assert!(!l.direct && l.peer.is_some());
    assert_eq!(
        l.expected_secret.as_ref().map(|(n, _)| n.as_str()),
        Some("x"),
        "the pair binding must carry over"
    );
    tokio::time::sleep(DROP_CLOSE_GRACE + Duration::from_millis(300)).await;
    assert_eq!(t.closes.load(Ordering::Relaxed), 1, "the dropped transport was not closed");
}

/// The acceptance-soak regression: a shell sitting idle at a prompt has
/// moved no bytes for minutes, but its direct transport is still alive. A
/// cosmetic signaling reconnect (same uid, new sid) must keep that link and
/// must not create a second one for the new sid. Pre-fix `link_flowing`
/// called the quiet link supersedable and dropped the pty.
#[tokio::test]
async fn idle_alive_link_survives_a_cosmetic_same_uid_reconnect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::idle(120_000);
    assert!(t.idle_ms() >= 120_000, "the fixture must model a long-idle link");
    conn.links
        .insert("sid-old".into(), linked_direct("sid-old", "soak-b", "uid-b", t.clone()));
    conn.bind_active("sid-old");

    let active = conn
        .maybe_adopt(
            &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
            true,
        )
        .await
        .expect("keeping an idle link is not an error");

    assert!(active, "the kept link is still the active one");
    assert!(conn.is_active("sid-old"), "active moved off the surviving link");
    assert!(conn.links.contains_key("sid-old"), "the idle shell link was dropped");
    assert_eq!(conn.links["sid-old"].generation, 7, "the idle link was replaced");
    assert!(!conn.links.contains_key("sid-new"), "keep path created a duplicate link");
    assert_eq!(conn.links.len(), 1, "keep path left more than one link");
    assert_eq!(t.closes.load(Ordering::Relaxed), 0, "the idle transport was closed");
}

/// The other half of the rule: a dead transport is not preserved. The new
/// sid supersedes it and the pair secret carries forward.
#[tokio::test]
async fn dead_old_link_is_superseded_on_same_uid_reconnect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::live();
    t.alive.store(false, Ordering::Relaxed);
    conn.links
        .insert("sid-old".into(), linked_direct("sid-old", "soak-b", "uid-b", t.clone()));
    conn.bind_active("sid-old");

    let active = conn
        .maybe_adopt(
            &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
            true,
        )
        .await
        .expect("rebuild over a dead link");

    assert!(active, "establish_as did not make the replacement active");
    assert!(!conn.links.contains_key("sid-old"), "the dead link survived");
    assert!(conn.links.contains_key("sid-new"), "no replacement link");
    assert!(conn.is_active("sid-new"));
    assert_eq!(
        conn.links["sid-new"].expected_secret.as_ref().map(|(n, _)| n.as_str()),
        Some("soak-b"),
        "the pair binding must carry across the supersede"
    );
}

/// A link with no transport at all has nothing to keep, even if its peer
/// object still claims to be connecting.
#[tokio::test]
async fn transportless_old_link_is_superseded_on_same_uid_reconnect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let mut old = linked_direct("sid-old", "soak-b", "uid-b", FakeQuic::live());
    old.transport = None;
    conn.links.insert("sid-old".into(), old);
    conn.bind_active("sid-old");

    let active = conn
        .maybe_adopt(
            &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
            true,
        )
        .await
        .expect("rebuild over a transportless link");

    assert!(active);
    assert!(!conn.links.contains_key("sid-old"), "the transportless link survived");
    assert!(conn.links.contains_key("sid-new"), "no replacement link");
    assert!(conn.is_active("sid-new"));
}

/// #28's flowing case must not change: an in-flight transfer that is still
/// moving bytes keeps the old link across the reconnect (gate 11b).
#[tokio::test]
async fn flowing_inflight_link_is_kept_on_same_uid_reconnect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::flowing(); // idle_ms 0: bytes are moving
    conn.links
        .insert("sid-old".into(), linked_direct("sid-old", "soak-b", "uid-b", t.clone()));
    conn.bind_active("sid-old");
    conn.resil
        .in_flight_since
        .insert("sid-old".into(), Instant::now());

    let active = conn
        .maybe_adopt(
            &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
            true,
        )
        .await
        .expect("keeping a flowing link is not an error");

    assert!(active);
    assert!(conn.is_active("sid-old"));
    assert!(conn.links.contains_key("sid-old"), "the flowing link was dropped");
    assert!(!conn.links.contains_key("sid-new"), "keep path created a duplicate link");
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);
}

/// Gate 11's frozen receiver: the transport is still alive but an in-flight
/// transfer has stopped moving. That is a stall, not an idle shell, so the
/// reconnect must supersede it. This is why an in-flight check remains.
#[tokio::test]
async fn frozen_inflight_link_is_still_superseded() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::idle(60_000); // alive transport, no byte progress
    conn.links
        .insert("sid-old".into(), linked_direct("sid-old", "soak-b", "uid-b", t.clone()));
    conn.bind_active("sid-old");
    conn.resil
        .in_flight_since
        .insert("sid-old".into(), Instant::now());

    let active = conn
        .maybe_adopt(
            &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
            true,
        )
        .await
        .expect("rebuild a frozen transfer");

    assert!(active, "establish_as did not make the replacement active");
    assert!(!conn.links.contains_key("sid-old"), "the frozen link was kept");
    assert!(conn.links.contains_key("sid-new"), "no replacement link");
    assert!(conn.is_active("sid-new"));
}

/// A relay link has no QUIC keepalive, so `peer_present` uses the peer's 5 s
/// application keepalive. A quiet but heard peer is an idle link and is
/// kept; a peer that stopped being heard is a dead path and is superseded.
#[tokio::test]
async fn relay_idle_link_is_kept_only_while_the_peer_is_still_heard() {
    for (heard_ms, expect_keep) in [(2_000u64, true), (30_000u64, false)] {
        let (mut conn, _far, _rx) = test_conn().await;
        let t = FakeQuic::relay(120_000, heard_ms);
        let mut old = linked_direct("sid-old", "soak-b", "uid-b", t.clone());
        old.direct = false; // relay/DataChannel link
        conn.links.insert("sid-old".into(), old);
        conn.bind_active("sid-old");

        let active = conn
            .maybe_adopt(
                &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
                true,
            )
            .await
            .expect("relay adoption");

        assert!(active, "heard={heard_ms}");
        if expect_keep {
            assert!(conn.links.contains_key("sid-old"), "a heard relay link was dropped");
            assert!(!conn.links.contains_key("sid-new"), "keep path created a duplicate link");
            assert_eq!(t.closes.load(Ordering::Relaxed), 0);
        } else {
            assert!(!conn.links.contains_key("sid-old"), "a silent relay link was kept");
            assert!(conn.links.contains_key("sid-new"), "no replacement link");
            assert!(conn.is_active("sid-new"));
        }
    }
}

/// The same-device keep rule must never reuse a link belonging to a
/// different identity. A different uid is a different device (or a changed
/// identity): it gets its own link rather than silently inheriting this
/// one's transport, secret and trust.
#[tokio::test]
async fn different_uid_is_not_reused_as_the_same_device() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::idle(120_000);
    conn.links
        .insert("sid-old".into(), linked_direct("sid-old", "someone-else", "uid-other", t.clone()));
    conn.bind_active("sid-old");

    conn.maybe_adopt(
        &json!({ "id": "sid-new", "name": "user@soak-b", "uid": "uid-b" }),
        true,
    )
    .await
    .expect("adopt a different identity");

    assert!(conn.links.contains_key("sid-old"), "another identity's link was dropped");
    assert_eq!(conn.links["sid-old"].generation, 7);
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);
    assert!(conn.links.contains_key("sid-new"), "the new identity got no link");
    assert_eq!(conn.links.len(), 2, "an identity change must not reuse the old link");
}

/// A pending direct attempt shaped like the one `start_direct_promote`
/// arms for a confirmed code ceremony (`ephemeral`).
fn promote_pending(attempt: net::AttemptId, sid: &str, secret: &str) -> DirectPending {
    DirectPending {
        attempt,
        auth: DirectAuth::device(1, "box", "00"),
        race_task: None,
        secret: (sid.into(), secret.into()),
        fleet: false,
        lan: false,
        ephemeral: true,
        deadline: Instant::now() + Duration::from_secs(30),
        racing: false,
        endpoint: None,
        punch_sock: None,
        my_srflx: None,
        peer_server_public: None,
        server_public_dialed: Arc::new(AtomicBool::new(false)),
        probe: false,
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

/// The direct link that ceremony's promotion publishes: born untrusted,
/// keyed by the ceremony secret, owned by the promotion's attempt.
fn promoted_link(pid: &str, uid: &str, secret: &str, attempt: net::AttemptId) -> Link {
    let mut l = linked_direct(pid, "peer", uid, FakeQuic::live());
    l.trusted = false;
    l.verified_name = None;
    l.expected_secret = Some((pid.to_string(), secret.to_string()));
    l.attempt = Some(attempt);
    l
}

/// Code authority after a confirmed ceremony with S1: the confirmed
/// transport (WebRTC fingerprints, or the ceremony's own direct promotion)
/// is authorized; a same-uid NEW sid installed from signal data, a rebuilt
/// WebRTC link with other fingerprints, and a direct link some other
/// attempt published are not. The receive gates (file-offer, code
/// consent, pair-keep) and the identity-unavailable consent all read this.
#[tokio::test]
async fn code_authority_is_bound_to_the_confirmed_session_and_transport() {
    let (mut conn, _far, _rx) = test_conn().await;
    let promote = net::AttemptId::next();
    conn.roster.insert("sid-s1".into(), json!({ "id": "sid-s1", "name": "user@s", "uid": "uid-u" }));
    conn.direct_pending.insert("sid-s1".into(), promote_pending(promote, "sid-s1", "k-secret"));
    conn.links.insert("sid-s1".into(), promoted_link("sid-s1", "uid-u", "k-secret", promote));

    // Unconfirmed: nothing is authorized, even the right link (policy
    // unchanged: no authority before the ceremony confirms).
    assert!(!conn.holds_code_authority("sid-s1").await);
    // consented_identity_peer lives behind the `dispatch` feature.
    #[cfg(feature = "dispatch")]
    assert!(!crate::recv::dispatch::consented_identity_peer(&conn, "sid-s1", true, true, false, false).await);

    conn.bind_active("sid-s1");
    conn.bind_code_session("sid-s1", ("fp-a", "fp-b"), "k-secret");
    assert_eq!(conn.code_session.as_ref().map(|c| c.sid()), Some("sid-s1"));

    // Positive control: the ceremony's own direct promotion.
    assert_eq!(conn.code_authority("sid-s1").await, Ok(()));
    assert!(conn.holds_code_authority("sid-s1").await);
    // consented_identity_peer lives behind the `dispatch` feature.
    #[cfg(feature = "dispatch")]
    assert!(crate::recv::dispatch::consented_identity_peer(&conn, "sid-s1", true, true, false, false).await);
    // ... but not before this run's ceremony confirmed (recv_pake_done).
    // consented_identity_peer lives behind the `dispatch` feature.
    #[cfg(feature = "dispatch")]
    assert!(!crate::recv::dispatch::consented_identity_peer(&conn, "sid-s1", true, false, false, false).await);

    // Same uid U, NEW sid S2, named only by an unauthenticated signal.
    conn.ensure_responder("sid-s2", &json!({ "type": "candidate", "uid": "uid-u" }))
        .await
        .expect("a candidate signal is not an error");
    assert_eq!(conn.roster["sid-s2"]["uid"], "uid-u", "first-seen uid is still recorded");
    conn.links.insert("sid-s2".into(), promoted_link("sid-s2", "uid-u", "k-secret", promote));
    assert_eq!(conn.code_authority("sid-s2").await, Err(CodeAuthorityRefusal::SessionMismatch));
    assert!(!conn.holds_code_authority("sid-s2").await);
    // consented_identity_peer lives behind the `dispatch` feature.
    #[cfg(feature = "dispatch")]
    assert!(!crate::recv::dispatch::consented_identity_peer(&conn, "sid-s2", true, true, false, false).await);

    // Same sid, a direct link some OTHER attempt published.
    conn.links.insert("sid-s1".into(), promoted_link("sid-s1", "uid-u", "k-secret", net::AttemptId::next()));
    assert_eq!(conn.code_authority("sid-s1").await, Err(CodeAuthorityRefusal::ForeignDirect));
    // consented_identity_peer lives behind the `dispatch` feature.
    #[cfg(feature = "dispatch")]
    assert!(!crate::recv::dispatch::consented_identity_peer(&conn, "sid-s1", true, true, false, false).await);

    // Same sid on a WebRTC link: only the confirmed fingerprint pair.
    let mut webrtc = promoted_link("sid-s1", "uid-u", "k-secret", promote);
    webrtc.direct = false;
    conn.links.insert("sid-s1".into(), webrtc);
    assert_eq!(conn.code_authority_on("sid-s1", Some(("fp-a", "fp-b"))), Ok(()));
    assert_eq!(
        conn.code_authority_on("sid-s1", Some(("fp-a", "fp-c"))),
        Err(CodeAuthorityRefusal::FingerprintMismatch)
    );
    // This fixture has no RTCPeerConnection, so no fingerprints to read.
    assert_eq!(conn.code_authority("sid-s1").await, Err(CodeAuthorityRefusal::NoTransport));

    // The confirmed session is set once and never moved.
    conn.bind_code_session("sid-s2", ("fp-x", "fp-y"), "k-secret");
    assert_eq!(conn.code_session.as_ref().map(|c| c.sid()), Some("sid-s1"));
}

/// The code-receive binding never hands the transfer slot to a new sid:
/// a same-install peer reconnecting on S2 (its S1 link gone) is refused
/// `want_active`, and the confirmed session still names S1. Control: the
/// exact sid takes the slot through the same path first.
#[tokio::test]
async fn a_same_uid_new_sid_cannot_take_the_code_receive_slot() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.roster.insert("sid-s1".into(), json!({ "id": "sid-s1", "name": "user@s", "uid": "uid-u" }));
    conn.bind_active("sid-s1");
    conn.bind_code_session("sid-s1", ("fp-a", "fp-b"), "k-secret");
    conn.active = None;

    // Control: the confirmed sid itself is claimable as the target.
    let active = conn
        .maybe_adopt(&json!({ "id": "sid-s1", "name": "user@s", "uid": "uid-u" }), true)
        .await
        .expect("adoption is not an error");
    assert!(active, "the confirmed sid could not take its own slot");

    // The S1 link dies and releases the slot; the same install returns on S2.
    conn.drop_link("sid-s1");
    assert!(conn.active.is_none());
    let active = conn
        .maybe_adopt(&json!({ "id": "sid-s2", "name": "user@s", "uid": "uid-u" }), true)
        .await
        .expect("adoption is not an error");
    assert!(!active, "a same-uid new sid took the code-receive slot");
    assert!(conn.active.is_none());
    assert_eq!(conn.active_binding.as_ref().map(|b| b.0.as_str()), Some("sid-s1"));
    assert_eq!(conn.code_session.as_ref().map(|c| c.sid()), Some("sid-s1"));
    assert!(!conn.holds_code_authority("sid-s2").await);
}

#[tokio::test]
async fn an_in_flight_code_transfer_continues_only_on_the_covered_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let promote = net::AttemptId::next();
    conn.direct_pending.insert("sid-s1".into(), promote_pending(promote, "sid-s1", "k-secret"));
    conn.links.insert("sid-s1".into(), promoted_link("sid-s1", "uid-u", "k-secret", promote));
    let mut cache = CodeAuthorityCache::default();

    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Lost);

    conn.bind_code_session("sid-s1", ("fp-a", "fp-b"), "k-secret");
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Holds);
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Holds);

    conn.links.insert("sid-s1".into(), promoted_link("sid-s1", "uid-u", "k-secret", net::AttemptId::next()));
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Lost);

    conn.links.insert("sid-s1".into(), promoted_link("sid-s1", "uid-u", "k-secret", promote));
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Holds);

    let mut rebuilt = promoted_link("sid-s1", "uid-u", "k-secret", promote);
    rebuilt.direct = false;
    conn.links.insert("sid-s1".into(), rebuilt);
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::Lost);

    conn.links.remove("sid-s1");
    assert_eq!(conn.code_continuation("sid-s1", &mut cache).await, CodeContinuation::NoLink);

    conn.links.insert("sid-s2".into(), promoted_link("sid-s2", "uid-u", "k-secret", promote));
    assert_eq!(conn.code_continuation("sid-s2", &mut cache).await, CodeContinuation::Lost);
}

/// A signal payload never replaces a roster uid the server already gave
/// (control: a peer with none yet still gets the first-seen one).
#[tokio::test]
async fn ensure_responder_does_not_overwrite_a_known_roster_uid() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.roster.insert("sid-a".into(), json!({ "id": "sid-a", "name": "a", "uid": "uid-real" }));
    conn.ensure_responder("sid-a", &json!({ "type": "candidate", "uid": "uid-claimed" }))
        .await
        .expect("not an error");
    assert_eq!(conn.roster["sid-a"]["uid"], "uid-real");

    conn.roster.insert("sid-b".into(), json!({ "id": "sid-b", "name": "b" }));
    conn.ensure_responder("sid-b", &json!({ "type": "candidate", "uid": "uid-first" }))
        .await
        .expect("not an error");
    assert_eq!(conn.roster["sid-b"]["uid"], "uid-first");
}

#[tokio::test]
async fn drop_link_closes_the_direct_connection() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::live();
    let w = FakeQuic::live();
    let mut l = direct_link("sid-1", "x", "user@x", t.clone());
    l.workers = vec![w.clone()];
    conn.links.insert("sid-1".into(), l);
    conn.drop_link("sid-1");
    assert!(!conn.links.contains_key("sid-1"));
    // Not at once: a last frame written before the drop must get out first.
    assert_eq!(t.closes.load(Ordering::Relaxed), 0, "closed before the grace");
    tokio::time::sleep(DROP_CLOSE_GRACE + Duration::from_millis(300)).await;
    assert_eq!(t.closes.load(Ordering::Relaxed), 1, "primary QUIC left open: split-brain");
    assert_eq!(w.closes.load(Ordering::Relaxed), 1, "worker QUIC left open");
}

#[tokio::test]
async fn exit_closes_every_direct_connection_at_once() {
    let (mut conn, _far, _rx) = test_conn().await;
    let a = FakeQuic::live();
    let aw = FakeQuic::live();
    let b = FakeQuic::live();
    let mut la = direct_link("sid-a", "a", "user@a", a.clone());
    la.workers = vec![aw.clone()];
    conn.links.insert("sid-a".into(), la);
    conn.links.insert("sid-b".into(), direct_link("sid-b", "b", "user@b", b.clone()));
    assert_eq!(conn.close_links_for_exit(), 3);
    // At once, not after a grace: the process is about to exit.
    assert_eq!(a.closes.load(Ordering::Relaxed), 1, "primary left open at exit");
    assert_eq!(aw.closes.load(Ordering::Relaxed), 1, "worker left open at exit");
    assert_eq!(b.closes.load(Ordering::Relaxed), 1, "second link left open at exit");
}

#[tokio::test]
async fn known_peer_left_drops_the_sid_from_the_roster() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.roster.insert(
        "sid-gone".into(),
        json!({ "id": "sid-gone", "name": "user@x", "channel": CH }),
    );
    conn.roster.insert(
        "sid-linked".into(),
        json!({ "id": "sid-linked", "name": "user@x", "channel": CH }),
    );
    conn.links.insert(
        "sid-linked".into(),
        direct_link("sid-linked", "x", "user@x", FakeQuic::live()),
    );
    assert!(conn.on_known_peer_left(&json!({ "id": "sid-gone", "channel": CH })));
    assert!(!conn.roster.contains_key("sid-gone"));
    // A sid still carrying a live link keeps its entry (role election and
    // adoption read it); the link reapers own that link's fate.
    assert!(!conn.on_known_peer_left(&json!({ "id": "sid-linked", "channel": CH })));
    assert!(conn.roster.contains_key("sid-linked"));
}

/// A link still mid-attempt (WebRTC peer New/Connecting, nothing
/// serving) does not keep a departed sid in the roster. It used to: the
/// retry ladder toward a vanished visitor was in flight at every
/// known-peer-left and every digest, so the entry outlived the sid and
/// warm-hold re-dialled it from there without bound (chaos O12,
/// transient-visitors-sequential). The link itself is left to its ladder.
#[tokio::test]
async fn an_in_flight_attempt_does_not_keep_a_departed_sid_in_the_roster() {
    let (mut conn, _far, _rx) = test_conn().await;
    for pid in ["sid-kpl", "sid-digest"] {
        conn.establish_as(
            json!({ "id": pid, "name": "visitor-4", "uid": format!("uid-{pid}") }),
            Some(true),
        )
        .await
        .expect("a WebRTC attempt that never connects");
        assert!(conn.has_live_transport(pid), "precondition: the attempt counts as progress");
        assert!(!conn.link_carries(pid), "an attempt in flight carries nothing");
        conn.roster.insert(
            pid.into(),
            json!({ "id": pid, "name": "visitor-4", "channel": CH }),
        );
    }
    assert!(conn.on_known_peer_left(&json!({ "id": "sid-kpl", "channel": CH })));
    assert!(!conn.roster.contains_key("sid-kpl"));
    assert!(conn.links.contains_key("sid-kpl"), "the ladder owns the link, not the roster");

    let none: HashSet<String> = HashSet::new();
    assert!(conn.prune_roster_absent(&none, &none).is_empty());
    assert_eq!(
        conn.prune_roster_absent(&none, &none),
        vec!["sid-digest".to_string()],
        "an in-flight attempt reset the absence count"
    );
    assert!(!conn.roster.contains_key("sid-digest"));
}

/// Warm-hold dials only a sid presence still vouches for and the ladder
/// has not given up on. A departed visitor's old sid (suppressed after its
/// ladder exhausted, or missing from the last digest) is never dialled and
/// does not hold the device in the auto tier; the same device back on a
/// NEW sid (a laptop waking) is dialled at once.
#[tokio::test]
async fn warm_hold_skips_a_departed_sid_and_rewarms_a_new_one() {
    let host = Arc::new(TestHost {
        devices: vec![("visitor-4".to_string(), "s4".to_string())],
        ..Default::default()
    });
    let channel = host.channel_of("s4");
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let entry = |pid: &str| json!({ "id": pid, "name": "user@visitor-4", "uid": "uid-v4", "channel": channel });

    // Its ladder gave up on the sid.
    conn.roster.insert("sid-old".into(), entry("sid-old"));
    conn.suppressed_digest_adoptions.insert("sid-old".into());
    for _ in 0..3 {
        assert!(conn.warm_hold_tick(true).await.is_empty());
    }
    assert!(!conn.links.contains_key("sid-old"), "warm-hold dialled a sid its ladder gave up on");
    assert!(conn.direct_pending.is_empty(), "warm-hold armed a direct dial to it");
    assert!(!conn.warm_hold.auto.contains("visitor-4"), "a departed sid kept the device warm");

    // Missing from the last digest (presence says it is gone).
    conn.suppressed_digest_adoptions.clear();
    conn.roster_absent.insert("sid-old".into(), 1);
    assert!(conn.warm_hold_tick(true).await.is_empty());
    assert!(!conn.links.contains_key("sid-old"), "warm-hold dialled a sid presence dropped");
    assert!(conn.direct_pending.is_empty());

    // The device is back on a new sid: re-warmed.
    conn.roster.insert("sid-new".into(), entry("sid-new"));
    conn.warm_hold_tick(true).await;
    assert!(conn.warm_hold.auto.contains("visitor-4"));
    assert!(
        conn.links.contains_key("sid-new") || conn.direct_pending.contains_key("sid-new"),
        "the device's new sid was not dialled"
    );
    assert!(!conn.links.contains_key("sid-old"));
}

#[tokio::test]
async fn digest_absence_prunes_the_roster_after_two_digests() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.roster.insert(
        "sid-ch".into(),
        json!({ "id": "sid-ch", "name": "user@x", "channel": CH }),
    );
    conn.roster
        .insert("sid-room".into(), json!({ "id": "sid-room", "name": "guest" }));
    conn.roster.insert(
        "sid-here".into(),
        json!({ "id": "sid-here", "name": "user@y", "channel": "c2" }),
    );
    let channel_present: HashSet<String> = ["sid-here".to_string()].into();
    let room_present: HashSet<String> = HashSet::new();
    assert!(conn.prune_roster_absent(&channel_present, &room_present).is_empty());
    assert_eq!(conn.roster.len(), 3, "one absent digest is not enough (hysteresis)");
    let mut gone = conn.prune_roster_absent(&channel_present, &room_present);
    gone.sort();
    assert_eq!(gone, vec!["sid-ch".to_string(), "sid-room".to_string()]);
    assert!(conn.roster.contains_key("sid-here"));
    assert!(conn.roster_absent.is_empty());
}

// --- digest reconcile liveness (PR512) --------------------------------

/// The failure: a channel digest miss on a signaling reconnect retired a
/// direct link that was still moving a shell's bytes. While the transport
/// flows, the reconcile must defer, however long the miss persists: a
/// moving data channel is stronger evidence than a missing presence entry.
#[tokio::test]
async fn digest_absence_defers_a_flowing_live_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::flowing();
    conn.links.insert(
        "sid-old".into(),
        direct_link("sid-old", "x", "user@x", t.clone()),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_absent_retirable_at("sid-old", t0));
    assert!(!conn.digest_absent_retirable_at(
        "sid-old",
        t0 + Duration::from_secs(60 * 60)
    ));
    assert!(conn.links.contains_key("sid-old"));
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);
}

/// A send whose WebRTC data channel latched dead under loss (a write the
/// association never acknowledged) while its peer connection stayed
/// connected: the chaos fuzzer's send-stuck-reconnecting-after-heal. The
/// stall watchdog read the dead transport as "establishing" and never fired,
/// the establishment watchdog keys on the peer connection and never fired
/// either, so the send printed "the link is down, trying to reconnect"
/// until its rejoin window ran out, long after the network healed.
#[tokio::test]
async fn a_dead_webrtc_transport_reaches_the_stall_ladder() {
    let (mut conn, _far, _rx) = test_conn().await;
    let dc = FakeQuic::dead_data_channel();
    assert!(dc.is_dead() && !dc.is_alive(), "fixture: the data channel's real shape");
    let pid = "sid-dc";
    conn.links
        .insert(pid.into(), relay_link(pid, "bravo", "bravo", dc));
    assert!(conn.detect_stall(pid, true, true).is_some(), "a dead channel mid-transfer is a stall");
    // Closed but not yet latched (quinn's window before the reader sees
    // it): `transport_severed` still calls that dead.
    conn.links.insert(
        "sid-closed".into(),
        relay_link("sid-closed", "bravo", "bravo", FakeQuic::closed_not_dead()),
    );
    assert!(conn.detect_stall("sid-closed", true, true).is_some());
    assert!(conn.detect_stall(pid, false, true).is_none(), "nothing in flight, nothing to repair");
    // The receiver leaves a dead channel to the sender's re-dial.
    assert!(conn.detect_stall(pid, true, false).is_none());
    // A link that has no transport yet is still the establishment
    // watchdog's, never the stall ladder's.
    let mut fresh = relay_link("sid-new", "bravo", "bravo", FakeQuic::live());
    fresh.transport = None;
    conn.links.insert("sid-new".into(), fresh);
    assert!(conn.detect_stall("sid-new", true, true).is_none());
}

/// The ladder's repair rung for that link must rebuild it: an ICE restart
/// keeps the same data channel, which stays dead whatever ICE does. The
/// dead link goes, a fresh dial of the known device is armed, and the
/// transfer target stays pointed at the peer so the new link's
/// ChannelReady re-offers with resume.
#[tokio::test]
async fn the_repair_rung_rebuilds_a_dead_webrtc_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let pid = "sid-dc";
    conn.links
        .insert(pid.into(), relay_link(pid, "bravo", "bravo", FakeQuic::dead_data_channel()));
    conn.active = Some(pid.to_string());
    assert_eq!(conn.correct_stall(pid).await, Rung::Repaired);
    assert!(
        conn.links
            .get(pid)
            .is_none_or(|l| l.transport.as_ref().is_none_or(|t| !Conn::transport_severed(t.as_ref()))),
        "the dead channel is still the link's transport"
    );
    assert!(conn.direct_pending.contains_key(pid), "no fresh dial was armed");
    assert_eq!(conn.active.as_deref(), Some(pid));
    // Stalls queued before that repair ran were measured on the link it
    // replaced: they must not climb the ladder toward the relay.
    let attempts = conn.resil.stall_repairs.get(pid).map(|s| s.attempts);
    for _ in 0..STALL_MAX_REPAIRS {
        assert_eq!(conn.correct_stall(pid).await, Rung::Repaired);
    }
    assert_eq!(conn.resil.stall_repairs.get(pid).map(|s| s.attempts), attempts);
    assert!(!conn.relay_only, "queued stalls escalated to the relay");
    // While that dial converges the ladder holds instead of re-firing.
    assert!(conn.detect_stall(pid, true, true).is_none());
}

/// The other side of the contract: a dead transport is a departure. The
/// reconcile retires it at once, with no grace at all.
#[tokio::test]
async fn digest_absence_retires_a_dead_link_immediately() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.links.insert(
        "sid-dead".into(),
        direct_link("sid-dead", "x", "user@x", FakeQuic::dead()),
    );
    assert!(conn.digest_absent_retirable_at("sid-dead", Instant::now()));
    assert!(conn.links.contains_key("sid-dead"), "the caller owns the drop");
}

/// An idle but ALIVE direct shell link is transport-bounded, not
/// grace-bounded: a signaling reconnect makes its old sid absent from the
/// digest, but retiring it 30 s later would drop the shell the establish
/// fix just kept. It survives past the grace and stays retired only when
/// QUIC says the connection is gone.
#[tokio::test]
async fn digest_absence_keeps_an_idle_alive_direct_link_past_the_grace() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::live(); // alive, idle_ms u64::MAX (never wrote)
    conn.links.insert(
        "sid-idle".into(),
        direct_link("sid-idle", "x", "user@x", t.clone()),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_absent_retirable_at("sid-idle", t0));
    assert!(!conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + DIGEST_ABSENT_IDLE_GRACE - Duration::from_millis(1)
    ));
    assert!(
        !conn.digest_absent_retirable_at(
            "sid-idle",
            t0 + DIGEST_ABSENT_IDLE_GRACE
        ),
        "an alive direct link was retired by the digest grace"
    );
    assert!(!conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + Duration::from_secs(60 * 60)
    ));
    assert!(conn.links.contains_key("sid-idle"));
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);
}

/// The other side of the transport bound: once QUIC reports the direct
/// connection closed, retirement is immediate, even if `is_dead` has not
/// latched. No half-closed zombie waits out the grace.
#[tokio::test]
async fn digest_absence_retires_a_closed_direct_transport_immediately() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::closed_not_dead();
    assert!(!t.is_alive() && !t.is_dead(), "fixture: closed before dead");
    conn.links.insert(
        "sid-closed".into(),
        direct_link("sid-closed", "x", "user@x", t.clone()),
    );
    assert!(conn.digest_absent_retirable_at("sid-closed", Instant::now()));
    assert!(conn.links.contains_key("sid-closed"), "the caller owns the drop");
}

/// Relay/DataChannel remains peer-originated: a fresh `heard_ms` keeps an
/// otherwise-idle relay link; a silent one still reaches the bounded grace.
#[tokio::test]
async fn digest_relay_busy_is_bounded_by_heard_not_idle() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.links.insert(
        "sid-relay".into(),
        relay_link("sid-relay", "x", "user@x", FakeQuic::relay_heard(2_000)),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_absent_retirable_at("sid-relay", t0));
    assert!(!conn.digest_absent_retirable_at(
        "sid-relay",
        t0 + DIGEST_ABSENT_IDLE_GRACE
    ));
}

/// Presence returning clears the clock. Without the clear, the second call
/// at exactly `t0 + GRACE` would already be retirable; with it, that moment
/// is merely the new first absence, and only a full fresh window retires.
#[tokio::test]
async fn digest_present_clears_the_deferral_clock() {
    let (mut conn, _far, _rx) = test_conn().await;
    // A relay link with a silent peer is grace-bounded (direct links are
    // transport-bounded, so they would never reach this clock).
    conn.links.insert(
        "sid-idle".into(),
        relay_link("sid-idle", "x", "user@x", FakeQuic::relay_writes_only()),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_absent_retirable_at("sid-idle", t0));
    assert!(conn.digest_deferred.contains_key("sid-idle"));
    conn.digest_present("sid-idle");
    assert!(!conn.digest_deferred.contains_key("sid-idle"));
    // A no-op `digest_present` would return true here (30s since t0).
    assert!(!conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + DIGEST_ABSENT_IDLE_GRACE
    ));
    assert!(!conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + DIGEST_ABSENT_IDLE_GRACE + Duration::from_secs(29)
    ));
    assert!(conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + DIGEST_ABSENT_IDLE_GRACE + DIGEST_ABSENT_IDLE_GRACE
    ));
}

/// A fresh signaling sid discards both the miss counters and the clock, so
/// a gap straddling the reconnect cannot be carried into the new one.
#[tokio::test]
async fn reset_digest_reconcile_starts_a_fresh_window() {
    let (mut conn, _far, _rx) = test_conn().await;
    // Grace-bounded relay shape: direct alive links are transport-bounded
    // and would never start this window.
    conn.links.insert(
        "sid-idle".into(),
        relay_link("sid-idle", "x", "user@x", FakeQuic::relay_writes_only()),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0
    ));
    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(1)
    ));
    assert!(conn.digest_deferred.contains_key("sid-idle"));
    assert_eq!(conn.room_digest_absent.get("sid-idle"), Some(&2));

    conn.reset_digest_reconcile();
    assert!(conn.digest_deferred.is_empty());
    assert!(conn.room_digest_absent.is_empty());
    assert!(conn.channel_digest_absent.is_empty());

    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(30)
    ));
    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(31)
    ));
    assert!(!conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + Duration::from_secs(60)
    ));
    assert!(conn.digest_absent_retirable_at(
        "sid-idle",
        t0 + Duration::from_secs(61)
    ));
}

/// BLOCKER regression: the channel surface is ticked every digest for its
/// own link, and must not clear the clock of a room-sourced link that is
/// idle but alive. Before the fix every non-channel link went through the
/// channel surface's `digest_present`, restarting the room grace forever.
#[tokio::test]
async fn channel_loop_does_not_reset_a_room_links_grace() {
    let (mut conn, _far, _rx) = test_conn().await;
    // Quiet relay shape, so the 30 s grace is what this surface test
    // measures (an alive direct link is transport-bounded instead).
    let mut room =
        relay_link("sid-room", "room", "user@room", FakeQuic::relay_writes_only());
    room.expected_secret = None; // room-sourced: no pair channel
    conn.links.insert("sid-room".into(), room);
    conn.links.insert(
        "sid-ch".into(),
        direct_link("sid-ch", "ch", "user@ch", FakeQuic::live()),
    );

    let t0 = Instant::now();
    // Two room misses make it a candidate and start the idle grace.
    assert!(!conn.digest_note_at(
        "sid-room",
        DigestSurface::Room,
        false,
        false,
        t0
    ));
    assert!(!conn.digest_note_at(
        "sid-room",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(1)
    ));
    assert!(conn.digest_deferred.contains_key("sid-room"));

    // The channel loop runs on every digest. Its own link is present; the
    // room link must not be touched by it.
    assert!(!conn.digest_note_at(
        "sid-ch",
        DigestSurface::Channel,
        true,
        false,
        t0 + Duration::from_secs(10)
    ));
    assert!(
        conn.digest_deferred.contains_key("sid-room"),
        "the channel surface cleared a room-sourced link's clock"
    );

    // 29s after the first deferral: still inside the bounded grace.
    assert!(!conn.digest_note_at(
        "sid-room",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(30)
    ));
    // 30s after it: retirable, exactly as the room surface alone would.
    assert!(conn.digest_note_at(
        "sid-room",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(31)
    ));
}

/// Relay/DataChannel keepalives are OUR writes and stamp `idle_ms`; a
/// wiped peer can look busy forever. Retirement prefers `heard_ms` (what
/// the PEER sent), so it still reaches the bounded grace and retires.
#[tokio::test]
async fn digest_absence_is_bounded_on_a_relay_link_that_only_writes() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.links.insert(
        "sid-relay".into(),
        relay_link("sid-relay", "x", "user@x", FakeQuic::relay_writes_only()),
    );
    let t0 = Instant::now();
    assert!(!conn.digest_absent_retirable_at("sid-relay", t0));
    assert!(conn.digest_deferred.contains_key("sid-relay"));
    assert!(!conn.digest_absent_retirable_at(
        "sid-relay",
        t0 + DIGEST_ABSENT_IDLE_GRACE - Duration::from_millis(1)
    ));
    assert!(conn.digest_absent_retirable_at(
        "sid-relay",
        t0 + DIGEST_ABSENT_IDLE_GRACE
    ));
}

/// Dropping a link discharges its digest bookkeeping with the link itself.
#[tokio::test]
async fn drop_link_clears_digest_deferral_and_counters() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = FakeQuic::live();
    let mut l = direct_link("sid-idle", "x", "user@x", t.clone());
    l.expected_secret = None;
    conn.links.insert("sid-idle".into(), l);
    let t0 = Instant::now();
    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0
    ));
    assert!(!conn.digest_note_at(
        "sid-idle",
        DigestSurface::Room,
        false,
        false,
        t0 + Duration::from_secs(1)
    ));
    assert!(conn.digest_deferred.contains_key("sid-idle"));
    assert_eq!(conn.room_digest_absent.get("sid-idle"), Some(&2));

    conn.drop_link("sid-idle");
    assert!(!conn.digest_deferred.contains_key("sid-idle"));
    assert!(!conn.room_digest_absent.contains_key("sid-idle"));
    assert!(!conn.channel_digest_absent.contains_key("sid-idle"));
}

/// A sid absent after its link was already dropped stays retirable: the
/// deferral map is not a link registry and cannot resurrect a dead peer.
#[tokio::test]
async fn digest_absence_with_no_link_is_retirable() {
    let (mut conn, _far, _rx) = test_conn().await;
    assert!(conn.digest_absent_retirable("sid-never-linked"));
}

/// Exit reconciliation still does NOT treat a digest-deferred link as
/// discharged: a presence gap can coexist with an active sender that may
/// offer more work. Only a real peer-left is safe to exit past.
#[tokio::test]
async fn only_deferred_links_ignores_digest_deferrals() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.links.insert(
        "sid-idle".into(),
        direct_link("sid-idle", "x", "user@x", FakeQuic::live()),
    );
    conn.digest_deferred.insert("sid-idle".into(), Instant::now());
    assert!(!conn.only_deferred_links());
    conn.deferred_left.insert("sid-idle".into(), json!({}));
    assert!(conn.only_deferred_links());
}

/// The event-loop gate: a mini loop that dispatches Stuck/RetryLink to
/// the REAL `on_stuck`/`on_retry_due` and answers a control request in
/// between, the way the daemon loop does. Stuck is re-injected for the
/// current attempt on every request. Before the fix `on_stuck` slept the
/// backoff (1,2,4,8s) inline and a request waited up to 4s behind it.
#[tokio::test]
async fn the_retry_ladder_never_blocks_a_control_request() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-stuck".to_string();
    conn.establish_as(
        json!({ "id": pid, "name": "user@x", "uid": "uid-x" }),
        Some(true),
    )
    .await
    .expect("build a WebRTC link that will never connect");
    let first_gen = conn.links[&pid].generation;

    type Probe = (Instant, oneshot::Sender<Duration>);
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Probe>();
    let driver = tokio::spawn(async move {
        let mut worst = Duration::ZERO;
        // ~5s: long enough for the 1s and 2s backoffs to fire.
        for _ in 0..100 {
            let (reply_tx, reply_rx) = oneshot::channel();
            ctl_tx.send((Instant::now(), reply_tx)).unwrap();
            worst = worst.max(reply_rx.await.unwrap());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        worst
    });

    let mut retries = 0;
    let worst = loop {
        tokio::select! {
            Some(ev) = rx.recv() => match ev {
                Ev::Stuck(p, g) => {
                    conn.on_stuck(&p, g, "stuck").await.unwrap();
                }
                Ev::RetryLink(p, g) => {
                    retries += 1;
                    conn.on_retry_due(&p, g).await.unwrap();
                }
                _ => {}
            },
            Some((sent, reply)) = ctl_rx.recv() => {
                let _ = reply.send(sent.elapsed());
                if let Some(l) = conn.links.get(&pid) {
                    let _ = conn.tx.send(Ev::Stuck(pid.clone(), l.generation));
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        if driver.is_finished() {
            break driver.await.unwrap();
        }
    };
    assert!(
        worst < Duration::from_millis(200),
        "a control request waited {worst:?} behind the retry ladder"
    );
    assert!(retries >= 2, "the ladder did not run ({retries} retries)");
    let l = conn.links.get(&pid).expect("the link is still being retried");
    assert!(l.generation > first_gen, "no retry rebuilt the stuck link");
    assert!(l.attempts >= 2, "attempts were not counted ({})", l.attempts);
}

#[tokio::test]
async fn a_stale_retry_is_ignored() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-stuck";
    conn.establish_as(
        json!({ "id": pid, "name": "user@x", "uid": "uid-x" }),
        Some(true),
    )
    .await
    .unwrap();
    let g = conn.links[pid].generation;
    assert!(!conn.on_stuck(pid, g, "stuck").await.unwrap());
    assert!(conn.stuck_retry.contains_key(pid));
    // A second watchdog for the same attempt does not count again.
    assert!(!conn.on_stuck(pid, g, "lost").await.unwrap());
    assert_eq!(conn.stuck_retry[pid].attempts, 1);
    // The link is replaced meanwhile: the retry must not touch it.
    let t = FakeQuic::live();
    conn.links
        .insert(pid.into(), direct_link(pid, "x", "user@x", t.clone()));
    assert!(!conn.on_retry_due(pid, g).await.unwrap());
    assert!(conn.links[pid].direct, "a stale retry replaced the new link");
    assert_eq!(t.closes.load(Ordering::Relaxed), 0);
}

// --- browser transport hint (web-shell "connecting" stall) -------------

#[test]
fn only_an_explicit_false_disables_direct() {
    assert!(Conn::direct_disabled_by_peer(
        &json!({ "direct": false })
    ));
    // CLI peers (and older clients) carry no field: direct-first stays.
    assert!(!Conn::direct_disabled_by_peer(&json!({})));
    assert!(!Conn::direct_disabled_by_peer(
        &json!({ "direct": true })
    ));
    assert!(!Conn::direct_disabled_by_peer(
        &json!({ "direct": "false" })
    ));
}

/// The web-shell regression: a browser sent a valid offer, but the CLI's
/// direct-QUIC attempt owned the peer until DIRECT_BUDGET expired, so
/// `establish_as` silently refused the responder and the web UI sat on
/// "connecting". A transport hint must cancel that wait and build the
/// WebRTC link immediately, with no time advance.
#[tokio::test]
async fn a_browser_transport_hint_establishes_without_the_direct_wait() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let pid = "sid-browser";
    // Authenticated presence already resolved this peer. An unauthenticated
    // hint must not be able to replace these fields.
    conn.roster.insert(
        pid.to_string(),
        json!({ "id": pid, "name": "real-device", "uid": "real-uid" }),
    );

    // A direct attempt already armed, exactly as KnownPeer does before the
    // hint arrives on the next signaling message.
    let cancel = Arc::new(AtomicBool::new(false));
    conn.direct_pending.insert(
        pid.to_string(),
        DirectPending {
            attempt: net::AttemptId::next(),
            auth: DirectAuth::device(1, "web", "00"),
            race_task: None,
            secret: ("web".into(), "00".into()),
            fleet: false,
            lan: false,
            ephemeral: false,
            deadline: Instant::now() + Duration::from_secs(30),
            racing: false,
            endpoint: None,
            punch_sock: None,
            my_srflx: None,
            peer_server_public: None,
            server_public_dialed: Arc::new(AtomicBool::new(false)),
            probe: false,
            cancel: cancel.clone(),
        },
    );

    let t0 = Instant::now();
    assert!(
        conn.accept_transport_hint(
            pid,
            &json!({ "type": "transport-hint", "direct": false, "uid": "spoof-uid", "name": "spoof-name" }),
        )
        .await
    );
    assert!(
        conn.direct_pending.is_empty(),
        "the direct-QUIC wait was not cancelled"
    );
    assert!(
        cancel.load(Ordering::Relaxed),
        "the transport-offer re-emitter was not cancelled"
    );
    assert_eq!(conn.roster[pid]["name"], json!("real-device"));
    assert_eq!(conn.roster[pid]["uid"], json!("real-uid"));
    assert!(
        conn.links.contains_key(pid),
        "the WebRTC responder was not built immediately"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "establish waited {}ms after the hint",
        t0.elapsed().as_millis()
    );
    // The link built as the direct attempt's fallback must keep that
    // attempt's binding: its ChannelReady proves the target with it, and the
    // post-channel pair-proof is keyed by it. A rebuild that drops it leaves
    // a live, authenticated channel that the sender never treats as the
    // peer it asked for (gate 16 phase 2: "no peer connected within 60s").
    assert_eq!(
        conn.links[pid].expected_secret,
        Some(("web".to_string(), "00".to_string())),
        "the fallback link lost the cancelled direct attempt's pair binding"
    );
    assert!(conn.webrtc_only.contains(pid));

    // The periodic KnownPeer push replaces the roster entry and has no
    // `direct` field. The fact lives in the dedicated set, so it survives.
    conn.maybe_adopt(
        &json!({ "id": pid, "name": "web", "uid": "browser-uid" }),
        false,
    )
    .await
    .unwrap();
    assert!(
        conn.webrtc_only.contains(pid),
        "a KnownPeer push erased the WebRTC-only fact"
    );

    // A later KnownPeer / warm-hold tick must not re-arm the wait.
    conn.start_direct(pid, "web", "00").await;
    assert!(
        conn.direct_pending.is_empty(),
        "a re-announce re-armed the direct wait for a browser peer"
    );
}

/// The carry-forward above is scoped to the hint's own peer and to a direct
/// attempt that actually exists: a hint must never invent a pair binding,
/// and one peer's pending secret must never be attached to another peer.
#[tokio::test]
async fn a_transport_hint_binds_nothing_without_its_own_pending() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let cancel = Arc::new(AtomicBool::new(false));
    conn.direct_pending.insert(
        "sid-someone-else".into(),
        DirectPending {
            attempt: net::AttemptId::next(),
            auth: DirectAuth::device(1, "other", "11"),
            race_task: None,
            secret: ("other".into(), "11".into()),
            fleet: false,
            lan: false,
            ephemeral: false,
            deadline: Instant::now() + Duration::from_secs(30),
            racing: false,
            endpoint: None,
            punch_sock: None,
            my_srflx: None,
            peer_server_public: None,
            server_public_dialed: Arc::new(AtomicBool::new(false)),
            probe: false,
            cancel,
        },
    );
    let pid = "sid-no-direct-attempt";
    assert!(
        conn.accept_transport_hint(pid, &json!({ "direct": false }))
            .await
    );
    assert_eq!(
        conn.links[pid].expected_secret, None,
        "a hint invented a pair binding with no direct attempt of its own"
    );
    assert_eq!(
        conn.direct_pending["sid-someone-else"].secret,
        ("other".to_string(), "11".to_string()),
        "another peer's direct attempt was consumed by this hint"
    );
}

/// A hint can cancel a direct attempt while a link already exists (an ICE
/// agent still gathering has no transport yet, so `start_direct` legitimately
/// armed one alongside it). Then the hint takes the early "link present"
/// return: an EMPTY binding is filled from the cancelled attempt, and a
/// binding that is already established is never overwritten by it.
#[tokio::test]
async fn a_hint_fills_an_empty_binding_and_never_overwrites_one() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let pid = "sid-existing-link";
    let hint = json!({ "direct": false });
    assert!(conn.accept_transport_hint(pid, &hint).await);
    assert!(conn.links.contains_key(pid));

    let arm = |conn: &mut Conn, secret: (&str, &str)| {
        conn.direct_pending.insert(
            pid.into(),
            DirectPending {
                attempt: net::AttemptId::next(),
                auth: DirectAuth::device(1, secret.0, secret.1),
                race_task: None,
                secret: (secret.0.into(), secret.1.into()),
                fleet: false,
                lan: false,
                ephemeral: false,
                deadline: Instant::now() + Duration::from_secs(30),
                racing: false,
                endpoint: None,
                punch_sock: None,
                my_srflx: None,
                peer_server_public: None,
                server_public_dialed: Arc::new(AtomicBool::new(false)),
                probe: false,
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
    };

    // No binding yet: the cancelled attempt's own secret fills it.
    arm(&mut conn, ("web", "00"));
    assert!(conn.accept_transport_hint(pid, &hint).await);
    assert_eq!(
        conn.links[pid].expected_secret,
        Some(("web".to_string(), "00".to_string())),
        "an empty binding was not filled from the cancelled direct attempt"
    );

    // Bound already: the newer attempt must not replace it.
    conn.links.get_mut(pid).unwrap().expected_secret =
        Some(("first".into(), "22".into()));
    arm(&mut conn, ("second", "33"));
    assert!(conn.accept_transport_hint(pid, &hint).await);
    assert_eq!(
        conn.links[pid].expected_secret,
        Some(("first".to_string(), "22".to_string())),
        "a cancelled attempt overwrote an established pair binding"
    );
    assert!(
        conn.direct_pending.is_empty(),
        "the cancelled attempt was left armed"
    );
}

/// A hint is scoped to one sid/link. Drop/replacement and peer-left must
/// clear it so a later session on that sid (or a CLI peer reusing the
/// roster slot) is direct-first again.
#[tokio::test]
async fn a_transport_hint_is_cleared_with_its_link_or_peer() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-scoped";
    conn.webrtc_only.insert(pid.to_string());
    conn.drop_link(pid);
    assert!(!conn.webrtc_only.contains(pid), "drop_link kept the hint");
    conn.webrtc_only.insert(pid.to_string());
    conn.on_known_peer_left(&json!({ "id": pid, "channel": "chan" }));
    assert!(
        !conn.webrtc_only.contains(pid),
        "known-peer-left kept the hint"
    );
    conn.webrtc_only.insert(pid.to_string());
    conn.on_peer_left(&json!({ "id": pid }));
    assert!(!conn.webrtc_only.contains(pid), "peer-left kept the hint");
}

/// The L2/exec initiator deliberately races WebRTC against direct. Its
/// inbound offer must NOT cancel our pending direct attempt; only an
/// explicit `direct:false` hint may do that. Otherwise the direct link's
/// expiry/revocation close semantics regress.
#[tokio::test]
async fn an_offer_from_a_cli_peer_does_not_cancel_its_direct_race() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let pid = "sid-cli-race";
    let cancel = Arc::new(AtomicBool::new(false));
    conn.direct_pending.insert(
        pid.to_string(),
        DirectPending {
            attempt: net::AttemptId::next(),
            auth: DirectAuth::device(1, "box", "00"),
            race_task: None,
            secret: ("box".into(), "00".into()),
            fleet: false,
            lan: false,
            ephemeral: false,
            deadline: Instant::now() + Duration::from_secs(30),
            racing: false,
            endpoint: None,
            punch_sock: None,
            my_srflx: None,
            peer_server_public: None,
            server_public_dialed: Arc::new(AtomicBool::new(false)),
            probe: false,
            cancel: cancel.clone(),
        },
    );
    conn.ensure_responder(
        pid,
        &json!({
            "type": "description",
            "uid": "cli-uid",
            "description": { "type": "offer", "sdp": "v=0" }
        }),
    )
    .await
    .unwrap();
    assert!(
        conn.direct_pending.contains_key(pid),
        "a CLI peer's WebRTC offer cancelled its direct race"
    );
    assert!(
        !cancel.load(Ordering::Relaxed),
        "a CLI peer's offer cancelled the direct offer re-emitter"
    );
    assert!(
        !conn.links.contains_key(pid),
        "WebRTC was built while the direct race still owned the peer"
    );
}

/// Skipping direct for a browser must not disable the relay path: the hint
/// only removes the QUIC wait, and the WebRTC link is still built with the
/// session's relay policy/config.
#[tokio::test]
async fn a_hint_still_builds_the_relay_responder() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    conn.relay_only = true;
    let pid = "sid-relay-browser";
    assert!(
        conn.accept_transport_hint(pid, &json!({ "direct": false }))
            .await
    );
    assert!(conn.direct_pending.is_empty());
    assert!(
        conn.links.contains_key(pid),
        "the relay/WebRTC responder was suppressed by the hint"
    );
}

// --- post-PAKE promotion: make-before-break ---------------------------

/// A serving path that records every control type and frame offset, in
/// order, so a test can read what each end put on which path.
struct Rec {
    name: &'static str,
    log: Arc<std::sync::Mutex<Vec<String>>>,
    alive: AtomicBool,
    source: Option<net::SourceId>,
    attempt: net::AttemptId,
}
impl Rec {
    fn new(name: &'static str, log: &Arc<std::sync::Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Rec {
            name,
            log: log.clone(),
            alive: AtomicBool::new(true),
            source: Some(net::SourceId::next()),
            attempt: net::AttemptId::next(),
        })
    }
    fn without_source(
        name: &'static str,
        log: &Arc<std::sync::Mutex<Vec<String>>>,
        attempt: net::AttemptId,
    ) -> Arc<Self> {
        Arc::new(Rec {
            name,
            log: log.clone(),
            alive: AtomicBool::new(true),
            source: None,
            attempt,
        })
    }
    fn with_attempt(
        name: &'static str,
        log: &Arc<std::sync::Mutex<Vec<String>>>,
        attempt: net::AttemptId,
    ) -> Arc<Self> {
        Arc::new(Rec {
            name,
            log: log.clone(),
            alive: AtomicBool::new(true),
            source: Some(net::SourceId::next()),
            attempt,
        })
    }
}
#[async_trait::async_trait]
impl Transport for Rec {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        let kind = msg["type"].as_str().unwrap_or("?");
        self.log.lock().unwrap().push(format!("{}:{kind}", self.name));
        Ok(())
    }
    async fn send_frame(&self, _sid: u32, offset: u64, _payload: &[u8]) -> Result<()> {
        self.log.lock().unwrap().push(format!("{}:@{offset}", self.name));
        Ok(())
    }
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn max_payload(&self) -> usize {
        1024
    }
    fn is_dead(&self) -> bool {
        !self.alive.load(Ordering::Relaxed)
    }
    fn force_close(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn source_id(&self) -> Option<net::SourceId> {
        self.source
    }
    fn attempt_id(&self) -> Option<net::AttemptId> {
        Some(self.attempt)
    }
}

fn rec_log(log: &Arc<std::sync::Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().unwrap().clone()
}

/// The code-path WebRTC link a PAKE just authenticated: untrusted, no
/// stored secret, active.
fn code_link(conn: &mut Conn, pid: &str, t: Arc<dyn Transport>) {
    let mut l = relay_link(pid, "peer", "peer", t);
    l.trusted = false;
    l.expected_secret = None;
    l.verified_name = None;
    conn.links.insert(pid.to_string(), l);
    conn.active = Some(pid.to_string());
}

/// What `start_direct_promote` registers, without the network: the
/// ephemeral pending and the promotion, gated on the lead end. Returns the
/// exact armed attempt so a fixture transport can carry the same immutable
/// identity production receives from the race.
fn armed_promotion(
    conn: &mut Conn,
    pid: &str,
    role: PromoteRole,
    deadline: Instant,
) -> net::AttemptId {
    let attempt = net::AttemptId::next();
    conn.direct_pending.insert(
        pid.to_string(),
        DirectPending {
            attempt,
            auth: DirectAuth::ephemeral(1),
            race_task: None,
            secret: (pid.to_string(), "ceremony".into()),
            fleet: false,
            lan: false,
            ephemeral: true,
            deadline,
            racing: true,
            endpoint: None,
            punch_sock: None,
            my_srflx: None,
            peer_server_public: None,
            server_public_dialed: Arc::new(AtomicBool::new(false)),
            probe: false,
            cancel: Arc::new(AtomicBool::new(false)),
        },
    );
    let auth = conn.direct_pending.get(pid).map(|pending| pending.auth.clone());
    let mut state = PromoteState::new(role);
    state.attempt = Some(attempt);
    state.auth = auth;
    conn.promotions.insert(pid.to_string(), state);
    conn.gate_for_promotion(pid);
    attempt
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

/// A direct attempt that lost its race, without the network: the deadline
/// is already past, so the next reaper call returns it.
fn expired_direct_pending(conn: &mut Conn, pid: &str, deadline: Instant) {
    conn.direct_pending.insert(
        pid.to_string(),
        DirectPending {
            attempt: net::AttemptId::next(),
            auth: DirectAuth::fleet(1),
            race_task: None,
            secret: (pid.to_string(), "fleet".into()),
            fleet: true,
            lan: false,
            ephemeral: false,
            deadline,
            racing: false,
            endpoint: None,
            punch_sock: None,
            my_srflx: None,
            peer_server_public: None,
            server_public_dialed: Arc::new(AtomicBool::new(false)),
            probe: false,
            cancel: Arc::new(AtomicBool::new(false)),
        },
    );
}

/// THE latency fix. The promotion used to tear the authenticated WebRTC
/// link down here and make the transfer wait for QUIC. It must keep the
/// link, put the transfer's gate around it, and leave it to be announced
/// so the offer goes out on it at once.
#[tokio::test]
async fn a_promotion_keeps_the_serving_link_and_announces_it() {
    let (mut conn, _far, mut rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-code";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let promo = conn
        .start_direct_promote(pid, pid, "ceremony", PromoteRole::Lead, true)
        .await;
    assert!(conn.links.contains_key(pid), "the promotion tore the serving link down");
    assert!(conn.is_active(pid), "the promotion released the transfer slot");
    assert!(
        conn.direct_pending.get(pid).is_some_and(|p| p.ephemeral),
        "no direct race was armed beside the link"
    );
    let served = conn.transport_of(pid).expect("the link lost its transport");
    assert!(handoff::as_handoff(&served).is_some(), "the transfer would not ride the gate");
    conn.rearm_channel_ready(pid, promo);
    let mut announced = false;
    while let Ok(ev) = rx.try_recv() {
        // The announcement must SURVIVE the loop's exact-source gate. The
        // gate fails closed on an untagged ChannelReady, so a handoff
        // wrapper that hides its serving transport's source makes this
        // re-emit vanish: no offer is ever sent and a `receive <code>`
        // waits forever after "authenticated, sending". Routing the event
        // through `stage_event` is what pins that (regression: the wrapper
        // returned the trait default `None`, the event arrived untagged and
        // was dropped here).
        if let Some((Ev::ChannelReady(p, t), source)) = conn.stage_event(ev) {
            announced = p == pid
                && Arc::ptr_eq(&t, &served)
                && source == conn.link(pid).map(|l| l.source);
        }
    }
    assert!(
        announced,
        "the retained link was not announced, so nothing would be offered"
    );
}

/// A peer that does not advertise `handoff` (an older CLI) tears its own
/// WebRTC link down at confirm and never answers `path-promote`. Against
/// it the promotion must do what it always did: replace the link at once,
/// arm no promotion and no frame gate, and let the winner adopt directly.
#[tokio::test]
async fn an_old_peer_gets_the_old_promotion() {
    let (mut conn, _far, mut rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-old-cli";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let promo = conn
        .start_direct_promote(pid, pid, "ceremony", PromoteRole::Lead, false)
        .await;
    assert_eq!(promo, Promotion::Replaced);
    assert!(!conn.links.contains_key(pid), "kept a link the old peer is closing");
    assert!(conn.promotions.is_empty(), "armed a handoff the old peer cannot answer");
    assert!(conn.direct_pending.get(pid).is_some_and(|p| p.ephemeral));
    conn.rearm_channel_ready(pid, promo);
    assert!(
        !std::iter::from_fn(|| rx.try_recv().ok())
            .any(|ev| matches!(ev, Ev::ChannelReady(..))),
        "announced a link that was replaced"
    );
    // The race's expiry still falls back to WebRTC, as before.
    conn.direct_pending.get_mut(pid).unwrap().deadline = Instant::now() - Duration::from_millis(1);
    assert_eq!(conn.expired_direct().len(), 1, "the old fallback was not armed");
}

/// A FLEET direct is keyed by the secret the whole fleet shares: it proves
/// fleet membership, not who the peer is. So a link that had been
/// PAIR-PROVEN must not keep that standing when it adopts a fleet-keyed
/// direct: the standing has to be re-established by the verified fleet
/// hello. Before this, the adopted link still read as pair-trusted with the
/// pair's name and principal, so a transport that authenticates only
/// against the fleet secret carried pair standing (and a cut in place left
/// it behind).
#[tokio::test]
async fn a_pair_proven_link_that_adopts_a_fleet_direct_loses_the_pair_standing() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-fleet";
    // The link before the adoption: a PAIR-proven WebRTC link, still
    // live. A live DIRECT primary with another attempt is not replaceable
    // through this path, so the fixture has to be the non-direct link that
    // adopts a fleet direct IN PLACE, which is the case this is about.
    let mut link = relay_link(pid, "peer", "peer", Rec::new("webrtc", &log));
    link.trusted = true;
    link.verified_name = Some("peer".to_string());
    link.principal_kind = PrincipalKind::OwnerDevice;
    link.expected_secret = Some(("peer".to_string(), "pair-secret".to_string()));
    conn.links.insert(pid.to_string(), link);

    // A fleet-keyed attempt for that peer: the pending says the attempt is
    // a fleet one, so the adoption is the fleet case.
    let attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(attempt, ("peer", "fleet-rv"));
    pending.fleet = true;
    pending.auth = DirectAuth::fleet(1);
    conn.direct_pending.insert(pid.to_string(), pending);

    let quic: Arc<dyn Transport> = Rec::with_attempt("quic", &log, attempt);
    assert!(matches!(
        conn.adopt_direct(pid, quic.clone(), "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    let l = conn.link(pid).expect("the adopted link");
    assert!(l.direct, "the adoption did not replace the transport");
    // The pair standing is gone: the fleet hello has to re-establish it.
    assert!(!l.trusted, "a fleet-keyed link kept pair trust");
    assert!(l.verified_name.is_none(), "a fleet-keyed link kept the pair name");
    assert!(
        matches!(l.principal_kind, PrincipalKind::Delegated { .. }),
        "a fleet-keyed link kept the pair principal"
    );
    assert!(!l.is_sibling_link(), "a fleet-keyed link read as a sibling");
    assert!(!l.fleet_proven(), "a fleet-keyed link claimed a proven fleet link");
    // The binding is the fleet one now, and the link is not yet a sibling
    // until the hello names it.
    assert_eq!(
        l.expected_secret.as_ref().map(|(_, s)| s.as_str()),
        Some("fleet-rv"),
        "the fleet binding did not replace the pair one"
    );
}

#[tokio::test]
async fn direct_adoption_does_not_grant_pair_standing_for_stale_or_revoked_binding() {
    for (held, revoked, expect_trusted) in [
        (None, false, false),
        (Some("different"), false, false),
        (Some("pair-secret"), true, false),
        (Some("pair-secret"), false, true),
    ] {
        let host = Arc::new(TestHost {
            fleet_rv: true,
            devices: held.map(|s| vec![("peer".into(), s.into())]).unwrap_or_default(),
            revoked_records: if revoked { vec!["peer".into()] } else { vec![] },
            ..TestHost::default()
        });
        let (mut conn, _far, _rx) = test_conn_with_host(host).await;
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pid = "sid-pair";
        conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", Rec::new("webrtc", &log)));
        let attempt = net::AttemptId::next();
        conn.direct_pending.insert(pid.into(), direct_pending_with(attempt, ("peer", "pair-secret")));
        let quic: Arc<dyn Transport> = Rec::with_attempt("quic", &log, attempt);
        assert!(matches!(conn.adopt_direct(pid, quic, "direct-quic"), DirectAdoption::Adopted { .. }));
        assert_eq!(conn.link(pid).unwrap().trusted, expect_trusted, "held={held:?}, revoked={revoked}");
    }
}

/// The whole fleet standing cycle on a real Link, through the same
/// functions the hello arm and the ChannelReady rotation call: an
/// admitted sibling adopts a fleet-keyed direct in place (Delegated, the
/// binding rotated), the rotation drops the verdict earned on the old
/// binding and leaves our hello owed, and the next verified hello makes
/// the link a FleetSibling again. Before the epoch stamps, nothing in
/// this path tied the verdict to the binding that earned it.
#[cfg(feature = "dispatch")]
#[tokio::test]
async fn a_sibling_that_adopts_a_fleet_direct_is_a_sibling_again_after_its_hello() {
    use crate::recv::dispatch::{
        admit_verified_fleet_hello, fleet_standing_after_rotation, link_epoch,
    };
    use crate::recv::fleet_bind::Standing;
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-sib";
    let mut link = relay_link(pid, "sib", "sib", Rec::new("webrtc", &log));
    link.trusted = false;
    link.verified_name = None;
    link.expected_secret = None;
    link.principal_kind = PrincipalKind::Delegated { caps: Vec::new() };
    conn.links.insert(pid.to_string(), link);
    let mut standing = Standing::default();
    let mut verified = std::collections::HashSet::new();
    let mut pending = std::collections::HashSet::new();
    let (owner, device) = ([1u8; 32], [2u8; 32]);

    // 1. FleetSibling: the hello verified on the WebRTC binding.
    let old = link_epoch(&conn, pid).expect("installed");
    assert!(admit_verified_fleet_hello(
        &mut conn, &mut standing, &mut verified, pid, Some("sib".into()), owner, device, u64::MAX
    ));
    standing.greeted(pid, old);
    assert!(conn.link(pid).unwrap().is_sibling_link(), "the hello did not admit a sibling");

    // 2. Rotate: a fleet-keyed direct is adopted in place.
    let attempt = net::AttemptId::next();
    let mut p = direct_pending_with(attempt, ("sib", "fleet-rv"));
    p.fleet = true;
    p.auth = DirectAuth::fleet(1);
    conn.direct_pending.insert(pid.to_string(), p);
    let quic: Arc<dyn Transport> = Rec::with_attempt("quic", &log, attempt);
    assert!(matches!(
        conn.adopt_direct(pid, quic, "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    let new = link_epoch(&conn, pid).expect("installed");
    assert_ne!(old, new, "the adoption did not rotate the binding epoch");

    // 3. Delegated: nothing the old binding proved stands on the new one.
    let l = conn.link(pid).unwrap();
    assert!(matches!(l.principal_kind, PrincipalKind::Delegated { .. }));
    assert!(!l.is_sibling_link());
    assert!(
        fleet_standing_after_rotation(&mut standing, &mut verified, &mut pending, pid, new),
        "the rotation kept a verdict from the old binding"
    );
    assert!(!verified.contains(pid));
    assert!(pending.contains(pid), "the hello was not queued again");
    assert!(standing.hello_owed(pid, Some(new)), "our hello is not owed on the new binding");

    // 4. Hello on the new binding: a sibling again, and the verdict is
    // stamped with the new epoch, so the same rotation event replayed
    // does not drop it.
    assert!(admit_verified_fleet_hello(
        &mut conn, &mut standing, &mut verified, pid, Some("sib".into()), owner, device, u64::MAX
    ));
    let l = conn.link(pid).unwrap();
    assert!(matches!(l.principal_kind, PrincipalKind::FleetSibling));
    assert!(l.is_sibling_link(), "the link did not become a sibling again");
    assert_eq!(l.verified_name.as_deref(), Some("sib"));
    assert!(!fleet_standing_after_rotation(&mut standing, &mut verified, &mut pending, pid, new));
    assert!(verified.contains(pid), "a verdict on the installed binding was dropped");
}

/// Code authority follows the old-peer promotion: the direct link the
/// ceremony's armed attempt publishes holds; another attempt is refused.
#[tokio::test]
async fn a_replaced_promotion_carries_code_authority_to_its_own_direct_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-code-old";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let promo = conn
        .start_direct_promote(pid, pid, "ceremony", PromoteRole::Lead, false)
        .await;
    assert_eq!(promo, Promotion::Replaced);
    conn.bind_code_session(pid, ("fp-a", "fp-b"), "ceremony");
    let attempt = conn.direct_pending.get(pid).expect("an armed attempt").attempt;
    let mut cache = CodeAuthorityCache::default();
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::NoLink);

    let quic: Arc<dyn Transport> = Rec::with_attempt("quic", &log, attempt);
    assert!(matches!(
        conn.adopt_direct(pid, quic.clone(), "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    assert_eq!(conn.code_authority(pid).await, Ok(()));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Holds);

    let foreign: Arc<dyn Transport> = Rec::with_attempt("foreign", &log, net::AttemptId::next());
    assert!(!matches!(
        conn.adopt_direct(pid, foreign, "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    assert!(conn.transport_of(pid).is_some_and(|t| Arc::ptr_eq(&t, &quic)));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Holds);

    // The same link under another attempt is not this ceremony's.
    conn.links.get_mut(pid).unwrap().attempt = Some(net::AttemptId::next());
    assert_eq!(conn.code_authority(pid).await, Err(CodeAuthorityRefusal::ForeignDirect));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Lost);
}

/// Code authority follows the make-before-break handoff: the confirmed
/// WebRTC link holds before it, the ceremony's direct link after it.
#[tokio::test]
async fn a_handed_promotion_carries_code_authority_to_its_own_direct_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-code-new";
    let webrtc: Arc<dyn Transport> = Rec::new("webrtc", &log);
    let webrtc_attempt = webrtc.attempt_id().expect("a fixture attempt");
    code_link(&mut conn, pid, webrtc);
    let promo = conn
        .start_direct_promote(pid, pid, "ceremony", PromoteRole::Lead, true)
        .await;
    assert_eq!(promo, Promotion::Retained);
    conn.bind_code_session(pid, ("fp-a", "fp-b"), "ceremony");
    let attempt = conn.direct_pending.get(pid).expect("an armed attempt").attempt;
    assert_eq!(conn.code_authority_on(pid, Some(("fp-a", "fp-b"))), Ok(()));

    let quic: Arc<dyn Transport> = Rec::with_attempt("quic", &log, attempt);
    {
        let promotion = conn.promotions.get_mut(pid).expect("a promotion");
        promotion.standby = Some((quic.clone(), "direct-quic"));
        promotion.handed = true;
    }
    // While handed, another attempt is not adopted and changes nothing.
    let foreign: Arc<dyn Transport> = Rec::with_attempt("foreign", &log, net::AttemptId::next());
    assert_eq!(conn.adopt_direct(pid, foreign.clone(), "direct-quic"), DirectAdoption::Rejected);
    assert!(foreign.is_dead());
    assert!(!conn.link(pid).expect("the serving link").direct);
    assert!(conn.promotions.get(pid).is_some_and(|p| p.handed));
    assert!(conn.direct_pending.contains_key(pid));
    assert!(matches!(
        conn.adopt_direct(pid, quic.clone(), "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    let l = conn.link(pid).expect("the link");
    assert!(l.direct, "the serving link was not retired");
    assert!(l.transport.as_ref().is_some_and(|t| Arc::ptr_eq(t, &quic)));
    assert_eq!(l.attempt, Some(attempt));
    // Retired and replaced, not updated in place: the serving link's own
    // attempt is retired and the promotion is gone.
    assert!(conn.retired_attempts.contains_key(&webrtc_attempt));
    assert!(!conn.promotions.contains_key(pid));
    let mut cache = CodeAuthorityCache::default();
    assert_eq!(conn.code_authority(pid).await, Ok(()));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Holds);

    // After adoption, another attempt is still not adopted.
    let late: Arc<dyn Transport> = Rec::with_attempt("late", &log, net::AttemptId::next());
    assert_eq!(conn.adopt_direct(pid, late, "direct-quic"), DirectAdoption::Rejected);
    assert!(conn.transport_of(pid).is_some_and(|t| Arc::ptr_eq(&t, &quic)));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Holds);

    // A cached verdict does not survive a changed secret on the same link.
    conn.links.get_mut(pid).unwrap().expected_secret = Some((pid.to_string(), "other".into()));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Lost);

    // Restored, it holds; under another attempt it does not.
    conn.links.get_mut(pid).unwrap().expected_secret = Some((pid.to_string(), "ceremony".into()));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Holds);
    conn.links.get_mut(pid).unwrap().attempt = Some(net::AttemptId::next());
    assert_eq!(conn.code_authority(pid).await, Err(CodeAuthorityRefusal::ForeignDirect));
    assert_eq!(conn.code_continuation(pid, &mut cache).await, CodeContinuation::Lost);
}

/// QUIC never comes up: WebRTC keeps serving. No fallback establish (the
/// old rebuild), no teardown, nothing left armed.
#[tokio::test]
async fn a_lost_race_leaves_webrtc_serving_with_nothing_to_rebuild() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lost";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let _ = armed_promotion(&mut conn, pid, PromoteRole::Lead, Instant::now() - Duration::from_millis(1));
    let fell_back = conn.expired_direct();
    assert!(fell_back.is_empty(), "a lost race rebuilt WebRTC: {fell_back:?}");
    assert!(conn.links.contains_key(pid), "the serving link was dropped");
    assert!(conn.direct_pending.is_empty() && conn.promotions.is_empty());
    let t = conn.transport_of(pid).unwrap();
    t.send_frame(1, 0, b"x").await.unwrap();
    assert_eq!(rec_log(&log), vec!["webrtc:@0"], "the transfer did not stay on WebRTC");
}

/// A fleet join starts one direct attempt per sibling, so the attempts that
/// lose their race expire together. Each fallback is a full WebRTC establish
/// awaited inline by the daemon loop, so the reaper must hand them over one
/// at a time: draining the whole batch in one loop turn added N establishes
/// to one iteration and exceeded the 20 s loop watchdog. Deferring must not
/// drop a peer: every pending is returned on a later call.
#[tokio::test]
async fn expired_direct_returns_one_fallback_per_call() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    for pid in ["sid-a", "sid-b", "sid-c"] {
        expired_direct_pending(&mut conn, pid, Instant::now() - Duration::from_millis(1));
    }
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        let batch = conn.expired_direct();
        assert_eq!(batch.len(), 1, "more than one fallback in a single loop turn");
        seen.insert(batch[0].0.clone());
    }
    assert_eq!(seen.len(), 3, "a peer was dropped instead of deferred: {seen:?}");
    assert!(conn.direct_pending.is_empty(), "deferred fallbacks were not drained");
    assert!(conn.expired_direct().is_empty());
}

/// A LAN reservation has no signaling peer to establish: expiry retires its
/// exact attempt and never returns a pid for a WebRTC fallback. A fleet LAN
/// reservation is still a LAN reservation; an ordinary expired attempt
/// still falls back exactly as before.
#[tokio::test]
async fn expired_lan_reservation_retires_without_webrtc_fallback() {
    let (mut conn, _far, _rx) = test_conn().await;
    let past = Instant::now() - Duration::from_millis(1);
    let lan_pid = "sid-lan-expired-device";
    let lan_attempt = net::AttemptId::next();
    conn.seed_lan(lan_pid, "dev", "secret", false, lan_attempt);
    conn.direct_pending.get_mut(lan_pid).unwrap().deadline = past;
    let fleet_pid = "sid-lan-expired-fleet";
    let fleet_attempt = net::AttemptId::next();
    conn.seed_lan(fleet_pid, "fleet", "fleet-rv", true, fleet_attempt);
    conn.direct_pending.get_mut(fleet_pid).unwrap().deadline = past;
    let normal_pid = "sid-normal-expired";
    expired_direct_pending(&mut conn, normal_pid, past);

    let batch = conn.expired_direct();
    assert!(
        batch.iter().all(|(pid, _, _)| pid != lan_pid && pid != fleet_pid),
        "a LAN reservation was handed to the WebRTC fallback"
    );
    assert_eq!(batch.len(), 1, "the normal pending must still fall back");
    assert_eq!(batch[0].0, normal_pid);
    assert!(!conn.direct_pending.contains_key(lan_pid));
    assert!(!conn.direct_pending.contains_key(fleet_pid));
    assert!(conn.retired_attempts.contains_key(&lan_attempt));
    assert!(conn.retired_attempts.contains_key(&fleet_attempt));
    assert!(!conn.direct_pending.contains_key(normal_pid));
}

/// A fleet one-shot's direct race must outlive the fleet-secret WebRTC link
/// that lands beside it. That WebRTC link exposes no channel binding, so it
/// can never carry the certificate proof the one-shot must present. Reaping
/// the race here retired the only attempt able to prove the dialer, and
/// `adopt_direct` then rejected the valid QUIC connection as `attempt
/// retired` (the one-shot saw `direct connection closed` right after
/// `tunnel up`).
#[tokio::test]
async fn a_fleet_direct_attempt_outlives_its_unbound_webrtc_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-fleet-oneshot";
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    expired_direct_pending(&mut conn, pid, soon());
    let attempt = conn.direct_pending[pid].attempt;

    assert!(conn.expired_direct().is_empty(), "a live link armed a fallback");
    assert!(
        conn.direct_pending.contains_key(pid),
        "the fleet race was reaped by an unproven WebRTC link"
    );
    assert!(
        !conn.retired_attempts.contains_key(&attempt),
        "the direct attempt was retired before its connection could be adopted"
    );

    // The exception is bounded by the attempt's own budget: once it has
    // expired the pending is retired (no fallback is needed, a link exists).
    conn.direct_pending.get_mut(pid).unwrap().deadline =
        Instant::now() - Duration::from_millis(1);
    assert!(conn.expired_direct().is_empty());
    assert!(!conn.direct_pending.contains_key(pid), "an expired fleet pending leaked");
    assert!(
        conn.retired_attempts.contains_key(&attempt),
        "an expired fleet attempt was not retired"
    );
}

/// The fleet exception must not change the ordinary cleanup: for any other
/// attempt, a link that landed by another route makes the direct race
/// redundant and it is retired exactly as before.
#[tokio::test]
async fn a_normal_direct_attempt_is_still_reaped_by_its_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-normal-linked";
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    expired_direct_pending(&mut conn, pid, soon());
    conn.direct_pending.get_mut(pid).unwrap().fleet = false;
    let attempt = conn.direct_pending[pid].attempt;

    assert!(conn.expired_direct().is_empty());
    assert!(!conn.direct_pending.contains_key(pid), "a redundant direct attempt survived");
    assert!(conn.retired_attempts.contains_key(&attempt));
}

/// The dispatch loop's shape: one reaper call and one awaited establish per
/// iteration, with the watchdog heartbeat stamped at the top. An establish
/// stand-in is awaited for each fallback; with the batch capped, the
/// heartbeat advances between them instead of only after all of them.
/// Before the cap, the first iteration returned every expired attempt, so
/// N establishes ran against ONE heartbeat.
#[tokio::test]
async fn expired_direct_keeps_the_loop_heartbeat_between_fallbacks() {
    const PEERS: usize = 4;
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    for n in 0..PEERS {
        expired_direct_pending(
            &mut conn,
            &format!("sid-{n}"),
            Instant::now() - Duration::from_millis(1),
        );
    }
    let mut beats = 0usize;
    let mut fallbacks = 0usize;
    let mut largest_batch = 0usize;
    // Bounded by PEERS: one fallback per iteration, so the loop above
    // drains every peer in exactly PEERS turns.
    for _ in 0..PEERS {
        beats += 1; // top-of-iteration watchdog tick
        let batch = conn.expired_direct();
        largest_batch = largest_batch.max(batch.len());
        for (_pid, _info, _secret) in batch {
            // Stands in for the awaited WebRTC establish. Its real ceiling
            // is ICE_CONFIG_BUDGET + PEER_BUILD_BUDGET (8 s cold).
            tokio::time::sleep(Duration::from_millis(5)).await;
            fallbacks += 1;
        }
    }
    assert_eq!(largest_batch, 1, "one loop turn drained more than one fallback");
    assert_eq!(fallbacks, PEERS, "a deferred fallback was never established");
    assert_eq!(beats, PEERS, "the loop advanced one heartbeat per fallback");
    assert!(conn.direct_pending.is_empty(), "a deferred fallback was left pending");
}

/// Deferring one per call must not starve a long-expired attempt. The
/// earliest deadline is always the one returned next.
#[tokio::test]
async fn expired_direct_falls_back_earliest_deadline_first() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let now = Instant::now();
    expired_direct_pending(&mut conn, "sid-new", now - Duration::from_secs(1));
    expired_direct_pending(&mut conn, "sid-old", now - Duration::from_secs(3));
    expired_direct_pending(&mut conn, "sid-mid", now - Duration::from_secs(2));
    let order: Vec<String> = std::iter::from_fn(|| conn.expired_direct().pop())
        .map(|(pid, _, _)| pid)
        .collect();
    assert_eq!(
        order,
        vec!["sid-old".to_string(), "sid-mid".to_string(), "sid-new".to_string()]
    );
}

fn build_state(generation: u32) -> BuildState {
    let (_tx, events_rx) = mpsc::unbounded_channel();
    BuildState {
        generation,
        cancel: Arc::new(BuildCancel::new()),
        handle: tokio::spawn(async {}),
        started: Instant::now(),
        signals: std::collections::VecDeque::new(),
        signal_bytes: 0,
        early: std::collections::VecDeque::new(),
        early_bytes: 0,
        events_rx: std::sync::Mutex::new(events_rx),
        binding: None,
    }
}

/// Test build state plus its candidate-local sender, so a test can prove
/// which events reach the installed link and which are discarded.
fn build_state_with_tx(generation: u32) -> (BuildState, mpsc::UnboundedSender<Ev>) {
    let (tx, events_rx) = mpsc::unbounded_channel();
    let mut state = build_state(generation);
    state.events_rx = std::sync::Mutex::new(events_rx);
    (state, tx)
}

fn direct_pending_with(attempt: net::AttemptId, secret: (&str, &str)) -> DirectPending {
    DirectPending {
        attempt,
        auth: DirectAuth::device(1, secret.0, secret.1),
        race_task: None,
        secret: (secret.0.into(), secret.1.into()),
        fleet: false,
        lan: false,
        ephemeral: false,
        deadline: Instant::now() + Duration::from_secs(30),
        racing: false,
        endpoint: None,
        punch_sock: None,
        my_srflx: None,
        peer_server_public: None,
        server_public_dialed: Arc::new(AtomicBool::new(false)),
        probe: false,
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

/// Prepare one intent for a test, optionally recording its binding first.
fn prepared_plan(conn: &mut Conn, pid: &str, binding: Option<(&str, &str)>) -> BuildPlan {
    if let Some((name, secret)) = binding {
        conn.note_binding(pid, (name.to_string(), secret.to_string()));
    }
    conn.prepare_build(
        json!({ "id": pid, "name": "peer" }),
        None,
        std::panic::Location::caller(),
        Replace::StuckAttempt,
    )
    .expect("prepare")
    .expect("a plan")
}

/// Candidate events never travel on the main queue, so an old link's
/// Control/PcState cannot be replayed onto a replacement. The dedicated
/// channel is the provenance.
#[tokio::test]
async fn candidate_events_are_candidate_local() {
    let (mut conn, _far, mut _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-building";
    let old = Rec::new("old", &log);
    let mut link = relay_link(pid, "peer", "peer", old.clone());
    link.transport = Some(old.clone());
    conn.links.insert(pid.to_string(), link);
    let (state, candidate_tx) = build_state_with_tx(7);
    conn.builds.insert(pid.to_string(), state);
    // A loop-authored event passes straight through the main queue.
    let old_event = Ev::LocalControl(pid.to_string(), json!({ "type": "ping" }));
    assert!(conn.stage_event(old_event).is_some());
    // Only events sent on the build's own channel are buffered.
    let candidate = Rec::new("candidate", &log);
    candidate_tx
        .send(Ev::ChannelReady(pid.to_string(), candidate))
        .unwrap();
    conn.pump_builds();
    assert_eq!(conn.builds[pid].early.len(), 1);
}

/// An installed WebRTC link's events wake the loop: the first event queues
/// one `BuildWake` on the main queue, further events before the next drain
/// queue none, and `pump_builds` forwards them in order and re-arms the
/// wake. Before this, nothing woke the loop and the events waited for an
/// unrelated one (promote-mbb M1/M3: 2.41 or 3.61 s instead of ~0.1 s).
#[tokio::test]
async fn an_installed_links_events_wake_the_loop_once_per_drain() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-wake";
    let t = Rec::new("webrtc", &log);
    let link = relay_link(pid, "peer", "peer", t);
    let generation = link.generation;
    conn.links.insert(pid.to_string(), link);
    let (candidate_tx, candidate_rx) = mpsc::unbounded_channel();
    conn.link_events.insert(
        pid.to_string(),
        LinkEvents {
            generation,
            rx: std::sync::Mutex::new(candidate_rx),
            departure_ready: None,
            departure_pending: None,
        },
    );
    let sink = net::EvSink::waking(candidate_tx, conn.tx.clone(), conn.candidate_wake.clone());
    let wakes = |rx: &mut mpsc::UnboundedReceiver<Ev>| {
        let mut n = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, Ev::BuildWake) {
                n += 1;
            }
        }
        n
    };
    let _ = wakes(&mut rx);

    for i in 0..50 {
        sink.send(Ev::Control(pid.to_string(), json!({ "type": "data", "i": i })))
            .unwrap();
    }
    assert_eq!(wakes(&mut rx), 1, "a burst must wake the loop exactly once");

    conn.pump_builds();
    let mut seen = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let Ev::Control(from, v) = ev {
            assert_eq!(from, pid);
            seen.push(v["i"].as_i64().unwrap());
        }
    }
    assert_eq!(seen, (0..50).collect::<Vec<i64>>(), "forwarded in order, none lost");

    sink.send(Ev::Control(pid.to_string(), json!({ "type": "data", "i": 50 })))
        .unwrap();
    assert_eq!(wakes(&mut rx), 1, "the drain must re-arm the wake");
}

/// The departure path drains the link's queue directly. With no forwarder
/// between the peer and that queue, an event the peer sent before departure
/// is already in it, so the drain sees it; and once the queue is gone a
/// late send fails and wakes nothing.
#[tokio::test]
async fn a_sent_event_is_in_the_queue_at_departure_and_a_dropped_queue_wakes_nothing() {
    let (conn, _far, mut rx) = test_conn().await;
    let (candidate_tx, mut candidate_rx) = mpsc::unbounded_channel();
    let sink = net::EvSink::waking(candidate_tx, conn.tx.clone(), conn.candidate_wake.clone());
    sink.send(Ev::Control("p".into(), json!({ "type": "l2-close", "sid": 1 })))
        .unwrap();
    // No await between the send and the drain: nothing else had to run.
    match candidate_rx.try_recv() {
        Ok(Ev::Control(_, v)) => assert_eq!(v["type"], "l2-close"),
        _ => panic!("the final control was not in the link's queue"),
    }
    while rx.try_recv().is_ok() {}
    conn.candidate_wake.store(false, Ordering::SeqCst);
    drop(candidate_rx);
    assert!(
        sink.send(Ev::Control("p".into(), json!({ "type": "late" }))).is_err(),
        "a dropped link's queue must refuse the event"
    );
    assert!(
        !std::iter::from_fn(|| rx.try_recv().ok()).any(|ev| matches!(ev, Ev::BuildWake)),
        "a dropped link's event woke the loop"
    );
}

/// Signaling can arrive before installation; the envelope names the peer in
/// `from`, which is what a candidate build must be matched on.
#[tokio::test]
async fn candidate_signals_are_staged_by_from_and_bounded_on_cancel() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-signal";
    conn.builds.insert(pid.to_string(), build_state(3));
    assert!(conn.stage_signal(&json!({ "from": pid, "data": { "type": "description" } })));
    assert!(!conn.stage_signal(&json!({ "from": "someone-else", "data": {} })));
    conn.cancel_build(pid);
    assert!(!conn.builds.contains_key(pid));
    assert!(conn.pending_bindings.is_empty());
}

/// The shipping path, not the inline test convenience: establish spawns a
/// task and the completion pump installs the link. This test sets the
/// test-only inline flag off on its own current thread.
#[tokio::test(flavor = "current_thread")]
async fn shipping_path_spawns_and_pumps_a_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-shipping";
    test_inline::set(false);
    let result = conn
        .establish_as(
            json!({ "id": pid, "name": "peer", "uid": "uid-shipping" }),
            Some(true),
        )
        .await;
    if result.is_err() {
        test_inline::set(true);
        panic!("shipping establish failed: {result:?}");
    }
    for _ in 0..100 {
        conn.pump_builds();
        if conn.links.contains_key(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    test_inline::set(true);
    assert!(
        conn.links.contains_key(pid),
        "the shipping task path never installed its link"
    );
    assert!(conn.builds.is_empty());
}

/// A present peer is being connected from adoption on, before its build
/// installs a link: the fleet presence evidence is kept through exactly
/// that window (recv dispatch), and lost once nothing connects to it.
#[tokio::test(flavor = "current_thread")]
async fn a_peer_with_an_uninstalled_build_is_connecting() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-building";
    assert!(!conn.connecting_or_linked(pid));
    conn.builds.insert(pid.to_string(), build_state(1));
    assert!(!conn.links.contains_key(pid), "premise: no link while it builds");
    assert!(conn.connecting_or_linked(pid));
    conn.cancel_build(pid);
    assert!(!conn.connecting_or_linked(pid));
}

/// The production retry ladder: every stuck rebuild goes through the
/// off-loop build and `install_built`. Before the fix the install reset
/// `attempts` to 0 (the stamp `on_retry_due` put on the old link died with
/// it), so a dead peer was re-dialled at "retrying (2/5)" forever and
/// every digest clock restarted. The ladder must exhaust and drop the link.
#[tokio::test(flavor = "current_thread")]
async fn shipping_stuck_rebuilds_keep_the_episode_and_exhaust() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-departed";
    conn.establish_as(
        json!({ "id": pid, "name": "ci-worker", "uid": "uid-departed" }),
        Some(true),
    )
    .await
    .expect("a WebRTC link that will never connect");
    conn.room_digest_absent.insert(pid.to_string(), 1);
    let deferred_at = Instant::now();
    conn.digest_deferred.insert(pid.to_string(), deferred_at);
    let mut rebuilds = 0u32;
    loop {
        let Some(g) = conn.links.get(pid).map(|l| l.generation) else {
            break;
        };
        assert!(
            rebuilds < MAX_ATTEMPTS + 1,
            "the ladder never exhausted ({rebuilds} rebuilds)"
        );
        conn.on_stuck(pid, g, "stuck").await.unwrap();
        if !conn.links.contains_key(pid) {
            break;
        }
        test_inline::set(false);
        let due = conn.on_retry_due(pid, g).await;
        test_inline::set(true);
        due.unwrap();
        for _ in 0..200 {
            conn.pump_builds();
            if conn.links.get(pid).is_some_and(|l| l.generation != g) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let l = conn.links.get(pid).expect("the rebuild installed");
        assert_ne!(l.generation, g, "the off-loop rebuild never installed");
        rebuilds += 1;
        assert_eq!(l.attempts, rebuilds, "the install lost the ladder count");
        assert_eq!(conn.room_digest_absent.get(pid), Some(&1));
        assert_eq!(conn.digest_deferred.get(pid), Some(&deferred_at));
    }
    assert!(!conn.links.contains_key(pid), "the dead peer is still linked");
    assert_eq!(rebuilds, MAX_ATTEMPTS - 1);
}

/// At the link cap a new contact (an enrolling device) displaces a link
/// the retry ladder keeps failing on, never a link that has not failed.
#[tokio::test]
async fn link_cap_admits_a_new_contact_over_a_retrying_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    for i in 0..MAX_LINKS {
        conn.establish_as(
            json!({ "id": format!("sid-{i}"), "name": format!("p{i}"), "uid": format!("uid-{i}") }),
            Some(true),
        )
        .await
        .unwrap();
    }
    assert_eq!(conn.links.len(), MAX_LINKS);
    let newcomer = json!({ "id": "sid-new", "name": "enrollee", "uid": "uid-new" });
    conn.maybe_adopt(&newcomer, false).await.unwrap();
    assert!(
        !conn.links.contains_key("sid-new"),
        "a link that never failed was evicted"
    );
    conn.links.get_mut("sid-3").unwrap().attempts = 2;
    conn.maybe_adopt(&newcomer, false).await.unwrap();
    assert!(conn.links.contains_key("sid-new"), "the new contact was starved");
    assert!(!conn.links.contains_key("sid-3"), "the retrying link was kept");
    assert_eq!(conn.links.len(), MAX_LINKS);
    // Evicting gives up on the sid as an exhausted ladder does: neither
    // digest adoption nor warm-hold restarts it at attempt 0.
    assert!(conn.suppressed_digest_adoptions.contains("sid-3"));
}

/// Room adoption chooses its target after spawning the build. Installing
/// that candidate must not erase the newer choice, or ChannelReady becomes
/// a responder-only event and no file is ever offered.
#[tokio::test(flavor = "current_thread")]
async fn room_target_selected_during_build_survives_installation() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-room-target";
    test_inline::set(false);
    let result = conn
        .maybe_adopt(
            &json!({ "id": pid, "name": "receiver", "uid": "cli-r-room-target" }),
            true,
        )
        .await;
    // Restore the convenience path even if the assertion below fails.
    test_inline::set(true);
    assert!(result.expect("room adoption"));
    assert!(conn.is_active(pid), "adoption never selected the room target");
    assert!(
        !conn.links.contains_key(pid),
        "the build was not asynchronous"
    );
    for _ in 0..100 {
        conn.pump_builds();
        if conn.links.contains_key(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        conn.links.contains_key(pid),
        "the room candidate was not installed"
    );
    assert!(
        conn.is_active(pid),
        "installing the room candidate erased its target slot"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn installing_a_room_responder_preserves_another_target() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-room-responder";
    conn.active = Some("selected-target".to_string());
    test_inline::set(false);
    let result = conn
        .maybe_adopt(
            &json!({ "id": pid, "name": "bystander", "uid": "cli-r-bystander" }),
            false,
        )
        .await;
    test_inline::set(true);
    assert!(!result.expect("room responder adoption"));
    for _ in 0..100 {
        conn.pump_builds();
        if conn.links.contains_key(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        conn.links.contains_key(pid),
        "the responder candidate was not installed"
    );
    assert!(
        conn.is_active("selected-target"),
        "a responder stole another target's slot"
    );
}

/// A failed build reports its cause, releases the slot and is retried with
/// a bounded backoff instead of looking like a successful spawn.
#[tokio::test]
async fn a_failed_build_is_retried_with_backoff() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-fail";
    let plan = conn
        .prepare_build(
            json!({ "id": pid, "name": "peer" }),
            None,
            std::panic::Location::caller(),
            Replace::NeverLive,
        )
        .expect("prepare")
        .expect("plan");
    let generation = plan.generation;
    conn.builds.insert(pid.to_string(), build_state(generation));
    conn.build_tx
        .send(BuildDone::Failed { plan, reason: "test cause".into() })
        .unwrap();
    conn.pump_builds();
    assert!(!conn.builds.contains_key(pid), "the failed build kept its slot");
    let (retry, due) = conn.build_deferred.get(pid).expect("retry intent");
    assert_eq!(retry.attempt, 1);
    assert!(*due > Instant::now(), "the retry is not delayed");
}

/// The retry ladder stops after three failed builds; a failed attempt is
/// never an unbounded loop.
#[tokio::test]
async fn failed_builds_exhaust_after_three_attempts() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-exhaust";
    let mut plan = conn
        .prepare_build(
            json!({ "id": pid, "name": "peer" }),
            None,
            std::panic::Location::caller(),
            Replace::NeverLive,
        )
        .expect("prepare")
        .expect("plan");
    for attempt in 0..3 {
        let generation = plan.generation;
        conn.builds.insert(pid.to_string(), build_state(generation));
        conn.build_tx
            .send(BuildDone::Failed {
                plan: plan.clone(),
                reason: "test cause".into(),
            })
            .unwrap();
        conn.pump_builds();
        if attempt < 2 {
            let (next, _due) = conn.build_deferred.remove(pid).expect("retry intent");
            assert_eq!(next.attempt, attempt + 1);
            plan = next;
        }
    }
    assert!(!conn.build_deferred.contains_key(pid), "a failed build retried forever");
    assert!(!conn.builds.contains_key(pid));
}

/// Relay escalation must carry the old link's pair binding into the build
/// before the replacement drop clears it.
#[tokio::test]
async fn relay_escalation_keeps_the_pair_binding() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-relay";
    let mut link = relay_link(pid, "peer", "peer", Rec::new("relay", &log));
    link.expected_secret = Some(("peer".into(), "secret".into()));
    conn.links.insert(pid.to_string(), link);
    conn.escalate_to_relay(pid).await;
    assert_eq!(
        conn.links.get(pid).and_then(|l| l.expected_secret.clone()),
        Some(("peer".to_string(), "secret".to_string())),
        "relay rebuild lost the target binding"
    );
}

/// Peer-left cancels a candidate that has no installed link, matching the
/// live forget/revoke sweep.
#[tokio::test]
async fn peer_left_cancels_a_build_only_peer() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-left";
    conn.builds.insert(pid.to_string(), build_state(4));
    conn.on_peer_left(&json!({ "id": pid }));
    assert!(!conn.builds.contains_key(pid));
}

/// A terminal failure must not tear down a newer successful direct link.
#[tokio::test]
async fn a_terminal_failure_keeps_a_newer_direct_link() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-fail-race";
    let mut plan = conn
        .prepare_build(
            json!({ "id": pid, "name": "peer" }),
            None,
            std::panic::Location::caller(),
            Replace::NeverLive,
        )
        .expect("prepare")
        .expect("plan");
    plan.attempt = 2;
    plan.prior_generation = Some(7);
    let generation = plan.generation;
    let direct: Arc<dyn Transport> = Rec::new("direct", &log);
    let mut link = direct_link(pid, "peer", "peer", direct.clone());
    link.generation = 99;
    link.transport = Some(direct.clone());
    conn.links.insert(pid.to_string(), link);
    conn.builds.insert(pid.to_string(), build_state(generation));
    conn.build_tx
        .send(BuildDone::Failed { plan, reason: "terminal".into() })
        .unwrap();
    conn.pump_builds();
    assert!(
        conn.links[pid]
            .transport
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(t, &direct)),
        "a failed old intent dropped the newer direct link"
    );
}

/// Shutdown is an invalidation for every held candidate, not just live links.
#[tokio::test]
async fn shutdown_cancels_every_pending_build() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.builds.insert("sid-a".into(), build_state(1));
    conn.builds.insert("sid-b".into(), build_state(2));
    conn.note_binding("sid-a", ("a".into(), "1".into()));
    conn.note_active("sid-b");
    conn.cancel_builds();
    assert!(conn.builds.is_empty());
    assert!(conn.pending_bindings.is_empty());
    assert!(conn.pending_active.is_empty());
}

/// A drop invalidates a candidate building for the same peer. This covers
/// forget/revoke/peer-left paths that call drop_link while a build is held.
#[tokio::test]
async fn dropping_a_link_cancels_a_pending_candidate() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-drop";
    conn.builds.insert(pid.to_string(), build_state(11));
    conn.note_binding(pid, ("peer".into(), "secret".into()));
    conn.drop_link(pid);
    assert!(!conn.builds.contains_key(pid), "a dropped peer kept its build");
    assert!(!conn.pending_bindings.contains_key(pid));
}

/// A newer direct link that landed while a WebRTC candidate was building
/// must survive the candidate's release. The candidate is closed, not
/// installed, and the build slot is released.
#[tokio::test]
async fn a_newer_direct_link_survives_a_released_candidate() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-race";
    let direct: Arc<dyn Transport> = Rec::new("direct", &log);
    let mut link = direct_link(pid, "peer", "peer", direct.clone());
    link.generation = 99;
    link.transport = Some(direct.clone());
    conn.links.insert(pid.to_string(), link);
    conn.builds.insert(pid.to_string(), build_state(42));
    let peer = net::Peer::connect(
        pid.to_string(),
        conn.my_uid.clone(),
        true,
        Vec::new(),
        false,
        conn.sio.clone(),
        conn.tx.clone(),
        42,
    )
    .await
    .expect("build a local candidate");
    conn.current_intent.insert(pid.to_string(), 42);
    let source = peer.source();
    conn.apply_built_peer(BuiltPeer {
        peer_id: pid.to_string(),
        generation: 42,
        source,
        peer,
        info: json!({ "id": pid, "name": "peer" }),
        name: "peer".to_string(),
        uid: None,
        carried_secret: None,
        active_on_apply: false,
        replace: Replace::StuckAttempt,
        caller: std::panic::Location::caller(),
        prior_generation: Some(7),
    });
    assert!(
        conn.links[pid]
            .transport
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(t, &direct)),
        "the newer direct link was replaced by the released candidate"
    );
    assert!(conn.builds.is_empty(), "the rejected candidate held its slot");
}

/// Cancelling a build releases the slot and the captured binding without
/// touching a serving link.
#[tokio::test]
async fn cancel_build_releases_the_slot_and_binding() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-cancel";
    conn.builds.insert(pid.to_string(), build_state(9));
    conn.note_binding(pid, ("peer".into(), "secret".into()));
    conn.note_active(pid);
    conn.cancel_build(pid);
    assert!(conn.builds.is_empty());
    assert!(!conn.pending_bindings.contains_key(pid));
    assert!(!conn.pending_active.contains(pid));
}

/// Forget A must not freeze B or an unrelated build-only peer C. The
/// departed device secret refuses any pid that presents it, and a fresh
/// authorized re-pair is a new intent above the retired generation.
#[tokio::test]
async fn forgetting_one_peer_leaves_unrelated_peers_building() {
    let host = Arc::new(TestHost {
        devices: vec![("a".into(), "secret-a2".into())],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let a: Arc<dyn Transport> = Rec::new("a", &log);
    let mut link = direct_link("sid-a", "a", "a", a);
    link.expected_secret = Some(("a".into(), "secret-a".into()));
    conn.links.insert("sid-a".into(), link);
    conn.builds.insert("sid-b".into(), build_state(5));
    conn.note_binding("sid-b", ("b".into(), "secret-b".into()));
    conn.builds.insert("sid-c".into(), build_state(6));
    conn.note_binding("sid-c", ("c".into(), "secret-c".into()));
    let mut dropped = HashSet::new();
    dropped.insert("secret-a".to_string());
    conn.invalidate_peers(&[("sid-a".into(), "a".into())], &dropped);
    assert!(conn.revoked_bindings.contains("secret-a"));
    assert!(!conn.revoked_bindings.contains("secret-b"));
    assert!(!conn.revoked_peers.contains_key("sid-b"));
    assert!(!conn.revoked_peers.contains_key("sid-c"));
    assert!(conn.builds.contains_key("sid-b"), "forget A cancelled B's build");
    assert!(conn.builds.contains_key("sid-c"), "forget A cancelled C's build");
    assert!(conn.intent_blocked("sid-a", Some(&("a".into(), "secret-a".into()))));
    assert!(
        !conn.intent_blocked("sid-a", Some(&("a".into(), "secret-a2".into()))),
        "a fresh authorized secret was refused"
    );
    assert!(
        conn.intent_blocked("sid-new", Some(&("a".into(), "secret-a".into()))),
        "a revoked binding was accepted on a new pid"
    );
}

/// A re-pair's fresh authorized binding supersedes an older deferred retry
/// for the same pid instead of letting the old generation race it.
#[tokio::test]
async fn a_re_pair_supersedes_an_older_deferred_retry() {
    let host = Arc::new(TestHost {
        devices: vec![("dev".into(), "new-secret".into())],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let pid = "sid-repair";
    let old = prepared_plan(&mut conn, pid, Some(("dev", "old-secret")));
    let old_generation = old.generation;
    conn.build_deferred.insert(pid.into(), (old.clone(), Instant::now()));
    let new = prepared_plan(&mut conn, pid, Some(("dev", "new-secret")));
    assert!(new.generation > old_generation);
    assert!(
        !conn.build_deferred.contains_key(pid),
        "an older deferred retry survived the re-pair"
    );
    assert!(matches!(conn.start_build(old), BuildStart::AlreadyBuilding));
    assert_eq!(conn.current_intent.get(pid), Some(&new.generation));
}

/// A failure queued before peer-left/drop/cancel must not requeue a retry.
#[tokio::test]
async fn a_failure_queued_before_drop_does_not_retry() {
    for left in [false, true] {
        let (mut conn, _far, _rx) = test_conn().await;
        let pid = "sid-fail-cancel";
        let plan = prepared_plan(&mut conn, pid, None);
        conn.builds.insert(pid.into(), build_state(plan.generation));
        conn.build_tx
            .send(BuildDone::Failed { plan, reason: "held".into() })
            .unwrap();
        if left {
            conn.on_peer_left(&json!({ "id": pid }));
        } else {
            conn.cancel_build(pid);
        }
        conn.pump_builds();
        assert!(conn.builds.is_empty(), "retired build was re-created");
        assert!(conn.build_deferred.is_empty(), "retired build was retried");
        assert!(conn.links.is_empty(), "retired build installed a link");
    }
}

/// An older Cancelled completion is terminal for its own generation only;
/// it must not remove a newer intent's build slot.
#[tokio::test]
async fn an_older_cancelled_completion_cannot_remove_a_newer_intent() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-older";
    let old = prepared_plan(&mut conn, pid, None);
    conn.builds.insert(pid.into(), build_state(old.generation));
    conn.build_tx
        .send(BuildDone::Cancelled { plan: old.clone() })
        .unwrap();
    conn.builds.insert(pid.into(), build_state(old.generation + 1));
    conn.current_intent.insert(pid.into(), old.generation + 1);
    conn.pump_builds();
    assert_eq!(
        conn.builds.get(pid).map(|state| state.generation),
        Some(old.generation + 1),
        "an older Cancelled removed a newer intent"
    );
}

/// The fleet rendezvous secret is shared by every sibling. Forgetting one
/// sibling retires its pid, never the shared binding.
#[tokio::test]
async fn revoking_a_fleet_sibling_does_not_revoke_the_shared_rendezvous() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let t: Arc<dyn Transport> = Rec::new("fleet", &log);
    let mut link = direct_link("sid-fleet", "sib", "sib", t);
    link.expected_secret = Some(("fleet".into(), "fleet-rv".into()));
    conn.links.insert("sid-fleet".into(), link);
    let mut dropped = HashSet::new();
    dropped.insert("device-secret".to_string());
    conn.invalidate_peers(&[("sid-fleet".into(), "sib".into())], &dropped);
    assert!(
        !conn.revoked_bindings.contains("fleet-rv"),
        "the shared fleet rendezvous secret was revoked"
    );
    assert!(!conn.intent_blocked(
        "sid-other",
        Some(&("sib".into(), "fleet-rv".into()))
    ));
}

/// Only the introduced secret is re-authorized by a vouch.
#[tokio::test]
async fn authorize_binding_clears_only_the_vouched_secret() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.revoked_bindings.insert("forgotten".into());
    conn.revoked_bindings.insert("vouched".into());
    conn.authorize_binding("vouched");
    assert!(!conn.revoked_bindings.contains("vouched"));
    assert!(conn.revoked_bindings.contains("forgotten"));
}

/// Signal staging follows the server-stamped `from`, never a payload `to`.
#[tokio::test]
async fn stage_signal_attributes_only_the_server_envelope_from() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-signal-attr";
    conn.builds.insert(pid.to_string(), build_state(3));
    assert!(conn.stage_signal(&json!({
        "from": pid,
        "data": { "to": "decoy", "type": "description" }
    })));
    assert!(!conn.stage_signal(&json!({
        "from": "someone-else",
        "data": { "to": pid, "type": "description" }
    })));
    assert_eq!(conn.builds[pid].signals.len(), 1);
}

/// P4: a transport-offer that arrived while the peer had neither a pending
/// nor a link (its candidate was still building) is buffered. Installing
/// the link must replay it once, under that pid, through the driver's
/// ordinary signal path; the old-link cleanup inside the install used to
/// discard it, so the offer was never answered.
#[tokio::test]
async fn a_buffered_offer_is_replayed_once_when_its_link_installs() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-buffered-offer";
    let other = "sid-other-offer";
    conn.buffer_offer(
        pid,
        (
            vec!["10.0.0.2:4433".to_string()],
            Some("203.0.113.7:5000".to_string()),
            None,
            2,
            Some("chan-fleet".to_string()),
        ),
    );
    conn.buffer_offer(other, (vec!["10.0.0.3:4433".to_string()], None, None, 1, None));
    for generation in [5u32, 6u32] {
        let peer = net::Peer::connect(
            pid.to_string(),
            conn.my_uid.clone(),
            true,
            Vec::new(),
            false,
            conn.sio.clone(),
            conn.tx.clone(),
            generation,
        )
        .await
        .expect("local candidate");
        let source = peer.source();
        conn.install_built(
            BuiltPeer {
                peer_id: pid.to_string(),
                generation,
                source,
                peer,
                info: json!({ "id": pid, "name": "peer" }),
                name: "peer".to_string(),
                uid: None,
                carried_secret: None,
                active_on_apply: false,
                replace: Replace::NeverLive,
                caller: std::panic::Location::caller(),
                prior_generation: None,
            },
            std::collections::VecDeque::new(),
            std::collections::VecDeque::new(),
            None,
            false,
        );
        assert!(conn.links.contains_key(pid), "the candidate was not installed");
        assert!(
            !conn.buffered_offers.contains_key(pid),
            "the replayed offer stayed buffered and could apply twice"
        );
        assert!(
            conn.buffered_offers.contains_key(other),
            "another peer's buffered offer was consumed by this install"
        );
        let mut replayed: Vec<Value> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let Ev::Signal(v) = ev {
                if v["data"]["type"].as_str() == Some("transport-offer") {
                    replayed.push(v);
                }
            }
        }
        if generation == 5 {
            assert_eq!(replayed.len(), 1, "the buffered offer was not replayed on install");
            let v = &replayed[0];
            assert_eq!(v["from"].as_str(), Some(pid), "the replay named another peer");
            assert_eq!(v["data"]["addrs"][0].as_str(), Some("10.0.0.2:4433"));
            assert_eq!(v["data"]["srflx"].as_str(), Some("203.0.113.7:5000"));
            assert!(v["data"]["server_public"].is_null());
            assert_eq!(v["data"]["proto"].as_u64(), Some(2));
            assert_eq!(v["data"]["ch"].as_str(), Some("chan-fleet"));
            assert!(v["data"]["probe"].is_null(), "a replay re-answered an upgrade probe");
        } else {
            assert!(replayed.is_empty(), "a second install replayed the offer again");
        }
    }
}

/// Install a locally built candidate for `pid` the way `apply_built_peer`
/// does, then return every transport-offer signal the install queued.
async fn install_candidate_offers(
    conn: &mut Conn,
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    pid: &str,
    generation: u32,
    replace: Replace,
    uid: Option<String>,
) -> Vec<Value> {
    let peer = net::Peer::connect(
        pid.to_string(),
        conn.my_uid.clone(),
        true,
        Vec::new(),
        false,
        conn.sio.clone(),
        conn.tx.clone(),
        generation,
    )
    .await
    .expect("local candidate");
    let source = peer.source();
    conn.install_built(
        BuiltPeer {
            peer_id: pid.to_string(),
            generation,
            source,
            peer,
            info: json!({ "id": pid, "name": "peer" }),
            name: "peer".to_string(),
            uid,
            carried_secret: None,
            active_on_apply: false,
            replace,
            caller: std::panic::Location::caller(),
            prior_generation: None,
        },
        std::collections::VecDeque::new(),
        std::collections::VecDeque::new(),
        None,
        false,
    );
    let mut offers: Vec<Value> = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let Ev::Signal(v) = ev {
            if v["data"]["type"].as_str() == Some("transport-offer") {
                offers.push(v);
            }
        }
    }
    offers
}

/// The offer the install-time replay exists for: it arrived while the
/// peer's FIRST candidate (generation 7) was building, with no link and
/// no pending. Installing that candidate replays it once, addressed to its
/// own pid only; another never-live peer's buffered offer is neither
/// consumed nor re-addressed (the `--to bob` shape).
#[tokio::test]
async fn a_first_link_install_replays_only_its_own_buffered_offer() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let bob = "sid-bob";
    let carol = "sid-carol";
    conn.current_intent.insert(bob.to_string(), 7);
    conn.current_intent.insert(carol.to_string(), 9);
    conn.buffer_offer(bob, (vec!["10.0.0.2:4433".to_string()], None, None, 2, None));
    conn.buffer_offer(carol, (vec!["10.0.0.3:4433".to_string()], None, None, 2, None));
    assert_eq!(conn.buffered_offers[bob].intent, Some(7));
    assert!(!conn.buffered_offers[bob].linked);

    let offers =
        install_candidate_offers(&mut conn, &mut rx, bob, 7, Replace::NeverLive, None).await;
    assert_eq!(offers.len(), 1, "the first-link install did not replay its offer");
    assert_eq!(offers[0]["from"].as_str(), Some(bob), "the replay named another peer");
    assert_eq!(offers[0]["data"]["addrs"][0].as_str(), Some("10.0.0.2:4433"));
    assert!(!conn.buffered_offers.contains_key(bob), "the replayed offer stayed buffered");
    assert_eq!(
        conn.buffered_offers.get(carol).map(|s| s.offer.0.clone()),
        Some(vec!["10.0.0.3:4433".to_string()]),
        "another peer's buffered offer was consumed or altered by this install"
    );
}

/// An install that supersedes an existing link (the retry ladder's stuck
/// rebuild) must not replay a buffered offer onto the new link: the offer
/// was staged for the old incarnation, and replaying it re-arms a direct
/// attempt against the link the install just put up (two dialers). The
/// offer is dropped with the old link, as `drop_link` always did.
#[tokio::test]
async fn an_install_that_supersedes_a_link_does_not_replay_a_buffered_offer() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-superseded";
    conn.current_intent.insert(pid.to_string(), 8);
    // Buffered before any link, so only the supersede itself can refuse it.
    conn.buffer_offer(pid, (vec!["10.0.0.2:4433".to_string()], None, None, 2, None));
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let t: Arc<dyn Transport> = Rec::new("old", &log);
    conn.links.insert(pid.to_string(), direct_link(pid, "peer", "peer", t));

    let offers =
        install_candidate_offers(&mut conn, &mut rx, pid, 8, Replace::StuckAttempt, None)
            .await;
    assert!(conn.links.contains_key(pid), "the replacement was not installed");
    assert_eq!(conn.links[pid].generation, 8, "the old link was kept");
    assert!(offers.is_empty(), "a supersede replayed a buffered offer onto the new link");
    assert!(
        !conn.buffered_offers.contains_key(pid),
        "the refused offer survived the supersede and could replay later"
    );
}

/// Same pid, same uid, reconnecting while its earlier link still exists:
/// an offer buffered under that link belongs to it (a re-emit of an offer
/// it already answered). Installing the reconnect's candidate must not
/// replay it, even on the NeverLive path.
#[tokio::test]
async fn a_same_uid_reconnect_does_not_replay_an_offer_buffered_under_the_old_link() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-same-uid";
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let t: Arc<dyn Transport> = Rec::new("old", &log);
    let mut old = direct_link(pid, "peer", "peer", t);
    old.uid = Some("uid-same".to_string());
    conn.links.insert(pid.to_string(), old);
    conn.current_intent.insert(pid.to_string(), 7);
    conn.buffer_offer(pid, (vec!["10.0.0.2:4433".to_string()], None, None, 2, None));
    assert!(conn.buffered_offers[pid].linked, "the offer was not tagged with its link");
    // The reconnect's candidate takes the next intent.
    conn.current_intent.insert(pid.to_string(), 9);

    let offers = install_candidate_offers(
        &mut conn,
        &mut rx,
        pid,
        9,
        Replace::NeverLive,
        Some("uid-same".to_string()),
    )
    .await;
    assert!(offers.is_empty(), "a same-uid reconnect replayed the old link's offer");
    assert!(!conn.buffered_offers.contains_key(pid));
}

/// An offer staged under an older build generation is stale for the
/// candidate that installs: a newer intent owns the peer. It is dropped,
/// never replayed, even though this is a first-link install.
#[tokio::test]
async fn a_stale_generation_buffered_offer_is_not_replayed() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-stale-gen";
    conn.current_intent.insert(pid.to_string(), 3);
    conn.buffer_offer(pid, (vec!["10.0.0.2:4433".to_string()], None, None, 2, None));
    // A re-pair superseded generation 3 before it installed.
    conn.current_intent.insert(pid.to_string(), 4);

    let offers =
        install_candidate_offers(&mut conn, &mut rx, pid, 4, Replace::NeverLive, None).await;
    assert!(conn.links.contains_key(pid), "the candidate was not installed");
    assert!(offers.is_empty(), "an offer from an older generation was replayed");
    assert!(!conn.buffered_offers.contains_key(pid));
}

/// P5: a build stages ONLY its own SDP traffic. A transport-hint,
/// transport-offer or PAKE frame from the same peer is handed straight
/// back to the caller's normal handler, so cancelling the build cannot
/// take it down with the staged SDP.
#[tokio::test]
async fn a_build_stages_only_sdp_and_cancel_keeps_other_frames() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-stage-sdp";
    conn.builds.insert(pid.to_string(), build_state(3));
    let non_sdp = [
        json!({ "from": pid, "data": { "type": "transport-hint", "direct": false } }),
        json!({ "from": pid, "data": { "type": "transport-offer", "v": 1, "addrs": [] } }),
        json!({ "from": pid, "data": { "type": "pake-msg", "msg": "x" } }),
        json!({ "from": pid, "data": { "type": "pake-confirm", "mac": "x" } }),
    ];
    for frame in &non_sdp {
        assert!(
            !conn.stage_signal(frame),
            "a non-SDP frame was parked for the build: {frame}"
        );
    }
    assert!(conn.stage_signal(&json!({
        "from": pid,
        "data": { "type": "description", "description": { "type": "offer", "sdp": "v=0" } }
    })));
    assert!(conn.stage_signal(&json!({
        "from": pid,
        "data": { "type": "candidate", "candidate": { "candidate": "candidate:1" } }
    })));
    assert_eq!(conn.builds[pid].signals.len(), 2, "only the SDP payloads are staged");
    assert!(
        conn.builds[pid]
            .signals
            .iter()
            .all(|v| matches!(v["data"]["type"].as_str(), Some("description") | Some("candidate"))),
        "a non-SDP frame reached the build's staging area"
    );
    // A deferred intent follows the same rule.
    let other = "sid-stage-deferred";
    let plan = conn
        .prepare_build(
            json!({ "id": other, "name": "peer" }),
            None,
            std::panic::Location::caller(),
            Replace::NeverLive,
        )
        .expect("prepare")
        .expect("plan");
    conn.build_deferred.insert(other.to_string(), (plan, Instant::now()));
    assert!(!conn.stage_signal(&json!({ "from": other, "data": { "type": "transport-offer" } })));
    assert!(conn.stage_signal(&json!({ "from": other, "data": { "type": "candidate" } })));
    assert_eq!(conn.build_deferred[other].0.signals.len(), 1);
    // Cancelling the build discards only the staged SDP; every non-SDP frame
    // was already returned to its handler and still is after the cancel.
    conn.cancel_build(pid);
    assert!(!conn.builds.contains_key(pid));
    for frame in &non_sdp {
        assert!(!conn.stage_signal(frame), "a frame was held after the cancel");
    }
}

/// A dropped/replaced link's queued candidate events are discarded, not
/// forwarded to whatever link reuses the pid.
#[tokio::test]
async fn a_replaced_link_cannot_forward_queued_events() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-forwarder";
    let t: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = relay_link(pid, "peer", "peer", t);
    link.generation = 7;
    conn.links.insert(pid.to_string(), link);
    let (tx, events_rx) = mpsc::unbounded_channel();
    conn.link_events
        .insert(pid.to_string(), LinkEvents { generation: 7, rx: std::sync::Mutex::new(events_rx), departure_ready: None, departure_pending: None });
    tx.send(Ev::Control(pid.to_string(), json!({ "type": "ping" })))
        .unwrap();
    conn.pump_builds();
    assert!(
        matches!(rx.try_recv(), Ok(Ev::Control(p, _)) if p == pid),
        "a live link's event was not forwarded"
    );
    tx.send(Ev::Control(pid.to_string(), json!({ "type": "stale" })))
        .unwrap();
    let retired_attempt = conn.links[pid].attempt;
    conn.drop_link(pid);
    conn.pump_builds();
    let forwarded: Vec<Ev> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        !forwarded
            .iter()
            .any(|ev| matches!(ev, Ev::Control(p, _) if p == pid)),
        "a stale old-link event was forwarded after replacement"
    );
    assert!(
        retired_attempt.is_none()
            || forwarded
                .iter()
                .any(|ev| matches!(ev, Ev::AttemptDrained(a) if Some(*a) == retired_attempt)),
        "the dropped link's drain barrier was not delivered"
    );
}

/// Retiring the old link's generation must not cancel a newer authorized
/// build for the same pid (a re-pair racing a forget).
#[tokio::test]
async fn a_forget_does_not_kill_a_newer_authorized_build() {
    let host = Arc::new(TestHost {
        devices: vec![("dev".into(), "new-secret".into())],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let pid = "sid-race-forget";
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let old: Arc<dyn Transport> = Rec::new("old", &log);
    let mut link = direct_link(pid, "dev", "dev", old);
    link.generation = 7;
    link.expected_secret = Some(("dev".into(), "old-secret".into()));
    conn.links.insert(pid.into(), link);
    conn.builds.insert(pid.into(), build_state(8));
    conn.note_binding(pid, ("dev".into(), "new-secret".into()));
    conn.current_intent.insert(pid.into(), 8);
    let mut dropped = HashSet::new();
    dropped.insert("old-secret".to_string());
    conn.invalidate_peers(&[(pid.into(), "dev".into())], &dropped);
    assert!(
        conn.builds.contains_key(pid),
        "a newer authorized build was cancelled by the old link's revocation"
    );
    assert!(!conn.intent_retired(pid, 8));
    assert!(conn.intent_retired(pid, 7));
}

/// Two devices may share a display name. A forgotten device selects only
/// its own build by device secret; the same-named peer is untouched.
#[tokio::test]
async fn a_duplicate_display_name_does_not_select_an_unrelated_build() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.builds.insert("sid-one".into(), build_state(5));
    conn.note_binding("sid-one", ("same-name".into(), "secret-one".into()));
    conn.builds.insert("sid-two".into(), build_state(6));
    conn.note_binding("sid-two", ("same-name".into(), "secret-two".into()));
    let mut dropped = HashSet::new();
    dropped.insert("secret-one".to_string());
    conn.invalidate_peers(&[], &dropped);
    assert!(
        !conn.builds.contains_key("sid-one"),
        "the forgotten device's build was not retired"
    );
    assert!(
        conn.builds.contains_key("sid-two"),
        "a same-named unrelated device was retired"
    );
}

/// A revoked armed attempt is retired at the exact attempt. Its tombstone
/// rejects a matching late DirectReady before mutation, and the reaper has
/// no pending left to turn into a WebRTC fallback.
#[tokio::test]
async fn a_revoked_armed_pending_cannot_be_resurrected_by_late_ready() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-revoke-late";
    let t: Arc<dyn Transport> = Rec::new("late", &log);
    let attempt = t.attempt_id().unwrap();
    let mut pending = direct_pending_with(attempt, ("dev", "old-secret"));
    pending.auth = DirectAuth::device(8, "dev", "old-secret");
    conn.direct_pending.insert(pid.into(), pending);
    let mut dropped = HashSet::new();
    dropped.insert("old-secret".to_string());
    conn.invalidate_peers(&[], &dropped);
    assert!(!conn.direct_pending.contains_key(pid), "revoked pending survived");
    assert!(
        conn.retired_attempts.contains_key(&attempt),
        "the exact attempt was not tombstoned for its drain barrier"
    );
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(!conn.links.contains_key(pid), "late ready resurrected a link");
    assert!(t.is_dead(), "the rejected incoming transport was not closed");
    assert!(conn.expired_direct().is_empty(), "a revoked pending fell back");
}

/// Invalidation cleans only the promotion, probe, and source entries that
/// carry the affected immutable attempt; unrelated newer metadata survives.
#[tokio::test]
async fn revocation_cleans_only_matching_promotion_probe_and_sources() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let promo_pid = "sid-revoke-promo";
    let promo_attempt = net::AttemptId::next();
    let promo_standby: Arc<dyn Transport> = Rec::new("promo-standby", &log);
    let mut pending = direct_pending_with(promo_attempt, ("dev", "old-secret"));
    pending.ephemeral = true;
    pending.auth = DirectAuth::ephemeral(8);
    conn.direct_pending.insert(promo_pid.into(), pending);
    let mut promotion = PromoteState::new(PromoteRole::Lead);
    promotion.attempt = Some(promo_attempt);
    promotion.auth = Some(DirectAuth::ephemeral(8));
    promotion.standby = Some((promo_standby.clone(), "direct-quic"));
    conn.promotions.insert(promo_pid.into(), promotion);
    conn.pending_sources.insert(
        net::SourceId::next(),
        PendingSource {
            pid: promo_pid.into(),
            attempt: Some(promo_attempt),
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );

    let probe_pid = "sid-revoke-probe";
    let probe_attempt = net::AttemptId::next();
    let probe_standby: Arc<dyn Transport> = Rec::new("probe-standby", &log);
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(probe_attempt);
    probe.auth = Some(DirectAuth::device(8, "dev", "old-secret"));
    probe.standby = Some(probe_standby.clone());
    probe.verify_started = Some(Instant::now());
    conn.resil.upgrade_probe.insert(probe_pid.into(), probe);
    conn.pending_sources.insert(
        net::SourceId::next(),
        PendingSource {
            pid: probe_pid.into(),
            attempt: Some(probe_attempt),
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );

    let keep_pid = "sid-keep-direct";
    let keep_attempt = net::AttemptId::next();
    let mut keep = direct_pending_with(keep_attempt, ("dev", "current-secret"));
    keep.auth = DirectAuth::device(9, "dev", "current-secret");
    conn.direct_pending.insert(keep_pid.into(), keep);
    let mut keep_probe = UpgradeProbe::armed();
    keep_probe.token = Some(net::AttemptId::next());
    keep_probe.auth = Some(DirectAuth::device(9, "dev", "current-secret"));
    conn.resil.upgrade_probe.insert(keep_pid.into(), keep_probe);
    let keep_source = net::SourceId::next();
    conn.pending_sources.insert(
        keep_source,
        PendingSource {
            pid: keep_pid.into(),
            attempt: Some(keep_attempt),
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );

    let mut dropped = HashSet::new();
    dropped.insert("old-secret".to_string());
    conn.invalidate_peers(
        &[(promo_pid.into(), "dev".into()), (probe_pid.into(), "dev".into())],
        &dropped,
    );
    assert!(!conn.promotions.contains_key(promo_pid));
    assert!(!conn.resil.upgrade_probe.contains_key(probe_pid));
    assert!(promo_standby.is_dead() && probe_standby.is_dead());
    assert!(conn
        .pending_sources
        .values()
        .all(|pending| pending.pid != promo_pid && pending.pid != probe_pid));
    assert!(conn.direct_pending.contains_key(keep_pid));
    assert!(conn.resil.upgrade_probe.contains_key(keep_pid));
    assert!(conn.pending_sources.contains_key(&keep_source));
}

/// A newer same-pid device attempt whose binding the current store holds
/// survives the old link's forget and adopts without the revoked secret.
/// The old primary is replaced whole (Arc, attempt, source, workers), never
/// a hybrid epoch that keeps the old transport or worker authority.
#[tokio::test]
async fn a_newer_current_store_device_attempt_survives_old_link_forget() {
    let host = Arc::new(TestHost {
        devices: vec![("dev".into(), "new-secret".into())],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let pid = "sid-new-device-successor";
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let old: Arc<dyn Transport> = Rec::new("old", &log);
    let old_attempt = old.attempt_id().unwrap();
    let old_source = old.source_id().unwrap();
    let old_worker: Arc<dyn Transport> = Rec::new("old-worker", &log);
    let old_worker_source = old_worker.source_id().unwrap();
    let mut link = direct_link(pid, "dev", "dev", old.clone());
    link.generation = 7;
    link.expected_secret = Some(("dev".into(), "old-secret".into()));
    link.workers = vec![old_worker.clone()];
    link.worker_sources.insert(old_worker_source);
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    let successor: Arc<dyn Transport> = Rec::new("successor", &log);
    let successor_attempt = successor.attempt_id().unwrap();
    let successor_source = successor.source_id().unwrap();
    let mut pending = direct_pending_with(successor_attempt, ("dev", "new-secret"));
    pending.auth = DirectAuth::device(8, "dev", "new-secret");
    conn.direct_pending.insert(pid.into(), pending);
    let unrelated_pid = "sid-unrelated-pending";
    conn.direct_pending.insert(
        unrelated_pid.into(),
        direct_pending_with(net::AttemptId::next(), ("dev", "unrelated-secret")),
    );
    let mut dropped = HashSet::new();
    dropped.insert("old-secret".to_string());
    conn.invalidate_peers(&[(pid.into(), "dev".into())], &dropped);
    assert!(conn.direct_pending.contains_key(pid), "the new store binding was swept");
    assert_eq!(conn.links[pid].attempt, Some(old_attempt));
    assert_eq!(conn.links[pid].source, old_source);
    assert!(!conn.retired_attempts.contains_key(&successor_attempt));
    assert!(matches!(
        conn.adopt_direct(pid, successor.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt, .. } if attempt == successor_attempt
    ));
    let installed = conn.links[pid].transport.as_ref().unwrap();
    assert!(Arc::ptr_eq(installed, &successor), "the successor epoch kept the OLD Arc (hybrid)");
    assert!(!Arc::ptr_eq(installed, &old));
    assert_eq!(conn.links[pid].attempt, Some(successor_attempt));
    assert_eq!(conn.links[pid].source, successor_source);
    assert_ne!(conn.links[pid].source, old_source);
    assert!(!conn.links[pid].worker_sources.contains(&old_worker_source));
    assert!(conn.is_active(pid), "active was lost while replacing the primary");
    assert!(conn.retired_attempts.contains_key(&old_attempt));
    assert!(
        !conn.retired_attempts.contains_key(&successor_attempt),
        "the old link's drop retired the newer attempt"
    );
    assert!(!conn.direct_pending.contains_key(pid));
    assert!(conn.direct_pending.contains_key(unrelated_pid));
    assert!(
        conn.stage_event(Ev::Sourced {
            pid: pid.into(),
            source: old_worker_source,
            inner: Box::new(Ev::Control(
                pid.into(),
                json!({ "type": "old-worker-control" }),
            )),
        })
        .is_none(),
        "a dropped primary's worker source still forwarded Control"
    );
    assert_eq!(
        conn.links[pid].expected_secret,
        Some(("dev".to_string(), "new-secret".to_string())),
        "the revoked secret was restored instead of the current binding"
    );
}

/// The fleet rendezvous secret is shared. Forgetting sibling A retires only
/// A's exact attempt; B and the shared secret remain untouched.
#[tokio::test]
async fn fleet_sibling_attempts_are_isolated_by_pid() {
    let (mut conn, _far, _rx) = test_conn().await;
    let a_pid = "sid-fleet-a";
    let b_pid = "sid-fleet-b";
    let a_attempt = net::AttemptId::next();
    let b_attempt = net::AttemptId::next();
    let mut a = direct_pending_with(a_attempt, ("fleet", "fleet-rv"));
    a.fleet = true;
    a.auth = DirectAuth::fleet(8);
    let mut b = direct_pending_with(b_attempt, ("fleet", "fleet-rv"));
    b.fleet = true;
    b.auth = DirectAuth::fleet(9);
    conn.direct_pending.insert(a_pid.into(), a);
    conn.direct_pending.insert(b_pid.into(), b);
    let mut dropped = HashSet::new();
    dropped.insert("device-secret".to_string());
    conn.invalidate_peers(&[(a_pid.into(), "sib-a".into())], &dropped);
    assert!(!conn.direct_pending.contains_key(a_pid));
    assert!(conn.direct_pending.contains_key(b_pid), "sibling B was revoked");
    assert!(!conn.revoked_bindings.contains("fleet-rv"));
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let b_transport: Arc<dyn Transport> = Rec::new("fleet-b", &log);
    if let Some(pending) = conn.direct_pending.get_mut(b_pid) {
        pending.attempt = b_transport.attempt_id().unwrap();
    }
    assert!(matches!(
        conn.adopt_direct(b_pid, b_transport, "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
}

/// A revoked binding is refused by the final adoption gate before any link
/// mutation; the serving Arc, generation, active slot, and pending survive.
#[tokio::test]
async fn revoked_binding_is_rejected_before_adoption_mutation() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-adopt-revoked";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = direct_link(pid, "dev", "dev", serving.clone());
    link.generation = 7;
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let attempt = incoming.attempt_id().unwrap();
    let mut pending = direct_pending_with(attempt, ("dev", "revoked-secret"));
    pending.auth = DirectAuth::device(8, "dev", "revoked-secret");
    conn.direct_pending.insert(pid.into(), pending);
    conn.revoked_bindings.insert("revoked-secret".into());
    assert!(matches!(
        conn.adopt_direct(pid, incoming.clone(), "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(incoming.is_dead());
    let link = &conn.links[pid];
    assert!(Arc::ptr_eq(link.transport.as_ref().unwrap(), &serving));
    assert_eq!(link.generation, 7);
    assert!(conn.is_active(pid));
    assert!(conn.direct_pending.contains_key(pid));
}

/// A revoked or retired upgrade standby is refused before relay commitment,
/// active state, serving link, probe, or pending can be mutated.
#[tokio::test]
async fn revoked_or_retired_upgrade_is_rejected_pre_mutation() {
    for retired in [false, true] {
        let (mut conn, _far, _rx) = test_conn().await;
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pid = if retired { "sid-upgrade-retired" } else { "sid-upgrade-revoked" };
        let serving: Arc<dyn Transport> = Rec::new("serving", &log);
        let mut link = direct_link(pid, "dev", "dev", serving.clone());
        link.generation = 7;
        link.expected_secret = Some(("dev".into(), "old-secret".into()));
        conn.links.insert(pid.into(), link);
        conn.active = Some(pid.into());
        conn.resil.relay_committed.insert(pid.into());
        let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
        let attempt = incoming.attempt_id().unwrap();
        let mut pending = direct_pending_with(attempt, ("dev", "old-secret"));
        pending.auth = DirectAuth::device(8, "dev", "old-secret");
        conn.direct_pending.insert(pid.into(), pending);
        let mut probe = UpgradeProbe::armed();
        probe.token = Some(attempt);
        probe.auth = Some(DirectAuth::device(8, "dev", "old-secret"));
        conn.resil.upgrade_probe.insert(pid.into(), probe);
        if retired {
            conn.retired_attempts.insert(
                attempt,
                RetiredAttempt::new(pid),
            );
        } else {
            conn.revoked_bindings.insert("old-secret".into());
        }
        conn.perform_upgrade(pid, incoming.clone(), "direct-quic").await;
        assert!(incoming.is_dead());
        let link = &conn.links[pid];
        assert!(Arc::ptr_eq(link.transport.as_ref().unwrap(), &serving));
        assert_eq!(link.generation, 7);
        assert!(conn.is_active(pid));
        assert!(conn.resil.relay_committed.contains(pid));
        assert!(conn.resil.upgrade_probe.contains_key(pid));
        assert!(conn.direct_pending.contains_key(pid));
    }
}

/// A same-attempt different-Arc upgrade ready is rejected before the
/// serving link or probe state is touched.
#[tokio::test]
async fn upgrade_same_attempt_different_arc_rejected_pre_mutation() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-different-arc";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let attempt = serving.attempt_id().unwrap();
    let mut link = direct_link(pid, "peer", "peer", serving.clone());
    link.generation = 7;
    link.attempt = Some(attempt);
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    conn.resil.relay_committed.insert(pid.into());
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(attempt);
    probe.auth = Some(DirectAuth::device(1, "peer", "secret"));
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let incoming: Arc<dyn Transport> = Rec::with_attempt("incoming", &log, attempt);
    conn.perform_upgrade(pid, incoming.clone(), "direct-quic").await;
    assert!(incoming.is_dead());
    assert!(Arc::ptr_eq(conn.links[pid].transport.as_ref().unwrap(), &serving));
    assert_eq!(conn.links[pid].generation, 7);
    assert!(conn.is_active(pid));
    assert!(conn.resil.relay_committed.contains(pid));
    assert!(conn.resil.upgrade_probe.contains_key(pid));
}

/// An authorized normal ready adopts the exact pending attempt.
#[tokio::test]
async fn authorized_normal_adopt_succeeds() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-normal-authorized";
    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    let attempt = t.attempt_id().unwrap();
    conn.direct_pending
        .insert(pid.into(), direct_pending_with(attempt, ("peer", "secret")));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt: seen, .. } if seen == attempt
    ));
    assert!(conn.links.contains_key(pid));
    assert!(Arc::ptr_eq(conn.links[pid].transport.as_ref().unwrap(), &t));
}

/// A real WebRTC offer envelope from `pid`, tagged with peer connection `pc`.
async fn offer_from(conn: &Conn, pid: &str, pc: u32) -> Value {
    let (otx, _orx) = mpsc::unbounded_channel();
    let offerer = net::Peer::connect(
        "sid-acceptor".to_string(),
        "cli-l2-far".to_string(),
        false,
        Vec::new(),
        false,
        conn.sio.clone(),
        otx,
        pc,
    )
    .await
    .expect("local offerer");
    let ld = offerer.raw_pc().local_description().await.expect("offer");
    json!({
        "from": pid,
        "data": { "type": "description", "uid": "cli-l2-far", "pc": pc, "description": ld }
    })
}

/// Cause 1 of the cold-connect failure: the initiator's offer arrived
/// while our direct attempt for its sid was pending. It used to be dropped
/// (no build may start during a pending) and, sent once per connection,
/// was never answered. It is held, and the fallback responder answers it.
#[tokio::test]
async fn an_offer_during_a_pending_direct_attempt_is_held_then_answered() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-cold-cli";
    expired_direct_pending(&mut conn, pid, Instant::now() + Duration::from_secs(30));
    let offer = offer_from(&conn, pid, 1).await;
    let cand = json!({
        "from": pid,
        "data": { "type": "candidate", "pc": 1, "candidate": { "candidate": "candidate:1 1 udp 1 10.0.0.9 9 typ host" } }
    });
    assert!(conn.hold_for_direct(&offer), "the offer was not held");
    assert!(conn.hold_for_direct(&cand), "its candidate was not held");
    assert_eq!(conn.held_signals[pid].signals.len(), 2);
    // A signal for a sid with no pending is not ours to hold.
    assert!(!conn.hold_for_direct(&json!({ "from": "sid-other", "data": offer["data"].clone() })));

    // The direct path loses: the reaper falls back and establishes.
    conn.direct_pending.get_mut(pid).unwrap().deadline = Instant::now();
    let fell = conn.expired_direct();
    assert_eq!(fell.len(), 1);
    conn.establish_as(json!({ "id": pid, "uid": "cli-l2-far", "name": "far" }), None)
        .await
        .expect("fallback establish");
    assert!(conn.held_signals.is_empty(), "the hold outlived its replay");
    let peer = conn.links[pid].peer.clone().expect("responder link");
    assert!(peer.polite, "a held offer must make the fallback its responder");

    // The replayed signals reach the loop in order; applying them answers.
    let mut replayed = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let Ev::Signal(v) = ev {
            replayed.push(v);
        }
    }
    assert_eq!(replayed.len(), 2, "held offer and candidate are replayed once");
    assert_eq!(replayed[0]["data"]["description"]["type"], "offer");
    for v in replayed {
        conn.apply_signal(pid, v["data"].clone()).await;
    }
    let local = peer.raw_pc().local_description().await.expect("answer");
    assert_eq!(local.sdp_type.to_string(), "answer");
    assert_eq!(peer.remote_pc().await, Some(1));
}

/// A held offer is discarded when the direct path wins and adopts, so a
/// later rebuild can never answer a connection the peer has abandoned. A
/// newer offer from the same sid replaces an older held one.
#[tokio::test]
async fn a_held_offer_is_discarded_when_direct_adopts() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-held-direct-wins";
    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    let attempt = t.attempt_id().unwrap();
    conn.direct_pending
        .insert(pid.into(), direct_pending_with(attempt, ("peer", "secret")));
    let first = json!({
        "from": pid,
        "data": { "type": "description", "pc": 1, "description": { "type": "offer", "sdp": "v=0" } }
    });
    let second = json!({
        "from": pid,
        "data": { "type": "description", "pc": 2, "description": { "type": "offer", "sdp": "v=0" } }
    });
    assert!(conn.hold_for_direct(&first));
    assert!(conn.hold_for_direct(&second));
    assert_eq!(conn.held_signals[pid].pc, Some(2), "a newer connection replaces the hold");
    assert_eq!(conn.held_signals[pid].signals.len(), 1);
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt: seen, .. } if seen == attempt
    ));
    assert!(!conn.held_signals.contains_key(pid), "direct adopted but the offer stayed held");
}

/// Cause 3: an offer from a NEW peer connection on the same sid (the
/// initiator rotated) rebuilds the responder instead of renegotiating the
/// one that answered the old connection.
#[tokio::test]
async fn an_offer_from_a_new_peer_connection_gets_a_fresh_responder() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-rotated-cli";
    let first = offer_from(&conn, pid, 1).await;
    conn.ensure_responder(pid, &first["data"]).await.expect("responder");
    conn.apply_signal(pid, first["data"].clone()).await;
    let old = conn.links[pid].peer.clone().expect("first responder");
    assert_eq!(old.remote_pc().await, Some(1));

    let second = offer_from(&conn, pid, 2).await;
    conn.apply_signal(pid, second["data"].clone()).await;
    let new = conn.links[pid].peer.clone().expect("fresh responder");
    assert!(!Arc::ptr_eq(&old, &new), "the old responder was renegotiated");
    assert_eq!(new.remote_pc().await, Some(2));
    let local = new.raw_pc().local_description().await.expect("answer");
    assert_eq!(local.sdp_type.to_string(), "answer");
}

/// The DoS guard: a link that is SERVING bytes is never torn down for an
/// offer that merely claims a new peer connection; it keeps the old
/// renegotiation path and its transport.
#[tokio::test]
async fn a_serving_link_never_gets_a_fresh_responder() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-serving";
    let first = offer_from(&conn, pid, 1).await;
    conn.ensure_responder(pid, &first["data"]).await.expect("responder");
    conn.apply_signal(pid, first["data"].clone()).await;
    let old = conn.links[pid].peer.clone().expect("responder");
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    conn.links.get_mut(pid).unwrap().transport = Some(serving.clone());

    let second = offer_from(&conn, pid, 2).await;
    conn.apply_signal(pid, second["data"].clone()).await;
    let link = &conn.links[pid];
    assert!(
        Arc::ptr_eq(link.peer.as_ref().expect("peer kept"), &old),
        "a serving link was rebuilt for a new-pc offer"
    );
    assert!(
        link.transport.as_ref().is_some_and(|t| Arc::ptr_eq(t, &serving)),
        "the serving transport was replaced"
    );
    assert!(!serving.is_dead(), "the serving transport was closed");
}

/// An untagged sender (a browser, an older build) keeps the renegotiation
/// path: its second offer is applied to the same responder.
#[tokio::test]
async fn an_untagged_peer_keeps_the_renegotiation_path() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-untagged";
    let untag = |mut v: Value| {
        if let Some(d) = v["data"].as_object_mut() {
            d.remove("pc");
        }
        v
    };
    let first = untag(offer_from(&conn, pid, 1).await);
    conn.ensure_responder(pid, &first["data"]).await.expect("responder");
    conn.apply_signal(pid, first["data"].clone()).await;
    let old = conn.links[pid].peer.clone().expect("responder");
    assert_eq!(old.remote_pc().await, None);
    let second = untag(offer_from(&conn, pid, 2).await);
    conn.apply_signal(pid, second["data"].clone()).await;
    let now = conn.links[pid].peer.clone().expect("responder");
    assert!(Arc::ptr_eq(&old, &now), "an untagged offer rebuilt the responder");
}

/// The driver loops' shared SDP tail (`deliver_sdp_signal`, called by
/// recv dispatch, send engine and join after `ensure_responder`): during a
/// pending direct attempt the offer is held, not applied or dropped; with
/// no pending it is applied to the responder.
#[tokio::test]
async fn the_driver_sdp_tail_holds_during_a_pending_direct_attempt() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-driver-tail";
    expired_direct_pending(&mut conn, pid, Instant::now() + Duration::from_secs(30));
    let offer = offer_from(&conn, pid, 1).await;
    conn.ensure_responder(pid, &offer["data"]).await.expect("no error during a pending");
    assert!(!conn.links.contains_key(pid), "a responder was built during the pending");
    conn.deliver_sdp_signal(&offer).await;
    assert!(conn.held_signals.get(pid).is_some_and(|h| h.has_offer), "the offer was not held");

    let other = "sid-driver-tail-nopending";
    let offer2 = offer_from(&conn, other, 1).await;
    conn.ensure_responder(other, &offer2["data"]).await.expect("responder");
    conn.deliver_sdp_signal(&offer2).await;
    assert!(!conn.held_signals.contains_key(other), "held with no pending");
    let p = conn.links[other].peer.clone().expect("responder");
    assert!(p.raw_pc().local_description().await.is_some(), "the offer was not applied");
}

/// The upgrade adoption site discards a hold too.
#[tokio::test]
async fn upgrade_adoption_discards_a_held_offer() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-held";
    conn.held_signals.insert(
        pid.to_string(),
        HeldSignals {
            since: Instant::now(),
            pc: Some(1),
            has_offer: true,
            signals: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );
    let t: Arc<dyn Transport> = Rec::new("upgrade", &log);
    let attempt = t.attempt_id().unwrap();
    let adopted = conn.adopt_direct_transport(
        pid,
        t,
        "direct-quic",
        attempt,
        Some(("peer".into(), "secret".into())),
        None,
        Some(DirectAuth::device(1, "peer", "secret")),
    );
    assert!(matches!(adopted, DirectAdoption::Adopted { .. }));
    assert!(!conn.held_signals.contains_key(pid), "upgrade adopted but the offer stayed held");
}

/// A hold whose direct attempt ended with nothing built to take it is
/// purged by the next reaper call; one still pending is kept.
#[tokio::test]
async fn an_orphan_hold_is_purged_by_the_reaper() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-orphan";
    let live = "sid-still-pending";
    expired_direct_pending(&mut conn, live, Instant::now() + Duration::from_secs(30));
    for p in [pid, live] {
        conn.held_signals.insert(
            p.to_string(),
            HeldSignals {
                since: Instant::now(),
                pc: None,
                has_offer: true,
                signals: std::collections::VecDeque::new(),
                bytes: 0,
            },
        );
    }
    let _ = conn.expired_direct();
    assert!(!conn.held_signals.contains_key(pid), "an orphan hold survived the reaper");
    assert!(conn.held_signals.contains_key(live), "a pending's hold was purged");
}

/// Cold adoption keys workers from the immutable AUTHORIZATION, exactly
/// like upgrade adoption. A fleet rendezvous secret or an ephemeral
/// ceremony secret must never become a worker key; a device binding does.
#[tokio::test]
async fn cold_adoption_keys_only_device_bindings() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));

    let fleet_pid = "sid-cold-fleet";
    let fleet: Arc<dyn Transport> = Rec::new("fleet-cold", &log);
    let fleet_attempt = fleet.attempt_id().unwrap();
    let mut fleet_pending = direct_pending_with(fleet_attempt, ("fleet", "fleet-rv"));
    fleet_pending.fleet = true;
    fleet_pending.auth = DirectAuth::fleet(1);
    conn.direct_pending.insert(fleet_pid.into(), fleet_pending);
    assert!(matches!(
        conn.adopt_direct(fleet_pid, fleet, "direct-quic"),
        DirectAdoption::Adopted { tkey: None, .. }
    ));

    let ephemeral_pid = "sid-cold-ephemeral";
    let ephemeral: Arc<dyn Transport> = Rec::new("ephemeral-cold", &log);
    let ephemeral_attempt = ephemeral.attempt_id().unwrap();
    let mut ephemeral_pending =
        direct_pending_with(ephemeral_attempt, ("ceremony", "one-time-code"));
    ephemeral_pending.ephemeral = true;
    ephemeral_pending.auth = DirectAuth::ephemeral(2);
    conn.direct_pending.insert(ephemeral_pid.into(), ephemeral_pending);
    assert!(matches!(
        conn.adopt_direct(ephemeral_pid, ephemeral, "direct-quic"),
        DirectAdoption::Adopted { tkey: None, .. }
    ));

    let device_pid = "sid-cold-device";
    let device: Arc<dyn Transport> = Rec::new("device-cold", &log);
    let device_attempt = device.attempt_id().unwrap();
    conn.direct_pending.insert(
        device_pid.into(),
        direct_pending_with(device_attempt, ("dev", "device-secret")),
    );
    assert!(matches!(
        conn.adopt_direct(device_pid, device, "direct-quic"),
        DirectAdoption::Adopted { tkey: Some(key), .. }
            if key == direct::transport_key("device-secret")
    ));
}

/// A fleet one-shot's direct connection usually replaces the unverified
/// WebRTC link already held for the same signaling id. Adoption must not
/// turn that into a pair-trusted link: `trusted` is what makes
/// `is_sibling_link()` false, and then the target ignores the owner grant
/// for the device its certificate just named (observed as "shell not
/// granted to 'bravo' here" on an otherwise verified direct link).
#[tokio::test]
async fn fleet_direct_adoption_over_webrtc_does_not_gain_pair_trust() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-fleet-oneshot-adopt";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));

    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    let attempt = t.attempt_id().unwrap();
    let mut pending = direct_pending_with(attempt, (FLEET_LINK_NAME, "fleet-rv"));
    pending.fleet = true;
    pending.auth = DirectAuth::fleet(1);
    conn.direct_pending.insert(pid.into(), pending);

    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt: seen, .. } if seen == attempt
    ));
    let link = &conn.links[pid];
    assert!(
        Arc::ptr_eq(link.transport.as_ref().unwrap(), &t),
        "adopted fleet direct transport was discarded for its live WebRTC predecessor"
    );
    assert!(link.direct, "the fleet transport was not installed");
    assert!(
        !link.trusted,
        "fleet direct adoption inherited pair trust from the unverified WebRTC link"
    );
    assert!(
        link.verified_name.is_none(),
        "fleet direct adoption minted a petname before fleet-hello"
    );
}

/// An authorized upgrade adopts the verified standby exactly once.
#[tokio::test]
async fn authorized_perform_upgrade_succeeds() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-authorized";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = direct_link(pid, "peer", "peer", serving);
    link.generation = 7;
    link.expected_secret = Some(("peer".into(), "secret".into()));
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    conn.resil.relay_committed.insert(pid.into());
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let attempt = incoming.attempt_id().unwrap();
    conn.direct_pending
        .insert(pid.into(), direct_pending_with(attempt, ("peer", "secret")));
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(attempt);
    probe.auth = Some(DirectAuth::device(1, "peer", "secret"));
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    conn.perform_upgrade(pid, incoming.clone(), "direct-quic").await;
    assert!(!incoming.is_dead());
    assert!(conn.links[pid].direct);
    assert!(Arc::ptr_eq(conn.links[pid].transport.as_ref().unwrap(), &incoming));
    assert!(!conn.resil.relay_committed.contains(pid));
    assert!(!conn.resil.upgrade_probe.contains_key(pid));
    assert!(!conn.direct_pending.contains_key(pid));
    assert!(conn.is_active(pid));
}

/// Upgrade adoption returns the worker key from stored DEVICE authorization,
/// and a non-device/no-key adoption remains safe. Fresh workers are accepted
/// only under the new primary source.
#[tokio::test]
async fn upgrade_adoption_returns_stored_key_and_no_key_is_safe() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-key";
    let t: Arc<dyn Transport> = Rec::new("upgrade", &log);
    let attempt = t.attempt_id().unwrap();
    let expected_key = direct::transport_key("secret");
    let adopted = conn.adopt_direct_transport(
        pid,
        t,
        "direct-quic",
        attempt,
        Some(("peer".into(), "secret".into())),
        None,
        Some(DirectAuth::device(1, "peer", "secret")),
    );
    assert!(matches!(
        adopted,
        DirectAdoption::Adopted { attempt: seen, tkey: Some(key) }
            if seen == attempt && key == expected_key
    ));
    let source = conn.links[pid].source;
    let fresh_worker: Arc<dyn Transport> = Rec::new("upgrade-worker", &log);
    let fresh_source = fresh_worker.source_id().unwrap();
    assert!(conn.accept_workers_ready(pid, vec![fresh_worker], source));
    assert!(conn.links[pid].worker_sources.contains(&fresh_source));
    assert!(matches!(
        conn.stage_event(Ev::Sourced {
            pid: pid.into(),
            source: fresh_source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "fresh" }))),
        }),
        Some((Ev::Control(..), Some(source))) if source == fresh_source
    ));

    let no_key_pid = "sid-upgrade-no-key";
    let no_key: Arc<dyn Transport> = Rec::new("no-key", &log);
    let no_key_attempt = no_key.attempt_id().unwrap();
    assert!(matches!(
        conn.adopt_direct_transport(
            no_key_pid,
            no_key,
            "direct-quic",
            no_key_attempt,
            None,
            None,
            Some(DirectAuth::ephemeral(2)),
        ),
        DirectAdoption::Adopted { tkey: None, .. }
    ));
    assert!(conn.links.contains_key(no_key_pid));
}

/// A queued ready for the revoked old attempt cannot consume the newer
/// same-pid pending; that pending can still adopt its own exact attempt.
#[tokio::test]
async fn old_revoked_ready_cannot_consume_new_same_pid_pending() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-old-ready-new-pending";
    let old: Arc<dyn Transport> = Rec::new("old", &log);
    let old_attempt = old.attempt_id().unwrap();
    let mut old_pending = direct_pending_with(old_attempt, ("dev", "old-secret"));
    old_pending.auth = DirectAuth::device(1, "dev", "old-secret");
    conn.direct_pending.insert(pid.into(), old_pending);
    let mut dropped = HashSet::new();
    dropped.insert("old-secret".into());
    conn.invalidate_peers(&[], &dropped);
    let new: Arc<dyn Transport> = Rec::new("new", &log);
    let new_attempt = new.attempt_id().unwrap();
    let mut new_pending = direct_pending_with(new_attempt, ("dev", "new-secret"));
    new_pending.auth = DirectAuth::device(8, "dev", "new-secret");
    conn.direct_pending.insert(pid.into(), new_pending);
    assert!(matches!(
        conn.adopt_direct(pid, old, "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(conn.direct_pending.contains_key(pid));
    assert!(matches!(
        conn.adopt_direct(pid, new, "direct-quic"),
        DirectAdoption::Adopted { attempt, .. } if attempt == new_attempt
    ));
}

/// Newer same-pid probe and promotion attempts survive retirement of an
/// older pending, including their source registration.
#[tokio::test]
async fn newer_same_pid_probe_and_promotion_survive_old_retirement() {
    let host = Arc::new(TestHost {
        devices: vec![("dev".into(), "new-secret".into())],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-newer-same-pid";
    let old: Arc<dyn Transport> = Rec::new("old", &log);
    let mut link = direct_link(pid, "dev", "dev", old);
    link.generation = 7;
    link.expected_secret = Some(("dev".into(), "old-secret".into()));
    conn.links.insert(pid.into(), link);
    let old_attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(old_attempt, ("dev", "old-secret"));
    pending.auth = DirectAuth::device(7, "dev", "old-secret");
    conn.direct_pending.insert(pid.into(), pending);
    let newer_attempt = net::AttemptId::next();
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(newer_attempt);
    probe.auth = Some(DirectAuth::device(9, "dev", "new-secret"));
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let mut promotion = PromoteState::new(PromoteRole::Lead);
    promotion.attempt = Some(newer_attempt);
    promotion.auth = Some(DirectAuth::device(9, "dev", "new-secret"));
    conn.promotions.insert(pid.into(), promotion);
    let source = net::SourceId::next();
    conn.pending_sources.insert(
        source,
        PendingSource {
            pid: pid.into(),
            attempt: Some(newer_attempt),
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );
    let mut dropped = HashSet::new();
    dropped.insert("old-secret".into());
    conn.invalidate_peers(&[(pid.into(), "dev".into())], &dropped);
    assert!(!conn.direct_pending.contains_key(pid));
    assert!(conn.retired_attempts.contains_key(&old_attempt));
    assert_eq!(
        conn.resil.upgrade_probe.get(pid).and_then(|p| p.token),
        Some(newer_attempt)
    );
    assert_eq!(
        conn.promotions.get(pid).and_then(|p| p.attempt),
        Some(newer_attempt)
    );
    assert!(conn.pending_sources.contains_key(&source));
}

/// drop_link retires only the removed link attempt and leaves a newer
/// same-pid pending, probe, and source untouched.
#[tokio::test]
async fn exact_drop_link_preserves_unrelated_new_state() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-drop-exact";
    let old: Arc<dyn Transport> = Rec::new("old", &log);
    let old_attempt = old.attempt_id().unwrap();
    let mut link = direct_link(pid, "dev", "dev", old);
    link.generation = 7;
    link.attempt = Some(old_attempt);
    conn.links.insert(pid.into(), link);
    let newer_attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(newer_attempt, ("dev", "new-secret"));
    pending.auth = DirectAuth::device(9, "dev", "new-secret");
    conn.direct_pending.insert(pid.into(), pending);
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(newer_attempt);
    probe.auth = Some(DirectAuth::device(9, "dev", "new-secret"));
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let source = net::SourceId::next();
    conn.pending_sources.insert(
        source,
        PendingSource {
            pid: pid.into(),
            attempt: Some(newer_attempt),
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );
    conn.drop_link(pid);
    assert!(conn.retired_attempts.contains_key(&old_attempt));
    assert!(conn.direct_pending.contains_key(pid));
    assert!(conn.resil.upgrade_probe.contains_key(pid));
    assert!(conn.pending_sources.contains_key(&source));
}

/// Promotion staging rejects source-less, different-Arc-same-attempt,
/// revoked, and retired readiness before any source or held state mutation.
#[tokio::test]
async fn promotion_helpers_reject_before_mutation() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-promo-prevalidate";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    conn.links
        .insert(pid.into(), relay_link(pid, "peer", "peer", serving.clone()));
    conn.active = Some(pid.into());
    let attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(attempt, ("peer", "secret"));
    pending.ephemeral = true;
    pending.auth = DirectAuth::device(1, "peer", "secret");
    conn.direct_pending.insert(pid.into(), pending);
    let mut promotion = PromoteState::new(PromoteRole::Lead);
    promotion.attempt = Some(attempt);
    promotion.auth = Some(DirectAuth::device(1, "peer", "secret"));
    conn.promotions.insert(pid.into(), promotion);
    let held: Arc<dyn Transport> = Rec::with_attempt("held", &log, attempt);
    conn.promotions.get_mut(pid).unwrap().standby = Some((held.clone(), "direct-quic"));
    let no_source: Arc<dyn Transport> = Rec::without_source("nosource", &log, attempt);
    conn.stash_upgrade_standby(pid, no_source.clone(), "direct-quic");
    assert!(no_source.is_dead());
    let different: Arc<dyn Transport> = Rec::with_attempt("different", &log, attempt);
    conn.stash_upgrade_standby(pid, different.clone(), "direct-quic");
    assert!(different.is_dead());
    assert!(!held.is_dead());
    conn.promotions.get_mut(pid).unwrap().standby = None;
    conn.revoked_bindings.insert("secret".into());
    let revoked: Arc<dyn Transport> = Rec::with_attempt("revoked", &log, attempt);
    conn.stash_upgrade_standby(pid, revoked.clone(), "direct-quic");
    assert!(revoked.is_dead());
    conn.revoked_bindings.remove("secret");
    conn.retired_attempts.insert(
        attempt,
        RetiredAttempt::new(pid),
    );
    let retired: Arc<dyn Transport> = Rec::with_attempt("retired", &log, attempt);
    conn.stash_upgrade_standby(pid, retired.clone(), "direct-quic");
    assert!(retired.is_dead());
    assert!(conn.promotions.contains_key(pid));
    assert!(conn.direct_pending.contains_key(pid));
    assert!(conn.pending_sources.values().all(|p| p.pid != pid));
    assert!(conn.is_active(pid));
    assert!(conn.links.contains_key(pid));
}

/// A handed promotion does not accept a new standby, and a rejected stash
/// leaves no orphan pending source.
#[tokio::test]
async fn handed_promotion_duplicate_leaves_no_orphan() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-promo-handed";
    let attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(attempt, ("peer", "secret"));
    pending.ephemeral = true;
    pending.auth = DirectAuth::device(1, "peer", "secret");
    conn.direct_pending.insert(pid.into(), pending);
    let mut promotion = PromoteState::new(PromoteRole::Follow);
    promotion.handed = true;
    promotion.attempt = Some(attempt);
    promotion.auth = Some(DirectAuth::device(1, "peer", "secret"));
    conn.promotions.insert(pid.into(), promotion);
    let incoming: Arc<dyn Transport> = Rec::with_attempt("incoming", &log, attempt);
    conn.stash_upgrade_standby(pid, incoming.clone(), "direct-quic");
    assert!(incoming.is_dead());
    assert!(conn.promotions.get(pid).is_some_and(|p| p.handed));
    assert!(conn.pending_sources.values().all(|p| p.pid != pid));
}

/// A dead primary can be replaced atomically: the new epoch installs the
/// incoming Arc, revokes old workers/sources, and accepts fresh K>1 workers.
#[tokio::test]
async fn changed_primary_revokes_old_workers_and_accepts_fresh_workers() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-workers-replace";
    let old_primary: Arc<dyn Transport> = Rec::new("old-primary", &log);
    let old_source = old_primary.source_id().unwrap();
    let old_attempt = net::AttemptId::next();
    let mut link = direct_link(pid, "peer", "peer", old_primary.clone());
    link.source = old_source;
    link.attempt = Some(old_attempt);
    link.generation = 7;
    let old_worker: Arc<dyn Transport> = Rec::new("old-worker", &log);
    let old_worker_source = old_worker.source_id().unwrap();
    link.workers = vec![old_worker.clone()];
    link.worker_sources.insert(old_worker_source);
    conn.links.insert(pid.into(), link);
    old_primary.force_close();
    let new_primary: Arc<dyn Transport> = Rec::new("new-primary", &log);
    let new_attempt = new_primary.attempt_id().unwrap();
    let new_source = new_primary.source_id().unwrap();
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(new_attempt, ("peer", "secret")),
    );
    assert!(matches!(
        conn.adopt_direct(pid, new_primary.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt, .. } if attempt == new_attempt
    ));
    assert!(Arc::ptr_eq(conn.links[pid].transport.as_ref().unwrap(), &new_primary));
    assert_eq!(conn.links[pid].attempt, Some(new_attempt));
    assert_eq!(conn.links[pid].source, new_source);
    assert!(!new_primary.is_dead());
    assert!(old_worker.is_dead());
    assert!(conn.links[pid].worker_sources.is_empty());
    assert!(conn
        .stage_event(Ev::Sourced {
            pid: pid.into(),
            source: old_worker_source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "old" }))),
        })
        .is_none());
    let fresh_worker: Arc<dyn Transport> = Rec::new("fresh-worker", &log);
    let fresh_source = fresh_worker.source_id().unwrap();
    assert!(conn.accept_workers_ready(pid, vec![fresh_worker], new_source));
    assert!(conn.links[pid].worker_sources.contains(&fresh_source));
    assert!(matches!(
        conn.stage_event(Ev::Sourced {
            pid: pid.into(),
            source: fresh_source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "fresh" }))),
        }),
        Some((Ev::Control(..), Some(source))) if source == fresh_source
    ));
}

/// A live different-attempt primary is rejected before mutation; the old
/// primary, workers, source authority, and epoch stay exact and the incoming
/// transport is discarded.
#[tokio::test]
async fn live_different_attempt_primary_is_rejected_without_hybrid() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-workers-live-reject";
    let old_primary: Arc<dyn Transport> = Rec::new("old-primary", &log);
    let old_source = old_primary.source_id().unwrap();
    let old_attempt = net::AttemptId::next();
    let mut link = direct_link(pid, "peer", "peer", old_primary.clone());
    link.source = old_source;
    link.attempt = Some(old_attempt);
    link.generation = 7;
    let old_worker: Arc<dyn Transport> = Rec::new("old-worker", &log);
    let old_worker_source = old_worker.source_id().unwrap();
    link.workers = vec![old_worker.clone()];
    link.worker_sources.insert(old_worker_source);
    conn.links.insert(pid.into(), link);
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let incoming_attempt = incoming.attempt_id().unwrap();
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(incoming_attempt, ("peer", "secret")),
    );
    assert!(matches!(
        conn.adopt_direct(pid, incoming.clone(), "direct-quic"),
        DirectAdoption::Rejected
    ));
    let link = &conn.links[pid];
    assert!(Arc::ptr_eq(link.transport.as_ref().unwrap(), &old_primary));
    assert_eq!(link.attempt, Some(old_attempt));
    assert_eq!(link.source, old_source);
    assert_eq!(link.generation, 7);
    assert!(!old_primary.is_dead());
    assert!(!old_worker.is_dead());
    assert!(link.worker_sources.contains(&old_worker_source));
    assert!(incoming.is_dead());
    assert!(conn.direct_pending.contains_key(pid));
}

/// A LAN reservation carries the exact checked attempt and authenticated
/// device binding. It adopts once, consumes only that reservation, mints no
/// worker key, is the pair (trusted, named, `OwnerDevice`) while its binding
/// is live, and a duplicate Arc is harmless.
#[tokio::test]
async fn lan_reservation_adopts_once_and_duplicate_is_harmless() {
    let host = Arc::new(TestHost {
        devices: vec![("dev".into(), "secret".into())],
        transfer_allowed: true,
        ceilings: vec![("dev".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lan-owned";
    let t: Arc<dyn Transport> =
        Rec::with_attempt("lan", &log, net::AttemptId::next());
    let attempt = t.attempt_id().unwrap();
    conn.seed_lan(pid, "dev", "secret", false, attempt);
    assert_eq!(
        conn.direct_pending.get(pid).map(|pending| pending.attempt),
        Some(attempt)
    );
    assert!(matches!(
        conn.direct_pending.get(pid).map(|pending| pending.auth.domain),
        Some(DirectAuthDomain::Lan)
    ));
    let other = "sid-lan-unrelated";
    conn.direct_pending.insert(
        other.into(),
        direct_pending_with(net::AttemptId::next(), ("dev", "secret")),
    );
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(net::AttemptId::next());
    probe.auth = Some(DirectAuth::device(1, "dev", "secret"));
    conn.resil.upgrade_probe.insert(other.into(), probe);
    conn.pending_bindings
        .insert("sid-lan-provision".into(), ("dev".into(), "secret".into()));

    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { attempt: seen, tkey: None } if seen == attempt
    ));
    let link = &conn.links[pid];
    assert_eq!(link.direct_route, filament_transport::lan::ROUTE_LAN);
    assert!(link.trusted, "a LAN link to a live paired device was not the pair");
    assert_eq!(link.verified_name.as_deref(), Some("dev"));
    assert!(link.expected_secret.is_none());
    assert_eq!(
        link.lan_binding.as_ref().and_then(|b| b.device.clone()),
        Some(("dev".to_string(), "secret".to_string())),
        "the authenticated LAN device binding was lost"
    );
    assert!(!t.is_dead());
    assert!(!conn.direct_pending.contains_key(pid), "LAN reservation survived adoption");
    assert!(conn.direct_pending.contains_key(other));
    assert!(conn.resil.upgrade_probe.contains_key(other));
    assert!(conn.pending_bindings.contains_key("sid-lan-provision"));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Duplicate
    ));
    assert!(!t.is_dead(), "duplicate LAN ready closed the live transport");

    // The existing-link update path must clear the same field, not restore
    // it after the LAN exemption. A dead serving transport forces that path.
    let existing_pid = "sid-lan-existing";
    let dead: Arc<dyn Transport> = Rec::new("dead-serving", &log);
    let mut existing = relay_link(existing_pid, "dev", "dev", dead.clone());
    existing.expected_secret = Some(("dev".into(), "secret".into()));
    dead.force_close();
    conn.links.insert(existing_pid.into(), existing);
    let lan_existing: Arc<dyn Transport> =
        Rec::with_attempt("lan-existing", &log, net::AttemptId::next());
    let lan_existing_attempt = lan_existing.attempt_id().unwrap();
    conn.seed_lan(existing_pid, "dev", "secret", false, lan_existing_attempt);
    assert!(matches!(
        conn.adopt_direct(existing_pid, lan_existing.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { attempt, .. } if attempt == lan_existing_attempt
    ));
    assert!(
        conn.links[existing_pid].expected_secret.is_none(),
        "existing-link LAN adoption restored a device binding"
    );
    assert_eq!(
        conn.links[existing_pid]
            .lan_binding
            .as_ref()
            .and_then(|b| b.device.clone()),
        Some(("dev".to_string(), "secret".to_string()))
    );
    assert!(Arc::ptr_eq(
        conn.links[existing_pid].transport.as_ref().unwrap(),
        &lan_existing
    ));
    // Both paths give the pair link's principal and trust, resolved from
    // the record exactly as a pair link is, not the empty delegated
    // ceiling that refused the forward a granted pair carries.
    for owned in [pid, existing_pid] {
        let link = &conn.links[owned];
        assert!(link.trusted, "LAN adoption of {owned} was not the pair");
        assert_eq!(link.verified_name.as_deref(), Some("dev"));
        assert!(
            matches!(&link.principal_kind, PrincipalKind::OwnerDevice),
            "LAN adoption of {owned} did not carry the pair principal"
        );
    }

    // A LAN fleet reservation keeps its name for dedup but exposes NO
    // device binding: the shared rendezvous secret never becomes one.
    let fleet_pid = "sid-lan-fleet";
    let fleet_lan: Arc<dyn Transport> =
        Rec::with_attempt("lan-fleet", &log, net::AttemptId::next());
    let fleet_lan_attempt = fleet_lan.attempt_id().unwrap();
    conn.seed_lan(fleet_pid, "fleet", "fleet-rv", true, fleet_lan_attempt);
    assert!(matches!(
        conn.adopt_direct(fleet_pid, fleet_lan, filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { tkey: None, .. }
    ));
    assert!(!conn.links[fleet_pid].trusted, "a fleet LAN reservation was trusted");
    assert!(conn.links[fleet_pid].verified_name.is_none());
    let fleet_binding = conn.links[fleet_pid].lan_binding.as_ref().unwrap();
    assert_eq!(fleet_binding.name, "fleet");
    assert!(fleet_binding.device.is_none());
    assert!(conn.links[fleet_pid].expected_secret.is_none());
    assert!(conn.links[fleet_pid].device_secret().is_none());
    assert!(
        matches!(
            &conn.links[fleet_pid].principal_kind,
            PrincipalKind::Delegated { caps } if caps.is_empty()
        ),
        "a fleet reservation must never inherit a device ceiling"
    );
    let auth = DirectAuth::lan_device(1, "dev", "secret");
    assert!(auth.device_binding.is_some());
    assert!(auth.transport_key().is_none());
}

/// A live LAN link is deduped by its authenticated reservation. Its exact
/// device binding drives
/// revocation, while a dead LAN link no longer dedups and unrelated device
/// or fleet links survive the LAN link's removal.
#[tokio::test]
async fn lan_binding_dedups_and_drives_revocation_only_for_its_device() {
    use crate::recv::revocation::{facts_for, link_must_close};
    let host = Arc::new(TestHost {
        devices: vec![
            ("dev".into(), "secret".into()),
            ("other".into(), "other-secret".into()),
        ],
        transfer_allowed: true,
        ceilings: vec![("dev".to_string(), vec!["transfer".to_string()])],
        ..Default::default()
    });
    let (mut conn, _far, _rx) = test_conn_with_host(host).await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lan-live";
    let t: Arc<dyn Transport> = Rec::with_attempt("lan-live", &log, net::AttemptId::next());
    let attempt = t.attempt_id().unwrap();
    conn.seed_lan(pid, "dev", "secret", false, attempt);
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { .. }
    ));
    assert!(conn.links[pid].trusted);
    assert_eq!(conn.links[pid].verified_name.as_deref(), Some("dev"));
    assert!(conn.links[pid].expected_secret.is_none());
    assert_eq!(
        conn.links[pid].lan_binding.as_ref().and_then(|b| b.device.clone()),
        Some(("dev".to_string(), "secret".to_string()))
    );
    assert!(conn.has_link_to("dev"));
    assert!(conn.has_link_to("DEV"));

    let other: Arc<dyn Transport> = Rec::new("other", &log);
    let mut other_link = relay_link("sid-other-device", "other", "other", other);
    other_link.expected_secret = Some(("other".into(), "other-secret".into()));
    conn.links.insert("sid-other-device".into(), other_link);
    let fleet: Arc<dyn Transport> = Rec::new("fleet", &log);
    let mut fleet_link = direct_link("sid-fleet", "fleet", "fleet", fleet);
    fleet_link.expected_secret = Some(("fleet".into(), "fleet-rv".into()));
    conn.links.insert("sid-fleet".into(), fleet_link);

    let mut forgotten = HashSet::new();
    forgotten.insert("secret".to_string());
    let never = |_: &[u8; 32]| false;
    assert!(link_must_close(&facts_for(&conn, pid), &forgotten, &never));
    assert!(!link_must_close(&facts_for(&conn, "sid-other-device"), &forgotten, &never));
    assert!(!link_must_close(&facts_for(&conn, "sid-fleet"), &forgotten, &never));

    t.force_close();
    assert!(!conn.has_link_to("dev"), "a dead LAN link still deduped");
    conn.drop_link(pid);
    assert!(!conn.links.contains_key(pid));
    assert!(conn.links.contains_key("sid-other-device"));
    assert!(conn.links.contains_key("sid-fleet"));
}

/// A retired LAN attempt cannot resurrect, and a withdrawn LAN link retires
/// its exact attempt for a queued duplicate.
#[tokio::test]
async fn retired_lan_attempt_cannot_resurrect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lan-retired";
    let t: Arc<dyn Transport> =
        Rec::with_attempt("lan", &log, net::AttemptId::next());
    let attempt = t.attempt_id().unwrap();
    conn.seed_lan(pid, "dev", "secret", false, attempt);
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Adopted { .. }
    ));
    conn.drop_link(pid);
    assert!(conn.retired_attempts.contains_key(&attempt));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Rejected
    ));
    assert!(!conn.links.contains_key(pid));

    let fresh_pid = "sid-lan-already-retired";
    let fresh: Arc<dyn Transport> =
        Rec::with_attempt("lan-retired", &log, net::AttemptId::next());
    let fresh_attempt = fresh.attempt_id().unwrap();
    conn.seed_lan(fresh_pid, "dev", "secret", false, fresh_attempt);
    conn.retired_attempts.insert(
        fresh_attempt,
        RetiredAttempt::new(fresh_pid),
    );
    assert!(matches!(
        conn.adopt_direct(fresh_pid, fresh.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Rejected
    ));
    assert!(fresh.is_dead());
    assert!(!conn.links.contains_key(fresh_pid));
}

/// A FULL retirement drain refuses new direct attempts, but not the relay
/// recovery or the no-op returns, which consume no drain capacity. With
/// the check first, a relay-committed peer with no link was refused its
/// relay re-establish whenever the drain was full, and stayed disconnected.
#[tokio::test]
async fn a_full_drain_still_re_establishes_a_relay_committed_peer() {
    let (mut conn, _far, _rx) = test_conn().await;
    conn.direct_ok = true;
    let log = Arc::new(crate::host::VecLog::new());
    conn.log = log.clone() as Arc<dyn LogSink>;
    // Live producers: the backstop cannot reap any of them.
    for _ in 0..MAX_RETIRED_ATTEMPTS {
        conn.retired_attempts
            .insert(net::AttemptId::next(), RetiredAttempt::new("sid-other"));
    }
    let pid = "sid-relay";
    conn.resil.relay_committed.insert(pid.into());
    conn.start_direct(pid, "peer", "pair-secret").await;
    assert!(
        conn.links.contains_key(pid),
        "the relay re-establish was refused by a full drain"
    );
    assert!(!conn.direct_pending.contains_key(pid), "a direct attempt was armed");
    let lines = log.take();
    assert!(
        !lines.iter().any(|(_, l)| l.contains("retirement drain capacity full")),
        "the relay recovery was counted as a refused direct attempt: {lines:?}"
    );

    // A peer that is NOT relay-committed is still refused, before any
    // pending exists: the drain bound itself is unchanged.
    let other = "sid-direct";
    conn.start_direct(other, "peer2", "pair-secret-2").await;
    assert!(!conn.direct_pending.contains_key(other), "a full drain armed a direct attempt");
    assert!(
        log.take().iter().any(|(_, l)| l.contains(&format!(
            "direct attempt for {other} refused: retirement drain capacity full"
        ))),
        "the full drain did not refuse the direct attempt"
    );
}

/// The capacity backstop reaps a tombstone by age only once its producer
/// is terminal. A drained tombstone past the TTL is reaped (its drain event
/// was lost); an undrained one past the TTL is kept, because its producer
/// may still emit a ready; a drained one inside the TTL is kept, because
/// its barrier may still be queued.
#[tokio::test]
async fn only_a_drained_tombstone_is_reaped_past_its_ttl() {
    let (mut conn, _far, _rx) = test_conn().await;
    let drained_old = net::AttemptId::next();
    let live_old = net::AttemptId::next();
    let drained_young = net::AttemptId::next();
    let at = Instant::now();
    let tombstone = |drained: bool| RetiredAttempt {
        pid: "sid-retired".into(),
        at,
        drained: Arc::new(AtomicBool::new(drained)),
    };
    conn.retired_attempts.insert(drained_old, tombstone(true));
    conn.retired_attempts.insert(live_old, tombstone(false));
    conn.reap_drained_tombstones(at + RETIRED_TOMBSTONE_TTL / 2);
    assert_eq!(conn.retired_attempts.len(), 2, "nothing is reaped inside the TTL");

    conn.retired_attempts.insert(drained_young, RetiredAttempt {
        pid: "sid-retired".into(),
        at: at + RETIRED_TOMBSTONE_TTL,
        drained: Arc::new(AtomicBool::new(true)),
    });
    conn.reap_drained_tombstones(at + RETIRED_TOMBSTONE_TTL + Duration::from_secs(1));
    assert!(
        !conn.retired_attempts.contains_key(&drained_old),
        "a drained tombstone past its TTL must be reaped"
    );
    assert!(
        conn.retired_attempts.contains_key(&live_old),
        "a tombstone whose producer is still live must keep its slot past the TTL"
    );
    assert!(
        conn.retired_attempts.contains_key(&drained_young),
        "a drained tombstone inside its TTL must be kept"
    );
}

/// The drain task marks a tombstone drained only after the producer's
/// handle has returned. A producer still running leaves it undrained.
#[tokio::test]
async fn retire_marks_drained_only_after_the_producer_is_terminal() {
    let (mut conn, _far, _rx) = test_conn().await;
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let producer = tokio::spawn(async move {
        let _ = released.await;
    });
    let attempt = net::AttemptId::next();
    conn.retire_attempt("sid-producer", attempt, Some(producer));
    let drained = conn.retired_attempts[&attempt].drained.clone();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !drained.load(Ordering::Acquire),
        "a live producer must leave its tombstone undrained"
    );
    let _ = release.send(());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !drained.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("a finished producer must mark its tombstone drained");

    let sync_attempt = net::AttemptId::next();
    conn.retire_attempt("sid-sync", sync_attempt, None);
    assert!(
        conn.retired_attempts[&sync_attempt].drained.load(Ordering::Acquire),
        "a retirement with no async producer is drained at once"
    );
}

/// A LAN reservation must match its exact attempt, and a forgotten device
/// secret cannot be reused by a queued ready even though the LAN pid is new.
#[tokio::test]
async fn lan_mismatch_and_forgotten_secret_reject() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lan-mismatch";
    let reserved: Arc<dyn Transport> =
        Rec::with_attempt("reserved", &log, net::AttemptId::next());
    let reserved_attempt = reserved.attempt_id().unwrap();
    conn.seed_lan(pid, "dev", "secret", false, reserved_attempt);
    let incoming: Arc<dyn Transport> =
        Rec::with_attempt("incoming", &log, net::AttemptId::next());
    assert!(matches!(
        conn.adopt_direct(pid, incoming.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Rejected
    ));
    assert!(incoming.is_dead());
    assert!(conn.direct_pending.contains_key(pid));
    assert!(!conn.links.contains_key(pid));

    let forgotten_pid = "sid-lan-forgotten";
    let forgotten: Arc<dyn Transport> =
        Rec::with_attempt("forgotten", &log, net::AttemptId::next());
    let forgotten_attempt = forgotten.attempt_id().unwrap();
    conn.seed_lan(forgotten_pid, "dev", "forgotten-secret", false, forgotten_attempt);
    conn.revoked_bindings.insert("forgotten-secret".into());
    assert!(matches!(
        conn.adopt_direct(forgotten_pid, forgotten.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Rejected
    ));
    assert!(forgotten.is_dead());
    assert!(!conn.links.contains_key(forgotten_pid));
}

/// LAN ownership does not widen any other route, and a LAN ready with no
/// reservation fails closed.
#[tokio::test]
async fn unknown_no_reservation_ready_still_fails_closed() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let non_lan_pid = "sid-non-lan-unknown";
    let non_lan: Arc<dyn Transport> =
        Rec::with_attempt("unknown", &log, net::AttemptId::next());
    assert!(matches!(
        conn.adopt_direct(non_lan_pid, non_lan.clone(), "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(non_lan.is_dead());
    assert!(!conn.links.contains_key(non_lan_pid));

    let lan_pid = "sid-lan-no-reservation";
    let lan: Arc<dyn Transport> =
        Rec::with_attempt("lan-unknown", &log, net::AttemptId::next());
    assert!(matches!(
        conn.adopt_direct(lan_pid, lan.clone(), filament_transport::lan::ROUTE_LAN),
        DirectAdoption::Rejected
    ));
    assert!(lan.is_dead());
    assert!(!conn.links.contains_key(lan_pid));
}

/// A source event forwarded while its link was current must be rejected if
/// the same pid is replaced before dequeue/dispatch (final-handler check).
#[tokio::test]
async fn a_forwarded_current_source_then_replaced_is_rejected() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-source-race";
    let old = Rec::new("old", &log);
    let source_a = old.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", old.clone());
    link.source = source_a;
    link.generation = 7;
    conn.links.insert(pid.to_string(), link);
    // Queue while A is current; do NOT dequeue yet.
    conn.tx
        .send(Ev::Sourced {
            pid: pid.into(),
            source: source_a,
            inner: Box::new(Ev::Control(
                pid.into(),
                json!({ "type": "l3-nonce", "nonce": "aaaa" }),
            )),
        })
        .unwrap();
    conn.tx
        .send(Ev::Sourced {
            pid: pid.into(),
            source: source_a,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "path-promote" }))),
        })
        .unwrap();
    // Replace the same pid before dispatch.
    let new = Rec::new("new", &log);
    let source_b = new.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", new);
    link.source = source_b;
    link.generation = 8;
    conn.links.insert(pid.to_string(), link);
    for _ in 0..2 {
        let ev = rx.try_recv().unwrap();
        assert!(conn.stage_event(ev).is_none(), "stale source accepted");
    }
}

/// The same event shape with the CURRENT source is accepted.
#[tokio::test]
async fn a_current_source_control_is_accepted() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-source-current";
    let t = Rec::new("current", &log);
    let source = t.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", t);
    link.source = source;
    conn.links.insert(pid.to_string(), link);
    conn.tx
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(
                pid.into(),
                json!({ "type": "l3-nonce", "nonce": "bbbb" }),
            )),
        })
        .unwrap();
    let ev = rx.try_recv().unwrap();
    assert!(matches!(conn.stage_event(ev), Some((Ev::Control(..), Some(s))) if s == source));
}

#[tokio::test]
async fn retained_webrtc_readiness_is_tagged_and_stale_readiness_rejected() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-readiness-source";
    let t: Arc<dyn Transport> = Rec::new("webrtc", &log);
    let source = t.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", t.clone());
    link.source = source;
    conn.links.insert(pid.to_string(), link);

    conn.tx
        .send(Ev::sourced_channel_ready(pid.into(), t.clone()))
        .unwrap();
    let ev = rx.try_recv().unwrap();
    match conn.stage_event(ev) {
        Some((Ev::ChannelReady(got_pid, got), Some(seen))) => {
            assert_eq!(got_pid, pid);
            assert!(Arc::ptr_eq(&got, &t), "the callback transport was replaced");
            assert_eq!(seen, source, "readiness did not carry the build source");
        }
        _ => panic!("retained WebRTC readiness was dropped by the exact-source gate"),
    }

    // The same immutable callback after the pid gains a newer build source
    // must be refused: it cannot re-attach the retired transport or open a
    // transfer on the replacement link.
    let new = Rec::new("webrtc-new", &log);
    let new_source = new.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", new);
    link.source = new_source;
    conn.links.insert(pid.to_string(), link);
    conn.tx.send(Ev::sourced_channel_ready(pid.into(), t)).unwrap();
    let ev = rx.try_recv().unwrap();
    assert!(
        conn.stage_event(ev).is_none(),
        "stale readiness reopened a replaced link"
    );
}

/// Envelope/inner pid mismatch, nesting, and untagged transport events are
/// all refused; the explicit internal variant is accepted.
#[tokio::test]
async fn source_envelope_validation_is_strict() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-source-shape";
    let t = Rec::new("shape", &log);
    let source = t.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", t);
    link.source = source;
    conn.links.insert(pid.to_string(), link);
    assert!(conn
        .stage_event(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control("other-pid".into(), json!({ "type": "x" }))),
        })
        .is_none());
    assert!(conn
        .stage_event(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Sourced {
                pid: pid.into(),
                source,
                inner: Box::new(Ev::Control(pid.into(), json!({ "type": "x" }))),
            }),
        })
        .is_none());
    assert!(conn
        .stage_event(Ev::Control(pid.into(), json!({ "type": "x" })))
        .is_none());
    assert!(conn
        .stage_event(Ev::LocalControl(pid.into(), json!({ "type": "x" })))
        .is_some());
}

#[tokio::test]
async fn chunk_attribution_fences_pairing_and_worker_dispatch() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "pairing-peer";
    let primary = Rec::new("primary", &log);
    let source = primary.source_id().unwrap();
    let worker = Rec::new("worker", &log);
    let worker_source = worker.source_id().unwrap();
    let retired = net::SourceId::next();
    let mut link = relay_link(pid, "peer", "peer", primary);
    link.source = source;
    link.worker_sources.insert(worker_source);
    conn.links.insert(pid.into(), link);
    let chunk = |s, envelope: &str, inner: &str| Ev::Sourced {
        pid: envelope.into(), source: s,
        inner: Box::new(Ev::Chunk(inner.into(), 42, Some(0), bytes::Bytes::from_static(b"pair"))),
    };
    assert!(matches!(conn.stage_event(chunk(source, pid, pid)), Some((Ev::Chunk(..), Some(s))) if s == source));
    assert!(matches!(conn.stage_event(chunk(worker_source, pid, pid)), Some((Ev::Chunk(..), Some(s))) if s == worker_source));
    assert!(conn.stage_event(chunk(retired, pid, pid)).is_none());
    assert!(conn.stage_event(chunk(source, pid, "other")).is_none());
    assert!(conn.stage_event(Ev::Chunk(pid.into(), 42, Some(0), bytes::Bytes::new())).is_none());

    // A registered standby may read before adoption. Replay stays tagged,
    // and replacement between flush and dispatch must still fence it.
    let standby = Rec::new("standby", &log);
    let standby_source = standby.source_id().unwrap();
    conn.pending_sources.insert(standby_source, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::new(), bytes: 0,
    });
    assert!(conn.stage_event(chunk(standby_source, pid, pid)).is_none());
    assert_eq!(conn.pending_sources[&standby_source].events.len(), 1);
    assert_eq!(conn.pending_sources[&standby_source].bytes, 4);
    conn.links.get_mut(pid).unwrap().source = standby_source;
    conn.flush_pending_source(standby_source);
    assert!(matches!(conn.stage_event(rx.try_recv().unwrap()), Some((Ev::Chunk(..), Some(s))) if s == standby_source));

    conn.links.get_mut(pid).unwrap().source = source;
    conn.pending_sources.insert(standby_source, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::new(), bytes: 0,
    });
    assert!(conn.stage_event(chunk(standby_source, pid, pid)).is_none());
    conn.links.get_mut(pid).unwrap().source = standby_source;
    conn.flush_pending_source(standby_source);
    conn.links.get_mut(pid).unwrap().source = source;
    assert!(conn.stage_event(rx.try_recv().unwrap()).is_none());
    conn.links.get_mut(pid).unwrap().worker_sources.clear();
    assert!(conn.stage_event(chunk(worker_source, pid, pid)).is_none());
}

#[tokio::test]
async fn buffered_standby_chunks_cannot_be_overtaken_at_adoption() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "ordered-standby";
    let old = Rec::new("old", &log);
    let old_source = old.source_id().unwrap();
    let standby = Rec::new("standby", &log);
    let source = standby.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", old);
    link.source = old_source;
    conn.links.insert(pid.into(), link);
    conn.pending_sources.insert(source, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::new(), bytes: 0,
    });
    let chunk = |offset, data: &'static [u8]| Ev::Sourced {
        pid: pid.into(), source,
        inner: Box::new(Ev::Chunk(pid.into(), 42, Some(offset), bytes::Bytes::from_static(data))),
    };
    assert!(conn.stage_event(chunk(0, b"old")).is_none());
    // This event is already in the normal queue when adoption happens.
    conn.tx.send(chunk(3, b"new")).unwrap();
    conn.links.get_mut(pid).unwrap().source = source;
    conn.flush_pending_source(source);
    let first = conn.stage_event(rx.try_recv().unwrap()).unwrap().0;
    let second = conn.stage_event(rx.try_recv().unwrap()).unwrap().0;
    assert!(matches!(first, Ev::Chunk(_, 42, Some(0), ref data) if data.as_ref() == b"old"));
    assert!(matches!(second, Ev::Chunk(_, 42, Some(3), ref data) if data.as_ref() == b"new"));
    assert!(conn.replaying_sources.is_empty());
}

#[tokio::test]
async fn replay_precedes_real_departure_paths_and_fences_replacement() {
    for sourced_barrier in [false, true] {
        let (mut conn, _far, mut rx) = test_conn().await;
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pid = "replay-departure";
        let transport = Rec::new("current", &log);
        let source = transport.source_id().unwrap();
        conn.links.insert(pid.into(), delegated_link(pid, transport));
        if sourced_barrier {
            let (_tx, queued) = tokio::sync::mpsc::unbounded_channel();
            conn.link_events.insert(pid.into(), LinkEvents {
                generation: 7, rx: std::sync::Mutex::new(queued),
                departure_ready: None, departure_pending: Some(source),
            });
        }
        conn.pending_sources.insert(source, PendingSource {
            pid: pid.into(), attempt: None, at: Instant::now(),
            events: std::collections::VecDeque::from([Ev::Chunk(
                pid.into(), 42, Some(0), bytes::Bytes::from_static(b"before-left"),
            )]), bytes: 11,
        });
        let payload = json!({"id": pid});
        let departure = if sourced_barrier {
            Ev::Sourced { pid: pid.into(), source, inner: Box::new(Ev::PeerLeft(payload.clone())) }
        } else { Ev::PeerLeft(payload.clone()) };
        conn.tx.send(departure).unwrap();
        conn.flush_pending_source(source);
        if let Some((Ev::PeerLeft(v), _)) = conn.stage_event(rx.try_recv().unwrap()) {
            assert!(!conn.on_peer_left(&v));
        } else {
            assert!(sourced_barrier, "ordinary room departure was not dispatched");
        }
        assert!(conn.links.contains_key(pid), "departure overtook buffered data");
        assert!(matches!(conn.stage_event(rx.try_recv().unwrap()), Some((Ev::Chunk(_, 42, Some(0), ref b), Some(s))) if s == source && b.as_ref() == b"before-left"));
        let (Ev::PeerLeft(v), seen) = conn.stage_event(rx.try_recv().unwrap()).expect("deferred departure") else { panic!("expected departure") };
        assert_eq!(seen, Some(source));
        conn.on_peer_left(&v);
        assert!(!conn.links.contains_key(pid), "departure did not finalize");
    }

    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "replay-replacement";
    let old = Rec::new("old", &log);
    let source = old.source_id().unwrap();
    conn.links.insert(pid.into(), delegated_link(pid, old));
    conn.pending_sources.insert(source, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::from([Ev::Chunk(pid.into(), 42, None, bytes::Bytes::from_static(b"x"))]), bytes: 1,
    });
    conn.flush_pending_source(source);
    assert!(!conn.on_peer_left(&json!({"id": pid})));
    let successor = Rec::new("successor", &log);
    conn.links.insert(pid.into(), delegated_link(pid, successor));
    assert!(conn.stage_event(rx.try_recv().unwrap()).is_none());
    assert!(conn.stage_event(rx.try_recv().unwrap()).is_none());
    assert!(conn.links.contains_key(pid), "stale deferred departure dropped replacement");

    // A replacement after the deferred event passes staging but before its
    // caller invokes on_peer_left must also survive.
    let current = conn.links[pid].source;
    conn.replaying_sources.insert(current, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::from([Ev::Chunk(pid.into(), 42, None, bytes::Bytes::from_static(b"y"))]), bytes: 1,
    });
    conn.tx.send(Ev::ReplaySource(current)).unwrap();
    assert!(!conn.on_peer_left(&json!({"id": pid})));
    assert!(matches!(conn.stage_event(rx.try_recv().unwrap()), Some((Ev::Chunk(..), _))));
    let (Ev::PeerLeft(deferred), _) = conn.stage_event(rx.try_recv().unwrap()).unwrap() else { panic!("expected staged departure") };
    conn.drop_link(pid);
    let newer = Rec::new("newer", &log);
    conn.links.insert(pid.into(), delegated_link(pid, newer));
    assert!(!conn.on_peer_left(&deferred));
    assert!(conn.links.contains_key(pid), "staged departure dropped a newer link");
}

/// The replay swap path closes the CURRENT, already adopted transport when
/// the replay would exceed the event budget. That is a behaviour change on
/// a live link, so it is pinned here rather than left implicit: the
/// standby's replay is dropped, the adopted link's transport is closed,
/// and the daemon keeps running.
#[tokio::test]
async fn a_replay_overflow_closes_the_adopted_link_not_the_standby() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "replay-overflow";
    let adopted = Rec::new("adopted", &log);
    let source = adopted.source_id().unwrap();
    conn.links
        .insert(pid.into(), delegated_link(pid, adopted.clone()));
    // A replay already in flight for this source, with one buffered event.
    conn.replaying_sources.insert(source, PendingSource {
        pid: pid.into(), attempt: None, at: Instant::now(),
        events: std::collections::VecDeque::from([Ev::Chunk(pid.into(), 42, None, bytes::Bytes::from_static(b"old"))]), bytes: 3,
    });
    // A new event over the budget: the swap overflows and must close the
    // adopted transport.
    // The comparison is strict (`>`), so exactly the limit is allowed.
    // One byte above it must take the overflow path.
    let big = vec![0u8; MAX_BUILD_EVENT_BYTES + 1];
    let ev = Ev::Sourced {
        pid: pid.into(),
        source,
        inner: Box::new(Ev::Chunk(pid.into(), 42, None, bytes::Bytes::from(big))),
    };
    assert!(conn.stage_event(ev).is_none(), "the overflowing event must not be dispatched");
    assert!(!conn.replaying_sources.contains_key(&source), "the replay entry must be dropped");
    assert!(conn.links.contains_key(pid), "the daemon must survive the overflow");
    assert!(adopted.is_dead(), "overflow must close the adopted transport");
}

/// A registered standby source buffers until adoption, replays with its tag,
/// and is still checked at the final gate.
#[tokio::test]
async fn a_standby_source_buffers_until_adoption_then_replays() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-source-standby";
    let t = Rec::new("standby", &log);
    let source = t.source_id().unwrap();
    conn.pending_sources.insert(
        source,
        PendingSource {
            pid: pid.into(),
            attempt: None,
            at: Instant::now(),
            events: std::collections::VecDeque::new(),
            bytes: 0,
        },
    );
    let ev = Ev::Sourced {
        pid: pid.into(),
        source,
        inner: Box::new(Ev::Control(pid.into(), json!({ "type": "l3-nonce" }))),
    };
    assert!(conn.stage_event(ev).is_none());
    assert_eq!(conn.pending_sources[&source].events.len(), 1);
    // Adopt: make the source current and flush the buffered event.
    let mut link = relay_link(pid, "peer", "peer", t);
    link.source = source;
    conn.links.insert(pid.to_string(), link);
    conn.flush_pending_source(source);
    let ev = rx.try_recv().unwrap();
    assert!(matches!(conn.stage_event(ev), Some((Ev::Control(..), Some(s))) if s == source));
}

/// A workers-ready from an older primary must not authorize its workers on
/// the new link; the current primary's ready is accepted.
#[tokio::test]
async fn stale_workers_ready_is_refused_and_current_is_accepted() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-workers-source";
    let primary = Rec::new("primary", &log);
    let primary_source = primary.source_id().unwrap();
    let mut link = relay_link(pid, "peer", "peer", primary);
    link.source = primary_source;
    conn.links.insert(pid.to_string(), link);
    let old_worker = Rec::new("old-worker", &log);
    let old_source = old_worker.source_id().unwrap();
    let new_worker = Rec::new("new-worker", &log);
    let new_source = new_worker.source_id().unwrap();
    assert!(!conn.accept_workers_ready(pid, vec![old_worker], net::SourceId::UNASSIGNED));
    assert!(conn.links[pid].workers.is_empty());
    assert!(conn.accept_workers_ready(pid, vec![new_worker], primary_source));
    assert!(conn.links[pid].worker_sources.contains(&new_source));
    assert!(!conn.links[pid].worker_sources.contains(&old_source));
}

/// Exact duplicate readiness for an adopted attempt is harmless; the live
/// transport is not closed and the link is unchanged.
#[tokio::test]
async fn duplicate_ready_after_adoption_is_harmless() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-attempt-duplicate";
    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    let attempt = t.attempt_id().unwrap();
    conn.direct_pending
        .insert(pid.into(), direct_pending_with(attempt, ("peer", "secret")));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Adopted { attempt: seen, .. } if seen == attempt
    ));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Duplicate
    ));
    assert!(conn.links.contains_key(pid));
    assert!(!t.is_dead(), "duplicate readiness closed the live transport");
}

/// A queued ready for an attempt whose link was dropped must not resurrect it.
#[tokio::test]
async fn ready_after_drop_does_not_resurrect() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-attempt-drop";
    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    let attempt = t.attempt_id().unwrap();
    conn.direct_pending
        .insert(pid.into(), direct_pending_with(attempt, ("peer", "secret")));
    assert!(matches!(
        conn.adopt_direct(pid, t.clone(), "direct-quic"),
        DirectAdoption::Adopted { .. }
    ));
    conn.drop_link(pid);
    assert!(!conn.links.contains_key(pid));
    assert!(matches!(
        conn.adopt_direct(pid, t, "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(!conn.links.contains_key(pid), "retired readiness resurrected a link");
}

/// A ready for a different attempt must not consume the pending or its
/// secret/fleet metadata.
#[tokio::test]
async fn mismatched_ready_does_not_consume_pending() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-attempt-mismatch";
    let pending_attempt = net::AttemptId::next();
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(pending_attempt, ("peer", "keep-me")),
    );
    let t: Arc<dyn Transport> = Rec::new("other", &log);
    assert!(matches!(
        conn.adopt_direct(pid, t, "direct-quic"),
        DirectAdoption::Rejected
    ));
    let pending = conn.direct_pending.get(pid).expect("pending was consumed");
    assert_eq!(pending.attempt, pending_attempt);
    assert_eq!(pending.secret, ("peer".to_string(), "keep-me".to_string()));
}

/// No pending/promotion ownership means no Conn adoption.
#[tokio::test]
async fn unowned_ready_is_rejected() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-attempt-unowned";
    let t: Arc<dyn Transport> = Rec::new("direct", &log);
    assert!(matches!(
        conn.adopt_direct(pid, t, "direct-quic"),
        DirectAdoption::Rejected
    ));
    assert!(!conn.links.contains_key(pid));
}

/// A rejected upgrade must not destroy the serving relay link, active flag,
/// probe token, pending metadata, or relay commitment.
#[tokio::test]
async fn upgrade_mismatch_preserves_serving_state() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-mismatch";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = direct_link(pid, "peer", "peer", serving.clone());
    link.generation = 7;
    let pending_attempt = net::AttemptId::next();
    link.attempt = Some(pending_attempt);
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    conn.resil.relay_committed.insert(pid.into());
    let pending = direct_pending_with(pending_attempt, ("peer", "keep"));
    conn.direct_pending.insert(pid.into(), pending);
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(pending_attempt);
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    conn.perform_upgrade(pid, incoming.clone(), "direct-quic").await;
    assert!(conn.links[pid]
        .transport
        .as_ref()
        .is_some_and(|live| Arc::ptr_eq(live, &serving)));
    assert_eq!(conn.links[pid].generation, 7);
    assert!(conn.is_active(pid));
    assert!(conn.resil.relay_committed.contains(pid));
    assert_eq!(
        conn.direct_pending.get(pid).map(|p| p.attempt),
        Some(pending_attempt)
    );
    assert_eq!(
        conn.resil.upgrade_probe.get(pid).and_then(|p| p.token),
        Some(pending_attempt)
    );
    assert!(incoming.is_dead(), "the rejected standby must be closed");
}

/// A matching attempt with no source identity still fails before any
/// destructive upgrade step.
#[tokio::test]
async fn upgrade_missing_source_preserves_serving_state() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-nosource";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = direct_link(pid, "peer", "peer", serving.clone());
    link.generation = 7;
    let try_attempt = net::AttemptId::next();
    link.attempt = Some(try_attempt);
    conn.links.insert(pid.into(), link);
    conn.active = Some(pid.into());
    conn.resil.relay_committed.insert(pid.into());
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(try_attempt, ("peer", "keep")),
    );
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(try_attempt);
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let incoming: Arc<dyn Transport> =
        Rec::without_source("incoming", &log, try_attempt);
    conn.perform_upgrade(pid, incoming.clone(), "direct-quic").await;
    assert!(conn.links[pid]
        .transport
        .as_ref()
        .is_some_and(|live| Arc::ptr_eq(live, &serving)));
    assert_eq!(conn.links[pid].generation, 7);
    assert!(conn.is_active(pid));
    assert!(conn.resil.relay_committed.contains(pid));
    assert_eq!(
        conn.direct_pending.get(pid).map(|p| p.attempt),
        Some(try_attempt)
    );
    assert_eq!(
        conn.resil.upgrade_probe.get(pid).and_then(|p| p.token),
        Some(try_attempt)
    );
    assert!(incoming.is_dead());
}

/// A matching pending with no armed probe must not be consumed by standby
/// staging.
#[tokio::test]
async fn standby_without_probe_preserves_pending() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-standby-noprobe";
    let attempt = net::AttemptId::next();
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(attempt, ("peer", "keep")),
    );
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let source = incoming.source_id().unwrap();
    conn.stash_upgrade_standby(pid, incoming.clone(), "direct-quic");
    let pending = conn.direct_pending.get(pid).expect("pending was consumed");
    assert_eq!(pending.attempt, attempt);
    assert_eq!(pending.secret, ("peer".to_string(), "keep".to_string()));
    assert!(!conn.pending_sources.contains_key(&source));
    assert!(incoming.is_dead());
}

/// A probe whose token does not match the pending must not consume pending
/// metadata or replace the probe token.
#[tokio::test]
async fn standby_probe_mismatch_preserves_pending_and_token() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-standby-mismatch";
    let attempt = net::AttemptId::next();
    let other = net::AttemptId::next();
    conn.direct_pending.insert(
        pid.into(),
        direct_pending_with(attempt, ("peer", "keep")),
    );
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(other);
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let source = incoming.source_id().unwrap();
    conn.stash_upgrade_standby(pid, incoming.clone(), "direct-quic");
    let pending = conn.direct_pending.get(pid).expect("pending was consumed");
    assert_eq!(pending.attempt, attempt);
    assert_eq!(
        conn.resil.upgrade_probe.get(pid).and_then(|p| p.token),
        Some(other)
    );
    assert!(!conn.pending_sources.contains_key(&source));
    assert!(incoming.is_dead());
}

/// A promotion with no upstream-attempt token is not authorization; a ready
/// must not consume pending metadata or create a source registration.
#[tokio::test]
async fn standby_promotion_none_token_preserves_pending() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-promo-none";
    let attempt = net::AttemptId::next();
    let mut pending = direct_pending_with(attempt, ("peer", "keep"));
    pending.ephemeral = true;
    conn.direct_pending.insert(pid.into(), pending);
    conn.promotions
        .insert(pid.into(), PromoteState::new(PromoteRole::Lead));
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    let source = incoming.source_id().unwrap();
    conn.stash_upgrade_standby(pid, incoming.clone(), "direct-quic");
    let pending = conn.direct_pending.get(pid).expect("pending was consumed");
    assert_eq!(pending.attempt, attempt);
    assert_eq!(pending.secret, ("peer".to_string(), "keep".to_string()));
    assert!(!conn.pending_sources.contains_key(&source));
    assert!(conn.promotions[pid].attempt.is_none());
    assert!(incoming.is_dead());
}

/// promote_adopt_now must not mint a promotion token from a ready when no
/// upstream pending/promotion token exists.
#[tokio::test]
async fn promote_adopt_now_without_upstream_token_is_rejected() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-promo-adopt-none";
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    conn.promote_adopt_now(pid, incoming.clone(), "direct-quic");
    assert!(!conn.links.contains_key(pid));
    assert!(!conn.promotions.contains_key(pid));
    assert!(incoming.is_dead());
}

/// on_promote_standby requires the upstream token even when a promotion
/// record exists.
#[tokio::test]
async fn on_promote_standby_none_token_is_rejected() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-promo-standby-none";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", serving));
    conn.promotions
        .insert(pid.into(), PromoteState::new(PromoteRole::Lead));
    let incoming: Arc<dyn Transport> = Rec::new("incoming", &log);
    conn.on_promote_standby(pid, incoming.clone(), "direct-quic");
    assert!(conn.promotions[pid].standby.is_none());
    assert!(incoming.is_dead());
}

/// A duplicate upgrade carrying the active link transport is harmless.
#[tokio::test]
async fn upgrade_duplicate_is_harmless() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-upgrade-duplicate";
    let serving: Arc<dyn Transport> = Rec::new("serving", &log);
    let mut link = direct_link(pid, "peer", "peer", serving.clone());
    link.generation = 7;
    let attempt = serving.attempt_id().unwrap();
    link.attempt = Some(attempt);
    conn.links.insert(pid.into(), link);
    let mut probe = UpgradeProbe::armed();
    probe.token = Some(attempt);
    conn.resil.upgrade_probe.insert(pid.into(), probe);
    conn.perform_upgrade(pid, serving.clone(), "direct-quic").await;
    assert!(conn.links[pid]
        .transport
        .as_ref()
        .is_some_and(|live| Arc::ptr_eq(live, &serving)));
    assert_eq!(conn.links[pid].generation, 7);
    assert!(!serving.is_dead(), "duplicate upgrade closed the live link");
}

/// A race that won must not be expired or reaped while it waits beside the
/// serving link: the old cleanup dropped any pending whose peer had a link.
#[tokio::test]
async fn a_won_race_survives_the_deadline_and_the_linked_cleanup() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-parked";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let armed = armed_promotion(&mut conn, pid, PromoteRole::Follow, soon());
    let quic = Rec::with_attempt("quic", &log, armed);
    conn.stash_upgrade_standby(pid, quic, "direct-quic");
    conn.direct_pending.get_mut(pid).unwrap().deadline = Instant::now() - Duration::from_millis(1);
    assert!(conn.expired_direct().is_empty());
    assert!(conn.direct_pending.contains_key(pid), "the won race's pending was reaped");
    assert!(conn.promotions.get(pid).is_some_and(|s| s.has_standby()));
    assert!(!conn.link(pid).unwrap().direct, "the follower moved before it was asked");
}

/// The lead's half: the winner is held beside the serving link, the ask
/// goes out on the old path after the last frame, frames wait for the
/// answer, and the answer moves them to QUIC and installs the direct link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lead_moves_frames_to_quic_only_after_the_peer_answers() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-lead";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let armed = armed_promotion(&mut conn, pid, PromoteRole::Lead, soon());
    let stream = conn.transport_of(pid).unwrap(); // what a running stream_one holds
    stream.send_frame(1, 0, b"a").await.unwrap();
    let quic = Rec::with_attempt("quic", &log, armed);
    conn.stash_upgrade_standby(pid, quic.clone(), "direct-quic");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!conn.link(pid).unwrap().direct, "the serving link changed before the answer");
    let blocked = {
        let s = stream.clone();
        tokio::spawn(async move { s.send_frame(1, 1, b"b").await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rec_log(&log), vec!["webrtc:@0", "webrtc:path-promote"]);
    assert!(
        conn.on_promote_control(pid, &handoff::message(handoff::PATH_PROMOTED))
            .await
    );
    blocked.await.unwrap().unwrap();
    stream.send_control(&json!({ "type": "file-end" })).await.unwrap();
    assert_eq!(
        rec_log(&log),
        vec!["webrtc:@0", "webrtc:path-promote", "quic:@1", "quic:file-end"]
    );
    let l = conn.link(pid).unwrap();
    assert!(l.direct, "the direct link was not installed");
    assert!(Arc::ptr_eq(l.transport.as_ref().unwrap(), &(quic as Arc<dyn Transport>)));
    assert!(!l.trusted, "a ceremony-keyed direct link was born trusted");
    assert!(conn.is_active(pid), "the move released the transfer slot");
    assert!(conn.promotions.is_empty() && conn.direct_pending.is_empty());
}

/// The follower's half: asked before its own race finished, it moves when
/// the race wins, answering on the serving path and handing the direct
/// link to the loop's DirectReady arm, whose adoption replaces the WebRTC
/// link in one step.
#[tokio::test]
async fn the_follower_moves_when_asked_and_its_race_wins() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-follow";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let armed = armed_promotion(&mut conn, pid, PromoteRole::Follow, soon());
    assert!(
        conn.on_promote_control(pid, &handoff::message(handoff::PATH_PROMOTE))
            .await
    );
    assert!(rec_log(&log).is_empty(), "answered before it had a direct link");
    let quic = Rec::with_attempt("quic", &log, armed);
    conn.stash_upgrade_standby(pid, quic.clone(), "direct-quic");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rec_log(&log), vec!["webrtc:path-promoted"]);
    let mut ready = None;
    while let Ok(ev) = rx.try_recv() {
        if let Ev::DirectReady(p, t, route) = ev {
            ready = Some((p, t, route));
        }
    }
    let (p, t, route) = ready.expect("the direct link was not handed to the loop");
    assert_eq!(p, pid);
    // The expiry tick between the hand-over and the arm must not reap the
    // pending the adoption needs.
    conn.direct_pending.get_mut(pid).unwrap().deadline = Instant::now() - Duration::from_millis(1);
    assert!(conn.expired_direct().is_empty());
    assert!(conn.links.contains_key(pid), "the peer had no link before its successor");
    assert!(conn
        .direct_pending
        .get(pid)
        .is_some_and(|pending| pending.attempt == t.attempt_id().unwrap()));
    conn.adopt_direct(&p, t, route);
    let l = conn.link(pid).unwrap();
    assert!(l.direct && !l.trusted);
    assert!(Arc::ptr_eq(l.transport.as_ref().unwrap(), &(quic as Arc<dyn Transport>)));
    assert!(conn.is_active(pid));
    assert!(conn.promotions.is_empty() && conn.direct_pending.is_empty());
}

/// No direct link at this end: the ask is declined at once; asked with a
/// race still running that then loses, the decline comes at its deadline.
/// Either way the receiver never leaves WebRTC.
#[tokio::test]
async fn a_follower_without_a_direct_link_declines() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    code_link(&mut conn, "sid-none", Rec::new("webrtc", &log));
    assert!(
        conn.on_promote_control("sid-none", &handoff::message(handoff::PATH_PROMOTE))
            .await
    );
    assert_eq!(rec_log(&log), vec!["webrtc:path-declined"]);

    let log2 = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-racing";
    code_link(&mut conn, pid, Rec::new("webrtc", &log2));
    armed_promotion(&mut conn, pid, PromoteRole::Follow, soon());
    let _ = conn
        .on_promote_control(pid, &handoff::message(handoff::PATH_PROMOTE))
        .await;
    conn.direct_pending.get_mut(pid).unwrap().deadline = Instant::now() - Duration::from_millis(1);
    assert!(conn.expired_direct().is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rec_log(&log2), vec!["webrtc:path-declined"]);
    assert!(!conn.link(pid).unwrap().direct);
    assert!(conn.promotions.is_empty() && conn.direct_pending.is_empty());
}

/// The lead stays on WebRTC when the peer declines, and its frames, held
/// for the round trip, resume there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_handoff_resumes_on_webrtc() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-declined";
    code_link(&mut conn, pid, Rec::new("webrtc", &log));
    let armed = armed_promotion(&mut conn, pid, PromoteRole::Lead, soon());
    let stream = conn.transport_of(pid).unwrap();
    let quic = Rec::with_attempt("quic", &log, armed);
    conn.stash_upgrade_standby(pid, quic, "direct-quic");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let held = {
        let s = stream.clone();
        tokio::spawn(async move { s.send_frame(1, 0, b"a").await })
    };
    assert!(
        conn.on_promote_control(pid, &handoff::message(handoff::PATH_DECLINED))
            .await
    );
    held.await.unwrap().unwrap();
    assert_eq!(rec_log(&log), vec!["webrtc:path-promote", "webrtc:@0"]);
    assert!(!conn.link(pid).unwrap().direct);
    assert!(conn.promotions.is_empty() && conn.direct_pending.is_empty());
}

/// A finished receive does not wait out the deferral for a sender that has
/// left: the deferral protects a transfer still in flight, and there is
/// none. Mid-transfer the deferral is unchanged.
#[tokio::test]
async fn a_completed_receive_does_not_defer_the_departed_sender() {
    let (mut conn, _far, _rx) = test_conn().await;
    let pid = "sid-sender";
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", FakeQuic::flowing()));
    conn.recv_done = false;
    assert!(!conn.on_peer_left(&json!({ "id": pid })) && conn.links.contains_key(pid));
    assert!(conn.deferred_left.contains_key(pid), "a mid-transfer departure was not deferred");
    conn.recv_done = true;
    conn.on_peer_left(&json!({ "id": pid }));
    assert!(!conn.links.contains_key(pid), "a completed receive deferred its departed sender");
}

/// A control the transport already READ, but the loop had not forwarded
/// yet when the peer's signaling departure arrived, must still be
/// dispatched. The departure waits behind it (one turn) instead of deleting
/// its queue with the link. This is the minimum-forget/decline-then-leave
/// race, deterministically: pre-fix the departure drops the link first and
/// `stage_event` never sees the control.
#[tokio::test]
async fn a_queued_control_is_dispatched_before_the_departed_link_is_dropped() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-leave-with-control";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid })), "a queued departure was taken as immediate");
    assert!(conn.links.contains_key(pid), "the link died before its queued control was dispatched");
    let control = rx.try_recv().expect("the queued control was not forwarded");
    let (inner, seen) = conn.stage_event(control).expect("the queued control was dropped");
    assert!(
        matches!(inner, Ev::Control(_, ref v)
            if v["type"].as_str() == Some("access-decline")),
        "a different event was dispatched"
    );
    assert_eq!(seen, Some(source), "the control lost its provenance");
    assert!(conn.links.contains_key(pid), "dispatching the control dropped the link");
    // A duplicate room signal while the barrier is queued must not finalize
    // on the now-empty local queue and beat the barrier.
    assert!(
        !conn.on_peer_left(&json!({ "id": pid })),
        "a duplicate departure finalized ahead of its barrier"
    );
    assert!(conn.links.contains_key(pid), "a duplicate departure dropped the link early");
    let barrier = rx.try_recv().expect("no departure barrier was queued behind the control");
    let payload = match conn.stage_event(barrier) {
        Some((Ev::PeerLeft(payload), seen)) => {
            assert_eq!(seen, Some(source), "the barrier lost its provenance");
            payload
        }
        _ => panic!("the barrier was not dispatched as an ordinary room departure"),
    };
    // The caller gets the normal bool: the handed-over control already ran,
    // and the departure still reports the active link.
    assert!(
        conn.on_peer_left(&payload),
        "the barrier no longer reports the active departure"
    );
    assert!(!conn.links.contains_key(pid), "the barrier did not finish the departure");
    // The drop's own tombstone is all that is left; nothing that could act on
    // the departed link survives it.
    let rest: Vec<Ev> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        !rest.iter().any(|e| matches!(e, Ev::Sourced { inner, .. }
            if matches!(inner.as_ref(), Ev::PeerLeft(_) | Ev::Control(..)))),
        "a departure or control leaked past the drop"
    );
    assert!(
        rest.iter().all(|e| matches!(e, Ev::AttemptDrained(_))),
        "unexpected events after the drop"
    );
    // Even a frame queued behind the barrier cannot be processed afterwards.
    let _ = conn.tx.send(Ev::Sourced {
        pid: pid.into(),
        source,
        inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
    });
    assert!(
        conn.stage_event(rx.try_recv().expect("the late frame was not queued")).is_none(),
        "a frame behind the barrier was processed after the drop"
    );
}

/// The barrier is tied to the exact link that departed. A newer authorized
/// link adopted for the same pid before the queue drains is not the link it
/// names, so the stale barrier rejects itself and the successor survives -
/// and the departed source's own control is not revived onto it.
#[tokio::test]
async fn a_departure_barrier_cannot_drop_a_replacement_link() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-leave-replaced";
    let old = Rec::new("webrtc", &log);
    let old_source = old.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), delegated_link(pid, old));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source: old_source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid })));
    let successor = Rec::new("direct", &log);
    let successor_source = successor.source_id().expect("fixture transport has a source");
    let mut replacement = relay_link(pid, "peer", "peer", successor);
    replacement.generation = 8;
    conn.links.insert(pid.into(), replacement);

    assert!(conn.stage_event(rx.try_recv().unwrap()).is_none(), "a departed source's control was revived");
    assert!(conn.stage_event(rx.try_recv().unwrap()).is_none(), "the stale barrier was dispatched");
    assert!(
        conn.link(pid).is_some_and(|l| l.source == successor_source && l.generation == 8),
        "the stale departure dropped the replacement link"
    );
}

/// Nothing queued: the departure is still immediate and still reports the
/// active link, exactly as before the queue-drain was added.
#[tokio::test]
async fn a_departure_with_nothing_queued_still_drops_the_link_at_once() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-leave-immediate";
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", Rec::new("webrtc", &log)));
    conn.bind_active(pid);
    let (_queue, queued) = tokio::sync::mpsc::unbounded_channel();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );
    assert!(conn.on_peer_left(&json!({ "id": pid })), "an idle departure stopped reporting the active link");
    assert!(!conn.links.contains_key(pid), "the departure did not drop the link");
    // The drop may queue its own retirement tombstone; it must not queue a
    // barrier or any control that could act on the gone link.
    let after = drained(&mut rx);
    assert!(!after.iter().any(is_barrier_or_control), "an empty queue still produced a barrier");
    assert!(after.iter().all(|e| matches!(e, Ev::AttemptDrained(_))), "unexpected events after the drop");
}

/// A link that is still moving bytes keeps the pre-existing deferral: the
/// queue belongs to a live channel, so it is left for `pump_builds` and no
/// departure barrier is queued.
#[tokio::test]
async fn a_flowing_link_keeps_the_old_deferral_even_with_queued_events() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let pid = "sid-leave-flowing";
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", FakeQuic::flowing()));
    conn.bind_active(pid);
    let source = net::SourceId::next();
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid })));
    assert!(conn.links.contains_key(pid), "a flowing link was dropped on departure");
    assert!(conn.deferred_left.contains_key(pid), "the flowing deferral stopped recording the leave");
    assert!(rx.try_recv().is_err(), "a flowing link's departure was queued as a barrier");
    let still_queued = conn
        .link_events
        .get(pid)
        .expect("the flowing link lost its event stream")
        .rx
        .lock()
        .unwrap()
        .try_recv()
        .is_ok();
    assert!(still_queued, "the flowing path consumed the queued events early");
}

/// The exact authz a temporary-access/service-offer guest carries: delegated
/// (ephemeral), never a standing device.
fn delegated_link(pid: &str, t: Arc<dyn Transport>) -> Link {
    let mut l = relay_link(pid, "guest", "guest", t);
    l.principal_kind = PrincipalKind::Delegated { caps: Vec::new() };
    l.trusted = false;
    l
}

/// The diagnosed temporary-access decline: the guest sends `access-decline`
/// and its signaling socket closes in the same breath. The frame is already
/// read, but the host's per-link queue has not forwarded it when peer-left
/// arrives. Pre-fix the delegated drop removes the link and the queue, so
/// the host never sees the decline. Here it is staged `Some` before the
/// enrollment ends, and the enrollment still ends (no rejoin window).
#[tokio::test]
async fn a_delegated_link_hands_its_queued_decline_over_before_its_enrollment_ends() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-temporary-guest";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), delegated_link(pid, t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(
        !conn.on_peer_left(&json!({ "id": pid })),
        "a delegated departure was reported as a rejoinable leave"
    );
    assert!(
        conn.links.contains_key(pid),
        "the delegated link died before its queued decline was handed over"
    );
    let control = rx.try_recv().expect("the queued decline was destroyed with the link");
    let (inner, seen) = conn.stage_event(control).expect("the delegated decline was not dispatched");
    assert!(
        matches!(inner, Ev::Control(_, ref v) if v["type"].as_str() == Some("access-decline")),
        "the delegated link dispatched something other than the decline"
    );
    assert_eq!(seen, Some(source), "the decline lost its provenance");
    let barrier = rx.try_recv().expect("no departure barrier followed the decline");
    let payload = match conn.stage_event(barrier) {
        Some((Ev::PeerLeft(payload), seen)) => {
            assert_eq!(seen, Some(source), "the delegated barrier lost its provenance");
            payload
        }
        _ => panic!("the delegated barrier was not dispatched as a room departure"),
    };
    assert!(
        !conn.on_peer_left(&payload),
        "the delegated departure reported a rejoinable leave"
    );
    assert!(!conn.links.contains_key(pid), "the delegated enrollment did not end");
    assert!(
        !conn.deferred_left.contains_key(pid),
        "a delegated departure was made rejoinable"
    );
}

/// A forced (reap/revoked) departure must never hand over queued control:
/// there is no authenticated live link left to act on it. The drop stays
/// immediate, the source's queue dies with it, and its tags are dead.
#[tokio::test]
async fn a_forced_delegated_departure_never_processes_queued_control() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-temporary-revoked";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), delegated_link(pid, t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-accept" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid, "__fil_force_drop": true })));
    assert!(!conn.links.contains_key(pid), "a forced departure was retained");
    assert!(!conn.link_events.contains_key(pid), "the forced departure kept the source's queue");
    // Forced teardown queues no hand-over: only its own retirement
    // tombstone may appear, never queued control or a barrier.
    let after = drained(&mut rx);
    assert!(!after.iter().any(is_barrier_or_control), "a forced departure queued a handover barrier");
    assert!(after.iter().all(|e| matches!(e, Ev::AttemptDrained(_))), "unexpected events after the forced drop");
    let stale = Ev::Sourced {
        pid: pid.into(),
        source,
        inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-accept" }))),
    };
    assert!(conn.stage_event(stale).is_none(), "a force-dropped source's control was revived");
}

fn drained(rx: &mut mpsc::UnboundedReceiver<Ev>) -> Vec<Ev> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

/// A departure barrier or a control that could act on a link. Tombstones
/// (`AttemptDrained`) are teardown bookkeeping, not retained authority.
fn is_barrier_or_control(ev: &Ev) -> bool {
    match ev {
        Ev::Sourced { inner, .. } => matches!(inner.as_ref(), Ev::PeerLeft(_) | Ev::Control(..)),
        Ev::PeerLeft(_) => true,
        _ => false,
    }
}

/// A barrier that `stage_event` already validated is bound to the exact
/// link. If that link is replaced before the ordinary handler runs, the
/// marker must die with it: no cleanup of the successor, no rejoin window,
/// no drop of newer authority.
#[tokio::test]
async fn a_validated_departure_marker_dies_with_its_link_not_the_successor() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-marker-replaced";
    let old = Rec::new("webrtc", &log);
    let old_source = old.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), delegated_link(pid, old));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source: old_source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );
    assert!(!conn.on_peer_left(&json!({ "id": pid })));
    let _ = rx.try_recv().expect("the queued control was not handed over");
    let payload = match conn.stage_event(rx.try_recv().expect("no barrier")) {
        Some((Ev::PeerLeft(payload), _)) => payload,
        _ => panic!("the barrier was not dispatched as a room departure"),
    };
    assert!(
        conn.link_events.get(pid).is_some_and(|e| e.departure_ready == Some(old_source)),
        "the validated barrier did not record its once-only marker"
    );

    let successor = Rec::new("direct", &log);
    let successor_source = successor.source_id().expect("fixture transport has a source");
    let mut replacement = relay_link(pid, "peer", "peer", successor);
    replacement.generation = 8;
    conn.links.insert(pid.into(), replacement);

    assert!(
        !conn.on_peer_left(&payload),
        "a stale marker reported the successor's departure"
    );
    assert!(
        conn.link(pid).is_some_and(|l| l.source == successor_source && l.generation == 8),
        "a stale marker dropped the replacement link"
    );
    assert!(
        conn.link_events.get(pid).is_some_and(|e| e.departure_ready.is_none()),
        "the stale marker survived its link"
    );
}

/// A concurrent producer must not turn the hand-over into an event-loop
/// stall: the batch is capped at the existing per-link event budget, and an
/// over-budget queue fails closed (drop now) instead of retaining or
/// retrying. The already-forwarded prefix is dead because the link is gone.
#[tokio::test]
async fn an_over_budget_queue_fails_closed_without_a_hand_over() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-leave-over-budget";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..MAX_BUILD_EVENTS + 1 {
        queue
            .send(Ev::Sourced {
                pid: pid.into(),
                source,
                inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
            })
            .unwrap();
    }
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(
        conn.on_peer_left(&json!({ "id": pid })),
        "the over-budget departure did not run the ordinary finalizer"
    );
    assert!(!conn.links.contains_key(pid), "an over-budget queue retained the link");
    let forwarded = drained(&mut rx);
    assert!(
        !forwarded.iter().any(|e| matches!(e, Ev::Sourced { inner, .. }
            if matches!(inner.as_ref(), Ev::PeerLeft(_)))),
        "an over-budget queue still queued a barrier"
    );
    assert_eq!(
        forwarded
            .iter()
            .filter(|e| matches!(e, Ev::Sourced { inner, .. }
                if matches!(inner.as_ref(), Ev::Control(..))))
            .count(),
        MAX_BUILD_EVENTS,
        "the hand-over was not capped at the per-link event budget"
    );
    let first = forwarded
        .into_iter()
        .find(|e| matches!(e, Ev::Sourced { inner, .. }
            if matches!(inner.as_ref(), Ev::Control(..))))
        .expect("the capped prefix is missing");
    assert!(
        conn.stage_event(first).is_none(),
        "an over-budget hand-over prefix was processed after the drop"
    );
}

/// A force/revoked order arriving while a hand-over barrier is QUEUED must
/// tear down immediately: both markers are cleared, the link drops, and the
/// already-handed-over control and the barrier itself fail the source gate.
#[tokio::test]
async fn a_forced_departure_beats_a_pending_barrier() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-force-after-pending";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid })));
    assert!(
        conn.link_events.get(pid).is_some_and(|e| e.departure_pending == Some(source)),
        "the barrier was not recorded as pending"
    );
    assert!(
        conn.on_peer_left(&json!({ "id": pid, "__fil_force_drop": true })),
        "a forced departure did not run the ordinary finalizer immediately"
    );
    assert!(!conn.links.contains_key(pid), "a forced departure was deferred behind its barrier");
    assert!(!conn.link_events.contains_key(pid), "the forced departure kept the link's markers");
    let control = rx.try_recv().expect("the hand-over prefix is missing");
    assert!(
        conn.stage_event(control).is_none(),
        "an old control was processed after the forced drop"
    );
    let barrier = rx.try_recv().expect("the barrier is missing");
    assert!(
        matches!(&barrier, Ev::Sourced { inner, .. } if matches!(inner.as_ref(), Ev::PeerLeft(_))),
        "the queued follow-up was not the barrier"
    );
    assert!(
        conn.stage_event(barrier).is_none(),
        "the queued barrier survived the forced drop"
    );
    let after = drained(&mut rx);
    assert!(
        after.iter().all(|e| matches!(e, Ev::AttemptDrained(_))),
        "unexpected events after the forced drop"
    );
}

/// A force/revoked order arriving between `stage_event` validating the
/// barrier (ready marker set) and the caller invoking `on_peer_left` must
/// still be immediate; the validated marker cannot resurrect the drop.
#[tokio::test]
async fn a_forced_departure_beats_an_already_validated_barrier() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-force-after-ready";
    let t = Rec::new("webrtc", &log);
    let source = t.source_id().expect("fixture transport has a source");
    conn.links.insert(pid.into(), relay_link(pid, "peer", "peer", t));
    conn.bind_active(pid);
    let (queue, queued) = tokio::sync::mpsc::unbounded_channel();
    queue
        .send(Ev::Sourced {
            pid: pid.into(),
            source,
            inner: Box::new(Ev::Control(pid.into(), json!({ "type": "access-decline" }))),
        })
        .unwrap();
    conn.link_events.insert(
        pid.into(),
        LinkEvents { generation: 7, rx: std::sync::Mutex::new(queued), departure_ready: None, departure_pending: None },
    );

    assert!(!conn.on_peer_left(&json!({ "id": pid })));
    let _ = rx.try_recv().expect("the queued control was not handed over");
    let payload = match conn.stage_event(rx.try_recv().expect("no barrier")) {
        Some((Ev::PeerLeft(payload), _)) => payload,
        _ => panic!("the barrier was not dispatched as a room departure"),
    };
    assert!(
        conn.link_events.get(pid).is_some_and(|e| e.departure_ready == Some(source)),
        "the validated barrier did not record its marker"
    );

    assert!(
        conn.on_peer_left(&json!({ "id": pid, "__fil_force_drop": true })),
        "a forced departure behind a validated barrier was not immediate"
    );
    assert!(!conn.links.contains_key(pid), "the validated marker blocked the forced drop");
    assert!(!conn.link_events.contains_key(pid), "the forced departure kept the validated marker");
    assert!(
        !conn.on_peer_left(&payload),
        "the validated barrier re-reported a link the forced drop already removed"
    );
    assert!(!conn.links.contains_key(pid), "the forced drop left the link behind");
}

/// The serving link died while the race ran: there is nothing to hand off
/// from, so the winner is adopted at once, as the promotion always did.
#[tokio::test]
async fn a_winner_with_no_serving_link_is_adopted_at_once() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pid = "sid-dead";
    let webrtc = Rec::new("webrtc", &log);
    code_link(&mut conn, pid, webrtc.clone());
    let armed = armed_promotion(&mut conn, pid, PromoteRole::Lead, soon());
    webrtc.alive.store(false, Ordering::Relaxed);
    conn.stash_upgrade_standby(pid, Rec::with_attempt("quic", &log, armed), "direct-quic");
    let readied = std::iter::from_fn(|| rx.try_recv().ok())
        .any(|ev| matches!(ev, Ev::DirectReady(ref p, _, _) if p == pid));
    assert!(readied, "the winner was not adopted");
    assert!(rec_log(&log).is_empty(), "a handoff was attempted over a dead path");
}

/// Cross-dial regression: an inbound WebRTC candidate for the current pair
/// secret must keep the channel the peer is answering, and a redundant
/// outbound establish must not delete it or strand the live serving link.
///
/// Deterministic: the candidate/install states are constructed directly, so
/// no ICE, STUN or timing is involved. What is asserted is the scheduling
/// rule and the readiness gate, not a network race.
#[tokio::test]
async fn a_binding_claim_joins_the_answered_candidate_and_reannounces_the_serving_link() {
    let host = Arc::new(TestHost {
        devices: vec![("boxb".to_string(), "pair-secret".to_string())],
        ..TestHost::default()
    });
    let (mut conn, _far, mut rx) = test_conn_with_host(host).await;
    // Keep generated intents above the generations this test names by hand,
    // exactly as the monotonic allocator does in production.
    conn.next_gen = 100;
    let pid = "sid-b";
    let info = json!({ "id": pid, "name": "boxb", "uid": "uid-b" });

    // 1. The inbound responder candidate the peer is answering: it is
    //    building and carries no binding yet.
    let gen1: u32 = 11;
    conn.current_intent.insert(pid.to_string(), gen1);
    conn.builds.insert(pid.to_string(), build_state(gen1));
    conn.note_binding(pid, ("boxb".into(), "pair-secret".into()));
    let plan = conn
        .prepare_build(info.clone(), Some(true), std::panic::Location::caller(), Replace::NeverLive)
        .expect("prepare");
    assert!(plan.is_none(), "the binding claim minted a rival candidate");
    assert_eq!(conn.current_intent[pid], gen1, "the answered candidate was retired");
    assert_eq!(
        conn.builds[pid].binding.as_ref().map(|(_, s)| s.as_str()),
        Some("pair-secret"),
        "the retained candidate did not take the claim"
    );

    // 2. That candidate installs: live transport, active target, but its
    //    readiness was already consumed while it was still unbound.
    conn.builds.clear();
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let serving = Rec::new("serving", &log);
    let serving_arc: Arc<dyn Transport> = serving.clone();
    let serving_source = serving.source.expect("fixture source");
    let mut link = relay_link(pid, "boxb", "boxb", serving_arc.clone());
    link.source = serving_source;
    link.expected_secret = None;
    conn.links.insert(pid.to_string(), link);
    conn.active = Some(pid.to_string());

    // A redundant known-target adoption on that live link reuses it: the
    // establish is skipped (a link exists), so the claim must land HERE and
    // the serving transport must be re-announced with its own immutable
    // source, or the target slot can never be taken.
    let adopted = conn
        .maybe_adopt(&json!({ "id": pid, "name": "boxb", "uid": "uid-b" }), true)
        .await
        .expect("adopt");
    assert!(adopted, "the live target was not adopted");
    assert_eq!(
        conn.links[pid].expected_secret.as_ref().map(|(_, s)| s.as_str()),
        Some("pair-secret"),
        "the live serving link never took the claim"
    );
    match conn.stage_event(rx.try_recv().expect("the serving link was not re-announced")) {
        Some((Ev::ChannelReady(got, t), Some(seen))) => {
            assert_eq!(got, pid);
            assert!(Arc::ptr_eq(&t, &serving_arc), "a different transport was announced");
            assert_eq!(seen, serving_source, "readiness lost its build source");
        }
        _ => panic!("the source-tagged readiness of the serving link was rejected"),
    }
    // A second claim is a no-op: an already-bound serving link is never
    // re-announced, so steady roster ticks cannot re-offer on it.
    let plan = conn
        .prepare_build(info.clone(), Some(true), std::panic::Location::caller(), Replace::NeverLive)
        .expect("prepare");
    assert!(plan.is_none(), "a redundant establish beat a live serving link");
    assert!(rx.try_recv().is_err(), "a bound serving link was re-announced");
    // The same Arc keeps serving, and it is still the active target.
    conn.mark_ready(pid, &serving_arc, false);
    assert!(conn.links[pid]
        .transport
        .as_ref()
        .is_some_and(|t| Arc::ptr_eq(t, &serving_arc)));
    assert!(conn.is_active(pid));
    serving_arc.send_control(&json!({ "type": "ping" })).await.unwrap();
    assert!(rec_log(&log).contains(&"serving:ping".to_string()));

    // 3. A concurrent redundant outbound candidate completes with the SAME
    //    authorized binding: it must not replace the live serving Arc.
    let redundant_source = net::SourceId::next();
    let peer = net::Peer::connect(
        pid.to_string(),
        conn.my_uid.clone(),
        true,
        Vec::new(),
        false,
        conn.sio.clone(),
        conn.tx.clone(),
        12,
    )
    .await
    .expect("local candidate");
    conn.builds.insert(pid.to_string(), build_state(12));
    conn.current_intent.insert(pid.to_string(), 12);
    conn.apply_built_peer(BuiltPeer {
        peer_id: pid.to_string(),
        generation: 12,
        source: redundant_source,
        peer,
        info: info.clone(),
        name: "boxb".to_string(),
        uid: Some("uid-b".to_string()),
        carried_secret: Some(("boxb".into(), "pair-secret".into())),
        active_on_apply: true,
        replace: Replace::NeverLive,
        caller: std::panic::Location::caller(),
        prior_generation: Some(gen1),
    });
    assert!(conn.builds.is_empty(), "the refused candidate held its slot");
    assert_eq!(conn.links[pid].source, serving_source, "the serving source was replaced");
    assert!(
        conn.links[pid]
            .transport
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(t, &serving_arc)),
        "a redundant completion replaced the serving transport"
    );

    // 4. A real replacement still happens, and then the OLD source must be
    //    refused while the replacement's own source is accepted.
    let replacement = Rec::new("replacement", &log);
    let replacement_arc: Arc<dyn Transport> = replacement.clone();
    let replacement_source = replacement.source.expect("fixture source");
    let peer2 = net::Peer::connect(
        pid.to_string(),
        conn.my_uid.clone(),
        true,
        Vec::new(),
        false,
        conn.sio.clone(),
        conn.tx.clone(),
        13,
    )
    .await
    .expect("local replacement candidate");
    conn.install_built(
        BuiltPeer {
            peer_id: pid.to_string(),
            generation: 13,
            source: replacement_source,
            peer: peer2,
            info: info.clone(),
            name: "boxb".to_string(),
            uid: Some("uid-b".to_string()),
            carried_secret: Some(("boxb".into(), "new-secret".into())),
            active_on_apply: true,
            replace: Replace::NeverLive,
            caller: std::panic::Location::caller(),
            prior_generation: Some(12),
        },
        std::collections::VecDeque::new(),
        std::collections::VecDeque::new(),
        Some(("boxb".into(), "new-secret".into())),
        false,
    );
    assert_eq!(conn.links[pid].source, replacement_source);
    assert!(conn.stage_event(Ev::Sourced {
        pid: pid.to_string(),
        source: serving_source,
        inner: Box::new(Ev::ChannelReady(pid.to_string(), serving_arc.clone())),
    })
    .is_none(), "the replaced link's source reopened it");
    assert!(
        conn.stage_event(Ev::sourced_channel_ready(pid.to_string(), replacement_arc)).is_some(),
        "the replacement's own readiness was refused"
    );

    // 5. A changed, still-authorized binding is a real re-pair: it must
    //    still supersede an in-flight candidate bound to a revoked one.
    let other = "sid-repair";
    let mut stale = build_state(21);
    stale.binding = Some(("boxb".into(), "old-secret".into()));
    conn.builds.insert(other.to_string(), stale);
    conn.current_intent.insert(other.to_string(), 21);
    conn.revoked_bindings.insert("old-secret".into());
    conn.note_binding(other, ("boxb".into(), "pair-secret".into()));
    let plan = conn
        .prepare_build(
            json!({ "id": other, "name": "boxb", "uid": "uid-b" }),
            Some(true),
            std::panic::Location::caller(),
            Replace::NeverLive,
        )
        .expect("prepare");
    assert!(plan.is_some(), "a changed authorized binding could not replace");
    assert!(!conn.builds.contains_key(other), "the revoked-bound candidate survived");
}

/// A transport for the revoked-link closer: it records each control it
/// writes and each close, carries a real source (so an ack can be bound
/// to it), and can be told to never complete a write (a frozen peer) or
/// to fail every write (a transport already gone).
struct RefusalT {
    source: net::SourceId,
    sent: std::sync::Mutex<Vec<Value>>,
    closes: AtomicUsize,
    hang: bool,
    fail: bool,
    dead: AtomicBool,
}
fn refusal_t(hang: bool) -> Arc<RefusalT> {
    Arc::new(RefusalT {
        source: net::SourceId::next(),
        sent: std::sync::Mutex::new(Vec::new()),
        closes: AtomicUsize::new(0),
        hang,
        fail: false,
        dead: AtomicBool::new(false),
    })
}
fn failing_refusal_t() -> Arc<RefusalT> {
    Arc::new(RefusalT {
        source: net::SourceId::next(),
        sent: std::sync::Mutex::new(Vec::new()),
        closes: AtomicUsize::new(0),
        hang: false,
        fail: true,
        dead: AtomicBool::new(false),
    })
}
#[async_trait::async_trait]
impl Transport for RefusalT {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.fail {
            anyhow::bail!("channel closed");
        }
        self.sent.lock().unwrap().push(msg.clone());
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
    fn force_close(&self) {
        self.closes.fetch_add(1, Ordering::Relaxed);
    }
    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn source_id(&self) -> Option<net::SourceId> {
        Some(self.source)
    }
}

fn refusal() -> Value {
    json!({ "type": "link-revoked", "reason": "forgotten" })
}

/// The nonce of the `link-revoked` the closer task wrote, once it has.
async fn written_refusal_nonce(t: &RefusalT) -> String {
    for _ in 0..100 {
        if let Some(v) = t.sent.lock().unwrap().first() {
            assert_eq!(v["type"], "link-revoked", "the refusal is the first frame");
            assert_eq!(v["reason"], "forgotten", "the refusal keeps its reason");
            return v["nonce"].as_str().expect("the refusal carries a nonce").to_string();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the closer never wrote the refusal");
}

fn revoked_ack(pid: &str, source: net::SourceId, nonce: &str) -> Ev {
    Ev::Sourced {
        pid: pid.to_string(),
        source,
        inner: Box::new(Ev::Control(
            pid.to_string(),
            json!({ "type": "link-revoked-ack", "nonce": nonce }),
        )),
    }
}

async fn closed_within(t: &RefusalT, bound: Duration) -> bool {
    let until = Instant::now() + bound;
    while Instant::now() < until {
        if t.closes.load(Ordering::Relaxed) > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    t.closes.load(Ordering::Relaxed) > 0
}

/// An installed WebRTC link's event stream, as `apply_built_peer` leaves it.
fn own_stream(conn: &mut Conn, pid: &str, generation: u32) -> mpsc::UnboundedSender<Ev> {
    let (etx, erx) = mpsc::unbounded_channel();
    conn.link_events.insert(
        pid.to_string(),
        LinkEvents {
            generation,
            rx: std::sync::Mutex::new(erx),
            departure_ready: None,
            departure_pending: None,
        },
    );
    etx
}

/// F1 (daemon-path gate): a write returning Ok is not delivery, and the
/// close discards what is still queued. The revoked link leaves routing at
/// once, but its transport closes only on the peer's ack for THIS cut,
/// bound by NONCE only (pid plus nonce): a stale nonce, or the right nonce
/// for another pid, does nothing, while the right nonce for this pid counts
/// from any source. This is the main-queue path (a link with no candidate
/// stream).
#[tokio::test]
async fn a_revoked_link_closes_on_the_peers_ack_and_not_before() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-r".into(), direct_link("sid-r", "b", "user@b", t.clone()));
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-r", refusal()));
    assert!(!conn.links.contains_key("sid-r"), "the cut link stayed routable");
    let nonce = written_refusal_nonce(&t).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(t.closes.load(Ordering::Relaxed), 0, "closed before the peer acked");
    assert!(conn.stage_event(revoked_ack("sid-r", t.source, "not-this-cut")).is_none());
    assert!(conn.stage_event(revoked_ack("sid-x", t.source, &nonce)).is_none());
    assert_eq!(conn.closing.len(), 1, "a stale nonce or another pid completed the cut");
    assert!(!closed_within(&t, Duration::from_millis(100)).await, "closed on a stale ack");
    // The peer may answer on another path of the same session (its primary
    // after a promotion, a worker): the nonce binds it, not the source.
    assert!(
        conn.stage_event(revoked_ack("sid-r", net::SourceId::next(), &nonce)).is_none(),
        "the ack authorizes nothing and is never dispatched"
    );
    assert!(conn.closing.is_empty(), "the matching ack did not complete the cut");
    assert!(closed_within(&t, Duration::from_millis(500)).await, "not closed after the ack");
    assert!(
        start.elapsed() < REFUSAL_ACK_BUDGET,
        "closed by the budget, not by the ack ({:?})",
        start.elapsed()
    );
}

/// The path the first version missed: a link built by `apply_built_peer`
/// (a WebRTC DataChannel link) delivers ONLY on its own candidate stream,
/// which the loop drains once per turn (up to 2 s on an idle daemon). The
/// closer reads that stream itself, so the ack closes the link with no
/// loop turn at all: nothing here calls `pump_builds` or `stage_event`.
/// Nothing else read from the cut link is forwarded.
#[tokio::test]
async fn a_cut_links_own_stream_ack_needs_no_loop_turn() {
    let (mut conn, _far, mut rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-e".into(), direct_link("sid-e", "b", "user@b", t.clone()));
    let etx = own_stream(&mut conn, "sid-e", 7);
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-e", refusal()));
    assert_eq!(conn.closing.len(), 1, "the main-queue path is watched as well");
    let nonce = written_refusal_nonce(&t).await;
    let _ = etx.send(Ev::Sourced {
        pid: "sid-e".into(),
        source: t.source,
        inner: Box::new(Ev::Control("sid-e".into(), json!({ "type": "exec-close", "sid": 1 }))),
    });
    let _ = etx.send(revoked_ack("sid-e", t.source, "not-this-cut"));
    let _ = etx.send(revoked_ack("sid-x", t.source, &nonce));
    assert!(!closed_within(&t, Duration::from_millis(150)).await, "closed on a stale ack");
    let _ = etx.send(revoked_ack("sid-e", t.source, &nonce));
    assert!(closed_within(&t, Duration::from_millis(300)).await, "not closed after the ack");
    assert!(start.elapsed() < REFUSAL_ACK_BUDGET, "closed by the budget, not by the ack");
    while let Ok(ev) = rx.try_recv() {
        if let Ev::Sourced { pid, .. } = &ev {
            assert_ne!(pid, "sid-e", "an event from the cut link was forwarded");
        }
    }
}

/// The cut link's reader ended (its stream's sender dropped) on a dead
/// transport: no ack can arrive on any path, so the closer closes at once,
/// not at the budget.
#[tokio::test]
async fn a_cut_link_whose_reader_ended_closes_at_once() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-d".into(), direct_link("sid-d", "b", "user@b", t.clone()));
    let etx = own_stream(&mut conn, "sid-d", 7);
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-d", refusal()));
    let _ = written_refusal_nonce(&t).await;
    t.dead.store(true, Ordering::Relaxed);
    drop(etx);
    assert!(closed_within(&t, Duration::from_millis(500)).await, "left open after the reader ended");
    assert!(start.elapsed() < REFUSAL_ACK_BUDGET, "waited out the budget for a dead reader");
}

/// The branch the two-link fix relies on: a cut link with its OWN stream
/// whose reader ends while the transport is still alive (the peer answers
/// on another path of the same session). The closer must keep waiting,
/// and the ack for the SAME nonce from a DIFFERENT source, delivered
/// through the main queue, completes the cut. Fails if the stream's end
/// stopped the wait unconditionally, or if the main-queue signal were not
/// registered alongside the stream.
#[tokio::test]
async fn an_ack_on_another_path_completes_a_cut_whose_own_stream_ended() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-s".into(), direct_link("sid-s", "b", "user@b", t.clone()));
    let etx = own_stream(&mut conn, "sid-s", 7);
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-s", refusal()));
    let nonce = written_refusal_nonce(&t).await;
    drop(etx);
    assert!(
        !closed_within(&t, Duration::from_millis(300)).await,
        "the stream's end on a live transport stopped the wait"
    );
    assert!(
        conn.stage_event(revoked_ack("sid-s", net::SourceId::next(), &nonce)).is_none(),
        "the ack was dispatched"
    );
    assert!(
        closed_within(&t, REFUSAL_ACK_BUDGET.saturating_sub(start.elapsed())).await,
        "the ack on another path did not complete the cut"
    );
    assert!(start.elapsed() < REFUSAL_ACK_BUDGET, "closed by the budget, not by the ack");
}

/// A candidate stream left from an EARLIER generation of the pid (a
/// replacement such as a direct upgrade) is not where this transport
/// delivers, and must not be watched: an event on it is not this link's.
/// The cut still waits on the main-queue signal for its ack.
#[tokio::test]
async fn a_stale_generation_stream_is_not_taken_for_the_ack() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-g".into(), direct_link("sid-g", "b", "user@b", t.clone()));
    let stale = own_stream(&mut conn, "sid-g", 6);
    assert!(conn.drop_link_after_refusal("sid-g", refusal()));
    assert_eq!(conn.closing.len(), 1, "a stale stream was taken instead of the signal path");
    let nonce = written_refusal_nonce(&t).await;
    let _ = stale.send(revoked_ack("sid-g", t.source, &nonce));
    assert!(
        !closed_within(&t, Duration::from_millis(300)).await,
        "the stale stream was watched"
    );
    assert!(conn.stage_event(revoked_ack("sid-g", t.source, &nonce)).is_none());
    assert!(closed_within(&t, Duration::from_millis(500)).await, "not closed after the ack");
}

/// A peer that never acks (dead, or an older build) costs the budget and
/// no more: the transport is closed then, and the entry is forgotten. An
/// ack arriving after that is consumed, never dispatched, and closes
/// nothing twice.
#[tokio::test]
async fn a_revoked_link_with_no_ack_closes_at_the_budget() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    conn.links.insert("sid-n".into(), direct_link("sid-n", "b", "user@b", t.clone()));
    assert!(conn.drop_link_after_refusal("sid-n", refusal()));
    let nonce = written_refusal_nonce(&t).await;
    tokio::time::sleep(REFUSAL_ACK_BUDGET - Duration::from_millis(500)).await;
    assert_eq!(t.closes.load(Ordering::Relaxed), 0, "closed before the budget");
    assert!(closed_within(&t, Duration::from_millis(1500)).await, "left open past the budget");
    assert!(
        conn.stage_event(revoked_ack("sid-n", t.source, &nonce)).is_none(),
        "a late ack was dispatched"
    );
    conn.pump_builds();
    assert!(conn.closing.is_empty(), "a finished cut stayed registered");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(t.closes.load(Ordering::Relaxed), 1, "a late ack closed the link again");
}

/// A frozen peer whose write never completes: the drop returns at once (it
/// is synchronous; the wait is on a task), and the transport is still
/// closed at the budget.
#[tokio::test]
async fn a_revoked_link_to_a_frozen_peer_never_holds_the_caller() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(true);
    conn.links.insert("sid-f".into(), direct_link("sid-f", "b", "user@b", t.clone()));
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-f", refusal()));
    assert!(start.elapsed() < Duration::from_millis(200), "the drop waited on the peer");
    assert!(
        closed_within(&t, REFUSAL_ACK_BUDGET + Duration::from_millis(1500)).await,
        "a frozen peer kept the cut transport open"
    );
}

/// A write that fails (the transport is already gone) closes at once.
#[tokio::test]
async fn a_revoked_link_whose_write_fails_closes_at_once() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = failing_refusal_t();
    conn.links.insert("sid-w".into(), direct_link("sid-w", "b", "user@b", t.clone()));
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-w", refusal()));
    assert!(closed_within(&t, Duration::from_millis(500)).await, "left open after a failed write");
    assert!(start.elapsed() < REFUSAL_ACK_BUDGET);
}

/// No transport (a WebRTC link that never reached ChannelReady): nothing
/// is attempted, the link is still dropped, and nothing is registered.
#[tokio::test]
async fn a_revoked_link_with_no_transport_is_a_plain_drop() {
    let (mut conn, _far, _rx) = test_conn().await;
    let log = Arc::new(crate::host::VecLog::new());
    conn.log = log.clone() as Arc<dyn LogSink>;
    let t = refusal_t(false);
    let mut l = direct_link("sid-t", "b", "user@b", t.clone());
    l.transport = None;
    conn.links.insert("sid-t".into(), l);
    assert!(!conn.drop_link_after_refusal("sid-t", refusal()));
    assert!(!conn.links.contains_key("sid-t"), "the link survived");
    assert!(conn.closing.is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(t.sent.lock().unwrap().is_empty(), "a refusal went out with no transport");
    let lines = log.take();
    assert!(
        lines.iter().any(|(_, l)| l.contains("link-revoked to sid-t: dropped_no_transport")),
        "the skipped refusal was not logged: {lines:?}"
    );
}

/// An unassigned source cannot carry a source-tagged ack: the refusal is
/// still written, nothing is awaited or registered, and the link closes
/// at once.
#[tokio::test]
async fn a_revoked_link_with_an_unassigned_source_awaits_no_ack() {
    let (mut conn, _far, _rx) = test_conn().await;
    let t = refusal_t(false);
    let mut l = direct_link("sid-u", "b", "user@b", t.clone());
    l.source = net::SourceId::UNASSIGNED;
    conn.links.insert("sid-u".into(), l);
    let start = Instant::now();
    assert!(conn.drop_link_after_refusal("sid-u", refusal()));
    assert!(conn.closing.is_empty(), "an unbindable cut was registered");
    let _ = written_refusal_nonce(&t).await;
    assert!(closed_within(&t, Duration::from_millis(500)).await);
    assert!(start.elapsed() < REFUSAL_ACK_BUDGET, "waited for an ack that cannot come");
}

/// F1a's shape: a forget dooms TWO links to one peer together (here a
/// stale one whose transport is already gone, and the live one). Each cut
/// has its own nonce and waits for its own ack: the dead one closes at once
/// on its failed write, the live one only on ITS nonce. An ack with the
/// other cut's nonce, or for the other pid, cannot complete it.
#[tokio::test]
async fn two_links_of_one_peer_cut_together_each_wait_for_their_own_ack() {
    let (mut conn, _far, _rx) = test_conn().await;
    let gone = failing_refusal_t();
    let live = refusal_t(false);
    conn.links.insert("sid-old".into(), direct_link("sid-old", "b", "user@b", gone.clone()));
    conn.links.insert("sid-new".into(), direct_link("sid-new", "b", "user@b", live.clone()));
    assert!(conn.drop_link_after_refusal("sid-old", refusal()));
    assert!(conn.drop_link_after_refusal("sid-new", refusal()));
    assert!(closed_within(&gone, Duration::from_millis(500)).await, "the dead link stayed open");
    let n_live = written_refusal_nonce(&live).await;
    let n_other = conn
        .closing
        .iter()
        .find(|(n, e)| e.pid == "sid-old" && **n != n_live)
        .map(|(n, _)| n.clone())
        .expect("the dead cut keeps its own entry until the next prune");
    assert!(conn.stage_event(revoked_ack("sid-new", live.source, &n_other)).is_none());
    assert!(conn.stage_event(revoked_ack("sid-old", live.source, &n_live)).is_none());
    assert!(!closed_within(&live, Duration::from_millis(150)).await, "closed on another cut's ack");
    assert!(conn.stage_event(revoked_ack("sid-new", live.source, &n_live)).is_none());
    assert!(closed_within(&live, Duration::from_millis(500)).await, "not closed after its ack");
}

/// An ack that comes back on a CURRENT link of the same pid (the peer
/// answered on a path this side re-established) still completes the cut,
/// and is consumed, never dispatched.
#[tokio::test]
async fn an_ack_on_a_current_link_of_the_same_pid_completes_the_cut() {
    let (mut conn, _far, _rx) = test_conn().await;
    let cut = refusal_t(false);
    conn.links.insert("sid-c".into(), direct_link("sid-c", "b", "user@b", cut.clone()));
    assert!(conn.drop_link_after_refusal("sid-c", refusal()));
    let nonce = written_refusal_nonce(&cut).await;
    let again = refusal_t(false);
    conn.links.insert("sid-c".into(), direct_link("sid-c", "b", "user@b", again.clone()));
    assert!(
        conn.stage_event(revoked_ack("sid-c", again.source, &nonce)).is_none(),
        "an ack on a current link was dispatched"
    );
    assert!(conn.closing.is_empty());
    assert!(closed_within(&cut, Duration::from_millis(500)).await, "not closed after the ack");
    assert_eq!(again.closes.load(Ordering::Relaxed), 0, "the current link was closed");
}
