//! Inbound mount endpoint admission. The receive driver retains link admission,
//! the serving guard, and the shared per-peer mux/data dispatch.

use crate::{
    Conn, device_allows, device_capability_denied, enqueue_if_requestable, l2, mount_proto,
    peer_authz,
};
use filament_cap::capability as cap;
use filament_peerloop::host::CapGate;
use serde_json::{Value, json};
use std::{collections::HashMap, path::Path, sync::Arc};

/// Handle an enabled `mount-open`, using the driver's shared SID namespace.
/// `share_root` is resolved freshly by the caller for this open, not cached at
/// daemon startup. Only the canonical confined root reaches the mount server.
pub(crate) async fn handle_mount_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    muxes: &mut HashMap<String, Arc<l2::Mux>>,
    share_root: &Path,
) {
    let host = conn.host.clone();
    let log = conn.log.clone();
    let Some(t) = conn.transport_of(pid) else {
        crate::conn::dropped_no_transport(pid, "mount-open");
        return;
    };
    // wire_sid rejects a missing OR out-of-range sid instead of
    // defaulting to 0 / wrapping into a forged is_l2_sid value.
    let Some(sid) = l2::wire_sid(v) else {
        return;
    };
    if !l2::is_l2_sid(sid) {
        return;
    }
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    // Decode and confine before authorization, in BOTH enforcement modes.
    // A grant never permits serving outside the operator's share root.
    let root_encoded = v["root"].as_str().unwrap_or(".");
    let requested_root = mount_proto::path_decode(root_encoded)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let confined_root = crate::mount_gate::confine_mount_root(share_root, &requested_root);
    let within_share = confined_root.is_some();
    let verified = conn.link(pid).and_then(|l| l.verified_name.clone());
    // Evaluate unconditionally: shadow samples the legacy-allowed population;
    // the injected host remains the effective policy site in either mode.
    let (authorized, read_only) = {
        let az = peer_authz(conn, pid);
        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
        let store = host.cap_store();
        let now = host.now_secs();
        let authoritative = host.cap_authoritative();
        let outcome = cap::authorize_in(
            &store, "self", cap::CAP_MOUNT, idev, iusr, ak_caps, now,
        );
        let outcome = cap::cap_trust_floor(&outcome, trusted, binding, authoritative);
        let (own_user, has_grant) = cap::fleet_inputs_in(
            &store, "self", cap::CAP_MOUNT, idev, iusr, ak_caps, now,
        );
        let same_owner = match (iusr, own_user.as_ref()) {
            (Some(u), Some(o)) => u == o,
            _ => false,
        };
        // #42 HOLD-OUT: the same-owner read-only scoped default is deliberately
        // not shipped. Re-enabling it requires auth-key-driven end-to-end proof
        // of confinement and EROFS; explicit mount grants remain required.
        let _ = within_share;
        let mount_scoped_default = false;
        let read_only = same_owner
            && binding == cap::BindingStrength::Proven
            && mount_scoped_default
            && !has_grant;
        // Trust alone is insufficient even in shadow: require a record or
        // signed mount grant and no recorded deny (not a shell/transfer grant).
        let (record_grants, denied) = verified
            .as_deref()
            .map(|n| {
                (
                    device_allows(n, cap::CAP_MOUNT),
                    device_capability_denied(n, cap::CAP_MOUNT),
                )
            })
            .unwrap_or((false, false));
        let legacy_ok = crate::mount_gate::mount_legacy_allowed(
            trusted, record_grants, has_grant, denied,
        );
        let d = host.cap_gate_effective(CapGate {
            legacy_allowed: legacy_ok,
            outcome: &outcome,
            action: cap::CAP_MOUNT,
            resource: "self",
            device_pub: idev,
            user_pub: iusr,
            binding,
            cert_expires: expires,
            auth_key_caps: ak_caps,
            own_user_pub: own_user.as_ref(),
            scoped_in_bounds: mount_scoped_default,
            has_explicit_grant: has_grant,
            cert_revoked,
            denied,
            ceiling_authorizes: false,
        });
        (d, read_only)
    };
    if !authorized.allowed() {
        let who = conn
            .link(pid)
            .and_then(|l| l.verified_name.clone())
            .unwrap_or_else(|| "<unverified>".into());
        log.say(&format!(
            "mount: refused for '{who}': {}",
            authorized.deny_reason("not authorized (mount capability required)")
        ));
        enqueue_if_requestable(&who, "mount");
        let deny = authorized.deny_reason("");
        let close = match crate::refusal::Refusal::final_cause(
            (!deny.is_empty()).then_some(deny),
            verified.clone(),
        ) {
            Some(r) => r.close_frame(sid),
            None => json!({ "type": "l2-close", "sid": sid, "err": "not authorized: mount capability required" }),
        };
        let _ = t.send_control(&close).await;
        return;
    }
    let Some(root_path) = confined_root else {
        let who = verified.clone().unwrap_or_else(|| "<unverified>".into());
        log.say(&format!(
            "mount: refused for '{who}': {} is outside the share root {} (set `share` in the config to serve another directory)",
            requested_root.display(),
            share_root.display()
        ));
        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "not authorized: path is outside the share root" })).await;
        return;
    };
    let mut caps = mount_proto::mount_caps_for_root(&root_path);
    // Advertise and enforce read-only together; the server rejects writes even
    // if a client ignores the zero writable size in the acknowledgement.
    if read_only {
        caps.max_write_size = 0;
    }
    let mux = muxes
        .entry(pid.to_owned())
        .or_insert_with(|| l2::Mux::new(t.clone(), conn.host.clone()))
        .clone();
    if mux.at_stream_cap().await {
        let _ = t.send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" })).await;
        return;
    }
    // Never displace another endpoint's live stream in the shared mux.
    let Some(rx) = mux.register_stream(sid).await else {
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
            .await;
        return;
    };
    let _ = t
        .send_control(&json!({ "type": "mount-open-ack", "sid": sid, "caps": caps }))
        .await;
    let transport = t.clone();
    let spawn_sid = sid;
    let proto_version = caps.protocol_version;
    // Keep the admitted identity for the existing per-request live-cut check.
    let spawn_idev = conn.link(pid).and_then(|l| l.identity_device_pub);
    mount_proto::spawn_mount_server(
        root_path,
        transport,
        spawn_sid,
        rx,
        proto_version,
        read_only,
        spawn_idev,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Link, Presence};
    use crate::net::Transport;
    use filament_peerloop::host::{HostServices, NoHost, NoLog};
    use std::path::PathBuf;
    use std::sync::{Mutex, atomic::{AtomicU64, Ordering}};
    use std::time::Duration;

    const PID: &str = "mount-peer";
    const SID: u32 = l2::L2_SID_BASE + 7;
    const DEVICE: [u8; 32] = [7; 32];

    #[derive(Default)]
    struct CaptureTransport {
        controls: Mutex<Vec<Value>>,
        frames: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Transport for CaptureTransport {
        async fn send_control(&self, msg: &Value) -> anyhow::Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, payload: &[u8]) -> anyhow::Result<()> {
            self.frames.lock().unwrap().push(payload.to_vec());
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> { Ok(()) }
        fn max_payload(&self) -> usize { 64 * 1024 }
        fn is_alive(&self) -> bool { true }
        fn is_dead(&self) -> bool { false }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    // The policy site is injected, not reimplemented here. It checks the inputs
    // delivered by the real handler, then supplies a verdict. Existing gate
    // suites cover the full policy matrix and persistent record/consent I/O.
    struct TestHost {
        authoritative: bool,
        grant: bool,
        refusal: Option<&'static str>,
        calls: AtomicU64,
    }

    impl TestHost {
        fn new(grant: bool, authoritative: bool) -> Arc<Self> {
            Arc::new(Self { authoritative, grant, refusal: None, calls: AtomicU64::new(0) })
        }
    }

    #[async_trait::async_trait]
    impl HostServices for TestHost {
        fn settings_get_str(&self, key: &str) -> Option<String> { NoHost.settings_get_str(key) }
        fn devices_load(&self) -> Vec<(String, String)> { NoHost.devices_load() }
        fn is_self_uid(&self, a: &str, b: Option<&str>) -> bool { NoHost.is_self_uid(a, b) }
        fn rejoin_unwarned(&self) -> Duration { NoHost.rejoin_unwarned() }
        fn relay_banner(&self) -> String { NoHost.relay_banner() }
        fn relay_forbidden(&self) -> bool { NoHost.relay_forbidden() }
        fn channel_of(&self, secret: &str) -> String { NoHost.channel_of(secret) }
        fn roster_snapshot_json(&self) -> Option<String> { NoHost.roster_snapshot_json() }
        fn fleet_rv_present(&self) -> bool { false }
        fn now_secs(&self) -> u64 { 100 }
        fn cap_authoritative(&self) -> bool { self.authoritative }
        fn cert_revoked_for(&self, device: Option<&[u8; 32]>) -> bool {
            assert_eq!(device, Some(&DEVICE));
            self.refusal == Some("device revoked")
        }
        fn cap_store(&self) -> Vec<Value> {
            // Parsed host snapshot: signature verification/store mutation are
            // outside this handler. A transfer-only snapshot must not grant mount.
            let header = cap::CapHeader {
                resource: "self".into(), epoch: 0, owner_pub: [1; 32], nonce: [2; 32],
                floors: vec![], issued_at: 1, prev_owner_pub: None,
                prev_header_hash: None, sig: [0; 64],
            };
            let mut store = vec![header.to_json()];
            cap::update_ratchet(&mut store, &[1; 32], 1).unwrap();
            store.push(json!({
                "type": "cap_grant", "resource": "self", "grantor": hex::encode([1; 32]),
                "targetKind": 1, "target": hex::encode(DEVICE), "expires": 1000,
                "permissions": [if self.grant { "mount" } else { "transfer" }],
            }));
            store
        }
        fn cap_gate_effective(&self, gate: CapGate<'_>) -> cap::GateDecision {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(gate.action, "mount");
            assert_eq!(gate.resource, "self");
            assert_eq!(gate.device_pub, Some(&DEVICE));
            assert_eq!(gate.has_explicit_grant, self.grant);
            assert_eq!(gate.legacy_allowed, self.grant);
            assert!(!gate.scoped_in_bounds, "mount scoped default remains held out");
            assert!(!gate.ceiling_authorizes);
            assert!(!gate.denied);
            assert_eq!(gate.cert_revoked, self.refusal == Some("device revoked"));
            if let Some(reason) = self.refusal {
                return cap::GateDecision::Deny { cap_reason: Some(reason.into()) };
            }
            if self.grant {
                assert!(matches!(gate.outcome, cap::CapOutcome::Authorized));
                cap::GateDecision::Allow
            } else {
                assert!(matches!(gate.outcome, cap::CapOutcome::Denied(_)));
                cap::GateDecision::Deny { cap_reason: None }
            }
        }
    }

    struct Share(PathBuf);
    impl Share {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "tunlion-mount-recv-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Share {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    async fn connection(host: Arc<TestHost>, t: Arc<CaptureTransport>) -> (Conn, tokio::net::TcpStream) {
        let (sio, far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut conn = Conn::for_command(
            "http://127.0.0.1:9", sio, tx, "me".into(), false, None, false, false,
            Arc::new(NoLog), host.clone(),
        );
        conn.links.insert(PID.into(), Link {
            peer: None, info: json!({"id": PID}), name: "untrusted display name".into(),
            uid: None, transport: Some(t), workers: vec![], generation: 1, attempts: 0,
            trusted: true, expected_secret: None,
            // Avoid ambient device-record/consent I/O: the signed grant is keyed
            // by the already-resolved device, never by the display name.
            verified_name: None, presence: Presence::Ready, direct: true,
            direct_route: "direct-quic", established_at: None,
            identity_device_pub: Some(DEVICE), identity_user_pub: Some([3; 32]),
            identity_binding: cap::BindingStrength::Proven, identity_cert_expires: Some(1000),
            principal_kind: cap::PrincipalKind::OwnerDevice, host,
        });
        (conn, far)
    }

    fn open(root: &Path) -> Value {
        json!({"type": "mount-open", "sid": SID, "root": mount_proto::path_encode(root)})
    }

    fn assert_close(t: &CaptureTransport, err: &str) {
        assert_eq!(*t.controls.lock().unwrap(), vec![json!({
            "type": "l2-close", "sid": SID, "err": err,
        })]);
        assert!(t.frames.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn transfer_only_is_refused_before_mux_creation_in_both_modes() {
        let share = Share::new();
        for authoritative in [false, true] {
            let host = TestHost::new(false, authoritative);
            let t = Arc::new(CaptureTransport::default());
            let (mut conn, _far) = connection(host.clone(), t.clone()).await;
            let mut muxes = HashMap::new();
            handle_mount_open(&mut conn, PID, &open(Path::new(".")), &mut muxes, &share.0).await;
            assert_close(&t, "not authorized: mount capability required");
            assert!(muxes.is_empty(), "refusal must not register or spawn a server");
            assert_eq!(host.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn invalid_sid_and_missing_transport_never_reach_the_gate() {
        let share = Share::new();
        let host = TestHost::new(true, false);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone()).await;
        let mut muxes = HashMap::new();
        for sid in [Value::Null, json!("bad"), json!(1), json!(u64::MAX)] {
            let mut frame = open(Path::new("."));
            frame["sid"] = sid;
            handle_mount_open(&mut conn, PID, &frame, &mut muxes, &share.0).await;
        }
        conn.links.get_mut(PID).unwrap().transport = None;
        handle_mount_open(&mut conn, PID, &open(Path::new(".")), &mut muxes, &share.0).await;
        assert!(t.controls.lock().unwrap().is_empty());
        assert!(muxes.is_empty());
        assert_eq!(host.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn policy_refusals_preserve_final_cause_frames_and_never_start_a_stream() {
        let share = Share::new();
        for authoritative in [false, true] {
            for (reason, code) in [
                ("device revoked", Some("cert-revoked")),
                ("access expired at 1970-01-01 00:00:01 UTC", Some("expired")),
                ("explicit deny", None),
            ] {
                let host = Arc::new(TestHost {
                    authoritative, grant: true, refusal: Some(reason), calls: AtomicU64::new(0),
                });
                let t = Arc::new(CaptureTransport::default());
                let (mut conn, _far) = connection(host, t.clone()).await;
                let mut muxes = HashMap::new();
                handle_mount_open(&mut conn, PID, &open(Path::new(".")), &mut muxes, &share.0).await;
                let expected = match code {
                    Some(code) => json!({"type": "l2-close", "sid": SID, "err": reason, "code": code}),
                    None => json!({"type": "l2-close", "sid": SID, "err": "not authorized: mount capability required"}),
                };
                assert_eq!(*t.controls.lock().unwrap(), vec![expected]);
                assert!(t.frames.lock().unwrap().is_empty());
                assert!(muxes.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn grant_never_bypasses_path_confinement() {
        let share = Share::new();
        let outside = Share::new();
        let linked = crate::platform::symlink(&outside.0, &share.0.join("escape")).is_ok();
        for authoritative in [false, true] {
            let mut roots = vec![Path::new("/"), Path::new("..")];
            if linked {
                roots.push(Path::new("escape"));
            }
            for root in roots {
                let t = Arc::new(CaptureTransport::default());
                let (mut conn, _far) = connection(TestHost::new(true, authoritative), t.clone()).await;
                let mut muxes = HashMap::new();
                handle_mount_open(&mut conn, PID, &open(root), &mut muxes, &share.0).await;
                assert_close(&t, "not authorized: path is outside the share root");
                assert!(muxes.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn collision_and_capacity_do_not_ack_or_replace_existing_streams() {
        let share = Share::new();
        for full in [false, true] {
            let t = Arc::new(CaptureTransport::default());
            let (mut conn, _far) = connection(TestHost::new(true, false), t.clone()).await;
            let mux = l2::Mux::new(t.clone(), conn.host.clone());
            let mut original = mux.register_stream(SID).await.unwrap();
            let mut receivers = Vec::new();
            if full {
                for offset in 1..l2::MAX_STREAMS_PER_LINK as u32 {
                    receivers.push(mux.register_stream(SID + offset).await.unwrap());
                }
            }
            let before = mux.live_sids().await;
            let mut muxes = HashMap::from([(PID.into(), mux.clone())]);
            handle_mount_open(&mut conn, PID, &open(Path::new(".")), &mut muxes, &share.0).await;
            assert_close(&t, if full { "too many streams" } else { "sid in use" });
            assert_eq!(mux.live_sids().await, before);
            assert!(Arc::ptr_eq(muxes.get(PID).unwrap(), &mux));
            mux.on_frame(SID, bytes::Bytes::from_static(b"original endpoint")).await;
            assert_eq!(original.recv().await.unwrap().unwrap(), "original endpoint");
        }
    }

    #[tokio::test]
    async fn success_acks_caps_and_serves_the_canonical_root_on_the_shared_mux() {
        let share = Share::new();
        let inside = share.0.join("inside");
        std::fs::create_dir(&inside).unwrap();
        std::fs::write(inside.join("marker"), b"canonical").unwrap();
        let alias = share.0.join("alias");
        // Use the platform fixture's capability probe, like sync_cmd's tests:
        // Windows may lack symlink privilege. Still exercise successful serving
        // and caps there; capable hosts additionally exercise alias retargeting.
        let linked = crate::platform::symlink(&inside, &alias).is_ok();
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(TestHost::new(true, true), t.clone()).await;
        let mux = l2::Mux::new(t.clone(), conn.host.clone());
        let other_sid = SID + 1;
        let mut other = mux.register_stream(other_sid).await.unwrap();
        let mut muxes = HashMap::from([(PID.into(), mux.clone())]);
        let requested = if linked { "alias" } else { "inside/../inside" };
        handle_mount_open(&mut conn, PID, &open(Path::new(requested)), &mut muxes, &share.0).await;
        assert_eq!(*t.controls.lock().unwrap(), vec![json!({
            "type": "mount-open-ack", "sid": SID,
            "caps": mount_proto::mount_caps_for_root(&inside.canonicalize().unwrap()),
        })]);
        assert!(Arc::ptr_eq(muxes.get(PID).unwrap(), &mux));
        // Retarget the requested alias after admission. A server holding that
        // path rather than the canonical confined root cannot find our marker.
        let outside = Share::new();
        if linked {
            std::fs::remove_file(&alias).unwrap();
            crate::platform::symlink(&outside.0, &alias).unwrap();
        }
        let request = mount_proto::MountRequest {
            id: 42, bin: None,
            op: mount_proto::MountOp::GetAttr { path: mount_proto::path_encode(Path::new("marker")) },
        };
        let mut payload = serde_json::to_vec(&request).unwrap();
        payload.push(b'\n');
        mux.on_frame(SID, bytes::Bytes::from(payload)).await;
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(frame) = t.frames.lock().unwrap().first().cloned() { break frame; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        let (header, _) = mount_proto::decode_frame(&response);
        let response: Value = serde_json::from_slice(header).unwrap();
        assert_eq!(response["id"], 42);
        assert_eq!(response["status"], "ok");
        assert_eq!(response["value"]["size"], 9);
        mux.on_frame(other_sid, bytes::Bytes::from_static(b"still shared")).await;
        assert_eq!(other.recv().await.unwrap().unwrap(), "still shared");
        mux.drop_stream(SID).await;
    }
}
