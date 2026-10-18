//! Inbound `sync-open` admission.
//!
//! This is the peer-loop half of `cli::sync_cmd::handle_sync_open`: destination
//! confinement, the transfer capability gate, and the shared-mux registration
//! order. The CLI keeps parking, the consent request, `serve_sync`'s stateful
//! protocol and the user-facing log lines; this module decides whether a stream
//! may exist and returns the validated root and the exact refusal to send.
//!
//! Ordering is the security contract, preserved from the CLI handler:
//! transport, checked L2 sid, path bounds, authorization, capacity, collision,
//! ack. Bounds run before the gate so an out-of-root request never becomes a
//! capability question (and never raises a consent request), while the gate
//! always sees the real scope (`scoped_in_bounds = true`, the transfer
//! scoped-default rule). The caller owns the shared [`MuxMap`]; a private mux
//! would split the SID namespace and the close/ack/data path.
//!
//! The library reads no settings file, environment, device store or clock. The
//! caller resolves the drop directory once per open and passes it in, and the
//! host supplies the cap store, the mode, the clock and the effective gate.

use crate::conn::{dropped_no_transport, Conn};
use crate::host::CapGate;
use crate::l2::{self, Mux, MuxMap, PipeItem};
use crate::shell_gate::peer_authz;
use filament_cap::capability as cap;
use filament_transfer::path_bounds::resolve_root;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// One inbound `sync-open` decision.
pub enum SyncAdmission {
    /// Admitted, registered on the caller's shared mux and acknowledged. The
    /// caller owns the stateful serving task (`serve_sync`) and the returned
    /// stream receiver.
    Accepted(SyncAccepted),
    /// Refused by the transfer gate. The caller may hold it for identity proof
    /// through its existing `park_on_deny`; if it does not, it records the
    /// consent request, logs, and sends [`SyncDenial::close_frame`].
    Denied(SyncDenial),
    /// Refused before or after authorization by a non-policy rule (path bounds,
    /// stream capacity, or sid collision). Final: send the exact close, do not
    /// park and do not raise a consent request.
    Refused(SyncRefusal),
    /// Nothing to send: the link has no transport, or the frame had no usable
    /// L2 sid. No close, no mux entry, no gate call.
    Ignored,
}

/// An admitted sync stream.
pub struct SyncAccepted {
    pub sid: u32,
    /// The acceptor's name for the peer at admission time, for the caller's
    /// success line. It is captured before `peer_authz` resolves identity,
    /// exactly as the CLI handler did.
    pub who: String,
    /// The canonical confined destination root (or the not-yet-created target
    /// of a dry run, which is why no files are written for one).
    pub root: PathBuf,
    pub dry_run: bool,
    pub delete: bool,
    pub rx: mpsc::Receiver<PipeItem>,
    /// The caller's shared mux the stream was registered on.
    pub mux: Arc<Mux>,
    /// The transport the ack was sent on; the caller serves and closes on the
    /// same link.
    pub transport: Arc<dyn Transport>,
}

/// A transfer-gate denial and the inputs the CLI hands to its parking rule.
pub struct SyncDenial {
    pub sid: u32,
    /// The gate's reason, without the wire prefix. The caller passes this to
    /// `park_on_deny` unchanged.
    pub reason: String,
    /// The transport captured before the gate, so the close rides the same link
    /// the admission examined.
    pub transport: Arc<dyn Transport>,
    /// The sid and reason the caller passes to `park_on_deny`. Present because
    /// admission has already rejected every frame that could not be re-driven.
    pub park: SyncPark,
}

/// The sid and reason a re-drive needs, unchanged from the CLI handler.
pub struct SyncPark {
    pub sid: u32,
    pub reason: String,
}

impl SyncDenial {
    /// The exact `l2-close` the CLI sends after its parking attempt. Sync has
    /// always used the plain not-authorized frame (no refusal code/as fields),
    /// so the wire shape is pinned here rather than re-derived by the caller.
    pub fn close_frame(&self) -> Value {
        json!({
            "type": "l2-close",
            "sid": self.sid,
            "err": self.err(),
        })
    }

    /// The exact wire error for this denial.
    pub fn err(&self) -> String {
        format!("not authorized: {}", self.reason)
    }
}

/// A final, non-policy refusal with the exact frame the CLI sends.
pub struct SyncRefusal {
    pub sid: u32,
    /// The historical log/wire reason, verbatim ("remote dir is outside this
    /// device's drop directory", "too many streams", "sid in use").
    pub reason: String,
    pub close: Value,
    pub transport: Arc<dyn Transport>,
}

impl SyncRefusal {
    fn new(sid: u32, reason: String, transport: Arc<dyn Transport>) -> Self {
        Self {
            sid,
            close: json!({ "type": "l2-close", "sid": sid, "err": reason.clone() }),
            reason,
            transport,
        }
    }
}

/// Admit one inbound `sync-open` and register an accepted stream on the
/// caller's shared mux.
///
/// `drop_dir` is already resolved by the caller (the receive command's drop
/// directory). Path bounds run before authorization; the transfer gate is the
/// same decision a `file-offer` from this peer gets; and the ack is sent only
/// after `register_stream` succeeds. Nothing is enqueued and nothing is parked
/// here: both are caller policy over the returned [`SyncDenial`].
pub async fn admit_sync_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    muxes: &mut MuxMap,
    drop_dir: &Path,
) -> SyncAdmission {
    // The live arm already drops a link with no transport, but a parked
    // re-drive must re-check it: the transport may have gone while it waited.
    let Some(t) = conn.transport_of(pid) else {
        dropped_no_transport(conn.log.as_ref(), pid, "sync-open");
        return SyncAdmission::Ignored;
    };
    // `wire_sid` rejects a missing or out-of-range sid instead of defaulting
    // to 0 / wrapping into a forged `is_l2_sid` value. Both return silently:
    // no close, no mux entry, no gate call.
    let Some(sid) = l2::wire_sid(v) else {
        return SyncAdmission::Ignored;
    };
    if !l2::is_l2_sid(sid) {
        return SyncAdmission::Ignored;
    }

    // Bounds first, as before: an out-of-root request never widens to a
    // grant-only decision it would have failed anyway, and the gate sees the
    // real scope. A dry run must not create the destination.
    let dry_run = v["dry_run"].as_bool() == Some(true);
    let root = match resolve_root(drop_dir, v["root"].as_str().unwrap_or(""), !dry_run) {
        Ok(root) => root,
        Err(reason) => return SyncAdmission::Refused(SyncRefusal::new(sid, reason, t)),
    };

    // Snapshot trust and the peer's name BEFORE `peer_authz` lazily resolves
    // identity: the transfer legacy fold uses this trust bit, and the success
    // line uses this pre-resolution name, exactly as the CLI handler did.
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let who = conn
        .link(pid)
        .and_then(|l| l.verified_name.clone())
        .unwrap_or_else(|| "<unverified>".into());

    // The transfer gate is unconditional in both modes. The injected host is
    // the one policy site: it owns the store, mode, clock and verdict, so this
    // endpoint never re-derives a capability decision or reads a file.
    let denied_reason = {
        let host = conn.host.clone();
        let az = peer_authz(conn, pid);
        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
        let store = host.cap_store();
        let now = host.now_secs();
        let authoritative = host.cap_authoritative();
        let outcome =
            cap::authorize_in(&store, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps, now);
        let outcome = cap::cap_trust_floor(&outcome, trusted, binding, authoritative);
        let (own_user, has_grant) =
            cap::fleet_inputs_in(&store, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps, now);
        // These are the `file-offer` transfer-gate inputs exactly. `denied` is
        // false because no deny list is consulted on the transfer path today;
        // `ceiling_authorizes` is false because transfer is a SCOPED DEFAULT
        // (the true below), not a deliberate-tier action the ceiling decides.
        let d = host.cap_gate_effective(CapGate {
            legacy_allowed: trusted,
            outcome: &outcome,
            action: cap::CAP_TRANSFER,
            resource: "self",
            device_pub: idev,
            user_pub: iusr,
            binding,
            cert_expires: expires,
            auth_key_caps: ak_caps,
            own_user_pub: own_user.as_ref(),
            scoped_in_bounds: true,
            has_explicit_grant: has_grant,
            cert_revoked,
            denied: false,
            ceiling_authorizes: false,
        });
        if let Some(reason) = cap::transfer_gate_decision(&d, authoritative) {
            Some(reason)
        } else if !d.allowed() {
            Some(d.deny_reason("unverified peer: pair first").to_string())
        } else {
            None
        }
    };
    if let Some(reason) = denied_reason {
        return SyncAdmission::Denied(SyncDenial {
            sid,
            park: SyncPark {
                sid,
                reason: reason.clone(),
            },
            reason,
            transport: t,
        });
    }

    // Get-or-create in the CALLER's map: sync shares the one SID namespace and
    // close/ack path with mount, forward, pty and exec.
    let mux = muxes
        .entry(pid.to_owned())
        .or_insert_with(|| Mux::new(t.clone(), conn.host.clone()))
        .clone();
    if mux.at_stream_cap().await {
        return SyncAdmission::Refused(SyncRefusal::new(sid, "too many streams".into(), t));
    }
    // Never displace another endpoint's live stream in the shared mux.
    let Some(rx) = mux.register_stream(sid).await else {
        return SyncAdmission::Refused(SyncRefusal::new(sid, "sid in use".into(), t));
    };

    // `delete` is read only after a stream exists, as before. `dest` is the
    // resolved absolute destination, so the sender can say where its files
    // went (additive; older senders ignore it).
    let delete = v["delete"].as_bool() == Some(true);
    let _ = t
        .send_control(&json!({
            "type": "sync-open-ack",
            "sid": sid,
            "dest": root.display().to_string(),
        }))
        .await;

    SyncAdmission::Accepted(SyncAccepted {
        sid,
        who,
        root,
        dry_run,
        delete,
        rx,
        mux,
        transport: t,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Link, Presence};
    use crate::host::{HostServices, NoHost, NoLog};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    const PID: &str = "sync-peer";
    const SID: u32 = l2::L2_SID_BASE + 7;
    const DEVICE: [u8; 32] = [7; 32];
    const USER: [u8; 32] = [3; 32];
    const OUTSIDE: &str = "remote dir is outside this device's drop directory";

    #[derive(Default)]
    struct CaptureTransport {
        controls: Mutex<Vec<Value>>,
    }

    #[async_trait::async_trait]
    impl Transport for CaptureTransport {
        async fn send_control(&self, msg: &Value) -> anyhow::Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            64 * 1024
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn is_dead(&self) -> bool {
            false
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn controls(t: &CaptureTransport) -> Vec<Value> {
        t.controls.lock().unwrap().clone()
    }

    #[derive(Clone)]
    enum Verdict {
        Allow,
        Deny(Option<String>),
        /// Decide exactly on the legacy fold, as the real policy site does in
        /// shadow mode. Lets a test pin the fold the endpoint delivered.
        Legacy,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct GateRecord {
        legacy: bool,
        action: String,
        resource: String,
        scoped: bool,
        denied: bool,
        ceiling: bool,
        has_grant: bool,
        cert_revoked: bool,
        binding: cap::BindingStrength,
        device: Option<[u8; 32]>,
        user: Option<[u8; 32]>,
    }

    // The policy site is injected, not reimplemented here: the test host
    // records the fold inputs the endpoint delivered and supplies a verdict.
    // The CLI's own gate suites cover the full capability/store matrix.
    struct TestHost {
        authoritative: bool,
        verdict: Verdict,
        cert_revoked: AtomicBool,
        gates: Mutex<Vec<GateRecord>>,
        consent: Mutex<Vec<(String, String)>>,
    }

    impl TestHost {
        fn new(authoritative: bool, verdict: Verdict) -> Arc<Self> {
            Arc::new(Self {
                authoritative,
                verdict,
                cert_revoked: AtomicBool::new(false),
                gates: Mutex::new(Vec::new()),
                consent: Mutex::new(Vec::new()),
            })
        }

        fn gates(&self) -> Vec<GateRecord> {
            self.gates.lock().unwrap().clone()
        }

        fn consent(&self) -> Vec<(String, String)> {
            self.consent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HostServices for TestHost {
        fn settings_get_str(&self, key: &str) -> Option<String> {
            NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            NoHost.devices_load()
        }
        fn is_self_uid(&self, a: &str, b: Option<&str>) -> bool {
            NoHost.is_self_uid(a, b)
        }
        fn rejoin_unwarned(&self) -> Duration {
            NoHost.rejoin_unwarned()
        }
        fn relay_banner(&self) -> String {
            NoHost.relay_banner()
        }
        fn relay_forbidden(&self) -> bool {
            NoHost.relay_forbidden()
        }
        fn channel_of(&self, secret: &str) -> String {
            NoHost.channel_of(secret)
        }
        fn roster_snapshot_json(&self) -> Option<String> {
            NoHost.roster_snapshot_json()
        }
        fn fleet_rv_present(&self) -> bool {
            false
        }
        fn now_secs(&self) -> u64 {
            100
        }
        fn cert_revoked_for(&self, _device_pub: Option<&[u8; 32]>) -> bool {
            self.cert_revoked.load(Ordering::Relaxed)
        }
        fn device_allows(&self, _name: &str, _capability: &str) -> bool {
            false
        }
        fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
            false
        }
        fn cap_authoritative(&self) -> bool {
            self.authoritative
        }
        fn cap_gate_effective(&self, gate: CapGate<'_>) -> cap::GateDecision {
            self.gates.lock().unwrap().push(GateRecord {
                legacy: gate.legacy_allowed,
                action: gate.action.to_string(),
                resource: gate.resource.to_string(),
                scoped: gate.scoped_in_bounds,
                denied: gate.denied,
                ceiling: gate.ceiling_authorizes,
                has_grant: gate.has_explicit_grant,
                cert_revoked: gate.cert_revoked,
                binding: gate.binding,
                device: gate.device_pub.copied(),
                user: gate.user_pub.copied(),
            });
            match &self.verdict {
                Verdict::Allow => cap::GateDecision::Allow,
                Verdict::Deny(reason) => cap::GateDecision::Deny {
                    cap_reason: reason.clone(),
                },
                Verdict::Legacy if gate.legacy_allowed => cap::GateDecision::Allow,
                Verdict::Legacy => cap::GateDecision::Deny { cap_reason: None },
            }
        }
        fn enqueue_request_if_requestable(&self, peer: &str, capability: &str) {
            self.consent
                .lock()
                .unwrap()
                .push((peer.to_string(), capability.to_string()));
        }
    }

    async fn connection(
        host: Arc<TestHost>,
        t: Arc<CaptureTransport>,
        trusted: bool,
        transport: bool,
        verified: Option<&str>,
    ) -> (Conn, tokio::net::TcpStream) {
        let (sio, far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let link_transport: Option<Arc<dyn Transport>> =
            if transport { Some(t.clone()) } else { None };
        let mut conn = Conn::for_command(
            filament_transport::TransportContext::default(),
            "http://127.0.0.1:9",
            sio,
            tx,
            "me".into(),
            false,
            None,
            false,
            false,
            Arc::new(NoLog),
            host.clone(),
        );
        conn.links.insert(
            PID.into(),
            Link {
                peer: None,
                info: json!({"id": PID}),
                name: "untrusted display name".into(),
                uid: None,
                transport: link_transport,
                workers: vec![],
                generation: 1,
                attempts: 0,
                trusted,
                expected_secret: None,
                // Avoid ambient device-record/consent I/O: the gate is keyed by
                // the resolved device key, not the display name.
                verified_name: verified.map(str::to_string),
                presence: Presence::Ready,
                direct: true,
                direct_route: "direct-quic",
                established_at: None,
                identity_device_pub: Some(DEVICE),
                identity_user_pub: Some(USER),
                identity_binding: cap::BindingStrength::Proven,
                identity_cert_expires: Some(1000),
                principal_kind: cap::PrincipalKind::OwnerDevice,
                host,
            },
        );
        (conn, far)
    }

    fn open(root: &str, sid: u32) -> Value {
        json!({"type": "sync-open", "sid": sid, "root": root})
    }

    struct Share(PathBuf);
    impl Share {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "tunlion-sync-recv-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Share {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            if target.is_dir() {
                std::os::windows::fs::symlink_dir(target, link)
            } else {
                std::os::windows::fs::symlink_file(target, link)
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no symlink support on this platform",
            ))
        }
    }

    #[tokio::test]
    async fn admitted_open_acks_the_canonical_root_on_the_shared_mux() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Accepted(a) = out else {
            panic!("a valid trusted open must be admitted");
        };
        assert_eq!(a.sid, SID);
        assert_eq!(
            a.who, "phone",
            "the pre-resolution verified name is the success label"
        );
        assert_eq!(a.root, share.0.join("inbox").canonicalize().unwrap());
        assert!(!a.dry_run);
        assert!(!a.delete);
        assert_eq!(
            controls(&t),
            vec![json!({
                "type": "sync-open-ack",
                "sid": SID,
                "dest": a.root.display().to_string(),
            })]
        );
        let mux = muxes.get(PID).expect("the shared mux entry is created");
        assert!(
            Arc::ptr_eq(mux, &a.mux),
            "admission must reuse the caller's mux"
        );
        assert!(mux.live_sids().await.contains(&SID));
        assert_eq!(
            host.gates(),
            vec![GateRecord {
                legacy: true,
                action: cap::CAP_TRANSFER.into(),
                resource: "self".into(),
                scoped: true,
                denied: false,
                ceiling: false,
                has_grant: false,
                cert_revoked: false,
                binding: cap::BindingStrength::Proven,
                device: Some(DEVICE),
                user: Some(USER),
            }]
        );
        mux.drop_stream(SID).await;
    }

    #[tokio::test]
    async fn shadow_denial_returns_the_park_inputs_and_raises_no_consent() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Deny(None));
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        // Shadow mode with no cap reason falls back to the legacy deny. The
        // caller parks on `park`, raises the request and sends the close.
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("a shadow deny must reach the caller for parking");
        };
        assert_eq!(d.sid, SID);
        assert_eq!(d.reason, "unverified peer: pair first");
        assert_eq!(d.park.sid, SID);
        assert_eq!(d.park.reason, d.reason);
        assert_eq!(d.err(), "not authorized: unverified peer: pair first");
        assert_eq!(
            d.close_frame(),
            json!({
                "type": "l2-close",
                "sid": SID,
                "err": "not authorized: unverified peer: pair first",
            })
        );
        assert!(controls(&t).is_empty(), "the caller sends the close");
        assert!(muxes.is_empty(), "a denied open registers nothing");
        assert!(
            host.consent().is_empty(),
            "consent stays the caller's decision, not admission's"
        );
        assert_eq!(host.gates().len(), 1);
    }

    #[tokio::test]
    async fn authoritative_denial_keeps_the_capability_reason() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(true, Verdict::Deny(Some("access expired".into())));
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("guest")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("an authoritative deny must be final at the gate");
        };
        assert_eq!(d.reason, "access expired");
        assert_eq!(d.park.reason, "access expired");
        assert_eq!(d.err(), "not authorized: access expired");
        assert!(controls(&t).is_empty());
        assert!(muxes.is_empty());
    }

    #[tokio::test]
    async fn gate_receives_the_transfer_trust_and_consent_inputs() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(true, Verdict::Deny(Some("cert revoked".into())));
        host.cert_revoked.store(true, Ordering::Relaxed);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Denied(_)));
        assert_eq!(
            host.gates(),
            vec![GateRecord {
                legacy: true,
                action: cap::CAP_TRANSFER.into(),
                resource: "self".into(),
                // Transfer is the scoped-default class; the enrolment ceiling
                // decides deliberate-tier actions, not transfer.
                scoped: true,
                denied: false,
                ceiling: false,
                has_grant: false,
                cert_revoked: true,
                binding: cap::BindingStrength::Proven,
                device: Some(DEVICE),
                user: Some(USER),
            }],
            "sync must keep the exact file-offer transfer gate inputs"
        );
        assert!(host.consent().is_empty());
    }

    #[tokio::test]
    async fn shadow_fold_uses_the_raw_trust_bit() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Legacy);

        // Trusted in shadow: the legacy fold admits.
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Accepted(_)));
        assert_eq!(host.gates()[0].legacy, true);

        // Untrusted in shadow: the same fold denies, and carries park inputs.
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) =
            connection(host.clone(), t.clone(), false, true, Some("phone")).await;
        let mut muxes = MuxMap::new();
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("the legacy fold must deny an untrusted link");
        };
        assert_eq!(d.reason, "unverified peer: pair first");
        assert_eq!(host.gates()[1].legacy, false);
    }

    #[tokio::test]
    async fn malformed_sid_and_missing_sid_are_ignored_without_gating() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();

        let frames = [
            json!({}),
            json!([]),
            json!({"type": "sync-open"}),
            json!({"type": "sync-open", "sid": 1}),
            json!({"type": "sync-open", "sid": u32::MAX as u64 + 1}),
            json!({"type": "sync-open", "sid": "7"}),
            json!({"type": "sync-open", "sid": null}),
        ];
        for frame in frames {
            let out = admit_sync_open(&mut conn, PID, &frame, &mut muxes, &share.0).await;
            assert!(
                matches!(out, SyncAdmission::Ignored),
                "malformed sid must be ignored: {frame}"
            );
        }
        assert!(controls(&t).is_empty(), "no close for an unaddressable sid");
        assert!(muxes.is_empty(), "no mux entry for an unaddressable sid");
        assert!(host.gates().is_empty(), "the gate must not run");
    }

    #[tokio::test]
    async fn missing_transport_is_ignored_before_any_gate() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, false, None).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Ignored));
        assert!(controls(&t).is_empty());
        assert!(muxes.is_empty());
        assert!(host.gates().is_empty());
    }

    #[tokio::test]
    async fn traversal_and_absolute_roots_refuse_before_authorization() {
        let share = Share::new();
        let outside = Share::new();
        let outside_abs = outside.0.to_string_lossy().into_owned();
        let requests = [outside_abs.as_str(), "../escape", "..", "/"];
        for request in requests {
            let t = Arc::new(CaptureTransport::default());
            let host = TestHost::new(false, Verdict::Allow);
            let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
            let mut muxes = MuxMap::new();

            let out =
                admit_sync_open(&mut conn, PID, &open(request, SID), &mut muxes, &share.0).await;
            let SyncAdmission::Refused(r) = out else {
                panic!("root {request:?} must be refused by path bounds");
            };
            assert_eq!(r.sid, SID);
            assert_eq!(r.reason, OUTSIDE, "moved path_bounds supplies the reason");
            assert_eq!(
                r.close,
                json!({"type": "l2-close", "sid": SID, "err": OUTSIDE})
            );
            assert!(
                host.gates().is_empty(),
                "bounds must run before authorization for {request:?}"
            );
            assert!(muxes.is_empty());
            assert!(controls(&t).is_empty(), "the caller sends the refusal");
        }
    }

    #[tokio::test]
    async fn symlinked_root_escape_refuses_before_authorization() {
        let share = Share::new();
        let outside = Share::new();
        let link = share.0.join("escape");
        if symlink(&outside.0, &link).is_err() {
            return;
        }
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("escape", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a symlinked root escape must be refused");
        };
        assert_eq!(r.reason, OUTSIDE);
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": OUTSIDE})
        );
        assert!(host.gates().is_empty());
        assert!(muxes.is_empty());
    }

    #[tokio::test]
    async fn capacity_and_collision_do_not_ack_or_replace() {
        let share = Share::new();

        // Capacity is checked before registration, so not even the stream that
        // was under the cap gets acked.
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mux = Mux::new(t.clone(), conn.host.clone());
        for i in 0..l2::MAX_STREAMS_PER_LINK {
            assert!(mux
                .register_stream(l2::L2_SID_BASE + i as u32)
                .await
                .is_some());
        }
        let mut muxes = MuxMap::from([(PID.to_string(), mux.clone())]);
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a full mux must refuse");
        };
        assert_eq!(r.reason, "too many streams");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "too many streams"})
        );
        assert!(controls(&t).is_empty(), "capacity must not ack");
        assert_eq!(mux.live_sids().await.len(), l2::MAX_STREAMS_PER_LINK);

        // A live sid is never displaced, and the existing stream keeps its pipe.
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mux = Mux::new(t.clone(), conn.host.clone());
        let mut existing = mux.register_stream(SID).await.unwrap();
        let mut muxes = MuxMap::from([(PID.to_string(), mux.clone())]);
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a colliding sid must refuse");
        };
        assert_eq!(r.reason, "sid in use");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "sid in use"})
        );
        assert!(controls(&t).is_empty(), "collision must not ack");
        assert_eq!(mux.live_sids().await, vec![SID]);
        assert!(
            matches!(
                existing.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the original stream's pipe must survive"
        );
        mux.drop_stream(SID).await;
    }

    #[tokio::test]
    async fn dry_run_bounds_the_root_without_creating_it() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();
        let frame = json!({
            "type": "sync-open",
            "sid": SID,
            "root": "later",
            "dry_run": true,
            "delete": true,
        });

        let out = admit_sync_open(&mut conn, PID, &frame, &mut muxes, &share.0).await;
        let SyncAdmission::Accepted(a) = out else {
            panic!("a dry run still admits the stream");
        };
        assert!(a.dry_run);
        assert!(a.delete);
        assert!(!share.0.join("later").exists(), "a dry run creates nothing");
        assert_eq!(a.root, share.0.join("later"));
        assert_eq!(
            controls(&t),
            vec![json!({
                "type": "sync-open-ack",
                "sid": SID,
                "dest": a.root.display().to_string(),
            })]
        );
        muxes.get(PID).unwrap().drop_stream(SID).await;
    }
}
