//! Inbound `l2-open` (forward) admission.
//!
//! This is the half of `cli::recv_cmd::handle_forward_open` that decides whether
//! an open may exist, then registers it on the caller's shared per-peer mux.
//! The dial and its byte pumps stay in [`Mux::dial_and_serve`](crate::l2::Mux::dial_and_serve);
//! the caller still spawns that task, owns the parking map and re-drives a
//! parked open through this same function.
//!
//! Ordering is the security contract and is preserved from the CLI handler:
//! serving guard, transport, checked `u16` port, the shared shell gate with the
//! expose scoped-default bound, the per-device `l2-allow.json` answer, then the
//! mux's raw-trusted check, capacity and collision rule. A policy denial is
//! returned for the caller's existing settle-then-evaluate parking; a mux
//! refusal is final and carries the exact `l2-close` the CLI sent.
//!
//! The library reads no file, environment, clock or allowlist. The caller
//! resolves `TUNLION_L2`, loads `expose.json`/`l2-allow.json` at the call site
//! and supplies `ShellPolicy`; these closures keep that host/config ownership
//! while the ordering stays here.

use crate::conn::{Conn, dropped_no_transport};
use crate::l2::{self, Mux, MuxMap, OpenVerdict, PipeItem};
use crate::refusal::{Code, Reinvite, Refusal, TUNNEL_OFF_REASON};
use crate::shell_gate::{ShellPolicy, forward_gate_decision, gather_shell_gate_inputs};
use filament_cap::capability as cap;
use filament_transport::net::Transport;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::mpsc;

/// The host-resolved inputs for one inbound forward frame.
///
/// `is_exposed` and `target_allowed` are closures rather than preloaded values
/// so the caller's file reads happen at the same points they always did: the
/// expose bound only for a nonzero port after the gate gathers, and the
/// allowlist only on the admitted branch. Neither closure may broaden access on
/// its own; the loopback rule remains in the mux.
pub struct ForwardConfig<'a> {
    /// The acceptor's shell policy (`--shell`, `--shell-only`, or granted-only).
    pub shell_policy: &'a ShellPolicy,
    /// Will this node accept inbound stream opens at all (`l2_enabled`)?
    pub l2_enabled: bool,
    /// `TUNLION_L2=1`, resolved by the caller (the blanket legacy fold).
    pub l2_forced: bool,
    /// Is this port in the caller's `expose.json` list (the scoped default)?
    pub is_exposed: &'a (dyn Fn(u16) -> bool + Send + Sync),
    /// The caller's per-device `l2-allow.json` answer for this target.
    pub target_allowed: &'a (dyn Fn(&str, &str, u16) -> bool + Send + Sync),
}

/// One admission decision.
pub enum ForwardAdmission {
    /// Admitted and registered on the caller's shared mux. The caller owns the
    /// dial task; [`Mux::dial_and_serve`](crate::l2::Mux::dial_and_serve) is
    /// unchanged and still sends the ack after the local dial succeeds.
    Accepted {
        sid: u32,
        host: String,
        port: u16,
        rx: mpsc::Receiver<PipeItem>,
        mux: Arc<Mux>,
    },
    /// Refused by the shell gate. The caller may hold it for identity proof via
    /// its existing `park_on_deny`; if it does not, it builds the close with
    /// [`ForwardDenial::close_frame`] and sends it.
    Denied(ForwardDenial),
    /// Refused by the shared mux (raw trust, loopback/allowlist, port, capacity
    /// or collision). Final: the exact close must be sent and nothing parked.
    Refused(ForwardRefusal),
    /// Nothing to send: serving is off (the tunnel-off close was sent here),
    /// the link has no transport, or the mux ignored a non-open/malformed frame.
    Ignored,
}

/// A policy denial that the receive driver's settle-then-evaluate path may park.
pub struct ForwardDenial {
    /// The sid echoed in the close; `0` when the frame had no usable sid, as
    /// the CLI handler always did on this path.
    pub sid: u32,
    /// The gate's cause when it named one (used for a final-cause refusal).
    pub cap_reason: Option<String>,
    /// The refusal line, with the historical "device not granted shell" fallback.
    pub reason: String,
    /// Present only when the existing parking rule may consider the denial:
    /// a checked port and an L2-high-half sid.
    pub park: Option<ForwardPark>,
    /// The transport captured before the gate, so the caller sends on the same
    /// link the admission examined.
    pub transport: Arc<dyn Transport>,
}

/// The sid and reason the driver passes to `park_on_deny` unchanged.
pub struct ForwardPark {
    pub sid: u32,
    pub reason: String,
}

impl ForwardDenial {
    /// The exact `l2-close` for this denial.
    ///
    /// `as_name` is the acceptor's name for the peer, re-read by the caller
    /// after its parking attempt. A final cause (expired, revoked) carries its
    /// code and name; otherwise the historical canonical not-granted frame is
    /// used. `reinvite_for` is invoked only for an expired invitation, exactly
    /// where the CLI read the device store before.
    pub fn close_frame<F>(&self, as_name: Option<String>, reinvite_for: F) -> Value
    where
        F: FnOnce() -> Option<Reinvite>,
    {
        match Refusal::final_cause(self.cap_reason.as_deref(), as_name.clone()) {
            Some(mut r) => {
                if r.code == Code::Expired {
                    r.reinvite = reinvite_for();
                }
                r.close_frame(self.sid)
            }
            None => {
                let mut close = json!({
                    "type": "l2-close",
                    "sid": self.sid,
                    "err": "not authorized: device lacks shell grant",
                });
                Refusal::new(Code::NotGranted, as_name).annotate(&mut close);
                close
            }
        }
    }
}

/// A final refusal produced by the mux, with the exact frame the CLI sent.
pub struct ForwardRefusal {
    pub sid: u32,
    pub reason: String,
    pub close: Value,
    pub transport: Arc<dyn Transport>,
}

/// Admit one inbound forward frame and register an accepted stream on the
/// caller's shared mux.
///
/// `MuxMap` is caller-owned and must be the same table every L2 sector uses: a
/// private mux would split the SID namespace and the close/ack path.
pub async fn admit_forward_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    muxes: &mut MuxMap,
    cfg: &ForwardConfig<'_>,
) -> ForwardAdmission {
    // The live arm denies an l2-open when serving is off BEFORE this function is
    // reached, but a PARKED open is re-driven straight here, bypassing that
    // guard. Apply it here too so "re-drive re-gathers every input" holds for
    // the L2 switch. The guard is OPENS ONLY: a peer's l2-close for a stream WE
    // opened is the one message an L2-off node must still act on.
    if !cfg.l2_enabled && v["type"].as_str() != Some("l2-close") {
        if let (Some(t), Some(sid)) = (conn.transport_of(pid), v["sid"].as_u64()) {
            let _ = t
                .send_control(&json!({
                    "type": "l2-close",
                    "sid": sid,
                    "err": TUNNEL_OFF_REASON,
                }))
                .await;
        }
        return ForwardAdmission::Ignored;
    }

    let Some(t) = conn.transport_of(pid) else {
        dropped_no_transport(conn.log.as_ref(), pid, "forward open");
        return ForwardAdmission::Ignored;
    };
    let host = conn.host.clone();

    // The raw proof-verified flag the mux requires, snapshotted before the gate
    // (the gate computes its own pair-or-fleet trust for the capability fold).
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);

    // Ports arrive as u64; a value that does not fit u16 is not addressable, so
    // deny rather than truncate it into a different (possibly exposed) port.
    // Parsed BEFORE the gate and any park: an out-of-range port is not an
    // identity question, so it keeps its own immediate verdict.
    let parsed_port = v["rport"]
        .as_u64()
        .or_else(|| v["port"].as_u64())
        .and_then(|p| u16::try_from(p).ok());
    let (reach_port, port_ok) = match parsed_port {
        Some(p) => (p, true),
        None => (0, false),
    };
    let mut cap_reason: Option<String> = (!port_ok).then(|| "port out of range".to_string());

    let authorized = v["type"].as_str() != Some("l2-open") || {
        let (_dev, mut gate_inputs) =
            gather_shell_gate_inputs(conn, pid, cfg.shell_policy, cap::CAP_SHELL);
        // Forward's auto-trust bound is the EXPOSE list (a scoped default,
        // mode-independent); the enrolment ceiling plays no part here.
        gate_inputs.scoped_default = reach_port != 0 && (cfg.is_exposed)(reach_port);
        // A FleetSibling gets no forward scoped default: the kind implies
        // transfer only, so an exposed port still needs an explicit grant.
        let sib = crate::shell_gate::sibling_facts(conn, pid, "forward");
        gate_inputs.scoped_default =
            crate::shell_gate::sibling_gate_inputs(&sib, "forward", gate_inputs.scoped_default, false).0;
        gate_inputs.ceiling_covers = false;
        let legacy_ok = {
            let blanket = cfg.shell_policy.enables_l2() || cfg.l2_forced;
            let (peer_has_shell, peer_denied) = conn
                .link(pid)
                .and_then(|l| l.verified_name.as_deref())
                .map(|n| {
                    (
                        host.device_allows(n, "shell"),
                        host.device_capability_denied(n, "shell"),
                    )
                })
                .unwrap_or((false, false));
            l2::policy::l2_open_allowed(blanket, peer_has_shell, peer_denied)
        };
        let d = forward_gate_decision(&gate_inputs, legacy_ok, host.as_ref());
        if let Err(Some(r)) = &d {
            cap_reason = Some(r.clone());
        }
        // port_ok is ANDed last: an out-of-range port denies even for a granted
        // peer (there is nothing valid to open), while keeping the recorded
        // reason specific.
        d.is_ok() && port_ok
    };

    if !authorized {
        // wire_sid (not a wrapping cast) so the close names the real sid; 0
        // only if absent/out-of-range.
        let sid = l2::wire_sid(v).unwrap_or(0);
        let reason = cap_reason
            .clone()
            .unwrap_or_else(|| "device not granted shell".to_string());
        // Settle-then-evaluate eligibility: only a good port and an L2-high-half
        // sid could ever be re-driven. The caller still applies its own
        // proof-attributable/budget/durable-deny rules.
        let park = (port_ok && l2::is_l2_sid(sid)).then(|| ForwardPark {
            sid,
            reason: reason.clone(),
        });
        return ForwardAdmission::Denied(ForwardDenial {
            sid,
            cap_reason,
            reason,
            park,
            transport: t,
        });
    }

    // Opt-in gateway: a non-loopback target is allowed only when the operator's
    // l2-allow.json lists it for this device (or "*"). Loopback ignores this
    // (the mux's check), but the caller's answer is computed for every admitted
    // open just as before.
    let allow_nonloopback = {
        let target_host = v["host"].as_str().unwrap_or("127.0.0.1");
        // Same truncation rule as the gate above: an out-of-range port matches
        // no allowlist entry.
        let port = v["rport"]
            .as_u64()
            .or_else(|| v["port"].as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0);
        let name = conn
            .link(pid)
            .and_then(|l| l.verified_name.clone())
            .unwrap_or_default();
        (cfg.target_allowed)(&name, target_host, port)
    };
    let mux = muxes
        .entry(pid.to_owned())
        .or_insert_with(|| Mux::new(t.clone(), host))
        .clone();
    match mux.accept_control(v, trusted, allow_nonloopback).await {
        OpenVerdict::Accept {
            sid,
            host,
            port,
            rx,
        } => ForwardAdmission::Accepted {
            sid,
            host,
            port,
            rx,
            mux,
        },
        OpenVerdict::Deny { sid, err } => ForwardAdmission::Refused(ForwardRefusal {
            sid,
            reason: err.to_string(),
            close: json!({ "type": "l2-close", "sid": sid, "err": err }),
            transport: t,
        }),
        OpenVerdict::Ignore => ForwardAdmission::Ignored,
    }
}

#[cfg(all(test, feature = "forward-server"))]
mod tests {
    use super::*;
    use crate::conn::{Link, Presence};
    use crate::host::{CapGate, HostServices, NoHost, NoLog};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    const PID: &str = "forward-peer";
    const SID: u32 = l2::L2_SID_BASE + 7;
    const DEVICE: [u8; 32] = [7; 32];

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

    #[derive(Clone)]
    enum Verdict {
        Allow,
        Deny(Option<String>),
        /// Decide exactly on the legacy fold, as the real policy site does in
        /// shadow mode. Lets a test pin the fold the endpoint delivered.
        Legacy,
    }

    // The policy site is injected, not reimplemented here: the test host records
    // the fold inputs the endpoint delivered and supplies a verdict. The CLI's
    // own gate suites cover the full capability/store matrix.
    struct TestHost {
        verdict: Verdict,
        record_grant: AtomicBool,
        denied: AtomicBool,
        gates: Mutex<Vec<(bool, bool)>>, // (legacy_allowed, scoped_in_bounds)
    }

    impl TestHost {
        fn new(verdict: Verdict) -> Arc<Self> {
            Arc::new(Self {
                verdict,
                record_grant: AtomicBool::new(false),
                denied: AtomicBool::new(false),
                gates: Mutex::new(Vec::new()),
            })
        }

        fn gates(&self) -> Vec<(bool, bool)> {
            self.gates.lock().unwrap().clone()
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
        fn device_allows(&self, _name: &str, _capability: &str) -> bool {
            self.record_grant.load(Ordering::Relaxed)
        }
        fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
            self.denied.load(Ordering::Relaxed)
        }
        fn cap_gate_effective(&self, gate: CapGate<'_>) -> cap::GateDecision {
            self.gates
                .lock()
                .unwrap()
                .push((gate.legacy_allowed, gate.scoped_in_bounds));
            match &self.verdict {
                Verdict::Allow => cap::GateDecision::Allow,
                Verdict::Deny(reason) => cap::GateDecision::Deny {
                    cap_reason: reason.clone(),
                },
                Verdict::Legacy if gate.legacy_allowed => cap::GateDecision::Allow,
                Verdict::Legacy => cap::GateDecision::Deny { cap_reason: None },
            }
        }
    }

    async fn connection(
        host: Arc<TestHost>,
        t: Arc<CaptureTransport>,
        trusted: bool,
    ) -> (Conn, tokio::net::TcpStream) {
        let (sio, far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
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
                transport: Some(t),
                workers: vec![],
                generation: 1,
                source: Default::default(),
                attempt: None,
                worker_sources: Default::default(),
                attempts: 0,
                trusted,
                expected_secret: None,
                // Avoid ambient device-record/consent I/O: the gate is keyed by
                // the resolved device key, not the display name.
                verified_name: None,
                presence: Presence::Ready,
                direct: true,
                direct_route: "direct-quic",
                established_at: None,
                identity_device_pub: Some(DEVICE),
                identity_user_pub: Some([3; 32]),
                identity_binding: cap::BindingStrength::Proven,
                identity_cert_expires: Some(1000),
                principal_kind: cap::PrincipalKind::OwnerDevice,
                host,
            },
        );
        (conn, far)
    }

    fn open(host: &str, port: u64, sid: u32) -> Value {
        json!({"type": "l2-open", "sid": sid, "host": host, "rport": port})
    }

    fn config<'a>(
        policy: &'a ShellPolicy,
        exposed: &'a (dyn Fn(u16) -> bool + Send + Sync),
        allowed: &'a (dyn Fn(&str, &str, u16) -> bool + Send + Sync),
        l2_enabled: bool,
        l2_forced: bool,
    ) -> ForwardConfig<'a> {
        ForwardConfig {
            shell_policy: policy,
            l2_enabled,
            l2_forced,
            is_exposed: exposed,
            target_allowed: allowed,
        }
    }

    #[tokio::test]
    async fn serving_off_sends_tunnel_off_and_only_closes_bypass_it() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), true).await;
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allowed = |_n: &str, _h: &str, _p: u16| true;
        let cfg = config(&policy, &exposed, &allowed, false, false);

        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Ignored));
        assert_eq!(
            *t.controls.lock().unwrap(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": TUNNEL_OFF_REASON,
            })]
        );
        assert!(host.gates().is_empty(), "the guard must precede the gate");
        assert!(muxes.is_empty());

        // A close for a stream WE opened is the one frame an L2-off node still
        // acts on: it reaches the shared mux and sends no tunnel-off refusal.
        let out = admit_forward_open(
            &mut conn,
            PID,
            &json!({"type": "l2-close", "sid": SID}),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Ignored));
        assert_eq!(t.controls.lock().unwrap().len(), 1);
        assert_eq!(muxes.len(), 1, "the close still uses the shared mux table");
    }

    #[tokio::test]
    async fn gate_denial_is_exact_and_skips_the_allowlist() {
        let host = TestHost::new(Verdict::Deny(None));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), true).await;
        conn.links.get_mut(PID).unwrap().verified_name = Some("phone".into());
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allow_calls = Mutex::new(Vec::new());
        let allowed = |name: &str, host: &str, port: u16| {
            allow_calls
                .lock()
                .unwrap()
                .push((name.to_string(), host.to_string(), port));
            true
        };
        let cfg = config(&policy, &exposed, &allowed, true, false);

        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Denied(d) = out else {
            panic!("expected a policy denial");
        };
        assert_eq!(d.sid, SID);
        assert_eq!(d.cap_reason, None);
        assert_eq!(d.reason, "device not granted shell");
        let park = d.park.as_ref().expect("a checked open may be parked");
        assert_eq!(park.sid, SID);
        assert_eq!(park.reason, d.reason);
        assert!(allow_calls.lock().unwrap().is_empty(), "deny must not read the allowlist");
        assert_eq!(host.gates(), vec![(false, false)]);
        assert!(t.controls.lock().unwrap().is_empty(), "the caller sends the close");

        assert_eq!(
            d.close_frame(Some("phone".into()), || panic!("no reinvite for a plain deny")),
            json!({
                "type": "l2-close",
                "sid": SID,
                "err": "not authorized: device lacks shell grant",
                "code": "not-granted",
                "as": "phone",
            })
        );
        assert!(muxes.is_empty());

        // A low-half sid is not L2's, so a denial for it is never parked. The
        // close still names the sid the frame carried (never a wrapped cast).
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, 1),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Denied(d) = out else {
            panic!("expected a policy denial for the low sid");
        };
        assert_eq!(d.sid, 1);
        assert!(d.park.is_none());
    }

    #[tokio::test]
    async fn expired_denial_carries_the_reinvite_only_when_expired() {
        let reason = crate::refusal::expired_reason(1);
        let host = TestHost::new(Verdict::Deny(Some(reason.clone())));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, true).await;
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allowed = |_n: &str, _h: &str, _p: u16| true;
        let cfg = config(&policy, &exposed, &allowed, true, false);
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Denied(d) = out else {
            panic!("expected a policy denial");
        };
        let close = d.close_frame(Some("guest".into()), || {
            Some(Reinvite {
                ceiling: vec!["shell".into(), "transfer".into()],
                lifetime: 240,
            })
        });
        assert_eq!(close["err"].as_str(), Some(reason.as_str()));
        assert_eq!(close["code"], "expired");
        assert_eq!(close["as"], "guest");
        assert_eq!(close["ceiling"], json!(["shell", "transfer"]));
        assert_eq!(close["lifetime"], 240);

        // A non-expired denial never touches the host's device store.
        let host = TestHost::new(Verdict::Deny(Some("device revoked".into())));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, true).await;
        let mut muxes = HashMap::new();
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Denied(d) = out else {
            panic!("expected a policy denial");
        };
        let close = d.close_frame(Some("phone".into()), || panic!("store read for a revoke"));
        assert_eq!(close["err"], "device revoked");
        assert_eq!(close["code"], "cert-revoked");
        assert_eq!(close["as"], "phone");
    }

    #[tokio::test]
    async fn out_of_range_port_denies_before_parking_and_keeps_the_canonical_frame() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t, true).await;
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allow_calls = Mutex::new(Vec::new());
        let allowed = |name: &str, host: &str, port: u16| {
            allow_calls
                .lock()
                .unwrap()
                .push((name.to_string(), host.to_string(), port));
            true
        };
        let cfg = config(&policy, &exposed, &allowed, true, true);

        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 65_536, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Denied(d) = out else {
            panic!("an out-of-range port must deny");
        };
        assert_eq!(d.reason, "port out of range");
        assert_eq!(d.cap_reason.as_deref(), Some("port out of range"));
        assert!(d.park.is_none(), "a bad port is not an identity question");
        assert!(allow_calls.lock().unwrap().is_empty());
        assert_eq!(host.gates().len(), 1, "the gate still runs before the port veto");
        assert_eq!(
            d.close_frame(None, || panic!("no reinvite")),
            json!({
                "type": "l2-close",
                "sid": SID,
                "err": "not authorized: device lacks shell grant",
                "code": "not-granted",
            })
        );
        assert!(muxes.is_empty());
    }

    #[tokio::test]
    async fn allowlist_answers_and_loopback_still_reach_the_mux() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, true).await;
        conn.links.get_mut(PID).unwrap().verified_name = Some("phone".into());
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allow = AtomicBool::new(false);
        let calls = Mutex::new(Vec::new());
        let allowed = |name: &str, host: &str, port: u16| {
            calls
                .lock()
                .unwrap()
                .push((name.to_string(), host.to_string(), port));
            allow.load(Ordering::Relaxed)
        };
        let cfg = config(&policy, &exposed, &allowed, true, true);

        // Non-loopback without an allowlist entry is the mux's final refusal.
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("10.0.0.5", 5432, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Refused(r) = out else {
            panic!("expected the non-loopback refusal");
        };
        assert_eq!(r.sid, SID);
        assert_eq!(r.reason, "non-loopback denied (not in l2-allow.json)");
        assert_eq!(
            r.close,
            json!({
                "type": "l2-close",
                "sid": SID,
                "err": "non-loopback denied (not in l2-allow.json)",
            })
        );

        // Loopback is always allowed, whatever the allowlist says.
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID + 1),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Accepted { sid, host, port, mux, .. } = out else {
            panic!("loopback must be admitted");
        };
        assert_eq!((sid, host.as_str(), port), (SID + 1, "127.0.0.1", 22));
        assert!(mux.live_sids().await.contains(&sid));

        // The same target with an allowlist answer is admitted.
        allow.store(true, Ordering::Relaxed);
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("10.0.0.5", 5432, SID + 2),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Accepted { .. }));
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                ("phone".to_string(), "10.0.0.5".to_string(), 5432),
                ("phone".to_string(), "127.0.0.1".to_string(), 22),
                ("phone".to_string(), "10.0.0.5".to_string(), 5432),
            ]
        );
    }

    #[tokio::test]
    async fn mux_keeps_the_raw_trusted_requirement() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, false).await;
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allowed = |_n: &str, _h: &str, _p: u16| true;
        let cfg = config(&policy, &exposed, &allowed, true, true);

        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Refused(r) = out else {
            panic!("an untrusted link must be refused by the mux");
        };
        assert_eq!(r.reason, "denied");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "denied"})
        );
        let mux = muxes.get(PID).expect("the shared mux entry is created");
        assert!(mux.live_sids().await.is_empty());
    }

    #[tokio::test]
    async fn expose_bound_sets_the_scoped_default_and_the_legacy_fold_is_shared() {
        let host = TestHost::new(Verdict::Legacy);
        host.record_grant.store(true, Ordering::Relaxed);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t, true).await;
        conn.links.get_mut(PID).unwrap().verified_name = Some("phone".into());
        let mut muxes = HashMap::new();
        let policy = ShellPolicy::Granted;
        let exposed = |p: u16| p == 2222;
        let allowed = |_n: &str, _h: &str, _p: u16| true;

        // A record grant satisfies the legacy fold without a blanket mode.
        let cfg = config(&policy, &exposed, &allowed, true, false);
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 2222, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Accepted { .. }));
        assert_eq!(host.gates(), vec![(true, true)]);

        // A port outside expose.json clears the scoped bound.
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 2223, SID + 1),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Accepted { .. }));
        assert_eq!(host.gates(), vec![(true, true), (true, false)]);

        // Blanket TUNLION_L2 admits without a record grant; an explicit deny
        // still wins over the blanket.
        host.record_grant.store(false, Ordering::Relaxed);
        let forced = config(&policy, &exposed, &allowed, true, true);
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 2224, SID + 2),
            &mut muxes,
            &forced,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Accepted { .. }));
        host.denied.store(true, Ordering::Relaxed);
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 2225, SID + 3),
            &mut muxes,
            &forced,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Denied(_)));
        assert_eq!(
            host.gates(),
            vec![
                (true, true),
                (true, false),
                (true, false),
                (false, false),
            ]
        );
    }

    #[tokio::test]
    async fn collision_does_not_displace_and_missing_transport_never_gates() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), true).await;
        let mux = Mux::new(t.clone(), conn.host.clone());
        let mut original = mux.register_stream(SID).await.unwrap();
        let mut muxes = HashMap::from([(PID.to_string(), mux.clone())]);
        let policy = ShellPolicy::Granted;
        let exposed = |_p: u16| false;
        let allowed = |_n: &str, _h: &str, _p: u16| true;
        let cfg = config(&policy, &exposed, &allowed, true, true);

        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID),
            &mut muxes,
            &cfg,
        )
        .await;
        let ForwardAdmission::Refused(r) = out else {
            panic!("a live foreign sid must be refused");
        };
        assert_eq!(r.reason, "sid in use");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "sid in use"})
        );
        assert!(Arc::ptr_eq(muxes.get(PID).unwrap(), &mux));
        mux.on_frame(SID, bytes::Bytes::from_static(b"original endpoint"))
            .await;
        assert_eq!(original.recv().await.unwrap().unwrap(), "original endpoint");

        conn.links.get_mut(PID).unwrap().transport = None;
        let out = admit_forward_open(
            &mut conn,
            PID,
            &open("127.0.0.1", 22, SID + 1),
            &mut muxes,
            &cfg,
        )
        .await;
        assert!(matches!(out, ForwardAdmission::Ignored));
        assert_eq!(host.gates().len(), 1, "no transport never reaches the gate");
        assert!(t.controls.lock().unwrap().is_empty());
    }
}
