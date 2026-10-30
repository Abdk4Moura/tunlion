//! Inbound shell-class admission: may a `pty-open`/`exec-open` exist?
//!
//! This is the security half of the two CLI handlers, moved so both live arms
//! and both parked re-drive arms ask one function. The endpoint decides WHO may
//! open, in what order, with which exact refusal, and returns a sanitized frame
//! plan. It never touches a mux, a session map, a PTY or a child process: the
//! caller still owns registration, reattach, acking and spawning.
//!
//! The acceptance order is the contract, preserved from the handlers:
//!
//! * pty: transport, serving close, `wire_sid` + `is_l2_sid`, the shared gate,
//!   the user-drop feasibility check, then frame fields.
//! * exec: serving close (only with transport AND sid, as the old arm),
//!   transport, frame parse, `wire_sid` + `is_l2_sid`, the shared gate.
//!
//! A gate denial is returned, never sent: the caller's existing
//! settle-then-evaluate rule decides whether to park it, and only when it does
//! not does it log, record one consent ask and send the refusal. Serving-off
//! and user-drop refusals are decided and sent here, because they are final and
//! never parked -- [`ShellAdmission::Ignored`] says "nothing left to do".
//!
//! `serving` is passed per call, not captured, so a PARKED open re-reads the
//! L2 switch on every re-drive. That is the fix for the parked exec-open that
//! used to be re-driven straight into the handler and served after L2 was
//! turned off.
//!
//! Nothing here reads a setting, an environment variable, a file or a clock;
//! the host and the link supply every fact. `user_drop_unavailable` is a lazy
//! closure because the uid/argv check is a process fact and runs only after the
//! gate allows, exactly where the CLI ran it.

use crate::conn::{dropped_no_transport, Conn};
use crate::l2::{is_l2_sid, wire_sid};
use crate::refusal::{Code, Refusal};
use crate::shell::exec::{parse_exec_open, ExecOpen};
use crate::shell::off::serving_off_refusal;
use crate::shell_gate::{
    exec_gate_decision, gather_shell_gate_inputs, pty_gate_decision, ShellPolicy,
};
use filament_cap::capability as cap;
use filament_transport::net::Transport;
use serde_json::Value;
use std::sync::Arc;

/// The two host/config facts an inbound shell open needs. The library never
/// reads `TUNLION_L2`, a settings key, an environment variable, a clock or a
/// file.
pub struct ShellAdmissionConfig<'a> {
    /// The acceptor's current shell posture (`--shell`, `--shell-only`, granted).
    pub policy: &'a ShellPolicy,
    /// The caller's `l2_enabled` at this open/re-drive. Passed per call so a
    /// parked open re-reads the switch and cannot be served after it turns off.
    pub serving: bool,
}

/// One admission decision.
pub enum ShellAdmission<A> {
    /// Admitted. The caller owns the shared mux, ack, session lookup, spawn.
    Admitted {
        /// The link the decision examined; use this, not a second lookup.
        transport: Arc<dyn Transport>,
        sid: u32,
        /// The verified name (`gather`'s `dev`) and the resolved device key.
        /// These are admission facts, not frame fields, so they live here
        /// rather than in the verb plan.
        device: Option<String>,
        device_pub: Option<[u8; 32]>,
        /// True when the gate admitted this open through the enrolment ceiling
        /// with no explicit grant. A live session re-checks a narrowed ceiling
        /// only for this population; a grant-admitted one ignores it.
        admitted_via_ceiling: bool,
        plan: A,
    },
    /// Refused by the shared shell gate. The caller's existing
    /// settle-then-evaluate rule decides whether to park it; if not, the caller
    /// logs, records one consent ask, and sends `denial.refusal.close_frame`.
    Denied(ShellDenial),
    /// Nothing to send: no transport, malformed/non-L2 sid, or a local refusal
    /// the endpoint already sent (serving off, user-drop unavailable).
    Ignored,
}

/// A shell-gate denial, before the caller's reinvite and parking rules.
pub struct ShellDenial {
    pub sid: u32,
    pub transport: Arc<dyn Transport>,
    /// The verified device name the gate resolved, if any. `gather` captures it
    /// from the link before `peer_authz`; `resolve_peer_identity` does not set
    /// `verified_name`, so the pre- and post-gate values are the same and this
    /// is also the name the old handler re-read for the consent ask.
    pub device: Option<String>,
    /// The resolved device key, for the caller's expiry re-invite lookup.
    pub device_pub: Option<[u8; 32]>,
    /// The exact wording the caller logs and passes to `park_on_deny`.
    /// pty and exec deliberately differ here (see the module docs).
    pub reason: String,
    /// Code/name already applied; `reinvite` is added by the caller from its
    /// own identity store, exactly where the CLI did it before.
    pub refusal: Refusal,
}

/// A validated `pty-open` frame. No shell resolution, no argv, no spawn.
pub struct PtyOpen {
    /// Device-scoped stable session id (`<device>\u{1}<client id>`, or
    /// `<pid>:<sid>` when the client omitted it).
    pub session: String,
    /// Validated/capped terminal name; terminfo fallback still happens at spawn.
    pub term: String,
    /// One-shot command; empty means an interactive login shell.
    pub cmd: String,
    pub resume: bool,
    pub resume_from: Option<u64>,
    pub cols: u16,
    pub rows: u16,
    /// `gate_inputs.ceiling_covers && !gate_inputs.has_grant`, exactly as pty
    /// computed it before the move.
    pub admitted_via_ceiling: bool,
}

/// Sanitized terminal fields shared by the standing PTY endpoint and the
/// agreement PTY endpoint. This is WIRE SANITIZATION ONLY: who may open, under
/// which policy, remains in the caller's admission path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtyOpenFields {
    pub term: String,
    pub cmd: String,
    pub cols: u16,
    pub rows: u16,
}

/// Apply the historical PTY field defaults/bounds once. `cols`/`rows` keep the
/// existing truncating `as u16` behaviour; `$TERM` is validated and capped.
pub fn parse_pty_open_fields(v: &Value) -> PtyOpenFields {
    PtyOpenFields {
        term: v["term"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_graphic()))
            .unwrap_or("xterm-256color")
            .to_string(),
        cmd: v["cmd"].as_str().unwrap_or("").to_string(),
        cols: v["cols"].as_u64().unwrap_or(80) as u16,
        rows: v["rows"].as_u64().unwrap_or(24) as u16,
    }
}

/// Admit one `pty-open` frame.
///
/// `user_drop_unavailable` is evaluated only after the gate allows, exactly
/// where the CLI checked `--shell-user`/root today. The host owns the uid and
/// argv facts; this endpoint only names the moment.
pub async fn admit_pty_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    cfg: &ShellAdmissionConfig<'_>,
    user_drop_unavailable: impl Fn() -> bool,
) -> ShellAdmission<PtyOpen> {
    let Some(t) = conn.transport_of(pid) else {
        dropped_no_transport(conn.log.as_ref(), pid, "pty open");
        return ShellAdmission::Ignored;
    };
    // #219: the acceptor is OFF (plain `up`, no --shell/--shell-only,
    // no TUNLION_L2). Say so, so the initiator errors instead of waiting.
    if !cfg.serving {
        let sid = wire_sid(v).unwrap_or(0);
        let refusal = serving_off_refusal(conn, pid, Code::ShellOff);
        let _ = t.send_control(&refusal.close_frame(sid)).await;
        return ShellAdmission::Ignored;
    }
    // wire_sid rejects a missing OR out-of-range sid instead of
    // defaulting to 0 / wrapping into a forged is_l2_sid value.
    let Some(sid) = wire_sid(v) else {
        return ShellAdmission::Ignored;
    };
    if !is_l2_sid(sid) {
        return ShellAdmission::Ignored;
    }
    // One shared shell gate (same function, same inputs as exec-open): gather,
    // then the pty entry point.
    let host = conn.host.clone();
    let (device, gate_inputs) = gather_shell_gate_inputs(conn, pid, cfg.policy, cap::CAP_SHELL);
    if let Err(cap_reason) = pty_gate_decision(&gate_inputs, host.as_ref()) {
        let reason = cap_reason
            .as_deref()
            .unwrap_or("no shell cap / untrusted")
            .to_string();
        let refusal = Refusal::from_shell_gate(
            host.cert_forgotten_for(gate_inputs.idev.as_ref()),
            gate_inputs.cert_revoked,
            gate_inputs.denied,
            cap_reason.as_deref(),
            device.clone(),
        );
        return ShellAdmission::Denied(ShellDenial {
            sid,
            transport: t,
            device,
            device_pub: gate_inputs.idev,
            reason,
            refusal,
        });
    }
    // A configured user drop (`--shell-user`, or `set shell-user` applied
    // live) needs root for runuser. Without it the spawn "succeeds" into a
    // shell that dies at once with runuser's own complaint; refuse up front
    // and say which setting is the problem.
    if user_drop_unavailable() {
        let refusal = Refusal::new(Code::UserDropUnavailable, device.clone());
        conn.log
            .say(&format!("l2: pty refused: {}", refusal.reason));
        let _ = t.send_control(&refusal.close_frame(sid)).await;
        return ShellAdmission::Ignored;
    }
    // #4: a stable, client-chosen session id binds reconnects to the same
    // persistent PTY. DEVICE-SCOPED: prefixed with the verified device so a
    // client id from device A can never address device B's session (no
    // cross-device collision or hijack) - the random per-invocation client id
    // then only needs to be unique per device. The client id must not contain
    // the scope separator, or the scoped string would be ambiguous to the
    // resolver at close. Absent/invalid (older client) -> a per-sid id that
    // never reattaches (old behavior).
    let session = match v["session"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.contains('\u{1}'))
    {
        Some(s) => format!("{}\u{1}{}", device.as_deref().unwrap_or(pid), s),
        None => format!("{pid}:{sid:#x}"),
    };
    let fields = parse_pty_open_fields(v);
    let plan = PtyOpen {
        session,
        term: fields.term,
        // One-shot command (non-empty when pty one-shot was requested).
        cmd: fields.cmd,
        // RESUME-ONLY (warm-drop fall-through): the client wants to REATTACH an
        // existing session and never start a fresh shell, so a clean warm exit
        // can't turn into a surprise re-login.
        resume: v["resume"].as_bool().unwrap_or(false),
        resume_from: v["resume_from"].as_u64(),
        cols: fields.cols,
        rows: fields.rows,
        // Ceiling-admitted (covered, grantless) sessions must die when the
        // ceiling narrows; grant-admitted ones ignore it.
        admitted_via_ceiling: gate_inputs.ceiling_covers && !gate_inputs.has_grant,
    };
    ShellAdmission::Admitted {
        transport: t,
        sid,
        device,
        device_pub: gate_inputs.idev,
        admitted_via_ceiling: gate_inputs.ceiling_covers && !gate_inputs.has_grant,
        plan,
    }
}

/// Admit one `exec-open` frame.
pub async fn admit_exec_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    cfg: &ShellAdmissionConfig<'_>,
) -> ShellAdmission<ExecOpen> {
    // The live arm denies an exec-open when serving is off BEFORE the handler,
    // but a PARKED open is re-driven straight here, bypassing that guard. Apply
    // it here so "re-drive re-gathers every input" holds for the L2 switch. The
    // old arm required BOTH a transport and a usable sid to send the close and
    // stayed silent when either was absent; preserve that exactly.
    if !cfg.serving {
        if let (Some(t), Some(sid)) = (conn.transport_of(pid), wire_sid(v)) {
            let refusal = serving_off_refusal(conn, pid, Code::ShellOff);
            let _ = t.send_control(&refusal.close_frame(sid)).await;
        }
        return ShellAdmission::Ignored;
    }
    let Some(t) = conn.transport_of(pid) else {
        dropped_no_transport(conn.log.as_ref(), pid, "exec-open");
        return ShellAdmission::Ignored;
    };
    // exec parses its frame BEFORE the sid, as it always has.
    let Some(plan) = parse_exec_open(v) else {
        return ShellAdmission::Ignored;
    };
    let Some(sid) = wire_sid(v) else {
        return ShellAdmission::Ignored;
    };
    if !is_l2_sid(sid) {
        return ShellAdmission::Ignored;
    }
    let host = conn.host.clone();
    let (device, gate_inputs) = gather_shell_gate_inputs(conn, pid, cfg.policy, cap::CAP_SHELL);
    if let Err(cap_reason) = exec_gate_decision(&gate_inputs, host.as_ref()) {
        let refusal = Refusal::from_shell_gate(
            host.cert_forgotten_for(gate_inputs.idev.as_ref()),
            gate_inputs.cert_revoked,
            gate_inputs.denied,
            cap_reason.as_deref(),
            device.clone(),
        );
        // The historical exec wording is the refusal's own reason; pty's
        // coarse fallback is deliberate and stays there.
        let reason = refusal.reason.clone();
        return ShellAdmission::Denied(ShellDenial {
            sid,
            transport: t,
            device,
            device_pub: gate_inputs.idev,
            reason,
            refusal,
        });
    }
    ShellAdmission::Admitted {
        transport: t,
        sid,
        device,
        device_pub: gate_inputs.idev,
        admitted_via_ceiling: gate_inputs.ceiling_covers && !gate_inputs.has_grant,
        plan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Link, Presence};
    use crate::host::{CapGate, HostServices, NoHost, VecLog};
    use crate::refusal::{CEILING_REASON, SHELL_OFF_REASON, USER_DROP_REASON};
    use crate::shell_gate::ShellPolicy;
    use filament_cap::capability::BindingStrength;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    const PID: &str = "shell-peer";
    const SID: u32 = crate::l2::L2_SID_BASE + 7;
    const ERR_SID: u32 = crate::l2::L2_SID_BASE + 8;
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
        Proven,
        /// Shadow mode, the default: the legacy fold decides.
        Legacy,
    }

    // The policy site is injected, not reimplemented here: the test host records
    // whether the endpoint reached the gate and supplies a verdict. The CLI's
    // own gate suites cover the full capability/store matrix.
    struct TestHost {
        verdict: Verdict,
        cert_revoked: AtomicBool,
        record_grant: AtomicBool,
        denied: AtomicBool,
        ceiling_covers: AtomicBool,
        ceiling_for: Mutex<Option<Vec<String>>>,
        /// `devices_load`: the records holding a pair secret.
        paired: Mutex<Vec<(String, String)>>,
        enqueues: Mutex<Vec<(String, String)>>,
        gates: Mutex<usize>,
    }

    impl TestHost {
        fn new(verdict: Verdict) -> Arc<Self> {
            Arc::new(Self {
                verdict,
                cert_revoked: AtomicBool::new(false),
                record_grant: AtomicBool::new(false),
                denied: AtomicBool::new(false),
                ceiling_covers: AtomicBool::new(false),
                ceiling_for: Mutex::new(None),
                paired: Mutex::new(Vec::new()),
                enqueues: Mutex::new(Vec::new()),
                gates: Mutex::new(0),
            })
        }

        fn gates(&self) -> usize {
            *self.gates.lock().unwrap()
        }

        fn enqueues(&self) -> Vec<(String, String)> {
            self.enqueues.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HostServices for TestHost {
        fn settings_get_str(&self, key: &str) -> Option<String> {
            NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            self.paired.lock().unwrap().clone()
        }
        fn is_self_uid(&self, a: &str, b: Option<&str>) -> bool {
            NoHost.is_self_uid(a, b)
        }
        fn rejoin_unwarned(&self) -> std::time::Duration {
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
        fn cert_revoked_for(&self, _device_pub: Option<&[u8; 32]>) -> bool {
            self.cert_revoked.load(Ordering::Relaxed)
        }
        fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
            self.denied.load(Ordering::Relaxed)
        }
        fn principal_ceiling_for(&self, _name: &str) -> Option<Vec<String>> {
            self.ceiling_for.lock().unwrap().clone()
        }
        fn ceiling_covers_action(&self, _device_pub: Option<&[u8; 32]>, _action: &str) -> bool {
            self.ceiling_covers.load(Ordering::Relaxed)
        }
        fn enqueue_request_if_requestable(&self, peer: &str, capability: &str) {
            self.enqueues
                .lock()
                .unwrap()
                .push((peer.to_string(), capability.to_string()));
        }
        fn cap_gate_effective(&self, _gate: CapGate<'_>) -> cap::GateDecision {
            *self.gates.lock().unwrap() += 1;
            match &self.verdict {
                Verdict::Allow => cap::GateDecision::Allow,
                Verdict::Deny(reason) => cap::GateDecision::Deny {
                    cap_reason: reason.clone(),
                },
                Verdict::Proven if _gate.binding == BindingStrength::Proven => {
                    cap::GateDecision::Allow
                }
                Verdict::Proven => cap::GateDecision::Deny { cap_reason: None },
                Verdict::Legacy if _gate.legacy_allowed => cap::GateDecision::Allow,
                Verdict::Legacy => cap::GateDecision::Deny { cap_reason: None },
            }
        }
    }

    async fn connection(
        host: Arc<TestHost>,
        t: Arc<CaptureTransport>,
        verified: Option<&str>,
    ) -> (Conn, tokio::net::TcpStream) {
        let (sio, far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let log: Arc<VecLog> = Arc::new(VecLog::new());
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
            log,
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
                attempts: 0,
                trusted: true,
                expected_secret: None,
                verified_name: verified.map(str::to_string),
                presence: Presence::Ready,
                direct: true,
                direct_route: "direct-quic",
                established_at: None,
                identity_device_pub: Some(DEVICE),
                identity_user_pub: Some([3; 32]),
                identity_binding: BindingStrength::Proven,
                identity_cert_expires: Some(1000),
                principal_kind: cap::PrincipalKind::OwnerDevice,
                host,
            },
        );
        (conn, far)
    }

    fn cfg<'a>(policy: &'a ShellPolicy, serving: bool) -> ShellAdmissionConfig<'a> {
        ShellAdmissionConfig { policy, serving }
    }

    fn pty_frame(extra: Value) -> Value {
        let mut v = json!({"type": "pty-open", "sid": SID});
        merge(&mut v, &extra);
        v
    }

    fn exec_frame(extra: Value) -> Value {
        let mut v = json!({
            "type": "exec-open", "sid": SID, "err_sid": ERR_SID,
            "argv": ["true"],
        });
        merge(&mut v, &extra);
        v
    }

    fn merge(dst: &mut Value, extra: &Value) {
        if let (Some(dst), Some(src)) = (dst.as_object_mut(), extra.as_object()) {
            for (k, val) in src {
                dst.insert(k.clone(), val.clone());
            }
        }
    }

    #[tokio::test]
    async fn pty_plan_is_device_scoped_and_sanitized() {
        let host = TestHost::new(Verdict::Allow);
        host.ceiling_covers.store(true, Ordering::Relaxed);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, Some("phone")).await;
        let policy = ShellPolicy::Granted;

        let v = pty_frame(json!({
            "session": "client-1",
            // 65_560 truncates to 24 like the old `as u16` cast.
            "term": "xterm-256color", "cols": 300, "rows": 65_560u64,
            "cmd": "id -un", "resume": true, "resume_from": 12,
        }));
        let out = admit_pty_open(&mut conn, PID, &v, &cfg(&policy, true), || false).await;
        let ShellAdmission::Admitted {
            transport,
            sid,
            device,
            device_pub,
            plan,
            ..
        } = out
        else {
            panic!("a granted device is admitted");
        };
        assert!(transport.is_alive());
        assert_eq!(sid, SID);
        assert_eq!(device.as_deref(), Some("phone"));
        assert_eq!(device_pub, Some(DEVICE));
        assert_eq!(plan.session, "phone\u{1}client-1");
        assert_eq!(plan.term, "xterm-256color");
        assert_eq!(
            (plan.cols, plan.rows),
            (300, 24),
            "truncating cast is preserved"
        );
        assert_eq!(plan.cmd, "id -un");
        assert!(plan.resume);
        assert_eq!(plan.resume_from, Some(12));
        assert!(plan.admitted_via_ceiling, "covered and grantless");

        // Absent, empty, over-long and separator-bearing session ids fall back
        // to the per-sid id: a client id containing `\u{1}` would make the
        // device scope ambiguous when a close resolves it.
        for bad in [
            Value::Null,
            json!(""),
            json!("x".repeat(129)),
            json!("dev\u{1}client"),
        ] {
            let v = pty_frame(json!({"session": bad.clone()}));
            let out = admit_pty_open(&mut conn, PID, &v, &cfg(&policy, true), || false).await;
            let ShellAdmission::Admitted { plan, .. } = out else {
                panic!("still admitted");
            };
            assert_eq!(plan.session, format!("{PID}:{SID:#x}"), "{bad}");
        }

        // A non-graphic or over-long term falls back; defaults are 80x24.
        for bad in [json!("xterm 256"), json!("x".repeat(65)), json!(42)] {
            let v = pty_frame(json!({"term": bad.clone()}));
            let out = admit_pty_open(&mut conn, PID, &v, &cfg(&policy, true), || false).await;
            let ShellAdmission::Admitted { plan, .. } = out else {
                panic!("still admitted");
            };
            assert_eq!(plan.term, "xterm-256color", "{bad}");
            assert_eq!((plan.cols, plan.rows), (80, 24));
            assert_eq!(plan.cmd, "");
            assert!(!plan.resume);
            assert_eq!(plan.resume_from, None);
        }
    }

    #[tokio::test]
    async fn unverified_pty_sessions_are_scoped_to_the_pid() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, None).await;
        let policy = ShellPolicy::Granted;
        let v = pty_frame(json!({"session": "client-1"}));
        let out = admit_pty_open(&mut conn, PID, &v, &cfg(&policy, true), || false).await;
        let ShellAdmission::Admitted { device, plan, .. } = out else {
            panic!("gate allows");
        };
        assert_eq!(device, None);
        assert_eq!(plan.session, format!("{PID}\u{1}client-1"));
    }

    #[tokio::test]
    async fn a_client_session_id_cannot_carry_the_scope_separator() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, Some("phone")).await;
        let policy = ShellPolicy::Granted;
        // The separator is the acceptor's, so a client that spells a scoped id
        // must not get it re-scoped (or matched) as if it were another device's.
        let v = pty_frame(json!({"session": "phone\u{1}victim"}));
        let out = admit_pty_open(&mut conn, PID, &v, &cfg(&policy, true), || false).await;
        let ShellAdmission::Admitted { plan, .. } = out else {
            panic!("gate allows");
        };
        assert_eq!(
            plan.session,
            format!("{PID}:{SID:#x}"),
            "a client id carrying the separator falls back to the per-sid id"
        );
    }

    #[tokio::test]
    async fn exec_plan_carries_argv_and_the_admission_identity() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, Some("phone")).await;
        let policy = ShellPolicy::Granted;
        let v = exec_frame(json!({
            "argv": ["rsync", "-a", "dir with space"],
            "cwd": "/tmp", "env": ["FOO=bar"], "tty": true, "alive_ms": 2000,
        }));
        let out = admit_exec_open(&mut conn, PID, &v, &cfg(&policy, true)).await;
        let ShellAdmission::Admitted {
            sid,
            device,
            device_pub,
            plan,
            ..
        } = out
        else {
            panic!("a granted device is admitted");
        };
        assert_eq!(sid, SID);
        assert_eq!(device.as_deref(), Some("phone"));
        assert_eq!(device_pub, Some(DEVICE));
        assert_eq!(plan.argv, vec!["rsync", "-a", "dir with space"]);
        assert_eq!(plan.cwd, Some(std::path::PathBuf::from("/tmp")));
        assert_eq!(plan.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert!(plan.tty);
        assert_eq!(plan.err_sid, ERR_SID);
        assert_eq!(plan.alive_ms, Some(2000));
    }

    #[tokio::test]
    async fn serving_off_pty_closes_with_sid_zero_and_never_gates() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let policy = ShellPolicy::Granted;
        // No sid at all: pty still names sid 0 and sends the shell-off close.
        let out = admit_pty_open(
            &mut conn,
            PID,
            &json!({"type": "pty-open", "session": "s"}),
            &cfg(&policy, false),
            || panic!("user-drop must not be reached"),
        )
        .await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert_eq!(
            *t.controls.lock().unwrap(),
            vec![json!({
                "type": "l2-close",
                "sid": 0,
                "err": SHELL_OFF_REASON,
                "code": "shell-off",
                "as": "phone",
            })]
        );
        assert_eq!(host.gates(), 0, "the guard precedes the gate");
        assert_eq!(
            host.enqueues(),
            vec![("phone".to_string(), "shell".to_string())]
        );
    }

    #[tokio::test]
    async fn serving_off_exec_stays_silent_without_a_sid() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let policy = ShellPolicy::Granted;
        let out = admit_exec_open(
            &mut conn,
            PID,
            &json!({"type": "exec-open", "argv": ["true"]}),
            &cfg(&policy, false),
        )
        .await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert!(
            t.controls.lock().unwrap().is_empty(),
            "old arm needed transport AND sid"
        );
        assert_eq!(host.gates(), 0);
        assert!(host.enqueues().is_empty(), "no close, no ask");
    }

    #[tokio::test]
    async fn serving_off_outside_a_ceiling_refuses_without_an_ask() {
        let host = TestHost::new(Verdict::Allow);
        *host.ceiling_for.lock().unwrap() = Some(vec!["transfer".into()]);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("guest")).await;
        let policy = ShellPolicy::Granted;
        let out =
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, false)).await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert_eq!(
            *t.controls.lock().unwrap(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": CEILING_REASON,
                "code": "ceiling",
                "as": "guest",
            })]
        );
        assert!(
            host.enqueues().is_empty(),
            "a ceiling cannot be granted away"
        );
    }

    #[tokio::test]
    async fn gate_denials_differ_in_wording_and_send_nothing() {
        let host = TestHost::new(Verdict::Deny(None));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let log = Arc::new(VecLog::new());
        conn.log = log.clone();
        let policy = ShellPolicy::Granted;

        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, true),
            || false,
        )
        .await;
        let ShellAdmission::Denied(d) = out else {
            panic!("an ungranted device is denied");
        };
        assert_eq!(d.sid, SID);
        assert_eq!(d.reason, "no shell cap / untrusted");
        assert_eq!(d.refusal.code, Code::NotGranted);
        assert_eq!(d.refusal.reason, "shell not granted to 'phone' here");
        assert_eq!(d.device.as_deref(), Some("phone"));
        assert_eq!(d.device_pub, Some(DEVICE));

        let out =
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, true)).await;
        let ShellAdmission::Denied(d) = out else {
            panic!("an ungranted device is denied");
        };
        assert_eq!(d.reason, "shell not granted to 'phone' here");
        assert_eq!(d.refusal.code, Code::NotGranted);

        assert!(
            t.controls.lock().unwrap().is_empty(),
            "the caller sends the denial"
        );
        assert!(host.enqueues().is_empty(), "the caller asks once");
        assert_eq!(host.gates(), 2);
        assert!(log.take().is_empty(), "denial tells belong to the caller");
    }

    #[tokio::test]
    async fn a_revoked_certificate_classifies_as_cert_revoked_on_both_paths() {
        let host = TestHost::new(Verdict::Deny(Some("device revoked".into())));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, Some("phone")).await;
        let policy = ShellPolicy::Granted;
        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, true),
            || false,
        )
        .await;
        let ShellAdmission::Denied(d) = out else {
            panic!("denied");
        };
        assert_eq!(d.reason, "device revoked");
        assert_eq!(d.refusal.code, Code::CertRevoked);
        assert_eq!(d.refusal.reason, "device revoked");

        let out =
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, true)).await;
        let ShellAdmission::Denied(d) = out else {
            panic!("denied");
        };
        assert_eq!(d.reason, "device revoked");
        assert_eq!(d.refusal.code, Code::CertRevoked);
    }

    #[tokio::test]
    async fn pty_user_drop_is_checked_after_allow_and_never_parks_or_asks() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let log = Arc::new(VecLog::new());
        conn.log = log.clone();
        let policy = ShellPolicy::Granted;
        let called = AtomicBool::new(false);
        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, true),
            || {
                called.store(true, Ordering::Relaxed);
                true
            },
        )
        .await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert!(called.load(Ordering::Relaxed));
        assert_eq!(
            *t.controls.lock().unwrap(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": USER_DROP_REASON,
                "code": "user-drop-unavailable",
                "as": "phone",
            })]
        );
        assert!(host.enqueues().is_empty());
        assert_eq!(
            log.take(),
            vec![(
                crate::host::Level::Info,
                format!("l2: pty refused: {USER_DROP_REASON}")
            )]
        );

        // A gate deny wins: the closure is never called.
        let host = TestHost::new(Verdict::Deny(None));
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host, t, Some("phone")).await;
        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, true),
            || panic!("must not run after a gate deny"),
        )
        .await;
        assert!(matches!(out, ShellAdmission::Denied(_)));
    }

    #[tokio::test]
    async fn missing_transport_bad_sid_and_low_sid_are_ignored_silently() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let policy = ShellPolicy::Granted;

        // Bad (over-u32) and low-half sids never reach the gate.
        for sid in [json!(u32::MAX as u64 + 1), json!(7)] {
            let out = admit_pty_open(
                &mut conn,
                PID,
                &pty_frame(json!({"sid": sid.clone()})),
                &cfg(&policy, true),
                || false,
            )
            .await;
            assert!(matches!(out, ShellAdmission::Ignored), "{sid}");
            let out = admit_exec_open(
                &mut conn,
                PID,
                &exec_frame(json!({"sid": sid.clone()})),
                &cfg(&policy, true),
            )
            .await;
            assert!(matches!(out, ShellAdmission::Ignored), "{sid}");
        }
        assert_eq!(host.gates(), 0);
        assert!(t.controls.lock().unwrap().is_empty());

        // A link with no transport logs the exact dropped word, sends nothing.
        conn.links.get_mut(PID).unwrap().transport = None;
        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, true),
            || false,
        )
        .await;
        assert!(matches!(out, ShellAdmission::Ignored));
        let out =
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, true)).await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert_eq!(host.gates(), 0);
        assert!(t.controls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn denial_frames_preserve_all_shell_causes_without_tells() {
        let expired = crate::refusal::expired_reason(1);
        for (reason, denied, cert_revoked, code, err) in [
            (
                None,
                false,
                false,
                "not-granted",
                "shell not granted to 'phone' here".to_string(),
            ),
            (
                None,
                true,
                false,
                "revoked",
                "shell revoked for 'phone' here".to_string(),
            ),
            (
                None,
                false,
                true,
                "cert-revoked",
                "device revoked".to_string(),
            ),
            (
                Some(CEILING_REASON.to_string()),
                false,
                false,
                "ceiling",
                CEILING_REASON.to_string(),
            ),
            (Some(expired.clone()), false, false, "expired", expired),
        ] {
            let host = TestHost::new(Verdict::Deny(reason.clone()));
            host.denied.store(denied, Ordering::Relaxed);
            host.cert_revoked.store(cert_revoked, Ordering::Relaxed);
            let t = Arc::new(CaptureTransport::default());
            let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
            let log = Arc::new(VecLog::new());
            conn.log = log.clone();
            let policy = ShellPolicy::Granted;
            let expected = json!({
                "type": "l2-close", "sid": SID, "code": code, "err": err, "as": "phone",
            });
            let ShellAdmission::Denied(d) = admit_pty_open(
                &mut conn,
                PID,
                &pty_frame(json!({})),
                &cfg(&policy, true),
                || panic!("denied before user-drop"),
            )
            .await
            else {
                panic!("expected pty denial")
            };
            assert_eq!(
                d.reason,
                reason.as_deref().unwrap_or("no shell cap / untrusted")
            );
            assert_eq!(d.refusal.close_frame(SID), expected);
            let ShellAdmission::Denied(d) =
                admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, true)).await
            else {
                panic!("expected exec denial")
            };
            assert_eq!(d.reason, d.refusal.reason);
            assert_eq!(d.refusal.close_frame(SID), expected);
            assert_eq!(host.gates(), 2);
            assert!(host.enqueues().is_empty());
            assert!(t.controls.lock().unwrap().is_empty());
            assert!(log.take().is_empty());
        }
    }

    #[tokio::test]
    async fn malformed_exec_frames_never_authorize_or_send() {
        let host = TestHost::new(Verdict::Allow);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let policy = ShellPolicy::Granted;
        for extra in [
            json!({"argv": null}),
            json!({"argv": []}),
            json!({"argv": [42]}),
            json!({"argv": "true"}),
            json!({"err_sid": null}),
            json!({"err_sid": 1}),
            json!({"err_sid": 0x1_8000_0000u64}),
            json!({"sid": null}),
        ] {
            assert!(matches!(
                admit_exec_open(&mut conn, PID, &exec_frame(extra), &cfg(&policy, true),).await,
                ShellAdmission::Ignored
            ));
        }
        assert_eq!(host.gates(), 0);
        assert!(t.controls.lock().unwrap().is_empty());
        assert!(host.enqueues().is_empty());
    }

    #[tokio::test]
    async fn serving_off_with_no_verified_name_does_not_ask() {
        for name in [None, Some("")] {
            let host = TestHost::new(Verdict::Allow);
            let t = Arc::new(CaptureTransport::default());
            let (mut conn, _far) = connection(host.clone(), t.clone(), name).await;
            let policy = ShellPolicy::Granted;
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(&policy, false)).await;
            assert!(host.enqueues().is_empty());
            assert_eq!(host.gates(), 0);
            let mut expected = json!({
                "type": "l2-close", "sid": SID, "err": SHELL_OFF_REASON, "code": "shell-off",
            });
            if let Some(name) = name {
                expected["as"] = json!(name);
            }
            assert_eq!(*t.controls.lock().unwrap(), vec![expected]);
        }
    }

    /// The regression: a parked exec-open re-driven after serving was turned
    /// off used to re-enter the handler and be SERVED. Every re-drive now
    /// passes here, where the current `serving` is read.
    /// This exercises the endpoint with a stored frame and a changed binding;
    /// it does not exercise the CLI's actual parking queue or sweep.
    #[tokio::test]
    async fn a_parked_exec_redrive_after_l2_off_is_refused_not_served() {
        let host = TestHost::new(Verdict::Proven);
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t.clone(), Some("phone")).await;
        let policy = ShellPolicy::Granted;
        let frame = exec_frame(json!({}));

        conn.links.get_mut(PID).unwrap().identity_binding = BindingStrength::Inferred;
        let out = admit_exec_open(&mut conn, PID, &frame, &cfg(&policy, true)).await;
        assert!(matches!(out, ShellAdmission::Denied(_)));
        assert!(
            t.controls.lock().unwrap().is_empty(),
            "caller may park the denied frame"
        );
        conn.links.get_mut(PID).unwrap().identity_binding = BindingStrength::Proven;

        // The same stored frame, re-driven with the switch off.
        let out = admit_exec_open(&mut conn, PID, &frame, &cfg(&policy, false)).await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert_eq!(
            host.gates(),
            1,
            "serving-off re-drive must not reach authorization"
        );
        assert_eq!(
            *t.controls.lock().unwrap(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": SHELL_OFF_REASON,
                "code": "shell-off",
                "as": "phone",
            })]
        );

        // And pty's re-drive keeps its guard too.
        let out = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(&policy, false),
            || false,
        )
        .await;
        assert!(matches!(out, ShellAdmission::Ignored));
        assert_eq!(t.controls.lock().unwrap().len(), 2);
        let out = admit_exec_open(&mut conn, PID, &frame, &cfg(&policy, true)).await;
        assert!(matches!(out, ShellAdmission::Admitted { .. }));
        assert_eq!(
            host.gates(),
            2,
            "serving-on re-drive gathers a fresh verdict"
        );
    }

    /// The same device over its two paths. `direct` is a fresh CLI dial: the
    /// pair secret was proven, so the link is pair-`trusted`. `warm` is the
    /// daemon's link verified by fleet-hello: Proven by certificate, named from
    /// that key, never pair-`trusted`.
    fn as_path(conn: &mut Conn, warm: bool) {
        let l = conn.links.get_mut(PID).unwrap();
        if warm {
            l.trusted = false;
            l.principal_kind = cap::PrincipalKind::FleetSibling;
        } else {
            l.trusted = true;
            l.principal_kind = cap::PrincipalKind::OwnerDevice;
        }
    }

    fn only(names: &[&str]) -> ShellPolicy {
        ShellPolicy::Only(names.iter().map(|n| n.to_string()).collect())
    }

    async fn exec_and_pty_admitted(
        host: &Arc<TestHost>,
        policy: &ShellPolicy,
        name: &str,
        warm: bool,
        binding: BindingStrength,
    ) -> (bool, bool) {
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) = connection(host.clone(), t, Some(name)).await;
        as_path(&mut conn, warm);
        conn.links.get_mut(PID).unwrap().identity_binding = binding;
        let exec =
            admit_exec_open(&mut conn, PID, &exec_frame(json!({})), &cfg(policy, true)).await;
        let pty = admit_pty_open(
            &mut conn,
            PID,
            &pty_frame(json!({})),
            &cfg(policy, true),
            || false,
        )
        .await;
        (
            matches!(exec, ShellAdmission::Admitted { .. }),
            matches!(pty, ShellAdmission::Admitted { .. }),
        )
    }

    /// `up --shell-only dovm` admitted dovm on a direct dial and refused it,
    /// "shell not granted to 'dovm' here", when the exec rode dovm's warm
    /// link, because the policy term read pair trust alone and a fleet link
    /// never has it. The direct decision is the reference.
    #[tokio::test]
    async fn shell_only_admits_the_paired_device_on_its_warm_fleet_link() {
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("dovm".into(), "pair-secret".into())];
        for policy in [only(&["dovm"]), ShellPolicy::All] {
            let direct =
                exec_and_pty_admitted(&host, &policy, "dovm", false, BindingStrength::Proven).await;
            assert_eq!(direct, (true, true), "the reference: direct dial admitted");
            let warm =
                exec_and_pty_admitted(&host, &policy, "dovm", true, BindingStrength::Proven).await;
            assert_eq!(
                warm, direct,
                "the warm link decides as the direct dial does"
            );
        }
    }

    /// Never wider than the direct dial: every case the direct path refuses
    /// (or could never reach) is refused on the fleet link too.
    #[tokio::test]
    async fn shell_only_refuses_on_the_fleet_link_what_the_direct_dial_refuses() {
        // Not listed: refused on both paths.
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("dovm".into(), "pair-secret".into())];
        let policy = only(&["laptop"]);
        for warm in [false, true] {
            let got =
                exec_and_pty_admitted(&host, &policy, "dovm", warm, BindingStrength::Proven).await;
            assert_eq!(got, (false, false), "unlisted device, warm={warm}");
        }

        // A fleet sibling with no pair secret: a direct dial can never prove a
        // pairing, so neither the scoped nor the blanket policy speaks for it.
        let host = TestHost::new(Verdict::Legacy);
        for policy in [only(&["dovm"]), ShellPolicy::All] {
            let got =
                exec_and_pty_admitted(&host, &policy, "dovm", true, BindingStrength::Proven).await;
            assert_eq!(got, (false, false), "unpaired sibling, {}", policy.label());
        }

        // The paired record is a DIFFERENT device than the one the fleet
        // certificate resolved to.
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("laptop".into(), "pair-secret".into())];
        let got = exec_and_pty_admitted(
            &host,
            &only(&["dovm", "laptop"]),
            "dovm",
            true,
            BindingStrength::Proven,
        )
        .await;
        assert_eq!(
            got,
            (false, false),
            "a pairing of another record does not transfer"
        );

        // A record whose secret is empty is not a pairing.
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("dovm".into(), String::new())];
        let got = exec_and_pty_admitted(
            &host,
            &only(&["dovm"]),
            "dovm",
            true,
            BindingStrength::Proven,
        )
        .await;
        assert_eq!(got, (false, false), "empty secret");

        // A fleet link whose identity is not Proven is not fleet-proven.
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("dovm".into(), "pair-secret".into())];
        let got = exec_and_pty_admitted(
            &host,
            &only(&["dovm"]),
            "dovm",
            true,
            BindingStrength::Inferred,
        )
        .await;
        assert_eq!(got, (false, false), "inferred binding");

        // An explicit deny still wins on both paths.
        let host = TestHost::new(Verdict::Legacy);
        *host.paired.lock().unwrap() = vec![("dovm".into(), "pair-secret".into())];
        host.denied.store(true, Ordering::Relaxed);
        for warm in [false, true] {
            let got = exec_and_pty_admitted(
                &host,
                &only(&["dovm"]),
                "dovm",
                warm,
                BindingStrength::Proven,
            )
            .await;
            assert_eq!(got, (false, false), "denied, warm={warm}");
        }
    }
}
