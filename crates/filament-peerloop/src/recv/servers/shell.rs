//! PTY-open orchestration: admission, reattach-vs-spawn, mux registration,
//! ack/replay ordering and session identity. Process spawn, PTY IO, user-drop
//! argv resolution, the process-wide PTY cap and the session map are host
//! effects behind [`PtyBackend`]; this module owns every protocol/state
//! decision.
//!
//! `pty-server` is default-on. A build without it keeps the frame vocabulary
//! and the shared admission code, compiles no PTY backend, and answers a
//! well-formed open with a NAMED `l2-close` instead of silence, exactly like
//! the reduced sync and exec receivers.

use crate::conn::Conn;
use crate::l2::{self, Mux};
use crate::recv::dispatch::ParkedOpen;
#[cfg(feature = "pty-server")]
use crate::recv::dispatch::{park_on_deny, ParkKind};
use crate::recv::ports::RecvPorts;
#[cfg(feature = "pty-server")]
use crate::shell::ShellHost;
use crate::shell_gate::ShellPolicy;
use async_trait::async_trait;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// The named refusal a build without `pty-server` sends.
pub const PTY_SERVER_UNAVAILABLE: &str = "pty receive is not available in this build";

/// The honest close for a reduced build that admitted the frame vocabulary but
/// has no PTY state machine. Testable without a Conn.
pub fn pty_unavailable_close(v: &Value) -> Option<(u32, Value)> {
    let sid = l2::wire_sid(v)?;
    // Parity with the mount/sync/exec reduced refusals: only a valid L2-half
    // sid names a stream this build could have opened. A low-half or wrapped
    // value is not a PTY stream and must not be echoed into an `l2-close`.
    if !l2::is_l2_sid(sid) {
        return None;
    }
    Some((
        sid,
        json!({
            "type": "l2-close",
            "sid": sid,
            "err": PTY_SERVER_UNAVAILABLE,
        }),
    ))
}

/// Admission-free named refusal for a build with `pty-server` off.
///
/// The reduced open runs BEFORE admission: it has no serving gate or session
/// store, so it answers only a syntactically valid L2-half sid. Every
/// serving-off/denial rule stays in the full state machine's `admit_pty_open`.
pub async fn open_pty_unavailable(conn: &Conn, pid: &str, v: &Value) {
    if let (Some((_, close)), Some(t)) = (pty_unavailable_close(v), conn.transport_of(pid)) {
        let _ = t.send_control(&close).await;
    }
}

/// What an open does once admission has passed and the session store answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PtyAction {
    Reattach,
    Spawn,
    /// A resume-only open whose session is gone: close with NO_SUCH_SESSION.
    CloseNoSession,
}

pub fn pty_open_action(live_session: bool, resume: bool) -> PtyAction {
    if live_session {
        PtyAction::Reattach
    } else if resume {
        PtyAction::CloseNoSession
    } else {
        PtyAction::Spawn
    }
}

/// A live PTY session. The host owns the child and IO; the library owns the
/// session identity and which link/sid it is attached to.
pub trait PtySession: Send + Sync {
    /// Downcast seam for the host's pump task (the library never inspects it).
    ///
    /// REQUIRED, deliberately: a host that cannot name its own session type
    /// must fail to compile here rather than default to `&()` and silently
    /// start no pumps after the ack, which hangs the initiator.
    fn as_any(&self) -> &dyn std::any::Any;
    fn attach(&self, t: Arc<dyn Transport>, sid: u32, resume_from: Option<u64>);
    fn resize(&self, cols: u16, rows: u16);
    fn detach(&self);
    fn end(&self);
}

/// Everything the host needs to create one PTY session.
pub struct PtySpawnSpec {
    pub session_id: String,
    pub transport: Arc<dyn Transport>,
    pub sid: u32,
    pub cols: u16,
    pub rows: u16,
    pub term: String,
    pub argv: Vec<String>,
    pub device_pub: Option<[u8; 32]>,
    pub admitted_via_ceiling: bool,
}

#[async_trait]
pub trait PtyBackend: Send + Sync {
    async fn get_live(&self, session_id: &str) -> Option<Arc<dyn PtySession>>;
    /// Reserve the process-wide PTY slot. The opaque token is handed to
    /// `spawn`, so the cap cannot be lost between check and creation.
    fn reserve(&self) -> Option<Box<dyn std::any::Any + Send>>;
    /// Spawn with the reserved slot; `None` means the backend already sent the
    /// precise `l2-close{err}`.
    async fn spawn(
        &self,
        spec: PtySpawnSpec,
        reservation: Box<dyn std::any::Any + Send>,
    ) -> Option<Arc<dyn PtySession>>;
    /// Drop the host's record of a session that has just been ended.
    ///
    /// REQUIRED, deliberately: `end()` is asynchronous, so a `pty-close`
    /// followed by a re-open with the same stable id must not find the dying
    /// handle and take the reattach path. The host's session map is the only
    /// place that can answer "is this id still live", so it is the only place
    /// that can forget it.
    async fn forget(&self, session_id: &str);
    /// Pump inbound stream bytes and resize events into the session.
    fn start_pumps(
        &self,
        session: Arc<dyn PtySession>,
        input: mpsc::Receiver<PipeItem>,
        resize: mpsc::UnboundedReceiver<(u16, u16)>,
    );
    /// Resolve the shell argv. Whether the user drop can actually run is a
    /// separate admission fact: [`PtyBackend::user_drop_available`].
    fn shell_argv(&self, shell_user: &Option<String>) -> Vec<String>;
    /// The host's user-drop explanation is empty when the drop can run.
    fn user_drop_available(&self, shell_user: &Option<String>) -> bool;
}

pub type PipeItem = l2::PipeItem;

#[cfg(feature = "pty-server")]
#[allow(clippy::too_many_arguments)]
pub async fn open_pty(
    ports: &RecvPorts,
    conn: &mut Conn,
    pid: String,
    v: &Value,
    shell_policy: &ShellPolicy,
    shell_user: &Option<String>,
    muxes: &mut HashMap<String, Arc<Mux>>,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
    l2_enabled: bool,
    parked: &mut Vec<ParkedOpen>,
) {
    let backend = ports.pty.as_ref();
    let admission = crate::shell::admit::admit_pty_open(
        conn,
        &pid,
        v,
        &crate::shell::admit::ShellAdmissionConfig {
            policy: shell_policy,
            serving: l2_enabled,
        },
        || backend.user_drop_available(shell_user),
    )
    .await;
    let (t, sid, dev, device_pub, plan) = match admission {
        crate::shell::admit::ShellAdmission::Admitted {
            transport,
            sid,
            device,
            device_pub,
            plan,
        } => (transport, sid, device, device_pub, plan),
        crate::shell::admit::ShellAdmission::Ignored => return,
        crate::shell::admit::ShellAdmission::Denied(d) => {
            let known = |p: &[u8; 32]| ports.store.devices_find_by_device_pub(p).is_some();
            let revoked = |p: &[u8; 32]| ports.identity.device_cert_revoked(p);
            let delegated = |p: &[u8; 32]| {
                conn.host
                    .delegated_access_for(p)
                    .is_some_and(|a| a.expired(filament_id::now_secs()))
            };
            let denied = |n: &str, c: &str| conn.host.device_capability_denied(n, c);
            if park_on_deny(
                &known,
                &revoked,
                &delegated,
                &denied,
                ports.identity.gate_settle_ms(),
                parked,
                conn,
                &pid,
                ParkKind::Pty,
                &d.transport,
                d.sid,
                v,
                &d.reason,
            )
            .await
            {
                return;
            }
            let who = d.device.as_deref().unwrap_or("<unverified>");
            conn.log
                .say(&format!("l2: pty refused: {who}: {}", d.reason));
            conn.host.enqueue_request_if_requestable(who, "shell");
            let refusal = ports
                .identity
                .reinvite_refusal(d.refusal, d.device_pub.as_ref());
            let _ = d.transport.send_control(&refusal.close_frame(d.sid)).await;
            return;
        }
    };
    let session_id = plan.session;
    let term = plan.term;
    let pty_cmd = plan.cmd;
    let resume = plan.resume;
    let cols = plan.cols;
    let rows = plan.rows;
    let mux = muxes
        .entry(pid.clone())
        .or_insert_with(|| l2::Mux::new(t.clone(), conn.host.clone()))
        .clone();
    let live_session = backend.get_live(&session_id).await;
    match pty_open_action(live_session.is_some(), resume) {
        PtyAction::Reattach => {
            let Some(sess) = live_session else { return };
            if mux.at_stream_cap().await {
                conn.log
                    .say("l2: pty reattach refused: too many streams on this link");
                let _ = t
                    .send_control(
                        &json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }),
                    )
                    .await;
                return;
            }
            let Some(rx) = mux.register_stream(sid).await else {
                conn.log
                    .say(&format!("l2: pty reattach refused: sid {sid:#x} in use"));
                let _ = t
                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
                    .await;
                return;
            };
            let (rtx, rrx) = mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, rtx).await;
            let _ = t
                .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
                .await;
            sess.attach(t.clone(), sid, plan.resume_from);
            sess.resize(cols, rows);
            bindings
                .entry(pid.clone())
                .or_default()
                .insert(sid, session_id.clone());
            backend.start_pumps(sess.clone(), rx, rrx);
            conn.log.say(&format!(
                "l2: pty REATTACHED to '{}', {cols}x{rows}",
                dev.unwrap_or_default()
            ));
            return;
        }
        PtyAction::CloseNoSession => {
            let _ = t
                .send_control(&json!({
                    "type": "l2-close",
                    "sid": sid,
                    "err": crate::l2::NO_SUCH_SESSION,
                }))
                .await;
            return;
        }
        PtyAction::Spawn => {}
    }
    if mux.at_stream_cap().await {
        conn.log
            .say("l2: pty refused: too many streams on this link");
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
            .await;
        return;
    }
    // The cap is the host's: `reserve` returns the one slot it enforces, and
    // the same figure is named in the log, so the refusal cannot drift from
    // the check. No second constant lives here.
    let Some(reservation) = backend.reserve() else {
        conn.log.say(&format!(
            "l2: pty refused: too many PTYs (global cap {})",
            l2::MAX_PTYS_GLOBAL
        ));
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
            .await;
        return;
    };
    let Some(rx) = mux.register_stream(sid).await else {
        conn.log
            .say(&format!("l2: pty refused: sid {sid:#x} in use"));
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
            .await;
        return;
    };
    let (rtx, rrx) = mpsc::unbounded_channel::<(u16, u16)>();
    mux.register_resizer(sid, rtx).await;
    let _ = t
        .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
        .await;
    // The argv is resolved by the host's shell policy (its shell program and
    // user-drop decision), then the host spawns; the library keeps the framing
    // and session identity.
    let shell_argv = backend.shell_argv(shell_user);
    let shell_host = ShellHost::new(&shell_argv);
    let argv = if pty_cmd.is_empty() {
        shell_host.interactive_args()
    } else {
        shell_host.exec_cmd_args(&pty_cmd)
    };
    let spec = PtySpawnSpec {
        session_id: session_id.clone(),
        transport: t.clone(),
        sid,
        cols,
        rows,
        term,
        argv,
        device_pub,
        admitted_via_ceiling: plan.admitted_via_ceiling,
    };
    match backend.spawn(spec, reservation).await {
        Some(sess) => {
            bindings
                .entry(pid.clone())
                .or_default()
                .insert(sid, session_id.clone());
            backend.start_pumps(sess, rx, rrx);
            conn.log.say(&format!(
                "l2: pty granted to '{}', {cols}x{rows}",
                dev.unwrap_or_default()
            ));
        }
        None => {
            mux.drop_pty(sid).await;
        }
    }
}

/// A build with `pty-server` off compiles no orchestration and no backend. The
/// frame is answered by name instead of silence, so the initiator fails fast
/// with a reason rather than waiting out its open deadline.
#[cfg(not(feature = "pty-server"))]
#[allow(clippy::too_many_arguments)]
pub async fn open_pty(
    _ports: &RecvPorts,
    conn: &mut Conn,
    pid: String,
    v: &Value,
    _shell_policy: &ShellPolicy,
    _shell_user: &Option<String>,
    _muxes: &mut HashMap<String, Arc<Mux>>,
    _bindings: &mut HashMap<String, HashMap<u32, String>>,
    _l2_enabled: bool,
    _parked: &mut Vec<ParkedOpen>,
) {
    open_pty_unavailable(conn, &pid, v).await;
}

pub async fn retire_link(
    ports: &RecvPorts,
    pid: &str,
    muxes: &mut HashMap<String, Arc<Mux>>,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
) {
    if let Some(mux) = muxes.remove(pid) {
        mux.shutdown_all().await;
    }
    if let Some(sid_map) = bindings.remove(pid) {
        for session_id in sid_map.values() {
            if let Some(sess) = ports.pty.get_live(session_id).await {
                sess.detach();
            }
        }
    }
}

pub async fn pty_resize(
    ports: &RecvPorts,
    pid: &str,
    v: &Value,
    muxes: &mut HashMap<String, Arc<Mux>>,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
) {
    let Some(sid) = l2::wire_sid(v) else { return };
    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
    if let Some(sid_map) = bindings.get(pid) {
        if let Some(session_id) = sid_map.get(&sid) {
            if let Some(sess) = ports.pty.get_live(session_id).await {
                sess.resize(cols, rows);
            }
        }
    }
    if let Some(mux) = muxes.get(pid) {
        mux.resize_pty(sid, cols, rows).await;
    }
}

/// Does this link's stored session key name the client's raw id?
///
/// Admission stores `<verified device|pid>\u{1}<client id>`; the browser sends
/// only its raw client id. Both the raw form (a programmatic caller that holds
/// the scoped key) and the suffix after the one acceptor-inserted separator
/// match.
fn scoped_session_matches(stored: &str, raw: &str) -> bool {
    stored == raw
        || stored
            .split_once('\u{1}')
            .is_some_and(|(_, client_id)| client_id == raw)
}

pub async fn pty_close(
    ports: &RecvPorts,
    pid: &str,
    v: &Value,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
) {
    let Some(raw) = v["session"].as_str().filter(|s| !s.is_empty()) else {
        return;
    };
    // Resolve ONLY inside the closing link's own bindings. The session store is
    // process-wide and keyed by the device-scoped id, so a frame-named key
    // would let any peer end/forget another device's shell. A key this link
    // never opened is not this link's to close.
    let Some(sid_map) = bindings.get(pid) else {
        return;
    };
    let matches: Vec<(u32, String)> = sid_map
        .iter()
        .filter(|(_, stored)| scoped_session_matches(stored, raw))
        .map(|(sid, stored)| (*sid, stored.clone()))
        .collect();
    if matches.is_empty() {
        return;
    }
    let mut ended: Vec<&str> = Vec::new();
    for (_, session_id) in &matches {
        if ended.contains(&session_id.as_str()) {
            continue;
        }
        if let Some(sess) = ports.pty.get_live(session_id).await {
            sess.end();
        }
        // The end is asynchronous and the handle may still look live until the
        // session task observes it. Forget the id unconditionally so a re-open
        // with the same stable id SPAWNS a fresh shell instead of reattaching to
        // the one being torn down.
        ports.pty.forget(session_id).await;
        ended.push(session_id.as_str());
    }
    if let Some(sid_map) = bindings.get_mut(pid) {
        sid_map.retain(|sid, _| !matches.iter().any(|(matched, _)| matched == sid));
    }
}

pub async fn detach_link_ptys(
    ports: &RecvPorts,
    pid: &str,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
) {
    if let Some(sid_map) = bindings.remove(pid) {
        for session_id in sid_map.values() {
            if let Some(sess) = ports.pty.get_live(session_id).await {
                sess.detach();
            }
        }
    }
}

#[cfg(all(test, feature = "pty-server"))]
mod tests {
    use super::{
        open_pty, pty_close, pty_open_action, PtyAction, PtyBackend, PtySession, PtySpawnSpec,
    };
    use crate::conn::{Conn, Link, Presence};
    use crate::host::{CapGate, HostServices, NoHost, VecLog};
    use crate::l2::{Mux, MuxMap, L2_SID_BASE, MAX_PTYS_GLOBAL, NO_SUCH_SESSION};
    use crate::recv::ports::{test_support, RecvEnv, RecvPorts};
    use crate::refusal::SHELL_OFF_REASON;
    use crate::shell_gate::ShellPolicy;
    use filament_cap::capability as cap;
    use filament_cap::capability::BindingStrength;
    use filament_transport::net::Transport;
    use serde_json::{json, Value};
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const PID: &str = "pty-peer";
    const PID_B: &str = "pty-peer-b";
    const SID: u32 = L2_SID_BASE + 9;
    const DEVICE: [u8; 32] = [5; 32];
    /// The stable, device-scoped id the admission plan derives for `client-1`
    /// from the verified device name.
    const SESSION: &str = "phone\u{1}client-1";

    #[tokio::test]
    async fn reattach_wins_over_resume_and_resume_without_a_session_closes() {
        assert_eq!(pty_open_action(true, false), PtyAction::Reattach);
        assert_eq!(pty_open_action(true, true), PtyAction::Reattach);
        assert_eq!(pty_open_action(false, true), PtyAction::CloseNoSession);
        assert_eq!(pty_open_action(false, false), PtyAction::Spawn);
    }

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
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A host that admits every shell gate: these tests are about the order of
    /// the backend/mux effects, not the capability matrix (shell/admit.rs owns
    /// that).
    struct AllowHost;

    #[async_trait::async_trait]
    impl HostServices for AllowHost {
        // The host facts the gate reads even on the allow path: inert answers,
        // as `NoHost` gives, except that this host grants `shell`.
        fn settings_get_str(&self, key: &str) -> Option<String> {
            NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            NoHost.devices_load()
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
            true
        }
        fn cert_revoked_for(&self, _device_pub: Option<&[u8; 32]>) -> bool {
            false
        }
        fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
            false
        }
        fn principal_ceiling_for(&self, _name: &str) -> Option<Vec<String>> {
            None
        }
        fn ceiling_covers_action(&self, _device_pub: Option<&[u8; 32]>, _action: &str) -> bool {
            false
        }
        fn cap_gate_effective(&self, _gate: CapGate<'_>) -> cap::GateDecision {
            cap::GateDecision::Allow
        }
    }

    fn link(
        pid: &str,
        t: Arc<CaptureTransport>,
        verified_name: &str,
        host: Arc<dyn HostServices>,
    ) -> Link {
        Link {
            peer: None,
            info: json!({"id": pid}),
            name: "display name".into(),
            uid: None,
            transport: Some(t),
            workers: vec![],
            generation: 1,
            attempts: 0,
            trusted: true,
            expected_secret: None,
            verified_name: Some(verified_name.into()),
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
        }
    }

    async fn connection(t: Arc<CaptureTransport>, log: Arc<VecLog>) -> Conn {
        let (sio, _far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let host: Arc<dyn HostServices> = Arc::new(AllowHost);
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
        conn.links.insert(PID.into(), link(PID, t, "phone", host));
        conn
    }

    /// Every effect the library is allowed to cause on the host, counted.
    #[derive(Default)]
    struct Counters {
        lookups: AtomicUsize,
        reserves: AtomicUsize,
        spawns: AtomicUsize,
        forgets: AtomicUsize,
        attaches: AtomicUsize,
        ends: AtomicUsize,
        reserve_ok: AtomicBool,
        /// Whether the ack was already on the wire when `spawn` was called.
        acked_at_spawn: Mutex<Vec<bool>>,
    }

    struct FakeSession {
        c: Arc<Counters>,
    }

    impl PtySession for FakeSession {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn attach(&self, _t: Arc<dyn Transport>, _sid: u32, _resume_from: Option<u64>) {
            self.c.attaches.fetch_add(1, Ordering::SeqCst);
        }
        fn resize(&self, _cols: u16, _rows: u16) {}
        fn detach(&self) {}
        fn end(&self) {
            // The real `end()` is asynchronous: the session task has not
            // necessarily marked the handle dead when the close returns. The
            // fake keeps it in the map until `forget`, which is exactly the
            // window the close->reopen regression lives in.
            self.c.ends.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FakePty {
        c: Arc<Counters>,
        live: Arc<Mutex<HashMap<String, Arc<FakeSession>>>>,
    }

    #[async_trait::async_trait]
    impl PtyBackend for FakePty {
        async fn get_live(&self, session_id: &str) -> Option<Arc<dyn PtySession>> {
            self.c.lookups.fetch_add(1, Ordering::SeqCst);
            self.live
                .lock()
                .unwrap()
                .get(session_id)
                .map(|s| s.clone() as Arc<dyn PtySession>)
        }
        fn reserve(&self) -> Option<Box<dyn Any + Send>> {
            self.c.reserves.fetch_add(1, Ordering::SeqCst);
            self.c
                .reserve_ok
                .load(Ordering::SeqCst)
                .then(|| Box::new(()) as Box<dyn Any + Send>)
        }
        async fn spawn(
            &self,
            spec: PtySpawnSpec,
            _reservation: Box<dyn Any + Send>,
        ) -> Option<Arc<dyn PtySession>> {
            let acked = spec
                .transport
                .as_any()
                .downcast_ref::<CaptureTransport>()
                .map(|t| {
                    t.controls
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|v| v["type"] == "pty-open-ack")
                })
                .unwrap_or(false);
            self.c.acked_at_spawn.lock().unwrap().push(acked);
            self.c.spawns.fetch_add(1, Ordering::SeqCst);
            let sess = Arc::new(FakeSession { c: self.c.clone() });
            self.live
                .lock()
                .unwrap()
                .insert(spec.session_id.clone(), sess.clone());
            Some(sess)
        }
        async fn forget(&self, session_id: &str) {
            self.c.forgets.fetch_add(1, Ordering::SeqCst);
            self.live.lock().unwrap().remove(session_id);
        }
        fn start_pumps(
            &self,
            _session: Arc<dyn PtySession>,
            _input: tokio::sync::mpsc::Receiver<crate::recv::servers::shell::PipeItem>,
            _resize: tokio::sync::mpsc::UnboundedReceiver<(u16, u16)>,
        ) {
        }
        fn shell_argv(&self, _shell_user: &Option<String>) -> Vec<String> {
            vec!["/bin/sh".into()]
        }
        fn user_drop_available(&self, _shell_user: &Option<String>) -> bool {
            false
        }
    }

    struct Harness {
        conn: Conn,
        ports: RecvPorts,
        t: Arc<CaptureTransport>,
        log: Arc<VecLog>,
        muxes: MuxMap,
        bindings: HashMap<String, HashMap<u32, String>>,
        c: Arc<Counters>,
        live: Arc<Mutex<HashMap<String, Arc<FakeSession>>>>,
    }

    async fn harness(admitting: bool) -> Harness {
        let c = Arc::new(Counters::default());
        c.reserve_ok.store(admitting, Ordering::SeqCst);
        let live = Arc::new(Mutex::new(HashMap::new()));
        let backend = FakePty {
            c: c.clone(),
            live: live.clone(),
        };
        let t = Arc::new(CaptureTransport::default());
        let log = Arc::new(VecLog::new());
        let conn = connection(t.clone(), log.clone()).await;
        let ports = RecvPorts::new(
            Arc::new(test_support::NoIdentity),
            Arc::new(test_support::NoStore),
            Box::new(test_support::NoServers),
            Box::new(test_support::NoDaemon),
            Arc::new(test_support::NoPrompt),
            Box::new(backend),
            Arc::new(crate::present::NoScreen),
            RecvEnv::default(),
        );
        Harness {
            conn,
            ports,
            t,
            log,
            muxes: MuxMap::new(),
            bindings: HashMap::new(),
            c,
            live,
        }
    }

    fn open_frame(session: &str, resume: bool) -> Value {
        json!({
            "type": "pty-open",
            "sid": SID,
            "session": session,
            "term": "xterm-256color",
            "cols": 80,
            "rows": 24,
            "resume": resume,
        })
    }

    async fn open(h: &mut Harness, frame: &Value) {
        open_pty(
            &h.ports,
            &mut h.conn,
            PID.into(),
            frame,
            &ShellPolicy::Granted,
            &None,
            &mut h.muxes,
            &mut h.bindings,
            true,
            &mut Vec::new(),
        )
        .await;
    }

    async fn pre_register(h: &mut Harness) -> tokio::sync::mpsc::Receiver<super::PipeItem> {
        let mux = Mux::new(h.t.clone(), h.conn.host.clone());
        let keep = mux.register_stream(SID).await.expect("sid is free");
        h.muxes.insert(PID.into(), mux);
        keep
    }

    fn controls(h: &Harness) -> Vec<Value> {
        h.t.controls.lock().unwrap().clone()
    }

    fn log_has(h: &Harness, needle: &str) -> bool {
        h.log.take().iter().any(|(_, line)| line.contains(needle))
    }

    #[tokio::test]
    async fn admission_precedes_every_backend_effect() {
        let mut h = harness(true).await;
        // Serving off: the admission endpoint answers shell-off and the handler
        // returns before it ever looks up a session, takes a cap slot or spawns.
        open_pty(
            &h.ports,
            &mut h.conn,
            PID.into(),
            &open_frame("client-1", false),
            &ShellPolicy::Granted,
            &None,
            &mut h.muxes,
            &mut h.bindings,
            false,
            &mut Vec::new(),
        )
        .await;
        assert_eq!(
            controls(&h),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": SHELL_OFF_REASON,
                "code": "shell-off",
                "as": "phone",
            })]
        );
        assert_eq!(h.c.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(h.c.reserves.load(Ordering::SeqCst), 0);
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 0);
        assert!(h.muxes.is_empty());
    }

    #[tokio::test]
    async fn spawn_registers_the_stream_acks_and_only_then_spawns() {
        let mut h = harness(true).await;
        open(&mut h, &open_frame("client-1", false)).await;

        assert_eq!(
            controls(&h),
            vec![json!({"type": "pty-open-ack", "sid": SID})],
            "the ack is the only control, and it precedes the spawn"
        );
        assert_eq!(h.c.lookups.load(Ordering::SeqCst), 1);
        assert_eq!(h.c.reserves.load(Ordering::SeqCst), 1);
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 1);
        assert_eq!(
            h.c.acked_at_spawn.lock().unwrap().as_slice(),
            &[true],
            "the initiator is acked before the host is asked to spawn"
        );
        assert_eq!(
            h.muxes[PID].live_sids().await,
            vec![SID],
            "the stream is registered before the spawn"
        );
        assert_eq!(h.bindings[PID][&SID], SESSION);
    }

    #[tokio::test]
    async fn global_cap_refusal_uses_the_shared_cap_and_never_acks() {
        let mut h = harness(false).await;
        let _keep = pre_register(&mut h).await;
        open(&mut h, &open_frame("client-1", false)).await;

        assert_eq!(h.c.reserves.load(Ordering::SeqCst), 1);
        assert_eq!(
            controls(&h),
            vec![json!({"type": "l2-close", "sid": SID, "err": "too many streams"})]
        );
        assert_eq!(
            h.muxes[PID].live_sids().await,
            vec![SID],
            "the refusal does not displace the stream that already owns the sid"
        );
        assert!(
            log_has(&h, &format!("global cap {MAX_PTYS_GLOBAL}")),
            "the refusal names the one shared cap, not a second copy"
        );
        assert!(h.bindings.is_empty());
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sid_collision_is_refused_after_the_reservation_and_before_the_ack() {
        let mut h = harness(true).await;
        let _keep = pre_register(&mut h).await;
        open(&mut h, &open_frame("client-1", false)).await;

        assert_eq!(h.c.reserves.load(Ordering::SeqCst), 1);
        assert_eq!(
            controls(&h),
            vec![json!({"type": "l2-close", "sid": SID, "err": "sid in use"})]
        );
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 0);
        assert_eq!(h.muxes[PID].live_sids().await, vec![SID]);
        assert!(h.bindings.is_empty());
    }

    #[tokio::test]
    async fn resume_without_a_session_closes_before_cap_and_collision() {
        let mut h = harness(false).await;
        let _keep = pre_register(&mut h).await;
        open(&mut h, &open_frame("client-1", true)).await;

        assert_eq!(
            controls(&h),
            vec![json!({"type": "l2-close", "sid": SID, "err": NO_SUCH_SESSION})]
        );
        assert_eq!(
            h.c.reserves.load(Ordering::SeqCst),
            0,
            "a resume close is decided before the cap is consulted"
        );
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 0);
        assert_eq!(h.c.attaches.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reattach_attaches_and_never_spawns() {
        let mut h = harness(true).await;
        h.live
            .lock()
            .unwrap()
            .insert(SESSION.into(), Arc::new(FakeSession { c: h.c.clone() }));
        open(&mut h, &open_frame("client-1", false)).await;

        assert_eq!(h.c.attaches.load(Ordering::SeqCst), 1);
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 0);
        assert_eq!(
            h.c.reserves.load(Ordering::SeqCst),
            0,
            "a reattach takes no PTY slot"
        );
        assert_eq!(
            controls(&h),
            vec![json!({"type": "pty-open-ack", "sid": SID})]
        );
        assert_eq!(h.bindings[PID][&SID], SESSION);
    }

    #[tokio::test]
    async fn close_only_resolves_ids_this_link_opened() {
        let mut h = harness(true).await;
        open(&mut h, &open_frame("client-1", false)).await;
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 1);

        // Link B presents link A's scoped value, then A's raw client id.
        // Neither is in B's own bindings, so B may end/forget nothing.
        let host = h.conn.host.clone();
        h.conn.links.insert(
            PID_B.into(),
            link(
                PID_B,
                Arc::new(CaptureTransport::default()),
                "phone-b",
                host,
            ),
        );
        for presented in [SESSION, "client-1"] {
            pty_close(
                &h.ports,
                PID_B,
                &json!({"type": "pty-close", "session": presented}),
                &mut h.bindings,
            )
            .await;
            assert_eq!(
                h.c.ends.load(Ordering::SeqCst),
                0,
                "link B cannot end link A's shell with {presented:?}"
            );
            assert_eq!(h.c.forgets.load(Ordering::SeqCst), 0);
        }
        assert!(
            !h.live.lock().unwrap().is_empty(),
            "link A's session is untouched"
        );
        assert_eq!(h.bindings[PID][&SID], SESSION, "A's binding is untouched");

        // A's own raw client id still closes A's session.
        pty_close(
            &h.ports,
            PID,
            &json!({"type": "pty-close", "session": "client-1"}),
            &mut h.bindings,
        )
        .await;
        assert_eq!(h.c.ends.load(Ordering::SeqCst), 1);
        assert_eq!(h.c.forgets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn close_then_open_with_the_same_session_spawns_fresh_and_never_reattaches() {
        let mut h = harness(true).await;
        open(&mut h, &open_frame("client-1", false)).await;
        assert_eq!(h.c.spawns.load(Ordering::SeqCst), 1);

        // The client closes the shell (the ✕ / unmount path). `end()` is
        // asynchronous, so the handle is still in the map until `forget`.
        pty_close(
            &h.ports,
            PID,
            // The browser sends its RAW client id, not the device-scoped key
            // admission stored.
            &json!({"type": "pty-close", "session": "client-1"}),
            &mut h.bindings,
        )
        .await;
        assert_eq!(h.c.ends.load(Ordering::SeqCst), 1);
        assert_eq!(h.c.forgets.load(Ordering::SeqCst), 1);
        assert!(h.live.lock().unwrap().is_empty(), "the id is forgotten");
        assert!(h.bindings[PID].is_empty());
        // The stream itself is torn down by the inbound `l2-close` for the
        // closed terminal, not by `pty-close`; do it here so the re-open is
        // decided by session identity alone.
        h.muxes[PID].drop_pty(SID).await;

        // Re-opening the SAME stable id after the close must spawn a fresh
        // shell. Before `forget` this reattached to the dying handle.
        open(&mut h, &open_frame("client-1", false)).await;
        assert_eq!(
            h.c.spawns.load(Ordering::SeqCst),
            2,
            "close->reopen spawns a fresh shell"
        );
        assert_eq!(
            h.c.attaches.load(Ordering::SeqCst),
            0,
            "close->reopen never takes the reattach path"
        );
        assert_eq!(h.c.forgets.load(Ordering::SeqCst), 1);
        assert_eq!(h.bindings[PID][&SID], SESSION);
    }
}

#[cfg(all(test, not(feature = "pty-server")))]
mod reduced_tests {
    use super::*;

    #[test]
    fn reduced_pty_open_closes_with_a_named_unavailable_error() {
        let (sid, close) = pty_unavailable_close(&json!({
            "type": "pty-open",
            "sid": 0x8000_0101u32,
            "session": "client-1",
        }))
        .expect("a well-formed pty-open gets an explicit close");
        assert_eq!(sid, 0x8000_0101u32);
        assert_eq!(close["type"], "l2-close");
        assert_eq!(close["sid"], 0x8000_0101u32);
        assert!(close["err"]
            .as_str()
            .unwrap()
            .contains("pty receive is not available in this build"));
    }

    #[test]
    fn reduced_pty_open_ignores_a_non_l2_sid() {
        for sid in [7u64, 0u64, u32::MAX as u64 + 1] {
            assert!(
                pty_unavailable_close(&json!({
                    "type": "pty-open",
                    "sid": sid,
                    "session": "client-1",
                }))
                .is_none(),
                "sid {sid} is not a valid L2-half stream"
            );
        }
    }
}
