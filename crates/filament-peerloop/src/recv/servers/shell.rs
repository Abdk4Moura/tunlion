//! PTY-open orchestration: admission, reattach-vs-spawn, mux registration,
//! ack/replay ordering and session identity. Process spawn, PTY IO, user-drop
//! argv resolution and the process-wide PTY cap are host effects behind
//! [`PtyBackend`]; this module owns every protocol/state decision.

use crate::conn::Conn;
use crate::l2::{self, Mux};
use crate::recv::dispatch::{park_on_deny, ParkKind, ParkedOpen};
use crate::recv::ports::RecvPorts;
use crate::shell::ShellHost;
use crate::shell_gate::ShellPolicy;
use async_trait::async_trait;
use bytes::Bytes;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A live PTY session. The host owns the child and IO; the library owns the
/// session identity and which link/sid it is attached to.
pub trait PtySession: Send + Sync {
    /// Downcast seam for the host's pump task (the library never inspects it).
    fn as_any(&self) -> &dyn std::any::Any {
        &()
    }
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
    /// Pump inbound stream bytes and resize events into the session.
    fn start_pumps(
        &self,
        session: Arc<dyn PtySession>,
        input: mpsc::Receiver<PipeItem>,
        resize: mpsc::Receiver<(u16, u16)>,
    );
    /// Resolve the shell argv/user-drop policy. `can_use_user` drives admission.
    fn shell_argv(&self, shell_user: &Option<String>) -> (Vec<String>, bool);
    /// The host's user-drop explanation is empty when the drop can run.
    fn user_drop_available(&self, shell_user: &Option<String>) -> bool;
}

pub type PipeItem = l2::PipeItem;

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
    if let Some(sess) = backend.get_live(&session_id).await {
        if mux.at_stream_cap().await {
            conn.log
                .say("l2: pty reattach refused: too many streams on this link");
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
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
    if resume {
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": l2::NO_SUCH_SESSION }))
            .await;
        return;
    }
    if mux.at_stream_cap().await {
        conn.log
            .say("l2: pty refused: too many streams on this link");
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
            .await;
        return;
    }
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
    let (shell_argv, _) = backend.shell_argv(shell_user);
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

pub async fn pty_close(
    ports: &RecvPorts,
    pid: &str,
    v: &Value,
    bindings: &mut HashMap<String, HashMap<u32, String>>,
) {
    if let Some(session_id) = v["session"].as_str() {
        if let Some(sess) = ports.pty.get_live(session_id).await {
            sess.end();
        }
        if let Some(sid_map) = bindings.get_mut(pid) {
            sid_map.retain(|_, id| id != session_id);
        }
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

#[allow(dead_code)]
fn _bytes(_: Bytes) {}
