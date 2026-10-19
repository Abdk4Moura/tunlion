//! The CLI's host-side receive capabilities.
//!
//! The dispatch loop lives in `filament_peerloop::recv::dispatch`. This module
//! implements the narrow capability traits it asks for, forwarding to the
//! machine-bound implementations that already existed here: the identity
//! lifecycle, the devices store, the optional inbound servers (PTY/exec/
//! forward/sync/mount/ssh), the daemon control plane, and stdin.
//!
//! Feature gates: `recv-servers` (default) compiles the optional server
//! implementations. A reduced build (Android) omits them and every open is
//! refused by the fallback in `NoRecvServers`.

use crate::host::{LogSink, Tone};
use crate::l2 as cli_l2;
use crate::recv_cmd::{ParkKind, ParkedOpen};
use crate::shell::ShellPolicy;
use crate::{identity, refusal};
use anyhow::{Context, Result};
use filament_peerloop::conn::Conn;
use filament_peerloop::control::Req;
use filament_peerloop::driver::Cancellation as _;
use filament_peerloop::host::HostServices;
use filament_peerloop::l2 as lib_l2;
use filament_peerloop::l2::Mux;
use filament_peerloop::mesh::MeshTunnel;
use filament_peerloop::recv::dispatch::{self, settle_timeout_reason};
use filament_peerloop::recv::ports::{
    RawMode, RecvDaemon, RecvEnv, RecvIdentity, RecvPorts, RecvPrompt, RecvServers, RecvStore,
};
use filament_peerloop::recv::report::RecvReport;
use filament_peerloop::recv::IncomingFile;
use filament_peerloop::session::Session;
use filament_peerloop::shell_gate::PeerAuthz;
use filament_signal::Client as SignalClient;
use filament_transport::net::{Ev, Transport};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct CliRecv {
    pub log: Arc<dyn LogSink>,
    pub pty_sessions: cli_l2::PtySessions,
    pub warm_ptys: crate::WarmPtys,
    pub liveness: crate::LivenessProbes,
    pub pending_bootstrap: crate::PendingBootstraps,
    pub daemon_mounts: crate::DaemonMounts,
    pub last_mount_check: Instant,
    pub exposer: Option<Arc<crate::expose::Exposer>>,
}

impl Default for CliRecv {
    fn default() -> Self {
        Self {
            log: Arc::new(filament_peerloop::host::NoLog),
            pty_sessions: cli_l2::PtySessions::new(),
            warm_ptys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            liveness: crate::LivenessProbes::new(),
            pending_bootstrap: HashMap::new(),
            daemon_mounts: crate::DaemonMounts {
                entries: HashMap::new(),
                children: HashMap::new(),
            },
            last_mount_check: Instant::now(),
            exposer: None,
        }
    }
}

impl CliRecv {
    pub fn new(log: Arc<dyn LogSink>) -> Self {
        Self {
            log,
            ..Self::default()
        }
    }
}

#[async_trait::async_trait]
impl RecvIdentity for CliRecv {
    async fn issue_proven_challenge_and_hold(
        &self,
        conn: &Conn,
        pid: &str,
        t: &Arc<dyn Transport>,
        pending_proven: &Arc<std::sync::Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) {
        crate::identity_lifecycle::issue_proven_challenge_and_hold(
            conn,
            pid,
            t,
            pending_proven,
            identity_nonces,
        )
        .await
    }
    async fn respond_to_identity_challenge(&self, t: &Arc<dyn Transport>, v: &Value) {
        crate::identity_lifecycle::respond_to_identity_challenge(t, v).await
    }
    fn handle_identity_expose(
        &self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        crate::identity_lifecycle::handle_identity_expose(conn, pid, v, identity_nonces)
    }
    fn store_provisional_identity(&self, name: &str, cert: &identity::DeviceCert) -> Result<()> {
        crate::identity_lifecycle::store_provisional_identity(name, cert)
    }
    fn load_provisional_identity(&self, name: &str) -> Option<identity::DeviceCert> {
        crate::identity_lifecycle::load_provisional_identity(name)
    }
    fn clear_provisional_identity(&self, name: &str) {
        crate::identity_lifecycle::clear_provisional_identity(name)
    }
    fn local_device_cert(&self) -> Option<identity::DeviceCert> {
        crate::local_device_cert()
    }
    async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str) {
        crate::renewal_lifecycle::maybe_request_cert_renewal(conn, pid).await
    }
    async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String) {
        crate::renewal_lifecycle::respond_to_cert_renew_request(conn, pid).await
    }
    async fn handle_cert_renew_ack(&self, v: &Value) {
        crate::renewal_lifecycle::handle_cert_renew_ack(v).await
    }
    async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value) {
        crate::renewal_lifecycle::respond_to_auth_key_enroll_request(conn, pid, v).await
    }
    async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value) {
        crate::renewal_lifecycle::handle_auth_key_enroll_response(conn, pid, v).await
    }
    fn gate_settle_ms(&self) -> u64 {
        crate::identity_state::gate_settle_ms()
    }
    fn hold_expired(&self, held: Instant) -> bool {
        crate::identity_lifecycle::hold_expired(held)
    }
    async fn resend_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        t: &Arc<dyn Transport>,
        pending_proven: &Arc<std::sync::Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) {
        crate::identity_lifecycle::resend_identity_challenge(
            conn,
            pid,
            t,
            pending_proven,
            identity_nonces,
        )
        .await
    }
    fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        crate::device_view::device_name_for_pub(device_pub)
    }
    fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        crate::device_view::device_cert_revoked(device_pub)
    }
    fn owner_pub_for_resources(&self) -> Option<[u8; 32]> {
        crate::owner_pub_for_resources()
    }
    fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<Value> {
        crate::identity_state::reinvite_for(device_pub)
    }
    fn enroll_channel(&self, public_key: &[u8]) -> String {
        crate::ephemeral::enroll_channel(public_key)
    }
    fn is_armed(&self) -> bool {
        crate::armed::is_armed()
    }
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        owner_pub: &[u8; 32],
        now: u64,
    ) -> Result<bool> {
        crate::roster::verify_and_store_roster(blob, owner_pub, now)
    }
    fn verify_depart(&self, device_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        crate::membership::verify_depart(device_pub, msg, sig)
    }
}

#[async_trait::async_trait]
impl RecvStore for CliRecv {
    fn devices_path(&self) -> PathBuf {
        crate::devices_store::devices_path()
    }
    fn devices_touch(
        &self,
        name: &str,
        v6: Option<std::net::Ipv6Addr>,
        v4: Option<std::net::Ipv4Addr>,
    ) {
        crate::device_view::devices_touch(name, v6, v4)
    }
    fn devices_remove(&self, name: &str) -> Result<()> {
        crate::device_caps::devices_remove(name)
    }
    fn devices_store(&self, name: &str, secret: &str) -> Result<String> {
        crate::device_view::devices_store(name, secret)
    }
    fn devices_store_new(
        &self,
        name: &str,
        secret: &str,
        introduced_by: Option<&str>,
    ) -> Result<String> {
        crate::devices_store::devices_store_new(name, secret, introduced_by)
    }
    fn device_was_introduced(&self, name: &str) -> bool {
        crate::devices_store::device_was_introduced(name)
    }
    fn devices_sweep_lapsed(&self, now: u64) -> usize {
        crate::device_view::devices_sweep_lapsed(now)
    }
    fn devices_upsert_atomic(
        &self,
        name: &str,
        secret: Option<&str>,
        cert: Option<&identity::DeviceCert>,
        caps: Option<&[String]>,
        scope: Option<u8>,
        user_key_hex: Option<&str>,
        delegated: Option<(&[String], u64, u64, u64)>,
        allow_reanchor: bool,
    ) -> Result<String> {
        crate::devices_store::devices_upsert_atomic(
            name,
            secret,
            cert,
            caps,
            scope,
            user_key_hex,
            delegated,
            allow_reanchor,
        )
    }
    fn promote_provisional_identity(
        &self,
        name: &str,
        cert: &identity::DeviceCert,
        scope: u8,
    ) -> Result<()> {
        crate::devices_store::with_devices_mut(|arr| {
            identity::apply_peer_identity(arr, name, cert, scope)
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .map(|_| ())
    }
    fn mark_bounded_cap_source(&self, name: &str, capability: &str, source: &str) -> Result<()> {
        crate::device_caps::mark_bounded_cap_source(name, capability, source)
    }
    fn merge_owner_cap_ops(&self, ops: &[Value]) -> usize {
        crate::identity_state::merge_owner_cap_ops(ops)
    }
    fn owner_signed_cap_ops(&self) -> Vec<Value> {
        crate::identity_state::owner_signed_cap_ops()
    }
    fn mark_lapsed_now(&self, device_pub: &[u8; 32]) -> Option<String> {
        crate::identity_state::mark_lapsed_now(device_pub)
    }
    fn sanitize_device_name(&self, name: &str) -> String {
        crate::identity_state::sanitize_device_name(name)
    }
    fn devices_find_by_device_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        crate::device_view::devices_find_by_device_pub(device_pub)
    }
    fn any_shell_grant(&self) -> bool {
        crate::shell_support::any_shell_grant()
    }
}

#[async_trait::async_trait]
impl RecvServers for CliRecv {
    async fn retire_link(
        &mut self,
        pid: &str,
        muxes: &mut HashMap<String, Arc<Mux>>,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    ) {
        if let Some(mux) = muxes.remove(pid) {
            mux.shutdown_all().await;
        }
        if let Some(sid_map) = bindings.remove(pid) {
            for session_id in sid_map.values() {
                if let Some(sess) = self.pty_sessions.get_live(session_id).await {
                    sess.detach();
                }
            }
        }
    }
    /// Accept one `pty-open` frame: validate, shell-gate, attach or spawn,
    /// acknowledge. Extracted verbatim from the recv loop arm so unsettled opens
    /// can be parked and re-driven through this same function.
    async fn open_pty(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        shell_policy: &ShellPolicy,
        shell_user: &Option<String>,
        l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
        pty_bindings: &mut HashMap<String, HashMap<u32, String>>,
        l2_enabled: bool,
        parked: &mut Vec<ParkedOpen>,
    ) {
        let admission = filament_peerloop::shell::admit::admit_pty_open(
            conn,
            &pid,
            v,
            &filament_peerloop::shell::admit::ShellAdmissionConfig {
                policy: shell_policy,
                serving: l2_enabled,
            },
            || {
                shell_user.is_some()
                    && crate::shell_root_note().is_empty()
                    && shell_argv(None, shell_user.as_deref()).1
            },
        )
        .await;
        let (t, sid, dev, device_pub, plan) = match admission {
            filament_peerloop::shell::admit::ShellAdmission::Admitted {
                transport,
                sid,
                device,
                device_pub,
                plan,
            } => (transport, sid, device, device_pub, plan),
            filament_peerloop::shell::admit::ShellAdmission::Ignored => return,
            filament_peerloop::shell::admit::ShellAdmission::Denied(d) => {
                // Settle-then-evaluate: park for re-drive on proof when this deny
                // is attributable to the unproven binding; else the live verdict.
                if park_on_deny(
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
                enqueue_if_requestable(who, "shell");
                // The refusal already carries the precise code and our name for
                // the peer (a missing grant is not "serving is off"); the caller
                // adds the invite details exactly where it did before.
                let refusal = crate::refusal::with_reinvite_for(d.refusal, d.device_pub.as_ref());
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
        let mux = l2_muxes
            .entry(pid.clone())
            .or_insert_with(|| l2::Mux::new(t.clone(), conn.host.clone()))
            .clone();
        // #4 REATTACH: a live session for this id means a reconnect.
        // Rebind its output to THIS link+sid and replay its buffer; do
        // not spawn a new shell. Register the input pump + resizer for
        // the new sid so typing and SIGWINCH reach the surviving PTY.
        if let Some(sess) = self.pty_sessions.get_live(&session_id).await {
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
            // Collision-safe: if this sid is already live (peer reused
            // a live forward/pty/mount sid) register refuses; deny the
            // reattach rather than displacing the existing stream.
            let Some(rx) = mux.register_stream(sid).await else {
                conn.log
                    .say(&format!("l2: pty reattach refused: sid {sid:#x} in use"));
                let _ = t
                    .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
                    .await;
                return;
            };
            let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
            mux.register_resizer(sid, rtx).await;
            let _ = t
                .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
                .await;
            // How much output the client already has, so only the missed part is
            // replayed (absent from older clients and the browser: replay all).
            sess.attach(t.clone(), sid, plan.resume_from);
            sess.resize(cols, rows);
            pty_bindings
                .entry(pid.clone())
                .or_default()
                .insert(sid, session_id.clone());
            spawn_session_pumps(sess.clone(), rx, rrx);
            conn.log.say(&format!(
                "l2: pty REATTACHED to '{}', {cols}x{rows}",
                dev.unwrap_or_default()
            ));
            return;
        }
        // Resume-only + no live session: the client is a warm-drop
        // fall-through and the session is gone (the shell exited cleanly).
        // Close instead of spawning a fresh shell, so the client exits
        // cleanly rather than getting a surprise re-login.
        if resume {
            let _ = t
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": l2::NO_SUCH_SESSION }),
                )
                .await;
            return;
        }
        // H-1 (DoS): refuse over the per-link stream cap or the global
        // PTY cap BEFORE spawning a shell. A flaky/hostile paired
        // device can otherwise flood `pty-open` and exhaust threads.
        if mux.at_stream_cap().await {
            conn.log
                .say("l2: pty refused: too many streams on this link");
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
                .await;
            return;
        }
        let Some(pty_guard) = l2::PtyGuard::try_acquire() else {
            conn.log.say(&format!(
                "l2: pty refused: too many PTYs (global cap {})",
                l2::MAX_PTYS_GLOBAL
            ));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
                .await;
            return;
        };
        // before spawn (race fix). Collision-safe: refuse (don't
        // displace) if the peer named an already-live sid. `pty_guard`
        // drops on `continue`, freeing the global PTY slot it reserved.
        let Some(rx) = mux.register_stream(sid).await else {
            conn.log
                .say(&format!("l2: pty refused: sid {sid:#x} in use"));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
                .await;
            return;
        };
        let (rtx, rrx) = tokio::sync::mpsc::unbounded_channel::<(u16, u16)>();
        // Resizer is owned by the mux so it is freed on EVERY teardown
        // path (inbound l2-close, link death), H-1.
        mux.register_resizer(sid, rtx).await;
        let _ = t
            .send_control(&json!({ "type": "pty-open-ack", "sid": sid }))
            .await;
        // #4: spawn the PTY as a PERSISTENT session keyed by session_id,
        // not a link-bound serve_pty. It outlives this link; a drop
        // detaches it, a reconnect reattaches above.
        // Resolve the shell and build interactive or one-shot argv.
        let (shell_argv, _can_use_user) = shell_argv(None, shell_user.as_deref());
        let shell_host = ShellHost::new(&shell_argv);
        let argv = if pty_cmd.is_empty() {
            shell_host.interactive_args()
        } else {
            shell_host.exec_cmd_args(&pty_cmd)
        };
        // The peer's device key, from the admission that just decided (the gate
        // resolved the same value for the open decision; no second lookup).
        let spawn_idev = device_pub;
        // Ceiling-admitted (covered, grantless) sessions must die
        // when the ceiling narrows; grant-admitted ones ignore it.
        let admitted_via_ceiling = plan.admitted_via_ceiling;
        match l2::spawn_pty_session(
            self.pty_sessions.clone(),
            session_id.clone(),
            t.clone(),
            sid,
            cols,
            rows,
            &term,
            argv,
            pty_guard,
            spawn_idev,
            admitted_via_ceiling,
        )
        .await
        {
            Some(sess) => {
                pty_bindings
                    .entry(pid.clone())
                    .or_default()
                    .insert(sid, session_id.clone());
                spawn_session_pumps(sess, rx, rrx);
                conn.log.say(&format!(
                    "l2: pty granted to '{}', {cols}x{rows}",
                    dev.unwrap_or_default()
                ));
            }
            None => {
                // spawn already sent an l2-close{err}; free the stream.
                mux.drop_pty(sid).await;
            }
        }
    }

    /// Accept one `l2-open` forward frame by delegating admission to the library.
    ///
    /// The endpoint owns the gate, expose bound, allowlist answer, raw-trusted mux
    /// check and capacity/collision ordering. This wrapper keeps the two things
    /// that are the receive driver's: the caller-owned parking map and the dial
    /// task (`Mux::dial_and_serve`). A parked forward open is re-driven straight
    /// into this same function, so every input is re-gathered.
    async fn open_forward(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        shell_policy: &ShellPolicy,
        l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
        l2_enabled: bool,
        parked: &mut Vec<ParkedOpen>,
    ) {
        // Host/config inputs stay here: the endpoint reads no environment or file.
        let l2_forced = std::env::var("TUNLION_L2")
            .map(|x| x == "1")
            .unwrap_or(false);
        let is_exposed = |port: u16| crate::expose::load().iter().any(|b| b.port == port);
        let target_allowed = |name: &str, host: &str, port: u16| {
            crate::l2_policy::l2_target_allowed(name, host, port)
        };
        let cfg = forward::ForwardConfig {
            shell_policy,
            l2_enabled,
            l2_forced,
            is_exposed: &is_exposed,
            target_allowed: &target_allowed,
        };
        match forward::admit_forward_open(conn, &pid, v, l2_muxes, &cfg).await {
            forward::ForwardAdmission::Accepted {
                sid,
                host,
                port,
                rx,
                mux,
            } => {
                // The peer's device key, resolved again for the live stream's
                // revocation re-check (the gate resolved the same value).
                let spawn_idev = conn.link(&pid).and_then(|l| l.identity_device_pub);
                tokio::spawn(mux.dial_and_serve(sid, host, port, rx, spawn_idev));
            }
            forward::ForwardAdmission::Denied(d) => {
                // Settle-then-evaluate: the verdict above may rest on stale
                // (unproven) identity. Park for re-drive on proof when the deny is
                // attributable to it; otherwise the live verdict stands.
                if let Some(p) = &d.park {
                    if park_on_deny(
                        parked,
                        conn,
                        &pid,
                        ParkKind::Forward,
                        &d.transport,
                        p.sid,
                        v,
                        &p.reason,
                    )
                    .await
                    {
                        return;
                    }
                }
                conn.log
                    .say(&format!("l2: refused stream {:#x}: {}", d.sid, d.reason));
                let who = conn.link(&pid).and_then(|l| l.verified_name.clone());
                let close = d.close_frame(who, || {
                    conn.link(&pid)
                        .and_then(|l| l.identity_device_pub)
                        .and_then(|d| crate::identity_state::reinvite_for(&d))
                });
                let _ = d.transport.send_control(&close).await;
            }
            forward::ForwardAdmission::Refused(r) => {
                // Log refused dials at INFO (visible by default, suppressed under
                // -q) - a refused SSRF/port-scan or untrusted/over-cap open is a
                // security event the operator should see.
                conn.log
                    .say(&format!("l2: refused stream {:#x}: {}", r.sid, r.reason));
                let _ = r.transport.send_control(&r.close).await;
            }
            forward::ForwardAdmission::Ignored => {}
        }
    }

    async fn open_exec(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        policy: &ShellPolicy,
        shell_user: &Option<String>,
        muxes: &mut HashMap<String, Arc<Mux>>,
        l2_enabled: bool,
        parked: &mut Vec<ParkedOpen>,
    ) {
        crate::exec_recv::handle_exec_open(
            conn, &pid, v, policy, shell_user, muxes, l2_enabled, parked,
        )
        .await
    }

    async fn open_sync(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        dir: &Path,
        parked: &mut Vec<ParkedOpen>,
    ) -> Option<(u32, filament_peerloop::sync::serving::SyncServeTask)> {
        crate::sync_cmd::handle_sync_open(conn, pid, v, muxes, dir, parked).await
    }

    async fn open_mount(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        share_root: &Path,
    ) {
        let _ = crate::mount_recv::handle_mount_open(conn, pid, v, muxes, share_root).await;
    }

    async fn ssh_sign(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        t: Arc<dyn Transport>,
        v: &Value,
        policy: &ShellPolicy,
        parked: &mut Vec<ParkedOpen>,
    ) {
        crate::ssh_ca::handle_ssh_sign(conn, pid, t, v, policy, parked).await
    }

    async fn pty_resize(
        &mut self,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    ) {
        let Some(sid) = lib_l2::wire_sid(v) else {
            return;
        };
        let cols = v["cols"].as_u64().unwrap_or(80) as u16;
        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
        if let Some(sid_map) = bindings.get(pid) {
            if let Some(session_id) = sid_map.get(&sid) {
                if let Some(sess) = self.pty_sessions.get_live(session_id).await {
                    sess.resize(cols, rows);
                }
            }
        }
        if let Some(mux) = muxes.get(pid) {
            mux.resize_pty(sid, cols, rows).await;
        }
    }

    async fn pty_close(
        &mut self,
        pid: &str,
        v: &Value,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    ) {
        if let Some(session_id) = v["session"].as_str() {
            if let Some(sess) = self.pty_sessions.get_live(session_id).await {
                sess.end();
            }
            self.pty_sessions.remove(session_id).await;
            if let Some(sid_map) = bindings.get_mut(pid) {
                sid_map.retain(|_, v| v != session_id);
            }
        }
    }

    async fn detach_link_ptys(
        &mut self,
        pid: &str,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    ) {
        if let Some(sid_map) = bindings.remove(pid) {
            for session_id in sid_map.values() {
                if let Some(sess) = self.pty_sessions.get_live(session_id).await {
                    sess.detach();
                }
            }
        }
    }

    async fn exec_control(
        &mut self,
        pid: &str,
        v: &Value,
        muxes: &HashMap<String, Arc<Mux>>,
    ) -> bool {
        if let (Some(mux), Some(sid), Some(msg)) = (
            muxes.get(pid),
            lib_l2::wire_sid(v),
            filament_peerloop::l2::mux::ExecCtl::from_frame(v),
        ) {
            let live = mux.exec_control(sid, msg).await;
            return live && msg == filament_peerloop::l2::mux::ExecCtl::Alive;
        }
        false
    }

    async fn apply_reconfigure(
        &mut self,
        key: &str,
        dir: &mut PathBuf,
        shell_policy: &mut ShellPolicy,
        shell_user: &mut Option<String>,
        l2_enabled: bool,
        sess: &mut Session,
        sio: &SignalClient,
        my_uid: &str,
    ) -> bool {
        crate::fleet_support::apply_reconfigure(
            key,
            dir,
            shell_policy,
            shell_user,
            l2_enabled,
            sess,
            sio,
            my_uid,
        )
        .await
    }

    async fn start_expose(&mut self, tunnel: Arc<dyn MeshTunnel>) -> usize {
        let ex = std::sync::Arc::new(crate::expose::Exposer::new(tunnel));
        let n = ex.reconcile().await;
        self.exposer = Some(ex);
        n
    }

    async fn reconcile_expose(&mut self, tunnel: &Arc<dyn MeshTunnel>) -> usize {
        self.start_expose(tunnel.clone()).await
    }

    async fn reload_expose(&mut self) -> usize {
        match self.exposer.as_ref() {
            Some(ex) => ex.reconcile().await,
            None => 0,
        }
    }
}

#[async_trait::async_trait]
impl RecvDaemon for CliRecv {
    async fn warm_req(
        &mut self,
        conn: &Conn,
        muxes: &mut HashMap<String, Arc<Mux>>,
        tx: &mpsc::UnboundedSender<Ev>,
        req: Req,
    ) {
        crate::daemon_ctl::handle_warm_req(conn, muxes, &self.warm_ptys, &self.liveness, tx, req)
            .await
    }
    async fn list_warm(&mut self, req: Req, conn_for_list: &Conn) {
        crate::daemon_ctl::handle_list_warm(conn_for_list, req).await
    }
    async fn mount(&mut self, req: Req, server: &str, relay: bool) {
        crate::daemon_ctl::handle_mount(
            req,
            server,
            relay,
            &mut self.daemon_mounts,
            &mut self.last_mount_check,
        )
        .await
    }
    async fn unmount(&mut self, req: Req) {
        crate::daemon_ctl::handle_unmount(req, &mut self.daemon_mounts).await
    }
    async fn list_mounts(&mut self, req: Req) {
        crate::daemon_ctl::handle_list_mounts(req, &self.daemon_mounts).await
    }
    async fn mount_health(&mut self, req: Req) {
        crate::daemon_ctl::handle_mount_health(req, &self.daemon_mounts).await
    }
    async fn mount_health_tick(&mut self, host: &dyn HostServices) {
        let dead_locals: Vec<String> = self
            .daemon_mounts
            .entries
            .iter()
            .filter_map(|(local, _entry)| {
                let is_alive = host.is_mount_point(local);
                let path_exists = Path::new(local).exists();
                if !path_exists || !is_alive {
                    Some(local.clone())
                } else {
                    None
                }
            })
            .collect();
        for local in dead_locals {
            if let Some(entry) = self.daemon_mounts.entries.remove(&local) {
                self.log.say(&format!(
                    "mount {local} is gone, removing from daemon tracking (was {}:{})",
                    entry.peer, entry.remote
                ));
                if let Some(mut child) = self.daemon_mounts.children.remove(&local) {
                    let _ = child.kill().await;
                }
                let _ = host.remove_mount(&local);
            }
        }
    }
    async fn warm_bootstrap(&mut self, conn: &Conn, _tx: &mpsc::UnboundedSender<Ev>, req: Req) {
        crate::daemon_ctl::handle_warm_bootstrap(conn, &mut self.pending_bootstrap, req).await
    }
    async fn complete_warm_bootstrap(&mut self, _conn: &Conn, pid: &str, reply: &Value) {
        crate::daemon_ctl::complete_warm_bootstrap(&mut self.pending_bootstrap, pid, reply).await
    }
    fn reap_warm_bootstraps(&mut self) {
        crate::daemon_ctl::reap_warm_bootstraps(&mut self.pending_bootstrap)
    }
    fn revocation_snapshot(&self) -> Option<HashSet<String>> {
        crate::revocation_live::store_snapshot()
    }
    fn prune_to_store(&self, held: &mut Vec<(String, String)>) -> HashSet<String> {
        crate::revocation_live::prune_to_store(held)
    }
    fn key_listed(&self, device_pub: &[u8; 32]) -> bool {
        crate::revocation_live::key_listed(device_pub)
    }
    fn enroll_channel(&self, public_key: &[u8]) -> String {
        crate::ephemeral::enroll_channel(public_key)
    }
    fn is_armed(&self) -> bool {
        crate::armed::is_armed()
    }
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        owner_pub: &[u8; 32],
        now: u64,
    ) -> Result<bool> {
        crate::roster::verify_and_store_roster(blob, owner_pub, now)
    }
    fn verify_depart(&self, device_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        crate::membership::verify_depart(device_pub, msg, sig)
    }
    fn fleet_share_root(&self) -> PathBuf {
        crate::fleet_support::fleet_share_root()
    }
    fn mark_daemon_ready(&mut self) {
        crate::file_io::mark_daemon_ready()
    }
    fn record_proxy(&self, bind: &str, port: u16) {
        crate::proxy_state::record(bind, port)
    }
    fn maybe_hint_local_wedge(&mut self, shown: &mut bool) {
        crate::maybe_hint_local_wedge(shown)
    }
    fn wg_usable(&self) -> bool {
        crate::wg::usable()
    }
    fn wg_claim_attempt(&self, addr: &str) -> bool {
        crate::wg::claim_attempt(addr)
    }
    fn wg_release_attempt(&self, addr: &str) {
        crate::wg::release_attempt(addr)
    }
    fn wg_local_offer(&self) -> Option<(String, u16)> {
        crate::wg::local_offer()
    }
    async fn wg_adopt_peer(&mut self, conn: &Conn, pid: &str, v: &Value) -> Result<()> {
        crate::wg::adopt_peer(conn, pid, v).await
    }
    fn subnet_enable(&mut self, ifname: &str, prefixes: &[String], snat: bool) -> Result<()> {
        crate::subnet_forward::enable(ifname, prefixes, snat).map(|_| ())
    }
    fn configure_sshd_overlay(&mut self, v6: &str, v4: &str) -> Result<()> {
        crate::sshd::configure_sshd_overlay(v6, v4)
    }
    async fn start_overlay_servers(&mut self, _host: &dyn HostServices) -> Vec<String> {
        Vec::new()
    }
    async fn reach_ping(&mut self, conn: &Conn, pid: &str, v: &Value) {
        if let Some(t) = conn.transport_of(pid) {
            let _ = t
                .send_control(&filament_peerloop::daemon_ctl::liveness_pong(v))
                .await;
        }
    }
    async fn reach_pong(&mut self, _conn: &Conn, pid: &str, v: &Value) {
        self.liveness.answered(None, pid, v);
    }
    fn peer_present(&self, conn: &Conn, pid: &str) -> bool {
        let Some(link) = conn.link(pid) else {
            return false;
        };
        let Some(transport) = link.transport.as_ref() else {
            return false;
        };
        crate::link_manager::peer_present(
            transport.is_alive(),
            link.direct,
            transport.heard_ms(),
            transport.idle_ms(),
        )
    }
    fn liveness_pong(v: &Value) -> Value {
        filament_peerloop::daemon_ctl::liveness_pong(v)
    }
    fn daemon_alive(&self) -> Option<u32> {
        crate::daemon_alive()
    }
    fn sdnotify_ready(&self) {
        crate::sdnotify::ready()
    }
    fn sdnotify_status(&self, status: &str) {
        crate::sdnotify::status(status)
    }
    fn sdnotify_watchdog(&self) {
        crate::sdnotify::watchdog()
    }
}

pub struct CliPrompt;

struct CliRawMode(crate::TtyGuard);

impl RawMode for CliRawMode {}

impl RecvPrompt for CliPrompt {
    fn ask_code(&self, prompt: &str) -> Result<Option<String>> {
        match crate::codeentry::run(prompt, crate::codeentry::Mode::Claim, "", "")? {
            crate::codeentry::Outcome::Submitted(c) | crate::codeentry::Outcome::Claim(c) => {
                Ok(Some(c))
            }
            crate::codeentry::Outcome::Empty => Ok(None),
            crate::codeentry::Outcome::Cancelled => Err(anyhow::anyhow!("cancelled")),
            crate::codeentry::Outcome::Interrupted => Err(anyhow::anyhow!("interrupted")),
        }
    }
    fn line(&self, prompt: &str) -> Result<String> {
        crate::prompt_line(prompt)
    }
    fn echo(&self, ch: char) {
        crate::ui::answer_echo(ch)
    }
    fn enter_raw_mode(&self) -> Option<Box<dyn RawMode>> {
        Some(Box::new(CliRawMode(crate::TtyGuard::raw())))
    }
}
