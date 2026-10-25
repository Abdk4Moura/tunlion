//! The CLI's host-side receive capabilities.
//!
//! The dispatch loop lives in `filament_peerloop::recv::dispatch`. This module
//! implements the narrow capability traits it asks for, forwarding to the
//! machine-bound implementations that already existed here: the identity
//! lifecycle, the devices store, the optional inbound servers (PTY/exec/
//! forward/sync/mount/ssh), the daemon control plane, and stdin.
//!
//! The dispatch feature and the `mesh`/`mount-server` sectors decide which
//! implementations are linked; the adapter has no separate server feature.

use crate::l2;
use crate::recv_cmd::park_on_deny;
use crate::ShellPolicy;
use crate::{enqueue_if_requestable, identity, refusal};
use crate::{shell_argv, shell_root_note, spawn_session_pumps};
use anyhow::{Context, Result};
use filament_peerloop::conn::Conn;
use filament_peerloop::control::Req;
use filament_peerloop::driver::Cancellation as _;
use filament_peerloop::host::HostServices;
use filament_peerloop::host::{LogSink, Tone};
use filament_peerloop::l2 as lib_l2;
use filament_peerloop::l2::forward;
use filament_peerloop::l2::Mux;
use filament_peerloop::recv::dispatch::{self, settle_timeout_reason};
use filament_peerloop::recv::dispatch::{ParkKind, ParkedOpen};
use filament_peerloop::recv::enrollment::EnrollmentService;
use filament_peerloop::recv::fleet_rv::FleetService;
use filament_peerloop::recv::identity::IdentityService;
use filament_peerloop::recv::ports::{
    RawMode, RecvDaemon, RecvEnv, RecvIdentity, RecvPorts, RecvPrompt, RecvServers, RecvStore,
};
use filament_peerloop::recv::report::RecvReport;
use filament_peerloop::recv::servers::shell::{PipeItem, PtyBackend, PtySession, PtySpawnSpec};
use filament_peerloop::recv::IncomingFile;
use filament_peerloop::recv::MeshTunnel;
use filament_peerloop::session::Session;
use filament_peerloop::shell::ShellHost;
use filament_peerloop::shell_gate::PeerAuthz;
use filament_proto as protocol;
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
    /// One identity service for this receive loop. Its drop-once state is
    /// per-instance and must outlive individual dispatch calls.
    pub identity: IdentityService,
    /// One enrollment runtime for this receive loop: nonces, live burns and
    /// rate-limit windows are per instance, never process globals.
    pub enrollment: EnrollmentService,
    /// Fleet rendezvous facts with this instance's explicit root/key/routes.
    pub fleet: FleetService,
    pub pty_sessions: std::sync::Arc<l2::PtySessions>,
    pub warm_ptys: crate::WarmPtys,
    pub liveness: crate::LivenessProbes,
    pub pending_bootstrap: crate::platform::PendingBootstraps,
    pub daemon_mounts: crate::DaemonMounts,
    pub last_mount_check: Instant,
    #[cfg(feature = "exec-server")]
    pub exec_process: Arc<dyn filament_peerloop::shell::exec::ExecProcess>,
    #[cfg(feature = "mesh")]
    pub exposer: Option<Arc<crate::expose::Exposer>>,
}

fn fleet_service() -> FleetService {
    FleetService::new(
        crate::devices_store::store(),
        filament_peerloop::recv::store::OverlayKey::new(
            crate::platform::Paths::config_path("overlay.ed25519"),
        ),
        crate::platform::Paths::config_path("overlay.announce-seq"),
        crate::display_name(),
        crate::l3::advertised_prefixes(),
    )
}

fn enrollment_service(log: Arc<dyn LogSink>) -> EnrollmentService {
    EnrollmentService::new(
        crate::devices_store::store(),
        filament_peerloop::recv::store::OverlayKey::new(
            crate::platform::Paths::config_path("overlay.ed25519"),
        ),
        crate::display_name(),
        log,
    )
}

impl Default for CliRecv {
    fn default() -> Self {
        let log: Arc<dyn LogSink> = Arc::new(filament_peerloop::host::NoLog);
        Self {
            identity: crate::identity_lifecycle::service_with_log(log.clone()),
            enrollment: enrollment_service(log.clone()),
            fleet: fleet_service(),
            log,
            pty_sessions: l2::PtySessions::new(),
            warm_ptys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            liveness: crate::LivenessProbes::new(),
            pending_bootstrap: Default::default(),
            daemon_mounts: crate::DaemonMounts {
                entries: HashMap::new(),
                children: HashMap::new(),
            },
            last_mount_check: Instant::now(),
            #[cfg(feature = "exec-server")]
            exec_process: Arc::new(crate::exec_recv::CliExecProcess),
            #[cfg(feature = "mesh")]
            exposer: None,
        }
    }
}

impl CliRecv {
    pub fn new(log: Arc<dyn LogSink>) -> Self {
        let mut recv = Self::default();
        recv.log = log;
        recv.identity = crate::identity_lifecycle::service_with_log(recv.log.clone());
        recv.enrollment = enrollment_service(recv.log.clone());
        recv.fleet = fleet_service();
        recv
    }

    /// The identity service for this receive loop, sharing its log sink.
    fn identity(&self) -> &IdentityService {
        &self.identity
    }
}

/// The receive loop's PTY capability.
///
/// With `pty-server` on this is the CLI's persistent-session backend: the
/// library owns every protocol decision, and every process effect (spawn, IO,
/// cap, session map) stays here. With it off no backend compiles; the library
/// answers a `pty-open` by name before this value would ever be called.
pub fn pty_backend(sessions: Arc<l2::PtySessions>) -> Box<dyn PtyBackend> {
    #[cfg(feature = "pty-server")]
    {
        Box::new(CliPty { sessions })
    }
    #[cfg(not(feature = "pty-server"))]
    {
        let _ = sessions;
        Box::new(filament_peerloop::recv::servers::shell::UnavailablePty)
    }
}

#[cfg(feature = "pty-server")]
pub struct CliPty {
    pub sessions: Arc<l2::PtySessions>,
}

#[cfg(feature = "pty-server")]
#[async_trait::async_trait]
impl PtyBackend for CliPty {
    async fn get_live(&self, session_id: &str) -> Option<Arc<dyn PtySession>> {
        self.sessions
            .get_live(session_id)
            .await
            .map(|s| Arc::new(s) as Arc<dyn PtySession>)
    }
    fn reserve(&self) -> Option<Box<dyn std::any::Any + Send>> {
        l2::PtyGuard::try_acquire().map(|g| Box::new(g) as Box<dyn std::any::Any + Send>)
    }
    async fn spawn(
        &self,
        spec: PtySpawnSpec,
        reservation: Box<dyn std::any::Any + Send>,
    ) -> Option<Arc<dyn PtySession>> {
        let guard = reservation.downcast::<l2::PtyGuard>().ok()?;
        let handle = l2::spawn_pty_session(
            self.sessions.clone(),
            spec.session_id,
            spec.transport,
            spec.sid,
            spec.cols,
            spec.rows,
            &spec.term,
            spec.argv,
            *guard,
            spec.device_pub,
            spec.admitted_via_ceiling,
            spec.admitted_via_owned_shell,
        )
        .await?;
        Some(Arc::new(handle))
    }
    async fn forget(&self, session_id: &str) {
        // The session task also removes itself when it exits, but that is
        // asynchronous: an explicit close must make the id absent NOW so the
        // very next open with the same stable id spawns instead of reattaching
        // to the handle that is still being torn down.
        self.sessions.remove(session_id).await;
    }
    fn start_pumps(
        &self,
        session: Arc<dyn PtySession>,
        input: tokio::sync::mpsc::Receiver<PipeItem>,
        resize: tokio::sync::mpsc::UnboundedReceiver<(u16, u16)>,
    ) {
        let Some(handle) = session.as_any().downcast_ref::<l2::PtySessionHandle>() else {
            return;
        };
        spawn_session_pumps(handle.clone(), input, resize);
    }
    fn shell_argv(&self, shell_user: &Option<String>) -> Vec<String> {
        shell_argv(None, shell_user.as_deref()).0
    }
    fn user_drop_available(&self, shell_user: &Option<String>) -> bool {
        // One source for the admission fact: `--shell-user` is set, this
        // process is not root, and the platform can actually drop to it.
        shell_user.is_some()
            && shell_root_note().is_empty()
            && shell_argv(None, shell_user.as_deref()).1
    }
}

#[cfg(feature = "pty-server")]
impl filament_peerloop::recv::servers::shell::PtySession for l2::PtySessionHandle {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn attach(
        &self,
        t: Arc<dyn filament_transport::net::Transport>,
        sid: u32,
        resume_from: Option<u64>,
    ) {
        l2::PtySessionHandle::attach(self, t, sid, resume_from)
    }
    fn resize(&self, cols: u16, rows: u16) {
        l2::PtySessionHandle::resize(self, cols, rows)
    }
    fn detach(&self) {
        l2::PtySessionHandle::detach(self)
    }
    fn end(&self) {
        l2::PtySessionHandle::end(self)
    }
    fn set_end_cleanup(&self, cleanup: Box<dyn FnOnce() + Send>) -> bool {
        l2::PtySessionHandle::set_end_cleanup(self, cleanup)
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
        self.identity()
            .issue_proven_challenge_and_hold(conn, pid, t, pending_proven, identity_nonces)
            .await
    }
    async fn respond_to_identity_challenge(&self, t: &Arc<dyn Transport>, v: &Value) {
        self.identity().respond_to_identity_challenge(t, v).await
    }
    fn handle_identity_expose(
        &self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        self.identity()
            .handle_identity_expose(conn, pid, v, identity_nonces)
    }
    fn store_provisional_identity(&self, name: &str, cert: &identity::DeviceCert) -> Result<()> {
        self.identity()
            .store()
            .store_provisional_identity(name, cert)
    }
    fn load_provisional_identity(&self, name: &str) -> Option<identity::DeviceCert> {
        self.identity().store().load_provisional_identity(name)
    }
    fn clear_provisional_identity(&self, name: &str) {
        self.identity().store().clear_provisional_identity(name)
    }
    fn local_device_cert(&self) -> Option<identity::DeviceCert> {
        self.identity().local_device_cert()
    }
    async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str) {
        self.identity().maybe_request_cert_renewal(conn, pid).await
    }
    async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String) {
        self.identity()
            .respond_to_cert_renew_request(conn, pid)
            .await
    }
    async fn handle_cert_renew_ack(&self, v: &Value) {
        self.identity().handle_cert_renew_ack(v).await
    }
    async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value) {
        self.enrollment
            .respond_to_auth_key_enroll_request(conn, pid, v)
            .await
    }
    async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value) {
        self.enrollment
            .handle_auth_key_enroll_response(conn, pid, v)
            .await
    }
    fn gate_settle_ms(&self) -> u64 {
        self.identity().gate_settle_ms()
    }
    fn hold_expired(&self, held: Instant) -> bool {
        held <= Instant::now()
    }
    async fn resend_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        identity_nonces: &HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        self.identity()
            .resend_identity_challenge(conn, pid, identity_nonces)
            .await
    }
    fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        self.identity().device_name_for_pub(device_pub)
    }
    fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        self.identity().device_cert_revoked(device_pub)
    }
    fn owner_pub_for_resources(&self) -> Option<[u8; 32]> {
        self.identity().owner_pub_for_resources()
    }
    fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<refusal::Reinvite> {
        self.identity().reinvite_for(device_pub)
    }
    fn reinvite_refusal(
        &self,
        refusal: refusal::Refusal,
        device_pub: Option<&[u8; 32]>,
    ) -> refusal::Refusal {
        crate::refusal::with_reinvite_for(refusal, device_pub)
    }
    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        self.identity().enroll_channel(public_key)
    }
    fn is_armed(&self) -> bool {
        self.identity().is_armed()
    }
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        owner_pub: &[u8; 32],
        now: u64,
    ) -> Result<bool> {
        filament_peerloop::recv::roster::verify_and_store_roster(
            self.identity.store(),
            blob,
            owner_pub,
            now,
        )
    }
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        filament_peerloop::recv::membership::verify_depart(device_pub, msg, sig)
    }
    fn fleet_channel(&self) -> Option<String> {
        self.fleet.channel()
    }
    fn fleet_rv(&self) -> Option<String> {
        self.fleet.rv()
    }
    fn is_fleet_channel(&self, ch: &str) -> bool {
        self.fleet.is_fleet_channel(ch)
    }
    fn make_fleet_hello(&self, cb: &[u8], name: &str) -> Result<Value> {
        // The route list is a live config fact; resolve it at hello time and
        // hand it to the library explicitly.
        self.fleet
            .with_routes(crate::l3::advertised_prefixes())
            .make_hello(cb, name)
    }
    fn fleet_owner_pub(&self) -> Option<[u8; 32]> {
        self.fleet.owner_pub()
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
        self.identity()
            .store()
            .promote_provisional_identity(name, cert, scope)
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
    fn devices_find_by_device_pub(&self, device_pub: &[u8; 32]) -> Option<Value> {
        crate::device_view::devices_find_by_device_pub(device_pub)
    }
    fn any_shell_grant(&self) -> bool {
        crate::shell_support::shell_serving_wanted()
    }
}

#[async_trait::async_trait]
impl RecvServers for CliRecv {
    /// Accept one `l2-open` forward frame by delegating admission to the library.
    ///
    /// The endpoint owns the gate, expose bound, allowlist answer, raw-trusted mux
    /// check and capacity/collision ordering. This wrapper keeps the two things
    /// that are the receive driver's: the caller-owned parking map and the dial
    /// task (`Mux::dial_and_serve`). A parked forward open is re-driven straight
    /// into this same function, so every input is re-gathered.
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
        #[cfg(feature = "exec-server")]
        {
            filament_peerloop::recv::servers::exec::open_exec(
                conn,
                &pid,
                v,
                policy,
                shell_user,
                muxes,
                l2_enabled,
                parked,
                self.exec_process.clone(),
            )
            .await
        }
        #[cfg(not(feature = "exec-server"))]
        {
            let _ = (policy, shell_user, muxes, l2_enabled, parked);
            filament_peerloop::recv::servers::exec::open_exec_unavailable(conn, &pid, v).await
        }
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
        #[cfg(feature = "ssh-sign")]
        filament_peerloop::ssh_ca::handle_ssh_sign(
            &crate::ssh_ca::CliSshCaHost,
            conn,
            pid,
            t,
            v,
            policy,
            parked,
        )
        .await;
        #[cfg(not(feature = "ssh-sign"))]
        {
            let _ = (conn, policy, parked);
            // The wire vocabulary is common; the signer is not compiled in this
            // reduced profile. Refuse a well-formed L2 sid by name so the
            // initiator reports a build limitation instead of timing out.
            if let Some(sid) = filament_peerloop::l2::wire_sid(v)
                .filter(|sid| filament_peerloop::l2::is_l2_sid(*sid))
            {
                let _ = t
                    .send_control(&json!({
                        "type": "l2-close",
                        "sid": sid,
                        "err": "ssh certificate signing is not available in this build",
                    }))
                    .await;
            }
        }
    }

    fn is_exposed(&self, port: u16) -> bool {
        crate::expose::load().iter().any(|b| b.port == port)
    }
    fn forward_target_allowed(&self, name: &str, host: &str, port: u16) -> bool {
        crate::l2_policy::l2_target_allowed(name, host, port)
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
        #[cfg(feature = "mesh")]
        {
            let ex = crate::expose::Exposer::new(tunnel);
            let n = ex.reconcile().await;
            self.exposer = Some(ex);
            n
        }
        #[cfg(not(feature = "mesh"))]
        {
            let _ = tunnel;
            0
        }
    }

    async fn reconcile_expose(&mut self, tunnel: &Arc<dyn MeshTunnel>) -> usize {
        self.start_expose(tunnel.clone()).await
    }

    async fn reload_expose(&mut self) -> usize {
        #[cfg(feature = "mesh")]
        {
            match self.exposer.as_ref() {
                Some(ex) => ex.reconcile().await,
                None => 0,
            }
        }
        #[cfg(not(feature = "mesh"))]
        {
            0
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
        crate::platform::list_warm(conn_for_list, req).await
    }
    async fn mount(&mut self, req: Req, server: &str, relay: bool) {
        crate::platform::mount(
            req,
            server,
            relay,
            &mut self.daemon_mounts,
            &mut self.last_mount_check,
        )
        .await
    }
    async fn unmount(&mut self, req: Req) {
        crate::platform::unmount(req, &mut self.daemon_mounts).await
    }
    async fn list_mounts(&mut self, req: Req) {
        crate::platform::list_mounts(req, &self.daemon_mounts).await
    }
    async fn mount_health(&mut self, req: Req) {
        crate::platform::mount_health(req, &self.daemon_mounts).await
    }
    async fn mount_health_tick(&mut self, host: &dyn HostServices) {
        crate::platform::mount_health_tick(host, &mut self.daemon_mounts, self.log.as_ref()).await;
    }
    async fn warm_bootstrap(&mut self, conn: &Conn, _tx: &mpsc::UnboundedSender<Ev>, req: Req) {
        crate::platform::warm_bootstrap(conn, &mut self.pending_bootstrap, req).await
    }
    async fn complete_warm_bootstrap(&mut self, _conn: &Conn, pid: &str, reply: &Value) {
        crate::platform::complete_warm_bootstrap(&mut self.pending_bootstrap, pid, reply).await
    }
    fn reap_warm_bootstraps(&mut self) {
        crate::platform::reap_warm_bootstraps(&mut self.pending_bootstrap)
    }
    fn revocation_snapshot(&self) -> Option<(String, String)> {
        crate::revocation_live::store_snapshot()
    }
    fn prune_to_store(&self, held: &mut Vec<(String, String)>) -> HashSet<String> {
        crate::revocation_live::prune_to_store(held)
    }
    fn key_listed(&self, device_pub: &[u8; 32]) -> bool {
        crate::revocation_live::key_listed(device_pub)
    }
    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
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
        filament_peerloop::recv::roster::verify_and_store_roster(
            self.identity.store(),
            blob,
            owner_pub,
            now,
        )
    }
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        filament_peerloop::recv::membership::verify_depart(device_pub, msg, sig)
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
    fn wg_local_offer(&self) -> Result<(String, u16)> {
        crate::wg::local_offer()
    }
    async fn wg_adopt_peer(
        &mut self,
        peer_pub: &str,
        peer_overlay: &str,
        our_overlay: &str,
        mtu: u32,
        peer_underlay: std::net::IpAddr,
        peer_wg_port: u16,
    ) -> Result<()> {
        crate::wg::adopt_peer(
            peer_pub,
            peer_overlay,
            our_overlay,
            mtu,
            peer_underlay,
            peer_wg_port,
        )
        .await
    }
    fn subnet_enable(&mut self, ifname: &str, prefixes: &[String], snat: bool) -> Result<()> {
        crate::subnet_forward::enable(ifname, prefixes, snat).map(|_| ())
    }
    fn configure_sshd_overlay(&mut self, v6: &str, v4: &str) -> Result<()> {
        #[cfg(feature = "ssh-server")]
        {
            crate::sshd::configure_sshd_overlay(v6, v4)
        }
        #[cfg(not(feature = "ssh-server"))]
        {
            let _ = (v6, v4);
            anyhow::bail!("sshd configuration is not available in this build")
        }
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
    async fn reach_pong(&mut self, conn: &Conn, pid: &str, v: &Value) {
        let peer = conn.links.get(pid).and_then(|l| l.verified_name.as_deref());
        self.liveness.answered(peer, pid, v);
    }
    fn peer_present(&self, alive: bool, direct: bool, heard_ms: Option<u64>, idle_ms: u64) -> bool {
        crate::link_manager::peer_present(alive, direct, heard_ms, idle_ms)
    }
    fn daemon_alive(&self) -> Option<u32> {
        crate::daemon_alive()
    }
    async fn start_proxy(
        &mut self,
        server: &str,
        relay: bool,
    ) -> std::result::Result<(u16, Vec<String>), String> {
        let (listener, port) = l2::bind_auto_proxy(1080).await?;
        let tok = l2::proxy_token().map_err(|e| format!("cannot create its token: {e}"))?;
        self.record_proxy("127.0.0.1", port);
        let server = server.to_string();
        let log = self.log.clone();
        tokio::spawn(async move {
            if let Err(e) =
                l2::proxy_serve(&server, listener, "127.0.0.1", port, 0, relay, tok.into()).await
            {
                // A proxy that stops is reported on the daemon log; the loop
                // does not own its lifetime.
                log.critical(&format!("auto-proxy on 127.0.0.1:{port} stopped: {e}"));
            }
        });
        Ok((port, l2::proxy_usage_lines("127.0.0.1", port)))
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
    fn request_reload(&mut self) {
        crate::platform::request_reload();
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
    fn spawn_stdin(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<Ev>,
        question_open: Arc<std::sync::atomic::AtomicBool>,
        present: Arc<dyn filament_peerloop::present::Presentation>,
    ) -> Option<Box<dyn filament_peerloop::recv::ports::StdinOwner>> {
        crate::platform::spawn_stdin(tx, question_open, present)
    }
}

/// The CLI's ambient settle-then-evaluate entry. The library decision takes
/// the four host answers as closures; this adapter supplies the process's own
/// device store/capability answers, exactly as the pre-move call sites did.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cli_park_on_deny(
    parked: &mut Vec<ParkedOpen>,
    conn: &Conn,
    pid: &str,
    kind: ParkKind,
    t: &Arc<dyn Transport>,
    sid: u32,
    v: &Value,
    gate_reason: &str,
) -> bool {
    let known = |p: &[u8; 32]| crate::device_view::devices_find_by_device_pub(p).is_some();
    let revoked = |p: &[u8; 32]| crate::device_view::device_cert_revoked(p);
    let delegated = |p: &[u8; 32]| {
        crate::identity_state::delegated_access_for(p)
            .is_some_and(|a| a.expired(identity::now_secs()))
    };
    let denied = |n: &str, c: &str| crate::device_capability_denied(n, c);
    filament_peerloop::recv::dispatch::park_on_deny(
        &known,
        &revoked,
        &delegated,
        &denied,
        crate::identity_state::gate_settle_ms(),
        parked,
        conn,
        pid,
        kind,
        t,
        sid,
        v,
        gate_reason,
    )
    .await
}
