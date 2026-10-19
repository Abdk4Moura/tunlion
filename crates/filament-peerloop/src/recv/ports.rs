//! The receive dispatch's host boundary.
//!
//! The dispatch loop is library code: it owns the event match, transfer state,
//! consent, completion and cleanup. What stays host-side is grouped by the
//! capability it needs, never bundled into one "do everything" trait:
//!
//! * [`RecvIdentity`] — identity proofs, certificate renewal and enrolment.
//! * [`RecvStore`] — the devices/capability store's mutating operations.
//! * [`RecvServers`] — the optional inbound servers (PTY/exec/forward/sync/
//!   mount/ssh). A reduced engine profile (Android) compiles none of these;
//!   it still compiles the dispatch and answers those opens with a refusal.
//! * [`RecvDaemon`] — the long-lived daemon's control-plane state (warm links,
//!   mounts, bootstraps). Also optional.
//! * [`RecvPrompt`] — stdin interaction (a code, a confirmation), which the
//!   CLI owns because it is a terminal.
//!
//! Machine facts that already had an interface stay on
//! [`HostServices`](crate::host::HostServices); presentation stays on
//! [`Presentation`](crate::present::Presentation); logging on
//! [`LogSink`](crate::host::LogSink). Nothing here is a second copy of those.

use crate::conn::Conn;
use crate::host::HostServices;
use crate::l2::Mux;
use crate::mesh::MeshTunnel;
use crate::recv::{IncomingFile, RecvReport};
use crate::shell_gate::ShellPolicy;
use crate::sync::serving::SyncServeTask;
use async_trait::async_trait;
use filament_id::{DeviceCert, IntroScope};
use filament_signal::Client as SignalClient;
use filament_transport::net::{Ev, Transport};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Values the process resolved before the dispatch started: the things that are
/// genuinely process policy (a name, a uid, whether stdin is a terminal, the
/// configured quiet window). Resolving them at the adapter boundary is what
/// keeps `std::env` and `std::io::stdin` out of the library loop.
#[derive(Clone, Debug)]
pub struct RecvEnv {
    pub display_name: String,
    pub uid: String,
    pub interactive_allowed: bool,
    pub interactive_requested: bool,
    pub config_name: Option<String>,
    pub consent_token: &'static str,
    pub direct_ok: bool,
    pub quiet_window: Duration,
    pub l2_forced: bool,
    pub daemon_ready: bool,
}

impl RecvEnv {
    pub fn command_arg(value: &str) -> String {
        crate::recv::dispatch::command_arg(value)
    }
}

/// Identity lifecycle: the proof/expose/renew/enrol handles the protocol drives.
#[async_trait]
pub trait RecvIdentity: Send + Sync {
    async fn issue_proven_challenge_and_hold(
        &self,
        conn: &Conn,
        pid: &str,
        t: &Arc<dyn Transport>,
        pending_proven: &Arc<std::sync::Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    );
    async fn respond_to_identity_challenge(&self, t: &Arc<dyn Transport>, v: &Value);
    fn handle_identity_expose(
        &self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool;
    fn store_provisional_identity(&self, name: &str, cert: &DeviceCert) -> anyhow::Result<()>;
    fn load_provisional_identity(&self, name: &str) -> Option<DeviceCert>;
    fn clear_provisional_identity(&self, name: &str);
    fn local_device_cert(&self) -> Option<DeviceCert>;
    async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str);
    async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String);
    async fn handle_cert_renew_ack(&self, v: &Value);
    async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value);
    async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value);
    /// Settle window for an unproven shell-class open.
    fn gate_settle_ms(&self) -> u64;
    /// A held challenge's bound passed.
    fn hold_expired(&self, held: Instant) -> bool;
    /// Re-issue a challenge for a parked open.
    async fn resend_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        identity_nonces: &HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool;
    fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String>;
    fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool;
    fn device_cert_revoked_some(&self, device_pub: Option<&[u8; 32]>) -> bool {
        device_pub
            .map(|p| self.device_cert_revoked(p))
            .unwrap_or(false)
    }
    fn owner_pub_for_resources(&self) -> Option<[u8; 32]>;
    fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<Value>;
    fn enroll_channel(&self, public_key: &[u8]) -> String;
    fn is_armed(&self) -> bool;
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        owner_pub: &[u8; 32],
        now: u64,
    ) -> anyhow::Result<bool>;
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str>;
    fn fleet_channel(&self) -> Option<String>;
    fn fleet_rv(&self) -> Option<String>;
    fn is_fleet_channel(&self, ch: &str) -> bool;
    fn make_fleet_hello(&self, cb: &[u8], name: &str) -> anyhow::Result<Value>;
    fn fleet_owner_pub(&self) -> Option<[u8; 32]>;
}

/// The devices store and capability writes: the mutating half the receive
/// dispatch needs. Reads that already existed on `HostServices` are not
/// duplicated here.
#[async_trait]
pub trait RecvStore: Send + Sync {
    fn devices_path(&self) -> PathBuf;
    fn devices_touch(
        &self,
        name: &str,
        v6: Option<std::net::Ipv6Addr>,
        v4: Option<std::net::Ipv4Addr>,
    );
    fn devices_remove(&self, name: &str) -> anyhow::Result<()>;
    fn devices_store(&self, name: &str, secret: &str) -> anyhow::Result<String>;
    fn devices_store_new(
        &self,
        name: &str,
        secret: &str,
        introduced_by: Option<&str>,
    ) -> anyhow::Result<String>;
    fn device_was_introduced(&self, name: &str) -> bool;
    fn devices_sweep_lapsed(&self, now: u64) -> usize;
    #[allow(clippy::too_many_arguments)]
    fn devices_upsert_atomic(
        &self,
        name: &str,
        secret: Option<&str>,
        cert: Option<&DeviceCert>,
        caps: Option<&[String]>,
        scope: Option<u8>,
        user_key_hex: Option<&str>,
        delegated: Option<(&[String], u64, u64, u64)>,
        allow_reanchor: bool,
    ) -> anyhow::Result<String>;
    /// Promote a provisional identity into the durable store through the one
    /// locked read-modify-write path.
    fn promote_provisional_identity(
        &self,
        name: &str,
        cert: &DeviceCert,
        scope: u8,
    ) -> anyhow::Result<()>;
    fn mark_bounded_cap_source(
        &self,
        name: &str,
        capability: &str,
        source: &str,
    ) -> anyhow::Result<()>;
    fn merge_owner_cap_ops(&self, ops: &[Value]) -> usize;
    fn owner_signed_cap_ops(&self) -> Vec<Value>;
    fn mark_lapsed_now(&self, device_pub: &[u8; 32]) -> Option<String>;
    fn sanitize_device_name(&self, name: &str) -> String;
    fn devices_find_by_device_pub(&self, device_pub: &[u8; 32]) -> Option<Value>;
    fn any_shell_grant(&self) -> bool;
}

/// Optional inbound servers. The default reduced profile has none of these and
/// a frame is refused honestly by the fallback implementation.
#[async_trait]
pub trait RecvServers: Send + Sync {
    async fn retire_link(
        &mut self,
        pid: &str,
        muxes: &mut HashMap<String, Arc<Mux>>,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    );
    #[allow(clippy::too_many_arguments)]
    async fn open_pty(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        policy: &ShellPolicy,
        shell_user: &Option<String>,
        muxes: &mut HashMap<String, Arc<Mux>>,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
        l2_enabled: bool,
        parked: &mut Vec<crate::recv::dispatch::ParkedOpen>,
    );
    #[allow(clippy::too_many_arguments)]
    async fn open_exec(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        policy: &ShellPolicy,
        shell_user: &Option<String>,
        muxes: &mut HashMap<String, Arc<Mux>>,
        l2_enabled: bool,
        parked: &mut Vec<crate::recv::dispatch::ParkedOpen>,
    );
    #[allow(clippy::too_many_arguments)]
    async fn open_forward(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        policy: &ShellPolicy,
        muxes: &mut HashMap<String, Arc<Mux>>,
        l2_enabled: bool,
        parked: &mut Vec<crate::recv::dispatch::ParkedOpen>,
    );
    #[allow(clippy::too_many_arguments)]
    async fn open_sync(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        dir: &Path,
        parked: &mut Vec<crate::recv::dispatch::ParkedOpen>,
    ) -> Option<(u32, SyncServeTask)>;
    #[allow(clippy::too_many_arguments)]
    async fn open_mount(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        share_root: &Path,
    );
    #[allow(clippy::too_many_arguments)]
    async fn ssh_sign(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        t: Arc<dyn Transport>,
        v: &Value,
        policy: &ShellPolicy,
        parked: &mut Vec<crate::recv::dispatch::ParkedOpen>,
    );
    /// A `pty-resize` control for a stable session id.
    async fn pty_resize(
        &mut self,
        pid: &str,
        v: &Value,
        muxes: &mut HashMap<String, Arc<Mux>>,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    );
    /// A `pty-close` control: end the shell and forget the session.
    async fn pty_close(
        &mut self,
        pid: &str,
        v: &Value,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    );
    /// A link's transport died: detach (not kill) its live PTY sessions.
    async fn detach_link_ptys(
        &mut self,
        pid: &str,
        bindings: &mut HashMap<String, HashMap<u32, String>>,
    );
    /// Route `exec-alive`/`exec-signal` to the exec session on this link.
    async fn exec_control(
        &mut self,
        pid: &str,
        v: &Value,
        muxes: &HashMap<String, Arc<Mux>>,
    ) -> bool;
    /// Apply a live `up` reconfigure request; true when serving state changed.
    #[allow(clippy::too_many_arguments)]
    async fn apply_reconfigure(
        &mut self,
        key: &str,
        dir: &mut PathBuf,
        shell_policy: &mut ShellPolicy,
        shell_user: &mut Option<String>,
        l2_enabled: bool,
        sess: &mut crate::session::Session,
        sio: &SignalClient,
        my_uid: &str,
    ) -> bool;
    /// Bind the persisted `expose` ports once the overlay is up.
    async fn start_expose(&mut self, tunnel: Arc<dyn MeshTunnel>) -> usize;
    async fn reconcile_expose(&mut self, tunnel: &Arc<dyn MeshTunnel>) -> usize;
    /// A live `reload-expose` request.
    async fn reload_expose(&mut self) -> usize;
}

/// The long-lived daemon's control plane. State (mounts, warm PTYs, probes,
/// bootstraps) lives in the implementation.
#[async_trait]
pub trait RecvDaemon: Send + Sync {
    async fn warm_req(
        &mut self,
        conn: &Conn,
        muxes: &mut HashMap<String, Arc<Mux>>,
        tx: &mpsc::UnboundedSender<Ev>,
        req: crate::control::Req,
    );
    async fn list_warm(&mut self, req: crate::control::Req, conn: &Conn);
    async fn mount(&mut self, req: crate::control::Req, server: &str, relay: bool);
    async fn unmount(&mut self, req: crate::control::Req);
    async fn list_mounts(&mut self, req: crate::control::Req);
    async fn mount_health(&mut self, req: crate::control::Req);
    /// Remove mounts whose host path vanished; daemon-only, periodic.
    async fn mount_health_tick(&mut self, host: &dyn HostServices);
    #[allow(clippy::too_many_arguments)]
    async fn bootstrap_ack(
        &mut self,
        conn: &Conn,
        pid: &str,
        v: &Value,
        tx: &mpsc::UnboundedSender<Ev>,
    );
    async fn bootstrap_deny(&mut self, conn: &Conn, pid: &str, v: &Value);
    /// `reach-ping`/`reach-pong` liveness probes.
    async fn reach_ping(&mut self, conn: &Conn, pid: &str, v: &Value);
    async fn reach_pong(&mut self, conn: &Conn, pid: &str, v: &Value);
    fn peer_present(&self, alive: bool, direct: bool, heard_ms: Option<u64>, idle_ms: u64) -> bool;
    async fn warm_bootstrap(
        &mut self,
        conn: &Conn,
        tx: &mpsc::UnboundedSender<Ev>,
        req: crate::control::Req,
    );
    async fn complete_warm_bootstrap(&mut self, conn: &Conn, pid: &str, reply: &Value);
    fn reap_warm_bootstraps(&mut self);
    fn revocation_snapshot(&self) -> Option<HashSet<String>>;
    fn prune_to_store(&self, held: &mut Vec<(String, String)>) -> HashSet<String>;
    fn key_listed(&self, device_pub: &[u8; 32]) -> bool;
    fn enroll_channel(&self, public_key: &[u8]) -> String;
    fn is_armed(&self) -> bool;
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        owner_pub: &[u8; 32],
        now: u64,
    ) -> anyhow::Result<bool>;
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str>;
    fn fleet_share_root(&self) -> PathBuf;
    fn mark_daemon_ready(&mut self);
    fn record_proxy(&self, bind: &str, port: u16);
    fn maybe_hint_local_wedge(&mut self, shown: &mut bool);
    fn wg_usable(&self) -> bool;
    fn wg_claim_attempt(&self, addr: &str) -> bool;
    fn wg_release_attempt(&self, addr: &str);
    fn wg_local_offer(&self) -> anyhow::Result<(String, u16)>;
    async fn wg_adopt_peer(
        &mut self,
        peer_pub: &str,
        peer_overlay: &str,
        our_overlay: &str,
        mtu: u32,
        peer_underlay: std::net::IpAddr,
        peer_wg_port: u16,
    ) -> anyhow::Result<()>;
    /// Enable/refresh subnet forwarding for the advertised prefixes.
    fn subnet_enable(
        &mut self,
        ifname: &str,
        prefixes: &[String],
        snat: bool,
    ) -> anyhow::Result<()>;
    /// Configure/refresh the sshd-overlay listener.
    fn configure_sshd_overlay(&mut self, v6: &str, v4: &str) -> anyhow::Result<()>;
    /// Start the optional overlay servers (sshd overlay, subnet forward).
    async fn start_overlay_servers(&mut self, host: &dyn HostServices) -> Vec<String>;
    fn daemon_alive(&self) -> Option<u32>;
    /// Bind/spawn the userspace SOCKS5 proxy; returns its port and usage lines.
    async fn start_proxy(
        &mut self,
        server: &str,
        relay: bool,
    ) -> std::result::Result<(u16, Vec<String>), String>;
    fn sdnotify_ready(&self);
    fn sdnotify_status(&self, status: &str);
    fn sdnotify_watchdog(&self);
}

/// Terminal interaction: the code prompt and the confirmation line.
pub trait RawMode: Send {}

pub trait RecvPrompt: Send + Sync {
    /// Ask for a code; `Ok(None)` means an empty submission, `Err` cancellation
    /// or interrupt.
    fn ask_code(&self, prompt: &str) -> anyhow::Result<Option<String>>;
    fn line(&self, prompt: &str) -> anyhow::Result<String>;
    fn echo(&self, ch: char);
    /// Put the terminal in cbreak mode; the returned guard restores it.
    fn enter_raw_mode(&self) -> Option<Box<dyn RawMode>>;
}

/// What the receive dispatch is handed once, at its entry.
pub struct RecvPorts {
    pub identity: Arc<dyn RecvIdentity>,
    pub store: Arc<dyn RecvStore>,
    pub servers: Box<dyn RecvServers>,
    pub daemon: Box<dyn RecvDaemon>,
    pub prompt: Arc<dyn RecvPrompt>,
    pub present: Arc<dyn crate::present::Presentation>,
    pub env: RecvEnv,
}

impl RecvPorts {
    pub fn new(
        identity: Arc<dyn RecvIdentity>,
        store: Arc<dyn RecvStore>,
        servers: Box<dyn RecvServers>,
        daemon: Box<dyn RecvDaemon>,
        prompt: Arc<dyn RecvPrompt>,
        present: Arc<dyn crate::present::Presentation>,
        env: RecvEnv,
    ) -> Self {
        Self {
            identity,
            store,
            servers,
            daemon,
            prompt,
            present,
            env,
        }
    }
}

/// Unused imports that keep the public signatures readable.
#[allow(dead_code)]
fn _type_anchors(_: &IncomingFile, _: &RecvReport, _: &Path, _: &HashSet<String>, _: IntroScope) {}
