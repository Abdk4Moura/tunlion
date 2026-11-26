use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use filament_transport::clock;
use filament_transport::net::Transport;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

use crate::conn::Conn;
use crate::control::{Req, ReqKind};
use crate::driver::{Cancellation, DriverOutcome, Engine};
use crate::host::{HostServices, Level, LogSink, Tone};
use crate::recv::dispatch::{drive, RecvCleanup};
use crate::recv::ports::test_support::{NoDaemon, NoIdentity, NoPrompt, NoPty, NoServers, NoStore};
use crate::recv::ports::{RecvDaemon, RecvEnv, RecvIdentity, RecvPorts};
use crate::recv::report::RecvReport;
use crate::shell_gate::ShellPolicy;
use crate::sim::assertions::{record_sometimes, reset_assertions, take_assertions, AssertionReport};
use crate::sim::net::{Fault, NetTraceEvent, SimNetwork};
use crate::sim::semantic::{
    ProtoEvent, SemanticAction, SemanticFault, SemanticTrigger, StateEdge, StateTransition,
};
use crate::sim_rt;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SimMutant {
    #[default]
    None,
    /// Planted canary: stalls inline if CapStatus runs during signaling blackhole.
    CanaryOnBlackholeStatus,
    /// In-process mirror of pre-#729 inline heartbeat stall when blackhole spans silence threshold.
    Pre729InlineHeartbeat,
    /// Noise-sensitive bug masked when partitions co-occur during restart+blackhole.
    NoiseSensitiveRestartInBlackhole,
    /// Timer-edge bug near 15s / 30s silence boundaries combined with CapStatus near timer edges.
    TimerEdgeSilenceBoundary,
    /// Simulates the send-reconnect bug dropping post-heal reconnects (caught by Tier-1 oracle).
    PostHealDroppedReconnect,
}

#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub name: String,
    pub uid: String,
    /// Paired peer records visible to this node: `(peer_name, shared_secret)`.
    pub peers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct ScheduledFault {
    pub at_ms: u64,
    pub fault: Fault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimTraceEntry {
    pub at_ms: u64,
    pub node: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct CapStatusResult {
    pub at_ms: u64,
    pub node: String,
    pub latency_ms: u64,
    pub response: Value,
}

#[derive(Debug, Clone)]
pub struct SimOutcome {
    pub seed: u64,
    pub trace_hash: u64,
    pub events: Vec<SimTraceEntry>,
    pub net_events: Vec<NetTraceEvent>,
    pub budget_violations: Vec<String>,
    pub cap_status_results: Vec<CapStatusResult>,
    pub telemetry: sim_rt::SimTelemetry,
    pub assertions: AssertionReport,
    pub state_edges: BTreeSet<StateEdge>,
    pub state_transitions: Vec<StateTransition>,
}

#[derive(Clone, Default)]
pub struct SimConfig {
    pub seed: u64,
    pub duration_ms: u64,
    pub nodes: Vec<NodeSpec>,
    pub schedule: Vec<ScheduledFault>,
    pub restart_node: Option<(String, u64, u64)>,
    pub cap_status_queries: Vec<(String, u64)>,
    pub inline_stall_injection: Option<(u64, u64)>,
    pub mutant: SimMutant,
    pub quiet_logs: bool,
    pub semantic_faults: Vec<SemanticFault>,
}

struct CapturingLog {
    node: String,
    sink: Arc<Mutex<Vec<SimTraceEntry>>>,
    quiet_logs: bool,
}

impl LogSink for CapturingLog {
    fn debug(&self, line: &str) {
        self.push("debug", line);
    }

    fn trace(&self, _line: &str) {}

    fn say(&self, line: &str) {
        self.push("say", line);
    }

    fn critical(&self, line: &str) {
        self.push("critical", line);
    }

    fn paint(&self, _tone: Tone, s: &str) -> String {
        s.to_string()
    }

    fn glyph_ok(&self) -> &'static str {
        "ok"
    }

    fn glyph_warn(&self) -> &'static str {
        "!"
    }

    fn enabled(&self, level: Level) -> bool {
        !matches!(level, Level::Trace)
    }
}

impl CapturingLog {
    fn push(&self, level: &str, line: &str) {
        if self.quiet_logs && level != "critical" {
            return;
        }
        let mut g = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        g.push(SimTraceEntry {
            at_ms: clock::now_ms(),
            node: self.node.clone(),
            message: format!("[{level}] {line}"),
        });
    }
}

struct SimHost {
    peers: Vec<(String, String)>,
    ctl_slot: Arc<Mutex<Option<mpsc::UnboundedSender<Req>>>>,
}

#[async_trait]
impl HostServices for SimHost {
    fn settings_get_str(&self, key: &str) -> Option<String> {
        match key {
            "network.transports" => Some("direct,relay".to_string()),
            "lan" => Some("0".to_string()),
            "auto-warm" => Some("1".to_string()),
            _ => None,
        }
    }

    fn settings_get_bool(&self, key: &str) -> bool {
        key == "auto-warm"
    }

    fn devices_load(&self) -> Vec<(String, String)> {
        self.peers.clone()
    }

    fn is_self_uid(&self, my_uid: &str, peer_uid: Option<&str>) -> bool {
        peer_uid == Some(my_uid)
    }

    fn rejoin_unwarned(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn relay_banner(&self) -> String {
        String::new()
    }

    fn relay_forbidden(&self) -> bool {
        false
    }

    fn channel_of(&self, secret: &str) -> String {
        crate::recv::store::channel_of(secret)
    }

    fn roster_snapshot_json(&self) -> Option<String> {
        None
    }

    fn fleet_rv_present(&self) -> bool {
        false
    }

    fn device_allows(&self, _name: &str, capability: &str) -> bool {
        capability == "transfer" || !self.peers.is_empty()
    }

    fn device_record_revoked(&self, _name: &str) -> bool {
        false
    }

    async fn serve_control(
        &self,
        tx: mpsc::UnboundedSender<Req>,
        ready: Option<oneshot::Sender<()>>,
    ) -> std::result::Result<(), String> {
        *self.ctl_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        if let Some(r) = ready {
            let _ = r.send(());
        }
        Ok(())
    }
}

struct SimIdentity(NoIdentity);

#[async_trait]
impl RecvIdentity for SimIdentity {
    async fn issue_proven_challenge_and_hold(
        &self,
        _: &Conn,
        _: &str,
        _: &Arc<dyn Transport>,
        _: &Arc<Mutex<HashMap<String, (Arc<dyn Transport>, filament_transport::clock::Instant)>>>,
        _: &mut HashMap<String, ([u8; 32], filament_transport::clock::Instant, [u8; 32])>,
    ) {
    }

    async fn respond_to_identity_challenge(&self, _: &Arc<dyn Transport>, _: &Value) {}

    fn handle_identity_expose(
        &self,
        _: &mut Conn,
        _: &str,
        _: &Value,
        _: &mut HashMap<String, ([u8; 32], filament_transport::clock::Instant, [u8; 32])>,
    ) -> bool {
        false
    }

    fn store_provisional_identity(
        &self,
        _: &str,
        _: &filament_id::DeviceCert,
    ) -> Result<()> {
        Ok(())
    }

    fn load_provisional_identity(&self, name: &str) -> Option<filament_id::DeviceCert> {
        self.0.load_provisional_identity(name)
    }

    fn clear_provisional_identity(&self, name: &str) {
        self.0.clear_provisional_identity(name);
    }

    fn local_device_cert(&self) -> Option<filament_id::DeviceCert> {
        self.0.local_device_cert()
    }

    async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str) {
        self.0.maybe_request_cert_renewal(conn, pid).await;
    }

    async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String) {
        self.0.respond_to_cert_renew_request(conn, pid).await;
    }

    async fn handle_cert_renew_ack(&self, v: &Value) {
        self.0.handle_cert_renew_ack(v).await;
    }

    async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value) {
        self.0
            .respond_to_auth_key_enroll_request(conn, pid, v)
            .await;
    }

    async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value) {
        self.0
            .handle_auth_key_enroll_response(conn, pid, v)
            .await;
    }

    fn gate_settle_ms(&self) -> u64 {
        self.0.gate_settle_ms()
    }

    fn hold_expired(&self, held: filament_transport::clock::Instant) -> bool {
        self.0.hold_expired(held)
    }

    async fn resend_identity_challenge(
        &self,
        t: &Arc<dyn Transport>,
        pid: &str,
        identity_nonces: &HashMap<String, ([u8; 32], filament_transport::clock::Instant, [u8; 32])>,
    ) -> bool {
        self.0
            .resend_identity_challenge(t, pid, identity_nonces)
            .await
    }

    fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        self.0.device_name_for_pub(device_pub)
    }

    fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        self.0.device_cert_revoked(device_pub)
    }

    fn device_tombstoned(&self, device_pub: &[u8; 32]) -> bool {
        self.0.device_tombstoned(device_pub)
    }

    fn sibling_admissible(&self, device_pub: &[u8; 32]) -> bool {
        self.0.sibling_admissible(device_pub)
    }

    fn owner_pub_for_resources(&self) -> Option<[u8; 32]> {
        self.0.owner_pub_for_resources()
    }

    fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<crate::refusal::Reinvite> {
        self.0.reinvite_for(device_pub)
    }

    fn reinvite_refusal(
        &self,
        refusal: crate::refusal::Refusal,
        device_pub: Option<&[u8; 32]>,
    ) -> crate::refusal::Refusal {
        self.0.reinvite_refusal(refusal, device_pub)
    }

    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        self.0.enroll_channel(public_key)
    }

    fn is_armed(&self) -> bool {
        self.0.is_armed()
    }

    fn verify_and_store_roster(
        &self,
        v: &Value,
        from_pub: &[u8; 32],
        now: u64,
    ) -> Result<bool> {
        self.0.verify_and_store_roster(v, from_pub, now)
    }

    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        self.0.verify_depart(device_pub, msg, sig)
    }

    fn fleet_channel(&self) -> Option<String> {
        self.0.fleet_channel()
    }

    fn fleet_rv(&self) -> Option<String> {
        self.0.fleet_rv()
    }

    fn is_fleet_channel(&self, ch: &str) -> bool {
        self.0.is_fleet_channel(ch)
    }

    fn make_fleet_hello(&self, _: &[u8], _: &str) -> Result<Value> {
        anyhow::bail!("sim identity has no fleet cert")
    }

    fn fleet_owner_pub(&self) -> Option<[u8; 32]> {
        self.0.fleet_owner_pub()
    }
}

struct SimDaemon {
    pid: u32,
    inner: NoDaemon,
}

#[async_trait]
impl RecvDaemon for SimDaemon {
    async fn warm_req(
        &mut self,
        conn: &Conn,
        muxes: &mut HashMap<String, Arc<crate::l2::Mux>>,
        tx: &mpsc::UnboundedSender<filament_transport::net::Ev>,
        req: Req,
    ) {
        self.inner.warm_req(conn, muxes, tx, req).await;
    }

    async fn list_warm(&mut self, req: Req, conn: &Conn) {
        self.inner.list_warm(req, conn).await;
    }

    async fn mount(&mut self, req: Req, server: &str, relay: bool) {
        self.inner.mount(req, server, relay).await;
    }

    async fn unmount(&mut self, req: Req) {
        self.inner.unmount(req).await;
    }

    async fn list_mounts(&mut self, req: Req) {
        self.inner.list_mounts(req).await;
    }

    async fn mount_health(&mut self, req: Req) {
        self.inner.mount_health(req).await;
    }

    async fn mount_health_tick(&mut self, host: &dyn HostServices) {
        self.inner.mount_health_tick(host).await;
    }

    async fn warm_bootstrap(
        &mut self,
        conn: &Conn,
        tx: &mpsc::UnboundedSender<filament_transport::net::Ev>,
        req: Req,
    ) {
        self.inner.warm_bootstrap(conn, tx, req).await;
    }

    async fn reach_ping(&mut self, conn: &Conn, pid: &str, v: &Value) {
        self.inner.reach_ping(conn, pid, v).await;
    }

    async fn reach_pong(&mut self, conn: &Conn, pid: &str, v: &Value) {
        self.inner.reach_pong(conn, pid, v).await;
    }

    fn peer_present(
        &self,
        alive: bool,
        direct: bool,
        _heard_ms: Option<u64>,
        _idle_ms: u64,
    ) -> bool {
        alive || direct
    }

    async fn complete_warm_bootstrap(&mut self, conn: &Conn, pid: &str, reply: &Value) {
        self.inner.complete_warm_bootstrap(conn, pid, reply).await;
    }

    fn reap_warm_bootstraps(&mut self) {
        self.inner.reap_warm_bootstraps();
    }

    fn revocation_snapshot(&self) -> Option<(String, String)> {
        self.inner.revocation_snapshot()
    }

    fn prune_to_store(&self, _: &mut Vec<(String, String)>) -> HashSet<String> {
        HashSet::new()
    }

    fn key_listed(&self, device_pub: &[u8; 32]) -> bool {
        self.inner.key_listed(device_pub)
    }

    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        self.inner.enroll_channel(public_key)
    }

    fn is_armed(&self) -> bool {
        self.inner.is_armed()
    }

    fn verify_and_store_roster(
        &self,
        v: &Value,
        from_pub: &[u8; 32],
        now: u64,
    ) -> Result<bool> {
        self.inner.verify_and_store_roster(v, from_pub, now)
    }

    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        self.inner.verify_depart(device_pub, msg, sig)
    }

    fn fleet_share_root(&self) -> PathBuf {
        self.inner.fleet_share_root()
    }

    fn mark_daemon_ready(&mut self) {
        self.inner.mark_daemon_ready();
    }

    fn record_proxy(&self, bind: &str, port: u16) {
        self.inner.record_proxy(bind, port);
    }

    fn maybe_hint_local_wedge(&mut self, shown: &mut bool) {
        self.inner.maybe_hint_local_wedge(shown);
    }

    fn wg_usable(&self) -> bool {
        false
    }

    fn wg_claim_attempt(&self, _addr: &str) -> bool {
        false
    }

    fn wg_release_attempt(&self, _addr: &str) {}

    fn wg_local_offer(&self) -> Result<(String, u16)> {
        anyhow::bail!("sim daemon has no wg")
    }

    async fn wg_adopt_peer(
        &mut self,
        _: &str,
        _: &str,
        _: &str,
        _: u32,
        _: std::net::IpAddr,
        _: u16,
    ) -> Result<()> {
        Ok(())
    }

    fn subnet_enable(&mut self, _: &str, _: &[String], _: bool) -> Result<()> {
        Ok(())
    }

    fn configure_sshd_overlay(&mut self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    async fn start_overlay_servers(&mut self, _: &dyn HostServices) -> Vec<String> {
        Vec::new()
    }

    fn daemon_alive(&self) -> Option<u32> {
        Some(self.pid)
    }

    async fn start_proxy(
        &mut self,
        _: &str,
        _: bool,
    ) -> std::result::Result<(u16, Vec<String>), String> {
        Err("sim daemon has no proxy".to_string())
    }

    fn sdnotify_ready(&self) {}
    fn sdnotify_status(&self, _: &str) {}
    fn sdnotify_watchdog(&self) {}
    fn request_reload(&mut self) {}
}

struct RunningNode {
    spec: NodeSpec,
    engine: Option<Engine<DriverOutcome<Result<()>>>>,
    ctl_slot: Arc<Mutex<Option<mpsc::UnboundedSender<Req>>>>,
}

fn build_recv_env(spec: &NodeSpec, pid: u32) -> RecvEnv {
    RecvEnv {
        display_name: spec.name.clone(),
        uid: spec.uid.clone(),
        interactive_allowed: false,
        interactive_requested: false,
        config_name: Some(spec.name.clone()),
        consent_token: "sim".to_string(),
        direct_ok: true,
        quiet_window: Duration::from_secs(0),
        l2_forced: false,
        daemon_ready: true,
        pid,
        interactive_terminal: false,
        pair_grace: Duration::from_secs(5),
        fleet_offer_grace: Duration::from_secs(5),
        trace_throughput: false,
        fleet_hello_trace: None,
        supervised: true,
        loop_stall_secs: 60,
        stall_exit: None,
        remember_stored: Arc::new(AtomicBool::new(false)),
        delivery: Arc::new(Mutex::new(HashMap::new())),
    }
}

fn spawn_daemon(
    net: &Arc<SimNetwork>,
    spec: &NodeSpec,
    pid: u32,
    logs: Arc<Mutex<Vec<SimTraceEntry>>>,
    quiet_logs: bool,
) -> RunningNode {
    net.register_node_identity(&spec.name, &spec.uid);
    let ctl_slot = Arc::new(Mutex::new(None));
    let tctx = net.node_context(&spec.name);
    let log: Arc<dyn LogSink> = Arc::new(CapturingLog {
        node: spec.name.clone(),
        sink: logs,
        quiet_logs,
    });
    let host: Arc<dyn HostServices> = Arc::new(SimHost {
        peers: spec.peers.clone(),
        ctl_slot: ctl_slot.clone(),
    });
    let env = build_recv_env(spec, pid);
    let ports = RecvPorts::new(
        Arc::new(SimIdentity(NoIdentity)),
        Arc::new(NoStore),
        Box::new(NoServers),
        Box::new(SimDaemon {
            pid,
            inner: NoDaemon,
        }),
        Arc::new(NoPrompt),
        Box::new(NoPty),
        Arc::new(crate::present::NoScreen),
        env,
    );
    let dir = PathBuf::from(format!("/tmp/sim-inbox-{}", spec.name));
    let cancel = Cancellation::default();
    let engine = Engine::start(cancel, move |stop, readiness| async move {
        let mut cleanup = RecvCleanup::default();
        drive(
            "http://sim.local",
            None,
            dir,
            true,
            None,
            None,
            true,
            None,
            None,
            false,
            None,
            true,
            None,
            ShellPolicy::Granted,
            None,
            false,
            tctx,
            log,
            host,
            ports,
            RecvReport::new(),
            &stop,
            &readiness,
            &mut cleanup,
        )
        .await
    });
    RunningNode {
        spec: spec.clone(),
        engine: Some(engine),
        ctl_slot,
    }
}

async fn send_cap_status(node_name: &str, ctl_slot: &Arc<Mutex<Option<mpsc::UnboundedSender<Req>>>>) -> Option<CapStatusResult> {
    let tx = ctl_slot.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
    let (client, server) = UnixStream::pair().ok()?;
    let req = Req {
        kind: ReqKind::CapStatus,
        sock: server,
    };
    let start_ms = clock::now_ms();
    if tx.send(req).is_err() {
        return None;
    }
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    let read_res = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
    let latency_ms = clock::now_ms().saturating_sub(start_ms);
    let _ = reader.into_inner().shutdown().await;
    let val = match read_res {
        Ok(Ok(n)) if n > 0 => serde_json::from_str(line.trim()).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    Some(CapStatusResult {
        at_ms: start_ms,
        node: node_name.to_string(),
        latency_ms,
        response: val,
    })
}

fn fnv1a64(events: &[SimTraceEntry], net_events: &[crate::sim::net::NetTraceEvent]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for e in events {
        for b in e.at_ms.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in e.node.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in e.message.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    for n in net_events {
        for b in n.at_ms.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in n.event.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

#[derive(Default)]
struct WorldTracker {
    blackhole_starts: BTreeMap<String, u64>,
    bh_silence_boundary_hit: bool,
    bh_healed_nodes: BTreeSet<String>,
    restarted_nodes: BTreeSet<String>,
    cap_status_results: Vec<CapStatusResult>,
    next_pid: u32,
}

fn apply_world_fault(
    net: &Arc<SimNetwork>,
    tracker: &Mutex<WorldTracker>,
    mutant: &SimMutant,
    f: Fault,
    at_ms: u64,
) {
    {
        let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
        match &f {
            Fault::BlackholeSignaling { node, active: true } => {
                t.blackhole_starts.insert(node.clone(), at_ms);
            }
            Fault::BlackholeSignaling { node, active: false } => {
                if let Some(s) = t.blackhole_starts.remove(node) {
                    let dur = at_ms.saturating_sub(s);
                    if (25_000..=35_000).contains(&dur) {
                        record_sometimes("blackhole_boundary_silence");
                    }
                    if dur.abs_diff(15_000) <= 800 || dur.abs_diff(30_000) <= 800 {
                        t.bh_silence_boundary_hit = true;
                    }
                    if matches!(mutant, SimMutant::Pre729InlineHeartbeat) && dur >= 18_000 {
                        sim_rt::set_sim_inline_stall_ms(2_000);
                    }
                }
                t.bh_healed_nodes.insert(node.clone());
            }
            Fault::Impair { .. } | Fault::Partition { .. } => {
                if net.any_blackholed() || net.has_impair() || net.partition_count() > 0 {
                    record_sometimes("multi_fault_overlap");
                }
            }
            _ => {}
        }
    }
    net.apply_fault(f);
    if net.has_impair() && net.partition_count() > 0 {
        record_sometimes("impair_under_partition");
    }
}

async fn kill_world_node(
    net: &Arc<SimNetwork>,
    running: &Mutex<Vec<RunningNode>>,
    name: &str,
) {
    net.disconnect_node(name);
    let eng_and_slot = {
        let mut r = running.lock().unwrap_or_else(|e| e.into_inner());
        r.iter_mut()
            .find(|n| n.spec.name == name)
            .map(|n| (n.engine.take(), n.ctl_slot.clone()))
    };
    if let Some((maybe_eng, slot)) = eng_and_slot {
        if let Some(mut eng) = maybe_eng {
            let _ = eng.stop_within(Duration::from_secs(2)).await;
        }
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn restart_world_node(
    net: &Arc<SimNetwork>,
    tracker: &Mutex<WorldTracker>,
    running: &Mutex<Vec<RunningNode>>,
    logs: &Arc<Mutex<Vec<SimTraceEntry>>>,
    mutant: &SimMutant,
    quiet_logs: bool,
    name: &str,
) {
    {
        let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
        t.restarted_nodes.insert(name.to_string());
    }
    if net.any_blackholed() {
        record_sometimes("peer_restarted_during_blackhole");
        if net.partition_count() == 0 {
            record_sometimes("clean_restart_no_partition");
            if matches!(mutant, SimMutant::NoiseSensitiveRestartInBlackhole) {
                sim_rt::set_sim_inline_stall_ms(1_200);
            }
        }
    }
    let mut r = running.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pos) = r.iter().position(|n| n.spec.name == name) {
        let spec = r[pos].spec.clone();
        let pid = {
            let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
            let p = t.next_pid;
            t.next_pid += 1;
            p
        };
        r[pos] = spawn_daemon(net, &spec, pid, logs.clone(), quiet_logs);
    }
    net.record_proto_event(name, ProtoEvent::PeerRestarted);
}

async fn run_world_cap_status(
    net: &Arc<SimNetwork>,
    tracker: &Mutex<WorldTracker>,
    running: &Mutex<Vec<RunningNode>>,
    mutant: &SimMutant,
    name: &str,
    at_ms: u64,
) {
    if net.any_blackholed() {
        record_sometimes("cap_status_during_blackhole");
        if matches!(mutant, SimMutant::CanaryOnBlackholeStatus) {
            sim_rt::set_sim_inline_stall_ms(1_500);
        }
    }
    if matches!(mutant, SimMutant::TimerEdgeSilenceBoundary) {
        let status_near_edge = [15_000u64, 20_000, 30_000]
            .iter()
            .any(|t| at_ms.abs_diff(*t) <= 800);
        let bh_hit = tracker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bh_silence_boundary_hit;
        if bh_hit && status_near_edge {
            sim_rt::set_sim_inline_stall_ms(1_200);
        }
    }
    net.record_proto_event(name, ProtoEvent::CapStatusQueried);
    let slot = {
        let r = running.lock().unwrap_or_else(|e| e.into_inner());
        r.iter()
            .find(|n| n.spec.name == name)
            .map(|n| n.ctl_slot.clone())
    };
    if let Some(slot) = slot {
        if let Some(res) = send_cap_status(name, &slot).await {
            tracker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cap_status_results
                .push(res);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_semantic_action(
    action: SemanticAction,
    delay_ms: u64,
    net: Arc<SimNetwork>,
    tracker: Arc<Mutex<WorldTracker>>,
    running: Arc<Mutex<Vec<RunningNode>>>,
    logs: Arc<Mutex<Vec<SimTraceEntry>>>,
    mutant: SimMutant,
    quiet_logs: bool,
) {
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    let now_ms = clock::now_ms();
    match action {
        SemanticAction::ApplyFault(f) => {
            apply_world_fault(&net, &tracker, &mutant, f, now_ms);
        }
        SemanticAction::HealBlackhole { node } => {
            apply_world_fault(
                &net,
                &tracker,
                &mutant,
                Fault::BlackholeSignaling {
                    node,
                    active: false,
                },
                now_ms,
            );
        }
        SemanticAction::QueryCapStatus { node } => {
            run_world_cap_status(&net, &tracker, &running, &mutant, &node, now_ms).await;
        }
        SemanticAction::RestartPeer { node, down_ms } => {
            kill_world_node(&net, &running, &node).await;
            if down_ms > 0 {
                tokio::time::sleep(Duration::from_millis(down_ms)).await;
            }
            restart_world_node(&net, &tracker, &running, &logs, &mutant, quiet_logs, &node);
        }
    }
}

pub struct SimWorld;

impl SimWorld {
    pub fn run(config: SimConfig) -> SimOutcome {
        let mut seed_bytes = [0u8; 32];
        for (i, chunk) in seed_bytes.chunks_exact_mut(8).enumerate() {
            let mixed = config
                .seed
                .wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
            chunk.copy_from_slice(&mixed.to_le_bytes());
        }
        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder.enable_all().start_paused(true);
        #[allow(unexpected_cfgs)]
        #[cfg(tokio_unstable)]
        {
            let _ = &seed_bytes;
            builder.rng_seed(tokio::runtime::RngSeed::from_bytes(&seed_bytes));
        }
        let rt = builder.build().expect("sim current_thread runtime");

        rt.block_on(async move {
            clock::reset_sim_epoch();
            sim_rt::reset_sim_rng(config.seed);
            sim_rt::reset_sim_telemetry();
            reset_assertions();
            sim_rt::set_sim_blocking_inline(true);
            sim_rt::set_sim_watchdog_disabled(true);
            sim_rt::set_sim_inline_stall_ms(0);

            let net = SimNetwork::with_mutant(config.seed, config.mutant.clone());
            let logs = Arc::new(Mutex::new(Vec::<SimTraceEntry>::new()));
            let tracker = Arc::new(Mutex::new(WorldTracker {
                next_pid: 1000,
                ..Default::default()
            }));

            let initial_running: Vec<RunningNode> = config
                .nodes
                .iter()
                .map(|spec| {
                    let pid = {
                        let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
                        let p = t.next_pid;
                        t.next_pid += 1;
                        p
                    };
                    spawn_daemon(&net, spec, pid, logs.clone(), config.quiet_logs)
                })
                .collect();
            let running = Arc::new(Mutex::new(initial_running));
            let semantic_subtasks = Arc::new(Mutex::new(Vec::<tokio::task::JoinHandle<()>>::new()));

            let semantic_handle = if !config.semantic_faults.is_empty() {
                let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<(u64, String, ProtoEvent)>();
                net.attach_event_bus(ev_tx);
                let faults = config.semantic_faults.clone();
                let s_net = net.clone();
                let s_tracker = tracker.clone();
                let s_running = running.clone();
                let s_logs = logs.clone();
                let s_mutant = config.mutant.clone();
                let s_quiet = config.quiet_logs;
                let s_tasks = semantic_subtasks.clone();
                Some(tokio::spawn(async move {
                    let mut counts: BTreeMap<(Option<String>, ProtoEvent), u8> = BTreeMap::new();
                    let mut fired = vec![false; faults.len()];
                    while let Some((_at_ms, node, event)) = ev_rx.recv().await {
                        let c_node = counts
                            .entry((Some(node.clone()), event))
                            .and_modify(|v| *v = v.saturating_add(1))
                            .or_insert(1);
                        let node_count = *c_node;
                        let c_any = counts
                            .entry((None, event))
                            .and_modify(|v| *v = v.saturating_add(1))
                            .or_insert(1);
                        let any_count = *c_any;

                        for (idx, sf) in faults.iter().enumerate() {
                            if fired[idx] {
                                continue;
                            }
                            match &sf.trigger {
                                SemanticTrigger::OnEvent {
                                    node: tn,
                                    event: te,
                                    nth,
                                } => {
                                    if *te != event {
                                        continue;
                                    }
                                    let count = match tn {
                                        Some(want) if want == &node => node_count,
                                        Some(_) => continue,
                                        None => any_count,
                                    };
                                    if count == (*nth).max(1) {
                                        fired[idx] = true;
                                        let h = tokio::spawn(execute_semantic_action(
                                            sf.action.clone(),
                                            sf.delay_ms,
                                            s_net.clone(),
                                            s_tracker.clone(),
                                            s_running.clone(),
                                            s_logs.clone(),
                                            s_mutant.clone(),
                                            s_quiet,
                                        ));
                                        s_tasks.lock().unwrap_or_else(|e| e.into_inner()).push(h);
                                    }
                                }
                                SemanticTrigger::OnSilenceBoundary {
                                    node: bn,
                                    boundary_ms,
                                    jitter_ms,
                                } => {
                                    if event == ProtoEvent::SigBlackholeStarted && bn == &node {
                                        fired[idx] = true;
                                        let wait_ms = (*boundary_ms as i64 + *jitter_ms)
                                            .max(100) as u64
                                            + sf.delay_ms;
                                        let action = sf.action.clone();
                                        let check_node = bn.clone();
                                        let n2 = s_net.clone();
                                        let t2 = s_tracker.clone();
                                        let r2 = s_running.clone();
                                        let l2 = s_logs.clone();
                                        let m2 = s_mutant.clone();
                                        let h = tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
                                            if n2.is_blackholed(&check_node) {
                                                execute_semantic_action(
                                                    action, 0, n2, t2, r2, l2, m2, s_quiet,
                                                )
                                                .await;
                                            }
                                        });
                                        s_tasks.lock().unwrap_or_else(|e| e.into_inner()).push(h);
                                    }
                                }
                            }
                        }
                    }
                }))
            } else {
                None
            };

            // Build sorted timeline of scheduled events.
            enum Action {
                Fault(Fault),
                KillNode(String),
                RestartNode(String),
                QueryCapStatus(String),
                InjectInlineStall(u64),
            }
            let mut timeline: Vec<(u64, Action)> = config
                .schedule
                .iter()
                .map(|s| (s.at_ms, Action::Fault(s.fault.clone())))
                .collect();
            if let Some((ref name, kill_ms, restart_ms)) = config.restart_node {
                timeline.push((kill_ms, Action::KillNode(name.clone())));
                timeline.push((restart_ms, Action::RestartNode(name.clone())));
            }
            for (name, at_ms) in &config.cap_status_queries {
                timeline.push((*at_ms, Action::QueryCapStatus(name.clone())));
            }
            if let Some((at_ms, stall_ms)) = config.inline_stall_injection {
                timeline.push((at_ms, Action::InjectInlineStall(stall_ms)));
            }
            timeline.sort_by_key(|(at, _)| *at);

            let mut cursor_ms = 0u64;
            for (at_ms, action) in timeline {
                if at_ms > cursor_ms {
                    tokio::time::sleep(Duration::from_millis(at_ms - cursor_ms)).await;
                    cursor_ms = at_ms;
                }
                match action {
                    Action::Fault(f) => {
                        apply_world_fault(&net, &tracker, &config.mutant, f, at_ms);
                    }
                    Action::KillNode(name) => {
                        kill_world_node(&net, &running, &name).await;
                    }
                    Action::RestartNode(name) => {
                        restart_world_node(
                            &net,
                            &tracker,
                            &running,
                            &logs,
                            &config.mutant,
                            config.quiet_logs,
                            &name,
                        );
                    }
                    Action::QueryCapStatus(name) => {
                        run_world_cap_status(
                            &net,
                            &tracker,
                            &running,
                            &config.mutant,
                            &name,
                            at_ms,
                        )
                        .await;
                        cursor_ms = clock::now_ms();
                    }
                    Action::InjectInlineStall(stall_ms) => {
                        sim_rt::set_sim_inline_stall_ms(stall_ms);
                    }
                }
            }

            if config.duration_ms > cursor_ms {
                tokio::time::sleep(Duration::from_millis(config.duration_ms - cursor_ms)).await;
            }

            if let Some(h) = semantic_handle {
                h.abort();
            }
            {
                let handles = std::mem::take(
                    &mut *semantic_subtasks.lock().unwrap_or_else(|e| e.into_inner()),
                );
                for h in handles {
                    h.abort();
                }
            }

            {
                let t = tracker.lock().unwrap_or_else(|e| e.into_inner());
                for (_n, start_ms) in &t.blackhole_starts {
                    if config.duration_ms.saturating_sub(*start_ms) >= 18_000
                        && matches!(config.mutant, SimMutant::Pre729InlineHeartbeat)
                    {
                        sim_rt::set_sim_inline_stall_ms(2_000);
                    }
                }
            }

            let final_nodes = std::mem::take(&mut *running.lock().unwrap_or_else(|e| e.into_inner()));
            for mut node in final_nodes {
                if let Some(mut eng) = node.engine.take() {
                    if let Ok(DriverOutcome::Returned(Err(e))) =
                        eng.stop_within(Duration::from_secs(2)).await
                    {
                        logs.lock().unwrap_or_else(|e| e.into_inner()).push(
                            SimTraceEntry {
                                at_ms: clock::now_ms(),
                                node: node.spec.name,
                                message: format!("[driver-err] {e:#}"),
                            },
                        );
                    }
                }
            }

            sim_rt::set_sim_inline_stall_ms(0);
            sim_rt::set_sim_watchdog_disabled(false);
            sim_rt::set_sim_blocking_inline(false);
            let events = logs.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let net_events = net.trace_events();
            let state_edges = net.state_edges();
            let state_transitions = net.state_transitions();
            let final_tracker = std::mem::take(&mut *tracker.lock().unwrap_or_else(|e| e.into_inner()));
            if !final_tracker.bh_healed_nodes.is_empty()
                && net_events
                    .iter()
                    .any(|e| e.event.starts_with("sig:connect:") || e.event.starts_with("direct:pair:"))
            {
                record_sometimes("signaling_healed_after_blackhole");
            }
            if !final_tracker.restarted_nodes.is_empty()
                && net_events.iter().any(|e| e.event.starts_with("sig:connect:"))
            {
                record_sometimes("reconnect_after_peer_restart");
            }

            let budget_violations: Vec<String> = events
                .iter()
                .filter(|e| e.message.contains("LOOP-BUDGET-EXCEEDED"))
                .map(|e| format!("{}@{}ms: {}", e.node, e.at_ms, e.message))
                .collect();
            let trace_hash = fnv1a64(&events, &net_events);
            let telemetry = sim_rt::take_sim_telemetry();
            let assertions = take_assertions();

            SimOutcome {
                seed: config.seed,
                trace_hash,
                events,
                net_events,
                budget_violations,
                cap_status_results: final_tracker.cap_status_results,
                telemetry,
                assertions,
                state_edges,
                state_transitions,
            }
        })
    }
}
