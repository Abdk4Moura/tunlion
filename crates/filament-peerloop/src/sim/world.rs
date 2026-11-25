use std::collections::{HashMap, HashSet};
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
use crate::sim::net::{Fault, SimNetwork};
use crate::sim_rt;

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
    pub budget_violations: Vec<String>,
    pub cap_status_results: Vec<CapStatusResult>,
    pub telemetry: sim_rt::SimTelemetry,
}

#[derive(Clone)]
pub struct SimConfig {
    pub seed: u64,
    pub duration_ms: u64,
    pub nodes: Vec<NodeSpec>,
    pub schedule: Vec<ScheduledFault>,
    pub restart_node: Option<(String, u64, u64)>,
    pub cap_status_queries: Vec<(String, u64)>,
    pub inline_stall_injection: Option<(u64, u64)>,
}

struct CapturingLog {
    node: String,
    sink: Arc<Mutex<Vec<SimTraceEntry>>>,
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
) -> RunningNode {
    net.register_node_identity(&spec.name, &spec.uid);
    let ctl_slot = Arc::new(Mutex::new(None));
    let tctx = net.node_context(&spec.name);
    let log: Arc<dyn LogSink> = Arc::new(CapturingLog {
        node: spec.name.clone(),
        sink: logs,
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
    tokio::task::yield_now().await;
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
            sim_rt::reset_sim_telemetry();
            sim_rt::set_sim_blocking_inline(true);
            sim_rt::set_sim_watchdog_disabled(true);
            sim_rt::set_sim_inline_stall_ms(0);

            let net = SimNetwork::new(config.seed);
            let logs = Arc::new(Mutex::new(Vec::<SimTraceEntry>::new()));
            let mut next_pid: u32 = 1000;

            let mut running: Vec<RunningNode> = config
                .nodes
                .iter()
                .map(|spec| {
                    let pid = next_pid;
                    next_pid += 1;
                    spawn_daemon(&net, spec, pid, logs.clone())
                })
                .collect();

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

            let mut cap_status_results = Vec::new();
            let mut cursor_ms = 0u64;
            for (at_ms, action) in timeline {
                if at_ms > cursor_ms {
                    tokio::time::sleep(Duration::from_millis(at_ms - cursor_ms)).await;
                    cursor_ms = at_ms;
                }
                match action {
                    Action::Fault(f) => net.apply_fault(f),
                    Action::KillNode(name) => {
                        net.disconnect_node(&name);
                        if let Some(node) = running.iter_mut().find(|n| n.spec.name == name) {
                            if let Some(mut eng) = node.engine.take() {
                                let _ = eng.stop_within(Duration::from_secs(2)).await;
                            }
                            *node.ctl_slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        }
                    }
                    Action::RestartNode(name) => {
                        if let Some(pos) = running.iter().position(|n| n.spec.name == name) {
                            let spec = running[pos].spec.clone();
                            let pid = next_pid;
                            next_pid += 1;
                            running[pos] = spawn_daemon(&net, &spec, pid, logs.clone());
                        }
                    }
                    Action::QueryCapStatus(name) => {
                        if let Some(node) = running.iter().find(|n| n.spec.name == name) {
                            let slot = node.ctl_slot.clone();
                            if let Some(res) = send_cap_status(&name, &slot).await {
                                cap_status_results.push(res);
                            }
                        }
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

            for mut node in running {
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
            let budget_violations: Vec<String> = events
                .iter()
                .filter(|e| e.message.contains("LOOP-BUDGET-EXCEEDED"))
                .map(|e| format!("{}@{}ms: {}", e.node, e.at_ms, e.message))
                .collect();
            let trace_hash = fnv1a64(&events, &net_events);
            let telemetry = sim_rt::take_sim_telemetry();

            SimOutcome {
                seed: config.seed,
                trace_hash,
                events,
                budget_violations,
                cap_status_results,
                telemetry,
            }
        })
    }
}
