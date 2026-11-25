use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use filament_signal::{alloc_conn_id, BoxFuture, Client, Incoming, SignalingBackend};
use filament_transport::clock;
use filament_transport::direct::{DirectBackend, SimDirectRaceReq, UnreadTransport};
use filament_transport::net::{
    AttemptId, Ev, EvSink, PathPair, PeerBackend, PeerFactory, SignalOutcome, SimPeerConnectReq,
    SourceId, Transport,
};
use filament_transport::{HttpBackend, SignalingConnector, TransportContext};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};

use crate::sim::assertions::record_sometimes;
use crate::sim::world::SimMutant;

/// Deterministic SplitMix64 PRNG so every simulation run with the same seed
/// makes identical loss, jitter, and timing choices.
#[derive(Debug, Clone)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn gen_range_u64(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }

    pub fn chance_pct(&mut self, pct: u8) -> bool {
        if pct == 0 {
            return false;
        }
        if pct >= 100 {
            return true;
        }
        self.gen_range_u64(100) < u64::from(pct)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    All,
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HangSite {
    SignalingConnect,
    SignalingEmit,
    HttpGetJson,
    GatherCandidates,
    PeerConnect,
    DirectRace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    Impair {
        node: String,
        delay_ms: u64,
        jitter_ms: u64,
        loss_pct: u8,
    },
    ClearImpair {
        node: String,
    },
    Partition {
        a: String,
        b: String,
        proto: Proto,
    },
    HealPartition {
        a: String,
        b: String,
    },
    BlackholeSignaling {
        node: String,
        active: bool,
    },
    Hang {
        node: String,
        site: HangSite,
        duration_ms: u64,
    },
}

#[derive(Debug, Clone, Default)]
struct ImpairConfig {
    delay_ms: u64,
    jitter_ms: u64,
    loss_pct: u8,
}

#[derive(Debug, Clone)]
struct SigClientState {
    conn_id: u64,
    node: String,
    sid: String,
    uid: Option<String>,
    display_name: Option<String>,
    channels: Vec<String>,
    tx: mpsc::UnboundedSender<Incoming>,
}

enum SimWireMsg {
    Control(Value),
    Frame {
        sid: u32,
        offset: u64,
        payload: Vec<u8>,
    },
    Close,
}

#[derive(Debug, Clone)]
enum RaceWaiterOutcome {
    Connected {
        tx: mpsc::UnboundedSender<SimWireMsg>,
        rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<SimWireMsg>>>>,
        peer_sid: String,
    },
}

struct DirectWaiter {
    node: String,
    my_uid: String,
    peer_uid: String,
    my_sid: String,
    secret: String,
    notify: Arc<Notify>,
    matched: Arc<Mutex<Option<RaceWaiterOutcome>>>,
}

#[derive(Debug, Clone)]
pub struct NetTraceEvent {
    pub at_ms: u64,
    pub event: String,
}

struct NetInner {
    rng: SimRng,
    mutant: SimMutant,
    drop_post_heal_reconnect: bool,
    had_partition_heal: bool,
    next_node_idx: u16,
    next_port_offset: u16,
    next_sid: u64,
    node_idx: HashMap<String, u16>,
    node_uid_map: HashMap<String, String>,
    uid_node_map: HashMap<String, String>,
    sig_clients: BTreeMap<u64, SigClientState>,
    sid_to_node: HashMap<String, String>,
    blackholed: HashSet<String>,
    impair: HashMap<String, ImpairConfig>,
    partitions: BTreeMap<(String, String), Proto>,
    hangs: HashMap<(String, HangSite), u64>,
    direct_waiters: Vec<DirectWaiter>,
    active_closers: HashMap<String, Vec<Arc<AtomicBool>>>,
    trace: Vec<NetTraceEvent>,
}

impl NetInner {
    fn ensure_node(&mut self, node: &str) -> u16 {
        if let Some(&idx) = self.node_idx.get(node) {
            return idx;
        }
        let idx = self.next_node_idx;
        self.next_node_idx = self.next_node_idx.saturating_add(1);
        self.node_idx.insert(node.to_string(), idx);
        idx
    }

    fn node_ip(&mut self, node: &str) -> String {
        let idx = self.ensure_node(node);
        format!("10.100.0.{idx}")
    }

    fn record(&mut self, event: impl Into<String>) {
        self.trace.push(NetTraceEvent {
            at_ms: clock::now_ms(),
            event: event.into(),
        });
    }

    fn pair_key(a: &str, b: &str) -> (String, String) {
        if a <= b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        }
    }

    fn is_partitioned(&self, a: &str, b: &str, udp: bool) -> bool {
        let key = Self::pair_key(a, b);
        match self.partitions.get(&key) {
            Some(Proto::All) => true,
            Some(Proto::Udp) => udp,
            Some(Proto::Tcp) => !udp,
            None => false,
        }
    }

    fn one_way_delay_ms(&mut self, from: &str, to: &str, reliable_retx: bool) -> u64 {
        let mut total = 2u64;
        for node in [from, to] {
            if let Some(cfg) = self.impair.get(node).cloned() {
                total = total.saturating_add(cfg.delay_ms);
                if cfg.jitter_ms > 0 {
                    let jitter = self.rng.gen_range_u64(cfg.jitter_ms.saturating_mul(2) + 1);
                    total = total.saturating_add(jitter / 2);
                }
                if reliable_retx && self.rng.chance_pct(cfg.loss_pct) {
                    // Simulated QUIC/SCTP retransmission RTT penalty on packet loss.
                    total = total.saturating_add(40 + cfg.delay_ms);
                }
            }
        }
        total
    }

    fn take_hang(&mut self, node: &str, site: HangSite) -> Option<u64> {
        self.hangs.remove(&(node.to_string(), site))
    }
}

/// Shared deterministic network and in-memory signaling fabric.
pub struct SimNetwork {
    inner: Mutex<NetInner>,
}

impl SimNetwork {
    pub fn new(seed: u64) -> Arc<Self> {
        Self::with_mutant(seed, SimMutant::None)
    }

    pub fn with_mutant(seed: u64, mutant: SimMutant) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(NetInner {
                rng: SimRng::new(seed),
                mutant,
                drop_post_heal_reconnect: false,
                had_partition_heal: false,
                next_node_idx: 1,
                next_port_offset: 10_000,
                next_sid: 0,
                node_idx: HashMap::new(),
                node_uid_map: HashMap::new(),
                uid_node_map: HashMap::new(),
                sig_clients: BTreeMap::new(),
                sid_to_node: HashMap::new(),
                blackholed: HashSet::new(),
                impair: HashMap::new(),
                partitions: BTreeMap::new(),
                hangs: HashMap::new(),
                direct_waiters: Vec::new(),
                active_closers: HashMap::new(),
                trace: Vec::new(),
            }),
        })
    }

    pub fn register_node_identity(&self, node: &str, uid: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.ensure_node(node);
        g.node_uid_map.insert(node.to_string(), uid.to_string());
        g.uid_node_map.insert(uid.to_string(), node.to_string());
    }

    pub fn node_context(self: &Arc<Self>, node: &str) -> TransportContext {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.ensure_node(node);
        }
        let ctx = TransportContext::new(
            None,
            |key, _peer| match key {
                "network.transports" => Some("direct,relay".to_string()),
                "lan" => Some("0".to_string()),
                "auto-warm" => Some("1".to_string()),
                _ => None,
            },
            |_| "off".to_string(),
        );
        let node_arc: Arc<str> = Arc::from(node);
        ctx.with_signaling_connector(Arc::new(SimSignalingConnector {
            net: self.clone(),
            node: node_arc.clone(),
        }))
        .with_http_backend(Arc::new(SimHttpBackend {
            net: self.clone(),
            node: node_arc.clone(),
        }))
        .with_peer_factory(Arc::new(SimPeerFactory {
            net: self.clone(),
            node: node_arc.clone(),
        }))
        .with_direct_backend(Arc::new(SimDirectBackend {
            net: self.clone(),
            node: node_arc,
        }))
    }

    pub fn apply_fault(&self, fault: Fault) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match fault {
            Fault::Impair {
                node,
                delay_ms,
                jitter_ms,
                loss_pct,
            } => {
                g.record(format!(
                    "fault:impair:{node}:delay={delay_ms}:jitter={jitter_ms}:loss={loss_pct}"
                ));
                g.impair.insert(
                    node,
                    ImpairConfig {
                        delay_ms,
                        jitter_ms,
                        loss_pct,
                    },
                );
            }
            Fault::ClearImpair { node } => {
                g.record(format!("fault:clear_impair:{node}"));
                g.impair.remove(&node);
            }
            Fault::Partition { a, b, proto } => {
                g.record(format!("fault:partition:{a}:{b}:{proto:?}"));
                g.partitions.insert(NetInner::pair_key(&a, &b), proto);
            }
            Fault::HealPartition { a, b } => {
                g.record(format!("fault:heal:{a}:{b}"));
                g.partitions.remove(&NetInner::pair_key(&a, &b));
                g.had_partition_heal = true;
                if matches!(g.mutant, SimMutant::PostHealDroppedReconnect) {
                    g.drop_post_heal_reconnect = true;
                    g.record(format!("link:dropped_by_partition:{a}:{b}"));
                    for n in [&a, &b] {
                        if let Some(closers) = g.active_closers.remove(n) {
                            for flag in closers {
                                flag.store(true, Ordering::Release);
                            }
                        }
                    }
                }
                for w in &g.direct_waiters {
                    w.notify.notify_waiters();
                }
            }
            Fault::BlackholeSignaling { node, active } => {
                g.record(format!("fault:blackhole:{node}:{active}"));
                if active {
                    g.blackholed.insert(node);
                } else {
                    g.blackholed.remove(&node);
                }
            }
            Fault::Hang {
                node,
                site,
                duration_ms,
            } => {
                g.record(format!("fault:hang:{node}:{site:?}:{duration_ms}"));
                g.hangs.insert((node, site), duration_ms);
            }
        }
    }

    /// Tear down all active signaling and transport handles for a killed node.
    pub fn disconnect_node(&self, node: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.record(format!("node:disconnect:{node}"));
        let dead_cids: Vec<u64> = g
            .sig_clients
            .iter()
            .filter(|(_, c)| c.node == node)
            .map(|(cid, _)| *cid)
            .collect();
        let mut dead_sids = Vec::new();
        for cid in dead_cids {
            if let Some(c) = g.sig_clients.remove(&cid) {
                g.sid_to_node.remove(&c.sid);
                dead_sids.push(c.sid);
            }
        }
        for sid in &dead_sids {
            for (_, other) in g.sig_clients.iter() {
                let _ = other.tx.send(Incoming::Event {
                    name: "peer-left".to_string(),
                    data: json!({ "id": sid }),
                });
            }
        }
        g.direct_waiters.retain(|w| w.node != node);
        if let Some(closers) = g.active_closers.remove(node) {
            for flag in closers {
                flag.store(true, Ordering::Release);
            }
        }
    }

    pub fn trace_events(&self) -> Vec<NetTraceEvent> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .trace
            .clone()
    }

    pub fn is_blackholed(&self, node: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .blackholed
            .contains(node)
    }

    pub fn any_blackholed(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .blackholed
            .is_empty()
    }

    pub fn partition_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .partitions
            .len()
    }

    pub fn has_impair(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .impair
            .is_empty()
    }

    pub fn is_partitioned(&self, a: &str, b: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.is_partitioned(a, b, true)
    }

    pub fn connected_sig_nodes(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.sig_clients.values().map(|c| c.node.clone()).collect()
    }
}

struct SimSignalingConnector {
    net: Arc<SimNetwork>,
    node: Arc<str>,
}

impl SignalingConnector for SimSignalingConnector {
    fn connect<'a>(
        &'a self,
        _server: &'a str,
        tx: mpsc::UnboundedSender<Incoming>,
    ) -> BoxFuture<'a, Result<Client>> {
        Box::pin(async move {
            let hang_ms = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.take_hang(&self.node, HangSite::SignalingConnect)
            };
            if let Some(ms) = hang_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            let (blackholed, delay_ms) = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                let bh = g.blackholed.contains(self.node.as_ref());
                let d = g.one_way_delay_ms(&self.node, "server", false);
                (bh, d)
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if blackholed {
                return Err(anyhow!("sim signaling blackholed for {}", self.node));
            }
            let conn_id = alloc_conn_id();
            let sid = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.next_sid += 1;
                let sid = format!("sim-sid-{}", g.next_sid);
                let suppress_heal = g.drop_post_heal_reconnect;
                g.sig_clients.insert(
                    conn_id,
                    SigClientState {
                        conn_id,
                        node: self.node.to_string(),
                        sid: sid.clone(),
                        uid: None,
                        display_name: None,
                        channels: Vec::new(),
                        tx: tx.clone(),
                    },
                );
                g.sid_to_node.insert(sid.clone(), self.node.to_string());
                if !suppress_heal {
                    g.record(format!("sig:connect:{}:{sid}", self.node));
                }
                sid
            };
            record_sometimes("sig_connected");
            let _ = tx.send(Incoming::Event {
                name: "welcome".to_string(),
                data: json!({ "id": sid, "peers": [] }),
            });
            let backend = Arc::new(SimSigBackend {
                net: self.net.clone(),
                node: self.node.clone(),
                conn_id,
            });
            Ok(Client::from_sim_backend(conn_id, backend))
        })
    }
}

struct SimSigBackend {
    net: Arc<SimNetwork>,
    node: Arc<str>,
    conn_id: u64,
}

impl SimSigBackend {
    fn handle_emit_inner(&self, event: &str, data: &Value) {
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(me) = g.sig_clients.get(&self.conn_id).cloned() else {
            return;
        };
        if let Some(uid) = data["uid"].as_str() {
            if let Some(c) = g.sig_clients.get_mut(&self.conn_id) {
                c.uid = Some(uid.to_string());
            }
        }
        if let Some(name) = data["name"].as_str() {
            if let Some(c) = g.sig_clients.get_mut(&self.conn_id) {
                c.display_name = Some(name.to_string());
            }
        }
        match event {
            "subscribe" => {
                let chans: Vec<String> = data["channels"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(c) = g.sig_clients.get_mut(&self.conn_id) {
                    for ch in &chans {
                        if !c.channels.contains(ch) {
                            c.channels.push(ch.clone());
                        }
                    }
                }
                let me = g.sig_clients.get(&self.conn_id).cloned().unwrap_or(me);
                let mut notifications: Vec<(mpsc::UnboundedSender<Incoming>, Value)> = Vec::new();
                for (_, other) in g.sig_clients.iter() {
                    if other.conn_id == self.conn_id {
                        continue;
                    }
                    if g.blackholed.contains(&other.node) {
                        continue;
                    }
                    if me.uid.is_some() && me.uid == other.uid {
                        continue;
                    }
                    for ch in &chans {
                        if other.channels.contains(ch) {
                            notifications.push((
                                me.tx.clone(),
                                json!({
                                    "id": other.sid,
                                    "name": other.display_name.clone().unwrap_or_else(|| other.node.clone()),
                                    "uid": other.uid.clone().unwrap_or_default(),
                                    "channel": ch,
                                }),
                            ));
                            notifications.push((
                                other.tx.clone(),
                                json!({
                                    "id": me.sid,
                                    "name": me.display_name.clone().unwrap_or_else(|| me.node.clone()),
                                    "uid": me.uid.clone().unwrap_or_default(),
                                    "channel": ch,
                                }),
                            ));
                        }
                    }
                }
                g.record(format!("sig:subscribe:{}:chans={}", self.node, chans.len()));
                for (tx, kp) in notifications {
                    let _ = tx.send(Incoming::Event {
                        name: "known-peer".to_string(),
                        data: kp,
                    });
                }
            }
            "sync" => {
                let me = g.sig_clients.get(&self.conn_id).cloned().unwrap_or(me);
                let _ = me.tx.send(Incoming::Event {
                    name: "synced".to_string(),
                    data: json!({ "peers": [] }),
                });
                let mut notifications: Vec<(mpsc::UnboundedSender<Incoming>, Value)> = Vec::new();
                for (_, other) in g.sig_clients.iter() {
                    if other.conn_id == self.conn_id || g.blackholed.contains(&other.node) {
                        continue;
                    }
                    if me.uid.is_some() && me.uid == other.uid {
                        continue;
                    }
                    for ch in &me.channels {
                        if other.channels.contains(ch) {
                            notifications.push((
                                me.tx.clone(),
                                json!({
                                    "id": other.sid,
                                    "name": other.display_name.clone().unwrap_or_else(|| other.node.clone()),
                                    "uid": other.uid.clone().unwrap_or_default(),
                                    "channel": ch,
                                }),
                            ));
                        }
                    }
                }
                for (tx, kp) in notifications {
                    let _ = tx.send(Incoming::Event {
                        name: "known-peer".to_string(),
                        data: kp,
                    });
                }
            }
            "signal" => {
                let to = data["to"].as_str().unwrap_or_default();
                let inner = data["data"].clone();
                if g.drop_post_heal_reconnect {
                    return;
                }
                let found = g
                    .sig_clients
                    .iter()
                    .find(|(_, c)| c.sid == to)
                    .map(|(_, c)| (c.node.clone(), c.tx.clone()));
                if let Some((target_node, target_tx)) = found {
                    if !g.blackholed.contains(&target_node) {
                        let sig_type = inner["type"].as_str().unwrap_or("unknown");
                        g.record(format!(
                            "sig:relay:{}->{}:{sig_type}",
                            self.node, target_node
                        ));
                        let _ = target_tx.send(Incoming::Event {
                            name: "signal".to_string(),
                            data: json!({
                                "from": me.sid,
                                "data": inner,
                            }),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

impl SignalingBackend for SimSigBackend {
    fn emit<'a>(&'a self, event: &'a str, data: Value) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (hang_ms, blackholed) = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                let hang = g.take_hang(&self.node, HangSite::SignalingEmit);
                let bh = g.blackholed.contains(self.node.as_ref());
                (hang, bh)
            };
            if let Some(ms) = hang_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            if blackholed {
                return Ok(());
            }
            self.handle_emit_inner(event, &data);
            Ok(())
        })
    }

    fn emit_with_ack<'a>(
        &'a self,
        event: &'a str,
        data: Value,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Option<Vec<Value>>>> {
        Box::pin(async move {
            let (hang_ms, blackholed) = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                let hang = g.take_hang(&self.node, HangSite::SignalingEmit);
                let bh = g.blackholed.contains(self.node.as_ref());
                (hang, bh)
            };
            if let Some(ms) = hang_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            if blackholed {
                if event == "sync" {
                    record_sometimes("heartbeat_fired_under_blackhole");
                }
                tokio::time::sleep(timeout).await;
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            self.handle_emit_inner(event, &data);
            Ok(Some(vec![json!({ "ok": true })]))
        })
    }

    fn disconnect<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(removed) = g.sig_clients.remove(&self.conn_id) {
                g.sid_to_node.remove(&removed.sid);
                g.record(format!("sig:disconnect:{}:{}", self.node, removed.sid));
                for (_, other) in g.sig_clients.iter() {
                    let _ = other.tx.send(Incoming::Event {
                        name: "peer-left".to_string(),
                        data: json!({ "id": removed.sid }),
                    });
                }
            }
            Ok(())
        })
    }
}

struct SimHttpBackend {
    net: Arc<SimNetwork>,
    node: Arc<str>,
}

impl HttpBackend for SimHttpBackend {
    fn get_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Value>> {
        Box::pin(async move {
            let (hang_ms, blackholed, ip) = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                let hang = g.take_hang(&self.node, HangSite::HttpGetJson);
                let bh = g.blackholed.contains(self.node.as_ref());
                let ip = g.node_ip(&self.node);
                (hang, bh, ip)
            };
            if let Some(ms) = hang_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            if blackholed {
                tokio::time::sleep(Duration::from_millis(200)).await;
                return Err(anyhow!("sim http blackholed for {}", self.node));
            }
            if url.contains("/api/whoami") {
                Ok(json!({ "ip": ip }))
            } else if url.contains("/api/config") {
                Ok(json!({ "iceServers": [] }))
            } else if url.contains("/api/room") {
                Ok(json!({ "ok": true }))
            } else {
                Ok(json!({}))
            }
        })
    }
}

struct SimDirectBackend {
    net: Arc<SimNetwork>,
    node: Arc<str>,
}

#[async_trait]
impl DirectBackend for SimDirectBackend {
    async fn gather_candidates(&self, _server: &str, port: u16) -> (Vec<String>, Option<String>) {
        let (hang_ms, ip, blackholed) = {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            let hang = g.take_hang(&self.node, HangSite::GatherCandidates);
            let ip = g.node_ip(&self.node);
            let bh = g.blackholed.contains(self.node.as_ref());
            (hang, ip, bh)
        };
        if blackholed {
            record_sometimes("gather_during_blackhole");
        }
        if let Some(ms) = hang_ms {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        (vec![format!("{ip}:{port}")], None)
    }

    fn bind_port(&self) -> Result<u16> {
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        let p = g.next_port_offset;
        g.next_port_offset = g.next_port_offset.saturating_add(1);
        Ok(p)
    }

    async fn race_connect(&self, req: SimDirectRaceReq) -> Option<UnreadTransport> {
        let hang_ms = {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.take_hang(&self.node, HangSite::DirectRace)
        };
        if let Some(ms) = hang_ms {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }

        let notify = Arc::new(Notify::new());
        let matched = Arc::new(Mutex::new(None));
        {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            // Check whether a matching peer waiter is already waiting and UDP is unpartitioned.
            let found_idx = g.direct_waiters.iter().position(|w| {
                w.secret == req.secret
                    && w.my_uid == req.peer_uid
                    && w.peer_uid == req.my_uid
                    && !g.is_partitioned(&w.node, &self.node, true)
            });
            if let Some(idx) = found_idx {
                let peer_waiter = g.direct_waiters.swap_remove(idx);
                if g.drop_post_heal_reconnect {
                    return None;
                }
                let (a_tx, a_rx) = mpsc::unbounded_channel();
                let (b_tx, b_rx) = mpsc::unbounded_channel();
                g.record(format!(
                    "direct:pair:{}:{}<->{}",
                    req.route, self.node, peer_waiter.node
                ));
                record_sometimes("direct_paired");
                if g.had_partition_heal {
                    record_sometimes("direct_after_partition_heal");
                }
                *peer_waiter
                    .matched
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(RaceWaiterOutcome::Connected {
                    tx: b_tx,
                    rx: Arc::new(Mutex::new(Some(a_rx))),
                    peer_sid: req.my_id.clone(),
                });
                peer_waiter.notify.notify_waiters();
                *matched.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(RaceWaiterOutcome::Connected {
                        tx: a_tx,
                        rx: Arc::new(Mutex::new(Some(b_rx))),
                        peer_sid: peer_waiter.my_sid,
                    });
            } else {
                g.direct_waiters.push(DirectWaiter {
                    node: self.node.to_string(),
                    my_uid: req.my_uid.clone(),
                    peer_uid: req.peer_uid.clone(),
                    my_sid: req.my_id.clone(),
                    secret: req.secret.clone(),
                    notify: notify.clone(),
                    matched: matched.clone(),
                });
            }
        }

        let deadline = tokio::time::Instant::now() + Duration::from_millis(1_800);
        loop {
            if let Some(RaceWaiterOutcome::Connected { tx, rx, peer_sid }) =
                matched.lock().unwrap_or_else(|e| e.into_inner()).take()
            {
                let rx_chan = rx.lock().unwrap_or_else(|e| e.into_inner()).take()?;
                let peer_node = {
                    let g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.uid_node_map
                        .get(&req.peer_uid)
                        .cloned()
                        .unwrap_or_else(|| "peer".to_string())
                };
                let source = SourceId::next();
                let answerer = req.my_uid < req.peer_uid;
                let dead = Arc::new(AtomicBool::new(false));
                let last_heard_ms = Arc::new(AtomicU64::new(clock::now_ms()));
                let last_idle_ms = Arc::new(AtomicU64::new(clock::now_ms()));
                {
                    let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.active_closers
                        .entry(self.node.to_string())
                        .or_default()
                        .push(dead.clone());
                }
                let transport = Arc::new(SimTransport {
                    source,
                    attempt: Some(req.attempt),
                    answerer,
                    dead: dead.clone(),
                    last_heard_ms: last_heard_ms.clone(),
                    last_idle_ms,
                    out_tx: tx,
                });
                let ev_tx = req.tx.clone();
                let pid = if peer_sid.is_empty() {
                    req.peer_id.clone()
                } else {
                    peer_sid
                };
                let net = self.net.clone();
                let my_node = self.node.clone();
                let reader = async move {
                    sim_transport_reader(
                        net,
                        my_node,
                        peer_node,
                        pid,
                        source,
                        dead,
                        last_heard_ms,
                        rx_chan,
                        ev_tx,
                    )
                    .await;
                };
                return Some(UnreadTransport::from_sim_with_reader(transport, reader));
            }
            if tokio::time::Instant::now() >= deadline {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.direct_waiters
                    .retain(|w| !(w.node == self.node.as_ref() && w.peer_uid == req.peer_uid));
                return None;
            }
            tokio::select! {
                _ = notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    fn local_ip_snapshot(&self) -> Vec<String> {
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        vec![g.node_ip(&self.node)]
    }
}

#[allow(clippy::too_many_arguments)]
async fn sim_transport_reader(
    net: Arc<SimNetwork>,
    my_node: Arc<str>,
    peer_node: String,
    pid: String,
    source: SourceId,
    dead: Arc<AtomicBool>,
    last_heard_ms: Arc<AtomicU64>,
    mut rx: mpsc::UnboundedReceiver<SimWireMsg>,
    ev_tx: mpsc::UnboundedSender<Ev>,
) {
    while let Some(msg) = rx.recv().await {
        if dead.load(Ordering::Acquire) {
            break;
        }
        let delay = {
            let mut g = net.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.is_partitioned(&my_node, &peer_node, true) {
                None
            } else {
                Some(g.one_way_delay_ms(&peer_node, &my_node, true))
            }
        };
        let Some(ms) = delay else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        tokio::time::sleep(Duration::from_millis(ms)).await;
        if dead.load(Ordering::Acquire) {
            break;
        }
        last_heard_ms.store(clock::now_ms(), Ordering::Release);
        match msg {
            SimWireMsg::Control(val) => {
                let _ = ev_tx.send(Ev::Sourced {
                    pid: pid.clone(),
                    source,
                    inner: Box::new(Ev::Control(pid.clone(), val)),
                });
            }
            SimWireMsg::Frame {
                sid,
                offset,
                payload,
            } => {
                let _ = ev_tx.send(Ev::Sourced {
                    pid: pid.clone(),
                    source,
                    inner: Box::new(Ev::Chunk(
                        pid.clone(),
                        sid,
                        Some(offset),
                        Bytes::from(payload),
                    )),
                });
            }
            SimWireMsg::Close => {
                dead.store(true, Ordering::Release);
                break;
            }
        }
    }
    dead.store(true, Ordering::Release);
    let _ = ev_tx.send(Ev::Sourced {
        pid: pid.clone(),
        source,
        inner: Box::new(Ev::PcState(pid, "disconnected".to_string())),
    });
}

struct SimTransport {
    source: SourceId,
    attempt: Option<AttemptId>,
    answerer: bool,
    dead: Arc<AtomicBool>,
    last_heard_ms: Arc<AtomicU64>,
    last_idle_ms: Arc<AtomicU64>,
    out_tx: mpsc::UnboundedSender<SimWireMsg>,
}

#[async_trait]
impl Transport for SimTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        if self.dead.load(Ordering::Acquire) {
            anyhow::bail!("sim transport closed");
        }
        self.last_idle_ms.store(clock::now_ms(), Ordering::Release);
        self.out_tx
            .send(SimWireMsg::Control(msg.clone()))
            .map_err(|_| anyhow!("sim peer receiver closed"))
    }

    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Acquire) {
            anyhow::bail!("sim transport closed");
        }
        self.last_idle_ms.store(clock::now_ms(), Ordering::Release);
        self.out_tx
            .send(SimWireMsg::Frame {
                sid,
                offset,
                payload: payload.to_vec(),
            })
            .map_err(|_| anyhow!("sim peer receiver closed"))
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn max_payload(&self) -> usize {
        16 * 1024
    }

    fn sid_answerer(&self) -> bool {
        self.answerer
    }

    fn idle_ms(&self) -> u64 {
        clock::now_ms().saturating_sub(self.last_idle_ms.load(Ordering::Acquire))
    }

    fn heard_ms(&self) -> Option<u64> {
        Some(clock::now_ms().saturating_sub(self.last_heard_ms.load(Ordering::Acquire)))
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::Acquire)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn source_id(&self) -> Option<SourceId> {
        Some(self.source)
    }

    fn attempt_id(&self) -> Option<AttemptId> {
        self.attempt
    }

    fn force_close(&self) {
        self.dead.store(true, Ordering::Release);
        let _ = self.out_tx.send(SimWireMsg::Close);
    }
}

struct SimPeerFactory {
    net: Arc<SimNetwork>,
    node: Arc<str>,
}

#[async_trait]
impl PeerFactory for SimPeerFactory {
    async fn connect(&self, req: SimPeerConnectReq) -> Result<Arc<dyn PeerBackend>> {
        record_sometimes("webrtc_fallback_attempted");
        let hang_ms = {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.record(format!("webrtc:connect:{}:{}", self.node, req.peer_id));
            g.take_hang(&self.node, HangSite::PeerConnect)
        };
        if let Some(ms) = hang_ms {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
        let closed = Arc::new(AtomicBool::new(false));
        {
            let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.active_closers
                .entry(self.node.to_string())
                .or_default()
                .push(closed.clone());
        }
        Ok(Arc::new(SimPeerBackend {
            net: self.net.clone(),
            node: self.node.clone(),
            peer_id: req.peer_id,
            source: req.source,
            _tx: req.tx,
            closed,
        }))
    }
}

struct SimPeerBackend {
    net: Arc<SimNetwork>,
    node: Arc<str>,
    peer_id: String,
    source: SourceId,
    _tx: EvSink,
    closed: Arc<AtomicBool>,
}

#[async_trait]
impl PeerBackend for SimPeerBackend {
    fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    async fn remote_pc(&self) -> Option<u64> {
        Some(self.source.get())
    }

    async fn establishing_progress(&self) -> bool {
        false
    }

    async fn restart_ice(&self) {
        let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.record(format!("webrtc:restart_ice:{}:{}", self.node, self.peer_id));
    }

    fn negotiation_backlog(&self) -> usize {
        0
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    async fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    async fn handle_signal(&self, _data: Value) -> Result<SignalOutcome> {
        Ok(SignalOutcome::Handled)
    }

    async fn fingerprints(&self) -> Option<(String, String)> {
        None
    }

    async fn route(&self) -> Option<String> {
        Some("relay".to_string())
    }

    async fn local_relay_transport(&self) -> Option<&'static str> {
        Some("udp")
    }

    async fn route_shown(&self, route: &str) -> String {
        route.to_string()
    }

    async fn path_detail(&self) -> Option<PathPair> {
        None
    }
}
