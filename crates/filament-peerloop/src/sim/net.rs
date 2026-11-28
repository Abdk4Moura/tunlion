use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};

use crate::sim::assertions::{record_always, record_antecedent, record_sometimes};
use crate::sim::semantic::{
    NodeStateTracker, ProtoEvent, SignalMsgKind, StateEdge, StateTransition,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    All,
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HangSite {
    SignalingConnect,
    SignalingEmit,
    HttpGetJson,
    GatherCandidates,
    PeerConnect,
    DirectRace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MessageChaosPolicy {
    pub drop_pct: u8,
    pub duplicate_pct: u8,
    pub reorder_max_delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    SetMessageChaos {
        policy: MessageChaosPolicy,
    },
    ClearMessageChaos,
    /// Every durable write on `node`'s disk takes `write_ms` from now on
    /// (fsync under writeback pressure, a saturated or failing disk).
    SlowDisk {
        node: String,
        write_ms: u64,
    },
    ClearSlowDisk {
        node: String,
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
        cb: Option<Vec<u8>>,
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
    node_idx: BTreeMap<String, u16>,
    node_uid_map: BTreeMap<String, String>,
    uid_node_map: BTreeMap<String, String>,
    sig_clients: BTreeMap<u64, SigClientState>,
    sid_to_node: BTreeMap<String, String>,
    blackholed: BTreeSet<String>,
    impair: BTreeMap<String, ImpairConfig>,
    partitions: BTreeMap<(String, String), Proto>,
    hangs: BTreeMap<(String, HangSite), u64>,
    direct_waiters: Vec<DirectWaiter>,
    active_closers: BTreeMap<String, Vec<Arc<AtomicBool>>>,
    msg_chaos: MessageChaosPolicy,
    sig_msg_chaos_triggered: bool,
    tracker: NodeStateTracker,
    event_tx: Option<mpsc::UnboundedSender<(u64, String, ProtoEvent)>>,
    trace: Vec<NetTraceEvent>,
    /// The wider world model (`SimConfig::reach`): server-assigned random
    /// session ids, HTTP requests that take a round trip, and a TLS-exporter
    /// channel binding on direct links, as production has.
    reach: bool,
    disks: BTreeMap<String, Arc<crate::sim::store::SimDisk>>,
}

struct PendingSigDelivery {
    tx: mpsc::UnboundedSender<Incoming>,
    name: String,
    data: Value,
    delay_ms: u64,
    kind_tag: Option<&'static str>,
}

fn dispatch_sig_deliveries(planned: Vec<PendingSigDelivery>) {
    for p in planned {
        if let Some(tag) = p.kind_tag {
            record_sometimes(tag);
        }
        if p.delay_ms == 0 {
            let _ = p.tx.send(Incoming::Event {
                name: p.name,
                data: p.data,
            });
        } else {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(p.delay_ms)).await;
                let _ = p.tx.send(Incoming::Event {
                    name: p.name,
                    data: p.data,
                });
            });
        }
    }
}

impl NetInner {
    fn plan_sig_deliveries(
        &mut self,
        items: Vec<(mpsc::UnboundedSender<Incoming>, &str, Value)>,
    ) -> Vec<PendingSigDelivery> {
        let mut out = Vec::with_capacity(items.len());
        let policy = self.msg_chaos;
        let active = policy.drop_pct > 0
            || policy.duplicate_pct > 0
            || policy.reorder_max_delay_ms > 0;
        for (tx, name, data) in items {
            if !active || name == "welcome" {
                out.push(PendingSigDelivery {
                    tx,
                    name: name.to_string(),
                    data,
                    delay_ms: 0,
                    kind_tag: None,
                });
                continue;
            }
            if self.rng.chance_pct(policy.drop_pct) {
                self.sig_msg_chaos_triggered = true;
                record_sometimes("sig_msg_dropped");
                continue;
            }
            let delay_ms = if policy.reorder_max_delay_ms > 0 {
                self.rng.gen_range_u64(policy.reorder_max_delay_ms + 1)
            } else {
                0
            };
            let kind_tag = if delay_ms > 0 {
                self.sig_msg_chaos_triggered = true;
                Some("sig_msg_reordered")
            } else {
                None
            };
            if self.rng.chance_pct(policy.duplicate_pct) {
                self.sig_msg_chaos_triggered = true;
                let dup_delay = delay_ms.saturating_add(5 + self.rng.gen_range_u64(145));
                out.push(PendingSigDelivery {
                    tx: tx.clone(),
                    name: name.to_string(),
                    data: data.clone(),
                    delay_ms: dup_delay,
                    kind_tag: Some("sig_msg_duplicated"),
                });
            }
            out.push(PendingSigDelivery {
                tx,
                name: name.to_string(),
                data,
                delay_ms,
                kind_tag,
            });
        }
        out
    }

    fn emit_proto_event(&mut self, node: &str, event: ProtoEvent) {
        let at_ms = clock::now_ms();
        self.tracker.record(at_ms, node, event);
        if let Some(tx) = &self.event_tx {
            let _ = tx.send((at_ms, node.to_string(), event));
        }
    }
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
        Self::with_options(seed, mutant, false)
    }

    pub fn with_options(seed: u64, mutant: SimMutant, reach: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(NetInner {
                rng: SimRng::new(seed),
                mutant,
                drop_post_heal_reconnect: false,
                had_partition_heal: false,
                next_node_idx: 1,
                next_port_offset: 10_000,
                next_sid: 0,
                node_idx: BTreeMap::new(),
                node_uid_map: BTreeMap::new(),
                uid_node_map: BTreeMap::new(),
                sig_clients: BTreeMap::new(),
                sid_to_node: BTreeMap::new(),
                blackholed: BTreeSet::new(),
                impair: BTreeMap::new(),
                partitions: BTreeMap::new(),
                hangs: BTreeMap::new(),
                direct_waiters: Vec::new(),
                active_closers: BTreeMap::new(),
                msg_chaos: MessageChaosPolicy::default(),
                sig_msg_chaos_triggered: false,
                tracker: NodeStateTracker::default(),
                event_tx: None,
                trace: Vec::new(),
                reach,
                disks: BTreeMap::new(),
            }),
        })
    }

    /// `node`'s disk (created on first use; it outlives a restart).
    pub fn disk(&self, node: &str) -> Arc<crate::sim::store::SimDisk> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.disks.entry(node.to_string()).or_default().clone()
    }

    /// Append a world-level event to the network trace (part of the hash).
    pub fn record_trace(&self, event: impl Into<String>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record(event);
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
                g.emit_proto_event(&a, ProtoEvent::LinkDroppedByPartition);
                g.emit_proto_event(&b, ProtoEvent::LinkDroppedByPartition);
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
                    g.emit_proto_event(&node, ProtoEvent::SigBlackholeStarted);
                    g.blackholed.insert(node);
                } else {
                    g.emit_proto_event(&node, ProtoEvent::SigBlackholeHealed);
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
            Fault::SetMessageChaos { policy } => {
                g.record(format!(
                    "fault:msg_chaos:drop={}:dup={}:delay={}",
                    policy.drop_pct, policy.duplicate_pct, policy.reorder_max_delay_ms
                ));
                g.msg_chaos = policy;
            }
            Fault::ClearMessageChaos => {
                g.record("fault:clear_msg_chaos");
                g.msg_chaos = MessageChaosPolicy::default();
            }
            Fault::SlowDisk { node, write_ms } => {
                g.record(format!("fault:slow_disk:{node}:{write_ms}"));
                g.disks.entry(node).or_default().set_write_ms(write_ms);
            }
            Fault::ClearSlowDisk { node } => {
                g.record(format!("fault:clear_slow_disk:{node}"));
                g.disks.entry(node).or_default().set_write_ms(0);
            }
        }
    }

    /// Tear down all active signaling and transport handles for a killed node.
    pub fn disconnect_node(&self, node: &str) {
        let planned = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.record(format!("node:disconnect:{node}"));
            g.emit_proto_event(node, ProtoEvent::SigDisconnected);
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
            let mut raw = Vec::new();
            for sid in &dead_sids {
                for (_, other) in g.sig_clients.iter() {
                    raw.push((other.tx.clone(), "peer-left", json!({ "id": sid })));
                }
            }
            g.direct_waiters.retain(|w| w.node != node);
            if let Some(closers) = g.active_closers.remove(node) {
                for flag in closers {
                    flag.store(true, Ordering::Release);
                }
            }
            g.plan_sig_deliveries(raw)
        };
        dispatch_sig_deliveries(planned);
    }

    pub fn trace_events(&self) -> Vec<NetTraceEvent> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .trace
            .clone()
    }

    pub fn attach_event_bus(&self, tx: mpsc::UnboundedSender<(u64, String, ProtoEvent)>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .event_tx = Some(tx);
    }

    pub fn record_proto_event(&self, node: &str, event: ProtoEvent) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .emit_proto_event(node, event);
    }

    pub fn state_edges(&self) -> BTreeSet<StateEdge> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tracker
            .edges()
            .clone()
    }

    pub fn state_transitions(&self) -> Vec<StateTransition> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tracker
            .transitions()
            .to_vec()
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
                let sid = if g.reach {
                    // A socket.io id: 20 random characters. Which end of a pair
                    // sorts higher is then random, as it is in production.
                    const ALPHA: &[u8] =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
                    (0..20)
                        .map(|_| ALPHA[g.rng.gen_range_u64(ALPHA.len() as u64) as usize] as char)
                        .collect()
                } else {
                    format!("sim-sid-{}", g.next_sid)
                };
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
                g.emit_proto_event(&self.node, ProtoEvent::SigConnected);
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
                g.emit_proto_event(&self.node, ProtoEvent::SigSubscribed);
                let items = notifications
                    .into_iter()
                    .map(|(tx, kp)| (tx, "known-peer", kp))
                    .collect();
                let planned = g.plan_sig_deliveries(items);
                drop(g);
                dispatch_sig_deliveries(planned);
            }
            "sync" => {
                let me = g.sig_clients.get(&self.conn_id).cloned().unwrap_or(me);
                let mut items = vec![(me.tx.clone(), "synced", json!({ "peers": [] }))];
                for (_, other) in g.sig_clients.iter() {
                    if other.conn_id == self.conn_id || g.blackholed.contains(&other.node) {
                        continue;
                    }
                    if me.uid.is_some() && me.uid == other.uid {
                        continue;
                    }
                    for ch in &me.channels {
                        if other.channels.contains(ch) {
                            items.push((
                                me.tx.clone(),
                                "known-peer",
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
                let planned = g.plan_sig_deliveries(items);
                drop(g);
                dispatch_sig_deliveries(planned);
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
                        g.emit_proto_event(
                            &self.node,
                            ProtoEvent::SignalRelayed(SignalMsgKind::from_type(sig_type)),
                        );
                        let planned = g.plan_sig_deliveries(vec![(
                            target_tx,
                            "signal",
                            json!({
                                "from": me.sid,
                                "data": inner,
                            }),
                        )]);
                        drop(g);
                        dispatch_sig_deliveries(planned);
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
                    self.net
                        .record_proto_event(&self.node, ProtoEvent::SigHeartbeatUnderBlackhole);
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
            let planned = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(removed) = g.sig_clients.remove(&self.conn_id) {
                    g.sid_to_node.remove(&removed.sid);
                    g.record(format!("sig:disconnect:{}:{}", self.node, removed.sid));
                    g.emit_proto_event(&self.node, ProtoEvent::SigDisconnected);
                    let mut items = Vec::new();
                    for (_, other) in g.sig_clients.iter() {
                        items.push((other.tx.clone(), "peer-left", json!({ "id": removed.sid })));
                    }
                    g.plan_sig_deliveries(items)
                } else {
                    Vec::new()
                }
            };
            dispatch_sig_deliveries(planned);
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
            let (hang_ms, blackholed, ip, rtt_ms) = {
                let mut g = self.net.inner.lock().unwrap_or_else(|e| e.into_inner());
                let hang = g.take_hang(&self.node, HangSite::HttpGetJson);
                let bh = g.blackholed.contains(self.node.as_ref());
                let ip = g.node_ip(&self.node);
                // An HTTP request is a round trip to the server.
                let rtt = if g.reach {
                    g.one_way_delay_ms(&self.node, "server", false)
                        + g.one_way_delay_ms("server", &self.node, false)
                } else {
                    0
                };
                (hang, bh, ip, rtt)
            };
            if let Some(ms) = hang_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            if rtt_ms > 0 && !blackholed {
                tokio::time::sleep(Duration::from_millis(rtt_ms)).await;
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
                // The TLS exporter both ends of one QUIC connection derive.
                let cb: Option<Vec<u8>> = g.reach.then(|| {
                    (0..4).flat_map(|_| g.rng.next_u64().to_le_bytes()).collect()
                });
                g.record(format!(
                    "direct:pair:{}:{}<->{}",
                    req.route, self.node, peer_waiter.node
                ));
                let peer_node_ev = peer_waiter.node.clone();
                let glare_corrupt = matches!(g.mutant, SimMutant::ReorderGlareViolation)
                    && g.sig_msg_chaos_triggered;
                let peer_answerer = peer_waiter.my_uid < peer_waiter.peer_uid;
                let local_answerer = if glare_corrupt {
                    peer_answerer
                } else {
                    req.my_uid < req.peer_uid
                };
                record_antecedent("est_i1_glare_free");
                record_always(
                    "est_i1_glare_free",
                    local_answerer != peer_answerer,
                    || {
                        format!(
                            "glare role collision between {} and {}: local_answerer={} peer_answerer={}",
                            self.node, peer_node_ev, local_answerer, peer_answerer
                        )
                    },
                );
                record_antecedent("est_i2_pair_symmetry");
                g.emit_proto_event(&self.node, ProtoEvent::DirectPaired);
                g.emit_proto_event(&peer_node_ev, ProtoEvent::DirectPaired);
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
                    cb: cb.clone(),
                });
                peer_waiter.notify.notify_waiters();
                *matched.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(RaceWaiterOutcome::Connected {
                        tx: a_tx,
                        rx: Arc::new(Mutex::new(Some(b_rx))),
                        peer_sid: peer_waiter.my_sid,
                        cb,
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
            if let Some(RaceWaiterOutcome::Connected { tx, rx, peer_sid, cb }) =
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
                    cb,
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
    cb: Option<Vec<u8>>,
}

#[async_trait]
impl Transport for SimTransport {
    fn channel_binding(&self) -> Option<Vec<u8>> {
        self.cb.clone()
    }

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
            g.emit_proto_event(&self.node, ProtoEvent::WebRtcFallback);
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

    fn restart_ice(&self) {
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
