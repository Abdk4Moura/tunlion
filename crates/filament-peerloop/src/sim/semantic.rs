use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sim::net::Fault;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalMsgKind {
    TransportOffer,
    DirectCandidates,
    Offer,
    Answer,
    Ice,
    Other,
}

impl SignalMsgKind {
    pub fn from_type(s: &str) -> Self {
        match s {
            "transport-offer" => Self::TransportOffer,
            "direct-candidates" => Self::DirectCandidates,
            "offer" => Self::Offer,
            "answer" => Self::Answer,
            "ice" => Self::Ice,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProtoEvent {
    SigConnected,
    SigSubscribed,
    SigHeartbeatUnderBlackhole,
    SigBlackholeStarted,
    SigBlackholeHealed,
    SigDisconnected,
    SignalRelayed(SignalMsgKind),
    DirectPaired,
    WebRtcFallback,
    LinkDroppedByPartition,
    PeerRestarted,
    CapStatusQueried,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub enum NodeProtoState {
    #[default]
    Booting,
    SigUp,
    DirectLinked,
    Partitioned,
    Blackholed,
    ProbingSilence,
    Restarting,
    Healed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StateEdge {
    pub from: NodeProtoState,
    pub event: ProtoEvent,
    pub to: NodeProtoState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    pub at_ms: u64,
    pub node: String,
    pub edge: StateEdge,
}

#[derive(Debug, Clone, Default)]
pub struct NodeStateTracker {
    states: BTreeMap<String, NodeProtoState>,
    edges: BTreeSet<StateEdge>,
    transitions: Vec<StateTransition>,
}

impl NodeStateTracker {
    pub fn next_state(prev: NodeProtoState, event: ProtoEvent) -> NodeProtoState {
        match event {
            ProtoEvent::SigConnected => NodeProtoState::SigUp,
            ProtoEvent::SigSubscribed => {
                if prev == NodeProtoState::Booting {
                    NodeProtoState::SigUp
                } else {
                    prev
                }
            }
            ProtoEvent::DirectPaired => NodeProtoState::DirectLinked,
            ProtoEvent::WebRtcFallback => match prev {
                NodeProtoState::Booting | NodeProtoState::SigUp | NodeProtoState::Partitioned => {
                    NodeProtoState::DirectLinked
                }
                _ => prev,
            },
            ProtoEvent::LinkDroppedByPartition => NodeProtoState::Partitioned,
            ProtoEvent::SigBlackholeStarted => NodeProtoState::Blackholed,
            ProtoEvent::SigHeartbeatUnderBlackhole => NodeProtoState::ProbingSilence,
            ProtoEvent::SigBlackholeHealed => NodeProtoState::Healed,
            ProtoEvent::SigDisconnected => NodeProtoState::Restarting,
            ProtoEvent::PeerRestarted => NodeProtoState::Booting,
            ProtoEvent::SignalRelayed(_) | ProtoEvent::CapStatusQueried => prev,
        }
    }

    pub fn record(&mut self, at_ms: u64, node: &str, event: ProtoEvent) -> StateEdge {
        let prev = self.states.get(node).copied().unwrap_or_default();
        let next = Self::next_state(prev, event);
        self.states.insert(node.to_string(), next);
        let edge = StateEdge {
            from: prev,
            event,
            to: next,
        };
        self.edges.insert(edge);
        self.transitions.push(StateTransition {
            at_ms,
            node: node.to_string(),
            edge,
        });
        edge
    }

    pub fn edges(&self) -> &BTreeSet<StateEdge> {
        &self.edges
    }

    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticTrigger {
    OnEvent {
        node: Option<String>,
        event: ProtoEvent,
        nth: u8,
    },
    OnSilenceBoundary {
        node: String,
        boundary_ms: u64,
        jitter_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticAction {
    ApplyFault(Fault),
    HealBlackhole { node: String },
    QueryCapStatus { node: String },
    RestartPeer { node: String, down_ms: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticFault {
    pub trigger: SemanticTrigger,
    pub delay_ms: u64,
    pub action: SemanticAction,
}
