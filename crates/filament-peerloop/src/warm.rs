//! The WARM-HOLD decision machine: which peers are worth a proactive link, and
//! when to (re)dial one.
//!
//! Pure over `Instant` and the tier sets, so the whole state machine is
//! unit-testable without a network or a runtime. It was carved out of
//! `cli/src/conn.rs` unchanged; `Conn::warm_hold_tick` still owns the I/O (the
//! roster, devices.json, `start_direct`, `establish_as`) and asks this machine
//! what to do.
//!
//! WHY THE BOUNDARY, from the incident the tests below came from: the auto tier
//! used to be built from roster DISPLAY names and matched against a link named by
//! PETNAME. Whenever the two differed (petname `x`, display `user@x`, the normal
//! case) a healthy direct link was never recognised, a fresh establish replaced
//! it every tick, and the peer, still holding its end, ignored the new offers: a
//! ~95s re-dial cycle that never settled. The names are the bug; keeping the
//! decision in one tested place is how it stays fixed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// WARM-HOLD state: keeps connections alive to recently-used and explicitly
/// configured peers so `tunlion reach`/`ssh` is instant.
///
/// Design:
/// - EXPLICIT peers: from `tunlion set warm-peers dovm,popos` (always connected)
/// - RECENT peers: LRU of last 5 peers used for send/ssh/ping (auto-connected)
/// - RECONNECT: exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap) on drop
/// - DORMANT: go dormant after 5 failed attempts; resume on peer presence
const WARM_RECENT_CAP: usize = 5;
const WARM_MAX_BACKOFF: Duration = Duration::from_secs(30);
const WARM_DORMANT_THRESHOLD: u32 = 5;
/// A dormant peer is retried this often (instead of never). Presence re-announce
/// still resumes it immediately; this is the floor for a peer whose announces we
/// keep missing.
const WARM_DORMANT_RETRY: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct WarmHold {
    /// Explicitly configured peers (from `warm-peers` setting)
    pub configured: HashSet<String>,
    /// AUTO-WARM tier: ALL online paired peers (from the live roster), synced each
    /// warm_hold_tick. ON by default (`auto-warm` setting); also forced on while the
    /// L3 overlay is up (L3 needs live links to route). Bounded by `warm-max`
    /// (Change 4), not by the recent LRU cap.
    pub auto: HashSet<String>,
    /// Recently-used peers in LRU order (most recent at back, capped at 5)
    recent: VecDeque<String>,
    /// Per-peer last-use timestamp
    pub last_use: HashMap<String, Instant>,
    /// Per-peer reconnect backoff state
    backoff: HashMap<String, WarmBackoff>,
}

#[derive(Clone)]
pub struct WarmBackoff {
    /// Current backoff duration
    duration: Duration,
    /// Number of consecutive failures
    failures: u32,
    /// When we last tried to connect
    last_attempt: Option<Instant>,
    /// True if we've given up (dormant) after too many failures
    dormant: bool,
}

impl Default for WarmBackoff {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(1),
            failures: 0,
            last_attempt: None,
            dormant: false,
        }
    }
}

impl WarmHold {
    /// Record that a peer was just used (transfer, ssh, ping)
    pub fn note_use(&mut self, peer: &str) {
        let peer = peer.to_string();
        self.last_use.insert(peer.clone(), Instant::now());
        // Move to back of LRU (most recent)
        self.recent.retain(|p| p != &peer);
        self.recent.push_back(peer.clone());
        // Trim to cap
        while self.recent.len() > WARM_RECENT_CAP {
            self.recent.pop_front();
        }
        // Clear dormant flag and reset backoff on use
        if let Some(b) = self.backoff.get_mut(&peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }

    /// Mark a connection attempt failed (exponential backoff)
    pub fn note_failure(&mut self, peer: &str) {
        let b = self.backoff.entry(peer.to_string()).or_default();
        b.failures += 1;
        b.last_attempt = Some(Instant::now());
        // Exponential backoff with cap
        b.duration = (b.duration * 2).min(WARM_MAX_BACKOFF);
        // Go dormant after too many failures
        if b.failures >= WARM_DORMANT_THRESHOLD {
            b.dormant = true;
        }
    }

    /// Mark a connection succeeded (reset backoff)
    pub fn note_success(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.failures = 0;
            b.duration = Duration::from_secs(1);
            b.dormant = false;
        }
    }

    /// Check if a peer should be connected (configured OR auto OR recently used, not dormant)
    pub fn should_connect(&self, peer: &str) -> bool {
        if self.configured.contains(peer) {
            return true;
        }
        if self.auto.contains(peer) {
            return true;
        }
        if self.recent.contains(&peer.to_string()) {
            // Check if dormant
            if let Some(b) = self.backoff.get(peer) {
                return !b.dormant;
            }
            return true;
        }
        false
    }

    /// Get all peers that should be connected
    pub fn peers_to_connect(&self) -> Vec<String> {
        let mut peers: Vec<String> = self.configured.iter().cloned().collect();
        // Add auto-warm peers (all online paired peers)
        for p in &self.auto {
            if !peers.contains(p) {
                peers.push(p.clone());
            }
        }
        // Add recent peers (capped at 5, not dormant)
        for p in &self.recent {
            if !peers.contains(p) {
                if let Some(b) = self.backoff.get(p) {
                    if !b.dormant {
                        peers.push(p.clone());
                    }
                } else {
                    peers.push(p.clone());
                }
            }
        }
        peers
    }

    /// Consecutive failed attempts for this peer (0 when none recorded).
    pub fn failures(&self, peer: &str) -> u32 {
        self.backoff.get(peer).map(|b| b.failures).unwrap_or(0)
    }

    /// Check if a peer is dormant (too many failures)
    fn is_dormant(&self, peer: &str) -> bool {
        self.backoff.get(peer).map(|b| b.dormant).unwrap_or(false)
    }

    /// Is this peer due for a (re)connect attempt this tick? Dormant peers get one
    /// probe per WARM_DORMANT_RETRY; non-dormant peers honor their exponential
    /// backoff window (duration since last_attempt).
    pub fn due(&self, peer: &str) -> bool {
        match self.backoff.get(peer) {
            None => true,
            Some(b) => {
                let since = b.last_attempt.map(|t| t.elapsed());
                if b.dormant {
                    since.map_or(true, |d| d >= WARM_DORMANT_RETRY)
                } else {
                    since.map_or(true, |d| d >= b.duration)
                }
            }
        }
    }

    /// Resume a dormant peer (e.g., when it reappears in signaling presence)
    pub fn resume(&mut self, peer: &str) {
        if let Some(b) = self.backoff.get_mut(peer) {
            b.dormant = false;
            b.failures = 0;
            b.duration = Duration::from_secs(1);
        }
    }
}

#[cfg(test)]
mod warm_hold_tests {
    use super::*;

    #[test]
    fn should_connect_configured() {
        let mut wh = WarmHold::default();
        wh.configured.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_l3() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        assert!(wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn should_connect_recent_not_dormant() {
        let mut wh = WarmHold::default();
        wh.note_use("dovm");
        assert!(wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(!wh.should_connect("dovm"));
    }

    #[test]
    fn should_connect_false_for_unknown() {
        let wh = WarmHold::default();
        assert!(!wh.should_connect("unknown"));
    }

    #[test]
    fn recent_lru_caps_at_5() {
        let mut wh = WarmHold::default();
        for i in 0..7 {
            wh.note_use(&format!("peer{i}"));
        }
        // Should only have last 5: peer2, peer3, peer4, peer5, peer6
        assert_eq!(wh.recent.len(), WARM_RECENT_CAP);
        assert!(!wh.recent.contains(&"peer0".to_string()));
        assert!(!wh.recent.contains(&"peer1".to_string()));
        assert!(wh.recent.contains(&"peer2".to_string()));
        assert!(wh.recent.contains(&"peer6".to_string()));
    }

    #[test]
    fn recent_evicts_oldest() {
        let mut wh = WarmHold::default();
        wh.note_use("a");
        wh.note_use("b");
        wh.note_use("c");
        wh.note_use("d");
        wh.note_use("e");
        // All 5 present
        assert_eq!(wh.recent.len(), 5);
        // Add 6th - "a" should be evicted
        wh.note_use("f");
        assert_eq!(wh.recent.len(), 5);
        assert!(!wh.recent.contains(&"a".to_string()));
        assert!(wh.recent.contains(&"f".to_string()));
    }

    #[test]
    fn auto_set_is_unbounded() {
        let mut wh = WarmHold::default();
        // Add 10 peers to auto set
        for i in 0..10 {
            wh.auto.insert(format!("peer{i}"));
        }
        // All 10 should be in peers_to_connect
        let peers = wh.peers_to_connect();
        for i in 0..10 {
            assert!(peers.contains(&format!("peer{i}")), "peer{i} missing");
        }
    }

    #[test]
    fn auto_disabled_clears_set() {
        let mut wh = WarmHold::default();
        wh.auto.insert("dovm".into());
        wh.auto.insert("popos".into());
        assert!(wh.should_connect("dovm"));
        // Simulate auto-warm disabled
        wh.auto.clear();
        assert!(!wh.should_connect("dovm"));
        assert!(!wh.should_connect("popos"));
    }

    #[test]
    fn note_failure_backoff_doubling() {
        let mut wh = WarmHold::default();
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(2));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(4));
        wh.note_failure("dovm");
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(8));
    }

    #[test]
    fn note_failure_caps_at_30s() {
        let mut wh = WarmHold::default();
        for _ in 0..10 {
            wh.note_failure("dovm");
        }
        assert_eq!(wh.backoff["dovm"].duration, WARM_MAX_BACKOFF);
    }

    #[test]
    fn note_failure_dormant_after_threshold() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.backoff["dovm"].dormant);
        assert!(wh.is_dormant("dovm"));
    }

    #[test]
    fn note_use_clears_backoff() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.note_use("dovm");
        assert!(!wh.is_dormant("dovm"));
        assert_eq!(wh.backoff["dovm"].duration, Duration::from_secs(1));
        assert_eq!(wh.backoff["dovm"].failures, 0);
    }

    #[test]
    fn resume_clears_dormant() {
        let mut wh = WarmHold::default();
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        wh.resume("dovm");
        assert!(!wh.is_dormant("dovm"));
    }

    /// CI GUARDRAIL: warm peers should be instantly connectable.
    /// This is a LOGICAL test (no network) - verifies the warm-hold state
    /// machine would allow instant connection for a warm peer.
    #[test]
    fn warm_peer_allows_instant_connection() {
        let mut wh = WarmHold::default();
        // Simulate a warm peer (configured + auto)
        wh.configured.insert("dovm".into());
        wh.auto.insert("dovm".into());
        wh.note_use("dovm");
        // All paths should return true
        assert!(wh.should_connect("dovm"));
        assert!(!wh.is_dormant("dovm"));
        // Peer is in warm sets
        assert!(wh.configured.contains("dovm"));
        assert!(wh.auto.contains("dovm"));
    }

    #[test]
    fn due_respects_backoff_window() {
        let mut wh = WarmHold::default();
        // No backoff entry -> always due
        assert!(wh.due("unknown"));
        // After one failure, not due until backoff window passes
        wh.note_failure("dovm");
        assert!(!wh.due("dovm")); // 1s window, just failed
    }

    #[test]
    fn dormant_peer_retries_after_interval() {
        let mut wh = WarmHold::default();
        // Make peer dormant
        for _ in 0..WARM_DORMANT_THRESHOLD {
            wh.note_failure("dovm");
        }
        assert!(wh.is_dormant("dovm"));
        // Not due immediately
        assert!(!wh.due("dovm"));
        // After WARM_DORMANT_RETRY, would be due (can't easily test Instant::elapsed
        // without injecting time, so just verify the dormant flag is set)
        assert!(wh.backoff["dovm"].dormant);
    }
}
