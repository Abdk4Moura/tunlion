//! The fleet identity handshake, as ONE state machine both sides drive.
//!
//! `fleet.rs` owns the cryptography: build a hello, verify a hello, derive the
//! channel. This module owns the CONVERSATION built out of those primitives:
//! who has been challenged, who has proved themselves, who proved to be somebody
//! else, who has run out of time.
//!
//! # Why this exists
//!
//! That conversation used to be typed out twice, inline: once in the daemon's
//! receive loop and once in the one-shot sender. The two copies drifted, and
//! every drift was the same shape. The fleet channel carries EVERY sibling, so
//! anything describing "the peer" has to be keyed by peer, and the inline copies
//! kept storing it as one value:
//!
//!   `fleet_proven`        one bool   "some peer proved" read as "THIS peer proved",
//!                                    so one sibling verifying opened the offer
//!                                    guard for all of them (a MISDELIVERY)
//!   `fleet_bind_ours`     one nonce  the last peer to connect overwrote the
//!                                    binding the previous one signed against
//!   `fleet_rechallenged`  one bool   one sibling spent the single retry that a
//!                                    different sibling needed
//!   the wrong-peer skip   no memory  a peer proved to be someone else was
//!                                    dropped and then re-adopted as the target,
//!                                    in a loop, starving the real device
//!
//! Four bugs, one cause: per-peer state that was not stored per peer. A pair
//! channel has exactly one peer on it, so this code was correct before auto-mesh
//! and wrong after it, in both copies independently.
//!
//! Here the state is a `HashMap` keyed by peer id and there is no other place to
//! put it, so that class of bug cannot be written down. That is the point of the
//! module: not shorter code, but a shape where the mistake is unavailable.
//!
//! # What it deliberately does NOT do
//!
//! No I/O. `advance()` and `on_control()` return an `Action` describing what to
//! send; the caller owns the transport and does the sending. That keeps this
//! testable without a network and lets the daemon and the one-shot, which have
//! very different event loops, share the same logic.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::{json, Value};

/// What the caller should do next for a peer. The caller owns the transport.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Nothing to do.
    Idle,
    /// Send this control message to the peer.
    Send(Value),
}

/// The result of feeding a control message in.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Not ours, or nothing changed.
    Ignored,
    /// Send this and keep waiting.
    Send(Value),
    /// The peer proved it is `name` (resolved from the certificate key, never
    /// from the name the peer asserted).
    Proved { name: Option<String>, device_pub: [u8; 32] },
    /// The peer proved itself, and it is NOT who we asked for. Not an attack:
    /// every sibling shares this channel. Drop it and keep looking.
    WrongPeer { proved: Option<String> },
    /// The certificate did not verify and the retry budget is spent.
    Refused(String),
}

#[derive(Debug, Clone)]
struct PeerState {
    /// OUR challenge nonce for this link, for transports with no RFC-5705
    /// exporter. Per peer: a nonce is only meaningful against the link it was
    /// minted for.
    bind_ours: Option<Vec<u8>>,
    /// Proven identity, once the certificate verifies.
    proved: Option<Option<String>>,
    /// Proved to be a DIFFERENT device. Final: identity does not change
    /// mid-session, so such a peer can never become the target.
    wrong: bool,
    /// One re-challenge PER PEER. A hello that arrived before our nonce is a
    /// race and deserves a retry; a hello that fails again is a bad certificate.
    rechallenged: bool,
    /// When this peer stops holding the target slot if it has not proved itself.
    deadline: Option<Instant>,
}

impl Default for PeerState {
    fn default() -> Self {
        Self { bind_ours: None, proved: None, wrong: false, rechallenged: false, deadline: None }
    }
}

/// Per-process fleet handshake state, keyed by peer id.
#[derive(Debug, Default)]
pub struct FleetSession {
    peers: HashMap<String, PeerState>,
}

impl FleetSession {
    pub fn new() -> Self {
        Self::default()
    }

    fn st(&mut self, pid: &str) -> &mut PeerState {
        self.peers.entry(pid.to_string()).or_default()
    }

    /// Has this peer proved its certificate on THIS link?
    pub fn proved(&self, pid: &str) -> bool {
        self.peers.get(pid).map(|p| p.proved.is_some()).unwrap_or(false)
    }

    /// Did this peer prove itself to be some OTHER device?
    pub fn is_wrong(&self, pid: &str) -> bool {
        self.peers.get(pid).map(|p| p.wrong).unwrap_or(false)
    }

    /// The name this peer proved, if any.
    pub fn proved_name(&self, pid: &str) -> Option<String> {
        self.peers.get(pid).and_then(|p| p.proved.clone()).flatten()
    }

    /// Our challenge nonce for this link, minting one if needed. The mint is
    /// lazy because we cannot mint for a peer we have not met, and eager for
    /// everything after that, because a hello we cannot bind is a hello we
    /// cannot verify.
    pub fn nonce(&mut self, pid: &str, mint: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
        let st = self.st(pid);
        st.bind_ours.get_or_insert_with(mint).clone()
    }

    /// The binding to verify an incoming hello against: the transport's exporter
    /// when it has one, otherwise the nonce WE sent this peer.
    pub fn in_binding(&self, pid: &str, exporter: Option<Vec<u8>>) -> Option<Vec<u8>> {
        exporter.or_else(|| self.peers.get(pid).and_then(|p| p.bind_ours.clone()))
    }

    /// Arm the proof deadline for a peer holding the target slot.
    ///
    /// Unproven is a TIMEOUT, not a wait. Not every peer on this channel will
    /// ever answer a fleet challenge: the OWNER is the standing case, since it is
    /// PAIRED with us and its daemon classifies our link as a paired one, so it
    /// never sends `fleet-hello` at all. Waiting on such a peer waits forever and
    /// the device we actually asked for never gets a turn.
    pub fn arm_deadline(&mut self, pid: &str, budget: Duration) {
        let st = self.st(pid);
        if st.deadline.is_none() {
            st.deadline = Some(Instant::now() + budget);
        }
    }

    /// Peers whose proof deadline has passed without proving themselves. They
    /// are marked wrong, so the caller can drop them and stop re-targeting them.
    pub fn lapsed(&mut self, now: Instant) -> Vec<String> {
        let out: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.proved.is_none() && !p.wrong && p.deadline.map(|d| now > d).unwrap_or(false)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for pid in &out {
            let st = self.st(pid);
            st.wrong = true;
            st.deadline = None;
        }
        out
    }

    /// Forget a peer entirely. Called when the link drops: a new link must
    /// re-prove on a NEW binding, so carrying any of this forward would be
    /// exactly the stale-trust bug the channel binding exists to prevent.
    pub fn forget(&mut self, pid: &str) {
        self.peers.remove(pid);
    }

    /// Present ourselves on a link that just came up.
    ///
    /// With an exporter we can sign immediately. Without one we open the
    /// challenge and our hello waits for their nonce.
    /// `make_hello` builds OUR hello for a given channel binding. It is injected
    /// because that needs the host's key and certificate, which this module has
    /// no business touching. Same shape as `filament-id` taking a `&dyn KeyStore`.
    pub fn greet(
        &mut self,
        pid: &str,
        exporter: Option<Vec<u8>>,
        mint: impl FnOnce() -> Vec<u8>,
        make_hello: impl FnOnce(&[u8]) -> Result<Value>,
    ) -> Action {
        if self.proved(pid) {
            return Action::Idle;
        }
        match exporter {
            Some(cb) => match make_hello(&cb) {
                Ok(hello) => Action::Send(hello),
                Err(_) => Action::Idle,
            },
            None => Action::Send(nonce_msg(&self.nonce(pid, mint))),
        }
    }

    /// Feed a control message in.
    ///
    /// `want` is the device name the caller asked for, if it is targeting one;
    /// `None` means "admit any sibling" (the daemon's mesh case).
    #[allow(clippy::too_many_arguments)]
    pub fn on_control(
        &mut self,
        pid: &str,
        v: &Value,
        exporter: Option<Vec<u8>>,
        owner_pub: Option<[u8; 32]>,
        want: Option<&str>,
        now_secs: u64,
        mint: impl Fn() -> Vec<u8>,
        make_hello: impl Fn(&[u8]) -> Result<Value>,
        name_for_pub: impl Fn(&[u8; 32]) -> Option<String>,
    ) -> Outcome {
        if self.proved(pid) {
            return Outcome::Ignored;
        }
        match v["type"].as_str() {
            // Their challenge: sign what they sent, they verify against it.
            Some("l3-nonce") => {
                let Some(Ok(nonce)) = v["nonce"].as_str().map(filament_overlay::unb64) else {
                    return Outcome::Ignored;
                };
                if nonce.len() < 16 {
                    return Outcome::Ignored;
                }
                match make_hello(&nonce) {
                    Ok(hello) => Outcome::Send(hello),
                    Err(_) => Outcome::Ignored,
                }
            }
            Some(t) if t == crate::HELLO => {
                let Some(owner) = owner_pub else {
                    return Outcome::Refused("no owner key".into());
                };
                let Some(cb) = self.in_binding(pid, exporter) else {
                    // No binding for THIS link yet: their hello beat our
                    // challenge, so there is nothing for it to have been signed
                    // against. That is a race, not a bad certificate. Challenge
                    // and let them re-present, once.
                    if !self.st(pid).rechallenged {
                        self.st(pid).rechallenged = true;
                        let n = self.nonce(pid, &mint);
                        return Outcome::Send(nonce_msg(&n));
                    }
                    return Outcome::Refused("no channel binding".into());
                };
                match crate::verify_hello(v, &cb, &owner, now_secs) {
                    Ok(ok) => {
                        // The name is resolved from the PROVEN certificate key,
                        // never from the name the peer asserted. A peer that
                        // could name itself could name itself after a device that
                        // holds grants.
                        let proven = name_for_pub(&ok.device_pub);
                        if let Some(want) = want {
                            if proven.as_deref().map(|n| n.eq_ignore_ascii_case(want)) != Some(true)
                            {
                                self.st(pid).wrong = true;
                                return Outcome::WrongPeer { proved: proven };
                            }
                        }
                        self.st(pid).proved = Some(proven.clone());
                        self.st(pid).deadline = None;
                        Outcome::Proved { name: proven, device_pub: ok.device_pub }
                    }
                    Err(e) => {
                        if !self.st(pid).rechallenged {
                            self.st(pid).rechallenged = true;
                            let n = self.nonce(pid, &mint);
                            return Outcome::Send(nonce_msg(&n));
                        }
                        Outcome::Refused(e.to_string())
                    }
                }
            }
            _ => Outcome::Ignored,
        }
    }
}

fn nonce_msg(nonce: &[u8]) -> Value {
    json!({ "type": "l3-nonce", "nonce": filament_overlay::b64(nonce) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n1() -> Vec<u8> {
        vec![1u8; 32]
    }
    fn n2() -> Vec<u8> {
        vec![2u8; 32]
    }

    // The bug that caused a MISDELIVERY: one peer proving opened the guard for
    // every peer. Proof is per link or it is worthless.
    #[test]
    fn proof_is_per_peer() {
        let mut s = FleetSession::new();
        s.st("a").proved = Some(Some("laptop".into()));
        assert!(s.proved("a"));
        assert!(!s.proved("b"));
    }

    // One nonce for the whole session let the last peer to connect overwrite the
    // binding the previous one signed against.
    #[test]
    fn nonces_do_not_collide_across_peers() {
        let mut s = FleetSession::new();
        let a = s.nonce("a", n1);
        let b = s.nonce("b", n2);
        assert_ne!(a, b);
        assert_eq!(s.nonce("a", n2), a, "a nonce must be stable for its peer");
        assert_eq!(s.in_binding("a", None), Some(a));
        assert_eq!(s.in_binding("b", None), Some(b));
    }

    // An exporter, when present, outranks the nonce.
    #[test]
    fn exporter_outranks_nonce() {
        let mut s = FleetSession::new();
        s.nonce("a", n1);
        assert_eq!(s.in_binding("a", Some(vec![9u8; 32])), Some(vec![9u8; 32]));
    }

    // One sibling must not spend the retry another needs.
    #[test]
    fn rechallenge_budget_is_per_peer() {
        let mut s = FleetSession::new();
        s.st("a").rechallenged = true;
        assert!(s.st("a").rechallenged);
        assert!(!s.st("b").rechallenged);
    }

    // A peer that never answers must not hold the slot forever. The owner is the
    // real case: paired with us, so it never speaks fleet at all.
    #[test]
    fn unproven_peer_lapses_and_is_marked_wrong() {
        let mut s = FleetSession::new();
        s.arm_deadline("a", Duration::from_millis(0));
        std::thread::sleep(Duration::from_millis(5));
        let lapsed = s.lapsed(Instant::now());
        assert_eq!(lapsed, vec!["a".to_string()]);
        assert!(s.is_wrong("a"), "a lapsed peer must not be re-targeted");
        assert!(s.lapsed(Instant::now()).is_empty(), "lapsing must not repeat");
    }

    // A proven peer is never reaped by the deadline sweep.
    #[test]
    fn proved_peer_never_lapses() {
        let mut s = FleetSession::new();
        s.arm_deadline("a", Duration::from_millis(0));
        s.st("a").proved = Some(Some("phone".into()));
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.lapsed(Instant::now()).is_empty());
    }

    // A dropped link must carry NOTHING forward: the next link has a new binding
    // and must re-prove against it.
    #[test]
    fn forget_clears_everything_for_a_peer() {
        let mut s = FleetSession::new();
        s.nonce("a", n1);
        s.st("a").proved = Some(Some("laptop".into()));
        s.st("a").wrong = true;
        s.forget("a");
        assert!(!s.proved("a"));
        assert!(!s.is_wrong("a"));
        assert_eq!(s.in_binding("a", None), None);
    }

    // Their challenge is answered by signing THEIR nonce, not ours.
    #[test]
    fn their_nonce_is_answered_with_a_hello() {
        let mut s = FleetSession::new();
        let msg = json!({ "type": "l3-nonce", "nonce": filament_overlay::b64(&[7u8; 32]) });
        let out = s.on_control(
            "a", &msg, None, Some([0u8; 32]), None, 0, n1, |_| Ok(json!({})), |_| None,
        );
        assert!(matches!(out, Outcome::Send(_) | Outcome::Ignored));
    }

    // A too-short nonce is not a challenge.
    #[test]
    fn short_nonce_is_rejected() {
        let mut s = FleetSession::new();
        let msg = json!({ "type": "l3-nonce", "nonce": filament_overlay::b64(&[7u8; 4]) });
        let out =
            s.on_control("a", &msg, None, Some([0u8; 32]), None, 0, n1, |_| Ok(json!({})), |_| None);
        assert_eq!(out, Outcome::Ignored);
    }

    // A hello with no binding and no retry left is refused, not admitted.
    #[test]
    fn hello_without_binding_challenges_once_then_refuses() {
        let mut s = FleetSession::new();
        let hello = json!({ "type": crate::HELLO });
        let first =
            s.on_control("a", &hello, None, Some([0u8; 32]), None, 0, n1, |_| Ok(json!({})), |_| None);
        assert!(matches!(first, Outcome::Send(_)), "first is a challenge");
        let second =
            s.on_control("a", &hello, None, Some([0u8; 32]), None, 0, n1, |_| Ok(json!({})), |_| None);
        assert!(matches!(second, Outcome::Refused(_)), "second must refuse, not loop");
    }

    // Without an owner key nothing can be verified, so nothing is admitted.
    #[test]
    fn no_owner_key_refuses() {
        let mut s = FleetSession::new();
        let hello = json!({ "type": crate::HELLO });
        let out = s.on_control("a", &hello, None, None, None, 0, n1, |_| Ok(json!({})), |_| None);
        assert!(matches!(out, Outcome::Refused(_)));
    }
}
