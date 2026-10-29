//! Reliable delivery of a code pairing's `identity-expose` (the frame that
//! carries a device's certificate to the other side).
//!
//! The frame went out once, unacknowledged, and the other side waited 5 s for
//! it. When that one frame was lost or late, the pairing completed on both
//! sides without the certificate: the device was paired but not certified, and
//! both sides said "connected". This is the lost-message class #597 fixed for
//! the SPAKE2 element and the confirmation, fixed the same way:
//!
//! - the sender re-sends the SAME frame at 250 ms, 500 ms, 1 s, then every 2 s
//!   ([`Resend`]) until the receiver acknowledges it, or the ceremony's own
//!   deadline ends;
//! - the receiver acknowledges every copy it accepted (a duplicate is
//!   harmless: same bytes, same certificate, same acknowledgement), and an
//!   acknowledgement is never answered;
//! - a side whose peer said it will send a certificate (`exposes: true` in its
//!   PAKE payloads) does not succeed until that certificate arrived and
//!   verified, and a side that sent one does not succeed until it was
//!   acknowledged. Otherwise the pairing fails and says which.
//!
//! All of it applies only to a peer that advertised `expose_ack: 1`. A 0.9.1
//! CLI and the browser do not, and get exactly the old behaviour: one send,
//! nothing waited for.
//!
//! Pure over its inputs (time is passed in), so the loss cases are tested
//! without a network.

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::retry::Resend;

/// The acknowledgement's `type`. Sent only to a peer that advertised
/// `expose_ack: 1`: a 0.9.1 CLI would route an unknown signal type into its
/// WebRTC path.
pub const ACK_TYPE: &str = "identity-expose-ack";

/// After a pairing succeeded, how long without a fresh copy of the peer's
/// frame this side keeps answering copies before it leaves. The sender's
/// widest re-send gap is 2 s, so a lost acknowledgement is answered again by
/// the next copy instead of leaving the sender to fail at its deadline. Ends
/// early when the peer leaves the room.
pub const LINGER_QUIET: Duration = Duration::from_millis(2200);

/// What checking one copy of the peer's frame found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It opened and verified: the certificate is the peer's.
    Accepted,
    /// It could not be checked yet (no key, or this link's fingerprints are
    /// not known): a later copy is checked. Not acknowledged.
    NotYet,
    /// It was checked and refused. Every copy is the same bytes, so a later
    /// copy would be refused the same way.
    Refused(String),
}

/// What is still missing when the ceremony ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unmet {
    /// We sent our certificate and the peer never said it arrived.
    NotAcknowledged,
    /// The peer said it would send its certificate and none arrived.
    CertMissing,
    /// The peer's certificate arrived and did not verify.
    CertRefused(String),
}

/// One pairing's identity-expose exchange, both directions.
#[derive(Debug, Default)]
pub struct ExposeExchange {
    /// Our frame, built once; every copy is these bytes.
    frame: Option<Value>,
    sent: bool,
    resend: Resend,
    acked: bool,
    /// The peer's certificate arrived and verified.
    peer_cert: bool,
    refused: Option<String>,
    /// We acknowledged at least one copy of the peer's frame.
    answered: bool,
    last_copy: Option<Instant>,
}

impl ExposeExchange {
    pub fn new() -> Self {
        Self::default()
    }

    /// Our frame. Only the first call counts: a re-send is never a new frame.
    pub fn offer(&mut self, frame: Value) {
        if self.frame.is_none() {
            self.frame = Some(frame);
        }
    }

    /// Whether our frame was built (we hold a certificate to present).
    pub fn offered(&self) -> bool {
        self.frame.is_some()
    }

    /// Whether our frame went out at least once.
    pub fn sent(&self) -> bool {
        self.sent
    }

    /// Our frame to emit now, if any: the first time it is asked for, then on
    /// the [`Resend`] backoff until acknowledged, and only to a peer that
    /// acknowledges (`peer_acks`). Facing a peer that does not, it goes out
    /// once, as it always did.
    pub fn take_due(&mut self, now: Instant, peer_acks: bool) -> Option<Value> {
        let frame = self.frame.as_ref()?;
        if !self.sent {
            self.sent = true;
            self.resend.arm(now);
            return Some(frame.clone());
        }
        if !peer_acks || self.acked || !self.resend.due(now) {
            return None;
        }
        Some(frame.clone())
    }

    /// The peer acknowledged the frame whose nonce is `of`. An acknowledgement
    /// for any other frame (or before ours went out) changes nothing.
    pub fn on_ack(&mut self, of: &str) -> bool {
        let ours = self.frame.as_ref().and_then(|f| f["nonce"].as_str());
        if self.sent && ours == Some(of) {
            self.acked = true;
        }
        self.acked
    }

    pub fn acked(&self) -> bool {
        self.acked
    }

    /// One copy of the peer's frame was checked. Returns whether to
    /// acknowledge it: every accepted copy is acknowledged (our answer to the
    /// first may have been lost), and only to a peer that acknowledges.
    pub fn on_peer_frame(&mut self, now: Instant, verdict: Verdict, peer_acks: bool) -> bool {
        match verdict {
            Verdict::Accepted => {
                self.peer_cert = true;
                self.refused = None;
                if peer_acks {
                    self.answered = true;
                    self.last_copy = Some(now);
                }
                peer_acks
            }
            Verdict::NotYet => false,
            Verdict::Refused(why) => {
                if !self.peer_cert {
                    self.refused = Some(why);
                }
                false
            }
        }
    }

    pub fn peer_cert(&self) -> bool {
        self.peer_cert
    }

    /// The refusal of the peer's frame, when its certificate did not verify.
    pub fn refused(&self) -> Option<&str> {
        self.refused.as_deref()
    }

    /// Whether this pairing must keep waiting before it may succeed.
    /// `peer_acks`: the peer advertised `expose_ack: 1`; `peer_will_expose`:
    /// it also advertised `exposes: true`. A refused certificate does not
    /// wait: it fails now (see [`ExposeExchange::unmet`]).
    pub fn waiting(&self, peer_acks: bool, peer_will_expose: bool) -> bool {
        let ours = self.sent && peer_acks && !self.acked;
        let theirs = peer_will_expose && !self.peer_cert && self.refused.is_none();
        ours || theirs
    }

    /// What stops this pairing from succeeding, if anything. The peer's side
    /// is reported first: it is the one this device can say most about.
    pub fn unmet(&self, peer_acks: bool, peer_will_expose: bool) -> Option<Unmet> {
        if peer_will_expose && !self.peer_cert {
            return Some(match &self.refused {
                Some(why) => Unmet::CertRefused(why.clone()),
                None => Unmet::CertMissing,
            });
        }
        if self.sent && peer_acks && !self.acked {
            return Some(Unmet::NotAcknowledged);
        }
        None
    }

    /// After success: whether to stay a moment answering re-sent copies (we
    /// acknowledged the peer's frame, and that acknowledgement may be lost).
    pub fn should_linger(&self) -> bool {
        self.answered
    }

    /// Note a copy of the peer's frame seen while lingering.
    pub fn note_copy(&mut self, now: Instant) {
        self.last_copy = Some(now);
    }

    /// Whether lingering is over at `now` (started at `since`): no copy of
    /// the peer's frame for [`LINGER_QUIET`].
    pub fn linger_over(&self, now: Instant, since: Instant) -> bool {
        let last = self.last_copy.map_or(since, |c| c.max(since));
        now.saturating_duration_since(last) >= LINGER_QUIET
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(n: &str) -> Value {
        json!({"type": "identity-expose", "v": 2, "nonce": n, "sealed": "00"})
    }

    /// Run two sides over a channel that drops the first `drop_first` copies
    /// of `a`'s frame (or all of them), until `deadline_ms`. Returns
    /// (a unmet, b unmet, copies of a's frame sent).
    fn run(drop_first: usize, drop_acks: usize, deadline_ms: u64) -> (Option<Unmet>, Option<Unmet>, usize) {
        let t0 = Instant::now();
        let mut a = ExposeExchange::new();
        let mut b = ExposeExchange::new();
        a.offer(frame("aa"));
        let (mut sent, mut acks) = (0usize, 0usize);
        let mut t = t0;
        while t < t0 + Duration::from_millis(deadline_ms) {
            if let Some(f) = a.take_due(t, true) {
                sent += 1;
                assert_eq!(f, frame("aa"), "every copy is the same bytes");
                if sent > drop_first && b.on_peer_frame(t, Verdict::Accepted, true) {
                    acks += 1;
                    if acks > drop_acks {
                        a.on_ack("aa");
                    }
                }
            }
            if !a.waiting(true, false) && !b.waiting(true, true) {
                break;
            }
            t += Duration::from_millis(10);
        }
        (a.unmet(true, false), b.unmet(true, true), sent)
    }

    #[test]
    fn the_certificate_lands_after_the_first_copies_are_lost() {
        for n in 0..8 {
            let (a, b, sent) = run(n, 0, 60_000);
            assert_eq!((a, b), (None, None), "drop first {n}");
            assert_eq!(sent, n + 1);
        }
    }

    #[test]
    fn a_lost_acknowledgement_is_answered_by_the_next_copy() {
        let (a, b, sent) = run(0, 3, 60_000);
        assert_eq!((a, b), (None, None));
        assert_eq!(sent, 4);
    }

    #[test]
    fn every_copy_lost_fails_both_sides() {
        let (a, b, sent) = run(usize::MAX, 0, 20_000);
        assert_eq!(a, Some(Unmet::NotAcknowledged));
        assert_eq!(b, Some(Unmet::CertMissing));
        // 250 ms, 500 ms, 1 s, then every 2 s: bounded, never a flood.
        assert!((10..=13).contains(&sent), "{sent}");
    }

    #[test]
    fn a_peer_that_does_not_acknowledge_gets_one_send_and_no_wait() {
        let t0 = Instant::now();
        let mut a = ExposeExchange::new();
        a.offer(frame("aa"));
        assert!(a.take_due(t0, false).is_some());
        for s in 1..30 {
            assert!(a.take_due(t0 + Duration::from_secs(s), false).is_none());
        }
        assert!(!a.waiting(false, false));
        assert_eq!(a.unmet(false, false), None);
        // A receiver facing it acknowledges nothing and waits for nothing.
        let mut b = ExposeExchange::new();
        assert!(!b.on_peer_frame(t0, Verdict::Accepted, false));
        assert!(!b.waiting(false, false) && !b.should_linger());
    }

    #[test]
    fn duplicates_and_stray_acks_change_nothing() {
        let t0 = Instant::now();
        let mut a = ExposeExchange::new();
        a.offer(frame("aa"));
        a.offer(frame("bb"));
        assert_eq!(a.take_due(t0, true), Some(frame("aa")), "the first frame stands");
        assert!(!a.on_ack("bb"), "an ack for another frame is not ours");
        assert!(a.on_ack("aa") && a.on_ack("aa"));
        assert!(a.take_due(t0 + Duration::from_secs(10), true).is_none());
        let mut b = ExposeExchange::new();
        assert!(b.on_peer_frame(t0, Verdict::Accepted, true));
        assert!(b.on_peer_frame(t0, Verdict::Accepted, true), "every copy is answered");
        assert!(!b.on_peer_frame(t0, Verdict::Refused("x".into()), true));
        assert!(b.peer_cert() && b.refused().is_none(), "a verified certificate stays verified");
    }

    #[test]
    fn a_refused_or_unchecked_copy_is_never_acknowledged() {
        let t0 = Instant::now();
        let mut b = ExposeExchange::new();
        assert!(!b.on_peer_frame(t0, Verdict::NotYet, true));
        assert!(b.waiting(true, true), "not checked yet: keep waiting");
        assert!(!b.on_peer_frame(t0, Verdict::Refused("seal does not open".into()), true));
        assert!(!b.waiting(true, true), "refused: fail now, do not wait");
        assert_eq!(b.unmet(true, true), Some(Unmet::CertRefused("seal does not open".into())));
    }

    #[test]
    fn lingering_ends_after_a_quiet_spell() {
        let t0 = Instant::now();
        let mut b = ExposeExchange::new();
        b.on_peer_frame(t0, Verdict::Accepted, true);
        assert!(b.should_linger());
        assert!(!b.linger_over(t0 + Duration::from_millis(2000), t0));
        b.note_copy(t0 + Duration::from_millis(2000));
        assert!(!b.linger_over(t0 + Duration::from_millis(4000), t0));
        assert!(b.linger_over(t0 + Duration::from_millis(4300), t0));
    }
}
