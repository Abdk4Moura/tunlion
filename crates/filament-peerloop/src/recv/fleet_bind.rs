//! Link-binding challenge bookkeeping for `fleet-hello` and `l3-announce` on a
//! transport with no exporter (CONTRACT.md, "Link channel binding").
//!
//! Three decisions live here, pure (no I/O; callers pass `now`):
//!
//! - **Epoch.** A challenge belongs to the INSTALLED link's (generation,
//!   source), not to whichever transport delivered an event. An event from a
//!   transport that is not the installed one changes nothing.
//! - **Retry.** Our challenge is re-sent, the SAME nonce, on a bounded backoff
//!   while the peer has not been verified on this link. The peer answers every
//!   nonce with a hello, so a lost nonce or a lost answer costs one backoff step
//!   instead of the link's life.
//! - **Retired nonces.** When the epoch rotates, the previous nonce stays
//!   acceptable for VERIFYING a hello for a short TTL, because a hello the peer
//!   signed over it can be in flight across the rotation. It is only ever
//!   combined with the CURRENT link's binding inputs (its DTLS fingerprint pair),
//!   and nothing here can hand it out for signing.

use filament_transport::net::SourceId;
use std::time::{Duration, Instant};

/// The installed transport a challenge belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub generation: u32,
    pub source: SourceId,
}

/// Re-send schedule for one challenge: the delay before retry N, measured from
/// the previous send. Four retries, the last ~30 s after the first send.
pub const RETRY_BACKOFF: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// How long a superseded nonce may still verify a hello.
pub const RETIRED_TTL: Duration = Duration::from_secs(10);

/// At most this many superseded nonces are held per peer.
pub const RETIRED_MAX: usize = 2;

/// What a ChannelReady means for the held challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochChange {
    /// No link is installed for this peer: touch nothing.
    NotInstalled,
    /// The first challenge for this peer.
    First,
    /// The installed transport is the one the challenge belongs to.
    Same,
    /// A different transport is installed: retire the old nonce, mint a new one,
    /// and drop the peer's nonce (it was for the previous transport).
    Rotated,
}

/// Decide from the held epoch and the installed link's epoch. The event's own
/// source is deliberately not an input: a racing transport that lost can still
/// deliver ChannelReady, and that must not reset the winner's challenge.
pub fn epoch_change(held: Option<Epoch>, installed: Option<Epoch>) -> EpochChange {
    match (held, installed) {
        (_, None) => EpochChange::NotInstalled,
        (None, Some(_)) => EpochChange::First,
        (Some(h), Some(i)) if h == i => EpochChange::Same,
        (Some(_), Some(_)) => EpochChange::Rotated,
    }
}

/// Our outstanding challenge on one link.
#[derive(Clone, Debug)]
pub struct Challenge {
    pub epoch: Epoch,
    pub nonce: Vec<u8>,
    retries: u32,
    last_sent: Instant,
}

impl Challenge {
    pub fn new(epoch: Epoch, nonce: Vec<u8>, now: Instant) -> Self {
        Challenge { epoch, nonce, retries: 0, last_sent: now }
    }

    /// A send that was not a retry (ChannelReady re-sends the same nonce).
    /// Restarts the backoff clock without spending the retry budget.
    pub fn note_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    /// Is a retry due now? False forever once the budget is spent.
    pub fn retry_due(&self, now: Instant) -> bool {
        RETRY_BACKOFF
            .get(self.retries as usize)
            .is_some_and(|wait| now.saturating_duration_since(self.last_sent) >= *wait)
    }

    /// Record a retry that went out; returns its 1-based number.
    pub fn note_retry(&mut self, now: Instant) -> u32 {
        self.retries = self.retries.saturating_add(1);
        self.last_sent = now;
        self.retries
    }

    pub fn retries(&self) -> u32 {
        self.retries
    }
}

/// May `c` be re-sent now? Only on the transport it was minted for (an epoch
/// mismatch means the link moved on and ChannelReady owns the new challenge),
/// only while the peer is unverified, and only on the backoff.
pub fn retry_allowed(c: &Challenge, installed: Option<Epoch>, peer_verified: bool, now: Instant) -> bool {
    !peer_verified && installed == Some(c.epoch) && c.retry_due(now)
}

/// Superseded nonces of one peer, verify-only, each with its expiry.
#[derive(Clone, Debug, Default)]
pub struct Retired {
    entries: Vec<(Vec<u8>, Instant)>,
}

impl Retired {
    /// Keep `nonce` verify-only until `now + RETIRED_TTL`; at most RETIRED_MAX.
    pub fn retire(&mut self, nonce: Vec<u8>, now: Instant) {
        self.entries.retain(|(_, until)| *until > now);
        self.entries.push((nonce, now + RETIRED_TTL));
        while self.entries.len() > RETIRED_MAX {
            self.entries.remove(0);
        }
    }

    /// The nonces still inside their TTL, newest first.
    pub fn live(&self, now: Instant) -> Vec<&[u8]> {
        self.entries
            .iter()
            .rev()
            .filter(|(_, until)| *until > now)
            .map(|(n, _)| n.as_slice())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Is `nonce` one of ours, expired or not?
    pub fn holds(&self, nonce: &[u8]) -> bool {
        self.entries.iter().any(|(n, _)| n.as_slice() == nonce)
    }
}

/// The stable reason a received challenge is refused when it is one we issued.
pub const REFLECTED_CHALLENGE: &str = "reflected-challenge";

/// The stable reason a verified hello is refused when it carries our own key.
pub const OWN_DEVICE_KEY: &str = "own-device-key";

/// May a received `l3-nonce` be kept as the peer's challenge? Not when it
/// equals a nonce WE issued, current or retired, on any link: a challenge is
/// answered only when the peer chose it.
pub fn accept_peer_nonce<'a>(
    nonce: &[u8],
    ours: impl IntoIterator<Item = &'a [u8]>,
    retired: impl IntoIterator<Item = &'a Retired>,
) -> Result<(), &'static str> {
    if ours.into_iter().any(|o| o == nonce) || retired.into_iter().any(|r| r.holds(nonce)) {
        return Err(REFLECTED_CHALLENGE);
    }
    Ok(())
}

/// Does a verified hello carry this device's own key? Such a hello is never
/// admitted as a peer.
pub fn is_own_device(device_pub: &[u8; 32], own: Option<[u8; 32]>) -> bool {
    own.is_some_and(|o| &o == device_pub)
}

/// The bindings a hello on the CURRENT link may verify against, in order: the
/// current challenge, then live retired nonces. `bind` computes a binding from
/// a nonce over the current link's inputs (exporter or DTLS fingerprint pair);
/// a nonce it cannot bind (inputs missing) contributes nothing. No stored
/// binding is ever reused, so a superseded nonce cannot verify a hello on a
/// link other than the one it is presented on.
pub fn verify_candidates<F>(
    current: Option<&[u8]>,
    retired: Option<&Retired>,
    now: Instant,
    bind: F,
) -> Vec<Vec<u8>>
where
    F: Fn(&[u8]) -> Option<Vec<u8>>,
{
    let mut out: Vec<Vec<u8>> = Vec::new();
    if let Some(n) = current {
        if let Some(cb) = bind(n) {
            out.push(cb);
        }
    }
    if let Some(r) = retired {
        for n in r.live(now) {
            if let Some(cb) = bind(n) {
                if !out.contains(&cb) {
                    out.push(cb);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn epoch(generation: u32, source: SourceId) -> Epoch {
        Epoch { generation, source }
    }

    // Stand-in for the DTLS binding: a hash over the fingerprint pair and nonce.
    fn dtls(fps: (&str, &str), nonce: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(fps.0.as_bytes());
        h.update([0u8]);
        h.update(fps.1.as_bytes());
        h.update([0u8]);
        h.update(nonce);
        h.finalize().to_vec()
    }

    #[test]
    fn retry_is_bounded_and_follows_the_backoff() {
        let t0 = Instant::now();
        let mut c = Challenge::new(epoch(1, SourceId::next()), vec![7; 32], t0);
        let mut at = t0;
        for (i, wait) in RETRY_BACKOFF.iter().enumerate() {
            assert!(!c.retry_due(at + *wait - Duration::from_millis(1)), "retry {i} early");
            at += *wait;
            assert!(c.retry_due(at), "retry {i} not due on time");
            assert_eq!(c.note_retry(at), i as u32 + 1);
        }
        // Budget spent: never due again, however long the link waits.
        assert!(!c.retry_due(at + Duration::from_secs(3600)));
        assert_eq!(c.retries() as usize, RETRY_BACKOFF.len());
        // The nonce never changed across retries.
        assert_eq!(c.nonce, vec![7; 32]);
    }

    #[test]
    fn a_non_retry_send_restarts_the_clock_without_spending_budget() {
        let t0 = Instant::now();
        let mut c = Challenge::new(epoch(1, SourceId::next()), vec![1; 32], t0);
        c.note_sent(t0 + Duration::from_secs(1));
        assert!(!c.retry_due(t0 + RETRY_BACKOFF[0]));
        assert!(c.retry_due(t0 + Duration::from_secs(1) + RETRY_BACKOFF[0]));
        assert_eq!(c.retries(), 0);
    }

    #[test]
    fn retry_stops_on_epoch_mismatch_and_once_verified() {
        let t0 = Instant::now();
        let a = SourceId::next();
        let b = SourceId::next();
        let c = Challenge::new(epoch(3, a), vec![2; 32], t0);
        let due = t0 + RETRY_BACKOFF[0];
        assert!(retry_allowed(&c, Some(epoch(3, a)), false, due));
        assert!(!retry_allowed(&c, Some(epoch(3, b)), false, due), "other source");
        assert!(!retry_allowed(&c, Some(epoch(4, a)), false, due), "other generation");
        assert!(!retry_allowed(&c, None, false, due), "no link");
        assert!(!retry_allowed(&c, Some(epoch(3, a)), true, due), "peer already verified");
    }

    #[test]
    fn epoch_follows_the_installed_link_not_the_event() {
        let a = SourceId::next();
        let b = SourceId::next();
        assert_eq!(epoch_change(None, None), EpochChange::NotInstalled);
        assert_eq!(epoch_change(Some(epoch(1, a)), None), EpochChange::NotInstalled);
        assert_eq!(epoch_change(None, Some(epoch(1, a))), EpochChange::First);
        assert_eq!(epoch_change(Some(epoch(1, a)), Some(epoch(1, a))), EpochChange::Same);
        // A new transport (source) or a new link generation rotates.
        assert_eq!(epoch_change(Some(epoch(1, a)), Some(epoch(1, b))), EpochChange::Rotated);
        assert_eq!(epoch_change(Some(epoch(1, a)), Some(epoch(2, a))), EpochChange::Rotated);
    }

    #[test]
    fn a_retired_nonce_verifies_only_within_its_ttl() {
        let t0 = Instant::now();
        let fps = ("AA", "BB");
        let mut r = Retired::default();
        r.retire(vec![9; 32], t0);
        let bind = |n: &[u8]| Some(dtls(fps, n));
        let inside = verify_candidates(Some(&[1u8; 32][..]), Some(&r), t0 + RETIRED_TTL / 2, bind);
        assert_eq!(inside.len(), 2, "current plus the live retired nonce");
        assert_eq!(inside[0], dtls(fps, &[1; 32]), "the current challenge is tried first");
        let after = verify_candidates(Some(&[1u8; 32][..]), Some(&r), t0 + RETIRED_TTL, bind);
        assert_eq!(after, vec![dtls(fps, &[1; 32])], "expired retired nonce is gone");
    }

    #[test]
    fn retired_nonces_are_capped() {
        let t0 = Instant::now();
        let mut r = Retired::default();
        for i in 0..5u8 {
            r.retire(vec![i; 32], t0);
        }
        let live = r.live(t0);
        assert_eq!(live.len(), RETIRED_MAX);
        assert_eq!(live[0], &[4u8; 32][..], "newest first");
    }

    #[test]
    fn a_nonce_binds_only_to_the_link_it_is_presented_on() {
        // A hello signed on link A (fingerprints A) over a nonce that is later
        // retired is replayed onto link B (fingerprints B). Every candidate on B
        // is computed over B's inputs, so A's signed binding is never among them.
        let t0 = Instant::now();
        let nonce = vec![5u8; 32];
        let on_a = dtls(("A1", "A2"), &nonce);
        let mut r = Retired::default();
        r.retire(nonce.clone(), t0);
        let on_b = verify_candidates(Some(&[6u8; 32][..]), Some(&r), t0, |n| Some(dtls(("B1", "B2"), n)));
        assert!(!on_b.contains(&on_a), "a binding from another link must not verify here");
        // The same nonce under the same link's inputs is what verifies.
        assert!(on_b.contains(&dtls(("B1", "B2"), &nonce)));
    }

    #[test]
    fn a_challenge_we_issued_is_refused_when_received() {
        let t0 = Instant::now();
        let current = vec![4u8; 32];
        let mut r = Retired::default();
        r.retire(vec![5u8; 32], t0);
        let ours = [current.as_slice()];
        // Our current nonce, echoed back.
        assert_eq!(
            accept_peer_nonce(&current, ours, [&r]),
            Err(REFLECTED_CHALLENGE)
        );
        // A retired one, echoed back.
        assert_eq!(accept_peer_nonce(&[5u8; 32], ours, [&r]), Err(REFLECTED_CHALLENGE));
        // A nonce the peer chose is kept.
        assert_eq!(accept_peer_nonce(&[6u8; 32], ours, [&r]), Ok(()));
        // Refused means nothing is bound from it: the only binding we would
        // sign is over a kept peer nonce, and there is none.
        assert!(accept_peer_nonce(&current, ours, [&r]).is_err());
    }

    #[test]
    fn a_hello_or_announce_carrying_our_own_key_is_ours() {
        let own = [8u8; 32];
        assert!(is_own_device(&own, Some(own)));
        assert!(!is_own_device(&[9u8; 32], Some(own)));
    }

    /// KNOWN LIMITATION, pinned so it cannot change unnoticed: with the local
    /// overlay key unavailable the own-key refusal is inert. This is not the
    /// intended property; admission then rests on the reflected-challenge
    /// refusal alone (and on exporter links, on nothing).
    #[test]
    fn own_key_refusal_is_inert_without_the_local_key() {
        assert!(!is_own_device(&[8u8; 32], None));
    }

    /// Shipped builds carry the local overlay key wherever fleet admission is
    /// compiled: the daemon's own-key refusals read it through the `mesh`
    /// host API. The peerloop feature graph does NOT make `fleet` imply `mesh`;
    /// the CLI default and tunlion-core's `fleet` enable both. A peerloop build
    /// with `fleet` and without `mesh` fails here on purpose.
    #[test]
    fn fleet_builds_carry_the_local_overlay_key() {
        if cfg!(feature = "fleet") {
            assert!(
                cfg!(feature = "mesh"),
                "fleet without mesh: the own-key refusals have no local key and are inert"
            );
        }
    }

    #[test]
    fn missing_binding_inputs_yield_no_candidates() {
        let t0 = Instant::now();
        let mut r = Retired::default();
        r.retire(vec![3; 32], t0);
        // Fingerprints unknown: nothing can be verified (never a bare-nonce fallback).
        assert!(verify_candidates(Some(&[1u8; 32][..]), Some(&r), t0, |_| None).is_empty());
    }
}
