//! Adoption matching: which roster entry a link may bind to, and whether an
//! exhausted peer may be re-adopted.
//!
//! Both are pure over the peer id, the peer uid and the suppression set. The
//! distinction the first one carries is the whole point: a DIGEST (roster
//! reconciliation) must not undo an exhausted give-up, while real CONTACT is
//! evidence the peer is reachable and does.

use filament_transport::net::AttemptId;
use std::collections::HashSet;

/// Why a roster entry is being adopted. Contact is the safe default for new
/// call sites; Digest is reserved for roster reconciliation, which must not
/// undo an exhausted give-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptSource {
    Contact,
    Digest,
}

pub fn match_adoption_source(
    suppressed: &mut HashSet<String>,
    peer_id: &str,
    source: AdoptSource,
) -> bool {
    match source {
        AdoptSource::Contact => {
            suppressed.remove(peer_id);
            true
        }
        AdoptSource::Digest => !suppressed.contains(peer_id),
    }
}

/// May a code-receive binding hand the TRANSFER SLOT to `peer_id`? Only the
/// exact sid whose ceremony confirmed. A same-install peer on a new sid (a
/// signaling reconnect whose old link died) is not this code's session: it
/// needs a fresh code. Code-path accept, consent and remember decisions are
/// [`code_authority_check`], which also requires the confirmed transport.
pub fn active_binding_matches(binding: &(String, Option<String>), peer_id: &str) -> bool {
    binding.0 == peer_id
}

/// The session a code ceremony (`receive <code>` / `send --code`) confirmed:
/// the exact signaling sid it ran with, the DTLS fingerprint pair its
/// confirmation MAC bound (`(mine, theirs)`, in `Peer::fingerprints` order),
/// the ceremony secret, and the direct attempt that ceremony's own promotion
/// armed (if it armed one). Set once at confirmation and never rewritten.
///
/// Deliberately not `Debug`: it holds the ceremony secret.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeSession {
    sid: String,
    mine: String,
    theirs: String,
    secret: String,
    promote_attempt: Option<AttemptId>,
}

impl CodeSession {
    pub fn new(
        sid: &str,
        fingerprints: (&str, &str),
        secret: &str,
        promote_attempt: Option<AttemptId>,
    ) -> Self {
        CodeSession {
            sid: sid.to_string(),
            mine: fingerprints.0.to_string(),
            theirs: fingerprints.1.to_string(),
            secret: secret.to_string(),
            promote_attempt,
        }
    }

    /// The signaling sid the ceremony confirmed with.
    pub fn sid(&self) -> &str {
        &self.sid
    }
}

/// The transport a code-path decision is about to be made on, as facts read
/// off the peer's CURRENT link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CodeTransport<'a> {
    /// No link to the peer.
    Absent,
    /// A WebRTC (DataChannel / relay) link and its DTLS fingerprints
    /// `(mine, theirs)`, `None` while they are not known.
    WebRtc(Option<(&'a str, &'a str)>),
    /// A direct QUIC link: the attempt that published it and the secret its
    /// handshake MAC was keyed with.
    Direct {
        attempt: Option<AttemptId>,
        secret: Option<&'a str>,
    },
}

// Hand-written so a formatted transport never prints the ceremony secret.
impl std::fmt::Debug for CodeTransport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::WebRtc(fps) => f.debug_tuple("WebRtc").field(fps).finish(),
            Self::Direct { attempt, secret } => f
                .debug_struct("Direct")
                .field("attempt", attempt)
                .field("secret", &secret.map(|_| "<redacted>"))
                .finish(),
        }
    }
}

/// Why a code-path decision was refused. Carries no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeAuthorityRefusal {
    /// No ceremony has confirmed on this run.
    Unconfirmed,
    /// The peer is not the exact signaling session the ceremony confirmed.
    SessionMismatch,
    /// No link to the peer, or its fingerprints are not known yet.
    NoTransport,
    /// The link's DTLS fingerprints are not the pair the ceremony confirmed.
    FingerprintMismatch,
    /// The direct link is not the one this ceremony's promotion published.
    ForeignDirect,
}

impl CodeAuthorityRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unconfirmed => "no code ceremony confirmed",
            Self::SessionMismatch => "not the session the code ceremony confirmed",
            Self::NoTransport => "no link with known fingerprints",
            Self::FingerprintMismatch => "link fingerprints differ from the confirmed pair",
            Self::ForeignDirect => "direct link is not this ceremony's promotion",
        }
    }
}

/// Code authority: may a code-path accept, consent or remember decision be
/// made for `peer_id` on `transport`? Only for the EXACT sid the ceremony
/// confirmed, and only on a transport the confirmation covers: a WebRTC link
/// whose DTLS fingerprints are exactly the confirmed pair, or the direct QUIC
/// link published by the promotion attempt that ceremony armed, keyed by the
/// ceremony secret (derived from K only after that confirmation verified). A
/// shared install uid, a roster entry or a replacement transport for the same
/// sid is never enough on its own. Pure.
pub fn code_authority_check(
    session: Option<&CodeSession>,
    peer_id: &str,
    transport: CodeTransport<'_>,
) -> Result<(), CodeAuthorityRefusal> {
    let Some(session) = session else {
        return Err(CodeAuthorityRefusal::Unconfirmed);
    };
    if session.sid != peer_id {
        return Err(CodeAuthorityRefusal::SessionMismatch);
    }
    match transport {
        CodeTransport::Absent | CodeTransport::WebRtc(None) => Err(CodeAuthorityRefusal::NoTransport),
        CodeTransport::WebRtc(Some((mine, theirs))) => {
            if mine == session.mine && theirs == session.theirs {
                Ok(())
            } else {
                Err(CodeAuthorityRefusal::FingerprintMismatch)
            }
        }
        CodeTransport::Direct { attempt, secret } => {
            let ours = session.promote_attempt.is_some()
                && attempt == session.promote_attempt
                && secret == Some(session.secret.as_str());
            if ours {
                Ok(())
            } else {
                Err(CodeAuthorityRefusal::ForeignDirect)
            }
        }
    }
}

/// May this peer become the TRANSFER TARGET? (Filters gate targeting, never
/// answering: every peer still gets a polite link.) A `--to` filter must appear
/// in the candidate's name, case-insensitively; and two CLI peers of the same
/// role never transfer to each other (gate 7), compared on the first six chars of
/// our own uid. Pure over the filter, our uid and the candidate.
pub fn peer_targetable(
    to_filter: Option<&str>,
    my_uid: &str,
    name: &str,
    peer_uid: Option<&str>,
) -> bool {
    if let Some(filter) = to_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return false;
        }
    }
    if let (Some(pu), Some(my_role)) = (peer_uid, my_uid.get(..6)) {
        if pu.starts_with(my_role) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The code-receive binding names the confirmed sender: its own sid is
    /// authorized and an unrelated paired peer is not. A same-install REJOIN on
    /// a new sid is not authorized either (a deliberate policy change: it used
    /// to inherit the binding through the install uid). Code authority is
    /// bound to the confirmed session and its transport, so a new sid needs a
    /// fresh ceremony, which means a fresh code.
    #[test]
    fn code_receive_binding_rejects_unrelated_paired_peer_and_an_unproven_rejoin() {
        let binding = (
            "sender-old-sid".to_string(),
            Some("sender-install".to_string()),
        );
        let session = CodeSession::new("sender-old-sid", ("fp-a", "fp-b"), "k-secret", None);
        let confirmed = CodeTransport::WebRtc(Some(("fp-a", "fp-b")));

        assert!(active_binding_matches(&binding, "sender-old-sid"));
        assert_eq!(
            code_authority_check(Some(&session), "sender-old-sid", confirmed),
            Ok(()),
            "the confirmed session on its confirmed transport is authorized"
        );
        // Same install uid, new sid, no fresh proof: refused.
        assert!(!active_binding_matches(&binding, "sender-new-sid"));
        assert_eq!(
            code_authority_check(Some(&session), "sender-new-sid", confirmed),
            Err(CodeAuthorityRefusal::SessionMismatch),
            "a same-install rejoin on a new sid needs a fresh code"
        );
        assert!(!active_binding_matches(&binding, "unrelated-paired-sid"));
        assert_eq!(
            code_authority_check(Some(&session), "unrelated-paired-sid", confirmed),
            Err(CodeAuthorityRefusal::SessionMismatch)
        );
    }

    /// The same sid on a REPLACEMENT transport is authorized only when that
    /// transport is one the ceremony covers: the confirmed fingerprint pair,
    /// or the direct link its own promotion attempt published.
    #[test]
    fn code_authority_follows_the_confirmed_transport_not_the_sid_alone() {
        let ours = AttemptId::next();
        let foreign = AttemptId::next();
        let session = CodeSession::new("sid-s1", ("fp-a", "fp-b"), "k-secret", Some(ours));
        let s = Some(&session);
        let direct = |attempt, secret| CodeTransport::Direct { attempt, secret };
        // Positive controls: the confirmed WebRTC link, and the direct link
        // this ceremony's promotion published.
        assert_eq!(code_authority_check(s, "sid-s1", CodeTransport::WebRtc(Some(("fp-a", "fp-b")))), Ok(()));
        assert_eq!(code_authority_check(s, "sid-s1", direct(Some(ours), Some("k-secret"))), Ok(()));
        // A replacement RTCPeerConnection: either fingerprint differs.
        assert_eq!(
            code_authority_check(s, "sid-s1", CodeTransport::WebRtc(Some(("fp-a", "fp-c")))),
            Err(CodeAuthorityRefusal::FingerprintMismatch)
        );
        assert_eq!(
            code_authority_check(s, "sid-s1", CodeTransport::WebRtc(Some(("fp-c", "fp-b")))),
            Err(CodeAuthorityRefusal::FingerprintMismatch)
        );
        // The order is (mine, theirs): a swapped pair is not the confirmed one.
        assert_eq!(
            code_authority_check(s, "sid-s1", CodeTransport::WebRtc(Some(("fp-b", "fp-a")))),
            Err(CodeAuthorityRefusal::FingerprintMismatch)
        );
        // Fingerprints not known (and not a promoted direct link), or no link.
        assert_eq!(
            code_authority_check(s, "sid-s1", CodeTransport::WebRtc(None)),
            Err(CodeAuthorityRefusal::NoTransport)
        );
        assert_eq!(code_authority_check(s, "sid-s1", CodeTransport::Absent), Err(CodeAuthorityRefusal::NoTransport));
        // A direct link some other attempt published, even keyed by the same
        // secret, or keyed by anything else, or with no attempt at all.
        assert_eq!(
            code_authority_check(s, "sid-s1", direct(Some(foreign), Some("k-secret"))),
            Err(CodeAuthorityRefusal::ForeignDirect)
        );
        assert_eq!(
            code_authority_check(s, "sid-s1", direct(Some(ours), Some("other"))),
            Err(CodeAuthorityRefusal::ForeignDirect)
        );
        assert_eq!(
            code_authority_check(s, "sid-s1", direct(None, Some("k-secret"))),
            Err(CodeAuthorityRefusal::ForeignDirect)
        );
        // A ceremony whose promotion never armed admits no direct link.
        let unpromoted = CodeSession::new("sid-s1", ("fp-a", "fp-b"), "k-secret", None);
        assert_eq!(
            code_authority_check(Some(&unpromoted), "sid-s1", direct(None, Some("k-secret"))),
            Err(CodeAuthorityRefusal::ForeignDirect)
        );
        // No confirmed ceremony: nothing is authorized, whatever the link.
        assert_eq!(
            code_authority_check(None, "sid-s1", CodeTransport::WebRtc(Some(("fp-a", "fp-b")))),
            Err(CodeAuthorityRefusal::Unconfirmed)
        );
    }

    #[test]
    fn a_to_filter_gates_targeting_but_an_unfiltered_peer_is_targetable() {
        // The filter matches the candidate's name, case-insensitively.
        assert!(peer_targetable(Some("lap"), "zz-me", "my-laptop", None));
        assert!(!peer_targetable(Some("lap"), "zz-me", "the-tower", None));
        // No filter: every peer is targetable.
        assert!(peer_targetable(None, "zz-me", "the-tower", None));
    }

    #[test]
    fn two_cli_peers_of_the_same_role_never_transfer_to_each_other() {
        // Same first six uid chars = same role: never a target (gate 7).
        assert!(!peer_targetable(
            None,
            "aaaaaa1-self",
            "peer",
            Some("aaaaaa2-peer")
        ));
        // Different role: targetable.
        assert!(peer_targetable(
            None,
            "aaaaaa1-self",
            "peer",
            Some("bbbbbb2-peer")
        ));
        // A uid too short to carry a role prefix is not rejected.
        assert!(peer_targetable(None, "zz", "peer", Some("aaaaaa2-peer")));
    }
}
