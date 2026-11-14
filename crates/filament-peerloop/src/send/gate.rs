//! Pure targeting rules shared by every code-sender adapter.
//!
//! A one-time code authenticates exactly ONE peer through the PAKE ceremony.
//! That peer owns the transfer slot; a different room member is never its
//! replacement, even when it claims the same install UID or kept a partial
//! file. A fresh send with a fresh code is the only way to resume.

/// Which event class a code sender is deciding for. All three are tied to the
/// one signaling peer the PAKE ceremony authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePeerEvent {
    /// Transport control frames: never accepted before the ceremony settles,
    /// and after it only from the ceremony peer.
    Control,
    /// A ready channel. Allowed before the ceremony so the PAKE itself can
    /// run; after it only the ceremony peer may ever become the receiver.
    Channel,
    /// Room/roster adoption. Same rule as a ready channel.
    Adoption,
}

/// May a code sender process an event from `pid`? Pure, so the adversarial
/// replacement case is testable without sockets.
///
/// A spent code authorizes exactly one receiver: the peer whose PAKE ceremony
/// completed. A different room member is not a replacement receiver, even if
/// it reuses the same install UID or kept a partial; it needs a fresh code.
pub fn code_peer_event_allowed(
    use_code: bool,
    pake_done: bool,
    ceremony_peer: Option<&str>,
    pid: &str,
    kind: CodePeerEvent,
) -> bool {
    if !use_code {
        return true;
    }
    match kind {
        CodePeerEvent::Control => pake_done && ceremony_peer == Some(pid),
        CodePeerEvent::Channel | CodePeerEvent::Adoption => {
            !pake_done || ceremony_peer == Some(pid)
        }
    }
}

/// May an adopted room peer take the transfer slot? On the code path, no peer
/// is the target until one authenticated (it takes the slot at confirm). Room
/// presence never authorizes a replacement after that code has been consumed.
pub fn adopt_wants_active(code_claimed: bool, use_code: bool, _pake_done: bool) -> bool {
    code_claimed && !use_code
}

/// Receiver answers that are bound to the code-authorized link.
pub const CODE_BOUND_ANSWERS: [&str; 5] = [
    "file-accept",
    "file-decline",
    "file-pending",
    "delivery-ack",
    "pair-keep-ack",
];

/// Code path only: may the sender act on answer `kind`? Pure.
pub fn code_answer_admitted(kind: &str, authority_holds: bool) -> bool {
    authority_holds || !CODE_BOUND_ANSWERS.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adversarial: the authentic receiver ran the PAKE ceremony and then
    /// died mid-transfer. A different room peer (even one sharing the install
    /// UID and a partial file) must not be treated as its replacement. The
    /// spent code authorizes only the ceremony peer; the room peer needs a
    /// fresh code, which starts a new ceremony.
    #[test]
    fn a_non_ceremony_room_peer_cannot_receive_after_the_authentic_receiver_dies() {
        let authentic = "sid-authentic";
        let replacement = "sid-replacement";
        let peer = Some(authentic);

        for kind in [
            CodePeerEvent::Control,
            CodePeerEvent::Channel,
            CodePeerEvent::Adoption,
        ] {
            assert!(
                code_peer_event_allowed(true, true, peer, authentic, kind),
                "the ceremony peer stays addressable after its channel dies: {kind:?}"
            );
            assert!(
                !code_peer_event_allowed(true, true, peer, replacement, kind),
                "a non-ceremony room peer must never be handled on a spent code: {kind:?}"
            );
        }

        // And adoption could not hand it the transfer slot even if some other
        // path let the event through: a code send never gives the slot to a
        // room peer, before or after the ceremony.
        assert!(!adopt_wants_active(true, true, true));
    }

    /// The event gate pins the ceremony's sid; the sender's offer, accept and
    /// pair-keep also require the link the ceremony confirmed
    /// (`Conn::holds_code_authority`, rule `code_authority_check`). A rebuilt
    /// link under the SAME sid passes the event gate and is still refused.
    #[test]
    fn a_code_sender_offers_only_on_the_confirmed_link_or_its_own_promotion() {
        use crate::{code_authority_check, CodeAuthorityRefusal, CodeSession, CodeTransport};
        use filament_transport::net::AttemptId;

        let ours = AttemptId::next();
        let session = CodeSession::new("sid-receiver", ("fp-sender", "fp-receiver"), "k", Some(ours));
        let s = Some(&session);
        assert!(code_peer_event_allowed(
            true,
            true,
            Some("sid-receiver"),
            "sid-receiver",
            CodePeerEvent::Channel
        ));
        // Positive controls: the confirmed WebRTC link and the ceremony's own
        // direct promotion.
        assert_eq!(
            code_authority_check(s, "sid-receiver", CodeTransport::WebRtc(Some(("fp-sender", "fp-receiver")))),
            Ok(())
        );
        assert_eq!(
            code_authority_check(
                s,
                "sid-receiver",
                CodeTransport::Direct { attempt: Some(ours), secret: Some("k") }
            ),
            Ok(())
        );
        // Same sid, rebuilt PeerConnection: refused.
        assert_eq!(
            code_authority_check(s, "sid-receiver", CodeTransport::WebRtc(Some(("fp-sender", "fp-other")))),
            Err(CodeAuthorityRefusal::FingerprintMismatch)
        );
        // Same sid, a direct link another attempt published: refused.
        assert_eq!(
            code_authority_check(
                s,
                "sid-receiver",
                CodeTransport::Direct { attempt: Some(AttemptId::next()), secret: Some("k") }
            ),
            Err(CodeAuthorityRefusal::ForeignDirect)
        );
    }

    #[test]
    fn a_code_senders_answers_count_only_from_the_confirmed_link() {
        for kind in ["file-accept", "file-decline", "file-pending", "delivery-ack", "pair-keep-ack"] {
            assert!(code_answer_admitted(kind, true), "{kind}");
            assert!(!code_answer_admitted(kind, false), "{kind}");
        }
        assert!(code_answer_admitted("path-promote", false));
    }

    #[test]
    fn an_unclaimed_code_still_accepts_the_room_channel_that_carries_the_ceremony() {
        assert!(code_peer_event_allowed(
            true,
            false,
            None,
            "sid-room",
            CodePeerEvent::Channel
        ));
        assert!(code_peer_event_allowed(
            true,
            false,
            None,
            "sid-room",
            CodePeerEvent::Adoption
        ));
        assert!(!code_peer_event_allowed(
            true,
            false,
            None,
            "sid-room",
            CodePeerEvent::Control
        ));
    }

    #[test]
    fn a_room_send_keeps_its_existing_adoption_and_event_rules() {
        assert!(adopt_wants_active(true, false, false));
        assert!(code_peer_event_allowed(
            false,
            false,
            None,
            "sid-any",
            CodePeerEvent::Control
        ));
    }
}
