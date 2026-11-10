//! Pure decisions around the ceremony: who may certify, and what a finished
//! pairing should report. No UI strings beyond the structured outcome.

use serde_json::Value;

/// What the owner device does with a certless device's offer of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolOfferDecision {
    /// The operator already said "one of mine" (`add <name>`, `--for device`).
    Certify,
    /// Ask the person at THIS (owner) device, once.
    Ask,
    /// Refuse: an ordinary pairing.
    Decline,
}

/// The facts the decision rests on, named so a test can state each rule.
#[derive(Debug, Clone, Copy)]
pub struct EnrolOfferInputs {
    /// This device holds the owner key, so only it can sign.
    pub owner_here: bool,
    /// The operator said "a device of mine" before the code was shown.
    pub operator_said_own: bool,
    /// The operator said "someone else" (`--for person`).
    pub operator_said_person: bool,
    /// The offer opened under this ceremony's key AND its possession proof
    /// verified: it came from the ceremony partner, for a key that partner holds.
    pub offer_opened: bool,
    /// The device can wait for a person to answer (`hold`).
    pub peer_can_hold: bool,
    /// A person is here to ask: a terminal, not a script or `--json`.
    pub can_ask: bool,
    /// This ceremony already asked or certified once.
    pub already_asked: bool,
}

/// The one rule for turning a pairing into "one of your devices". The owner
/// key signs only on an explicit owner decision made on the owner device: said
/// up front, or answered here. Never from what the other side claims, never in
/// a script, never twice per ceremony. Pure.
pub fn enrol_offer_decision(i: EnrolOfferInputs) -> EnrolOfferDecision {
    if !i.owner_here || !i.offer_opened {
        return EnrolOfferDecision::Decline;
    }
    if i.operator_said_own {
        return if i.already_asked {
            EnrolOfferDecision::Decline
        } else {
            EnrolOfferDecision::Certify
        };
    }
    if i.operator_said_person || !i.peer_can_hold || !i.can_ask || i.already_asked {
        return EnrolOfferDecision::Decline;
    }
    EnrolOfferDecision::Ask
}

/// What a finished pairing did about "one of my devices", from either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolOutcome {
    /// Nothing to report: enrolled, already the same owner's, or never asked.
    Fine,
    /// OWNER SIDE, asked for one of its devices: the peer did not become one.
    OwnerNotEnrolled {
        offer_seen: bool,
        failed_proof: bool,
    },
    /// OWNER SIDE, asked for one of its devices, but the peer identified itself
    /// as a browser: the pairing is real (files and shell), the fleet
    /// enrolment is impossible and is not a failure.
    OwnerBrowserNotFleet,
    /// OWNER SIDE: certified, but the device never said it stored it.
    OwnerUnconfirmed,
    /// DEVICE SIDE: offered its key, nobody answered.
    DeviceNoAnswer,
    /// DEVICE SIDE: a certificate arrived and was refused.
    DeviceGrantRefused(String),
}

#[derive(Debug, Clone)]
pub struct EnrolOutcomeInputs {
    pub owner_asked_own: bool,
    pub certified_here: bool,
    pub already_same_owner: bool,
    pub peer_presented_cert: bool,
    /// The PAKE partner announced, on its transport hint, that it is a browser.
    /// Advisory device-kind evidence only: it can explain why a pairing is not
    /// a fleet enrolment, never admit one or excuse a failed key proof.
    pub peer_is_browser: bool,
    pub offer_seen: bool,
    pub offer_failed_proof: bool,
    pub unconfirmed_grant: bool,
    pub offered_here: bool,
    pub joined_here: bool,
    pub declined: bool,
    pub grant_refused: Option<String>,
}

/// Pure. A peer that already holds another identity is the EXTERNAL notice's
/// case (`external_notice_applies`), not this one.
pub fn enrolment_outcome(i: EnrolOutcomeInputs) -> EnrolOutcome {
    if i.owner_asked_own && !i.certified_here && !i.already_same_owner && !i.peer_presented_cert {
        // A browser has no device key to offer, so "no offer" is its normal
        // outcome, not a failed enrolment. Only the explicit browser marker
        // earns this; a missing or malformed key offer from any other peer
        // stays the failure below.
        if i.peer_is_browser && !i.offer_seen && !i.offer_failed_proof && !i.joined_here {
            return EnrolOutcome::OwnerBrowserNotFleet;
        }
        return EnrolOutcome::OwnerNotEnrolled {
            offer_seen: i.offer_seen,
            failed_proof: i.offer_failed_proof,
        };
    }
    if i.certified_here && i.unconfirmed_grant {
        return EnrolOutcome::OwnerUnconfirmed;
    }
    if i.offered_here && !i.joined_here {
        if let Some(why) = i.grant_refused {
            return EnrolOutcome::DeviceGrantRefused(why);
        }
        if !i.declined {
            return EnrolOutcome::DeviceNoAnswer;
        }
    }
    EnrolOutcome::Fine
}

/// Whether this signal is the browser's explicit device-kind hint. The hint is
/// advisory and unauthenticated (it arrives before PAKE); it is used ONLY to
/// word the outcome of a completed pairing, never to admit a device. `direct`
/// alone is a transport fact, not a kind: a native peer may run without direct.
/// Pure.
pub fn browser_hint(data: &Value) -> bool {
    data["type"].as_str() == Some("transport-hint")
        && data["client"].as_str() == Some("browser")
}
