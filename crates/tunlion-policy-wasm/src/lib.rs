//! Browser-facing JSON bridge to the one shared transfer-admission policy.
//!
//! `admitTransfer(input)` is the entire surface: both sides are JSON strings.
//! The decision itself is [`filament_policy::transfer_decision`]; this crate
//! only translates the wire shape and renders the structured result. It has no
//! crypto and reads no clock: `now` is required in the input, so the same
//! vectors can be replayed natively and in a browser.
//!
//! The native Rust function [`admit_transfer`] is the implementation used by
//! the wasm export. The JS name is defined once, in the cfg-gated module below.

use filament_policy::{
    BindingStrength, CapOutcome, IdentityState, TransferDeny, TransferDecision, TransferGateInput,
    transfer_decision,
};
use serde::{Deserialize, Serialize};

/// Capability outcome on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Outcome {
    Authorized,
    Denied { reason: String },
    Unprovisioned,
}

/// Link binding strength on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Binding {
    None,
    Proven,
    Inferred,
}

/// Identity ordering state on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Identity {
    Pending,
    Resolved,
    ExplicitlyUnavailableAnonymous,
}

/// Structured denial on the wire. `kind` names the variant; `at`/`reason` are
/// present only where the policy carries them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Deny {
    Revoked,
    Denied,
    Ceiling,
    Expired { at: u64 },
    AnonymousOutOfBounds,
    AnonymousNoConsent,
    FleetNeedsGrant,
    Unauthorized { reason: String },
    ShadowLegacy,
}

/// The complete input. Every field is required: there are no defaults, so a
/// caller cannot omit `now` or an identity fact and get a decision anyway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmitTransferInput {
    pub authoritative: bool,
    pub legacy_allowed: bool,
    pub outcome: Outcome,
    pub cert_revoked: bool,
    pub denied: bool,
    pub auth_key_caps: Option<Vec<String>>,
    pub cert_expires: Option<u64>,
    /// Seconds since the epoch. The policy reads no other clock.
    pub now: u64,
    pub same_owner: bool,
    pub binding: Binding,
    pub scoped_in_bounds: bool,
    pub has_explicit_grant: bool,
    pub ceiling_authorizes: bool,
    pub identity_state: Identity,
}

/// The complete decision, including the observability facts native counters
/// consume. JSON field order follows this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmitTransferOutput {
    pub allowed: bool,
    pub deny: Option<Deny>,
    pub deny_reason: Option<String>,
    pub observable_outcome: Outcome,
    pub fleet_ok: bool,
    pub ceiling_ok: bool,
}

impl Outcome {
    fn to_policy(&self) -> CapOutcome {
        match self {
            Outcome::Authorized => CapOutcome::Authorized,
            Outcome::Denied { reason } => CapOutcome::Denied(reason.clone()),
            Outcome::Unprovisioned => CapOutcome::Unprovisioned,
        }
    }

    fn from_policy(outcome: &CapOutcome) -> Self {
        match outcome {
            CapOutcome::Authorized => Outcome::Authorized,
            CapOutcome::Denied(reason) => Outcome::Denied {
                reason: reason.clone(),
            },
            CapOutcome::Unprovisioned => Outcome::Unprovisioned,
        }
    }
}

impl Binding {
    fn to_policy(self) -> BindingStrength {
        match self {
            Binding::None => BindingStrength::None,
            Binding::Proven => BindingStrength::Proven,
            Binding::Inferred => BindingStrength::Inferred,
        }
    }
}

impl Identity {
    fn to_policy(self) -> IdentityState {
        match self {
            Identity::Pending => IdentityState::Pending,
            Identity::Resolved => IdentityState::Resolved,
            Identity::ExplicitlyUnavailableAnonymous => {
                IdentityState::ExplicitlyUnavailableAnonymous
            }
        }
    }
}

impl Deny {
    fn from_policy(deny: &TransferDeny) -> Self {
        match deny {
            TransferDeny::Revoked => Deny::Revoked,
            TransferDeny::Denied => Deny::Denied,
            TransferDeny::Ceiling => Deny::Ceiling,
            TransferDeny::Expired { at } => Deny::Expired { at: *at },
            TransferDeny::AnonymousOutOfBounds => Deny::AnonymousOutOfBounds,
            TransferDeny::AnonymousNoConsent => Deny::AnonymousNoConsent,
            TransferDeny::FleetNeedsGrant => Deny::FleetNeedsGrant,
            TransferDeny::Unauthorized(reason) => Deny::Unauthorized {
                reason: reason.clone(),
            },
            TransferDeny::ShadowLegacy => Deny::ShadowLegacy,
        }
    }
}

impl AdmitTransferInput {
    /// Evaluate the shared policy. Pure: the only time value is `self.now`.
    pub fn decide(&self) -> AdmitTransferOutput {
        let outcome = self.outcome.to_policy();
        let decision = transfer_decision(&TransferGateInput {
            authoritative: self.authoritative,
            legacy_allowed: self.legacy_allowed,
            outcome: &outcome,
            cert_revoked: self.cert_revoked,
            denied: self.denied,
            auth_key_caps: self.auth_key_caps.as_deref(),
            cert_expires: self.cert_expires,
            now: self.now,
            same_owner: self.same_owner,
            binding: self.binding.to_policy(),
            scoped_in_bounds: self.scoped_in_bounds,
            has_explicit_grant: self.has_explicit_grant,
            ceiling_authorizes: self.ceiling_authorizes,
            identity_state: self.identity_state.to_policy(),
        });
        AdmitTransferOutput::from_decision(&decision)
    }
}

impl AdmitTransferOutput {
    fn from_decision(decision: &TransferDecision) -> Self {
        Self {
            allowed: decision.allowed,
            deny: decision.deny.as_ref().map(Deny::from_policy),
            deny_reason: decision.deny_reason(),
            observable_outcome: Outcome::from_policy(&decision.observable_outcome),
            fleet_ok: decision.fleet_ok,
            ceiling_ok: decision.ceiling_ok,
        }
    }
}

/// JSON-in/JSON-out admission call. Invalid input returns
/// `{"error":"..."}` rather than panicking across the FFI boundary.
pub fn admit_transfer(input: &str) -> String {
    match serde_json::from_str::<AdmitTransferInput>(input) {
        Ok(parsed) => match serde_json::to_string(&parsed.decide()) {
            Ok(output) => output,
            Err(err) => error_json(&err.to_string()),
        },
        Err(err) => error_json(&err.to_string()),
    }
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// The one browser export: JSON string in, JSON string out.
    #[wasm_bindgen(js_name = admitTransfer)]
    pub fn admit_transfer_js(input: &str) -> String {
        super::admit_transfer(input)
    }
}
