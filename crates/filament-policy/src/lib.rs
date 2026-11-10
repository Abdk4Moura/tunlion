//! The pure transfer-admission decision.
//!
//! This is the host-free slice of `filament-cap`'s capability policy. It
//! answers exactly one question — may this transfer proceed? — from facts the
//! caller has already established: the capability outcome, certificate
//! revocation/expiry, binding strength, identity state, local deny, fleet
//! facts, and the current time.
//!
//! ## Boundary
//!
//! Nothing here touches a filesystem, runtime, socket, TLS stack, key material
//! or clock. `now` is an explicit input to [`TransferGateInput`], and expiry is
//! evaluated against it. That is deliberate: the same decision must be
//! replayable in a native unit test and in a browser. `filament-cap` re-exports
//! these items under their original `filament_cap::capability::*` paths and
//! keeps the one wall-clock wrapper (`cap_authorize_expired`) for callers that
//! do not supply time themselves.
//!
//! ## What this is not
//!
//! Calling this from a browser does not by itself end the browser's
//! pairwise-only trust model. It moves one decision onto shared code so a
//! later change can be made once. The browser still has to be wired to this
//! surface, and the surrounding identity/transport facts still have to be
//! established there.

#![forbid(unsafe_code)]

/// The transfer capability name. Kept here because the policy compares action
/// names; `filament-cap` re-exports it so existing paths are unchanged.
pub const CAP_TRANSFER: &str = "transfer";

/// The outcome of a capability query at a gate. Unlike `Decision`, it separates
/// an ABSENT header (the resource is UNPROVISIONED) from a header that EXISTS
/// and refused (`Denied`, a real disagreement). Absent means "provision this
/// node"; denied means "the grants disagree". Conflating them floods the shadow
/// log and makes the flip criterion unsatisfiable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapOutcome {
    Authorized,
    Denied(String),
    Unprovisioned,
}

/// How strongly the link's identity is bound to a device certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingStrength {
    None,
    Proven,
    Inferred,
}

/// The identity fact a link carries at gate time.
///
/// `Pending` and `Resolved` are the ordering states the #161 probe guards: a
/// legacy-trusted open must never be decided while identity resolution is
/// merely unfinished. `ExplicitlyUnavailableAnonymous` is different in kind:
/// the peer answered our possession challenge with `identity-unavailable`
/// AFTER a one-time code ceremony or an explicit local transfer consent
/// (`-y`/daemon room acceptance) selected it, so the absence of a certificate
/// is a fact, not a race. Only a transfer consents to that class; every other
/// action remains denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityState {
    /// Not resolved yet, or the peer never answered. Fail closed: hold, then
    /// deny, rather than decide with revocation unknowable.
    #[default]
    Pending,
    /// The link carries a device certificate (Inferred or Proven).
    Resolved,
    /// The peer explicitly said it holds no certificate, after the one-time
    /// code ceremony or the operator's explicit room consent selected it. That
    /// consent is the authority; revocation cannot be consulted because there
    /// is no device identity to consult.
    ExplicitlyUnavailableAnonymous,
}

/// A same-owner device with a proven certificate and an in-bounds action is
/// auto-trusted; a revocation disables that trust independently of every other
/// input.
pub fn fleet_auto_trust(
    same_owner: bool,
    binding: BindingStrength,
    scoped_in_bounds: bool,
    cert_not_revoked: bool,
) -> bool {
    same_owner && binding == BindingStrength::Proven && scoped_in_bounds && cert_not_revoked
}

/// Why a transfer was refused. Structured instead of a bare string so the
/// adapter that owns the wording (CLI refusal messages, Core status text) can
/// render it without re-deciding the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferDeny {
    Revoked,
    Denied,
    Ceiling,
    Expired { at: u64 },
    AnonymousOutOfBounds,
    AnonymousNoConsent,
    FleetNeedsGrant,
    Unauthorized(String),
    /// Shadow mode refused a legacy-denied open with no capability reason to
    /// name. The effective decision is Deny with no operator reason.
    ShadowLegacy,
}

impl TransferDeny {
    pub fn reason(&self) -> Option<String> {
        match self {
            TransferDeny::Revoked => Some("device revoked".into()),
            TransferDeny::Denied => Some("explicitly denied by owner (deniedCaps)".into()),
            TransferDeny::Ceiling => {
                Some("this capability is outside the device's invitation ceiling".into())
            }
            TransferDeny::Expired { at } => Some(format!("access expired at {at}")),
            TransferDeny::AnonymousOutOfBounds => Some(
                "anonymous code transfer must land inside the receiver's inbox".into(),
            ),
            TransferDeny::AnonymousNoConsent => {
                Some("anonymous code peer has no transfer consent".into())
            }
            TransferDeny::FleetNeedsGrant => Some(
                "fleet device: action needs an explicit grant (deliberate tier or out of scope)"
                    .into(),
            ),
            TransferDeny::Unauthorized(reason) => {
                if reason.is_empty() {
                    Some("transfer not authorized".into())
                } else {
                    Some(reason.clone())
                }
            }
            TransferDeny::ShadowLegacy => None,
        }
    }
}

/// One transfer decision, plus the observability facts the CLI's counters and
/// shadow log need. The policy is entirely here; adapters only render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferDecision {
    pub allowed: bool,
    pub deny: Option<TransferDeny>,
    /// The post-compose capability outcome (same-owner fleet recomputation and
    /// the proven/expired composers applied). Counter bucketing uses this.
    pub observable_outcome: CapOutcome,
    pub fleet_ok: bool,
    pub ceiling_ok: bool,
}

impl TransferDecision {
    fn allow(observable_outcome: CapOutcome, fleet_ok: bool, ceiling_ok: bool) -> Self {
        Self {
            allowed: true,
            deny: None,
            observable_outcome,
            fleet_ok,
            ceiling_ok,
        }
    }
    fn deny(
        deny: TransferDeny,
        observable_outcome: CapOutcome,
        fleet_ok: bool,
        ceiling_ok: bool,
    ) -> Self {
        Self {
            allowed: false,
            deny: Some(deny),
            observable_outcome,
            fleet_ok,
            ceiling_ok,
        }
    }
    pub fn allowed(&self) -> bool {
        self.allowed
    }
    pub fn deny_reason(&self) -> Option<String> {
        self.deny.as_ref().and_then(TransferDeny::reason)
    }
}

/// Explicit inputs for the single transfer policy. `same_owner` is the
/// certificate-derived fact (`own_user_pub == peer user_pub`), never a claimed
/// name. `now` is seconds since the epoch and is the ONLY clock the policy
/// reads.
pub struct TransferGateInput<'a> {
    pub authoritative: bool,
    pub legacy_allowed: bool,
    pub outcome: &'a CapOutcome,
    pub cert_revoked: bool,
    pub denied: bool,
    pub auth_key_caps: Option<&'a [String]>,
    pub cert_expires: Option<u64>,
    pub now: u64,
    pub same_owner: bool,
    pub binding: BindingStrength,
    pub scoped_in_bounds: bool,
    pub has_explicit_grant: bool,
    pub ceiling_authorizes: bool,
    pub identity_state: IdentityState,
}

/// THE transfer allow/deny policy. CLI, Core and any future client must call
/// this instead of composing their own transfer gate. (The pre-existing
/// `transfer_gate_decision` in `filament-cap` is the renderer for a finished
/// GateDecision, not a policy.)
pub fn transfer_decision(input: &TransferGateInput<'_>) -> TransferDecision {
    let TransferGateInput {
        authoritative,
        legacy_allowed,
        outcome,
        cert_revoked,
        denied,
        auth_key_caps,
        cert_expires,
        now,
        same_owner,
        binding,
        scoped_in_bounds,
        has_explicit_grant,
        ceiling_authorizes,
        identity_state,
    } = *input;

    // An explicitly anonymous peer answered identity-unavailable after the
    // ceremony/consent selected it. It has no key to revoke, and the consent
    // authorizes a bounded transfer only.
    if identity_state == IdentityState::ExplicitlyUnavailableAnonymous {
        if cert_revoked {
            return TransferDecision::deny(
                TransferDeny::Revoked,
                outcome.clone(),
                false,
                false,
            );
        }
        if denied {
            return TransferDecision::deny(
                TransferDeny::Denied,
                outcome.clone(),
                false,
                false,
            );
        }
        if !scoped_in_bounds {
            return TransferDecision::deny(
                TransferDeny::AnonymousOutOfBounds,
                outcome.clone(),
                false,
                false,
            );
        }
        return if legacy_allowed {
            TransferDecision::allow(outcome.clone(), false, false)
        } else {
            TransferDecision::deny(
                TransferDeny::AnonymousNoConsent,
                outcome.clone(),
                false,
                false,
            )
        };
    }

    if cert_revoked {
        return TransferDecision::deny(TransferDeny::Revoked, outcome.clone(), false, false);
    }

    // A delegated principal's composed deadline is absolute in both modes.
    if auth_key_caps.is_some() {
        if let Some(at) = cert_expires {
            if now >= at {
                return TransferDecision::deny(
                    TransferDeny::Expired { at },
                    outcome.clone(),
                    false,
                    false,
                );
            }
        }
    }

    if let Some(caps) = auth_key_caps {
        if !caps.iter().any(|c| c.eq_ignore_ascii_case(CAP_TRANSFER)) {
            return TransferDecision::deny(TransferDeny::Ceiling, outcome.clone(), false, false);
        }
    }

    if denied {
        return TransferDecision::deny(TransferDeny::Denied, outcome.clone(), false, false);
    }

    let fleet_ok = fleet_auto_trust(same_owner, binding, scoped_in_bounds, !cert_revoked);
    let ceiling_ok =
        ceiling_authorizes && same_owner && binding == BindingStrength::Proven && !cert_revoked;
    let base_outcome = if same_owner {
        if fleet_ok || ceiling_ok || has_explicit_grant {
            CapOutcome::Authorized
        } else {
            CapOutcome::Denied(
                "fleet device: action needs an explicit grant (deliberate tier or out of scope)"
                    .into(),
            )
        }
    } else {
        outcome.clone()
    };
    let composed = cap_authorize_proven(&base_outcome, binding, authoritative);
    let composed = cap_authorize_expired_at(&composed, cert_expires, authoritative, now);
    let fleet_allow = !denied
        && (fleet_ok || (authoritative && ceiling_ok))
        && matches!(
            cap_authorize_expired_at(&CapOutcome::Authorized, cert_expires, true, now),
            CapOutcome::Authorized
        );
    let effective = fleet_allow
        || if authoritative {
            matches!(composed, CapOutcome::Authorized)
        } else {
            legacy_allowed
        };
    if effective {
        return TransferDecision::allow(composed, fleet_ok, ceiling_ok);
    }
    if authoritative {
        let reason = match &composed {
            CapOutcome::Denied(reason) => reason.clone(),
            CapOutcome::Unprovisioned => {
                "resource unprovisioned (no capability header); run tunlion grant/init".to_string()
            }
            CapOutcome::Authorized => String::new(),
        };
        TransferDecision::deny(
            TransferDeny::Unauthorized(reason),
            composed,
            fleet_ok,
            ceiling_ok,
        )
    } else {
        TransferDecision::deny(
            TransferDeny::ShadowLegacy,
            composed,
            fleet_ok,
            ceiling_ok,
        )
    }
}

/// Purely restrictive: under authoritative, downgrades Authorized→Denied when
/// binding is not Proven. Denied/Unprovisioned pass through; shadow passes through.
pub fn cap_authorize_proven(
    outcome: &CapOutcome,
    binding: BindingStrength,
    authoritative: bool,
) -> CapOutcome {
    if !authoritative || binding == BindingStrength::Proven {
        return outcome.clone();
    }
    match outcome {
        CapOutcome::Authorized => CapOutcome::Denied("identity not proven".into()),
        _ => outcome.clone(),
    }
}

/// Purely restrictive expiry composer with the clock made explicit.
///
/// `now` is the same seconds-since-epoch value the gate was called with. The
/// wall-clock wrapper `filament_cap::capability::cap_authorize_expired` stays in
/// `filament-cap` for callers that compose the policy without supplying time.
pub fn cap_authorize_expired_at(
    outcome: &CapOutcome,
    cert_expires: Option<u64>,
    authoritative: bool,
    now: u64,
) -> CapOutcome {
    if !authoritative {
        return outcome.clone();
    }
    let expired = match cert_expires {
        None => true,
        Some(exp) => now >= exp,
    };
    if expired {
        match outcome {
            CapOutcome::Authorized => CapOutcome::Denied("cert expired".into()),
            _ => outcome.clone(),
        }
    } else {
        outcome.clone()
    }
}
