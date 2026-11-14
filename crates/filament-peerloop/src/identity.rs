//! Peer identity resolution: what a link PROVED, applied to the link.
//!
//! This function used to live in `cli/src/identity_lifecycle.rs`, next to the
//! challenge/response machinery. It operates on `Link`, and the only host facts
//! it needs (the stored certificate, the persisted principal record, the
//! ceiling, the clock) are read through the link's injected `HostServices`, so
//! it moves with `Link` rather than staying behind.
//!
//! The precedence rule and both fail-closed branches are unchanged.

use crate::conn::Link;
use crate::host::HostServices;
use filament_cap::capability::{BindingStrength, IdentityState, PrincipalKind};

/// Populate link identity from the peer's stored device cert, if the
/// link already has a proof-verified name but identity pubkeys are absent.
/// Cached back onto the link on first successful resolution (resolve-once,
/// not per open).
///
/// The binding model: `verified_name` is set ONLY after a session-bound
/// pair-proof HMAC (proof_for over shared secret + UIDs + fingerprints),
/// so the name is cryptographically bound to this link. `device_cert_for`
/// returns the cert we already verified at pairing (provisional_promote_ok
/// checked device_pub against the overlay transport key at storage time).
/// Together these form a sufficient trust join: a proven name plus the
/// cert trusted-for-that-name. No additional link-level cert-to-transport
/// comparison is needed.
///
/// Fail-closed on: no verified_name, no stored cert, cert expired or
/// otherwise invalid. For a DELEGATED peer "fail closed" cannot be a bare
/// `return`: see `pin_delegated_denied`.
pub fn resolve_peer_identity(link: &mut Link) {
    // Precedence rule: a Proven binding must NOT be downgraded to Inferred.
    // The identity-expose handler (possession-sig) sets Proven, and this
    // function (symmetric-secret proof + name->cert lookup) sets Inferred.
    // An Inferred MAY later be upgraded to Proven by identity-expose.
    if link.identity_device_pub.is_some() || link.identity_user_pub.is_some() {
        link.identity_state = IdentityState::Resolved;
        return; // already resolved (any binding, Proven or Inferred, stays)
    }
    let name = match &link.verified_name {
        Some(n) => n.clone(),
        None => return, // no proven name, nothing to resolve
    };
    let host = link.host.clone();
    let now = host.now_secs();
    let Some(cert) = host.device_cert_for(&name) else {
        pin_delegated_denied(link, &name, &*host);
        return;
    };
    if cert.verify(now).is_err() {
        pin_delegated_denied(link, &name, &*host);
        // An INVITED device whose certificate ran out has ended, and the gate
        // must be able to say so. Leaving the link with no identity made every
        // refusal read "outside the device's invitation ceiling" (the pinned
        // empty ceiling), which sent the user to widen a ceiling that was fine.
        // The key is the record's own, so this names who the link is without
        // trusting anything the peer said; binding stays unproven.
        if host.principal_ceiling_for(&name).is_some() {
            link.identity_device_pub = Some(cert.device_pub);
            link.identity_user_pub = Some(cert.user_pub);
            link.identity_cert_expires = Some(cert.expires);
            link.identity_state = IdentityState::Resolved;
        }
        return;
    }
    link.identity_device_pub = Some(cert.device_pub);
    link.identity_user_pub = Some(cert.user_pub);
    link.identity_binding = BindingStrength::Inferred;
    link.identity_state = IdentityState::Resolved;
    let principal = host.persisted_principal_for_cert(&cert);
    let deadline = host.principal_deadline(
        cert.expires,
        principal.not_after,
        principal.last_seen,
        principal.max_offline,
    );
    link.identity_cert_expires = Some(deadline);
    // A delegated principal runs on three clocks: cert expiry, an absolute stop
    // time, and an offline budget. `principal_deadline` composes them, and
    // `cap_gate_effective` composes `identity_cert_expires` into the outcome,
    // but that composer is a no-op while the capability engine is in SHADOW
    // mode, where the effective decision is the legacy one. The ceiling is the
    // only thing enforcing a delegated principal in shadow, so a passed deadline
    // has to empty the ceiling here (#272).
    link.principal_kind = principal_after_liveness(principal.kind, deadline > now);
}

/// The principal a link must carry once liveness is known. `alive` is whether
/// the peer's certificate verifies AND its composed deadline is still ahead.
///
/// A delegated principal that is not alive collapses to an EMPTY ceiling, which
/// denies every action, because an empty `auth_key_caps` matches no action in
/// `cap_gate_effective`. An owner device passes through unchanged: owner cert
/// semantics are a separate question and this is not the place to answer it.
///
/// Pure on purpose. The bug this closes (#272) lived in the one branch that had
/// no test, so the branch is now reachable without a `Link` or a config dir.
pub fn principal_after_liveness(stored: PrincipalKind, alive: bool) -> PrincipalKind {
    match stored {
        PrincipalKind::Delegated { .. } if !alive => {
            PrincipalKind::Delegated { caps: Vec::new() }
        }
        other => other,
    }
}

/// The principal a link carries once a possession proof (`identity-expose`)
/// lands on it, or `None` when the proof must be refused.
///
/// A link the fleet hello already admitted as a SIBLING keeps that kind when
/// the proof names the same device key. The persisted principal cannot stand
/// in for it: a sibling's index record carries no principal kind, which reads
/// back as an owner device, and a sibling relabelled that way is no longer
/// governed by the sibling rules (the cut-on-revocation sweep, the transfer
/// scope). A proof naming a DIFFERENT key than the admitted one is refused:
/// one link cannot be two devices.
///
/// Every other link takes the persisted principal, after liveness, exactly as
/// before. Pure, so the decision is testable without a `Link`.
pub fn principal_after_proof(
    current: &PrincipalKind,
    admitted_device: Option<&[u8; 32]>,
    proven_device: &[u8; 32],
    persisted: PrincipalKind,
    alive: bool,
) -> Option<PrincipalKind> {
    if matches!(current, PrincipalKind::FleetSibling) {
        return match admitted_device {
            Some(k) if k == proven_device => Some(PrincipalKind::FleetSibling),
            Some(_) => None,
            // Admission always records the key; a sibling without one is not a
            // state admission produces. Fail closed to a ceiling that denies.
            None => Some(PrincipalKind::Delegated { caps: Vec::new() }),
        };
    }
    Some(principal_after_liveness(persisted, alive))
}

#[cfg(test)]
mod proof_principal_tests {
    use super::*;

    #[test]
    fn a_proof_keeps_an_admitted_sibling_a_sibling_and_others_unchanged() {
        let k = [7u8; 32];
        let other = [8u8; 32];
        // The decision point: a sibling's record reads back as OwnerDevice, and
        // that must NOT replace the sibling admission for the same key.
        assert_eq!(
            principal_after_proof(
                &PrincipalKind::FleetSibling,
                Some(&k),
                &k,
                PrincipalKind::OwnerDevice,
                true
            ),
            Some(PrincipalKind::FleetSibling)
        );
        // A different key on an admitted sibling link is refused outright.
        assert_eq!(
            principal_after_proof(
                &PrincipalKind::FleetSibling,
                Some(&k),
                &other,
                PrincipalKind::OwnerDevice,
                true
            ),
            None
        );
        // Positive controls: a non-sibling link takes the persisted principal,
        // and an expired delegated one still collapses to an empty ceiling.
        assert_eq!(
            principal_after_proof(
                &PrincipalKind::OwnerDevice,
                None,
                &k,
                PrincipalKind::OwnerDevice,
                true
            ),
            Some(PrincipalKind::OwnerDevice)
        );
        assert_eq!(
            principal_after_proof(
                &PrincipalKind::OwnerDevice,
                None,
                &k,
                PrincipalKind::Delegated { caps: vec!["transfer".into()] },
                false
            ),
            Some(PrincipalKind::Delegated { caps: Vec::new() })
        );
    }
}

/// Pin a DELEGATED peer to a ceiling-less principal, which denies every action.
/// A no-op for an owner device, whose semantics are unchanged.
///
/// This is what "fail closed" has to mean on the resolver's early-return paths.
/// A bare `return` was not it (#272): a `Link` is constructed with
/// `PrincipalKind::OwnerDevice`, and `auth_key_caps()` returns None for an
/// owner device, so the ceiling check in `cap_gate_effective` is skipped
/// entirely. Leaving the principal untouched therefore left an expired guest
/// owner-equivalent, and the same guest was refused MORE while its certificate
/// was still valid. Measured: a transfer-only guest whose cert had expired
/// opened a TCP connection to an arbitrary port on the owner's loopback, which
/// it could not do three minutes earlier.
fn pin_delegated_denied(link: &mut Link, name: &str, host: &dyn HostServices) {
    if let Some(caps) = host.principal_ceiling_for(name) {
        link.principal_kind =
            principal_after_liveness(PrincipalKind::Delegated { caps }, false);
    }
}
