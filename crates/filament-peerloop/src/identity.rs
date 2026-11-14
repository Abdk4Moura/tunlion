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

/// What a possession proof (`identity-expose`) is decided on: the link's
/// state BEFORE the proof is applied, and the proof itself.
pub struct ProofFacts<'a> {
    /// The link's principal now (set by admission, or by an earlier proof).
    pub current: &'a PrincipalKind,
    /// The device key the link was admitted on, if any.
    pub admitted_device: Option<&'a [u8; 32]>,
    /// The device key the proof names.
    pub proven_device: &'a [u8; 32],
    /// Is the proven key a recognized sibling: a device record carries it, OR
    /// the owner's roster lists it ([`crate::recv::store::DeviceStore::sibling_recognized`]).
    /// The roster is the authorization fact; the index record is presentation
    /// and may be missing (a failed or refused index write), so it is never
    /// required on its own.
    pub recognized: bool,
    /// The proven certificate's own expiry.
    pub cert_expires: u64,
}

/// The principal, and the deadline for `identity_cert_expires`, a link carries
/// once a possession proof lands on it, or `None` when the proof must be
/// refused.
///
/// A link the fleet hello already admitted as a SIBLING keeps that kind, with
/// its certificate's own expiry, when the proof names the same device key and
/// that key is recognized (recorded, or listed by the owner's roster). The persisted principal cannot stand in for it: a
/// sibling's index record carries no principal kind and reads back as an owner
/// device, and an unrelated record's deadline is not the sibling's. A proof
/// naming a DIFFERENT key than the admitted one is refused: one link cannot be
/// two devices. A sibling with no admitted key, or a key neither recorded nor
/// listed, fails closed to an empty ceiling that has already ended.
///
/// Every other link takes the persisted principal, after liveness, and the
/// persisted (composed) deadline, exactly as before. Pure, so the decision is
/// testable without a `Link`.
pub fn principal_after_proof(
    f: &ProofFacts<'_>,
    persisted: PrincipalKind,
    persisted_deadline: u64,
    now: u64,
) -> Option<(PrincipalKind, u64)> {
    if matches!(f.current, PrincipalKind::FleetSibling) {
        return match f.admitted_device {
            Some(k) if k != f.proven_device => None,
            Some(_) if f.recognized => Some((PrincipalKind::FleetSibling, f.cert_expires)),
            _ => Some((PrincipalKind::Delegated { caps: Vec::new() }, 0)),
        };
    }
    Some((
        principal_after_liveness(persisted, persisted_deadline > now),
        persisted_deadline,
    ))
}

#[cfg(test)]
mod proof_principal_tests {
    use super::*;

    fn facts<'a>(
        current: &'a PrincipalKind,
        admitted: Option<&'a [u8; 32]>,
        proven: &'a [u8; 32],
        recognized: bool,
    ) -> ProofFacts<'a> {
        ProofFacts {
            current,
            admitted_device: admitted,
            proven_device: proven,
            recognized,
            cert_expires: 5_000,
        }
    }

    #[test]
    fn a_proof_keeps_an_admitted_sibling_a_sibling_and_others_unchanged() {
        let k = [7u8; 32];
        let other = [8u8; 32];
        let sib = PrincipalKind::FleetSibling;
        // The decision point: a sibling's record reads back as OwnerDevice with
        // an unrelated deadline; neither replaces the sibling admission, and
        // the deadline is the certificate's own.
        assert_eq!(
            principal_after_proof(&facts(&sib, Some(&k), &k, true), PrincipalKind::OwnerDevice, 0, 100),
            Some((PrincipalKind::FleetSibling, 5_000))
        );
        // A different key on an admitted sibling link is refused outright.
        assert_eq!(
            principal_after_proof(&facts(&sib, Some(&k), &other, true), PrincipalKind::OwnerDevice, 9_000, 100),
            None
        );
        // Positive controls: a non-sibling link takes the persisted principal
        // and deadline, and an expired delegated one still collapses to an
        // empty ceiling.
        let owner = PrincipalKind::OwnerDevice;
        assert_eq!(
            principal_after_proof(&facts(&owner, None, &k, true), PrincipalKind::OwnerDevice, 9_000, 100),
            Some((PrincipalKind::OwnerDevice, 9_000))
        );
        assert_eq!(
            principal_after_proof(
                &facts(&owner, None, &k, true),
                PrincipalKind::Delegated { caps: vec!["transfer".into()] },
                50,
                100
            ),
            Some((PrincipalKind::Delegated { caps: Vec::new() }, 50))
        );
    }

    #[test]
    fn an_unrecognized_sibling_or_one_with_no_admitted_key_fails_closed() {
        let k = [7u8; 32];
        let sib = PrincipalKind::FleetSibling;
        let closed = Some((PrincipalKind::Delegated { caps: Vec::new() }, 0));
        // Neither recorded nor listed: whatever the persisted principal says
        // (an owner device, a live deadline), the link is not kept a sibling
        // and is not owner-equivalent.
        assert_eq!(
            principal_after_proof(&facts(&sib, Some(&k), &k, false), PrincipalKind::OwnerDevice, 9_000, 100),
            closed
        );
        // Admitted without a key: not a state admission produces.
        assert_eq!(
            principal_after_proof(&facts(&sib, None, &k, true), PrincipalKind::OwnerDevice, 9_000, 100),
            closed
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
