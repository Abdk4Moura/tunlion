//! Certificate renewal: the mechanism that makes expiry a real bound.
//!
//! WHY THIS EXISTS. `docs/design-pairing-ux.md` rule 2 is the security model:
//! there is no global revocation, so expiry is the only bound, fleet certs are
//! short, and removing a device is "stop renewing". Renewal IS
//! revocation-without-propagation: a pull model that works offline and needs
//! nothing to reach a thief.
//!
//! None of it was built. `DeviceCert::certify` is reached only from init,
//! recover, enrollment/join and pairing, so certs were issued once, for 90 days,
//! and never refreshed. #236 found the UI promising "renews in 87d" and fixed
//! the SENTENCE, leaving the model unimplemented. That left both halves broken
//! at once: devices silently fall off the mesh when their cert lapses, and a
//! removed device keeps full fleet trust until its long cert runs out.
//!
//! THE RULE-2 / RULE-3 TENSION, resolved deliberately. Rule 2 wants renewal
//! automatic. Rule 3 says signing requires a human at the primary, "no ambient
//! or remote signing path, ever". Those collide only if renewal is treated as
//! signing a NEW trust relationship. It is not: renewal re-signs a device the
//! owner already admitted, with the same key and the same ceiling, moving only
//! the clock. The human decision is the negative one, and withholding it is
//! what removes the device. So this module will renew a device in good standing
//! and will NEVER admit one:
//!
//!   - absent record  -> refuse. Removal is exactly "stop renewing", so a
//!                       device with no record must not be able to talk its way
//!                       back in.
//!   - revoked        -> refuse, terminally. Same as `enrollment_refusal`.
//!   - lapsed         -> refuse. This is where renewal DIVERGES from enrollment
//!                       on purpose: a fresh invitation revives a lapsed device
//!                       because a human issued it. Renewal has no human in the
//!                       loop, so letting it revive a lapsed device would create
//!                       the ambient signing path rule 3 forbids. Renewal
//!                       continues good standing; it cannot restore it.
//!   - key mismatch   -> refuse. The presented key must be the enrolled key.

use anyhow::{bail, Result};

use crate::identity::DeviceCert;

/// What the owner knows about the requesting device, lifted out of the JSON
/// record so the decision below is pure and testable without a config dir.
#[derive(Debug, Clone, Default)]
pub struct Standing {
    /// A record for this device_pub exists at all.
    pub known: bool,
    /// `certRevoked` or `principalState == "revoked"`.
    pub revoked: bool,
    /// `principalState == "lapsed"`.
    pub lapsed: bool,
    /// The device_pub actually stored on that record.
    pub stored_device_pub: Option<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Re-sign, same key and ceiling, new clock.
    Renew,
    /// Do not sign. The string is shown to the operator, never to the peer:
    /// a refusal that explains itself to an untrusted caller is a probe oracle.
    Refuse(&'static str),
}

/// The owner's half. Pure: no filesystem, no clock, no network.
pub fn owner_decides(standing: &Standing, presented_device_pub: [u8; 32]) -> Decision {
    if !standing.known {
        return Decision::Refuse("no record for this device; removal is 'stop renewing'");
    }
    if standing.revoked {
        return Decision::Refuse("device is revoked, which is terminal");
    }
    if standing.lapsed {
        return Decision::Refuse(
            "device has lapsed; reviving it needs a fresh invitation from a human",
        );
    }
    match standing.stored_device_pub {
        Some(stored) if stored == presented_device_pub => Decision::Renew,
        Some(_) => Decision::Refuse("presented device key is not the enrolled key"),
        None => Decision::Refuse("record carries no device key to match against"),
    }
}

/// Renew when less than a third of the lifetime remains.
///
/// A THIRD, not "nearly expired": the device must get many chances to reach a
/// primary before it falls out, or a laptop that is closed at the wrong moment
/// is evicted for being asleep rather than for being untrusted. With the design's
/// short certs this still means renewal traffic is rare.
///
/// Not-yet-due is not an error; it is the common case, and asking early every
/// tick would turn renewal into a self-inflicted load.
pub fn renewal_due(cert: &DeviceCert, now: u64) -> bool {
    let lifetime = cert.expires.saturating_sub(cert.issued);
    if lifetime == 0 {
        // A degenerate cert cannot be reasoned about with a fraction. Treat it
        // as due rather than never-due: failing toward asking is recoverable,
        // failing toward silence is the bug this module exists to fix.
        return true;
    }
    let remaining = cert.expires.saturating_sub(now);
    remaining * 3 <= lifetime
}

/// The lifetime a renewal may grant: the one the current certificate already
/// has, never more.
///
/// NOT the global default. A device invited with `--expires 1h` carries a
/// one-hour certificate on purpose, and re-signing it for the 90-day default
/// would let renewal quietly widen the very bound it exists to enforce: a
/// short-lived guest would become a permanent member by doing nothing but
/// staying connected. Renewal moves the clock forward by the same amount the
/// owner originally chose.
///
/// Clamped to `max_ttl` so a corrupt or hostile stored cert cannot mint an
/// unbounded one, and floored at one second so a degenerate cert still produces
/// a cert that is strictly later than its predecessor.
pub fn renewal_ttl(current: &DeviceCert, max_ttl: u64) -> u64 {
    let original = current.expires.saturating_sub(current.issued);
    original.clamp(1, max_ttl)
}

/// The requesting device's half: is this replacement acceptable?
///
/// Renewal MUST NOT WIDEN ANYTHING. Only the clock may move. A renewal that can
/// change the device key would let a compromised primary silently rebind the
/// identity, and one that can change the user key would let any signer take the
/// device over, which is the whole trust root.
pub fn accept_renewal(
    old: &DeviceCert,
    new: &DeviceCert,
    owner_pub: &[u8; 32],
    now: u64,
) -> Result<()> {
    if new.device_pub != old.device_pub {
        bail!("renewal changed the device key");
    }
    if new.user_pub != old.user_pub {
        bail!("renewal changed the owner key");
    }
    if new.user_pub != *owner_pub {
        bail!("renewal is signed by a different owner than the one we trust");
    }
    if new.expires <= old.expires {
        // Also blocks a REPLAY of an older cert, which would otherwise be a
        // free downgrade back toward expiry.
        bail!("renewal does not extend the certificate");
    }
    // Signature and not-expired, against the owner key we already trust.
    new.verify_chain(owner_pub, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::UserKey;

    const DEV: [u8; 32] = [7u8; 32];
    const OTHER: [u8; 32] = [9u8; 32];

    fn good() -> Standing {
        Standing { known: true, revoked: false, lapsed: false, stored_device_pub: Some(DEV) }
    }

    #[test]
    fn a_device_in_good_standing_renews() {
        assert_eq!(owner_decides(&good(), DEV), Decision::Renew);
    }

    /// Removal is "stop renewing", so this is the whole removal mechanism. If an
    /// unknown device could renew, nothing the owner does would ever evict it.
    #[test]
    fn a_removed_device_cannot_renew_its_way_back_in() {
        let gone = Standing { known: false, ..good() };
        assert!(matches!(owner_decides(&gone, DEV), Decision::Refuse(_)));
    }

    #[test]
    fn a_revoked_device_is_refused_terminally() {
        let revoked = Standing { revoked: true, ..good() };
        assert!(matches!(owner_decides(&revoked, DEV), Decision::Refuse(_)));
    }

    /// The rule-2/rule-3 seam. Enrollment revives a lapsed device because a human
    /// issued a fresh invitation. Renewal has no human in it, so if renewal could
    /// revive, "no ambient signing path" would be false: a device that fell out
    /// while an attacker held it would quietly re-admit itself.
    #[test]
    fn renewal_cannot_revive_a_lapsed_device_even_though_enrollment_can() {
        let lapsed = Standing { lapsed: true, ..good() };
        assert!(matches!(owner_decides(&lapsed, DEV), Decision::Refuse(_)));
    }

    #[test]
    fn a_different_key_cannot_renew_someone_elses_record() {
        assert!(matches!(owner_decides(&good(), OTHER), Decision::Refuse(_)));
    }

    #[test]
    fn due_only_in_the_last_third_of_the_lifetime() {
        let cert = DeviceCert {
            device_pub: DEV,
            user_pub: OTHER,
            issued: 0,
            expires: 300,
            sig: [0u8; 64],
        };
        assert!(!renewal_due(&cert, 0), "fresh cert is not due");
        assert!(!renewal_due(&cert, 100), "two thirds left is not due");
        assert!(renewal_due(&cert, 200), "one third left is due");
        assert!(renewal_due(&cert, 299), "nearly expired is due");
    }

    /// Failing toward "ask" is recoverable; failing toward "never ask" is the
    /// silent-death bug this module exists to fix.
    #[test]
    fn a_degenerate_lifetime_is_due_rather_than_never_due() {
        let cert =
            DeviceCert { device_pub: DEV, user_pub: OTHER, issued: 5, expires: 5, sig: [0u8; 64] };
        assert!(renewal_due(&cert, 5));
    }

    fn pair(uk: &UserKey, issued: u64, ttl: u64) -> DeviceCert {
        DeviceCert::certify(uk, DEV, issued, ttl).unwrap()
    }

    /// Deterministic and in-memory: these tests are about the decision rules,
    /// so they must not depend on a config dir or a process-global env var.
    fn key(seed: u8) -> UserKey {
        UserKey::from_seed(&[seed; 32]).unwrap()
    }

    /// The bound renewal exists to enforce must not be widened BY renewing.
    #[test]
    fn renewal_keeps_the_lifetime_the_owner_originally_chose() {
        let hour = DeviceCert {
            device_pub: DEV,
            user_pub: OTHER,
            issued: 1_000,
            expires: 1_000 + 3_600,
            sig: [0u8; 64],
        };
        assert_eq!(
            renewal_ttl(&hour, 90 * 24 * 3600),
            3_600,
            "a one-hour guest must not renew into a 90-day member"
        );
    }

    #[test]
    fn renewal_lifetime_is_clamped_and_never_zero() {
        let absurd = DeviceCert {
            device_pub: DEV,
            user_pub: OTHER,
            issued: 0,
            expires: u64::MAX,
            sig: [0u8; 64],
        };
        assert_eq!(renewal_ttl(&absurd, 1_000), 1_000, "clamped to the maximum");
        let degenerate =
            DeviceCert { device_pub: DEV, user_pub: OTHER, issued: 5, expires: 5, sig: [0u8; 64] };
        assert_eq!(renewal_ttl(&degenerate, 1_000), 1, "never zero");
    }

    #[test]
    fn a_longer_certificate_from_the_same_owner_is_accepted() {
        let uk = key(1);
        let owner = uk.public_key_bytes();
        let old = pair(&uk, 1_000, 1_000);
        let new = pair(&uk, 1_500, 1_000);
        accept_renewal(&old, &new, &owner, 1_600).expect("same owner, later expiry");
    }

    /// A renewal that may rebind the device key is a silent identity takeover.
    #[test]
    fn renewal_may_not_change_the_device_key() {
        let uk = key(1);
        let owner = uk.public_key_bytes();
        let old = pair(&uk, 1_000, 1_000);
        let new = DeviceCert::certify(&uk, OTHER, 1_500, 1_000).unwrap();
        assert!(accept_renewal(&old, &new, &owner, 1_600).is_err());
    }

    /// The trust root. If another signer could "renew" us, pairing means nothing.
    #[test]
    fn a_stranger_cannot_renew_our_certificate() {
        let mine = key(2);
        let attacker = key(3);
        let owner = mine.public_key_bytes();
        let old = pair(&mine, 1_000, 1_000);
        let forged = pair(&attacker, 1_500, 1_000);
        assert!(accept_renewal(&old, &forged, &owner, 1_600).is_err());
    }

    /// Replaying an older cert would be a free downgrade back toward expiry.
    #[test]
    fn an_older_certificate_cannot_replace_a_newer_one() {
        let uk = key(1);
        let owner = uk.public_key_bytes();
        let new = pair(&uk, 1_500, 1_000);
        let old = pair(&uk, 1_000, 1_000);
        assert!(accept_renewal(&new, &old, &owner, 1_600).is_err());
    }
}
