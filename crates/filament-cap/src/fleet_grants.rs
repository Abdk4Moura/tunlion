//! Fleet trust: the `FleetSibling` principal and owner-signed grant sets.
//!
//! Two narrow additions to the capability model, both about devices certified
//! by ONE owner key that were never paired with each other (siblings).
//!
//! # The `FleetSibling` kind
//!
//! A sibling's identity is proven by its own owner-signed `DeviceCert`, bound to
//! the live link. It is the owner's device, and it is NOT owner-equivalent: the
//! kind implies exactly one thing, [`FLEET_SIBLING_DEFAULT`] (file transfer into
//! the receiving directory), and nothing else. Shell, exec, forward, mount and
//! routes are never implied, not even the scoped defaults a paired same-owner
//! device gets (forward to an exposed port, read-only mount); each needs an
//! explicit grant. A local deny outranks everything, and revocation or
//! certificate expiry ends all of it at once (the gate's absolute checks; see
//! [`fleet_sibling_inputs`] for how the kind enters the gate).
//!
//! # Owner-signed grant sets
//!
//! A grant made ON the owner device FOR another fleet device (`tunlion grant
//! <subject> <cap> --on <target>`) is signed by the owner key into a set about
//! that one target and pushed to it, like the roster. The rules here decide
//! whether a verified set is accepted ([`judge_grant_set`]) and whether a held
//! set grants something ([`grant_set_allows`]).
//!
//! Why this does not reopen "the cap store has no network write": the set is
//! never written into the capability store. It is a separate, wholly replaced
//! file, consulted only for a `FleetSibling` subject. Only the owner key can
//! author one (a compromised sibling holds no such key, and a set signed by any
//! other key is refused), only for the owner's own fleet (the receiver accepts
//! only its own owner and only a set naming itself as target), and it can never
//! outrank a local deny, revocation or expiry.

use crate::capability::{CAP_MOUNT, CAP_SHELL, CAP_TRANSFER};

/// The authority the `FleetSibling` kind itself implies: transfer, and only
/// transfer. Everything else needs an explicit grant.
pub const FLEET_SIBLING_DEFAULT: &[&str] = &[CAP_TRANSFER];

/// Does the kind itself (no grant) cover `action`?
pub fn sibling_default_covers(action: &str) -> bool {
    FLEET_SIBLING_DEFAULT.iter().any(|a| a.eq_ignore_ascii_case(action))
}

/// Map a gate's raw inputs for a `FleetSibling` link to what the shared gate
/// (`cap_gate_effective`) takes: `(scoped_in_bounds, has_explicit_grant)`.
///
/// * The scoped default is in force for a sibling only for its one implied
///   action, and only within bounds. For any other action it is withheld, so a
///   sibling never inherits a paired device's scoped defaults.
/// * An explicit grant is the receiver's own record grant OR an owner-signed
///   grant about this device. Neither is implied by the kind.
///
/// For a non-sibling every input passes through unchanged. Revocation, cert
/// expiry, binding strength and local denies are not inputs here: the gate
/// applies them absolutely, before and regardless of this mapping.
pub fn fleet_sibling_inputs(
    is_sibling: bool,
    action: &str,
    scoped_in_bounds: bool,
    has_grant: bool,
    local_record_grant: bool,
    owner_grant: bool,
) -> (bool, bool) {
    if !is_sibling {
        return (scoped_in_bounds, has_grant);
    }
    let scoped = scoped_in_bounds && sibling_default_covers(action);
    (scoped, has_grant || local_record_grant || owner_grant)
}

/// The facts of a VERIFIED-SIGNATURE grant set that the accept rule needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantSetHeader {
    pub owner_pub: [u8; 32],
    pub target_pub: [u8; 32],
    pub epoch: u64,
    pub valid_until: u64,
}

/// Why a grant set was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSetRefusal {
    /// The signature does not verify against the key the set names.
    BadSignature,
    /// Signed by a key other than the owner key this device holds.
    OtherOwner,
    /// About another device.
    OtherTarget,
    /// Already past its `valid_until`.
    Expired,
    /// This device's `fleet.owner_grants` is `off`: owner-signed sets are not
    /// accepted at all.
    OwnerGrantsOff,
}

/// The accept rule's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSetJudgement {
    /// Store it, replacing the held one.
    Accept,
    /// Valid but not newer than what is held: a replay, a silent no-op.
    Stale,
    Refuse(GrantSetRefusal),
}

/// Accept a grant set? Pure: `now` and the held `(epoch, valid_until)` are
/// arguments. Every refusal is checked before staleness, so a forged or foreign
/// set is reported as what it is rather than as "old".
pub fn judge_grant_set(
    h: &GrantSetHeader,
    signature_ok: bool,
    my_owner: &[u8; 32],
    my_device: &[u8; 32],
    now: u64,
    held: Option<(u64, u64)>,
) -> GrantSetJudgement {
    use GrantSetJudgement::*;
    if !signature_ok {
        return Refuse(GrantSetRefusal::BadSignature);
    }
    if h.owner_pub != *my_owner {
        return Refuse(GrantSetRefusal::OtherOwner);
    }
    if h.target_pub != *my_device {
        return Refuse(GrantSetRefusal::OtherTarget);
    }
    if h.valid_until <= now {
        return Refuse(GrantSetRefusal::Expired);
    }
    match held {
        Some((e, u)) if !(h.epoch > e || (h.epoch == e && h.valid_until > u)) => Stale,
        _ => Accept,
    }
}

/// One held grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldGrant {
    pub subject_pub: [u8; 32],
    pub cap: String,
    /// 0: no grant-level expiry.
    pub expires: u64,
}

/// Does a held (previously accepted) set grant `subject` the `action`, now?
/// A set past its `valid_until` grants nothing, even though it was accepted
/// while valid: an owner that stops refreshing stops granting.
pub fn grant_set_allows(
    valid_until: u64,
    grants: &[HeldGrant],
    subject: &[u8; 32],
    action: &str,
    now: u64,
) -> bool {
    now < valid_until
        && grants.iter().any(|g| {
            g.subject_pub == *subject
                && g.cap.eq_ignore_ascii_case(action)
                && (g.expires == 0 || now < g.expires)
        })
}

/// `fleet.owner_grants`: how much an owner-signed grant set may give a sibling
/// on THIS device. A local setting of the target, read at accept time and again
/// at every use; nothing received over the network can set or widen it.
///
/// * `Off`: owner-signed sets are refused outright and never kept. A sibling
///   gets what its kind implies (file transfer into the inbox) and nothing more.
/// * `Files` (default): `transfer` and `mount` entries apply; `shell` does not.
/// * `All`: `transfer`, `mount` and `shell` apply.
///
/// Whatever the policy, only the distributable capabilities ever apply, and a
/// local deny, revocation and certificate expiry outrank it (they are absolute
/// in the gate, before any grant is consulted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OwnerGrantPolicy {
    Off,
    #[default]
    Files,
    All,
}

impl OwnerGrantPolicy {
    /// The setting's name, as `tunlion set` shows it.
    pub const SETTING: &'static str = "fleet.owner_grants";
    /// The values `tunlion set fleet.owner_grants` accepts, narrowest first.
    pub const VALUES: &'static [&'static str] = &["off", "files", "all"];

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "files" => Some(Self::Files),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// The policy a stored value means: absent is the default (`Files`); a value
    /// that is present but unreadable (a hand edit gone wrong) is `Off`, the
    /// narrowest, rather than a guess.
    pub fn from_stored(raw: Option<&str>) -> Self {
        match raw.map(str::trim).filter(|v| !v.is_empty()) {
            None => Self::default(),
            Some(v) => Self::parse(v).unwrap_or(Self::Off),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Files => "files",
            Self::All => "all",
        }
    }

    /// Does an owner-signed grant of `cap` take effect under this policy?
    pub fn applies(self, cap: &str) -> bool {
        let c = cap.trim();
        let file_class = c.eq_ignore_ascii_case(CAP_TRANSFER) || c.eq_ignore_ascii_case(CAP_MOUNT);
        match self {
            Self::Off => false,
            Self::Files => file_class,
            Self::All => file_class || c.eq_ignore_ascii_case(CAP_SHELL),
        }
    }
}

/// [`judge_grant_set`] under the local policy: with `Off` every set is refused
/// before anything else is looked at, so nothing is ever kept.
pub fn judge_grant_set_under(
    policy: OwnerGrantPolicy,
    h: &GrantSetHeader,
    signature_ok: bool,
    my_owner: &[u8; 32],
    my_device: &[u8; 32],
    now: u64,
    held: Option<(u64, u64)>,
) -> GrantSetJudgement {
    if policy == OwnerGrantPolicy::Off {
        return GrantSetJudgement::Refuse(GrantSetRefusal::OwnerGrantsOff);
    }
    judge_grant_set(h, signature_ok, my_owner, my_device, now, held)
}

/// [`grant_set_allows`] under the local policy, read at USE time: a set held
/// since before the policy narrowed grants only what the policy allows NOW.
pub fn grant_set_allows_under(
    policy: OwnerGrantPolicy,
    valid_until: u64,
    grants: &[HeldGrant],
    subject: &[u8; 32],
    action: &str,
    now: u64,
) -> bool {
    policy.applies(action) && grant_set_allows(valid_until, grants, subject, action, now)
}

#[cfg(test)]
mod laws {
    use super::*;
    use crate::capability::fleet_auto_trust;
    use crate::capability::BindingStrength;

    const OWNER: [u8; 32] = [1; 32];
    const ME: [u8; 32] = [2; 32];
    const OTHER: [u8; 32] = [3; 32];

    fn hdr(epoch: u64, until: u64) -> GrantSetHeader {
        GrantSetHeader { owner_pub: OWNER, target_pub: ME, epoch, valid_until: until }
    }

    #[test]
    fn law_kind_implies_transfer_and_nothing_else() {
        assert!(sibling_default_covers(CAP_TRANSFER));
        for a in [CAP_SHELL, CAP_MOUNT, "exec", "forward", "route:10.0.0.0/8", "pty"] {
            assert!(!sibling_default_covers(a), "{a} must not be implied");
        }
    }

    #[test]
    fn law_sibling_scoped_default_is_transfer_only_and_never_widens() {
        // In bounds, no grant: transfer auto, everything else withheld.
        assert_eq!(fleet_sibling_inputs(true, CAP_TRANSFER, true, false, false, false), (true, false));
        assert_eq!(fleet_sibling_inputs(true, CAP_SHELL, true, false, false, false), (false, false));
        assert_eq!(fleet_sibling_inputs(true, CAP_MOUNT, true, false, false, false), (false, false));
        // Out of bounds stays out, for every action.
        for a in [CAP_TRANSFER, CAP_SHELL, CAP_MOUNT] {
            assert!(!fleet_sibling_inputs(true, a, false, false, false, false).0);
        }
        // Never widens the scope: scoped out implies scoped in.
        for sib in [false, true] {
            for a in [CAP_TRANSFER, CAP_SHELL, CAP_MOUNT] {
                for b in [false, true] {
                    for g in [false, true] {
                        let (s, _) = fleet_sibling_inputs(sib, a, b, g, g, g);
                        assert!(!s || b);
                    }
                }
            }
        }
    }

    #[test]
    fn law_grants_are_explicit_and_count_from_either_source() {
        assert!(fleet_sibling_inputs(true, CAP_SHELL, false, false, true, false).1);
        assert!(fleet_sibling_inputs(true, CAP_SHELL, false, false, false, true).1);
        assert!(!fleet_sibling_inputs(true, CAP_SHELL, false, false, false, false).1);
    }

    #[test]
    fn law_non_siblings_pass_through_untouched() {
        for a in [CAP_TRANSFER, CAP_SHELL, CAP_MOUNT] {
            for b in [false, true] {
                for g in [false, true] {
                    // Sibling-only grant sources are ignored for a non-sibling.
                    assert_eq!(fleet_sibling_inputs(false, a, b, g, true, true), (b, g));
                }
            }
        }
    }

    #[test]
    fn law_kind_composed_with_the_gate_rule() {
        // Ungranted sibling transfer in bounds: the gate's fleet auto-trust allows.
        let (s, _) = fleet_sibling_inputs(true, CAP_TRANSFER, true, false, false, false);
        assert!(fleet_auto_trust(true, BindingStrength::Proven, s, true));
        // Revoked, or not Proven: refused whatever the kind says.
        assert!(!fleet_auto_trust(true, BindingStrength::Proven, s, false));
        assert!(!fleet_auto_trust(true, BindingStrength::Inferred, s, true));
        // Not same owner (cross-owner): refused.
        assert!(!fleet_auto_trust(false, BindingStrength::Proven, s, true));
        // Shell is never auto-trusted for a sibling.
        let (s, _) = fleet_sibling_inputs(true, CAP_SHELL, true, false, false, false);
        assert!(!fleet_auto_trust(true, BindingStrength::Proven, s, true));
    }

    #[test]
    fn law_forgery_foreign_owner_and_wrong_target_are_refused() {
        use GrantSetJudgement::Refuse;
        assert_eq!(judge_grant_set(&hdr(1, 100), false, &OWNER, &ME, 10, None), Refuse(GrantSetRefusal::BadSignature));
        let mut h = hdr(1, 100);
        h.owner_pub = OTHER;
        assert_eq!(judge_grant_set(&h, true, &OWNER, &ME, 10, None), Refuse(GrantSetRefusal::OtherOwner));
        let mut h = hdr(1, 100);
        h.target_pub = OTHER;
        assert_eq!(judge_grant_set(&h, true, &OWNER, &ME, 10, None), Refuse(GrantSetRefusal::OtherTarget));
    }

    #[test]
    fn law_expired_is_never_accepted_at_the_boundary() {
        use GrantSetJudgement::*;
        assert_eq!(judge_grant_set(&hdr(1, 100), true, &OWNER, &ME, 99, None), Accept);
        assert_eq!(judge_grant_set(&hdr(1, 100), true, &OWNER, &ME, 100, None), Refuse(GrantSetRefusal::Expired));
        // Even a newer epoch that is already expired never replaces a held set.
        assert_eq!(judge_grant_set(&hdr(9, 100), true, &OWNER, &ME, 100, Some((1, 500))), Refuse(GrantSetRefusal::Expired));
    }

    #[test]
    fn law_monotonic_replay_is_a_no_op() {
        use GrantSetJudgement::*;
        let held = Some((3, 200));
        assert_eq!(judge_grant_set(&hdr(3, 200), true, &OWNER, &ME, 10, held), Stale);
        assert_eq!(judge_grant_set(&hdr(2, 900), true, &OWNER, &ME, 10, held), Stale);
        assert_eq!(judge_grant_set(&hdr(3, 199), true, &OWNER, &ME, 10, held), Stale);
        assert_eq!(judge_grant_set(&hdr(3, 201), true, &OWNER, &ME, 10, held), Accept);
        assert_eq!(judge_grant_set(&hdr(4, 50), true, &OWNER, &ME, 10, held), Accept);
    }

    #[test]
    fn law_held_set_grants_only_its_subject_its_cap_until_expiry() {
        let gs = vec![
            HeldGrant { subject_pub: OTHER, cap: "shell".into(), expires: 0 },
            HeldGrant { subject_pub: ME, cap: "mount".into(), expires: 50 },
        ];
        assert!(grant_set_allows(100, &gs, &OTHER, "shell", 10));
        assert!(!grant_set_allows(100, &gs, &OTHER, "mount", 10), "no cap it does not list");
        assert!(!grant_set_allows(100, &gs, &[9; 32], "shell", 10), "no third party");
        assert!(grant_set_allows(100, &gs, &ME, "mount", 49));
        assert!(!grant_set_allows(100, &gs, &ME, "mount", 50), "grant expiry binds");
        assert!(!grant_set_allows(100, &gs, &OTHER, "shell", 100), "set expiry binds");
    }

    // ---- fleet.owner_grants ----

    const ALL_POLICIES: [OwnerGrantPolicy; 3] =
        [OwnerGrantPolicy::Off, OwnerGrantPolicy::Files, OwnerGrantPolicy::All];

    #[test]
    fn law_owner_grant_policy_default_is_files_and_garbage_is_off() {
        assert_eq!(OwnerGrantPolicy::default(), OwnerGrantPolicy::Files);
        assert_eq!(OwnerGrantPolicy::from_stored(None), OwnerGrantPolicy::Files);
        assert_eq!(OwnerGrantPolicy::from_stored(Some("  ")), OwnerGrantPolicy::Files);
        assert_eq!(OwnerGrantPolicy::from_stored(Some("ALL")), OwnerGrantPolicy::All);
        assert_eq!(OwnerGrantPolicy::from_stored(Some("everything")), OwnerGrantPolicy::Off);
        for p in ALL_POLICIES {
            assert_eq!(OwnerGrantPolicy::parse(p.as_str()), Some(p));
            assert!(OwnerGrantPolicy::VALUES.contains(&p.as_str()));
        }
    }

    #[test]
    fn law_shell_applies_only_under_all() {
        for p in ALL_POLICIES {
            assert_eq!(p.applies(CAP_SHELL), p == OwnerGrantPolicy::All, "{p:?}");
            assert_eq!(p.applies("SHELL"), p == OwnerGrantPolicy::All, "{p:?}");
        }
    }

    #[test]
    fn law_off_applies_nothing_files_applies_transfer_and_mount() {
        for c in [CAP_TRANSFER, CAP_MOUNT, CAP_SHELL, "exec", "forward", "route:0.0.0.0/0", "*"] {
            assert!(!OwnerGrantPolicy::Off.applies(c), "{c}");
        }
        assert!(OwnerGrantPolicy::Files.applies(CAP_TRANSFER));
        assert!(OwnerGrantPolicy::Files.applies(CAP_MOUNT));
        // Nothing outside the distributable set applies under any policy, so a
        // stolen owner key cannot name a capability the CLI never distributes.
        for p in ALL_POLICIES {
            for c in ["exec", "forward", "route:0.0.0.0/0", "*", ""] {
                assert!(!p.applies(c), "{p:?} {c}");
            }
        }
    }

    #[test]
    fn law_policies_are_nested() {
        // off is inside files is inside all, for every capability.
        for c in [CAP_TRANSFER, CAP_MOUNT, CAP_SHELL, "exec"] {
            assert!(!OwnerGrantPolicy::Off.applies(c) || OwnerGrantPolicy::Files.applies(c));
            assert!(!OwnerGrantPolicy::Files.applies(c) || OwnerGrantPolicy::All.applies(c));
        }
    }

    #[test]
    fn law_off_refuses_every_set_even_a_perfect_one() {
        use GrantSetJudgement::*;
        assert_eq!(judge_grant_set(&hdr(1, 100), true, &OWNER, &ME, 10, None), Accept);
        assert_eq!(
            judge_grant_set_under(OwnerGrantPolicy::Off, &hdr(1, 100), true, &OWNER, &ME, 10, None),
            Refuse(GrantSetRefusal::OwnerGrantsOff)
        );
        for p in [OwnerGrantPolicy::Files, OwnerGrantPolicy::All] {
            for (sig, until, held) in [(true, 100, None), (false, 100, None), (true, 5, None), (true, 100, Some((3, 200)))] {
                assert_eq!(
                    judge_grant_set_under(p, &hdr(1, until), sig, &OWNER, &ME, 10, held),
                    judge_grant_set(&hdr(1, until), sig, &OWNER, &ME, 10, held),
                );
            }
        }
    }

    #[test]
    fn law_use_time_filter_follows_the_current_policy() {
        // One held set granting shell and mount: what it grants depends on the
        // policy at the moment of use, not on when it was accepted.
        let gs = vec![
            HeldGrant { subject_pub: OTHER, cap: "shell".into(), expires: 0 },
            HeldGrant { subject_pub: OTHER, cap: "mount".into(), expires: 0 },
        ];
        let at = |p| (grant_set_allows_under(p, 100, &gs, &OTHER, CAP_SHELL, 10),
                      grant_set_allows_under(p, 100, &gs, &OTHER, CAP_MOUNT, 10));
        assert_eq!(at(OwnerGrantPolicy::All), (true, true));
        assert_eq!(at(OwnerGrantPolicy::Files), (false, true));
        assert_eq!(at(OwnerGrantPolicy::Off), (false, false));
        // And the policy never widens what the set says.
        for p in ALL_POLICIES {
            assert!(!grant_set_allows_under(p, 100, &gs, &OTHER, CAP_TRANSFER, 10));
            assert!(!grant_set_allows_under(p, 100, &gs, &OTHER, CAP_SHELL, 100));
        }
    }
}
