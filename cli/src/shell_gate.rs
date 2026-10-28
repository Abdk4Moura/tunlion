//! CLI shim over `filament_peerloop::shell_gate`.
//!
//! The single shell gate moved into the peer-loop crate in issue #465 slice 3.
//! The module name stays because pty-open, exec-open, forward, ssh-sign and the
//! devices view already import it; the types and the gathering function are
//! re-exported under their old names.
//!
//! The four verdict entry points keep their one-argument signatures here. The
//! crate takes the host explicitly so an embedder can supply its own; the CLI
//! has exactly one `HostServices` implementation (`host_impl::CliHost`), so the
//! wrappers bind it and every call site stays byte-identical. This is a binding,
//! not a second decision: the core, the fold and the policy site are the
//! crate's.
#![allow(unused_imports)]

use filament_cap::capability::{BindingStrength, CapOutcome, GateDecision, PrincipalKind};

pub(crate) use filament_peerloop::shell_gate::{
    PeerAuthz, ShellGateInputs, ShellPolicy, exec_gate_decision as gate_exec_decision,
    fleet_link_proven, forward_gate_decision as gate_forward_decision,
    gather_shell_gate_inputs, peer_authz, pty_gate_decision as gate_pty_decision,
    ssh_gate_decision as gate_ssh_decision,
};

/// Exec-open's verdict, with the CLI's host bound.
pub(crate) fn exec_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    gate_exec_decision(inputs, &crate::host_impl::CliHost)
}

/// Pty-open's verdict, with the CLI's host bound.
pub(crate) fn pty_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    gate_pty_decision(inputs, &crate::host_impl::CliHost)
}

/// Forward-open's verdict, with the caller's legacy fold and the CLI's host.
pub(crate) fn forward_gate_decision(
    inputs: &ShellGateInputs,
    legacy_ok: bool,
) -> Result<(), Option<String>> {
    gate_forward_decision(inputs, legacy_ok, &crate::host_impl::CliHost)
}

/// SSH-sign's verdict, with the CLI's host bound.
pub(crate) fn ssh_gate_decision(inputs: &ShellGateInputs) -> Result<(), Option<String>> {
    gate_ssh_decision(inputs, &crate::host_impl::CliHost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CAP_SHELL, CapOutcome};

    /// Cross-path equivalence: exec's decision == pty-open's for every cell
    /// of trusted x has_grant x cert_revoked x delegated-ceiling x
    /// ceiling-covers x denied x authoritative(on/off), calling all three
    /// entry points. Fabricated inputs
    /// mirror production gathering (store_allows tracks the grant, outcome
    /// tracks it the way cap_authorize's grant dependence does, legacy folds
    /// trust with store fixed grant-leaning); authoritative toggles via env
    /// under the config lock because the engine reads it globally.
    #[test]
    fn exec_matches_pty_across_gate_matrix() {
        let _guard = crate::tests::lock_test_config();
        let prior = std::env::var("TUNLION_CAP_AUTHORITATIVE").ok();
        for authoritative in [false, true] {
            unsafe {
                std::env::set_var(
                    "TUNLION_CAP_AUTHORITATIVE",
                    if authoritative { "1" } else { "0" },
                );
            }
            for trusted in [false, true] {
                // Binding is a DIMENSION, not a constant: the regression this
                // pins was a secret-paired peer (binding None/Inferred, no
                // resolved cert) being denied by a settle path that held
                // binding fixed at Proven.
                for binding in [
                    BindingStrength::Proven,
                    BindingStrength::Inferred,
                    BindingStrength::None,
                ] {
                    // Scope-default class (transfer into the drop dir, forward to
                    // an exposed port): pre-existing fleet auto-trust, which is
                    // mode-INDEPENDENT for this class, unlike the ceiling.
                    for scoped_default in [false, true] {
                        for has_grant in [false, true] {
                            for cert_revoked in [false, true] {
                                for ceiling_allows in [false, true] {
                                    for ceiling_covers in [false, true] {
                                        for denied in [false, true] {
                                            let outcome = if has_grant {
                                                CapOutcome::Authorized
                                            } else {
                                                CapOutcome::Denied("test: no grant".into())
                                            };
                                            let ak_caps = if ceiling_allows {
                                                None
                                            } else {
                                                Some(vec!["transfer".to_string()])
                                            };
                                            let inputs = ShellGateInputs {
                                                trusted,
                                                denied,
                                                policy_allows: false,
                                                store_allows: has_grant,
                                                outcome,
                                                idev: Some([0x42u8; 32]),
                                                iusr: Some([0x11u8; 32]),
                                                binding,
                                                // Fixed far-future expiry (not an axis): None
                                                // fail-closes under authoritative, which would
                                                // deny every allow-cell for a reason outside
                                                // the matrix.
                                                expires: Some(9_999_999_999u64),
                                                ak_caps,
                                                // Same user key as iusr: these cells model the
                                                // same-owner fleet population the ceiling branch
                                                // exists for (without it same_owner is false
                                                // and no covered cell could ever allow).
                                                own_user: Some([0x11u8; 32]),
                                                has_grant,
                                                cert_revoked,
                                                ceiling_covers,
                                                scoped_default,
                                                action: CAP_SHELL.to_string(),
                                            };
                                            let e = exec_gate_decision(&inputs);
                                            let p = pty_gate_decision(&inputs);
                                            let s = ssh_gate_decision(&inputs);
                                            let f = forward_gate_decision(
                                                &inputs,
                                                inputs.trusted
                                                    && !inputs.denied
                                                    && (inputs.policy_allows
                                                        || inputs.store_allows),
                                            );
                                            assert_eq!(
                                                e, p,
                                                "exec vs pty disagree: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                            );
                                            // Blanket axis: the forward caller computes its legacy
                                            // fold through l2_open_allowed (blanket mode), not
                                            // the shell fold -- mirror that composition here so
                                            // the pin tests the real path, not an unreachable
                                            // forced-legacy input. Denied must deny even
                                            // blanketed -- N4 pins the l2_open_allowed rule.
                                            let f_blanket = forward_gate_decision(
                                                &inputs,
                                                filament_peerloop::l2::policy::l2_open_allowed(
                                                    true,
                                                    inputs.store_allows,
                                                    inputs.denied,
                                                ),
                                            );
                                            if denied {
                                                assert!(
                                                    f_blanket.is_err(),
                                                    "denied device opens nothing even blanketed: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                                );
                                            }
                                            assert_eq!(
                                                f, e,
                                                "forward vs exec disagree on shared inputs: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} denied={denied} auth={authoritative}"
                                            );
                                            assert_eq!(
                                                e, s,
                                                "exec vs ssh-sign disagree: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                            );
                                            // Oracle pins (not just equality): absolutes deny in
                                            // every cell, and the two canonical allows hold in
                                            // every cell. A core regression either way fails
                                            // here even if both wrappers still agree.
                                            if cert_revoked {
                                                assert!(
                                                    e.is_err(),
                                                    "revoked cert must deny: trusted={trusted} grant={has_grant} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                                );
                                            }
                                            if !ceiling_allows {
                                                assert!(
                                                    e.is_err(),
                                                    "narrow ceiling must deny: trusted={trusted} grant={has_grant} revoked={cert_revoked} covers={ceiling_covers} auth={authoritative}"
                                                );
                                            }
                                            // An allow is pinned only where the mode
                                            // and binding can produce one: shadow always
                                            // follows legacy; authoritative additionally
                                            // requires Proven (cap_authorize_proven).
                                            let binding_can_allow = !authoritative
                                                || binding == BindingStrength::Proven;
                                            if trusted
                                                && has_grant
                                                && !cert_revoked
                                                && ceiling_allows
                                                && !denied
                                                && binding_can_allow
                                            {
                                                assert!(
                                                    e.is_ok(),
                                                    "trusted+granted must allow: ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                                );
                                            }
                                            // Shadow follows the legacy fold EXACTLY where the
                                            // unconditional auth-key ceiling check passes (in this
                                            // matrix policy=false and store=grant, so legacy is
                                            // trusted && !denied && grant): the ceiling
                                            // substitution is authoritative-only, so those shadow
                                            // cells are a literal golden table of pre-change
                                            // behavior. ak-narrow cells deny in both modes via
                                            // the unconditional ceiling check, independent of
                                            // legacy -- that predates this change.
                                            // (cert-revoked cells excluded: the legacy fold has
                                            // no revocation term, but the gate denies revoked
                                            // absolutely in both modes -- that predates this
                                            // change.)
                                            // Widened: shadow takes the legacy fold PLUS the
                                            // scope-default fleet class, which has always
                                            // auto-authorized a same-owner Proven device in
                                            // BOTH modes. The ceiling is deliberately absent
                                            // here -- it decides only under authoritative.
                                            if !authoritative && ceiling_allows && !cert_revoked {
                                                let legacy_fold = trusted && !denied && has_grant;
                                                let fleet_default = !denied
                                                    && binding == BindingStrength::Proven
                                                    && scoped_default;
                                                assert_eq!(
                                                    e.is_ok(),
                                                    legacy_fold || fleet_default,
                                                    "shadow must follow the legacy fold exactly: trusted={trusted} grant={has_grant} denied={denied}"
                                                );
                                            }
                                            // An explicit deny short-circuits everything including
                                            // fleet auto-trust (#244 class): denied denies in
                                            // every cell, both modes, all paths.
                                            if denied {
                                                assert!(
                                                    e.is_err(),
                                                    "explicit deny must deny: trusted={trusted} grant={has_grant} revoked={cert_revoked} ceiling={ceiling_allows} covers={ceiling_covers} auth={authoritative}"
                                                );
                                            }
                                            // covers=false is the pre-change behavior (scoped_in_bounds
                                            // was hardcoded false): authoritative deliberate-tier cells
                                            // without a grant must still deny, pinning the flip
                                            // blocker exactly where it was.
                                            if !ceiling_covers
                                                && !scoped_default
                                                && authoritative
                                                && !has_grant
                                            {
                                                assert!(
                                                    e.is_err(),
                                                    "uncovered deliberate action must deny under authoritative: trusted={trusted} revoked={cert_revoked} ceiling={ceiling_allows} auth={authoritative}"
                                                );
                                            }
                                            // covers=true opens exactly one new door: authoritative,
                                            // trusted, Proven, unrevoked, grantless, covered,
                                            // UNDENIED (an explicit deny outranks coverage).
                                            if (ceiling_covers || scoped_default)
                                                && authoritative
                                                && !cert_revoked
                                                && ceiling_allows
                                                && !denied
                                                && binding == BindingStrength::Proven
                                            {
                                                assert!(
                                                    e.is_ok(),
                                                    "covered enrolment ceiling must allow under authoritative: ceiling={ceiling_allows} auth={authoritative}"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        match prior {
            Some(v) => unsafe { std::env::set_var("TUNLION_CAP_AUTHORITATIVE", v) },
            None => unsafe { std::env::remove_var("TUNLION_CAP_AUTHORITATIVE") },
        }
    }

    // The revoked cells above are fabricated inputs, which is all a unit test
    // can reach: a secret-paired link resolves no identity, so `cert_revoked`
    // is false in every such harness whatever the product does. That was
    // recorded as verdict debt behind an ignored placeholder here. The debt is
    // paid LIVE instead, by `cli/tests/fleet-cert-gates.sh`, which enrols a
    // real certified device (`add --for` / `join`), revokes its CERTIFICATE
    // (`revoke <device> --certificate`) and asserts all three paths -- exec,
    // pty and ssh-sign -- refuse it, with a restore control so a broken link
    // cannot pass as a revocation. Keep that gate and this matrix together:
    // the matrix pins the decision, the gate pins that the decision is reached
    // with the real input.

    /// Eval item 4: on a member, `grant u1-b shell` for a fleet sibling was
    /// recorded, the caps view said EFFECTIVE yes, and every exec was refused
    /// "shell not granted to 'u1-b' here", because the fold read the link's
    /// pair `trusted` flag, which a fleet link never has. A proven fleet link
    /// now satisfies the record-grant term (shadow, the default mode), and
    /// the explicit deny and revocation still win.
    #[test]
    fn a_proven_fleet_sibling_with_a_record_grant_is_admitted() {
        use crate::capability::PrincipalKind;
        let _guard = crate::tests::lock_test_config();
        let prior = std::env::var("TUNLION_CAP_AUTHORITATIVE").ok();
        unsafe { std::env::set_var("TUNLION_CAP_AUTHORITATIVE", "0") };

        let fp = fleet_link_proven(&PrincipalKind::FleetSibling, BindingStrength::Proven, true, true);
        assert!(fp, "what admit_fleet leaves on a verified fleet-hello link");
        assert!(!fleet_link_proven(&PrincipalKind::FleetSibling, BindingStrength::Inferred, true, true));
        assert!(!fleet_link_proven(&PrincipalKind::FleetSibling, BindingStrength::Proven, true, false));
        assert!(!fleet_link_proven(&PrincipalKind::FleetSibling, BindingStrength::Proven, false, true));
        assert!(!fleet_link_proven(&PrincipalKind::OwnerDevice, BindingStrength::Proven, true, true));

        let owner = [0x11u8; 32];
        let cell = |trusted: bool, store_allows: bool, denied: bool, cert_revoked: bool| ShellGateInputs {
            trusted,
            denied,
            policy_allows: false,
            store_allows,
            outcome: CapOutcome::Denied("no header grant".into()),
            idev: Some([0x42u8; 32]),
            iusr: Some(owner),
            binding: BindingStrength::Proven,
            expires: Some(9_999_999_999u64),
            ak_caps: None,
            own_user: Some(owner),
            has_grant: false,
            cert_revoked,
            ceiling_covers: false,
            scoped_default: false,
            action: CAP_SHELL.to_string(),
        };
        let pair_trusted = false; // a fleet link is born untrusted
        // The grant the member recorded is honoured over the proven link.
        assert!(exec_gate_decision(&cell(pair_trusted || fp, true, false, false)).is_ok());
        assert!(pty_gate_decision(&cell(pair_trusted || fp, true, false, false)).is_ok());
        // Before the fix the fold saw pair trust alone: this is the refusal
        // the evaluator met.
        assert!(exec_gate_decision(&cell(pair_trusted, true, false, false)).is_err());
        // No grant, an explicit deny, or a revoked certificate still refuse.
        assert!(exec_gate_decision(&cell(fp, false, false, false)).is_err());
        assert!(exec_gate_decision(&cell(fp, true, true, false)).is_err());
        assert!(exec_gate_decision(&cell(fp, true, false, true)).is_err());

        unsafe {
            match prior {
                Some(v) => std::env::set_var("TUNLION_CAP_AUTHORITATIVE", v),
                None => std::env::remove_var("TUNLION_CAP_AUTHORITATIVE"),
            }
        }
    }
}
