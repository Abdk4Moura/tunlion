//! Pure subnet-route acceptance, not signature verification or installation.
//!
//! The caller supplies host snapshots and applies the full result, including an
//! empty withdrawal. Packet endpoints, OS routes and their lifetime stay outside
//! this module. This extraction does not repair replay or route-table teardown.

use filament_cap::capability as cap;
use serde_json::Value;

/// Host-resolved inputs to the receiver-consent and owner-authority gates.
pub struct RoutePolicy<'a> {
    /// Receiver's per-peer consent; no owner authority overrides false.
    pub accept_routes: bool,
    /// Persisted enrolment ceiling, in stored `route:<cidr>` form. Bare `route`
    /// and entries for other capabilities authorize nothing here.
    pub ceiling: &'a [String],
    /// Owner public key naming the resources (not an owner signing key).
    pub owner_pub: Option<[u8; 32]>,
    /// Capability store already loaded by the host.
    pub cap_store: &'a [Value],
    /// Authenticated link principal, never keys asserted in an advertisement.
    pub device_pub: Option<[u8; 32]>,
    pub user_pub: Option<[u8; 32]>,
    /// Host clock, in seconds since the Unix epoch.
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAcceptance {
    /// Accepted strings, unchanged and in advertisement order. Empty is a
    /// withdrawal: the caller must still restate the peer's subnet set.
    pub accepted: Vec<String>,
    /// Always `advertised.len() - accepted.len()` (duplicates count).
    pub declined: usize,
}

/// Apply receiver consent AND (persisted ceiling OR capability authorization).
///
/// The caller must first verify the base announce/channel binding, refuse
/// revoked/expired peers, accept its fresh sequence, and complete identity and
/// transport admission. `advertised` must be the output of
/// `filament_overlay::Announce::verify_routes` for that same announce/binding.
/// This function cannot enforce those preconditions: it has no wire frame,
/// sequence state, identity store or transport, and must not become a second
/// signature/freshness authority.
///
/// Preserves the existing ceiling-OR-cap-store rule, not an intersection. The
/// cap branch uses `authorize_in` verbatim (including its owner semantics), with
/// deliberate `CAP_ROUTE`, an owner-bound prefix resource and no auth-key caps.
/// No scoped default, fleet-auto-trust or shell grant is substituted for it.
pub fn accept_advertised(advertised: &[String], policy: RoutePolicy<'_>) -> RouteAcceptance {
    let ceiling: Vec<String> = policy
        .ceiling
        .iter()
        .filter_map(|c| c.strip_prefix("route:").map(str::to_string))
        .collect();
    let accepted = super::installable_routes(advertised, policy.accept_routes, |cidr| {
        authorized(cidr, &ceiling, &policy)
    });
    RouteAcceptance {
        declined: advertised.len() - accepted.len(),
        accepted,
    }
}

fn authorized(cidr: &str, ceiling: &[String], policy: &RoutePolicy<'_>) -> bool {
    if cap::cidr_within_any(cidr, ceiling) {
        return true;
    }
    let Some(owner) = policy.owner_pub else {
        return false;
    };
    let Ok(resource) = cap::route_resource_id(&owner, cidr) else {
        return false;
    };
    matches!(
        cap::authorize_in(
            policy.cap_store,
            &resource,
            cap::CAP_ROUTE,
            policy.device_pub.as_ref(),
            policy.user_pub.as_ref(),
            None,
            policy.now,
        ),
        cap::CapOutcome::Authorized
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const NOW: u64 = 100;
    const DEVICE: [u8; 32] = [7; 32];
    // Not the owner: fixtures must exercise signed grants, not the owner shortcut.
    const USER: [u8; 32] = [8; 32];
    const LAN: &str = "10.66.0.0/24";

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_string()).collect()
    }

    fn policy<'a>(ceiling: &'a [String], store: &'a [Value]) -> RoutePolicy<'a> {
        RoutePolicy {
            accept_routes: true,
            ceiling,
            owner_pub: None,
            cap_store: store,
            device_pub: Some(DEVICE),
            user_pub: Some(USER),
            now: NOW,
        }
    }

    struct Grant {
        store: Vec<Value>,
        owner: [u8; 32],
        key: Ed25519KeyPair,
        header: cap::CapHeader,
        op: cap::CapOp,
    }

    impl Grant {
        fn new(cidr: &str, target_kind: u8, target: [u8; 32], action: &str) -> Self {
            let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let key = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
            let owner: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
            let spec = cap::parse_grant_spec(&format!("route:{cidr}"), &owner).unwrap();
            let mut header = cap::CapHeader {
                resource: spec.resource.clone(),
                nonce: spec.nonce,
                epoch: 0,
                owner_pub: owner,
                floors: Vec::new(),
                issued_at: NOW,
                prev_owner_pub: None,
                prev_header_hash: None,
                sig: [0; 64],
            };
            header.sig = cap::sign_cap_header(&header, &key);
            let mut op = cap::CapOp {
                op: cap::CapOpKind::Grant,
                grantor: owner,
                target_kind,
                target,
                resource: spec.resource,
                permissions: vec![action.to_string()],
                expires: NOW + 10,
                issued_at: NOW,
                version: 1,
                sig: [0; 64],
            };
            op.sig = cap::sign_cap_op(&op, &key);
            // Use the real verified store writers: raw op.to_json() is not a
            // cap_grant entry and lacks the freshness ratchet required by evaluate.
            let mut store = Vec::new();
            cap::apply_header(&mut store, &header).unwrap();
            cap::apply_cap_op(&mut store, &header, &op, NOW).unwrap();
            Self {
                store,
                owner,
                key,
                header,
                op,
            }
        }

        fn policy(&self) -> RoutePolicy<'_> {
            RoutePolicy {
                owner_pub: Some(self.owner),
                ..policy(&[], &self.store)
            }
        }
    }

    #[test]
    fn accept_off_is_total_even_with_both_authorities() {
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        let ceiling = strings(&["route:0.0.0.0/0"]);
        let advertised = strings(&[LAN, "0.0.0.0/0"]);
        let result = accept_advertised(
            &advertised,
            RoutePolicy {
                accept_routes: false,
                ceiling: &ceiling,
                ..grant.policy()
            },
        );
        assert_eq!(
            result,
            RouteAcceptance {
                accepted: vec![],
                declined: 2
            }
        );
    }

    #[test]
    fn persisted_ceiling_containment_is_directional_and_family_aware() {
        let ceiling = strings(&["route:10.0.0.0/8", "route:2001:db8::/32"]);
        let advertised = strings(&[LAN, "11.0.0.0/24", "0.0.0.0/0", "2001:db8:1::/48", "::/0"]);
        let result = accept_advertised(&advertised, policy(&ceiling, &[]));
        assert_eq!(result.accepted, strings(&[LAN, "2001:db8:1::/48"]));
        assert_eq!(result.declined, 3);
        let narrow = strings(&["route:10.66.0.0/24"]);
        assert!(
            accept_advertised(&strings(&["10.0.0.0/8"]), policy(&narrow, &[]))
                .accepted
                .is_empty()
        );
    }

    #[test]
    fn bare_route_and_other_capabilities_do_not_authorize() {
        let ceiling = strings(&["route", "shell", "mount", "transfer", "Route:0.0.0.0/0"]);
        assert!(accept_advertised(&strings(&[LAN]), policy(&ceiling, &[]))
            .accepted
            .is_empty());
        assert!(cap::is_deliberate_capability(cap::CAP_ROUTE));
        assert!(!cap::is_scoped_default_action(cap::CAP_ROUTE));
        let shell = Grant::new(LAN, 1, DEVICE, cap::CAP_SHELL);
        assert!(accept_advertised(&strings(&[LAN]), shell.policy())
            .accepted
            .is_empty());
    }

    #[test]
    fn signed_owner_grant_names_an_exact_normalized_prefix() {
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        let advertised = strings(&[LAN, "10.66.0.0/16", "10.66.1.0/24", "192.168.0.0/16"]);
        let result = accept_advertised(&advertised, grant.policy());
        assert_eq!(result.accepted, strings(&[LAN]));
        assert_eq!(result.declined, 3);
    }

    #[test]
    fn link_device_and_user_keys_are_the_grant_principals() {
        let device = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        for key in [None, Some([9; 32])] {
            assert!(accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    device_pub: key,
                    ..device.policy()
                }
            )
            .accepted
            .is_empty());
        }
        let user = Grant::new(LAN, 0, USER, cap::CAP_ROUTE);
        assert_eq!(
            accept_advertised(&strings(&[LAN]), user.policy()).accepted,
            strings(&[LAN])
        );
        for key in [None, Some([9; 32])] {
            assert!(accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    user_pub: key,
                    ..user.policy()
                }
            )
            .accepted
            .is_empty());
        }
    }

    #[test]
    fn authority_is_ceiling_or_cap_store_not_an_intersection() {
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        // Persisted ceiling need not cover an independently granted prefix.
        let unrelated = strings(&["route:192.168.0.0/16"]);
        assert_eq!(
            accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    ceiling: &unrelated,
                    ..grant.policy()
                }
            )
            .accepted,
            strings(&[LAN])
        );
        // A ceiling match needs neither a resource header nor an owner key.
        let ceiling = strings(&["route:10.0.0.0/8"]);
        assert_eq!(
            accept_advertised(&strings(&[LAN]), policy(&ceiling, &[])).accepted,
            strings(&[LAN])
        );
    }

    #[test]
    fn owner_public_key_is_required_only_for_the_cap_branch() {
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        assert_eq!(
            accept_advertised(&strings(&[LAN]), grant.policy()).accepted,
            strings(&[LAN])
        );
        for owner in [None, Some([9; 32])] {
            assert!(accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    owner_pub: owner,
                    ..grant.policy()
                }
            )
            .accepted
            .is_empty());
        }
    }

    #[test]
    fn cap_authorization_retains_existing_owner_semantics() {
        let mut grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        // A real signed header alone authorizes its owner in authorize_in.
        // Do not silently replace that API with grants-only authorization.
        grant
            .store
            .retain(|e| e["type"].as_str() != Some("cap_grant"));
        assert_eq!(
            accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    user_pub: Some(grant.owner),
                    ..grant.policy()
                }
            )
            .accepted,
            strings(&[LAN])
        );
        assert!(accept_advertised(&strings(&[LAN]), grant.policy())
            .accepted
            .is_empty());
    }

    #[test]
    fn verified_route_set_is_the_input_and_bad_route_signature_means_withdrawal() {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let identity = filament_overlay::Identity::from_pkcs8(doc.as_ref()).unwrap();
        let binding = b"route-policy-test-channel";
        let mut announce = identity.announce_with_routes(7, binding, strings(&[LAN]));
        assert!(announce.verify(binding).is_ok());
        assert!(filament_overlay::seq_is_fresh(Some(6), announce.seq));
        let ceiling = strings(&["route:10.0.0.0/8"]);
        assert_eq!(
            accept_advertised(&announce.verify_routes(binding), policy(&ceiling, &[])).accepted,
            strings(&[LAN])
        );
        announce.routes_sig = Some([0; 64]);
        assert!(
            announce.verify(binding).is_ok(),
            "base address is independent"
        );
        assert_eq!(
            accept_advertised(&announce.verify_routes(binding), policy(&ceiling, &[])),
            RouteAcceptance {
                accepted: vec![],
                declined: 0,
            }
        );
        announce.routes_sig = None;
        assert!(
            accept_advertised(&announce.verify_routes(binding), policy(&ceiling, &[]))
                .accepted
                .is_empty()
        );
        // This only demonstrates the input boundary. The real CLI's prior
        // identity/freshness checks and unconditional restatement stay in place.
    }

    #[test]
    fn expired_revoked_and_unprovisioned_grants_fail_closed() {
        let mut grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        for now in [NOW + 10, NOW + 11] {
            assert!(accept_advertised(
                &strings(&[LAN]),
                RoutePolicy {
                    now,
                    ..grant.policy()
                }
            )
            .accepted
            .is_empty());
        }
        assert!(accept_advertised(
            &strings(&[LAN]),
            RoutePolicy {
                cap_store: &[],
                ..grant.policy()
            }
        )
        .accepted
        .is_empty());
        grant.op.op = cap::CapOpKind::Revoke;
        grant.op.version += 1;
        grant.op.sig = cap::sign_cap_op(&grant.op, &grant.key);
        cap::apply_cap_op(&mut grant.store, &grant.header, &grant.op, NOW).unwrap();
        assert!(accept_advertised(&strings(&[LAN]), grant.policy())
            .accepted
            .is_empty());
    }

    #[test]
    fn a_default_needs_matching_ceiling_or_exact_cap_authority() {
        let advertised = strings(&["0.0.0.0/0", "::/0"]);
        let lan = strings(&["route:10.0.0.0/8"]);
        assert!(accept_advertised(&advertised, policy(&lan, &[]))
            .accepted
            .is_empty());
        let all = strings(&["route:0.0.0.0/0", "route:::/0"]);
        assert_eq!(
            accept_advertised(&advertised, policy(&all, &[])).accepted,
            advertised
        );
        let grant = Grant::new("0.0.0.0/0", 1, DEVICE, cap::CAP_ROUTE);
        assert_eq!(
            accept_advertised(&advertised, grant.policy()).accepted,
            strings(&["0.0.0.0/0"])
        );
    }

    #[test]
    fn malformed_prefixes_fail_both_branches_without_panicking() {
        let advertised = strings(&["", "10.0.0.0", "10.0.0.0/33", "2001:db8::/129", "nope/24"]);
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        let ceiling = strings(&["route:0.0.0.0/0", "route:::/0", "route:bad"]);
        let result = accept_advertised(
            &advertised,
            RoutePolicy {
                ceiling: &ceiling,
                ..grant.policy()
            },
        );
        assert_eq!(
            result,
            RouteAcceptance {
                accepted: vec![],
                declined: advertised.len()
            }
        );
    }

    #[test]
    fn acceptance_preserves_text_order_duplicates_and_empty_withdrawal() {
        let grant = Grant::new(LAN, 1, DEVICE, cap::CAP_ROUTE);
        let advertised = strings(&[" 10.66.0.5/24 ", "192.168.0.0/16", LAN, LAN]);
        let result = accept_advertised(&advertised, grant.policy());
        assert_eq!(result.accepted, strings(&[" 10.66.0.5/24 ", LAN, LAN]));
        assert_eq!(result.declined, 1);
        assert_eq!(result.accepted.len() + result.declined, advertised.len());
        assert_eq!(
            accept_advertised(&[], grant.policy()),
            RouteAcceptance {
                accepted: vec![],
                declined: 0
            }
        );
    }

    // Moved from cli/src/l3.rs: the generic two-gate rule remains the single
    // filtering loop used by accept_advertised.
    #[test]
    fn installing_a_route_needs_the_receiver_and_the_owner_to_agree() {
        let adv = strings(&["10.0.0.0/24", "192.168.1.0/24"]);
        let granted = |c: &str| c == "10.0.0.0/24";
        assert_eq!(
            super::super::installable_routes(&adv, true, granted),
            strings(&["10.0.0.0/24"])
        );
        assert!(super::super::installable_routes(&adv, false, granted).is_empty());
        assert!(super::super::installable_routes(&adv, true, |_| false).is_empty());
        assert!(super::super::installable_routes(&[], true, |_| true).is_empty());
    }
}
