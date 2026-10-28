//! Revocation decisions the receive loop applies to live links and routes.
//!
//! Moved from `cli/src/revocation_live.rs`: the wire-free decision functions and
//! the `BrokeredBy` record. Reading the store and the key-revocation file stays
//! on the host port ([`crate::recv::ports::RecvDaemon`]); these only decide.

use crate::conn::{Conn, Link};
use std::collections::HashSet;
use std::sync::Arc;

/// Who brokered a meeting place: the PROVEN identity of the certificate
/// verified fleet link the `fleet-rendezvous` arrived on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokeredBy {
    pub device_pub: [u8; 32],
    pub owner_pub: [u8; 32],
    pub expires: u64,
    pub name: Option<String>,
}

pub const BROKERED_NO_RECORD: &str = "\u{7f}fleet: brokered, no record";

/// The name a link on a brokered meeting place is dialed under.
pub fn brokered_dial_name(broker: &BrokeredBy) -> String {
    broker
        .name
        .clone()
        .unwrap_or_else(|| BROKERED_NO_RECORD.to_string())
}

/// Bind a link that arrived on a brokered meeting place to its broker.
pub fn bind_brokered_link(link: &mut Link, broker: &BrokeredBy) {
    link.trusted = false;
    link.verified_name = broker.name.clone();
    link.admit_fleet(broker.owner_pub, broker.device_pub, broker.expires);
}

/// What the sweep needs to know about one link.
pub struct LinkFacts<'a> {
    pub secret: Option<&'a str>,
    pub device_pub: Option<[u8; 32]>,
}

/// Must this link close now?
pub fn link_must_close(
    f: &LinkFacts<'_>,
    removed_secrets: &HashSet<String>,
    key_listed: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    if f.secret.is_some_and(|s| removed_secrets.contains(s)) {
        return true;
    }
    f.device_pub.as_ref().is_some_and(|k| key_listed(k))
}

/// Must this fleet SIBLING link close now? A sibling (a `FleetSibling`
/// principal: admitted on its owner-signed certificate, never paired) holds its
/// link on exactly two facts, and loses it the moment either stops being true:
/// the device is not revoked (locally, or by the owner withdrawing it from the
/// signed roster, which `revoked` folds in), and its certificate is unexpired.
/// Any other link kind is never closed by this rule.
pub fn sibling_link_must_close(
    is_fleet_sibling: bool,
    device_pub: Option<&[u8; 32]>,
    cert_expires: Option<u64>,
    now: u64,
    revoked: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    if !is_fleet_sibling {
        return false;
    }
    let Some(dev) = device_pub else {
        // A sibling principal with no proven key is not a state admission can
        // produce; fail closed rather than keep an unidentified sibling.
        return true;
    };
    revoked(dev) || cert_expires.is_some_and(|exp| exp <= now)
}

/// Must this link lose its overlay route?
pub fn route_must_withdraw(
    device_pub: Option<&[u8; 32]>,
    revoked: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    device_pub.is_some_and(|k| revoked(k))
}

/// Adapt a link to the facts the decision needs.
pub fn facts_for<'a>(conn: &'a Conn, pid: &str) -> LinkFacts<'a> {
    let link = conn.link(pid);
    LinkFacts {
        secret: link.and_then(|l| l.expected_secret.as_ref().map(|(_, s)| s.as_str())),
        device_pub: link.and_then(|l| l.identity_device_pub),
    }
}

#[allow(dead_code)]
fn _arc(_: &Arc<dyn std::any::Any>) {}

#[cfg(test)]
mod sibling_cut_tests {
    use super::sibling_link_must_close;

    #[test]
    fn a_sibling_link_closes_on_revocation_or_expiry_and_nothing_else() {
        let dev = [7u8; 32];
        let never = |_: &[u8; 32]| false;
        let always = |_: &[u8; 32]| true;
        // Healthy sibling: kept.
        assert!(!sibling_link_must_close(true, Some(&dev), Some(200), 100, &never));
        // Revoked (locally or delisted by the owner's roster): closed.
        assert!(sibling_link_must_close(true, Some(&dev), Some(200), 100, &always));
        // Certificate expired: closed, at the expiry second itself.
        assert!(sibling_link_must_close(true, Some(&dev), Some(100), 100, &never));
        // Unidentified sibling: fail closed.
        assert!(sibling_link_must_close(true, None, Some(200), 100, &never));
        // Not a sibling (paired, owner, delegated): this rule never fires,
        // whatever the other inputs say. Pairwise links keep their own rules.
        assert!(!sibling_link_must_close(false, Some(&dev), Some(1), 100, &always));
        assert!(!sibling_link_must_close(false, None, None, 100, &always));
    }
}
