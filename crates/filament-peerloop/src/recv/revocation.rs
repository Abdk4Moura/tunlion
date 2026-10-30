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

/// What the peer on a link the sweep is about to close is told, in the
/// product's two words for "this ended".
///
/// `forget` and `revoke` are different promises: one says "I no longer
/// recognize this device" (`Code::Unrecognized`, "not recognized"), the other
/// "I still know it and cut it off" (`Code::CertRevoked`, "device revoked").
/// The peer must hear which one it met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkCut {
    /// The device is not recognized here any more (or never was).
    Forgotten,
    /// The device is still known, and its access was revoked.
    Revoked,
}

/// Classify a link the sweep is closing.
///
/// A link is FORGOTTEN when the store no longer holds the pair secret that
/// proves it (`secret_forgotten`), or when its device key is on the forget
/// block in `revoked-keys.json` (`key_on_forget_block`). `devices forget` is
/// the only writer of that block, and an explicit re-add or `promote` lifts it,
/// so it means exactly "forgotten", never an in-place revoke or an expiry.
///
/// The key block wins even while the record is still visible: `forget` writes
/// the block FIRST and drops the record after (revocation-first, so there is no
/// window in which fleet-hello re-admits the key), and the daemon's store poll
/// can land between the two writes. Reading that instant as "revoked" made the
/// same forget answer differently from run to run, and a fleet-only link (no
/// pair secret, so no secret to see removed) answer "revoked" every time.
///
/// Everything else the sweep closes - a sibling the owner's signed roster no
/// longer lists, or whose certificate ran out - is a genuine revocation and
/// stays [`LinkCut::Revoked`]. Pure.
pub fn link_cut_reason(secret_forgotten: bool, key_on_forget_block: bool) -> LinkCut {
    if secret_forgotten || key_on_forget_block {
        LinkCut::Forgotten
    } else {
        LinkCut::Revoked
    }
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

#[cfg(test)]
mod link_cut_tests {
    use super::{LinkCut, link_cut_reason};

    /// A paired device whose secret left the store was forgotten: every later
    /// open is refused as unrecognized, and the running exec must hear the same.
    #[test]
    fn a_removed_pair_secret_is_a_forget() {
        assert_eq!(link_cut_reason(true, false), LinkCut::Forgotten);
    }

    /// A fleet-only link carries no pair secret, so nothing in the link shows
    /// the removal. The forget block does, and it is the only signal there is.
    #[test]
    fn a_fleet_only_link_cut_by_the_forget_block_is_a_forget() {
        assert_eq!(link_cut_reason(false, true), LinkCut::Forgotten);
    }

    /// `forget` writes the key block BEFORE it drops the record. The daemon's
    /// store poll can see exactly that instant: the record is still listed, so
    /// no secret looks removed, but the block already names the key. It must
    /// read as forgotten, or the same forget answers differently run to run.
    #[test]
    fn the_forgets_pre_removal_instant_is_still_a_forget() {
        assert_eq!(link_cut_reason(false, true), LinkCut::Forgotten);
        // And once the record is gone too.
        assert_eq!(link_cut_reason(true, true), LinkCut::Forgotten);
    }

    /// The genuine revocations keep their word: a sibling the owner's signed
    /// roster delisted, or whose certificate ran out, is still known to us and
    /// was cut off. Neither path writes the forget block.
    #[test]
    fn a_delisted_or_expired_sibling_is_still_a_revocation() {
        assert_eq!(link_cut_reason(false, false), LinkCut::Revoked);
    }
}
