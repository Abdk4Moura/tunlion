//! Fleet link-shape decisions the receive dispatch asks before routing.
//!
//! Moved from `cli/src/fleet_support.rs`: these are pure reads over `Conn`
//! (and the fleet rendezvous secret), with no terminal or host effect.

use crate::conn::Conn;
use filament_fleet as fleet;

/// May a route be installed to this peer? A direct-QUIC link always can (real
/// QUIC datagrams). A relay link only when the peer advertised relay datagrams.
pub fn route_ok(conn: &Conn, pid: &str, peer_relay_datagrams: bool) -> bool {
    conn.link(pid).map(|l| l.direct).unwrap_or(false) || peer_relay_datagrams
}

/// Is this link one that must prove itself with a `fleet-hello`?
pub fn shaped_link(conn: &Conn, pid: &str) -> bool {
    conn.link(pid)
        .map(|l| {
            !l.trusted
                && match &l.expected_secret {
                    None => true,
                    Some((_, secret)) => fleet::rv().as_deref() == Some(secret.as_str()),
                }
        })
        .unwrap_or(false)
}

/// Must L3 wait for `fleet-hello` on this link?
pub fn identity_pending(conn: &Conn, pid: &str, pending: bool, verified: bool) -> bool {
    if !pending || verified {
        return false;
    }
    conn.link(pid)
        .map(|l| l.expected_secret.is_none())
        .unwrap_or(true)
}
