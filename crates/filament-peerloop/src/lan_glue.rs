//! Local discovery in the command and daemon loops: the seam between
//! `filament_transport::lan` (sockets, listener, store) and `Conn`.
//!
//! A LAN link is a direct-QUIC link that met without the server. It goes
//! through the same `Ev::DirectReady` handling as a signaled direct link, so
//! trust, identity, capability gates and the warm path are the existing ones.
//! The only extra state is a seeded pending entry (which secret proved the
//! link) and a roster entry naming it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use filament_transport::lan::{self, LanEvent, LanKey};
use filament_transport::net::{AttemptId, Ev};
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;
use tunlion_lan::record::{not_circular, RouteOwner};

use crate::conn::{Conn, DirectAuth, DirectPending};

/// Route ownership for the circular-route guard (spec section 9.3): an
/// address belongs to the link to X when it is X's overlay address, as the
/// device store recorded it or as the live overlay table has it. Built from
/// state, never from an interface name.
#[derive(Default)]
pub struct Ownership(pub HashMap<IpAddr, String>);

impl RouteOwner for Ownership {
    fn carried_by(&self, ip: IpAddr) -> Option<String> {
        self.0.get(&ip.to_canonical()).cloned()
    }
}

impl Ownership {
    /// From the device store's recorded overlay addresses and the overlay's
    /// live peers (petname, address).
    pub fn build(stored: impl IntoIterator<Item = (String, Option<String>, Option<String>)>, live: impl IntoIterator<Item = (String, IpAddr)>) -> Ownership {
        let mut m = HashMap::new();
        for (name, v6, v4) in stored {
            for a in [v6, v4].into_iter().flatten() {
                if let Ok(ip) = a.parse::<IpAddr>() {
                    m.insert(ip, name.clone());
                }
            }
        }
        for (name, ip) in live {
            m.insert(ip, name);
        }
        Ownership(m)
    }
}

impl Conn {
    /// Record that `pid` is a LAN link authenticated with `secret` for `name`.
    /// The reservation carries the exact attempt and device binding. It mints
    /// no worker key; adoption makes a live device binding the pair.
    pub fn seed_lan(&mut self, pid: &str, name: &str, secret: &str, fleet: bool, attempt: AttemptId) {
        self.roster.insert(pid.to_string(), json!({ "id": pid, "name": name, "via": lan::ROUTE_LAN }));
        self.next_gen += 1;
        let auth = if fleet {
            DirectAuth::lan_fleet(self.next_gen)
        } else {
            DirectAuth::lan_device(self.next_gen, name, secret)
        };
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                attempt,
                auth,
                race_task: None,
                secret: (name.to_string(), secret.to_string()),
                fleet,
                lan: true,
                ephemeral: false,
                deadline: Instant::now() + Duration::from_secs(30),
                racing: true,
                endpoint: None,
                punch_sock: None,
                my_srflx: None,
                peer_server_public: None,
                server_public_dialed: Arc::new(AtomicBool::new(false)),
                probe: false,
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
    }

    /// Is there a usable link to `name` already (any route)?
    ///
    /// A LAN link whose binding no longer resolves is neither trusted nor
    /// `verified_name`d, so the warm/Proven matcher cannot see it. Match it by
    /// its own authenticated reservation instead: a live `ROUTE_LAN` transport whose reservation name
    /// is this device. This is identity for DEDUP only and grants no capability.
    pub fn has_link_to(&self, name: &str) -> bool {
        crate::conn::warm_link_for(self, name).is_some()
            || self.links.values().any(|link| {
                link.direct
                    && link.direct_route == lan::ROUTE_LAN
                    && link
                        .lan_binding
                        .as_ref()
                        .is_some_and(|binding| binding.name.eq_ignore_ascii_case(name))
                    && link
                        .transport
                        .as_ref()
                        .is_some_and(|t| t.is_alive() && !t.is_dead())
            })
    }

    /// Dial `name` over local discovery: its remembered addresses plus
    /// `extra` (from a beacon), minus anything carried by our own link to it.
    /// Returns how many addresses were dialed.
    pub fn lan_dial(&self, name: &str, secret: &str, fleet: bool, extra: &[SocketAddr], owner: &dyn RouteOwner) -> usize {
        let Some(svc) = self.lan.as_ref() else { return 0 };
        let mut addrs: Vec<SocketAddr> = extra.to_vec();
        for a in svc.store.dial_order(name) {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
        let addrs = not_circular(name, addrs, owner);
        let n = addrs.len();
        if n > 0 {
            svc.dial(LanKey { name: name.to_string(), secret: secret.to_string(), fleet }, addrs);
        }
        n
    }
}

/// Handle `Ev::Lan(Linked)` the same way in every loop: seed, then announce
/// the transport as `Ev::DirectReady`, which starts its reader only after the
/// ready event is queued (the order `UnreadTransport` exists to keep).
pub fn on_linked(conn: &mut Conn, tx: &UnboundedSender<Ev>, ev: LanEvent, log: &dyn crate::host::LogSink) {
    if let LanEvent::Linked { pid, name, secret, fleet, attempt, transport, remote, dialer } = ev {
        log.debug(&format!(
            "lan: {} {name} at {remote} ({pid})",
            if dialer { "linked to" } else { "accepted" }
        ));
        conn.seed_lan(&pid, &name, &secret, fleet, attempt);
        transport.announce(tx, |t| Ev::DirectReady(pid, t, lan::ROUTE_LAN));
    }
}

/// The secrets a LAN link may authenticate with: every LIVE paired device.
/// Revoked records may retain their pair secret in the store (`devices_load`),
/// so they are filtered here as well: a revoked device must not even complete
/// the LAN MAC handshake, not merely be declined later by the resolver or
/// consent. (Fleet siblings are the next step: their link is admitted by
/// certificate after the MAC, and the hello must wait for that; see the design
/// doc's plan.)
pub fn keys(host: &dyn crate::host::HostServices) -> Vec<LanKey> {
    host.devices_load()
        .into_iter()
        .filter(|(name, _)| !host.device_record_revoked(name))
        .map(|(name, secret)| LanKey { name, secret, fleet: false })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tunlion's own overlay is an interface like any other: the address of
    /// laptop on it is dropped only when dialing laptop, and a third device's
    /// overlay address stays a valid path.
    #[test]
    fn ownership_guard_uses_stored_and_live_overlay_addresses() {
        let own = Ownership::build(
            vec![("laptop".to_string(), Some("fdf1:1af7:c30d::a".to_string()), Some("100.120.0.5".to_string()))],
            vec![("desktop".to_string(), "fdf1:1af7:c30d::b".parse().unwrap())],
        );
        let cands: Vec<SocketAddr> = vec![
            "[fdf1:1af7:c30d::a]:47821".parse().unwrap(),
            "100.120.0.5:47821".parse().unwrap(),
            "[fdf1:1af7:c30d::b]:47821".parse().unwrap(),
            "[::ffff:100.120.0.5]:47821".parse().unwrap(),
            "192.168.1.4:47821".parse().unwrap(),
        ];
        assert_eq!(
            not_circular("laptop", cands.clone(), &own),
            vec![cands[2], cands[4]],
            "laptop's own overlay addresses, v4-mapped included, are not dialed for laptop"
        );
        assert_eq!(not_circular("desktop", cands.clone(), &own), vec![cands[0], cands[1], cands[3], cands[4]]);
    }
}
