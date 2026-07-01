//! L3 (serve_tun) manager: one TUN for this node, a route table mapping a peer's
//! overlay IP to its link transport, and the datagram pumps. Lives in the `up`
//! daemon, which owns the QUIC connections the datagrams ride.
//!
//! Data path (symmetric on both ends):
//!   TUN read  -> dest IP -> route lookup -> peer.send_datagram(packet)
//!   peer datagram -> TUN write
//!
//! The daemon's link layer is already a full mesh of authenticated links; L3 just
//! attaches an IP plane to it. Each node's overlay address is derived from its
//! Ed25519 overlay key (see `overlay`); peers learn and TRUST each other's address
//! via a SIGNED `l3-announce` verified against the live link's channel binding
//! (main.rs). Only direct-QUIC links carry datagrams; relay links are skipped for
//! now (no L3 over relay yet).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use crate::net::Transport;
use crate::overlay::{Announce, Identity};
use crate::tun::Tun;

/// The TUN interface name the daemon creates for the overlay.
const IFNAME: &str = "filament0";

/// A routed peer: the transport its overlay packets ride, plus the reader task so
/// a replaced/removed peer's reader is aborted (never leaked, review fix #2).
struct PeerRoute {
    transport: Arc<dyn Transport>,
    reader: AbortHandle,
}

pub struct L3 {
    tun: Arc<Tun>,
    /// overlay dest IP -> that peer's route. Read on the TUN hot path, written as
    /// links come and go. The hot path takes the lock only to clone one Arc.
    routes: Arc<Mutex<HashMap<IpAddr, PeerRoute>>>,
    /// pid -> overlay IP, so a link drop (keyed by pid in main.rs) can retract the
    /// right route.
    by_pid: Mutex<HashMap<String, IpAddr>>,
    /// This node's overlay identity (crypto mode) for signing announces; `None` in
    /// manual/PSK addressing mode (no announce, routes added out of band).
    identity: Option<Identity>,
    /// Monotonic announce sequence so a peer can ignore a stale re-announce.
    seq: AtomicU64,
}

impl L3 {
    /// Start the overlay. In CRYPTO mode (`identity` set) the TUN takes this node's
    /// derived `<addr>/128` and the whole overlay prefix is routed to it; in manual
    /// mode `cidr` is used verbatim (PSK/lab). Spawns the TUN->datagram reader.
    /// Needs CAP_NET_ADMIN.
    pub fn start(cidr: &str, mtu: u32, identity: Option<Identity>) -> Result<Arc<L3>> {
        cidr.split('/')
            .next()
            .and_then(|a| a.parse::<IpAddr>().ok())
            .ok_or_else(|| anyhow!("bad overlay address '{cidr}', want IP/PREFIX"))?;
        let tun = Arc::new(Tun::open(IFNAME, cidr, mtu)?);
        // Crypto mode: overlay addresses are scattered /128s across the shared ULA
        // prefix, so route the whole prefix to the TUN (userspace demuxes per /128).
        if identity.is_some() {
            crate::tun::add_route(&crate::overlay::prefix_cidr(), IFNAME)?;
        }
        let routes: Arc<Mutex<HashMap<IpAddr, PeerRoute>>> = Arc::new(Mutex::new(HashMap::new()));
        let l3 = Arc::new(L3 {
            tun: tun.clone(),
            routes: routes.clone(),
            by_pid: Mutex::new(HashMap::new()),
            identity,
            seq: AtomicU64::new(1),
        });

        // TUN -> datagram: one reader for the whole node. Each packet's dest IP
        // selects the peer link (cryptokey-routing style). A miss (no route) or a
        // send error is a silent drop, correct for a lossy datagram plane.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(_) => break, // TUN closed -> daemon shutting down
                };
                let Some(dst) = dest_ip(&buf[..n]) else { continue };
                let peer = routes.lock().await.get(&dst).map(|r| r.transport.clone());
                if let Some(t) = peer {
                    let _ = t.send_datagram(&buf[..n]);
                }
            }
        });
        Ok(l3)
    }

    /// This node's overlay address (crypto mode only).
    pub fn my_addr(&self) -> Option<Ipv6Addr> {
        self.identity.as_ref().map(|i| i.addr())
    }

    /// Build a signed announce of our address bound to link channel-binding `cb`.
    /// `None` in manual mode (no identity to sign with).
    pub fn make_announce(&self, cb: &[u8]) -> Option<Announce> {
        let id = self.identity.as_ref()?;
        Some(id.announce(self.seq.fetch_add(1, Ordering::Relaxed), cb))
    }

    /// Attach a VERIFIED peer to the overlay: route `peer_ip` (already checked to
    /// match the announcing key + link, see main.rs) to `t`, keyed by `pid` so a
    /// link drop can retract it. Aborts any prior reader for this IP or pid, so a
    /// repair/supersede never leaks the old reader or its connection (fix #2).
    /// Skips links that can't carry datagrams (relay).
    pub async fn add_peer(&self, pid: &str, peer_ip: IpAddr, t: Arc<dyn Transport>) {
        if !t.supports_datagrams() {
            return;
        }
        // Retire any previous route this pid pointed at (its overlay IP may even
        // have changed), then the one currently at this IP.
        if let Some(old_ip) = self.by_pid.lock().await.insert(pid.to_string(), peer_ip) {
            if old_ip != peer_ip {
                self.retract(old_ip).await;
            }
        }
        let tun = self.tun.clone();
        let routes = self.routes.clone();
        let t_reader = t.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = t_reader.recv_datagram() => match r {
                        Ok(pkt) => { let _ = tun.send(&pkt).await; }
                        Err(_) => break, // link closed
                    },
                    // Wake periodically so a zombie link (alive at QUIC but dead
                    // for datagrams) is noticed even if read_datagram never errors.
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        if !t_reader.is_alive() { break; }
                    }
                }
            }
            let mut map = routes.lock().await;
            if let Some(cur) = map.get(&peer_ip) {
                if Arc::ptr_eq(&cur.transport, &t_reader) {
                    map.remove(&peer_ip);
                }
            }
        });
        let mut map = self.routes.lock().await;
        if let Some(prev) = map.insert(peer_ip, PeerRoute { transport: t, reader: handle.abort_handle() }) {
            prev.reader.abort(); // stop the superseded reader now
        }
    }

    /// Retract the route for a specific overlay IP (aborting its reader).
    async fn retract(&self, ip: IpAddr) {
        if let Some(r) = self.routes.lock().await.remove(&ip) {
            r.reader.abort();
        }
    }

    /// Retract whatever route a link (by pid) installed, on link drop. Keeps the
    /// route table and reader tasks in step with the link layer.
    pub async fn remove_by_pid(&self, pid: &str) {
        let ip = self.by_pid.lock().await.remove(pid);
        if let Some(ip) = ip {
            self.retract(ip).await;
        }
    }
}

/// Standalone point-to-point serve_tun (no signaling): open `dev` with `tun_addr`
/// and pump IP packets both ways over an already-authenticated QUIC connection's
/// datagrams. Runs until the link or TUN closes. Backs `filament serve-tun` and
/// the lab's filament-l3 carrier (WireGuard-style known-endpoint overlay).
pub async fn run_point_to_point(
    conn: quinn::Connection,
    dev: &str,
    tun_addr: &str,
    mtu: u32,
) -> Result<()> {
    let tun = Arc::new(Tun::open(dev, tun_addr, mtu)?);
    // datagram -> TUN (background)
    let c = conn.clone();
    let t = tun.clone();
    let down = tokio::spawn(async move {
        while let Ok(pkt) = c.read_datagram().await {
            let _ = t.send(&pkt).await;
        }
    });
    // TUN -> datagram (this task). Select against conn.closed() so a peer that
    // drops while our TUN is idle ends the pump promptly, instead of parking in
    // tun.recv() forever (the process would otherwise hang holding filament0).
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = conn.closed() => break,
            r = tun.recv(&mut buf) => {
                let n = match r {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        down.abort();
                        return Err(e);
                    }
                };
                // A too-big packet errors (over the datagram MTU) and is dropped;
                // a closed link ends the pump.
                if conn.send_datagram(bytes::Bytes::copy_from_slice(&buf[..n])).is_err()
                    && conn.close_reason().is_some()
                {
                    break;
                }
            }
        }
    }
    down.abort();
    Ok(())
}

/// Destination IP of a raw IP packet (v4 header dst at [16..20], v6 at [24..40]).
/// `None` for a truncated or non-IP frame.
fn dest_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]])),
        6 if pkt.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::dest_ip;
    use std::net::IpAddr;

    #[test]
    fn parses_ipv4_dest() {
        // minimal IPv4 header: version/IHL=0x45, dst=10.9.0.2 at bytes 16..20
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[10, 9, 0, 2]);
        assert_eq!(dest_ip(&p), Some(IpAddr::from([10, 9, 0, 2])));
    }

    #[test]
    fn parses_ipv6_dest() {
        let mut p = [0u8; 40];
        p[0] = 0x60;
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        p[24..40].copy_from_slice(&dst);
        assert_eq!(dest_ip(&p), Some(IpAddr::from(dst)));
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        assert_eq!(dest_ip(&[]), None);
        assert_eq!(dest_ip(&[0x45, 0, 0]), None); // too short for v4
        assert_eq!(dest_ip(&[0x70, 0, 0, 0]), None); // not v4/v6
    }
}
