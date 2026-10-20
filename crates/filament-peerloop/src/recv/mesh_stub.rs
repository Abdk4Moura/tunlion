//! The reduced-profile shape of the overlay endpoint.
//!
//! When `mesh` is off the loop has no overlay (`l3 = None`). The few arms that
//! inspect it must still type-check, so this trait mirrors only the routing
//! methods those arms call. There is no TUN, no route and no overlay package in
//! this profile; every method here would be unreachable because the value is
//! always `None`.

use filament_transport::net::Transport;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

pub trait MeshTunnel: Send + Sync + 'static {
    fn my_addr(&self) -> Option<Ipv6Addr>;
    fn my_addr_v4(&self) -> Option<Ipv4Addr>;
    fn is_userspace(&self) -> bool;
    fn identity_addrs(&self) -> Option<(Ipv6Addr, Ipv4Addr)>;
    async fn names_insert(&self, _pid: &str, _name: &str, _v6: Ipv6Addr, _v4: Option<Ipv4Addr>) {}
    async fn refresh_hosts(&self) {}
    async fn rename_peer(&self, _pid: &str, _name: &str) -> bool {
        false
    }
    async fn peers_with_transport(&self) -> Vec<(String, IpAddr, Arc<dyn Transport>)> {
        Vec::new()
    }
    async fn reconcile_routes(&self) {}
    async fn remove_by_pid(&self, _pid: &str) {}
    async fn accept_seq(&self, _pubkey: &[u8; 32], _seq: u64) -> bool {
        false
    }
    async fn add_peer(
        &self,
        _pid: &str,
        _who: &str,
        _v6: IpAddr,
        _v4: Option<Ipv4Addr>,
        _t: Arc<dyn Transport>,
    ) {
    }
    async fn set_peer_subnets(&self, _pid: &str, _t: &Arc<dyn Transport>, _cidrs: &[String]) {}
    async fn peer_overlay_of(&self, _pid: &str) -> Option<IpAddr> {
        None
    }
}
