//! The mesh packet plane, as the peer loop sees it.
//!
//! The receive loop owns the ROUTING decisions: which peer announced which
//! address, whether its signature and sequence are fresh, and when a route must
//! be retracted. It does not own the packet endpoint. Creating a TUN device (or
//! a userspace netstack), writing the OS hosts file and knowing this machine's
//! host name are host work, so they arrive through [`crate::host::HostServices`]
//! and this module defines the object that host hands back.
//!
//! What lives here is pure: the interface name the loop must name to the kernel,
//! the mode selector, the `<name>.mesh` sanitizer, the advertised-prefix parse
//! and the two-gate route rule. None of it touches a file, a setting or a
//! terminal, so a caller can test the routing policy without a TUN.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use filament_overlay::Announce;
use filament_transport::net::Transport;

pub mod route;
pub use route::{RouteAcceptance, RoutePolicy, accept_advertised};

/// The TUN interface name the daemon creates for the overlay.
pub const IFNAME: &str = "tunlion0";

/// How the overlay's packet endpoint is provided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum L3Mode {
    /// Kernel TUN when it can be created, else the userspace netstack. The default.
    Auto,
    /// Force the kernel TUN; fail if it can't be created.
    Kernel,
    /// Force the userspace smoltcp netstack (zero privilege; containers/CI/no-sudo).
    Userspace,
}

/// Machine-readable health of this node's L3 packet endpoint.
///
/// `state` is deliberately limited to three words so a script can gate on it:
///
/// - `ready`: a live [`MeshTunnel`] exists and `bind`/`dial` can work.
/// - `starting`: the endpoint is being created (the daemon has not published a
///   result yet). Never interchangeable with `ready`.
/// - `down`: no live endpoint; `reason` says why in one line.
///
/// `mode` distinguishes `kernel` (TUN/Wintun), `userspace` (smoltcp netstack) and
/// `none` (no endpoint). A derived overlay address is NOT evidence that either
/// mode is live, which is the bug this type exists to make unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct L3Status {
    pub state: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl L3Status {
    /// A live endpoint that can bind and dial.
    pub fn ready(mode: &str) -> Self {
        Self { state: "ready".into(), mode: mode.into(), reason: None }
    }

    /// No endpoint yet, but startup is in progress.
    pub fn starting(mode: &str) -> Self {
        Self { state: "starting".into(), mode: mode.into(), reason: None }
    }

    /// No live endpoint. `reason` is the operator-facing cause, never empty.
    pub fn down(mode: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            state: "down".into(),
            mode: mode.into(),
            reason: Some(if reason.trim().is_empty() {
                "no live L3 endpoint".to_string()
            } else {
                reason
            }),
        }
    }

    /// Is this endpoint live enough to bind/dial?
    pub fn is_ready(&self) -> bool {
        self.state == "ready"
    }
}

/// The mode word for a live endpoint.
pub fn l3_mode_word(userspace: bool) -> &'static str {
    if userspace {
        "userspace"
    } else {
        "kernel"
    }
}

/// The prefixes this machine offers to carry, parsed from the setting.
///
/// One parser for every announce path, so a route cannot be forwarded by the
/// kernel but omitted from the wire (or the reverse) because two call sites
/// parsed the same setting differently.
pub fn advertised_prefixes(setting: Option<&str>) -> Vec<String> {
    setting
        .unwrap_or_default()
        .split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect()
}

/// `<name>.mesh` label sanitizer: keep [a-z0-9.-], strip `user@`, trim dashes.
///
/// Pure so the same rule names the local record and a peer's record.
pub fn sanitize_host(name: &str) -> String {
    // If name contains @, extract just the hostname part (user@host -> host)
    let base = name.split('@').last().unwrap_or(name);
    let s: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches('-').to_string()
}

/// `Kabir-MacBook.local` -> `kabir-macbook`: the first DNS label, lowercased,
/// with anything outside [a-z0-9-] turned into `-`, so the name works as a
/// `<name>.mesh` label. Falls back to "device" when nothing usable is left.
pub fn short_host_label(host: &str) -> String {
    let first = host.trim().split('.').next().unwrap_or("");
    let mut label = String::new();
    for c in first.chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_alphanumeric() || c == '-' {
            c
        } else {
            '-'
        };
        if c == '-' && (label.is_empty() || label.ends_with('-')) {
            continue;
        }
        label.push(c);
    }
    let label: String = label.trim_end_matches('-').chars().take(63).collect();
    let label = label.trim_end_matches('-').to_string();
    if label.is_empty() {
        "device".to_string()
    } else {
        label
    }
}

/// Which advertised prefixes may actually be installed from one peer.
///
/// TWO GATES, both required, and they answer different questions:
///
/// - `accept_routes` is the RECEIVER's decision: "do I take routes from this
///   device at all". Off by default, per peer.
/// - `authorized` is the OWNER's decision, carried by a signed CAP_ROUTE grant
///   naming that exact prefix as its resource.
///
/// Requiring both is not belt-and-braces. The grant says the owner designated
/// this device to carry this prefix; accept-routes says this machine wants to
/// route through it. A device can be legitimately granted a prefix that a given
/// peer still has no business sending its traffic through, and a peer can want
/// routes from a device the owner never authorized. Neither implies the other.
///
/// A verified signature on the advertisement is a THIRD, prior condition handled
/// by the caller (`Announce::verify_routes`): it establishes who said it, which
/// is what makes asking these two questions meaningful at all.
pub fn installable_routes<F>(
    advertised: &[String],
    accept_routes: bool,
    authorized: F,
) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    if !accept_routes {
        // Cheap and total: no grant can override the receiver declining.
        return Vec::new();
    }
    advertised
        .iter()
        .filter(|c| authorized(c))
        .cloned()
        .collect()
}

/// One accepted overlay connection, however the host provides it: a kernel
/// TCP stream or a userspace netstack stream. The loop only needs the async
/// byte-stream traits, so the concrete type stays with the host.
pub trait MeshStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> MeshStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// A listening overlay socket, however the host provides it.
#[async_trait::async_trait]
pub trait MeshListener: Send + Sync {
    /// The next connection and its overlay source address.
    async fn accept(&self) -> Result<(Box<dyn MeshStream>, IpAddr), String>;
}

/// The mesh packet endpoint the receive loop drives.
///
/// Every method is a decision the loop already made, carried out by the host:
/// install or retract a route, record a peer's `<name>.mesh` address, sign this
/// node's announce, or open a connection over the overlay. The host owns the
/// device and the files; the loop owns the policy.
///
/// A host that cannot provide an endpoint returns no value from
/// [`crate::host::HostServices::l3_start`], so the loop serves with no overlay
/// and says why. It never constructs one of these itself.
#[async_trait::async_trait]
pub trait MeshTunnel: Send + Sync + 'static {
    /// This node's v6 overlay address (crypto mode only).
    fn my_addr(&self) -> Option<Ipv6Addr>;
    /// This node's v4 overlay address, when dual-stack is on.
    fn my_addr_v4(&self) -> Option<Ipv4Addr>;
    /// Is the endpoint the userspace netstack (no kernel TUN, no host firewall)?
    fn is_userspace(&self) -> bool;
    /// This node's identity addrs, when it has a signing identity.
    fn identity_addrs(&self) -> Option<(Ipv6Addr, Ipv4Addr)>;
    /// Record `name` -> overlay addresses for MagicDNS and refresh the host file.
    async fn names_insert(&self, pid: &str, name: &str, v6: Ipv6Addr, v4: Option<Ipv4Addr>);
    /// Refresh the host's MagicDNS block from the recorded names.
    async fn refresh_hosts(&self);
    /// Sign this node's address bound to `cb`; `None` without an identity.
    fn make_announce(&self, cb: &[u8]) -> Option<Announce>;
    /// Correct a peer's recorded name after its certificate names it.
    async fn rename_peer(&self, pid: &str, name: &str) -> bool;
    /// Every peer on the overlay with the transport its packets ride.
    async fn peers_with_transport(&self) -> Vec<(String, IpAddr, Arc<dyn Transport>)>;
    /// Reconcile kernel routes with the live transports.
    async fn reconcile_routes(&self);
    /// Retract every route a link id installed.
    async fn remove_by_pid(&self, pid: &str);
    /// Accept `seq` from `pubkey` if it is strictly fresh.
    async fn accept_seq(&self, pubkey: &[u8; 32], seq: u64) -> bool;
    /// Attach a verified peer to the overlay.
    async fn add_peer(
        &self,
        pid: &str,
        who: &str,
        v6: IpAddr,
        v4: Option<Ipv4Addr>,
        t: Arc<dyn Transport>,
    );
    /// Install (or withdraw, with an empty list) the prefixes a peer carries.
    async fn set_peer_subnets(&self, pid: &str, t: &Arc<dyn Transport>, cidrs: &[String]);
    /// The overlay address recorded for a link id.
    async fn peer_overlay_of(&self, pid: &str) -> Option<IpAddr>;
    /// Resolve a verified peer name to its v6 overlay address.
    async fn addr_of(&self, name: &str) -> Option<Ipv6Addr>;
    /// Open an overlay connection to `dst:port`.
    async fn dial(&self, dst: Ipv6Addr, port: u16) -> Result<Box<dyn MeshStream>, String>;
    /// Listen on `port` on this node's overlay address.
    async fn bind(&self, port: u16) -> Result<Box<dyn MeshListener>, String>;
    /// Is `addr` a verified overlay peer?
    async fn is_verified_peer(&self, addr: IpAddr) -> bool;
    /// The petname recorded for a verified overlay address.
    async fn petname_of(&self, addr: IpAddr) -> Option<String>;
}

#[cfg(test)]
mod l3_status_tests {
    use super::*;

    #[test]
    fn three_states_serialize_with_the_documented_shape() {
        let ready = serde_json::to_value(L3Status::ready("kernel")).unwrap();
        assert_eq!(ready, serde_json::json!({"state":"ready","mode":"kernel"}));
        assert!(L3Status::ready("kernel").is_ready());
        assert_eq!(
            serde_json::to_value(L3Status::ready("userspace")).unwrap()["mode"],
            "userspace"
        );

        let down = serde_json::to_value(L3Status::down("none", "no /dev/net/tun")).unwrap();
        assert_eq!(down["state"], "down");
        assert_eq!(down["mode"], "none");
        assert_eq!(down["reason"], "no /dev/net/tun");
        assert!(!L3Status::down("none", "x").is_ready());

        let starting = serde_json::to_value(L3Status::starting("kernel")).unwrap();
        assert_eq!(starting["state"], "starting");
        assert!(!L3Status::starting("kernel").is_ready());
    }

    /// A blank reason must never become an unexplained `down`.
    #[test]
    fn down_always_carries_a_reason() {
        let s = L3Status::down("none", "   ");
        assert_eq!(s.reason.as_deref(), Some("no live L3 endpoint"));
    }

    #[test]
    fn mode_words_are_the_contract_words() {
        assert_eq!(l3_mode_word(true), "userspace");
        assert_eq!(l3_mode_word(false), "kernel");
    }
}
