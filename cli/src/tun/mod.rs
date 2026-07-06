//! Cross-platform L3 TUN device + privilege/route helpers.
//!
//! The overlay data plane (`l3.rs`) is written against one small surface and never
//! sees OS specifics: the `Tun` type (`open`/`name`/`recv`/`send`, moving raw IP
//! packets), `add_route` (point the overlay prefix at the device), and the
//! privilege helpers (`ensure_net_admin_for_l3`, `ensure_hosts_writable`). Each OS
//! supplies a backend that implements exactly that surface:
//!
//! - Linux (`linux`):  `/dev/net/tun` + `TUNSETIFF` ioctl, iproute2, CAP_NET_ADMIN.
//! - macOS (`macos`):  `utun` via a PF_SYSTEM control socket, `ifconfig`/`route`, root.
//! - Windows (`windows`): Wintun (`wintun.dll`), the IP Helper API, Administrator.
//!
//! `recv`/`send` always exchange bare IP packets with `l3.rs`; any per-OS framing
//! (macOS prepends a 4-byte address-family header, Linux with IFF_NO_PI does not)
//! is added/stripped inside the backend so the overlay logic stays portable.

/// The overlay's packet endpoint, abstracted so `l3.rs` is agnostic to HOW bare IP
/// packets reach the wire. `KernelTun` (below) is the privileged backend that hands
/// packets to the OS stack via a kernel TUN; a userspace smoltcp `NetstackTun`
/// (added later) implements the same surface with ZERO privilege. `recv` yields an
/// OUTBOUND packet the local stack wants sent to a peer (l3.rs routes it by dest IP
/// to that peer's datagram transport); `send` injects a peer's INBOUND packet into
/// the local stack. Byte-exact bare IP in both directions (per-OS framing, e.g.
/// macOS's 4-byte AF header, is added/stripped inside the backend).
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    /// The interface name (Linux honors `filament0`; macOS assigns `utunN`).
    fn name(&self) -> &str;
    /// Await the next OUTBOUND bare IP packet the local stack wants on the wire.
    async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize>;
    /// Inject one INBOUND bare IP packet (received from a peer) into the local stack.
    async fn send(&self, packet: &[u8]) -> anyhow::Result<usize>;
}

// Userspace (zero-privilege) overlay backend. Platform-independent (pure smoltcp,
// no OS device). Selected by l3.rs when there is no kernel TUN.
mod netstack;
pub use netstack::{NetstackListener, NetstackStream, NetstackTun, OverlayAddr};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{add_addr, add_route, ensure_hosts_writable, ensure_net_admin_for_l3, KernelTun};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{add_addr, add_route, ensure_hosts_writable, ensure_net_admin_for_l3, KernelTun};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_addr, add_route, ensure_hosts_writable, ensure_net_admin_for_l3, KernelTun};
