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

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{add_route, ensure_hosts_writable, ensure_net_admin_for_l3, Tun};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{add_route, ensure_hosts_writable, ensure_net_admin_for_l3, Tun};

// Windows (Wintun) backend lands in Phase 3; until then `l3` excludes Windows.
