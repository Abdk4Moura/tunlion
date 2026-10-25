//! CLI shim for the L3 overlay data plane.
//!
//! The implementation moved, whole, to `filament-peerloop::l3`: the same TUN and
//! userspace-netstack paths, routes, exit-route plan and MagicDNS machinery the
//! daemon used before. This module only supplies the two facts that are still
//! the CLI's own — the `advertise-routes` setting and this machine's short name —
//! and re-exports the library API (`L3::start`, `dial`, `bind`, `addr_of`,
//! `is_verified_peer`, …). No implementation is duplicated here.

pub use filament_peerloop::l3::*;

/// The prefixes this machine offers to carry, read from the CLI's setting.
pub fn advertised_prefixes() -> Vec<String> {
    filament_peerloop::mesh::advertised_prefixes(
        crate::settings::get_str("advertise-routes", None).as_deref(),
    )
}

/// This machine's short hostname (MagicDNS, the `init` name suggestion, the
/// forward-to-self check). Asks the OS through the CLI's platform adapter.
pub fn hostname() -> String {
    filament_peerloop::mesh::short_host_label(&crate::platform::os_hostname().unwrap_or_default())
}
