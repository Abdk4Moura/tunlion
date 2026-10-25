//! CLI shim for the L3 TUN/netstack backends.
//!
//! The implementation moved to `filament-peerloop::l3::tun` (the library that
//! owns the overlay data plane). This module keeps every existing
//! `crate::tun::...` call site resolving to the same item; there is no second
//! copy here.
pub use filament_peerloop::l3::tun::*;
