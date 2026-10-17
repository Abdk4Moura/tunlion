//! CLI shim over `filament_peerloop::local`.
//!
//! The same-machine TCP transport moved into the crate with `Conn`, its only
//! user. Kept as a module so `crate::local::...` still resolves.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::local::*;
