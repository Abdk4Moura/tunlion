//! CLI shim over `filament_peerloop::link_manager`.
//!
//! Placement, warm-reuse and upgrade-verify decisions moved into the crate with
//! the link table they decide about. `daemon_ctl` still imports two names from
//! here, so the module name stays.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::link_manager::*;
