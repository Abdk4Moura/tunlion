//! CLI shim over `filament_peerloop::resilience`.
//!
//! The stall ladder's policy and liveness phase machine moved into the crate
//! with `Conn`, which is their only caller. The name stays so any command module
//! that still says `crate::resilience::...` resolves unchanged.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::resilience::*;
