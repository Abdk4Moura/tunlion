//! CLI shim over `filament_peerloop::holepunch`.
//!
//! Rung-2 STUN discovery and UDP punch moved into the crate with the ladder that
//! calls it. `doctor` still reads the STUN helpers from `crate::holepunch`, and
//! those are protocol and network, not terminal, so they moved unchanged.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::holepunch::*;
