//! CLI shim over `filament_peerloop::recv::signaling_health`.
//!
//! The signaling link's health record moved with the receive dispatch loop, so
//! the loop and the CLI's `status`/`doctor` read the SAME process state. Keeping
//! a second copy here made the daemon's `cap-status` report `unknown` while the
//! loop was reconnecting.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::recv::signaling_health::*;
