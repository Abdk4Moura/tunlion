//! CLI shim over `filament_peerloop::send::liveness`.
//!
//! The sentences and bounds moved with the send engine. Keeping this module
//! name means every existing CLI call site resolves to the one implementation.

#![allow(unused_imports)]

pub(crate) use filament_peerloop::send::liveness::{
    disconnect_line, receiver_gone_message, still_waiting_line, HEARTBEAT,
};
