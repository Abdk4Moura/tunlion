//! CLI shim over `filament_peerloop::session`.
//!
//! The convergent session (C30) moved into the peer-loop crate in issue #465
//! slice 3 with `git mv`: it is the desired signaling state and the idempotent
//! sync that converges the server onto it, with no terminal, host or CLI
//! reference in it. The module name stays because every command loop already
//! imports `session::Session`; this file is only that name.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::session::*;
