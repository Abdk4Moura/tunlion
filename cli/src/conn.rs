//! CLI shim over `filament_peerloop::conn`.
//!
//! `Conn`, `Link` and the peer-loop state moved into the crate in issue #465
//! slice 3 with `git mv`, so this file is only the name every command module
//! already imports. The two helpers whose callers live in modules this slice may
//! not edit (`recv_cmd`, `renewal_lifecycle`) stay in `host_impl`: they render
//! and read the keystore, which is the host's job, and re-exporting them here
//! keeps `crate::conn::dropped_no_transport` and `owner_pub_for_resources`
//! resolving unchanged.
#![allow(unused_imports)]

pub(crate) use crate::host_impl::{dropped_no_transport, owner_pub_for_resources};
pub(crate) use filament_peerloop::conn::*;
