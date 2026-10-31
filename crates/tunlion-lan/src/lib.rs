//! Local discovery for tunlion, as a protocol core with no I/O.
//!
//! The normative description is `docs/protocol/local-discovery.md`; the test
//! vectors in `vectors/v1.json` are checked against this crate by
//! `tests/conformance.rs`, and any other implementation (the Android app, the
//! browser, a third-party client) can run the same file.
//!
//! - [`wire`]: beacon bytes, presence tags, epochs, the pairing label.
//! - [`mdns`]: the DNS-SD carrier of the same beacon.
//! - [`iface`]: interfaces by capability and the bounded unicast sweep.
//! - [`record`]: the hello sent over an authenticated link, the remembered
//!   addresses built from it, and the circular-route guard.
//! - [`engine`]: a sans-IO state machine an adapter drives with time and
//!   datagrams.

pub mod engine;
pub mod iface;
pub mod mdns;
pub mod record;
pub mod wire;
