//! The transport ladder: an authenticated byte pipe to a peer behind NAT, that
//! fails over.
//!
//! `net` is signalling and WebRTC; `direct` is authenticated QUIC with the
//! fallback ladder. Both implement the `Transport` trait, which is the whole
//! interface the layers above need: send bytes, receive bytes, tell me the
//! channel binding, tell me the route.
//!
//! # What it does not know
//!
//! Nothing here knows how to draw on a terminal, where this machine keeps config
//! files, how the user configured membership, or how to enumerate local
//! interfaces. It used to know all four. Those are asked through `hooks`, each
//! with a safe default, so a consumer that installs none still gets a working
//! transport with diagnostics discarded.
//!
//! That separation is why this could become a crate at all, and it was done as
//! its own step, verified live, BEFORE the files moved: the transport is what
//! filament's reliability rests on, and a half-verified transport is worse than
//! a coupled one.

pub mod direct;
pub mod hooks;
pub mod net;
