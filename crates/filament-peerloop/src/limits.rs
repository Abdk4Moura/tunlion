//! Limits and wire markers the peer loop shares with the command modules.
//!
//! These are protocol and ladder bounds, not host facts, so they live with the
//! state that enforces them. The CLI re-exports every one of them from its
//! `shared_defs` module under the same names, so no call site changed.

use std::time::Duration;

/// C4/C6/C21: how long we wait for a vanished peer to rejoin. UNWARNED is the
/// blind default; a peer that announced `brb` gets its declared ttl instead.
pub const REJOIN_WINDOW: Duration = Duration::from_secs(120);

/// C3/C4: connection (re)establishment attempts before failing honestly.
pub const MAX_ATTEMPTS: u32 = 5;

/// P0 (GAP-1): stall-correction ladder bound. Attempt 0 is rung (a) (resume on
/// the same transport); attempts 1..STALL_MAX_REPAIRS are rung (c) (repair the
/// transport in place, a fresh direct dial / ICE-restart).
pub const STALL_MAX_REPAIRS: u32 = 5;

/// P5 (GAP-6): reserved sid for the relay->direct upgrade VERIFY heartbeat.
pub const VERIFY_PROBE_SID: u32 = 0x7FFF_FFFF;

/// Display name for a fleet link before its certificate names it.
pub const FLEET_LINK_NAME: &str = "fleet: unverified";
