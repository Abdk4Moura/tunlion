//! Host glue for `filament-fleet`, as the CLI's process adapter.
//!
//! The rendezvous facts, owner key and fleet-hello builder moved to
//! `filament_peerloop::recv::fleet_rv::FleetService` with an explicit store
//! root, overlay key, announce sequence path and route list. This module only
//! resolves the process paths and the configured advertised prefixes.

use anyhow::Result;
use serde_json::Value;

pub use filament_fleet::*;

fn service() -> filament_peerloop::recv::fleet_rv::FleetService {
    filament_peerloop::recv::fleet_rv::FleetService::new(
        crate::devices_store::store(),
        filament_peerloop::recv::store::OverlayKey::new(
            crate::platform::Paths::config_path("overlay.ed25519"),
        ),
        crate::platform::Paths::config_path("overlay.announce-seq"),
        crate::display_name(),
        crate::l3::advertised_prefixes(),
    )
}

/// The fleet rendezvous secret this device holds, if any (64 hex chars).
pub fn rv() -> Option<String> {
    service().rv()
}

/// The owner's copy, minted on first use.
pub fn rv_load_or_create() -> Result<String> {
    service().rv_load_or_create()
}

/// Persist a fleet rendezvous secret received at enrollment.
pub fn store_rv(hex_secret: &str) -> Result<()> {
    service().store_rv(hex_secret)
}

/// The fleet meeting point, derived from the rendezvous secret.
pub fn channel() -> Option<String> {
    service().channel()
}

pub fn is_fleet_channel(ch: &str) -> bool {
    service().is_fleet_channel(ch)
}

/// Build our `fleet-hello` for a link whose channel binding is `cb`.
pub fn make_hello(cb: &[u8], name: &str) -> Result<Value> {
    service().make_hello(cb, name)
}

/// Our own owner key, as every fleet check needs it.
pub fn my_owner_pub() -> Option<[u8; 32]> {
    service().owner_pub()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_rv_rejects_a_wrong_length_secret() {
        assert!(store_rv("abcd").is_err());
        assert!(store_rv("zz".repeat(32).as_str()).is_err());
    }

    #[test]
    fn is_fleet_channel_is_false_for_empty() {
        assert!(!is_fleet_channel(""));
    }
}
