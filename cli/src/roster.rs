//! Owner-signed mesh roster, as the CLI's process adapter.
//!
//! Verification, minting and storage moved to `filament_peerloop::recv::roster`
//! with the explicit-root device store. This module only resolves the process
//! config/self key and forwards; there is no second accept rule.

use anyhow::Result;
use filament_id::{RosterDevice, UserKey};
use serde_json::Value;

pub(crate) use filament_peerloop::recv::roster::{RosterStaleness, roster_is_newer};

/// Short on purpose (amendment 3): the roster authorizes nothing, so a spoke
/// whose roster expires loses nothing functional. The env read is a CLI
/// adapter; the library takes the TTL explicitly.
pub fn roster_ttl_secs() -> u64 {
    std::env::var("TUNLION_ROSTER_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(15 * 60)
}

fn store() -> filament_peerloop::recv::store::DeviceStore {
    crate::devices_store::store()
}

fn self_pub() -> Option<[u8; 32]> {
    crate::overlay::overlay_pubkey_bytes().ok()
}

pub fn owner_snapshot(owner_pub: &[u8; 32]) -> Vec<RosterDevice> {
    filament_peerloop::recv::roster::owner_snapshot(&store(), owner_pub, self_pub().as_ref())
}

pub fn mint_roster(owner: &UserKey, now: u64) -> Result<(Value, bool)> {
    filament_peerloop::recv::roster::mint_roster(
        &store(),
        owner,
        now,
        self_pub().as_ref(),
        roster_ttl_secs(),
    )
}

pub fn verify_and_store_roster(blob: &Value, owner_pub: &[u8; 32], now: u64) -> Result<bool> {
    filament_peerloop::recv::roster::verify_and_store_roster(&store(), blob, owner_pub, now)
}

pub fn stored_roster() -> Option<Value> {
    filament_peerloop::recv::roster::stored_roster(&store())
}

pub fn roster_device_names() -> Vec<String> {
    filament_peerloop::recv::roster::roster_device_names(&store(), self_pub().as_ref())
}

pub fn roster_staleness(now: u64) -> RosterStaleness {
    filament_peerloop::recv::roster::roster_staleness(&store(), now)
}
