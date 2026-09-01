//! Host glue for `filament-fleet`.
//!
//! The admission ceremony and the per-peer conversation live in the crate, which
//! knows nothing about this machine. What stays here is the part that does: the
//! rendezvous secret on disk, the owner key in the keystore, this device's own
//! certificate, and deriving the channel id from all of it.
//!
//! Design: `docs/design-fleet-automesh.md`. Model check:
//! `proofs/fleet_automesh_model.py` (gated in CI by `.github/workflows/proof.yml`).

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

pub use filament_fleet::*;

fn rv_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("fleet.rv")
}

/// The fleet rendezvous secret this device holds, if any (64 hex chars).
pub fn rv() -> Option<String> {
    let raw = std::fs::read_to_string(rv_path()).ok()?;
    let s = raw.trim().to_string();
    (hex::decode(&s).map(|b| b.len()).ok() == Some(32)).then_some(s)
}

/// The owner's copy, minted on first use. Only a device holding the UserKey
/// calls this; every other device RECEIVES the secret at enrollment.
pub fn rv_load_or_create() -> Result<String> {
    if let Some(s) = rv() {
        return Ok(s);
    }
    let s = crate::fresh_secret();
    store_rv(&s)?;
    Ok(s)
}

/// Persist a fleet rendezvous secret received at enrollment.
pub fn store_rv(hex_secret: &str) -> Result<()> {
    if hex::decode(hex_secret).map(|b| b.len()).ok() != Some(32) {
        bail!("fleet rendezvous secret must be 32 bytes of hex");
    }
    crate::platform::SecretFile::write_str(&rv_path(), hex_secret)?;
    Ok(())
}

/// The fleet meeting point, derived from the rendezvous secret with the SAME
/// construction pair channels use, so the signaling server needs no changes and
/// cannot tell the two apart.
pub fn channel() -> Option<String> {
    rv().map(|s| crate::channel_of(&s))
}

pub fn is_fleet_channel(ch: &str) -> bool {
    !ch.is_empty() && channel().as_deref() == Some(ch)
}

/// Build our `fleet-hello` for a link whose channel binding is `cb`.
///
/// This is the host half: load the overlay identity and this device's
/// certificate, then hand both to the crate to assemble.
pub fn make_hello(cb: &[u8], name: &str) -> Result<Value> {
    let id = crate::overlay::load_identity()?;
    let ann = id.announce(crate::overlay::next_announce_seq(), cb);
    let cert = crate::local_device_cert()
        .ok_or_else(|| anyhow!("this device holds no certificate to present"))?;
    Ok(filament_fleet::build_hello(&ann, &cert, name))
}

/// Our own owner key, as every fleet check needs it. The owner device holds the
/// UserKey; a joined device carries the owner's key inside its own certificate.
pub fn my_owner_pub() -> Option<[u8; 32]> {
    if let Ok(Some(uk)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        return Some(uk.public_key_bytes());
    }
    crate::local_device_cert().map(|c| c.user_pub)
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
