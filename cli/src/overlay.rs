//! Host glue for `filament-overlay`.
//!
//! The addressing, the announce ceremony and the replay rule live in the crate,
//! which knows nothing about this machine. What stays here is the only part that
//! does: WHERE the key and sequence files live, and generating the key on first
//! use. Three functions, and they are the reason the rest could leave.

use anyhow::{Context, Result};
use ring::signature::Ed25519KeyPair;

pub use filament_overlay::*;

fn key_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("overlay.ed25519")
}

fn seq_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("overlay.announce-seq")
}

/// The next announce sequence number, persisted beside the identity key.
///
/// See `filament_overlay::next_announce_seq_at` for WHY it is persisted: an
/// in-process counter restarts at zero and permanently locks this device out of
/// peers that still hold a higher last-seen.
pub fn next_announce_seq() -> u64 {
    filament_overlay::next_announce_seq_at(&seq_path())
}

/// Load the overlay key, generating and persisting it (PKCS8, 0600) on first
/// use. Kept separate from the ssh managed key so neither format constrains the
/// other.
pub fn load_identity() -> Result<Identity> {
    let path = key_path();
    let pkcs8 = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            let rng = ring::rand::SystemRandom::new();
            let doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| anyhow::anyhow!("overlay key generation failed"))?;
            crate::platform::SecretFile::write(&path, doc.as_ref())
                .context("write overlay key")?;
            doc.as_ref().to_vec()
        }
    };
    Identity::from_pkcs8(&pkcs8)
}

/// Convenience: load the overlay key and return just the 32-byte public key.
pub fn overlay_pubkey_bytes() -> Result<[u8; 32]> {
    Ok(load_identity()?.public_key_bytes())
}

/// Convenience: sign arbitrary bytes with this device's overlay private key.
pub fn overlay_sign_possession(msg: &[u8]) -> Result<[u8; 64]> {
    Ok(load_identity()?.sign(msg))
}
