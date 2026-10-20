//! Host glue for `filament-overlay`.
//!
//! The addressing, the announce ceremony and the replay rule live in the crate,
//! which knows nothing about this machine. The key load/generate lives in the
//! library's explicit-path `OverlayKey`; what stays here is WHERE the key and
//! sequence files live and the sequence helper.

use anyhow::Result;

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
/// use. The generation and the file format are the library's explicit-path
/// `OverlayKey`; this module only names the process path.
pub fn load_identity() -> Result<Identity> {
    filament_peerloop::recv::store::OverlayKey::new(key_path()).identity()
}

/// Convenience: load the overlay key and return just the 32-byte public key.
pub fn overlay_pubkey_bytes() -> Result<[u8; 32]> {
    Ok(load_identity()?.public_key_bytes())
}

/// Convenience: sign arbitrary bytes with this device's overlay private key.
pub fn overlay_sign_possession(msg: &[u8]) -> Result<[u8; 64]> {
    Ok(load_identity()?.sign(msg))
}
