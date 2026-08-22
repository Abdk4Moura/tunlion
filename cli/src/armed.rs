//! The armed set: which auth keys are outstanding and must keep the daemon
//! subscribed to the enrollment room.
//!
//! #205/#211 taught the hard way that this must be a FILE, not process memory.
//! In memory it lived in the daemon alone, so the only way a mint could tell
//! the daemon "an invitation is outstanding" was IPC, and IPC is the one thing
//! with no portable form (a unix socket on unix, nothing on Windows, a bind
//! race everywhere). File-backed, the mint writes `armed.json` directly and the
//! daemon's per-tick arm-gate reads it; no IPC, no platform branch, no race,
//! and a daemon restart no longer silently disarms every outstanding
//! invitation.
//!
//! The file holds only `key_id` (the enroll public half, hex) and `expires`
//! (absolute unix seconds), both non-secret. Enrollment still requires the
//! signed invitation, so a burned key lingering until expiry is harmless.

use std::path::PathBuf;

use serde_json::json;

fn armed_path() -> PathBuf {
    crate::platform::Paths::config_path("armed.json")
}

struct ArmedEntry {
    key_id: String,
    expires: u64,
}

fn load() -> Vec<ArmedEntry> {
    let raw = match std::fs::read_to_string(armed_path()) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { return Vec::new() };
    let arr = v.as_array().cloned().unwrap_or_default();
    arr.iter()
        .filter_map(|e| {
            let key_id = e["key_id"].as_str()?.to_string();
            let expires = e["expires"].as_u64()?;
            Some(ArmedEntry { key_id, expires })
        })
        .collect()
}

fn save(entries: &[ArmedEntry]) {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| json!({ "key_id": e.key_id, "expires": e.expires }))
        .collect();
    let Ok(body) = serde_json::to_string_pretty(&arr) else { return };
    // SecretFile::write_str is owner-only (0600) and atomic on POSIX, so the
    // daemon never reads a half-written array.
    let _ = crate::platform::SecretFile::write_str(&armed_path(), &body);
}

/// Record that an auth key is outstanding until `expires_at` (absolute unix
/// seconds). Dedupes by key_id. The mint writes this directly; the daemon's
/// per-tick arm-gate reads it.
pub fn arm(key_id: String, expires_at: u64) {
    let mut entries = load();
    entries.retain(|e| e.key_id != key_id);
    entries.push(ArmedEntry { key_id, expires: expires_at });
    save(&entries);
}

/// Drop a key from the armed set (called when it burns, or on explicit disarm).
pub fn disarm(key_id: &str) {
    let mut entries = load();
    entries.retain(|e| e.key_id != key_id);
    save(&entries);
}

/// Any unexpired armed key? Prunes expired entries on read, so the file self-
/// cleans and a stale entry never keeps the room open.
pub fn is_armed() -> bool {
    let now = crate::capability::now_secs();
    let mut entries = load();
    let before = entries.len();
    entries.retain(|e| e.expires > now);
    if entries.len() != before {
        save(&entries);
    }
    !entries.is_empty()
}
