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
    /// The name the owner gave the invitee (`add <name> --out`), if any. Not
    /// secret, not signed: it decides only what THIS store calls the device
    /// that enrols with this key.
    name: Option<String>,
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
            let name = e["name"].as_str().map(str::to_string);
            Some(ArmedEntry { key_id, expires, name })
        })
        .collect()
}

fn save(entries: &[ArmedEntry]) {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| match &e.name {
            Some(n) => json!({ "key_id": e.key_id, "expires": e.expires, "name": n }),
            None => json!({ "key_id": e.key_id, "expires": e.expires }),
        })
        .collect();
    let Ok(body) = serde_json::to_string_pretty(&arr) else { return };
    // SecretFile::write_str is owner-only (0600) and atomic on POSIX, so the
    // daemon never reads a half-written array.
    let _ = crate::platform::SecretFile::write_str(&armed_path(), &body);
}

/// Record that an auth key is outstanding until `expires_at` (absolute unix
/// seconds). Dedupes by key_id. The mint writes this directly; the daemon's
/// per-tick arm-gate reads it.
pub fn arm(key_id: String, expires_at: u64, name: Option<String>) {
    let mut entries = load();
    entries.retain(|e| e.key_id != key_id);
    entries.push(ArmedEntry { key_id, expires: expires_at, name });
    save(&entries);
}

/// The name the owner chose for whoever enrols with this key, while the key
/// is outstanding. `add beta --out f` then `join f` used to file the device
/// under the JOINER's hostname, not "beta": the owner's choice was dropped at
/// the mint.
pub fn invitee_name(key_id: &str) -> Option<String> {
    let now = crate::capability::now_secs();
    load()
        .into_iter()
        .find(|e| e.key_id == key_id && e.expires > now)
        .and_then(|e| e.name)
        .filter(|n| !n.trim().is_empty())
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

#[cfg(test)]
mod invitee_name_tests {
    #[test]
    fn the_owner_chosen_name_rides_with_its_key_until_expiry() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!("fil-armed-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let later = crate::capability::now_secs() + 600;
        super::arm("aa".repeat(32), later, Some("beta".into()));
        super::arm("bb".repeat(32), later, None);
        super::arm("cc".repeat(32), 1, Some("gone".into()));
        assert_eq!(super::invitee_name(&"aa".repeat(32)).as_deref(), Some("beta"));
        assert_eq!(super::invitee_name(&"bb".repeat(32)), None, "unnamed invitation");
        assert_eq!(super::invitee_name(&"cc".repeat(32)), None, "an expired key names nobody");
        assert_eq!(super::invitee_name(&"dd".repeat(32)), None);
        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
