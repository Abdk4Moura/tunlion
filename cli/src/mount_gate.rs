//! CLI shim over `filament_peerloop::mount::gate`.
//!
//! The pure mount rules moved with the endpoint. This module keeps the old
//! names and the one store-shape test that needs the CLI's device store
//! (`device_caps::device_allows_at`); the rules themselves need no host.
#![allow(unused_imports)]
#![allow(unused_imports)]

pub(crate) use filament_peerloop::mount::gate::{confine_mount_root, mount_legacy_allowed};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_caps::device_allows_at;
    use std::path::{Path, PathBuf};

    fn store(dir: &Path) -> PathBuf {
        let p = dir.join("devices.json");
        std::fs::write(
            &p,
            serde_json::to_string(&serde_json::json!([
                {"name": "phone", "secret": "a".repeat(64), "v": 2, "caps": ["transfer"]},
                {"name": "laptop", "secret": "b".repeat(64), "v": 2, "caps": ["transfer", "mount"]},
            ]))
            .unwrap(),
        )
        .unwrap();
        p
    }

    /// The record shapes the acceptor sees: a device enrolled transfer-only and
    /// one enrolled with the transfer+mount default. This is the store rule the
    /// server relies on; the pure gate only receives its boolean.
    #[test]
    fn transfer_only_device_cannot_mount() {
        let dir = std::env::temp_dir().join(format!("fil-mount-gate-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = store(&dir);
        let grants = device_allows_at(&p, "phone", "mount");
        assert!(!grants, "a transfer-only record must not hold mount");
        assert!(
            !mount_legacy_allowed(true, grants, false, false),
            "a trusted transfer-only device must be refused a mount"
        );
        assert!(device_allows_at(&p, "laptop", "mount"));
        assert!(mount_legacy_allowed(true, true, false, false));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
