//! The `mount-open` decision inputs that do not need a live link: whether the
//! requesting device holds `mount`, and which directory a mount may serve.
//!
//! Pure functions, so the decision is unit-testable without a daemon. The
//! acceptor (`recv_cmd.rs`, the `mount-open` arm) feeds them the live facts.
//!
//! Why this exists: in shadow mode (the default) the effective verdict of
//! `cap_gate_effective` is its `legacy_allowed` input, and for mount that input
//! was `trusted` alone. Any paired device, a transfer-only one included, got a
//! read-write mount of whatever root it named, `/` included, as the daemon user.
//! Two rules close that, in BOTH modes:
//!
//! 1. Capability: the legacy input requires a `mount` capability for the
//!    device, the same record check `device_allows` makes for shell (a device
//!    enrolled with the transfer+mount default holds it; a transfer-only device
//!    does not), or an owner-signed explicit grant, and no recorded deny.
//! 2. Confinement: the served root must lie within the SHARE ROOT
//!    (`fleet_share_root()`: the `share` config key, default
//!    `~/filament-share`), which is what the `mount` help already promised
//!    ("the remote share root and grant remain authoritative"). A relative
//!    root is resolved against the share root, so the default `.` means the
//!    share root itself. To serve a different directory, the OWNER points
//!    `share` at it; the peer cannot.
use std::path::{Path, PathBuf};

/// The legacy (shadow-mode effective) verdict for a `mount-open`.
///
/// `trusted`: the link authenticated as a known device. `record_grants`: that
/// device's record holds `mount` (`device_allows(name, "mount")`).
/// `signed_grant`: an owner-signed explicit `mount` grant covers the device.
/// `denied`: the owner recorded a deny for `mount`, which outranks both.
pub(crate) fn mount_legacy_allowed(
    trusted: bool,
    record_grants: bool,
    signed_grant: bool,
    denied: bool,
) -> bool {
    trusted && !denied && (record_grants || signed_grant)
}

/// The directory a mount of `requested` may serve, or `None` when it falls
/// outside `share_root`. Relative paths resolve against the share root.
/// Both sides are canonicalized (symlinks resolved), so a symlink inside the
/// share pointing out of it is refused, and a root that does not exist is
/// refused too. Returns the CANONICAL path, so the server serves exactly the
/// directory that was checked.
pub(crate) fn confine_mount_root(share_root: &Path, requested: &Path) -> Option<PathBuf> {
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        share_root.join(requested)
    };
    let root_c = share_root.canonicalize().ok()?;
    let path_c = resolved.canonicalize().ok()?;
    if root_c.as_os_str().is_empty() || !path_c.starts_with(&root_c) {
        return None;
    }
    Some(path_c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_caps::device_allows_at;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fil-mount-gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The record shapes the acceptor sees: a device enrolled transfer-only and
    /// one enrolled with the transfer+mount default.
    fn store(dir: &Path) -> PathBuf {
        let p = dir.join("devices.json");
        let sec = "a".repeat(64);
        std::fs::write(
            &p,
            serde_json::to_string(&serde_json::json!([
                {"name": "phone", "secret": sec, "v": 2, "caps": ["transfer"]},
                {"name": "laptop", "secret": "b".repeat(64), "v": 2, "caps": ["transfer", "mount"]},
            ]))
            .unwrap(),
        )
        .unwrap();
        p
    }

    #[test]
    fn transfer_only_device_cannot_mount() {
        let dir = tmp("cap");
        let p = store(&dir);
        let grants = device_allows_at(&p, "phone", "mount");
        assert!(!grants, "a transfer-only record must not hold mount");
        assert!(
            !mount_legacy_allowed(true, grants, false, false),
            "a trusted transfer-only device must be refused a mount"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mount_granted_device_within_share_is_allowed() {
        let dir = tmp("ok");
        let p = store(&dir);
        let share = dir.join("share");
        std::fs::create_dir_all(share.join("docs")).unwrap();
        let grants = device_allows_at(&p, "laptop", "mount");
        assert!(mount_legacy_allowed(true, grants, false, false));
        assert_eq!(
            confine_mount_root(&share, Path::new("docs")),
            Some(share.join("docs").canonicalize().unwrap())
        );
        assert_eq!(
            confine_mount_root(&share, &share.join("docs")),
            Some(share.join("docs").canonicalize().unwrap())
        );
        assert_eq!(
            confine_mount_root(&share, Path::new(".")),
            Some(share.canonicalize().unwrap()),
            "the default root is the share root itself"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn untrusted_or_denied_never_mounts() {
        assert!(!mount_legacy_allowed(false, true, true, false), "untrusted link");
        assert!(!mount_legacy_allowed(true, true, true, true), "a deny outranks grants");
        assert!(mount_legacy_allowed(true, false, true, false), "a signed grant suffices");
    }

    #[test]
    fn root_outside_share_is_refused_unless_configured() {
        let dir = tmp("root");
        let share = dir.join("share");
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&share).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert_eq!(confine_mount_root(&share, Path::new("/")), None, "/ is refused");
        assert_eq!(confine_mount_root(&share, &elsewhere), None);
        assert_eq!(confine_mount_root(&share, Path::new("../elsewhere")), None, "dotdot");
        // The owner CONFIGURED that path for mount: pointing the share root at
        // it is the only way to serve it.
        assert_eq!(
            confine_mount_root(&elsewhere, &elsewhere),
            Some(elsewhere.canonicalize().unwrap())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
