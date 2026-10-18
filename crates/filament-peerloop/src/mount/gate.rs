//! The `mount-open` decision inputs that do not need a live link: whether the
//! requesting device holds `mount`, and which directory a mount may serve.
//!
//! Pure functions, so the decision is unit-testable without a daemon. The
//! endpoint ([`super::handle_mount_open`]) feeds them the live facts.
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
//!    `~/tunlion-share`), which is what the `mount` help already promised
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
pub fn mount_legacy_allowed(
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
pub fn confine_mount_root(share_root: &Path, requested: &Path) -> Option<PathBuf> {
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

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fil-mount-gate-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The rule the store-shape test in the CLI pins: a transfer-only record
    /// (`record_grants == false`) with no signed grant is refused a mount even
    /// on a trusted link. The record lookup itself is the host's.
    #[test]
    fn transfer_only_device_cannot_mount() {
        assert!(!mount_legacy_allowed(true, false, false, false));
    }

    #[test]
    fn mount_granted_device_within_share_is_allowed() {
        let dir = tmp("ok");
        let share = dir.join("share");
        std::fs::create_dir_all(share.join("docs")).unwrap();
        assert!(mount_legacy_allowed(true, true, false, false));
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
