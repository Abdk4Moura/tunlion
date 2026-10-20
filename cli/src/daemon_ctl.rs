//! Daemon control-socket handlers: the CLI's re-export shim.
//!
//! The handlers moved into `filament_peerloop`: the warm `Open`/`Pty`/`Resize`
//! dispatcher and the mount spawn/track/store/unmount/list/health code are
//! library modules with host-effect seams. This file keeps every old path
//! resolving under `crate::daemon_ctl::` so the daemon loop and platform
//! wrappers do not change shape.
//!
//! What remains here is one compatibility type for a reduced profile that did
//! not compile the mount daemon: an empty tracker the control plane can still
//! name, and the named refusal the handlers send when asked to mount.

pub(crate) use crate::link_manager::peer_present;

pub(crate) use filament_peerloop::daemon_ctl::{
    LivenessProbes, WarmPtys, handle_warm_req, liveness_pong, sshd_listening,
};
#[cfg(unix)]
pub(crate) use filament_peerloop::daemon_ctl::{
    PendingBootstraps, complete_warm_bootstrap, handle_list_warm, handle_warm_bootstrap,
    handle_warm_ping, log_warm_miss, reap_warm_bootstraps,
};

#[cfg(all(feature = "mount-daemon", unix))]
pub(crate) use filament_peerloop::mount::daemon::{
    DaemonMounts, handle_list_mounts, handle_mount, handle_mount_health, handle_unmount,
};

#[cfg(not(all(feature = "mount-daemon", unix)))]
mod reduced {
    use serde_json::json;
    use std::collections::HashMap;
    use std::time::Instant;

    pub struct DaemonMountEntry {
        pub peer: String,
        pub remote: String,
    }

    #[derive(Default)]
    pub struct DaemonMounts {
        pub entries: HashMap<String, DaemonMountEntry>,
        pub children: HashMap<String, tokio::process::Child>,
    }

    const UNAVAILABLE: &str = "mount daemon is not available in this build";

    pub async fn handle_mount(
        req: filament_peerloop::control::Req,
        _server: &str,
        _relay: bool,
        _mounts: &mut DaemonMounts,
        _last_check: &mut Instant,
        _host: &dyn filament_peerloop::host::HostServices,
        _log: &dyn filament_peerloop::host::LogSink,
    ) {
        req.reject(UNAVAILABLE).await;
    }

    pub async fn handle_unmount(
        req: filament_peerloop::control::Req,
        _mounts: &mut DaemonMounts,
        _host: &dyn filament_peerloop::host::HostServices,
        _log: &dyn filament_peerloop::host::LogSink,
    ) {
        req.reject(UNAVAILABLE).await;
    }

    pub async fn handle_list_mounts(
        req: filament_peerloop::control::Req,
        _mounts: &DaemonMounts,
        _host: &dyn filament_peerloop::host::HostServices,
        _log: &dyn filament_peerloop::host::LogSink,
    ) {
        req.reply(&json!({ "ok": true, "mounts": [] })).await;
    }

    pub async fn handle_mount_health(
        req: filament_peerloop::control::Req,
        _mounts: &DaemonMounts,
        _host: &dyn filament_peerloop::host::HostServices,
        _log: &dyn filament_peerloop::host::LogSink,
    ) {
        req.reject(UNAVAILABLE).await;
    }
}

#[cfg(not(all(feature = "mount-daemon", unix)))]
pub(crate) use reduced::{
    DaemonMounts, handle_list_mounts, handle_mount, handle_mount_health, handle_unmount,
};
