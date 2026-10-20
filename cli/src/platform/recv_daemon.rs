//! Portable wrappers for the daemon control operations that only exist on
//! unix. The branch lives here; the receive adapter calls one function name on
//! every target (docs/architecture/PLATFORM.md).

use crate::host::HostServices;
use filament_peerloop::conn::Conn;
use filament_peerloop::control::Req;
use std::path::PathBuf;

#[cfg(unix)]
pub(crate) type PendingBootstraps = filament_peerloop::daemon_ctl::PendingBootstraps;
#[cfg(not(unix))]
pub(crate) type PendingBootstraps = ();

#[cfg(unix)]
pub(crate) async fn warm_bootstrap(conn: &Conn, pending: &mut PendingBootstraps, req: Req) {
    crate::daemon_ctl::handle_warm_bootstrap(conn, pending, req).await
}
#[cfg(not(unix))]
pub(crate) async fn warm_bootstrap(_conn: &Conn, _pending: &mut PendingBootstraps, req: Req) {
    drop(req);
}

#[cfg(unix)]
pub(crate) async fn complete_warm_bootstrap(
    pending: &mut PendingBootstraps,
    pid: &str,
    reply: &serde_json::Value,
) {
    crate::daemon_ctl::complete_warm_bootstrap(pending, pid, reply).await
}
#[cfg(not(unix))]
pub(crate) async fn complete_warm_bootstrap(
    _pending: &mut PendingBootstraps,
    _pid: &str,
    _reply: &serde_json::Value,
) {
}

#[cfg(unix)]
pub(crate) fn reap_warm_bootstraps(pending: &mut PendingBootstraps) {
    crate::daemon_ctl::reap_warm_bootstraps(pending)
}
#[cfg(not(unix))]
pub(crate) fn reap_warm_bootstraps(_pending: &mut PendingBootstraps) {}

#[cfg(unix)]
pub(crate) async fn list_warm(conn: &Conn, req: Req) {
    filament_peerloop::daemon_ctl::handle_list_warm(conn, req).await
}
#[cfg(not(unix))]
pub(crate) async fn list_warm(_conn: &Conn, req: Req) {
    drop(req);
}

#[cfg(unix)]
pub(crate) async fn mount(
    req: Req,
    server: &str,
    relay: bool,
    mounts: &mut crate::DaemonMounts,
    last_check: &mut std::time::Instant,
) {
    crate::daemon_ctl::handle_mount(req, server, relay, mounts, last_check).await
}
#[cfg(not(unix))]
pub(crate) async fn mount(
    req: Req,
    _server: &str,
    _relay: bool,
    _mounts: &mut crate::DaemonMounts,
    _last_check: &mut std::time::Instant,
) {
    drop(req);
}

#[cfg(unix)]
pub(crate) async fn unmount(req: Req, mounts: &mut crate::DaemonMounts) {
    crate::daemon_ctl::handle_unmount(req, mounts).await
}
#[cfg(not(unix))]
pub(crate) async fn unmount(req: Req, _mounts: &mut crate::DaemonMounts) {
    drop(req);
}

#[cfg(unix)]
pub(crate) async fn list_mounts(req: Req, mounts: &crate::DaemonMounts) {
    crate::daemon_ctl::handle_list_mounts(req, mounts).await
}
#[cfg(not(unix))]
pub(crate) async fn list_mounts(req: Req, _mounts: &crate::DaemonMounts) {
    drop(req);
}

#[cfg(unix)]
pub(crate) async fn mount_health(req: Req, mounts: &crate::DaemonMounts) {
    crate::daemon_ctl::handle_mount_health(req, mounts).await
}
#[cfg(not(unix))]
pub(crate) async fn mount_health(req: Req, _mounts: &crate::DaemonMounts) {
    drop(req);
}

#[cfg(unix)]
pub(crate) fn remove_mount(host: &dyn HostServices, local: &str) {
    let _ = host.remove_mount(local);
}
#[cfg(not(unix))]
pub(crate) fn remove_mount(_host: &dyn HostServices, _local: &str) {}

#[allow(dead_code)]
fn _path(_: PathBuf) {}
