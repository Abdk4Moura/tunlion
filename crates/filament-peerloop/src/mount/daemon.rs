//! The daemon's mount control plane: spawn/track sshfs, the persistent mount
//! record, unmount, list and health.
//!
//! Moved out of `cli/src/daemon_ctl.rs` (issue #465). The decision order, the
//! sshfs argv, the child ownership, the store's read-modify-write shape and the
//! reply/error words are the ones the CLI had. What stays host-side is the
//! network bootstrap that resolves a peer's ssh endpoint and the atomic private
//! write the store uses; both are ordinary host effects, not the handler.
//!
//! Compiled only with `mount-daemon` (which implies `mount-server`) on unix. A
//! reduced profile has no sshfs spawn and no mount store; the control handler
//! answers with a named refusal.

use crate::control;
use crate::host::{HostServices, LogSink};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MOUNTS_FILE: &str = "mounts.json";

/// One persistent mount record. Same fields and serde shape as the CLI's.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct MountEntry {
    pub id: String,
    pub parent_id: Option<String>,
    pub local: String,
    pub peer: String,
    pub remote: String,
    pub pid: u32,
    pub read_only: bool,
    #[serde(default)]
    pub auto_restore: bool,
    pub created: String,
}

pub fn mounts_path(host: &dyn HostServices) -> PathBuf {
    host.config_dir().join(MOUNTS_FILE)
}

pub fn load_mounts(host: &dyn HostServices) -> Vec<MountEntry> {
    let path = mounts_path(host);
    let Ok(data) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_mounts(host: &dyn HostServices, mounts: &[MountEntry]) -> Result<()> {
    let path = mounts_path(host);
    let data = serde_json::to_string_pretty(mounts)?;
    // Owner-only and atomic (creates the directory 0700 too): the host owns
    // the private-write primitive (the CLI uses SecretFile).
    host.write_private_file(&path, data.as_bytes())?;
    Ok(())
}

pub fn add_mount(host: &dyn HostServices, entry: MountEntry) -> Result<()> {
    let mut mounts = load_mounts(host);
    // Remove any stale entry for the same local path.
    mounts.retain(|m| m.local != entry.local);
    mounts.push(entry);
    save_mounts(host, &mounts)
}

pub fn remove_mount(host: &dyn HostServices, local: &str) -> Result<()> {
    let mut mounts = load_mounts(host);
    mounts.retain(|m| m.local != local);
    save_mounts(host, &mounts)
}

pub fn find_parent_mount(host: &dyn HostServices, local: &str) -> Option<String> {
    let mounts = load_mounts(host);
    mounts
        .iter()
        .filter(|m| local.starts_with(&m.local) && m.local != local && is_mount_alive(host, m))
        .max_by_key(|m| m.local.len())
        .map(|m| m.id.clone())
}

fn find_child_mounts(host: &dyn HostServices, parent_id: &str) -> Vec<MountEntry> {
    load_mounts(host)
        .into_iter()
        .filter(|m| m.parent_id.as_deref() == Some(parent_id))
        .collect()
}

fn is_mount_alive(host: &dyn HostServices, entry: &MountEntry) -> bool {
    host.is_mount_point(&entry.local)
}

fn generate_mount_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 4];
    // Use /dev/urandom for true randomness.
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf));
    let val = u32::from_ne_bytes(buf);
    format!("{:06x}", val & 0xffffff)
}

pub fn unique_mount_id(host: &dyn HostServices) -> String {
    let mounts = load_mounts(host);
    loop {
        let id = generate_mount_id();
        if !mounts.iter().any(|m| m.id == id) {
            return id;
        }
    }
}

pub struct DaemonMountEntry {
    local: String,
    pub peer: String,
    pub remote: String,
    pid: u32,
    read_only: bool,
    auto_restore: bool,
    created: String,
}

#[derive(Default)]
pub struct DaemonMounts {
    pub entries: HashMap<String, DaemonMountEntry>,
    pub children: HashMap<String, tokio::process::Child>,
}

impl DaemonMounts {
    /// Remove mounts whose host path vanished; daemon-only, periodic. Moved
    /// from `RecvDaemon::mount_health_tick` so the loop's adapter is one line.
    pub async fn health_tick(&mut self, host: &dyn HostServices, log: &dyn LogSink) {
        let dead_locals: Vec<String> = self
            .entries
            .iter()
            .filter_map(|(local, _entry)| {
                let is_alive = host.is_mount_point(local);
                let path_exists = Path::new(local).exists();
                if !path_exists || !is_alive {
                    Some(local.clone())
                } else {
                    None
                }
            })
            .collect();
        for local in dead_locals {
            if let Some(entry) = self.entries.remove(&local) {
                log.say(&format!(
                    "mount {local} is gone, removing from daemon tracking (was {}:{})",
                    entry.peer, entry.remote
                ));
                if let Some(mut child) = self.children.remove(&local) {
                    let _ = child.kill().await;
                }
                let _ = host.remove_mount(&local);
            }
        }
    }
}

/// Handle a mount request: spawn sshfs directly and track the child process
/// centrally so `handle_unmount` can kill it.
pub async fn handle_mount(
    req: control::Req,
    server: &str,
    relay: bool,
    daemon_mounts: &mut DaemonMounts,
    last_mount_check: &mut Instant,
    host: &dyn HostServices,
    log: &dyn LogSink,
) {
    let control::ReqKind::Mount {
        peer,
        remote,
        local,
        read_only,
        auto_restore,
        port,
    } = &req.kind
    else {
        return;
    };
    let peer = peer.clone();
    let remote = remote.clone();
    let local = local.clone();
    let read_only = *read_only;
    let auto_restore = *auto_restore;
    let port = *port;

    // Ensure mount point exists.
    if !Path::new(&local).exists() {
        if let Err(e) = std::fs::create_dir_all(&local) {
            req.reject(&format!("failed to create mount point: {e}"))
                .await;
            return;
        }
        log.say(&format!("created mount point: {local}"));
    }

    // Check sshfs is available.
    if crate::process::command("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        req.reject("sshfs not found").await;
        return;
    }

    // Bootstrap peer connection info (sshfs authenticates with the managed
    // key: cert mode is `shell --ssh` only).
    let info = match host.prepare_mount_transport(server, &peer, relay, port).await {
        Ok(info) => info,
        Err(e) => {
            req.reject(&format!("bootstrap failed: {e}")).await;
            return;
        }
    };
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(&peer);

    // Build the sshfs command args directly.
    let mut args: Vec<String> = Vec::new();

    // Common SSH options.
    args.extend_from_slice(&[
        "-o".into(),
        format!("IdentityFile={}", info.key_path.display()),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=4".into(),
    ]);

    // L3 preferred, L2 fallback.
    let dest = if let Some(d) = &info.direct_dest {
        d.clone() // L3 direct: user@peer.mesh, no ProxyCommand
    } else {
        // L2 fallback: user@tunlion-peer with ProxyCommand
        let exe = host.current_exe();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" forward {peer_name}:{} --stdio", info.rport));
        args.push("-o".into());
        args.push(format!("ProxyCommand={proxy}"));
        format!("{}@{}", info.login, info.host)
    };

    args.push(format!("{dest}:{remote}"));
    args.push(local.clone());
    if read_only {
        args.push("-o".into());
        args.push("ro".into());
    }

    // Spawn sshfs via tokio so we get a Child we can kill later.
    let child = match crate::process::tokio_command("sshfs")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            req.reject(&format!("failed to spawn sshfs: {e}")).await;
            return;
        }
    };

    let pid = child.id().unwrap_or(0);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mount_id = unique_mount_id(host);
    let parent_id = find_parent_mount(host, &local);

    // Record in persistent mount tracking.
    let _ = add_mount(
        host,
        MountEntry {
            id: mount_id.clone(),
            parent_id,
            local: local.clone(),
            peer: peer_name.to_string(),
            remote: remote.clone(),
            pid,
            read_only,
            auto_restore,
            created: now.clone(),
        },
    );

    // Store in daemon in-memory tracking.
    let entry = DaemonMountEntry {
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now,
    };
    daemon_mounts.entries.insert(local.clone(), entry);
    daemon_mounts.children.insert(local.clone(), child);

    *last_mount_check = Instant::now();
    log.say(&format!(
        "mounted {peer_name}:{remote} at {local} (id: {mount_id})"
    ));
    req.reply(&json!({ "ok": true })).await;
}

/// Unmount one tracked path, recursively, using the same fusermount/umount
/// fallback and the same "tracking is still removed on failure" rule as the
/// CLI's async unmount.
async fn unmount_persistent(host: &dyn HostServices, target: &str, log: &dyn LogSink) -> Result<()> {
    let mounts = load_mounts(host);
    let entry = mounts.iter().find(|m| m.id == target || m.local == target);
    match entry {
        Some(entry) => {
            let children = find_child_mounts(host, &entry.id);
            for child in children {
                if let Err(e) = Box::pin(unmount_persistent(host, &child.local, log)).await {
                    log.say(&format!(
                        "warning: failed to unmount child {}: {}",
                        child.local, e
                    ));
                }
            }

            let path = &entry.local;
            let status = crate::process::tokio_command("fusermount")
                .arg("-u")
                .arg(path)
                .status()
                .await;
            match status {
                Ok(s) if s.success() => {
                    let _ = remove_mount(host, path);
                    log.say(&format!("unmounted {path} (id: {})", entry.id));
                    Ok(())
                }
                _ => {
                    let status = crate::process::tokio_command("umount")
                        .arg(path)
                        .status()
                        .await?;
                    if status.success() {
                        let _ = remove_mount(host, path);
                        log.say(&format!("unmounted {path} (id: {})", entry.id));
                        Ok(())
                    } else {
                        let _ = remove_mount(host, path);
                        bail!("failed to unmount {path}, but tracking removed");
                    }
                }
            }
        }
        None => {
            if Path::new(target).exists() {
                let status = crate::process::tokio_command("fusermount")
                    .arg("-u")
                    .arg(target)
                    .status()
                    .await;
                match status {
                    Ok(s) if s.success() => {
                        log.say(&format!("unmounted {target}"));
                        Ok(())
                    }
                    _ => {
                        let status = crate::process::tokio_command("umount")
                            .arg(target)
                            .status()
                            .await?;
                        if status.success() {
                            log.say(&format!("unmounted {target}"));
                            Ok(())
                        } else {
                            bail!("failed to unmount {target}");
                        }
                    }
                }
            } else {
                bail!("no mount found for '{target}' (use `tunlion mount --list` to see active mounts)");
            }
        }
    }
}

/// Handle an unmount request: kill the sshfs process and remove tracking.
pub async fn handle_unmount(
    req: control::Req,
    daemon_mounts: &mut DaemonMounts,
    host: &dyn HostServices,
    log: &dyn LogSink,
) {
    let control::ReqKind::Unmount { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Kill the child process if tracked by the daemon.
    if let Some(mut child) = daemon_mounts.children.remove(&target) {
        let _ = child.kill().await;
    }
    daemon_mounts.entries.remove(&target);

    // Also remove from persistent tracking (async-safe, no block_on).
    match unmount_persistent(host, &target, log).await {
        Ok(()) => req.reply(&json!({ "ok": true })).await,
        Err(e) => req.reject(&format!("unmount failed: {e}")).await,
    }
}

/// Handle a list-mounts request: return all tracked mounts and their status.
pub async fn handle_list_mounts(
    req: control::Req,
    daemon_mounts: &DaemonMounts,
    host: &dyn HostServices,
    _log: &dyn LogSink,
) {
    let mounts: Vec<Value> = daemon_mounts
        .entries
        .values()
        .map(|e| {
            let is_alive = host.is_mount_point(&e.local);
            let status = if is_alive { "healthy" } else { "dead" };
            json!({
                "local": e.local,
                "peer": e.peer,
                "remote": e.remote,
                "read_only": e.read_only,
                "auto_restore": e.auto_restore,
                "created": e.created,
                "status": status,
            })
        })
        .collect();
    req.reply(&json!({ "ok": true, "mounts": mounts })).await;
}

/// Handle a mount-health request: check health of a specific mount.
pub async fn handle_mount_health(
    req: control::Req,
    daemon_mounts: &DaemonMounts,
    host: &dyn HostServices,
    _log: &dyn LogSink,
) {
    let control::ReqKind::MountHealth { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Find the entry by local path or ID.
    let entry = daemon_mounts.entries.get(&target);
    match entry {
        Some(e) => {
            let is_alive = host.is_mount_point(&e.local);
            let path_exists = Path::new(&e.local).exists();
            let status = if !path_exists {
                "missing"
            } else if !is_alive {
                "dead"
            } else {
                match std::fs::metadata(&e.local) {
                    Ok(_) => "healthy",
                    Err(_) => "stale",
                }
            };
            req.reply(&json!({ "ok": true, "status": status, "local": e.local, "peer": e.peer, "remote": e.remote })).await;
        }
        None => {
            // Not tracked by daemon, but check if it's a live mount anyway.
            if host.is_mount_point(&target) {
                req.reply(&json!({ "ok": true, "status": "untracked", "local": target }))
                    .await;
            } else {
                req.reject(&format!("no mount found for '{target}'")).await;
            }
        }
    }
}
