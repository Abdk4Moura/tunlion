use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::io::IsTerminal;

const MOUNTS_FILE: &str = "mounts.json";

fn mounts_path() -> PathBuf {
    crate::settings::config_dir().join(MOUNTS_FILE)
}

fn generate_mount_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 4];
    // Use /dev/urandom for true randomness.
    let _ = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf));
    let val = u32::from_ne_bytes(buf);
    format!("{:06x}", val & 0xffffff)
}

fn unique_mount_id() -> String {
    let mounts = load_mounts();
    loop {
        let id = generate_mount_id();
        if !mounts.iter().any(|m| m.id == id) {
            return id;
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct MountEntry {
    id: String,
    parent_id: Option<String>,
    local: String,
    peer: String,
    remote: String,
    pid: u32,
    read_only: bool,
    created: String,
}

fn load_mounts() -> Vec<MountEntry> {
    let path = mounts_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_mounts(mounts: &[MountEntry]) -> Result<()> {
    let path = mounts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(mounts)?;
    std::fs::write(&path, data)?;
    Ok(())
}

fn add_mount(entry: MountEntry) -> Result<()> {
    let mut mounts = load_mounts();
    // Remove any stale entry for the same local path.
    mounts.retain(|m| m.local != entry.local);
    mounts.push(entry);
    save_mounts(&mounts)
}

fn remove_mount(local: &str) -> Result<()> {
    let mut mounts = load_mounts();
    mounts.retain(|m| m.local != local);
    save_mounts(&mounts)
}

fn find_parent_mount(local: &str) -> Option<String> {
    let mounts = load_mounts();
    mounts.iter()
        .filter(|m| local.starts_with(&m.local) && m.local != local && is_mount_alive(m))
        .max_by_key(|m| m.local.len())
        .map(|m| m.id.clone())
}

fn find_child_mounts(parent_id: &str) -> Vec<MountEntry> {
    load_mounts().into_iter()
        .filter(|m| m.parent_id.as_deref() == Some(parent_id))
        .collect()
}

fn is_mount_alive(entry: &MountEntry) -> bool {
    // Check if the mount point is still active via /proc/mounts.
    is_mount_point(&entry.local)
}

fn check_mount_health(entry: &MountEntry) -> MountStatus {
    if !Path::new(&entry.local).exists() {
        return MountStatus::Missing;
    }
    if !is_mount_alive(entry) {
        return MountStatus::Dead;
    }
    // Try to stat a file to check if mount is responsive.
    match std::fs::metadata(&entry.local) {
        Ok(_) => MountStatus::Healthy,
        Err(_) => MountStatus::Stale,
    }
}

#[derive(PartialEq)]
enum MountStatus {
    Healthy,
    Stale,
    Dead,
    Missing,
}

impl std::fmt::Display for MountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountStatus::Healthy => write!(f, "healthy"),
            MountStatus::Stale => write!(f, "stale (unresponsive)"),
            MountStatus::Dead => write!(f, "dead (process gone)"),
            MountStatus::Missing => write!(f, "missing (mount point gone)"),
        }
    }
}

pub async fn mount_cmd(
    server: &str,
    peer: &str,
    remote: &str,
    local: Option<String>,
    read_only: bool,
    extra_opts: Option<String>,
    relay: bool,
    foreground: bool,
) -> Result<()> {
    let local_path = match local {
        Some(p) => p,
        None => {
            let basename = Path::new(remote)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| peer.to_string());
            basename
        }
    };

    if !Path::new(&local_path).exists() {
        std::fs::create_dir_all(&local_path)?;
        crate::ui::say(&format!("created mount point: {local_path}"));
    }

    if std::process::Command::new("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        crate::ui::problem(
            "sshfs not found",
            "sshfs is required for `filament mount` but is not installed.",
            &[
                "apt install sshfs          # Debian/Ubuntu".to_string(),
                "brew install sshfs         # macOS (via macFUSE)".to_string(),
                "pacman -S sshfs            # Arch".to_string(),
            ],
        );
        std::process::exit(1);
    }

    let info = crate::l2::ensure_peer_bootstrap(server, peer, relay).await?;
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(peer);

    // Build the sshfs command.
    let build_sshfs = |info: &crate::l2::PeerSshInfo, use_l3: bool| -> std::process::Command {
        let mut cmd = std::process::Command::new("sshfs");
        cmd.arg("-o").arg(format!("IdentityFile={}", info.key_path.display()));
        cmd.arg("-o").arg("IdentitiesOnly=yes");
        cmd.arg("-o").arg(format!("UserKnownHostsFile={}", info.known_hosts_path.display()));
        cmd.arg("-o").arg("GlobalKnownHostsFile=/dev/null");
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        cmd.arg("-o").arg("ConnectTimeout=10");
        cmd.arg("-o").arg("ServerAliveInterval=15");
        cmd.arg("-o").arg("ServerAliveCountMax=4");

        if use_l3 {
            if let Some(dest) = crate::l2::l3_dest(info) {
                cmd.arg(format!("{dest}:{remote}"));
                return cmd;
            }
        }

        // L2 fallback.
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" netcat {peer_name} {}", info.rport));
        cmd.arg("-o").arg(format!("ProxyCommand={proxy}"));
        let dest_token = format!("{}@{}", info.login, info.host);
        cmd.arg(format!("{dest_token}:{remote}"));
        cmd
    };

    let mut cmd = build_sshfs(&info, true);
    cmd.arg(&local_path);
    if read_only {
        cmd.arg("-o").arg("ro");
    }
    if let Some(opts) = &extra_opts {
        for opt in opts.split(',') {
            cmd.arg("-o").arg(opt.trim());
        }
    }

    // In foreground mode, run sshfs and wait. In background mode, spawn and track.
    if foreground {
        let status = cmd.status();
        match status {
            Ok(s) if s.success() => {
                crate::ui::say(&format!("mounted {peer}:{remote} at {local_path}"));
                crate::ui::say(&format!("  unmount with: filament unmount {local_path}"));
                Ok(())
            }
            Ok(s) => {
                let code = s.code().unwrap_or(1);
                if code == 255 && info.took_fast_path {
                    crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
                    let retry = crate::l2::rebootstrap_peer(server, peer, relay).await?;
                    let mut cmd = build_sshfs(&retry, true);
                    cmd.arg(&local_path);
                    if read_only { cmd.arg("-o").arg("ro"); }
                    if let Some(opts) = &extra_opts {
                        for opt in opts.split(',') { cmd.arg("-o").arg(opt.trim()); }
                    }
                    let s = cmd.status()?;
                    std::process::exit(s.code().unwrap_or(1));
                }
                bail!("sshfs exited with code {code}");
            }
            Err(e) => bail!("failed to run sshfs: {e}"),
        }
    } else {
        // Background mode: spawn sshfs, record PID, start monitor.
        let mut child = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        let pid = child.id();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mount_id = unique_mount_id();

        let parent_id = find_parent_mount(&local_path);

        add_mount(MountEntry {
            id: mount_id.clone(),
            parent_id,
            local: local_path.clone(),
            peer: peer_name.to_string(),
            remote: remote.to_string(),
            pid,
            read_only,
            created: now,
        })?;

        crate::ui::say(&format!("mounted {peer}:{remote} at {local_path} (id: {mount_id})"));
        crate::ui::say(&format!("  check with: filament mount --check {mount_id}"));
        crate::ui::say(&format!("  unmount with: filament unmount {local_path}"));

        // Spawn monitor thread (not tokio, because we use std::process::Command).
        let monitor_local = local_path.clone();
        let monitor_peer = peer_name.to_string();
        let monitor_remote = remote.to_string();
        let monitor_server = server.to_string();
        std::thread::spawn(move || {
            monitor_mount(monitor_local, monitor_peer, monitor_remote, monitor_server, relay);
        });

        Ok(())
    }
}

fn monitor_mount(local: String, peer: String, remote: String, server: String, relay: bool) {
    let check_interval = std::time::Duration::from_secs(30);
    let mut consecutive_failures = 0u32;

    loop {
        std::thread::sleep(check_interval);

        let mounts = load_mounts();
        let entry = match mounts.iter().find(|m| m.local == local) {
            Some(e) => e.clone(),
            None => return, // Mount was removed.
        };

        let status = check_mount_health(&entry);
        match status {
            MountStatus::Healthy => {
                consecutive_failures = 0;
            }
            MountStatus::Stale | MountStatus::Dead => {
                consecutive_failures += 1;
                if consecutive_failures >= 3 {
                    crate::ui::say(&format!(
                        "mount {local} is {status}, run `filament mount --check {local}` for details"
                    ));
                    crate::ui::say(&format!(
                        "  to recover: filament unmount {local} && filament mount {peer} {remote} {local}"
                    ));
                    let _ = remove_mount(&local);
                    return;
                }
            }
            MountStatus::Missing => {
                crate::ui::say(&format!("mount {local} point gone, removing tracking"));
                let _ = remove_mount(&local);
                return;
            }
        }
    }
}

pub fn list_cmd() -> Result<()> {
    let mounts = load_mounts();
    if mounts.is_empty() {
        crate::ui::say("no active filament mounts");
        return Ok(());
    }

    let is_tty = std::io::stdout().is_terminal();
    let mut healthy = 0;
    let mut unhealthy = 0;

    for entry in &mounts {
        let status = check_mount_health(entry);
        let status_str = status.to_string();
        let is_ok = status == MountStatus::Healthy;
        if is_ok { healthy += 1; } else { unhealthy += 1; }

        if is_tty {
            let color = if is_ok { "\x1b[32m" } else { "\x1b[31m" };
            let reset = "\x1b[0m";
            println!(
                "{color}{}{reset}  {color}{}{reset}  {}:{} -> {}",
                status_str, entry.id, entry.peer, entry.remote, entry.local
            );
        } else {
            println!(
                "{} {} {}:{} -> {}",
                status_str, entry.id, entry.peer, entry.remote, entry.local
            );
        }
    }

    if is_tty {
        println!("\n{healthy} healthy, {unhealthy} unhealthy, {} total", mounts.len());
        println!("unmount with: filament unmount <id>");
    }

    Ok(())
}

pub fn check_cmd(target: &str) -> Result<()> {
    let mounts = load_mounts();
    // Try to find by ID first, then by path.
    let entry = mounts.iter().find(|m| m.id == target || m.local == target);

    match entry {
        None => {
            // Not tracked, but check if it's a live mount anyway.
            if is_mount_point(target) {
                crate::ui::say(&format!("{target} is a mount point but not tracked by filament"));
                Ok(())
            } else {
                bail!("{target} is not a filament mount (use `filament mount --list` to see active mounts)");
            }
        }
        Some(entry) => {
            let status = check_mount_health(entry);
            let is_tty = std::io::stdout().is_terminal();

            if is_tty {
                let (color, label) = match status {
                    MountStatus::Healthy => ("\x1b[32m", "HEALTHY"),
                    _ => ("\x1b[31m", "UNHEALTHY"),
                };
                let reset = "\x1b[0m";
                println!("{color}[{label}]{reset} {} ({})", entry.id, entry.local);
                println!("  peer:   {}:{}", entry.peer, entry.remote);
                println!("  status: {status}");
                println!("  since:  {}", entry.created);
            } else {
                println!("{} {} {}:{} created={}", status, entry.id, entry.peer, entry.remote, entry.created);
            }

            if status != MountStatus::Healthy {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn is_mount_point(path: &str) -> bool {
    // Check /proc/mounts for FUSE mounts.
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            if line.contains("fuse.sshfs") && line.contains(path) {
                return true;
            }
        }
    }
    false
}

pub fn unmount_cmd(target: &str) -> Result<()> {
    let mounts = load_mounts();

    // Try to find by ID first, then by path.
    let entry = mounts.iter().find(|m| m.id == target || m.local == target);

    match entry {
        Some(entry) => {
            // Recursively unmount children first.
            let children = find_child_mounts(&entry.id);
            for child in children {
                if let Err(e) = unmount_cmd(&child.local) {
                    crate::ui::say(&format!("warning: failed to unmount child {}: {}", child.local, e));
                }
            }

            let path = &entry.local;
            // Try fusermount first.
            let status = std::process::Command::new("fusermount")
                .arg("-u")
                .arg(path)
                .status();

            match status {
                Ok(s) if s.success() => {
                    let _ = remove_mount(path);
                    crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                    Ok(())
                }
                _ => {
                    let status = std::process::Command::new("umount").arg(path).status()?;
                    if status.success() {
                        let _ = remove_mount(path);
                        crate::ui::say(&format!("unmounted {path} (id: {})", entry.id));
                        Ok(())
                    } else {
                        // Still remove tracking even if unmount fails.
                        let _ = remove_mount(path);
                        bail!("failed to unmount {path}, but tracking removed");
                    }
                }
            }
        }
        None => {
            // Not tracked - try as a direct path.
            if Path::new(target).exists() {
                let status = std::process::Command::new("fusermount")
                    .arg("-u")
                    .arg(target)
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        crate::ui::say(&format!("unmounted {target}"));
                        Ok(())
                    }
                    _ => {
                        let status = std::process::Command::new("umount").arg(target).status()?;
                        if status.success() {
                            crate::ui::say(&format!("unmounted {target}"));
                            Ok(())
                        } else {
                            bail!("failed to unmount {target}");
                        }
                    }
                }
            } else {
                bail!("no mount found for '{target}' (use `filament mount --list` to see active mounts)");
            }
        }
    }
}
