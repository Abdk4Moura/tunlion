use anyhow::{bail, Result};
use std::path::Path;

pub async fn mount_cmd(
    server: &str,
    peer: &str,
    remote: &str,
    local: Option<String>,
    read_only: bool,
    extra_opts: Option<String>,
    relay: bool,
) -> Result<()> {
    // Resolve local path: default to basename of remote path in cwd.
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

    // Create local directory if it doesn't exist.
    if !Path::new(&local_path).exists() {
        std::fs::create_dir_all(&local_path)?;
        crate::ui::say(&format!("created mount point: {local_path}"));
    }

    // Check sshfs is available.
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

    // Try L3 direct first, fall back to L2.
    let mut cmd = std::process::Command::new("sshfs");
    if let Some(dest) = crate::l2::l3_dest(&info) {
        crate::ui::debug("mounting over the L3 overlay (survives link repairs)");
        cmd.arg(format!("{dest}:{remote}"));
    } else {
        // L2 fallback: use ProxyCommand.
        let peer_name = peer.strip_suffix(".mesh").unwrap_or(peer);
        let transport_args = crate::l2::ssh_transport_args(&info, server, peer_name, relay);
        let dest_token = format!("{}@{}", info.login, info.host);
        cmd.arg(format!("{dest_token}:{remote}"));
        for arg in &transport_args {
            cmd.arg(arg);
        }
    }
    cmd.arg(&local_path);
    if read_only {
        cmd.arg("-o").arg("ro");
    }
    if let Some(opts) = &extra_opts {
        for opt in opts.split(',') {
            cmd.arg("-o").arg(opt.trim());
        }
    }

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {
            crate::ui::say(&format!(
                "mounted {peer}:{remote} at {local_path}"
            ));
            crate::ui::say(&format!(
                "  unmount with: filament unmount {local_path}"
            ));
            Ok(())
        }
        Ok(s) => {
            let code = s.code().unwrap_or(1);
            if code == 255 && info.took_fast_path {
                // Retry with fresh bootstrap.
                crate::ui::say(&format!("filament: re-authenticating with '{peer}'..."));
                let retry = crate::l2::rebootstrap_peer(server, peer, relay).await?;
                let mut cmd = std::process::Command::new("sshfs");
                if let Some(dest) = crate::l2::l3_dest(&retry) {
                    cmd.arg(format!("{dest}:{remote}"));
                } else {
                    let peer_name = peer.strip_suffix(".mesh").unwrap_or(peer);
                    let transport_args = crate::l2::ssh_transport_args(&retry, server, peer_name, relay);
                    let dest_token = format!("{}@{}", retry.login, retry.host);
                    cmd.arg(format!("{dest_token}:{remote}"));
                    for arg in &transport_args {
                        cmd.arg(arg);
                    }
                }
                cmd.arg(&local_path);
                if read_only {
                    cmd.arg("-o").arg("ro");
                }
                if let Some(opts) = &extra_opts {
                    for opt in opts.split(',') {
                        cmd.arg("-o").arg(opt.trim());
                    }
                }
                let s = cmd.status()?;
                std::process::exit(s.code().unwrap_or(1));
            }
            bail!("sshfs exited with code {code}");
        }
        Err(e) => {
            bail!("failed to run sshfs: {e}");
        }
    }
}

pub fn unmount_cmd(path: &str) -> Result<()> {
    if !Path::new(path).exists() {
        bail!("mount point does not exist: {path}");
    }

    // Try fusermount first (Linux), fall back to umount.
    let status = std::process::Command::new("fusermount")
        .arg("-u")
        .arg(path)
        .status();

    match status {
        Ok(s) if s.success() => {
            crate::ui::say(&format!("unmounted {path}"));
            Ok(())
        }
        _ => {
            // Fall back to umount.
            let status = std::process::Command::new("umount").arg(path).status()?;
            if status.success() {
                crate::ui::say(&format!("unmounted {path}"));
                Ok(())
            } else {
                bail!("failed to unmount {path}");
            }
        }
    }
}
