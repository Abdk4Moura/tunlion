//! Mount planning, the mount implementation, and `tunlion reset`.
//!
//! `resolve_mount_plan` turns `mount <device> <dir>` into a plan, `mount_fuse_cmd`
//! carries it out through the platform mount adapter, and `reset_cmd` wipes this
//! machine's tunlion state.
//!
//! CFG, handled explicitly because anyhow::{ Result, anyhow, bail };
use crate::MountPlan;
use crate::UiCapability;
use crate::codeentry;
use crate::command_arg;
use crate::daemon_alive;
use crate::default_mount_point;
use crate::device_view::device_cert_for;
use crate::devices_store::devices_load;
use crate::interactive_requested;
use crate::load_owner_key;
use crate::mount_proto;
use crate::principal_ceiling_for;
use crate::prompt_line;
use crate::reset_remove;
use crate::ui;
// The cfg here must match the DEFINITION gate in runtime_support.rs and the
// re-export gate in main.rs. It was missing the windows arm, so on
// `--features mount-windows` the function existed and was re-exported while the
// import was compiled out, and both call sites below failed with E0425. Nothing
// caught it because mount-ci.yml is path-triggered and no change had touched its
// trigger paths since the arm was added.
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "mount-macos"),
    all(target_os = "windows", feature = "mount-windows")
))]
use crate::unmount_fuse;
use anyhow::{Context, Result, anyhow, bail};
use std::time::Duration;

pub(crate) fn reset_cmd(ui_caps: &UiCapability) -> Result<()> {
    // 1. Refuse while the daemon runs: reset yanks the keys and device store out
    //    from under a live acceptor. Make the user stop it explicitly.
    if let Some(pid) = daemon_alive() {
        bail!(
            "the tunlion daemon is running (pid {pid}); run `tunlion down` first, then `tunlion reset`"
        );
    }

    // 2. Confirm (destructive). ui_caps.confirm honors the global -y/--yes and
    //    REFUSES from a non-TTY without it, exactly the required behavior.
    ui_caps.confirm(
        "wipe ALL local tunlion state (identity, devices, caps, managed ssh keys) on this machine",
    )?;

    let cfg = crate::settings::config_dir();
    let mut wiped: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();

    // 3. Strip the managed authorized_keys blocks BEFORE devices.json is gone,
    //    so we know every petname whose block tunlion may have installed. Only
    //    the delimited `# BEGIN/END filament-managed <device>` blocks are removed;
    //    everything else in authorized_keys is preserved verbatim.
    let ak_path = crate::sshkeys::authorized_keys_path();
    if let Ok(existing) = std::fs::read_to_string(&ak_path) {
        let mut content = existing.clone();
        let mut stripped: Vec<String> = Vec::new();
        for (name, _) in devices_load() {
            if crate::sshkeys::has_block(&content, &name) {
                content = crate::sshkeys::strip_block(&content, &name);
                stripped.push(name);
            }
        }
        if content != existing {
            // Best-effort restrictive write (owner-only), same as the installer.
            if crate::platform::SecretFile::write_str(&ak_path, &content).is_ok() {
                wiped.push(format!(
                    "managed authorized_keys blocks: {}  ({})",
                    stripped.join(", "),
                    ak_path.display()
                ));
            } else {
                failed.push(format!(
                    "managed authorized_keys blocks: {}  ({}): could not rewrite the file",
                    stripped.join(", "),
                    ak_path.display()
                ));
            }
        }
    }

    // 4. Remove tunlion's own state files (RESET_STATE). Every failure is
    //    collected and reported: a reset that silently leaves state behind
    //    must not call itself a clean slate.
    let outcome = reset_state_in(&cfg, &reset_remove);
    wiped.extend(outcome.wiped);
    failed.extend(outcome.failed);

    // 5. Invalidate the in-process cap-store read cache so a same-process reader
    //    can't serve the just-deleted store from memory.
    crate::capability::invalidate_cap_cache();

    if !wiped.is_empty() {
        ui::say(&format!(
            "  {} wiped local tunlion state:",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        for line in &wiped {
            ui::say(&format!("    - {line}"));
        }
    }
    if !failed.is_empty() {
        ui::say(&format!(
            "  {} could not remove:",
            ui::paint(ui::Tone::Warn, ui::glyph_warn())
        ));
        for line in &failed {
            ui::say(&format!("    - {line}"));
        }
        bail!(
            "reset is incomplete: {} item(s) above are still in place, so this machine is NOT a clean slate. Fix the cause (often a file owned by another user, e.g. state written by a daemon started with sudo) and run `tunlion reset` again.",
            failed.len()
        );
    }
    if wiped.is_empty() {
        ui::say("  nothing to wipe / no local tunlion state found");
    } else {
        ui::say("  this machine is now a clean slate (`tunlion init` to start over)");
    }
    Ok(())
}

/// Every piece of tunlion's OWN state under the config dir, with the label
/// `reset` reports for it. An explicit list (NOT a blanket rmdir of the config
/// dir) so a mis-set FILAMENT_CONFIG_DIR can never take out unrelated files.
/// A writer that adds a file to the config dir must add it here, or `reset`
/// stops being the clean slate it says it is. Lock sidecars come last.
pub(crate) const RESET_STATE: &[(&str, &str)] = &[
    ("identity.ed25519", "user identity key"),
    ("identity", "local device certificate (identity/)"),
    ("overlay.ed25519", "overlay key"),
    ("overlay.announce-seq", "overlay announce sequence"),
    ("device.id", "install id"),
    ("devices.json", "paired-device store (device certs)"),
    ("caps.json", "capability store"),
    ("requests.json", "pending consent requests"),
    ("expose.json", "exposed-service records"),
    ("mounts.json", "mount records"),
    ("l2-allow.json", "L2 forward allowlist"),
    ("signaling-dns.json", "signaling DNS cache"),
    ("fleet.rv", "fleet rendezvous secret"),
    ("roster.json", "fleet roster"),
    ("roster-state.json", "fleet roster state"),
    ("armed.json", "armed invitations"),
    ("ssh_ca_issued.json", "ssh certificate issuance log"),
    ("ssh_ca_serial", "ssh certificate serial counter"),
    ("peerconf", "per-peer settings"),
    ("config", "global settings"),
    ("diag.jsonl", "diagnostics log"),
    ("up.log", "daemon session log"),
    ("daemon.log", "daemon console log"),
    ("up.pid", "daemon pidfile"),
    // The daemon's other run-state: its executable record, its readiness
    // marker, its single-instance lock and the local proxy's token. A reset
    // that left these behind was not a clean slate (the hostile-env test
    // found up.ready, up.exe and proxy.token surviving `reset -y`).
    ("up.exe", "daemon executable record"),
    ("up.ready", "daemon readiness marker"),
    ("up.lock", "daemon single-instance lock"),
    ("proxy.token", "local proxy token"),
    ("control.sock", "daemon control socket"),
    ("mount-profiles", "saved mount profiles"),
    // Managed ssh material (private key, known_hosts pins, bootstrap cache, the
    // ssh CA key) lives under {config}/ssh, distinct from the user's ~/.ssh.
    ("ssh", "managed ssh material (key, known_hosts, cache, CA)"),
    ("permissions-migration", "permissions migration stamp"),
    ("identity.lock", "identity lock file"),
    ("devices.json.lock", "device store lock file"),
];

/// What a reset removed, and what it could not.
#[derive(Debug, Default)]
pub(crate) struct ResetOutcome {
    pub(crate) wiped: Vec<String>,
    pub(crate) failed: Vec<String>,
}

/// Remove every RESET_STATE entry under `cfg` through `remove` (Ok(true)
/// removed, Ok(false) absent, Err could not). Split from `reset_cmd` so the
/// list and the failure reporting are testable on a temp dir.
pub(crate) fn reset_state_in(
    cfg: &std::path::Path,
    remove: &dyn Fn(&std::path::Path) -> std::io::Result<bool>,
) -> ResetOutcome {
    let mut out = ResetOutcome::default();
    for (name, label) in RESET_STATE {
        let path = cfg.join(name);
        match remove(&path) {
            Ok(true) => out.wiped.push(format!("{label}  ({})", path.display())),
            Ok(false) => {}
            Err(e) => out.failed.push(format!("{label}  ({}): {e}", path.display())),
        }
    }
    out
}

pub(crate) fn resolve_mount_plan(
    caps: &UiCapability,
    mut peer: Option<String>,
    mut remote: Option<String>,
    local: Option<String>,
    mut read_write: bool,
) -> Result<MountPlan> {
    let opened_flow =
        caps.interactive && (peer.is_none() || remote.is_none() || interactive_requested());
    if remote.is_none() {
        let (device, path) = match peer.as_deref().and_then(|raw| raw.split_once(':')) {
            Some((device, path)) if !device.is_empty() && !path.is_empty() => {
                (device.to_string(), path.to_string())
            }
            _ => (String::new(), String::new()),
        };
        if !device.is_empty() && !path.is_empty() {
            peer = Some(device);
            remote = Some(path);
        }
    }
    if peer.is_none() {
        if !caps.interactive {
            bail!(
                "mount needs a device in non-interactive mode: tunlion mount <device> <remote> [local]"
            );
        }
        let devices = devices_load();
        if devices.is_empty() {
            bail!("no devices are connected; start with `tunlion add`");
        }
        let labels = devices
            .iter()
            .map(|(name, _)| {
                let relation = device_cert_for(name)
                    .and_then(|cert| {
                        load_owner_key().map(|owner| cert.user_pub == owner.public_key_bytes())
                    })
                    .map(|mine| if mine { "MY DEVICE" } else { "EXTERNAL" })
                    .unwrap_or("PAIRED");
                format!("{name:<20} {relation}")
            })
            .collect::<Vec<_>>();
        let selected =
            codeentry::pick("MOUNT FILES FROM", &labels)?.ok_or_else(|| anyhow!("cancelled"))?;
        peer = Some(devices[selected].0.clone());
    }
    let peer = peer.unwrap();
    // #206: a joined device knows its own ceiling (it printed it at join). If
    // the ceiling excludes mount, say so BEFORE opening a stream, instead of
    // letting the peer's denial come back as a ten-second transport timeout.
    // The device's ceiling lives on its record; a peer with no delegated
    // ceiling (an owner device or a plain pair) is not restricted here.
    if let Some(caps) = principal_ceiling_for(&peer) {
        if !caps.iter().any(|c| c == "mount") {
            bail!("{}", crate::identity_state::ceiling_refusal_here("mount", &peer, "mount", &caps));
        }
    }
    let remote = match remote {
        Some(remote) => remote,
        None if caps.interactive => {
            let entered = prompt_line(&format!("  Shared path on {peer} [.]: "))?;
            if entered.is_empty() {
                ".".to_string()
            } else {
                entered
            }
        }
        None => bail!("mount needs a remote path in non-interactive mode"),
    };
    let suggested = default_mount_point(&peer, &remote);
    let local = match local {
        Some(local) => local,
        None if caps.interactive && opened_flow => {
            let entered = prompt_line(&format!("  Mount here [{suggested}]: "))?;
            if entered.is_empty() {
                suggested
            } else {
                entered
            }
        }
        None => suggested,
    };
    if caps.interactive && opened_flow && !read_write {
        let access = prompt_line("  Access [read only] (type WRITE for read and write): ")?;
        read_write = access == "WRITE";
    }
    let plan = MountPlan {
        peer,
        remote,
        local,
        read_only: !read_write,
    };
    if caps.interactive && opened_flow {
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "MOUNT"));
        eprintln!("  source   {}:{}", plan.peer, plan.remote);
        eprintln!("  local    {}", plan.local);
        eprintln!(
            "  access   {}",
            if plan.read_only {
                "read only"
            } else {
                "read and write"
            }
        );
        eprintln!();
        eprintln!("  The remote device still enforces its configured share root and grant.");
        eprintln!(
            "  command  tunlion mount {} {} {}{}",
            command_arg(&plan.peer),
            command_arg(&plan.remote),
            command_arg(&plan.local),
            if plan.read_only { "" } else { " --read-write" }
        );
        let confirmation = prompt_line("\n  Press Enter to mount, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    Ok(plan)
}

/// Present the connected `client` as a local FUSE mount at `local`.
///
/// Before touching the filesystem we run a connection-honesty probe: one
/// GetAttr on the mount root under a timeout. An untrusted or refused peer
/// (the acceptor replies l2-close, which EOFs the stream) surfaces here as one
/// clean pre-mount error, instead of a cryptic failure on the first `ls` after
/// the kernel has already accepted the mount. On any failure we leave no stale
/// mountpoint behind (the #22 contract).
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "mount-macos"),
    all(target_os = "windows", feature = "mount-windows")
))]
pub(crate) async fn mount_fuse_cmd(
    mut client: crate::mount_proto::MountClient,
    plan: &MountPlan,
) -> Result<()> {
    use crate::mount_proto::{MountOp, MountResult};

    let peer = &plan.peer;
    let remote = &plan.remote;
    let local = &plan.local;
    client.set_read_only(plan.read_only);
    // 1. Probe the link before we mount anything.
    let root_enc = mount_proto::path_encode(std::path::Path::new("."));
    let probe = tokio::time::timeout(
        Duration::from_secs(10),
        client.call(MountOp::GetAttr { path: root_enc }),
    )
    .await;
    match probe {
        Ok(Ok(resp)) => match resp.result {
            MountResult::Ok(_) => {}
            MountResult::Err(e) => {
                bail!("mount refused by {peer}: {} (remote path {remote})", e.msg)
            }
        },
        Ok(Err(e)) => bail!(
            "mount to {peer} failed before it started: {e} \
             (peer may be untrusted or the link dropped; nothing was mounted)"
        ),
        Err(_) => bail!(
            "mount to {peer} timed out waiting for the remote filesystem \
             (no response in 10s; nothing was mounted)"
        ),
    }

    // 2. Create the mountpoint. Track whether WE created it so a failed mount
    //    cleans up after itself and never leaves a stale empty dir.
    let mnt = std::path::PathBuf::from(local);
    let created_dir = !mnt.exists();
    if created_dir {
        std::fs::create_dir_all(&mnt)
            .with_context(|| format!("failed to create mount point {local}"))?;
    }

    ui::say(&format!(
        "  {} mesh-native mount: {peer}:{remote} -> {local} ({}, FUSE)",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        if plan.read_only {
            "read only"
        } else {
            "read and write"
        }
    ));
    ui::say(&format!(
        "  {} mounted. unmount with `tunlion mount --off {local}` or ctrl-c",
        ui::paint(ui::Tone::Ok, ui::glyph_ok())
    ));

    // 3. Run the blocking FUSE session on a dedicated thread so the tokio mux
    //    pump keeps draining the transport. ctrl-c triggers an unmount, which
    //    makes the blocking session loop return.
    let mnt_run = mnt.clone();
    #[cfg(any(target_os = "linux", all(target_os = "macos", feature = "mount-macos")))]
    let session =
        tokio::task::spawn_blocking(move || crate::mount_fuse::run_mount(client, &mnt_run));
    #[cfg(all(target_os = "windows", feature = "mount-windows"))]
    let session =
        tokio::task::spawn_blocking(move || crate::mount_winfsp::run_mount(client, &mnt_run));

    let result: Result<()> = tokio::select! {
        joined = session => {
            match joined {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow::anyhow!("mount session panicked: {e}")),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            ui::say("\n  unmounting...");
            let _ = unmount_fuse(local);
            Ok(())
        }
    };

    // 4. On any error, remove the mountpoint we created (leave a pre-existing
    //    dir alone). A clean unmount leaves the empty dir in place, matching the
    //    legacy behaviour.
    if result.is_err() && created_dir {
        let _ = unmount_fuse(local);
        let _ = std::fs::remove_dir(&mnt);
    }
    result
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    fn temp_cfg(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tunlion-reset-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn populate(dir: &std::path::Path) {
        for (name, _) in RESET_STATE {
            let p = dir.join(name);
            if matches!(*name, "identity" | "ssh" | "mount-profiles") {
                std::fs::create_dir_all(&p).unwrap();
                std::fs::write(p.join("inner"), b"x").unwrap();
            } else {
                std::fs::write(&p, b"x").unwrap();
            }
        }
    }

    // The files the audit found `reset` leaving behind are on the list.
    #[test]
    fn reset_list_covers_every_config_dir_writer() {
        let names: Vec<&str> = RESET_STATE.iter().map(|(n, _)| *n).collect();
        for must in [
            "fleet.rv",
            "roster.json",
            "roster-state.json",
            "armed.json",
            "up.log",
            "daemon.log",
            "ssh_ca_issued.json",
            "ssh_ca_serial",
            "device.id",
            "overlay.announce-seq",
            "up.pid",
            "up.exe",
            "up.ready",
            "up.lock",
            "proxy.token",
            "control.sock",
            "identity",
            "devices.json",
            "caps.json",
            "ssh",
        ] {
            assert!(names.contains(&must), "reset does not remove {must}");
        }
    }

    // A real directory: everything on the list goes, nothing else does.
    #[test]
    fn reset_removes_all_state_and_only_state() {
        let dir = temp_cfg("all");
        populate(&dir);
        std::fs::write(dir.join("not-ours.txt"), b"keep").unwrap();
        let out = reset_state_in(&dir, &crate::reset_remove);
        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert_eq!(out.wiped.len(), RESET_STATE.len());
        for (name, _) in RESET_STATE {
            assert!(!dir.join(name).exists(), "{name} survived reset");
        }
        assert!(dir.join("not-ours.txt").exists(), "reset removed a file it does not own");
        // Idempotent: a second run finds nothing and fails nothing.
        let again = reset_state_in(&dir, &crate::reset_remove);
        assert!(again.wiped.is_empty() && again.failed.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A deletion that fails is reported, never swallowed: this is what lets
    // `reset_cmd` refuse to call the machine a clean slate.
    #[test]
    fn reset_reports_every_failed_deletion() {
        let dir = temp_cfg("fail");
        populate(&dir);
        let failing = |p: &std::path::Path| -> std::io::Result<bool> {
            if p.ends_with("fleet.rv") || p.ends_with("ssh") {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
            } else {
                crate::reset_remove(p)
            }
        };
        let out = reset_state_in(&dir, &failing);
        assert_eq!(out.failed.len(), 2, "{:?}", out.failed);
        assert!(out.failed.iter().any(|f| f.contains("fleet.rv") && f.contains("denied")));
        assert!(out.failed.iter().any(|f| f.contains("ssh")));
        assert_eq!(out.wiped.len(), RESET_STATE.len() - 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // reset_remove's outcomes: absent is Ok(false), removed is Ok(true) (the
    // Err arm is exercised through the injected remover above).
    #[test]
    fn reset_remove_distinguishes_absent_from_removed() {
        let dir = temp_cfg("err");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").unwrap();
        assert!(!crate::reset_remove(&dir.join("absent")).unwrap());
        assert!(crate::reset_remove(&file).unwrap());
        assert!(!file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
