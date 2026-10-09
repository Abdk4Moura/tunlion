//! Shell authority helpers and the daemon/service probes.
//!
//! The shell half decides who may be given a shell and under what terms: whether a
//! shell may be served at all (any_shell_grant), the grant name lists, the argv the
//! owner-equivalence gate builds, the root warning, and the acknowledgement that
//! must be explicit before a shell-user PTY is allowed.
//!
//! The probe half answers questions about this machine's daemon and its service
//! manager: is it running, is it alive, and which manager owns a given pid/cgroup.
//!
//! NO member is definition-gated. Three statement-level cfg attributes travel with
//! their bodies (one in shell_root_note, two in service_manager_for_pid). The
//! pre-check confirmed no member holds a `tunlion <command>` instruction line, so
//! the two hardcoded-file-list tests are unaffected by this move.
use crate::devices_store::devices_path;
use crate::file_io::pidfile;
use crate::shared_defs::ServiceManager;
use crate::{platform, same_executable, settings};
use anyhow::{Result, bail};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// True if ANY known device has been granted the `shell` capability. The daemon
/// uses this to switch L2/shell ON even for a plain `tunlion up`: otherwise
/// `tunlion grant <dev> shell` writes a grant the running daemon never consults
/// (l2_enabled was set only by --shell/--shell-only at startup), so the grant
/// silently did nothing and `tunlion shell --ssh` timed out. With this, a grant alone is
/// enough; the per-device cap gate (auto_allows || device_allows) still denies
/// every non-granted device, so this does NOT broaden access, it only honors the
/// grants that already exist.
pub(crate) fn any_shell_grant() -> bool {
    !shell_grant_names_at(&devices_path()).is_empty()
}

pub(crate) fn any_shell_grant_at(path: &Path) -> bool {
    !shell_grant_names_at(path).is_empty()
}

/// `any_shell_grant`, re-read whenever devices.json changes.
///
/// The daemon used to evaluate `any_shell_grant()` ONCE, at startup, into its
/// `l2_enabled` switch. So on a plain `up`, `tunlion grant <dev> shell` wrote a
/// grant the running daemon could never act on: every open was refused with
/// "shell serving is off there" (true of the stale switch, false of the
/// config) until someone restarted the daemon, and nothing said a restart was
/// needed. The receive loop now asks this on every iteration, so a grant (or
/// the revoke of the last one) takes effect on the next open. Keyed on the
/// file's mtime and length, the same cross-process invalidation the cap-store
/// cache uses, so the hot loop pays one stat, not a parse.
pub(crate) fn any_shell_grant_live() -> bool {
    use std::sync::Mutex;
    type Key = (PathBuf, Option<std::time::SystemTime>, u64);
    static CACHE: Mutex<Option<(Key, bool)>> = Mutex::new(None);
    let path = devices_path();
    let meta = std::fs::metadata(&path).ok();
    let key: Key = (
        path.clone(),
        meta.as_ref().and_then(|m| m.modified().ok()),
        meta.as_ref().map(|m| m.len()).unwrap_or(0),
    );
    if let Ok(c) = CACHE.lock() {
        if let Some((k, v)) = c.as_ref() {
            if *k == key {
                return *v;
            }
        }
    }
    let v = any_shell_grant_at(&path);
    if let Ok(mut c) = CACHE.lock() {
        *c = Some((key, v));
    }
    v
}

pub(crate) fn shell_grant_names() -> Vec<String> {
    shell_grant_names_at(&devices_path())
}

pub(crate) fn shell_grant_names_at(path: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    let mut names: Vec<String> = arr
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| {
            d.get("caps")
                .and_then(|c| c.as_array())
                .map(|list| list.iter().any(|c| c.as_str() == Some("shell")))
                .unwrap_or(false)
        })
        .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    names.sort();
    names
}

/// True when an `up` daemon is currently running (drives the "takes effect on
/// next up" hint after a settings change).
pub(crate) fn daemon_running() -> bool {
    daemon_alive().is_some()
}

pub(crate) fn daemon_alive() -> Option<u32> {
    let raw = std::fs::read_to_string(pidfile()).ok()?;
    let mut lines = raw.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    // The executable the daemon recorded when it wrote the pidfile. A pidfile
    // from before this fix records only the pid; the daemon and this CLI are
    // the same installed binary, so fall back to our own executable.
    let recorded = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let expected = recorded.or_else(|| std::env::current_exe().ok())?;
    // Identify the process by its executable path, never by matching a name.
    // process_exe_path returns None for a dead or recycled pid, which is
    // exactly the case the pidfile alone cannot detect.
    let live = platform::process_exe_path(pid)?;
    same_executable(&live, &expected).then_some(pid)
}

/// The argv for a web-shell PTY.
///
/// M-1 (owner-equivalence gate): when `--shell-user <name>` is set, drop the PTY
/// to that account via `runuser -l <user>`. Without it, the PTY runs as the
/// up-process user and is owner-equivalent at any uid. Startup requires the
/// explicit `--i-know` acknowledgement in `require_shell_owner_ack`; root also
/// makes the shell machine-wide. See docs/security/web-shell-review.md.
pub(crate) fn shell_argv(
    shell_program: Option<&str>,
    shell_user: Option<&str>,
) -> (Vec<String>, bool) {
    let shell_config = settings::get_str("shell-program", None);
    platform::Paths::shell_argv(shell_program, shell_config.as_deref(), shell_user)
}

pub(crate) fn shell_root_note() -> &'static str {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return " This process is root, so the shell can control the whole machine.";
        }
    }
    ""
}

pub(crate) fn require_shell_owner_ack(
    shell_enabled: bool,
    shell_user: Option<&str>,
    can_use_user: bool,
    i_know: bool,
) -> Result<()> {
    if shell_enabled && shell_user.is_some() && !can_use_user && !i_know {
        bail!(
            "--shell-user is unsupported on this platform; the PTY would run as this process's user and retain the owner's authority. Pass --i-know to deliberately serve an owner-equivalent shell."
        );
    }
    if shell_enabled && shell_user.is_none() && !i_know {
        bail!("{}", owner_shell_refusal(!shell_root_note().is_empty()));
    }
    Ok(())
}

/// The refusal for serving a shell as the owner without saying so. One plain
/// sentence of risk, then `--i-know` as the explicit choice it is. The gate
/// itself is unchanged; only the words are. For a non-root user `--i-know` is
/// the only way to serve a shell at all (`--shell-user` needs root for
/// runuser), so it is presented as the path, not buried as an override.
pub(crate) fn owner_shell_refusal(is_root: bool) -> String {
    let risk = "A shell served this way runs as you, so any device you let in gets the owner's authority: it can do anything you can, including use your tunlion keys to act as you.";
    if is_root {
        format!(
            "{risk} This process is root, so that means the whole machine.\n\
             To serve it anyway, say so explicitly:  tunlion up --shell --i-know\n\
             Safer: drop shells to a separate account:  tunlion up --shell --shell-user <account>"
        )
    } else {
        format!(
            "{risk}\n\
             If that is what you want, say so explicitly:  tunlion up --shell --i-know\n\
             (or allow single devices instead of all of them:  tunlion grant <device> shell)"
        )
    }
}

pub(crate) fn service_manager_for_cgroup(cg: &str) -> Option<ServiceManager> {
    // The unit name is matched as a cgroup segment (`/filament.service`), never
    // as a substring, so a neighbouring unit (`my-filament.service`) cannot
    // collide. The scope decides which manager.
    if cg.contains("/system.slice/filament.service") {
        return Some(ServiceManager::SystemdSystem);
    }
    if cg.contains("/app.slice/filament.service") && cg.contains("/user.slice/") {
        return Some(ServiceManager::SystemdUser);
    }
    None
}

pub(crate) fn service_manager_for_pid(pid: u32) -> Option<ServiceManager> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|cg| service_manager_for_cgroup(&cg))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
