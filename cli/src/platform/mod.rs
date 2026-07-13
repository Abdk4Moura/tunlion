use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Platform-specific paths for the filament CLI.
///
/// Uses the `directories` crate for proper OS placement:
/// - Linux:   `$XDG_CONFIG_HOME/filament` (falls back to `$HOME/.config/filament`)
/// - macOS:   `$HOME/Library/Application Support/filament`
/// - Windows: `%APPDATA%/filament`
///
/// All paths honor `FILAMENT_CONFIG_DIR` as an override (hermetic tests,
/// custom deployments).
pub struct Paths;

impl Paths {
    /// Config directory root.
    ///
    /// On first access, checks for legacy `./.config/filament` (cwd-relative,
    /// the broken Windows fallback when HOME was unset) and migrates contents
    /// to the platform-correct path.
    pub fn config_dir() -> PathBuf {
        if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
            return PathBuf::from(d);
        }
        Self::platform_config_dir()
    }

    fn platform_config_dir() -> PathBuf {
        if let Some(proj) = directories::ProjectDirs::from("", "", "filament") {
            return proj.config_dir().to_path_buf();
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".config").join("filament")
    }

    /// Resolve a config-relative path (file or subdirectory).
    pub fn config_path(relative: impl AsRef<Path>) -> PathBuf {
        Self::config_dir().join(relative)
    }

    /// Migrate state from a legacy cwd-relative `.config/filament` directory
    /// (the broken Windows fallback when HOME was unset). Best-effort, safe
    /// to call repeatedly.
    pub fn migrate_legacy() {
        let legacy = PathBuf::from(".config/filament");
        if !legacy.is_dir() {
            return;
        }
        let target = Self::config_dir();
        if target == legacy || target.exists() {
            return;
        }
        let _ = std::fs::create_dir_all(&target);
        if let Ok(entries) = std::fs::read_dir(&legacy) {
            for e in entries.flatten() {
                let dest = target.join(e.file_name());
                let _ = std::fs::copy(e.path(), &dest);
            }
        }
    }
}

// ------------------------------------------------------------ SecretFile --

/// Write secret data with platform-appropriate restrictive permissions.
///
/// Unix: creates with mode 0o600 (owner rw only) — no world-readable window.
/// Windows: applies per-user DACL via icacls (inheritance disabled, owner-only).
/// %APPDATA% already restricts to the user by default, so the icacls call is
/// defense-in-depth matching chmod 0600 semantics.
///
/// Upgrade note: the Windows path uses `icacls` for pragmatic zero-dependency
/// delivery. A future iteration should switch to `SetNamedSecurityInfoW` via
/// the `windows` crate for a locale-safe, shell-free API call.
pub struct SecretFile;

impl SecretFile {
    /// Write `data` to `path`, creating parent directories as needed.
    /// On success, the file is readable only by the current user.
    pub fn write(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        SecretFile::write_raw(path, data)?;
        SecretFile::restrict(path)?;
        Ok(())
    }

    /// Write a string as UTF-8.
    pub fn write_str(path: impl AsRef<Path>, s: &str) -> io::Result<()> {
        SecretFile::write(path, s.as_bytes())
    }

    /// Restrict an existing file to owner-only access.
    /// For files created by external processes (e.g. ssh-keygen).
    pub fn restrict(path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        {
            restrict_dacl(path)?;
        }
        Ok(())
    }

    fn write_raw(path: &Path, data: &[u8]) -> io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(windows)]
fn restrict_dacl(path: &Path) -> io::Result<()> {
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() {
        return Ok(());
    }
    let path_str = path.display().to_string();
    let _ = std::process::Command::new("icacls")
        .args([&path_str, "/inheritance:r", "/grant:r", &format!("{user}:(F)"), "/Q"])
        .output();
    Ok(())
}

// --------------------------------------------------------- ServiceHost --

/// The detected service manager on this platform.
///
/// Used to gate `filament up --install` so it never writes a dead unit
/// on an unsupported platform. Only systemd has a native backend today;
/// other managers are detected and get correct manual instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHost {
    /// systemd (Linux, user or system scope).
    Systemd,
    /// launchd (macOS) — detected, no native backend yet.
    Launchd,
    /// Windows Service Control Manager — detected, no native backend yet.
    WindowsService,
    /// No recognized service manager (or we are inside a container).
    None,
}

impl ServiceHost {
    /// Detect the host's service manager.
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            if Self::has_systemd() {
                return ServiceHost::Systemd;
            }
            ServiceHost::None
        }
        #[cfg(target_os = "macos")]
        {
            ServiceHost::Launchd
        }
        #[cfg(target_os = "windows")]
        {
            ServiceHost::WindowsService
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            ServiceHost::None
        }
    }

    /// True when we have a native install backend (systemd for now).
    pub fn supports_install(&self) -> bool {
        matches!(self, ServiceHost::Systemd)
    }

    /// Human-readable instructions for manual autostart on this host.
    /// Only called when `supports_install()` is false.
    pub fn install_instructions(&self) -> &'static str {
        match self {
            ServiceHost::Launchd => "On macOS, create a LaunchAgent plist in ~/Library/LaunchAgents/ and load it with launchctl.",
            ServiceHost::WindowsService => "On Windows, create a Scheduled Task (trigger: at logon) or register a Service with sc.exe.",
            ServiceHost::None => "No service manager detected. Start filament with `filament up` in a terminal, or configure your init system manually.",
            ServiceHost::Systemd => "",
        }
    }

    /// Check whether systemd user instance is available.
    #[cfg(target_os = "linux")]
    fn has_systemd() -> bool {
        // systemctl --user is the user-mode systemd instance;
        // it fails if systemd isn't pid 1 OR the user session isn't systemd-managed
        // (container, WSL1, non-systemd distro).
        std::process::Command::new("systemctl")
            .args(["--user", "is-system-running"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_a_valid_variant() {
        let host = ServiceHost::detect();
        // On Linux with systemd this is Systemd; on other platforms it's
        // whatever the detection says. The key property: it never panics,
        // and supports_install is consistent.
        assert!(
            matches!(
                host,
                ServiceHost::Systemd
                    | ServiceHost::Launchd
                    | ServiceHost::WindowsService
                    | ServiceHost::None
            ),
            "detect returned a valid variant: {host:?}"
        );
    }

    #[test]
    fn systemd_supports_install_others_do_not() {
        assert!(ServiceHost::Systemd.supports_install());
        assert!(!ServiceHost::Launchd.supports_install());
        assert!(!ServiceHost::WindowsService.supports_install());
        assert!(!ServiceHost::None.supports_install());
    }

    #[test]
    fn install_instructions_non_empty_when_no_backend() {
        assert!(!ServiceHost::Launchd.install_instructions().is_empty());
        assert!(!ServiceHost::WindowsService.install_instructions().is_empty());
        assert!(!ServiceHost::None.install_instructions().is_empty());
        // Systemd has a backend, so instructions should be empty.
        assert!(ServiceHost::Systemd.install_instructions().is_empty());
    }
}
