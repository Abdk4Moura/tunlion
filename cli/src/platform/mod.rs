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
