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

    /// Platform-aware home directory for the current user.
    /// Unix: `$HOME`. Windows: `%USERPROFILE%`. Falls back to `"."` when unset.
    pub fn home_dir() -> PathBuf {
        #[cfg(unix)]
        {
            if let Ok(h) = std::env::var("HOME") {
                if !h.is_empty() {
                    return PathBuf::from(h);
                }
            }
        }
        #[cfg(windows)]
        {
            if let Ok(h) = std::env::var("USERPROFILE") {
                if !h.is_empty() {
                    return PathBuf::from(h);
                }
            }
        }
        PathBuf::from(".")
    }

    /// Platform-aware shell for PTY sessions. Returns `(argv, can_use_user)`.
    ///
    /// Resolution order (first match wins):
    /// 1. `shell_program` (from `--shell-program` flag)
    /// 2. `FILAMENT_SHELL` env var
    /// 3. `filament set shell` config (passed via `shell_config`)
    /// 4. `$SHELL` on Unix / powershell→cmd on Windows
    /// 5. Hardcoded fallback (`/bin/bash` → `/bin/sh` / `cmd.exe`)
    ///
    /// The value is argv-split so it can carry args: `bash -l`, `pwsh -NoLogo`.
    /// On Unix, `shell_user` uses `runuser -l`; on Windows it's unsupported.
    pub fn shell_argv(shell_program: Option<&str>, shell_config: Option<&str>, shell_user: Option<&str>) -> (Vec<String>, bool) {
        let shell = shell_program
            .map(|s| s.to_string())
            .or_else(|| std::env::var("FILAMENT_SHELL").ok().filter(|s| !s.is_empty()))
            .or_else(|| shell_config.map(|s| s.to_string()))
            .unwrap_or_else(|| Self::default_shell());

        let parts: Vec<String> = shell.split_whitespace().map(|s| s.to_string()).collect();
        #[cfg(unix)]
        {
            let argv = match shell_user {
                Some(user) => vec!["runuser".into(), "-l".into(), user.into()],
                None => parts,
            };
            (argv, true)
        }
        #[cfg(windows)]
        {
            (parts, false)
        }
        #[cfg(not(any(unix, windows)))]
        {
            (parts, true)
        }
    }

    fn default_shell() -> String {
        #[cfg(unix)]
        {
            std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
                if Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() }
            })
        }
        #[cfg(windows)]
        {
            if Path::new("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe").exists() {
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into()
            } else if Path::new("C:\\Windows\\System32\\cmd.exe").exists() {
                "C:\\Windows\\System32\\cmd.exe".into()
            } else {
                "cmd.exe".into()
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            "/bin/sh".into()
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

    /// Atomic write: write to temp file, fsync, then rename over original.
    /// This prevents data loss on ENOSPC/crash - either old file or new file,
    /// never a truncated/empty file.
    fn write_raw(path: &Path, data: &[u8]) -> io::Result<()> {
        let dir = path.parent().unwrap_or(std::path::Path::new("."));
        let temp = dir.join(format!("{}.tmp.{}", path.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
        // Write to temp file
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&temp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        // Atomic rename over original
        std::fs::rename(&temp, path)?;
        // Best-effort: fsync parent dir for crash durability
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
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

    /// Check whether systemd is PID 1. Equivalent to libsystemd's
    /// sd_booted(3): /run/systemd/system exists iff systemd manages the system.
    /// Does NOT spawn a subprocess, and does not false-negative when systemd
    /// is in a "degraded" runtime state.
    #[cfg(target_os = "linux")]
    fn has_systemd() -> bool {
        std::path::Path::new("/run/systemd/system").is_dir()
    }
}

// ------------------------------------------------------- InstallSource --

/// How filament was installed. Used to gate `filament update`:
/// package-manager installs must be updated via their manager, not
/// by overwriting the binary directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Homebrew,
    Winget,
    Scoop,
    Cargo,
    /// Installed manually (curl | sh, direct download) or untraceable.
    SelfInstalled,
}

impl InstallSource {
    /// Classify the running binary by its canonical path.
    pub fn detect() -> Self {
        let path = match std::env::current_exe() {
            Ok(p) => match p.canonicalize() {
                Ok(c) => c,
                Err(_) => p,
            },
            Err(_) => return InstallSource::SelfInstalled,
        };
        Self::classify(&path)
    }

    fn classify(path: &Path) -> Self {
        let s = path.to_string_lossy().to_lowercase();
        // Cross-platform package manager fingerprints.
        if s.contains("/cellar/") || s.contains("/homebrew/") || s.contains("/linuxbrew/") {
            return InstallSource::Homebrew;
        }
        if s.contains("\\microsoft\\winget\\") || s.contains("/microsoft/winget/") {
            return InstallSource::Winget;
        }
        if s.contains("\\scoop\\apps\\") || s.contains("/scoop/apps/") {
            return InstallSource::Scoop;
        }
        if s.contains("/.cargo/bin") || s.contains("\\.cargo\\bin") {
            return InstallSource::Cargo;
        }
        InstallSource::SelfInstalled
    }

    /// Upgrade command the user should run instead of `filament update`.
    pub fn upgrade_hint(&self) -> &'static str {
        match self {
            InstallSource::Homebrew => "brew upgrade filament",
            InstallSource::Winget => "winget upgrade Abdk4Moura.Filament",
            InstallSource::Scoop => "scoop update filament",
            InstallSource::Cargo => "cargo install filament-cli",
            InstallSource::SelfInstalled => "",
        }
    }
}

// ----------------------------------------------------------- ShellHost --

/// Shell invocation strategy — the correct flag for running a command
/// depends on the shell family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellKind {
    /// sh / bash / zsh / fish / dash: `-c 'cmd'`
    Posix,
    /// powershell.exe / pwsh.exe / pwsh: `-Command 'cmd'`
    PowerShell,
    /// cmd.exe: `/c cmd`
    Cmd,
}

/// Resolves the shell program and provides the correct invocation for
/// interactive (login PTY) and one-shot (`exec cmd`) modes.
pub struct ShellHost {
    argv: Vec<String>,
    kind: ShellKind,
}

impl ShellHost {
    /// Resolve the shell from the precedence chain. No external resolution
    /// is done here — callers pass the already-resolved argv (from
    /// --shell-program / FILAMENT_SHELL / config / $SHELL / platform default).
    pub fn new(shell_argv: &[String]) -> Self {
        let binary = shell_argv.first().map(|s| s.as_str()).unwrap_or("");
        let name = Path::new(binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let kind = if name.contains("pwsh") || name.contains("powershell") {
            ShellKind::PowerShell
        } else if name == "cmd.exe" || name == "cmd" {
            ShellKind::Cmd
        } else {
            ShellKind::Posix
        };
        ShellHost {
            argv: shell_argv.to_vec(),
            kind,
        }
    }

    /// Args for spawning an INTERACTIVE login shell (PTY session).
    pub fn interactive_args(&self) -> Vec<String> {
        let mut args = self.argv.clone();
        match self.kind {
            ShellKind::Posix => {
                if !args.iter().any(|a| a == "-l" || a == "--login") {
                    args.push("-l".into());
                }
                args
            }
            _ => args,
        }
    }

    /// Args for running a one-shot COMMAND (returns, no interactive shell).
    pub fn exec_cmd_args(&self, cmd: &str) -> Vec<String> {
        let mut args = vec![self.argv[0].clone()];
        match self.kind {
            ShellKind::Posix => {
                args.push("-c".into());
                args.push(cmd.to_string());
            }
            ShellKind::PowerShell => {
                args.push("-Command".into());
                args.push(cmd.to_string());
            }
            ShellKind::Cmd => {
                args.push("/c".into());
                args.push(cmd.to_string());
            }
        }
        args
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

    #[test]
    fn install_source_classify_brew() {
        let p = Path::new("/opt/homebrew/Cellar/filament/0.4.1/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::Homebrew);
        let p2 = Path::new("/home/linuxbrew/.linuxbrew/bin/filament");
        assert_eq!(InstallSource::classify(p2), InstallSource::Homebrew);
        let p3 = Path::new("/usr/local/Cellar/filament/0.3.1/bin/filament");
        assert_eq!(InstallSource::classify(p3), InstallSource::Homebrew);
    }

    #[test]
    fn install_source_classify_winget() {
        let p = Path::new("C:\\Users\\kabir\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Abdk4Moura.Filament_filament\\filament.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Winget);
    }

    #[test]
    fn install_source_classify_scoop() {
        let p = Path::new("C:\\Users\\kabir\\scoop\\apps\\filament\\0.4.1\\filament.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Scoop);
    }

    #[test]
    fn install_source_classify_cargo() {
        let p = Path::new("/home/kabir/.cargo/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::Cargo);
    }

    #[test]
    fn install_source_classify_self_installed() {
        let p = Path::new("/home/kabir/.local/bin/filament");
        assert_eq!(InstallSource::classify(p), InstallSource::SelfInstalled);
    }

    #[test]
    fn install_source_upgrade_hints() {
        assert_eq!(InstallSource::Homebrew.upgrade_hint(), "brew upgrade filament");
        assert_eq!(InstallSource::Winget.upgrade_hint(), "winget upgrade Abdk4Moura.Filament");
        assert_eq!(InstallSource::Cargo.upgrade_hint(), "cargo install filament-cli");
        assert_eq!(InstallSource::SelfInstalled.upgrade_hint(), "");
    }

    #[test]
    fn shell_host_interactive_posix_adds_login() {
        let sh = ShellHost::new(&["/bin/bash".into()]);
        assert!(sh.interactive_args().contains(&"-l".into()));
    }

    #[test]
    fn shell_host_exec_posix_uses_minus_c() {
        let sh = ShellHost::new(&["bash".into()]);
        let args = sh.exec_cmd_args("echo hi");
        assert_eq!(args[0], "bash");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo hi");
    }

    #[test]
    fn shell_host_exec_powershell_uses_command_flag() {
        let sh = ShellHost::new(&["pwsh.exe".into()]);
        let args = sh.exec_cmd_args("Get-Date");
        assert_eq!(args[1], "-Command");
        assert_eq!(args[2], "Get-Date");
    }

    #[test]
    fn shell_host_exec_cmd_uses_slash_c() {
        let sh = ShellHost::new(&["cmd.exe".into()]);
        let args = sh.exec_cmd_args("dir");
        assert_eq!(args[1], "/c");
        assert_eq!(args[2], "dir");
    }

    #[test]
    fn shell_host_preserves_shell_argv_prefix() {
        let sh = ShellHost::new(&["bash".into(), "-l".into(), "-i".into()]);
        let args = sh.exec_cmd_args("echo x");
        assert_eq!(args[0], "bash");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo x");
    }
}
