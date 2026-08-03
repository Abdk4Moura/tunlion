use std::path::{Path, PathBuf};

use anyhow::Result;

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

    /// Repair permissions on sensitive state left by older releases. This is
    /// intentionally separate from SecretFile::write: an unchanged legacy
    /// file is otherwise never rewritten and never gets its mode repaired.
    pub fn repair_sensitive_permissions() -> std::io::Result<usize> {
        repair_sensitive_permissions_in(&Self::config_dir())
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
    /// On Unix, `shell_user` uses `runuser -l`; on Windows it's unsupported
    /// because running a process as another user requires either elevated
    /// privileges (CreateProcessAsUser) or the target user's credentials
    /// (CreateProcessWithLogonW), both of which have security implications.
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

fn repair_sensitive_permissions_in(dir: &Path) -> std::io::Result<usize> {
    let mut repaired = 0;
    for name in [
        "caps.json",
        "devices.json",
        "device.id",
        "peerconf",
        "identity.ed25519",
        "overlay.ed25519",
        "diag.jsonl",
    ] {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            repaired += repair_sensitive_dir(&path)?;
        } else if repair_sensitive_file(&path)? {
            repaired += 1;
        }
    }
    Ok(repaired)
}

fn repair_sensitive_dir(dir: &Path) -> std::io::Result<usize> {
    let mut repaired = 0;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(dir)?.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            repaired += 1;
        }
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && repair_sensitive_file(&path)? {
            repaired += 1;
        }
    }
    Ok(repaired)
}

fn repair_sensitive_file(path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o777 == 0o600 {
            return Ok(false);
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(true);
    }
    #[cfg(windows)]
    {
        // Reassert the owner-only ACL on existing files. APPDATA is already
        // user-scoped, but old files may predate the SecretFile writer.
        SecretFile::restrict(path)?;
        return Ok(true);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(false)
    }
}

// ------------------------------------------------------------ SecretFile --

// The safe restricted-file writer now lives in the standalone `secret-write`
// crate. Re-exported here so existing `crate::platform::SecretFile` call sites
// (identity.rs, sshkeys.rs, capability.rs, main.rs, overlay.rs, settings.rs)
// keep resolving unchanged.
pub use secret_write::SecretFile;

/// Host key-persistence adapter for the standalone `filament-id` crate: it
/// forwards to `secret-write` (owner-only atomic write) and `Paths` (config
/// dir) so identity has no dependency on this platform module. Passed to
/// `identity::UserKey::generate` / `::load` at the CLI's call sites.
pub struct PlatformKeyStore;

impl filament_id::KeyStore for PlatformKeyStore {
    fn write_secret(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        SecretFile::write(path, data)
    }
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn config_path(&self, relative: &str) -> PathBuf {
        Paths::config_path(relative)
    }
}

// --------------------------------------------------------- ServiceHost --

/// The detected service manager on this platform.
///
/// Supports two install tiers:
/// - **system**: privileged, kernel TUN, autostart at boot (requires admin).
/// - **user**: unprivileged, userspace-only, autostart at logon.
///
/// `filament up --install` tries system first (elevation popup), falls back to
/// user on decline. `--uninstall` removes whatever was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHost {
    Systemd,
    Launchd,
    WindowsService,
    None,
}

/// Outcome of an install attempt.
pub enum InstallResult {
    /// Privileged system-level service installed.
    System,
    /// User-level autostart installed (admin declined or unavailable).
    User,
}

impl ServiceHost {
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            if Self::has_systemd() { return ServiceHost::Systemd; }
            ServiceHost::None
        }
        #[cfg(target_os = "macos")]
        { ServiceHost::Launchd }
        #[cfg(target_os = "windows")]
        { ServiceHost::WindowsService }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        { ServiceHost::None }
    }

    pub fn supports_install(&self) -> bool {
        !matches!(self, ServiceHost::None)
    }

    pub fn install_instructions(&self) -> &'static str {
        match self {
            ServiceHost::Systemd => "",
            ServiceHost::Launchd => "On macOS, create a LaunchAgent plist in ~/Library/LaunchAgents/ and load it with launchctl.",
            ServiceHost::WindowsService => "On Windows, create a Scheduled Task (trigger: at logon) or register a Service with sc.exe.",
            ServiceHost::None => "No service manager detected. Start filament with `filament up` in a terminal, or configure your init system manually.",
        }
    }

    /// Attempt privileged install (system-level). Returns Ok if the privileged
    /// path completed, Err if elevation was declined or unavailable (caller
    /// should fall back to install_user).
    pub fn install_system(&self, exe: &Path, shell_args: &str) -> Result<InstallResult> {
        // If already elevated (root on unix, admin on Windows), do the actual
        // system install directly. Otherwise, try to elevate.
        if self.is_elevated() {
            self.do_install_system(exe, shell_args)?;
            return Ok(InstallResult::System);
        }
        let elevated = self.try_elevate(exe, shell_args)?;
        if elevated {
            return Ok(InstallResult::System);
        }
        Err(anyhow::anyhow!("elevation declined"))
    }

    fn is_elevated(&self) -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            true // try_elevate already ran via ShellExecute; this host is the elevated instance
        }
        #[cfg(not(any(unix, windows)))]
        { false }
    }

    fn do_install_system(&self, exe: &Path, shell_args: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                let unit = std::path::Path::new("/etc/systemd/system/filament.service");
                std::fs::write(unit, format!(
                    "[Unit]\nDescription=Filament drop target\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=multi-user.target\n",
                    exe.display(), shell_args
                ))?;
                let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
                let _ = std::process::Command::new("systemctl").args(["enable", "--now", "filament"]).status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // Quote the exe inside binPath so a spaced install path (e.g.
                // C:\Program Files\...) is parsed as one program, not split.
                let status = std::process::Command::new("sc")
                    .args(["create", "filament", "binPath=", &format!("\"{}\" up{}", exe.display(), shell_args),
                           "start=", "auto", "obj=", "LocalSystem"])
                    .status()?;
                if !status.success() {
                    anyhow::bail!("sc create failed");
                }
                let _ = std::process::Command::new("sc").args(["start", "filament"]).status();
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let plist = std::path::Path::new("/Library/LaunchDaemons/autumated.filament.plist");
                std::fs::write(plist, format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>autumated.filament</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>up</string>{}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>"#,
                    exe.display(), shell_args
                ))?;
                let _ = std::process::Command::new("launchctl").args(["bootstrap", "system"]).arg(plist).status();
            }
            _ => anyhow::bail!("system install not supported"),
        }
        Ok(())
    }

    /// Install user-level autostart (no elevation needed).
    pub fn install_user(&self, exe: &Path, shell_args: &str) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                install_systemd_user(exe, shell_args)
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                install_scheduled_task(exe, shell_args)
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                install_launch_agent(exe, shell_args)
            }
            _ => Err(anyhow::anyhow!("no service manager detected")),
        }
    }

    /// Uninstall any previously-registered service or autostart.
    pub fn uninstall(&self) {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "disable", "--now", "filament"])
                    .status();
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--now", "filament"])
                    .status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                let _ = std::process::Command::new("sc")
                    .args(["delete", "filament"])
                    .status();
                let _ = std::process::Command::new("schtasks")
                    .args(["/delete", "/tn", "Filament", "/f"])
                    .status();
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootout", "gui/501/autumated.filament"])
                    .status();
            }
            _ => {}
        }
    }

    /// Try to elevate and re-run ourselves with admin privileges. Returns
    /// true if the elevation dialog was accepted, false if declined.
    fn try_elevate(&self, exe: &Path, shell_args: &str) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let ok = std::process::Command::new("pkexec")
                .arg(exe)
                .args(["--install-system", shell_args])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            return Ok(ok);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt;

            unsafe extern "system" {
                fn ShellExecuteW(
                    hwnd: isize,
                    lpOperation: *const u16,
                    lpFile: *const u16,
                    lpParameters: *const u16,
                    lpDirectory: *const u16,
                    nShowCmd: i32,
                ) -> isize;
                fn GetLastError() -> u32;
            }

            const SW_HIDE: i32 = 0;

            let exe_win: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

            let args = format!("--install-system {shell_args}");
            let args_win: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();

            let verb: Vec<u16> = "runas\0".encode_utf16().collect();

            let ret = unsafe {
                ShellExecuteW(
                    0, // hwnd
                    verb.as_ptr(),
                    exe_win.as_ptr(),
                    args_win.as_ptr(),
                    std::ptr::null(),
                    SW_HIDE,
                )
            };

            // ShellExecuteW returns HINSTANCE > 32 on success.
            if ret as usize > 32 {
                return Ok(true);
            }
            let code = unsafe { GetLastError() };
            if code == 1223 {
                // ERROR_CANCELLED — user declined UAC
                return Ok(false);
            }
            anyhow::bail!("ShellExecuteW failed: {}", code);
        }
        #[cfg(target_os = "macos")]
        {
            // Escape the exe path and shell_args for the AppleScript do-shell-script
            // double-quote context. The shell_args are our own --shell / --shell-only
            // flags so they are constrained, but we escape defensively anyway.
            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!(
                "do shell script \"'{}' --install-system {}\" with administrator privileges",
                esc(&exe.display().to_string()),
                esc(shell_args)
            );
            let ok = std::process::Command::new("osascript")
                .args(["-e", &script])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            return Ok(ok);
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        { Ok(false) }
    }

    #[cfg(target_os = "linux")]
    fn has_systemd() -> bool {
        Path::new("/run/systemd/system").is_dir()
    }
}

// ------------------------------------------------- platform installers --

#[cfg(target_os = "linux")]
fn install_systemd_user(exe: &Path, shell_args: &str) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit = unit_dir.join("filament.service");
    std::fs::write(&unit, format!(
        "[Unit]\nDescription=Filament drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=default.target\n",
        exe.display(), shell_args
    ))?;
    let ok = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).status()
        .and_then(|_| std::process::Command::new("systemctl").args(["--user", "enable", "--now", "filament"]).status())
        .map(|s| s.success()).unwrap_or(false);
    if !ok {
        anyhow::bail!("systemctl --user enable --now filament failed; run it manually or check journalctl --user -u filament");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_scheduled_task(exe: &Path, shell_args: &str) -> Result<()> {
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger/></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Actions><Exec><Command>{}</Command><Arguments>up{}</Arguments></Exec></Actions>
</Task>"#,
        exe.display(), shell_args
    );
    let tmp = std::env::temp_dir().join("filament-task.xml");
    std::fs::write(&tmp, &task_xml)?;
    let out = std::process::Command::new("schtasks")
        .args(["/create", "/tn", "Filament", "/xml", &tmp.to_string_lossy(), "/f"])
        .output()?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("schtasks failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launch_agent(exe: &Path, shell_args: &str) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    let plist = dir.join("autumated.filament.plist");
    std::fs::write(&plist, format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>autumated.filament</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>up</string>{}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>"#,
        exe.display(), shell_args
    ))?;
    let _ = std::process::Command::new("launchctl").args(["bootstrap", "gui/501", &plist.to_string_lossy()]).status();
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn add_firewall_rule(exe: &Path) {
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
            "name=Filament QUIC", "dir=in", "action=allow",
            "protocol=udp",
            "program=", &exe.display().to_string(),
            "enable=yes"])
        .output();
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
    fn all_detected_hosts_support_install() {
        assert!(ServiceHost::Systemd.supports_install());
        assert!(ServiceHost::Launchd.supports_install());
        assert!(ServiceHost::WindowsService.supports_install());
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

    #[cfg(unix)]
    #[test]
    fn repairs_preexisting_world_readable_caps_store() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("filament-perm-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let caps = dir.join("caps.json");
        std::fs::write(&caps, "[]").unwrap();
        std::fs::set_permissions(&caps, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(std::fs::metadata(&caps).unwrap().permissions().mode() & 0o777, 0o644);

        let repaired = repair_sensitive_permissions_in(&dir).unwrap();

        assert_eq!(repaired, 1);
        assert_eq!(std::fs::metadata(&caps).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
