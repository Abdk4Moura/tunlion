use std::path::{Path, PathBuf};

use anyhow::Result;

/// Platform-specific paths for the tunlion CLI.
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
        // THE DIRECTORY NAME STAYS `filament` ACROSS THE RENAME, and that is
        // deliberate rather than an oversight. This path holds the user key, the
        // device certificate, devices.json and the capability store: everything
        // that makes an install *this* install. Renaming it would present every
        // existing user with a machine that has forgotten its identity, every
        // pairing, and every grant, with no error message -- it would simply look
        // like a fresh install. A brand is not worth that, and a migration that
        // moves live secrets is a worse risk than a directory with the old name.
        //
        // The new name is honoured when it is ALREADY the one in use, so anyone
        // who starts fresh after the rename lands on `tunlion` and keeps it.
        if let Some(proj) = directories::ProjectDirs::from("", "", "tunlion") {
            let new_dir = proj.config_dir().to_path_buf();
            if new_dir.exists() {
                return new_dir;
            }
        }
        if let Some(proj) = directories::ProjectDirs::from("", "", "filament") {
            return proj.config_dir().to_path_buf();
        }
        // #184: route through home_dir() (USERPROFILE on Windows) instead of a
        // bare HOME read that falls back to "." on Windows.
        Self::home_dir().join(".config").join("filament")
    }

    /// Resolve a config-relative path (file or subdirectory).
    pub fn config_path(relative: impl AsRef<Path>) -> PathBuf {
        Self::config_dir().join(relative)
    }

    /// Repair permissions on sensitive state left by older releases. This is
    /// intentionally separate from SecretFile::write: an unchanged legacy
    /// file is otherwise never rewritten and never gets its mode repaired.
    ///
    /// #178: this is a MIGRATION, so it runs ONCE per version, stamped in the
    /// config dir. SecretFile applies the owner-only ACL at write time, so
    /// every file this version creates is correct when created; the sweep
    /// exists solely to catch files written by older releases. Without the
    /// stamp it would (on Windows) shell out to icacls for every sensitive
    /// file on every command, adding 150-600ms to `--version`, `--help`, and
    /// everything else. Steady state after the stamp: zero process spawns,
    /// zero stat calls, no message. The stamp is a version number, not a
    /// boolean, so a future migration can bump it and re-run.
    pub fn repair_sensitive_permissions() -> std::io::Result<usize> {
        const MIGRATION_VERSION: u32 = 1;
        let dir = Self::config_dir();
        let stamp = dir.join("permissions-migration");
        let current = std::fs::read_to_string(&stamp)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if current == Some(MIGRATION_VERSION) {
            return Ok(0);
        }
        let repaired = repair_sensitive_permissions_in(&dir)?;
        // Best-effort stamp: a failure to write it just means the sweep runs
        // once more next time, which is acceptable for a migration.
        let _ = std::fs::write(&stamp, MIGRATION_VERSION.to_string());
        Ok(repaired)
    }

    /// Migrate state from a legacy `$HOME/.config/filament` directory (the
    /// broken Windows fallback when HOME was unset, which resolved relative to
    /// the process cwd). Best-effort, safe to call repeatedly.
    ///
    /// Two guards, both earned:
    /// 1. An explicit FILAMENT_CONFIG_DIR override means the caller knows where
    ///    their config lives; migrating INTO it would copy whatever a
    ///    cwd-relative ".config/filament" resolves to — the production identity
    ///    when the shell's cwd is $HOME (issue #149, a key clone). Never
    ///    migrate under an override.
    /// 2. The legacy location is pinned to home_dir(), not the process cwd.
    ///    "./.config/filament" names a different directory in every process;
    ///    with the default shell cwd of $HOME it was indistinguishable from the
    ///    live production config, which is exactly what let the override case
    ///    clone keys. When HOME is unset, home_dir() falls back to ".", which
    ///    is the original broken-Windows behaviour.
    pub fn migrate_legacy() {
        if std::env::var_os("FILAMENT_CONFIG_DIR").is_some() {
            return;
        }
        let legacy = Self::home_dir().join(".config").join("filament");
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
    /// 3. `tunlion set shell` config (passed via `shell_config`)
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

/// Tighten a directory we just created to owner-only, where the platform has
/// POSIX modes. BOTH ARMS LIVE HERE, per docs/architecture/PLATFORM.md: on
/// Windows a directory created under the user's profile inherits an ACL that is
/// already owner-only, so there is nothing to set, and saying so in code is the
/// difference between "portable" and "never tested on the other platform".
/// Best effort: a config dir that exists with the wrong mode is not a reason to
/// fail the command that created it, and `repair_sensitive_permissions()` is the
/// path that reports on modes.
pub fn tighten_new_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
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
        // user-scoped, but old files may predate the SecretFile writer. This
        // arm of the sweep is only reached by the one-time migration stamp
        // (repair_sensitive_permissions skips the sweep entirely once it has
        // run for this version), so its cost is not on the command hot path.
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

// --------------------------------------------------------- DevicesFileLock --

/// An exclusive advisory lock on the `devices.json.lock` sidecar, held for the
/// lifetime of the guard. Coordinates the read-modify-write of `devices.json`
/// across processes (#238): the store itself is written by atomic replace
/// (temp + rename), so a lock on the store inode would be replaced out from
/// under a holder. The sidecar is never replaced.
///
/// Unix: flock(LOCK_EX). Windows: LockFileEx. Other platforms: the file is
/// opened but not locked (tunlion targets unix + windows).
pub struct DevicesFileLock {
    _file: std::fs::File,
}

impl DevicesFileLock {
    /// Acquire the lock, blocking until it is available.
    pub fn acquire() -> anyhow::Result<Self> {
        Self::acquire_at(&Paths::config_dir().join("devices.json.lock"))
    }

    /// The same exclusive lock on an arbitrary sidecar (the identity mint in
    /// `identity_flow::ensure_user_key_inner` uses `identity.lock`).
    pub fn acquire_at(path: &Path) -> anyhow::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        owner_only_mode(&mut opts);
        let file = opts.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc != 0 {
                return Err(anyhow::anyhow!(
                    "flock {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::LockFileEx;
            let handle = file.as_raw_handle() as HANDLE;
            // Lock the first u32::MAX bytes at offset 0 (a zeroed OVERLAPPED).
            // Blocking (no LOCKFILE_FAIL_IMMEDIATELY).
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            let ok = unsafe {
                LockFileEx(
                    handle,
                    windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    overlapped.as_mut_ptr(),
                )
            };
            if ok == 0 {
                return Err(anyhow::anyhow!(
                    "LockFileEx {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(DevicesFileLock { _file: file })
    }
}

impl Drop for DevicesFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self._file.as_raw_fd();
            unsafe { libc::flock(fd, libc::LOCK_UN) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            let handle = self._file.as_raw_handle() as HANDLE;
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            unsafe { UnlockFileEx(handle, 0, u32::MAX, u32::MAX, overlapped.as_mut_ptr()) };
        }
    }
}

// --------------------------------------------------------- ServiceHost --

/// The detected service manager on this platform.
///
/// Supports two install tiers:
/// - **system**: privileged, kernel TUN, autostart at boot (requires admin).
/// - **user**: unprivileged, userspace-only, autostart at logon.
///
/// `tunlion up --install` tries system first (elevation popup), falls back to
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
            ServiceHost::None => "No service manager detected. Start tunlion with `tunlion up` in a terminal, or configure your init system manually.",
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
            // #173: this used to return true unconditionally, on the
            // assumption that the only caller was an already-elevated
            // re-launch. It is ALSO the first, non-elevated call, so the UAC
            // re-launch could never run. Query the token elevation state
            // instead.
            unsafe {
                unsafe extern "system" {
                    fn GetCurrentProcess() -> isize;
                    fn OpenProcessToken(h: isize, access: u32, tok: *mut isize) -> i32;
                    fn GetTokenInformation(tok: isize, cls: u32, buf: *mut u8, len: u32, ret: *mut u32) -> i32;
                    fn CloseHandle(h: isize) -> i32;
                }
                const TOKEN_QUERY: u32 = 0x0008;
                const TOKEN_ELEVATION: u32 = 20;
                let mut tok: isize = 0;
                let h = GetCurrentProcess();
                if OpenProcessToken(h, TOKEN_QUERY, &mut tok) == 0 {
                    return false;
                }
                let mut elev: u32 = 0;
                let mut ret: u32 = 0;
                let ok = GetTokenInformation(
                    tok,
                    TOKEN_ELEVATION,
                    (&mut elev as *mut u32).cast::<u8>(),
                    std::mem::size_of::<u32>() as u32,
                    &mut ret,
                );
                CloseHandle(tok);
                ok != 0 && elev != 0
            }
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
                    "[Unit]\nDescription=Tunlion drop target\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=multi-user.target\n",
                    exe.display(), shell_args
                ))?;
                let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
                let _ = std::process::Command::new("systemctl").args(["enable", "--now", "tunlion"]).status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // 0.8.5 (rec 4): a machine-wide Windows service cannot work yet.
                // `sc create` registers the exe as an SCM service, but tunlion
                // is a plain console program with no service protocol, so
                // `sc start` always times out (exit 1053). Until that protocol
                // exists, refuse clearly instead of half-installing. The default
                // per-user autostart (HKCU Run) is unaffected and never reaches
                // this path.
                anyhow::bail!(
                    "a machine-wide Windows service is not supported yet: tunlion has no service protocol, \
                     so the installed service could never start. The per-user autostart (the default) is \
                     already installed. See #177."
                );
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let plist = std::path::Path::new("/Library/LaunchDaemons/autumated.filament.plist");
                std::fs::write(plist, format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>autumated.tunlion</string>
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
                // #173: per-user autostart via HKCU Run. No elevation needed:
                // autostarting a user's own file receiver at logon is not an
                // administrative act, and the first-run wizard must not demand
                // UAC for it (matches systemd --user and the LaunchAgent). A
                // machine-wide service is the explicit --install-system path.
                install_run_key(exe, shell_args)
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
                    .args(["--user", "disable", "--now", "tunlion"])
                    .status();
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--now", "tunlion"])
                    .status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // #173: `sc delete` needs admin; only run it when elevated (the
                // machine-wide service path). The per-user autostart is removed
                // with the HKCU Run entry, which needs no elevation.
                if self.is_elevated() {
                    let _ = std::process::Command::new("sc")
                        .args(["delete", "tunlion"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
                let _ = std::process::Command::new("reg")
                    .args([
                        "delete",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "Tunlion",
                        "/f",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("schtasks")
                    .args(["/delete", "/tn", "Tunlion", "/f"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootout", "gui/501/autumated.tunlion"])
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
                fn ShellExecuteExW(pExecInfo: *mut SHELLEXECUTEINFOW) -> i32;
                fn WaitForSingleObject(h: isize, ms: u32) -> u32;
                fn GetExitCodeProcess(h: isize, code: *mut u32) -> i32;
                fn CloseHandle(h: isize) -> i32;
                fn GetLastError() -> u32;
            }

            // SHELLEXECUTEINFOW, fields through hProcess. repr(C) keeps the
            // Windows x64 layout (int nShow is followed by pointer alignment).
            #[repr(C)]
            struct SHELLEXECUTEINFOW {
                cb_size: u32,
                f_mask: u32,
                hwnd: isize,
                lp_verb: *const u16,
                lp_file: *const u16,
                lp_parameters: *const u16,
                lp_directory: *const u16,
                n_show: i32,
                h_inst_app: isize,
                lp_id_list: isize,
                lp_class: *const u16,
                hkey_class: isize,
                dw_hot_key: u32,
                h_icon: isize,
                h_process: isize,
            }

            const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
            const SW_HIDE: i32 = 0;

            let exe_win: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let args = format!("--install-system {shell_args}");
            let args_win: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();
            let verb: Vec<u16> = "runas\0".encode_utf16().collect();

            let mut sei = SHELLEXECUTEINFOW {
                cb_size: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                f_mask: SEE_MASK_NOCLOSEPROCESS,
                hwnd: 0,
                lp_verb: verb.as_ptr(),
                lp_file: exe_win.as_ptr(),
                lp_parameters: args_win.as_ptr(),
                lp_directory: std::ptr::null(),
                n_show: SW_HIDE,
                h_inst_app: 0,
                lp_id_list: 0,
                lp_class: std::ptr::null(),
                hkey_class: 0,
                dw_hot_key: 0,
                h_icon: 0,
                h_process: 0,
            };

            let ret = unsafe { ShellExecuteExW(&mut sei) };
            if ret == 0 {
                let code = unsafe { GetLastError() };
                if code == 1223 {
                    // ERROR_CANCELLED — user declined UAC
                    return Ok(false);
                }
                anyhow::bail!("elevation failed to launch: {}", code);
            }
            let h = sei.h_process;
            if h == 0 {
                return Ok(false);
            }
            // #177: wait for the elevated child and read its exit code. The
            // old ShellExecuteW returned the moment the UAC prompt was shown,
            // so the parent claimed "installed as a system service" before the
            // child had even run. A failed install must never print success.
            unsafe {
                WaitForSingleObject(h, 120_000); // generous bound; sc create is fast
                let mut exit_code: u32 = 0;
                GetExitCodeProcess(h, &mut exit_code);
                CloseHandle(h);
                if exit_code == 0 {
                    return Ok(true);
                }
            }
            anyhow::bail!("elevated install failed; the service was not created")
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
        "[Unit]\nDescription=Tunlion drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={} up{}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=default.target\n",
        exe.display(), shell_args
    ))?;
    let ok = std::process::Command::new("systemctl").args(["--user", "daemon-reload"]).status()
        .and_then(|_| std::process::Command::new("systemctl").args(["--user", "enable", "--now", "tunlion"]).status())
        .map(|s| s.success()).unwrap_or(false);
    if !ok {
        anyhow::bail!("systemctl --user enable --now tunlion failed; run it manually or check journalctl --user -u tunlion");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_run_key(exe: &Path, shell_args: &str) -> Result<()> {
    // Per-user autostart via HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
    // Runs as the current user at logon with no elevation. This is the default
    // background receiver on Windows.
    let cmd = format!("\"{}\" up{}", exe.display(), shell_args);
    let out = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", "Tunlion",
            "/t", "REG_SZ",
            "/d", &cmd,
            "/f",
        ])
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("reg add HKCU Run failed: {}", stderr.trim());
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
        .args(["/create", "/tn", "Tunlion", "/xml", &tmp.to_string_lossy(), "/f"])
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
  <key>Label</key><string>autumated.tunlion</string>
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
            "name=Tunlion QUIC", "dir=in", "action=allow",
            "protocol=udp",
            "program=", &exe.display().to_string(),
            "enable=yes"])
        .output();
}

/// Set in the environment of the daemon `spawn_detached` starts. See `up_cmd`.
pub const DETACHED_CHILD_ENV: &str = "TUNLION_DETACHED_CHILD";

/// Spawn `exe` with `args` detached from this process's terminal, its stdout
/// and stderr appended to `log`. One portable operation with two arms, written
/// together: the unix arm detaches with `setsid`, the Windows arm with
/// `CREATE_NO_WINDOW | DETACHED_PROCESS`; both redirect the child's console to
/// the same log file. The caller polls the pidfile itself for "is it up yet"
/// (`daemon_alive` is portable since #204).
///
/// The two arms MUST ship together. #215 was a half-written detach: the
/// Windows arm computed the log path and then discarded it, so `logs`,
/// `up`-follows and `--detach` all dead-ended on a file that never appeared.
pub fn spawn_detached(exe: &Path, args: &[&str], log: &Path) -> Result<std::process::Child> {
    // Name the path in every failure: a HOME that does not exist used to print
    // only "No such file or directory (os error 2)", which names nothing.
    if let Some(parent) = log.parent() {
        create_private_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("cannot create the config directory {}: {e}", parent.display())
        })?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let log_file = opts
        .open(log)
        .map_err(|e| anyhow::anyhow!("cannot open the daemon log {}: {e}", log.display()))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    // Marks the child as the detached daemon, whose console is `log`: it must
    // never follow that log (see up_cmd). Windows needs this; unix also
    // compares the inode.
    cmd.env(DETACHED_CHILD_ENV, "1");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::from(log_file.try_clone()?));
    cmd.stderr(std::process::Stdio::from(log_file));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("detached spawn is not supported on this platform");
    }
    Ok(cmd.spawn()?)
}

// --------------------------------------------------- process identity --

/// The absolute path of the executable backing a live process, or `None` when
/// the pid does not name a process we can inspect (a dead or recycled pid).
/// This is the identity check behind `daemon_alive`: a command-line substring
/// can be defeated by renaming the binary, the executable path cannot.
///
/// Linux reads the `/proc/<pid>/exe` symlink, macOS asks libproc for the pid's
/// image path, and Windows asks the kernel for the full image name (there is no
/// /proc on either). The arms must ship together; a missing variant makes
/// `daemon_alive` constant-false on that platform, which is the #204 bug this
/// predicate exists to close for good.
#[cfg(target_os = "linux")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
}

#[cfg(target_os = "macos")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    // proc_pidpath may include the NUL terminator in its return count.
    let mut end = (n as usize).min(buf.len());
    if end > 0 && buf[end - 1] == 0 {
        end -= 1;
    }
    String::from_utf8(buf[..end].to_vec()).ok().map(PathBuf::from)
}

#[cfg(target_os = "windows")]
pub fn process_exe_path(pid: u32) -> Option<PathBuf> {
    unsafe {
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
            fn QueryFullProcessImageNameW(h: isize, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
            fn CloseHandle(h: isize) -> i32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return None;
        }
        let mut buf = [0u16; 512];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Some(PathBuf::from(path))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn process_exe_path(_pid: u32) -> Option<PathBuf> {
    None
}

// ------------------------------------------------------- InstallSource --

/// How tunlion was installed. Used to gate `tunlion update`:
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

    /// Upgrade command the user should run instead of `tunlion update`.
    pub fn upgrade_hint(&self) -> &'static str {
        match self {
            InstallSource::Homebrew => "brew upgrade tunlion",
            InstallSource::Winget => "winget upgrade Abdk4Moura.Tunlion",
            InstallSource::Scoop => "scoop update tunlion",
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
        let p = Path::new("/opt/homebrew/Cellar/tunlion/0.4.1/bin/tunlion");
        assert_eq!(InstallSource::classify(p), InstallSource::Homebrew);
        let p2 = Path::new("/home/linuxbrew/.linuxbrew/bin/tunlion");
        assert_eq!(InstallSource::classify(p2), InstallSource::Homebrew);
        let p3 = Path::new("/usr/local/Cellar/tunlion/0.3.1/bin/tunlion");
        assert_eq!(InstallSource::classify(p3), InstallSource::Homebrew);
    }

    #[test]
    fn install_source_classify_winget() {
        let p = Path::new("C:\\Users\\kabir\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Abdk4Moura.Tunlion_tunlion\\tunlion.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Winget);
    }

    #[test]
    fn install_source_classify_scoop() {
        let p = Path::new("C:\\Users\\kabir\\scoop\\apps\\tunlion\\0.4.1\\tunlion.exe");
        assert_eq!(InstallSource::classify(p), InstallSource::Scoop);
    }

    #[test]
    fn install_source_classify_cargo() {
        let p = Path::new("/home/kabir/.cargo/bin/tunlion");
        assert_eq!(InstallSource::classify(p), InstallSource::Cargo);
    }

    #[test]
    fn install_source_classify_self_installed() {
        let p = Path::new("/home/kabir/.local/bin/tunlion");
        assert_eq!(InstallSource::classify(p), InstallSource::SelfInstalled);
    }

    #[test]
    fn install_source_upgrade_hints() {
        assert_eq!(InstallSource::Homebrew.upgrade_hint(), "brew upgrade tunlion");
        assert_eq!(InstallSource::Winget.upgrade_hint(), "winget upgrade Abdk4Moura.Tunlion");
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

    /// Regression for #149: setting FILAMENT_CONFIG_DIR to a fresh path from a
    /// shell whose cwd is $HOME must NOT migrate the production identity into
    /// it. Before the fix, `.config/filament` (cwd-relative) resolved to
    /// $HOME/.config/filament, the live production config, and the migration
    /// copied it wholesale into the override: a key clone.
    #[cfg(unix)]
    #[test]
    fn override_config_dir_is_not_migrated_into() {
        let uid = format!("{}-cfgdir-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let work = std::env::temp_dir().join(format!("fil-cfg-{uid}"));
        let home = work.join("home");
        let legacy = home.join(".config").join("filament");
        let target = work.join("target");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("identity.ed25519"), b"production key").unwrap();
        std::fs::write(legacy.join("overlay.ed25519"), b"production key 2").unwrap();

        // Snapshot the real process state so it can be restored even if the
        // assertion below fails (the failure must not leak into parallel tests).
        let old_cwd = std::env::current_dir().unwrap();
        // Mutates HOME, FILAMENT_CONFIG_DIR and the process cwd, all process-wide.
        // Without the shared lock it could swap the config dir out from under any
        // concurrently running test that reads it.
        let _guard = crate::tests::lock_test_config();
        let old_home = std::env::var_os("HOME");
        let old_override = std::env::var_os("FILAMENT_CONFIG_DIR");

        // Reproduce the report: fresh override, cwd == $HOME, populated legacy.
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("FILAMENT_CONFIG_DIR", &target);
        }
        std::env::set_current_dir(&home).unwrap();

        Paths::migrate_legacy();

        // Restore process-global state BEFORE asserting, so a failure cannot
        // leave env/cwd mutated for sibling tests.
        std::env::set_current_dir(&old_cwd).unwrap();
        match old_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match old_override {
            Some(v) => unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", v) },
            None => unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") },
        }

        // The override must stay EMPTY: migrating production keys into a fresh
        // explicit config dir is the #149 key clone.
        let entries: Vec<_> = std::fs::read_dir(&target)
            .map(|it| it.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(
            entries.is_empty(),
            "FILAMENT_CONFIG_DIR override was populated by legacy migration: {entries:?}"
        );

        let _ = std::fs::remove_dir_all(&work);
    }
}

/// Policy routing for exit nodes, kept behind the platform adapter so the rest
/// of the tree stays free of `cfg(target_os)`.
///
/// The exit-node design (docs/design-subnet-routes.md) is expressed in iproute2
/// terms: a dedicated table, a rule, and carve-outs. That vocabulary is Linux's.
/// macOS and Windows have policy routing, but neither speaks these commands, so
/// the honest portable contract is "supported, or say so", not a silent no-op
/// that would leave a caller believing traffic is tunnelled when it is not.
pub mod policy_route {
    /// Whether this platform can install the exit-route policy at all.
    pub fn supported() -> bool {
        cfg!(target_os = "linux")
    }

    /// The current default gateway, if one can be determined.
    pub fn default_gateway() -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let out = std::process::Command::new("ip")
                .args(["-4", "route", "show", "default"])
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let mut fields = text.split_whitespace();
            while let Some(f) = fields.next() {
                if f == "via" {
                    return fields.next().map(str::to_string);
                }
            }
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Run one `ip` plan produced by `exit_route`.
    ///
    /// Every step is attempted even after one fails, because a partly-applied
    /// plan whose CARVE-OUTS succeeded is strictly safer than one abandoned
    /// after the default route went in. Deleting something already absent is
    /// success, not failure: reconciliation is repeated and idempotent.
    pub fn run_plan(plan: &[Vec<String>]) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let mut failures = Vec::new();
            for step in plan {
                match std::process::Command::new("ip").args(step).output() {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                        if !err.contains("No such process") && !err.contains("not found") {
                            failures.push(format!("ip {}: {err}", step.join(" ")));
                        }
                    }
                    Err(e) => failures.push(format!("ip {}: {e}", step.join(" "))),
                }
            }
            return if failures.is_empty() { Ok(()) } else { Err(failures.join("; ")) };
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = plan;
            Err("policy routing is implemented for Linux only".to_string())
        }
    }
}

/// Create a symlink, for tests that need a symlinked entry in a fixture.
///
/// Both arms live here because platform differences belong in `platform/` (docs/architecture/PLATFORM.md):
/// the budget for platform-conditional blocks in every file outside this directory is 0, so moving the
/// branch here is exactly what that budget asks for. The `Result` is the point: creating a symlink on
/// Windows needs SeCreateSymbolicLinkPrivilege (or Developer Mode), so a caller checks the capability
/// rather than guessing it from the platform, and an error means "this host cannot exercise that arm",
/// not "the product is broken".
#[cfg(test)]
pub fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        // Windows distinguishes a file target from a directory target and the caller does not always
        // know which it means, so try both.
        std::os::windows::fs::symlink_file(target, link)
            .or_else(|_| std::os::windows::fs::symlink_dir(target, link))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no symlink support on this platform"))
    }
}

// ------------------------------------------------------- private state dirs --

/// Create `dir` and every missing parent owner-only (0700), whatever the umask.
///
/// `create_dir_all` asks for 0777 and lets the umask decide, so under `umask
/// 0000` the config directory and `identity/` came out world-writable: anyone on
/// the machine could swap the files in them. Every directory that holds tunlion
/// state is created through here instead. The mode is set explicitly after the
/// create because a umask can still strip bits from a DirBuilder mode. A
/// directory that already existed is left alone: its mode is the user's choice,
/// and `repair_sensitive_permissions` is the path that reports on legacy modes.
/// Windows: the profile ACL is already owner-only, so a plain create is right.
pub fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Walk up to the deepest existing ancestor, then create downwards, so
        // each directory WE create is tightened and nothing pre-existing is.
        let mut missing = Vec::new();
        let mut cur = Some(dir);
        while let Some(p) = cur {
            if p.as_os_str().is_empty() || p.exists() {
                break;
            }
            missing.push(p.to_path_buf());
            cur = p.parent();
        }
        for p in missing.iter().rev() {
            match std::fs::DirBuilder::new().mode(0o700).create(p) {
                Ok(()) => tighten_new_dir(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && p.is_dir() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

// ------------------------------------------------------------ InstanceLock --

/// The daemon's single-instance election: an exclusive lock on `{config}/up.lock`,
/// taken WITHOUT blocking and held for the daemon's whole life.
///
/// The pidfile cannot elect anything. Three `up --detach` started together all
/// read "no pidfile", all spawned a daemon, and the two losers then found the
/// winner's pidfile and settled into "following its log" with their own stdout
/// pointed INTO that log, so every line they read they appended again: daemon.log
/// went from 0 to 22 MB in under two seconds and filled the home directory. A lock
/// is atomic where read-then-write is not, and the kernel releases it when the
/// holder dies, so a crashed daemon never leaves a stale election behind.
///
/// Unix: `flock(LOCK_EX | LOCK_NB)`. Windows: `LockFileEx` with
/// `LOCKFILE_FAIL_IMMEDIATELY`. The descriptor is close-on-exec (std opens every
/// file that way), so a shell or helper the daemon spawns does not inherit the
/// lock and keep it after the daemon is gone.
pub struct InstanceLock {
    _file: std::fs::File,
}

impl InstanceLock {
    /// `Ok(Some(lock))`: this process won and holds it until the guard drops (or
    /// the process exits). `Ok(None)`: another live process holds it.
    pub fn try_acquire(path: &Path) -> std::io::Result<Option<InstanceLock>> {
        if let Some(parent) = path.parent() {
            create_private_dir_all(parent)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Ok(None);
                }
                return Err(e);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::{
                LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            };
            let handle = file.as_raw_handle() as HANDLE;
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            let ok = unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    overlapped.as_mut_ptr(),
                )
            };
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                // ERROR_LOCK_VIOLATION: someone else holds it.
                if e.raw_os_error() == Some(33) {
                    return Ok(None);
                }
                return Err(e);
            }
        }
        Ok(Some(InstanceLock { _file: file }))
    }
}

/// Make `opts` create the file owner-only (0600), whatever the umask. A no-op
/// on Windows, where the profile ACL already restricts it.
pub fn owner_only_mode(opts: &mut std::fs::OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        let _ = opts;
    }
}

/// True when this process's stdout or stderr IS the file at `path` (same device
/// and inode). A detached daemon's console is daemon.log, so a process whose
/// output already goes there must never follow that log: every line it read it
/// would write back, which is the feedback loop that filled a disk.
/// Windows has no inode to compare; it returns false there, and the detached
/// child is recognised by the marker its parent sets instead (see `up_cmd`).
pub fn stdio_is_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        for fd in [1, 2] {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } == 0
                && st.st_dev as u64 == meta.dev()
                && st.st_ino as u64 == meta.ino()
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

// --------------------------------------------------------------- disk space --

/// Bytes available to this (unprivileged) user on the filesystem holding `dir`,
/// or `None` when the platform cannot say. Used to refuse a transfer that cannot
/// fit BEFORE accepting it, instead of discovering ENOSPC half way through and
/// reporting it as a checksum failure.
pub fn free_space(dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        let unit = if st.f_frsize as u64 > 0 { st.f_frsize as u64 } else { st.f_bsize as u64 };
        Some((st.f_bavail as u64).saturating_mul(unit))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut avail: u64 = 0;
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut avail,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 { None } else { Some(avail) }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        None
    }
}

/// A local storage failure a receiver reports to the sender as a typed refusal
/// instead of going silent. See `storage_failure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailure {
    NoSpace,
    NameTooLong,
    ReadOnly,
    Permission,
}

/// Classify an io error as a storage failure, or `None` for anything else.
pub fn storage_failure(e: &std::io::Error) -> Option<StorageFailure> {
    #[cfg(unix)]
    {
        match e.raw_os_error() {
            Some(libc::ENOSPC) | Some(libc::EDQUOT) => return Some(StorageFailure::NoSpace),
            Some(libc::ENAMETOOLONG) => return Some(StorageFailure::NameTooLong),
            Some(libc::EROFS) => return Some(StorageFailure::ReadOnly),
            Some(libc::EACCES) | Some(libc::EPERM) => return Some(StorageFailure::Permission),
            _ => {}
        }
    }
    #[cfg(windows)]
    {
        // ERROR_DISK_FULL / ERROR_HANDLE_DISK_FULL, ERROR_FILENAME_EXCED_RANGE,
        // ERROR_WRITE_PROTECT, ERROR_ACCESS_DENIED.
        match e.raw_os_error() {
            Some(112) | Some(39) => return Some(StorageFailure::NoSpace),
            Some(206) => return Some(StorageFailure::NameTooLong),
            Some(19) => return Some(StorageFailure::ReadOnly),
            Some(5) => return Some(StorageFailure::Permission),
            _ => {}
        }
    }
    // The kind, for an error that was re-wrapped on its way here and lost its
    // OS code (safe_create_part adds context that way).
    match e.kind() {
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            Some(StorageFailure::NoSpace)
        }
        std::io::ErrorKind::InvalidFilename => Some(StorageFailure::NameTooLong),
        std::io::ErrorKind::ReadOnlyFilesystem => Some(StorageFailure::ReadOnly),
        std::io::ErrorKind::PermissionDenied => Some(StorageFailure::Permission),
        _ => None,
    }
}

// ----------------------------------------------------------- control socket --

/// The longest control-socket path we bind. `sun_path` holds 108 bytes on
/// Linux and 104 on macOS, NUL included; the margin keeps us clear of both.
pub const SOCKET_PATH_MAX: usize = 100;

/// Where the control socket lives: `preferred` (in the config directory) when it
/// fits in `sun_path`, otherwise a short per-user directory, `$XDG_RUNTIME_DIR/
/// tunlion-<uid>/` or `/tmp/tunlion-<uid>/`, with a name derived from the config
/// directory so two configs never share a socket.
///
/// A deep HOME used to leave the daemon with no socket at all while `up` and
/// `status` reported "ok"; only daemon.log said "control socket unavailable".
/// The daemon and every client compute this the same way, so they meet.
///
/// A short directory that exists but is not private to this user (another
/// owner, writable by others, a symlink) is never used: `preferred` comes back
/// instead, which cannot bind, so the daemon fails loudly rather than serve or
/// be reached through a directory someone else controls.
pub fn control_socket_path(preferred: &Path, config_dir: &Path) -> PathBuf {
    if preferred.as_os_str().len() < SOCKET_PATH_MAX {
        return preferred.to_path_buf();
    }
    #[cfg(unix)]
    {
        let key = config_dir_key(config_dir);
        let uid = unsafe { libc::geteuid() };
        let mut bases: Vec<PathBuf> = Vec::new();
        if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if x.is_absolute() && x.is_dir() {
                bases.push(x);
            }
        }
        bases.push(PathBuf::from("/tmp"));
        for base in bases {
            let dir = base.join(format!("tunlion-{uid}"));
            let sock = dir.join(format!("{key}.sock"));
            if sock.as_os_str().len() >= SOCKET_PATH_MAX {
                continue;
            }
            if dir.exists() && private_dir_check(&dir).is_err() {
                continue;
            }
            return sock;
        }
        preferred.to_path_buf()
    }
    #[cfg(not(unix))]
    {
        let _ = config_dir;
        preferred.to_path_buf()
    }
}

/// Prepare the directory a socket is about to be bound in: create it 0700 when
/// missing, then insist it is a real directory owned by this user that nobody
/// else can write. A directory of ours that is group- or world-writable (a
/// config dir made under `umask 0000` by an older build) is tightened rather
/// than refused; one owned by someone else is refused.
pub fn prepare_socket_dir(sock: &Path) -> std::io::Result<()> {
    let Some(dir) = sock.parent() else {
        return Ok(());
    };
    create_private_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(dir)?;
        let uid = unsafe { libc::geteuid() };
        if meta.is_dir() && meta.uid() == uid && meta.mode() & 0o022 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        private_dir_check(dir)
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

/// Err unless `dir` is a directory (not a symlink) owned by this user and not
/// writable by group or others.
#[cfg(unix)]
fn private_dir_check(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir)?;
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is not a private directory owned by this user (owner uid {}, mode {:o}); refusing to put the control socket there",
                dir.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// A short stable name for a config directory (FNV-1a over its path bytes).
#[cfg(unix)]
fn config_dir_key(dir: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in dir.as_os_str().as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

// ------------------------------------------------------------ serving user --

/// The login name of the user this process runs as, from the password database
/// (`getpwuid_r(geteuid())`), falling back to `$USER` / `$LOGNAME`. The
/// environment is the fallback, not the source: a daemon started from cron, a
/// container or `env -i` has no `$USER`, and the ssh CA refused to arm with
/// "cannot determine serving user" while `getent passwd` knew the answer.
/// Windows: `%USERNAME%`.
pub fn current_username() -> Option<String> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        let rc = unsafe {
            libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
        };
        if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            if !name.is_empty() {
                return Some(name);
            }
        }
        std::env::var("USER")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("LOGNAME").ok().filter(|s| !s.is_empty()))
    }
    #[cfg(not(unix))]
    {
        std::env::var("USERNAME").ok().filter(|s| !s.is_empty())
    }
}

// ------------------------------------------------------- stale temp files --

/// Remove `<file>.tmp.<pid>` leftovers of the atomic writer in `dir` whose
/// writing process is gone. A write that died part way (ENOSPC, a kill) used to
/// leave them forever: config.tmp.*, armed.json.tmp.*, devices.json.tmp.*.
/// Called when the daemon starts. Returns how many were removed.
pub fn sweep_stale_temp_files(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let me = std::process::id();
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = stale_temp_pid(&name.to_string_lossy()) else {
            continue;
        };
        if pid == me || process_exe_path(pid).is_some() {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The writer pid in an atomic-writer temp name (`<file>.tmp.<pid>`), if it is one.
pub fn stale_temp_pid(name: &str) -> Option<u32> {
    let (stem, pid) = name.rsplit_once(".tmp.")?;
    if stem.is_empty() || pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

#[cfg(test)]
mod hostile_env_tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tl-hostile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_instance_lock_elects_exactly_one_holder() {
        let d = scratch("lock");
        let path = d.join("cfg").join("up.lock");
        let first = InstanceLock::try_acquire(&path).unwrap();
        assert!(first.is_some(), "the first taker wins");
        // A second open file description conflicts even inside one process,
        // which is exactly the concurrent-`up` race.
        assert!(InstanceLock::try_acquire(&path).unwrap().is_none(), "a second taker loses");
        drop(first);
        assert!(
            InstanceLock::try_acquire(&path).unwrap().is_some(),
            "released on drop, so a dead daemon never blocks the next one"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn private_dirs_are_owner_only_whatever_the_umask() {
        let d = scratch("dirs");
        let deep = d.join("a").join("b").join("identity");
        create_private_dir_all(&deep).unwrap();
        assert!(deep.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [d.join("a"), d.join("a").join("b"), deep.clone()] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{} is {mode:o}", p.display());
            }
        }
        // Idempotent on an existing directory.
        create_private_dir_all(&deep).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_secret_file_and_its_new_directory_are_owner_only() {
        let d = scratch("secret");
        let f = d.join("identity").join("device-cert.json");
        SecretFile::write_str(&f, "{}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let fm = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            let dm = std::fs::metadata(f.parent().unwrap()).unwrap().permissions().mode() & 0o777;
            assert_eq!((fm, dm), (0o600, 0o700));
        }
        // No temp left behind by a successful write.
        let leftovers: Vec<_> = std::fs::read_dir(f.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stale_temp_files_of_dead_writers_are_swept_and_live_ones_kept() {
        assert_eq!(stale_temp_pid("config.tmp.1234"), Some(1234));
        assert_eq!(stale_temp_pid("devices.json.tmp.99"), Some(99));
        assert_eq!(stale_temp_pid("config.tmp."), None);
        assert_eq!(stale_temp_pid(".tmp.12"), None);
        assert_eq!(stale_temp_pid("notes.tmp.txt"), None);
        assert_eq!(stale_temp_pid("config"), None);
        let d = scratch("sweep");
        std::fs::create_dir_all(&d).unwrap();
        // A pid that cannot be running: above any real pid_max.
        let dead = d.join("config.tmp.4194999");
        let mine = d.join(format!("armed.json.tmp.{}", std::process::id()));
        let unrelated = d.join("config");
        for p in [&dead, &mine, &unrelated] {
            std::fs::write(p, "x").unwrap();
        }
        assert_eq!(sweep_stale_temp_files(&d), 1);
        assert!(!dead.exists(), "a dead writer's temp is removed");
        assert!(mine.exists(), "a live writer's temp is never touched");
        assert!(unrelated.exists(), "only temp names are candidates");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn storage_failures_are_classified_for_the_typed_refusal() {
        use std::io::{Error, ErrorKind};
        assert_eq!(storage_failure(&Error::from(ErrorKind::StorageFull)), Some(StorageFailure::NoSpace));
        assert_eq!(storage_failure(&Error::from(ErrorKind::QuotaExceeded)), Some(StorageFailure::NoSpace));
        assert_eq!(storage_failure(&Error::from(ErrorKind::InvalidFilename)), Some(StorageFailure::NameTooLong));
        assert_eq!(storage_failure(&Error::from(ErrorKind::ReadOnlyFilesystem)), Some(StorageFailure::ReadOnly));
        assert_eq!(storage_failure(&Error::from(ErrorKind::PermissionDenied)), Some(StorageFailure::Permission));
        assert_eq!(storage_failure(&Error::from(ErrorKind::ConnectionReset)), None);
        #[cfg(unix)]
        {
            assert_eq!(storage_failure(&Error::from_raw_os_error(libc::ENOSPC)), Some(StorageFailure::NoSpace));
            assert_eq!(
                storage_failure(&Error::from_raw_os_error(libc::ENAMETOOLONG)),
                Some(StorageFailure::NameTooLong)
            );
            // Re-wrapped with context the OS code is gone, but the kind survives.
            let wrapped = Error::new(Error::from_raw_os_error(libc::ENOSPC).kind(), "safe create .part: x");
            assert_eq!(storage_failure(&wrapped), Some(StorageFailure::NoSpace));
        }
    }

    #[test]
    fn free_space_is_known_for_a_real_directory() {
        let d = std::env::temp_dir();
        assert!(free_space(&d).is_some(), "no free-space answer for {}", d.display());
    }

    #[test]
    fn a_plain_file_is_not_our_console() {
        let d = scratch("stdio");
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("daemon.log");
        std::fs::write(&f, "x").unwrap();
        assert!(!stdio_is_file(&f));
        assert!(!stdio_is_file(&d.join("missing.log")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn the_serving_user_resolves_from_the_password_database() {
        // The CI runner account always has a passwd entry; $USER is not consulted
        // first, so an unset $USER cannot make this None.
        let name = current_username();
        assert!(name.as_deref().is_some_and(|n| !n.is_empty()), "{name:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_dir_owned_by_us_and_writable_by_others_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("sockdir");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        prepare_socket_dir(&d.join("control.sock")).unwrap();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let _ = std::fs::remove_dir_all(&d);
    }
}
