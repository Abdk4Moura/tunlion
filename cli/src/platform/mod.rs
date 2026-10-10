pub mod fs_at;

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
        // A `tunlion` directory is honoured only when it ALREADY exists (for
        // example one created by hand). Nothing here creates it: a fresh
        // install, before or after the rename, gets the `filament` directory.
        //
        // PROTOCOL LITERAL: frozen, do not rename (the `filament` dir name).
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
        let _ = SecretFile::write_str(&stamp, &MIGRATION_VERSION.to_string());
        Ok(repaired)
    }

    /// Migrate state from a legacy `%USERPROFILE%\.config\filament` directory
    /// (the broken Windows fallback when HOME was unset) into the platform
    /// directory. Best-effort, safe to call repeatedly.
    ///
    /// WHY IT IS THIS NARROW. It used to run on every platform and COPY every
    /// file. On Linux the "legacy" path, `$HOME/.config/filament`, is simply the
    /// default config directory, so `XDG_CONFIG_HOME=/some/new/dir tunlion init`
    /// found the live config there and copied identity.ed25519, overlay.ed25519,
    /// proxy.token, devices.json, the logs and up.pid into the new directory
    /// (only subdirectories escaped, because `fs::copy` cannot copy one). init
    /// then refused with the OLD identity's fingerprint, `up` reported the old
    /// config's daemon as already running, and `down` there killed it: a key
    /// clone plus a second config acting on the first one's daemon.
    ///
    /// So, see `legacy_migration`: only on Windows, where the two directories
    /// really are the old and new homes of the same install; never under an
    /// explicit FILAMENT_CONFIG_DIR or XDG_CONFIG_HOME (the caller chose where
    /// their config lives, #149); and as a MOVE of the whole directory, never a
    /// copy, so secrets never exist in two places. A move that fails leaves
    /// the legacy directory where it was and copies nothing.
    pub fn migrate_legacy() {
        let overridden = std::env::var_os("FILAMENT_CONFIG_DIR").is_some()
            || std::env::var_os("XDG_CONFIG_HOME").is_some();
        let Some(home) = Self::home_dir_known() else { return };
        let legacy = home.join(".config").join("filament");
        let target = Self::config_dir();
        if let Some((from, to)) = legacy_migration(&legacy, &target, overridden, cfg!(windows)) {
            if let Some(parent) = to.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::rename(&from, &to);
        }
    }

    /// Platform-aware home directory for the current user.
    /// Unix: `$HOME`, else the password database's home for this uid.
    /// Windows: `%USERPROFILE%`. Falls back to `"."` when neither says; a
    /// caller that would PERSIST a path derived from it uses `home_dir_known`.
    pub fn home_dir() -> PathBuf {
        Self::home_dir_known().unwrap_or_else(|| PathBuf::from("."))
    }

    /// The home directory, or None when nothing names one. `env -u HOME` (cron,
    /// a container, a service manager) is not "no home": the password database
    /// still knows it, and reading it is what `getent passwd` does. Without
    /// this, `init` wrote `dir ./Tunlion` to the config, a path that names a
    /// different directory from every working directory the daemon runs in.
    /// Only an absolute answer counts.
    pub fn home_dir_known() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            if let Ok(h) = std::env::var("HOME") {
                if !h.is_empty() {
                    return Some(PathBuf::from(h));
                }
            }
            passwd_home().filter(|p| p.is_absolute())
        }
        #[cfg(windows)]
        {
            std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty()).map(PathBuf::from)
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
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

    /// The argv that runs one `tunlion exec` program, dropped to `shell_user`
    /// through the SAME mechanism `shell_argv` uses for the PTY (`runuser` on
    /// Unix). The exec path spawns argv[] directly with no shell, so the drop
    /// uses runuser's command form (`-u <user> -- <program> <args>`) instead of
    /// `-l <user>`, which would need a shell to carry the command and lose argv
    /// exactness. No user: the argv is returned unchanged.
    ///
    /// Err where the PTY drop does not exist (Windows, see `shell_argv`): the
    /// caller must REFUSE the exec rather than run it as the daemon user, which
    /// would hand the peer the very authority `--shell-user` was set to remove.
    pub fn exec_as_user_argv(
        program: &str,
        args: &[String],
        shell_user: Option<&str>,
    ) -> std::result::Result<Vec<String>, String> {
        let mut direct = Vec::with_capacity(args.len() + 1);
        direct.push(program.to_string());
        direct.extend(args.iter().cloned());
        let Some(user) = shell_user else {
            return Ok(direct);
        };
        #[cfg(unix)]
        {
            let mut argv: Vec<String> = vec!["runuser".into(), "-u".into(), user.into(), "--".into()];
            argv.extend(direct);
            Ok(argv)
        }
        #[cfg(not(unix))]
        {
            let _ = direct;
            Err(format!(
                "exec refused: --shell-user {user} is set but this platform cannot run a command as another account, and running it as the daemon user would ignore that setting"
            ))
        }
    }

    /// Home directory of a named local account, when the platform can say.
    /// Used to give a dropped exec the same starting directory a login shell
    /// for that account would have. None when unknown; callers fall back.
    pub fn home_of_user(user: &str) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            use std::ffi::{CStr, CString};
            let name = CString::new(user).ok()?;
            // SAFETY: getpwnam_r writes only into `pwd` and `buf`, both owned
            // here and sized as passed; `result` is either null or `&pwd`.
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut buf = vec![0 as libc::c_char; 16 * 1024];
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
            };
            if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
                return None;
            }
            let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_str().ok()?;
            if dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(dir))
            }
        }
        #[cfg(not(unix))]
        {
            let _ = user;
            None
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

/// The one legacy move `migrate_legacy` may make, as (from, to), or None.
/// Pure so every refusal is testable: not on a platform whose legacy path is
/// its real config dir (everything but Windows), not under an explicit config
/// location, not onto a directory that already exists, and not a directory
/// onto itself.
pub(crate) fn legacy_migration(
    legacy: &Path,
    target: &Path,
    overridden: bool,
    windows: bool,
) -> Option<(PathBuf, PathBuf)> {
    if !windows || overridden || legacy == target || target.exists() || !legacy.is_dir() {
        return None;
    }
    Some((legacy.to_path_buf(), target.to_path_buf()))
}

/// The home directory the password database records for this effective uid.
#[cfg(unix)]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    let uid = unsafe { libc::geteuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: getpwuid_r writes only into `pwd` and `buf`, both owned here and
    // sized as passed; `result` is either null or `&pwd`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_str().ok()?;
    (!dir.is_empty()).then(|| PathBuf::from(dir))
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

/// Create the receiving inbox (the drop dir, `~/Tunlion` by default) and any
/// missing parent, owner-only (0700 on unix). Peers write into it, so it is not
/// a shared folder: before this it took the process umask (0777 & ~umask), and
/// under umask 0 anyone on the machine could plant or swap files in it. An
/// inbox that already exists is left as the user set it. Windows: the
/// profile's inherited ACL already makes it owner-only; nothing to set.
pub fn create_inbox_dir(dir: &Path) -> std::io::Result<()> {
    create_dirs_with_mode(dir, 0o700)
}

/// Create directories for content received or synced from a peer, under
/// `inbox` (created owner-only first when missing). Content directories take
/// the ordinary 0755 masked by the umask, matching received files (0644 masked
/// by the umask, `publish_received_file`): never world-writable, and private in
/// practice because the inbox above them is 0700.
pub fn create_content_dirs(inbox: &Path, dir: &Path) -> std::io::Result<()> {
    if !inbox.exists() {
        create_inbox_dir(inbox)?;
    }
    create_dirs_with_mode(dir, 0o755)
}

fn create_dirs_with_mode(dir: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(mode).create(dir)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::create_dir_all(dir)
    }
}

/// Keep the config dir owner-only on EVERY start, not just at the one-time
/// migration: it holds keys, grants and the proxy token, and a dir someone
/// loosened (or a tool created 0755) would expose new files' NAMES and any file
/// a writer forgot to restrict. Only a directory this user owns, that is not a
/// symlink, and that is not a shared sticky dir (a FILAMENT_CONFIG_DIR pointed
/// at /tmp must never be chmodded) is touched. Windows: the profile ACL is
/// already owner-only.
pub fn tighten_config_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(md) = std::fs::symlink_metadata(dir) else { return };
        let mode = md.permissions().mode();
        let mine = md.uid() == unsafe { libc::getuid() };
        if md.is_dir() && mine && mode & 0o1000 == 0 && mode & 0o077 != 0 {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Open an owner-only (0600 on unix) log-style file, creating it if needed,
/// for appending, or truncating when `truncate`. An existing file with a
/// looser mode is tightened through the handle. Used for diag.jsonl and the
/// daemon logs, which carry peer names, addresses and activity.
pub fn open_private_log(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true);
    if truncate {
        opts.truncate(true);
    } else {
        opts.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata().map(|m| m.permissions().mode() & 0o077 != 0).unwrap_or(false) {
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }
    Ok(file)
}

/// Create a NEW file for writing that is owner-only (0600 on unix) from the
/// moment it exists: the mode is passed to the create itself, so there is no
/// window in which another account could open it, and it does not depend on
/// the process umask (a daemon started with umask 0 made 0666 sidecars).
/// Fails if anything (a file, a planted symlink) already sits at `path`.
/// Windows: files take the containing directory's ACL; nothing to set here.
pub fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Make an already-open file owner-only (0600 on unix) through its handle,
/// never through a path that could have been swapped for a symlink. Used on a
/// resumed partial that an older build created with a looser mode. Windows:
/// nothing to set.
pub fn restrict_open_file(file: &std::fs::File) -> std::io::Result<()> {
    fs_at::set_mode_via_handle(file, 0o600)
}

/// The mode a freshly received file takes once it is complete: what a plain
/// create would have given it (0644 masked by the process umask). A partial is
/// assembled owner-only; this restores the ordinary mode through the handle
/// just before the partial is renamed into place, so a finished download is
/// readable exactly as it was before partials became private.
/// Windows: nothing to set.
pub fn publish_received_file(file: &std::fs::File) -> std::io::Result<()> {
    fs_at::set_mode_via_handle(file, 0o644 & !process_umask())
}

/// The process umask. Linux reads it from /proc/self/status (no side effect);
/// other unix learns it once by the set-and-restore dance, cached so the brief
/// swap happens at most once per process. Non-unix: 0 (unused).
fn process_umask() -> u32 {
    static UMASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *UMASK.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
                if let Some(v) = s.lines().find_map(|l| l.strip_prefix("Umask:")) {
                    if let Ok(m) = u32::from_str_radix(v.trim(), 8) {
                        return m & 0o777;
                    }
                }
            }
            0o022
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let old = unsafe { libc::umask(0o077) };
            unsafe { libc::umask(old) };
            (old as u32) & 0o777
        }
        #[cfg(not(unix))]
        {
            0
        }
    })
}

/// Permission bits of the file at `path` (the link itself, never its target),
/// or None where the platform has no POSIX modes. Lets portable tests assert
/// owner-only files without a platform branch of their own.
#[cfg(test)]
pub fn file_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
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

// ------------------------------------------------------ termination signal --

/// Wait for a signal that ends the process from outside (SIGTERM, SIGHUP,
/// SIGQUIT on Unix) and return the conventional exit status for it (128 + n).
/// Never resolves where there is no such signal to wait for. A caller holding
/// the terminal in raw mode restores it before exiting: a signal skips every
/// Drop, so a guard alone would leave the user's shell stair-stepping.
pub async fn termination_signal() -> i32 {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut hup), Ok(mut quit)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
            signal(SignalKind::quit()),
        ) else {
            return std::future::pending::<i32>().await;
        };
        tokio::select! {
            _ = term.recv() => 143,
            _ = hup.recv() => 129,
            _ = quit.recv() => 131,
        }
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<i32>().await
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

// ------------------------------------------------------- mount prerequisite --

/// Whether this machine can present a local mount at all, checked before any
/// connection is made. Linux needs the FUSE device: without /dev/fuse (a
/// container started without `--device /dev/fuse`, or no fuse module) the mount
/// can only fail, and it used to fail late, as exit 1, after saying "mounted".
/// Err carries the sentence to show; elsewhere the platform adapter reports
/// its own prerequisite.
pub fn mount_prerequisite() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/dev/fuse").exists() {
            return Err(
                "this machine cannot mount: /dev/fuse is missing. Install FUSE (the fuse3 package), or start the container with --device /dev/fuse, then run the mount again"
                    .to_string(),
            );
        }
    }
    Ok(())
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
/// `tunlion up --install` installs the user tier and nothing else. The system
/// tier is only ever an explicit `--install --system`: a root service is a
/// different consent from "keep receiving while I am logged in", and asking
/// for it implicitly (the old "try system first" order) handed the receiver to
/// root on any machine where elevation happened to succeed.
///
/// Every installer takes the daemon's argv as a LIST (`["up", "--shell", ..]`)
/// and encodes it for its own format: a quoted systemd ExecStart, one plist
/// `<string>` per element, a CommandLineToArgvW-safe command line. Splicing a
/// pre-joined string was how the plist ended up with `--shell` as raw text
/// between `<string>` elements, which launchd never passes as an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHost {
    Systemd,
    Launchd,
    WindowsService,
    None,
}

/// Outcome of an install attempt.
pub enum InstallResult {
    /// Privileged system-level service installed. (There is no "fell back to
    /// a user service" outcome: a declined elevation is an error, never a
    /// quiet switch to the other tier.)
    System,
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
    /// path completed, Err if elevation was declined or unavailable, or the
    /// install itself failed. Never falls back to a user service: the caller
    /// asked for a system one, and the other tier is a different thing.
    ///
    /// Linux does not come through here: `up --install --system` there is
    /// `install_service::install_system_service`, which writes a unit with
    /// `User=` and ambient CAP_NET_ADMIN instead of a bare root service.
    pub fn install_system(&self, exe: &Path, argv: &[String]) -> Result<InstallResult> {
        // If already elevated (root on unix, admin on Windows), do the actual
        // system install directly. Otherwise, try to elevate.
        if self.is_elevated() {
            self.do_install_system(exe, argv)?;
            return Ok(InstallResult::System);
        }
        let elevated = self.try_elevate(exe, argv)?;
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

    fn do_install_system(&self, exe: &Path, argv: &[String]) -> Result<()> {
        // No Linux arm. The one that lived here wrote a unit with no `User=`,
        // so the receiver ran as root, and ignored both systemctl results.
        // Linux's system tier is `up --install --system` (install_service.rs).
        let _ = (exe, argv);
        match self {
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // 0.8.5 (rec 4): a machine-wide Windows service cannot work yet.
                // `sc create` registers the exe as an SCM service, but tunlion
                // is a plain console program with no service protocol, so
                // `sc start` always times out (exit 1053). Until that protocol
                // exists, refuse clearly instead of half-installing. The default
                // per-user autostart (HKCU Run) is unaffected and never reaches
                // this path.
                Err(anyhow::anyhow!(
                    "a machine-wide Windows service is not supported yet: tunlion has no service protocol, \
                     so the installed service could never start. The per-user autostart (the default) is \
                     already installed. See #177."
                ))
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                // PROTOCOL LITERAL: frozen, do not rename (plist file = LAUNCHD_LABEL).
                let plist = std::path::Path::new("/Library/LaunchDaemons/autumated.filament.plist");
                std::fs::write(plist, launchd_plist(LAUNCHD_LABEL, exe, argv))?;
                launchctl_bootstrap("system", plist)
            }
            ServiceHost::Systemd => Err(anyhow::anyhow!(
                "a system service on Linux is `tunlion up --install --system`"
            )),
            _ => Err(anyhow::anyhow!("system install not supported")),
        }
    }

    /// Install user-level autostart (no elevation needed).
    pub fn install_user(&self, exe: &Path, argv: &[String]) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            ServiceHost::Systemd => {
                install_systemd_user(exe, argv)
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // #173: per-user autostart via HKCU Run. No elevation needed:
                // autostarting a user's own file receiver at logon is not an
                // administrative act, and the first-run wizard must not demand
                // UAC for it (matches systemd --user and the LaunchAgent). A
                // machine-wide service is the explicit --install-system path.
                install_run_key(exe, argv)
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                install_launch_agent(exe, argv)
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
                    .args(["--user", "disable", "--now", SYSTEMD_UNIT])
                    .status();
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--now", SYSTEMD_UNIT])
                    .status();
            }
            #[cfg(target_os = "windows")]
            ServiceHost::WindowsService => {
                // #173: `sc delete` needs admin; only run it when elevated (the
                // machine-wide service path). The per-user autostart is removed
                // with the HKCU Run entry, which needs no elevation.
                if self.is_elevated() {
                    let _ = std::process::Command::new("sc")
                        .args(["delete", WINDOWS_SERVICE_NAME])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
                let _ = std::process::Command::new("reg")
                    .args([
                        "delete",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", WINDOWS_AUTOSTART_NAME,
                        "/f",
                    ])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                let _ = std::process::Command::new("schtasks")
                    .args(["/delete", "/tn", WINDOWS_AUTOSTART_NAME, "/f"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            #[cfg(target_os = "macos")]
            ServiceHost::Launchd => {
                let _ = std::process::Command::new("launchctl")
                    .arg("bootout")
                    .arg(format!("gui/{}/{LAUNCHD_LABEL}", unsafe { libc::getuid() }))
                    .status();
            }
            _ => {}
        }
    }

    /// Try to elevate and re-run ourselves with admin privileges. Returns
    /// true if the elevation dialog was accepted, false if declined.
    fn try_elevate(&self, exe: &Path, argv: &[String]) -> Result<bool> {
        // The elevated child re-runs `up` with the same daemon flags plus the
        // hidden `--install-system`, which makes it write the system service
        // and exit. (The pkexec arm that lived here ran `<exe> --install-system
        // <every flag as ONE argument>`, which clap rejects before any install.)
        let elevated_argv = elevated_install_argv(argv);
        let _ = (exe, &elevated_argv);
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
            let args = windows_args_line(&elevated_argv);
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
            // Each word is single-quoted for `sh` (do shell script runs sh), then
            // the whole line is escaped for the AppleScript string around it.
            let mut line = sh_quote(&exe.display().to_string());
            for a in &elevated_argv {
                line.push(' ');
                line.push_str(&sh_quote(a));
            }
            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
            let script = format!(
                "do shell script \"{}\" with administrator privileges",
                esc(&line)
            );
            let ok = std::process::Command::new("osascript")
                .args(["-e", &script])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            return Ok(ok);
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        { Ok(false) }
    }

    #[cfg(target_os = "linux")]
    fn has_systemd() -> bool {
        Path::new("/run/systemd/system").is_dir()
    }
}

// PROTOCOL LITERAL: frozen, do not rename. These are the names released builds
// registered with the OS service managers (systemd unit `filament.service`,
// launchd label `autumated.filament`, HKCU Run value and scheduled task
// `Filament`, SCM service `filament`, firewall rule `Filament QUIC`). Every
// later start, stop, status, log, uninstall and sudoers rule must name the SAME
// thing, or an upgraded install can no longer manage the service it already
// has (and a second one appears beside it). Pinned by `frozen_service_names`.
pub(crate) const SYSTEMD_UNIT: &str = "filament";
#[allow(dead_code)] // macOS only
const LAUNCHD_LABEL: &str = "autumated.filament";
#[allow(dead_code)] // Windows only
const WINDOWS_AUTOSTART_NAME: &str = "Filament";
#[allow(dead_code)] // Windows only
const WINDOWS_SERVICE_NAME: &str = "filament";
#[allow(dead_code)] // Windows only
const WINDOWS_FIREWALL_RULE: &str = "name=Filament QUIC";

#[cfg(test)]
mod frozen_service_names {
    /// Each digest is SHA-256 of the ORIGINAL literal (`printf '%s' '<name>' |
    /// sha256sum`); a find-and-replace cannot keep a digest in step.
    #[test]
    fn frozen_service_names() {
        use sha2::{Digest, Sha256};
        for (name, value, digest) in [
            ("SYSTEMD_UNIT", super::SYSTEMD_UNIT, "5696d135fe7eb0f05ce06041ec050633b7e8820d0afc490c936e73e5cafb378e"),
            ("LAUNCHD_LABEL", super::LAUNCHD_LABEL, "550c6c611b45bb2f7a356cfa36bf28a44df6b963c22b7dd8517db8b592b4c3c2"),
            ("WINDOWS_AUTOSTART_NAME", super::WINDOWS_AUTOSTART_NAME, "0a9066fa6acd2d7a545af769171444d090e5b7940f5dd39e77b9a2c924b5982c"),
            ("WINDOWS_SERVICE_NAME", super::WINDOWS_SERVICE_NAME, "5696d135fe7eb0f05ce06041ec050633b7e8820d0afc490c936e73e5cafb378e"),
            ("WINDOWS_FIREWALL_RULE", super::WINDOWS_FIREWALL_RULE, "89a571ce57a1e8b0ed042cfa0e474c33e112170f01d9175f64f5123781a5fb1d"),
        ] {
            let got: String = Sha256::digest(value.as_bytes())
                .as_slice()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(got, digest, "frozen service name {name} changed");
        }
    }
}

// ----------------------------------------------- service argv encoders --
//
// The daemon's argv reaches four service formats. Each gets the SAME list and
// encodes it for itself, so an argument is either passed exactly or the format
// says it cannot be. These are pure so their output is unit-tested on every
// platform, not just the one that ships the format.

/// Escape text for an XML element body or attribute value.
#[allow(dead_code)] // macOS (plist) and Windows (task XML) only
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// A launchd plist that runs `exe` with `argv`, one `<string>` per element.
#[allow(dead_code)] // macOS only
pub(crate) fn launchd_plist(label: &str, exe: &Path, argv: &[String]) -> String {
    let mut args = format!("    <string>{}</string>\n", xml_escape(&exe.display().to_string()));
    for a in argv {
        args.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
        xml_escape(label)
    )
}

/// One word for a systemd `ExecStart=` line. systemd expands `%` specifiers
/// and `$VAR` everywhere in the line, so those are doubled; anything that
/// would split or confuse the word is double-quoted with C-style escapes.
fn systemd_word(s: &str) -> String {
    let escaped = s.replace('%', "%%").replace('$', "$$");
    let plain = !escaped.is_empty()
        && escaped
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._,=:@+-%$".contains(c));
    if plain {
        return escaped;
    }
    let mut out = String::from("\"");
    for c in escaped.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `ExecStart=` value (without the key) that runs `exe` with `argv`.
#[allow(dead_code)] // Linux only
pub(crate) fn systemd_exec_start(exe: &Path, argv: &[String]) -> String {
    let mut line = systemd_word(&exe.display().to_string());
    for a in argv {
        line.push(' ');
        line.push_str(&systemd_word(a));
    }
    line
}

/// The per-user systemd unit `up --install` writes on Linux.
#[allow(dead_code)] // Linux only
pub(crate) fn systemd_user_unit(exe: &Path, argv: &[String]) -> String {
    format!(
        "[Unit]\nDescription=Tunlion drop target (trusted devices only)\nAfter=network-online.target\n\n[Service]\nType=notify\nExecStart={}\nRestart=always\nRestartSec=2\nWatchdogSec=45\n\n[Install]\nWantedBy=default.target\n",
        systemd_exec_start(exe, argv)
    )
}

/// Quote one argument the way CommandLineToArgvW (and the MSVC runtime)
/// splits it back: backslashes are literal except before a quote, where they
/// must be doubled.
#[allow(dead_code)] // Windows only
fn windows_arg(s: &str) -> String {
    if !s.is_empty() && !s.chars().any(|c| matches!(c, ' ' | '\t' | '\n' | '"')) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The arguments part of a Windows command line (no program name).
#[allow(dead_code)] // Windows only
pub(crate) fn windows_args_line(argv: &[String]) -> String {
    argv.iter().map(|a| windows_arg(a)).collect::<Vec<_>>().join(" ")
}

/// A full Windows command line: quoted program, then the arguments.
#[allow(dead_code)] // Windows only
pub(crate) fn windows_command_line(exe: &Path, argv: &[String]) -> String {
    let exe = format!("\"{}\"", exe.display());
    if argv.is_empty() {
        exe
    } else {
        format!("{exe} {}", windows_args_line(argv))
    }
}

/// Single-quote one word for `sh`.
#[allow(dead_code)] // macOS only (osascript elevation)
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The argv an elevated child runs: the daemon argv with the hidden
/// `--install-system` added to `up`, so the child installs and exits.
fn elevated_install_argv(argv: &[String]) -> Vec<String> {
    let mut out: Vec<String> = argv.to_vec();
    let at = out.iter().position(|a| a == "up").map(|i| i + 1).unwrap_or(0);
    if at == 0 {
        out.insert(0, "up".into());
        out.insert(1, "--install-system".into());
    } else {
        out.insert(at, "--install-system".into());
    }
    out
}

/// Run a command and turn anything but a zero exit into an error that names
/// the command, so a caller can say exactly which step failed.
#[allow(dead_code)] // Linux and macOS installers
fn run_checked(program: &str, args: &[&str]) -> Result<()> {
    let shown = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    match std::process::Command::new(program).args(args).status() {
        Ok(st) if st.success() => Ok(()),
        Ok(st) => anyhow::bail!("`{shown}` failed ({st})"),
        Err(e) => anyhow::bail!("could not run `{shown}`: {e}"),
    }
}

// ------------------------------------------------- platform installers --

#[cfg(target_os = "linux")]
fn install_systemd_user(exe: &Path, argv: &[String]) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let unit_dir = PathBuf::from(&home).join(".config/systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let unit = unit_dir.join(format!("{SYSTEMD_UNIT}.service"));
    std::fs::write(&unit, systemd_user_unit(exe, argv))?;
    // Each step's result is checked: `daemon-reload` failing (no user bus, as
    // in a bare ssh session or a container) means `enable` cannot work either,
    // and the user must hear which one broke, not "installed".
    run_checked("systemctl", &["--user", "daemon-reload"])
        .and_then(|_| run_checked("systemctl", &["--user", "enable", "--now", SYSTEMD_UNIT]))
        .map_err(|e| {
            anyhow::anyhow!(
                "wrote {} but {e}. Finish by hand: systemctl --user daemon-reload && systemctl --user enable --now {SYSTEMD_UNIT}",
                unit.display()
            )
        })
}

#[cfg(target_os = "windows")]
fn install_run_key(exe: &Path, argv: &[String]) -> Result<()> {
    // Per-user autostart via HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
    // Runs as the current user at logon with no elevation. This is the default
    // background receiver on Windows.
    let cmd = windows_command_line(exe, argv);
    let out = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v", WINDOWS_AUTOSTART_NAME,
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
#[allow(dead_code)]
fn install_scheduled_task(exe: &Path, argv: &[String]) -> Result<()> {
    let task_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger/></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Actions><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>"#,
        xml_escape(&exe.display().to_string()),
        xml_escape(&windows_args_line(argv))
    );
    let tmp = std::env::temp_dir().join("filament-task.xml");
    std::fs::write(&tmp, &task_xml)?;
    let out = std::process::Command::new("schtasks")
        .args(["/create", "/tn", WINDOWS_AUTOSTART_NAME, "/xml", &tmp.to_string_lossy(), "/f"])
        .output()?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("schtasks failed: {}", stderr.trim());
    }
    Ok(())
}

/// Load a plist into a launchd domain, replacing any copy already loaded
/// (bootstrap refuses a label that is already there, which is every re-run of
/// `up --install`). The bootout is allowed to fail: nothing loaded is fine.
#[cfg(target_os = "macos")]
fn launchctl_bootstrap(domain: &str, plist: &Path) -> Result<()> {
    let _ = std::process::Command::new("launchctl")
        .arg("bootout")
        .arg(format!("{domain}/{LAUNCHD_LABEL}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let path = plist.display().to_string();
    run_checked("launchctl", &["bootstrap", domain, &path]).map_err(|e| {
        anyhow::anyhow!("wrote {path} but {e}. Load it by hand: launchctl bootstrap {domain} {path}")
    })
}

#[cfg(target_os = "macos")]
fn install_launch_agent(exe: &Path, argv: &[String]) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    let plist = dir.join(format!("{LAUNCHD_LABEL}.plist"));
    std::fs::write(&plist, launchd_plist(LAUNCHD_LABEL, exe, argv))?;
    launchctl_bootstrap(&format!("gui/{}", unsafe { libc::getuid() }), &plist)
}

#[cfg(test)]
mod service_argv_encoding {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The plist carries every argument as its own `<string>`, escaped. The
    /// defect this pins: `--shell` spliced as raw text inside `<array>`, which
    /// launchd does not pass to the program at all.
    #[test]
    fn plist_has_one_string_element_per_argument() {
        let a = argv(&["up", "--shell-only=a,b", "--dir=/Users/k/A&B <x>", "--i-know"]);
        let p = launchd_plist("autumated.filament", Path::new("/opt/tun lion/tunlion"), &a);
        let start = p.find("<array>").expect("array");
        let end = p.find("</array>").expect("array end");
        let body = &p[start + "<array>".len()..end];
        let strings: Vec<&str> = body
            .split("<string>")
            .skip(1)
            .map(|s| s.split("</string>").next().unwrap())
            .collect();
        assert_eq!(
            strings,
            vec![
                "/opt/tun lion/tunlion",
                "up",
                "--shell-only=a,b",
                "--dir=/Users/k/A&amp;B &lt;x&gt;",
                "--i-know",
            ]
        );
        // Nothing but whitespace between the elements: no raw argument text.
        let stripped: String = body
            .split("<string>")
            .map(|s| s.split("</string>").nth(1).unwrap_or(""))
            .collect::<String>();
        assert!(stripped.trim().is_empty(), "raw text inside <array>: {stripped:?}");
        assert!(p.contains("<key>Label</key><string>autumated.filament</string>"));
    }

    #[test]
    fn xml_escape_covers_the_five_entities() {
        assert_eq!(xml_escape(r#"a&b<c>d"e'f"#), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
    }

    #[test]
    fn systemd_exec_start_quotes_what_would_split_or_expand() {
        let a = argv(&[
            "up",
            "--shell-only=a,b",
            "--dir=/home/u/My Files",
            "--shell-program=bash -l",
            "--name-as=100%",
            "--server=https://x.example/$HOME",
            "--shell-user=say \"hi\"",
        ]);
        let line = systemd_exec_start(Path::new("/usr/local/bin/tunlion"), &a);
        assert_eq!(
            line,
            "/usr/local/bin/tunlion up --shell-only=a,b \"--dir=/home/u/My Files\" \
             \"--shell-program=bash -l\" --name-as=100%% \
             --server=https://x.example/$$HOME \"--shell-user=say \\\"hi\\\"\""
        );
        let unit = systemd_user_unit(Path::new("/usr/local/bin/tunlion"), &argv(&["up", "--shell"]));
        assert!(unit.contains("\nExecStart=/usr/local/bin/tunlion up --shell\n"), "{unit}");
    }

    #[test]
    fn windows_command_line_round_trips_the_msvc_rules() {
        assert_eq!(windows_arg("plain"), "plain");
        assert_eq!(windows_arg(""), "\"\"");
        assert_eq!(windows_arg("a b"), "\"a b\"");
        assert_eq!(windows_arg("C:\\x y\\"), "\"C:\\x y\\\\\"");
        assert_eq!(windows_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(
            windows_command_line(Path::new("C:\\T\\tunlion.exe"), &argv(&["up", "--dir=C:\\My Files"])),
            "\"C:\\T\\tunlion.exe\" up \"--dir=C:\\My Files\""
        );
    }

    #[test]
    fn elevated_child_runs_up_with_install_system() {
        assert_eq!(
            elevated_install_argv(&argv(&["up", "--shell", "--dir=/x"])),
            argv(&["up", "--install-system", "--shell", "--dir=/x"])
        );
        assert_eq!(elevated_install_argv(&[]), argv(&["up", "--install-system"]));
    }

    #[test]
    fn sh_quote_survives_single_quotes() {
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }
}

#[cfg(target_os = "windows")]
pub fn add_firewall_rule(exe: &Path) {
    let _ = std::process::Command::new("netsh")
        .args(["advfirewall", "firewall", "add", "rule",
            WINDOWS_FIREWALL_RULE, "dir=in", "action=allow",
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
/// Whether a terminal clipboard write (OSC 52) can plausibly land somewhere.
/// macOS and Windows sessions always have a clipboard. On Linux and the BSDs
/// only a graphical session (X11 or Wayland) has one; a headless box, a
/// console, or a plain ssh login has none we can know about, so `send` must
/// not claim "(copied to clipboard)" there.
pub fn clipboard_reachable() -> bool {
    #[cfg(any(target_os = "macos", windows))]
    {
        true
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        set("DISPLAY") || set("WAYLAND_DISPLAY")
    }
}

/// What a FUSE mount needs before `mount` may say "mounted": the kernel
/// device and (unless root, which can mount directly) the setuid helper the
/// `fuser` crate execs. `Err` names the missing piece and how to install it,
/// per distro. Elsewhere (macOS/Windows have their own stacks) nothing to check.
pub fn fuse_prerequisites() -> std::result::Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let install = fuse_install_hint();
        if !Path::new("/dev/fuse").exists() {
            return Err(format!(
                "FUSE is not available here: /dev/fuse does not exist. Load the module with `sudo modprobe fuse`{}; inside a container, start it with `--device /dev/fuse --cap-add SYS_ADMIN`.",
                if install.is_empty() { String::new() } else { format!(" (and install it: `{install}`)") }
            ));
        }
        let root = unsafe { libc::geteuid() } == 0;
        let helper = ["fusermount3", "fusermount"].iter().any(|h| {
            std::env::var_os("PATH")
                .map(|p| std::env::split_paths(&p).any(|d| d.join(h).is_file()))
                .unwrap_or(false)
        });
        if !root && !helper {
            return Err(format!(
                "FUSE's mount helper (fusermount3) is not installed, so this user cannot mount. Install it: `{}`",
                if install.is_empty() { "your distribution's fuse3 package" } else { install }
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// The install command for FUSE 3 on this Linux distribution, from the
/// os-release file (read only). Empty when the distribution is not recognised.
#[cfg(target_os = "linux")]
fn fuse_install_hint() -> &'static str {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim_matches('"').to_ascii_lowercase())
            .unwrap_or_default()
    };
    let ids = format!("{} {}", field("ID="), field("ID_LIKE="));
    let has = |n: &str| ids.split_whitespace().any(|w| w == n);
    if has("debian") || has("ubuntu") {
        "sudo apt install fuse3"
    } else if has("fedora") || has("rhel") || has("centos") {
        "sudo dnf install fuse3"
    } else if has("arch") {
        "sudo pacman -S fuse3"
    } else if has("alpine") {
        "sudo apk add fuse3"
    } else if has("opensuse") || has("suse") || has("sles") {
        "sudo zypper install fuse3"
    } else {
        ""
    }
}

pub fn spawn_detached(exe: &Path, args: &[&str], log: &Path) -> Result<std::process::Child> {
    // Name the path in every failure: a HOME that does not exist used to print
    // only "No such file or directory (os error 2)", which names nothing.
    if let Some(parent) = log.parent() {
        create_private_dir_all(parent).map_err(|e| {
            anyhow::anyhow!("cannot create the config directory {}: {e}", parent.display())
        })?;
    }
    let log_file = open_private_log(log, false)
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

// ------------------------------------------------------------ hostname --

/// The machine's hostname as the OS reports it, or `None` when it cannot be
/// read. Unix asks the kernel (`gethostname`) rather than reading
/// /etc/hostname, which macOS does not have; Windows reads COMPUTERNAME.
#[cfg(unix)]
pub fn os_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(windows)]
pub fn os_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.trim().is_empty())
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

    /// True when the argv is the `--shell-user` drop built by `shell_argv`.
    fn is_user_drop(&self) -> bool {
        self.argv.len() >= 3
            && Path::new(&self.argv[0]).file_name().and_then(|n| n.to_str()) == Some("runuser")
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
        // A `--shell-user` argv is `runuser -l <user>`. Keeping only argv[0]
        // here would yield `runuser -c <cmd>`, and runuser with no user named
        // defaults to root: the one-shot command would run as root while the
        // operator asked for <user>. Keep the whole drop prefix instead.
        if self.is_user_drop() {
            let mut args = self.argv.clone();
            args.push("-c".into());
            args.push(cmd.to_string());
            return args;
        }
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

    fn mode_tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tunlion-mode-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The inbox peers write into is owner-only, and content directories are
    /// never world-writable, whatever the umask (it can only remove bits from
    /// the explicit modes, so these hold under umask 0 as well).
    #[test]
    fn inbox_is_owner_only_and_content_dirs_are_not_world_writable() {
        let d = mode_tmp("inbox");
        let inbox = d.join("Tunlion");
        let sub = inbox.join("synced").join("deep");
        create_content_dirs(&inbox, &sub).unwrap();
        assert!(sub.is_dir());
        if let Some(m) = file_mode(&inbox) {
            assert_eq!(m & 0o077, 0, "the inbox must be owner-only, got {m:o}");
        }
        for p in [inbox.join("synced"), sub.clone()] {
            if let Some(m) = file_mode(&p) {
                assert_eq!(m & 0o022, 0, "{} must not be group/world-writable, got {m:o}", p.display());
            }
        }
        // An existing inbox is left alone, and creating it again is not an error.
        create_inbox_dir(&inbox).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The partial-receive sidecars are created through this; it must be
    /// owner-only at creation, never umask-dependent.
    #[test]
    fn create_new_private_is_owner_only() {
        let d = mode_tmp("private");
        let p = d.join("x.part.meta");
        drop(create_new_private(&p).unwrap());
        if let Some(m) = file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a new private file must be 0600, got {m:o}");
        }
        // create_new: it never reuses (or writes through) what is already there.
        assert!(create_new_private(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restrict_open_file_tightens_a_loose_file() {
        let d = mode_tmp("restrict");
        let p = d.join("old.part");
        let f = std::fs::File::create(&p).unwrap();
        fs_at::set_mode_via_handle(&f, 0o666).unwrap();
        restrict_open_file(&f).unwrap();
        drop(f);
        if let Some(m) = file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a resumed partial must end up 0600, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A finished receive gets the ordinary create mode back: 0644 under the
    /// process umask, never more than that and never executable.
    #[test]
    fn publish_received_file_restores_the_umask_mode() {
        let d = mode_tmp("publish");
        let p = d.join("done.bin");
        let f = create_new_private(&p).unwrap();
        publish_received_file(&f).unwrap();
        drop(f);
        if let Some(m) = file_mode(&p) {
            assert_eq!(m & 0o777, 0o644 & !process_umask(), "got {m:o}");
            assert_eq!(m & 0o133, 0, "never group/other writable nor executable, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `mount` without FUSE is refused up front, naming the missing piece,
    /// and only then: a machine that has /dev/fuse is never refused by it.
    #[test]
    fn mount_prerequisite_tracks_the_fuse_device() {
        let has_fuse = !cfg!(target_os = "linux") || Path::new("/dev/fuse").exists();
        match mount_prerequisite() {
            Ok(()) => assert!(has_fuse, "no /dev/fuse here, yet the mount was allowed"),
            Err(m) => {
                assert!(!has_fuse, "refused although FUSE is present: {m}");
                assert!(m.contains("/dev/fuse"), "{m}");
            }
        }
    }

    /// The /proc/locks parser: the holder, never a waiter, device numbers in
    /// hex, inode in decimal, and an OFD lock's -1 is "held, pid unknown".
    #[test]
    fn the_lock_holder_is_read_from_proc_locks_text() {
        let text = "1: FLOCK  ADVISORY  WRITE 4242 fd:01:131087 0 EOF\n\
                    1: -> FLOCK  ADVISORY  WRITE 5151 fd:01:131087 0 EOF\n\
                    2: POSIX  ADVISORY  WRITE 777 08:02:99 0 EOF\n\
                    3: OFDLCK ADVISORY  READ  -1 08:02:1234 0 EOF\n";
        assert_eq!(lock_holder_in(text, 0xfd, 0x01, 131087), LockHolder::Held(Some(4242)));
        assert_eq!(lock_holder_in(text, 0x08, 0x02, 99), LockHolder::Held(Some(777)));
        assert_eq!(lock_holder_in(text, 0x08, 0x02, 1234), LockHolder::Held(None));
        // Same inode number on another device, and a free inode.
        assert_eq!(lock_holder_in(text, 0x08, 0x03, 99), LockHolder::Free);
        assert_eq!(lock_holder_in(text, 0xfd, 0x01, 5), LockHolder::Free);
        assert_eq!(lock_holder_in("", 0xfd, 0x01, 5), LockHolder::Free);
    }

    /// The setcap'd daemon: a process that is NOT dumpable (what a file
    /// capability makes it) holding the instance lock. Its /proc/<pid>/exe is
    /// unreadable to its own user, which the old executable check read as
    /// "dead", so `status` said "not running" for everyone on kernel TUN. The
    /// lock names it anyway, the daemon check accepts it, and once it dies the
    /// lock is free and the same pidfile no longer counts.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_dumpable_daemon_is_found_by_its_lock_not_its_exe() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("tl-lockholder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("up.lock");
        let pidfile = dir.join("up.pid");
        std::fs::write(&lock, b"").unwrap();
        let c_lock = std::ffi::CString::new(lock.as_os_str().as_bytes()).unwrap();
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // The child does only async-signal-safe syscalls: it opens the lock
        // file ITSELF (a lock taken through an fd inherited from this process
        // would outlive the child), drops dumpability, locks, reports, waits.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                let fd = libc::open(c_lock.as_ptr(), libc::O_RDWR);
                if fd < 0 || libc::flock(fd, libc::LOCK_EX) != 0 {
                    libc::_exit(3);
                }
                libc::write(fds[1], b"k".as_ptr() as *const libc::c_void, 1);
                loop {
                    libc::pause();
                }
            }
        }
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1) };
        let child = child as u32;
        let outcome = std::panic::catch_unwind(|| {
            assert_eq!(n, 1, "the child never took the lock");
            if unsafe { libc::geteuid() } != 0 {
                // The precondition the bug needs (root may read it anyway).
                assert_eq!(process_exe_path(child), None, "the child should be non-dumpable");
            }
            assert_eq!(instance_lock_holder(&lock), LockHolder::Held(Some(child)));
            std::fs::write(&pidfile, format!("{child}\n")).unwrap();
            assert_eq!(crate::shell_support::daemon_alive_in(&pidfile, &lock), Some(child));
            // A pidfile naming any other live process is not this config's daemon.
            std::fs::write(&pidfile, format!("{}\n", std::process::id())).unwrap();
            assert_eq!(crate::shell_support::daemon_alive_in(&pidfile, &lock), None);
        });
        unsafe {
            libc::kill(child as i32, libc::SIGKILL);
            libc::waitpid(child as i32, std::ptr::null_mut(), 0);
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        if let Err(e) = outcome {
            std::panic::resume_unwind(e);
        }
        // Dead: the lock is free, and the pidfile naming it is nobody.
        assert_eq!(instance_lock_holder(&lock), LockHolder::Free);
        std::fs::write(&pidfile, format!("{child}\n")).unwrap();
        assert_eq!(crate::shell_support::daemon_alive_in(&pidfile, &lock), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The copied-config case without a fork: this process holds the lock on
    /// one config dir; the other dir's `up.lock` and `up.pid` are byte-for-byte
    /// copies (pid included), and the other dir still has no daemon.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_copied_config_dir_does_not_inherit_the_daemon() {
        let base = std::env::temp_dir().join(format!("tl-cfgcopy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let held = InstanceLock::try_acquire(&a.join("up.lock")).unwrap().expect("lock");
        let me = std::process::id();
        std::fs::write(a.join("up.pid"), format!("{me}\n")).unwrap();
        std::fs::copy(a.join("up.lock"), b.join("up.lock")).unwrap();
        std::fs::copy(a.join("up.pid"), b.join("up.pid")).unwrap();
        assert_eq!(instance_lock_holder(&a.join("up.lock")), LockHolder::Held(Some(me)));
        assert_eq!(instance_lock_holder(&b.join("up.lock")), LockHolder::Free);
        assert_eq!(
            crate::shell_support::daemon_alive_in(&a.join("up.pid"), &a.join("up.lock")),
            Some(me)
        );
        assert_eq!(
            crate::shell_support::daemon_alive_in(&b.join("up.pid"), &b.join("up.lock")),
            None,
            "a copied config dir must not see the original's daemon"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&base);
    }

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

    // --shell-user one-shot PTY command: the drop prefix must survive, or
    // `runuser -c <cmd>` runs the command as root.
    #[test]
    fn shell_host_exec_keeps_the_shell_user_drop() {
        let sh = ShellHost::new(&["runuser".into(), "-l".into(), "nobody".into()]);
        assert_eq!(
            sh.exec_cmd_args("id -un"),
            vec!["runuser", "-l", "nobody", "-c", "id -un"]
        );
        assert_eq!(sh.interactive_args(), vec!["runuser", "-l", "nobody"]);
    }

    #[test]
    fn exec_as_user_argv_without_user_is_the_direct_argv() {
        let argv = Paths::exec_as_user_argv("/bin/echo", &["a b".into()], None).unwrap();
        assert_eq!(argv, vec!["/bin/echo", "a b"]);
    }

    #[cfg(unix)]
    #[test]
    fn exec_as_user_argv_drops_through_runuser_on_unix() {
        let argv = Paths::exec_as_user_argv("/usr/bin/id", &["-un".into()], Some("nobody")).unwrap();
        assert_eq!(argv, vec!["runuser", "-u", "nobody", "--", "/usr/bin/id", "-un"]);
        // Same tool as the PTY drop: one mechanism, not two.
        let (pty, _) = Paths::shell_argv(Some("bash"), None, Some("nobody"));
        assert_eq!(pty[0], argv[0]);
    }

    #[cfg(not(unix))]
    #[test]
    fn exec_as_user_argv_refuses_where_no_drop_exists() {
        let err = Paths::exec_as_user_argv("cmd", &[], Some("nobody")).unwrap_err();
        assert!(err.contains("--shell-user"), "{err}");
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

    /// The blind-test report, exactly: a populated default config at
    /// `$HOME/.config/filament`, then `XDG_CONFIG_HOME=<new empty dir>`. The
    /// new directory received copies of identity.ed25519, overlay.ed25519,
    /// proxy.token, devices.json and up.pid. Nothing may appear there, and the
    /// default config must be left exactly as it was.
    #[test]
    fn an_xdg_config_home_is_never_filled_from_the_default_config() {
        let uid = format!(
            "{}-xdg-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let work = std::env::temp_dir().join(format!("fil-cfg-{uid}"));
        let home = work.join("home");
        let legacy = home.join(".config").join("filament");
        let xdg = work.join("deep").join("new-xdg");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        for f in ["identity.ed25519", "overlay.ed25519", "proxy.token", "devices.json", "up.pid"] {
            std::fs::write(legacy.join(f), b"the default config's").unwrap();
        }

        let _guard = crate::tests::lock_test_config();
        let old_home = std::env::var_os("HOME");
        let old_override = std::env::var_os("FILAMENT_CONFIG_DIR");
        let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::remove_var("FILAMENT_CONFIG_DIR");
            std::env::set_var("XDG_CONFIG_HOME", &xdg);
        }
        Paths::migrate_legacy();
        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(v) => unsafe { std::env::set_var(k, v) },
            None => unsafe { std::env::remove_var(k) },
        };
        restore("HOME", old_home);
        restore("FILAMENT_CONFIG_DIR", old_override);
        restore("XDG_CONFIG_HOME", old_xdg);

        let mut copied = Vec::new();
        let mut stack = vec![xdg.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    copied.push(e.path());
                }
            }
        }
        assert!(copied.is_empty(), "the new XDG config dir received files: {copied:?}");
        for f in ["identity.ed25519", "overlay.ed25519", "proxy.token", "devices.json", "up.pid"] {
            assert!(legacy.join(f).is_file(), "the default config lost {f}");
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn the_legacy_move_happens_only_on_windows_unoverridden_and_never_onto_a_dir() {
        let work = std::env::temp_dir().join(format!("fil-legacy-pure-{}", std::process::id()));
        let legacy = work.join("legacy");
        let target = work.join("appdata").join("filament");
        std::fs::create_dir_all(&legacy).unwrap();
        // The one case that moves: Windows, no override, target absent.
        assert_eq!(
            legacy_migration(&legacy, &target, false, true),
            Some((legacy.clone(), target.clone()))
        );
        // Linux and macOS: the "legacy" path is the real config dir.
        assert_eq!(legacy_migration(&legacy, &target, false, false), None);
        // An explicit FILAMENT_CONFIG_DIR or XDG_CONFIG_HOME.
        assert_eq!(legacy_migration(&legacy, &target, true, true), None);
        // Onto itself, or onto a directory that already exists.
        assert_eq!(legacy_migration(&legacy, &legacy, false, true), None);
        std::fs::create_dir_all(&target).unwrap();
        assert_eq!(legacy_migration(&legacy, &target, false, true), None);
        // No legacy directory: nothing to move.
        let _ = std::fs::remove_dir_all(&target);
        assert_eq!(legacy_migration(&work.join("absent"), &target, false, true), None);
        let _ = std::fs::remove_dir_all(&work);
    }

    /// `env -u HOME`: the home still comes from the password database, and
    /// whatever answer there is is absolute (never `.`).
    #[cfg(unix)]
    #[test]
    fn with_home_unset_the_home_dir_is_the_password_databases_and_absolute() {
        let _guard = crate::tests::lock_test_config();
        let old_home = std::env::var_os("HOME");
        unsafe { std::env::remove_var("HOME") };
        let known = Paths::home_dir_known();
        let fallback = Paths::home_dir();
        match old_home {
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        assert_eq!(known, super::passwd_home().filter(|p| p.is_absolute()));
        if let Some(h) = known {
            assert!(h.is_absolute(), "{h:?}");
            assert_eq!(fallback, h);
        }
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

/// Whether a compiled terminfo entry for `name` is installed on this machine.
///
/// Used to decide the TERM a remote shell gets (l2::effective_term): forwarding
/// a terminal name the machine has no entry for makes curses programs refuse
/// outright ("missing or unsuitable terminal: xterm-kitty"). Probes ncurses' own
/// search path -- $TERMINFO, ~/.terminfo, $TERMINFO_DIRS, then the system
/// directories -- in both the first-character and the hex-code subdirectory
/// layouts (Linux and macOS respectively). `name` must already be validated by
/// the caller: it comes from a peer and is joined onto directories here.
///
/// Windows has no terminfo (ConPTY), so every name is "available" and the
/// requested one is kept.
pub fn terminfo_exists(name: &str) -> bool {
    #[cfg(unix)]
    {
        let Some(first) = name.chars().next() else { return false };
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Some(d) = std::env::var_os("TERMINFO") {
            dirs.push(d.into());
        }
        dirs.push(Paths::home_dir().join(".terminfo"));
        if let Some(list) = std::env::var_os("TERMINFO_DIRS") {
            dirs.extend(std::env::split_paths(&list).filter(|p| !p.as_os_str().is_empty()));
        }
        for d in [
            "/etc/terminfo",
            "/lib/terminfo",
            "/usr/share/terminfo",
            "/usr/lib/terminfo",
            "/usr/local/share/terminfo",
        ] {
            dirs.push(d.into());
        }
        let hex = format!("{:x}", first as u32);
        dirs.iter().any(|d| {
            d.join(first.to_string()).join(name).is_file() || d.join(&hex).join(name).is_file()
        })
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        true
    }
}

/// The local console's modes around an interactive remote PTY.
///
/// WINDOWS: crossterm's raw mode only clears line input, echo and processed
/// input. It never sets ENABLE_VIRTUAL_TERMINAL_INPUT, so mouse events (and
/// arrow, function and other special keys) arrive as INPUT_RECORDs that a plain
/// stdin byte read never sees: a remote tmux asking for mouse reports never got
/// one, while `--ssh` worked because OpenSSH for Windows sets the flag itself.
/// `enable_vt` adds VT input, clears quick-edit (with ENABLE_EXTENDED_FLAGS, or
/// the change is ignored) so clicks are not kept for the console's own
/// selection, and adds VT output processing so the remote app's mouse request is
/// honoured even on the classic console host. `restore` puts back the exact
/// original modes. Only mode numbers are kept, never a HANDLE: in windows-sys
/// 0.59 a HANDLE is a raw pointer (not Send) and this lives in async code.
///
/// ELSEWHERE: a terminal already delivers mouse and keys as bytes in raw mode,
/// so every call is a no-op.
pub struct ConsoleModes {
    #[cfg(windows)]
    input: Option<u32>,
    #[cfg(windows)]
    output: Option<u32>,
}

impl ConsoleModes {
    /// Record the console's modes as they are now, BEFORE anything changes them.
    pub fn snapshot() -> Self {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
            ConsoleModes {
                input: win_console_get(STD_INPUT_HANDLE),
                output: win_console_get(STD_OUTPUT_HANDLE),
            }
        }
        #[cfg(not(windows))]
        {
            ConsoleModes {}
        }
    }

    /// Call AFTER entering raw mode.
    pub fn enable_vt(&self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                ENABLE_EXTENDED_FLAGS, ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };
            if let Some(cur) = win_console_get(STD_INPUT_HANDLE) {
                let want = (cur | ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_EXTENDED_FLAGS)
                    & !ENABLE_QUICK_EDIT_MODE;
                win_console_set(STD_INPUT_HANDLE, want);
            }
            if let Some(cur) = win_console_get(STD_OUTPUT_HANDLE) {
                win_console_set(STD_OUTPUT_HANDLE, cur | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }

    /// Put back exactly what `snapshot` recorded.
    pub fn restore(&self) {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
            if let Some(m) = self.input {
                win_console_set(STD_INPUT_HANDLE, m);
            }
            if let Some(m) = self.output {
                win_console_set(STD_OUTPUT_HANDLE, m);
            }
        }
    }
}

#[cfg(windows)]
fn win_console_get(which: u32) -> Option<u32> {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle};
    let mut mode: u32 = 0;
    // SAFETY: GetStdHandle has no preconditions; GetConsoleMode writes one u32
    // through a valid pointer and fails cleanly on a non-console handle.
    let ok = unsafe { GetConsoleMode(GetStdHandle(which), &mut mode) };
    (ok != 0).then_some(mode)
}

#[cfg(windows)]
fn win_console_set(which: u32, mode: u32) {
    use windows_sys::Win32::System::Console::{GetStdHandle, SetConsoleMode};
    // SAFETY: as above; a failure leaves the console unchanged.
    unsafe {
        SetConsoleMode(GetStdHandle(which), mode);
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
/// The platform fact effective_term relies on, tested where the conditional
/// lives: on unix an invented terminal name has no terminfo entry, and a name
/// every CI image ships does. (On Windows terminfo_exists is true by design.)
#[cfg(all(test, unix))]
#[test]
fn terminfo_lookup_distinguishes_known_from_invented_names() {
    assert!(!terminfo_exists("definitely-not-a-real-terminal-x9"));
    assert!(terminfo_exists("xterm-256color"), "every Linux/macOS image ships xterm-256color");
}

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

// ------------------------------------------------------- instance lock holder --

/// Who holds a daemon's single-instance lock (`{config}/up.lock`), as the
/// kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockHolder {
    /// Held, by this pid when the kernel names it (None: it is held by a
    /// process this one cannot name, e.g. in another pid namespace).
    Held(Option<u32>),
    /// The lock file exists and nobody holds it: no daemon serves this config.
    Free,
    /// This platform (or this box: no /proc/locks, no lock file yet) cannot
    /// say. The caller falls back to the pidfile and the executable check.
    Unknown,
}

/// Who holds the instance lock at `path`, read WITHOUT taking it.
///
/// WHY THE LOCK AND NOT THE PIDFILE. The pidfile is only a claim: a copied or
/// migrated config dir carries another config's `up.pid`, and that config's
/// live daemon then passed every check, so `up` there said "already running",
/// `status` probed a socket nobody served, and `down` killed the other config's
/// daemon. The lock is held by exactly the process serving THIS config dir: a
/// copy of `up.lock` is a different inode that nobody holds.
///
/// WHY NOT /proc/<pid>/exe EITHER. A daemon run from a binary given
/// CAP_NET_ADMIN by `setcap` (the kernel-TUN setup `init` recommends) is not
/// dumpable, so its `/proc/<pid>/exe` cannot be read by its own user and the
/// old check called a healthy daemon dead. /proc/locks is world-readable and
/// names the holder of every lock by device and inode.
///
/// Read-only on purpose: probing by TAKING the lock would make a concurrent
/// `up` lose the election to a `status` that happened to look at that instant.
pub fn instance_lock_holder(path: &Path) -> LockHolder {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return LockHolder::Unknown;
        };
        let Ok(locks) = std::fs::read_to_string("/proc/locks") else {
            return LockHolder::Unknown;
        };
        let dev = meta.dev();
        // glibc/musl dev_t encoding (what `major(3)`/`minor(3)` decode).
        let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0fff);
        let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x00ff);
        lock_holder_in(&locks, major, minor, meta.ino())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        LockHolder::Unknown
    }
}

/// The holder of the lock on inode (`major`:`minor`, `ino`) in the text of
/// /proc/locks, whose lines read
/// `1: FLOCK  ADVISORY  WRITE 1234 08:02:131087 0 EOF`
/// (device numbers in hex, inode in decimal; `-> ` marks a waiter, not a
/// holder; an OFD lock has pid -1). Any lock type counts: on NFS a flock is
/// carried as a POSIX lock. Pure.
pub fn lock_holder_in(locks: &str, major: u64, minor: u64, ino: u64) -> LockHolder {
    for line in locks.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[1] == "->" {
            continue;
        }
        let mut id = fields[5].split(':');
        let (Some(ma), Some(mi), Some(ino_s)) = (id.next(), id.next(), id.next()) else {
            continue;
        };
        let same = u64::from_str_radix(ma, 16).ok() == Some(major)
            && u64::from_str_radix(mi, 16).ok() == Some(minor)
            && ino_s.parse::<u64>().ok() == Some(ino);
        if same {
            let pid = fields[4].parse::<i64>().ok().filter(|p| *p > 0).map(|p| p as u32);
            return LockHolder::Held(pid);
        }
    }
    LockHolder::Free
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

    /// Write this process's pid into the lock file, so a loser can say WHICH
    /// process holds the election. Holding the lock already proves the holder is
    /// alive (the kernel drops it on exit); the pid is what turns "already running
    /// (starting)" into a claim that can be checked. Best effort.
    pub fn record_owner(&self) {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = &self._file;
        let _ = f.set_len(0);
        let _ = f.seek(SeekFrom::Start(0));
        let _ = writeln!(f, "{}", std::process::id());
        let _ = f.flush();
    }

    /// The pid the current holder recorded in `path`, if any. On Windows a held
    /// lock blocks the read, so this is None there and callers fall back to the
    /// pidfile alone.
    pub fn recorded_owner(path: &Path) -> Option<u32> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }
}

// --------------------------------------------------------- process control --

/// The signals `down` uses beyond its first polite request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escalate {
    /// Resume a stopped (SIGSTOP) process so it can act on the request to exit
    /// it already has pending. A no-op where processes cannot be stopped.
    Continue,
    /// End it now (SIGKILL; TerminateProcess on Windows).
    Kill,
}

#[cfg(unix)]
pub fn escalate(pid: u32, how: Escalate) -> std::io::Result<()> {
    let sig = match how {
        Escalate::Continue => libc::SIGCONT,
        Escalate::Kill => libc::SIGKILL,
    };
    if unsafe { libc::kill(pid as libc::pid_t, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub fn escalate(pid: u32, how: Escalate) -> std::io::Result<()> {
    match how {
        Escalate::Continue => Ok(()),
        Escalate::Kill => {
            let st = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?;
            if st.success() {
                Ok(())
            } else {
                Err(std::io::Error::other(format!("taskkill exited {st}")))
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn escalate(_pid: u32, _how: Escalate) -> std::io::Result<()> {
    Err(std::io::Error::other("cannot signal processes on this platform"))
}

/// Is `pid` stopped (SIGSTOP, a debugger, a terminal stop)? Some(true/false)
/// where the kernel says, None where this platform cannot tell. A stopped
/// process keeps its pid and its locks but runs nothing: it neither serves nor
/// exits when asked, which is why `status` and `up` must not call it running.
#[cfg(target_os = "linux")]
pub fn process_stopped(pid: u32) -> Option<bool> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The state is the first field after the parenthesised command name, which
    // may itself contain spaces or parentheses, so split at the LAST ')'.
    let state = stat.rsplit_once(')')?.1.split_whitespace().next()?;
    Some(matches!(state, "T" | "t"))
}

#[cfg(not(target_os = "linux"))]
pub fn process_stopped(_pid: u32) -> Option<bool> {
    None
}

/// Does `pid` name a process that has not exited? A zombie (exited, waiting to
/// be reaped) has exited. Unlike `process_exe_path` this works for a daemon
/// whose executable cannot be read (one run from a setcap'd binary is not
/// dumpable), which `down` must not mistake for gone.
#[cfg(target_os = "linux")]
pub fn process_exists(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !matches!(
            stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().next()),
            Some("Z" | "X") | None
        ),
        Err(_) => false,
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn process_exists(pid: u32) -> bool {
    // Signal 0 checks existence and permission without delivering anything;
    // EPERM still means the process exists.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn process_exists(pid: u32) -> bool {
    process_exe_path(pid).is_some()
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
        use std::os::unix::fs::FileTypeExt;
        let key = config_dir_key(config_dir);
        let uid = unsafe { libc::geteuid() };
        // Every short directory the socket may live in, in order of preference.
        // `/run/user/<uid>` is listed even when XDG_RUNTIME_DIR is not set,
        // because it is where XDG_RUNTIME_DIR points for a daemon started from
        // a login session or a user service, while `sudo`, cron and a bare ssh
        // command run without the variable.
        let mut bases: Vec<PathBuf> = Vec::new();
        if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if x.is_absolute() && x.is_dir() {
                bases.push(x);
            }
        }
        let run_user = PathBuf::from(format!("/run/user/{uid}"));
        if run_user.is_dir() && !bases.contains(&run_user) {
            bases.push(run_user);
        }
        bases.push(PathBuf::from("/tmp"));
        let candidates: Vec<PathBuf> = bases
            .into_iter()
            .map(|base| base.join(format!("tunlion-{uid}")).join(format!("{key}.sock")))
            .filter(|sock| sock.as_os_str().len() < SOCKET_PATH_MAX)
            .filter(|sock| {
                let dir = sock.parent().unwrap_or(Path::new("/"));
                !dir.exists() || private_dir_check(dir).is_ok()
            })
            .collect();
        // The daemon and its clients must MEET. A client whose environment
        // differs from the daemon's (XDG_RUNTIME_DIR set for one and not the
        // other) used to compute a different directory and report a healthy
        // daemon as "not responding" at a path that never existed. A socket
        // that already exists for THIS config (the name is this config dir's
        // key, so another config's socket can never match) is the one a daemon
        // bound; the newest wins when an old one lingers. With none, the first
        // candidate, which is where a starting daemon binds and creates it.
        let existing = candidates
            .iter()
            .filter_map(|sock| {
                let md = std::fs::symlink_metadata(sock).ok()?;
                md.file_type().is_socket().then(|| (md.modified().ok(), sock))
            })
            .max_by_key(|(mtime, _)| *mtime)
            .map(|(_, sock)| sock.clone());
        existing
            .or_else(|| candidates.first().cloned())
            .unwrap_or_else(|| preferred.to_path_buf())
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
/// writable by group or others. Root may use a directory another user owns: a
/// daemon run with sudo against that user's FILAMENT_CONFIG_DIR (the
/// `--shell-user` setup) binds its socket there, and root can already do
/// anything that user can.
#[cfg(unix)]
fn private_dir_check(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(dir)?;
    let uid = unsafe { libc::geteuid() };
    let owner_ok = meta.uid() == uid || uid == 0;
    if !meta.is_dir() || !owner_ok || meta.mode() & 0o022 != 0 {
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
