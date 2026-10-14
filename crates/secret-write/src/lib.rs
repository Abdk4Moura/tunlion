//! Write secret data with platform-appropriate restrictive permissions.
//!
//! Carved out of `cli/src/platform/mod.rs` so every trust crate shares one
//! byte-identical secret writer. Pure `std` + `std::process::Command`; no app
//! coupling and no `windows` crate (the DACL path shells out to `icacls`).

use std::io::{self, Write};
use std::path::Path;

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
            create_private_dir_all(parent)?;
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
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
        }
        Ok(())
    }

    /// Atomic write: write to temp file, fsync, then rename over original.
    /// This prevents data loss on ENOSPC/crash - either old file or new file,
    /// never a truncated/empty file.
    fn write_raw(path: &Path, data: &[u8]) -> io::Result<()> {
        let dir = path.parent().unwrap_or(std::path::Path::new("."));
        let temp = dir.join(format!("{}.tmp.{}", path.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
        // Write to temp file. ANY failure from here on removes the temp: a write
        // that hit ENOSPC used to leave `config.tmp.<pid>` (and the same for
        // armed.json, devices.json) behind forever, eating the very space whose
        // absence caused the failure.
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let written = opts.open(&temp).and_then(|mut f| {
                f.write_all(data)?;
                f.sync_all()
            });
            if let Err(e) = written {
                let _ = std::fs::remove_file(&temp);
                return Err(e);
            }
        }
        // Atomic rename over original.
        //
        // WINDOWS NEEDS A RETRY and POSIX does not. On POSIX rename(2) onto an
        // existing path is atomic and succeeds even while other processes hold
        // the old inode open. On Windows the call fails outright if ANY handle
        // is open on the destination, and a handle appears there routinely and
        // briefly: the indexer, a virus scanner, or a reader that has not yet
        // been dropped. The result is a write that looks like it landed and did
        // not, which is how #349 presented -- a value not visible to the very
        // next read, on Windows only, on the second write of a file rather than
        // the first, because the first has no destination to replace.
        //
        // Bounded and short: five attempts over ~100ms, then surface the real
        // error. This never loops on POSIX because the first attempt succeeds.
        let mut last = match std::fs::rename(&temp, path) {
            Ok(()) => return Self::fsync_parent(path),
            Err(e) => e,
        };
        for backoff_ms in [5u64, 10, 25, 50] {
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            match std::fs::rename(&temp, path) {
                Ok(()) => return Self::fsync_parent(path),
                Err(e) => last = e,
            }
        }
        let _ = std::fs::remove_file(&temp);
        return Err(last);
    }

    /// Best-effort parent-directory fsync, for crash durability of the rename.
    fn fsync_parent(path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::OpenOptions::new().read(true).open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// Create `dir` and any missing parents owner-only (0700) regardless of the
/// umask. `create_dir_all` lets the umask decide, so under `umask 0000` the
/// directory holding a secret came out world-writable, and anyone could replace
/// the file inside it. Directories that already exist are left as they are.
fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
                Ok(()) => {
                    // A umask can strip bits from the requested mode; say it outright.
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && p.is_dir() => {}
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

/// Resolve the current process's user SID from the access token.
///
/// We deliberately do NOT use the `%USERNAME%` env var: in a Windows SERVICE
/// context (LocalSystem, a machine account, or any non-interactive logon)
/// USERNAME is frequently absent, so keying the ACL off it makes
/// `restrict_dacl` fail for a reason unrelated to key exposure. Even when set,
/// a display name is locale- and rename-fragile.
///
/// `whoami /user` reads the calling process's token directly (the same
/// TokenUser SID an interactive user would get), is present on every supported
/// Windows SKU, and needs no added dependency, so it works identically whether
/// tunlion runs interactively or as a service. Fail-closed: if no SID can be
/// parsed we return Err (the caller fails loud) rather than guessing a
/// principal.
#[cfg(windows)]
fn current_user_sid() -> io::Result<String> {
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to run whoami: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("whoami /user failed with exit code {:?}", out.status.code()),
        ));
    }
    // Output is one CSV row, no header: "DOMAIN\\user","S-1-5-21-...".
    // Extract the SID token (well-known `S-1-...` form) by scanning fields
    // rather than trusting exact quoting/positions across locales. A SID
    // contains only 'S', digits, and '-', so it is isolated cleanly by
    // splitting on comma / quote / whitespace.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let sid = stdout
        .split(|c: char| c == ',' || c == '"' || c.is_whitespace())
        .find(|tok| tok.starts_with("S-1-"));
    match sid {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("could not parse a user SID from whoami output: {:?}", stdout.trim()),
        )),
    }
}

#[cfg(windows)]
fn restrict_dacl(path: &Path) -> io::Result<()> {
    // Grant to the current user's SID (from the process token), NOT %USERNAME%.
    // icacls accepts a raw SID via the `*S-1-...` syntax, which is the
    // canonical, service-safe, locale-independent principal.
    let sid = current_user_sid()?;
    let path_str = path.display().to_string();
    // Capture (not inherit) icacls' stdout: even with `/Q` it prints the noisy
    // "Successfully processed 1 files; Failed processing 0 files" banner to the
    // parent's stdout, which leaks into every managed-key install. Buffer it and
    // only surface the output when the call actually fails.
    let out = std::process::Command::new("icacls")
        .args([&path_str, "/inheritance:r", "/grant:r", &format!("*{sid}:(F)"), "/Q"])
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failed to run icacls: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "icacls failed with exit code {:?}: {}{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim(),
            ),
        ));
    }
    Ok(())
}
