//! Directory-relative ("*at") filesystem primitives for the mount server.
//!
//! The mount server resolves a peer-supplied path LEXICALLY (`resolve`), which
//! cannot see a symlink. Anything that then acts on the resulting absolute path
//! by name follows a symlink planted inside the share to wherever it points.
//! The mutating handlers already avoid that by opening the PARENT to a dirfd
//! the kernel keeps beneath the root and acting on the bare final name. These
//! are the read-side and metadata counterparts: stat, readlink and readdir
//! that never follow the final component and never re-resolve a path.
//!
//! Both arms live here, per docs/architecture/PLATFORM.md. On unix the parent
//! is an `OwnedFd` and the name a `CStr`; on other platforms (where the live
//! mount surface is WinFsp, so this is defense in depth) the parent is a
//! canonicalized directory path and the name a plain path, mirroring
//! `mount_proto::resolve_parent_beneath`.

use std::path::{Path, PathBuf};

/// Metadata of one entry, read WITHOUT following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtMeta {
    pub ino: u64,
    pub size: u64,
    /// Full `st_mode` (type bits included) on unix; synthesized elsewhere.
    pub mode: u32,
    pub mtime: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Metadata for the share root itself. The root is chosen by the owner, not
/// the peer, so following it (it may legitimately be reached via a symlink) is
/// correct here and nowhere else.
pub fn stat_root(root: &Path) -> std::io::Result<AtMeta> {
    let meta = std::fs::metadata(root)?;
    Ok(from_std(&meta, root))
}

/// The open-flag bits beyond the access mode that create or modify data:
/// O_CREAT, O_TRUNC, O_APPEND and O_TMPFILE. A read-only share must refuse an
/// open carrying any of them even when the access mode is O_RDONLY (Linux
/// truncates on `O_RDONLY|O_TRUNC` for a file the server can write).
pub fn open_flags_modify(flags: i32) -> bool {
    #[cfg(unix)]
    {
        if flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0 {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            // O_TMPFILE includes the O_DIRECTORY bit, so require the full value.
            if flags & libc::O_TMPFILE == libc::O_TMPFILE {
                return true;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        // No native POSIX flags here; the wire carries the client's (Linux)
        // values, so test those: O_CREAT 0o100, O_TRUNC 0o1000, O_APPEND
        // 0o2000, __O_TMPFILE 0o20000000.
        flags & (0o100 | 0o1000 | 0o2000 | 0o20000000) != 0
    }
}

/// `flags` plus the platform's O_CREAT|O_EXCL, for an exclusive create.
pub fn create_excl_flags(flags: i32) -> i32 {
    #[cfg(unix)]
    {
        flags | libc::O_CREAT | libc::O_EXCL
    }
    #[cfg(not(unix))]
    {
        // safe_open_beneath's non-unix arm does not consume POSIX creation
        // flags (Windows mounts go through WinFsp).
        flags
    }
}

/// Apply a peer-requested mode to a file we just created, THROUGH THE HANDLE
/// (fchmod, never a path that could have been swapped), keeping only the
/// permission bits: setuid, setgid and sticky are never granted by a peer.
pub fn set_mode_via_handle(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
        Ok(())
    }
}

/// The uid reported for every entry (the serving user).
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// The gid reported for every entry (the serving user's group).
pub fn current_gid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getgid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn from_std(meta: &std::fs::Metadata, path: &Path) -> AtMeta {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        AtMeta {
            ino: meta.ino(),
            size: meta.len(),
            mode: meta.mode(),
            mtime,
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
        }
    }
    #[cfg(not(unix))]
    {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut h);
        AtMeta {
            ino: h.finish(),
            size: meta.len(),
            mode: if meta.is_dir() { 0o40755 } else { 0o100644 },
            mtime,
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
        }
    }
}

// ------------------------------------------------------------------ unix --

#[cfg(unix)]
fn from_stat(st: &libc::stat) -> AtMeta {
    let mode = st.st_mode as u32;
    let fmt = mode & (libc::S_IFMT as u32);
    AtMeta {
        ino: st.st_ino as u64,
        size: st.st_size.max(0) as u64,
        mode,
        mtime: st.st_mtime.max(0) as u64,
        is_dir: fmt == libc::S_IFDIR as u32,
        is_symlink: fmt == libc::S_IFLNK as u32,
    }
}

#[cfg(unix)]
fn fstatat_nofollow(dirfd: std::os::fd::RawFd, name: &std::ffi::CStr) -> std::io::Result<AtMeta> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(from_stat(&st))
}

/// lstat of `name` relative to the contained parent dirfd.
#[cfg(unix)]
pub fn lstat_at(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<AtMeta> {
    use std::os::fd::AsRawFd;
    fstatat_nofollow(parent.as_raw_fd(), name)
}

/// readlink of `name` relative to the contained parent dirfd. The link is
/// read, never followed; its target is returned verbatim, as before.
#[cfg(unix)]
pub fn readlink_at(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; 1024];
    loop {
        let n = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)));
        }
        // Possibly truncated: grow, bounded (PATH_MAX is 4096 on Linux, 1024 on
        // Darwin; 64 KiB is far past any real link).
        if buf.len() >= 64 * 1024 {
            return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        let grown = buf.len() * 2;
        buf.resize(grown, 0);
    }
}

/// List the directory behind an OPEN handle (one opened beneath the root),
/// with each entry's metadata read relative to that same handle. Never goes
/// back to a path, so swapping the directory for a symlink after it was
/// opened changes nothing. `.` and `..` are omitted, like `std::fs::read_dir`.
#[cfg(unix)]
pub fn read_dir_handle(
    dir: &std::fs::File,
    _path: &Path,
) -> std::io::Result<Vec<(std::ffi::OsString, Option<AtMeta>)>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    // fdopendir takes ownership of the fd, so hand it a duplicate. The dup
    // shares the file offset with the handle, so rewind before reading: every
    // ReadDir lists the whole directory, the same as the path-based version.
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dp = unsafe { libc::fdopendir(fd) };
    if dp.is_null() {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    unsafe { libc::rewinddir(dp) };
    let mut out = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(dp) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let meta = fstatat_nofollow(dir.as_raw_fd(), name).ok();
        out.push((std::ffi::OsStr::from_bytes(bytes).to_os_string(), meta));
    }
    unsafe { libc::closedir(dp) };
    Ok(out)
}

// -------------------------------------------------------------- non-unix --

/// lstat of `name` inside the canonicalized, contained parent directory.
#[cfg(not(unix))]
pub fn lstat_at(parent: &Path, name: &Path) -> std::io::Result<AtMeta> {
    let p = parent.join(name);
    let meta = std::fs::symlink_metadata(&p)?;
    Ok(from_std(&meta, &p))
}

/// readlink of `name` inside the canonicalized, contained parent directory.
#[cfg(not(unix))]
pub fn readlink_at(parent: &Path, name: &Path) -> std::io::Result<PathBuf> {
    std::fs::read_link(parent.join(name))
}

/// List a directory. Without dirfds this falls back to the path the handle
/// was opened from (WinFsp is the live mount surface on Windows).
#[cfg(not(unix))]
pub fn read_dir_handle(
    _dir: &std::fs::File,
    path: &Path,
) -> std::io::Result<Vec<(std::ffi::OsString, Option<AtMeta>)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(path)? {
        let e = e?;
        let p = e.path();
        let meta = std::fs::symlink_metadata(&p).ok().map(|m| from_std(&m, &p));
        out.push((e.file_name(), meta));
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fil-fsat-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn dirfd(p: &Path) -> std::os::fd::OwnedFd {
        std::fs::File::open(p).unwrap().into()
    }

    #[test]
    fn lstat_and_readlink_do_not_follow_the_final_component() {
        let d = tmp("lstat");
        std::fs::write(d.join("f"), b"hello").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("l")).unwrap();
        let fd = dirfd(&d);
        let f = lstat_at(&fd, c"f").unwrap();
        assert!(!f.is_dir && !f.is_symlink);
        assert_eq!(f.size, 5);
        let l = lstat_at(&fd, c"l").unwrap();
        assert!(l.is_symlink, "the link itself, not /etc/passwd");
        assert_eq!(l.size, "/etc/passwd".len() as u64);
        assert_eq!(readlink_at(&fd, c"l").unwrap(), PathBuf::from("/etc/passwd"));
        assert!(readlink_at(&fd, c"f").is_err(), "a regular file is not a link");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn read_dir_handle_lists_the_opened_dir_and_lstats_entries() {
        let d = tmp("rd");
        std::fs::write(d.join("a"), b"1").unwrap();
        std::fs::create_dir(d.join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc", d.join("ln")).unwrap();
        let h = std::fs::File::open(&d).unwrap();
        for _ in 0..2 {
            // Twice: the second listing must rewind, not come back empty.
            let mut got = read_dir_handle(&h, &d).unwrap();
            got.sort_by(|a, b| a.0.cmp(&b.0));
            let names: Vec<_> = got.iter().map(|(n, _)| n.to_string_lossy().into_owned()).collect();
            assert_eq!(names, ["a", "ln", "sub"]);
            assert!(got[1].1.unwrap().is_symlink, "ln is reported as a link, not /etc");
            assert!(got[2].1.unwrap().is_dir);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn set_mode_via_handle_strips_setuid_setgid_sticky() {
        let d = tmp("mode");
        let p = d.join("f");
        let f = std::fs::File::create(&p).unwrap();
        set_mode_via_handle(&f, 0o7755).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777, 0o755);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn modifying_open_flags_are_recognized() {
        assert!(!open_flags_modify(libc::O_RDONLY));
        assert!(open_flags_modify(libc::O_RDONLY | libc::O_TRUNC));
        assert!(open_flags_modify(libc::O_RDONLY | libc::O_CREAT));
        assert!(open_flags_modify(libc::O_RDONLY | libc::O_APPEND));
        assert!(!open_flags_modify(libc::O_RDONLY | libc::O_DIRECTORY));
    }
}
