//! Confinement for the receiving end of a transfer.
//!
//! The receiver never trusts a path from the wire. There are two separate
//! bounds, and both must hold before anything is created, renamed or deleted:
//!
//! * a relative name must be reduced by [`safe_relpath`] (no absolute, no
//!   `..`, no `.`, no control bytes, no backslash);
//! * the destination root must resolve under the daemon's drop directory by
//!   [`resolve_root`], and every write below it must stay under that root by
//!   [`bound_parent`].
//!
//! Lexical containment is not enough on its own. `path_within` is used where the
//! target may not exist yet, and it cannot see a symlinked DIRECTORY already
//! sitting inside the root: `root/sub -> /etc` makes `sub/passwd` a
//! lexically-clean path that writes outside. [`refuse_symlinked_ancestors`] and
//! the canonical probes in [`resolve_root`] / [`bound_parent`] close that hole,
//! and they run BEFORE `create_dir_all`, because a refusal issued after creation
//! leaves the directory already landed outside the root.
//!
//! This module is filesystem-local and has no opinion about the peer, the
//! transport, consent, or the UI. `peerloop::sync` calls [`resolve_root`] for
//! inbound admission; the CLI keeps the stateful protocol and the write/delete
//! helpers below.

use std::path::{Path, PathBuf};

/// Lexically normalize a path (resolve `.`/`..` without touching the FS) so a
/// scope check can't be defeated by `share/../../etc`. Returns the normalized
/// component vector.
fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component::*;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            ParentDir => {
                out.pop();
            }
            CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// True when `path`, lexically normalized, is within (or equal to) `root`. Used
/// to bound a fleet transfer landing path to the drop dir. A relative or
/// non-normalizable request fails closed (not within), so it falls through to
/// explicit-grant. LEXICAL is correct here because the landing path may not
/// exist yet (file about to be received); the actual symlink protection lives
/// in the safe-open primitives (`O_NOFOLLOW|O_EXCL`) at the write site and in
/// [`bound_parent`] for directories.
pub fn path_within(root: &Path, path: &Path) -> bool {
    let root_n = lexical_normalize(root);
    let path_n = lexical_normalize(path);
    !root_n.as_os_str().is_empty() && path_n.starts_with(&root_n)
}

/// True when `path`, canonicalized (symlinks resolved), is within `root`.
/// Used to bound a fleet mount REQUEST to the share root. Both paths must
/// exist on disk (canonicalize fails on non-existent paths). A symlink at
/// the mount root or requested path escaping the share root is refused.
pub fn path_within_canonical(root: &Path, path: &Path) -> bool {
    let Ok(root_c) = root.canonicalize() else {
        return false;
    };
    let Ok(path_c) = path.canonicalize() else {
        return false;
    };
    !root_c.as_os_str().is_empty() && path_c.starts_with(&root_c)
}

/// A relative path that cannot leave its root: no absolute, no `..`, no `.`,
/// no control bytes, no backslash. `None` means refuse.
pub fn safe_relpath(s: &str) -> Option<PathBuf> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    // Textual, not `Path::components()`: that normalizes an interior `.` away,
    // and a path the peer spelled with one is a path we refuse, not tidy.
    let mut out = PathBuf::new();
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        out.push(seg);
    }
    Some(out)
}

/// The receiver's manifest gate: every name in a manifest must survive
/// [`safe_relpath`]. A manifest carrying one unsafe name is refused as a whole,
/// before the receiver compares it with what is on disk or writes anything.
pub fn manifest_paths_are_bounded<'a>(paths: impl IntoIterator<Item = &'a str>) -> bool {
    paths.into_iter().all(|p| safe_relpath(p).is_some())
}

/// Bound the requested root to the drop directory: relative, or absolute under
/// it; every existing ancestor canonical-within before anything is created,
/// and the result canonical-within after. With `create` false (a dry run) a
/// missing root is returned as is and nothing touches the disk.
pub fn resolve_root(drop_dir: &Path, req: &str, create: bool) -> Result<PathBuf, String> {
    let outside = || "remote dir is outside this device's drop directory".to_string();
    let rel = match req.trim() {
        "" | "." => PathBuf::new(),
        r if Path::new(r).is_absolute() => {
            let inside = Path::new(r).strip_prefix(drop_dir).map_err(|_| outside())?;
            if inside.as_os_str().is_empty() {
                PathBuf::new()
            } else {
                safe_relpath(&inside.to_string_lossy()).ok_or_else(outside)?
            }
        }
        r => safe_relpath(r).ok_or_else(outside)?,
    };
    let target = drop_dir.join(&rel);
    if !path_within(drop_dir, &target) {
        return Err(outside());
    }
    let mut probe = target.clone();
    while !probe.exists() {
        probe = probe.parent().map(Path::to_path_buf).ok_or_else(outside)?;
    }
    if !path_within_canonical(drop_dir, &probe) {
        return Err(outside());
    }
    if !create && !target.exists() {
        return Ok(target);
    }
    create_content_dirs(drop_dir, &target).map_err(|e| format!("cannot create remote dir: {e}"))?;
    if !path_within_canonical(drop_dir, &target) {
        return Err(outside());
    }
    target.canonicalize().map_err(|e| e.to_string())
}

/// Refuse any symlinked component of `parent` below `root` (root itself is not
/// walked, so a root reached through a symlink stays legitimate). Shared by the
/// write path ([`bound_parent`]) and the delete path ([`delete_within`]).
///
/// REFUSE BEFORE CREATING. Every component of `parent` below `root` is checked
/// for symlinks before anything is created, because the checks below can only
/// report what they find: `create_dir_all` follows a symlinked parent, so a
/// refusal issued after it leaves the directory already landed outside the
/// root.
///
/// The predicate is `symlink_metadata` and `is_symlink`, deliberately NOT
/// canonicalize: Windows returns verbatim `\\?\` paths from canonicalize, so a
/// within-root decision built on it can miss on one platform while passing on
/// another.
pub fn refuse_symlinked_ancestors(root: &Path, parent: &Path) -> std::io::Result<()> {
    if let Ok(rel) = parent.strip_prefix(root) {
        let mut walked = root.to_path_buf();
        for c in rel.components() {
            walked.push(c.as_os_str());
            match std::fs::symlink_metadata(&walked) {
                Ok(md) if md.file_type().is_symlink() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("path escapes the remote dir: {walked:?} is a symlink"),
                    ));
                }
                Ok(_) => {}
                // Does not exist yet, so nothing below it can be a symlink either.
                Err(_) => break,
            }
        }
    }
    Ok(())
}

/// Create `parent` under `root`, refusing a symlinked ancestor. `path_within`
/// is LEXICAL, so it cannot see a symlinked DIRECTORY already sitting inside
/// the root: `root/sub -> /etc` makes `sub/passwd` a lexically-clean path that
/// writes outside, and [`safe_relpath`] cannot see it either (it only reads the
/// string). So bound the parent by canonical path the way [`resolve_root`]
/// bounds the root: every existing ancestor first, then the parent once it
/// exists. Nothing is written before both hold.
pub fn bound_parent(root: &Path, parent: &Path) -> std::io::Result<()> {
    refuse_symlinked_ancestors(root, parent)?;
    let mut probe = parent.to_path_buf();
    while !probe.exists() {
        probe = match probe.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path escapes the remote dir",
                ))
            }
        };
    }
    if !path_within_canonical(root, &probe) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path escapes the remote dir",
        ));
    }
    create_content_dirs(root, parent)?;
    if !path_within_canonical(root, parent) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path escapes the remote dir",
        ));
    }
    Ok(())
}

/// Remove `root/rel` for `sync --delete`, under the SAME containment rule the
/// writes use. `path_within` is lexical and `symlink_metadata` only looks at
/// the last component, so `root/sub -> /elsewhere` used to make `sub/f` a
/// deletable path that removed `/elsewhere/f`. Here every ancestor below the
/// root must exist and not be a symlink, the parent must canonicalize inside
/// the root, and the target itself must be a regular file (a symlink is never
/// followed). Creates nothing. Returns whether a file was removed.
pub fn delete_within(root: &Path, rel: &Path) -> bool {
    let target = root.join(rel);
    if !path_within(root, &target) {
        return false;
    }
    let Some(parent) = target.parent() else {
        return false;
    };
    if refuse_symlinked_ancestors(root, parent).is_err() {
        return false;
    }
    // A parent that does not exist holds nothing to delete.
    if !parent.is_dir() || !path_within_canonical(root, parent) {
        return false;
    }
    let is_file = std::fs::symlink_metadata(&target)
        .map(|md| md.is_file())
        .unwrap_or(false);
    is_file && std::fs::remove_file(&target).is_ok()
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
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("fil-transfer-bounds-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Directory symlinks, checked rather than assumed. Unix always supports
    /// them. Windows needs SeCreateSymbolicLinkPrivilege (or Developer Mode),
    /// which the Windows CI runner has; a failure there is a test failure, not
    /// a skip, or the Windows arm would silently stop covering the escape.
    /// Other platforms have no directory symlink and skip visibly.
    fn symlink_dir(target: &Path, link: &Path) -> Option<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
                .expect("unix must create a directory symlink for the escape arm");
            Some(())
        }
        #[cfg(windows)]
        {
            match std::os::windows::fs::symlink_dir(target, link) {
                Ok(()) => Some(()),
                Err(e) => panic!(
                    "Windows CI must create a directory symlink ({link:?} -> {target:?}): {e}. \
                     The Windows symlink arm would otherwise be skipped silently."
                ),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            eprintln!("note: this platform has no directory symlinks; symlink escape arm skipped");
            None
        }
    }

    #[test]
    fn relpaths_that_could_escape_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../b",
            "./a",
            "a/./b",
            "a/",
            "a//b",
            "a\\b",
            "a\0b",
        ] {
            assert!(safe_relpath(bad).is_none(), "{bad:?}");
        }
        assert_eq!(
            safe_relpath("a/b/c.txt").unwrap(),
            PathBuf::from("a/b/c.txt")
        );
    }

    /// This is the receiver's actual manifest gate (`manifest_paths_are_bounded`,
    /// called from `serve_sync`), not just `safe_relpath` in isolation: one
    /// unsafe name refuses the whole manifest before anything is written.
    #[test]
    fn every_manifest_name_must_survive_the_manifest_gate() {
        let good = ["docs/a.txt", "photos/2026/one.jpg"];
        assert!(manifest_paths_are_bounded(good));
        for bad in [
            "docs/../../etc/passwd",
            "/etc/passwd",
            "docs/a\\b",
            "docs//a",
        ] {
            assert!(
                !manifest_paths_are_bounded(["docs/a.txt", bad]),
                "a manifest carrying {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn remote_root_is_bounded_to_the_drop_dir() {
        let d = tmp("root");
        assert_eq!(resolve_root(&d, "dry", false).unwrap(), d.join("dry"));
        assert!(!d.join("dry").exists(), "a dry run creates nothing");
        assert_eq!(
            resolve_root(&d, "inbox/photos", true).unwrap(),
            d.join("inbox/photos").canonicalize().unwrap()
        );
        assert_eq!(
            resolve_root(&d, "", true).unwrap(),
            d.canonicalize().unwrap()
        );
        assert_eq!(
            resolve_root(&d, &d.join("abs").to_string_lossy(), true).unwrap(),
            d.join("abs").canonicalize().unwrap()
        );
        for bad in ["../out", "/etc", "a/../../b"] {
            assert!(resolve_root(&d, bad, true).is_err(), "{bad}");
            assert!(resolve_root(&d, bad, false).is_err(), "{bad}");
        }
        let escape = tmp("root-escape");
        if symlink_dir(&escape, &d.join("esc")).is_some() {
            assert!(
                resolve_root(&d, "esc/x", true).is_err(),
                "symlink escape must be refused"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&escape);
    }

    /// Absolute requests are accepted only when they are already under the drop
    /// dir; relative requests resolve beneath it. A dry run still creates
    /// nothing, and a sibling with a similar name is not inside.
    #[test]
    fn absolute_and_relative_requests_share_the_drop_dir_bound() {
        let d = tmp("absrel");
        std::fs::create_dir_all(d.join("inbox")).unwrap();
        let by_relative = resolve_root(&d, "inbox", true).unwrap();
        let by_absolute = resolve_root(&d, &d.join("inbox").to_string_lossy(), true).unwrap();
        assert_eq!(by_relative, by_absolute);
        assert_eq!(by_relative, d.join("inbox").canonicalize().unwrap());
        assert!(resolve_root(&d, &d.join("inbox").to_string_lossy(), false).is_ok());
        // Another child of the drop dir is still inside.
        assert!(resolve_root(&d, &d.join("inbox-evil").to_string_lossy(), true).is_ok());
        // A sibling directory whose NAME begins with the drop dir's name is not.
        let sibling = d.with_file_name(format!(
            "{}-sibling",
            d.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&sibling).unwrap();
        assert!(resolve_root(&d, &sibling.to_string_lossy(), true).is_err());
        assert!(!sibling.join("x").exists());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&sibling);
    }

    /// Lexical containment accepts a non-existent landing inside the drop dir
    /// (the file is about to be written) and refuses a relative request against
    /// an absolute root. Canonical containment additionally refuses a link that
    /// leaves the root.
    #[test]
    fn lexical_and_canonical_bounds_hold() {
        let root = tmp("lexroot");
        let docs = root.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("a.txt"), b"test").unwrap();
        let outside = tmp("lex-outside");

        assert!(path_within(&root, &root));
        assert!(path_within(&root, &docs.join("a.txt")));
        assert!(!path_within(&root, &outside));
        assert!(!path_within(&root, Path::new("/")));
        assert!(!path_within(&root, Path::new("tunlion-share")));

        assert!(path_within_canonical(&root, &root));
        assert!(path_within_canonical(&root, &docs));
        assert!(!path_within_canonical(&root, &outside));
        if symlink_dir(&outside, &root.join("evil")).is_some() {
            assert!(path_within(&root, &root.join("evil")), "lexically inside");
            assert!(
                !path_within_canonical(&root, &root.join("evil")),
                "canonical check must refuse the escaping link"
            );
        } else {
            eprintln!("note: this platform would not create a symlink; the escape arm is skipped");
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// `safe_relpath` reads a string and `path_within` is lexical, so neither
    /// can see a symlinked DIRECTORY planted inside the root. `bound_parent` is
    /// what refuses it, and this is the case that proves it: `sub` is a clean
    /// relative segment and `sub/x` a clean relative path, yet it resolves out.
    #[test]
    fn a_symlinked_parent_inside_the_root_cannot_be_written_through() {
        let root = tmp("bound");
        let out = tmp("bound-outside");
        std::fs::create_dir_all(root.join("real/deep")).unwrap();
        assert!(bound_parent(&root, &root.join("real/deep")).is_ok());
        // A parent that does not exist yet is created, and stays inside.
        assert!(bound_parent(&root, &root.join("fresh/deeper")).is_ok());
        assert!(root.join("fresh/deeper").is_dir());
        assert!(
            safe_relpath("sub/x").is_some(),
            "the string itself is clean"
        );
        if symlink_dir(&out, &root.join("sub")).is_some() {
            assert!(path_within(&root, &root.join("sub/x")), "lexically inside");
            assert!(
                bound_parent(&root, &root.join("sub")).is_err(),
                "a symlinked parent must be refused"
            );
            assert!(
                bound_parent(&root, &root.join("sub/x")).is_err(),
                "and so must a path under it"
            );
            // The assertion that discriminates is on the file BELOW the symlink, not on the
            // target directory itself: `tmp()` already created the target, so asserting that
            // the target does not exist tests the fixture rather than the product. On Windows
            // the pre-fix code created `x` here (its first check is defeated by canonicalize's
            // verbatim paths) and this is the assertion that caught it, while on Unix the old
            // canonical re-check already refused before creating anything below the symlink.
            assert!(
                !out.join("x").exists(),
                "nothing was created outside the root"
            );
        } else {
            eprintln!("note: this platform would not create a symlink; the symlinked-parent arm is skipped");
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&out);
    }

    /// `sync --delete` must use the same containment as the writes: a
    /// symlinked directory inside the root pointing outside is not a way to
    /// delete files outside it.
    #[test]
    fn delete_does_not_follow_a_symlinked_dir_out_of_the_root() {
        let root = tmp("del");
        let out = tmp("del-outside");
        std::fs::write(out.join("victim"), b"keep me").unwrap();
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::write(root.join("real/gone"), b"x").unwrap();
        assert!(
            delete_within(&root, Path::new("real/gone")),
            "a plain file inside is deleted"
        );
        assert!(!root.join("real/gone").exists());
        assert!(
            !delete_within(&root, Path::new("missing/f")),
            "nothing to delete, nothing created"
        );
        assert!(!root.join("missing").exists());
        assert!(
            !delete_within(&root, Path::new("../victim")),
            "a traversal name is refused before the filesystem"
        );
        if symlink_dir(&out, &root.join("sub")).is_some() {
            assert!(
                path_within(&root, &root.join("sub/victim")),
                "lexically inside"
            );
            assert!(
                !delete_within(&root, Path::new("sub/victim")),
                "a symlinked parent must be refused"
            );
            assert_eq!(
                std::fs::read(out.join("victim")).unwrap(),
                b"keep me",
                "the outside file survives"
            );
        } else {
            eprintln!("note: this platform would not create a symlink; the symlinked-parent arm is skipped");
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&out);
    }
}
