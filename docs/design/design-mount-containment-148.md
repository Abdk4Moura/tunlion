# Design: mount mutation containment (#148)

Status: design for review, no patch yet. No cargo run; branch only.
Scope: five mutating mount handlers in `cli/src/mount_proto.rs`.
Out of scope: the read path, already swept and clean; safe_open_beneath's
behavior, which must not change here.

## 1. The defect

`resolve()` at mount_proto.rs:713 is purely lexical. It collapses `..` textually
and checks `starts_with(root)`. It never touches the filesystem, so it cannot
see a symlink. The five mutating handlers then run raw `std::fs` on the resolved
absolute path, and the kernel resolves each component including any symlink:

    do_unlink    :828   std::fs::remove_file(&resolved)
    do_mkdir     :834   std::fs::create_dir(&resolved)
    do_rmdir     :845   std::fs::remove_dir(&resolved)
    do_rename    :852   std::fs::rename(&from_resolved, &to_resolved)
    do_truncate  :858   OpenOptions::write(true).open(&resolved) + set_len

A pre-existing symlink inside the share whose target is outside it is followed,
and the mutation lands outside the share root. The read-only gate at
handle_mount_request is not the fix: it is the security boundary for the scoped
default, and exposure requires a WRITE mount, which is the deliberate tier. The
fix must make "write inside this directory" actually mean that.

## 2. The primitive (Linux)

Use openat2 with RESOLVE_BENEATH on the PARENT, then a bare-name `*at` syscall
for the mutation.

The five operations split into two groups by whether they follow the FINAL
component:

- unlink, mkdir, rmdir, rename operate on a NAME. The final component is never
  followed: unlinkat removes a symlink itself, rmdir fails ENOTDIR on one,
  mkdirat creates a fresh entry, renameat moves the entry. So for these four,
  containment is entirely about the PARENT path. Resolve the parent to a dirfd
  the kernel guarantees is inside root, then act on the final name relative to
  it.
- truncate FOLLOWS the final component (you truncate the target). It must be
  handled like an open: `safe_open_beneath(root, rel, O_WRONLY, false)` then
  `file.set_len(size)`. This reuses the existing, tested primitive unchanged and
  inherits its behavior: on Linux RESOLVE_BENEATH returns EXDEV if any
  component (including the last) resolves outside the root; in-share symlinks
  still resolve, matching the mount path's `deny_symlinks=false` semantics.

New helper, one per platform (mirroring safe_open_beneath's three-arm split):

    #[cfg(unix)]
    fn resolve_parent_beneath(root, rel) -> io::Result<(OwnedFd, CString)>
    #[cfg(not(unix))]
    fn resolve_parent_beneath(root, rel) -> io::Result<(PathBuf, PathBuf)>

- Linux arm: split rel into parent + final name (empty parent = root itself).
  `openat2(parent_fd = O_DIRECTORY on root, parent, O_DIRECTORY | O_CLOEXEC,
  RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`. Same constants, same CString
  handling as safe_open_beneath. Returns the parent dirfd and the final name.
  Reject a final name that is "." or ".." (resolve() already collapses these,
  but the helper must not trust its caller).
- The four handlers then call:
    do_unlink   -> unlinkat(parent_fd, name, 0)
    do_rmdir    -> unlinkat(parent_fd, name, AT_REMOVEDIR)
    do_mkdir    -> mkdirat(parent_fd, name, mode), then
                   openat(parent_fd, name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW)
                   + fchmod(fd, mode) to apply the unmasked mode as today
                   (O_NOFOLLOW is safe: we just created the entry, it cannot
                   be a symlink; fchmod on the fd has no TOCTOU)
    do_rename   -> resolve_parent_beneath for BOTH from and to, then
                   renameat(from_dirfd, from_name, to_dirfd, to_name)
- libc 0.2 (already a dependency) exports unlinkat, mkdirat, renameat,
  fchmodat, AT_REMOVEDIR, O_NOFOLLOW on all unix targets. Confirmed at
  implementation compile time; no new dependency.

Why this and not the alternatives:

- canonicalize + starts_with: TOCTOU by construction. The attacker and the
  check race. This is precisely the property the fix exists to remove.
- openat2 on the FULL path for everything: there is no openat2 for
  unlink/mkdir/rmdir/rename. The kernel only gives RESOLVE_BENEATH on open.
  So the parent must be opened with RESOLVE_BENEATH and the mutation applied
  as a bare name relative to it. That is not a compromise, it is the only
  kernel-enforced shape these syscalls offer.
- A pure component walk with O_NOFOLLOW for everything: works and is what the
  non-Linux unix arm does, but on Linux openat2 allows in-share symlinks to
  keep resolving (mount semantics), which is strictly better than refusing all
  symlinks. Keep the platform split identical to safe_open_beneath's.

## 3. The non-Linux arms

The containment decision lives in ONE helper, `resolve_parent_beneath`. The
platform arms mirror safe_open_beneath exactly, so the codebase keeps one
established divergence shape instead of gaining a new one per handler.

- Other Unix (macOS): component walk with `openat(O_DIRECTORY|O_NOFOLLOW)`
  relative to the previous fd, exactly the loop in safe_open_beneath's
  not-linux arm but walking all-but-last components and returning the parent
  fd. O_NOFOLLOW on every step means this arm refuses ANY symlink, including
  in-share ones. That is stricter than Linux and documented as safe in the
  existing helper: never the reverse, so a link that resolves on macOS resolves
  on Linux, never the other way around.
- Non-Unix (Windows): return the canonicalized parent PathBuf via
  canonicalize + starts_with, and the handlers use std::fs on the canonical
  path. TOCTOU caveat documented, identical to safe_open_beneath's non-Unix
  arm. On Windows the live mount surface is WinFsp, not this FUSE handler
  path, so this arm is defense in depth, not the primary enforcement point.
  It keeps the parity check from drifting to nothing.

The drift control: there is exactly ONE place that decides "beneath or not"
per platform, and five callers use it. No handler re-derives a containment
decision. This is the same structure as safe_open_beneath (which had the .part
survive for four releases precisely because a check existed in one arm and not
the other): the split is platform-vs-platform, never call-site-vs-call-site.

## 4. safe_open_beneath is untouched

The .part writers and do_open/do_create call safe_open_beneath. This design
does not modify it, its signature, or its semantics. do_truncate becomes another
caller of it. That is the point of designing before patching: the last change
to this primitive fixed the mount path and broke the .part path in the same
commit, and the blast radius here is the same shared surface. A follow-up
(factor the beneath-walk into one shared internal used by both safe_open_beneath
and resolve_parent_beneath) is worth doing, but it must land with its own
green/red pair covering the .part path, not inside this fix.

## 5. Tests (RED first)

One test per op, `#[cfg(unix)]` (symlinks are unix-native). Each plants a
symlink inside the share pointing at a directory OUTSIDE it, calls the op
through handle_mount_request (the protocol entry, not the bare handler), and
asserts two things: the op returns MountResult::Err, and the outside state is
byte-for-byte unchanged.

Fixture:

    share/    <- the mount root
    outside/  <- a directory the share must never reach
    share/evil -> symlink to outside/
    outside/victim.txt   "AAAA" (4 bytes)

Calls (paths encoded with path_encode, as the protocol carries them):

    Unlink   { path: "evil/victim.txt" }       -> Err + victim.txt still exists
    MkDir    { path: "evil/newdir", mode }     -> Err + outside/newdir NOT created
    RmDir    { path: "evil/emptydir" }         -> Err + outside/emptydir still exists
    Rename   { from: "evil/a.txt", to: "renamed.txt" } -> Err + outside/a.txt
                                                  still exists, share/renamed.txt absent
    Truncate { path: "evil/victim.txt", size: 0 } -> Err + victim.txt length still 4

Pre-registered interpretation, so the green result cannot be read two ways:

- RED (no fix): each op returns Ok and mutates outside/. The outside-state
  assertions fail. This proves the test discriminates, not that it merely
  executes.
- GREEN (fix): each op returns Err and outside/ is untouched. The
  outside-state assertions are what prove refusal actually prevented the write,
  which is the property being bought.

Two discriminators the test must get right, or it will be green for the wrong
reason:

1. read_only MUST be false. The mutating gate (EROFS) refuses these ops for an
   unrelated reason; a test running with read_only=true would go red (fail) on
   the gate, not on the containment primitive, and its green after a fix would
   prove nothing. The test must exercise the WRITE tier, which is the tier the
   issue is about.
2. The outside-state assertion is the separating one. "Op returned Err" alone
   would pass even for a fix that refuses before mutating; it would also pass
   for a fix that mutates and then reports failure. Only "outside/ unchanged"
   distinguishes refusal that prevents the write from refusal that does not.

Tests live in the existing `#[cfg(test)] mod tests` in mount_proto.rs alongside
resolve_blocks_path_traversal. handle_mount_request is async, so they are
#[tokio::test], which the crate already uses elsewhere.

## 6. What changes, in one list

    + resolve_parent_beneath (3 cfg arms)
    rewrite do_unlink, do_mkdir, do_rmdir, do_rename to use it
    rewrite do_truncate to reuse safe_open_beneath + set_len
    + five RED-first containment tests
    unchanged: resolve(), safe_open_beneath, the read path, the read_only gate

## 7. Open items

- Confirm at implementation compile time that libc::AT_REMOVEDIR and
  libc::renameat exist on the macOS libc 0.2 in use (expected: yes).
- Whether the follow-up factoring of the shared beneath-walk is worth its own
  change. Not needed for #148 to be correct.
