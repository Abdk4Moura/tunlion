# authkeys-managed

Safely maintain a **managed block** inside `~/.ssh/authorized_keys` — add, update,
and remove keys your program controls without ever disturbing the keys a human put
there.

Editing `authorized_keys` by hand from software is a classic footgun: it is easy to
clobber a user's own keys, follow a symlink, or leave the file world-readable and
have `sshd` silently ignore it. This crate confines your program to a clearly
delimited, per-owner block and leaves everything outside it byte-for-byte untouched.

- **Delimited block** — begin/end markers per managed owner; only lines between the
  markers are ever rewritten.
- **Non-destructive** — unmanaged keys are preserved exactly; removing your block
  leaves the rest of the file intact.
- **Cross-platform, permission-aware** — writes with the right restrictive
  permissions (shares [`secret-write`](https://crates.io/crates/secret-write)).

Extracted from [filament](https://github.com/Abdk4Moura/filament), where it backs
the capability layer's SSH-key reconciler (grant shell → key added, revoke → key
removed).

## Status

Pre-1.0; API may change between minor versions. Security-reviewed, not independently
audited.

## License

MIT
