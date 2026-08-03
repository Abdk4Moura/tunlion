# `--shell-user` Permission Boundary

## Finding

On Unix, `--shell-user` is a real file-permission boundary for the current
config format. It is not a substitute for shell capability policy, but a
different ordinary account cannot read the owner's device keys merely because
it can traverse the config directory.

`runuser -l <user>` is selected by `cli/src/platform/mod.rs:107-113` when
`--shell-user` is set. The PTY therefore runs with the target user's Unix uid.

## Config Locations

`Paths::platform_config_dir` uses the `directories` crate
(`cli/src/platform/mod.rs:29-35`):

- Linux: `$XDG_CONFIG_HOME/filament`, falling back to `$HOME/.config/filament`.
- macOS: `$HOME/Library/Application Support/filament`.
- Windows: `%APPDATA%/filament`.
- `FILAMENT_CONFIG_DIR` overrides all three.

The daemon creates parent directories with ordinary `create_dir_all`, for
example in `devices_upsert_atomic` (`cli/src/main.rs:1468-1478`). No explicit
directory mode is set. Under the Linux default umask `0022`, a scratch config
directory was observed as `0755 root:root` when created by root. A root daemon's
normal `/root/.config/filament` ancestry is usually more restrictive because
`/root` itself is not traversable by ordinary users, but a custom
`FILAMENT_CONFIG_DIR` may be publicly traversable.

## Secret Files

Secret-bearing files are written through `SecretFile::write` or
`write_str`. The implementation creates temporary files with mode `0600` and
also applies `0600` after the atomic rename on Unix
(`crates/secret-write/src/lib.rs:22-32`, `:40-48`, `:56-76`). This covers the
device store, overlay key, authorized keys, and other callers that use
`SecretFile`.

The small plain-text `config` file is currently written with
`std::fs::write` (`cli/src/main.rs:1213-1226`), so under umask `0022` it was
observed as `0644`. It contains settings, not the device secret. This is not a
claim that every file in the directory is secret or unreadable.

## Scratch Verification

Using a disposable `/tmp` tree, with no daemon running, the observed modes were:

```text
0755 root:root config-directory
0644 root:root config
0600 root:root devices.json
0600 root:root overlay.ed25519
```

`nobody` could list the `0755` directory and read `config`, but reading
`devices.json` returned `Permission denied` (exit status 1). A second scratch
case created `devices.json` as `daemon:daemon` with `0600`; `nobody` again got
`Permission denied`. The exact command used was:

```sh
runuser -u nobody -- /bin/cat <scratch>/config/devices.json
```

The result was nonzero in both owner cases. No real Filament config or running
daemon was touched.

## Existing Installs

The writer fix does not change files that are never rewritten. A deployed
`caps.json` created by an older release can therefore remain `0644` indefinitely
even though new writes use `0600`; this was observed on the development box for
the file dated July 27. Startup now repairs the known-sensitive files and the
`peerconf` directory before command dispatch. It is idempotent and silent when
nothing changes, but emits one repair message when it changes any path. The
regression test creates a pre-existing `0644` file, then runs the repair and
asserts `0600`; it does not write the file through `SecretFile` first.

On Windows, startup reasserts the owner ACL on existing sensitive files via the
same `icacls` path used by `SecretFile`; the config directory is not made a
Unix-style mode boundary. `config` remains unclassified as a secret because it
contains settings only. `diag.jsonl` is repaired to owner-only access because
its fields include peer identifiers, session identifiers, phases, and roles.
That metadata discloses the owner's private peer topology and session history
under the trusted-group threat model. This may break workflows that tail
diagnostics as another user; operators should use an explicit log export or ACL
rather than silently expose the file world-readably.

## Deployment Cases

- Root `up` plus `--shell-user nobody`: effective for the keys. Root owns the
  `0600` files, and nobody cannot read them. If the default `/root` ancestry is
  intact, nobody cannot even traverse the default directory.
- Ordinary user `alice` plus `--shell-user bob`: effective for the keys. Bob
  cannot read Alice-owned `0600` files, even when a custom config directory is
  `0755` and listable.
- Root `up` plus no `--shell-user`: the PTY would run as root and is
  owner-equivalent, but startup now refuses unless the operator passes
  `--i-know`; the gate is `require_shell_owner_ack` in `cli/src/main.rs`.
- Any non-root `up` plus no `--shell-user`: the PTY still runs as that real user
  and is owner-equivalent for that account, so the same `--i-know` acknowledgement
  applies. Root is additionally machine-wide.
- Windows: `--shell-user` is unsupported. The platform code returns the normal
  shell argv and reports that another-user execution requires credentials or an
  elevated process (`cli/src/platform/mod.rs:95-121`). The Unix permission
  conclusion must not be presented as a Windows guarantee.

The mitigation is therefore genuine on Unix for current secret files, while
the broader shell grant remains a separate authorization decision. The
acknowledgement gate does not bound shell authority. Operators must still use
shell capability scoping and should not expose a custom config directory's
non-secret metadata as if it were protected.
