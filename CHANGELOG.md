# Changelog

All notable, user-facing changes to filament are recorded here. This file was
started at the 0.7 capability cutover; earlier history lives in the git log and
the GitHub release notes.

## [0.7.6] - 2026-07-31

`shell` defaults to a native PTY, and file transfers stop spuriously rejecting
perfectly good files.

### Changed

- **`filament shell <device>` now opens filament's own native PTY by default**
  (the peer must run `up --shell`). Use `filament shell <device> --ssh` to run
  your real ssh over the data channel via ProxyCommand as before. The refined PTY
  engine (warm-link reuse, resumable reconnect, single shared stdin reader) is
  unchanged; only which command drives it changed.

### Fixed

- **Transfers no longer spuriously reject good files as "corrupt" (Linux).** The
  intermittent "received all bytes but whole-file checksum FAILED, refusing to
  accept a corrupt file" was never corrupted data: `safe_open_beneath` passed a
  non-NUL-terminated `&str` as the `openat2` pathname, so the kernel read past the
  name into adjacent memory and created the `.part` under a garbage-suffixed
  filename (mode 000). Verification then hashed the clean intended path, found
  nothing, and refused a byte-perfect file. Fixed by NUL-terminating the pathname
  (and setting the file mode only when creating). A cross-machine rig confirms the
  verify-failure rate drops from ~77% / ~89% to 0% on both transports, with the
  received bytes byte-identical to source every time. This was also the cause of
  intermittent `.part` symlink-refusal test flakiness.
- **A single bad `.part` no longer takes down the whole receive session.** A
  leftover `.part` from an interrupted transfer, or a common filename re-offered
  by another peer, made the fresh `O_EXCL` create return `EEXIST`, and that error
  unwound the entire receive loop, killing every other in-flight transfer.
  Restart-from-zero now replaces a stale partial, and a per-file open failure
  declines just that file instead of aborting the loop.
- **Remote file names are stripped of control bytes** before becoming a path, so
  a peer cannot embed a NUL (or other control characters) in an offered filename.

### Internal

- DataChannel now frames the absolute chunk offset like the QUIC transport, the
  reassembly coverage map is written by the writer after the bytes land (not as
  pre-write intent), completion gates on a contiguous byte range, and a contiguity
  guard reports the exact gap on any future regression instead of a bare digest
  mismatch. Concurrent coverage writers use `fetch_max` so a reordered store can
  never regress the received count.

## [0.7.5] - 2026-07-31

The command surface, finished: a clean ~15-verb CLI with no legacy names.

### Changed

- **Legacy commands are deleted, not aliased.** With no external users yet, the old names
  are simply gone (a deleted name errors with a "did you mean" suggestion): `ssh`/`pty` →
  `shell`; `netcat`/`dial` → `reach` (`--socks` for a proxy); `unexpose` → `expose --off`;
  `unmount` → `mount --off`; `cap-status`/`ping` → `status`/`doctor`; `get`/`unset` → `set`
  (`set <key>` shows, `set <key> <val>` sets, `set <key> --unset` clears); `introduce` →
  `devices vouch`; `serve-tun`/`tag-bind` removed. `filament --help` now lists exactly the
  real verbs, grouped (Connect / Share / Devices / Identity / Mesh). ~360 lines removed.

## [0.7.4] - 2026-07-31

Command-surface simplification and a genuinely useful `--help`, plus the
same-owner-devices "auto-detect" half of fleet trust.

### Changed

- **`filament --help` is now a grouped, curated command reference** (Connect / Share /
  Devices / Identity / Mesh) instead of a flat dump of every subcommand with deprecated
  and canonical names side by side. Each command still has its own `filament <cmd> --help`.
- **Simpler verbs:** `filament shell <device>` (folds `ssh`/`pty`), `filament reach
  <device>:<port>` (folds `netcat`/`dial`; `--socks` for a local proxy), `filament devices
  vouch <a> <b>` (folds `introduce`). All 13 old names keep working as deprecation aliases
  with a one-line note to stderr (suppress with `FILAMENT_NO_DEPRECATION=1`), so no
  existing script or muscle memory breaks.

### Added

- **Same-owner device auto-recognition (opt-in enforcement).** A genuine second device of
  your own (same user key, its own device key, your owner-signed cert) now reaches Proven
  and gets scoped auto-trust over direct, relay, AND reconnect — not just at your desk.
  Rig-verified cross-machine on all three paths. Enforcement stays opt-in
  (`FILAMENT_CAP_AUTHORITATIVE=1`).

### Fixed

- The Linux transfer-resume path no longer hangs if a FIFO is planted at the `.part` path
  (`O_NONBLOCK` on open; the non-regular-file refusal still applies).

### Notes

- Still landing (0.7.5): the `mint` wizard, `identity restore/rotate/guardians`,
  `devices promote`, and the `expose --off` / `mount --off` / `status`-absorbing folds.

## [0.7.3] - 2026-07-30

Release-engineering fixes for the 0.7.2 content. 0.7.2's release build failed on Windows
and its crates.io publish failed, so no 0.7.2 binaries or crates shipped; 0.7.3 carries
the same features and actually builds and publishes.

### Fixed

- **Windows build broke on the mount server.** `do_create` used `libc::O_CREAT | O_EXCL`
  without a cfg gate (introduced by the 0.7.2 transfer/mount symlink hardening), which
  does not compile on Windows where `libc` is absent. Gated the POSIX flags to Unix; the
  non-Unix `safe_open_beneath` fallback is used on Windows.
- **crates.io publish of the CLI failed to verify.** `filament-cap` gained new public API
  in this release (fleet-trust: `fleet_auto_trust`, `evaluate_grants_only`,
  `is_scoped_default_action`, and the shared delegated-ceiling helper) but was still
  `0.1.0` on crates.io and got skipped as already-published, so the CLI's publish
  verification built against a `filament-cap` that lacked those functions. Bumped
  `filament-cap` to `0.1.1` and the CLI's dependency pin to match, so the crate
  republishes and the CLI verifies against the API it actually uses.

## [0.7.2] - 2026-07-30 (release build failed on Windows; superseded by 0.7.3)

### Added

- **Fleet trust — the auth-key half: your own devices join with a minted key and
  just work, scoped.** Enroll a device with an ephemeral auth key and it becomes a
  Proven member of your fleet. Within scoped defaults it needs no per-capability
  grant: it can drop files in your inbox and reach the ports you've exposed. Opening
  a shell, writing to a mount, or reaching a port you did NOT expose stays the
  deliberate tier — an explicit grant, every time. Delegated enrollment reaches
  Proven over any transport (direct or relay). (Same-account "your devices find each
  other" auto-detection is not in this release; it is the next slice.)

### Security / Fixed

- **Fleet shell revocation now actually removes the SSH key.** The shell-key
  reconciler used the owner shortcut, so a same-owner (fleet) device was never listed
  as revoked and its managed `authorized_keys` block survived forever after you
  revoked its shell grant — permanent SSH on the one surface that bypasses every
  filament gate. It now tracks the grant exactly like an external device: revoke
  shell → key removed. Proven live via a fixed-vs-buggy binary differential.
- **Transfer scope is enforced against the real write target, not asserted.** The
  fleet transfer scope check was a dead binding; it now verifies the landing path is
  within the receiving directory, failing closed to grant-only if the sanitizer or
  the receive directory ever changes.
- **Transfer writes refuse symlinks and non-regular files (Unix).** Received `.part`
  files are created and resumed with symlink/FIFO/device refusal —
  `openat2`/`RESOLVE_BENEATH` on Linux, `O_NOFOLLOW` + a post-open `fstat` on other
  Unix — so a symlink or FIFO planted at the target cannot redirect a write. On
  Windows the resume path is not yet hardened (tracked as a follow-up); this
  protection is Unix-only in 0.7.2.
- **Shared the delegated-principal ceiling and the grant scan** between the two
  authorization paths so they cannot diverge (the recurring "two copies of a
  security check drift apart" bug class).

### Changed

- **Enrollment presence oracle closed in production.** The signaling server now
  handles `channel-goodbye` (unsubscribe without dropping the socket) on the Redis
  path. Deployed and verified live.
- **The mount scoped-default is not shipped yet.** A fleet device does not get an
  automatic read-only mount in this release: it is not drivable end-to-end yet, so
  its scope enforcement has never been exercised. Mount requires an explicit grant.
  It ships, rig-verified, with the same-account auto-detect slice.

### Notes

- Enforcement remains opt-in (`FILAMENT_CAP_AUTHORITATIVE=1`). Fleet auto-trust for
  the scoped defaults works in both shadow and authoritative mode.

## [0.7.1] - 2026-07-29

### Changed

- **Reverted the default-on capability flip: enforcement is opt-in again.** The
  0.7.0 default-on flip was premature. Real same-owner fleets show
  `flip_ready=false` (paired daemons aren't provisioned), so authoritative-by-
  default broke the owner's own ssh/transfer/mount until every capability was
  granted by hand. `cap_authoritative()` now defaults OFF (legacy shadow
  gating); enable enforcement explicitly with `FILAMENT_CAP_AUTHORITATIVE=1`
  (or `true`). Any other value, or leaving it unset, keeps shadow gating. The
  env var is now the opt-in switch, pending same-owner fleet-trust that makes a
  default-on flip safe. Everything else the 0.7.0 flip added (the self-genesis
  header, the restrictive gates, the shell-key reconciler) stays; only the
  default changed. See `docs/cap-flip-checklist.md`.

### Added

- **`filament reset`** — a conservative clean slate for the local machine.
  Wipes only filament's own state (identity + overlay keys, the paired-device
  store, the capability store, pending consent requests, exposed-service and
  mount records, per-peer + global settings, the managed ssh material) and
  strips the delimited `# BEGIN/END filament-managed <device>` blocks it
  installed in `~/.ssh/authorized_keys`. Your own ssh keys and any lines
  outside those blocks are never touched. Destructive: prompts for
  confirmation (required `-y`/`--yes` from a non-TTY) and refuses while the
  daemon is running (`filament down` first). Prints exactly what it removed.

### Fixed

- CLI ergonomics: `filament init` now hints `filament identity init`;
  `filament help` works as an alias for `--help`; `filament devices remove <x>`
  now suggests `forget` (the semantic match) instead of clap's `rename`; and
  the Windows managed-key install no longer leaks `icacls`' "Successfully
  processed 1 files" banner to stdout (captured, surfaced only on error).

## [0.7.0] - unreleased

### Changed

- **BREAKING: capability enforcement is now authoritative by default.** Devices
  without a matching grant are denied shell/transfer/mount. Opt out with
  `FILAMENT_CAP_AUTHORITATIVE=0` (shadow mode), which restores the previous
  legacy gating. The environment variable is the rollback: unset (or `=1`)
  keeps enforcement on, `=0`/`=false` turns it off. See
  `docs/cap-flip-checklist.md` for the evidence trail behind the flip.
  **(Reverted in 0.7.1 — see above.)**
