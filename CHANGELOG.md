# Changelog

All notable, user-facing changes to filament are recorded here. This file was
started at the 0.7 capability cutover; earlier history lives in the git log and
the GitHub release notes.

## [0.7.2] - 2026-07-30

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
