# Changelog

All notable, user-facing changes to filament are recorded here. This file was
started at the 0.7 capability cutover; earlier history lives in the git log and
the GitHub release notes.

## [0.7.1] - unreleased

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
