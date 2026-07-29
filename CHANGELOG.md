# Changelog

All notable, user-facing changes to filament are recorded here. This file was
started at the 0.7 capability cutover; earlier history lives in the git log and
the GitHub release notes.

## [0.7.0] - unreleased

### Changed

- **BREAKING: capability enforcement is now authoritative by default.** Devices
  without a matching grant are denied shell/transfer/mount. Opt out with
  `FILAMENT_CAP_AUTHORITATIVE=0` (shadow mode), which restores the previous
  legacy gating. The environment variable is the rollback: unset (or `=1`)
  keeps enforcement on, `=0`/`=false` turns it off. See
  `docs/cap-flip-checklist.md` for the evidence trail behind the flip.
