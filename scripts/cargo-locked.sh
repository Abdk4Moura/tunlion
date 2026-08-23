#!/usr/bin/env bash
# Serialize local Cargo work on the shared 4-core build host.
set -euo pipefail

LOCK_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/filament"
LOCK_FILE="$LOCK_DIR/cargo-build.lock"
STATUS_FILE="$LOCK_DIR/cargo-build.status"
# Release tests take minutes. Ten minutes permits ordinary queueing but fails
# before an outer test timeout can turn a wedged holder into an unattributed run.
WAIT_SECS="${FILAMENT_BUILD_LOCK_WAIT_SECS:-600}"

case "${1:-}" in
  metadata|locate-project|version|-V|--version)
    exec cargo "$@"
    ;;
esac

mkdir -p "$LOCK_DIR"
exec 9>"$LOCK_FILE"
if ! flock -w "$WAIT_SECS" 9; then
  holder="$(cat "$STATUS_FILE" 2>/dev/null || printf 'unknown holder')"
  printf 'build lock held by %s; waited %ss\n' "$holder" "$WAIT_SECS" >&2
  exit 75
fi

# Keep this shell's descriptor locked for Cargo's whole lifetime. Never unlink
# LOCK_FILE: flock is inode-based, so replacing it would permit split locks.
printf 'PID %s since %s: cargo %s\n' "$$" "$(date -Is)" "$*" >"$STATUS_FILE"
trap 'rm -f "$STATUS_FILE"' EXIT
cargo "$@"
