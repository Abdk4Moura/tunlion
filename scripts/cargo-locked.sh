#!/usr/bin/env bash
# Serialize local Cargo work on the shared 4-core build host.
set -euo pipefail

LOCK_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/filament"
LOCK_FILE="$LOCK_DIR/cargo-build.lock"
STATUS_FILE="$LOCK_DIR/cargo-build.status"
# Release tests take minutes. Ten minutes permits ordinary queueing but fails
# before an outer test timeout can turn a wedged holder into an unattributed run.
WAIT_SECS="${FILAMENT_BUILD_LOCK_WAIT_SECS:-600}"

# Find the subcommand, skipping a leading +toolchain and any leading flags.
# `case "$1"` alone was defeated by `cargo +nightly metadata` and
# `cargo --offline metadata`, which would then queue behind a build. That is the
# read-only deadlock this wrapper exists to avoid: gates.sh calls
# `cargo metadata` to discover its target dir, and blocking it would wedge the
# very script that needs the answer.
subcmd=""
for a in "$@"; do
  case "$a" in
    +*|-*) continue ;;
    *) subcmd="$a"; break ;;
  esac
done
case "$subcmd" in
  metadata|locate-project|version)
    exec cargo "$@"
    ;;
esac
case "${1:-}" in
  -V|--version) exec cargo "$@" ;;
esac

mkdir -p "$LOCK_DIR"
exec 9>"$LOCK_FILE"
if ! flock -w "$WAIT_SECS" 9; then
  holder="$(cat "$STATUS_FILE" 2>/dev/null || printf 'unknown holder')"
  # The EXIT trap below does NOT run on SIGKILL, and the incident that motivated
  # this wrapper was an OOM kill. So the holder file outlives a killed holder:
  # flock itself is fine, the kernel closes the FD and releases the lock, but the
  # message would name a PID that no longer exists. A false diagnostic during a
  # resource incident is worse than none, so check before reporting.
  holder_pid="$(printf '%s' "$holder" | sed -n 's/^PID \([0-9][0-9]*\).*/\1/p')"
  if [ -n "$holder_pid" ] && ! kill -0 "$holder_pid" 2>/dev/null; then
    holder="$holder [STALE: that process is gone; it was probably killed]"
  fi
  printf 'build lock held by %s; waited %ss\n' "$holder" "$WAIT_SECS" >&2
  exit 75
fi

# Keep this shell's descriptor locked for Cargo's whole lifetime. Never unlink
# LOCK_FILE: flock is inode-based, so replacing it would permit split locks.
printf 'PID %s since %s: cargo %s\n' "$$" "$(date -Is)" "$*" >"$STATUS_FILE"
trap 'rm -f "$STATUS_FILE"' EXIT
cargo "$@"
