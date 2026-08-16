#!/usr/bin/env bash
# #235: a revoked certificate must stop an ALREADY-ESTABLISHED mount.
# Standalone, hermetic, fixture port 8106 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./mount-revoke-gates.sh
#
# The property is bounded staleness, not immediacy. The server re-asks the gate
# every recheck interval, so the gate allows a grace period and then requires the
# access to be gone.
#
# Gates:
#   A  a live mount serves before the revoke         (positive control)
#   A2 a healthy mount survives its own recheck       (no-revoke control)
#   B  a file created AFTER the revoke is NOT readable through that same mount
#   C  the mount stops serving entirely within the bound
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8106
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-mount-revoke.XXXXXX")"
DA="$WORK/A"
GRACE=12   # > REVOKE_RECHECK, with slack for a slow box

source "$HERE/lib/fixture.sh"

# Mount needs a FUSE daemon that must be killed BEFORE the backend/acceptor, or a
# wedged mountpoint leaves processes in D state and fusermount returns EBUSY.
MOUNT_PID=""
cleanup() {
  [ -n "$MOUNT_PID" ] && kill "$MOUNT_PID" 2>/dev/null
  sleep 1
  fusermount3 -uz "$WORK/mnt" 2>/dev/null || fusermount -uz "$WORK/mnt" 2>/dev/null
  fixture_cleanup
}
trap cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow mount

mkdir -p "$WORK/share"
echo "written before the revoke" > "$WORK/share/before.txt"

# ===================================================================== GATE A ==
say "mount-revoke gate A"
env FILAMENT_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" mount alpha "$WORK/share" "$WORK/mnt" \
    >"$WORK/mount.log" 2>&1 &
MOUNT_PID=$!; FIX_PIDS+=("$MOUNT_PID")
for _ in $(seq 1 40); do timeout 5 ls "$WORK/mnt" >/dev/null 2>&1 && break; sleep 0.5; done
BEFORE=$(fs_bounded 10 cat "$WORK/mnt/before.txt")
echo "## read before revoke: $BEFORE"
if [ "$BEFORE" = "written before the revoke" ]; then
  ok "gateA: the live mount serves before the revoke"
else
  bad "gateA: mount never established, the rest proves nothing"
  echo "-- mount.log --"; tail -5 "$WORK/mount.log"
  echo; echo "==========================================="
  echo "mount-revoke gates: $PASS passed, $FAIL failed --$FAILED"
  echo "work: $WORK"
  exit 1
fi

# ==================================================================== GATE A2 ==
# The recheck's OTHER half: a healthy mount must survive its own recheck, or a
# fix that closed every session on the first recheck would score green here.
say "mount-revoke gate A2"
sleep 8
STILLOK=$(fs_bounded 15 cat "$WORK/mnt/before.txt"); stA2="$(fs_state)"
echo "## read past the recheck, not revoked: [$stA2] $STILLOK"
if [ "$STILLOK" = "written before the revoke" ]; then
  ok "gateA2: a healthy mount survives a recheck cycle (no false close)"
else
  bad "gateA2: the recheck closed a mount that was NOT revoked"
fi

# ===================================================================== GATE B ==
# The discriminator. A file that did not exist at revoke time cannot come from
# any cache, so reading it proves the data plane is still live.
say "mount-revoke gate B"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
echo "written AFTER the revoke" > "$WORK/share/after.txt"
sleep "$GRACE"
AFTER=$(fs_bounded 15 cat "$WORK/mnt/after.txt"); stB="$(fs_state)"
echo "## read after revoke (${GRACE}s): [$stB] $AFTER"
if [ "$AFTER" = "written AFTER the revoke" ]; then
  bad "gateB: a revoked peer read a file created AFTER the revoke"
elif [ "$stB" = "wedged" ]; then
  bad "gateB: the read did not return data, but the client WEDGED (no denial reached it)"
else
  ok "gateB: a file created after the revoke is NOT readable, and the read FAILED (#235)"
fi

# ===================================================================== GATE C ==
say "mount-revoke gate C"
STILL=$(fs_bounded 15 ls "$WORK/mnt"); stC="$(fs_state)"
echo "## listing after revoke: [$stC] $STILL"
if echo "$STILL" | grep -q "before.txt"; then
  bad "gateC: the revoked mount still serves its original contents"
elif [ "$stC" = "wedged" ]; then
  bad "gateC: the listing did not return, but the client WEDGED (no denial reached it)"
else
  ok "gateC: the revoked mount stopped serving within ${GRACE}s"
fi

echo
echo "==========================================="
if [ "$FAIL" = "0" ]; then
  echo "mount-revoke gates: $PASS passed, 0 failed"
else
  echo "mount-revoke gates: $PASS passed, $FAIL failed --$FAILED"
fi
echo "work: $WORK"
[ "$FAIL" = "0" ]
