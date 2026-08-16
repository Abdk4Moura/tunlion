#!/usr/bin/env bash
# #235: a revoked certificate must stop an ALREADY-ESTABLISHED mount.
# Standalone, hermetic, fixture port 8106 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./mount-revoke-gates.sh
#
# The capability gate runs once, at `mount-open`. A mount is a long-lived
# channel whose file operations never re-enter it, so before the fix a revoked
# device kept listing and reading, including files created AFTER the revoke,
# for as long as it chose not to disconnect. Confirmed live on 88be7a7f at 30,
# 60 and 120 seconds.
#
# The property is bounded staleness, not immediacy. The server re-asks the gate
# every REVOKE_RECHECK (5s), so the gate below allows a grace period and then
# requires the access to be gone. "Immediately" is not deliverable and claiming
# it would be the same defect this issue is about.
#
# Gates:
#   A  a live mount serves before the revoke        (the positive control)
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
GRACE=12   # > REVOKE_RECHECK, with slack for a slow box

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== mount-revoke gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
MOUNT_PID=""
cleanup() {
  # Kill the FUSE daemon FIRST. If the server stopped answering without saying
  # so, every process on the mountpoint is in uninterruptible D state and
  # `fusermount -u` returns EBUSY; killing the daemon is what releases them.
  [ -n "$MOUNT_PID" ] && kill "$MOUNT_PID" 2>/dev/null
  sleep 1
  fusermount3 -uz "$WORK/mnt" 2>/dev/null || fusermount -uz "$WORK/mnt" 2>/dev/null
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# Run a filesystem command against the mount with a HARD bound.
#
# `timeout` is not enough here and neither is SIGKILL: a FUSE client waiting on
# a server that never replies sits in D state, where no signal lands. So run it
# detached, poll for a completion marker, and if the marker never appears
# declare the mount WEDGED. A wedge must be reported, never counted as a denial:
# "the read did not return the data" is true of both a refusal and a hang, and
# only one of them is the behaviour we want.
# Echoes the output; writes ok|err|wedged to $WORK/fs.state (a FILE, because
# callers use $(...) and a variable set inside a command substitution dies with
# its subshell). Read it with fs_state.
fs_bounded() {  # $1 = seconds, rest = command
  local secs="$1"; shift
  local out="$WORK/fs.out" done="$WORK/fs.done"
  rm -f "$out" "$done"
  ( "$@" >"$out" 2>&1; echo $? >"$done" ) &
  for _ in $(seq 1 $((secs * 2))); do [ -f "$done" ] && break; sleep 0.5; done
  if [ -f "$done" ]; then
    [ "$(cat "$done")" = "0" ] && echo ok >"$WORK/fs.state" || echo err >"$WORK/fs.state"
  else
    echo wedged >"$WORK/fs.state"
  fi
  cat "$out" 2>/dev/null
}
fs_state() { cat "$WORK/fs.state" 2>/dev/null; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

DA="$WORK/A"; mkdir -p "$DA" "$WORK/share"
echo "written before the revoke" > "$WORK/share/before.txt"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name alpha --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1 \
  || { echo "init failed"; exit 2; }
# FILAMENT_L2=1 is REQUIRED on the acceptor: `mount-open` is gated on
# `l2_enabled` (main.rs), which a plain `up` leaves off, so without it the
# handler is never reached and the mount times out with no acceptor-side trace.
env FILAMENT_CONFIG_DIR="$DA" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up.log" 2>&1 &
pids+=($!)
sleep 2

DB="$WORK/B"; mkdir -p "$DB"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for bravo --allow mount \
    --out "$WORK/inv.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" \
    --name bravo --no-interactive >"$WORK/join.log" 2>&1
sleep 2

# ===================================================================== GATE A ==
say A
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" mount alpha "$WORK/share" "$WORK/mnt" \
    >"$WORK/mount.log" 2>&1 &
MOUNT_PID=$!
pids+=("$MOUNT_PID")
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
# The recheck's OTHER half. Gate A reads within a second or two of mounting, so
# it can be satisfied without the recheck ever running. This read is deliberately
# past REVOKE_RECHECK with NO revoke in force: a healthy mount must survive its
# own recheck. Without this, a fix that closed every session on the first
# recheck would score three passes.
say A2
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
say B
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
echo "written AFTER the revoke" > "$WORK/share/after.txt"
sleep "$GRACE"
AFTER=$(fs_bounded 15 cat "$WORK/mnt/after.txt"); stB="$(fs_state)"
echo "## read after revoke (${GRACE}s): [$stB] $AFTER"
if [ "$AFTER" = "written AFTER the revoke" ]; then
  bad "gateB: a revoked peer read a file created AFTER the revoke"
elif [ "$stB" = "wedged" ]; then
  # The data did not come back, but the client is hung in D state rather than
  # refused. Not a pass: an unkillable process on the mountpoint is its own
  # defect, and it hides whether the gate ran at all.
  bad "gateB: the read did not return data, but the client WEDGED (no denial reached it)"
else
  ok "gateB: a file created after the revoke is NOT readable, and the read FAILED (#235)"
fi

# ===================================================================== GATE C ==
say C
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
