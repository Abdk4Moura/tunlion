#!/usr/bin/env bash
# Mesh-native mount gates: prove the Linux FUSE client adapter end-to-end over a
# real mount (fusermount3 + /dev/fuse). Standalone, hermetic, fixture port 8098.
#
#   ./mount-gates.sh
#
# Gates:
#   1 read byte-exact   mount a peer dir; stat size + cmp a 1 MiB binary read
#   2 write-through     write a file INTO the mount; cmp against the served dir
#   3 non-utf8 name     a filename with a raw 0xFF byte lists + reads byte-exact
#   4 mutations         mkdir / rename / unlink through the mount hit the server
#   5 teardown          fusermount -u is clean; mountpoint empties; no leaked proc
#   6 refused pre-mount  a bad remote path is refused by the probe, no stale dir
#
# Topology (mirrors l2-gates.sh): side B runs `filament up` (the acceptor, serves
# the mount protocol on a trusted link); side A runs `filament mount`. The two
# share a reciprocal pair secret so B marks A trusted.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$CLI_DIR/target/release/filament"
PORT=8098
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-/root/filament-bench/venv/bin/python}"
WORK="$(mktemp -d /tmp/wt-mount-gates.XXXXXX)"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== mount gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
OWN_BACKEND=""
MNTS=()
cleanup() {
  for m in "${MNTS[@]:-}"; do fusermount3 -u "$m" 2>/dev/null || fusermount -u "$m" 2>/dev/null; done
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  [ -n "$OWN_BACKEND" ] && kill "$OWN_BACKEND" 2>/dev/null
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
[ -e /dev/fuse ] || { echo "no /dev/fuse on this host"; exit 2; }
command -v fusermount3 >/dev/null || command -v fusermount >/dev/null || { echo "no fusermount"; exit 2; }
[ -x "$PYV" ] || { echo "no python venv at $PYV (set FILAMENT_TEST_VENV)"; exit 2; }

# --- own fixture backend on 8098 (kill only our own listeners on 8098) ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
OWN_BACKEND=$!
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# --- two mutually-trusted devices: reciprocal pair secret (what `pair` mints) ---
DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

# --- the directory boxB will serve, seeded with known fixtures ---
SERVED="$WORK/served"; mkdir -p "$SERVED/subdir"
head -c 1048576 /dev/urandom > "$SERVED/big.bin"
printf 'hello mesh mount\n' > "$SERVED/hello.txt"
printf 'nested\n' > "$SERVED/subdir/inner.txt"
# A filename that is valid on Linux but NOT valid UTF-8 (lone 0xFF byte).
WEIRD=$'caf\xffe.bin'
printf 'non-utf8-name-payload' > "$SERVED/$WEIRD"

# Start the acceptor (side B) ONCE. FILAMENT_L2=1 opts into the L2/mount path.
B_DROP="$WORK/Bdrop"; mkdir -p "$B_DROP"
start_boxB() {
  FILAMENT_CONFIG_DIR="$DB" FILAMENT_L2=1 FILAMENT_NAME=boxB \
    "$BIN" up --dir "$B_DROP" --server "$SERVER" >"$WORK/up.log" 2>&1 &
  BPID=$!
  pids+=("$BPID")
  sleep 3
}
BPID=""
start_boxB

A_ENV=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_L2=1 FILAMENT_NAME=boxA)

# Helper: mount $SERVED at $1 in the background; wait until it is live.
start_mount() {
  local mnt="$1"; local remote="$2"; local log="$3"
  MNTS+=("$mnt")
  "${A_ENV[@]}" "$BIN" mount boxB "$remote" "$mnt" --server "$SERVER" >"$log" 2>&1 &
  echo $! > "$WORK/mount.pid"
  pids+=($!)
  for _ in $(seq 1 60); do
    if mountpoint -q "$mnt" 2>/dev/null; then return 0; fi
    grep -q "mounted\." "$log" 2>/dev/null && mountpoint -q "$mnt" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

MNT="$WORK/mnt"; mkdir -p "$MNT"

# ===================================================================== gate 1 ==
say 1
if start_mount "$MNT" "$SERVED" "$WORK/m1.log"; then
  sz=$(stat -c '%s' "$MNT/big.bin" 2>/dev/null)
  if [ "$sz" = "1048576" ] && cmp -s "$SERVED/big.bin" "$MNT/big.bin"; then
    ok "gate1: mount live, stat size=$sz, 1 MiB read byte-exact"
  else
    echo "-- m1.log --"; cat "$WORK/m1.log"; echo "-- up.log tail --"; tail -15 "$WORK/up.log"
    bad "gate1: read NOT byte-exact (size=$sz)"
  fi
else
  echo "-- m1.log --"; cat "$WORK/m1.log"; echo "-- up.log tail --"; tail -20 "$WORK/up.log"
  bad "gate1: mount never came live"
fi

# ===================================================================== gate 1b ==
# enumeration: a directory listing through the mount must show the ASCII
# fixtures. This is the instrument that was missing when #135 hid: file reads
# (gate 1) work even when listing is broken, so nothing caught it.
say 1b
if mountpoint -q "$MNT" 2>/dev/null; then
  listing=$(ls -A "$MNT" 2>"$WORK/ls.err")
  if [ "$?" = "0" ] \
     && printf '%s\n' "$listing" | grep -qx "big.bin" \
     && printf '%s\n' "$listing" | grep -qx "hello.txt"; then
    ok "gate1b: directory enumerates (ls lists big.bin, hello.txt)"
  else
    echo "-- listing --"; printf '%s\n' "$listing"; echo "-- ls.err --"; cat "$WORK/ls.err"
    bad "gate1b: directory does not enumerate"
  fi
else
  bad "gate1b: no live mount to enumerate"
fi

# ===================================================================== gate 2 ==
# write-through: create a file inside the mount, verify it lands in $SERVED.
say 2
if mountpoint -q "$MNT" 2>/dev/null; then
  head -c 65536 /dev/urandom > "$WORK/w.bin"
  if cp "$WORK/w.bin" "$MNT/written.bin" 2>"$WORK/w.err" \
     && cmp -s "$WORK/w.bin" "$SERVED/written.bin"; then
    ok "gate2: write-through byte-exact (65536 B landed on the server)"
  else
    echo "-- w.err --"; cat "$WORK/w.err"; bad "gate2: write-through NOT byte-exact"
  fi
else
  bad "gate2: no live mount to write into"
fi

# ===================================================================== symlink ==
say symlink
SYMLINK_TARGET="$SERVED/symlink-target.txt"
printf 'symlink-target-original\n' > "$SYMLINK_TARGET"
if ln -s "$SYMLINK_TARGET" "$MNT/symlink.part" 2>"$WORK/symlink.err"; then
  echo "-- symlink.err --"; cat "$WORK/symlink.err"
  bad "symlink: creation unexpectedly succeeded; mount symlinks would make the non-unix safe_open_beneath race remotely reachable"
elif [ -L "$MNT/symlink.part" ]; then
  echo "-- symlink.err --"; cat "$WORK/symlink.err"
  bad "symlink: command refused but a symlink appeared; refusal is not pinned"
else
  ok "symlink: creation refused; this refusal pins the setup step for the non-unix safe_open_beneath race"
fi
cat "$WORK/symlink.err" 2>/dev/null || true

# ===================================================================== gate 3 ==
# non-UTF-8 name: the 0xFF-byte filename must be visible AND byte-exact readable
# through the mount (spec rule 2: names are raw bytes, never lossy).
say 3
if mountpoint -q "$MNT" 2>/dev/null; then
  # Presence: the raw-byte name appears in the listing (find is byte-safe).
  found=$(find "$MNT" -maxdepth 1 -name $'caf\xffe.bin' | wc -l)
  got=$(cat "$MNT/$WEIRD" 2>"$WORK/u.err")
  if [ "$found" = "1" ] && [ "$got" = "non-utf8-name-payload" ]; then
    ok "gate3: non-utf8 filename listed and read byte-exact through the mount"
  else
    echo "-- listing --"; find "$MNT" -maxdepth 1 | cat -v; echo "-- u.err --"; cat "$WORK/u.err"
    bad "gate3: non-utf8 name not handled (found=$found got='$got')"
  fi
else
  bad "gate3: no live mount for non-utf8 test"
fi

# ===================================================================== gate 4 ==
# mutations through the mount reach the server's real filesystem.
say 4
if mountpoint -q "$MNT" 2>/dev/null; then
  g4=0
  mkdir "$MNT/newdir" 2>"$WORK/g4.err" && [ -d "$SERVED/newdir" ] || g4=1
  mv "$MNT/hello.txt" "$MNT/renamed.txt" 2>>"$WORK/g4.err" \
    && [ -f "$SERVED/renamed.txt" ] && [ ! -e "$SERVED/hello.txt" ] || g4=1
  rm "$MNT/subdir/inner.txt" 2>>"$WORK/g4.err" && [ ! -e "$SERVED/subdir/inner.txt" ] || g4=1
  if [ "$g4" = "0" ]; then
    ok "gate4: mkdir + rename + unlink through the mount all hit the server"
  else
    echo "-- g4.err --"; cat "$WORK/g4.err"; bad "gate4: a mutation did not reach the server"
  fi
else
  bad "gate4: no live mount for mutation test"
fi

# ===================================================================== gate 5 ==
# teardown: fusermount -u detaches cleanly; the mountpoint empties; the mount
# process exits (no leaked filament holding the FUSE session).
say 5
MPID=$(cat "$WORK/mount.pid" 2>/dev/null)
if fusermount3 -u "$MNT" 2>"$WORK/umount.err" || fusermount -u "$MNT" 2>>"$WORK/umount.err"; then
  sleep 2
  still_mounted=0; mountpoint -q "$MNT" 2>/dev/null && still_mounted=1
  proc_alive=0; [ -n "$MPID" ] && kill -0 "$MPID" 2>/dev/null && proc_alive=1
  # after a clean unmount the mountpoint dir is present but shows the LOCAL
  # (empty) dir again, not the served contents.
  leftover=$(ls -A "$MNT" 2>/dev/null | wc -l)
  if [ "$still_mounted" = "0" ] && [ "$proc_alive" = "0" ] && [ "$leftover" = "0" ]; then
    ok "gate5: unmount clean (detached, process exited, mountpoint empty)"
  else
    echo "-- still_mounted=$still_mounted proc_alive=$proc_alive leftover=$leftover --"
    bad "gate5: teardown not clean"
  fi
else
  echo "-- umount.err --"; cat "$WORK/umount.err"; bad "gate5: fusermount -u failed"
fi

# ===================================================================== gate 6 ==
# refused pre-mount: a non-existent remote path is caught by the connection
# probe (GetAttr on the root returns ENOENT from the server), so the mount fails
# BEFORE touching FUSE and leaves no stale mountpoint. This is the same probe
# path that rejects an untrusted peer (there the stream EOFs instead of ENOENT);
# either way: fail loud pre-mount, no stale dir.
#
# Restart boxB first so this is a FRESH first establishment (a second cold
# direct-quic establish to the same peer is flaky in this sandbox and would mask
# the server-side refusal we are actually testing).
say 6
kill "$BPID" 2>/dev/null; sleep 2
start_boxB
BADMNT="$WORK/badmnt"  # must NOT exist beforehand so we can assert no stale dir
rc6=1
for attempt in 1 2 3; do
  timeout 30 "${A_ENV[@]}" "$BIN" mount boxB "$SERVED/does-not-exist" "$BADMNT" \
    --server "$SERVER" >"$WORK/m6.log" 2>&1
  rc6=$?
  # A clean server refusal names ENOENT / "refused"; retry only on a transport
  # establishment flake so the gate stays deterministic on the real path.
  grep -qiE "refused|failed before it started|timed out|no such file" "$WORK/m6.log" && break
  sleep 2
done
if [ "$rc6" != "0" ] \
   && grep -qiE "refused|failed before it started|timed out|no such file" "$WORK/m6.log" \
   && [ ! -e "$BADMNT" ]; then
  ok "gate6: bad remote refused pre-mount (rc=$rc6), no stale mountpoint left"
else
  echo "-- m6.log --"; cat "$WORK/m6.log"; echo "badmnt exists: $([ -e "$BADMNT" ] && echo yes || echo no)"
  bad "gate6: refusal path not clean (rc=$rc6)"
fi

# ===================================================================================
printf '\n\033[1m== summary ==\033[0m\n'
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ] && { echo "ALL GREEN"; exit 0; } || { echo "FAILED:$FAILED"; exit 1; }
