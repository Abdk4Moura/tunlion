#!/usr/bin/env bash
# Bounded ci-dogfood worker leases: liveness probes and fixture teardown.
#
# The incident this gate covers: a worker lease stayed in_progress for 39
# minutes after its daemon was gone, because the serve step only slept. A second
# leak: a gate backend inherited the build lock (fd 3 from the worker wrapper,
# fd 9 from scripts/cargo-locked.sh) and outlived the gate, wedging the next
# build behind a flock it could not see.
#
#   L1  a live daemon answers -> probe true
#   L2  a dead daemon (exit 11) -> probe false
#   L3  an exit-0 but running:false object -> probe false (JSON is checked)
#   L4  a hung status read is bounded and counts as not live
#   L5  require_daemon on a dead daemon returns 7 inside its bound
#   L6  an idle live lease serves to its deadline (idle is legitimate)
#   L7  three consecutive failed probes end a serve loop with 7, bounded
#   L8  a STOP file ends the loop cleanly with 0
#   L9  fixture backend: the recorded PID is the backend; inherited lock fds are
#       closed; cleanup kills it and a fresh flock -n succeeds
#   L10 a real daemon: live, then killed by this gate -> require_daemon 7 fast
#   L11 cargo-locked: the cargo child has no fd 9 but the parent still holds
#       the lock for its lifetime
#   L12 cargo-locked: after the wrapper exits the lock is free again
#
# Standalone and hermetic: fixture port defaults to 8177. Refuses (exit 2) when
# it cannot measure (no binary, no flock, no backend deps) rather than skipping.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT="${WORKER_LIFECYCLE_PORT:-8177}"
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/worker-lifecycle.XXXXXX")"
export CI_WORKER_STOP_FILE="$WORK/STOP"
export CI_WORKER_PROBE_TIMEOUT=2
export TUNLION_BIN="$BIN"

say() { printf '\n\033[1m== worker lifecycle gate %s ==\033[0m\n' "$*"; }
PASS=0; FAIL=0; FAILED=""
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

# shellcheck source=../scripts/ci-worker-liveness.sh
. "$CLI_DIR/../scripts/ci-worker-liveness.sh"
# shellcheck source=lib/fixture.sh
. "$HERE/lib/fixture.sh"

pids=()
cleanup() {
  fixture_cleanup
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
command -v flock >/dev/null || { echo "REFUSED: flock is required"; exit 2; }

now() { date +%s; }

cat > "$WORK/alive" <<'EOF'
#!/bin/sh
cat <<'JSON'
{"ok":true,"running":true}
JSON
exit 0
EOF
cat > "$WORK/dead" <<'EOF'
#!/bin/sh
cat <<'JSON'
{"ok":false,"running":false}
JSON
exit 11
EOF
cat > "$WORK/lying" <<'EOF'
#!/bin/sh
cat <<'JSON'
{"ok":false,"running":false}
JSON
exit 0
EOF
cat > "$WORK/hung" <<'EOF'
#!/bin/sh
sleep 30
EOF
chmod +x "$WORK/alive" "$WORK/dead" "$WORK/lying" "$WORK/hung"
ALIVE="$WORK/alive"; DEAD="$WORK/dead"; LYING="$WORK/lying"; HUNG="$WORK/hung"

say "L1: live daemon -> probe true"
TUNLION_BIN="$ALIVE" ci_daemon_live
if [ $? -eq 0 ]; then ok "L1: live daemon is live"; else bad "L1: live daemon reported dead"; fi

say "L2: dead daemon -> probe false"
TUNLION_BIN="$DEAD" ci_daemon_live
if [ $? -ne 0 ]; then ok "L2: dead daemon is not live"; else bad "L2: dead daemon was accepted as live"; fi

say "L3: exit 0 with running:false is not live"
TUNLION_BIN="$LYING" ci_daemon_live
if [ $? -ne 0 ]; then ok "L3: JSON running:false rejected despite exit 0"; else bad "L3: exit 0 masked a non-running daemon"; fi

say "L4: a hung status call is bounded"
t0=$(now)
TUNLION_BIN="$HUNG" ci_daemon_live
rc=$?; took=$(( $(now) - t0 ))
if [ "$rc" -ne 0 ] && [ "$took" -le 6 ]; then
  ok "L4: hung status counted as not live in ${took}s"
else
  bad "L4: hung status rc=$rc took=${took}s"
fi

say "L5: require_daemon on a dead daemon returns 7 inside the bound"
t0=$(now)
TUNLION_BIN="$DEAD" ci_require_daemon 2
rc=$?; took=$(( $(now) - t0 ))
if [ "$rc" -eq 7 ] && [ "$took" -le 8 ]; then
  ok "L5: require_daemon gave 7 in ${took}s"
else
  bad "L5: require_daemon rc=$rc took=${took}s"
fi

say "L6: an idle live lease stays up to its deadline"
rm -f "$CI_WORKER_STOP_FILE"
end=$(( $(now) + 3 ))
t0=$(now)
TUNLION_BIN="$ALIVE" ci_serve_until "$end" 1 3
rc=$?; took=$(( $(now) - t0 ))
if [ "$rc" -eq 0 ] && [ "$took" -ge 2 ] && [ "$took" -le 8 ]; then
  ok "L6: idle lease ended cleanly at its deadline after ${took}s"
else
  bad "L6: idle lease rc=$rc took=${took}s (a healthy idle lease must not fail)"
fi

say "L7: three consecutive failed probes end a serve loop with 7"
rm -f "$CI_WORKER_STOP_FILE"
end=$(( $(now) + 60 ))
t0=$(now)
TUNLION_BIN="$DEAD" ci_serve_until "$end" 1 3
rc=$?; took=$(( $(now) - t0 ))
if [ "$rc" -eq 7 ] && [ "$took" -le 12 ]; then
  ok "L7: dead daemon ended the loop in ${took}s with 7"
else
  bad "L7: dead daemon rc=$rc took=${took}s"
fi

say "L8: STOP ends the loop cleanly even with a dead daemon"
: > "$CI_WORKER_STOP_FILE"
end=$(( $(now) + 60 ))
t0=$(now)
TUNLION_BIN="$DEAD" ci_serve_until "$end" 1 3
rc=$?; took=$(( $(now) - t0 ))
if [ "$rc" -eq 0 ] && [ "$took" -le 3 ]; then
  ok "L8: STOP ended the lease cleanly in ${took}s"
else
  bad "L8: STOP rc=$rc took=${took}s"
fi
rm -f "$CI_WORKER_STOP_FILE"

say "L9: fixture backend cleanup kills the backend and keeps no inherited flock"
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
LOCK="$WORK/build.lock"
: > "$LOCK"
exec 9>"$LOCK"
if ! flock -w 2 9; then
  bad "L9: this gate could not take its own build lock"
else
  start_backend || { bad "L9: fixture backend did not start"; }
  bpid=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
  if [ -z "$bpid" ]; then
    bad "L9: no backend pid on port $PORT"
  else
    # The recorded pid must be the backend itself, not a wrapper subshell.
    rec=${FIX_PIDS[${#FIX_PIDS[@]}-1]}
    if [ "$rec" = "$bpid" ]; then
      ok "L9: fixture recorded the backend pid $bpid, not a subshell"
    else
      bad "L9: fixture recorded $rec but the backend is $bpid"
    fi
    if ls -l "/proc/$bpid/fd" 2>/dev/null | grep -qF "$LOCK"; then
      bad "L9: backend inherited the build lock fd"
    else
      ok "L9: backend did not inherit the build lock fd"
    fi
  fi
  # Release our copy. If the backend inherited the lock this flock -n will
  # block/fail even though this shell closed its descriptor.
  exec 9>&-
  if timeout 3 flock -n "$LOCK" -c true; then
    ok "L9: flock -n succeeds after the gate released the lock"
  else
    bad "L9: a descendant retained the build lock"
  fi
  fixture_cleanup
  if [ -n "${bpid:-}" ] && kill -0 "$bpid" 2>/dev/null; then
    bad "L9: backend $bpid survived fixture_cleanup"
  else
    ok "L9: fixture_cleanup killed the backend"
  fi
  if curl -fsS "$SERVER/api/health" >/dev/null 2>&1; then
    bad "L9: backend still answers on $PORT after cleanup"
  else
    ok "L9: backend port $PORT is closed after cleanup"
  fi
fi

say "L10: a real daemon is live, then this gate kills it and require_daemon returns 7"
# The real daemon needs a signaling server; L9 cleaned up the previous one.
start_backend || { bad "L10: fixture backend did not restart"; }
DA="$WORK/da"; mkdir -p "$DA"
init_owner "$DA" || { bad "L10: init_owner failed"; }
start_acceptor "$DA"
TUNLION_BIN="$BIN"
export TUNLION_CONFIG_DIR="$DA"
live=0
for _ in $(seq 1 40); do ci_daemon_live && { live=1; break; }; sleep 0.5; done
if [ "$live" = 1 ]; then
  ok "L10: real daemon is live"
else
  bad "L10: real daemon never answered status"
fi
pid=$(sed -n '1p' "$DA/up.pid" 2>/dev/null)
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  t0=$(now)
  ci_require_daemon 5
  rc=$?; took=$(( $(now) - t0 ))
  if [ "$rc" -eq 7 ] && [ "$took" -le 10 ]; then
    ok "L10: killed daemon detected in ${took}s with 7"
  else
    bad "L10: killed daemon rc=$rc took=${took}s"
  fi
else
  bad "L10: no live pid in $DA/up.pid to kill"
fi

unset TUNLION_CONFIG_DIR

say "L11: cargo-locked's child does not inherit fd 9, but the parent holds the lock"
mkdir -p "$WORK/fakebin" "$WORK/state/filament"
cat > "$WORK/fakebin/cargo" <<'EOF'
#!/bin/sh
if [ -e /proc/self/fd/9 ]; then
  echo CHILD_FD9_OPEN
  exit 90
fi
if flock -n "$LOCK_FILE" -c true; then
  echo CHILD_LOCK_FREE
  exit 91
fi
echo CHILD_OK
echo CHILD_LOCK_HELD
exit 0
EOF
chmod +x "$WORK/fakebin/cargo"
LOCK_FILE="$WORK/state/filament/cargo-build.lock"
out=$(PATH="$WORK/fakebin:$PATH" XDG_STATE_HOME="$WORK/state" LOCK_FILE="$LOCK_FILE" \
  bash "$CLI_DIR/../scripts/cargo-locked.sh" build --fake 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^CHILD_OK$' \
   && printf '%s\n' "$out" | grep -q '^CHILD_LOCK_HELD$'; then
  ok "L11: cargo child had no fd 9 and saw the parent holding the lock"
else
  bad "L11: cargo-locked child rc=$rc out=$(printf '%s' "$out" | tr '\n' ' ')"
fi

say "L12: the build lock is free after cargo-locked exits"
if timeout 3 flock -n "$LOCK_FILE" -c true; then
  ok "L12: cargo-locked released the build lock"
else
  bad "L12: cargo-locked left the build lock held"
fi

echo
echo "worker lifecycle gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
[ "$FAIL" -eq 0 ]
