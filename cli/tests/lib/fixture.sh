#!/usr/bin/env bash
# Shared hermetic-gate fixture. Source this from a gate script (which must set
# PORT, SERVER, WORK, BIN, CLI_DIR, PYV, DA before sourcing), then call the
# helpers below. See mount-revoke-gates.sh / pty-revoke-gates.sh /
# l2-revoke-gates.sh for the pattern.
#
# `FILAMENT_L2=1` on the acceptor is baked into `start_acceptor`, not left to the
# caller, because pty-open / mount-open / l2-open are all gated on `l2_enabled`
# and a plain `up` leaves it off with a failure that is silent on both sides.

# TWO HAZARDS THIS BOX HAS ALREADY CHARGED US FOR, both of which degrade to a
# plausible WRONG ANSWER rather than an error, which is what makes them expensive:
#
#   1. PORT COLLISION. Several worktrees run gates here at once. A gate whose
#      fixture port is already held by another worktree's backend will happily
#      health-check the STRANGER's process and proceed, and every result after
#      that is about someone else's server. Call `claim_port` for every port you
#      intend to own, before binding anything. And when a gate stands up its own
#      fake service, have it identify itself with something only it could produce
#      (a custom header, say) and verify THAT, not the response body: a real
#      backend also answers /api/whoami with an IP, so the body cannot tell the
#      two apart.
#
#   2. THE BINARY'S NAME MUST CONTAIN "filament". `daemon_alive()` confirms the
#      pidfile's pid by reading /proc/<pid>/cmdline and testing it CONTAINS the
#      literal string "filament" (main.rs, `is_filament_process`). A gate that
#      copies the binary to, say, `fil-237-base` gets `daemon_alive() == None`,
#      so `up` never creates its control.sock, so every `reach`/warm-link lookup
#      silently falls back to a cold probe whose JSON has no `route` field at
#      all. It looks exactly like "the peers won't link". Name reference binaries
#      `filament-<something>`. (Tracked as #224.)

# Refuse to start if a port we intend to own is already taken. Exits 2 rather
# than returning, because every later assertion would be unattributable.
claim_port() {
  for p in "$@"; do
    if ss -tln 2>/dev/null | grep -q ":$p "; then
      echo "port $p is already in use by another process; refusing to run."
      echo "  another worktree's gate probably owns it - pick a free port rather than"
      echo "  sharing one: a gate that talks to a stranger's backend proves nothing."
      exit 2
    fi
  done
}

# --- assertion bookkeeping ---
PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

FIX_PIDS=()
fixture_cleanup() {
  for p in "${FIX_PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
}

# Start the fixture signaling backend on $PORT and block until healthy.
start_backend() {
  for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
  sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
  FIX_PIDS+=($!)
  for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
  curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
  # Record the pid that actually HOLDS the port, not just the subshell we
  # backgrounded. `( cd ... ) &` gives us the subshell's pid; killing that leaves
  # the python child orphaned and still listening, which is how a box ends up
  # with a row of fixture ports held by dead gates and the next run silently
  # health-checking a stranger.
  for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do
    FIX_PIDS+=("$pid")
  done
  [ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
}

# $1 = config dir. Create an owner identity named alpha there.
init_owner() {
  mkdir -p "$1"
  env FILAMENT_CONFIG_DIR="$1" "$BIN" init --name alpha --recovery-file "$1/rec.txt" --yes >/dev/null 2>&1 \
    || { echo "init failed"; exit 2; }
}

# $1 = acceptor config dir. Start the acceptor daemon (FILAMENT_L2=1 baked in).
start_acceptor() {
  env FILAMENT_CONFIG_DIR="$1" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up.log" 2>&1 &
  FIX_PIDS+=($!)
  sleep 2
}

# $1 = device name, $2... = extra `add` flags (e.g. `--allow shell`). Enroll a
# delegated device from the owner config, then have it join from a fresh dir.
enroll_delegate() {
  local name="$1"; shift
  local ddir="$WORK/$name"; mkdir -p "$ddir"
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for "$name" "$@" --out "$WORK/$name-inv.txt" --yes >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$ddir" "$BIN" --server "$SERVER" join --invite-file "$WORK/$name-inv.txt" --name "$name" --no-interactive >"$WORK/$name-join.log" 2>&1
  sleep 2
}

# Run `$@` with a HARD bound that can distinguish a refusal from a hang.
#
# `timeout` is not enough and neither is SIGKILL: a client waiting on a server
# that never replies can sit in uninterruptible D state, where no signal lands.
# So run detached, poll for a completion marker, and if the marker never appears
# declare it WEDGED. A wedge is a FAILURE, not a pass: "the output stopped" is
# satisfied by a hang exactly as well as by a refusal.
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
