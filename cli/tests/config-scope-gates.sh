#!/usr/bin/env bash
# Config-scope and output gates: what the launch candidate did when a blind
# tester pointed it at a second config directory, ran it with HOME unset, and
# piped its output into `head`. Each gate drives the real binary end to end and
# asserts the user-visible property.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/config-scope-gates.sh
#
# Gates:
#   A  a new XDG_CONFIG_HOME dir next to a live default config: before init it
#      holds NO file (the default config's identity.ed25519, overlay.ed25519,
#      proxy.token, devices.json and up.pid were copied into it), init there
#      creates a NEW identity, and `status`/`down` there neither report nor stop
#      the default config's daemon.
#   H  `env -u HOME tunlion init`: the inbox written to the config is absolute
#      (it was `dir ./Tunlion`), and a relative --inbox is made absolute.
#   E  output into a closed pipe (`status | true`, the reader gone before the
#      write): no panic, and the exit code the same command gives unpiped, for
#      the human text and for --json (both exited 101 with "failed printing").
#   P  the same with no daemon: `status 2>&1 | head -1` exits with status's own
#      code (11 with the exit-code taxonomy), never 0.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8133
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-cfgscope.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== config-scope gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

HOMEA="$WORK/home"
DEFCFG="$HOMEA/.config/filament"
# The default config is selected the way a user's is: by HOME, with no
# FILAMENT_CONFIG_DIR and no XDG_CONFIG_HOME.
dflt() { env -u FILAMENT_CONFIG_DIR -u XDG_CONFIG_HOME HOME="$HOMEA" "$@"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  dflt timeout 10 "$BIN" down -y >/dev/null 2>&1
  [ -n "${CREATED_INBOX:-}" ] && rmdir "$CREATED_INBOX" 2>/dev/null
  true
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# The default config, with a running daemon.
mkdir -p "$HOMEA"
dflt "$BIN" init --name alpha --recovery-file "$WORK/alpha-rec.txt" --yes >"$WORK/alpha-init.log" 2>&1 \
  || { echo "setup: default init failed"; cat "$WORK/alpha-init.log"; exit 2; }
dflt timeout 30 "$BIN" --server "$SERVER" up --detach --dir "$WORK/alpha-drop" >"$WORK/alpha-up.log" 2>&1
DPID=""
for _ in $(seq 1 40); do DPID=$(head -1 "$DEFCFG/up.pid" 2>/dev/null); [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null && break; sleep 0.25; done
[ -n "$DPID" ] && pids+=("$DPID")
if [ -z "$DPID" ] || ! kill -0 "$DPID" 2>/dev/null; then
  echo "setup: the default config's daemon did not start"; cat "$WORK/alpha-up.log"; tail -5 "$DEFCFG/daemon.log" 2>/dev/null; exit 2
fi
echo "## default config $DEFCFG, daemon pid $DPID"

# ===================================================================== GATE A ==
say "A: a new XDG_CONFIG_HOME is its own config, never a copy of the default"
# A long path, as reported (204 characters), so the control socket also takes
# the short per-user fallback.
XDG="$WORK/deep/$(printf 'x%.0s' $(seq 1 120))/$(printf 'y%.0s' $(seq 1 40))"
mkdir -p "$XDG"
xdgc() { env -u FILAMENT_CONFIG_DIR HOME="$HOMEA" XDG_CONFIG_HOME="$XDG" "$@"; }
echo "## XDG_CONFIG_HOME is ${#XDG} bytes"
# Any command runs the legacy migration; status is the read-only one.
xdgc timeout 20 "$BIN" status >"$WORK/xdg-status0.log" 2>&1; rcS0=$?
# Leaked: any file of the default config that now also exists in the new one,
# by name (identity.ed25519, overlay.ed25519, proxy.token, devices.json, up.pid,
# the logs...). The one exception is the permissions-migration stamp, which
# every command writes into its OWN config dir (its content is a version
# number, not state copied from anywhere).
leaked=""
for f in $(cd "$DEFCFG" && find . -type f | sed 's|^\./||'); do
  [ "$f" = "permissions-migration" ] && continue
  [ -e "$XDG/filament/$f" ] && leaked="$leaked $f"
done
others=$(find "$XDG" -type f ! -name permissions-migration 2>/dev/null | sed "s|$XDG/||" | tr '\n' ' ')
[ -n "$others" ] && leaked="$leaked [unexpected: $others]"
xdgc "$BIN" init --name bravo --recovery-file "$WORK/bravo-rec.txt" --yes >"$WORK/xdg-init.log" 2>&1; rcI=$?
NEWCFG="$XDG/filament"
same_key=no
cmp -s "$DEFCFG/identity.ed25519" "$NEWCFG/identity.ed25519" 2>/dev/null && same_key=yes
xdgc timeout 20 "$BIN" status >"$WORK/xdg-status.log" 2>&1
xdgc timeout 20 "$BIN" down -y >"$WORK/xdg-down.log" 2>&1; rcD=$?
sleep 1
alive=no; kill -0 "$DPID" 2>/dev/null && alive=yes
dflt timeout 20 "$BIN" status >"$WORK/dflt-status.log" 2>&1
echo "## before init: files in the new dir: [${leaked}] (status rc=$rcS0)"
echo "## init rc=$rcI, same identity key as the default: $same_key"
sed 's/^/    init:   /' "$WORK/xdg-init.log" | head -4
sed 's/^/    status: /' "$WORK/xdg-status.log" | head -3
sed 's/^/    down:   /' "$WORK/xdg-down.log" | head -3
echo "## default daemon (pid $DPID) alive after down in the new dir: $alive"
sed 's/^/    default status: /' "$WORK/dflt-status.log" | head -2
if [ -z "$leaked" ] && [ "$rcI" = "0" ] && [ "$same_key" = "no" ] && [ -f "$NEWCFG/identity.ed25519" ] \
   && ! grep -q "already has identity" "$WORK/xdg-init.log" \
   && ! grep -q "pid $DPID" "$WORK/xdg-status.log" "$WORK/xdg-down.log" \
   && [ "$alive" = "yes" ] && grep -qE "up( but degraded)? \(pid $DPID\)" "$WORK/dflt-status.log"; then
  ok "gateA: the new config dir got nothing from the default one, a new identity, and left its daemon alone"
else
  bad "gateA: config dir scope (leaked=[$leaked] init=$rcI same_key=$same_key default_alive=$alive)"
fi

# ===================================================================== GATE E ==
say "E: output into a closed pipe ends quietly with the command's own exit code"
# The reader (`true`) is gone before the first write, so every write is EPIPE.
# The exit code must be the one the same command gives unpiped (the default
# config's daemon is up here, so that is 0): a closed pipe changes nothing.
dflt timeout 20 "$BIN" status >/dev/null 2>&1; rcU=$?
dflt timeout 20 "$BIN" status --json >/dev/null 2>&1; rcUJ=$?
{ sleep 0.5; dflt timeout 20 "$BIN" status; echo $? >"$WORK/epipe-text.rc"; } 2>"$WORK/epipe-text.err" | true
{ sleep 0.5; dflt timeout 20 "$BIN" status 2>&1; echo $? >"$WORK/epipe-both.rc"; } | true
{ sleep 0.5; dflt timeout 20 "$BIN" status --json; echo $? >"$WORK/epipe-json.rc"; } 2>"$WORK/epipe-json.err" | true
rcT=$(cat "$WORK/epipe-text.rc"); rcB=$(cat "$WORK/epipe-both.rc"); rcJ=$(cat "$WORK/epipe-json.rc")
echo "## unpiped: status rc=$rcU, --json rc=$rcUJ; status | true: rc=$rcT; status 2>&1 | true: rc=$rcB; status --json | true: rc=$rcJ"
cat "$WORK/epipe-text.err" "$WORK/epipe-json.err" 2>/dev/null | head -4 | sed 's/^/    stderr: /'
if [ "$rcT" = "$rcU" ] && [ "$rcB" = "$rcU" ] && [ "$rcJ" = "$rcUJ" ] && [ "$rcU" = "0" ] \
   && ! grep -qi "panicked\|failed printing" "$WORK/epipe-text.err" "$WORK/epipe-json.err"; then
  ok "gateE: a closed pipe ends the command quietly with its own exit code ($rcU)"
else
  bad "gateE: closed pipe (unpiped rc=$rcU/json $rcUJ; piped text=$rcT both=$rcB json=$rcJ)"
fi

# ===================================================================== GATE P ==
say "P: a closed pipe keeps a nonzero answer: status with no daemon"
# The tester's case: `tunlion status 2>&1 | head -1` with no daemon gave
# PIPESTATUS 0 where plain `status` exits 11, so a script lost the answer. The
# command decides its exit code before printing and a closed pipe exits with it.
DP="$WORK/cfg-pipe"
env FILAMENT_CONFIG_DIR="$DP" "$BIN" init --name piper --recovery-file "$WORK/piper-rec.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DP" timeout 20 "$BIN" status >/dev/null 2>&1; rcPU=$?
env FILAMENT_CONFIG_DIR="$DP" timeout 20 "$BIN" status --json >/dev/null 2>&1; rcPUJ=$?
{ sleep 0.5; env FILAMENT_CONFIG_DIR="$DP" timeout 20 "$BIN" status 2>&1; echo $? >"$WORK/pipe-p.rc"; } | true
{ sleep 0.5; env FILAMENT_CONFIG_DIR="$DP" timeout 20 "$BIN" status --json; echo $? >"$WORK/pipe-pj.rc"; } 2>"$WORK/pipe-pj.err" | true
rcPP=$(cat "$WORK/pipe-p.rc"); rcPPJ=$(cat "$WORK/pipe-pj.rc")
# And through `head -1`, exactly as reported.
env FILAMENT_CONFIG_DIR="$DP" timeout 20 "$BIN" status 2>&1 | head -1 >/dev/null; rcPH=${PIPESTATUS[0]}
echo "## no daemon: status rc=$rcPU (piped $rcPP, | head -1 $rcPH); --json rc=$rcPUJ (piped $rcPPJ)"
if [ "$rcPP" = "$rcPU" ] && [ "$rcPH" = "$rcPU" ] && [ "$rcPPJ" = "$rcPUJ" ] \
   && ! grep -qi "panicked\|failed printing" "$WORK/pipe-pj.err"; then
  ok "gateP: with no daemon, a closed pipe keeps status's exit code ($rcPU)"
else
  bad "gateP: a closed pipe changed status's exit code (unpiped $rcPU, piped $rcPP, head -1 $rcPH; json $rcPUJ vs $rcPPJ)"
fi
# ===================================================================== GATE H ==
say "H: with HOME unset, init never writes a relative inbox"
DH="$WORK/cfg-nohome"
PWHOME="$(getent passwd "$(id -u)" | cut -d: -f6)"
# init creates the default inbox under the password-database home; remove it
# afterwards only if this gate created it (and it is still empty).
[ -n "$PWHOME" ] && [ ! -e "$PWHOME/Tunlion" ] && CREATED_INBOX="$PWHOME/Tunlion"
( cd "$WORK" && env -u HOME FILAMENT_CONFIG_DIR="$DH" "$BIN" init --yes --name charlie \
    --recovery-file "$WORK/charlie-rec.txt" >"$WORK/nohome-init.log" 2>&1 ); rcH=$?
DIRH=$(grep '^dir ' "$DH/config" 2>/dev/null | cut -d' ' -f2-)
DR="$WORK/cfg-relinbox"
( cd "$WORK" && env FILAMENT_CONFIG_DIR="$DR" "$BIN" init --yes --name delta --inbox rel-inbox \
    --recovery-file "$WORK/delta-rec.txt" >"$WORK/relinbox-init.log" 2>&1 ); rcR=$?
DIRR=$(grep '^dir ' "$DR/config" 2>/dev/null | cut -d' ' -f2-)
echo "## env -u HOME init rc=$rcH, dir=[$DIRH] (password-database home: $PWHOME)"
echo "## --inbox rel-inbox init rc=$rcR, dir=[$DIRR]"
grep -i "inbox" "$WORK/nohome-init.log" | head -2 | sed 's/^/    /'
if [ "$rcH" = "0" ] && case "$DIRH" in /*) true ;; *) false ;; esac && case "$DIRH" in "$PWHOME"/*) true ;; *) false ;; esac \
   && ! grep -q "inbox: \./" "$WORK/nohome-init.log" \
   && [ "$rcR" = "0" ] && [ "$DIRR" = "$WORK/rel-inbox" ] && [ -d "$WORK/rel-inbox" ]; then
  ok "gateH: HOME unset resolves the home from the password database; every inbox written is absolute"
else
  bad "gateH: relative inbox (HOME unset: rc=$rcH dir=[$DIRH]; --inbox rel: rc=$rcR dir=[$DIRR])"
  cat "$WORK/nohome-init.log" | head -5
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "config-scope gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
