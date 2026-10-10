#!/usr/bin/env bash
# Hostile-environment gates: what a launch candidate did on a box that was not
# a developer's laptop (full disk, tmpfs home, umask 0000, a deep HOME, a
# stopped daemon, concurrent starts). Each gate reproduces one reported defect
# end to end against the real binary and asserts the user-visible property.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/hostile-env-gates.sh
#
# Gates:
#   R  five concurrent `up --detach`: exactly one daemon, every launcher exits 0
#      (four say "already running"), and daemon.log stays small. The crash was a
#      log-follow feedback loop: daemon.log 0 -> 22 MB in under two seconds.
#   U  umask 0000: every directory under the config dir is 0700 and every file
#      0600 after init, set, and a daemon run.
#   S  a config dir too deep for a unix socket path: the daemon still gets a
#      control socket (short per-user path) and `status` reports it responding.
#   K  a client whose XDG_RUNTIME_DIR differs from the daemon's (unset, or
#      another directory) still reaches its short control socket.
#   P  a SIGSTOPped daemon: `status` says "not responding", never "up", and
#      exits 6.
#   C  a copy of a config dir whose daemon is running (`cp -a`, up.pid and
#      up.lock included): `status` there says not running (exit 11) and `down`
#      there leaves the original's daemon alone.
#   Z  after `down`, `status` says not running and exits 11 (it exited 0).
#   J  `status --json` exits with the same code as `status` (6 frozen, 11
#      stopped) and says `"ok": false` with an `error`; it said ok:true, exit 0.
#   L  a config path past PATH_MAX: `up` names the length, not writability.
#   D  a send into a 2 MB disk: refused BEFORE streaming, the sender exits 4 and
#      names "out of disk space" with both sizes; nothing is left on that disk.
#   W  two files that each fit but not together: the write that hits ENOSPC is
#      reported as out of disk space (exit 4), never as a corrupt file.
#   N  a 250-character file name: saved, shortened to the filesystem limit with
#      its extension kept, and the send succeeds (it used to hang forever).
#   O  `add --out` onto a full disk: the error is printed and no partial file is
#      left to block the retry.
#   T  `set` with the config dir on a full disk: fails, and leaves no
#      `config.tmp.<pid>` behind.
#   I  `init` under a read-only config parent: fails, and leaves no orphan
#      recovery-phrase file for an identity that was never created.
#   H  `up --detach` with a HOME that does not exist names the path it needed.
#   X  with 127.0.0.1:1080 held, the daemon's auto SOCKS5 proxy binds another
#      port and says which, instead of announcing 1080 and binding nothing.
#
# D, W, O and T mount small tmpfs filesystems, so they need passwordless sudo
# (GitHub's ubuntu runners have it). Without it the script REFUSES (exit 2)
# rather than report a result it did not measure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8131
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-hostile.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== hostile-env gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

MOUNTS=()
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill -CONT "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  for d in "$WORK"/cfg-*; do
    [ -d "$d" ] && FILAMENT_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1
  done
  for m in "${MOUNTS[@]:-}"; do [ -n "$m" ] && sudo -n umount -l "$m" 2>/dev/null; done
  chmod -R u+w "$WORK" 2>/dev/null
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
sudo -n true 2>/dev/null || { echo "REFUSED: gates D/W/O/T mount tmpfs and need passwordless sudo"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# A tmpfs of $2 at $1, owned by us.
mount_small() {
  mkdir -p "$1"
  sudo -n mount -t tmpfs -o "size=$2,uid=$(id -u),gid=$(id -g),mode=0700" tmpfs "$1" \
    || { echo "REFUSED: cannot mount a tmpfs at $1"; exit 2; }
  MOUNTS+=("$1")
}
# Fill the filesystem holding $1 to the last byte.
fill_up() { dd if=/dev/zero of="$1/.fill" bs=4k >/dev/null 2>&1; dd if=/dev/zero of="$1/.fill2" bs=512 >/dev/null 2>&1; true; }

# ===================================================================== GATE R ==
say "R: five concurrent up --detach"
DR="$WORK/cfg-race"; mkdir -p "$DR"
env FILAMENT_CONFIG_DIR="$DR" "$BIN" init --name racer --recovery-file "$DR/rec.txt" --yes >/dev/null 2>&1 \
  || { echo "init failed"; exit 2; }
for i in 1 2 3 4 5; do
  ( env FILAMENT_CONFIG_DIR="$DR" timeout 60 "$BIN" --server "$SERVER" up --detach --dir "$WORK/race-drop" \
      >"$WORK/race-$i.log" 2>&1; echo $? >"$WORK/race-$i.rc" ) &
done
wait_for() { for _ in $(seq 1 60); do [ -f "$1" ] && return 0; sleep 0.5; done; return 1; }
for i in 1 2 3 4 5; do wait_for "$WORK/race-$i.rc"; done
sleep 4
ndaemons=0
for p in $(pgrep -f "tunlion.*up" 2>/dev/null); do
  if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null | grep -qx "FILAMENT_CONFIG_DIR=$DR"; then
    ndaemons=$((ndaemons+1)); pids+=("$p")
  fi
done
rcs="$(cat "$WORK"/race-*.rc 2>/dev/null | tr '\n' ' ')"
already=$(grep -l "already running" "$WORK"/race-*.log 2>/dev/null | wc -l)
logsize=$(stat -c %s "$DR/daemon.log" 2>/dev/null || echo 0)
echo "## daemons=$ndaemons rcs=[$rcs] already-running=$already daemon.log=${logsize}B"
for i in 1 2 3 4 5; do sed "s/^/    [$i] /" "$WORK/race-$i.log"; done
if [ "$ndaemons" = "1" ] && [ "$rcs" = "0 0 0 0 0 " ] && [ "$already" -ge 4 ] && [ "$logsize" -lt 1048576 ]; then
  ok "gateR: one daemon, five clean exits (four already running), daemon.log ${logsize}B"
else
  bad "gateR: concurrent up --detach (daemons=$ndaemons rcs=[$rcs] already=$already log=${logsize}B)"
  tail -5 "$DR/daemon.log" 2>/dev/null
fi
FILAMENT_CONFIG_DIR="$DR" timeout 15 "$BIN" down -y >/dev/null 2>&1

# ===================================================================== GATE U ==
say "U: umask 0000 never leaves state open to others"
DU="$WORK/cfg-umask/nested/filament"
(
  umask 0000
  env FILAMENT_CONFIG_DIR="$DU" "$BIN" init --name opener --recovery-file "$WORK/umask-rec.txt" --yes >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$DU" "$BIN" set auto-extract on >/dev/null 2>&1
  env FILAMENT_CONFIG_DIR="$DU" timeout 30 "$BIN" --server "$SERVER" up --detach --dir "$WORK/umask-drop" >/dev/null 2>&1
  sleep 3
  env FILAMENT_CONFIG_DIR="$DU" timeout 15 "$BIN" down -y >/dev/null 2>&1
)
sleep 1
open_items=$(find "$WORK/cfg-umask" \( -type d -perm /077 \) -o \( -type f -perm /077 \) 2>/dev/null)
nfiles=$(find "$DU" -type f 2>/dev/null | wc -l)
echo "## files under config: $nfiles"
find "$WORK/cfg-umask" -exec stat -c '    %a %n' {} \; 2>/dev/null | head -40
if [ -n "$open_items" ] || [ "$nfiles" -lt 3 ] || [ ! -f "$DU/identity.ed25519" ]; then
  bad "gateU: state readable or writable by others under umask 0000: $(echo $open_items)"
else
  ok "gateU: under umask 0000 every config dir is 0700 and every file 0600 ($nfiles files)"
fi

# ===================================================================== GATE S ==
say "S: a config dir too deep for a socket path still gets a control socket"
DS="$WORK/cfg-deep/$(printf 'd%.0s' $(seq 1 60))/$(printf 'e%.0s' $(seq 1 40))/filament"
mkdir -p "$DS"
echo "## config dir is ${#DS} bytes; $DS/control.sock would be $(( ${#DS} + 13 ))"
env FILAMENT_CONFIG_DIR="$DS" "$BIN" init --name deep --recovery-file "$WORK/deep-rec.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DS" timeout 30 "$BIN" --server "$SERVER" up --detach --dir "$WORK/deep-drop" >"$WORK/deep-up.log" 2>&1
sleep 3
STJ=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status --json 2>/dev/null)
ST=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1)
DPID=$(head -1 "$DS/up.pid" 2>/dev/null)
[ -n "$DPID" ] && pids+=("$DPID")
echo "$ST" | sed 's/^/    /'
if echo "$STJ" | "$PYV" -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get("running") and d.get("responding") is True else 1)' \
   && echo "$ST" | grep -q "up (pid" && ! grep -q "control socket unavailable" "$DS/daemon.log" 2>/dev/null; then
  ok "gateS: deep config dir, daemon answers on a short control socket"
else
  bad "gateS: deep config dir (status --json: $STJ)"
  tail -5 "$DS/daemon.log" 2>/dev/null
fi

# ===================================================================== GATE K ==
say "K: a client with a different XDG_RUNTIME_DIR still reaches the daemon"
# The daemon picked its short socket directory from ITS environment. A client
# run under sudo, cron or a bare ssh command has no XDG_RUNTIME_DIR, or another
# one; it computed a different directory and called a healthy daemon "not
# responding" at a path that never existed.
OTHERRUN="$WORK/other-run"; mkdir -p "$OTHERRUN"; chmod 700 "$OTHERRUN"
STK1=$(env -u XDG_RUNTIME_DIR FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1); rcK1=$?
STK2=$(env XDG_RUNTIME_DIR="$OTHERRUN" FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1); rcK2=$?
echo "## XDG_RUNTIME_DIR unset: rc=$rcK1; XDG_RUNTIME_DIR=$OTHERRUN: rc=$rcK2 (daemon's: ${XDG_RUNTIME_DIR:-unset})"
echo "$STK1" | head -2 | sed 's/^/    unset: /'; echo "$STK2" | head -2 | sed 's/^/    other: /'
if [ "$rcK1" = "0" ] && [ "$rcK2" = "0" ] && echo "$STK1" | grep -qE "up( but degraded)? \(pid $DPID\)" \
   && echo "$STK2" | grep -qE "up( but degraded)? \(pid $DPID\)"; then
  ok "gateK: clients with any XDG_RUNTIME_DIR reach the daemon's short control socket"
else
  bad "gateK: control socket not found from a different environment (rc unset=$rcK1 other=$rcK2)"
fi

# ===================================================================== GATE P ==
say "P: a stopped daemon is not reported up"
if [ -n "$DPID" ] && kill -STOP "$DPID" 2>/dev/null; then
  STP=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1); rcP=$?
  STPJ=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status --json 2>/dev/null); rcPJ=$?
  kill -CONT "$DPID" 2>/dev/null
  echo "## status rc=$rcP"; echo "$STP" | sed 's/^/    /'
  if echo "$STP" | grep -q "not responding" && ! echo "$STP" | grep -q " up (pid" && [ "$rcP" = "6" ]; then
    ok "gateP: SIGSTOPped daemon reported as running but not responding, exit 6"
  else
    bad "gateP: SIGSTOPped daemon still reported up, or status exited $rcP (want 6)"
  fi
else
  bad "gateP: no daemon pid to stop (gate S setup failed)"
fi

# ===================================================================== GATE C ==
say "C: a copied config dir does not see or stop the original's daemon"
# cp -a carries up.pid (the live daemon's pid) and up.lock (as a NEW inode,
# held by nobody). The copy has no daemon. It used to report the original's
# daemon as its own, and `down` there killed it.
sleep 1
DC="$WORK/cfg-copy"
cp -a "$DS" "$DC" 2>/dev/null
STC=$(env FILAMENT_CONFIG_DIR="$DC" timeout 20 "$BIN" status 2>&1); rcC=$?
DNC=$(env FILAMENT_CONFIG_DIR="$DC" timeout 20 "$BIN" down -y 2>&1)
sleep 1
aliveC=no; [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null && aliveC=yes
STO=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1)
echo "## copy has up.pid=$(head -1 "$DC/up.pid" 2>/dev/null); copy status rc=$rcC; original pid $DPID alive after down in copy: $aliveC"
echo "$STC" | head -1 | sed 's/^/    copy status: /'; echo "$DNC" | head -1 | sed 's/^/    copy down:   /'
echo "$STO" | head -1 | sed 's/^/    original:    /'
if [ "$rcC" = "11" ] && echo "$STC" | grep -q "not running" && ! echo "$DNC" | grep -q "stopped" \
   && [ "$aliveC" = "yes" ] && echo "$STO" | grep -qE "(up|up but degraded|running but not responding) \(pid $DPID\)"; then
  ok "gateC: a copied config dir sees no daemon, and its down leaves the original running"
else
  bad "gateC: copied config dir acted on the original's daemon (status rc=$rcC, original alive=$aliveC)"
fi
env FILAMENT_CONFIG_DIR="$DS" timeout 15 "$BIN" down -y >/dev/null 2>&1

# ===================================================================== GATE Z ==
say "Z: status after down says not running and exits 11"
STZ=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status 2>&1); rcZ=$?
STZJ=$(env FILAMENT_CONFIG_DIR="$DS" timeout 20 "$BIN" status --json 2>/dev/null); rcZJ=$?
echo "## status rc=$rcZ, status --json rc=$rcZJ"; echo "$STZ" | head -1 | sed 's/^/    /'
if [ "$rcZ" = "11" ] && echo "$STZ" | grep -q "not running" && [ "$rcZJ" = "11" ] \
   && echo "$STZJ" | "$PYV" -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get("running") is False else 1)'; then
  ok "gateZ: no daemon is exit 11, as text and as --json (running:false)"
else
  bad "gateZ: status with no daemon (rc=$rcZ, --json rc=$rcZJ)"
fi

# ===================================================================== GATE J ==
say "J: status --json says what the exit code says, for a frozen and a stopped daemon"
# `ok` used to be true, with exit 0, for both: a script gating on
# `status --json` went ahead against a daemon the plain `status` called down.
# Now `ok` is false, `error.exit` repeats the code, and the process exits with
# it; the frozen daemon's proxy is not reported as running.
jcheck() {  # $1 = json, $2 = rc, $3 = want exit, $4 = want error code
  printf '%s' "$1" | "$PYV" -c '
import sys, json
d = json.load(sys.stdin)
rc, want, tok = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
err = d.get("error") or {}
proxy = d.get("proxy")
ok = (rc == want and d.get("ok") is False and err.get("exit") == want
      and err.get("code") == tok and not (isinstance(proxy, dict) and proxy.get("running")))
sys.exit(0 if ok else 1)' "$2" "$3" "$4"
}
echo "## frozen: --json rc=${rcPJ:-unset}"; printf '%s\n' "${STPJ:-}" | head -12 | sed 's/^/    /'
echo "## stopped: --json rc=$rcZJ"; printf '%s\n' "$STZJ" | head -6 | sed 's/^/    /'
if jcheck "${STPJ:-}" "${rcPJ:-0}" 6 unreachable && jcheck "$STZJ" "$rcZJ" 11 not_running; then
  ok "gateJ: status --json is ok:false with the exit code (6 frozen, 11 stopped), never ok:true"
else
  bad "gateJ: status --json disagrees with its exit code (frozen rc=${rcPJ:-unset}, stopped rc=$rcZJ)"
fi

# ===================================================================== GATE L ==
say "L: a config path past PATH_MAX names the length"
DL="$WORK/cfg-long"; for _ in $(seq 1 22); do DL="$DL/$(printf 'L%.0s' $(seq 1 200))"; done
outL=$(env FILAMENT_CONFIG_DIR="$DL" timeout 30 "$BIN" --server "$SERVER" up --detach 2>&1); rcL=$?
echo "## config path ${#DL} bytes; up rc=$rcL"; echo "$outL" | tail -2 | cut -c1-300 | sed 's/^/    /'
if [ "$rcL" != "0" ] && echo "$outL" | grep -q "too long" && ! echo "$outL" | grep -q "writable?"; then
  ok "gateL: the failure names the path length, not writability"
else
  bad "gateL: over-long config path (rc=$rcL)"
fi

# ===================================================================== GATE X ==
say "X: the auto SOCKS5 proxy reports the port it actually bound"
# Hold 127.0.0.1:1080 (another daemon on this box may already hold it, which is
# the same situation), then start a userspace-L3 daemon whose auto-proxy wants
# 1080. It used to announce 1080 anyway and bind nothing.
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 1080)); s.listen(4)
except OSError:
    pass
time.sleep(120)
" >/dev/null 2>&1 &
pids+=($!)
sleep 1
DX="$WORK/cfg-socks"; mkdir -p "$DX"
env FILAMENT_CONFIG_DIR="$DX" "$BIN" init --name socksy --recovery-file "$WORK/socks-rec.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DX" "$BIN" set l3-mode userspace >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DX" "$BIN" set auto-proxy on >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DX" timeout 30 "$BIN" --server "$SERVER" up --detach --dir "$WORK/socks-drop" >/dev/null 2>&1
for _ in $(seq 1 20); do grep -q "SOCKS5 proxy" "$DX/daemon.log" 2>/dev/null && break; sleep 0.5; done
grep -i "socks5" "$DX/daemon.log" 2>/dev/null | sed 's/^/    /' | head -5
if grep -qE "started SOCKS5 proxy on 127\.0\.0\.1:10(8[1-9]) \(1080 was taken\)" "$DX/daemon.log" 2>/dev/null \
   && ! grep -q "SOCKS5 proxy on 127.0.0.1:1080 " "$DX/daemon.log" 2>/dev/null; then
  ok "gateX: with 1080 held, the auto-proxy says the port it really bound"
else
  bad "gateX: auto-proxy port report"
  tail -15 "$DX/daemon.log" 2>/dev/null
fi
FILAMENT_CONFIG_DIR="$DX" timeout 15 "$BIN" down -y >/dev/null 2>&1

# ============================================= transfer fixture (D, W, N) ======
# Owner A runs a daemon; B joins A's fleet and receives into a tiny disk.
DA="$WORK/cfg-A"; DB="$WORK/cfg-B"; mkdir -p "$DA" "$DB"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name boxA --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/A-drop" >"$WORK/A-up.log" 2>&1 &
ADAEMON=$!; pids+=($ADAEMON)
sleep 3
env FILAMENT_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for boxB --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1
env FILAMENT_CONFIG_DIR="$DB" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" --name boxB --no-interactive >"$WORK/join.log" 2>&1
# The sends below are one-shots from A, as in transport-gates.sh: A's daemon
# was only needed to admit the join.
kill "$ADAEMON" 2>/dev/null; sleep 2
if ! FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q boxB; then
  echo "setup: boxB did not join"; tail -5 "$WORK/add.log" "$WORK/join.log"
fi
FULL="$WORK/tiny"; mount_small "$FULL" 2m
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$FULL" >"$WORK/B-up.log" 2>&1 &
pids+=($!)
sleep 4

# ===================================================================== GATE D ==
say "D: a file larger than the receiver's free space"
head -c 3000000 /dev/urandom >"$WORK/three.bin"
outD=$(env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/three.bin" --to boxB 2>&1); rcD=$?
echo "## send rc=$rcD"; echo "$outD" | tail -8 | sed 's/^/    /'
leftD=$(ls -A "$FULL" 2>/dev/null | tr '\n' ' ')
if [ "$rcD" = "4" ] && echo "$outD" | grep -q "out of disk space" && echo "$outD" | grep -q "needs" \
   && ! echo "$outD" | grep -qi "checksum\|corrupt\|may have gotten nothing" && [ -z "$leftD" ]; then
  ok "gateD: refused up front, exit 4, names out of disk space with sizes, nothing left behind"
else
  bad "gateD: full-disk send (rc=$rcD, left on disk: [$leftD])"
  tail -8 "$WORK/B-up.log"
fi

# ===================================================================== GATE W ==
say "W: ENOSPC part way through is out of disk space, not corruption"
head -c 1500000 /dev/urandom >"$WORK/w1.bin"; head -c 1500000 /dev/urandom >"$WORK/w2.bin"
outW=$(env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/w1.bin" "$WORK/w2.bin" --to boxB 2>&1); rcW=$?
echo "## send rc=$rcW"; echo "$outW" | tail -8 | sed 's/^/    /'
if [ "$rcW" = "4" ] && echo "$outW" | grep -q "out of disk space" \
   && ! grep -qi "checksum still wrong" "$WORK/B-up.log" && ! ls "$FULL"/*.part >/dev/null 2>&1; then
  ok "gateW: two files that do not fit together: out of disk space (exit 4), no corrupt verdict, no partial left"
else
  bad "gateW: ENOSPC mid-transfer (rc=$rcW)"
  tail -8 "$WORK/B-up.log"
fi
rm -f "$FULL"/* 2>/dev/null

# ===================================================================== GATE N ==
say "N: a 250-character file name"
LONGNAME="$(printf 'n%.0s' $(seq 1 246)).bin"
mkdir -p "$WORK/longsrc"
head -c 1000 /dev/urandom >"$WORK/longsrc/$LONGNAME" 2>/dev/null || cp "$WORK/w1.bin" "$WORK/longsrc/x.bin"
outN=$(env FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$WORK/longsrc/$LONGNAME" --to boxB 2>&1); rcN=$?
echo "## send rc=$rcN"; echo "$outN" | tail -5 | sed 's/^/    /'
gotN=$(ls "$FULL" 2>/dev/null | grep '\.bin$' | head -1)
echo "## landed as: ${gotN:-(nothing)} (${#gotN} bytes)"
if [ "$rcN" = "0" ] && [ -n "$gotN" ] && [ "${#gotN}" -le 240 ] && [ "${#gotN}" -ge 200 ]; then
  ok "gateN: long name saved, shortened to ${#gotN} bytes with its extension kept"
else
  bad "gateN: long file name (rc=$rcN, landed=[${gotN}])"
  tail -8 "$WORK/B-up.log"
fi

# ===================================================================== GATE O ==
say "O: add --out onto a full disk"
OUTDISK="$WORK/outdisk"; mount_small "$OUTDISK" 1m; fill_up "$OUTDISK"
outO=$(env FILAMENT_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for ghost --out "$OUTDISK/inv.txt" --yes 2>&1); rcO=$?
echo "## add rc=$rcO"; echo "$outO" | tail -4 | sed 's/^/    /'
if [ "$rcO" != "0" ] && [ ! -e "$OUTDISK/inv.txt" ] && echo "$outO" | grep -qi "no space\|could not write"; then
  ok "gateO: add --out on a full disk prints the error and leaves no partial file"
else
  bad "gateO: add --out on a full disk (rc=$rcO, file left: $([ -e "$OUTDISK/inv.txt" ] && echo yes || echo no))"
fi

# ===================================================================== GATE T ==
say "T: a settings write on a full disk leaves no temp file"
CFGDISK="$WORK/cfgdisk"; mount_small "$CFGDISK" 1m
DT="$CFGDISK/filament"
env FILAMENT_CONFIG_DIR="$DT" "$BIN" set auto-extract on >/dev/null 2>&1
fill_up "$CFGDISK"
outT=$(env FILAMENT_CONFIG_DIR="$DT" "$BIN" set auto-extract off 2>&1); rcT=$?
temps=$(ls -A "$DT" 2>/dev/null | grep '\.tmp\.' | tr '\n' ' ')
echo "## set rc=$rcT temps=[$temps]"; echo "$outT" | tail -3 | sed 's/^/    /'
if [ "$rcT" != "0" ] && [ -z "$temps" ]; then
  ok "gateT: failed settings write left no config.tmp.<pid>"
else
  bad "gateT: settings write on a full disk (rc=$rcT, temps=[$temps])"
fi

# ===================================================================== GATE I ==
say "I: init under a read-only parent leaves no orphan recovery file"
RO="$WORK/rohome"; mkdir -p "$RO"; chmod 555 "$RO"
outI=$(env FILAMENT_CONFIG_DIR="$RO/filament" "$BIN" init --name ro --recovery-file "$WORK/ro-rec.txt" --yes 2>&1); rcI=$?
chmod 755 "$RO"
echo "## init rc=$rcI"; echo "$outI" | tail -3 | sed 's/^/    /'
if [ "$rcI" != "0" ] && [ ! -e "$WORK/ro-rec.txt" ] && [ ! -e "$RO/filament/identity.ed25519" ]; then
  ok "gateI: failed init wrote neither an identity nor an orphan recovery phrase"
else
  bad "gateI: init on a read-only parent (rc=$rcI, phrase file left: $([ -e "$WORK/ro-rec.txt" ] && echo yes || echo no))"
fi

# ===================================================================== GATE H ==
say "H: up --detach with a HOME that does not exist names the path"
# Under / so it cannot be created by this (non-root) user: a HOME under $WORK
# would simply be created, which is not the case being tested.
NOHOME="/nonexistent-tunlion-home-$$"
outH=$(env -u FILAMENT_CONFIG_DIR -u XDG_CONFIG_HOME HOME="$NOHOME" timeout 30 "$BIN" --server "$SERVER" up --detach 2>&1); rcH=$?
echo "## up rc=$rcH"; echo "$outH" | tail -3 | sed 's/^/    /'
if [ "$rcH" != "0" ] && echo "$outH" | grep -q "$NOHOME"; then
  ok "gateH: the failure names the path it could not create"
else
  bad "gateH: nonexistent HOME (rc=$rcH)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "hostile-env gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
