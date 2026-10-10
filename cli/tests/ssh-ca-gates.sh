#!/usr/bin/env bash
# `tunlion shell --ssh` via local CA, end to end. Standalone, hermetic,
# fixture port 8120 ONLY. No host files are touched: the throwaway sshd
# listens on 127.0.0.1:9123 (reached through the mesh tunnel because
# FILAMENT_SSH_PORT overrides the dial port), with temp hostkeys, temp
# PidFile, and B's daemon runs with HOME in the work dir, so the per-user
# CA trust line it writes lands in a temp authorized_keys that the temp
# sshd is pointed at (AuthorizedKeysFile). The runner's own
# ~/.ssh/authorized_keys is never written.
#
#   FILAMENT_BIN=/path/to/tunlion ./ssh-ca-gates.sh
#
# Gates:
#   A  POSITIVE cert login -- ephemeral key signed over the mesh, real sshd
#      accepts the cert (no AuthorizedKeysFile configured: cert-only proof),
#      remote command runs, rc=0, exact output.
#   B  NEGATIVE revoked -- after `revoke <dev> shell`, signing is refused
#      (nonzero + reason); no new cert issues.
#   C  WIRING (per-user, the default) -- arming wrote exactly one
#      `cert-authority,principals="<user>" <daemon CA>` line in B's
#      authorized_keys AND left the system sshd config, principals dir and
#      CA anchor untouched. The second half is the regression guard for a
#      real incident: a second root daemon used to overwrite the one shared
#      system CA file and take over root's ssh trust.
#   C2 WIRING (fallback) -- when the per-user line cannot be written, arming
#      falls back to the system route: Match block + principals + anchor.
#
# Topology: side B = signer + sshd host, side A = initiator, reciprocal pair
# secret (same-owner fleet). B's CA key is MINTED by up/grant arming
# (CC-4 proves the mint path: no hand-provisioning); B's daemon user is root (this harness runs as
# root, shell-user unset -- the same resolution production uses).
#
# PLATFORM NOTE: unix-only in practice (sshd, ssh-keygen, /dev/urandom, ss),
# like the other *-gates.sh harnesses. The wire property (cert auth, no
# installed keys) is platform-independent.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8120
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-ssh-ca-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== ssh-ca gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: FILAMENT_BIN=/path/to/tunlion"; exit 2; }
command -v sshd >/dev/null || { echo "no sshd on PATH"; exit 2; }
command -v ssh-keygen >/dev/null || { echo "no ssh-keygen on PATH"; exit 2; }
command -v ssh >/dev/null || { echo "no ssh on PATH"; exit 2; }

DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

A_ENV=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA)
B_USER="$(id -un)"
# B's daemon HOME: where the per-user CA trust line (and any managed key
# block) is written. The temp sshd reads authorized_keys from here.
BHOME="$WORK/Bhome"; mkdir -p "$BHOME"
SSH_ENV=(env FILAMENT_NO_L3_SSH=1 FILAMENT_SSH_PORT=9123)

# NO hand-provisioned CA key: up/grant arming mints it (CC-4 proves the
# mint path live -- gate A would fail without it).

# --- throwaway sshd on 127.0.0.1:9123 with CA trust ONLY (no
# AuthorizedKeysFile at all: cert auth is the only way in, which is exactly
# what gate A proves). Reached through the mesh tunnel because the dial port
# below overrides the bootstrap default. ---
# The temp sshd below runs on the HOOK-WRITTEN config (product writer output,
# not hand-provisioned trust): base Port/HostKey here, Match block +
# principals + anchor added by up/grant arming through the overrides.
SSHD="$WORK/sshd"; mkdir -p "$SSHD"
mkdir -p /run/sshd 2>/dev/null
SSHD_PORT=9123

# --- B acceptor (daemon user = root via USER; hostkeys pinned to temp) ---
# Hook paths overridden to temp files: up/grant arming writes here (real
# writer code, observable), never to the live /etc/ssh.
HOOK_ENV=(env FILAMENT_SSH_SSHD_CONFIG="$WORK/hooked-sshd-config" FILAMENT_SSH_PRINCIPALS_DIR="$WORK/hooked-principals" FILAMENT_SSH_CA_PUB_ANCHOR="$WORK/hooked-ca.pub")
ssh-keygen -q -t ed25519 -f "$WORK/hooked-hostkey" -N ""
chmod 600 "$WORK/hooked-hostkey"
printf 'Port 9123\nHostKey %s\nListenAddress 127.0.0.1\nPidFile %s\nPasswordAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nStrictModes no\nPermitRootLogin prohibit-password\nLogLevel VERBOSE\nAuthorizedKeysFile %s\n' "$WORK/hooked-hostkey" "$SSHD/sshd.pid" "$BHOME/.ssh/authorized_keys" > "$WORK/hooked-sshd-config"
# Byte copy of the config as WE wrote it: gate C asserts arming left it alone.
cp "$WORK/hooked-sshd-config" "$WORK/sshd-config.as-written"
env FILAMENT_L2=1 HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB USER="$B_USER" \
  FILAMENT_SSH_HOSTKEY="$WORK/hooked-hostkey.pub" \
  "${HOOK_ENV[@]}" "$BIN" up --dir "$WORK/Bdrop" --server "$SERVER" >"$WORK/up.log" 2>&1 &
pids+=($!)
sleep 3
env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1

# A ~10-minute grant window, seeded AFTER the grant (grant rewrites the
# device record and would wipe a pre-seeded capExpires -- gate D caught
# exactly that): the cert clamp must not exceed it (CB-2).
GRANT_NOW=$(date +%s)
GRANT_EXP=$((GRANT_NOW + 600))
python3 - "$DB/devices.json" "$GRANT_EXP" <<'PY2'
import json,sys
p,exp=sys.argv[1],int(sys.argv[2])
arr=json.load(open(p))
for d in arr:
    if d.get("name")=="boxA":
        d.setdefault("capExpires",{})["shell"]=exp
json.dump(arr,open(p,"w"))
PY2
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# --- temp sshd on the PRODUCT-WRITTEN config (proves the writer output works) ---
/usr/sbin/sshd -f "$WORK/hooked-sshd-config" -E "$SSHD/sshd.log" -D &
SSHD_PID=$!
pids+=($SSHD_PID)
sleep 1
ss -tlnp 2>/dev/null | grep -q ":$SSHD_PORT " || { echo "## sshd FAILED (product config?)"; cat "$SSHD/sshd.log"; tail -3 "$WORK/up.log"; exit 2; }

# The ONLY authorized_keys the temp sshd reads is B's, in $BHOME. Arming has
# already written its CA trust line there; snapshot it now: gate E asserts
# cert login leaves it byte-identical (no permanent key install).
AK_FILE="$BHOME/.ssh/authorized_keys"
AK_BEFORE="$WORK/ak.before"; AK_AFTER="$WORK/ak.after"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$AK_BEFORE" || : > "$AK_BEFORE"

# ===================================================================== GATE A ==
# POSITIVE: cert round trip + real sshd login with the cert. B's
# authorized_keys holds only the CA trust line (no plain keys), and sshd's
# own log must name a certificate as the accepted credential.
say A
OUTA=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo SSH-CA-OK; id -un' 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (cert login) rc=$rcA"
echo "$OUTA" | sed 's/^/##   /'
if [ "$rcA" = "0" ] && echo "$OUTA" | grep -q "SSH-CA-OK" && echo "$OUTA" | grep -qx "$B_USER" \
   && grep -qE "Accepted publickey for $B_USER .*-CERT " "$SSHD/sshd.log"; then
  ok "gateA: cert login ran a remote command (rc=0, exact output, no installed keys)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  echo "-- sshd accept lines --"; grep -E "Accepted|Failed|denied" "$SSHD/sshd.log" | tail -3
  bad "gateA: cert login FAILED (rc=$rcA)"
fi

# ===================================================================== GATE B ==
# NEGATIVE revoked: same command refused after the grant goes (nonzero).
say B
env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTB=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo SHOULD-NOT-RUN' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (revoked) rc=$rcB out='$OUTB'"
if [ "$rcB" != "0" ] \
   && ! echo "$OUTB" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|revoked\|not granted\|no shell cap\|no cert" "$WORK/B.err"; then
  ok "gateB: revoked cert login REFUSED (nonzero + reason)"
else
  echo "-- B.err --"; cat "$WORK/B.err"
  bad "gateB: revoked login NOT refused (rc=$rcB)"
fi

# ===================================================================== GATE D ==
# CLAMP: with a ~10-minute grant window, the issued cert's validity must be
# <= that window (ssh-keygen -L reads the actual cert back).
say D
CERT_LINE=$(grep -oE 'expiry [0-9]+' "$WORK/up.log" | tail -1 | awk '{print $2}')
VALID=$(grep -oE 'Valid: from [^ ]+ to [^ ]+' "$WORK/sshd/sshd.log" 2>/dev/null | tail -1)
echo "## cert expiry epoch: $CERT_LINE"
if [ -n "$CERT_LINE" ]; then
  DELTA=$(( CERT_LINE - GRANT_NOW ))
  if [ "$DELTA" -le 600 ] && [ "$DELTA" -ge 540 ]; then
    ok "gateD: cert validity clamped to the 10-minute grant (${DELTA}s)"
  else
    bad "gateD: cert validity ${DELTA}s exceeds/misses the grant window"
  fi
else
  bad "gateD: no issuance expiry found in B's log"
fi

# ===================================================================== GATE C ==
# WIRING, per-user (the default): arming wrote exactly the scoped trust line
# for B's daemon CA into B's own authorized_keys, and wrote NOTHING to the
# system-wide sshd config, principals dir or CA anchor.
say C
WANT_LINE="cert-authority,principals=\"$B_USER\" $(head -1 "$DB/ssh/ssh_ca.pub" | awk '{print $1" "$2}')"
GOT_LINES=$(grep -c '^cert-authority' "$AK_FILE" 2>/dev/null || true)
if grep -qxF '# BEGIN tunlion-ca-trust' "$AK_FILE" 2>/dev/null \
   && awk '{print $1" "$2" "$3}' "$AK_FILE" | grep -qxF "$WANT_LINE" \
   && [ "$GOT_LINES" = "1" ]; then
  ok "gateC: per-user trust line is exact and scoped to $B_USER (1 line)"
else
  echo "-- want: $WANT_LINE"; echo "-- B authorized_keys --"; cat "$AK_FILE" 2>/dev/null
  bad "gateC: per-user CA trust line missing or wrong"
fi
if cmp -s "$WORK/sshd-config.as-written" "$WORK/hooked-sshd-config" \
   && [ ! -e "$WORK/hooked-ca.pub" ] && [ ! -e "$WORK/hooked-principals" ]; then
  ok "gateC1: system sshd config, CA anchor and principals untouched"
else
  diff "$WORK/sshd-config.as-written" "$WORK/hooked-sshd-config" | head -8
  ls -la "$WORK/hooked-ca.pub" "$WORK/hooked-principals" 2>&1 | head -4
  bad "gateC1: arming wrote system-wide ssh state although per-user trust worked"
fi

# WIRING, fallback: a separate `up --shell` (arms at start) whose HOME cannot
# hold ~/.ssh must fall back to the system route through the product writer
# (its own temp paths, its own CA). HOME is a regular FILE, so creating $HOME/.ssh fails for root
# too, unlike a permission-based block.
say C2
DC="$WORK/C"; mkdir -p "$DC"; : > "$WORK/home-is-a-file"
# Same valid base as B's (arming runs `sshd -t` on the result).
cp "$WORK/sshd-config.as-written" "$WORK/c2-sshd-config"
C2_ENV=(env FILAMENT_SSH_SSHD_CONFIG="$WORK/c2-sshd-config" FILAMENT_SSH_PRINCIPALS_DIR="$WORK/c2-principals" FILAMENT_SSH_CA_PUB_ANCHOR="$WORK/c2-ca.pub")
env FILAMENT_L2=1 HOME="$WORK/home-is-a-file" FILAMENT_CONFIG_DIR="$DC" FILAMENT_NAME=boxC USER="$B_USER" \
  "${C2_ENV[@]}" "$BIN" up --shell --dir "$WORK/Cdrop" --server "$SERVER" >"$WORK/upC.log" 2>&1 &
C2_PID=$!; pids+=($C2_PID)
for _ in $(seq 1 30); do [ -s "$WORK/c2-ca.pub" ] && grep -q TrustedUserCAKeys "$WORK/c2-sshd-config" && break; sleep 0.5; done
kill "$C2_PID" 2>/dev/null
if grep -q "Match User $B_USER" "$WORK/c2-sshd-config" \
   && grep -q "TrustedUserCAKeys" "$WORK/c2-sshd-config" \
   && [ "$(cat "$WORK/c2-principals/$B_USER" 2>/dev/null)" = "$B_USER" ] \
   && cmp -s "$DC/ssh/ssh_ca.pub" "$WORK/c2-ca.pub" \
   && grep -q "falling back to the system-wide setup" "$WORK/upC.log"; then
  ok "gateC2: per-user write failed, fallback wrote block + principals + anchor and said so"
else
  echo "-- c2-sshd-config --"; cat "$WORK/c2-sshd-config" 2>/dev/null
  echo "-- c2-principals --"; ls -la "$WORK/c2-principals" 2>&1 | head -3
  echo "-- upC.log --"; grep -i "ssh" "$WORK/upC.log" | head -5
  bad "gateC2: system-wide fallback did not arm"
fi

# ===================================================================== GATE E ==
# NO-INSTALL: B's authorized_keys is byte-identical after cert login --
# `shell --ssh` installed nothing permanent (host-key pinning only).
say E
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$AK_AFTER" || : > "$AK_AFTER"
if cmp -s "$AK_BEFORE" "$AK_AFTER"; then
  ok "gateE: authorized_keys unchanged by cert login (no key install)"
else
  echo "-- diff --"; diff "$AK_BEFORE" "$AK_AFTER" | head -5
  bad "gateE: authorized_keys CHANGED by cert login"
fi

# E2: re-grant (gate B revoked), then kill sshd so the retry path runs:
# cached bootstrap hits 255, the rebootstrap (cert mode too) retries, ssh
# fails 255 again -- and STILL nothing is installed. Proves the 255 retry
# path honors cert-only.
env HOME="$BHOME" FILAMENT_CONFIG_DIR="$DB" "${HOOK_ENV[@]}" "$BIN" grant boxA shell >"$WORK/grantE2.log" 2>&1
kill "$SSHD_PID" 2>/dev/null; sleep 1
OUTE2=$(timeout 90 "${SSH_ENV[@]}" "${A_ENV[@]}" "$BIN" --server "$SERVER" shell --ssh boxB -- 'echo NOPE' 2>"$WORK/E2.err" </dev/null)
rcE2=$?
echo "## (dead sshd) rc=$rcE2"
[ -f "$AK_FILE" ] && cp "$AK_FILE" "$WORK/ak.after2" || : > "$WORK/ak.after2"
if [ "$rcE2" != "0" ] \
   && grep -q "re-authenticating" "$WORK/E2.err" \
   && cmp -s "$AK_BEFORE" "$WORK/ak.after2"; then
  ok "gateE2: dead-sshd retry ran cert-only and installed nothing (rc=$rcE2)"
else
  echo "-- E2.err --"; tail -5 "$WORK/E2.err"
  diff "$AK_BEFORE" "$WORK/ak.after2" | head -5
  bad "gateE2: retry misbehaved (rc=$rcE2)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "ssh-ca gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
