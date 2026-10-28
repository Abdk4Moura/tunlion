#!/usr/bin/env bash
# The Linux end of .github/workflows/windows-native-overlay.yml: a throwaway
# owner with a kernel L3 daemon and an HTTP server on its overlay addresses, so
# the Windows box can prove NATIVE traffic (its own HTTP client, its own source
# address, the Wintun adapter) rather than a tunlion proxy.
#
#   $1 = start|wait   $2 = tunlion binary   $3 = work dir (evidence: $3/evidence)
#
# `start` brings the owner, its daemon and the HTTP server up (they keep running
# into later steps) and writes the one-claim invitation to $3/invite, which the
# workflow publishes as a run artifact. `wait` deletes that artifact once the
# Windows box has claimed it (GH_TOKEN, actions: write) and exits 0 only when the
# Windows box fetched /done, i.e. it reached the end of its acceptance.
set -uo pipefail
MODE="$1"; BIN="$2"; WORK="$3"
EV="$WORK/evidence"; CFG="$WORK/config"; WWW="$WORK/www"; INV="$WORK/invite"
mkdir -p "$EV" "$CFG" "$WWW" "$INV"
# Everything runs as root with this run's private config dir: the kernel TUN
# needs CAP_NET_ADMIN, and one owner for every file keeps the daemon and the CLI
# reading the same state. Disposable runner, no --shell, nothing touches sshd.
T() { sudo env TUNLION_CONFIG_DIR="$CFG" TUNLION_COLOR=never "$BIN" "$@"; }
PEER_NAME="${PEER_NAME:-ci-linux-owner}"; WIN_NAME="${WIN_NAME:-win-native}"
REPO="${GITHUB_REPOSITORY:?}"; RUN="${GITHUB_RUN_ID:?}"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$EV/peer.log"; }
die() { log "FAIL: $*"; tail -60 "$EV/daemon.log" 2>/dev/null; exit 1; }

T --version | tee -a "$EV/peer.log"
if [ "$MODE" = start ]; then
T init --name "$PEER_NAME" --recovery-file "$WORK/rec.txt" --yes >>"$EV/peer.log" 2>&1 || die "init"
T set l3-mode kernel >>"$EV/peer.log" 2>&1 || die "set l3-mode kernel"

nohup sudo env TUNLION_CONFIG_DIR="$CFG" TUNLION_COLOR=never "$BIN" up --dir "$WORK/drop" \
  >"$EV/daemon.log" 2>&1 </dev/null &
ready=""
for _ in $(seq 1 90); do
  j=$(T addr --json 2>/dev/null) || true
  if printf '%s' "$j" | python3 -c 'import json,sys; d=json.load(sys.stdin); l=d.get("l3") or (d.get("data") or {}).get("l3") or {}; sys.exit(0 if l.get("state")=="ready" and l.get("mode")=="kernel" else 1)' 2>/dev/null; then
    ready=1; break
  fi
  sleep 2
done
printf '%s\n' "$j" > "$EV/addr-json.txt"
[ -n "$ready" ] || die "kernel L3 never became ready: $j"
V4=$(T addr --v4 2>/dev/null | tr -d '[:space:]'); V6=$(T addr 2>/dev/null | tr -d '[:space:]')
[ -n "$V4" ] && [ -n "$V6" ] || die "no overlay addresses (v4='$V4' v6='$V6')"
log "overlay v4=$V4 v6=$V6"
ip -4 addr show dev tunlion0 >>"$EV/peer.log" 2>&1; ip -6 addr show dev tunlion0 >>"$EV/peer.log" 2>&1
ip route show dev tunlion0 >>"$EV/peer.log" 2>&1; ip -6 route show dev tunlion0 >>"$EV/peer.log" 2>&1

# The body the Windows box must fetch byte for byte.
TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf 'tunlion-native-overlay %s\n' "$TOKEN" > "$WWW/token.txt"
printf 'done\n' > "$WWW/done"
( cd "$WWW" && nohup python3 -m http.server 8766 --bind :: >"$EV/http.log" 2>&1 </dev/null & )
sleep 1
# Dual-stack bind (:: with v4-mapped) so the v4 and v6 overlay addresses both answer.
curl -fsS --max-time 5 "http://$V4:8766/token.txt" >/dev/null || die "local HTTP on $V4 not answering"
curl -fsS --max-time 5 -g "http://[$V6]:8766/token.txt" >/dev/null || die "local HTTP on $V6 not answering"

# One claim, two hours: the Windows box is the only intended holder.
T add --for device --name "$WIN_NAME" --expires 2h --out "$INV/win.key" --yes >>"$EV/peer.log" 2>&1 || die "add --for device"
printf '%s\n' "$V4" > "$INV/peer-v4.txt"; printf '%s\n' "$V6" > "$INV/peer-v6.txt"
printf '%s\n' "$PEER_NAME" > "$INV/peer-name.txt"
sha256sum "$WWW/token.txt" | cut -d' ' -f1 > "$INV/token.sha256"
sudo chown -R "$(id -u):$(id -g)" "$INV"
log "invitation written; the workflow publishes it"
exit 0
fi

claimed=""; finished=""
deadline=$(( $(date +%s) + 100*60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  pgrep -f "$BIN up" >/dev/null || die "daemon exited"
  if [ -z "$claimed" ] && T devices 2>/dev/null | grep -q "$WIN_NAME"; then
    claimed=1; log "claimed by $WIN_NAME"
    ids=$(gh api "repos/$REPO/actions/runs/$RUN/artifacts" --jq ".artifacts[] | select(.name==\"native-overlay-invite-$RUN\") | .id")
    for id in $ids; do gh api -X DELETE "repos/$REPO/actions/artifacts/$id" && log "invitation artifact $id deleted"; done
  fi
  if grep -q 'GET /done' "$EV/http.log" 2>/dev/null; then finished=1; break; fi
  # The Windows job's evidence upload is its last step: if it exists and /done
  # never came, the Windows side ended without reaching us. Stop waiting.
  if gh api "repos/$REPO/actions/runs/$RUN/artifacts" --jq '.artifacts[].name' 2>/dev/null | grep -qx "native-overlay-windows-$RUN"; then
    sleep 5; grep -q 'GET /done' "$EV/http.log" 2>/dev/null && finished=1; break
  fi
  sleep 10
done
T devices >>"$EV/peer.log" 2>&1
grep -E 'GET ' "$EV/http.log" | sed 's/^/  http: /' | tee -a "$EV/peer.log"
pkill -f 'http.server 8766' 2>/dev/null; sudo pkill -f "$BIN up" 2>/dev/null
[ -n "$finished" ] || die "the Windows box never reached /done"
log "Windows acceptance reached /done"
