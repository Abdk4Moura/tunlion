#!/usr/bin/env bash
# Run a chaos campaign on a leased test machine, from the owner box.
#
#   fuzz/chaos/run-on-lease.sh WORKER MODE [chaos.py args...]
#   e.g.  fuzz/chaos/run-on-lease.sh ci-worker-dovm-77 canary
#         fuzz/chaos/run-on-lease.sh ci-worker-dovm-77 replay
#         fuzz/chaos/run-on-lease.sh ci-worker-dovm-77 explore --budget-min 60
#
# WORKER is a machine attached to the fleet for testing (a lease brought up by
# the ci-dogfood workflow in worker mode). It is driven with `tunlion exec`;
# nothing heavy runs on the owner box. Steps:
#   1. ship the COMMITTED source (git archive HEAD, so the run is tied to a SHA)
#   2. build the test-hooks release binary in the worker's warm cargo target
#   3. copy that binary into the job dir and record its sha256: the shared
#      target can be rebuilt by another job mid-run, and chaos.py asserts the
#      hash before every schedule
#   4. run chaos.py as root (namespaces, tc, iptables); it runs every daemon as
#      the unprivileged runner user
#   5. bring the results back as a tarball under ./chaos-results/<sha>-<mode>/
set -euo pipefail
WORKER=${1:?worker device name}; MODE=${2:?canary|replay|explore}; shift 2
ROOT=$(git rev-parse --show-toplevel)
SHA=$(git -C "$ROOT" rev-parse --short=12 HEAD)
if [ -n "$(git -C "$ROOT" status --porcelain -- fuzz cli crates backend)" ]; then
  echo "uncommitted changes under fuzz/ cli/ crates/ backend/: commit first, the run must name a SHA" >&2
  exit 2
fi
JOB="chaos-$SHA-$MODE-$(date +%s)"
TAR=$(mktemp -d)/"$JOB.tar"
git -C "$ROOT" archive --format=tar HEAD -o "$TAR"
echo "== ship $SHA ($(du -h "$TAR" | cut -f1)) to $WORKER"
tunlion send "$TAR" --to "$WORKER" --timeout 240 --json >/dev/null

printf -v ARGS '%q ' "$@"
REMOTE=$(cat <<EOF
set -euo pipefail
source /home/runner/work/_temp/tunlion-work/worker.env
root="\$TUNLION_WORKER_ROOT"
inbox="\$root/$JOB.tar"
[ -f "\$inbox" ] || { echo "shipped tarball not found at \$inbox" >&2; exit 2; }
job="\$root/jobs/$JOB"; mkdir -p "\$job"; tar -xf "\$inbox" -C "\$job"
find "\$job" -type f -exec touch {} +
cd "\$job/cli"
export CARGO_TARGET_DIR="\${CARGO_TARGET_DIR:-\$root/cargo-target}"
flock --close "\$root/build.lock" cargo build --features test-hooks --release 2>&1 | tail -3
cp "\$CARGO_TARGET_DIR/release/tunlion" "\$job/tunlion-under-test"
sha256sum "\$job/tunlion-under-test"
python3 -m venv "\$root/chaos-venv" 2>/dev/null || true
"\$root/chaos-venv/bin/pip" -q install flask==3.1.0 flask-socketio==5.5.1 flask-cors==5.0.1 eventlet==0.39.0
cd "\$job"
set +e
sudo -E env "PATH=\$PATH" python3 -I fuzz/chaos/chaos.py $MODE --bin "\$job/tunlion-under-test" \
  --python "\$root/chaos-venv/bin/python" --out "\$job/out" $ARGS
rc=\$?
set -e
sudo chown -R "\$(id -u):\$(id -g)" "\$job/out"
echo "CHAOS_RC=\$rc"
tar -C "\$job" -czf "\$job/out.tgz" out
echo "CHAOS_OUT=\$job/out.tgz"
EOF
)
LOG="$ROOT/chaos-results/$JOB.log"; mkdir -p "$ROOT/chaos-results"
echo "== run $MODE on $WORKER (log: $LOG)"
WENV=(--env HOME=/home/runner --env PATH=/home/runner/work/_temp/bin:/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)
tunlion exec "$WORKER" "${WENV[@]}" -- bash -c "$REMOTE" 2>&1 | tee "$LOG"
OUT=$(grep -oP '^CHAOS_OUT=\K.*' "$LOG" | tail -1)
RC=$(grep -oP '^CHAOS_RC=\K\d+' "$LOG" | tail -1)
if [ -n "$OUT" ]; then
  DEST="$ROOT/chaos-results/$JOB"; mkdir -p "$DEST"
  tunlion exec "$WORKER" -- base64 -w0 "$OUT" | base64 -d | tar -xz -C "$DEST"
  echo "== results in $DEST"
fi
exit "${RC:-3}"
