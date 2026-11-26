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
#   2. build the test-hooks binary with the `fuzz` profile (Cargo.toml) in one
#      STABLE source dir and one target dir on the worker, so a small edit
#      rebuilds in seconds, not the minutes a fat-LTO release build takes
#   3. copy that binary into the job dir and record its sha256: the shared
#      target can be rebuilt by another job mid-run, and chaos.py asserts the
#      hash before every schedule
#   4. run chaos.py as root (namespaces, tc, iptables); it runs every daemon as
#      the unprivileged runner user
#   5. bring the results back as a tarball under ./chaos-results/<sha>-<mode>/
set -euo pipefail
# Bash reads a script while it runs it, so editing this file during a campaign
# breaks the running copy (it did, on 2026-11-25). Run from a private copy.
if [ -z "${CHAOS_SELF_COPY:-}" ]; then
  self=$(mktemp)
  cp "$0" "$self"
  CHAOS_SELF_COPY=1 CHAOS_ORIG="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" exec bash "$self" "$@"
fi
WORKER=${1:?worker device name}; MODE=${2:?canary|replay|explore}; shift 2
ROOT=$(git -C "$(dirname "${CHAOS_ORIG:-$0}")" rev-parse --show-toplevel)
SHA=$(git -C "$ROOT" rev-parse --short=12 HEAD)
if [ -n "$(git -C "$ROOT" status --porcelain -- fuzz cli crates backend)" ]; then
  echo "uncommitted changes under fuzz/ cli/ crates/ backend/: commit first, the run must name a SHA" >&2
  exit 2
fi
# The binary depends only on cli/, crates/, Cargo.lock and the root Cargo.toml
# (which holds the profiles), so a fuzz-only change reuses the cached binary.
TREE=$(git -C "$ROOT" rev-parse HEAD:cli HEAD:crates HEAD:Cargo.lock HEAD:Cargo.toml | sha256sum | cut -c1-16)
# CHAOS_PROFILE: `fuzz` (default) rebuilds incrementally in seconds; `release`
# is the shipped fat-LTO build, for confirming a finding against it.
PROFILE=${CHAOS_PROFILE:-fuzz}
case "$PROFILE" in *[!a-z0-9_-]*|"") echo "bad CHAOS_PROFILE: $PROFILE" >&2; exit 2;; esac
TREE="$TREE-$PROFILE"
PUP=$(printf '%s' "$PROFILE" | tr a-z- A-Z_)
# CHAOS_SYMBOLS=1: keep line tables and skip strip, so a wedged daemon's
# thread dump names functions. The fuzz profile already does both, so there it
# changes nothing; for release it is a different binary, so a different key.
SYMS=""
if [ "${CHAOS_SYMBOLS:-0}" = 1 ] && [ "$PROFILE" != fuzz ]; then
  TREE="$TREE-syms"
  SYMS="CARGO_PROFILE_${PUP}_STRIP=false CARGO_PROFILE_${PUP}_DEBUG=line-tables-only"
fi
# CHAOS_FEATURES: extra cargo features on top of test-hooks. Part of the key.
FEATURES="test-hooks"
if [ -n "${CHAOS_FEATURES:-}" ]; then
  case "$CHAOS_FEATURES" in *[!a-zA-Z0-9_,\ /-]*) echo "bad CHAOS_FEATURES: $CHAOS_FEATURES" >&2; exit 2;; esac
  FEATURES="test-hooks ${CHAOS_FEATURES//,/ }"
  TREE="$TREE-f$(printf '%s' "$FEATURES" | tr ' ' '\n' | sort -u | sha256sum | cut -c1-8)"
fi
# CHAOS_RUSTFLAGS, e.g. "--cfg tokio_unstable" for async task dumps. Part of
# the key, and it gets its own target dir: RUSTFLAGS changes every unit, so
# sharing one dir with the plain build would rebuild everything on each switch.
RFKEY=""
if [ -n "${CHAOS_RUSTFLAGS:-}" ]; then
  RFKEY=$(printf '%s' "$CHAOS_RUSTFLAGS" | sha256sum | cut -c1-8)
  TREE="$TREE-$RFKEY"
fi
JOB="chaos-$SHA-$MODE-$(date +%s)-$$"   # pid: two runs started in the same second must not share a job dir
TAR=$(mktemp -d)/"$JOB.tar"
git -C "$ROOT" archive --format=tar HEAD -o "$TAR"
echo "== ship $SHA ($(du -h "$TAR" | cut -f1)) to $WORKER"
tunlion send "$TAR" --to "$WORKER" --timeout 240 --json >/dev/null
rm -f "$TAR"; rmdir "$(dirname "$TAR")" 2>/dev/null || true   # 43 MB per run; they filled /tmp

ARGS=""
[ "$#" -gt 0 ] && printf -v ARGS '%q ' "$@"
REMOTE=$(cat <<EOF
set -euo pipefail
source /home/runner/work/_temp/tunlion-work/worker.env
root="\$TUNLION_WORKER_ROOT"
inbox="\$root/$JOB.tar"
[ -f "\$inbox" ] || { echo "shipped tarball not found at \$inbox" >&2; exit 2; }
job="\$root/jobs/$JOB"; mkdir -p "\$job"; tar -xf "\$inbox" -C "\$job"
cached="\$root/chaos-bins/$TREE/tunlion"
if [ -x "\$cached" ]; then
  echo "== reusing binary built for product tree $TREE"
else
  # ONE source dir and ONE target dir for every run on this worker. rsync
  # --checksum without --times rewrites only files whose CONTENT changed (they
  # get a fresh mtime) and leaves every other file, and its old mtime, alone,
  # so cargo recompiles exactly the crates this commit touched. Never copy the
  # archive's mtimes in: they are the commit time, which can be older than the
  # last build, and cargo would then keep a stale binary.
  src="\$root/src-stable"
  tgt="\${CARGO_TARGET_DIR:-\$root/cargo-target}"
  [ -z "$RFKEY" ] || tgt="\$tgt-rf-$RFKEY"
  # No linker override: rustc already links x86_64 Linux with its bundled
  # rust-lld, and mold measured no faster on this binary (21.7 s vs 21.9 s).
  rf=${CHAOS_RUSTFLAGS:+$(printf '%q' "$CHAOS_RUSTFLAGS")}
  (
    flock 9
    mkdir -p "\$src"
    rsync -rlc --delete "\$job/" "\$src/"
    cd "\$src/cli"
    t0=\$(date +%s)
    [ -z "\$rf" ] || export RUSTFLAGS="\$rf"
    env CARGO_TARGET_DIR="\$tgt" CARGO_BUILD_JOBS="\$(nproc)" $SYMS \
      cargo build --features "$FEATURES" --profile $PROFILE 2>&1 | tail -3
    echo "== built $PROFILE in \$(( \$(date +%s) - t0 ))s (target \$tgt)"
    mkdir -p "\$root/chaos-bins/$TREE"
    cp "\$tgt/$PROFILE/tunlion" "\$cached.tmp" && mv "\$cached.tmp" "\$cached"
  ) 9>"\$root/build.lock"
fi
cp "\$cached" "\$job/tunlion-under-test"
sha256sum "\$job/tunlion-under-test"
python3 -m venv "\$root/chaos-venv" 2>/dev/null || true
command -v gdb >/dev/null || sudo apt-get install -y -qq gdb >/dev/null 2>&1 || echo "gdb unavailable: thread dumps without function names"
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
# The essentials (verdicts, findings with their logs, grown corpus) in a small
# tarball fetched first: the exec channel can drop a long stream, and losing
# the per-run records must never cost the findings.
( cd "\$job" && tar -czf out-essential.tgz --ignore-failed-read \$(cd "\$job" && ls -d out/summary.json out/throughput.json out/replay-rates.json out/canary.json out/hookcheck.json out/findings out/corpus-grown 2>/dev/null) )
echo "CHAOS_OUT=\$job/out.tgz"
echo "CHAOS_OUT_ESSENTIAL=\$job/out-essential.tgz"
EOF
)
LOG="$ROOT/chaos-results/$JOB.log"; mkdir -p "$ROOT/chaos-results"
echo "== run $MODE on $WORKER (log: $LOG)"
WENV=(--env HOME=/home/runner --env PATH=/home/runner/work/_temp/bin:/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)
tunlion exec "$WORKER" "${WENV[@]}" -- bash -c "$REMOTE" 2>&1 | tee "$LOG"
OUT=$(grep -oP '^CHAOS_OUT=\K.*' "$LOG" | tail -1)
RC=$(grep -oP '^CHAOS_RC=\K\d+' "$LOG" | tail -1)
ESS=$(grep -oP '^CHAOS_OUT_ESSENTIAL=\K.*' "$LOG" | tail -1)
if [ -n "$OUT" ]; then
  DEST="$ROOT/chaos-results/$JOB"; mkdir -p "$DEST"
  if [ -n "$ESS" ]; then
    tunlion exec "$WORKER" -- base64 -w0 "$ESS" | base64 -d | tar --no-same-owner -xz -C "$DEST" \
      && echo "== findings and summary in $DEST" \
      || echo "== could not fetch the essentials; they stay on $WORKER at $ESS"
  fi
  tunlion exec "$WORKER" -- base64 -w0 "$OUT" | base64 -d | tar --no-same-owner -xz -C "$DEST" 2>/dev/null \
    && echo "== full results in $DEST" \
    || echo "== full results did not come back whole (the exec stream dropped); they stay on $WORKER at $OUT"
fi
exit "${RC:-3}"
