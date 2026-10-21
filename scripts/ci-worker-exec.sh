#!/usr/bin/env bash
# Run another job on the ACTIVE reusable worker. Never provisions a machine.
# Usage: bash scripts/ci-worker-exec.sh cargo --version
#        bash scripts/ci-worker-exec.sh bash -c 'cd jobs/pairing-ux; cargo test ...'
set -euo pipefail
if [ "$#" = 0 ] || [ "${1:-}" = --help ]; then
  sed -n '2,4p' "$0"
  if [ "$#" = 0 ]; then exit 2; fi
  exit 0
fi
exec tunlion exec "${TUNLION_CI_WORKER:-ci-worker-dovm}" \
  --env HOME=/home/runner \
  --env PATH=/home/runner/work/_temp/bin:/home/runner/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -- bash -c '
    set -euo pipefail
    source /home/runner/work/_temp/tunlion-work/worker.env
    cd "$TUNLION_WORKER_ROOT"
    # Keep the lock in flock itself, not in background fixtures/daemons spawned
    # by the job. Otherwise an orphan child can pin the entire shared queue.
    exec flock --close "$TUNLION_WORKER_ROOT/build.lock" "$@"
  ' worker-job "$@"
