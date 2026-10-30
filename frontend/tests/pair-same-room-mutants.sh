#!/usr/bin/env bash
# Mutant check for pair-same-room.spec.cjs: with the fix reverted (the
# creator fails the ceremony on the claimer's peer-left at once, as before),
# the gate must FAIL; with the fix it must pass. Restores frontend/src and
# rebuilds dist at the end. Run from the repo root.
#   PSR_RUNS=5 bash frontend/tests/pair-same-room-mutants.sh
set -u
F=frontend/src/lib/useTunlion.js
GRACE='}, PEER_LEFT_GRACE_MS)'
grep -qF "$GRACE" "$F" || { echo "mutant: grace timer not found"; exit 2; }

mutate() {
  python3 - "$F" "$GRACE" <<'PY'
import sys
p, grace = sys.argv[1:]
s = open(p).read()
assert s.count(grace) == 1
open(p, 'w').write(s.replace(grace, '}, 0)'))
PY
}
build() { (cd frontend && VITE_TUNLION_API= npm run build >/dev/null 2>&1); }
run() {
  PSR_ENGINES=${PSR_ENGINES:-chromium} TUNLION_TEST_VENV=${TUNLION_TEST_VENV:-python3} \
    node frontend/tests/pair-same-room.spec.cjs >"/tmp/psr-$1.log" 2>&1
  echo $?
}

bad=0
for m in fixed reverted; do
  git checkout -q -- "$F"
  [ "$m" = reverted ] && mutate
  build
  rc=$(run "$m")
  ok=$(grep -c 'paired in' "/tmp/psr-$m.log")
  failed=$(grep -c 'RUN FAILED' "/tmp/psr-$m.log")
  echo "$m: exit $rc, paired $ok, failed $failed"
  grep -m3 'RUN FAILED' "/tmp/psr-$m.log" | cut -c1-200
  if [ "$m" = reverted ]; then
    [ "$rc" != 0 ] || { echo "MUTANT SURVIVED: the gate passes with the fix reverted"; bad=1; }
  else
    [ "$rc" = 0 ] || { echo "the gate fails with the fix"; bad=1; }
  fi
done
git checkout -q -- "$F"
build
exit $bad
