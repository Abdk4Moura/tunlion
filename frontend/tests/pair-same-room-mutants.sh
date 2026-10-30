#!/usr/bin/env bash
# Mutant check for pair-same-room.spec.cjs: each half of the fix alone must
# pass the gate, and with BOTH halves reverted the gate must fail. Restores
# frontend/src and rebuilds dist at the end. Run from the repo root.
#   PSR_RUNS=5 bash frontend/tests/pair-same-room-mutants.sh
set -u
F=frontend/src/lib/useTunlion.js
SKIP='if (!shouldRejoinOnPairMatched(roomIdRef.current, room)) {'
GRACE='}, PEER_LEFT_GRACE_MS)'
grep -qF "$SKIP" "$F" || { echo "mutant: skip guard not found"; exit 2; }
grep -qF "$GRACE" "$F" || { echo "mutant: grace timer not found"; exit 2; }

# skip: the claimer always leaves and re-joins; grace: the creator fails at once.
mutate() {
  python3 - "$F" "$1" "$SKIP" "$GRACE" <<'PY'
import sys
p, which, skip, grace = sys.argv[1:]
s = open(p).read()
old, new = (skip, 'if (false) {') if which == 'skip' else (grace, '}, 0)')
assert s.count(old) == 1, which
open(p, 'w').write(s.replace(old, new))
PY
}
build() { (cd frontend && VITE_TUNLION_API= npm run build >/dev/null 2>&1); }
run() {
  PSR_ENGINES=${PSR_ENGINES:-chromium} TUNLION_TEST_VENV=${TUNLION_TEST_VENV:-python3} \
    node frontend/tests/pair-same-room.spec.cjs >"/tmp/psr-$1.log" 2>&1
  echo $?
}

bad=0
for m in grace-only skip-only neither; do
  git checkout -q -- "$F"
  case $m in
    grace-only) mutate skip ;;
    skip-only) mutate grace ;;
    neither) mutate skip; mutate grace ;;
  esac
  build
  rc=$(run "$m")
  ok=$(grep -c 'paired in' "/tmp/psr-$m.log")
  failed=$(grep -c 'RUN FAILED' "/tmp/psr-$m.log")
  echo "mutant $m: exit $rc, paired $ok, failed $failed"
  grep -m3 'RUN FAILED' "/tmp/psr-$m.log" | cut -c1-200
  if [ "$m" = neither ]; then
    [ "$rc" != 0 ] || { echo "MUTANT SURVIVED: reverting both halves still passes"; bad=1; }
  else
    [ "$rc" = 0 ] || { echo "half $m alone does not fix it"; bad=1; }
  fi
done
git checkout -q -- "$F"
build
exit $bad
