#!/usr/bin/env bash
# Ratchet for the deterministic core (#249 item 1, #34).
#
# gates.sh does not currently pass in full: at the time of writing 12 of 22
# report PASS and the rest have named, tracked causes. Two dishonest ways to get
# a green tick from that were rejected:
#
#   continue-on-error  a step that reports success while proving nothing, which
#                      is the exact defect #249 exists to fix
#   a pass-count floor a run can hit "12 passed" with a DIFFERENT twelve, so the
#                      number says nothing about which behaviour still holds
#
# Instead this asserts, by name, that every gate KNOWN to work still works. A
# regression in any of them fails the build. A still-broken gate does not,
# because it was already broken and this job is not where that gets discovered.
#
# When a red gate is repaired, add it to EXPECTED_GREEN in the same commit. The
# list only ever grows; that is the ratchet. Removing an entry needs a reason in
# the commit message, because it means a behaviour that used to hold no longer
# does.
#
# MEASURE THE LIST WHERE THE RATCHET RUNS. The first version of this list was
# measured on the do-vm host and asserted against GitHub runners, and one gate
# differed: "kill-resume: replacement receiver resumed" passes locally and fails
# on a runner. It is deliberately NOT in the list below. The kill half works
# there (the .part reached 20336640 bytes, so the gate's premise held); it is
# the resume half that does not, which makes it environment-sensitive rather
# than deterministic by construction, and an environment-sensitive gate in this
# list makes the job fail for reasons that are not regressions.
#
# It is a candidate to add back once it is understood, not a gate to quietly
# drop. Tracked in #249.
#
# Matching is on a stable SUBSTRING of each gate's ok() text, deliberately not
# the whole line: some carry a measured value ("22.8 MB/s") that varies per run,
# and pinning those would make this fail for the wrong reason.
set -uo pipefail

LOG="${1:-}"
[ -n "$LOG" ] && [ -r "$LOG" ] || { echo "usage: gates-ratchet.sh <gates-output.log>" >&2; exit 2; }

EXPECTED_GREEN=(
  "unit tests"
  "pair-code variance/security tests"
  "code transfer, hashes match"
  "code burns on first use"
  "head mismatch detected, restarted from 0"
  "dir tar + stdin round-trip"
  "offer declined without consent"
  "transferred + hash match within ceiling"
  "active link preserved across same-uid reconnect"
  "deferred drop: flowing link survives its peer-left"
  "stepped-away sender: held"
)

missing=0
for want in "${EXPECTED_GREEN[@]}"; do
  if grep -aq "^PASS:.*$want" "$LOG"; then
    printf '  ok       %s\n' "$want"
  else
    printf '  REGRESSED %s\n' "$want"
    missing=$((missing + 1))
  fi
done

green=$(grep -ac '^PASS:' "$LOG" || true)
red=$(grep -ac '^FAIL:' "$LOG" || true)
printf '\n%s of %s expected-green gates held; run reported %s PASS / %s FAIL\n' \
  "$(( ${#EXPECTED_GREEN[@]} - missing ))" "${#EXPECTED_GREEN[@]}" "$green" "$red"

if [ "$missing" -gt 0 ]; then
  echo "FAIL: $missing gate(s) that used to pass no longer do. That is a regression, not a known-red gate." >&2
  exit 1
fi
echo "ratchet held. Known-red gates remain red and are tracked in #249; this job does not police them."
