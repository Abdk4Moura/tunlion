#!/usr/bin/env bash
# Worker-only real-process proof: owner withdrawal kills the matching exec/PTY
# tree, not another sibling's terminal or the target's inbox/link.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:?TUNLION_BIN must name the exact-head worker binary}"
PORT=${PORT:-8137}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
# This proof is about terminal authorization and withdrawal, not the transport
# race that carries it. Pin the fixture to the supported WebRTC path so a
# direct-QUIC sibling stall is reported by the fleet-automesh gates that own it,
# not as a terminal failure here. The session is still authenticated by the
# daemon-brokered private secret before any open is sent.
# `TUNLION_DIRECT=0` alone is not enough: a long-lived acceptor forces the
# direct rung on to avoid glare, so the test-hooks build exposes the explicit
# no-direct switch this worker binary is built with.
export TUNLION_DIRECT=0
export TUNLION_TEST_NO_DIRECT=1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fleet-terminal-cut.XXXXXX")"
DA="$WORK/alpha"
source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
# Which sources produced this run. A gate failure that names its exact tree is
# reproducible; one that says only which assertion fired is not.
SOURCE_HASHES="$WORK/source-hashes.txt"
{
    printf 'head=%s\n' "$(git -C "$CLI_DIR/.." rev-parse HEAD 2>/dev/null || echo unknown)"
    sha256sum "$(readlink -f "$0")" "$HERE/lib/fixture.sh" \
        "$CLI_DIR/../crates/filament-peerloop/src/shell_gate.rs"
} > "$SOURCE_HASHES"
cat "$SOURCE_HASHES"
as_node() {
    local node=$1
    shift
    env HOME="$WORK/home-$node" TUNLION_CONFIG_DIR="$WORK/$node" "$BIN" --server "$SERVER" "$@"
}
wait_file() {
    local path=$1
    for _ in $(seq 1 60); do [ -s "$path" ] && return 0; sleep 0.5; done
    return 1
}
# The cold one-shot path resolves a fleet sibling through the index record a
# verified fleet-hello writes. A roster NAME alone is not dialable. Wait for
# that record, then exercise the same terminal path with a one-shot `true`
# instead of trusting a reach liveness ping: the warm ping is a separate
# liveness surface and its failure does not mean the terminal cannot open.
fleet_indexed() {
    python3 - "$WORK/$1/devices.json" <<'PY'
import json,sys
try: arr=json.load(open(sys.argv[1]))
except (OSError,ValueError): raise SystemExit(1)
assert any(d.get('name')=='charlie' and not d.get('secret') for d in arr)
PY
}
wait_terminal_path() {
    local node=$1
    local _ attempt
    for _ in $(seq 1 60); do
        fleet_indexed "$node" && break
        sleep 0.5
    done
    fleet_indexed "$node" || return 1
    for attempt in 1 2 3; do
        fs_bounded 20 as_node "$node" exec charlie -- true \
            >"$WORK/$node-preflight.log" 2>&1
        if [ "$(fs_state)" = ok ] && [ "$(fs_rc)" = 0 ]; then
            ok "$node: terminal path to charlie answered before controls"
            return 0
        fi
        # Authority refusals are not a readiness race: report them at once.
        if grep -qiE 'refus|denied|no grant|ceiling|not authorized' "$WORK/$node-preflight.log"; then
            return 1
        fi
        sleep 1
    done
    return 1
}
# Failure evidence lives here because the job's sealed artifact has only this
# transcript. Print the per-process stderr/stdout and both daemons' decisions,
# never a device secret.
node_facts() {
    local node=$1
    python3 - "$WORK/$node/devices.json" "$WORK/$node/settings.json" <<'PY'
import json,sys
try: arr=json.load(open(sys.argv[1]))
except (OSError,ValueError) as e:
    print('devices unreadable:', e); arr=[]
print('devices:', json.dumps([{
    'name': d.get('name'), 'hasSecret': bool(d.get('secret')),
    'devicePub': ((d.get('deviceCert') or {}).get('devicePub') or '')[:16],
    'principalKind': d.get('principalKind'),
    'principalCeiling': d.get('principalCeiling'),
    'certRevoked': d.get('certRevoked'),
} for d in arr]))
try:
    s=json.load(open(sys.argv[2]))
except (OSError,ValueError):
    s={}
print('fleet.owner_grants:', s.get('fleet.owner_grants'))
PY
}
diagnose() {
    local why=$1
    local node f
    {
        echo "===== TERMINAL DIAGNOSTICS: $why"
        echo "work=$WORK"
        echo "--- source"; cat "$SOURCE_HASHES" 2>/dev/null
        echo "--- work directory"; ls -la "$WORK" 2>/dev/null
        echo "--- per-process output"
        for f in "$WORK"/*.err "$WORK"/*.out "$WORK"/*-preflight.log "$WORK"/*-reach.json "$WORK"/*-reach.err; do
            [ -f "$f" ] || continue
            echo "### ${f##*/}"; tail -80 "$f"
        done
        echo "--- daemon logs"
        for f in "$WORK"/up-*.log "$WORK"/backend.log; do
            [ -f "$f" ] || continue
            echo "### ${f##*/}"; tail -120 "$f"
        done
        echo "--- node facts"
        for node in bravo charlie delta; do
            echo "### $node"; node_facts "$node"
        done
        echo "--- live processes"
        ps -eo pid,ppid,stat,etimes,args | grep -E 'tunlion|fleet-terminal-cut' | grep -v grep | head -40
        echo "===== END TERMINAL DIAGNOSTICS"
    } >&2
}
start_terminal() {
    local node=$1 mode=$2 tag=$3
    local command="echo \$\$ > '$WORK/$tag.child'; while :; do echo '$tag-ALIVE'; sleep 1; done"
    if [ "$mode" = exec ]; then
        as_node "$node" exec charlie -- sh -c "$command"
    else
        as_node "$node" shell charlie -- "$command"
    fi
}
for node in alpha bravo charlie delta; do mkdir -p "$WORK/home-$node" "$WORK/$node-drop"; done
export HOME="$WORK/home-alpha"
start_backend
init_owner "$DA"
start_acceptor "$DA"
for node in bravo charlie delta; do enroll_delegate "$node" --allow transfer,mount,shell; done
# Premise: the terminal is not refused or admitted by the enrollment ceiling.
# Every participant's invited ceiling includes shell, so the only remaining
# authorization fact these controls can be measuring is the owner grant.
python3 - "$WORK/alpha/devices.json" <<'PY'
import json,sys
arr=json.load(open(sys.argv[1]))
for name in ('bravo','charlie','delta'):
    rec=next(d for d in arr if d.get('name')==name)
    assert 'shell' in (rec.get('principalCeiling') or []), name
PY
ok "premise: every terminal participant's invitation ceiling includes shell"
as_node charlie set fleet.owner_grants all >/dev/null || fixture_die "target owner grant policy setup"
for node in bravo charlie delta; do
    env HOME="$WORK/home-$node" TUNLION_CONFIG_DIR="$WORK/$node" TUNLION_L2=1 TUNLION_LOG=debug \
        "$BIN" --server "$SERVER" up --dir "$WORK/$node-drop" >"$WORK/up-$node.log" 2>&1 &
    FIX_PIDS+=($!)
done
for mode in exec pty; do
    as_node alpha grant bravo shell --on charlie >"$WORK/$mode-grant-bravo.log" 2>&1 || fixture_die "grant bravo"
    as_node alpha grant delta shell --on charlie >"$WORK/$mode-grant-delta.log" 2>&1 || fixture_die "grant delta"
    # Wait for delivery, not an arbitrary post-command sleep. The local grant
    # file is the target's held receiver fact, not the owner's recorded intent.
    delivered=0
    for _ in $(seq 1 60); do
        if python3 - "$WORK/charlie/fleet-grants-held.json" <<'PY'
import json,sys
try: held=json.load(open(sys.argv[1]))
except (OSError,ValueError): raise SystemExit(1)
assert len([g for g in held['grants'] if g['cap']=='shell'])==2
PY
        then delivered=1; break; fi
        sleep 0.5
    done
    [ "$delivered" = 1 ] || fixture_die "$mode: both owner shell grants not delivered"
    # A delegated device carries its invitation ceiling into every gate, so a
    # terminal scenario enrolls the whole participating fleet with shell in the
    # ceiling. The owner's per-device grant below is still the only thing that
    # authorizes these terminals: the ceiling is a cap, not a grant.
    for node in bravo delta; do
        wait_terminal_path "$node" || {
            diagnose "$mode: $node has no working terminal path to charlie"
            fixture_die "$mode: $node has no working terminal path to charlie"
        }
    done
    start_terminal bravo "$mode" "$mode-match" >"$WORK/$mode-match.out" 2>"$WORK/$mode-match.err" &
    matching=$!; FIX_PIDS+=("$matching")
    start_terminal delta "$mode" "$mode-control" >"$WORK/$mode-control.out" 2>"$WORK/$mode-control.err" &
    control=$!; FIX_PIDS+=("$control")
    if ! wait_file "$WORK/$mode-match.child" || ! wait_file "$WORK/$mode-control.child"; then
        diagnose "$mode: terminal positive controls before withdrawal"
        fixture_die "$mode: terminal positive controls failed before withdrawal"
    fi
    match_child=$(cat "$WORK/$mode-match.child")
    control_child=$(cat "$WORK/$mode-control.child")
    # A healthy owner-granted terminal must survive the existing 5s recheck.
    sleep 6
    kill -0 "$match_child" 2>/dev/null && kill -0 "$control_child" 2>/dev/null \
        || fixture_die "$mode: healthy terminal falsely ended at recheck"
    ok "$mode: both authenticated owner-granted terminal trees survive recheck"
    as_node alpha revoke bravo shell --on charlie >"$WORK/$mode-withdraw.log" 2>&1 \
        || fixture_die "$mode: owner withdrawal failed"
    # Same 12s bound as existing PTY revocation gates, no timeout widening.
    # The target's held grant set is the receiver fact a running session
    # rechecks, so wait for both that removal and the child's exit in one bound.
    cleared=0
    for _ in $(seq 1 24); do
        if [ "$cleared" = 0 ] && python3 - "$WORK/alpha/devices.json" "$WORK/charlie/fleet-grants-held.json" <<'PY'
import json,sys
try:
    recs=json.load(open(sys.argv[1]))
    held=json.load(open(sys.argv[2]))
except (OSError,ValueError):
    raise SystemExit(1)
pub={d['name']: (d.get('deviceCert') or {}).get('devicePub') for d in recs}
subjects={g.get('subject_pub') for g in held.get('grants') or [] if g.get('cap')=='shell'}
assert pub['bravo'] not in subjects and pub['delta'] in subjects
PY
        then cleared=1; fi
        kill -0 "$match_child" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$match_child" 2>/dev/null; then
        bad "$mode: matching terminal child survived owner withdrawal"
    else
        ok "$mode: matching terminal child was terminated within 12s"
    fi
    if [ "$cleared" = 1 ]; then
        ok "$mode: target holds no shell grant for the withdrawn subject"
    else
        bad "$mode: target still holds the withdrawn subject's shell grant"
    fi
    # The ceiling still includes shell, so the terminated session proves the
    # owner grant was the authorizing fact, not the enrollment ceiling.
    python3 - "$WORK/alpha/devices.json" <<'PY'
import json,sys
recs=json.load(open(sys.argv[1]))
rec=next(d for d in recs if d.get('name')=='bravo')
assert 'shell' in (rec.get('principalCeiling') or [])
PY
    ok "$mode: matching terminal ended while its shell ceiling remained"
    if kill -0 "$control_child" 2>/dev/null && kill -0 "$control" 2>/dev/null; then
        ok "$mode: unrelated sibling terminal remains active"
    else
        bad "$mode: withdrawal ended unrelated sibling terminal"
    fi
    if kill -0 "$matching" 2>/dev/null; then
        bad "$mode: initiator did not acknowledge terminal closure"
    else
        wait "$matching"; rc=$?
        if [ "$rc" != 0 ] && grep -q "access revoked" "$WORK/$mode-match.err"; then
            ok "$mode: initiator reports nonzero access-revoked closure"
        else
            bad "$mode: closure missing nonzero scoped reason (rc=$rc)"
        fi
    fi
    echo "$mode-inbox-control" > "$WORK/$mode-inbox.txt"
    fs_cli 60 as_node bravo send "$WORK/$mode-inbox.txt" --to charlie
    if [ "$(fs_rc)" = 0 ] && cmp -s "$WORK/$mode-inbox.txt" "$WORK/charlie-drop/$mode-inbox.txt"; then
        ok "$mode: terminal withdrawal preserves matching peer inbox access"
    else
        bad "$mode: terminal withdrawal disturbed unrelated inbox access"
    fi
    # End only the control terminal's owned tree before testing the next kind.
    kill "$control_child" 2>/dev/null || true
    kill "$control" 2>/dev/null || true
    wait "$control" 2>/dev/null || true
done
if [ "$FAIL" != 0 ]; then
    diagnose "gate failures:$FAILED"
fi
printf 'fleet terminal withdrawal: %s passed, %s failed; evidence=%s\n' "$PASS" "$FAIL" "$WORK"
[ "$FAIL" = 0 ]
