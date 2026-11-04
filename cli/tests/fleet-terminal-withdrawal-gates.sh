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
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fleet-terminal-cut.XXXXXX")"
DA="$WORK/alpha"
source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
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
for node in bravo charlie delta; do enroll_delegate "$node"; done
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
    start_terminal bravo "$mode" "$mode-match" >"$WORK/$mode-match.out" 2>"$WORK/$mode-match.err" &
    matching=$!; FIX_PIDS+=("$matching")
    start_terminal delta "$mode" "$mode-control" >"$WORK/$mode-control.out" 2>"$WORK/$mode-control.err" &
    control=$!; FIX_PIDS+=("$control")
    wait_file "$WORK/$mode-match.child" && wait_file "$WORK/$mode-control.child" \
        || fixture_die "$mode: terminal positive controls failed before withdrawal"
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
    for _ in $(seq 1 24); do kill -0 "$match_child" 2>/dev/null || break; sleep 0.5; done
    if kill -0 "$match_child" 2>/dev/null; then
        bad "$mode: matching terminal child survived owner withdrawal"
    else
        ok "$mode: matching terminal child was terminated within 12s"
    fi
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
printf 'fleet terminal withdrawal: %s passed, %s failed; evidence=%s\n' "$PASS" "$FAIL" "$WORK"
[ "$FAIL" = 0 ]
