#!/usr/bin/env bash
# Dashboard gates: `tunlion dashboard` against the real binary. The dashboard
# is a screen served by this device on 127.0.0.1, so the gates drive its HTTP
# surface the way a browser (and an attacker on the same machine) would.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/dashboard-gates.sh
#
# Gates:
#   H  a request naming another Host (DNS rebinding) is refused 403, and the
#      page itself is served with a script-src 'self' policy.
#   O  a session request from another Origin, or with no Origin, is refused.
#   S  a wrong secret is refused; the right one gives an HttpOnly,
#      SameSite=Strict cookie; the same secret a second time is refused.
#   A  the API answers only with the session cookie, and reports this device.
#   W  actions take only stored devices and shaped values: an unknown device,
#      a flag in the device slot, and an unknown verb are refused 400.
#   I  an invitation made through the dashboard comes back once and leaves no
#      file behind; the person who joins with it appears as a device.
#   G  grant and revoke through the dashboard change what the gate allows,
#      exactly as `tunlion grant`/`revoke` do.
#   X  the dashboard closes when the background service it started beside
#      stops.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8186
DPORT=8291
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-dash.XXXXXX")"
export TUNLION_NONINTERACTIVE=1

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend

DA="$WORK/a"; DB="$WORK/b"
trap 'fixture_cleanup; env TUNLION_CONFIG_DIR="$DA" "$BIN" down -y >/dev/null 2>&1' EXIT
init_owner "$DA"
t() { local d="$1"; shift; env TUNLION_CONFIG_DIR="$d" "$BIN" --server "$SERVER" "$@"; }
t "$DA" up --detach >"$WORK/up.log" 2>&1 || { echo "up --detach failed"; cat "$WORK/up.log"; exit 2; }

env TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" dashboard --no-open --port "$DPORT" >"$WORK/dash.log" 2>&1 &
DASH=$!; FIX_PIDS+=($DASH)
SECRET=""
for _ in $(seq 1 40); do SECRET=$(grep -oE '#k=[0-9a-f]{64}' "$WORK/dash.log" | head -1 | cut -c4-); [ -n "$SECRET" ] && break; sleep 0.25; done
[ -n "$SECRET" ] || { echo "dashboard printed no link"; cat "$WORK/dash.log"; exit 2; }
B="http://127.0.0.1:$DPORT"
ORIGIN="Origin: http://127.0.0.1:$DPORT"
code() { curl -s -o "$WORK/body" -D "$WORK/head" -w '%{http_code}' "$@"; }

# ---------------------------------------------------------------------- H --
say "H: Host must name this listener; the page carries a strict policy"
h1=$(code -H "Host: evil.example:$DPORT" "$B/api/state")
h2=$(code "$B/")
csp=$(grep -i '^content-security-policy:' "$WORK/head" | tr -d '\r')
echo "## rebinding Host -> $h1, page -> $h2, $csp"
if [ "$h1" = 403 ] && [ "$h2" = 200 ] && echo "$csp" | grep -q "script-src 'self'" && echo "$csp" | grep -q "frame-ancestors 'none'"; then
  ok "H: another Host is refused and the page is served with script-src 'self'"
else
  bad "H host check ($h1/$h2)"
fi

# ---------------------------------------------------------------------- O --
say "O: a session request from another site, or with no Origin, is refused"
o1=$(code -X POST -H 'Origin: https://evil.example' -H 'Content-Type: application/json' --data "{\"secret\":\"$SECRET\"}" "$B/api/session")
o2=$(code -X POST -H 'Content-Type: application/json' --data "{\"secret\":\"$SECRET\"}" "$B/api/session")
echo "## cross-origin -> $o1, no origin -> $o2"
if [ "$o1" = 403 ] && [ "$o2" = 403 ]; then ok "O: cross-site and Origin-less session requests are refused (and did not spend the secret)"; else bad "O origin check ($o1/$o2)"; fi

# ---------------------------------------------------------------------- S --
say "S: the secret works once"
s1=$(code -X POST -H "$ORIGIN" -H 'Content-Type: application/json' --data "{\"secret\":\"$(printf '0%.0s' $(seq 64))\"}" "$B/api/session")
s2=$(code -X POST -H "$ORIGIN" -H 'Content-Type: application/json' --data "{\"secret\":\"$SECRET\"}" "$B/api/session")
cookie=$(grep -i '^set-cookie:' "$WORK/head" | tr -d '\r')
TOKEN=$(echo "$cookie" | grep -oE 'tl_dash=[0-9a-f]+' | cut -d= -f2)
s3=$(code -X POST -H "$ORIGIN" -H 'Content-Type: application/json' --data "{\"secret\":\"$SECRET\"}" "$B/api/session")
echo "## wrong -> $s1, right -> $s2 ($cookie), again -> $s3"
if [ "$s1" = 401 ] && [ "$s2" = 200 ] && [ -n "$TOKEN" ] && echo "$cookie" | grep -q HttpOnly && echo "$cookie" | grep -q 'SameSite=Strict' && [ "$s3" = 401 ]; then
  ok "S: wrong secret refused, the right one gives an HttpOnly SameSite=Strict cookie, a second use is refused"
else
  bad "S secret exchange ($s1/$s2/$s3)"
fi
CK="Cookie: tl_dash=$TOKEN"

# ---------------------------------------------------------------------- A --
say "A: the API needs the session"
a1=$(code "$B/api/state")
a2=$(code -H "$CK" "$B/api/state")
name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["me"]["name"])' "$WORK/body" 2>/dev/null)
echo "## no cookie -> $a1, cookie -> $a2 (me=$name)"
if [ "$a1" = 401 ] && [ "$a2" = 200 ] && [ "$name" = alpha ]; then ok "A: no cookie is refused; with it the state names this device (alpha)"; else bad "A session ($a1/$a2/$name)"; fi

act() { code -X POST -H "$ORIGIN" -H "$CK" -H 'Content-Type: application/json' --data "$1" "$B/api/act"; }

# ---------------------------------------------------------------------- W --
say "W: actions take only stored devices and shaped values"
w1=$(act '{"verb":"grant","device":"nobody","cap":"shell"}')
w2=$(act '{"verb":"grant","device":"--all","cap":"shell"}')
w3=$(act '{"verb":"reset"}')
echo "## unknown device -> $w1, flag as device -> $w2, unknown verb -> $w3"
if [ "$w1" = 400 ] && [ "$w2" = 400 ] && [ "$w3" = 400 ]; then ok "W: unknown device, a flag in the device slot and an unknown verb are refused"; else bad "W whitelist ($w1/$w2/$w3)"; fi

# ---------------------------------------------------------------------- I --
say "I: an invitation comes back once, leaves no file, and the joiner appears"
i1=$(code -X POST -H "$ORIGIN" -H "$CK" -H 'Content-Type: application/json' --data '{"kind":"person","name":"dana","allow":["transfer"],"expires":"3d"}' "$B/api/invite")
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open(sys.argv[2],"w").write(d.get("invitation") or ""); print("ok" if d.get("ok") else d)' "$WORK/body" "$WORK/dana.invite" >"$WORK/i.out"
chmod 600 "$WORK/dana.invite"
left=$(ls "$DA" | grep -c '^dashboard-invite-' || true)
mkdir -p "$DB"
fs_bounded 60 env TUNLION_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" join "$WORK/dana.invite" --name dana -y >"$WORK/join.log" 2>&1
jr=$(fs_rc)
sleep 2
code -H "$CK" "$B/api/state" >/dev/null
has=$(python3 -c 'import json,sys; print(any(d["name"]=="dana" for d in json.load(open(sys.argv[1]))["devices"]))' "$WORK/body" 2>/dev/null)
echo "## invite -> $i1 $(cat "$WORK/i.out"), leftover files: $left, join rc=$jr, dana listed: $has"
if [ "$i1" = 200 ] && grep -q ok "$WORK/i.out" && [ -s "$WORK/dana.invite" ] && [ "$left" = 0 ] && [ "$jr" = 0 ] && [ "$has" = True ]; then
  ok "I: the invitation came back once, no file was left, and dana joined and is listed"
else
  bad "I invitation ($i1, left $left, join $jr, listed $has)"; cat "$WORK/join.log"
fi

# ---------------------------------------------------------------------- G --
say "G: grant and revoke through the dashboard change what the gate allows"
eff() { env TUNLION_CONFIG_DIR="$DA" "$BIN" devices --caps dana --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["devices"][0]; print(any(c["action"]=="shell" and c["effective"] for c in d["caps"]))'; }
g0=$(eff)
g1=$(act '{"verb":"grant","device":"dana","cap":"shell"}'); g1b=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ok"])' "$WORK/body")
ga=$(eff)
g2=$(act '{"verb":"revoke-cap","device":"dana","cap":"shell"}'); g2b=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ok"])' "$WORK/body")
gb=$(eff)
echo "## shell before=$g0, grant $g1/$g1b -> $ga, revoke $g2/$g2b -> $gb"
if [ "$g0" = False ] && [ "$g1b" = True ] && [ "$ga" = True ] && [ "$g2b" = True ] && [ "$gb" = False ]; then
  ok "G: grant made shell effective for dana and revoke removed it"
else
  bad "G grant/revoke ($g0 -> $ga -> $gb)"; cat "$WORK/body"
fi

# ---------------------------------------------------------------------- X --
say "X: the dashboard closes when the background service stops"
t "$DA" down -y >"$WORK/down.log" 2>&1
gone=no
for _ in $(seq 1 40); do kill -0 "$DASH" 2>/dev/null || { gone=yes; break; }; sleep 0.25; done
echo "## dashboard exited after down: $gone"; tail -n 2 "$WORK/dash.log"
if [ "$gone" = yes ] && grep -q "background service stopped" "$WORK/dash.log"; then
  ok "X: the dashboard closed within 10 s of tunlion down, and said why"
else
  bad "X close on daemon stop"; kill "$DASH" 2>/dev/null
fi

echo
echo "== dashboard gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
