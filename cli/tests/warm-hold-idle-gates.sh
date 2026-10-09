#!/usr/bin/env bash
# Warm-hold stability: two paired daemons on loopback whose PETNAMES differ
# from their DISPLAY names (the normal case: petname `boxB`, display
# `user@boxB-host`) must sit on one link and do nothing, while the peer device
# runs ordinary one-shot commands at them now and then. Standalone, hermetic,
# fixture port 8131 ONLY.
#
#   FILAMENT_BIN=/path/to/tunlion ./warm-hold-idle-gates.sh
#
# The defect this pins (deterministic whenever petname != display name):
# warm-hold keyed the device by its roster DISPLAY name, but a direct link is
# named by PETNAME, so the live direct link was never recognised. Every warm
# tick asked for a fresh establish, which dropped the healthy direct link
# without closing its QUIC connection; the peer kept its end, ignored the new
# WebRTC offers, the retry ladder exhausted, and the cycle repeated about
# every 95s forever. The ladder's backoff was also SLEPT on the event loop, so
# control requests waited up to 4s (7-10ms normal) and peer exec stalled.
#
# THE TRAFFIC IS WHAT TRIGGERS IT. Measured: two daemons left completely idle
# on unfixed main pass every zero-count gate below, because the one link they
# form is born under the display name. What the lab ran, and what real use
# looks like, is the peer device issuing one-shot commands: every one-shot is a
# new sid on the shared pair channel under the SAME display name. Those sids
# stayed in the roster forever, warm-hold looked them up by display name,
# dialled the departed ones and tore down the live link. So during the window
# B runs `reach boxA` and `send <file> --to boxA` every 30s, exactly the lab's
# probe loop minus exec (which needs a shell grant), and those round trips must
# succeed quickly too.
#
# Gates (each line below is one PASS):
#   setup     A holds a verified link to boxB, keyed by petname
#   instr     the instrument is present: warm-hold ran during the idle window
#             and logged that it skipped the live link (debug logging is on),
#             so the zero counts below are measurements, not silence
#   estab     zero warm-hold/adoption establishes (`ESTABLISH ... conn.rs`)
#             on either daemon while idle
#   reap      zero "digest reconcile" reaps on either daemon while idle
#   ladder    zero STALL-LADDER lines on either daemon while idle
#   latency   control-socket p99 < 250ms on both daemons, probed with a cheap
#             request (`list-warm`, answered on the event loop) every 0.3s
#   stable    the link to the peer was present in every probe on both sides,
#             under ONE pid (never torn down and rebuilt)
#   traffic   every one-shot round from B during the window succeeded (reach
#             ok, the file landed on A), each command within 15s
#   rtt       a `reach boxB` round trip at the end succeeds within 10s
#
# WHY 180s. In the lab the first wrong establish fired 21s after the first
# one-shot ghost appeared (warm ticks are 10s apart), and the re-dial cycle
# is ~95s. 180s holds five one-shot rounds, 18 warm ticks, nearly two full
# cycles and six 30s digest ticks (the reaper needs two), so every symptom has
# room to show more than once. It fits the Gate Suite's per-gate bound for this
# script with setup (~20s) and the final round trip. Override with
# WARM_IDLE_SECS for a longer local soak.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8131
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-warm-idle.XXXXXX")"
DA="$WORK/A"; DB="$WORK/B"
IDLE_SECS="${WARM_IDLE_SECS:-180}"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend

mkdir -p "$DA" "$DB" "$WORK/Adrop" "$WORK/Bdrop"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

# Display names deliberately differ from the petnames each side stores.
env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME="user@boxA-host" FILAMENT_LOG=debug \
  "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/upA.log" 2>&1 &
FIX_PIDS+=($!)
env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME="user@boxB-host" FILAMENT_LOG=debug \
  "$BIN" --server "$SERVER" up --dir "$WORK/Bdrop" >"$WORK/upB.log" 2>&1 &
FIX_PIDS+=($!)

# The control-socket probe. One request per connection, exactly what a CLI
# command does; the latency is connect-to-reply, so it measures the event
# loop's responsiveness, not process start-up.
cat >"$WORK/probe.py" <<'PY'
import json, socket, sys, time
sock_path, out_path, secs, peer = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
end = time.monotonic() + secs
with open(out_path, "w") as out:
    while time.monotonic() < end:
        t0 = time.monotonic()
        row = {"ms": None, "pids": []}
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(sock_path)
            s.sendall(b'{"op":"list-warm"}\n')
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            s.close()
            row["ms"] = (time.monotonic() - t0) * 1000.0
            reply = json.loads(buf.decode() or "{}")
            # Every held link to the peer: the one-shot commands the peer runs
            # show up here too while they last, beside the daemon's own link.
            row["pids"] = sorted(
                l.get("pid") for l in reply.get("links", [])
                if l.get("name", "").lower() == peer.lower() and l.get("pid")
            )
        except Exception as e:
            row["err"] = str(e)
        out.write(json.dumps(row) + "\n")
        out.flush()
        time.sleep(max(0.0, 0.3 - (time.monotonic() - t0)))
PY

# --- setup: wait (bounded) for A to hold a verified link to boxB -------------
say "setup: link up under the petname"
linked=0
for _ in $(seq 1 60); do
  if python3 "$WORK/probe.py" "$DA/control.sock" "$WORK/once.jsonl" 0.1 boxB 2>/dev/null \
     && grep -q '"pids": \["' "$WORK/once.jsonl"; then
    linked=1; break
  fi
  sleep 1
done
if [ "$linked" = 1 ]; then
  ok "setup: A holds a verified link to petname boxB (display name user@boxB-host)"
else
  echo "-- upA.log (tail) --"; tail -30 "$WORK/upA.log"
  echo "-- upB.log (tail) --"; tail -30 "$WORK/upB.log"
  fixture_die "setup: A never held a link to boxB within 60s"
fi
# Let both ends settle (B's side of the link, the first warm ticks), then mark
# where the idle window starts in each log.
sleep 12
LA0=$(wc -l <"$WORK/upA.log"); LB0=$(wc -l <"$WORK/upB.log")

# --- idle window, probed ------------------------------------------------------
say "idle ${IDLE_SECS}s, probing both control sockets every 0.3s"
python3 "$WORK/probe.py" "$DA/control.sock" "$WORK/probeA.jsonl" "$IDLE_SECS" boxB &
PA=$!
python3 "$WORK/probe.py" "$DB/control.sock" "$WORK/probeB.jsonl" "$IDLE_SECS" boxA &
PB=$!
# The peer device's ordinary use: one-shot commands at A every 30s.
cat >"$WORK/traffic.sh" <<'SH'
#!/usr/bin/env bash
# $1 = rounds. Writes one line per command: "<tag> rc=<rc> ms=<ms>".
for n in $(seq 1 "$1"); do
  t0=$(date +%s%N)
  timeout 15 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" reach boxA --json </dev/null >"$WORK/traffic-reach-$n.out" 2>&1
  rc=$?; t1=$(date +%s%N); echo "reach-$n rc=$rc ms=$(( (t1 - t0) / 1000000 ))"
  printf 'probe %s\n' "$n" >"$WORK/probe-$n.txt"
  t0=$(date +%s%N)
  timeout 15 env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" send "$WORK/probe-$n.txt" --to boxA </dev/null >"$WORK/traffic-send-$n.out" 2>&1
  rc=$?; t1=$(date +%s%N); echo "send-$n rc=$rc ms=$(( (t1 - t0) / 1000000 ))"
  sleep 30
done
SH
ROUNDS=$(( IDLE_SECS / 32 ))
[ "$ROUNDS" -ge 1 ] || ROUNDS=1
DB="$DB" BIN="$BIN" SERVER="$SERVER" WORK="$WORK" bash "$WORK/traffic.sh" "$ROUNDS" >"$WORK/traffic.log" 2>&1 &
PT=$!
wait "$PA" "$PB"
wait "$PT"

idle_log() { tail -n +"$(( $2 + 1 ))" "$1"; }
idle_log "$WORK/upA.log" "$LA0" >"$WORK/idleA.log"
idle_log "$WORK/upB.log" "$LB0" >"$WORK/idleB.log"
count() { cat "$WORK/idleA.log" "$WORK/idleB.log" | grep -cE "$1" || true; }

# --- instrument present -------------------------------------------------------
skips=$(grep -c "warm-hold: skip 'boxB'" "$WORK/idleA.log" || true)
min_skips=$(( IDLE_SECS / 10 - 3 ))
if [ "$skips" -ge "$min_skips" ]; then
  ok "instr: warm-hold ran on A and skipped the live link to boxB ($skips ticks, >= $min_skips)"
else
  echo "-- idleA.log (warm-hold lines) --"; grep "warm-hold" "$WORK/idleA.log" | tail -20
  bad "instr: warm-hold skip lines on A: $skips, expected >= $min_skips (instrument absent or link not recognised)"
fi

# --- the zero counts ----------------------------------------------------------
est=$(count 'tunlion: ESTABLISH peer=.*caller=.*conn\.rs')
if [ "$est" -eq 0 ]; then
  ok "estab: zero conn.rs establishes on either daemon over ${IDLE_SECS}s idle"
else
  cat "$WORK/idleA.log" "$WORK/idleB.log" | grep -E 'ESTABLISH|warm-hold: will' | head -20
  bad "estab: $est conn.rs establishes while idle (warm-hold re-dialled a held device)"
fi

reaps=$(count 'digest reconcile')
if [ "$reaps" -eq 0 ]; then
  ok "reap: zero digest-reconcile reaps while idle"
else
  cat "$WORK/idleA.log" "$WORK/idleB.log" | grep 'digest reconcile' | head -10
  bad "reap: $reaps digest-reconcile reaps while idle"
fi

ladders=$(count 'STALL-LADDER')
if [ "$ladders" -eq 0 ]; then
  ok "ladder: zero STALL-LADDER lines while idle"
else
  cat "$WORK/idleA.log" "$WORK/idleB.log" | grep 'STALL-LADDER' | head -10
  bad "ladder: $ladders STALL-LADDER lines while idle"
fi

# --- control-socket latency + link continuity ---------------------------------
verdict=$(python3 - "$WORK/probeA.jsonl" "$WORK/probeB.jsonl" "$IDLE_SECS" <<'PY'
import json, math, sys
a, b, secs = sys.argv[1], sys.argv[2], float(sys.argv[3])
want = int(secs / 0.3 * 0.7)   # the probe must actually have run
lat_ok, stable_ok, notes = True, True, []
for path, side in ((a, "A"), (b, "B")):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    ms = sorted(r["ms"] for r in rows if r.get("ms") is not None)
    errs = sum(1 for r in rows if r.get("ms") is None)
    if len(ms) < want:
        lat_ok = False
        notes.append(f"{side}: only {len(ms)} answered probes (want >= {want}, {errs} errors)")
        continue
    p99 = ms[min(len(ms) - 1, math.ceil(0.99 * len(ms)) - 1)]
    notes.append(f"{side}: n={len(ms)} p50={ms[len(ms)//2]:.1f}ms p99={p99:.1f}ms max={ms[-1]:.1f}ms errors={errs}")
    if p99 >= 250 or errs:
        lat_ok = False
    # The daemons' own link must be in EVERY probe: some pid common to all of
    # them. A one-shot's transient link may come and go beside it.
    sets = [set(r.get("pids") or []) for r in rows]
    missing = sum(1 for x in sets if not x)
    common = set.intersection(*sets) if sets else set()
    notes.append(f"{side}: no link in {missing}/{len(sets)} probes, held throughout={sorted(common)}")
    if missing or len(common) != 1:
        stable_ok = False
print(("LAT_OK" if lat_ok else "LAT_BAD") + " " + ("STABLE_OK" if stable_ok else "STABLE_BAD"))
for n in notes:
    print("  " + n)
PY
)
echo "$verdict"
case "$verdict" in
  LAT_OK*) ok "latency: control-socket p99 < 250ms on both daemons through the idle window" ;;
  *)       bad "latency: control-socket p99 >= 250ms (or probe errors) during idle" ;;
esac
case "$verdict" in
  *STABLE_OK*) ok "stable: one link to the peer held under the same pid through every probe on both sides" ;;
  *)           bad "stable: the link to the peer was missing or replaced during idle" ;;
esac

# --- the peer's one-shot traffic --------------------------------------------
cat "$WORK/traffic.log"
want_cmds=$(( ROUNDS * 2 ))
good=$(grep -c ' rc=0 ' "$WORK/traffic.log" || true)
landed=0
for n in $(seq 1 "$ROUNDS"); do
  [ -f "$WORK/Adrop/probe-$n.txt" ] && landed=$((landed + 1))
done
if [ "$good" -eq "$want_cmds" ] && [ "$landed" -eq "$ROUNDS" ]; then
  ok "traffic: all $ROUNDS one-shot rounds from B succeeded ($good/$want_cmds commands, $landed files landed on A)"
else
  for f in "$WORK"/traffic-*.out; do echo "-- $f"; tail -3 "$f"; done
  bad "traffic: $good/$want_cmds one-shot commands succeeded, $landed/$ROUNDS files landed on A"
fi

# --- a round trip at the end --------------------------------------------------
say "round trip after idle"
t0=$(date +%s%N)
fs_cli 30 env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" reach boxB
rc=$?
t1=$(date +%s%N)
ms=$(( (t1 - t0) / 1000000 ))
fs_out
if [ "$rc" = "0" ] && [ "$ms" -lt 10000 ]; then
  ok "rtt: reach boxB succeeded in ${ms}ms after ${IDLE_SECS}s idle"
else
  tail -20 "$WORK/upA.log"
  bad "rtt: reach boxB rc=$rc in ${ms}ms (want rc=0 within 10000ms)"
fi

declare_known_red_summary
echo
echo "==========================================="
echo "warm-hold idle gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
