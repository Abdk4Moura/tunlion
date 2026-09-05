#!/usr/bin/env bash
# The footprint numbers a background networking tool is actually judged on.
#
# WHY THESE FIVE. A daemon that lives forever is judged differently from a
# command that runs and exits, and the metric people notice is rarely the one
# benchmarks report:
#
#   binary size    what you ship, and what a flash-constrained device cannot fit.
#   idle RSS       a daemon holds this 24/7. This is the number that decides
#                  whether it belongs on a 128MB box.
#   idle CPU       the battery metric. A daemon that wakes constantly is worse
#                  than one that uses more RAM, and it never shows in a benchmark
#                  that measures throughput.
#   threads/fds    per-peer scaling. Fine at one peer, decisive at fifty.
#   startup        felt on every single invocation of the CLI half.
#
# Reference points are printed alongside, because "25MB" means nothing until you
# know tmux is 4MB and a shell is 1.4MB.
set -uo pipefail
BIN=${1:-$(command -v filament || echo "$HOME/.local/bin/filament")}
[ -x "$BIN" ] || { echo "no filament binary at $BIN"; exit 2; }
CFG=$(mktemp -d /tmp/footprint-XXXX)
cleanup() {
  for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$(readlink -f "$BIN")" ] && kill "$p" 2>/dev/null
  done
  rm -rf "$CFG"
}
trap cleanup EXIT

mb() { printf '%.1f MB' "$(echo "$1/1048576" | bc -l)"; }

echo "=== BINARY SIZE"
printf '  %-14s %s\n' "filament" "$(mb "$(wc -c < "$BIN")")"
for ref in tmux bash ssh curl; do
  p=$(command -v "$ref" 2>/dev/null) || continue
  printf '  %-14s %s\n' "$ref" "$(mb "$(wc -c < "$(readlink -f "$p")")")"
done

echo
echo "=== ONE-SHOT CLI (peak RSS)"
for c in "--version" "devices" ""; do
  r=$(FILAMENT_CONFIG_DIR="$CFG" /usr/bin/time -f '%M' "$BIN" $c 2>&1 >/dev/null | tail -1)
  printf '  %-20s %s KB\n' "filament ${c:-<bare>}" "$r"
done
printf '  %-20s %s KB\n' "/bin/true (floor)" "$(/usr/bin/time -f '%M' /bin/true 2>&1 >/dev/null | tail -1)"

echo
echo "=== DAEMON AT IDLE  (the number that decides if this fits on a small box)"
FILAMENT_CONFIG_DIR="$CFG" "$BIN" init --yes --name footprint --recovery-file "$CFG/rec" >/dev/null 2>&1
FILAMENT_CONFIG_DIR="$CFG" setsid nohup "$BIN" up >"$CFG/up.log" 2>&1 &
sleep 25
P=""
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$(readlink -f "$BIN")" ] && P=$p && break
done
if [ -z "$P" ]; then
  echo "  daemon did not start; see $CFG/up.log"
else
  awk '/^VmRSS|^Threads/ {printf "  %-14s %s %s\n", $1, $2, $3}' "/proc/$P/status"
  printf '  %-14s %s\n' "open fds:" "$(ls /proc/$P/fd 2>/dev/null | wc -l)"
  A=$(awk '{print $14+$15}' "/proc/$P/stat"); sleep 10; B=$(awk '{print $14+$15}' "/proc/$P/stat")
  # 100 ticks = 1 CPU-second. Anything above a handful over 10s idle means the
  # daemon is polling when it should be waiting, which is a battery bug.
  printf '  %-14s %s ticks / 10s idle  (0-2 is good, >20 means it is polling)\n' "idle CPU:" "$((B-A))"
fi
