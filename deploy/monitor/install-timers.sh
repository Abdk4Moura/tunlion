#!/usr/bin/env bash
# Install and enable the production monitor timers on the host that runs the
# deployment.
#
# WHY THIS EXISTS
#
# The unit files in this directory were added on 2026-06-27 and the signaling
# monitor's own docstring said "Run by a systemd timer (see the .timer /
# .service in this directory)". On 2026-08-04 that was checked for the first
# time: `systemctl list-timers --all | grep filament` returned nothing, no unit
# file existed under /etc/systemd/system, and no cron entry referenced the
# script anywhere on the box. Its state file was last written on 2026-07-31 by a
# hand-run, and that hand-run had recorded a real DOWN and recovery. So the
# signaling monitor did work, and nothing was running it.
#
# The unit files being IN THE REPO and the units being INSTALLED ON THE HOST are
# two different facts, and only one of them is visible in a diff. That is the
# same shape as the OOM shield: `oom_score_adj: -800` in docker-compose.yml, and
# oom_score_adj=0 on every running container. Config is not effect.
#
# So: no installation step that lives only in someone's memory. This script is
# the step, `verify` is how you check it took.
#
# Usage:
#   deploy/monitor/install-timers.sh            install + enable + verify
#   deploy/monitor/install-timers.sh verify     check only, changes nothing
#
# Exit 0 = both timers installed and armed. Exit 1 = at least one is not.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNITS=(filament-monitor.service filament-monitor.timer
       filament-oom-shield.service filament-oom-shield.timer
       filament-memory-pressure.service filament-memory-pressure.timer)
TIMERS=(filament-monitor.timer filament-oom-shield.timer filament-memory-pressure.timer)
DEST=/etc/systemd/system

verify() {
  local bad=0
  for t in "${TIMERS[@]}"; do
    if ! systemctl is-enabled --quiet "$t" 2>/dev/null; then
      echo "install-timers: NOT ENABLED: $t"; bad=1; continue
    fi
    if ! systemctl is-active --quiet "$t" 2>/dev/null; then
      echo "install-timers: NOT ACTIVE: $t"; bad=1; continue
    fi
    # Armed means systemd has an actual next-elapse for it, not just that the
    # unit loaded. A timer can be enabled and still never fire if its unit is
    # malformed, and `is-enabled` will not tell you that. This check has caught
    # exactly that state twice, on both occasions it has run against a fresh
    # install; a `daemon-reload` clears it.
    #
    # USE `list-timers`, NOT A PROPERTY QUERY. It is deliberate and it matters.
    # `systemctl show -p NextElapseUSecRealtime` returns a CLEAN EMPTY VALUE for
    # these timers, because they are MONOTONIC (`OnUnitActiveSec=`) and their
    # next elapse lives in `NextElapseUSecMonotonic`. Realtime is for calendar
    # timers (`OnCalendar=`). Querying the wrong property does not error, it
    # returns nothing, and nothing is indistinguishable from an unscheduled
    # timer. On 2026-08-04 that mistake nearly reported all three working safety
    # timers as dead, and it would have been believed, because it produces
    # exactly the failure this line exists to detect.
    #
    # `list-timers` is shape-agnostic and shows both kinds. If you "improve"
    # this to a property query, you must branch on the timer's schedule type,
    # and you will reintroduce a false alarm that looks like a real finding.
    if ! systemctl list-timers --all --no-pager 2>/dev/null | grep -q "$t"; then
      echo "install-timers: ENABLED BUT NOT SCHEDULED: $t"; bad=1; continue
    fi
    echo "install-timers: OK: $t enabled, active, scheduled"
  done
  return $bad
}

if [ "${1:-}" = "verify" ]; then
  verify; exit $?
fi

[ "$(id -u)" -eq 0 ] || { echo "install-timers: must run as root"; exit 1; }

# The units hardcode /root/stunning-tribble as the checkout path. Refuse rather
# than install a timer whose ExecStart points at a file that is not there: a
# unit that fails every 5 minutes is worse than no unit, because its failures
# are quiet unless someone reads the journal.
for u in "${UNITS[@]}"; do
  [ -f "$HERE/$u" ] || { echo "install-timers: missing $HERE/$u"; exit 1; }
done
for s in "$HERE/signaling-monitor.py" "$HERE/oom-shield-monitor.py" "$HERE/memory-pressure-monitor.py" "$HERE/../assert-oom-shield.sh"; do
  [ -f "$s" ] || { echo "install-timers: unit target missing: $s"; exit 1; }
done
for u in "${UNITS[@]}"; do
  want="$(grep -oP '(?<=ExecStart=).*' "$HERE/$u" 2>/dev/null | awk '{print $2}')"
  [ -z "$want" ] && continue
  [ -f "$want" ] || { echo "install-timers: $u ExecStart points at a missing file: $want"; exit 1; }
done

install -m 0644 "${UNITS[@]/#/$HERE/}" "$DEST/"
systemctl daemon-reload
systemctl enable --now "${TIMERS[@]}"
echo
verify
