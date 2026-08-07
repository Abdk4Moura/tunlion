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
# HOW THE MONITORS RUN (2026-08-05)
#
# The three monitors used to execute straight out of the repo working tree:
#
#     ExecStart=/usr/bin/python3 /root/stunning-tribble/deploy/monitor/signaling-monitor.py
#
# A git checkout therefore changed production behaviour with no deploy step and
# no signal that anything moved. This script now installs the monitors to a
# stable path OUTSIDE any git worktree (/usr/local/lib/filament-monitor),
# rewrites the installed units' ExecStart to point there, and stamps the
# deployed commit sha. `verify` FAILS if any installed unit still points INTO a
# git worktree, and fails if the version stamp is missing, so "which code is
# production running" has an answer that is not "whatever is checked out".
#
# Usage:
#   deploy/monitor/install-timers.sh            install + enable + verify
#   deploy/monitor/install-timers.sh verify     check only, changes nothing
#
# Exit 0 = all timers installed, armed, and running deployed copies.
# Exit 1 = at least one is not.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNITS=(filament-monitor.service filament-monitor.timer
       filament-oom-shield.service filament-oom-shield.timer
       filament-memory-pressure.service filament-memory-pressure.timer)
SERVICES=(filament-monitor.service filament-oom-shield.service filament-memory-pressure.service)
TIMERS=(filament-monitor.timer filament-oom-shield.timer filament-memory-pressure.timer)
DEST=/etc/systemd/system

# Stable home for the deployed monitors, OUTSIDE any git worktree. Production
# must never run from a checkout, because a branch switch silently changes what
# the timers execute.
INSTALL_DIR=/usr/local/lib/filament-monitor
# The monitor scripts, copied verbatim from this checkout.
SCRIPTS=(signaling-monitor.py oom-shield-monitor.py memory-pressure-monitor.py)
# Sibling of INSTALL_DIR: oom-shield-monitor.py resolves its assertion script
# as ../assert-oom-shield.sh relative to its own directory, mirroring the repo
# layout (deploy/monitor + deploy/assert-oom-shield.sh).
ASSERT_SIBLING="$(dirname "$INSTALL_DIR")/assert-oom-shield.sh"

# Path a unit's ExecStart runs, or empty if the unit has none (timers).
exec_script() {
  local unit="$1"
  grep -oP '(?<=ExecStart=).*' "$unit" 2>/dev/null | awk '{print $2}'
}

# Is the given file path inside a git worktree? Walks up from the file's
# directory looking for `.git`: a directory for a normal checkout, a FILE for a
# linked worktree; either marks the parent as a worktree root. Returns 0 if
# yes, 1 if no.
in_git_worktree() {
  local p="$1"
  local dir
  dir="$(cd "$(dirname "$p")" && pwd)"
  while [ "$dir" != "/" ]; do
    if [ -e "$dir/.git" ]; then return 0; fi
    dir="$(dirname "$dir")"
  done
  return 1
}

# Print the deployed version stamp. Fails if the stamp is missing, which means
# units were installed without recording what they run.
show_version() {
  if [ -f "$INSTALL_DIR/version" ]; then
    echo "install-timers: deployed monitor version:"
    sed 's/^/  /' "$INSTALL_DIR/version"
    return 0
  fi
  echo "install-timers: MISSING: $INSTALL_DIR/version (units deployed with no recorded version)"
  return 1
}

verify() {
  local bad=0
  # THE CHECK THAT MATTERS: each installed unit must run a deployed copy, never
  # a file inside a git worktree. A unit whose ExecStart still points at a
  # checkout silently changes production behaviour on every branch switch.
  for u in "${SERVICES[@]}"; do
    local target
    target="$(exec_script "$DEST/$u")"
    if [ -z "$target" ]; then
      echo "install-timers: $u has no ExecStart script to check"; bad=1; continue
    fi
    if [ ! -f "$target" ]; then
      echo "install-timers: $u ExecStart points at a missing file: $target"; bad=1; continue
    fi
    if in_git_worktree "$target"; then
      echo "install-timers: $u ExecStart runs from a git worktree: $target"; bad=1; continue
    fi
    echo "install-timers: OK: $u runs deployed copy $target"
  done
  show_version || bad=1
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
    #
    # DO NOT use `grep -q` here. With `pipefail` set, an early-exiting grep
    # SIGPIPEs the still-writing `systemctl` (exit 141), so a PRESENT timer can
    # be reported as NOT SCHEDULED. Measured 2026-08-05: the `grep -q` form
    # false-missed 23/80 runs; plain `grep -F` consuming all output missed
    # 0/80. The two "dead timer, daemon-reload clears it" incidents recorded
    # here were likely this flake, not dead timers.
    if ! systemctl list-timers --all --no-pager 2>/dev/null | grep -F "$t" >/dev/null; then
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
  want="$(exec_script "$HERE/$u")"
  [ -z "$want" ] && continue
  [ -f "$want" ] || { echo "install-timers: $u ExecStart points at a missing file: $want"; exit 1; }
done

# --- Deploy the monitors to a stable path outside any git worktree ---
install -d -m 0755 "$INSTALL_DIR"
for s in "${SCRIPTS[@]}"; do
  install -m 0644 "$HERE/$s" "$INSTALL_DIR/$s"
done
# oom-shield-monitor.py finds its assertion script as ../assert-oom-shield.sh
# relative to its own directory; deploy it as the sibling of INSTALL_DIR so the
# relative reference resolves unchanged.
install -m 0755 "$HERE/../assert-oom-shield.sh" "$ASSERT_SIBLING"

# Stamp the deployed version so "what is production running" is recorded, not
# inferred from whatever happens to be checked out.
{
  echo "deployed_commit=$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "deployed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$INSTALL_DIR/version"

install -m 0644 "${UNITS[@]/#/$HERE/}" "$DEST/"
# Rewrite each installed unit's ExecStart from the checkout path to the stable
# install path. A unit whose ExecStart still names $HERE after this is a sign
# the committed unit drifted from the layout this script assumes.
for u in "${SERVICES[@]}"; do
  if grep -qF "$HERE/" "$DEST/$u"; then
    sed -i "s|$HERE/|$INSTALL_DIR/|g" "$DEST/$u"
    echo "install-timers: $u ExecStart -> $INSTALL_DIR/"
  else
    echo "install-timers: WARNING: $u ExecStart does not reference $HERE; left unchanged"
  fi
done

systemctl daemon-reload
systemctl enable --now "${TIMERS[@]}"
echo
verify
