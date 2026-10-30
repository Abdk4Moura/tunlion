#!/usr/bin/env bash
# Liveness probes for a bounded ci-dogfood worker lease.
#
# ci-dogfood.yml fetches this file from the SAME commit it runs (gh api,
# ?ref=$GITHUB_SHA) and sources it. Keeping the probe here rather than inline in
# YAML means the gate suite executes the exact code the workflow executes.
#
# Contract:
#   TUNLION_BIN              the tunlion binary under test (required)
#   CI_WORKER_PROBE_TIMEOUT  per-probe wall-clock bound in seconds (default 5)
#   CI_WORKER_STOP_FILE      a caller-created STOP file ends the lease cleanly
#   CI_WORKER_DAEMON_LOG     daemon log to print on the abnormal path
#
# The probe is about PROCESS HEALTH, not connectivity:
#   - status --json exits 0 only while a daemon serves this config dir and
#     answers on its control socket, and its JSON says ok:true, running:true.
#   - a live daemon whose signaling link is degraded still exits 0. That is a
#     network condition the mesh retries; it must not tear down an idle lease.
# Each invocation is bounded, so "three consecutive failures" has a bound.
set -uo pipefail

ci_probe_timeout() { printf '%s\n' "${CI_WORKER_PROBE_TIMEOUT:-5}"; }

# Run the status probe with a hard wall-clock ceiling. `timeout` is present on
# the Linux worker; if it is missing the probe still runs (a missing tool is not
# a daemon failure), but this file is only wired on the Linux worker image.
ci_status_json() {
  local bin="${TUNLION_BIN:?TUNLION_BIN is required}"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$(ci_probe_timeout)" "$bin" status --json 2>/dev/null
  else
    "$bin" status --json 2>/dev/null
  fi
}

# 0 only when the daemon is both live and answering. The exit code is the first
# answer; the JSON check closes the older "exited 0 while running:false" shape
# and refuses a truncated/partial object.
ci_daemon_live() {
  local out rc
  out="$(ci_status_json)"
  rc=$?
  [ "$rc" -eq 0 ] || return 1
  printf '%s' "$out" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d.get("ok") is True and d.get("running") is True else 1)
' 2>/dev/null
}

# Wait up to $1 seconds for a just-started daemon to answer. Returns 0 on live,
# 7 on timeout. The loop is bounded by the caller's deadline plus at most one
# probe timeout.
ci_require_daemon() {
  local deadline=$(( $(date +%s) + ${1:-60} ))
  while :; do
    ci_daemon_live && return 0
    (( $(date +%s) >= deadline )) && return 7
    sleep 1
  done
}

# Serve an idle lease until $1 (epoch seconds). Returns:
#   0  STOP file or deadline reached
#   7  $3 consecutive status probes failed (default 3)
# A single transient failure is retried after $2 seconds (default 10), so a
# healthy but busy box is not torn down by one slow status read.
ci_serve_until() {
  local end="$1" interval="${2:-10}" max_fail="${3:-3}"
  local stop="${CI_WORKER_STOP_FILE:-${WORK:?WORK or CI_WORKER_STOP_FILE is required}/STOP}"
  local fails=0
  while :; do
    [ ! -f "$stop" ] || return 0
    (( $(date +%s) < end )) || return 0
    if ci_daemon_live; then
      fails=0
    else
      fails=$((fails + 1))
      printf 'worker daemon probe failed (%s/%s)\n' "$fails" "$max_fail" >&2
      (( fails < max_fail )) || return 7
    fi
    sleep "$interval"
  done
}

# Evidence for the abnormal path. The worker is an ephemeral GitHub runner, so
# this output is the only surviving copy of the daemon's last words.
ci_worker_diagnostics() {
  local bin="${TUNLION_BIN:-tunlion}"
  printf '\n== worker diagnostics ==\n'
  printf -- '-- status --json --\n'
  if command -v timeout >/dev/null 2>&1; then
    timeout "$(ci_probe_timeout)" "$bin" status --json 2>&1 || printf 'status rc=%s\n' "$?"
  else
    "$bin" status --json 2>&1 || printf 'status rc=%s\n' "$?"
  fi
  printf -- '-- daemon log tail --\n'
  tail -n 120 "${CI_WORKER_DAEMON_LOG:-$HOME/.config/tunlion/daemon.log}" 2>/dev/null \
    || printf '(no daemon log at %s)\n' "${CI_WORKER_DAEMON_LOG:-$HOME/.config/tunlion/daemon.log}"
  printf -- '-- memory --\n'
  free -m 2>/dev/null || true
  cat /proc/pressure/memory 2>/dev/null || true
}
