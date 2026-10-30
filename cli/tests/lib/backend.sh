#!/usr/bin/env bash
# Sourced-only helper for starting the Python signaling backend in a gate.
#
# It exists so every gate records the REAL backend PID instead of a wrapper
# subshell. Before this, `( cd backend && python app.py ) &` recorded the
# subshell: the gate's cleanup killed the subshell and `python app.py` kept
# running, kept the test port, and could keep an inherited build-lock
# descriptor open after the gate exited.
#
# The caller keeps ownership of the process: backend_start assigns the PID to
# BACKEND_PID in the CALLING shell (no command substitution, so the backend is
# still the caller's child and `wait` can reap it). backend_stop only ever
# signals that recorded PID, and refuses when its Linux start time no longer
# matches, so a recycled PID is never killed.
#
# The two known build-lock descriptors are closed for the CHILD ONLY:
#   fd 3  the shared worker's `flock build.lock` wrapper (cache-branch contract)
#   fd 9  scripts/cargo-locked.sh
# The calling gate keeps its own descriptors and its lock for the whole gate.
#
# Callers pass their own environment explicitly. This helper deliberately has
# no default PORT/FIL_* values: gates differ (ping windows, TURN, chunk size,
# append vs truncate) and a uniform default would silently change them.

BACKEND_PID=""
BACKEND_START=""

# Linux /proc/<pid>/stat field 22 (starttime). A PID alone is not proof of
# identity because a long gate can outlive a PID wrap. Empty elsewhere is
# accepted by backend_stop, which then has only the PID as a guard.
_backend_starttime() {
  local stat
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  # The comm field is parenthesised and may contain spaces; drop through the
  # last ')' so the remaining fields start at state.
  stat=${stat##*) }
  # shellcheck disable=SC2086
  set -- $stat
  [ "$#" -ge 20 ] || return 1
  printf '%s\n' "${20}"
}

# backend_start [--append] <backend-dir> <python> <log> [ENV=VALUE ...]
# Sets BACKEND_PID in the caller. Leaves BACKEND_START empty when /proc is
# unavailable. Returns nonzero only when the launch itself fails to fork.
backend_start() {
  local append=0 dir py log
  if [ "${1:-}" = "--append" ]; then append=1; shift; fi
  dir="${1:-}"; py="${2:-}"; log="${3:-}"
  if [ -z "$dir" ] || [ -z "$py" ] || [ -z "$log" ]; then
    echo "backend_start: usage: backend_start [--append] <dir> <python> <log> [ENV=VALUE ...]" >&2
    return 2
  fi
  shift 3
  if [ "$append" = "1" ]; then
    ( cd "$dir" || exit 1; exec env "$@" "$py" app.py ) >>"$log" 2>&1 3>&- 9>&- &
  else
    ( cd "$dir" || exit 1; exec env "$@" "$py" app.py ) >"$log" 2>&1 3>&- 9>&- &
  fi
  BACKEND_PID=$!
  BACKEND_START=$(_backend_starttime "$BACKEND_PID" 2>/dev/null || true)
  return 0
}

# backend_stop [pid] [expected-starttime]
# Bounded TERM, then KILL, then reap. Defaults to BACKEND_PID/BACKEND_START.
# Never signals a process whose start time differs from the one recorded at
# launch, and never looks up a PID by name or port.
backend_stop() {
  local p="${1:-${BACKEND_PID:-}}" expected="${2:-${BACKEND_START:-}}" now i=0
  [ -n "$p" ] || return 0
  if [ -n "$expected" ]; then
    now=$(_backend_starttime "$p" 2>/dev/null || true)
    if [ -n "$now" ] && [ "$now" != "$expected" ]; then
      echo "backend_stop: pid $p was recycled since launch; not signalling it" >&2
      return 0
    fi
  fi
  if kill "$p" 2>/dev/null; then
    while [ "$i" -lt 20 ]; do
      kill -0 "$p" 2>/dev/null || break
      sleep 0.25
      i=$((i + 1))
    done
    kill -9 "$p" 2>/dev/null || true
  fi
  wait "$p" 2>/dev/null || true
  if [ "$p" = "${BACKEND_PID:-}" ]; then
    BACKEND_PID=""
    BACKEND_START=""
  fi
  return 0
}
