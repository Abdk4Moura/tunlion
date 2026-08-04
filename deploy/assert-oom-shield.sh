#!/usr/bin/env bash
# Assert the production OOM shield is IN EFFECT, not merely configured.
#
# WHY THIS EXISTS
#
# docker-compose.yml sets `oom_score_adj: -800` on every production service.
# That is applied at container CREATION. A container running from before the
# compose change keeps whatever it started with, and nothing reports the
# difference.
#
# On 2026-08-03 all four production containers were found at oom_score_adj=0
# while the compose file had said -800 for hours. MemAvailable was 1.63 GiB and
# SwapFree was 0.43 GiB of 4.00 with a build running, which is close to the
# state that OOM-killed a 1.17 GB rustc earlier that week. The shield existed in
# config and was absent from the running system, and the only reason anyone
# looked was an unrelated memory check.
#
# So: the compose setting and a hand-applied value cover each other BY LUCK.
# Compose covers a recreation; a hand-application covers a running container.
# Neither reports when NEITHER is in effect. This does.
#
# WHY IT WALKS cgroup.procs
#
# `docker inspect .State.Pid` returns the container's SUPERVISOR. For the api
# service that is the gunicorn master, and shielding only the master leaves the
# single `-w 1` worker exposed, which is worse than no shield: the master
# respawns, the container never exits, `docker ps` says Up, and every live
# socket.io connection dies anyway. That mistake was made once here already.
# Every process in the cgroup must be checked.
#
# EXIT CODES, distinct on purpose
#   0  every process in every container is shielded
#   1  at least one process is NOT shielded          <- act on this
#   2  could not check (docker missing, no containers, cgroup unreadable)
#      NOT the same as "shielded". An unverifiable shield is not a shield.
#
# Usage:  deploy/assert-oom-shield.sh [--fix]
#         --fix applies -800 to any unshielded process and re-verifies.
set -uo pipefail

WANT=-800
SERVICES=(deploy-api-1 deploy-redis-1 deploy-coturn-1 deploy-cloudflared-1)
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

command -v docker >/dev/null || { echo "assert-oom-shield: UNVERIFIABLE: docker not found"; exit 2; }

bad=0
seen=0
for c in "${SERVICES[@]}"; do
  pid="$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null)" || pid=""
  if [ -z "$pid" ] || [ "$pid" = "0" ]; then
    echo "assert-oom-shield: $c not running (skipped)"
    continue
  fi
  cg="$(sed 's/.*://' /proc/"$pid"/cgroup 2>/dev/null | head -1)"
  procs="/sys/fs/cgroup${cg}/cgroup.procs"
  if [ ! -r "$procs" ]; then
    echo "assert-oom-shield: UNVERIFIABLE: cannot read $procs for $c"
    exit 2
  fi
  n=0
  for p in $(cat "$procs" 2>/dev/null); do
    s="$(cat /proc/"$p"/oom_score_adj 2>/dev/null)" || continue
    n=$((n + 1))
    seen=$((seen + 1))
    if [ "$s" != "$WANT" ]; then
      echo "assert-oom-shield: UNSHIELDED $c pid=$p oom_score_adj=$s (want $WANT)"
      bad=$((bad + 1))
      if [ "$FIX" = "1" ]; then
        if echo "$WANT" > /proc/"$p"/oom_score_adj 2>/dev/null; then
          echo "assert-oom-shield:   fixed pid=$p"
          bad=$((bad - 1))
        else
          echo "assert-oom-shield:   FAILED to fix pid=$p (need root?)"
        fi
      fi
    fi
  done
  [ "$n" -eq 0 ] && { echo "assert-oom-shield: UNVERIFIABLE: no processes in $c cgroup"; exit 2; }
done

if [ "$seen" -eq 0 ]; then
  echo "assert-oom-shield: UNVERIFIABLE: no production containers running"
  exit 2
fi

if [ "$bad" -gt 0 ]; then
  echo "assert-oom-shield: FAIL: $bad process(es) unshielded out of $seen."
  echo "  Production can be OOM-killed ahead of a build. Run with --fix to"
  echo "  apply now; the compose setting only takes effect on recreation."
  exit 1
fi

echo "assert-oom-shield: OK: all $seen production processes at oom_score_adj=$WANT"
