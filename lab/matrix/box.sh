#!/usr/bin/env bash
# Runs on the lab host (a machine with docker). Usage:
#   box.sh build <tunlion-binary>
#   box.sh up <name> [hostile]      one container named <name> (env BOX_SERVER / MX_SERVER_URL: signaling server)
#   box.sh down <name>...
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
case "${1:?build|up|down}" in
  build)
    cp "${2:?binary}" "$here/ctx/tunlion"
    docker build -q -t tunlion-matrix "$here/ctx" >/dev/null
    rm -f "$here/ctx/tunlion" ;;
  up)
    n="${2:?name}"; extra=()
    # BOX_SERVER (or MX_SERVER_URL for every machine) points the machine at a
    # signaling server other than the CLI default (a local backend).
    srv="${BOX_SERVER:-${MX_SERVER_URL:-}}"
    [ -n "$srv" ] && extra+=(-e "TUNLION_SERVER=$srv")
    if [ "${3:-}" = hostile ]; then
      # Read-only root, a small tmpfs home, no IPv6, 192 MB RAM, half a CPU,
      # C locale and a dumb terminal: hostile but plausible.
      extra+=(--read-only --tmpfs /tmp:size=16m --tmpfs /home/sam:size=24m,uid=1000,gid=1000,mode=0755
             --memory 192m --cpus 0.5 --sysctl net.ipv6.conf.all.disable_ipv6=1
             -e LANG=C -e LC_ALL=C -e TERM=dumb)
    fi
    docker rm -f "$n" >/dev/null 2>&1 || true
    docker run -d --name "$n" --hostname "$n" --init "${extra[@]}" tunlion-matrix sleep infinity >/dev/null ;;
  down)
    shift; for n in "$@"; do docker rm -f "$n" >/dev/null 2>&1 || true; done ;;
esac
