#!/usr/bin/env bash
# iroh transport PoC: the two commands CI and the lease worker both run.
#
#   scripts/iroh-poc.sh test    # unit + integration tests (in-process relay)
#   scripts/iroh-poc.sh demo    # two local nodes, relay bi-stream echo + datagram
#
# This is deliberately not wired into the main test matrix: it pulls iroh and an
# in-process relay server, which no existing job should pay for. The dedicated
# workflow is .github/workflows/iroh-transport.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

mode=${1:-test}
case "$mode" in
  test)
    # First prove the PRODUCTION feature set compiles: `test-relay` is what
    # brings iroh's relay server and `insecure_skip_verify`, and a product
    # build must not depend on either.
    cargo build --locked -p filament-transport-iroh --features iroh-transport
    # One relay per test run; serial tests keep the port/relay lifecycle obvious.
    cargo test --locked -p filament-transport-iroh \
      --features iroh-transport,test-relay -- --test-threads=1
    ;;
  demo)
    cargo run --locked -p filament-transport-iroh \
      --features iroh-transport,test-relay --example relay_echo
    ;;
  *)
    echo "usage: $0 [test|demo]" >&2
    exit 2
    ;;
esac
