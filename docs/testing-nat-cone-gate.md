# Cone NAT Gate Retirement

Status: RETIRED. `cli/tests/nat-cone-gate.sh` was deleted on 2026-08-07 and is
tombstoned in the artifact registry (issue #134). Do not revive it as a product
gate without re-proving it can discriminate.

## What it was

Two client network namespaces, two MASQUERADE routers, and a WAN namespace
containing signaling, STUN, and the capture point. It tried to (1) prove both
NATs were "cone" and (2) assert a hole-punched, byte-exact transfer between two
Filament peers behind them.

## Why it was retired (evidence)

- **The "cone" proof measured mapping only.** `natprobe.py` classifies a NAT by
  whether two independent reflectors observe the same source port
  (endpoint-independent) or different ports (endpoint-dependent). That is a
  MAPPING classification. A cone NAT also requires endpoint-independent
  FILTERING. Linux MASQUERADE gives endpoint-independent mapping but
  endpoint-dependent filtering, so the emulated NAT is not a cone by the
  filtering dimension the gate never measured. "Cone proven" was an
  adjacent-question instrument: it answered a mapping question and the result
  was read as a filtering claim.
- **The transfer assertion never passed on any NAT topology.** Only the
  `NO_NAT=1` positive control passed. Under two MASQUERADEs the hole-punch
  transfer failed at the receiving-router inbound path (documented below). A
  gate that cannot go green on the topology it claims to accept cannot
  discriminate, so it was not fixable by tuning the transfer assertion.
- **The one correct measurement was redundant.** `natprobe-test.sh` already
  proves the probe classifies both endpoint-independent (plain MASQUERADE) and
  endpoint-dependent (`--random-fully`) mappings. It is wired into CI as a
  required linux-netns artifact and passes. Nothing useful died with the gate.

## The emulation failure that motivated the investigation

Checks crossed the WAN (256 packets, both directions), reached the receiving
router's public side, and were not delivered to its client LAN. Conntrack reply
tuples matched the peer addresses and ports but stayed `[UNREPLIED]`;
`rp_filter=2` and `ip_forward=1` were set on both routers and the WAN. The
cause was never established, which is part of why the gate was retired rather
than repaired: the emulation could not demonstrate even stock UDP hole punching,
and a cone-NAT emulation needs endpoint-independent filtering that plain Linux
MASQUERADE does not provide.

## Scope boundary

Retiring this gate does not resolve issue #50 (the original real-NAT pairing
failure). That issue concerns real NAT, real Internet connectivity, a reachable
STUN service, and a production binary. Nothing in the lab work bore on it.

## What to cite instead

- For UDP mapping classification: `cli/tests/natprobe-test.sh` (wired, passes).
- For a real-NAT verdict: nothing in this repo yet; see
  `docs/test-topology-coverage.md` for the cheapest real-NAT recommendation.
