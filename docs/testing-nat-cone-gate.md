# Cone NAT Gate Investigation

Status: the topology is not valid evidence about Filament NAT traversal.

The gate is `cli/tests/nat-cone-gate.sh`. It builds two client namespaces,
two MASQUERADE routers, and a WAN namespace containing signaling, STUN, and
the packet capture point.

## Established

- `NO_NAT=1` is a positive control: pairing completes, the payload is
  byte-exact, and the direct route succeeds with exit code 0.
- The hand-rolled STUN responder is not compatible with stock clients:
  `turnutils_stunclient` times out. Replacing it with coturn makes srflx
  candidates appear on both peers.
- With coturn, ICE emits checks to both advertised srflx addresses, but the
  connection still fails.
- The advertised srflx ports match the peer destinations.
- Plain MASQUERADE is used. There is no `--random-fully` rule.
- Conntrack reply tuples match the peer addresses and ports, but remain
  `[UNREPLIED]`.
- `rp_filter=2` and `ip_forward=1` are set on both routers and the WAN.
  Routes exist and all input, forward, and output chains accept traffic.
- A WAN capture saw 256 peer-check packets crossing in both directions.
- Client captures saw none of those peer-check packets arriving on either LAN.

The failure is located at the receiving router inbound path in this emulation:
the checks cross the WAN, reach the receiving router's public side, and are
not delivered to its client LAN.

## Not Established

- Why the receiving router drops packets matching its conntrack reply tuple.
- Whether the emulated filtering behavior matches a real cone NAT.
- Whether Filament has a NAT traversal defect.

## Scope Boundary

This does not resolve issue #50. That issue concerns real NAT, real Internet
connectivity, a reachable STUN service, and a production binary without test
hooks. This gate cannot provide a product verdict while its emulated topology
cannot demonstrate stock UDP hole punching.

## Method Lesson

Before the positive control, the gate had never passed, so its red result had
no discriminating power. The no-NAT control established that the signaling,
pairing driver, and transfer assertion work. Subsequent measurements then
separated the responder defect, ICE checks, conntrack state, WAN forwarding,
and receiving-router drop instead of treating one end-to-end timeout as a
product diagnosis.

Diagnostic options include `NO_NAT=1`, `COTURN=1`, and `CAPTURE=1`. The branch
also records route tables, firewall rules, sysctls, client/WAN packet captures,
and conntrack state when capture is enabled.
