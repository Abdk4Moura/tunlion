# Test Topology Coverage

This document qualifies what a green test board proves. It is an inventory of
the checked-in test estate, not a claim that every test runs in every workflow.

## Coverage Matrix

| Estate | How peers run | Network path | NAT coverage | Where verified |
| --- | --- | --- | --- | --- |
| Capability CI | Two daemons on one hosted runner | Local signaling and same-host WebRTC/UDP; loopback is enabled on Linux and Windows | None. A host interface hairpin is possible, but there is no NAT boundary | `cli/tests/capability_harness.rs:117-121`, `:172-176`; `.github/workflows/capability-ci.yml:59-60`, `:175-182` |
| Default CLI gates | Two local CLI processes | Fixture backend on `127.0.0.1`; direct and WebRTC paths stay on one host | None | `cli/tests/transport-gates.sh:23-25`, `:40-48`, `:61-77`; `cli/tests/gates.sh:37-48` |
| L2 and SSH gates | Two local daemons plus local sshd | `127.0.0.1` services and a same-host data channel | None | `cli/tests/l2-gates.sh:25`, `:96-115`, `:148-163`; `cli/tests/ssh-gates.sh:32`, `:60-65` |
| Local lab | Two Linux network namespaces on one host | Direct veth, userspace UDP, WireGuard, or filament carrier over a private underlay | None. Namespaces are isolated, but no NAT or Internet edge is configured | `lab/README.md:8-15`, `:37-57`, `:69-78`; `lab/topologies/two-nodes.yml:18-21` |
| Relay gate | Two local peers and local coturn | Forced TURN relay on `127.0.0.1` | Relay transport is covered, but not NAT traversal | `cli/tests/gates.sh:329-347` |
| NAT mapping probe | One Linux NAT namespace | MASQUERADE with and without `--random-fully` | Measures UDP mapping classification only (endpoint-independent vs endpoint-dependent); it is not NAT traversal coverage and not a cone-NAT claim | `cli/tests/natprobe-test.sh`; `cli/tests/natprobe.py` |

The old hole-punch script was retired because its external transport lab was
never committed and no longer exists. The cone-NAT emulation
(`cli/tests/nat-cone-gate.sh`) was retired with it: its probe proved only
endpoint-independent mapping (not a cone NAT, which also requires
endpoint-independent filtering), and its hole-punch transfer assertion never
passed on any NAT topology in the emulation. Its mapping probe survives as the
wired `natprobe-test.sh`. The surviving NAT probe is not evidence from two
independent residential or mobile networks.

## What A Green Board Does Not Prove

The default CI and local gates have zero coverage for:

- Two physical hosts on the same LAN. They cannot expose interface selection,
  host firewall, or peer-to-peer routing differences between machines.
- Two peers behind separate ordinary NATs. They cannot expose STUN mapping,
  inbound filtering, simultaneous-open timing, or direct-QUIC candidate failure
  across an actual NAT boundary.
- Symmetric NAT and CGNAT in production networks. No active gate exercises
  carrier-grade NAT policy, ISP filtering, or mobile-network behavior.
- NAT hairpin behavior across different hosts. The same-host hairpin probe in
  CI (`capability-ci.yml:108-119`) checks a host kernel path, not a router's
  hairpin implementation.
- Relay fallback after a real NAT failure. The relay gate forces coturn on
  loopback; it does not prove that a peer behind NAT reaches TURN or that the
  application selects relay after an Internet-path failure.

These gaps can hide defects in ICE candidate gathering and filtering, STUN
mapping interpretation, UDP pinhole lifetime, direct-QUIC promotion and
fallback, TURN authentication and reachability, MTU or fragmentation, and
transport recovery after a NAT mapping changes. A same-host test also makes
same-install identity mistakes difficult to trigger: separate config
directories change install identity, while no independent host boundary
exercises the real deployment topology.

## Topology Knobs

- `FILAMENT_DIRECT_LOOPBACK_ONLY=1` is enabled for Ubuntu and Windows CI so
  same-host direct candidates use loopback. macOS sets it to `0` because its
  hosted ARM64 runner does not gather usable loopback host candidates. This is
  a same-host test workaround, not NAT coverage (`.github/workflows/capability-ci.yml:181-182`).
- `FILAMENT_DIRECT_PER_OS=0` disables direct-QUIC on macOS CI, while Ubuntu and
  Windows use `1`. This leaves macOS without rung-1 direct-QUIC coverage and
  does not simulate a NAT failure (`.github/workflows/capability-ci.yml:175-182`).
- `--relay` and the local coturn gate exercise a selected relay route, but do
  not create a NAT boundary (`cli/tests/gates.sh:329-347`).

With independent-network coverage, the loopback-only and per-OS workarounds
would no longer be substitutes for the topology under test. They may remain
useful platform-specific controls, but every green result should state whether
it tested direct candidates over a real interface, a NAT, or a forced relay.

## Cheapest Real-NAT Recommendation

Keep the opt-in netns hole-punch gates as a fast deterministic regression suite,
then add one scheduled two-host smoke test. Run one Filament daemon on each of
two small machines or CI runners on different networks, use the existing
signaling service and TURN endpoint, and record the observed route plus a
byte-exact transfer. Start with one ordinary home NAT and one mobile hotspot;
repeat with direct disabled to verify relay fallback. This adds real candidate,
mapping, firewall, and TURN reachability coverage without changing the normal
CI build or requiring a new production component.
