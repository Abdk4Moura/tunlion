# Current project state

> **Status:** canonical current-state index  
> **Last full verification:** 2026-09-07 against commit `3c6599f`
>
> **Fleet section source-verified:** 2026-11-02 against `a5f525e04577602796034b8add96b7eff8dd0dc0`; other entries retain their earlier verification scope.
>
> **Authority:** this file states only source-audited present state. `ROADMAP.md` is the priority backlog; designs are not implementation claims.

## Product

Filament is a peer-to-peer device-connectivity system. A React/WebRTC browser peer, a Flask + Socket.IO signaling service, and the Rust CLI share the protocol. The server coordinates peers; file and interactive data are intended to travel peer-to-peer.

The CLI package is `tunlion` **0.9.2** on crates.io (it was `filament-cli` through 0.8.5). Its scope includes transfers, pairing, device identity and capabilities, shell/PTY, port forwarding, mounts, direct QUIC transport, and an L3 overlay. Focused Rust crates hold shared transport, protocol, transfer, pairing, identity, capability, overlay, fleet, and secure-storage code.

## Recently verified changes

- **WireGuard L3 wiring:** commit `3c6599f` wires the previously uncalled WireGuard module and carries route-ceiling scope.
- **Footprint/startup:** commit `cf5f896` records measurements and reduces binary/startup cost.
- **Certificate renewal and exit-route safety:** commit `2f434b0`.
- **Subnet routes:** commits `452356f`, `2f434b0`, and `3c6599f` complete signed route advertisement, scoped route authorization, kernel forwarding/NAT, withdrawal cleanup, and real-machine end-to-end evidence. See `docs/design-subnet-routes.md`.
- **Fleet auto-mesh and trust:** #291 established sibling connections; #609 added roster-bound admission/removal and reliability fixes; #616 introduced `FleetSibling` inbox-only defaults and target-specific owner grants. See [the current fleet guide](../fleet.md) for shipped behavior and session/propagation limits. #657 later fixed the stale ICE-cache refresh deadlock; it did not change fleet authorization.
- **Integration validation (now on main):** at integration head `9144ee749`, the exec (29/29), SSH (8/8) and terminal withdrawal (19/19) suites were green. Validated behavior there: certificate-less authenticated pairs retain explicit local shell access; anonymous peers are transfer-only. This does not establish browser/WASM parity, termination of every session kind on cut-off or capability revoke, or completed Core removals.
- **Capability CI:** commit `96de120` ratchets deterministic core checks; GitHub workflows cover browser, capability, mount, proof, release, and platform test paths.

## Current boundaries

- `CONTRACT.md` is the normative cross-component protocol/UI contract. It describes shipped interoperable behavior only.
- `ROADMAP.md` is the sole ordered backlog. A roadmap item is not proof that work exists in the tree.
- `docs/design*/` contains proposals and implementation records. Read each document's status before relying on it.
- `docs/cli-resilience.md` and `docs/resilience.md` are failure ledgers; their named gates are the evidence for verified fixes.
- Product-specific compute/GPU work is intentionally outside Filament core; `docs/design-product-interface.md` remains a design for the local product interface.

## Open design directions

These are not active implementation claims: the versioned local product interface, per-stream L2 QUIC, edge signaling, enterprise async delivery, and expanded transport rungs remain design/proposal material unless a document explicitly records a landed change.

## Historical records

Session handoffs, investigations, completed plans, and previous work-state material live under `docs/archive/`. They preserve rationale and evidence but are not current instructions. Use `docs/README.md` to navigate the documentation and its authority levels.
