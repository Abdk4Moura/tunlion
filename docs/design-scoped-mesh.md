# Scoped mesh: projecting capabilities onto the L3 dataplane

Status: designed, pending adversarial review + implementation. This is the fix for
the accepted WG limit (`cli/src/capability.rs`, "LIMIT, WireGuard / serve-tun mesh").
It is the single lever that (1) makes capabilities authoritative over L3, (2) lets
ephemeral / auth-key devices join a mesh safely, and (3) de-escalates the tray
consent card so weight scales with scope, not with the word "mesh".

## The problem (as built)

Capability gates live in filament's `open()` broker: shell/mount/forward/transfer
are checked when a peer opens an L2 control stream. A WireGuard mesh peer never
touches that broker. Once admitted it has raw L3 IP reach and can point a plain
`ssh` or `curl` at a listening port over the tunnel, skipping the path where the
check lives. The grant is not bypassed because it is "L2 vs L3" in the abstract;
it is bypassed because raw IP transport skips the broker that does the checking.

The bypass is already narrow. A WG-only peer can reach exactly two things at L3:
the SSH daemon on the overlay address, and any port opened with `filament expose`.
Everything else (forward, netcat, proxy, transfer, mount, PTY) still requires an L2
control channel the WG peer lacks, so those stay gated. The WG PSK is currently the
*sole* authorization for that L3 reach: mesh admission is all-or-nothing.

## The fix

Project the capability decision down onto the dataplane. Compile each peer's
owner-signed grants into per-peer **WireGuard `AllowedIPs`** (crypto-routing: which
overlay addresses the peer may talk to) plus an **overlay packet filter** (port /
protocol level within an allowed address). "On the mesh" then means "reach exactly
your granted services at L3", not "reach everything". Because the raw-L3 surface is
already just sshd + exposed ports, the filter target is small.

- `grant forward:svc-X` (or an equivalent overlay grant) -> allow only svc-X's
  `ip:port`.
- `grant mesh` unscoped -> allow all (the deliberate, weighty full-mesh grant,
  still a distinct thing).
- no grant -> no route; the peer is on the overlay but reaches nothing.

Prior art: Tailscale compiles its ACL into per-node packet filters, this is the same
move. WireGuard's per-peer `AllowedIPs` is the native primitive that makes it
tractable; the work is driving it from caps and adding port-level filtering, not
inventing a mechanism.

## Edge-local enforcement (no central compiler)

Each device compiles its **own inbound** overlay filter from the owner-signed grants
it has issued for its resources. Authorization stays where it belongs, on the
resource being reached, which is also the correct trust posture: the joiner is the
least-trusted party, so the filter must not depend on the joiner enforcing it.
Best-effort joiner-side filtering is defense in depth, never the boundary. This
keeps the model edge-local: no central policy engine, revocation bounded by expiry
(the same no-global-revocation bound as capabilities), and a grant change triggers a
filter recompile applied live without tearing the tunnel down.

## The honest residual

Even scoped, a mesh peer speaks raw IP **directly** to its allowed set, so its trust
surface is the packet filter plus those services' own authentication. An L2
capability grant is different in kind: filament brokers every open and the peer never
gets raw IP at all. So scoped-mesh-to-service-X narrows the blast radius to near
parity with a forward grant, not to byte-identical. This matters when scoping a
hostile borrower; it is not a reason to avoid it. It also means `filament expose`d
ports must themselves become cap-gated rather than PSK-only, or they remain a hole
inside the scoped mesh.

## What it unlocks (three threads, one lever)

- **Closes the WG limit.** The accepted posture in `capability.rs` becomes revisable:
  capabilities finally constrain L3, so mesh admission stops being the coarsest grant.
- **Ephemeral / auth-key mesh, safely.** `design-ephemeral-auth-keys.md` currently
  disallows `mesh` in an auth key *because* the mesh is flat. With scoped mesh the
  ban relaxes to "allowed but scoped": a `gpu-run`-only borrower can be on the mesh
  reaching only the lender's GPU service, off everything else.
- **De-escalates consent.** The tray consent card (and `filament mesh add`) can scale
  weight with actual reach: a scoped join that exposes one service is calm; an
  unscoped full-mesh join stays amber and deliberate.

## Scope model

A mesh grant carries a **scope**: the set of overlay addresses / services it may
reach, default-narrow. Unscoped "full mesh" remains a separate, explicit, weighty
grant (the current `filament mesh add` semantics), never the default. The grant is an
ordinary capability op, so it flows through the same signed apply path, preview, and
directed-graph view as every other grant.

## Open / to settle before build

- **Filter granularity, in order**: `AllowedIPs` (device-level, WG-native, cheap)
  first; port/proto packet filter second.
- **Enforcement point**: resource-side inbound is authoritative; joiner-side is
  best-effort defense in depth.
- **Filter substrate**: kernel (nftables / WG config) vs userspace, perf vs
  portability. Cross-platform differences tie to `design-cross-platform-capabilities.md`
  and `design-per-os-ci.md`.
- **`filament expose` must become cap-gated**, not PSK-only, or it is a hole inside
  the scope.
- **Dynamic recompile**: grant change -> filter update without tunnel teardown.
- **Adversarial review** (claude-advisor) before implementation: filter-bypass via
  overlay source spoofing, the expose hole, joiner-side non-enforcement, and the
  residual raw-IP surface vs an L2 broker.
