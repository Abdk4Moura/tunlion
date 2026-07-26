# Work state and task list

> Living index of where filament + the product stand, written so context survives
> across sessions and compaction. The committed design docs are the source of
> truth; this file is the map and the ordering. Update status here as work lands.
> Last updated: 2026-07-26.

## One-paragraph state

filament's L3 data plane is moving to WireGuard (built + measured, branch
`feat/wireguard-l3`, ready to merge). The identity/access/product design is
complete and committed. The trust root, L1 PAKE v2, is spec'd with owner decisions
locked (`L1-pake-protocol.md` §13) and is the next thing to build, contracted to
filament-professional. Product thesis: a no-account pairwise mesh plus a secure
compute-pooling platform on top; the p2p send is the consumer wedge; enterprise
features are a demand-pulled compliance envelope built LAST.

## The core / product boundary (READ FIRST)

filament is the CORE/platform: pairing (L1), the transport ladder (L2), the overlay
(L3 = WireGuard), identity, capabilities, transfer, and `mount`, exposed through a
stable PRODUCT INTERFACE (the local control socket, `ctl.rs`). PRODUCTS -- the
compute/GPU product and any others -- are SEPARATE codebases that CONSUME that
interface. Nothing product-specific (GPU sandbox, job protocol, OpenAI routing)
lives in filament core. filament's job is to make itself usable for those purposes,
not to be them.

## Master build order (and why this sequence)

1. **L1 PAKE v2** (trust root). Identity/certs/capabilities root in the
   first-pairing secret; PAKE closes the first-pairing MITM gap. Decisions locked.
   IN PROGRESS -> filament-professional.
2. **L2 per-sid QUIC streams** (HoL-free multiplexing). Each sid its own QUIC
   stream; kills head-of-line blocking. IN PROGRESS -> mimo-0x0
   (`design-l2-perstream-quic.md`).
3. **Merge WireGuard L3 data plane** (`feat/wireguard-l3`). Built + measured, ready.
4. **Product interface.** Formalize the control socket (`ctl.rs`) into a stable,
   versioned local API + a thin SDK (pair, peers+events, streams gated by grants,
   transfer, mount). The seam every product builds on. The highest-leverage
   "make filament usable" move.
5. **Identity layer** (user-key over device-certs). Roots in L1.
6. **Capabilities / grant** (edge-local typed signed ops). Generalize L2's
   `filament grant`; the exposed authz primitive; meets the interface at `open`.
7. **[SEPARATE PRODUCT] Compute product (lend-gpu).** CONSUMES the interface; GPU
   sandbox + consent + edge routing (OpenAI-compatible) + model distribution
   (`mount <cid>`). The p2p-send inverted. NOT filament core.
8. **Enterprise envelope** (org authority: SSO/audit/device-approval). LAST,
   demand-pulled, not a wedge.

Fabric is the FOUNDATION we own standalone (Tailscale = compat bridge only). The
WEDGE is compute (govern USE, not reachability), built as a separate product ON the
core. Pitch: "secure compute pooling among trusted devices," never "a no-account
Tailscale."

## Status by workstream

### WireGuard L3 data plane -- BUILT + MEASURED, ready to merge
- ADR: `docs/adr-0001-wireguard-as-l3-data-plane.md`
- Branch `feat/wireguard-l3`: adr `6639d6d`, wg module `691a4be`, wiring `08f72a4`.
- Numbers: loopback 0.48 -> 1.37 Gbps (0 retransmits vs 382); cross-machine
  do-vm<->other-do (~2 Gbps UDP policer) 396 -> 1256 Mbps (~99% of the UDP ceiling,
  near-clean). WG is env-bound here (shared CPU / policer), not its own ceiling.
- `serve-tun --wireguard`: filament brokers WG keys over its authed conn; kernel WG
  moves bytes. `cli/src/wg.rs` + `main.rs` wiring.
- NEXT: final review + rebase on main + merge. Bench scripts in the job tmp
  (`l3bench.sh`, `wgbench.sh`, `cross_wg_bench.sh`).

### L1 PAKE v2 (trust root) -- SPEC'D, DECISIONS LOCKED, to build
- Spec: `docs/L1-pake-protocol.md` (decisions §13, 2026-07-26).
- Locked: v2-only cutover (no v1 fallback); auto-mint 16-bit (256x256);
  user-chosen gate = "2 distinct words, not a common phrase"; gate #3
  (burn-on-claim + no-retry) HARD + negatively tested; nameplate 900 + monitor;
  `spake2 = "=0.4.0"`.
- Browser PAKE v2 substantially built (`frontend/src/lib/words.js`, `pairing.js`,
  `PakePairing`, custom-code form). Remaining: CLI/native side, server
  nameplate-only split (remove word minting in `backend/signaling.py`), decisions
  2-4, and the §10 gates (esp. negative gates #2 server-can't-derive, #3 burn+no-retry).
- NEXT: contract to filament-professional.

### L2 per-sid QUIC streams -- IN PROGRESS (mimo-0x0)
- Spec: `docs/design-l2-perstream-quic.md` (PROPOSED). Each L2 `sid` gets its own
  QUIC bidi stream (QUIC gives per-stream flow control + no cross-stream HoL), so a
  stalled stream no longer blocks the others. App-credit (`feat/l2-credit`) was
  tried and FAILED validation. Breaking wire change: v2 negotiation + v1 fallback.
- File: `cli/src/direct.rs` (also touched by the WireGuard branch; merge ordering TBD).
- NEXT: mimo-0x0 returns a plan, then implements; money test = fast stream not
  blocked by a stalled slow stream over one link.

### Product interface -- CORE, to build
- The seam: `ctl.rs`, the local 0600 unix control socket (JSON line + reply +
  raw bytes; ~15 internal ops today: open/dial/pty/mount/...). Used only by the CLI
  talking to its own daemon; internal and unstable.
- The work: (1) stabilize + version + document it as a public contract; (2) fill
  gaps a product needs -- identity/pair, peers + an EVENTS subscription, open a
  stream to peer:action gated by the grant model, transfer, grants, mount; (3) a
  thin SDK (Python first for the compute MVP, then Rust/JS).
- Boundary: filament owns the API + primitives; products own compute-specific logic
  on the consumer side. Capabilities meet the interface at `open`.
- Spec: `docs/design-product-interface.md` (design 2026-07-26, stress-tested):
  versioned JSON-NDJSON over UDS, persistent-subscription events (2 lanes,
  replay), grants = authz + registration = service-discovery/consent, 0600 now +
  scope-able later. Build seq ends by porting the lend-gpu MVP onto the SDK.

### Identity + access UX -- DESIGNED + COMMITTED
- `docs/design-identity-access-ux.md`: onboarding, contact book, introduce,
  recovery presets, capabilities (edge-local typed-signed-op CRDT), postures +
  enterprise-as-envelope positioning.
- `docs/design-introduce-user-identity.md`: user-key over device-certs (SSH-CA
  shaped), introduce-to-one-device, privacy of the device set.
- Recovery: 2 dials -> 4 presets (Anonymous-purist / Consumer-default /
  High-availability / Trusted-circle); blind federated timestamping witness for the
  compromise race; 7-day pending + old-key freeze; duress PIN; private per-contact
  contacts.

### GPU / compute product -- FEASIBILITY + POSITIONING COMMITTED
- `docs/gpu-product-feasibility.md`: trusted-group edge inference is the feasible
  wedge; open marketplace gated on verifiable-compute + open-DHT Sybil;
  identity-continuity is the owed design.
- lend-gpu MVP: `runner/` Python (23 tests): sandbox (`--network none`, mem/cpu
  caps) + consent gate + send/borrow. Awaiting GPU-host validation + Rust subcommand.

### Mesh / discovery -- DECIDED (filament stays pairwise)
- `docs/design-mesh-network.md`: no mesh/DHT/coordinator in filament core. Any
  product discovery rides on top; closed-by-default, introduce-gated (Sybil research
  conclusion: introduce IS the Sybil defense).

## Pointers
- Memory: `gpu-product-mesh-wireguard.md` (durable summary of all of the above).
- Portfolio (public): "The Data Plane Underneath", "Who are you, really".
- Adversarial design reviews this session ran through xats agent `wise-agent`.
