# Feasibility: a GPU-compute product riding on filament

> Status: assessment (2026-07-25). Not a commitment to build. This memo answers
> "can a Salad/Vast-class GPU-compute product be built ON filament, and what is
> the honest wedge," grounded in filament's own decisions and two research passes
> (GPU-linking, and Sybil-vs-anonymity) run this session.

## The framing that makes it coherent

The product **rides on** filament; it is not filament. This matters because
filament already decided (`docs/design-mesh-network.md`, 2026-07-16) to stay
**strictly pairwise**: no mesh, no DHT, no gossip, no coordinator, no transitive
trust. It declines multi-hop reach and says "use a mesh product instead of
filament for that."

That decision is not a blocker; it is the architecture. filament separates two
things the product must keep separate too:

- **Authorization** (who I open a secure channel with): pairwise, explicit,
  introduce-assisted. Absolute in filament, and the product must not violate it.
- **Reachability** (who can route bytes to me): the layer filament keeps and
  hardens (holepunch, relay, self-hostable rendezvous).

The product builds its discovery / pool / routing in the **reachability** layer,
on top of filament's pairwise authorized channels, and it keeps **authorization
pairwise and introduce-gated**. It never asks filament to authorize transitively
or hold group state. The pool/registry is a product-layer concern.

This is exactly what the Sybil research independently recommended: closed-by-
default, PAKE-introduce as the Sybil defense (not a bolt-on), and a DHT used only
as a reachability/rendezvous aid between already-introduced peers, never as a
stranger-discovery mechanism (RetroShare's "admission and discovery are
orthogonal dials"). filament's mesh decision and the Sybil posture converge on the
same shape: **introduce-gated trust, reachability-only discovery.**

## What filament already provides (the primitives)

| Primitive | State |
|---|---|
| Pairwise authorized, channel-bound secure channels | shipped |
| Anonymous key-derived identity (overlay IP = f(Ed25519), no accounts) | shipped |
| Kernel-WireGuard data plane | built + measured this session (ADR-0001) |
| Introducer-TOFU trust bootstrap (key-exchange helper, user confirms) | designed/shipping |
| Sandbox + consent gate (Docker: --network none, mem/cpu caps, --user nobody, /work ro, timeout) + live stdout/stderr + file shipping | lend-gpu MVP, 23 tests passing |
| Content-addressed `mount <cid>` | mesh-native mount protocol foundation shipped |

## The feasible product: trusted-group edge inference

Both research passes force the same wedge (and away from the market map's
open-marketplace ambition):

- **Inference, not training.** Training over a consumer mesh is bandwidth-bound
  and effectively a meme (GPU-linking research; the market map agrees). Low-latency
  edge inference is unserved.
- **Trusted group, not open marketplace.** A trusted/introduced pool is Sybil-free
  by construction and needs no verifiable-compute (you trust your own/introduced
  hosts). An open pool of strangers hits two unsolved walls at once (below).

The shape:

- **Hosts**: one-click (Windows-native is the liquidity wedge; 80% of consumer
  4090s are on Windows gaming rigs, and filament already leans Windows), lending an
  idle GPU inside the lend-gpu sandbox.
- **Borrowers**: an OpenAI-compatible endpoint that routes to the nearest
  *introduced* lender over a pairwise WireGuard tunnel.
- **Model distribution**: `mount <cid>` so hosts stream model blocks content-
  addressed instead of re-pulling from S3. This is the "data plane, not control
  plane" gap nobody else fills.
- **Pool/registry**: a product-layer roster built from pairwise introductions; a
  stable peer doubles as relay + rendezvous (filament's sanctioned pattern). No
  transitive trust; every borrower-lender channel is separately authorized.

## The two walls that gate the OPEN version (and why we start closed)

1. **Verifiable compute / proof-of-inference is unsolved cheaply.** Enterprise will
   not run on random nodes without proof; nobody has cheap proof-of-inference. The
   market map lists it as a gap then assumes it anyway. A trusted pool sidesteps it.
2. **Open-DHT Sybil/eclipse is unsolved durably.** Even a hardened IPFS is still
   beaten by new attacks as of 2026; BitTorrent MLDHT ran ~300k live Sybils;
   Ethereum eclipse needs two hosts. Key-derived identity stops impersonation, not
   flooding. A closed/introduced pool sidesteps it.

So the sequencing is forced, not chosen: trusted-group first; the open,
permissionless, enterprise-on-strangers marketplace is a later expansion gated on
two independent hard-research problems.

## The design we would owe: identity continuity

No comparable anonymous-key mesh (cjdns, Yggdrasil) solved multi-device, key
rotation, or key-loss recovery: "lost key = lost identity forever, one key = one
node." For a consumer product this is a host losing their laptop and losing their
host identity and accrued standing. This is both:

- a differentiation opportunity: define identity as a set of linked, individually-
  revocable device keys, with **social recovery via the same introduce-graph** used
  for trust; and
- a real risk: original UX design in the exact area "Why Johnny Can't Encrypt"
  proved is easy to get catastrophically wrong.

## Honest seams (do not oversell)

- **No-account is not zero-trusted-parties.** A small bootstrap/rendezvous seed is
  unavoidable; the honest goal is small, diverse, replaceable, non-load-bearing
  once a peer has one introduced contact. filament's signaling server is already
  this (rendezvous, not coordinator) and is on a self-hostable trajectory.
- **Vouching-chain abuse is not covered by Sybil defense.** A malicious introduced
  host, or one that introduces bad actors into the pool, needs a revocation layer
  ("eject a bad host") the product must own.
- **Consumer GPUs lack TEEs.** Data privacy defaults to "trust the host" (already
  noted in the lend-gpu MVP). Confidential compute is out of reach on this hardware.

## Verdict

A **no-account, trusted-group, edge-inference** product is feasible on filament's
existing primitives plus the WireGuard data plane built this session. It is
"Tailscale-for-GPUs for a trusted fleet/community," and it respects filament's
pairwise core by keeping authorization pairwise and building pool/discovery in the
reachability layer. The open marketplace is gated on verifiable-compute and open-
DHT Sybil resistance, both unsolved. The one net-new design the feasible version
owes is identity continuity.

## Network-homework scorecard

| Layer | State |
|---|---|
| Secure data plane (WireGuard) | done, measured |
| Trust / Sybil posture | done, researched: closed-by-default, introduce-gated |
| filament mesh boundary | decided: filament stays pairwise; product rides on top |
| Discovery / routing (reachability layer) | product-layer; reuse rendezvous/relay pattern |
| Identity continuity | net-new gap, must design |
| Model distribution (mount + CID) | wedge exists; streaming layer TBD |
| Sandbox + consent | done (lend-gpu MVP) |
| Edge routing surface (OpenAI-compatible) | not built |

## Sources in-repo

- `docs/design-mesh-network.md` (filament stays pairwise)
- `docs/adr-0001-wireguard-as-l3-data-plane.md` (data plane, measured)
- lend-gpu MVP notes (`LEND_GPU.md`, `LEND_GPU_RUST_SPEC.md`, worktree)
- session research: GPU-linking (RDMA vs kernel vs userspace), Sybil-vs-anonymity
