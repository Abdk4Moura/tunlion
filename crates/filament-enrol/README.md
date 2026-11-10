# filament-enrol

The host-free half of Tunlion's pairing enrolment ceremony, extracted from
`cli/src/pair_cmd.rs` so the CLI and a browser compile the **same** code.

```text
filament_enrol::build_enrol_offer       sealed "here is my device key" offer
filament_enrol::open_enrol_offer        verify that offer for THIS ceremony
filament_enrol::enrol_offer_decision    certify / ask / decline, once per ceremony
filament_enrol::seal_enrol_grant        seal an owner-built grant payload
filament_enrol::open_enrol_grant        open a sealed grant
filament_enrol::verify_mesh_grant       pure certificate checks before storing
filament_enrol::verify_cert_chain       pinned-owner certificate verification
filament_enrol::build_identity_expose   sealed cert + possession signature
filament_enrol::open_identity_expose    verify a peer's sealed expose
filament_enrol::enrolment_outcome       what a finished pairing should report
filament_enrol::browser_hint            the advisory browser device-kind marker
filament_enrol::DeviceIdentity          seed -> offer -> grant -> expose -> verify peer
```

## Boundary

This crate contains no `std::fs`, no clock, no runtime, no network stack, no
WebRTC, no QUIC, no `secret-write` and no native TLS. The rules are:

* `now` is an argument to every lifetime check.
* AEAD nonces and Ed25519 seeds are arguments; callers own randomness.
* The owner/device signing keys are injected through `UserKey` values or a
  signing closure.
* Key persistence is the `SeedStore` trait; fleet/capability store reads stay in
  the CLI and are passed in as an already-built grant payload.
* Frames are serde structs (`EnrolOffer`, `EnrolGrant`, `IdentityExpose`).
* The only crypto is `filament-id`'s ring-backed Ed25519, HKDF and
  ChaCha20-Poly1305. There is no second certificate, possession or seal
  implementation.

The CLI keeps only the host glue: where the keys live, the wall clock, the
terminal prompt, the signal transport, `secret-write`, and the on-disk fleet and
capability stores. `persist_mesh_grant` now calls `verify_mesh_grant` before it
writes anything.

## CLI integration points

`cli/src/pair_cmd.rs`:

| CLI site | Shared call |
| --- | --- |
| offer send loop | `build_enrol_offer`, with `fresh_seal_nonce()` |
| owner receives `enrol-offer` | `EnrolOffer::from_value` then `open_enrol_offer` |
| owner decision | `enrol_offer_decision` |
| owner issues a grant | existing `mesh_enrolment` payload then `seal_enrol_grant` |
| device receives `enrol-grant` | `EnrolGrant::from_value`, `open_enrol_grant`, `persist_mesh_grant` |
| `persist_mesh_grant` | `verify_mesh_grant` (now pinned to the peer's owner when known) |
| device/owner sends `identity-expose` | `build_identity_expose`, with `fresh_seal_nonce()` |
| `identity-expose` received | `IdentityExpose::from_value`, `open_identity_expose` |
| post-ceremony report | `enrolment_outcome` |
| browser marker | `browser_hint` |

The CLI still builds the grant payload through `mesh_enrolment`, exactly as the
invitation path does. The crate does not read the fleet rendezvous, capability
header or owner certificate; those arrive in the payload.

## Shared vectors

`testdata/enrol_vectors.json` is the single source of truth for the six required
cases plus a within-ceremony replay rule:

* valid offer + grant round trip
* forged possession proof
* wrong device key
* wrong owner
* expired certificate
* replayed offer in another ceremony
* replayed offer within one ceremony (decision declines)

The fixture stores the ceremony key, fingerprints, capability string, Ed25519
seeds, nonces and times. It does **not** store captured ciphertext: both a
native test and a browser harness derive identical frames from those inputs.
`tests/enrol_vectors.rs` replays every case through the public API and checks
the stable `EnrolError::code()` value.

## Remote validation (no local build was run)

From a clean checkout of the branch:

```sh
git fetch origin feat/browser-enroll-core
git worktree add /tmp/tunlion-browser-enroll origin/feat/browser-enroll-core
cd /tmp/tunlion-browser-enroll

# 1. The shared crate: vectors, seed store, DeviceIdentity.
cargo test -p filament-enrol --all-targets

# 2. The CLI still compiles and its pairing/enrolment tests still pass.
cargo test -p tunlion --bin tunlion pair_cmd

# 3. The whole product graph is still coherent.
cargo check --workspace

# 4. Compile-only wasm check (no artefact committed). Needs the target:
rustup target add wasm32-unknown-unknown
cargo check -p filament-enrol --target wasm32-unknown-unknown
```

`ring` is the only transitive dependency that has historically been awkward on
`wasm32-unknown-unknown`; this commit does not add a second crypto backend to
work around it. If the wasm check fails inside `ring`, that is a toolchain
issue, not logic in this crate.

## What this commit does NOT do

It does **not** make the browser a fleet device. There is no frontend wiring, no
generated wasm artefact and no UI in this change. A browser remains a
pairwise-only peer until the frontend state machine:

1. creates and persists a browser `DeviceIdentity` seed,
2. drives the offer / hold / grant / ack frames on its transport,
3. verifies and stores the grant, and
4. uses the certified key for fleet admission.

Until then, calling this crate proves that the ceremony logic is shared and
testable, not that a browser is admitted by a CLI.
