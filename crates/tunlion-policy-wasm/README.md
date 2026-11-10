# tunlion-policy-wasm

A deliberately small bridge from a browser to Tunlion's one
transfer-admission decision.

```text
admitTransfer(inputJson: string) -> outputJson: string
```

The decision itself is `filament_policy::transfer_decision`, the same function
`filament-cap` re-exports and the CLI/Core call. This crate owns only the JSON
wire shape. It contains no crypto, no clock, no filesystem, no runtime and no
network stack. `now` is required in the input; there is no implicit
`Date.now()`.

## Scope

This is a de-risking slice. It moves the pure allow/deny rule onto code the
browser can compile. It does **not** end the browser's pairwise-only trust
model by itself: the frontend is not wired to this module yet, and the browser
still has to supply the surrounding identity, revocation, expiry and fleet
facts from its own transport path.

## Input

All fields are required. Unknown fields are refused, so a caller cannot smuggle
an unhandled fact past the policy.

```json
{
  "authoritative": true,
  "legacyAllowed": true,
  "outcome": { "kind": "authorized" },
  "certRevoked": false,
  "denied": false,
  "authKeyCaps": null,
  "certExpires": 2000,
  "now": 1000,
  "sameOwner": false,
  "binding": "proven",
  "scopedInBounds": true,
  "hasExplicitGrant": false,
  "ceilingAuthorizes": false,
  "identityState": "resolved"
}
```

`outcome.kind` is `authorized`, `denied` (with `reason`), or `unprovisioned`.
`binding` is `none`, `proven`, or `inferred`. `identityState` is `pending`,
`resolved`, or `explicitlyUnavailableAnonymous`.

## Output

```json
{
  "allowed": true,
  "deny": null,
  "denyReason": null,
  "observableOutcome": { "kind": "authorized" },
  "fleetOk": false,
  "ceilingOk": false
}
```

A denial carries `deny` (`revoked`, `denied`, `ceiling`, `expired` with `at`,
`anonymousOutOfBounds`, `anonymousNoConsent`, `fleetNeedsGrant`, `unauthorized`
with `reason`, or `shadowLegacy`) and the operator-facing string in
`denyReason`. Invalid input returns `{"error":"..."}` instead of panicking
across the FFI boundary.

## Shared vectors

`testdata/transfer_vectors.json` is the single source of truth for native and
browser checks. The native test replays every case through the same Rust
function the wasm export calls:

```sh
cargo test -p tunlion-policy-wasm
```

A future browser test should fetch that JSON file, call
`admitTransfer(JSON.stringify(case.input))`, and compare the parsed result with
`case.expected`.

## Intended next wiring (not done here)

1. Build the module for the browser:
   `wasm-pack build crates/tunlion-policy-wasm --target web --out-dir pkg`
   (or `cargo build -p tunlion-policy-wasm --target wasm32-unknown-unknown`
   for a compile-only check). The generated `pkg/` directory is not committed.
2. In the frontend transfer-admission path, replace the local boolean with a
   call to `admitTransfer`, passing the capability outcome, revocation/expiry,
   binding, identity state, fleet facts and a caller-supplied `now`.
3. Run the shared vectors in the browser harness before changing any default.
4. Only then evaluate the larger question — browser pairwise-only trust — as a
   separate change. This slice does not answer it.

## Build commands (for CI or a remote worker)

```sh
cargo test -p filament-policy -p filament-cap -p tunlion-policy-wasm
cargo build -p tunlion-policy-wasm --target wasm32-unknown-unknown
```

The second command needs the `wasm32-unknown-unknown` target installed. No
generated wasm is checked in.
