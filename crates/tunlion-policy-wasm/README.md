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

This crate is the browser's only transfer-admission decision. The frontend
translates its real link facts into the input below and calls
`admitTransfer`; it keeps no allow rule of its own. The browser still has no
device certificate and no owner certificate: facts it cannot establish
(revocation, certificate expiry, same-owner, invitation ceiling) stay
unestablished (false or null on the wire), and the core decides without them. A
decision that cannot reach this core is an `unsupported` denial, never an
allow.

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

The browser gate `frontend/tests/policy-wire.spec.cjs` reads that JSON file,
calls the committed module's `admitTransfer(JSON.stringify(case.input))`, and
compares the parsed result with `case.expected` in a real Chromium tab.

## Browser wiring

`frontend/src/lib/policy.js` is the adapter:

- `toAdmitInput(facts)` builds the complete DTO. There are no defaults on the
  wire; a missing `now` never calls the core.
- `admitTransfer(input)` is the raw JSON surface used by the shared-vector
  gate. It calls the wasm export of the same name.
- `decideTransfer(facts)` calls the core with an explicit `now` and maps its
  answer to allow/deny. Core errors become an `unsupported` denial.

`frontend/src/lib/policyCore.js` loads the committed module; the artifact is
produced by `build-wasm.sh` in CI and committed under `frontend/src/policy/`
from that run's artifact (see `.github/workflows/policy-wasm.yml`). It is not
generated in this change.

## Build commands (for CI or a remote worker)

```sh
cargo test -p filament-policy -p filament-cap -p tunlion-policy-wasm
bash crates/tunlion-policy-wasm/build-wasm.sh
```

The second command needs the `wasm32-unknown-unknown` target installed. The
generated wasm is committed from the CI artifact after review; see
`frontend/src/policy/README.md`.
