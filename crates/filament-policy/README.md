# filament-policy

The pure transfer-admission rule, extracted so it can be compiled anywhere.

`filament-cap` re-exports every public item here under its historical
`filament_cap::capability::*` paths. The CLI, Core and peerloop therefore keep
their existing imports, and the existing `filament-cap` tests still exercise
this code. The browser calls the same function through
`tunlion-policy-wasm`'s `admitTransfer`.

## Why a separate crate

The rule is pure. It needs no filesystem, runtime, socket, QUIC/WebRTC stack,
secret store, native TLS, crypto or clock. Given the same facts and the same
`now`, it returns the same decision. That is what makes it safe to compile to
WASM and safe to replay from shared vectors.

The clock is the important boundary: `TransferGateInput::now` is the only time
value the decision reads. `filament-cap` keeps a wall-clock
`cap_authorize_expired` wrapper for old callers, but the shared expiry composer
is `cap_authorize_expired_at(..., now)`.

## What is here

- `TransferGateInput`, `TransferDecision`, `TransferDeny`
- `BindingStrength`, `IdentityState`, `CapOutcome`
- `transfer_decision` — THE transfer allow/deny policy
- `fleet_auto_trust`
- `cap_authorize_proven`, `cap_authorize_expired_at`
- `CAP_TRANSFER`

## Scope

This is a de-risking slice, not a claim that browser trust is now equivalent to
native trust. The frontend is not wired to this crate yet. Identity
establishment, revocation freshness and transport binding remain the caller's
responsibility on every host.

## Test the vectors

`crates/tunlion-policy-wasm/testdata/transfer_vectors.json` covers allow,
anonymous transfer, pending identity, revocation, ceiling denial and expiry.
The native test replays them through the shared decision:

```sh
cargo test -p tunlion-policy-wasm
```

## License

MIT
