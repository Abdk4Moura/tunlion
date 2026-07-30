# filament-pair

Password-authenticated device pairing (PAKE, SPAKE2 over Ed25519) from a short
human-readable code. Two devices that both type the same few words derive the same
32-byte shared secret; a network attacker who does not know the code learns
nothing, and cannot silently substitute their own transport identity.

This is the pairing core (L1) of
[filament](https://github.com/Abdk4Moura/filament) — the same implementation runs
native and in the browser (wasm32).

## What's inside

- **Symmetric SPAKE2** — `start()` returns a 33-byte outbound element + opaque
  state; `finish()` consumes the peer's element and returns the shared value `K`
  (both peers may initiate; both must pass the identical password and identity).
- **Key confirmation** — `confirm_mac(K, dir, fp_lo, fp_hi, caps)` folds the
  **sorted transport fingerprints** and the **agreed capability set** into the
  confirmation MAC, so a middlebox that swaps the transport certificate or rewrites
  the capabilities breaks confirmation instead of going unnoticed.
- **Secret derivation** — `secret_from_k(K)` HKDFs to the 32-byte pinned secret
  (agreed, never transmitted).
- **Word lists** — the `words` module for rendering/parsing the human code.

Production randomness is `OsRng` (getrandom / `crypto.getRandomValues`).

## Status

Pre-1.0; API may change between minor versions. Security-reviewed, not independently
audited. See `docs/L1-pake-protocol.md` in the filament repo for the protocol.

## License

MIT
