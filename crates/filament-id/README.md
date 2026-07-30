# filament-id

Multi-device identity with no certificate authority: one **user key** signs a
**device cert** for each of your machines, SSH-CA shaped. A peer proves it is
"you" by presenting a device cert that chains to your user key and proving
possession of that device's private key — no directory, no online check.

This is the identity layer of
[filament](https://github.com/Abdk4Moura/filament), extracted for reuse.

## What's inside

- **`UserKey`** — the root of your identity. `generate` / load via a `KeyStore`
  (you provide the platform key storage; the crate is storage-agnostic).
- **`DeviceCert`** — a user-key-signed statement binding a device public key (and
  its capabilities and expiry) to your user identity, with an injective canonical
  encoding and offline `verify`.
- **Possession proofs** — the message construction a device signs to prove it
  holds the private key its cert names, so a stolen cert alone is inert.

The model is deliberately CA-free and pairwise: identity is something your own
devices share, not an account issued by a third party.

## Status

Pre-1.0; API may change between minor versions. Part of filament; security-reviewed,
not independently audited.

## License

MIT
