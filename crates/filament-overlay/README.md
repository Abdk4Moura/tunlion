# filament-overlay

Self-certifying overlay addresses: an IPv6 address derived from an Ed25519 public
key, plus signed claims to that address that are **bound to a specific link**.

Carved out of the [filament](https://github.com/Abdk4Moura/filament) CLI.

```rust
use filament_overlay::{addr_from_pubkey, Identity};

// The address IS the key. Nothing needs to hand out or agree on addresses.
let id = Identity::from_pkcs8(&pkcs8)?;
assert_eq!(id.addr(), addr_from_pubkey(&id.pubkey()));

// A claim is bound to THIS link's channel binding.
let announce = id.announce(seq, channel_binding);
let claimed_addr = announce.verify(channel_binding)?;
```

The link binding is the whole point. A signed claim to an address, on its own,
can be replayed onto a different link by anyone who observed it. Binding it to
the channel binding of the link it arrives on is what makes "this address is
mine, *here*" a checkable statement rather than a transferable token.

`seq` handles the other half: a genuine announce captured on a link can still be
replayed onto that same link later, which is an address rollback.
`seq_is_fresh` enforces strictly-increasing, and the sequence must be
**persisted** — an in-process counter restarts at zero, so a peer that restarts
announces 0, 1, 2 while its peers still hold a last-seen of 47, and every one of
them locks it out permanently. That failure is silent, per-peer, and looks
exactly like a network problem. A timestamp is deliberately not used: it imports
clock skew into a security check.

Where the key file lives, and who generates it, is the caller's business. This
crate takes the bytes.

MIT licensed.
