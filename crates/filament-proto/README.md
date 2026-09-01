# filament-proto

The file-transfer wire vocabulary and its pure ceremony decisions, carved out of
the [filament](https://github.com/Abdk4Moura/filament) CLI.

Pure by construction: bytes and state in, a decision out. No timers, no retries,
no transport, no filesystem. The stateful event loops own the I/O and call in
here.

```rust
use filament_proto::{decide_verify, VerifyResult};

// Full size but the hash is wrong: the body is corrupt, so the partial is
// poisoned and the transfer must restart from zero.
assert_eq!(
    decide_verify(100, 100, Some(false)),
    VerifyResult::Mismatch { restart_from_zero: true },
);

// Short: merely truncated, so resume the tail.
assert_eq!(
    decide_verify(60, 100, None),
    VerifyResult::Mismatch { restart_from_zero: false },
);
```

That distinction is the point of the crate. Treating a corrupt full-size file as
resumable appends to poisoned bytes forever; treating a truncated file as corrupt
throws away work that was fine.

The message builders are the exact JSON control shapes, one definition each
rather than inline literals scattered through the send and receive loops. They
mirror `frontend/src/net/protocol/transfer.js`, and that mirroring is why the
shapes belong in one place: a divergence is a silent interop break with the
browser peer.

`decide_ack_fallback` never returns "complete". A send is delivered only on a
genuine `delivery-ack`, because bytes draining out of a send buffer prove
nothing: a path that black-holes without ICE or QUIC noticing drains happily
while nothing arrives.

MIT licensed.
