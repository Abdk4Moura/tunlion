# Durable transfer requests: first engine slice

Status: library state store implemented; receive-dispatch and CLI wiring are the
next slice.

## Scope

`crates/filament-peerloop/src/recv/requests.rs` owns the receiver-side record for
an asynchronous file offer. It answers four questions without touching the
network, the terminal or file placement:

1. Is this exact manifest well formed and safe to store?
2. Is the sender, as observed *now*, allowed to create or advance this request?
3. What decision and destination are durably recorded for that exact digest?
4. What authoritative snapshot should a client see after a restart?

It deliberately does not deliver bytes, approve capabilities, or promise that an
offline sender will return.

## Encoded rules

- A manifest has 1..=256 entries with relative, traversal-free paths and a
  mandatory lower-case 64-hex SHA-256 per entry. Entries are sorted, duplicate
  and case-fold duplicate paths are refused, and total bytes/metadata are
  bounded.
- The digest covers `path`, `size` and `sha256` only. `mtime` is display
  metadata and cannot change the reviewed agreement.
- A record is one exact offer id plus manifest. Reusing an offer id with a
  different sender or digest is refused. A fulfilled/denied/expired record that
  has been pruned leaves a tombstone so the id cannot be replayed.
- States are `pending`, `approved` (accepted; waiting for the sender),
  `delivering`, `denied`, `expired`, `fulfilled`, `failed`, `withdrawn`.
  `approved` never means bytes arrived.
- Same-owner offers are auto-approved only when the caller supplies a
  destination. External offers stay pending for review.
- Acceptance binds the exact manifest digest and a destination string.
  Destination confinement to receive roots remains the caller's policy.
- Every write requires a fresh `SenderIdentity` observation. A revoked,
  unverified, unknown or expired sender is refused even if acceptance succeeded
  earlier. Stored sender fields are a snapshot, not a capability.
- Mutations are revision-checked. The store is written atomically under a
  cross-process lock. A mutation returns its notification event only after the
  commit; there is no notification inside the store.
- Snapshots are full authoritative snapshots. A cursor below the retained
  terminal floor reports `resync_required`. There is no event log or mailbox.
- Terminal records and tombstones are bounded. No record contains grants or
  capability lists, so accepting an offer creates no standing access.

## Deliberately not in this slice

- Receive dispatch does not yet create or advance these records on a real
  `file-offer`.
- Sender-side retained offers and retry scheduling.
- Multi-file transport grouping; the current wire offer is one file, stored as
  a one-entry manifest.
- Destination confinement, free-space reservations and per-chunk authority
  rechecks at delivery time.
- CLI request list/accept/decline adapters over this store.

## Verification

Remote unit suite: `cargo test -p filament-peerloop --lib requests::tests`.
The tests cover canonicalization and unsafe paths, sender refusal, same-owner
versus external decisions, exact digest/revision binding, restart persistence,
idempotent decline, tombstone replay refusal, fresh-authority delivery, expiry,
bounded retention and snapshot resynchronization.
