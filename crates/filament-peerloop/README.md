# filament-peerloop

Host-free policy for tunlion's peer loop, carved out of the CLI's
`cli/src/conn.rs`.

Carved out of the [tunlion](https://github.com/Abdk4Moura/tunlion) CLI.

`Conn` carries link state, adoption policy and presentation together, and it is
what every command's event loop manipulates. This crate is the half of that
which is *not* about this machine: it has no opinion about how a peer was found,
authenticated or named, where files live, or how anything is rendered to a
terminal. That is the rule `docs/design-libfilament.md` sets for what may leave
the CLI, and the reason this can be a crate while `Conn` stays behind is the
first proof that the split is real.

What is here:

- **`warm::WarmHold`** -- the warm-hold decision machine. Which peers are worth a
  proactive link (explicitly configured, auto-warmed, or recently used), their
  exponential reconnect backoff, and when a peer goes dormant and gets one probe
  per retry window instead of never.
- **`liveness`** -- `link_dead_for` / `link_has_live_for` (the #246 rule that a
  link mid-`establish` is alive even with no transport yet), `ice_fallback_allowed`
  and `direct_permitted`.
- **`retry`** -- `stuck_backoff` and `schedule_retry`: how long the stuck-link
  ladder waits, and the armed timer that posts the retry back to the loop.
- **`adoption`** -- `match_adoption_source`, `active_binding_matches` and
  `peer_targetable`: whether a roster entry may be adopted, whether a link still
  belongs to the peer a transfer is bound to, and whether a peer may become the
  transfer target.
- **`petname`** -- `link_petname` and the rule it encodes: a device lookup joins on
  the petname a link PROVED it reaches, never on the broadcast display name.

`Conn` itself is not here. It moves in the next slice, as a `git mv`, on top of
this crate.
