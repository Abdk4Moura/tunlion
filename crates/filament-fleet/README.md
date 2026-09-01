# filament-fleet

Same-owner device auto-mesh: devices certified by **one owner key** find each
other on a rendezvous channel and admit each other on that **certificate**,
never on presence.

Carved out of the [filament](https://github.com/Abdk4Moura/filament) CLI.

The channel is a meeting point and nothing more. Anyone who learns its id can see
that devices are there, and none of them can be admitted, because admission
requires an owner-signed certificate bound to a live possession proof over *this
link's* channel binding. A hello captured on one link cannot be replayed onto
another, and a valid certificate for device X cannot front for device Y's
possession proof.

What auto-mesh grants is **reachability, not capability**. A newly met sibling is
admitted with an empty ceiling: the link forms and routes, while transfer, shell
and mount each still need an explicit grant. A bug here cannot escalate
privilege; it can only connect something it should not have.

## `session::FleetSession`

The per-peer conversation: who has been challenged, who proved themselves, who
proved to be somebody *else*, and who ran out of time.

Its state is keyed by peer id **by construction**, and that is the point of the
type. The same conversation used to be written inline, twice, and both copies
stored per-peer facts as single values on a channel that carries every sibling.
Four bugs came out of that, including a misdelivery: one sibling verifying opened
the offer guard for all of them. A pair channel has exactly one peer on it, so
that code was correct before auto-mesh and wrong after it.

There is no I/O. `greet` and `on_control` return an `Action`/`Outcome` that the
caller sends, and building your own hello is injected as a closure, because that
needs the host's key and certificate.

MIT licensed.
