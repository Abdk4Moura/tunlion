# Pure route acceptance extraction

`filament_peerloop::mesh::route::accept_advertised` takes a signed advertisement's
verified prefix strings and `RoutePolicy` (receiver consent, persisted ceiling,
owner public key, cap-store snapshot, authenticated link keys and host time).
It returns `RouteAcceptance { accepted, declined }`. Strings/order/duplicates are
preserved; the caller must apply even an empty accepted set as a withdrawal.

Authority is receiver consent **AND** (persisted `route:<cidr>` containment **OR**
`authorize_in` for the owner-bound prefix resource and `CAP_ROUTE`). This preserves
the existing cap evaluator, including its owner semantics and `auth_key_caps=None`;
it does not impose a new ceiling intersection or a grants-only rule.

The CLI still resolves `accept-routes` with exactly `on`/`true`, reads persisted
identity/ceiling/store facts, verifies the base announce and channel binding,
checks revocation/expiry/freshness and identity pinning, admits the transport,
verifies the route signature, and applies/logs the result. The policy is pure:
no host trait, filesystem, environment, task, TUN/netstack or OS route operation.
It is under the existing `mesh` feature, with no new feature or dependency.

## Follow-ups deliberately not fixed here

- **Cached announce replay:** `ChannelReady` currently adds the host route but
  does not apply the signed subnet set. Unify immediate/replay application in a
  separately tested behavior fix.
- **Revoke/forget and table ownership:** `L3::remove_by_pid` does not remove
  transport-keyed subnet entries; `set_peer_subnets` ignores pid. Add explicit
  peer/generation ownership and kernel reconciliation on withdrawal. Dead-default
  liveness filtering is not a substitute for removing this stale authority.
- **Platform/task cleanup:** TUN pumps, forwarding/firewall applied state,
  exit-route plans and hosts-file changes need explicit owners and teardown.
- **Feature exclusion:** a later positive `route` feature must gate actual
  route state/dispatch and effects; a linked Android engine must exclude
  mesh/route and their endpoint providers in an isolated compile graph.

This is an extraction of existing acceptance semantics, not a whole-sector
safety claim. `Core::start`/`Core::stop` now run the reduced dispatch, but signed
cap-store fixtures do not prove real kernel routing, replay handling or teardown.
Rust builds/tests run in CI only for this PR.
