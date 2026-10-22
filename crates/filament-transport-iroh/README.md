# filament-transport-iroh

An **optional, feature-gated PoC** that adds iroh as a relay transport behind
tunlion's existing `Transport` trait.

- Default: **off**. The `iroh-transport` cargo feature is empty by default, so
  iroh is not in a normal build's dependency graph.
- Runtime: **off** unless `FILAMENT_IROH=1`.
- No caller changes: `IrohTransport` implements
  `filament_transport::net::Transport`.
- No second identity: the iroh node key is derived from the Ed25519 device key
  and published with a device-key signature.
- No public relay default and no forced relay: a missing or dead relay is an
  error, and the host keeps its existing transport.

## Run the acceptance test

From the workspace root:

```sh
cargo test -p filament-transport-iroh \
  --features iroh-transport,test-relay -- --test-threads=1
```

The acceptance test binds two nodes to an in-process iroh relay with
`relay_only: true` (no IP transports), opens a bidirectional stream, echoes
bytes both ways, exchanges a control frame and a datagram, and asserts the two
ends derive the same TLS channel binding. It also asserts the **selected path is
the relay**, so a loopback direct path cannot be mistaken for success.

## Run the demo

```sh
cargo run -p filament-transport-iroh \
  --features iroh-transport,test-relay --example relay_echo
```

Observed on the Linux worker (2026-10-21):

```text
relay: https://127.0.0.1:46395/
A endpoint: 8e368e5e2ba6029b4eab470f1925e4a0a8e4f86247de0f005b44b9a2a0a2286d
B endpoint: 11418a2a787a8db0cd1ab735d1eb0e19db1d5200f7666e6386df51bf3aac0362
A device:   d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
B device:   a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0
connected: A sees device a09aa5…a4f0 / node 11418a…0362 / relay path Some(true)
B got b"tunlion over iroh relay" sid=7 offset=Some(0) from node-a
A got echo: b"echo: tunlion over iroh relay" (sid 7)
datagrams supported, max payload 1414
B got datagram: b"ping-datagram"
channel binding equal: true (len Some(32))
PASS: relay path carried a bi stream, an echo and a datagram
```

## Integrate

```rust
use filament_transport_iroh::{DeviceIdentity, IrohConfig, IrohNode, RelayPlan};

// Host glue: load the DER bytes of the EXISTING device key (e.g.
// overlay.ed25519). Do not generate a second key.
let identity = DeviceIdentity::from_pkcs8_der(&der)?;
let relays = RelayPlan::from_urls(&["https://relay.example.net"])?;
let node = IrohNode::bind(identity, IrohConfig::new(relays)).await?;

let transport = node
    .connect("peer-sid", peer_binding, Some(&relay_url), event_tx)
    .await?; // Err => caller keeps its current transport
```

`peer_binding` is the `IrohBinding` learned over the host's existing signed
channel. `transport.peer_device_pub()` is the **verified** device key; check it
against the existing certificate/roster before authorizing anything.

## Read next

`docs/design-iroh-transport-poc.md` in the repository root: scope, API gaps,
what is genuinely working, and the staged integration plan.

## Licence

MIT.
