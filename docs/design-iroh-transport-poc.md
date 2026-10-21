# iroh as an optional relay transport — PoC design note

**Status:** proof of concept, feature-gated, not integrated, not merged.
**Date:** 2026-10-21.
**Base:** `work/iroh-transport-poc` branched from `feat/filament-peerloop-l3`
at `edbf792d` (2026-10-21 22:54 UTC). That branch carries the current
`filament-peerloop` crate and the current `Transport` trait; `main` is five
weeks stale and has neither.

**Non-goals, explicit:** no production cutover, no daemon changes, no change to
`cli/src/l3.rs`, `cli/src/tun/**`, `filament-peerloop/src/mesh.rs`,
`filament-peerloop/src/host.rs` or the overlay crate, and no merge, tag or
deploy. The PoC adds one crate and does not edit any existing `.rs` file.

---

## 1. What was investigated

### 1.1 The existing transport contract

`filament_transport::net::Transport` (in `crates/filament-transport/src/net.rs`)
is the whole interface the transfer, L2 and L3 layers consume. It is not a
socket trait; it is a *link* trait:

| Method | Contract |
| --- | --- |
| `send_control(&Value)` | one JSON control message, ordered with data |
| `send_frame(sid, offset, payload)` | `[u32 BE sid][u64 BE abs_offset][payload]`, backpressured |
| `flush()` | per-file flush; must not end the stream |
| `drain_finish()` | final delivery barrier; may end the send half |
| `max_payload()` | largest single frame payload |
| `sid_answerer()` | which half of the L2 sid space this end owns |
| `supports_datagrams()`, `send_datagram`, `recv_datagram`, `max_datagram_size` | L3 packet plane |
| `channel_binding()` | per-connection secret a relay cannot reproduce |
| `open_stream()`, `quic_connection()` | quinn-typed mesh reuse handles |
| `idle_ms`, `is_alive`, `is_dead`, `force_close`, `has_flowed` | liveness / teardown |
| `rtt_ms`, `remote_addr`, `local_ip` | display and path selection |
| `as_any()` | concrete-type escape hatch |

The direct-QUIC implementation (`direct.rs`) already solves the "QUIC is a byte
stream but the layers want messages" problem with one framing:
`[1B kind][4B BE len][body]`, kind 0 = control JSON, kind 1 =
`[sid][offset][payload]`. Its reader demultiplexes into
`Ev::Control(peer_id, Value)` and `Ev::Chunk(peer_id, sid, Some(offset), Bytes)`
on an `mpsc::UnboundedSender<Ev>`. The PoC reuses that framing byte for byte,
which is what makes it possible to add a third `impl Transport` without touching
a caller.

### 1.2 Peer-loop link/mux boundaries

On the base branch, `filament-peerloop` owns the connection state machine:

- `src/conn.rs` — `Conn`, `Link`, adoption, warm links, the establish ladder.
  A transport enters the system as `Ev::ChannelReady(pid, Arc<dyn Transport>)`;
  the direct rung additionally emits `Ev::DirectReady` / worker events after its
  authenticated race. `adopt_direct` installs a transport for a peer and
  re-emits `ChannelReady`, so any second transport implementation can ride the
  same path.
- `src/link_manager.rs` — pure placement policy (`Work`, `Placement::Reuse` /
  `Establish`), the relay→direct `VerifyAction` and no-flap guard. It reasons
  over `LinkObs` and does not know concrete transports.
- `src/l2/mux.rs` — the L2 stream multiplexer, which speaks only
  `send_frame` + `Ev::Chunk` + the sid space. `sid_answerer()` is the only
  transport-specific fact it needs.
- `src/l3.rs` (L3 lane, not touched) — the IP data plane, gated on
  `supports_datagrams()` and `channel_binding()`. A transport with datagrams but
  no binding is deliberately not allowed to carry L3 announces.

The boundary is therefore clean for this PoC: implement `Transport`, deliver
`Ev::Control` / `Ev::Chunk`, return the right `sid_answerer`, and the L2 mux and
transfer code work unchanged. The PoC does **not** touch `conn.rs`,
`link_manager.rs` or `l2/`; wiring is left to the owners of that lane.

### 1.3 iroh API actually used (iroh 1.4.1, 2026-10-21)

`iroh` 1.4.1 is the current release. Key facts verified from the crate source,
not from memory:

- Public identity types are `EndpointId` (= `PublicKey`, 32-byte Ed25519) and
  `SecretKey`. `SecretKey::from_bytes(&[u8; 32])` means "this 32-byte Ed25519
  seed", and `SecretKey::public()` is the `EndpointId`. This is the hook the
  device-key binding needs.
- `Endpoint::builder(presets::Minimal)` + `.secret_key(...)` + `.alpns(...)` +
  `.relay_mode(RelayMode::Custom(RelayMap))` + `.bind().await`.
- Relays are a set: `RelayMap` is a `BTreeMap<RelayUrl, RelayConfig>`. There is
  no ordered failover list inside iroh. `RelayMode::Default` uses number 0's
  public relays and is never used here.
- `EndpointAddr::new(id).with_relay_url(url)` addresses a peer; `connect(addr,
  alpn)` is mutually authenticated by the iroh TLS handshake.
- `Connection::open_bi()` / `accept_bi()` give the bidirectional stream;
  `send_datagram(Bytes)` / `read_datagram()` / `max_datagram_size()` give the
  datagram plane.
- `Connection::export_keying_material(&mut out, label, context)` is the RFC 5705
  TLS exporter. This is a genuine channel binding and closes an early concern
  that iroh might not expose one.
- `Connection::paths()` exposes the selected `Path`, with `is_relay()`,
  `rtt()`, `remote_addr()` and `local_addr()`. The test uses `is_relay()` to
  prove the traffic is on the relay path.
- `Endpoint::online()` waits for a home relay and has no timeout of its own; the
  PoC wraps it.
- `iroh::test_utils::run_relay_server()` starts an in-process relay with a
  self-signed certificate; endpoints must use
  `CaTlsConfig::insecure_skip_verify()` for it.

The two QUIC stacks are different: iroh 1.4.1 uses `noq`, while tunlion's direct
path uses `quinn 0.11`. They coexist in one process but not in one type.

---

## 2. Design

### 2.1 One identity: device key → node key

The crate never generates an iroh identity. `DeviceIdentity` holds the 32-byte
Ed25519 device seed (the same seed `ring::Ed25519KeyPair` uses) and derives:

```text
Derived (default):
  node_seed  = HKDF-SHA256(salt="filament/iroh/node-key/v1",
                           ikm=device_seed,
                           info="ed25519-iroh-endpoint")
  EndpointId = PublicKey(node_seed)

Direct:
  node_seed  = device_seed
  EndpointId = device_pub
```

`Derived` avoids presenting the product's device signing key to a second
protocol stack with different transcript rules. `Direct` is the simplest
binding (`EndpointId == device_pub`, no mapping needed) and is provided for
hosts that accept cross-protocol key reuse; the default is `Derived`.

Either way the device key signs a small record:

```text
canonical = "filament/iroh/node-binding/v1"
          || version(1) || mode(1)
          || device_pub(32) || endpoint_id(32) || created(u64 LE)

IrohBinding { v, mode, devicePub, endpointId, created, sig }
```

The record travels as a **setup frame** (`kind 2`) on the iroh bidirectional
stream, written and read before the reader task starts. A peer refuses the link
if:

- the JSON does not parse or the version/mode is unknown;
- the device signature does not verify;
- the record's `endpointId` differs from `conn.remote_id()` (the id the iroh
  handshake authenticated);
- an expected device key was supplied and differs.

Why this is not a second identity:

- there is no new key file, no new enrolment, no new revocation path;
- the node key cannot be used to claim a device: the signed record binds it to
  the device key;
- the relay cannot swap the record: it cannot forge the iroh handshake for the
  node key or the device signature;
- authorization is still the existing certificate/roster check. The PoC only
  exposes `transport.peer_device_pub()`; it deliberately does not decide whether
  that device is trusted. A product caller must check it before
  `ChannelReady`, exactly as it checks the peer's device key today.

`DeviceIdentity::from_pkcs8_der` loads the on-disk key (`overlay.ed25519` /
`identity.ed25519`) by parsing the Ed25519 PKCS#8 structure and requiring the
Ed25519 OID. A non-Ed25519 key is rejected rather than interpreted as a seed.
`ring`'s in-memory `Ed25519KeyPair` cannot export its seed, so a host that kept
only the keypair must load the DER it wrote; this is recorded as a host-glue
constraint, not hidden.

**Lifetime and distribution.** The binding record has no independent expiry: it
is valid exactly as long as the device key is trusted. Rotating or revoking the
device key makes the record stop verifying, which is the intended coupling, not
a missing field. The record is small JSON and must travel over the host's
existing signed channel (transport offer / roster / signaling) so the dialer
learns the peer's `EndpointId` before connecting. It is deliberately **not**
published to pkarr/DNS: iroh's address lookup is cleared in `bind()`.

### 2.2 Relay configuration

`RelayPlan` is an explicit, ordered list of `RelayEndpoint`s. There is **no
public default**:

- `RelayPlan::empty()` → `RelayMode::Disabled`; a connect attempt with no relay
  and no address is an error.
- `https` only, except `http` on loopback for a local dev relay.
- `insecure_skip_verify` is accepted **only** for a loopback URL. A production
  relay with a self-signed cert is refused at parse time.
- `probe()` performs a bounded TCP connect to each URL concurrently. This is a
  reachability probe, not a relay health API: it answers "is something
  accepting on this port", not "will this relay carry QUIC".
- `healthy_order()` returns reachable relays first, preserving configured order
  within each group, then unreachable ones. `any_reachable()` is a cheap
  pre-flight.
- No relay is added implicitly, and iroh's address lookup (pkarr/DNS) is
  cleared: peer addressing comes from the host's existing signed channel.

**Order is a host preference, not an iroh failover order.** `RelayMap` is a
`BTreeMap`; iroh selects a home relay and retries internally. The PoC documents
this instead of pretending the list is an SLA or a deterministic failover
chain. If strict ordered failover is required, it has to live above iroh (e.g.
multiple endpoints or a rebuild on health loss).

### 2.3 Transport mapping

| Trait surface | iroh implementation |
| --- | --- |
| control + data | one iroh bidirectional stream, direct-path framing (`kind 0/1`, `[sid][offset][payload]`) |
| `flush` | no-op success (QUIC ordered/reliable); never finishes the stream |
| `drain_finish` | `SendStream::finish()` + `stopped()` with a 180 s wall |
| `max_payload` | 1 MiB, same ceiling as direct |
| `sid_answerer` | false for dialer, true for acceptor |
| datagrams | `Connection::send_datagram` / `read_datagram` / `max_datagram_size` |
| `channel_binding` | 32 bytes from `export_keying_material(label="filament/iroh/channel-binding/v1")` |
| `is_alive` / `is_dead` / `idle_ms` / `has_flowed` | connection state + atomics updated on send/receive |
| `force_close` | `Connection::close(0, "dropped")` |
| `rtt_ms` | selected path's RTT from `Connection::paths()` |
| `remote_addr` / `local_ip` | selected path, only when it is an IP path; relay path answers `None` |
| `open_stream` / `quic_connection` | default `None`: quinn-typed and structurally unavailable (see gaps) |

### 2.4 Failure behaviour

Two gates, both closed by default:

```text
cargo feature  iroh-transport   (off by default; no iroh in the graph)
runtime env    FILAMENT_IROH=1  (checked by filament_transport_iroh::enabled())
```

Failure paths are values, never hangs or silent relays:

| Condition | Result |
| --- | --- |
| feature off | implementation not compiled; `compiled_in() == false` |
| runtime flag unset | host does not attempt iroh |
| no relay configured | `connect` → `Err("no relay configured…")`; never public default |
| relay unreachable | `bind` → `Err` after `relay_online_timeout` (1 s in the test) |
| TLS/cert failure | `bind`/`connect` → `Err` |
| peer binding bad/mismatched | hello is refused; no application byte is read; accept loop continues with diagnostics |
| connection dies | `is_dead()` true, `is_alive()` false, calls return `Err` |

Nothing here falls back automatically, because "fall back" is the ladder's
decision and the PoC must not change it. The host calls `IrohNode::connect` only
after `enabled()` + a health probe + its own policy, and on `Err` keeps the
transport it already has.

---

## 3. Evidence (worker, 2026-10-21)

Remote Linux worker (`ci-worker-dovm`), rustc 1.99.1, no local cargo/rustc.
Commands ran through `worker-job.sh` with unique `iroh-*` job names and the
shared flock; no `cargo clean`.

```sh
# build
cargo test -p filament-transport-iroh --features iroh-transport,test-relay --no-run
# Finished `test` profile in 9.50s (warm shared target)

# tests
cargo test -p filament-transport-iroh --features iroh-transport,test-relay \
  -- --nocapture --test-threads=1

running 18 tests  ... 18 passed; 0 failed   (unit)
running 3 tests   ... 3 passed; 0 failed    (fallback)
running 3 tests   ... 3 passed; 0 failed    (identity_binding)
running 1 test    ... 1 passed; 0 failed    (relay_echo)
```

The acceptance test (`tests/relay_echo.rs`) asserts, with `relay_only: true`:

- two nodes bind to an in-process relay and complete the hello exchange;
- each side sees the other's **device** key and node id;
- the selected path is the relay on both ends (`selected_path_is_relay() ==
  Some(true)`), so the test is not secretly using loopback direct;
- a `send_frame` arrives as `Ev::Chunk` with the right sid/offset/bytes, and the
  echo comes back;
- a control JSON message arrives as `Ev::Control`;
- datagrams round-trip both ways (`max_datagram_size()` reported 1414 in the
  demo);
- both ends derive the same 32-byte channel binding;
- `sid_answerer()` differs between the two ends;
- `rtt_ms()` is available from the selected path.

`tests/fallback.rs` proves a dead loopback relay returns an error in about one
second and that an empty relay plan is an error, not `RelayMode::Default`.

`examples/relay_echo.rs` produced the transcript quoted in the crate README.

**CI wiring:** `.github/workflows/iroh-transport.yml` runs `scripts/iroh-poc.sh
test` and `demo` on PRs touching this crate or the lock. It has **not** been
observed green in GitHub Actions in this environment; the evidence above is the
lease-worker run. Do not read the workflow file as a passing CI check.

**Lock impact:** the workspace `Cargo.lock` grows by ~154 packages (iroh, noq,
iroh-relay, ed25519-dalek 3 rc, etc.). Existing pins: rustls 0.23.45 → 0.23.46,
rustc-hash 2.1.2 → 2.1.3, data-encoding 2.11.0 → 2.11.1, cfg_aliases 0.2.1 →
0.2.2 (all semver-compatible requirements of iroh). Everything else is an
additional side-by-side version, not an upgrade.

This is a real cost of making the PoC a workspace member and should be reviewed
with the dependency-graph owner before merge.

---

## 4. What genuinely works vs design-only

### Works (observed on the worker)

- Ed25519 seed → device key → derived iroh key; deterministic; OpenSSL fixture
  matches.
- Ed25519 PKCS#8 DER loading, with non-Ed25519 rejection.
- Signed binding: create, JSON round-trip, verify, tamper rejection
  (device/node/created swaps), cross-device rejection.
- Relay plan validation (https, loopback-only http/insecure), reachability
  probing, reachable-first ordering.
- Two-node relay connection, iroh-authenticated device binding on both ends.
- Relay-only path selection verified, framed control/data both directions,
  datagram round-trip, channel binding equality, liveness/RTT reporting.
- Dead relay → bounded error; empty plan → explicit error; default-off gates.
- 25 tests green (18 unit + 7 integration), demo transcript.

### Design-only / not done

- Host wiring: no CLI loader, no config file, no settings surface.
- Peer-loop rung: no `ChannelReady` emission, no placement/upgrade policy, no
  route label or `filament ping` display.
- Authorization: the PoC verifies the *binding*, not the device certificate or
  roster membership. That check must remain in the existing identity path.
- L3 pump: datagrams and channel binding are implemented, but the L3 lane is
  not wired and was not touched.
- Relay operations: deployment, auth tokens, metrics, multi-relay ordered
  failover, health-driven endpoint rebuild.
- Reconnect/migration: no backoff loop, no warm-hold integration, no mobile.
- WAN evidence: only loopback + in-process relay. No NAT, loss, or cross-region
  relay measurement.
- Windows/macOS: not compiled or tested. The crate is platform-neutral Rust, but
  that is a claim, not evidence.
- Throughput/latency: no benchmark; the PoC measures correctness only.
- `open_stream` / mesh stream reuse: impossible without a trait change.

---

## 5. API gaps and sharp edges

1. **`open_stream` / `quic_connection` are quinn-typed.** iroh 1.4.1 is built on
   `noq`; a `quinn::Connection` cannot be produced. Consequently the mesh-reuse
   path and any caller that needs the concrete QUIC handle stay unavailable on
   this rung. Fixing it means a trait change (an opaque stream-handle enum or a
   second optional trait), which is deliberately out of scope here.
2. **`RelayMap` has no order.** It is a `BTreeMap`; a configured list cannot be
   a deterministic failover chain. iroh picks a home relay and retries. The
   host's order is preserved only for probing/diagnostics. Strict failover must
   be built above iroh.
3. **`Endpoint::online()` never gives up.** It waits until a home relay
   connects. The PoC wraps it in `relay_online_timeout` and drops the endpoint
   on expiry; a product path should also surface the last relay error
   (`home_relay_status()` watcher) instead of only "timed out".
4. **Health is TCP-only.** The probe is not a QUIC/WebSocket health check and
   cannot see auth denial. iroh's `home_relay_status()` exposes auth-denied and
   last-error states; the PoC does not yet plumb them.
5. **`ring` cannot export its Ed25519 seed.** The host must load the DER bytes
   of the device key. If a future device key lives only in an HSM or an opaque
   keypair, derivation needs an explicit signing interface instead; that is a
   design decision, not a code detail.
6. **Two QUIC stacks in one binary.** Enabling the feature links `noq` alongside
   `quinn`; expect compile time and binary-size cost even though the code paths
   are independent. This is why the feature is off by default and the CI job is
   separate.
7. **1.4.1 is brand new** (released the same day as this PoC) and requires rustc
   ≥ 1.91. Pinning `=1.4.1` is intentional; a bump needs the same tests
   re-run.
8. **Accept loop is unbounded on bad peers.** It drops invalid bindings and
   continues, which is correct for availability but needs rate limiting before
   exposure to the internet.
9. **Datagram sizing.** `max_datagram_size()` is path- and peer-dependent (1414
   observed); the L3 pump must keep respecting it rather than assuming a fixed
   MTU.
10. **Insecure relay TLS needs the test feature.** iroh gates
    `insecure_skip_verify()` on its `test-utils` feature. The PoC's
    `test-relay` feature enables it; a production build (feature
    `iroh-transport` only) compiles and refuses an insecure relay at bind time
    with an explicit error. `scripts/iroh-poc.sh test` builds both feature
    sets, so this asymmetry cannot rot silently.

---

## 6. Integration plan

Sequenced so each stage is independently reversible and none changes the
default route.

**Stage 0 — PoC (this branch).** Crate + tests + docs. No call sites.

**Stage 1 — host glue (CLI, small).** Load `overlay.ed25519` DER into
`DeviceIdentity`; add `[iroh]` settings (relay URLs, key mode, timeouts,
relay-only) with `FILAMENT_IROH=1` as the only way to turn it on. No new key
file, no default relay. This touches the host layer only.

**Stage 2 — peer-loop rung (coordinate with the lane owner).** Add a lowest
priority rung after the existing direct/WebRTC/relay ladder: only when
`enabled()`, the relay probe passes, and the existing ladder has failed or
exceeded its budget. On success emit `Ev::ChannelReady(pid, Arc<dyn
Transport>)` with route label `iroh-relay`; reuse `adopt_direct`'s re-offer
path. Never pre-empt a direct path and never disable WebRTC/TURN.

**Stage 3 — authorization.** Before delivering `ChannelReady`, check
`transport.peer_device_pub()` against the existing `DeviceCert`/roster in the
same place the current code resolves peer identity. A valid binding with an
untrusted device is still untrusted. No second certificate type.

**Stage 4 — L3 (coordinate with the L3 lane).** Enable the pump only when
`supports_datagrams()` and `channel_binding()` are both present; sign the
announce over the iroh exporter value; keep `max_datagram_size()` authoritative.
This is the first stage that touches `l3.rs`/`tun`, so it needs the L3 owner.

**Stage 5 — operations.** Relay inventory, auth tokens if the relay requires
them, health metrics (probe + `home_relay_status`), fallback counters, a kill
switch, and a documented "relay down = existing transports" runbook.

**Promotion criteria before any default-on discussion:**

- two-machine WAN run through a real relay (not loopback), with NAT on at least
  one side;
- relay kill/restart during an active transfer and during L2: existing
  transports continue, no hang, bounded error;
- throughput and RTT comparison against the current relay/TURN path;
- device revocation and key rotation invalidate the binding as expected;
- security review of HKDF domain separation and of the accept-loop exposure;
- Windows/macOS build + a smoke test;
- explicit product decision on cross-protocol key reuse (`Derived` vs `Direct`).

---

## 7. Files

New, all under the worktree:

```text
crates/filament-transport-iroh/Cargo.toml
crates/filament-transport-iroh/README.md
crates/filament-transport-iroh/src/lib.rs          gates + module wiring
crates/filament-transport-iroh/src/identity.rs     device -> node key, binding, DER
crates/filament-transport-iroh/src/relay.rs        explicit relays, probes
crates/filament-transport-iroh/src/transport.rs    IrohNode + IrohTransport
crates/filament-transport-iroh/tests/{relay_echo,identity_binding,fallback}.rs
crates/filament-transport-iroh/examples/relay_echo.rs
scripts/iroh-poc.sh
.github/workflows/iroh-transport.yml
docs/design-iroh-transport-poc.md
Cargo.lock                                         (+154 packages, 4 patch bumps)
```

No existing L3, peer-loop `mesh.rs`/`host.rs`, overlay, daemon or CLI source
file is modified.
