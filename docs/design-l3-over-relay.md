# L3 over relay, and L3 on by default

> Status: built (2026-08-25). Closes the two gaps that remained after
> `docs/design-fleet-automesh.md`: the overlay was opt-in, and a pair that could
> not go direct had no overlay path at all.

## 1. L3 is on by default

`tun-addr` defaulted to empty, which meant L3 off, so a fresh install had no IP
plane until someone ran `filament set tun-addr auto`. It now defaults to `auto`,
deriving the address from the overlay key.

The privilege question is the reason this was not already the default: a non-root
daemon needs `CAP_NET_ADMIN` to open the tunnel device. `filament init` now asks
for that one-time grant, because init is the moment there is a terminal to answer
a sudo prompt and the daemon has none. Declining is not fatal: the overlay falls
back to the userspace netstack, which needs no privilege but has no kernel route,
so native tools reach peers through the SOCKS proxy instead.

Consequence to be aware of when upgrading: an existing install that never opted
in will bring up `filament0` on its next daemon restart.

## 2. L3 over relay

`Transport::supports_datagrams()` was false for the relay/DataChannel transport,
so `L3::add_peer` returned early and no overlay route was ever installed over a
relay. Any pair that could not hole-punch was a hole in the mesh.

**Mechanism.** The DataChannel already distinguishes text frames (control JSON)
from binary frames (`[u32 sid][u64 offset][payload]`). L3 packets ride the binary
shape on a reserved sid, `net::L3_DATAGRAM_SID` (`u32::MAX`), which no L2 stream
can allocate. The wire format is unchanged.

Two queues bridge the impedance mismatch: `Transport::send_datagram` is
synchronous (quinn's is non-blocking) while the DataChannel write is async, so a
writer task drains an outbound queue, and the read loop pushes packets off the
reserved sid into an inbound queue. Both ends `try_send` and **drop** when full.
That is deliberate: IP packets are droppable, and blocking the tunnel to deliver
a stale packet would also stall the file transfer sharing the channel.

**Honest cost.** A DataChannel is reliable and ordered; IP wants neither. A lost
packet head-of-line blocks those behind it, and the tunnel competes with file
transfer on one channel. The ladder always prefers direct, and this path only
carries traffic for pairs that have no direct option.

**Compatibility, and why it is a gate not a default.** An older peer does not
know the reserved sid and discards those frames silently. Installing a route into
such a peer would produce something worse than no route: an address that looks
reachable and black-holes. So the announce carries an advisory `dg_relay` flag,
absent means NO, and a relayed route is installed only when the peer advertises
it. The flag sits outside the signature on purpose: it selects a transport and
authorizes nothing, and the worst a tamperer achieves is suppressing
L3-over-relay, a denial they could already cause by dropping the announce.

## The link binding on a transport with no exporter

Datagram carriage was necessary but not sufficient. `l3-announce` is itself
gated on `t.channel_binding()`, an RFC-5705 exporter that only direct-QUIC has,
so a relay link never announced and `add_peer` was never reached no matter what
`supports_datagrams()` returned. `webrtc-rs` 0.17 exposes no DTLS exporter (the
trait exists in `webrtc-util`, unimplemented on this path), so the binding could
not simply be plumbed through.

`Announce::verify` rests on three checks: address-is-key, channel binding,
possession. Only the middle one was missing, and it exists to stop a genuine
announce captured on one link being replayed onto another.

**Chosen: a per-link challenge.** Each side generates a random 32-byte nonce and
sends it as `l3-nonce`; the PEER signs its announce against the nonce it
received, and each side verifies against the nonce it sent. This drops straight
into the existing `bind_message(addr, seq, cb)` with the nonce as `cb`, so
`Announce::verify` is unchanged and the security argument keeps its shape. It
costs one extra message before the first announce.

Rejected: binding to the DTLS fingerprint pair. It is available today and needs
no round trip, but it is stable across reconnects between the same two peers, so
an announce captured on one link would still verify on a later one between the
same pair. The nonce is fresh per link, which is the property the exporter was
providing.

The nonce is generated ONCE per link, not per `ChannelReady`. That event fires
again on every re-establish and re-announce, and regenerating there invalidates
the nonce the peer is already signing against, which presents as a permanent
"signature or channel-binding mismatch". It is dropped with the link, so a new
link still gets a new one.

Because `fleet-hello` was gated on the same binding, this fix also lets fleet
auto-mesh admit a peer over a relay link.

## Verification

Item 1 is verified live: a fresh install with no `tun-addr` in its config brings
up `filament0` dual-stack with a working `<name>.mesh`.

Item 2 is verified working end to end. With the direct ladder refused, two
daemons hold a DataChannel link, exchange nonces, announce, install routes both
ways, and a `ping6` across the overlay returns 3/3 with 0% loss. The path under
test: host to `filament0`, A's L3 pump, a DataChannel datagram on the reserved
sid, B's smoltcp netstack, ICMP echo reply.

The hook that made this testable: `FILAMENT_TEST_NO_DIRECT=1` refuses the rung-1 direct
ladder even for a daemon, which is otherwise impossible to arrange since
`direct_ok_for` forces direct ON for every long-lived acceptor (an anti-glare
rule that is correct in production), so two daemons on one host always find each
other over loopback QUIC. Like every hook in `test_hooks`, it compiles only under
`--features test-hooks` and is stripped from released binaries.

Worth recording why the earlier signal was misleading: with `--relay` the two
daemons DID install L3 routes and DID pass a ping, which looks like success. It
was not. `--relay` constrains ICE candidate selection; it does not stop the
direct-QUIC ladder, and `filament reach` showed the link was `direct-quic` over
loopback. The route and the ping were real, and they were the OLD path.
