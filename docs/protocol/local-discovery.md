# Local discovery protocol, version 1

Status: normative for tunlion clients (CLI/daemon, Android, browser, third
parties). Design rationale: `docs/design-local-discovery.md`. Reference core:
`crates/tunlion-lan` (sans-IO Rust). Second, independent implementation and
test vectors: `crates/tunlion-lan/vectors/gen_vectors.py` and `vectors/v1.json`.
A client conforms when it reproduces every vector in `v1.json`.

The words MUST, SHOULD and MAY are as in RFC 2119.

## 1. Purpose and trust

Two devices that already share a secret (a pair secret, or the fleet secret)
find each other's address with no server and connect directly. Discovery yields
**addresses only**. A discovered address is dialed with the existing
authenticated direct-QUIC handshake (`CONTRACT.md`, "Local discovery (lan)";
`crates/filament-transport/src/direct.rs`, module header), and that handshake,
never a beacon, decides who the peer is. A forged, replayed or misdirected
beacon costs one failed handshake and nothing else.

Nothing sent by this protocol to a network carries a device name, a public key,
a key fingerprint, an account id, or any value stable across epochs (section
3.4 lists the one bounded exception, the listener port).

## 2. Constants

| Name | Value |
|---|---|
| `MAGIC` | `0x54 0x4C` (ASCII `TL`) |
| `VERSION` | `0x01` |
| `EPOCH_SECS` | 600 |
| `DISCOVERY_PORT` | UDP 47820 |
| `DEFAULT_LISTEN_PORT` | UDP 47821 (QUIC listener; any port MAY be used and is then advertised) |
| `GROUP_V4` | `239.255.84.76`, TTL 1 |
| `GROUP_V6` | `ff02::7475:6e6c`, hop limit 1 |
| mDNS | `224.0.0.251` / `ff02::fb`, UDP 5353, service `_tunlion._udp.local` |

All integers are big-endian. `HMAC` is HMAC-SHA256 (RFC 2104). `||` is
concatenation. Labels are ASCII without a terminator.

## 3. Keys and the beacon

### 3.1 Presence key

Each device holds a random 32-byte presence key `P`, generated once from a
CSPRNG and stored privately. A device gives `P` only to peers over an already
authenticated link, in the hello (section 8). A device SHOULD rotate `P` when
it unpairs a device or leaves a fleet, and send the new `P` to its remaining
peers on their next link.

### 3.2 Epoch

`epoch = floor(unix_seconds / 600)` as a 32-bit unsigned integer. A receiver
MUST accept the epochs `e - 1`, `e` and `e + 1` around its own clock and
nothing else.

### 3.3 Datagram layout (34 bytes, every kind)

| Offset | Length | Field |
|---|---|---|
| 0 | 2 | `MAGIC` |
| 2 | 1 | `VERSION` |
| 3 | 1 | kind: `1` presence, `2` pairing, `3` query |
| 4 | 12 | nonce, fresh random bytes for every datagram sent |
| 16 | 16 | field (below) |
| 32 | 2 | port: the sender's QUIC listener port |

- **presence**: `field = HMAC(P, "tunlion-lan-v1/presence" || epoch_be32 || nonce || port_be16)[0..16]`.
- **pairing**: `field` = a random 16-byte pairing id, fixed while one code is
  on screen (section 7). No value derived from the code is sent.
- **query**: `field` = 16 zero bytes, `port` = 0. A query is the full 34 bytes
  so that the reply (a presence datagram) is never larger than the query.

A receiver MUST drop a datagram whose length is not 34, whose magic or version
differ, whose kind is unknown, a query with a non-zero field or port, and a
presence or pairing datagram with port 0. Unknown versions are dropped, not
answered.

### 3.4 Recognition

For a presence datagram received from source address `S`, the receiver
computes the tag with each presence key it holds, for each accepted epoch, and
compares in constant time. A match on the key of device D means "D's listener
is probably at `S.ip : port`". A device MUST ignore datagrams that match its own
key (multicast loopback).

Privacy. The tag and nonce are fresh per datagram, so two datagrams from one
device are unlinkable by content. The port is the default for almost every
device and so identifies nothing; a device that could not bind the default
port sends its own port in every beacon, which a same-link observer can use to
link that device's beacons together. Such an observer can also link beacons by
source MAC address. Rotation prevents a stranger from learning who you are or
linking you across networks; it does not hide that some tunlion device sits at
an address the observer can already see.

## 4. Sending

Per interface, by capability (section 6), a device in discovery mode:

- sends a presence datagram to `GROUP_V4` (and `GROUP_V6`) port 47820 on every
  shared interface, and to each IPv4 subnet broadcast address, every 30 s and
  at start;
- at start, and whenever it wants a peer it has no link to, also sends a query
  the same way;
- on point-to-point interfaces sends unicast queries to the sweep targets
  (section 6.2) and to neighbor-table hints, at most 200 per second in total,
  one sweep at start and then every 5 minutes;
- on receiving a query on an interface where discovery is on, replies with one
  presence datagram unicast to the query's source address and port, at most one
  reply per source address per 2 s and 50 replies per second in total.

## 5. DNS-SD carrier

The same presence datagram is also announced over mDNS (RFC 6762/6763), for
networks that pass mDNS but filter other multicast:

- An unsolicited response (flags `0x8400`) with, in the answer section:
  `PTR _tunlion._udp.local -> <label>._tunlion._udp.local`;
  `SRV <label>._tunlion._udp.local` priority 0 weight 0 port = listener port,
  target `<label>.local`;
  `TXT <label>._tunlion._udp.local` with exactly two strings `v=1` and
  `b=<68 lowercase hex chars of the presence datagram>`;
  one `A`/`AAAA` for `<label>.local` per advertised address.
  All TTLs are 120; SRV, TXT, A and AAAA set the cache-flush bit (class `0x8001`).
  Names are uncompressed.
- `<label>` is 16 lowercase hex characters from a CSPRNG, replaced every epoch.
  It MUST NOT be derived from the device name or any stable value.
- A query is a standard question `PTR _tunlion._udp.local IN`.
- A receiver extracts every `b=` TXT string under `*._tunlion._udp.local`,
  decodes the datagram and processes it as in section 3.4, taking the address
  from the packet source. Pairing datagrams MAY ride the same TXT.

Implementations MAY use the OS responder (Bonjour, Windows DNS-SD, Avahi,
Android `NsdManager`) instead of their own, as long as the records are the
ones above.

## 6. Interfaces

### 6.1 By capability, never by name

A client enumerates every interface that is up and has a unicast address, and
classes it from its flags only:

| Class | Flags | Mechanisms |
|---|---|---|
| `loopback` | loopback | none |
| `shared` | not point-to-point, and multicast or broadcast | group multicast, subnet broadcast, mDNS |
| `p2p` | point-to-point, or neither multicast nor broadcast | bounded unicast sweep, neighbor hints |

This covers Ethernet, Wi-Fi, USB tethering, Hyper-V/WSL switches, WireGuard,
ZeroTier, Tailscale, Nebula and tunlion's own overlay without listing any of
them. A client MUST NOT keep a list of interface names it treats specially.

Remembered addresses (section 9) are dialed on every class.

Discovery MUST be off on an interface the user opted out of, and on a network
the OS classes as public (Windows "Public" profile): nothing is sent there and
no query is answered from there. Received datagrams MAY still be read.

### 6.2 Sweep

For a `p2p` interface, the sweep covers, for each IPv4 prefix of the interface
and each IPv4 on-link route through it: every host of the prefix except the
network and broadcast addresses (both kept for /31 and /32) and the device's
own addresses. Prefixes shorter than /22 are not swept. A sweep covers at most
1024 hosts in total per interface. IPv6 prefixes are not swept; neighbor hints
and remembered addresses cover them.

## 7. Pairing nearby

While, and only while, a pairing code is on screen, the device also sends a
pairing datagram (kind 2) with its pairing id wherever it sends presence. Both
screens show `label = format("%04d", be32(SHA256("tunlion-lan-v1/label" || id)[0..4]) mod 10000)`
beside the code. The joiner, after the code is typed, connects to the
announcing device's listener and runs the same SPAKE2 code ceremony as over
signaling (`CONTRACT.md`, "Code ceremony frames"); a wrong target costs one
online guess, counted by the existing attempt limit.

## 8. Hello (over an authenticated link only)

When a link to a recognized peer is up (by any path, server or not), each side
sends one control message on it:

```json
{"type":"lan-hello","v":1,"pk":"<64 hex: P>","port":47821,
 "addrs":[{"ip":"192.168.1.20","class":"shared"},{"ip":"10.8.0.2","class":"p2p"}]}
```

`addrs` lists every unicast address on every up interface except loopback,
unspecified, multicast and IPv6 link-local (which cannot be dialed without a
scope id), each with its interface class. A receiver MUST ignore unknown
fields, and MUST skip entries whose class it does not know or whose address is
not advertisable as just defined. It MUST NOT accept a hello on a link whose
peer identity is not yet proven.

## 9. Remembered addresses

A receiver of a hello keeps, per peer: the peer's presence key, its listener
port, and up to 16 addresses, each with its class, `seen` (last hello that
listed it) and `ok` (last authenticated dial to it, 0 if never). New addresses
are added; addresses absent from a later hello are kept (they belong to another
network), and an address neither seen nor used for 30 days is forgotten. A
successful dial to an address sets its `ok`.

Recommended JSON (the CLI's `lan-peers.json` maps device name to this):

```json
{"v":1,"pk":"<64 hex>","port":47821,
 "addrs":[{"ip":"10.8.0.2","port":47821,"class":"p2p","seen":1800000000,"ok":1800000100}]}
```

Dialing: when the signaling server is unreachable, and in parallel at start, a
device dials the best 8 remembered addresses of each peer it wants (highest
`ok`, then highest `seen`) concurrently, plus any address discovered from a
beacon.

### 9.3 The circular-route guard

A device MUST NOT dial peer X at an address whose route is carried by its own
link to X (for example X's address on tunlion's overlay, which only exists
while that link is up). The test is route ownership, never the interface name:
an overlay address carried by a link to some other device is a real path (a
third device relays) and is dialed like any other.

## 10. The handshake on a discovered address

The listener is a QUIC endpoint (ALPN `filament-direct/1`, any certificate)
that authenticates each connection as in `direct.rs`: `km` = the 32-byte TLS
exporter value with label `filament-direct-auth` and empty context; `tkey` =
HKDF-SHA256 of the shared secret with info `filament-direct-transport-v1`; the
dialer opens a bidirectional stream and writes `HMAC(tkey, km || "|dialer")`;
the listener reads it and, holding several secrets, finds the one whose tag
matches (constant time), then writes `HMAC(tkey, km || "|acceptor")`; the dialer
verifies it. No identifier precedes the tag: trying every held secret costs one
HMAC each. A connection whose tag matches nothing is closed. After this the
stream carries the ordinary direct-transport framing; the observed-address
exchange of the signaled path is not run.

## 11. Off switch

`network.transports` (a list; `auto` is every transport) without `lan` turns
all of this off: no datagram is sent, no listener is bound, nothing is dialed
from remembered addresses.

## 12. Test vectors

`crates/tunlion-lan/vectors/v1.json` holds, with fixed keys and nonces: a
presence datagram and its tag, recognition across epochs (accepted at ±1,
refused at +2 and for a wrong key), a query, a pairing datagram and its label,
malformed datagrams that MUST be dropped, the mDNS announce and query bytes, a
hello with entries that MUST be skipped, and sweep host lists for /30, /31,
/32, /21 and /22.
