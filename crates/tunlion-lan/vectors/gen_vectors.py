#!/usr/bin/env python3
"""Reference implementation of the tunlion local discovery wire format, in
Python with the standard library only, written from
docs/protocol/local-discovery.md and NOT from the Rust crate.

It writes vectors/v1.json. tests/conformance.rs checks the Rust core against
that file, so the two implementations agree byte for byte or CI fails. A third
implementation (Android, JS, anything) runs the same file.

    python3 -I crates/tunlion-lan/vectors/gen_vectors.py > crates/tunlion-lan/vectors/v1.json
"""
import hashlib
import hmac
import ipaddress
import json
import struct

MAGIC = b"TL"
VERSION = 1
EPOCH_SECS = 600
KIND = {"presence": 1, "pairing": 2, "query": 3}


def epoch(unix):
    return unix // EPOCH_SECS


def presence_tag(pk, ep, nonce, port):
    msg = b"tunlion-lan-v1/presence" + struct.pack(">I", ep) + nonce + struct.pack(">H", port)
    return hmac.new(pk, msg, hashlib.sha256).digest()[:16]


def beacon(kind, nonce, field, port):
    return MAGIC + bytes([VERSION, KIND[kind]]) + nonce + field + struct.pack(">H", port)


def pairing_label(pid):
    d = hashlib.sha256(b"tunlion-lan-v1/label" + pid).digest()
    return "%04d" % (struct.unpack(">I", d[:4])[0] % 10000)


def name(n):
    out = b""
    for label in n.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def rr(n, ty, cls, rdata):
    return name(n) + struct.pack(">HHIH", ty, cls, 120, len(rdata)) + rdata


SERVICE = "_tunlion._udp.local"


def mdns_announce(label, b, port, addrs):
    inst = "%s.%s" % (label, SERVICE)
    host = "%s.local" % label
    ans = rr(SERVICE, 12, 1, name(inst))
    ans += rr(inst, 33, 0x8001, struct.pack(">HHH", 0, 0, port) + name(host))
    txt = b""
    for e in [b"v=1", b"b=" + b.hex().encode()]:
        txt += bytes([len(e)]) + e
    ans += rr(inst, 16, 0x8001, txt)
    for a in addrs:
        ip = ipaddress.ip_address(a)
        ans += rr(host, 1 if ip.version == 4 else 28, 0x8001, ip.packed)
    return struct.pack(">HHHHHH", 0, 0x8400, 0, 3 + len(addrs), 0, 0) + ans


def mdns_query():
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + name(SERVICE) + struct.pack(">HH", 12, 1)


def sweep(net, prefix, own):
    if prefix < 22 or prefix > 32:
        return []
    n = ipaddress.ip_network("%s/%d" % (net, prefix), strict=False)
    if prefix >= 31:
        hosts = list(n)
    else:
        hosts = list(n.hosts())
    return [str(h) for h in hosts if str(h) not in own][:1024]


pk = bytes(range(32))
pk2 = bytes(range(32, 64))
nonce = bytes(range(0xA0, 0xAC))
unix = 1_800_000_000
port = 47821
ep = epoch(unix)
tag = presence_tag(pk, ep, nonce, port)
pres = beacon("presence", nonce, tag, port)
qry = beacon("query", bytes(range(0xB0, 0xBC)), bytes(16), 0)
pid = bytes(range(0x10, 0x20))
pair = beacon("pairing", bytes(range(0xC0, 0xCC)), pid, port)

vectors = {
    "spec": "docs/protocol/local-discovery.md",
    "version": 1,
    "presence": {
        "presence_key": pk.hex(),
        "unix": unix,
        "epoch": ep,
        "nonce": nonce.hex(),
        "port": port,
        "tag": tag.hex(),
        "beacon": pres.hex(),
    },
    "recognize": [
        {"beacon": pres.hex(), "keys": [pk2.hex(), pk.hex()], "unix": unix, "match": 1},
        {"beacon": pres.hex(), "keys": [pk.hex()], "unix": unix + EPOCH_SECS, "match": 0},
        {"beacon": pres.hex(), "keys": [pk.hex()], "unix": unix - EPOCH_SECS, "match": 0},
        {"beacon": pres.hex(), "keys": [pk.hex()], "unix": unix + 2 * EPOCH_SECS, "match": None},
        {"beacon": pres.hex(), "keys": [pk2.hex()], "unix": unix, "match": None},
    ],
    "query": {"nonce": bytes(range(0xB0, 0xBC)).hex(), "beacon": qry.hex()},
    "pairing": {
        "id": pid.hex(),
        "nonce": bytes(range(0xC0, 0xCC)).hex(),
        "port": port,
        "beacon": pair.hex(),
        "label": pairing_label(pid),
    },
    "malformed": [
        pres[:-1].hex(),
        (b"TX" + pres[2:]).hex(),
        (pres[:2] + b"\x02" + pres[3:]).hex(),
        (pres[:3] + b"\x09" + pres[4:]).hex(),
        (qry[:20] + b"\x01" + qry[21:]).hex(),
        (pres[:32] + b"\x00\x00").hex(),
    ],
    "mdns": {
        "label": "0011223344556677",
        "beacon": pres.hex(),
        "port": port,
        "addrs": ["192.168.1.20", "fd00::20"],
        "announce": mdns_announce("0011223344556677", pres, port, ["192.168.1.20", "fd00::20"]).hex(),
        "query": mdns_query().hex(),
    },
    "hello": {
        "json": {
            "type": "lan-hello",
            "v": 1,
            "pk": pk.hex(),
            "port": port,
            "addrs": [
                {"ip": "192.168.1.20", "class": "shared"},
                {"ip": "10.8.0.2", "class": "p2p"},
                {"ip": "fe80::1", "class": "shared"},
                {"ip": "127.0.0.1", "class": "loopback"},
                {"ip": "100.64.1.2", "class": "future-class"},
            ],
            "extra": "ignored",
        },
        "kept": ["192.168.1.20", "10.8.0.2"],
    },
    "sweep": [
        {"net": "10.8.0.1", "prefix": 30, "own": ["10.8.0.1"], "hosts": sweep("10.8.0.1", 30, ["10.8.0.1"])},
        {"net": "10.8.0.0", "prefix": 31, "own": ["10.8.0.0"], "hosts": sweep("10.8.0.0", 31, ["10.8.0.0"])},
        {"net": "10.8.0.2", "prefix": 32, "own": [], "hosts": sweep("10.8.0.2", 32, [])},
        {"net": "10.8.0.0", "prefix": 21, "own": [], "hosts": []},
        {"net": "10.8.0.9", "prefix": 22, "own": ["10.8.0.9"], "count": len(sweep("10.8.0.9", 22, ["10.8.0.9"])),
         "first": sweep("10.8.0.9", 22, ["10.8.0.9"])[0], "last": sweep("10.8.0.9", 22, ["10.8.0.9"])[-1]},
    ],
}
print(json.dumps(vectors, indent=2))
