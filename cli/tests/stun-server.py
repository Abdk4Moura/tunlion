#!/usr/bin/env python3
"""Minimal unauthenticated STUN Binding responder for the NAT gate."""

import socket
import struct
import sys

COOKIE = 0x2112A442


def main():
    bind = sys.argv[1]
    port = int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    print(f"READY {bind}:{port}", flush=True)
    while True:
        data, source = sock.recvfrom(2048)
        if len(data) < 20 or data[:2] != b"\x00\x01":
            continue
        txid = data[8:20]
        ip = struct.unpack("!I", socket.inet_aton(source[0]))[0]
        value = b"\x00\x01" + struct.pack("!H", source[1] ^ (COOKIE >> 16)) + struct.pack("!I", ip ^ COOKIE)
        attr = struct.pack("!HH", 0x0020, len(value)) + value
        response = struct.pack("!HHI", 0x0101, len(attr), COOKIE) + txid + attr
        sock.sendto(response, source)


if __name__ == "__main__":
    main()
