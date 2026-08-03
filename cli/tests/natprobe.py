#!/usr/bin/env python3
"""Small UDP mapping probe used by the Linux NAT topology gate.

The probe deliberately measures the source port observed by two independent
reflectors. Equal mapped ports mean endpoint-independent mapping for this test.
A destination-dependent port means symmetric (endpoint-dependent) mapping. A
multi-homed NAT may legitimately use a different public address per egress
interface, so the address is reported but is not the mapping discriminator.
"""

import argparse
import json
import socket
import sys
import time
import uuid


def server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(f"READY {args.port}", flush=True)
    while True:
        data, source = sock.recvfrom(4096)
        try:
            request = json.loads(data.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if request.get("op") != "probe":
            continue
        reply = {
            "label": args.label,
            "token": request.get("token"),
            "source": [source[0], source[1]],
        }
        sock.sendto(json.dumps(reply).encode(), source)


def probe(args):
    targets = {}
    for value in args.target:
        try:
            label, address = value.split("=", 1)
            host, port = address.rsplit(":", 1)
            targets[label] = (host, int(port))
        except ValueError as exc:
            raise SystemExit(f"invalid --target {value!r}: use label=host:port") from exc
    if len(targets) < 2:
        raise SystemExit("need at least two --target values")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    sock.settimeout(args.timeout)
    token = uuid.uuid4().hex
    request = json.dumps({"op": "probe", "token": token}).encode()
    for address in targets.values():
        sock.sendto(request, address)

    observations = {}
    deadline = time.monotonic() + args.timeout
    while len(observations) < len(targets) and time.monotonic() < deadline:
        try:
            payload, _ = sock.recvfrom(4096)
            reply = json.loads(payload.decode())
        except (socket.timeout, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if reply.get("token") == token and reply.get("label") in targets:
            observations[reply["label"]] = reply["source"]
    if len(observations) != len(targets):
        missing = sorted(set(targets) - set(observations))
        raise SystemExit(f"UNPROVEN: reflector responses missing: {','.join(missing)}")

    mappings = list(observations.values())
    mapping_type = "endpoint-independent" if len({m[1] for m in mappings}) == 1 else "endpoint-dependent"
    print(json.dumps({"mapping": mapping_type, "observations": observations}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server_parser = subparsers.add_parser("server")
    server_parser.add_argument("--bind", default="0.0.0.0")
    server_parser.add_argument("--port", type=int, required=True)
    server_parser.add_argument("--label", required=True)
    server_parser.set_defaults(func=server)

    probe_parser = subparsers.add_parser("probe")
    probe_parser.add_argument("--bind", default="0.0.0.0")
    probe_parser.add_argument("--port", type=int, required=True)
    probe_parser.add_argument("--target", action="append", required=True)
    probe_parser.add_argument("--timeout", type=float, default=5.0)
    probe_parser.set_defaults(func=probe)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
