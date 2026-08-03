#!/usr/bin/env python3
"""Can two same-host processes reach each other over the host's OWN non-loopback
address, via UDP?

That is exactly what direct-QUIC requires here. `local_ip_snapshot` FILTERS OUT
loopback (direct.rs:433), so two peers on one machine advertise only real
interface addresses and must hairpin: send to the host's own IP and have the
packet come back to a socket bound on that host.

The local-tcp path does NOT need this. It dials 127.0.0.1 explicitly, which is
why it works on macOS while direct-QUIC never completes there.

Prints one verdict line per address so a CI log answers the question directly.
"""
import socket, sys

TIMEOUT = 2.0


def local_ips():
    """The same set direct.rs gathers: real interfaces, loopback excluded."""
    ips = set()
    # The trick local_ips() uses: connect a UDP socket outward, read its
    # local address. No packets are sent.
    for target in (("8.8.8.8", 53), ("1.1.1.1", 53)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(target)
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                ips.add(ip)
            s.close()
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


def hairpin(addr, proto):
    """Bind on `addr`-reachable wildcard, then send to `addr` from a second
    socket. Success means a same-host peer can reach us at that address."""
    typ = socket.SOCK_DGRAM if proto == "UDP" else socket.SOCK_STREAM
    srv = socket.socket(socket.AF_INET, typ)
    try:
        srv.bind(("0.0.0.0", 0))
        port = srv.getsockname()[1]
        srv.settimeout(TIMEOUT)
        if proto == "TCP":
            srv.listen(1)
            cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli.settimeout(TIMEOUT)
            cli.connect((addr, port))
            conn, _ = srv.accept()
            conn.close(); cli.close()
            return True, f"connected to {addr}:{port}"
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(TIMEOUT)
        cli.sendto(b"filament-hairpin", (addr, port))
        data, src = srv.recvfrom(64)
        cli.close()
        return True, f"{len(data)}B arrived from {src[0]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        srv.close()


def main():
    ips = local_ips()
    print(f"non-loopback addresses gathered: {ips or '(none)'}")
    print("loopback is EXCLUDED from direct-QUIC candidates by direct.rs:433\n")

    ok, why = hairpin("127.0.0.1", "UDP")
    print(f"  UDP 127.0.0.1      {'OK  ' if ok else 'FAIL'}  {why}   <- not advertised")
    ok, why = hairpin("127.0.0.1", "TCP")
    print(f"  TCP 127.0.0.1      {'OK  ' if ok else 'FAIL'}  {why}   <- the local-tcp path")

    verdict = []
    for ip in ips:
        ok, why = hairpin(ip, "UDP")
        verdict.append(ok)
        print(f"  UDP {ip:<14} {'OK  ' if ok else 'FAIL'}  {why}   <- what direct-QUIC needs")

    print()
    if ips and not any(verdict):
        print("VERDICT: same-host UDP hairpin FAILS on every real interface.")
        print("         direct-QUIC cannot complete between two peers on this host,")
        print("         because loopback is filtered out of its candidate list.")
    elif ips:
        print("VERDICT: same-host UDP hairpin works here; this is NOT the blocker.")
    else:
        print("VERDICT: no non-loopback address found; inconclusive.")


if __name__ == "__main__":
    main()
