"""provider: filament — native L3 (serve_tun) carrier.

THE INTEGRATION TARGET, now REALIZED. Each node runs ``filament serve-tun``: a
TUN whose IP packets ride QUIC **datagrams** directly over a point-to-point link
to the peer's underlay endpoint. No signaling, no pairing, no userspace relay —
the two ends share a PSK out of band (the WireGuard model) and connect over the
lab's private underlay veth. This is the collapse the L2-forward approximation
was a placeholder for:

    node-a ns:  filament serve-tun --listen  <a.underlay>:PORT --tun-addr a/NN ...
    node-b ns:  filament serve-tun --connect <a.underlay>:PORT --tun-addr b/NN ...

Each ``serve-tun`` creates its own TUN (``labtun-<node>``) inside its netns and
adds the connected overlay route itself, so the provider has nothing else to
wire. Data path (a <-> b):

    TUN-a (node-a ns)  <->  QUIC datagrams over the underlay veth  <->  TUN-b

SAFETY: the locally-built ``cli/target/release/filament`` only; the processes run
INSIDE the lab netns (serve-tun needs no internet — it dials the peer's underlay
IP directly), so this never touches host networking, ``~/.config/filament``, or
the running ``up`` daemon. serve-tun reads no config at all (PSK on the CLI).
"""

from __future__ import annotations

import secrets

from labkit import netns
from labkit.context import LinkContext, FILAMENT_BIN
from providers import underlay

# serve-tun rendezvous port on the listener's (node-a's) underlay IP.
PORT = 51820


def up(ctx: LinkContext) -> None:
    if not FILAMENT_BIN.exists():
        raise RuntimeError(
            f"locally-built filament not found at {FILAMENT_BIN}; "
            f"build it: (cd cli && cargo build --release).")
    fb = str(FILAMENT_BIN)

    # The veth underlay between the two netns is serve-tun's transport (unlike the
    # old host-ns relay model, native serve-tun connects directly over it).
    underlay.establish(ctx)

    # PSK shared by both ends (stored so a re-`up` of the same lab is idempotent).
    psk = ctx.ledger.meta("fil_psk") or secrets.token_hex(16)
    ctx.ledger.set_meta("fil_psk", psk)

    a, b = ctx.a, ctx.b
    connect_to = f"{a.underlay_ip}:{PORT}"
    mtu = str(ctx.mtu)
    a_cidr = f"{a.overlay_ip}/{ctx.overlay_prefixlen}"
    b_cidr = f"{b.overlay_ip}/{ctx.overlay_prefixlen}"

    # The engine pre-creates a BARE TUN per node; serve-tun creates and addresses
    # its own (with IFF_NO_PI), so drop the engine's placeholder first to avoid a
    # name clash / flag mismatch. serve-tun's TUN is non-persistent: it vanishes
    # when the process is signalled on teardown.
    for ep in (a, b):
        netns.nsx(ep.ns, "ip", "link", "del", ctx.tun_iface(ep), check=False)

    # Listener in node-a's netns: bind 0.0.0.0:PORT (reachable at the underlay IP),
    # create TUN labtun-a, and add the connected overlay route (all inside the
    # netns, since the process is spawned via `ip netns exec`).
    a_pid = netns.spawn(
        [fb, "serve-tun", "--listen", f"0.0.0.0:{PORT}", "--tun-addr", a_cidr,
         "--psk", psk, "--dev", ctx.tun_iface(a), "--mtu", mtu],
        ns=a.ns, logfile=ctx.log("serve-tun-a"))
    ctx.ledger.add("pid", str(a_pid), role="serve-tun-a")

    # Connector in node-b's netns dials the listener over the underlay veth.
    # serve_tun_connect retries internally, so a small start-order gap is fine.
    b_pid = netns.spawn(
        [fb, "serve-tun", "--connect", connect_to, "--tun-addr", b_cidr,
         "--psk", psk, "--dev", ctx.tun_iface(b), "--mtu", mtu],
        ns=b.ns, logfile=ctx.log("serve-tun-b"))
    ctx.ledger.add("pid", str(b_pid), role="serve-tun-b")

    ctx.ledger.set_meta(
        "fil_note",
        "native serve_tun: TUN <-> QUIC datagrams, point-to-point over the "
        "underlay, PSK channel-binding auth (no signaling).")

    # Wait for a packet to actually cross before returning, so the next
    # `lab probe` sees a ready tunnel (the QUIC handshake wires in well under 1s).
    _wait_data_path(ctx, timeout=20.0)


def _wait_data_path(ctx: LinkContext, timeout: float) -> None:
    """Poll a ping across the overlay until it succeeds (or timeout). Best-effort:
    a failure here is not fatal (the probe reports it), but waiting makes bring-up
    deterministic for scripted/AI use."""
    import time

    deadline = time.time() + timeout
    target = ctx.b.overlay_ip
    while time.time() < deadline:
        ok, _ = netns.ping(ctx.a.ns, target, count=1, timeout_s=1)
        if ok:
            ctx.ledger.set_meta("fil_ready", True)
            return
        time.sleep(0.5)
    ctx.ledger.set_meta("fil_ready", False)


def down(ctx: LinkContext) -> None:
    # serve-tun processes are tracked as `pid` resources; the ledger sweep signals
    # them and each TUN is removed by the kernel when its fd closes. Nothing else.
    pass
