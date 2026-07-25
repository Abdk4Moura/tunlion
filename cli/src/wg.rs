//! Kernel-WireGuard L3 carrier for `serve-tun --wireguard` (ADR-0001 data plane).
//!
//! filament owns identity, authentication and reachability; WireGuard moves the
//! bytes. The flow: filament first establishes its normal authenticated
//! (channel-bound) connection, then each side generates a Curve25519 WireGuard
//! keypair and swaps {public key, WG listen-port} over that authenticated stream.
//! With the peer's key and endpoint in hand, a kernel WireGuard interface carries
//! the L3 traffic at kernel speed, instead of the userspace QUIC-datagram pump.
//!
//! Linux-only, and requires the `wireguard` kernel module plus the `wg` and `ip`
//! tools (same iproute2 dependency the kernel TUN backend already relies on).

use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Generate a WireGuard keypair, returned as (private_b64, public_b64), via `wg`.
pub fn gen_keypair() -> Result<(String, String)> {
    let out = Command::new("wg")
        .arg("genkey")
        .output()
        .context("run `wg genkey` (is wireguard-tools installed?)")?;
    if !out.status.success() {
        bail!("wg genkey failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let privkey = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("spawn `wg pubkey`")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("wg pubkey: no stdin"))?
        .write_all(format!("{privkey}\n").as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("wg pubkey failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((privkey, pubkey))
}

fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip").args(args).output().context("exec ip")?;
    if !out.status.success() {
        bail!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Create the WG interface with our private key and an ephemeral listen-port, and
/// return the port the kernel actually chose (advertised to the peer as our endpoint).
pub fn create_iface(dev: &str, privkey: &str) -> Result<u16> {
    let _ = ip(&["link", "del", dev]); // best-effort clear a stale interface
    ip(&["link", "add", dev, "type", "wireguard"]).with_context(|| format!("create wg dev {dev} (is the wireguard module loaded?)"))?;

    // `wg set <dev> private-key <path>`: feed the key on stdin via /dev/stdin so it
    // never lands on disk.
    let mut child = Command::new("wg")
        .args(["set", dev, "private-key", "/dev/stdin", "listen-port", "0"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn `wg set private-key`")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("wg set: no stdin"))?
        .write_all(format!("{privkey}\n").as_bytes())?;
    if !child.wait()?.success() {
        let _ = ip(&["link", "del", dev]);
        bail!("wg set private-key failed");
    }

    let out = Command::new("wg").args(["show", dev, "listen-port"]).output().context("wg show listen-port")?;
    if !out.status.success() {
        bail!("wg show listen-port failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    String::from_utf8_lossy(&out.stdout).trim().parse::<u16>().context("parse wg listen-port")
}

/// Attach the peer (key + endpoint + allowed-ips), address the interface, bring it up.
pub fn configure_peer(
    dev: &str,
    peer_pub: &str,
    allowed_ips: &str,
    endpoint: &str,
    addr_cidr: &str,
    mtu: u32,
) -> Result<()> {
    let out = Command::new("wg")
        .args([
            "set", dev, "peer", peer_pub, "allowed-ips", allowed_ips, "endpoint", endpoint,
            "persistent-keepalive", "25",
        ])
        .output()
        .context("wg set peer")?;
    if !out.status.success() {
        bail!("wg set peer: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    ip(&["addr", "add", addr_cidr, "dev", dev]).context("ip addr add on wg dev")?;
    ip(&["link", "set", "dev", dev, "mtu", &mtu.to_string()]).context("ip link set mtu")?;
    ip(&["link", "set", "dev", dev, "up"]).context("ip link set up")?;
    Ok(())
}

/// Remove the WG interface (best-effort; used on teardown).
pub fn teardown(dev: &str) {
    let _ = ip(&["link", "del", dev]);
}

/// The network CIDR that `addr_cidr` (IP/PREFIX) sits in, used as the peer's
/// allowed-ips for a point-to-point overlay (route the whole overlay to the peer).
pub fn network_cidr(addr_cidr: &str) -> Result<String> {
    let (ip_s, pfx_s) = addr_cidr.split_once('/').ok_or_else(|| anyhow!("tun-addr must be IP/PREFIX"))?;
    let pfx: u8 = pfx_s.parse().context("bad prefix in tun-addr")?;
    match ip_s.parse::<IpAddr>().context("bad ip in tun-addr")? {
        IpAddr::V4(v4) => {
            if pfx > 32 { bail!("v4 prefix > 32"); }
            let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx as u32) };
            Ok(format!("{}/{}", std::net::Ipv4Addr::from(u32::from(v4) & mask), pfx))
        }
        IpAddr::V6(v6) => {
            if pfx > 128 { bail!("v6 prefix > 128"); }
            let mask = if pfx == 0 { 0 } else { u128::MAX << (128 - pfx as u32) };
            Ok(format!("{}/{}", std::net::Ipv6Addr::from(u128::from(v6) & mask), pfx))
        }
    }
}

/// Format a WireGuard endpoint (bracket IPv6).
pub fn endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Swap {public key, WG listen-port} with the peer over the authenticated
/// connection. The initiator opens the bi stream; the responder accepts it. Both
/// sides write their line, finish, and read the peer's, so it is symmetric.
pub async fn exchange(
    conn: &quinn::Connection,
    our_pub: &str,
    our_port: u16,
    initiator: bool,
) -> Result<(String, u16)> {
    let (mut send, mut recv) = if initiator {
        conn.open_bi().await.context("open wg key-exchange stream")?
    } else {
        conn.accept_bi().await.context("accept wg key-exchange stream")?
    };
    send.write_all(format!("{our_pub} {our_port}\n").as_bytes()).await.context("send wg key-exchange")?;
    send.finish().context("finish wg key-exchange")?;

    let buf = recv.read_to_end(1024).await.context("read peer wg key-exchange")?;
    let line = String::from_utf8(buf).context("wg key-exchange not utf8")?;
    let line = line.trim();
    let (pk, pt) = line.split_once(' ').ok_or_else(|| anyhow!("malformed wg key-exchange: {line:?}"))?;
    let port: u16 = pt.trim().parse().context("parse peer wg listen-port")?;
    if pk.is_empty() {
        bail!("empty peer wg public key");
    }
    Ok((pk.to_string(), port))
}
