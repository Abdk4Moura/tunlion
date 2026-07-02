//! Userspace L3 backend: an in-process smoltcp TCP/IP stack behind the `TunDevice`
//! seam, so a node with NO CAP_NET_ADMIN / no `/dev/net/tun` (e.g. a container) is
//! still a first-class overlay member. Same bare-IP contract as `KernelTun`:
//! `recv()` yields an OUTBOUND packet the local stack wants on the wire (l3.rs
//! routes it by dest IP to that peer's datagram transport); `send()` injects a peer
//! INBOUND packet into the local stack.
//!
//! One poll task owns the smoltcp `Interface` + `SocketSet` + a queue-backed phy.
//! Input/output cross the task boundary over channels so the trait methods
//! (`recv`/`send`, called from l3.rs's datagram pumps) never touch smoltcp state
//! directly. Sockets (dial/listen) are added in a later milestone; this milestone
//! is the plumbing + IP-level processing (smoltcp answers ICMPv6 echo itself).
//!
//! INVARIANT (address is identity): only THIS node's `/128` goes in `ip_addrs`, so
//! the stack terminates traffic ONLY for our own crypto-address. Outbound reach to
//! the rest of the overlay `/48` is a default ROUTE, never a widened `ip_addrs`
//! (which would make us answer for other members' addresses).

use std::collections::VecDeque;
use std::net::Ipv6Addr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, Mutex, Notify};

/// A phy device backed by two packet queues, owned by the poll task:
///   rx = peer -> stack (injected by `TunDevice::send`, drained into smoltcp)
///   tx = stack -> peers (emitted by smoltcp, drained out to `TunDevice::recv`)
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Device for QueueDevice {
    type RxToken<'a> = QRx;
    type TxToken<'a> = QTx<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        // Default checksum caps = compute on Tx, verify on Rx. REAL IP/TCP/ICMP
        // checksums (not ::ignored()) so a kernel-TUN peer accepts our packets and
        // we drop corrupt ones - required for cross-stack interop.
        c
    }

    fn receive(&mut self, _t: Instant) -> Option<(QRx, QTx<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((QRx { buf }, QTx { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _t: Instant) -> Option<QTx<'_>> {
        Some(QTx { tx: &mut self.tx })
    }
}

struct QRx {
    buf: Vec<u8>,
}
impl phy::RxToken for QRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

struct QTx<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}
impl<'a> phy::TxToken for QTx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push_back(buf);
        r
    }
}

/// The userspace overlay endpoint. Cheap to hold; the stack lives in the poll task.
pub struct NetstackTun {
    name: String,
    /// send() -> poll loop (multi-producer: one per-peer reader in l3.rs calls send).
    inject_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// poll loop -> recv() (single consumer: l3.rs's one TUN reader loop).
    out_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Wake the poll loop when a packet is injected.
    wake: std::sync::Arc<Notify>,
    /// The poll task; kept so dropping the NetstackTun ends it. Supervised in a
    /// later milestone (restart/teardown on unexpected exit).
    _poll: tokio::task::JoinHandle<()>,
}

impl NetstackTun {
    /// Bring up the userspace stack for `cidr` (this node's overlay `<addr>/prefix`;
    /// crypto mode passes a `/128`). IPv6 only - the overlay is an IPv6 ULA and the
    /// smoltcp build has no IPv4. Needs NO privilege.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<NetstackTun> {
        let (addr, prefix) = parse_v6_cidr(cidr)?;
        let mtu = mtu as usize;

        let mut dev = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = rand_seed()?;
        let mut iface = Interface::new(cfg, &mut dev, Instant::now());
        // Only OUR /128 (address is identity). A push failure means the fixed addr
        // table is full, which cannot happen for a single address.
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::from(addr), prefix));
        });
        // Outbound reach to the whole overlay via a default route. Medium::Ip does no
        // neighbor resolution, so the gateway is notional (a link-local placeholder);
        // it only marks non-local destinations as routable out the device.
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|_| anyhow!("netstack route table full"))?;

        let (inject_tx, inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let wake = std::sync::Arc::new(Notify::new());
        let wake_poll = wake.clone();

        let poll = tokio::spawn(async move {
            let mut sockets = SocketSet::new(Vec::new());
            let mut inject_rx = inject_rx;
            poll_loop(&mut iface, &mut dev, &mut sockets, &mut inject_rx, &out_tx, &wake_poll).await;
        });

        Ok(NetstackTun {
            name: name.to_string(),
            inject_tx,
            out_rx: Mutex::new(out_rx),
            wake,
            _poll: poll,
        })
    }
}

/// The single poll driver: drain injected inbound packets, run smoltcp, drain the
/// outbound queue to `recv()` waiters, then sleep until the next timer or a wake.
async fn poll_loop(
    iface: &mut Interface,
    dev: &mut QueueDevice,
    sockets: &mut SocketSet<'static>,
    inject_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
    wake: &Notify,
) {
    loop {
        // 1. inbound: move injected peer packets into the phy rx queue.
        while let Ok(pkt) = inject_rx.try_recv() {
            dev.rx.push_back(pkt);
        }
        // 2. run the stack. A packet-level panic here (hostile paired-peer input
        // parsed in-process) must not kill the daemon/QUIC links, so isolate it.
        let now = Instant::now();
        let polled = std::panic::AssertUnwindSafe(|| iface.poll(now, dev, sockets));
        if std::panic::catch_unwind(polled).is_err() {
            // A corrupt packet tripped smoltcp. Drop whatever is queued and carry on
            // rather than tearing down the overlay.
            dev.rx.clear();
        }
        // 3. outbound: hand emitted packets to recv(). A closed out_tx means the
        // NetstackTun was dropped -> end the task.
        while let Some(pkt) = dev.tx.pop_front() {
            if out_tx.send(pkt).is_err() {
                return;
            }
        }
        // 4. sleep until smoltcp's next deadline or a fresh inject, whichever first.
        match iface.poll_at(now, sockets) {
            Some(at) if at > now => {
                let d = Duration::from_millis((at - now).total_millis());
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(d) => {}
                }
            }
            Some(_) => {
                // Immediate work pending: loop right away, but yield so a hot stack
                // never starves the runtime.
                tokio::task::yield_now().await;
            }
            None => {
                // Idle: nothing until the next inject. A long backstop sleep bounds
                // any missed-wake bug without busy-waiting.
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::tun::TunDevice for NetstackTun {
    fn name(&self) -> &str {
        &self.name
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let pkt = self
            .out_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("netstack poll loop ended"))?;
        let n = pkt.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt[..n]);
        Ok(n)
    }

    async fn send(&self, packet: &[u8]) -> Result<usize> {
        self.inject_tx
            .send(packet.to_vec())
            .map_err(|_| anyhow!("netstack poll loop ended"))?;
        self.wake.notify_one();
        Ok(packet.len())
    }
}

/// Parse `addr/prefix` as IPv6 (the overlay is IPv6-only). A bare address is a host
/// route (`/128`).
fn parse_v6_cidr(cidr: &str) -> Result<(Ipv6Addr, u8)> {
    let (a, p) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().map_err(|_| anyhow!("bad prefix in '{cidr}'"))?),
        None => (cidr, 128),
    };
    let addr: Ipv6Addr = a
        .parse()
        .map_err(|_| anyhow!("netstack overlay address must be IPv6, got '{a}'"))?;
    if p > 128 {
        bail!("prefix /{p} out of range for IPv6");
    }
    Ok((addr, p))
}

/// A CSPRNG seed for smoltcp (ISN/ephemeral-port randomization). Reuses the ring
/// CSPRNG already in the tree, so no new rand dependency.
fn rand_seed() -> Result<u64> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut b = [0u8; 8];
    rng.fill(&mut b).map_err(|_| anyhow!("csprng seed"))?;
    Ok(u64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::TunDevice;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Packet, Ipv6Repr};

    fn build_echo_request(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let echo = Icmpv6Repr::EchoRequest { ident: 0x1234, seq_no: 1, data: b"filament" };
        let ipr = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Icmpv6,
            payload_len: echo.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ipr.buffer_len() + echo.buffer_len()];
        {
            let mut p = Ipv6Packet::new_unchecked(&mut buf[..]);
            ipr.emit(&mut p);
            let mut icmp = Icmpv6Packet::new_unchecked(p.payload_mut());
            echo.emit(&src, &dst, &mut icmp, &ChecksumCapabilities::default());
        }
        buf
    }

    /// THE M2 gate: inject a well-formed ICMPv6 echo request addressed to our /128
    /// and get a valid echo reply back out the wire. Proves the whole phy <-> queue
    /// <-> poll <-> IP-processing <-> checksum path end to end, with no OS device.
    #[tokio::test]
    async fn netstack_answers_icmpv6_echo() {
        let me: Ipv6Addr = "fdf1:1af7:c30d:1a1::2".parse().unwrap();
        let peer: Ipv6Addr = "fdf1:1af7:c30d:1a1::99".parse().unwrap();
        let tun = NetstackTun::open("filament0", &format!("{me}/128"), 1280).unwrap();

        tun.send(&build_echo_request(peer, me)).await.unwrap();

        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), tun.recv(&mut rbuf))
            .await
            .expect("no echo reply within 2s")
            .unwrap();
        assert!(n >= 40, "reply too short to be an IPv6 packet: {n}");
        let rp = Ipv6Packet::new_checked(&rbuf[..n]).expect("reply is a valid IPv6 packet");
        assert_eq!(rp.src_addr(), me, "reply must come FROM our overlay address");
        assert_eq!(rp.dst_addr(), peer, "reply must go back TO the requester");
        // ICMPv6 type 0x81 = Echo Reply.
        assert_eq!(rbuf[40], 0x81, "expected an ICMPv6 echo reply");
    }

    /// Robustness: hostile paired-peer input is parsed IN-PROCESS, so malformed /
    /// truncated / oversized garbage must never panic or wedge the poll loop. After
    /// a flood of junk the stack must STILL answer a real echo (the loop survived).
    #[tokio::test]
    async fn netstack_survives_malformed_injection() {
        let me: Ipv6Addr = "fdf1:1af7:c30d:1a1::2".parse().unwrap();
        let peer: Ipv6Addr = "fdf1:1af7:c30d:1a1::99".parse().unwrap();
        let tun = NetstackTun::open("filament0", &format!("{me}/128"), 1280).unwrap();

        // Deterministic pseudo-garbage (no rng): truncated headers, oversized frames,
        // all-zero, all-ones, random-ish bytes.
        for i in 0..200u32 {
            let len = (i as usize * 7) % 2000;
            let mut junk = vec![0u8; len];
            for (j, b) in junk.iter_mut().enumerate() {
                *b = ((i.wrapping_mul(2654435761)) ^ (j as u32).wrapping_mul(40503)) as u8;
            }
            // Sometimes stamp a v6-ish version nibble so the IP parser goes deeper.
            if !junk.is_empty() {
                junk[0] = if i % 2 == 0 { 0x60 } else { junk[0] };
            }
            tun.send(&junk).await.unwrap();
        }

        // The loop is still alive and correct: a real echo still round-trips.
        tun.send(&build_echo_request(peer, me)).await.unwrap();
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(3), tun.recv(&mut rbuf))
            .await
            .expect("stack wedged: no echo reply after malformed flood")
            .unwrap();
        // The garbage produced no valid replies; the only well-formed reply is ours.
        assert!(n >= 40 && rbuf[40] == 0x81, "expected a clean echo reply after the flood");
    }
}
