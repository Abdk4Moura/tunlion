//! Userspace L3 backend: an in-process smoltcp TCP/IP stack behind the `TunDevice`
//! seam, so a node with NO CAP_NET_ADMIN / no `/dev/net/tun` (e.g. a container) is
//! still a first-class overlay member. Same bare-IP contract as `KernelTun`:
//! `recv()` yields an OUTBOUND packet the local stack wants on the wire (l3.rs
//! routes it by dest IP to that peer's datagram transport); `send()` injects a peer
//! INBOUND packet into the local stack.
//!
//! One poll task owns the smoltcp `Interface` + `SocketSet` + a queue-backed phy AND
//! the TCP sockets. Everything crosses the task boundary over channels: the datagram
//! pumps (recv/send) over packet channels, and app I/O (dial/listen) over per-socket
//! byte pipes driven by commands. The app never touches smoltcp state directly.
//!
//! INVARIANT (address is identity): only THIS node's `/128` goes in `ip_addrs`, so
//! the stack terminates traffic ONLY for our own crypto-address. Outbound reach to
//! the rest of the overlay `/48` is a default ROUTE, never a widened `ip_addrs`.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify};

/// Per-socket byte buffers. 256 KiB each keeps a full BDP over a fast overlay.
const SOCK_BUF: usize = 256 * 1024;
/// App-facing pipe capacity per direction; bounds memory + gives TCP backpressure.
const PIPE_CAP: usize = 256 * 1024;

// ---------------------------------------------------------------- byte pipe -----

/// A bounded single-producer/single-consumer byte buffer bridging the async app
/// side and the synchronous poll loop. One direction per pipe. Wakers cross the
/// boundary: the poll loop wakes the app's read/write waker after it moves bytes,
/// and the app wakes the poll loop (via the shared `Notify`) after it moves bytes.
struct PipeState {
    buf: VecDeque<u8>,
    /// The producer end is done (writer shut down or socket closed): reader sees EOF.
    closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct Pipe {
    st: Mutex<PipeState>,
}

impl Pipe {
    fn new() -> Arc<Pipe> {
        Arc::new(Pipe {
            st: Mutex::new(PipeState {
                buf: VecDeque::new(),
                closed: false,
                read_waker: None,
                write_waker: None,
            }),
        })
    }
}

// ------------------------------------------------------------ app-side streams --

/// An accepted or dialed overlay TCP connection, as an async byte stream. Reads
/// drain the net->app pipe; writes fill the app->net pipe and kick the poll loop.
pub struct NetstackStream {
    /// app -> net (app writes here; the poll loop drains into the socket tx buffer).
    out: Arc<Pipe>,
    /// net -> app (the poll loop fills from the socket rx buffer; app reads here).
    inp: Arc<Pipe>,
    /// Kick the poll loop after app I/O so bytes move without waiting for a timer.
    wake: Arc<Notify>,
}

impl AsyncRead for NetstackStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut st = self.inp.st.lock().unwrap();
        if st.buf.is_empty() {
            if st.closed {
                return Poll::Ready(Ok(())); // clean EOF
            }
            st.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = st.buf.len().min(buf.remaining());
        for b in st.buf.drain(..n) {
            buf.put_slice(&[b]);
        }
        drop(st);
        self.wake.notify_one(); // freed capacity: let the poll loop push more
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NetstackStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let mut st = self.out.st.lock().unwrap();
        if st.closed {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
        }
        let room = PIPE_CAP.saturating_sub(st.buf.len());
        if room == 0 {
            st.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        st.buf.extend(&data[..n]);
        drop(st);
        self.wake.notify_one(); // kick the poll loop to drain into the socket
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut st = self.out.st.lock().unwrap();
        st.closed = true;
        drop(st);
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// The overlay source address of an accepted connection, which may be IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverlayAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl OverlayAddr {
    pub fn as_ipv6(&self) -> Ipv6Addr {
        match self {
            OverlayAddr::V4(a) => {
                // IPv4-mapped IPv6: ::ffff:a.b.c.d
                Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, u16::from(a.octets()[0]) << 8 | u16::from(a.octets()[1]), u16::from(a.octets()[2]) << 8 | u16::from(a.octets()[3]))
            }
            OverlayAddr::V6(a) => *a,
        }
    }
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            OverlayAddr::V4(a) => Some(*a),
            OverlayAddr::V6(_) => None,
        }
    }
}

/// A listening overlay port. `accept()` yields the next inbound connection and the
/// peer's overlay source address (load-bearing for the expose allowlist).
pub struct NetstackListener {
    port: u16,
    accept_rx: AsyncMutex<mpsc::UnboundedReceiver<(NetstackStream, OverlayAddr)>>,
}

impl NetstackListener {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub async fn accept(&self) -> Result<(NetstackStream, OverlayAddr)> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("netstack poll loop ended"))
    }
    /// Accept returning an Ipv6Addr for backward compatibility. IPv4 connections
    /// are returned as IPv4-mapped IPv6 addresses (::ffff:a.b.c.d).
    pub async fn accept_v6(&self) -> Result<(NetstackStream, Ipv6Addr)> {
        let (stream, addr) = self.accept().await?;
        Ok((stream, addr.as_ipv6()))
    }
}

// -------------------------------------------------------------- poll-loop cmds --

enum Cmd {
    Dial {
        dst: Ipv6Addr,
        port: u16,
        reply: oneshot::Sender<Result<NetstackStream>>,
    },
    DialV4 {
        dst: Ipv4Addr,
        port: u16,
        reply: oneshot::Sender<Result<NetstackStream>>,
    },
    Listen {
        port: u16,
        reply: oneshot::Sender<Result<NetstackListener>>,
    },
}

/// Poll-loop-owned per-socket record: the smoltcp handle, both pipe ends, a residual
/// for a partial `send_slice`, and (until Established) the dial reply / (for a
/// listener) the accept sink so backlog slots can be re-armed.
struct SockRec {
    handle: SocketHandle,
    out: Arc<Pipe>,
    inp: Arc<Pipe>,
    out_residual: Vec<u8>,
    established: bool,
    dial_reply: Option<oneshot::Sender<Result<NetstackStream>>>,
    /// For a listening socket: (port, sink to deliver the accepted stream). When it
    /// establishes we hand the stream to the sink and arm a fresh listen socket.
    listen: Option<(u16, mpsc::UnboundedSender<(NetstackStream, OverlayAddr)>)>,
    /// The overlay SOURCE of an ACCEPTED (delivered) connection; used to budget
    /// live sockets per peer so one paired peer can't exhaust the netstack.
    src: Option<OverlayAddr>,
}

/// Max live sockets total, and max ACCEPTED connections from one overlay source.
/// smoltcp has no SYN-cookies or large conn table, so budget both: a paired peer
/// (paired != fully trusted) opening a flood of connections to an exposed port must
/// not deny it to every other peer, nor exhaust process memory.
const MAX_SOCKETS: usize = 512;
const MAX_PER_SOURCE: usize = 64;
/// Listen sockets kept armed per exposed port, so simultaneous connections aren't
/// refused for want of a pending accept slot.
const LISTEN_BACKLOG: usize = 16;

// ----------------------------------------------------------------- phy device ---

/// A phy backed by two packet queues, owned by the poll task: rx = peer -> stack
/// (injected via `TunDevice::send`), tx = stack -> peers (drained to `TunDevice::recv`).
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
        // Default checksum caps = compute on Tx, verify on Rx. REAL checksums (not
        // ::ignored()) so a kernel-TUN peer accepts our packets and we drop corrupt
        // ones - required for cross-stack interop.
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

// -------------------------------------------------------------- the netstack ----

/// The userspace overlay endpoint. Cheap to hold; the stack lives in the poll task.
pub struct NetstackTun {
    name: String,
    addr: Ipv6Addr,
    addr_v4: Option<Ipv4Addr>,
    inject_tx: mpsc::UnboundedSender<Vec<u8>>,
    out_rx: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    wake: Arc<Notify>,
    _poll: tokio::task::JoinHandle<()>,
}

impl NetstackTun {
    /// Bring up the userspace stack for `cidr` (this node's overlay `<addr>/prefix`;
    /// crypto mode passes a `/128`). IPv6 only. Needs NO privilege.
    pub fn open(name: &str, cidr: &str, mtu: u32) -> Result<NetstackTun> {
        let (addr, prefix) = parse_v6_cidr(cidr)?;
        let mtu = mtu as usize;

        let mut dev = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = rand_seed()?;
        let mut iface = Interface::new(cfg, &mut dev, Instant::now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::from(addr), prefix));
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|_| anyhow!("netstack route table full"))?;

        let (inject_tx, inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        let wake = Arc::new(Notify::new());
        let wake_poll = wake.clone();

        let poll = tokio::spawn(async move {
            let mut sockets = SocketSet::new(Vec::new());
            let mut inject_rx = inject_rx;
            let mut cmd_rx = cmd_rx;
            let mut socks: Vec<SockRec> = Vec::new();
            let mut eph: u16 = 49152;
            poll_loop(
                &mut iface, &mut dev, &mut sockets, &mut socks, &mut eph, addr, None, wake_poll,
                &mut inject_rx, &mut cmd_rx, &out_tx,
            )
            .await;
        });

        Ok(NetstackTun {
            name: name.to_string(),
            addr,
            addr_v4: None,
            inject_tx,
            out_rx: AsyncMutex::new(out_rx),
            cmd_tx,
            wake,
            _poll: poll,
        })
    }

    /// This node's overlay address.
    #[allow(dead_code)]
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    /// This node's optional IPv4 overlay address.
    #[allow(dead_code)]
    pub fn addr_v4(&self) -> Option<Ipv4Addr> {
        self.addr_v4
    }

    /// Whether this netstack is configured with both IPv4 and IPv6 addresses.
    #[allow(dead_code)]
    pub fn is_dual_stack(&self) -> bool {
        self.addr_v4.is_some()
    }

    /// Bring up a dual-stack userspace stack with IPv6 (`cidr6`) and optional IPv4
    /// (`cidr4`). `cidr6` is required; `cidr4` may be `None` for IPv6-only.
    pub fn open_dual(name: &str, cidr6: &str, cidr4: Option<&str>, mtu: u32) -> Result<NetstackTun> {
        let (addr, prefix6) = parse_v6_cidr(cidr6)?;
        let mtu = mtu as usize;

        let mut dev = QueueDevice { rx: VecDeque::new(), tx: VecDeque::new(), mtu };
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = rand_seed()?;
        let mut iface = Interface::new(cfg, &mut dev, Instant::now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::from(addr), prefix6));
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|_| anyhow!("netstack route table full"))?;

        let addr_v4 = match cidr4 {
            Some(c4) => {
                let (v4addr, prefix4) = parse_v4_cidr(c4)?;
                iface.update_ip_addrs(|a| {
                    let _ = a.push(IpCidr::new(IpAddress::from(v4addr), prefix4));
                });
                iface
                    .routes_mut()
                    .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1))
                    .map_err(|_| anyhow!("netstack route table full"))?;
                Some(v4addr)
            }
            None => None,
        };

        let (inject_tx, inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
        let wake = Arc::new(Notify::new());
        let wake_poll = wake.clone();

        let poll = tokio::spawn(async move {
            let mut sockets = SocketSet::new(Vec::new());
            let mut inject_rx = inject_rx;
            let mut cmd_rx = cmd_rx;
            let mut socks: Vec<SockRec> = Vec::new();
            let mut eph: u16 = 49152;
            poll_loop(
                &mut iface, &mut dev, &mut sockets, &mut socks, &mut eph, addr, addr_v4, wake_poll,
                &mut inject_rx, &mut cmd_rx, &out_tx,
            )
            .await;
        });

        Ok(NetstackTun {
            name: name.to_string(),
            addr,
            addr_v4,
            inject_tx,
            out_rx: AsyncMutex::new(out_rx),
            cmd_tx,
            wake,
            _poll: poll,
        })
    }

    /// Dial `dst:port` over the overlay in userspace. Resolves once the TCP
    /// connection is Established.
    #[allow(dead_code)]
    pub async fn dial(&self, dst: Ipv6Addr, port: u16) -> Result<NetstackStream> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Dial { dst, port, reply })
            .map_err(|_| anyhow!("netstack poll loop ended"))?;
        self.wake.notify_one();
        rx.await.map_err(|_| anyhow!("netstack poll loop ended"))?
    }

    /// Listen on `port` on our overlay address. `accept()` yields connections.
    #[allow(dead_code)]
    pub async fn listen(&self, port: u16) -> Result<NetstackListener> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Listen { port, reply })
            .map_err(|_| anyhow!("netstack poll loop ended"))?;
        self.wake.notify_one();
        rx.await.map_err(|_| anyhow!("netstack poll loop ended"))?
    }

    /// Dial `dst:port` over IPv4 on the overlay. Resolves once the TCP
    /// connection is Established.
    #[allow(dead_code)]
    pub async fn dial_v4(&self, dst: Ipv4Addr, port: u16) -> Result<NetstackStream> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::DialV4 { dst, port, reply })
            .map_err(|_| anyhow!("netstack poll loop ended"))?;
        self.wake.notify_one();
        rx.await.map_err(|_| anyhow!("netstack poll loop ended"))?
    }

    /// Listen on `port` accepting both IPv4 and IPv6 connections. `accept()`
    /// yields connections. The overlay address family of the accepted connection
    /// is passed to the caller.
    #[allow(dead_code)]
    pub async fn listen_v4(&self, port: u16) -> Result<NetstackListener> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Listen { port, reply })
            .map_err(|_| anyhow!("netstack poll loop ended"))?;
        self.wake.notify_one();
        rx.await.map_err(|_| anyhow!("netstack poll loop ended"))?
    }
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut s = tcp::Socket::new(rx, tx);
    s.set_nagle_enabled(false); // interactive latency over the overlay
    s
}

fn mark_closed(pipe: &Arc<Pipe>) {
    let mut st = pipe.st.lock().unwrap();
    st.closed = true;
    if let Some(w) = st.read_waker.take() {
        w.wake();
    }
    if let Some(w) = st.write_waker.take() {
        w.wake();
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_loop(
    iface: &mut Interface,
    dev: &mut QueueDevice,
    sockets: &mut SocketSet<'static>,
    socks: &mut Vec<SockRec>,
    eph: &mut u16,
    my_addr: Ipv6Addr,
    my_addr_v4: Option<Ipv4Addr>,
    wake: Arc<Notify>,
    inject_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    out_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    loop {
        // 1. commands: create dial / listen sockets.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Cmd::Dial { dst, port, reply } => {
                    let mut sock = new_tcp_socket();
                    let local = next_eph(eph);
                    let r = sock.connect(iface.context(), (IpAddress::from(dst), port), local);
                    match r {
                        Ok(()) => {
                            let handle = sockets.add(sock);
                            let (out, inp, _stream) = wire_stream_placeholder();
                            // stream is handed out only once Established (below).
                            socks.push(SockRec {
                                handle,
                                out,
                                inp,
                                out_residual: Vec::new(),
                                established: false,
                                dial_reply: Some(reply),
                                listen: None,
                                src: None,
                            });
                        }
                        Err(e) => {
                            let _ = reply.send(Err(anyhow!("connect: {e}")));
                        }
                    }
                }
                Cmd::DialV4 { dst, port, reply } => {
                    let mut sock = new_tcp_socket();
                    let local = next_eph(eph);
                    let r = sock.connect(iface.context(), (IpAddress::from(dst), port), local);
                    match r {
                        Ok(()) => {
                            let handle = sockets.add(sock);
                            let (out, inp, _stream) = wire_stream_placeholder();
                            // stream is handed out only once Established (below).
                            socks.push(SockRec {
                                handle,
                                out,
                                inp,
                                out_residual: Vec::new(),
                                established: false,
                                dial_reply: Some(reply),
                                listen: None,
                                src: None,
                            });
                        }
                        Err(e) => {
                            let _ = reply.send(Err(anyhow!("connect: {e}")));
                        }
                    }
                }
                Cmd::Listen { port, reply } => {
                    // Arm a BACKLOG of listen sockets so simultaneous connections
                    // aren't RST'd for want of a pending socket (each accept re-arms
                    // one, keeping the backlog topped up).
                    let (tx, rx) = mpsc::unbounded_channel();
                    let mut err = None;
                    for _ in 0..LISTEN_BACKLOG {
                        if let Err(e) = arm_listen(sockets, socks, port, tx.clone()) {
                            err = Some(e);
                            break;
                        }
                    }
                    match err {
                        None => {
                            let _ = reply.send(Ok(NetstackListener { port, accept_rx: AsyncMutex::new(rx) }));
                        }
                        Some(e) => {
                            let _ = reply.send(Err(e));
                        }
                    }
                }
            }
        }

        // 2. inbound: injected peer packets into the phy rx queue.
        while let Ok(pkt) = inject_rx.try_recv() {
            dev.rx.push_back(pkt);
        }

        // 3. app -> net: drain each socket's out pipe into its tx buffer.
        for rec in socks.iter_mut() {
            let s = sockets.get_mut::<tcp::Socket>(rec.handle);
            while s.can_send() {
                if rec.out_residual.is_empty() {
                    let mut st = rec.out.st.lock().unwrap();
                    if st.buf.is_empty() {
                        drop(st);
                        break;
                    }
                    rec.out_residual = st.buf.drain(..).collect();
                    if let Some(w) = st.write_waker.take() {
                        w.wake(); // freed pipe capacity
                    }
                }
                match s.send_slice(&rec.out_residual) {
                    Ok(0) => break,
                    Ok(n) => {
                        rec.out_residual.drain(..n);
                    }
                    Err(_) => break,
                }
            }
            // App shut its write side and everything drained: half-close the socket.
            if rec.out_residual.is_empty() {
                let app_closed = rec.out.st.lock().unwrap().closed;
                if app_closed && s.may_send() {
                    s.close();
                }
            }
        }

        // 4. run the stack (packet-level panics on hostile input stay contained).
        let now = Instant::now();
        let polled = std::panic::AssertUnwindSafe(|| iface.poll(now, dev, sockets));
        if std::panic::catch_unwind(polled).is_err() {
            dev.rx.clear();
        }

        // 5. net -> app: pull rx bytes into each socket's in pipe (respect capacity);
        //    fire dial replies / listener accepts on establishment; reap dead sockets.
        // Per-source budget snapshot for this pass (accepted connections per peer).
        let mut per_src: std::collections::HashMap<OverlayAddr, usize> = std::collections::HashMap::new();
        for r in socks.iter() {
            if let Some(a) = r.src {
                *per_src.entry(a).or_default() += 1;
            }
        }
        let total_socks = socks.len();
        let mut new_listens: Vec<(u16, mpsc::UnboundedSender<(NetstackStream, OverlayAddr)>)> = Vec::new();
        let mut remove: Vec<usize> = Vec::new();
        for (idx, rec) in socks.iter_mut().enumerate() {
            let s = sockets.get_mut::<tcp::Socket>(rec.handle);

            // Establishment edge: hand out the stream (dial) or accept (listen).
            if !rec.established && s.state() == tcp::State::Established {
                rec.established = true;
                if let Some(reply) = rec.dial_reply.take() {
                    let stream = NetstackStream {
                        out: rec.out.clone(),
                        inp: rec.inp.clone(),
                        wake: wake.clone(),
                    };
                    let _ = reply.send(Ok(stream));
                }
                if let Some((port, sink)) = rec.listen.take() {
                    let src = match s.remote_endpoint() {
                        Some(IpEndpoint { addr: IpAddress::Ipv6(a), .. }) => OverlayAddr::V6(a),
                        Some(IpEndpoint { addr: IpAddress::Ipv4(a), .. }) => OverlayAddr::V4(a),
                        _ => OverlayAddr::V6(my_addr),
                    };
                    // Re-arm the port either way so it keeps serving other peers.
                    new_listens.push((port, sink.clone()));
                    let over = total_socks >= MAX_SOCKETS
                        || *per_src.get(&src).unwrap_or(&0) >= MAX_PER_SOURCE;
                    if over {
                        // Budget exceeded: RST this connection; the lifecycle check
                        // below reaps the socket. Other peers are unaffected.
                        s.abort();
                    } else {
                        *per_src.entry(src).or_default() += 1;
                        rec.src = Some(src); // count it against this source
                        let stream = NetstackStream {
                            out: rec.out.clone(),
                            inp: rec.inp.clone(),
                            wake: wake.clone(),
                        };
                        let _ = sink.send((stream, src));
                    }
                }
            }

            // Deliver received bytes.
            while s.can_recv() {
                let cap = {
                    let st = rec.inp.st.lock().unwrap();
                    PIPE_CAP.saturating_sub(st.buf.len())
                };
                if cap == 0 {
                    break; // app is slow: leave it in the rx buffer (TCP backpressure)
                }
                let got = s.recv(|data| {
                    let n = data.len().min(cap);
                    (n, data[..n].to_vec())
                });
                match got {
                    Ok(bytes) if !bytes.is_empty() => {
                        let mut st = rec.inp.st.lock().unwrap();
                        st.buf.extend(&bytes);
                        if let Some(w) = st.read_waker.take() {
                            w.wake();
                        }
                    }
                    _ => break,
                }
            }

            // Lifecycle: a closed/reset socket EOFs the app pipes and is reaped.
            if !s.is_active() && rec.established {
                mark_closed(&rec.inp);
                mark_closed(&rec.out);
                remove.push(idx);
            }
        }
        for (port, sink) in new_listens {
            let _ = arm_listen(sockets, socks, port, sink);
        }
        for idx in remove.into_iter().rev() {
            let rec = socks.remove(idx);
            sockets.remove(rec.handle);
        }

        // 6. outbound: hand emitted packets to recv(). A closed out_tx = dropped tun.
        while let Some(pkt) = dev.tx.pop_front() {
            if out_tx.send(pkt).is_err() {
                return;
            }
        }

        // 7. sleep until smoltcp's next deadline or a wake (new inject / cmd / app I/O).
        match iface.poll_at(now, sockets) {
            Some(at) if at > now => {
                let d = Duration::from_millis((at - now).total_millis());
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(d) => {}
                }
            }
            Some(_) => tokio::task::yield_now().await,
            None => {
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                }
            }
        }
    }
}

/// Add a fresh listening socket for `port` with its accept sink.
fn arm_listen(
    sockets: &mut SocketSet<'static>,
    socks: &mut Vec<SockRec>,
    port: u16,
    sink: mpsc::UnboundedSender<(NetstackStream, OverlayAddr)>,
) -> Result<()> {
    let mut sock = new_tcp_socket();
    sock.listen(IpListenEndpoint::from(port)).map_err(|e| anyhow!("listen: {e}"))?;
    let handle = sockets.add(sock);
    let (out, inp, _placeholder) = wire_stream_placeholder();
    socks.push(SockRec {
        handle,
        out,
        inp,
        out_residual: Vec::new(),
        established: false,
        dial_reply: None,
        listen: Some((port, sink)),
        src: None,
    });
    Ok(())
}

/// Pipes for a not-yet-established socket; the app-facing stream is built later
/// (on the establishment edge) so we only need the two pipe ends here.
fn wire_stream_placeholder() -> (Arc<Pipe>, Arc<Pipe>, ()) {
    (Pipe::new(), Pipe::new(), ())
}

fn next_eph(eph: &mut u16) -> u16 {
    let p = *eph;
    *eph = if *eph >= 65535 { 49152 } else { *eph + 1 };
    p
}

/// Parse `addr/prefix` as IPv6 (the overlay is IPv6-only). Bare address = `/128`.
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

/// Parse an IPv4 CIDR string (e.g., "192.168.1.1/24") into (Ipv4Addr, prefix).
/// Defaults to /32 if no prefix specified.
fn parse_v4_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (a, p) = match cidr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().map_err(|_| anyhow!("bad prefix in '{cidr}'"))?),
        None => (cidr, 32),
    };
    let addr: std::net::Ipv4Addr = a
        .parse()
        .map_err(|_| anyhow!("netstack overlay address must be IPv4, got '{a}'"))?;
    if p > 32 {
        bail!("prefix /{p} out of range for IPv4");
    }
    Ok((addr, p))
}

/// A CSPRNG seed for smoltcp (ISN/ephemeral-port randomization) from ring.
fn rand_seed() -> Result<u64> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut b = [0u8; 8];
    rng.fill(&mut b).map_err(|_| anyhow!("csprng seed"))?;
    Ok(u64::from_le_bytes(b))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::TunDevice;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv4Packet, Ipv4Repr,
        Ipv6Packet, Ipv6Repr,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        assert!(n >= 40);
        let rp = Ipv6Packet::new_checked(&rbuf[..n]).unwrap();
        assert_eq!(rp.src_addr(), me);
        assert_eq!(rp.dst_addr(), peer);
        assert_eq!(rbuf[40], 0x81, "expected an ICMPv6 echo reply");
    }

    #[tokio::test]
    async fn netstack_survives_malformed_injection() {
        let me: Ipv6Addr = "fdf1:1af7:c30d:1a1::2".parse().unwrap();
        let peer: Ipv6Addr = "fdf1:1af7:c30d:1a1::99".parse().unwrap();
        let tun = NetstackTun::open("filament0", &format!("{me}/128"), 1280).unwrap();
        for i in 0..200u32 {
            let len = (i as usize * 7) % 2000;
            let mut junk = vec![0u8; len];
            for (j, b) in junk.iter_mut().enumerate() {
                *b = ((i.wrapping_mul(2654435761)) ^ (j as u32).wrapping_mul(40503)) as u8;
            }
            if !junk.is_empty() && i % 2 == 0 {
                junk[0] = 0x60;
            }
            tun.send(&junk).await.unwrap();
        }
        tun.send(&build_echo_request(peer, me)).await.unwrap();
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(3), tun.recv(&mut rbuf))
            .await
            .expect("stack wedged after malformed flood")
            .unwrap();
        assert!(n >= 40 && rbuf[40] == 0x81);
    }

    /// Cross-wire two userspace stacks (A.recv -> B.send and vice versa) so they
    /// exchange real IP packets, then dial A -> B and round-trip bytes both ways.
    /// This is the M3 gate: the netstack can dial, accept, and move a byte stream.
    #[tokio::test]
    async fn two_netstacks_dial_listen_roundtrip() {
        let a_addr: Ipv6Addr = "fdf1:1af7:c30d:aaa::1".parse().unwrap();
        let b_addr: Ipv6Addr = "fdf1:1af7:c30d:bbb::1".parse().unwrap();
        let a = Arc::new(NetstackTun::open("filament0", &format!("{a_addr}/128"), 1280).unwrap());
        let b = Arc::new(NetstackTun::open("filament0", &format!("{b_addr}/128"), 1280).unwrap());

        // Wire the "datagram plane": each node's outbound packets become the other's
        // inbound. (In production l3.rs routes by dest IP to the peer's transport.)
        let (a1, b1) = (a.clone(), b.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok(n) = a1.recv(&mut buf).await {
                if n == 0 || b1.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        let (a2, b2) = (a.clone(), b.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok(n) = b2.recv(&mut buf).await {
                if n == 0 || a2.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        let listener = b.listen(9000).await.unwrap();

        // Server: echo one message back, uppercased, then shut down.
        let server = tokio::spawn(async move {
            let (mut s, src) = listener.accept_v6().await.unwrap();
            assert_eq!(src, a_addr, "listener must see the dialer's overlay src");
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            let up = buf[..n].to_ascii_uppercase();
            s.write_all(&up).await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut client = tokio::time::timeout(Duration::from_secs(3), a.dial(b_addr, 9000))
            .await
            .expect("dial timed out")
            .expect("dial failed");
        client.write_all(b"hello-overlay").await.unwrap();
        client.flush().await.unwrap();

        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
                .await
                .expect("read timed out")
                .unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.len() >= b"HELLO-OVERLAY".len() {
                break;
            }
        }
        assert_eq!(&got, b"HELLO-OVERLAY", "byte stream must round-trip through both stacks");
        server.await.unwrap();
    }

    /// Cross-wire two stacks' datagram planes, optionally DROPPING every `drop_nth`
    /// packet each direction to model a lossy overlay. `drop_nth == 0` = lossless.
    fn cross_wire(a: Arc<NetstackTun>, b: Arc<NetstackTun>, drop_nth: u64) {
        fn pump(from: Arc<NetstackTun>, to: Arc<NetstackTun>, drop_nth: u64) {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                let mut n = 0u64;
                while let Ok(sz) = from.recv(&mut buf).await {
                    if sz == 0 {
                        break;
                    }
                    n += 1;
                    if drop_nth != 0 && n % drop_nth == 0 {
                        continue; // drop this packet; TCP must retransmit
                    }
                    if to.send(&buf[..sz]).await.is_err() {
                        break;
                    }
                }
            });
        }
        pump(a.clone(), b.clone(), drop_nth);
        pump(b, a, drop_nth);
    }

    /// M7 resilience: a real byte stream survives a LOSSY overlay. smoltcp TCP over
    /// unreliable QUIC datagrams must retransmit and deliver every byte intact - the
    /// core assumption behind running TCP on the datagram plane.
    #[tokio::test]
    async fn netstack_transfers_intact_through_packet_loss() {
        let a_addr: Ipv6Addr = "fdf1:1af7:c30d:a11::1".parse().unwrap();
        let b_addr: Ipv6Addr = "fdf1:1af7:c30d:b22::1".parse().unwrap();
        let a = Arc::new(NetstackTun::open("filament0", &format!("{a_addr}/128"), 1280).unwrap());
        let b = Arc::new(NetstackTun::open("filament0", &format!("{b_addr}/128"), 1280).unwrap());
        cross_wire(a.clone(), b.clone(), 7); // drop ~1 in 7 packets each way

        let listener = b.listen(9100).await.unwrap();
        let payload: Vec<u8> = (0..12000u32).map(|i| (i.wrapping_mul(2654435761) >> 16) as u8).collect();
        let expect = payload.clone();
        let server = tokio::spawn(async move {
            let (mut s, _src) = listener.accept_v6().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 2048];
            while got.len() < expect.len() {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, expect, "payload corrupted or truncated under loss");
            let _ = s.write_all(b"OK").await;
            let _ = s.flush().await;
            let _ = s.shutdown().await;
        });

        let mut client = tokio::time::timeout(Duration::from_secs(25), a.dial(b_addr, 9100))
            .await
            .expect("dial timed out under loss")
            .expect("dial failed");
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        let mut ack = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(25), client.read_exact(&mut ack))
            .await
            .expect("ack timed out under loss")
            .unwrap();
        assert_eq!(&ack, b"OK");
        server.await.unwrap();
    }

    /// M7 concurrency/soak: many simultaneous connections to one netstack listener
    /// all complete (accept loop + per-socket servicing don't wedge or cross wires),
    /// and the sockets are reaped afterwards (no leak).
    #[tokio::test]
    async fn netstack_serves_many_concurrent_connections() {
        let a_addr: Ipv6Addr = "fdf1:1af7:c30d:c33::1".parse().unwrap();
        let b_addr: Ipv6Addr = "fdf1:1af7:c30d:d44::1".parse().unwrap();
        let a = Arc::new(NetstackTun::open("filament0", &format!("{a_addr}/128"), 1280).unwrap());
        let b = Arc::new(NetstackTun::open("filament0", &format!("{b_addr}/128"), 1280).unwrap());
        cross_wire(a.clone(), b.clone(), 0); // lossless

        const N: u32 = 12;
        let listener = std::sync::Arc::new(b.listen(9200).await.unwrap());
        let srv = {
            let listener = listener.clone();
            tokio::spawn(async move {
                for _ in 0..N {
                    let (mut s, _src) = match listener.accept_v6().await {
                        Ok(x) => x,
                        Err(_) => break,
                    };
                    tokio::spawn(async move {
                        let mut buf = [0u8; 64];
                        let n = s.read(&mut buf).await.unwrap_or(0);
                        let up = buf[..n].to_ascii_uppercase();
                        let _ = s.write_all(&up).await;
                        let _ = s.flush().await;
                        let _ = s.shutdown().await;
                    });
                }
            })
        };

        let mut clients = Vec::new();
        for i in 0..N {
            let a = a.clone();
            clients.push(tokio::spawn(async move {
                let mut c = a.dial(b_addr, 9200).await.expect("dial failed");
                let msg = format!("client-{i}");
                c.write_all(msg.as_bytes()).await.unwrap();
                c.flush().await.unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 64];
                while got.len() < msg.len() {
                    let n = c.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                assert_eq!(got, msg.to_ascii_uppercase().into_bytes(), "connection {i} crossed wires or truncated");
            }));
        }
        for (i, h) in clients.into_iter().enumerate() {
            tokio::time::timeout(Duration::from_secs(15), h)
                .await
                .unwrap_or_else(|_| panic!("client {i} timed out"))
                .unwrap();
        }
        srv.abort();
    }

    #[test]
    fn parses_ipv4_cidr() {
        let (addr, prefix) = parse_v4_cidr("192.168.1.1/24").unwrap();
        assert_eq!(addr, std::net::Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefix, 24);

        let (addr, prefix) = parse_v4_cidr("10.0.0.1").unwrap();
        assert_eq!(addr, std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(prefix, 32);

        let (addr, prefix) = parse_v4_cidr("0.0.0.0/0").unwrap();
        assert_eq!(addr, std::net::Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix, 0);

        assert!(parse_v4_cidr("192.168.1.1/33").is_err());
        assert!(parse_v4_cidr("192.168.1.1/128").is_err());
        assert!(parse_v4_cidr("not-an-ip/24").is_err());
        assert!(parse_v4_cidr("192.168.1.1/not-a-number").is_err());
    }

    #[tokio::test]
    async fn netstack_opens_with_ipv4() {
        let me6: Ipv6Addr = "fdf1:1af7:c30d:d01::1".parse().unwrap();
        let me4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let peer: Ipv6Addr = "fdf1:1af7:c30d:d01::99".parse().unwrap();

        let tun = NetstackTun::open_dual(
            "filament0",
            &format!("{me6}/128"),
            Some("10.0.0.1/24"),
            1280,
        )
        .unwrap();

        assert!(tun.is_dual_stack());
        assert_eq!(tun.addr_v4(), Some(me4));
        assert_eq!(tun.addr(), me6);

        // IPv6 still works
        tun.send(&build_echo_request(peer, me6)).await.unwrap();
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), tun.recv(&mut rbuf))
            .await
            .expect("no echo reply within 2s")
            .unwrap();
        assert!(n >= 40);
        let rp = Ipv6Packet::new_checked(&rbuf[..n]).unwrap();
        assert_eq!(rp.src_addr(), me6);
        assert_eq!(rp.dst_addr(), peer);
        assert_eq!(rbuf[40], 0x81, "expected an ICMPv6 echo reply");
    }

    fn build_icmpv4_echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let echo = Icmpv4Repr::EchoRequest { ident: 0x5678, seq_no: 1, data: b"filament" };
        let ipr = Ipv4Repr {
            src_addr: src.into(),
            dst_addr: dst.into(),
            next_header: IpProtocol::Icmp,
            payload_len: echo.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ipr.buffer_len() + echo.buffer_len()];
        {
            let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
            ipr.emit(&mut p, &ChecksumCapabilities::default());
            let mut icmp = Icmpv4Packet::new_unchecked(p.payload_mut());
            echo.emit(&mut icmp, &ChecksumCapabilities::default());
        }
        buf
    }

    #[tokio::test]
    async fn netstack_ipv4_route_works() {
        let a6: Ipv6Addr = "fdf1:1af7:c30d:e41::1".parse().unwrap();
        let a4: Ipv4Addr = "10.0.42.1".parse().unwrap();
        let b6: Ipv6Addr = "fdf1:1af7:c30d:e42::1".parse().unwrap();
        let b4: Ipv4Addr = "10.0.42.2".parse().unwrap();
        let peer4: Ipv4Addr = "10.0.42.99".parse().unwrap();

        let a = Arc::new(
            NetstackTun::open_dual("filament0", &format!("{a6}/128"), Some(&format!("{a4}/24")), 1280)
                .unwrap(),
        );
        let b = Arc::new(
            NetstackTun::open_dual("filament0", &format!("{b6}/128"), Some(&format!("{b4}/24")), 1280)
                .unwrap(),
        );

        assert!(a.is_dual_stack());
        assert!(b.is_dual_stack());

        // B: inject ICMPv4 echo request → B replies with its own IPv4 address.
        b.send(&build_icmpv4_echo_request(peer4, b4)).await.unwrap();
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), b.recv(&mut rbuf))
            .await
            .expect("B: no IPv4 echo reply within 2s")
            .unwrap();
        assert!(n >= 28, "reply too short: {n}");
        let rp = Ipv4Packet::new_checked(&rbuf[..n]).unwrap();
        let b4_addr: smoltcp::wire::Ipv4Address = b4.into();
        let peer4_addr: smoltcp::wire::Ipv4Address = peer4.into();
        assert_eq!(rp.src_addr(), b4_addr);
        assert_eq!(rp.dst_addr(), peer4_addr);
        assert_eq!(rbuf[20], 0x00, "expected ICMPv4 echo reply (type 0)");

        // A: inject ICMPv4 echo request → A replies with its own IPv4 address.
        a.send(&build_icmpv4_echo_request(peer4, a4)).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), a.recv(&mut rbuf))
            .await
            .expect("A: no IPv4 echo reply within 2s")
            .unwrap();
        assert!(n >= 28, "reply too short: {n}");
        let rp = Ipv4Packet::new_checked(&rbuf[..n]).unwrap();
        let a4_addr: smoltcp::wire::Ipv4Address = a4.into();
        assert_eq!(rp.src_addr(), a4_addr);
        assert_eq!(rp.dst_addr(), peer4_addr);
        assert_eq!(rbuf[20], 0x00, "expected ICMPv4 echo reply (type 0)");

        // Verify IPv6 still works on both dual-stack nodes.
        let peer6: Ipv6Addr = "fdf1:1af7:c30d:e41::99".parse().unwrap();
        a.send(&build_echo_request(peer6, a6)).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), a.recv(&mut rbuf))
            .await
            .expect("A: no IPv6 echo reply within 2s")
            .unwrap();
        assert!(n >= 40);
        assert_eq!(rbuf[40], 0x81, "expected ICMPv6 echo reply");

        let peer6b: Ipv6Addr = "fdf1:1af7:c30d:e42::99".parse().unwrap();
        b.send(&build_echo_request(peer6b, b6)).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), b.recv(&mut rbuf))
            .await
            .expect("B: no IPv6 echo reply within 2s")
            .unwrap();
        assert!(n >= 40);
        assert_eq!(rbuf[40], 0x81, "expected ICMPv6 echo reply");
    }

    /// IPv4 dial/listen: two dual-stack netstacks cross-wire, B listens on IPv4,
    /// A dials B over IPv4, and the byte stream round-trips correctly. This
    /// validates Cmd::DialV4 and dual-stack listen acceptance.
    #[tokio::test]
    async fn netstack_ipv4_dial_listen() {
        let a6: Ipv6Addr = "fdf1:1af7:c30d:f01::1".parse().unwrap();
        let a4: Ipv4Addr = "10.0.50.1".parse().unwrap();
        let b6: Ipv6Addr = "fdf1:1af7:c30d:f02::1".parse().unwrap();
        let b4: Ipv4Addr = "10.0.50.2".parse().unwrap();

        let a = Arc::new(
            NetstackTun::open_dual("filament0", &format!("{a6}/128"), Some(&format!("{a4}/24")), 1280)
                .unwrap(),
        );
        let b = Arc::new(
            NetstackTun::open_dual("filament0", &format!("{b6}/128"), Some(&format!("{b4}/24")), 1280)
                .unwrap(),
        );

        cross_wire(a.clone(), b.clone(), 0);

        // B listens; accept via listen_v4() (dual-stack).
        let listener = b.listen_v4(9300).await.unwrap();

        let server = tokio::spawn(async move {
            let (mut s, src) = listener.accept().await.unwrap();
            // Source must be the IPv4 overlay address of A.
            assert_eq!(src.as_ipv4(), Some(a4), "listener must see the dialer's IPv4 overlay src");
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            let up = buf[..n].to_ascii_uppercase();
            s.write_all(&up).await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        // A dials B over IPv4.
        let mut client = tokio::time::timeout(Duration::from_secs(5), a.dial_v4(b4, 9300))
            .await
            .expect("IPv4 dial timed out")
            .expect("IPv4 dial failed");
        client.write_all(b"hello-ipv4").await.unwrap();
        client.flush().await.unwrap();

        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
                .await
                .expect("read timed out")
                .unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.len() >= b"HELLO-IPV4".len() {
                break;
            }
        }
        assert_eq!(&got, b"HELLO-IPV4", "IPv4 byte stream must round-trip through both stacks");
        server.await.unwrap();
    }
}
