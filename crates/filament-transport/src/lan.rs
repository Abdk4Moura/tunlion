//! Adapter for local discovery (`docs/protocol/local-discovery.md`).
//!
//! The protocol itself is `tunlion-lan`, a sans-IO core with no sockets and no
//! runtime. This module is the thin tokio adapter the CLI daemon and the
//! one-shot commands use: it enumerates interfaces by capability, owns the
//! discovery and mDNS sockets, runs the core's engine, binds the QUIC listener
//! that authenticates a connection against every held secret (spec section
//! 10), dials remembered and discovered addresses, and persists the
//! remembered-address records.
//!
//! What it reports goes back to the caller's loop as `Ev::Lan`, so the loop
//! decides what to do with a found peer or a new link, exactly as it does for
//! the signaled direct path.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use quinn::{Endpoint, RecvStream, SendStream};
use serde_json::{json, Value};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use tunlion_lan::engine::{Action, Channel, Engine, Known};
use tunlion_lan::iface::{self, Addr, Class, Flags, Interface};
use tunlion_lan::record::{self, Hello, HelloAddr, Record};
use tunlion_lan::wire;

use crate::direct;
use crate::net::Ev;

/// The shown and compared route word for a link made by local discovery.
pub const ROUTE_LAN: &str = "lan";
/// How long a dial of remembered/discovered addresses may take.
pub const DIAL_BUDGET: Duration = Duration::from_secs(4);
/// Delay between successive addresses of one dial.
pub const DIAL_STAGGER: Duration = Duration::from_millis(250);
/// While the server is reachable, signaling gets this long after start to
/// link a device before local discovery dials it (no duplicate links).
pub const ONLINE_GRACE: Duration = Duration::from_secs(8);

/// May local discovery dial now? Always when the server is unreachable;
/// beside a working server only after the grace, so the signaled link (when
/// it forms) is the one kept and the two never race into duplicates.
pub fn may_dial(offline: bool, since_start: Duration) -> bool {
    offline || since_start >= ONLINE_GRACE
}
const ACCEPT_AUTH_BUDGET: Duration = Duration::from_secs(10);
const MAX_INFLIGHT_ACCEPTS: usize = 32;

/// A secret a LAN link may authenticate with.
#[derive(Clone)]
pub struct LanKey {
    pub name: String,
    pub secret: String,
    /// The fleet rendezvous secret: the link proves fleet membership only.
    pub fleet: bool,
}

/// What the adapter reports to the loop.
pub enum LanEvent {
    /// An authenticated link is up. `pid` is a fresh local id for it. The
    /// transport is not reading yet: the loop records the link, then
    /// `announce`s it, so no frame from the peer can be handled before the
    /// link exists (a file-offer arriving first was dropped).
    Linked { pid: String, name: String, secret: String, fleet: bool, transport: direct::UnreadTransport, remote: SocketAddr, dialer: bool },
    /// A recognized peer announced itself at `addr` (its listener).
    Found { name: String, addr: SocketAddr },
    /// A pairing code is on screen on a device at `addr` (spec section 7).
    PairingNearby { addr: SocketAddr, label: String },
}

/// A pairing-carrier connection, handed to the one-shot pair command. The
/// adapter does not run the ceremony: the command owns the state, consent and
/// persistence.
pub struct PairLink {
    pub conn: quinn::Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub keying_material: [u8; 32],
    pub remote: SocketAddr,
    pub dialer: bool,
}

impl std::fmt::Debug for PairLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PairLink({}, dialer={})", self.remote, self.dialer)
    }
}

/// Cooperative stop for every task a `LanService` started. `shutdown` joins
/// them, so success, expiry and cancellation leave no listener or ticker behind.
#[derive(Clone)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Shutdown {
    fn new() -> Self {
        Self { flag: Arc::new(AtomicBool::new(false)), notify: Arc::new(Notify::new()) }
    }
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    pub fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
    async fn wait(&self) {
        while !self.is_stopped() {
            self.notify.notified().await;
        }
    }
}

impl std::fmt::Debug for LanEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        match self {
            LanEvent::Linked { pid, name, remote, dialer, fleet, .. } => write!(f, "Linked({pid}, {name}, {remote}, dialer={dialer}, fleet={fleet})"),
            LanEvent::Found { name, addr } => write!(f, "Found({name}, {addr})"),
            LanEvent::PairingNearby { addr, label } => write!(f, "PairingNearby({addr}, {label})"),
        }
    }
}

fn fresh_pid() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom_fill(&mut b);
    format!("lan-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

fn getrandom_fill(b: &mut [u8]) -> Result<()> {
    // ring is already in the graph through rustls/quinn.
    use rustls::crypto::ring::default_provider;
    default_provider().secure_random.fill(b).map_err(|_| anyhow!("no secure random"))
}

fn rng(b: &mut [u8]) {
    if getrandom_fill(b).is_err() {
        // Not reachable on supported platforms; a zero nonce is still only a
        // hint and cannot admit anything.
        b.fill(0);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

// ------------------------------------------------------------- the store --

/// `<config>/lan.key` (this device's presence key) and `<config>/lan-peers.json`
/// (device name -> remembered record).
#[derive(Clone)]
pub struct LanStore {
    dir: PathBuf,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

impl LanStore {
    pub fn new(dir: &Path) -> LanStore {
        LanStore { dir: dir.to_path_buf() }
    }

    pub fn presence_key(&self) -> Result<[u8; 32]> {
        let p = self.dir.join("lan.key");
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(b) = hex_decode(s.trim()) {
                if let Ok(k) = <[u8; 32]>::try_from(b.as_slice()) {
                    return Ok(k);
                }
            }
        }
        let mut k = [0u8; 32];
        getrandom_fill(&mut k)?;
        std::fs::create_dir_all(&self.dir).ok();
        write_private(&p, hex_encode(&k).as_bytes())?;
        Ok(k)
    }

    fn peers_path(&self) -> PathBuf {
        self.dir.join("lan-peers.json")
    }

    pub fn load(&self) -> BTreeMap<String, Record> {
        let Ok(s) = std::fs::read_to_string(self.peers_path()) else { return BTreeMap::new() };
        let Ok(v) = serde_json::from_str::<Value>(&s) else { return BTreeMap::new() };
        v.as_object()
            .map(|o| o.iter().filter_map(|(k, r)| Record::from_json(r).map(|r| (k.to_ascii_lowercase(), r))).collect())
            .unwrap_or_default()
    }

    fn save(&self, m: &BTreeMap<String, Record>) -> Result<()> {
        let v: serde_json::Map<String, Value> = m.iter().map(|(k, r)| (k.clone(), r.to_json())).collect();
        std::fs::create_dir_all(&self.dir).ok();
        write_private(&self.peers_path(), serde_json::to_string_pretty(&Value::Object(v))?.as_bytes())
    }

    fn update(&self, name: &str, f: impl FnOnce(&mut Record)) {
        let mut m = self.load();
        f(m.entry(name.to_ascii_lowercase()).or_default());
        if let Err(e) = self.save(&m) {
            crate::hooks::debug(&format!("lan: could not save remembered addresses: {e:#}"));
        }
    }

    pub fn learn(&self, name: &str, h: &Hello) {
        self.update(name, |r| r.learn(h, unix_now()));
    }

    pub fn mark_ok(&self, name: &str, addr: SocketAddr) {
        self.update(name, |r| r.mark_ok(canonical(addr), unix_now()));
    }

    /// Forget a device (unpair). Its record and key go with it.
    pub fn forget(&self, name: &str) {
        let mut m = self.load();
        if m.remove(&name.to_ascii_lowercase()).is_some() {
            let _ = self.save(&m);
        }
    }

    pub fn dial_order(&self, name: &str) -> Vec<SocketAddr> {
        self.load().get(&name.to_ascii_lowercase()).map(|r| r.dial_order()).unwrap_or_default()
    }

    pub fn known(&self) -> Vec<Known> {
        self.load()
            .into_iter()
            .filter_map(|(name, r)| r.presence_key.map(|presence_key| Known { name, presence_key }))
            .collect()
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd hex"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("{e}"))).collect()
}

// --------------------------------------------------------- interfaces --

/// User opt-out: interface names or CIDRs from `network.lan-skip`.
#[derive(Clone, Default)]
pub struct Skip(pub Vec<String>);

impl Skip {
    pub fn matches(&self, i: &Interface) -> bool {
        self.0.iter().any(|item| {
            let item = item.trim();
            if item.is_empty() {
                return false;
            }
            if item.eq_ignore_ascii_case(&i.name) {
                return true;
            }
            if let Some((net, len)) = item.split_once('/') {
                if let (Ok(net), Ok(len)) = (net.parse::<IpAddr>(), len.parse::<u8>()) {
                    return i.addrs.iter().any(|a| in_prefix(a.ip, net, len));
                }
            }
            false
        })
    }
}

fn in_prefix(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) if len <= 32 => {
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if len <= 128 => {
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

#[cfg(unix)]
fn prefix_of(mask: *const libc::sockaddr) -> u8 {
    if mask.is_null() {
        return 0;
    }
    unsafe {
        match (*mask).sa_family as i32 {
            libc::AF_INET => {
                let m = &*(mask as *const libc::sockaddr_in);
                u32::from_be(m.sin_addr.s_addr).count_ones() as u8
            }
            libc::AF_INET6 => {
                let m = &*(mask as *const libc::sockaddr_in6);
                m.sin6_addr.s6_addr.iter().map(|b| b.count_ones() as u8).sum()
            }
            _ => 0,
        }
    }
}

#[cfg(unix)]
fn ip_of(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        match (*sa).sa_family as i32 {
            libc::AF_INET => {
                let a = &*(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let a = &*(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// Every up interface with at least one unicast address, with its flags. No
/// interface is treated specially by name.
#[cfg(unix)]
pub fn interfaces() -> Vec<Interface> {
    let mut out: BTreeMap<String, Interface> = BTreeMap::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            let Some(ip) = ip_of(ifa.ifa_addr) else { continue };
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let fl = ifa.ifa_flags as i32;
            let flags = Flags {
                up: fl & libc::IFF_UP != 0 && fl & libc::IFF_RUNNING != 0,
                loopback: fl & libc::IFF_LOOPBACK != 0,
                multicast: fl & libc::IFF_MULTICAST != 0,
                broadcast: fl & libc::IFF_BROADCAST != 0,
                point_to_point: fl & libc::IFF_POINTOPOINT != 0,
            };
            let index = libc::if_nametoindex(ifa.ifa_name);
            let e = out.entry(name.clone()).or_insert_with(|| Interface {
                index,
                name,
                flags,
                addrs: Vec::new(),
                opted_out: false,
                public_network: false,
            });
            e.addrs.push(Addr { ip, prefix: prefix_of(ifa.ifa_netmask) });
        }
        libc::freeifaddrs(head);
    }
    out.into_values().filter(|i| i.flags.up && !i.addrs.is_empty()).collect()
}

/// Windows: not yet enumerated (the Public-profile check comes with it), so
/// no beacon or probe is ever sent there; remembered addresses still work.
#[cfg(not(unix))]
pub fn interfaces() -> Vec<Interface> {
    Vec::new()
}

/// On-link IPv4 routes per interface index (Linux `/proc/net/route`): the
/// `10.8.0.2/32 dev wg0` kind that makes a /32 tunnel sweepable.
pub fn routes(ifs: &[Interface]) -> Vec<(u32, Ipv4Addr, u8)> {
    let Ok(s) = std::fs::read_to_string("/proc/net/route") else { return Vec::new() };
    let mut out = Vec::new();
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Ok(dst), Ok(gw), Ok(mask)) = (u32::from_str_radix(f[1], 16), u32::from_str_radix(f[2], 16), u32::from_str_radix(f[7], 16)) else { continue };
        if gw != 0 || mask == 0 {
            continue; // only on-link, never the default route
        }
        let Some(i) = ifs.iter().find(|i| i.name == f[0]) else { continue };
        out.push((i.index, Ipv4Addr::from(u32::from_be(dst)), u32::from_be(mask).count_ones() as u8));
    }
    out
}

/// Neighbor-table hints (Linux `/proc/net/arp`), complete entries only.
pub fn neighbors() -> Vec<IpAddr> {
    let Ok(s) = std::fs::read_to_string("/proc/net/arp") else { return Vec::new() };
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 4 && f[2] == "0x2").then(|| f[0].parse().ok()).flatten()
        })
        .collect()
}

fn mark(ifs: Vec<Interface>, skip: &Skip) -> Vec<Interface> {
    ifs.into_iter()
        .map(|mut i| {
            i.opted_out = skip.matches(&i);
            i
        })
        .collect()
}

/// This device's hello: every advertisable address on every up interface.
pub fn hello(pk: [u8; 32], port: u16, skip: &Skip) -> Hello {
    let mut addrs = Vec::new();
    for i in mark(interfaces(), skip) {
        if i.opted_out {
            continue;
        }
        let class = iface::classify(&i.flags);
        for a in &i.addrs {
            if record::advertisable(&a.ip) && !addrs.iter().any(|h: &HelloAddr| h.ip == a.ip) {
                addrs.push(HelloAddr { ip: a.ip, class });
            }
        }
    }
    if addrs.is_empty() {
        // No getifaddrs (Windows for now): the default-route sources.
        for ip in direct::local_ips() {
            if record::advertisable(&ip) {
                addrs.push(HelloAddr { ip, class: Class::Shared });
            }
        }
    }
    Hello { presence_key: pk, port, addrs }
}

// ------------------------------------------------------------ the QUIC side --

/// A dual-stack QUIC endpoint on `port` (0 = any), accepting and dialing.
pub fn bind(port: u16) -> Result<(Endpoint, u16)> {
    bind_with(port, false)
}

/// `pair` adds the pairing ALPN to the listener. The daemon and one-shot
/// senders keep the frozen direct-only listener.
fn bind_with(port: u16, pair: bool) -> Result<(Endpoint, u16)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).context("lan UDP socket")?;
    sock.set_only_v6(false).ok();
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    sock.bind(&addr.into()).with_context(|| format!("bind lan listener on {port}"))?;
    let port = sock.local_addr()?.as_socket().map(|a| a.port()).unwrap_or(port);
    let socket: std::net::UdpSocket = sock.into();
    socket.set_nonblocking(true)?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
    let server = if pair { direct::server_config_lan()? } else { direct::server_config()? };
    let mut ep = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        runtime.wrap_udp_socket(socket)?,
        runtime,
    )?;
    ep.set_default_client_config(direct::client_config()?);
    Ok((ep, port))
}

/// The ALPN the peer selected, if the handshake exposed one.
fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    conn.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol)
}

fn to_dial(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), a.port()),
        _ => a,
    }
}

/// Acceptor side of spec section 10: read the dialer's tag, find the secret
/// that produced it, answer with ours.
async fn accept_auth(conn: &quinn::Connection, keys: &[LanKey]) -> Result<(LanKey, quinn::SendStream, quinn::RecvStream)> {
    let km = direct::keying_material(conn)?;
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let mut tag = [0u8; 32];
    recv.read_exact(&mut tag).await.context("read auth tag")?;
    let mut hit: Option<&LanKey> = None;
    for k in keys {
        let tkey = direct::transport_key(&k.secret);
        // Every key is tried even after a match, so timing does not say which.
        if direct::ct_eq(&direct::auth_tag(&tkey, &km, "dialer"), &tag) && hit.is_none() {
            hit = Some(k);
        }
    }
    let k = hit.ok_or_else(|| anyhow!("DIRECT-AUTH-FAIL: no held secret matches this lan dialer"))?;
    let tkey = direct::transport_key(&k.secret);
    send.write_all(&direct::auth_tag(&tkey, &km, "acceptor")).await.context("write auth tag")?;
    Ok((k.clone(), send, recv))
}

/// Accept loop on the listener. A direct connection becomes
/// `Ev::Lan(Linked)`; a `filament-pair/1` connection becomes a `PairLink` on
/// `pair`, and is closed when no pairing code is on screen.
pub fn spawn_accept(
    ep: Endpoint,
    keys: Arc<dyn Fn() -> Vec<LanKey> + Send + Sync>,
    pair: Option<Sender<PairLink>>,
    shutdown: Shutdown,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    tx: UnboundedSender<Ev>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_ACCEPTS));
        loop {
            let incoming = tokio::select! {
                _ = shutdown.wait() => break,
                incoming = ep.accept() => match incoming { Some(i) => i, None => break },
            };
            let Ok(permit) = inflight.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let keys = keys.clone();
            let tx = tx.clone();
            let pair = pair.clone();
            let ep2 = ep.clone();
            let shutdown2 = shutdown.clone();
            let tasks2 = tasks.clone();
            let h = tokio::spawn(async move {
                let _permit = permit;
                let r = tokio::time::timeout(ACCEPT_AUTH_BUDGET, async {
                    let conn = incoming.await.context("lan accept handshake")?;
                    let alpn = negotiated_alpn(&conn);
                    crate::hooks::debug(&format!("lan: inbound alpn {alpn:?}"));
                    if alpn.as_deref() == Some(direct::PAIR_ALPN) {
                        let Some(pair) = pair else {
                            conn.close(quinn::VarInt::from_u32(0x5041), b"no pairing code");
                            return Ok(None);
                        };
                        let (send, recv) = conn.accept_bi().await.context("accept pairing stream")?;
                        let keying_material = direct::pairing_keying_material(&conn)?;
                        let remote = canonical(conn.remote_address());
                        if pair.try_send(PairLink {
                            conn,
                            send,
                            recv,
                            keying_material,
                            remote,
                            dialer: false,
                        }).is_err() {
                            return Ok(None);
                        }
                        return Ok(None);
                    }
                    let (k, send, recv) = accept_auth(&conn, &keys()).await?;
                    Ok::<_, anyhow::Error>(Some((conn, k, send, recv)))
                })
                .await;
                match r {
                    Ok(Ok(Some((conn, k, send, recv)))) => {
                        if shutdown2.is_stopped() { conn.close(quinn::VarInt::from_u32(0), b"lan stopped"); return; }
                        let remote = canonical(conn.remote_address());
                        let pid = fresh_pid();
                        let transport = direct::make_transport_unread(pid.clone(), conn, send, recv, tx.clone(), true, Some(ep2), true);
                        let _ = tx.send(Ev::Lan(LanEvent::Linked { pid, name: k.name, secret: k.secret, fleet: k.fleet, transport, remote, dialer: false }));
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => crate::hooks::debug(&format!("lan: inbound refused: {e:#}")),
                    Err(_) => crate::hooks::debug("lan: inbound did not authenticate in time"),
                }
            });
            if shutdown.is_stopped() {
                h.abort();
            } else {
                tasks2.lock().unwrap().push(h);
            }
        }
    })
}

/// Dial one of up to five pairing candidates with the pairing ALPN only. The
/// caller owns the ceremony and consent; this returns the first session that
/// completed the QUIC handshake, not an authenticated peer.
pub async fn pair_dial(ep: &Endpoint, addrs: Vec<SocketAddr>) -> Result<PairLink> {
    let cfg = direct::pair_client_config()?;
    let mut last: Option<anyhow::Error> = None;
    for (i, a) in addrs.into_iter().take(5).enumerate() {
        if i > 0 {
            tokio::time::sleep(DIAL_STAGGER).await;
        }
        let r = tokio::time::timeout(Duration::from_secs(5), async {
            let conn = ep.connect_with(cfg.clone(), to_dial(a), "filament-pair")?.await.context("pair dial handshake")?;
            let (send, recv) = conn.open_bi().await.context("open pairing stream")?;
            let keying_material = direct::pairing_keying_material(&conn)?;
            let remote = canonical(conn.remote_address());
            Ok::<_, anyhow::Error>(PairLink {
                conn,
                send,
                recv,
                keying_material,
                remote,
                dialer: true,
            })
        })
        .await;
        match r {
            Ok(Ok(link)) => return Ok(link),
            Ok(Err(e)) => last = Some(e),
            Err(_) => last = Some(anyhow!("pair dial timed out")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no pairing candidate")))
}

/// One pairing frame is a u32-BE length plus JSON. The cap is deliberately
/// far above the contract frames and far below anything that could pin memory.
pub const PAIR_MAX_FRAME: usize = 64 * 1024;
const PAIR_FRAME_BUDGET: Duration = Duration::from_secs(10);

pub async fn pair_write(send: &mut SendStream, v: &Value) -> Result<()> {
    let body = serde_json::to_vec(v)?;
    if body.is_empty() || body.len() > PAIR_MAX_FRAME {
        return Err(anyhow!("pairing frame is {} bytes", body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    eprintln!("PAIRDBG write {} bytes", out.len());
    tokio::time::timeout(PAIR_FRAME_BUDGET, send.write_all(&out))
        .await
        .map_err(|_| anyhow!("pairing frame write timed out"))??;
    eprintln!("PAIRDBG write done");
    Ok(())
}

pub async fn pair_read(recv: &mut RecvStream) -> Result<Value> {
    let mut hdr = [0u8; 4];
    tokio::time::timeout(PAIR_FRAME_BUDGET, recv.read_exact(&mut hdr))
        .await
        .map_err(|_| anyhow!("pairing frame header timed out"))??;
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 || len > PAIR_MAX_FRAME {
        return Err(anyhow!("pairing frame length {len} is outside 1..={PAIR_MAX_FRAME}"));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(PAIR_FRAME_BUDGET, recv.read_exact(&mut body))
        .await
        .map_err(|_| anyhow!("pairing frame body timed out"))??;
    eprintln!("PAIRDBG read {} bytes", len);
    serde_json::from_slice(&body).context("pairing frame is not JSON")
}

/// Dial `addrs` concurrently with `key`; the first authenticated connection
/// wins and is announced as `Ev::Lan(Linked)` with `dialer: true`. Returns
/// the address that answered.
pub async fn dial(ep: Endpoint, key: LanKey, addrs: Vec<SocketAddr>, tx: UnboundedSender<Ev>) -> Option<SocketAddr> {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    if addrs.is_empty() {
        return None;
    }
    let tkey = direct::transport_key(&key.secret);
    // Staggered, best first (happy eyeballs): one address usually wins before
    // the next is tried, so the far end does not authenticate several
    // connections of which all but one are dropped at once.
    let mut set: FuturesUnordered<_> = addrs
        .into_iter()
        .enumerate()
        .map(|(i, a)| {
            let ep = ep.clone();
            async move {
                tokio::time::sleep(DIAL_STAGGER * i as u32).await;
                let conn = ep.connect(to_dial(a), "filament-direct")?.await.context("lan dial handshake")?;
                let (s, r) = direct::authenticate(&conn, &tkey, true).await?;
                Ok::<_, anyhow::Error>((a, conn, s, r))
            }
        })
        .collect();
    let won = tokio::time::timeout(DIAL_BUDGET, async {
        while let Some(r) = set.next().await {
            match r {
                Ok(w) => return Some(w),
                Err(e) => crate::hooks::debug(&format!("lan: dial attempt failed: {e:#}")),
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    let (addr, conn, send, recv) = won?;
    let pid = fresh_pid();
    let remote = canonical(conn.remote_address());
    let transport = direct::make_transport_unread(pid.clone(), conn, send, recv, tx.clone(), false, Some(ep), true);
    let _ = tx.send(Ev::Lan(LanEvent::Linked { pid, name: key.name, secret: key.secret, fleet: key.fleet, transport, remote, dialer: true }));
    Some(addr)
}

// ----------------------------------------------------------- the service --

#[derive(Clone, Default)]
pub struct Options {
    /// Bind the listener and send beacons (the daemon). A one-shot command
    /// only queries and dials.
    pub serve: bool,
    /// Receive discovery datagrams without announcing (a pairing joiner).
    /// Binds the discovery port with reuse so it hears pairing beacons.
    pub listen_discovery: bool,
    /// Advertise this pairing id while a code is on screen. `None` never sends
    /// a pairing beacon and never accepts a pairing connection.
    pub pairing: Option<[u8; 16]>,
    pub skip: Skip,
}

struct Shared {
    engine: Engine,
    ifaces: Vec<Interface>,
    port: u16,
    started: Option<Instant>,
    errors: Vec<String>,
}

/// A running discovery service.
#[derive(Clone)]
pub struct LanService {
    shared: Arc<Mutex<Shared>>,
    pub store: LanStore,
    pk: [u8; 32],
    port: u16,
    skip: Skip,
    listen_ep: Option<Endpoint>,
    dial_ep: Endpoint,
    shutdown: Shutdown,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    tx: UnboundedSender<Ev>,
}

fn mcast_v4() -> Ipv4Addr {
    let g = wire::GROUP_V4;
    Ipv4Addr::new(g[0], g[1], g[2], g[3])
}

fn mcast_v6() -> Ipv6Addr {
    let g = wire::GROUP_V6;
    Ipv6Addr::new(g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7])
}

fn udp(domain_v6: bool, port: u16, reuse: bool) -> Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(if domain_v6 { Domain::IPV6 } else { Domain::IPV4 }, Type::DGRAM, Some(Protocol::UDP))?;
    if reuse {
        s.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        let _ = s.set_reuse_port(true);
    }
    let addr: SocketAddr = if domain_v6 {
        s.set_only_v6(true)?;
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        s.set_broadcast(true)?;
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    };
    s.bind(&addr.into())?;
    if domain_v6 {
        let _ = s.set_multicast_hops_v6(1);
        let _ = s.set_multicast_loop_v6(true);
    } else {
        let _ = s.set_multicast_ttl_v4(1);
        let _ = s.set_multicast_loop_v4(true);
    }
    s.set_nonblocking(true)?;
    Ok(tokio::net::UdpSocket::from_std(s.into())?)
}

struct Sockets {
    beacon4: Option<tokio::net::UdpSocket>,
    beacon6: Option<tokio::net::UdpSocket>,
    mdns4: Option<tokio::net::UdpSocket>,
}

impl Sockets {
    fn join(&self, ifs: &[Interface]) {
        for i in ifs {
            if iface::classify(&i.flags) != Class::Shared || !i.flags.multicast || i.opted_out || i.public_network {
                continue;
            }
            for a in &i.addrs {
                if let IpAddr::V4(v4) = a.ip {
                    if let Some(s) = &self.beacon4 {
                        let _ = s.join_multicast_v4(mcast_v4(), v4);
                    }
                    if let Some(s) = &self.mdns4 {
                        let g = tunlion_lan::mdns::MDNS_V4;
                        let _ = s.join_multicast_v4(Ipv4Addr::new(g[0], g[1], g[2], g[3]), v4);
                    }
                }
            }
            if let Some(s) = &self.beacon6 {
                let _ = s.join_multicast_v6(&mcast_v6(), i.index);
            }
        }
    }

    async fn send(&self, s: &tunlion_lan::engine::Send) {
        let sock = match (s.chan, s.to.is_ipv4()) {
            (Channel::Beacon, true) => self.beacon4.as_ref(),
            (Channel::Beacon, false) => self.beacon6.as_ref(),
            (Channel::Mdns, true) => self.mdns4.as_ref(),
            (Channel::Mdns, false) => None,
        };
        let Some(sock) = sock else { return };
        let r = socket2::SockRef::from(sock);
        if let Some(src) = s.src_v4 {
            let _ = r.set_multicast_if_v4(&src);
        }
        if let (Some(ix), false) = (s.iface, s.to.is_ipv4()) {
            let _ = r.set_multicast_if_v6(ix);
        }
        if let Err(e) = sock.send_to(&s.bytes, s.to).await {
            crate::hooks::trace(&format!("lan: send to {} failed: {e}", s.to));
        }
    }
}

fn allowed_from(ifs: &[Interface], src: IpAddr) -> bool {
    let src = src.to_canonical();
    // Discovery is off on a source that falls in an opted-out or public
    // interface's prefix; an unknown source (routed, VPN) is fine.
    !ifs.iter().any(|i| (i.opted_out || i.public_network) && i.addrs.iter().any(|a| in_prefix(src, a.ip, a.prefix)))
}

impl LanService {
    /// Start the service. With `opts.serve` the listener is bound (default
    /// port, else any), beacons go out, queries are answered and inbound links
    /// are accepted with `keys`.
    pub async fn start(
        config_dir: &Path,
        opts: Options,
        keys: Arc<dyn Fn() -> Vec<LanKey> + Send + Sync>,
        pair_tx: Option<Sender<PairLink>>,
        tx: UnboundedSender<Ev>,
    ) -> Result<LanService> {
        let store = LanStore::new(config_dir);
        let pk = store.presence_key()?;
        let mut errors = Vec::new();
        let pairing = opts.pairing.is_some();
        let (listen_ep, port) = if opts.serve {
            match bind_with(wire::DEFAULT_LISTEN_PORT, pairing).or_else(|_| bind_with(0, pairing)) {
                Ok((ep, port)) => (Some(ep), port),
                Err(e) => {
                    errors.push(format!("listener: {e:#}"));
                    (None, 0)
                }
            }
        } else {
            (None, 0)
        };
        let (dial_ep, _) = bind(0)?;
        let shutdown = Shutdown::new();
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        if let Some(ep) = listen_ep.clone() {
            let h = spawn_accept(ep, keys, pair_tx, shutdown.clone(), tasks.clone(), tx.clone());
            tasks.lock().unwrap().push(h);
        }
        let mut engine = Engine::new(pk, port);
        // A one-shot command has no listener: it queries, never announces.
        engine.set_announce(opts.serve);
        engine.set_pairing(opts.pairing);
        engine.set_known(store.known());
        let shared = Arc::new(Mutex::new(Shared { engine, ifaces: Vec::new(), port, started: Some(Instant::now()), errors }));
        let svc = LanService {
            shared: shared.clone(),
            store,
            pk,
            port,
            skip: opts.skip.clone(),
            listen_ep,
            dial_ep,
            shutdown: shutdown.clone(),
            tasks: tasks.clone(),
            tx: tx.clone(),
        };

        // Sockets: the daemon owns the discovery port; a pairing joiner binds
        // it with reuse but never announces, so it hears beacons without
        // answering them. Other one-shots bind any port for query replies.
        let receive_only = opts.listen_discovery;
        let bport = if opts.serve || receive_only { wire::DISCOVERY_PORT } else { 0 };
        let reuse = opts.serve || receive_only;
        let note = |what: &str, r: Result<tokio::net::UdpSocket>, errs: &mut Vec<String>| match r {
            Ok(s) => Some(s),
            Err(e) => {
                errs.push(format!("{what}: {e:#}"));
                None
            }
        };
        let mut errs = Vec::new();
        let socks = Arc::new(Sockets {
            beacon4: note("discovery socket (v4)", udp(false, bport, reuse).or_else(|_| udp(false, 0, false)), &mut errs),
            beacon6: note("discovery socket (v6)", udp(true, bport, reuse).or_else(|_| udp(true, 0, false)), &mut errs),
            mdns4: if opts.serve { note("mDNS socket", udp(false, tunlion_lan::mdns::MDNS_PORT, true), &mut errs) } else { None },
        });
        shared.lock().unwrap().errors.extend(errs);

        // Receivers.
        for (chan, which) in [(Channel::Beacon, 4u8), (Channel::Beacon, 6), (Channel::Mdns, 4)] {
            let socks = socks.clone();
            let shared = shared.clone();
            let tx = tx.clone();
            let serve = opts.serve;
            let shutdown = shutdown.clone();
            let h = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let sock = match (chan, which) {
                        (Channel::Beacon, 4) => socks.beacon4.as_ref(),
                        (Channel::Beacon, _) => socks.beacon6.as_ref(),
                        (Channel::Mdns, _) => socks.mdns4.as_ref(),
                    };
                    let Some(sock) = sock else { return };
                    let recv = tokio::select! {
                        _ = shutdown.wait() => return,
                        recv = sock.recv_from(&mut buf) => recv,
                    };
                    let Ok((n, src)) = recv else {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    };
                    let src = canonical(src);
                    let actions = {
                        let mut g = shared.lock().unwrap();
                        let allowed = serve && allowed_from(&g.ifaces, src.ip());
                        g.engine.on_datagram(now_ms(), unix_now(), chan, src, &buf[..n], allowed, &mut rng)
                    };
                    for a in actions {
                        match a {
                            Action::Send(s) => socks.send(&s).await,
                            Action::Found { peer, addr, .. } => {
                                let _ = tx.send(Ev::Lan(LanEvent::Found { name: peer, addr }));
                            }
                            Action::PairingNearby { addr, label, .. } => {
                                let _ = tx.send(Ev::Lan(LanEvent::PairingNearby { addr, label }));
                            }
                        }
                    }
                }
            });
            tasks.lock().unwrap().push(h);
        }

        // Ticker: interfaces are re-read every 5 s; the engine paces itself.
        {
            let shared = shared.clone();
            let skip = opts.skip.clone();
            let shutdown = shutdown.clone();
            let h = tokio::spawn(async move {
                let mut last_scan: Option<Instant> = None;
                let mut routes_cache = Vec::new();
                let mut hints = Vec::new();
                loop {
                    if last_scan.map_or(true, |t| t.elapsed() >= Duration::from_secs(5)) {
                        last_scan = Some(Instant::now());
                        let ifs = mark(interfaces(), &skip);
                        routes_cache = routes(&ifs);
                        hints = neighbors();
                        socks.join(&ifs);
                        shared.lock().unwrap().ifaces = ifs;
                    }
                    let actions = {
                        let mut g = shared.lock().unwrap();
                        let ifs = g.ifaces.clone();
                        g.engine.tick(now_ms(), unix_now(), &ifs, &routes_cache, &hints, &mut rng)
                    };
                    for a in actions {
                        if let Action::Send(s) = a {
                            socks.send(&s).await;
                        }
                    }
                    tokio::select! {
                        _ = shutdown.wait() => break,
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                }
            });
            tasks.lock().unwrap().push(h);
        }
        Ok(svc)
    }

    /// This device's hello, to send on every new authenticated link.
    pub fn hello_json(&self) -> Value {
        hello(self.pk, self.port, &self.skip).to_json()
    }

    /// A hello arrived on an authenticated link to `name`.
    pub fn learn(&self, name: &str, v: &Value) -> bool {
        let Some(h) = Hello::from_json(v) else { return false };
        self.store.learn(name, &h);
        self.shared.lock().unwrap().engine.set_known(self.store.known());
        true
    }

    pub fn query_soon(&self) {
        self.shared.lock().unwrap().engine.query_soon();
    }

    /// Stop every task this service started and close both endpoints. Used by
    /// the one-shot pair command on success, expiry, cancellation and failure.
    pub async fn shutdown(&self) {
        self.shutdown.stop();
        if let Some(ep) = &self.listen_ep {
            ep.close(quinn::VarInt::from_u32(0), b"lan stopped");
        }
        self.dial_ep.close(quinn::VarInt::from_u32(0), b"lan stopped");
        let handles = {
            let mut g = self.tasks.lock().unwrap();
            std::mem::take(&mut *g)
        };
        for mut h in handles {
            tokio::select! {
                _ = &mut h => {}
                _ = tokio::time::sleep(Duration::from_secs(2)) => {
                    h.abort();
                    let _ = h.await;
                }
            }
        }
    }

    /// Dial pairing candidates with the pairing ALPN only.
    pub async fn pair_dial(&self, addrs: Vec<SocketAddr>) -> Result<PairLink> {
        pair_dial(&self.dial_ep, addrs).await
    }

    /// Dial `addrs` for `key` in the background. The result arrives as
    /// `Ev::Lan(Linked)`; a dial that wins also marks the address ok.
    pub fn dial(&self, key: LanKey, addrs: Vec<SocketAddr>) {
        let ep = self.dial_ep.clone();
        let tx = self.tx.clone();
        let store = self.store.clone();
        tokio::spawn(async move {
            let name = key.name.clone();
            let fleet = key.fleet;
            if let Some(addr) = dial(ep, key, addrs, tx).await {
                if !fleet {
                    store.mark_ok(&name, addr);
                }
            }
        });
    }

    /// Publish the snapshot to `<config>/lan-state.json` for `doctor`, with the
    /// time it was taken (a stale file means the daemon is not running it).
    pub fn write_state(&self, dir: &Path) {
        let mut v = self.snapshot();
        v["at"] = json!(unix_now());
        v["remembered"] = json!(self.store.load().iter().map(|(n, r)| json!({"name": n, "addrs": r.addrs.len(), "has_key": r.presence_key.is_some()})).collect::<Vec<_>>());
        if let Ok(text) = serde_json::to_string_pretty(&v) {
            let _ = write_private(&dir.join("lan-state.json"), text.as_bytes());
        }
    }

    /// For `doctor` and `status`: listener, counters, interfaces by class.
    pub fn snapshot(&self) -> Value {
        let g = self.shared.lock().unwrap();
        let st = &g.engine.stats;
        json!({
            "on": true,
            "listen_port": g.port,
            "up_s": g.started.map(|t| t.elapsed().as_secs()),
            "beacons_sent": st.beacons_sent,
            "queries_sent": st.queries_sent,
            "probes_sent": st.probes_sent,
            "received": st.received,
            "recognized": st.recognized,
            "replies_sent": st.replies_sent,
            "known_peers": self.store.known().len(),
            "interfaces": g.ifaces.iter().map(|i| {
                let plan = iface::plan(i, &[]);
                json!({
                    "name": i.name,
                    "class": iface::classify(&i.flags).as_str(),
                    "addrs": i.addrs.iter().map(|a| format!("{}/{}", a.ip, a.prefix)).collect::<Vec<_>>(),
                    "multicast": plan.multicast_v4 || plan.multicast_v6,
                    "broadcast": !plan.broadcast.is_empty(),
                    "sweep": plan.sweep.len(),
                    "off": if i.opted_out { Some("opted out") } else if i.public_network { Some("public network") } else { None },
                })
            }).collect::<Vec<_>>(),
            "errors": g.errors,
        })
    }
}

fn now_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Transport;

    #[tokio::test]
    async fn pair_carrier_negotiates_and_frames_both_ways() {
        let (srv, port) = bind_with(0, true).unwrap();
        let (cli, _) = bind_with(0, false).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let (ptx, mut prx) = tokio::sync::mpsc::channel(1);
        let accept = spawn_accept(
            srv,
            Arc::new(Vec::<LanKey>::new),
            Some(ptx),
            Shutdown::new(),
            Arc::new(Mutex::new(Vec::new())),
            tx,
        );
        let dial = tokio::time::timeout(
            Duration::from_secs(10),
            pair_dial(&cli, vec![format!("127.0.0.1:{port}").parse().unwrap()]),
        )
        .await
        .expect("pair dial did not finish")
        .expect("pair dial failed");
        let mut host = tokio::time::timeout(Duration::from_secs(10), prx.recv())
            .await
            .expect("host did not receive a pair link")
            .expect("pair link channel closed");
        let mut dial = dial;
        pair_write(&mut dial.send, &serde_json::json!({"type":"pake-msg","v":2})).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), pair_read(&mut host.recv))
            .await
            .expect("host read timed out")
            .unwrap();
        assert_eq!(got["type"], "pake-msg");
        pair_write(&mut host.send, &serde_json::json!({"type":"pake-confirm","v":2})).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), pair_read(&mut dial.recv))
            .await
            .expect("dial read timed out")
            .unwrap();
        assert_eq!(got["type"], "pake-confirm");
        accept.abort();
    }

    #[test]
    fn skip_matches_by_user_name_or_cidr() {
        let i = Interface {
            index: 3,
            name: "wg0".into(),
            flags: Flags { up: true, point_to_point: true, ..Flags::default() },
            addrs: vec![Addr { ip: "10.8.0.1".parse().unwrap(), prefix: 24 }],
            opted_out: false,
            public_network: false,
        };
        assert!(Skip(vec!["WG0".into()]).matches(&i));
        assert!(Skip(vec!["10.8.0.0/16".into()]).matches(&i));
        assert!(!Skip(vec!["eth0".into(), "192.168.0.0/16".into()]).matches(&i));
    }

    #[test]
    fn store_round_trips_and_forgets() {
        let dir = std::env::temp_dir().join(format!("lan-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = LanStore::new(&dir);
        let k1 = s.presence_key().unwrap();
        assert_eq!(s.presence_key().unwrap(), k1, "the presence key is stable once made");
        let h = Hello { presence_key: [4; 32], port: 47821, addrs: vec![HelloAddr { ip: "10.8.0.2".parse().unwrap(), class: Class::PointToPoint }] };
        s.learn("Laptop", &h);
        assert_eq!(s.dial_order("laptop"), vec!["10.8.0.2:47821".parse::<SocketAddr>().unwrap()]);
        s.mark_ok("laptop", "[::ffff:192.168.1.4]:47821".parse().unwrap());
        assert_eq!(s.dial_order("laptop")[0], "192.168.1.4:47821".parse::<SocketAddr>().unwrap());
        assert_eq!(s.known().len(), 1);
        s.forget("LAPTOP");
        assert!(s.dial_order("laptop").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two endpoints on loopback: the dialer authenticates with the pair
    /// secret and the listener finds it among several held secrets; a dialer
    /// with a secret the listener does not hold is refused.
    #[tokio::test]
    async fn trial_mac_listener_admits_only_held_secrets() {
        let (lep, lport) = bind(0).unwrap();
        let held: Arc<dyn Fn() -> Vec<LanKey> + Send + Sync> = Arc::new(|| {
            vec![
                LanKey { name: "other".into(), secret: "11".repeat(32), fleet: false },
                LanKey { name: "laptop".into(), secret: "22".repeat(32), fleet: false },
            ]
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        spawn_accept(lep, held, None, Shutdown::new(), Arc::new(Mutex::new(Vec::new())), tx.clone());
        let target: SocketAddr = format!("127.0.0.1:{lport}").parse().unwrap();

        let (dep, _) = bind(0).unwrap();
        let won = tokio::time::timeout(Duration::from_secs(8), dial(dep, LanKey { name: "desk".into(), secret: "22".repeat(32), fleet: false }, vec![target], tx.clone()))
            .await
            .unwrap();
        assert_eq!(won, Some(target));
        let mut names = Vec::new();
        for _ in 0..2 {
            match tokio::time::timeout(Duration::from_secs(8), rx.recv()).await.unwrap() {
                Some(Ev::Lan(LanEvent::Linked { name, dialer, .. })) => names.push((name, dialer)),
                other => panic!("unexpected {other:?}"),
            }
        }
        names.sort();
        assert_eq!(names, vec![("desk".to_string(), true), ("laptop".to_string(), false)]);

        // (Linked events carry unread transports; dropping them here starts
        // their readers, as an unannounced UnreadTransport does.)
        let (bad, _) = bind(0).unwrap();
        let lost = tokio::time::timeout(Duration::from_secs(8), dial(bad, LanKey { name: "x".into(), secret: "33".repeat(32), fleet: false }, vec![target], tx))
            .await
            .unwrap();
        assert_eq!(lost, None, "a secret the listener does not hold never links");
    }

    /// The ordering the loops rely on: a frame the peer sends the moment the
    /// link is up is not delivered before the link is announced, and after
    /// announce it arrives behind the ready event. (The failure this pins: a
    /// one-shot's file-offer reached the daemon before the link existed and
    /// was dropped.)
    #[tokio::test]
    async fn lan_link_frames_wait_for_announce() {
        let (lep, lport) = bind(0).unwrap();
        let held: Arc<dyn Fn() -> Vec<LanKey> + Send + Sync> =
            Arc::new(|| vec![LanKey { name: "desk".into(), secret: "44".repeat(32), fleet: false }]);
        let (atx, mut arx) = tokio::sync::mpsc::unbounded_channel();
        spawn_accept(lep, held, None, Shutdown::new(), Arc::new(Mutex::new(Vec::new())), atx.clone());
        let (dtx, mut drx) = tokio::sync::mpsc::unbounded_channel();
        let (dep, _) = bind(0).unwrap();
        let target: SocketAddr = format!("127.0.0.1:{lport}").parse().unwrap();
        let key = LanKey { name: "laptop".into(), secret: "44".repeat(32), fleet: false };
        assert!(tokio::time::timeout(Duration::from_secs(8), dial(dep, key, vec![target], dtx.clone())).await.unwrap().is_some());
        // Dialer: announce its side and send a control frame at once.
        let Some(Ev::Lan(LanEvent::Linked { transport: dt, .. })) = tokio::time::timeout(Duration::from_secs(8), drx.recv()).await.unwrap() else {
            panic!("dialer did not link")
        };
        dt.announce(&dtx, |t| Ev::DirectReady("d".into(), t, ROUTE_LAN));
        let Some(Ev::DirectReady(_, dtrans, _)) = drx.recv().await else { panic!("no dialer ready") };
        dtrans.send_control(&json!({"type": "file-offer", "probe": 1})).await.unwrap();
        // Acceptor: the link event comes first, and nothing else until announce.
        let Some(Ev::Lan(LanEvent::Linked { transport: at, pid, .. })) = tokio::time::timeout(Duration::from_secs(8), arx.recv()).await.unwrap() else {
            panic!("acceptor did not link")
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(500), arx.recv()).await.is_err(),
            "a frame was delivered before the link was announced"
        );
        at.announce(&atx, |t| Ev::DirectReady(pid.clone(), t, ROUTE_LAN));
        assert!(matches!(arx.recv().await, Some(Ev::DirectReady(..))), "the ready event comes first");
        match tokio::time::timeout(Duration::from_secs(5), arx.recv()).await.unwrap() {
            Some(Ev::Control(p, v)) => {
                assert_eq!(p, pid);
                assert_eq!(v["type"], "file-offer");
            }
            other => panic!("expected the peer's frame, got {other:?}"),
        }
    }
}

/// Is local discovery on? `network.transports` is `auto` (the default) or a
/// list that includes `lan`.
pub fn enabled(ctx: &crate::TransportContext) -> bool {
    let v = ctx.setting("network.transports", None).unwrap_or_else(|| "auto".into());
    let v = v.trim().to_ascii_lowercase();
    v.is_empty() || v == "auto" || v.split(',').any(|t| t.trim() == "lan")
}

/// The user's per-interface opt-out (`network.lan-skip`).
pub fn skip(ctx: &crate::TransportContext) -> Skip {
    Skip(ctx.setting("network.lan-skip", None).unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}
