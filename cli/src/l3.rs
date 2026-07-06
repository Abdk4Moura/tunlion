//! L3 (serve_tun) manager: one TUN for this node, a route table mapping a peer's
//! overlay IP to its link transport, and the datagram pumps. Lives in the `up`
//! daemon, which owns the QUIC connections the datagrams ride.
//!
//! Data path (symmetric on both ends):
//!   TUN read  -> dest IP -> route lookup -> peer.send_datagram(packet)
//!   peer datagram -> TUN write
//!
//! The daemon's link layer is already a full mesh of authenticated links; L3 just
//! attaches an IP plane to it. Each node's overlay address is derived from its
//! Ed25519 overlay key (see `overlay`); peers learn and TRUST each other's address
//! via a SIGNED `l3-announce` verified against the live link's channel binding
//! (main.rs). Only direct-QUIC links carry datagrams; relay links are skipped for
//! now (no L3 over relay yet).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use crate::net::Transport;
use crate::overlay::{Announce, Identity};
use crate::tun::{KernelTun, NetstackListener, NetstackStream, NetstackTun, TunDevice};

/// How the overlay's packet endpoint is provided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum L3Mode {
    /// Kernel TUN when it can be created, else the userspace netstack. The default.
    Auto,
    /// Force the kernel TUN; fail if it can't be created.
    Kernel,
    /// Force the userspace smoltcp netstack (zero privilege; containers/CI/no-sudo).
    Userspace,
}

/// A mode-agnostic accepted overlay connection: a kernel `TcpStream` (bound on the
/// overlay IP) or a userspace smoltcp stream. Implements the same async byte-stream
/// traits either way, so `expose`'s splice code is identical in both modes.
pub enum OverlayStream {
    Kernel(tokio::net::TcpStream),
    Netstack(NetstackStream),
}

impl tokio::io::AsyncRead for OverlayStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for OverlayStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_write(cx, b),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_write(cx, b),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_flush(cx),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OverlayStream::Kernel(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OverlayStream::Netstack(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A mode-agnostic overlay listener. `accept` yields the next connection and the
/// peer's overlay SOURCE address (the expose allowlist matches on it).
pub enum OverlayListener {
    Kernel(tokio::net::TcpListener),
    Netstack(NetstackListener),
}

impl OverlayListener {
    pub async fn accept(&self) -> Result<(OverlayStream, IpAddr)> {
        match self {
            OverlayListener::Kernel(l) => {
                let (s, src) = l.accept().await?;
                Ok((OverlayStream::Kernel(s), src.ip()))
            }
            OverlayListener::Netstack(nl) => {
                let (s, src) = nl.accept().await?;
                Ok((OverlayStream::Netstack(s), src.as_ipv6().into()))
            }
        }
    }
}

/// The TUN interface name the daemon creates for the overlay.
const IFNAME: &str = "filament0";

pub struct L3 {
    tun: Arc<dyn TunDevice>,
    /// overlay dest IP -> the transport that peer's packets ride. Read on the TUN hot
    /// path, written as links come and go. A dual-stack peer has TWO entries here (its
    /// v6 ULA and its v4 address) both pointing at the same transport. The hot path
    /// takes the lock only to clone one Arc.
    routes: Arc<Mutex<HashMap<IpAddr, Arc<dyn Transport>>>>,
    /// pid -> that link's datagram->TUN pump. ONE reader per link (a peer's datagrams
    /// carry both families; the pump just forwards each to the TUN, which demuxes by
    /// dest), aborted when the link is replaced/removed so it is never leaked (fix #2).
    readers: Mutex<HashMap<String, AbortHandle>>,
    /// pid -> every overlay IP that link installed (v6 always; v4 in dual-stack), so a
    /// link drop or re-key (keyed by pid in main.rs) can retract exactly those routes.
    by_pid: Mutex<HashMap<String, Vec<IpAddr>>>,
    /// This node's overlay identity (crypto mode) for signing announces; `None` in
    /// manual/PSK addressing mode (no announce, routes added out of band).
    identity: Option<Identity>,
    /// Monotonic announce sequence so a peer can ignore a stale re-announce.
    seq: AtomicU64,
    /// MagicDNS: pid -> (petname, v6 overlay addr, optional v4 overlay addr) for
    /// VERIFIED peers, mirrored into a managed block in /etc/hosts so native tools
    /// resolve `<petname>` / `<petname>.mesh` (both AAAA and A records).
    names: Mutex<HashMap<String, (String, Ipv6Addr, Option<Ipv4Addr>)>>,
    /// `Some` when the endpoint is the userspace netstack (no kernel TUN). Held as
    /// the concrete type so `bind`/`dial` can open smoltcp sockets; its presence also
    /// means there is no kernel route to the overlay, so we do NOT write /etc/hosts
    /// (names would resolve but not route) and `add_route` is a no-op.
    netstack: Option<Arc<NetstackTun>>,
}

impl L3 {
    /// Start the overlay. In CRYPTO mode (`identity` set) the endpoint takes this
    /// node's derived `<addr>/128` and the whole overlay prefix routes to it; in
    /// manual mode `cidr` is used verbatim (PSK/lab). `mode` picks the packet
    /// endpoint: Kernel needs CAP_NET_ADMIN; Userspace needs none; Auto tries the
    /// kernel TUN and silently falls back to the userspace netstack if it can't be
    /// created (no cap, no /dev/net/tun, container without `ip`, locked netns).
    /// `FILAMENT_L3_USERSPACE=1` forces Userspace regardless of `mode`.
    pub fn start(cidr: &str, mtu: u32, identity: Option<Identity>, mode: L3Mode) -> Result<Arc<L3>> {
        cidr.split('/')
            .next()
            .and_then(|a| a.parse::<IpAddr>().ok())
            .ok_or_else(|| anyhow!("bad overlay address '{cidr}', want IP/PREFIX"))?;
        let mode = if std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1") {
            L3Mode::Userspace
        } else {
            mode
        };
        let crypto = identity.is_some();
        // This node's v4 overlay address (crypto mode), derived from its identity key.
        // Passed to the kernel path so the TUN also carries our v4 address + route.
        let my_v4 = identity.as_ref().map(|id| id.addr_v4());
        // Keep the concrete NetstackTun (for bind/dial) AND the dyn handle (for the
        // datagram pumps) when userspace; `None` netstack == kernel TUN.
        let v4_cidr = my_v4.map(|v4| format!("{v4}/32"));
        let open_netstack = || -> Result<(Arc<dyn TunDevice>, Option<Arc<NetstackTun>>)> {
            let ns = Arc::new(NetstackTun::open_dual(
                IFNAME,
                cidr,
                v4_cidr.as_deref(),
                mtu,
            )?);
            Ok((ns.clone() as Arc<dyn TunDevice>, Some(ns)))
        };
        let (tun, netstack): (Arc<dyn TunDevice>, Option<Arc<NetstackTun>>) = match mode {
            L3Mode::Userspace => open_netstack()?,
            L3Mode::Kernel => (open_kernel(cidr, mtu, crypto, my_v4)?, None),
            L3Mode::Auto => match open_kernel(cidr, mtu, crypto, my_v4) {
                Ok(t) => (t, None),
                Err(e) => {
                    crate::ui::say(&format!(
                        "  {} no kernel TUN ({e}); using the userspace overlay (zero privilege)",
                        crate::ui::paint(crate::ui::Tone::Brand, "●")
                    ));
                    open_netstack()?
                }
            },
        };
        let userspace = netstack.is_some();
        let routes: Arc<Mutex<HashMap<IpAddr, Arc<dyn Transport>>>> = Arc::new(Mutex::new(HashMap::new()));
        let l3 = Arc::new(L3 {
            tun: tun.clone(),
            routes: routes.clone(),
            readers: Mutex::new(HashMap::new()),
            by_pid: Mutex::new(HashMap::new()),
            identity,
            seq: AtomicU64::new(1),
            names: Mutex::new(HashMap::new()),
            netstack,
        });
        // Clear any stale MagicDNS block from a previous run - but only in kernel
        // mode; the userspace path never writes /etc/hosts (see `userspace`).
        if !userspace {
            let _ = rewrite_hosts_block(&[]);
        }

        // TUN -> datagram: one reader for the whole node. Each packet's dest IP
        // selects the peer link (cryptokey-routing style). A miss (no route) or a
        // send error is a silent drop, correct for a lossy datagram plane.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(_) => break, // TUN closed -> daemon shutting down
                };
                let Some(dst) = dest_ip(&buf[..n]) else { continue };
                let peer = routes.lock().await.get(&dst).cloned();
                if let Some(t) = peer {
                    let _ = t.send_datagram(&buf[..n]);
                }
            }
        });
        Ok(l3)
    }

    /// This node's overlay address (crypto mode only).
    pub fn my_addr(&self) -> Option<Ipv6Addr> {
        self.identity.as_ref().map(|i| i.addr())
    }

    /// This node's dual-stack IPv4 overlay address (crypto mode only), key-derived
    /// in the reserved 198.18.0.0/15 range.
    pub fn my_addr_v4(&self) -> Option<std::net::Ipv4Addr> {
        self.identity.as_ref().map(|i| i.addr_v4())
    }

    /// True when running on the userspace netstack (no kernel TUN / no privilege).
    /// Callers use this to warn that host firewalling is bypassed and that native
    /// tools need the proxy/dial to reach `<peer>.mesh`.
    pub fn is_userspace(&self) -> bool {
        self.netstack.is_some()
    }

    /// Access the overlay identity (crypto mode only).
    pub fn identity_ref(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Insert a name entry into the MagicDNS table (for self-registration).
    pub async fn names_insert(&self, pid: &str, name: &str, v6: Ipv6Addr, v4: Option<Ipv4Addr>) {
        self.names.lock().await.insert(pid.to_string(), (name.to_string(), v6, v4));
    }

    /// Dial `dst:port` over the overlay, in BOTH modes: a kernel `TcpStream`
    /// (routed via filament0) or an in-process smoltcp connection. This is what lets
    /// a node reach a peer's OVERLAY-exposed service (an `expose` bound on the
    /// overlay IP, which an L2 loopback open cannot reach) - and the ONLY way a
    /// userspace node (no kernel route) reaches `<peer>.mesh:port` at all.
    pub async fn dial(&self, dst: Ipv6Addr, port: u16) -> Result<OverlayStream> {
        match &self.netstack {
            Some(ns) => Ok(OverlayStream::Netstack(ns.dial(dst, port).await?)),
            None => {
                let s = tokio::net::TcpStream::connect(std::net::SocketAddr::new(IpAddr::V6(dst), port)).await?;
                Ok(OverlayStream::Kernel(s))
            }
        }
    }

    /// Listen on `port` on this node's overlay address, returning an endpoint that
    /// works in BOTH modes: a kernel `TcpListener` bound to the overlay IP, or a
    /// userspace smoltcp listener. `expose` rides this so it is TUN-free.
    pub async fn bind(&self, port: u16) -> Result<OverlayListener> {
        match &self.netstack {
            Some(ns) => Ok(OverlayListener::Netstack(ns.listen(port).await?)),
            None => {
                let addr = self.my_addr().ok_or_else(|| anyhow!("L3 overlay address not set"))?;
                let l = tokio::net::TcpListener::bind(std::net::SocketAddr::new(IpAddr::V6(addr), port)).await?;
                Ok(OverlayListener::Kernel(l))
            }
        }
    }

    /// True if `addr` is a currently-routed (verified) peer on the overlay. Any
    /// datagram on filament0 already came from a paired peer, so this is the
    /// membership check the expose allowlist builds on.
    pub async fn is_verified_peer(&self, addr: IpAddr) -> bool {
        self.routes.lock().await.contains_key(&addr)
    }

    /// Reverse MagicDNS: the petname of a verified peer by overlay address, so an
    /// `expose --peer` allowlist can match an incoming connection's source.
    pub async fn petname_of(&self, addr: IpAddr) -> Option<String> {
        self.names.lock().await.values().find(|(n, v6, v4)| {
            matches!(addr, IpAddr::V6(a) if a == *v6)
                || matches!(addr, IpAddr::V4(a) if v4.map_or(false, |v| a == v))
        }).map(|(n, _, _)| n.clone())
    }

    /// Resolve a verified peer's petname to its overlay address (the inverse of
    /// `petname_of`). The daemon uses this so a `dial` targets an address DERIVED
    /// from a paired identity, never one the client asserts.
    pub async fn addr_of(&self, name: &str) -> Option<Ipv6Addr> {
        let name = sanitize_host(name);
        self.names.lock().await.values().find(|(n, _, _)| *n == name).map(|(_, a, _)| *a)
    }

    /// Resolve a verified peer's petname to its v4 overlay address (if dual-stack).
    pub async fn addr_v4_of(&self, name: &str) -> Option<Ipv4Addr> {
        let name = sanitize_host(name);
        self.names.lock().await.values().find(|(n, _, _)| *n == name).and_then(|(_, _, a)| *a)
    }

    /// Build a signed announce of our address bound to link channel-binding `cb`.
    /// `None` in manual mode (no identity to sign with).
    pub fn make_announce(&self, cb: &[u8]) -> Option<Announce> {
        let id = self.identity.as_ref()?;
        Some(id.announce(self.seq.fetch_add(1, Ordering::Relaxed), cb))
    }

    /// Attach a VERIFIED peer to the overlay: route its overlay addresses (already
    /// checked to match the announcing key + link, see main.rs) to `t`, keyed by
    /// `pid` so a link drop can retract them, and register `petname` for MagicDNS.
    /// `peer_ip` is the v6 ULA (always); `peer_ip_v4` is the peer's v4 address in
    /// dual-stack mode (both derive from the same verified key). Both families point
    /// at ONE transport with ONE datagram pump. Aborts any prior pump for this pid,
    /// so a repair/supersede never leaks the old reader or its connection (fix #2).
    /// Skips links that can't carry datagrams.
    pub async fn add_peer(
        &self,
        pid: &str,
        petname: &str,
        peer_ip: IpAddr,
        peer_ip_v4: Option<IpAddr>,
        t: Arc<dyn Transport>,
    ) {
        if !t.supports_datagrams() {
            return;
        }
        // Every overlay address this peer answers to (v6 always; v4 in dual-stack).
        let mut ips = vec![peer_ip];
        if let Some(v4) = peer_ip_v4 {
            if !ips.contains(&v4) {
                ips.push(v4);
            }
        }
        // Retire any address a prior incarnation of this pid installed that is no
        // longer ours to serve (its overlay IP may have changed across a re-key).
        if let Some(old) = self.by_pid.lock().await.insert(pid.to_string(), ips.clone()) {
            for ip in old {
                if !ips.contains(&ip) {
                    self.retract_route(ip).await;
                }
            }
        }
        // MagicDNS: record <petname> -> v6 addr (+ v4 if dual-stack) and refresh /etc/hosts.
        if let IpAddr::V6(v6) = peer_ip {
            let v4 = peer_ip_v4.and_then(|ip| match ip {
                IpAddr::V4(a) => Some(a),
                _ => None,
            });
            self.names.lock().await.insert(pid.to_string(), (sanitize_host(petname), v6, v4));
            self.refresh_hosts().await;
        }
        // ONE datagram->TUN pump per link (a peer's datagrams carry both families;
        // the pump just forwards each packet to the TUN, which demuxes by dest).
        let tun = self.tun.clone();
        let t_reader = t.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = t_reader.recv_datagram() => match r {
                        Ok(pkt) => { let _ = tun.send(&pkt).await; }
                        Err(_) => break, // link closed
                    },
                    // Wake periodically so a zombie link (alive at QUIC but dead
                    // for datagrams) is noticed even if read_datagram never errors.
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        if !t_reader.is_alive() { break; }
                    }
                }
            }
            // CONTINUITY: on transport death we do NOT retract the routes. The
            // overlay IPs stay in the table pointing at the (now dead) transport,
            // so datagrams merely drop (the inner TCP pauses, like WireGuard) until
            // the peer's repair calls add_peer, which atomically SWAPS in the fresh
            // transport (aborting this finished pump). Retracting here would open a
            // routability gap that can reset a live session across a link repair.
        });
        if let Some(old) = self.readers.lock().await.insert(pid.to_string(), handle.abort_handle()) {
            old.abort(); // stop the superseded pump now
        }
        // Install/replace every route for this peer, all pointing at the fresh transport.
        let mut map = self.routes.lock().await;
        for ip in &ips {
            map.insert(*ip, t.clone());
        }
    }

    /// Drop the route for a specific overlay IP. The datagram pump is keyed by pid,
    /// not by IP, so it is aborted separately (add_peer supersede / remove_by_pid).
    async fn retract_route(&self, ip: IpAddr) {
        self.routes.lock().await.remove(&ip);
    }

    /// Retract every route a link (by pid) installed and abort its pump. NOT called
    /// on a transient link drop (that would break continuity across a repair);
    /// reserved for an explicit device-forget path. Kept for that use.
    #[allow(dead_code)]
    pub async fn remove_by_pid(&self, pid: &str) {
        if let Some(ips) = self.by_pid.lock().await.remove(pid) {
            let mut map = self.routes.lock().await;
            for ip in ips {
                map.remove(&ip);
            }
        }
        if let Some(r) = self.readers.lock().await.remove(pid) {
            r.abort();
        }
        if self.names.lock().await.remove(pid).is_some() {
            self.refresh_hosts().await;
        }
    }

    /// Rewrite the managed /etc/hosts block from the current verified names so
    /// native tools resolve `<petname>` and `<petname>.mesh`. Best-effort: a
    /// non-root daemon (or read-only /etc/hosts) just skips it and the overlay
    /// still works by IP.
    /// Refresh the managed /etc/hosts block from the current verified names so
    /// native tools resolve `<petname>` and `<petname>.mesh`. Best-effort: a
    /// non-root daemon (or read-only /etc/hosts) just skips it and the overlay
    /// still works by IP.
    pub async fn refresh_hosts(&self) {
        // Userspace mode has no kernel route to the overlay, so a resolved
        // `<peer>.mesh` would point at an unroutable IP (worse than not resolving);
        // skip /etc/hosts entirely and let dial/proxy resolve names in-process.
        if self.netstack.is_some() {
            return;
        }
        let entries: Vec<(String, Ipv6Addr, Option<Ipv4Addr>)> = self
            .names
            .lock()
            .await
            .values()
            .map(|(n, v6, v4)| (n.clone(), *v6, *v4))
            .collect();
        if let Err(e) = rewrite_hosts_block(&entries) {
            crate::ui::debug(&format!("  MagicDNS: /etc/hosts not updated ({e}); overlay still works by IP"));
        }
    }
}

/// Open the KERNEL TUN end to end: create the device AND install the overlay-prefix
/// route (crypto mode). Both steps can fail in a container (no cap, no /dev/net/tun,
/// no `ip`, locked netns); doing them together lets `L3Mode::Auto` catch ANY failure
/// and fall back to the userspace netstack instead of dropping off the overlay.
#[cfg(l3)]
fn open_kernel(
    cidr: &str,
    mtu: u32,
    crypto: bool,
    addr_v4: Option<std::net::Ipv4Addr>,
) -> Result<Arc<dyn TunDevice>> {
    let tun: Arc<dyn TunDevice> = Arc::new(KernelTun::open(IFNAME, cidr, mtu)?);
    // Route by the device's ACTUAL name: Linux honors `filament0`, but macOS assigns
    // `utunN` (utun devices can't be renamed). Crypto mode scatters /128s across the
    // shared ULA prefix, so route the whole prefix to the TUN (userspace demuxes).
    if crypto {
        let name = tun.name().to_string();
        crate::tun::add_route(&crate::overlay::prefix_cidr(), &name)?;
        // Dual-stack v4 is ADDITIVE and BEST-EFFORT. The v6 ULA is the load-bearing,
        // self-certifying stack; a v4 quirk on any platform must never knock a working
        // overlay off the kernel path (that would force a needless userspace fallback).
        // So assign our v4 address + route the v4 prefix, logging on failure rather
        // than bailing. `add_addr` first so the /32 is local before the /15 is routed.
        if let Some(v4) = addr_v4 {
            if let Err(e) = crate::tun::add_addr(&format!("{v4}/32"), &name) {
                crate::ui::debug(&format!("  L3 v4 address not assigned ({e}); v6 overlay unaffected"));
            } else if let Err(e) = crate::tun::add_route(&crate::overlay::prefix_v4_cidr(), &name) {
                crate::ui::debug(&format!("  L3 v4 route not installed ({e}); v6 overlay unaffected"));
            }
        }
    }
    Ok(tun)
}

const HOSTS_BEGIN: &str = "# BEGIN filament-mesh (managed by filament; edits here are overwritten)";
const HOSTS_END: &str = "# END filament-mesh";

/// Get this machine's hostname for MagicDNS.
pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "cli".into())
}

/// The OS hosts file for MagicDNS. Unix: /etc/hosts. Windows: the drivers\etc\hosts
/// under %SystemRoot% (default C:\Windows), which the resolver consults like /etc/hosts.
fn hosts_path() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        std::path::PathBuf::from(root).join("System32\\drivers\\etc\\hosts")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// Replace the filament-mesh managed block in /etc/hosts with `entries`
/// (`<addr> <name>.mesh` per peer, both AAAA and A records). Atomic via
/// temp-file + rename. An empty `entries` removes the block. Names are
/// display-only; routing is always by the cryptographically-verified address.
pub(crate) fn sanitize_host(name: &str) -> String {
    // If name contains @, extract just the hostname part (user@host → host)
    let base = name.split('@').last().unwrap_or(name);
    let s: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect();
    s.trim_matches('-').to_string()
}

fn rewrite_hosts_block(entries: &[(String, Ipv6Addr, Option<Ipv4Addr>)]) -> std::io::Result<()> {
    let path = hosts_path();
    let cur = std::fs::read_to_string(&path).unwrap_or_default();
    let out = render_hosts(&cur, entries);
    // Preferred: atomic sibling-temp + rename (crash-safe), which needs write on
    // the hosts DIRECTORY (root/Administrator). Fallback for a non-root daemon that
    // only has a per-file ACL on the hosts file: a single-shot in-place truncating
    // write, which needs write on the file alone. The in-place path writes the whole
    // buffer in one std::fs::write so the corruption window is one syscall.
    let tmp = path.with_extension("filament.tmp");
    match std::fs::write(&tmp, &out).and_then(|()| std::fs::rename(&tmp, &path)) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = std::fs::remove_file(&tmp);
            std::fs::write(&path, out)
        }
    }
}

/// Pure transform: strip any prior filament-mesh block from `current`, then append
/// a fresh one for `entries` (none => block removed). Non-filament lines are kept
/// verbatim, so we never clobber the user's /etc/hosts.
fn render_hosts(current: &str, entries: &[(String, Ipv6Addr, Option<Ipv4Addr>)]) -> String {
    let mut out = String::with_capacity(current.len() + 256);
    let mut in_block = false;
    for line in current.lines() {
        let t = line.trim_start();
        if t.starts_with("# BEGIN filament-mesh") {
            in_block = true;
            continue;
        }
        if in_block {
            if t.starts_with(HOSTS_END) {
                in_block = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // Dedup exact (name, v6_addr) pairs: the names table is keyed per-link, so a
    // peer that reconnected under several link ids can appear more than once and
    // would otherwise emit duplicate /etc/hosts lines.
    let mut seen = std::collections::HashSet::new();
    let live: Vec<&(String, Ipv6Addr, Option<Ipv4Addr>)> = entries
        .iter()
        .filter(|(n, _, _)| is_safe_mesh_name(n))
        .filter(|(n, v6, _)| seen.insert((n.clone(), *v6)))
        .collect();
    if !live.is_empty() {
        out.push_str(HOSTS_BEGIN);
        out.push('\n');
        for (name, v6, v4) in live {
            // AAAA record: the v6 overlay address (always present).
            // ONLY the namespaced `<name>.mesh` is emitted, never a bare `<name>`:
            // a bare entry could shadow a real hostname (localhost, an internal
            // host, a public domain). Under the reserved `.mesh` suffix a peer
            // name can never collide with real resolution. (Security: DNS-hijack
            // hardening; the petname is the locally-assigned one, but this holds
            // even if a name is ever influenced by the peer.)
            out.push_str(&format!("{v6} {name}.mesh\n"));
            // A record: the v4 overlay address (dual-stack only). Same .mesh
            // suffix so both families resolve to the same name.
            if let Some(v4) = v4 {
                out.push_str(&format!("{v4} {name}.mesh\n"));
            }
        }
        out.push_str(HOSTS_END);
        out.push('\n');
    }
    out
}

/// Reject empty or reserved labels so a mesh name can never map to something
/// load-bearing even under `.mesh` (defense in depth beyond the `.mesh` suffix).
fn is_safe_mesh_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    !matches!(name.to_ascii_lowercase().as_str(), "localhost" | "localhost4" | "localhost6")
}

/// Standalone point-to-point serve_tun (no signaling): open `dev` with `tun_addr`
/// and pump IP packets both ways over an already-authenticated QUIC connection's
/// datagrams. Runs until the link or TUN closes. Backs `filament serve-tun` and
/// the lab's filament-l3 carrier (WireGuard-style known-endpoint overlay).
pub async fn run_point_to_point(
    conn: quinn::Connection,
    dev: &str,
    tun_addr: &str,
    mtu: u32,
) -> Result<()> {
    let tun: Arc<dyn TunDevice> = Arc::new(KernelTun::open(dev, tun_addr, mtu)?);
    // datagram -> TUN (background)
    let c = conn.clone();
    let t = tun.clone();
    let down = tokio::spawn(async move {
        while let Ok(pkt) = c.read_datagram().await {
            let _ = t.send(&pkt).await;
        }
    });
    // TUN -> datagram (this task). Select against conn.closed() so a peer that
    // drops while our TUN is idle ends the pump promptly, instead of parking in
    // tun.recv() forever (the process would otherwise hang holding filament0).
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = conn.closed() => break,
            r = tun.recv(&mut buf) => {
                let n = match r {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        down.abort();
                        return Err(e);
                    }
                };
                // A too-big packet errors (over the datagram MTU) and is dropped;
                // a closed link ends the pump.
                if conn.send_datagram(bytes::Bytes::copy_from_slice(&buf[..n])).is_err()
                    && conn.close_reason().is_some()
                {
                    break;
                }
            }
        }
    }
    down.abort();
    Ok(())
}

/// Destination IP of a raw IP packet (v4 header dst at [16..20], v6 at [24..40]).
/// `None` for a truncated or non-IP frame.
fn dest_ip(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]])),
        6 if pkt.len() >= 40 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::from(a))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{dest_ip, render_hosts, sanitize_host};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn magicdns_block_roundtrips_without_clobbering() {
        let base = "127.0.0.1 localhost\n::1 localhost\n";
        let a: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        let with = render_hosts(base, &[("other-do".into(), a, None)]);
        // user lines preserved, managed block added with the NAMESPACED name only
        assert!(with.contains("127.0.0.1 localhost"));
        assert!(with.contains(&format!("{a} other-do.mesh")));
        // never a bare hostname (would shadow real names); never `localhost`
        assert!(!with.contains(&format!("{a} other-do.mesh other-do")));
        assert!(!with.lines().any(|l| l.trim() == format!("{a} other-do")));
        assert!(with.contains("# BEGIN filament-mesh"));
        // re-rendering replaces (not stacks) the block, and empty removes it
        let again = render_hosts(&with, &[("other-do".into(), a, None)]);
        assert_eq!(again.matches("# BEGIN filament-mesh").count(), 1);
        let cleared = render_hosts(&again, &[]);
        assert!(!cleared.contains("filament-mesh"));
        assert!(cleared.contains("127.0.0.1 localhost"));
    }

    #[test]
    fn hostnames_are_sanitized() {
        assert_eq!(sanitize_host("other-do"), "other-do");
        assert_eq!(sanitize_host("user@cli"), "cli");  // strips user@ prefix
        assert_eq!(sanitize_host("a b/c"), "a-b-c");
    }

    #[test]
    fn reserved_and_empty_names_are_dropped() {
        use super::is_safe_mesh_name;
        assert!(!is_safe_mesh_name(""));
        assert!(!is_safe_mesh_name("localhost"));
        assert!(!is_safe_mesh_name("LocalHost"));
        assert!(is_safe_mesh_name("other-do"));
        // a peer named "localhost" is skipped entirely (no localhost.mesh either)
        let a: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        assert!(!render_hosts("", &[("localhost".into(), a, None)]).contains("filament-mesh"));
    }

    #[test]
    fn parses_ipv4_dest() {
        // minimal IPv4 header: version/IHL=0x45, dst=10.9.0.2 at bytes 16..20
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[10, 9, 0, 2]);
        assert_eq!(dest_ip(&p), Some(IpAddr::from([10, 9, 0, 2])));
    }

    #[test]
    fn parses_ipv6_dest() {
        let mut p = [0u8; 40];
        p[0] = 0x60;
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        p[24..40].copy_from_slice(&dst);
        assert_eq!(dest_ip(&p), Some(IpAddr::from(dst)));
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        assert_eq!(dest_ip(&[]), None);
        assert_eq!(dest_ip(&[0x45, 0, 0]), None); // too short for v4
        assert_eq!(dest_ip(&[0x70, 0, 0, 0]), None); // not v4/v6
    }

    // A transport that carries datagrams but never delivers one, so add_peer's pump
    // parks; we only inspect the route/reader bookkeeping it leaves behind.
    struct DgramTransport;
    #[async_trait::async_trait]
    impl super::Transport for DgramTransport {
        async fn send_control(&self, _m: &serde_json::Value) -> super::Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _p: &[u8]) -> super::Result<()> {
            Ok(())
        }
        async fn flush(&self) -> super::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1200
        }
        fn supports_datagrams(&self) -> bool {
            true
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn send_datagram(&self, _p: &[u8]) -> super::Result<()> {
            Ok(())
        }
        async fn recv_datagram(&self) -> super::Result<bytes::Bytes> {
            std::future::pending().await
        }
    }

    // Build an L3 backed by the userspace netstack (no privilege, and refresh_hosts
    // early-returns so the test never touches /etc/hosts). Routing bookkeeping is the
    // same in kernel and userspace mode - it is just a HashMap keyed by dest IP.
    fn test_l3() -> std::sync::Arc<super::L3> {
        use super::*;
        let ns = std::sync::Arc::new(NetstackTun::open(IFNAME, "fdf1:1af7:c30d::1/128", 1280).unwrap());
        std::sync::Arc::new(L3 {
            tun: ns.clone() as std::sync::Arc<dyn TunDevice>,
            routes: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            readers: tokio::sync::Mutex::new(HashMap::new()),
            by_pid: tokio::sync::Mutex::new(HashMap::new()),
            identity: None,
            seq: std::sync::atomic::AtomicU64::new(1),
            names: tokio::sync::Mutex::new(HashMap::new()),
            netstack: Some(ns),
        })
    }

    #[tokio::test]
    async fn dual_stack_add_peer_routes_both_families_and_retracts() {
        use super::Transport;
        let l3 = test_l3();
        let v6: IpAddr = "fdf1:1af7:c30d::1".parse().unwrap();
        let v4: IpAddr = "198.18.5.6".parse().unwrap();
        let t: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);

        // A verified dual-stack peer installs BOTH families, one pump for the link.
        l3.add_peer("pidA", "alice", v6, Some(v4), t.clone()).await;
        {
            let map = l3.routes.lock().await;
            assert!(map.contains_key(&v6), "v6 route installed");
            assert!(map.contains_key(&v4), "v4 route installed");
        }
        assert_eq!(l3.readers.lock().await.len(), 1, "exactly one pump per link");

        // Re-key: the same link now announces a different v6+v4; the old pair is
        // retracted and only the new pair remains, still one pump.
        let v6b: IpAddr = "fdf1:1af7:c30d::2".parse().unwrap();
        let v4b: IpAddr = "198.18.9.9".parse().unwrap();
        l3.add_peer("pidA", "alice", v6b, Some(v4b), t.clone()).await;
        {
            let map = l3.routes.lock().await;
            assert!(!map.contains_key(&v6) && !map.contains_key(&v4), "stale pair retracted on re-key");
            assert!(map.contains_key(&v6b) && map.contains_key(&v4b), "new pair installed");
            assert_eq!(map.len(), 2, "no leaked routes");
        }
        assert_eq!(l3.readers.lock().await.len(), 1, "still one pump after supersede");

        // Explicit forget drops every route and the pump for that link.
        l3.remove_by_pid("pidA").await;
        assert!(l3.routes.lock().await.is_empty(), "all routes gone");
        assert!(l3.readers.lock().await.is_empty(), "pump aborted");
    }

    #[test]
    fn magicdns_emits_both_a_and_aaaa_records() {
        let base = "127.0.0.1 localhost\n";
        let v6: Ipv6Addr = "fdf1:1af7:c30d:1a1::99aa".parse().unwrap();
        let v4: Ipv4Addr = "198.18.5.6".parse().unwrap();
        let out = render_hosts(base, &[("peer-one".into(), v6, Some(v4))]);
        // Both AAAA (v6) and A (v4) records present
        assert!(out.contains(&format!("{v6} peer-one.mesh")), "AAAA record present");
        assert!(out.contains(&format!("{v4} peer-one.mesh")), "A record present");
        // v6-only peer: no A record emitted
        let v6b: Ipv6Addr = "fdf1:1af7:c30d:2b2::bb".parse().unwrap();
        let out2 = render_hosts(base, &[("v6-only".into(), v6b, None)]);
        assert!(out2.contains(&format!("{v6b} v6-only.mesh")), "AAAA record present");
        assert!(!out2.contains("v6-only.mesh") || out2.lines().filter(|l| l.contains("v6-only.mesh")).count() == 1, "no duplicate A record for v6-only peer");
    }

    #[test]
    fn magicdns_dual_stack_add_peer_registers_v4_in_names() {
        use super::Transport;
        // Use a userspace-backed L3 so refresh_hosts is a no-op (avoids /etc/hosts)
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            let v6: IpAddr = "fdf1:1af7:c30d::1".parse().unwrap();
            let v4: IpAddr = "198.18.5.6".parse().unwrap();
            let t: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            l3.add_peer("pidA", "alice", v6, Some(v4), t).await;
            // petname_of matches both v6 and v4
            assert_eq!(l3.petname_of(v6).await.as_deref(), Some("alice"));
            assert_eq!(l3.petname_of(v4).await.as_deref(), Some("alice"));
            // addr_of returns v6; addr_v4_of returns v4
            assert_eq!(l3.addr_of("alice").await, Some("fdf1:1af7:c30d::1".parse().unwrap()));
            assert_eq!(l3.addr_v4_of("alice").await, Some("198.18.5.6".parse().unwrap()));
            // v6-only peer: addr_v4_of returns None
            let v6b: IpAddr = "fdf1:1af7:c30d::2".parse().unwrap();
            let t2: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            l3.add_peer("pidB", "bob", v6b, None, t2).await;
            assert_eq!(l3.addr_v4_of("bob").await, None);
        });
    }

    #[test]
    fn magicdns_same_name_different_peers_both_emitted() {
        use super::Transport;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            // Two peers with the same petname "host1" but different addresses
            let v6a: IpAddr = "fdf1:1af7:c30d::aa".parse().unwrap();
            let v4a: IpAddr = "198.18.1.1".parse().unwrap();
            let v6b: IpAddr = "fdf1:1af7:c30d::bb".parse().unwrap();
            let v4b: IpAddr = "198.18.2.2".parse().unwrap();
            let ta: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            let tb: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            // Both registered under same name, different pids
            l3.add_peer("pidA", "host1", v6a, Some(v4a), ta).await;
            l3.add_peer("pidB", "host1", v6b, Some(v4b), tb).await;
            // Both addresses are routable
            assert!(l3.is_verified_peer(v6a).await);
            assert!(l3.is_verified_peer(v6b).await);
            assert!(l3.is_verified_peer(v4a).await);
            assert!(l3.is_verified_peer(v4b).await);
            // petname_of returns one of them (which one is implementation-defined)
            let found = l3.petname_of(v6a).await;
            assert!(found.is_some(), "petname_of must return a result for known peer");
            // render_hosts emits both entries (DNS round-robin)
            let base = "";
            let entries: Vec<(String, std::net::Ipv6Addr, Option<std::net::Ipv4Addr>)> = vec![
                ("host1".into(), "fdf1:1af7:c30d::aa".parse().unwrap(), Some("198.18.1.1".parse().unwrap())),
                ("host1".into(), "fdf1:1af7:c30d::bb".parse().unwrap(), Some("198.18.2.2".parse().unwrap())),
            ];
            let out = render_hosts(base, &entries);
            // Both v6 addresses should appear as host1.mesh
            assert!(out.contains("fdf1:1af7:c30d::aa host1.mesh"));
            assert!(out.contains("fdf1:1af7:c30d::bb host1.mesh"));
            // Both v4 addresses should appear as host1.mesh
            assert!(out.contains("198.18.1.1 host1.mesh"));
            assert!(out.contains("198.18.2.2 host1.mesh"));
        });
    }

    #[test]
    fn magicdns_case_insensitive_collision() {
        // "Host1" and "host1" should collide after sanitization
        use super::Transport;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let l3 = test_l3();
            let v6a: IpAddr = "fdf1:1af7:c30d::aa".parse().unwrap();
            let v6b: IpAddr = "fdf1:1af7:c30d::bb".parse().unwrap();
            let ta: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            let tb: std::sync::Arc<dyn Transport> = std::sync::Arc::new(DgramTransport);
            // Different case names
            l3.add_peer("pidA", "Host1", v6a, None, ta).await;
            l3.add_peer("pidB", "host1", v6b, None, tb).await;
            // Both are routable
            assert!(l3.is_verified_peer(v6a).await);
            assert!(l3.is_verified_peer(v6b).await);
            // render_hosts deduplicates by (sanitized_name, v6) - different v6 means both emitted
            let entries: Vec<(String, std::net::Ipv6Addr, Option<std::net::Ipv4Addr>)> = vec![
                ("host1".into(), "fdf1:1af7:c30d::aa".parse().unwrap(), None),
                ("host1".into(), "fdf1:1af7:c30d::bb".parse().unwrap(), None),
            ];
            let out = render_hosts("", &entries);
            assert!(out.contains("fdf1:1af7:c30d::aa host1.mesh"));
            assert!(out.contains("fdf1:1af7:c30d::bb host1.mesh"));
        });
    }

    #[tokio::test]
    async fn l3_start_with_ipv4() {
        use super::*;
        let identity = Identity::load_or_create().unwrap();
        let expected_v4 = identity.addr_v4();
        let cidr = format!("{}/128", identity.addr());
        let l3 = L3::start(&cidr, 1280, Some(identity), L3Mode::Userspace).unwrap();
        assert!(l3.is_userspace(), "should be userspace mode");
        assert_eq!(l3.my_addr_v4(), Some(expected_v4), "v4 address from identity");
        // The netstack should be dual-stack when v4 is available
        let ns = l3.netstack.as_ref().unwrap();
        assert!(ns.is_dual_stack(), "netstack should be dual-stack with v4 CIDR");
    }
}
