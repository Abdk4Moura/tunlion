//! TURN over TCP and TLS for the CLI's WebRTC stack.
//!
//! `/api/config` hands out `turn:` (UDP), `turn:...?transport=tcp` and
//! `turns:` (TLS) relay URLs. The browser uses all of them. webrtc-ice 0.17
//! gathers a relay candidate ONLY for `turn:` over UDP: the TCP and TLS cases in
//! `gather_candidates_relay` are a commented-out TODO, and the webrtc 0.21
//! rewrite still skips every non-UDP TURN URL. So on a network that blocks UDP
//! the CLI had no relay at all and failed where a browser succeeded.
//!
//! TURN over TCP or TLS is the SAME protocol on a byte stream (RFC 8656 §6.2):
//! STUN messages are self-delimiting, ChannelData is padded to four bytes, and
//! the allocation on the server is still a UDP relay. So instead of forking
//! webrtc-ice, each TCP/TLS URL becomes a loopback UDP endpoint:
//!
//! ```text
//!   webrtc-ice turn client --UDP--> 127.0.0.1:P (bridge) ==TCP or TLS==> TURN server
//! ```
//!
//! and webrtc-ice is handed `turn:127.0.0.1:P` with the same credentials. The
//! bridge never sees or needs the credentials; it moves frames. The candidate
//! the peer receives is an ordinary relay candidate on the TURN server, so the
//! browser and older CLIs see nothing new on the wire.
//!
//! # Order: UDP, then TCP, then TLS
//!
//! webrtc-ice gives every relay candidate the same priority, so if all three
//! allocated, ICE could pick a TCP relay where a UDP one works. A bridge
//! therefore HOLDS its client's first packets and decides from what has
//! actually been gathered, never from a probe of its own:
//!
//! - a UDP relay candidate appears: TCP and TLS refuse (fast `403`), so the
//!   UDP case costs nothing but a few loopback datagrams;
//! - no UDP relay within [`TCP_AFTER`]: TCP proceeds;
//! - a TCP relay candidate appears: TLS refuses;
//! - every TCP server failed to connect, or [`TLS_AFTER_TCP`] more passed: TLS
//!   proceeds (443 is the port that survives the strictest networks).
//!
//! The clock starts at the first packet any bridge sees, which is when ICE
//! started gathering relays (it gathers every relay URL at once).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use webrtc::ice::url::{ProtoType, SchemeType, Url};
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;
use webrtc::ice_transport::ice_server::RTCIceServer;

/// How long TCP waits for a UDP relay candidate before allocating itself. A UDP
/// allocation is two round trips to the TURN server (401 challenge, then the
/// authenticated Allocate), well under this on any network UDP works on.
pub const TCP_AFTER: Duration = Duration::from_millis(1500);
/// How much longer TLS waits for a TCP relay candidate, unless every TCP server
/// already failed to connect (then it goes at once).
pub const TLS_AFTER_TCP: Duration = Duration::from_millis(1500);
/// Bound on one TCP connect plus TLS handshake to a TURN server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A session with no packet from its client for this long is finished. A live
/// TURN client refreshes its allocation and permissions every few minutes.
const IDLE: Duration = Duration::from_secs(15 * 60);
/// Packets held per session while it waits for its turn.
const HOLD_MAX: usize = 32;
/// Kernel send buffer for a bridge's TCP socket, and the packets queued ahead
/// of it. A stream never drops, so without a bound a sender faster than the
/// stream fills the socket buffer (autotuned to megabytes) and every packet on
/// the path, ICE consent checks included, waits seconds behind it: CI measured
/// exactly that on TLS 443, where the browser declared the path dead and
/// restarted ICE mid-transfer. Bounded, the excess is dropped as it would be on
/// a UDP relay, and SCTP congestion control backs off. 128 KiB (the kernel
/// doubles it) still allows ~2.5 MB/s at 100 ms to the TURN server.
const STREAM_SNDBUF: u32 = 128 * 1024;
const SESSION_QUEUE: usize = 64;
/// Opt-out: `TUNLION_TURN_STREAM=0` hands webrtc-ice the config untouched (TCP
/// and TLS URLs are then ignored again, as before this bridge existed).
pub const DISABLE_ENV: &str = "TUNLION_TURN_STREAM";

/// The byte stream a bridge carries TURN over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    Tcp,
    Tls,
}

impl StreamKind {
    pub fn label(self) -> &'static str {
        match self {
            StreamKind::Tcp => "tcp",
            StreamKind::Tls => "tls",
        }
    }
}

/// A TURN server reached over a stream.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Upstream {
    pub kind: StreamKind,
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TURN over {} to {}:{}", self.kind.label(), self.host, self.port)
    }
}

/// Which bridge, if any, a URL needs. Parsed with webrtc-ice's own parser so the
/// decision matches how webrtc-ice would read the URL: `turn:` defaults to UDP
/// (left alone), `turns:` defaults to TCP. `turns:?transport=udp` (DTLS) and
/// anything unparsable are left alone too, exactly as unusable as before.
pub(crate) fn classify(url: &str) -> Option<Upstream> {
    let u = Url::parse_url(url.trim()).ok()?;
    let kind = match (u.scheme, u.proto) {
        (SchemeType::Turn, ProtoType::Tcp) => StreamKind::Tcp,
        (SchemeType::Turns, ProtoType::Tcp) => StreamKind::Tls,
        _ => return None,
    };
    Some(Upstream { kind, host: u.host, port: u.port })
}

/// True for a URL webrtc-ice itself turns into a relay candidate.
fn is_udp_turn(url: &str) -> bool {
    matches!(
        Url::parse_url(url.trim()),
        Ok(Url { scheme: SchemeType::Turn, proto: ProtoType::Udp, .. })
    )
}

// ------------------------------------------------------------------ gating --

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Hold packets, decide again after this long (or on a state change).
    Wait(Duration),
    Proceed,
    /// An earlier transport already produced a relay: refuse this one.
    Suppress,
}

/// What the gate decides from. Pure data so the ordering is unit-testable.
#[derive(Debug, Clone, Default)]
pub(crate) struct GateView {
    /// Since the first packet any bridge of this peer saw.
    pub elapsed: Duration,
    /// How long TCP waits for UDP: [`TCP_AFTER`], or zero when the config has
    /// no UDP TURN URL at all (nothing to wait for).
    pub udp_wait: Duration,
    pub udp_relay: bool,
    pub tcp_relay: bool,
    pub tcp_upstreams: usize,
    pub tcp_failed: usize,
}

pub(crate) fn gate(kind: StreamKind, v: &GateView) -> Gate {
    if v.udp_relay {
        return Gate::Suppress;
    }
    if v.elapsed < v.udp_wait {
        return Gate::Wait(v.udp_wait - v.elapsed);
    }
    match kind {
        StreamKind::Tcp => Gate::Proceed,
        StreamKind::Tls => {
            if v.tcp_relay {
                return Gate::Suppress;
            }
            if v.tcp_upstreams == 0 || v.tcp_failed >= v.tcp_upstreams {
                return Gate::Proceed;
            }
            let at = v.udp_wait + TLS_AFTER_TCP;
            if v.elapsed >= at {
                Gate::Proceed
            } else {
                Gate::Wait(at - v.elapsed)
            }
        }
    }
}

#[derive(Default)]
struct GateState {
    start: Option<Instant>,
    udp_relay: bool,
    tcp_relay: bool,
    tcp_failed: HashSet<Upstream>,
}

struct Shared {
    state: Mutex<GateState>,
    changed: watch::Sender<u64>,
    /// Client source port (the turn client's socket, which is also the relay
    /// candidate's related port) -> the stream that carries it.
    sources: Mutex<HashMap<u16, StreamKind>>,
    tcp_upstreams: usize,
    udp_wait: Duration,
}

impl Shared {
    fn view(&self) -> GateView {
        let st = self.state.lock().unwrap();
        GateView {
            elapsed: st.start.map(|s| s.elapsed()).unwrap_or_default(),
            udp_wait: self.udp_wait,
            udp_relay: st.udp_relay,
            tcp_relay: st.tcp_relay,
            tcp_upstreams: self.tcp_upstreams,
            tcp_failed: st.tcp_failed.len(),
        }
    }

    fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    fn register(&self, port: u16, kind: StreamKind) {
        self.sources.lock().unwrap().insert(port, kind);
        let mut st = self.state.lock().unwrap();
        if st.start.is_none() {
            st.start = Some(Instant::now());
        }
    }

    fn note_failed(&self, up: &Upstream) {
        if up.kind == StreamKind::Tcp {
            self.state.lock().unwrap().tcp_failed.insert(up.clone());
            self.bump();
        }
    }
}

// ----------------------------------------------------------------- bridges --

/// The bridges of one peer connection. Dropping it (or [`TurnBridges::shutdown`])
/// stops every listener and session.
pub struct TurnBridges {
    shared: Arc<Shared>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for TurnBridges {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl TurnBridges {
    pub fn shutdown(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    /// Feed every locally gathered candidate here (from `on_ice_candidate`):
    /// relay candidates are what the TCP/TLS gates decide from.
    pub fn note_candidate(&self, c: &RTCIceCandidate) {
        if c.typ != RTCIceCandidateType::Relay {
            return;
        }
        let kind = self.kind_for_port(c.related_port);
        {
            let mut st = self.shared.state.lock().unwrap();
            match kind {
                None => st.udp_relay = true,
                Some(StreamKind::Tcp) => st.tcp_relay = true,
                Some(StreamKind::Tls) => {}
            }
        }
        crate::hooks::debug(&format!(
            "tunlion: relay candidate {}:{} over {}",
            c.address,
            c.port,
            kind.map(StreamKind::label).unwrap_or("udp")
        ));
        self.shared.bump();
    }

    /// The stream under a relay candidate, by its related port. `None` means the
    /// candidate is not bridged: webrtc-ice's own UDP relay.
    pub fn kind_for_port(&self, related_port: u16) -> Option<StreamKind> {
        self.shared.sources.lock().unwrap().get(&related_port).copied()
    }
}

/// Rewrite `turn:?transport=tcp` and `turns:` URLs to loopback bridges. Returns
/// the config to hand webrtc-ice and the bridges to keep alive with the peer
/// connection (`None` when there was nothing to bridge or it is disabled).
pub async fn install(ice_servers: Vec<RTCIceServer>) -> (Vec<RTCIceServer>, Option<Arc<TurnBridges>>) {
    if std::env::var(DISABLE_ENV).map(|v| v == "0").unwrap_or(false) {
        return (ice_servers, None);
    }
    let mut wanted: Vec<Upstream> = Vec::new();
    for s in &ice_servers {
        for u in &s.urls {
            if let Some(up) = classify(u) {
                if !wanted.contains(&up) {
                    wanted.push(up);
                }
            }
        }
    }
    if wanted.is_empty() {
        return (ice_servers, None);
    }
    let has_udp_turn = ice_servers.iter().flat_map(|s| s.urls.iter()).any(|u| is_udp_turn(u));

    let mut sockets: HashMap<Upstream, (Arc<UdpSocket>, u16)> = HashMap::new();
    for up in &wanted {
        match UdpSocket::bind("127.0.0.1:0").await {
            Ok(sock) => {
                let port = match sock.local_addr() {
                    Ok(a) => a.port(),
                    Err(_) => continue,
                };
                sockets.insert(up.clone(), (Arc::new(sock), port));
            }
            Err(e) => crate::hooks::debug(&format!("tunlion: {up}: no loopback bridge ({e})")),
        }
    }
    let tcp_upstreams = sockets.keys().filter(|u| u.kind == StreamKind::Tcp).count();
    let (changed, _) = watch::channel(0u64);
    let shared = Arc::new(Shared {
        state: Mutex::new(GateState::default()),
        changed,
        sources: Mutex::new(HashMap::new()),
        tcp_upstreams,
        udp_wait: if has_udp_turn { TCP_AFTER } else { Duration::ZERO },
    });

    let out = ice_servers
        .into_iter()
        .map(|s| {
            let mut urls: Vec<String> = Vec::with_capacity(s.urls.len());
            for u in s.urls {
                let mapped = match classify(&u) {
                    None => u,
                    Some(up) => match sockets.get(&up) {
                        Some((_, port)) => format!("turn:127.0.0.1:{port}?transport=udp"),
                        // No bridge: keep the URL, webrtc-ice ignores it as before.
                        None => u,
                    },
                };
                if !urls.contains(&mapped) {
                    urls.push(mapped);
                }
            }
            RTCIceServer { urls, ..s }
        })
        .collect();

    let mut tasks = Vec::new();
    for (up, (sock, port)) in sockets {
        crate::hooks::debug(&format!("tunlion: {up} bridged at 127.0.0.1:{port}"));
        tasks.push(tokio::spawn(listener(shared.clone(), up, sock)));
    }
    (out, Some(Arc::new(TurnBridges { shared, tasks: Mutex::new(tasks) })))
}

async fn listener(shared: Arc<Shared>, up: Upstream, sock: Arc<UdpSocket>) {
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut dropped: u64 = 0;
    // Dropped with this task, which aborts every session (TurnBridges::shutdown).
    let mut running = JoinSet::new();
    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(x) => x,
                    // Windows reports an earlier ICMP unreachable on the next
                    // recv; nothing to do but keep serving.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if !src.ip().is_loopback() {
                    continue;
                }
                let pkt = buf[..n].to_vec();
                let live = sessions.get(&src).filter(|tx| !tx.is_closed()).cloned();
                let tx = match live {
                    Some(tx) => tx,
                    None => {
                        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
                        shared.register(src.port(), up.kind);
                        running.spawn(session(shared.clone(), up.clone(), sock.clone(), src, rx));
                        sessions.insert(src, tx.clone());
                        tx
                    }
                };
                // Full means the stream is backed up: drop, as UDP would, so
                // the sender sees loss instead of an ever-growing queue.
                if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(pkt) {
                    dropped += 1;
                    if dropped == 1 || dropped % 1000 == 0 {
                        crate::hooks::debug(&format!("tunlion: {up}: stream backed up, {dropped} packet(s) dropped"));
                    }
                }
            }
            Some(_) = running.join_next(), if !running.is_empty() => {
                sessions.retain(|_, tx| !tx.is_closed());
            }
        }
    }
}

fn stun_txid(p: &[u8]) -> Option<&[u8]> {
    (p.len() >= 20 && p[0] & 0xC0 == 0).then(|| &p[8..20])
}

fn hold(held: &mut VecDeque<Vec<u8>>, p: Vec<u8>) {
    // The turn client retransmits on its UDP timer while we hold; one copy of
    // each transaction is enough.
    if let Some(id) = stun_txid(&p) {
        if held.iter().any(|h| stun_txid(h) == Some(id)) {
            return;
        }
    }
    if held.len() >= HOLD_MAX {
        held.pop_front();
    }
    held.push_back(p);
}

async fn session(
    shared: Arc<Shared>,
    up: Upstream,
    sock: Arc<UdpSocket>,
    src: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut held: VecDeque<Vec<u8>> = VecDeque::new();
    let mut changed = shared.changed.subscribe();
    loop {
        match gate(up.kind, &shared.view()) {
            Gate::Proceed => break,
            Gate::Suppress => {
                crate::hooks::trace(&format!("[turn-bridge] {up}: not needed, a preferred relay is up"));
                return refuse(&sock, src, held, rx).await;
            }
            Gate::Wait(d) => {
                tokio::select! {
                    p = rx.recv() => match p {
                        Some(p) => hold(&mut held, p),
                        None => return,
                    },
                    _ = tokio::time::sleep(d) => {}
                    _ = changed.changed() => {}
                }
            }
        }
    }
    // Packets that queued while we decided.
    while let Ok(p) = rx.try_recv() {
        hold(&mut held, p);
    }
    crate::hooks::debug(&format!("tunlion: {up}: allocating (no UDP relay yet)"));
    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, connect(&up)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            crate::hooks::debug(&format!("tunlion: {up}: {e}"));
            shared.note_failed(&up);
            return refuse(&sock, src, held, rx).await;
        }
        Err(_) => {
            crate::hooks::debug(&format!("tunlion: {up}: connect timed out"));
            shared.note_failed(&up);
            return refuse(&sock, src, held, rx).await;
        }
    };
    let (mut rd, mut wr) = tokio::io::split(stream);
    let to_server = async {
        for p in held {
            write_frame(&mut wr, &p).await?;
        }
        loop {
            match tokio::time::timeout(IDLE, rx.recv()).await {
                Ok(Some(p)) => {
                    let t = Instant::now();
                    write_frame(&mut wr, &p).await?;
                    let took = t.elapsed();
                    if took > Duration::from_secs(1) {
                        crate::hooks::debug(&format!("tunlion: {up}: a write stalled {} ms", took.as_millis()));
                    }
                }
                Ok(None) | Err(_) => return Ok::<(), std::io::Error>(()),
            }
        }
    };
    let r = tokio::select! { r = to_server => r, r = pump_to_client(&mut rd, &sock, src) => r };
    if let Err(e) = r {
        crate::hooks::debug(&format!("tunlion: {up}: stream closed ({e})"));
    }
}

async fn pump_to_client<R: AsyncRead + Unpin>(rd: &mut R, sock: &UdpSocket, src: SocketAddr) -> std::io::Result<()> {
    loop {
        let f = read_frame(rd).await?;
        sock.send_to(&f, src).await?;
    }
}

/// Answer every STUN request from this client with `403 Forbidden` so its
/// allocation fails at once instead of retransmitting for ~25 s.
async fn refuse(sock: &UdpSocket, src: SocketAddr, held: VecDeque<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    for p in held {
        if let Some(r) = forbidden_response(&p) {
            let _ = sock.send_to(&r, src).await;
        }
    }
    loop {
        match tokio::time::timeout(IDLE, rx.recv()).await {
            Ok(Some(p)) => {
                if let Some(r) = forbidden_response(&p) {
                    let _ = sock.send_to(&r, src).await;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// A STUN error response (`403 Forbidden`) to a STUN request, or `None` for
/// anything that is not a request (indications, ChannelData, junk).
pub(crate) fn forbidden_response(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < 20 || req[0] & 0xC0 != 0 || req[4..8] != MAGIC_COOKIE {
        return None;
    }
    let typ = u16::from_be_bytes([req[0], req[1]]);
    if typ & 0x0110 != 0 {
        return None; // not a request
    }
    let resp_typ = typ | 0x0110;
    let reason = b"Forbidden";
    let value_len = 4 + reason.len(); // 13
    let padded = (value_len + 3) & !3; // 16
    let mut out = Vec::with_capacity(20 + 4 + padded);
    out.extend_from_slice(&resp_typ.to_be_bytes());
    out.extend_from_slice(&((4 + padded) as u16).to_be_bytes());
    out.extend_from_slice(&req[4..20]);
    out.extend_from_slice(&0x0009u16.to_be_bytes()); // ERROR-CODE
    out.extend_from_slice(&(value_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 4, 3]);
    out.extend_from_slice(reason);
    out.resize(20 + 4 + padded, 0);
    Some(out)
}

trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}

async fn connect(up: &Upstream) -> std::io::Result<Box<dyn ByteStream>> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((up.host.as_str(), up.port)).await?.collect();
    // IPv4 first: many hosts have no route to public IPv6 (see net::prefer_v4).
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address");
    let mut tcp = None;
    for a in addrs {
        match dial(a).await {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let tcp = tcp.ok_or(last)?;
    let _ = tcp.set_nodelay(true);
    match up.kind {
        StreamKind::Tcp => Ok(Box::new(tcp)),
        StreamKind::Tls => {
            let cfg = crate::http::turn_tls_config().map_err(std::io::Error::other)?;
            let name = rustls::pki_types::ServerName::try_from(up.host.clone())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?;
            Ok(Box::new(tls))
        }
    }
}

async fn dial(a: SocketAddr) -> std::io::Result<TcpStream> {
    let sock = if a.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    // Before connect, so the window is sized from the start.
    let _ = sock.set_send_buffer_size(STREAM_SNDBUF);
    sock.connect(a).await
}

/// Client -> server: STUN goes as is (always a multiple of four); ChannelData
/// is padded to four bytes, which a stream transport requires (RFC 8656 §12.5).
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, p: &[u8]) -> std::io::Result<()> {
    w.write_all(p).await?;
    let pad = (4 - p.len() % 4) % 4;
    if pad != 0 && p.first().map(|b| b & 0xC0 == 0x40).unwrap_or(false) {
        w.write_all(&[0u8; 3][..pad]).await?;
    }
    w.flush().await
}

/// Server -> client: one STUN message or one ChannelData message off the
/// stream, ChannelData padding stripped (the datagram carries exactly its
/// declared length).
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let (body, keep) = match hdr[0] >> 6 {
        0 => (16 + len, 16 + len),
        1 => ((len + 3) & !3, len),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not STUN or ChannelData",
            ))
        }
    };
    let mut out = vec![0u8; 4 + body];
    out[..4].copy_from_slice(&hdr);
    r.read_exact(&mut out[4..]).await?;
    out.truncate(4 + keep);
    Ok(out)
}

#[cfg(test)]
#[path = "turn_bridge_tests.rs"]
mod tests;
