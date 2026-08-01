//! TLS-over-TCP transport for UDP-hostile networks.
//!
//! Implements the `Transport` trait over a TLS 1.3 session (rustls) on a raw TCP
//! byte stream. This is the filament-native survival path when all UDP is blocked:
//! the transport runs end-to-end TLS between the two peers, either directly (LAN /
//! public/forwarded port) or inside a DERP-relayed WSS tunnel.
//!
//! Wire format: length-prefixed frames matching the `Transport` trait's expectations.
//! - Control frames: [1B kind=0][4B BE len][JSON payload]
//! - Data frames:    [1B kind=1][4B BE len][u32 BE sid][u64 BE offset][payload]
//!
//! Channel binding: RFC 5705 TLS exporter from the inner end-to-end TLS session.
//! The relay (and any DPI middlebox terminating the outer 443 TLS) cannot reproduce
//! this value, so identity binding is cryptographically tied to the genuine peer.

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bytes::Bytes;
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::net::{Ev, Transport};

/// Frame kind markers (same convention as DirectTransport).
const KIND_CONTROL: u8 = 0;
const KIND_DATA: u8 = 1;

/// Max app payload per send_frame. 1 MiB matches DirectTransport.
pub const MAX_TLS_TCP_PAYLOAD: usize = 1024 * 1024;

/// The TLS exporter label for channel binding (RFC 5705).
const EXPORTER_LABEL: &[u8] = b"filament-tls-tcp-binding";
const EXPORTER_CONTEXT: &[u8] = b"v1";
/// Length of the exported keying material (32 bytes = 256 bits).
const EXPORTER_LEN: usize = 32;
/// Separate exporter label for auth keying material. Must be distinct from
/// `EXPORTER_LABEL` to avoid cross-context reuse (same key in two roles).
const AUTH_EXPORTER_LABEL: &[u8] = b"filament-tls-tcp-auth";

// =========================================================== crypto helpers ==

/// Generate an ephemeral self-signed certificate for this connection.
/// Returns (cert_der, private_key_der).
fn ephemeral_cert() -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
    let key_pair = KeyPair::generate().expect("rcgen keygen");
    let params = CertificateParams::new(vec!["filament-ephemeral".to_string()])
        .expect("rcgen params");
    let cert = params.self_signed(&key_pair).expect("rcgen self-signed");
    let cert_der = cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    (cert_der, key_der)
}

/// No-op server cert verifier: we don't verify the peer's cert at the TLS layer.
/// We use ephemeral self-signed certs; authentication happens end-to-end via
/// PAKE / pair-secret after the transport is up. Same trust model as DTLS.
#[derive(Debug)]
struct NoopServerVerifier;

impl ServerCertVerifier for NoopServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// ============================================================= transport ==

type TlsStream = tokio_rustls::TlsStream<TcpStream>;

/// TLS-over-TCP transport implementing the filament `Transport` trait.
pub struct TlsTcpTransport {
    /// The TLS session over the TCP stream.
    tls: Arc<Mutex<TlsStream>>,
    last_activity: AtomicU64,
    dead: AtomicBool,
    /// Whether this end is the "answerer" (determines L2 sid half allocation).
    answerer: bool,
    /// Cached channel binding value (TLS exporter).
    channel_binding: Vec<u8>,
    /// The remote address of the underlying TCP connection.
    remote_addr: SocketAddr,
    /// Whether any data byte has flowed (for establishment grace tracking).
    has_flowed: AtomicBool,
}

impl TlsTcpTransport {
    /// Create a new TLS-over-TCP transport from an established TLS session.
    ///
    /// `tls` must be a completed TLS handshake over a TCP stream.
    /// `answerer` determines which half of the L2 sid space this end allocates from.
    /// `remote_addr` is the peer's socket address.
    pub fn new(
        tls: TlsStream,
        answerer: bool,
        remote_addr: SocketAddr,
        channel_binding: Vec<u8>,
    ) -> Self {
        Self {
            tls: Arc::new(Mutex::new(tls)),
            last_activity: AtomicU64::new(now_ms()),
            dead: AtomicBool::new(false),
            answerer,
            channel_binding,
            remote_addr,
            has_flowed: AtomicBool::new(false),
        }
    }

    /// Write a length-prefixed frame: [1B kind][4B BE len][payload].
    async fn write_framed(&self, kind: u8, payload: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(anyhow!("tls-tcp connection closed"));
        }
        let mut hdr = [0u8; 5];
        hdr[0] = kind;
        hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let mut tls = self.tls.lock().await;
        if let Err(e) = tls.write_all(&hdr).await {
            self.dead.store(true, Ordering::Relaxed);
            return Err(anyhow!("tls-tcp write hdr: {e}"));
        }
        if let Err(e) = tls.write_all(payload).await {
            self.dead.store(true, Ordering::Relaxed);
            return Err(anyhow!("tls-tcp write body: {e}"));
        }
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    /// Read one length-prefixed frame from the TLS stream.
    /// Returns (kind, payload).
    async fn read_framed(&self) -> Result<(u8, Vec<u8>)> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(anyhow!("tls-tcp connection closed"));
        }
        let mut hdr = [0u8; 5];
        let mut tls = self.tls.lock().await;
        if let Err(e) = tls.read_exact(&mut hdr).await {
            self.dead.store(true, Ordering::Relaxed);
            return Err(anyhow!("tls-tcp read hdr: {e}"));
        }
        let kind = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_TLS_TCP_PAYLOAD + 12 {
            // +12 for sid+offset overhead on data frames
            self.dead.store(true, Ordering::Relaxed);
            return Err(anyhow!("tls-tcp frame too large: {len}"));
        }
        let mut payload = vec![0u8; len];
        if let Err(e) = tls.read_exact(&mut payload).await {
            self.dead.store(true, Ordering::Relaxed);
            return Err(anyhow!("tls-tcp read body: {e}"));
        }
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        Ok((kind, payload))
    }
}

#[async_trait]
impl Transport for TlsTcpTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        let text = msg.to_string();
        self.write_framed(KIND_CONTROL, text.as_bytes()).await
    }

    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(anyhow!("tls-tcp connection closed"));
        }
        // Frame: [u32 BE sid][u64 BE offset][payload]
        let mut framed = Vec::with_capacity(4 + 8 + payload.len());
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(&offset.to_be_bytes());
        framed.extend_from_slice(payload);
        self.write_framed(KIND_DATA, &framed).await?;
        self.has_flowed.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            return Err(anyhow!("tls-tcp connection closed"));
        }
        let mut tls = self.tls.lock().await;
        tls.flush().await.map_err(|e| {
            self.dead.store(true, Ordering::Relaxed);
            anyhow!("tls-tcp flush: {e}")
        })
    }

    async fn drain_finish(&self) -> Result<()> {
        self.flush().await
    }

    fn max_payload(&self) -> usize {
        MAX_TLS_TCP_PAYLOAD
    }

    fn sid_answerer(&self) -> bool {
        self.answerer
    }

    fn idle_ms(&self) -> u64 {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = now_ms();
        now.saturating_sub(last)
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn force_close(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    fn channel_binding(&self) -> Option<Vec<u8>> {
        Some(self.channel_binding.clone())
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    fn has_flowed(&self) -> bool {
        self.has_flowed.load(Ordering::Relaxed)
    }
}

// ============================================================ dialer helpers ==

/// Create a rustls ClientConfig for the TLS-TCP transport.
///
/// The client does NOT verify the server cert (we use self-signed ephemeral certs
/// at the TLS layer; authentication happens end-to-end via PAKE / pair-secret).
/// This is the same trust model as the WebRTC/DTLS path.
pub fn client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopServerVerifier))
        .with_no_client_auth();
    // ALPN: present browser-like to avoid fingerprinting on corporate nets.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Create a rustls ServerConfig for the TLS-TCP transport.
///
/// Uses the ephemeral self-signed cert generated per connection.
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
) -> rustls::ServerConfig {
    let key_der: PrivateKeyDer = PrivateKeyDer::Pkcs8(key);
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key_der)
        .expect("server config");
    // ALPN: match the client's browser-like presentation.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// Extract the channel binding (TLS exporter) from an established TLS session.
///
/// This is the inner-session exporter (RFC 5705) that both peers compute
/// independently. A MITM terminating the outer TLS gets a different exporter.
pub fn extract_channel_binding(tls: &TlsStream) -> Result<Vec<u8>> {
    let mut buf = [0u8; EXPORTER_LEN];
    match tls {
        tokio_rustls::TlsStream::Client(conn) => {
            conn.get_ref()
                .1
                .export_keying_material(&mut buf, EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
                .map_err(|e| anyhow!("export keying material: {e}"))?;
        }
        tokio_rustls::TlsStream::Server(conn) => {
            conn.get_ref()
                .1
                .export_keying_material(&mut buf, EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
                .map_err(|e| anyhow!("export keying material: {e}"))?;
        }
    }
    Ok(buf.to_vec())
}

/// Extract auth keying material from the TLS session using a DISTINCT exporter
/// label. This is cryptographically independent from the channel binding
/// exporter, preventing cross-context reuse of the same key in two roles.
fn extract_auth_km(tls: &TlsStream) -> Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    match tls {
        tokio_rustls::TlsStream::Client(conn) => {
            conn.get_ref()
                .1
                .export_keying_material(&mut buf, AUTH_EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
                .map_err(|e| anyhow!("export auth keying material: {e}"))?;
        }
        tokio_rustls::TlsStream::Server(conn) => {
            conn.get_ref()
                .1
                .export_keying_material(&mut buf, AUTH_EXPORTER_LABEL, Some(EXPORTER_CONTEXT))
                .map_err(|e| anyhow!("export auth keying material: {e}"))?;
        }
    }
    Ok(buf)
}

// ============================================================ dialer ==

/// Dial a peer via TLS-over-TCP (direct connection).
///
/// `addr` is the peer's TCP listen address (LAN or public/forwarded port).
/// `answerer` determines which half of the L2 sid space this end allocates from.
///
/// Returns the transport, the channel binding, and the remote address.
/// NOTE: this does NOT authenticate. Use `race_connect_tls_tcp` for the
/// authenticated path with pair-secret MAC verification.
async fn dial_tls_tcp(
    addr: SocketAddr,
    answerer: bool,
) -> Result<(TlsTcpTransport, Vec<u8>, SocketAddr)> {
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| anyhow!("tls-tcp connect timeout: {addr}"))?
    .map_err(|e| anyhow!("tls-tcp connect: {e}"))?;

    let remote_addr = tcp.peer_addr().map_err(|e| anyhow!("peer_addr: {e}"))?;

    let config = client_config();
    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from("filament-ephemeral").expect("server name");

    let tls = connector
        .connect(domain, tcp)
        .await
        .map_err(|e| anyhow!("tls handshake: {e}"))?;

    let tls_stream: TlsStream = TlsStream::Client(tls);
    let channel_binding = extract_channel_binding(&tls_stream)?;
    let transport = TlsTcpTransport::new(tls_stream, answerer, remote_addr, channel_binding.clone());

    Ok((transport, channel_binding, remote_addr))
}

/// Accept a TLS-over-TCP connection on an existing TCP stream.
///
/// `tcp` is the accepted TCP connection.
/// `answerer` determines which half of the L2 sid space this end allocates from.
///
/// Returns the transport, the channel binding, and the remote address.
/// NOTE: this does NOT authenticate. Use `race_connect_tls_tcp` for the
/// authenticated path with pair-secret MAC verification.
async fn accept_tls_tcp(
    tcp: TcpStream,
    answerer: bool,
) -> Result<(TlsTcpTransport, Vec<u8>, SocketAddr)> {
    let remote_addr = tcp.peer_addr().map_err(|e| anyhow!("peer_addr: {e}"))?;

    let (cert, key) = ephemeral_cert();
    let config = server_config(cert, key);
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| anyhow!("tls handshake: {e}"))?;

    let tls_stream: TlsStream = TlsStream::Server(tls);
    let channel_binding = extract_channel_binding(&tls_stream)?;
    let transport = TlsTcpTransport::new(tls_stream, answerer, remote_addr, channel_binding.clone());

    Ok((transport, channel_binding, remote_addr))
}

// ============================================================ reader task ==

/// Spawn a reader task that reads frames from the TLS stream and sends them
/// to the provided event channel.
///
/// This is the TLS-TCP equivalent of the DataChannel/QUIC reader tasks.
/// It reads control and data frames and dispatches them as events.
pub fn spawn_reader(
    transport: Arc<TlsTcpTransport>,
    peer_id: String,
    event_tx: tokio::sync::mpsc::UnboundedSender<Ev>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match transport.read_framed().await {
                Ok((KIND_CONTROL, payload)) => {
                    if let Ok(text) = std::str::from_utf8(&payload) {
                        if let Ok(msg) = serde_json::from_str::<Value>(text) {
                            let _ = event_tx.send(Ev::Control(peer_id.clone(), msg));
                        }
                    }
                }
                Ok((KIND_DATA, payload)) => {
                    if payload.len() < 12 {
                        continue; // too short for sid + offset
                    }
                    let sid = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let offset = u64::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                        payload[8], payload[9], payload[10], payload[11],
                    ]);
                    let data = Bytes::copy_from_slice(&payload[12..]);
                    let _ = event_tx.send(Ev::Chunk(
                        peer_id.clone(),
                        sid,
                        Some(offset),
                        data,
                    ));
                }
                Ok((kind, _)) => {
                    // Unknown frame kind — skip
                    eprintln!("[tls-tcp] unknown frame kind: {kind}");
                }
                Err(e) => {
                    if !transport.is_dead() {
                        eprintln!("[tls-tcp] reader error: {e}");
                    }
                    break;
                }
            }
        }
    })
}

// ============================================================ auth ==

// ============================================================ TCP listener ==

/// Bind a TCP listener for TLS/TCP transport connections.
///
/// `port` is the preferred port; 0 means OS-assigned. Returns the bound listener
/// and the actual port. The listener is used for accepting inbound TLS/TCP
/// connections from peers that received our transport-offer.
pub async fn bind_tls_tcp_listener(
    port: u16,
) -> Result<(tokio::net::TcpListener, u16)> {
    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual_port = listener.local_addr()?.port();
    Ok((listener, actual_port))
}

// ============================================================ race connect ==

/// Race TLS/TCP connections: accept inbound on `listener` AND dial each peer
/// candidate simultaneously. Returns the first authenticated transport.
///
/// This is the TLS/TCP equivalent of `direct::race_connect_labeled` for QUIC.
/// Both sides run the same race (accept + dial); the first to complete the TLS
/// handshake AND pass the pair-secret MAC wins.
///
/// The `answerer` bit (which L2 sid half this end allocates from) is derived
/// deterministically via `net::polite_role` — the two ends compute OPPOSITE
/// bits, which is what keeps their L2 sid spaces disjoint. No caller can get
/// this wrong.
pub async fn race_connect_tls_tcp(
    listener: tokio::net::TcpListener,
    peer_cands: Vec<String>,
    secret: &str,
    my_uid: &str,
    peer_uid: Option<&str>,
    my_id: &str,
    peer_id: String,
    tx: tokio::sync::mpsc::UnboundedSender<crate::net::Ev>,
    route: &'static str,
) -> Option<Arc<dyn Transport>> {
    use crate::direct::{auth_tag, ct_eq, transport_key, DIRECT_BUDGET};

    // Derive the answerer bit deterministically — opposite on the two ends by
    // construction, so their L2 sid spaces never collide. Same logic as QUIC.
    let answerer = crate::net::polite_role(my_uid, peer_uid, my_id, &peer_id);

    let tkey = transport_key(secret);

    type AuthResult = Result<(TlsTcpTransport, Vec<u8>)>;

    let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult> + Send>>> = Vec::new();

    // Acceptor: loop accepting inbound TLS/TCP connections, spawning each
    // connection's auth as a separate tokio task so we loop back to
    // listener.accept() IMMEDIATELY. A silent peer holding a connection for
    // 3s does NOT block the next accept — the attacker burns one task, not
    // the accept slot. First task that passes auth sends the result back.
    {
        let tkey = tkey;
        let answerer = answerer;
        futs.push(Box::pin(async move {
            let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<AuthResult>(4);
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        let (tcp, _remote_addr) = res.map_err(|e| anyhow!("tls-tcp accept: {e}"))?;
                        let tkey = tkey;
                        let done_tx = done_tx.clone();
                        // Spawn: this connection's auth runs concurrently with
                        // the next accept(). The 3s timeout is inside the task.
                        tokio::spawn(async move {
                            let result = tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                async move {
                                    let (transport, cb, _) = accept_tls_tcp(tcp, answerer).await?;
                                    {
                                        let tls = transport.tls.lock().await;
                                        let auth_km = extract_auth_km(&*tls)?;
                                        let my_tag = auth_tag(&tkey, &auth_km, "acceptor");
                                        let their_expected = auth_tag(&tkey, &auth_km, "dialer");
                                        drop(tls);
                                        let mut tls = transport.tls.lock().await;
                                        let mut peer_tag = [0u8; 32];
                                        tls.read_exact(&mut peer_tag).await.map_err(|e| anyhow!("auth recv: {e}"))?;
                                        if !ct_eq(&peer_tag, &their_expected) {
                                            bail!("TLS-TCP-AUTH-FAIL: pair-secret MAC mismatch, rejecting peer");
                                        }
                                        tls.write_all(&my_tag).await.map_err(|e| anyhow!("auth send: {e}"))?;
                                    }
                                    Ok((transport, cb))
                                }
                            ).await;

                            match result {
                                Ok(Ok(transport_cb)) => { let _ = done_tx.send(Ok(transport_cb)).await; }
                                Ok(Err(e)) => {
                                    let s = e.to_string();
                                    if s.contains("TLS-TCP-AUTH-FAIL") {
                                        crate::ui::trace(&format!("filament: {s}"));
                                    }
                                }
                                Err(_) => {
                                    crate::ui::trace("filament: tls-tcp accept conn timed out (silent peer), discarded");
                                }
                            }
                        });
                    }
                    Some(res) = done_rx.recv() => {
                        // A spawned task completed auth successfully.
                        return res;
                    }
                }
            }
        }));
    }

    // Dialer: one future per candidate, authenticate as dialer.
    for cand in peer_cands {
        let addr: std::net::SocketAddr = match cand.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let tkey = tkey;
        futs.push(Box::pin(async move {
            let (transport, cb, _) = dial_tls_tcp(addr, answerer).await?;
            // Authenticate: dialer sends first, then reads. Uses a SEPARATE
            // exporter label from the channel binding.
            {
                let tls = transport.tls.lock().await;
                let auth_km = extract_auth_km(&*tls)?;
                let my_tag = auth_tag(&tkey, &auth_km, "dialer");
                let their_expected = auth_tag(&tkey, &auth_km, "acceptor");
                drop(tls);
                let mut tls = transport.tls.lock().await;
                tls.write_all(&my_tag).await.map_err(|e| anyhow!("auth send: {e}"))?;
                let mut peer_tag = [0u8; 32];
                tls.read_exact(&mut peer_tag).await.map_err(|e| anyhow!("auth recv: {e}"))?;
                if !ct_eq(&peer_tag, &their_expected) {
                    bail!("TLS-TCP-AUTH-FAIL: pair-secret MAC mismatch, rejecting peer");
                }
            }
            Ok((transport, cb))
        }));
    }

    use futures_util::stream::{FuturesUnordered, StreamExt};
    let race = async {
        let mut set: FuturesUnordered<_> = futs.into_iter().collect();
        while let Some(res) = set.next().await {
            match res {
                Ok((transport, _cb)) => return Some(transport),
                Err(e) => {
                    let s = e.to_string();
                    if s.contains("TLS-TCP-AUTH-FAIL") {
                        crate::ui::trace(&format!("filament: {s}"));
                    }
                    continue;
                }
            }
        }
        None
    };

    match tokio::time::timeout(DIRECT_BUDGET, race).await {
        Ok(Some(transport)) => {
            crate::ui::debug(&format!(
                "filament: TLS-TCP-CONNECT ok (route: {}) peer={}",
                route, peer_id,
            ));
            // Spawn the reader BEFORE wrapping in Arc<dyn Transport>.
            let transport_arc = Arc::new(transport);
            spawn_reader(transport_arc.clone(), peer_id, tx);
            Some(transport_arc)
        }
        _ => {
            crate::ui::trace(&format!("filament: TLS-TCP race timed out for {peer_id}"));
            None
        }
    }
}

// ============================================================ utilities ==

fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

// ============================================================== tests ==

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that polite_role produces opposite answerer bits for two peers,
    /// and that the resulting L2 sid spaces are disjoint. This is the actual
    /// proof that the answerer-bit fix works — a single-stream test cannot
    /// catch the collision because it only manifests when both ends allocate
    /// L2 sids on the same link.
    #[test]
    fn sid_disjoint_both_ends_via_polite_role() {
        // Simulate two peers with different uids and ids.
        let uid_a = "user-alpha";
        let uid_b = "user-beta";
        let id_a = "device-aaa";
        let id_b = "device-bbb";

        // Both ends compute their answerer bit via polite_role.
        let answerer_a = crate::net::polite_role(uid_a, Some(uid_b), id_a, id_b);
        let answerer_b = crate::net::polite_role(uid_b, Some(uid_a), id_b, id_a);

        // They MUST be opposite — that's the invariant polite_role guarantees.
        assert_ne!(
            answerer_a, answerer_b,
            "polite_role must return opposite bits for the two ends"
        );

        // Simulate L2 sid allocation: each end generates sids in a loop.
        // The role bit is 0x4000_0000 for the answerer, 0 for the dialer.
        let role_a: u32 = if answerer_a { 0x4000_0000 } else { 0 };
        let role_b: u32 = if answerer_b { 0x4000_0000 } else { 0 };

        let mut sids_a = std::collections::HashSet::new();
        let mut sids_b = std::collections::HashSet::new();
        for i in 0..1000u32 {
            sids_a.insert(role_a | i);
            sids_b.insert(role_b | i);
        }

        // The two sets must be completely disjoint.
        let overlap: Vec<_> = sids_a.intersection(&sids_b).collect();
        assert!(
            overlap.is_empty(),
            "L2 sid spaces overlap! {} colliding sids, first: {:?}",
            overlap.len(),
            overlap.first()
        );

        // Also verify the specific sid_answerer() field matches.
        // (We can't construct a real TlsTcpTransport without a TLS session,
        // but we can verify the bit that feeds into sid_answerer().)
        assert_eq!(role_a ^ role_b, 0x4000_0000, "roles must differ by exactly the answerer bit");
    }

    /// Edge case: same uid (two devices under one account) falls back to id comparison.
    #[test]
    fn sid_disjoint_same_uid_different_id() {
        let uid = "shared-user";
        let id_a = "device-aaa";
        let id_b = "device-bbb";

        let answerer_a = crate::net::polite_role(uid, Some(uid), id_a, id_b);
        let answerer_b = crate::net::polite_role(uid, Some(uid), id_b, id_a);

        assert_ne!(
            answerer_a, answerer_b,
            "same uid, different ids must still produce opposite bits"
        );
    }

    /// Edge case: symmetric identity (swapped uids produce consistent results).
    #[test]
    fn sid_disjoint_symmetric() {
        let uid_a = "alpha";
        let uid_b = "beta";
        let id_a = "s1";
        let id_b = "s2";

        // Run 100 times with swapped order to verify determinism.
        for _ in 0..100 {
            let a = crate::net::polite_role(uid_a, Some(uid_b), id_a, id_b);
            let b = crate::net::polite_role(uid_b, Some(uid_a), id_b, id_a);
            assert_ne!(a, b, "polite_role must be antisymmetric");
        }
    }
}
