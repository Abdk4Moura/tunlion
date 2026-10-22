//! `IrohTransport`: the existing [`Transport`] contract over an iroh connection.
//!
//! # The wire is the existing wire
//!
//! The direct-QUIC transport and the WebRTC data channel already agree on one
//! framing for a connection that is a byte stream, not a message channel:
//!
//! ```text
//! frame  = [1B kind][4B BE length][body]
//! kind 0 = control, body = JSON
//! kind 1 = data,    body = [4B BE sid][8B BE absolute offset][payload]
//! ```
//!
//! This module reuses it byte for byte, including the 1 MiB payload ceiling and
//! the sid/offset shape. That is the whole reason [`IrohTransport`] can be a
//! drop-in `impl Transport` without a caller change: the layers above see the
//! same `Ev::Control` / `Ev::Chunk` values they already handle.
//!
//! One extra frame kind is used only during setup:
//!
//! ```text
//! kind 2 = hello, body = the device-key-signed IrohBinding JSON
//! ```
//!
//! It is written and read before the reader task starts, so it never reaches a
//! caller. A peer that sends a wrong, unsigned or mismatched binding is refused
//! before a single application byte is read.
//!
//! # What the trait can and cannot express
//!
//! Implemented for real: control, framed data, flush, final drain, datagrams,
//! max datagram size, liveness, idle tracking, force-close, channel binding (the
//! RFC 5705 TLS exporter — a terminating relay cannot reproduce it), and the
//! sid-answerer role.
//!
//! Left at the trait default because the shape cannot cross the iroh boundary:
//! `open_stream()` and `quic_connection()` return `quinn` types. iroh uses
//! `noq`, a different QUIC implementation; returning a `quinn::Connection` would
//! be a lie. Mesh stream reuse and anything that requires the concrete quinn
//! handle therefore stay unavailable on this rung. See the design note.
//!
//! # Failure is a value, not a hang
//!
//! Relay unreachable, handshake refused, binding mismatch, feature off: every
//! one is an `Err` from [`IrohNode::bind`] / [`IrohNode::connect`] /
//! [`IrohNode::accept_one`]. Nothing here retries by itself and nothing falls
//! back by itself, because "fall back to the transport I already have" is a
//! decision the host's ladder makes. The PoC never forces a relay.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use filament_transport::net::{Ev, Transport};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use serde_json::Value;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;

use crate::identity::{DeviceIdentity, IrohBinding, NodeKeyMode};
use crate::relay::RelayPlan;
use crate::ALPN;

/// Frame kind for application JSON. Matches `filament-transport`'s direct path.
const KIND_CONTROL: u8 = 0;
/// Frame kind for `[sid][offset][payload]`. Matches the direct path.
const KIND_DATA: u8 = 1;
/// Setup-only frame carrying the signed binding.
const KIND_HELLO: u8 = 2;

/// Largest application payload this transport will send, matching the direct
/// path's ceiling. A caller that respects `max_payload()` never trips the frame
/// guard.
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// A hello is a small JSON record, not a data frame. Capped separately so a
/// hostile peer cannot make us allocate a megabyte before authentication.
const MAX_HELLO: usize = 8 * 1024;

/// Domain separation for the channel binding. Both peers must use exactly these
/// bytes or the exporter outputs differ; that is the point.
const CHANNEL_BINDING_LABEL: &[u8] = b"filament/iroh/channel-binding/v1";

/// Node configuration. Relays are explicit; there is no public default.
#[derive(Debug, Clone)]
pub struct IrohConfig {
    pub relays: RelayPlan,
    pub key_mode: NodeKeyMode,
    /// Bound on `Endpoint::bind`.
    pub bind_timeout: Duration,
    /// Bound on waiting for a home relay after bind. A dead relay turns into an
    /// error here rather than a hung daemon.
    pub relay_online_timeout: Duration,
    /// Bound on dial + binding exchange.
    pub connect_timeout: Duration,
    /// Remove IP transports, leaving only the relay path. Used by the PoC test
    /// to prove traffic really went through the relay; also useful as an
    /// operator's "relay-only" mode.
    pub relay_only: bool,
    pub max_payload: usize,
}

impl Default for IrohConfig {
    fn default() -> Self {
        Self {
            relays: RelayPlan::empty(),
            key_mode: NodeKeyMode::Derived,
            bind_timeout: Duration::from_secs(10),
            relay_online_timeout: Duration::from_secs(8),
            connect_timeout: Duration::from_secs(10),
            relay_only: false,
            max_payload: MAX_PAYLOAD,
        }
    }
}

impl IrohConfig {
    pub fn new(relays: RelayPlan) -> Self {
        Self {
            relays,
            ..Self::default()
        }
    }
}

/// An iroh endpoint bound to a tunlion device identity.
///
/// The endpoint key is derived from the device key at construction; the node
/// does not accept a caller-supplied iroh secret, so there is no way to
/// accidentally run the PoC under a fresh, unrelated identity.
pub struct IrohNode {
    ep: Endpoint,
    binding: IrohBinding,
    config: IrohConfig,
}

impl std::fmt::Debug for IrohNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohNode")
            .field("endpoint_id", &self.binding.endpoint_id.to_string())
            .field("device_pub", &hex::encode(self.binding.device_pub))
            .field("relays", &self.config.relays.len())
            .finish()
    }
}

impl IrohNode {
    /// Bind an iroh endpoint whose identity is `identity`.
    ///
    /// `Err` here is the expected outcome when iroh is unavailable or the
    /// configured relay is down. The caller keeps its existing transport; this
    /// function never panics for a network condition and never starts a
    /// background retry loop.
    pub async fn bind(identity: DeviceIdentity, config: IrohConfig) -> Result<Self> {
        if config.max_payload == 0 || config.max_payload > MAX_PAYLOAD {
            bail!(
                "iroh max_payload must be in 1..={MAX_PAYLOAD}, got {}",
                config.max_payload
            );
        }

        let binding = identity.binding(config.key_mode);
        let node_secret = identity.node_secret(config.key_mode);

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(node_secret)
            .alpns(vec![ALPN.to_vec()])
            // No pkarr/DNS publishing: the PoC learns peers through the host's
            // existing signed channel, not a public discovery service.
            .clear_address_lookup()
            .relay_mode(config.relays.relay_mode());

        if config.relay_only {
            builder = builder.clear_ip_transports();
        }
        if config.relays.uses_insecure_tls() {
            // RelayPlan::parse only allows this for loopback URLs. The iroh
            // method itself is gated on iroh's `test-utils` feature, so a
            // production build (which must not link a relay server) has to
            // refuse the setting rather than fail to compile.
            #[cfg(feature = "test-relay")]
            {
                builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
            }
            #[cfg(not(feature = "test-relay"))]
            {
                bail!(
                    "relay {} requested insecure_skip_verify, but this build lacks \
                     the test-relay feature needed for a self-signed relay",
                    config
                        .relays
                        .first_url()
                        .map(|url| url.to_string())
                        .unwrap_or_default()
                );
            }
        }

        let ep = tokio::time::timeout(config.bind_timeout, builder.bind())
            .await
            .map_err(|_| {
                anyhow!(
                    "iroh endpoint bind timed out after {:?}",
                    config.bind_timeout
                )
            })?
            .context("iroh endpoint bind failed")?;

        if !config.relays.is_empty() {
            match tokio::time::timeout(config.relay_online_timeout, ep.online()).await {
                Ok(()) => {}
                Err(_) => {
                    // Drop the endpoint rather than leave a retry loop behind.
                    drop(ep);
                    bail!(
                        "iroh relay did not come online within {:?}; not forcing it",
                        config.relay_online_timeout
                    );
                }
            }
        }

        Ok(Self {
            ep,
            binding,
            config,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.ep
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.binding.endpoint_id
    }

    pub fn device_pub(&self) -> [u8; 32] {
        self.binding.device_pub
    }

    pub fn binding(&self) -> &IrohBinding {
        &self.binding
    }

    pub fn config(&self) -> &IrohConfig {
        &self.config
    }

    /// Dial `peer` through a relay and complete the binding exchange.
    ///
    /// `relay` is the address the caller learned for the peer (the same
    /// `EndpointAddr` role the direct path's candidates play). When `None`, the
    /// first reachable configured relay is used.
    pub async fn connect(
        &self,
        peer_id: impl Into<String>,
        peer: &IrohBinding,
        relay: Option<&RelayUrl>,
        tx: UnboundedSender<Ev>,
    ) -> Result<IrohTransport> {
        peer.verify().context("peer iroh binding is not valid")?;

        let relay_url = match relay {
            Some(url) => url.clone(),
            None => self
                .config
                .relays
                .healthy_order()
                .await
                .into_iter()
                .next()
                .map(|endpoint| endpoint.url)
                .ok_or_else(|| anyhow!("no relay configured; refusing to use a public default"))?,
        };

        let addr = EndpointAddr::new(peer.endpoint_id).with_relay_url(relay_url);
        let conn = tokio::time::timeout(self.config.connect_timeout, self.ep.connect(addr, ALPN))
            .await
            .map_err(|_| {
                anyhow!(
                    "iroh connect timed out after {:?}",
                    self.config.connect_timeout
                )
            })?
            .context("iroh connect failed")?;

        let remote = conn.remote_id();
        if remote != peer.endpoint_id {
            bail!("iroh authenticated {remote}, expected {}", peer.endpoint_id);
        }

        let (send, recv) = conn.open_bi().await.context("iroh open_bi failed")?;
        let transport = tokio::time::timeout(
            self.config.connect_timeout,
            build_transport(
                self.ep.clone(),
                conn,
                send,
                recv,
                &self.binding,
                remote,
                Some(peer.device_pub),
                peer_id.into(),
                false,
                self.config.max_payload,
                tx,
            ),
        )
        .await
        .map_err(|_| anyhow!("iroh binding exchange timed out"))??;

        Ok(transport)
    }

    /// Accept one iroh connection, verify the peer's device binding, and return
    /// the transport.
    ///
    /// `expected_device` is the device public key the host already believes this
    /// peer is (from its roster / the signaling session). `None` accepts any
    /// valid binding and leaves the check to the caller — use `Some` in a
    /// product path.
    pub async fn accept_one(
        &self,
        peer_id: impl Into<String>,
        expected_device: Option<[u8; 32]>,
        tx: UnboundedSender<Ev>,
    ) -> Result<IrohTransport> {
        let peer_id = peer_id.into();
        loop {
            let incoming = self
                .ep
                .accept()
                .await
                .ok_or_else(|| anyhow!("iroh endpoint closed while accepting"))?;
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(error) => {
                    filament_transport::hooks::debug(&format!(
                        "iroh incoming handshake failed: {error}"
                    ));
                    continue;
                }
            };
            let remote = conn.remote_id();
            let accepted =
                tokio::time::timeout(self.config.connect_timeout, conn.accept_bi()).await;
            let (send, recv) = match accepted {
                Ok(Ok(streams)) => streams,
                Ok(Err(error)) => {
                    filament_transport::hooks::debug(&format!(
                        "iroh accept_bi failed for {remote}: {error}"
                    ));
                    continue;
                }
                Err(_) => {
                    // A peer that connects and never opens the stream must not
                    // hold the accept loop forever.
                    filament_transport::hooks::debug(&format!(
                        "iroh peer {remote} opened no stream within {:?}",
                        self.config.connect_timeout
                    ));
                    continue;
                }
            };
            let built = tokio::time::timeout(
                self.config.connect_timeout,
                build_transport(
                    self.ep.clone(),
                    conn,
                    send,
                    recv,
                    &self.binding,
                    remote,
                    expected_device,
                    peer_id.clone(),
                    true,
                    self.config.max_payload,
                    tx.clone(),
                ),
            )
            .await;
            match built {
                Ok(Ok(transport)) => return Ok(transport),
                Ok(Err(error)) => {
                    // A bad peer must not take the accept loop down. The error is
                    // visible to the host's diagnostics path, not swallowed.
                    filament_transport::hooks::debug(&format!(
                        "iroh peer refused ({remote}): {error:#}"
                    ));
                    continue;
                }
                Err(_) => {
                    filament_transport::hooks::debug(&format!(
                        "iroh binding exchange with {remote} timed out"
                    ));
                    continue;
                }
            }
        }
    }
}

/// One link, ready to be handed to the existing transfer/L2/L3 layers as
/// `Arc<dyn Transport>`.
pub struct IrohTransport {
    conn: Connection,
    send: Arc<Mutex<SendStream>>,
    /// Kept so the endpoint outlives the connection it produced.
    _ep: Endpoint,
    peer: IrohBinding,
    answerer: bool,
    dead: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
    first_data: Arc<AtomicBool>,
    max_payload: usize,
}

impl std::fmt::Debug for IrohTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohTransport")
            .field("peer_endpoint_id", &self.peer.endpoint_id.to_string())
            .field("peer_device_pub", &hex::encode(self.peer.device_pub))
            .field("answerer", &self.answerer)
            .field("dead", &self.dead.load(Ordering::Relaxed))
            .finish()
    }
}

impl IrohTransport {
    /// The peer's VERIFIED device -> node binding. The device key here is
    /// authenticated by the iroh handshake plus the device signature; the
    /// caller still decides whether that device is enrolled.
    pub fn peer_binding(&self) -> &IrohBinding {
        &self.peer
    }

    pub fn peer_device_pub(&self) -> [u8; 32] {
        self.peer.device_pub
    }

    pub fn peer_endpoint_id(&self) -> EndpointId {
        self.peer.endpoint_id
    }

    /// Whether the path currently carrying application bytes is the relay.
    ///
    /// `None` means iroh has not selected a path yet. iroh may upgrade a relay
    /// path to a direct one when hole punching succeeds; this reports the path
    /// at the moment of the call, which is what a `filament ping` style display
    /// or the PoC test needs.
    pub fn selected_path_is_relay(&self) -> Option<bool> {
        let paths = self.conn.paths();
        let path = paths.iter().find(|path| path.is_selected())?;
        Some(path.is_relay())
    }

    /// The selected path's remote address, when it is an IP path.
    pub fn selected_path_remote_addr(&self) -> Option<std::net::SocketAddr> {
        let paths = self.conn.paths();
        match paths.iter().find(|path| path.is_selected())?.remote_addr() {
            iroh::TransportAddr::Ip(addr) => Some(*addr),
            _ => None,
        }
    }

    async fn write_framed(&self, kind: u8, body: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            bail!("iroh connection already closed");
        }
        let mut send = self.send.lock().await;
        if let Err(error) = write_frame(&mut send, kind, body).await {
            self.dead.store(true, Ordering::Relaxed);
            return Err(error);
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        self.write_framed(KIND_CONTROL, msg.to_string().as_bytes())
            .await
    }

    async fn send_frame(&self, sid: u32, offset: u64, payload: &[u8]) -> Result<()> {
        if payload.len() > self.max_payload {
            bail!(
                "iroh frame payload {} exceeds max_payload {}",
                payload.len(),
                self.max_payload
            );
        }
        let mut body = Vec::with_capacity(12 + payload.len());
        body.extend_from_slice(&sid.to_be_bytes());
        body.extend_from_slice(&offset.to_be_bytes());
        body.extend_from_slice(payload);
        self.write_framed(KIND_DATA, &body).await?;
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        self.first_data.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // QUIC is ordered and reliable; `flush` is per-file and must not finish
        // the stream. The delivery barrier is `drain_finish`.
        if self.dead.load(Ordering::Relaxed) {
            bail!("iroh connection closed while flushing");
        }
        Ok(())
    }

    async fn drain_finish(&self) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            return Ok(());
        }
        let stopped = {
            let mut send = self.send.lock().await;
            let _ = send.finish();
            send.stopped()
        };
        // Same reasoning as the direct path: FIN gets every byte committed to
        // the peer's QUIC stack. The wall is only a backstop against a
        // half-dead peer so a daemon cannot hang forever.
        match tokio::time::timeout(Duration::from_secs(180), stopped).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(anyhow!("iroh drain: peer dropped before full ack: {error}")),
            Err(_) => Err(anyhow!(
                "iroh drain: timed out after 180s awaiting peer ack"
            )),
        }
    }

    fn max_payload(&self) -> usize {
        self.max_payload
    }

    fn sid_answerer(&self) -> bool {
        self.answerer
    }

    fn idle_ms(&self) -> u64 {
        if self.dead.load(Ordering::Relaxed) {
            return u64::MAX;
        }
        now_ms().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::Relaxed) && self.conn.close_reason().is_none()
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn force_close(&self) {
        self.conn.close(0u32.into(), b"dropped");
    }

    fn supports_datagrams(&self) -> bool {
        // Honest about the negotiation: iroh enables datagrams by default, but a
        // peer that did not advertise them makes `max_datagram_size()` `None`,
        // and the L3 pump must not start on a transport that cannot carry it.
        self.conn.max_datagram_size().is_some()
    }

    fn send_datagram(&self, packet: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            bail!("iroh connection already closed");
        }
        self.conn
            .send_datagram(Bytes::copy_from_slice(packet))
            .map_err(|error| anyhow!("iroh send_datagram: {error}"))
    }

    async fn recv_datagram(&self) -> Result<Bytes> {
        self.conn
            .read_datagram()
            .await
            .map_err(|error| anyhow!("iroh read_datagram: {error}"))
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn channel_binding(&self) -> Option<Vec<u8>> {
        // RFC 5705 exporter over the iroh TLS session. Both peers derive the
        // same 32 bytes; a relay that terminates each leg separately derives
        // different ones, so an announce signed against this cannot be replayed
        // across the relay. This is the same property the direct path relies on.
        let mut out = [0u8; 32];
        self.conn
            .export_keying_material(&mut out, CHANNEL_BINDING_LABEL, b"")
            .ok()
            .map(|()| out.to_vec())
    }

    fn has_flowed(&self) -> bool {
        self.first_data.load(Ordering::Relaxed)
    }

    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        // A relay path is not one socket 5-tuple, so it answers `None`; a path
        // that iroh has upgraded to direct does have one.
        self.selected_path_remote_addr()
    }

    fn local_ip(&self) -> Option<std::net::IpAddr> {
        let paths = self.conn.paths();
        match paths.iter().find(|path| path.is_selected())?.local_addr() {
            iroh::endpoint::LocalTransportAddr::Ip(Some(ip)) => Some(*ip),
            _ => None,
        }
    }

    fn rtt_ms(&self) -> Option<u64> {
        let paths = self.conn.paths();
        let path = paths.iter().find(|path| path.is_selected())?;
        Some(path.rtt().as_millis() as u64)
    }
}

// ------------------------------------------------------------------- setup --

#[allow(clippy::too_many_arguments)]
async fn build_transport(
    ep: Endpoint,
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    own: &IrohBinding,
    expected_endpoint: EndpointId,
    expected_device: Option<[u8; 32]>,
    peer_id: String,
    answerer: bool,
    max_payload: usize,
    tx: UnboundedSender<Ev>,
) -> Result<IrohTransport> {
    // Both sides write first, then read. Neither can block the other: the hello
    // is far below any QUIC stream window.
    let hello = own.to_json().to_string();
    write_frame(&mut send, KIND_HELLO, hello.as_bytes())
        .await
        .context("write iroh binding hello")?;

    let peer = read_hello(&mut recv, expected_endpoint, expected_device)
        .await
        .context("read peer iroh binding")?;

    let dead = Arc::new(AtomicBool::new(false));
    let last_activity = Arc::new(AtomicU64::new(now_ms()));
    let first_data = Arc::new(AtomicBool::new(false));

    let transport = IrohTransport {
        conn,
        send: Arc::new(Mutex::new(send)),
        _ep: ep,
        peer,
        answerer,
        dead: dead.clone(),
        last_activity: last_activity.clone(),
        first_data: first_data.clone(),
        max_payload,
    };

    spawn_reader(
        peer_id,
        recv,
        tx,
        last_activity,
        dead,
        first_data,
        max_payload,
    );

    Ok(transport)
}

async fn read_hello(
    recv: &mut RecvStream,
    expected_endpoint: EndpointId,
    expected_device: Option<[u8; 32]>,
) -> Result<IrohBinding> {
    let mut header = [0u8; 5];
    recv.read_exact(&mut header)
        .await
        .map_err(|error| anyhow!("read hello header: {error}"))?;
    let kind = header[0];
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if kind != KIND_HELLO {
        bail!("first iroh frame was kind {kind}, expected hello");
    }
    if len == 0 || len > MAX_HELLO {
        bail!("iroh hello length {len} out of range");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| anyhow!("read hello body: {error}"))?;
    let value: Value = serde_json::from_slice(&body).context("iroh hello is not JSON")?;
    let binding = IrohBinding::from_json(&value).context("iroh hello is not a binding")?;
    binding.verify().context("iroh binding signature")?;
    if binding.endpoint_id != expected_endpoint {
        bail!(
            "iroh binding names node {}, but the TLS handshake authenticated {}",
            binding.endpoint_id,
            expected_endpoint
        );
    }
    if let Some(expected) = expected_device {
        if binding.device_pub != expected {
            bail!(
                "iroh peer presented device {}, expected {}",
                hex::encode(binding.device_pub),
                hex::encode(expected)
            );
        }
    }
    Ok(binding)
}

async fn write_frame(send: &mut SendStream, kind: u8, body: &[u8]) -> Result<()> {
    if body.len() > u32::MAX as usize {
        bail!("frame body too large");
    }
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..5].copy_from_slice(&(body.len() as u32).to_be_bytes());
    send.write_all(&header)
        .await
        .map_err(|error| anyhow!("write frame header: {error}"))?;
    send.write_all(body)
        .await
        .map_err(|error| anyhow!("write frame body: {error}"))?;
    Ok(())
}

fn spawn_reader(
    peer_id: String,
    mut recv: RecvStream,
    tx: UnboundedSender<Ev>,
    last_activity: Arc<AtomicU64>,
    dead: Arc<AtomicBool>,
    first_data: Arc<AtomicBool>,
    max_payload: usize,
) {
    tokio::spawn(async move {
        // A frame is at most payload + the 12-byte sid/offset prefix; the guard
        // is a little wider so a control frame is never rejected.
        let max_frame = max_payload.saturating_add(64);
        loop {
            let mut header = [0u8; 5];
            match recv.read_exact(&mut header).await {
                Ok(()) => {}
                Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => break,
                Err(error) => {
                    filament_transport::hooks::debug(&format!(
                        "iroh reader {peer_id}: header error: {error}"
                    ));
                    dead.store(true, Ordering::Relaxed);
                    break;
                }
            }
            let kind = header[0];
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if len > max_frame {
                filament_transport::hooks::debug(&format!(
                    "iroh reader {peer_id}: absurd frame length {len} (max {max_frame})"
                ));
                dead.store(true, Ordering::Relaxed);
                break;
            }
            let mut body = vec![0u8; len];
            match recv.read_exact(&mut body).await {
                Ok(()) => {}
                Err(iroh::endpoint::ReadExactError::FinishedEarly(_)) => break,
                Err(error) => {
                    filament_transport::hooks::debug(&format!(
                        "iroh reader {peer_id}: body error: {error}"
                    ));
                    dead.store(true, Ordering::Relaxed);
                    break;
                }
            }

            match kind {
                KIND_CONTROL => {
                    if let Ok(value) = serde_json::from_slice::<Value>(&body) {
                        let _ = tx.send(Ev::Control(peer_id.clone(), value));
                    }
                }
                KIND_DATA if body.len() >= 12 => {
                    last_activity.store(now_ms(), Ordering::Relaxed);
                    first_data.store(true, Ordering::Relaxed);
                    let sid = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let offset = u64::from_be_bytes([
                        body[4], body[5], body[6], body[7], body[8], body[9], body[10], body[11],
                    ]);
                    let bytes = Bytes::from(body);
                    let _ = tx.send(Ev::Chunk(
                        peer_id.clone(),
                        sid,
                        Some(offset),
                        bytes.slice(12..),
                    ));
                }
                // A duplicate hello or an unknown kind is ignored: it is not
                // application data, and refusing the whole link for it would be
                // a denial-of-service win for the sender.
                _ => {}
            }
        }
    });
}

fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    #[test]
    fn frame_header_is_the_existing_wire_shape() {
        // [kind][u32 BE length], body [sid][offset][payload]. This is the
        // contract the direct and data-channel transports already speak.
        let mut body = Vec::new();
        body.extend_from_slice(&7u32.to_be_bytes());
        body.extend_from_slice(&42u64.to_be_bytes());
        body.extend_from_slice(b"hello");
        let mut header = [0u8; 5];
        header[0] = KIND_DATA;
        header[1..5].copy_from_slice(&(body.len() as u32).to_be_bytes());
        assert_eq!(header[0], 1);
        assert_eq!(
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
            17
        );
    }

    #[test]
    fn config_rejects_a_payload_over_the_ceiling() {
        // A bind with an invalid config must fail before touching the network.
        let config = IrohConfig {
            max_payload: MAX_PAYLOAD + 1,
            ..IrohConfig::default()
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(IrohNode::bind(
                DeviceIdentity::from_seed(&[3u8; 32]),
                config,
            ))
            .unwrap_err();
        assert!(error.to_string().contains("max_payload"));
    }

    #[test]
    fn channel_binding_label_is_versioned() {
        assert!(CHANNEL_BINDING_LABEL.ends_with(b"/v1"));
    }
}
