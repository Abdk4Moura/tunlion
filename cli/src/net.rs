// Networking plumbing: /api config fetch, Socket.IO signaling, the WebRTC
// peer, and the Transport abstraction the transfer logic rides on.
//
// Transport is a trait on purpose: the control protocol (JSON text + sid-framed
// binary) is transport-agnostic. DataChannelTransport is implementation #1;
// a QUIC transport for CLI<->CLI bulk speed slots in later without touching
// the transfer logic.
//
// Resilience parity with the browser (docs/cli-resilience.md):
//   C3 establishment watchdog  -> Peer::connect spawns a 15s timer -> Ev::Stuck
//   C4 transient 'disconnected'-> surfaced as PcState; main loop graces + retries
//   C8a backpressure           -> event-driven via on_buffered_amount_low

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use rust_socketio::asynchronous::{Client, ClientBuilder};
use rust_socketio::{Event as SioEvent, Payload, TransportType};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data::data_channel::DataChannel as RawDataChannel;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::signaling_state::RTCSignalingState;
use webrtc::peer_connection::RTCPeerConnection;

/// SCTP default max message size is 65535; keep payload + 4-byte header under it.
pub const MAX_DC_PAYLOAD: usize = 60 * 1024;
const HIGH_WATER: usize = 4 * 1024 * 1024;
const LOW_WATER: usize = 1024 * 1024;
pub const WATCHDOG_SECS: u64 = 15;

/// P0 (GAP-1): default no-progress threshold (ms) for the bytes-moved stall
/// watchdog. An in-flight transfer whose link's `idle_ms()` exceeds this, while
/// the control channel is still alive, is declared STALLED (the 0% hang). 6 s
/// sits well above a slow-but-moving link's inter-chunk gap on a bad mobile
/// uplink (the threshold is on *time since the last byte*, never on throughput,
/// so a slow link that still advances resets it) and well below human patience.
/// Overridable via `FILAMENT_STALL_MS`, mirroring the `FILAMENT_ADOPT_ACTIVE_MS`
/// / `FILAMENT_REJOIN_SECS` knob style.
pub const STALL_MS_DEFAULT: u64 = 6_000;

/// Read the configured stall threshold (`FILAMENT_STALL_MS`, default 6 s).
pub fn stall_ms() -> u64 {
    std::env::var("FILAMENT_STALL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(STALL_MS_DEFAULT)
}

/// P0 (GAP-1) FOLLOW-UP: the BEFORE-FIRST-BYTE grace (ms). The 6 s stall
/// threshold is calibrated for a *flowing* transfer's inter-chunk gap, but a
/// link that has not yet delivered its first data byte is still ESTABLISHING:
/// over a TURN relay at a high RTT (e.g. a phone on a slow mobile uplink, ~700 ms
/// RTT) the TURN allocation + ICE checks + DTLS/SCTP handshake + the first
/// chunk's round trip routinely exceed 6 s. Charging that one-time setup cost as
/// a "stall" makes the watchdog tear the link down and rebuild it, and the
/// rebuild's setup ALSO exceeds 6 s, so it loops forever and zero bytes ever
/// land (the exact "stuck at N%" the watchdog was meant to PREVENT). So until a
/// link moves its first data byte (`Transport::has_flowed`) we give it this much
/// larger grace; once bytes flow, the tight `stall_ms` applies. Each fresh
/// transport (e.g. after a repair) re-earns the grace. Overridable via
/// `FILAMENT_ESTABLISH_GRACE_MS`.
pub const ESTABLISH_GRACE_MS_DEFAULT: u64 = 45_000;

/// Read the before-first-byte establishment grace (`FILAMENT_ESTABLISH_GRACE_MS`,
/// default 45 s). Never below `stall_ms()` (a smaller grace would defeat itself).
pub fn establish_grace_ms() -> u64 {
    std::env::var("FILAMENT_ESTABLISH_GRACE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(ESTABLISH_GRACE_MS_DEFAULT)
        .max(stall_ms())
}

/// P2 (GAP-2): how long a long-lived acceptor's signaling link may go SILENT
/// (no inbound socket.io event AND no successful `sync` ack) before the outer
/// reconnect loop declares it dead and re-dials. The session ticks a `sync`
/// every ≤5 s and the server acks it with `synced`, so a healthy link is never
/// silent this long; a severed TCP (the flaky proxy) produces no events at all,
/// so the silence climbs past this and trips the re-announce. Well above the 5 s
/// sync cadence (so a single slow ack never false-trips) and well below the
/// minute-scale rediscovery latency the supervisor's cadence imposed.
/// Overridable via `FILAMENT_SIGNALING_SILENCE_MS`.
pub const SIGNALING_SILENCE_MS_DEFAULT: u64 = 15_000;

/// Read the configured signaling-silence threshold (`FILAMENT_SIGNALING_SILENCE_MS`).
pub fn signaling_silence_ms() -> u64 {
    std::env::var("FILAMENT_SIGNALING_SILENCE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(SIGNALING_SILENCE_MS_DEFAULT)
}

/// P3 (GAP-3): is the WARM redundant transport opt-in override set?
///
/// Warm redundancy keeps one alternate transport READY so a detected stall cuts
/// over INSTANTLY (rung b) instead of paying the cold re-establish latency of
/// the direct-repair rungs (a)/(c). It costs a second live path, so it is
/// SELECTIVE: ON only for long-lived / interactive sessions (PTY, L2 tunnels,
/// `up --shell` acceptors), OFF for one-shot file `send` (the P0/P1 ladder is
/// already fine there, the on-disk partial + resume make a cold repair correct
/// and bounded, and a warm standby isn't worth a second socket for a single
/// transfer).
///
/// The session kind decides the default (set on `Conn::warm_standby` at
/// construction). This knob is the explicit override:
///   `FILAMENT_WARM_STANDBY=1` forces it ON  (e.g. a sustained transfer standing
///                                            in for an interactive session in a
///                                            test / power-user case),
///   `FILAMENT_WARM_STANDBY=0` forces it OFF (kill switch / A-B baseline).
/// Returns `None` when unset, so the session-kind default stands.
pub fn warm_standby_override() -> Option<bool> {
    match std::env::var("FILAMENT_WARM_STANDBY").ok().as_deref() {
        Some("1") | Some("true") | Some("on") => Some(true),
        Some("0") | Some("false") | Some("off") => Some(false),
        _ => None,
    }
}

// --- P5 (GAP-6): relay->direct auto-upgrade prober knobs ---------------------
//
// P1 makes a peer FALL to relay when direct stalls; `relay_committed` then stops
// the known-bad direct path from re-winning the race during cutover. But that
// makes relay a ONE-WAY TRAPDOOR: once on relay the peer STAYS there even after
// the network heals and direct would work again. P5 fixes that: a background
// prober keeps probing for a direct path while serving on relay and SEAMLESSLY
// upgrades back when one is confirmed STABLE (verify-before-upgrade). Relay
// becomes a way-station, not a destination.

/// Is the relay->direct upgrade prober ENABLED? (`FILAMENT_UPGRADE_PROBE=0`
/// disables it, the kill switch the resilience plan calls for. Default ON.)
/// A no-op under `--no-relay` (that path never reaches relay) regardless of
/// this knob, the caller also gates on `relay_forbidden()`.
pub fn upgrade_prober_enabled() -> bool {
    match std::env::var("FILAMENT_UPGRADE_PROBE").ok().as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        _ => true,
    }
}

/// FIRST direct re-probe delay after a peer falls to relay (ms). Soon, because
/// the cause is often transient (a momentary NAT/path hiccup that heals in
/// seconds). `FILAMENT_UPGRADE_FIRST_MS`, default ~5 s.
pub const UPGRADE_FIRST_MS_DEFAULT: u64 = 5_000;
pub fn upgrade_first_ms() -> u64 {
    std::env::var("FILAMENT_UPGRADE_FIRST_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(UPGRADE_FIRST_MS_DEFAULT)
}

/// STEADY re-probe cadence once direct keeps failing (ms). Backs off from the
/// eager first probe to a calm cadence so a symmetric-NAT peer that will NEVER
/// get direct doesn't get hammered (CPU/battery). `FILAMENT_UPGRADE_STEADY_MS`,
/// default ~25 s. The schedule is: first probe at `first_ms`, then each failed
/// probe doubles the interval toward this cap.
pub const UPGRADE_STEADY_MS_DEFAULT: u64 = 25_000;
pub fn upgrade_steady_ms() -> u64 {
    std::env::var("FILAMENT_UPGRADE_STEADY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(UPGRADE_STEADY_MS_DEFAULT)
}

/// VERIFY-before-upgrade window (ms): once a direct standby CONNECTS alongside
/// the live relay link, it must move real data CONTINUOUSLY for at least this
/// long before we cut over. Prevents thrash on a flaky direct path that
/// connects then immediately re-stalls. `FILAMENT_UPGRADE_VERIFY_MS`, default
/// ~2.5 s of sustained progress.
pub const UPGRADE_VERIFY_MS_DEFAULT: u64 = 2_500;
pub fn upgrade_verify_ms() -> u64 {
    std::env::var("FILAMENT_UPGRADE_VERIFY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(UPGRADE_VERIFY_MS_DEFAULT)
}

/// VERIFY-before-upgrade idle guard (ms): during the verify window, if the
/// direct standby goes idle for this long it is judged regressed and DISCARDED
/// (we stay on relay). Tighter than `stall_ms` so a flaky standby fails fast.
/// `FILAMENT_UPGRADE_VERIFY_IDLE_MS`, default ~1.2 s.
pub const UPGRADE_VERIFY_IDLE_MS_DEFAULT: u64 = 1_200;
pub fn upgrade_verify_idle_ms() -> u64 {
    std::env::var("FILAMENT_UPGRADE_VERIFY_IDLE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(UPGRADE_VERIFY_IDLE_MS_DEFAULT)
}

// ------------------------------------------------------------------ events --

#[derive(Debug)]
pub enum Ev {
    Welcome(Value),
    PeerJoined(Value),
    PeerLeft(Value),
    Signal(Value),
    PairCode(Value),
    /// L1-a: v2 nameplate-allocation ack (server allocated our nameplate; it
    /// echoes NO words, the creator displays its own locally-minted code).
    PairOk(Value),
    PairMatched(Value),
    #[allow(dead_code)] // payload is {code}; senders only need the wake-up
    PairUsed(Value),
    PairError(Value),
    /// C12: a mutually-known device appeared on a shared presence channel.
    KnownPeer(Value),
    #[allow(dead_code)] // payload is {id,channel}; presence UIs will want it
    KnownPeerLeft(Value),
    /// C30: the server's session digest (mirror of the sync ack)
    Synced(Value),
    /// The silence-watchdog heartbeat's ACK came back: the signaling socket is
    /// alive even though no application event has flowed. A room-less idle
    /// acceptor (`up`) gets no `synced` EVENT (the server emits that only for a
    /// room) and this loop is events-only, so without an ack-driven liveness
    /// signal the watchdog falsely declared a healthy idle link dead every ~30 s
    /// and reconnected, churning presence for every known device.
    SignalingAlive,
    /// (peer sid, ...), every channel event is attributed to its link so
    /// the loops can hold many links at once (C18 multi-link).
    ChannelReady(String, Arc<dyn Transport>),
    /// rung-1 direct path (FILAMENT_DIRECT): an AUTHENTICATED QUIC transport for
    /// (peer sid) won the simultaneous-open race and passed the pair-secret MAC.
    /// Handled like ChannelReady but the link is pre-trusted (the MAC already
    /// proved the secret, stronger than the post-DC pair-proof), so the
    /// DTLS-bound pair-proof dance is skipped.
    /// (peer sid, transport, route label). The route label is `direct-quic`
    /// (rung-1) or `holepunched` (rung-2), a direct link has no WebRTC
    /// `route()` to query, so the winning rung tells us which path it used.
    DirectReady(String, Arc<dyn Transport>, &'static str),
    /// P5 (GAP-6): a relay->direct UPGRADE probe's fresh authenticated direct
    /// transport CONNECTED alongside the live relay link (peer sid, transport,
    /// route label). Unlike `DirectReady` this MUST NOT clobber the serving relay
    /// link: the handler stashes it as a warm DIRECT standby and runs the
    /// verify-before-upgrade dance, only cutting over once it is confirmed moving
    /// data. Distinct event so the normal `adopt_direct` path is never reached for
    /// a probe.
    DirectUpgradeReady(String, Arc<dyn Transport>, &'static str),
    Control(String, Value),
    Chunk(String, u32, Bytes),
    PcState(String, String),
    /// A local outgoing stream finished (sent by the streaming task so the
    /// main loop re-evaluates its all-done exit condition).
    #[allow(dead_code)] // id kept for symmetry with TransferFailed
    TransferDone(String),
    /// A local outgoing stream failed; the transfer stays pending so it can
    /// be re-offered (resume) on the next channel (C10: no process::exit).
    TransferFailed { id: String, err: String },
    /// C3: the establishment watchdog fired for (peer sid, attempt generation).
    Stuck(String, u32),
    /// P0 (GAP-1): the bytes-moved watchdog declared an in-flight transfer
    /// STALLED, the link is open and its control channel is alive (liveness
    /// probe passed) but `idle_ms()` crossed the stall threshold, i.e. the data
    /// path is moving zero bytes (the "stuck at 0%" hang). Carries (peer sid,
    /// link_idle_ms) and drives the least-disruptive correction ladder in the
    /// main loop, never the establishment retry path. Distinct from `Stuck`
    /// (establishment never completed) and `GraceExpired` (the link itself died).
    TransferStalled(String, u64),
    /// C4: the 6s disconnected-grace timer expired for (peer sid, generation).
    GraceExpired(String, u32),
    /// P2 (GAP-2): the signaling socket reported a clean close/error (the
    /// socket.io `close`/`error` callbacks). A FAST-PATH hint that the link is
    /// gone, the long-lived acceptor's outer reconnect loop re-dials signaling
    /// and re-announces. NOTE this fires only on a server-sent disconnect or a
    /// protocol error; a hard TCP sever (the flaky-proxy case) produces NO
    /// callback at all, so the silence watchdog (`signaling_silence_ms`) is the
    /// authoritative trigger and this is purely an accelerant.
    #[allow(dead_code)] // reason kept for logs/debug; the loop only needs the wake-up
    SignalingDown(String),
    /// Ctrl-C: park state, print the resume hint, leave cleanly.
    Interrupted,
    /// A line typed into a listening recv (claim-a-code convenience).
    StdinLine(String),
}

impl std::fmt::Debug for dyn Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transport")
    }
}

// --------------------------------------------------------------- transport --

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_control(&self, msg: &Value) -> Result<()>;
    /// Frame and send one chunk: [u32 BE sid][payload]. Applies backpressure.
    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()>;
    /// Resolve once all queued bytes are flushed to the wire.
    async fn flush(&self) -> Result<()>;
    /// FINAL-teardown drain: block until the peer has acknowledged *all* written
    /// bytes, then end the send direction. Distinct from `flush()`, which is
    /// called per-file (after each `file-end`) and must NOT end the stream.
    /// Default delegates to `flush()`, correct for the DataChannel transport,
    /// whose `flush()` already polls `buffered_amount` to zero before exit. The
    /// direct-QUIC transport overrides this: dropping a quinn connection discards
    /// un-acked send-buffer bytes, so a no-op here truncates the tail of the last
    /// file on any link slower than loopback (the cross-machine bug).
    async fn drain_finish(&self) -> Result<()> {
        self.flush().await
    }
    fn max_payload(&self) -> usize;
    /// Which half of the L2 sid space THIS end allocates from. Both ends of a
    /// link MUST return opposite values (derived from the deterministic `polite`
    /// role) so a sid this end allocates can never equal one the peer allocated —
    /// otherwise, when BOTH ends open L2 streams on one link (e.g. a pty plus a
    /// warm-reuse forward sharing the up-daemon's link), their sids collide and
    /// frames cross between unrelated tunnels. Default `false` (the low half);
    /// real transports return the role-derived bit.
    fn sid_answerer(&self) -> bool {
        false
    }
    /// Milliseconds since this link last moved a byte. `u64::MAX` means "no
    /// activity tracked / idle forever", the safe default, so an untracked
    /// transport never blocks a supersede. Backs the #28 data-flow guard.
    fn idle_ms(&self) -> u64 {
        u64::MAX
    }
    /// Best-effort liveness: `false` if the underlying connection is known closed.
    /// Default `true` (untracked transports are assumed live). Warm-link reuse
    /// consults this so it never opens a stream over a dead/zombie link (and falls
    /// back to a fresh establish instead). A direct-QUIC link reports its real
    /// state; with keepalive a dead peer is detected and this flips within ~30s.
    fn is_alive(&self) -> bool {
        true
    }
    /// The literal remote socket address the underlying connection is pinned to
    /// (the `IP:port` `filament ping` shows for a direct link). `None` for a
    /// transport with no single socket endpoint (a relay/DataChannel link, whose
    /// path is the ICE-selected candidate pair, not one UDP 5-tuple).
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
    /// Smoothed round-trip time of the underlying connection in ms, when the
    /// transport measures one. Direct-QUIC reports quinn's estimate (free, no peer
    /// cooperation); `None` for transports that don't measure RTT themselves.
    fn rtt_ms(&self) -> Option<u64> {
        None
    }
    /// Local IP this transport's socket is bound to (so `filament ping` can name
    /// the network INTERFACE the path uses — tailscale0 / eth0 / docker0). Direct-
    /// QUIC reports quinn's local_ip; `None` for transports that don't expose it
    /// (a relay/DataChannel link's local candidate is read from the ICE pair).
    fn local_ip(&self) -> Option<std::net::IpAddr> {
        None
    }
    /// Has this transport ever moved a DATA byte (not just control)? Backs the
    /// before-first-byte establishment grace (`establish_grace_ms`): a link still
    /// awaiting its first chunk is establishing, not stalled. Default `true`
    /// (untracked transports use the normal threshold); the DataChannel transport
    /// reports its real first-data flag.
    fn has_flowed(&self) -> bool {
        true
    }
}

// The channel is DETACHED (SettingEngine::detach_data_channels): webrtc-rs's
// managed read loop has a hardcoded 65535-byte buffer (DATA_CHANNEL_BUFFER_SIZE)
// that an inbound browser frame of 64 KiB + 4 overflows, killing the channel
// (ledger C1). Detaching lets us read with our own 1 MiB buffer, matching the
// `a=max-message-size` we advertise.
const READ_BUF: usize = 1 << 20;

/// Milliseconds since a process-wide monotonic epoch. Backs data-flow recency:
/// it lets `maybe_adopt`/`on_peer_left` tell an actively-transferring link from
/// a frozen-alive one (gate 11's SIGSTOP'd receiver vs #28's live reconnect).
/// Monotonic on purpose, an NTP wall-clock step must not flip a recency check.
fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

pub struct DataChannelTransport {
    raw: Arc<RawDataChannel>,
    drained: Arc<Notify>,
    dead: Arc<std::sync::atomic::AtomicBool>, // set by the read loop on EOF/error
    // Monotonic ms-stamp of the last byte that actually moved (send_frame write
    // returned Ok, or the read loop delivered a frame). #28: a same-uid
    // signaling reconnect must not supersede a link whose data channel, which
    // is independent of the socket, is still flowing.
    last_activity: Arc<std::sync::atomic::AtomicU64>,
    // Flips true the first time a DATA frame moves in either direction. Backs the
    // before-first-byte establishment grace (a link awaiting its first chunk over
    // a high-RTT relay is establishing, not stalled).
    first_data: Arc<std::sync::atomic::AtomicBool>,
    // The `polite` role for this link (opposite on the two ends). Selects which
    // half of the L2 sid space this end allocates from, so the two ends never
    // collide (Transport::sid_answerer).
    answerer: bool,
}

impl DataChannelTransport {
    fn is_dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl Transport for DataChannelTransport {
    async fn send_control(&self, msg: &Value) -> Result<()> {
        if self.is_dead() {
            return Err(anyhow!("channel closed"));
        }
        self.raw
            .write_data_channel(&Bytes::from(msg.to_string()), true)
            .await?;
        Ok(())
    }

    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&sid.to_be_bytes());
        framed.extend_from_slice(payload);
        // Event-driven backpressure (C8a): park on the buffered-amount-low
        // notification instead of sleep-polling. Re-check after registering
        // to close the notify race. The read loop notifies on death, so a
        // sender parked on a dying channel wakes up and errors out.
        loop {
            if self.is_dead() {
                return Err(anyhow!("channel closed"));
            }
            if self.raw.buffered_amount() <= HIGH_WATER {
                break;
            }
            let notified = self.drained.notified();
            if self.raw.buffered_amount() <= HIGH_WATER {
                break;
            }
            notified.await;
        }
        self.raw
            .write_data_channel(&Bytes::from(framed), false)
            .await?;
        // Stamp at the unambiguous "bytes moved" point: the write returned Ok.
        // A frozen receiver (gate 11) stalls send_frame in the backpressure park
        // above, so this never fires and the link goes idle, exactly the signal
        // that lets the supersede proceed for frozen-alive but not for flowing.
        self.last_activity
            .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
        self.first_data
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // Tail-drain only; polling is fine for the final few buffers.
        while self.raw.buffered_amount() > 0 {
            if self.is_dead() {
                return Err(anyhow!("channel closed while flushing"));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn max_payload(&self) -> usize {
        MAX_DC_PAYLOAD
    }

    fn idle_ms(&self) -> u64 {
        // A dead channel has been idle forever, never let a recent-but-now-dead
        // stamp keep a link reading as "flowing". Without this, a same-uid
        // supersede could be skipped for an old link that just died (its last
        // stamp still fresh), keeping a dead link instead of swapping to the new
        // sid. The `dead` flag is the unambiguous "channel gone" signal.
        if self.is_dead() {
            return u64::MAX;
        }
        now_ms().saturating_sub(self.last_activity.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn has_flowed(&self) -> bool {
        self.first_data.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Real liveness for a DataChannel/relay link (the base trait defaults to
    /// `true`, which let warm-reuse open a stream over a dead relay link and hang).
    /// The read loop already sets `dead` on EOF/error, so expose it: unlike
    /// direct-QUIC there is no keepalive here, so this `dead` flag plus the
    /// idle-staleness gate in `warm_link_for` are what keep warm-reuse off a
    /// silently-evicted relay path.
    fn is_alive(&self) -> bool {
        !self.is_dead()
    }

    fn sid_answerer(&self) -> bool {
        self.answerer
    }
}

// ----------------------------------------------------------- DNS happy-eyes --
//
// Why this exists: on some hosts (notably a multi-homed systemd-resolved box
// with both a LAN resolver and Tailscale MagicDNS) the FIRST `getaddrinfo` of
// the signaling host after the resolver state goes cold stalls ~5 s before it
// answers, even though each upstream server answers in milliseconds when asked
// directly. Every `filament ssh`/`send`/`recv` is a fresh process, so its DNS
// cache is cold and that stall lands squarely on the signaling phase (measured
// 5.6 s vs a ~0.5 s warm connect, blowing the 1.2 s budget).
//
// The fix is in-app and helps every user, not just that box: after a connect
// succeeds we remember the host's resolved IPs in the config dir, and on the
// next connect we RACE a fresh OS resolution against the cached IPs. A slow
// resolver can no longer gate the connection, the cached IP wins the race and
// the connect proceeds in ~0.5 s; the fresh resolution, when it lands, refreshes
// the cache. TLS SNI / Host stay the original hostname (we only steer which IP
// the TCP connect targets, via reqwest `resolve_to_addrs`), so certificate
// validation is unchanged. The cached IP is never trusted blindly: it is only
// ever an alternate connect target for the same hostname+TLS, and the fresh
// resolution always runs alongside it.

/// Bounded wait for the fresh OS resolution before the cached IPs are allowed
/// to win the race outright. Comfortably above a healthy resolver's answer
/// (single-digit to low-hundreds ms) and well below the ~5 s cold stall, so a
/// healthy box always uses fresh DNS and only a stalling resolver falls back to
/// the cache. Overridable via `FILAMENT_DNS_RACE_MS`.
const DNS_RACE_MS_DEFAULT: u64 = 700;

fn dns_race_ms() -> u64 {
    std::env::var("FILAMENT_DNS_RACE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DNS_RACE_MS_DEFAULT)
}

/// Hard cap on the fresh OS resolution itself, so our own pre-resolve can never
/// hang the process even when the cache is empty (first ever connect from a box
/// with the cold-resolver stall). Above the observed worst case (~7.4 s) with
/// headroom. Overridable via `FILAMENT_DNS_TIMEOUT_MS`.
const DNS_TIMEOUT_MS_DEFAULT: u64 = 9_000;

fn dns_timeout_ms() -> u64 {
    std::env::var("FILAMENT_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DNS_TIMEOUT_MS_DEFAULT)
}

fn dns_cache_path() -> PathBuf {
    let base = if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        PathBuf::from(d)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".config/filament")
    };
    base.join("signaling-dns.json")
}

/// Pull `host` and `port` out of an `http(s)://` URL for resolution. Returns the
/// conventional port for the scheme when none is given. Pure (no I/O) so the
/// parse is unit-testable.
pub(crate) fn host_port_from_url(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    // Strip path/query, keep only the authority.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any userinfo.
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" | "wss" => 443,
        "http" | "ws" => 80,
        _ => return None,
    };
    // IPv6 literal: [::1]:443
    if let Some(hp) = hostport.strip_prefix('[') {
        let (h, after) = hp.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((h.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port = p.parse::<u16>().unwrap_or(default_port);
            Some((h.to_string(), port))
        }
        _ => Some((hostport.to_string(), default_port)),
    }
}

/// Parse a persisted DNS-cache document for `host` into usable `SocketAddr`s at
/// `port`. The document is `{ "<host>": ["ip", ...], ... }`. Pure (no I/O) so
/// selection is unit-testable; robust to a missing host / malformed entries.
pub(crate) fn cached_addrs_from_doc(doc: &Value, host: &str, port: u16) -> Vec<SocketAddr> {
    doc.get(host)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        })
        .unwrap_or_default()
}

fn read_cached_addrs(host: &str, port: u16) -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string(dns_cache_path()) else {
        return Vec::new();
    };
    let Ok(doc) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    cached_addrs_from_doc(&doc, host, port)
}

/// Persist the freshly-resolved IPs for `host` (best-effort, never fatal). Reads
/// the existing doc so other hosts' entries survive.
fn write_cached_addrs(host: &str, addrs: &[SocketAddr]) {
    if addrs.is_empty() {
        return;
    }
    let path = dns_cache_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    let ips: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
    doc[host] = json!(ips);
    let _ = std::fs::write(&path, doc.to_string());
}

/// Resolve `host:port` to connect targets, immune to a cold-resolver stall.
///
/// Races a fresh OS resolution (capped at `dns_timeout_ms`) against the IPs
/// cached from a previous successful connect:
///   - Fresh resolution wins if it answers within `dns_race_ms` (the healthy
///     case): its result is returned AND written back to the cache.
///   - Otherwise the cached IPs are returned immediately so a stalling resolver
///     never gates the connect; the fresh resolution keeps running and updates
///     the cache when (if) it lands, for next time.
///   - No cache and a slow resolver: we wait out the fresh resolution (bounded
///     by `dns_timeout_ms`), the unavoidable first-ever-connect cost.
///
/// Returns the IPs to hand to reqwest `resolve_to_addrs`. An empty result means
/// "resolve normally" (caller omits the override and lets reqwest resolve).
/// Side effect: a successful fresh lookup also warms the OS resolver cache, so a
/// socket.io connect that resolves the same host moments later hits warm cache.
pub(crate) async fn resolve_warm(host: &str, port: u16) -> Vec<SocketAddr> {
    // Skip the dance for an IP literal: nothing to resolve or cache.
    if host.parse::<IpAddr>().is_ok() {
        return Vec::new();
    }
    let cached = read_cached_addrs(host, port);
    let host_owned = format!("{host}:{port}");
    let host_for_cache = host.to_string();
    let fresh = tokio::spawn(async move {
        let lookup = tokio::net::lookup_host(host_owned);
        match tokio::time::timeout(Duration::from_millis(dns_timeout_ms()), lookup).await {
            Ok(Ok(it)) => {
                let addrs: Vec<SocketAddr> = it.collect();
                if !addrs.is_empty() {
                    write_cached_addrs(&host_for_cache, &addrs);
                }
                addrs
            }
            _ => Vec::new(),
        }
    });

    if cached.is_empty() {
        // Nothing to fall back to: take whatever fresh resolution returns
        // (bounded inside the task by dns_timeout_ms). Empty => caller resolves
        // normally as a last resort.
        return fresh.await.unwrap_or_default();
    }

    // Have a fallback: give fresh DNS a short head start, else use the cache.
    match tokio::time::timeout(Duration::from_millis(dns_race_ms()), fresh).await {
        Ok(Ok(addrs)) if !addrs.is_empty() => addrs,
        // Fresh lost the race (still resolving) or failed: use the cache now.
        // The spawned task keeps running and refreshes the cache when it lands.
        _ => cached,
    }
}

// ------------------------------------------------------------- HTTP config --

#[derive(Clone)]
pub struct ServerConfig {
    pub ice_servers: Vec<RTCIceServer>,
    pub chunk_size: usize,
}

/// True when an ICE server is STUN-only (no relay). `--no-relay` keeps only these
/// so the connection can still discover its public address (srflx) but can never
/// fall onto a TURN relay. A server whose every url is `stun:` is relay-free; a
/// `turn:`/`turns:` url makes it a relay.
pub fn is_stun_only(s: &RTCIceServer) -> bool {
    !s.urls.is_empty()
        && s.urls.iter().all(|u| {
            let u = u.trim().to_ascii_lowercase();
            u.starts_with("stun:") || u.starts_with("stuns:")
        })
}

/// C5: callers fetch this fresh before EVERY peer connection, TURN
/// credentials are expiry-stamped HMACs and go stale in long-lived processes.
pub async fn fetch_config(server: &str) -> Result<ServerConfig> {
    let body: Value = http_get_json(&format!("{server}/api/config")).await?;
    let mut ice_servers = Vec::new();
    if let Some(arr) = body["iceServers"].as_array() {
        for s in arr {
            let urls: Vec<String> = match &s["urls"] {
                Value::String(u) => vec![u.clone()],
                Value::Array(us) => us
                    .iter()
                    .filter_map(|u| u.as_str().map(|x| x.to_string()))
                    .collect(),
                _ => continue,
            };
            ice_servers.push(RTCIceServer {
                urls,
                username: s["username"].as_str().unwrap_or_default().to_string(),
                credential: s["credential"].as_str().unwrap_or_default().to_string(),
            });
        }
    }
    let chunk_size = body["chunkSize"].as_u64().unwrap_or(64 * 1024) as usize;
    Ok(ServerConfig {
        ice_servers,
        chunk_size: chunk_size.min(MAX_DC_PAYLOAD),
    })
}

pub async fn fetch_auto_room(server: &str) -> Result<String> {
    let body: Value = http_get_json(&format!("{server}/api/room")).await?;
    body["room"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no room in /api/room response"))
}

pub(crate) async fn http_get_json(url: &str) -> Result<Value> {
    // rust_socketio already pulls in reqwest; reuse it instead of adding a dep.
    // 3 quick attempts: establish() refetches config per connection attempt
    // (C5), and one blip of the API mustn't kill a transfer in progress.
    //
    // Happy-eyeballs DNS: resolve the host ourselves (cached IP raced against a
    // fresh lookup) so a cold-resolver stall can't gate the connect, then steer
    // reqwest at those IPs with `resolve_to_addrs`. Host/SNI stay the hostname,
    // so TLS verification is unchanged. Done once, reused across the 3 attempts.
    let host_port = host_port_from_url(url);
    let overrides = match &host_port {
        Some((host, port)) => {
            let addrs = resolve_warm(host, *port).await;
            (!addrs.is_empty()).then(|| (host.clone(), addrs))
        }
        None => None,
    };
    let mut last = None;
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        }
        // Explicit timeout: reqwest has none by default, and this is awaited
        // from the event loop, a hung GET must not freeze the process.
        let mut builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
        if let Some((host, addrs)) = &overrides {
            builder = builder.resolve_to_addrs(host, addrs);
        }
        let client = builder.build();
        let Ok(client) = client else { continue };
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(v) => return Ok(v),
                Err(e) => last = Some(anyhow!(e)),
            },
            Ok(resp) => last = Some(anyhow!("GET {url} -> {}", resp.status())),
            Err(e) => last = Some(anyhow!(e)),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("GET {url} failed"))).with_context(|| format!("GET {url}"))
}

// ---------------------------------------------------------------- signaling --

pub async fn connect_signaling(server: &str, tx: mpsc::UnboundedSender<Ev>) -> Result<Client> {
    // Warm the OS resolver cache before rust_socketio resolves the host itself.
    // rust_socketio's builder takes only a URL string (no DNS-override or custom
    // client hook), so we cannot steer its connect at a cached IP the way the
    // reqwest path can. What we CAN do is run our bounded happy-eyeballs resolve
    // first: on success it primes glibc/systemd-resolved so socket.io's own
    // immediately-following lookup hits warm cache (the common case), and it is
    // bounded so even a stalling resolver only adds `dns_race_ms`, not the full
    // ~5 s cold stall. In nearly every connect path `fetch_config` runs first and
    // has already warmed the cache, this just covers the socket.io-first paths.
    if let Some((host, port)) = host_port_from_url(server) {
        let _ = resolve_warm(&host, port).await;
    }

    let fwd = |variant: fn(Value) -> Ev, tx: mpsc::UnboundedSender<Ev>| {
        move |payload: Payload, _c: Client| {
            let tx = tx.clone();
            let v = match payload {
                Payload::Text(mut vals) if !vals.is_empty() => Some(vals.remove(0)),
                _ => None,
            };
            async move {
                if let Some(v) = v {
                    let _ = tx.send(variant(v));
                }
            }
            .boxed()
        }
    };

    // P2 (GAP-2): forward socket.io's close/error to the event loop as
    // Ev::SignalingDown. `down` carries a reason string but the loop only needs
    // the wake-up, the outer reconnect re-dials regardless of cause.
    let down = {
        let tx = tx.clone();
        move |reason: &'static str| {
            let tx = tx.clone();
            move |_p: Payload, _c: Client| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Ev::SignalingDown(reason.to_string()));
                }
                .boxed()
            }
        }
    };

    // We keep `reconnect(false)` ON PURPOSE (the explicit-outer-loop decision,
    // P2): socket.io's own reconnect would silently bring a FRESH sid back
    // without re-firing our join/subscribe/sync, and it can't be observed
    // cleanly from the event loop where the C-series perfect-negotiation / glare
    // handling lives. Owning the loop ourselves means every reconnect re-asserts
    // presence through the C30 session module on a fresh `welcome`, integrating
    // with the existing machinery rather than racing it. The triggers are the
    // close/error callbacks below (fast path) PLUS the silence watchdog in the
    // acceptor loop (the authoritative path, a hard TCP sever fires no callback).
    // Connect over a RAW websocket, never long-polling. The default
    // (TransportType::Any) handshakes on polling and only upgrades "if
    // possible"; behind Cloudflare the upgrade leg 400s, so it gets STUCK on
    // long-polling, where consecutive poll requests die and the server's 5 s
    // engine.io pings never arrive. The client then sees 30 s of silence, the
    // acceptor watchdog re-dials, and every reconnect re-announces presence to
    // every known device, a churn storm that prevents any link (ssh included)
    // from holding. A direct websocket (proven to traverse Cloudflare) carries
    // the pings reliably and removes the silence/reconnect cycle entirely.
    let sio = ClientBuilder::new(server)
        .transport_type(TransportType::Websocket)
        .reconnect(false)
        .on(SioEvent::Connect, |_p: Payload, _c: Client| async {}.boxed())
        .on(SioEvent::Close, down("close"))
        .on(SioEvent::Error, down("error"))
        .on("welcome", fwd(Ev::Welcome, tx.clone()))
        .on("peer-joined", fwd(Ev::PeerJoined, tx.clone()))
        .on("peer-left", fwd(Ev::PeerLeft, tx.clone()))
        .on("signal", fwd(Ev::Signal, tx.clone()))
        .on("pair-code", fwd(Ev::PairCode, tx.clone()))
        .on("pair-ok", fwd(Ev::PairOk, tx.clone()))
        .on("pair-matched", fwd(Ev::PairMatched, tx.clone()))
        .on("pair-used", fwd(Ev::PairUsed, tx.clone()))
        .on("pair-error", fwd(Ev::PairError, tx.clone()))
        .on("known-peer", fwd(Ev::KnownPeer, tx.clone()))
        .on("known-peer-left", fwd(Ev::KnownPeerLeft, tx.clone()))
        .on("synced", fwd(Ev::Synced, tx.clone()))
        .connect()
        .await
        .with_context(|| format!("socket.io connect to {server}"))?;
    Ok(sio)
}

/// P2 (GAP-2): re-dial signaling for a long-lived acceptor whose socket died.
/// A fresh `connect_signaling` with the SAME event sender, so the new client
/// emits into the same loop, gets a fresh `welcome`/sid, and the C30 session
/// module re-asserts room + channel subscriptions on the next tick. Returns the
/// new `Client` to swap into the loop's `conn.sio` / `sess` emit target. The
/// caller owns the backoff (so it can also keep ticking the rest of the loop).
pub async fn reconnect_signaling(server: &str, tx: mpsc::UnboundedSender<Ev>) -> Result<Client> {
    connect_signaling(server, tx).await
}

/// Silence-watchdog heartbeat: an ACK'd `sync` round-trip that proves the
/// signaling socket is alive WITHOUT depending on application traffic. The
/// server acks `sync` unconditionally (even a room-less / channel-only `up`,
/// whose ack is just `{ok:false}`), but it emits the `synced` EVENT only for a
/// room, and this loop consumes events only. So we listen for the ACK and turn
/// it into `Ev::SignalingAlive`. A live socket answers within the timeout and
/// the loop's liveness gap resets; a dead one never fires the callback and the
/// watchdog escalates to a reconnect. `emit_with_ack` only fails if the socket
/// is already gone, which the close/error fast-path handles, so errors here are
/// benign and swallowed.
pub async fn heartbeat(sio: &Client, payload: Value, tx: mpsc::UnboundedSender<Ev>) {
    let _ = sio
        .emit_with_ack(
            "sync",
            payload,
            std::time::Duration::from_secs(5),
            move |_p: Payload, _c: Client| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Ev::SignalingAlive);
                }
                .boxed()
            },
        )
        .await;
}

/// Subscribe to presence channels and DETERMINISTICALLY discover the members
/// already present, via the socket.io ACK rather than the async `known-peer`
/// push.
///
/// The server's `on_subscribe` returns `{ok, n, peers:[{id,name,uid,channel}]}`,
/// the live roster of every device already on the channel (signaling.py
/// `_do_subscribe`). It ALSO emits a one-shot async `known-peer` per existing
/// member, but that single push is lossy: if it dies in a half-open socket the
/// subscriber waits for a peer that, from its view, never appeared, and stalls
/// in "presence" forever (the dominant `filament ssh` establishment failure,
/// reproduced as ~40% of pop-os->do-vm attempts). The `up` acceptor never hit
/// this because its `sync` tick re-subscribes on a cadence AND reconciles the
/// digest roster; the one-shot L2 initiator (`bring_up_to_known`) did neither.
///
/// This mirrors `heartbeat`: emit-with-ack, then turn each ack roster entry into
/// an `Ev::KnownPeer` so the loop's existing dedup / self-filter / queue logic
/// handles it on the SAME path as the async push (idempotent, so a roster entry
/// that also arrives as an async push is harmless). `emit_with_ack` only fails
/// if the socket is already gone; errors are benign and swallowed (the caller's
/// re-subscribe cadence retries).
pub async fn subscribe_with_ack(sio: &Client, channels: Vec<String>, tx: mpsc::UnboundedSender<Ev>) {
    let _ = sio
        .emit_with_ack(
            "subscribe",
            json!({ "channels": channels }),
            std::time::Duration::from_secs(5),
            move |payload: Payload, _c: Client| {
                let tx = tx.clone();
                async move {
                    if let Payload::Text(vals) = payload {
                        for p in roster_from_ack(&vals) {
                            let _ = tx.send(Ev::KnownPeer(p));
                        }
                    }
                }
                .boxed()
            },
        )
        .await;
}

/// Pull the `peers` roster entries out of a `subscribe` ACK payload. The ack is
/// `{ok, n, peers:[{id,name,uid,channel}]}`; each roster entry is shaped exactly
/// like an async `known-peer` push, so the caller can replay them through the
/// same `Ev::KnownPeer` path. Factored out so the (otherwise socket-bound)
/// forwarding is unit-testable. Robust to a missing/empty/non-array `peers`.
fn roster_from_ack(vals: &[Value]) -> Vec<Value> {
    vals.iter()
        .filter_map(|v| v["peers"].as_array())
        .flatten()
        .cloned()
        .collect()
}

// --------------------------------------------------------------------- peer --

/// Mirror of webrtc.js politeRole(): prefer stable uids, fall back to sids.
pub fn polite_role(my_uid: &str, peer_uid: Option<&str>, my_id: &str, peer_id: &str) -> bool {
    match peer_uid {
        Some(p) if p != my_uid => my_uid > p,
        _ => my_id > peer_id,
    }
}

pub struct Peer {
    pub id: String,
    pub polite: bool,
    pub pc: Arc<RTCPeerConnection>,
    state: Mutex<PeerSignalState>,
    sio: Client,
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// C20: DTLS cert fingerprints (ours, theirs) parsed from the SDP we
    /// exchange, pair-proofs are bound to them so a MITM'd channel (even by
    /// the signaling server) fails verification.
    fps: Mutex<(Option<String>, Option<String>)>,
}

/// Extract `a=fingerprint:...` from an SDP (normalized uppercase hex).
fn sdp_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=fingerprint:"))
        .map(|v| v.trim().to_uppercase())
}

struct PeerSignalState {
    pending_candidates: Vec<RTCIceCandidateInit>,
    has_remote: bool,
}

/// What `handle_signal` did with a relayed signal.
#[derive(Debug)]
pub enum SignalOutcome {
    Handled,
    /// Polite-side offer collision webrtc-rs can't roll back from: the owner
    /// must drop this Peer, rebuild the link as a responder (polite, no local
    /// offer), and re-apply the carried offer signal.
    Glare(Value),
}

impl Peer {
    /// Build the RTCPeerConnection, wire callbacks into `tx`, and (if impolite)
    /// create the data channel + offer, exactly the browser's PeerLink dance.
    /// `generation` tags watchdog events so stale timers from torn-down attempts are
    /// ignored by the main loop (C3).
    pub async fn connect(
        peer_id: String,
        polite: bool,
        ice_servers: Vec<RTCIceServer>,
        relay_only: bool,
        sio: Client,
        tx: mpsc::UnboundedSender<Ev>,
        generation: u32,
    ) -> Result<Arc<Peer>> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;
        let mut se = SettingEngine::default();
        se.detach_data_channels(); // C1: we run our own read loop (see READ_BUF)
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .with_setting_engine(se)
            .build();
        let pc = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers,
                ice_transport_policy: if relay_only {
                    RTCIceTransportPolicy::Relay
                } else {
                    RTCIceTransportPolicy::All
                },
                ..Default::default()
            })
            .await?,
        );

        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Trickle ICE -> relay each candidate.
        {
            let sio = sio.clone();
            let to = peer_id.clone();
            pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
                let sio = sio.clone();
                let to = to.clone();
                Box::pin(async move {
                    if let Some(c) = c {
                        if let Ok(init) = c.to_json() {
                            let _ = sio
                                .emit(
                                    "signal",
                                    json!({ "to": to, "data": { "type": "candidate", "candidate": init } }),
                                )
                                .await;
                        }
                    }
                })
            }));
        }

        {
            let tx = tx.clone();
            let closed = closed.clone();
            let pid = peer_id.clone();
            pc.on_peer_connection_state_change(Box::new(move |s| {
                if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = tx.send(Ev::PcState(pid.clone(), s.to_string()));
                }
                Box::pin(async {})
            }));
        }

        if !polite {
            let dc = pc.create_data_channel("filament", None).await?;
            wire_channel(peer_id.clone(), dc, tx.clone(), closed.clone(), polite).await;
            let offer = pc.create_offer(None).await?;
            pc.set_local_description(offer).await?;
            let ld = pc
                .local_description()
                .await
                .ok_or_else(|| anyhow!("no local description"))?;
            sio.emit(
                "signal",
                json!({ "to": peer_id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
            )
            .await
            .ok();
        } else {
            let tx = tx.clone();
            let closed = closed.clone();
            let pid = peer_id.clone();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let tx = tx.clone();
                let closed = closed.clone();
                let pid = pid.clone();
                Box::pin(async move {
                    wire_channel(pid, dc, tx, closed, polite).await;
                })
            }));
        }

        // C3: establishment watchdog. ICE only times out once descriptions are
        // exchanged; a lost offer would otherwise mean 'connecting' forever.
        {
            let pc = pc.clone();
            let tx = tx.clone();
            let pid = peer_id.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(WATCHDOG_SECS)).await;
                if !closed.load(std::sync::atomic::Ordering::Relaxed)
                    && pc.connection_state() != RTCPeerConnectionState::Connected
                {
                    let _ = tx.send(Ev::Stuck(pid, generation));
                }
            });
        }

        let peer = Arc::new(Peer {
            id: peer_id,
            polite,
            pc,
            state: Mutex::new(PeerSignalState {
                pending_candidates: Vec::new(),
                has_remote: false,
            }),
            sio,
            closed,
            fps: Mutex::new((None, None)),
        });
        // local fingerprint from whatever description we already sent (offer
        // path emits before Peer exists; capture lazily on first access too)
        if let Some(ld) = peer.pc.local_description().await {
            peer.fps.lock().await.0 = sdp_fingerprint(&ld.sdp);
        }
        Ok(peer)
    }

    pub fn is_connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }

    /// C4: nudge ICE recovery after a transient 'disconnected' (impolite side
    /// only, mirroring the browser).
    pub async fn restart_ice(&self) {
        let _ = self.pc.restart_ice().await;
        // restart_ice marks negotiation needed; drive the new offer ourselves
        // (webrtc-rs has no negotiationneeded auto-loop in this setup).
        if let Ok(offer) = self.pc.create_offer(None).await {
            if self.pc.set_local_description(offer).await.is_ok() {
                if let Some(ld) = self.pc.local_description().await {
                    let _ = self
                        .sio
                        .emit(
                            "signal",
                            json!({ "to": self.id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
                        )
                        .await;
                }
            }
        }
    }

    /// Silence callbacks immediately (synchronous, atomic) so a dying pc
    /// can't spam the event loop (browser fix #3, the CLI flavor).
    pub fn mark_closed(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Tear down. May block on network teardown against an unreachable peer,
    /// callers in the event loop must mark_closed() and spawn this, never
    /// await it inline (gate 11 deadlock).
    pub async fn close(&self) {
        self.mark_closed();
        let _ = self.pc.close().await;
    }

    /// Apply one relayed signal (description or candidate), browser-equivalent
    /// ordering rules: candidates buffer until a remote description lands.
    ///
    /// Offer-collision (glare) rules, mirroring webrtc.js perfect negotiation:
    /// the impolite side IGNORES a colliding offer (its own offer stands; the
    /// polite peer answers it), the polite side yields. webrtc-rs 0.17 cannot
    /// SetLocal(rollback) out of have-local-offer (the transition table has no
    /// arm for it), so the polite side can't recover in-place, it returns
    /// `Glare(offer)` and the OWNER of this Peer must rebuild the link as a
    /// pure responder and re-apply that offer.
    pub async fn handle_signal(&self, data: Value) -> Result<SignalOutcome> {
        match data["type"].as_str() {
            Some("description") => {
                let desc: RTCSessionDescription =
                    serde_json::from_value(data["description"].clone())
                        .context("parse remote description")?;
                let is_offer = desc.sdp_type.to_string() == "offer";
                let state = self.pc.signaling_state();
                if desc.sdp_type == RTCSdpType::Offer && state != RTCSignalingState::Stable {
                    if !self.polite {
                        return Ok(SignalOutcome::Handled); // their polite side yields
                    }
                    return Ok(SignalOutcome::Glare(data));
                }
                if desc.sdp_type == RTCSdpType::Answer
                    && state != RTCSignalingState::HaveLocalOffer
                {
                    // Stale answer (e.g. to an offer this side abandoned).
                    return Ok(SignalOutcome::Handled);
                }
                self.fps.lock().await.1 = sdp_fingerprint(&desc.sdp);
                self.pc.set_remote_description(desc).await?;
                let pending = {
                    let mut st = self.state.lock().await;
                    st.has_remote = true;
                    std::mem::take(&mut st.pending_candidates)
                };
                for c in pending {
                    if let Err(e) = self.pc.add_ice_candidate(c).await {
                        crate::ui::trace(&format!("filament: queued candidate failed: {e}"));
                    }
                }
                if is_offer {
                    let answer = self.pc.create_answer(None).await?;
                    self.pc.set_local_description(answer).await?;
                    let ld = self
                        .pc
                        .local_description()
                        .await
                        .ok_or_else(|| anyhow!("no local description"))?;
                    self.fps.lock().await.0 = sdp_fingerprint(&ld.sdp);
                    self.sio
                        .emit(
                            "signal",
                            json!({ "to": self.id, "data": { "type": "description", "description": advertise_max_message_size(&ld) } }),
                        )
                        .await
                        .ok();
                }
            }
            Some("candidate") => {
                let init: RTCIceCandidateInit =
                    serde_json::from_value(data["candidate"].clone()).context("parse candidate")?;
                let buffered = {
                    let mut st = self.state.lock().await;
                    if st.has_remote {
                        false
                    } else {
                        st.pending_candidates.push(init.clone());
                        true
                    }
                };
                if !buffered {
                    if let Err(e) = self.pc.add_ice_candidate(init).await {
                        crate::ui::trace(&format!("filament: addIceCandidate failed: {e}"));
                    }
                }
            }
            _ => {}
        }
        Ok(SignalOutcome::Handled)
    }

    /// C20: (our fp, their fp) once the handshake exchanged descriptions.
    pub async fn fingerprints(&self) -> Option<(String, String)> {
        {
            let mut f = self.fps.lock().await;
            if f.0.is_none() {
                if let Some(ld) = self.pc.local_description().await {
                    f.0 = sdp_fingerprint(&ld.sdp);
                }
            }
            if f.1.is_none() {
                if let Some(rd) = self.pc.remote_description().await {
                    f.1 = sdp_fingerprint(&rd.sdp);
                }
            }
            if let (Some(a), Some(b)) = (&f.0, &f.1) {
                return Some((a.clone(), b.clone()));
            }
        }
        None
    }

    /// Which physical path did ICE pick? Same taxonomy as the browser badge.
    /// C2 fix: read the agent's actual selected pair, and classify
    /// local-vs-direct by ADDRESS rather than candidate type, the answering
    /// side often sees its peer as prflx even on the same LAN, and what the
    /// badge promises is "bytes never leave your network", which is an
    /// address property.
    pub async fn route(&self) -> Option<&'static str> {
        let pair = self
            .pc
            .sctp()
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .await?;
        if pair.local.typ == RTCIceCandidateType::Relay
            || pair.remote.typ == RTCIceCandidateType::Relay
        {
            return Some("relayed");
        }
        // Same address on both ends = same machine (loopback via any of its
        // IPs, public included), bytes never leave the host.
        // "local" when bytes can't leave the machine/network: identical
        // addresses, the remote address being one of THIS host's own
        // addresses (multi-homed same-host pairs select different interfaces
        // nondeterministically), or both ends private.
        let same_host =
            pair.local.address == pair.remote.address || is_own_addr(&pair.remote.address);
        let both_private = is_private_addr(&pair.local.address) && is_private_addr(&pair.remote.address);
        Some(if same_host || both_private { "local" } else { "direct" })
    }

    /// The selected ICE pair's concrete endpoints, for `filament ping`/`doctor`
    /// to render the exact path (local↔remote address + candidate type + whether
    /// it's relayed). `route()` answers the policy question ("does it leave the
    /// network?"); this hands back the raw 5-tuple so the UI can name the
    /// interface and show the addresses instead of guessing.
    pub async fn path_detail(&self) -> Option<PathPair> {
        let pair = self
            .pc
            .sctp()
            .transport()
            .ice_transport()
            .get_selected_candidate_pair()
            .await?;
        let typ = |t: RTCIceCandidateType| {
            match t {
                RTCIceCandidateType::Host => "host",
                RTCIceCandidateType::Srflx => "srflx",
                RTCIceCandidateType::Prflx => "prflx",
                RTCIceCandidateType::Relay => "relay",
                _ => "?",
            }
            .to_string()
        };
        Some(PathPair {
            local_ip: pair.local.address.clone(),
            local_typ: typ(pair.local.typ),
            remote_ip: pair.remote.address.clone(),
            remote_port: pair.remote.port,
            remote_typ: typ(pair.remote.typ),
            relayed: pair.local.typ == RTCIceCandidateType::Relay
                || pair.remote.typ == RTCIceCandidateType::Relay,
        })
    }
}

/// The concrete endpoints of a selected ICE candidate pair, for path display.
#[derive(Debug, Clone)]
pub struct PathPair {
    pub local_ip: String,
    pub local_typ: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub remote_typ: String,
    pub relayed: bool,
}

/// A rendered description of a link's path, shared by `filament ping` (warm) and
/// `filament doctor` (probe) so both name the path identically: the local
/// INTERFACE, the address class, the concrete endpoints, and whether it's
/// relayed. Fields are `Option` because a relay/webrtc link exposes less than a
/// direct one.
#[derive(Debug, Clone, Default)]
pub struct PathInfo {
    pub iface: Option<String>,
    pub vpn: bool,
    pub class: Option<String>,
    pub local: Option<String>,
    pub remote: Option<String>,
    pub cand: Option<String>,
    pub relay: bool,
}

impl PathInfo {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        if let Some(i) = &self.iface {
            m.insert("iface".into(), json!(i));
            m.insert("vpn".into(), json!(self.vpn));
        }
        if let Some(c) = &self.class {
            m.insert("class".into(), json!(c));
        }
        if let Some(l) = &self.local {
            m.insert("local".into(), json!(l));
        }
        if let Some(r) = &self.remote {
            m.insert("remote".into(), json!(r));
        }
        if let Some(c) = &self.cand {
            m.insert("cand".into(), json!(c));
        }
        m.insert("relay".into(), json!(self.relay));
        Value::Object(m)
    }
}

/// Describe a link's path. Transport-FIRST: a direct-QUIC transport knows its
/// own 5-tuple (`remote_addr`), so that's authoritative even if a stale webrtc
/// `peer` Arc rode along on the guard; only when the transport has no address (a
/// relay/DataChannel link) do we read the ICE candidate pair off the peer. The
/// local interface comes from quinn's `local_ip` when available, else from the
/// kernel's route to the remote (`source_ip_for`) — so the interface name shows
/// even for holepunched sockets.
pub async fn describe_path(t: &dyn Transport, peer: Option<&Peer>) -> PathInfo {
    let mut info = PathInfo::default();
    if let Some(ra) = t.remote_addr() {
        info.remote = Some(ra.to_string());
        info.class = Some(crate::doctor::ip_class(ra.ip()));
        if let Some(la) = t.local_ip().or_else(|| source_ip_for(ra)) {
            info.local = Some(la.to_string());
            if let Some((n, v)) = crate::doctor::iface_for_ip(la) {
                info.iface = Some(n);
                info.vpn = v;
            }
        }
    } else if let Some(p) = peer {
        if let Some(pp) = p.path_detail().await {
            info.remote = Some(format!("{}:{}", pp.remote_ip, pp.remote_port));
            info.local = Some(pp.local_ip.clone());
            info.cand = Some(format!("{}\u{2194}{}", pp.local_typ, pp.remote_typ));
            info.relay = pp.relayed;
            if let Ok(rip) = pp.remote_ip.parse::<std::net::IpAddr>() {
                info.class = Some(crate::doctor::ip_class(rip));
            }
            if let Ok(lip) = pp.local_ip.parse::<std::net::IpAddr>() {
                if let Some((n, v)) = crate::doctor::iface_for_ip(lip) {
                    info.iface = Some(n);
                    info.vpn = v;
                }
            }
        }
    }
    info
}

/// C1: webrtc-rs never writes `a=max-message-size` into its SDP, so browsers
/// assume the RFC 8841 default of 64K (65536), and the browser's frame is
/// 64 KiB payload + 4-byte header = 65540, four bytes over, making Chrome's
/// send() throw against a CLI peer. Advertise a roomy limit in the
/// application m-section of every description we relay; datachannel-only SDP
/// has exactly one m-section, so appending is safe. Our own sends stay at
/// 60 KiB regardless.
pub const ADVERTISED_MAX_MESSAGE: u32 = 262144;

fn advertise_max_message_size(desc: &RTCSessionDescription) -> Value {
    let mut sdp = desc.sdp.clone();
    if !sdp.contains("max-message-size") && sdp.contains("m=application") {
        if !sdp.ends_with('\n') {
            sdp.push_str("\r\n");
        }
        sdp.push_str(&format!("a=max-message-size:{ADVERTISED_MAX_MESSAGE}\r\n"));
    }
    json!({ "type": desc.sdp_type.to_string(), "sdp": sdp })
}

/// Is this address one of this host's own? Std-only trick: a UDP socket
/// "connected" to one of our own IPs reports that same IP as its local
/// address (the kernel routes it locally); a genuinely remote IP yields our
/// interface address instead. No packets are sent.
pub fn is_own_addr(addr: &str) -> bool {
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    std::net::UdpSocket::bind(bind)
        .and_then(|s| {
            s.connect((ip, 9))?;
            s.local_addr()
        })
        .map(|la| la.ip() == ip)
        .unwrap_or(false)
}

/// The local source IP the kernel would use to reach `remote`. Same no-packets
/// UDP-connect trick as `is_own_addr`: after `connect()`, `local_addr()` reports
/// the source the routing table picked. Lets `filament ping` name the outbound
/// interface even when quinn's `local_ip()` is `None` (holepunched / specifically
/// bound sockets don't carry per-packet dst info). `None` only if the bind fails.
pub fn source_ip_for(remote: std::net::SocketAddr) -> Option<std::net::IpAddr> {
    let bind = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    std::net::UdpSocket::bind(bind)
        .and_then(|s| {
            s.connect(remote)?;
            s.local_addr()
        })
        .ok()
        .map(|la| la.ip())
        .filter(|ip| !ip.is_unspecified())
}

/// RFC1918/4193 + loopback + link-local, "on your network" for the route badge.
pub fn is_private_addr(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // 100.64/10 (RFC6598 shared/CGNAT): in practice these are
                // overlay networks like Tailscale, bytes stay on your wire.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
        Err(_) => false,
    }
}

async fn wire_channel(
    peer_id: String,
    dc: Arc<RTCDataChannel>,
    tx: mpsc::UnboundedSender<Ev>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    polite: bool,
) {
    // With detach_data_channels(), on_open still fires but webrtc-rs's
    // managed (65535-byte-buffer) read loop never starts, we detach and run
    // our own with a buffer matching the max-message-size we advertise (C1).
    let dc2 = dc.clone();
    dc.on_open(Box::new(move || {
        let dc2 = dc2.clone();
        let tx = tx.clone();
        let closed = closed.clone();
        Box::pin(async move {
            let raw = match dc2.detach().await {
                Ok(raw) => raw,
                Err(e) => {
                    crate::ui::trace(&format!("filament: data channel detach failed: {e}"));
                    return;
                }
            };
            let drained = Arc::new(Notify::new());
            let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
            // Seed activity at open so a link mid-handshake (no bytes yet) is
            // never falsely treated as idle/supersedable (#28 guard).
            let last_activity = Arc::new(std::sync::atomic::AtomicU64::new(now_ms()));
            let first_data = Arc::new(std::sync::atomic::AtomicBool::new(false));

            // C8a: one persistent buffered-amount-low subscription wakes all
            // parked senders.
            raw.set_buffered_amount_low_threshold(LOW_WATER);
            {
                let drained = drained.clone();
                raw.on_buffered_amount_low(Box::new(move || {
                    let drained = drained.clone();
                    Box::pin(async move {
                        drained.notify_waiters();
                    })
                }));
            }

            // Our read loop: text -> Control, binary -> [u32 sid][payload].
            {
                let raw = raw.clone();
                let tx = tx.clone();
                let closed = closed.clone();
                let dead = dead.clone();
                let drained = drained.clone();
                let last_activity = last_activity.clone();
                let first_data = first_data.clone();
                let peer_id = peer_id.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; READ_BUF];
                    loop {
                        match raw.read_data_channel(&mut buf).await {
                            Ok((0, _)) | Err(_) => {
                                dead.store(true, std::sync::atomic::Ordering::Relaxed);
                                drained.notify_waiters(); // wake parked senders
                                break;
                            }
                            Ok((n, true)) => {
                                if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                                    if let Ok(v) = serde_json::from_slice::<Value>(&buf[..n]) {
                                        let _ = tx.send(Ev::Control(peer_id.clone(), v));
                                    }
                                }
                            }
                            Ok((n, false)) => {
                                if n >= 4 && !closed.load(std::sync::atomic::Ordering::Relaxed) {
                                    // Inbound transfer bytes = link is flowing (#28
                                    // guard). Only data frames count, not control,
                                    // periodic acks/state pings must not keep an
                                    // otherwise-idle link looking active.
                                    last_activity
                                        .store(now_ms(), std::sync::atomic::Ordering::Relaxed);
                                    first_data
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                    let sid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                                    let _ = tx.send(Ev::Chunk(
                                        peer_id.clone(),
                                        sid,
                                        Bytes::copy_from_slice(&buf[4..n]),
                                    ));
                                }
                            }
                        }
                    }
                });
            }

            if !closed.load(std::sync::atomic::Ordering::Relaxed) {
                // Relay/DataChannel links have NO QUIC keepalive, so an idle one
                // on a container/DERP path is silently evicted in ~10s, after which
                // warm-reuse refuses it (the 8s staleness gate) and falls back to a
                // slow cold establish. Send a tiny keepalive every 7s (under that
                // window) so the path stays alive AND idle_ms stays low, keeping the
                // link instantly warm-reusable across idle gaps. The peer ignores an
                // unknown control type, and receiving it stamps ITS activity too, so
                // the reverse direction stays warm symmetrically.
                {
                    let raw_k = raw.clone();
                    let dead_k = dead.clone();
                    let act_k = last_activity.clone();
                    tokio::spawn(async move {
                        let frame = Bytes::from(json!({ "type": "ping", "reason": "keepalive" }).to_string());
                        loop {
                            tokio::time::sleep(std::time::Duration::from_secs(7)).await;
                            if dead_k.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }
                            if raw_k.write_data_channel(&frame, true).await.is_err() {
                                break;
                            }
                            act_k.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
                let transport: Arc<dyn Transport> =
                    Arc::new(DataChannelTransport { raw, drained, dead, last_activity, first_data, answerer: polite });
                let _ = tx.send(Ev::ChannelReady(peer_id.clone(), transport));
            }
        })
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polite_role_prefers_uid_then_sid() {
        // Distinct uids: lexical comparison of uids decides (mirrors webrtc.js).
        assert!(polite_role("uid-z", Some("uid-a"), "s1", "s9"));
        assert!(!polite_role("uid-a", Some("uid-z"), "s9", "s1"));
        // Same/None uid: fall back to sid comparison.
        assert!(polite_role("u", None, "s9", "s1"));
        assert!(!polite_role("u", None, "s1", "s9"));
        assert!(polite_role("u", Some("u"), "s9", "s1"));
    }

    #[test]
    fn roster_from_ack_extracts_present_peers() {
        // A real subscribe ACK: {ok, n, peers:[...]}. Every roster entry is
        // shaped like a known-peer push and must be forwarded.
        let ack = json!({
            "ok": true, "n": 1,
            "peers": [
                {"id": "sidA", "name": "dovm", "uid": "cli-r-1", "channel": "ch"},
                {"id": "sidB", "name": "dovm2", "uid": "cli-r-2", "channel": "ch"}
            ]
        });
        let out = roster_from_ack(&[ack]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["id"], "sidA");
        assert_eq!(out[1]["id"], "sidB");
        assert_eq!(out[0]["channel"], "ch");
    }

    #[test]
    fn host_port_parses_scheme_defaults_and_explicit() {
        assert_eq!(
            host_port_from_url("https://api.filament.autumated.com"),
            Some(("api.filament.autumated.com".to_string(), 443))
        );
        assert_eq!(
            host_port_from_url("http://example.com/api/config?x=1"),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            host_port_from_url("https://example.com:8443/api/config"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            host_port_from_url("wss://relay.example.com"),
            Some(("relay.example.com".to_string(), 443))
        );
        // userinfo is dropped; path/query ignored.
        assert_eq!(
            host_port_from_url("https://user:pass@host.example/path"),
            Some(("host.example".to_string(), 443))
        );
        // IPv6 literal with and without explicit port.
        assert_eq!(
            host_port_from_url("https://[2606:4700::1]:443/api"),
            Some(("2606:4700::1".to_string(), 443))
        );
        assert_eq!(
            host_port_from_url("http://[::1]"),
            Some(("::1".to_string(), 80))
        );
        // Unknown scheme: no default port, decline.
        assert_eq!(host_port_from_url("ftp://example.com"), None);
        assert_eq!(host_port_from_url("not a url"), None);
    }

    #[test]
    fn cached_addrs_select_host_and_apply_port() {
        let doc = json!({
            "api.filament.autumated.com": ["104.21.73.85", "172.67.142.8"],
            "other.example": ["10.0.0.1"]
        });
        let mut got = cached_addrs_from_doc(&doc, "api.filament.autumated.com", 443);
        got.sort();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&"104.21.73.85:443".parse::<SocketAddr>().unwrap()));
        assert!(got.contains(&"172.67.142.8:443".parse::<SocketAddr>().unwrap()));
        // Other host, different port applied.
        let other = cached_addrs_from_doc(&doc, "other.example", 8443);
        assert_eq!(other, vec!["10.0.0.1:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn cached_addrs_robust_to_missing_or_malformed() {
        // Host absent.
        assert!(cached_addrs_from_doc(&json!({}), "nope.example", 443).is_empty());
        // Entry not an array.
        assert!(cached_addrs_from_doc(&json!({"h": "oops"}), "h", 443).is_empty());
        // Array with junk: only valid IPs survive, no panic.
        let doc = json!({"h": ["not-an-ip", "192.0.2.7", 42, null]});
        assert_eq!(
            cached_addrs_from_doc(&doc, "h", 443),
            vec!["192.0.2.7:443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn roster_from_ack_robust_to_empty_or_missing() {
        // Empty roster (nobody present yet): no entries, no panic.
        assert!(roster_from_ack(&[json!({"ok": true, "n": 1, "peers": []})]).is_empty());
        // `peers` absent entirely (error ack / older server): no entries.
        assert!(roster_from_ack(&[json!({"ok": false, "n": 0})]).is_empty());
        // `peers` present but not an array: ignored, no panic.
        assert!(roster_from_ack(&[json!({"peers": "oops"})]).is_empty());
        // No payload values at all.
        assert!(roster_from_ack(&[]).is_empty());
    }
}
