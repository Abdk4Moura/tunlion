// L2, ssh / raw TCP tunnelled over the Tunlion WebRTC data channel.
//
// Productionizes docs/L2-tunnel-design.md (spike: cli/spike/l2spike.rs). L2
// multiplexes logical TCP streams over the SAME data channel that moves files
// today, reusing the `Transport` trait verbatim, no transport changes.
//
// SCOPE: single-stream (ssh / one forward at a time is the supported case and
// what ships first). Multiple *concurrent heavy* streams over one link need
// per-stream credit flow control (design §4) to stay deadlock-free; that is a
// follow-up, see TODO(credits) below. l2-open-ack is mandatory here (it closes
// the early-frame-drop race and the open/deny ambiguity); the `credit` field it
// will eventually carry is the only piece deferred.
//
// Three surfaces, smallest-primitive-first (each is sugar over the one below):
//   * `tunlion netcat <peer> <rport>`            stdio  <-> one L2 stream
//   * `tunlion forward <lport> <peer> <rport>`   local TCP listener; conn=stream
//   * `tunlion shell --ssh <peer> [args...]`             real ssh -o ProxyCommand=netcat
//
// The ACCEPTOR (the side that dials the localhost target) is NOT a subcommand:
// it lives inside `tunlion up` / `tunlion recv`, gated on the existing
// proof-verified `trusted` flag (the capability placeholder) + localhost-only
// dialing (the SSRF defense). See `Mux::accept_control` (in
// `filament_peerloop::l2::mux`) and main.rs's recv loop.

mod proxy;
mod pty_session;
mod ssh;
mod terminal;

use crate::net::{self, Ev, Peer, Transport};
use anyhow::{Result, anyhow, bail};
#[cfg(feature = "forward-server")]
use proxy::{cold_link_live, manage_cold_link, serve_cold_connection};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "forward-server")]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub(crate) use proxy::{
    OVERLAY_DIAL_BOUND, OVERLAY_DIAL_TIMED_OUT, OVERLAY_SETTLE_MAX, OVERLAY_TARGET_CLOSED,
    PROXY_USER, cold_link_bound, mesh_fail_for_refusal, mesh_verdict, overlay_settle_window,
    proxy_token, proxy_token_path, proxy_usage_lines,
};
#[cfg(feature = "forward-server")]
pub use proxy::proxy_cmd;
pub use proxy::{bind_auto_proxy, proxy_serve};
pub(crate) use proxy::MeshFail;

pub use pty_session::{
    LIVE_PTYS, MAX_PTYS_GLOBAL, PtyGuard, PtySessionHandle, PtySessions, SESSION_BUFFER_CAP,
    SESSION_DETACHED_IDLE, SESSION_MAX_LIFETIME, spawn_pty_session,
};
pub(crate) use pty_session::{effective_term, replay_skip};

pub use ssh::ssh_cmd;
pub(crate) use ssh::{
    PeerSshInfo, ensure_peer_bootstrap, ensure_peer_bootstrap_port, l3_dest, rebootstrap_peer,
    ssh_transport_args,
};

pub use terminal::pty_cmd;
pub(crate) use terminal::{
    CookedNewlines, normalize_cooked_newlines, normalize_stdin_chunk, spawn_stdin_reader,
    strip_mouse_reports,
};

// The L2 wire + mux unit moved to `filament_peerloop::l2::mux` (issue #465,
// slice 3). These are the names every caller here and in the command modules
// already used, re-exported so no call site changes. `MAX_STREAMS_PER_LINK`
// stays re-exported for completeness even though this file no longer reads it;
// the mux is its only consumer.
#[allow(unused_imports)]
/// Test-only transport selector for the L2/exec authorization proofs. The L2
/// dialer normally races direct-QUIC unconditionally because the long-lived
/// acceptor forces that rung; the test hook must still be able to exercise the
/// WebRTC authorization path while a separate control runs direct.
#[cfg(feature = "test-hooks")]
fn direct_race_allowed() -> bool {
    !crate::test_hooks::no_direct()
}
#[cfg(not(feature = "test-hooks"))]
fn direct_race_allowed() -> bool {
    true
}

pub(crate) use filament_peerloop::l2::mux::{
    L2_SID_BASE, MAX_STREAMS_PER_LINK, Mux, OpenOutcome, OpenVerdict, PipeItem, is_l2_sid,
    serve_stream, wire_sid,
};
// The caller-owned per-peer table every L2 sector receives. Re-exported so
// sector modules name it through `crate::l2`, as they name `Mux`.
pub(crate) use filament_peerloop::l2::MuxMap;

// Warm-stream verification moved to `filament_peerloop::l2::warm` (the daemon
// handlers that consume it are library code). Re-exported under the old names
// so every caller and test here keeps its path.
#[allow(unused_imports)]
pub(crate) use filament_peerloop::l2::{open_stream, open_stream_verified_reason, WarmOpen};
#[cfg(unix)]
#[allow(unused_imports)]
pub(crate) use filament_peerloop::l2::{
    open_pty_stream_verified, serve_opened_stream, serve_verified_stream, warm_verify_window,
    WarmPtyVerdict,
};

/// Test-only flattening of the verified open (zombie tests pin this shape).
#[cfg(all(unix, test))]
pub(crate) async fn open_stream_verified(
    mux: &Arc<Mux>,
    rport: u16,
    verify: std::time::Duration,
) -> Result<(u32, PipeItem, mpsc::Receiver<PipeItem>)> {
    match open_stream_verified_reason(mux, rport, verify).await {
        WarmOpen::Opened(sid, first, rx) => Ok((sid, first, rx)),
        WarmOpen::Refused(reason) => Err(anyhow!("warm stream refused: {reason}")),
        WarmOpen::Dead(e) => Err(e),
    }
}

// ------------------------------------------------------------ INITIATOR side --

/// Holds the signaling client + WebRTC peer that back a brought-up link so the
/// CALLER decides their fate. A long-lived consumer (netcat/forward) calls
/// `forget()` to keep the link alive for the process lifetime (byte-identical to
/// the old `std::mem::forget`). A short-lived consumer (the shell bootstrap)
/// calls `close().await` to TEAR THE LINK DOWN before opening a second link to
/// the same device, otherwise the acceptor sees two same-device peers at once
/// and its C6 supersede/adopt logic churns (one link gets dropped mid-use).
pub struct LinkGuard {
    sio: Option<filament_signal::Client>,
    peer: Option<Arc<Peer>>,
}

impl LinkGuard {
    /// Keep the link alive forever (leaks sio+peer, as the long-lived tunnels
    /// want). Consumes the guard.
    pub(crate) fn forget(mut self) {
        if let Some(sio) = self.sio.take() {
            std::mem::forget(sio);
        }
        if let Some(p) = self.peer.take() {
            std::mem::forget(p);
        }
    }

    /// Cleanly close the link: drop the WebRTC peer connection and disconnect
    /// signaling, so the acceptor reaps this peer promptly. Consumes the guard.
    async fn close(mut self) {
        if let Some(p) = self.peer.take() {
            p.close().await;
        }
        if let Some(sio) = self.sio.take() {
            let _ = sio.disconnect().await;
        }
    }
}

/// Candidate bookkeeping for a dial on the shared FLEET channel.
///
/// Every sibling (and this device's own daemon) sits on that channel, so
/// presence and transport-offers arrive from devices that are not the target.
/// Each candidate's identity is proven by certificate (`verify_fleet_identity`);
/// this only decides the ORDER candidates are tried in and remembers the ones
/// that proved to be some other device, so one wrong answer rejects that
/// candidate instead of ending the connect. It grants nothing: a candidate it
/// lets through still has to pass the certificate check.
#[derive(Default)]
struct FleetDial {
    /// Candidates (signaling sids) that proved a different identity.
    rejected: std::collections::HashSet<String>,
    /// A transport-offer from a candidate that is not the current one, held
    /// until it is. Racing it at once ran the single direct race against
    /// whichever sibling offered first, with the CURRENT candidate's uid.
    held_offers: HashMap<String, Value>,
}

impl FleetDial {
    /// A candidate appeared. `None`: skip it (already rejected). `Some(true)`:
    /// try it first, because it CALLS itself the target (its own claim, only an
    /// ordering hint). `Some(false)`: queue it behind the others.
    fn presence(&self, pid: &str, asserted_name: Option<&str>, target: &str) -> Option<bool> {
        if self.rejected.contains(pid) {
            return None;
        }
        Some(asserted_name.is_some_and(|n| n.eq_ignore_ascii_case(target)))
    }

    /// A transport-offer arrived. True: race it now (it is from the candidate
    /// being dialed). False: it was held for later or dropped.
    fn offer(&mut self, signal: &Value, current: Option<&str>) -> bool {
        let from = signal["from"].as_str().unwrap_or_default();
        if self.rejected.contains(from) {
            return false;
        }
        if current == Some(from) {
            return true;
        }
        self.held_offers.insert(from.to_string(), signal.clone());
        false
    }

    /// We started dialing `pid`: hand back its held offer, if any, to replay.
    fn on_dial(&mut self, pid: &str) -> Option<Value> {
        self.held_offers.remove(pid)
    }

    /// `pid` proved a different identity: never dial it again in this connect.
    fn reject(&mut self, pid: &str) {
        self.held_offers.remove(pid);
        self.rejected.insert(pid.to_string());
    }
}

/// Minimal identity-mode link bring-up to a *known* device, mirroring the
/// production send/recv path but stripped to exactly what L2 needs: join a solo
/// room, subscribe to the device's presence channel, dial it when it appears,
/// and prove our identity (pair-proof) so its `up`/`recv` marks us trusted,
/// which is what unlocks the acceptor's capability gate. Returns the ready
/// Transport, the event receiver, and a `LinkGuard` the caller must either
/// `forget()` (keep alive) or `close().await` (tear down).
/// Prove that the peer on this link is the device the caller NAMED.
///
/// Dialing with the fleet secret authenticates the link as "someone in this
/// fleet". Turning that into "this is `expected`" needs the owner-signed
/// certificate, bound to this link, and the device key it names has to resolve to
/// the local record `expected` refers to. Anything else is refused: a same-fleet
/// device answering to the wrong name is exactly the case this exists to stop.
async fn verify_fleet_identity(
    t: &Arc<dyn Transport>,
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    tx: &mpsc::UnboundedSender<Ev>,
    link: &str,
    expected: &str,
    own_device: Option<[u8; 32]>,
) -> Result<()> {
    // Everything that is not this link's control traffic (presence, other
    // candidates' offers, timers) still belongs to the dial loop, which keeps
    // going if this candidate is not the one. Swallowing it here lost the
    // target's own transport-offer while the wrong sibling was being checked.
    let mut deferred = Vec::new();
    let r = verify_fleet_identity_inner(t, rx, &mut deferred, link, expected, own_device).await;
    for ev in deferred {
        let _ = tx.send(ev);
    }
    r
}

/// Direct-QUIC (and WebRTC) transports tag every inbound event with the
/// immutable `SourceId` of the transport that produced it. This dial loop
/// routes candidates by peer id and checks the direct attempt at `DirectReady`;
/// before a link is selected there is no single source to compare against, so
/// unwrap the tag here. The destinations that DO know their owner re-apply the
/// gate: `verify_fleet_identity_inner` accepts only the source of the transport
/// it is verifying, and `pump_initiator` accepts only the selected link's
/// source. Without this, the loop never sees a `ChannelReady` or `Control` at
/// all (the source-attributed event shape made both invisible).
fn unsource_event(ev: Ev) -> Ev {
    match ev {
        Ev::Sourced { inner, .. } => *inner,
        other => other,
    }
}

/// The control message carried by `ev` for the link being verified, if any.
///
/// The direct reader delivers control frames as `Ev::Sourced { inner:
/// Ev::Control }`; the WebRTC/LAN readers use the untagged shape. A tagged
/// event is accepted only from the exact transport being verified, otherwise a
/// hello bound to a losing/superseded QUIC connection could be read as this
/// link's certificate.
fn control_for_link<'a>(
    ev: &'a Ev,
    link: &str,
    source: Option<net::SourceId>,
) -> Option<&'a Value> {
    match ev {
        Ev::Control(from, v) if from == link => Some(v),
        Ev::Sourced { pid, source: event_source, inner } if pid == link => {
            if source != Some(*event_source) {
                return None;
            }
            match inner.as_ref() {
                Ev::Control(from, v) if from == link => Some(v),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The event the selected link's pump may act on.
///
/// A source-attributed event is only this link's if its `SourceId` matches the
/// transport the mux selected. Anything else is a callback from a candidate
/// that lost the race (or an earlier attempt on the same signaling id) and must
/// not reach the mux after selection: an old `l2-close` would end the wrong
/// stream. Chunks must always be attributed; the envelope and inner pid must
/// agree before any data can be routed by stream id.
///
/// Only the inner events this gate can attribute are unwrapped: `Control`,
/// `PcState`, `ChannelReady`, `Chunk` and `PeerLeft`. The last is the
/// source-tagged departure barrier the daemon queues behind a link's
/// already-read events; it carries no inner pid, so it is admitted on the
/// source match alone. Any other inner event is dropped rather than
/// unwrapped, because it cannot be shown to belong to this link.
fn selected_event(ev: Ev, source: Option<net::SourceId>) -> Option<Ev> {
    match ev {
        Ev::Sourced { pid, source: event_source, inner } if Some(event_source) == source => {
            let valid = match inner.as_ref() {
                Ev::Control(inner_pid, _) | Ev::PcState(inner_pid, _)
                | Ev::ChannelReady(inner_pid, _) | Ev::Chunk(inner_pid, ..) => *inner_pid == pid,
                // The departure barrier has no inner pid to compare.
                Ev::PeerLeft(_) => true,
                _ => false,
            };
            valid.then_some(*inner)
        }
        Ev::Sourced { .. } => None,
        Ev::Chunk(..) => None,
        other => Some(other),
    }
}

/// Read replies from the selected transport without accepting late frames
/// from a losing candidate. Exec and SSH bootstrap use the same source gate
/// as the L2 pump, including while waiting for their first acknowledgment.
pub(crate) async fn recv_selected_event(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    source: Option<net::SourceId>,
) -> Option<Ev> {
    while let Some(ev) = rx.recv().await {
        if let Some(ev) = selected_event(ev, source) {
            return Some(ev);
        }
    }
    None
}

async fn verify_fleet_identity_inner(
    t: &Arc<dyn Transport>,
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    deferred: &mut Vec<Ev>,
    link: &str,
    expected: &str,
    own_device: Option<[u8; 32]>,
) -> Result<()> {
    // Fail closed: without our own key the own-key refusal below cannot run.
    let own_device = own_device.ok_or_else(|| {
        crate::exit_codes::err(
            crate::exit_codes::ExitKind::NoIdentity,
            format!("cannot verify '{expected}': this device's own key is unavailable"),
        )
    })?;
    let cb = t.channel_binding().ok_or_else(|| {
        anyhow!("cannot verify '{expected}': this link exposes no channel binding")
    })?;
    let owner = crate::fleet::my_owner_pub()
        .ok_or_else(|| anyhow!("cannot verify '{expected}': this device holds no owner key"))?;
    let hello = crate::fleet::make_hello(&cb, &crate::display_name())?;
    t.send_control(&hello).await?;
    let source = t.source_id();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        // A peer that drops the link (it bound the proof to a different
        // connection of a simultaneous open) says so by closing, not by
        // answering; notice that instead of waiting out the deadline.
        if t.is_dead() {
            bail!("link closed before '{expected}' presented a certificate");
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            bail!("'{expected}' never presented a certificate");
        }
        let tick = (deadline - now).min(Duration::from_millis(250));
        let ev = match tokio::time::timeout(tick, rx.recv()).await {
            Err(_) => continue,
            Ok(None) => bail!("link closed before '{expected}' presented a certificate"),
            Ok(Some(ev)) => ev,
        };
        let v = match control_for_link(&ev, link, source) {
            Some(v) => v,
            None => match &ev {
                Ev::Control(..) | Ev::Chunk(..) => continue,
                Ev::Sourced { pid, .. } if pid == link => continue,
                _ => {
                    deferred.push(ev);
                    continue;
                }
            },
        };
        if v["type"].as_str() != Some(crate::fleet::HELLO) {
            continue;
        }
        let proven = crate::fleet::verify_hello(v, &cb, &owner, crate::identity::now_secs())?;
        // Never accept a hello carrying this device's own key (own-device-key).
        if proven.device_pub == own_device {
            return Err(anyhow::Error::new(WrongFleetDevice(format!(
                "refusing: the device answering as '{expected}' presented this device's own key (own-device-key). No command payload was sent."
            ))));
        }
        let name = crate::device_name_for_pub(&proven.device_pub);
        if name.as_deref().map(|n| n.eq_ignore_ascii_case(expected)) != Some(true) {
            return Err(anyhow::Error::new(WrongFleetDevice(format!(
                "refusing: the device answering as '{expected}' proved a different identity ({}). Nothing was sent.",
                name.as_deref().unwrap_or("unknown device")
            ))));
        }
        return Ok(());
    }
}

/// `verify_fleet_identity` reached a device that PROVED it is not the target.
/// Only this rejects the candidate for the rest of the dial; any other failure
/// (no answer, link closed) leaves it eligible for another attempt.
#[derive(Debug)]
struct WrongFleetDevice(String);

impl std::fmt::Display for WrongFleetDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WrongFleetDevice {}

/// How long `exec` waits for a single signal from the device it is reaching
/// before saying it is offline. A live daemon answers the moment it sees us.
const EXEC_SILENT_PEER: Duration = Duration::from_secs(15);

/// The establish bound of the candidate being dialed.
///
/// The per-candidate timer (`TUNLION_L2_CANDIDATE_SECS`, 7s) exists to rotate
/// past GHOSTS: dead or wrong sids that never say a word. A candidate that has
/// answered (any signal from its sid, or ICE with a remote description, checking
/// or connected) is a real peer still negotiating; abandoning it rebuilds the
/// connection the far end is answering. Such a candidate is KEPT, and keeping
/// arms a one-shot `Stuck` at its hard bound (`started + bound`, the C3 watchdog
/// time), so it is rotated there whatever its peer connection state. The C3
/// watchdog alone is not that bound: it stays silent for a CONNECTED peer
/// connection (a fleet link waiting for its direct proof, or a data channel that
/// never opens). A timer configured at or past the bound rotates as before.
struct CandidateBound {
    started: tokio::time::Instant,
    bound: Duration,
    rearmed: bool,
}

impl CandidateBound {
    fn new(bound: Duration) -> Self {
        CandidateBound {
            started: tokio::time::Instant::now(),
            bound,
            rearmed: false,
        }
    }

    /// A new peer connection is being dialed (a new candidate, or a glare
    /// rebuild): its bound starts now.
    fn restart(&mut self) {
        self.started = tokio::time::Instant::now();
        self.rearmed = false;
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A `Stuck` fired for the current candidate `pid` at generation `g`.
    /// Returns true to rotate it. When it is kept, the hard bound is armed
    /// (once) on `tx`, so a kept candidate is always rotated by then.
    fn on_stuck(
        &mut self,
        heard: bool,
        progressing: bool,
        tx: &mpsc::UnboundedSender<Ev>,
        pid: &str,
        g: u32,
    ) -> bool {
        let hard = self.started + self.bound;
        if tokio::time::Instant::now() >= hard || !(heard || progressing) {
            return true;
        }
        if !self.rearmed {
            self.rearmed = true;
            let tx = tx.clone();
            let pid = pid.to_string();
            tokio::spawn(async move {
                tokio::time::sleep_until(hard).await;
                let _ = tx.send(Ev::Stuck(pid, g));
            });
        }
        false
    }
}

/// The one transient "waiting" line an `exec` may show. Created only after
/// [`crate::ui::wait_status_enabled`] said a live, non-quiet, non-JSON TTY is
/// watching, so a pipe never receives it. The delay is owned by the caller's
/// timer; this guard only erases the line on EVERY exit (success, refusal,
/// timeout) so the command's real output never lands on top of it.
struct ExecWaitLine {
    enabled: bool,
    shown: bool,
}

impl ExecWaitLine {
    fn new(enabled: bool) -> Self {
        Self { enabled, shown: false }
    }

    fn show(&mut self, line: &str) {
        if self.enabled {
            crate::ui::status(line);
            self.shown = true;
        }
    }
}

impl Drop for ExecWaitLine {
    fn drop(&mut self) {
        if self.shown {
            crate::ui::clear_status();
        }
    }
}

pub(crate) async fn bring_up_to_known(
    server: &str,
    peer_name: &str,
    relay: bool,
    role: &'static str,
) -> Result<(
    Arc<dyn Transport>,
    mpsc::UnboundedReceiver<Ev>,
    LinkGuard,
    crate::diag::Attempt,
)> {
    bring_up_to_known_in_span(server, peer_name, relay, role, crate::diag::correlation_id()).await
}

/// [`bring_up_to_known`] recording its connect span under `span_id`, so a
/// caller that loses the `Attempt` (an error, or its own deadline dropping
/// this future) can still read back where THIS bring-up died.
async fn bring_up_to_known_in_span(
    server: &str,
    peer_name: &str,
    relay: bool,
    role: &'static str,
    span_id: String,
) -> Result<(
    Arc<dyn Transport>,
    mpsc::UnboundedReceiver<Ev>,
    LinkGuard,
    crate::diag::Attempt,
)> {
    // A paired device has its own secret. A FLEET sibling is indexed WITHOUT one
    // (design-fleet-automesh.md), so fall back to the fleet secret, which is what
    // the daemon dials such peers with. `fleet_mode` matters at the return sites:
    // that secret proves MEMBERSHIP, not identity, so the certificate has to be
    // checked before the link is handed to the caller.
    let (secret, fleet_mode) = match crate::devices_load()
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(peer_name))
        .map(|(_, s)| s)
    {
        Some(s) => (s, false),
        None => {
            // Ask the daemon to broker a PRIVATE rendezvous before falling back
            // to the fleet secret. Same mechanism `send --to` uses (WORK-STATE
            // 1h), which took sibling send from ~50% to 58/58: the fleet secret
            // below meets the peer on the channel EVERY sibling sits on, and the
            // dial then has to work out which of the answering peers is the
            // target. A brokered secret has exactly two parties on it, so that
            // race does not get safer, it stops existing.
            //
            // Condition mirrors send_cmd's: only a fleet-indexed name, only when
            // this device is in a fleet. A typo must not cost a daemon round
            // trip, and a paired device never reaches here at all.
            //
            // fleet_mode is FALSE for a brokered secret, also matching send_cmd,
            // because the secret travelled over a link the daemon had ALREADY
            // verified by certificate and so identifies the peer by itself. The
            // daemon holds up that end: it brokers only over a link with a
            // Proven identity binding (`warm_link_for`), never on presence, so a
            // stranger on the fleet channel cannot obtain one.
            let brokered = if crate::fleet_indexed_name(peer_name) && crate::fleet::rv().is_some() {
                crate::ctl::try_fleet_rendezvous(peer_name).await
            } else {
                None
            };
            match brokered {
                Some(sec) => {
                    crate::ui::debug(&format!(
                        "fleet: daemon brokered a private rendezvous with '{peer_name}' for {role}"
                    ));
                    (sec, false)
                }
                None => match (crate::fleet_indexed_name(peer_name), crate::fleet::rv()) {
                    (true, Some(rv)) => (rv, true),
                    _ => bail!(
                        "no known device named '{peer_name}', run `tunlion add` first (see `tunlion devices`)"
                    ),
                },
            }
        }
    };
    // This device's own key, read ONCE for a fleet dial. A hello carrying it is
    // refused, and an unreadable key fails the dial instead of leaving that
    // refusal inert for it.
    let own_device: Option<[u8; 32]> = if fleet_mode {
        Some(crate::overlay::overlay_pubkey_bytes().map_err(|e| {
            crate::exit_codes::err(
                crate::exit_codes::ExitKind::NoIdentity,
                format!(
                    "refusing the fleet dial to '{peer_name}': this device's own key at {} could not be read ({e}). Check that file's permissions, or run `tunlion init` if this device has no identity. No command payload was sent.",
                    crate::overlay::key_path().display()
                ),
            )
        })?)
    } else {
        None
    };
    let channel = crate::channel_of(&secret);

    // Establishment telemetry: a connect span, peer tagged by SHORT HASH (never
    // the petname). The Attempt is returned to the caller so it can record the
    // L2Open round trip and the final `up`. We start in Signaling (socket + the
    // first `welcome`); the loop drives the phase transitions below.
    let mut diag =
        crate::diag::Attempt::with_id(span_id, server, &crate::diag::peer_hash_from_secret(&secret), role);
    // Latch so we record the Presence->Establishing transition exactly once
    // (the loop dequeues a candidate every time `peer` is idle, but the connect
    // lifecycle's "establishing" begins at the FIRST candidate).
    let mut entered_establishing = false;

    let transport_context = crate::transport_context::for_root(&crate::settings::config_dir())?;
    let cfg = net::fetch_config(&transport_context, server).await?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let mut sio = net::connect_signaling(&transport_context, server, tx.clone()).await?;

    let my_uid = crate::mk_uid("l2");
    // A solo room keeps strangers out; presence-channel subscription is how we
    // actually find the known device (same as `--to` identity mode).
    let solo = format!("l2-{}", crate::fresh_secret());
    let join_payload =
        json!({ "room": solo, "uid": my_uid.clone(), "name": crate::display_name() });
    sio.emit("join", join_payload.clone()).await.ok();
    // NOTE: subscribe is emitted on Ev::Welcome (below), not here, `welcome` is
    // the proof the socket.io connection is fully established, so the subscribe
    // can't be lost in the connect->emit race that intermittently left the client
    // unsubscribed and "waiting for known device" forever (harness finding).
    //
    // The `join` ABOVE has the SAME connect->emit race: fired the instant
    // `connect_signaling` returns, it can land before the socket.io connection is
    // fully ready and be silently dropped, the server then never runs `_do_join`,
    // never emits `welcome`, and this loop waits for a Welcome that never comes,
    // stranding `tunlion shell --ssh` in "waiting for known device" (~30% of attempts in
    // the isolated repro). So we RE-EMIT join on the same cadence as the
    // re-subscribe below until Welcome lands (idempotent: a repeat join to the
    // same solo room is a no-op server-side once it took).

    let mut my_id: Option<String> = None;
    let mut peer: Option<Arc<Peer>> = None;
    let mut peer_uid: Option<String> = None;
    let mut peer_present = false;
    let mut generation: u32 = 0;
    // Ghost tolerance: the channel can hold DEAD sids (a SIGKILL'd process
    // lingers until the server's ping-timeout) and WRONG peers (our own up
    // subscribes the same pair channel). Locking onto the first known-peer
    // forever was the dominant stall. Instead: one candidate AT A TIME (a
    // parallel race glares, proven, see multicandidate-attempt.patch), a
    // short per-candidate timer, and rotation through everything seen.
    let mut queue: VecDeque<(String, Option<String>, bool)> = VecDeque::new();
    // Per-candidate establish budget for the INTERACTIVE L2/ssh path: how long a
    // single candidate gets to complete (WebRTC + direct-QUIC race) before it is
    // declared Stuck and we rotate to the next. This is a TIMEOUT, not the
    // connect time: a healthy candidate completes in 1.7-3.3s regardless, so a
    // larger budget never slows a good path, it only stops abandoning a real one
    // too early.
    //
    // It was briefly tightened to 4s chasing Tailscale's sub-5s connect, but 4s
    // is BELOW the time a legitimately slow-but-real ICE needs (~5s, e.g. a
    // cross-NAT path that nominates a srflx/relay pair): the budget fired before
    // the real candidate finished, every rotation got cut at 4s, and the link
    // never came up ("establishment timed out", reproduced live as a consistent
    // pop-os -> do-vm failure that 7s/12s established cleanly). Back to 7s, which
    // clears the real ICE time with margin; field-overridable via
    // TUNLION_L2_CANDIDATE_SECS. It rotates only a SILENT candidate: one that has
    // answered keeps its connection until its hard bound, the C3 watchdog time
    // (`CandidateBound`): a relayed or direct-fallback path can need longer
    // than 7s, and rotating it threw away the connection the far end was
    // answering.
    let candidate_secs: u64 = std::env::var("TUNLION_L2_CANDIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(7);
    // Item 3: the L2 initiator races a DIRECT-QUIC dial against WebRTC. On
    // KnownPeer we bind a quinn endpoint + advertise our candidates (mirrors
    // `start_direct` in main.rs); when the peer's transport-offer arrives we
    // consume this endpoint into the race. UNCONDITIONAL here: `bring_up_to_known`
    // only ever serves L2 (netcat/ssh/forward), which always wants direct, and
    // `tunlion shell --ssh`/`netcat` do NOT set TUNLION_L2 in their own env, so gating
    // on `direct_enabled()` would kill the direct dial on the live path. main.rs
    // gates because it ALSO serves file transfer; this function never does.
    let mut endpoint: Option<quinn::Endpoint> = None;
    // Candidates gathered once at first bind; re-advertised to each new
    // candidate peer we rotate to (the endpoint accepts from any of them,
    // the QUIC race is pair-secret-authenticated either way).
    let mut direct_cands: Option<(Vec<String>, Option<String>)> = None;
    // The acceptor re-sends its transport-offer (a late initiator can miss the
    // first). Race only the FIRST offer we get; later re-sends are duplicates.
    let mut direct_racing = false;
    let mut direct_attempt: Option<filament_transport::net::AttemptId> = None;
    // FLEET MODE ONLY. The fleet channel is shared by every sibling (and by our
    // own daemon), so presence and transport-offers arrive from devices that are
    // not the target. Each candidate's identity is proven by certificate
    // (`verify_fleet_identity`); a candidate that proves a DIFFERENT device is
    // remembered here and skipped, and the dial moves on to the next one. This
    // used to end the whole connect, so `tunlion shell <sibling>` from a device
    // without a daemon broker (Windows) failed whenever another fleet member
    // answered first, reported as "can't reach" even when the target was online
    // and would have refused or served the shell in milliseconds.
    let mut fleet = FleetDial::default();
    // Sids that have sent us any signal (transport-offer, description,
    // candidate): those are answering peers, not ghosts, and the per-candidate
    // timer keeps them until their hard bound (`CandidateBound`).
    let mut heard_sids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut candidate_bound = CandidateBound::new(Duration::from_secs(net::WATCHDOG_SECS));

    let spawn_timer = |pid: String, g: u32| {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(candidate_secs)).await;
            let _ = tx.send(Ev::Stuck(pid, g));
        });
    };

    // Distinct wording for the shell-auth pre-flight so the two sequential
    // bring-ups of `tunlion shell --ssh` (the bootstrap link, then the netcat data link)
    // do not read as a flap/retry of one connection. "bootstrap" has its own
    // wording; "reconnect" is silent (post-warm resume check — the link was
    // already up; re-reporting it after a clean logout is noise).
    let silent = role.starts_with("reconnect");
    // `exec` is the one role whose wait line is a DEFERRED transient: a warm or
    // fast cold path must print nothing, a pipe/quiet/JSON run must print
    // nothing, and a slow path gets one line that is erased the instant we are
    // ready. Every other role keeps its established wording.
    let exec_wait = role == "exec" && crate::ui::wait_status_enabled();
    let mut wait_line = ExecWaitLine::new(exec_wait);
    let wait_timer =
        tokio::time::sleep_until(tokio::time::Instant::now() + crate::ui::WAIT_STATUS_DELAY);
    tokio::pin!(wait_timer);
    if !silent && role != "exec" {
        crate::ui::say(&match role {
            "bootstrap" => format!("tunlion: authenticating with '{peer_name}'..."),
            _ => format!("\rtunlion: waiting for known device '{peer_name}'..."),
        });
    }

    // Presence re-subscribe cadence: while we have NOT yet discovered a candidate
    // (empty queue, no live peer), re-emit the ack'd subscribe every ~2s. This
    // recovers the inverse of the ack-roster race, the acceptor that subscribes
    // AFTER us, whose single async `known-peer` push to us is lost. The `up`
    // acceptor gets this self-healing free from its `sync` tick; the one-shot L2
    // initiator needs it explicitly or a lost push strands it in "presence"
    // forever. Cheap (one emit) and idempotent, and it STOPS the instant a
    // candidate is queued/dialing, so a healthy connect never re-subscribes.
    let mut resubscribe = tokio::time::interval(Duration::from_millis(2000));
    resubscribe.tick().await; // consume the immediate first tick (we just subscribed on Welcome)
    // How many re-join ticks we've waited with NO Welcome. rust_socketio's
    // websocket client occasionally finishes `.connect().await` in a state where
    // it can SEND but silently never DELIVERS inbound events to our handlers: the
    // server receives our `join` (and re-emits `welcome` on every retry, verified
    // in the backend telemetry) but this loop never sees `Ev::Welcome`, so it
    // hangs in "waiting for known device" no matter how many times we re-join the
    // SAME dead socket (the residual ~30% rapid-`ssh` failure). Re-emitting can't
    // fix a socket that won't receive, so after a couple of silent ticks we tear
    // the socket DOWN and dial a FRESH one (reconnect_signaling) on the same `tx`.
    let mut welcome_silent_ticks: u32 = 0;

    // Heartbeat so a slow establish never reads as a silent hang: every 7s while
    // still connecting, emit elapsed progress (skipped for `doctor`, which renders
    // its own per-phase ladder). The overall deadline lives at the call site.
    let connect_started = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(7));
    heartbeat.tick().await; // consume the immediate first tick
    // A known device whose daemon is not running never answers, and this loop
    // used to say only "still reaching" until the timeout. Once nothing has
    // answered for a few seconds, say the likely cause ONCE, and keep waiting
    // (it may still come up). "Answered" is a signal FROM a candidate, not its
    // presence: a daemon stopped without a clean leave stays on the roster as
    // a ghost for a while, and a fleet channel carries siblings that are not
    // the target. Keyed on presence, the first-time-user test saw `exec` and
    // `shell` against a stopped daemon print "still reaching ... (35s)" with
    // no hint at all, while `send` named the cause. A live acceptor offers its
    // transport the instant it sees us, well inside the hint delay.
    let mut heard_from_peer = false;
    let mut offline_hinted = false;
    let mut offline_check = tokio::time::interval(Duration::from_millis(500));
    offline_check.tick().await;

    loop {
        // One candidate at a time: start the next attempt whenever idle.
        if peer.is_none() {
            if let Some((pid, uid, candidate_present)) = queue.pop_front() {
                peer_present = candidate_present;
                // A candidate appeared and we are dialing it: presence is done,
                // we are now in the Establishing (WebRTC + direct-QUIC race)
                // phase. Latched so re-dials of later candidates don't re-emit.
                if !entered_establishing {
                    diag.enter(crate::diag::Phase::Establishing);
                    entered_establishing = true;
                }
                let Some(mine) = my_id.clone() else {
                    eprintln!("role election deferred for {pid}: local session ID unavailable");
                    continue;
                };
                let polite = match uid.as_deref() {
                    Some(peer_uid) => net::polite_role(&my_uid, peer_uid, &mine, &pid)?,
                    None => {
                        let source = if peer_present {
                            "presence"
                        } else {
                            "absent-roster"
                        };
                        net::polite_role_legacy(&my_uid, None, &mine, &pid, source, peer_present)?
                    }
                };
                generation += 1;
                candidate_bound.restart();
                spawn_timer(pid.clone(), generation);
                let p = Peer::connect(
                    pid.clone(),
                    my_uid.clone(),
                    polite,
                    cfg.ice_servers.clone(),
                    relay,
                    sio.clone(),
                    tx.clone(),
                    generation,
                )
                .await?;
                peer_uid = uid;
                peer = Some(p);
                if fleet_mode {
                    if let Some(offer) = fleet.on_dial(&pid) {
                        let _ = tx.send(Ev::Signal(offer));
                    }
                }

                // Item 3: also start a DIRECT-QUIC attempt racing the WebRTC
                // dial. Bind once, advertise to whichever candidate is current
                // (mirrors `start_direct`); the peer's own offer drives the
                // race (handled in Ev::Signal below). Gated on
                // `direct_enabled()` — when `TUNLION_DIRECT=0` (e.g. macOS
                // hyperkit CI), the L2 establish skips direct-quic entirely and
                // uses WebRTC (srflx / relay candidates), exercising the relay
                // fallback path.
                // --relay: no offer at all, it would carry our host/public
                // candidates to the peer (`direct_permitted`).
                if !direct_racing
                    && direct_race_allowed()
                    && crate::conn::direct_permitted(relay, crate::direct::direct_enabled())
                {
                    if endpoint.is_none() {
                        match crate::direct::bind_endpoint() {
                            Ok((ep, port)) => {
                                direct_cands =
                                    Some(crate::direct::gather_candidates(&transport_context, server, port).await);
                                endpoint = Some(ep);
                                // TRACE, direct-offer detail.
                                crate::ui::trace(&format!(
                                    "tunlion: DIRECT-OFFER sent to '{peer_name}', port {port}"
                                ));
                            }
                            Err(e) => {
                                crate::ui::trace(&format!(
                                    "tunlion: direct disabled (endpoint bind failed: {e}), WebRTC only"
                                ));
                            }
                        }
                    }
                    if endpoint.is_some() {
                        if let Some((c, server_public)) = &direct_cands {
                            // #237: advertise the address adopted on the server's
                            // say-so (the peer dials it and may have to name it)
                            // and our protocol version (gates the observed-address
                            // exchange on both sides).
                            let mut offer = json!({ "type": "transport-offer", "v": 1, "proto": 2, "addrs": c });
                            if let Some(s) = server_public {
                                offer["server_public"] = json!(s);
                            }
                            sio.emit("signal", json!({ "to": pid, "data": offer }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        let ev = tokio::select! {
            _ = &mut wait_timer, if exec_wait && !wait_line.shown => {
                wait_line.show(&format!("tunlion: waiting for known device '{peer_name}'..."));
                continue;
            }
            ev = rx.recv() => match ev {
                Some(ev) => ev,
                None => break,
            },
            _ = heartbeat.tick() => {
                if role == "exec" {
                    // A slow establish: refresh the transient line; it is erased
                    // by the guard when this function returns.
                    wait_line.show(&format!(
                        "tunlion: still reaching '{peer_name}'... ({}s)",
                        connect_started.elapsed().as_secs()
                    ));
                } else if role != "doctor" {
                    crate::ui::say(&format!(
                        "tunlion: still reaching '{peer_name}'... ({}s)",
                        connect_started.elapsed().as_secs()
                    ));
                }
                continue;
            }
            _ = offline_check.tick(), if !heard_from_peer => {
                if !offline_hinted && connect_started.elapsed() >= crate::conn::OFFLINE_HINT_AFTER {
                    offline_hinted = true;
                    if role == "exec" {
                        wait_line.show(&crate::conn::offline_hint(peer_name));
                    } else if role != "doctor" && !silent {
                        crate::ui::say(&crate::conn::offline_hint(peer_name));
                    }
                }
                // `exec` is a one-shot command: a peer that has not said a
                // single word in this long is not running a daemon (a killed
                // one lingers on the server's roster as a ghost), and waiting
                // out the whole connect timeout only delays the answer.
                if role == "exec" && connect_started.elapsed() >= EXEC_SILENT_PEER {
                    // Before blaming the peer, look at our own side: the local
                    // daemon's server link, this attempt's own signaling time,
                    // or no welcome from the server at all.
                    let own = crate::ping::own_link_from_daemon(crate::daemon_health::signaling().await.as_ref())
                        .or_else(|| crate::ping::slow_own_link_in(diag.timings()))
                        .or_else(|| {
                            my_id.is_none().then(|| crate::ping::OwnLink::Slow {
                                signaling_ms: connect_started.elapsed().as_millis() as u64,
                            })
                        });
                    if let Some(own) = own {
                        bail!(
                            "{}",
                            crate::ping::exec_silent_peer_own_link(peer_name, EXEC_SILENT_PEER.as_secs(), own)
                        );
                    }
                    bail!(
                        "'{peer_name}' did not answer within {}s: it is offline, or `tunlion up` is not running there",
                        EXEC_SILENT_PEER.as_secs()
                    );
                }
                continue;
            }
            _ = resubscribe.tick() => {
                if my_id.is_none() {
                    // No Welcome yet. Re-emit the `join` once (it may have raced the
                    // socket-ready and been dropped server-bound); but if the socket
                    // stays silent across a couple of ticks the socket itself is
                    // RECEIVE-dead, so dial a fresh one and re-join on it.
                    welcome_silent_ticks += 1;
                    if welcome_silent_ticks >= 2 {
                        welcome_silent_ticks = 0;
                        if let Ok(fresh) = net::reconnect_signaling(&transport_context, server, tx.clone()).await {
                            let _ = sio.disconnect().await;
                            sio = fresh;
                        }
                    }
                    sio.emit("join", join_payload.clone()).await.ok();
                } else if peer.is_none() && queue.is_empty() {
                    // Welcome landed but no candidate found yet: re-subscribe so a
                    // lost `known-peer` push / a late-appearing acceptor is still
                    // discovered. Stops the instant a candidate is queued/dialing.
                    net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
                }
                continue;
            }
        };
        let ev = unsource_event(ev);
        match ev {
            Ev::Welcome(v) => {
                my_id = v["id"].as_str().map(|s| s.to_string());
                // Signaling is live (socket + welcome); we now subscribe and wait
                // for the known device to appear, that is the Presence phase.
                diag.enter(crate::diag::Phase::Presence);
                // Subscribe now that the connection is confirmed (see the note at
                // the join site). DETERMINISTIC discovery: emit-with-ack and read
                // the roster the server returns synchronously, so a known device
                // already present is found even if its one-shot async `known-peer`
                // push is lost (the dominant presence stall, see
                // `net::subscribe_with_ack`). The periodic re-subscribe below
                // covers the inverse race (the acceptor appearing AFTER us).
                net::subscribe_with_ack(&sio, vec![channel.clone()], tx.clone()).await;
            }
            Ev::KnownPeer(v) => {
                if v["channel"].as_str() != Some(channel.as_str()) {
                    continue;
                }
                let pid = match v["id"].as_str() {
                    Some(p) => p.to_string(),
                    None => continue,
                };
                if Some(pid.as_str()) == my_id.as_deref() {
                    continue;
                }
                // #9: never dial our OWN install (the up subscribes this pair
                // channel too). Pair secrets are symmetric, so a self-connect
                // can pass the pair-proof and tunnel into the WRONG host's
                // sshd, the local daemon answering as the remote device.
                if crate::is_self_uid(&my_uid, v["uid"].as_str()) {
                    continue;
                }
                // Queue every distinct sid; the loop top rotates through them.
                if peer.as_ref().is_some_and(|p| p.id == pid)
                    || queue.iter().any(|(q, _, _)| *q == pid)
                {
                    continue;
                }
                let front = if fleet_mode {
                    match fleet.presence(&pid, v["name"].as_str(), peer_name) {
                        Some(front) => front,
                        None => continue,
                    }
                } else {
                    false
                };
                let entry = (pid, v["uid"].as_str().map(|s| s.to_string()), true);
                if front {
                    queue.push_front(entry);
                } else {
                    queue.push_back(entry);
                }
            }
            Ev::Signal(v) => {
                heard_from_peer = true;
                if let Some(from) = v["from"].as_str() {
                    if heard_sids.len() < 64 || heard_sids.contains(from) {
                        heard_sids.insert(from.to_string());
                    }
                }
                let data = v["data"].clone();
                // Item 3: a relayed `transport-offer` carries the peer's direct
                // candidates. Do NOT hand it to the WebRTC `Peer`; instead consume
                // our endpoint and spawn the simultaneous-open + auth race
                // (`race_connect_labeled`, the same primitive `start_direct`
                // drives). The winner posts Ev::DirectReady into THIS loop's tx,
                // so the DirectTransport's reader funnels Chunk/Control/PcState to
                // the rx the caller hands to `pump_initiator`.
                if data["type"].as_str() == Some("transport-offer") {
                    if !direct_race_allowed() {
                        continue;
                    }
                    // --relay hides our address from the peer: dialing its
                    // direct candidates would hand it our IP as the source.
                    if !crate::conn::direct_permitted(relay, true) {
                        continue;
                    }
                    if fleet_mode
                        && !fleet.offer(&v, peer.as_ref().map(|p| p.id.as_str()))
                    {
                        continue;
                    }
                    if direct_racing {
                        continue; // already racing the first offer; ignore re-sends
                    }
                    // Bind on-demand if the offer beat our own KnownPeer: on real
                    // WAN the already-running acceptor fires its offer the instant
                    // we appear, which can arrive BEFORE our presence event sets
                    // `endpoint`. The old `if let Some` silently DROPPED it and we
                    // never dialed (the cross-machine stall). We DIAL the peer's
                    // candidates, so we don't need to have sent our own offer first.
                    let ep = endpoint
                        .take()
                        .or_else(|| crate::direct::bind_endpoint().ok().map(|(ep, _)| ep));
                    if let Some(ep) = ep {
                        direct_racing = true;
                        let peer_cands: Vec<String> = data["addrs"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        // #237: the initiated race only runs the observed-address
                        // exchange when the PEER's offer says it speaks it; the
                        // peer makes the same decision from OUR offer (we always
                        // advertise proto 2), so both ends skip or both run.
                        let peer_proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                        let exchange = peer_proto >= 2;
                        // The L2 initiator has no fallback to attribute, and
                        // does not track the peer's claimed server-asserted
                        // address (dial-tracking is unused here, held so the
                        // shared race keeps a single signature).
                        let l2_dialed = Arc::new(AtomicBool::new(false));
                        // DEBUG, resilience/direct internal (racing a direct path).
                        crate::ui::debug(&format!(
                            "tunlion: got transport-offer ({} cand), racing direct-quic",
                            peer_cands.len()
                        ));
                        let secret = secret.clone();
                        let pid = v["from"].as_str().unwrap_or_default().to_string();
                        let peer_uid_for_race = match peer_uid.clone() {
                            Some(value) => value,
                            None => {
                                eprintln!("direct role election deferred for {pid}: no peer UID");
                                continue;
                            }
                        };
                        let my_uid_for_race = my_uid.clone();
                        let Some(my_id_for_race) = my_id.clone() else {
                            eprintln!(
                                "direct role election deferred for {pid}: local session ID unavailable"
                            );
                            continue;
                        };
                        let tx = tx.clone();
                        let transport_context = transport_context.clone();
                        let attempt = filament_transport::net::AttemptId::next();
                        direct_attempt = Some(attempt);
                        tokio::spawn(async move {
                            if let Some(t) = crate::direct::race_connect_labeled(
                                &transport_context,
                                ep,
                                peer_cands,
                                &secret,
                                pid.clone(),
                                attempt,
                                my_uid_for_race,
                                peer_uid_for_race,
                                my_id_for_race,
                                tx.clone(),
                                "direct-quic",
                                exchange,
                                None,
                                l2_dialed,
                            )
                            .await
                            {
                                // Announce, THEN read (direct.rs UnreadTransport).
                                t.announce(&tx, |t| Ev::DirectReady(pid, t, "direct-quic"));
                            }
                            // On None the WebRTC path (Ev::ChannelReady) continues.
                        });
                    }
                    continue;
                }
                // Route by sender: the channel is multi-party (our own up
                // subscribes it too, plus lingering dead sids), a stray offer
                // applied to the current pc was a reliable glare generator.
                let from = v["from"].as_str().unwrap_or_default();
                let Some(p) = &peer else { continue };
                if p.id != from {
                    continue;
                }
                match p.handle_signal(data).await {
                    Ok(net::SignalOutcome::Handled) => {}
                    Ok(net::SignalOutcome::Glare(offer)) => {
                        // Both sides offered (role confusion). Yield: rebuild
                        // this attempt as a pure responder answering theirs.
                        let old = peer.take().unwrap();
                        let pid = old.id.clone();
                        old.mark_closed();
                        tokio::spawn(async move { old.close().await });
                        generation += 1;
                        candidate_bound.restart();
                        spawn_timer(pid.clone(), generation);
                        let p = Peer::connect(
                            pid,
                            my_uid.clone(),
                            true,
                            cfg.ice_servers.clone(),
                            relay,
                            sio.clone(),
                            tx.clone(),
                            generation,
                        )
                        .await?;
                        if let Err(e) = p.handle_signal(offer).await {
                            crate::ui::trace(&format!("tunlion: signal: {e}"));
                        }
                        peer = Some(p);
                    }
                    Err(e) => crate::ui::trace(&format!("tunlion: signal: {e}")),
                }
            }
            Ev::DirectReady(pid, t, route) => {
                if t.attempt_id() != direct_attempt {
                    t.force_close();
                    direct_attempt = None;
                    continue;
                }
                direct_attempt = None;
                // Item 3: the DIRECT-QUIC race won before WebRTC. The acceptor's
                // `adopt_direct` (main.rs) is born `trusted: true` + identity-bound
                // `verified_name`, its pair-secret MAC already proved who we are,
                // so the cap gate is satisfied WITHOUT a pair-proof. We deliberately
                // do NOT replicate the ChannelReady proof here: that MAC is built
                // from the WebRTC DTLS fingerprints, which a direct QUIC link does
                // not have, and the acceptor's direct link (`peer: None`) has none
                // to verify against. (design-l2-direct-ladder.md §NOTE: pre-trust
                // OR pair-proof, we confirmed pre-trust holds for the L2 acceptor.)
                // INFO, tunnel established (with its route label). Silent for the
                // bootstrap pre-flight (internal; the data link reports the route)
                // and for reconnect roles (post-warm resume noise suppression).
                if !role.starts_with("reconnect") && role != "bootstrap" {
                    crate::ui::debug(&format!(
                        "\rtunlion: tunnel up to '{peer_name}' (route: {route})"
                    ));
                }
                // The fleet secret got us CONNECTED to a fleet member. It does not
                // say WHICH one: every sibling sits on the same channel, so a peer
                // answering to this name merely ASSERTED it. Prove it with the
                // certificate before the caller moves any bytes, or
                // `send --to laptop` could hand the file to whichever fleet device
                // answered first. Fails closed on a transport with no channel
                // binding, because there is nothing to bind the proof to. A
                // failed proof rejects THIS candidate, not the connect.
                if fleet_mode {
                    if let Err(e) = verify_fleet_identity(&t, &mut rx, &tx, &pid, peer_name, own_device).await {
                        crate::ui::debug(&format!("fleet: {e:#}; trying the next fleet device"));
                        t.force_close();
                        let mut uid = None;
                        if peer.as_ref().is_some_and(|p| p.id == pid) {
                            let p = peer.take().unwrap();
                            p.mark_closed();
                            tokio::spawn(async move { p.close().await });
                            uid = peer_uid.take();
                        }
                        if e.downcast_ref::<WrongFleetDevice>().is_some() {
                            fleet.reject(&pid);
                            queue.retain(|(q, _, _)| *q != pid);
                        } else if !queue.iter().any(|(q, _, _)| *q == pid) {
                            // Unproven, not disproven: it may be the target on a
                            // connection that lost a simultaneous open. Retry it.
                            queue.push_back((pid.clone(), uid, true));
                        }
                        // The next candidate gets its own direct race.
                        direct_racing = false;
                        continue;
                    }
                }
                // Transport is up: the Establishing race is won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                // The WebRTC `peer` is now superfluous; the guard owns it (its
                // teardown/forget semantics are unchanged, no extra teardown).
                let guard = LinkGuard {
                    sio: Some(sio),
                    peer: peer.take(),
                };
                return Ok((t, rx, guard, diag));
            }
            Ev::Stuck(pid, g) => {
                // Per-candidate timer (or the 15s watchdog) fired for the
                // CURRENT attempt. A silent candidate (a ghost) is dropped and
                // rotated: the sid goes to the back of the queue and just cycles
                // until the server evicts it. One that is answering is kept
                // until its hard bound (`CandidateBound::on_stuck`).
                if g == generation && peer.as_ref().is_some_and(|p| p.id == pid) {
                    let progressing = match peer.as_ref() {
                        Some(p) => p.is_connected() || p.establishing_progress().await,
                        None => false,
                    };
                    if !candidate_bound.on_stuck(
                        heard_sids.contains(&pid),
                        progressing,
                        &tx,
                        &pid,
                        g,
                    ) {
                        // DEBUG: the timer fired on a peer that is answering.
                        crate::ui::debug(&format!(
                            "tunlion: candidate answering (ice progress: {progressing}), keeping it until its {}s bound",
                            net::WATCHDOG_SECS
                        ));
                        continue;
                    }
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    // The per-candidate establish budget fired: this candidate
                    // wedged and we rotate. Record a stall (the "burns the budget
                    // then succeeds on retry" signal we are hunting).
                    diag.stall(crate::diag::Phase::Establishing, candidate_bound.elapsed_ms());
                    crate::ui::debug("tunlion: candidate unresponsive, rotating");
                    queue.push_back((pid, peer_uid.take(), peer_present));
                    // On the fleet channel the next candidate may be the target,
                    // and the direct race is the only path that can prove it
                    // (see the ChannelReady arm), so it gets its own race. A late
                    // win from the abandoned race is still certificate-checked.
                    if fleet_mode {
                        direct_racing = false;
                    }
                }
            }
            Ev::ChannelReady(pid, t) if peer.as_ref().is_some_and(|p| p.id == pid) => {
                // A fleet-secret link can only be proven by a certificate bound
                // to the link, and a WebRTC data channel exposes no binding, so
                // it can never pass `verify_fleet_identity`. Do not let it end
                // the connect: keep this candidate's direct-QUIC race going (it
                // has the binding), and the per-candidate timer rotates if that
                // never lands. Nothing is sent over the unproven channel.
                if fleet_mode && t.channel_binding().is_none() {
                    crate::ui::debug(&format!(
                        "fleet: data channel to a candidate for '{peer_name}' cannot be bound to a certificate; waiting for its direct path"
                    ));
                    continue;
                }
                // Prove identity so the peer's up/recv marks this link trusted,
                // the acceptor's capability gate keys on exactly that.
                if let Some(p) = &peer {
                    if let Some((my_fp, their_fp)) = p.fingerprints().await {
                        let mac = crate::proof_for(
                            &secret,
                            &my_uid,
                            &my_uid,
                            peer_uid.as_deref().unwrap_or(""),
                            &my_fp,
                            &their_fp,
                        );
                        t.send_control(&json!({ "type": "pair-proof", "mac": mac }))
                            .await?;
                    }
                }
                // Hand sio + peer to the caller via a guard: a long-lived tunnel
                // `forget()`s it (keep alive); the bootstrap `close().await`s it
                // (tear down before the second link).
                // DEBUG, like the direct-QUIC arm above: a transport being up
                // says nothing about whether the peer will serve this device.
                // At INFO it read as a promise, and a forgotten device saw
                // "tunnel up to 'alpha'" right before alpha refused it.
                if !role.starts_with("reconnect") && role != "bootstrap" {
                    crate::ui::debug(&format!("tunlion: tunnel up to '{peer_name}'"));
                }
                // Transport is up via WebRTC: Establishing race won. Record Ready;
                // the caller records the L2Open round trip and the final `up`.
                diag.enter(crate::diag::Phase::Ready);
                // Same certificate proof as the direct arm above; the binding
                // exists here (checked at the top of this arm).
                if fleet_mode {
                    if let Err(e) = verify_fleet_identity(&t, &mut rx, &tx, &pid, peer_name, own_device).await {
                        crate::ui::debug(&format!("fleet: {e:#}; trying the next fleet device"));
                        t.force_close();
                        let mut uid = None;
                        if peer.as_ref().is_some_and(|p| p.id == pid) {
                            let p = peer.take().unwrap();
                            p.mark_closed();
                            tokio::spawn(async move { p.close().await });
                            uid = peer_uid.take();
                        }
                        if e.downcast_ref::<WrongFleetDevice>().is_some() {
                            fleet.reject(&pid);
                            queue.retain(|(q, _, _)| *q != pid);
                        } else if !queue.iter().any(|(q, _, _)| *q == pid) {
                            // Unproven, not disproven: it may be the target on a
                            // connection that lost a simultaneous open. Retry it.
                            queue.push_back((pid.clone(), uid, true));
                        }
                        direct_racing = false;
                        continue;
                    }
                }
                let guard = LinkGuard {
                    sio: Some(sio),
                    peer: peer.take(),
                };
                return Ok((t, rx, guard, diag));
            }
            Ev::PcState(pid, s) if s == "failed" || s == "closed" => {
                // Was fatal; now just rotate, the overall command timeout
                // (or the user) bounds how long we keep trying.
                if peer.as_ref().is_some_and(|p| p.id == pid) {
                    let p = peer.take().unwrap();
                    p.mark_closed();
                    tokio::spawn(async move { p.close().await });
                    crate::ui::debug(&format!("tunlion: connection {s}, rotating"));
                    queue.push_back((pid, peer_uid.take(), peer_present));
                }
            }
            _ => {}
        }
    }
    diag.fail("signaling ended before a data channel came up");
    Err(anyhow!("signaling ended before a data channel came up"))
}

// ------------------------------------------------------------- DOCTOR PROBE --
//
// `tunlion doctor <device>` drives this: an "establish then drop" probe that
// runs the EXACT same bring-up as netcat (`bring_up_to_known` with role
// "doctor"), opens one L2 stream so the L2Open round trip is exercised, then
// IMMEDIATELY tears the link down. It never opens a shell or moves payload. The
// point is to surface WHERE establishment is slow or stalls, using the same
// `Attempt` instrumentation (phases + budgets) a real connect uses, so the
// ladder a probe prints matches what a live ssh would have hit.

/// The result of one `establish_probe`: the per-phase ladder (reused verbatim
/// from the `Attempt`), the total span time, and the terminal verdict.
pub struct ProbeOutcome {
    /// Per-phase timings, in completion order (signaling, presence, ...). Each
    /// carries its over-budget flag, computed by `diag::over_budget`.
    pub timings: Vec<crate::diag::PhaseTiming>,
    /// Total establish time, signaling start to link usable.
    pub total_ms: u64,
    /// True iff the link came up. On `false`, `failed_phase` says where it died.
    pub established: bool,
    /// On failure, the phase the bring-up was IN when it gave up.
    pub failed_phase: Option<crate::diag::Phase>,
    /// On failure, the error string.
    pub error: Option<String>,
    /// On success, the path the probe link actually took (interface, address
    /// class, endpoints) - so `tunlion doctor` shows the route in the same fine
    /// detail as `tunlion reach`. `None` when the link never came up.
    pub path: Option<crate::net::PathInfo>,
}

/// Establish a link to `peer` exactly as netcat would, then drop it. Returns the
/// per-phase timings + verdict. Reuses `bring_up_to_known` (role "doctor"), so
/// the phases/budgets are identical to a real connect, and cleans up BOTH the
/// link (LinkGuard::close) and the mux (no leaked streams/pumps).
///
/// `timeout_secs` is the caller's bound: `reach --timeout` and
/// `doctor --timeout` pass theirs (None = TUNLION_DOCTOR_PROBE_SECS or 30 s).
/// The outer bound of one `doctor <device>` probe, in seconds: `--timeout`,
/// else TUNLION_DOCTOR_PROBE_SECS, else 30. Doctor announces it before it
/// starts, so the wait is never a silent one.
pub(crate) fn doctor_probe_secs(timeout_secs: Option<u64>) -> u64 {
    timeout_secs.filter(|n| *n > 0).unwrap_or_else(|| {
        std::env::var("TUNLION_DOCTOR_PROBE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30)
    })
}

pub async fn establish_probe_within(
    server: &str,
    peer: &str,
    relay: bool,
    timeout_secs: Option<u64>,
) -> Result<ProbeOutcome> {
    // Overall safety bound so a wedged candidate cannot hang the probe forever
    // (the per-candidate rotation already re-races inside bring_up_to_known; this
    // is the outer wall). Generous: a slow-but-real ICE lands around 5s and we
    // want to OBSERVE that, not abort it prematurely. Overridable for the field.
    let probe_secs = doctor_probe_secs(timeout_secs);
    let deadline = std::time::Duration::from_secs(probe_secs);

    // The span id is ours, so a failure reads back THIS probe's ladder, not
    // whichever process wrote to the shared diag JSONL last.
    let span_id = crate::diag::correlation_id();
    match tokio::time::timeout(deadline, bring_up_to_known_in_span(server, peer, relay, "doctor", span_id.clone())).await {
        Ok(Ok((t, rx, guard, mut diag))) => {
            // The link is up (Ready recorded). Exercise the L2Open round trip the
            // same way netcat does: pump inbound events, open one stream (sends
            // l2-open), record `up`. We do NOT wait on payload; the open is the
            // last establishment rung we care about.
            let mux = Mux::new(t, crate::host_impl::cli_host());
            let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

            diag.enter(crate::diag::Phase::L2Open);
            // rport is irrelevant for the timing: the acceptor dials localhost:0
            // and refuses, but the l2-open / l2-close round trip is what we time.
            // Use a benign port and tear the stream down immediately afterwards.
            let probe_rport: u16 = 9; // discard
            let (sid, _rx_pipe) = open_stream(&mux, probe_rport).await?;
            diag.up("tunnel", "datachannel-or-direct");

            // Capture the path BEFORE teardown: the transport (direct) or the
            // guard's webrtc peer (relay) still holds the live endpoints here.
            let path = Some(
                crate::net::describe_path(mux.transport().as_ref(), guard.peer.as_deref()).await,
            );

            // Tear DOWN, no leak: drop the stream, tell the peer, stop the pump,
            // and close the link (peer + signaling), so the acceptor reaps us.
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            mux.shutdown_all().await;
            pump.abort();
            guard.close().await;

            Ok(ProbeOutcome {
                timings: diag.timings().to_vec(),
                total_ms: diag.total_ms(),
                established: true,
                failed_phase: None,
                error: None,
                path,
            })
        }
        Ok(Err(e)) => {
            // bring_up_to_known recorded `fail` on its (now-consumed) Attempt and
            // wrote the partial ladder to the JSONL. Read it back so the verdict
            // can name where it died, the SAME timings a live connect recorded.
            let (timings, failed_phase) = match crate::diag::span_ladder(&span_id) {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: 0,
                established: false,
                failed_phase,
                error: Some(e.to_string()),
                path: None,
            })
        }
        Err(_elapsed) => {
            // The outer wall fired: the bring-up is still running (the Attempt was
            // never returned). Recover whatever ladder it logged so far.
            let (timings, failed_phase) = match crate::diag::span_ladder(&span_id) {
                Some((t, p)) => (t, Some(p)),
                None => (Vec::new(), None),
            };
            Ok(ProbeOutcome {
                timings,
                total_ms: probe_secs * 1000,
                established: false,
                failed_phase,
                error: Some(format!("establishment timed out after {probe_secs}s")),
                path: None,
            })
        }
    }
}

/// Drive the initiator's inbound event pump: route L2 control/data into the mux
/// and tear everything down on data-channel death. The initiator never accepts
/// inbound opens (it allocates ids); an l2-open-ack is delivered to the stream as a
/// liveness marker so warm-reuse verification passes even for a client-speaks-first
/// protocol (see `Mux::on_open_ack`).
async fn pump_initiator(mut rx: mpsc::UnboundedReceiver<Ev>, mux: Arc<Mux>) {
    let source = mux.transport().source_id();
    while let Some(ev) = rx.recv().await {
        let Some(ev) = selected_event(ev, source) else {
            continue;
        };
        match ev {
            Ev::Control(_pid, v) => match v["type"].as_str() {
                Some("l2-close") => {
                    if let Some(sid) = wire_sid(&v) {
                        mux.on_close(sid, v["err"].as_str()).await;
                    }
                }
                Some("l2-open-ack") => {
                    if let Some(sid) = wire_sid(&v) {
                        mux.on_open_ack(sid).await;
                    }
                }
                Some("mount-open-ack") | Some("pty-open-ack") => {
                    if let Some(sid) = wire_sid(&v) {
                        if let Some(tx) = mux.take_open_ack(sid).await {
                            let _ = tx.send(OpenOutcome::Opened(v.clone()));
                        }
                    }
                }
                _ => {}
            },
            Ev::Chunk(_pid, sid, _offset, data) if is_l2_sid(sid) => {
                mux.on_frame(sid, data).await;
            }
            Ev::PcState(pid, s)
                if s == "failed" || s == "closed" || s == "disconnected" =>
            {
                // ICE/WebRTC candidates race the direct QUIC transport and
                // report state through the same event channel. A losing
                // candidate's state is not evidence that this mux's selected
                // transport died. Only its own liveness can retire the mux.
                if !mux.transport().is_alive() {
                    crate::ui::debug(&format!(
                        "tunlion: tunnel {s} for {pid}, closing streams"
                    ));
                    mux.shutdown_all().await;
                } else {
                    crate::ui::trace(&format!(
                        "tunlion: ignoring tunnel {s} for {pid}; selected transport is alive"
                    ));
                }
            }
            _ => {}
        }
    }
    mux.shutdown_all().await;
}

/// What the peer said to one probe open of `rport`, before `forward` says ready.
#[cfg(feature = "forward-server")]
pub(crate) enum ForwardProbe {
    Accepted,
    Refused(String),
    Silent,
}

/// Ask the peer to open `rport` once and close it again, so `forward` can tell
/// the user the truth BEFORE it claims to be ready: it used to print "ready"
/// having asked nothing, and the first client got an empty reply while the
/// refusal went to a log. Costs one connect+close on the peer's target port.
#[cfg(feature = "forward-server")]
async fn probe_forward(mux: &Arc<Mux>, rport: u16) -> ForwardProbe {
    let Ok((sid, mut rx)) = open_stream(mux, rport).await else {
        return ForwardProbe::Silent;
    };
    let outcome = tokio::time::timeout(Duration::from_secs(8), rx.recv()).await;
    match outcome {
        // The ack's liveness marker, or a server-speaks-first banner: open.
        Ok(Some(_)) => {
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            ForwardProbe::Accepted
        }
        Ok(None) => match mux.take_close_err(sid).await {
            Some(reason) => ForwardProbe::Refused(reason),
            None => ForwardProbe::Silent,
        },
        Err(_) => {
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            ForwardProbe::Silent
        }
    }
}

/// How `forward` should treat one refusal from the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardRefusal {
    /// The peer's POLICY says no (tunnels off, no grant, revoked grant or
    /// certificate, ceiling, untrusted device): every later connection will be
    /// refused the same way, so retrying is pointless and a supervisor must be
    /// told.
    Policy,
    /// The peer is willing, but nothing accepts on the target port there. A
    /// service may start later, so the forward keeps running.
    NothingListening,
    /// Anything else (the acceptor's stream cap, another dial error): this
    /// connection failed; the forward keeps running and retries as before.
    Transient,
}

/// Classify a refusal reason as carried in `l2-close{err}`. Policy is decided
/// by the canonical reasons `refusal::code_from_reason` recognizes, plus the
/// acceptor's bare "denied" for an untrusted device. A closed target port is
/// recognized by the OS dial error ("Connection refused" on unix, "actively
/// refused it" on Windows).
pub(crate) fn classify_forward_refusal(reason: &str) -> ForwardRefusal {
    let r = reason.trim();
    if crate::refusal::code_from_reason(r).is_some() || r == "denied" {
        return ForwardRefusal::Policy;
    }
    if r.to_ascii_lowercase().contains("refused") {
        return ForwardRefusal::NothingListening;
    }
    ForwardRefusal::Transient
}

/// Exit status of a running `forward` that the peer stopped allowing (grant or
/// certificate revoked, tunnels turned off): distinct from a plain failure (1)
/// so a supervisor can tell "denied, a restart will not help" from "broke".
///
/// 4 is `exit_codes::ExitKind::Denied` in the exit-code taxonomy
/// (cli/src/exit_codes.rs, #393). It is a literal here only because this branch
/// predates exit_codes.rs; once both have merged, switch it to that constant.
pub(crate) const FORWARD_DENIED_EXIT: i32 = 4;

/// What the startup probe learned about the target, for the "ready" line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "forward-server")]
pub(crate) enum ForwardTarget {
    /// The peer accepted the probe (or gave no conclusive answer).
    Open,
    /// The peer is willing, but nothing listens on the target port yet.
    NothingListening,
}

/// The word that opens the "ready" line, carrying the target's state so a
/// warning printed above it is not contradicted by a bare "ready" below it.
#[cfg(feature = "forward-server")]
pub(crate) fn forward_ready_word(rport: u16, target: ForwardTarget) -> String {
    match target {
        ForwardTarget::Open => "ready".to_string(),
        ForwardTarget::NothingListening => {
            format!("ready (nothing is listening on {rport} there yet)")
        }
    }
}

/// The final line a forward prints when the peer's policy stops it.
#[cfg(feature = "forward-server")]
pub(crate) fn forward_denied_line(peer: &str, rport: u16, reason: &str) -> String {
    format!(
        "tunlion: forward to {peer}:{rport} stopped: {peer} no longer allows it ({reason}); not listening any more (exit {FORWARD_DENIED_EXIT})"
    )
}

/// What a forward prints when a connection waited the whole bound for a peer
/// that never answered.
#[cfg(feature = "forward-server")]
pub(crate) fn forward_unreachable_line(peer: &str, secs: u64) -> String {
    format!(
        "tunlion: cannot reach {peer} (no answer within {secs}s); closed the connection, and new ones are closed at once until {peer} is back (check with `tunlion reach {peer}`)"
    )
}

/// The remedy lines for a policy refusal, when the reason carries a known code.
#[cfg(feature = "forward-server")]
fn forward_refusal_fix(peer: &str, reason: &str) -> Option<(String, Option<String>)> {
    let code = crate::refusal::code_from_reason(reason)?;
    let me = crate::refusal::name_from_reason(reason).unwrap_or_else(crate::display_name);
    Some(crate::refusal::remedy_from_reason(code, peer, &me, reason))
}

/// G: `forward` rides the shell grant, so a device without one was refused
/// with the shell remedy (a grant, or a re-enrolment for a ceiling) even for a
/// port the peer had EXPOSED, which needs no shell at all. For a refusal about
/// shell, also name the route that works for an exposed port: `<peer>.mesh`,
/// directly with a kernel TUN or through the daemon's SOCKS5 proxy. Pure.
#[cfg(feature = "forward-server")]
pub(crate) fn forward_exposed_note(peer: &str, rport: u16, reason: &str) -> Option<String> {
    use crate::refusal::Code;
    let code = crate::refusal::code_from_reason(reason)?;
    matches!(
        code,
        Code::ShellOff | Code::TunnelOff | Code::NotGranted | Code::Revoked | Code::Ceiling
    )
    .then(|| {
        let host = format!("{}.mesh", peer.to_ascii_lowercase());
        format!(
            "If '{peer}' exposed port {rport} (`tunlion expose {rport}` there), no shell is needed: \
             open {host}:{rport} directly, or through the SOCKS5 proxy `tunlion up` runs here \
             (`tunlion status` shows its curl line), e.g. curl -x socks5h://... http://{host}:{rport}/"
        )
    })
}

/// Act on a probe verdict: a POLICY refusal (the peer will refuse every
/// connection: tunnels off, no grant, revoked) ends the forward now with the
/// reason and its remedy; a refusal of the target port itself (nothing
/// listening there yet) is a warning, since a service may start later.
#[cfg(feature = "forward-server")]
fn forward_probe_verdict(peer: &str, rport: u16, probe: ForwardProbe) -> Result<ForwardTarget> {
    match probe {
        ForwardProbe::Accepted | ForwardProbe::Silent => Ok(ForwardTarget::Open),
        ForwardProbe::Refused(reason) => match classify_forward_refusal(&reason) {
            ForwardRefusal::Policy => {
                let mut fix = match forward_refusal_fix(peer, &reason) {
                    Some((text, Some(c))) => format!("\n  {text}\n    {c}"),
                    Some((text, None)) => format!("\n  {text}"),
                    None => String::new(),
                };
                if let Some(note) = forward_exposed_note(peer, rport, &reason) {
                    fix.push_str(&format!("\n  {note}"));
                }
                bail!("tunlion: {peer}:{rport} refused the connection: {reason}{fix}");
            }
            ForwardRefusal::NothingListening => {
                crate::ui::critical(&format!(
                    "tunlion: {peer}:{rport} refused a test connection: {reason}. Nothing is accepting on port {rport} there right now; connections will fail until something listens on it."
                ));
                Ok(ForwardTarget::NothingListening)
            }
            ForwardRefusal::Transient => {
                crate::ui::critical(&format!(
                    "tunlion: {peer}:{rport} refused a test connection: {reason}. The forward stays up; connections may fail until that clears."
                ));
                Ok(ForwardTarget::Open)
            }
        },
    }
}

/// Open a mesh-native mount stream to the peer, sending `mount-open` with the
/// encoded root path. Waits for the `mount-open-ack` control message carrying
/// server capabilities, then sends `mount-cap-ack` to confirm the negotiated
/// protocol. Returns sid + inbound pipe + the server's MountCaps.
/// No sshd, no sshfs.
async fn open_mount_stream(
    mux: &Arc<Mux>,
    root: &str,
) -> Result<(u32, mpsc::Receiver<PipeItem>, crate::mount_proto::MountCaps)> {
    let sid = mux.alloc_sid();
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("mount open: sid {sid:#x} already in use"))?;
    let outcome_rx = mux.arm_open_ack(sid).await;
    let encoded = crate::mount_proto::path_encode(std::path::Path::new(root));
    mux.transport()
        .send_control(&json!({ "type": "mount-open", "sid": sid, "root": encoded }))
        .await?;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), outcome_rx)
        .await
        .map_err(|_| anyhow::anyhow!("mount-open-ack not received (timed out)"))?
        .map_err(|_| anyhow::anyhow!("mount-open-ack channel closed"))?;
    // #206: an l2-close from the acceptor is a DENIAL (authorization, ceiling,
    // stream cap) carrying a reason. It must surface as a denial, never as a
    // transport-shaped timeout. Silence still means timeout; a refusal is never
    // silent.
    let caps_value = match outcome {
        OpenOutcome::Opened(v) => v.get("caps").cloned().unwrap_or(serde_json::Value::Null),
        OpenOutcome::Refused(reason) => return Err(anyhow!("mount denied by {reason}")),
        OpenOutcome::ClosedWithoutAck => {
            return Err(anyhow!("mount denied by connection closed by the peer"));
        }
    };
    let caps = crate::mount_proto::parse_mount_caps(caps_value)?;
    // Send mount-cap-ack: the client confirms it accepts the server's caps.
    let _ = mux
        .transport()
        .send_control(&json!({
            "type": "mount-cap-ack", "sid": sid,
            "binary_frames": caps.protocol_version >= 2
        }))
        .await;
    Ok((sid, rx, caps))
}


/// Pump this process's stdio over a connected warm-reuse socket: stdin -> sock,
/// sock -> stdout. Exit when the remote half closes (sock read EOF), the same
/// "session over" semantics the cold netcat path has. Its OWN `tokio::io::stdin()`
/// is fine here because netcat is a single-shot ProxyCommand (one process, one
/// attach, no reconnect): the singleton is created once and never handed off.
#[cfg(unix)]
async fn pump_stdio_over(sock: tokio::net::UnixStream) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    let writer = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut wr).await; // local EOF
        let _ = wr.shutdown().await; // half-close so the remote sees our EOF
    });
    let mut stdout = tokio::io::stdout();
    tokio::io::copy(&mut rd, &mut stdout).await?;
    let _ = stdout.flush().await;
    writer.abort();
    Ok(())
}

/// `tunlion forward <peer> <port>`: wire this process's stdio to a service the peer
/// EXPOSED on its overlay address, over L3 (the overlay-port counterpart of
/// `netcat`; also an ssh ProxyCommand for an overlay-exposed sshd). Goes through the
/// local daemon, which resolves the peer to its verified overlay address and dials
/// it, so it works from a userspace node with no kernel route.
#[cfg(unix)]
pub async fn dial_cmd(peer: &str, port: u16) -> Result<()> {
    match crate::ctl::try_dial(peer, port).await {
        Some(sock) => pump_stdio_over(sock).await,
        None => bail!(
            "could not dial {peer}.mesh:{port} over the overlay (is the daemon up, the peer paired, and the port expose'd on it?)"
        ),
    }
}

#[cfg(not(unix))]
pub async fn dial_cmd(_peer: &str, _port: u16) -> Result<()> {
    bail!("tunlion: `forward` needs the local daemon's control socket (unix only)")
}

/// `tunlion netcat <peer> <rport>`: wire this process's stdio to one L2 stream.
/// This is the ssh ProxyCommand primitive.
#[cfg(feature = "forward-server")]
pub async fn netcat_cmd(server: &str, peer: &str, rport: u16, relay: bool) -> Result<()> {
    // WARM-LINK FAST PATH: if a local `up` daemon already holds a link to `peer`,
    // ride it (no signaling, no establishment, ~1s saved). Skipped under --relay
    // (the user forced a relay path; a warm link may be direct) and self-heals: any
    // miss / no daemon / dead stream falls through to a fresh establish below.
    // Unix-only: the control socket is a unix-domain socket (no-op elsewhere).
    #[cfg(unix)]
    if !relay {
        match crate::ctl::try_open_reason(peer, rport).await {
            Ok(sock) => {
                crate::ui::trace(&format!(
                    "tunlion: reusing warm link to '{peer}' (no establish)"
                ));
                return pump_stdio_over(sock).await;
            }
            // The PEER answered no through the warm link (expired, revoked,
            // not granted): that is definitive, and the cold path would only
            // ask again. Say it and exit as denied.
            Err(Some(r)) if r.starts_with("refused:") => {
                let reason = r.trim_start_matches("refused:").trim().to_string();
                if classify_forward_refusal(&reason) == ForwardRefusal::Policy {
                    let (code, as_name) = (
                        crate::refusal::code_from_reason(&reason),
                        crate::refusal::name_from_reason(&reason),
                    );
                    return Err(crate::exit_codes::err(
                        crate::exit_codes::ExitKind::Denied,
                        crate::refusal::explain("forward", peer, &reason, code, as_name.as_deref()),
                    ));
                }
            }
            Err(_) => {}
        }
    }
    // Bound the connect so an unreachable peer fails with a clear message
    // instead of hanging forever. Override with TUNLION_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("TUNLION_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, "init"),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            crate::ui::problem(
                &format!("tunlion netcat: can't reach '{peer}'"),
                &format!(
                    "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                ),
                &[
                    format!(
                        "check it's reachable: {}",
                        crate::ui::paint(crate::ui::Tone::Brand, &format!("tunlion reach {peer}"))
                    ),
                    format!(
                        "diagnose the connect: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("tunlion doctor {peer}")
                        )
                    ),
                ],
            );
            std::process::exit(1);
        }
    };
    guard.forget(); // long-lived tunnel, keep the link alive for the process
    let mux = Mux::new(t, crate::host_impl::cli_host());
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    // L2Open round trip: open the stream and wait for the acceptor's l2-open-ack
    // (the stream-is-live confirmation) before declaring the link Up. The ack is
    // consumed by pump_initiator, so we instead wait for the FIRST inbound byte
    // or a bounded grace, the practical "stream usable" signal for stdio netcat.
    diag.enter(crate::diag::Phase::L2Open);
    let (sid, mut rx_pipe) = open_stream(&mux, rport).await?;
    // The link is now usable end to end (the ssh handshake will flow). Record
    // `up` with the route label we can infer (the transport carries no route()
    // for a direct link, so we report the generic tunnel transport here).
    diag.up("tunnel", "datachannel-or-direct");

    // stdin -> dc
    let t_in = mux.transport();
    let reader = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let cap = t_in.max_payload();
        let mut buf = vec![0u8; cap];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = t_in.send_frame(sid, 0, &[]).await; // local EOF -> FIN
                    break;
                }
                Ok(n) => {
                    if t_in.send_frame(sid, 0, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // dc -> stdout
    let mut stdout = tokio::io::stdout();
    while let Some(item) = rx_pipe.recv().await {
        match item {
            Some(bytes) => {
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            None => break, // peer FIN
        }
    }
    // The acceptor closed the stream WITH a reason: a refusal at open (no
    // grant, expired, revoked) or a policy cut mid-stream. That is a denial,
    // exit 4 with the reason and its remedy, never the clean exit 0 a refused
    // cold forward used to report with nothing on the terminal. Not waiting on
    // stdin: the stream is over and nothing more will be read from it.
    if let Some(reason) = mux.take_close_err(sid).await {
        reader.abort();
        mux.drop_stream(sid).await;
        pump.abort();
        if classify_forward_refusal(&reason) == ForwardRefusal::Policy {
            let (code, as_name) = (crate::refusal::code_from_reason(&reason), crate::refusal::name_from_reason(&reason));
            return Err(crate::exit_codes::err(
                crate::exit_codes::ExitKind::Denied,
                crate::refusal::explain("forward", peer, &reason, code, as_name.as_deref()),
            ));
        }
        bail!("forward to {peer}:{rport} closed by {peer}: {reason}");
    }
    let _ = reader.await;
    mux.drop_stream(sid).await;
    let _ = mux
        .transport()
        .send_control(&json!({ "type": "l2-close", "sid": sid }))
        .await;
    pump.abort();
    Ok(())
}

fn port_in_use_msg(lport: u16, peer: &str, rport: u16) -> String {
    let suggested = lport.saturating_add(1);
    // The suggestion must be a command that PARSES. It used to print the
    // positional form `forward <lport> <peer> <rport>`, which the CLI rejects
    // ("unexpected argument"); a first-time-user test copied it verbatim, and it
    // was the one place the tool told them something wrong. The real shape is
    // `forward <device>:<port> --lport <n>` (cli_def.rs Forward), and
    // a_suggested_forward_command_parses pins that.
    format!(
        "tunlion: local port {lport} is already in use, pick another (e.g. tunlion forward {peer}:{rport} --lport {suggested})"
    )
}

/// Bidirectionally copy an accepted local TCP connection and a warm-reuse unix
/// socket (the daemon bridges the unix socket to an L2 stream over its existing
/// link). One copy per direction; either side's EOF ends the pair. Unix-only.
#[cfg(unix)]
async fn bridge_streams(
    mut tcp: TcpStream,
    mut unix: tokio::net::UnixStream,
) -> std::io::Result<()> {
    tokio::io::copy_bidirectional(&mut tcp, &mut unix)
        .await
        .map(|_| ())
}

/// `tunlion forward <lport> <peer> <rport>`: local TCP listener; every accepted
/// connection opens a fresh L2 stream to `peer:127.0.0.1:rport`.
///
/// WARM-LINK FAST PATH: when a local daemon already holds a link to `peer`, each
/// accepted connection rides it (no establishment) via the control socket. If the
/// daemon can't serve it (no daemon / no warm link / --relay), we fall back to
/// establishing ONE cold link lazily and multiplexing connections over it, the
/// original behavior. The warm path also sidesteps the single-link credit caveat:
/// each connection is an independent stream over the daemon's link.
/// Normalize a device name for self-comparison: lowercase, alphanumerics only, so
/// "pop-os", "popos", and "Pop_OS" all compare equal.
fn norm_device_name(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True when `peer` names THIS device (its configured name, that name's host part,
/// or the system hostname), so the forward would just loop back to this machine.
#[cfg(feature = "forward-server")]
fn forward_target_is_self(peer: &str) -> bool {
    let p = norm_device_name(peer);
    if p.is_empty() {
        return false;
    }
    let dn = crate::display_name();
    let host_part = dn.rsplit('@').next().unwrap_or("").to_string();
    // #184: /etc/hostname is UNIX-only; l3::hostname() handles Windows.
    let hostname = crate::l3::hostname();
    [dn.as_str(), host_part.as_str(), hostname.as_str()]
        .iter()
        .any(|c| !c.is_empty() && norm_device_name(c) == p)
}

/// Live per-connection accounting for `forward`, so the user can SEE it working
/// instead of staring at a static "ready" line. Increments on accept, decrements on
/// close (RAII), keeps one updating status line ("N active, M total"), and prints a
/// one-time confirmation on the very first forwarded connection.
#[cfg(feature = "forward-server")]
struct ForwardActivity {
    active: std::sync::Arc<std::sync::atomic::AtomicU64>,
    total: std::sync::Arc<std::sync::atomic::AtomicU64>,
    first: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// #232/#268: report a peer refusal ONCE. A browser retrying a dead port
    /// would otherwise repeat the same line per connection, and a reason
    /// printed twenty times reads as a storm rather than an explanation.
    refused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A POLICY refusal (revoked, not granted, tunnels off) is final: every later
    /// connection would be refused the same way. The connection task reports it
    /// here and the accept loop ends the process with the denied exit code, so a
    /// supervisor sees the forward stop instead of a listener that resets every
    /// client forever while the reason goes only to the log.
    denied: tokio::sync::mpsc::UnboundedSender<String>,
    /// The peer could not be reached within `cold_link_bound` and no live link
    /// has appeared since: new connections are closed at once rather than held.
    unreachable: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer: String,
    rport: u16,
}

#[cfg(feature = "forward-server")]
impl ForwardActivity {
    fn new(peer: &str, rport: u16) -> (Self, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let (denied, denied_rx) = tokio::sync::mpsc::unbounded_channel();
        let me = Self {
            active: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            first: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            refused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            denied,
            unreachable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            peer: peer.to_string(),
            rport,
        };
        (me, denied_rx)
    }
    fn line(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        crate::ui::status(&format!(
            "tunlion: forwarding to {}:{} - {} active, {} total",
            self.peer,
            self.rport,
            self.active.load(Relaxed),
            self.total.load(Relaxed)
        ));
    }
    /// A handle sharing the same counters, for the per-connection tasks.
    fn handle(&self) -> ForwardActivity {
        ForwardActivity {
            active: self.active.clone(),
            total: self.total.clone(),
            first: self.first.clone(),
            refused: self.refused.clone(),
            denied: self.denied.clone(),
            unreachable: self.unreachable.clone(),
            peer: self.peer.clone(),
            rport: self.rport,
        }
    }

    /// #232/#268: the peer said no, and said why. Surface it.
    ///
    /// Before this, `forward` printed an accept-time line and then nothing: a
    /// refusal reached `Mux::on_close`, which recorded the reason in `close_err`
    /// exactly so a caller could read it, and forward was the one caller that
    /// never did. pty already reads it via `take_close_err`. So this is wiring a
    /// channel that existed, not building one, which is the correction the
    /// reviewer made to my first description of this work.
    ///
    /// Reported for EVERY refused connection, on stderr at the level `-q` keeps:
    /// a client that gets an empty reply needs the reason each time, not only
    /// the first. The remedy (when the reason has one) is printed once.
    ///
    /// A POLICY refusal is different in kind: the forward cannot work again
    /// until the owner changes something, so its remedy is always printed and
    /// the accept loop is told to end the process (`FORWARD_DENIED_EXIT`).
    /// Anything else (nothing listening on the port, a transient failure) keeps
    /// the forward up, exactly as before.
    fn refused_once(&self, reason: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        crate::ui::critical(&format!(
            "tunlion: {}:{} refused the connection: {reason}",
            self.peer, self.rport
        ));
        let policy = classify_forward_refusal(reason) == ForwardRefusal::Policy;
        if self.refused.swap(true, Relaxed) && !policy {
            return;
        }
        if let Some((text, cmd)) = forward_refusal_fix(&self.peer, reason) {
            crate::ui::critical(&format!("  {text}"));
            if let Some(c) = cmd {
                crate::ui::critical(&format!("    {c}"));
            }
        }
        if let Some(note) = forward_exposed_note(&self.peer, self.rport, reason) {
            crate::ui::critical(&format!("  {note}"));
        }
        if policy {
            let _ = self.denied.send(reason.trim().to_string());
        }
    }

    /// A connection waited `cold_link_bound` for the peer and was closed. Said
    /// once per outage on stderr (a browser retrying would otherwise print a
    /// line per attempt); from here new connections are closed at once.
    fn unreachable(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.unreachable.swap(true, Relaxed) {
            crate::ui::critical(&forward_unreachable_line(&self.peer, cold_link_bound().as_secs()));
        }
    }

    /// The peer answered again: accept connections normally.
    fn reachable(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.unreachable.swap(false, Relaxed) {
            crate::ui::critical(&format!(
                "tunlion: {} is reachable again; forwarding connections",
                self.peer
            ));
        }
    }

    fn is_unreachable(&self) -> bool {
        self.unreachable.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Register a newly accepted connection; the returned guard decrements on drop.
    fn begin(&self) -> ConnGuard {
        use std::sync::atomic::Ordering::Relaxed;
        self.total.fetch_add(1, Relaxed);
        self.active.fetch_add(1, Relaxed);
        if !self.first.swap(true, Relaxed) {
            // #232: this used to read "first connection forwarded to X:Y", and it
            // fires on `listener.accept()`, before any l2-open has been sent. On
            // the cold path the peer has not been asked yet; on either path
            // `open_stream` returns as soon as the l2-open frame is WRITTEN, so
            // even that is not proof the peer accepted. The reporter saw
            // "the link is live" printed while curl got an empty reply.
            //
            // Accepting a local connection is true and narrower than the peer
            // forwarding it, so the line now claims only what is known here.
            // Proof of delivery is the first inbound frame, which lives behind
            // `verify_first_frame` on the warm path and behind `serve_stream`'s
            // shared plumbing on the cold one; reporting from there needs an
            // outcome channel that several other callers must NOT inherit, so it
            // is a follow-up rather than a claim made loosely here.
            crate::ui::say(&format!(
                "tunlion: first connection accepted, opening to {}:{}",
                self.peer, self.rport
            ));
        }
        self.line();
        ConnGuard {
            active: self.active.clone(),
            total: self.total.clone(),
            peer: self.peer.clone(),
            rport: self.rport,
        }
    }
}

#[cfg(feature = "forward-server")]
struct ConnGuard {
    active: std::sync::Arc<std::sync::atomic::AtomicU64>,
    total: std::sync::Arc<std::sync::atomic::AtomicU64>,
    peer: String,
    rport: u16,
}

#[cfg(feature = "forward-server")]
impl Drop for ConnGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.active.fetch_sub(1, Relaxed);
        crate::ui::status(&format!(
            "tunlion: forwarding to {}:{} - {} active, {} total",
            self.peer,
            self.rport,
            self.active.load(Relaxed),
            self.total.load(Relaxed)
        ));
    }
}

/// `tunlion mount <peer> <remote>`: open a mesh-native mount stream to the
/// peer and serve the remote filesystem over the mount protocol. No sshd,
/// no sshfs — the server runs the mount handler on the peer's side of the
/// authenticated mesh stream, and the client drives it via `MountClient`.
///
/// Returns a `MountClient` ready for FUSE or direct operations.
pub async fn mount_cmd(
    server: &str,
    peer: &str,
    relay: bool,
    root: &str,
) -> Result<crate::mount_proto::MountClient> {
    let (t, rx, guard, _diag) = bring_up_to_known(server, peer, relay, "mount").await?;
    guard.forget();
    let mux = Mux::new(t.clone(), crate::host_impl::cli_host());
    let _pump = tokio::spawn(pump_initiator(rx, mux.clone()));
    let (sid, pipe_rx, caps) = open_mount_stream(&mux, root).await?;
    let client = crate::mount_proto::MountClient::from_mux_v2(t.clone(), sid, pipe_rx, caps);
    Ok(client)
}

#[cfg(feature = "forward-server")]
pub async fn forward_cmd(
    server: &str,
    lport: u16,
    peer: &str,
    rport: u16,
    relay: bool,
) -> Result<()> {
    // Refuse a forward to THIS device before doing anything: it would just loop back,
    // and the generic "no known device" error hides what actually happened.
    if forward_target_is_self(peer) {
        bail!(
            "tunlion: '{peer}' is this device - a forward reaches a DIFFERENT machine. \
             Whatever runs on this host's :{rport} is already here as 127.0.0.1:{rport}; \
             point the forward at another peer (see `tunlion devices`)."
        );
    }
    // Resolve the peer against the paired devices UP FRONT, so an unknown/typo'd
    // target fails immediately with a clear message instead of after a premature
    // "ready" (the warm path used to announce success before ever reaching the peer).
    if !crate::devices_load()
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(peer))
    {
        bail!(
            "tunlion: no known device named '{peer}'. Add it first with `tunlion add`, \
             then `tunlion devices` shows who you can reach."
        );
    }
    // Bind first so a port conflict fails fast, before any network work.
    let listener = match TcpListener::bind(("127.0.0.1", lport)).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            bail!("{}", port_in_use_msg(lport, peer, rport));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(
                "tunlion: cannot bind 127.0.0.1:{lport}: permission denied. Local ports below \
                 1024 need root; pick a higher local port (e.g. `tunlion forward {peer}:{rport} --lport 8{lport:0>3}`) \
                 or run with sudo."
            );
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "tunlion: failed to bind 127.0.0.1:{lport} for forward to {peer}:127.0.0.1:{rport}"
            )));
        }
    };
    crate::ui::say(&format!(
        "tunlion: forwarding 127.0.0.1:{lport} -> {peer}:127.0.0.1:{rport}"
    ));

    // Ride a local `up` daemon's warm link when one exists (unix control socket):
    // connections are then instant and open NO new presence on the peer (the
    // daemon is the one connected), and the daemon reports its own link state.
    // Probed once, up front.
    #[cfg(unix)]
    let via_daemon = !relay && crate::ctl::daemon_present().await;
    #[cfg(not(unix))]
    let via_daemon = false;
    let warm = via_daemon; // per-connection warm attempts (unix only)

    // Cold link (no daemon): managed by a background task that establishes it,
    // WATCHES its liveness, and reconnects on loss, reporting lost/recovered so a
    // network blip is never silent (the old code held one link and never noticed).
    // Published via a watch channel the accept loop reads. Not started on the warm
    // path (that would create the extra presence we are avoiding).
    let (activity, mut denied_rx) = ForwardActivity::new(peer, rport);
    let mut cold_rx = if via_daemon {
        // Report the ACTUAL peer link state, not a blanket "ready". The daemon may
        // hold a live warm link (then connections really are instant) or none yet
        // (then it opens on the first connection) - saying "ready, instant" in the
        // second case is what left the user unsure whether it was forwarding.
        // Ask once through the daemon, so a refusal ends the forward here with
        // its reason instead of reaching the first client as an empty reply.
        let target = match crate::ctl::forward_probe(peer, rport).await {
            Some(Err(reason)) => {
                forward_probe_verdict(peer, rport, ForwardProbe::Refused(reason))?
            }
            Some(Ok(())) | None => ForwardTarget::Open,
        };
        match crate::ctl::try_ping(peer).await {
            Some(facts) => {
                let route = facts["route"].as_str().unwrap_or("link");
                crate::ui::say(&format!(
                    "tunlion: {} - 127.0.0.1:{lport} -> {peer}:{rport} over the daemon's live {route} link (no extra presence on {peer})",
                    forward_ready_word(rport, target)
                ));
            }
            None => {
                crate::ui::say(&format!(
                    "tunlion: listening on 127.0.0.1:{lport} -> {peer}:{rport} via the local daemon; no live link to {peer} yet - it opens on the first connection (check with `tunlion reach {peer}`)"
                ));
            }
        }
        None
    } else {
        crate::ui::status(&format!("tunlion: bringing up the link to {peer} ..."));
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
        {
            let (server, peer_s) = (server.to_string(), peer.to_string());
            tokio::spawn(async move { manage_cold_link(server, peer_s, relay, tx).await });
        }
        // Wait for the first link so "ready" is honest, but BOUNDED: the
        // listener is already bound, so while this waited the kernel completed
        // every client's handshake and nothing ever served or closed them.
        let first_link = tokio::time::timeout(cold_link_bound(), async {
            while rx.borrow().is_none() {
                if rx.changed().await.is_err() {
                    return false;
                }
            }
            true
        })
        .await;
        match first_link {
            Ok(true) => {
                // ...and ask the peer once, so "ready" also means "it will forward".
                let first = rx.borrow().clone();
                let target = match first {
                    Some(m) => forward_probe_verdict(peer, rport, probe_forward(&m, rport).await)?,
                    None => ForwardTarget::Open,
                };
                crate::ui::say(&format!(
                    "tunlion: {}, listening on 127.0.0.1:{lport} -> {peer}:{rport} (connect to it to forward; run `tunlion up` here to avoid a separate presence on {peer})",
                    forward_ready_word(rport, target)
                ));
            }
            Ok(false) => bail!(
                "tunlion: could not establish the link to {peer}; is it online? check with `tunlion reach {peer}` (or `tunlion devices`)"
            ),
            Err(_) => {
                // Not reachable yet. Keep listening (it may come up), but close
                // each connection at once until it does, and say so.
                activity.unreachable.store(true, std::sync::atomic::Ordering::Relaxed);
                crate::ui::critical(&format!(
                    "tunlion: cannot reach {peer} yet (no link within {}s); listening on 127.0.0.1:{lport} -> {peer}:{rport} anyway, closing connections at once until {peer} is back",
                    cold_link_bound().as_secs()
                ));
            }
        }
        Some(rx)
    };

    loop {
        // A transient accept error (e.g. EMFILE/ENFILE under fd pressure) must NOT
        // tear down the listener; back off briefly and keep serving.
        let accepted = tokio::select! {
            r = listener.accept() => r,
            // A connection task saw a POLICY refusal (revoked, not granted,
            // tunnels off). The forward can never work again without the owner,
            // so stop listening and exit with the denied code instead of
            // resetting every later client. Transport errors never reach here.
            Some(reason) = denied_rx.recv() => {
                crate::ui::critical(&forward_denied_line(peer, rport, &reason));
                std::process::exit(FORWARD_DENIED_EXIT);
            }
        };
        let sock = match accepted {
            Ok((s, _)) => s,
            Err(e) => {
                crate::ui::status(&format!("tunlion: accept paused ({e}), retrying..."));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        // The whole connection, warm attempt included, gets one bound from here.
        let deadline = tokio::time::Instant::now() + cold_link_bound();
        // Warm path: bridge this connection straight to the daemon's link. Retried
        // per connection so it is used whenever the daemon holds a warm link.
        #[cfg(unix)]
        if warm {
            match tokio::time::timeout_at(deadline, crate::ctl::try_open_reason(peer, rport))
                .await
                .unwrap_or(Err(None))
            {
                Ok(usock) => {
                    activity.reachable();
                    let guard = activity.begin();
                    tokio::spawn(async move {
                        let _guard = guard; // decrements + refreshes the activity line on close
                        let _ = bridge_streams(sock, usock).await;
                    });
                    continue;
                }
                // The PEER said no: say so on this terminal, for this connection,
                // and drop it. A cold retry would only be refused again.
                Err(Some(reason)) if reason.starts_with("refused:") => {
                    activity.reachable();
                    activity.refused_once(reason.trim_start_matches("refused:").trim());
                    drop(sock);
                    continue;
                }
                Err(_) => {}
            }
            // Warm miss (the daemon has no live link to the peer right now): fall
            // through to a cold link instead of dropping the connection. The cold
            // manager is started once, lazily, and self-heals from there.
        }
        // Cold path (also the warm-miss fallback): ensure the managed cold link
        // exists, then serve over the current live link.
        if cold_rx.is_none() {
            crate::ui::debug(&format!(
                "tunlion: no warm link to {peer}, using a direct link for forwarding"
            ));
            let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
            let (server, peer_s) = (server.to_string(), peer.to_string());
            tokio::spawn(async move { manage_cold_link(server, peer_s, relay, tx).await });
            cold_rx = Some(rx);
        }
        let rx = cold_rx.clone().unwrap();
        // The peer is known unreachable and no link has come back since: close
        // this connection now instead of making the client wait out the bound
        // again. The outage was announced once on stderr when it began.
        if activity.is_unreachable() && !cold_link_live(&rx) {
            crate::ui::status(&format!(
                "tunlion: {peer} unreachable; closed a connection at once"
            ));
            drop(sock);
            continue;
        }
        let guard = activity.begin();
        // #232/#268: a handle sharing the same counters, so the spawned task can
        // report a refusal against this forward's once-only flag.
        let act = activity.handle();
        // Serve this connection, retrying across a reconnect: a link that died in
        // the poll window is skipped (is_alive) and open failures re-wait for the
        // manager's fresh link, all inside `deadline`. On give-up the socket is
        // dropped (closed), but the ACCEPT LOOP ALWAYS SURVIVES -- one connection
        // is never allowed to kill the whole forward (the beta.28/29 regression
        // class).
        tokio::spawn(async move {
            let _guard = guard; // decrements + refreshes the activity line on close
            serve_cold_connection(rx, sock, rport, act, deadline).await;
        });
    }
}

#[cfg(test)]
mod forward_exposed_note_tests {
    use super::forward_exposed_note;

    /// G: a forward refused for want of shell names the route for an exposed
    /// port; a refusal that has nothing to do with shell does not.
    #[test]
    fn a_shell_refusal_points_to_the_mesh_route_for_exposed_ports() {
        for reason in [
            crate::capability::CEILING_REASON,
            crate::capability::TUNNEL_OFF_REASON,
            crate::capability::SHELL_OFF_REASON,
            "shell not granted to 'b' here",
        ] {
            let n = forward_exposed_note("Alpha", 7777, reason).unwrap_or_else(|| panic!("{reason}"));
            assert!(n.contains("alpha.mesh:7777") && n.contains("expose 7777") && n.contains("SOCKS5"), "{n}");
        }
        assert!(forward_exposed_note("alpha", 7777, "connection refused").is_none());
    }
}

#[cfg(test)]
mod candidate_timer_tests {
    use super::*;

    /// The timer rotates a candidate that never said a word (a ghost).
    #[tokio::test]
    async fn a_silent_candidate_is_rotated() {
        let (tx, _rx) = mpsc::unbounded_channel::<Ev>();
        let mut b = CandidateBound::new(Duration::from_secs(net::WATCHDOG_SECS));
        assert!(b.on_stuck(false, false, &tx, "sid-ghost", 1));
    }

    /// B1: a kept candidate is re-bounded. Keeping it arms exactly one Stuck
    /// for the same pid and generation at the hard bound, and that Stuck
    /// rotates it even though its peer connection is CONNECTED (progressing),
    /// which the C3 watchdog would never report.
    #[tokio::test]
    async fn a_kept_candidate_is_rotated_at_its_bound_even_when_connected() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
        let mut b = CandidateBound::new(Duration::from_millis(150));
        assert!(!b.on_stuck(true, true, &tx, "sid-real", 7), "answering candidate kept");
        assert!(!b.on_stuck(true, true, &tx, "sid-real", 7), "kept again before the bound");
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the hard bound never fired")
            .expect("channel open");
        match ev {
            Ev::Stuck(pid, g) => assert_eq!((pid.as_str(), g), ("sid-real", 7)),
            _ => panic!("the bound sent something other than Stuck"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx.recv()).await.is_err(),
            "the bound was armed more than once"
        );
        assert!(b.on_stuck(true, true, &tx, "sid-real", 7), "a connected candidate outlived its bound");
    }

    /// A rebuilt peer connection (glare, or the next candidate) gets a fresh
    /// bound and may arm it again.
    #[tokio::test]
    async fn restart_gives_a_fresh_bound() {
        let (tx, _rx) = mpsc::unbounded_channel::<Ev>();
        let mut b = CandidateBound::new(Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(b.on_stuck(true, true, &tx, "sid-real", 1), "past the bound");
        b.restart();
        assert!(!b.on_stuck(true, false, &tx, "sid-real", 2), "fresh bound keeps it");
        assert!(b.rearmed);
    }
}

#[cfg(test)]
mod forward_refusal_tests {
    use super::*;
    use super::proxy::ProxyProto;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn policy_refusals_are_classified_as_policy() {
        for reason in [
            crate::capability::REVOKED_REASON,
            crate::capability::TUNNEL_OFF_REASON,
            crate::capability::SHELL_OFF_REASON,
            crate::capability::CEILING_REASON,
            "not authorized: device lacks shell grant",
            "shell not granted to 'bravo' here",
            "shell revoked for 'bravo' here",
            "device revoked",
            "denied",
        ] {
            assert_eq!(
                classify_forward_refusal(reason),
                ForwardRefusal::Policy,
                "{reason:?} must end the forward"
            );
        }
    }

    #[test]
    fn a_closed_target_port_is_not_policy() {
        for reason in [
            "Connection refused (os error 111)",
            "No connection could be made because the target machine actively refused it. (os error 10061)",
        ] {
            assert_eq!(
                classify_forward_refusal(reason),
                ForwardRefusal::NothingListening,
                "{reason:?}"
            );
        }
    }

    #[test]
    fn transport_and_capacity_failures_keep_retrying() {
        for reason in [
            "too many streams",
            "sid in use",
            "stream input flooded (consumer stalled)",
            "Connection reset by peer (os error 104)",
            "timed out",
        ] {
            assert_eq!(
                classify_forward_refusal(reason),
                ForwardRefusal::Transient,
                "{reason:?} must not stop the forward"
            );
        }
    }

    #[test]
    fn ready_line_says_when_nothing_listens() {
        assert_eq!(forward_ready_word(8000, ForwardTarget::Open), "ready");
        assert_eq!(
            forward_ready_word(8000, ForwardTarget::NothingListening),
            "ready (nothing is listening on 8000 there yet)"
        );
    }

    #[test]
    fn a_nothing_listening_probe_reports_that_state() {
        let t = forward_probe_verdict(
            "bravo",
            39998,
            ForwardProbe::Refused("Connection refused (os error 111)".into()),
        )
        .expect("a closed port must not end the forward");
        assert_eq!(t, ForwardTarget::NothingListening);
        assert_eq!(
            forward_probe_verdict("bravo", 39998, ForwardProbe::Accepted).unwrap(),
            ForwardTarget::Open
        );
    }

    #[test]
    fn a_policy_probe_ends_the_forward_with_the_reason() {
        let e = forward_probe_verdict(
            "bravo",
            8000,
            ForwardProbe::Refused(crate::capability::TUNNEL_OFF_REASON.into()),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("refused the connection"), "{e}");
        assert!(e.contains("tunnelling is off"), "{e}");
    }

    /// The proxy answers a `.mesh` CONNECT with the RFC 1928 code that names
    /// what the peer said. It used to answer 0x00 before asking, then hang.
    #[test]
    fn mesh_verdict_maps_the_peers_answer_to_a_socks_reply() {
        let off = crate::capability::TUNNEL_OFF_REASON;
        // Policy refusal (tunnels off, no grant): not allowed by ruleset,
        // whatever the overlay dial said.
        for l3 in [None, Some(OVERLAY_DIAL_TIMED_OUT), Some("overlay dial failed: Connection refused")] {
            assert_eq!(mesh_verdict(Some(off), l3), Some(MeshFail::NotAllowed), "{l3:?}");
        }
        assert_eq!(mesh_verdict(Some("denied"), None), Some(MeshFail::NotAllowed));
        // Nothing listening on the peer's port.
        assert_eq!(
            mesh_verdict(Some("Connection refused (os error 111)"), Some(OVERLAY_DIAL_TIMED_OUT)),
            Some(MeshFail::Refused)
        );
        // A transient refusal defers to the overlay dial's answer.
        assert_eq!(mesh_verdict(Some("stream cap"), Some(OVERLAY_DIAL_TIMED_OUT)), Some(MeshFail::TimedOut));
        assert_eq!(mesh_verdict(Some("stream cap"), Some("overlay dial failed: connection reset")), Some(MeshFail::Refused));
        assert_eq!(mesh_verdict(Some("stream cap"), None), Some(MeshFail::General));
        // B: an EXPOSED port that took the connection and closed it at once
        // (nothing listening behind it) is "connection refused", even when
        // the loopback open was refused by policy (no shell) or never asked.
        for l2 in [Some(off), Some("stream cap"), None] {
            assert_eq!(mesh_verdict(l2, Some(OVERLAY_TARGET_CLOSED)), Some(MeshFail::Refused), "{l2:?}");
        }
        assert_eq!(MeshFail::Refused.socks_rep(), 0x05);
        // The settle wait is bounded both ways.
        assert_eq!(overlay_settle_window(Duration::ZERO), Duration::from_millis(250));
        assert_eq!(overlay_settle_window(Duration::from_millis(100)), Duration::from_millis(350));
        assert_eq!(overlay_settle_window(Duration::from_secs(5)), Duration::from_millis(1500));
        // No warm link to ask through: nothing definitive, try a cold link.
        assert_eq!(mesh_verdict(None, Some(OVERLAY_DIAL_TIMED_OUT)), None);
        assert_eq!(mesh_verdict(None, None), None);
    }

    #[test]
    fn mesh_fail_codes_are_rfc1928() {
        assert_eq!(MeshFail::General.socks_rep(), 0x01);
        assert_eq!(MeshFail::NotAllowed.socks_rep(), 0x02);
        assert_eq!(MeshFail::Unreachable.socks_rep(), 0x04);
        assert_eq!(MeshFail::Refused.socks_rep(), 0x05);
        assert_eq!(MeshFail::TimedOut.socks_rep(), 0x06);
        assert!(MeshFail::NotAllowed.http_status().starts_with("403"));
        assert!(MeshFail::TimedOut.http_status().starts_with("504"));
    }

    /// A proxy client gets its answer on the wire: the success reply is never
    /// written before the outcome is known, and a failure is a full SOCKS reply.
    #[tokio::test]
    async fn proxy_failure_reply_is_a_complete_socks_reply() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 10];
            c.read_exact(&mut buf).await.unwrap();
            buf
        });
        let (mut s, _) = l.accept().await.unwrap();
        ProxyProto::Socks.fail(&mut s, MeshFail::NotAllowed).await.unwrap();
        let got = client.await.unwrap();
        assert_eq!(got, [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn unreachable_line_names_the_peer_and_the_bound() {
        let l = forward_unreachable_line("alpha", 10);
        assert!(l.contains("cannot reach alpha"), "{l}");
        assert!(l.contains("10s"), "{l}");
        assert!(l.contains("closed"), "{l}");
    }

    #[test]
    fn denied_line_names_the_reason_and_the_exit_code() {
        assert_eq!(FORWARD_DENIED_EXIT, 4);
        let l = forward_denied_line("bravo", 8000, "access revoked");
        assert!(l.contains("access revoked"), "{l}");
        assert!(l.contains("exit 4"), "{l}");
        assert!(l.contains("bravo:8000"), "{l}");
    }

    #[test]
    fn only_a_policy_refusal_signals_the_accept_loop() {
        let (act, mut rx) = ForwardActivity::new("bravo", 8000);
        act.refused_once("Connection refused (os error 111)");
        act.refused_once("too many streams");
        assert!(
            rx.try_recv().is_err(),
            "a non-policy refusal must not stop the forward"
        );
        act.handle().refused_once(crate::capability::REVOKED_REASON);
        assert_eq!(rx.try_recv().unwrap(), crate::capability::REVOKED_REASON);
    }
}

#[cfg(test)]
mod h1_tests;
