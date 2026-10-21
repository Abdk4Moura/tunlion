//! The one-shot sender engine used by the library surface.
//!
//! This is the send-side counterpart of `recv::dispatch`: it drives the real
//! `Conn`, `Session`, `Ceremony`, `filament-proto` control messages and the
//! shared [`crate::send::stream::stream_one`] byte loop. It deliberately keeps
//! the command surface (argument parsing, terminals, fleet brokering, daemon
//! warm links) out: those are CLI policy. What it does own is the one-shot code
//! and known-device transfer, its code registration, expiry and cancellation.
//!
//! Honest scope: this is a one-shot sender. It does not resume after a link
//! loss, does not use fleet rendezvous, and does not spawn a process. A failure
//! is a typed failure; a success means a receiver's whole-file `delivery-ack`
//! landed (or, only for a source with no digest, that every byte was written
//! and acknowledged at the transport).

use crate::conn::Conn;
use crate::driver::Cancellation;
use crate::host::{HostServices, LogSink};
use crate::present::Presentation;
use crate::recv::dispatch::proof_for;
use crate::recv::identity::IdentityService;
use crate::send::ceremony::{Ceremony, Inbound as PakeInbound, pair_v2_caps};
use crate::send::source::{as_source_read, head_hash, source_digest};
use crate::session::Session;
use anyhow::Result;
use filament_id::IntroScope;
use filament_pair::words;
use filament_proto as protocol;
use filament_transfer::Outgoing;
use filament_transport::direct;
use filament_transport::net::{self, Ev, Transport};
use filament_transport::TransportContext;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The code's own lifetime, matching the server's `pair-create` TTL.
const CODE_TTL: Duration = Duration::from_secs(600);
/// How long a code sender waits for a claim before it gives up.
const CLAIM_WINDOW: Duration = Duration::from_secs(600);
/// How long after the last byte a receiver may take to return its ack.
const ACK_WAIT: Duration = Duration::from_secs(15);
const ACK_REPROBE: Duration = Duration::from_secs(5);
const PAKE_GRACE: Duration = Duration::from_secs(60);
/// After a claim/established link, the transfer may legitimately outlive the
/// code's TTL. This is an idle/progress bound, not a code-expiry bound.
const POST_CLAIM_IDLE: Duration = Duration::from_secs(900);

/// How this send finds its one receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendMode {
    /// Mint a one-time code and wait for its claimer.
    Code { word: Option<String> },
    /// A known, paired device by petname.
    Device { name: String },
}

/// One one-shot send request. Paths are regular files; directories/stdin remain
/// CLI concerns in this slice.
#[derive(Clone, Debug)]
pub struct SendRequest {
    pub server: String,
    pub paths: Vec<PathBuf>,
    pub name: Option<String>,
    pub mode: SendMode,
    pub relay: bool,
    pub timeout: Option<u64>,
    pub display_name: String,
    pub uid: String,
}

/// The host seams this engine needs. The CLI and Core each supply their own
/// explicit implementation; there is no process-global lookup here.
/// Called exactly once, when the signaling server has allocated the code.
pub type CodeNotify = Box<dyn Fn(CodeInfo) + Send + 'static>;

pub struct SendPorts {
    pub host: Arc<dyn HostServices>,
    pub identity: Arc<IdentityService>,
    pub log: Arc<dyn LogSink>,
    pub present: Arc<dyn Presentation>,
    pub transport_context: TransportContext,
}

/// What a successful code allocation tells its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeInfo {
    pub code: String,
    pub expires_in_secs: u64,
}

/// One file's transfer fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentFile {
    pub name: String,
    pub stored_name: Option<String>,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub delivered: bool,
}

/// What the engine did. `code` is set only for [`SendMode::Code`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendSummary {
    pub code: Option<String>,
    pub expires_in_secs: Option<u64>,
    pub files: Vec<SentFile>,
    pub bytes: u64,
}

/// The failure classes a caller maps to its own exit vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendFailureKind {
    Usage,
    Unreachable,
    Denied,
    Partial,
    Interrupted,
    Refused,
    Engine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFailure {
    pub kind: SendFailureKind,
    pub message: String,
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for SendFailure {}

impl SendFailure {
    fn usage(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Usage, message: message.into() }
    }
    fn unreachable(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Unreachable, message: message.into() }
    }
    fn denied(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Denied, message: message.into() }
    }
    fn partial(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Partial, message: message.into() }
    }
    fn interrupted(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Interrupted, message: message.into() }
    }
    fn refused(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Refused, message: message.into() }
    }
    fn engine(message: impl Into<String>) -> Self {
        Self { kind: SendFailureKind::Engine, message: message.into() }
    }
}


/// The claim window (and the code's TTL) applies only until someone claims the
/// code. After that a slow or large transfer must not be aborted as expired.
fn claim_expired(
    code_used: bool,
    now: Instant,
    claim_deadline: Instant,
    code_deadline: Option<Instant>,
) -> bool {
    !code_used && (now >= claim_deadline || code_deadline.is_some_and(|d| now >= d))
}

fn internal(error: impl std::fmt::Display) -> SendFailure {
    SendFailure::engine(error.to_string())
}



fn build_outgoing(request: &SendRequest, log: &dyn LogSink) -> Result<Vec<Outgoing>, SendFailure> {
    if request.paths.is_empty() {
        return Err(SendFailure::usage("nothing to send; pass at least one regular file"));
    }
    let single = request.paths.len() == 1;
    let mut outgoing = Vec::with_capacity(request.paths.len());
    for (i, path) in request.paths.iter().enumerate() {
        let meta = std::fs::metadata(path).map_err(|e| {
            SendFailure::usage(format!(
                "cannot send '{}': {} (a local file problem; nothing was sent)",
                path.display(),
                e
            ))
        })?;
        if !meta.is_file() {
            return Err(SendFailure::usage(format!(
                "cannot send '{}': not a regular file (nothing was sent)",
                path.display()
            )));
        }
        let full = source_digest(&path.display().to_string(), &meta)
            .map_err(|failure| SendFailure::usage(failure.message))?;
        let name = request
            .name
            .clone()
            .filter(|_| single)
            .unwrap_or_else(|| {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string())
            });
        let sid = (i + 1) as u32;
        let out = Outgoing {
            id: format!("{}-{}", request.uid, sid),
            sid,
            name: name.clone(),
            size: meta.len(),
            head: head_hash(path),
            full: Some(full),
            path: path.clone(),
            temp: false,
            accepted_once: false,
            sent: false,
            acked: false,
            declined: false,
            done: false,
            stream_started: None,
            stream_bytes: 0,
        };
        log.say(&format!(
            "send: {} ({})",
            out.name,
            crate::present::human(out.size)
        ));
        outgoing.push(out);
    }
    Ok(outgoing)
}

fn adopt_wants_active(code_claimed: bool, use_code: bool, pake_done: bool) -> bool {
    code_claimed && (!use_code || pake_done)
}

fn code_partner(
    latched: Option<&str>,
    from: &str,
    is_msg: bool,
    addressed: Option<bool>,
    code_claimed: bool,
) -> Partner {
    match latched {
        Some(p) if p == from => Partner::Ours,
        Some(_) => Partner::NotOurs,
        None => {
            let ours = match addressed {
                Some(mine) => mine,
                None => code_claimed,
            };
            if ours && is_msg { Partner::Latch } else { Partner::NotOurs }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Partner {
    Ours,
    Latch,
    NotOurs,
}

async fn offer_unfinished(
    outgoing: &Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    t: &Arc<dyn Transport>,
) -> Result<(), SendFailure> {
    let offers = {
        let out = outgoing.lock().await;
        out.iter()
            .filter(|o| !o.done)
            .map(|o| {
                protocol::offer_msg(
                    &o.id,
                    o.sid,
                    &o.name,
                    o.size,
                    o.head.as_deref(),
                    o.full.as_deref(),
                    o.accepted_once,
                )
            })
            .collect::<Vec<_>>()
    };
    let count = offers.len();
    for offer in offers {
        t.send_control(&offer).await.map_err(internal)?;
    }
    Ok(())
}

/// Drive one one-shot send. The caller owns the cancellation latch and turns
/// [`Cancellation`] into its own interrupted result.
pub async fn drive(
    request: SendRequest,
    ports: SendPorts,
    mut code_notify: Option<CodeNotify>,
    cancel: &Cancellation,
) -> Result<SendSummary, SendFailure> {
    if cancel.is_cancelled() {
        return Err(SendFailure::interrupted("the send was cancelled"));
    }
    let outgoing = Arc::new(tokio::sync::Mutex::new(build_outgoing(
        &request,
        ports.log.as_ref(),
    )?));
    let use_code = matches!(request.mode, SendMode::Code { .. });
    let known_target: Option<(String, String)> = match &request.mode {
        SendMode::Device { name } => ports
            .host
            .devices_load()
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                SendFailure::usage(format!(
                    "send to '{name}': no known device by that name; pair it first"
                ))
            })
            .map(Some)?,
        SendMode::Code { .. } => None,
    };

    let room = net::fetch_auto_room(&ports.transport_context, &request.server)
        .await
        .map_err(|error| {
            SendFailure::unreachable(format!("the signaling server is unreachable: {error}"))
        })?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    let sio = net::connect_signaling(&ports.transport_context, &request.server, tx.clone())
        .await
        .map_err(|error| {
            SendFailure::unreachable(format!("the signaling server is unreachable: {error}"))
        })?;
    let mut sess = Session::new(&request.display_name, &request.uid);
    sess.room = Some(room.clone());
    sess.emit(
        &sio,
        "join",
        json!({ "room": room, "name": request.display_name, "uid": request.uid }),
    )
    .await;

    let mut conn = Conn::for_command(
        ports.transport_context.clone(),
        &request.server,
        sio.clone(),
        tx.clone(),
        request.uid.clone(),
        request.relay,
        None,
        false,
        direct::direct_enabled(),
        ports.log.clone(),
        ports.host.clone(),
    );

    let mut send_words = String::new();
    let mut send_nameplate = String::new();
    if let Some((name, secret)) = &known_target {
        conn.to_filter = None;
        sess.channels = vec![crate::recv::store::channel_of(secret)];
        sess.emit(
            &sio,
            "subscribe",
            json!({ "channels": [crate::recv::store::channel_of(secret)] }),
        )
        .await;
        ports.log.say(&format!(
            "  waiting for known device {}",
            ports.log.paint(crate::host::Tone::Bold, name)
        ));
    } else if let SendMode::Code { word } = &request.mode {
        send_words = match word {
            Some(w) => {
                let (words, _np) = filament_pair::split_chosen_code(&filament_pair::norm_code(w));
                if let Err(why) = words::validate_chosen_password(&words, &request.display_name) {
                    return Err(SendFailure::usage(format!("'{w}' is too weak: {why}")));
                }
                words
            }
            None => words::mint_words(),
        };
        send_nameplate = words::mint_nameplate();
        sio.emit(
            "pair-create",
            json!({ "nameplate": send_nameplate, "v": 2 }),
        )
        .await
        .ok();
    }

    let mut send_cer: Option<Ceremony> = use_code.then(|| {
        Ceremony::new(
            &send_words,
            &send_nameplate,
            pair_v2_caps(),
            IntroScope::Device.to_byte(),
        )
    });
    let mut pake_peer: Option<String> = None;
    let mut pake_done = !use_code;
    let mut pake_deadline: Option<Instant> = None;
    let mut pake_heard: HashSet<String> = HashSet::new();
    let mut code_used = !use_code && known_target.is_none();
    let mut code_info: Option<CodeInfo> = None;
    let mut code_deadline: Option<Instant> = None;
    let mut code_sent_to_caller = false;
    // The caller's timeout bounds the CLAIM (or the wait for a known device),
    // not the transfer that follows. Once a receiver claims/establishes, the
    // code's TTL and this claim bound stop applying.
    let claim_deadline = request
        .timeout
        .filter(|secs| *secs > 0)
        .map(|secs| Instant::now() + Duration::from_secs(secs))
        .unwrap_or_else(|| Instant::now() + CLAIM_WINDOW);
    let mut last_activity = Instant::now();
    let mut established = false;
    let mut sent_all_at: Option<Instant> = None;
    let mut ack_reprobed = false;
    let mut stored: HashMap<String, String> = HashMap::new();
    let mut stream_tasks: Vec<JoinHandle<()>> = Vec::new();
    let source_failed: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        if cancel.is_cancelled() {
            return Err(SendFailure::interrupted("the send was cancelled"));
        }
        let all_done = {
            let out = outgoing.lock().await;
            out.iter().all(|o| o.done)
        };
        if all_done {
            break;
        }
        if claim_expired(code_used, Instant::now(), claim_deadline, code_deadline) {
            return Err(SendFailure::unreachable(if use_code {
                "the transfer code expired before it was claimed; nothing was sent".to_string()
            } else {
                format!(
                    "'{}' did not appear on the server in time; nothing was sent",
                    known_target
                        .as_ref()
                        .map(|(n, _)| n.as_str())
                        .unwrap_or("the device")
                )
            }));
        }
        if code_used && !all_done && last_activity.elapsed() >= POST_CLAIM_IDLE {
            let out = outgoing.lock().await;
            let confirmed = out.iter().filter(|o| o.acked).count();
            let total = out.len();
            return Err(SendFailure::unreachable(format!(
                "the receiver stopped making progress for {}s after claiming; {confirmed}/{total} file(s) confirmed",
                POST_CLAIM_IDLE.as_secs()
            )));
        }
        // A direct attempt that timed out without an authenticated QUIC
        // connection falls back to the WebRTC establish. The CLI loop does this
        // every iteration; without it a failed direct promote would strand the
        // code receiver.
        for (pid, info, (name, secret)) in conn.expired_direct() {
            conn.establish_as(info, None).await.map_err(|error| {
                SendFailure::engine(format!("direct fallback establish failed for {pid}: {error}"))
            })?;
            if let Some(link) = conn.link_mut(&pid) {
                link.expected_secret = Some((name, secret));
            }
            if conn.to_filter.is_none() && conn.active.is_none() {
                conn.active = Some(pid);
            }
        }
        // Code ceremony progression: relay our element, then our confirmation.
        if let (Some(cer), Some(pid)) = (send_cer.as_mut(), pake_peer.clone()) {
            if let Some(data) = cer.take_msg_payload() {
                sio.emit("signal", json!({ "to": pid, "data": data }))
                    .await
                    .ok();
            }
            if cer.has_k() {
                if let Some(l) = conn.link(&pid) {
                    if let Some((my_fp, their_fp)) = match &l.peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        if let Some(data) = cer.take_confirm_payload(&my_fp, &their_fp) {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        if !pake_done {
            if let Some(deadline) = pake_deadline {
                if Instant::now() > deadline {
                    if pake_peer.is_some() {
                        return Err(SendFailure::refused(
                            "the receiver started the encrypted handshake but did not finish it; ask for a fresh code",
                        ));
                    }
                    if !pake_heard.is_empty() {
                        pake_deadline = None;
                    } else {
                        return Err(SendFailure::refused(
                            "the other device uses an older version and cannot receive securely over a code",
                        ));
                    }
                }
            }
        }
        // Wait for the whole-file ack before calling a full-digest file done.
        let (all_sent, all_acked) = {
            let out = outgoing.lock().await;
            (
                out.iter().all(|o| o.sent),
                out.iter().all(|o| o.acked || o.full.is_none()),
            )
        };
        if all_sent && !all_acked {
            if sent_all_at.is_none() {
                sent_all_at = Some(Instant::now());
            }
            let elapsed = sent_all_at.unwrap().elapsed();
            if elapsed >= ACK_WAIT && !ack_reprobed {
                ack_reprobed = true;
                sent_all_at = Some(Instant::now());
                if let Some(t) = conn.transport() {
                    let out = outgoing.lock().await;
                    for o in out.iter().filter(|o| !o.acked) {
                        let _ = t.send_control(&protocol::end_msg(&o.id, o.sid)).await;
                    }
                }
            } else if elapsed >= ACK_WAIT + ACK_REPROBE {
                let out = outgoing.lock().await;
                let confirmed = out.iter().filter(|o| o.acked).count();
                let unconfirmed = out.len().saturating_sub(confirmed);
                let message = format!(
                    "delivery not confirmed: {confirmed} file(s) confirmed, {unconfirmed} sent but never delivery-acked by the receiver"
                );
                return Err(if confirmed > 0 {
                    SendFailure::partial(message)
                } else {
                    SendFailure::unreachable(message)
                });
            }
        }
        let ev = tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                sess.tick(&sio).await;
                conn.reap_deferred();
                None
            }
            ev = crate::recv::events::next_ev(&mut rx, &conn, false) => {
                ev.map_err(internal)?
            }
        };
        let Some(ev) = ev else { continue };
        last_activity = Instant::now();
        match ev {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        conn.maybe_adopt(
                            p,
                            adopt_wants_active(code_used, use_code, pake_done),
                        )
                        .await
                        .map_err(internal)?;
                    }
                }
                sess.invalidate();
            }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for p in &roster.peers {
                        conn.maybe_adopt_from(
                            p,
                            adopt_wants_active(code_used, use_code, pake_done),
                            crate::AdoptSource::Digest,
                        )
                        .await
                        .map_err(internal)?;
                    }
                }
            }
            Ev::PairOk(v) => {
                let ttl = v["ttl"].as_u64().unwrap_or(CODE_TTL.as_secs());
                let expires = code_expiry_secs(ttl, claim_deadline);
                let code = format!("{send_words}-{send_nameplate}");
                ports.log.say("");
                ports.log.say(&format!(
                    "  code   {}",
                    ports.log.paint(crate::host::Tone::Brand, &code)
                ));
                ports.log.say("");
                code_deadline = Some(Instant::now() + Duration::from_secs(expires));
                code_info = Some(CodeInfo {
                    code: code.clone(),
                    expires_in_secs: expires,
                });
                if !code_sent_to_caller {
                    code_sent_to_caller = true;
                    if let Some(notify) = code_notify.take() {
                        notify(code_info.clone().expect("just set"));
                    }
                }
            }
            Ev::PairCode(_) => {
                return Err(SendFailure::refused(
                    "the server returned a legacy transfer code; update the server",
                ));
            }
            Ev::PairError(v) => {
                if use_code && v["error"].as_str() == Some("taken") {
                    send_nameplate = words::mint_nameplate();
                    if let Some(cer) = send_cer.as_mut() {
                        cer.restart(&send_words, &send_nameplate);
                    }
                    sio.emit(
                        "pair-create",
                        json!({ "nameplate": send_nameplate, "v": 2 }),
                    )
                    .await
                    .ok();
                    continue;
                }
                return Err(SendFailure::refused(format!(
                    "code allocation failed: {}",
                    v["error"].as_str().unwrap_or("unknown error")
                )));
            }
            Ev::PairUsed(_) => {
                code_used = true;
                // The code did its job. A late claimer or a slow/large transfer
                // must not be aborted by the code's TTL or the claim timeout.
                code_deadline = None;
                last_activity = Instant::now();
                ports.log.say("code claimed, connecting...");
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, adopt_wants_active(code_used, use_code, pake_done))
                    .await
                    .map_err(internal)?;
            }
            Ev::KnownPeer(v) => {
                if let Some((name, secret)) = &known_target {
                    if v["channel"].as_str() == Some(crate::recv::store::channel_of(secret).as_str()) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        conn.start_direct(&pid, name, secret).await;
                        conn.maybe_adopt(&v, true).await.map_err(internal)?;
                        if let Some(l) = conn.link_mut(&pid) {
                            l.expected_secret = Some((name.clone(), secret.clone()));
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                if data["type"].as_str() == Some("not-recognized") {
                    return Err(SendFailure::denied(format!(
                        "'{}' refused this send: it no longer recognizes this device",
                        known_target
                            .as_ref()
                            .map(|(n, _)| n.as_str())
                            .unwrap_or("the peer")
                    )));
                }
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let srflx = data["srflx"].as_str().map(String::from);
                    let public = data["server_public"].as_str().map(String::from);
                    let proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                    if !conn.direct_pending.contains_key(&from) {
                        if let Some((name, secret)) = known_target.as_ref() {
                            conn.start_direct(&from, name, secret).await;
                        }
                    }
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(&from, cands, srflx, public, proto);
                    } else {
                        conn.buffered_offers.insert(from.clone(), (cands, srflx, public, proto));
                    }
                    continue;
                }
                if matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm")) {
                    if let Some(cer) = send_cer.as_mut() {
                        pake_heard.insert(from.clone());
                        match code_partner(
                            pake_peer.as_deref(),
                            &from,
                            data["type"].as_str() == Some("pake-msg"),
                            crate::send::ceremony::addressed_to(&data, &send_nameplate),
                            code_used,
                        ) {
                            Partner::Ours => {}
                            Partner::Latch => {
                                pake_peer = Some(from.clone());
                                pake_deadline = Some(Instant::now() + PAKE_GRACE);
                                ports.log.say("  authenticating...");
                            }
                            Partner::NotOurs => continue,
                        }
                        let fps = match conn.link(&from).and_then(|l| l.peer.as_ref()) {
                            Some(peer) => peer.fingerprints().await,
                            None => None,
                        };
                        let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                if let Some(secret) = cer.secret().cloned() {
                                    if !pake_done {
                                        pake_done = true;
                                        code_deadline = None;
                                        last_activity = Instant::now();
                                        ports.log.say("  authenticated, sending");
                                        let promotion = if cer.peer_supports_direct() {
                                            conn.start_direct_promote(&from, &from, &secret).await
                                        } else {
                                            crate::conn::Promotion::Retained
                                        };
                                        // The promote may drop the serving WebRTC
                                        // link, and drop_link clears the active
                                        // slot. The authenticated peer is the
                                        // target, so claim it AFTER the promote.
                                        conn.active = Some(from.clone());
                                        conn.rearm_channel_ready(&from, promotion);
                                    }
                                }
                            }
                            PakeInbound::Abort(why) => {
                                return Err(SendFailure::refused(format!(
                                    "transfer REFUSED: {why}. Nothing was sent; ask for a fresh code"
                                )));
                            }
                            PakeInbound::Ignored => {}
                        }
                        continue;
                    }
                }
                conn.ensure_responder(&from, &data)
                    .await
                    .map_err(internal)?;
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, t, route) => {
                conn.adopt_direct(&pid, t.clone(), route);
                let _ = tx.send(Ev::ChannelReady(pid, t));
            }
            Ev::DirectWorkersReady(pid, workers) => {
                if let Some(link) = conn.link_mut(&pid) {
                    link.workers = workers;
                }
            }
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                conn.mark_ready(&pid, &t, false);
                if !conn.is_active(&pid) && !established && !use_code {
                    let proves = known_target.as_ref().is_some_and(|(_, sec)| {
                        conn.link(&pid)
                            .and_then(|l| l.expected_secret.as_ref())
                            .is_some_and(|(_, s)| s == sec)
                    });
                    if proves {
                        conn.active = Some(pid.clone());
                    }
                }
                if use_code && !pake_done && code_used && pake_deadline.is_none() {
                    pake_deadline = Some(Instant::now() + PAKE_GRACE);
                }
                if !conn.is_active(&pid) {
                    continue;
                }
                established = true;
                last_activity = Instant::now();
                let is_direct = conn.link(&pid).is_some_and(|l| l.direct);
                if let Some(l) = conn.link(&pid) {
                    if !is_direct {
                        if let Some(sec) = l.expected_secret.as_ref().map(|(_, s)| s.clone()) {
                            if let Some((my_fp, their_fp)) = match &l.peer {
                                Some(p) => p.fingerprints().await,
                                None => None,
                            } {
                                t.send_control(&json!({
                                    "type": "pair-proof",
                                    "mac": proof_for(sec.as_str(), &conn.my_uid, &conn.my_uid, l.uid.as_deref().unwrap_or(""), &my_fp, &their_fp),
                                }))
                                .await
                                .map_err(internal)?;
                            }
                        }
                    }
                }
                if use_code && !is_direct && !pake_done {
                    continue;
                }
                offer_unfinished(&outgoing, &t).await?;
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-nonce-challenge") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        ports.identity.respond_to_identity_challenge(&t, &v).await;
                    }
                }
                Some("file-accept") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        continue;
                    };
                    let workers = conn.link(&pid).map(|l| l.workers.clone()).unwrap_or_default();
                    let mut transports = vec![t];
                    if !crate::recv::transfer_truth::accept_is_sequential(&v) {
                        transports.extend(workers);
                    }
                    let offset = v["offset"].as_u64().unwrap_or(0);
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    {
                        let mut out = outgoing.lock().await;
                        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                            o.accepted_once = true;
                        }
                    }
                    let out = outgoing.clone();
                    let chunk = transports[0].max_payload();
                    let tx2 = tx.clone();
                    let active_sid = conn.active.clone();
                    let source_failed = source_failed.clone();
                    let log = ports.log.clone();
                    let present = ports.present.clone();
                    stream_tasks.push(tokio::spawn(async move {
                        match crate::send::stream::stream_one(
                            out,
                            transports,
                            id.clone(),
                            offset,
                            chunk,
                            active_sid,
                            tx2.clone(),
                            log,
                            present,
                        )
                        .await
                        {
                            Ok(()) => {
                                let _ = tx2.send(Ev::TransferDone(id));
                            }
                            Err(e) => {
                                if let Some(why) = as_source_read(&e) {
                                    if let Ok(mut m) = source_failed.lock() {
                                        m.insert(id.clone(), why);
                                    }
                                }
                                let _ = tx2.send(Ev::TransferFailed { id, err: e.to_string() });
                            }
                        }
                    }));
                }
                Some("file-decline") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    let why = v["error"].as_str().filter(|e| !e.trim().is_empty());
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        o.declined = true;
                        o.done = true;
                        if let Some(why) = why {
                            return Err(SendFailure::refused(format!(
                                "{} not delivered: {why}",
                                o.name
                            )));
                        }
                        return Err(SendFailure::denied(format!("declined: {}", o.name)));
                    }
                }
                Some("delivery-ack") => {
                    let id = v["id"].as_str().unwrap_or_default();
                    if let Some(name) = v["stored"].as_str() {
                        stored.insert(id.to_string(), name.to_string());
                    }
                    let mut out = outgoing.lock().await;
                    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
                        o.acked = true;
                        o.done = true;
                    }
                }
                Some("pair-proof-ack") => {
                    if v["ok"].as_bool() == Some(false) && !use_code {
                        return Err(SendFailure::denied(format!(
                            "'{}' refused this device's identity proof; pair the device again",
                            known_target
                                .as_ref()
                                .map(|(n, _)| n.as_str())
                                .unwrap_or("the receiver")
                        )));
                    }
                }
                Some("file-pending") => {}
                Some("link-revoked") => {
                    return Err(SendFailure::denied(
                        "the receiver revoked this device during the send",
                    ));
                }
                other => {
                }
            },
            Ev::TransferFailed { id, err } => {
                let local = source_failed.lock().ok().and_then(|mut m| m.remove(&id));
                if let Some(why) = local {
                    if let Some(t) = conn.transport() {
                        let _ = t
                            .send_control(&crate::send::source::cancel_msg(
                                &id,
                                0,
                                "",
                                "source unreadable",
                            ))
                            .await;
                    }
                    return Err(SendFailure::usage(why));
                }
                return Err(SendFailure::engine(format!("transfer {id} failed: {err}")));
            }
            Ev::Interrupted => {
                return Err(SendFailure::interrupted("the send was interrupted"));
            }
            Ev::PeerLeft(v) => {
                let pid = v["id"].as_str().unwrap_or_default();
                conn.drop_link(pid);
            }
            Ev::PcState(pid, state) => conn.on_pc_state(&pid, &state).await,
            _ => {}
        }
    }
    for task in stream_tasks {
        let _ = task.await;
    }
    let out = outgoing.lock().await;
    let files: Vec<SentFile> = out
        .iter()
        .map(|o| SentFile {
            name: o.name.clone(),
            stored_name: stored.get(&o.id).cloned(),
            bytes: o.size,
            sha256: o.full.clone(),
            delivered: o.acked || o.full.is_none(),
        })
        .collect();
    let bytes = files.iter().map(|f| f.bytes).sum();
    Ok(SendSummary {
        code: code_info.as_ref().map(|c| c.code.clone()),
        expires_in_secs: code_info.as_ref().map(|c| c.expires_in_secs),
        files,
        bytes,
    })
}

fn code_expiry_secs(ttl: u64, claim: Instant) -> u64 {
    ttl.min(claim.saturating_duration_since(Instant::now()).as_secs())
        .max(1)
}

fn no_peer_message(device: Option<&str>, use_code: bool) -> String {
    match (device, use_code) {
        (Some(name), _) => format!("'{name}' did not connect in time; nothing was sent"),
        (None, true) => "no receiver claimed the code in time; nothing was sent".to_string(),
        _ => "no receiver connected in time; nothing was sent".to_string(),
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claimed_code_is_not_expired_by_its_ttl_or_claim_bound() {
        let now = Instant::now();
        let claim = now.checked_sub(Duration::from_secs(1)).unwrap();
        let code = now.checked_sub(Duration::from_secs(1));
        assert!(
            !claim_expired(true, now, claim, code),
            "a claimed code must let the transfer outlive the code TTL"
        );
    }

    #[test]
    fn an_unclaimed_code_expires_at_the_claim_bound_or_ttl() {
        let now = Instant::now();
        let claim = now.checked_sub(Duration::from_secs(1)).unwrap();
        assert!(claim_expired(false, now, claim, None));
        let claim = now + Duration::from_secs(30);
        let code = now.checked_sub(Duration::from_secs(1));
        assert!(claim_expired(false, now, claim, code));
        assert!(!claim_expired(false, now, claim, None));
    }
}
