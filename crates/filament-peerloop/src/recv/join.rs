//! The JOINER's enrollment driver, shared by the CLI and Core.
//!
//! This is the loop that used to live in `cli/src/enrollment.rs::enroll_cmd`,
//! moved here so a blank device joins through the same ceremony whether a
//! person ran `tunlion join` or an app called `Core::join_invitation`.
//!
//! The joiner owns its signaling connection. It mints no owner identity: the
//! preflight refuses a config directory that already holds an owner key or a
//! local certificate, and the acknowledgement persistence re-checks that under
//! `identity.lock` before it writes a local certificate last.
//!
//! One establishment is bounded by [`ESTABLISH_BUDGET`] because it runs on the
//! event loop; the whole join is bounded by the caller's timeout. Cancellation
//! is a [`Cancellation`] latch, not a process signal, so a library caller can
//! stop a join without installing a signal handler.

use anyhow::Result;
use filament_cap::ephemeral::{
    enrollment_possession_msg, enroll_channel_fp, EnrollmentPayload, EnrollmentPrincipal,
    Invitation,
};
use filament_id::{now_secs, DeviceCert};
use filament_transport::net::Ev;
use filament_transport::TransportContext;
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use crate::conn::Conn;
use crate::driver::{Cancellation, DriverOutcome};
use crate::host::{HostServices, LogSink};
use crate::recv::store::{DeviceStore, OverlayKey};
use crate::session::Session;

/// How long one `establish_as` may hold the join event loop.
pub const ESTABLISH_BUDGET: Duration = Duration::from_secs(45);
/// The default whole-join budget, matching the CLI's long-op window.
pub const JOIN_BUDGET: Duration = Duration::from_secs(60);

/// Everything the joiner needs that is not a host dependency.
#[derive(Clone)]
pub struct JoinRequest {
    pub server: String,
    pub invitation: Invitation,
    /// The name this device asks to be filed under.
    pub proposed_name: String,
    /// Restrict adoption to one peer name, for `join --to`.
    pub peer_name: Option<String>,
    pub relay: bool,
    /// An ephemeral lease request. Only ever narrows the invitation.
    pub lease: Option<u64>,
    pub timeout: Duration,
    /// Suppress human-facing status lines (a JSON or library caller).
    pub quiet: bool,
}

impl JoinRequest {
    pub fn new(server: impl Into<String>, invitation: Invitation, proposed_name: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            invitation,
            proposed_name: proposed_name.into(),
            peer_name: None,
            relay: false,
            lease: None,
            timeout: JOIN_BUDGET,
            quiet: false,
        }
    }
}

/// The facts a completed join produced. The local certificate is on disk; this
/// is what the caller may display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinOutcome {
    pub name: String,
    pub owner_name: String,
    pub device_pub: [u8; 32],
    pub ceiling: Vec<String>,
    pub expires: u64,
    pub ephemeral: bool,
}

/// A typed join failure. No variant carries the invitation seed or owner words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinFailure {
    Cancelled,
    /// The input or local state cannot be acted on before any network work.
    Usage(String),
    /// No owner answered within the caller's bound.
    Timeout(String),
    /// The owner refused the claim, naming a reason.
    Denied(String),
    /// Signaling ended or could not be established.
    Signaling(String),
    /// The acknowledgement failed a bound check or could not be stored.
    Storage(String),
}

impl std::fmt::Display for JoinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::Usage(text)
            | Self::Timeout(text)
            | Self::Denied(text)
            | Self::Signaling(text)
            | Self::Storage(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for JoinFailure {}

struct PendingJoin {
    seed: [u8; 32],
    device_pub: [u8; 32],
    invitation: Invitation,
}

impl Drop for PendingJoin {
    fn drop(&mut self) {
        // Best-effort zeroing of the possession seed after the claim.
        for byte in &mut self.seed {
            *byte = 0;
        }
    }
}

/// The joiner's pending claim state, owned by one driver instance rather than
/// a process global.
#[derive(Default)]
struct JoinState {
    pending: Mutex<HashMap<String, PendingJoin>>,
}

impl JoinState {
    fn register(&self, pid: &str, seed: [u8; 32], device_pub: [u8; 32], invitation: Invitation) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(
                pid.to_string(),
                PendingJoin {
                    seed,
                    device_pub,
                    invitation,
                },
            );
        }
    }

    /// Answer the owner's challenge only when the certificate proves the same
    /// owner the invitation names. Removal happens only on success, so a failed
    /// attempt does not burn a single-use key.
    fn respond(
        &self,
        pid: &str,
        nonce: [u8; 32],
        verifier_pub: [u8; 32],
        device_cert: &Value,
        overlay: &OverlayKey,
    ) -> Option<Value> {
        let cert = DeviceCert::from_json(device_cert)?;
        if cert.verify(now_secs()).is_err() || cert.device_pub != verifier_pub {
            return None;
        }
        let mut pending = self.pending.lock().ok()?;
        let claim = pending.get(pid)?;
        if filament_cap::ephemeral::issuer_fingerprint(&cert.user_pub) != claim.invitation.issuer_fp {
            return None;
        }
        let claim = pending.remove(pid)?;
        let enroll_kp = Ed25519KeyPair::from_seed_unchecked(&claim.seed).ok()?;
        let message = enrollment_possession_msg(&nonce, &claim.device_pub, &verifier_pub);
        let enroll_signature = enroll_kp.sign(&message);
        let mut enroll_possession_sig = [0u8; 64];
        enroll_possession_sig.copy_from_slice(enroll_signature.as_ref());
        let device_possession_sig = overlay.sign(&message).ok()?;
        let payload = EnrollmentPayload {
            principal: EnrollmentPrincipal::Compact(claim.invitation.clone()),
            device_pub: claim.device_pub,
            enroll_possession_sig,
            device_possession_sig,
        };
        Some(payload.to_json())
    }
}

fn uid() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("join-{}-{:x}", std::process::id(), nanos)
}

fn localized_denial(reason: &str) -> String {
    match reason {
        "already used" => "this invitation has already been used".to_string(),
        "use limit reached" => "this invitation has reached its use limit".to_string(),
        crate::recv::store::WITHDRAWN_WIRE_REASON => {
            "the owner withdrew this invitation, so it can no longer be used; ask them for a new one"
                .to_string()
        }
        other => format!("enrollment denied: {other}"),
    }
}

async fn run(
    request: &JoinRequest,
    store: &DeviceStore,
    overlay: &OverlayKey,
    transport_context: TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
) -> Result<JoinOutcome, JoinFailure> {
    let invitation = &request.invitation;
    if UserKeyPresent::check(store) {
        return Err(JoinFailure::Usage(
            "this device already holds an identity key; join only from a clean Tunlion identity"
                .to_string(),
        ));
    }
    if store.local_device_cert_path().exists() {
        return Err(JoinFailure::Usage(
            "this device already holds a joined certificate; refusing to overwrite it".to_string(),
        ));
    }
    if now_secs() >= invitation.expires {
        return Err(JoinFailure::Usage("this invitation has expired".to_string()));
    }
    let device_pub = overlay
        .public_key_bytes()
        .map_err(|e| JoinFailure::Storage(format!("local device key: {e}")))?;
    let seed = invitation.enroll_private_key;
    let enroll_chan = enroll_channel_fp(&invitation.issuer_fp);
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    // Match the CLI command loop exactly: the pre-existing compatibility
    // adapter detaches the signaling forwarder into this call's event channel.
    // The join is one-shot and owns its socket through the client; there is no
    // long-lived engine here that needs a separate joinable signaling task.
    let sio = filament_transport::net::connect_signaling(
        &transport_context,
        &request.server,
        tx.clone(),
    )
    .await
    .map_err(|e| JoinFailure::Signaling(format!("signaling: {e}")))?;

    let mut sess = Session::new(&request.proposed_name, &uid());
    sess.room = Some(format!("enrollup-{}", crate::secret::fresh_secret()));
    sess.channels = vec![enroll_chan.clone()];
    sess.emit(
        &sio,
        "join",
        json!({
            "room": sess.room.as_ref().expect("room set above"),
            "name": request.proposed_name,
            "uid": sess.uid,
        }),
    )
    .await;
    sess.emit(&sio, "subscribe", json!({ "channels": [enroll_chan] }))
        .await;

    let mut conn = Conn::for_command(
        transport_context,
        &request.server,
        sio.clone(),
        tx.clone(),
        sess.uid.clone(),
        request.relay,
        request.peer_name.clone(),
        false,
        filament_transport::direct::direct_enabled(),
        log.clone(),
        host.clone(),
    );
    let self_host = host;
    let state = JoinState::default();
    let started = Instant::now();

    loop {
        conn.pump_builds();
        let elapsed = started.elapsed();
        if elapsed >= request.timeout {
            return Err(JoinFailure::Timeout(format!(
                "enrollment timed out after {}s (no response from peer)",
                request.timeout.as_secs()
            )));
        }
        let slice = Duration::from_secs(2).min(request.timeout.saturating_sub(elapsed));
        let event = match tokio::time::timeout(slice, rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => {
                return Err(JoinFailure::Signaling(
                    "signaling channel closed".to_string(),
                ))
            }
            Err(_) => None,
        };
        sess.tick(&sio).await;
        let Some(event) = event else { continue };
        let event = match conn.stage_event(event) {
            Some((event, _)) => event,
            None => continue,
        };
        match event {
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                if let Some(peers) = v["peers"].as_array() {
                    for peer in peers {
                        conn.maybe_adopt(peer, false)
                            .await
                            .map_err(|e| JoinFailure::Signaling(e.to_string()))?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                conn.maybe_adopt(&v, false)
                    .await
                    .map_err(|e| JoinFailure::Signaling(e.to_string()))?;
            }
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    for peer in &roster.peers {
                        conn.maybe_adopt_from(peer, false, crate::adoption::AdoptSource::Digest)
                            .await
                            .map_err(|e| JoinFailure::Signaling(e.to_string()))?;
                    }
                    for peer in &roster.channel_peers {
                        if peer["channel"].as_str() == Some(enroll_chan.as_str())
                            && !self_host.is_self_uid(&conn.my_uid, peer["uid"].as_str())
                        {
                            conn.maybe_adopt_from(
                                peer,
                                false,
                                crate::adoption::AdoptSource::Digest,
                            )
                            .await
                            .map_err(|e| JoinFailure::Signaling(e.to_string()))?;
                        }
                    }
                }
            }
            Ev::KnownPeer(v) => {
                // The enroller drives: the owner daemon is present on the
                // enrollment channel and answers as the polite peer.
                if !self_host.is_self_uid(&conn.my_uid, v["uid"].as_str())
                    && v["channel"].as_str() == Some(enroll_chan.as_str())
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty()
                        && !conn.links.contains_key(&pid)
                        && !conn.direct_pending.contains_key(&pid)
                    {
                        conn.roster.insert(pid.clone(), v.clone());
                        // This is on the event loop. `establish_as` must not be
                        // allowed to hold the only handler for Signal,
                        // DirectReady, ChannelReady and Control indefinitely.
                        match tokio::time::timeout(
                            ESTABLISH_BUDGET,
                            conn.establish_as(v.clone(), Some(false)),
                        )
                        .await
                        {
                            Ok(result) => result
                                .map_err(|e| JoinFailure::Signaling(e.to_string()))?,
                            Err(_) => {
                                log.say(&format!(
                                    "tunlion: establish for '{pid}' exceeded {}s and was abandoned; the event loop was released (#350)",
                                    ESTABLISH_BUDGET.as_secs()
                                ));
                                continue;
                            }
                        }
                        if conn.active.is_none() {
                            conn.active = Some(pid);
                        }
                    }
                }
            }
            Ev::Signal(v) => {
                if conn.stage_signal(&v) {
                    continue;
                }
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                conn.ensure_responder(&from, &data)
                    .await
                    .map_err(|e| JoinFailure::Signaling(e.to_string()))?;
                if conn.build_pending(&from) {
                    conn.stage_signal(&v);
                    continue;
                }
                conn.apply_signal(&from, data).await;
            }
            Ev::DirectReady(pid, transport, route) => {
                if !matches!(
                    conn.adopt_direct(&pid, transport.clone(), route),
                    crate::conn::DirectAdoption::Adopted { .. }
                ) {
                    continue;
                }
                let _ = tx.send(Ev::sourced_channel_ready(pid, transport));
            }
            Ev::ChannelReady(pid, transport) => {
                conn.mark_ready(&pid, &transport, true);
                state.register(&pid, seed, device_pub, invitation.clone());
                use base64::Engine;
                let sent = transport
                    .send_control(&json!({
                        "type": "identity-auth-key-enroll-request",
                        "auth_key_v2": base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(invitation.to_payload()),
                        "device_pub": hex::encode(device_pub),
                    }))
                    .await;
                if sent.is_err() {
                    continue;
                }
                if !request.quiet {
                    let to = conn
                        .display_name_of(&pid)
                        .map(|name| format!("'{name}'"))
                        .unwrap_or_else(|| "the inviting device".to_string());
                    log.say(&format!(
                        "  {} sent enrollment request to {to}",
                        log.paint(crate::host::Tone::Dim, "->"),
                    ));
                }
            }
            Ev::Control(pid, v) => match v["type"].as_str() {
                Some("identity-auth-key-enroll-challenge") => {
                    let Some(transport) = conn.transport_of(&pid) else {
                        continue;
                    };
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    let verifier_hex = v["verifier_pub"].as_str().unwrap_or_default();
                    let Ok(nonce_bytes) = hex::decode(nonce_hex) else {
                        continue;
                    };
                    let Ok(verifier_bytes) = hex::decode(verifier_hex) else {
                        continue;
                    };
                    let (Ok(nonce), Ok(verifier_pub)) = (
                        nonce_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                        verifier_bytes.as_slice().try_into().map(|a: &[u8; 32]| *a),
                    ) else {
                        continue;
                    };
                    let device_cert = v
                        .get("device_cert")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    if let Some(response) =
                        state.respond(&pid, nonce, verifier_pub, &device_cert, overlay)
                    {
                        let mut message =
                            json!({ "type": "identity-auth-key-enroll-response" });
                        if let Some(object) = response.as_object() {
                            for (key, value) in object {
                                message[key] = value.clone();
                            }
                        }
                        if let Some(lease) = request.lease {
                            message["lease"] = json!(lease);
                        }
                        let _ = transport.send_control(&message).await;
                    }
                }
                Some("identity-auth-key-enroll-ack") => {
                    let name = crate::recv::enrollment::persist_join_ack(
                        store,
                        &device_pub,
                        invitation,
                        &v,
                    )
                    .map_err(|e| JoinFailure::Storage(format!("{e:#}")))?;
                    return Ok(JoinOutcome {
                        name,
                        owner_name: invitation.owner_name.clone(),
                        device_pub,
                        ceiling: invitation.scoped_caps(),
                        expires: v["expires"].as_u64().unwrap_or(invitation.expires),
                        ephemeral: invitation.ephemeral,
                    });
                }
                Some("identity-auth-key-enroll-error") => {
                    let reason = v["reason"].as_str().unwrap_or("unknown");
                    return Err(JoinFailure::Denied(localized_denial(reason)));
                }
                _ => {}
            },
            Ev::SignalingDown(reason, _) => {
                return Err(JoinFailure::Signaling(format!(
                    "signaling connection lost: {reason}"
                )))
            }
            Ev::Interrupted => return Err(JoinFailure::Cancelled),
            _ => {}
        }
    }
}

/// A tiny named helper so the preflight reads as a fact, not a side effect.
struct UserKeyPresent;

impl UserKeyPresent {
    fn check(store: &DeviceStore) -> bool {
        filament_id::UserKey::load(&store.keystore())
            .ok()
            .flatten()
            .is_some()
    }
}

/// Join an owner's fleet.
///
/// The returned error is typed; cancellation between polls returns
/// [`JoinFailure::Cancelled`] and never a partial success. The local
/// certificate is written by [`crate::recv::enrollment::persist_join_ack`]
/// only after every signed bound is checked, and last among the writes.
pub async fn drive(
    request: JoinRequest,
    store: &DeviceStore,
    overlay: &OverlayKey,
    transport_context: TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
    cancel: &Cancellation,
) -> Result<JoinOutcome, JoinFailure> {
    match cancel
        .run(run(&request, store, overlay, transport_context, log, host))
        .await
    {
        DriverOutcome::Cancelled => Err(JoinFailure::Cancelled),
        DriverOutcome::Returned(result) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_reasons_are_the_existing_wire_reasons() {
        assert_eq!(
            localized_denial("already used"),
            "this invitation has already been used"
        );
        assert_eq!(
            localized_denial("use limit reached"),
            "this invitation has reached its use limit"
        );
        assert!(localized_denial(crate::recv::store::WITHDRAWN_WIRE_REASON)
            .contains("withdrew this invitation"));
        assert_eq!(
            localized_denial("something else"),
            "enrollment denied: something else"
        );
    }
}
