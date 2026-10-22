//! Auth-key enrollment: the owner-side request/response handlers.
//!
//! This is the real implementation behind the two `RecvIdentity` methods that
//! used to forward to `cli/src/renewal_lifecycle.rs`. The host facts are
//! explicit:
//!
//! * [`DeviceStore`] — devices/revocations/armed/used-invitations/cap store,
//!   all rooted at the caller's config directory;
//! * [`OverlayKey`] — the explicit-path verification key;
//! * [`EnrollmentState`] — an **owned** nonce/burn/rate-limit runtime, so two
//!   engines in one process never share a challenge or a use window;
//! * a [`LogSink`] — terminal output, chosen by the adapter.
//!
//! Trust decisions are unchanged. The signed invitation is still verified under
//! this device's owner key, the payload still binds the nonce and verifier, the
//! durable `used-invitations.json` count is still written before admission, and
//! the device record still carries the signed ceiling, expiry and offline
//! budget. The certificate/ceiling/grant paths are the library store's.

use crate::conn::Conn;
use crate::host::{LogSink, Tone};
use crate::recv::identity::local_device_cert;
use crate::recv::store::{
    sanitize_device_name, DeviceStore, InvitationRefusal, OverlayKey, PRINCIPAL_STATE_LAPSED,
    PRINCIPAL_STATE_REVOKED,
};
use anyhow::Result;
use base64::Engine;
use filament_cap::ephemeral::{
    EnrollmentPayload, EnrollmentPrincipal, EnrollmentState, Invitation,
};
use filament_id::{now_secs, DeviceCert, IntroScope, UserKey};
use serde_json::{json, Value};
use std::sync::Arc;

/// The owner-side enrollment handlers for one engine/config identity.
pub struct EnrollmentService {
    store: DeviceStore,
    overlay: OverlayKey,
    display_name: String,
    log: Arc<dyn LogSink>,
    runtime: EnrollmentState,
}

impl EnrollmentService {
    pub fn new(
        store: DeviceStore,
        overlay: OverlayKey,
        display_name: impl Into<String>,
        log: Arc<dyn LogSink>,
    ) -> Self {
        Self {
            store,
            overlay,
            display_name: display_name.into(),
            log,
            runtime: EnrollmentState::default(),
        }
    }

    /// The live enrollment state this instance owns. Exposed so a caller can
    /// observe/inspect it; production paths never share it.
    pub fn runtime(&self) -> &EnrollmentState {
        &self.runtime
    }

    fn local_device_cert(&self) -> Option<DeviceCert> {
        local_device_cert(&self.store, &self.overlay, &self.display_name)
    }

    async fn deny(&self, t: &Arc<dyn filament_transport::net::Transport>, reason: &str) {
        let _ = t
            .send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": reason}))
            .await;
    }

    /// OWNER SIDE: verify an invitation, then challenge the enroller's
    /// possession of the advertised enrollment key.
    pub async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value) {
        let Some(t) = conn.transport_of(&pid) else {
            crate::conn::dropped_no_transport(self.log.as_ref(), &pid, "enrolment request");
            return;
        };

        // Rate-limit FIRST — keyed on pid, counts every request including
        // unparseable ones, before any parse cycles.
        if let Err(e) = self.runtime.check_rate_limit_at(&pid, now_secs()) {
            self.log.debug(&format!("enroll request rate-limited: {e}"));
            self.deny(&t, "enrollment denied").await;
            return;
        }

        // ONE READER: the compact invitation payload only.
        let ak = {
            let Some(v2_b64) = v.get("auth_key_v2").and_then(|x| x.as_str()) else {
                self.deny(&t, "enrollment denied").await;
                return;
            };
            let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v2_b64) else {
                self.deny(&t, "enrollment denied").await;
                return;
            };
            match Invitation::from_payload(&bytes) {
                Some(inv) => EnrollmentPrincipal::Compact(inv),
                None => {
                    self.deny(&t, "enrollment denied").await;
                    return;
                }
            }
        };

        let Some(owner_key) = UserKey::load(&self.store.keystore()).ok().flatten() else {
            self.deny(&t, "enrollment denied").await;
            return;
        };
        let owner_pub = owner_key.public_key_bytes();
        let verifier_pub = match self.overlay.public_key_bytes() {
            Ok(pk) => pk,
            Err(e) => {
                self.log
                    .debug(&format!("enroll request overlay-key error: {e}"));
                self.deny(&t, "enrollment denied").await;
                return;
            }
        };
        let _ak = match &ak {
            EnrollmentPrincipal::Compact(inv) => {
                if !inv.verify_against_owner(&owner_pub) {
                    self.log
                        .debug("enroll request auth-key rejected (fingerprint or signature)");
                    self.deny(&t, "enrollment denied").await;
                    return;
                }
                if now_secs() >= inv.expires {
                    self.log.debug("enroll request auth-key expired");
                    self.deny(&t, "enrollment denied").await;
                    return;
                }
                inv.to_auth_key(&owner_pub)
            }
            EnrollmentPrincipal::Legacy(ak) => {
                if ak.verify_against_owner(&owner_pub, &verifier_pub).is_err() {
                    self.log.debug("enroll request legacy auth-key rejected");
                    self.deny(&t, "enrollment denied").await;
                    return;
                }
                ak.clone()
            }
        };

        let nonce = match self
            .runtime
            .generate_nonce_at(&pid, std::time::Instant::now())
        {
            Ok(n) => n,
            Err(e) => {
                self.log
                    .debug(&format!("enroll request nonce CSPRNG failure: {e}"));
                self.deny(&t, "enrollment denied").await;
                return;
            }
        };
        let cert_value = self.local_device_cert().map(|c| c.to_json());
        let _ = t
            .send_control(&json!({
                "type": "identity-auth-key-enroll-challenge",
                "nonce": hex::encode(nonce),
                "verifier_pub": hex::encode(verifier_pub),
                "device_cert": cert_value,
            }))
            .await;
    }

    /// OWNER SIDE: consume our nonce, verify the enroller's payload, burn the
    /// invitation (live and durable), then admit the delegated principal.
    pub async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value) {
        let Some(t) = conn.transport_of(&pid) else {
            crate::conn::dropped_no_transport(self.log.as_ref(), &pid, "enrolment response");
            return;
        };
        let Some(payload) = EnrollmentPayload::from_json(&v) else {
            self.deny(&t, "enrollment denied").await;
            return;
        };
        let Some(owner_key) = UserKey::load(&self.store.keystore()).ok().flatten() else {
            self.deny(&t, "enrollment denied").await;
            return;
        };
        let owner_pub = owner_key.public_key_bytes();
        let verifier_pub = match self.overlay.public_key_bytes() {
            Ok(pk) => pk,
            Err(e) => {
                self.log
                    .debug(&format!("enroll response overlay-key error: {e}"));
                self.deny(&t, "enrollment denied").await;
                return;
            }
        };

        // Structural nonce consumption: never trust a nonce echoed by the peer.
        let nonce = match self
            .runtime
            .consume_latest_nonce_at(&pid, std::time::Instant::now())
        {
            Ok(n) => n,
            Err(e) => {
                self.log
                    .debug(&format!("enroll response nonce consumption failed: {e}"));
                self.deny(&t, "enrollment denied").await;
                return;
            }
        };

        match payload.verify(&owner_pub, &nonce, &verifier_pub) {
            Ok((enroll_pub, device_pub, ak)) => {
                // A retry of an enrollment this owner ALREADY COMMITTED is a
                // receipt, before any use accounting. This matters for
                // `--reuse N`/`--reuse forever`: the live and durable counters
                // still have room, so the ordinary path below would consume a
                // SECOND use, mint a new certificate and rotate the secret just
                // because an acknowledgement was lost. Only a different device
                // key (or different signed bounds) reaches the ordinary path.
                if self
                    .reissue_enrolment_receipt(
                        conn, &pid, &owner_key, device_pub, enroll_pub, &ak,
                    )
                    .await
                {
                    return;
                }
                // Burn ON SUCCESS only (never-reset live counter).
                if let Err(e) = self
                    .runtime
                    .burn_auth_key_at(&enroll_pub, &ak.reuse, now_secs())
                {
                    self.log.debug(&format!("enroll response burn failed: {e}"));
                    // A RETRY OF AN ENROLLMENT THE OWNER ALREADY COMMITTED is
                    // not a refusal. The invitation was burned, the device
                    // record was written and the certificate was sent; the
                    // joining side may have lost the acknowledgement to a
                    // dropped link, or its local store write may have failed.
                    // Denying that retry told automation "this invitation has
                    // already been used" while the fleet already held the
                    // device, and left one machine with a key the other had
                    // certified. Answer with the SAME receipt instead, and
                    // never consume a second use.
                    if self
                        .reissue_enrolment_receipt(
                            conn, &pid, &owner_key, device_pub, enroll_pub, &ak,
                        )
                        .await
                    {
                        return;
                    }
                    let msg = e.to_string();
                    let reason = if msg.contains("already used") {
                        "already used"
                    } else if msg.contains("exhausted") {
                        "use limit reached"
                    } else if msg.contains("rate-limited") {
                        "rate-limited"
                    } else {
                        "enrollment denied"
                    };
                    self.deny(&t, reason).await;
                    return;
                }
                // Durable count, apart from every device record. A daemon
                // restart clears the live burn but not this file.
                if let Err(refusal) = self.store.record_invitation_use(
                    &hex::encode(enroll_pub),
                    &ak.reuse,
                    ak.expires,
                    now_secs(),
                ) {
                    self.log.debug(&format!(
                        "enroll response refused: invitation {:?} (durable use count)",
                        refusal
                    ));
                    // The live burn counter is empty after an OWNER RESTART, so
                    // a retry of an enrollment this owner already committed
                    // reaches this durable refusal instead of the live one.
                    // Answer with the same idempotent receipt; otherwise a
                    // restart turns an accepted join into "already used".
                    if matches!(
                        refusal,
                        InvitationRefusal::AlreadyUsed | InvitationRefusal::UseLimitReached
                    ) && self
                        .reissue_enrolment_receipt(
                            conn, &pid, &owner_key, device_pub, enroll_pub, &ak,
                        )
                        .await
                    {
                        return;
                    }
                    self.deny(&t, refusal.wire_reason()).await;
                    return;
                }

                let persistent = !ak.ephemeral;
                let mut requested_name = conn
                    .link(&pid)
                    .map(|link| link.name.clone())
                    .unwrap_or_else(|| "joined-device".to_string());
                if let Some(chosen) = self.store.invitee_name(&hex::encode(enroll_pub)) {
                    if chosen != requested_name {
                        self.log.say(&format!(
                            "  a device that calls itself '{requested_name}' joined with the invitation you made for '{chosen}'; it is listed as '{chosen}'"
                        ));
                    }
                    requested_name = chosen;
                }

                let prior = self.store.devices_find_by_device_pub(&device_pub);
                if self.store.device_key_revoked(&device_pub, now_secs()) {
                    self.log.debug(&format!(
                        "enroll response refused: device {pid} holds a revoked key"
                    ));
                    self.deny(&t, "this device key was revoked by the owner; run `tunlion reset` on this device for a new key, then join again").await;
                    return;
                }
                if let Some(prior_record) = &prior {
                    if let Some(reason) = enrollment_refusal(prior_record) {
                        self.log.debug(&format!(
                            "enroll response refused: device {pid} was revoked"
                        ));
                        self.deny(&t, &reason).await;
                        return;
                    }
                    if persistent
                        && prior_record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED)
                    {
                        if let Some(name) = prior_record["name"].as_str() {
                            requested_name = name.to_string();
                        }
                    }
                }

                let mut candidate = sanitize_device_name(&requested_name);
                let allow_reanchor =
                    prior.as_ref().and_then(|r| r["name"].as_str()) == Some(candidate.as_str());
                if !allow_reanchor {
                    let base = candidate.clone();
                    let key_hex = hex::encode(device_pub);
                    let mut n = 2u32;
                    while self.store.name_pinned_by_other(&candidate, &key_hex) && n < 1000 {
                        candidate = format!("{base}-{n}");
                        n += 1;
                    }
                    if candidate != base {
                        self.log.say(&format!(
                            "  {} a new device asked to be called {base}, a name another key holds, so it was stored as {candidate}. If {base} was reset and this is the same machine: `tunlion devices forget {base} -y` then `tunlion devices rename {candidate} {base}`.",
                            self.log.paint(Tone::Warn, self.log.glyph_warn())
                        ));
                    }
                }
                let requested_name = candidate;
                let secret = crate::secret::fresh_secret();
                let (device_cert, enrolment) = match self
                    .build_enrolment(&owner_key, device_pub, &ak.caps, ak.expires, persistent)
                {
                    Ok(pair) => pair,
                    Err(error) => {
                        self.log
                            .debug(&format!("enroll response certificate failed: {error}"));
                        self.deny(&t, "enrollment denied").await;
                        return;
                    }
                };

                let stored_name = if persistent {
                    match self.store.devices_upsert_atomic(
                        &requested_name,
                        Some(&secret),
                        Some(&device_cert),
                        Some(&ak.caps),
                        Some(IntroScope::Device.to_byte()),
                        None,
                        Some((&ak.caps, ak.expires, ak.max_offline, ak.max_offline)),
                        allow_reanchor,
                    ) {
                        Ok(name) => name,
                        Err(error) => {
                            self.log
                                .debug(&format!("enroll response persistence failed: {error}"));
                            self.deny(&t, "enrollment denied").await;
                            return;
                        }
                    }
                } else {
                    requested_name
                };
                if persistent
                    && self.store.invitee_kind(&hex::encode(enroll_pub)).as_deref()
                        == Some("person")
                {
                    if let Err(error) = self.store.devices_mark_invited_as(&stored_name, "person") {
                        self.log.debug(&format!(
                            "enroll response: could not record the invited kind: {error}"
                        ));
                    }
                }
                if let Some(link) = conn.link_mut(&pid) {
                    link.verified_name = Some(stored_name.clone());
                    link.admit_delegated(owner_pub, device_pub, ak.expires, ak.caps.clone());
                }
                let mut ack = enrolment;
                ack["type"] = json!("identity-auth-key-enroll-ack");
                ack["name"] = json!(stored_name);
                ack["owner_name"] = json!(self.display_name);
                ack["secret"] = json!(secret);
                ack["device_pub"] = json!(hex::encode(device_pub));
                ack["max_offline"] = json!(ak.max_offline);
                let _ = t.send_control(&ack).await;
                let kind = if persistent {
                    "device"
                } else {
                    "ephemeral device"
                };
                let who = if persistent {
                    stored_name.as_str()
                } else {
                    pid.as_str()
                };
                self.log.say(&format!(
                    "  {} {kind} {who} enrolled (caps: {})",
                    self.log.paint(Tone::Ok, self.log.glyph_ok()),
                    capability_summary(&ak.caps)
                ));
            }
            Err(e) => {
                self.log
                    .debug(&format!("enroll response verify failed: {e}"));
                self.deny(&t, "enrollment denied").await;
            }
        }
    }

    /// Re-send the acknowledgement for an enrollment this owner already
    /// committed, when a retry arrives after the invitation's use was burned.
    ///
    /// Safe because the retry proved possession of BOTH keys again (the caller
    /// runs `EnrollmentPayload::verify` before this), the durable use count is
    /// for this enrollment key, and the stored device record names exactly this
    /// device key. A different device key, a different invitation, renewed
    /// bounds or a revoked record all fall through to the ordinary refusal.
    async fn reissue_enrolment_receipt(
        &self,
        conn: &mut Conn,
        pid: &str,
        owner_key: &UserKey,
        device_pub: [u8; 32],
        enroll_pub: [u8; 32],
        ak: &filament_cap::ephemeral::AuthKey,
    ) -> bool {
        let Some(t) = conn.transport_of(pid) else {
            return false;
        };
        let key_id = hex::encode(enroll_pub);
        if self.store.invitation_uses(&key_id, now_secs()).unwrap_or(0) == 0 {
            return false;
        }
        let Some(record) = self.store.devices_find_by_device_pub(&device_pub) else {
            return false;
        };
        // A separate `devices forget` records the key revocation BEFORE it
        // removes the record/grants. If that later step failed, the record is
        // still here but the key is revoked; a receipt would hand back a cert
        // and secret the owner has already killed. `device_key_revoked` is
        // fail-closed (an unreadable list reads as revoked).
        let key_revoked = self.store.device_key_revoked(&device_pub, now_secs());
        let Some((name, secret, cert)) = receipt_from_record(
            &record,
            ak,
            device_pub,
            owner_key.public_key_bytes(),
            key_revoked,
        ) else {
            return false;
        };
        let Ok((_, mut ack)) =
            self.build_enrolment(owner_key, device_pub, &ak.caps, ak.expires, true)
        else {
            return false;
        };
        // The stored certificate is what the fleet certified; re-sending a
        // freshly minted one would change the receipt's substance.
        ack["device_cert"] = cert.to_json();
        ack["type"] = json!("identity-auth-key-enroll-ack");
        ack["name"] = json!(name);
        ack["owner_name"] = json!(self.display_name);
        ack["secret"] = json!(secret);
        ack["device_pub"] = json!(hex::encode(device_pub));
        ack["max_offline"] = json!(ak.max_offline);
        ack["receipt"] = json!(true);
        let _ = t.send_control(&ack).await;
        self.log.say(&format!(
            "  {} re-sent the join receipt for {name} (already enrolled; the invitation was not used again)",
            self.log.paint(Tone::Ok, self.log.glyph_ok())
        ));
        if let Some(link) = conn.link_mut(pid) {
            link.verified_name = Some(name);
            link.admit_delegated(
                owner_key.public_key_bytes(),
                device_pub,
                ak.expires,
                ak.caps.clone(),
            );
        }
        true
    }

    fn build_enrolment(
        &self,
        owner_key: &UserKey,
        device_pub: [u8; 32],
        caps: &[String],
        expires: u64,
        persistent: bool,
    ) -> Result<(DeviceCert, Value)> {
        build_enrolment(
            &self.store,
            &self.overlay,
            &self.display_name,
            owner_key,
            device_pub,
            caps,
            expires,
            persistent,
        )
    }
}

/// One enrolment builder for the enrollment handler and the pairing ceremony.
/// The signed bounds, owner certificate, fleet rendezvous and cap policy are
/// read from the explicit store; nothing here is a second policy.
pub fn build_enrolment(
    store: &DeviceStore,
    overlay: &OverlayKey,
    display_name: &str,
    owner_key: &UserKey,
    device_pub: [u8; 32],
    caps: &[String],
    expires: u64,
    persistent: bool,
) -> Result<(DeviceCert, Value)> {
    let now = now_secs();
    let cert = DeviceCert::certify(owner_key, device_pub, now, expires.saturating_sub(now))
        .map_err(|e| anyhow::anyhow!("could not certify the device: {e}"))?;
    let fleet_rv = if persistent {
        store.fleet_rv_load_or_create().ok()
    } else {
        None
    };
    let cap_header = if persistent {
        store.owner_cap_header()
    } else {
        None
    };
    let cap_ops = if persistent {
        json!(store
            .clone()
            .with_owner_pub(Some(owner_key.public_key_bytes()))
            .owner_signed_cap_ops())
    } else {
        Value::Null
    };
    let payload = json!({
        "device_cert": cert.to_json(),
        "owner_cert": local_device_cert(store, overlay, display_name).map(|c| c.to_json()),
        "fleet_rv": fleet_rv,
        "cap_header": cap_header,
        "cap_ops": cap_ops,
        "ceiling": caps,
        "expires": expires,
        "persistent": persistent,
    });
    Ok((cert, payload))
}

/// The one refusal wording for a device record that cannot re-enroll.
pub fn enrollment_refusal(prior: &Value) -> Option<String> {
    let revoked = prior["certRevoked"].as_bool() == Some(true)
        || prior["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED);
    revoked.then(|| {
        "this device was revoked; the owner must run 'tunlion devices restore <name>' to allow it back"
            .to_string()
    })
}

/// Validate that a stored record is exactly the enrollment these signed bounds
/// describe, and return `(name, secret, certificate)` for an idempotent receipt.
///
/// Pure, so the rule is testable without a transport. Every mismatch is a
/// reason NOT to reissue: a different device key, a different owner, a renewed
/// certificate, a different ceiling/offline budget, a revoked record, or an
/// ephemeral invitation (which never leaves a record) all fail closed.
pub fn receipt_from_record(
    record: &Value,
    ak: &filament_cap::ephemeral::AuthKey,
    device_pub: [u8; 32],
    owner_pub: [u8; 32],
    key_revoked: bool,
) -> Option<(String, String, DeviceCert)> {
    if ak.ephemeral || key_revoked {
        return None;
    }
    if enrollment_refusal(record).is_some() {
        return None;
    }
    let cert = DeviceCert::from_json(&record["deviceCert"])?;
    if cert.device_pub != device_pub
        || cert.user_pub != owner_pub
        || cert.expires != ak.expires
        || cert.verify(now_secs()).is_err()
    {
        return None;
    }
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    // The SIGNED bounds, not the mutable/effective view. `caps` is a local
    // grant mirror and `principalMaxOffline` is the effective budget (local
    // policy may tighten it); neither is the enrollment's commitment. A
    // missing or malformed signed field fails closed: an absent offline
    // ceiling must not be read as "any budget".
    let signed_ceiling = record["principalCeiling"]
        .as_array()?
        .iter()
        .map(|c| c.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()?;
    if signed_ceiling != ak.caps {
        return None;
    }
    if record["principalMaxOfflineCeiling"].as_u64()? != ak.max_offline {
        return None;
    }
    if record["principalExpires"].as_u64()? != ak.expires {
        return None;
    }
    let name = record["name"].as_str()?.to_string();
    let secret = record["secret"].as_str()?.to_string();
    if hex::decode(&secret).map(|b| b.len()).ok() != Some(32) {
        return None;
    }
    Some((name, secret, cert))
}

fn capability_summary(caps: &[String]) -> String {
    caps.iter()
        .map(|cap| match cap.as_str() {
            "shell" => "OWNER-EQUIVALENT shell (can act as you)".to_string(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recv::store::InvitationRefusal;

    #[test]
    fn a_revoked_record_is_refused_in_the_old_words() {
        let record = json!({"certRevoked": true});
        assert!(enrollment_refusal(&record)
            .unwrap()
            .contains("devices restore"));
        let lapsed = json!({"principalState": PRINCIPAL_STATE_LAPSED});
        assert!(enrollment_refusal(&lapsed).is_none());
    }

    fn auth_key_for(caps: &[&str], ttl: u64) -> filament_cap::ephemeral::AuthKey {
        use filament_cap::ephemeral::{Invitation, Reuse};
        let owner_seed = [9u8; 32];
        let owner = ring::signature::Ed25519KeyPair::from_seed_unchecked(&owner_seed).unwrap();
        let inv = Invitation::mint(
            &owner,
            [5u8; 32],
            caps.iter().map(|c| c.to_string()).collect(),
            now_secs() + ttl,
            600,
            Reuse::Once,
            false,
            "owner".into(),
            Vec::new(),
        )
        .unwrap();
        let user = filament_id::UserKey::from_seed(&owner_seed).unwrap();
        inv.to_auth_key(&user.public_key_bytes())
    }

    fn delegated_record(
        owner: &filament_id::UserKey,
        device_pub: [u8; 32],
        expires: u64,
        caps: &[&str],
        max_offline: u64,
    ) -> Value {
        // Certify from a fixed issued time so `expires` is exact, not "now+ttl
        // rounded to whenever this second ticked".
        let issued = expires.saturating_sub(3600);
        let cert = DeviceCert::certify(owner, device_pub, issued, 3600).unwrap();
        // The shape `upsert_peer_record` actually writes: signed bounds are
        // `principalCeiling`/`principalMaxOfflineCeiling`/`principalExpires`,
        // while `caps`/`principalMaxOffline` are mutable/effective views.
        json!({
            "name": "joined-device",
            "secret": "11".repeat(32),
            "deviceCert": cert.to_json(),
            "caps": caps,
            "principalKind": "delegated",
            "principalCeiling": caps,
            "principalExpires": expires,
            "principalMaxOffline": max_offline,
            "principalMaxOfflineCeiling": max_offline,
        })
    }

    #[test]
    fn an_already_enrolled_retry_gets_the_same_receipt() {
        let owner = filament_id::UserKey::from_seed(&[9u8; 32]).unwrap();
        let device_pub = [7u8; 32];
        let ak = auth_key_for(&["transfer"], 3600);
        let record = delegated_record(&owner, device_pub, ak.expires, &["transfer"], ak.max_offline);
        let stored = DeviceCert::from_json(&record["deviceCert"]).unwrap();
        assert_eq!(stored.expires, ak.expires);
        assert_eq!(stored.user_pub, owner.public_key_bytes());
        assert!(stored.verify(now_secs()).is_ok());
        assert_eq!(record["principalMaxOffline"].as_u64(), Some(ak.max_offline));
        assert_eq!(record["caps"], json!(["transfer"]));
        assert_eq!(ak.caps, vec!["transfer".to_string()]);
        let (name, secret, cert) =
            receipt_from_record(&record, &ak, device_pub, owner.public_key_bytes(), false)
                .expect("the committed record is exactly this enrollment");
        assert_eq!(name, "joined-device");
        assert_eq!(secret, "11".repeat(32));
        assert_eq!(cert.device_pub, device_pub);
        assert_eq!(cert.expires, ak.expires);
    }

    #[test]
    fn a_receipt_is_refused_for_a_different_device_key_or_bounds() {
        let owner = filament_id::UserKey::from_seed(&[9u8; 32]).unwrap();
        let device_pub = [7u8; 32];
        let ak = auth_key_for(&["transfer"], 3600);
        let record = delegated_record(&owner, device_pub, ak.expires, &["transfer"], ak.max_offline);
        // A different device key must not inherit this receipt.
        assert!(receipt_from_record(&record, &ak, [8u8; 32], owner.public_key_bytes(), false).is_none());
        // A revoked record is refused.
        let mut revoked = record.clone();
        revoked["principalState"] = json!("revoked");
        assert!(receipt_from_record(&revoked, &ak, device_pub, owner.public_key_bytes(), false).is_none());
        // A key in the SEPARATE revoked-keys list is refused even when the
        // record still carries no revocation marker (a partial forget).
        assert!(receipt_from_record(&record, &ak, device_pub, owner.public_key_bytes(), true).is_none());
        // A different signed ceiling is refused (the new invitation is not this one).
        let wider = auth_key_for(&["transfer", "shell"], 3600);
        assert!(receipt_from_record(&record, &wider, device_pub, owner.public_key_bytes(), false).is_none());
        // A different owner key is refused.
        let other_owner = filament_id::UserKey::from_seed(&[4u8; 32]).unwrap();
        assert!(receipt_from_record(&record, &ak, device_pub, other_owner.public_key_bytes(), false).is_none());
    }

    #[test]
    fn a_receipt_validates_the_persisted_signed_bounds_not_mutable_views() {
        let owner = filament_id::UserKey::from_seed(&[9u8; 32]).unwrap();
        let device_pub = [7u8; 32];
        let ak = auth_key_for(&["transfer"], 3600);
        let record = delegated_record(&owner, device_pub, ak.expires, &["transfer"], ak.max_offline);

        // Local grant/revoke changes `caps`; the receipt is still the same
        // enrollment and must not be refused for a mutable mirror.
        let mut locally_granted = record.clone();
        locally_granted["caps"] = json!(["transfer", "mount"]);
        assert!(
            receipt_from_record(&locally_granted, &ak, device_pub, owner.public_key_bytes(), false).is_some()
        );
        // Local policy may tighten the EFFECTIVE offline budget.
        let mut tightened = record.clone();
        tightened["principalMaxOffline"] = json!(ak.max_offline.saturating_sub(60));
        assert!(
            receipt_from_record(&tightened, &ak, device_pub, owner.public_key_bytes(), false).is_some()
        );

        // A missing effective field is fine; a missing SIGNED field is not.
        let mut no_effective_offline = record.clone();
        no_effective_offline.as_object_mut().unwrap().remove("principalMaxOffline");
        assert!(
            receipt_from_record(&no_effective_offline, &ak, device_pub, owner.public_key_bytes(), false).is_some()
        );
        for field in [
            "principalCeiling",
            "principalMaxOfflineCeiling",
            "principalExpires",
        ] {
            let mut missing = record.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                receipt_from_record(&missing, &ak, device_pub, owner.public_key_bytes(), false).is_none(),
                "missing {field} must fail closed"
            );
        }
        // A locally widened persisted ceiling must not stand in for the signed one.
        let mut changed_ceiling = record.clone();
        changed_ceiling["principalCeiling"] = json!(["transfer", "shell"]);
        assert!(
            receipt_from_record(&changed_ceiling, &ak, device_pub, owner.public_key_bytes(), false).is_none()
        );
        // An absent signed offline ceiling is not "any budget".
        let mut no_offline_ceiling = record.clone();
        no_offline_ceiling["principalMaxOfflineCeiling"] = json!(null);
        assert!(
            receipt_from_record(&no_offline_ceiling, &ak, device_pub, owner.public_key_bytes(), false).is_none()
        );
    }

    #[test]
    fn invitation_refusal_reasons_are_the_wire_reasons() {
        assert_eq!(InvitationRefusal::AlreadyUsed.wire_reason(), "already used");
        assert_eq!(
            InvitationRefusal::UseLimitReached.wire_reason(),
            "use limit reached"
        );
        assert_eq!(
            InvitationRefusal::Unverifiable.wire_reason(),
            "enrollment denied"
        );
    }
}
