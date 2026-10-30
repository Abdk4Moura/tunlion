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
                // Refuse a withdrawn invitation at the first message, so the
                // joiner hears why without a challenge round. This is the
                // early answer only; the response handler re-checks under the
                // use-file lock, which is the decision.
                if self
                    .store
                    .invitation_withdrawn(&hex::encode(inv.enroll_pub), now_secs())
                    == Ok(true)
                {
                    self.log.debug("enroll request refused: invitation withdrawn");
                    self.deny(&t, InvitationRefusal::Withdrawn.wire_reason()).await;
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
                // Burn ON SUCCESS only (never-reset live counter).
                if let Err(e) = self
                    .runtime
                    .burn_auth_key_at(&enroll_pub, &ak.reuse, now_secs())
                {
                    self.log.debug(&format!("enroll response burn failed: {e}"));
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

                // A claim in flight when the owner withdrew the invitation must
                // not complete. The use was counted above, under the use-file
                // lock; a withdrawal that landed after that count is seen here,
                // before anything is stored or sent. An unreadable file refuses.
                match self
                    .store
                    .invitation_withdrawn(&hex::encode(enroll_pub), now_secs())
                {
                    Ok(false) => {}
                    Ok(true) => {
                        self.log.debug(
                            "enroll response refused: invitation withdrawn while the claim was in flight",
                        );
                        self.deny(&t, InvitationRefusal::Withdrawn.wire_reason()).await;
                        return;
                    }
                    Err(refusal) => {
                        self.log.debug(&format!(
                            "enroll response refused: withdrawal state unreadable ({refusal:?})"
                        ));
                        self.deny(&t, refusal.wire_reason()).await;
                        return;
                    }
                }
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
        "this device was revoked; the owner must run 'tunlion promote <name>' to allow it back"
            .to_string()
    })
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
            .contains("tunlion promote"));
        let lapsed = json!({"principalState": PRINCIPAL_STATE_LAPSED});
        assert!(enrollment_refusal(&lapsed).is_none());
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
        // PROTOCOL LITERAL. A 0.9.1 joiner prints an unknown reason verbatim
        // after "enrollment denied: ", so this must stay a sentence that names
        // the withdrawal; the current joiner matches it exactly.
        assert_eq!(
            InvitationRefusal::Withdrawn.wire_reason(),
            "the owner withdrew this invitation"
        );
    }
}
