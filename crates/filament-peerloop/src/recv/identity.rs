//! Identity proof, expose and certificate renewal, with an explicit host.
//!
//! This is the implementation half of [`RecvIdentity`](crate::recv::ports::RecvIdentity)
//! for the handlers that only need the device store, the overlay signing key
//! and a log sink. Both are instance inputs:
//!
//! * [`DeviceStore`] — the explicit-root store from `recv::store`;
//! * [`OverlayKey`] — the explicit-path Ed25519 key that proves possession.
//!
//! The CLI builds one of these over its process paths and forwards; there is no
//! second copy of the proof/expose/renew rules. The remaining `RecvIdentity`
//! methods (auth-key enrolment, roster/depart, fleet rendezvous) still need
//! per-instance enrollment/nonce/burn state and the fleet files; they stay on
//! the CLI adapter until those stores move, and are named in
//! `docs/engine-driver.md`.
//!
//! Certificates, capability ceilings, revocation and expiry are unchanged: the
//! only edits from `cli/src/identity_lifecycle.rs` are the host facts
//! (`ui::*` became a log sink, `overlay::*` became `self.overlay`, store reads
//! became `self.store`, and `fleet_renewal` became the library module).

use crate::conn::Conn;
use crate::host::{LogSink, Tone};
use crate::identity::principal_after_liveness;
use crate::recv::renewal;
use crate::recv::store::{
    effective_principal_deadline, DeviceStore, OverlayKey, PRINCIPAL_STATE_LAPSED,
    PRINCIPAL_STATE_REVOKED,
};
use filament_cap::capability::BindingStrength;
use filament_id::{now_secs, DeviceCert, IntroScope, UserKey, CERT_TTL_SECS};
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// #161: how long the possession challenge stays LIVE. Must be raised in
/// lockstep with the offer hold and the nonce lifetime: if the challenge entry
/// expires first, a re-issue clobbers the in-flight nonce and the peer's answer
/// verifies against the wrong nonce and never reaches Proven.
pub const PROVEN_CHALLENGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// The identity host for one instance: explicit store, explicit overlay key,
/// explicit display name and settle window, and the log sink the caller chose.
pub struct IdentityService {
    store: DeviceStore,
    overlay: OverlayKey,
    display_name: String,
    settle_ms: u64,
    log: Arc<dyn LogSink>,
    /// Per-instance drop-once bookkeeping, so two services do not share a
    /// "already said that" set.
    drop_seen: Mutex<HashSet<String>>,
}

impl IdentityService {
    pub fn new(
        store: DeviceStore,
        overlay: OverlayKey,
        display_name: impl Into<String>,
        settle_ms: u64,
        log: Arc<dyn LogSink>,
    ) -> Self {
        Self {
            store,
            overlay,
            display_name: display_name.into(),
            settle_ms,
            log,
            drop_seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn store(&self) -> &DeviceStore {
        &self.store
    }

    pub fn gate_settle_ms(&self) -> u64 {
        self.settle_ms
    }

    fn note_drop(&self, pid: &str, why: &str) {
        const DROP_ONCE_CAP: usize = 512;
        let key = format!("{pid}|{why}");
        if let Ok(mut seen) = self.drop_seen.lock() {
            if seen.contains(&key) || seen.len() >= DROP_ONCE_CAP {
                return;
            }
            seen.insert(key);
        }
        self.log.say(&format!(
            "l2: identity-expose dropped for {pid}: {why} (not repeated for this link)"
        ));
    }

    /// Whether a recorded challenge hold has served its whole deadline. Pure.
    pub fn hold_expired(&self, deadline: Instant, now: Instant) -> bool {
        now >= deadline
    }

    /// This device's certificate, minting the self-cert on demand exactly where
    /// the CLI always did.
    pub fn local_device_cert(&self) -> Option<DeviceCert> {
        let overlay_pub = self.overlay.public_key_bytes().ok();
        if let Some(cert) = self
            .store
            .local_device_cert(overlay_pub.as_ref(), &self.display_name)
        {
            return Some(cert);
        }
        if let (Ok(Some(user_key)), Ok(overlay_pub)) = (
            UserKey::load(&self.store.keystore()),
            self.overlay.public_key_bytes(),
        ) {
            if let Ok(cert) = DeviceCert::certify(&user_key, overlay_pub, now_secs(), CERT_TTL_SECS)
            {
                return Some(cert);
            }
        }
        None
    }

    async fn send_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) {
        if let Ok(own_dpub) = self.overlay.public_key_bytes() {
            if let Some(t) = conn.transport_of(pid) {
                use ring::rand::{SecureRandom, SystemRandom};
                let rng = SystemRandom::new();
                let mut nonce = [0u8; 32];
                let _ = rng.fill(&mut nonce);
                identity_nonces.insert(pid.to_string(), (nonce, Instant::now(), own_dpub));
                let challenge = json!({
                    "type": "identity-nonce-challenge",
                    "nonce": hex::encode(nonce),
                    "receiver_device_pub": hex::encode(own_dpub)
                });
                if let Err(e) = t.send_control(&challenge).await {
                    self.log.say(&format!(
                        "l2: identity challenge to {pid} could NOT be sent ({e})"
                    ));
                }
            }
        }
    }

    /// Register the Proven hold, then issue the possession challenge. Both
    /// readiness sites call this one method so their ordering cannot diverge.
    pub async fn issue_proven_challenge_and_hold(
        &self,
        conn: &Conn,
        pid: &str,
        t: &Arc<dyn Transport>,
        pending_proven: &Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) {
        {
            let mut pend = pending_proven.lock().unwrap();
            if let Some((held_t, deadline)) = pend.get(pid) {
                if Instant::now() < *deadline && Arc::ptr_eq(held_t, t) {
                    return;
                }
            }
            pend.insert(
                pid.to_string(),
                (t.clone(), Instant::now() + PROVEN_CHALLENGE_DEADLINE),
            );
        }
        self.send_identity_challenge(conn, pid, identity_nonces)
            .await;
    }

    /// Re-send the challenge already held for this link, SAME nonce.
    pub async fn resend_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        identity_nonces: &HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        let Some((nonce, _issued, recv_dpub)) = identity_nonces.get(pid) else {
            return false;
        };
        let Some(t) = conn.transport_of(pid) else {
            return false;
        };
        let challenge = json!({
            "type": "identity-nonce-challenge",
            "nonce": hex::encode(nonce),
            "receiver_device_pub": hex::encode(recv_dpub)
        });
        if let Err(e) = t.send_control(&challenge).await {
            self.log.say(&format!(
                "l2: identity challenge to {pid} could NOT be sent ({e}); the peer cannot prove until this link carries frames"
            ));
            return false;
        }
        true
    }

    /// Handle a possession-sig identity-expose response sent by a peer after we
    /// challenged it.
    pub fn handle_identity_expose(
        &self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        let fail = |why: &'static str| {
            self.note_drop(pid, why);
            self.log
                .debug(&format!("identity-expose dropped for {pid}: {why}"));
            false
        };
        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
        let Ok(nonce_bytes) = hex::decode(nonce_hex) else {
            return fail("malformed nonce");
        };
        if nonce_bytes.len() != 32 {
            return fail("nonce wrong length");
        }
        let mut nonce_arr = [0u8; 32];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let Some((held_nonce, _ts, _held_recv_dpub)) = identity_nonces.get(pid) else {
            return fail("no challenge is held for this link (proof arrived on a different link?)");
        };
        if held_nonce != &nonce_arr {
            return fail("nonce does not match the one held for this link");
        }
        let Some(cert_json) = v.get("cert") else {
            return fail("no certificate in the frame");
        };
        let Some(cert) = DeviceCert::from_json(cert_json) else {
            return fail("unparseable certificate");
        };
        if cert.verify(now_secs()).is_err() {
            return fail("certificate expired or malformed");
        }
        let Some(sig_hex) = v.get("possession_sig").and_then(|x| x.as_str()) else {
            return fail("no possession signature");
        };
        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return fail("possession signature is not hex");
        };
        if sig_bytes.len() != 64 {
            return fail("possession signature wrong length");
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let scope = IntroScope::User.to_byte();
        let caps_d = filament_id::caps_digest("transfer");
        let chash = filament_id::cert_hash(&cert);
        let Ok(own_dpub) = self.overlay.public_key_bytes() else {
            return fail("this device has no overlay key");
        };
        let sender_dpub = cert.device_pub;
        let receiver_dpub = own_dpub;
        let msg = filament_id::possession_msg(
            0x02,
            &nonce_arr,
            scope,
            &caps_d,
            &chash,
            &sender_dpub,
            &receiver_dpub,
        );
        if filament_id::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_err() {
            return fail("possession signature does not verify");
        }
        if cert.device_pub == own_dpub {
            return fail("reflection: the certificate is this device's own");
        }
        let _ = self
            .store
            .store_provisional_identity(&format!("peer-{pid}"), &cert);
        let own_user_pub = self.store.owner_pub_from_keystore();
        let (principal_kind, not_after, max_offline, last_seen) = self
            .store
            .persisted_principal_for_cert(&cert, own_user_pub.as_ref());
        if let Some(l) = conn.link_mut(pid) {
            l.identity_device_pub = Some(cert.device_pub);
            l.identity_user_pub = Some(cert.user_pub);
            l.identity_binding = BindingStrength::Proven;
            let (deadline, _clock) =
                effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
            l.identity_cert_expires = Some(deadline);
            let alive = deadline > now_secs();
            l.principal_kind = principal_after_liveness(principal_kind, alive);
        }
        self.log.debug(&format!(
            "{} identity proven for peer {}",
            self.log.paint(Tone::Ok, self.log.glyph_ok()),
            pid
        ));
        let petname = conn.link(pid).map(|l| l.name.clone()).unwrap_or_default();
        if !petname.is_empty()
            && self.store.device_cert_valid_for(&petname).is_none()
            && self.store.devices_load().iter().any(|(n, _)| n == &petname)
        {
            match self
                .store
                .update_peer_identity(&petname, &cert, VOUCH_CERT_SCOPE)
            {
                Ok(()) => self.log.say(&format!(
                    "  {} first identity for '{}' pinned; `tunlion revoke {} --certificate` can now reach it",
                    self.log.paint(Tone::Ok, self.log.glyph_ok()),
                    petname,
                    petname
                )),
                Err(e) => self.log.caution(
                    &format!("'{petname}' is paired but not certified"),
                    Some(&format!(
                        "its certificate was not stored ({e}), so revoke has nothing to key on."
                    )),
                    &[format!(
                        "remove it instead: tunlion devices forget {petname} -y"
                    )],
                ),
            }
        }
        identity_nonces.remove(pid);
        true
    }

    async fn say_identity_unavailable(t: &Arc<dyn Transport>, nonce_hex: &str) {
        let _ = t
            .send_control(&json!({ "type": "identity-unavailable", "nonce": nonce_hex }))
            .await;
    }

    /// Answer a challenge addressed to us, proving device-key possession.
    pub async fn respond_to_identity_challenge(&self, t: &Arc<dyn Transport>, v: &Value) {
        let nonce_hex = v["nonce"].as_str().unwrap_or_default();
        let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
        let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) =
            (hex::decode(nonce_hex), hex::decode(recv_dpub_hex))
        else {
            self.log
                .debug("identity challenge ignored: malformed nonce/receiver fields");
            return;
        };
        if nonce_bytes.len() != 32 || recv_dpub_bytes.len() != 32 {
            self.log
                .debug("identity challenge ignored: nonce/receiver wrong length");
            return;
        }
        let mut nonce_arr = [0u8; 32];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let mut recv_dpub_arr = [0u8; 32];
        recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
        if let Ok(own_dpub) = self.overlay.public_key_bytes() {
            if recv_dpub_arr == own_dpub {
                self.log
                    .debug("identity challenge ignored: it names my own device key");
                Self::say_identity_unavailable(t, nonce_hex).await;
                return;
            }
        }
        let Some(local_cert) = self.local_device_cert() else {
            let msg =
                "identity challenge NOT answered: this device holds no certificate for its own key";
            if self.store.has_identity() {
                self.log.say(msg);
            } else {
                self.log.debug(msg);
            }
            Self::say_identity_unavailable(t, nonce_hex).await;
            return;
        };
        match self.overlay.public_key_bytes() {
            Ok(own_pub) if local_cert.device_pub == own_pub => {}
            Ok(_) => {
                self.log.say(
                    "identity challenge NOT answered: the local certificate is not this device's key (refusing to sign as another identity)",
                );
                return;
            }
            Err(e) => {
                self.log.say(&format!(
                    "identity challenge NOT answered: this device's key is unreadable ({e}); nothing can be signed"
                ));
                return;
            }
        }
        let scope = IntroScope::User.to_byte();
        let caps_d = filament_id::caps_digest("transfer");
        let chash = filament_id::cert_hash(&local_cert);
        let sender_dpub = local_cert.device_pub;
        let msg = filament_id::possession_msg(
            0x02,
            &nonce_arr,
            scope,
            &caps_d,
            &chash,
            &sender_dpub,
            &recv_dpub_arr,
        );
        if let Ok(sig) = self.overlay.sign(&msg) {
            let payload = json!({
                "type": "identity-expose",
                "v": 2,
                "binding_type": 0x02,
                "nonce": hex::encode(nonce_arr),
                "cert": local_cert.to_json(),
                "possession_sig": hex::encode(sig)
            });
            match t.send_control(&payload).await {
                Ok(()) => self
                    .log
                    .debug("identity challenge answered (identity-expose sent)"),
                Err(e) => self.log.say(&format!(
                    "l2: identity-expose could NOT be sent ({e}); the challenger will see no proof"
                )),
            }
        } else {
            self.log
                .debug("identity challenge NOT answered: possession signing failed");
        }
    }

    /// Ask a peer to renew our certificate, if it is time and we are a fleet
    /// member. Cheap and idempotent.
    pub async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str) {
        if self.store.owner_pub_from_keystore().is_some() {
            return;
        }
        let Some(cert) = self.local_device_cert() else {
            return;
        };
        if !renewal::renewal_due(&cert, now_secs()) {
            return;
        }
        if let Some(t) = conn.transport_of(pid) {
            let _ = t
                .send_control(&json!({"type": "identity-cert-renew-request"}))
                .await;
        }
    }

    fn renewal_standing_for(&self, device_pub: &[u8; 32]) -> renewal::Standing {
        let Some(record) = self.store.devices_find_by_device_pub(device_pub) else {
            return renewal::Standing::default();
        };
        let stored = record["deviceCert"]["devicePub"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        renewal::Standing {
            known: true,
            revoked: record["certRevoked"].as_bool() == Some(true)
                || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED),
            lapsed: record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED),
            stored_device_pub: stored,
            access_until: (record["principalKind"].as_str() == Some("delegated"))
                .then(|| record["principalExpires"].as_u64().unwrap_or(0)),
        }
    }

    /// OWNER SIDE: re-sign a fleet device's certificate, or refuse.
    pub async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String) {
        let Some(link) = conn.link(&pid) else { return };
        let proven = link.identity_binding == BindingStrength::Proven;
        let device_pub = link.identity_device_pub;
        let (Some(device_pub), true) = (device_pub, proven) else {
            self.log
                .debug("  cert renewal refused: requester is not identity-proven on this link");
            if let Some(t) = conn.transport_of(&pid) {
                let _ = t
                    .send_control(&json!({"type": "identity-cert-renew-error"}))
                    .await;
            }
            return;
        };
        let Some(owner_key) = UserKey::load(&self.store.keystore()).ok().flatten() else {
            self.log
                .debug("  cert renewal declined: this device holds no owner signing key");
            if let Some(t) = conn.transport_of(&pid) {
                let _ = t
                    .send_control(&json!({"type": "identity-cert-renew-error"}))
                    .await;
            }
            return;
        };
        let standing = self.renewal_standing_for(&device_pub);
        match renewal::owner_decides(&standing, device_pub) {
            renewal::Decision::Refuse(why) => {
                self.log.debug(&format!("  cert renewal refused: {why}"));
                if let Some(t) = conn.transport_of(&pid) {
                    let _ = t
                        .send_control(&json!({"type": "identity-cert-renew-error"}))
                        .await;
                }
            }
            renewal::Decision::Renew => {
                let now = now_secs();
                let Some(current) = self
                    .store
                    .devices_find_by_device_pub(&device_pub)
                    .as_ref()
                    .and_then(|r| DeviceCert::from_json(&r["deviceCert"]))
                else {
                    self.log
                        .debug("  cert renewal refused: no stored certificate to extend");
                    if let Some(t) = conn.transport_of(&pid) {
                        let _ = t
                            .send_control(&json!({"type": "identity-cert-renew-error"}))
                            .await;
                    }
                    return;
                };
                let Some(expires) =
                    renewal::renewal_expiry(&current, now, CERT_TTL_SECS, standing.access_until)
                else {
                    self.log.debug(
                        "  cert renewal declined: the device's invitation ends before this would extend its certificate",
                    );
                    if let Some(t) = conn.transport_of(&pid) {
                        let _ = t
                            .send_control(&json!({"type": "identity-cert-renew-error"}))
                            .await;
                    }
                    return;
                };
                let ttl = expires.saturating_sub(now);
                let Ok(fresh) = DeviceCert::certify(&owner_key, device_pub, now, ttl) else {
                    self.log.debug("  cert renewal failed: could not sign");
                    return;
                };
                if let Some(record) = self.store.devices_find_by_device_pub(&device_pub) {
                    if let Some(name) = record["name"].as_str() {
                        let _ = self.store.devices_upsert_atomic(
                            name,
                            None,
                            Some(&fresh),
                            None,
                            None,
                            None,
                            None,
                            false,
                        );
                    }
                }
                if let Some(l) = conn.link_mut(&pid) {
                    let own_user_pub = self.store.owner_pub_from_keystore();
                    let (_, not_after, max_offline, last_seen) = self
                        .store
                        .persisted_principal_for_cert(&fresh, own_user_pub.as_ref());
                    let (deadline, _) = effective_principal_deadline(
                        fresh.expires,
                        not_after,
                        last_seen,
                        max_offline,
                    );
                    l.identity_cert_expires = Some(deadline);
                }
                if let Some(t) = conn.transport_of(&pid) {
                    let _ = t
                        .send_control(&json!({
                            "type": "identity-cert-renew-ack",
                            "cert": fresh.to_json(),
                        }))
                        .await;
                }
                self.log.debug(&format!(
                    "  renewed certificate for {}",
                    hex::encode(device_pub).chars().take(8).collect::<String>()
                ));
            }
        }
    }

    /// REQUESTING SIDE: adopt a renewed certificate, or keep the one we have.
    pub async fn handle_cert_renew_ack(&self, v: &Value) {
        let Some(fresh) = DeviceCert::from_json(&v["cert"]) else {
            self.log
                .debug("  renewal ack carried no readable certificate");
            return;
        };
        let Some(current) = self.local_device_cert() else {
            self.log
                .debug("  renewal ack ignored: this device holds no certificate to extend");
            return;
        };
        let owner_pub = current.user_pub;
        if let Err(e) = renewal::accept_renewal(&current, &fresh, &owner_pub, now_secs()) {
            self.log.debug(&format!("  renewal rejected: {e}"));
            return;
        }
        let name = self
            .store
            .local_device_cert_record()
            .as_ref()
            .and_then(|r| r["name"].as_str().map(str::to_string))
            .unwrap_or_default();
        let body = json!({ "name": name, "cert": fresh.to_json() });
        match self.store.write_local_device_cert_record(&body) {
            Ok(()) => self.log.debug(&format!(
                "  certificate renewed, now valid for {}",
                short_duration(fresh.expires.saturating_sub(now_secs()))
            )),
            Err(e) => self
                .log
                .debug(&format!("  could not persist renewed certificate: {e}")),
        }
    }

    pub fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        self.store.device_name_for_pub(device_pub)
    }

    pub fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        self.store.device_cert_revoked(device_pub)
    }

    pub fn owner_pub_for_resources(&self) -> Option<[u8; 32]> {
        let local = self.overlay.public_key_bytes().ok();
        self.store.owner_pub_for_resources(local.as_ref())
    }

    pub fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<crate::refusal::Reinvite> {
        self.store.reinvite_for(device_pub)
    }

    pub fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        filament_cap::ephemeral::enroll_channel(public_key)
    }

    pub fn is_armed(&self) -> bool {
        self.store.is_armed()
    }
}

/// The intro scope a vouch stores. A vouch introduces a DEVICE, not a user.
pub const VOUCH_CERT_SCOPE: u8 = 0x01; // IntroScope::Device

fn short_duration(secs: u64) -> String {
    if secs >= 86400 && secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 && secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}
