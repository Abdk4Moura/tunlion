//! Auth-key enrolment handlers, lifted out of `main.rs`.
//!
//! Certificate renewal moved to `filament_peerloop::recv::identity` with the
//! identity store and overlay key it needs. What stays here is the enrolment
//! door, because it still depends on the process-local burn/nonce/rate-limit
//! state in `filament_cap::ephemeral` and the owner-side invitation stores
//! (`armed`, `used-invitations`). Those are the exact host facts named in
//! `docs/engine-driver.md`; until they have per-instance stores, this half
//! cannot move without inventing one.
use crate::identity;
use crate::ui;
use crate::{
    PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, capability_list_summary,
    devices_find_by_device_pub, devices_upsert_atomic, display_name, enrollment_refusal,
    fresh_secret, local_device_cert, mesh_enrolment,
};
use serde_json::{Value, json};

pub(crate) async fn respond_to_auth_key_enroll_request(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else {
        // Never silent: the joiner cannot tell a dropped request from a slow
        // one, so it waits out its whole deadline (the join hang).
        crate::conn::dropped_no_transport(&pid, "enrolment request");
        return;
    };

    // Rate-limit FIRST — keyed on pid, counts EVERY request including garbage.
    // An attacker sending unparseable JSON is bounded here, before parse cycles.
    if let Err(e) = crate::ephemeral::check_rate_limit(&pid) {
        ui::debug(&format!("enroll request rate-limited: {e}"));
        let _ = t
            .send_control(
                &json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"}),
            )
            .await;
        return;
    }

    // Enroll-and-use is coherent in BOTH modes: the delegated ceiling is
    // enforced in shadow mode too (cap_gate_effective's ceiling check is
    // mode-independent and load-bearing exactly because shadow's effective
    // decision is legacy_allowed, which the ceiling check precedes). An
    // earlier gate refused enrollment unless TUNLION_CAP_AUTHORITATIVE=1;
    // that rationale is stale and it made the flagship join flow fail for a
    // default-configured owner. The joined device's ceiling binds either way.

    // ONE READER. The enrolment request carries the invitation payload,
    // base64url. There was a second branch here for an `auth_key` JSON, whose
    // own comment said "the legacy v1 mint/enroll path (hidden) still sends"
    // it: that path was `ephemeral mint`, which no longer exists, so nothing
    // produces that form and this accepted a shape it could never receive.
    //
    // A second accepted credential shape on an ENROLMENT handler is not free
    // even when unused. It is a second way to become a principal, reviewed
    // once and then carried, and it is the kind of thing that outlives the
    // reason it was added.
    let ak = {
        use base64::Engine;
        let Some(v2_b64) = v.get("auth_key_v2").and_then(|x| x.as_str()) else {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        };
        let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v2_b64) else {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        };
        match crate::ephemeral::Invitation::from_payload(&bytes) {
            Some(inv) => crate::ephemeral::EnrollmentPrincipal::Compact(inv),
            None => {
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
        }
    };

    // Verify against our trusted owner
    let owner_key = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk,
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_pub = owner_key.public_key_bytes();
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll request overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    // Verify the principal under our trusted owner, then reconstruct the full
    // auth key (Compact: fingerprint + compact signature; Legacy: full-issuer
    // verify) for the principal registration that follows.
    let _ak = match &ak {
        crate::ephemeral::EnrollmentPrincipal::Compact(inv) => {
            if !inv.verify_against_owner(&owner_pub) {
                ui::debug("enroll request auth-key rejected (fingerprint or signature)");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            if identity::now_secs() >= inv.expires {
                ui::debug("enroll request auth-key expired");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            inv.to_auth_key(&owner_pub)
        }
        crate::ephemeral::EnrollmentPrincipal::Legacy(ak) => {
            if ak.verify_against_owner(&owner_pub, &verifier_pub).is_err() {
                ui::debug("enroll request legacy auth-key rejected");
                let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                return;
            }
            ak.clone()
        }
    };

    // Generate nonce challenge — include daemon's device cert so the enroller
    // can verify it chains to the auth key's issuer (mutual authentication).
    let nonce = match crate::ephemeral::generate_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll request nonce CSPRNG failure: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let cert_value = local_device_cert().map(|c| c.to_json());
    let _ = t
        .send_control(&json!({
            "type": "identity-auth-key-enroll-challenge",
            "nonce": hex::encode(nonce),
            "verifier_pub": hex::encode(verifier_pub),
            "device_cert": cert_value,
        }))
        .await;
}

/// Handle the enrollment response from the enroller.
/// Step 4 (burn only on SUCCESS): consume nonce, verify payload, admit as delegated.
pub(crate) async fn handle_auth_key_enroll_response(
    conn: &mut Conn,
    pid: String,
    v: serde_json::Value,
) {
    let Some(t) = conn.transport_of(&pid) else {
        crate::conn::dropped_no_transport(&pid, "enrolment response");
        return;
    };
    let payload = match crate::ephemeral::EnrollmentPayload::from_json(&v) {
        Some(p) => p,
        None => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_key = match crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(uk)) => uk,
        _ => {
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };
    let owner_pub = owner_key.public_key_bytes();
    let verifier_pub = match crate::overlay::overlay_pubkey_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            ui::debug(&format!("enroll response overlay-key error: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Structural nonce consumption — daemon retrieves its OWN stored nonce,
    // never trusts a nonce value echoed by the enroller.
    let nonce = match crate::ephemeral::consume_latest_nonce(&pid) {
        Ok(n) => n,
        Err(e) => {
            ui::debug(&format!("enroll response nonce consumption failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
            return;
        }
    };

    // Verify payload with consumed nonce
    match payload.verify(&owner_pub, &nonce, &verifier_pub) {
        Ok((enroll_pub, device_pub, ak)) => {
            // Burn ON SUCCESS only (never-reset counter)
            if let Err(e) = crate::ephemeral::burn_auth_key(&enroll_pub, &ak.reuse) {
                ui::debug(&format!("enroll response burn failed: {e}"));
                // #222: the burn state knows WHY it refused (already used,
                // use limit reached, rate-limited). Send that specific fact,
                // not the generic "enrollment denied", so the joiner can say
                // it the way the expired path does.
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
                let _ = t
                    .send_control(
                        &json!({"type": "identity-auth-key-enroll-error", "reason": reason}),
                    )
                    .await;
                return;
            }
            // The in-memory burn above is process-local: a daemon restart
            // cleared it, and a used invitation enrolled again (with the old
            // device key or a brand-new one). The durable count is kept apart
            // from every device record, so no forget/rename/revoke resets it;
            // only the invitation's own expiry does (invite_burn.rs).
            if let Err(refusal) = crate::invite_burn::record_use(
                &hex::encode(enroll_pub),
                &ak.reuse,
                ak.expires,
                identity::now_secs(),
            ) {
                ui::debug(&format!(
                    "enroll response refused: invitation {:?} (durable use count)",
                    refusal
                ));
                let _ = t
                    .send_control(&json!({
                        "type": "identity-auth-key-enroll-error",
                        "reason": refusal.wire_reason()
                    }))
                    .await;
                return;
            }
            // #155: the enrollment side READS the signed `ephemeral` flag. An
            // ephemeral key admits in-memory only: nothing durable is written,
            // so the device is gone at daemon restart by construction (Q2). A
            // persistent key writes the durable record with the ceiling and the
            // offline-budget pair, surviving restart.
            let persistent = !ak.ephemeral;
            let mut requested_name = conn
                .link(&pid)
                .map(|link| link.name.clone())
                .unwrap_or_else(|| "joined-device".to_string());
            // The owner named this invitee when minting (`add beta --out f`):
            // that choice wins over the name the joiner proposes (its
            // hostname, unless `join --name` said otherwise). The usual rules
            // below still apply to it: a name another key holds is suffixed.
            if let Some(chosen) = crate::armed::invitee_name(&hex::encode(enroll_pub)) {
                if chosen != requested_name {
                    ui::say(&format!(
                        "  a device that calls itself '{requested_name}' joined with the invitation you made for '{chosen}'; it is listed as '{chosen}'"
                    ));
                }
                requested_name = chosen;
            }
            // A device re-joining with its own device_pub meets its prior record.
            // LAPSED revives (a network accident): keep the name for continuity,
            // and the delegated write below OVERWRITES the whole bounding set
            // from the NEW key (fresh bounds win, never merged). REVOKED is a
            // decision, not an accident: refuse, and tell the owner only
            // `devices restore` undoes it.
            let prior = devices_find_by_device_pub(&device_pub);
            // A key revoked and then forgotten has no record left to refuse
            // it, so a fresh invitation would have re-admitted the very key
            // the owner cut off. The key list keeps that decision.
            // Whatever record does or does not exist: a key on the revocation
            // list never enrols again, by any invitation.
            if crate::fleet_support::device_key_revoked(&device_pub, identity::now_secs()) {
                ui::debug(&format!("enroll response refused: device {pid} holds a revoked key"));
                let _ = t
                    .send_control(&json!({
                        "type": "identity-auth-key-enroll-error",
                        "reason": "this device key was revoked by the owner; run `tunlion reset` on this device for a new key, then join again"
                    }))
                    .await;
                return;
            }
            if let Some(prior_record) = &prior {
                if let Some(reason) = enrollment_refusal(prior_record) {
                    ui::debug(&format!(
                        "enroll response refused: device {pid} was revoked"
                    ));
                    let _ = t
                        .send_control(
                            &json!({"type": "identity-auth-key-enroll-error", "reason": reason}),
                        )
                        .await;
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
            // Re-anchor ONLY an identity we already know under this exact
            // name (this same key re-enrolling, e.g. the lapsed revival
            // above reusing its name). A new key under a taken name takes
            // a free-or-suffixed name and never overwrites another
            // identity's record -- the invitation authorizes enrollment,
            // not name-squatting.
            let mut candidate = crate::sanitize_device_name(&requested_name);
            let allow_reanchor =
                prior.as_ref().and_then(|r| r["name"].as_str()) == Some(candidate.as_str());
            if !allow_reanchor {
                let base = candidate.clone();
                let hex = hex::encode(device_pub);
                let mut n = 2u32;
                while crate::devices_store::name_pinned_by_other(&candidate, &hex) && n < 1000 {
                    candidate = format!("{base}-{n}");
                    n += 1;
                }
                // The suffix is the security rule (a new key never takes over
                // another key's name). Say it out loud, with the way back, so a
                // reset device does not sit beside its stale self forever.
                if candidate != base {
                    ui::say(&format!(
                        "  {} a new device asked to be called {base}, a name another key holds, so it was stored as {candidate}. If {base} was reset and this is the same machine: `tunlion devices forget {base} -y` then `tunlion devices rename {candidate} {base}`.",
                        ui::paint(ui::Tone::Warn, "!")
                    ));
                }
            }
            let requested_name = candidate;
            let secret = fresh_secret();
            let now = identity::now_secs();
            let _certificate_ttl = ak.expires.saturating_sub(now);
            // ONE enrolment builder, shared with the pairing ceremony. Minting a
            // certificate for a peer happens in exactly one place.
            let (device_cert, enrolment) = match mesh_enrolment(
                &owner_key, device_pub, &ak.caps, ak.expires, persistent,
            ) {
                Ok(pair) => pair,
                Err(error) => {
                    ui::debug(&format!("enroll response certificate failed: {error}"));
                    let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                    return;
                }
            };
            // `ak.caps` already carries the route scope as `route:<cidr>`:
            // Invitation::to_auth_key does that conversion once, so nothing here
            // has to reassemble it.
            let stored_name = if persistent {
                match devices_upsert_atomic(
                    &requested_name,
                    Some(&secret),
                    Some(&device_cert),
                    Some(&ak.caps),
                    Some(identity::IntroScope::Device.to_byte()),
                    None,
                    Some((&ak.caps, ak.expires, ak.max_offline, ak.max_offline)),
                    allow_reanchor,
                ) {
                    Ok(name) => name,
                    Err(error) => {
                        ui::debug(&format!("enroll response persistence failed: {error}"));
                        let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
                        return;
                    }
                }
            } else {
                // Ephemeral: nothing durable is written; the name is session-only.
                requested_name
            };
            // A person's invitation enrols with an owner-signed certificate like
            // a device's; record what was invited so `devices` files them as
            // someone else's, not as one of the owner's devices.
            if persistent && crate::armed::invitee_kind(&hex::encode(enroll_pub)).as_deref() == Some("person") {
                if let Err(error) = crate::devices_store::devices_mark_invited_as(&stored_name, "person") {
                    ui::debug(&format!("enroll response: could not record the invited kind: {error}"));
                }
            }
            // Admit as Delegated principal — structurally, all four fields together
            if let Some(link) = conn.link_mut(&pid) {
                link.verified_name = Some(stored_name.clone());
                link.admit_delegated(owner_pub, device_pub, ak.expires, ak.caps.clone());
            }
            let mut ack = enrolment;
            ack["type"] = json!("identity-auth-key-enroll-ack");
            ack["name"] = json!(stored_name);
            ack["owner_name"] = json!(display_name());
            ack["secret"] = json!(secret);
            ack["device_pub"] = json!(hex::encode(device_pub));
            ack["max_offline"] = json!(ak.max_offline);
            let _ = t.send_control(&ack).await;
            // A `--for <device>` invitation enrolls a lasting device under its
            // name; only a session-only enrolment is ephemeral.
            let kind = if persistent { "device" } else { "ephemeral device" };
            let who = if persistent { stored_name.as_str() } else { pid.as_str() };
            ui::say(&format!(
                "  {} {kind} {who} enrolled (caps: {})",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                capability_list_summary(&ak.caps)
            ));
        }
        Err(e) => {
            ui::debug(&format!("enroll response verify failed: {e}"));
            let _ = t.send_control(&json!({"type": "identity-auth-key-enroll-error", "reason": "enrollment denied"})).await;
        }
    }
}
