//! Ephemeral devices and auth keys — CLI-side glue over `filament-cap`.
//!
//! The reusable auth-key layer (AuthKey / EnrollmentPayload / Reuse, the
//! normalize/intersect helpers, and the process-local burn / nonce / armed
//! state with their accessors) now lives in the `filament-cap` crate and is
//! re-exported below so every `crate::ephemeral::X` call site resolves unchanged.
//!
//! What STAYS here is the pending-enrollment glue: `register_enrollment` and
//! `build_enrollment_response`. `build_enrollment_response` reads a
//! `crate::identity::DeviceCert` (mutual authentication of the daemon's cert),
//! and `filament-cap` deliberately carries NO filament-id dependency. Those two
//! functions also share a single static (`PENDING_ENROLLS`), and by the
//! move-the-static-with-all-its-accessors rule they must move together — so the
//! whole group stays in the CLI.
//!
//! Design: docs/design-ephemeral-auth-keys.md

pub use filament_cap::ephemeral::*;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Pending enrollment state (enroller side)
// ---------------------------------------------------------------------------

struct PendingEnroll {
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    auth_key: AuthKey,
}

impl Drop for PendingEnroll {
    fn drop(&mut self) {
        self.enroll_seed.zeroize();
    }
}

static PENDING_ENROLLS: OnceLock<Mutex<HashMap<String, PendingEnroll>>> = OnceLock::new();

/// Register a pending enrollment attempt. Called by the ephemeral enroll CLI.
pub fn register_enrollment(
    peer_id: String,
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    auth_key: AuthKey,
) {
    let mut store = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    store.insert(peer_id, PendingEnroll { enroll_seed, device_pub, auth_key });
}

/// Take a pending enrollment and build the response to the daemon's challenge.
/// Verifies the daemon's device cert chains to the auth key's issuer (mutual
/// authentication — the cert is MANDATORY) and that the verifier_pub is in the
/// auth key's audience (mirror audience check). Removal from the store happens
/// ONLY on success so a failed attempt doesn't burn a single-use key.
///
/// STAYS in the CLI (not filament-cap): it reads a `crate::identity::DeviceCert`,
/// and the crate carries no filament-id dependency. It shares `PENDING_ENROLLS`
/// with `register_enrollment`, so the pair moves together — here.
pub fn build_enrollment_response(
    peer_id: &str,
    nonce: [u8; 32],
    verifier_pub: [u8; 32],
    device_cert: &serde_json::Value,
) -> Option<serde_json::Value> {
    let store_ref = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut store = store_ref.lock().unwrap();
    let pe = match store.get(peer_id) {
        Some(p) => p,
        None => return None,
    };
    let issuer = pe.auth_key.issuer;
    let audience = pe.auth_key.audience.clone();

    // Mutual authentication: daemon's cert MUST chain to auth_key.issuer.
    // Cert is MANDATORY — no if-let bypass for a missing field.
    let cert = crate::identity::DeviceCert::from_json(device_cert)?;
    if cert.user_pub != issuer
        || cert.verify(now_secs()).is_err()
        || cert.device_pub != verifier_pub
    {
        return None;
    }

    // Mirror audience check: the enroller verifies it was handed a verifier_pub
    // that its auth key actually authorizes (audience-scoped protection).
    if !(audience.is_empty() || audience.contains(&verifier_pub)) {
        return None;
    }

    // ALL checks passed — now remove from store and build.
    let pe = store.remove(peer_id)?;
    let ak = pe.auth_key.clone();
    let enroll_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&pe.enroll_seed).ok()?;
    let message = enrollment_possession_msg(&nonce, &pe.device_pub, &verifier_pub);
    let enroll_signature = enroll_kp.sign(&message);
    let mut enroll_possession_sig = [0u8; 64];
    enroll_possession_sig.copy_from_slice(enroll_signature.as_ref());
    let device_possession_sig = crate::overlay::overlay_sign_possession(&message).ok()?;
    let payload = EnrollmentPayload {
        auth_key: ak.clone(),
        device_pub: pe.device_pub,
        enroll_possession_sig,
        device_possession_sig,
    };
    Some(serde_json::json!({
        "auth_key": payload.auth_key.to_json(),
        "device_pub": hex::encode(payload.device_pub),
        "enroll_possession_sig": hex::encode(payload.enroll_possession_sig),
        "device_possession_sig": hex::encode(payload.device_possession_sig),
    }))
}
