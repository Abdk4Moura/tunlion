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

enum PendingEnroll {
    /// #186 compact-invitation join: the full invitation (carries the 8-byte
    /// owner fingerprint + the compact signature); the daemon reconstructs the
    /// full issuer after the fingerprint matches.
    Compact {
        enroll_seed: [u8; 32],
        device_pub: [u8; 32],
        inv: InvitationV2,
    },
    /// Legacy mint/enroll path (hidden): a full AuthKey with its own issuer.
    Legacy {
        enroll_seed: [u8; 32],
        device_pub: [u8; 32],
        auth_key: AuthKey,
    },
}

impl PendingEnroll {
    fn enroll_seed(&self) -> [u8; 32] {
        match self {
            PendingEnroll::Compact { enroll_seed, .. } | PendingEnroll::Legacy { enroll_seed, .. } => *enroll_seed,
        }
    }
    fn device_pub(&self) -> [u8; 32] {
        match self {
            PendingEnroll::Compact { device_pub, .. } | PendingEnroll::Legacy { device_pub, .. } => *device_pub,
        }
    }
    fn zeroize_seed(&mut self) {
        match self {
            PendingEnroll::Compact { enroll_seed, .. } => enroll_seed.zeroize(),
            PendingEnroll::Legacy { enroll_seed, .. } => enroll_seed.zeroize(),
        }
    }
}

impl Drop for PendingEnroll {
    fn drop(&mut self) {
        self.zeroize_seed();
    }
}

static PENDING_ENROLLS: OnceLock<Mutex<HashMap<String, PendingEnroll>>> = OnceLock::new();

/// Register a pending enrollment attempt for the COMPACT (v2) invitation path.
/// The invitation carries the owner fingerprint + signature the daemon checks.
pub fn register_enrollment(
    peer_id: String,
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    inv: InvitationV2,
) {
    let mut store = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    store.insert(peer_id, PendingEnroll::Compact { enroll_seed, device_pub, inv });
}

/// Register a pending enrollment attempt for the LEGACY mint/enroll path,
/// which carries a full AuthKey.
pub fn register_enrollment_legacy(
    peer_id: String,
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    auth_key: AuthKey,
) {
    let mut store = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    store.insert(peer_id, PendingEnroll::Legacy { enroll_seed, device_pub, auth_key });
}

/// Take a pending enrollment and build the response to the daemon's challenge.
/// Verifies the daemon's device cert carries a user key whose 8-byte
/// fingerprint matches the invitation's owner fingerprint (mutual
/// authentication — the cert is MANDATORY). #186: the compact invitation
/// carries only the fp, so the cert's user_pub is compared by fingerprint
/// (64-bit selection) rather than by full-key equality. Removal from the store
/// happens ONLY on success so a failed attempt doesn't burn a single-use key.
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
    // Mutual authentication: daemon's cert MUST belong to the invitation's
    // owner. Compact: an 8-byte fingerprint check. Legacy: full-issuer equality.
    // Cert is MANDATORY — no if-let bypass for a missing field.
    let cert = crate::identity::DeviceCert::from_json(device_cert)?;
    if cert.verify(now_secs()).is_err() || cert.device_pub != verifier_pub {
        return None;
    }
    let owner_ok = match pe {
        PendingEnroll::Compact { inv, .. } => {
            filament_cap::ephemeral::issuer_fingerprint(&cert.user_pub) == inv.issuer_fp
        }
        PendingEnroll::Legacy { auth_key, .. } => cert.user_pub == auth_key.issuer,
    };
    if !owner_ok {
        return None;
    }

    // ALL checks passed — now remove from store and build.
    let pe = store.remove(peer_id)?;
    let enroll_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&pe.enroll_seed()).ok()?;
    let message = enrollment_possession_msg(&nonce, &pe.device_pub(), &verifier_pub);
    let enroll_signature = enroll_kp.sign(&message);
    let mut enroll_possession_sig = [0u8; 64];
    enroll_possession_sig.copy_from_slice(enroll_signature.as_ref());
    let device_possession_sig = crate::overlay::overlay_sign_possession(&message).ok()?;
    let principal = match &pe {
        PendingEnroll::Compact { inv, .. } => {
            crate::ephemeral::EnrollmentPrincipal::Compact(inv.clone())
        }
        PendingEnroll::Legacy { auth_key, .. } => {
            crate::ephemeral::EnrollmentPrincipal::Legacy(auth_key.clone())
        }
    };
    let payload = crate::ephemeral::EnrollmentPayload {
        principal,
        device_pub: pe.device_pub(),
        enroll_possession_sig,
        device_possession_sig,
    };
    Some(payload.to_json())
}
