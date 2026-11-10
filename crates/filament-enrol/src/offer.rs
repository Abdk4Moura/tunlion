//! The certless device's sealed `enrol-offer`.
//!
//! The offer proves possession of the device key it names, bound to THIS
//! ceremony's confirmation MAC (which itself folds K, both link fingerprints,
//! the canonical capability list and the introduction scope). A signature that
//! verified in one ceremony therefore cannot be replayed into another.

use crate::frame::{EnrolOffer, FrameKind};
use crate::{EnrolError, Result};
use filament_id::{
    caps_digest, open_sealed, possession_msg, seal_plaintext_with_nonce, sealing_key_from_k,
    verify_possession_sig,
};
use filament_pair::{confirm_dirs, confirm_mac, our_confirm, sort_fps};
use serde::{Deserialize, Serialize};

/// The sealed body of an offer. Kept private: callers see the proven key, never
/// a body they might trust without verifying the proof over it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OfferBody {
    #[serde(with = "crate::hexwire::hex32")]
    device_pub: [u8; 32],
    #[serde(with = "crate::hexwire::hex64")]
    possession_sig: [u8; 64],
    #[serde(default)]
    name: Option<String>,
}

/// Build the sealed `enrol-offer` a certless device sends.
///
/// `sign` signs with the device key and is injected so this crate never holds
/// key material. `nonce` is injected so the caller owns randomness and a vector
/// can replay the exact bytes. Pure over its inputs.
pub fn build_enrol_offer(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    device_pub: [u8; 32],
    name: &str,
    nonce: [u8; 12],
    sign: &dyn Fn(&[u8]) -> Option<[u8; 64]>,
) -> Result<EnrolOffer> {
    let cmv: [u8; 32] = our_confirm(k, my_fp, their_fp, caps_canon, scope)
        .try_into()
        .map_err(|_| EnrolError::MacLength)?;
    let msg = possession_msg(
        0x01,
        &cmv,
        scope,
        &caps_digest(caps_canon),
        &[0u8; 32],
        &device_pub,
        &[0u8; 32],
    );
    let possession_sig = sign(&msg).ok_or(EnrolError::SigningRefused)?;
    let body = OfferBody {
        device_pub,
        possession_sig,
        name: Some(name.to_string()),
    };
    let plain = serde_json::to_vec(&body).map_err(|_| EnrolError::OfferMalformed)?;
    let sealed = seal_plaintext_with_nonce(&sealing_key_from_k(k), &nonce, &plain)
        .map_err(|_| EnrolError::SealFailed)?;
    Ok(EnrolOffer::new(nonce, &sealed))
}

/// Open a peer's sealed offer and return the device key it proved it holds.
///
/// Refuses this device's own key (a reflection) and fails closed when our own
/// key is unknown. The fact that the frame opened under K proves the sender
/// held the PAKE secret; the possession signature proves it holds the device key
/// it offers. Pure over its inputs.
///
/// A byte-identical replay inside the SAME ceremony is indistinguishable here:
/// the proof is deterministic for that ceremony. `enrol_offer_decision`'s
/// `already_asked` is what refuses a second certification. Across ceremonies
/// (another K, link or scope) the AEAD or the possession proof fails.
pub fn open_enrol_offer(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    frame: &EnrolOffer,
    own_device_pub: Option<[u8; 32]>,
) -> Result<[u8; 32]> {
    frame.ensure_kind()?;
    let nonce = frame.nonce_bytes()?;
    let sealed = frame.sealed_bytes()?;
    let plain = open_sealed(&sealing_key_from_k(k), &nonce, &sealed)
        .map_err(|_| EnrolError::OfferSealed)?;
    let body: OfferBody =
        serde_json::from_slice(&plain).map_err(|_| EnrolError::OfferMalformed)?;
    let (lo, hi) = sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = confirm_dirs(my_fp, lo);
    let expected: [u8; 32] = confirm_mac(k, expect_dir, lo, hi, caps_canon, scope)
        .try_into()
        .map_err(|_| EnrolError::MacLength)?;
    let msg = possession_msg(
        0x01,
        &expected,
        scope,
        &caps_digest(caps_canon),
        &[0u8; 32],
        &body.device_pub,
        &[0u8; 32],
    );
    verify_possession_sig(&body.device_pub, &msg, &body.possession_sig)
        .map_err(|_| EnrolError::PossessionProofInvalid)?;
    match own_device_pub {
        Some(own) if own != body.device_pub => Ok(body.device_pub),
        Some(_) => Err(EnrolError::OwnKeyReflected),
        None => Err(EnrolError::OwnKeyUnknown),
    }
}

/// The frame kind helper is public so a state machine can reject a mis-typed
/// frame before trying to open it.
pub fn is_enrol_offer(value: &serde_json::Value) -> bool {
    value.get("type").and_then(|v| v.as_str()) == Some(FrameKind::EnrolOffer.as_str())
}
