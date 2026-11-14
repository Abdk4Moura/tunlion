//! The sealed `identity-expose` and its possession proof.
//!
//! This was the other half of the CLI's inline ceremony: send a device
//! certificate plus a signature over this session's confirmation MAC, sealed
//! under K. Moved here so a browser DeviceIdentity produces and checks exactly
//! the same bytes the CLI does.

use crate::frame::{FrameKind, IdentityExpose};
use crate::{EnrolError, Result};
use filament_id::{
    caps_digest, cert_hash, open_sealed, possession_msg, seal_plaintext_with_nonce,
    sealing_key_from_k, verify_possession_sig, DeviceCert,
};
use filament_pair::{confirm_dirs, confirm_mac, our_confirm, sort_fps};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExposeBody {
    cert: Value,
    #[serde(with = "crate::hexwire::hex64")]
    possession_sig: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_pub: Option<String>,
}

/// Build our sealed `identity-expose`: this device's certificate and a
/// possession signature over this ceremony's confirmation MAC. `sign` signs
/// with the device key; `nonce` is injected. Pure over its inputs.
pub fn build_identity_expose(
    k: &[u8],
    my_fp: &str,
    their_fp: &str,
    caps_canon: &str,
    scope: u8,
    cert: &DeviceCert,
    nonce: [u8; 12],
    sign: &dyn Fn(&[u8]) -> Option<[u8; 64]>,
) -> Result<IdentityExpose> {
    let cmv: [u8; 32] = our_confirm(k, my_fp, their_fp, caps_canon, scope)
        .try_into()
        .map_err(|_| EnrolError::MacLength)?;
    let dpub = cert.device_pub;
    let msg = possession_msg(
        0x01,
        &cmv,
        scope,
        &caps_digest(caps_canon),
        &cert_hash(cert),
        &dpub,
        &[0u8; 32],
    );
    let possession_sig = sign(&msg).ok_or(EnrolError::SigningRefused)?;
    let body = ExposeBody {
        cert: cert.to_json(),
        possession_sig,
        device_pub: Some(hex::encode(dpub)),
    };
    let plain = serde_json::to_vec(&body).map_err(|_| EnrolError::ExposeMalformed)?;
    let sealed = seal_plaintext_with_nonce(&sealing_key_from_k(k), &nonce, &plain)
        .map_err(|_| EnrolError::SealFailed)?;
    Ok(IdentityExpose::new(nonce, &sealed))
}

/// Open a peer's sealed `identity-expose` and check everything it claims: the
/// seal, the certificate's own signature and lifetime, the possession signature
/// over this session's confirmation MAC, and that it is not our own key
/// reflected back. `Err` names the check that refused it.
///
/// `fps` stays optional because the link's fingerprints may not be known yet;
/// `None` is a "not yet", not a bad frame. `own_dpub` is `None` when our key
/// could not be read, which fails closed.
pub fn open_identity_expose(
    frame: &IdentityExpose,
    k: &[u8],
    fps: Option<(&str, &str)>,
    caps_canon: &str,
    scope: u8,
    own_dpub: Option<[u8; 32]>,
    now: u64,
) -> Result<DeviceCert> {
    frame.ensure_kind()?;
    let nonce = frame.nonce_bytes()?;
    let sealed = frame.sealed_bytes()?;
    let plain = open_sealed(&sealing_key_from_k(k), &nonce, &sealed)
        .map_err(|_| EnrolError::ExposeSealed)?;
    let body: ExposeBody =
        serde_json::from_slice(&plain).map_err(|_| EnrolError::ExposeMalformed)?;
    let cert = DeviceCert::from_json(&body.cert).ok_or(EnrolError::NoCertificateInExpose)?;
    cert.verify(now)
        .map_err(|_| EnrolError::CertInvalid("certificate does not verify".to_string()))?;
    // Session-bound: the MAC binds K, both DTLS fingerprints, caps and scope.
    let (my_fp, their_fp) = fps.ok_or(EnrolError::FingerprintsUnknown)?;
    let (lo, hi) = sort_fps(my_fp, their_fp);
    let (_send, expect_dir) = confirm_dirs(my_fp, lo);
    let cmv: [u8; 32] = confirm_mac(k, expect_dir, lo, hi, caps_canon, scope)
        .try_into()
        .map_err(|_| EnrolError::MacLength)?;
    // Reconstruct cert_hash locally from parsed cert fields (never hash a
    // sender-framed blob). For the PAKE path receiver_device_pub MUST be zeros.
    let msg = possession_msg(
        0x01,
        &cmv,
        scope,
        &caps_digest(caps_canon),
        &cert_hash(&cert),
        &cert.device_pub,
        &[0u8; 32],
    );
    verify_possession_sig(&cert.device_pub, &msg, &body.possession_sig)
        .map_err(|_| EnrolError::PossessionProofInvalid)?;
    // Anti-reflection: the PAKE path zeroes receiver_device_pub, so this
    // comparison is the only thing preventing our own certificate being
    // reflected back. Fail closed without our own key.
    match own_dpub {
        Some(own) if own == cert.device_pub => Err(EnrolError::OwnKeyReflected),
        Some(_) => Ok(cert),
        None => Err(EnrolError::OwnKeyUnknown),
    }
}

/// True when this value names the identity-expose frame. A state machine can
/// use it before paying for a parse.
pub fn is_identity_expose(value: &Value) -> bool {
    value.get("type").and_then(|v| v.as_str()) == Some(FrameKind::IdentityExpose.as_str())
}
