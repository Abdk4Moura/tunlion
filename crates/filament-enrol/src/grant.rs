//! The owner's sealed `enrol-grant` and the pure verification half of
//! persisting it.
//!
//! `seal_enrol_grant` deliberately takes the already-built owner-signed payload
//! and the sealing nonce. The caller owns the store reads (fleet rendezvous,
//! capability header and ops, the owner's own certificate) and the clock. That
//! keeps this crate free of `std::fs`, a wallet of owner keys and a second
//! enrolment policy.

use crate::frame::EnrolGrant;
use crate::{EnrolError, Result};
use filament_id::{
    open_sealed, seal_plaintext_with_nonce, sealing_key_from_k, DeviceCert,
};
use serde_json::Value;

/// The parts of a grant this device may persist after verification.
#[derive(Debug, Clone)]
pub struct VerifiedMeshGrant {
    /// The owner-signed certificate, already checked against this device's key
    /// and (when pinned) the expected owner.
    pub cert: DeviceCert,
    /// The owner's display name, for the local certificate file.
    pub owner_name: String,
    /// The fleet rendezvous secret, when the grant carried one.
    pub fleet_rv: Option<String>,
    /// The owner-signed capability header, when present and an object.
    pub cap_header: Option<Value>,
    /// The owner-signed capability operations, when present.
    pub cap_ops: Vec<Value>,
}

/// Seal an owner-built grant payload under this ceremony's PAKE key.
///
/// The payload is the object `build_enrolment` produced (device certificate,
/// owner certificate, fleet rendezvous, capability header/ops, ceiling and
/// expiry). This function only adds the two fields the pairing frame owns
/// (`type` and `owner_name`) and seals the bytes. `nonce` is injected so the
/// caller owns randomness. Pure over its inputs.
pub fn seal_enrol_grant(
    k: &[u8],
    payload: Value,
    owner_name: &str,
    nonce: [u8; 12],
) -> Result<EnrolGrant> {
    let mut payload = payload;
    let object = payload
        .as_object_mut()
        .ok_or(EnrolError::GrantPayloadMalformed)?;
    object.insert("type".to_string(), Value::String("enrol-grant".to_string()));
    object.insert(
        "owner_name".to_string(),
        Value::String(owner_name.to_string()),
    );
    let plain = serde_json::to_vec(&payload).map_err(|_| EnrolError::GrantMalformed)?;
    let sealed = seal_plaintext_with_nonce(&sealing_key_from_k(k), &nonce, &plain)
        .map_err(|_| EnrolError::SealFailed)?;
    Ok(EnrolGrant::new(nonce, &sealed))
}

/// Open a sealed grant. Returns the owner's payload; verification of the
/// certificate inside it is [`verify_mesh_grant`]'s job.
pub fn open_enrol_grant(k: &[u8], frame: &EnrolGrant) -> Result<Value> {
    frame.ensure_kind()?;
    let nonce = frame.nonce_bytes()?;
    let sealed = frame.sealed_bytes()?;
    let plain = open_sealed(&sealing_key_from_k(k), &nonce, &sealed)
        .map_err(|_| EnrolError::GrantSealed)?;
    serde_json::from_slice(&plain).map_err(|_| EnrolError::GrantMalformed)
}

/// Verify the certificate a grant carries against this device's key and,
/// when known, the pinned owner key.
///
/// This is the pure half of the old `persist_mesh_grant`: the CLI still checks
/// that no certificate is already stored and owns the write. No I/O here.
pub fn verify_mesh_grant(
    grant: &Value,
    own_device_pub: [u8; 32],
    pinned_owner_pub: Option<[u8; 32]>,
    now: u64,
) -> Result<VerifiedMeshGrant> {
    let cert = DeviceCert::from_json(&grant["device_cert"])
        .ok_or(EnrolError::NoCertificateInGrant)?;
    if cert.device_pub != own_device_pub {
        return Err(EnrolError::WrongDeviceKey {
            expected: own_device_pub,
            got: cert.device_pub,
        });
    }
    verify_cert_chain(&cert, pinned_owner_pub, now)?;

    let owner_name = grant["owner_name"]
        .as_str()
        .unwrap_or("owner")
        .to_string();
    let fleet_rv = grant["fleet_rv"].as_str().map(str::to_string);
    let cap_header = grant
        .get("cap_header")
        .filter(|value| value.is_object())
        .cloned();
    let cap_ops = grant
        .get("cap_ops")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(VerifiedMeshGrant {
        cert,
        owner_name,
        fleet_rv,
        cap_header,
        cap_ops,
    })
}

/// Verify a device certificate's lifetime and owner signature.
///
/// When `pinned_owner_pub` is `Some`, the certificate must also name that key
/// as its owner. `None` is the trust-on-first-use case: the PAKE ceremony
/// proved who sent the certificate, so its own signature is all that can be
/// checked.
pub fn verify_cert_chain(
    cert: &DeviceCert,
    pinned_owner_pub: Option<[u8; 32]>,
    now: u64,
) -> Result<()> {
    if now >= cert.expires {
        return Err(EnrolError::CertExpired {
            now,
            expires: cert.expires,
        });
    }
    if let Some(expected) = pinned_owner_pub {
        if cert.user_pub != expected {
            return Err(EnrolError::WrongOwner {
                expected,
                got: cert.user_pub,
            });
        }
    }
    cert.verify(now)
        .map_err(|err| EnrolError::CertInvalid(err.to_string()))
}
