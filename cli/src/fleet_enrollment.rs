//! Persistent fleet certificate enrollment over the existing auth-key proof.

use anyhow::{bail, Result};

/// Issue a DeviceCert only when the possession-proven key is the overlay key.
pub fn issue(
    owner: &crate::identity::UserKey,
    possession_device_pub: [u8; 32],
    overlay_pub: [u8; 32],
    now: u64,
) -> Result<crate::identity::DeviceCert> {
    ensure_same_device_key(possession_device_pub, overlay_pub)?;
    crate::identity::DeviceCert::certify(
        owner,
        possession_device_pub,
        now,
        crate::identity::CERT_TTL_SECS,
    )
}

pub fn ensure_same_device_key(possession_device_pub: [u8; 32], overlay_pub: [u8; 32]) -> Result<()> {
    if possession_device_pub != overlay_pub {
        bail!("fleet enrollment key mismatch: possession and overlay keys differ");
    }
    Ok(())
}

/// Validate the cert returned by the owner on the enrolling device.
pub fn accept(
    cert: &crate::identity::DeviceCert,
    owner_pub: &[u8; 32],
    possession_device_pub: [u8; 32],
    overlay_pub: [u8; 32],
    now: u64,
) -> Result<()> {
    if cert.device_pub != possession_device_pub || cert.device_pub != overlay_pub {
        bail!("fleet enrollment certificate key mismatch");
    }
    cert.verify_chain(owner_pub, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_divergent_possession_and_overlay_keys() {
        let err = ensure_same_device_key([1; 32], [2; 32]).unwrap_err();
        assert!(err.to_string().contains("key mismatch"));
    }

    #[test]
    fn rejects_cert_for_different_overlay_key_before_signature_check() {
        let cert = crate::identity::DeviceCert {
            device_pub: [1; 32],
            user_pub: [3; 32],
            expires: u64::MAX,
            issued: 0,
            sig: [0; 64],
        };
        let err = accept(&cert, &[3; 32], [1; 32], [2; 32], 1_000).unwrap_err();
        assert!(err.to_string().contains("key mismatch"));
    }
}
