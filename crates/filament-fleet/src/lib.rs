//! Same-owner auto-mesh: the admission ceremony and the per-peer conversation.
//!
//! Devices certified by ONE owner key meet on a rendezvous channel and admit
//! each other on that CERTIFICATE, never on presence. The channel is a MEETING
//! POINT and nothing more: anyone who learns its id can see that devices are
//! present, and none of them can be admitted, because admission requires an
//! owner-signed `DeviceCert` bound to a live possession proof over the link's
//! channel binding.
//!
//! What auto-mesh grants is REACHABILITY, not capability. A newly met sibling is
//! admitted with an empty ceiling: the link forms and routes, while transfer,
//! shell and mount still need their own explicit grant. So a bug in this crate
//! cannot escalate privilege; it can only connect something it should not have.
//!
//! There is no I/O here. `session::FleetSession` returns an `Action`/`Outcome`
//! that the caller sends, and building our OWN hello is injected as a closure,
//! because that needs the host's key and certificate.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use filament_id::DeviceCert;
use filament_overlay::Announce;

pub mod session;

/// The `type` of the mutual fleet handshake control message.
pub const HELLO: &str = "fleet-hello";

/// The possession and certificate halves of a hello, assembled.
///
/// Reuses `Announce` rather than inventing a second possession proof: enrollment
/// forces the overlay key and the certified device key to be the SAME key, so an
/// announce that verifies against the link binding is already a live possession
/// proof of the key the certificate names.
///
/// Loading the identity and the certificate is the caller's job; this only
/// assembles what they hand over.
pub fn build_hello(announce: &Announce, cert: &DeviceCert, name: &str) -> Value {
    json!({
        "type": HELLO,
        "name": name,
        "cert": cert.to_json(),
        "announce": announce.to_json(),
    })
}

/// The two keys a hello binds together must be the same key.
///
/// Without this a valid certificate for device X could front for device Y's
/// possession proof: two halves that are each fine and together are a lie.
pub fn ensure_same_device_key(possession_device_pub: [u8; 32], overlay_pub: [u8; 32]) -> Result<()> {
    if possession_device_pub != overlay_pub {
        bail!("fleet enrollment key mismatch: possession and overlay keys differ");
    }
    Ok(())
}

/// What a verified `fleet-hello` establishes about the peer.
#[derive(Debug, Clone)]
pub struct Verified {
    pub device_pub: [u8; 32],
    pub owner_pub: [u8; 32],
    pub cert_expires: u64,
    pub claimed_name: String,
}

/// Verify a `fleet-hello` against OUR owner key and THIS link's channel binding.
///
/// Order matters for what an error MEANS, not for what passes: all three checks
/// are required.
pub fn verify_hello(
    v: &Value,
    cb: &[u8],
    my_owner_pub: &[u8; 32],
    now: u64,
) -> Result<Verified> {
    let ann = Announce::from_json(&v["announce"])?;
    // Possession of the announced key, bound to THIS link. Without the binding a
    // hello captured on one link would replay onto another.
    ann.verify(cb)?;
    let cert = DeviceCert::from_json(&v["cert"])
        .ok_or_else(|| anyhow!("fleet-hello carried no certificate"))?;
    let name = v["name"].as_str().unwrap_or("peer").to_string();
    bind_cert_to_possession(&cert, ann.pubkey, my_owner_pub, now, name)
}

/// The non-crypto half, split out so the binding rule is unit-testable without
/// forging signatures over a channel binding.
fn bind_cert_to_possession(
    cert: &DeviceCert,
    proven_pubkey: [u8; 32],
    my_owner_pub: &[u8; 32],
    now: u64,
    claimed_name: String,
) -> Result<Verified> {
    // The certificate must name the key that was just PROVEN on this link.
    ensure_same_device_key(cert.device_pub, proven_pubkey)?;
    // ... and it must chain to the owner key WE already hold. This is the step
    // that makes admission non-transitive: no peer's assertion is an input.
    cert.verify_chain(my_owner_pub, now)?;
    Ok(Verified {
        device_pub: cert.device_pub,
        owner_pub: cert.user_pub,
        cert_expires: cert.expires,
        claimed_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(device_pub: [u8; 32], user_pub: [u8; 32]) -> DeviceCert {
        DeviceCert { device_pub, user_pub, expires: u64::MAX, issued: 0, sig: [0; 64] }
    }

    #[test]
    fn rejects_cert_that_does_not_name_the_proven_key() {
        // A perfectly valid certificate for device [1;32], presented on a link
        // where device [2;32] proved possession. Must be refused BEFORE the
        // signature is even considered, so a real cert cannot front for another
        // device's proof.
        let err = bind_cert_to_possession(
            &cert([1; 32], [9; 32]), [2; 32], &[9; 32], 1_000, "peer".into(),
        ).unwrap_err();
        assert!(err.to_string().contains("key mismatch"), "got: {err}");
    }

    #[test]
    fn rejects_cert_chaining_to_another_owner() {
        // Possession is genuine and the cert names the right device, but it was
        // signed by somebody else's owner key. This is the non-transitivity
        // check: another fleet's certificate is not evidence in ours.
        let err = bind_cert_to_possession(
            &cert([1; 32], [8; 32]), [1; 32], &[9; 32], 1_000, "peer".into(),
        ).unwrap_err();
        assert!(err.to_string().contains("different user key"), "got: {err}");
    }

}
