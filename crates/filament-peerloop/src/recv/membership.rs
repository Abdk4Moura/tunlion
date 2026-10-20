//! Departure trust policy, with no network or store.
//!
//! The only thing that makes a depart advisory safe is that the signature is
//! bound to EXACTLY the message for the departing device key. The same device
//! key signs pairing and enrollment possession proofs, so verifying a signature
//! over whatever text the sender supplied would accept any of those replayed as
//! a departure. The expected text is rebuilt from the key, never taken from the
//! wire.

/// PROTOCOL LITERAL: frozen, do not rename. The exact bytes a departing device
/// signs.
pub const DEPART_MSG_PREFIX: &str = "filament-depart:v1:";

/// The one message a depart request may carry for `device_pub`.
pub fn depart_message(device_pub: &[u8; 32]) -> String {
    format!("{DEPART_MSG_PREFIX}{}", hex::encode(device_pub))
}

/// Accept only the exact depart message for `device_pub` and a valid possession
/// signature over it. A wrong text, another device's key, a replayed pairing
/// signature or an invalid signature is refused with the same fixed reason.
pub fn verify_depart(
    device_pub: &[u8; 32],
    msg: &str,
    sig: &[u8; 64],
) -> std::result::Result<(), &'static str> {
    if msg != depart_message(device_pub) {
        return Err("message is not the depart message for that device key");
    }
    filament_id::verify_possession_sig(device_pub, msg.as_bytes(), sig)
        .map_err(|_| "signature does not verify for that device key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key(seed: [u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(kp.public_key().as_ref());
        (kp, public)
    }

    fn sign(kp: &Ed25519KeyPair, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(kp.sign(msg).as_ref());
        out
    }

    #[test]
    fn a_forged_or_wrong_text_depart_is_refused() {
        let (kp, public) = key([4u8; 32]);
        let msg = depart_message(&public);
        assert!(verify_depart(&public, &msg, &sign(&kp, msg.as_bytes())).is_ok());

        // Replaying another signed text (a pairing-style possession proof)
        // under its own message must not count as a departure.
        let other = format!("filament-pair-proof:{}", hex::encode(public));
        let other_sig = sign(&kp, other.as_bytes());
        assert!(verify_depart(&public, &other, &other_sig).is_err());

        // A different device key cannot sign for this one.
        let (forger, _) = key([5u8; 32]);
        assert!(verify_depart(&public, &msg, &sign(&forger, msg.as_bytes())).is_err());
    }

    #[test]
    fn an_expired_departure_is_the_owner_s_liveness_decision_not_this_policy() {
        // Departure has no timestamp: expiry is enforced by the owner's
        // delegated deadline/revocation state, not by a signed clock here.
        let (kp, public) = key([6u8; 32]);
        let msg = depart_message(&public);
        assert_eq!(
            verify_depart(&public, &msg, &sign(&kp, msg.as_bytes())),
            Ok(())
        );
    }
}
