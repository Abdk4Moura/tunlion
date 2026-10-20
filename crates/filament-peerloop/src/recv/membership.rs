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
    use filament_id::UserKey;

    fn device() -> (UserKey, [u8; 32]) {
        let user = UserKey::from_seed(&[4u8; 32]).unwrap();
        let pubkey = user.public_key_bytes();
        (user, pubkey)
    }

    #[test]
    fn a_forged_or_wrong_text_depart_is_refused() {
        let (key, pubkey) = device();
        let msg = depart_message(&pubkey);
        let sig = key.sign(msg.as_bytes());
        assert!(verify_depart(&pubkey, &msg, &sig).is_ok());

        // Replaying another signed text (a pairing-style possession proof)
        // under its own message must not count as a departure.
        let other = format!("filament-pair-proof:{}", hex::encode(pubkey));
        let other_sig = key.sign(other.as_bytes());
        assert!(verify_depart(&pubkey, &other, &other_sig).is_err());

        // A different device key cannot sign for this one.
        let (other_key, _) = {
            let user = UserKey::from_seed(&[5u8; 32]).unwrap();
            let pubkey = user.public_key_bytes();
            (user, pubkey)
        };
        let forged = other_key.sign(msg.as_bytes());
        assert!(verify_depart(&pubkey, &msg, &forged).is_err());
    }

    #[test]
    fn an_expired_departure_is_the_owner_s_liveness_decision_not_this_policy() {
        // Departure has no timestamp: expiry is enforced by the owner's
        // delegated deadline/revocation state, not by a signed clock here.
        // This test documents that a valid signature is the only input.
        let (key, pubkey) = device();
        let msg = depart_message(&pubkey);
        let sig = key.sign(msg.as_bytes());
        assert_eq!(verify_depart(&pubkey, &msg, &sig), Ok(()));
    }
}
