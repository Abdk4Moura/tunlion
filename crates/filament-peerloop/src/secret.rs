//! Random secrets and nonces, without a host.
//!
//! One CSPRNG-derived hex string, used for room names, one-shot rendezvous
//! secrets and link nonces. It was `cli::crypto_atoms::fresh_secret`; moving it
//! here keeps the generation rule beside the loop that consumes it and leaves
//! the CLI a re-export, so every call site produces the same bytes.
//!
//! NO cfg, NO I/O beyond the OS entropy source, NO CLI types.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// 32 bytes of OS entropy as lowercase hex (64 characters).
///
/// On unix it reads `/dev/urandom`; when that cannot be opened (a non-unix
/// host) it hashes the wall clock and the pid, which is the fallback the CLI
/// carried before the move. Neither branch is a host policy decision, so the
/// function stays here unchanged.
pub fn fresh_secret() -> String {
    let mut buf = [0u8; 32];
    // std-only CSPRNG is unavailable; derive from getrandom via std::fs on unix
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // fallback (non-unix): hash of time+pid noise, still unpredictable enough
        let mut h = Sha256::new();
        h.update(format!("{:?}{}", SystemTime::now(), std::process::id()));
        buf.copy_from_slice(&h.finalize()[..32]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_secret_is_32_bytes_of_hex_and_does_not_repeat() {
        let a = fresh_secret();
        let b = fresh_secret();
        assert_eq!(a.len(), 64, "{a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b);
    }
}
