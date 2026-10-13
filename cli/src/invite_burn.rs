//! Used invitations, on disk, apart from any device record.
//!
//! An invitation says it is good for one use. The only thing that enforced that
//! was `filament_cap::ephemeral::burn_auth_key`, whose own doc says "Burn is
//! process-local: a daemon restart clears all burn state". Measured on the
//! launch candidate: a device joined with `beta.invite`, the owner forgot it and
//! restarted its daemon (which the forget then needed, see revocation_live.rs),
//! the device was wiped, and `join used.invite` came back `"joined":true` and
//! paired. A second replay was refused only because that daemon had now burned
//! the key in ITS memory. It looked as if forget reset the used marker; the
//! marker was never anywhere a forget or a restart could not reach.
//!
//! This file is that marker: `used-invitations.json`, keyed by the invitation's
//! enrolment key (never by device key or name), counting uses, and pruned only
//! when the invitation itself has expired (after which it cannot verify
//! anyway). Nothing in device forget, rename, revoke or restore touches it.
//! Keying on the invitation, not on the joiner, is what makes a replay with a
//! NEW device key fail exactly like a replay with the old one.
//!
//! Fail closed: a file that exists but cannot be read or written refuses the
//! enrolment, because "I could not check whether this was used" is not "it was
//! not used".

use std::path::{Path, PathBuf};

use filament_cap::ephemeral::Reuse;
use serde_json::{json, Value};

pub(crate) const USED_INVITATIONS_FILE: &str = "used-invitations.json";

fn used_path() -> PathBuf {
    crate::platform::Paths::config_path(USED_INVITATIONS_FILE)
}

/// Why an enrolment was refused, in the words the joiner is sent (the same
/// wire reasons `burn_auth_key` refusals already use).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    AlreadyUsed,
    UseLimitReached,
    /// The store could not be read or written.
    Unverifiable,
}

impl Refusal {
    pub(crate) fn wire_reason(&self) -> &'static str {
        match self {
            Refusal::AlreadyUsed => "already used",
            Refusal::UseLimitReached => "use limit reached",
            Refusal::Unverifiable => "enrollment denied",
        }
    }
}

/// May this use be admitted, given `uses` already recorded? Pure.
pub(crate) fn admit(uses: u64, reuse: &Reuse) -> Result<(), Refusal> {
    match reuse {
        Reuse::Once if uses >= 1 => Err(Refusal::AlreadyUsed),
        Reuse::N(max) if uses >= u64::from(*max) => Err(Refusal::UseLimitReached),
        _ => Ok(()),
    }
}

fn load_at(path: &Path) -> Result<Vec<Value>, Refusal> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<Vec<Value>>(&raw).map_err(|_| Refusal::Unverifiable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(Refusal::Unverifiable),
    }
}

/// Count one use of the invitation `key_id` (hex enrolment public key) that
/// expires at `expires`, or refuse it. The use is written BEFORE the caller
/// admits anything, so a crash after this line can lose a use but never grant
/// an extra one.
pub(crate) fn record_use_at(
    path: &Path,
    key_id: &str,
    reuse: &Reuse,
    expires: u64,
    now: u64,
) -> Result<(), Refusal> {
    let mut entries = load_at(path)?;
    // Prune only what can no longer verify: an expired invitation.
    entries.retain(|e| e["expires"].as_u64().map_or(true, |x| x > now));
    let uses = entries
        .iter()
        .find(|e| e["keyId"].as_str() == Some(key_id))
        .and_then(|e| e["uses"].as_u64())
        .unwrap_or(0);
    admit(uses, reuse)?;
    entries.retain(|e| e["keyId"].as_str() != Some(key_id));
    entries.push(json!({
        "keyId": key_id,
        "uses": uses + 1,
        "expires": expires,
        "lastUsed": now,
    }));
    let body = serde_json::to_string_pretty(&entries).map_err(|_| Refusal::Unverifiable)?;
    crate::state_files::keep_backup(path);
    crate::platform::SecretFile::write_str(path, &body).map_err(|_| Refusal::Unverifiable)?;
    Ok(())
}

/// `record_use_at` on this config's store.
pub(crate) fn record_use(key_id: &str, reuse: &Reuse, expires: u64, now: u64) -> Result<(), Refusal> {
    record_use_at(&used_path(), key_id, reuse, expires, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tunlion-invburn-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(USED_INVITATIONS_FILE)
    }

    #[test]
    fn a_single_use_invitation_admits_once_and_survives_a_restart() {
        let p = scratch("once");
        assert_eq!(record_use_at(&p, "k1", &Reuse::Once, 1_000, 10), Ok(()));
        // A "restart" is a fresh read of the same file: nothing in memory.
        assert_eq!(record_use_at(&p, "k1", &Reuse::Once, 1_000, 11), Err(Refusal::AlreadyUsed));
        // Another invitation is unaffected.
        assert_eq!(record_use_at(&p, "k2", &Reuse::Once, 1_000, 12), Ok(()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn a_bounded_invitation_counts_to_its_limit() {
        let p = scratch("n");
        for t in 0..3 {
            assert_eq!(record_use_at(&p, "k", &Reuse::N(3), 1_000, t), Ok(()));
        }
        assert_eq!(record_use_at(&p, "k", &Reuse::N(3), 1_000, 9), Err(Refusal::UseLimitReached));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn only_expiry_clears_a_use() {
        let p = scratch("exp");
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 100, 10), Ok(()));
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 100, 99), Err(Refusal::AlreadyUsed));
        // Past expiry the entry is pruned; the invitation cannot verify by
        // then, which the enrolment path checks before it ever gets here.
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 100, 100), Ok(()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn an_unreadable_store_refuses_rather_than_admits() {
        let p = scratch("bad");
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 1_000, 1), Err(Refusal::Unverifiable));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn reusable_is_never_refused_by_count() {
        assert_eq!(admit(1_000_000, &Reuse::Reusable), Ok(()));
        assert_eq!(admit(0, &Reuse::Once), Ok(()));
        assert_eq!(admit(1, &Reuse::Once), Err(Refusal::AlreadyUsed));
    }
}
