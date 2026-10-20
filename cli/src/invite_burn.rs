//! Used invitations, on disk, apart from any device record.
//!
//! The implementation moved to `filament_peerloop::recv::store` with the
//! explicit-root store. This module keeps the old names so every CLI caller
//! and test resolves unchanged; there is no second use-count policy.

pub(crate) use filament_peerloop::recv::store::InvitationRefusal as Refusal;
pub(crate) use filament_peerloop::recv::store::USED_INVITATIONS_FILE;
pub(crate) use filament_peerloop::recv::store::admit_invitation_use as admit;
pub(crate) use filament_peerloop::recv::store::record_invitation_use_at as record_use_at;

use filament_cap::ephemeral::Reuse;

/// `record_use_at` on this config's store.
pub(crate) fn record_use(
    key_id: &str,
    reuse: &Reuse,
    expires: u64,
    now: u64,
) -> Result<(), Refusal> {
    crate::devices_store::store().record_invitation_use(key_id, reuse, expires, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tunlion-invburn-{tag}-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join(USED_INVITATIONS_FILE)
    }

    #[test]
    fn a_single_use_invitation_admits_once_and_survives_a_restart() {
        let p = scratch("once");
        assert_eq!(record_use_at(&p, "k1", &Reuse::Once, 1_000, 10), Ok(()));
        // A "restart" is a fresh read of the same file: nothing in memory.
        assert_eq!(
            record_use_at(&p, "k1", &Reuse::Once, 1_000, 11),
            Err(Refusal::AlreadyUsed)
        );
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
        assert_eq!(
            record_use_at(&p, "k", &Reuse::N(3), 1_000, 9),
            Err(Refusal::UseLimitReached)
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn only_expiry_clears_a_use() {
        let p = scratch("exp");
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 100, 10), Ok(()));
        assert_eq!(
            record_use_at(&p, "k", &Reuse::Once, 100, 99),
            Err(Refusal::AlreadyUsed)
        );
        // Past expiry the entry is pruned; the invitation cannot verify by
        // then, which the enrolment path checks before it ever gets here.
        assert_eq!(record_use_at(&p, "k", &Reuse::Once, 100, 100), Ok(()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn an_unreadable_store_refuses_rather_than_admits() {
        let p = scratch("bad");
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(
            record_use_at(&p, "k", &Reuse::Once, 1_000, 1),
            Err(Refusal::Unverifiable)
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn reusable_is_never_refused_by_count() {
        assert_eq!(admit(1_000_000, &Reuse::Reusable), Ok(()));
        assert_eq!(admit(0, &Reuse::Once), Ok(()));
        assert_eq!(admit(1, &Reuse::Once), Err(Refusal::AlreadyUsed));
    }
}
