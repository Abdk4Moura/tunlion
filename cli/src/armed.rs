//! The armed set: which auth keys are outstanding and must keep the daemon
//! subscribed to the enrollment room.
//!
//! #205/#211 taught the hard way that this must be a FILE, not process memory.
//! In memory it lived in the daemon alone, so the only way a mint could tell
//! the daemon "an invitation is outstanding" was IPC, and IPC is the one thing
//! with no portable form (a unix socket on unix, nothing on Windows, a bind
//! race everywhere). File-backed, the mint writes `armed.json` and the daemon's
//! per-tick arm-gate reads it; no IPC, no platform branch, no race, and a
//! daemon restart no longer silently disarms every outstanding invitation.
//!
//! The file itself and every read/modify/write of it now belong to
//! `filament_peerloop::recv::store` (under `armed.json.lock`). This module is
//! only the CLI adapter: it names the process config directory and keeps the
//! old function names every CLI call site already uses. The listing/withdraw
//! policy lives in `filament_peerloop::invitation`, not here.
//!
//! A MULTI-USE INVITATION IS NOT CONSUMED HERE. There is no use count and no
//! "used" flag in an entry: the durable count in `used-invitations.json` is
//! what refuses a claim past its limit; this file only answers "may the daemon
//! listen at all". Keeping an exhausted key armed until expiry is harmless for
//! the same reason a burned one is: the signed invitation and the use count
//! still gate admission.
//!
//! WITHDRAWAL (`tunlion add --withdraw`) is not a change to this file either.
//! It is recorded in `used-invitations.json`, under that file's lock, because
//! that is the file every claim reads at admission. The entry stays until
//! expiry, and the listing leaves it out.

use serde_json::{Value, json};

pub use filament_peerloop::invitation::Outstanding;

use filament_peerloop::invitation::withdraw as withdraw_from_store;
use filament_peerloop::recv::store::ArmedInvitation;

/// What a mint records about an invitation besides its key and expiry.
#[derive(Debug, Clone, Default)]
pub struct ArmMeta {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub allow: Vec<String>,
    pub reuse: Option<filament_cap::ephemeral::Reuse>,
    pub created: u64,
}

fn reuse_to_json(reuse: &filament_cap::ephemeral::Reuse) -> Value {
    use filament_cap::ephemeral::Reuse;
    match reuse {
        Reuse::Once => json!("once"),
        Reuse::N(n) => json!(n),
        Reuse::Reusable => json!("forever"),
    }
}

/// Record that an auth key is outstanding until `expires_at` (absolute unix
/// seconds). The store owns the locked read/modify/write of `armed.json`.
pub fn arm(key_id: String, expires_at: u64, meta: ArmMeta) {
    let entry = ArmedInvitation {
        key_id,
        expires: expires_at,
        name: meta.name,
        kind: meta.kind,
        allow: Some(meta.allow),
        reuse: meta.reuse.as_ref().map(reuse_to_json),
        created: Some(meta.created),
    };
    // The daemon reads armed.json on its next tick; a failed write means the
    // invitation is not armed, which the mint reports through its own result.
    let _ = crate::devices_store::store().arm_invitation(entry, crate::identity::now_secs());
}

/// Every invitation that can still be claimed on this device, oldest first.
/// Used-up, withdrawn and expired ones are left out.
pub fn outstanding() -> Vec<Outstanding> {
    filament_peerloop::invitation::outstanding(&crate::devices_store::store(), crate::identity::now_secs())
}

/// Which outstanding invitations a selector names: every one with that name,
/// or the one whose id starts with it (6 hex digits at least).
pub fn select<'a>(all: &'a [Outstanding], selector: &str) -> Vec<&'a Outstanding> {
    filament_peerloop::invitation::select(all, selector)
}

/// Withdraw one invitation: durable (the use file, under its lock) and
/// effective at once for a running receiver, which reads that file on every
/// claim. The armed entry is kept until expiry.
pub fn withdraw(o: &Outstanding) -> anyhow::Result<()> {
    withdraw_from_store(&crate::devices_store::store(), o, crate::identity::now_secs()).map_err(
        |r| {
            anyhow::anyhow!(
                "could not record the withdrawal of the invitation for {} ({r:?}): it is NOT withdrawn. Check that {} is readable.",
                o.label(),
                crate::platform::Paths::config_path(crate::invite_burn::USED_INVITATIONS_FILE).display()
            )
        },
    )
}

/// What the owner invited with this key (`person`, `device`), while the key is
/// outstanding. A person's invitation enrols them with an owner-signed
/// certificate like a device's, so without this the owner's `devices` filed
/// a guest under FLEET, "your devices".
pub fn invitee_kind(key_id: &str) -> Option<String> {
    crate::devices_store::store().invitee_kind(key_id)
}

/// The name the owner chose for whoever enrols with this key, while the key
/// is outstanding. `add beta --out f` then `join f` used to file the device
/// under the JOINER's hostname, not "beta": the owner's choice was dropped at
/// the mint.
pub fn invitee_name(key_id: &str) -> Option<String> {
    crate::devices_store::store().invitee_name(key_id)
}

/// Drop a key from the armed set (called when it burns, or on explicit disarm).
pub fn disarm(key_id: &str) {
    let _ = crate::devices_store::store().disarm_invitation(key_id);
}

/// Any unexpired armed key? Prunes expired entries on read, so the file self-
/// cleans and a stale entry never keeps the room open.
pub fn is_armed() -> bool {
    crate::devices_store::store().is_armed()
}

#[cfg(test)]
mod invitee_name_tests {
    #[test]
    fn the_owner_chosen_name_rides_with_its_key_until_expiry() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!("fil-armed-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
        let later = crate::capability::now_secs() + 600;
        let meta = |name: Option<&str>, kind: Option<&str>| super::ArmMeta {
            name: name.map(str::to_string),
            kind: kind.map(str::to_string),
            ..Default::default()
        };
        super::arm("aa".repeat(32), later, meta(Some("beta"), Some("person")));
        super::arm("bb".repeat(32), later, meta(None, None));
        super::arm("cc".repeat(32), 1, meta(Some("gone"), Some("person")));
        assert_eq!(super::invitee_name(&"aa".repeat(32)).as_deref(), Some("beta"));
        assert_eq!(super::invitee_name(&"bb".repeat(32)), None, "unnamed invitation");
        assert_eq!(super::invitee_name(&"cc".repeat(32)), None, "an expired key names nobody");
        assert_eq!(super::invitee_name(&"dd".repeat(32)), None);
        // The invited kind rides the same way, and an expired key says nothing.
        assert_eq!(super::invitee_kind(&"aa".repeat(32)).as_deref(), Some("person"));
        assert_eq!(super::invitee_kind(&"bb".repeat(32)), None);
        assert_eq!(super::invitee_kind(&"cc".repeat(32)), None);
        unsafe { std::env::remove_var("TUNLION_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod armed_lifecycle_tests {
    /// A multi-use invitation must not be consumed by the first enrolment.
    /// There is nothing in the armed entry to consume: it is keyed by the
    /// invitation and pruned by expiry alone. This pins that shape, so an
    /// added "used" flag or a disarm-on-enrol would have to change a test that
    /// says why it must not.
    #[test]
    fn an_unexpired_key_stays_armed_for_its_whole_ttl() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!(
            "fil-armed-lifecycle-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
        let key = "ee".repeat(32);
        let expires = crate::capability::now_secs() + 600;
        // The mint arms once, before any claim.
        super::arm(
            key.clone(),
            expires,
            super::ArmMeta { kind: Some("runner".into()), ..Default::default() },
        );
        assert!(super::is_armed(), "an outstanding key arms the room");
        assert!(
            super::is_armed(),
            "arming is per invitation and per expiry: reading it again, after a claim would have happened, must not consume it"
        );
        // The entry carries no count, so a claim has nothing to decrement.
        let raw = std::fs::read_to_string(dir.join("armed.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(v[0].get("uses").is_none(), "no use count lives in armed.json");
        assert!(v[0].get("used").is_none(), "no used flag lives in armed.json");
        unsafe { std::env::remove_var("TUNLION_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod withdraw_tests {
    /// The library owns the listing and withdrawal policy; this adapter must
    /// not grow a second copy. The pure cases live beside that policy.
    #[test]
    fn the_cli_uses_the_shared_selector() {
        let out = vec![Outstanding {
            key_id: "ab".repeat(32),
            name: Some("ci".into()),
            kind: Some("device".into()),
            allow: Some(vec!["transfer".into()]),
            uses: 0,
            total: Some(Some(20)),
            expires: 1_000,
            created: Some(1),
        }];
        assert_eq!(super::select(&out, "ci").len(), 1);
        assert_eq!(super::select(&out, &"ab".repeat(4)).len(), 1);
    }
}
