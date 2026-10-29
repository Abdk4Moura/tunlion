//! The armed set: which auth keys are outstanding and must keep the daemon
//! subscribed to the enrollment room.
//!
//! #205/#211 taught the hard way that this must be a FILE, not process memory.
//! In memory it lived in the daemon alone, so the only way a mint could tell
//! the daemon "an invitation is outstanding" was IPC, and IPC is the one thing
//! with no portable form (a unix socket on unix, nothing on Windows, a bind
//! race everywhere). File-backed, the mint writes `armed.json` directly and the
//! daemon's per-tick arm-gate reads it; no IPC, no platform branch, no race,
//! and a daemon restart no longer silently disarms every outstanding
//! invitation.
//!
//! The file holds only `key_id` (the enroll public half, hex) and `expires`
//! (absolute unix seconds), both non-secret. Enrollment still requires the
//! signed invitation, so a burned key lingering until expiry is harmless.
//!
//! A MULTI-USE INVITATION IS NOT CONSUMED HERE, and needs no change to this
//! store. There is no use count and no "used" flag in an entry: `is_armed`
//! drops an entry only when `expires` passes, and no code path calls `disarm`
//! on a successful enrolment. So `Reuse::N(n)` and `Reuse::Reusable` stay
//! subscribed to the enrollment channel for the whole TTL, which is exactly
//! what a second or third box needs. The durable count in
//! `used-invitations.json` is what refuses the claim past its limit; this file
//! only answers "may the daemon listen at all". Keeping an exhausted key armed
//! until expiry is harmless for the same reason a burned one is: the signed
//! invitation and the use count still gate admission.
//!
//! WITHDRAWAL (`tunlion add --withdraw`) is not a change to this file either.
//! It is recorded in `used-invitations.json`, under that file's lock, beside
//! the use count it overrides, because that is the file every claim reads at
//! admission. Hiding an entry here would hide it from `devices` without
//! refusing anything; dropping it here would stop the receiver listening, so a
//! late claimer would wait on a silent room instead of hearing "withdrawn".
//! The entry stays until expiry, and [`outstanding`] leaves it out.
//!
//! Entries minted by 0.9.2 and later also carry the ceiling, the reuse limit
//! and the mint time, for the listing only.

use std::path::PathBuf;

use serde_json::{Value, json};

fn armed_path() -> PathBuf {
    crate::platform::Paths::config_path("armed.json")
}

struct ArmedEntry {
    key_id: String,
    expires: u64,
    /// The name the owner gave the invitee (`add <name> --out`), if any. Not
    /// secret, not signed: it decides only what THIS store calls the device
    /// that enrols with this key.
    name: Option<String>,
    /// What the owner invited: `person` or `device` (`add --for ...`). Not
    /// secret, not signed: like `name`, it decides only how THIS store files
    /// the device that enrols with this key. The signed ceiling still bounds
    /// what it may do.
    kind: Option<String>,
    /// What the owner saw when minting, kept so `devices` can list the
    /// invitation honestly while it is outstanding: the ceiling it carries,
    /// how many claims it admits, and when it was made. Not secret, not
    /// signed, and never consulted for admission: the signed invitation and
    /// the durable use file decide that. Absent on entries minted before
    /// 0.9.2, which the listing shows as unknown rather than guesses.
    allow: Option<Vec<String>>,
    reuse: Option<Value>,
    created: Option<u64>,
}

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

/// How many claims an invitation admits: `Some(n)`, or `None` for
/// `--reuse forever`. `Err` when the entry predates the field.
fn reuse_total(v: Option<&Value>) -> Result<Option<u64>, ()> {
    match v {
        Some(Value::String(s)) if s == "once" => Ok(Some(1)),
        Some(Value::String(s)) if s == "forever" => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or(()),
        _ => Err(()),
    }
}

fn load() -> Vec<ArmedEntry> {
    let raw = match std::fs::read_to_string(armed_path()) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else { return Vec::new() };
    let arr = v.as_array().cloned().unwrap_or_default();
    arr.iter()
        .filter_map(|e| {
            let key_id = e["key_id"].as_str()?.to_string();
            let expires = e["expires"].as_u64()?;
            let name = e["name"].as_str().map(str::to_string);
            let kind = e["kind"].as_str().map(str::to_string);
            let allow = e["allow"].as_array().map(|a| {
                a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect()
            });
            let reuse = e.get("reuse").cloned().filter(|v| !v.is_null());
            let created = e["created"].as_u64();
            Some(ArmedEntry { key_id, expires, name, kind, allow, reuse, created })
        })
        .collect()
}

fn save(entries: &[ArmedEntry]) {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let mut v = json!({ "key_id": e.key_id, "expires": e.expires });
            if let Some(n) = &e.name {
                v["name"] = json!(n);
            }
            if let Some(k) = &e.kind {
                v["kind"] = json!(k);
            }
            if let Some(a) = &e.allow {
                v["allow"] = json!(a);
            }
            if let Some(r) = &e.reuse {
                v["reuse"] = r.clone();
            }
            if let Some(c) = e.created {
                v["created"] = json!(c);
            }
            v
        })
        .collect();
    let Ok(body) = serde_json::to_string_pretty(&arr) else { return };
    // SecretFile::write_str is owner-only (0600) and atomic on POSIX, so the
    // daemon never reads a half-written array.
    let _ = crate::platform::SecretFile::write_str(&armed_path(), &body);
}

/// Record that an auth key is outstanding until `expires_at` (absolute unix
/// seconds). Dedupes by key_id. The mint writes this directly; the daemon's
/// per-tick arm-gate reads it.
pub fn arm(key_id: String, expires_at: u64, meta: ArmMeta) {
    let mut entries = load();
    entries.retain(|e| e.key_id != key_id);
    entries.push(ArmedEntry {
        key_id,
        expires: expires_at,
        name: meta.name,
        kind: meta.kind,
        allow: Some(meta.allow),
        reuse: meta.reuse.as_ref().map(reuse_to_json),
        created: Some(meta.created),
    });
    save(&entries);
}

/// An invitation that can still be claimed: unexpired, not withdrawn, and
/// with claims left. What `tunlion devices` lists under INVITATIONS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outstanding {
    /// The enrolment public key, hex. Not secret: it is the public half, and
    /// a claim still needs the signed invitation and the private half.
    pub key_id: String,
    pub name: Option<String>,
    pub kind: Option<String>,
    /// The ceiling it carries, when the mint recorded it.
    pub allow: Option<Vec<String>>,
    /// Claims admitted so far (from the durable use file).
    pub uses: u64,
    /// `Some(Some(n))` admits n claims, `Some(None)` any number until it
    /// expires, `None` unknown (minted before 0.9.2 recorded it).
    pub total: Option<Option<u64>>,
    pub expires: u64,
    pub created: Option<u64>,
}

impl Outstanding {
    /// The short id the owner can name it by: the first 12 hex digits of
    /// the public key, unique in practice and never secret.
    pub fn id(&self) -> &str {
        &self.key_id[..self.key_id.len().min(12)]
    }

    /// The name shown and matched, `(unnamed)` when the mint gave none.
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("({})", self.id()))
    }

    /// "3 of 20 left", "any number, until it expires", "1 used".
    pub fn uses_phrase(&self) -> String {
        match self.total {
            Some(Some(t)) => format!("{} of {t} left", t.saturating_sub(self.uses)),
            Some(None) if self.uses == 0 => "any number, not used yet".to_string(),
            Some(None) => format!("any number, {} used", self.uses),
            None => format!("{} used", self.uses),
        }
    }

    pub fn to_json(&self) -> Value {
        let (max, left) = match self.total {
            Some(Some(t)) => (json!(t), json!(t.saturating_sub(self.uses))),
            Some(None) => (json!("forever"), Value::Null),
            None => (Value::Null, Value::Null),
        };
        json!({
            "id": self.id(),
            "name": self.name,
            "kind": self.kind,
            "allow": self.allow,
            "uses": self.uses,
            "maxUses": max,
            "usesLeft": left,
            "expires": self.expires,
            "created": self.created,
        })
    }
}

/// Pure core of [`outstanding`]: join the armed entries with the durable
/// ledger and keep what can still be claimed at `now`.
fn outstanding_from(
    entries: &[ArmedEntry],
    ledger: &[filament_peerloop::recv::store::InvitationLedgerEntry],
    now: u64,
) -> Vec<Outstanding> {
    let mut out: Vec<Outstanding> = entries
        .iter()
        .filter(|e| e.expires > now)
        .filter_map(|e| {
            let line = ledger.iter().find(|l| l.key_id == e.key_id);
            if line.is_some_and(|l| l.withdrawn) {
                return None;
            }
            let uses = line.map_or(0, |l| l.uses);
            let total = reuse_total(e.reuse.as_ref()).ok();
            if let Some(Some(t)) = total {
                if uses >= t {
                    return None; // used up: nothing left to claim
                }
            }
            Some(Outstanding {
                key_id: e.key_id.clone(),
                name: e.name.clone().filter(|n| !n.trim().is_empty()),
                kind: e.kind.clone(),
                allow: e.allow.clone(),
                uses,
                total,
                expires: e.expires,
                created: e.created,
            })
        })
        .collect();
    out.sort_by(|a, b| a.created.cmp(&b.created).then(a.expires.cmp(&b.expires)));
    out
}

/// Every invitation that can still be claimed on this device, oldest first.
/// Used-up, withdrawn and expired ones are left out. Expired entries are
/// pruned from the file by the daemon's arm-gate on its next tick.
///
/// A used-up or withdrawn entry stays in `armed.json` until its expiry on
/// purpose: it keeps the receiver listening, so a late claimer is told
/// "withdrawn" or "use limit reached" instead of waiting on a silent room.
pub fn outstanding() -> Vec<Outstanding> {
    let now = crate::identity::now_secs();
    let ledger = crate::devices_store::store().invitation_ledger(now);
    outstanding_from(&load(), &ledger, now)
}

/// Which outstanding invitations a selector names: every one with that
/// name, or the one whose id starts with it (6 hex digits at least).
pub fn select<'a>(all: &'a [Outstanding], selector: &str) -> Vec<&'a Outstanding> {
    let sel = selector.trim();
    if sel.is_empty() {
        return Vec::new();
    }
    let by_name: Vec<_> = all.iter().filter(|o| o.name.as_deref() == Some(sel)).collect();
    if !by_name.is_empty() {
        return by_name;
    }
    let hex = sel.trim_start_matches('(').trim_end_matches(')').to_ascii_lowercase();
    if hex.len() >= 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return all.iter().filter(|o| o.key_id.starts_with(&hex)).collect();
    }
    Vec::new()
}

/// Withdraw one invitation: durable (the use file, under its lock) and
/// effective at once for a running receiver, which reads that file on every
/// claim. The armed entry is kept until expiry (see [`outstanding`]).
pub fn withdraw(o: &Outstanding) -> anyhow::Result<()> {
    crate::devices_store::store()
        .withdraw_invitation(&o.key_id, o.expires, crate::identity::now_secs())
        .map_err(|r| {
            anyhow::anyhow!(
                "could not record the withdrawal of the invitation for {} ({r:?}): it is NOT withdrawn. Check that {} is readable.",
                o.label(),
                crate::platform::Paths::config_path(crate::invite_burn::USED_INVITATIONS_FILE).display()
            )
        })
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
    let mut entries = load();
    entries.retain(|e| e.key_id != key_id);
    save(&entries);
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
mod outstanding_tests {
    use super::*;
    use filament_cap::ephemeral::Reuse;
    use filament_peerloop::recv::store::InvitationLedgerEntry;

    fn entry(key: &str, name: &str, reuse: Option<Value>, expires: u64) -> ArmedEntry {
        ArmedEntry {
            key_id: key.repeat(32),
            expires,
            name: Some(name.to_string()),
            kind: Some("device".into()),
            allow: Some(vec!["transfer".into()]),
            reuse,
            created: Some(10),
        }
    }

    fn line(key: &str, uses: u64, withdrawn: bool) -> InvitationLedgerEntry {
        InvitationLedgerEntry { key_id: key.repeat(32), uses, expires: 1_000, withdrawn }
    }

    #[test]
    fn the_listing_hides_used_up_withdrawn_and_expired_invitations() {
        let entries = vec![
            entry("aa", "fresh", Some(json!(20)), 1_000),
            entry("bb", "spent", Some(json!("once")), 1_000),
            entry("cc", "pulled", Some(json!("forever")), 1_000),
            entry("dd", "old", Some(json!(5)), 50),
            entry("ee", "legacy", None, 1_000),
            entry("ff", "forever", Some(json!("forever")), 1_000),
        ];
        let ledger = vec![
            line("aa", 3, false),
            line("bb", 1, false),
            line("cc", 1, true),
            line("ee", 2, false),
            line("ff", 7, false),
        ];
        let out = outstanding_from(&entries, &ledger, 100);
        let names: Vec<_> = out.iter().map(|o| o.label()).collect();
        assert_eq!(names, ["fresh", "legacy", "forever"]);
        assert_eq!(out[0].uses_phrase(), "17 of 20 left");
        assert_eq!(out[0].to_json()["usesLeft"], json!(17));
        assert_eq!(out[1].uses_phrase(), "2 used", "a pre-0.9.2 entry does not guess its limit");
        assert_eq!(out[1].to_json()["maxUses"], Value::Null);
        assert_eq!(out[2].uses_phrase(), "any number, 7 used");
        assert_eq!(out[2].to_json()["maxUses"], json!("forever"));
    }

    #[test]
    fn a_selector_is_a_name_or_an_id_prefix() {
        let entries = vec![
            entry("ab", "ci", Some(json!(20)), 1_000),
            entry("cd", "ci", Some(json!(20)), 1_000),
            entry("ef", "laptop", Some(json!("once")), 1_000),
        ];
        let out = outstanding_from(&entries, &[], 100);
        assert_eq!(select(&out, "ci").len(), 2, "a name names every invitation made for it");
        assert_eq!(select(&out, "laptop").len(), 1);
        assert_eq!(select(&out, &"cd".repeat(4)).len(), 1);
        assert_eq!(select(&out, &format!("({})", "ef".repeat(3))).len(), 1);
        assert!(select(&out, "abab").is_empty(), "too short to be an id");
        assert!(select(&out, "nobody").is_empty());
        assert!(select(&out, "").is_empty());
    }

    #[test]
    fn withdrawing_hides_it_and_the_store_refuses_its_claims() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!("fil-armed-withdraw-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
        let now = crate::identity::now_secs();
        let key = "a1".repeat(32);
        arm(
            key.clone(),
            now + 600,
            ArmMeta {
                name: Some("ci".into()),
                kind: Some("device".into()),
                allow: vec!["transfer".into()],
                reuse: Some(Reuse::N(20)),
                created: now,
            },
        );
        assert_eq!(
            crate::invite_burn::record_use(&key, &Reuse::N(20), now + 600, now),
            Ok(())
        );
        let listed = outstanding();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].uses_phrase(), "19 of 20 left");
        withdraw(&listed[0]).unwrap();
        assert!(outstanding().is_empty(), "a withdrawn invitation is not listed");
        assert_eq!(
            crate::invite_burn::record_use(&key, &Reuse::N(20), now + 600, now + 1),
            Err(crate::invite_burn::Refusal::Withdrawn),
            "and its key is refused at claim time, not only hidden"
        );
        // It keeps the receiver listening so a late claimer hears why.
        assert!(is_armed());
        unsafe { std::env::remove_var("TUNLION_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
