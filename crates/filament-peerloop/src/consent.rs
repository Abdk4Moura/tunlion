//! CONSENT QUEUE: the pending-access record and its pure wording.
//!
//! A peer's refused action becomes a request the owner can approve or deny. The
//! record moves through `pending`, `approved`, `denied`, `expired` and
//! `withdrawn`; the store itself (where the file lives, how it is written) is a
//! host fact and stays behind [`HostServices`](crate::host::HostServices).
//!
//! What lives here is everything that has no opinion about the host: the record
//! shape on the wire, the reason a device is barred, and the sentence that
//! refusal prints. The CLI keeps the readers and writers, and its device-store
//! lookups, because those need the machine.
//!
//! NO item here calls back into the CLI, so the moved wording cannot drift from
//! the wording the CLI prints.

use serde::{Deserialize, Serialize};

/// One pending ask: a peer, the capability it wants, when it asked and where
/// the decision stands. The field names are the on-disk JSON keys, so moving
/// this struct must not change a single stored or printed byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: u64,
    pub peer: String,
    pub capability: String,
    pub timestamp: u64,
    /// `pending`, `approved`, `denied`, `expired` or `withdrawn`.
    pub status: String,
    pub granted_at: Option<u64>,
}

/// Status of a request withdrawn because its device can no longer be let in.
pub const REQUEST_WITHDRAWN: &str = "withdrawn";

/// Why a device can neither file an access request nor have one approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBar {
    /// Revoked here (`demote --to cut`), or its key is refused (forgotten).
    Revoked,
    /// The invitation that admitted it ended at this time.
    Expired(u64),
    /// No record of it any more (`devices forget`).
    Forgotten,
}

/// Why `requests approve` refuses a barred device, with the one command that
/// actually restores its access. Pure.
pub fn request_bar_refusal(id: u64, peer: &str, bar: RequestBar) -> String {
    let w = word(peer);
    match bar {
        RequestBar::Revoked => format!(
            "request {id} is from '{peer}', which is revoked here; approving cannot let it in. \
             To restore it, run:  tunlion promote {w}"
        ),
        RequestBar::Expired(at) => format!(
            "request {id} is from '{peer}', whose access expired {}; approving cannot extend it. \
             Only a fresh invitation admits it again:  tunlion add --for {w}",
            format_approval_expiry(at)
        ),
        RequestBar::Forgotten => format!(
            "request {id} is from '{peer}', which is no longer paired here (forgotten); approving cannot let it in. \
             Pair it again with `tunlion add`"
        ),
    }
}

/// A name as a command word the person can paste: unchanged when every
/// character is shell-safe, else quoted so it stays ONE argument with every
/// character intact (`Abdul's iPad` must not become `Abduls iPad`, which names
/// no device). POSIX shells get single quotes with `'\''` for a quote inside;
/// Windows (PowerShell, where the hints are pasted) gets single quotes with
/// the quote doubled. Pure. The one rule every hint that prints a device name
/// uses (re-exported as `cli::refusal::word`).
pub fn word(s: &str) -> String {
    if cfg!(windows) {
        word_powershell(s)
    } else {
        word_posix(s)
    }
}

fn shell_safe(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
}

/// POSIX sh quoting: `it's` -> `'it'\''s'`. Pure.
pub fn word_posix(s: &str) -> String {
    if shell_safe(s) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// PowerShell quoting: `it's` -> `'it''s'`. Pure.
pub fn word_powershell(s: &str) -> String {
    if shell_safe(s) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "''"))
    }
}

/// The absolute time an invitation or grant ends, as the CLI prints it. Pure.
/// `expires.to_string()` on an out-of-range timestamp, exactly as before.
pub fn format_approval_expiry(expires: u64) -> String {
    chrono::DateTime::from_timestamp(expires as i64, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires.to_string())
}

/// May the paired device `hub` introduce a new device into this store?
///
/// An introduction (`devices vouch`) stores a pairing secret this device never
/// agreed to by itself. That is only this device's owner's decision to make,
/// so it is accepted only from a device certified by THE SAME OWNER as this
/// one (`owner` is this device's owner key, from its keystore or its own
/// certificate). From anyone else (someone else's device, or a plain pairing)
/// it is refused: the way in for them is a code this device's person types.
/// Pure over the records.
pub fn intro_hub_is_same_owner(records: &[serde_json::Value], hub: &str, owner: Option<[u8; 32]>) -> bool {
    let Some(owner) = owner else { return false };
    let want = hex::encode(owner);
    records.iter().any(|r| {
        r["name"].as_str() == Some(hub)
            && r["deviceCert"]["userPub"].as_str().is_some_and(|u| u.eq_ignore_ascii_case(&want))
            && !r["certRevoked"].as_bool().unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// `devices vouch` cannot introduce a third party through someone else's
    /// device or a plain pairing, only through the same owner's own device.
    #[test]
    fn only_the_same_owners_device_may_introduce() {
        let owner = [7u8; 32];
        let cert = |u: [u8; 32]| json!({"userPub": hex::encode(u), "devicePub": hex::encode([1u8; 32])});
        let records = vec![
            json!({"name": "laptop", "deviceCert": cert(owner)}),
            json!({"name": "carol", "deviceCert": cert([8u8; 32])}),
            json!({"name": "plain"}),
            json!({"name": "cut", "deviceCert": cert(owner), "certRevoked": true}),
        ];
        assert!(intro_hub_is_same_owner(&records, "laptop", Some(owner)));
        assert!(!intro_hub_is_same_owner(&records, "carol", Some(owner)), "someone else's device");
        assert!(!intro_hub_is_same_owner(&records, "plain", Some(owner)), "a plain pairing");
        assert!(!intro_hub_is_same_owner(&records, "cut", Some(owner)), "a cut-off device");
        assert!(!intro_hub_is_same_owner(&records, "nobody", Some(owner)));
        // A device with no identity of its own accepts introductions from nobody.
        assert!(!intro_hub_is_same_owner(&records, "laptop", None));
    }

    use super::*;

    /// The three sentences name the one command that restores access, and an
    /// expired device is never told that approving could help.
    #[test]
    fn a_barred_device_is_named_for_why_and_given_the_restoring_command() {
        let r = request_bar_refusal(2, "guest2", RequestBar::Revoked);
        assert!(
            r.contains("revoked") && r.contains("tunlion promote guest2"),
            "{r}"
        );
        let e = request_bar_refusal(2, "guest2", RequestBar::Expired(10));
        assert!(
            e.contains("expired") && e.contains("tunlion add --for guest2"),
            "{e}"
        );
        assert!(
            !e.contains("approve"),
            "an expired device is never told to approve: {e}"
        );
        let f = request_bar_refusal(2, "guest2", RequestBar::Forgotten);
        assert!(f.contains("no longer paired") && f.contains("tunlion add"), "{f}");
    }

    /// A petname with a space or a quote becomes one shell word with every
    /// character kept; a plain name is unchanged.
    #[test]
    fn a_name_is_quoted_only_when_it_needs_to_be() {
        assert_eq!(word("alpha"), "alpha");
        assert_eq!(word("pop-os.mesh"), "pop-os.mesh");
        assert_eq!(word("two words"), "'two words'");
        assert_eq!(word_posix("Abdul's iPad"), r"'Abdul'\''s iPad'");
        assert_eq!(word_posix("it's"), r"'it'\''s'");
        assert_eq!(word_posix(""), "''");
        assert_eq!(word_posix("a\"b"), "'a\"b'");
        assert_eq!(word_posix("$(rm -rf ~)"), "'$(rm -rf ~)'");
        assert_eq!(word_powershell("Abdul's iPad"), "'Abdul''s iPad'");
        assert_eq!(word_powershell("two words"), "'two words'");
        assert_eq!(word_powershell("alpha"), "alpha");
    }

    /// The POSIX form is what a real `sh` reads back as the original name,
    /// as one argument.
    #[cfg(unix)]
    #[test]
    fn the_posix_word_round_trips_through_sh() {
        for name in ["Abdul's iPad", "it's", "two  spaces", "a\"b", "$HOME `x` \\ ;|&", "Zo\u{eb}'s", "''"] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s|' {}", word_posix(name)))
                .output()
                .expect("sh runs");
            assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{name}|"), "{name}");
        }
    }

    /// The bar refusal names a device with an apostrophe so it can be pasted.
    #[test]
    fn a_refusal_quotes_an_apostrophe_name_intact() {
        let r = request_bar_refusal(3, "Abdul's iPad", RequestBar::Revoked);
        assert!(r.contains(&format!("tunlion promote {}", word("Abdul's iPad"))), "{r}");
        assert!(!r.contains("Abduls"), "{r}");
    }

    /// The stored shape uses the same JSON keys the CLI always wrote.
    #[test]
    fn a_pending_request_keeps_its_stored_field_names() {
        let req = PendingRequest {
            id: 1,
            peer: "alpha".into(),
            capability: "shell".into(),
            timestamp: 10,
            status: "pending".into(),
            granted_at: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["peer"], "alpha");
        assert_eq!(v["capability"], "shell");
        assert_eq!(v["timestamp"], 10);
        assert_eq!(v["status"], "pending");
        assert!(v["granted_at"].is_null());
        let back: PendingRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, 1);
        assert_eq!(back.status, "pending");
    }
}
