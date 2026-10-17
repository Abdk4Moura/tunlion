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
    /// Revoked here (`devices revoke`), or its key is refused (forgotten).
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
             To restore it, run:  tunlion devices restore {w}"
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

/// A name as a command word: quoted when it contains whitespace or a quote, so
/// a petname copied into `tunlion devices restore ...` stays one argument.
/// Pure. Moved here from `cli::refusal` so the two sentences that quote a peer
/// use one rule.
pub fn word(s: &str) -> String {
    if s.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"') {
        format!("'{}'", s.replace('\'', ""))
    } else {
        s.to_string()
    }
}

/// The absolute time an invitation or grant ends, as the CLI prints it. Pure.
/// `expires.to_string()` on an out-of-range timestamp, exactly as before.
pub fn format_approval_expiry(expires: u64) -> String {
    chrono::DateTime::from_timestamp(expires as i64, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three sentences name the one command that restores access, and an
    /// expired device is never told that approving could help.
    #[test]
    fn a_barred_device_is_named_for_why_and_given_the_restoring_command() {
        let r = request_bar_refusal(2, "guest2", RequestBar::Revoked);
        assert!(
            r.contains("revoked") && r.contains("tunlion devices restore guest2"),
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

    /// A petname with a space or a quote becomes one shell word; a plain name
    /// is unchanged. The rule is the one the refusal sentences relied on.
    #[test]
    fn a_name_is_quoted_only_when_it_needs_to_be() {
        assert_eq!(word("alpha"), "alpha");
        assert_eq!(word("two words"), "'two words'");
        assert_eq!(word("it's"), "'its'");
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
