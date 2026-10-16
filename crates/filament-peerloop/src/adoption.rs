//! Adoption matching: which roster entry a link may bind to, and whether an
//! exhausted peer may be re-adopted.
//!
//! Both are pure over the peer id, the peer uid and the suppression set. The
//! distinction the first one carries is the whole point: a DIGEST (roster
//! reconciliation) must not undo an exhausted give-up, while real CONTACT is
//! evidence the peer is reachable and does.

use std::collections::HashSet;

/// Why a roster entry is being adopted. Contact is the safe default for new
/// call sites; Digest is reserved for roster reconciliation, which must not
/// undo an exhausted give-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptSource {
    Contact,
    Digest,
}

pub fn match_adoption_source(
    suppressed: &mut HashSet<String>,
    peer_id: &str,
    source: AdoptSource,
) -> bool {
    match source {
        AdoptSource::Contact => {
            suppressed.remove(peer_id);
            true
        }
        AdoptSource::Digest => !suppressed.contains(peer_id),
    }
}

pub fn active_binding_matches(
    binding: &(String, Option<String>),
    peer_id: &str,
    peer_uid: Option<&str>,
) -> bool {
    binding.0 == peer_id
        || binding
            .1
            .as_deref()
            .zip(peer_uid)
            .is_some_and(|(bound, candidate)| bound == candidate)
}

/// May this peer become the TRANSFER TARGET? (Filters gate targeting, never
/// answering: every peer still gets a polite link.) A `--to` filter must appear
/// in the candidate's name, case-insensitively; and two CLI peers of the same
/// role never transfer to each other (gate 7), compared on the first six chars of
/// our own uid. Pure over the filter, our uid and the candidate.
pub fn peer_targetable(
    to_filter: Option<&str>,
    my_uid: &str,
    name: &str,
    peer_uid: Option<&str>,
) -> bool {
    if let Some(filter) = to_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return false;
        }
    }
    if let (Some(pu), Some(my_role)) = (peer_uid, my_uid.get(..6)) {
        if pu.starts_with(my_role) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_receive_binding_rejects_unrelated_paired_peer_but_allows_rejoin() {
        let binding = (
            "sender-old-sid".to_string(),
            Some("sender-install".to_string()),
        );

        assert!(active_binding_matches(
            &binding,
            "sender-old-sid",
            Some("sender-install")
        ));
        assert!(active_binding_matches(
            &binding,
            "sender-new-sid",
            Some("sender-install")
        ));
        assert!(!active_binding_matches(
            &binding,
            "unrelated-paired-sid",
            Some("unrelated-install")
        ));
    }

    #[test]
    fn a_to_filter_gates_targeting_but_an_unfiltered_peer_is_targetable() {
        // The filter matches the candidate's name, case-insensitively.
        assert!(peer_targetable(Some("lap"), "zz-me", "my-laptop", None));
        assert!(!peer_targetable(Some("lap"), "zz-me", "the-tower", None));
        // No filter: every peer is targetable.
        assert!(peer_targetable(None, "zz-me", "the-tower", None));
    }

    #[test]
    fn two_cli_peers_of_the_same_role_never_transfer_to_each_other() {
        // Same first six uid chars = same role: never a target (gate 7).
        assert!(!peer_targetable(
            None,
            "aaaaaa1-self",
            "peer",
            Some("aaaaaa2-peer")
        ));
        // Different role: targetable.
        assert!(peer_targetable(
            None,
            "aaaaaa1-self",
            "peer",
            Some("bbbbbb2-peer")
        ));
        // A uid too short to carry a role prefix is not rejected.
        assert!(peer_targetable(None, "zz", "peer", Some("aaaaaa2-peer")));
    }
}
