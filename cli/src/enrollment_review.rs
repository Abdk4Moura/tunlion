//! Rendering only: shared enrollment facts never become effective-access claims.
use filament_id::enrollment::{EnrollmentReview, Relationship};

pub(crate) fn lines(review: &EnrollmentReview) -> Vec<String> {
    let relationship = match review.relationship {
        Relationship::OrdinaryPair => "ordinary pairing (no fleet membership)",
        Relationship::OwnDevice => "your device (requests fleet membership)",
        Relationship::OtherPerson => "someone else's device (no fleet membership)",
        Relationship::TemporaryWorker => "temporary worker (not a lasting fleet member)",
        Relationship::Unknown => "relationship not stated by this invitation",
    };
    let mut lines = vec![format!("  Relationship: {relationship}")];
    if review.relationship.requests_fleet_membership() {
        lines.push("  Certified siblings discover each other and can send files into their inboxes by default.".into());
    }
    lines.push(format!("  Requested permissions: {}", if review.requested_capabilities.is_empty() {
        "none".into()
    } else {
        review.requested_capabilities.join(", ")
    }));
    if review.requests("mount") {
        lines.push("  Folder access is included in this request, subject to the receiver's share bounds.".into());
    }
    if review.requests("shell") {
        lines.push("  Terminal access is included: OWNER-EQUIVALENT command execution as the serving user.".into());
    }
    lines.push("  This reviews the request; access is not confirmed until enrollment and the receiver's checks succeed.".into());
    lines
}

pub(crate) fn show(relationship: Relationship, capabilities: &[String]) {
    let review = EnrollmentReview::new(relationship, capabilities);
    for line in lines(&review) { crate::ui::say(&line); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_and_code_reviews_share_the_same_facts() {
        let requested = vec!["transfer".into(), "mount".into()];
        let review = EnrollmentReview::new(Relationship::OwnDevice, &requested);
        let text = lines(&review).join("\n");
        assert!(text.contains("Folder access is included"));
        assert!(!text.contains("Terminal access is included"));
        assert!(text.contains("access is not confirmed"));
        assert!(!text.contains("will not get access to folders"));
    }

    #[test]
    fn workers_and_external_people_are_never_described_as_fleet_members() {
        for relationship in [Relationship::TemporaryWorker, Relationship::OtherPerson] {
            let text = lines(&EnrollmentReview::new(relationship, &["transfer".into()])).join("\n");
            assert!(!text.contains("requests fleet membership"));
            assert!(!text.contains("Certified siblings"));
        }
    }

    #[test]
    fn terminal_authority_is_named_only_when_requested() {
        let review = EnrollmentReview::new(Relationship::OtherPerson, &["shell".into()]);
        assert!(lines(&review).join("\n").contains("OWNER-EQUIVALENT"));
    }
}
