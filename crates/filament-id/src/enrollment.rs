//! Client-independent review of an enrollment request, not an authorization
//! decision. Code, file and nearby are carriers, never relationship kinds.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relationship {
    OrdinaryPair,
    OwnDevice,
    OtherPerson,
    TemporaryWorker,
}

impl Relationship {
    /// Describes the intended relationship, not a completed certificate exchange.
    pub fn requests_fleet_membership(self) -> bool {
        self == Self::OwnDevice
    }
}

/// Exact requested maximum authority. A client must not present this as
/// delivered, granted, or effective access. The enrollment and capability gates
/// remain authoritative and may refuse the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentReview {
    pub relationship: Relationship,
    pub requested_capabilities: Vec<String>,
}

impl EnrollmentReview {
    pub fn new(relationship: Relationship, capabilities: &[String]) -> Self {
        let mut requested_capabilities = capabilities.to_vec();
        requested_capabilities.sort();
        requested_capabilities.dedup();
        Self { relationship, requested_capabilities }
    }

    /// Unknown or resource-scoped capabilities remain visible verbatim; a
    /// reviewer must never silently lose authority it does not understand.
    pub fn requests(&self, capability: &str) -> bool {
        self.requested_capabilities.iter().any(|c| c == capability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_own_device_requests_fleet_membership() {
        assert!(Relationship::OwnDevice.requests_fleet_membership());
        for relationship in [Relationship::OrdinaryPair, Relationship::OtherPerson, Relationship::TemporaryWorker] {
            assert!(!relationship.requests_fleet_membership());
        }
    }

    #[test]
    fn review_never_invents_or_hides_requested_authority() {
        let caps = vec!["transfer".into(), "route:10.2.0.0/16".into(), "future-capability".into(), "transfer".into()];
        let review = EnrollmentReview::new(Relationship::OwnDevice, &caps);
        assert_eq!(review.requested_capabilities.len(), 3);
        for cap in &caps { assert!(review.requests(cap)); }
        assert!(!review.requests("mount"));
        assert!(!review.requests("shell"));
        assert!(!review.requests("route"));
        assert_eq!(caps.len(), 4);
    }

    #[test]
    fn own_device_review_does_not_imply_folder_or_terminal_authority() {
        let review = EnrollmentReview::new(Relationship::OwnDevice, &["transfer".into()]);
        assert!(review.requests("transfer"));
        assert!(!review.requests("mount"));
        assert!(!review.requests("shell"));
    }
}
