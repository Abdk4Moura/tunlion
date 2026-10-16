//! The petname rule: which name a device lookup joins on.
//!
//! LOAD-BEARING. A device is identified by the petname a link PROVED it reaches
//! (`Link::verified_name`, the devices.json key), or, before proof, by the
//! petname whose pair secret the link carries (`Link::expected_secret`). A lookup
//! joins on THAT, never on `Link::name`, the broadcast display string a peer
//! announces. The two differ in the normal case (petname `x`, display `user@x`),
//! and joining on the display name is the shape of the ~95s re-dial cycle: a
//! healthy direct link named by petname was never recognised, a fresh establish
//! replaced it every tick, and the peer ignored the new offers.
//!
//! `Link` stays in the CLI: it also carries a live transport, a WebRTC peer and
//! an identity binding, and reads this rule out through the two fields below. The
//! blanket impl in the CLI is the whole adapter, so `link_petname(&link)` keeps
//! working at every call site while the RULE lives here.

/// The two names the petname rule reads, so it can be stated without `Link`.
pub trait LinkPetname {
    /// The devices.json petname this link PROVED as (`Link::verified_name`).
    /// `None` until a verified `pair-proof` (or a direct link born identity
    /// bound).
    fn proven_petname(&self) -> Option<&str>;
    /// The petname whose pair secret this link carries, not yet proven
    /// (`Link::expected_secret`). This is a hypothesis and must not be written
    /// into a device record.
    fn dialed_petname(&self) -> Option<&str>;
}

/// The device petname a link belongs to: the one it proved as, else the one
/// whose pair secret it carries. `None` for an unproven, secretless link.
pub fn link_petname<L: LinkPetname>(l: &L) -> Option<&str> {
    l.proven_petname().or_else(|| l.dialed_petname())
}
