//! LINK MANAGER: the one place that decides which link a piece of work rides,
//! when a link is worth keeping warm, when a direct standby has earned the
//! cutover, and which correction a stalled link gets.
//!
//! Discipline (the same split as `resilience.rs`): every function here is PURE.
//! It takes an observation of the links (route, liveness, idleness, the identity
//! they proved, what rides on them) plus what the caller wants, and returns a
//! plan. `Conn` and the daemon control socket own the state and the I/O; they
//! build the observation, ask in here, and carry out the answer. A decision that
//! lives here can be unit-tested without a network and model-checked in
//! `proofs/link_manager_model.py`.
//!
//! Before this module the same decisions were spread across `conn.rs`
//! (warm-hold), `daemon_ctl.rs` (warm reuse, peer presence) and the upgrade
//! prober, each with its own copy of the eligibility rules. They are gathered
//! here unchanged: this module changes WHERE a rule is written, not what it says.

// Warm reuse (the only placement caller today) is unix-only, like the control
// socket it serves.
#![cfg_attr(not(unix), allow(dead_code))]

/// A non-direct (relay/WebRTC) link has no QUIC keepalive, so an idle one may be
/// silently NAT/relay-evicted while `is_alive()`/`is_dead()` still lag (the read
/// loop hasn't seen the EOF yet). Container/DERP paths evict ~10s; reusing such a
/// link would open a stream into a black hole and hang. So past this idle window
/// we refuse to warm-reuse a non-direct link and fall back to a fresh establish
/// (correct, just not free). Direct links are exempt: the keepalive keeps them
/// genuinely alive across idle gaps, and their `idle_ms()` is unreliable here
/// anyway (quinn keepalive frames don't stamp last_activity).
/// The net.rs 5s relay keepalive keeps idle_ms under this gate on healthy links;
/// tripping it means the keepalive stopped, so a fresh establish is the right answer.
pub const WARM_RELAY_STALE_MS: u64 = 8_000;

// ============================================================================
// PLACEMENT: which existing link (if any) a request rides.
// ============================================================================

/// What the caller wants to do with a device. The class is carried so the rule
/// can differ per class without touching any caller. The first difference:
/// work that needs the peer's trusted grant ranks authority (a non-LAN link)
/// above route, see `place`. A bulk transfer next to a live shell is the next
/// case that will want its own connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Work {
    /// Interactive: shell, pty, exec, forward, netcat, control requests.
    Interactive,
    /// Bulk: a file transfer or sync of about `bytes`.
    Bulk { bytes: u64 },
    /// Mesh traffic and fleet control (rendezvous, roster).
    Mesh,
}

/// One link as placement sees it.
#[derive(Debug, Clone)]
pub struct LinkObs<'a> {
    pub pid: &'a str,
    /// The device name this link PROVED it reaches (`Link::verified_name`).
    pub verified_name: Option<&'a str>,
    /// The canonical store name of an exact authenticated LAN DEVICE reservation
    /// (`Link::authenticated_device_name`). Populated by the caller ONLY while the
    /// reservation's `(name, secret)` is the current store's binding and the
    /// secret is not revoked. A routing name, never an identity proof: the link
    /// stays untrusted and un-Proven, and no capability is granted.
    pub lan_device_name: Option<&'a str>,
    /// We know WHO this link reaches: the legacy pair-proof trust flag, or a
    /// proven certificate binding. This decides ROUTING, never permission: what
    /// the peer may do is still decided by the capability gate on its side.
    pub identity_known: bool,
    /// The link has a transport at all.
    pub has_transport: bool,
    /// The transport's own liveness verdict.
    pub alive: bool,
    /// An authenticated direct (QUIC) link rather than WebRTC/relay.
    pub direct: bool,
    /// The link came up through the LAN handshake (`Link::lan_binding`). That
    /// handshake proves a local holder of a shared secret, not the pair binding,
    /// so the link is born untrusted with a delegated principal, and the peer
    /// refuses work (a forward, a shell) that its pair link to the same device
    /// would carry. Placement ranks it below a non-LAN link of the same kind.
    pub lan: bool,
    /// Milliseconds since the transport last moved bytes either way.
    pub idle_ms: u64,
    /// Milliseconds since the link was established (`Link::established_at`).
    /// This is the only lifetime signal a link carries: nothing on it records
    /// WHY it was dialled, and a one-shot `exec` client proves the same pair
    /// identity as the long-lived daemon it runs next to. So placement uses age,
    /// not a purpose bit, to keep a freshly-created one-shot link from
    /// displacing the stable link the daemon already holds.
    ///
    /// `None` means the lifetime is unknown; it ranks as the youngest, so an
    /// unknown-age link never outranks one we know has lived longer.
    pub age_ms: Option<u64>,
}

/// Where a request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Ride this existing link.
    Reuse { pid: String },
    /// No existing link qualifies: establish a fresh one.
    Establish,
}

/// May a request for `peer` ride this link? Pure.
///
/// The link must reach `peer` by its PROVEN name (matched case-insensitively),
/// OR by an exact authenticated LAN DEVICE reservation that the caller has
/// already checked against the current store. A LAN link is deliberately NOT
/// `identity_known` and stays untrusted/un-Proven; this is a routing decision
/// only, and permission is still decided by the receiving capability gate. The
/// link must be alive; a non-direct link must also not have gone quiet past
/// `WARM_RELAY_STALE_MS`, since that is a relay path that may already be evicted.
pub fn eligible(l: &LinkObs<'_>, peer: &str) -> bool {
    let reaches_peer = (l.identity_known
        && l.verified_name.is_some_and(|n| n.eq_ignore_ascii_case(peer)))
        || l.lan_device_name.is_some_and(|n| n.eq_ignore_ascii_case(peer));
    reaches_peer
        && l.has_transport
        && l.alive
        && (l.direct || l.idle_ms < WARM_RELAY_STALE_MS)
}

/// Place `work` for `peer` on the given links. Pure.
///
/// Every eligible link qualifies. For work that needs the peer's trusted grant
/// (`Work::Interactive`: shell, pty, exec, forward) a non-LAN link beats a LAN
/// one before anything else, whatever their route or age (P8): both may reach
/// the device, but only the pair link carries the authority the peer checks,
/// so a capability-less LAN link is a refusal waiting to happen whenever the
/// pair link is also up, even when the LAN link is direct and the pair link is
/// relayed. A LAN link is still placed when it is the only usable one.
///
/// Then a direct link is preferred over a relayed one (P6; for other work
/// classes this comes first and LAN-ness only orders links of the same route).
/// Then the LONGEST-LIVED one wins. That is the durability rule: a one-shot `exec` client opens a fresh link to the same
/// device and proves the same identity, so without a lifetime preference it can
/// be selected (HashMap order is `last-equal`) and then close under the work it
/// was given. Nothing in `Link` says whether it was dialled by a daemon or by a
/// one-shot command, so age is the available signal; see `LinkObs::age_ms`.
///
/// Ties are broken by the lexicographically smallest pid, not by iteration
/// order, so the same link set always yields the same placement.
pub fn place(work: Work, peer: &str, links: &[LinkObs<'_>]) -> Placement {
    let authority_first = needs_trusted_grant(work);
    links
        .iter()
        .filter(|l| eligible(l, peer))
        .max_by(|a, b| {
            // Reversed: `false` (not LAN) must rank higher.
            let authority = b.lan.cmp(&a.lan);
            let route = a.direct.cmp(&b.direct);
            let (first, second) = if authority_first {
                (authority, route)
            } else {
                (route, authority)
            };
            first
                .then(second)
                .then_with(|| age_rank(a).cmp(&age_rank(b)))
                // Reversed so `max_by` picks the SMALLEST pid on a full tie.
                .then_with(|| b.pid.cmp(a.pid))
        })
        .map(|l| Placement::Reuse { pid: l.pid.to_string() })
        .unwrap_or(Placement::Establish)
}

/// Does this work class need the peer's trusted grant (shell, forward), which
/// only the pair link carries? Such work ranks authority above route.
fn needs_trusted_grant(work: Work) -> bool {
    matches!(work, Work::Interactive)
}

/// A link's lifetime for placement. Unknown ranks as youngest (0 ms), so it
/// cannot displace a link we know has been alive longer.
fn age_rank(l: &LinkObs<'_>) -> u64 {
    l.age_ms.unwrap_or(0)
}

/// Is the PEER on this link demonstrably there right now? What `devices` may
/// call "online" and what refreshes a device's "last seen". Pure.
///
/// `alive` is the transport's own verdict (a direct QUIC link flips it within
/// its 21 s idle timeout of a peer going silent). `heard_ms` is how long since
/// the peer last sent anything, where the transport tracks it (relay links):
/// both ends send a keepalive every 5 s, so past WARM_RELAY_STALE_MS of silence
/// the peer is gone even though our own keepalive writes keep succeeding. It
/// used to be judged on `idle_ms`, which those writes stamp, so a relay link to
/// a SIGSTOPped or wiped peer read as "online (last seen just now)" forever.
/// Without `heard_ms`, a relay link falls back to the old `idle_ms` rule.
pub fn peer_present(alive: bool, direct: bool, heard_ms: Option<u64>, idle_ms: u64) -> bool {
    alive
        && match heard_ms {
            Some(h) => h < WARM_RELAY_STALE_MS,
            None => direct || idle_ms < WARM_RELAY_STALE_MS,
        }
}

/// Peer-originated liveness for a relay/DataChannel link. `heard_ms` is stamped
/// only by the PEER (see `Transport::heard_ms`); our own relay keepalive writes
/// stamp `idle_ms` but not this. `Some(true)` means the peer was heard inside
/// the one stale window above, `Some(false)` means it has gone silent past it,
/// and `None` means the transport does not track peer-only silence (direct
/// QUIC), so the caller must apply its own transport-bounded rule.
///
/// This is the same rule as `peer_present` for tracked transports, exposed
/// without the `alive`/`direct` inputs so a caller that has already judged
/// transport liveness does not restate the window.
pub fn relay_peer_live(heard_ms: Option<u64>) -> Option<bool> {
    heard_ms.map(|heard| heard < WARM_RELAY_STALE_MS)
}

// ============================================================================
// WARM-HOLD: should a link to a warm-tier device be dialled this tick?
// ============================================================================

/// One link as warm-hold sees it.
pub struct WarmLinkView<'a> {
    pub pid: &'a str,
    /// `link_petname`: the device it is bound to, when known.
    pub petname: Option<&'a str>,
    /// The name the link was born with (a display name for a WebRTC link,
    /// the petname for a direct one).
    pub name: &'a str,
    /// `Conn::has_live_transport`: serving, or still making progress.
    pub live: bool,
}

/// One roster entry (a sid we saw on signaling) as warm-hold sees it.
pub struct WarmRosterView<'a> {
    pub pid: &'a str,
    /// The DISPLAY name the sid announced.
    pub name: Option<&'a str>,
    /// The pair channel it was met on, for a channel-introduced entry.
    pub channel: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WarmDecision {
    /// A live link to the device exists: leave it alone.
    Skip { pid: String },
    /// No live link: dial this present sid.
    Establish { pid: String },
    /// No live link and no present sid to dial.
    Absent,
}

/// What warm-hold should do for `peer` this tick. Pure, so the rule is
/// testable without a network.
///
/// `peer` is a warm-tier key. For a paired device (`channel` is its pair
/// channel) the device is identified by that channel and by the petname
/// links carry, never by the display name a sid announces: two devices may
/// share a display name and one device changes sids. Only a key that is not a
/// paired device falls back to matching display name or sid.
///
/// Skip if ANY link to the device is live, whatever its kind (direct,
/// WebRTC, relay) or the name it was born with. Otherwise dial one of the
/// sids actually present for it; `rotation` (the peer's consecutive failure
/// count) walks through them when there are several, so one stale sid cannot
/// absorb every attempt.
pub fn warm_decide(
    peer: &str,
    channel: Option<&str>,
    links: &[WarmLinkView<'_>],
    roster: &[WarmRosterView<'_>],
    rotation: usize,
) -> WarmDecision {
    let is_peer = |s: &str| s.eq_ignore_ascii_case(peer);
    let mut sids: Vec<&str> = roster
        .iter()
        .filter(|r| match channel {
            Some(ch) => r.channel == Some(ch),
            None => r.name.is_some_and(is_peer) || is_peer(r.pid),
        })
        .map(|r| r.pid)
        .collect();
    sids.sort_unstable();
    sids.dedup();
    let belongs = |l: &WarmLinkView<'_>| {
        l.petname.is_some_and(is_peer)
            || sids.contains(&l.pid)
            || (channel.is_none() && (is_peer(l.name) || is_peer(l.pid)))
    };
    if let Some(l) = links.iter().filter(|l| l.live && belongs(*l)).min_by_key(|l| l.pid) {
        return WarmDecision::Skip {
            pid: l.pid.to_string(),
        };
    }
    if sids.is_empty() {
        return WarmDecision::Absent;
    }
    WarmDecision::Establish {
        pid: sids[rotation % sids.len()].to_string(),
    }
}

// ============================================================================
// UPGRADE: has a direct standby earned the cutover from relay?
// ============================================================================

/// What to do with a connected direct standby on this verify tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyAction {
    /// First look at this standby: start the verify window now.
    StartWindow,
    /// The heartbeat failed or the path went idle past the guard: discard the
    /// standby, stay on relay, back off (the no-flap guard).
    Discard,
    /// Still inside the window and holding: keep watching.
    Wait,
    /// Moved data continuously for the whole window: cut over to direct.
    Upgrade,
}

/// Judge a direct standby. Pure.
///
///   elapsed_ms     time since the verify window started; None = not started
///   beat_ok        this tick's bounded heartbeat over the standby succeeded
///   idle_ms        the standby's idle time right now
///   verify_idle_ms the idle guard: at or past it the standby has regressed
///   verify_ms      how long it must hold before the cutover
///
/// The window starts on the first look whatever that look saw; every later look
/// discards on a failed beat or an idle path before it can upgrade.
pub fn decide_upgrade_verify(
    elapsed_ms: Option<u64>,
    beat_ok: bool,
    idle_ms: u64,
    verify_idle_ms: u64,
    verify_ms: u64,
) -> VerifyAction {
    let Some(elapsed) = elapsed_ms else {
        return VerifyAction::StartWindow;
    };
    if !beat_ok || idle_ms >= verify_idle_ms {
        return VerifyAction::Discard;
    }
    if elapsed >= verify_ms {
        VerifyAction::Upgrade
    } else {
        VerifyAction::Wait
    }
}

// ============================================================================
// STALL: which correction rung a stalled link gets. The ladder's policy is
// `resilience::decide_stall_action`; it is named here so every link decision is
// reachable from one module.
// ============================================================================

pub use crate::resilience::{StallAction, decide_stall_action};

#[cfg(test)]
mod tests {
    use super::*;

    fn obs<'a>(pid: &'a str, name: Option<&'a str>) -> LinkObs<'a> {
        LinkObs {
            pid,
            verified_name: name,
            lan_device_name: None,
            identity_known: true,
            has_transport: true,
            alive: true,
            direct: false,
            lan: false,
            idle_ms: 0,
            age_ms: Some(0),
        }
    }

    #[test]
    fn an_exact_authenticated_lan_device_link_resolves_without_trust() {
        // The LAN link is deliberately untrusted and un-Proven; the caller has
        // already checked its exact (name, secret) reservation against the
        // current store. Routing may name it, permission is unchanged.
        let mut lan = obs("lan", None);
        lan.identity_known = false;
        lan.lan_device_name = Some("Laptop");
        lan.direct = true;
        assert_eq!(
            place(Work::Interactive, "laptop", &[lan]),
            Placement::Reuse { pid: "lan".into() }
        );
    }

    #[test]
    fn a_pair_link_beats_an_older_lan_link_to_the_same_device() {
        // Shape from the net-blockers and forward-refusal CI runs: two live
        // direct links to bravo, the LAN one 42 ms older. Age picked the LAN
        // link and bravo refused the forward ("denied"). Both orders, and the
        // LAN link made far older, so neither iteration nor age can decide.
        let mut lan = obs("lan-6daee5532e971aa3", Some("bravo"));
        lan.direct = true;
        lan.lan = true;
        lan.age_ms = Some(900_000);
        let mut pair = obs("YZr4lvfHwQ8A9RLlAAAJ", Some("bravo"));
        pair.direct = true;
        pair.age_ms = Some(6_441);
        for links in [[lan.clone(), pair.clone()], [pair.clone(), lan.clone()]] {
            assert_eq!(
                place(Work::Interactive, "bravo", &links),
                Placement::Reuse { pid: "YZr4lvfHwQ8A9RLlAAAJ".into() }
            );
        }
        // Reached only by its LAN reservation (not identity-known), the same.
        lan.identity_known = false;
        lan.verified_name = None;
        lan.lan_device_name = Some("bravo");
        for links in [[lan.clone(), pair.clone()], [pair.clone(), lan.clone()]] {
            assert_eq!(
                place(Work::Interactive, "bravo", &links),
                Placement::Reuse { pid: "YZr4lvfHwQ8A9RLlAAAJ".into() }
            );
        }
    }

    #[test]
    fn a_relayed_pair_link_beats_a_direct_lan_link_for_interactive_work() {
        // Owner decision: capability first. A direct LAN link must not outrank
        // a relayed pair link that holds the grant a shell or forward needs,
        // in either order and however much older the LAN link is.
        let mut lan = obs("lan", Some("bravo"));
        lan.direct = true;
        lan.lan = true;
        lan.age_ms = Some(900_000);
        let mut relay = obs("relay", Some("bravo"));
        relay.age_ms = Some(24);
        for links in [[lan.clone(), relay.clone()], [relay.clone(), lan.clone()]] {
            assert_eq!(
                place(Work::Interactive, "bravo", &links),
                Placement::Reuse { pid: "relay".into() }
            );
        }
        // Work that does not ride the trusted grant keeps the route first.
        for links in [[lan.clone(), relay.clone()], [relay.clone(), lan.clone()]] {
            assert_eq!(
                place(Work::Bulk { bytes: 1 << 20 }, "bravo", &links),
                Placement::Reuse { pid: "lan".into() }
            );
        }
    }

    #[test]
    fn a_lan_link_is_still_used_when_it_is_the_only_usable_one() {
        // The LAN rank orders links, it never makes one ineligible.
        let mut lan = obs("lan", Some("bravo"));
        lan.direct = true;
        lan.lan = true;
        assert_eq!(
            place(Work::Interactive, "bravo", &[lan.clone()]),
            Placement::Reuse { pid: "lan".into() }
        );
        // The pair link is a quiet relay (a possible zombie), so it is not
        // usable and the LAN link carries the work.
        let mut stale = obs("relay", Some("bravo"));
        stale.idle_ms = WARM_RELAY_STALE_MS;
        for links in [[lan.clone(), stale.clone()], [stale.clone(), lan.clone()]] {
            assert_eq!(
                place(Work::Interactive, "bravo", &links),
                Placement::Reuse { pid: "lan".into() }
            );
        }
    }

    #[test]
    fn a_lan_reservation_never_resolves_a_different_device() {
        let mut lan = obs("lan", None);
        lan.identity_known = false;
        lan.lan_device_name = Some("server");
        lan.direct = true;
        assert_eq!(place(Work::Interactive, "laptop", &[lan]), Placement::Establish);
    }

    #[test]
    fn a_dead_lan_link_is_not_placed_even_when_the_binding_matches() {
        let mut lan = obs("lan", None);
        lan.identity_known = false;
        lan.lan_device_name = Some("laptop");
        lan.direct = true;
        lan.alive = false;
        assert_eq!(place(Work::Interactive, "laptop", &[lan]), Placement::Establish);
    }

    #[test]
    fn reuses_a_live_proven_link_to_the_peer() {
        let links = [obs("p1", Some("Laptop"))];
        assert_eq!(
            place(Work::Interactive, "laptop", &links),
            Placement::Reuse { pid: "p1".into() }
        );
    }

    #[test]
    fn never_places_on_a_link_to_another_device() {
        let links = [obs("p1", Some("server"))];
        assert_eq!(place(Work::Interactive, "laptop", &links), Placement::Establish);
    }

    #[test]
    fn never_places_on_an_unproven_or_unknown_link() {
        let mut a = obs("p1", Some("laptop"));
        a.identity_known = false;
        let b = obs("p2", None);
        assert_eq!(place(Work::Interactive, "laptop", &[a, b]), Placement::Establish);
    }

    #[test]
    fn never_places_on_a_dead_or_transportless_link() {
        let mut a = obs("p1", Some("laptop"));
        a.alive = false;
        let mut b = obs("p2", Some("laptop"));
        b.has_transport = false;
        assert_eq!(place(Work::Interactive, "laptop", &[a, b]), Placement::Establish);
    }

    #[test]
    fn a_quiet_relay_link_is_a_possible_zombie_but_a_quiet_direct_one_is_not() {
        let mut relay = obs("p1", Some("laptop"));
        relay.idle_ms = WARM_RELAY_STALE_MS;
        assert_eq!(place(Work::Interactive, "laptop", &[relay.clone()]), Placement::Establish);
        relay.idle_ms = WARM_RELAY_STALE_MS - 1;
        assert_eq!(
            place(Work::Interactive, "laptop", &[relay]),
            Placement::Reuse { pid: "p1".into() }
        );
        let mut direct = obs("p2", Some("laptop"));
        direct.direct = true;
        direct.idle_ms = 10 * WARM_RELAY_STALE_MS;
        assert_eq!(
            place(Work::Interactive, "laptop", &[direct]),
            Placement::Reuse { pid: "p2".into() }
        );
    }

    #[test]
    fn prefers_direct_over_relay_in_either_order() {
        let relay = obs("r", Some("laptop"));
        let mut direct = obs("d", Some("laptop"));
        direct.direct = true;
        for links in [[relay.clone(), direct.clone()], [direct.clone(), relay.clone()]] {
            assert_eq!(
                place(Work::Interactive, "laptop", &links),
                Placement::Reuse { pid: "d".into() }
            );
        }
    }

    #[test]
    fn one_shot_exec_link_does_not_displace_the_long_lived_daemon_link() {
        // Shape from the PR512 soak: a just-created one-shot exec link (24 ms)
        // and the daemon's stable link (156 s) both eligible for the same peer.
        let mut daemon = obs("daemon", Some("laptop"));
        daemon.direct = true;
        daemon.age_ms = Some(156_000);
        let mut exec = obs("exec", Some("laptop"));
        exec.direct = true;
        exec.age_ms = Some(24);
        for links in [
            [exec.clone(), daemon.clone()],
            [daemon.clone(), exec.clone()],
        ] {
            assert_eq!(
                place(Work::Interactive, "laptop", &links),
                Placement::Reuse { pid: "daemon".into() }
            );
        }
    }

    #[test]
    fn direct_eligibility_still_beats_an_older_relay() {
        // P6 is primary: age only orders links of the same kind, so a young
        // direct one-shot still wins over an old relay that is eligible.
        let mut relay = obs("relay", Some("laptop"));
        relay.age_ms = Some(900_000);
        let mut direct = obs("exec", Some("laptop"));
        direct.direct = true;
        direct.age_ms = Some(24);
        assert_eq!(
            place(Work::Interactive, "laptop", &[relay, direct]),
            Placement::Reuse { pid: "exec".into() }
        );
    }

    #[test]
    fn an_older_but_dead_or_quiet_link_is_not_selected_over_a_live_one() {
        let mut quiet = obs("old-relay", Some("laptop"));
        quiet.age_ms = Some(900_000);
        quiet.idle_ms = WARM_RELAY_STALE_MS;
        let mut dead = obs("dead-direct", Some("laptop"));
        dead.direct = true;
        dead.age_ms = Some(900_000);
        dead.alive = false;
        let mut live = obs("new-relay", Some("laptop"));
        live.age_ms = Some(1);
        assert_eq!(
            place(Work::Interactive, "laptop", &[quiet, dead, live]),
            Placement::Reuse { pid: "new-relay".into() }
        );
    }

    #[test]
    fn lifetime_ties_are_deterministic_and_unknown_age_ranks_youngest() {
        let mut a = obs("a", Some("laptop"));
        a.age_ms = Some(5_000);
        let mut b = obs("b", Some("laptop"));
        b.age_ms = Some(5_000);
        // Same direct-ness and age: the smallest pid wins whatever the order.
        for links in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
            assert_eq!(
                place(Work::Interactive, "laptop", &links),
                Placement::Reuse { pid: "a".into() }
            );
        }
        let mut unknown = obs("unknown", Some("laptop"));
        unknown.age_ms = None;
        let mut known = obs("known", Some("laptop"));
        known.age_ms = Some(1);
        for links in [
            [unknown.clone(), known.clone()],
            [known.clone(), unknown.clone()],
        ] {
            assert_eq!(
                place(Work::Interactive, "laptop", &links),
                Placement::Reuse { pid: "known".into() }
            );
        }
    }

    #[test]
    fn every_work_class_is_placed_the_same_today() {
        let links = [obs("p1", Some("laptop"))];
        for w in [Work::Interactive, Work::Bulk { bytes: 4 << 30 }, Work::Mesh] {
            assert_eq!(place(w, "laptop", &links), Placement::Reuse { pid: "p1".into() });
        }
    }

    #[test]
    fn peer_presence_prefers_what_the_peer_sent() {
        assert!(peer_present(true, false, Some(WARM_RELAY_STALE_MS - 1), u64::MAX));
        assert!(!peer_present(true, false, Some(WARM_RELAY_STALE_MS), 0));
        assert!(peer_present(true, true, None, u64::MAX));
        assert!(!peer_present(true, false, None, WARM_RELAY_STALE_MS));
        assert!(!peer_present(false, true, Some(0), 0));
    }

    #[test]
    fn relay_peer_live_is_the_one_stale_window_without_our_own_writes() {
        assert_eq!(relay_peer_live(Some(WARM_RELAY_STALE_MS - 1)), Some(true));
        assert_eq!(relay_peer_live(Some(WARM_RELAY_STALE_MS)), Some(false));
        assert_eq!(relay_peer_live(None), None);
    }

    #[test]
    fn upgrade_verify_window() {
        const IDLE: u64 = 2_000;
        const HOLD: u64 = 3_000;
        // First look always starts the window, even if this look looks bad.
        assert_eq!(decide_upgrade_verify(None, false, u64::MAX, IDLE, HOLD), VerifyAction::StartWindow);
        assert_eq!(decide_upgrade_verify(Some(0), true, 0, IDLE, HOLD), VerifyAction::Wait);
        assert_eq!(decide_upgrade_verify(Some(HOLD), true, 0, IDLE, HOLD), VerifyAction::Upgrade);
        // Any regression discards, however long it held.
        assert_eq!(decide_upgrade_verify(Some(HOLD * 9), false, 0, IDLE, HOLD), VerifyAction::Discard);
        assert_eq!(decide_upgrade_verify(Some(HOLD * 9), true, IDLE, IDLE, HOLD), VerifyAction::Discard);
        assert_eq!(decide_upgrade_verify(Some(HOLD - 1), true, IDLE - 1, IDLE, HOLD), VerifyAction::Wait);
    }
}
