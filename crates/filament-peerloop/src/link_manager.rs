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

/// What the caller wants to do with a device. Every class is placed by the same
/// rule today; the class is carried so the rule can differ per class without
/// touching any caller (a bulk transfer next to a live shell is the first case
/// that will want its own connection).
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
    /// Milliseconds since the transport last moved bytes either way.
    pub idle_ms: u64,
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
/// The link must reach `peer` (by its PROVEN name, matched case-insensitively),
/// we must know who it reaches, and it must be alive; a non-direct link must also
/// not have gone quiet past `WARM_RELAY_STALE_MS`, since that is a relay path
/// that may already be evicted.
pub fn eligible(l: &LinkObs<'_>, peer: &str) -> bool {
    l.identity_known
        && l.verified_name.is_some_and(|n| n.eq_ignore_ascii_case(peer))
        && l.has_transport
        && l.alive
        && (l.direct || l.idle_ms < WARM_RELAY_STALE_MS)
}

/// Place `work` for `peer` on the given links. Pure.
///
/// Every eligible link qualifies; a direct one is preferred over a relayed one.
/// Among equals the last one in iteration order wins, which is exactly what the
/// resolver this replaced (`max_by_key` over the link table) did.
pub fn place(_work: Work, peer: &str, links: &[LinkObs<'_>]) -> Placement {
    links
        .iter()
        .filter(|l| eligible(l, peer))
        .max_by_key(|l| l.direct as u8)
        .map(|l| Placement::Reuse { pid: l.pid.to_string() })
        .unwrap_or(Placement::Establish)
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
            identity_known: true,
            has_transport: true,
            alive: true,
            direct: false,
            idle_ms: 0,
        }
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
