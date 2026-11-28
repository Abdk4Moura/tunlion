//! CONNECTION STATE: the peer-link table and its per-link record, presence, the
//! resilience bookkeeping, and `Conn` itself -- the orchestration state every
//! command's event loop manipulates. The host-free policy over that state is
//! re-exported from `filament-peerloop` further down.
//!
//! Lifted out of `main.rs` in two slices: 1a moved the state types and their
//! pure helpers, 1b moved `Conn`, `impl Conn` and the owner/principal helpers
//! that sit with them. The command surface deliberately stayed behind:
//! `send_cmd`, `recv_cmd`, `pair_cmd`, `async_main`'s dispatch and the daemon ctl
//! handlers are all still in `main.rs`, which is the only reader of the
//! `pub` items here.
//!
//! Layout mirrors the state it belongs to, not a new abstraction:
//!   Link / Presence / Rung / StallState / DirectPending   per-link and per-attempt state
//!   ResilienceState / RejoinState                          bookkeeping bags
//!   Conn + impl Conn                                      the link table and its policy
//!   promotion, principal, presentation decisions            pure helpers over the above
//!
//! Whole decisions left the file in slice 3 and are re-exported below:
//! the warm-hold machine, link_dead_for / link_has_live_for / direct_permitted /
//! ice_fallback_allowed, stuck_backoff / schedule_retry, the adoption matcher, and
//! the petname rule. Every call site here and in the command modules is unchanged.
//!
//! BACK-EDGES -- what a future peer-loop carve still owes. The terminal and the
//! machine's own facts no longer appear here as imports: `Conn` carries
//! `log: Arc<dyn LogSink>`, `host: Arc<dyn HostServices>` and
//! `present: Arc<dyn Presentation>` (traits defined in `filament-peerloop::host`
//! and `filament-peerloop::present`, implemented over the real CLI functions in
//! `cli/src/host_impl.rs`). Rendering (`ui::…`), config (`settings::get_str`),
//! devices.json, the owner key, the rendezvous channel, the roster snapshot, the
//! relay policy and the fleet-presence check all go through those fields now.
//! Two helpers whose callers live in frozen modules (`recv_cmd`,
//! `renewal_lifecycle`) are defined in `host_impl` and re-exported here.
//!
//! What is still imported, and why (see docs/design-libfilament.md, "the rule
//! for what may leave"):
//!   - `crate::resilience` / `crate::link_manager`: PURE policy, no host opinion;
//!     they leave with `Conn` itself, not behind a trait.
//!   - `crate::local` / `crate::holepunch`: async network binding (a TCP listener,
//!     a STUN punch socket); their async surface does not fit a sync trait object.
//!   - `resolve_peer_identity`: operates on the CLI `Link` type and is called from
//!     frozen `recv_cmd`; the abstraction waits on the `Link` move.
//!   - `crate::test_hooks` and the FLEET/REJOIN constants: process/test facts, not
//!     host services.
mod digest;
mod source_routing;

pub use self::digest::{DigestSurface, DigestTracker};
#[cfg(test)]
use self::digest::DIGEST_ABSENT_IDLE_GRACE;
pub use self::source_routing::{
    AckWatch, ClosingLink, LinkEvents, PendingSource, RefusalOutcome, SourceRouting,
    deliver_refusal,
};
use self::source_routing::{QueueDrain, ev_weight};

use crate::handoff::{self, HandoffTransport};
use crate::holepunch;
use crate::host::{peer_entry, HostServices, Level, LogSink, Tone};
use crate::identity::resolve_peer_identity;
use crate::limits::{
    FLEET_LINK_NAME, MAX_ATTEMPTS, REJOIN_WINDOW, STALL_MAX_REPAIRS, VERIFY_PROBE_SID,
};
use crate::link_manager::{LinkObs, Placement, Work, peer_present, place};
use crate::present::{NoScreen, Presentation};
use crate::resilience;
use crate::test_hooks;
use filament_cap::capability::{BindingStrength, IdentityState, PrincipalKind};
use filament_transport::direct;
use filament_transport::net::{self, Ev, Peer, Transport};

/// The host-free policy now lives in `filament-peerloop`; this module re-exports
/// it so the ~200 call sites spread across the command modules stay unchanged.
pub use crate::{
    AdoptSource, CodeAuthorityRefusal, CodeSession, CodeTransport, LinkPetname, WarmHold,
    active_binding_matches, code_authority_check, direct_permitted,
    ice_fallback_allowed, link_carries_for, link_dead_for, link_has_live_for, link_petname, match_adoption_source,
    peer_targetable, schedule_retry, stuck_backoff,
};
use anyhow::Result;
use serde_json::{Value, json};
use crate::sim_rt::{SimHashMap, SimHashSet};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use filament_transport::clock::Instant;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// An in-flight code transfer on its peer's current link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeContinuation {
    Holds,
    NoLink,
    Lost,
}

/// Link facts a cached verdict is keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CodeLinkKey {
    generation: u32,
    source: net::SourceId,
    direct: bool,
    attempt: Option<net::AttemptId>,
    /// A digest of the link's `expected_secret`, never the secret itself.
    secret_tag: u64,
}

/// The last link that held code authority.
#[derive(Default)]
pub struct CodeAuthorityCache {
    held: Option<(String, CodeLinkKey)>,
}

/// Why a direct attempt is being started. A bool pair gave four states, three
/// meaningful and one nonsense (`probe && promote` = "a test dial that tears
/// down a serving link", exactly what the guard exists to prevent), with
/// nothing rejecting it. Every expensive defect this week was a boolean-ish
/// value legal in the type system and wrong in the domain: a hardcoded
/// `answerer: true`, `has_flowed() -> true`, `expected_secret: None`. This
/// makes the meaningless combination unrepresentable instead of merely
/// unreachable-by-convention.
/// What a promotion leaves behind: the serving WebRTC link, always.
///
/// A promotion used to have two outcomes. `Replaced` tore the authenticated
/// WebRTC link down and waited for direct QUIC to bring a successor (Option A),
/// so the transfer could not start until QUIC was up, 1.35 to 1.5 s after
/// `authenticated` on every cross-network code transfer, and a lost race meant
/// rebuilding WebRTC from scratch. `Retained` was the case where direct was off.
///
/// Promotion is now make-before-break (see `handoff`): the WebRTC link keeps
/// serving, the transfer starts on it, and a direct link that wins its race
/// takes over at a frame boundary through an explicit round trip. So the link
/// is retained and must be announced, which is what this token is for. The one
/// exception is a peer that does not advertise `handoff` (an older CLI, which
/// tears its own side down at confirm): against it the promotion still
/// replaces the link, exactly as before, and reports `Replaced`.
///
/// The `#[must_use]` is the point, and so is taking this by value in
/// `rearm_channel_ready`: it keeps re-announcement unreachable from a `Normal`
/// or `Probe` start_direct, whose winners adopt or verify on their own. A
/// promotion's winner never clobbers the serving link (it is routed to the
/// handoff as a standby), so announcing the retained link is always right.
/// Same argument that made `DirectIntent` an enum rather than two bools.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use = "a promotion RETAINS the serving link and leaves its transport \
              unannounced, and nothing else will announce it. Pass this to \
              `rearm_channel_ready`, or explain in a comment why this command \
              does not need the retained link announced."]
pub enum Promotion {
    /// Only against a peer that does not run make-before-break (an older
    /// CLI): the link was torn down at confirm, as that peer does on its own
    /// side, and the direct link will announce itself.
    Replaced,
    Retained,
}

/// Which end of a make-before-break promotion this is. The end that sends the
/// data leads, because only it can stop its frames at a boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PromoteRole {
    /// Sends the file: asks the peer to move once its own direct link is up.
    Lead,
    /// Receives it: moves when asked, and only then.
    Follow,
}

/// One post-PAKE promotion in progress. Exists from `start_direct_promote`
/// until the direct link is adopted, the race is lost, or the link goes away.
pub struct PromoteState {
    pub role: PromoteRole,
    /// The direct transport, once our race won (authenticated QUIC). Held
    /// beside the serving link, which it does not touch, until the handoff.
    standby: Option<(Arc<dyn Transport>, &'static str)>,
    /// Lead: the wrapper around the serving transport whose frame gate is the
    /// boundary.
    gate: Option<Arc<HandoffTransport>>,
    /// Lead: resolves the barrier with the peer's answer.
    answer: Option<oneshot::Sender<Option<Arc<dyn Transport>>>>,
    /// Follow: the peer asked before our own race finished.
    asked: bool,
    /// The handoff completed; the next `adopt_direct` for this peer retires
    /// the serving WebRTC link and installs the direct one in its place.
    handed: bool,
    /// Authorization token of the held direct standby.
    attempt: Option<net::AttemptId>,
    /// Immutable authorization snapshot copied from the pending that armed it.
    auth: Option<DirectAuth>,
}

impl PromoteState {
    fn new(role: PromoteRole) -> Self {
        PromoteState {
            role,
            standby: None,
            gate: None,
            answer: None,
            asked: false,
            handed: false,
            attempt: None,
            auth: None,
        }
    }

    fn has_standby(&self) -> bool {
        self.standby.is_some()
    }
}

/// How long a retired WebRTC link keeps delivering what the peer queued on it
/// before the handoff, before it is closed.
const RETIRE_GRACE: Duration = DROP_CLOSE_GRACE;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirectIntent {
    /// Never disturb a live link.
    Normal,
    /// Upgrade probe: bypass the live-link guard, but never drop.
    Probe,
    /// Post-PAKE promotion: dial alongside the serving WebRTC link, which is
    /// replaced only through the make-before-break handoff (`handoff`).
    Promote,
    /// Fleet auto-mesh: dial a same-owner device using the FLEET rendezvous
    /// secret as the transport MAC key. Behaves like `Normal` for teardown, but
    /// the resulting link is born UNPRIVILEGED: the fleet secret is shared by
    /// the whole fleet, so it proves MEMBERSHIP, not identity, and definitely
    /// not owner-equivalence. Identity arrives only with a verified
    /// `fleet-hello` (see cli/src/fleet.rs).
    Fleet,
}

/// Which existing link an establish may replace. Two values, not a bool, so a
/// call site says what it means.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Replace {
    /// Every caller but one: an existing live link satisfies the request and
    /// is kept (the establish is refused and logged).
    NeverLive,
    /// The retry ladder rebuilding the stuck attempt it was scheduled for.
    StuckAttempt,
}

/// `ice_config` reuses a config younger than this without asking again.
const ICE_CONFIG_FRESH: Duration = Duration::from_secs(60);
/// Ceiling on the config GET when the cache is not fresh.
const ICE_CONFIG_BUDGET: Duration = Duration::from_secs(3);
/// A failed GET falls back to a cached config younger than this.
const ICE_CONFIG_STALE_OK: Duration = Duration::from_secs(20 * 60);
/// The STUN server used when the config API does not answer in time; the same
/// default the backend hands out (backend/config.py DEFAULT_ICE).
const FALLBACK_STUN: &str = "stun:stun.l.google.com:19302";

/// A config that finds direct paths without the API: STUN only, default chunks.
fn stun_only_ice_config() -> net::ServerConfig {
    net::ServerConfig {
        ice_servers: vec![webrtc::ice_transport::ice_server::RTCIceServer {
            urls: vec![FALLBACK_STUN.to_string()],
            username: String::new(),
            credential: String::new(),
        }],
        chunk_size: 64 * 1024,
    }
}
/// Ceiling on building a WebRTC peer connection inside an establish.
const PEER_BUILD_BUDGET: Duration = Duration::from_secs(5);
/// Off-loop build lifecycle bounds. Four concurrent candidates is enough for a
/// fleet join; more wait in a deduped intent map instead of spawning tasks.
const MAX_PENDING_BUILDS: usize = 8;
const MAX_DEFERRED_BUILDS: usize = 64;
const MAX_BUILD_EVENTS: usize = 64;
const MAX_BUILD_EVENT_BYTES: usize = 256 * 1024;
const MAX_BUILD_SIGNALS: usize = 64;
const MAX_BUILD_SIGNAL_BYTES: usize = 256 * 1024;
/// Peers whose WebRTC offer may be held while our direct attempt for them is
/// pending (`hold_for_direct`). Beyond this a new peer's offer is not held.
const MAX_HELD_PEERS: usize = 32;
/// How long a held offer stays answerable: the direct budget plus the time the
/// initiator keeps that peer connection alive while it is making progress.
fn held_signal_ttl() -> Duration {
    direct::DIRECT_BUDGET + Duration::from_secs(10)
}

/// A peer's WebRTC offer and trickled candidates that arrived while our direct
/// attempt for that sid was still pending, when no responder may be built yet
/// (`prepare_build` refuses during a pending). Without this hold the offer was
/// discarded, and an initiator that sends one offer per peer connection could
/// never be answered on its first attempt. `pc` is the sender's peer-connection
/// tag (`None` from builds that do not send one); a different tag, or a second
/// offer, starts a new hold because it belongs to a newer attempt.
pub struct HeldSignals {
    since: Instant,
    pc: Option<u64>,
    has_offer: bool,
    signals: std::collections::VecDeque<Value>,
    bytes: usize,
}

/// Is this signal payload (the envelope's `data`) a WebRTC offer?
fn is_offer_data(data: &Value) -> bool {
    data["type"].as_str() == Some("description")
        && data["description"]["type"].as_str() == Some("offer")
}

/// Does this signal payload belong to a newer attempt than the one `held`
/// captured (aged out, another peer-connection tag, or a second offer)?
fn supersedes_held(held: &HeldSignals, data: &Value) -> bool {
    held.since.elapsed() >= held_signal_ttl()
        || held.pc != data["pc"].as_u64()
        || (held.has_offer && is_offer_data(data))
}
/// An offer from a different peer connection than the one this responder
/// answered: both sides tagged, and the tags differ. Untagged senders (older
/// builds, browsers) never match, so they keep the renegotiation path.
fn new_peer_connection(answered: Option<u64>, offered: Option<u64>) -> bool {
    matches!((answered, offered), (Some(a), Some(o)) if a != o)
}
/// Terminal-drain tombstones and inbound registrations are bounded. New direct
/// attempts fail closed when full.
const MAX_RETIRED_ATTEMPTS: usize = 16;
/// A candidate that never completes is reaped, not left to a detached timer.
const BUILD_REAP_GRACE: Duration = Duration::from_secs(30);
/// A retired attempt's readiness producer must be terminal before its drain
/// barrier is enqueued. That producer can itself hang on a socket that never
/// answers; waiting forever left 16 tombstones in place and every later direct
/// attempt was refused ("retirement drain capacity full"), which turns one
/// stuck build into a permanent direct-path outage. Abort and drain after this.
const RETIRED_DRAIN_BUDGET: Duration = Duration::from_secs(30);
/// Backstop for a lost drain event, applied ONLY to a tombstone whose producer
/// is known terminal (its drain task set [`RetiredAttempt::drained`]). Age
/// alone proves nothing: the abort above takes effect only at the producer's
/// next await, so a producer stuck elsewhere can outlive any budget, and
/// reaping its tombstone would let its late ready be adopted. A live, undrained
/// producer therefore keeps its slot, and new attempts fail closed against
/// [`MAX_RETIRED_ATTEMPTS`]. A drained tombstone still waits out this TTL
/// because its `AttemptDrained` barrier may be queued behind the old attempt's
/// own events; past it, the event was lost and the slot is reaped.
const RETIRED_TOMBSTONE_TTL: Duration = Duration::from_secs(60);
/// Direct attempts that expired at the same time are handed to the caller one
/// per call, not as a batch. The fallback caller awaits a full WebRTC establish
/// for each entry, and that establish can take up to the ICE config budget plus
/// [`PEER_BUILD_BUDGET`]. A fleet join starts one attempt per sibling, so they
/// expire together; draining the batch in one daemon-loop iteration made N
/// joins add up to a stall longer than the 20 s loop watchdog. The caller runs
/// this once per iteration, so the remaining peers fall back on later ticks.
const DIRECT_FALLBACKS_PER_CALL: usize = 1;
/// How long `drop_link` lets a dropped link's last frames reach the peer
/// before it closes the QUIC connection under them.
const DROP_CLOSE_GRACE: Duration = Duration::from_secs(2);
/// One bound for a revoked link's last act: write the `link-revoked` refusal
/// and wait for the peer's `link-revoked-ack`. The link is already out of
/// routing when this starts, so the bound only decides how long the cut
/// transport stays open for that one frame; it never holds the event loop.
/// Kept equal to `DROP_CLOSE_GRACE` so a peer that never answers keeps the
/// transport no longer than an ordinary drop did.
const REFUSAL_ACK_BUDGET: Duration = DROP_CLOSE_GRACE;

/// Close what a dropped link owned. Never awaited in the event loop (F8):
/// the WebRTC peer is marked and closed on a task, the direct transports after
/// a short grace.
fn close_dropped_link(old: Link) {
    // Never await close in the event loop (F8): mark + spawn.
    if let Some(p) = old.peer.clone() {
        p.mark_closed();
        tokio::spawn(async move { p.close().await });
    }
    // CLOSE the direct transports explicitly. Dropping the Link only
    // drops OUR Arc: the L3 overlay pump, the mesh accept loop, the
    // endpoint keeper and any warm stream hold their own clones, so the
    // QUIC connection stayed up and the peer never learned the link was
    // gone. It kept its own direct link for this pid and ignored our
    // WebRTC offers (no `peer` on its link to apply them to), our ladder
    // exhausted, and the cycle repeated forever: split-brain. Closing
    // sends ApplicationClose, the peer sees ConnectionLost, drops its
    // side and both ends re-converge.
    //
    // After a short grace, not at once: QUIC has no flush-on-close
    // (RFC 9000 s10.2), and several callers drop right after writing a
    // last frame on this link (the l2-close that answers a parked open,
    // a refusal). Closing immediately discarded that frame and the
    // client saw "no answer" instead of the reason. No-op for transports
    // without a connection to close (DataChannel, local).
    let closing: Vec<Arc<dyn Transport>> =
        old.transport.into_iter().chain(old.workers).collect();
    if !closing.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(DROP_CLOSE_GRACE).await;
            for t in closing {
                t.force_close();
            }
        });
    }
}

/// The local-discovery reservation that authenticated a LAN link.
///
/// `name` is the reservation name used for dedup/route matching. `device` is
/// the exact stored (name, secret) DEVICE binding, and is `None` for a LAN
/// fleet reservation: the shared rendezvous secret is membership evidence, not
/// a device binding, and must never enter revocation comparisons as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanBinding {
    pub name: String,
    pub device: Option<(String, String)>,
}

/// Resolve a LAN reservation to the CURRENT store's canonical device name, only
/// for an exact authenticated DEVICE binding.
///
/// Pure so every consumer (warm routing, send's target selection, the daemon's
/// baseline transfer consent) uses one rule. Deliberately narrow:
/// * `device` is `None` for a fleet reservation, whose shared rendezvous secret
///   is membership evidence and must never name a device;
/// * the binding's `(name, secret)` must match one store record (name
///   case-insensitively, secret exactly) — a forgotten or re-paired device
///   matches nothing;
/// * the secret must not be in the session's revoked set;
/// * `record_revoked` must say the matching record is live. `devices_load`
///   deliberately KEEPS revoked rows with their secret, so this is the
///   authoritative check that fails closed before the next revocation sweep.
///
/// Returns the store's casing of the name. This is a ROUTING name: it grants no
/// capability and never marks the link trusted or Proven.
pub fn authenticated_lan_device_name<'a, S: std::hash::BuildHasher>(
    binding: Option<&LanBinding>,
    devices: &'a [(String, String)],
    revoked: &HashSet<String, S>,
    record_revoked: &dyn Fn(&str) -> bool,
) -> Option<&'a str> {
    let (bound_name, secret) = binding?.device.as_ref()?;
    if secret.is_empty() || revoked.contains(secret) {
        return None;
    }
    devices
        .iter()
        .find(|entry| {
            entry.0.eq_ignore_ascii_case(bound_name)
                && entry.1.as_str() == secret
                // `devices_load` keeps revoked rows (with their secret) so they
                // can be displayed/re-enabled. A revoked record is not a live
                // authority: resolution and consent fail closed NOW, not at the
                // next sweep.
                && !record_revoked(entry.0.as_str())
        })
        .map(|entry| entry.0.as_str())
}

#[cfg(test)]
mod lan_resolution_tests {
    use super::*;

    fn store(rows: &[(&str, &str)]) -> Vec<(String, String)> {
        rows.iter()
            .map(|(n, s)| ((*n).to_string(), (*s).to_string()))
            .collect()
    }

    fn device_binding(name: &str, secret: &str) -> LanBinding {
        LanBinding {
            name: name.to_string(),
            device: Some((name.to_string(), secret.to_string())),
        }
    }

    fn live(_: &str) -> bool {
        false
    }

    #[test]
    fn an_exact_current_device_binding_resolves_to_the_stored_name() {
        let devices = store(&[("Laptop", "s1")]);
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "s1")),
                &devices,
                &HashSet::new(),
                &live
            ),
            Some("Laptop"),
            "routing uses the store casing, matched case-insensitively on the binding"
        );
    }

    #[test]
    fn a_repaired_or_wrong_secret_binding_resolves_nothing() {
        let devices = store(&[("laptop", "new")]);
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "old")),
                &devices,
                &HashSet::new(),
                &live
            ),
            None
        );
    }

    #[test]
    fn a_forgotten_binding_resolves_nothing() {
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "s1")),
                &[],
                &HashSet::new(),
                &live
            ),
            None
        );
    }

    #[test]
    fn a_revoked_binding_resolves_nothing() {
        let devices = store(&[("laptop", "s1")]);
        let revoked: HashSet<String> = ["s1".to_string()].into_iter().collect();
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "s1")),
                &devices,
                &revoked,
                &live
            ),
            None
        );
    }

    /// The store RETAINS a revoked record's pair secret (`certRevoked` /
    /// terminal `principalState`). That row must not resolve, even when the
    /// session's revoked-secret set is still empty (before the next sweep).
    #[test]
    fn a_revoked_record_with_a_retained_secret_resolves_nothing() {
        let devices = store(&[("laptop", "s1")]);
        let revoked_record = |name: &str| name.eq_ignore_ascii_case("Laptop");
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "s1")),
                &devices,
                &HashSet::new(),
                &revoked_record
            ),
            None
        );
    }

    #[test]
    fn a_fleet_reservation_never_names_a_device() {
        let devices = store(&[("laptop", "s1")]);
        let fleet = LanBinding {
            name: "laptop".into(),
            device: None,
        };
        assert_eq!(
            authenticated_lan_device_name(Some(&fleet), &devices, &HashSet::new(), &live),
            None,
            "the shared fleet rendezvous secret is membership evidence, not a device binding"
        );
    }

    #[test]
    fn an_empty_secret_resolves_nothing() {
        let devices = store(&[("laptop", "s1")]);
        assert_eq!(
            authenticated_lan_device_name(
                Some(&device_binding("laptop", "")),
                &devices,
                &HashSet::new(),
                &live
            ),
            None
        );
    }
}

pub struct Link {
    /// WebRTC peer connection. `None` for a rung-1 direct link (no ICE/DTLS
    /// negotiation, it rides authenticated QUIC), so every WebRTC-only call
    /// site (`handle_signal`, `fingerprints`, `restart_ice`, the watchdog's
    /// `is_connected`) is reachable only when this is `Some`.
    pub peer: Option<Arc<Peer>>,
    pub info: Value, // {id,name,uid} as last seen, enough to re-establish
    pub name: String,
    pub uid: Option<String>,
    pub transport: Option<Arc<dyn Transport>>,
    pub generation: u32,
    /// Immutable identity of the primary transport attempt that owns this link.
    /// Read by the event gate immediately before dispatch.
    pub source: net::SourceId,
    /// Direct readiness attempt that owns this link, if direct.
    pub attempt: Option<net::AttemptId>,
    /// Immutable identities of the current parallel worker transports. Kept
    /// separate from `source` so a worker can never authorize primary teardown
    /// and a stale worker source is removed with its worker.
    pub worker_sources: SimHashSet<net::SourceId>,
    pub attempts: u32,
    /// C12: proof-verified known device (per link, not global)
    pub trusted: bool,
    /// (name, secret) hypothesis to prove/verify on this link
    pub expected_secret: Option<(String, String)>,
    /// LAN-origin reservation identity. Separate from `expected_secret` so a
    /// LAN link mints no worker key or pair-proof hypothesis, while revocation,
    /// dedup and adoption can still see its exact device binding (device LAN
    /// only; never the fleet shared RV). A live binding makes the link the pair
    /// at adoption (`adopt_direct`).
    pub lan_binding: Option<LanBinding>,
    /// The devices.json PETNAME this link proved as (the cap-store key). Set on a
    /// verified `pair-proof` (WebRTC) or at birth for a direct link (already
    /// identity-bound). `None` until proven. Capability lookups (e.g. the `shell`
    /// gate) MUST key on this, NOT on `name` (a presence display string that may
    /// not match a stored record).
    pub verified_name: Option<String>,
    /// C26: what the status roster shows for this peer
    pub presence: Presence,
    /// rung-1 (TUNLION_DIRECT): this link's transport is an authenticated direct
    /// QUIC connection, its pair-secret MAC already proved identity, so the
    /// post-channel DTLS pair-proof is skipped and the link is born trusted.
    pub direct: bool,
    /// Route label for a direct link (no WebRTC `route()` to query): `direct-quic`
    /// for rung-1, `holepunched` for rung-2. Ignored for WebRTC links.
    pub direct_route: &'static str,
    /// Parallel QUIC transports for multi-stream file transfer
    /// (`TUNLION_DIRECT_STREAMS` > 1). Empty when striping is disabled
    /// or when the link uses a non-QUIC transport.
    pub workers: Vec<Arc<dyn Transport>>,
    /// When this link was established. Reported when an establish is refused
    /// over it (warm-hold no longer needs a pair-proof grace: it never asks to
    /// replace a live link at all).
    pub established_at: Option<Instant>,
    /// Identity cert device_pub (set when identity-expose is verified).
    pub identity_device_pub: Option<[u8; 32]>,
    /// Identity cert user_pub (set when identity-expose is verified).
    pub identity_user_pub: Option<[u8; 32]>,
    /// Binding strength of the identity fields (set alongside them).
    pub identity_binding: BindingStrength,
    /// Whether the identity fields are Pending, Resolved, or the peer
    /// explicitly answered that it holds no certificate after the code
    /// ceremony. The gate distinguishes an unfinished resolution (must hold,
    /// then fail closed) from an explicit anonymous code peer (transfer only).
    pub identity_state: IdentityState,
    /// Identity cert expiry (unix seconds). None = no cert resolved.
    pub identity_cert_expires: Option<u64>,
    /// Principal kind: OwnerDevice or Delegated { caps }. A Delegated
    /// principal CANNOT exist without its ceiling — the compiler enforces it.
    pub principal_kind: PrincipalKind,
    /// The session's host facts. `resolve_peer_identity` reads the stored
    /// certificate and principal record through this, so `Link` never names a
    /// CLI module. It is the same object `Conn` carries.
    pub host: Arc<dyn HostServices>,
}

impl Link {
    /// The name to SHOW for this peer. A known device proves into its local
    /// petname (`verified_name`); show that, so one device reads consistently as
    /// (e.g.) `dovm` everywhere instead of flipping between the petname and the
    /// peer's broadcast display name (`name`, e.g. `Abdul's server`). The
    /// broadcast name is the fallback only for an unverified / unknown peer.
    pub fn shown(&self) -> &str {
        self.verified_name.as_deref().unwrap_or(&self.name)
    }

    /// DISPLAY only, never a lookup key: the proven petname, else the petname
    /// this link is being dialed as (the known-device hypothesis, not yet
    /// proven), else the broadcast name. Progress lines read "ok <petname>"
    /// instead of a raw peer id or `user@host` for a device the user named.
    /// `shown()` stays as it is because last-seen and overlay naming key on
    /// it, and an unproven hypothesis must not touch a device record.
    pub fn label(&self) -> &str {
        self.verified_name
            .as_deref()
            .or(self.expected_secret.as_ref().map(|(n, _)| n.as_str()))
            .or(self.lan_binding.as_ref().map(|b| b.name.as_str()))
            .unwrap_or(&self.name)
    }

    /// ROUTING ONLY: the canonical stored name this link reaches when it carries
    /// an exact authenticated LAN DEVICE reservation that is STILL the current
    /// store's binding.
    ///
    /// This lookup itself sets nothing. Adoption uses it once to make a live
    /// LAN device link the pair (`adopt_direct`); routing (`reach`/`send` warm
    /// reuse) uses it to match a link the local handshake authenticated with
    /// that device's pair secret. A forgotten, revoked, re-paired or
    /// fleet-reserved link resolves
    /// nothing: the store lookup is exact on `(name, secret)` and the secret
    /// must not be in `revoked`.
    pub fn authenticated_device_name<'a, S: std::hash::BuildHasher>(
        &self,
        devices: &'a [(String, String)],
        revoked: &HashSet<String, S>,
        record_revoked: &dyn Fn(&str) -> bool,
    ) -> Option<&'a str> {
        authenticated_lan_device_name(self.lan_binding.as_ref(), devices, revoked, record_revoked)
    }

    /// The exact device secret this link is bound to: a pair-secret hypothesis,
    /// or an authenticated LAN device reservation. A LAN fleet reservation
    /// carries no device binding, so its shared rendezvous secret is never
    /// returned here.
    pub fn device_secret(&self) -> Option<&str> {
        self.expected_secret
            .as_ref()
            .map(|(_, secret)| secret.as_str())
            .or_else(|| {
                self.lan_binding
                    .as_ref()
                    .and_then(|binding| binding.device.as_ref())
                    .map(|(_, secret)| secret.as_str())
            })
    }

    /// Admit this link as a delegated (auth-key-enrolled) principal.
    /// Ensures caps are structurally tied to the Proven identity — a Delegated
    /// principal CANNOT exist without its ceiling.
    ///
    /// PERSISTENCE INVARIANT: a delegated device record writes its certificate,
    /// reconnect secret, principal kind, capability ceiling, and expiry in one
    /// atomic devices.json update. `resolve_peer_identity` restores the ceiling
    /// and clamps the certificate expiry before any owner-derived authorization.
    /// A same-owner certificate with no matching record fails closed as a
    /// delegated principal with an empty ceiling and expiry zero.
    /// Admit a same-owner FLEET device: identity proven, no ceiling, not owner.
    ///
    /// Deliberately NOT `admit_delegated`. That pins an auth-key ceiling, and the
    /// ceiling check is unconditional and purely restrictive, so the empty
    /// ceiling a sibling starts with denied everything before the fleet policy
    /// was consulted. `trusted` stays false here for the same reason it does
    /// there: binding=Proven is what authorizes, and `trusted` leaks into the
    /// legacy_ok gates.
    pub fn admit_fleet(&mut self, owner_pub: [u8; 32], device_pub: [u8; 32], expires: u64) {
        self.identity_user_pub = Some(owner_pub);
        self.identity_device_pub = Some(device_pub);
        self.identity_binding = BindingStrength::Proven;
        self.identity_state = IdentityState::Resolved;
        self.identity_cert_expires = Some(expires);
        self.principal_kind = PrincipalKind::FleetSibling;
    }

    /// Identity bound by a verified fleet-hello: Proven possession of a cert
    /// chaining to our owner key, with `verified_name` resolved from that
    /// cert's device key (never a claimed name). That answers the question the
    /// shell fold's `trusted` term asks, "is this the device whose record
    /// grants it", as strongly as a pair MAC does. Deliberately NOT written
    /// into `trusted`, which also drives transfer auto-accept, vouching and the
    /// blanket `--shell` policy.
    /// Is this a fleet SIBLING link: certificate-admitted over the fleet channel
    /// (or a meeting place a verified sibling brokered), and NOT pair-proven?
    ///
    /// The principal kind alone does not say so. A verified `fleet-hello` also
    /// arrives over the owner's own PAIR link, and the hello arm admits that
    /// link with the fleet principal too. Rules written for siblings (the
    /// cut-on-revocation sweep, the transfer scope) must not touch a paired
    /// link, whose authorization is its pair secret: treating it as a sibling
    /// ended a delegated guest's held exec as "revoked" instead of "expired".
    /// `trusted` is the pair-proof flag, which a sibling link never sets.
    pub fn is_sibling_link(&self) -> bool {
        matches!(&self.principal_kind, PrincipalKind::FleetSibling) && !self.trusted
    }

    pub fn fleet_proven(&self) -> bool {
        // The rule lives in the crate (written once, shared with
        // `shell_gate::fleet_link_proven`); this is only the field extraction.
        crate::host::fleet_link_proven(
            matches!(&self.principal_kind, PrincipalKind::FleetSibling),
            self.identity_binding == BindingStrength::Proven,
            self.identity_device_pub.is_some(),
            self.verified_name.is_some(),
        )
    }

    pub fn admit_delegated(
        &mut self,
        owner_pub: [u8; 32],
        device_pub: [u8; 32],
        expires: u64,
        caps: Vec<String>,
    ) {
        // A delegated principal acts UNDER the owner's user identity (the auth
        // key issuer), so it presents user_pub = owner_pub. evaluate()'s owner
        // shortcut then authorizes, but ONLY after the auth-key caps ceiling
        // (checked first) has passed — so a transfer-only key gets transfer and
        // is denied shell/mount. This is the delegation grant.
        self.identity_user_pub = Some(owner_pub);
        self.identity_device_pub = Some(device_pub);
        self.identity_binding = BindingStrength::Proven;
        self.identity_state = IdentityState::Resolved;
        self.identity_cert_expires = Some(expires);
        self.principal_kind = PrincipalKind::Delegated { caps };
        // NOTE: deliberately do NOT set self.trusted. binding=Proven satisfies
        // cap_trust_floor under authoritative mode, and the auth-key caps ceiling
        // (auth_key_caps ∩ owner_effective) bounds the principal. Setting trusted
        // would leak into legacy_ok for gates that read it directly (e.g. mount),
        // handing an ephemeral borrower an unbounded, un-ceilinged grant.
    }
}

/// The CLI half of the petname rule: the two fields `filament_peerloop`'s
/// `link_petname` reads. The rule itself (verify first, else the dial hypothesis,
/// NEVER the broadcast display name) lives in the crate, so it cannot drift from
/// the warm-hold key that depends on it.
impl LinkPetname for Link {
    fn proven_petname(&self) -> Option<&str> {
        self.verified_name.as_deref()
    }

    fn dialed_petname(&self) -> Option<&str> {
        self.expected_secret.as_ref().map(|(n, _)| n.as_str())
    }
}

/// How long a command waits on a known device with NO presence before saying
/// it may simply be offline (it keeps waiting until its own timeout).
pub const OFFLINE_HINT_AFTER: Duration = Duration::from_secs(5);

/// The one-time hint for a known device that has not appeared at all.
pub fn offline_hint(peer: &str) -> String {
    format!("tunlion: {peer} doesn't seem to be online. Is `tunlion up` running there?")
}

/// The one wording for an inbound open that arrived on a link with no
/// transport: nothing can be sent back, so it is logged and dropped. The caller
/// supplies the sink, so this carries the sentence and not the terminal.
pub fn dropped_no_transport(log: &dyn LogSink, pid: &str, what: &str) {
    log.say(&format!(
        "tunlion: {what} from {pid} dropped: its link has no transport attached, so nothing was sent back"
    ));
}

/// C26: per-peer presence for the static status roster.
#[derive(Clone, Copy, PartialEq)]
pub enum Presence {
    Connecting,
    Ready,
    Away,
    Reconnecting,
}

/// True when a link's label is an identifier rather than a name: the
/// signaling id or uid it was filed under, or a long run of hex (a key or id
/// a peer announced in place of a name). Shown to a person only under -v.
pub fn label_is_raw_id(label: &str, id: &str, uid: Option<&str>) -> bool {
    label == id
        || uid == Some(label)
        || (label.len() >= 16 && label.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        || looks_like_session_id(label)
}

/// The route line for a direct link: its internal "direct-quic" label in the
/// words every other route uses ("direct over lo", "direct over eth0"), read
/// from the address the link is pinned to. Other labels pass through.
pub fn shown_direct_route(label: &str, t: &Arc<dyn Transport>) -> String {
    match (label, t.remote_addr()) {
        ("direct-quic", Some(remote)) => filament_transport::net::direct_route_label(remote),
        // Met by local discovery, no server: "lan (direct over wlan0)".
        (filament_transport::lan::ROUTE_LAN, Some(remote)) => {
            format!("lan ({})", filament_transport::net::direct_route_label(remote))
        }
        _ => label.to_string(),
    }
}

/// A signaling session id by its shape: 20 base64url characters mixing upper
/// case, lower case and digits (`hNZONFIoto2k9bQ9ABGV`). A link can carry one
/// that is not its own key (the name it was filed under came from an earlier
/// session), so `label == id` missed it and a person read "ok
/// hNZONFIoto2k9bQ9ABGV" on the roster line. A device name of exactly that
/// shape is not a name anyone types. Pure.
pub fn looks_like_session_id(label: &str) -> bool {
    let count = |f: fn(&char) -> bool| label.chars().filter(|c| f(c)).count();
    label.len() == 20
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        // One digit, not two: the lab printed "ok DrUEPIADYWGghg6rAAVO", a
        // real session id with a single digit (and one in ~30 has none at
        // all, which the case mix below still has to carry).
        && count(char::is_ascii_digit) >= 1
        && count(char::is_ascii_uppercase) >= 3
        && count(char::is_ascii_lowercase) >= 3
}

/// Is a dropped link's departure worth a line? Not when another link to a
/// peer of the same name is still up: that was a stale duplicate, and "alpha
/// left" beside "ok alpha" is a contradiction on one line. An unnamed link
/// (empty name) is always news. Pure.
pub fn departure_is_news<'a>(name: &str, remaining: impl IntoIterator<Item = &'a str>) -> bool {
    name.is_empty() || !remaining.into_iter().any(|n| n == name)
}

fn presence_glyph(p: Presence, log: &dyn LogSink) -> (&'static str, Tone, &'static str) {
    match p {
        Presence::Ready => (log.glyph_ok(), Tone::Ok, ""),
        Presence::Away => ("●", Tone::Warn, "away"),
        Presence::Reconnecting => ("◌", Tone::Warn, "reconnecting..."),
        Presence::Connecting => ("◌", Tone::Dim, "connecting..."),
    }
}

/// C18: browsers are mesh peers, they connect to EVERY room member. The CLI
/// must answer every offer politely or unanswered browsers wedge at
/// "connecting" (and their retry storms degrade the whole room). So: a links
/// MAP, every peer answered; SEND still aims transfers at one `active`
/// target; RECV accepts from any link, gated per-link by consent/trust.
const MAX_LINKS: usize = 16;

/// The longest the event loop waits on a best-effort control send to one link
/// (the periodic `state` ping, the stall probe). Those sends run inline, so an
/// unbounded one hands the whole loop to whichever peer stopped acknowledging.
pub const CONTROL_PROBE_BUDGET: Duration = Duration::from_secs(2);

/// RESILIENCE state, split out of the `Conn` god-struct so the stall/relay/
/// warm-standby/upgrade-probe bookkeeping is one named bag, not mixed in with
/// signaling + protocol state. The pure decisions live in `resilience.rs`.
#[derive(Default)]
pub struct ResilienceState {
    /// P0 (GAP-1): per-peer stall-repair bookkeeping for the bytes-moved
    /// watchdog. Tracks how many correction-ladder repairs we've already run for
    /// the current stall episode (bounded by MAX_ATTEMPTS) and whether a repair
    /// is in flight, so a single stall can't re-fire the ladder every tick while
    /// a repair is converging. Reset once the link starts flowing again.
    pub stall_repairs: SimHashMap<String, StallState>,
    /// P1 (GAP-4): peers this session has COMMITTED to the relay route after the
    /// direct ladder exhausted (rung d). Once a pid is in here, we stop dialing /
    /// answering direct-QUIC for it (the direct path is what just failed and would
    /// only re-freeze, racing the relay link); all (re)establishment for it goes
    /// over relay-only WebRTC. Survives link drops (keyed by pid, not stored on the
    /// Link), so a re-establish never bounces back to the known-bad direct path.
    pub relay_committed: SimHashSet<String>,
    /// P3 (GAP-3): the WARM-REDUNDANCY selectivity gate. TRUE only for long-lived
    /// / interactive sessions (the `up`/`up --shell` daemon acceptor; a transfer
    /// flagged interactive via `TUNLION_WARM_STANDBY=1` standing in for a tunnel),
    /// the sessions §2.4 says a mid-session drop is intolerable for. When set,
    /// `correct_stall` keeps the relay path as a pre-designated WARM standby and
    /// CUTS OVER to it on the FIRST stall (rung b) instead of grinding through the
    /// slow direct-repair rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, so the
    /// failover is near-instant rather than a perceptible gap. FALSE for one-shot
    /// file `send` (the 90% case): the on-disk partial + C7 resume make the cold
    /// repair ladder correct and bounded, and a warm standby isn't worth a second
    /// socket / NAT mapping / keepalive for a single transfer (the honest cost
    /// tradeoff, §2.4 / §6). Defaulted by session kind at construction, overridable
    /// by `net::warm_standby_override()` (`TUNLION_WARM_STANDBY`).
    pub warm_standby: bool,
    /// P3: per-peer warm-standby bookkeeping, peers whose relay standby has
    /// already been cut over to in the current stall episode, so a flapping relay
    /// path can't re-fire the instant cutover every tick (it falls through to the
    /// bounded relay-stalled `Exhausted` honesty instead). Cleared by
    /// `note_progress` once bytes move again.
    pub warm_cutover: SimHashSet<String>,
    /// P5 (GAP-6): per-peer relay->direct UPGRADE-PROBE bookkeeping. Present only
    /// for peers currently committed to relay (`relay_committed`) on a session
    /// where the prober is eligible (warm_standby/daemon, relay permitted). Drives
    /// the backoff schedule (probe soon, then steady cadence) and the
    /// verify-before-upgrade window for a connected direct standby. Removed on a
    /// successful upgrade (cutover) or when the peer leaves.
    pub upgrade_probe: SimHashMap<String, UpgradeProbe>,
    /// P5: a snapshot of the local interface set (sorted IP strings) at the last
    /// probe schedule. A change (new/removed interface, wifi<->cellular,
    /// default-route move surfacing a new local IP) is the "walked home onto wifi"
    /// signal, we re-probe IMMEDIATELY. Polled cheaply each tick (no platform
    /// netlink dependency); the portable best-effort trigger the plan asks for.
    pub iface_snapshot: Vec<String>,
    /// When each peer's current inbound/outbound transfer became in flight, so
    /// the bytes-moved watchdog measures silence since the transfer began, not
    /// since the link was opened. See `detect_stall`.
    pub in_flight_since: SimHashMap<String, Instant>,
}

/// ORCHESTRATION: peer-absence / rejoin-grace bookkeeping, split out of the Conn
/// god-struct. Tracks the reconnect window we hold open for a vanished peer and a
/// peer's declared absence (C21 `brb`).
pub struct RejoinState {
    /// when set, we are holding a reconnect window open for a vanished peer.
    pub waiting_rejoin: Option<Instant>,
    /// How long the current rejoin window runs (set when it opens; depends on
    /// whether the peer declared `brb`).
    pub rejoin_window: Duration,
    /// (peer sid, until), the peer told us it's stepping away (C21).
    pub away: Option<(String, Instant)>,
}

/// Auto-warm size guard: warm at most this many roster peers (see `warm-max`).
/// Must stay under MAX_LINKS (16) so warm-all can never starve on-demand,
/// inbound, or upgrade-probe links of link-table slots.
fn warm_max(host: &dyn HostServices) -> usize {
    host.settings_get_str("warm-max")
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(12)
        .min(MAX_LINKS - 2)
}

pub use crate::link_manager::{WarmDecision, WarmLinkView, WarmRosterView, warm_decide};

/// P0: one peer's stall-repair episode state.
#[derive(Default)]
pub struct StallState {
    /// Repairs attempted in the current episode (rung a is the first).
    pub attempts: u32,
    /// `true` between firing the ladder and the next observed byte of progress,
    /// so the per-tick watchdog doesn't re-arm while a repair is converging.
    pub pending: bool,
    /// P1 (GAP-4): `true` once this episode escalated to relay (rung d) and a
    /// FRESH relay WebRTC link is establishing (no transport yet). The new link
    /// isn't tracked by `direct_pending`, so without this latch `detect_stall`
    /// would keep seeing the (transport-less) link idle and re-fire the ladder
    /// into a premature `Exhausted` before relay even connects. Cleared by
    /// `note_progress` on the first byte over the relay path.
    pub relayed: bool,
}

/// P5 (GAP-6): one peer's relay->direct UPGRADE-PROBE state. Lifecycle:
///   IDLE  : armed (relay-committed); `next_at` is when the next probe fires,
///            `attempt` drives the exponential backoff (first_ms → steady_ms).
///   PROBING: a direct dial is in flight (a `DirectPending{probe:true}` exists);
///            we don't re-fire until it resolves (win → VERIFYING, or expiry →
///            back to IDLE with a longer backoff).
///   VERIFYING: a direct standby CONNECTED (`standby` set). It must move data
///            CONTINUOUSLY for `verify_ms` before we cut over; `verify_started`
///            marks when it connected. If it goes idle past `verify_idle_ms` or
///            never reaches `verify_ms` of sustained progress, it is DISCARDED
///            and we go back to IDLE (stay on relay, the no-flap guard).
pub struct UpgradeProbe {
    /// failed-probe count; each failure backs the cadence off toward steady_ms.
    pub attempt: u32,
    /// when the next probe may fire (None ⇒ probe ASAP, e.g. just armed or a
    /// network-change re-probe).
    pub next_at: Option<Instant>,
    /// the connected-but-unverified direct standby transport (VERIFYING state).
    pub standby: Option<Arc<dyn Transport>>,
    /// the route label of the standby (`direct-quic` / `holepunched`).
    pub standby_route: &'static str,
    /// when the standby connected, the start of the verify window.
    pub verify_started: Option<Instant>,
    /// the standby's `idle_ms()` floor observed so far in the verify window, used
    /// to require SUSTAINED progress (it must keep moving, not just connect).
    pub verify_last_idle: u64,
    /// Authorization token of the current standby, captured at readiness.
    pub token: Option<net::AttemptId>,
    /// Immutable authorization snapshot copied from the probe's DirectPending.
    pub auth: Option<DirectAuth>,
}

impl UpgradeProbe {
    pub fn armed() -> Self {
        UpgradeProbe {
            attempt: 0,
            next_at: None, // first probe is scheduled by the prober tick
            standby: None,
            standby_route: "direct-quic",
            verify_started: None,
            verify_last_idle: u64::MAX,
            token: None,
            auth: None,
        }
    }
}

/// P0: which correction rung the stall ladder took (see `Conn::correct_stall`).
#[derive(Debug, PartialEq)]
pub enum Rung {
    /// (a) re-offer unfinished transfers on the SAME transport (resume:true).
    Resume,
    /// (c) the transport was repaired in place (fresh direct dial / ICE-restart).
    Repaired,
    /// (d) P1: direct rungs a→c spent → the link was RE-ESTABLISHED over the TURN
    /// relay (relay-only ICE), preserving the on-disk partial. The fresh relay
    /// transport's ChannelReady re-offers the unfinished transfers (resume:true)
    /// and prints the honest relay banner.
    Relayed,
    /// rungs a→d unavailable: direct rungs spent AND relay is forbidden
    /// (`--no-relay`) or we were already on relay. The caller FAILS CLEANLY, a
    /// kept partial, a clear error, never a hang.
    Exhausted,
}

/// Which authority an immutable direct attempt was authorized by. A fleet
/// rendezvous secret proves membership, and a ceremony secret proves only the
/// code holder; neither is a device binding and neither may enter
/// `revoked_bindings`. Keeping the domain explicit prevents a shared string
/// from being compared as if it named a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectAuthDomain {
    Device,
    Ephemeral,
    Fleet,
    /// A LAN-origin primary whose ownership was established by the local
    /// discovery handshake. It keeps the exact device reservation for revocation
    /// but never mints a worker transport key.
    Lan,
}

/// Immutable authorization snapshot for one direct attempt. `generation` is
/// allocated from `Conn::next_gen` before any async work. `device_binding` is
/// populated ONLY for `Device`; it is the exact (name, secret) held by the
/// current device store when the attempt was armed.
#[derive(Clone, Debug)]
pub struct DirectAuth {
    pub generation: u32,
    pub domain: DirectAuthDomain,
    pub device_binding: Option<(String, String)>,
}

impl DirectAuth {
    fn device(generation: u32, name: &str, secret: &str) -> Self {
        DirectAuth {
            generation,
            domain: DirectAuthDomain::Device,
            device_binding: Some((name.to_string(), secret.to_string())),
        }
    }

    fn ephemeral(generation: u32) -> Self {
        DirectAuth { generation, domain: DirectAuthDomain::Ephemeral, device_binding: None }
    }

    fn fleet(generation: u32) -> Self {
        DirectAuth { generation, domain: DirectAuthDomain::Fleet, device_binding: None }
    }

    /// LAN reservation for a device-domain secret authenticated by the local
    /// handshake. The exact binding is retained so revocation/store checks use
    /// the real secret, never the fresh LAN pid alone.
    pub(crate) fn lan_device(generation: u32, name: &str, secret: &str) -> Self {
        DirectAuth {
            generation,
            domain: DirectAuthDomain::Lan,
            device_binding: Some((name.to_string(), secret.to_string())),
        }
    }

    /// LAN reservation authenticated by the shared fleet rendezvous secret.
    pub(crate) fn lan_fleet(generation: u32) -> Self {
        DirectAuth { generation, domain: DirectAuthDomain::Fleet, device_binding: None }
    }

    /// Worker transport key derived only from the stored DEVICE binding. Fleet,
    /// ephemeral, and LAN authority never mint one here.
    fn transport_key(&self) -> Option<[u8; 32]> {
        if self.domain != DirectAuthDomain::Device {
            return None;
        }
        self.device_binding
            .as_ref()
            .map(|(_, secret)| direct::transport_key(secret))
    }
}

/// rung-1: state for one in-flight direct-QUIC attempt.
pub struct DirectPending {
    /// Authorization token for this attempt, allocated before any async work.
    pub attempt: net::AttemptId,    /// The single outer task that can publish primary readiness for this
    /// attempt. Awaited by retirement cleanup before the drain barrier.
    pub race_task: Option<tokio::task::JoinHandle<()>>,
    /// Immutable authorization context captured when this attempt was armed.
    pub auth: DirectAuth,
    /// (name, secret) for the known device, gates the attempt and keys the MAC.
    pub secret: (String, String),
    /// This dial used the FLEET rendezvous secret, so the link it produces must
    /// NOT be born trusted / owner-equivalent. See `DirectIntent::Fleet`.
    pub fleet: bool,
    /// Seeded by local discovery (`seed_lan`). A LAN reservation has no
    /// signaling pid/path to fall back to, so expiry retires it instead of
    /// handing it to the WebRTC establish.
    pub lan: bool,
    /// This dial is a post-PAKE PROMOTION on the one-time-code path, keyed by
    /// the EPHEMERAL ceremony secret. Its MAC proves "the peer that typed this
    /// code", not "a device we remember", so the link it produces must not be
    /// born trusted either. See `adopt_direct`.
    pub ephemeral: bool,
    /// budget deadline; on expiry with no DirectReady we fall back to WebRTC.
    pub deadline: Instant,
    /// set once the peer's transport-offer arrived and we spawned the racer, so
    /// a duplicate offer doesn't spawn a second race.
    pub racing: bool,
    /// kept alive so the bound UDP port stays ours until the race consumes it.
    pub endpoint: Option<direct::BoundEndpoint>,
    /// rung-2 (TUNLION_HOLEPUNCH): a SECOND raw UDP socket, already STUN'd, kept
    /// raw (not connected) so its NAT mapping is the one we punch + run QUIC on.
    /// Consumed by the chained ladder in `on_transport_offer` only if rung-1
    /// fails. None when hole-punch is off or STUN discovery failed.
    pub punch_sock: Option<std::net::UdpSocket>,
    /// rung-2: our advertised srflx (logged at offer time; kept for diagnostics).
    #[allow(dead_code)]
    pub my_srflx: Option<std::net::SocketAddr>,
    /// #237: the server-asserted (whoami) public candidate the PEER advertised in
    /// its transport-offer, when the peer adopted one (None when the peer had
    /// already observed OUR address, suppressed whoami, or was answered a local
    /// address). This is the candidate OUR race actually dialed, so it is the one
    /// the relay-fallback attribution may honestly name as "never answered".
    pub peer_server_public: Option<String>,
    /// #237: set true at the dial site exactly when the race dialed THE PEER'S
    /// CLAIMED server-asserted address (see `dials_claimed`), never for a dial
    /// of any other candidate and never for a knob that skips the dials. The
    /// attribution says "dialed and never answered" only when this is true, so
    /// the sentence is bound to the address it names.
    pub server_public_dialed: Arc<AtomicBool>,
    /// P5 (GAP-6): this is a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE a live relay link (not the cold establishment path). When the
    /// race wins, `on_transport_offer` posts `Ev::DirectUpgradeReady` (verify-
    /// before-upgrade) instead of `Ev::DirectReady` (which would clobber the
    /// serving relay link). When the budget expires with no winner, `expired_direct`
    /// just DROPS the pending (no WebRTC fallback, the relay link is still serving)
    /// and the prober schedules the next backoff.
    pub probe: bool,
    /// Stop flag for the 6-shot `transport-offer` re-emitter spawned by
    /// `start_direct_inner`. Cancelling the pending (a browser hint, adoption,
    /// expiry, replacement) must also stop that task; otherwise it keeps
    /// advertising a direct dial we have already abandoned for several seconds.
    pub cancel: Arc<AtomicBool>,
}

/// A transport-offer held until its peer has a pending or a link:
/// (candidates, srflx, server_public, proto, ch). `ch` is the meeting place
/// the offer named (absent from a one-shot dialer), kept so a replay goes
/// through the same forgotten-channel and fleet checks as the original.
pub type BufferedOffer = (Vec<String>, Option<String>, Option<String>, u8, Option<String>);

/// A buffered transport-offer together with what this end knew about its peer
/// at the moment it was buffered. The install-time replay (`install_built`)
/// reads these to tell the one offer it exists for (the peer's dial that
/// arrived before ANY link for it, while its first candidate was building)
/// from the offers it must never replay: a re-emit of an offer an earlier link
/// already answered, or an offer staged under an older build generation.
#[derive(Clone, Debug)]
pub struct StagedOffer {
    pub offer: BufferedOffer,
    /// `current_intent` for the pid when the offer was buffered: the build
    /// generation that was in flight (or the installed link's), `None` when no
    /// intent existed yet.
    pub intent: Option<u32>,
    /// A link (live or not) already existed for the pid when the offer was
    /// buffered, so the offer belongs to that link's incarnation.
    pub linked: bool,
}

/// Rebuild the server envelope of a buffered transport-offer so a replay is
/// handled by the driver's ordinary `Ev::Signal` transport-offer arm. `from`
/// is the pid the offer was buffered under, never a payload field, so a replay
/// cannot be attributed to another peer. `probe` is deliberately not carried:
/// the upgrade-probe answer already ran when the offer first arrived.
fn buffered_offer_signal(pid: &str, offer: BufferedOffer) -> Value {
    let (cands, srflx, server_public, proto, ch) = offer;
    let mut data = json!({ "type": "transport-offer", "v": 1, "proto": proto, "addrs": cands });
    if let Some(s) = srflx {
        data["srflx"] = json!(s);
    }
    if let Some(s) = server_public {
        data["server_public"] = json!(s);
    }
    if let Some(c) = ch {
        data["ch"] = json!(c);
    }
    json!({ "from": pid, "data": data })
}

/// The SDP payloads a building WebRTC candidate consumes: a session
/// description or an ICE candidate. `envelope` is the server-stamped signal
/// (`{from, data}`); only these kinds are ever staged for a build.
fn is_candidate_sdp_signal(envelope: &Value) -> bool {
    matches!(
        envelope["data"]["type"].as_str(),
        Some("description") | Some("candidate")
    )
}

/// One prepared establish that has done only loop-local work: guards, role,
/// generation and the ICE cache decision. No network call has run yet.
#[derive(Clone)]
pub struct BuildPlan {
    peer_id: String,
    info: Value,
    name: String,
    uid: Option<String>,
    carried_secret: Option<(String, String)>,
    generation: u32,
    polite: bool,
    relay_ice: bool,
    config: BuildIce,
    replace: Replace,
    active_on_apply: bool,
    caller: &'static std::panic::Location<'static>,
    attempt: u8,
    prior_generation: Option<u32>,
    signals: std::collections::VecDeque<Value>,
    signal_bytes: usize,
}

#[derive(Clone)]
pub(crate) enum BuildIce {
    Cached(net::ServerConfig),
    Fetch,
}

/// The bounded, cancellable build task for one peer. `signals` is the per-pid
/// staging area for inbound signaling that arrives before the candidate is
/// installed. `early` holds candidate-origin events drained from the build's
/// OWN channel; that channel is the immutable provenance, so an event from the
/// previously serving link can never be replayed onto the installed candidate.
pub struct BuildState {
    generation: u32,
    cancel: Arc<BuildCancel>,
    handle: tokio::task::JoinHandle<()>,
    started: Instant,
    signals: std::collections::VecDeque<Value>,
    signal_bytes: usize,
    early: std::collections::VecDeque<Ev>,
    early_bytes: usize,
    events_rx: std::sync::Mutex<mpsc::UnboundedReceiver<Ev>>,
    /// Binding this intent was prepared with (authoritative pair secret). Used
    /// only to decide whether a re-pair supersedes the in-flight intent.
    binding: Option<(String, String)>,
}

pub(crate) struct BuildCancel {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}

impl BuildCancel {
    fn new() -> Self {
        Self { flag: AtomicBool::new(false), notify: tokio::sync::Notify::new() }
    }
    fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }
    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

/// A fully built candidate, produced only by the build task. `early` holds the
/// Ev callbacks queued during construction; `events_rx` keeps the same
/// candidate-local channel for later events and is forwarded only after
/// installation.
pub struct BuiltPeer {
    peer_id: String,
    generation: u32,
    /// Source identity captured from the Peer before any callback was enqueued.
    source: net::SourceId,
    peer: Arc<net::Peer>,
    info: Value,
    name: String,
    uid: Option<String>,
    carried_secret: Option<(String, String)>,
    active_on_apply: bool,
    replace: Replace,
    caller: &'static std::panic::Location<'static>,
    prior_generation: Option<u32>,
}

pub(crate) enum BuildStart {
    Started(u32),
    AlreadyBuilding,
    Deferred,
    Busy,
}

/// See `Conn::stuck_episode`.
struct StuckEpisode {
    attempts: u32,
    presence: Presence,
    channel_absent: Option<u8>,
    room_absent: Option<u8>,
    digest_deferred: Option<Instant>,
}

/// A build always reports a terminal result, so a failed task releases its
/// per-peer slot instead of blocking retries until the reap grace.
pub enum BuildDone {
    Ready(BuiltPeer),
    Failed { plan: BuildPlan, reason: String },
    Cancelled { plan: BuildPlan },
}


fn close_built(peer: Arc<net::Peer>) {
    peer.mark_closed();
    tokio::spawn(async move { peer.close().await });
}

fn discard_built(built: BuiltPeer) {
    close_built(built.peer);
}

fn discard_pending_state(mut state: BuildState) {
    let early = std::mem::take(&mut state.early);
    let queued: Vec<Ev> = {
        let rx = state
            .events_rx
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    };
    for ev in early.into_iter().chain(queued) {
        let inner = match ev {
            Ev::Sourced { inner, .. } => *inner,
            other => other,
        };
        if let Ev::ChannelReady(_, transport) = inner {
            transport.force_close();
        }
    }
}

fn discard_state(state: BuildState, peer: Arc<net::Peer>) {
    discard_pending_state(state);
    close_built(peer);
}

/// Move the build's own queued events into its bounded early buffer. Returns
/// false when a bound was hit; the caller cancels that build. Nothing from the
/// previous link can enter this channel, so everything here is candidate-local.
fn drain_candidate_events(state: &mut BuildState) -> bool {
    loop {
        let ev = {
            let mut rx = state
                .events_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            rx.try_recv().ok()
        };
        let Some(ev) = ev else {
            return true;
        };
        let weight = ev_weight(&ev);
        if state.early.len() >= MAX_BUILD_EVENTS
            || state.early_bytes.saturating_add(weight) > MAX_BUILD_EVENT_BYTES
        {
            return false;
        }
        state.early_bytes += weight;
        state.early.push_back(ev);
    }
}

/// How long a pending direct attempt may spend gathering its candidates
/// before the fallback reaper gives up on it. Gathering is bounded by its own
/// timeouts (whoami 3 s; with hole-punching the config fetch's retries and
/// STUN), so this is a backstop for a gathering task that never reports, not
/// a budget a healthy attempt comes near.
const DIRECT_GATHER_GRACE: Duration = Duration::from_secs(10);

/// The direct ladder's budget, counted from the moment our transport-offer
/// goes out. The WebRTC fallback reaper (`expired_direct`) fires at its end.
/// rung-1's race always burns the full DIRECT_BUDGET when it can't win (its
/// acceptor future never self-completes), so with hole-punch enabled the
/// deadline MUST cover the WHOLE ladder, rung-1 budget + punch budget + QUIC
/// handshake slack, or the reaper would race WebRTC against an in-flight punch
/// and the route would be a coin flip. Flag-gated, so rung-1-only timing is
/// byte-identical.
fn direct_ladder_budget() -> Duration {
    if holepunch::holepunch_enabled() {
        direct::DIRECT_BUDGET + holepunch::PUNCH_BUDGET + Duration::from_secs(3)
    } else {
        direct::DIRECT_BUDGET
    }
}

/// A pending direct attempt whose candidates are still being gathered off the
/// event loop (`gather_and_offer`). A peer's transport-offer that arrives in
/// that window is held here and raced once gathering reports.
pub struct DirectGathering {
    pub attempt: net::AttemptId,
    pub offer: Option<BufferedOffer>,
}

/// What a finished gathering task hands back to the loop (`pump_builds`).
pub struct DirectGathered {
    pub pid: String,
    pub attempt: net::AttemptId,
    /// rung-2 (TUNLION_HOLEPUNCH): the STUN'd raw socket and its srflx.
    pub punch_sock: Option<std::net::UdpSocket>,
    pub my_srflx: Option<std::net::SocketAddr>,
}

/// Everything `gather_and_offer` needs, owned, so it runs off the loop.
struct GatherJob {
    context: filament_transport::TransportContext,
    server: String,
    sio: filament_signal::Client,
    log: Arc<dyn LogSink>,
    pid: String,
    name: String,
    attempt: net::AttemptId,
    port: u16,
    /// A same-machine peer's candidates, already known: nothing to gather.
    local_cands: Option<Vec<String>>,
    channel: String,
    probe: bool,
    cancel: Arc<AtomicBool>,
    done: Arc<std::sync::Mutex<Vec<DirectGathered>>>,
    wake: mpsc::UnboundedSender<Ev>,
}

/// Gather a direct attempt's candidates, report them to the loop, then send
/// the transport-offer and its re-emits. Runs on its own task: gathering
/// awaits HTTP and STUN, which must never hold the daemon event loop
/// (`Conn::start_direct_inner`).
async fn gather_and_offer(job: GatherJob) {
    let GatherJob {
        context,
        server,
        sio,
        log,
        pid,
        name,
        attempt,
        port,
        local_cands,
        channel,
        probe,
        cancel,
        done,
        wake,
    } = job;
    // #1 (parallelism): gather the host/public candidates (incl. the
    // /api/whoami HTTP) and the rung-2 STUN srflx CONCURRENTLY. Both are
    // independent network round-trips that must finish before the
    // transport-offer can go out, and the initiator's "establishing" phase
    // waits on exactly that offer, so overlapping them shaves a round-trip off
    // every cold connect.
    //
    // rung-2 (TUNLION_HOLEPUNCH): bind a SECOND raw socket and STUN it so we
    // can advertise a server-reflexive candidate. This socket is kept RAW
    // (not handed to quinn), its NAT mapping is the one we'll punch + run
    // QUIC on if rung-1's host-candidate race fails. STUN failure is graceful:
    // no srflx is advertised and rung-2 simply won't fire for this peer.
    //
    // #237: gather_candidates is the ONE computation of both the candidate
    // set and the server-asserted address adopted into it (Some exactly
    // when a server-chosen address was pushed and no peer had observed us
    // yet). The offer carries that value to the peer so the PEER's race can
    // dial it and, if it never answers, name it at ITS fallback decision.
    // No second copy of the rule exists to desynchronize.
    let (cands, server_public, srflx) = match local_cands {
        Some(cands) => (cands, None, None),
        None => {
            let srflx_fut = async {
                #[cfg(feature = "sim")]
                if context.direct_backend().is_some() {
                    return None;
                }
                if holepunch::holepunch_enabled() {
                    gather_srflx(&context, &server).await
                } else {
                    None
                }
            };
            let ((cands, server_public), srflx) =
                tokio::join!(direct::gather_candidates(&context, &server, port), srflx_fut);
            (cands, server_public, srflx)
        }
    };
    let (punch_sock, my_srflx) = match srflx {
        Some((sock, srflx)) => (Some(sock), Some(srflx)),
        None => (None, None),
    };
    // Report BEFORE the offer goes out: the peer answers our offer with its
    // own, and the loop must already hold the rung-2 socket and the restarted
    // budget when that answer is raced.
    done.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(DirectGathered { pid: pid.clone(), attempt, punch_sock, my_srflx });
    let _ = wake.send(Ev::BuildWake);
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    // transport-offer rides the OPAQUE signaling relay (same channel as ICE
    // signals); the server cannot read or forge it without failing the MAC.
    let mut offer = json!({ "type": "transport-offer", "v": 1, "proto": 2, "addrs": cands });
    // The meeting place this dial is for. A daemon that has since FORGOTTEN
    // the secret behind it can then answer "not recognized" at once instead
    // of buffering an offer it can never match (recv_cmd, forgotten_channels).
    offer["ch"] = json!(channel);
    if let Some(s) = my_srflx {
        offer["srflx"] = json!(s.to_string());
    }
    // #237: the candidate this offer adopts on the server's say-so alone.
    // The peer dials it; if it never answers, the peer's fallback can name
    // exactly this address instead of claiming a cause it never dialed.
    if let Some(s) = server_public {
        // Test-only (gate C-negative/mismatch): advertise a server_public
        // label that is NOT the dialed candidate, modelling a peer (or
        // adversarially-mislabeled offer) whose claimed address is not in
        // its addrs. The peer that dials THIS offer's addrs must NOT name
        // this label on fallback - it never dialed 8.8.8.8:53.
        let tag = if std::env::var("TUNLION_DIRECT_SERVER_PUBLIC_MISMATCH")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            "8.8.8.8:53".to_string()
        } else {
            s
        };
        offer["server_public"] = json!(tag);
    }
    // P5 (GAP-6): tag a probe offer so the PEER races it as an upgrade probe
    // too, its winning side then posts Ev::DirectUpgradeReady (verify-before-
    // upgrade) instead of clobbering ITS serving relay link. Both ends must
    // treat the new direct path as a standby until verified, or one end would
    // tear down its relay link unilaterally.
    if probe {
        offer["probe"] = json!(true);
    }
    let _ = sio
        .emit("signal", json!({ "to": pid, "data": offer.clone() }))
        .await;
    // TRACE, direct-offer / signaling detail.
    log.trace(&format!(
        "tunlion: {} sent to {name} ({pid}), port {} srflx {}",
        if probe { "UPGRADE-PROBE-OFFER" } else { "DIRECT-OFFER" },
        port,
        my_srflx.map(|s| s.to_string()).unwrap_or_else(|| "-".into())
    ));
    // Re-send the offer periodically. The L2 initiator (netcat/ssh) subscribes
    // to the channel AFTER us, so on a late join it can miss BOTH our single
    // fire-once offer AND its own KnownPeer for us (presence delivery is racy),
    // the cross-machine stall. Re-emitting lets it catch a later offer and
    // dial our (reachable) candidates; the initiator only races the FIRST
    // offer it gets, so the extra emits are harmless once linked.
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let _ = sio
            .emit("signal", json!({ "to": pid, "data": offer.clone() }))
            .await;
    }
}

/// rung-2: bind a raw punch socket and discover its srflx via STUN against
/// the ICE config's STUN server. Returns (raw socket, srflx) or None.
async fn gather_srflx(
    context: &filament_transport::TransportContext,
    server: &str,
) -> Option<(std::net::UdpSocket, std::net::SocketAddr)> {
    let cfg = net::fetch_config(context, server).await.ok()?;
    let stun_urls: Vec<String> = cfg
        .ice_servers
        .iter()
        .flat_map(|s| s.urls.iter().cloned())
        .collect();
    // #3 (parallelism): race ALL configured STUN servers so a slow/dead one
    // never stalls gathering (the offer the initiator waits on).
    let stun_addrs = holepunch::stun_server_addrs(&stun_urls);
    if stun_addrs.is_empty() {
        return None;
    }
    let sock = holepunch::bind_punch_socket().ok()?;
    // STUN is blocking UDP I/O, run it off the reactor.
    crate::sim_rt::run_blocking(move || {
        holepunch::stun_srflx_any(&sock, &stun_addrs).map(|srflx| (sock, srflx))
    })
    .await
    .ok()?
    .ok()
}

#[allow(clippy::too_many_arguments)]
async fn run_build_task(
    plan: BuildPlan,
    candidate: mpsc::UnboundedSender<Ev>,
    wake: mpsc::UnboundedSender<Ev>,
    wake_pending: Arc<AtomicBool>,
    cancel: Arc<BuildCancel>,
    out: mpsc::UnboundedSender<BuildDone>,
    context: filament_transport::TransportContext,
    server: String,
    sio: filament_signal::Client,
    my_uid: String,
    cache: SharedIceCache,
    relay_forbidden: bool,
) {
    let connect_pid = plan.peer_id.clone();
    let connect_polite = plan.polite;
    let connect_relay = plan.relay_ice;
    let connect_gen = plan.generation;
    // The peer's events wake the loop: the candidate channel is drained only
    // by `pump_builds`, and nothing else turns the loop when a data-channel
    // event lands in it (see `EvSink::waking`).
    let candidate = net::EvSink::waking(candidate, wake.clone(), wake_pending);
    let wake_tx = wake;
    let retry_plan = plan.clone();
    let connect_cfg = plan.config;
    let delay_pid = plan.peer_id.clone();
    let build = async move {
        let mut cfg = match connect_cfg {
            BuildIce::Cached(cfg) => cfg,
            BuildIce::Fetch => match tokio::time::timeout(
                ICE_CONFIG_BUDGET,
                net::fetch_config(&context, &server),
            )
            .await
            {
                Ok(Ok(cfg)) => {
                    lock_ice(&cache).cfg = Some((Instant::now(), cfg.clone()));
                    cfg
                }
                _ if ice_fallback_allowed(connect_relay) => stun_only_ice_config(),
                _ => anyhow::bail!("ICE config: no answer within {ICE_CONFIG_BUDGET:?}"),
            },
        };
        if relay_forbidden {
            cfg.ice_servers.retain(|s| net::is_stun_only(s));
        }
        let delay = test_hooks::establish_delay_ms();
        if delay > 0 {
            filament_transport::hooks::debug(&format!(
                "BUILD-DELAY peer={} ms={delay}",
                delay_pid
            ));
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match tokio::time::timeout(
            PEER_BUILD_BUDGET,
            net::Peer::connect_with_context(
                &context,
                connect_pid,
                my_uid,
                connect_polite,
                cfg.ice_servers,
                connect_relay,
                sio,
                candidate,
                connect_gen,
            ),
        )
        .await
        {
            Ok(Ok(peer)) => Ok(peer),
            Ok(Err(error)) => Err(error),
            Err(_) => anyhow::bail!("building the peer connection took over {PEER_BUILD_BUDGET:?}"),
        }
    };
    tokio::pin!(build);
    let peer = tokio::select! {
        result = &mut build => match result {
            Ok(peer) => peer,
            Err(error) => {
                let _ = out.send(BuildDone::Failed {
                    plan: retry_plan,
                    reason: error.to_string(),
                });
                let _ = wake_tx.send(Ev::BuildWake);
                return;
            }
        },
        _ = cancel.cancelled() => {
            let _ = out.send(BuildDone::Cancelled { plan: retry_plan });
            let _ = wake_tx.send(Ev::BuildWake);
            return;
        }
    };
    let hold = test_hooks::build_hold_ms(&plan.peer_id);
    if hold > 0 {
        filament_transport::hooks::debug(&format!("BUILD-HOLD peer={} ms={hold}", plan.peer_id));
        tokio::time::sleep(Duration::from_millis(hold)).await;
    }
    let source = peer.source();
    let _ = out.send(BuildDone::Ready(BuiltPeer {
        peer_id: plan.peer_id,
        generation: plan.generation,
        source,
        peer,
        info: plan.info,
        name: plan.name,
        uid: plan.uid,
        carried_secret: plan.carried_secret,
        active_on_apply: plan.active_on_apply,
        replace: plan.replace,
        caller: plan.caller,
        prior_generation: plan.prior_generation,
    }));
    let _ = wake_tx.send(Ev::BuildWake);
}

/// One peer's retired build generation. Cancelled generations are terminal:
/// the completion pump will not retry or apply them. Cancellation is per peer,
/// not a global epoch, so retiring A leaves B and C free to build.
#[derive(Clone, Copy)]
pub struct RetiredIntent {
    pub generation: u32,
    pub at: Instant,
}

/// Result of a side-effect-free readiness validation. `Duplicate` means the
/// exact same live or held transport is already owned, so the caller must not
/// close it or mutate state. `Reject` requires closing only the incoming
/// transport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirectReadyCheck {
    Accept {
        source: net::SourceId,
        attempt: net::AttemptId,
    },
    Duplicate,
    Reject,
}

/// Result of a direct readiness adoption. Callers MUST skip all follow-up on
/// Duplicate/Rejected (no worker spawn, identity bind, or readiness re-drive).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DirectAdoption {
    Adopted {
        attempt: net::AttemptId,
        tkey: Option<[u8; 32]>,
    },
    Duplicate,
    Rejected,
}

/// One retired attempt until its terminal-drain barrier is handled.
pub struct RetiredAttempt {
    pub pid: String,
    pub at: Instant,
    /// Set by the drain task only once the attempt's readiness producer is
    /// terminal (its handle returned, by completion or after abort), or at
    /// retirement when there is no async producer. Only a drained tombstone
    /// may be reaped by age; see [`RETIRED_TOMBSTONE_TTL`].
    pub drained: Arc<AtomicBool>,
}

impl RetiredAttempt {
    /// A tombstone whose producer is not yet known terminal.
    pub fn new(pid: impl Into<String>) -> Self {
        Self { pid: pid.into(), at: Instant::now(), drained: Arc::new(AtomicBool::new(false)) }
    }

    /// May the capacity backstop reap this tombstone at `now`? Only when its
    /// producer is terminal AND the drain barrier had the TTL to arrive.
    fn reapable(&self, now: Instant) -> bool {
        self.drained.load(Ordering::Acquire)
            && now.duration_since(self.at) >= RETIRED_TOMBSTONE_TTL
    }
}

pub struct Conn {
    pub transport_context: filament_transport::TransportContext,
    pub server: String,
    pub sio: filament_signal::Client,
    pub tx: mpsc::UnboundedSender<Ev>,
    pub my_uid: String,
    pub my_id: String,
    pub relay_only: bool,
    pub to_filter: Option<String>,
    pub links: SimHashMap<String, Link>,
    pub roster: SimHashMap<String, Value>, // sid -> {id,name,uid} from welcome/peer-joined
    /// Local discovery (`filament_transport::lan`), when it is on for this
    /// session. Set by the loop after construction.
    pub lan: Option<filament_transport::lan::LanService>,
    pub active: Option<String>, // the transfer-target sid (send side)
    /// A code-claimed receive is bound to the peer that completed PAKE. The sid
    /// may change on signaling reconnect, so retain its install uid as well.
    /// Targeting only: authority is `code_session`.
    pub active_binding: Option<(String, Option<String>)>,
    /// The session the code ceremony confirmed (`receive <code>` and
    /// `send --code`): its exact sid, the DTLS fingerprint pair its
    /// confirmation bound, and the ceremony secret. Every code-path accept,
    /// consent and remember decision is `holds_code_authority`, which checks
    /// the peer's CURRENT link against it.
    pub code_session: Option<CodeSession>,
    pub next_gen: u32,
    /// Peer-absence / rejoin-grace state (the reconnect window + declared brb).
    pub rejoin: RejoinState,
    pub chunk_size: usize,
    pub digest: DigestTracker,
    pub sources: SourceRouting,
    /// Gate-18 Mode B: set TRUE by the recv loop, each tick, exactly when the
    /// transfer is COMPLETE and nothing is in flight (`completed>0 &&
    /// by_sid.is_empty() && !keep_open`). When it holds, `on_stuck` DROPS a
    /// stuck/lost link instead of re-establishing it: there is nothing left to
    /// fetch, so reconnect attempts are pointless and a sender that departs
    /// AFTER delivering every byte would otherwise FLAP the link forever
    /// (establish → connect → die → Stuck → establish ...), each cycle resetting
    /// `attempts` (so MAX_ATTEMPTS never caps it) and re-arming `expected_secret`
    /// (so `digest_says_alone` never holds), `conn.links` never empties and the
    /// quiet-exit never fires → RC=124 hang. Dropping the link empties
    /// `conn.links` and lets the quiet-exit fire. Recomputed PER TICK (never
    /// sticky) so a mid-transfer link (`by_sid` non-empty) always reconnects
    /// normally, kill-resume (gate 2) and the #28 deferred-drop (gate 11c)
    /// reconnect paths are untouched. Defaults false, so the send-side and
    /// connecting-phase `on_stuck` callers are unaffected.
    pub recv_done: bool,
    /// rung-1 (TUNLION_DIRECT): in-flight direct-QUIC attempts, keyed by peer
    /// sid. While an attempt is pending we do NOT establish WebRTC for that peer
    /// (sequential, per the design review, avoids two transports racing to
    /// ChannelReady). On deadline expiry with no DirectReady the entry is
    /// dropped and the normal WebRTC `establish` runs; the fallback is unchanged.
    pub retired_attempts: SimHashMap<net::AttemptId, RetiredAttempt>,
    pub direct_pending: SimHashMap<String, DirectPending>,
    /// Peers that explicitly announced `direct:false` (WebRTC-only, e.g. the
    /// browser). Kept OUT of the roster because presence pushes replace roster
    /// entries; this fact must survive every KnownPeer/sync refresh for the
    /// lifetime of the peer's sid.
    pub webrtc_only: SimHashSet<String>,
    /// Bug 2: transport-offers that arrived before the receiver's DirectPending
    /// was created (peer's re-dial after a mid-transfer death). Same class as Bug
    /// 1 (pre-PAKE offers): buffered here and replayed once a pending OR a link
    /// for that peer appears: `start_direct` replays it into the new pending,
    /// and installing a built link re-queues it through the driver's ordinary
    /// transport-offer handler (`install_built`). pid → (candidates, srflx,
    /// server_public, proto, ch) plus the intent/link facts captured when it
    /// was buffered (`StagedOffer`). Insert only through `buffer_offer`.
    pub buffered_offers: SimHashMap<String, StagedOffer>,
    /// WebRTC offers (and their candidates) held while a direct attempt for the
    /// same sid is pending; replayed into the fallback responder's build. Insert
    /// only through `hold_for_direct`. `pub` only because the CLI builds a
    /// `Conn` with a struct literal (cli/src/membership.rs); its contents stay
    /// private, so start it as `HashMap::new()` and never insert directly.
    pub held_signals: SimHashMap<String, HeldSignals>,
    /// Post-PAKE promotions in progress (make-before-break; see `handoff`),
    /// keyed by peer sid. Each pairs with an ephemeral `direct_pending` entry
    /// that must survive beside the serving link until the handoff resolves.
    pub promotions: SimHashMap<String, PromoteState>,
    /// RESILIENCE bookkeeping (stall/relay/warm/upgrade); see ResilienceState.
    pub resil: ResilienceState,
    /// Is the rung-1 direct-QUIC path allowed for THIS session? Normally this is
    /// just `direct::direct_enabled()` (the TUNLION_DIRECT/TUNLION_L2 env gate),
    /// but ANY long-lived acceptor must ALSO take it even when those env vars are
    /// unset: the L2/ssh ACCEPTOR (`up --shell`) AND the plain `up` daemon. An
    /// acceptor that doesn't silently drops the initiator's `transport-offer` AND
    /// builds its own WebRTC peer dialing back, colliding with the initiator's
    /// offer (GLARE), which for `up --shell` stalls at "stuck while connecting" and
    /// for a plain `up` (two mutually-known daemons) loops the supersede churn and
    /// never settles to one link. Answering the direct dial instead is sequential,
    /// authenticated, and rides the reachable host candidate (e.g. the Tailscale
    /// link), so it neither glares nor depends on cross-NAT ICE. Set via
    /// `direct_ok_for`; `start_direct_inner` gates on this instead of the bare env
    /// check. One-shot send/recv/pair keep the bare `direct_enabled()` default.
    pub direct_ok: bool,
    /// Local transport for same-machine peers.
    pub local_port: Option<u16>,
    pub local_listener: Option<Arc<tokio::net::TcpListener>>,
    /// Shared direct-QUIC endpoint, cloned from the originating Endpoint so that
    /// worker connections for multi-stream transfers can be dialled (sender side)
    /// or accepted (receiver side) without racing the winner's keepalive closure.
    /// Set once in `start_direct_inner`; `None` when direct is not in use, or
    /// when multi-streaming is disabled (`direct_streams() == 1`).
    pub direct_endpoint: Option<direct::BoundEndpoint>,
    /// WARM-HOLD: keeps connections alive to recently-used and explicitly
    /// configured peers so `tunlion reach`/`ssh` is instant. Tracked per-peer
    /// with LRU eviction and exponential backoff on failures.
    pub warm_hold: WarmHold,
    /// Oneshot senders for per-endpoint worker port negotiation, keyed by pid.
    /// The dialer-side `spawn_direct_workers` stores a sender here; the
    /// `worker-ports` control message handler delivers the acceptor's port list
    /// through it. Removed by the receiver on delivery (one-shot).
    pub worker_port_tx: HashMap<String, oneshot::Sender<Vec<u16>>>,
    /// Retry ladder: the stuck attempt per peer sid whose backoff timer is
    /// running. `on_stuck` records it and returns; `Ev::RetryLink` resumes it.
    pub stuck_retry: SimHashMap<String, StuckRetry>,
    /// Last good ICE config and when it was fetched, so an establish does not
    /// block the event loop on the config GET (see `ice_config`). Shared with
    /// the off-loop refresh task.
    pub ice_cache: SharedIceCache,
    /// Off-loop WebRTC build lifecycle: one bounded task per peer, a deferred
    /// intent map for the global cap, and the completion channel the drivers
    /// pump each iteration. No driver holds a lock across a build await.
    pub builds: SimHashMap<String, BuildState>,
    pub build_deferred: std::collections::BTreeMap<String, (BuildPlan, Instant)>,
    pub build_tx: mpsc::UnboundedSender<BuildDone>,
    pub build_rx: std::sync::Mutex<mpsc::UnboundedReceiver<BuildDone>>,
    /// Pair bindings and active intent captured by the caller before a build
    /// starts, applied only when the candidate is installed.
    pub pending_bindings: SimHashMap<String, (String, String)>,
    pub pending_active: SimHashSet<String>,
    /// Per-peer intent generations retired by cancel/drop/peer-left/reap. A
    /// Ready or Failed completion at or below the retired generation is dead:
    /// a queued failure cannot retry a peer that already left, and an older
    /// completion cannot remove a newer intent. A fresh intent gets a higher
    /// `next_gen`, so cancelling one peer never blocks another.
    pub cancelled_intents: SimHashMap<String, RetiredIntent>,
    /// The generation of the newest intent prepared for each pid. Any older
    /// spawn/deferred retry/apply is stale, so a re-pair supersedes an older
    /// retry instead of racing it.
    pub current_intent: SimHashMap<String, u32>,
    /// Peers whose current intent was explicitly forgotten/revoked, with the
    /// generation retired. A same-pid rebuild is refused unless it carries a
    /// fresh authorized binding; a new-signaling-session pid is a new peer.
    pub revoked_peers: SimHashMap<String, RetiredIntent>,
    /// Stable device secrets the store has forgotten. A build carrying one is
    /// refused regardless of pid, so a reconnect cannot re-use a stale label;
    /// only an authenticated re-pair/vouch clears that exact secret. Fleet
    /// rendezvous secrets are NOT device identities and never enter this set.
    pub revoked_bindings: SimHashSet<String>,
    /// Set by a candidate sender when it has queued a `BuildWake`, cleared by
    /// `pump_builds` before it drains. One wake is outstanding at a time, so a
    /// busy data channel cannot flood the main queue with wakes.
    pub candidate_wake: Arc<AtomicBool>,
    /// Direct attempts whose candidates are still being gathered off the
    /// loop, keyed by pid (`start_direct_inner`, `apply_direct_gathered`).
    pub direct_gathering: HashMap<String, DirectGathering>,
    /// Finished gatherings, drained by `pump_builds`.
    pub direct_gathered: Arc<std::sync::Mutex<Vec<DirectGathered>>>,
    /// The injected terminal sink. Every line `Conn` renders goes through this
    /// instead of `crate::ui`, so the host can be a test capture or a daemon
    /// journal. See `filament_peerloop::host`.
    pub log: Arc<dyn LogSink>,
    /// The injected host facts. Every settings/devices/keystore/roster/relay
    /// read goes through this instead of a CLI import, so this state has no
    /// back-edge into the CLI and can later `git mv` into the crate.
    pub host: Arc<dyn HostServices>,
    /// The injected terminal presentation. The sticky line, a waiting question,
    /// transfer bars, OSC 52 and the raw-mode echo go through this instead of
    /// `cli::ui`, so a screen-less consumer gets the same loop with `NoScreen`.
    /// See `filament_peerloop::present`.
    pub present: Arc<dyn Presentation>,
}

/// The cached ICE config (see `Conn::ice_config`).
#[derive(Default)]
pub struct IceCache {
    pub cfg: Option<(Instant, net::ServerConfig)>,
    refreshing: bool,
}
pub type SharedIceCache = Arc<std::sync::Mutex<IceCache>>;

/// Poison-tolerant: a panicked refresh task must not wedge every establish.
fn lock_ice(cache: &SharedIceCache) -> std::sync::MutexGuard<'_, IceCache> {
    cache.lock().unwrap_or_else(|e| e.into_inner())
}

/// A stuck link whose retry is scheduled (see `Conn::on_stuck`).
pub struct StuckRetry {
    /// Generation of the stuck attempt. The retry fires only if the link still
    /// carries it: a link replaced or recovered meanwhile makes it stale.
    pub generation: u32,
    /// Attempt number the retry will be (already counted against MAX_ATTEMPTS).
    pub attempts: u32,
}

/// What principal a relay->direct upgrade's rebuilt Link should carry.
///
/// Extracted as a PURE fn so the invariant is testable: `Conn::for_command`
/// needs a live socket.io client, so the calling method cannot be unit-tested,
/// and before this the only check on the rule was reading it.
///
/// The rule: carry the pre-upgrade principal. `adopt_direct_transport` used to
/// hardcode `(true, OwnerDevice)`, so an upgrade PROMOTED any link to
/// owner-equivalence, the escalation `adopt_direct` fail-safes against and whose
/// comment records a REVOKED device delivering a file. `None` keeps the old
/// default, since it means the link vanished and that is a separate question.
pub fn upgrade_principal(
    carried: &Option<(bool, PrincipalKind)>,
) -> (bool, PrincipalKind) {
    match carried {
        Some((trusted, kind)) => (*trusted, kind.clone()),
        None => (true, PrincipalKind::OwnerDevice),
    }
}

/// The TCP-localhost transport for two processes of ONE install (c6100a6d) is
/// unfinished, so it stays off. Its offer advertised a listener that nothing
/// ever `accept`s, and the offer's receiver returned before trying it because a
/// local pending carries no QUIC endpoint (`on_transport_offer` takes one or
/// returns). Every same-install promotion therefore dropped its working WebRTC
/// link, waited out DIRECT_BUDGET with nothing dialled, and re-established
/// WebRTC: measured in CI, a 5 MiB code transfer between two processes sharing
/// a config dir took 31 s, 8 runs of 8, each with DIRECT-FALLBACK on both ends.
/// Those peers now take the same authenticated QUIC race as any other pair
/// (their session ids differ, so role election holds). It is also unencrypted
/// and unauthenticated, which a finished version would have to answer first.
const LOCAL_TCP_TRANSPORT: bool = false;

/// Resolve `peer` (matched case-insensitively on the PROVEN `verified_name`, or
/// on an exact authenticated LAN DEVICE reservation that is still the current
/// store's binding) to a warm, alive link, preferring a direct one and then the
/// longest-lived (so a fresh one-shot `exec` link cannot displace the daemon's
/// stable link). The single resolver for every warm-reuse op (open + pty), so
/// the eligibility rule lives in exactly one place. A miss means the caller
/// falls back to a fresh establish, which is correct. Routing only: permission
/// is still the receiving capability gate's decision.
///
/// Moved here from `cli/src/daemon_ctl.rs`; it takes a [`Conn`] and returns a
/// transport pair, both of which this crate owns. The body now also resolves an
/// exact authenticated LAN DEVICE reservation (routing only; the link stays
/// untrusted and un-Proven).
#[cfg_attr(not(unix), allow(dead_code))]
pub fn warm_link_for(conn: &Conn, peer: &str) -> Option<(String, Arc<dyn Transport>)> {
    // Eligibility is "do I know WHO this link reaches", because the caller is
    // asking to route a request AT that peer. `l.trusted` is a narrower thing:
    // the legacy blanket-trust flag, which a fleet link deliberately never sets
    // (its identity comes from a verified certificate, and `admit_delegated`
    // avoids `trusted` precisely so it cannot leak into the legacy_ok gates).
    // Testing only `trusted` made every fleet sibling ineligible for the warm
    // path, so `shell`/`open` fell through to a cold dial for a peer we hold no
    // secret for and reported it as unreachable while a healthy link sat right
    // there. A Proven identity binding answers the actual question.
    // NOTE: this decides ROUTING, not permission. What the peer may do to us is
    // still decided by the capability gate on the receiving side.
    // LAN device reservations are resolved here, once, from the CURRENT store
    // and the session's revoked set. They are routing names only (see
    // `Link::authenticated_device_name`); the link itself stays untrusted and
    // carries no capability. One observation per link, so the name and its pid
    // can never be paired from different iterations.
    let devices = conn.host.devices_load();
    let observed: Vec<(&str, &Link, Option<String>)> = conn
        .links
        .iter()
        .map(|(pid, l)| {
            (
                pid.as_str(),
                l,
                l.authenticated_device_name(
                    &devices,
                    &conn.revoked_bindings,
                    &|name: &str| conn.host.device_record_revoked(name),
                )
                .map(str::to_string),
            )
        })
        .collect();
    let links: Vec<LinkObs<'_>> = observed
        .iter()
        .map(|(pid, l, lan_device_name)| LinkObs {
            pid: *pid,
            verified_name: l.verified_name.as_deref(),
            identity_known: l.trusted || l.identity_binding == BindingStrength::Proven,
            lan_device_name: lan_device_name.as_deref(),
            has_transport: l.transport.is_some(),
            alive: l
                .transport
                .as_ref()
                .is_some_and(|t| t.is_alive() && !t.is_dead()),
            direct: l.direct,
            idle_ms: l.transport.as_ref().map_or(u64::MAX, |t| t.idle_ms()),
            age_ms: l.established_at.map(|t| t.elapsed().as_millis() as u64),
        })
        .collect();
    match place(Work::Interactive, peer, &links) {
        Placement::Reuse { pid } => {
            let t = conn.links.get(&pid)?.transport.clone()?;
            Some((pid, t))
        }
        Placement::Establish => None,
    }
}

impl Conn {
    /// Single constructor for the `pair`/`send`/`recv` command event loops, which
    /// built the identical ~17-field `Conn` literal three times (the only
    /// per-command differences are `relay_only`, `to_filter`, and the
    /// warm-standby default). Everything else is the fixed fresh-session state.
    /// `warm_standby_default` is the per-session-kind default that the
    /// `TUNLION_WARM_STANDBY` override (via `net::warm_standby_override`) can
    /// still force either way. NOTE: the long-lived `up` daemon loop keeps its
    /// own literal on purpose, it is a different (non-command) session.
    ///
    /// `transport_context` is the engine-owned transport settings/membership/DNS
    /// and public-IP state for every foreground and detached task this session
    /// starts. `HostServices` remains a separate (partly process-root) seam.
    pub fn for_command(
        transport_context: filament_transport::TransportContext,
        server: &str,
        sio: filament_signal::Client,
        tx: mpsc::UnboundedSender<Ev>,
        my_uid: String,
        relay_only: bool,
        to_filter: Option<String>,
        warm_standby_default: bool,
        direct_ok: bool,
        log: Arc<dyn LogSink>,
        host: Arc<dyn HostServices>,
    ) -> Self {
        let (build_tx, build_rx) = mpsc::unbounded_channel();
        Conn {
            transport_context,
            server: server.to_string(),
            sio,
            tx,
            my_uid,
            my_id: String::new(),
            relay_only,
            to_filter,
            links: SimHashMap::default(),
            roster: SimHashMap::default(),
            active: None,
            active_binding: None,
            code_session: None,
            next_gen: 0,
            rejoin: RejoinState {
                waiting_rejoin: None,
                rejoin_window: REJOIN_WINDOW,
                away: None,
            },
            chunk_size: net::MAX_DC_PAYLOAD,
            digest: DigestTracker::default(),
            sources: SourceRouting::default(),
            recv_done: false,
            direct_pending: SimHashMap::default(),
            retired_attempts: SimHashMap::default(),
            lan: None,
            webrtc_only: SimHashSet::default(),
            buffered_offers: SimHashMap::default(),
            held_signals: SimHashMap::default(),
            promotions: SimHashMap::default(),
            resil: ResilienceState {
                stall_repairs: SimHashMap::default(),
                relay_committed: SimHashSet::default(),
                warm_standby: net::warm_standby_override().unwrap_or(warm_standby_default),
                warm_cutover: SimHashSet::default(),
                upgrade_probe: SimHashMap::default(),
                iface_snapshot: Vec::new(),
                in_flight_since: SimHashMap::default(),
            },
            direct_ok: direct_permitted(relay_only, direct_ok),
            local_port: None,
            local_listener: None,
            direct_endpoint: None,
            warm_hold: WarmHold::default(),
            worker_port_tx: HashMap::new(),
            stuck_retry: SimHashMap::default(),
            ice_cache: SharedIceCache::default(),
            builds: SimHashMap::default(),
            build_deferred: std::collections::BTreeMap::new(),
            build_tx,
            build_rx: std::sync::Mutex::new(build_rx),
            pending_bindings: SimHashMap::default(),
            pending_active: SimHashSet::default(),
            cancelled_intents: SimHashMap::default(),
            current_intent: SimHashMap::default(),
            revoked_peers: SimHashMap::default(),
            revoked_bindings: SimHashSet::default(),
            candidate_wake: Arc::new(AtomicBool::new(false)),
            direct_gathering: HashMap::new(),
            direct_gathered: Arc::new(std::sync::Mutex::new(Vec::new())),
            log,
            host,
            present: Arc::new(NoScreen),
        }
    }

    /// Install the session's terminal presentation. The constructor leaves the
    /// inert [`NoScreen`] so a caller that renders nothing (a daemon journal, a
    /// library consumer, a test) is silent by default; the CLI command loop
    /// replaces it with its `ui` adapter, keeping the bytes identical.
    pub fn with_presentation(mut self, present: Arc<dyn Presentation>) -> Self {
        self.present = present;
        self
    }

    pub fn link(&self, pid: &str) -> Option<&Link> {
        self.links.get(pid)
    }

    /// A NAME for this peer to show a person, never its signaling id: the
    /// link's label, else the name the server listed it under, when either is
    /// a name rather than an id. `None` when nothing but an id is known (a link
    /// built from a bare signal is filed under its id). DISPLAY only.
    pub fn display_name_of(&self, pid: &str) -> Option<String> {
        let uid = self.links.get(pid).and_then(|l| l.uid.clone()).or_else(|| {
            self.roster.get(pid).and_then(|r| r["uid"].as_str().map(String::from))
        });
        let named = |n: &str| {
            (!n.is_empty()
                && !label_is_raw_id(n, pid, uid.as_deref())
                && !self.links.contains_key(n))
            .then(|| n.to_string())
        };
        self.links
            .get(pid)
            .and_then(|l| named(l.label()))
            .or_else(|| self.roster.get(pid).and_then(|r| r["name"].as_str()).and_then(named))
    }
    pub fn link_mut(&mut self, pid: &str) -> Option<&mut Link> {
        self.links.get_mut(pid)
    }
    fn active_link(&self) -> Option<&Link> {
        self.active.as_ref().and_then(|a| self.links.get(a))
    }
    pub fn is_active(&self, pid: &str) -> bool {
        self.active.as_deref() == Some(pid)
    }
    /// The gate-relevant identity fact for `pid`. A missing link is Pending,
    /// never anonymous: only an explicit identity-unavailable answer sets the
    /// anonymous state, and it is stored on the link that received it.
    pub fn identity_state_of(&self, pid: &str) -> IdentityState {
        self.links
            .get(pid)
            .map(|l| l.identity_state)
            .unwrap_or(IdentityState::Pending)
    }
    pub fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.active_link().and_then(|l| l.transport.clone())
    }
    pub fn transport_of(&self, pid: &str) -> Option<Arc<dyn Transport>> {
        self.links.get(pid).and_then(|l| l.transport.clone())
    }

    /// The transports to answer a frame from `pid` on: the one whose source
    /// carried it (the primary, or a worker), then the link's current primary
    /// if that is a different one. Empty when the link is gone.
    pub fn reply_transports(
        &self,
        pid: &str,
        source: Option<net::SourceId>,
    ) -> Vec<Arc<dyn Transport>> {
        let Some(link) = self.links.get(pid) else {
            return Vec::new();
        };
        let carrying = match source {
            Some(s) if s == link.source => link.transport.clone(),
            Some(s) => link.workers.iter().find(|w| w.source_id() == Some(s)).cloned(),
            None => None,
        };
        let mut out: Vec<Arc<dyn Transport>> = carrying.into_iter().collect();
        if let Some(primary) = link.transport.clone() {
            if !out.iter().any(|t| Arc::ptr_eq(t, &primary)) {
                out.push(primary);
            }
        }
        out
    }

    /// #28: is the link keyed by `pid` actively moving transfer bytes right now?
    /// The data channel is independent of the signaling socket, so when a
    /// same-uid reconnect arrives as a new sid, superseding must NOT tear down
    /// an old link that's still flowing. A frozen-alive peer (gate 11's
    /// SIGSTOP'd receiver) stops stamping activity, so it reads as not-flowing.
    /// This is deliberately NOT the whole keep test any more: an idle shell is
    /// also not-flowing but is not broken. `old_link_survives_reconnect` asks
    /// the transport, and uses this only to protect an in-flight transfer.
    /// Threshold is overridable for deterministic gating
    /// (TUNLION_ADOPT_ACTIVE_MS); the 3 s default sits well above a healthy
    /// sub-100 ms inter-frame gap so a transient ICE blip can't masquerade as
    /// idle and let a spurious supersede through.
    fn link_flowing(&self, pid: &str) -> bool {
        let threshold = std::env::var("TUNLION_ADOPT_ACTIVE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3000);
        self.transport_of(pid)
            .map(|t| t.idle_ms() < threshold)
            .unwrap_or(false)
    }

    /// C6/#28: may a same-uid reconnect leave `pid`'s existing link in place?
    ///
    /// This asks whether the TRANSPORT is still usable, not whether bytes moved
    /// in the last three seconds. `link_flowing` alone used to answer this, so
    /// every quiet-but-healthy link read as supersedable: a cosmetic signaling
    /// reconnect dropped an idle shell's direct link and the pty had to
    /// reattach. A shell that is sitting at a prompt is idle, not dead, and
    /// signaling is independent of the data plane.
    ///
    /// Two constraints keep the old behaviour where it was earning its keep:
    ///
    /// * A dead, absent or half-closed transport is never kept. `peer_present`
    ///   additionally rejects a relay link that stopped hearing the peer: relay
    ///   has no QUIC keepalive, only the 5 s application keepalive, so 8 s of
    ///   silence is a dead path (the relay stale window is owned by the link
    ///   manager, not repeated here).
    /// * A transfer that is IN FLIGHT is protected only while it is moving. If
    ///   it has gone quiet, the reconnect is the recovery path: that is the
    ///   frozen-receiver supersede gate 11 asserts. Without this clause an idle
    ///   shell and a SIGSTOPped receiver would look identical here.
    ///
    /// The deferral is bounded by the transport, not by a timer we invent.
    /// Direct QUIC closes a departed peer at its 21 s idle timeout (7 s
    /// keepalive); a relay path stops passing `peer_present` after 8 s without
    /// the peer's keepalive. The daemon's 8 s dead-link sweep then drops the
    /// link and the next KnownPeer/warm-hold tick rebuilds it under the new sid.
    /// A fixed grace shorter than the idle lifetime would recreate this bug; a
    /// longer one would be an arbitrary number of minutes.
    fn old_link_survives_reconnect(&self, pid: &str) -> bool {
        let Some(l) = self.links.get(pid) else {
            return false;
        };
        let Some(t) = l.transport.as_ref() else {
            return false;
        };
        // `is_alive` and `is_dead` answer different questions on a direct link:
        // a primary whose peer ended its send half is still "alive" for writes
        // but can never receive again, so it must not survive a reconnect.
        let alive = t.is_alive() && !t.is_dead();
        let usable = alive && peer_present(alive, l.direct, t.heard_ms(), t.idle_ms());
        if !usable {
            return false;
        }
        if self.link_flowing(pid) {
            return true; // actively moving bytes: #28's original keep
        }
        // Quiet. With nothing in flight this is an idle link, not a broken one.
        // With a transfer in flight and no bytes moving it is stalled, and the
        // reconnect should replace it.
        !self.resil.in_flight_since.contains_key(pid)
    }

    /// A spent code authorizes exactly the peer its PAKE ceremony confirmed.
    /// A same-device signaling reconnect (same install uid, new sid) is not a
    /// replacement receiver, but it must not churn a live link either (#28):
    /// when the code peer's link is still usable, keep it and say so. Returns
    /// true when the reconnect was deliberately kept; false (including a dead
    /// or stalled link) means the caller must refuse the new sid, never
    /// supersede to it.
    pub fn code_reconnect_kept(&self, ceremony_peer: &str, peer_uid: Option<&str>) -> bool {
        let Some(uid) = peer_uid else {
            return false;
        };
        let Some(old) = self.links.get(ceremony_peer) else {
            return false;
        };
        if old.uid.as_deref() != Some(uid) {
            return false; // a different device, not this code's receiver
        }
        let name = old.name.clone();
        if self.old_link_survives_reconnect(ceremony_peer) {
            self.log
                .debug(&format!("{name} reconnected, keeping active link"));
            return true;
        }
        self.log.debug(&format!(
            "{name} reconnected on a spent code; refusing to replace the authenticated receiver"
        ));
        false
    }

    /// Attach a freshly-opened channel to its link and mark the peer Ready.
    ///
    /// Every `Ev::ChannelReady` arm opened with these same few lines, copied
    /// eight times with three different formattings. The tails genuinely differ
    /// per command, but this prologue never did, and a prologue that is retyped
    /// per call site is one that can drift per call site.
    ///
    /// `claim_active` asks for the peer to become the target if no target exists
    /// yet. Attaching the transport happens FIRST either way: claiming the slot
    /// while the link has no transport hands the caller a target it cannot send
    /// to. Returns true if this peer is now the active one.
    pub fn mark_ready(
        &mut self,
        pid: &str,
        t: &Arc<dyn Transport>,
        claim_active: bool,
    ) -> bool {
        if let Some(l) = self.link_mut(pid) {
            l.transport = Some(t.clone());
            l.presence = Presence::Ready;
        }
        // A promotion's lead end may have authenticated before its channel
        // opened; the transfer it is about to start must ride the gate.
        self.gate_for_promotion(pid);
        if claim_active && self.active.is_none() {
            self.active = Some(pid.to_string());
        }
        self.active.as_deref() == Some(pid)
    }

    /// May this peer become the TRANSFER TARGET? (Filters gate targeting,
    /// never answering, every peer still gets a polite link.) The rule is
    /// `filament_peerloop::peer_targetable`, unit-tested there; this method only
    /// reads the two fields it needs off `Conn`.
    fn targetable(&self, name: &str, peer_uid: Option<&str>) -> bool {
        peer_targetable(self.to_filter.as_deref(), &self.my_uid, name, peer_uid)
    }

    fn adoption_allowed(&mut self, peer_id: &str, source: AdoptSource) -> bool {
        match_adoption_source(&mut self.digest.suppressed_digest_adoptions, peer_id, source)
    }

    pub fn bind_active(&mut self, peer_id: &str) {
        let uid = self
            .links
            .get(peer_id)
            .and_then(|link| link.uid.clone())
            .or_else(|| {
                self.roster
                    .get(peer_id)
                    .and_then(|peer| peer["uid"].as_str().map(String::from))
            });
        self.active_binding = Some((peer_id.to_string(), uid));
        self.active = Some(peer_id.to_string());
        self.rejoin.waiting_rejoin = None;
    }

    /// Record the session a code ceremony confirmed with `sid`: the DTLS
    /// fingerprint pair `(mine, theirs)` its confirmation MAC bound, the
    /// ceremony secret, and the direct attempt its promotion armed
    /// (`start_direct_promote`, called just before; none when it armed
    /// nothing). Set once: a run confirms one ceremony, and a later call
    /// never moves the session to another sid or transport.
    pub fn bind_code_session(&mut self, sid: &str, fingerprints: (&str, &str), secret: &str) {
        if self.code_session.is_some() {
            self.log
                .debug("tunlion: code session already bound; keeping the confirmed one");
            return;
        }
        let promote_attempt = self
            .direct_pending
            .get(sid)
            .filter(|pending| pending.ephemeral)
            .map(|pending| pending.attempt);
        self.code_session = Some(CodeSession::new(sid, fingerprints, secret, promote_attempt));
    }

    /// Code authority for `pid` on its CURRENT link (`code_authority_check`):
    /// the exact sid the ceremony confirmed, on a WebRTC link whose DTLS
    /// fingerprints are the confirmed pair or the direct link that ceremony's
    /// own promotion attempt published with its secret. A uid, a roster
    /// entry or a replacement transport for the same sid is not enough.
    pub async fn code_authority(&self, pid: &str) -> Result<(), CodeAuthorityRefusal> {
        let fps = match self.links.get(pid) {
            Some(l) if !l.direct => match &l.peer {
                Some(p) => p.fingerprints().await,
                None => None,
            },
            _ => None,
        };
        self.code_authority_on(pid, fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str())))
    }

    /// [`Conn::code_authority`] once a WebRTC link's DTLS fingerprints have
    /// been read (`webrtc_fps`, ignored for a direct link).
    fn code_authority_on(
        &self,
        pid: &str,
        webrtc_fps: Option<(&str, &str)>,
    ) -> Result<(), CodeAuthorityRefusal> {
        let transport = match self.links.get(pid) {
            None => CodeTransport::Absent,
            Some(l) if l.direct => CodeTransport::Direct {
                attempt: l.attempt,
                secret: l.expected_secret.as_ref().map(|(_, s)| s.as_str()),
            },
            Some(_) => CodeTransport::WebRtc(webrtc_fps),
        };
        code_authority_check(self.code_session.as_ref(), pid, transport)
    }

    /// [`Conn::code_authority`] as a decision, logging why at debug when it
    /// is refused (never the fingerprints or the secret).
    pub async fn holds_code_authority(&self, pid: &str) -> bool {
        match self.code_authority(pid).await {
            Ok(()) => true,
            Err(why) => {
                self.log.debug(&format!(
                    "tunlion: code authority refused for {pid}: {}",
                    why.reason()
                ));
                false
            }
        }
    }

    /// Continuation of a code transfer is bound to the code-authorized link.
    /// Only a holding verdict is cached, keyed by the link's generation,
    /// source, kind, attempt and secret digest.
    pub async fn code_continuation(
        &self,
        pid: &str,
        cache: &mut CodeAuthorityCache,
    ) -> CodeContinuation {
        let Some(l) = self.links.get(pid) else {
            return CodeContinuation::NoLink;
        };
        let secret_tag = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            l.expected_secret.as_ref().map(|(_, s)| s.as_str()).hash(&mut h);
            h.finish()
        };
        let key = CodeLinkKey {
            generation: l.generation,
            source: l.source,
            direct: l.direct,
            attempt: l.attempt,
            secret_tag,
        };
        if cache.held.as_ref().is_some_and(|(p, k)| p == pid && *k == key) {
            return CodeContinuation::Holds;
        }
        if self.holds_code_authority(pid).await {
            cache.held = Some((pid.to_string(), key));
            CodeContinuation::Holds
        } else {
            cache.held = None;
            CodeContinuation::Lost
        }
    }

    /// Track a roster entry and (re)connect to it. `want_active` marks it as
    /// the intended transfer target if it passes the target filters and no
    /// target exists yet. Returns true if this peer is (now) the active one.
    pub async fn maybe_adopt(&mut self, v: &Value, want_active: bool) -> Result<bool> {
        self.maybe_adopt_from(v, want_active, AdoptSource::Contact)
            .await
    }

    pub async fn maybe_adopt_from(
        &mut self,
        v: &Value,
        want_active: bool,
        source: AdoptSource,
    ) -> Result<bool> {
        let peer_id = v["id"].as_str().unwrap_or_default().to_string();
        let peer_uid = v["uid"].as_str().map(|s| s.to_string());
        let name = v["name"].as_str().unwrap_or("peer").to_string();
        if peer_id.is_empty() || peer_id == self.my_id {
            return Ok(false);
        }
        if !self.adoption_allowed(&peer_id, source) {
            return Ok(false);
        }
        if test_hooks::fail_adopt() {
            anyhow::bail!("ICE config: injected adoption failure (TUNLION_TEST_FAIL_ADOPT)");
        }
        // NOTE: same-install peers (our own daemon) are filtered at the
        // KnownPeer call sites, NOT here, room discovery must keep working
        // between two processes of one machine (loopback self-send is the
        // first thing every new user tries).
        self.roster.insert(peer_id.clone(), v.clone());
        self.log.debug(&format!(
            "tunlion: ADOPT peer={peer_id} source={source:?} want_active={want_active}"
        ));

        // C6: same device on a NEW sid, supersede the stale link.
        let stale: Option<String> = self
            .links
            .iter()
            .find(|(sid, l)| l.uid.is_some() && l.uid == peer_uid && **sid != peer_id)
            .map(|(sid, _)| sid.clone());
        if let Some(old_sid) = stale {
            // #28/C6: the same device reconnected its signaling socket (fresh
            // sid). That is COSMETIC while the old link's transport can still
            // carry bytes: an idle shell at a prompt is alive, even though no
            // byte moved recently. Only a dead/absent/quiet-relay transport, or
            // a transfer that went quiet mid-flight, justifies a supersede.
            if self.old_link_survives_reconnect(&old_sid) {
                // Observable so a gate can assert the keep happened (true
                // positive), not merely that no supersede line appeared. The
                // old sid keeps serving and no link is created for the new sid.
                self.log.debug(&format!("{name} reconnected, keeping active link"));
                return Ok(self.is_active(&old_sid));
            }
            self.log.debug(&format!("{name} reconnected, superseding old link"));
            let was_active = self.is_active(&old_sid);
            let secret = self
                .links
                .get(&old_sid)
                .and_then(|l| l.expected_secret.clone());
            self.drop_link(&old_sid);
            if let Some((name, secret)) = &secret {
                self.note_binding(&peer_id, (name.clone(), secret.clone()));
            }
            if was_active {
                self.note_active(&peer_id);
            }
            self.establish_as(v.clone(), None).await?;
            return Ok(self.is_active(&peer_id));
        }

        if !self.links.contains_key(&peer_id) {
            if self.links.len() >= MAX_LINKS && !self.evict_retrying_link(&peer_id) {
                self.log.debug(&format!(
                    "tunlion: ADOPT-REFUSED peer={peer_id}: link cap ({MAX_LINKS}) reached"
                ));
                return Ok(false);
            }
            self.establish_as(v.clone(), None).await?;
        } else if let Some(binding) = self.pending_bindings.get(&peer_id).cloned() {
            // The establish below is skipped because a link already exists, so
            // this is the LAST chance to act on the claim: a live link with no
            // binding yet cannot claim the target slot and would otherwise
            // never be announced again. Reuse it -- bind the store-authorized
            // device and re-announce the transport it serves, with that
            // transport's own immutable source. No-op once the link is bound.
            self.claim_live_unbound_link(&peer_id, Some(binding));
        }
        // #28: a deferred-active slot is claimable. When the active link got a
        // peer-left but is still flowing, we keep `active` pointing at it (so a
        // same-uid reconnect's supersede still sees it active, and the live
        // transfer's offer/exit machinery is undisturbed). But a DIFFERENT-uid
        // replacement (gate 2: hard-killed receiver, fresh recv) must still be
        // able to take over, otherwise the deferred link squats the slot until
        // the reap, and the replacement (whose ChannelReady already fired) never
        // gets promoted or offered the file. Treating a deferred active as
        // "claimable" promotes the replacement at peer-joined, before its
        // ChannelReady, so the offer goes out on the same baseline path.
        let active_deferred = self
            .active
            .as_ref()
            .is_some_and(|a| self.digest.deferred_left.contains_key(a));
        // A code-receive binding hands the slot only to the exact sid whose
        // ceremony confirmed; a new sid (even the same install) needs a fresh
        // code. No binding (every non-code path): unchanged.
        let binding_allows = self
            .active_binding
            .as_ref()
            .is_none_or(|binding| active_binding_matches(binding, &peer_id));
        if want_active && !binding_allows {
            self.log.debug("tunlion: ADOPT refused: peer is not the authenticated code sender");
        }
        if want_active
            && binding_allows
            && (self.active.is_none() || active_deferred)
            && self.targetable(&name, peer_uid.as_deref())
        {
            // Claiming the slot from a deferred link: discharge that link now
            // (it left the room and is being replaced) so reap doesn't later
            // re-inject a stale peer-left against the slot the new peer holds.
            if active_deferred {
                if let Some(old) = self.active.clone() {
                    if old != peer_id {
                        self.drop_link(&old);
                    }
                }
            }
            self.active = Some(peer_id.clone());
            self.rejoin.waiting_rejoin = None;
        }
        Ok(self.is_active(&peer_id))
    }

    /// Buffer a transport-offer that found no pending for `pid`, recording the
    /// peer's current intent generation and whether a link already existed.
    /// `start_direct` replays it into the next pending unchanged; the
    /// install-time replay (`install_built`) uses the recorded facts to replay
    /// only an offer that predates every link of this pid and belongs to the
    /// candidate being installed. A later offer for the same pid replaces it.
    pub fn buffer_offer(&mut self, pid: &str, offer: BufferedOffer) {
        let staged = StagedOffer {
            offer,
            intent: self.current_intent.get(pid).copied(),
            linked: self.links.contains_key(pid),
        };
        self.buffered_offers.insert(pid.to_string(), staged);
    }

    /// A link is "live" if its primary transport or any worker is still alive,
    /// or its WebRTC peer is still making progress (#246). Restored: the
    /// pending-only guard made it briefly dead, but promotion intent needs it
    /// back. Every caller EXCEPT a deliberate promotion must leave a live link
    /// alone, which is what warm-hold depends on.
    fn has_live_transport(&self, pid: &str) -> bool {
        self.links
            .get(pid)
            .map(|l| {
                // #246: a link mid-establish (peer present, ICE still working
                // toward Connected) is making progress even before any
                // transport/worker exists. Counting it as live is what lets a
                // Normal re-dial yield to the in-flight establish instead of
                // arming a fresh direct attempt whose 5s fallback timer then
                // tears that establish down at the moment it is about to win.
                let peer_live = l.peer.as_ref().map(|p| p.is_live()).unwrap_or(false);
                let primary_ok = l.transport.as_ref().map(|t| !t.is_dead()).unwrap_or(false);
                let workers_ok = l.workers.iter().any(|w| !w.is_dead());
                link_has_live_for(peer_live, primary_ok, workers_ok)
            })
            .unwrap_or(false)
    }

    /// Does a link to `pid` actually carry traffic (see `link_carries_for`)?
    /// The roster's liveness: an attempt still in flight does not keep a sid
    /// the server reports gone.
    fn link_carries(&self, pid: &str) -> bool {
        self.links
            .get(pid)
            .map(|l| {
                let peer_connected = l.peer.as_ref().is_some_and(|p| p.is_connected());
                let primary_ok = l.transport.as_ref().is_some_and(|t| !t.is_dead());
                let workers_ok = l.workers.iter().any(|w| !w.is_dead());
                link_carries_for(peer_connected, primary_ok, workers_ok)
            })
            .unwrap_or(false)
    }

    /// May warm-hold dial `pid` from its roster entry? Not when the server's
    /// last digest left it out (presence says it is gone; the entry only waits
    /// out the two-digest hysteresis), and not when its retry ladder already
    /// gave up on it (`suppressed_digest_adoptions`, lifted only by a Contact
    /// from that sid). A device that comes back does so on a NEW sid, which is
    /// neither, so a laptop that slept is re-warmed as soon as it reappears.
    fn warm_dialable(&self, pid: &str) -> bool {
        !self.digest.roster_absent.contains_key(pid) && !self.digest.suppressed_digest_adoptions.contains(pid)
    }

    /// What link `pid` holds and how long it has been up, for log lines.
    fn link_kind(&self, pid: &str) -> String {
        let Some(l) = self.links.get(pid) else {
            return "absent".to_string();
        };
        let kind = if l.direct {
            "direct"
        } else if l.peer.is_some() {
            "WebRTC"
        } else {
            "transport"
        };
        match l.established_at {
            Some(at) => format!("{kind}, up {}s", at.elapsed().as_secs()),
            None => kind.to_string(),
        }
    }

    /// Re-emit `ChannelReady` for a link that ALREADY holds a live transport.
    ///
    /// The `--code` path DEFERS every offer until the PAKE confirms. The offer
    /// site says so, and states who is supposed to wake it:
    ///
    /// ```text
    /// // ...on confirm the Signal handler sets `pake_done` and re-emits
    /// // ChannelReady to fall through here and offer.
    /// if use_code && !is_direct && !pake_done {
    ///     continue; // offers/remember wait for PAKE confirm
    /// }
    /// ```
    ///
    /// The Signal handler sets `pake_done`. It has never re-emitted anything.
    /// What actually woke the loop was the Option A teardown: dropping the link
    /// forced a rebuild, and the rebuilt link's FRESH `ChannelReady` fell through
    /// the (now satisfied) guard and carried the offer. A destroy-and-rebuild
    /// cycle was standing in for an event dispatch.
    ///
    /// That is why removing the unconditional teardown wedged macOS. With direct
    /// disabled there was nothing to promote, so nothing dropped, so nothing was
    /// rebuilt, so no second `ChannelReady` ever arrived. The sender sat on a
    /// healthy authenticated link and never attempted a byte, which is exactly
    /// what the #78 artifact shows: `authenticated, sending`, then 15 minutes of
    /// nothing but 30s backend syncs.
    ///
    /// So this honours the contract the comment already documents. It mirrors
    /// the direct-upgrade re-emit in `adopt_direct_transport`, which does the
    /// same thing for the same reason: a transport that becomes usable without a
    /// fresh channel-open still has to tell the loop.
    ///
    /// No-op when the link is gone or its transport is dead, so it is safe to
    /// call unconditionally after a promotion attempt. A promotion never
    /// replaces the link any more (make-before-break), so after one this always
    /// has the serving transport to announce, and the transfer starts on it.
    pub fn rearm_channel_ready(&self, pid: &str, outcome: Promotion) {
        if outcome == Promotion::Replaced {
            return; // the replacement transport announces itself
        }
        let Some(l) = self.links.get(pid) else { return };
        let Some(t) = l.transport.as_ref() else {
            return;
        };
        if t.is_dead() {
            return;
        }
        let _ = self.tx.send(Ev::sourced_channel_ready(pid.to_string(), t.clone()));
    }

    /// `#[track_caller]` so a teardown NAMES the path that ordered it. There are
    /// 17 call sites, and a link that dies 40ms after authenticating leaves a
    /// `timed out waiting for a peer` whose guard cannot distinguish "no peer
    /// ever arrived" from "the peer's link died". Two of us built root-cause
    /// narratives out of that ambiguity before noticing the instrument was
    /// missing. This is that instrument: no runtime cost, and it cannot drift
    /// from the call sites the way a manual audit does.
    #[track_caller]
    pub fn drop_link(&mut self, pid: &str) {
        // The link's queued events are discarded with its stream.
        let (old, _events) = self.unlink(pid);
        if let Some(old) = old {
            close_dropped_link(old);
        }
    }

    /// Drop a link cut by a revocation, delivering `frame` (the
    /// `link-revoked` refusal) first. Everything `drop_link` invalidates is
    /// invalidated here at once: the link leaves `links`, its builds, intents
    /// and routing go, and no further event from it is admitted. Only the
    /// CLOSE is deferred, to a spawned task that owns the transport: it writes
    /// the frame with a fresh nonce, waits for the peer's matching
    /// `link-revoked-ack` (read by the task itself from the link's own
    /// candidate stream, or signalled by `closing` when the link's events
    /// reach the main queue), then closes, all under one `REFUSAL_ACK_BUDGET`.
    /// The event loop never awaits the peer, so a dead or frozen peer costs it
    /// nothing. The ack is a diagnostic: its absence is logged as unconfirmed
    /// and nothing treats it as "not delivered".
    ///
    /// Why an ack and not a flush: a successful write only means the frame is
    /// queued in this process (the QUIC send buffer, the SCTP stream queue),
    /// and both QUIC's CONNECTION_CLOSE and a WebRTC peer close discard what
    /// is still queued or unacknowledged. A transport-level flush would prove
    /// at most that the peer's stack received the bytes, not that its daemon
    /// processed the refusal before its own teardown of the dying link.
    ///
    /// Returns whether a refusal was attempted (false: no such link, or no
    /// transport to carry it, in which case this is a plain `drop_link`).
    #[track_caller]
    pub fn drop_link_after_refusal(&mut self, pid: &str, mut frame: Value) -> bool {
        let (old, events) = self.unlink(pid);
        let Some(mut old) = old else {
            return false;
        };
        let Some(t) = old.transport.clone() else {
            // A WebRTC link that never reached ChannelReady has nothing to
            // carry the refusal on. Say so rather than attempt nothing silently.
            self.log.debug(&format!(
                "link-revoked to {pid}: dropped_no_transport (no channel to carry the refusal)"
            ));
            close_dropped_link(old);
            return false;
        };
        let mut random = [0u8; 16];
        let nonce = match getrandom::getrandom(&mut random) {
            Ok(()) => hex::encode(random),
            // No randomness: still unique per process and never reused.
            Err(_) => {
                static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
                format!("n{}", SEQ.fetch_add(1, Ordering::Relaxed))
            }
        };
        frame["nonce"] = Value::String(nonce.clone());
        // Bind the ack to this cut's nonce and pid. A
        // link whose source is unassigned emits no source-tagged events, so
        // no ack can come back and none is awaited. The ack is looked for in
        // BOTH places it can arrive: the link's own candidate stream, read by
        // the closer itself (no loop turn in between), and the main queue,
        // where `stage_event` signals the closer. A WebRTC link promoted to a
        // direct path, or a peer that answers on another path of the same
        // session, delivers there.
        let watch = if old.source != net::SourceId::UNASSIGNED {
            // Only the stream of THIS link generation. A stale one (left by a
            // replacement, such as a direct upgrade of a WebRTC link) is not
            // where this transport delivers: watching it would end the wait at
            // once (its reader is gone) and close before the ack, so such a
            // link uses the main-queue signal instead.
            let stream = events
                .filter(|e| e.generation == old.generation)
                .map(|e| e.rx.into_inner().unwrap_or_else(|p| p.into_inner()));
            let (ack_tx, ack_rx) = oneshot::channel();
            self.sources.closing.insert(
                nonce.clone(),
                ClosingLink { pid: pid.to_string(), ack: Some(ack_tx) },
            );
            Some(AckWatch {
                pid: pid.to_string(),
                nonce,
                signal: Some(ack_rx),
                stream,
            })
        } else {
            None
        };
        let peer = old.peer.take();
        let closing: Vec<Arc<dyn Transport>> =
            old.transport.take().into_iter().chain(std::mem::take(&mut old.workers)).collect();
        drop(old);
        let log = self.log.clone();
        let pid = pid.to_string();
        tokio::spawn(async move {
            let outcome = deliver_refusal(t.as_ref(), &frame, watch, REFUSAL_ACK_BUDGET).await;
            log.debug(&format!("link-revoked to {pid}: {}", outcome.describe()));
            for t in closing {
                t.force_close();
            }
            if let Some(p) = peer {
                p.mark_closed();
                p.close().await;
            }
        });
        true
    }

    /// Everything `drop_link` does except closing the transports: the caller
    /// owns the returned link and decides when its transports close. The
    /// link's event stream is returned too; dropping it discards what is
    /// queued on it.
    #[track_caller]
    fn unlink(&mut self, pid: &str) -> (Option<Link>, Option<LinkEvents>) {
        // A drop is an invalidation: a candidate still building for this peer
        // must not publish after the link it was replacing is gone.
        self.cancel_build(pid);
        let link_attempt = self.links.get(pid).and_then(|link| link.attempt);
        if let Some(attempt) = link_attempt {
            // The adopted producer is already terminal; a queued duplicate ready
            // for this attempt must not resurrect the link.
            self.retire_attempt(pid, attempt, None);
        }
        let events = self.sources.clear_for_unlink(pid);
        self.log.debug(&format!(
            "  drop_link({pid}) ordered by {}",
            std::panic::Location::caller()
        ));
        // The hint is scoped to the sid's link/session. A replacement or a
        // peer-left must not pin direct off for whatever reuses this sid later;
        // a browser's fresh PeerLink sends its own hint before the next SDP.
        self.webrtc_only.remove(pid);
        // #28: dropping a link also discharges any deferred peer-left for it,
        // so a supersede (maybe_adopt) of a deferred same-uid sid can't leave a
        // stale entry blocking adoption. Invariant: deferred_left only ever
        // holds sids that are still live links.
        self.digest.clear_peer(pid);
        self.buffered_offers.remove(pid);
        self.held_signals.remove(pid);
        self.stuck_retry.remove(pid);
        // A promotion dies with its link: nothing will adopt the standby, and a
        // barrier still waiting on the peer must release onto the old path. One
        // already handed over is the exception: its adoption is queued and needs
        // the entry to keep its ephemeral pending from being reaped first.
        let promotion_attempt = if self.promotions.get(pid).is_some_and(|s| s.handed) {
            None
        } else {
            self.promotions.get(pid).and_then(|s| s.attempt)
        };
        if !self.promotions.get(pid).is_some_and(|s| s.handed) {
            self.abandon_promotion(pid);
        }
        // Retire only the exact ownership removed with this link. A newer
        // same-pid attempt, probe, or source must not be swept by a drop.
        if let Some(attempt) = promotion_attempt {
            self.retire_direct_ownership(pid, attempt);
        }
        if let Some(attempt) = link_attempt {
            self.retire_direct_ownership(pid, attempt);
        }
        let old = self.links.remove(pid);
        if self.is_active(pid) {
            self.active = None;
        }
        (old, events)
    }

    /// Exit path: close every link's QUIC connection NOW, so each peer learns
    /// this instance is gone. Without it a peer kept its direct link to the
    /// departed instance alive until QUIC's 30s idle timeout, and when the
    /// device came back on a new instance the peer held two live-looking links
    /// to it and routed warm opens to the dead one, waiting out the 2.5s
    /// verify window on every such open (net-blockers P1). Returns how many
    /// transports were closed. The caller must still await something before
    /// exiting (the endpoint task sends the close frames); there is no
    /// flush-on-close in QUIC.
    pub fn close_links_for_exit(&self) -> usize {
        let mut n = 0;
        for l in self.links.values() {
            for t in l.transport.iter().chain(l.workers.iter()) {
                t.force_close();
                n += 1;
            }
        }
        // A promotion's direct standby is a live QUIC connection too.
        for (t, _) in self.promotions.values().filter_map(|p| p.standby.as_ref()) {
            t.force_close();
            n += 1;
        }
        n
    }

    // --- WARM-HOLD: proactive connection management ---

    /// Record that a peer was just used (transfer, ssh, ping). This updates the
    /// LRU and marks the peer as warm so the daemon proactively connects/reconnects.
    pub fn note_warm_use(&mut self, peer: &str) {
        self.warm_hold.note_use(peer);
    }

    /// Record the sender of a COMPLETED inbound transfer as warm. Called only
    /// after a successful completion, never for a failed, truncated or refused
    /// transfer. The name is the link's proven `verified_name` now, else the
    /// one `captured` when the stream was accepted (`IncomingFile::sender`);
    /// never a name the peer claimed.
    ///
    /// The warm tier used to be fed from the streams STILL in flight once
    /// anything had completed. The finished stream had already been removed
    /// by then, so a single transfer warmed nobody, and with another sender
    /// mid-transfer it warmed that one instead.
    pub fn note_completed_transfer(&mut self, pid: &str, captured: Option<&str>) {
        let name = self
            .links
            .get(pid)
            .and_then(|l| l.verified_name.clone())
            .or_else(|| captured.map(str::to_string))
            .filter(|n| !n.is_empty());
        if let Some(name) = name {
            self.note_warm_use(&name);
        }
    }

    /// Load configured warm-peers from settings. Called at daemon startup and
    /// at the top of each warm_hold_tick to stay in sync with runtime changes.
    pub fn load_warm_peers_config(&mut self) {
        if let Some(setting) = self.host.settings_get_str("warm-peers") {
            self.warm_hold.configured.clear();
            for p in setting.split(',') {
                let p = p.trim().to_string();
                if !p.is_empty() {
                    self.warm_hold.configured.insert(p);
                }
            }
        }
    }

    /// Check for warm peers that need connections and establish them.
    /// Called periodically from the daemon event loop. Returns the list of
    /// peers we attempted to connect to.
    ///
    /// `auto_warm`: sync the auto tier (ALL online paired devices). Default ON
    /// (`auto-warm` setting); forced on while L3 is up. When off, the auto tier
    /// is cleared and only configured + recent peers stay warm.
    ///
    /// KEYED BY DEVICE, not by display name. Every tier is a devices.json
    /// PETNAME (the known-peer arrival, `note_warm_use` and `warm-peers` all
    /// use it), and a device counts as connected when ANY link to it is live:
    /// one that proved as it, one bound to its pair secret, or one to a sid
    /// on its channel. This used to build the auto tier from roster DISPLAY
    /// names and look for a link with that name, while a direct link is named
    /// by petname. Whenever the two differ, which is the normal case (petname
    /// `x`, display `user@x`), a healthy direct link was never recognised, a
    /// fresh establish replaced it every tick, and the peer, still holding its
    /// end, ignored the new offers: a ~95s re-dial cycle that never settled.
    pub async fn warm_hold_tick(&mut self, auto_warm: bool) -> Vec<String> {
        // Reload configured peers from settings to stay in sync
        self.load_warm_peers_config();
        let devices = self.host.devices_load();
        if auto_warm {
            let mut online: Vec<(String, Option<Instant>)> = devices
                .iter()
                .filter(|(name, secret)| {
                    let channel = self.host.channel_of(secret);
                    self.roster.iter().any(|(pid, v)| {
                        v["channel"].as_str() == Some(channel.as_str()) && self.warm_dialable(pid)
                    })
                        || self.links.values().any(|l| {
                            link_petname(l).is_some_and(|p| p.eq_ignore_ascii_case(name))
                        })
                })
                .map(|(n, _)| (n.clone(), self.warm_hold.last_use.get(n).copied()))
                .collect();
            // Change 4 size guard: over warm-max, keep the most recently USED peers
            // warm (never-used peers rank last; name tie-break keeps it deterministic).
            let cap = warm_max(&*self.host);
            if online.len() > cap {
                online.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                online.truncate(cap);
            }
            let current: std::collections::HashSet<String> =
                online.into_iter().map(|(n, _)| n).collect();
            for name in &current {
                if !self.warm_hold.auto.contains(name) {
                    self.warm_hold.auto.insert(name.clone());
                    self.log.debug(&format!("warm-hold: auto-warming peer '{name}'"));
                }
            }
            // Drop peers that went offline (or fell over the warm-max recency cut)
            self.warm_hold.auto.retain(|name| current.contains(name));
        } else {
            if !self.warm_hold.auto.is_empty() {
                self.log.debug("warm-hold: auto-warm off, clearing auto tier");
                self.warm_hold.auto.clear();
            }
        }
        let mut connected = Vec::new();
        let peers = self.warm_hold.peers_to_connect();
        // At most ONE peer per tick: each attempt may gather candidates, and
        // serializing several of them over the daemon loop is what produced the
        // 20 s watchdog stall after a fleet join. Warming one peer per 10 s tick
        // is fast enough and keeps the loop responsive.
        let mut dial_attempted = false;
        for peer in peers {
            if dial_attempted {
                break;
            }
            let device = devices
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(&peer))
                .cloned();
            let channel = device.as_ref().map(|(_, s)| self.host.channel_of(s));
            let decision = {
                let links: Vec<WarmLinkView<'_>> = self
                    .links
                    .iter()
                    .map(|(pid, l)| WarmLinkView {
                        pid: pid.as_str(),
                        petname: link_petname(l),
                        name: &l.name,
                        live: self.has_live_transport(pid),
                    })
                    .collect();
                // Only sids presence still vouches for and the ladder has not
                // given up on: a departed sid's entry waits out its digest
                // hysteresis, and dialling it meanwhile restarted the ladder.
                let roster: Vec<WarmRosterView<'_>> = self
                    .roster
                    .iter()
                    .filter(|(pid, _)| self.warm_dialable(pid))
                    .map(|(pid, v)| WarmRosterView {
                        pid: pid.as_str(),
                        name: v["name"].as_str(),
                        channel: v["channel"].as_str(),
                    })
                    .collect();
                warm_decide(
                    &peer,
                    channel.as_deref(),
                    &links,
                    &roster,
                    self.warm_hold.failures(&peer) as usize,
                )
            };
            let pid = match decision {
                WarmDecision::Skip { pid } => {
                    // A link still mid-attempt is not a result yet; one that
                    // carries traffic settles a started warm build as a success.
                    if self.link_carries(&pid) {
                        self.warm_hold.settle_pending(&peer, true);
                    }
                    // The live link's principal rides along, so a gate can see
                    // what the link IS between events, not only at admission.
                    let (kind, sibling) = self
                        .links
                        .get(&pid)
                        .map(|l| (format!("{:?}", l.principal_kind), l.is_sibling_link()))
                        .unwrap_or_default();
                    self.log.debug(&format!(
                        "warm-hold: skip '{peer}' (link {pid} to it is live) principal={kind} sibling={sibling}"
                    ));
                    continue;
                }
                WarmDecision::Absent => {
                    self.log.trace(&format!("warm-hold: '{peer}' is not present, nothing to dial"));
                    continue;
                }
                WarmDecision::Establish { pid } => pid,
            };
            // Having to establish again means the build the last warm dial
            // started never came up (the ladder gave up on it, or it was
            // evicted): that is a failed attempt, and the backoff grows.
            self.warm_hold.settle_pending(&peer, false);
            // Honor per-peer backoff; a dormant peer still gets one probe per
            // WARM_DORMANT_RETRY so an online-but-unlucky peer cannot stay cold forever.
            if !self.warm_hold.due(&peer) {
                continue;
            }
            self.log.debug(&format!(
                "warm-hold: will establish '{peer}' via {pid} (no live link to it)"
            ));
            let Some(info) = self.roster.get(&pid).cloned() else {
                continue;
            };
            dial_attempted = true;
            // A paired device is re-dialled the way its known-peer arrival dials
            // it: direct first (establish below then yields to the pending
            // attempt), and the link bound to its pair secret. A secretless link
            // proves nothing and is exactly what the room digest reconcile reaps
            // as a room peer that left.
            if let Some((petname, secret)) = &device {
                // Candidate gathering (public_ip probe + srflx) runs off the
                // loop (`gather_and_offer`), so arming the warm dial returns at
                // once and is never cut short half-way.
                self.start_direct(&pid, petname, secret).await;
                self.note_binding(&pid, (petname.clone(), secret.clone()));
            }
            let result = self.establish_as(info, None).await;
            if let (Some((petname, secret)), Some(l)) = (&device, self.links.get_mut(&pid)) {
                if l.expected_secret.is_none() {
                    l.expected_secret = Some((petname.clone(), secret.clone()));
                }
            }
            match result {
                Ok(()) => {
                    // The backoff is settled on what the link CARRIES: an
                    // attempt still in flight is only started, and the next
                    // look decides whether it came up.
                    if self.link_carries(&pid) {
                        self.warm_hold.note_success(&peer);
                    } else {
                        self.warm_hold.note_started(&peer);
                    }
                    if self.has_live_transport(&pid) {
                        self.log.debug(&format!("warm-hold: established connection to '{peer}'"));
                        connected.push(peer);
                    } else {
                        self.log.debug(&format!(
                            "warm-hold: build started for '{peer}'; link completion is not establishment yet"
                        ));
                    }
                }
                Err(e) => {
                    self.warm_hold.note_failure(&peer);
                    self.log.debug(&format!("warm-hold: failed to connect to '{peer}': {e}"));
                }
            }
        }
        connected
    }

    /// `known-peer-left`: a sid left one of the channels we watch. Forget it
    /// from the roster, unless a live link still runs to it (the link carries
    /// its own copy of the info, and worker role election reads the roster).
    ///
    /// Without this the roster only ever shrank on a ROOM peer-left, so every
    /// past one-shot CLI and old daemon instance of a paired device stayed in
    /// it forever under the same display name, and warm-hold dialled those
    /// ghosts, each with its own retry ladder. Returns true if an entry went.
    pub fn on_known_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid) = v["id"].as_str() else {
            return false;
        };
        self.digest.roster_absent.remove(pid);
        // Only a link that carries traffic keeps the entry. An attempt still
        // in flight toward a sid the server just reported gone cannot finish
        // (its signals are refused), and keeping the entry for it is what let
        // warm-hold re-dial a departed visitor from that entry forever.
        if self.link_carries(pid) {
            return false;
        }
        self.webrtc_only.remove(pid);
        let removed = self.roster.remove(pid).is_some();
        if removed {
            self.log.debug(&format!("roster: forgot {pid} (known-peer-left)"));
        }
        removed
    }

    /// Resume a dormant warm peer (e.g., when it reappears in signaling presence)
    fn resume_warm_peer(&mut self, peer: &str) {
        self.warm_hold.resume(peer);
    }

    /// `force_polite: Some(true)` builds a pure responder link (no local offer)
    /// regardless of uid comparison, required when the link exists to ANSWER
    /// an incoming offer (ensure_responder / glare rebuild). The uid-based role
    /// can come out impolite there (especially on the bare `{id}` roster-miss
    /// fallback, which compares sids), making the "responder" offer too: glare.
    #[track_caller]
    pub fn establish_as(
        &mut self,
        info: Value,
        force_polite: Option<bool>,
    ) -> impl std::future::Future<Output = Result<()>> + '_ {
        let caller = std::panic::Location::caller();
        async move {
            self.establish_as_inner(info, force_polite, caller, Replace::NeverLive)
                .await
        }
    }

    /// The retry ladder's rebuild of a STUCK link (`on_retry_due`): the only
    /// establish allowed to replace a link `has_live_transport` still counts as
    /// live. A stuck WebRTC attempt is exactly that shape (its peer is still
    /// New/Connecting, which #246 counts as progress), and replacing it is the
    /// whole point of the ladder. `on_retry_due` has already checked that the
    /// link is the stuck generation and not connected.
    #[track_caller]
    fn reestablish_stuck(
        &mut self,
        info: Value,
    ) -> impl std::future::Future<Output = Result<()>> + '_ {
        let caller = std::panic::Location::caller();
        async move {
            self.establish_as_inner(info, None, caller, Replace::StuckAttempt)
                .await
        }
    }

    /// ICE config for an establish without letting the config GET hold the
    /// event loop. `fetch_config` retries 3x with a 10s timeout each, and it
    /// was awaited inline on every establish, so one slow API answer could
    /// freeze the daemon for ~30s.
    ///
    /// A config younger than ICE_CONFIG_FRESH is reused outright. One younger
    /// than ICE_CONFIG_STALE_OK is reused while a background task refreshes it
    /// OFF the loop. Only with nothing usable cached (the first establish, or
    /// after a long idle) does an establish wait, and then for at most
    /// ICE_CONFIG_BUDGET. TURN credentials are expiry-stamped (backend
    /// FIL_TURN_TTL, 1h default), so every reused config is still valid (C5:
    /// fresh credentials, just not a round trip per attempt).
    async fn ice_config(&mut self) -> Result<net::ServerConfig> {
        let cached = lock_ice(&self.ice_cache).cfg.clone();
        if let Some((at, cfg)) = cached {
            if at.elapsed() < ICE_CONFIG_FRESH {
                return Ok(cfg);
            }
            if at.elapsed() < ICE_CONFIG_STALE_OK {
                self.refresh_ice_config_off_loop();
                return Ok(cfg);
            }
        }
        let got = match tokio::time::timeout(ICE_CONFIG_BUDGET, net::fetch_config(&self.transport_context, &self.server)).await {
            Ok(Ok(cfg)) => {
                lock_ice(&self.ice_cache).cfg = Some((Instant::now(), cfg.clone()));
                return Ok(cfg);
            }
            Ok(Err(e)) => Err(e.context("ICE config")),
            Err(_) => Err(anyhow::anyhow!(
                "ICE config: no answer within {ICE_CONFIG_BUDGET:?}"
            )),
        };
        // A slow config API must not fail the whole connection (a `join` whose
        // first establish found the API slow used to exit 1 after 3 s). STUN is
        // enough to find a direct path, so proceed with it and keep asking for
        // the full config (with TURN) off the loop for the next attempt. A forced
        // relay is the exception: without TURN it cannot work, so say why.
        if ice_fallback_allowed(self.relay_only) {
            if let Err(e) = &got {
                self.log.debug(&format!("{e:#}; continuing with STUN only, TURN when the config arrives"));
            }
            self.refresh_ice_config_off_loop();
            return Ok(stun_only_ice_config());
        }
        got
    }

    /// Refresh the cached ICE config on a spawned task (at most one in flight).
    fn refresh_ice_config_off_loop(&self) {
        {
            let mut cache = lock_ice(&self.ice_cache);
            if cache.refreshing {
                return;
            }
            cache.refreshing = true;
        }
        let cache = self.ice_cache.clone();
        let server = self.server.clone();
        let context = self.transport_context.clone();
        tokio::spawn(async move {
            let got = net::fetch_config(&context, &server).await;
            let mut cache = lock_ice(&cache);
            cache.refreshing = false;
            if let Ok(cfg) = got {
                cache.cfg = Some((Instant::now(), cfg));
            }
        });
    }

    /// Prepare a build without touching the network. Guards and role election
    /// are loop-local; the ICE cache is read synchronously and a cold fetch is
    /// handed to the build task.
    fn prepare_build(
        &mut self,
        info: Value,
        force_polite: Option<bool>,
        caller: &'static std::panic::Location<'static>,
        replace: Replace,
    ) -> Result<Option<BuildPlan>> {
        let peer_id = info["id"].as_str().unwrap_or_default().to_string();
        let carried_secret = self
            .pending_bindings
            .get(&peer_id)
            .cloned()
            .or_else(|| self.links.get(&peer_id).and_then(|l| l.expected_secret.clone()));
        // Per-peer intent guard. A forgotten binding refuses every pid that
        // presents it; a forgotten pid refuses a bare rebuild but accepts a
        // fresh authorized binding (a real re-pair). No display name is a key.
        if self.intent_blocked(&peer_id, carried_secret.as_ref()) {
            self.log.debug(&format!(
                "tunlion: ESTABLISH-REFUSED peer={peer_id} caller={caller}: \
                 its intent was revoked and no fresh binding authorized it"
            ));
            return Ok(None);
        }
        if self.direct_pending.contains_key(&peer_id) {
            return Ok(None);
        }
        if self.resil.relay_committed.contains(&peer_id) && self.links.contains_key(&peer_id) {
            return Ok(None);
        }
        if replace == Replace::NeverLive && self.has_live_transport(&peer_id) {
            self.log.debug(&format!(
                "tunlion: ESTABLISH-REFUSED peer={peer_id} caller={caller}: \
                 keeping its live link ({})",
                self.link_kind(&peer_id)
            ));
            // Reuse, do not strand: a live link that has no binding yet cannot
            // claim the target slot, and a refusal is the LAST establish that
            // peer will get. Claim the store-authorized binding onto THIS link
            // and announce the transport it already serves, with that
            // transport's own immutable source, so the ordinary ChannelReady
            // path takes the slot. Nothing is reattributed: the announcement
            // names the serving Arc, never a replaced one.
            self.claim_live_unbound_link(&peer_id, carried_secret);
            return Ok(None);
        }
        if self.builds.contains_key(&peer_id) {
            let supersedes = self
                .builds
                .get(&peer_id)
                .is_some_and(|state| self.authorized_replacement(&state.binding, &carried_secret));
            if !supersedes {
                // Join, do not retire: the candidate already building is the
                // one the peer can answer (it may carry that very offer), and a
                // binding claim is authorization, not a new negotiation.
                // Retiring it here deleted the only channel that could carry
                // the answer while the replacement waited for a readiness the
                // peer never sent -- it still held the link it had answered.
                self.claim_binding_on_pending_build(&peer_id, carried_secret);
                return Ok(None);
            }
            self.retire_build(&peer_id);
        }
        if let Some((plan, _)) = self.build_deferred.get(&peer_id) {
            if !self.authorized_replacement(&plan.carried_secret, &carried_secret) {
                self.claim_binding_on_pending_build(&peer_id, carried_secret);
                return Ok(None);
            }
            self.retire_build(&peer_id);
        }
        let uid = info["uid"].as_str().map(|s| s.to_string());
        let peer_present = self.roster.contains_key(&peer_id);
        let name = info["name"].as_str().unwrap_or("peer").to_string();
        // An offer held during the direct attempt makes this build its
        // responder: the peer already offered, so answering it is the only role
        // that cannot glare (the same reason `ensure_responder` forces polite).
        // Peek here and take the hold only after the role is decided, so a role
        // error leaves it in place for the next build.
        let held_offer = self
            .held_signals
            .get(&peer_id)
            .is_some_and(|h| h.has_offer && h.since.elapsed() < held_signal_ttl());
        let polite = match force_polite {
            Some(value) => value,
            None if held_offer => true,
            None => match uid.as_deref() {
                Some(uid) => net::polite_role(&self.my_uid, uid, &self.my_id, &peer_id)?,
                None => {
                    let source = if peer_present { "presence" } else { "absent-roster" };
                    net::polite_role_legacy(
                        &self.my_uid,
                        None,
                        &self.my_id,
                        &peer_id,
                        source,
                        peer_present,
                    )?
                }
            },
        };
        let (signals, signal_bytes) = match self.take_held(&peer_id) {
            Some(h) => {
                self.log.debug(&format!(
                    "tunlion: HOLD-REPLAY peer={peer_id} caller={caller}: {} held signal(s) staged into its build",
                    h.signals.len()
                ));
                (h.signals, h.bytes)
            }
            None => (std::collections::VecDeque::new(), 0),
        };
        self.next_gen += 1;
        let generation = self.next_gen;
        let relay_ice = self.relay_only || test_hooks::webrtc_relay_only();
        // This is now the only intent allowed to run/install for this pid. A
        // re-pair therefore supersedes an older deferred retry instead of
        // racing it; the older generation remains retired.
        self.current_intent.insert(peer_id.clone(), generation);
        // Bind the cached value, not the guard: a `match lock_ice(...).cfg.clone()`
        // keeps the temporary MutexGuard alive for the whole match, and the
        // stale arm calls refresh_ice_config_off_loop(), which locks the SAME
        // non-reentrant std::Mutex. That self-deadlocked the daemon loop for the
        // watchdog's 20 s window once the cache aged past ICE_CONFIG_FRESH
        // (caught live on the Android emulator during a stuck-link retry).
        let cached = lock_ice(&self.ice_cache).cfg.clone();
        let config = match cached {
            Some((at, cfg)) if at.elapsed() < ICE_CONFIG_FRESH => {
                self.chunk_size = cfg.chunk_size;
                BuildIce::Cached(cfg)
            }
            Some((at, cfg)) if at.elapsed() < ICE_CONFIG_STALE_OK => {
                self.refresh_ice_config_off_loop();
                self.chunk_size = cfg.chunk_size;
                BuildIce::Cached(cfg)
            }
            _ => BuildIce::Fetch,
        };
        let config = match config {
            BuildIce::Cached(mut cfg) => {
                if self.host.relay_forbidden() {
                    cfg.ice_servers.retain(|s| net::is_stun_only(s));
                }
                BuildIce::Cached(cfg)
            }
            other => other,
        };
        let active_on_apply = self.pending_active.contains(&peer_id) || self.is_active(&peer_id);
        let prior_generation = self.links.get(&peer_id).map(|l| l.generation);
        Ok(Some(BuildPlan {
            peer_id,
            info,
            name,
            uid,
            carried_secret,
            generation,
            polite,
            relay_ice,
            config,
            replace,
            active_on_apply,
            caller,
            attempt: 0,
            prior_generation,
            signals,
            signal_bytes,
        }))
    }

    async fn establish_as_inner(
        &mut self,
        info: Value,
        force_polite: Option<bool>,
        caller: &'static std::panic::Location<'static>,
        replace: Replace,
    ) -> Result<()> {
        let Some(plan) = self.prepare_build(info, force_polite, caller, replace)? else {
            return Ok(());
        };
        #[cfg(test)]
        if test_inline::enabled() {
            return self.establish_inline(plan).await;
        }
        match self.start_build(plan) {
            BuildStart::Busy => anyhow::bail!("too many concurrent link builds; retry"),
            _ => Ok(()),
        }
    }

    /// Test-only synchronous path. It uses the same plan, peer construction and
    /// installer as the build task; only the task boundary is absent.
    #[cfg(test)]
    async fn establish_inline(&mut self, mut plan: BuildPlan) -> Result<()> {
        let pid = plan.peer_id.clone();
        // Signals staged into the plan (an offer held during a direct attempt)
        // replay on install exactly as the off-loop build's do.
        let staged = std::mem::take(&mut plan.signals);
        let mut cfg = match plan.config {
            BuildIce::Cached(cfg) => cfg,
            BuildIce::Fetch => match tokio::time::timeout(
                ICE_CONFIG_BUDGET,
                net::fetch_config(&self.transport_context, &self.server),
            )
            .await
            {
                Ok(Ok(cfg)) => cfg,
                _ if ice_fallback_allowed(plan.relay_ice) => stun_only_ice_config(),
                _ => anyhow::bail!("ICE config: no answer within {ICE_CONFIG_BUDGET:?}"),
            },
        };
        if self.host.relay_forbidden() {
            cfg.ice_servers.retain(|s| net::is_stun_only(s));
        }
        let peer = tokio::time::timeout(
            PEER_BUILD_BUDGET,
            net::Peer::connect_with_context(
                &self.transport_context,
                plan.peer_id.clone(),
                self.my_uid.clone(),
                plan.polite,
                cfg.ice_servers,
                plan.relay_ice,
                self.sio.clone(),
                self.tx.clone(),
                plan.generation,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("building the peer connection took over {PEER_BUILD_BUDGET:?}"))??;
        let source = peer.source();
        let binding = self
            .pending_bindings
            .remove(&pid)
            .or(plan.carried_secret.clone());
        let pending_active = self.pending_active.remove(&pid);
        self.install_built(
            BuiltPeer {
                peer_id: pid.clone(),
                generation: plan.generation,
                source,
                peer,
                info: plan.info,
                name: plan.name,
                uid: plan.uid,
                carried_secret: plan.carried_secret,
                active_on_apply: plan.active_on_apply,
                replace: plan.replace,
                caller: plan.caller,
                prior_generation: plan.prior_generation,
            },
            std::collections::VecDeque::new(),
            staged,
            binding,
            pending_active,
        );
        Ok(())
    }

    fn start_build(&mut self, plan: BuildPlan) -> BuildStart {
        if self.intent_retired(&plan.peer_id, plan.generation)
            || self.current_intent.get(&plan.peer_id) != Some(&plan.generation)
            || self.intent_blocked(&plan.peer_id, plan.carried_secret.as_ref())
        {
            return BuildStart::AlreadyBuilding;
        }
        if self.builds.contains_key(&plan.peer_id) {
            return BuildStart::AlreadyBuilding;
        }
        if self.builds.len() >= MAX_PENDING_BUILDS {
            if self.build_deferred.len() < MAX_DEFERRED_BUILDS
                || self.build_deferred.contains_key(&plan.peer_id)
            {
                self.build_deferred.insert(plan.peer_id.clone(), (plan, Instant::now()));
                return BuildStart::Deferred;
            }
            return BuildStart::Busy;
        }
        let generation = plan.generation;
        self.spawn_build(plan);
        BuildStart::Started(generation)
    }

    fn spawn_build(&mut self, mut plan: BuildPlan) {
        let pid = plan.peer_id.clone();
        let generation = plan.generation;
        let signals = std::mem::take(&mut plan.signals);
        let signal_bytes = plan.signal_bytes;
        let binding = plan.carried_secret.clone();
        let cancel = Arc::new(BuildCancel::new());
        let task_cancel = cancel.clone();
        let out = self.build_tx.clone();
        // Candidate events go to this build's OWN channel, never the main
        // queue. That is the immutable provenance: the previously serving
        // link's events stay on the main queue, and stale callbacks cannot be
        // replayed onto the candidate after installation.
        let (candidate_tx, candidate_rx) = mpsc::unbounded_channel();
        let wake = self.tx.clone();
        let wake_pending = self.candidate_wake.clone();
        let context = self.transport_context.clone();
        let server = self.server.clone();
        let sio = self.sio.clone();
        let my_uid = self.my_uid.clone();
        let cache = self.ice_cache.clone();
        let relay_forbidden = self.host.relay_forbidden();
        let handle = tokio::spawn(async move {
            run_build_task(
                plan,
                candidate_tx,
                wake,
                wake_pending,
                task_cancel,
                out,
                context,
                server,
                sio,
                my_uid,
                cache,
                relay_forbidden,
            )
            .await;
        });
        self.builds.insert(
            pid,
            BuildState {
                generation,
                cancel,
                handle,
                started: Instant::now(),
                signals,
                signal_bytes,
                early: std::collections::VecDeque::new(),
                early_bytes: 0,
                events_rx: std::sync::Mutex::new(candidate_rx),
                binding,
            },
        );
    }

    /// Poll the build lifecycle: drain candidate-local events into their
    /// bounded buffers, apply finished candidates, start deferred intents while
    /// slots are free, and reap a task that outlived its grace. Every Conn
    /// driver calls this once per loop turn; it never awaits.
    pub fn pump_builds(&mut self) -> usize {
        // Clear BEFORE draining. An event queued after this point sees the
        // flag clear and sends a fresh wake, so it is never left for an
        // unrelated event to collect; one queued before it is drained below.
        self.candidate_wake.store(false, Ordering::SeqCst);
        // Finished candidate gatherings: their pendings can now race.
        let gathered = std::mem::take(
            &mut *self
                .direct_gathered
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for done in gathered {
            self.apply_direct_gathered(done);
        }
        // Installed-link event streams are candidate-local. Forward them only
        // while the link still carries the generation that created the stream;
        // a replaced/dropped link's queued events are discarded, never applied
        // to a newer link that reused the pid.
        let linked: Vec<(String, u32)> = self
            .sources.link_events
            .iter()
            .map(|(pid, events)| (pid.clone(), events.generation))
            .collect();
        for (pid, generation) in linked {
            let current = self.links.get(&pid).map(|l| l.generation) == Some(generation);
            if !current {
                self.sources.link_events.remove(&pid);
                continue;
            }
            let tx = self.tx.clone();
            if let Some(events) = self.sources.link_events.get_mut(&pid) {
                let mut rx = events
                    .rx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                while let Ok(ev) = rx.try_recv() {
                    let _ = tx.send(ev);
                }
            }
        }
        self.pump_closing();
        // Candidate events are drained here, never taken from the main queue.
        // An event from the previously serving link therefore cannot be
        // replayed onto a candidate that is about to install.
        let mut overflow: Vec<String> = Vec::new();
        for (pid, state) in self.builds.iter_mut() {
            if !drain_candidate_events(state) {
                overflow.push(pid.clone());
            }
        }
        for pid in overflow {
            self.cancel_build(&pid);
        }
        // Retirement entries are bounded by outstanding work plus the build
        // reap grace. A build task is aborted/reaped at that bound, and its
        // completion is drained in the same pump, so no queued completion can
        // outlive this window; pruning therefore cannot revive a stale apply.
        let now = Instant::now();
        let active: HashSet<String> = self
            .builds
            .keys()
            .chain(self.build_deferred.keys())
            .chain(self.links.keys())
            .cloned()
            .collect();
        self.cancelled_intents.retain(|pid, retired| {
            now.duration_since(retired.at) < BUILD_REAP_GRACE || active.contains(pid)
        });
        self.revoked_peers.retain(|pid, retired| {
            now.duration_since(retired.at) < BUILD_REAP_GRACE || active.contains(pid)
        });
        self.current_intent.retain(|pid, _| active.contains(pid));
        let stale_sources: Vec<net::SourceId> = self
            .sources.pending_sources
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.at) >= BUILD_REAP_GRACE)
            .map(|(source, _)| *source)
            .collect();
        for source in stale_sources {
            self.drop_pending_source(source);
        }
        let mut applied = 0usize;
        loop {
            let done = {
                let mut rx = self
                    .build_rx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                rx.try_recv().ok()
            };
            let Some(done) = done else { break; };
            match done {
                BuildDone::Ready(built) => {
                    self.apply_built_peer(built);
                    applied += 1;
                }
                BuildDone::Failed { plan, reason } => {
                    let pid = plan.peer_id.clone();
                    let generation = plan.generation;
                    if self
                        .builds
                        .get(&pid)
                        .is_some_and(|state| state.generation == generation)
                    {
                        self.builds.remove(&pid);
                    }
                    self.log.debug(&format!(
                        "tunlion: BUILD-FAILED peer={pid} attempt={} reason={reason}",
                        plan.attempt
                    ));
                    // A failure queued before peer-left/drop/cancel belongs to
                    // a retired intent. It is terminal: no retry and no link
                    // teardown (the cancel already decided this peer's fate).
                    if self.intent_retired(&pid, generation) {
                        self.log.debug(&format!(
                            "tunlion: BUILD-FAILED peer={pid} gen={generation} retired, not retrying"
                        ));
                        continue;
                    }
                    if plan.attempt + 1 < 3
                        && self.current_intent.get(&pid) == Some(&generation)
                        && !self.builds.contains_key(&pid)
                        && (self.build_deferred.len() < MAX_DEFERRED_BUILDS
                            || self.build_deferred.contains_key(&pid))
                    {
                        let mut retry = plan;
                        retry.attempt += 1;
                        let delay = Duration::from_millis(250u64 << retry.attempt.min(3));
                        let due = Instant::now() + delay;
                        self.build_deferred.insert(pid.clone(), (retry, due));
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            let _ = tx.send(Ev::BuildWake);
                        });
                    } else {
                        // Terminal failure: restore the ladder's observable
                        // outcome instead of leaving a silent half-link.
                        self.log.say(&format!(
                            "tunlion: could not build a WebRTC link for {pid}: {reason}"
                        ));
                        // Drop only the generation this failed intent owned. A
                        // newer direct link that landed meanwhile must survive.
                        if self
                            .links
                            .get(&pid)
                            .is_none_or(|l| Some(l.generation) == plan.prior_generation)
                        {
                            self.drop_link(&pid);
                        }
                    }
                }
                BuildDone::Cancelled { plan } => {
                    let pid = plan.peer_id.clone();
                    let generation = plan.generation;
                    self.log.debug(&format!("tunlion: BUILD-CANCELLED peer={pid}"));
                    // Cancelled is terminal for THIS generation. A newer intent
                    // (higher generation) must keep its slot.
                    let matches = self
                        .builds
                        .get(&pid)
                        .is_some_and(|state| state.generation == generation);
                    if matches {
                        self.builds.remove(&pid);
                    }
                    self.retire_intent(&pid, generation);
                }
            }
        }
        let expired: Vec<String> = self
            .builds
            .iter()
            .filter(|(_, s)| s.started.elapsed() > BUILD_REAP_GRACE)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired {
            self.cancel_build(&pid);
        }
        while self.builds.len() < MAX_PENDING_BUILDS {
            let now = Instant::now();
            let next = self
                .build_deferred
                .iter()
                .find(|(_, (_, due))| *due <= now)
                .map(|(pid, _)| pid.clone());
            let Some(pid) = next else { break };
            let Some((plan, _)) = self.build_deferred.remove(&pid) else { break };
            if self.builds.contains_key(&pid)
                || self.current_intent.get(&pid) != Some(&plan.generation)
                || self.intent_retired(&pid, plan.generation)
                || self.intent_blocked(&pid, plan.carried_secret.as_ref())
            {
                continue;
            }
            self.spawn_build(plan);
        }
        applied
    }

    fn apply_built_peer(&mut self, built: BuiltPeer) {
        let Some(mut state) = self.builds.remove(&built.peer_id) else {
            discard_built(built);
            return;
        };
        if state.generation != built.generation
            || state.cancel.is_cancelled()
            || self.current_intent.get(&built.peer_id) != Some(&built.generation)
            || self.intent_retired(&built.peer_id, built.generation)
        {
            discard_built(built);
            return;
        }
        let live = self.has_live_transport(&built.peer_id);
        let newer = self
            .links
            .get(&built.peer_id)
            .is_some_and(|l| Some(l.generation) != built.prior_generation);
        if live && (built.replace != Replace::StuckAttempt || newer) {
            self.log.debug(&format!(
                "tunlion: ESTABLISH-REFUSED peer={} caller={}: a newer link won the race",
                built.peer_id, built.caller
            ));
            discard_state(state, built.peer);
            return;
        }
        if !self.links.contains_key(&built.peer_id) && self.links.len() >= MAX_LINKS {
            self.log.debug(&format!(
                "tunlion: ESTABLISH-REFUSED peer={} caller={}: link cap reached at apply",
                built.peer_id, built.caller
            ));
            discard_state(state, built.peer);
            return;
        }
        debug_assert!(
            built.replace == Replace::StuckAttempt || !live,
            "apply_built_peer must never drop a link with a live transport"
        );
        let pid = built.peer_id.clone();
        let generation = built.generation;
        let binding = self
            .pending_bindings
            .remove(&built.peer_id)
            .or(built.carried_secret.clone());
        // A revocation that landed after prepare must still fence the apply.
        if self.intent_blocked(&pid, binding.as_ref()) {
            discard_state(state, built.peer);
            return;
        }
        // Anything already emitted during construction is replayed first, in
        // order; then the SAME candidate channel is forwarded for the life of
        // the link. No old-link event can enter it.
        if !drain_candidate_events(&mut state) {
            discard_state(state, built.peer);
            return;
        }
        let early = std::mem::take(&mut state.early);
        let candidate_rx = state
            .events_rx
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pending_active = self.pending_active.remove(&built.peer_id);
        self.install_built(built, early, state.signals, binding, pending_active);
        // The forwarder is owned by the link: pump_builds drains this receiver
        // only while the link still carries `generation`, and drop_link/
        // replacement removes it, discarding queued stale events.
        self.sources.link_events.insert(pid, LinkEvents { generation, rx: std::sync::Mutex::new(candidate_rx), departure_ready: None, departure_pending: None });
    }

    /// The retry-episode state a stuck-attempt rebuild must not lose: the
    /// ladder count (`on_retry_due` stamps it on the old link before the
    /// build lands), the presence it reports, and the departure evidence the
    /// digest reapers have gathered. None when there is no link to carry from.
    fn stuck_episode(&self, pid: &str) -> Option<StuckEpisode> {
        let l = self.links.get(pid)?;
        Some(StuckEpisode {
            attempts: l.attempts,
            presence: l.presence,
            channel_absent: self.digest.channel_digest_absent.get(pid).copied(),
            room_absent: self.digest.room_digest_absent.get(pid).copied(),
            digest_deferred: self.digest.digest_deferred.get(pid).copied(),
        })
    }

    fn restore_stuck_episode(&mut self, pid: &str, episode: StuckEpisode) {
        if let Some(l) = self.links.get_mut(pid) {
            l.attempts = episode.attempts;
            l.presence = episode.presence;
        }
        if let Some(n) = episode.channel_absent {
            self.digest.channel_digest_absent.insert(pid.to_string(), n);
        }
        if let Some(n) = episode.room_absent {
            self.digest.room_digest_absent.insert(pid.to_string(), n);
        }
        if let Some(at) = episode.digest_deferred {
            self.digest.digest_deferred.insert(pid.to_string(), at);
        }
    }

    /// At the link cap, a fresh contact may displace a link the retry ladder
    /// is still failing to (re)connect: it has failed at least once, its peer
    /// is not connected and no transport or worker carries bytes. A full table
    /// of such links is exactly what starved enrollment on the owner daemon
    /// (every new device was refused silently while dead sids kept retrying).
    /// Never evicts the active target or a link that is up. Returns true when
    /// a slot was freed.
    fn evict_retrying_link(&mut self, for_pid: &str) -> bool {
        let victim = self
            .links
            .iter()
            .filter(|(pid, l)| {
                pid.as_str() != for_pid
                    && !l.direct
                    && l.attempts > 0
                    && l.peer.as_ref().is_some_and(|p| !p.is_connected())
                    && l.transport.as_ref().is_none_or(|t| t.is_dead())
                    && l.workers.iter().all(|w| w.is_dead())
                    && self.active.as_deref() != Some(pid.as_str())
            })
            .max_by_key(|(_, l)| l.attempts)
            .map(|(pid, _)| pid.clone());
        let Some(victim) = victim else {
            return false;
        };
        self.log.debug(&format!(
            "tunlion: link cap ({MAX_LINKS}) reached; dropping retrying link {victim} for new contact {for_pid}"
        ));
        // Evicting a failing link gives up on that sid as an exhausted ladder
        // does: neither digest adoption nor warm-hold may restart it (a fresh
        // episode at attempt 0) until the sid itself makes contact. Without
        // this an evicted departed sid was re-dialled by warm-hold seconds
        // later and its ladder never got to exhaust.
        self.digest.suppressed_digest_adoptions.insert(victim.clone());
        self.drop_link(&victim);
        true
    }

    fn install_built(
        &mut self,
        built: BuiltPeer,
        early: std::collections::VecDeque<Ev>,
        signals: std::collections::VecDeque<Value>,
        binding: Option<(String, String)>,
        pending_active: bool,
    ) {
        let webrtc_only = self.webrtc_only.contains(&built.peer_id);
        // A candidate that reached apply with a binding the store still holds
        // is a fresh authorized intent: the old revoked generation stays
        // retired (monotonic generations), but the pid is no longer blocked.
        if let Some((_, secret)) = &binding {
            if self.store_holds_binding(secret) && !self.revoked_bindings.contains(secret) {
                self.revoked_peers.remove(&built.peer_id);
            }
        }
        // Room adoption can select this target after its asynchronous build
        // captured active_on_apply. Keep that current selection across the
        // old-link cleanup, which also clears the active slot.
        let selected_while_building = self.is_active(&built.peer_id);
        // A transport-offer buffered while this candidate was building (no
        // pending and no link existed, so the driver could not arm one) must
        // outlive the old-link cleanup below: `drop_link` clears
        // `buffered_offers`, and nothing else would ever replay it. Take it
        // here, before the cleanup, and requeue it once the link exists.
        //
        // Only for a FIRST-LINK install. Whether this pid already had a link
        // is read here, before the cleanup removes it, never from the
        // plan-time snapshot. An install that replaces a link (a stuck-attempt
        // rebuild, a same-pid reconnect) keeps a single dialer: the offer was
        // the old incarnation's, and replaying it would re-arm a direct
        // attempt against the link this install just put up. So would an
        // offer buffered while a link existed (a re-emit of an offer that link
        // already answered), one staged under another build generation, or
        // one for a peer a direct attempt already owns. Those are dropped
        // with the old link, as before this replay existed.
        let staged_offer = self.buffered_offers.remove(&built.peer_id);
        let replay_offer = staged_offer.and_then(|staged| {
            let first_link = built.replace == Replace::NeverLive
                && !self.links.contains_key(&built.peer_id);
            let same_intent =
                staged.intent.is_none() || staged.intent == Some(built.generation);
            let owned_elsewhere = self.direct_pending.contains_key(&built.peer_id);
            if first_link && !staged.linked && same_intent && !owned_elsewhere {
                Some(staged.offer)
            } else {
                self.log.debug(&format!(
                    "dropping buffered transport-offer from {} on link install: \
                     first_link={first_link} buffered_with_link={} intent={:?} \
                     generation={} direct_pending={owned_elsewhere}",
                    built.peer_id, staged.linked, staged.intent, built.generation
                ));
                None
            }
        });
        // A stuck-attempt rebuild continues the SAME retry episode against the
        // same sid. `drop_link` below wipes everything keyed by that sid, which
        // made each off-loop rebuild install at attempts 0 with fresh digest
        // clocks: the ladder logged "retrying (2/5)" forever and a departed
        // peer was never retired (prod owner daemon, 12 dead sids re-dialled
        // every ~16 s until the link cap starved enrollment). Carry the episode.
        let carried = (built.replace == Replace::StuckAttempt)
            .then(|| self.stuck_episode(&built.peer_id))
            .flatten();
        self.drop_link(&built.peer_id);
        if webrtc_only {
            self.webrtc_only.insert(built.peer_id.clone());
        }
        self.links.insert(
            built.peer_id.clone(),
            Link {
                peer: Some(built.peer),
                info: built.info,
                name: built.name,
                uid: built.uid,
                transport: None,
                workers: vec![],
                generation: built.generation,
                source: built.source,
                attempt: None,
                worker_sources: SimHashSet::default(),
                attempts: 0,
                trusted: false,
                expected_secret: binding,
                lan_binding: None,
                verified_name: None,
                presence: Presence::Connecting,
                direct: false,
                direct_route: "direct-quic",
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: BindingStrength::None,
                identity_state: IdentityState::Pending,
                identity_cert_expires: None,
                principal_kind: PrincipalKind::OwnerDevice,
                host: self.host.clone(),
            },
        );
        if let Some(episode) = carried {
            self.restore_stuck_episode(&built.peer_id, episode);
        }
        if built.active_on_apply || pending_active || selected_while_building {
            self.active = Some(built.peer_id.clone());
        }
        self.log.debug(&format!(
            "tunlion: ESTABLISH peer={} caller={} early={} signals={}",
            built.peer_id, built.caller, early.len(), signals.len()
        ));
        for ev in early {
            let _ = self.tx.send(ev);
        }
        for signal in signals {
            let _ = self.tx.send(Ev::Signal(signal));
        }
        // Invariant: an offer buffered before any link or pending existed for
        // a never-live peer is replayed once, when that peer's first link
        // installs. Hand it back to the driver's own transport-offer arm
        // (refusal, re-arm, answer, or buffer again), whose single-dialer and
        // live-link guards still apply. It was removed from the map above, so
        // it replays once, and its envelope names exactly this pid.
        if let Some(offer) = replay_offer {
            self.log.debug(&format!(
                "replaying buffered transport-offer from {} on link install",
                built.peer_id
            ));
            let _ = self
                .tx
                .send(Ev::Signal(buffered_offer_signal(&built.peer_id, offer)));
        }
    }

    /// Final pre-dispatch gate. Transport-origin Control/PcState/ChannelReady/Chunk
    /// must carry an immutable SourceId; the event is accepted only if that
    /// source still belongs to the pid's CURRENT link at the moment the driver
    /// is about to handle it. A replacement after forwarding therefore cannot
    /// replay an old callback. Returns the inner event plus its source (used by
    /// handlers that defer/requeue the event).
    /// Stage an inbound signal for a candidate that is still being built.
    /// Returns true when consumed. Callers must invoke this before their normal
    /// signal handler. The candidate is named by the server-stamped envelope
    /// `from`; a payload's `to`/`from` is peer-controlled data and is never
    /// used to choose a build.
    ///
    /// Only the candidate's own SDP traffic (`description`/`candidate`) is
    /// staged: it is the one kind that needs the peer connection being built.
    /// Everything else (transport-hint, transport-offer, PAKE, identity,
    /// not-recognized, ...) returns false and takes the normal handler NOW. Held
    /// here it was invisible for the whole build and was discarded with the
    /// build when the build was cancelled.
    pub fn stage_signal(&mut self, data: &Value) -> bool {
        if !is_candidate_sdp_signal(data) {
            return false;
        }
        let Some(pid) = data["from"].as_str() else {
            return false;
        };
        if let Some(state) = self.builds.get_mut(pid) {
            if state.signals.len() >= MAX_BUILD_SIGNALS
                || state.signal_bytes + data.to_string().len() > MAX_BUILD_SIGNAL_BYTES
            {
                state.cancel.cancel();
                return true;
            }
            state.signal_bytes += data.to_string().len();
            state.signals.push_back(data.clone());
            return true;
        }
        if let Some((plan, _)) = self.build_deferred.get_mut(pid) {
            if plan.signals.len() >= MAX_BUILD_SIGNALS
                || plan.signal_bytes + data.to_string().len() > MAX_BUILD_SIGNAL_BYTES
            {
                return true;
            }
            plan.signal_bytes += data.to_string().len();
            plan.signals.push_back(data.clone());
            return true;
        }
        false
    }

    /// Hold a WebRTC offer or candidate that cannot be answered yet because our
    /// direct attempt for that sid is still pending (`prepare_build` refuses
    /// any build during a pending, and there is neither a link nor a build to
    /// stage into). The fallback responder's build takes the hold
    /// (`take_held`), so the offer is answered the moment the direct path
    /// loses; a direct win discards it. Returns true when the signal was
    /// consumed (held, or dropped by the bound), false when the caller should
    /// apply it as before.
    pub fn hold_for_direct(&mut self, envelope: &Value) -> bool {
        if !is_candidate_sdp_signal(envelope) {
            return false;
        }
        let Some(pid) = envelope["from"].as_str() else {
            return false;
        };
        if !self.direct_pending.contains_key(pid)
            || self.links.contains_key(pid)
            || self.build_pending(pid)
        {
            return false;
        }
        if self
            .held_signals
            .get(pid)
            .is_some_and(|h| supersedes_held(h, &envelope["data"]))
        {
            self.discard_held(pid, "a newer connection attempt arrived");
        }
        if !self.held_signals.contains_key(pid) {
            if self.held_signals.len() >= MAX_HELD_PEERS {
                self.held_signals.retain(|_, h| h.since.elapsed() < held_signal_ttl());
            }
            if self.held_signals.len() >= MAX_HELD_PEERS {
                return false;
            }
            self.held_signals.insert(
                pid.to_string(),
                HeldSignals {
                    since: Instant::now(),
                    pc: envelope["data"]["pc"].as_u64(),
                    has_offer: false,
                    signals: std::collections::VecDeque::new(),
                    bytes: 0,
                },
            );
        }
        let len = envelope.to_string().len();
        let offer = is_offer_data(&envelope["data"]);
        let Some(held) = self.held_signals.get_mut(pid) else {
            return false;
        };
        if held.signals.len() >= MAX_BUILD_SIGNALS || held.bytes + len > MAX_BUILD_SIGNAL_BYTES {
            return true;
        }
        held.has_offer |= offer;
        held.bytes += len;
        held.signals.push_back(envelope.clone());
        if offer {
            self.log.debug(&format!(
                "tunlion: HOLD-OFFER peer={pid}: direct attempt pending, holding its WebRTC offer for the fallback responder"
            ));
        }
        true
    }

    /// Drop `pid`'s held offer, if any, saying why.
    fn discard_held(&mut self, pid: &str, why: &str) {
        if let Some(held) = self.held_signals.remove(pid) {
            self.log.debug(&format!(
                "tunlion: HOLD-DISCARD peer={pid}: {} held signal(s) dropped, {why}",
                held.signals.len()
            ));
        }
    }

    /// Drop holds whose direct pending is gone with no build or link to take
    /// them, and holds past their age.
    fn reap_orphan_holds(&mut self) {
        let orphans: Vec<String> = self
            .held_signals
            .iter()
            .filter(|(pid, h)| {
                h.since.elapsed() >= held_signal_ttl()
                    || (!self.direct_pending.contains_key(pid.as_str())
                        && !self.build_pending(pid.as_str()))
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in orphans {
            self.discard_held(&pid, "its direct attempt ended with no build to answer it");
        }
    }

    /// Take `pid`'s held signals for the build being prepared, unless they aged out.
    fn take_held(&mut self, pid: &str) -> Option<HeldSignals> {
        let held = self.held_signals.remove(pid)?;
        if held.since.elapsed() >= held_signal_ttl() {
            self.log.debug(&format!(
                "tunlion: HOLD-DISCARD peer={pid}: {} held signal(s) dropped, expired",
                held.signals.len()
            ));
            return None;
        }
        Some(held)
    }

    /// True when a build for this peer is pending and no transport is installed
    /// yet. A signal that starts the candidate must be staged after this check.
    pub fn build_pending(&self, pid: &str) -> bool {
        (self.builds.contains_key(pid) || self.build_deferred.contains_key(pid))
            && self.transport_of(pid).is_none()
    }

    /// True while anything connects us to `pid`: an installed link, a WebRTC
    /// build that has not installed one yet, or a direct attempt. The build
    /// runs off the loop, so right after adoption a present peer has a build
    /// and no link; state that belongs to the peer's presence rather than to
    /// one transport must survive that window.
    pub fn connecting_or_linked(&self, pid: &str) -> bool {
        self.links.contains_key(pid)
            || self.builds.contains_key(pid)
            || self.build_deferred.contains_key(pid)
            || self.direct_pending.contains_key(pid)
    }

    /// A different binding the store still authorizes is a real re-pair and may
    /// supersede an older in-flight/deferred intent for the same pid. Any other
    /// case is a duplicate establish and is deduped.
    ///
    /// A candidate that has NO binding yet is not stale authority: it is the
    /// candidate the peer may be answering at that moment, and a binding claim
    /// is an authorization fact, not a new negotiation. Retiring it here is the
    /// cross-dial hang: the outbound fallback's claim retired the inbound
    /// responder candidate that carried the peer's offer, and the replacement
    /// then waited for a readiness the peer never sent, because the peer still
    /// held the link it had already answered.
    fn authorized_replacement(
        &self,
        current: &Option<(String, String)>,
        incoming: &Option<(String, String)>,
    ) -> bool {
        let Some((name, new)) = incoming else {
            return false;
        };
        if !self.binding_authorized(name, new) {
            return false;
        }
        match current {
            Some((_, old)) => old != new,
            None => false,
        }
    }

    /// The current device store is the authority for a binding. A hint, a stale
    /// envelope or an arbitrary string is not enough, and a revoked or
    /// forgotten secret never authorizes anything (it stays fail-closed). The
    /// durable record revocation is checked too: `devices_load` deliberately
    /// retains revoked rows with their pair secret until the next sweep.
    fn binding_authorized(&self, name: &str, secret: &str) -> bool {
        !secret.is_empty()
            && !self.revoked_bindings.contains(secret)
            && !self.host.device_record_revoked(name)
            && self.store_holds_binding(secret)
    }

    /// Keep a store-authorized binding claim on the candidate that is already
    /// building instead of minting a rival generation for the same pid.
    ///
    /// `apply_built_peer` reads `pending_bindings` at apply time, so recording
    /// it here is enough for the retained candidate to install bound to the
    /// claimed device. A DIFFERENT claim is never overwritten: that is a re-pair
    /// and takes the supersede path instead.
    fn claim_binding_on_pending_build(
        &mut self,
        peer_id: &str,
        carried: Option<(String, String)>,
    ) {
        let Some(binding) = carried.filter(|(name, secret)| self.binding_authorized(name, secret)) else {
            return;
        };
        if self
            .pending_bindings
            .get(peer_id)
            .is_some_and(|held| held.1 != binding.1)
        {
            return;
        }
        if let Some(state) = self.builds.get_mut(peer_id) {
            if state.binding.is_none() {
                state.binding = Some(binding.clone());
            }
        }
        if let Some((plan, _)) = self.build_deferred.get_mut(peer_id) {
            if plan.carried_secret.is_none() {
                plan.carried_secret = Some(binding.clone());
            }
        }
        self.pending_bindings.insert(peer_id.to_string(), binding);
    }

    /// Bind a LIVE, non-direct link that carries no binding yet to a
    /// store-authorized pair secret, then re-announce the transport it already
    /// serves, tagged with that transport's own immutable source.
    ///
    /// This is the reuse half of the cross-dial fix: refusing an establish must
    /// not leave behind a live-but-unclaimable link. Deliberately narrow -- a
    /// link that already holds a binding is left untouched (so a daemon's
    /// steady roster ticks never re-offer), and a direct link's binding stays
    /// owned by its attempt, never claimed here.
    fn claim_live_unbound_link(&mut self, peer_id: &str, carried: Option<(String, String)>) {
        let Some(binding) = carried.filter(|(name, secret)| self.binding_authorized(name, secret)) else {
            return;
        };
        let Some(link) = self.links.get(peer_id) else {
            return;
        };
        if link.direct || link.lan_binding.is_some() || link.expected_secret.is_some() {
            return;
        }
        let Some(t) = link.transport.as_ref().filter(|t| !t.is_dead()).cloned() else {
            return;
        };
        if let Some(link) = self.links.get_mut(peer_id) {
            link.expected_secret = Some(binding);
        }
        let _ = self.tx.send(Ev::sourced_channel_ready(peer_id.to_string(), t));
    }

    /// True when this build generation is no longer allowed to run or install.
    /// Both tombstones are per peer: a retirement for A says nothing about B.
    fn intent_retired(&self, pid: &str, generation: u32) -> bool {
        let cancelled = self
            .cancelled_intents
            .get(pid)
            .is_some_and(|r| generation <= r.generation);
        let revoked = self
            .revoked_peers
            .get(pid)
            .is_some_and(|r| generation <= r.generation);
        cancelled || revoked
    }

    /// Record a generation as terminal. Only the highest retired generation is
    /// kept; `next_gen` is monotonic, so a fresh intent is always above it.
    fn retire_intent(&mut self, pid: &str, generation: u32) {
        let entry = self
            .cancelled_intents
            .entry(pid.to_string())
            .or_insert(RetiredIntent { generation, at: Instant::now() });
        if generation > entry.generation {
            entry.generation = generation;
            entry.at = Instant::now();
        }
    }

    /// The current device store is the authority for a re-pair's binding. A
    /// hint, a stale envelope, or an arbitrary new string is not enough.
    fn store_holds_binding(&self, secret: &str) -> bool {
        !secret.is_empty()
            && self
                .host
                .devices_load()
                .iter()
                .any(|(_, held)| held == secret)
    }

    /// Is `pid`'s link the target device `(name, secret)` for ROUTING?
    ///
    /// A pair/proof link answers from its `expected_secret` SECRET alone (the
    /// historical rule; aliases and brokered rendezvous names must keep
    /// working). A LAN link answers only from an exact authenticated DEVICE
    /// reservation whose `(name, secret)` is still a LIVE current-store record
    /// (not revoked) and whose secret is not in the revoked set. Used by send's
    /// active-target selection so a LAN link authenticated with the target's
    /// pair secret is recognized without minting `verified_name`, `trusted`,
    /// Proven, or a worker key. This decides WHICH link carries the request,
    /// never what the peer may do.
    pub fn link_matches_device(&self, pid: &str, name: &str, secret: &str) -> bool {
        let Some(link) = self.links.get(pid) else { return false };
        // Preserve the pre-existing NON-LAN target rule exactly: the link's
        // pair-secret hypothesis matches on the SECRET only, so an alias or a
        // brokered rendezvous name that differs from `expected_secret.0` still
        // selects its link.
        if link
            .expected_secret
            .as_ref()
            .is_some_and(|(_, s)| s.as_str() == secret)
        {
            return true;
        }
        // LAN: only an exact authenticated DEVICE reservation (name AND
        // secret, live current-store record, not revoked) selects the target.
        let Some((_, bound_secret)) = link
            .lan_binding
            .as_ref()
            .and_then(|binding| binding.device.as_ref())
        else {
            return false;
        };
        if bound_secret.as_str() != secret {
            return false;
        }
        let devices = self.host.devices_load();
        link.authenticated_device_name(
            &devices,
            &self.revoked_bindings,
            &|name: &str| self.host.device_record_revoked(name),
        )
        .is_some_and(|held| held.eq_ignore_ascii_case(name))
    }

    /// The canonical stored device name of an exact authenticated LAN DEVICE
    /// link, for the daemon's BASELINE transfer consent only.
    ///
    /// The local LAN handshake already verified this device's pair-secret MAC,
    /// so for the transfer capability every paired device holds, a daemon may
    /// accept the offer without asking. This lookup sets nothing; a live LAN
    /// device link is already trusted as the pair from adoption.
    /// A revoked record, or a record that denies transfer, fails closed here
    /// even while its pair secret is still present in the store.
    pub fn authenticated_lan_peer(&self, pid: &str) -> Option<String> {
        let link = self.links.get(pid)?;
        let devices = self.host.devices_load();
        let name = link
            .authenticated_device_name(
                &devices,
                &self.revoked_bindings,
                &|name: &str| self.host.device_record_revoked(name),
            )?
            .to_string();
        if self.host.device_record_revoked(&name)
            || !self.host.device_allows(&name, "transfer")
            || self.host.device_capability_denied(&name, "transfer")
        {
            return None;
        }
        Some(name)
    }

    /// The name a link-keyed reply (the `reach-pong` registry) may key this link
    /// by: a PROVEN `verified_name`, else the canonical current-store name of an
    /// exact authenticated LAN DEVICE binding. Display/roster names are NEVER
    /// used; a revoked, unbound or fleet link answers `None`.
    pub fn link_peer_name(&self, pid: &str) -> Option<String> {
        self.links
            .get(pid)
            .and_then(|l| l.verified_name.clone())
            .or_else(|| self.authenticated_lan_peer(pid))
    }


    /// Refusal predicate for a build intent.
    ///
    /// A secret the store dropped refuses EVERY pid that presents it. A pid
    /// whose intent was explicitly revoked refuses a bare rebuild, and accepts
    /// only a binding the current store still holds (a real re-pair). Display
    /// names are never keys: several devices may share one.
    fn intent_blocked(&self, pid: &str, binding: Option<&(String, String)>) -> bool {
        if let Some((_, secret)) = binding {
            if !secret.is_empty() {
                if self.revoked_bindings.contains(secret) {
                    return true;
                }
                if self.revoked_peers.contains_key(pid) {
                    return !self.store_holds_binding(secret);
                }
                return false;
            }
        }
        self.revoked_peers.contains_key(pid)
    }

    /// Explicit forget/revoke invalidation for the departed set only.
    ///
    /// `revoked_secrets` are DEVICE secrets the store dropped (never a fleet
    /// rendezvous secret). Doomed pids are retired by pid+generation, which is
    /// enough for fleet links whose binding is shared across siblings. A build
    /// is retired only when its own binding is one of the dropped device
    /// secrets; a shared display name is not evidence and never names a target.
    pub fn invalidate_peers(
        &mut self,
        doomed: &[(String, String)],
        revoked_secrets: &HashSet<String>,
    ) {
        for secret in revoked_secrets {
            if !secret.is_empty() {
                self.revoked_bindings.insert(secret.clone());
            }
        }
        // Direct ownership is invalidated by exact attempt, never by pid alone
        // and never by a display name. A revoked DEVICE binding selects only
        // device-domain attempts; fleet and ephemeral attempts are selected only
        // when their own pid is doomed. A newer same-pid device attempt that the
        // current store proves survives its old link's forget.
        let doomed_pids: HashSet<String> =
            doomed.iter().map(|(pid, _)| pid.clone()).collect();
        let mut direct_targets: Vec<(String, net::AttemptId)> = Vec::new();
        let mut push_target = |pid: &str,
                               attempt: net::AttemptId,
                               targets: &mut Vec<(String, net::AttemptId)>| {
            if !targets.iter().any(|(p, a)| p.as_str() == pid && *a == attempt) {
                targets.push((pid.to_string(), attempt));
            }
        };
        for (pid, pending) in &self.direct_pending {
            let revoked_device = pending.auth.domain == DirectAuthDomain::Device
                && pending
                    .auth
                    .device_binding
                    .as_ref()
                    .is_some_and(|(_, secret)| revoked_secrets.contains(secret));
            let doomed_attempt = doomed_pids.contains(pid.as_str())
                && !self.direct_auth_survives_forget(pid, &pending.auth);
            if revoked_device || doomed_attempt {
                push_target(pid, pending.attempt, &mut direct_targets);
            }
        }
        // A standby may already have consumed its pending. Its immutable attempt
        // and authorization snapshot still identify exactly what to retire.
        for (pid, probe) in &self.resil.upgrade_probe {
            let Some(attempt) = probe.token else {
                continue;
            };
            let Some(auth) = probe.auth.as_ref() else {
                continue;
            };
            let revoked_device = auth.domain == DirectAuthDomain::Device
                && auth
                    .device_binding
                    .as_ref()
                    .is_some_and(|(_, secret)| revoked_secrets.contains(secret));
            let doomed_attempt =
                doomed_pids.contains(pid.as_str()) && !self.direct_auth_survives_forget(pid, auth);
            if revoked_device || doomed_attempt {
                push_target(pid, attempt, &mut direct_targets);
            }
        }
        for (pid, promotion) in &self.promotions {
            let (Some(attempt), Some(auth)) = (promotion.attempt, promotion.auth.as_ref()) else {
                continue;
            };
            let revoked_device = auth.domain == DirectAuthDomain::Device
                && auth
                    .device_binding
                    .as_ref()
                    .is_some_and(|(_, secret)| revoked_secrets.contains(secret));
            let doomed_attempt =
                doomed_pids.contains(pid.as_str()) && !self.direct_auth_survives_forget(pid, auth);
            if revoked_device || doomed_attempt {
                push_target(pid, attempt, &mut direct_targets);
            }
        }
        for (pid, attempt) in direct_targets {
            self.retire_direct_ownership(&pid, attempt);
        }
        let build_pids: Vec<(String, Option<String>)> = self
            .builds
            .keys()
            .map(|pid| {
                let secret = self
                    .pending_bindings
                    .get(pid)
                    .map(|(_, s)| s.clone())
                    .or_else(|| {
                        self.links
                            .get(pid)
                            .and_then(|l| l.expected_secret.as_ref().map(|(_, s)| s.clone()))
                    });
                (pid.clone(), secret)
            })
            .chain(self.build_deferred.iter().map(|(pid, (plan, _))| {
                (pid.clone(), plan.carried_secret.as_ref().map(|(_, s)| s.clone()))
            }))
            .collect();
        let mut targets: HashMap<String, u32> = HashMap::new();
        {
            let mut add = |pid: &str, generation: u32| {
                let entry = targets.entry(pid.to_string()).or_insert(0);
                *entry = (*entry).max(generation);
            };
            for (pid, _) in doomed {
                // Retire the LINK generation, not a newer authorized build
                // that may already be superseding it for the same pid.
                let generation = self.links.get(pid).map(|l| l.generation).unwrap_or(0);
                add(pid, generation);
            }
            for (pid, secret) in build_pids {
                if secret.as_deref().is_some_and(|s| revoked_secrets.contains(s)) {
                    let generation = self
                        .builds
                        .get(&pid)
                        .map(|state| state.generation)
                        .or_else(|| {
                            self.build_deferred
                                .get(&pid)
                                .map(|(plan, _)| plan.generation)
                        })
                        .unwrap_or(0);
                    add(&pid, generation);
                }
            }
        }
        for (pid, generation) in targets {
            let entry = self
                .revoked_peers
                .entry(pid.clone())
                .or_insert(RetiredIntent { generation, at: Instant::now() });
            if generation > entry.generation {
                entry.generation = generation;
                entry.at = Instant::now();
            }
            // Retire only intents at or below the revoked generation. A newer
            // authorized re-pair for the same pid must keep building.
            self.cancel_intent_through(&pid, generation);
        }
    }

    /// Cancel a build/deferred intent only when it belongs to the retired
    /// generation or older. A newer authorized intent survives.
    fn cancel_intent_through(&mut self, pid: &str, generation: u32) {
        let mut removed = false;
        if self
            .builds
            .get(pid)
            .is_some_and(|state| state.generation <= generation)
        {
            if let Some(state) = self.builds.remove(pid) {
                state.cancel.cancel();
                state.handle.abort();
                self.retire_intent(pid, state.generation);
                discard_pending_state(state);
                removed = true;
            }
        }
        if self
            .build_deferred
            .get(pid)
            .is_some_and(|(plan, _)| plan.generation <= generation)
        {
            if let Some((plan, _)) = self.build_deferred.remove(pid) {
                self.retire_intent(pid, plan.generation);
                removed = true;
            }
        }
        if removed {
            self.pending_bindings.remove(pid);
            self.pending_active.remove(pid);
        }
    }

    /// An authenticated vouch authorizes exactly this introduced secret again.
    /// Callers must already have passed trusted + same-owner + not-introduced
    /// and the store write. A different forgotten secret stays revoked.
    pub fn authorize_binding(&mut self, secret: &str) {
        if !secret.is_empty() {
            self.revoked_bindings.remove(secret);
        }
    }

    pub fn note_binding(&mut self, pid: &str, binding: (String, String)) {
        self.pending_bindings.insert(pid.to_string(), binding);
    }

    pub fn note_active(&mut self, pid: &str) {
        self.pending_active.insert(pid.to_string());
    }

    pub fn cancel_build(&mut self, pid: &str) {
        self.retire_build(pid);
        self.pending_bindings.remove(pid);
        self.pending_active.remove(pid);
    }

    /// Retire an in-flight/deferred intent without discarding the caller's
    /// just-recorded binding. Used when a re-pair supersedes an older intent.
    fn retire_build(&mut self, pid: &str) {
        if let Some(state) = self.builds.remove(pid) {
            state.cancel.cancel();
            state.handle.abort();
            self.retire_intent(pid, state.generation);
            discard_pending_state(state);
        }
        if let Some((plan, _)) = self.build_deferred.remove(pid) {
            // Deferred-only peers still need a tombstone: a queued Failed for
            // that generation must not re-queue a retry after this cancel.
            self.retire_intent(pid, plan.generation);
        }
    }

    pub fn cancel_builds(&mut self) {
        let pids: Vec<String> = self.builds.keys().cloned().collect();
        for pid in pids {
            self.cancel_build(&pid);
        }
        self.build_deferred.clear();
    }

    // --- rung-1 direct-QUIC path (TUNLION_DIRECT) ---------------------------
    //
    // Sequential by design: when both peers are CLIs and a pair secret is known,
    // try a direct authenticated QUIC connection FIRST and only fall back to the
    // WebRTC `establish` above if no authenticated connection lands within the
    // budget. The whole thing is gated on `direct::direct_enabled()`, so with the
    // flag OFF none of this runs and the WebRTC path is byte-for-byte unchanged.

    /// Remove a pending only when it is the expected attempt, transferring its
    /// already-terminal producer handle to an await-only cleanup. Used when the
    /// transport becomes the standby/link, so no tombstone is installed.
    fn take_pending_for_adoption(
        &mut self,
        pid: &str,
        expected: net::AttemptId,
    ) -> Option<DirectPending> {
        if self
            .direct_pending
            .get(pid)
            .is_some_and(|pending| pending.attempt != expected)
        {
            return None;
        }
        let mut pending = self.direct_pending.remove(pid)?;
        pending.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = pending.race_task.take() {
            tokio::spawn(async move {
                let _ = handle.await;
            });
        }
        Some(pending)
    }

    /// Reap tombstones whose producer is terminal and whose drain barrier has
    /// had [`RETIRED_TOMBSTONE_TTL`] to arrive. An undrained tombstone is kept
    /// however old: its producer may still emit a ready.
    fn reap_drained_tombstones(&mut self, now: Instant) {
        self.retired_attempts.retain(|_, retired| !retired.reapable(now));
    }

    /// Retire an attempt and enqueue its terminal-drain barrier only after the
    /// finite readiness producer is terminal.
    fn retire_attempt(
        &mut self,
        pid: &str,
        attempt: net::AttemptId,
        task: Option<tokio::task::JoinHandle<()>>,
    ) {
        if self.retired_attempts.contains_key(&attempt) {
            return;
        }
        let retired = RetiredAttempt::new(pid);
        let drained = retired.drained.clone();
        self.retired_attempts.insert(attempt, retired);
        match task {
            Some(handle) => {
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    // Normal return, early return, panic/JoinError: all terminal
                    // before the barrier is enqueued. A producer that never
                    // returns is aborted after the budget so one hung build
                    // cannot fill the tombstone cap and refuse every later
                    // direct attempt.
                    let mut handle = handle;
                    if tokio::time::timeout(RETIRED_DRAIN_BUDGET, &mut handle)
                        .await
                        .is_err()
                    {
                        handle.abort();
                        let _ = handle.await;
                    }
                    // Only now is the producer terminal: the tombstone may be
                    // reaped by age if this barrier is lost.
                    drained.store(true, Ordering::Release);
                    let _ = tx.send(Ev::AttemptDrained(attempt));
                });
            }
            None => {
                // A promotion-held readiness producer is synchronous; no async
                // producer can emit after this loop turn.
                drained.store(true, Ordering::Release);
                let _ = self.tx.send(Ev::AttemptDrained(attempt));
            }
        }
    }

    /// Remove a pending direct attempt and stop its offer re-emitter. Every
    /// abandonment path (hint, adoption, expiry) goes through here so the task
    /// cannot keep advertising a dial that no longer exists.
    fn take_direct_pending(&mut self, pid: &str) -> Option<DirectPending> {
        let mut pending = self.direct_pending.remove(pid)?;
        pending.cancel.store(true, Ordering::Relaxed);
        self.retire_attempt(pid, pending.attempt, pending.race_task.take());
        Some(pending)
    }

    /// Exact-attempt retirement: a newer pending for the same pid is untouched.
    fn take_direct_pending_if(
        &mut self,
        pid: &str,
        expected: net::AttemptId,
    ) -> Option<DirectPending> {
        if self
            .direct_pending
            .get(pid)
            .is_some_and(|pending| pending.attempt != expected)
        {
            return None;
        }
        self.take_direct_pending(pid)
    }

    /// Side-effect-free final authorization check for one direct attempt.
    ///
    /// Unknown provenance fails closed. A device binding must not be revoked and
    /// only needs current-store membership when the pid itself was revoked (a
    /// newer same-pid re-pair). An ephemeral or fleet attempt is never treated
    /// as a device binding; while its pid is revoked, neither has an explicit
    /// reauthorization context in this state, so both stay rejected.
    fn direct_attempt_authorized(
        &self,
        pid: &str,
        attempt: net::AttemptId,
        auth: Option<&DirectAuth>,
    ) -> bool {
        if self.retired_attempts.contains_key(&attempt) {
            return false;
        }
        let Some(auth) = auth else {
            return false;
        };
        match auth.domain {
            DirectAuthDomain::Device => {
                let Some((_, secret)) = auth.device_binding.as_ref() else {
                    return false;
                };
                if self.revoked_bindings.contains(secret) {
                    return false;
                }
                if let Some(revoked) = self.revoked_peers.get(pid) {
                    if auth.generation <= revoked.generation {
                        return false;
                    }
                    if !self.store_holds_binding(secret) {
                        return false;
                    }
                }
                true
            }
            DirectAuthDomain::Ephemeral | DirectAuthDomain::Fleet => {
                !self.revoked_peers.contains_key(pid)
            }
            DirectAuthDomain::Lan => {
                let Some((name, secret)) = auth.device_binding.as_ref() else {
                    return false;
                };
                if self.revoked_bindings.contains(secret) {
                    return false;
                }
                if let Some(revoked) = self.revoked_peers.get(pid) {
                    if auth.generation <= revoked.generation {
                        return false;
                    }
                }
                let devices = self.host.devices_load();
                let remembered = devices
                    .iter()
                    .any(|(held_name, _)| held_name.eq_ignore_ascii_case(name));
                if remembered {
                    devices.iter().any(|(held_name, held_secret)| {
                        held_name.eq_ignore_ascii_case(name) && held_secret == secret
                    })
                } else {
                    // First-time LAN pairing: no store entry exists yet. The
                    // exact reservation secret is still checked against
                    // revoked_bindings above.
                    true
                }
            }
        }
    }

    /// Shared, side-effect-free readiness gate. Source and attempt identities
    /// come from the transport, while authorization comes only from stored
    /// state passed by the caller. Duplicate means the exact same held or live
    /// Arc is already owned and is harmless; Reject closes only the incoming.
    fn check_direct_ready(
        &self,
        pid: &str,
        t: &Arc<dyn Transport>,
        expected_attempt: net::AttemptId,
        auth: Option<&DirectAuth>,
        held: Option<&Arc<dyn Transport>>,
    ) -> DirectReadyCheck {
        let Some(source) = t.source_id() else {
            return DirectReadyCheck::Reject;
        };
        let Some(attempt) = t.attempt_id() else {
            return DirectReadyCheck::Reject;
        };
        if attempt != expected_attempt {
            return DirectReadyCheck::Reject;
        }
        if held.is_some_and(|held| Arc::ptr_eq(held, t)) {
            return DirectReadyCheck::Duplicate;
        }
        if held.is_some() {
            return DirectReadyCheck::Reject;
        }
        if let Some(link) = self.links.get(pid) {
            if link.attempt == Some(attempt) {
                if link
                    .transport
                    .as_ref()
                    .is_some_and(|live| Arc::ptr_eq(live, t))
                {
                    return DirectReadyCheck::Duplicate;
                }
                return DirectReadyCheck::Reject;
            }
        }
        if !self.direct_attempt_authorized(pid, attempt, auth) {
            return DirectReadyCheck::Reject;
        }
        DirectReadyCheck::Accept { source, attempt }
    }

    /// A newer device attempt survives an old-link forget only when the current
    /// store proves the new binding and the attempt is newer than that link.
    fn direct_auth_survives_forget(&self, pid: &str, auth: &DirectAuth) -> bool {
        if auth.domain != DirectAuthDomain::Device {
            return false;
        }
        let Some((_, secret)) = auth.device_binding.as_ref() else {
            return false;
        };
        if self.revoked_bindings.contains(secret) || !self.store_holds_binding(secret) {
            return false;
        }
        let old_generation = self.links.get(pid).map(|link| link.generation).unwrap_or(0);
        auth.generation > old_generation
    }

    /// A newer current-store device binding may supersede a LIVE direct primary
    /// only when that primary's own binding is no longer current (the store
    /// dropped it, or revocation still marks it). Everything else keeps the
    /// no-hybrid rejection in `adopt_direct`: a different attempt must never
    /// leave the old transport installed under the new epoch.
    fn direct_supersedes_live_primary(
        &self,
        pid: &str,
        auth: Option<&DirectAuth>,
        existing: &Link,
    ) -> bool {
        let Some(auth) = auth else { return false; };
        if !self.direct_auth_survives_forget(pid, auth) {
            return false;
        }
        let Some((_, old_secret)) = existing.expected_secret.as_ref() else {
            return false;
        };
        self.revoked_bindings.contains(old_secret) || !self.store_holds_binding(old_secret)
    }

    /// Retire exactly one attempt and only the promotion, probe, or source
    /// entries that carry that same immutable attempt. Anything with different
    /// or unknown provenance is left alone and is re-checked at readiness.
    fn retire_direct_ownership(&mut self, pid: &str, attempt: net::AttemptId) {
        let _ = self.take_direct_pending_if(pid, attempt);
        if self
            .promotions
            .get(pid)
            .is_some_and(|promotion| promotion.attempt == Some(attempt))
        {
            if let Some(st) = self.promotions.remove(pid) {
                if let Some(answer) = st.answer {
                    let _ = answer.send(None);
                }
                if let Some((transport, _)) = st.standby {
                    transport.force_close();
                }
            }
        }
        if self
            .resil
            .upgrade_probe
            .get(pid)
            .is_some_and(|probe| probe.token == Some(attempt))
        {
            if let Some(probe) = self.resil.upgrade_probe.remove(pid) {
                if let Some(transport) = probe.standby {
                    transport.force_close();
                }
            }
        }
        self.sources.pending_sources
            .retain(|_, pending| !(pending.pid == pid && pending.attempt == Some(attempt)));
    }

    /// Whether a peer explicitly told us it has no direct-QUIC transport.
    ///
    /// The browser's PeerLink sends `{type:"transport-hint", direct:false}` as
    /// its FIRST signal, before any SDP. The direct-first ladder is correct for
    /// CLI peers, but a browser can never answer a QUIC `transport-offer`, so
    /// arming the ladder against one only makes it sit out DIRECT_BUDGET (plus
    /// the fallback tick) before WebRTC is even offered. That wait is exactly
    /// the web client's "connecting" stall. Treat an explicit `false` as a hard
    /// skip; absent (all CLI peers, and old browsers) keeps direct-first.
    pub(crate) fn direct_disabled_by_peer(v: &Value) -> bool {
        v.get("direct").and_then(Value::as_bool) == Some(false)
    }

    /// Record a peer's self-declared transport capabilities and cancel any
    /// direct attempt already armed against it. Returns true when the hint was
    /// understood (`direct:false`).
    ///
    /// This is deliberately separate from the establish effect (`accept_
    /// transport_hint`) so the state change is synchronous: the very next
    /// `start_direct` for this peer is a no-op, even if a periodic KnownPeer /
    /// warm-hold tick interleaves before the new WebRTC link is built.
    pub(crate) fn note_transport_hint(&mut self, pid: &str, data: &Value) -> bool {
        if !Self::direct_disabled_by_peer(data) {
            return false;
        }
        let cancelled = self.take_direct_pending(pid).is_some();
        // ONLY the transport fact is recorded, and `accept_transport_hint`
        // installs it after the establish below (an establish calls drop_link,
        // which clears per-link facts). A hint is unauthenticated and arrives
        // before pair-proof/PAKE; its uid/name must never enter the roster,
        // where the rest of the loop treats them as presence identity.
        if cancelled {
            self.log.debug(&format!(
                "tunlion: {pid} is WebRTC-only, cancelled the direct-QUIC wait"
            ));
        } else {
            self.log.debug(&format!(
                "tunlion: {pid} announced direct:false, skipping the direct-QUIC ladder"
            ));
        }
        true
    }

    /// Apply a peer's transport hint and immediately establish the WebRTC link
    /// when it says direct is unavailable. Called from the signaling loop before
    /// any SDP is handled, so the offer/answer starts at once instead of after
    /// the direct budget expires.
    pub async fn accept_transport_hint(&mut self, pid: &str, data: &Value) -> bool {
        // The hint cancels a direct attempt that was armed because we KNOW this
        // device (the pair (name, secret) lives only in that pending while no
        // Link exists). Read it BEFORE the cancel, so the WebRTC link built
        // below can inherit the binding. Without this the link is born
        // `expected_secret: None`: its ChannelReady cannot prove it is the
        // target we asked for, so it never becomes active, and the sender waits
        // out its whole establishment window as "no peer connected" while the
        // data channel is up and authenticated (gate 16, phase 2). This is the
        // same carry-forward `expired_direct`'s fallback caller does by hand.
        let carried = self.direct_pending.get(pid).map(|p| p.secret.clone());
        if let Some((name, secret)) = &carried {
            self.note_binding(pid, (name.clone(), secret.clone()));
        }
        // The hint must be visible to the build's prepare step even though the
        // build starts before the old post-await bookkeeping would run.
        self.webrtc_only.insert(pid.to_string());
        if !self.note_transport_hint(pid, data) {
            return false;
        }
        if self.links.contains_key(pid) || self.links.len() >= MAX_LINKS {
            self.carry_pending_secret(pid, carried);
            self.webrtc_only.insert(pid.to_string());
            return true;
        }
        let mut info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid }));
        // Use the hinted uid for the symmetric polite/impolite election only.
        // It is not written to the roster; the real name/uid arrive with the
        // authenticated presence/pair-proof events.
        if info.get("uid").is_none() {
            if let Some(uid) = data["uid"].as_str().filter(|s| !s.is_empty()) {
                if net::ensure_ascii_uid(uid).is_ok() {
                    info["uid"] = json!(uid);
                }
            }
        }
        if let Err(e) = self.establish_as(info, None).await {
            self.log
                .debug(&format!("tunlion: WebRTC establish after transport hint failed for {pid}: {e}"));
        }
        // The build applies the carried binding and the webrtc_only mark; the
        // post-await carry is only for a link that already exists.
        self.carry_pending_secret(pid, carried);
        true
    }

    /// Put the secret of a just-cancelled direct attempt back on the peer's
    /// link, if that link does not already have one. A rebuild must never lose
    /// the only binding to the device we asked for: `expected_secret` is what
    /// lets the link's ChannelReady prove it is the target, and what keys the
    /// post-channel pair-proof. `get_or_insert` keeps a binding already carried
    /// from a previous link authoritative.
    fn carry_pending_secret(&mut self, pid: &str, carried: Option<(String, String)>) {
        let Some(secret) = carried else { return };
        if let Some(link) = self.link_mut(pid) {
            link.expected_secret.get_or_insert(secret);
        }
    }

    /// Begin a direct attempt against `pid`: bind a quinn endpoint, advertise our
    /// candidates via a relayed `transport-offer`, and stash the pending state.
    /// No Link is created yet, it is born (with `peer: None`, pre-trusted) only
    /// when an authenticated connection wins (Ev::DirectReady). Idempotent per
    /// peer (a second call while pending is a no-op). The peer's own
    /// transport-offer (Ev::TransportOffer) drives the race.
    pub async fn start_direct(&mut self, pid: &str, name: &str, secret: &str) {
        self.start_direct_inner(pid, name, secret, DirectIntent::Normal)
            .await
    }

    /// Dial a same-owner device met on the fleet channel. There is no pair
    /// secret for such a peer, so the fleet rendezvous secret keys the MAC. The
    /// display name is deliberately one no petname can be, because it must never
    /// key into the capability store; `adopt_direct` leaves `verified_name`
    /// unset for fleet links regardless.
    pub async fn start_direct_fleet(&mut self, pid: &str, secret: &str) {
        self.start_direct_inner(pid, FLEET_LINK_NAME, secret, DirectIntent::Fleet)
            .await
    }

    /// Post-PAKE promotion, make-before-break. Dials direct QUIC with the
    /// ceremony secret while the authenticated WebRTC link keeps serving: the
    /// caller announces the retained link (`rearm_channel_ready`) and the
    /// transfer starts on it at once. When the race wins, the direct link is
    /// held as a standby and the two ends move to it at a frame boundary (see
    /// `handoff`); a race that never wins leaves WebRTC serving with nothing to
    /// rebuild. `role` says which end this is: the sender leads the handoff.
    ///
    /// This used to tear the WebRTC link down here ("Option A") and make the
    /// transfer wait for QUIC, 1.35 to 1.5 s after `authenticated` on every
    /// cross-network code transfer (and a full WebRTC rebuild when QUIC lost).
    pub async fn start_direct_promote(
        &mut self,
        pid: &str,
        name: &str,
        secret: &str,
        role: PromoteRole,
        peer_handoff: bool,
    ) -> Promotion {
        self.start_direct_inner(pid, name, secret, DirectIntent::Promote)
            .await;
        // An armed promotion is exactly an ephemeral pending: every early return
        // in start_direct_inner (direct off, browser peer, bind failure) leaves
        // none, and then there is nothing to hand off and nothing to track.
        let armed = self.direct_pending.get(pid).is_some_and(|p| p.ephemeral);
        if armed && !peer_handoff {
            // The peer is an older CLI (no `handoff` in its ceremony): it tears
            // its own WebRTC link down at confirm and adopts direct QUIC the
            // moment its race wins, and it would never answer `path-promote`.
            // Keeping our side of a link it is closing, or gating frames on an
            // answer it cannot give, only adds a stall. So do exactly what it
            // does: replace the link now (the pending is registered, so the
            // fallback reaper still has an attempt to expire).
            self.drop_link(pid);
            return Promotion::Replaced;
        }
        if armed {
            self.abandon_promotion(pid);
            let pending = self.direct_pending.get(pid);
            let attempt = pending.map(|pending| pending.attempt);
            let auth = pending.map(|pending| pending.auth.clone());
            let mut state = PromoteState::new(role);
            state.attempt = attempt;
            state.auth = auth;
            self.promotions.insert(pid.to_string(), state);
            self.gate_for_promotion(pid);
        }
        Promotion::Retained
    }

    /// Lead end: put the frame gate around the serving WebRTC transport, so a
    /// transfer that starts on it can be moved at a boundary. Idempotent; a
    /// no-op until the link has a transport (the channel may open after the
    /// ceremony; `mark_ready` calls this again when it does).
    fn gate_for_promotion(&mut self, pid: &str) {
        let Some(st) = self.promotions.get_mut(pid) else {
            return;
        };
        if st.role != PromoteRole::Lead || st.handed {
            return;
        }
        let Some(l) = self.links.get_mut(pid) else {
            return;
        };
        if l.direct {
            return;
        }
        let Some(t) = l.transport.clone() else {
            return;
        };
        if handoff::as_handoff(&t).is_some() {
            return; // already gated
        }
        let gate = HandoffTransport::wrap(t);
        let wrapped: Arc<dyn Transport> = gate.clone();
        l.transport = Some(wrapped);
        st.gate = Some(gate);
    }

    /// Forget a promotion: release a barrier still waiting on the peer onto the
    /// serving path, and close a standby nothing will adopt.
    fn abandon_promotion(&mut self, pid: &str) {
        if let Some(st) = self.promotions.remove(pid) {
            if let Some(answer) = st.answer {
                let _ = answer.send(None);
            }
            if let Some((t, _)) = st.standby {
                t.force_close();
            }
            if let Some(attempt) = st.attempt {
                self.sources.pending_sources
                    .retain(|_, pending| !(pending.pid == pid && pending.attempt == Some(attempt)));
            }
        }
    }

    /// P5 (GAP-6): arm a relay->direct UPGRADE probe, a direct dial run
    /// ALONGSIDE the live relay link. Bypasses the `relay_committed` /
    /// already-linked early-returns of `start_direct` (the whole POINT is to dial
    /// direct while a relay link serves), and marks the `DirectPending` as a
    /// probe so the winner posts `Ev::DirectUpgradeReady` (verify-before-upgrade)
    /// rather than clobbering the serving relay link. A no-op if a probe is
    /// already in flight for this peer.
    async fn start_upgrade_probe(&mut self, pid: &str, name: &str, secret: &str) {
        // A probe must not re-arm a binding the store dropped or a pid whose
        // current authorization was revoked. The relay path stays serving.
        if self.intent_blocked(pid, Some(&(name.to_string(), secret.to_string()))) {
            self.resil.upgrade_probe.remove(pid);
            return;
        }
        // A probe already in flight (its own DirectPending), don't double-dial.
        if self.direct_pending.contains_key(pid) {
            return;
        }
        self.start_direct_inner(pid, name, secret, DirectIntent::Probe)
            .await;
        // Capture the upstream attempt and authorization BEFORE any readiness can
        // arrive; the probe token is an authorization identity, never inferred
        // from a ready.
        if let Some(pending) = self.direct_pending.get(pid) {
            let attempt = pending.attempt;
            let auth = pending.auth.clone();
            if let Some(probe) = self.resil.upgrade_probe.get_mut(pid) {
                probe.token = Some(attempt);
                probe.auth = Some(auth);
            }
        }
    }

    /// Ensure we have a TCP listener for local connections.
    async fn ensure_local_listener(&mut self) -> u16 {
        if let Some(p) = self.local_port {
            return p;
        }
        let (listener, port) = crate::local::listen_local().await.unwrap();
        self.local_listener = Some(Arc::new(listener));
        self.local_port = Some(port);
        port
    }

    /// No intent tears down a live link here. `Promote` (after PAKE) dials
    /// alongside the serving WebRTC link and its winner becomes a standby that
    /// replaces the link only through the handoff, once both ends agree.
    /// Every other caller (known-peer appeared, warm-hold, re-dial) must leave
    /// a healthy link alone too: dropping it is what broke
    /// `warm_all_makes_first_contact_warm`, because warm-hold's whole job is to
    /// have a link already up when first contact arrives.
    async fn start_direct_inner(
        &mut self,
        pid: &str,
        name: &str,
        secret: &str,
        intent: DirectIntent,
    ) {
        let probe = intent == DirectIntent::Probe;
        // Gate on the per-session flag, not the bare env check: the L2/ssh
        // acceptor (`up --shell`) sets `direct_ok` true even with the env unset,
        // so it answers the initiator's transport-offer (rung-1 direct-QUIC over
        // the reachable host candidate) instead of building a colliding WebRTC
        // peer that glares with the initiator's offer.
        if !self.direct_ok {
            return;
        }
        // Browser peers announced `direct:false` before their SDP. There is no
        // QUIC stack on the other end, so arming the ladder would buy nothing
        // and cost the whole DIRECT_BUDGET before WebRTC is offered. CLI peers
        // carry no hint and keep direct-first unchanged.
        if self.webrtc_only.contains(pid) {
            return;
        }
        if !probe && self.resil.relay_committed.contains(pid) {
            // P1: this peer escalated to relay, never re-dial direct (it would
            // only re-freeze and race the relay link). If a link already exists
            // (the relay link that escalate_to_relay built, possibly still
            // converging), DON'T rebuild it, repeated KnownPeer/`appeared` events
            // would otherwise tear it down and re-establish mid-handshake, so it
            // never connects ("stuck while connecting"). Only (re)establish over
            // relay when there is no link at all to carry the session.
            // P5 (GAP-6): a `probe` deliberately bypasses this guard, it dials
            // direct ALONGSIDE the serving relay link (warm direct standby) and
            // never touches `links`, so it cannot disturb the relay path.
            if !self.links.contains_key(pid) {
                let info = json!({ "id": pid, "name": name });
                if let Err(e) = self.establish_as(info, None).await {
                    self.log.debug(&format!("  re-establish for {pid} failed: {e}"));
                }
            }
            return;
        }
        // A probe expects a relay link to be present (it's the one we'd upgrade
        // AWAY from); only the cold path bails when a link already exists.
        // #246: a link without a transport and without workers is NOT
        // necessarily dead. A WebRTC link that just finished `establish` has
        // exactly that shape: peer present, ICE gathering, presence
        // Connecting. Judging it dead here is what destroyed the in-flight
        // ICE agent about a second into the relay fallback, on every 5s direct
        // retry, forever. A link is dead only when BOTH nothing is serving AND
        // its peer has reached a terminal state (Failed/Closed) or is absent.
        let link_dead = self
            .links
            .get(pid)
            .map(|l| {
                let peer_live = l.peer.as_ref().map(|p| p.is_live()).unwrap_or(false);
                link_dead_for(
                    peer_live,
                    l.transport.as_ref().map(|t| t.is_dead()).unwrap_or(true),
                    l.workers.iter().all(|w| w.is_dead()),
                )
            })
            .unwrap_or(false);
        if link_dead {
            // The link is already dead, so destroying it loses nothing. Its
            // PENDING is a different matter, see `supersede`.
            self.drop_link(pid);
        }
        // A stale pending must not BLOCK a fresh attempt, but REMOVING it here
        // would disarm the fallback, and the two are not the same thing.
        //
        // `expired_direct` reaps a pending in order to fire the WebRTC
        // re-establish, so a pending removed now and not replaced is a recovery
        // trigger that can never fire. `bind_endpoint` is ~24 lines below and
        // returns ~100 lines BEFORE the re-insert, so a box where bind fails
        // (which is exactly a box where the previous attempt died and left a
        // dead link, so the two conditions co-occur by construction rather than
        // by coincidence) ends with no link, no pending, and nothing armed.
        //
        // That is the same destroy-without-a-successor shape as the teardown
        // bug this file already fixed, one level up: not the link this time,
        // the recovery trigger. The rule is identical. Do not remove the
        // pending until you are certain you can replace it.
        //
        // So the decision to supersede is made WITHOUT mutating. The insert
        // below replaces the entry, and that is the first point at which we are
        // certain a replacement exists. A promotion supersedes for its own
        // reason: any pending started before PAKE completed was dialled without
        // the shared secret and cannot authenticate, so letting it block the
        // promotion is how the promotion silently never runs.
        let supersede = link_dead || intent == DirectIntent::Promote;
        if self.direct_pending.contains_key(pid) && !supersede {
            return; // already trying
        }
        // A live link is a REASON TO STOP for everyone except a deliberate
        // promotion, the one caller that intends to (eventually) replace it.
        // #246: `has_live_transport` now counts a mid-establish WebRTC peer as
        // live, so a Normal re-dial YIELDS to an establish that is still
        // making progress instead of arming a fresh direct attempt whose own
        // 5s fallback timer would then re-enter `establish` at the same cursor
        // and swap the still-establishing link. That is the livelock relocated
        // rather than removed, which is why both gates are needed. Promote
        // bypasses on purpose (it dials beside the live link it means to
        // displace, through the handoff, never by tearing it down), and Probe
        // bypasses on purpose (it dials ALONGSIDE the serving relay link and
        // never touches `links`, so it cannot disturb an establish it did not
        // create).
        if intent == DirectIntent::Normal && self.has_live_transport(pid) {
            return; // already linked via a live transport
        }

        // The retirement drain is BOUNDED (MAX_RETIRED_ATTEMPTS), and a full
        // drain refuses every new direct attempt for the whole session. So the
        // check comes before a QUIC endpoint is bound, before candidates are
        // gathered (that includes an HTTP whoami), before a transport-offer is
        // emitted, and before the 6x/1.2s re-emitter is spawned. Checked last,
        // every refused attempt had already paid all of that and left a
        // re-emitter running with a cancel flag on a pending that was never
        // created: one stuck build became a session-wide outage and an
        // unstoppable burst. It comes AFTER the relay recovery and the no-op
        // returns above, which consume no drain capacity: refusing those on a
        // full drain left a relay-committed peer disconnected.
        if self.retired_attempts.len() >= MAX_RETIRED_ATTEMPTS {
            // Liveness backstop for a lost drain event. Only a tombstone whose
            // producer is terminal is reaped; a live producer keeps its slot
            // and this attempt fails closed below.
            self.reap_drained_tombstones(Instant::now());
            if self.retired_attempts.len() >= MAX_RETIRED_ATTEMPTS {
                self.log.debug(&format!(
                    "tunlion: direct attempt for {pid} refused: retirement drain capacity full"
                ));
                return;
            }
        }

        // Check if target is same-machine peer (local transport).
        let peer_uid = self.roster.get(pid).and_then(|info| info["uid"].as_str());
        let is_local = LOCAL_TCP_TRANSPORT && self.host.is_self_uid(&self.my_uid, peer_uid);

        let (ep, port) = if is_local {
            // For local peers, we don't need a QUIC endpoint.
            (None, 0u16)
        } else {
            match direct::bind_endpoint_with_context(&self.transport_context) {
                Ok(v) => {
                    // Clone for multi-stream worker connections before the
                    // original is consumed by the race in on_transport_offer.
                    if net::direct_streams() > 1 {
                        self.direct_endpoint = Some(v.0.clone());
                    }
                    (Some(v.0), v.1)
                }
                Err(e) => {
                    // Keep the existing WebRTC link: direct_pending is not
                    // registered yet, so the fallback reaper has nothing to
                    // expire. The caller must retain a working path on failure.
                    self.log.debug(&format!(
                        "tunlion: direct disabled (endpoint bind failed: {e}); WebRTC retained"
                    ));
                    return;
                }
            }
        };
        // Candidate gathering is network I/O: the `/api/whoami` round trip on
        // a cold cache (its timeout is 3 s, and the first contact after a
        // daemon start always finds the cache cold) and, with
        // TUNLION_HOLEPUNCH, an `/api/config` fetch plus STUN. Awaited here it
        // parked the whole daemon event loop on a known-peer contact (chaos
        // finding 83681ee4ef: 1224 ms in handler/KnownPeer, a restarted daemon
        // under 20% loss). So the pending is armed NOW, because idempotency,
        // the fallback reaper, promotion and the offer buffer all key on it,
        // and the gathering, the transport-offer and its re-emits run on a
        // task (`gather_and_offer`). The task reports the rung-2 socket back
        // through `pump_builds` and sends the offer the moment gathering ends,
        // as the inline path did: no round trip is added to a connect.
        //
        // A same-machine peer needs no gathering: its one candidate is the
        // local TCP listener, bound here (a local bind, no network).
        let local_cands = if is_local {
            if self.local_port.is_none() {
                let (listener, port) = crate::local::listen_local().await.unwrap();
                self.local_listener = Some(Arc::new(listener));
                self.local_port = Some(port);
            }
            Some(vec![format!(
                "{{\"type\":\"tcp-localhost\",\"port\":{}}}",
                self.local_port.unwrap()
            )])
        } else {
            None
        };
        let cancel_emitter = Arc::new(AtomicBool::new(false));
        let attempt = net::AttemptId::next();
        self.next_gen += 1;
        let auth = match intent {
            DirectIntent::Fleet => DirectAuth::fleet(self.next_gen),
            DirectIntent::Promote => DirectAuth::ephemeral(self.next_gen),
            DirectIntent::Normal | DirectIntent::Probe => {
                DirectAuth::device(self.next_gen, name, secret)
            }
        };
        // Until gathering reports, the reaper deadline also covers the
        // gathering itself. `apply_direct_gathered` restarts the ladder budget
        // when the offer goes out, which is when it always started.
        let deadline = Instant::now() + DIRECT_GATHER_GRACE + direct_ladder_budget();
        // A peer offer stashed for a superseded gathering is this pid's latest
        // offer: it carries over to the attempt that replaces it.
        let carried = self.direct_gathering.remove(pid).and_then(|g| g.offer);
        self.direct_pending.insert(
            pid.to_string(),
            DirectPending {
                attempt,
                auth,
                race_task: None,
                fleet: intent == DirectIntent::Fleet,
                lan: false,
                ephemeral: intent == DirectIntent::Promote,
                secret: (name.to_string(), secret.to_string()),
                deadline,
                racing: false,
                endpoint: ep,
                // rung-2: filled by `apply_direct_gathered`.
                punch_sock: None,
                my_srflx: None,
                // #237: the peer's server-asserted candidate arrives with its transport-offer
                // (on_transport_offer fills it); at insert time no offer has
                // arrived yet. The per-address dial gate starts false and flips
                // only when the race dials exactly the claimed address.
                peer_server_public: None,
                server_public_dialed: Arc::new(AtomicBool::new(false)),
                probe,
                cancel: cancel_emitter.clone(),
            },
        );
        self.direct_gathering
            .insert(pid.to_string(), DirectGathering { attempt, offer: carried });
        // Nothing is torn down here, for any intent. A promotion keeps the
        // serving WebRTC link and its winner is routed to the handoff as a
        // standby (`on_transport_offer`); upgrade probes keep their relay link.
        tokio::spawn(gather_and_offer(GatherJob {
            context: self.transport_context.clone(),
            server: self.server.clone(),
            sio: self.sio.clone(),
            log: self.log.clone(),
            pid: pid.to_string(),
            name: name.to_string(),
            attempt,
            port,
            local_cands,
            channel: self.host.channel_of(secret),
            probe,
            cancel: cancel_emitter,
            done: self.direct_gathered.clone(),
            wake: self.tx.clone(),
        }));
    }

    /// A gathering task finished (`gather_and_offer`): hand its rung-2 socket
    /// to the pending it was started for, restart that pending's ladder
    /// budget from now (the offer is going out), and race the peer's offer if
    /// one arrived while we were gathering. A report for an attempt that was
    /// replaced or retired meanwhile changes nothing; the peer offer it held
    /// is kept for the next attempt, as an offer with no pending always is.
    fn apply_direct_gathered(&mut self, done: DirectGathered) {
        let DirectGathered { pid, attempt, punch_sock, my_srflx } = done;
        let stashed = match self.direct_gathering.get(&pid) {
            Some(g) if g.attempt == attempt => {
                self.direct_gathering.remove(&pid).and_then(|g| g.offer)
            }
            _ => None,
        };
        let Some(p) = self
            .direct_pending
            .get_mut(&pid)
            .filter(|p| p.attempt == attempt)
        else {
            if let Some(offer) = stashed {
                self.buffer_offer(&pid, offer);
            }
            return;
        };
        p.punch_sock = punch_sock;
        p.my_srflx = my_srflx;
        p.deadline = Instant::now() + direct_ladder_budget();
        // Bug 2: replay a transport-offer that was buffered while we had no
        // DirectPending (the sender re-dialed after a mid-transfer death), or
        // one that arrived while this attempt was gathering.
        let offer = stashed.or_else(|| self.buffered_offers.remove(&pid).map(|s| s.offer));
        if let Some((cands, srflx, server_public, proto, _ch)) = offer {
            self.log.debug(&format!("replaying buffered transport-offer from {pid}"));
            self.on_transport_offer(&pid, cands, srflx, server_public, proto);
        }
    }

    /// Is `pid`'s pending direct attempt still gathering its candidates (no
    /// offer of ours out yet, no rung-2 socket)?
    fn direct_gathering_for(&self, pid: &str) -> bool {
        match (self.direct_gathering.get(pid), self.direct_pending.get(pid)) {
            (Some(g), Some(p)) => g.attempt == p.attempt,
            _ => false,
        }
    }

    /// The peer advertised its candidates. If we have a matching pending attempt
    /// and haven't started the race yet, consume the endpoint and spawn the
    /// simultaneous-open + auth race; the winner posts Ev::DirectReady (or, for an
    /// upgrade probe, Ev::DirectUpgradeReady, verify-before-upgrade).
    /// `peer_server_public`/`peer_proto` come from the peer's transport-offer
    /// (#237): the server-asserted candidate the peer adopted (which OUR race
    /// will dial) and the protocol version that gates the observed-address
    /// exchange.
    pub fn on_transport_offer(
        &mut self,
        pid: &str,
        peer_cands: Vec<String>,
        peer_srflx: Option<String>,
        peer_server_public: Option<String>,
        peer_proto: u8,
    ) {
        // A peer that announced `direct:false` cannot consume this path. Ignore
        // a late/contradictory offer rather than spawning a race that could
        // later replace the WebRTC link the hint asked us to build.
        if self.webrtc_only.contains(pid) {
            return;
        }
        // Our own candidates are still being gathered: race this offer once
        // they are (`apply_direct_gathered`), with the rung-2 socket in hand.
        // The latest offer wins, as a re-emit replaces a buffered one.
        if self.direct_gathering_for(pid) {
            if let Some(g) = self.direct_gathering.get_mut(pid) {
                g.offer = Some((peer_cands, peer_srflx, peer_server_public, peer_proto, None));
            }
            return;
        }
        let Some(p) = self.direct_pending.get_mut(pid) else {
            return;
        };
        if p.racing {
            return;
        }
        let Some(ep) = p.endpoint.take() else { return };
        // #237: record what the peer advertised on the server's say-so, BEFORE the
        // race consumes the endpoint. The claim is WIRE DATA and untrusted:
        // it only becomes a fact when the race dials that exact address (the
        // dial site sets server_public_dialed, nothing else can).
        let peer_name = p.secret.0.clone();
        // An unparseable claim can never be dialed (there is no such address);
        // passing None keeps it silent, which is the safe direction.
        let peer_claimed = peer_server_public
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let server_public_dialed = p.server_public_dialed.clone();
        p.peer_server_public = peer_server_public;
        // #237 (mixed-fleet): a peer running an older build (no `proto` >= 2 in
        // its offer) gets a clear sentence instead of a hang or a mismatch. The
        // observed-address exchange is skipped on BOTH sides (the race below is
        // told `exchange=false`, so the stream stays byte-identical to the old
        // protocol and the direct link still forms). A refusal without a
        // sentence is just a support mystery; this is the sentence.
        if peer_proto < 2 {
            self.log.say(&format!(
                "peer {peer_name} is running an older build without the direct address exchange; link still works, address supersession skipped"
            ));
        }
        p.racing = true;
        let secret = p.secret.1.clone();
        // P5 (GAP-6): is THIS the upgrade-probe pending? Then the winner posts
        // DirectUpgradeReady (verify-before-upgrade) so the serving relay link is
        // never clobbered. A cold pending posts DirectReady as before.
        let is_probe = p.probe;
        let attempt = p.attempt;
        // A post-PAKE promotion's winner must not clobber the serving WebRTC
        // link either: it is a standby for the make-before-break handoff, and
        // every loop that promotes routes this event to the same stash.
        let standby = is_probe || (p.ephemeral && self.promotions.contains_key(pid));
        // rung-2: hand the punch socket + peer's srflx to the chained ladder.
        let punch_sock = p.punch_sock.take();
        let peer_srflx_addr = peer_srflx
            .as_deref()
            .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
        let tx = self.tx.clone();
        let pid_s = pid.to_string();
        // #237: the observed-address exchange runs only when BOTH ends agreed
        // (our build is proto 2, so the negotiator is the peer's advertised
        // version). The peer computes the same boolean from OUR offer, so both
        // sides skip or both sides run - never one of each.
        let exchange = peer_proto >= 2;
        let peer_uid = self
            .roster
            .get(pid)
            .and_then(|info| info["uid"].as_str())
            .map(str::to_owned);
        let Some(peer_uid) = peer_uid else {
            eprintln!("direct role election deferred for {pid}: no peer UID");
            return;
        };
        let my_uid = self.my_uid.clone();
        let my_id = self.my_id.clone();
        let mk = move |pid: String, t: Arc<dyn Transport>, route: &'static str| {
            if standby {
                Ev::DirectUpgradeReady(pid, t, route)
            } else {
                Ev::DirectReady(pid, t, route)
            }
        };
        // The race runs off the event loop, so it carries its own handle to the
        // log sink rather than borrowing `self`.
        let log = self.log.clone();
        let context = self.transport_context.clone();
        let race_task = tokio::spawn(async move {
            // Check for TCP localhost candidate (same-machine peer).
            for cand in &peer_cands {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(cand) {
                    if v["type"] == "tcp-localhost" {
                        if let Some(port) = v["port"].as_u64() {
                            let addr = format!("127.0.0.1:{port}");
                            log.trace(&format!("tunlion: trying TCP localhost to {addr}"));
                            match crate::local::LocalTransport::connect(&addr, attempt).await {
                                Ok(t) => {
                                    let _ = tx.send(mk(pid_s, Arc::new(t), "local-tcp"));
                                    return;
                                }
                                Err(e) => {
                                    log.trace(&format!("tunlion: TCP localhost failed: {e}"));
                                }
                            }
                        }
                    }
                }
            }
            // rung-1: direct-dial QUIC over host candidates. The answerer role is
            // derived inside the race from both endpoint identity tuples, so the
            // connector and offer-receiver cannot drift via caller literals.
            if let Some(t) = direct::race_connect(
                &context,
                ep,
                peer_cands,
                &secret,
                pid_s.clone(),
                attempt,
                my_uid.clone(),
                peer_uid.clone(),
                my_id.clone(),
                tx.clone(),
                exchange,
                peer_claimed,
                server_public_dialed.clone(),
            )
            .await
            {
                direct::test_setup_delay().await;
                t.announce(&tx, |t| mk(pid_s, t, "direct-quic"));
                return;
            }
            // rung-2: UDP hole-punch, then rung-1's QUIC race over the punched
            // socket. Only fires with the flag on, a punch socket bound, and a
            // peer srflx to punch toward. On failure (e.g. symmetric NAT) we fall
            // through to the WebRTC step-down via the per-tick reaper.
            if holepunch::holepunch_enabled() {
                if let (Some(sock), Some(peer_srflx)) = (punch_sock, peer_srflx_addr) {
                    // TRACE, direct/hole-punch detail.
                    log.trace(&format!(
                        "tunlion: rung-1 failed, attempting hole-punch to {peer_srflx}"
                    ));
                    if let Some(t) = holepunch::connect(
                        &context,
                        sock,
                        peer_srflx,
                        &secret,
                        pid_s.clone(),
                        attempt,
                        my_uid.clone(),
                        peer_uid.clone(),
                        my_id.clone(),
                        tx.clone(),
                        exchange,
                        // The punched race dials ONLY the srflx, never the
                        // claimed server-asserted address, so it cannot set the
                        // flag that would let the fallback name that address.
                        None,
                        server_public_dialed.clone(),
                        log.clone(),
                    )
                    .await
                    {
                        direct::test_setup_delay().await;
                        t.announce(&tx, |t| mk(pid_s, t, "holepunched"));
                        return;
                    }
                }
            }
            // On None the per-tick reaper handles the WebRTC fallback at deadline.
        });
        if let Some(pending) = self.direct_pending.get_mut(pid) {
            pending.race_task = Some(race_task);
        }
    }

    /// P5 (GAP-6): a relay-committed peer received an UPGRADE-PROBE transport-
    /// offer (`probe:true`) from the other end while we have no probe pending of
    /// our own yet. ARM a matching upgrade probe so the symmetric direct dial can
    /// complete (both ends must offer their candidates for the QUIC simultaneous-
    /// open race). Only fires for a peer we are actually serving on relay
    /// (`relay_committed` + a live link) and only when the prober is enabled and
    /// relay isn't forbidden, otherwise the probe offer is ignored.
    pub async fn answer_upgrade_probe(&mut self, pid: &str) {
        if !net::upgrade_prober_enabled() || self.host.relay_forbidden() {
            return;
        }
        if !self.resil.relay_committed.contains(pid) || !self.links.contains_key(pid) {
            return;
        }
        if self.direct_pending.contains_key(pid) {
            return; // our own probe is already in flight, its race will consume the offer
        }
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        if let Some((name, secret)) = known {
            self.start_upgrade_probe(pid, &name, &secret).await;
        }
    }

    /// File a link the local daemon carries for a one-shot send (warm send,
    /// `l2::warm_send`) under `pid`, as a pre-authenticated direct link to the
    /// known device `name`. The daemon's link is identity-proven (it only
    /// offers one it holds a verified binding for) and direct; this process
    /// never dialed it, so there is no pending attempt to match and no worker
    /// to stripe over. The caller emits the ready event, as for any link.
    /// Refuses (false) a transport with no source identity, or a `pid` that is
    /// already filed: a warm link never replaces anything.
    pub fn adopt_warm_link(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        name: &str,
        secret: &str,
        route: &'static str,
    ) -> bool {
        let Some(source) = t.source_id() else {
            return false;
        };
        if self.links.contains_key(pid) {
            return false;
        }
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info: json!({ "id": pid, "name": name }),
                name: name.to_string(),
                uid: None,
                transport: Some(t),
                workers: vec![],
                generation,
                source,
                attempt: None,
                worker_sources: SimHashSet::default(),
                attempts: 0,
                trusted: true,
                verified_name: Some(name.to_string()),
                expected_secret: Some((name.to_string(), secret.to_string())),
                lan_binding: None,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: BindingStrength::None,
                identity_state: IdentityState::Pending,
                identity_cert_expires: None,
                principal_kind: PrincipalKind::OwnerDevice,
                host: self.host.clone(),
            },
        );
        true
    }

    /// Create the Link for a direct connection that won the race. `peer: None`
    /// (no WebRTC), `direct: true`, `trusted: true` (the pair-secret MAC already
    /// proved identity, at least as strong as the DTLS pair-proof it replaces).
    pub fn adopt_direct(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) -> DirectAdoption {
        let Some(source) = t.source_id() else {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: transport has no source identity"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        };
        let Some(attempt) = t.attempt_id() else {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: transport has no attempt identity"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        };
        // Exact already-owned duplicate: same attempt and same transport Arc.
        if let Some(existing) = self.links.get(pid) {
            if existing.attempt == Some(attempt) {
                if existing
                    .transport
                    .as_ref()
                    .is_some_and(|live| Arc::ptr_eq(live, &t))
                {
                    return DirectAdoption::Duplicate;
                }
                t.force_close();
                return DirectAdoption::Rejected;
            }
        }
        if self.retired_attempts.contains_key(&attempt) {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: attempt retired"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        }
        // LAN ownership is carried by the reservation `lan_glue::seed_lan`
        // creates from LanEvent::Linked. It is an ordinary pending here, so
        // adoption matches and consumes only that exact reservation. A LAN
        // ready with no reservation fails closed like every other route.
        // Validate attempt ownership BEFORE reading pending state or mutating
        // any state. A promotion-held standby is the only no-pending owner.
        if let Some(pending) = self.direct_pending.get(pid) {
            if pending.attempt != attempt {
                self.log.debug(&format!(
                    "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: ready attempt does not match pending"
                ));
                t.force_close();
                return DirectAdoption::Rejected;
            }
        } else if !self
            .promotions
            .get(pid)
            .is_some_and(|promotion| promotion.attempt == Some(attempt))
        {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: no attempt ownership"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        }
        // Final side-effect-free authorization gate BEFORE any promotion or link
        // mutation. Unknown provenance fails closed. A revoked old device binding
        // cannot be laundered through a surviving pending or promotion, while a
        // newer same-pid re-pair proven by the current store survives.
        let auth = self
            .direct_pending
            .get(pid)
            .map(|pending| pending.auth.clone())
            .or_else(|| self.promotions.get(pid).and_then(|promotion| promotion.auth.clone()));
        if !self.direct_attempt_authorized(pid, attempt, auth.as_ref()) {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: attempt authorization revoked"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        }
        // A live DIRECT primary with a different attempt is not replaceable
        // through this path. Installing only the new epoch while keeping the old
        // transport was a hybrid that dropped the incoming Arc. Reject before
        // promoting, taking pending state, or touching workers. Same-attempt
        // live exact duplicates already returned Duplicate above. The one
        // exception is a newer current-store binding whose old link binding was
        // forgotten/revoked: that re-pair supersedes the live primary below.
        let live_different_attempt_primary = self.links.get(pid).is_some_and(|existing| {
            existing.direct
                && existing.attempt != Some(attempt)
                && existing
                    .transport
                    .as_ref()
                    .is_some_and(|live| !live.is_dead())
        });
        let supersedes_live_primary = live_different_attempt_primary
            && self.links.get(pid).is_some_and(|existing| {
                self.direct_supersedes_live_primary(pid, auth.as_ref(), existing)
            });
        if live_different_attempt_primary && !supersedes_live_primary {
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: live primary attempt is different"
            ));
            t.force_close();
            return DirectAdoption::Rejected;
        }
        // A promotion handed over (make-before-break): retire the serving
        // WebRTC link in the same step that installs its successor below, so
        // the peer is never without a link. The old channel keeps delivering
        // what was already queued on it for a grace (`retire_serving_link`).
        if self.promotions.get(pid).is_some_and(|s| s.handed) {
            self.promotions.remove(pid);
            if self.links.contains_key(pid) {
                self.retire_serving_link(pid);
            }
        }
        // A superseding re-pair replaces the whole live primary, not just its
        // epoch: dropping the link closes the old transport after the normal
        // grace so the incoming Arc is the one installed, never a hybrid.
        if supersedes_live_primary {
            let was_active = self.is_active(pid);
            self.log.debug(&format!(
                "tunlion: DIRECT-ADOPT-REPLACE peer={pid}: a newer authorized attempt supersedes the live binding"
            ));
            self.drop_link(pid);
            if was_active {
                self.active = Some(pid.to_string());
            }
        }
        let lan = route == filament_transport::lan::ROUTE_LAN;
        let pend = self.take_pending_for_adoption(pid, attempt);
        // Only a DEVICE binding may key workers, exactly as the upgrade path
        // does. Deriving this from `pending.secret` handed a fleet rendezvous
        // secret (or an ephemeral ceremony secret) a worker key it must never
        // have.
        let tkey = pend.as_ref().and_then(|pending| pending.auth.transport_key());
        // Keep the exact device reservation for revocation/dedup. A fleet LAN
        // reservation carries no device binding; its shared RV must never be
        // stored here as one.
        let lan_device_binding = pend.as_ref().and_then(|pending| {
            if pending.auth.domain == DirectAuthDomain::Lan {
                pending.auth.device_binding.clone()
            } else {
                None
            }
        });
        // Read the fleet flag BEFORE the secret moves out of the pending.
        //
        // FAIL SAFE WITH NO PENDING. Only the DIALER holds a `DirectPending`, so
        // `unwrap_or(false)` meant the ACCEPTING side of a fleet dial was born
        // `trusted: true` + OwnerDevice, which is the exact escalation the Fleet
        // intent exists to prevent, reachable by anyone holding the fleet secret.
        // It was caught live: a device whose transfer grant had been REVOKED still
        // delivered a file, because the acceptor had granted it owner-equivalence
        // at link birth.
        //
        // With no pending we cannot see which secret authenticated the MAC, so we
        // infer from what we know: a peer we hold a PAIR secret for is a paired
        // device (only it could have produced that MAC); anything else, while we
        // have a fleet secret at all, is treated as a fleet link and stays
        // untrusted until `fleet-hello` names it.
        let fleet = match pend.as_ref() {
            Some(p) => {
                let stale_device_binding = p.auth.domain == DirectAuthDomain::Device
                    && self.host.fleet_rv_present()
                    && !p.auth.device_binding.as_ref().is_some_and(|(name, secret)| {
                        !secret.is_empty()
                            && !self.host.device_record_revoked(name)
                            && self.host.devices_load().iter().any(|(n, held)| {
                                n.eq_ignore_ascii_case(name) && held == secret
                            })
                    });
                p.fleet || stale_device_binding
            }
            None => {
                let claimed = self
                    .roster
                    .get(pid)
                    .and_then(|v| v["name"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let paired = !claimed.is_empty()
                    && !self.host.device_record_revoked(&claimed)
                    && self.host.devices_load()
                        .iter()
                        .any(|(n, secret)| !secret.is_empty() && n.eq_ignore_ascii_case(&claimed));
                self.host.fleet_rv_present() && !paired
            }
        };
        // A code-path promotion is authenticated by the one-time ceremony
        // secret, which the transfer DISCARDS. On WebRTC that peer is an
        // untrusted link that must be asked for consent; the direct link that
        // replaces it was born `trusted: true` with a petname, so a
        // `receive <code>` without -y took every offer unasked once QUIC won
        // the race (gate 15 measured it the moment same-host promotion started
        // working), and `trusted` is also what admits `pair-intro`, l2 and
        // mount opens. It keeps the trust the WebRTC link had: none.
        let ephemeral = pend.as_ref().is_some_and(|p| p.ephemeral);
        let (name, secret) = match pend {
            Some(p) => p.secret,
            None => ("peer".to_string(), String::new()),
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": name }));
        let uid = info["uid"].as_str().map(|s| s.to_string());
        // A LAN link never mints `expected_secret`: that field also keys worker
        // transports and the pair-proof hypothesis, which a LAN route does not
        // use. Its device reservation is kept separately in `lan_binding`.
        let expected_secret = if lan || secret.is_empty() {
            None
        } else {
            Some((name.clone(), secret))
        };
        let lan_binding = lan.then(|| LanBinding {
            name: name.clone(),
            device: lan_device_binding,
        });
        // A LAN DEVICE link is the pair. Its handshake is the same pair-secret
        // MAC as any direct link (`direct::authenticate` keyed by
        // `transport_key(secret)`), and the listener only holds the secrets of
        // live, unrevoked device records (`lan_glue::keys`). So when its exact
        // binding still resolves in the current store, it gets what the pair
        // link to that device gets: trusted, named by the canonical petname,
        // born `OwnerDevice` and resolved from the record like any pair link.
        // Pairwise trust must not depend on the route two paired devices found.
        // A fleet reservation, or a binding the store no longer holds, stays
        // untrusted with no ceiling.
        let lan_pair_name: Option<String> = if lan && !fleet && !ephemeral {
            let devices = self.host.devices_load();
            authenticated_lan_device_name(
                lan_binding.as_ref(),
                &devices,
                &self.revoked_bindings,
                &|n: &str| self.host.device_record_revoked(n),
            )
            .map(str::to_string)
        } else {
            None
        };
        let lan_untrusted = lan && lan_pair_name.is_none();
        self.next_gen += 1;
        let generation = self.next_gen;
        // If a Link already exists for this pid (e.g. from a stall-watchdog
        // repair re-dial), UPDATE its transport + workers in place instead of
        // full-insert replacing the old Link (which would drop the primary
        // transport Arc → quinn ApplicationClosed → primary death at K>1).
        // Workers belong to the old primary attempt and are revoked on this
        // ownership change; fresh workers arrive through the normal Adopted
        // follow-up.
        let _existing_generation = self.links.get(pid).map(|l| l.generation).unwrap_or(0);
        if let Some(existing) = self.links.get_mut(pid) {
            // A new primary attempt owns a new worker epoch. Old workers were
            // authorized only by the replaced primary, so they must neither
            // remain source-authorized nor stripe after this ownership change.
            // The standard Adopted follow-up installs fresh workers on the new
            // primary, preserving K>1 without inheriting stale authority.
            let old_workers = std::mem::take(&mut existing.workers);
            existing.worker_sources.clear();
            for worker in old_workers {
                worker.force_close();
            }
            if !existing.direct
                || existing
                    .transport
                    .as_ref()
                    .map(|t2| t2.is_dead())
                    .unwrap_or(true)
            {
                // A live WebRTC predecessor is not the adopted direct
                // transport. Retaining it while installing the direct source
                // drops the incoming connection and leaves a hybrid link.
                existing.transport = Some(t);
            }
            existing.direct = true;
            existing.direct_route = route;
            existing.generation = generation;
            existing.source = source;
            existing.attempt = Some(attempt);
            existing.attempts = 0;
            // A FLEET direct link is not pair-authenticated. The new-link branch
            // below already keeps `trusted: false` and no petname until a verified
            // fleet-hello names it; the update branch used to grant both anyway when
            // the one-shot already had an unverified WebRTC link on this pid. That
            // made `is_sibling_link()` false, so the target ignored the owner grant
            // for the very device its certificate named and refused the terminal as
            // "shell not granted".
            if !ephemeral && !fleet {
                existing.trusted = true;
                if let Some((n, _)) = &expected_secret {
                    existing.verified_name = Some(n.clone());
                }
            }
            if lan {
                // Never inherit a worker key from another direct path.
                existing.expected_secret = None;
            }
            if lan {
                // Whatever this link proved before, a LAN adoption starts its
                // identity over: `resolve_peer_identity` keeps any cached key
                // as already resolved, so a stale one would outlive the route
                // that proved it.
                existing.identity_device_pub = None;
                existing.identity_user_pub = None;
                existing.identity_binding = BindingStrength::None;
                existing.identity_state = IdentityState::Pending;
                existing.identity_cert_expires = None;
            }
            if fleet {
                // A FLEET direct is keyed by the secret the whole fleet shares:
                // it proves fleet membership, not who the peer is. So NOTHING
                // pair-derived may survive on this link: the standing has to be
                // re-established by the verified fleet hello. Before this, a
                // link that had been pair-proven kept `trusted`, its verified
                // name and its principal kind across the adoption, so a
                // transport that authenticates only against the fleet secret
                // still carried pair standing, and a cut in place (revoke
                // without a close) left that standing behind.
                existing.trusted = false;
                existing.verified_name = None;
                existing.principal_kind = PrincipalKind::Delegated { caps: Vec::new() };
                existing.identity_device_pub = None;
                existing.identity_user_pub = None;
                existing.identity_binding = BindingStrength::None;
                existing.identity_state = IdentityState::Pending;
                existing.identity_cert_expires = None;
            }
            if let Some(n) = &lan_pair_name {
                // Re-resolve from the record as a fresh pair link would, so a
                // delegated record gets its ceiling.
                existing.trusted = true;
                existing.verified_name = Some(n.clone());
                existing.principal_kind = PrincipalKind::OwnerDevice;
            } else if lan_untrusted {
                // A fleet reservation, or a binding the store no longer holds:
                // no device trust, no identity, no ceiling.
                existing.trusted = false;
                existing.verified_name = None;
                existing.principal_kind = PrincipalKind::Delegated { caps: Vec::new() };
            }
            resolve_peer_identity(existing);
            if expected_secret.is_some() {
                existing.expected_secret = expected_secret;
            }
            // Unconditional: a non-LAN replacement must not inherit a stale LAN
            // reservation, and a LAN replacement keeps (or clears, for fleet)
            // its exact device binding.
            existing.lan_binding = lan_binding.clone();
        } else {
            // Mesh reuse: spawn accept loop before t moves into Link.
            direct::spawn_mesh_accept(pid.to_string(), &t, self.tx.clone());
            self.links.insert(
                pid.to_string(),
                Link {
                    peer: None,
                    info,
                    name,
                    uid,
                    transport: Some(t),
                    workers: vec![],
                    generation,
                    source,
                    attempt: Some(attempt),
                    worker_sources: SimHashSet::default(),
                    attempts: 0,
                    // A direct link is normally born identity-bound: its PAIR-secret
                    // MAC already proved who it is. A FLEET link is not. Its MAC was
                    // keyed by a secret the whole fleet shares, which proves only
                    // that the peer is in the fleet. So it is born untrusted, with no
                    // petname and no owner-equivalence, until a verified fleet-hello
                    // names it.
                    trusted: !fleet && !ephemeral && !lan_untrusted,
                    verified_name: if fleet || ephemeral || lan_untrusted {
                        None
                    } else if lan_pair_name.is_some() {
                        lan_pair_name.clone()
                    } else {
                        expected_secret.as_ref().map(|(n, _)| n.clone())
                    },
                    expected_secret,
                    lan_binding,
                    presence: Presence::Ready,
                    direct: true,
                    direct_route: route,
                    established_at: Some(Instant::now()),
                    identity_device_pub: None,
                    identity_user_pub: None,
                    identity_binding: BindingStrength::None,
                    identity_state: IdentityState::Pending,
                    identity_cert_expires: None,
                    principal_kind: if fleet || lan_untrusted {
                        PrincipalKind::Delegated { caps: Vec::new() }
                    } else {
                        PrincipalKind::OwnerDevice
                    },
                    host: self.host.clone(),
                },
            );
        }
        if lan_pair_name.is_some() {
            // Resolve now, not at the later ready event: a delegated (invited)
            // record must get its ceiling before anything can be gated on it.
            if let Some(link) = self.links.get_mut(pid) {
                resolve_peer_identity(link);
            }
        }
        // Replay anything the standby buffered before adoption. The tags remain,
        // so a second replacement still rejects them at the handler gate.
        self.flush_pending_source(source);
        self.discard_held(pid, "the direct path was adopted");
        DirectAdoption::Adopted { attempt, tkey }
    }

    /// Install worker transports only when the ready event belongs to the
    /// link's CURRENT primary source. A stale event closes its workers and
    /// leaves the primary untouched.
    pub fn accept_workers_ready(
        &mut self,
        pid: &str,
        workers: Vec<Arc<dyn Transport>>,
        primary_source: net::SourceId,
    ) -> bool {
        let Some(link) = self.links.get_mut(pid) else {
            for worker in &workers {
                worker.force_close();
            }
            return false;
        };
        if link.source != primary_source {
            for worker in &workers {
                worker.force_close();
            }
            return false;
        }
        link.worker_sources = workers.iter().filter_map(|w| w.source_id()).collect();
        link.workers = workers;
        true
    }

    /// Spawn K-1 parallel QUIC worker transports in a background task after
    /// the primary direct connection wins.  The non-answerer side dials; the
    /// answerer side accepts.  Each worker gets its OWN quinn::Endpoint (own
    /// UDP socket, own driver task) so packet I/O parallelises across cores.
    /// Workers arrive asynchronously via `Ev::DirectWorkersReady` and are
    /// populated on the Link.  File send (`stream_one`) gracefully degrades
    /// to fewer streams if workers are not yet ready.
    pub fn spawn_direct_workers(
        &mut self,
        pid: &str,
        primary: &Arc<dyn Transport>,
        tkey: [u8; 32],
    ) {
        let k = net::direct_streams();
        if k <= 1 {
            return;
        }
        let primary_source = primary.source_id().unwrap_or(net::SourceId::UNASSIGNED);
        let peer_uid = self.roster.get(pid).and_then(|i| i["uid"].as_str());
        let peer_present = self.roster.contains_key(pid);
        let answerer = match peer_uid {
            Some(peer_uid) => match net::polite_role(&self.my_uid, peer_uid, &self.my_id, pid) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("direct worker role election failed for {pid}: {error}");
                    return;
                }
            },
            None => {
                let source = if peer_present {
                    "presence"
                } else {
                    "absent-roster"
                };
                match net::polite_role_legacy(
                    &self.my_uid,
                    None,
                    &self.my_id,
                    pid,
                    source,
                    peer_present,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("worker role election failed for peer {pid}: {error}");
                        return;
                    }
                }
            }
        };
        let count = k - 1;
        let pid = pid.to_string();
        let tx = self.tx.clone();
        let primary = primary.clone();

        if answerer {
            // ACCEPTOR: create independent QUIC endpoints (one per worker),
            // send their ports to the dialer, then accept incoming connections.
            let mut endpoints = Vec::with_capacity(count);
            let mut ports = Vec::with_capacity(count);
            for _ in 0..count {
                if let Ok((ep, port)) = direct::bind_endpoint() {
                    endpoints.push(ep);
                    ports.push(port);
                }
            }
            if endpoints.is_empty() {
                return;
            }
            let offer = json!({ "type": "worker-ports", "v": 1, "ports": ports, "for": &pid });
            let p = primary.clone();
            tokio::spawn(async move {
                let _ = p.send_control(&offer).await;
            });
            tokio::spawn(async move {
                let workers =
                    direct::accept_workers(endpoints, tkey, pid.clone(), tx.clone(), count).await;
                direct::announce_workers(workers, &tx, pid, primary_source);
            });
        } else {
            // DIALER: wait for the acceptor's worker ports, then connect to each.
            let peer_ip = match primary.remote_addr().map(|a| a.ip()) {
                Some(ip) => ip,
                None => return,
            };
            let (port_tx, port_rx) = tokio::sync::oneshot::channel();
            self.worker_port_tx.insert(pid.clone(), port_tx);
            tokio::spawn(async move {
                let ports =
                    match tokio::time::timeout(std::time::Duration::from_secs(5), port_rx).await {
                        Ok(Ok(p)) => p,
                        _ => return,
                    };
                let workers =
                    direct::dial_workers(ports, peer_ip, tkey, pid.clone(), tx.clone(), count)
                        .await;
                direct::announce_workers(workers, &tx, pid, primary_source);
            });
        }
    }

    /// Per-tick: a direct attempt whose budget expired without an authenticated
    /// connection falls back to the WebRTC `establish` (unchanged). Returns the
    /// one (pid, info) to establish, caller awaits establish outside the borrow,
    /// so one loop iteration pays for at most ONE establish. Remaining expired
    /// attempts stay pending and are returned by the next call. Also drops any
    /// pending whose Link already exists. LAN reservations are the exception:
    /// they have no signaling peer, so expiry retires them without a fallback.
    pub fn expired_direct(&mut self) -> Vec<(String, Value, (String, String))> {
        let now = Instant::now();
        // A hold outlives its direct pending only until the build that takes
        // it. One whose pending ended (fallback, retirement, revocation) with no
        // build to take it is an orphan by the next reaper call: purge it.
        self.reap_orphan_holds();
        let mut fell_back = Vec::new();
        // Post-PAKE promotions first: one whose race lost leaves WebRTC serving
        // (nothing was torn down, so nothing falls back), one whose race won is
        // waiting on its handoff, not on this deadline.
        self.settle_promotions(now);
        // P5 (GAP-6): an UPGRADE-PROBE pending whose budget expired with no winner
        // must NOT fall back to WebRTC, the relay link is still serving and the
        // whole point of the probe was to find a DIRECT path. Just DROP it and let
        // the prober's backoff schedule the next attempt (mark_probe_failed). The
        // cold (non-probe) pendings keep their existing WebRTC-fallback behavior.
        let expired_probes: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(_, p)| p.probe && now >= p.deadline)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired_probes {
            if let Some(pending) = self.direct_pending.remove(&pid) {
                self.retire_attempt(&pid, pending.attempt, pending.race_task);
            }
            // DEBUG, resilience internal (upgrade probe found no path).
            self.log.debug(&format!(
                "tunlion: UPGRADE-PROBE for {pid} found no direct path in budget, staying on relay"
            ));
            self.mark_probe_failed(&pid);
        }
        // LAN reservations were seeded by local discovery, not by a signaling
        // offer. Their pid is a fresh local id with no signaling peer to
        // establish, so expiry must retire the exact attempt and never return a
        // WebRTC fallback for it. Fleet LAN is still a LAN reservation here.
        let expired_lan: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(_, p)| p.lan && now >= p.deadline)
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in expired_lan {
            if let Some(pending) = self.direct_pending.remove(&pid) {
                self.retire_attempt(&pid, pending.attempt, pending.race_task);
            }
            self.log.debug(&format!(
                "tunlion: LAN reservation for {pid} expired; no WebRTC fallback"
            ));
        }
        let mut expired: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| {
                !p.probe
                    && !p.lan
                    && now >= p.deadline
                    && !self.links.contains_key(*pid)
                    && !self.promotions.contains_key(*pid)
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        // Earliest deadline first, so a steady stream of newly expired attempts
        // can never starve one that has waited longer.
        expired.sort_by_key(|pid| self.direct_pending.get(pid).map(|p| p.deadline));
        let per_call = if test_hooks::expired_direct_batch() {
            usize::MAX
        } else {
            DIRECT_FALLBACKS_PER_CALL
        };
        for pid in expired.into_iter().take(per_call) {
            if let Some(mut p) = self.direct_pending.remove(&pid) {
                self.retire_attempt(&pid, p.attempt, p.race_task.take());
                let info = self
                    .roster
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| json!({ "id": pid, "name": p.secret.0 }));
                // Gate C (#237): the fallback is now ATTRIBUTED - and only when the
                // attribution is TRUE. The decision to use the relay names the
                // peer's claimed server-asserted public candidate only when the
                // race actually DIALED THAT EXACT ADDRESS (the dial site set
                // server_public_dialed; nothing else can). The claim is wire
                // data and untrusted: absent a dial of the named address,
                // "never answered" would blame a sentence rather than a fact -
                // whether the claim was never in the candidate set, never
                // parsed, or the budget went to other dials. All of those stay
                // silent at default verbosity: the infinite negative run stays
                // quiet, and a fallback with an unrelated cause - or a lying
                // label - never names a cause it has not established.
                let attributed = p
                    .peer_server_public
                    .as_ref()
                    .filter(|_| p.server_public_dialed.load(Ordering::Relaxed));
                match attributed {
                    Some(sp) => self.log.say(&format!(
                        "falling back to relay: the public address from the server ({sp}) never answered"
                    )),
                    None => {
                        // DEBUG, resilience internal (direct→WebRTC fallback).
                        self.log.debug(&format!(
                            "tunlion: DIRECT-FALLBACK for {}, no authenticated QUIC in budget, using WebRTC",
                            p.secret.0
                        ))
                    }
                }
                fell_back.push((pid, info, p.secret));
            }
        }
        // Drop pendings whose link landed by another route (cleanup). P5 (GAP-6):
        // EXCLUDE upgrade probes, a probe pending ALWAYS coexists with the serving
        // relay link (that's the point), so this cleanup must not reap it before its
        // race runs; a probe is reaped only by its own deadline (above) or by the
        // upgrade cutover consuming it.
        // A promotion's pending is EXCLUDED too: it coexists with the serving
        // WebRTC link by design (make-before-break), and its adoption needs it.
        // A FLEET pending is excluded while its link is still unproven for the
        // same reason: a fleet-secret WebRTC link exposes no channel binding, so
        // it can never carry the certificate proof a one-shot dialer must present.
        // Reaping the direct race here retired the only attempt that could ever
        // verify that dialer, and adopt_direct then refused the late but valid
        // QUIC connection as `attempt retired`. The pending still dies at its
        // deadline (the two filters above/below never leave it parked).
        let linked: Vec<String> = self
            .direct_pending
            .iter()
            .filter(|(pid, p)| {
                if p.probe || self.promotions.contains_key(*pid) {
                    return false;
                }
                let Some(link) = self.links.get(*pid) else {
                    return false;
                };
                !(p.fleet && !link.fleet_proven() && now < p.deadline)
            })
            .map(|(pid, _)| pid.clone())
            .collect();
        for pid in linked {
            let _ = self.take_direct_pending(&pid);
        }
        fell_back
    }

    /// C3/C4: watchdog or grace expiry, retry that LINK with fresh config,
    /// up to MAX_ATTEMPTS, then drop it. Returns true when the exhausted link
    /// was the active transfer target (send decides whether that is fatal).
    pub async fn on_stuck(&mut self, pid: &str, generation: u32, why: &str) -> Result<bool> {
        // C21: don't burn retry attempts against a peer that told us it's
        // away, re-dialing a suspended tab is wasted attrition.
        if self.is_away(pid) {
            return Ok(false);
        }
        let Some(l) = self.links.get(pid) else {
            return Ok(false);
        };
        // rung-1: a direct link has no WebRTC watchdog (no Peer::connect timer),
        // so on_stuck can't fire for it; defensively no-op if it ever does.
        if l.direct {
            return Ok(false);
        }
        if l.generation != generation || l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // stale timer from a superseded attempt
        }
        // Stuck and GraceExpired can both fire for one attempt; a retry already
        // scheduled for it owns the ladder step, so a second one must not
        // count another attempt or arm a second timer.
        if self
            .stuck_retry
            .get(pid)
            .is_some_and(|r| r.generation == generation)
        {
            return Ok(false);
        }
        // Gate-18 Mode B: the transfer is COMPLETE (recv_done; recomputed per
        // tick by the recv loop, so this can only be true with by_sid empty and
        // !keep_open) and this link just went stuck/lost. Reconnecting would
        // fetch nothing and merely FLAP the link, resetting attempts and
        // re-arming expected_secret each cycle, so conn.links never empties and
        // the quiet-exit can't fire (RC=124 hang under contention). DROP it
        // instead: links empties, quiet-exit fires. Fenced to complete-only, so
        // a mid-transfer link (recv_done=false) reconnects normally (gate 2/11c).
        // TUNLION_TEST_DISABLE_MODEB_DROP reverts to the old reconnect-always
        // behaviour so the gate proves A/B with ONE binary: baseline (toggle set)
        // hangs to RC=124 under the churn hook; fix (toggle unset) exits cleanly.
        if self.recv_done && !test_hooks::disable_modeb_drop() {
            let was_active = self.is_active(pid);
            self.log.debug(&self.log.paint(
                Tone::Dim,
                &format!(
                    "dropping peer (connection {why} after completion, nothing left to fetch)"
                ),
            ));
            self.drop_link(pid);
            return Ok(was_active);
        }
        let attempts = l.attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            let was_active = self.is_active(pid);
            self.log.debug(&format!(
                "tunlion: STALL-LADDER-EXHAUSTED peer={pid} attempts={attempts} reason={why}"
            ));
            self.log.debug(&self.log.paint(
                Tone::Dim,
                &format!("dropping peer (connection {why} after {attempts} attempts)"),
            ));
            self.digest.suppressed_digest_adoptions.insert(pid.to_string());
            self.drop_link(pid);
            return Ok(was_active);
        }
        // DEBUG, resilience internal (link retry).
        self.log.debug(&format!(
            "connection {why}, retrying ({}/{})",
            attempts + 1,
            MAX_ATTEMPTS
        ));
        // Exponential backoff between retries so the attempts are not burned
        // instantly. SCHEDULED, never slept: this runs on the event loop, and
        // sleeping here froze every control request, peer exec and signaling
        // event for the whole ladder (measured: ctl latency up to 4008ms against
        // 7-10ms normal, the loop frozen ~30% of the time with 2-3 ladders).
        let backoff = stuck_backoff(attempts);
        self.stuck_retry.insert(
            pid.to_string(),
            StuckRetry {
                generation,
                attempts,
            },
        );
        schedule_retry(&self.tx, pid, generation, backoff);
        Ok(false)
    }

    /// `Ev::RetryLink`: the backoff `on_stuck` scheduled has elapsed. Re-check
    /// that the stuck attempt is still the link's CURRENT one (nothing
    /// replaced, dropped or recovered it meanwhile), then rebuild it. Returns
    /// what `on_stuck` returns: true when the ladder is exhausted and the
    /// dropped link was the active transfer target.
    ///
    /// A rebuild failure is not propagated (it used to escape through `?` and
    /// end the caller's loop): it counts as another stuck attempt instead, so
    /// the ladder stays bounded by MAX_ATTEMPTS either way.
    pub async fn on_retry_due(&mut self, pid: &str, generation: u32) -> Result<bool> {
        let Some(pending) = self.stuck_retry.get(pid) else {
            return Ok(false);
        };
        if pending.generation != generation {
            return Ok(false); // a later on_stuck superseded this timer
        }
        let attempts = pending.attempts;
        self.stuck_retry.remove(pid);
        let Some(l) = self.links.get(pid) else {
            return Ok(false); // dropped meanwhile (peer-left, reap): nothing to retry
        };
        if l.generation != generation {
            return Ok(false); // replaced meanwhile (direct adopt, supersede)
        }
        if l.peer.as_ref().map(|p| p.is_connected()).unwrap_or(true) {
            return Ok(false); // recovered on its own during the backoff
        }
        let info = l.info.clone();
        let secret = l.expected_secret.clone();
        // C26: a link that was ever up is *re*connecting; one that never
        // connected is still just connecting, keeps "recovered" honest.
        let prev = match l.presence {
            Presence::Connecting => Presence::Connecting,
            _ => Presence::Reconnecting,
        };
        let was_active = self.is_active(pid);
        if let Err(e) = self.reestablish_stuck(info).await {
            self.log.debug(&format!(
                "connection retry for {pid} failed to build: {e}; counting it as an attempt"
            ));
            if let Some(l) = self.links.get_mut(pid) {
                l.attempts = attempts;
            }
            return self.on_stuck(pid, generation, "retry failed").await;
        }
        if self.builds.contains_key(pid) {
            if let Some((name, secret)) = &secret {
                self.note_binding(pid, (name.clone(), secret.clone()));
            }
            if was_active {
                self.note_active(pid);
            }
            if let Some(l) = self.links.get_mut(pid) {
                l.attempts = attempts;
                l.presence = prev;
            }
            return Ok(false);
        }
        if let Some(nl) = self.links.get_mut(pid) {
            nl.attempts = attempts;
            nl.expected_secret = secret;
            nl.presence = prev;
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        Ok(false)
    }

    // --- P0 (GAP-1): the bytes-moved STALL watchdog + correction ladder ------
    //
    // The single byte-flow primitive `Transport::idle_ms()` already exists
    // (net.rs) and is stamped at the unambiguous "a data byte moved" point on
    // both send and receive. #28 wired it ONLY to the supersede decision; this
    // is the second consumer the audit calls the core gap: a watchdog that
    // declares an OPEN, ALIVE link bad when an in-flight transfer moves zero
    // bytes, the "stuck at 0%" hang, and drives the least-disruptive
    // correction. Run from the main event loop's tick (no new concurrency: F8).

    /// Build the detector's transport observation without treating presence or
    /// an idle sentinel as proof of liveness. Dead transports are excluded from
    /// the activity sample, and the maximum idle age prevents a worker from
    /// masking a stalled primary.
    /// Whether a transport can never carry another byte: latched dead, or
    /// reporting itself not alive. A WebRTC data channel answers both the same
    /// way (its `is_dead` is the latch `is_alive` reads). Both are still asked
    /// because a direct QUIC link disagrees for a moment: quinn has closed the
    /// connection (`is_alive() == false`) before the reader latched `dead`, and
    /// a link in that window is just as gone.
    pub fn transport_severed(t: &dyn Transport) -> bool {
        t.is_dead() || !t.is_alive()
    }

    pub fn stall_observation(
        transport: Option<&dyn Transport>,
        workers: &[Arc<dyn Transport>],
    ) -> (bool, bool, u64) {
        let mut transport_up = false;
        let mut flowed = false;
        let mut idle_ms: Option<u64> = None;

        let mut observe = |t: &dyn Transport| {
            if !t.is_alive() {
                return;
            }
            transport_up = true;
            if let Some(idle) = t.idle_ms_tracked() {
                flowed = true;
                idle_ms = Some(idle_ms.map_or(idle, |current| current.max(idle)));
            }
        };
        if let Some(t) = transport {
            observe(t);
        }
        for worker in workers {
            observe(worker.as_ref());
        }

        (transport_up, flowed, idle_ms.unwrap_or(u64::MAX))
    }

    /// Per-tick check: if a transfer is in flight (`in_flight`) on a link whose
    /// `idle_ms()` has crossed the stall threshold, return its (pid, idle_ms) so
    /// the loop can emit `Ev::TransferStalled`. Returns `None` for a flowing or
    /// idle-but-empty link. Resetting bookkeeping on observed progress lives in
    /// `note_progress`, so a slow-but-MOVING link (which keeps advancing
    /// idle_ms's baseline) never trips, the threshold is on time-since-last-byte,
    /// never on throughput.
    ///
    /// `dead_is_stall`: whether a transport that latched dead counts as a stall.
    /// The SENDER passes true: it owns the offer, so it owns re-establishing a
    /// link whose channel died, and nothing else does while the peer connection
    /// still reads connected. The receiver passes false: it answers the
    /// sender's re-dial, and parking its partials plus dropping the link on its
    /// own would let a one-shot receive with one file done and one mid-transfer
    /// quiet-exit as "done".
    pub fn detect_stall(&mut self, pid: &str, in_flight: bool, dead_is_stall: bool) -> Option<u64> {
        let in_episode = self
            .resil
            .stall_repairs
            .get(pid)
            .map(|s| s.pending)
            .unwrap_or(false);
        // The liveness PHASE is the single source of truth (resilience::classify):
        // it pairs each phase with its own clock, so an ESTABLISHING link (no first
        // byte yet) is judged by the generous grace and a FLOWING one by the tight
        // stall threshold. This makes "judge a still-establishing link by the 6 s
        // flowing threshold" - the high-RTT relay repair loop - unrepresentable.
        // See docs/transfer-state-machine.md.
        // Aggregate across primary + worker transports: during multi-stream
        // transfers data rides the workers, so the primary can appear idle.
        // Do not infer liveness from presence or idle sentinels.
        let link = self.links.get(pid);
        let transport = link.and_then(|l| l.transport.as_ref());
        let workers: Vec<Arc<dyn Transport>> = link.map(|l| l.workers.clone()).unwrap_or_default();
        let (transport_up, flowed, idle_ms) =
            Self::stall_observation(transport.map(|t| t.as_ref()), &workers);
        // A severed primary with no live worker beside it: the link
        // had a transport and lost it. The send loop already routes a dead
        // transport to the ladder (`transport_dead || link_alive`); without
        // this the classifier read it as an establishment and never got there.
        let transport_dead = dead_is_stall
            && transport.is_some_and(|t| Self::transport_severed(t.as_ref()))
            && workers.iter().all(|w| Self::transport_severed(w.as_ref()));
        // The stall clock starts when THIS transfer did. A link's idle time
        // counts from when it opened (or last moved bytes), so a link that sat
        // idle before a transfer was offered on it read as stalled the moment
        // the transfer began: measured in CI (gate 14b at -vv), a restarted
        // daemon's link idle 16.98 s accepted a resume and declared "inbound
        // stall: 16983ms" in the same second, tearing down the link it had just
        // accepted on, before one byte could move.
        let idle_ms = if in_flight {
            let since = *self
                .resil
                .in_flight_since
                .entry(pid.to_string())
                .or_insert_with(Instant::now);
            idle_ms.min(u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX))
        } else {
            self.resil.in_flight_since.remove(pid);
            idle_ms
        };
        #[cfg(debug_assertions)]
        eprintln!(
            "[STALL] pid={pid} in_flight={in_flight} transport_up={transport_up} flowed={flowed} idle_ms={idle_ms} workers={} cluster={:?}",
            workers.len(),
            transport
                .map(|t| t.idle_ms())
                .into_iter()
                .chain(workers.iter().map(|w| w.idle_ms()))
                .collect::<Vec<_>>()
        );
        let obs = resilience::LiveObs {
            in_flight,
            transport_up,
            transport_dead,
            flowed,
            idle_ms,
            grace_ms: net::establish_grace_ms(),
            stall_ms: net::stall_ms(),
        };
        match resilience::classify(&obs) {
            resilience::Liveness::Flowing => {
                self.note_progress(pid);
                None
            }
            resilience::Liveness::Establishing => {
                // During an active repair cycle (new transport not yet
                // established), the episode must survive so the next stall
                // picks up at the correct rung instead of restarting from
                // Resume (which fails because the link was dropped).
                let in_repair = self
                    .resil
                    .stall_repairs
                    .get(pid)
                    .map(|s| s.pending)
                    .unwrap_or(false);
                if !in_repair {
                    self.note_progress(pid);
                }
                None
            }
            // Nothing in flight: drop stray bookkeeping.
            resilience::Liveness::Idle => {
                self.resil.stall_repairs.remove(pid);
                None
            }
            // No progress past the phase threshold. Open a new episode, or (if one
            // is already open) re-fire the ladder UNLESS a repair is converging -
            // re-emitting every tick would thrash while the replacement transport
            // is still establishing.
            resilience::Liveness::Stalled => {
                if in_episode && self.repair_in_flight(pid) {
                    None
                } else {
                    Some(obs.idle_ms)
                }
            }
        }
    }

    /// Is a repair for this peer's stall episode currently converging (a re-dial
    /// in flight or the ladder mid-step)? Used to avoid re-firing every tick.
    fn repair_in_flight(&self, pid: &str) -> bool {
        // A direct re-dial is pending, OR the ladder just acted and we're waiting
        // on the next observation. We treat `direct_pending` as the convergence
        // signal for rung (c)'s fresh dial. P1: a relay escalation (rung d) builds
        // a fresh WebRTC link NOT tracked by `direct_pending`, so the per-episode
        // `relayed` latch is its convergence signal, both keep the watchdog from
        // re-firing while the replacement transport is still establishing.
        if self.direct_pending.contains_key(pid) {
            return true;
        }
        self.resil
            .stall_repairs
            .get(pid)
            .map(|s| s.relayed)
            .unwrap_or(false)
    }

    /// Clear a peer's stall episode, called when bytes are observed moving
    /// again (the link recovered) or nothing is in flight.
    pub fn note_progress(&mut self, pid: &str) {
        self.resil.stall_repairs.remove(pid);
        // P3: a fresh byte means the (warm-cut-over) path is healthy again, let a
        // FUTURE episode warm-cut-over once more if it too stalls.
        self.resil.warm_cutover.remove(pid);
    }

    /// P0 liveness cross-check: is the link's CONTROL path still answering? A
    /// black-holed *data* path (the case we recover) still carries reliable,
    /// ordered control frames, so a successful control send distinguishes
    /// "data wedged, link alive" (→ correction ladder) from "link dead" (→ the
    /// established C3/C4 establishment-retry path, which already handles it).
    /// We send a cheap `ping` control frame; success ⇒ alive. We do NOT await a
    /// pong (F8: the event loop must never block on something a remote controls),
    /// a send that returns Ok over a reliable channel is sufficient evidence
    /// the transport itself is up; a dead transport errors or is flagged dead and
    /// returns Err here.
    ///
    /// BOUNDED by [`CONTROL_PROBE_BUDGET`]: this runs inline in the event loop,
    /// and a write to a peer that vanished without closing the association does
    /// not error, it waits for an acknowledgement that never comes. A probe that
    /// cannot even be queued within the budget is a link that is not answering.
    pub async fn link_alive(&self, pid: &str) -> bool {
        match self.transport_of(pid) {
            Some(t) => matches!(
                tokio::time::timeout(
                    CONTROL_PROBE_BUDGET,
                    t.send_control(&json!({ "type": "ping", "v": 1, "reason": "stall-probe" })),
                )
                .await,
                Ok(Ok(()))
            ),
            None => false,
        }
    }

    /// Decide the correction RUNG for the current stall episode and (for rung c)
    /// repair the transport in place WITHOUT tearing the session down. Returns:
    ///   `Rung::Resume`: rung (a): caller re-offers unfinished transfers with
    ///                     resume:true on the SAME transport (cheapest).
    ///   `Rung::Repaired`: rung (c): the transport was repaired in place
    ///                     (direct: fresh QUIC dial of the known device;
    ///                     WebRTC: restart_ice), caller re-offers once it's back.
    ///   `Rung::Relayed`, rung (b)/(d): re-established over the TURN relay. P3
    ///                     reaches this on the FIRST stall for a warm-standby
    ///                     (interactive) session, instant failover to the
    ///                     pre-designated warm alternate; P1 reaches it at the
    ///                     ladder ceiling for a one-shot transfer.
    ///   `Rung::Exhausted`: rungs a→c spent (MAX_ATTEMPTS) AND relay unavailable
    ///                     (forbidden / already on relay), fail clean, kept partial.
    /// Bounds the episode by MAX_ATTEMPTS, reusing the same ceiling as on_stuck.
    pub async fn correct_stall(&mut self, pid: &str) -> Rung {
        // P3 (GAP-3): once this episode has CUT OVER to the warm relay standby, a
        // SECOND Ev::TransferStalled that was already QUEUED before the cutover ran
        // (the loops emit one per tick while the stall holds) must NOT re-enter the
        // ladder and run a COLD in-place repair on top of the converging cutover,
        // that tore the fresh relay link down ("ICE Agent can not be restarted when
        // gathering"). Swallow it as a no-op (`Repaired` is the benign "in flight,
        // nothing to do" for both handlers). This guard is keyed on `warm_cutover`,
        // which is ONLY ever set on the warm path, so the COLD ladder (P0/P1) is
        // byte-for-byte unchanged and still climbs rung a→c→d normally. Cleared by
        // `note_progress` when the relay path moves a byte.
        if self.resil.warm_cutover.contains(pid) {
            return Rung::Repaired;
        }
        // The send loop measures a stall on every pass and the event that
        // carries it is handled later, so several are queued before the first
        // one repairs anything. Once a repair is converging (a re-dial pending,
        // or the link rebuilding with no transport yet), the rest were measured
        // on the link that repair already replaced. Counting them climbed the
        // ladder from attempt 1 to the relay escalation in one second, and with
        // no TURN server that relay-only re-dial could never connect.
        if self.resil.stall_repairs.get(pid).is_some_and(|s| s.pending)
            && (self.direct_pending.contains_key(pid) || self.transport_of(pid).is_none())
        {
            return Rung::Repaired;
        }
        // Check transport dead BEFORE the mutable borrow so the borrow-split
        // is unambiguous. When the transport is structurally dead (I/O error,
        // not a vanished peer), rung (a) Resume (re-offer on the same transport)
        // is guaranteed wasted — send_frame checks the dead flag and errors
        // immediately. Skip ahead to rung (c) Repair (re-dial direct QUIC) on
        // the first ladder tick, collapsing a wasted stall cycle.
        let dead_on_entry = self
            .transport_of(pid)
            .is_some_and(|t| Self::transport_severed(t.as_ref()));
        let st = self.resil.stall_repairs.entry(pid.to_string()).or_default();
        st.pending = true;
        if dead_on_entry && st.attempts == 0 {
            st.attempts = 1;
        }
        let attempt = st.attempts;
        st.attempts += 1;

        // P3 (GAP-3): WARM-REDUNDANCY instant failover (rung b). For a long-lived
        // / interactive session (`warm_standby`), the relay is a PRE-DESIGNATED
        // WARM standby kept ready alongside the primary direct path. On the FIRST
        // detected stall we CUT OVER to it IMMEDIATELY rather than grinding through
        // the slow direct-repair rungs, rung (a)'s resume-and-wait-another-stall,
        // then rung (c)'s up-to-MAX_ATTEMPTS cold re-dials, each of which costs a
        // full stall threshold before it gives up. Those rungs are correct for a
        // one-shot file (the on-disk partial makes a cold repair fine), but for an
        // interactive session every one of those windows is a visible, intolerable
        // gap. Cutting straight to the warm relay collapses N×stall_ms of cold
        // re-establish into a single relay cutover (rung d's machinery, but reached
        // on stall #1 instead of stall #~6), preserving the on-disk partial / PTY
        // stream / tunnel state via the same C7 resume seam.
        //
        // Gated tightly so we never pay this on the wrong session:
        //   - `warm_standby` (session-kind selectivity) must be on;
        //   - relay must be PERMITTED (`--no-relay` keeps the hard direct-only
        //     promise → fall through to the normal ladder, which fails clean);
        //   - we must not be ON relay already (`relay_only`), then relay is the
        //     PRIMARY that stalled, so there's no warmer alternate; fall through to
        //     the ladder, which lands on the honest "still stalled on relay" exit;
        //   - we cut over at most ONCE per episode (`warm_cutover`), a flapping
        //     relay can't re-fire instant cutover every tick; the second stall on
        //     the relay path falls through to the bounded relay-stalled honesty.
        let warm_eligible = self.resil.warm_standby
            && !self.host.relay_forbidden()
            && !self.relay_only
            && !self.resil.warm_cutover.contains(pid);
        // The ladder DECISION (which rung) is pure and lives in resilience.rs; this
        // method owns the state mutation + the rung's side effect.
        match resilience::decide_stall_action(
            attempt,
            STALL_MAX_REPAIRS,
            warm_eligible,
            self.host.relay_forbidden(),
            self.relay_only,
        ) {
            resilience::StallAction::WarmCutover => {
                // P3 (GAP-3) WARM-REDUNDANCY instant failover (rung b): cut straight
                // to the pre-designated warm relay standby instead of grinding the
                // slow direct-repair rungs (intolerable for an interactive session).
                // DEBUG, resilience internal; visible at -v / TUNLION_LOG=debug.
                self.log.debug(&self.log.paint(
                    Tone::Warn,
                    "  transfer stalled, cutting over to the warm relay standby (instant failover)",
                ));
                self.resil.warm_cutover.insert(pid.to_string());
                // Latch the episode as relaying so detect_stall waits for the fresh
                // relay path to move a byte (clearing the episode) instead of
                // re-firing the ladder while the cutover converges.
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Resume => {
                // Rung (a): cheapest, re-issue on the same transport. The caller
                // owns `outgoing` and does the actual re-offer; we just classify.
                // DEBUG, resilience internal (rung (a) resume on the same link).
                self.log.debug(&self.log.paint(
                    Tone::Warn,
                    "  transfer stalled, resuming on the same link",
                ));
                Rung::Resume
            }
            resilience::StallAction::ExhaustedRelayForbidden => {
                // The hard direct-only promise: never silently fall to a relay.
                // CRITICAL, a clean fatal path-decision the user must see (-q too).
                self.log.critical(&self.log.paint(
                    Tone::Warn,
                    "  couldn't establish a direct path; relay disabled (--no-relay), \
                    partial kept on disk. Re-run to resume, or drop --no-relay to \
                     allow relay fallback.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::ExhaustedAlreadyRelay => {
                // We already re-established over relay and it ALSO stalled: no harder
                // rung. Stop honestly with the partial preserved.
                // CRITICAL, a terminal honesty line the user must see (-q too).
                self.log.critical(&self.log.paint(
                    Tone::Warn,
                    "  transfer still stalled on the relay route, partial kept on disk. \
                     Re-run to resume.",
                ));
                Rung::Exhausted
            }
            resilience::StallAction::RelayEscalate => {
                // Rung (d): re-establish over the TURN relay, preserving the on-disk
                // partial (C7 resume). Bounded: one escalation per episode.
                // CRITICAL, P1's value-prop: the never-flaky promise kicking in.
                self.log.critical(&self.log.paint(
                    Tone::Warn,
                    "  direct paths exhausted, falling back to the TURN relay",
                ));
                if let Some(st) = self.resil.stall_repairs.get_mut(pid) {
                    st.relayed = true;
                }
                self.escalate_to_relay(pid).await;
                Rung::Relayed
            }
            resilience::StallAction::Repair => {
                // Rung (c): repair the transport IN PLACE under the live session.
                // DEBUG, resilience internal (in-place repair).
                self.log.debug(&self.log.paint(
                    Tone::Warn,
                    &format!(
                        "  transfer stalled, repairing the link in place (attempt {}/{})",
                        attempt, STALL_MAX_REPAIRS
                    ),
                ));
                self.repair_link_in_place(pid).await;
                Rung::Repaired
            }
        }
    }

    /// Rung (c): rebuild a path under the LIVE session, preserving the on-disk
    /// partial (C7 resume re-offers from the saved offset on the new transport).
    /// - direct-QUIC link: drop the wedged transport and re-arm the known-device
    ///   direct dial (`start_direct`), which re-advertises candidates; the peer's
    ///   matching re-dial (it runs the same watchdog) completes a FRESH
    ///   authenticated QUIC connection → `Ev::DirectReady` → `adopt_direct` swaps
    ///   in the new transport → ChannelReady re-offers the unfinished transfers.
    /// - WebRTC link: `restart_ice()`, keeps the RTCPeerConnection + DTLS keys;
    ///   only ICE re-gathers, so transfers resume on the same channel once ICE
    ///   re-converges (no re-key, the preferred repair when available). Not for
    ///   a channel that already latched dead: that one is rebuilt like a direct
    ///   link, since no ICE restart revives it.
    async fn repair_link_in_place(&mut self, pid: &str) {
        let Some(l) = self.links.get(pid) else { return };
        // An ICE restart renews the PATH under a data channel; it cannot revive
        // a channel that already latched dead (a write or flush the association
        // never acknowledged). That transport stays dead whatever ICE does, so
        // a dead WebRTC link is rebuilt the way a wedged direct one is.
        let dead = l.transport.as_ref().is_some_and(|t| Self::transport_severed(t.as_ref()))
            && l.workers.iter().all(|w| Self::transport_severed(w.as_ref()));
        if l.direct || dead {
            // Fresh QUIC dial of the known device. Pull the (name,secret) the
            // link was born with so the re-dial re-authenticates to the SAME pair
            // secret (session identity is stable across the swap; only the wire
            // keys rotate, documented in §2.5).
            let known = l.expected_secret.clone();
            let info = l.info.clone();
            let was_active = self.is_active(pid);
            self.drop_link(pid); // tears down the wedged transport (frees the port)
            if let Some((name, secret)) = known {
                self.start_direct(pid, &name, &secret).await;
                if was_active {
                    // start_direct creates no Link yet; keep the slot pointed here
                    // so adopt_direct's ChannelReady re-offers to the right target.
                    self.active = Some(pid.to_string());
                }
            } else {
                // No stored secret to re-dial direct, fall back to a WebRTC
                // re-establish under the session (still preserves the partial).
                // This IS the fallback: swallowing its failure is how a lost
                // direct race became a transfer with no link and no diagnostic.
                if was_active {
                    self.note_active(pid);
                }
                if let Err(e) = self.establish_as(info, None).await {
                    self.log.debug(&format!("  WebRTC fallback for {pid} failed: {e}"));
                }
            }
        } else if let Some(p) = l.peer.clone() {
            // WebRTC: ICE-restart in place, no teardown, no re-key.
            p.restart_ice();
        }
    }

    /// Rung (d), P1 (GAP-4): the direct/in-place ladder is exhausted, so
    /// RE-ESTABLISH this transfer over the TURN relay (relay-only ICE), the
    /// automatic version of the manual `--relay` the Pixel delivery and the runner
    /// both had to perform by hand. The on-disk partial is preserved at the seam:
    /// we re-establish a fresh WebRTC link with `RTCIceTransportPolicy::Relay`, and
    /// its ChannelReady re-offers the unfinished transfers with `resume:true` from
    /// the saved `.part` offset (no restart-from-zero, C7). Flipping the
    /// connection-wide `relay_only` flag also makes any subsequent repair on this
    /// session relay-only, so we don't bounce back to a known-bad direct path.
    /// Session identity (the pair secret / verified petname) is stable across the
    /// swap, only the wire keys rotate (§2.5). Bounded: one escalation per stall
    /// episode (the caller returns `Rung::Relayed` and the `stall_repairs` counter
    /// is already at the ceiling, so the ladder can't re-fire until progress
    /// resumes and resets it).
    async fn escalate_to_relay(&mut self, pid: &str) {
        // Latch the whole connection onto relay-only ICE: the re-establish below
        // and every later (re)establish for this session now forces TURN.
        self.relay_only = true;
        // Commit THIS peer to relay: stop dialing/answering direct-QUIC for it, so
        // the known-bad direct path can't keep winning the race and re-freezing
        // while the relay link tries to form (the exact thrash the sim exposed).
        self.resil.relay_committed.insert(pid.to_string());
        let Some(l) = self.links.get(pid) else { return };
        let info = l.info.clone();
        let known = l.expected_secret.clone();
        let was_active = self.is_active(pid);
        // Tear down the wedged (direct) transport, then re-establish over WebRTC
        // relay-only. We deliberately do NOT re-arm the direct-QUIC dial here even
        // if a secret is known: direct is what just failed, and relay is a WebRTC
        // path, so we go straight to `establish` (relay-only ICE). The metadata is
        // captured AFTER the drop: drop_link cancels a build and clears it.
        self.drop_link(pid);
        if let Some((name, secret)) = &known {
            self.note_binding(pid, (name.clone(), secret.clone()));
        }
        if was_active {
            self.note_active(pid);
        }
        // Clear any stray pending direct attempt so `establish` (which early-
        // returns while a direct attempt owns the peer, to keep the ladder
        // sequential) is never suppressed for the relay re-establish.
        let _ = self.take_direct_pending(pid);
        // Carry the proven identity into the fresh relay link so the post-channel
        // pair-proof still binds to the same device (set after establish creates
        // the Link below).
        if let Err(e) = self.establish_as(info, None).await {
            self.log.debug(&format!("  relay-only re-establish for {pid} failed: {e}"));
        }
        // Honest, loud: the user must know this session is now on a relay.
        // CRITICAL, the value-prop path label; shown even under -q.
        self.log.critical(&format!("  {}", self.host.relay_banner()));
        // P5 (GAP-6): ARM the relay->direct upgrade prober for this peer. Relay is
        // a way-station, not a destination: while we serve on relay we keep probing
        // for a direct path and upgrade back the moment one is confirmed stable.
        // Eligibility mirrors warm redundancy (long-lived/interactive sessions +
        // the daemon, a one-shot send that already completed doesn't need it) and
        // requires relay to be PERMITTED. The kill switch (`TUNLION_UPGRADE_PROBE=0`)
        // and `--no-relay` both make this a no-op.
        if self.upgrade_eligible() {
            self.resil
                .upgrade_probe
                .entry(pid.to_string())
                .or_insert_with(UpgradeProbe::armed);
            self.log.say(&self.log.paint(
                Tone::Dim,
                "  on relay, will keep trying for a direct path and upgrade automatically",
            ));
        }
    }

    /// P5 (GAP-6): is this session eligible to run the relay->direct prober?
    /// Selective like P3's warm redundancy: ON for long-lived / interactive
    /// sessions (the `up`/`up --shell` daemon acceptor; a transfer flagged
    /// interactive via `TUNLION_WARM_STANDBY=1`). Gated off by the kill switch
    /// and by `--no-relay` (which never reaches relay anyway).
    fn upgrade_eligible(&self) -> bool {
        self.resil.warm_standby && net::upgrade_prober_enabled() && !self.host.relay_forbidden()
    }

    /// P5 (GAP-6): a portable network-change-ish event fired (a signaling
    /// reconnect / fresh welcome). Re-probe every relay-committed peer IMMEDIATELY
    /// (reset its backoff to fire now), unless it's already mid-verify on a standby.
    /// Cheap and idempotent, the prober tick does the actual dialing.
    pub fn reprobe_on_network_event(&mut self) {
        if !net::upgrade_prober_enabled() || self.host.relay_forbidden() {
            return;
        }
        for up in self.resil.upgrade_probe.values_mut() {
            if up.standby.is_none() {
                up.next_at = Some(Instant::now());
            }
        }
    }

    /// P5 (GAP-6): record a failed/expired probe and back the cadence off toward
    /// the steady cadence (exponential, capped at steady_ms). Also clears any
    /// stale standby/verify state so the next probe starts clean.
    fn mark_probe_failed(&mut self, pid: &str) {
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            return;
        };
        up.attempt = up.attempt.saturating_add(1);
        up.standby = None;
        up.verify_started = None;
        up.verify_last_idle = u64::MAX;
        // Backoff: first failure → first_ms; then double toward steady_ms (cap).
        let first = net::upgrade_first_ms();
        let steady = net::upgrade_steady_ms();
        let backoff = first.saturating_mul(1u64 << up.attempt.min(8)).min(steady);
        up.next_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    /// P5 (GAP-6): the per-tick prober. Run from each live-session event loop's
    /// tick (no new concurrency, F8). For every peer currently committed to relay
    /// with an armed `UpgradeProbe`: (1) if a direct standby is mid-VERIFY, judge
    /// it (cut over if it has sustained progress for verify_ms; discard + back off
    /// if it regressed); (2) else if a probe is due (`next_at`), fire a fresh
    /// direct dial ALONGSIDE the relay link (warm direct standby) without
    /// disturbing it. Also detects a local interface change (`iface_snapshot`) and
    /// re-probes IMMEDIATELY, the "walked home onto wifi" trigger.
    pub async fn tick_upgrade_prober(&mut self) {
        if !net::upgrade_prober_enabled() || self.host.relay_forbidden() {
            return;
        }
        if self.resil.upgrade_probe.is_empty() {
            return;
        }
        // Network-change trigger: a change to the local interface set is the
        // strongest "a new direct path may exist NOW" signal we can read without a
        // platform netlink dependency. On change, reset every armed probe's
        // backoff to fire immediately (catches the wifi/cellular handoff instantly).
        let snap = direct::local_ip_snapshot_with_context(&self.transport_context);
        if snap != self.resil.iface_snapshot {
            if !self.resil.iface_snapshot.is_empty() {
                // DEBUG, resilience internal (upgrade-probe trigger).
                self.log.debug(&self.log.paint(
                    Tone::Dim,
                    "  network changed, re-probing for a direct path now",
                ));
                for up in self.resil.upgrade_probe.values_mut() {
                    if up.standby.is_none() {
                        up.next_at = Some(Instant::now()); // fire ASAP
                    }
                }
            }
            self.resil.iface_snapshot = snap;
        }

        let now = Instant::now();
        let pids: Vec<String> = self.resil.upgrade_probe.keys().cloned().collect();
        for pid in pids {
            // A peer that is no longer relay-committed (already upgraded or gone)
            // shouldn't be probed; drop its entry.
            if !self.resil.relay_committed.contains(&pid) || !self.links.contains_key(&pid) {
                self.resil.upgrade_probe.remove(&pid);
                let _ = self.take_direct_pending(&pid);
                continue;
            }
            // VERIFYING: a standby connected, judge it before scheduling anything.
            let verifying = self
                .resil
                .upgrade_probe
                .get(&pid)
                .map(|u| u.standby.is_some())
                .unwrap_or(false);
            if verifying {
                self.judge_upgrade_standby(&pid).await;
                continue;
            }
            // PROBING: a direct dial is in flight (its DirectPending), wait for it
            // to win (→ DirectUpgradeReady) or expire (→ expired_direct backoff).
            if self.direct_pending.contains_key(&pid) {
                continue;
            }
            // IDLE: schedule / fire the next probe per the backoff.
            let due = match self.resil.upgrade_probe.get(&pid).and_then(|u| u.next_at) {
                None => true,          // armed but unscheduled → schedule first probe
                Some(at) => now >= at, // due
            };
            if let Some(up) = self.resil.upgrade_probe.get_mut(&pid) {
                if up.next_at.is_none() {
                    // First scheduling after arming: probe after first_ms.
                    up.next_at = Some(now + Duration::from_millis(net::upgrade_first_ms()));
                    continue;
                }
            }
            if !due {
                continue;
            }
            // Fire a probe: dial direct ALONGSIDE the relay link.
            let known = self.links.get(&pid).and_then(|l| l.expected_secret.clone());
            let Some((name, secret)) = known else {
                // No stored secret to authenticate a direct dial, can't probe;
                // disarm so we don't spin.
                self.resil.upgrade_probe.remove(&pid);
                continue;
            };
            // DEBUG, resilience internal (upgrade probe attempt).
            self.log.debug(&self.log.paint(
                Tone::Dim,
                "  probing for a direct path (alongside the relay)...",
            ));
            // Pre-set the NEXT backoff deadline so a probe that silently makes no
            // progress still re-schedules (expired_direct also calls
            // mark_probe_failed on budget expiry; whichever fires first wins).
            self.start_upgrade_probe(&pid, &name, &secret).await;
        }
    }

    /// P5 (GAP-6): VERIFY-before-upgrade. A direct standby has connected for
    /// `pid`. Decide whether it is STABLE enough to cut over to:
    ///   - if it has been moving data (idle_ms stays low) CONTINUOUSLY for
    ///     `verify_ms`, perform the upgrade (clear relay_committed/relay_only, cut
    ///     over to the direct transport, tear down relay, re-offer transfers);
    ///   - if it goes idle past `verify_idle_ms` before that, DISCARD it and stay
    ///     on relay (back off), the mandatory no-flap guard against a flaky direct
    ///     path that connects then immediately re-stalls.
    /// We drive a tiny VERIFY heartbeat over the standby (a control ping) so a
    /// healthy path keeps stamping its `idle_ms()` low even before the session's
    /// real transfer bytes are re-routed onto it.
    pub async fn judge_upgrade_standby(&mut self, pid: &str) {
        let verify_ms = net::upgrade_verify_ms();
        let verify_idle_ms = net::upgrade_verify_idle_ms();
        // Heartbeat the standby with a real DATA frame (reserved verify sid) so a
        // healthy path advances its activity clock (`idle_ms()` stays low) while a
        // stalled/flaky standby, which black-holes the DATA path, not the control
        // path, either errors here or lets idle climb. A control ping would wrongly
        // pass on a flaky standby (whose control path stays alive), so we MUST probe
        // the data path. The peer drops the unknown-sid chunk harmlessly but stamps
        // its inbound activity, so its side's idle drops too (symmetric verify).
        let standby = self
            .resil
            .upgrade_probe
            .get(pid)
            .and_then(|u| u.standby.clone());
        let Some(standby) = standby else { return };
        // BOUND the heartbeat (F8: never block the event loop on something a remote
        // / a wedged path controls). A flaky standby's data path black-holes, the
        // send_frame would park forever, so a timeout reads as "didn't hold".
        let beat_ok = matches!(
            tokio::time::timeout(
                Duration::from_millis(500),
                standby.send_frame(VERIFY_PROBE_SID, 0, b"upgrade-verify"),
            )
            .await,
            Ok(Ok(()))
        );
        let idle = standby.idle_ms();
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            return;
        };
        use crate::link_manager::{VerifyAction, decide_upgrade_verify};
        let elapsed_ms = up.verify_started.map(|t| t.elapsed().as_millis() as u64);
        match decide_upgrade_verify(elapsed_ms, beat_ok, idle, verify_idle_ms, verify_ms) {
            VerifyAction::StartWindow => {
                up.verify_started = Some(Instant::now());
                up.verify_last_idle = idle;
                return;
            }
            // Regressed: control send failed OR the path went idle past the guard.
            // Discard the standby, stay on relay, back off (the no-flap guard).
            VerifyAction::Discard => {
                // DEBUG, resilience internal (no-flap guard rejecting a standby).
                self.log.debug(&self.log.paint(
                    Tone::Warn,
                    "  direct path connected but didn't hold, staying on relay (no flap)",
                ));
                self.take_direct_pending(pid);
                self.mark_probe_failed(pid);
                return;
            }
            VerifyAction::Wait | VerifyAction::Upgrade => {}
        }
        up.verify_last_idle = up.verify_last_idle.min(idle);
        // Sustained: moved data continuously for the whole verify window → upgrade.
        if decide_upgrade_verify(elapsed_ms, beat_ok, idle, verify_idle_ms, verify_ms)
            == VerifyAction::Upgrade
        {
            let t = standby;
            let route = self
                .resil
                .upgrade_probe
                .get(pid)
                .map(|u| u.standby_route)
                .unwrap_or("direct-quic");
            self.perform_upgrade(pid, t, route).await;
        }
    }

    /// P5 (GAP-6): the upgrade cutover. The direct standby is CONFIRMED stable,
    /// commit it as the session's transport, preserving the session (the same
    /// cutover seam P1/P3 use): clear `relay_committed` + `relay_only` so direct
    /// may win again, swap the verified direct transport into the link (the relay
    /// link/transport is dropped), and re-offer any unfinished transfers
    /// (resume:true) on the new direct path. Honest + loud, mirroring the relay
    /// banner: the user is told they're back on a direct path.
    async fn perform_upgrade(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let was_active = self.is_active(pid);
        let known = self.links.get(pid).and_then(|l| l.expected_secret.clone());
        // CARRY the pre-upgrade principal across the swap. `drop_link` below
        // destroys the old link, and `adopt_direct_transport` rebuilt it with a
        // hardcoded `trusted: true` + OwnerDevice, so a relay->direct upgrade
        // PROMOTED whatever the link was into owner-equivalence.
        //
        // That is the same escalation `adopt_direct` fail-safes against a
        // thousand lines up, where the comment records it being caught live: "a
        // device whose transfer grant had been REVOKED still delivered a file,
        // because the acceptor had granted it owner-equivalence at link birth."
        // The fix landed there and not in this sibling.
        //
        // It also contradicts this function's own contract, which says it reuses
        // the known identity so only the wire path changes.
        let carried = self
            .links
            .get(pid)
            .map(|l| (l.trusted, l.principal_kind.clone()));
        // Validate ownership BEFORE clearing relay state or dropping the serving
        // link. A rejected/stale standby must leave the relay path intact.
        let Some(expected_attempt) = self
            .resil
            .upgrade_probe
            .get(pid)
            .and_then(|probe| probe.token)
        else {
            t.force_close();
            return;
        };
        let auth = self
            .resil
            .upgrade_probe
            .get(pid)
            .and_then(|probe| probe.auth.clone());
        match self.check_direct_ready(pid, &t, expected_attempt, auth.as_ref(), None) {
            DirectReadyCheck::Duplicate => return,
            DirectReadyCheck::Reject => {
                self.log.debug(&format!(
                    "tunlion: UPGRADE-REFUSED peer={pid}: standby failed validation"
                ));
                t.force_close();
                return;
            }
            DirectReadyCheck::Accept { .. } => {}
        }
        if self
            .direct_pending
            .get(pid)
            .is_some_and(|pending| pending.attempt != expected_attempt)
        {
            t.force_close();
            return;
        }
        // Clear the relay commitment FIRST so the new direct link isn't treated as
        // a known-bad path and so a future stall can escalate cleanly again.
        self.resil.relay_committed.remove(pid);
        self.relay_only = false;
        self.resil.upgrade_probe.remove(pid);
        // Transfer the matching producer; never raw-remove another pending.
        let _ = self.take_pending_for_adoption(pid, expected_attempt);
        // Swap the verified direct transport into the link, dropping the relay
        // link/transport (drop_link tears down the WebRTC peer). adopt the new
        // transport via the same direct-link shape adopt_direct builds, but reusing
        // the existing identity so the session is preserved across the swap.
        self.drop_link(pid);
        let adopted = self.adopt_direct_transport(
            pid,
            t.clone(),
            route,
            expected_attempt,
            known,
            carried,
            auth,
        );
        let tkey = match adopted {
            DirectAdoption::Adopted { tkey, .. } => tkey,
            DirectAdoption::Duplicate => return,
            DirectAdoption::Rejected => return,
        };
        if let Some(k) = tkey {
            self.spawn_direct_workers(pid, &t, k);
        }
        if was_active {
            self.active = Some(pid.to_string());
        }
        // CRITICAL, P5's value-prop line: relay released, back on a direct path.
        self.log.critical(&self.log.paint(
            Tone::Ok,
            &format!("  upgraded back to a direct path (route: {route}), relay released"),
        ));
        // Re-offer unfinished transfers on the new direct transport (resume:true);
        // the ChannelReady re-emit drives the same path for the send loop.
        let _ = self.tx.send(Ev::sourced_channel_ready(pid.to_string(), t));
    }

    /// P5 (GAP-6): build the post-upgrade DIRECT link from a verified standby
    /// transport, reusing the known identity (so the session/petname is stable
    /// across the relay->direct swap, only the wire path changes). Mirrors
    /// `adopt_direct` but takes an already-connected transport and a carried
    /// (name,secret) instead of consuming a `DirectPending`.
    fn adopt_direct_transport(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
        expected_attempt: net::AttemptId,
        known: Option<(String, String)>,
        // (trusted, principal_kind) carried from the pre-upgrade link. None only
        // if the link vanished, where the previous defaults are kept so this
        // change stays scoped to the escalation it fixes.
        carried: Option<(bool, PrincipalKind)>,
        // Immutable authorization captured before the probe was consumed.
        auth: Option<DirectAuth>,
    ) -> DirectAdoption {
        let attempt = expected_attempt;
        let tkey = auth.as_ref().and_then(DirectAuth::transport_key);
        let source = match self.check_direct_ready(pid, &t, attempt, auth.as_ref(), None) {
            DirectReadyCheck::Duplicate => return DirectAdoption::Duplicate,
            DirectReadyCheck::Reject => {
                self.log.debug(&format!(
                    "tunlion: DIRECT-ADOPT-REFUSED peer={pid}: upgrade failed validation"
                ));
                t.force_close();
                return DirectAdoption::Rejected;
            }
            DirectReadyCheck::Accept { source, .. } => source,
        };
        let info = self
            .roster
            .get(pid)
            .cloned()
            .unwrap_or_else(|| json!({ "id": pid, "name": known.as_ref().map(|(n, _)| n.clone()).unwrap_or_else(|| "peer".into()) }));
        let name = known
            .as_ref()
            .map(|(n, _)| n.clone())
            .or_else(|| info["name"].as_str().map(String::from))
            .unwrap_or_else(|| "peer".into());
        let uid = info["uid"].as_str().map(|s| s.to_string());
        self.next_gen += 1;
        let generation = self.next_gen;
        self.links.insert(
            pid.to_string(),
            Link {
                peer: None,
                info,
                name,
                uid,
                transport: Some(t),
                workers: vec![],
                generation,
                source,
                attempt: Some(attempt),
                worker_sources: SimHashSet::default(),
                attempts: 0,
                trusted: upgrade_principal(&carried).0,
                verified_name: known.as_ref().map(|(n, _)| n.clone()),
                expected_secret: known,
                lan_binding: None,
                presence: Presence::Ready,
                direct: true,
                direct_route: route,
                established_at: Some(Instant::now()),
                identity_device_pub: None,
                identity_user_pub: None,
                identity_binding: BindingStrength::None,
                identity_state: IdentityState::Pending,
                identity_cert_expires: None,
                principal_kind: upgrade_principal(&carried).1,
                host: self.host.clone(),
            },
        );
        self.flush_pending_source(source);
        self.discard_held(pid, "the direct path was adopted");
        DirectAdoption::Adopted { attempt, tkey }
    }

    // --- POST-PAKE PROMOTION: the make-before-break handoff (see `handoff`) ---

    /// Our promotion race won: an authenticated direct link is up beside the
    /// serving WebRTC link, which keeps carrying the transfer. The lead end
    /// asks the peer to move now; a follower that was already asked moves now.
    /// With nothing serving (the WebRTC link died while the race ran) there is
    /// nothing to hand off from, and the direct link is adopted at once, as the
    /// promotion always did.
    fn on_promote_standby(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let serving = self
            .links
            .get(pid)
            .and_then(|l| l.transport.as_ref())
            .is_some_and(|tr| !tr.is_dead());
        if !serving || !self.promotions.contains_key(pid) {
            self.promote_adopt_now(pid, t, route);
            return;
        }
        let (expected, auth, held, handed) = {
            let Some(st) = self.promotions.get(pid) else {
                t.force_close();
                return;
            };
            (
                st.attempt,
                st.auth.clone(),
                st.standby.as_ref().map(|(held, _)| held.clone()),
                st.handed,
            )
        };
        if handed {
            if held.as_ref().is_some_and(|held| Arc::ptr_eq(held, &t)) {
                return; // duplicate held standby
            }
            t.force_close();
            return;
        }
        let Some(expected) = expected else {
            t.force_close();
            return;
        };
        match self.check_direct_ready(pid, &t, expected, auth.as_ref(), held.as_ref()) {
            DirectReadyCheck::Duplicate => return,
            DirectReadyCheck::Reject => {
                t.force_close();
                return;
            }
            DirectReadyCheck::Accept { .. } => {}
        }
        let Some(st) = self.promotions.get_mut(pid) else {
            t.force_close();
            return;
        };
        if st.handed {
            return;
        }
        st.attempt = Some(expected);
        st.standby = Some((t, route));
        let role = st.role;
        let asked = st.asked;
        self.log.debug(&format!(
            "tunlion: PROMOTE-STANDBY peer={pid} route={route}: direct link up beside the serving link"
        ));
        match role {
            PromoteRole::Lead => self.begin_handoff(pid),
            PromoteRole::Follow if asked => self.follow_moves(pid),
            PromoteRole::Follow => {}
        }
    }

    /// Adopt a promotion's direct link with nothing to hand off from. It goes to
    /// the loop as a plain `DirectReady`, whose arm adopts it exactly as before
    /// make-before-break. The entry stays (`handed`) until that adoption so the
    /// ephemeral pending it needs cannot be reaped in between: adopting with no
    /// pending would be born trusted.
    fn promote_adopt_now(&mut self, pid: &str, t: Arc<dyn Transport>, route: &'static str) {
        let expected = self
            .promotions
            .get(pid)
            .and_then(|state| state.attempt)
            .or_else(|| self.direct_pending.get(pid).map(|pending| pending.attempt));
        let Some(expected) = expected else {
            t.force_close();
            return;
        };
        let auth = self
            .promotions
            .get(pid)
            .and_then(|s| s.auth.clone())
            .or_else(|| self.direct_pending.get(pid).map(|p| p.auth.clone()));
        let held = self
            .promotions
            .get(pid)
            .and_then(|s| s.standby.as_ref().map(|(held, _)| held.clone()));
        match self.check_direct_ready(pid, &t, expected, auth.as_ref(), held.as_ref()) {
            DirectReadyCheck::Duplicate => return,
            DirectReadyCheck::Reject => {
                self.log.debug(&format!(
                    "tunlion: PROMOTE-REFUSED peer={pid}: standby failed validation"
                ));
                t.force_close();
                return;
            }
            DirectReadyCheck::Accept { .. } => {}
        }
        if self
            .direct_pending
            .get(pid)
            .is_some_and(|pending| pending.attempt != expected)
        {
            t.force_close();
            return;
        }
        let attempt = expected;
        let role = self
            .promotions
            .get(pid)
            .map(|s| s.role)
            .unwrap_or(PromoteRole::Follow);
        if let Some(st) = self.promotions.remove(pid) {
            if let Some(answer) = st.answer {
                let _ = answer.send(None);
            }
            if let Some((held, _)) = st.standby {
                if !Arc::ptr_eq(&held, &t) {
                    held.force_close();
                }
            }
        }
        let mut st = PromoteState::new(role);
        st.handed = true;
        st.attempt = Some(attempt);
        st.auth = auth;
        self.promotions.insert(pid.to_string(), st);
        self.log.debug(&format!(
            "tunlion: PROMOTE-ADOPT peer={pid} route={route}: no serving link to hand off from"
        ));
        let _ = self.tx.send(Ev::DirectReady(pid.to_string(), t, route));
    }

    /// Lead end: close the frame gate and ask the peer to move. Runs off the
    /// event loop; the loop's only part is delivering the answer
    /// (`on_promote_control`). A transfer that does not ride the gate (its
    /// channel was re-announced with a raw transport) cannot be stopped at a
    /// boundary, so then the promotion stays on WebRTC instead.
    fn begin_handoff(&mut self, pid: &str) {
        let serving = self.links.get(pid).and_then(|l| l.transport.clone());
        let gate = self
            .promotions
            .get(pid)
            .and_then(|st| st.gate.clone())
            .filter(|g| {
                serving
                    .as_ref()
                    .and_then(handoff::as_handoff)
                    .is_some_and(|h| std::ptr::eq(h, g.as_ref()))
            });
        let Some(gate) = gate else {
            self.promotion_stays(pid, "the serving transport is not gated");
            if let Some(s) = serving {
                // The follower may already hold a standby; it must not move.
                tokio::spawn(async move {
                    let msg = handoff::message(handoff::PATH_STAY);
                    let _ = tokio::time::timeout(Duration::from_secs(2), s.send_control(&msg)).await;
                });
            }
            return;
        };
        let (answer, rx) = oneshot::channel();
        if let Some(st) = self.promotions.get_mut(pid) {
            st.answer = Some(answer);
        }
        let log = self.log.clone();
        let who = pid.to_string();
        // Longer than the follower's own race can run, so it has always answered
        // (moved or declined) before this gives up and withdraws the ask.
        let backstop = if holepunch::holepunch_enabled() {
            direct::DIRECT_BUDGET + holepunch::PUNCH_BUDGET + Duration::from_secs(5)
        } else {
            direct::DIRECT_BUDGET + Duration::from_secs(2)
        };
        tokio::spawn(async move {
            let ask = handoff::message(handoff::PATH_PROMOTE);
            let stay = handoff::message(handoff::PATH_STAY);
            let outcome = gate.hand_off(&ask, &stay, rx, backstop).await;
            log.debug(&format!("tunlion: PROMOTE-HANDOFF peer={who} outcome={outcome:?}"));
        });
    }

    /// Follow end: asked to move with our direct link up. Answer on the serving
    /// channel, then hand the direct link to the loop's `DirectReady` arm; its
    /// `adopt_direct` retires the WebRTC link (still read for `RETIRE_GRACE`,
    /// so nothing the lead queued on it is lost) and installs the direct one in
    /// the same step, so the peer is never without a link.
    fn follow_moves(&mut self, pid: &str) {
        let serving = self.links.get(pid).and_then(|l| l.transport.clone());
        let Some(st) = self.promotions.get_mut(pid) else {
            return;
        };
        let Some((t, route)) = st.standby.clone() else {
            return;
        };
        let Some(attempt) = t.attempt_id() else {
            t.force_close();
            return;
        };
        if t.source_id().is_none() || st.attempt != Some(attempt) {
            t.force_close();
            return;
        }
        if self.links.get(pid).is_some_and(|link| {
            link.attempt == Some(attempt)
                && link
                    .transport
                    .as_ref()
                    .is_some_and(|live| Arc::ptr_eq(live, &t))
        }) {
            return; // duplicate of the already-active link
        }
        st.handed = true;
        if let Some(s) = serving {
            tokio::spawn(async move {
                let msg = handoff::message(handoff::PATH_PROMOTED);
                let _ = tokio::time::timeout(Duration::from_secs(2), s.send_control(&msg)).await;
            });
        }
        self.log.debug(&format!(
            "tunlion: PROMOTED peer={pid} route={route}: moving to the direct link at the lead's boundary"
        ));
        let _ = self.tx.send(Ev::DirectReady(pid.to_string(), t, route));
    }

    /// Lead end: the peer moved. Open the gate onto the direct link (frames
    /// resume there from the next chunk), then retire the WebRTC link and
    /// install the direct one, exactly as the promotion's adoption always built
    /// it. Nothing is re-offered: what was offered on WebRTC is answered on
    /// whichever path the peer is using.
    fn lead_moves(&mut self, pid: &str) {
        let Some(st) = self.promotions.get_mut(pid) else {
            return;
        };
        if st.handed || st.gate.as_ref().is_none_or(|g| !g.asked()) {
            return; // not an answer to anything we asked
        }
        let Some((t, route)) = st.standby.clone() else {
            return;
        };
        let Some(attempt) = t.attempt_id() else {
            t.force_close();
            return;
        };
        if t.source_id().is_none() || st.attempt != Some(attempt) {
            t.force_close();
            return;
        }
        if self.links.get(pid).is_some_and(|link| {
            link.attempt == Some(attempt)
                && link
                    .transport
                    .as_ref()
                    .is_some_and(|live| Arc::ptr_eq(live, &t))
        }) {
            return; // duplicate of the already-active link
        }
        match st.answer.take() {
            Some(answer) if !answer.is_closed() => {
                let _ = answer.send(Some(t.clone()));
            }
            _ => {
                // Our barrier already gave up (the answer crossed our
                // `path-stay`), but the peer has moved and will close the old
                // path, so follow it rather than strand the transfer there.
                if let Some(g) = &st.gate {
                    g.force_switch(t.clone());
                }
            }
        }
        st.handed = true;
        let verdict = self.adopt_direct(pid, t.clone(), route);
        let tkey = match verdict {
            DirectAdoption::Adopted { tkey, .. } => tkey,
            _ => return,
        };
        if let Some(k) = tkey {
            self.spawn_direct_workers(pid, &t, k);
        }
        self.log.debug(&format!(
            "tunlion: PROMOTED peer={pid} route={route}: the transfer moved to the direct link at a frame boundary"
        ));
        // A handoff REPLACES the serving link's source, so the re-armed
        // ChannelReady queued at PAKE confirm is rejected by the exact-source
        // gate (the `begin_handoff` ask and the offer cross the same boundary).
        // Re-announce the link just installed, exactly as the relay->direct
        // upgrade does: without it a sender whose offer was dropped in that
        // window has no second chance ("Nothing is re-offered" below), and the
        // receiver waits forever for a first byte after "authenticated,
        // sending". The handler offers only the transfers still unfinished.
        let _ = self.tx.send(Ev::sourced_channel_ready(pid.to_string(), t));
    }

    /// The promotion ends with the WebRTC link still serving.
    fn promotion_stays(&mut self, pid: &str, why: &str) {
        self.abandon_promotion(pid);
        let _ = self.take_direct_pending(pid);
        self.log.debug(&format!(
            "tunlion: PROMOTE-STAY peer={pid} ({why}): the WebRTC link keeps serving"
        ));
    }

    /// Take the serving WebRTC link out of `links` without cutting off what it
    /// is still delivering: the peer may have queued messages on it before it
    /// moved, so its channel keeps being read for `RETIRE_GRACE`, then closes.
    /// The active slot stays with the peer; the caller installs the successor.
    fn retire_serving_link(&mut self, pid: &str) {
        let peer = self.links.get_mut(pid).and_then(|l| {
            // On the lead end this is the handoff gate, which now forwards to
            // the direct link: closing it with the link would close that.
            l.transport = None;
            l.peer.take()
        });
        let was_active = self.is_active(pid);
        self.drop_link(pid);
        if was_active {
            self.active = Some(pid.to_string());
        }
        if let Some(p) = peer {
            tokio::spawn(async move {
                tokio::time::sleep(RETIRE_GRACE).await;
                p.mark_closed();
                p.close().await;
            });
        }
    }

    /// The handoff's control messages (`handoff::PATH_*`). Returns true when
    /// `v` was one of them, so the loop does not dispatch it further.
    pub async fn on_promote_control(&mut self, pid: &str, v: &Value) -> bool {
        let Some(kind) = v["type"].as_str() else {
            return false;
        };
        let role = self.promotions.get(pid).map(|s| s.role);
        match kind {
            handoff::PATH_PROMOTE => {
                if role == Some(PromoteRole::Follow) {
                    let Some(st) = self.promotions.get_mut(pid) else {
                        return true;
                    };
                    if st.handed {
                        return true;
                    }
                    if st.has_standby() {
                        self.follow_moves(pid);
                    } else {
                        // Our race is still running; answer when it resolves
                        // (moved on a win, declined at its deadline).
                        st.asked = true;
                    }
                } else if let Some(t) = self.transport_of(pid) {
                    // No direct link is coming at this end.
                    let msg = handoff::message(handoff::PATH_DECLINED);
                    let _ = tokio::time::timeout(Duration::from_secs(2), t.send_control(&msg)).await;
                }
            }
            handoff::PATH_PROMOTED => {
                if role == Some(PromoteRole::Lead) {
                    self.lead_moves(pid);
                }
            }
            handoff::PATH_DECLINED => {
                if role == Some(PromoteRole::Lead)
                    && !self.promotions.get(pid).is_some_and(|s| s.handed)
                {
                    self.promotion_stays(pid, "the peer has no direct link");
                }
            }
            handoff::PATH_STAY => {
                if role == Some(PromoteRole::Follow)
                    && !self.promotions.get(pid).is_some_and(|s| s.handed)
                {
                    self.promotion_stays(pid, "the lead withdrew the handoff");
                }
            }
            _ => return false,
        }
        true
    }

    /// Per tick: settle promotions whose race did not end in a handoff. A won
    /// race whose serving link has since died is adopted directly; one whose
    /// lead barrier gave up stays; a race past its deadline with no winner
    /// leaves WebRTC serving (a follower that was asked says so), with no
    /// rebuild because nothing was torn down.
    fn settle_promotions(&mut self, now: Instant) {
        let pids: Vec<String> = self.promotions.keys().cloned().collect();
        for pid in pids {
            let serving = self
                .links
                .get(&pid)
                .and_then(|l| l.transport.as_ref())
                .is_some_and(|t| !t.is_dead());
            let Some(st) = self.promotions.get(&pid) else {
                continue;
            };
            if st.handed {
                continue; // its adoption is already queued
            }
            if let Some((t, route)) = st.standby.clone() {
                if !serving {
                    self.promote_adopt_now(&pid, t, route);
                } else if st.answer.as_ref().is_some_and(|a| a.is_closed()) {
                    self.promotion_stays(&pid, "the peer never answered the handoff");
                }
                continue;
            }
            let expired = self
                .direct_pending
                .get(&pid)
                .is_none_or(|p| now >= p.deadline);
            if !expired {
                continue;
            }
            if serving {
                let decline = (st.role == PromoteRole::Follow && st.asked)
                    .then(|| self.transport_of(&pid))
                    .flatten();
                self.promotion_stays(&pid, "no direct path in budget");
                if let Some(t) = decline {
                    tokio::spawn(async move {
                        let msg = handoff::message(handoff::PATH_DECLINED);
                        let _ = tokio::time::timeout(Duration::from_secs(2), t.send_control(&msg)).await;
                    });
                }
            } else {
                // No live link: the pending's own expiry rebuilds WebRTC, as
                // it always has. Only the promotion's bookkeeping goes.
                self.abandon_promotion(&pid);
            }
        }
    }

    /// P5 (GAP-6): a relay->direct upgrade probe's direct standby CONNECTED. Stash
    /// it on the peer's `UpgradeProbe` and START the verify window. Crucially, do
    /// NOT touch `links`, the relay link keeps serving until the standby is proven
    /// stable. If we have no armed probe for this peer (it upgraded/left while the
    /// race was in flight), just drop the transport (it closes on drop). Idempotent:
    /// a second DirectUpgradeReady for an already-stashed standby is ignored.
    pub fn stash_upgrade_standby(
        &mut self,
        pid: &str,
        t: Arc<dyn Transport>,
        route: &'static str,
    ) {
        let Some(source) = t.source_id() else {
            self.log.debug(&format!(
                "tunlion: STANDBY-REFUSED peer={pid}: transport has no source identity"
            ));
            t.force_close();
            return;
        };
        let Some(attempt) = t.attempt_id() else {
            self.log.debug(&format!(
                "tunlion: STANDBY-REFUSED peer={pid}: transport has no attempt identity"
            ));
            t.force_close();
            return;
        };
        // A post-PAKE promotion's winner rides this event too (it must not
        // clobber the serving link any more than a probe's may). Validate its
        // ownership BEFORE inserting a pending source or consuming pending state.
        let promotion_branch = self.promotions.contains_key(pid)
            || self.direct_pending.get(pid).is_some_and(|p| p.ephemeral && !p.probe);
        if promotion_branch {
            let (expected, auth, held, handed) = {
                let Some(st) = self.promotions.get(pid) else {
                    t.force_close();
                    return;
                };
                (
                    st.attempt,
                    st.auth.clone(),
                    st.standby.as_ref().map(|(held, _)| held.clone()),
                    st.handed,
                )
            };
            if handed {
                if held.as_ref().is_some_and(|held| Arc::ptr_eq(held, &t)) {
                    return;
                }
                t.force_close();
                return;
            }
            let Some(expected) = expected else {
                t.force_close();
                return;
            };
            if self
                .direct_pending
                .get(pid)
                .is_some_and(|pending| pending.attempt != expected)
            {
                t.force_close();
                return;
            }
            match self.check_direct_ready(pid, &t, expected, auth.as_ref(), held.as_ref()) {
                DirectReadyCheck::Duplicate => return,
                DirectReadyCheck::Reject => {
                    self.log.debug(&format!(
                        "tunlion: STANDBY-REFUSED peer={pid}: promotion failed validation"
                    ));
                    t.force_close();
                    return;
                }
                DirectReadyCheck::Accept { .. } => {}
            }
            self.sources.pending_sources.insert(
                source,
                PendingSource {
                    pid: pid.to_string(),
                    attempt: Some(attempt),
                    at: Instant::now(),
                    events: std::collections::VecDeque::new(),
                    bytes: 0,
                },
            );
            self.on_promote_standby(pid, t, route);
            return;
        }
        // Probe branch: require an armed probe and matching token BEFORE taking
        // any pending or inserting a source entry. Validation is shared with the
        // promotion/adoption paths and uses the stored pending authorization.
        let (probe_token, held) = match self.resil.upgrade_probe.get(pid) {
            Some(up) => (
                up.token,
                up.standby.clone(),
            ),
            None => {
                t.force_close();
                return;
            }
        };
        let Some(probe_token) = probe_token else {
            t.force_close();
            return;
        };
        let Some(pending) = self.direct_pending.get(pid) else {
            t.force_close();
            return;
        };
        if pending.attempt != attempt || probe_token != attempt {
            self.log.debug(&format!(
                "tunlion: STANDBY-REFUSED peer={pid}: standby attempt does not match pending"
            ));
            t.force_close();
            return;
        }
        let auth = pending.auth.clone();
        match self.check_direct_ready(pid, &t, attempt, Some(&auth), held.as_ref()) {
            DirectReadyCheck::Duplicate => return,
            DirectReadyCheck::Reject => {
                self.log.debug(&format!(
                    "tunlion: STANDBY-REFUSED peer={pid}: probe failed validation"
                ));
                t.force_close();
                return;
            }
            DirectReadyCheck::Accept { .. } => {}
        }
        self.sources.pending_sources.insert(
            source,
            PendingSource {
                pid: pid.to_string(),
                attempt: Some(attempt),
                at: Instant::now(),
                events: std::collections::VecDeque::new(),
                bytes: 0,
            },
        );
        let _ = self.take_pending_for_adoption(pid, attempt);
        let Some(up) = self.resil.upgrade_probe.get_mut(pid) else {
            t.force_close();
            return;
        };
        if up.token.is_some_and(|token| token != attempt) {
            t.force_close();
            return;
        }
        if let Some(held) = &up.standby {
            if !Arc::ptr_eq(held, &t) {
                t.force_close();
            }
            return; // already verifying a standby; ignore the duplicate.
        }
        up.token = Some(attempt);
        up.standby = Some(t);
        up.standby_route = route;
        up.verify_started = None; // judge_upgrade_standby stamps it on first look
        up.verify_last_idle = u64::MAX;
        // DEBUG, resilience internal (upgrade verify window opening).
        self.log.debug(&self.log.paint(
            Tone::Dim,
            "  direct path connected, verifying it holds before upgrading...",
        ));
    }

    /// C4: transient `disconnected`, nudge ICE from the impolite side and
    /// give it grace before treating it as failure. C21: a peer that said
    /// `brb` gets its declared window instead of the 6 s blip grace, and no
    /// scary message.
    pub async fn on_pc_state(&mut self, pid: &str, s: &str) {
        let away = self.is_away(pid);
        let Some(l) = self.links.get_mut(pid) else {
            return;
        };
        // A link with no WebRTC peer has no connection state to report. This is
        // the retired peer of a promotion that moved to direct QUIC, still being
        // read for a grace: its `disconnected` is the old path closing, not this
        // link reconnecting.
        if l.peer.is_none() {
            return;
        }
        // C26: collect the announcement, print after the borrow ends so the
        // roster can read every link.
        let mut announce: Option<(&'static str, Tone, &'static str)> = None;
        match s {
            "connected" => {
                if l.presence == Presence::Reconnecting {
                    announce = Some((self.log.glyph_ok(), Tone::Ok, "recovered"));
                }
                l.presence = Presence::Ready;
                l.attempts = 0;
            }
            "disconnected" => {
                let grace = if away {
                    l.presence = Presence::Away;
                    if let Some((_, until)) = &self.rejoin.away {
                        until.duration_since(Instant::now()) + Duration::from_secs(15)
                    } else {
                        Duration::from_secs(6)
                    }
                } else {
                    l.presence = Presence::Reconnecting;
                    announce = Some(("◌", Tone::Warn, "reconnecting..."));
                    Duration::from_secs(6)
                };
                if let Some(p) = &l.peer {
                    if !p.polite && !away {
                        p.restart_ice();
                    }
                }
                let tx = self.tx.clone();
                let pid = pid.to_string();
                let generation = l.generation;
                tokio::spawn(async move {
                    tokio::time::sleep(grace).await;
                    let _ = tx.send(Ev::GraceExpired(pid, generation));
                });
            }
            _ => {}
        }
        if let Some((mark, tone, note)) = announce {
            self.log.say(&self.roster(pid, mark, tone, note, "peer"));
        }
    }

    /// A peer's socket died. Drop its link; if it was the active target, open
    /// the rejoin window (their client auto-rejoins; C6 supersede completes
    /// the recovery). Returns true if the ACTIVE peer left.
    ///
    /// #28 DEFERRED DROP: peer-left fires when a sid LEAVES THE ROOM, but the
    /// WebRTC data channel is independent and may still be flowing, either a
    /// cosmetic signaling reconnect mid-transfer (keep it!) or a hard-killed
    /// peer whose channel reads flowing for a beat before DTLS notices (must
    /// still drop, or the sender strands). We can't tell the two apart at this
    /// instant, so we DEFER: stash the payload and re-check each tick
    /// (`reap_deferred`). If it goes idle/dead it gets re-injected here with a
    /// force marker and dropped then; if it keeps flowing the transfer
    /// completes on the live channel and the idle link is reaped harmlessly.
    /// The roster entry is removed immediately (the sid truly left); only the
    /// LINK drop is deferred.
    ///
    /// The link drop can also be deferred one turn for a current link that
    /// still has events the transport already read: those are forwarded first
    /// and an internal `Ev::PeerLeft` barrier, tagged with the link's exact
    /// current source, follows them. Delegated/ephemeral links are included —
    /// a temporary-access decline is exactly such a control — but only the
    /// QUEUE HANDOVER is deferred; their enrollment still ends and they are
    /// never rejoinable. A forced reap drop never takes this path, so a
    /// revoked/force-dropped source can never process queued control.
    /// See `drain_current_link_events`.
    pub fn on_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid_val) = v["id"].as_str() else {
            return false;
        };
        // A force/revoked departure is an IMMEDIATE teardown order. It must not
        // be swallowed by a hand-over already in flight: clear BOTH once-only
        // markers first, so the queued barrier and the controls it carried can
        // no longer act on this link, then fall through to the ordinary cleanup
        // and finalizer below. Ordinary ready/pending behaviour is unchanged.
        let forced = v["__fil_force_drop"].as_bool() == Some(true);
        if forced {
            self.sources.force_clear_departure(pid_val);
        } else {
            if let Some((source, ready)) = self.sources.replay_departures.get(pid_val).copied() {
                if self.links.get(pid_val).map(|link| link.source) != Some(source) {
                    self.sources.replay_departures.remove(pid_val);
                    if ready { return false; }
                } else {
                    if !ready { return false; }
                    self.sources.replay_departures.remove(pid_val);
                }
            } else if let Some(source) = self.links.get(pid_val).map(|link| link.source) {
                if self.sources.replaying_sources.contains_key(&source) {
                    self.sources.replay_departures.insert(pid_val.to_string(), (source, false));
                    let _ = self.tx.send(Ev::ReplayDeparture(pid_val.to_string(), source, v.clone()));
                    return false;
                }
            }
            // A departure barrier `stage_event` admitted: the departed link's
            // already-read events were dispatched ahead of it, and the marker is
            // bound to that exact source. Consume it once and run the ordinary
            // finalizer now, with its normal return value. A marker whose source
            // is not the CURRENT link's belongs to a link replaced before this
            // ran: the successor is newer authority, so nothing of it is touched
            // (not even the cleanup below), and the stale marker dies here.
            if let Some(source) = self
                .sources.link_events
                .get_mut(pid_val)
                .and_then(|events| events.departure_ready.take())
            {
                return if self.links.get(pid_val).map(|link| link.source) == Some(source) {
                    self.finalize_peer_left(v)
                } else {
                    false
                };
            }
            // A barrier for this exact link is already queued: its events were
            // handed over, so the local queue is legitimately empty. A DUPLICATE
            // room signal must not finalize on that empty queue and beat the
            // barrier; the barrier does the drop. Checked after the ready marker
            // (that one is the validated hand-over itself).
            if let Some(source) = self
                .sources.link_events
                .get(pid_val)
                .and_then(|events| events.departure_pending)
            {
                if self.links.get(pid_val).map(|link| link.source) == Some(source) {
                    return false;
                }
                // The link it protected is gone or replaced: the flag dies with it.
                if let Some(events) = self.sources.link_events.get_mut(pid_val) {
                    events.departure_pending = None;
                }
            }
        }
        let pid = pid_val.to_string();
        self.roster.remove(&pid);
        self.webrtc_only.remove(&pid);
        if let Some(_state) = self.builds.get(&pid) {
            #[cfg(feature = "test-hooks")]
            let generation = format!(" gen={}", _state.generation);
            #[cfg(not(feature = "test-hooks"))]
            let generation = "";
            self.log
                .debug(&format!("peer-left invalidated build pid={pid}{generation}"));
        }
        self.cancel_build(&pid);
        self.sources.retain_pending_except_pid(&pid);
        if !self.links.contains_key(&pid) {
            return false;
        }
        // Delegated (ephemeral) devices are removed on disconnect — not
        // deferred, not rejoinable; they must re-enroll on reconnect. The drop
        // itself still runs through `finalize_peer_left` below, because even a
        // delegated link can hold an already-read control (a temporary-access
        // decline) that belongs to this departure. Only the QUEUE HANDOVER is
        // allowed to run first; nothing about the delegation changes.
        let delegated = matches!(
            self.link(&pid).map(|l| &l.principal_kind),
            Some(PrincipalKind::Delegated { .. })
        );
        // Defer the drop while the data channel is still moving bytes, unless
        // this is the force re-injection from reap_deferred (the link has since
        // gone idle/dead and must drop now). TUNLION_TEST_NO_DEFER reverts to
        // the old unconditional-drop behaviour so an A/B repro can prove the
        // deferral is what saves the live transfer (baseline must FAIL).
        //
        // A receive that is already COMPLETE (`recv_done`: every file verified,
        // nothing in flight, not a daemon) has nothing left for a live channel
        // to carry, so deferring only delays the exit. That delay was 2 s on
        // every code transfer that finished on WebRTC: the sender exits right
        // after the delivery-ack and its data channel still reads as flowing
        // (`link_flowing` counts the last data byte for 3 s). Promotion now
        // lets small transfers finish on WebRTC, so this is the common case.
        let defer_disabled = test_hooks::no_defer();
        if !forced && !delegated && !defer_disabled && !self.recv_done && self.link_flowing(&pid) {
            // Idempotent: first peer-left for this sid records the original
            // payload; a duplicate is swallowed (no double-defer, no drop).
            self.digest.deferred_left
                .entry(pid.clone())
                .or_insert_with(|| v.clone());
            let name = self
                .link(&pid)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred drop while channel flowing).
            self.log.debug(&format!(
                "{name} signaling left, data channel still flowing, deferring drop"
            ));
            return false;
        }
        // A current link can still hold events the transport already READ but
        // the loop has not forwarded yet (the per-link candidate queue is
        // drained once per turn by `pump_builds`). Dropping the link here
        // deletes that queue, so the last control a peer sent just before
        // leaving - a decline, a final open/close - is lost even though it
        // arrived. Hand over a BOUNDED batch of that link's current events in
        // order (never a loop over a concurrent producer), then queue an
        // internal, source-tagged departure behind them. Over the per-link
        // budget the hand-over fails closed: drop now, as before, and let the
        // gate reject the already-forwarded prefix once the link is gone.
        if !forced {
            match self.drain_current_link_events(&pid) {
                QueueDrain::Empty => {}
                QueueDrain::Moved(moved) => {
                    if let Some(source) = self.links.get(&pid).map(|link| link.source) {
                        let _ = self.tx.send(Ev::Sourced {
                            pid: pid.clone(),
                            source,
                            inner: Box::new(Ev::PeerLeft(v.clone())),
                        });
                        if let Some(events) = self.sources.link_events.get_mut(&pid) {
                            events.departure_pending = Some(source);
                        }
                        self.log.debug(&format!(
                            "peer-left for {pid}: {moved} already-read event(s) handed over ahead of the departure"
                        ));
                    }
                    return false;
                }
                QueueDrain::Overflow => {
                    self.log.debug(&format!(
                        "peer-left for {pid}: already-read events exceed {MAX_BUILD_EVENTS}; dropping without hand-over"
                    ));
                    return self.finalize_peer_left(v);
                }
            }
        }
        self.finalize_peer_left(v)
    }

    /// The departure itself, split out so a queued `Ev::PeerLeft` barrier can
    /// run it only after the departed link's already-read events were handled.
    /// `v` is the ORIGINAL peer-left payload (a forced reap re-injection runs
    /// this directly, exactly as it always did).
    ///
    /// This is the ONE drop path for an ordinary departure, so it keeps both
    /// tails: delegated/ephemeral devices still lose their enrollment at once
    /// and are never rejoinable, and every other link still opens the rejoin
    /// window when it was active. Nothing here retains a link indefinitely:
    /// the queue handover in `on_peer_left` defers the CALL by one queue drain,
    /// never the decision.
    fn finalize_peer_left(&mut self, v: &Value) -> bool {
        let Some(pid) = v["id"].as_str().map(str::to_string) else {
            return false;
        };
        if matches!(
            self.link(&pid).map(|l| &l.principal_kind),
            Some(PrincipalKind::Delegated { .. })
        ) {
            let name = self.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
            self.drop_link(&pid);
            self.log.debug(&format!(
                "ephemeral device {name} disconnected, enrollment revoked"
            ));
            return false;
        }
        let was_active = self.is_active(&pid);
        self.drop_link(&pid);
        if was_active {
            // C21: informed waits, a peer that declared `brb` gets its
            // promised window (plus slack); an unannounced vanish gets the
            // short default. Their client auto-rejoins; C6 supersede or a
            // fresh adopt completes the recovery.
            self.rejoin.rejoin_window = match &self.rejoin.away {
                Some((apid, until)) if *apid == pid && *until > Instant::now() => {
                    until.duration_since(Instant::now()) + Duration::from_secs(15)
                }
                _ => self.host.rejoin_unwarned(),
            };
            self.rejoin.waiting_rejoin = Some(Instant::now());
        }
        was_active
    }

    /// C21: any traffic from a peer cancels its declared absence.
    pub fn note_alive(&mut self, pid: &str) {
        if matches!(&self.rejoin.away, Some((apid, _)) if apid == pid) {
            self.rejoin.away = None;
        }
    }

    /// C26: set a link's roster presence; returns its name for the announce.
    pub fn link_presence(&mut self, pid: &str, p: Presence) -> String {
        match self.links.get_mut(pid) {
            Some(l) => {
                l.presence = p;
                l.name.clone()
            }
            None => String::new(),
        }
    }

    pub fn is_away(&self, pid: &str) -> bool {
        matches!(&self.rejoin.away, Some((apid, until)) if apid == pid && *until > Instant::now())
    }

    /// C26: one static colored status line showing EVERY peer, the changed
    /// one carrying the note, `✓ daring-wombat   ● deft-gibbon  away...`.
    /// `fallback_name` covers a peer already dropped from the map (peer-left).
    pub fn roster(
        &self,
        pid: &str,
        mark: &str,
        tone: impl Into<Tone>,
        note: &str,
        fallback_name: &str,
    ) -> String {
        // Frozen callers in `recv_cmd`/`send_cmd` still hand this a `ui::Tone`;
        // the CLI glue implements `From<ui::Tone>` so those calls do not move.
        let tone = tone.into();
        // A link with no name yet is labelled by its raw signaling id. That id
        // means nothing to a person (a first-time-user test read "ok alpha
        // ok 3f9c...e1" after `receive <code>`), so it shows only under -v:
        // the line names the peer it is about, and leaves unnamed others out.
        let show_raw = self.log.enabled(Level::Debug);
        let mut links: Vec<(&String, &Link)> = self.links.iter().collect();
        links.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let mut parts = Vec::new();
        let mut seen = false;
        // A label that is ANY live link's signaling id or uid is an id, not a
        // name, whatever its shape.
        let is_some_links_id = |label: &str| {
            self.links.iter().any(|(k, l)| k == label || l.uid.as_deref() == Some(label))
        };
        for (id, l) in links {
            let unnamed = label_is_raw_id(l.label(), id, l.uid.as_deref()) || is_some_links_id(l.label());
            if id == pid {
                seen = true;
                let label = if unnamed && !show_raw && !label_is_raw_id(fallback_name, pid, None) {
                    fallback_name
                } else if unnamed && !show_raw {
                    "the other device"
                } else {
                    l.label()
                };
                parts.push(peer_entry(&*self.log, label, mark, tone, note));
            } else if unnamed && !show_raw {
                continue;
            } else {
                let (m, t, n) = presence_glyph(l.presence, &*self.log);
                parts.push(peer_entry(&*self.log, l.label(), m, t, n));
            }
        }
        if !seen {
            let label = if label_is_raw_id(fallback_name, pid, None) && !show_raw {
                "the other device"
            } else {
                fallback_name
            };
            parts.push(peer_entry(&*self.log, label, mark, tone, note));
        }
        format!("  {}", parts.join("   "))
    }

    /// #7 for the CLI: an offer from a roster peer we haven't linked yet
    /// creates a polite responder link. Stray signals from unknowns drop.
    /// Apply a relayed signal to `from`'s link. Never fatal (F6): the
    /// watchdog/grace machinery owns failed negotiations. On polite-side
    /// glare (webrtc-rs can't roll back out of have-local-offer) the link is
    /// rebuilt as a pure responder and the colliding offer re-applied.
    pub async fn apply_signal(&mut self, from: &str, data: Value) {
        let peer = match self.link(from).and_then(|l| l.peer.clone()) {
            Some(p) => p,
            None => return,
        };
        // The initiator rebuilt its peer connection on the same sid (a
        // rotation): its offer carries a new `pc` tag. Applying it to the
        // responder that answered the OLD connection is a renegotiation across
        // two different DTLS endpoints, which never connects. Rebuild a fresh
        // responder for it instead, unless the link is already serving bytes.
        let serving = self
            .links
            .get(from)
            .and_then(|l| l.transport.as_ref())
            .is_some_and(|t| !t.is_dead());
        if !serving
            && peer.polite
            && is_offer_data(&data)
            && new_peer_connection(peer.remote_pc().await, data["pc"].as_u64())
        {
            self.log.debug(&format!(
                "tunlion: FRESH-RESPONDER peer={from}: offer from a new peer connection, rebuilding the responder"
            ));
            self.drop_link(from);
            if let Err(e) = self.ensure_responder(from, &data).await {
                self.log.trace(&format!("signal: fresh responder failed: {e} (recovering)"));
                return;
            }
            let envelope = json!({ "from": from, "data": data.clone() });
            if self.build_pending(from) {
                self.stage_signal(&envelope);
            } else if !self.hold_for_direct(&envelope) {
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(data).await {
                        self.log.trace(&format!("signal failed to apply: {e} (recovering)"));
                    }
                }
            }
            return;
        }
        match peer.handle_signal(data).await {
            Ok(net::SignalOutcome::Handled) => {}
            Ok(net::SignalOutcome::Glare(offer)) => {
                self.drop_link(from);
                if let Err(e) = self.ensure_responder(from, &offer).await {
                    self.log.trace(&format!("signal: glare rebuild failed: {e} (recovering)"));
                    return;
                }
                if let Some(p) = self.link(from).and_then(|l| l.peer.clone()) {
                    if let Err(e) = p.handle_signal(offer).await {
                        self.log.trace(&format!("signal failed to apply: {e} (recovering)"));
                    }
                }
            }
            Err(e) => self.log.trace(&format!("signal failed to apply: {e} (recovering)")),
        }
    }

    /// The SDP tail every driver loop runs after `ensure_responder`: stage the
    /// signal into a build still in flight for its sid, else HOLD it when our
    /// direct attempt for that sid is pending (no responder may be built yet,
    /// and the peer sends its offer once per connection), else apply it.
    pub async fn deliver_sdp_signal(&mut self, envelope: &Value) {
        let from = envelope["from"].as_str().unwrap_or_default().to_string();
        if self.build_pending(&from) {
            self.stage_signal(envelope);
            return;
        }
        if self.hold_for_direct(envelope) {
            return;
        }
        self.apply_signal(&from, envelope["data"].clone()).await;
    }

    pub async fn ensure_responder(&mut self, from: &str, data: &Value) -> Result<()> {
        // A held offer from an older attempt must not be replayed in front of
        // this newer one (the build below would answer the stale offer first).
        if self
            .held_signals
            .get(from)
            .is_some_and(|h| supersedes_held(h, data))
        {
            self.discard_held(from, "a newer connection attempt arrived");
        }
        if let Some(uid) = data["uid"].as_str() {
            net::ensure_ascii_uid(uid)?;
            if let Some(info) = self.roster.get_mut(from) {
                // A signal payload names a uid only for a peer we have none
                // for yet. It never replaces one the roster already holds
                // (from the server's welcome / peer-joined), and it is never
                // authority: code authority is `holds_code_authority`.
                if info["uid"].as_str().is_none() {
                    info["uid"] = json!(uid);
                }
            } else {
                self.roster
                    .insert(from.to_string(), json!({ "id": from, "uid": uid }));
            }
        }
        if self.links.contains_key(from) {
            return Ok(());
        }
        if data["type"].as_str() == Some("description")
            && data["description"]["type"].as_str() == Some("offer")
        {
            // Answer a WebRTC offer from a channel-peer EVEN IF we never got its
            // known-peer. The existing-member known-peer notification is
            // unreliable on prod (proven via the signaling harness: the NEW
            // joiner is reliably notified, but the EXISTING member often is NOT),
            // which left the acceptor ignoring a valid initiator's offer and
            // looking like "stuck connecting". One-sided discovery is now enough:
            // whoever discovers drives, the other answers. SAFE: trust still
            // gates entirely on the pair-proof MAC (an attacker without the
            // secret fails it and is never trusted), we only answer the offer
            // and let the proof decide. A later known-peer refreshes name/uid.
            let info = self
                .roster
                .get(from)
                .cloned()
                .unwrap_or_else(|| json!({ "id": from }));
            // SCOPED fallback, never blanket: only a peer that explicitly
            // announced `direct:false` (the browser hint) may cancel a pending
            // direct attempt from its offer. The L2/exec initiator deliberately
            // races a WebRTC peer against a direct-QUIC dial; cancelling for it
            // made the acceptor choose WebRTC and broke the direct path's
            // expiry/revocation close semantics (expiry-race + pty-resume
            // gates). CLI peers carry no hint, so their pending survives this.
            if self.webrtc_only.contains(from) {
                let _ = self.take_direct_pending(from);
            }
            if self.links.len() < MAX_LINKS {
                // Forced responder: this link exists to answer THEIR offer.
                self.establish_as(info, Some(true)).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod relay_privacy_tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn direct_is_never_permitted_in_relay_mode() {
        for direct_ok in [false, true] {
            assert!(!direct_permitted(true, direct_ok));
        }
        assert!(direct_permitted(false, true));
        assert!(!direct_permitted(false, false));
    }

    /// One client->server websocket frame (clients always mask).
    async fn read_client_frame(s: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await.ok()?;
        let opcode = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut len = (h[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.ok()?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            s.read_exact(&mut b).await.ok()?;
            len = u64::from_be_bytes(b);
        }
        let mut mask = [0u8; 4];
        if masked {
            s.read_exact(&mut mask).await.ok()?;
        }
        let mut payload = vec![0u8; len as usize];
        s.read_exact(&mut payload).await.ok()?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Some((opcode, payload))
    }

    /// One short unmasked server->client text frame.
    async fn send_text(s: &mut tokio::net::TcpStream, text: &str) {
        let bytes = text.as_bytes();
        assert!(bytes.len() < 126);
        let mut f = vec![0x81u8, bytes.len() as u8];
        f.extend_from_slice(bytes);
        s.write_all(&f).await.unwrap();
    }

    /// A minimal Engine.IO / Socket.IO endpoint: completes the handshake
    /// `filament_signal::connect` expects, then records every text frame the
    /// client sends until it closes. Everything a Conn emits is in that list.
    async fn fake_signaling() -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let h = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut byte = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut byte).await.unwrap();
                req.push(byte[0]);
            }
            let req = String::from_utf8_lossy(&req).to_string();
            let key = req
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| v.trim().to_string())
                })
                .expect("websocket key");
            let digest = ring::digest::digest(
                &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            );
            let accept = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
            s.write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            send_text(&mut s, r#"0{"sid":"t","upgrades":[],"pingInterval":25000,"pingTimeout":20000}"#).await;
            let mut seen = Vec::new();
            while let Some((op, payload)) = read_client_frame(&mut s).await {
                match op {
                    0x1 => {
                        let t = String::from_utf8_lossy(&payload).to_string();
                        if t == "40" {
                            send_text(&mut s, "40").await;
                        }
                        seen.push(t);
                    }
                    0x8 => break,
                    _ => {}
                }
            }
            seen
        });
        (url, h)
    }

    // --relay hides our IP from the peer. A relay-mode Conn, even one whose
    // caller asked for direct (the daemon and L2 acceptors always do), must
    // never send a transport-offer: it carries our host/public candidates.
    #[test]
    fn a_relay_mode_conn_never_sends_a_transport_offer() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (url, server) = fake_signaling().await;
            let (itx, _irx) = mpsc::unbounded_channel::<filament_signal::Incoming>();
            let sio = filament_signal::connect(&url, itx)
                .await
                .expect("connect to the fake signaling endpoint");
            let (tx, _rx) = mpsc::unbounded_channel::<Ev>();
            let mut conn = Conn::for_command(
                filament_transport::TransportContext::default(),
                &url,
                sio.clone(),
                tx,
                "uid-relay-test".to_string(),
                true, // --relay
                None,
                false,
                true, // direct requested (as `up` and L2 acceptors do)
                Arc::new(crate::host::NoLog),
                Arc::new(crate::host::NoHost),
            );
            assert!(!conn.direct_ok, "relay mode must not keep direct_ok");
            conn.start_direct("peer-sid", "peer", "00").await;
            conn.start_direct_fleet("peer-sid", "00").await;
            let _ = conn
                .start_direct_promote("peer-sid", "peer", "00", PromoteRole::Lead, true)
                .await;
            assert!(conn.direct_pending.is_empty(), "no direct attempt may be armed");
            // Control: the recorder really does see what this client emits.
            sio.emit(
                "signal",
                json!({ "to": "peer-sid", "data": { "type": "control-marker" } }),
            )
            .await
            .unwrap();
            sio.disconnect().await.unwrap();
            let seen = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("fake signaling ended")
                .unwrap();
            assert!(seen.iter().any(|t| t.contains("control-marker")), "{seen:?}");
            assert!(
                !seen.iter().any(|t| t.contains("transport-offer")),
                "relay mode sent a transport-offer: {seen:?}"
            );
        });
    }

    /// A browser says `direct:false`; the acceptor must not even advertise a
    /// QUIC transport-offer for it. Without this the offer is emitted and the
    /// WebRTC link is suppressed until the direct budget expires, which is the
    /// "connecting" stall the web shell reported.
    #[test]
    fn a_browser_peer_never_gets_a_transport_offer() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (url, server) = fake_signaling().await;
            let (itx, _irx) = mpsc::unbounded_channel::<filament_signal::Incoming>();
            let sio = filament_signal::connect(&url, itx)
                .await
                .expect("connect to the fake signaling endpoint");
            let (tx, _rx) = mpsc::unbounded_channel::<Ev>();
            let mut conn = Conn::for_command(
                filament_transport::TransportContext::default(),
                &url,
                sio.clone(),
                tx,
                "uid-host-test".to_string(),
                false, // not relay mode
                None,
                false,
                true, // direct requested, as `up --shell` does
                Arc::new(crate::host::NoLog),
                Arc::new(crate::host::NoHost),
            );
            assert!(conn.direct_ok);
            let pid = "browser-sid";
            conn.roster
                .insert(pid.to_string(), json!({ "id": pid, "direct": false }));
            conn.webrtc_only.insert(pid.to_string());
            conn.start_direct(pid, "web", "00").await;
            assert!(
                conn.direct_pending.is_empty(),
                "a browser peer armed the direct-QUIC ladder"
            );
            sio.disconnect().await.unwrap();
            let seen = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("fake signaling ended")
                .unwrap();
            assert!(
                !seen.iter().any(|t| t.contains("transport-offer")),
                "a browser peer was sent a transport-offer: {seen:?}"
            );
        });
    }
}

#[cfg(test)]
mod raw_label_tests {
    use super::label_is_raw_id;

    // `receive <code>` printed "ok <raw peer id>": names show, ids do not.
    #[test]
    fn ids_are_raw_and_names_are_not() {
        assert!(label_is_raw_id("Xy3_fAbcQ1", "Xy3_fAbcQ1", None));
        assert!(label_is_raw_id("u-123", "sid", Some("u-123")));
        assert!(label_is_raw_id("3f9c0a1be2d4c5f60718293a4b5c6d7e", "sid", None));
        assert!(!label_is_raw_id("alpha", "sid", None));
        assert!(!label_is_raw_id("p5-b", "sid", Some("uid")));
        // A session id that is not this link's key (the tester's "ok hNZONFIoto2k9bQ9ABGV").
        assert!(label_is_raw_id("hNZONFIoto2k9bQ9ABGV", "other-sid", None));
        // RC lab item 3: a session id with a single digit.
        assert!(label_is_raw_id("DrUEPIADYWGghg6rAAVO", "other-sid", None));
        // Names, including long mixed ones, stay names.
        assert!(!label_is_raw_id("WorkstationAlpha2", "sid", None));
        assert!(!label_is_raw_id("my-laptop-2024-home", "sid", None));
        assert!(!label_is_raw_id("buildbox-ci-runner-1", "sid", None));
        assert!(!label_is_raw_id("cafe", "sid", None)); // short hex is a name
    }
}

#[cfg(test)]
mod test_inline {
    use std::cell::Cell;

    thread_local! {
        static INLINE: Cell<bool> = const { Cell::new(true) };
    }

    pub fn enabled() -> bool {
        INLINE.with(Cell::get)
    }

    #[allow(dead_code)]
    pub fn set(on: bool) {
        INLINE.with(|flag| flag.set(on));
    }
}

#[cfg(test)]
mod tests {
    use crate::limits::MAX_ATTEMPTS;
    use crate::{AdoptSource, match_adoption_source};
    use std::collections::HashSet;

    #[test]
    fn exhausted_giveup_then_digest_does_not_recreate_link() {
        let mut suppressed = HashSet::new();
        let mut link_present = true;
        let mut attempts = MAX_ATTEMPTS;

        // Model the exhausted on_stuck transition: dropping the Link loses the
        // counter, so only the out-of-Link suppression mark carries the give-up.
        if attempts >= MAX_ATTEMPTS {
            link_present = false;
            attempts = 0;
            suppressed.insert("peer-sid".to_string());
        }
        assert!(!link_present);
        assert_eq!(attempts, 0);
        assert!(!match_adoption_source(
            &mut suppressed,
            "peer-sid",
            AdoptSource::Digest
        ));

        // A real contact is evidence the peer is reachable and clears only the
        // digest suppression, allowing the next adoption.
        assert!(match_adoption_source(
            &mut suppressed,
            "peer-sid",
            AdoptSource::Contact
        ));
        assert!(!suppressed.contains("peer-sid"));
        assert!(match_adoption_source(
            &mut suppressed,
            "peer-sid",
            AdoptSource::Digest
        ));
    }
}

/// Warm-hold identity, live-link replacement, the non-blocking retry ladder
/// and roster pruning: the defects behind the ~95s re-dial cycle and the
/// frozen event loop. Everything here runs without a network; `Conn` is built
/// on a loopback signaling client.
#[cfg(test)]
mod warm_identity_tests;

#[cfg(test)]
mod departure_tests {
    use super::departure_is_news;

    #[test]
    fn a_stale_duplicate_of_a_linked_peer_is_not_a_departure() {
        assert!(!departure_is_news("alpha", ["alpha", "bravo"]), "alpha is still linked");
        assert!(departure_is_news("alpha", ["bravo"]));
        assert!(departure_is_news("alpha", std::iter::empty::<&str>()));
        assert!(departure_is_news("", ["", "alpha"]), "an unnamed link is always reported");
    }
}

#[cfg(test)]
mod ice_fallback_tests {
    use super::*;

    // B08 on production signaling: a `join` whose first establish found the
    // config API slow exited 1 with "ICE config: no answer within 3s". A slow
    // API now falls back to STUN, which still finds a direct path.
    #[test]
    fn a_slow_config_api_falls_back_to_stun_unless_relay_is_forced() {
        assert!(ice_fallback_allowed(false));
        assert!(!ice_fallback_allowed(true), "a forced relay needs TURN and must say so");
        let cfg = stun_only_ice_config();
        assert_eq!(cfg.ice_servers.len(), 1);
        assert!(cfg.ice_servers.iter().all(net::is_stun_only), "the fallback must never claim a relay");
        assert!(cfg.chunk_size > 0 && cfg.chunk_size <= 64 * 1024);
    }
}
