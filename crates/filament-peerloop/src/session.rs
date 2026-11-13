//! C30: the convergent session, the CLI's half of "no emit is ever
//! load-bearing; only convergence is" (docs/design-c30-convergent-session.md).
//!
//! Each command loop owns a `Session` describing the DESIRED signaling state
//! (room, identity, presence channels) and calls `tick()` every loop
//! iteration (the loops already tick every ≤2 s). The session re-emits one
//! idempotent `sync` whenever the server's last-confirmed digest disagrees
//! with desire or has gone stale, so a join or subscribe that died in a
//! half-open socket is repaired within a tick instead of becoming a roomless
//! ghost / invisible device / zombie lease (the C24/C28/#14 disease class).
//!
//! The loss shim lives here on purpose: ALL session-state emits flow through
//! `lossy_emit`, so gate L (`TUNLION_TEST_EMIT_LOSS` + `_SEED`) adversarially
//! drops them and the suite proves convergence survives.

use filament_signal::Client;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// At most one sync per this interval unless desire changed.
const SYNC_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// A confirmed digest older than this is re-asserted even if unchanged.
const CONFIRM_TTL: Duration = Duration::from_secs(30);
/// Re-sync cadence while the server keeps truncating an UNCHANGED desire.
/// The cap is deterministic, so a fast retry cannot fix it and every `sync`
/// re-emits `known-peer` to every channel peer; retrying no faster than a
/// healthy session re-asserts (CONFIRM_TTL) adds no load over the normal
/// state. A changed desire, `touch()` or a fresh sid still syncs at once.
const TRUNCATED_RESYNC_INTERVAL: Duration = CONFIRM_TTL;

/// The signaling server accepts at most this many channels in one `subscribe`
/// or `sync` and silently drops the rest (`MAX_CHANNELS` in
/// backend/signaling.py and edge/signal/src/policy.ts). Whatever must never be
/// dropped has to sit inside this prefix of the list we send.
pub const SIGNALING_MAX_CHANNELS: usize = 64;

/// The ONE place a subscription list is ordered: the enrollment channel, then
/// the fleet channel, then every device channel, de-duplicated (first
/// occurrence wins, device order otherwise preserved).
///
/// The order is load-bearing. The server keeps only the first
/// [`SIGNALING_MAX_CHANNELS`] entries, so an owner with 64+ paired devices
/// that listed devices first lost the enrollment and fleet channels on every
/// new socket: no new device could enroll and the request simply timed out.
/// The two shared meeting points go first; a truncated tail can then only
/// cost device channels.
pub fn subscription_order(
    enroll: Option<String>,
    fleet: Option<String>,
    devices: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    enroll
        .into_iter()
        .chain(fleet)
        .chain(devices)
        .filter(|c| seen.insert(c.clone()))
        .collect()
}

pub struct Session {
    pub room: Option<String>,
    pub enroll_room: Option<String>,
    pub name: String,
    pub uid: String,
    pub channels: Vec<String>,
    /// digest of the last server-confirmed state + when
    confirmed: Option<(String, Instant)>,
    last_attempt: Option<Instant>,
    /// The channels the last cadence `sync` put on the wire, in wire order:
    /// what the ack's accepted count is checked against.
    last_sent: Option<Vec<String>>,
    /// Set while the server's last ack accepted fewer channels than we sent.
    truncated: Option<ChannelTruncation>,
    /// A loud line for the host to log, set when a truncation is first seen
    /// or its numbers change (see [`Session::take_channel_warning`]).
    channel_warning: Option<String>,
    rng: u64, // loss-shim PRNG state (deterministic under _SEED)
    loss: f64,
}

/// The server accepted fewer channels than a `sync` sent: its
/// [`SIGNALING_MAX_CHANNELS`] cap cut the tail of the list, so those channels
/// are not registered on this socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelTruncation {
    /// The `channels` count in the server's ack.
    pub accepted: usize,
    /// How many server-valid channels we sent.
    pub sent: usize,
    /// The valid channels we sent past the cap, which the server cannot have
    /// kept (empty when the shortfall has another cause).
    pub dropped: Vec<String>,
    /// The digest of the desire that was sent and cut: an unchanged desire re-syncs on
    /// the slow [`TRUNCATED_RESYNC_INTERVAL`] cadence, a changed one at once.
    digest: String,
}

impl ChannelTruncation {
    /// The line the host logs at critical level.
    pub fn warning(&self) -> String {
        const SHOWN: usize = 8;
        let mut named: Vec<String> = self
            .dropped
            .iter()
            .take(SHOWN)
            .map(|c| c.chars().take(12).collect::<String>())
            .collect();
        if self.dropped.len() > SHOWN {
            named.push(format!("+{} more", self.dropped.len() - SHOWN));
        }
        let dropped = if named.is_empty() {
            String::new()
        } else {
            format!(" (dropped: {})", named.join(", "))
        };
        format!(
            "signaling accepted {} of {} channels: the server's {}-channel cap truncated the \
             subscription{}; enrollment/fleet channels may be unregistered, re-syncing every {}s",
            self.accepted,
            self.sent,
            SIGNALING_MAX_CHANNELS,
            dropped,
            TRUNCATED_RESYNC_INTERVAL.as_secs(),
        )
    }
}

/// The shape the server accepts (`CHAN_RE`, 64 lowercase hex). It counts only
/// these, so only these are counted as sent.
fn is_server_channel(c: &str) -> bool {
    c.len() == 64 && c.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The server's confirmed view of both discovery surfaces. Room membership and
/// channel subscriptions have different lifetimes, so callers must reconcile
/// them independently.
#[derive(Debug, Default, Clone)]
pub struct SyncedRoster {
    pub peers: Vec<Value>,
    pub channel_peers: Vec<Value>,
}

/// gate L (`TUNLION_TEST_EMIT_LOSS` + `_SEED`): the loss-shim parameters. These
/// are env-gated test injectors compiled in ONLY under `--features test-hooks`.
/// The `not` twin returns the production no-loss defaults (loss 0.0, fixed seed),
/// so the shipped binary never reads the env and `emit` never drops.
#[cfg(feature = "test-hooks")]
fn emit_loss_params() -> (f64, u64) {
    let loss = std::env::var("TUNLION_TEST_EMIT_LOSS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|l| (0.0..1.0).contains(l))
        .unwrap_or(0.0);
    let seed = std::env::var("TUNLION_TEST_EMIT_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0xF11A_C30D);
    (loss, seed)
}

#[cfg(not(feature = "test-hooks"))]
#[inline]
fn emit_loss_params() -> (f64, u64) {
    (0.0, 0xF11A_C30D)
}

impl Session {
    pub fn new(name: &str, uid: &str) -> Self {
        let (loss, seed) = emit_loss_params();
        Session {
            room: None,
            enroll_room: None,
            name: name.to_string(),
            uid: uid.to_string(),
            channels: Vec::new(),
            confirmed: None,
            last_attempt: None,
            last_sent: None,
            truncated: None,
            channel_warning: None,
            rng: seed | 1,
            loss,
        }
    }

    /// The full-desire `sync` payload. Shared by the cadence tick AND the
    /// silence-watchdog heartbeat so the two stay byte-identical. `room` may be
    /// None for a channel-only acceptor (`up`): the server answers that with an
    /// `{ok:false}` ack (still proof the socket is alive), it just emits no
    /// `synced` event.
    pub fn sync_payload(&self) -> Value {
        let mut p = json!({
            "v": 1,
            "room": self.room,
            "name": self.name,
            "uid": self.uid,
            "channels": self.channels,
        });
        if let Some(ref er) = self.enroll_room {
            p["enroll_room"] = json!(er);
        }
        p
    }

    /// A liveness-only `sync` for the silence-watchdog heartbeat. `room` is
    /// intentionally null so the server takes its no-op early-return path: it
    /// still ACKs (proving the socket is alive, which is all the watchdog needs)
    /// but does NOT run channel subscription, so it emits NO `known-peer`. A
    /// full `sync_payload()` heartbeat would re-`_do_subscribe` every cycle and
    /// re-emit `known-peer` to every channel peer, a ~15 s presence-churn storm
    /// ("known device X appeared, connecting" on both ends). Channel/room state
    /// is owned by the cadence `tick()`, not the heartbeat.
    pub fn heartbeat_payload(&self) -> Value {
        json!({ "v": 1, "room": Value::Null, "name": self.name, "uid": self.uid })
    }

    /// What we want the server to hold for us, as a comparable string.
    fn desired_digest(&self) -> String {
        self.digest_with(&self.channels)
    }

    /// The digest our desire would have with `channels` as its channel set.
    fn digest_with(&self, channels: &[String]) -> String {
        let mut chans = channels.to_vec();
        chans.sort();
        format!("{}|{}|{}", self.room.as_deref().unwrap_or(""), self.enroll_room.as_deref().unwrap_or(""), chans.join(","))
    }

    /// The server confirmed our state (Ev::Synced), record its digest.
    /// The digest we store is OUR desire at confirm time: the server applies
    /// what we sent, so a later desire change diffs against it correctly.
    /// Phase 2: the digest may carry the server's roster (`peers`), the
    /// loops reconcile against it (missed peer-joined/left self-correct).
    /// Adoption is intent-agnostic: local intent is private, while the confirmed
    /// roster is authoritative shared state. Reconcile to the roster even after
    /// a deliberate local drop, then let the lifecycle policy decide reaping.
    /// The returned rosters are the RECOVERY CHANNEL for every class-S push
    /// (`welcome`, `peer-joined`, `peer-left`, `known-peer`, `known-peer-left`):
    /// a consumer that misses one re-derives it here. `#[must_use]` because call sites silently
    /// discarded it with a bare `sess.on_synced(&v);`, which is how a sender
    /// that missed a `peer-joined` waited out its full claim deadline while
    /// the peer could see it. Discarding must now be deliberate and explained,
    /// never accidental.
    #[must_use = "the digest rosters recover missed room and channel presence pushes; \
                  reconcile them, or explain why this command cannot miss one"]
    pub fn on_synced(&mut self, v: &Value) -> Option<SyncedRoster> {
        if v["ok"].as_bool() != Some(true) {
            return None; // error digests carry no roster (server contract)
        }
        let roster = SyncedRoster {
            peers: v["peers"].as_array().cloned().unwrap_or_default(),
            channel_peers: v["channel_peers"].as_array().cloned().unwrap_or_default(),
        };
        // The server silently keeps only the first SIGNALING_MAX_CHANNELS of
        // the list and reports how many it accepted. Fewer than we sent means
        // part of the desired set is NOT registered: never record that as
        // confirmed. The roster is still the server's truth for what it did
        // register, so it is returned either way. An ack without the count
        // (an older server) cannot be checked and confirms as before.
        if let Some(accepted) = v["channels"].as_u64() {
            let accepted = usize::try_from(accepted).unwrap_or(usize::MAX);
            let sent_list: &[String] = self.last_sent.as_deref().unwrap_or(&self.channels);
            let sent = sent_list.iter().filter(|c| is_server_channel(c)).count();
            if accepted < sent {
                let dropped: Vec<String> = sent_list
                    .iter()
                    .skip(SIGNALING_MAX_CHANNELS)
                    .filter(|c| is_server_channel(c))
                    .cloned()
                    .collect();
                let changed = match &self.truncated {
                    Some(t) => t.accepted != accepted || t.sent != sent,
                    None => true,
                };
                let t = ChannelTruncation {
                    accepted,
                    sent,
                    dropped,
                    // What was SENT and cut: if desire has moved on since,
                    // the slow cadence does not apply to the new set.
                    digest: self.digest_with(sent_list),
                };
                if changed {
                    self.channel_warning = Some(t.warning());
                }
                self.truncated = Some(t);
                self.confirmed = None;
                return Some(roster);
            }
        }
        self.truncated = None;
        self.confirmed = Some((self.desired_digest(), Instant::now()));
        Some(roster)
    }

    /// The loud line for a channel truncation the last ack revealed, once per
    /// distinct truncation (a repeat of the same numbers is not re-announced).
    /// Hosts log it at critical level right after [`Session::on_synced`].
    pub fn take_channel_warning(&mut self) -> Option<String> {
        self.channel_warning.take()
    }

    /// The truncation the server's last ack reported, if it is still current.
    pub fn channel_truncation(&self) -> Option<&ChannelTruncation> {
        self.truncated.as_ref()
    }

    /// Add a priority channel (the enrollment or fleet meeting point) at the
    /// FRONT of the desired set, moving it there if it is already present
    /// further back. Appending would put it past the server's
    /// [`SIGNALING_MAX_CHANNELS`] cap on a large fleet; see
    /// [`subscription_order`].
    pub fn prioritize_channel(&mut self, ch: String) {
        if let Some(i) = self.channels.iter().position(|c| *c == ch) {
            self.channels.remove(i);
        }
        self.channels.insert(0, ch);
    }

    /// Any local change to desire invalidates confirmation timing so the next
    /// tick syncs immediately.
    pub fn touch(&mut self) {
        self.last_attempt = None;
    }

    /// A fresh sid (welcome after reconnect) voids everything the server held
    /// for the old one, even if desire is unchanged, it must be re-asserted.
    /// (Without this, a fast reconnect inside CONFIRM_TTL looks "confirmed"
    /// while the new sid is roomless and unsubscribed, the browser track hit
    /// the identical hole.)
    pub fn invalidate(&mut self) {
        self.confirmed = None;
        self.last_attempt = None;
    }

    /// xorshift64*, deterministic, no rand crate; gate L replays by seed.
    fn roll(&mut self) -> f64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// All session-state emits go through here so the loss shim covers them,
    /// including the commands' INITIAL join/subscribe fast-path emits (public
    /// for that reason). Under gate L the shim drops a deterministic fraction;
    /// the tick loop is what must repair the damage.
    pub async fn emit(&mut self, sio: &Client, event: &str, payload: Value) {
        if self.loss > 0.0 && self.roll() < self.loss {
            return; // gate L: this emit "died in a half-open socket"
        }
        let _ = sio.emit(event, payload).await;
    }

    /// A code typed into a listening session is being claimed: stop asserting
    /// the listening room until the server names the room to join
    /// (`pair-matched`) or refuses the claim. Returns the room to hand back to
    /// [`Session::resume_room`] if the claim fails.
    ///
    /// While the claim is in flight the next cadence `sync` would still name
    /// the listening room. The server does not handle one socket's events in a
    /// guaranteed order, so a `sync` sent just before `pair-matched` arrived
    /// could be handled AFTER the `join` of the matched room and move the
    /// claimer back out. Its `synced` ack then confirms the NEW desire, so the
    /// claimer believes it is in the right room while the sender sees it leave,
    /// until the next 30 s re-assertion. This is the same race #599 fixed for
    /// the `join` claimer: assert no room you are about to leave.
    pub fn release_room_for_claim(&mut self) -> Option<String> {
        self.touch();
        self.room.take()
    }

    /// The claim failed (or the socket was replaced under it): assert the
    /// listening room again, immediately. A `pair-matched` that already set a
    /// new room wins; this never overwrites it.
    pub fn resume_room(&mut self, room: Option<String>) {
        if self.room.is_none() && room.is_some() {
            self.room = room;
            self.touch();
        }
    }

    /// Whether the next `tick` puts a `sync` on the wire. A session with no
    /// desired room sends nothing.
    fn sync_due(&self, now: Instant) -> bool {
        if self.room.is_none() {
            return false;
        }
        match (&self.confirmed, &self.last_attempt) {
            // never confirmed: retry on the attempt cadence
            // A truncated ack also leaves us unconfirmed; while desire is
            // unchanged it retries on the slow cadence, never in a loop.
            (None, Some(at)) => now.duration_since(*at) >= self.unconfirmed_retry_interval(),
            (None, None) => true,
            (Some((digest, at)), _) => {
                let stale = now.duration_since(*at) >= CONFIRM_TTL;
                let diverged = *digest != self.desired_digest();
                (stale || diverged)
                    && self
                        .last_attempt
                        .map(|a| now.duration_since(a) >= SYNC_MIN_INTERVAL)
                        .unwrap_or(true)
            }
        }
    }

    /// How long an unconfirmed session waits between `sync` attempts: the
    /// slow truncation cadence while the server keeps cutting the SAME
    /// desire, the normal attempt cadence otherwise.
    fn unconfirmed_retry_interval(&self) -> Duration {
        match &self.truncated {
            Some(t) if t.digest == self.desired_digest() => TRUNCATED_RESYNC_INTERVAL,
            _ => SYNC_MIN_INTERVAL,
        }
    }

    /// Called every loop iteration; cheap no-op most ticks.
    pub async fn tick(&mut self, sio: &Client) {
        let now = Instant::now();
        if !self.sync_due(now) {
            return;
        }
        self.last_attempt = Some(now);
        self.last_sent = Some(self.channels.clone());
        self.emit(sio, "sync", self.sync_payload()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_orders_channels() {
        let mut s = Session::new("n", "u");
        s.room = Some("r".into());
        s.channels = vec!["b".into(), "a".into()];
        let d1 = s.desired_digest();
        s.channels = vec!["a".into(), "b".into()];
        assert_eq!(d1, s.desired_digest());
    }

    #[test]
    fn loss_shim_deterministic() {
        // (no env manipulation, edition 2024 makes set/remove_var unsafe;
        // the default seed path is what's under test)
        let mut a = Session::new("n", "u");
        let mut b = Session::new("n", "u");
        let ra: Vec<u64> = (0..8).map(|_| (a.roll() * 1e9) as u64).collect();
        let rb: Vec<u64> = (0..8).map(|_| (b.roll() * 1e9) as u64).collect();
        assert_eq!(ra, rb, "same seed must replay the same drop pattern");
    }

    /// A typed claim releases the listening room: while it is in flight no
    /// cadence `sync` can name the room the claimer is about to leave, even
    /// when that room's confirmation is stale and would otherwise be
    /// re-asserted. A refused claim brings the room back at once; a
    /// `pair-matched` room set in the meantime is never overwritten.
    #[test]
    fn a_claim_in_flight_asserts_no_room() {
        let mut s = Session::new("n", "u");
        s.room = Some("listen".into());
        assert!(s.sync_due(Instant::now()), "a fresh desire syncs");
        // Confirmed long ago: the TTL re-assertion is due.
        s.confirmed = Some((s.desired_digest(), Instant::now() - CONFIRM_TTL * 2));
        s.last_attempt = Some(Instant::now() - SYNC_MIN_INTERVAL * 2);
        assert!(s.sync_due(Instant::now()), "a stale confirmation is re-asserted");

        let held = s.release_room_for_claim();
        assert_eq!(held.as_deref(), Some("listen"));
        assert!(!s.sync_due(Instant::now()), "no sync may name the room while a claim is in flight");
        assert_eq!(s.sync_payload()["room"], Value::Null);

        // Refused: the listening room comes back and is asserted immediately.
        s.resume_room(held.clone());
        assert_eq!(s.room.as_deref(), Some("listen"));
        assert!(s.sync_due(Instant::now()));

        // Matched: pair-matched set the new room first; a late resume is a no-op.
        let held = s.release_room_for_claim();
        s.room = Some("matched".into());
        s.resume_room(held);
        assert_eq!(s.room.as_deref(), Some("matched"));
    }

    fn chan(i: u64) -> String {
        format!("{i:064x}")
    }

    /// The production incident: 65 paired devices pushed the enrollment and
    /// fleet channels past the server's 64-channel cap on every new socket.
    /// The meeting points must lead the list, and nothing may be lost.
    #[test]
    fn enroll_and_fleet_lead_a_list_longer_than_the_server_cap() {
        let devices: Vec<String> = (0..70).map(chan).collect();
        let enroll = chan(1_000);
        let fleet = chan(2_000);
        // Duplicates (a device listed twice, the fleet channel also among the
        // devices) collapse to their first occurrence.
        let mut input = devices.clone();
        input.push(devices[3].clone());
        input.push(fleet.clone());
        let c = subscription_order(Some(enroll.clone()), Some(fleet.clone()), input);

        assert!(c.len() > SIGNALING_MAX_CHANNELS);
        assert_eq!(c[0], enroll, "enrollment channel first");
        assert_eq!(c[1], fleet, "fleet channel second");
        let kept = &c[..SIGNALING_MAX_CHANNELS];
        assert!(kept.contains(&enroll) && kept.contains(&fleet));
        // Nothing lost, nothing duplicated, device order preserved.
        assert_eq!(c.len(), devices.len() + 2);
        assert_eq!(&c[2..], &devices[..]);
        let unique: std::collections::HashSet<&String> = c.iter().collect();
        assert_eq!(unique.len(), c.len());

        // Absent meeting points simply drop out of the prefix.
        let only_devices = subscription_order(None, None, devices.clone());
        assert_eq!(only_devices, devices);
        let fleet_only = subscription_order(None, Some(fleet.clone()), devices.clone());
        assert_eq!(fleet_only[0], fleet);
        assert_eq!(&fleet_only[1..], &devices[..]);
    }

    /// The daemon's arm-gate adds the enrollment channel to a LIVE list long
    /// after startup; it must land inside the cap, not after 70 devices.
    #[test]
    fn a_prioritized_channel_goes_to_the_front_once() {
        let mut s = Session::new("n", "u");
        let fleet = chan(2_000);
        let enroll = chan(1_000);
        s.channels = subscription_order(None, Some(fleet.clone()), (0..70).map(chan));
        s.prioritize_channel(enroll.clone());
        assert_eq!(s.channels[0], enroll);
        assert_eq!(s.channels[1], fleet);
        assert_eq!(s.channels.len(), 72);
        // Re-adding never duplicates; a channel found further back moves up.
        s.prioritize_channel(enroll.clone());
        assert_eq!(s.channels.len(), 72);
        s.channels.push(chan(3_000));
        s.prioritize_channel(chan(3_000));
        assert_eq!(s.channels[0], chan(3_000));
        assert_eq!(s.channels.len(), 73);
        assert!(s.channels[..SIGNALING_MAX_CHANNELS].contains(&enroll));
    }

    fn ack(accepted: usize) -> Value {
        json!({ "v": 1, "ok": true, "channels": accepted, "peers": [], "channel_peers": [] })
    }

    /// The server's cap cut the list: the ack says it accepted fewer channels
    /// than we sent. The set must stay unconfirmed (so it is re-synced), the
    /// host must get one loud line naming both numbers and the dropped tail,
    /// and the retry must run on the slow cadence, never in a loop.
    #[test]
    fn a_truncated_sync_ack_is_not_confirmation() {
        let mut s = Session::new("n", "u");
        s.room = Some("r".into());
        s.channels = (0..70).map(chan).collect();
        let t0 = Instant::now();
        // As `tick` records it when the sync goes on the wire.
        s.last_attempt = Some(t0);
        s.last_sent = Some(s.channels.clone());

        let roster = s.on_synced(&ack(64));
        assert!(roster.is_some(), "the roster of what WAS registered is still returned");
        assert!(s.confirmed.is_none(), "a truncated set is never confirmed");
        let t = s.channel_truncation().expect("truncation recorded");
        assert_eq!((t.accepted, t.sent), (64, 70));
        assert_eq!(t.dropped, (64..70).map(chan).collect::<Vec<_>>());

        let w = s.take_channel_warning().expect("a loud line for the host");
        assert!(w.contains("accepted 64 of 70 channels"), "{w}");
        assert!(w.contains("enrollment/fleet channels may be unregistered"), "{w}");
        assert!(w.contains(&chan(64)[..12]), "names the dropped channels: {w}");
        assert!(s.take_channel_warning().is_none(), "taken once");

        // No retry storm: an unchanged desire waits the slow cadence, not
        // SYNC_MIN_INTERVAL, and the same truncation is not re-announced.
        assert!(!s.sync_due(t0 + SYNC_MIN_INTERVAL * 2));
        assert!(s.sync_due(t0 + TRUNCATED_RESYNC_INTERVAL));
        let _ = s.on_synced(&ack(64));
        assert!(s.confirmed.is_none());
        assert!(s.take_channel_warning().is_none(), "same numbers, no repeat line");

        // A changed desire is worth trying at the normal cadence.
        s.channels.truncate(SIGNALING_MAX_CHANNELS);
        assert!(s.sync_due(t0 + SYNC_MIN_INTERVAL));

        // A full acceptance confirms and clears the truncation.
        s.last_sent = Some(s.channels.clone());
        let _ = s.on_synced(&ack(64));
        assert!(s.confirmed.is_some());
        assert!(s.channel_truncation().is_none());
        assert!(s.take_channel_warning().is_none());
    }

    /// Without a recorded send (the ack raced the first tick) the check falls
    /// back to the current desire.
    #[test]
    fn a_truncated_ack_is_caught_without_a_recorded_send() {
        let mut s = Session::new("n", "u");
        s.room = Some("r".into());
        s.channels = (0..66).map(chan).collect();
        let _ = s.on_synced(&ack(64));
        assert!(s.confirmed.is_none());
        assert!(s.take_channel_warning().unwrap().contains("accepted 64 of 66"));
    }

    /// accepted == sent confirms exactly as before; so does an ack from a
    /// server that reports no count, and channels the server would reject by
    /// shape are not counted as sent.
    #[test]
    fn a_complete_sync_ack_confirms_as_before() {
        let mut s = Session::new("n", "u");
        s.room = Some("r".into());
        s.channels = (0..3).map(chan).collect();
        s.last_sent = Some(s.channels.clone());
        let _ = s.on_synced(&ack(3));
        assert!(s.confirmed.is_some());
        assert!(s.channel_truncation().is_none());
        assert!(s.take_channel_warning().is_none());

        let mut old = Session::new("n", "u");
        old.room = Some("r".into());
        old.channels = (0..3).map(chan).collect();
        let _ = old.on_synced(&json!({ "ok": true }));
        assert!(old.confirmed.is_some(), "no count in the ack: unchanged behavior");

        let mut odd = Session::new("n", "u");
        odd.room = Some("r".into());
        odd.channels = vec!["not-a-channel".into(), chan(1)];
        let _ = odd.on_synced(&ack(1));
        assert!(odd.confirmed.is_some(), "only server-valid channels count as sent");
    }

    #[test]
    fn synced_returns_room_and_channel_rosters() {
        let mut s = Session::new("n", "u");
        let digest = json!({
            "ok": true,
            "peers": [{"id": "room-peer"}],
            "channel_peers": [{"id": "channel-peer", "channel": "c"}],
        });
        let roster = s.on_synced(&digest).expect("successful digest has rosters");
        assert_eq!(roster.peers[0]["id"], "room-peer");
        assert_eq!(roster.channel_peers[0]["id"], "channel-peer");
    }
}
