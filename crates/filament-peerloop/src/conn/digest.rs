use super::Conn;
use crate::host::Tone;
use crate::sim_rt::{SimHashMap, SimHashSet};
use filament_transport::clock::Instant;
use filament_transport::net::Ev;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// A link absent from a channel/room digest is retired only after its transport
/// has been quiet this long. Presence is best-effort and a signaling reconnect
/// gives the peer a new sid, so the old sid vanishes from the digest while its
/// data channel is still the one carrying a shell. The grace is for the
/// transport shapes where "quiet" can still mean a peer that is there (a relay
/// path between keepalives) or where no transport exists yet.
///
/// It is NOT the bound for a DIRECT link. Direct QUIC has no `heard_ms` and its
/// `idle_ms` includes our own writes, but `is_alive`/`is_dead` are the
/// transport's own verdict (7 s keepalive, 21 s idle timeout). An idle shell is
/// a healthy direct link, so it is kept for as long as the connection is alive;
/// the grace must not retire it 30 s after a signaling reconnect. When QUIC
/// reports the connection dead/closed, retirement is immediate. That path is
/// transport-bounded, not grace-bounded.
///
/// `Conn::digest_link_active` is the decision: direct -> transport liveness;
/// relay/DataChannel -> peer-originated `heard_ms`; anything else -> idle.
pub(super) const DIGEST_ABSENT_IDLE_GRACE: Duration = Duration::from_secs(30);

/// "Moving enough to call the peer present" for digest retirement, in ms, for a
/// relay/DataChannel transport that does not track peer-originated traffic.
/// Direct QUIC does NOT use this clock (its liveness is transport-bounded); see
/// `Conn::digest_link_active`.
pub(super) const DIGEST_ACTIVE_MS: u64 = 3_000;

/// Which signaling surface owns a link, and therefore which digest may judge
/// its absence. A channel-introduced link is room-independent: only
/// `channel_peers` speaks about it. A room-sourced link is the converse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DigestSurface {
    Channel,
    Room,
}

/// Digest reconciliation, deferred-departure tracking, and owner roster/grant
/// push bookkeeping owned by `Conn`.
#[derive(Default)]
pub struct DigestTracker {
    /// #28 (deferred drop): sids that got a peer-left while their data channel
    /// was still FLOWING. The signaling socket left the room, but the WebRTC
    /// link is independent and may be a cosmetic reconnect mid-transfer. We do
    /// NOT drop immediately (that kills a live transfer) and do NOT drop never
    /// (a hard-killed peer reads flowing for a beat and would strand the
    /// sender). Instead we stash the original peer-left payload here and
    /// re-check on every main-loop tick: once the link goes idle past the
    /// flowing threshold (or its channel is dead), we re-inject the stored
    /// peer-left so the normal handler runs verbatim, now dropping it. A live
    /// reconnect never goes idle (the transfer completes on it), so its entry
    /// is reaped harmlessly once done. Cleared in drop_link so a supersede of a
    /// deferred sid can't leave a stale blocker.
    pub(super) deferred_left: SimHashMap<String, Value>,
    /// Digest reconcile deferral: sid -> when its live transport was first seen
    /// absent from a digest while it could not yet be called departed. A
    /// signaling reconnect gives the peer a fresh sid, so the old sid disappears
    /// from `channel_peers` while its direct link still serves a shell; dropping
    /// it there is the PR512 tear-down. A live direct link is deferred for as
    /// long as QUIC says the connection is alive; a relay link while it still
    /// hears the peer, then for `DIGEST_ABSENT_IDLE_GRACE` after that stops.
    /// Cleared when the sid reappears, when the link is dropped, and on a fresh
    /// signaling sid. Not used by `on_peer_left`, which keeps its own payload
    /// (`deferred_left`) because a peer-left is a real roster departure.
    pub(super) digest_deferred: SimHashMap<String, Instant>,
    /// Per-surface digest hysteresis, kept with `digest_deferred` so a link is
    /// always judged by the digest that OWNS it. A channel-introduced link must
    /// never be ticked by the room surface (and vice versa): the other surface
    /// is legitimately missing it, and clearing its clock there turned the
    /// bounded deferral into an eternal one. Values are consecutive misses.
    pub(super) channel_digest_absent: SimHashMap<String, u8>,
    pub(super) room_digest_absent: SimHashMap<String, u8>,
    /// Roster sids absent from consecutive channel/room digests, for the
    /// two-tick hysteresis in `prune_roster_absent`.
    pub(super) roster_absent: SimHashMap<String, u8>,
    /// Peer IDs whose exhausted stall ladder deliberately gave up. Contact
    /// clears these; digest reconciliation skips them.
    pub(super) suppressed_digest_adoptions: SimHashSet<String>,
    /// Owner-only roster push bookkeeping: the (epoch, valid_until) last pushed
    /// and the live links it reached, so a re-push fires only on a membership
    /// change (new epoch), a validity refresh (new valid_until), or a new link.
    pub(super) roster_pushed: Option<(u64, u64, HashSet<String>)>,
    /// Owner-only: the `(epoch, valid_until)` of the fleet grant set last
    /// delivered on each link, so an unchanged set is not resent every tick.
    pub(super) fleet_grants_pushed: HashMap<String, (u64, u64)>,
}

impl DigestTracker {
    pub(super) fn clear_peer(&mut self, pid: &str) {
        self.deferred_left.remove(pid);
        self.digest_deferred.remove(pid);
        self.channel_digest_absent.remove(pid);
        self.room_digest_absent.remove(pid);
    }

    pub(super) fn clear_surfaces(&mut self) {
        self.digest_deferred.clear();
        self.channel_digest_absent.clear();
        self.room_digest_absent.clear();
    }

    pub(super) fn clear_surface_absent(&mut self, surface: DigestSurface, pid: &str) {
        match surface {
            DigestSurface::Channel => {
                self.channel_digest_absent.remove(pid);
            }
            DigestSurface::Room => {
                self.room_digest_absent.remove(pid);
            }
        }
    }

    pub(super) fn is_deferred_left(&self, pid: &str) -> bool {
        self.deferred_left.contains_key(pid)
    }
}

impl Conn {
    pub fn is_deferred_left(&self, pid: &str) -> bool {
        self.digest.is_deferred_left(pid)
    }

    pub fn clear_digest_absent(&mut self, surface: DigestSurface, pid: &str) {
        self.digest.clear_surface_absent(surface, pid);
    }

    /// Owner-only: mint the current roster and push it to every live link whose
    /// view is stale (membership changed = new epoch, validity refreshed = new
    /// valid_until, or a newly-established link). A push that fails is dropped
    /// silently here; the next tick re-tries because `roster_pushed` still holds
    /// the old mark, so a lost push is not a fact we swallow.
    pub async fn roster_maintenance(&mut self) {
        let Some(blob_json) = self.host.roster_snapshot_json() else {
            return;
        };
        let Ok(blob) = serde_json::from_str::<Value>(&blob_json) else {
            return;
        };
        let epoch = blob["epoch"].as_u64().unwrap_or(0);
        let until = blob["valid_until"].as_u64().unwrap_or(0);
        let live: HashSet<String> = self
            .links
            .iter()
            .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
            .map(|(pid, _)| pid.clone())
            .collect();
        let should_push = match &self.digest.roster_pushed {
            None => true,
            Some((e, u, pids)) => *e != epoch || *u != until || *pids != live,
        };
        if !should_push {
            return;
        }
        let mut msg = blob.clone();
        msg["type"] = json!("roster");
        let mut pushed_to: HashSet<String> = HashSet::new();
        let mut sends = tokio::task::JoinSet::new();
        for pid in &live {
            if let Some(t) = self.transport_of(pid) {
                let msg = msg.clone();
                let pid = pid.clone();
                sends.spawn(async move {
                    let sent = tokio::time::timeout(
                        Duration::from_millis(750),
                        t.send_control(&msg),
                    )
                    .await
                    .is_ok_and(|r| r.is_ok());
                    (pid, sent)
                });
            }
        }
        while let Some(result) = sends.join_next().await {
            if let Ok((pid, true)) = result {
                pushed_to.insert(pid);
            }
        }
        if pushed_to.len() != live.len() {
            // A failed push is a fact worth surfacing: a spoke that missed it
            // stays stale until the next successful push. Re-tried next tick.
            let missed = live.len() - pushed_to.len();
            self.log.say(&format!(
                "  {} roster push did not reach {missed} device(s); will retry",
                self.log.paint(Tone::Warn, self.log.glyph_warn())
            ));
        }
        self.digest.roster_pushed = Some((epoch, until, pushed_to));
    }

    /// Owner-only: deliver each live link's device the owner-signed grant set
    /// ABOUT THAT DEVICE, when it changed (new epoch or refreshed validity) or
    /// the link is new. Each device only ever receives its own set. A failed
    /// send is retried next tick because the mark is not advanced.
    pub async fn fleet_grants_maintenance(&mut self) {
        let targets: Vec<(String, [u8; 32])> = self
            .links
            .iter()
            .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
            .filter_map(|(pid, l)| {
                // The proven device key when identity has resolved; otherwise the
                // certificate on the record this PAIRED link was proven against
                // (a pair-secret MAC proves the link is that device). Only a
                // pair-secret link may use the fallback.
                let dev = l.identity_device_pub.or_else(|| {
                    let (name, _) = l.expected_secret.as_ref()?;
                    self.host.device_cert_for(name).map(|c| c.device_pub)
                })?;
                Some((pid.clone(), dev))
            })
            .collect();
        self.digest.fleet_grants_pushed.retain(|pid, _| self.links.contains_key(pid));
        let mut pending = Vec::new();
        for (pid, target) in targets {
            let Some(blob) = self
                .host
                .fleet_grants_snapshot_json(&target)
                .and_then(|j| serde_json::from_str::<Value>(&j).ok())
            else {
                continue;
            };
            let mark = (
                blob["epoch"].as_u64().unwrap_or(0),
                blob["valid_until"].as_u64().unwrap_or(0),
            );
            if self.digest.fleet_grants_pushed.get(&pid) == Some(&mark) {
                continue;
            }
            let mut msg = blob;
            msg["type"] = json!("fleet-grants");
            if let Some(t) = self.transport_of(&pid) {
                pending.push((pid, mark, t, msg));
            }
        }
        let mut sends = tokio::task::JoinSet::new();
        for (pid, mark, t, msg) in pending {
            sends.spawn(async move {
                let sent = tokio::time::timeout(
                    Duration::from_millis(750),
                    t.send_control(&msg),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                (pid, mark, sent)
            });
        }
        while let Some(result) = sends.join_next().await {
            if let Ok((pid, mark, true)) = result {
                self.digest.fleet_grants_pushed.insert(pid, mark);
            }
        }
    }

    /// Digest reconcile for the ROSTER (links have their own reapers): a sid
    /// absent from two consecutive digests, with no live link, is forgotten.
    /// A channel-introduced entry (it carries `channel`) is judged against the
    /// channel digest, anything else against the room digest. The backstop for
    /// a `known-peer-left` that never arrived. Returns the sids forgotten.
    pub fn prune_roster_absent(
        &mut self,
        channel_present: &HashSet<String>,
        room_present: &HashSet<String>,
    ) -> Vec<String> {
        let mut gone = Vec::new();
        let pids: Vec<String> = self.roster.keys().cloned().collect();
        for pid in pids {
            let via_channel = self.roster[&pid]["channel"].as_str().is_some();
            let present = if via_channel {
                channel_present.contains(&pid)
            } else {
                room_present.contains(&pid)
            };
            // Present, or reached over a link that carries traffic. An attempt
            // in flight is neither: a retry ladder that is mid-attempt at every
            // digest used to reset this count each time, so the entry of a
            // departed sid outlived it and warm-hold kept dialling it.
            if present || self.link_carries(&pid) {
                self.digest.roster_absent.remove(&pid);
                continue;
            }
            let count = self.digest.roster_absent.entry(pid.clone()).or_insert(0);
            *count += 1;
            if *count >= 2 {
                gone.push(pid);
            }
        }
        for pid in &gone {
            self.roster.remove(pid);
            self.webrtc_only.remove(pid);
            self.digest.roster_absent.remove(pid);
            self.log.debug(&format!("roster: forgot {pid} (absent from two digests)"));
        }
        let roster = &self.roster;
        self.digest.roster_absent.retain(|pid, _| roster.contains_key(pid));
        gone
    }

    /// #28: re-check every deferred peer-left. Called on every main-loop tick
    /// (idempotent, cheap). A deferred sid is discharged when it is no longer
    /// flowing, its data channel went idle past the threshold OR died
    /// (idle_ms == u64::MAX). We then re-inject the ORIGINAL peer-left payload
    /// (flagged force) so the normal Ev::PeerLeft handler runs verbatim, same
    /// loop-side flush/messaging/rejoin behaviour as a non-deferred leave, with
    /// the link now correctly dropped. A sid that vanished from `links` (e.g. a
    /// supersede dropped it; drop_link already cleared its entry, but belt-and-
    /// braces) is forgotten silently. A still-flowing sid is left to keep
    /// flowing, the reconnect case, where the transfer completes on the live
    /// channel and the all-done exit reaps it.
    pub fn reap_deferred(&mut self) {
        if self.digest.deferred_left.is_empty() {
            return;
        }
        let ready: Vec<(String, Value)> = self
            .digest
            .deferred_left
            .iter()
            .filter(|(sid, _)| !self.links.contains_key(*sid) || !self.link_flowing(sid))
            .map(|(sid, v)| (sid.clone(), v.clone()))
            .collect();
        for (sid, mut payload) in ready {
            self.digest.deferred_left.remove(&sid);
            if !self.links.contains_key(&sid) {
                continue; // link already gone (superseded); nothing to drop
            }
            // Force the drop this time (the channel is now idle/dead).
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("__fil_force_drop".into(), Value::Bool(true));
            }
            let name = self
                .link(&sid)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "peer".into());
            // DEBUG, resilience internal (deferred-leave reap).
            self.log.debug(&format!(
                "{name} link went idle after deferred leave, dropping now"
            ));
            // Re-inject so the loop's own peer-left branch handles partials,
            // messaging and the rejoin window exactly as a fresh leave would.
            let _ = self.tx.send(Ev::PeerLeft(payload));
        }
    }

    /// Digest reconcile decision for ONE link on the surface that owns it.
    ///
    /// The digest describes SIGNALING presence, but the data channel is
    /// independent. A signaling reconnect gives the peer a new sid, so the old
    /// sid legitimately drops out of `channel_peers` while the direct link is
    /// still the one carrying a shell. `on_peer_left` already defers that case
    /// (`deferred_left` + `reap_deferred`); digest reconcile did not, and tore
    /// those links down (PR512, `cli/src/recv_cmd.rs` reconcile loop).
    ///
    /// Hysteresis and deferral stay on `surface`: a link is offered to exactly
    /// one digest. Presence there (or a fresh signaling sid) clears both its
    /// miss count and its clock; absence counts two consecutive misses, then
    /// defers while the link is alive and active (see
    /// `digest_absent_retirable_at`). Returns true when the caller may retire
    /// the link now.
    pub fn digest_note(
        &mut self,
        pid: &str,
        surface: DigestSurface,
        present: bool,
        fresh: bool,
    ) -> bool {
        self.digest_note_at(pid, surface, present, fresh, Instant::now())
    }

    pub(super) fn digest_note_at(
        &mut self,
        pid: &str,
        surface: DigestSurface,
        present: bool,
        fresh: bool,
        now: Instant,
    ) -> bool {
        let candidate = {
            let counts = match surface {
                DigestSurface::Channel => &mut self.digest.channel_digest_absent,
                DigestSurface::Room => &mut self.digest.room_digest_absent,
            };
            if present || fresh {
                counts.remove(pid);
                false
            } else {
                let count = counts.entry(pid.to_string()).or_insert(0);
                *count += 1;
                *count >= 2
            }
        };
        if present || fresh {
            // Only the owning surface may clear this link's clock.
            self.digest.digest_deferred.remove(pid);
            return false;
        }
        candidate && self.digest_absent_retirable_at(pid, now)
    }

    /// May the caller retire a link that missed two digests? Dead/closed
    /// transport: yes, at once. A live DIRECT link: no, for as long as its QUIC
    /// connection is alive (an idle shell is not a departed peer; the transport
    /// idle/dead verdict is the bound). A live relay: no while it is still
    /// hearing the peer, then `DIGEST_ABSENT_IDLE_GRACE` from when that stopped.
    /// A transport-less/peer-only link still gets the bounded grace.
    ///
    /// `has_live_transport` deliberately counts an in-progress WebRTC peer
    /// (#246) even before a transport exists, so a dead primary beside a still
    /// live peer model gets this bounded grace rather than an immediate drop.
    /// That is a delay, not an exemption: the grace still runs.
    pub fn digest_absent_retirable(&mut self, pid: &str) -> bool {
        self.digest_absent_retirable_at(pid, Instant::now())
    }

    pub(super) fn digest_absent_retirable_at(&mut self, pid: &str, now: Instant) -> bool {
        if !self.has_live_transport(pid) {
            self.digest.digest_deferred.remove(pid);
            return true;
        }
        // A direct link whose QUIC connection has closed is gone NOW, even if
        // the transport's `dead` flag has not latched yet. `has_live_transport`
        // asks the weaker `!is_dead()`; for a direct primary it is the stricter
        // `is_alive()` that says whether the shell can still be served. Without
        // this, a closed-but-not-yet-dead QUIC link would sit out the 30 s grace.
        if self.links.get(pid).is_some_and(|l| {
            l.direct && l.transport.as_ref().is_some_and(|t| !t.is_alive())
        }) {
            self.digest.digest_deferred.remove(pid);
            return true;
        }
        if self.digest_link_active(pid) {
            // A live transport outranks a missing presence entry. Refresh the
            // clock so the grace starts if/when the link really goes quiet.
            self.digest.digest_deferred.insert(pid.to_string(), now);
            return false;
        }
        let first = *self.digest.digest_deferred.entry(pid.to_string()).or_insert(now);
        if now.saturating_duration_since(first) >= DIGEST_ABSENT_IDLE_GRACE {
            self.digest.digest_deferred.remove(pid);
            return true;
        }
        false
    }

    /// Is the PEER demonstrably active on this link right now?
    ///
    /// Three transport shapes, deliberately:
    ///
    /// * **Direct QUIC** has no peer-originated `heard_ms`. Its `idle_ms` is
    ///   stamped by our own writes too, so a quiet shell and a busy transfer are
    ///   indistinguishable by bytes. Use the transport's own liveness instead:
    ///   `is_alive()` (and not `is_dead()`) is the QUIC 7 s keepalive / 21 s
    ///   idle verdict. An alive link is kept for as long as it is alive; a
    ///   closed/dead one retires at once (see `digest_absent_retirable_at`).
    /// * **Relay/DataChannel** keepalives are OUR writes and stamp `idle_ms`, so
    ///   a link to a wiped or SIGSTOPped peer can read busy forever. Its
    ///   `heard_ms` is peer-only; the shared `link_manager::relay_peer_live`
    ///   rule bounds it, and silence still reaches the grace and retires.
    /// * **Untracked** transports fall back to idle for compatibility.
    ///
    /// This is intentionally not `link_flowing` (which backs supersede/peer-left
    /// and must keep its byte-movement meaning).
    pub(super) fn digest_link_active(&self, pid: &str) -> bool {
        let Some(l) = self.links.get(pid) else {
            return false;
        };
        let Some(t) = l.transport.as_ref() else {
            return false;
        };
        if t.is_dead() || !t.is_alive() {
            return false;
        }
        if l.direct {
            // Transport-bounded: no 30 s idle cutoff for a live direct link.
            return true;
        }
        if let Some(peer_live) = crate::link_manager::relay_peer_live(t.heard_ms()) {
            return peer_live;
        }
        t.idle_ms() < DIGEST_ACTIVE_MS
    }

    /// The sid is present again in a digest: nothing is deferred for it. The
    /// next absence starts a fresh grace window.
    pub fn digest_present(&mut self, pid: &str) {
        self.digest.digest_deferred.remove(pid);
    }

    /// A fresh signaling sid invalidates the previous digest window. The peer is
    /// re-subscribing on its own new sid at the same time, so an absence window
    /// that started before the reconnect (or the first digest after it) must not
    /// carry over and retire a link that never stopped flowing.
    pub fn reset_digest_reconcile(&mut self) {
        self.digest.clear_surfaces();
    }

    /// #28 exit reconciliation: true when every remaining link is one we're only
    /// holding open for its deferred-drop reap (vacuously true with no links). A
    /// link in `deferred_left` is a peer whose signaling already left; once all
    /// transfers are complete it protects nothing, so it must not delay exit by
    /// the full deferral window.
    ///
    /// `digest_deferred` is deliberately NOT counted here. Unlike a peer-left,
    /// a digest miss can be a presence gap while the peer is still active on the
    /// data channel; a one-shot receiver that already completed a file must not
    /// exit out from under a sender that may offer another. The bounded grace
    /// and the normal quiet/Mode-B exits retire it.
    pub fn only_deferred_links(&self) -> bool {
        self.links
            .keys()
            .all(|k| self.digest.deferred_left.contains_key(k))
    }
}
