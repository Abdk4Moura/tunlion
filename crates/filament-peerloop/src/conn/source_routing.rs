use super::{Conn, MAX_BUILD_EVENTS, MAX_BUILD_EVENT_BYTES, MAX_PENDING_BUILDS};
use crate::sim_rt::SimHashMap;
use filament_transport::clock::Instant;
use filament_transport::net::{self, Ev, Transport};
use serde_json::Value;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// A link cut by a revocation whose refusal is still in flight, keyed in
/// `SourceRouting::closing` by the refusal's nonce. Control-plane only: the
/// link is gone from `links`, so no Control/PcState/ChannelReady from its
/// source is dispatched, and this entry only recognizes the peer's
/// `link-revoked-ack` carrying exactly this nonce, read for this pid on any of
/// its paths. The nonce is ours, fresh and random per cut, and only the peer
/// that received the frame holds it, so accepting the ack from any path of
/// that peer does not widen what it proves; two links cut together each wait
/// for their own. It authorizes nothing either way: it only lets the closer
/// close sooner. Untagged data events from a main-queue link can still reach
/// the loop until the close, exactly as during the plain drop's grace; they
/// open nothing new.
pub struct ClosingLink {
    pub(super) pid: String,
    pub(super) ack: Option<oneshot::Sender<()>>,
}

/// `inner` is a `link-revoked-ack` from `ipid`: its pid and nonce.
pub(super) fn refusal_ack_nonce(inner: &Ev) -> Option<(&str, &str)> {
    match inner {
        Ev::Control(ipid, v) if v["type"].as_str() == Some("link-revoked-ack") => {
            v["nonce"].as_str().map(|n| (ipid.as_str(), n))
        }
        _ => None,
    }
}

/// What became of a revoked link's refusal. A DIAGNOSTIC, never a delivery
/// verdict: only `Acknowledged` says something positive (the peer recorded
/// it), and nothing may read the others as "not delivered". A one-shot peer
/// never acknowledges at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalOutcome {
    /// The peer answered with `link-revoked-ack` for this nonce, which it sends
    /// only after it recorded the refusal on the link.
    Acknowledged,
    /// Written, no ack within the budget (a dead, frozen, older or one-shot
    /// peer, or a link whose reader ended).
    Unconfirmed,
    /// The write itself failed: the transport was already gone.
    SendFailed,
    /// The write did not complete within the budget.
    SendTimedOut,
}

impl RefusalOutcome {
    pub(super) fn describe(self) -> &'static str {
        match self {
            RefusalOutcome::Acknowledged => "acknowledged by the peer",
            RefusalOutcome::Unconfirmed => "sent, not acknowledged within the budget (unconfirmed)",
            RefusalOutcome::SendFailed => "send failed, the link was already gone",
            RefusalOutcome::SendTimedOut => "send did not complete within the budget",
        }
    }
}

/// Where a cut link's ack may show up. Both are optional: `signal` is fired by
/// `Conn` when the ack reaches the main queue; `stream` is the link's own
/// candidate stream, read here directly so no loop turn is needed.
pub struct AckWatch {
    pub pid: String,
    pub nonce: String,
    pub signal: Option<oneshot::Receiver<()>>,
    pub stream: Option<mpsc::UnboundedReceiver<Ev>>,
}

async fn ack_signal(signal: &mut Option<oneshot::Receiver<()>>) -> bool {
    match signal {
        Some(rx) => rx.await.is_ok(),
        None => std::future::pending().await,
    }
}

async fn ack_stream(stream: &mut Option<mpsc::UnboundedReceiver<Ev>>) -> Option<Ev> {
    match stream {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

enum AckStep {
    Acked,
    SignalGone,
    Event(Ev),
    StreamEnded,
    Deadline,
}

/// Write `frame` and wait for its ack, both under ONE deadline `budget` from
/// now. A peer that never reads, never acks, or whose write parks forever
/// costs at most `budget`; a link whose reader ended on a dead transport ends
/// the wait at once. Everything else read from the stream is discarded. Must run off the event loop (it awaits the peer).
pub async fn deliver_refusal(
    t: &dyn Transport,
    frame: &Value,
    watch: Option<AckWatch>,
    budget: Duration,
) -> RefusalOutcome {
    let deadline = tokio::time::Instant::now() + budget;
    match tokio::time::timeout_at(deadline, t.send_control(frame)).await {
        Err(_) => return RefusalOutcome::SendTimedOut,
        Ok(Err(_)) => return RefusalOutcome::SendFailed,
        Ok(Ok(())) => {}
    }
    let Some(mut watch) = watch else {
        return RefusalOutcome::Unconfirmed;
    };
    loop {
        if watch.signal.is_none() && watch.stream.is_none() {
            return RefusalOutcome::Unconfirmed;
        }
        let step = tokio::select! {
            acked = ack_signal(&mut watch.signal) => {
                if acked { AckStep::Acked } else { AckStep::SignalGone }
            }
            ev = ack_stream(&mut watch.stream) => match ev {
                Some(ev) => AckStep::Event(ev),
                None => AckStep::StreamEnded,
            },
            _ = tokio::time::sleep_until(deadline) => AckStep::Deadline,
        };
        match step {
            AckStep::Acked => return RefusalOutcome::Acknowledged,
            AckStep::SignalGone => watch.signal = None,
            AckStep::StreamEnded => {
                watch.stream = None;
                // The reader ended. With the transport dead too, nothing can
                // answer on any path any more: stop now, not at the deadline.
                if t.is_dead() {
                    return RefusalOutcome::Unconfirmed;
                }
            }
            AckStep::Deadline => return RefusalOutcome::Unconfirmed,
            AckStep::Event(Ev::Sourced { pid, inner, .. }) => {
                let ours = refusal_ack_nonce(&inner).is_some_and(|(ipid, nonce)| {
                    ipid == pid && pid == watch.pid && nonce == watch.nonce
                });
                if ours {
                    return RefusalOutcome::Acknowledged;
                }
            }
            AckStep::Event(_) => {}
        }
    }
}

pub(super) fn ev_weight(ev: &Ev) -> usize {
    match ev {
        Ev::Sourced { inner, .. } => ev_weight(inner),
        Ev::Chunk(_, _, _, bytes) => bytes.len().max(1),
        Ev::Control(_, value) | Ev::LocalControl(_, value) => value.to_string().len().max(1),
        _ => 1,
    }
}

/// One installed link's candidate-origin event stream. Owned by `Conn`, keyed
/// by pid, and drained once per loop turn. It dies with its link.
pub struct LinkEvents {
    pub generation: u32,
    pub rx: std::sync::Mutex<mpsc::UnboundedReceiver<Ev>>,
    /// Set by `stage_event` when it admits a departure barrier for THIS exact
    /// source (the link's current primary). `on_peer_left` consumes it once to
    /// distinguish that validated hand-over from a fresh room departure; it
    /// dies with this entry (replacement/drop re-insert it or remove it) and is
    /// never written by anything that has not passed the exact-source gate.
    pub departure_ready: Option<net::SourceId>,
    /// A departure barrier for this exact source is queued (its events were
    /// already handed over, so the local queue is empty). A DUPLICATE ordinary
    /// peer-left for the same link must not finalize on that empty queue; it
    /// waits for the barrier, which is already in the main queue.
    pub departure_pending: Option<net::SourceId>,
}

/// What a bounded hand-over of one link's already-read events moved.
pub(super) enum QueueDrain {
    Empty,
    Moved(usize),
    /// More than the per-link event budget was queued: the hand-over cannot be
    /// completed without an unbounded loop, so the caller drops instead.
    Overflow,
}

/// Source-bound events from a standby/upgrade transport that is not adopted
/// yet. They are replayed only if that exact source becomes the link source.
pub struct PendingSource {
    pub pid: String,
    /// The direct attempt that owns this source. None for a generic staged
    /// source; direct standby cleanup only touches an exact match.
    pub attempt: Option<net::AttemptId>,
    pub at: Instant,
    pub events: std::collections::VecDeque<Ev>,
    pub bytes: usize,
}

/// Source-tagged event routing, replay buffering, and revocation close tracking
/// owned by `Conn`.
#[derive(Default)]
pub struct SourceRouting {
    /// Candidate-origin event streams for INSTALLED links, keyed by pid. The
    /// entry is owned by the link: drop_link/replacement removes and drains it,
    /// so a queued ChannelReady/Control from the old generation is discarded
    /// instead of being replayed onto the new link.
    pub(super) link_events: SimHashMap<String, LinkEvents>,
    /// Source-bound standby/upgrade events awaiting adoption. Bounded per source
    /// and in total; overflow closes the standby instead of growing forever.
    pub(super) pending_sources: SimHashMap<net::SourceId, PendingSource>,
    pub(super) replaying_sources: SimHashMap<net::SourceId, PendingSource>,
    pub(super) replay_departures: SimHashMap<String, (net::SourceId, bool)>,
    /// Links cut by a revocation whose refusal is still in flight, keyed by the
    /// refusal's nonce. See `ClosingLink` and `drop_link_after_refusal`.
    pub(super) closing: SimHashMap<String, ClosingLink>,
}

impl SourceRouting {
    pub(super) fn total_buffered_events(&self) -> usize {
        self.pending_sources
            .values()
            .chain(self.replaying_sources.values())
            .map(|p| p.events.len())
            .sum()
    }

    pub(super) fn total_buffered_bytes(&self) -> usize {
        self.pending_sources
            .values()
            .chain(self.replaying_sources.values())
            .map(|p| p.bytes)
            .sum()
    }

    pub(super) fn clear_for_unlink(&mut self, pid: &str) -> Option<LinkEvents> {
        // #686: fence the departure behind any adopted-source replay. This
        // runs on every invalidation, an ordinary drop and a revocation cut.
        self.replaying_sources.retain(|_, pending| pending.pid != pid);
        if self.replay_departures.get(pid).is_some_and(|(_, ready)| !ready) {
            self.replay_departures.remove(pid);
        }
        // The installed link owns its candidate-origin stream; dropping the
        // receiver discards any queued ChannelReady/Control from this
        // generation instead of forwarding it to a later link.
        self.link_events.remove(pid)
    }

    pub(super) fn retain_pending_except_pid(&mut self, pid: &str) {
        self.pending_sources.retain(|_, pending| pending.pid != pid);
    }

    pub(super) fn force_clear_departure(&mut self, pid: &str) {
        self.replay_departures.remove(pid);
        if let Some(events) = self.link_events.get_mut(pid) {
            events.departure_ready = None;
            events.departure_pending = None;
        }
    }
}

impl Conn {
    pub fn stage_event(&mut self, ev: Ev) -> Option<(Ev, Option<net::SourceId>)> {
        match ev {
            Ev::ReplayDeparture(pid, source, payload) => {
                if self.sources.replay_departures.get(&pid) != Some(&(source, false)) {
                    return None;
                }
                if self.links.get(&pid).map(|link| link.source) != Some(source) {
                    self.sources.replay_departures.remove(&pid);
                    return None;
                }
                if self.sources.replaying_sources.contains_key(&source) {
                    let _ = self.tx.send(Ev::ReplayDeparture(pid, source, payload));
                    return None;
                }
                self.sources.replay_departures.insert(pid, (source, true));
                return Some((Ev::PeerLeft(payload), Some(source)));
            }
            Ev::ReplaySource(source) => {
                let pending = self.sources.replaying_sources.get_mut(&source)?;
                let pid = pending.pid.clone();
                let inner = pending.events.pop_front()?;
                pending.bytes = pending.bytes.saturating_sub(ev_weight(&inner));
                if pending.events.is_empty() {
                    self.sources.replaying_sources.remove(&source);
                }
                return self.source_current(&pid, source, &inner).then_some((inner, Some(source)));
            }
            Ev::AttemptDrained(attempt) => {
                self.retired_attempts.remove(&attempt);
                None
            }
            Ev::Sourced { pid, source, inner } => {
                // A departure barrier (`on_peer_left` queued it behind that
                // link's already-read events). The exact-source gate still runs
                // HERE, but the event is then handed to the ordinary caller as
                // a normal `Ev::PeerLeft`: its pre-drop snapshot and messaging
                // must run as they do for any room departure. The once-only
                // marker records that this departure was already validated, so
                // `on_peer_left` can finish it without re-draining the queue.
                if let Ev::PeerLeft(v) = inner.as_ref() {
                    if v["id"].as_str() != Some(pid.as_str()) {
                        return None;
                    }
                    // A replacement adopted after the barrier was queued is
                    // newer authority and must survive; a stale barrier only
                    // self-rejects (and never marks anything).
                    if !self.source_current(&pid, source, inner.as_ref()) {
                        return None;
                    }
                    if self.sources.replaying_sources.contains_key(&source) {
                        let _ = self.tx.send(Ev::Sourced { pid, source, inner });
                        return None;
                    }
                    match self.sources.link_events.get_mut(&pid) {
                        Some(events)
                            if self.links.get(&pid).map(|link| link.generation)
                                == Some(events.generation) =>
                        {
                            events.departure_ready = Some(source);
                        }
                        // No live queue for this link (dropped since the drain):
                        // there is nothing this hand-over protects.
                        _ => return None,
                    }
                    let v = v.clone();
                    return Some((Ev::PeerLeft(v), Some(source)));
                }
                // Envelope and inner pid must agree, and nesting is invalid:
                // otherwise checking one pid would handle another.
                let valid_inner = match inner.as_ref() {
                    Ev::Control(ipid, _)
                    | Ev::PcState(ipid, _)
                    | Ev::ChannelReady(ipid, _)
                    | Ev::Chunk(ipid, ..) => ipid == &pid,
                    _ => false,
                };
                if !valid_inner {
                    return None;
                }
                // The ack for a cut link's refusal, from whichever path of that
                // peer it came back on (current or not). It is consumed here:
                // it authorizes nothing and is never dispatched.
                if self.closing_ack(&pid, inner.as_ref()) {
                    return None;
                }
                if self.source_current(&pid, source, inner.as_ref()) {
                    if self.sources.replaying_sources.contains_key(&source) {
                        // The replay tokens were queued behind already-read newer
                        // events. Swap this arrival behind the oldest buffered
                        // event, so the consumer sees source order, not queue order.
                        let total = self.sources.total_buffered_bytes();
                        let Some(pending) = self.sources.replaying_sources.get_mut(&source) else { return None; };
                        if pending.pid != pid { return None; }
                        // The token invariant says one buffered event per token.
                        // If it does not hold, fail closed: drop the replay and
                        // close the transport rather than panic in the daemon's
                        // event loop.
                        let Some(older) = pending.events.pop_front() else {
                            self.sources.replaying_sources.remove(&source);
                            if let Some(t) = self.transport_of(&pid) { t.force_close(); }
                            return None;
                        };
                        let bytes = pending.bytes.saturating_sub(ev_weight(&older))
                            .saturating_add(ev_weight(&inner));
                        let total_after = total.saturating_sub(pending.bytes).saturating_add(bytes);
                        if bytes > MAX_BUILD_EVENT_BYTES || total_after > MAX_BUILD_EVENT_BYTES {
                            self.sources.replaying_sources.remove(&source);
                            if let Some(t) = self.transport_of(&pid) { t.force_close(); }
                            return None;
                        }
                        pending.bytes = bytes;
                        pending.events.push_back(*inner);
                        return self.source_current(&pid, source, &older).then_some((older, Some(source)));
                    }
                    return Some((*inner, Some(source)));
                }
                // A standby/upgrade attempt may deliver before adoption. Buffer
                // it only for its registered source and pid, bounded.
                if self.sources.pending_sources.get(&source).is_some_and(|p| p.pid == pid) {
                    self.buffer_pending_source(pid, source, *inner);
                }
                None
            }
            // A transport-origin event must never arrive untagged. Fail closed
            // whether or not a link exists.
            Ev::Control(..) | Ev::PcState(..) | Ev::ChannelReady(..) | Ev::Chunk(..) => None,
            // Loop-authored events are explicitly trusted: they are created by
            // this loop, not a transport callback.
            Ev::LocalControl(pid, value) => Some((Ev::Control(pid, value), None)),
            Ev::LocalPcState(pid, state) => Some((Ev::PcState(pid, state), None)),
            other => Some((other, None)),
        }
    }

    /// Forget cut-link entries whose closer has finished. Never awaits.
    pub(super) fn pump_closing(&mut self) {
        self.sources
            .closing
            .retain(|_, entry| entry.ack.as_ref().is_some_and(|a| !a.is_closed()));
    }

    /// A `link-revoked-ack` answering a cut in flight completes it: the nonce
    /// must be that cut's, read for that cut's pid (on any of its paths).
    /// Returns whether `inner` was a `link-revoked-ack` at all; every
    /// one is consumed (a stale or unknown one is logged), since it authorizes
    /// nothing and has no handler.
    pub(super) fn closing_ack(&mut self, pid: &str, inner: &Ev) -> bool {
        let Some((ipid, nonce)) = refusal_ack_nonce(inner) else {
            return false;
        };
        let matched = ipid == pid
            && self
                .sources
                .closing
                .get(nonce)
                .is_some_and(|entry| entry.pid == pid);
        if matched {
            if let Some(mut entry) = self.sources.closing.remove(nonce) {
                if let Some(ack) = entry.ack.take() {
                    let _ = ack.send(());
                }
            }
        } else {
            self.log.debug(&format!(
                "link-revoked-ack from {pid} for nonce {nonce}: already settled or unknown \
                 (duplicate acks on a second path are expected)"
            ));
        }
        true
    }

    /// A source is current when it is the link's primary source, or (for
    /// Control and Chunk only) one of its current worker sources. PcState/ChannelReady
    /// and a departure barrier (`Ev::PeerLeft`) are primary-only so a worker
    /// can never trigger primary teardown/readiness or a departure.
    pub(super) fn source_current(&self, pid: &str, source: net::SourceId, inner: &Ev) -> bool {
        let Some(link) = self.links.get(pid) else {
            return false;
        };
        if link.source == source {
            return true;
        }
        matches!(inner, Ev::Control(..) | Ev::Chunk(..)) && link.worker_sources.contains(&source)
    }

    /// Buffer a pre-adoption event for a registered source. Per-source and total
    /// bounds are the existing build-event budget; overflow fails closed by
    /// dropping the pending source and its standby transport.
    pub(super) fn buffer_pending_source(&mut self, pid: String, source: net::SourceId, inner: Ev) {
        let weight = ev_weight(&inner);
        let total_events = self.sources.total_buffered_events();
        let total_bytes = self.sources.total_buffered_bytes();
        let over_total = total_events >= MAX_BUILD_EVENTS
            || total_bytes.saturating_add(weight) > MAX_BUILD_EVENT_BYTES;
        let is_new = !self.sources.pending_sources.contains_key(&source);
        let over_sources = is_new && self.sources.pending_sources.len() >= MAX_PENDING_BUILDS;
        let over_source = self.sources.pending_sources.get(&source).is_none_or(|p| {
            p.events.len() >= MAX_BUILD_EVENTS
                || p.bytes.saturating_add(weight) > MAX_BUILD_EVENT_BYTES
        });
        if over_total || over_sources || over_source {
            self.drop_pending_source(source);
            return;
        }
        let entry = self
            .sources
            .pending_sources
            .entry(source)
            .or_insert_with(|| PendingSource {
                pid: pid.clone(),
                attempt: None,
                at: Instant::now(),
                events: std::collections::VecDeque::new(),
                bytes: 0,
            });
        entry.bytes += weight;
        entry.events.push_back(inner);
    }

    /// Drop a pending source and close its standby, so overflow cannot leave a
    /// live transport that will never be adopted.
    pub(super) fn drop_pending_source(&mut self, source: net::SourceId) {
        let Some(pending) = self.sources.pending_sources.remove(&source) else {
            return;
        };
        if let Some(promotion) = self.promotions.get_mut(&pending.pid) {
            let matches = promotion
                .standby
                .as_ref()
                .is_some_and(|(transport, _)| transport.source_id() == Some(source));
            if matches {
                if let Some((transport, _)) = promotion.standby.take() {
                    transport.force_close();
                }
            }
        }
        if let Some(probe) = self.resil.upgrade_probe.get_mut(&pending.pid) {
            let matches = probe
                .standby
                .as_ref()
                .is_some_and(|transport| transport.source_id() == Some(source));
            if matches {
                if let Some(transport) = probe.standby.take() {
                    transport.force_close();
                }
            }
        }
    }

    /// Queue one token per buffered event. Newer already-queued events swap with
    /// the oldest replay item at the final gate, preserving source order.
    pub(super) fn flush_pending_source(&mut self, source: net::SourceId) {
        let Some(pending) = self.sources.pending_sources.remove(&source) else {
            return;
        };
        let count = pending.events.len();
        if count == 0 {
            return;
        }
        self.sources.replaying_sources.insert(source, pending);
        for _ in 0..count {
            let _ = self.tx.send(Ev::ReplaySource(source));
        }
    }

    /// Move a BOUNDED batch of the events already READ from `pid`'s current
    /// link (its candidate queue) onto the main queue, in arrival order,
    /// without touching another link's stream. The batch is capped at the
    /// existing per-link event budget, so a producer still writing cannot keep
    /// this loop spinning; over the cap the caller fails closed instead of
    /// retrying or retaining. Only called from `on_peer_left`, immediately
    /// before queueing the departure barrier, so those events are dispatched
    /// while the link they came from still exists.
    pub(super) fn drain_current_link_events(&mut self, pid: &str) -> QueueDrain {
        let Some(generation) = self
            .sources
            .link_events
            .get(pid)
            .map(|events| events.generation)
        else {
            return QueueDrain::Empty;
        };
        // The entry must belong to the link this leave names. A newer
        // generation is different authority and is not ours to drain.
        if self.links.get(pid).map(|link| link.generation) != Some(generation) {
            return QueueDrain::Empty;
        }
        let tx = self.tx.clone();
        let Some(events) = self.sources.link_events.get_mut(pid) else {
            return QueueDrain::Empty;
        };
        let mut rx = events
            .rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut moved = 0;
        while moved < MAX_BUILD_EVENTS {
            match rx.try_recv() {
                Ok(ev) => {
                    let _ = tx.send(ev);
                    moved += 1;
                }
                Err(_) => {
                    return if moved == 0 {
                        QueueDrain::Empty
                    } else {
                        QueueDrain::Moved(moved)
                    };
                }
            }
        }
        // Exactly at the cap: probe once (never loop) to tell "the queue ended
        // there" from "there is more than may be handed over in one turn".
        if rx.try_recv().is_ok() {
            QueueDrain::Overflow
        } else {
            QueueDrain::Moved(moved)
        }
    }
}
