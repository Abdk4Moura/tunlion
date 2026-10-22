//! Bounded terminal cleanup receipts, not permission policy. Resource revocation
//! must complete before an adapter starts this exchange. Transport loss never
//! restores access, extends the deadline, or creates another invitation claim.
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Message { End, Receipt, Confirmed }
impl Message {
    pub(crate) fn wire(self) -> &'static str {
        match self { Self::End => "access-end", Self::Receipt => "access-ended", Self::Confirmed => "access-end-confirmed" }
    }
    pub(crate) fn parse(kind: &str) -> Option<Self> {
        match kind { "access-end" => Some(Self::End), "access-ended" => Some(Self::Receipt),
            "access-end-confirmed" => Some(Self::Confirmed), _ => None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome { PeerAcknowledged, Confirmed, TimedOut, Disconnected }

#[derive(Default)]
pub(crate) struct Exchange {
    local: bool,
    remote: bool,
    end_sent: bool,
    receipt_sent: bool,
    receipt_received: bool,
    confirmed: bool,
    confirm_due: bool,
    deadline: Option<Instant>,
    next_end: Option<Instant>,
    next_receipt: Option<Instant>,
    finished: Option<Outcome>,
}

pub(crate) struct Step {
    pub(crate) messages: Vec<Message>,
    pub(crate) outcome: Option<Outcome>,
}

impl Exchange {
    pub(crate) fn is_ending(&self) -> bool { self.deadline.is_some() }

    pub(crate) fn begin_local(&mut self, now: Instant) {
        if self.finished.is_some() { return; }
        self.deadline.get_or_insert(now + BUDGET);
        if !self.local { self.local = true; self.next_end = Some(now); }
    }

    pub(crate) fn receive(&mut self, message: Message, now: Instant) {
        if self.finished.is_some() || self.deadline.is_some_and(|deadline| now >= deadline) { return; }
        match message {
            Message::End => {
                self.deadline.get_or_insert(now + BUDGET);
                self.remote = true;
                // A duplicate End requests the same receipt, never a new grant,
                // cleanup operation, or renewed time budget.
                self.next_receipt = Some(now);
            }
            Message::Receipt if self.local && self.end_sent => {
                self.receipt_received = true;
                self.confirm_due = true;
            }
            Message::Confirmed if self.remote && self.receipt_sent => self.confirmed = true,
            _ => {},
        }
    }

    pub(crate) fn poll(&mut self, now: Instant, connected: bool) -> Step {
        let mut messages = Vec::new();
        if let Some(outcome) = self.finished { return Step { messages, outcome: Some(outcome) }; }
        let Some(deadline) = self.deadline else { return Step { messages, outcome: None }; };
        if self.confirm_due {
            messages.push(Message::Confirmed);
            self.confirm_due = false;
        }
        let complete = (!self.local || self.receipt_received) && (!self.remote || self.confirmed);
        let outcome = if complete {
            Some(if self.local { Outcome::PeerAcknowledged } else { Outcome::Confirmed })
        } else if !connected { Some(Outcome::Disconnected) }
        else if now >= deadline { Some(Outcome::TimedOut) }
        else { None };
        if let Some(outcome) = outcome {
            self.finished = Some(outcome);
            return Step { messages, outcome: Some(outcome) };
        }
        if self.local && !self.receipt_received && self.next_end.is_some_and(|due| now >= due) {
            messages.push(Message::End);
            self.end_sent = true;
            self.next_end = Some(now + RETRY);
        }
        if self.remote && !self.confirmed && self.next_receipt.is_some_and(|due| now >= due) {
            messages.push(Message::Receipt);
            self.receipt_sent = true;
            self.next_receipt = Some(now + RETRY);
        }
        Step { messages, outcome: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_receipt_retries_same_end_and_duplicate_end_repeats_receipt() {
        let now = Instant::now();
        let (mut host, mut peer) = (Exchange::default(), Exchange::default());
        host.begin_local(now);
        assert_eq!(host.poll(now, true).messages, vec![Message::End]);
        peer.receive(Message::End, now);
        assert_eq!(peer.poll(now, true).messages, vec![Message::Receipt]); // dropped
        let retry = now + RETRY;
        assert_eq!(host.poll(retry, true).messages, vec![Message::End]);
        peer.receive(Message::End, retry);
        assert_eq!(peer.poll(retry, true).messages, vec![Message::Receipt]);
        host.receive(Message::Receipt, retry);
        let step = host.poll(retry, true);
        assert_eq!(step.messages, vec![Message::Confirmed]);
        assert_eq!(step.outcome, Some(Outcome::PeerAcknowledged));
        peer.receive(Message::Confirmed, retry);
        assert_eq!(peer.poll(retry, true).outcome, Some(Outcome::Confirmed));
        host.receive(Message::Receipt, retry);
        assert!(host.poll(retry, true).messages.is_empty(), "late duplicate restarted exchange");
    }

    #[test]
    fn duplicate_end_cannot_extend_deadline_and_late_ack_cannot_revive_timeout() {
        let now = Instant::now();
        let mut exchange = Exchange::default();
        exchange.begin_local(now);
        exchange.poll(now, true);
        exchange.begin_local(now + BUDGET - RETRY);
        exchange.receive(Message::End, now + BUDGET - RETRY);
        assert_eq!(exchange.poll(now + BUDGET, true).outcome, Some(Outcome::TimedOut));
        exchange.receive(Message::Receipt, now + BUDGET);
        assert_eq!(exchange.poll(now + BUDGET, true).outcome, Some(Outcome::TimedOut));
        assert!(exchange.poll(now + BUDGET, true).messages.is_empty());
    }

    #[test]
    fn simultaneous_end_requires_both_receipt_directions_without_reopening() {
        let now = Instant::now();
        let (mut first, mut second) = (Exchange::default(), Exchange::default());
        first.begin_local(now);
        second.begin_local(now);
        first.poll(now, true);
        second.poll(now, true);
        first.receive(Message::End, now);
        second.receive(Message::End, now);
        assert_eq!(first.poll(now, true).messages, vec![Message::Receipt]);
        assert_eq!(second.poll(now, true).messages, vec![Message::Receipt]);
        first.receive(Message::Receipt, now);
        second.receive(Message::Receipt, now);
        assert_eq!(first.poll(now, true).outcome, None);
        assert_eq!(second.poll(now, true).messages, vec![Message::Confirmed]);
        first.receive(Message::Confirmed, now);
        second.receive(Message::Confirmed, now);
        assert_eq!(first.poll(now, true).outcome, Some(Outcome::PeerAcknowledged));
        assert_eq!(second.poll(now, true).outcome, Some(Outcome::PeerAcknowledged));
    }

    #[test]
    fn peer_disconnect_and_unrequested_or_late_receipts_never_claim_success() {
        let now = Instant::now();
        let mut exchange = Exchange::default();
        exchange.receive(Message::Receipt, now);
        exchange.receive(Message::Confirmed, now);
        assert!(!exchange.is_ending());
        exchange.begin_local(now);
        assert_eq!(exchange.poll(now, false).outcome, Some(Outcome::Disconnected));
        exchange.receive(Message::Receipt, now);
        assert_eq!(exchange.poll(now, true).outcome, Some(Outcome::Disconnected));
        let mut peer = Exchange::default();
        peer.receive(Message::End, now);
        peer.poll(now, true);
        // Lost final confirmation is bounded and still leaves resources ended.
        assert_eq!(peer.poll(now + BUDGET, true).outcome, Some(Outcome::TimedOut));
    }
}
