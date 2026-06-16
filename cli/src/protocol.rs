//! PROTOCOL — the filament file-transfer ceremony decisions (the Rust mirror of
//! the JS `net/protocol` layer). Pure: bytes/state in, a decision out, NO timers,
//! NO retries, NO transport. The stateful event loops (`send_cmd`/`recv_cmd` in
//! `main.rs`) own the I/O and call in here. Mirrors
//! `frontend/src/net/protocol/transfer.js` (`decideAfterVerify`/`decideAckFallback`).

/// RECEIVER: may we drop a dead link instead of reconnecting? Pulled out so the
/// gate-2 / gate-11c fence (a mid-transfer link must NEVER be dropped) is
/// unit-testable without a live WebRTC peer. The recv loop computes
/// `conn.recv_done` from exactly this each tick; `on_stuck` then reads the flag.
///
/// - `completed`: files fully placed on disk so far.
/// - `keep_open`: the receiver was asked to stay resident (gate 13).
/// - `by_sid_empty`: NO stream is in flight (an in-progress reconnect/resume keeps
///   a by_sid entry, which must keep the link reconnecting — gate 2/11c).
pub fn recv_transfer_done(completed: usize, keep_open: bool, by_sid_empty: bool) -> bool {
    completed > 0 && !keep_open && by_sid_empty
}

/// SENDER: what a send should do when its delivery-ack window elapses with NO
/// whole-file-verified `delivery-ack`. A send is "delivered + verified" ONLY on a
/// genuine `delivery-ack`, so this NEVER returns a "complete": bytes draining out
/// of the send buffer prove nothing (a path that black-holes without ICE/QUIC
/// noticing drains while NOTHING arrives). Pure, so the completion decision is
/// unit-testable without a live peer.
///
/// - `link_alive`: a live transport is still attached (mirrors "channel open").
///   When false the link is gone — nothing can prompt or carry a re-ack.
/// - `reprobed`: we have already re-sent `file-end` once this window.
#[derive(Debug, PartialEq, Eq)]
pub enum AckFallback {
    /// link looks alive and we have not re-probed — the ack may be lost; re-send
    /// `file-end` once to prompt it and extend the window.
    Reprobe,
    /// end honestly (nonzero exit, partial kept resumable), never a false
    /// "delivered + verified". Link gone, or a re-probe still drew no ack.
    FailUnconfirmed,
}

pub fn decide_ack_fallback(link_alive: bool, reprobed: bool) -> AckFallback {
    if !link_alive {
        return AckFallback::FailUnconfirmed;
    }
    if !reprobed {
        return AckFallback::Reprobe;
    }
    AckFallback::FailUnconfirmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_done_drops_only_when_complete() {
        // Gate-18 Mode B: the drop-instead-of-reconnect decision holds ONLY when
        // the transfer is complete and idle. This is the exact fence that protects
        // gate 2 (kill-resume) and gate 11c (deferred-drop).
        assert!(recv_transfer_done(1, false, true));
        assert!(recv_transfer_done(3, false, true));
    }

    #[test]
    fn recv_done_false_mid_transfer_protects_resume() {
        // by_sid NON-empty == a stream in flight (an in-progress reconnect/resume).
        // Must NOT drop — gate 2 / gate 11c reconnect paths depend on this.
        assert!(!recv_transfer_done(0, false, false)); // nothing done, mid-stream
        assert!(!recv_transfer_done(1, false, false)); // file done but another in flight
        // keep_open (gate 13): a resident receiver never self-drops its links.
        assert!(!recv_transfer_done(1, true, true));
        assert!(!recv_transfer_done(5, true, true));
        // nothing completed yet (still connecting / first stream) -> reconnect.
        assert!(!recv_transfer_done(0, false, true));
    }

    #[test]
    fn ack_fallback_never_completes_silently() {
        // P4 silent-data-loss fix: the no-ack window must NEVER claim success.
        // Link gone: fail honestly, no point re-probing into a dead link.
        assert_eq!(decide_ack_fallback(false, false), AckFallback::FailUnconfirmed);
        assert_eq!(decide_ack_fallback(false, true), AckFallback::FailUnconfirmed);
        // Link alive, first window: the ack may be lost, re-probe once.
        assert_eq!(decide_ack_fallback(true, false), AckFallback::Reprobe);
        // Link alive but already re-probed and STILL no ack: fail as unconfirmed
        // (resumable) — the exact case the old code falsely completed.
        assert_eq!(decide_ack_fallback(true, true), AckFallback::FailUnconfirmed);
    }
}
