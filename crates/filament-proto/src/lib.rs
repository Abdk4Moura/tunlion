//! PROTOCOL: the filament file-transfer ceremony decisions (the Rust mirror of
//! the JS `net/protocol` layer). Pure: bytes/state in, a decision out, NO timers,
//! NO retries, NO transport. The stateful event loops (`send_cmd`/`recv_cmd` in
//! `main.rs`) own the I/O and call in here. Mirrors
//! `frontend/src/net/protocol/transfer.js` (`decideAfterVerify`/`decideAckFallback`).

use serde_json::{json, Value};

// ---- control-message builders (the file-transfer wire vocabulary) -----------
// The exact JSON control shapes, mirroring frontend/src/net/protocol/transfer.js.
// Control messages are parsed by key (order-independent), so these stay
// interop-safe with the JS peer. One definition per message instead of the inline
// `json!` literals that were scattered through send_cmd/recv_cmd.

/// A file offer. `head` (C7 resume digest) and `full` (P4 whole-file digest) are
/// included when present; `resume` marks a re-offer after a prior accept.
pub fn offer_msg(
    id: &str,
    sid: u32,
    name: &str,
    size: u64,
    head: Option<&str>,
    full: Option<&str>,
    resume: bool,
) -> Value {
    let mut o = json!({
        "type": "file-offer", "id": id, "sid": sid,
        "name": name, "size": size, "mime": "application/octet-stream",
    });
    if let Some(h) = head {
        o["head"] = json!(h);
    }
    if let Some(f) = full {
        o["full"] = json!(f);
    }
    if resume {
        o["resume"] = json!(true);
    }
    o
}

pub fn accept_msg(id: &str, offset: u64) -> Value {
    json!({ "type": "file-accept", "id": id, "offset": offset })
}

pub fn decline_msg(id: &str) -> Value {
    json!({ "type": "file-decline", "id": id })
}

pub fn end_msg(id: &str, sid: u32) -> Value {
    json!({ "type": "file-end", "id": id, "sid": sid })
}

/// P4: sent ONLY after the whole file verified (sha256 matched).
pub fn delivery_ack_msg(id: &str, sid: u32) -> Value {
    json!({ "type": "delivery-ack", "id": id, "sid": sid, "v": 1 })
}

/// RECEIVER: may we drop a dead link instead of reconnecting? Pulled out so the
/// gate-2 / gate-11c fence (a mid-transfer link must NEVER be dropped) is
/// unit-testable without a live WebRTC peer. The recv loop computes
/// `conn.recv_done` from exactly this each tick; `on_stuck` then reads the flag.
///
/// - `completed`: files fully placed on disk so far.
/// - `keep_open`: the receiver was asked to stay resident (gate 13).
/// - `by_sid_empty`: NO stream is in flight (an in-progress reconnect/resume keeps
///   a by_sid entry, which must keep the link reconnecting (gate 2/11c).
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
///   When false the link is gone, nothing can prompt or carry a re-ack.
/// - `reprobed`: we have already re-sent `file-end` once this window.
#[derive(Debug, PartialEq, Eq)]
pub enum AckFallback {
    /// link looks alive and we have not re-probed, the ack may be lost; re-send
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

/// P4 (GAP-5): outcome of the RECEIVER's whole-file integrity check at file-end.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// Received bytes hash to the sender's offered digest, accept + ack.
    Match,
    /// Hash didn't match. `restart_from_zero` distinguishes the two cases: a SHORT
    /// file (received < size) is merely TRUNCATED, resume the tail; a FULL-SIZE
    /// file with the wrong hash has a CORRUPT BODY (the partial is poisoned), so
    /// re-fetch from 0.
    Mismatch { restart_from_zero: bool },
}

/// The pure whole-file verify DECISION (digest present). Mirrors the JS
/// `decideAfterVerify` (net/protocol/transfer.js). `verify_incoming` does the I/O
/// (flush + sha256) and calls this; a truncated file is classified WITHOUT hashing
/// (pass `hash_matches: None`).
///   received      bytes on disk so far
///   size          the offered file size
///   hash_matches  Some(true/false) once hashed; None when skipped (truncated)
pub fn decide_verify(received: u64, size: u64, hash_matches: Option<bool>) -> VerifyResult {
    if received < size {
        // Truncated, can't possibly match yet; resume the tail.
        return VerifyResult::Mismatch { restart_from_zero: false };
    }
    match hash_matches {
        Some(true) => VerifyResult::Match,
        // Full size but wrong/uncomputable hash → corrupt body, re-fetch whole.
        _ => VerifyResult::Mismatch { restart_from_zero: true },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_msg_shapes() {
        // Fresh offer (no digests, no resume).
        assert_eq!(
            offer_msg("id1", 7, "a.bin", 100, None, None, false),
            json!({ "type": "file-offer", "id": "id1", "sid": 7, "name": "a.bin", "size": 100, "mime": "application/octet-stream" })
        );
        // With head + full digests and resume.
        assert_eq!(
            offer_msg("id1", 7, "a.bin", 100, Some("hh"), Some("ff"), true),
            json!({ "type": "file-offer", "id": "id1", "sid": 7, "name": "a.bin", "size": 100, "mime": "application/octet-stream", "head": "hh", "full": "ff", "resume": true })
        );
    }

    #[test]
    fn accept_decline_end_ack_shapes() {
        assert_eq!(accept_msg("id1", 0), json!({ "type": "file-accept", "id": "id1", "offset": 0 }));
        assert_eq!(accept_msg("id1", 4096), json!({ "type": "file-accept", "id": "id1", "offset": 4096 }));
        assert_eq!(decline_msg("id1"), json!({ "type": "file-decline", "id": "id1" }));
        assert_eq!(end_msg("id1", 7), json!({ "type": "file-end", "id": "id1", "sid": 7 }));
        assert_eq!(delivery_ack_msg("id1", 7), json!({ "type": "delivery-ack", "id": "id1", "sid": 7, "v": 1 }));
    }

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
        // Must NOT drop, gate 2 / gate 11c reconnect paths depend on this.
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
        // (resumable), the exact case the old code falsely completed.
        assert_eq!(decide_ack_fallback(true, true), AckFallback::FailUnconfirmed);
    }

    #[test]
    fn verify_match_only_on_full_size_correct_hash() {
        assert_eq!(decide_verify(100, 100, Some(true)), VerifyResult::Match);
    }

    #[test]
    fn verify_truncated_resumes_tail() {
        // Short file → truncated, resume from the current offset (no re-hash).
        assert_eq!(decide_verify(60, 100, None), VerifyResult::Mismatch { restart_from_zero: false });
        // Even if a stale hash were passed, a short file is always truncated.
        assert_eq!(decide_verify(60, 100, Some(false)), VerifyResult::Mismatch { restart_from_zero: false });
    }

    #[test]
    fn verify_full_size_wrong_hash_is_corrupt_restart() {
        assert_eq!(decide_verify(100, 100, Some(false)), VerifyResult::Mismatch { restart_from_zero: true });
        // Unhashable (None) at full size is treated as corrupt too (can't accept).
        assert_eq!(decide_verify(100, 100, None), VerifyResult::Mismatch { restart_from_zero: true });
    }
}
