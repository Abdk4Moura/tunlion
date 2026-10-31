//! Fault-injection hooks for the peer-loop paths, env-gated exactly as they were
//! in `cli/src/main.rs`. Compiled in ONLY under `--features test-hooks`; the
//! production twin returns the no-hook value for every one, so the surrounding
//! logic compiles and behaves as if the hook were absent.

#[cfg(feature = "test-hooks")]
mod on {
    /// P1: force every WebRTC link relay-only (models a hard-NAT peer).
    pub fn webrtc_relay_only() -> bool {
        std::env::var("TUNLION_TEST_WEBRTC_RELAY_ONLY")
            .map(|v| v == "1")
            .unwrap_or(false)
    }
    /// Suppress the Mode-B drop on recorder completion.
    pub fn disable_modeb_drop() -> bool {
        std::env::var("TUNLION_TEST_DISABLE_MODEB_DROP").is_ok()
    }
    /// Disable the deferred-link grace window.
    pub fn no_defer() -> bool {
        std::env::var("TUNLION_TEST_NO_DEFER").is_ok()
    }
    /// gate 11b: hold each chunk briefly so a transfer is still flowing when
    /// the gate's second receiver rejoins.
    pub fn transfer_stall_ms() -> u64 {
        std::env::var("TUNLION_TEST_TRANSFER_STALL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }
    /// #28: synthesize a peer-left for the active sid once N file-data bytes
    /// have been sent.
    pub fn inject_peer_left_at() -> Option<u64> {
        std::env::var("TUNLION_TEST_INJECT_PEER_LEFT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
    }
    /// Daemon-survival gate (14c): make the first `n` peer adoptions fail the
    /// way an ICE-config timeout does. The count is a process-global latch,
    /// exactly as it was in `cli/src/main.rs`.
    static FAIL_ADOPT_USED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    pub fn fail_adopt() -> bool {
        let Some(n) = std::env::var("TUNLION_TEST_FAIL_ADOPT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
        else {
            return false;
        };
        FAIL_ADOPT_USED
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |used| (used < n).then_some(used + 1),
            )
            .is_ok()
    }

    /// Truncation/ack gate corruption injector. `TUNLION_TEST_CORRUPT_RECV=<id>`
    /// flips the last on-disk byte of the matching transfer; `_CORRUPT_ONCE=1`
    /// fires exactly once (proving auto-recovery). The "already fired" latch is a
    /// process-global AtomicBool, no env mutation. Moved here with the receive
    /// verify (`recv::verify_incoming`), whose only reader they are.
    static CORRUPT_FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// The configured corrupt-recv target id, if any.
    pub fn corrupt_recv_target() -> Option<String> {
        std::env::var("TUNLION_TEST_CORRUPT_RECV").ok()
    }
    pub fn corrupt_recv_once() -> bool {
        std::env::var("TUNLION_TEST_CORRUPT_ONCE")
            .map(|v| v == "1")
            .unwrap_or(false)
    }
    pub fn corrupt_already_fired() -> bool {
        CORRUPT_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn corrupt_mark_fired() {
        CORRUPT_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Signaling self-heal gate: revert to the no-reconnect baseline.
    pub fn no_signaling_reconnect() -> bool {
        std::env::var("TUNLION_TEST_NO_SIGNALING_RECONNECT").is_ok()
    }
    /// Shutdown-hang gate: wedge the event loop forever.
    pub fn wedge_loop_on_shutdown() -> bool {
        std::env::var("TUNLION_TEST_WEDGE_LOOP").is_ok()
    }
    /// Warm-standby gate: churn surviving links after completion.
    pub fn churn_after_complete() -> bool {
        std::env::var("TUNLION_TEST_CHURN_AFTER_COMPLETE").is_ok()
    }
    /// Gate 18: drop the file-end control frame.
    pub fn drop_file_end() -> bool {
        std::env::var("TUNLION_TEST_DROP_FILE_END").is_ok()
    }
    /// Gate 18: drop a peer-left event.
    pub fn drop_peer_left() -> bool {
        std::env::var("TUNLION_TEST_DROP_PEER_LEFT").is_ok()
    }
    /// Suppress the delivery ack for an ack-loss gate.
    pub fn suppress_delivery_ack() -> bool {
        std::env::var("TUNLION_TEST_SUPPRESS_ACK").is_ok()
    }
    static PREMATURE_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    pub fn premature_close_after_ack() -> bool {
        std::env::var("TUNLION_TEST_PREMATURE_CLOSE").as_deref() == Ok("1")
    }
    pub fn premature_close_once() -> bool {
        std::env::var("TUNLION_TEST_PREMATURE_CLOSE").as_deref() == Ok("once")
    }
    pub fn premature_already_fired() -> bool {
        PREMATURE_FIRED.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn premature_mark_fired() {
        PREMATURE_FIRED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Real-loop latency gate: log the wall gap between daemon-loop iterations
    /// so the worker gate can measure the maximum heartbeat gap, not just the
    /// watchdog's one report. Test-only; the production build has no call.
    pub fn loop_beat() {
        if std::env::var("TUNLION_TEST_LOOP_BEAT").as_deref() != Ok("1") {
            return;
        }
        static LAST: std::sync::Mutex<Option<std::time::Instant>> =
            std::sync::Mutex::new(None);
        let now = std::time::Instant::now();
        let mut last = LAST.lock().unwrap();
        let gap_ms = (*last).map(|at| now.duration_since(at).as_millis()).unwrap_or(0);
        *last = Some(now);
        eprintln!("LOOP-BEAT gap_ms={gap_ms}");
    }

    /// Real-loop latency gate: hold every WebRTC establish for this many
    /// milliseconds, modelling a slow establish without changing production
    /// timing. `0` (the default) is a no-op.
    pub fn establish_delay_ms() -> u64 {
        std::env::var("TUNLION_TEST_ESTABLISH_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// Real-loop latency gate: restore the old whole-batch drain of expired
    /// direct attempts, so one binary can prove the before/after difference.
    pub fn expired_direct_batch() -> bool {
        std::env::var("TUNLION_TEST_EXPIRED_DIRECT_BATCH").as_deref() == Ok("1")
    }

    /// Real-loop publication gate: hold a built candidate before it is reported,
    /// so the gate can forget/revoke/stop its peer while the candidate exists.
    /// When TUNLION_TEST_BUILD_HOLD_PID is set, only that sid is held; an unset
    /// PID keeps the original global behavior.
    pub fn build_hold_ms(pid: &str) -> u64 {
        let only = std::env::var("TUNLION_TEST_BUILD_HOLD_PID").ok();
        if only.as_deref().is_some_and(|only| only != pid) {
            return 0;
        }
        std::env::var("TUNLION_TEST_BUILD_HOLD_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// Raw offer-first gate: suppress the automatic KnownPeer adoption that
    /// normally races ahead of the browser's SDP, so the gate can prove the
    /// responder path from a bare offer. Test-only; release builds never read it.
    pub fn suppress_known_peer() -> bool {
        std::env::var("TUNLION_TEST_SUPPRESS_KNOWN_PEER").as_deref() == Ok("1")
    }
}

#[cfg(not(feature = "test-hooks"))]
mod off {
    #[inline]
    pub fn webrtc_relay_only() -> bool {
        false
    }
    #[inline]
    pub fn disable_modeb_drop() -> bool {
        false
    }
    #[inline]
    pub fn no_defer() -> bool {
        false
    }
    #[inline]
    pub fn transfer_stall_ms() -> u64 {
        0
    }
    #[inline]
    pub fn inject_peer_left_at() -> Option<u64> {
        None
    }
    #[inline]
    pub fn fail_adopt() -> bool {
        false
    }
    #[inline]
    pub fn corrupt_recv_target() -> Option<String> {
        None
    }
    #[inline]
    pub fn corrupt_recv_once() -> bool {
        false
    }
    #[inline]
    pub fn corrupt_already_fired() -> bool {
        false
    }
    #[inline]
    pub fn corrupt_mark_fired() {}

    #[inline]
    pub fn no_signaling_reconnect() -> bool {
        false
    }
    #[inline]
    pub fn wedge_loop_on_shutdown() -> bool {
        false
    }
    #[inline]
    pub fn churn_after_complete() -> bool {
        false
    }
    #[inline]
    pub fn drop_file_end() -> bool {
        false
    }
    #[inline]
    pub fn drop_peer_left() -> bool {
        false
    }
    #[inline]
    pub fn suppress_delivery_ack() -> bool {
        false
    }
    #[inline]
    pub fn premature_close_after_ack() -> bool {
        false
    }
    #[inline]
    pub fn premature_close_once() -> bool {
        false
    }
    #[inline]
    pub fn premature_already_fired() -> bool {
        false
    }
    #[inline]
    pub fn premature_mark_fired() {}

    #[inline]
    pub fn loop_beat() {}

    #[inline]
    pub fn establish_delay_ms() -> u64 {
        0
    }

    #[inline]
    pub fn expired_direct_batch() -> bool {
        false
    }

    #[inline]
    pub fn build_hold_ms(_pid: &str) -> u64 {
        0
    }

    #[inline]
    pub fn suppress_known_peer() -> bool {
        false
    }
}

#[cfg(not(feature = "test-hooks"))]
pub(crate) use off::*;
#[cfg(feature = "test-hooks")]
pub(crate) use on::*;
