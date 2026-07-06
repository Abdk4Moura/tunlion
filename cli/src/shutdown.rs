//! SHUTDOWN: prompt, bounded exit on SIGTERM/SIGINT regardless of link count.
//!
//! The daemon acceptor's signal handling used to route a signal through the
//! event-loop channel (`Ev::Interrupted`): the loop had to be FREE to see it,
//! then ran `flush + sio.disconnect().await + process::exit`. With several live
//! peer links one wedged transport write inside the per-tick work (a WebRTC data
//! channel `write_data_channel().await` against a frozen / half-open peer, or a
//! `send_frame` parked on backpressure that never drains) starves the loop. The
//! `Interrupted` event then never gets processed, the process ignores SIGTERM for
//! the full systemd `TimeoutStopSec` (90s) and is SIGKILLed. The class of
//! webrtc-rs `close()`/write deadlock-on-drop is well known; the resilience layer
//! already treats a dropped link as an ordinary disconnect on both ends.
//!
//! The fix here is a SIGNAL-OWNED watchdog: the moment a termination signal lands
//! we arm a hard, bounded deadline that force-exits the process even if the
//! graceful path (event loop) is wedged. A dropped link is recovered by the
//! resilience layer, so a bounded best-effort teardown loses nothing a normal
//! disconnect wouldn't.

use std::time::Duration;

/// Default grace before the watchdog force-exits, in milliseconds. Comfortably
/// under systemd's default `TimeoutStopSec` (90s) so the process exits on its
/// own terms well before SIGKILL. Overridable for tests / tuning via
/// `FILAMENT_SHUTDOWN_GRACE_MS`.
pub const DEFAULT_GRACE_MS: u64 = 3_000;

/// The bounded shutdown grace, env-tunable. Pure given the environment; the
/// parsing/clamping logic is unit-tested via `grace_from`.
pub fn grace() -> Duration {
    grace_from(std::env::var("FILAMENT_SHUTDOWN_GRACE_MS").ok().as_deref())
}

/// Pure: turn an optional `FILAMENT_SHUTDOWN_GRACE_MS` value into the grace
/// duration. A missing / unpar0able value falls back to the default. `0` is
/// honored (force-exit on the next scheduler tick) so an operator can opt into
/// an immediate exit; everything else is taken verbatim.
pub fn grace_from(raw: Option<&str>) -> Duration {
    let ms = raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_GRACE_MS);
    Duration::from_millis(ms)
}

/// Arm a detached watchdog that force-exits the process with `code` after
/// `grace`, independent of the event loop. Call this the instant a termination
/// signal is observed: even if the graceful shutdown (flush + signaling
/// disconnect + the loop's own `process::exit`) wedges on a stuck transport, the
/// watchdog guarantees the process is gone within `grace`. Idempotent in effect
/// (extra arms just schedule more force-exits at the same deadline; the first to
/// fire wins).
pub fn arm_force_exit(code: i32, grace: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        // The graceful path did not finish in time. A dropped link is already an
        // ordinary disconnect to the peer's resilience layer, so exiting now
        // corrupts nothing a normal disconnect wouldn't.
        std::process::exit(code);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_defaults_when_unset() {
        assert_eq!(grace_from(None), Duration::from_millis(DEFAULT_GRACE_MS));
    }

    #[test]
    fn grace_defaults_on_garbage() {
        assert_eq!(grace_from(Some("not-a-number")), Duration::from_millis(DEFAULT_GRACE_MS));
        assert_eq!(grace_from(Some("")), Duration::from_millis(DEFAULT_GRACE_MS));
    }

    #[test]
    fn grace_parses_explicit_value() {
        assert_eq!(grace_from(Some("500")), Duration::from_millis(500));
        assert_eq!(grace_from(Some("  1500 ")), Duration::from_millis(1500));
    }

    #[test]
    fn grace_honors_zero() {
        assert_eq!(grace_from(Some("0")), Duration::from_millis(0));
    }
}
