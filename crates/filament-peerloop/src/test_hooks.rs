//! Fault-injection hooks for the peer-loop paths, env-gated exactly as they were
//! in `cli/src/main.rs`. Compiled in ONLY under `--features test-hooks`; the
//! production twin returns the no-hook value for every one, so the surrounding
//! logic compiles and behaves as if the hook were absent.

#[cfg(feature = "test-hooks")]
mod on {
    /// P1: force every WebRTC link relay-only (models a hard-NAT peer).
    pub fn webrtc_relay_only() -> bool {
        std::env::var("TUNLION_TEST_WEBRTC_RELAY_ONLY").map(|v| v == "1").unwrap_or(false)
    }
    /// Suppress the Mode-B drop on recorder completion.
    pub fn disable_modeb_drop() -> bool {
        std::env::var("TUNLION_TEST_DISABLE_MODEB_DROP").is_ok()
    }
    /// Disable the deferred-link grace window.
    pub fn no_defer() -> bool {
        std::env::var("TUNLION_TEST_NO_DEFER").is_ok()
    }
    /// Daemon-survival gate (14c): make the first `n` peer adoptions fail the
    /// way an ICE-config timeout does. The count is a process-global latch,
    /// exactly as it was in `cli/src/main.rs`.
    static FAIL_ADOPT_USED: std::sync::atomic::AtomicU32 =
        std::sync::atomic::AtomicU32::new(0);
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
}

#[cfg(not(feature = "test-hooks"))]
mod off {
    #[inline] pub fn webrtc_relay_only() -> bool { false }
    #[inline] pub fn disable_modeb_drop() -> bool { false }
    #[inline] pub fn no_defer() -> bool { false }
    #[inline] pub fn fail_adopt() -> bool { false }
}

#[cfg(feature = "test-hooks")]
pub(crate) use on::*;
#[cfg(not(feature = "test-hooks"))]
pub(crate) use off::*;
