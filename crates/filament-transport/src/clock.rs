//! Virtualizable monotonic clock seam for deterministic simulation builds.
//!
//! Under default builds (`not(feature = "sim")`), `Instant` is
//! `std::time::Instant` with zero runtime overhead. Under `--features sim`,
//! `Instant` is `tokio::time::Instant` so `tokio::time::pause()` controls every
//! timer, deadline, and recency calculation across the transport and peer loop.

#[cfg(not(feature = "sim"))]
mod imp {
    use std::sync::OnceLock;

    pub type Instant = std::time::Instant;

    #[inline]
    pub fn now() -> Instant {
        Instant::now()
    }

    pub fn now_ms() -> u64 {
        static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
        EPOCH
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }

    #[inline]
    pub fn reset_sim_epoch() {}
}

#[cfg(feature = "sim")]
mod imp {
    use std::cell::Cell;

    pub type Instant = tokio::time::Instant;

    thread_local! {
        static SIM_EPOCH: Cell<Option<tokio::time::Instant>> = const { Cell::new(None) };
    }

    /// Reset the thread-local epoch used by `now_ms()` at the start of a
    /// simulation runtime so sequential runs in one process start at 0 ms.
    pub fn reset_sim_epoch() {
        SIM_EPOCH.with(|cell| cell.set(Some(tokio::time::Instant::now())));
    }

    #[inline]
    pub fn now() -> Instant {
        tokio::time::Instant::now()
    }

    pub fn now_ms() -> u64 {
        let cur = tokio::time::Instant::now();
        SIM_EPOCH.with(|cell| {
            let epoch = match cell.get() {
                Some(ep) if cur >= ep => ep,
                _ => {
                    cell.set(Some(cur));
                    cur
                }
            };
            cur.saturating_duration_since(epoch).as_millis() as u64
        })
    }
}

pub use imp::{now, now_ms, reset_sim_epoch, Instant};
