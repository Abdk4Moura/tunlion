//! Deterministic runtime helpers for simulation builds (`--features sim`).
//!
//! In default builds, `SimHashMap`/`SimHashSet` alias standard `HashMap`/`HashSet`
//! with `RandomState`, and `run_blocking` delegates to `tokio::task::spawn_blocking`.
//! Under `sim`, maps use a fixed FNV-1a hasher for deterministic iteration order
//! and blocking closures execute inline on the single-threaded runtime.

use std::hash::{BuildHasher, Hasher};

/// Fixed 64-bit FNV-1a hasher for deterministic map iteration under `sim`.
#[derive(Clone, Copy, Default, Debug)]
pub struct DetBuildHasher;

pub struct DetHasher(u64);

impl Default for DetHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for DetHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

impl BuildHasher for DetBuildHasher {
    type Hasher = DetHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DetHasher::default()
    }
}

#[cfg(not(feature = "sim"))]
pub type SimHashMap<K, V> = std::collections::HashMap<K, V>;

#[cfg(not(feature = "sim"))]
pub type SimHashSet<K> = std::collections::HashSet<K>;

#[cfg(feature = "sim")]
pub type SimHashMap<K, V> = std::collections::HashMap<K, V, DetBuildHasher>;

#[cfg(feature = "sim")]
pub type SimHashSet<K> = std::collections::HashSet<K, DetBuildHasher>;

#[cfg(feature = "sim")]
thread_local! {
    static SIM_BLOCKING_INLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Enable inline execution of `run_blocking` closures inside the deterministic
/// simulation harness while keeping `spawn_blocking` active for regular tests.
pub fn set_sim_blocking_inline(inline: bool) {
    #[cfg(feature = "sim")]
    SIM_BLOCKING_INLINE.with(|cell| cell.set(inline));
    #[cfg(not(feature = "sim"))]
    let _ = inline;
}

#[cfg(feature = "sim")]
pub(crate) fn is_sim_blocking_inline() -> bool {
    SIM_BLOCKING_INLINE.with(|cell| cell.get())
}

/// Execute blocking work via `tokio::task::spawn_blocking` in production (or
/// when inline sim mode is inactive), or inline on the current-thread sim runtime.
pub async fn run_blocking<F, R>(f: F) -> Result<R, tokio::task::JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[cfg(not(feature = "sim"))]
    {
        tokio::task::spawn_blocking(f).await
    }
    #[cfg(feature = "sim")]
    {
        if SIM_BLOCKING_INLINE.with(|cell| cell.get()) {
            Ok(f())
        } else {
            tokio::task::spawn_blocking(f).await
        }
    }
}

#[cfg(feature = "sim")]
thread_local! {
    static SIM_DISABLE_WATCHDOG: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Disable spawning the real-time OS `loop-watchdog` thread while running in
/// the deterministic simulation harness.
pub fn set_sim_watchdog_disabled(disabled: bool) {
    #[cfg(feature = "sim")]
    SIM_DISABLE_WATCHDOG.with(|cell| cell.set(disabled));
    #[cfg(not(feature = "sim"))]
    let _ = disabled;
}

pub fn is_sim_watchdog_disabled() -> bool {
    #[cfg(feature = "sim")]
    {
        SIM_DISABLE_WATCHDOG.with(|cell| cell.get())
    }
    #[cfg(not(feature = "sim"))]
    {
        false
    }
}

#[cfg(feature = "sim")]
thread_local! {
    static SIM_INLINE_STALL_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Inject a one-shot virtual-time inline stall inside the daemon event loop
/// (`recv_run`) under `--features sim` to verify the loop-budget oracle.
#[cfg(feature = "sim")]
pub fn set_sim_inline_stall_ms(ms: u64) {
    SIM_INLINE_STALL_MS.with(|cell| cell.set(ms));
}

#[cfg(feature = "sim")]
pub(crate) fn take_sim_inline_stall_ms() -> u64 {
    SIM_INLINE_STALL_MS.with(|cell| cell.replace(0))
}

/// Read-only per-run loop-budget telemetry collected for search guidance.
/// Guidance uses continuous metrics here (`max_iter_busy_ms`, phase histogram)
/// and never alters `recv::loop_budget::BUDGET` or any oracle threshold.
#[cfg(feature = "sim")]
#[derive(Debug, Clone, Default)]
pub struct SimTelemetry {
    pub iterations: u64,
    pub max_iter_busy_ms: u64,
    pub max_slowest_ms: u64,
    pub max_phase: String,
    pub max_event: String,
    pub phases_hit: std::collections::BTreeMap<String, u64>,
    pub events_hit: std::collections::BTreeMap<String, u64>,
    pub phase_first_seen_ms: std::collections::BTreeMap<String, u64>,
}

#[cfg(feature = "sim")]
thread_local! {
    static SIM_TELEMETRY: std::cell::RefCell<SimTelemetry> =
        std::cell::RefCell::new(SimTelemetry::default());
}

#[cfg(feature = "sim")]
pub fn reset_sim_telemetry() {
    SIM_TELEMETRY.with(|cell| *cell.borrow_mut() = SimTelemetry::default());
}

#[cfg(feature = "sim")]
pub(crate) fn record_iter_busy(
    busy_ms: u64,
    slowest_ms: u64,
    phase: &'static str,
    event: &'static str,
) {
    let now = filament_transport::clock::now_ms();
    SIM_TELEMETRY.with(|cell| {
        let mut t = cell.borrow_mut();
        t.iterations = t.iterations.saturating_add(1);
        if busy_ms >= t.max_iter_busy_ms {
            t.max_iter_busy_ms = busy_ms;
            t.max_phase = phase.to_string();
            t.max_event = event.to_string();
        }
        if slowest_ms > t.max_slowest_ms {
            t.max_slowest_ms = slowest_ms;
        }
        *t.phases_hit.entry(phase.to_string()).or_insert(0) += 1;
        *t.events_hit.entry(event.to_string()).or_insert(0) += 1;
        t.phase_first_seen_ms.entry(phase.to_string()).or_insert(now);
    });
}

#[cfg(feature = "sim")]
pub fn take_sim_telemetry() -> SimTelemetry {
    SIM_TELEMETRY.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

#[cfg(feature = "sim")]
thread_local! {
    static SIM_PRNG_STATE: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0x9E37_79B9_7F4A_7C15) };
}

#[cfg(feature = "sim")]
pub fn reset_sim_rng(seed: u64) {
    SIM_PRNG_STATE.with(|cell| cell.set(seed ^ 0x9E37_79B9_7F4A_7C15));
}

#[cfg(feature = "sim")]
pub fn next_sim_u64() -> u64 {
    SIM_PRNG_STATE.with(|cell| {
        let state = cell.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        cell.set(state);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    })
}
