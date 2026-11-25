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

/// Virtual-time per-iteration loop budget oracle aligned with PR #731's
/// `LOOP-BUDGET-EXCEEDED` marker and 1 s busy threshold.
#[cfg(feature = "sim")]
pub struct SimLoopBudget {
    enabled: bool,
    iter_start: Option<filament_transport::clock::Instant>,
    idle_start: Option<filament_transport::clock::Instant>,
    idle_total: std::time::Duration,
    phase: &'static str,
    event: &'static str,
}

#[cfg(feature = "sim")]
impl SimLoopBudget {
    pub const BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            iter_start: None,
            idle_start: None,
            idle_total: std::time::Duration::ZERO,
            phase: "prelude",
            event: "none",
        }
    }

    pub fn finish_and_start(&mut self, log: &dyn crate::host::LogSink) {
        if !self.enabled {
            return;
        }
        let now = filament_transport::clock::now();
        if let Some(start) = self.iter_start {
            let total = now.saturating_duration_since(start);
            let busy = total.saturating_sub(self.idle_total);
            if busy >= Self::BUDGET {
                log.critical(&format!(
                    "LOOP-BUDGET-EXCEEDED {} {}/{} slowest_ms={} budget_ms={}",
                    busy.as_millis(),
                    self.phase,
                    self.event,
                    busy.as_millis(),
                    Self::BUDGET.as_millis()
                ));
            }
        }
        self.iter_start = Some(now);
        self.idle_start = None;
        self.idle_total = std::time::Duration::ZERO;
        self.phase = "prelude";
        self.event = "none";
    }

    pub fn begin_idle(&mut self) {
        if self.enabled {
            self.idle_start = Some(filament_transport::clock::now());
        }
    }

    pub fn end_idle(&mut self) {
        if self.enabled {
            if let Some(idle_start) = self.idle_start.take() {
                let elapsed = filament_transport::clock::now().saturating_duration_since(idle_start);
                self.idle_total = self.idle_total.saturating_add(elapsed);
            }
        }
    }

    pub fn set_phase(&mut self, phase: &'static str, event: &'static str) {
        if self.enabled {
            self.phase = phase;
            self.event = event;
        }
    }
}

#[cfg(feature = "sim")]
pub(crate) fn sim_ev_kind(ev: &filament_transport::net::Ev) -> &'static str {
    use filament_transport::net::Ev;
    match ev {
        Ev::Lan(_) => "lan",
        Ev::Welcome(_) => "welcome",
        Ev::PeerJoined(_) => "peer-joined",
        Ev::PeerLeft(_) => "peer-left",
        Ev::Signal(_) => "signal",
        Ev::PairCode(_) => "pair-code",
        Ev::PairOk(_) => "pair-ok",
        Ev::PairMatched(_) => "pair-matched",
        Ev::PairUsed(_) => "pair-used",
        Ev::PairError(_) => "pair-error",
        Ev::KnownPeer(_) => "known-peer",
        Ev::KnownPeerLeft(_) => "known-peer-left",
        Ev::Synced(_) => "synced",
        Ev::SignalingAlive => "signaling-alive",
        Ev::BuildWake => "build-wake",
        Ev::ChannelReady(..) => "channel-ready",
        Ev::DirectReady(..) => "direct-ready",
        Ev::DirectUpgradeReady(..) => "direct-upgrade-ready",
        Ev::DirectWorkersReady(..) => "direct-workers-ready",
        Ev::ReplaySource(_) => "replay-source",
        Ev::ReplayDeparture(..) => "replay-departure",
        Ev::Control(..) => "control",
        Ev::Sourced { inner, .. } => sim_ev_kind(inner),
        Ev::LocalControl(..) => "local-control",
        Ev::LocalPcState(..) => "local-pc-state",
        Ev::Chunk(..) => "chunk",
        Ev::PcState(..) => "pc-state",
        Ev::TransferDone(_) => "transfer-done",
        Ev::TransferFailed { .. } => "transfer-failed",
        Ev::MaybeComplete(..) => "maybe-complete",
        Ev::Stuck(..) => "stuck",
        Ev::TransferStalled(..) => "transfer-stalled",
        Ev::GraceExpired(..) => "grace-expired",
        Ev::RetryLink(..) => "retry-link",
        Ev::SignalingDown(..) => "signaling-down",
        Ev::DropLink(_) => "drop-link",
        Ev::Interrupted => "interrupted",
        Ev::StdinLine(_) => "stdin-line",
        Ev::AttemptDrained(_) => "attempt-drained",
    }
}
