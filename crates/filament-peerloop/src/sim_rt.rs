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

/// Execute blocking work via `tokio::task::spawn_blocking` in production, or
/// inline on the current-thread sim runtime under `--features sim`.
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
        Ok(f())
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
