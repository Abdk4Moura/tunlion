//! filament-cap: capability primitives + pure authorization evaluation.
//!
//! Carved out of the CLI as a PARTIAL extraction. See `Cargo.toml` for the
//! boundary rationale. The CLI re-exports these two modules via
//! `pub use filament_cap::capability::*;` / `pub use filament_cap::ephemeral::*;`
//! so its `crate::capability::X` / `crate::ephemeral::X` call sites resolve
//! unchanged, and keeps the host-bound orchestration (store I/O, mode flag,
//! observability counters, the DeviceCert-reading glue) alongside those
//! re-exports.

pub mod capability;
pub mod ephemeral;
