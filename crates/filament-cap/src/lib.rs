//! filament-cap: capability primitives + pure authorization evaluation.
//!
//! Carved out of the CLI as a PARTIAL extraction. See `Cargo.toml` for the
//! boundary rationale. The CLI re-exports these two modules via
//! `pub use filament_cap::capability::*;` / `pub use filament_cap::ephemeral::*;`
//! so its `crate::capability::X` / `crate::ephemeral::X` call sites resolve
//! unchanged, and keeps the host-bound orchestration (store I/O, mode flag,
//! observability counters, the DeviceCert-reading glue) alongside those
//! re-exports.
//!
//! The transfer-admission policy (TransferGateInput / TransferDecision /
//! TransferDeny / BindingStrength / IdentityState / CapOutcome /
//! transfer_decision / the proven and expiry composers) lives in the
//! dependency-free `filament-policy` crate and is re-exported by
//! [`capability`] under its historical paths. That crate has no clock: `now` is
//! an input, which is what lets the browser compile the same decision.

pub mod capability;
pub mod ephemeral;
pub mod fleet_grants;
