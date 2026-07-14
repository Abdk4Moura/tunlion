// Thin WASM shim — the real source lives at cli/src/pake/mod.rs.
// filament-pake is publish=false; used only for browser wasm builds.
// The shared source is SHA-identical, parity-gated (GATE4 interop).
//
// Keep pake/src/bin/ as-is (adversary, native_side) for the GATE4 parity
// test — those are built via cargo in this directory and path-include the
// shared source too.

#[path = "../../cli/src/pake/mod.rs"]
mod core;
pub use core::*;
