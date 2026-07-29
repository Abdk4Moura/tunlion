// Thin WASM shim — the real source now lives in the standalone `filament-pair`
// crate (crates/filament-pair). filament-pake is publish=false; used only for
// browser wasm builds. Re-exporting keeps the wasm-bindgen surface (mod wasm in
// filament-pair's lib.rs) and every public fn available under `filament_pake::*`.
//
// The GATE4 parity bins (src/bin/adversary.rs, native_side.rs) `use
// filament_pake::…` and resolve through this re-export unchanged.
pub use filament_pair::*;
