//! Generates the Kotlin (and other) bindings for `tunlion-core`.
//!
//!   cargo run --manifest-path crates/tunlion-core/Cargo.toml \
//!     --features cli --bin uniffi-bindgen -- \
//!     generate --library <path-to-libtunlion_core.so> --language kotlin --out-dir <dir>
//!
//! `--library` reads the metadata out of the built shared object, so the
//! bindings always match the symbols they will call.

fn main() {
    uniffi::uniffi_bindgen_main()
}
