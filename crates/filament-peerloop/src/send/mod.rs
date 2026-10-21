//! The shared send-side mechanics: source facts, the SPAKE2 ceremony, liveness
//! sentences and the byte-stream engine.
//!
//! The command surface and the interactive/fleet orchestration stay in the CLI.
//! This module is what both a CLI send and a library caller must run the same
//! way: the exact source digest/refusal, the exact ceremony, the exact chunk
//! loop and `file-end`, and the exact disconnection sentences.

pub mod ceremony;
pub mod engine;
pub mod liveness;
pub mod source;
pub mod stream;
