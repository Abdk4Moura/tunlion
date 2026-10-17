//! L2: the wire vocabulary and the stream multiplexer, carved out of
//! `cli/src/l2.rs`.
//!
//! This module owns the part of L2 that is a protocol and a router, not a
//! command: stream ids, the per-link stream table, the open/ack/close state
//! machine, and the pumps between a data-channel stream and a local socket.
//! It has no terminal, no settings, and no link establishment; the acceptor's
//! two host edges go through [`crate::host::HostServices`].
//!
//! Later slices add siblings here (PTY sessions, link bring-up, forward, proxy,
//! mesh, ssh, mount) rather than growing `cli/src/l2.rs` again. Every item
//! `cli/src/l2.rs` re-exports keeps its old path, so existing callers do not
//! change.

pub mod mux;

pub use mux::{
    ExecCtl, L2_SID_BASE, MAX_STREAMS_PER_LINK, Mux, OpenOutcome, OpenVerdict, PipeItem,
    TreeSignal, is_l2_sid, serve_stream, wire_sid,
};
