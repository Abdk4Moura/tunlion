//! L2: the wire vocabulary and the stream multiplexer, carved out of
//! `cli/src/l2.rs`.
//!
//! This module owns the part of L2 that is a protocol and a router, not a
//! command: stream ids, the per-link stream table, the open/ack/close state
//! machine, and the pumps between a data-channel stream and a local socket.
//! It has no terminal, no settings, and no link establishment; the acceptor's
//! two host edges go through [`crate::host::HostServices`].
//!
//! Later slices add siblings here (forward admission, PTY sessions, link
//! bring-up, proxy, mesh, ssh, mount) rather than growing `cli/src/l2.rs` again.
//! Every item `cli/src/l2.rs` re-exports keeps its old path, so existing
//! callers do not change.

pub mod forward;
pub mod mux;
pub mod policy;
pub mod warm;

use std::collections::HashMap;
use std::sync::Arc;

/// The per-peer mux table the receive driver owns. Every L2 sector (mount,
/// forward, pty, exec, sync) receives THIS map: one SID namespace and one
/// close/ack path per link, never a private mux.
pub type MuxMap = HashMap<String, Arc<mux::Mux>>;

pub use mux::{
    ExecCtl, L2_SID_BASE, MAX_STREAMS_PER_LINK, Mux, OpenOutcome, OpenVerdict, PipeItem,
    TreeSignal, is_l2_sid, serve_stream, wire_sid,
};
pub use warm::{open_stream, open_stream_verified_reason, WarmOpen};
#[cfg(unix)]
pub use warm::{
    open_pty_stream_verified, serve_opened_stream, serve_verified_stream, warm_verify_window,
    WarmPtyVerdict,
};

/// Process-wide live-PTY cap shared by acceptors and hosts.
pub const MAX_PTYS_GLOBAL: usize = 32;
/// Close reason for a resume with no live session.
pub const NO_SUCH_SESSION: &str = "no such session";
