//! What a transfer says about itself when it resumes, writes to a stream, or
//! loses its peer.
//!
//! The implementation lives in `filament-peerloop::recv::transfer_truth`, the
//! host-free receive crate. This module is only a re-export shim so every
//! `crate::transfer_truth::…` call site keeps resolving to the one
//! implementation. Rendering the sentences, choosing the directory, and
//! deciding when a receive is over all stay in the CLI; the library never calls
//! back into it.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::recv::transfer_truth::{
    KeptPartial, SessionPart, accept_is_sequential, kept_partials, note_part, resume_line,
    sender_gone_message,
};
