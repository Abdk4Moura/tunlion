//! CLI shim over `filament_peerloop::send::ceremony`.
//!
//! The SPAKE2 state machine moved into the library with the send engine it
//! serves. `pair` and the transfer path still import the same names through this
//! module, so there is one ceremony implementation, not a CLI copy and a library
//! copy.

#![allow(unused_imports)]

pub(crate) use filament_peerloop::send::ceremony::{
    Ceremony, Inbound, Partner, addressed_to, b64_decode, b64_encode, pair_v2_caps, partner_for,
};
