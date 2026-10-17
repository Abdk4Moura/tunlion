//! The peer loop's policy, without the host.
//!
//! This is the host-free decision layer of `cli/src/conn.rs`, carved out so the
//! later move of `Conn` itself is a `git mv`. Everything here decides something
//! about the LINKS, and nothing here has an opinion about how a peer was found,
//! authenticated or named, where files live on this machine, or how anything is
//! rendered to a terminal. That is the test `docs/design-libfilament.md` sets for
//! what may leave the CLI, and it is why this crate calls back into nothing: the
//! caller builds the observation, asks in here, and carries out the answer.
//!
//! Why the split is worth a crate rather than a module, from this repo's own
//! history: the fleet identity handshake was written twice, inline, and four bugs
//! came out of the divergence; the close-reason hole was fixed for `mount` and
//! survived in `pty` because nobody walked the other copy. A module boundary is not
//! decoration here, it is the thing that makes a whole class of bug unwritable. The
//! warm-hold machine below is the first proof: its ~95s re-dial cycle came from the
//! same rule living in two places under two names.
//!
//! What is deliberately NOT here, and WHY:
//! - `Conn` itself: it carries `Arc<dyn Transport>`, `Arc<Peer>`, a signaling
//!   client and tokio channels, and every command's event loop manipulates it. It
//!   moves in the next slice, on top of this crate.
//! - `Link`: it holds a live transport, a WebRTC peer and an identity binding, and
//!   one of its methods reads the shell gate. Its petname rule is here as the
//!   `petname::LinkPetname` trait the CLI implements for it.
//! - presentation (`shown`, `label`, `display_name_of`, `link_kind`, the roster):
//!   it renders, and rendering is the CLI's.
//! - anything that reads settings, devices.json, the keystore or a `Paths`.
//!
//! `host` is the seam for those last two: it defines the `LogSink` and
//! `HostServices` traits the peer loop asks through, plus host-free defaults,
//! so `Conn` can carry an injected sink and host instead of importing the CLI.
//! Nothing here calls back into the CLI; the CLI implements the traits.

mod adoption;
pub mod host;
mod liveness;
mod petname;
mod retry;
mod warm;

pub use adoption::{
    AdoptSource, active_binding_matches, match_adoption_source, peer_targetable,
};
pub use liveness::{direct_permitted, ice_fallback_allowed, link_dead_for, link_has_live_for};
pub use petname::{LinkPetname, link_petname};
pub use retry::{schedule_retry, stuck_backoff};
pub use warm::{WarmBackoff, WarmHold};
