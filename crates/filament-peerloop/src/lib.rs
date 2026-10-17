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
//! `Conn` and `Link` moved here in issue #465 slice 3, as a `git mv` from
//! `cli/src/conn.rs`, together with the policy modules they own: `resilience`
//! (the stall ladder), `link_manager` (placement and warm-cutover decisions),
//! `local` (the loopback TCP transport) and `holepunch` (rung-2 STUN + UDP
//! punch). `identity` carries `resolve_peer_identity`, which operates on `Link`.
//!
//! What the crate still does NOT contain:
//! - the command surface (`send_cmd`, `recv_cmd`, the daemons, the roster UI):
//!   those decide what a person asked for and render it.
//! - anything that reads settings, devices.json, the keystore or a `Paths`:
//!   `host` defines the `LogSink` and `HostServices` traits the peer loop asks
//!   through, plus host-free defaults, and the CLI implements them.
//! Nothing here calls back into the CLI; the CLI depends on this crate.

mod adoption;
pub mod conn;
pub mod holepunch;
pub mod host;
pub mod identity;
pub mod limits;
pub mod link_manager;
pub mod liveness;
pub mod local;
mod petname;
pub mod resilience;
mod retry;
pub mod shell;
#[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
pub(crate) mod test_hooks;
mod warm;

pub use adoption::{
    AdoptSource, active_binding_matches, match_adoption_source, peer_targetable,
};
pub use liveness::{direct_permitted, ice_fallback_allowed, link_dead_for, link_has_live_for};
pub use petname::{LinkPetname, link_petname};
pub use retry::{schedule_retry, stuck_backoff};
pub use warm::{WarmBackoff, WarmHold};
