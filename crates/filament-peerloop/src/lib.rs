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
//! `l2::mux` carries the L2 wire vocabulary and the stream multiplexer, moved
//! out of `cli/src/l2.rs` in the next slice; its acceptor dial and live-session
//! cut go through `host::HostServices`, never the CLI.
//!
//! `recv` carries the host-free receive-side file mechanics lifted from
//! `cli/src/recv_files.rs`: the untrusted-name collision rule, the whole-file
//! digest, the `.part.meta` sidecar and the resumable-partial lifecycle, the
//! storage-failure vocabulary, the in-order `StdoutSink`, the `IncomingFile`
//! state, the whole-file verify and the confinement-safe `.part` open. It also
//! carries `recv::transfer_truth`, the host-free truth/decision half lifted
//! from `cli/src/transfer_truth.rs`: the sequential-accept rule, the resume
//! line, the partials a receive recorded and the ones actually kept, and the
//! sender-gone sentence. It also carries `recv::report`: the per-invocation
//! `RecvReport` (files, last refusal, outcome, `--json` object) that replaced
//! the CLI's process-global report state. The CLI re-exports them; what stays
//! there is the orchestration plus the host/UI adapters (`finalize_incoming`,
//! the inbox helpers, the rendered refusal, the exit-code mapping, and every
//! place a sentence is shown).
//!
//! What the crate still does NOT contain:
//! - the command surface (`send_cmd`, `recv_cmd`, the daemons, the roster UI):
//!   those decide what a person asked for and render it.
//! - anything that resolves a config directory, a `Paths`, or a keystore from
//!   the process environment. `host` defines the `LogSink` and `HostServices`
//!   traits the peer loop asks through, and the CLI implements them. `present`
//!   does the same for terminal state. One deliberate exception is
//!   `recv::store`, `recv::identity`, `recv::enrollment`, `recv::roster`,
//!   `recv::membership` and `recv::fleet_rv`: they read and write
//!   `devices.json`, the capability store, the identity sidecars, the overlay
//!   key, the roster files and the enrollment nonce/burn runtime, but every
//!   entry point is built from an explicit root/key/route path and nothing in
//!   them consults the environment.
//! Nothing here calls back into the CLI; the CLI depends on this crate.

#![cfg_attr(not(feature = "mesh"), doc = include_str!("mesh_disabled.md"))]

mod adoption;
pub mod access;
#[cfg(feature = "dispatch")]
pub mod access_session;
pub mod conn;
pub mod consent;
pub mod control;
pub mod daemon_ctl;
pub mod driver;
pub mod download_output;
pub mod exec_frame;
#[cfg(feature = "mount-server")]
pub mod fs_at;
pub mod holepunch;
pub mod host;
pub mod identity;
pub mod l2;
#[cfg(feature = "l3")]
pub mod l3;
pub mod limits;
pub mod link_manager;
pub mod liveness;
pub mod local;
#[cfg(feature = "mount-server")]
pub mod mount;
#[cfg(feature = "mount-server")]
pub mod mount_proto;
#[cfg(feature = "mesh")]
pub mod mesh;
mod petname;
pub mod present;
pub mod process;
pub mod recv;
pub mod refusal;
pub mod resilience;
mod retry;
pub mod secret;
#[cfg(feature = "dispatch")]
pub mod send;
pub mod session;
pub mod shell;
pub mod shell_gate;
pub mod ssh_ca;
pub mod sync;
#[cfg_attr(not(feature = "test-hooks"), allow(dead_code))]
pub(crate) mod test_hooks;
mod warm;

pub use adoption::{
    AdoptSource, active_binding_matches, match_adoption_source, peer_targetable,
};
pub use liveness::{RevokeRecheck, direct_permitted, ice_fallback_allowed, link_dead_for, link_has_live_for};
pub use petname::{LinkPetname, link_petname};
pub use retry::{schedule_retry, stuck_backoff};
pub use warm::{WarmBackoff, WarmHold};
