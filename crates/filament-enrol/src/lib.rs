//! Host-free enrolment ceremony and device identity.
//!
//! This crate is the shared half of the CLI's `pair` enrolment: the sealed
//! `enrol-offer` and `enrol-grant` frames, the owner's decision, the pure
//! certificate verification and the final outcome. It exists so the CLI and a
//! browser compile and test the SAME code instead of two copies that drift.
//!
//! ## Boundary
//!
//! No `std::fs`, no clock, no runtime, no network stack, no `secret-write` and
//! no native TLS. Time (`now`), randomness (nonces and seeds), key material
//! (`UserKey`, injected signers) and storage (`SeedStore`) are inputs. The only
//! crypto is `filament-id`'s ring-backed Ed25519, HKDF and ChaCha20-Poly1305;
//! this crate adds no second implementation.
//!
//! ## Not done here
//!
//! This is the core of the browser fleet slice, not the slice itself. The
//! frontend is not wired to this API, no wasm artefact is generated, and a
//! browser is NOT yet a fleet device: until the frontend state machine drives
//! these calls, pairs the ceremony with its transport and persists the grant,
//! a browser remains a pairwise-only peer.

#![forbid(unsafe_code)]

mod error;
mod expose;
mod frame;
mod grant;
mod hexwire;
mod identity;
mod offer;
mod outcome;

pub use error::{EnrolError, Result};
pub use expose::{build_identity_expose, is_identity_expose, open_identity_expose};
pub use frame::{EnrolGrant, EnrolOffer, FrameKind, IdentityExpose};
pub use grant::{
    open_enrol_grant, seal_enrol_grant, verify_cert_chain, verify_mesh_grant, VerifiedMeshGrant,
};
pub use identity::{DeviceIdentity, RandomSource, SeedStore};
pub use offer::{build_enrol_offer, is_enrol_offer, open_enrol_offer};
pub use outcome::{
    browser_hint, enrol_offer_decision, enrolment_outcome, EnrolOfferDecision, EnrolOfferInputs,
    EnrolOutcome, EnrolOutcomeInputs,
};

/// The version of the offer frame this crate emits.
pub const ENROL_OFFER_VERSION: u8 = 1;
/// The version of the grant frame this crate emits.
pub const ENROL_GRANT_VERSION: u8 = 1;
/// The version of the identity-expose frame this crate emits.
pub const IDENTITY_EXPOSE_VERSION: u8 = 2;
