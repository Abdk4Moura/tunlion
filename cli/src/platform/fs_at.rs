//! CLI shim over `filament_peerloop::fs_at`.
//!
//! The directory-relative metadata/read primitives moved with the mount server
//! (`git mv`), so the security-reviewed implementation has one home. The CLI's
//! `platform::fs_at` name still resolves for its own mode setters.
#![allow(unused_imports)]

pub use filament_peerloop::fs_at::*;
