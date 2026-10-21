//! An OPTIONAL iroh relay rung for tunlion's transport ladder.
//!
//! # What this is
//!
//! A bounded proof of concept: two local nodes meet through an iroh relay, open
//! a bidirectional QUIC stream through the frame format the existing
//! [`filament_transport::net::Transport`] trait already speaks, echo bytes, and
//! exchange a datagram. The direct-QUIC, WebRTC and TURN paths are untouched;
//! this crate is a second `impl Transport`, and nothing calls it unless a host
//! asks for it.
//!
//! # What this is not
//!
//! - Not a replacement for the ladder. There is no call-site change, no default
//!   route and no forced relay.
//! - Not a second identity. tunlion's Ed25519 device key is the trust root; the
//!   iroh endpoint key is derived from it and published with a device-key
//!   signature (or, in [`NodeKeyMode::Direct`], *is* the device key).
//! - Not an SLA. Relay URLs are explicit and may be down. A failed relay is an
//!   `Err`, and the caller keeps whatever transport it already had.
//!
//! # Gates
//!
//! Two gates, both closed by default:
//!
//! ```text
//! cargo feature : iroh-transport     (this crate)
//! runtime env   : FILAMENT_IROH=1   (a host's opt-in, checked by `enabled()`)
//! ```
//!
//! The runtime gate exists so a build that *contains* the code does not use it
//! unless an operator or a gate asks. The crate feature exists so a build that
//! does not want iroh in its dependency graph does not get it.
//!
//! # Layout
//!
//! - [`identity`]: device Ed25519 key -> iroh node key + signed binding record.
//! - [`relay`]: explicit relay list, loopback-only insecure TLS, health probes.
//! - [`transport`]: [`IrohTransport`] (the `Transport` impl) and [`IrohNode`].
//!
//! With the feature off this module tree is absent; only the gate helpers and
//! the wire constants remain, so a consumer can ask "is iroh compiled in?"
//! without linking it.

/// ALPN used by this PoC. A separate value from the direct-QUIC one on purpose:
/// an iroh endpoint and a quinn endpoint must never negotiate each other's
/// protocol by accident.
pub const ALPN: &[u8] = b"filament/iroh-transport/1";

/// Cargo feature that compiles the implementation.
pub const FEATURE: &str = "iroh-transport";

/// Environment variable a host sets to opt into an iroh attempt at runtime.
pub const ENV_FLAG: &str = "FILAMENT_IROH";

/// Pure form of [`enabled`], so the rule is testable without mutating a
/// process-global environment in parallel tests.
///
/// Accepts `1` or `true`; everything else (including unset) is off.
pub fn enabled_with(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true"))
}

/// Is an iroh attempt allowed in this process?
///
/// This says nothing about whether the relay is reachable or the crate was
/// compiled with the feature. It is only the operator's opt-in.
pub fn enabled() -> bool {
    enabled_with(std::env::var(ENV_FLAG).ok().as_deref())
}

/// Was the implementation compiled into this build?
pub const fn compiled_in() -> bool {
    cfg!(feature = "iroh-transport")
}

#[cfg(feature = "iroh-transport")]
pub mod identity;
#[cfg(feature = "iroh-transport")]
pub mod relay;
#[cfg(feature = "iroh-transport")]
pub mod transport;

#[cfg(feature = "iroh-transport")]
pub use identity::{DeviceIdentity, IrohBinding, NodeKeyMode};
#[cfg(feature = "iroh-transport")]
pub use relay::{RelayEndpoint, RelayHealth, RelayPlan};
#[cfg(feature = "iroh-transport")]
pub use transport::{IrohConfig, IrohNode, IrohTransport, MAX_PAYLOAD};

#[cfg(test)]
mod gate_tests {
    use super::*;

    #[test]
    fn runtime_gate_is_off_unless_explicitly_on() {
        assert!(!enabled_with(None));
        assert!(!enabled_with(Some("0")));
        assert!(!enabled_with(Some("")));
        assert!(!enabled_with(Some("yes")));
        assert!(enabled_with(Some("1")));
        assert!(enabled_with(Some("true")));
    }

    #[test]
    fn compiled_in_matches_the_feature() {
        assert_eq!(compiled_in(), cfg!(feature = "iroh-transport"));
    }
}
