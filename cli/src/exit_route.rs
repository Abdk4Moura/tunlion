//! CLI shim for the exit-route plan.
//!
//! The plan and its tests moved to `filament_peerloop::l3::exit_route`. The only
//! CLI fact left is WHICH signaling server this machine talks to, so
//! `signaling_addrs` resolves that setting here and hands the host to the
//! library's pure resolver.
/// Addresses of the configured signaling server, resolved now. The library
/// takes the server host; this wrapper reads the CLI setting.
pub fn signaling_addrs() -> Vec<std::net::IpAddr> {
    let server = crate::settings::get_str("server", None)
        .unwrap_or_else(|| crate::DEFAULT_SERVER.to_string());
    filament_peerloop::l3::exit_route::signaling_addrs_for(&server)
}
