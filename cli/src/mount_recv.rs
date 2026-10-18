//! CLI shim over `filament_peerloop::mount`.
//!
//! The inbound mount-open admission moved to the peer-loop crate with the
//! protocol and the pure gate. The receive driver still owns the serving guard
//! (`l2_enabled`), the shared per-peer mux map, the fresh share root and the
//! task lifetime: it calls this function and drops the returned handle, which is
//! today's detached behaviour.
pub(crate) use filament_peerloop::mount::handle_mount_open;
