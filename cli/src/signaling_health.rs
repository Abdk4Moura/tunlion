//! CLI shim over `filament_peerloop::recv::signaling_health`.
//!
//! The signaling link's health record moved with the receive dispatch loop, so
//! the loop and the CLI's `status`/`doctor` read the SAME process state. Keeping
//! a second copy here made the daemon's `cap-status` report `unknown` while the
//! loop was reconnecting.
#![allow(unused_imports)]

pub(crate) use filament_peerloop::recv::signaling_health::*;

/// Observation cache for `status`/`doctor`; the loop's `Health` is the owner.
static REPORTED: std::sync::Mutex<Option<serde_json::Value>> = std::sync::Mutex::new(None);

pub(crate) fn report(snapshot: serde_json::Value) {
    *REPORTED.lock().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
}

pub(crate) fn snapshot_json() -> serde_json::Value {
    REPORTED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(|| serde_json::json!({ "state": "unknown", "connected": false }))
}
