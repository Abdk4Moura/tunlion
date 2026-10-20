//! Peer-identity proof and expose lifecycle, as the CLI's process adapter.
//!
//! The implementation moved to `filament_peerloop::recv::identity`
//! (`IdentityService`), where the store root, the overlay key path and the log
//! sink are explicit per instance. This module builds that service on the
//! process paths and forwards, so the old function names keep resolving for
//! the receive loop and the one-shot sender.
//!
//! `resolve_peer_identity` and `principal_after_liveness` already live with
//! `Link` in `filament_peerloop::identity`; they stay re-exported here because
//! the rest of this module and the CLI's tests still call them.

use crate::identity;
use crate::net::Transport;
use anyhow::Result;
use filament_peerloop::host::LogSink;
use filament_peerloop::recv::identity::IdentityService;
use filament_peerloop::recv::store::OverlayKey;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// `resolve_peer_identity` and `principal_after_liveness` moved into
/// `filament-peerloop::identity` with `Link`. The names stay imported here
/// because the rest of the module and the CLI's tests still call them.
pub(crate) use filament_peerloop::identity::{principal_after_liveness, resolve_peer_identity};

/// The possession challenge's live window. The constant lives with the service
/// that holds the challenge.
pub(crate) use filament_peerloop::recv::identity::PROVEN_CHALLENGE_DEADLINE;

/// The intro scope a vouch stores. A vouch introduces a DEVICE, not a user.
pub(crate) use filament_peerloop::recv::identity::VOUCH_CERT_SCOPE;

/// Build the identity service on this process's paths, with the caller's log
/// sink. The receive loop owns one; each one-shot send/exec/shell flow builds
/// one and reuses it for that flow's challenges.
pub(crate) fn service_with_log(log: Arc<dyn LogSink>) -> IdentityService {
    IdentityService::new(
        crate::devices_store::store(),
        OverlayKey::new(crate::platform::Paths::config_path("overlay.ed25519")),
        crate::display_name(),
        crate::identity_state::gate_settle_ms(),
        log,
    )
}

pub(crate) async fn issue_proven_challenge_and_hold(
    identity: &IdentityService,
    conn: &crate::Conn,
    pid: &str,
    t: &Arc<dyn Transport>,
    pending_proven: &Arc<std::sync::Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) {
    identity
        .issue_proven_challenge_and_hold(conn, pid, t, pending_proven, identity_nonces)
        .await
}

pub(crate) async fn respond_to_identity_challenge(
    identity: &IdentityService,
    t: &Arc<dyn Transport>,
    v: &Value,
) {
    identity.respond_to_identity_challenge(t, v).await
}

pub(crate) fn handle_identity_expose(
    identity: &IdentityService,
    conn: &mut crate::Conn,
    pid: &str,
    v: &Value,
    identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) -> bool {
    identity.handle_identity_expose(conn, pid, v, identity_nonces)
}

pub(crate) fn hold_expired(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

pub(crate) async fn resend_identity_challenge(
    identity: &IdentityService,
    conn: &crate::Conn,
    pid: &str,
    identity_nonces: &HashMap<String, ([u8; 32], Instant, [u8; 32])>,
) -> bool {
    identity
        .resend_identity_challenge(conn, pid, identity_nonces)
        .await
}

pub(crate) fn update_peer_identity(
    name: &str,
    peer_cert: &identity::DeviceCert,
    scope: u8,
) -> Result<()> {
    crate::devices_store::store().update_peer_identity(name, peer_cert, scope)
}

/// Store provisional identity (held in memory, not durable trust) for later overlay check.
/// Written to a temp file, not devices.json, so a failed overlay session leaves no anchor.
pub(crate) fn store_provisional_identity(
    name: &str,
    peer_cert: &identity::DeviceCert,
) -> Result<()> {
    crate::devices_store::store().store_provisional_identity(name, peer_cert)
}

/// How long a provisional identity is worth keeping. It exists to bridge one
/// session's identity proof to that session's overlay announcement, which
/// follows within seconds; an hour is generous.
pub(crate) use filament_peerloop::recv::store::PROVISIONAL_TTL_SECS;

/// Remove provisional identity records under `dir` older than
/// PROVISIONAL_TTL_SECS (by their `storedAt`, or the file's mtime when that is
/// unreadable). Returns how many were removed. Best effort: a file that cannot
/// be removed is left for the next sweep or `tunlion reset`.
pub(crate) use filament_peerloop::recv::store::sweep_stale_provisional;

pub(crate) fn load_provisional_identity(name: &str) -> Option<identity::DeviceCert> {
    crate::devices_store::store().load_provisional_identity(name)
}

pub(crate) fn clear_provisional_identity(name: &str) {
    crate::devices_store::store().clear_provisional_identity(name)
}

#[cfg(test)]
mod provisional_sweep_tests {
    use super::{sweep_stale_provisional, PROVISIONAL_TTL_SECS};

    #[test]
    fn stale_provisional_identities_are_collected_and_fresh_ones_kept() {
        let dir = std::env::temp_dir().join(format!("fil-prov-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = 10_000_000u64;
        let write = |name: &str, at: u64| {
            std::fs::write(
                dir.join(format!("provisional_{name}.json")),
                serde_json::json!({"name": name, "storedAt": at}).to_string(),
            )
            .unwrap();
        };
        write("peer-old", now - PROVISIONAL_TTL_SECS - 1);
        write("peer-older", 1);
        write("peer-fresh", now - 5);
        std::fs::write(dir.join("devices.json"), b"[]").unwrap();
        assert_eq!(sweep_stale_provisional(&dir, now), 2);
        assert!(
            dir.join("provisional_peer-fresh.json").exists(),
            "a live session keeps its record"
        );
        assert!(!dir.join("provisional_peer-old.json").exists());
        assert!(
            dir.join("devices.json").exists(),
            "only provisional records are swept"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
