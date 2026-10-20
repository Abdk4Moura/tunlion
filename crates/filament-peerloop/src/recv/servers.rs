//! Inbound server protocol that is host-free, with the process effects behind
//! [`RecvServers`](crate::recv::ports::RecvServers).
//!
//! The forward stream admission and its refusal/park ordering live here. The
//! host supplies only its configuration answers (`is_exposed`,
//! `forward_target_allowed`) and the optional dial implementation.

use crate::host::HostServices;
use crate::l2::forward;
use crate::l2::Mux;
use crate::recv::dispatch::{park_on_deny, ParkKind, ParkedOpen};
use crate::recv::ports::RecvPorts;
use crate::shell_gate::ShellPolicy;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub async fn open_forward(
    ports: &RecvPorts,
    host: &dyn HostServices,
    conn: &mut crate::conn::Conn,
    pid: String,
    v: &Value,
    shell_policy: &ShellPolicy,
    muxes: &mut HashMap<String, Arc<Mux>>,
    l2_enabled: bool,
    parked: &mut Vec<ParkedOpen>,
) -> Option<tokio::task::JoinHandle<()>> {
    let is_exposed = |port: u16| ports.servers.is_exposed(port);
    let target_allowed =
        |name: &str, host: &str, port: u16| ports.servers.forward_target_allowed(name, host, port);
    let cfg = forward::ForwardConfig {
        shell_policy,
        l2_enabled,
        l2_forced: ports.env.l2_forced,
        is_exposed: &is_exposed,
        target_allowed: &target_allowed,
    };
    match forward::admit_forward_open(conn, &pid, v, muxes, &cfg).await {
        forward::ForwardAdmission::Accepted {
            sid,
            host,
            port,
            rx,
            mux,
        } => {
            let spawn_idev = conn.link(&pid).and_then(|l| l.identity_device_pub);
            return Some(tokio::spawn(
                mux.dial_and_serve(sid, host, port, rx, spawn_idev),
            ));
        }
        forward::ForwardAdmission::Denied(d) => {
            if let Some(p) = &d.park {
                let known = |p: &[u8; 32]| ports.store.devices_find_by_device_pub(p).is_some();
                let revoked = |p: &[u8; 32]| ports.identity.device_cert_revoked(p);
                let delegated = |p: &[u8; 32]| {
                    host.delegated_access_for(p)
                        .is_some_and(|a| a.expired(filament_id::now_secs()))
                };
                let denied = |n: &str, c: &str| host.device_capability_denied(n, c);
                if park_on_deny(
                    &known,
                    &revoked,
                    &delegated,
                    &denied,
                    ports.identity.gate_settle_ms(),
                    parked,
                    conn,
                    &pid,
                    ParkKind::Forward,
                    &d.transport,
                    p.sid,
                    v,
                    &p.reason,
                )
                .await
                {
                    return None;
                }
            }
            conn.log
                .say(&format!("l2: refused stream {:#x}: {}", d.sid, d.reason));
            let who = conn.link(&pid).and_then(|l| l.verified_name.clone());
            let close = d.close_frame(who, || {
                conn.link(&pid)
                    .and_then(|l| l.identity_device_pub)
                    .and_then(|d| ports.identity.reinvite_for(&d))
            });
            let _ = d.transport.send_control(&close).await;
        }
        forward::ForwardAdmission::Refused(r) => {
            conn.log
                .say(&format!("l2: refused stream {:#x}: {}", r.sid, r.reason));
            let _ = r.transport.send_control(&r.close).await;
        }
        forward::ForwardAdmission::Ignored => {}
    }
    None
}

/// The honest close for a reduced build that admitted the frame vocabulary
/// but has no stateful sync receiver. Testable without a Conn.
pub fn sync_unavailable_close(v: &Value) -> Option<(u32, Value)> {
    let sid = crate::l2::wire_sid(v)?;
    Some((
        sid,
        json!({
            "type": "l2-close",
            "sid": sid,
            "err": "sync receive is not available in this build",
        }),
    ))
}

#[allow(dead_code)]
fn _transport(_: &Arc<dyn Transport>) {}

/// Directory-sync admission and serving. The protocol and task ownership are
/// library code; the host supplies only the drop directory and request queue.
#[allow(clippy::too_many_arguments)]
pub async fn open_sync(
    ports: &RecvPorts,
    host: &dyn HostServices,
    conn: &mut crate::conn::Conn,
    pid: &str,
    v: &Value,
    muxes: &mut HashMap<String, Arc<Mux>>,
    drop_dir: &std::path::Path,
    parked: &mut Vec<ParkedOpen>,
) -> Option<(u32, crate::recv::dispatch::SyncTask)> {
    #[cfg(feature = "mount-server")]
    {
        use crate::sync::{SyncAccepted, SyncAdmission};
        match crate::sync::admit_sync_open(conn, pid, v, muxes, drop_dir).await {
            SyncAdmission::Accepted(a) => {
                let SyncAccepted {
                    sid,
                    who,
                    root,
                    dry_run,
                    delete,
                    rx,
                    mux,
                    transport: t,
                } = a;
                conn.log.say(&format!(
                    "sync: '{who}' -> {}{}",
                    root.display(),
                    if dry_run { " (dry run)" } else { "" }
                ));
                let task = crate::sync::serving::spawn_sync_server(
                    crate::sync::serving::SyncServeConfig {
                        transport: t,
                        mux,
                        sid,
                        root,
                        delete,
                        dry_run,
                        stream: rx,
                        max_record_bytes: crate::sync::MAX_SYNC_RECORD_BYTES,
                        #[cfg(test)]
                        finalization_gate: None,
                        #[cfg(test)]
                        staging_gate: None,
                    },
                );
                return Some((sid, crate::recv::dispatch::SyncTask(task)));
            }
            SyncAdmission::Denied(d) => {
                let known = |p: &[u8; 32]| ports.store.devices_find_by_device_pub(p).is_some();
                let revoked = |p: &[u8; 32]| ports.identity.device_cert_revoked(p);
                let delegated = |p: &[u8; 32]| {
                    host.delegated_access_for(p)
                        .is_some_and(|a| a.expired(filament_id::now_secs()))
                };
                let denied = |n: &str, c: &str| host.device_capability_denied(n, c);
                if park_on_deny(
                    &known,
                    &revoked,
                    &delegated,
                    &denied,
                    ports.identity.gate_settle_ms(),
                    parked,
                    conn,
                    pid,
                    ParkKind::Sync,
                    &d.transport,
                    d.park.sid,
                    v,
                    &d.park.reason,
                )
                .await
                {
                    return None;
                }
                let name = conn.link(pid).and_then(|l| l.verified_name.clone());
                host.enqueue_request_if_requestable(
                    name.as_deref().unwrap_or("<unverified>"),
                    "transfer",
                );
                let err = d.err();
                conn.log.say(&format!("sync: refused: {err}"));
                let _ = d.transport.send_control(&d.close_frame()).await;
            }
            SyncAdmission::Refused(r) => {
                conn.log.say(&format!("sync: refused: {}", r.reason));
                let _ = r.transport.send_control(&r.close).await;
            }
            SyncAdmission::Ignored => {}
        }
        None
    }
    #[cfg(not(feature = "mount-server"))]
    {
        let _ = (ports, host, muxes, drop_dir, parked);
        if let Some((sid, close)) = sync_unavailable_close(v) {
            if let Some(t) = conn.transport_of(pid) {
                let _ = t.send_control(&close).await;
            }
            let _ = sid;
        }
        None
    }
}

#[cfg(all(test, not(feature = "mount-server")))]
mod reduced_tests {
    use super::*;

    #[test]
    fn reduced_sync_open_closes_with_a_named_unavailable_error() {
        let (sid, close) = sync_unavailable_close(&json!({
            "type": "sync-open",
            "sid": 0x8000_0101u32,
            "root": "docs",
        }))
        .expect("a well-formed sync-open gets an explicit close");
        assert_eq!(sid, 0x8000_0101u32);
        assert_eq!(close["type"], "l2-close");
        assert_eq!(close["sid"], 0x8000_0101u32);
        assert!(close["err"]
            .as_str()
            .unwrap()
            .contains("sync receive is not available in this build"));
    }
}
