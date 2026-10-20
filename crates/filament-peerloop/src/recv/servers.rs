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
use serde_json::Value;
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
) {
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
            tokio::spawn(mux.dial_and_serve(sid, host, port, rx, spawn_idev));
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
                    return;
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
}

#[allow(dead_code)]
fn _transport(_: &Arc<dyn Transport>) {}
