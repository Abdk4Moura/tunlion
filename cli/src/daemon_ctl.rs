//! Daemon control-socket handlers that still need the CLI's tunnel and mount code.
//!
//! This file is the CLI half of what used to be one 910-line module (issue #465
//! slice 3). The crate-owned half now lives in `filament_peerloop::daemon_ctl`:
//! the reach liveness probes, `sshd_listening`, the warm `Ping`/`ListWarm`
//! replies, the deferred `Bootstrap` sockets and `log_warm_miss`. They are
//! re-exported below, so every daemon call site still resolves under
//! `crate::daemon_ctl::`.
//!
//! What stayed, and why it stays here rather than being dragged across:
//!   * `handle_warm_req` and the warm `Open`/`Pty`/`Resize` handlers take
//!     `l2::Mux` and the verified-stream helpers. `l2` is a 7,000-line tunnel
//!     implementation that is not in the peer-loop crate and is not host-bound:
//!     it is the daemon's own stream multiplexer. Moving it is a different
//!     slice.
//!   * the mount handlers track sshfs children in `DaemonMounts` and write the
//!     CLI's persistent mount record (`mount::add_mount`, `unmount_cmd_async`),
//!     and `handle_mount` also bootstraps over `l2`. The host trait carries the
//!     restore/query hooks, not the spawn-and-track store, so these handlers
//!     stay next to the module that owns that store.
//!
//! Everything moved kept its body, its cfg gates and its replies. Only the
//! naming changed: `ctl::` to the crate's `control::`, `ui::debug` to the
//! injected `Conn::log`, and `crate::net` to `filament_transport::net`.

use crate::Conn;
use crate::ctl;
use crate::l2;
use crate::mount;
use crate::net::Ev;
use crate::ui;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

// The half whose inputs are crate-owned. Re-exported, not redefined.
pub(crate) use filament_peerloop::daemon_ctl::{
    liveness_answered, liveness_ping, liveness_pong, liveness_register, liveness_window,
    sshd_listening,
};
#[cfg(unix)]
pub(crate) use filament_peerloop::daemon_ctl::{
    PendingBootstraps, complete_warm_bootstrap, handle_list_warm, handle_warm_bootstrap,
    handle_warm_ping, log_warm_miss, reap_warm_bootstraps,
};
pub(crate) type WarmPtys = std::sync::Arc<std::sync::Mutex<HashMap<String, (String, u32)>>>;

pub(crate) struct DaemonMountEntry {
    local: String,
    pub(crate) peer: String,
    pub(crate) remote: String,
    pid: u32,
    read_only: bool,
    auto_restore: bool,
    created: String,
}

pub(crate) struct DaemonMounts {
    pub(crate) entries: HashMap<String, DaemonMountEntry>,
    pub(crate) children: HashMap<String, tokio::process::Child>,
}

/// Dispatch one warm-reuse control request to the right handler. Warm reuse is
/// unix-only (the control socket is a unix-domain socket); on non-unix `ctl::Req`
/// is uninhabited so this is never reached - it only keeps the event loop portable.
#[cfg(not(unix))]
pub(crate) async fn handle_warm_req(
    _conn: &Conn,
    _l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    _warm_ptys: &WarmPtys,
    _tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match req {}
}

#[cfg(unix)]
pub(crate) async fn handle_warm_req(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    match &req.kind {
        ctl::ReqKind::Open { .. } => handle_warm_open(conn, l2_muxes, tx, req).await,
        // Dial is handled inline in the daemon loop (it needs the L3 manager);
        // answer defensively if it ever reaches here.
        ctl::ReqKind::Dial { .. } => req.reject("dial not handled here").await,
        ctl::ReqKind::Pty { .. } => handle_warm_pty(conn, l2_muxes, warm_ptys, tx, req).await,
        ctl::ReqKind::Resize { .. } => handle_warm_resize(l2_muxes, warm_ptys, req).await,
        ctl::ReqKind::Ping { .. } => handle_warm_ping(conn, req).await,
        // Bootstrap is dispatched before this (it defers its reply), so it never
        // reaches here; reject defensively so a future caller falls back to cold.
        ctl::ReqKind::Bootstrap { .. } => req.reject("bootstrap not handled here").await,
        // Reconfigure is handled inline in the daemon loop (it mutates loop state),
        // so it never reaches this dispatcher; answer defensively if it ever does.
        ctl::ReqKind::Reconfigure { .. } => req.reply(&json!({ "ok": true, "live": false })).await,
        // ReqKind::Arm is gone: the mint writes armed.json directly (no IPC),
        // and the per-tick arm-gate reads it. See cli/src/armed.rs.
        // ReloadExpose is likewise handled inline in the daemon loop (it owns the
        // Exposer); answer defensively if it ever reaches here.
        ctl::ReqKind::ReloadExpose => {
            req.reply(&json!({ "ok": true, "live": false, "count": 0 }))
                .await
        }
        // Reload is handled inline in the daemon loop (it self-SIGTERMs); answer
        // defensively if it ever reaches here.
        ctl::ReqKind::Reload => req.reply(&json!({ "ok": true, "reloading": false })).await,
        // Wake is handled inline in the daemon loop (its whole purpose is to make
        // the loop iterate); answer defensively if it ever reaches here.
        ctl::ReqKind::Wake => req.reply(&json!({ "ok": true })).await,
        // RevocationSync is handled inline in the daemon loop (it owns the
        // device list and the links it must close). Never confirm it from here:
        // `ok:false` makes the caller say the revocation is not yet confirmed.
        ctl::ReqKind::RevocationSync => req.reply(&json!({ "ok": false })).await,
        // Mount/Unmount/ListMounts/MountHealth are handled inline in the daemon
        // loop (they need access to DaemonMounts); answer defensively if reached.
        ctl::ReqKind::Mount { .. } => req.reject("mount not handled here").await,
        ctl::ReqKind::Unmount { .. } => req.reject("unmount not handled here").await,
        ctl::ReqKind::ListMounts => req.reject("list-mounts not handled here").await,
        ctl::ReqKind::MountHealth { .. } => req.reject("mount-health not handled here").await,
        ctl::ReqKind::CapStatus => req.reject("cap-status not handled here").await,
        ctl::ReqKind::ListWarm => req.reject("list-warm not handled here").await,
        ctl::ReqKind::FleetRendezvous { .. } => {
            req.reject("fleet-rendezvous not handled here").await
        }
        ctl::ReqKind::ListPending => req.reject("list-pending not handled here").await,
        ctl::ReqKind::ApproveRequest { .. } => req.reject("approve-request not handled here").await,
        ctl::ReqKind::DenyRequest { .. } => req.reject("deny-request not handled here").await,
    }
}

/// Handle a mount request: spawn sshfs directly and track the child process
/// centrally so `handle_unmount` can kill it.
#[cfg(unix)]
pub(crate) async fn handle_mount(
    req: ctl::Req,
    server: &str,
    relay: bool,
    daemon_mounts: &mut DaemonMounts,
    last_mount_check: &mut Instant,
) {
    let ctl::ReqKind::Mount {
        peer,
        remote,
        local,
        read_only,
        auto_restore,
        port,
    } = &req.kind
    else {
        return;
    };
    let peer = peer.clone();
    let remote = remote.clone();
    let local = local.clone();
    let read_only = *read_only;
    let auto_restore = *auto_restore;
    let port = *port;

    // Ensure mount point exists.
    if !Path::new(&local).exists() {
        if let Err(e) = std::fs::create_dir_all(&local) {
            req.reject(&format!("failed to create mount point: {e}"))
                .await;
            return;
        }
        crate::ui::say(&format!("created mount point: {local}"));
    }

    // Check sshfs is available.
    if crate::platform::command("which")
        .arg("sshfs")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        req.reject("sshfs not found").await;
        return;
    }

    // Bootstrap peer connection info (sshfs authenticates with the managed
    // key: cert mode is `shell --ssh` only).
    let info = match crate::l2::ensure_peer_bootstrap_port(server, &peer, relay, port, false).await {
        Ok(info) => info,
        Err(e) => {
            req.reject(&format!("bootstrap failed: {e}")).await;
            return;
        }
    };
    let peer_name = peer.strip_suffix(".mesh").unwrap_or(&peer);

    // Build the sshfs command args directly.
    let mut args: Vec<String> = Vec::new();

    // Common SSH options.
    args.extend_from_slice(&[
        "-o".into(),
        format!("IdentityFile={}", info.key_path.display()),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=4".into(),
    ]);

    // L3 preferred, L2 fallback.
    let dest = if let Some(d) = crate::l2::l3_dest(&info) {
        d // L3 direct: user@peer.mesh, no ProxyCommand
    } else {
        // L2 fallback: user@tunlion-peer with ProxyCommand
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_string_lossy();
        let mut proxy = format!("{exe} --server {server}");
        if relay {
            proxy.push_str(" --relay");
        }
        proxy.push_str(&format!(" forward {peer_name}:{} --stdio", info.rport));
        args.push("-o".into());
        args.push(format!("ProxyCommand={proxy}"));
        format!("{}@{}", info.login, info.host)
    };

    args.push(format!("{dest}:{remote}"));
    args.push(local.clone());
    if read_only {
        args.push("-o".into());
        args.push("ro".into());
    }

    // Spawn sshfs via tokio so we get a Child we can kill later.
    let child = match crate::platform::tokio_command("sshfs")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            req.reject(&format!("failed to spawn sshfs: {e}")).await;
            return;
        }
    };

    let pid = child.id().unwrap_or(0);
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mount_id = mount::unique_mount_id();
    let parent_id = mount::find_parent_mount(&local);

    // Record in persistent mount tracking.
    let _ = mount::add_mount(mount::MountEntry {
        id: mount_id.clone(),
        parent_id,
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now.clone(),
    });

    // Store in daemon in-memory tracking.
    let entry = DaemonMountEntry {
        local: local.clone(),
        peer: peer_name.to_string(),
        remote: remote.clone(),
        pid,
        read_only,
        auto_restore,
        created: now,
    };
    daemon_mounts.entries.insert(local.clone(), entry);
    daemon_mounts.children.insert(local.clone(), child);

    *last_mount_check = Instant::now();
    crate::ui::say(&format!(
        "mounted {peer_name}:{remote} at {local} (id: {mount_id})"
    ));
    req.reply(&json!({ "ok": true })).await;
}

/// Handle an unmount request: kill the sshfs process and remove tracking.
#[cfg(unix)]
pub(crate) async fn handle_unmount(req: ctl::Req, daemon_mounts: &mut DaemonMounts) {
    let ctl::ReqKind::Unmount { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Kill the child process if tracked by the daemon.
    if let Some(mut child) = daemon_mounts.children.remove(&target) {
        let _ = child.kill().await;
    }
    daemon_mounts.entries.remove(&target);

    // Also remove from persistent tracking (async-safe, no block_on).
    match mount::unmount_cmd_async(&target).await {
        Ok(()) => req.reply(&json!({ "ok": true })).await,
        Err(e) => req.reject(&format!("unmount failed: {e}")).await,
    }
}

/// Handle a list-mounts request: return all tracked mounts and their status.
#[cfg(unix)]
pub(crate) async fn handle_list_mounts(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let mounts: Vec<Value> = daemon_mounts
        .entries
        .values()
        .map(|e| {
            let is_alive = mount::is_mount_point(&e.local);
            let status = if is_alive { "healthy" } else { "dead" };
            json!({
                "local": e.local,
                "peer": e.peer,
                "remote": e.remote,
                "read_only": e.read_only,
                "auto_restore": e.auto_restore,
                "created": e.created,
                "status": status,
            })
        })
        .collect();
    req.reply(&json!({ "ok": true, "mounts": mounts })).await;
}

/// Handle a mount-health request: check health of a specific mount.
#[cfg(unix)]
pub(crate) async fn handle_mount_health(req: ctl::Req, daemon_mounts: &DaemonMounts) {
    let ctl::ReqKind::MountHealth { target } = &req.kind else {
        return;
    };
    let target = target.clone();

    // Find the entry by local path or ID.
    let entry = daemon_mounts.entries.get(&target);
    match entry {
        Some(e) => {
            let is_alive = mount::is_mount_point(&e.local);
            let path_exists = Path::new(&e.local).exists();
            let status = if !path_exists {
                "missing"
            } else if !is_alive {
                "dead"
            } else {
                match std::fs::metadata(&e.local) {
                    Ok(_) => "healthy",
                    Err(_) => "stale",
                }
            };
            req.reply(&json!({ "ok": true, "status": status, "local": e.local, "peer": e.peer, "remote": e.remote })).await;
        }
        None => {
            // Not tracked by daemon, but check if it's a live mount anyway.
            if mount::is_mount_point(&target) {
                req.reply(&json!({ "ok": true, "status": "untracked", "local": target }))
                    .await;
            } else {
                req.reject(&format!("no mount found for '{target}'")).await;
            }
        }
    }
}

pub(crate) use crate::link_manager::peer_present;

/// Resolve `peer` to a warm, trusted, alive link. Moved to
/// `filament-peerloop::conn`: it takes the crate's `Conn` and returns the
/// crate's transport pair, so the loop can call it without naming the CLI.
#[cfg(unix)]
pub(crate) use filament_peerloop::conn::warm_link_for;

/// DEBUG: every link that names `peer`, and which one the warm path chose, so
/// a slow warm open on a peer with more than one link is diagnosable.
#[cfg(unix)]
fn log_warm_pick(conn: &Conn, peer: &str, chosen: &str) {
    for (p, l) in conn.links.iter() {
        if !l.verified_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(peer)) {
            continue;
        }
        ui::debug(&format!(
            "warm-pick '{peer}': pid={p} chosen={} direct={} alive={} age_ms={:?} deferred_left={}",
            p == chosen,
            l.direct,
            l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false),
            l.established_at.map(|t| t.elapsed().as_millis()),
            conn.deferred_left.contains_key(p),
        ));
    }
}

/// Warm-reuse: open a raw L2 stream to `peer:rport` over its existing link and
/// bridge it to the client's unix socket (netcat/ssh/forward fast path).
#[cfg(unix)]
async fn handle_warm_open(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Open { peer, rport } = &req.kind else {
        return;
    };
    let (peer, rport) = (peer.clone(), *rport);
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    log_warm_pick(conn, &peer, &pid);
    // Reuse the SAME per-peer mux the event loop routes inbound L2 frames to.
    let mux = l2_muxes
        .entry(pid.clone())
        .or_insert_with(|| l2::Mux::new(t, conn.host.clone()))
        .clone();
    let tx = tx.clone();
    // SELF-HEALING warm-reuse: VERIFY the held link still delivers BEFORE committing
    // the client. Open the stream and wait for the first inbound frame (sshd's
    // banner - the byte we needed anyway, so a healthy link pays ~1 RTT and nothing
    // extra), then accept. A zombie link (alive at the QUIC layer but black-holing
    // new streams - the popos hang) yields nothing within the window, so we DROP it
    // (the loop re-forms a healthy one, keeping warm-reuse fast) and REJECT, which
    // makes the client's `try_open` return None and fall straight through to a fresh
    // establish. Verifying before accepting is what makes the fallback INSTANT: an
    // accepted-then-dead connection would instead stall the client until ITS own
    // timeout (the 25s ssh ConnectTimeout we measured). Spawned so the verify wait
    // never blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_stream_verified_reason(&mux, rport, l2::warm_verify_window()).await {
            l2::WarmOpen::Opened(sid, first, rx) => {
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx).await;
            }
            // The peer ANSWERED: the link is healthy, keep it, and relay the
            // reason so the client can show it (it used to be read as a zombie).
            l2::WarmOpen::Refused(reason) => {
                ui::debug(&format!(
                    "tunlion: warm open to '{peer}':{rport} refused by the peer ({reason})"
                ));
                req.reject(&format!("refused: {reason}")).await;
            }
            l2::WarmOpen::Dead(e) => {
                ui::debug(&format!(
                    "tunlion: warm link to '{peer}' is a zombie ({e}); dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh")
                    .await;
            }
        }
    });
}

/// Warm-reuse: open a PTY on `peer` over its existing link and bridge it to the
/// client's stdio socket (the `tunlion shell` fast path). Records the session->sid
/// so a later `pty-resize` can find it; the entry is dropped when the bridge ends.
#[cfg(unix)]
async fn handle_warm_pty(
    conn: &Conn,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    tx: &mpsc::UnboundedSender<Ev>,
    req: ctl::Req,
) {
    let ctl::ReqKind::Pty {
        peer,
        session,
        cols,
        rows,
        term,
        cmd,
    } = &req.kind
    else {
        return;
    };
    let (peer, session, cols, rows, term, cmd) = (
        peer.clone(),
        session.clone(),
        *cols,
        *rows,
        term.clone(),
        cmd.clone(),
    );
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    let mux = l2_muxes
        .entry(pid.clone())
        .or_insert_with(|| l2::Mux::new(t, conn.host.clone()))
        .clone();
    let warm_ptys = warm_ptys.clone();
    let tx = tx.clone();
    let verify = l2::warm_verify_window();
    // SELF-HEALING warm pty, same shape as handle_warm_open: VERIFY the held link
    // delivers (the shell prompt / replayed buffer, sent unprompted, is the first
    // frame) BEFORE recording the session and accepting the terminal. On a zombie
    // link we DROP it and REJECT, so the client falls straight through to a cold
    // pty rather than getting a dead terminal. Spawned so the verify wait never
    // blocks the event loop (F8).
    tokio::spawn(async move {
        match l2::open_pty_stream_verified(&mux, &session, cols, rows, &term, &cmd, verify).await {
            l2::WarmPtyVerdict::Opened(sid, first, rx_pipe) => {
                if let Ok(mut m) = warm_ptys.lock() {
                    m.insert(session.clone(), (pid, sid));
                }
                let sock = req.accept().await;
                l2::serve_verified_stream(mux, sid, sock, first, rx_pipe).await;
                // Bridge ended (shell exit / client gone / link drop): drop our
                // entry, but only if it is still ours (a reconnect may have
                // replaced it).
                if let Ok(mut m) = warm_ptys.lock() {
                    if m.get(&session).map(|(_, s)| *s == sid).unwrap_or(false) {
                        m.remove(&session);
                    }
                }
            }
            l2::WarmPtyVerdict::Refused(reason) => {
                ui::debug(&format!(
                    "tunlion: warm pty to '{peer}' refused by the peer ({reason})"
                ));
                req.reject(&format!("refused: {reason}")).await;
            }
            l2::WarmPtyVerdict::LinkDead => {
                ui::debug(&format!(
                    "tunlion: warm pty link to '{peer}' died; dropping + establishing fresh"
                ));
                let _ = tx.send(Ev::DropLink(pid));
                req.reject("warm link unresponsive; establishing fresh")
                    .await;
            }
            l2::WarmPtyVerdict::Silent => {
                // Clean end, no output: accept and drop at once so the
                // client reads EOF as exit 0 (the cold path's Exited).
                // Nothing is recorded (no live session exists to reattach).
                ui::debug(&format!(
                    "tunlion: warm pty to '{peer}' exited cleanly with no output"
                ));
                let _sock = req.accept().await;
            }
        }
    });
}

/// Warm-reuse: relay a window-size change to an already-open warm PTY (by session).
#[cfg(unix)]
async fn handle_warm_resize(
    l2_muxes: &HashMap<String, Arc<l2::Mux>>,
    warm_ptys: &WarmPtys,
    req: ctl::Req,
) {
    let ctl::ReqKind::Resize {
        session,
        cols,
        rows,
    } = &req.kind
    else {
        return;
    };
    let (cols, rows) = (*cols, *rows);
    let target = warm_ptys.lock().ok().and_then(|m| m.get(session).cloned());
    if let Some((pid, sid)) = target {
        if let Some(mux) = l2_muxes.get(&pid) {
            let _ = mux
                .transport()
                .send_control(
                    &json!({ "type": "pty-resize", "sid": sid, "cols": cols, "rows": rows }),
                )
                .await;
        }
    }
    req.accept().await; // close the client's short connection cleanly
}
