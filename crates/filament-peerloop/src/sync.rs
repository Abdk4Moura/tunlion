//! Inbound `sync-open` admission.
//!
//! This is the peer-loop half of `cli::sync_cmd::handle_sync_open`: destination
//! confinement, the transfer capability gate, and the shared-mux registration
//! order. The CLI keeps parking, the consent request and user-facing log lines;
//! this module also owns the admitted stream's record protocol and file-write
//! state machine through the `serving` submodule (present only when the
//! `mount-server` feature is on).
//!
//! Ordering is the security contract, preserved from the CLI handler:
//! transport, checked L2 sid, path bounds, authorization, capacity, collision,
//! ack. Bounds run before the gate so an out-of-root request never becomes a
//! capability question (and never raises a consent request), while the gate
//! always sees the real scope (`scoped_in_bounds = true`, the transfer
//! scoped-default rule). The caller owns the shared [`MuxMap`]; a private mux
//! would split the SID namespace and the close/ack/data path.
//!
//! The library reads no settings file, environment, device store or clock. The
//! caller resolves the drop directory once per open and passes it in, and the
//! host supplies the cap store, the mode, the clock and the effective gate.

use crate::conn::{dropped_no_transport, Conn};
use crate::host::CapGate;
use crate::l2::{self, Mux, MuxMap, PipeItem};
use crate::shell_gate::peer_authz;
use filament_cap::capability as cap;
use filament_transfer::path_bounds::resolve_root;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// File chunk size used by the sync manifest and receiver.
pub const SYNC_CHUNK: u64 = 256 * 1024;

/// A manifest entry, shared by the sender and receiver protocol.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub p: String,
    pub size: u64,
    pub mtime: u64,
    pub full: String,
    pub chunks: Vec<String>,
}

/// One file the receiver needs from a manifest.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct Need {
    pub p: String,
    pub new: bool,
    pub chunks: Vec<u32>,
}

/// The receiver's chunk plan for one manifest.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
pub struct Plan {
    pub need: Vec<Need>,
    pub same: Vec<String>,
    pub extra: Vec<String>,
}

/// The receiver's maximum record payload. It bounds a serialized manifest as
/// well as every individual control/data record, preserving the CLI limit.
pub const MAX_SYNC_RECORD_BYTES: usize = 64 << 20;

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whole-file digest and per-chunk digests in one pass.
pub fn hash_file(path: &Path) -> std::io::Result<(String, Vec<String>)> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut whole = sha2::Sha256::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; SYNC_CHUNK as usize];
    loop {
        let mut n = 0;
        while n < buf.len() {
            let k = f.read(&mut buf[n..])?;
            if k == 0 { break; }
            n += k;
        }
        if n == 0 { break; }
        whole.update(&buf[..n]);
        chunks.push(hex(&sha2::Sha256::digest(&buf[..n])));
        if n < buf.len() { break; }
    }
    Ok((hex(&whole.finalize()), chunks))
}

/// Walk `root` without following symlinks. Returns a sorted manifest and
/// skipped entries, shared by sender and receiver.
pub fn walk_manifest(root: &Path) -> anyhow::Result<(Vec<Entry>, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for e in std::fs::read_dir(root.join(&rel))? {
            let e = e?;
            let r = rel.join(e.file_name());
            let rs = r.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
            let md = e.metadata()?;
            if md.file_type().is_symlink() {
                skipped.push((rs, "symlink".into()));
            } else if md.is_dir() {
                stack.push(r);
            } else if !md.is_file() {
                skipped.push((rs, "not a regular file".into()));
            } else if filament_transfer::path_bounds::safe_relpath(&rs).is_none()
                || !filament_transfer::path_bounds::path_within(root, &root.join(&r))
            {
                skipped.push((rs, "path escapes the directory".into()));
            } else {
                let (full, chunks) = hash_file(&e.path())?;
                let mtime = md.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()).unwrap_or(0);
                out.push(Entry { p: rs, size: md.len(), mtime, full, chunks });
            }
        }
    }
    out.sort_by(|a, b| a.p.cmp(&b.p));
    skipped.sort();
    Ok((out, skipped))
}

/// Compute what `remote` lacks relative to `local`.
pub fn diff(local: &[Entry], remote: &[Entry]) -> Plan {
    let have: BTreeMap<&str, &Entry> = remote.iter().map(|e| (e.p.as_str(), e)).collect();
    let mut plan = Plan::default();
    for l in local {
        match have.get(l.p.as_str()) {
            Some(r) if r.full == l.full && r.size == l.size => plan.same.push(l.p.clone()),
            other => {
                let rc: &[String] = other.map(|r| r.chunks.as_slice()).unwrap_or(&[]);
                let chunks = l.chunks.iter().enumerate().filter(|(i, h)| rc.get(*i) != Some(h))
                    .map(|(i, _)| i as u32).collect();
                plan.need.push(Need { p: l.p.clone(), new: other.is_none(), chunks });
            }
        }
    }
    let want: BTreeSet<&str> = local.iter().map(|e| e.p.as_str()).collect();
    plan.extra = remote.iter().filter(|e| !want.contains(e.p.as_str())).map(|e| e.p.clone()).collect();
    plan
}

/// One inbound `sync-open` decision.
pub enum SyncAdmission {
    /// Admitted, registered on the caller's shared mux and acknowledged. The
    /// caller owns the returned stream receiver and starts the stateful server
    /// through the `serving` submodule (present only with `mount-server`).
    Accepted(SyncAccepted),
    /// Refused by the transfer gate. The caller may hold it for identity proof
    /// through its existing `park_on_deny`; if it does not, it records the
    /// consent request, logs, and sends [`SyncDenial::close_frame`].
    Denied(SyncDenial),
    /// Refused before or after authorization by a non-policy rule (path bounds,
    /// stream capacity, or sid collision). Final: send the exact close, do not
    /// park and do not raise a consent request.
    Refused(SyncRefusal),
    /// Nothing to send: the link has no transport, or the frame had no usable
    /// L2 sid. No close, no mux entry, no gate call.
    Ignored,
}

/// An admitted sync stream.
pub struct SyncAccepted {
    pub sid: u32,
    /// The acceptor's name for the peer at admission time, for the caller's
    /// success line. It is captured before `peer_authz` resolves identity,
    /// exactly as the CLI handler did.
    pub who: String,
    /// The canonical confined destination root (or the not-yet-created target
    /// of a dry run, which is why no files are written for one).
    pub root: PathBuf,
    pub dry_run: bool,
    pub delete: bool,
    pub rx: mpsc::Receiver<PipeItem>,
    /// The caller's shared mux the stream was registered on.
    pub mux: Arc<Mux>,
    /// The transport the ack was sent on; the caller serves and closes on the
    /// same link.
    pub transport: Arc<dyn Transport>,
}

/// A transfer-gate denial and the inputs the CLI hands to its parking rule.
pub struct SyncDenial {
    pub sid: u32,
    /// The gate's reason, without the wire prefix. The caller passes this to
    /// `park_on_deny` unchanged.
    pub reason: String,
    /// The transport captured before the gate, so the close rides the same link
    /// the admission examined.
    pub transport: Arc<dyn Transport>,
    /// The sid and reason the caller passes to `park_on_deny`. Present because
    /// admission has already rejected every frame that could not be re-driven.
    pub park: SyncPark,
}

/// The sid and reason a re-drive needs, unchanged from the CLI handler.
pub struct SyncPark {
    pub sid: u32,
    pub reason: String,
}

impl SyncDenial {
    /// The exact `l2-close` the CLI sends after its parking attempt. Sync has
    /// always used the plain not-authorized frame (no refusal code/as fields),
    /// so the wire shape is pinned here rather than re-derived by the caller.
    pub fn close_frame(&self) -> Value {
        json!({
            "type": "l2-close",
            "sid": self.sid,
            "err": self.err(),
        })
    }

    /// The exact wire error for this denial.
    pub fn err(&self) -> String {
        format!("not authorized: {}", self.reason)
    }
}

/// A final, non-policy refusal with the exact frame the CLI sends.
pub struct SyncRefusal {
    pub sid: u32,
    /// The historical log/wire reason, verbatim ("remote dir is outside this
    /// device's drop directory", "too many streams", "sid in use").
    pub reason: String,
    pub close: Value,
    pub transport: Arc<dyn Transport>,
}

impl SyncRefusal {
    fn new(sid: u32, reason: String, transport: Arc<dyn Transport>) -> Self {
        Self {
            sid,
            close: json!({ "type": "l2-close", "sid": sid, "err": reason.clone() }),
            reason,
            transport,
        }
    }
}

/// Admit one inbound `sync-open` and register an accepted stream on the
/// caller's shared mux.
///
/// `drop_dir` is already resolved by the caller (the receive command's drop
/// directory). Path bounds run before authorization; the transfer gate is the
/// same decision a `file-offer` from this peer gets; and the ack is sent only
/// after `register_stream` succeeds. Nothing is enqueued and nothing is parked
/// here: both are caller policy over the returned [`SyncDenial`].
pub async fn admit_sync_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    muxes: &mut MuxMap,
    drop_dir: &Path,
) -> SyncAdmission {
    // The live arm already drops a link with no transport, but a parked
    // re-drive must re-check it: the transport may have gone while it waited.
    let Some(t) = conn.transport_of(pid) else {
        dropped_no_transport(conn.log.as_ref(), pid, "sync-open");
        return SyncAdmission::Ignored;
    };
    // `wire_sid` rejects a missing or out-of-range sid instead of defaulting
    // to 0 / wrapping into a forged `is_l2_sid` value. Both return silently:
    // no close, no mux entry, no gate call.
    let Some(sid) = l2::wire_sid(v) else {
        return SyncAdmission::Ignored;
    };
    if !l2::is_l2_sid(sid) {
        return SyncAdmission::Ignored;
    }

    // Bounds first, as before: an out-of-root request never widens to a
    // grant-only decision it would have failed anyway, and the gate sees the
    // real scope. A dry run must not create the destination.
    let dry_run = v["dry_run"].as_bool() == Some(true);
    let root = match resolve_root(drop_dir, v["root"].as_str().unwrap_or(""), !dry_run) {
        Ok(root) => root,
        Err(reason) => return SyncAdmission::Refused(SyncRefusal::new(sid, reason, t)),
    };

    // Snapshot trust and the peer's name BEFORE `peer_authz` lazily resolves
    // identity: the transfer legacy fold uses this trust bit, and the success
    // line uses this pre-resolution name, exactly as the CLI handler did.
    let trusted = conn.link(pid).map(|l| l.trusted).unwrap_or(false);
    let who = conn
        .link(pid)
        .and_then(|l| l.verified_name.clone())
        .unwrap_or_else(|| "<unverified>".into());

    // The transfer gate is unconditional in both modes. The injected host is
    // the one policy site: it owns the store, mode, clock and verdict, so this
    // endpoint never re-derives a capability decision or reads a file.
    let denied_reason = {
        let host = conn.host.clone();
        let az = peer_authz(conn, pid);
        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
        let store = host.cap_store();
        let now = host.now_secs();
        let authoritative = host.cap_authoritative();
        let outcome =
            cap::authorize_in(&store, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps, now);
        let outcome = cap::cap_trust_floor(&outcome, trusted, binding, authoritative);
        let (own_user, has_grant) =
            cap::fleet_inputs_in(&store, "self", cap::CAP_TRANSFER, idev, iusr, ak_caps, now);
        // These are the `file-offer` transfer-gate inputs exactly. `denied` is
        // false because no deny list is consulted on the transfer path today;
        // `ceiling_authorizes` is false because transfer is a SCOPED DEFAULT
        // (the true below), not a deliberate-tier action the ceiling decides.
        let d = host.cap_gate_effective(CapGate {
            legacy_allowed: trusted,
            outcome: &outcome,
            action: cap::CAP_TRANSFER,
            resource: "self",
            device_pub: idev,
            user_pub: iusr,
            binding,
            cert_expires: expires,
            auth_key_caps: ak_caps,
            own_user_pub: own_user.as_ref(),
            scoped_in_bounds: true,
            has_explicit_grant: has_grant,
            cert_revoked,
            denied: false,
            ceiling_authorizes: false,
        });
        if let Some(reason) = cap::transfer_gate_decision(&d, authoritative) {
            Some(reason)
        } else if !d.allowed() {
            Some(d.deny_reason("unverified peer: pair first").to_string())
        } else {
            None
        }
    };
    if let Some(reason) = denied_reason {
        return SyncAdmission::Denied(SyncDenial {
            sid,
            park: SyncPark {
                sid,
                reason: reason.clone(),
            },
            reason,
            transport: t,
        });
    }

    // Get-or-create in the CALLER's map: sync shares the one SID namespace and
    // close/ack path with mount, forward, pty and exec.
    let mux = muxes
        .entry(pid.to_owned())
        .or_insert_with(|| Mux::new(t.clone(), conn.host.clone()))
        .clone();
    if mux.at_stream_cap().await {
        return SyncAdmission::Refused(SyncRefusal::new(sid, "too many streams".into(), t));
    }
    // Never displace another endpoint's live stream in the shared mux.
    let Some(rx) = mux.register_stream(sid).await else {
        return SyncAdmission::Refused(SyncRefusal::new(sid, "sid in use".into(), t));
    };

    // `delete` is read only after a stream exists, as before. `dest` is the
    // resolved absolute destination, so the sender can say where its files
    // went (additive; older senders ignore it).
    let delete = v["delete"].as_bool() == Some(true);
    let _ = t
        .send_control(&json!({
            "type": "sync-open-ack",
            "sid": sid,
            "dest": root.display().to_string(),
        }))
        .await;

    SyncAdmission::Accepted(SyncAccepted {
        sid,
        who,
        root,
        dry_run,
        delete,
        rx,
        mux,
        transport: t,
    })
}

/// Stateful receiver for an admitted sync stream. This module owns record
/// framing, manifest validation, delta planning, bounded file writes, content
/// verification, deletion, cancellation and stream cleanup. The CLI owns the
/// user-facing outcome and the consent/parking policy.
///
/// This is inbound filesystem serving, so it is absent from reduced engine
/// profiles exactly like the mount server: it reuses the `mount_proto`
/// parent-relative confinement primitives (`safe_open_beneath`,
/// `safe_rename_beneath`, `safe_unlink_staged_beneath`), which are themselves
/// gated behind `mount-server`. Admission ([`admit_sync_open`]) and the wire
/// vocabulary stay common; a reduced build admits an open but has no stateful
/// receiver to start it, and its CLI refuses the `sync-open` by name.
#[cfg(feature = "mount-server")]
pub mod serving {
    use super::{Entry, MAX_SYNC_RECORD_BYTES, SYNC_CHUNK};
    use crate::l2::Mux;
    use anyhow::{Result, bail};
    use bytes::Bytes;
    use filament_transfer::path_bounds::{
        bound_parent, delete_within, manifest_paths_are_bounded, path_within, safe_relpath,
    };
    use filament_transport::net::Transport;
    use serde_json::{Value, json};
    use sha2::Digest;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};
    #[cfg(test)]
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;

    /// Server configuration resolved by the caller from one admitted open.
    /// `root` must be the validated result of `path_bounds::resolve_root`; the
    /// library repeats per-file confinement checks before every write/delete.
    pub struct SyncServeConfig {
        pub transport: Arc<dyn Transport>,
        pub mux: Arc<Mux>,
        pub sid: u32,
        pub root: PathBuf,
        pub delete: bool,
        pub dry_run: bool,
        pub stream: mpsc::Receiver<Option<Bytes>>,
        /// Maximum individual length-prefixed record, including the manifest.
        pub max_record_bytes: usize,
        #[cfg(test)]
        pub(crate) finalization_gate: Option<(Arc<Notify>, Arc<Notify>)>,
        #[cfg(test)]
        pub(crate) staging_gate: Option<(Arc<Notify>, Arc<Notify>)>,
    }

    /// Owns the exclusively created `.part` entry until it is atomically
    /// renamed into place. Every return, cancellation, and unwind after create
    /// attempts identity-checked cleanup; an existing name is never adopted.
    #[cfg(not(windows))]
    struct StagedPart {
        root: PathBuf,
        rel: PathBuf,
        file: Option<std::fs::File>,
        committed: bool,
    }

    #[cfg(not(windows))]
    impl StagedPart {
        fn new(root: &Path, rel: &Path, file: std::fs::File) -> Self {
            Self {
                root: root.to_path_buf(),
                rel: rel.to_path_buf(),
                file: Some(file),
                committed: false,
            }
        }

        fn file(&self) -> &std::fs::File {
            self.file.as_ref().expect("uncommitted staging file is present")
        }

        fn file_mut(&mut self) -> &mut std::fs::File {
            self.file.as_mut().expect("uncommitted staging file is present")
        }

        fn mark_committed(&mut self) {
            self.committed = true;
        }
    }

    #[cfg(not(windows))]
    impl Drop for StagedPart {
        fn drop(&mut self) {
            if self.committed {
                return;
            }
            if let Some(file) = self.file.as_ref() {
                // Drop is the all-path fallback. Cleanup errors are deliberately
                // fail-safe: never replace/delete an entry that no longer
                // matches our open file. Explicit transfer errors remain the
                // protocol's primary error.
                let _ = crate::mount_proto::safe_unlink_staged_beneath(
                    &self.root,
                    &self.rel,
                    file,
                );
            }
        }
    }

    /// An owned serving task. The caller can cancel and join it; dropping the
    /// owner requests cancellation before detaching the join handle.
    pub struct SyncServeTask {
        cancel: watch::Sender<bool>,
        commit_state: Arc<std::sync::Mutex<bool>>,
        join: Option<JoinHandle<Result<(), String>>>,
    }

    impl SyncServeTask {
        /// Request cancellation. The server exits at its next record boundary,
        /// then closes and removes its mux stream before completing the handle.
        pub fn cancel(&self) {
            let mut cancelled = self.commit_state.lock().unwrap_or_else(|e| e.into_inner());
            *cancelled = true;
            drop(cancelled);
            self.cancel.send_replace(true);
        }

        /// Whether the serving future has completed. Callers can use this to
        /// reap completed tasks with [`Self::join`] without awaiting active ones.
        pub fn is_finished(&self) -> bool {
            self.join.as_ref().map_or(true, |join| join.is_finished())
        }

        /// Join and retrieve the protocol result. Errors are strings to keep
        /// the CLI's existing user-facing rendering policy outside the library.
        pub async fn join(
            mut self,
        ) -> std::result::Result<std::result::Result<(), String>, tokio::task::JoinError> {
            self.join.take().expect("sync task joined once").await
        }
    }

    impl Drop for SyncServeTask {
        fn drop(&mut self) {
            // A dropped owner must not silently leave a live receiver behind.
            self.cancel();
        }
    }

    /// Spawn one stateful sync receiver and return its cancellation/join owner.
    /// The task sends the same close on protocol failure as the CLI handler did
    /// and always removes the stream on success, refusal, or cancellation.
    pub fn spawn_sync_server(config: SyncServeConfig) -> SyncServeTask {
        let (cancel, cancel_rx) = watch::channel(false);
        let commit_state = Arc::new(std::sync::Mutex::new(false));
        let task_commit_state = commit_state.clone();
        let join = tokio::spawn(async move {
            let result = serve(config, cancel_rx, task_commit_state).await;
            result.map_err(|e| e.to_string())
        });
        SyncServeTask { cancel, commit_state, join: Some(join) }
    }

    #[derive(Default)]
    struct Records(Vec<u8>);

    impl Records {
        fn next(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
            if self.0.len() < 4 { return Ok(None); }
            let n = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
            if n > max { bail!("sync record too large ({n} bytes)"); }
            if self.0.len() < 4 + n { return Ok(None); }
            let rec = self.0[4..4 + n].to_vec();
            self.0.drain(..4 + n);
            Ok(Some(rec))
        }
    }

    async fn next_rec(
        pipe: &mut mpsc::Receiver<Option<Bytes>>,
        recs: &mut Records,
        max: usize,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        loop {
            if let Some(record) = recs.next(max)? { return Ok(record); }
            tokio::select! {
                biased;
                changed = cancel.changed() => {
                    if changed.is_err() {
                        // Dropping the owner detaches; it is not a cancel request.
                        std::future::pending::<()>().await;
                    } else if *cancel.borrow() {
                        bail!("sync cancelled");
                    }
                }
                item = pipe.recv() => match item {
                    Some(Some(bytes)) => recs.0.extend_from_slice(&bytes),
                    _ => bail!("the peer closed the sync stream"),
                },
                _ = tokio::time::sleep_until(deadline) => bail!("timed out waiting for the peer"),
            }
        }
    }

    async fn next_json(
        pipe: &mut mpsc::Receiver<Option<Bytes>>,
        recs: &mut Records,
        max: usize,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Value> {
        Ok(serde_json::from_slice(&next_rec(pipe, recs, max, cancel).await?)?)
    }

    async fn send_rec(t: &Arc<dyn Transport>, sid: u32, payload: &[u8]) -> Result<()> {
        let mut record = (payload.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(payload);
        for chunk in record.chunks(t.max_payload().max(1)) {
            t.send_frame(sid, 0, chunk).await?;
        }
        Ok(())
    }

    async fn send_json(t: &Arc<dyn Transport>, sid: u32, value: &Value) -> Result<()> {
        send_rec(t, sid, &serde_json::to_vec(value)?).await
    }

    async fn serve(
        mut cfg: SyncServeConfig,
        mut cancel: watch::Receiver<bool>,
        commit_state: Arc<std::sync::Mutex<bool>>,
    ) -> Result<()> {
        let result = serve_protocol(&mut cfg, &mut cancel, &commit_state).await;
        if let Err(error) = &result {
            let _ = cfg.transport.send_control(&json!({
                "type": "l2-close", "sid": cfg.sid, "err": error.to_string()
            })).await;
        }
        cfg.mux.drop_stream(cfg.sid).await;
        result
    }

    async fn serve_protocol(
        cfg: &mut SyncServeConfig,
        cancel: &mut watch::Receiver<bool>,
        commit_state: &Arc<std::sync::Mutex<bool>>,
    ) -> Result<()> {
        let mut recs = Records::default();
        let max_record_bytes = cfg.max_record_bytes.min(MAX_SYNC_RECORD_BYTES);
        let mut manifest = next_json(&mut cfg.stream, &mut recs, max_record_bytes, cancel).await?;
        if manifest["type"].as_str() != Some("manifest") { bail!("expected a manifest"); }
        let files: Vec<Entry> = serde_json::from_value(manifest["files"].take())?;
        if !manifest_paths_are_bounded(files.iter().map(|entry| entry.p.as_str())) {
            bail!("manifest names an unsafe path");
        }
        let root = cfg.root.clone();
        let (have, _) = if root.is_dir() {
            tokio::task::spawn_blocking(move || super::walk_manifest(&root)).await??
        } else {
            (Vec::new(), Vec::new())
        };
        let plan = super::diff(&files, &have);
        send_json(&cfg.transport, cfg.sid, &serde_json::to_value(&plan)?).await?;

        loop {
            let record = next_json(&mut cfg.stream, &mut recs, max_record_bytes, cancel).await?;
            match record["type"].as_str() {
                Some("done") => return Ok(()),
                Some("file") if !cfg.dry_run => {
                    let path = record["p"].as_str().unwrap_or("").to_string();
                    let result = receive_file(
                        cfg, &record, &mut recs, cancel, max_record_bytes, commit_state,
                    ).await;
                    let cancelled = *cancel.borrow();
                    let ack = match &result {
                        Ok(()) => json!({ "type": "file-ack", "p": path, "ok": true }),
                        Err(error) => json!({ "type": "file-ack", "p": path, "ok": false, "err": error.to_string() }),
                    };
                    send_json(&cfg.transport, cfg.sid, &ack).await?;
                    // Cancellation is terminal. The peer may already have
                    // pipelined the rest of this file, but those records are
                    // payload, not top-level messages; reinterpreting them
                    // after an aborted receive would misreport the abort.
                    if cancelled { bail!("sync cancelled"); }
                }
                Some("delete") if cfg.delete && !cfg.dry_run => {
                    let mut gone = Vec::new();
                    for path in record["paths"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                        let Some(rel) = safe_relpath(path) else { continue };
                        if delete_within(&cfg.root, &rel) { gone.push(path.to_string()); }
                    }
                    send_json(&cfg.transport, cfg.sid, &json!({ "type": "deleted", "paths": gone })).await?;
                }
                other => bail!("unexpected sync record {other:?}"),
            }
        }
    }

    async fn receive_file(
        cfg: &mut SyncServeConfig,
        record: &Value,
        recs: &mut Records,
        cancel: &mut watch::Receiver<bool>,
        max_record_bytes: usize,
        commit_state: &Arc<std::sync::Mutex<bool>>,
    ) -> Result<()> {
        #[cfg(windows)]
        {
            let _ = (record, commit_state);
            discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
            bail!("Windows sync receive disabled: race-safe parent-relative rename unavailable; no target or .part file was changed");
        }
        #[cfg(not(windows))]
        {
            receive_file_confined(cfg, record, recs, cancel, max_record_bytes, commit_state).await
        }
    }

    #[cfg(not(windows))]
    async fn receive_file_confined(
        cfg: &mut SyncServeConfig,
        record: &Value,
        recs: &mut Records,
        cancel: &mut watch::Receiver<bool>,
        max_record_bytes: usize,
        commit_state: &Arc<std::sync::Mutex<bool>>,
    ) -> Result<()> {
        if *cancel.borrow() { bail!("sync cancelled"); }
        let rel = safe_relpath(record["p"].as_str().unwrap_or("")).ok_or_else(|| anyhow::anyhow!("unsafe path"))?;
        let size = record["size"].as_u64().unwrap_or(0);
        let full = record["full"].as_str().unwrap_or("").to_string();
        let target = cfg.root.join(&rel);
        if !path_within(&cfg.root, &target) { bail!("path escapes the remote dir"); }
        if let Some(parent) = target.parent() { bound_parent(&cfg.root, parent)?; }
        let part_name = format!(
            "{}.part", rel.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
        );
        let mut part_rel = rel.clone();
        part_rel.set_file_name(part_name);
        let source = match safe_open_existing_file(&cfg.root, &rel) {
            Ok(source) => match source.metadata() {
                Ok(metadata) if metadata.is_file() => Some(source),
                Ok(_) => {
                    discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
                    bail!("destination exists and is not a regular file");
                }
                Err(error) => {
                    discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
                    return Err(error.into());
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
                return Err(error.into());
            }
        };
        // Create the staging file atomically and exclusively. Never unlink an
        // existing name and reopen it: that can follow a planted/replaced
        // symlink. Existing stale `.part` files fail closed. CREATE_NEW / O_EXCL
        // also closes the check/open race without a preceding path lookup.
        let file = match safe_create_part(&cfg.root, &part_rel) {
            Ok(file) => file,
            Err(error) => {
                discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
                return Err(error.into());
            }
        };
        let mut staged = StagedPart::new(&cfg.root, &part_rel, file);
        #[cfg(test)]
        if let Some((entered, release)) = &cfg.staging_gate {
            entered.notify_one();
            release.notified().await;
        }
        // Cancellation is a hard barrier: once the owner asks to stop, no
        // further payload is copied or written, and the guard above removes
        // the stage we created. Check here as well as at each record boundary
        // so a large prefetched file cannot defer the abort until finalization.
        if *cancel.borrow() { bail!("sync cancelled"); }
        if let Some(mut source) = source {
            use std::io::{Seek, SeekFrom};
            let copied = (|| -> std::io::Result<()> {
                staged.file_mut().set_len(0)?;
                std::io::copy(&mut source, staged.file_mut())?;
                staged.file_mut().seek(SeekFrom::Start(0))?;
                Ok(())
            })();
            if let Err(error) = copied {
                discard_file_payload(cfg, recs, cancel, max_record_bytes).await?;
                return Err(error.into());
            }
        }
        loop {
            if *cancel.borrow() { bail!("sync cancelled"); }
            let header = next_json(&mut cfg.stream, recs, max_record_bytes, cancel).await?;
            match header["type"].as_str() {
                Some("file-end") => break,
                Some("chunk") => {
                    let idx = header["idx"].as_u64().unwrap_or(u64::MAX);
                    let data = next_rec(&mut cfg.stream, recs, max_record_bytes, cancel).await?;
                    let pos = idx.checked_mul(SYNC_CHUNK).filter(|p| *p < size.max(1))
                        .ok_or_else(|| anyhow::anyhow!("chunk index out of range"))?;
                    if data.len() as u64 > SYNC_CHUNK || pos + data.len() as u64 > size { bail!("chunk overruns the file"); }
                    filament_transfer::pwrite_at(staged.file(), &data, pos)?;
                }
                other => bail!("unexpected record inside a file: {other:?}"),
            }
        }
        staged.file().set_len(size)?;
        staged.file().sync_all()?;
        let (mut staged, digest) = tokio::task::spawn_blocking(move || {
            let digest = hash_open_file(staged.file_mut());
            (staged, digest)
        }).await?;
        #[cfg(test)]
        if let Some((entered, release)) = &cfg.finalization_gate {
            entered.notify_one();
            release.notified().await;
        }
        if *cancel.borrow() {
            bail!("sync cancelled");
        }
        if digest.as_deref() != Some(full.as_str()) {
            bail!("content hash mismatch after transfer");
        }
        let cancelled = commit_state.lock().unwrap_or_else(|e| e.into_inner());
        if *cancelled {
            bail!("sync cancelled");
        }
        crate::mount_proto::safe_rename_beneath(&cfg.root, &part_rel, &rel, staged.file())?;
        staged.mark_committed();
        drop(cancelled);
        Ok(())
    }

    async fn discard_file_payload(
        cfg: &mut SyncServeConfig,
        recs: &mut Records,
        cancel: &mut watch::Receiver<bool>,
        max_record_bytes: usize,
    ) -> Result<()> {
        loop {
            let header = next_json(&mut cfg.stream, recs, max_record_bytes, cancel).await?;
            match header["type"].as_str() {
                Some("file-end") => return Ok(()),
                Some("chunk") => {
                    let _ = header["idx"].as_u64().ok_or_else(|| anyhow::anyhow!("invalid chunk index"))?;
                    let _ = next_rec(&mut cfg.stream, recs, max_record_bytes, cancel).await?;
                }
                other => bail!("unexpected record inside a file: {other:?}"),
            }
        }
    }

    #[cfg(not(windows))]
    fn safe_create_part(root: &Path, rel: &Path) -> std::io::Result<std::fs::File> {
        #[cfg(unix)]
        {
            crate::mount_proto::safe_open_beneath(
                root,
                rel,
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                true,
                0o600,
            )
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(root.join(rel))
        }
    }

    #[cfg(not(windows))]
    fn safe_open_existing_file(root: &Path, rel: &Path) -> std::io::Result<std::fs::File> {
        #[cfg(unix)]
        {
            crate::mount_proto::safe_open_beneath(root, rel, libc::O_RDONLY, true, 0)
        }
        #[cfg(not(unix))]
        {
            let path = root.join(rel);
            std::fs::File::open(path)
        }
    }

    fn hash_open_file(file: &mut std::fs::File) -> Option<String> {
        use std::io::Read;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut hash = sha2::Sha256::new();
        let mut buf = vec![0; 1 << 20];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hash.update(&buf[..n]),
                Err(_) => return None,
            }
        }
        Some(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::host::{HostServices, NoHost};
        use filament_transport::net::Transport;
        use sha2::Digest;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering};

        const SID: u32 = crate::l2::L2_SID_BASE + 191;

        #[derive(Default)]
        struct CaptureTransport {
            controls: Mutex<Vec<Value>>,
            frames: Mutex<Vec<Vec<u8>>>,
        }

        #[async_trait::async_trait]
        impl Transport for CaptureTransport {
            async fn send_control(&self, value: &Value) -> anyhow::Result<()> {
                self.controls.lock().unwrap().push(value.clone());
                Ok(())
            }
            async fn send_frame(&self, _sid: u32, _offset: u64, bytes: &[u8]) -> anyhow::Result<()> {
                self.frames.lock().unwrap().push(bytes.to_vec());
                Ok(())
            }
            async fn flush(&self) -> anyhow::Result<()> { Ok(()) }
            fn max_payload(&self) -> usize { 64 * 1024 }
            fn is_alive(&self) -> bool { true }
            fn is_dead(&self) -> bool { false }
            fn as_any(&self) -> &dyn std::any::Any { self }
        }

        struct TempRoot(PathBuf);
        impl TempRoot {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let path = std::env::temp_dir().join(format!(
                    "filament-sync-serving-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for TempRoot {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
        }

        fn record(value: &Value, wire: &mut Vec<u8>) {
            let payload = serde_json::to_vec(value).unwrap();
            wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(&payload);
        }

        fn record_bytes(payload: &[u8], wire: &mut Vec<u8>) {
            wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            wire.extend_from_slice(payload);
        }

        fn outgoing_json(t: &CaptureTransport) -> Vec<Value> {
            let bytes = t.frames.lock().unwrap().concat();
            let mut rest = bytes.as_slice();
            let mut values = Vec::new();
            while rest.len() >= 4 {
                let size = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                if rest.len() < 4 + size { break; }
                if let Ok(value) = serde_json::from_slice(&rest[4..4 + size]) {
                    values.push(value);
                }
                rest = &rest[4 + size..];
            }
            values
        }

        async fn setup(root: &Path, wire: Vec<u8>) -> (SyncServeTask, Arc<Mux>, Arc<CaptureTransport>) {
            setup_with_finalization_gate(root, wire, None).await
        }

        async fn setup_with_finalization_gate(
            root: &Path,
            wire: Vec<u8>,
            finalization_gate: Option<(Arc<Notify>, Arc<Notify>)>,
        ) -> (SyncServeTask, Arc<Mux>, Arc<CaptureTransport>) {
            setup_with_gates(root, wire, finalization_gate, None).await
        }

        async fn setup_with_staging_gate(
            root: &Path,
            wire: Vec<u8>,
            staging_gate: Option<(Arc<Notify>, Arc<Notify>)>,
        ) -> (SyncServeTask, Arc<Mux>, Arc<CaptureTransport>) {
            setup_with_gates(root, wire, None, staging_gate).await
        }

        async fn setup_with_gates(
            root: &Path,
            wire: Vec<u8>,
            finalization_gate: Option<(Arc<Notify>, Arc<Notify>)>,
            staging_gate: Option<(Arc<Notify>, Arc<Notify>)>,
        ) -> (SyncServeTask, Arc<Mux>, Arc<CaptureTransport>) {
            let host: Arc<dyn HostServices> = Arc::new(NoHost);
            let transport = Arc::new(CaptureTransport::default());
            let mux = Mux::new(transport.clone(), host);
            let stream = mux.register_stream(SID).await.unwrap();
            if !wire.is_empty() {
                mux.on_frame(SID, Bytes::from(wire)).await;
            }
            let task = spawn_sync_server(SyncServeConfig {
                transport: transport.clone(),
                mux: mux.clone(),
                sid: SID,
                root: root.to_path_buf(),
                delete: true,
                dry_run: false,
                stream,
                max_record_bytes: super::super::MAX_SYNC_RECORD_BYTES,
                #[cfg(test)]
                finalization_gate,
                #[cfg(test)]
                staging_gate,
            });
            (task, mux, transport)
        }

        #[tokio::test]
        async fn success_writes_verified_file_and_cleans_shared_stream() {
            let root = TempRoot::new();
            let bytes = b"sync lands this file";
            let digest = sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
            let chunk_digest = digest.clone();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[{
                "p":"nested/file.txt", "size":bytes.len(), "mtime":1,
                "full":digest, "chunks":[chunk_digest]
            }]}), &mut wire);
            record(&json!({"type":"file", "p":"nested/file.txt", "size":bytes.len(), "full":digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);
            let (task, mux, transport) = setup(&root.0, wire).await;
            assert_eq!(task.join().await.unwrap().unwrap(), ());
            assert_eq!(std::fs::read(root.0.join("nested/file.txt")).unwrap(), bytes);
            assert_eq!(mux.live_streams().await, 0, "normal completion cleans the shared SID");
            let replies = outgoing_json(&transport);
            assert_eq!(replies[0]["need"].as_array().unwrap().len(), 1);
            assert_eq!(replies[0]["need"][0]["p"], "nested/file.txt");
            assert_eq!(replies[1], json!({"type":"file-ack", "p":"nested/file.txt", "ok":true}));
            assert!(transport.controls.lock().unwrap().is_empty());
        }

        #[tokio::test]
        async fn unsafe_manifest_is_refused_and_cleans_shared_stream() {
            let root = TempRoot::new();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[{
                "p":"../escape", "size":0, "mtime":0, "full":"", "chunks":[]
            }]}), &mut wire);
            let (task, mux, transport) = setup(&root.0, wire).await;
            let result = task.join().await.unwrap();
            assert_eq!(result.unwrap_err(), "manifest names an unsafe path");
            assert_eq!(
                transport.controls.lock().unwrap().as_slice(),
                &[json!({"type":"l2-close", "sid":SID, "err":"manifest names an unsafe path"})]
            );
            assert_eq!(mux.live_streams().await, 0, "refusal cleans the shared SID");
            assert!(std::fs::read_dir(&root.0).unwrap().next().is_none());
        }

        #[tokio::test]
        async fn hash_mismatch_preserves_existing_file_and_reports_negative_ack() {
            let root = TempRoot::new();
            std::fs::write(root.0.join("file.txt"), b"original").unwrap();
            let bytes = b"tampered";
            let wrong_digest = sha2::Sha256::digest(b"different").iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut wire);
            record(&json!({"type":"file", "p":"file.txt", "size":bytes.len(), "full":wrong_digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);
            let (task, mux, transport) = setup(&root.0, wire).await;
            assert!(task.join().await.unwrap().is_ok());
            assert_eq!(std::fs::read(root.0.join("file.txt")).unwrap(), b"original");
            assert!(!root.0.join("file.txt.part").exists());
            let replies = outgoing_json(&transport);
            assert_eq!(replies[1]["type"], "file-ack");
            assert_eq!(replies[1]["ok"], false);
            assert_eq!(replies[1]["err"], "content hash mismatch after transfer");
            assert_eq!(mux.live_streams().await, 0);
            assert!(transport.controls.lock().unwrap().is_empty());
        }

        #[cfg(windows)]
        #[tokio::test]
        async fn windows_receive_fails_closed_without_touching_target_or_staging() {
            let root = TempRoot::new();
            std::fs::write(root.0.join("file.txt"), b"original").unwrap();
            let bytes = b"must not be written";
            let digest = sha2::Sha256::digest(bytes).iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut wire);
            record(&json!({"type":"file", "p":"file.txt", "size":bytes.len(), "full":digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);

            let (task, mux, transport) = setup(&root.0, wire).await;
            assert!(task.join().await.unwrap().is_ok());
            assert_eq!(std::fs::read(root.0.join("file.txt")).unwrap(), b"original");
            assert!(!root.0.join("file.txt.part").exists());
            let replies = outgoing_json(&transport);
            assert_eq!(replies[1]["type"], "file-ack");
            assert_eq!(replies[1]["ok"], false);
            let reason = replies[1]["err"].as_str().unwrap();
            assert_eq!(
                reason,
                "Windows sync receive disabled: race-safe parent-relative rename unavailable; no target or .part file was changed",
            );
            assert_eq!(mux.live_streams().await, 0);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn planted_part_symlink_is_not_removed_or_followed() {
            let root = TempRoot::new();
            let outside = TempRoot::new();
            let outside_file = outside.0.join("outside.bin");
            std::fs::write(&outside_file, b"outside must remain unchanged").unwrap();
            let part = root.0.join("file.txt.part");
            std::os::unix::fs::symlink(&outside_file, &part).unwrap();

            let bytes = b"payload";
            let digest = sha2::Sha256::digest(bytes).iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut wire);
            record(&json!({"type":"file", "p":"file.txt", "size":bytes.len(), "full":digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);

            let (task, mux, transport) = setup(&root.0, wire).await;
            assert!(task.join().await.unwrap().is_ok());
            assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside must remain unchanged");
            assert!(std::fs::symlink_metadata(&part).unwrap().file_type().is_symlink());
            assert!(!root.0.join("file.txt").exists());
            let replies = outgoing_json(&transport);
            assert_eq!(replies[1]["type"], "file-ack");
            assert_eq!(replies[1]["ok"], false);
            assert_eq!(mux.live_streams().await, 0);
        }

        #[tokio::test]
        async fn cancellation_during_hash_finalization_preserves_target_and_withholds_success_ack() {
            let root = TempRoot::new();
            std::fs::write(root.0.join("file.txt"), b"initial").unwrap();
            let bytes = b"updated";
            let digest = sha2::Sha256::digest(bytes).iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut wire);
            record(&json!({"type":"file", "p":"file.txt", "size":bytes.len(), "full":digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);

            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let (task, mux, transport) = setup_with_finalization_gate(
                &root.0,
                wire,
                Some((entered.clone(), release.clone())),
            ).await;
            entered.notified().await;
            task.cancel();
            release.notify_one();

            assert_eq!(task.join().await.unwrap().unwrap_err(), "sync cancelled");
            assert_eq!(std::fs::read(root.0.join("file.txt")).unwrap(), b"initial");
            assert!(!root.0.join("file.txt.part").exists());
            let replies = outgoing_json(&transport);
            assert_eq!(replies[1]["type"], "file-ack");
            assert_eq!(replies[1]["ok"], false);
            assert_eq!(replies[1]["err"], "sync cancelled");
            assert_eq!(mux.live_streams().await, 0);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn cancellation_after_stage_creation_cleans_stage_and_retry_succeeds() {
            let root = TempRoot::new();
            let bytes = b"retry after cancelled stage";
            let digest = sha2::Sha256::digest(bytes).iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut first_wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut first_wire);
            record(&json!({"type":"file", "p":"retry.txt", "size":bytes.len(), "full":digest}), &mut first_wire);
            record(&json!({"type":"chunk", "idx":0}), &mut first_wire);
            record_bytes(bytes, &mut first_wire);
            record(&json!({"type":"file-end"}), &mut first_wire);
            record(&json!({"type":"done"}), &mut first_wire);

            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let (task, mux, transport) = setup_with_staging_gate(
                &root.0,
                first_wire,
                Some((entered.clone(), release.clone())),
            ).await;
            entered.notified().await;
            task.cancel();
            release.notify_one();
            // Mid-file cancellation is terminal: the per-file negative ack is
            // sent, then the serve loop aborts with the cancellation error
            // instead of reinterpreting the file's unread payload records as
            // top-level protocol messages.
            assert_eq!(task.join().await.unwrap().unwrap_err(), "sync cancelled");
            assert!(!root.0.join("retry.txt.part").exists());
            assert!(!root.0.join("retry.txt").exists());
            assert_eq!(mux.live_streams().await, 0);
            let first_ack = outgoing_json(&transport);
            assert_eq!(first_ack[1]["type"], "file-ack");
            assert_eq!(first_ack[1]["ok"], false);
            assert_eq!(first_ack[1]["err"], "sync cancelled");
            assert_eq!(first_ack.len(), 2, "cancellation must not acknowledge success");

            let mut retry_wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut retry_wire);
            record(&json!({"type":"file", "p":"retry.txt", "size":bytes.len(), "full":digest}), &mut retry_wire);
            record(&json!({"type":"chunk", "idx":0}), &mut retry_wire);
            record_bytes(bytes, &mut retry_wire);
            record(&json!({"type":"file-end"}), &mut retry_wire);
            record(&json!({"type":"done"}), &mut retry_wire);

            let (retry, retry_mux, retry_transport) = setup(&root.0, retry_wire).await;
            assert!(retry.join().await.unwrap().is_ok());
            assert_eq!(std::fs::read(root.0.join("retry.txt")).unwrap(), bytes);
            assert!(!root.0.join("retry.txt.part").exists());
            let retry_ack = outgoing_json(&retry_transport);
            assert_eq!(retry_ack[1], json!({"type":"file-ack", "p":"retry.txt", "ok":true}));
            assert_eq!(retry_mux.live_streams().await, 0);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn parent_swap_to_outside_symlink_is_refused_by_final_rename() {
            let root = TempRoot::new();
            let outside = TempRoot::new();
            let nested = root.0.join("nested");
            std::fs::create_dir(&nested).unwrap();
            let bytes = b"confined";
            let digest = sha2::Sha256::digest(bytes).iter()
                .map(|b| format!("{b:02x}")).collect::<String>();
            let mut wire = Vec::new();
            record(&json!({"type":"manifest", "files":[]}), &mut wire);
            record(&json!({"type":"file", "p":"nested/file.txt", "size":bytes.len(), "full":digest}), &mut wire);
            record(&json!({"type":"chunk", "idx":0}), &mut wire);
            record_bytes(bytes, &mut wire);
            record(&json!({"type":"file-end"}), &mut wire);
            record(&json!({"type":"done"}), &mut wire);

            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let (task, mux, transport) = setup_with_finalization_gate(
                &root.0,
                wire,
                Some((entered.clone(), release.clone())),
            ).await;
            entered.notified().await;
            let displaced = root.0.join("nested-displaced");
            std::fs::rename(&nested, &displaced).unwrap();
            std::os::unix::fs::symlink(&outside.0, &nested).unwrap();
            release.notify_one();

            assert!(task.join().await.unwrap().is_ok());
            assert!(std::fs::read_dir(&outside.0).unwrap().next().is_none());
            // The staging entry remains in the directory handle opened before
            // the swap; the final target name must not be committed there.
            assert!(displaced.join("file.txt.part").exists());
            assert!(!displaced.join("file.txt").exists());
            let replies = outgoing_json(&transport);
            assert_eq!(replies[1]["type"], "file-ack");
            assert_eq!(replies[1]["ok"], false);
            assert_eq!(mux.live_streams().await, 0);
        }

        #[cfg(unix)]
        #[test]
        fn safe_final_rename_replaces_final_symlink_without_following_it() {
            let root = TempRoot::new();
            let outside = TempRoot::new();
            let outside_file = outside.0.join("outside.txt");
            std::fs::write(&outside_file, b"outside remains").unwrap();
            std::fs::write(root.0.join("file.txt.part"), b"new content").unwrap();
            std::os::unix::fs::symlink(&outside_file, root.0.join("file.txt")).unwrap();
            let source = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.0.join("file.txt.part"))
                .unwrap();

            crate::mount_proto::safe_rename_beneath(
                &root.0,
                Path::new("file.txt.part"),
                Path::new("file.txt"),
                &source,
            ).unwrap();

            assert_eq!(std::fs::read(root.0.join("file.txt")).unwrap(), b"new content");
            assert_eq!(std::fs::read(outside_file).unwrap(), b"outside remains");
        }

        #[tokio::test]
        async fn cancellation_closes_and_cleans_an_idle_stream() {
            let root = TempRoot::new();
            let (task, mux, transport) = setup(&root.0, Vec::new()).await;
            task.cancel();
            let result = task.join().await.unwrap();
            assert_eq!(result.unwrap_err(), "sync cancelled");
            assert_eq!(
                transport.controls.lock().unwrap().as_slice(),
                &[json!({"type":"l2-close", "sid":SID, "err":"sync cancelled"})]
            );
            assert_eq!(mux.live_streams().await, 0, "cancel cleans the shared SID");
        }

        #[tokio::test]
        async fn dropping_owner_requests_cancellation_and_cleans_stream() {
            let root = TempRoot::new();
            let (task, mux, transport) = setup(&root.0, Vec::new()).await;
            drop(task);
            tokio::time::timeout(Duration::from_secs(1), async {
                while mux.live_streams().await != 0 {
                    tokio::task::yield_now().await;
                }
            }).await.expect("dropping the owner must not leave the receiver detached");
            assert_eq!(
                transport.controls.lock().unwrap().as_slice(),
                &[json!({"type":"l2-close", "sid":SID, "err":"sync cancelled"})]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Link, Presence};
    use crate::host::{HostServices, NoHost, NoLog};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    const PID: &str = "sync-peer";
    const SID: u32 = l2::L2_SID_BASE + 7;
    const DEVICE: [u8; 32] = [7; 32];
    const USER: [u8; 32] = [3; 32];
    const OUTSIDE: &str = "remote dir is outside this device's drop directory";

    #[derive(Default)]
    struct CaptureTransport {
        controls: Mutex<Vec<Value>>,
    }

    #[async_trait::async_trait]
    impl Transport for CaptureTransport {
        async fn send_control(&self, msg: &Value) -> anyhow::Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            64 * 1024
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn is_dead(&self) -> bool {
            false
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn controls(t: &CaptureTransport) -> Vec<Value> {
        t.controls.lock().unwrap().clone()
    }

    #[derive(Clone)]
    enum Verdict {
        Allow,
        Deny(Option<String>),
        /// Decide exactly on the legacy fold, as the real policy site does in
        /// shadow mode. Lets a test pin the fold the endpoint delivered.
        Legacy,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct GateRecord {
        legacy: bool,
        action: String,
        resource: String,
        scoped: bool,
        denied: bool,
        ceiling: bool,
        has_grant: bool,
        cert_revoked: bool,
        binding: cap::BindingStrength,
        device: Option<[u8; 32]>,
        user: Option<[u8; 32]>,
    }

    // The policy site is injected, not reimplemented here: the test host
    // records the fold inputs the endpoint delivered and supplies a verdict.
    // The CLI's own gate suites cover the full capability/store matrix.
    struct TestHost {
        authoritative: bool,
        verdict: Verdict,
        cert_revoked: AtomicBool,
        gates: Mutex<Vec<GateRecord>>,
        consent: Mutex<Vec<(String, String)>>,
    }

    impl TestHost {
        fn new(authoritative: bool, verdict: Verdict) -> Arc<Self> {
            Arc::new(Self {
                authoritative,
                verdict,
                cert_revoked: AtomicBool::new(false),
                gates: Mutex::new(Vec::new()),
                consent: Mutex::new(Vec::new()),
            })
        }

        fn gates(&self) -> Vec<GateRecord> {
            self.gates.lock().unwrap().clone()
        }

        fn consent(&self) -> Vec<(String, String)> {
            self.consent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HostServices for TestHost {
        fn settings_get_str(&self, key: &str) -> Option<String> {
            NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            NoHost.devices_load()
        }
        fn is_self_uid(&self, a: &str, b: Option<&str>) -> bool {
            NoHost.is_self_uid(a, b)
        }
        fn rejoin_unwarned(&self) -> Duration {
            NoHost.rejoin_unwarned()
        }
        fn relay_banner(&self) -> String {
            NoHost.relay_banner()
        }
        fn relay_forbidden(&self) -> bool {
            NoHost.relay_forbidden()
        }
        fn channel_of(&self, secret: &str) -> String {
            NoHost.channel_of(secret)
        }
        fn roster_snapshot_json(&self) -> Option<String> {
            NoHost.roster_snapshot_json()
        }
        fn fleet_rv_present(&self) -> bool {
            false
        }
        fn now_secs(&self) -> u64 {
            100
        }
        fn cert_revoked_for(&self, _device_pub: Option<&[u8; 32]>) -> bool {
            self.cert_revoked.load(Ordering::Relaxed)
        }
        fn device_allows(&self, _name: &str, _capability: &str) -> bool {
            false
        }
        fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
            false
        }
        fn cap_authoritative(&self) -> bool {
            self.authoritative
        }
        fn cap_gate_effective(&self, gate: CapGate<'_>) -> cap::GateDecision {
            self.gates.lock().unwrap().push(GateRecord {
                legacy: gate.legacy_allowed,
                action: gate.action.to_string(),
                resource: gate.resource.to_string(),
                scoped: gate.scoped_in_bounds,
                denied: gate.denied,
                ceiling: gate.ceiling_authorizes,
                has_grant: gate.has_explicit_grant,
                cert_revoked: gate.cert_revoked,
                binding: gate.binding,
                device: gate.device_pub.copied(),
                user: gate.user_pub.copied(),
            });
            match &self.verdict {
                Verdict::Allow => cap::GateDecision::Allow,
                Verdict::Deny(reason) => cap::GateDecision::Deny {
                    cap_reason: reason.clone(),
                },
                Verdict::Legacy if gate.legacy_allowed => cap::GateDecision::Allow,
                Verdict::Legacy => cap::GateDecision::Deny { cap_reason: None },
            }
        }
        fn enqueue_request_if_requestable(&self, peer: &str, capability: &str) {
            self.consent
                .lock()
                .unwrap()
                .push((peer.to_string(), capability.to_string()));
        }
    }

    async fn connection(
        host: Arc<TestHost>,
        t: Arc<CaptureTransport>,
        trusted: bool,
        transport: bool,
        verified: Option<&str>,
    ) -> (Conn, tokio::net::TcpStream) {
        let (sio, far) = filament_signal::Client::loopback().await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let link_transport: Option<Arc<dyn Transport>> =
            if transport { Some(t.clone()) } else { None };
        let mut conn = Conn::for_command(
            filament_transport::TransportContext::default(),
            "http://127.0.0.1:9",
            sio,
            tx,
            "me".into(),
            false,
            None,
            false,
            false,
            Arc::new(NoLog),
            host.clone(),
        );
        conn.links.insert(
            PID.into(),
            Link {
                peer: None,
                info: json!({"id": PID}),
                name: "untrusted display name".into(),
                uid: None,
                transport: link_transport,
                workers: vec![],
                generation: 1,
                attempts: 0,
                trusted,
                expected_secret: None,
                // Avoid ambient device-record/consent I/O: the gate is keyed by
                // the resolved device key, not the display name.
                verified_name: verified.map(str::to_string),
                presence: Presence::Ready,
                direct: true,
                direct_route: "direct-quic",
                established_at: None,
                identity_device_pub: Some(DEVICE),
                identity_user_pub: Some(USER),
                identity_binding: cap::BindingStrength::Proven,
                identity_cert_expires: Some(1000),
                principal_kind: cap::PrincipalKind::OwnerDevice,
                host,
            },
        );
        (conn, far)
    }

    fn open(root: &str, sid: u32) -> Value {
        json!({"type": "sync-open", "sid": sid, "root": root})
    }

    struct Share(PathBuf);
    impl Share {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "tunlion-sync-recv-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Share {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            if target.is_dir() {
                std::os::windows::fs::symlink_dir(target, link)
            } else {
                std::os::windows::fs::symlink_file(target, link)
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no symlink support on this platform",
            ))
        }
    }

    #[tokio::test]
    async fn admitted_open_acks_the_canonical_root_on_the_shared_mux() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Accepted(a) = out else {
            panic!("a valid trusted open must be admitted");
        };
        assert_eq!(a.sid, SID);
        assert_eq!(
            a.who, "phone",
            "the pre-resolution verified name is the success label"
        );
        assert_eq!(a.root, share.0.join("inbox").canonicalize().unwrap());
        assert!(!a.dry_run);
        assert!(!a.delete);
        assert_eq!(
            controls(&t),
            vec![json!({
                "type": "sync-open-ack",
                "sid": SID,
                "dest": a.root.display().to_string(),
            })]
        );
        let mux = muxes.get(PID).expect("the shared mux entry is created");
        assert!(
            Arc::ptr_eq(mux, &a.mux),
            "admission must reuse the caller's mux"
        );
        assert!(mux.live_sids().await.contains(&SID));
        assert_eq!(
            host.gates(),
            vec![GateRecord {
                legacy: true,
                action: cap::CAP_TRANSFER.into(),
                resource: "self".into(),
                scoped: true,
                denied: false,
                ceiling: false,
                has_grant: false,
                cert_revoked: false,
                binding: cap::BindingStrength::Proven,
                device: Some(DEVICE),
                user: Some(USER),
            }]
        );
        mux.drop_stream(SID).await;
    }

    #[tokio::test]
    async fn shadow_denial_returns_the_park_inputs_and_raises_no_consent() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Deny(None));
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        // This tests only the admission-to-caller park inputs, NOT an actual
        // park/prove/re-drive through the CLI receive loop. That loop and its
        // durable-record/budget checks stay CLI-owned; its existing settle
        // tests cover pure sweep decisions, not this full integration flow.
        // Shadow mode with no cap reason falls back to the legacy deny. The
        // caller decides whether to park, or raise the request and send close.
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("a shadow deny must reach the caller for parking");
        };
        assert_eq!(d.sid, SID);
        assert_eq!(d.reason, "unverified peer: pair first");
        assert_eq!(d.park.sid, SID);
        assert_eq!(d.park.reason, d.reason);
        assert_eq!(d.err(), "not authorized: unverified peer: pair first");
        assert_eq!(
            d.close_frame(),
            json!({
                "type": "l2-close",
                "sid": SID,
                "err": "not authorized: unverified peer: pair first",
            })
        );
        assert!(controls(&t).is_empty(), "the caller sends the close");
        assert!(muxes.is_empty(), "a denied open registers nothing");
        assert!(
            host.consent().is_empty(),
            "consent stays the caller's decision, not admission's"
        );
        assert_eq!(host.gates().len(), 1);
    }

    #[tokio::test]
    async fn authoritative_denial_keeps_the_capability_reason() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(true, Verdict::Deny(Some("access expired".into())));
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("guest")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("an authoritative deny must be final at the gate");
        };
        assert_eq!(d.reason, "access expired");
        assert_eq!(d.park.reason, "access expired");
        assert_eq!(d.err(), "not authorized: access expired");
        assert!(controls(&t).is_empty());
        assert!(muxes.is_empty());
    }

    #[tokio::test]
    async fn gate_receives_the_transfer_trust_and_consent_inputs() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(true, Verdict::Deny(Some("cert revoked".into())));
        host.cert_revoked.store(true, Ordering::Relaxed);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Denied(_)));
        assert_eq!(
            host.gates(),
            vec![GateRecord {
                legacy: true,
                action: cap::CAP_TRANSFER.into(),
                resource: "self".into(),
                // Transfer is the scoped-default class; the enrolment ceiling
                // decides deliberate-tier actions, not transfer.
                scoped: true,
                denied: false,
                ceiling: false,
                has_grant: false,
                cert_revoked: true,
                binding: cap::BindingStrength::Proven,
                device: Some(DEVICE),
                user: Some(USER),
            }],
            "sync must keep the exact file-offer transfer gate inputs"
        );
        assert!(host.consent().is_empty());
    }

    #[tokio::test]
    async fn shadow_fold_uses_the_raw_trust_bit() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Legacy);

        // Trusted in shadow: the legacy fold admits.
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, Some("phone")).await;
        let mut muxes = MuxMap::new();
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Accepted(_)));
        assert_eq!(host.gates()[0].legacy, true);

        // Untrusted in shadow: the same fold denies, and carries park inputs.
        let t = Arc::new(CaptureTransport::default());
        let (mut conn, _far) =
            connection(host.clone(), t.clone(), false, true, Some("phone")).await;
        let mut muxes = MuxMap::new();
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Denied(d) = out else {
            panic!("the legacy fold must deny an untrusted link");
        };
        assert_eq!(d.reason, "unverified peer: pair first");
        assert_eq!(host.gates()[1].legacy, false);
    }

    #[tokio::test]
    async fn malformed_sid_and_missing_sid_are_ignored_without_gating() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();

        let frames = [
            json!({}),
            json!([]),
            json!({"type": "sync-open"}),
            json!({"type": "sync-open", "sid": 1}),
            json!({"type": "sync-open", "sid": u32::MAX as u64 + 1}),
            json!({"type": "sync-open", "sid": "7"}),
            json!({"type": "sync-open", "sid": null}),
        ];
        for frame in frames {
            let out = admit_sync_open(&mut conn, PID, &frame, &mut muxes, &share.0).await;
            assert!(
                matches!(out, SyncAdmission::Ignored),
                "malformed sid must be ignored: {frame}"
            );
        }
        assert!(controls(&t).is_empty(), "no close for an unaddressable sid");
        assert!(muxes.is_empty(), "no mux entry for an unaddressable sid");
        assert!(host.gates().is_empty(), "the gate must not run");
    }

    #[tokio::test]
    async fn missing_transport_is_ignored_before_any_gate() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, false, None).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        assert!(matches!(out, SyncAdmission::Ignored));
        assert!(controls(&t).is_empty());
        assert!(muxes.is_empty());
        assert!(host.gates().is_empty());
    }

    #[tokio::test]
    async fn traversal_and_absolute_roots_refuse_before_authorization() {
        let share = Share::new();
        let outside = Share::new();
        let outside_abs = outside.0.to_string_lossy().into_owned();
        let requests = [outside_abs.as_str(), "../escape", "..", "/"];
        for request in requests {
            let t = Arc::new(CaptureTransport::default());
            let host = TestHost::new(false, Verdict::Allow);
            let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
            let mut muxes = MuxMap::new();

            let out =
                admit_sync_open(&mut conn, PID, &open(request, SID), &mut muxes, &share.0).await;
            let SyncAdmission::Refused(r) = out else {
                panic!("root {request:?} must be refused by path bounds");
            };
            assert_eq!(r.sid, SID);
            assert_eq!(r.reason, OUTSIDE, "moved path_bounds supplies the reason");
            assert_eq!(
                r.close,
                json!({"type": "l2-close", "sid": SID, "err": OUTSIDE})
            );
            assert!(
                host.gates().is_empty(),
                "bounds must run before authorization for {request:?}"
            );
            assert!(muxes.is_empty());
            assert!(controls(&t).is_empty(), "the caller sends the refusal");
        }
    }

    #[tokio::test]
    async fn symlinked_root_escape_refuses_before_authorization() {
        let share = Share::new();
        let outside = Share::new();
        let link = share.0.join("escape");
        #[cfg(any(unix, windows))]
        symlink(&outside.0, &link).unwrap_or_else(|e| {
            panic!(
                "must create the directory-symlink escape fixture ({link:?} -> {:?}): {e}. \
                 On Windows enable Developer Mode or grant SeCreateSymbolicLinkPrivilege; \
                 supported CI targets must run this arm, not skip it.",
                outside.0
            )
        });
        #[cfg(not(any(unix, windows)))]
        {
            eprintln!("note: this platform has no directory symlinks; symlink escape arm skipped");
            return;
        }
        assert_eq!(
            link.canonicalize().unwrap(),
            outside.0.canonicalize().unwrap(),
            "the escape fixture must resolve to the outside directory"
        );
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host.clone(), t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();

        let out = admit_sync_open(&mut conn, PID, &open("escape", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a symlinked root escape must be refused");
        };
        assert_eq!(r.reason, OUTSIDE);
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": OUTSIDE})
        );
        assert!(host.gates().is_empty());
        assert!(muxes.is_empty());
    }

    #[tokio::test]
    async fn capacity_and_collision_do_not_ack_or_replace() {
        let share = Share::new();

        // Capacity is checked before registration, so not even the stream that
        // was under the cap gets acked.
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mux = Mux::new(t.clone(), conn.host.clone());
        for i in 0..l2::MAX_STREAMS_PER_LINK {
            assert!(mux
                .register_stream(l2::L2_SID_BASE + i as u32)
                .await
                .is_some());
        }
        let mut muxes = MuxMap::from([(PID.to_string(), mux.clone())]);
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a full mux must refuse");
        };
        assert_eq!(r.reason, "too many streams");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "too many streams"})
        );
        assert!(controls(&t).is_empty(), "capacity must not ack");
        assert_eq!(mux.live_sids().await.len(), l2::MAX_STREAMS_PER_LINK);

        // A live sid is never displaced, and the existing stream keeps its pipe.
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mux = Mux::new(t.clone(), conn.host.clone());
        let mut existing = mux.register_stream(SID).await.unwrap();
        let mut muxes = MuxMap::from([(PID.to_string(), mux.clone())]);
        let out = admit_sync_open(&mut conn, PID, &open("inbox", SID), &mut muxes, &share.0).await;
        let SyncAdmission::Refused(r) = out else {
            panic!("a colliding sid must refuse");
        };
        assert_eq!(r.reason, "sid in use");
        assert_eq!(
            r.close,
            json!({"type": "l2-close", "sid": SID, "err": "sid in use"})
        );
        assert!(controls(&t).is_empty(), "collision must not ack");
        assert_eq!(mux.live_sids().await, vec![SID]);
        assert!(
            matches!(
                existing.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the original stream's pipe must survive"
        );
        mux.drop_stream(SID).await;
    }

    #[tokio::test]
    async fn dry_run_bounds_the_root_without_creating_it() {
        let share = Share::new();
        let t = Arc::new(CaptureTransport::default());
        let host = TestHost::new(false, Verdict::Allow);
        let (mut conn, _far) = connection(host, t.clone(), true, true, None).await;
        let mut muxes = MuxMap::new();
        let frame = json!({
            "type": "sync-open",
            "sid": SID,
            "root": "later",
            "dry_run": true,
            "delete": true,
        });

        let out = admit_sync_open(&mut conn, PID, &frame, &mut muxes, &share.0).await;
        let SyncAdmission::Accepted(a) = out else {
            panic!("a dry run still admits the stream");
        };
        assert!(a.dry_run);
        assert!(a.delete);
        assert!(!share.0.join("later").exists(), "a dry run creates nothing");
        assert_eq!(a.root, share.0.join("later"));
        assert_eq!(
            controls(&t),
            vec![json!({
                "type": "sync-open-ack",
                "sid": SID,
                "dest": a.root.display().to_string(),
            })]
        );
        muxes.get(PID).unwrap().drop_stream(SID).await;
    }
}
