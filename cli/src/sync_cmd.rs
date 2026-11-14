//! `tunlion sync <local-dir> <device>:<remote-dir>`: rsync-shaped delta
//! transfer between paired devices. The sender walks the tree into a manifest
//! (whole-file sha256 plus per-chunk sha256), the receiver answers with what it
//! lacks, and only those chunks cross. Every landed file is verified by the same
//! whole-file digest `send`/`receive` use before it is
//! renamed into place, and the receiver admits the stream through the same
//! transfer gate a `file-offer` from a paired device passes (`CAP_TRANSFER`).
//!
//! Wire: one L2 stream, opened like `exec-open`. Both directions carry
//! `[u32 BE len][payload]` records; JSON records steer, raw records carry chunk
//! bytes. The receiver never trusts a path: every relative path is reduced by
//! `safe_relpath` and bounded to its root, which itself must lie inside the
//! daemon's drop directory.
use crate::conn::Conn;
use crate::l2;
use crate::net::{Ev, Transport};
use crate::ui;
use anyhow::{bail, Result};
use bytes::Bytes;
use filament_peerloop::sync::{self, SyncAccepted, SyncAdmission};
pub(crate) use filament_peerloop::sync::{
    diff, hash_file, walk_manifest, Entry, Need, Plan, SYNC_CHUNK,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const MAX_RECORD: usize = filament_peerloop::sync::MAX_SYNC_RECORD_BYTES;

// ------------------------------------------------------------- records ------

#[derive(Default)]
struct Records(Vec<u8>);

impl Records {
    fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.0.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        if n > MAX_RECORD {
            bail!("sync record too large ({n} bytes)");
        }
        if self.0.len() < 4 + n {
            return Ok(None);
        }
        let rec = self.0[4..4 + n].to_vec();
        self.0.drain(..4 + n);
        Ok(Some(rec))
    }
}

async fn send_rec(t: &Arc<dyn Transport>, sid: u32, payload: &[u8]) -> Result<()> {
    let mut v = (payload.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(payload);
    for c in v.chunks(t.max_payload().max(1)) {
        t.send_frame(sid, 0, c).await?;
    }
    Ok(())
}

async fn send_json(t: &Arc<dyn Transport>, sid: u32, v: &Value) -> Result<()> {
    send_rec(t, sid, &serde_json::to_vec(v)?).await
}

/// One inbound record from the stream pipe. `rx` is the initiator's link event
/// channel (None on the receiver, whose daemon loop routes frames for it):
/// frames are handed to the mux, an `l2-close` for our sid ends the stream.
async fn next_rec(
    pipe: &mut mpsc::Receiver<Option<Bytes>>,
    mut rx: Option<&mut mpsc::UnboundedReceiver<Ev>>,
    mux: &l2::Mux,
    sid: u32,
    recs: &mut Records,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let source = mux.transport().source_id();
    loop {
        if let Some(r) = recs.next()? {
            return Ok(r);
        }
        tokio::select! {
            item = pipe.recv() => match item {
                Some(Some(b)) => recs.0.extend_from_slice(&b),
                _ => bail!("the peer closed the sync stream"),
            },
            // Selected-source reads, as exec does: the direct reader tags its
            // events with their source, and a bare match never saw them.
            ev = async { match rx.as_deref_mut() { Some(rx) => l2::recv_selected_event(rx, source).await, None => std::future::pending().await } } => match ev {
                Some(Ev::Control(_, v)) => {
                    if v["type"].as_str() == Some("l2-close") && v["sid"].as_u64() == Some(sid as u64) {
                        bail!("{}", v["err"].as_str().unwrap_or("closed"));
                    }
                }
                Some(Ev::Chunk(_, got, _, data)) => mux.on_frame(got, data).await,
                Some(_) => {}
                None => bail!("the link died during sync"),
            },
            _ = tokio::time::sleep_until(deadline) => bail!("timed out waiting for the peer"),
        }
    }
}

/// Wait for the receiver's answer to `sync-open`: `Ok(dest)` on the ack,
/// `Err(reason)` on a refusal or a link that closed first. Frames for the
/// stream that arrive meanwhile go to the mux.
///
/// Reads through the selected-source gate, as exec does. The direct reader
/// delivers the ack source-tagged; a bare `Ev::Control` match dropped it and
/// the caller timed out as "no answer" with the peer's ack already received.
async fn wait_open_ack(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    source: Option<crate::net::SourceId>,
    mux: &l2::Mux,
    sid: u32,
) -> std::result::Result<Option<String>, String> {
    loop {
        match l2::recv_selected_event(rx, source).await {
            Some(Ev::Control(_, v)) if v["sid"].as_u64() == Some(sid as u64) => {
                match v["type"].as_str() {
                    Some("sync-open-ack") => return Ok(v["dest"].as_str().map(str::to_string)),
                    Some("l2-close") => {
                        return Err(v["err"].as_str().unwrap_or("closed").to_string())
                    }
                    _ => {}
                }
            }
            Some(Ev::Chunk(_, got, _, data)) => mux.on_frame(got, data).await,
            Some(_) => {}
            None => return Err("closed the link before answering".into()),
        }
    }
}

async fn next_json(
    pipe: &mut mpsc::Receiver<Option<Bytes>>,
    rx: Option<&mut mpsc::UnboundedReceiver<Ev>>,
    mux: &l2::Mux,
    sid: u32,
    recs: &mut Records,
    timeout: Duration,
) -> Result<Value> {
    Ok(serde_json::from_slice(
        &next_rec(pipe, rx, mux, sid, recs, timeout).await?,
    )?)
}

// ------------------------------------------------------------ initiator -----

pub(crate) struct SyncOpts {
    pub delete: bool,
    pub dry_run: bool,
    pub json: bool,
    /// `--json-lines`: one record per file as it happens, then the summary
    /// (NDJSON). Plain `--json` is one document, like every other verb.
    pub json_lines: bool,
}

/// Exit codes per docs/agent-output-audit.md: 3 unknown device, 4 denied,
/// 6 unreachable, 8 partial, 1 anything else (the taxonomy in exit_codes.rs;
/// 5 belongs to `reach --until-direct`, so unreachable and partial moved).
struct Fail(i32, &'static str, String);
impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.2)
    }
}
impl std::fmt::Debug for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.2)
    }
}
impl std::error::Error for Fail {}
fn fail(exit: i32, code: &'static str, msg: impl Into<String>) -> anyhow::Error {
    Fail(exit, code, msg.into()).into()
}

/// What a sync did, counted one way for every output. Pure, unit-tested.
///
/// The counters a script reads, and what each one means:
///
///   counts.total      local entries considered: every regular file in the
///                     manifest plus every entry skipped while walking
///   counts.<state>    entries that ended in that state; the states partition
///                     `total`, so sent + updated + same + skipped + failed
///                     (+ would_send + would_update on a dry run) == total.
///                     `deleted`/`would_delete` are REMOTE files and are not
///                     part of `total`.
///   bytes.total       size of every local regular file (the tree)
///   bytes.moved       bytes actually transferred and acknowledged (sent and
///                     updated only; 0 on a dry run, failed files excluded)
///   bytes.would_move  on a dry run, what `moved` would have been
///
/// The old summary had `moved` (bytes, including failed and dry-run bytes)
/// beside `sent` (a file count) and `total` (bytes), which read as
/// "moved 4 of total 4, sent 2" for two files. `moved` and `total` are kept
/// with their byte meaning for existing scripts; `counts` and `bytes` are the
/// labelled form.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Tally {
    pub(crate) files_total: u64,
    pub(crate) bytes_total: u64,
    pub(crate) bytes_moved: u64,
    pub(crate) bytes_would_move: u64,
    pub(crate) counts: BTreeMap<&'static str, u64>,
}

impl Tally {
    pub(crate) fn record(&mut self, state: &'static str, bytes: u64) {
        *self.counts.entry(state).or_insert(0) += 1;
        match state {
            "sent" | "updated" => self.bytes_moved += bytes,
            "would send" | "would update" => self.bytes_would_move += bytes,
            _ => {}
        }
    }

    pub(crate) fn count(&self, state: &str) -> u64 {
        self.counts.get(state).copied().unwrap_or(0)
    }

    /// Local entries that reached a state: must equal `files_total`.
    pub(crate) fn accounted(&self) -> u64 {
        [
            "sent",
            "updated",
            "same",
            "skipped",
            "failed",
            "would send",
            "would update",
        ]
        .iter()
        .map(|s| self.count(s))
        .sum()
    }

    /// The summary `data` object (without the per-file list).
    pub(crate) fn summary(&self, dry_run: bool, exit: i32) -> Value {
        let mut counts = json!({ "total": self.files_total });
        for s in [
            "sent",
            "updated",
            "same",
            "skipped",
            "failed",
            "deleted",
            "would send",
            "would update",
            "would delete",
        ] {
            counts[s.replace(' ', "_")] = json!(self.count(s));
        }
        let mut d = json!({
            "counts": counts,
            "bytes": {
                "total": self.bytes_total,
                "moved": self.bytes_moved,
                "would_move": self.bytes_would_move,
            },
            "dry_run": dry_run,
            "exit": exit,
            // Schema-1 names, kept for existing scripts: both are BYTES.
            "moved": self.bytes_moved,
            "total": self.bytes_total,
        });
        for (k, v) in &self.counts {
            d[*k] = json!(v);
        }
        d
    }
}

struct Report {
    json: bool,
    json_lines: bool,
    tally: Tally,
    files: Vec<Value>,
    /// Where the files landed on the peer, as the peer reported it in its
    /// ack (absolute). `None` from an older peer that does not say.
    dest: Option<String>,
    /// Files on the device that the local directory does not have, left in
    /// place because `--delete` was not given. Counted so the summary can say
    /// so: sync is a one-way update, and a deletion on the source that is not
    /// carried over must not pass silently.
    kept_on_peer: u64,
}
impl Report {
    fn line(&mut self, state: &'static str, p: &str, bytes: u64, reason: Option<&str>) {
        self.tally.record(state, bytes);
        if self.json || self.json_lines {
            let mut d = json!({ "file": p, "state": state, "bytes": bytes });
            if let Some(r) = reason {
                d["reason"] = json!(r);
            }
            if self.json_lines {
                println!("{}", json!({ "ok": true, "verb": "sync", "data": d }));
            } else {
                self.files.push(d);
            }
        } else {
            ui::say(&format!("  {}", file_result_text(state, p, bytes, reason)));
        }
    }
}

/// Human-readable per-file result. Keep the receiver's refusal reason intact:
/// security-policy refusals (such as Windows' temporary fail-closed path) must
/// not collapse into a generic "transfer failed" line.
fn file_result_text(state: &str, path: &str, bytes: u64, reason: Option<&str>) -> String {
    let tail = match (reason, bytes) {
        (Some(reason), _) => format!(": {reason}  {path}"),
        (None, 0) => format!("  {path}"),
        (None, n) => format!("  {path}  ({})", crate::human(n)),
    };
    format!("{state}{tail}")
}

/// Run the verb end to end and return the process exit code. Prints its own
/// lines (human via `ui::`, machine via one JSONL envelope per file plus a
/// final one), so the dispatch arm only has to exit.
pub(crate) async fn run(
    server: &str,
    local: &Path,
    peer: &str,
    remote_dir: &str,
    relay: bool,
    opts: SyncOpts,
) -> i32 {
    let mut rep = Report {
        json: opts.json,
        json_lines: opts.json_lines,
        tally: Tally::default(),
        files: Vec::new(),
        dest: None,
        kept_on_peer: 0,
    };
    match sync_inner(server, local, peer, remote_dir, relay, &opts, &mut rep).await {
        Ok(total) => {
            let partial = rep.tally.count("failed") > 0;
            let exit = if partial { 8 } else { 0 };
            if opts.json || opts.json_lines {
                let mut d = rep.tally.summary(opts.dry_run, exit);
                if let Some(dest) = &rep.dest {
                    d["dest"] = json!(dest);
                }
                d["only_on_peer"] = json!(rep.kept_on_peer);
                if !opts.json_lines {
                    d["files"] = Value::Array(std::mem::take(&mut rep.files));
                }
                crate::ui::json_out(&json!({ "ok": !partial, "verb": "sync", "data": d }));
            } else {
                let c = |k: &str| rep.tally.count(k);
                // On a dry run nothing moved: say what WOULD, in bytes.
                let moved = if opts.dry_run {
                    rep.tally.bytes_would_move
                } else {
                    rep.tally.bytes_moved
                };
                ui::say(&format!(
                    "  {} {} of {} {}{}: {} sent, {} updated, {} same, {} skipped{}{}",
                    if partial {
                        ui::glyph_warn()
                    } else {
                        ui::glyph_ok()
                    },
                    crate::human(moved),
                    crate::human(total),
                    if opts.dry_run { "would move" } else { "moved" },
                    if opts.dry_run {
                        " (dry run, nothing moved)"
                    } else {
                        ""
                    },
                    c("sent") + c("would send"),
                    c("updated") + c("would update"),
                    c("same"),
                    c("skipped"),
                    if c("deleted") + c("would delete") > 0 {
                        format!(", {} deleted", c("deleted") + c("would delete"))
                    } else {
                        String::new()
                    },
                    if partial {
                        format!(", {} FAILED", c("failed"))
                    } else {
                        String::new()
                    },
                ));
                // Say WHERE: `sync dir peer:proj` lands under the peer's drop
                // folder, which the output never said, so the files looked lost.
                ui::say(&format!(
                    "  {} {}",
                    if opts.dry_run { "would land in" } else { "on" },
                    sync_destination(peer, remote_dir, rep.dest.as_deref())
                ));
                if let Some(line) = kept_on_peer_line(rep.kept_on_peer, peer) {
                    ui::say(&line);
                }
            }
            exit
        }
        Err(e) => {
            let (exit, code) = match e.downcast_ref::<Fail>() {
                Some(Fail(x, c, _)) => (*x, *c),
                None => (1, "error"),
            };
            if opts.json || opts.json_lines {
                crate::ui::json_out(
                    &json!({ "ok": false, "verb": "sync", "error": { "code": code, "exit": exit, "message": e.to_string() } }),
                );
            } else {
                ui::problem("sync failed", &e.to_string(), &[]);
            }
            exit
        }
    }
}

/// The honest end of a sync without `--delete`: files that exist only on the
/// device were left there. A first-time-user test deleted a file locally,
/// re-ran sync, and saw nothing say that the device still had it.
fn kept_on_peer_line(n: u64, peer: &str) -> Option<String> {
    (n > 0).then(|| {
        format!(
            "  {n} file{} exist{} only on '{peer}' (not deleted; use --delete to remove)",
            if n == 1 { "" } else { "s" },
            if n == 1 { "s" } else { "" },
        )
    })
}

async fn sync_inner(
    server: &str,
    local: &Path,
    peer: &str,
    remote_dir: &str,
    relay: bool,
    opts: &SyncOpts,
    rep: &mut Report,
) -> Result<u64> {
    let local = local
        .canonicalize()
        .map_err(|e| fail(2, "usage", format!("{}: {e}", local.display())))?;
    if !local.is_dir() {
        return Err(fail(
            2,
            "usage",
            format!("{} is not a directory", local.display()),
        ));
    }
    crate::identity_state::require_known_device(peer)
        .map_err(|e| fail(3, "unknown_device", e.to_string()))?;
    let (files, skipped) = walk_manifest(&local)?;
    let total: u64 = files.iter().map(|e| e.size).sum();
    rep.tally.files_total = (files.len() + skipped.len()) as u64;
    rep.tally.bytes_total = total;

    let (t, mut rx, guard, _diag) = match tokio::time::timeout(
        Duration::from_secs(45),
        l2::bring_up_to_known(server, peer, relay, "sync"),
    )
    .await
    {
        Ok(Ok(x)) => x,
        Ok(Err(e)) if e.to_string().contains("no known device") => {
            return Err(fail(3, "unknown_device", e.to_string()));
        }
        Ok(Err(e)) => return Err(fail(6, "unreachable", e.to_string())),
        Err(_) => {
            return Err(fail(
                6,
                "unreachable",
                format!("couldn't reach '{peer}' in 45s"),
            ))
        }
    };
    guard.forget();
    let mux = l2::Mux::new(t.clone(), crate::host_impl::cli_host());
    let sid = mux.alloc_sid();
    let mut pipe = mux
        .register_stream(sid)
        .await
        .ok_or_else(|| fail(1, "error", format!("sid {sid:#x} already in use")))?;
    t.send_control(&json!({
        "type": "sync-open", "sid": sid, "root": remote_dir,
        "delete": opts.delete, "dry_run": opts.dry_run,
    }))
    .await?;
    // Ack wait, exec's four outcomes: ack, refusal with the receiver's reason,
    // stream closed, silence.
    let ack = tokio::time::timeout(
        Duration::from_secs(15),
        wait_open_ack(&mut rx, t.source_id(), &mux, sid),
    )
    .await
    .map_err(|_| {
        fail(
            6,
            "unreachable",
            format!("no answer from '{peer}' (is `tunlion up` running there?)"),
        )
    })?;
    match ack {
        Err(reason) => {
            return Err(fail(
                4,
                "denied",
                format!("'{peer}' refused sync: {reason}"),
            ));
        }
        Ok(dest) => rep.dest = dest,
    }
    let mut recs = Records::default();
    send_json(&t, sid, &json!({ "type": "manifest", "files": files })).await?;
    let plan: Plan = serde_json::from_value(
        next_json(
            &mut pipe,
            Some(&mut rx),
            &mux,
            sid,
            &mut recs,
            Duration::from_secs(300),
        )
        .await?,
    )?;

    for (p, why) in &skipped {
        rep.line("skipped", p, 0, Some(why));
    }
    for p in &plan.same {
        rep.line("same", p, 0, None);
    }
    let by_path: BTreeMap<&str, &Entry> = files.iter().map(|e| (e.p.as_str(), e)).collect();
    for n in &plan.need {
        let Some(e) = by_path.get(n.p.as_str()) else {
            continue;
        };
        // `n.chunks` comes off the wire, so its indices are the PEER's claim,
        // not ours. `saturating_*` keeps an index past the end of the file from
        // panicking this side in a debug build (and from wrapping in release);
        // such a chunk reads zero bytes and the receiver refuses it by range.
        let bytes: u64 = (n.chunks.iter())
            .map(|&i| {
                e.size
                    .saturating_sub((i as u64).saturating_mul(SYNC_CHUNK))
                    .min(SYNC_CHUNK)
            })
            .sum();
        let state = match (opts.dry_run, n.new) {
            (true, true) => "would send",
            (true, false) => "would update",
            (false, true) => "sent",
            (false, false) => "updated",
        };
        if opts.dry_run {
            rep.line(state, &n.p, bytes, None);
            continue;
        }
        send_json(
            &t,
            sid,
            &json!({ "type": "file", "p": e.p, "size": e.size, "full": e.full, "mtime": e.mtime }),
        )
        .await?;
        let mut f = std::fs::File::open(local.join(&e.p))?;
        let mut buf = vec![0u8; SYNC_CHUNK as usize];
        for &i in &n.chunks {
            use std::io::{Read, Seek};
            f.seek(std::io::SeekFrom::Start(i as u64 * SYNC_CHUNK))?;
            let mut got = 0;
            while got < buf.len() {
                let k = f.read(&mut buf[got..])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            send_json(&t, sid, &json!({ "type": "chunk", "idx": i })).await?;
            send_rec(&t, sid, &buf[..got]).await?;
        }
        send_json(&t, sid, &json!({ "type": "file-end" })).await?;
        let ack = next_json(
            &mut pipe,
            Some(&mut rx),
            &mux,
            sid,
            &mut recs,
            Duration::from_secs(300),
        )
        .await?;
        if ack["ok"].as_bool() == Some(true) {
            rep.line(state, &n.p, bytes, None);
        } else {
            rep.line(
                "failed",
                &n.p,
                bytes,
                Some(ack["err"].as_str().unwrap_or("receiver refused the file")),
            );
        }
    }
    if !opts.delete {
        rep.kept_on_peer = plan.extra.len() as u64;
    }
    if opts.delete && !plan.extra.is_empty() {
        if opts.dry_run {
            for p in &plan.extra {
                rep.line("would delete", p, 0, None);
            }
        } else {
            send_json(&t, sid, &json!({ "type": "delete", "paths": plan.extra })).await?;
            let ack = next_json(
                &mut pipe,
                Some(&mut rx),
                &mux,
                sid,
                &mut recs,
                Duration::from_secs(120),
            )
            .await?;
            for p in ack["paths"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str())
            {
                rep.line("deleted", p, 0, None);
            }
        }
    }
    send_json(&t, sid, &json!({ "type": "done" })).await?;
    let _ = t.flush().await;
    mux.drop_stream(sid).await;
    Ok(total)
}

// ------------------------------------------------------------- receiver -----

/// `peer:/abs/path` as the peer reported it, else the request as typed with
/// where it is relative to (an older peer does not report the path).
fn sync_destination(peer: &str, remote_dir: &str, dest: Option<&str>) -> String {
    match dest {
        Some(d) => format!("{peer}:{d}"),
        None => format!("{peer}:{remote_dir} (under {peer}'s drop folder)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport whose events carry `source`. Records nothing, sends nothing.
    struct SourcedTransport(Option<crate::net::SourceId>);
    #[async_trait::async_trait]
    impl Transport for SourcedTransport {
        async fn send_control(&self, _msg: &Value) -> Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> Result<()> {
            Ok(())
        }
        async fn flush(&self) -> Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            1024
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn source_id(&self) -> Option<crate::net::SourceId> {
            self.0
        }
    }

    fn sourced(source: crate::net::SourceId, inner: Ev) -> Ev {
        Ev::Sourced { pid: "boxb".into(), source, inner: Box::new(inner) }
    }

    /// The direct reader delivers the ack source-tagged (`Ev::Sourced {
    /// Control }`); from the selected transport it is accepted, from another
    /// source (a losing candidate) it is not, even naming our sid.
    ///
    /// The chunks here are tagged with their source, the shape the QUIC and
    /// WebRTC readers now emit (see the transport's chunk attribution). The
    /// gate admits a chunk only from the selected source, so a losing
    /// candidate's chunk does not reach this link's stream.
    #[tokio::test]
    async fn open_ack_reads_the_selected_source_and_drops_others() {
        let selected = crate::net::SourceId::next();
        let stale = crate::net::SourceId::next();
        let mux = l2::Mux::new(
            Arc::new(SourcedTransport(Some(selected))),
            crate::host_impl::cli_host(),
        );
        let sid = mux.alloc_sid();
        let mut pipe = mux.register_stream(sid).await.expect("register stream");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let ack = |dest: &str| {
            Ev::Control("boxb".into(), json!({"type": "sync-open-ack", "sid": sid, "dest": dest}))
        };
        let chunk = |b: &'static [u8]| Ev::Chunk("boxb".into(), sid, None, Bytes::from_static(b));
        tx.send(sourced(stale, chunk(b"stale"))).unwrap();
        tx.send(sourced(stale, ack("/stale"))).unwrap();
        tx.send(sourced(selected, chunk(b"live"))).unwrap();
        tx.send(sourced(selected, ack("/live"))).unwrap();

        let got = tokio::time::timeout(
            Duration::from_secs(5),
            wait_open_ack(&mut rx, Some(selected), &mux, sid),
        )
        .await
        .expect("a selected-source ack must end the wait");
        assert_eq!(got, Ok(Some("/live".to_string())), "the stale ack was taken");
        assert_eq!(
            pipe.try_recv().ok(),
            Some(Some(Bytes::from_static(b"live"))),
            "the selected chunk must reach the stream, and the stale one must not precede it"
        );
        assert!(pipe.try_recv().is_err(), "a stale chunk reached the stream");
    }

    /// A transport with no source of its own still delivers an untagged
    /// control, and the gate accepts it. Only a CHUNK must be attributed, so
    /// an untagged control keeps working while an untagged chunk does not.
    #[tokio::test]
    async fn open_ack_still_reads_untagged_events() {
        let mux = l2::Mux::new(Arc::new(SourcedTransport(None)), crate::host_impl::cli_host());
        let sid = mux.alloc_sid();
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(Ev::Control("boxb".into(), json!({"type": "sync-open-ack", "sid": sid, "dest": "/d"})))
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), wait_open_ack(&mut rx, None, &mux, sid))
            .await
            .expect("an untagged ack must end the wait");
        assert_eq!(got, Ok(Some("/d".to_string())));
    }

    /// The plan and file acks come back as length-prefixed JSON records on the
    /// stream, carried in chunks, here split across two frames. A stale-source
    /// `l2-close` between them must not end the read, and a stale-source chunk
    /// must not reach the stream; the record must be reassembled whole.
    ///
    /// The chunks are tagged with the selected source, the shape the readers
    /// now emit: an untagged chunk is refused by the source gate, because a
    /// chunk without a source cannot be attributed to this link.
    #[tokio::test]
    async fn next_json_reads_an_ack_record_across_tagged_chunks() {
        let selected = crate::net::SourceId::next();
        let stale = crate::net::SourceId::next();
        let mux = l2::Mux::new(
            Arc::new(SourcedTransport(Some(selected))),
            crate::host_impl::cli_host(),
        );
        let sid = mux.alloc_sid();
        let mut pipe = mux.register_stream(sid).await.expect("register stream");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let body = serde_json::to_vec(&json!({"type": "plan-ack", "need": ["a", "b"]})).unwrap();
        let mut rec = (body.len() as u32).to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        let (head, tail) = rec.split_at(7);
        // A stale source's chunk for our sid must not reach the stream.
        tx.send(sourced(
            stale,
            Ev::Chunk("boxb".into(), sid, None, Bytes::from_static(b"stale")),
        ))
        .unwrap();
        tx.send(sourced(
            selected,
            Ev::Chunk("boxb".into(), sid, None, Bytes::copy_from_slice(head)),
        ))
        .unwrap();
        tx.send(sourced(
            stale,
            Ev::Control("boxb".into(), json!({"type": "l2-close", "sid": sid, "err": "stale close"})),
        ))
        .unwrap();
        tx.send(sourced(
            selected,
            Ev::Chunk("boxb".into(), sid, None, Bytes::copy_from_slice(tail)),
        ))
        .unwrap();
        let mut recs = Records(Vec::new());
        let v = next_json(&mut pipe, Some(&mut rx), &mux, sid, &mut recs, Duration::from_secs(5))
            .await
            .expect("the ack record must arrive whole despite the stale close");
        assert_eq!(v, json!({"type": "plan-ack", "need": ["a", "b"]}));
    }

    /// Mid-stream, an `l2-close` for our sid ends the transfer only when it
    /// comes from the selected transport. A stale close must not end it.
    #[tokio::test]
    async fn next_rec_honours_only_the_selected_close() {
        let selected = crate::net::SourceId::next();
        let stale = crate::net::SourceId::next();
        let mux = l2::Mux::new(
            Arc::new(SourcedTransport(Some(selected))),
            crate::host_impl::cli_host(),
        );
        let sid = mux.alloc_sid();
        let mut pipe = mux.register_stream(sid).await.expect("register stream");
        let (tx, mut rx) = mpsc::unbounded_channel();
        let close = |err: &str| {
            Ev::Control("boxb".into(), json!({"type": "l2-close", "sid": sid, "err": err}))
        };
        tx.send(sourced(stale, close("stale close"))).unwrap();
        tx.send(sourced(selected, close("receiver refused"))).unwrap();
        let mut recs = Records(Vec::new());
        let err = next_rec(&mut pipe, Some(&mut rx), &mux, sid, &mut recs, Duration::from_secs(5))
            .await
            .expect_err("the selected close must end the stream");
        assert_eq!(err.to_string(), "receiver refused");
    }

    #[test]
    fn windows_sync_refusal_is_operator_visible_without_genericizing_reason() {
        // Windows receive now works for NTFS; an unsupported filesystem still
        // fails closed with this named reason, and the renderer must keep it
        // verbatim instead of replacing it with a generic sentence.
        let reason = "Windows sync finalization is not supported on this filesystem: the filesystem cannot express a handle-relative replace";
        assert_eq!(
            file_result_text("failed", "docs/notes.txt", 123, Some(reason)),
            "failed: Windows sync finalization is not supported on this filesystem: the filesystem cannot express a handle-relative replace  docs/notes.txt",
        );
        let mut report = Report {
            json: true,
            json_lines: false,
            tally: Tally::default(),
            files: Vec::new(),
            dest: None,
            kept_on_peer: 0,
        };
        report.line("failed", "docs/notes.txt", 123, Some(reason));
        assert_eq!(report.files[0]["reason"], reason);
        assert_eq!(report.files[0]["state"], "failed");
    }

    /// J4: two files gave `"moved":4,"sent":2,"total":4` and three gave
    /// `"moved":2,"sent":1,"same":2,"total":6`: bytes and file counts side by
    /// side with no labels, and failed or dry-run bytes counted as moved. The
    /// labelled counters partition the files and the bytes add up.
    #[test]
    fn sync_counters_add_up() {
        // The reported run: three files of 2 bytes each, 1 sent and 2 same.
        let mut t = Tally {
            files_total: 3,
            bytes_total: 6,
            ..Default::default()
        };
        t.record("sent", 2);
        t.record("same", 0);
        t.record("same", 0);
        assert_eq!(t.accounted(), t.files_total);
        let s = t.summary(false, 0);
        assert_eq!(s["counts"]["total"], json!(3));
        assert_eq!(s["counts"]["sent"], json!(1));
        assert_eq!(s["counts"]["same"], json!(2));
        assert_eq!(s["counts"]["updated"], json!(0));
        assert_eq!(s["bytes"]["total"], json!(6));
        assert_eq!(s["bytes"]["moved"], json!(2));
        assert_eq!(
            s["moved"], s["bytes"]["moved"],
            "the schema-1 name is bytes"
        );
        assert_eq!(
            s["total"], s["bytes"]["total"],
            "the schema-1 name is bytes"
        );

        // A failed file's bytes did not move; a skipped entry is counted.
        let mut f = Tally {
            files_total: 4,
            bytes_total: 30,
            ..Default::default()
        };
        f.record("sent", 10);
        f.record("updated", 4);
        f.record("failed", 9);
        f.record("skipped", 0);
        f.record("deleted", 0);
        assert_eq!(
            f.accounted(),
            4,
            "deleted is a remote file, not part of total"
        );
        assert_eq!(f.bytes_moved, 14);
        let s = f.summary(false, 8);
        assert_eq!(s["counts"]["failed"], json!(1));
        assert_eq!(s["counts"]["deleted"], json!(1));
        let parts: u64 = [
            "sent",
            "updated",
            "same",
            "skipped",
            "failed",
            "would_send",
            "would_update",
        ]
        .iter()
        .map(|k| s["counts"][*k].as_u64().unwrap())
        .sum();
        assert_eq!(parts, s["counts"]["total"].as_u64().unwrap());

        // A dry run moves nothing and says what would have.
        let mut d = Tally {
            files_total: 2,
            bytes_total: 7,
            ..Default::default()
        };
        d.record("would send", 5);
        d.record("would update", 2);
        let s = d.summary(true, 0);
        assert_eq!(s["bytes"]["moved"], json!(0));
        assert_eq!(s["bytes"]["would_move"], json!(7));
        assert_eq!(s["counts"]["would_send"], json!(1));
        assert_eq!(d.accounted(), 2);
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fil-sync-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn chunk_hashes_cover_the_file_and_agree_with_the_whole_digest() {
        let d = tmp("hash");
        let p = d.join("f");
        let data: Vec<u8> = (0..(SYNC_CHUNK as usize * 2 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&p, &data).unwrap();
        let (full, chunks) = hash_file(&p).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(Some(full), crate::recv_files::full_hash(&p));
        assert_eq!(
            hash_file(&d.join({
                std::fs::write(d.join("e"), b"").unwrap();
                "e"
            }))
            .unwrap()
            .1
            .len(),
            0
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn walk_skips_symlinks_and_diff_names_only_changed_chunks() {
        let d = tmp("walk");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        let big: Vec<u8> = vec![7u8; SYNC_CHUNK as usize * 3];
        std::fs::write(d.join("big"), &big).unwrap();
        std::fs::write(d.join("sub/small"), b"hello").unwrap();
        // Symlink support is CHECKED, not assumed from the platform: creating one on Windows needs
        // SeCreateSymbolicLinkPrivilege (or Developer Mode), and the arms live in platform/ because
        // platform branching outside it has a budget of 0 (docs/architecture/PLATFORM.md).
        let linked = crate::platform::symlink(Path::new("/etc/passwd"), &d.join("link")).is_ok();
        if !linked {
            crate::ui::say(
                "note: this platform would not create a symlink; the symlink arm is skipped",
            );
        }
        let (local, skipped) = walk_manifest(&d).unwrap();
        assert_eq!(
            local.iter().map(|e| e.p.as_str()).collect::<Vec<_>>(),
            ["big", "sub/small"]
        );
        if linked {
            assert_eq!(skipped, vec![("link".to_string(), "symlink".to_string())]);
        }

        // Remote: identical small, big with the MIDDLE chunk changed, plus a stray.
        let r = tmp("walk-remote");
        std::fs::create_dir_all(r.join("sub")).unwrap();
        let mut rb = big.clone();
        rb[SYNC_CHUNK as usize + 5] = 0;
        std::fs::write(r.join("big"), &rb).unwrap();
        std::fs::write(r.join("sub/small"), b"hello").unwrap();
        std::fs::write(r.join("stray"), b"x").unwrap();
        let (remote, _) = walk_manifest(&r).unwrap();
        let plan = diff(&local, &remote);
        assert_eq!(plan.same, vec!["sub/small".to_string()]);
        assert_eq!(
            plan.need,
            vec![Need {
                p: "big".into(),
                new: false,
                chunks: vec![1]
            }]
        );
        assert_eq!(plan.extra, vec!["stray".to_string()]);
        // Empty remote: everything is new, every chunk needed.
        let plan = diff(&local, &[]);
        assert_eq!(plan.need.len(), 2);
        assert!(plan.need.iter().all(|n| n.new));
        assert_eq!(plan.need[0].chunks, vec![0, 1, 2]);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn files_left_on_the_peer_are_reported_not_silent() {
        assert_eq!(kept_on_peer_line(0, "box"), None);
        assert_eq!(
            kept_on_peer_line(1, "box").as_deref(),
            Some("  1 file exists only on 'box' (not deleted; use --delete to remove)")
        );
        assert_eq!(
            kept_on_peer_line(3, "box").as_deref(),
            Some("  3 files exist only on 'box' (not deleted; use --delete to remove)")
        );
    }

    #[test]
    fn records_reassemble_across_frame_boundaries() {
        let mut r = Records::default();
        let mut wire = (5u32).to_be_bytes().to_vec();
        wire.extend_from_slice(b"hello");
        wire.extend_from_slice(&(0u32).to_be_bytes());
        r.0.extend_from_slice(&wire[..3]);
        assert!(r.next().unwrap().is_none());
        r.0.extend_from_slice(&wire[3..7]);
        assert!(r.next().unwrap().is_none());
        r.0.extend_from_slice(&wire[7..]);
        assert_eq!(r.next().unwrap().unwrap(), b"hello");
        assert_eq!(r.next().unwrap().unwrap(), b"");
        assert!(r.next().unwrap().is_none());
    }
}
