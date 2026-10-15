//! `tunlion exec` initiator: open the stream, pump stdio, surface the exit code.
//!
//! Deliberately one-shot where `pty_cmd` is resumable: an exec invocation has
//! no session worth reattaching (the receiver holds no persistent state for
//! it), so there is NO warm-daemon fast path and NO reconnect loop. A dropped
//! link fails loudly instead of re-running the command -- re-running would
//! execute side effects twice, which is exactly the wrong default for a
//! non-idempotent remote command. That asymmetry with shells is intentional
//! and documented here so a future "make exec resilient" change has to reckon
//! with double-execution first.
//!
//! Wire contract (CONTRACT.md, "Exec streams"): allocator registers both pipes
//! BEFORE the open goes out (a racing ack/close must not find no pipe, same
//! race discipline as pty's open waiter); the ack wait is bounded at 10 s with
//! the same four outcomes (opened / refused / unconfirmed / timeout); stdin
//! EOF goes out as one empty frame and then we stop reading stdin but keep
//! draining both outputs until the close arrives.

use crate::identity_lifecycle::respond_to_identity_challenge;
use crate::l2;
use crate::platform::TreeSignal;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Built initiator options: argv already final (shell wrapping applied by the
/// caller), env already validated into pairs.
pub(crate) struct ExecOpts {
    pub(crate) argv: Vec<String>,
    pub(crate) tty: bool,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
}

/// Bounded fd0 reader: the pty shared reader's shape (`spawn_stdin_reader`)
/// with a 64-chunk cap so unread stdin cannot grow without bound. One
/// consumer per invocation (same singleton discipline); kept exec-local so
/// the shared reader's unbounded contract for pty is untouched. When the
/// link stalls, `blocking_send` parks this thread instead of buffering
/// forever: file reads pause, pipe writers block -- backpressure end to
/// end instead of OOM. An empty Vec is the EOF sentinel, same convention.
fn spawn_bounded_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.blocking_send(Vec::new()); // EOF sentinel
                    break;
                }
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break; // the client hung up
                    }
                }
            }
        }
    });
    rx
}

/// Build the final argv: direct spawn passes through untouched; `--shell`
/// wraps as `/bin/sh -c <joined>` (cmd /C on Windows). The receiver never
/// invokes a shell on its own -- this wrapping is the ONLY shell in the path,
// and it happens here, visibly, on the initiator side.
pub(crate) fn build_argv(argv: &[String], shell: bool) -> Vec<String> {
    if !shell {
        return argv.to_vec();
    }
    let joined = argv.join(" ");
    #[cfg(windows)]
    {
        vec!["cmd".to_string(), "/C".to_string(), joined]
    }
    #[cfg(not(windows))]
    {
        vec!["/bin/sh".to_string(), "-c".to_string(), joined]
    }
}

/// Validate one `--env KEY=VALUE` pair. Same rule as the receiver enforces, so
/// a malformed pair fails fast locally instead of being silently dropped over
/// the wire. Returns the split pair.
pub(crate) fn parse_env_pair(s: &str) -> Result<(String, String)> {
    let Some((k, v)) = s.split_once('=') else {
        bail!("--env must be KEY=VALUE, got {s:?}");
    };
    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("--env key must be [A-Za-z0-9_], got {k:?}");
    }
    Ok((k.to_string(), v.to_string()))
}

/// How one exec session ended on this side.
enum SessionEnd {
    Done(Result<i32>),
    Signalled(TreeSignal, i32),
}

/// The local signal that interrupted this exec, as the signal to forward and
/// the exit status to end with (128 + n). Ctrl-C everywhere; SIGTERM, SIGHUP
/// and SIGQUIT where they exist.
async fn interruption() -> (TreeSignal, i32) {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = ctrl_c => (TreeSignal::Interrupt, 130),
        code = crate::platform::termination_signal() => {
            let sig = if code == 129 { TreeSignal::Hangup } else { TreeSignal::Terminate };
            (sig, code)
        }
    }
}

/// How long an interrupted initiator waits for the acceptor to confirm the
/// remote tree is gone before exiting anyway.
const HANG_UP_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Tell the acceptor this side is going: forward `sig` when there is one, then
/// close the session, which ends the remote process tree. Waits briefly for
/// the acceptor's word that it is gone, so the frames leave before this
/// process (and its link) does; a link already dead gets nothing.
async fn hang_up_remote(
    t: &std::sync::Arc<dyn crate::net::Transport>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::net::Ev>,
    sid: u32,
    sig: Option<TreeSignal>,
    why: &str,
) {
    if t.is_dead() {
        return;
    }
    if let Some(sig) = sig {
        let _ = t
            .send_control(&json!({ "type": "exec-signal", "sid": sid, "signal": sig.wire() }))
            .await;
    }
    if t
        .send_control(&json!({ "type": "l2-close", "sid": sid, "err": why }))
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::time::timeout(HANG_UP_WAIT, async {
        while let Some(ev) = rx.recv().await {
            if let crate::net::Ev::Control(_pid, v) = ev {
                let ty = v.get("type").and_then(|t| t.as_str());
                if matches!(ty, Some("exec-close") | Some("l2-close"))
                    && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                {
                    break;
                }
            }
        }
    })
    .await;
}

/// Run a command on a peer and return its remote exit status. Local failures
/// (connect, open, link death) are Err with a human message; a clean remote
/// close -- including a remote NONZERO exit -- is Ok(status).
/// A refusal that names itself as retryable is ACTED ON: the settle path
/// hands us "identity not proven within N ms; retry" (or "identity
/// settling, retry") after dropping the link that failed to prove, so a
/// second attempt establishes a fresh link instead of parking on the same
/// corpse. A retry hint nobody consumes is just a slower failure.
fn settle_retryable(err: &anyhow::Error) -> bool {
    let m = err.to_string();
    m.contains("retry") && (m.contains("identity not proven") || m.contains("identity settling"))
}

/// Exit codes `exec` produces itself, beside the remote command's own status
/// (docs/ui/OUTPUT.md, Exit codes). 127 and 126 are what a shell returns for
/// a command it cannot find or cannot execute; the remote daemon refuses
/// those before spawning, so they are produced here from its refusal. They
/// were 4, "denied", which sent people to check permissions for a typo.
const EXEC_NOT_FOUND: i32 = 127;
const EXEC_CANNOT_RUN: i32 = 126;
/// 128 + SIGPIPE: this side's stdout (or stderr) was closed before the remote
/// command finished (`exec box -- seq 1 100000 | head -2`). It was 1 with
/// "Error: Broken pipe".
const EXEC_OUTPUT_CLOSED: i32 = 141;

/// How long a running session may hear NOTHING from the serving daemon before
/// it is declared gone. The daemon answers every `exec-alive` (sent each
/// EXEC_ALIVE_INTERVAL) with `exec-alive-ack`, and any output counts too, so a
/// healthy idle session hears something every two seconds. A daemon killed
/// outright used to be noticed only when the transport itself timed out, up
/// to ~35 s later.
const EXEC_PEER_SILENT: std::time::Duration = std::time::Duration::from_secs(12);

/// The daemon closed this session's link because it no longer recognizes
/// this device (`devices forget`, a revocation). A refusal, not a dead link.
pub(crate) fn revoked_mid_session(peer: &str, v: &Value) -> String {
    let reason = v
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or(crate::refusal::UNRECOGNIZED_REASON);
    format!("'{peer}' refused to continue: {reason}")
}

/// The shell exit code for a remote refusal that means "could not start the
/// command", or None for any other refusal. Matched on the remote daemon's
/// own reason text (exec_recv.rs). Pure.
pub(crate) fn spawn_refusal_code(reason: &str) -> Option<i32> {
    let r = reason.to_lowercase();
    if r.contains("not found on daemon path") {
        return Some(EXEC_NOT_FOUND);
    }
    if r.contains("spawn failed")
        && (r.contains("permission denied")
            || r.contains("os error 13)")
            || r.contains("exec format error")
            || r.contains("os error 8)"))
    {
        return Some(EXEC_CANNOT_RUN);
    }
    None
}

/// Say why the remote command could not start, and return its shell code.
fn spawn_refused(peer: &str, argv0: &str, reason: &str, code: i32) -> i32 {
    let what = if code == EXEC_NOT_FOUND {
        format!("'{argv0}' is not on {peer}'s PATH")
    } else {
        format!("'{argv0}' cannot be executed on {peer}")
    };
    crate::ui::critical(&format!("tunlion exec: {what} ({reason}); exit {code}"));
    code
}

/// A write to this side's stdout/stderr failed: a closed reader is 141
/// (quietly, as SIGPIPE would end a local command), anything else is an error.
fn local_output_failed(e: std::io::Error) -> Result<i32> {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        Ok(EXEC_OUTPUT_CLOSED)
    } else {
        Err(e.into())
    }
}

pub(crate) async fn exec_cmd(server: &str, peer: &str, relay: bool, opts: ExecOpts) -> Result<i32> {
    // Bounded by BOTH count and wall clock. Measured: the window in which a
    // challenge is unanswered is the peer's own reconnect churn (a daemon
    // restart on either side), which lasts seconds to tens of seconds; three
    // attempts at 300ms land inside it every time. A retry budget the daemon
    // itself asked for ("identity not proven within N ms; retry") is bounded
    // and honest; the count cap keeps a permanently unprovable peer from
    // spinning forever.
    const ATTEMPTS: u32 = 12;
    let started = std::time::Instant::now();
    let mut attempt = 0;
    // One signal listener for the whole invocation, retries included: tokio
    // keeps a signal's handler installed once registered, so a listener per
    // attempt would leave the gaps between attempts swallowing Ctrl-C.
    let mut interrupted: Interrupted = Box::pin(interruption());
    loop {
        attempt += 1;
        match exec_once(server, peer, relay, &opts, &mut interrupted).await {
            Ok(code) => return Ok(code),
            Err(e)
                if attempt < ATTEMPTS
                    && started.elapsed() < std::time::Duration::from_secs(20)
                    && settle_retryable(&e) =>
            {
                if attempt <= 2 {
                    crate::ui::say(&format!(
                        "tunlion: {e} -- re-establishing the link (attempt {attempt})"
                    ));
                } else {
                    crate::ui::debug(&format!("tunlion: {e} -- retry {attempt}"));
                }
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
                    (_sig, code) = interrupted.as_mut() => return Ok(code),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// The invocation's signal listener (see `exec_cmd`).
type Interrupted = std::pin::Pin<Box<dyn std::future::Future<Output = (TreeSignal, i32)> + Send>>;

async fn exec_once(
    server: &str,
    peer: &str,
    relay: bool,
    opts: &ExecOpts,
    interrupted: &mut Interrupted,
) -> Result<i32> {
    // Signals are handled from the first moment, not only once the session
    // runs: a SIGTERM during bring-up or the open used to take the default
    // action, and a command the acceptor had already started then ran until
    // its heartbeat deadline. Before the open nothing is remote; after it the
    // session is hung up (forwarded signal, then close).
    let bring_up = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        l2::bring_up_to_known(server, peer, relay, "exec"),
    );
    let (t, mut rx, guard, _diag) = tokio::select! {
        r = bring_up => match r {
            Ok(inner) => inner?,
            Err(_) => {
                bail!("connect timeout: couldn't reach '{peer}' in 45s");
            }
        },
        (_sig, code) = interrupted.as_mut() => return Ok(code),
    };
    guard.forget();
    let mux = l2::Mux::new(t.clone());
    let sid = mux.alloc_sid();
    // Register BOTH inbound pipes before the open goes out: bytes or a close
    // racing the ack must find a pipe, same discipline as pty's open waiter.
    let mut out_pipe = mux
        .register_stream(sid)
        .await
        .ok_or_else(|| anyhow::anyhow!("exec open: sid {sid:#x} already in use"))?;
    // The stderr sid is initiator-allocated and announced in the open (same
    // value both ends use, like `sid` itself): the pipe is registered before
    // the open goes out, so stderr racing the ack finds it. A receiver-side
    // second allocation would name a stream nobody listens on.
    let err_sid = mux.alloc_sid();
    let mut err_pipe = mux
        .register_stream(err_sid)
        .await
        .ok_or_else(|| anyhow::anyhow!("exec open: sid {err_sid:#x} already in use"))?;
    let frame = {
        let mut f = json!({
            "type": "exec-open",
            "sid": sid,
            "err_sid": err_sid,
            "argv": opts.argv.clone(),
            // Heartbeat promise: the acceptor ends the command if these stop.
            "alive_ms": crate::exec_recv::EXEC_ALIVE_INTERVAL.as_millis() as u64,
        });
        if let Some(cwd) = &opts.cwd {
            f["cwd"] = json!(cwd.to_string_lossy());
        }
        if !opts.env.is_empty() {
            f["env"] = json!(opts
                .env
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>());
        }
        if opts.tty {
            f["tty"] = json!(true);
        }
        f
    };
    t.send_control(&frame).await?;
    // Bounded ack wait with pty's four outcomes. A refusal surfaces the
    // RECEIVER's reason (dropping it here reported every refusal as a
    // confusing transport error); anything else names what actually happened.
    let ack_wait = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => {
                    break Err(format!("'{peer}' closed the exec stream before answering"));
                }
            };
            match ev {
                crate::net::Ev::Control(_pid, v) => {
                    // #309: a covered-without-grant open needs a PROVEN link, and
                    // the owner challenges the pid carrying the open -- this one.
                    // Without an answer here the link can never become Proven,
                    // the open parks and expires, and every retry mints a fresh
                    // equally silent link. Same shared helper send_cmd uses, so
                    // there is one possession-signing path, not two; its doc
                    // comment states which key is which, and why the path can
                    // only ever sign as itself.
                    if v.get("type").and_then(|t| t.as_str()) == Some("identity-nonce-challenge") {
                        respond_to_identity_challenge(&t, &v).await;
                    }
                    if v.get("type").and_then(|t| t.as_str()) == Some("exec-open-ack")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        break Ok(v);
                    }
                    if v.get("type").and_then(|t| t.as_str()) == Some("l2-close")
                        && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                    {
                        // The acceptor's code says WHY, and its `as` says what it
                        // calls us, so the remedy names the right fix and the
                        // right device (a missing grant is not "serving is off").
                        // An expiry also carries the re-invite to print.
                        break Err(crate::refusal::explain_frame("exec", peer, &v, "err"));
                    }
                }
                crate::net::Ev::Chunk(_pid, got, _offset, data) => {
                    mux.on_frame(got, data).await;
                }
                _ => {}
            }
        }
    });
    let ack_wait = tokio::select! {
        r = ack_wait => r,
        (sig, code) = interrupted.as_mut() => {
            hang_up_remote(&t, &mut rx, sid, Some(sig), "the initiator was interrupted").await;
            return Ok(code);
        }
    };
    let ack: std::result::Result<Value, String> = ack_wait
    .map_err(|_| {
        anyhow::anyhow!(
            "no answer from '{peer}' - it may be unresponsive or running a build without exec"
        )
    })?;
    let ack = match ack {
        Ok(v) => v,
        Err(reason) => match spawn_refusal_code(&reason) {
            Some(code) => return Ok(spawn_refused(peer, opts.argv.first().map(String::as_str).unwrap_or("?"), &reason, code)),
            None => bail!("{reason}"),
        },
    };
    let _ = ack;
    // Heartbeats, on their own task so a pump blocked on a slow local
    // consumer never looks like a dead initiator: the acceptor ends the
    // remote command when they stop (kill -9 of this process, a vanished
    // host), instead of letting it run on with nobody to report to.
    let beats = {
        let t = t.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(crate::exec_recv::EXEC_ALIVE_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                if t
                    .send_control(&json!({ "type": "exec-alive", "sid": sid }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };
    // Set when the ACCEPTOR ended the session (its l2-close): nothing is left
    // over there to hang up, so an error exit does not wait on it.
    let mut remote_ended = false;
    // Set when THIS side's stdout/stderr failed (`| head` closed it): the
    // session then returns 141, and the remote producer must not run on.
    let mut local_closed = false;
    let session = async {
        // Pumps: bounded fd0 reader (one consumer for the whole invocation,
        // same singleton discipline as pty's shared reader), stdout/stderr to
        // local stdio, close status out. No reconnect: link death below fails
        // loudly by design.
        let mut stdin_rx = spawn_bounded_stdin_reader();
        let mut stdin_done = false;
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let exit_status: Option<i32>;
        // Bytes consumed per stream: the close announces both counts, and the
        // drain below collects stragglers until the counts are met (or bounded
        // time passes). Incremented everywhere a pipe item is consumed.
        let mut out_recv: u64 = 0;
        let mut err_recv: u64 = 0;
        let want_out: Option<u64>;
        let want_err: Option<u64>;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        ticker.tick().await;
        // Last time anything arrived from the daemon (see EXEC_PEER_SILENT).
        let mut last_heard = std::time::Instant::now();
        loop {
            tokio::select! {
                item = out_pipe.recv() => match item {
                    Some(Some(bytes)) => {
                        last_heard = std::time::Instant::now();
                        out_recv += bytes.len() as u64;
                        if let Err(e) = stdout.write_all(&bytes).await {
                            local_closed = true;
                            return local_output_failed(e);
                        }
                        if let Err(e) = stdout.flush().await {
                            local_closed = true;
                            return local_output_failed(e);
                        }
                    }
                    _ => {
                        // Pipe closed without a close payload: transport-level liveness
                        // decides whether this was a clean end we misread or a drop.
                        // The STRICT question, asked here because only this caller wants it: for the exec select,
                        // a peer that can never send again means waiting is pointless, even though the
                        // connection is otherwise usable.
                        if mux.transport().is_dead() {
                            return Err(crate::identity_flow::link_died_error(peer, "during exec (the output stream ended and the connection is closed)"));
                        }
                        // TERMINAL AND NAMED, with no timeout involved: the session's stream ended
                        // and no `exec-close` carrying a status will follow, so waiting longer can
                        // only wait on a link that is working and a frame that is not coming.
                        remote_ended = true;
                        bail!(
                            "exec stream ended without an exit status; the peer's close frame did not arrive ('{peer}')"
                        );
                    }
                },
                item = err_pipe.recv() => match item {
                    Some(Some(bytes)) => {
                        last_heard = std::time::Instant::now();
                        err_recv += bytes.len() as u64;
                        if let Err(e) = stderr.write_all(&bytes).await {
                            local_closed = true;
                            return local_output_failed(e);
                        }
                        if let Err(e) = stderr.flush().await {
                            local_closed = true;
                            return local_output_failed(e);
                        }
                    }
                    _ => {}
                },
                chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                    Some(c) if c.is_empty() => {
                        let _ = t.send_frame(sid, 0, &[]).await;
                        stdin_done = true;
                    }
                    Some(c) => {
                        let cap = t.max_payload().max(1);
                        let mut failed = false;
                        for chunk in c.chunks(cap) {
                            if t.send_frame(sid, 0, chunk).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            return Err(crate::identity_flow::link_died_error(peer, "mid-send"));
                        }
                    }
                    None => { stdin_done = true; }
                },
                ev = rx.recv() => match ev {
                    Some(crate::net::Ev::Control(_pid, v)) => {
                        last_heard = std::time::Instant::now();
                        // Forgotten or revoked there while this ran: the daemon
                        // says so before closing the link, and that is a
                        // refusal (exit 4), not a link that died.
                        if v.get("type").and_then(|t| t.as_str()) == Some("link-revoked") {
                            remote_ended = true;
                            bail!("{}", revoked_mid_session(peer, &v));
                        }
                        // #309: the owner re-challenges while an open is parked (and
                        // after any re-adopt), so the same answer is owed here, in
                        // the long-lived pump, not only during the ack wait. Same
                        // shared helper: one possession-signing path, not two.
                        if v.get("type").and_then(|t| t.as_str())
                            == Some("identity-nonce-challenge")
                        {
                            respond_to_identity_challenge(&t, &v).await;
                        }
                        if v.get("type").and_then(|t| t.as_str()) == Some("exec-close")
                            && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                        {
                            exit_status = v.get("status").and_then(|s| s.as_i64()).map(|s| s as i32);
                            want_out = v.get("out_bytes").and_then(|n| n.as_u64());
                            want_err = v.get("err_bytes").and_then(|n| n.as_u64());
                            // The command over there has exited: nothing to hang up.
                            remote_ended = true;
                            break;
                        }
                        if v.get("type").and_then(|t| t.as_str()) == Some("l2-close")
                            && v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64)
                        {
                            let err = v.get("err").and_then(|e| e.as_str()).unwrap_or("closed");
                            remote_ended = true;
                            if let Some(code) = spawn_refusal_code(err) {
                                return Ok(spawn_refused(peer, opts.argv.first().map(String::as_str).unwrap_or("?"), err, code));
                            }
                            // A POLICY close mid-session (revoked, expired) is a
                            // refusal, exit 4 with its reason and remedy, not a
                            // generic failure (it exited 1, which a supervisor
                            // reads as "broke, retry").
                            let (code, _) = crate::refusal::from_frame(&v, "err");
                            if code.is_some() {
                                bail!("{}", crate::refusal::explain_frame("exec", peer, &v, "err"));
                            }
                            bail!("'{peer}' closed the exec stream: {err}");
                        }
                    }
                    Some(crate::net::Ev::Chunk(_pid, got, _offset, data)) => {
                        last_heard = std::time::Instant::now();
                        mux.on_frame(got, data).await;
                    }
                    // Bring-up's LOSER keeps emitting on this shared channel after
                    // it returns (a late ChannelReady/DirectReady, Stuck, PcState
                    // ...): pty's pump never polls rx at all, and polling it here
                    // must not mistake those for death -- a late winner-arrival
                    // killed every session living past ~2s with a bogus "link
                    // died". Only a CLOSED channel means the link is really gone;
                    // anything else is ignored, with the 2s ticker as backstop.
                    Some(_) => {}
                    None => {
                        return Err(crate::identity_flow::link_died_error(peer, "during exec (the link's event channel closed)"));
                    }
                },
                _ = ticker.tick() => {
                    // The STRICT question, asked here because only this caller wants it: for the exec select,
                    // a peer that can never send again means waiting is pointless, even though the
                    // connection is otherwise usable.
                    if mux.transport().is_dead() {
                        return Err(crate::identity_flow::link_died_error(peer, "during exec (the connection is closed)"));
                    }
                    if last_heard.elapsed() >= EXEC_PEER_SILENT {
                        return Err(crate::identity_flow::link_died_error(
                            peer,
                            &format!("during exec: no answer for {}s", EXEC_PEER_SILENT.as_secs()),
                        ));
                    }
                }
            }
        }
        // Bounded drain: exec-close travels control while bytes travel frames,
        // so a fast-exiting child can beat its own tail (observed live: a missing
        // 8 KiB tail with rc=0). The close announces both byte counts, so the
        // drain is DETERMINISTIC on a healthy link -- collect until the counts
        // are met -- with a 3s cap for a dying one. Skipped when the close
        // carried no status (abnormal end: nothing to collect for).
        if exit_status.is_some() {
            let drain_end = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let met = match (want_out, want_err) {
                    (Some(o), Some(e)) => out_recv >= o && err_recv >= e,
                    _ => false,
                };
                if met || tokio::time::Instant::now() >= drain_end {
                    break;
                }
                tokio::select! {
                    ev = rx.recv() => match ev {
                        Some(crate::net::Ev::Chunk(_pid, got, _offset, data)) => {
                            mux.on_frame(got, data).await;
                        }
                        _ => {}
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                }
                while let Ok(Some(bytes)) = out_pipe.try_recv() {
                    out_recv += bytes.len() as u64;
                    if let Err(e) = stdout.write_all(&bytes).await {
                        local_closed = true;
                        return local_output_failed(e);
                    }
                }
                while let Ok(Some(bytes)) = err_pipe.try_recv() {
                    err_recv += bytes.len() as u64;
                    if let Err(e) = stderr.write_all(&bytes).await {
                        local_closed = true;
                        return local_output_failed(e);
                    }
                }
                if let Err(e) = stdout.flush().await {
                    local_closed = true;
                    return local_output_failed(e);
                }
                if let Err(e) = stderr.flush().await {
                    local_closed = true;
                    return local_output_failed(e);
                }
            }
        }
        mux.drop_stream(sid).await;
        mux.drop_stream(err_sid).await;
        // No exit-status payload means the process did not exit cleanly: never
        // render that as success (contract). A clean remote 0 falls through to Ok.
        match exit_status {
            Some(code) => Ok::<i32, anyhow::Error>(code),
            None => bail!("'{peer}' closed the exec stream without an exit status"),
        }
    };
    let end = tokio::select! {
        r = session => SessionEnd::Done(r),
        (sig, code) = interrupted.as_mut() => SessionEnd::Signalled(sig, code),
    };
    beats.abort();
    match end {
        SessionEnd::Done(Ok(code)) => {
            // A clean remote exit needs nothing; a closed local reader means
            // the command over there is still writing to nobody: EPIPE it.
            if local_closed && !remote_ended {
                hang_up_remote(&t, &mut rx, sid, None, "the initiator's output was closed").await;
            }
            Ok(code)
        }
        SessionEnd::Done(Err(e)) => {
            // Whatever ended this side (its stdout closed under `| head`, the
            // peer refused mid-session, a local error), the remote command must
            // not outlive it. A session already closed remotely ignores this.
            if !remote_ended {
                hang_up_remote(&t, &mut rx, sid, None, "the initiator ended the session").await;
            }
            Err(e)
        }
        SessionEnd::Signalled(sig, code) => {
            // Ctrl-C or SIGTERM here is Ctrl-C or SIGTERM there, then the
            // close that ends whatever ignores it. Exit as the signal would.
            hang_up_remote(&t, &mut rx, sid, Some(sig), "the initiator was interrupted").await;
            Ok(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_argv_direct_passthrough() {
        let argv = vec!["rsync".to_string(), "-a".to_string(), "my dir/".to_string()];
        assert_eq!(build_argv(&argv, false), argv);
    }

    #[test]
    fn build_argv_shell_wraps() {
        let argv = vec!["ls *.log".to_string()];
        let built = build_argv(&argv, true);
        assert_eq!(built.len(), 3);
        assert_eq!(built[2], "ls *.log");
        #[cfg(not(windows))]
        assert_eq!(&built[..2], ["/bin/sh", "-c"]);
    }

    #[test]
    fn parse_env_pair_accepts_and_rejects() {
        assert_eq!(
            parse_env_pair("FOO=bar").unwrap(),
            ("FOO".to_string(), "bar".to_string())
        );
        assert_eq!(
            parse_env_pair("A=b=c").unwrap(),
            ("A".to_string(), "b=c".to_string())
        );
        for bad in ["NOEQUALS", "=nokey", "BAD KEY=x", ""] {
            assert!(parse_env_pair(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn frame_carries_argv_exact_and_opts() {
        let opts = ExecOpts {
            argv: vec!["a b".to_string()],
            tty: false,
            cwd: Some(PathBuf::from("/tmp")),
            env: vec![("K".to_string(), "V".to_string())],
        };
        assert_eq!(opts.argv, vec!["a b".to_string()]);
        assert!(!opts.tty);
    }

    /// J6: a remote "command not found" exited 4 ("denied"); exec passes 42
    /// and 137 through, so the codes a shell uses for "cannot start it" are
    /// the honest ones: 127 not found, 126 found but not executable.
    #[test]
    fn a_command_that_cannot_start_exits_like_a_shell() {
        assert_eq!(spawn_refusal_code("argv[0] not found on daemon PATH"), Some(127));
        assert_eq!(
            spawn_refusal_code("'box' refused exec: argv[0] not found on daemon PATH"),
            Some(127)
        );
        assert_eq!(spawn_refusal_code("spawn failed: Permission denied (os error 13)"), Some(126));
        assert_eq!(spawn_refusal_code("spawn failed: Exec format error (os error 8)"), Some(126));
        // Refusals that are not about starting the command keep their kinds.
        assert_eq!(spawn_refusal_code("shell not granted"), None);
        assert_eq!(spawn_refusal_code("cwd does not exist"), None);
        assert_eq!(spawn_refusal_code("spawn failed: Resource temporarily unavailable"), None);
    }

    /// J1/J6: `exec ... | head -2` exited 1 with "Error: Broken pipe". A
    /// closed local reader ends exec as SIGPIPE ends a local command, 141;
    /// any other write failure is still an error.
    #[test]
    fn a_closed_local_output_is_141_not_an_error() {
        let closed = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        assert_eq!(local_output_failed(closed).unwrap(), 141);
        let full = std::io::Error::other("No space left on device (os error 28)");
        assert!(local_output_failed(full).is_err());
    }
}
