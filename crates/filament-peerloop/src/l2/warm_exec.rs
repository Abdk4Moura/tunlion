//! Warm `exec`: carry a one-shot command over a link the daemon ALREADY holds.
//!
//! The cold `exec` path (`cli/src/exec_send.rs`) establishes a fresh link, sends
//! `exec-open`, pumps stdin/stdout/stderr and returns the remote status. When a
//! local `up` daemon already holds a live, identity-proven link to the peer,
//! doing that again costs an entire establish and puts a second presence on the
//! peer for a command that lasts milliseconds. This module is the daemon half of
//! riding the existing link instead.
//!
//! WHAT IS REUSED: the peer's transport and its per-peer [`Mux`] from the
//! daemon's table. No second link, no second mux, no re-derived identity. The
//! daemon sends the SAME `exec-open` a cold initiator sends, so the peer runs the
//! SAME admission (serving switch, capability/ceiling, revocation) at request
//! time. This module decides only whether a warm path EXISTS; it never grants
//! anything the peer would not grant a cold open.
//!
//! WHAT IS NOT REUSED: a session. An exec is one-shot. Once `exec-open` has left
//! this machine, link death is reported loudly and NEVER retried on a fresh link:
//! the command may have run, and re-running a non-idempotent command is the one
//! thing exec must not do. Before the open is sent, a miss is safe to report as
//! `no warm path`, which is what lets the CLI fall back to its normal one-shot
//! establish.
//!
//! BRIDGE: the control socket becomes a binary frame pipe (see
//! [`crate::exec_frame`]): stdin/EOF/signal in, stdout/stderr/exit out. The exit
//! status is a frame, not a process signal, so stdout, stderr and the status stay
//! exactly what the cold path produces.
//!
//! PLATFORM: Unix control socket only. Windows has no control socket yet; the
//! CLI's warm client returns `NoPath` there and every exec uses the cold path.

use crate::conn::{warm_link_for, Conn};
use crate::control;
use crate::exec_frame::{
    read_frame, write_frame, FRAME_CLOSE, FRAME_EXIT, FRAME_SIGNAL, FRAME_STDERR, FRAME_STDIN,
    FRAME_STDIN_EOF, FRAME_STDOUT,
};
use crate::l2::{Mux, MuxMap, TreeSignal};
use bytes::Bytes;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::mpsc;

/// How long the daemon waits for the peer's `exec-open-ack`. The cold path uses
/// the same 10 s bound.
const EXEC_ACK_WAIT: Duration = Duration::from_secs(10);
/// How long a delivered `exec-close` may wait for announced tail bytes. Same
/// bound as the cold path's drain.
const EXEC_TAIL_DRAIN: Duration = Duration::from_secs(3);
/// A running warm exec may hear NOTHING from the serving daemon for this long
/// before it is declared gone. The daemon answers every `exec-alive` with
/// `exec-alive-ack` (and output counts too), so a SIGKILLed peer is noticed
/// here instead of on QUIC's much longer idle timeout. This is the same 12 s
/// bound the cold initiator uses.
const EXEC_PEER_SILENT: Duration = Duration::from_secs(12);

/// Handle one `exec` control request. Resolves the warm link inline (cheap) and
/// spawns the session: waiting for the peer's ack must never block the daemon's
/// single receive loop.
pub async fn handle_warm_exec(
    conn: &Conn,
    muxes: &mut MuxMap,
    tx: &mpsc::UnboundedSender<filament_transport::net::Ev>,
    req: control::Req,
) {
    let control::ReqKind::Exec {
        peer,
        argv,
        cwd,
        env,
        tty,
    } = req.kind.clone()
    else {
        return;
    };
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        crate::daemon_ctl::log_warm_miss(conn, &peer);
        req.reject("no warm path: no live link to that peer").await;
        return;
    };
    conn.log.debug(&format!(
        "warm-exec: riding the daemon's link to '{peer}' (pid={pid})"
    ));
    let mux = muxes
        .entry(pid.clone())
        .or_insert_with(|| Mux::new(t.clone(), conn.host.clone()))
        .clone();
    let tx = tx.clone();
    let log = conn.log.clone();
    tokio::spawn(async move {
        run_warm_exec(mux, t, pid, peer, argv, cwd, env, tty, tx, log, req).await;
    });
}

/// The session body, detached from the receive loop.
#[allow(clippy::too_many_arguments)]
async fn run_warm_exec(
    mux: Arc<Mux>,
    t: Arc<dyn Transport>,
    pid: String,
    peer: String,
    argv: Vec<String>,
    cwd: Option<String>,
    env: Vec<String>,
    tty: bool,
    tx: mpsc::UnboundedSender<filament_transport::net::Ev>,
    log: Arc<dyn crate::host::LogSink>,
    req: control::Req,
) {
    // H-1: the same per-link cap the acceptor applies. An exec needs TWO local
    // pipes (stdout and stderr), so require room for both; a warm path that
    // cannot fit is not a path, and falling back beats evicting somebody else's
    // stream.
    if mux.live_streams().await + 2 > crate::l2::MAX_STREAMS_PER_LINK {
        req.reject("no warm path: too many streams on that link")
            .await;
        return;
    }
    let sid = mux.alloc_sid();
    let Some(mut out_pipe) = mux.register_stream(sid).await else {
        req.reject("no warm path: exec sid already in use").await;
        return;
    };
    let err_sid = mux.alloc_sid();
    let Some(mut err_pipe) = mux.register_stream(err_sid).await else {
        mux.drop_stream(sid).await;
        req.reject("no warm path: exec stderr sid already in use")
            .await;
        return;
    };
    // Register the control waiter BEFORE the open leaves, so the ack/refusal
    // cannot race a missing receiver (same ordering as the data pipes).
    let mut ctl = mux.register_exec_initiator(sid).await;
    let mut open = json!({
        "type": "exec-open",
        "sid": sid,
        "err_sid": err_sid,
        "argv": argv,
        "alive_ms": crate::shell::exec::EXEC_ALIVE_INTERVAL.as_millis() as u64,
    });
    if let Some(cwd) = cwd {
        open["cwd"] = json!(cwd);
    }
    if !env.is_empty() {
        open["env"] = json!(env);
    }
    if tty {
        open["tty"] = json!(true);
    }
    // BEFORE the open: a send failure means no command was started, so a cold
    // fallback is safe and honest.
    if t.send_control(&open).await.is_err() {
        mux.drop_stream(sid).await;
        mux.drop_stream(err_sid).await;
        req.reject("no warm path: the warm link could not carry the open")
            .await;
        return;
    }
    // FROM HERE ON an `exec-open` is on the wire: no fallback, ever.
    match await_ack(&mux, &mut ctl, &t, sid, &peer).await {
        Ack::Opened => {}
        Ack::Refused(frame) => {
            mux.drop_stream(sid).await;
            mux.drop_stream(err_sid).await;
            // Carry the WHOLE refusal frame, not just its reason: the CLI builds
            // the same code/as/reinvite remedy a cold exec prints.
            req.reject(&format!("refused-frame: {frame}")).await;
            return;
        }
        Ack::Failed(why) => {
            // The open MAY have been served even though its answer was lost.
            // Tell the peer to end whatever it started before reporting the
            // failure; there is no second link and no replay.
            let _ = t
                .send_control(&json!({
                    "type": "l2-close",
                    "sid": sid,
                    "err": "the initiator lost the exec open answer",
                }))
                .await;
            mux.drop_stream(sid).await;
            mux.drop_stream(err_sid).await;
            log.debug(&format!(
                "warm-exec to '{peer}' failed before the ack: {why}"
            ));
            req.reject(&format!("failed: {why}")).await;
            return;
        }
    }

    let sock = req.accept().await;
    let (read_half, write_half) = sock.into_split();
    // A dedicated reader task owns the read half so a partial frame can never be
    // lost to select cancellation; its channel closing means the CLIENT went
    // away, which is the signal to hang up the remote tree.
    let (in_tx, mut in_rx) = mpsc::channel::<(u8, Vec<u8>)>(8);
    let reader = tokio::spawn(async move {
        let mut r = BufReader::new(read_half);
        loop {
            match read_frame(&mut r).await {
                Ok(Some(f)) => {
                    if in_tx.send(f).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    });
    // One writer owns the write half, so stdout, stderr and the terminal frame
    // keep wire order. Backpressure reaches the peer through `send_frame`.
    enum Out {
        Data(u8, Bytes),
        Close(Value),
        Exit(i32),
    }
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(64);
    let writer = tokio::spawn(async move {
        let mut w = BufWriter::new(write_half);
        while let Some(msg) = out_rx.recv().await {
            let res = match msg {
                Out::Data(kind, bytes) => write_frame(&mut w, kind, bytes.as_ref()).await,
                Out::Close(v) => {
                    let payload = v.to_string();
                    write_frame(&mut w, FRAME_CLOSE, payload.as_bytes()).await
                }
                Out::Exit(code) => {
                    let _ = write_frame(&mut w, FRAME_EXIT, &code.to_be_bytes()).await;
                    let _ = w.flush().await;
                    return;
                }
            };
            if res.is_err() {
                return;
            }
        }
        let _ = w.flush().await;
    });
    // Heartbeat: the peer ends the remote command when these stop. Spawned so a
    // slow local socket never looks like a dead initiator.
    let beats = {
        let t = t.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(crate::shell::exec::EXEC_ALIVE_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                if t.send_control(&json!({ "type": "exec-alive", "sid": sid }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };

    let mut out_count: u64 = 0;
    let mut err_count: u64 = 0;
    let mut status: Option<i32> = None;
    let mut want_out: Option<u64> = None;
    let mut want_err: Option<u64> = None;
    let mut terminal: Option<Value> = None;
    let mut client_gone = false;
    let mut last_heard = tokio::time::Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await;
    loop {
        tokio::select! {
            frame = in_rx.recv() => match frame {
                Some((FRAME_STDIN, payload)) => {
                    // The link's own payload bound decides the chunk size, the
                    // same rule the cold initiator uses; the local framing is
                    // transport-agnostic.
                    let cap = t.max_payload().max(1);
                    let mut failed = false;
                    for chunk in payload.chunks(cap) {
                        if t.send_frame(sid, 0, chunk).await.is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        terminal = Some(warm_error("the warm link died while sending stdin"));
                        break;
                    }
                }
                Some((FRAME_STDIN_EOF, _)) => {
                    let _ = t.send_frame(sid, 0, &[]).await;
                }
                Some((FRAME_SIGNAL, payload)) => {
                    let wire = std::str::from_utf8(&payload).unwrap_or("");
                    if let Some(sig) = TreeSignal::from_wire(wire) {
                        let _ = t
                            .send_control(&json!({
                                "type": "exec-signal", "sid": sid, "signal": sig.wire()
                            }))
                            .await;
                    }
                }
                Some(_) => {}
                // The client dropped the control socket. Unlike a stdin EOF
                // frame, this is "nobody is listening": end the remote tree.
                None => {
                    let _ = t
                        .send_control(&json!({
                            "type": "l2-close",
                            "sid": sid,
                            "err": "the initiator's warm control connection closed",
                        }))
                        .await;
                    break;
                }
            },
            msg = ctl.recv() => match msg {
                Some(v) if v["type"].as_str() == Some("exec-close") => {
                    last_heard = tokio::time::Instant::now();
                    status = v["status"].as_i64().map(|s| s as i32);
                    want_out = v["out_bytes"].as_u64();
                    want_err = v["err_bytes"].as_u64();
                    break;
                }
                Some(v) if v["type"].as_str() == Some("l2-close")
                    && v["sid"].as_u64() == Some(sid as u64) =>
                {
                    last_heard = tokio::time::Instant::now();
                    // The peer's own close, with its code/as/reinvite fields
                    // intact, so the CLI renders the same refusal the cold path
                    // would (a bare reason loses the expiry remedy).
                    terminal = Some(v);
                    break;
                }
                Some(v) if v["type"].as_str() == Some("link-revoked") => {
                    last_heard = tokio::time::Instant::now();
                    terminal = Some(v);
                    break;
                }
                Some(_) => {
                    // `exec-alive-ack` (and any other answer) proves the peer
                    // is still there even when the command is quiet.
                    last_heard = tokio::time::Instant::now();
                }
                None => {
                    terminal = Some(warm_error(
                        "the warm exec control channel closed without an exit status",
                    ));
                    break;
                }
            },
            item = out_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    last_heard = tokio::time::Instant::now();
                    out_count += bytes.len() as u64;
                    if out_tx.send(Out::Data(FRAME_STDOUT, bytes)).await.is_err() {
                        client_gone = true;
                        break;
                    }
                }
                // A clean stream EOF is not the end of the session: the
                // `exec-close` carrying the status is what ends it.
                Some(None) => {}
                None => {
                    // The dispatch loop queues the full `l2-close` frame BEFORE
                    // it drops the stream, so prefer that frame over the
                    // reason-only fallback (it carries the expiry remedy).
                    match ctl.try_recv() {
                        Ok(v) if v["type"].as_str() == Some("l2-close") => {
                            terminal = Some(v);
                        }
                        _ => terminal = Some(stream_ended(&mux, &peer, sid).await),
                    }
                    break;
                }
            },
            item = err_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    last_heard = tokio::time::Instant::now();
                    err_count += bytes.len() as u64;
                    if out_tx.send(Out::Data(FRAME_STDERR, bytes)).await.is_err() {
                        client_gone = true;
                        break;
                    }
                }
                Some(None) => {}
                None => {}
            },
            _ = ticker.tick() => {
                if t.is_dead() {
                    terminal = Some(warm_error("the warm link died during exec"));
                    break;
                }
                if last_heard.elapsed() >= EXEC_PEER_SILENT {
                    terminal = Some(warm_error(&format!(
                        "the warm link died during exec: no answer from the peer for {}s",
                        EXEC_PEER_SILENT.as_secs()
                    )));
                    break;
                }
            }
        }
    }
    // A terminal set above means a failure path; a status of None with no
    // terminal means the control channel ended silently. Either way, never
    // invent success.
    if terminal.is_none() && status.is_none() {
        terminal = Some(stream_ended(&mux, &peer, sid).await);
    }
    // Bounded drain: a fast-exiting child can beat its own tail. The close
    // announces both byte counts, so collect until they are met (3 s cap on a
    // dying link), exactly like the cold initiator.
    if terminal.is_none() && status.is_some() {
        let deadline = tokio::time::Instant::now() + EXEC_TAIL_DRAIN;
        loop {
            let met = match (want_out, want_err) {
                (Some(o), Some(e)) => out_count >= o && err_count >= e,
                _ => false,
            };
            if met || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::select! {
                item = out_pipe.recv() => match item {
                    Some(Some(bytes)) => {
                        out_count += bytes.len() as u64;
                        if out_tx.send(Out::Data(FRAME_STDOUT, bytes)).await.is_err() {
                            client_gone = true;
                            break;
                        }
                    }
                    _ => {}
                },
                item = err_pipe.recv() => match item {
                    Some(Some(bytes)) => {
                        err_count += bytes.len() as u64;
                        if out_tx.send(Out::Data(FRAME_STDERR, bytes)).await.is_err() {
                            client_gone = true;
                            break;
                        }
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    }
    beats.abort();
    reader.abort();
    // A client that stopped reading is not a reason to leave the remote tree
    // running until its heartbeat deadline. Same hang-up the cold initiator
    // sends when its output pipe closes.
    if client_gone {
        let _ = t
            .send_control(&json!({
                "type": "l2-close",
                "sid": sid,
                "err": "the initiator's warm output channel closed",
            }))
            .await;
    }
    mux.drop_stream(sid).await;
    mux.drop_stream(err_sid).await;
    let terminal = match terminal {
        Some(v) => Out::Close(v),
        None => match status {
            Some(code) => Out::Exit(code),
            None => Out::Close(warm_error(
                "the peer closed the exec stream without an exit status",
            )),
        },
    };
    let _ = out_tx.send(terminal).await;
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    // A stream that ended must not leave a half-live remote tree behind.
    if t.is_dead() {
        let _ = tx.send(filament_transport::net::Ev::DropLink(pid));
    }
}

/// The peer's answer to a warm `exec-open`, or the honest reason there was none.
enum Ack {
    Opened,
    /// The peer answered with a refusal: the exact `l2-close`/`link-revoked`
    /// frame, so the CLI can render its code/as/reinvite remedy.
    Refused(Value),
    /// The open may have reached the peer, but no answer did. Never a fallback.
    Failed(String),
}

async fn await_ack(
    mux: &Arc<Mux>,
    ctl: &mut mpsc::Receiver<Value>,
    t: &Arc<dyn Transport>,
    sid: u32,
    peer: &str,
) -> Ack {
    let deadline = tokio::time::Instant::now() + EXEC_ACK_WAIT;
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await;
    loop {
        tokio::select! {
            msg = ctl.recv() => match msg {
                Some(v) if v["type"].as_str() == Some("exec-open-ack")
                    && v["sid"].as_u64() == Some(sid as u64) => return Ack::Opened,
                Some(v) if v["type"].as_str() == Some("exec-close") => {
                    return Ack::Failed(format!(
                        "'{peer}' closed the exec stream before acknowledging the open"
                    ));
                }
                Some(v) if v["type"].as_str() == Some("l2-close")
                    && v["sid"].as_u64() == Some(sid as u64) =>
                {
                    return Ack::Refused(v);
                }
                Some(v) if v["type"].as_str() == Some("link-revoked") => {
                    return Ack::Refused(v);
                }
                Some(_) => {}
                None => {
                    return match mux.take_close_err(sid).await {
                        Some(reason) => Ack::Refused(json!({
                            "type": "l2-close",
                            "sid": sid,
                            "err": reason,
                        })),
                        None => Ack::Failed(format!(
                            "'{peer}' closed the exec stream before answering"
                        )),
                    };
                }
            },
            _ = ticker.tick() => {
                if t.is_dead() {
                    return Ack::Failed("the warm link died before the peer answered".to_string());
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Ack::Failed(format!(
                    "no answer from '{peer}' - it may be unresponsive or running a build without exec"
                ));
            }
        }
    }
}

/// The terminal frame for a stream that ended without a status. If the mux
/// recorded a peer close reason, forward that exact `l2-close` so the CLI can
/// render the same refusal the cold path would.
async fn stream_ended(mux: &Arc<Mux>, peer: &str, sid: u32) -> Value {
    match mux.take_close_err(sid).await {
        Some(reason) => json!({ "type": "l2-close", "sid": sid, "err": reason }),
        None => json!({
            "type": "warm-error",
            "err": format!(
                "exec stream ended without an exit status; the peer's close frame did not arrive ('{peer}')"
            ),
        }),
    }
}

fn warm_error(why: &str) -> Value {
    json!({ "type": "warm-error", "err": why })
}
