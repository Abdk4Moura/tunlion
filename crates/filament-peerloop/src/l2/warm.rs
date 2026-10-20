//! WARM STREAM VERIFICATION: prove a held link still delivers before committing
//! a client to it.
//!
//! These are the `l2` helpers the daemon's warm-reuse handlers use, moved out of
//! `cli/src/l2.rs` with their bodies unchanged. They are host-free: a mux, a
//! port/session and a duration in, a verdict out. The daemon handlers that
//! decide what to do with the verdict live in [`crate::daemon_ctl`].

use anyhow::{anyhow, Result};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::l2::mux::{serve_stream, Mux, PipeItem};

/// How long warm-reuse waits for the first inbound frame proving a held link
/// still delivers, before treating it as a zombie. A healthy link answers in ~1
/// RTT; for ssh that frame is sshd's banner and for pty the shell prompt, both of
/// which the peer sends UNPROMPTED, so the wait overlaps work we needed anyway.
/// Only a black-holed link burns the whole window. Override with
/// TUNLION_WARM_VERIFY_MS.
#[cfg(unix)]
pub fn warm_verify_window() -> std::time::Duration {
    let ms = std::env::var("TUNLION_WARM_VERIFY_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(2500);
    std::time::Duration::from_millis(ms)
}

/// Open one stream to `peer:rport`, sending l2-open and waiting (briefly) until
/// the inbound pipe is wired. Returns the registered receiver. The initiator
/// registers its OWN pipe up front so a server-speaks-first protocol (ssh
/// banner) can't lose bytes.
pub async fn open_stream(mux: &Arc<Mux>, rport: u16) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    // alloc_sid hands out a fresh sid, so register never collides here; guard
    // anyway so a refusal can never be silently ignored (which would re-open the
    // collision hole if this path ever shared sid space).
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("l2 open: sid {sid:#x} already in use"))?;
    // The dial target is ALWAYS 127.0.0.1 in production (localhost-only is the
    // contract). TUNLION_L2_DIALHOST is a TEST-ONLY override so the SSRF gate
    // can drive a non-loopback open and observe the acceptor refuse it.
    let host = std::env::var("TUNLION_L2_DIALHOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    mux.transport()
        .send_control(&json!({ "type": "l2-open", "sid": sid, "host": host, "rport": rport }))
        .await?;
    Ok((sid, rx))
}

/// Confirm a just-opened warm stream (`sid` + its inbound `rx`) actually delivers,
/// BEFORE the caller commits the client to it. Waits up to `verify` for the first
/// inbound frame - data OR an l2-close (a real refusal): either proves the link is
/// alive. Returns the frame so the caller can replay it (no bytes lost). `Err` if
/// nothing arrives in time: a ZOMBIE link, up at the QUIC layer but black-holing
/// new streams, so the caller drops it and falls back to a fresh establish rather
/// than handing the client a dead connection (which would stall until ITS own
/// timeout - the 25s ssh ConnectTimeout we measured). Verifying first means the
/// fallback is immediate and the client never sends bytes into a black hole.
async fn verify_first_frame(
    mux: &Arc<Mux>,
    sid: u32,
    mut rx: mpsc::Receiver<PipeItem>,
    verify: std::time::Duration,
) -> Result<(PipeItem, mpsc::Receiver<PipeItem>)> {
    match tokio::time::timeout(verify, rx.recv()).await {
        Ok(Some(first)) => Ok((first, rx)),
        Ok(None) => Err(anyhow!("warm stream closed before any frame")),
        Err(_) => {
            // Best-effort tear-down of the half-open sid on the peer, then bail so
            // the caller drops this zombie link and establishes fresh.
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            Err(anyhow!(
                "warm link unresponsive after {}ms (zombie)",
                verify.as_millis()
            ))
        }
    }
}

/// Open an L2 stream over a warm link and CONFIRM the peer responds before the
/// caller commits the client. Returns (sid, first_frame, remaining_rx) once the
/// first inbound frame lands. `Err` on a zombie link (see `verify_first_frame`).
/// Production goes through `open_stream_verified_reason` (the daemon must tell a
/// refusal from a zombie); this flattening of it is what the zombie tests pin.
#[cfg(all(unix, test))]
pub async fn open_stream_verified(
    mux: &Arc<Mux>,
    rport: u16,
    verify: std::time::Duration,
) -> Result<(u32, PipeItem, mpsc::Receiver<PipeItem>)> {
    match open_stream_verified_reason(mux, rport, verify).await {
        WarmOpen::Opened(sid, first, rx) => Ok((sid, first, rx)),
        WarmOpen::Refused(reason) => Err(anyhow!("warm stream refused: {reason}")),
        WarmOpen::Dead(e) => Err(e),
    }
}

/// `open_stream_verified`, but a REFUSAL stays a refusal. The plain version maps
/// a peer's `l2-close{err}` to the same error as a zombie link, so the daemon
/// dropped a healthy warm link every time a forward was refused, and the client
/// fell to a cold path that refused again with nothing on its terminal.
pub enum WarmOpen {
    Opened(u32, PipeItem, mpsc::Receiver<PipeItem>),
    Refused(String),
    Dead(anyhow::Error),
}

pub async fn open_stream_verified_reason(
    mux: &Arc<Mux>,
    rport: u16,
    verify: std::time::Duration,
) -> WarmOpen {
    let (sid, rx) = match open_stream(mux, rport).await {
        Ok(v) => v,
        Err(e) => return WarmOpen::Dead(e),
    };
    match verify_first_frame(mux, sid, rx, verify).await {
        Ok((first, rx)) => WarmOpen::Opened(sid, first, rx),
        // on_close records the reason BEFORE it closes the pipe the verify
        // reads, so a refusal is always visible here.
        Err(e) => match mux.take_close_err(sid).await {
            Some(reason) => WarmOpen::Refused(reason),
            None => WarmOpen::Dead(e),
        },
    }
}

/// Bridge a verified warm stream to the client `sock`, replaying the already-read
/// `first` frame so no peer bytes are lost.
#[cfg(unix)]
pub async fn serve_verified_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    sock: S,
    first: PipeItem,
    rx: mpsc::Receiver<PipeItem>,
) {
    serve_stream(mux, sid, sock, rx, true, Some(first), None).await;
}

/// WARM pty (daemon side): open a PTY on the peer over an EXISTING link's `mux`,
/// sending `pty-open` (vs `open_stream`'s `l2-open`). Returns the sid + inbound
/// pipe; the caller bridges with `serve_opened_stream` and relays `pty-resize` by
/// the sid. `session` keys the peer's persistent PTY so a reconnect reattaches.
/// The remote acceptor serves this exactly as a cold `pty-open`.
async fn open_pty_stream(
    mux: &Arc<Mux>,
    session: &str,
    cols: u16,
    rows: u16,
    term: &str,
    cmd: &str,
) -> Result<(u32, mpsc::Receiver<PipeItem>)> {
    let sid = mux.alloc_sid();
    let rx = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("pty open: sid {sid:#x} already in use"))?;
    let mut ctl = json!({
        "type": "pty-open", "sid": sid, "session": session, "cols": cols, "rows": rows, "term": term
    });
    if !cmd.is_empty() {
        ctl["cmd"] = json!(cmd);
    }
    mux.transport().send_control(&ctl).await?;
    Ok((sid, rx))
}

/// Verdict of a verified warm pty open, decided where the sid is in scope
/// (the caller never sees it on failure, so reason/link checks that need it
/// live here, not at the call site).
/// - Opened: first frame arrived, session bridged from here.
/// - Refused: the peer answered with a close reason (definitive; report it).
/// - LinkDead: our link died under the verify (or the open never left):
///   the caller drops it and falls back to cold, which re-verifies there.
/// - Silent: stream closed with no reason on a live link. Every refusal
///   carries err, so this is a CLEAN session end with no output (fast
///   `true`), never a denial: the caller accepts and closes at once so
///   the client reads EOF as a clean exit, mirroring the cold path.
#[cfg(unix)]
pub enum WarmPtyVerdict {
    Opened(u32, PipeItem, mpsc::Receiver<PipeItem>),
    Refused(String),
    LinkDead,
    Silent,
}

#[cfg(unix)]
pub async fn open_pty_stream_verified(
    mux: &Arc<Mux>,
    session: &str,
    cols: u16,
    rows: u16,
    term: &str,
    cmd: &str,
    verify: std::time::Duration,
) -> WarmPtyVerdict {
    let (sid, mut rx) = match open_pty_stream(mux, session, cols, rows, term, cmd).await {
        Ok(v) => v,
        // Local open failure (sid collision is ours; a send failure means the
        // link is already gone): fall back rather than report a refusal the
        // peer never sent.
        Err(_) => return WarmPtyVerdict::LinkDead,
    };
    // Same wait as verify_first_frame (kept inline so the verdict, which
    // needs the sid, is decided here; mount keeps the shared helper).
    match tokio::time::timeout(verify, rx.recv()).await {
        Ok(Some(first)) => WarmPtyVerdict::Opened(sid, first, rx),
        Ok(None) => {
            // Pipe closed with no frames: a recorded close reason means the
            // peer answered (refusal); a dead link means the verify raced a
            // flap (the mux entry dies with the link) -- fall back. Silent
            // close on a live link stays the legacy refusal.
            if let Some(reason) = mux.take_close_err(sid).await {
                WarmPtyVerdict::Refused(reason)
            } else if !mux.transport().is_alive() {
                WarmPtyVerdict::LinkDead
            } else {
                WarmPtyVerdict::Silent
            }
        }
        Err(_) => {
            // Timeout (zombie): same teardown verify_first_frame performs --
            // free the half-open sid, tell the peer, and let the caller drop
            // the link and fall back.
            mux.drop_stream(sid).await;
            let _ = mux
                .transport()
                .send_control(&json!({ "type": "l2-close", "sid": sid }))
                .await;
            WarmPtyVerdict::LinkDead
        }
    }
}

/// Bridge an already-opened L2 stream (`sid` + its inbound `rx`) to a local
/// `stream` (the warm pty client's unix socket), running to completion (stream
/// EOF or peer FIN). The daemon's warm-pty path uses this after a verified open.
#[cfg(unix)]
pub async fn serve_opened_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mux: Arc<Mux>,
    sid: u32,
    stream: S,
    rx: mpsc::Receiver<PipeItem>,
) {
    serve_stream(mux, sid, stream, rx, true, None, None).await;
}

// Keep the Duration import meaningful on non-unix builds, where the verify
// window (and therefore the only public use) is cfg'd out.
#[allow(dead_code)]
fn _duration(_: Duration) {}
