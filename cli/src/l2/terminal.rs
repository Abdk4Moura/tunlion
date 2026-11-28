//! Interactive and one-shot PTY terminal client, raw mode, and stdin/stdout bridging.

use super::pty_session::SESSION_DETACHED_IDLE;
use super::{Mux, OpenOutcome, bring_up_to_known, pump_initiator};
use crate::net::Transport;
use anyhow::{Result, anyhow, bail};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Warm-pty variant of `pump_stdio_over` that draws input from the SHARED,
/// invocation-long stdin reader instead of its own `tokio::io::stdin()`. The pty
/// client can hand off warm->cold on a drop, so both halves MUST consume the one
/// fd0 reader or a stale singleton swallows input after the handoff (see
/// `spawn_stdin_reader`). `pending` preserves an input chunk pulled just as the
/// warm socket died so the cold reattach re-sends it. Returns when the socket's
/// remote half closes (warm session over: a drop OR a clean shell exit).
#[cfg(unix)]
async fn pump_warm_pty_stdio(
    sock: tokio::net::UnixStream,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
    received: &mut u64,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    if let Some(buf) = pending.take() {
        if wr.write_all(&buf).await.is_err() {
            *pending = Some(buf);
            return Ok(());
        }
        let _ = wr.flush().await;
    }
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // remote half closed: warm session over
                Ok(n) => {
                    stdout.write_all(&buf[..n]).await?;
                    stdout.flush().await?;
                    *received += n as u64;
                }
            },
            chunk = stdin_rx.recv() => match chunk {
                Some(c) if c.is_empty() => { let _ = wr.shutdown().await; } // fd0 EOF
                Some(c) => {
                    if wr.write_all(&c).await.is_err() { *pending = Some(c); break; }
                    let _ = wr.flush().await;
                }
                None => { let _ = wr.shutdown().await; }
            },
        }
    }
    let _ = stdout.flush().await;
    Ok(())
}

/// Pump a one-shot warm pty: stream output to stdout until the command exits.
/// No raw mode, no SIGWINCH, no interactive features. Forwards stdin to match
/// cold path parity (supports `echo hi | tunlion shell peer -- cat`).
#[cfg(unix)]
async fn pump_warm_pty_one_shot(
    sock: tokio::net::UnixStream,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(sock);
    if let Some(buf) = pending.take() {
        if wr.write_all(&buf).await.is_err() {
            *pending = Some(buf);
            return Ok(());
        }
        let _ = wr.flush().await;
    }
    // For scripted one-shot: on stdin-EOF, shut down the write-half to signal
    // stdin-EOF to the daemon (cat etc. will see stdin EOF and exit), but do
    // NOT let serve_stream tear down the pty session yet. The daemon's
    // socket_to_dc sees the read-EOF and sends an empty frame (FIN) to the
    // daemon transport, which closes the pty stdin. The daemon keeps the pty
    // open until the command exits, then closes the socket (dc_to_socket
    // finishes as the pty output pipe closes), which we see as read-EOF.
    //
    // Key insight: on a Unix socket, closing the write-half sends FIN to the
    // reader, but the reader half stays open. socket_to_dc sees the FIN and
    // returns Ok(()), but the writer (dc_to_socket) is NOT aborted until the
    // daemon's pty output pipe closes. serve_stream's select! picks up the
    // writer finishing AFTER the reader, not before.
    let mut stdin_done = false;
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            r = rd.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // command exited / link closed
                Ok(n) => {
                    stdout.write_all(&buf[..n]).await?;
                    stdout.flush().await?;
                }
            },
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                Some(c) if c.is_empty() => {
                    // stdin-EOF: shut down write-half to signal the daemon.
                    // socket_to_dc sees read-EOF, sends FIN to daemon transport.
                    // Daemon keeps pty open until command exits, then closes socket.
                    let _ = wr.shutdown().await;
                    stdin_done = true;
                }
                Some(c) => {
                    if wr.write_all(&c).await.is_err() { *pending = Some(c); break; }
                    let _ = wr.flush().await;
                }
                None => {
                    // Shared reader gone (only at shutdown) - don't close socket.
                    stdin_done = true;
                }
            },
        }
    }
    let _ = stdout.flush().await;
    Ok(())
}

/// Recovery for the LOCAL terminal at client entry/final exit only. Interactive
/// shell takes ownership of its attached tty; a parent TUI must suspend its own
/// modes before launching the child and restore them after it returns. A killed
/// TUI may leave mouse/focus/paste reports enabled, polluting the next shell's
/// stdin. These bytes belong on local stdout, NEVER in transport frames or the
/// PTY replay ring: the remote application owns modes while attached, including
/// across reconnects. Do not touch the alternate screen or discard scrollback.
const LOCAL_TERMINAL_INPUT_RESET: &[u8] =
    b"\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?1004l\x1b[?2004l";

#[derive(Clone, Copy)]
pub(super) enum LocalTerminalReset {
    Entry,
    Exit,
}

/// The only sink is a local writer, not a Transport. The tty check also applies
/// to final cleanup, so redirected stdout never acquires escape sequences.
pub(super) fn write_local_terminal_reset(
    out: &mut impl std::io::Write,
    is_terminal: bool,
    phase: LocalTerminalReset,
) -> std::io::Result<()> {
    if !is_terminal {
        return Ok(());
    }
    out.write_all(LOCAL_TERMINAL_INPUT_RESET)?;
    if matches!(phase, LocalTerminalReset::Exit) {
        out.write_all(b"\x1b[?1l\x1b>\x1b[?25h")?;
    }
    out.flush()
}

fn reset_terminal_modes(phase: LocalTerminalReset) {
    use std::io::IsTerminal;
    let mut out = std::io::stdout();
    let is_terminal = out.is_terminal();
    let _ = write_local_terminal_reset(&mut out, is_terminal, phase);
}

/// Input that arrived before the remote PTY was ready is kept (typing ahead at
/// "waiting for known device" works), but mouse reports are taken out of it:
/// a terminal an earlier session left in mouse mode reports every mouse move,
/// and those must not reach the new shell as if typed. Runs once, when raw
/// mode is first entered; what is left goes out first through `pending`.
///
/// The bytes are also restored from cooked-mode line discipline to what a raw
/// terminal would have sent (`normalize_cooked_newlines`): Enter reached us as
/// LF, and a Windows ConPTY shell treats LF as "insert a newline in the edit
/// buffer", not "submit". That left the first typed command sitting behind a
/// `>>` continuation prompt until a later raw-mode CR arrived; its output then
/// appeared late (and out of order) with that command. Unix ttys map CR back to
/// LF via ICRNL, so normalizing is safe there too.
fn scrub_typeahead(
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
) {
    let mut queued = pending.take().unwrap_or_default();
    while let Ok(chunk) = stdin_rx.try_recv() {
        queued.extend_from_slice(&chunk);
    }
    let kept = normalize_cooked_newlines(&strip_mouse_reports(&queued));
    if !kept.is_empty() {
        *pending = Some(kept);
    }
}

/// Undo the terminal's cooked-mode line-ending translation for input typed
/// before raw mode: Enter arrives as LF (`ICRNL`) or CRLF (a Windows console
/// read), while a raw terminal sends the CR a remote PTY expects. `\n` and
/// `\r\n` each become one `\r`; a lone `\r` is already right. This is not
/// applied to piped stdin, where LF is the script's own line ending, nor to
/// raw-mode input, where a deliberate Ctrl+J must reach a remote TUI unchanged.
pub(crate) fn normalize_cooked_newlines(input: &[u8]) -> Vec<u8> {
    CookedNewlines::default().push(input)
}

/// State carried across cooked stdin reads, because a CRLF can be split by the
/// reader: chunk `A\r` followed by chunk `\nB` must be one Enter, not two.
///
/// The CR at the end of a chunk is emitted immediately (no latency, no hold);
/// this only remembers that if the NEXT cooked chunk opens with LF, that LF is
/// the second half of the same line ending.
#[derive(Default)]
pub(crate) struct CookedNewlines {
    /// The last byte emitted from a cooked chunk was a CR.
    cr_at_chunk_end: bool,
}

impl CookedNewlines {
    /// Restore the line endings of ONE cooked chunk. LF and CRLF become one CR;
    /// a lone CR stays CR. An empty chunk changes nothing (the reader's EOF
    /// sentinel never reaches here).
    pub(crate) fn push(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        // The previous chunk ended in CR. If this one opens with LF, the CR is
        // already out; drop the LF instead of making a second Enter.
        if self.cr_at_chunk_end && input.first() == Some(&b'\n') {
            i = 1;
        }
        self.cr_at_chunk_end = false;
        while i < input.len() {
            match input[i] {
                b'\r' => {
                    out.push(b'\r');
                    if input.get(i + 1) == Some(&b'\n') {
                        // CRLF within this chunk is ONE Enter.
                        i += 1;
                    } else if i + 1 == input.len() {
                        // Remember it for a split CRLF in the next chunk.
                        self.cr_at_chunk_end = true;
                    }
                }
                b'\n' => out.push(b'\r'),
                byte => out.push(byte),
            }
            i += 1;
        }
        out
    }
}

/// One read's contribution to the cooked-input stream. `cooked=false` means the
/// terminal is already raw (or stdin is a pipe): bytes pass through exactly, and
/// any split-CRLF state is cleared so a stale CR can never eat a later raw LF.
pub(crate) fn normalize_stdin_chunk(
    state: &mut CookedNewlines,
    input: &[u8],
    cooked: bool,
) -> Vec<u8> {
    if !cooked {
        state.cr_at_chunk_end = false;
        return input.to_vec();
    }
    state.push(input)
}

/// Queue data from a successful, nonzero stdin read. A suppressed split-CRLF
/// tail can normalize to nothing: do not queue that as the bridge's EOF sentinel.
fn queue_stdin_chunk(
    state: &mut CookedNewlines,
    input: &[u8],
    cooked: bool,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> std::result::Result<(), mpsc::error::SendError<Vec<u8>>> {
    let chunk = normalize_stdin_chunk(state, input, cooked);
    if chunk.is_empty() {
        return Ok(());
    }
    tx.send(chunk)
}

/// Remove terminal mouse reports from `input`: SGR (`ESC [ < b ; x ; y M|m`),
/// urxvt (`ESC [ b ; x ; y M`) and the original X10 form (`ESC [ M` and three
/// bytes). Everything else, keystrokes and other escape sequences, is kept.
pub(crate) fn strip_mouse_reports(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == 0x1b && input.get(i + 1) == Some(&b'[') {
            let rest = &input[i + 2..];
            // X10: ESC [ M Cb Cx Cy
            if rest.first() == Some(&b'M') && rest.len() >= 4 {
                i += 6;
                continue;
            }
            // SGR (with '<') or urxvt (without): digits;digits;digits then M or m
            let body = if rest.first() == Some(&b'<') { &rest[1..] } else { rest };
            let lead = rest.len() - body.len();
            let mut j = 0;
            let mut fields = 1;
            while j < body.len() && (body[j].is_ascii_digit() || body[j] == b';') {
                if body[j] == b';' {
                    fields += 1;
                }
                j += 1;
            }
            let sgr = lead == 1;
            if j > 0 && fields == 3 && j < body.len() && (body[j] == b'M' || (sgr && body[j] == b'm')) {
                i += 2 + lead + j + 1;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// RAII guard: put the local terminal in raw mode for an interactive PTY and
/// ALWAYS restore cooked mode on drop (normal exit, error, or `?`). Without raw
/// mode the local tty line-buffers + echoes and swallows control keys, so a
/// remote TUI (claude/opencode/vim/htop) can't receive keystrokes or escape
/// sequences and renders unusable.
struct RawGuard {
    active: bool,
    /// The console's original modes, restored exactly on drop. On Windows this
    /// is what turns on VT input so mouse and special keys reach the remote PTY
    /// (see platform::ConsoleModes); elsewhere it is a no-op.
    console: crate::platform::ConsoleModes,
}
impl RawGuard {
    fn enable() -> Result<Self> {
        let console = crate::platform::ConsoleModes::snapshot();
        crossterm::terminal::enable_raw_mode()?;
        console.enable_vt();
        // On Windows this must follow enable_vt, otherwise a classic console
        // may not interpret the cleanup escapes. Never repeat on reconnect.
        reset_terminal_modes(LocalTerminalReset::Entry);
        Ok(RawGuard { active: true, console })
    }
}
impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            // Flush reporting/keypad/cursor recovery while VT output is still
            // enabled, before restoring raw mode and the Windows console modes.
            reset_terminal_modes(LocalTerminalReset::Exit);
            let _ = crossterm::terminal::disable_raw_mode();
            self.console.restore();
            eprint!("\r\n");
        }
    }
}

/// The acceptor's answer to a RESUME-only attach whose session is gone: the
/// shell exited while we were away (or on the warm path, which cannot tell a
/// clean exit from a drop, see `pty_cmd`). It is the normal end of a session,
/// never a refusal. The wire string is fixed: older acceptors send exactly it.
///
/// Re-exported from the library, which sends it: the string we compare against
/// is the string this build sends, not a second copy of it.
pub(crate) use filament_peerloop::l2::NO_SUCH_SESSION;

/// Why a single PTY attach ended.
enum PtyOutcome {
    /// The remote shell exited (acceptor sent `l2-close` while the link was
    /// healthy) - we are DONE, do not reconnect.
    Exited,
    /// The link died under us (transport not alive) - the remote PTY session may
    /// still be alive on the acceptor; reconnect and REATTACH the same session.
    Dropped,
    /// The acceptor refused the open with an explicit reason (no shell cap,
    /// acceptor off, stream cap, ...). Nonzero, print the reason.
    Refused(String),
    /// The stream closed (or never answered) before we could confirm the peer
    /// opened a shell. Nonzero, with a weaker sentence rather than a confident
    /// wrong one.
    Unconfirmed(String),
}

/// A single, process-lifetime reader of fd0 for the resumable pty client.
///
/// tokio's `io::stdin()` is a GLOBAL singleton backed by an UNCANCELLABLE blocking
/// read thread. The resumable client re-attaches on every link drop (and hands off
/// warm->cold), and the old code spawned a fresh stdin reader per attach then
/// `abort()`ed the previous one. Aborting a task parked in that shared blocking
/// read does NOT stop the read: a stale reader keeps draining fd0 and routing bytes
/// to a DEAD stream, so after a real reattach every keystroke is silently swallowed
/// (observed live: a 30s outage closes QUIC, forces a true reattach, input dies -
/// the read even shows up in strace, it just goes nowhere). Fix: read fd0 exactly
/// ONCE, on a dedicated thread that lives for the whole invocation, and fan chunks
/// to whichever attach is current over an mpsc channel. An empty Vec is the EOF
/// sentinel (matches the `send_frame(sid, &[])` FIN convention). The thread ends on
/// EOF/error; on a clean session exit the process exits right after, reaping it.
///
/// `cooked` is true while stdin is a tty that has not reached raw mode. Each
/// chunk read in that state is restored from cooked line endings before it is
/// queued, with `CookedNewlines` carrying the split-CRLF state across reads.
///
/// The flag is sampled AFTER the blocking read returns, so this NARROWS but
/// cannot CLOSE the cooked/raw switch: a line the tty completed while cooked
/// whose reader thread is not scheduled until after the caller clears the flag
/// is classified as raw, and its LF still passes through. Userspace cannot see
/// the tty mode at the instant the kernel delivered those bytes, so a residual
/// of one scheduler delay remains. The caller stores `false` only after
/// `enable_raw_mode`, which makes a chunk read during the switch over-normalize
/// (only a deliberate raw Ctrl-J can differ) rather than under-normalize.
pub(crate) fn spawn_stdin_reader(
    cooked: Arc<AtomicBool>,
) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 16 * 1024];
        let mut newlines = CookedNewlines::default();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(Vec::new()); // EOF sentinel
                    break;
                }
                Ok(n) => {
                    if queue_stdin_chunk(
                        &mut newlines,
                        &buf[..n],
                        cooked.load(Ordering::Acquire),
                        &tx,
                    ).is_err() {
                        break; // the client hung up
                    }
                }
            }
        }
    });
    rx
}

/// Send `data` to the peer over one L2 stream, split into transport-sized frames.
/// `Err(())` means a frame was rejected (the link is gone); the caller stashes the
/// unsent input for the next attach so a keystroke typed at the drop is not lost.
async fn send_frames_chunked(
    t: &Arc<dyn Transport>,
    sid: u32,
    data: &[u8],
) -> std::result::Result<(), ()> {
    let cap = t.max_payload().max(1);
    for chunk in data.chunks(cap) {
        if t.send_frame(sid, 0, chunk).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}

/// One attach to the peer's PTY over a freshly-established link: open/reattach the
/// `session_id`, bridge stdio, and return why it ended. Raw mode is owned by the
/// caller (held across reconnects), so this only does size/resize/IO. `stdin_rx`
/// is the shared, invocation-long stdin source (see `spawn_stdin_reader`); `pending`
/// carries input pulled-but-unsent when the previous attach dropped, so a keystroke
/// at the seam survives the reconnect.
#[allow(clippy::too_many_arguments)]
async fn pty_attach_once(
    server: &str,
    peer: &str,
    relay: bool,
    role: &'static str,
    session_id: &str,
    term: &str,
    cmd: &str,
    interactive: bool,
    resume: bool,
    raw: &mut Option<RawGuard>,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
    received: &mut u64,
    cooked: &Arc<AtomicBool>,
) -> Result<PtyOutcome> {
    // Bound the connect so an unreachable peer fails with a clear message
    // instead of hanging forever. Override with TUNLION_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("TUNLION_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, role),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            bail!("connect timeout: couldn't reach '{peer}' in {connect_secs}s");
        }
    };
    guard.forget();
    let mux = Mux::new(t, crate::host_impl::cli_host());
    let pump = tokio::spawn(pump_initiator(rx, mux.clone()));

    diag.enter(crate::diag::Phase::L2Open);
    let sid = mux.alloc_sid();
    let mut rx_pipe = mux
        .register(sid)
        .await
        .ok_or_else(|| anyhow!("pty open: sid {sid:#x} already in use"))?;

    // Register the open waiter BEFORE the pty-open goes out, so an ack/close that
    // races back cannot be lost. Only the FIRST attach needs this: a resume that
    // finds no session is a clean end (the acceptor says "no such session"), not a
    // denial, and exit 0 is correct there.
    let ack_rx = if resume {
        None
    } else {
        Some(mux.arm_open_ack(sid).await)
    };

    // Real terminal: query the ACTUAL tty size (crossterm asks the tty via
    // ioctl), NOT the COLUMNS/LINES shell vars which are usually unexported and
    // leave a TUI rendering at a stale size. Fall back to env/defaults for a pipe.
    let (cols, rows) = if interactive {
        crossterm::terminal::size().unwrap_or((80, 24))
    } else {
        (
            std::env::var("COLUMNS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80u16),
            std::env::var("LINES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(24u16),
        )
    };
    // `session` makes reconnects REATTACH the same shell (acceptor keys it per
    // verified device); a fresh per-invocation id means two `tunlion shell` runs
    // never collide. `term` is forwarded so the remote matches THIS terminal.
    mux.transport()
        .send_control(&{
            let mut ctl = json!({
                "type": "pty-open", "sid": sid, "session": session_id,
                "cols": cols, "rows": rows, "term": term, "resume": resume,
            });
            // A reattach says how much output it already has, so the acceptor
            // replays only what was missed.
            if resume {
                ctl["resume_from"] = json!(*received);
            }
            if !cmd.is_empty() {
                ctl["cmd"] = json!(cmd);
            }
            ctl
        })
        .await?;
    diag.up("tunnel", "datachannel-or-direct");

    // Exit 0 must mean "the peer told me it opened". Wait (bounded) for the
    // pty-open-ack before committing to the session, so a refusal, a silent
    // close, or a black hole all become nonzero instead of an empty-success.
    // `-- true` stays exit 0: the ack arrives, then the clean l2-close follows.
    if let Some(ack_rx) = ack_rx {
        let outcome = tokio::time::timeout(Duration::from_secs(10), ack_rx).await;
        match outcome {
            Ok(Ok(OpenOutcome::Opened(_))) => {}
            Ok(Ok(OpenOutcome::Refused(reason))) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Refused(reason));
            }
            Ok(Ok(OpenOutcome::ClosedWithoutAck)) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "could not confirm '{peer}' opened a shell (the connection closed before it answered)"
                )));
            }
            Ok(Err(_)) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "could not confirm '{peer}' opened a shell (the link closed)"
                )));
            }
            Err(_) => {
                mux.drop_stream(sid).await;
                pump.abort();
                return Ok(PtyOutcome::Unconfirmed(format!(
                    "no answer from '{peer}' - it may be unresponsive or running a build that does not ack shell opens"
                )));
            }
        }
    }

    // Enable raw mode LAZILY, AFTER the establishment status lines have printed in
    // cooked mode (so `\n` still does CR+LF and they don't "staircase"). Held in
    // the caller's scope so it persists across reconnects and is restored on exit.
    // On a reconnect raw is already on; the acceptor's buffer replay redraws the
    // screen cleanly anyway.
    if interactive && raw.is_none() {
        scrub_typeahead(stdin_rx, pending);
        *raw = Some(RawGuard::enable()?);
        // Only now is new input raw. The reader samples the flag after each
        // blocking read, so clearing it here narrows (but does not close) the
        // cooked/raw switch; see spawn_stdin_reader.
        cooked.store(false, Ordering::Release);
    }

    // Forward terminal resizes to the remote PTY (acceptor handles `pty-resize`).
    #[cfg(unix)]
    let winch = if interactive {
        let t_resize = mux.transport();
        Some(tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    let _ = t_resize
                        .send_control(
                            &json!({ "type": "pty-resize", "sid": sid, "cols": c, "rows": r }),
                        )
                        .await;
                }
            }
        }))
    } else {
        None
    };

    let t_in = mux.transport();
    // Input buffered-but-unsent by the PREVIOUS (dropped) attach goes out first, so
    // a keystroke typed right at the seam survives the reconnect. If this link is
    // already dead, keep it stashed and report a drop so the loop reattaches again.
    if let Some(buf) = pending.take() {
        if send_frames_chunked(&t_in, sid, &buf).await.is_err() {
            *pending = Some(buf);
            #[cfg(unix)]
            if let Some(w) = winch {
                w.abort();
            }
            mux.drop_stream(sid).await;
            pump.abort();
            return Ok(PtyOutcome::Dropped);
        }
    }

    // Stream remote output to stdout AND forward local input, driven by the SHARED
    // stdin reader (see `spawn_stdin_reader`) so reconnects never spawn a second
    // fd0 consumer. End when the pipe closes (shell exit OR link death) - disambiguated
    // by the transport's liveness. A 2s liveness poll is the backstop for a silent
    // black-hole that never closes the pipe.
    let mut stdout = tokio::io::stdout();
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.tick().await; // consume the immediate tick
    let mut stdin_done = false; // fd0 hit EOF: stop reading it, keep pumping stdout
    let dropped;
    let mut close_reason: Option<String> = None;
    loop {
        tokio::select! {
            item = rx_pipe.recv() => match item {
                Some(Some(bytes)) => {
                    stdout.write_all(&bytes).await?;
                    stdout.flush().await?;
                    *received += bytes.len() as u64;
                }
                // Pipe closed: clean exit (l2-close, link still alive), a mid-session
                // denial (l2-close{err}, the revoke case), or a drop.
                _ => {
                    dropped = !mux.transport().is_alive();
                    close_reason = mux.take_close_err(sid).await;
                    break;
                }
            },
            chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                // Empty Vec = fd0 EOF: send the FIN once, then stop reading stdin but
                // keep draining remote output until the shell actually closes.
                Some(c) if c.is_empty() => { let _ = t_in.send_frame(sid, 0, &[]).await; stdin_done = true; }
                Some(c) => {
                    if send_frames_chunked(&t_in, sid, &c).await.is_err() {
                        // Link died mid-send: stash the input for the next attach and
                        // reconnect rather than lose it.
                        *pending = Some(c);
                        dropped = true;
                        break;
                    }
                }
                None => { stdin_done = true; } // shared reader gone (only at shutdown)
            },
            _ = ticker.tick() => {
                if !mux.transport().is_alive() { dropped = true; break; }
            }
        }
    }

    #[cfg(unix)]
    if let Some(w) = winch {
        w.abort();
    }
    mux.drop_stream(sid).await;
    // Only send our own l2-close on a CLEAN exit. On a drop the link is gone and,
    // crucially, an l2-close would tell the acceptor to END the session we want
    // to reattach - so we stay silent and let it buffer for the reattach.
    if !dropped {
        let _ = mux
            .transport()
            .send_control(&json!({ "type": "l2-close", "sid": sid }))
            .await;
    }
    pump.abort();
    match close_reason {
        // A resume that finds no session is the shell having exited: the
        // common case is `exit` in a shell opened over the warm link, which
        // hands off to this resume-only attach. Reported as a refusal it
        // printed "shell refused ... no such session", exited 1, and left the
        // terminal raw. It is a clean end.
        Some(reason) if resume && reason.trim() == NO_SUCH_SESSION => Ok(PtyOutcome::Exited),
        // A mid-session denial (revoke): nonzero with the reason, never a clean
        // exit that would carry a `&&` pipeline forward (#223).
        Some(reason) => Ok(PtyOutcome::Refused(reason)),
        None if dropped => Ok(PtyOutcome::Dropped),
        None => Ok(PtyOutcome::Exited),
    }
}

/// Warm fast path for `tunlion shell`: if the local daemon already holds a link to
/// `peer`, open the PTY over it (via the control socket) and bridge this process's
/// stdio to it - raw mode + SIGWINCH forwarded as a `resize` op. Returns
/// `Some(result)` once it has handled the session (stdio EOF = shell exit or a
/// warm-link drop -> we exit), or `None` when there is no warm link, so the caller
/// falls through to the cold resumable path. Unix-only (the control socket is unix).
#[cfg(unix)]
async fn try_warm_pty(
    peer: &str,
    session: &str,
    term: &str,
    cmd: &str,
    interactive: bool,
    raw: &mut Option<RawGuard>,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    pending: &mut Option<Vec<u8>>,
    received: &mut u64,
    cooked: &Arc<AtomicBool>,
) -> Option<Result<()>> {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    // `Err(Some(reason))` means the DAEMON answered. A `refused:` reason is the
    // PEER's answer relayed back, and it is definitive: returning None here would
    // send the caller down the cold path, which for a fleet peer dies at name
    // resolution and reports "can't reach ... may be offline" for a peer that is
    // demonstrably reachable and simply said no.
    let sock = match crate::ctl::try_pty_reason(peer, session, cols, rows, term, cmd).await {
        Ok(sock) => sock,
        Err(Some(reason)) if reason.starts_with("refused:") => {
            let why = reason.trim_start_matches("refused:").trim();
            return Some(Err(anyhow!(
                "{}",
                crate::refusal::explain("a shell", peer, why, None, None)
            )));
        }
        Err(_) => return None, // no warm path; the cold path is the right answer
    };
    if interactive {
        crate::ui::trace(&format!(
            "tunlion: reusing warm link to '{peer}' for pty (no establish)"
        ));
        if raw.is_none() {
            scrub_typeahead(stdin_rx, pending);
            match RawGuard::enable() {
                Ok(g) => *raw = Some(g),
                Err(e) => return Some(Err(e)),
            }
            cooked.store(false, Ordering::Release);
        }
        // Forward SIGWINCH as a `resize` control op (a fresh short connection each time).
        let session_owned = session.to_string();
        let winch = tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::window_change()) {
                Ok(s) => s,
                Err(_) => return,
            };
            while sig.recv().await.is_some() {
                if let Ok((c, r)) = crossterm::terminal::size() {
                    crate::ctl::try_resize(&session_owned, c, r).await;
                }
            }
        });
        let r = pump_warm_pty_stdio(sock, stdin_rx, pending, received).await;
        winch.abort();
        let r = match r {
            Ok(()) => match crate::ctl::warm_pty_end_reason(session).await {
                Some(reason) => Err(anyhow::anyhow!("{reason}")),
                None => Ok(()),
            },
            Err(error) => Err(error),
        };
        Some(r)
    } else {
        // One-shot (scripted): no raw mode, no SIGWINCH, just stream output.
        crate::ui::trace(&format!(
            "tunlion: reusing warm link to '{peer}' for one-shot pty"
        ));
        // A scoped close (revoked, expired, forgotten) is still recorded by
        // the daemon bridge even though the socket itself just reaches EOF.
        // Ask for it so a one-shot exits nonzero with the reason instead of
        // reporting a clean shell exit.
        let result = pump_warm_pty_one_shot(sock, stdin_rx, pending).await;
        match result {
            Ok(()) => match crate::ctl::warm_pty_end_reason(session).await {
                Some(reason) => Some(Err(anyhow::anyhow!("{reason}"))),
                None => Some(Ok(())),
            },
            Err(error) => Some(Err(error)),
        }
    }
}

/// `tunlion shell <peer>`: open a PTY shell on the peer and bridge it to this
/// terminal (the CLI sibling of the browser web-shell). On a real terminal it is
/// a FULL interactive client - real tty size, raw mode, SIGWINCH, $TERM - AND
/// RESUMABLE: a per-invocation random session id lets a dropped link reconnect
/// and reattach the SAME live shell (mosh/tmux-style, the acceptor replays its
/// output buffer), so a flaky link (e.g. a Coder workspace reconnecting every
/// ~90s) no longer loses the session. The session id lives only in THIS process,
/// so a separate `tunlion shell` run always gets a fresh shell, never this one.
/// A non-tty stdio (a pipe) keeps the plain cooked, non-resuming bridge.
pub async fn pty_cmd(server: &str, peer: &str, relay: bool, cmd: Vec<String>) -> Result<()> {
    let one_shot = cmd.join(" ");
    use std::io::IsTerminal;
    let stdin_is_tty = std::io::stdin().is_terminal();
    let interactive = stdin_is_tty && std::io::stdout().is_terminal();
    // Random, per-invocation, in-memory only: distinct runs never collide; only
    // THIS process's reconnects reattach (see the user's "same client" concern).
    // TUNLION_SHELL_SESSION names the session instead, so a later run on THIS
    // device can pick a detached shell back up. The acceptor scopes every
    // session id to the device that proved itself on the link, so a name is
    // never a way into another device's shell.
    let session_id = std::env::var("TUNLION_SHELL_SESSION")
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= 64)
        .unwrap_or_else(crate::fresh_secret);
    let term = std::env::var("TERM")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "xterm-256color".into());

    // Raw mode is held for the WHOLE invocation (enabled lazily inside the first
    // attach, AFTER its status lines, so they don't staircase), persists across
    // reconnects, and is restored on every exit path by this guard's Drop.
    let mut raw: Option<RawGuard> = None;
    // The guard's Drop does not run on `process::exit` (every exit below drops
    // it first) nor on a signal from outside: SIGTERM, or
    // SIGHUP when the terminal goes away. Restore the terminal for those too.
    if interactive {
        // A terminal an earlier session left in mouse mode (or a different
        // client entirely) is fixed before anything else is shown.
        reset_terminal_modes(LocalTerminalReset::Entry);
        tokio::spawn(async {
            let code = crate::platform::termination_signal().await;
            reset_terminal_modes(LocalTerminalReset::Exit);
            let _ = crossterm::terminal::disable_raw_mode();
            std::process::exit(code);
        });
    }

    // ONE fd0 reader for the whole invocation, shared across the warm bridge and
    // every cold reattach. tokio's stdin singleton can't be cancelled, so a
    // per-attach reader leaks and swallows input after a reconnect (see
    // `spawn_stdin_reader`). `pending` carries input pulled just as a link died so
    // the reattach re-sends it instead of losing the keystroke.
    //
    // `cooked` follows STDIN, not `interactive`: with a tty stdin and a piped
    // stdout, raw mode is never entered, so the tty stays cooked for the whole
    // session and every line still arrives as LF and needs restoring. Piped
    // stdin (non-interactive) is never normalized: its LF is the script's own
    // line ending.
    let cooked = Arc::new(AtomicBool::new(stdin_is_tty));
    let mut stdin_rx = spawn_stdin_reader(cooked.clone());
    let mut pending: Option<Vec<u8>> = None;

    // WARM FAST PATH: if the local `up` daemon already holds a (verified, direct)
    // link to `peer`, open the PTY over it - no signaling, no establishment, ~0.2s
    // instead of seconds. A miss / no daemon / no warm link falls through to the
    // cold resumable path below. Skipped under --relay (the user forced relay; a
    // warm link may be direct) and for non-tty stdio (scripted). Resumability
    // lives on the cold path, where flaky peers (no warm link) need it anyway.
    // Loop state up front so the warm path can hand off INTO the resumable loop
    // instead of returning (the old behavior, which re-logged-in on a warm drop).
    let mut ever_connected = false;
    let mut last_up = std::time::Instant::now();
    let mut backoff = Duration::from_millis(300);
    let mut role: &'static str = "init";
    // Set when a WARM session ended (a drop OR a clean shell exit - the warm bridge
    // can't tell). The first cold attach after that is RESUME-ONLY: a warm drop
    // reattaches the SAME live shell/TUI (seamless, no re-login); a clean warm exit
    // finds no session and the acceptor closes it, so we exit cleanly.
    // TODO: distinguish clean-exit from transport-drop at the warm layer.
    //   Currently the bridge sees an opaque socket close for both cases.
    //
    //   INVESTIGATED 2026-08-30, and the `ctl::session_alive(peer)` probe this
    //   note used to propose DOES NOT WORK. The initiating daemon's warm_ptys
    //   entry is dropped for both outcomes -- its own comment says "Bridge ended
    //   (shell exit / client gone / link drop): drop our entry" -- so the probe
    //   answers "not alive" either way. It would skip the cold path for both,
    //   which breaks the warm-drop reattach this path exists to provide, or for
    //   neither, which changes nothing.
    //
    //   The fact lives on the PEER: does its acceptor still hold the session?
    //   Asking costs a transport establishment, which is the thing being
    //   avoided. So the real fix is a PROTOCOL addition, the acceptor sending an
    //   explicit clean-exit marker before it closes, which the initiator records
    //   so the next attach can tell the two apart locally. Bigger than a ctl op,
    //   and worth knowing before someone builds a probe that cannot answer.
    let mut warm_ended = false;
    // Bytes of this session's output already written to the terminal, across
    // every attach (warm or cold). A reattach sends it so the acceptor replays
    // only what this terminal has not shown yet.
    let mut received: u64 = 0;

    #[cfg(unix)]
    if !relay && (interactive || !one_shot.is_empty()) {
        match try_warm_pty(
            peer,
            &session_id,
            &term,
            &one_shot,
            interactive,
            &mut raw,
            &mut stdin_rx,
            &mut pending,
            &mut received,
            &cooked,
        )
        .await
        {
            Some(Err(e)) => return Err(e),
            Some(Ok(())) => {
                // For one-shot exec: the warm bridge already streamed the command's
                // output and waited for exit. Return immediately - do NOT enter the
                // reconnect/resume loop which would cold-establish redundantly.
                if !one_shot.is_empty() {
                    return Ok(());
                }
                warm_ended = true;
                role = "reconnect";
            }
            None => {} // no warm link -> normal cold path below
        }
    }

    loop {
        // Resume-only after any prior connection (warm or cold). If the session
        // is gone (shell exited cleanly on a prior drop), the acceptor returns
        // "no such session" and we exit cleanly instead of spawning a fresh shell.
        let resume = ever_connected || warm_ended;
        match pty_attach_once(
            server,
            peer,
            relay,
            role,
            &session_id,
            &term,
            &one_shot,
            interactive,
            resume,
            &mut raw,
            &mut stdin_rx,
            &mut pending,
            &mut received,
            &cooked,
        )
        .await
        {
            Ok(PtyOutcome::Exited) => return Ok(()),
            Ok(PtyOutcome::Refused(reason)) => {
                // Cooked mode first: the message must not stair-step, and the
                // exit below skips the guard's Drop.
                drop(raw.take());
                // The peer is up and said no. Nonzero with the reason; never a
                // false success that would carry a `&&` pipeline forward.
                // The remedy depends on WHICH refusal, and the acceptor's reason
                // says which: a revoked certificate is not repaired by a grant,
                // a ceiling cannot be widened by one, and a missing grant is not
                // "serving is off". `refusal` maps each to its one fix, naming
                // this device the way the peer knows it.
                let hint = match crate::refusal::code_from_reason(&reason) {
                    Some(code) => {
                        let me = crate::refusal::name_from_reason(&reason)
                            .unwrap_or_else(crate::display_name);
                        let (text, cmd) = crate::refusal::remedy_from_reason(code, peer, &me, &reason);
                        match cmd {
                            Some(c) => format!(
                                "{text} {}",
                                crate::ui::paint(crate::ui::Tone::Brand, &c)
                            ),
                            None => text,
                        }
                    }
                    None => format!(
                        "if this device should have a shell there, on '{peer}' run: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("tunlion grant {} shell", crate::display_name())
                        )
                    ),
                };
                crate::ui::problem(&format!("shell refused by '{peer}'"), &reason, &[hint]);
                std::process::exit(1);
            }
            Ok(PtyOutcome::Unconfirmed(reason)) => {
                drop(raw.take());
                // We could not establish that the peer opened a shell. Say the
                // weaker true sentence rather than a confident wrong one.
                crate::ui::problem(
                    &format!("shell could not be confirmed on '{peer}'"),
                    &reason,
                    &[],
                );
                std::process::exit(1);
            }
            Ok(PtyOutcome::Dropped) => {
                // Non-tty (scripted) sessions don't resume; a drop is the end.
                if !interactive {
                    return Ok(());
                }
                ever_connected = true;
                last_up = std::time::Instant::now();
                backoff = Duration::from_millis(300);
                role = "reconnect";
                // The local terminal is the remote PTY display. Writing even to
                // stderr here can overwrite a TUI row or split a partial escape
                // sequence, so reconnect silently and keep it a byte-stream
                // continuation. Connection diagnostics remain in trace logs.
                continue;
            }
            Err(e) => {
                // A first COLD connect (no warm session) failing is fatal. But if a
                // warm session just ended, a failed reattach should RETRY (the mesh
                // may be mid-repair) until the reaper window, not bail.
                if !ever_connected && !warm_ended {
                    drop(raw.take());
                    // A REFUSAL is not a reachability failure, and saying it is
                    // sends the user to `ping`/`doctor` to debug a healthy link.
                    // The peer answers an unauthorized open with an l2-close
                    // carrying a reason, which arrives in milliseconds; report
                    // that instead of the connect-timeout copy.
                    let refused = {
                        let msg = e.to_string();
                        (msg.contains("closed the shell request")
                            || msg.contains("refused")
                            || msg.contains("not authorized")
                            || msg.contains("capability")
                            || msg.contains("not in auth key caps"))
                        .then_some(msg)
                    };
                    if let Some(reason) = refused {
                        // Both verbs here used to be invented: `tunlion pty` and
                        // `tunlion request`. Neither exists, so the hint sent the
                        // user to a command that would not run. main's
                        // printed_hints_name_verbs_that_exist gate caught it on
                        // merge, which is exactly what that gate is for.
                        //
                        // The real shape: the attempt already queues a consent
                        // request on the PEER, so there is nothing to type here.
                        // What helps is knowing it was queued and how the other
                        // side answers it.
                        crate::ui::problem(
                            &format!("tunlion shell: '{peer}' refused the shell"),
                            &reason,
                            &[
                                format!(
                                    "on {peer}, approve it: {}",
                                    crate::ui::paint(crate::ui::Tone::Brand, "tunlion requests")
                                ),
                                format!(
                                    "or on {peer}, grant it outright: {}",
                                    crate::ui::paint(
                                        crate::ui::Tone::Brand,
                                        "tunlion grant <this device> shell"
                                    )
                                ),
                            ],
                        );
                        std::process::exit(1);
                    }
                    crate::ui::debug(&format!("tunlion shell: connect failed: {e:#}"));
                    let connect_secs: u64 = std::env::var("TUNLION_CONNECT_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .filter(|n| *n > 0)
                        .unwrap_or(45);
                    crate::ui::problem(
                        &format!("tunlion shell: can't reach '{peer}'"),
                        &format!(
                            "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                        ),
                        &[
                            format!(
                                "check it's reachable: {}",
                                crate::ui::paint(
                                    crate::ui::Tone::Brand,
                                    &format!("tunlion reach {peer}")
                                )
                            ),
                            format!(
                                "diagnose the connect: {}",
                                crate::ui::paint(
                                    crate::ui::Tone::Brand,
                                    &format!("tunlion doctor {peer}")
                                )
                            ),
                        ],
                    );
                    // 6 = unreachable in the exit-code taxonomy (#393's
                    // exit_codes::ExitKind::Unreachable), the code `exec` and
                    // `send` give for the same "it did not answer" outcome.
                    std::process::exit(6);
                }
                // A reconnect attempt failed. Keep trying until the acceptor would
                // have reaped the detached session (SESSION_DETACHED_IDLE); stop a
                // bit under that so we don't reattach into a fresh shell. A peer
                // on an older build with a shorter window answers the resume with
                // "no such session", which ends cleanly.
                if last_up.elapsed() > SESSION_DETACHED_IDLE.saturating_sub(Duration::from_secs(30)) {
                    drop(raw.take());
                    crate::ui::say("shell session ended after the reconnect window expired");
                    return Ok(());
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                role = "reconnect";
                continue;
            }
        }
    }
}

/// Build the user-facing message for the case where `tunlion forward` could
/// not bind its local listener because the requested port is in use. The
/// tunnel itself is healthy; only the local bind failed. We suggest
/// lport+1 with a saturating increment so the suggestion is always a valid
/// u16 (the helper is pure so the unit test below can pin the message shape
/// without touching the network).

#[cfg(test)]
mod terminal_reset_tests {
    use super::{LocalTerminalReset, write_local_terminal_reset};

    /// Entry only stops unsolicited input reports. Final exit does that first,
    /// then restores normal keys and cursor visibility. Neither changes screens.
    #[test]
    fn local_reset_bytes_and_order_are_exact() {
        let expected = b"\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?1004l\x1b[?2004l";
        let mut entry = Vec::new();
        write_local_terminal_reset(&mut entry, true, LocalTerminalReset::Entry).unwrap();
        assert_eq!(entry, expected);
        let mut exit = Vec::new();
        write_local_terminal_reset(&mut exit, true, LocalTerminalReset::Exit).unwrap();
        assert_eq!(exit, [expected.as_slice(), b"\x1b[?1l\x1b>\x1b[?25h"].concat());
        for screen in [b"?47".as_slice(), b"?1047", b"?1049"] {
            assert!(!exit.windows(screen.len()).any(|w| w == screen));
        }
    }

    #[test]
    fn redirected_local_stdout_gets_no_reset_bytes_or_flush() {
        struct NotATerminal;
        impl std::io::Write for NotATerminal {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                panic!("redirected stdout must not be written");
            }
            fn flush(&mut self) -> std::io::Result<()> {
                panic!("redirected stdout must not be flushed");
            }
        }
        for phase in [LocalTerminalReset::Entry, LocalTerminalReset::Exit] {
            write_local_terminal_reset(&mut NotATerminal, false, phase).unwrap();
        }
    }

    /// Mouse reports are taken out of typed-ahead input; keystrokes, Enter and
    /// other escape sequences (arrow keys) are kept, in order.
    #[test]
    fn typeahead_keeps_keys_and_drops_mouse_reports() {
        use super::strip_mouse_reports;
        let input = b"ls\x1b[<35;84;9M\x1b[<0;1;2m -la\x1b[35;80;12M\x1b[M #!\r\x1b[A";
        assert_eq!(strip_mouse_reports(input), b"ls -la\r\x1b[A".to_vec());
        assert_eq!(strip_mouse_reports(b"echo G-42\n"), b"echo G-42\n".to_vec());
        // Not a mouse report: two fields, or no terminator yet.
        assert_eq!(strip_mouse_reports(b"\x1b[1;5A"), b"\x1b[1;5A".to_vec());
        assert_eq!(strip_mouse_reports(b"\x1b[<35;84"), b"\x1b[<35;84".to_vec());
    }

    /// Cooked-mode line endings are restored to the CR a raw terminal sends.
    /// Enter in a cooked local tty arrives as LF; a Windows ConPTY shell inserts
    /// that as a new edit line instead of submitting, so the command waits behind
    /// `>>` until a later CR. CRLF is one Enter, and a lone CR must stay one.
    #[test]
    fn cooked_typeahead_newlines_become_cr() {
        use super::normalize_cooked_newlines;
        assert_eq!(normalize_cooked_newlines(b"echo A\n"), b"echo A\r".to_vec());
        assert_eq!(normalize_cooked_newlines(b"echo A\r\n"), b"echo A\r".to_vec());
        assert_eq!(normalize_cooked_newlines(b"echo A\r"), b"echo A\r".to_vec());
        assert_eq!(
            normalize_cooked_newlines(b"a\nb\r\nc\r\n"),
            b"a\rb\rc\r".to_vec(),
            "each cooked line ending is exactly one Enter"
        );
        assert_eq!(
            normalize_cooked_newlines(b"\x1b[A\n\x1b[<35;84;9M\n"),
            b"\x1b[A\r\x1b[<35;84;9M\r".to_vec(),
            "escape sequences pass through untouched"
        );
        assert_eq!(normalize_cooked_newlines(b""), Vec::<u8>::new());
    }

    /// A CRLF split by the reader must still be ONE Enter. Test every possible
    /// split point, plus one byte at a time, because the reader's chunk
    /// boundaries are arbitrary.
    #[test]
    fn cooked_newlines_survive_a_split_at_every_boundary() {
        use super::{CookedNewlines, normalize_cooked_newlines};
        let input = b"a\r\nb\nc\r";
        let expected = normalize_cooked_newlines(input);
        assert_eq!(expected, b"a\rb\rc\r".to_vec());

        for split in 0..=input.len() {
            let mut state = CookedNewlines::default();
            let mut got = state.push(&input[..split]);
            got.extend_from_slice(&state.push(&input[split..]));
            assert_eq!(got, expected, "split after byte {split}");
        }

        let mut state = CookedNewlines::default();
        let mut got = Vec::new();
        for byte in input {
            got.extend_from_slice(&state.push(std::slice::from_ref(byte)));
        }
        assert_eq!(got, expected, "one byte per read");
    }

    /// Several split CRLFs in a row, and a lone CR followed by a non-LF byte:
    /// the state must not turn one Enter into two, nor eat the next key.
    #[test]
    fn cooked_newlines_multiple_splits_and_lone_cr() {
        use super::CookedNewlines;
        let mut state = CookedNewlines::default();
        let mut got = Vec::new();
        let chunks: [&[u8]; 5] = [b"a\r", b"\n", b"b\r", b"\n", b"c\n"];
        for chunk in chunks {
            got.extend_from_slice(&state.push(chunk));
        }
        assert_eq!(got, b"a\rb\rc\r".to_vec());

        let mut state = CookedNewlines::default();
        assert_eq!(state.push(b"x\r"), b"x\r".to_vec());
        assert_eq!(
            state.push(b"y"),
            b"y".to_vec(),
            "a lone CR must not eat the next ordinary byte"
        );
        assert_eq!(state.push(b"\n"), b"\r".to_vec(), "a later LF is its own Enter");
    }

    /// An empty chunk is a no-op: it neither emits nor forgets a split CRLF.
    #[test]
    fn cooked_newlines_empty_chunk_changes_nothing() {
        use super::CookedNewlines;
        let mut state = CookedNewlines::default();
        assert!(state.push(b"").is_empty());
        assert_eq!(state.push(b"a\r"), b"a\r".to_vec());
        assert!(state.push(b"").is_empty());
        assert_eq!(state.push(b"\nb"), b"b".to_vec(), "the CRLF stays one Enter");
    }

    #[test]
    fn suppressed_split_lf_is_not_queued_as_eof() {
        use super::{CookedNewlines, queue_stdin_chunk};
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut state = CookedNewlines::default();
        queue_stdin_chunk(&mut state, b"a\r", true, &tx).unwrap();
        // CR is emitted immediately, without waiting for the next read.
        assert_eq!(rx.try_recv().unwrap(), b"a\r".to_vec());
        queue_stdin_chunk(&mut state, b"\n", true, &tx).unwrap();
        assert!(matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)));
        queue_stdin_chunk(&mut state, b"b\n", true, &tx).unwrap();
        assert_eq!(rx.try_recv().unwrap(), b"b\r".to_vec());
        queue_stdin_chunk(&mut state, b"raw\n\r\n", false, &tx).unwrap();
        assert_eq!(rx.try_recv().unwrap(), b"raw\n\r\n".to_vec());
        // The actual EOF path still sends exactly one empty sentinel.
        tx.send(Vec::new()).unwrap();
        assert!(rx.try_recv().unwrap().is_empty());
    }

    /// The reader honors its flag: raw/piped input passes LF and CR through
    /// exactly, and clears any stale split-CRLF state.
    #[test]
    fn raw_and_piped_input_passes_through_unchanged() {
        use super::{CookedNewlines, normalize_stdin_chunk};
        let mut state = CookedNewlines::default();
        assert_eq!(
            normalize_stdin_chunk(&mut state, b"a\nb\r\nc\rd", false),
            b"a\nb\r\nc\rd".to_vec()
        );

        // A cooked chunk ends in CR, then the terminal goes raw: the raw LF
        // must pass, not be consumed as the second half of a cooked CRLF.
        let mut state = CookedNewlines::default();
        assert_eq!(normalize_stdin_chunk(&mut state, b"x\r", true), b"x\r".to_vec());
        assert_eq!(normalize_stdin_chunk(&mut state, b"\ny", false), b"\ny".to_vec());
        // And the cleared state cannot eat a cooked LF if normalization resumes.
        assert_eq!(normalize_stdin_chunk(&mut state, b"\nz", true), b"\rz".to_vec());
    }

    /// The whole typeahead scrub (mouse removal + newline restoration), as the
    /// client uses it before entering raw mode. This is the regression cell: with
    /// the LF left in place, a Windows shell never ran the first typed command.
    #[test]
    fn typeahead_scrub_restores_enter_and_strips_mouse() {
        use super::scrub_typeahead;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        tx.send(b"echo one\n".to_vec()).unwrap();
        tx.send(b"echo two\r\n".to_vec()).unwrap();
        tx.send(b"\x1b[<35;84;9M".to_vec()).unwrap();
        let mut pending = None;
        scrub_typeahead(&mut rx, &mut pending);
        assert_eq!(pending.as_deref(), Some(b"echo one\recho two\r".as_slice()));
    }
}
