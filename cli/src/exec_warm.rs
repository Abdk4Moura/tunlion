//! `tunlion exec` warm reuse: ride a daemon's already-established link.
//!
//! The daemon side is `filament_peerloop::l2::warm_exec`. This half makes ONE
//! attempt against the local control socket:
//!
//!   * `NoPath` - no daemon, no warm link, or the daemon explicitly said
//!     `no warm path`. The caller falls back to the normal cold establish.
//!   * `Done`   - the daemon carried the exec (or answered definitively). This
//!     is returned even for a network error AFTER the open left the daemon, so
//!     `exec_cmd` cannot replay a non-idempotent command on a fresh link.
//!
//! Only an explicit `no warm path` reply (or a failure to connect/write the
//! request) falls back. A refusal from the peer is definitive: the peer already
//! answered, and a cold retry would only turn a clear refusal into a timeout.
//!
//! Stdout, stderr and the exit status are byte-exact: the binary framing in
//! `filament_peerloop::exec_frame` carries them separately, and nothing in this
//! path writes status text to stdout.

/// The outcome of the one warm attempt.
pub(crate) enum WarmExec {
    /// Safe to cold-establish: no daemon, no warm link, or an explicit miss.
    NoPath,
    /// The daemon owns the result now. Errors here are final; never replay.
    Done(anyhow::Result<i32>),
}

#[cfg(unix)]
mod imp {
    use super::WarmExec;
    use crate::exec_send::{
        ExecOpts, Interrupted, local_output_failed, revoked_mid_session,
        spawn_bounded_stdin_reader, spawn_refusal_code, spawn_refused,
    };
    use anyhow::{Result, bail};
    use filament_peerloop::exec_frame::{
        FRAME_CLOSE, FRAME_EXIT, FRAME_SIGNAL, FRAME_STDERR, FRAME_STDIN, FRAME_STDIN_EOF,
        FRAME_STDOUT, read_frame, write_frame,
    };
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;

    /// Read the one JSON reply line, byte at a time, so the binary frames that
    /// follow are never consumed by the line reader.
    async fn read_line(s: &mut UnixStream, max: usize) -> Result<String> {
        let mut buf = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        loop {
            let n = s.read(&mut byte).await?;
            if n == 0 {
                bail!("the local daemon closed before answering the warm exec request");
            }
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
            if buf.len() > max {
                bail!("the local daemon's warm exec reply is too long");
            }
        }
        Ok(String::from_utf8(buf)?)
    }

    /// Does the RUNNING daemon understand the `exec` op? A stale daemon from
    /// before this feature closes an unknown request without a reply; that must
    /// be a cold fallback, not the "reply lost after the open" failure. One
    /// short local round trip is cheap next to a cold establish.
    async fn supports_warm_exec() -> bool {
        let Ok(mut sock) = UnixStream::connect(crate::ctl::control_sock_path()).await else {
            return false;
        };
        if sock.write_all(b"{\"op\":\"exec-cap\"}\n").await.is_err() || sock.flush().await.is_err()
        {
            return false;
        }
        let Ok(line) =
            tokio::time::timeout(std::time::Duration::from_secs(1), read_line(&mut sock, 256))
                .await
        else {
            return false;
        };
        match line
            .ok()
            .and_then(|l| serde_json::from_str::<Value>(&l).ok())
        {
            Some(v) => v["ok"].as_bool() == Some(true),
            None => false,
        }
    }

    pub(crate) async fn try_exec(
        peer: &str,
        opts: &ExecOpts,
        interrupted: &mut Interrupted,
    ) -> WarmExec {
        if crate::ctl::reuse_disabled() || !supports_warm_exec().await {
            return WarmExec::NoPath;
        }
        let mut sock = match UnixStream::connect(crate::ctl::control_sock_path()).await {
            Ok(s) => s,
            Err(_) => return WarmExec::NoPath,
        };
        let mut req = json!({
            "op": "exec",
            "peer": peer,
            "argv": opts.argv.clone(),
            "tty": opts.tty,
        });
        if let Some(cwd) = &opts.cwd {
            req["cwd"] = json!(cwd.to_string_lossy());
        }
        if !opts.env.is_empty() {
            req["env"] = json!(
                opts.env
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
            );
        }
        let mut line = match serde_json::to_vec(&req) {
            Ok(v) => v,
            Err(e) => return WarmExec::Done(Err(e.into())),
        };
        line.push(b'\n');
        // The daemon's request line is bounded at 1 MiB. A bigger command line
        // never reached it, so falling back to the cold path is safe.
        if line.len() > 1024 * 1024 {
            return WarmExec::NoPath;
        }
        // Before the request is fully flushed, a failure means the daemon never
        // saw a complete request: no exec can have started, so cold is safe.
        if sock.write_all(&line).await.is_err() || sock.flush().await.is_err() {
            return WarmExec::NoPath;
        }
        // AFTER the flush the daemon may already have sent `exec-open`. A lost
        // reply is now a failure, never a fallback.
        let reply = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            read_line(&mut sock, 8192),
        )
        .await
        {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return WarmExec::Done(Err(e)),
            Err(_) => {
                return WarmExec::Done(Err(anyhow::anyhow!(
                    "the local daemon did not answer the warm exec request in 15s"
                )));
            }
        };
        let v: Value = match serde_json::from_str(&reply) {
            Ok(v) => v,
            Err(e) => return WarmExec::Done(Err(e.into())),
        };
        if v["ok"].as_bool() == Some(true) {
            crate::ui::debug(&format!(
                "exec: riding the local daemon's warm link to '{peer}'"
            ));
            return WarmExec::Done(serve(sock, peer, opts, interrupted).await);
        }
        let err = v["err"].as_str().unwrap_or("rejected").to_string();
        if err.starts_with("no warm path") {
            return WarmExec::NoPath;
        }
        if let Some(reason) = err.strip_prefix("refused: ") {
            if let Some(code) = spawn_refusal_code(reason) {
                return WarmExec::Done(Ok(spawn_refused(
                    peer,
                    opts.argv.first().map(String::as_str).unwrap_or("?"),
                    reason,
                    code,
                )));
            }
            return WarmExec::Done(Err(anyhow::anyhow!("{reason}")));
        }
        let msg = err
            .strip_prefix("failed: ")
            .unwrap_or(err.as_str())
            .to_string();
        WarmExec::Done(Err(anyhow::anyhow!("{msg}")))
    }

    async fn serve(
        sock: UnixStream,
        peer: &str,
        opts: &ExecOpts,
        interrupted: &mut Interrupted,
    ) -> Result<i32> {
        let (read_half, mut write_half) = sock.into_split();
        let (tx, mut frames) = mpsc::channel::<(u8, Vec<u8>)>(32);
        let reader = tokio::spawn(async move {
            let mut r = read_half;
            loop {
                match read_frame(&mut r).await {
                    Ok(Some(f)) => {
                        if tx.send(f).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        });
        let mut stdin_rx = spawn_bounded_stdin_reader();
        let mut stdin_done = false;
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let result = loop {
            tokio::select! {
                frame = frames.recv() => match frame {
                    Some((FRAME_STDOUT, bytes)) => {
                        if let Err(e) = stdout.write_all(&bytes).await {
                            break local_output_failed(e);
                        }
                        if let Err(e) = stdout.flush().await {
                            break local_output_failed(e);
                        }
                    }
                    Some((FRAME_STDERR, bytes)) => {
                        if let Err(e) = stderr.write_all(&bytes).await {
                            break local_output_failed(e);
                        }
                        if let Err(e) = stderr.flush().await {
                            break local_output_failed(e);
                        }
                    }
                    Some((FRAME_EXIT, payload)) => {
                        if payload.len() != 4 {
                            break Err(anyhow::anyhow!(
                                "the daemon sent a malformed warm exec exit status"
                            ));
                        }
                        let code = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let _ = stdout.flush().await;
                        let _ = stderr.flush().await;
                        break Ok(code);
                    }
                    Some((FRAME_CLOSE, payload)) => {
                        match serde_json::from_slice::<Value>(&payload) {
                            Ok(v) => break close_result(peer, opts, &v),
                            Err(e) => break Err(e.into()),
                        }
                    }
                    Some(_) => {}
                    None => break Err(anyhow::anyhow!(
                        "the local daemon closed the warm exec channel without an exit status"
                    )),
                },
                chunk = stdin_rx.recv(), if !stdin_done => match chunk {
                    Some(c) if c.is_empty() => {
                        if write_frame(&mut write_half, FRAME_STDIN_EOF, &[]).await.is_err() {
                            break Err(anyhow::anyhow!(
                                "the warm exec control connection closed while sending stdin"
                            ));
                        }
                        stdin_done = true;
                    }
                    Some(c) => {
                        let mut failed = false;
                        for chunk in c.chunks(16 * 1024) {
                            if write_frame(&mut write_half, FRAME_STDIN, chunk).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            break Err(anyhow::anyhow!(
                                "the warm exec control connection closed while sending stdin"
                            ));
                        }
                    }
                    None => stdin_done = true,
                },
                (sig, code) = interrupted.as_mut() => {
                    // The daemon forwards this to the remote tree and then ends
                    // the session; this side exits exactly as the cold path does.
                    let _ = write_frame(&mut write_half, FRAME_SIGNAL, sig.wire().as_bytes()).await;
                    break Ok(code);
                }
            }
        };
        drop(write_half);
        reader.abort();
        result
    }

    fn close_result(peer: &str, opts: &ExecOpts, v: &Value) -> Result<i32> {
        if v["type"].as_str() == Some("link-revoked") {
            bail!("{}", revoked_mid_session(peer, v));
        }
        if v["type"].as_str() == Some("warm-error") {
            bail!("{}", v["err"].as_str().unwrap_or("warm exec failed"));
        }
        let err = v["err"].as_str().unwrap_or("closed");
        if let Some(code) = spawn_refusal_code(err) {
            return Ok(spawn_refused(
                peer,
                opts.argv.first().map(String::as_str).unwrap_or("?"),
                err,
                code,
            ));
        }
        let (code, _) = crate::refusal::from_frame(v, "err");
        if code.is_some() {
            bail!("{}", crate::refusal::explain_frame("exec", peer, v, "err"));
        }
        bail!("'{peer}' closed the exec stream: {err}")
    }
}

#[cfg(not(unix))]
mod imp {
    use super::WarmExec;
    use crate::exec_send::{ExecOpts, Interrupted};

    /// Windows has no control socket yet, so there is never a warm path: the
    /// caller uses the cold establish. This is a NAMED absence, not a silent
    /// success and not a pretend named-pipe implementation.
    pub(crate) async fn try_exec(
        _peer: &str,
        _opts: &ExecOpts,
        _interrupted: &mut Interrupted,
    ) -> WarmExec {
        WarmExec::NoPath
    }
}

pub(crate) use imp::try_exec;

#[cfg(test)]
mod tests {
    use super::WarmExec;

    /// The one decision that keeps exec from replaying: only an explicit miss
    /// may fall back. A daemon that already sent `exec-open` reports `Done`,
    /// even when that result is an error, and the caller must not cold-retry.
    #[test]
    fn only_no_path_falls_back() {
        fn is_fallback(w: &WarmExec) -> bool {
            matches!(w, WarmExec::NoPath)
        }
        assert!(is_fallback(&WarmExec::NoPath));
        assert!(!is_fallback(&WarmExec::Done(Err(anyhow::anyhow!(
            "the warm link died during exec"
        )))));
        assert!(!is_fallback(&WarmExec::Done(Ok(7))));
    }
}
