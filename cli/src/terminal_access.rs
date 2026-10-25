//! Recipient-side interactive terminal for one accepted temporary agreement.
//!
//! The terminal is a real PTY on the host, reached over the agreement's own
//! accepted revision, proven peer and Mux. This module owns only the local
//! UI/byte bridge: it sends the existing `access-open{kind:"pty"}` vocabulary,
//! forwards raw terminal input, writes terminal output, and forwards size
//! changes as the existing `pty-resize` control. No standing shell admission,
//! no daemon connection, and no resume/reattach are involved.
use anyhow::{Result, anyhow, bail};
use filament_peerloop::access::{AgreementSnapshot, AgreementState};
use filament_peerloop::l2::{Mux, OpenOutcome, PipeItem};
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

/// Ctrl-] leaves the terminal locally. It is not sent to the remote shell.
const DETACH: u8 = 0x1d;

enum StdinItem {
    Bytes(Vec<u8>),
    Detach,
}

pub(crate) struct TerminalJob {
    mux: Arc<Mux>,
    sid: u32,
    generation: u64,
    ack: Option<tokio::sync::oneshot::Receiver<OpenOutcome>>,
    pipe: Option<mpsc::Receiver<PipeItem>>,
    input: Option<std::sync::mpsc::Receiver<StdinItem>>,
    stdin: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    reply: Option<std::sync::mpsc::SyncSender<std::result::Result<(), String>>>,
    last_size: (u16, u16),
    raw: bool,
    active: bool,
    detached: bool,
    finished: bool,
}

impl TerminalJob {
    /// Register the terminal stream and send the scoped open. The ack arrives
    /// through the existing agreement control loop, never a second transport.
    pub(crate) async fn begin(mux: Arc<Mux>, snapshot: &AgreementSnapshot) -> Result<Self> {
        if snapshot.state != AgreementState::Active
            || snapshot.accepted_revision != Some(snapshot.revision) {
            bail!("the accepted temporary revision is not active");
        }
        if !snapshot.spec.shell { bail!("this temporary scope has no shell"); }
        let size = terminal_size();
        let term = std::env::var("TERM")
            .ok()
            .filter(|term| !term.is_empty() && term.len() <= 64 && term.bytes().all(|b| b.is_ascii_graphic()))
            .unwrap_or_else(|| "xterm-256color".into());
        let sid = mux.alloc_sid();
        let (pipe, generation) = mux.register_access_stream(sid).await
            .ok_or_else(|| anyhow!("terminal stream capacity reached"))?;
        let ack = mux.arm_open_ack(sid).await;
        let frame = json!({"type":"access-open","v":1,"id":snapshot.id,
            "revision":snapshot.revision,"sid":sid,"kind":"pty",
            "cols":size.0,"rows":size.1,"term":term});
        if let Err(error) = mux.transport().send_control(&frame).await {
            mux.drop_stream_if(sid, generation).await;
            return Err(anyhow!("terminal open could not be sent: {error}"));
        }
        Ok(Self {
            mux, sid, generation, ack: Some(ack), pipe: Some(pipe), input: None,
            stdin: None, stop: Arc::new(AtomicBool::new(false)), reply: None,
            last_size: size, raw: false, active: false, detached: false, finished: false,
        })
    }

    pub(crate) fn set_reply(&mut self, reply: std::sync::mpsc::SyncSender<std::result::Result<(), String>>) {
        self.reply = Some(reply);
    }

    pub(crate) fn sid(&self) -> u32 { self.sid }

    /// Service the terminal without blocking the agreement/signaling loop.
    /// Returns `Some(outcome)` once the attachment is over; the caller drops
    /// the job, which restores the local terminal and releases the stream.
    pub(crate) async fn poll(&mut self) -> Option<std::result::Result<(), String>> {
        if !self.active {
            let outcome = match self.ack.as_mut() {
                Some(ack) => match ack.try_recv() {
                    Ok(OpenOutcome::Opened(_)) => None,
                    Ok(OpenOutcome::Refused(reason)) => Some(Err(format!("terminal refused: {}", crate::access_ui::terminal_label(&reason)))),
                    Ok(OpenOutcome::ClosedWithoutAck) => Some(Err("terminal closed before activation".into())),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => return None,
                    Err(tokio::sync::oneshot::error::TryRecvError::Closed) => Some(Err("terminal activation channel closed".into())),
                },
                None => return None,
            };
            if let Some(outcome) = outcome { self.finish(outcome.clone()); return Some(outcome); }
            self.ack = None;
            if let Err(error) = self.start() {
                self.finish(Err(error.clone()));
                return Some(Err(error));
            }
        }
        let pipe_outcome = {
            let Some(pipe) = self.pipe.as_mut() else { return Some(Ok(())); };
            let mut outcome = None;
            loop {
                match pipe.try_recv() {
                    Ok(Some(bytes)) => {
                        let mut out = std::io::stdout();
                        if out.write_all(&bytes).and_then(|_| out.flush()).is_err() {
                            outcome = Some(Err("terminal output could not be written".into()));
                            break;
                        }
                    }
                    Ok(None) => { outcome = Some(Ok(())); break; }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => { outcome = Some(Ok(())); break; }
                }
            }
            outcome
        };
        if let Some(outcome) = pipe_outcome { self.finish(outcome.clone()); return Some(outcome); }
        let input_outcome = {
            let Some(input) = self.input.as_ref() else { return None; };
            let mut outcome = None;
            loop {
                match input.try_recv() {
                    Ok(StdinItem::Bytes(bytes)) => {
                        if let Err(error) = self.mux.transport().send_frame(self.sid, 0, &bytes).await {
                            outcome = Some(Err(format!("terminal input could not be sent: {error}")));
                            break;
                        }
                    }
                    Ok(StdinItem::Detach) => {
                        self.detached = true;
                        outcome = Some(Ok(()));
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => { outcome = Some(Ok(())); break; }
                }
            }
            outcome
        };
        if let Some(outcome) = input_outcome { self.finish(outcome.clone()); return Some(outcome); }
        let size = terminal_size();
        if size != self.last_size {
            self.last_size = size;
            let _ = self.mux.transport().send_control(&json!({
                "type":"pty-resize","sid":self.sid,"cols":size.0,"rows":size.1,
            })).await;
        }
        if self.mux.stream_generation(self.sid).await.is_none() {
            self.finish(Ok(()));
            return Some(Ok(()));
        }
        None
    }

    fn start(&mut self) -> std::result::Result<(), String> {
        crossterm::terminal::enable_raw_mode().map_err(|error| format!("terminal raw mode unavailable: {error}"))?;
        self.raw = true;
        let mut out = std::io::stdout();
        let _ = write!(out, "\r\n  Shared terminal · host accepted revision · Ctrl-] detaches\r\n");
        let _ = out.flush();
        let (handle, input) = spawn_stdin(self.stop.clone());
        self.stdin = Some(handle);
        self.input = Some(input);
        self.active = true;
        Ok(())
    }

    fn finish(&mut self, outcome: std::result::Result<(), String>) {
        if self.finished { return; }
        self.finished = true;
        self.stop.store(true, Ordering::Release);
        if self.raw {
            let _ = crossterm::terminal::disable_raw_mode();
            self.raw = false;
        }
        if let Some(handle) = self.stdin.take() { let _ = handle.join(); }
        if self.active || self.ack.is_some() {
            self.mux_drop();
        }
        self.input = None;
        self.pipe = None;
        self.ack = None;
        match &outcome {
            Ok(()) if self.detached => crate::ui::say("  Shared terminal detached here; the host session was closed."),
            Ok(()) => crate::ui::say("  Shared terminal ended; the host session is closed."),
            Err(error) => crate::ui::say(&format!("  Shared terminal closed: {}", crate::access_ui::terminal_label(error))),
        }
        if let Some(reply) = self.reply.take() { let _ = reply.send(outcome); }
    }

    fn mux_drop(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return; };
        let mux = self.mux.clone();
        let sid = self.sid;
        let generation = self.generation;
        runtime.spawn(async move {
            mux.drop_stream_if(sid, generation).await;
            let _ = mux.transport().send_control(&json!({"type":"l2-close","sid":sid})).await;
        });
    }
}

impl Drop for TerminalJob {
    fn drop(&mut self) {
        self.finish(Err("temporary access ended".into()));
    }
}

fn terminal_size() -> (u16, u16) {
    crossterm::terminal::size().unwrap_or((80, 24))
}

/// Poll stdin with a bounded timeout so it can stop when the terminal ends.
/// `libc` keeps this to the same Unix-only path the agreement PTY serving uses;
/// no Windows shell/terminal support is claimed by this adapter.
#[cfg(unix)]
fn spawn_stdin(stop: Arc<AtomicBool>) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<StdinItem>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut fd = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        let mut buffer = [0u8; 1024];
        while !stop.load(Ordering::Acquire) {
            let ready = unsafe { libc::poll(&mut fd, 1, 50) };
            if ready <= 0 { continue; }
            let count = unsafe { libc::read(0, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count <= 0 { break; }
            let bytes = &buffer[..count as usize];
            if let Some(position) = bytes.iter().position(|byte| *byte == DETACH) {
                if position > 0 && tx.send(StdinItem::Bytes(bytes[..position].to_vec())).is_err() { return; }
                let _ = tx.send(StdinItem::Detach);
                return;
            }
            if tx.send(StdinItem::Bytes(bytes.to_vec())).is_err() { return; }
        }
    });
    (handle, rx)
}

#[cfg(not(unix))]
fn spawn_stdin(_: Arc<AtomicBool>) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<StdinItem>) {
    (std::thread::spawn(|| {}), std::sync::mpsc::channel().1)
}

/// The terminal menu calls this while a remote session is active. It is kept
/// here so the local timeout/state rules are not scattered through the UI.
pub(crate) const POLL_ACTIVE: Duration = Duration::from_millis(15);
