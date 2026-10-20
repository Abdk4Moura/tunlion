//! The receive loop's event pump: next event, with the rejoin countdown.
//!
//! Moved from `cli/src/runtime_support.rs`. The terminal countdown is the
//! injected `Presentation`; the loop and its bound are library policy.

use crate::conn::Conn;
use crate::host::Tone;
use crate::present::Presentation;
use anyhow::{anyhow, bail, Result};
use filament_transport::net::Ev;
use std::time::Duration;
use tokio::sync::mpsc;

/// Receive the next event; while a rejoin window is open, tick every second
/// so the window can expire AND the countdown stays visible (C22, "45s"
/// frozen on screen reads as broken).
pub async fn next_ev(
    rx: &mut mpsc::UnboundedReceiver<Ev>,
    conn: &Conn,
    suppress_countdown: bool,
) -> Result<Option<Ev>> {
    if let Some(since) = conn.rejoin.waiting_rejoin {
        if since.elapsed() > conn.rejoin.rejoin_window {
            conn.present.clear_sticky();
            // "unreachable" is what the exit-code taxonomy classifies on (6):
            // the peer is gone, which is not the same failure as a refusal or a
            // network outage on this side, and a script must be able to tell.
            bail!(
                "peer unreachable: disconnected and did not come back within {}s (partial state kept for resume)",
                conn.rejoin.rejoin_window.as_secs()
            );
        }
        if !suppress_countdown {
            let left = conn
                .rejoin
                .rejoin_window
                .saturating_sub(since.elapsed())
                .as_secs();
            conn.present.sticky(&format!(
                "  {} {}",
                conn.present.pulse(),
                conn.log.paint(
                    Tone::Dim,
                    &format!("holding the line, {left}s for them to come back (Ctrl-C to stop)")
                )
            ));
        }
        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    } else {
        // C30: never block indefinitely, a 2s tick lets the convergent
        // session repair lost emits even when no events arrive.
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(anyhow!("signaling channel closed")),
            Err(_) => Ok(None), // tick
        }
    }
}

/// Redial signaling until the network is back, with a bounded exponential
/// backoff. The daemon waits instead of exiting; a one-shot receive still
/// fails fast by calling `net::connect_signaling` directly.
pub async fn connect_signaling_patiently(
    context: &filament_transport::TransportContext,
    server: &str,
    tx: mpsc::UnboundedSender<Ev>,
    log: &dyn crate::host::LogSink,
) -> Result<filament_signal::Client> {
    if !(server.starts_with("http://") || server.starts_with("https://")) {
        bail!("--server must be an http:// or https:// URL, got '{server}'");
    }
    let mut attempt: u32 = 0;
    loop {
        match filament_transport::net::connect_signaling(context, server, tx.clone()).await {
            Ok(client) => {
                if attempt > 0 {
                    log.say(&format!(
                        "  {} network is back; connected to {server}",
                        log.paint(crate::host::Tone::Ok, log.glyph_ok())
                    ));
                }
                return Ok(client);
            }
            Err(e) => {
                let wait = signaling_backoff(attempt);
                if attempt == 0 {
                    log.say(&format!(
                        "  {} waiting for network: can't reach the tunlion server yet; retrying (ctrl-c to stop)",
                        log.paint(crate::host::Tone::Warn, "!")
                    ));
                }
                log.debug(&format!(
                    "  signaling connect failed ({e:#}); retry in {}s",
                    wait.as_secs()
                ));
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// Backoff before the next patient redial: 1,2,4,8,16 then 30 s.
pub fn signaling_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(match attempt {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        _ => 30,
    })
}
