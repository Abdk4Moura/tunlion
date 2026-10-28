//! One file, streamed over one or more established transports.
//!
//! Moved from `cli/src/send_cmd.rs` so the library sender and the CLI use one
//! chunking/completion implementation. The caller supplies the transport set,
//! the log/presentation seams, and the event sender; this module owns the byte
//! loop, the parallel ranges, `file-end`, and the "bytes sent, not yet acked"
//! state. It does not decide whether a transfer may start.

use crate::host::LogSink;
use crate::present::{Presentation, Progress};
use crate::recv::transfer_truth::resume_line;
use crate::test_hooks;
use anyhow::{Result, anyhow};
use filament_proto as protocol;
use filament_transport::net::{Ev, Transport};
use filament_transfer::Outgoing;
use serde_json::json;
use std::io::SeekFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Optional caller policy checked before each chunk. An ordinary sender passes
/// `None`; the CLI's retained-send adapter uses it to stop a bounded attempt
/// after its claim changes or its timeout cancels the operation.
pub type StreamGuard = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Stream one offered file from `offset`.
#[allow(clippy::too_many_arguments)]
pub async fn stream_one(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    transports: Vec<Arc<dyn Transport>>,
    id: String,
    offset: u64,
    chunk: usize,
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
    log: Arc<dyn LogSink>,
    present: Arc<dyn Presentation>,
) -> Result<()> {
    stream_one_guarded(
        outgoing, transports, id, offset, chunk, active_sid, tx, log, present, None,
    )
    .await
}

/// [`stream_one`] with a per-chunk caller policy hook.
#[allow(clippy::too_many_arguments)]
pub async fn stream_one_guarded(
    outgoing: Arc<tokio::sync::Mutex<Vec<Outgoing>>>,
    transports: Vec<Arc<dyn Transport>>,
    id: String,
    offset: u64,
    chunk: usize,
    active_sid: Option<String>,
    tx: mpsc::UnboundedSender<Ev>,
    log: Arc<dyn LogSink>,
    present: Arc<dyn Presentation>,
    guard: Option<StreamGuard>,
) -> Result<()> {
    let (sid, name, size, path) = {
        let out = outgoing.lock().await;
        let o = out
            .iter()
            .find(|o| o.id == id)
            .ok_or_else(|| anyhow!("unknown transfer {id}"))?;
        (o.sid, o.name.clone(), o.size, o.path.clone())
    };
    if offset > 0 {
        log.say(&resume_line(&name, offset, size));
    }
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let inject_at: Option<u64> = test_hooks::inject_peer_left_at();
    let num = transports.len().max(1);
    let bar: Arc<tokio::sync::Mutex<Box<dyn Progress>>> =
        Arc::new(tokio::sync::Mutex::new(present.progress(&name, size)));
    {
        let mut out = outgoing.lock().await;
        if let Some(o) = out.iter_mut().find(|o| o.id == id) {
            o.stream_started = Some(Instant::now());
            o.stream_bytes = size.saturating_sub(offset);
        }
    }
    let progress = Arc::new(std::sync::atomic::AtomicU64::new(offset));
    let injected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let remaining = size.saturating_sub(offset);
    let per = remaining / num as u64;
    let mut handles = Vec::with_capacity(num);
    for i in 0..num {
        let start = offset + i as u64 * per;
        let end = if i == num - 1 { size } else { start + per };
        if start >= end {
            continue;
        }
        let t = transports[i].clone();
        let path = path.clone();
        let bar = bar.clone();
        let progress = progress.clone();
        let injected = injected.clone();
        let tx = tx.clone();
        let active_sid = active_sid.clone();
        let log = log.clone();
        let guard = guard.clone();
        handles.push(tokio::spawn(async move {
            let trace =
                cfg!(feature = "debug-logs") && std::env::var("TUNLION_TRACE_THROUGHPUT").is_ok();
            use crate::send::source::source_read;
            let mut f = tokio::fs::File::open(&path)
                .await
                .map_err(|e| source_read(&path, e))?;
            f.seek(SeekFrom::Start(start))
                .await
                .map_err(|e| source_read(&path, e))?;
            let mut pos = start;
            let mut buf_a = vec![0u8; chunk];
            let mut buf_b = vec![0u8; chunk];
            let mut using_buf_a = true;
            let mut chunk_idx: u64 = 0;

            let first_want = std::cmp::min(chunk as u64, end - pos) as usize;
            if first_want == 0 {
                return Ok(());
            }
            let t_first_read = if trace {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let mut cur_n = f
                .read(&mut buf_a[..first_want])
                .await
                .map_err(|e| source_read(&path, e))?;
            let _first_read_us = t_first_read.map(|t| t.elapsed().as_micros()).unwrap_or(0);
            if cur_n == 0 {
                return Err(source_read(
                    &path,
                    format!("it ended at {pos} bytes, shorter than offered"),
                ));
            }

            while pos < end {
                if let Some(guard) = &guard {
                    guard()?;
                }
                let stall = test_hooks::transfer_stall_ms();
                if stall > 0 {
                    let units = (cur_n as u64).div_ceil(64 * 1024).max(1);
                    tokio::time::sleep(Duration::from_millis(stall.saturating_mul(units))).await;
                }
                let next_want = std::cmp::min(chunk as u64, end - (pos + cur_n as u64)) as usize;
                let next_read = if next_want > 0 {
                    let mut f2 = tokio::fs::File::open(&path)
                        .await
                        .map_err(|e| source_read(&path, e))?;
                    f2.seek(SeekFrom::Start(pos + cur_n as u64))
                        .await
                        .map_err(|e| source_read(&path, e))?;
                    let alt_buf = if using_buf_a {
                        std::mem::replace(&mut buf_b, vec![0u8; chunk])
                    } else {
                        std::mem::replace(&mut buf_a, vec![0u8; chunk])
                    };
                    let read_path = path.clone();
                    Some(tokio::spawn(async move {
                        let mut buf = alt_buf;
                        let n = f2
                            .read(&mut buf[..next_want])
                            .await
                            .map_err(|e| source_read(&read_path, e))?;
                        Ok::<(Vec<u8>, usize), anyhow::Error>((buf, n))
                    }))
                } else {
                    None
                };

                let cur_buf = if using_buf_a {
                    &buf_a[..cur_n]
                } else {
                    &buf_b[..cur_n]
                };
                let t_send_start = if trace {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                t.send_frame(sid, pos, cur_buf).await?;
                let send_us = t_send_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                pos += cur_n as u64;

                let total = progress.fetch_add(cur_n as u64, std::sync::atomic::Ordering::Relaxed)
                    + cur_n as u64;
                chunk_idx += 1;
                let should_tick = chunk_idx % 8 == 0 || pos >= end;
                let t_tick_start = if trace && should_tick {
                    Some(std::time::Instant::now())
                } else {
                    None
                };
                if should_tick {
                    bar.lock().await.tick(total);
                }
                let tick_us = t_tick_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                // Compiled out unless `debug-logs`: a runtime `trace` check alone
                // still links the format string, and cli-release fails any
                // release binary that carries a `[TRACE ...]` marker.
                #[cfg(not(feature = "debug-logs"))]
                let _ = (trace, send_us, tick_us);
                #[cfg(feature = "debug-logs")]
                if trace && (chunk_idx % 10 == 0 || send_us + tick_us > 5000) {
                    log.debug(&format!(
                        "[TRACE stream_one] chunk={} offset={} len={} send_frame={}us tick={}us",
                        chunk_idx,
                        pos - cur_n as u64,
                        cur_n,
                        send_us,
                        tick_us
                    ));
                }
                if let (Some(at), Some(asid)) = (inject_at, active_sid.as_ref()) {
                    if total >= at && !injected.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        eprintln!(
                            "[test] injecting synthetic peer-left for active sid at {total} bytes"
                        );
                        let _ = tx.send(Ev::PeerLeft(json!({ "id": asid })));
                    }
                }

                match next_read {
                    Some(handle) => match handle.await {
                        Ok(Ok((buf, n))) => {
                            if using_buf_a {
                                buf_b = buf;
                            } else {
                                buf_a = buf;
                            }
                            using_buf_a = !using_buf_a;
                            cur_n = n;
                            if cur_n == 0 {
                                return Err(source_read(
                                    &path,
                                    format!("it ended at {pos} bytes, shorter than offered"),
                                ));
                            }
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(e) => return Err(anyhow!("read-ahead task panicked: {e}")),
                    },
                    None => break,
                }
            }
            t.flush().await?;
            Ok::<(), anyhow::Error>(())
        }));
    }
    for h in handles {
        h.await.map_err(|e| anyhow!("stream task join: {e}"))??;
    }
    transports[0]
        .send_control(&protocol::end_msg(&id, sid))
        .await?;
    for t in &transports {
        t.flush().await?;
    }
    let mut out = outgoing.lock().await;
    if let Some(o) = out.iter_mut().find(|o| o.id == id) {
        o.sent = true;
        if o.full.is_none() {
            o.acked = true;
            o.done = true;
            bar.lock().await.done(o.stream_bytes);
        }
    }
    Ok(())
}
