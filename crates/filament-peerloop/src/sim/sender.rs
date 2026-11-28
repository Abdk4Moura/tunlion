//! A sim file sender: one `tunlion send <file> --to <device>` that rides the
//! sending daemon's held link (`l2::warm_send`), so the receiving daemon runs
//! its production receive path end to end (offer, chunks, `file-end`, the
//! whole-file check, the rename and the `delivery-ack`).
//!
//! It speaks the warm-send control socket exactly as the CLI does: a
//! `send-link` request, then `file-offer`, data frames and `file-end` as
//! frames on the socket, and the receiver's answers back as inbound frames.
//! The file is `bytes` of a fixed pattern, so a run replays.
//!
//! Milestones go to the network trace: `send:start:<from>:<to>`,
//! `send:accepted:<from>:<to>:<offset>`, `send:acked:<from>:<to>` and
//! `send:gaveup:<from>:<to>:<why>`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::control::{Req, ReqKind};
use crate::exec_frame::{read_frame, write_frame};
use crate::l2::warm_send::{encode_data, WS_CONTROL, WS_DATA, WS_INBOUND};
use crate::sim::net::SimNetwork;

/// One send in a sim world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimSend {
    pub at_ms: u64,
    pub from: String,
    pub to: String,
    pub bytes: u64,
}

/// How long the sender waits for each answer (accept, delivery-ack).
const ANSWER_BOUND: Duration = Duration::from_secs(60);
/// The data frame size the client writes to the socket.
const CHUNK: usize = 64 * 1024;

fn payload(bytes: u64) -> Vec<u8> {
    (0..bytes).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

pub async fn send(
    net: Arc<SimNetwork>,
    ctl: Arc<Mutex<Option<mpsc::UnboundedSender<Req>>>>,
    s: SimSend,
    n: usize,
) {
    let tag = format!("{}:{}", s.from, s.to);
    net.record_trace(format!("send:start:{tag}"));
    let why = match run(&net, &ctl, &s, n, &tag).await {
        Ok(()) => {
            net.record_trace(format!("send:acked:{tag}"));
            return;
        }
        Err(why) => why,
    };
    net.record_trace(format!("send:gaveup:{tag}:{why}"));
}

async fn run(
    net: &Arc<SimNetwork>,
    ctl: &Arc<Mutex<Option<mpsc::UnboundedSender<Req>>>>,
    s: &SimSend,
    n: usize,
    tag: &str,
) -> Result<(), String> {
    let data = payload(s.bytes);
    let full: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    let id = format!("sim-send-{n}");
    let name = format!("sim-send-{n}.bin");
    let tx = ctl
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("no-control-socket")?;
    let (client, server) = UnixStream::pair().map_err(|_| "socketpair")?;
    tx.send(Req {
        kind: ReqKind::SendLink { peer: s.to.clone(), ids: vec![id.clone()], any: true },
        sock: server,
    })
    .map_err(|_| "daemon-gone")?;
    let mut r = BufReader::new(client);
    let mut line = String::new();
    match tokio::time::timeout(ANSWER_BOUND, r.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return Err("no-reply".into()),
    }
    let reply: Value = serde_json::from_str(line.trim()).map_err(|_| "bad-reply")?;
    if reply["ok"] != true {
        return Err(format!("refused:{}", reply["error"].as_str().unwrap_or("?").replace(' ', "_")));
    }
    let sid = reply["sid_base"].as_u64().ok_or("no-sid")? as u32;
    // One buffered reader for everything the daemon sends (it may already
    // hold a health frame); writes go to the same socket. All in turn.
    let control = |v: Value| v.to_string().into_bytes();
    let offer = filament_proto::offer_msg(&id, sid, &name, s.bytes, None, Some(&full), false);
    write_frame(r.get_mut(), WS_CONTROL, &control(offer)).await.map_err(|_| "write-offer")?;
    // The receiver's answer to the offer.
    let offset = loop {
        let v = inbound(&mut r).await?;
        match v["type"].as_str() {
            Some("file-accept") => break v["offset"].as_u64().unwrap_or(0),
            Some("file-decline") => return Err("declined".into()),
            Some("delivery-ack") => return Ok(()),
            _ => continue,
        }
    };
    net.record_trace(format!("send:accepted:{tag}:{offset}"));
    let mut at = offset as usize;
    while at < data.len() {
        let end = (at + CHUNK).min(data.len());
        write_frame(r.get_mut(), WS_DATA, &encode_data(sid, at as u64, &data[at..end]))
            .await
            .map_err(|_| "write-data")?;
        at = end;
    }
    let end = json!({ "type": "file-end", "id": id, "sid": sid });
    write_frame(r.get_mut(), WS_CONTROL, &control(end)).await.map_err(|_| "write-end")?;
    loop {
        let v = inbound(&mut r).await?;
        match v["type"].as_str() {
            Some("delivery-ack") => return Ok(()),
            Some("file-decline") => return Err("refused-after-end".into()),
            _ => continue,
        }
    }
}

/// The next frame the receiver sent this send (health frames skipped).
async fn inbound<R: tokio::io::AsyncRead + Unpin>(rd: &mut R) -> Result<Value, String> {
    loop {
        let frame = tokio::time::timeout(ANSWER_BOUND, read_frame(rd))
            .await
            .map_err(|_| "no-answer")?
            .map_err(|_| "read")?;
        let Some((kind, payload)) = frame else {
            return Err("closed".into());
        };
        if kind == WS_INBOUND {
            return serde_json::from_slice(&payload).map_err(|_| "bad-frame".into());
        }
        if kind == crate::l2::warm_send::WS_CLOSE {
            return Err("warm-error".into());
        }
    }
}
