// Mesh-native mount protocol: a small SFTP-like request/response over the
// authenticated mesh stream. No sshd, no sshfs — the peer serves its local
// filesystem through this protocol, the client presents it via FUSE (or a
// future WinFsp/ProjFS adapter).
//
// Wire format: each message is a JSON line (ends with '\n') sent as one data
// frame over the L2 stream. Requests go client→server, responses server→client.
// The message id ties each response to its request; the protocol is pipelined:
// a client may issue multiple requests without waiting for the prior response.
//
// Stream lifecycle:
//   1. Initiator sends `mount-open` control message with `sid` + `root` path
//   2. Acceptor spawns a `serve_mount` task on that sid
//   3. The initiator sends MountRequest messages, the acceptor replies with
//      MountResponse messages
//   4. On stream close (l2-close or transport death), the server tears down

use anyhow::Result;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use crate::net::Transport;

/// Inbound frame from the mux stream: Some(data) = bytes, None = EOF.
pub type PipeItem = Option<Bytes>;

// ---------------------------------------------------------- message types --

#[derive(Debug, Serialize, Deserialize)]
pub struct MountRequest {
    pub id: u64,
    /// True when this request carries a binary data suffix after the JSON line.
    /// Makes framing unambiguous for pipelined and future transport paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<bool>,
    #[serde(flatten)]
    pub op: MountOp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "args")]
pub enum MountOp {
    GetAttr { path: String },
    ReadLink { path: String },
    Open { path: String, flags: i32 },
    Read { fh: u64, offset: u64, size: u32 },
    Write { fh: u64, offset: u64, size: u32 },  // data is binary suffix of the frame
    ReadDir { fh: u64, offset: i64 },
    Release { fh: u64 },
    Create { path: String, mode: u32, flags: i32 },
    Unlink { path: String },
    MkDir { path: String, mode: u32 },
    RmDir { path: String },
    Rename { from: String, to: String },
    Truncate { path: String, size: u64 },
    FSync { fh: u64, datasync: bool },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MountResponse {
    pub id: u64,
    /// True when this response carries a binary data suffix after the JSON line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<bool>,
    #[serde(flatten)]
    pub result: MountResult,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "value")]
pub enum MountResult {
    #[serde(rename = "ok")]
    Ok(Value),
    #[serde(rename = "err")]
    Err(MountError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MountError {
    pub code: i32,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    pub ino: u64,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    #[serde(default)]
    pub nlink: u32,
    #[serde(default)]
    pub blocks: u64,
    #[serde(default = "default_blksize")]
    pub blksize: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FileKind>,
}

fn default_blksize() -> u32 { 4096 }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub stat: FileStat,
}

/// Protocol version this implementation speaks. The server advertises it in
/// `mount-open-ack`; the client negotiates via `mount-cap-ack`. Both sides can
/// speak v1 (base64 data) or v2 (binary data frames), selected at mount-open time.
pub const PROTOCOL_VERSION: u32 = 2;

/// Default max read/write payload size advertised by the server. Kept well
/// below net::MAX_DC_PAYLOAD (60 KiB) so a single mount frame fits through
/// WebRTC/relay DataChannels, not just direct-quic.
pub const DEFAULT_MOUNT_MAX_SIZE: u32 = 32 * 1024;

/// Server capabilities advertised in `mount-open-ack`, per spec rule 5: the two
/// ends exchange what they can represent before the first file op, so the client
/// knows up front what to escape and what to refuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountCaps {
    pub protocol_version: u32,
    pub case_sensitive: bool,
    pub max_path_len: u32,
    pub max_component_len: u32,
    #[serde(default)]
    pub forbidden_bytes: Vec<u8>,
    #[serde(default)]
    pub forbidden_names: Vec<String>,
    pub supports_symlinks: bool,
    pub supports_hardlinks: bool,
    pub supports_fifo: bool,
    #[serde(default)]
    pub metadata_fields: Vec<String>,
    #[serde(default)]
    pub max_read_size: u32,
    #[serde(default)]
    pub max_write_size: u32,
}

impl Default for MountCaps {
    /// Sensible defaults for a v1-only, unix-like server that does not advertise
    /// any specific capabilities. v2+ servers MUST provide real values from the
    /// OS at mount-open time.
    fn default() -> Self {
        MountCaps {
            protocol_version: 1,
            case_sensitive: true,
            max_path_len: 4096,
            max_component_len: 255,
            forbidden_bytes: vec![0x00],
            forbidden_names: Vec::new(),
            supports_symlinks: false,
            supports_hardlinks: false,
            supports_fifo: false,
            metadata_fields: vec!["mtime".into(), "mode".into(), "uid".into(), "gid".into()],
            max_read_size: 0,
            max_write_size: 0,
        }
    }
}

/// Build the server's real mount capabilities from the OS and filesystem at
/// `root`. Called by the acceptor at mount-open time so every link gets honest
/// caps rather than compile-time defaults.
pub fn mount_caps_for_root(root: &std::path::Path) -> MountCaps {
    MountCaps {
        protocol_version: PROTOCOL_VERSION,
        case_sensitive: cfg!(unix) && !cfg!(target_os = "macos"),
        max_path_len: max_path_len_for(root),
        max_component_len: 255,
        forbidden_bytes: forbidden_bytes_for_os(),
        forbidden_names: forbidden_names_for_os(),
        supports_symlinks: cfg!(unix),
        supports_hardlinks: cfg!(unix),
        supports_fifo: cfg!(target_os = "linux"),
        metadata_fields: vec![
            "mtime".into(), "mode".into(), "uid".into(), "gid".into(),
        ],
        max_read_size: DEFAULT_MOUNT_MAX_SIZE,
        max_write_size: DEFAULT_MOUNT_MAX_SIZE,
    }
}

/// Parse server capabilities from a mount-open-ack value and enforce a minimum
/// supported protocol version. Fails loud on missing, unparseable, or
/// too-old caps so the client never silently falls back to a broken path.
pub fn parse_mount_caps(value: serde_json::Value) -> Result<MountCaps> {
    if value.is_null() {
        anyhow::bail!("peer did not advertise mount capabilities; upgrade filament");
    }
    let caps: MountCaps = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("peer mount capabilities unreadable ({e}); upgrade filament"))?;
    if caps.protocol_version < 2 {
        anyhow::bail!(
            "peer mount protocol version {} unsupported (need v2); upgrade filament",
            caps.protocol_version
        );
    }
    Ok(caps)
}

#[cfg(unix)]
fn max_path_len_for(_root: &std::path::Path) -> u32 {
    // PATH_MAX is 4096 on Linux, 1024 on macOS. statvfs has f_namemax.
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        let p = std::ffi::CString::new(".").unwrap_or_default();
        if libc::statvfs(p.as_ptr(), &mut buf) == 0 && buf.f_namemax > 0 {
            buf.f_namemax.min(4096) as u32
        } else {
            4096
        }
    }
}

#[cfg(not(unix))]
fn max_path_len_for(_root: &std::path::Path) -> u32 { 260 }

#[cfg(unix)]
fn forbidden_bytes_for_os() -> Vec<u8> { vec![0x00, 0x2f] }  // NUL + /

#[cfg(not(unix))]
fn forbidden_bytes_for_os() -> Vec<u8> {
    // Windows: NUL + control chars + < > : " | ? *
    let mut v: Vec<u8> = (0..=31).collect();
    v.extend_from_slice(&[0x3c, 0x3e, 0x3a, 0x22, 0x7c, 0x3f, 0x2a]);
    v
}

fn forbidden_names_for_os() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let reserved = ["CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"];
        reserved.iter().map(|s| s.to_string()).collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

// ----------------------------------------------------- binary frame helpers --
// v2+ frames: JSON line + '\n' + optional 4-byte LE u32 length prefix + raw bytes.
// Non-data ops omit the binary suffix. This preserves v1 JSON-only framing for ops
// like GetAttr/ReadDir while letting Read/Write carry raw payloads.

/// Encode a frame: header bytes (JSON line + '\n'), optionally followed by a
/// 4-byte LE u32 length prefix and raw data. Returns the complete frame payload.
pub fn encode_frame(header: &[u8], data: Option<&[u8]>) -> Vec<u8> {
    if let Some(d) = data {
        let mut out = Vec::with_capacity(header.len() + 4 + d.len());
        out.extend_from_slice(header);
        let len = d.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(d);
        out
    } else {
        header.to_vec()
    }
}

/// Decode a frame, returning the JSON header, optional binary payload, and the
/// number of bytes consumed from the input. Returns `None` when a complete frame
/// is not yet available (e.g. partial binary suffix).
pub fn decode_frame_with_len(frame: &[u8]) -> Option<(&[u8], Option<&[u8]>, usize)> {
    let nl = frame.iter().position(|&b| b == b'\n')?;
    let header_end = nl;
    if frame.len() >= nl + 1 + 4 {
        let len = u32::from_le_bytes([frame[nl + 1], frame[nl + 2], frame[nl + 3], frame[nl + 4]]) as usize;
        let frame_end = nl + 1 + 4 + len;
        if frame.len() >= frame_end {
            let data = &frame[nl + 1 + 4..frame_end];
            return Some((&frame[..header_end], Some(data), frame_end));
        }
        // Partial binary suffix: wait for more data.
        return None;
    }
    // No binary suffix; frame ends at the newline.
    Some((&frame[..header_end], None, nl + 1))
}

/// Decode a frame: returns the JSON-line header (up to the first '\n') and an
/// optional binary payload (4-byte LE length prefix + data following it).
/// Returns `None` for the payload if the frame ends at the JSON line terminator.
/// Prefer `decode_frame_with_len` for bounded buffer parsing.
pub fn decode_frame(frame: &[u8]) -> (&[u8], Option<&[u8]>) {
    match decode_frame_with_len(frame) {
        Some((hdr, data, _)) => (hdr, data),
        None => (&[], None),
    }
}

// ----------------------------------------------------------- protocol transport --

/// A client-end handle for talking to the mount server over the mux stream.
pub struct MountClient {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    buf: Vec<u8>,
    next_id: u64,
    /// True when the server advertised protocol_version >= 2 in mount-open-ack.
    /// Read/Write payloads use binary frames instead of base64.
    pub binary_frames: bool,
    /// Server capabilities advertised at mount-open time. Used by the FUSE
    /// adapters to honor transport limits and OS-specific restrictions.
    pub caps: MountCaps,
}

impl MountClient {
    /// Create a MountClient that bridges over an L2 mux stream.
    /// Spawns a background task to pump outgoing frames to the transport.
    pub fn from_mux(
        transport: Arc<dyn Transport>,
        sid: u32,
        mut rx: mpsc::Receiver<PipeItem>,
    ) -> Self {
        let (tx_bytes, mut rx_bytes) = mpsc::unbounded_channel::<Vec<u8>>();
        // Bridge: MountClient sends bytes → transport.send_frame
        tokio::spawn(async move {
            let t = transport.clone();
            while let Some(payload) = rx_bytes.recv().await {
                if t.send_frame(sid, 0, &payload).await.is_err() {
                    break;
                }
            }
        });
        // Bridge: transport frames → MountClient receives bytes
        let (rx_out, mut rx_in) = mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    Some(data) => {
                        if rx_out.send(data).is_err() { break; }
                    }
                    None => break, // EOF
                }
            }
        });
        MountClient { tx: tx_bytes, rx: rx_in, buf: Vec::new(), next_id: 1, binary_frames: false, caps: MountCaps::default() }
    }

    /// Create a MountClient with binary frame support enabled (protocol v2+).
    /// `caps` are the server's advertised MountCaps.
    pub fn from_mux_v2(
        transport: Arc<dyn Transport>,
        sid: u32,
        rx: mpsc::Receiver<PipeItem>,
        caps: MountCaps,
    ) -> Self {
        let mut c = Self::from_mux(transport, sid, rx);
        c.binary_frames = true;
        // A zero max-size cap means "unspecified"; fall back to the safe default.
        let mut caps = caps;
        if caps.max_read_size == 0 { caps.max_read_size = DEFAULT_MOUNT_MAX_SIZE; }
        if caps.max_write_size == 0 { caps.max_write_size = DEFAULT_MOUNT_MAX_SIZE; }
        c.caps = caps;
        c
    }

    /// Send a request and await its response (async).
    pub async fn call(&mut self, op: MountOp) -> Result<MountResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = MountRequest { id, bin: None, op };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        self.tx.send(payload).ok();
        loop {
            if self.binary_frames {
                let parsed = if let Some((hdr, _bin, consumed)) = decode_frame_with_len(&self.buf) {
                    let resp: MountResponse = serde_json::from_slice(hdr)?;
                    Some((resp, consumed))
                } else {
                    None
                };
                if let Some((resp, consumed)) = parsed {
                    let frame_bytes: Vec<u8> = self.buf.drain(..consumed).collect();
                    if resp.id == id { return Ok(resp); }
                    self.buf.splice(0..0, frame_bytes);
                    continue;
                }
            } else {
                if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                    let line = self.buf.drain(..nl).collect::<Vec<_>>();
                    if !self.buf.is_empty() && self.buf[0] == b'\n' {
                        self.buf.remove(0);
                    }
                    let resp: MountResponse = serde_json::from_slice(&line)?;
                    if resp.id == id {
                        return Ok(resp);
                    }
                    self.buf.splice(0..0, line);
                    continue;
                }
            }
            match self.rx.recv().await {
                Some(bytes) => self.buf.extend_from_slice(&bytes),
                None => anyhow::bail!("mount channel closed"),
            }
        }
    }

    /// Synchronous call using `blocking_recv`, for FUSE callbacks that run
    /// outside a tokio runtime context. Same protocol but blocks the thread.
    pub fn call_sync(&mut self, op: MountOp) -> Result<MountResponse> {
        self.call_sync_inner(op, None).map(|(r, _)| r)
    }

    /// Like `call_sync` but attaches a binary data payload to the request frame
    /// (v2 Read/Write) and collects any binary payload from the response.
    /// `data` is only meaningful for Write ops; for Read/other ops pass `None`.
    pub fn call_sync_binary(
        &mut self,
        op: MountOp,
        data: Option<&[u8]>,
    ) -> Result<(MountResponse, Option<Bytes>)> {
        self.call_sync_inner(op, data)
    }

    fn call_sync_inner(
        &mut self,
        op: MountOp,
        data: Option<&[u8]>,
    ) -> Result<(MountResponse, Option<Bytes>)> {
        let id = self.next_id;
        self.next_id += 1;
        let has_data = data.is_some();
        let req = MountRequest { id, bin: if has_data { Some(true) } else { None }, op };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        if self.binary_frames {
            if let Some(d) = data {
                payload.extend_from_slice(&(d.len() as u32).to_le_bytes());
                payload.extend_from_slice(d);
            }
        }
        self.tx.send(payload).ok();
        loop {
            if self.binary_frames {
                let parsed = if let Some((hdr, bin, consumed)) = decode_frame_with_len(&self.buf) {
                    let resp: MountResponse = serde_json::from_slice(hdr)?;
                    let bin_data = bin.map(|b| Bytes::copy_from_slice(b));
                    Some((resp, bin_data, consumed))
                } else {
                    None
                };
                if let Some((resp, bin_data, consumed)) = parsed {
                    let frame_bytes: Vec<u8> = self.buf.drain(..consumed).collect();
                    if resp.id == id { return Ok((resp, bin_data)); }
                    self.buf.splice(0..0, frame_bytes);
                    continue;
                }
            } else {
                if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = self.buf.drain(..nl).collect();
                    if !self.buf.is_empty() && self.buf[0] == b'\n' { self.buf.remove(0); }
                    let resp: MountResponse = serde_json::from_slice(&line)?;
                    if resp.id == id { return Ok((resp, None)); }
                    self.buf.splice(0..0, line);
                    continue;
                }
            }
            match self.rx.blocking_recv() {
                Some(bytes) => self.buf.extend_from_slice(&bytes),
                None => anyhow::bail!("mount channel closed"),
            }
        }
    }
}

// POSIX errno values, used for error codes in the protocol.
const EACCES: i32 = 13;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const EEXIST: i32 = 17;
const ENOTEMPTY: i32 = 39;
const EROFS: i32 = 30;

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
// Access-mode mask. The read/write intent lives in the low two bits, NOT in a
// set bit: O_RDONLY is 0, so `flags & O_RDONLY` is always 0 and can never be
// tested for. Mask with O_ACCMODE and compare the result to the three modes.
const O_ACCMODE: i32 = 3;

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine;

/// Encode an OS-native path to a base64 string for the wire protocol.
/// On unix this preserves raw bytes (non-UTF-8 safe); on Windows it
/// falls back to lossy UTF-8 (Windows paths are UTF-16, so this is safe).
pub fn path_encode(path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return base64::engine::general_purpose::STANDARD.encode(path.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    {
        base64::engine::general_purpose::STANDARD.encode(path.to_string_lossy().as_bytes())
    }
}

/// Decode a base64 wire path back to a native PathBuf.
/// On unix, raw bytes → OsString → PathBuf (preserving non-UTF-8).
/// On Windows, raw bytes → UTF-8 string → PathBuf.
pub fn path_decode(encoded: &str) -> Result<PathBuf, MountError> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)
        .map_err(|e| MountError { code: EINVAL, msg: format!("bad base64 path: {e}") })?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        return Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)));
    }
    #[cfg(not(unix))]
    {
        let s = String::from_utf8_lossy(&bytes).into_owned();
        Ok(PathBuf::from(s))
    }
}

/// Serve the mount protocol on a stream. Spawned by the acceptor daemon
/// when a `mount-open` control message arrives. Reads requests from `rx`
/// (mux inbound pipe) and writes responses via `transport.send_frame`.
///
/// `proto_version` is the negotiated protocol version (advertised in
/// mount-open-ack). v2+ uses binary data frames for Read/Write; v1 uses
/// base64-inside-JSON (legacy, no server speaks this by default).
pub fn spawn_mount_server(
    root: PathBuf,
    transport: Arc<dyn Transport>,
    sid: u32,
    mut rx: mpsc::Receiver<PipeItem>,
    proto_version: u32,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut open_files: HashMap<u64, (std::fs::File, PathBuf)> = HashMap::new();
        let mut next_fh: u64 = 1;
        let mut buf = Vec::new();
        let v2 = proto_version >= 2;

        loop {
            // In v2, each frame is: JSON line + '\n' + optional (4-byte LE len + data).
            // The JSON line's `\n` delimiter marks the header boundary; if `buf` has
            // enough bytes after it for a length prefix, the frame includes the binary
            // suffix. Drain the complete frame atomically so a raw `\n` byte inside
            // payload data never triggers a false header boundary.
            while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                let frame_end = if v2 && buf.len() >= nl + 1 + 4 {
                    let len = u32::from_le_bytes([buf[nl + 1], buf[nl + 2], buf[nl + 3], buf[nl + 4]]) as usize;
                    if buf.len() >= nl + 1 + 4 + len {
                        nl + 1 + 4 + len
                    } else {
                        // Partial frame: wait for more data.
                        break;
                    }
                } else {
                    nl + 1
                };
                let frame: Vec<u8> = buf.drain(..frame_end).collect();
                let (hdr, bin) = if v2 {
                    let (h, b) = decode_frame(&frame);
                    (h, b.map(|d| d.to_vec()))
                } else {
                    let end = frame.iter().position(|&b| b == b'\n').unwrap_or(frame.len());
                    (&frame[..end], None)
                };
                let req: MountRequest = match serde_json::from_slice(hdr) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = MountResponse { id: 0, bin: None, result: MountResult::Err(MountError { code: EINVAL, msg: format!("parse: {e}") }) };
                        let mut p = serde_json::to_vec(&resp).unwrap_or_default();
                        p.push(b'\n');
                        let _ = transport.send_frame(sid, 0, &p).await;
                        continue;
                    }
                };
                let (resp_body, resp_data) =
                    handle_mount_request(&root, &mut open_files, &mut next_fh, &req, bin.as_deref(), v2).await;
                let mut resp_json = serde_json::to_vec(&resp_body).unwrap_or_default();
                resp_json.push(b'\n');
                let payload = if v2 {
                    encode_frame(&resp_json, resp_data.as_deref())
                } else {
                    resp_json
                };
                if transport.send_frame(sid, 0, &payload).await.is_err() { return; }
            }

            // Read next frame
            match rx.recv().await {
                Some(Some(data)) => buf.extend_from_slice(&data),
                Some(None) => break, // EOF
                None => break,       // channel closed
            }
        }
        drop(open_files);
    })
}

/// Handle one mount request. Returns the JSON response body and (for Read ops
/// under v2+) a binary data payload the server will attach as a frame suffix.
/// `write_data` is the binary payload decoded from a v2 Write request frame;
/// `v2` controls whether Read data is returned through the binary suffix.
async fn handle_mount_request(
    root: &PathBuf,
    open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>,
    next_fh: &mut u64,
    req: &MountRequest,
    write_data: Option<&[u8]>,
    v2: bool,
) -> (MountResponse, Option<Vec<u8>>) {
    let result = match &req.op {
        MountOp::GetAttr { path } => (do_getattr(root, path), None),
        MountOp::Open { path, flags } => (do_open(root, path, *flags, open_files, next_fh), None),
        MountOp::Read { fh, offset, size } => {
            match do_read(open_files, *fh, *offset, *size) {
                Ok((v, bytes)) => (Ok(v), if v2 { Some(bytes) } else { None }),
                Err(e) => (Err(e), None),
            }
        }
        MountOp::Write { fh, offset, size: _ } => {
            let r = if let Some(data) = write_data {
                do_write(open_files, *fh, *offset, data)
            } else {
                Err(MountError { code: EINVAL, msg: "Write missing data payload".into() })
            };
            (r, None)
        }
        MountOp::ReadDir { fh, offset } => (do_readdir(root, open_files, *fh, *offset), None),
        MountOp::Release { fh } => { open_files.remove(fh); (Ok(Value::Null), None) }
        MountOp::Create { path, mode, flags } => (do_create(root, path, *mode, *flags, open_files, next_fh), None),
        MountOp::Unlink { path } => (do_unlink(root, path), None),
        MountOp::MkDir { path, mode } => (do_mkdir(root, path, *mode), None),
        MountOp::RmDir { path } => (do_rmdir(root, path), None),
        MountOp::Rename { from, to } => (do_rename(root, from, to), None),
        MountOp::Truncate { path, size } => (do_truncate(root, path, *size), None),
        MountOp::FSync { fh, .. } => (do_fsync(open_files, *fh), None),
        MountOp::ReadLink { path } => (do_readlink(root, path), None),
    };

    let (res, data) = result;
    match res {
        Ok(v) => (
            MountResponse {
                id: req.id,
                bin: if data.is_some() { Some(true) } else { None },
                result: MountResult::Ok(v),
            },
            data,
        ),
        Err(e) => (MountResponse { id: req.id, bin: None, result: MountResult::Err(e) }, None),
    }
}

// ---------------------------------------------------------- handler implementations --

fn resolve(root: &PathBuf, encoded_path: &str) -> Result<PathBuf, MountError> {
    let path = path_decode(encoded_path)?;
    let mut resolved = root.clone();
    for comp in path.iter() {
        if comp == ".." {
            resolved.pop();
        } else if comp != "." {
            resolved.push(comp);
        }
    }
    // Path traversal guard
    if !resolved.starts_with(root) {
        return Err(MountError { code: EACCES, msg: "path escapes root".into() });
    }
    Ok(resolved)
}

fn do_getattr(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let meta = std::fs::symlink_metadata(&resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    let st = file_stat(&resolved, &meta);
    Ok(serde_json::to_value(&st).unwrap_or_default())
}

fn do_open(root: &PathBuf, path: &str, flags: i32, open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>, next_fh: &mut u64) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let file = open_file(&resolved, flags).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    let fh = *next_fh;
    *next_fh += 1;
    open_files.insert(fh, (file, resolved));
    Ok(serde_json::json!({ "fh": fh }))
}

fn do_create(root: &PathBuf, path: &str, mode: u32, flags: i32, open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>, next_fh: &mut u64) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    // create implies write; also open for read unless the caller asked write-only.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read((flags & O_ACCMODE) != O_WRONLY)
        .open(&resolved)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&resolved, std::fs::Permissions::from_mode(mode));
    }
    let fh = *next_fh;
    *next_fh += 1;
    open_files.insert(fh, (file, resolved));
    Ok(serde_json::json!({ "fh": fh }))
}

fn do_read(open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, offset: u64, size: u32) -> Result<(Value, Vec<u8>), MountError> {
    use std::io::{Read, Seek, SeekFrom};
    let (file, _) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    let mut file = file.try_clone().map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    file.seek(SeekFrom::Start(offset)).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    let mut buf = vec![0u8; size as usize];
    let n = file.read(&mut buf).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    buf.truncate(n);
    Ok((serde_json::json!({ "n": n }), buf))
}

fn do_write(open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, offset: u64, data: &[u8]) -> Result<Value, MountError> {
    use std::io::{Seek, SeekFrom, Write};
    let (file, _) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    let mut file = file.try_clone().map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    file.seek(SeekFrom::Start(offset)).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    let n = file.write(data).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    Ok(serde_json::json!({ "size": n }))
}

fn do_readdir(root: &PathBuf, open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, _offset: i64) -> Result<Value, MountError> {
    let (_, dir_path) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    // For directories, the "file" handle is the dir itself; we open with read_dir
    let entries: Vec<DirEntry> = match std::fs::read_dir(dir_path) {
        Ok(iter) => {
            iter.filter_map(|e| e.ok())
                .map(|e| {
                    let name_os = e.file_name();
                    let name = path_encode(std::path::Path::new(&name_os));
                    let meta = e.metadata().ok();
                    let stat = match (&e.path(), meta) {
                        (p, Some(m)) => file_stat(p, &m),
                        (_, None) => FileStat { ino: 0, size: 0, mode: 0, uid: 0, gid: 0, mtime: 0, nlink: 0, blocks: 0, blksize: 4096, kind: None },
                    };
                    DirEntry { name, stat }
                })
                .collect()
        }
        Err(e) => {
            return Err(MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() });
        }
    };
    Ok(serde_json::to_value(entries).unwrap_or_default())
}

fn do_unlink(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    std::fs::remove_file(&resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_mkdir(root: &PathBuf, path: &str, mode: u32) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    std::fs::create_dir(&resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&resolved, std::fs::Permissions::from_mode(mode));
    }
    Ok(Value::Null)
}

fn do_rmdir(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    std::fs::remove_dir(&resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_rename(root: &PathBuf, from: &str, to: &str) -> Result<Value, MountError> {
    let from_resolved = resolve(root, from)?;
    let to_resolved = resolve(root, to)?;
    std::fs::rename(&from_resolved, &to_resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_truncate(root: &PathBuf, path: &str, size: u64) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let file = std::fs::OpenOptions::new().write(true).open(&resolved)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    file.set_len(size).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_fsync(open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64) -> Result<Value, MountError> {
    let (file, _) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    file.sync_all().map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_readlink(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let target = std::fs::read_link(&resolved).map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(serde_json::Value::String(path_encode(&target)))
}

// ---- helpers ----

fn file_stat(path: &std::path::Path, meta: &std::fs::Metadata) -> FileStat {
    let kind = if meta.is_dir() { FileKind::Dir } else if meta.file_type().is_symlink() { FileKind::Symlink } else { FileKind::File };
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH).duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    FileStat {
        ino: file_ino(path),
        size: meta.len(),
        mode: mode_from_meta(meta),
        uid: cfg_unix_uid(),
        gid: cfg_unix_gid(),
        mtime,
        nlink: 1,
        blocks: meta.len() / 512,
        blksize: 4096,
        kind: Some(kind),
    }
}

fn open_file(path: &std::path::Path, flags: i32) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    let accmode = flags & O_ACCMODE;
    let rd = accmode == O_RDONLY || accmode == O_RDWR;
    let wr = accmode == O_WRONLY || accmode == O_RDWR;
    OpenOptions::new()
        .read(rd)
        .write(wr)
        .open(path)
}

fn file_ino(path: &std::path::Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).map(|m| m.ino()).unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf()).hash(&mut h);
        h.finish()
    }
}

fn mode_from_meta(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        if meta.is_dir() { 0o40755 } else { 0o100644 }
    }
}

fn cfg_unix_uid() -> u32 {
    #[cfg(unix)] { unsafe { libc::getuid() } }
    #[cfg(not(unix))] { 0 }
}

fn cfg_unix_gid() -> u32 {
    #[cfg(unix)] { unsafe { libc::getgid() } }
    #[cfg(not(unix))] { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn path_roundtrip_preserves_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        // A filename with a lone 0xFF byte is valid on Linux but invalid UTF-8.
        let raw = std::ffi::OsStr::from_bytes(b"caf\xffe.bin");
        let p = std::path::Path::new(raw);
        let enc = path_encode(p);
        let dec = path_decode(&enc).expect("decode");
        assert_eq!(dec.as_os_str().as_bytes(), b"caf\xffe.bin");
    }

    #[test]
    fn accmode_masks_low_two_bits() {
        // O_RDONLY is 0, so a naive `flags & O_RDONLY` is always 0. The mask is
        // the only correct test. O_CREAT (0x40) etc. must not disturb the mode.
        let rdonly = O_RDONLY | 0o100 /* O_CREAT */;
        let wronly = O_WRONLY | 0o2000 /* O_APPEND */;
        let rdwr = O_RDWR;
        assert_eq!(rdonly & O_ACCMODE, O_RDONLY);
        assert_eq!(wronly & O_ACCMODE, O_WRONLY);
        assert_eq!(rdwr & O_ACCMODE, O_RDWR);
    }

    #[test]
    fn open_file_read_only_flag_opens_for_read() {
        // Regression for the accmode bug: a plain read-only open (flags == 0)
        // must build an OpenOptions that can actually read.
        let dir = std::env::temp_dir().join(format!("fil-mount-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("hello.txt");
        std::fs::write(&f, b"hi").unwrap();
        let mut file = open_file(&f, O_RDONLY).expect("open ro");
        use std::io::Read;
        let mut s = String::new();
        file.read_to_string(&mut s).expect("read");
        assert_eq!(s, "hi");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_blocks_path_traversal() {
        let root = std::path::PathBuf::from("/srv/share");
        let enc = path_encode(std::path::Path::new("../../etc/passwd"));
        let err = resolve(&root, &enc).unwrap_err();
        assert_eq!(err.code, EACCES);
    }

    // -------------------------------------------------- binary frame round-trip

    #[test]
    fn binary_frame_roundtrip_no_data() {
        let header = b"{\"id\":1}\n";
        let frame = encode_frame(header, None);
        let (hdr, data) = decode_frame(&frame);
        assert_eq!(hdr, b"{\"id\":1}"); // decode_frame strips newline
        assert!(data.is_none());
    }

    #[test]
    fn binary_frame_roundtrip_with_data() {
        let header = b"{\"id\":1}\n";
        let payload = b"hello binary world";
        let frame = encode_frame(header, Some(payload));
        let (hdr, data) = decode_frame(&frame);
        assert_eq!(hdr, b"{\"id\":1}");
        assert_eq!(data.unwrap(), payload);
    }

    #[test]
    fn binary_frame_roundtrip_empty_data() {
        let header = b"{\"id\":1}\n";
        let frame = encode_frame(header, Some(b""));
        let (hdr, data) = decode_frame(&frame);
        assert_eq!(hdr, b"{\"id\":1}");
        assert_eq!(data.unwrap(), b"");
    }

    #[test]
    fn binary_frame_roundtrip_4kb() {
        let header = b"{\"id\":1}\n";
        let payload = vec![0xAAu8; 4096];
        let frame = encode_frame(header, Some(&payload));
        let (hdr, data) = decode_frame(&frame);
        assert_eq!(hdr, b"{\"id\":1}");
        assert_eq!(data.unwrap(), &payload[..]);
        assert_eq!(data.unwrap().len(), 4096);
    }

    #[test]
    fn binary_frame_roundtrip_1mb() {
        let header = b"{\"id\":1}\n";
        let payload = vec![0xBBu8; 1_048_576];
        let frame = encode_frame(header, Some(&payload));
        let (hdr, data) = decode_frame(&frame);
        assert_eq!(hdr, b"{\"id\":1}");
        assert_eq!(data.unwrap(), &payload[..]);
        assert_eq!(data.unwrap().len(), 1_048_576);
    }

    #[test]
    fn decode_frame_without_binary_suffix_returns_none() {
        let frame = b"{\"id\":1}\n";
        let (hdr, data) = decode_frame(frame);
        assert_eq!(hdr, b"{\"id\":1}");
        assert!(data.is_none());
    }

    #[test]
    fn decode_frame_with_truncated_length_returns_none() {
        let mut frame = b"{\"id\":1}\n".to_vec();
        frame.extend_from_slice(&4096u32.to_le_bytes());
        frame.extend_from_slice(&[0u8; 2]);
        let (hdr, data) = decode_frame(&frame);
        assert!(data.is_none());
    }

    #[test]
    fn encode_frame_preserves_binary_byte_exactness() {
        let header = b"{\"r\":1}\n";
        let all_bytes: Vec<u8> = (0..=255).collect();
        let frame = encode_frame(header, Some(&all_bytes));
        let (_, data) = decode_frame(&frame);
        assert_eq!(data.unwrap(), &all_bytes[..]);
    }

    // ------------------------------------------------- MountCaps + version

    #[test]
    fn mount_caps_serialize_roundtrip() {
        let caps = MountCaps {
            protocol_version: 2,
            case_sensitive: true,
            max_path_len: 4096,
            max_component_len: 255,
            forbidden_bytes: vec![0x00, 0x2f],
            forbidden_names: vec!["CON".into(), "PRN".into()],
            supports_symlinks: true,
            supports_hardlinks: false,
            supports_fifo: false,
            metadata_fields: vec!["mtime".into(), "mode".into()],
            max_read_size: 65536,
            max_write_size: 65536,
        };
        let json = serde_json::to_value(&caps).unwrap();
        let back: MountCaps = serde_json::from_value(json).unwrap();
        assert_eq!(back.protocol_version, 2);
        assert!(back.case_sensitive);
        assert_eq!(back.forbidden_bytes, vec![0x00, 0x2f]);
    }

    #[test]
    fn mount_caps_default_is_v1() {
        let caps = MountCaps::default();
        assert_eq!(caps.protocol_version, 1);
        assert!(!caps.supports_symlinks);
    }

    #[test]
    fn protocol_version_is_two() {
        assert_eq!(PROTOCOL_VERSION, 2);
    }

    #[test]
    fn mount_caps_for_root_has_version() {
        let caps = mount_caps_for_root(&std::path::PathBuf::from("/tmp"));
        assert_eq!(caps.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn parse_mount_caps_rejects_null() {
        let err = parse_mount_caps(serde_json::Value::Null).unwrap_err().to_string();
        assert!(err.contains("did not advertise"));
    }

    #[test]
    fn parse_mount_caps_rejects_v1() {
        let json = serde_json::json!({
            "protocol_version": 1,
            "case_sensitive": true,
            "max_path_len": 4096,
            "max_component_len": 255,
            "supports_symlinks": true,
            "supports_hardlinks": false,
            "supports_fifo": false
        });
        let err = parse_mount_caps(json).unwrap_err().to_string();
        assert!(err.contains("version 1 unsupported"));
    }

    #[test]
    fn parse_mount_caps_rejects_unparseable() {
        let json = serde_json::json!({ "protocol_version": "not-a-number", "case_sensitive": true });
        let err = parse_mount_caps(json).unwrap_err().to_string();
        assert!(err.contains("unreadable"));
    }

    #[test]
    fn parse_mount_caps_accepts_v2() {
        let json = serde_json::json!({
            "protocol_version": 2,
            "case_sensitive": true,
            "max_path_len": 4096,
            "max_component_len": 255,
            "supports_symlinks": true,
            "supports_hardlinks": false,
            "supports_fifo": false
        });
        let caps = parse_mount_caps(json).unwrap();
        assert_eq!(caps.protocol_version, 2);
    }

    #[test]
    fn mount_caps_default_max_sizes_are_zero() {
        let caps = MountCaps::default();
        assert_eq!(caps.max_read_size, 0);
        assert_eq!(caps.max_write_size, 0);
    }

    #[test]
    fn mount_caps_for_root_advertises_safe_max_size() {
        let caps = mount_caps_for_root(&std::path::PathBuf::from("/tmp"));
        assert!(caps.max_read_size > 0);
        assert!(caps.max_write_size > 0);
        assert!(caps.max_read_size <= 60 * 1024);
        assert!(caps.max_write_size <= 60 * 1024);
    }

    #[test]
    fn binary_frame_header_includes_bin_discriminator() {
        let req = MountRequest {
            id: 1,
            bin: Some(true),
            op: MountOp::Write { fh: 7, offset: 0, size: 5 },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"bin\":true"));
    }

    #[test]
    fn binary_frame_header_omits_bin_when_no_data() {
        let req = MountRequest {
            id: 1,
            bin: None,
            op: MountOp::Read { fh: 7, offset: 0, size: 5 },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("bin"));
    }

    #[test]
    fn response_header_includes_bin_discriminator() {
        let resp = MountResponse {
            id: 1,
            bin: Some(true),
            result: MountResult::Ok(serde_json::json!({ "n": 5 })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"bin\":true"));
    }
}
