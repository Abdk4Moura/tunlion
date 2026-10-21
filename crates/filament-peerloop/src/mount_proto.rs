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
use tokio::sync::mpsc;
use crate::host::{HostServices, LiveCutCause, LogSink};
use crate::liveness::RevokeRecheck;
use filament_transport::net::Transport;

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
        anyhow::bail!("peer did not advertise mount capabilities; upgrade tunlion");
    }
    let caps: MountCaps = serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("peer mount capabilities unreadable ({e}); upgrade tunlion"))?;
    if caps.protocol_version < 2 {
        anyhow::bail!(
            "peer mount protocol version {} unsupported (need v2); upgrade tunlion",
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
    /// A local, restrictive override. The server still enforces its own grant;
    /// this prevents a read-only user choice from ever emitting a write op.
    read_only: bool,
    /// Runtime handle, captured at construction, so the blocking FUSE thread can
    /// wait on the response channel WITH A DEADLINE (#239). `blocking_recv()`
    /// has no timeout, so a peer that stops answering without closing parked the
    /// call forever.
    rt: tokio::runtime::Handle,
}

/// How long one mount operation waits for its response before giving up.
///
/// #239: there was no timeout anywhere on this path. `mount_proto.rs` contained
/// zero occurrences of the word, and the EIO mapping in `mount_fuse.rs` only
/// fires when the transport RETURNS AN ERROR. A peer that stops answering
/// without closing returns nothing, so the call blocked rather than failing, in
/// uninterruptible `D` state on `request_wait_answer`, where SIGKILL does not
/// land and `fusermount -u` returns EBUSY.
///
/// It needed no attacker: a sleeping laptop, a dropped link or a killed daemon
/// did it. And it took the whole mountpoint, not one call, because `call_data`
/// holds the client mutex across the request.
///
/// The only other timeout in the stack is the FUSE option `daemon_timeout=60`,
/// which is macFUSE and FreeBSD; Linux FUSE does not implement it, so there was
/// no bound at the kernel layer either.
///
/// Generous on purpose: this is a ceiling that turns "forever" into "an error",
/// not a latency target. A slow large read over a relay must not trip it.
const MOUNT_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

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
        let (rx_out, rx_in) = mpsc::unbounded_channel::<Bytes>();
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
        MountClient {
            tx: tx_bytes,
            rx: rx_in,
            buf: Vec::new(),
            next_id: 1,
            binary_frames: false,
            caps: MountCaps::default(),
            read_only: false,
            // Captured here because this constructor runs inside the runtime,
            // while call_sync_inner runs on a blocking FUSE thread where
            // Handle::current() is unavailable.
            rt: tokio::runtime::Handle::current(),
        }
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
        self.refuse_local_write(&op)?;
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
        self.refuse_local_write(&op)?;
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
            // Bounded wait. See MOUNT_CALL_TIMEOUT: an unbounded blocking_recv
            // here is what made a gone-away peer wedge the mountpoint forever.
            // Returning Err lets the existing `Err(_) => Err(EIO)` mapping in
            // mount_fuse.rs do its job, so the kernel finally gets an answer.
            let got = self
                .rt
                .block_on(async { tokio::time::timeout(MOUNT_CALL_TIMEOUT, self.rx.recv()).await });
            match got {
                Ok(Some(bytes)) => self.buf.extend_from_slice(&bytes),
                Ok(None) => anyhow::bail!("mount channel closed"),
                Err(_) => anyhow::bail!(
                    "mount operation timed out after {}s: the peer stopped answering",
                    MOUNT_CALL_TIMEOUT.as_secs()
                ),
            }
        }
    }

    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    fn refuse_local_write(&self, op: &MountOp) -> Result<()> {
        if !self.read_only {
            return Ok(());
        }
        if mount_op_writes(op) {
            anyhow::bail!("read-only mount refused a local write operation");
        }
        Ok(())
    }
}

fn mount_op_writes(op: &MountOp) -> bool {
    match op {
        MountOp::Open { flags, .. } => open_mutates(*flags),
        MountOp::Write { .. }
        | MountOp::Create { .. }
        | MountOp::Unlink { .. }
        | MountOp::MkDir { .. }
        | MountOp::RmDir { .. }
        | MountOp::Rename { .. }
        | MountOp::Truncate { .. } => true,
        _ => false,
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
const EMFILE: i32 = 24;

/// Open handles one mount stream may hold. Each is a real fd in the serving
/// daemon, so an unbounded table lets one peer exhaust the daemon's fd limit
/// (and with it every other link). FUSE releases handles as files close, so a
/// well-behaved client sits far below this.
const MAX_OPEN_FILES_PER_STREAM: usize = 256;

/// Largest JSON header line the server will buffer. A header carries at most
/// two base64 paths (rename) bounded by max_path_len, plus a few numbers.
const MAX_HEADER_LEN: usize = 64 * 1024;

/// Largest binary payload a frame may declare. The server advertises
/// DEFAULT_MOUNT_MAX_SIZE for reads and writes, so anything larger is a
/// protocol violation; refusing it stops a peer from making the server wait
/// on (and buffer toward) a 4 GiB frame.
const MAX_FRAME_DATA_LEN: usize = DEFAULT_MOUNT_MAX_SIZE as usize;

/// True when an Open with these flags would create or modify data: a writable
/// access mode, or O_CREAT/O_TRUNC/O_APPEND/O_TMPFILE even with O_RDONLY.
fn open_mutates(flags: i32) -> bool {
    (flags & O_ACCMODE) != 0 || crate::fs_at::open_flags_modify(flags)
}

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

/// Everything the mount server needs from its caller. The CLI composes it
/// (canonical confined root, shared transport, the mux pipe, the host and the
/// log sink); the library never discovers a share root or reads a config.
pub struct MountServerConfig {
    /// A CANONICAL, confined root. `confine_mount_root` decided it; the server
    /// holds this path, not the peer's requested alias.
    pub root: PathBuf,
    pub transport: Arc<dyn Transport>,
    pub sid: u32,
    pub stream: mpsc::Receiver<PipeItem>,
    /// The negotiated protocol version advertised in `mount-open-ack`.
    /// v2+ uses binary data frames for Read/Write; v1 uses base64-inside-JSON
    /// (legacy, no server speaks this by default).
    pub protocol_version: u32,
    pub read_only: bool,
    /// The admitted peer's device key, for the live-session re-check. `None`
    /// means no resolved identity, which `live_session_cut` treats as
    /// no-opinion, so behaviour is unchanged for those links.
    pub device_pub: Option<[u8; 32]>,
    /// The verdict and cadence source: `live_session_cut` and
    /// `revoke_recheck_interval`.
    pub host: Arc<dyn HostServices>,
    /// Server diagnostics (`debug`/`critical`), never a terminal.
    pub log: Arc<dyn LogSink>,
}

/// Serve the mount protocol on a stream. Spawned by the acceptor when a
/// `mount-open` control message arrives. Reads requests from the mux pipe and
/// writes responses via `transport.send_frame`.
pub fn spawn_mount_server(cfg: MountServerConfig) -> tokio::task::JoinHandle<()> {
    let MountServerConfig {
        root,
        transport,
        sid,
        stream: mut rx,
        protocol_version: proto_version,
        read_only,
        device_pub: idev,
        host,
        log,
    } = cfg;
    tokio::spawn(async move {
        // The recheck mechanism is host-driven: the interval and the verdict
        // are both this host's (`revoke_recheck_interval` / `live_session_cut`).
        let mut recheck = RevokeRecheck::new(host.revoke_recheck_interval());
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
                if nl > MAX_HEADER_LEN {
                    log.debug(&format!("mount: header over {MAX_HEADER_LEN} bytes, closing (sid {sid})"));
                    return;
                }
                let frame_end = if v2 && buf.len() >= nl + 1 + 4 {
                    let len = u32::from_le_bytes([buf[nl + 1], buf[nl + 2], buf[nl + 3], buf[nl + 4]]) as usize;
                    if len > MAX_FRAME_DATA_LEN {
                        // A declared length past anything the server advertised:
                        // the stream is out of sync or hostile. Close rather than
                        // buffer toward it.
                        log.debug(&format!("mount: frame declares {len} bytes (max {MAX_FRAME_DATA_LEN}), closing (sid {sid})"));
                        return;
                    }
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
                // Re-ask the gate, rate-limited by the shared interval helper so a
                // read-heavy mount does not re-read the device store per operation
                // (#235).
                if let Some(cut) = recheck.cut(host.as_ref(), idev.as_ref()) {
                    let cut_reason = cut.reason.clone();
                    log.critical(&format!(
                        "mount: peer {}, closing the live session (sid {sid})",
                        match cut.cause {
                            LiveCutCause::Revoked => "revoked",
                            LiveCutCause::Expired => "access expired",
                        }
                    ));
                    // Answer the in-flight request before tearing the stream
                    // down, and then say so on the control channel. Returning
                    // silently is NOT enough: the client is a FUSE filesystem
                    // blocked in `request_wait_answer`, and a server that just
                    // stops replying leaves every process touching the
                    // mountpoint in uninterruptible D state, unkillable and
                    // not even `fusermount -u`-able. Denial has to arrive as a
                    // denial. EACCES gives the user "Permission denied"; the
                    // l2-close ends the stream so later operations fail fast
                    // instead of waiting for a reply that will never come.
                    let resp = MountResponse {
                        id: req.id,
                        bin: None,
                        result: MountResult::Err(MountError {
                            code: EACCES,
                            msg: cut_reason.clone(),
                        }),
                    };
                    let mut p = serde_json::to_vec(&resp).unwrap_or_default();
                    p.push(b'\n');
                    let payload = if v2 { encode_frame(&p, None) } else { p };
                    let _ = transport.send_frame(sid, 0, &payload).await;
                    let _ = transport
                        .send_control(&serde_json::json!({
                            "type": "l2-close",
                            "sid": sid,
                            "err": cut_reason,
                        }))
                        .await;
                    return;
                }
                let (resp_body, resp_data) =
                    handle_mount_request(&root, &mut open_files, &mut next_fh, &req, bin.as_deref(), v2, read_only).await;
                let mut resp_json = serde_json::to_vec(&resp_body).unwrap_or_default();
                resp_json.push(b'\n');
                let payload = if v2 {
                    encode_frame(&resp_json, resp_data.as_deref())
                } else {
                    resp_json
                };
                if transport.send_frame(sid, 0, &payload).await.is_err() { return; }
            }

            // No complete frame buffered. A header that never ends is the same
            // unbounded wait as an oversized frame, so bound the buffer too.
            if buf.len() > MAX_HEADER_LEN + 1 + 4 + MAX_FRAME_DATA_LEN {
                log.debug(&format!("mount: unterminated frame over the limit, closing (sid {sid})"));
                return;
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
    read_only: bool,
) -> (MountResponse, Option<Vec<u8>>) {
    // Read-only enforcement (fleet-auto-trusted share mounts): reject every
    // mutating op — and any Open that requests write access — with EROFS before
    // it touches the filesystem. This is the SECURITY boundary for the scoped
    // `mount` default: a same-owner fleet device gets a READ-ONLY view of the
    // share root and can never write (write-mount is authority-equivalent, the
    // deliberate tier). The server is the enforcement point, not the advertised
    // caps, so a hostile client cannot regain writes by ignoring the ack.
    if read_only {
        let mutating = match &req.op {
            MountOp::Write { .. }
            | MountOp::Create { .. }
            | MountOp::Unlink { .. }
            | MountOp::MkDir { .. }
            | MountOp::RmDir { .. }
            | MountOp::Rename { .. }
            | MountOp::Truncate { .. } => true,
            // O_RDONLY == 0, so the access mode alone misses O_RDONLY|O_TRUNC
            // (which truncates) and O_CREAT/O_APPEND/O_TMPFILE.
            MountOp::Open { flags, .. } => open_mutates(*flags),
            _ => false,
        };
        if mutating {
            return (
                MountResponse {
                    id: req.id,
                    bin: None,
                    result: MountResult::Err(MountError { code: EROFS, msg: "read-only fleet share".into() }),
                },
                None,
            );
        }
    }
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
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    // resolve() is lexical, so stat-by-path followed a symlinked DIRECTORY in
    // the share out of it (`sub -> /etc` made `sub/shadow` stat-able). Stat the
    // final name relative to a parent dirfd the kernel keeps beneath root, not
    // following the final component (lstat semantics, as before).
    let looked_up = if rel.as_os_str().is_empty() {
        crate::fs_at::stat_root(root)
    } else {
        resolve_parent_beneath(root, rel)
            .and_then(|(parent, name)| crate::fs_at::lstat_at(&parent, &name))
    };
    let meta = looked_up
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(serde_json::to_value(file_stat(&meta)).unwrap_or_default())
}

fn too_many_open(open_files: &HashMap<u64, (std::fs::File, PathBuf)>) -> Result<(), MountError> {
    if open_files.len() >= MAX_OPEN_FILES_PER_STREAM {
        return Err(MountError { code: EMFILE, msg: format!("too many open files on this mount (max {MAX_OPEN_FILES_PER_STREAM})") });
    }
    Ok(())
}

fn do_open(root: &PathBuf, path: &str, flags: i32, open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>, next_fh: &mut u64) -> Result<Value, MountError> {
    too_many_open(open_files)?;
    let resolved = resolve(root, path)?;
    // Use safe_open_beneath to prevent symlink traversal out of the share root
    let rel = match resolved.strip_prefix(root) {
        Ok(r) => r.to_path_buf(),
        Err(_) => return Err(MountError { code: EACCES, msg: "path not beneath root".into() }),
    };
    let file = safe_open_beneath(root, &rel, flags, false, 0o644)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    let fh = *next_fh;
    *next_fh += 1;
    open_files.insert(fh, (file, resolved));
    Ok(serde_json::json!({ "fh": fh }))
}

fn do_create(root: &PathBuf, path: &str, mode: u32, flags: i32, open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>, next_fh: &mut u64) -> Result<Value, MountError> {
    too_many_open(open_files)?;
    let resolved = resolve(root, path)?;
    // Use safe_open_beneath with O_CREAT to prevent symlink traversal
    let rel = match resolved.strip_prefix(root) {
        Ok(r) => r.to_path_buf(),
        Err(_) => return Err(MountError { code: EACCES, msg: "path not beneath root".into() }),
    };
    // O_CREAT|O_EXCL are POSIX (libc) flags; the platform adapter supplies them
    // (on non-Unix, safe_open_beneath's fallback does not consume POSIX creation
    // flags: Windows mounts go through WinFsp, where this is not the create surface).
    let create_flags = crate::fs_at::create_excl_flags(flags);
    let file = safe_open_beneath(root, &rel, create_flags, false, 0o644)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    // The mode is applied through the handle we just created (a path could
    // have been swapped for a symlink since), and only its permission bits:
    // a peer never gets to create a setuid/setgid/sticky file on this host.
    let _ = crate::fs_at::set_mode_via_handle(&file, mode);
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
    // The peer picks `size`; allocating it verbatim was a 4 GiB allocation per
    // request. Clamp to the read size this server advertises.
    let mut buf = vec![0u8; size.min(DEFAULT_MOUNT_MAX_SIZE) as usize];
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

fn do_readdir(_root: &PathBuf, open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, _offset: i64) -> Result<Value, MountError> {
    let (dir, dir_path) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    // List through the HANDLE, which was opened beneath the root. Listing by
    // the stored path re-resolved it, so a directory swapped for a symlink
    // after the open (or reached through one) listed whatever it pointed at.
    let listed = crate::fs_at::read_dir_handle(dir, dir_path)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    let entries: Vec<DirEntry> = listed
        .into_iter()
        .map(|(name_os, meta)| {
            let name = path_encode(std::path::Path::new(&name_os));
            let stat = match meta {
                Some(m) => file_stat(&m),
                None => FileStat { ino: 0, size: 0, mode: 0, uid: 0, gid: 0, mtime: 0, nlink: 0, blocks: 0, blksize: 4096, kind: None },
            };
            DirEntry { name, stat }
        })
        .collect();
    Ok(serde_json::to_value(entries).unwrap_or_default())
}

fn do_unlink(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    // #148: resolve() is lexical and cannot see a symlink, so the parent must
    // be resolved to a dirfd the kernel guarantees is inside root and the
    // mutation applied to the bare name relative to it. The final component is
    // never followed by unlinkat, so containment is purely a parent question.
    let (parent, name) = resolve_parent_beneath(root, rel)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    beneath_unlink(&parent, &name)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_mkdir(root: &PathBuf, path: &str, mode: u32) -> Result<Value, MountError> {
    // Bound the mode at the protocol boundary: a mode is 12 significant bits
    // (0o7777). libc::mode_t is u32 on Linux but u16 on Darwin, so an unmasked
    // peer value would truncate differently per platform. Masking here makes
    // "the same request means the same thing on every platform" (the property
    // this whole change exists for) and lets the syscall boundary cast freely.
    let mode = mode & 0o7777;
    let resolved = resolve(root, path)?;
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    let (parent, name) = resolve_parent_beneath(root, rel)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    beneath_mkdir(&parent, &name, mode)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_rmdir(root: &PathBuf, path: &str) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    let (parent, name) = resolve_parent_beneath(root, rel)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    beneath_rmdir(&parent, &name)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_rename(root: &PathBuf, from: &str, to: &str) -> Result<Value, MountError> {
    let from_resolved = resolve(root, from)?;
    let to_resolved = resolve(root, to)?;
    let from_rel = from_resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "from path not beneath root".into() })?;
    let to_rel = to_resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "to path not beneath root".into() })?;
    // Both sides of the rename must be contained; they may be in different
    // directories, so each parent is resolved beneath root independently and
    // renameat ties the two contained names together.
    let (from_parent, from_name) = resolve_parent_beneath(root, from_rel)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    let (to_parent, to_name) = resolve_parent_beneath(root, to_rel)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    beneath_rename(&from_parent, &from_name, &to_parent, &to_name)
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(Value::Null)
}

fn do_truncate(root: &PathBuf, path: &str, size: u64) -> Result<Value, MountError> {
    let resolved = resolve(root, path)?;
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    // #148: truncate FOLLOWS its target, so unlike the four name-ops it is an
    // open. Reuse safe_open_beneath unchanged: on Linux RESOLVE_BENEATH
    // refuses (EXDEV) any component that resolves outside the root.
    let file = safe_open_beneath(root, rel, O_WRONLY, false, 0o644)
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
    let rel = resolved
        .strip_prefix(root)
        .map_err(|_| MountError { code: EACCES, msg: "path not beneath root".into() })?;
    // Same containment as getattr: read the link named relative to a parent
    // dirfd beneath root, so a symlinked directory cannot redirect it.
    let target = resolve_parent_beneath(root, rel)
        .and_then(|(parent, name)| crate::fs_at::readlink_at(&parent, &name))
        .map_err(|e| MountError { code: e.raw_os_error().unwrap_or(EIO), msg: e.to_string() })?;
    Ok(serde_json::Value::String(path_encode(&target)))
}

// ---- helpers ----

fn file_stat(meta: &crate::fs_at::AtMeta) -> FileStat {
    let kind = if meta.is_dir { FileKind::Dir } else if meta.is_symlink { FileKind::Symlink } else { FileKind::File };
    FileStat {
        ino: meta.ino,
        size: meta.size,
        mode: meta.mode,
        uid: crate::fs_at::current_uid(),
        gid: crate::fs_at::current_gid(),
        mtime: meta.mtime,
        nlink: 1,
        blocks: meta.size / 512,
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

/// Open a file beneath a root directory, refusing to follow symlinks that
/// escape the root. On Linux, uses openat2 with RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS.
/// On other Unix, uses a component-walk with O_NOFOLLOW. On non-Unix, falls back
/// to canonicalize + starts_with (best-effort, no TOCTOU guarantee).
/// Open a file beneath a root directory, refusing to follow symlinks that
/// escape the root. On Linux, uses openat2 with RESOLVE_BENEATH. On other Unix,
/// uses a component-walk with O_NOFOLLOW. On non-Unix, falls back to canonicalize
/// + starts_with (best-effort, no TOCTOU guarantee).
///
/// `deny_symlinks` adds RESOLVE_NO_SYMLINKS on the Linux openat2 arm. The mount
/// path passes false (a symlink beneath the share root is legitimate content);
/// the .part writers pass true (the final component is a file being created and
/// must never be a symlink, so an attacker who can write into the download
/// directory cannot plant a symlink that redirects an incoming transfer within
/// that directory).
#[cfg(unix)]
pub fn safe_open_beneath(root: &std::path::Path, rel_path: &std::path::Path, flags: i32, deny_symlinks: bool, create_mode: u32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    // On Linux 5.6+, use openat2 with RESOLVE_BENEATH for strictest enforcement.
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let root_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(root)?;

        // Values per include/uapi/linux/openat2.h:
        //   RESOLVE_NO_XDEV 0x01, RESOLVE_NO_MAGICLINKS 0x02,
        //   RESOLVE_NO_SYMLINKS 0x04, RESOLVE_BENEATH 0x08.
        // The previous 0x02/0x04 were NO_MAGICLINKS and NO_SYMLINKS, so openat2
        // was never actually scoped beneath the root.
        const RESOLVE_BENEATH: u64 = 0x08;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;

        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (flags as u64) | libc::O_CLOEXEC as u64;
        // mode is meaningful ONLY with O_CREAT/O_TMPFILE; openat2 returns EINVAL if
        // mode is non-zero without one of them. libc::O_TMPFILE includes the
        // O_DIRECTORY bit, so `flags & O_TMPFILE != 0` is true for every directory
        // open; require the FULL O_TMPFILE bit set instead so a plain directory
        // open keeps mode 0. Creates take the caller's `create_mode` (the mount
        // server passes 0o644, the .part writers 0o600 so a partial is
        // owner-only), 0 otherwise (e.g. the O_WRONLY resume open).
        let creating = (flags & libc::O_CREAT) != 0
            || (flags & libc::O_TMPFILE) == libc::O_TMPFILE;
        how.mode = if creating { u64::from(create_mode) } else { 0 };
        // Mount path allows symlinks beneath the root (legitimate content);
        // the .part writers add NO_SYMLINKS so the final component can never
        // be a symlink planted inside the download directory.
        let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if deny_symlinks {
            resolve |= RESOLVE_NO_SYMLINKS;
        }
        how.resolve = resolve;

        // openat2 takes a C string: the pathname must be NUL-terminated. In 2026-07,
        // a bare `.as_ptr()` made the kernel read past the bytes into adjacent memory
        // until a stray NUL, creating a garbage-suffixed name and corrupting transfers
        // intermittently. In 2026-08, routing through `&str` rejected non-UTF-8 names.
        // CString preserves native path bytes, adds the terminator, and rejects an
        // interior NUL (the only invalid byte possible for a real path).
        // An empty rel path is the share root itself; openat2 rejects "" with
        // ENOENT, so normalize it to "." (which resolves to the root fd).
        let rel_os = if rel_path.as_os_str().as_bytes().is_empty() {
            std::ffi::OsStr::new(".")
        } else {
            rel_path.as_os_str()
        };
        let rel_c = std::ffi::CString::new(rel_os.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains an interior NUL byte",
            )
        })?;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd.as_raw_fd(),
                rel_c.as_ptr(),
                &how as *const _,
                std::mem::size_of::<libc::open_how>(),
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };

        // Verify the opened file is NOT a symlink (defense in depth)
        let meta = file.metadata()?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "symlink detected beneath share root",
            ));
        }

        Ok(file)
    }

    // Fallback for non-Linux Unix: component-walk with O_NOFOLLOW
    // Uses openat(dirfd, component, ...) relative to the previous fd,
    // NOT by reconstructed absolute path. Rejects `..` components explicitly.
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let mut current = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;

        let components: Vec<_> = rel_path.components().collect();
        for (i, comp) in components.iter().enumerate() {
            use std::path::Component;
            match comp {
                Component::Normal(name) => {
                    let is_last = i == components.len() - 1;
                    // Unlike the openat2 path, the old `to_str().unwrap_or("")` here
                    // silently substituted an empty name instead of rejecting it.
                    let name_cstr = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "path component contains an interior NUL byte",
                        )
                    })?;

                    // O_NOFOLLOW on every component: this arm always refuses
                    // symlinks, regardless of `deny_symlinks`. That satisfies the
                    // .part requirement outright and is stricter than Linux for the
                    // mount path (a mount symlink resolves as content on Linux but
                    // is refused here). Known, safe divergence; never the reverse.
                    let mut walk_flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
                    if is_last {
                        // Last component: OR in the caller's requested access mode
                        // and creation flags so writes and creates work correctly.
                        walk_flags |= flags & (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL | libc::O_APPEND);
                    } else {
                        walk_flags |= libc::O_DIRECTORY;
                    }

                    let fd = unsafe {
                        libc::openat(current.as_raw_fd(), name_cstr.as_ptr(), walk_flags, create_mode as libc::c_uint)
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    current = unsafe { std::fs::File::from_raw_fd(fd) };
                }
                Component::CurDir => {}
                // REJECT `..` explicitly — RESOLVE_BENEATH does this for free;
                // the hand-rolled walk must do it manually to prevent climbing
                // out of the share root without any symlink involved.
                Component::ParentDir => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "path component '..' escapes root (RESOLVE_BENEATH equivalent)",
                    ));
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "path component escapes root",
                    ));
                }
            }
        }
        Ok(current)
    }
}

// ------------------------------------------------------- Windows "at" layer --
//
// The Unix arms above make every containment decision with a directory fd the
// kernel keeps beneath the root: openat2 RESOLVE_BENEATH on Linux, an
// O_NOFOLLOW component walk elsewhere, and renameat/unlinkat relative to that
// parent. Windows has no `openat`; the equivalent is a pinned chain of
// directory HANDLEs opened with `NtCreateFile(RootDirectory=parent)` plus
// FILE_OPEN_REPARSE_POINT at every step:
//
//   * a component that is a junction/symlink opens as itself and is refused,
//     so a parent swapped for a reparse point cannot redirect the walk;
//   * the final parent HANDLE is pinned for the whole operation, so renaming
//     an ancestor path afterwards cannot move the target;
//   * the staging file is created relative to that pinned parent with
//     FILE_CREATE (exclusive) and FILE_OPEN_REPARSE_POINT, never by path;
//   * finalization renames the OPEN staging HANDLE with
//     SetFileInformationByHandle(FileRenameInfo, RootDirectory=parent), which
//     replaces (never follows) an existing destination entry. A destination
//     symlink/junction is replaced as a name, so its target is untouched.
//
// Windows offers no portable handle-relative rename across different
// directories in one call, and sync's staging name always sits beside its
// target. A caller asking for different parents therefore gets an explicit
// Unsupported error rather than a path-based fallback.
#[cfg(windows)]
mod win_at {
    use std::ffi::{c_void, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::{Component, Path};
    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem as WinFs;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: HANDLE,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    /// `IO_STATUS_BLOCK` is a union of NTSTATUS/PVOID followed by ULONG_PTR.
    #[repr(C)]
    struct IoStatusBlock {
        status: usize,
        information: usize,
    }

    /// Layout matches `FILE_RENAME_INFO` (BOOLEAN/Flags union, HANDLE, ULONG,
    /// WCHAR[]); the name is written into the trailing variable-length space.
    #[repr(C)]
    struct FileRenameInfo {
        replace_if_exists: u8,
        root_directory: HANDLE,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut HANDLE,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut c_void,
            ea_length: u32,
        ) -> i32;
        fn NtSetInformationFile(
            file_handle: HANDLE,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    /// `FILE_RENAME_INFORMATION` (ntddk.h). Win32's
    /// SetFileInformationByHandle(FileRenameInfo) rejects the RootDirectory
    /// form with ERROR_INVALID_PARAMETER, so the handle-relative rename goes
    /// straight to the NT information class the structure was designed for.
    const FILE_RENAME_INFORMATION: u32 = 10;
    /// No FILE_SHARE_DELETE: while a directory/file HANDLE is pinned, another
    /// handle cannot rename, replace or delete it. That is what makes the
    /// retained root/parent/staging handles stable for the whole receive.
    const SHARE_RW: u32 = WinFs::FILE_SHARE_READ | WinFs::FILE_SHARE_WRITE;
    /// `FILE_ADD_FILE`/`FILE_DELETE_CHILD` are what a handle-relative create
    /// and replace need on the pinned parent, not just list/read.
    const DIR_ACCESS: u32 = WinFs::FILE_LIST_DIRECTORY
        | WinFs::FILE_TRAVERSE
        | WinFs::FILE_ADD_FILE
        | WinFs::FILE_DELETE_CHILD
        | WinFs::FILE_READ_ATTRIBUTES
        | WinFs::SYNCHRONIZE;
    const OPEN_REPARSE: u32 = WinFs::FILE_FLAG_OPEN_REPARSE_POINT;
    const ACCESS_READ: u32 = GENERIC_READ | WinFs::FILE_READ_ATTRIBUTES | WinFs::SYNCHRONIZE;
    const ACCESS_READ_WRITE: u32 = GENERIC_READ | GENERIC_WRITE | WinFs::DELETE | WinFs::SYNCHRONIZE;

    fn denied(what: &str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, what)
    }

    /// One path component as NT wants it: case-insensitive, relative to a
    /// pinned parent, with no Win32 name games (ADS colon, trailing dot/space,
    /// reserved DOS device names). `..`/`.`/separators never reach here: sync
    /// paths are validated by `safe_relpath` first, and this repeats the check
    /// because the primitive is also reachable from tests and future callers.
    fn units(name: &OsStr) -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty() || wide.len() > 255 {
            return Err(denied("Windows sync path component is empty or too long"));
        }
        let text = String::from_utf16_lossy(&wide);
        if text == "." || text == ".." {
            return Err(denied("Windows sync path component is not a plain name"));
        }
        if wide.iter().any(|&u| {
            u == u16::from(b':')
                || u == u16::from(b'\\')
                || u == u16::from(b'/')
                || u < 0x20
        }) {
            return Err(denied(
                "Windows sync path component contains a separator, stream colon or control character",
            ));
        }
        if text.ends_with('.') || text.ends_with(' ') {
            return Err(denied(
                "Windows sync path component ends in a dot or space (Win32 name ambiguity)",
            ));
        }
        // DOS device names are special in path-based Win32 APIs. NT relative
        // opens do not apply that mapping, but refusing them keeps a future
        // path-based caller from reintroducing the ambiguity.
        let stem = text.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL"
                | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
                | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
        );
        if reserved {
            return Err(denied(
                "Windows sync path component is a reserved DOS device name",
            ));
        }
        Ok(wide)
    }

    fn attributes(handle: HANDLE) -> io::Result<u32> {
        let mut info: WinFs::BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { WinFs::GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.dwFileAttributes)
    }

    fn file_id(handle: HANDLE) -> io::Result<(u32, u32, u32)> {
        let mut info: WinFs::BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { WinFs::GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow))
    }

    fn nt_open(
        parent: &OwnedHandle,
        name: &[u16],
        disposition: u32,
        access: u32,
        options: u32,
        file_attributes: u32,
    ) -> io::Result<OwnedHandle> {
        let byte_len = (name.len() * 2) as u16;
        let mut unicode = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: name.as_ptr() as *mut u16,
        };
        let mut attrs = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle() as HANDLE,
            object_name: &mut unicode,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut handle: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &mut attrs,
                &mut iosb,
                std::ptr::null_mut(),
                file_attributes,
                SHARE_RW,
                disposition,
                options,
                std::ptr::null_mut(),
                0,
            )
        };
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }

    fn open_root_handle(root: &Path, open_reparse: bool) -> io::Result<OwnedHandle> {
        let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut flags = WinFs::FILE_FLAG_BACKUP_SEMANTICS;
        if open_reparse {
            flags |= OPEN_REPARSE;
        }
        let handle = unsafe {
            WinFs::CreateFileW(
                wide.as_ptr(),
                DIR_ACCESS,
                SHARE_RW,
                std::ptr::null(),
                WinFs::OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        let attrs = attributes(owned.as_raw_handle() as HANDLE)?;
        if attrs & WinFs::FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(denied("Windows sync root is not a directory"));
        }
        if attrs & WinFs::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied(
                "refusing Windows sync root: the admitted root is a junction/symlink (reparse point)",
            ));
        }
        Ok(owned)
    }

    pub(super) fn ensure_stable_id(id: (u32, u32, u32)) -> io::Result<(u32, u32, u32)> {
        if id.0 == 0 || (id.1 == 0 && id.2 == 0) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows sync finalization is not supported on this filesystem: it exposes no stable file identity (volume serial/file index)",
            ));
        }
        Ok(id)
    }

    fn stable_id(handle: HANDLE) -> io::Result<(u32, u32, u32)> {
        ensure_stable_id(file_id(handle)?)
    }

    /// The admitted root, opened ONCE and retained for the whole receive.
    ///
    /// Every later create/open/rename is relative to this HANDLE; the path is
    /// never reopened. It is opened with FILE_OPEN_REPARSE_POINT (so a junction
    /// at the admitted path is refused rather than followed) and without
    /// FILE_SHARE_DELETE (so no other handle can rename or delete the root
    /// while the receive holds it). A second, following open at pin time must
    /// report the same volume serial + file index: a root swapped between
    /// canonicalisation and pinning is refused.
    pub(crate) struct WinRoot {
        handle: OwnedHandle,
        _id: (u32, u32, u32),
    }

    impl WinRoot {
        pub fn open(root: &Path) -> io::Result<Self> {
            let handle = open_root_handle(root, true)?;
            let id = stable_id(handle.as_raw_handle() as HANDLE)?;
            let follow = open_root_handle(root, false)?;
            let follow_id = stable_id(follow.as_raw_handle() as HANDLE)?;
            if follow_id != id {
                return Err(denied(
                    "Windows sync root changed while pinning; refusing the receive",
                ));
            }
            Ok(Self { handle, _id: id })
        }

        /// Walk/recreate `parent_rel` relative to the pinned root. A missing
        /// component is created with FILE_CREATE in the directory HANDLE we
        /// already hold, never by path; a junction/symlink component is
        /// refused. The returned HANDLE is the staging parent, retained
        /// through finalization.
        pub fn ensure_parent(&self, parent_rel: &Path) -> io::Result<OwnedHandle> {
            let mut current = self.handle.try_clone()?;
            for component in parent_rel.components() {
                match component {
                    Component::Normal(name) => {
                        let name = units(name)?;
                        current = open_or_create_dir(&current, &name)?;
                    }
                    Component::CurDir => {}
                    _ => {
                        return Err(denied(
                            "Windows sync path component escapes the pinned root",
                        ))
                    }
                }
            }
            Ok(current)
        }

        pub fn create_staging(&self, parent: &OwnedHandle, name: &OsStr) -> io::Result<File> {
            let name = units(name)?;
            let file = nt_open(
                parent,
                &name,
                FILE_CREATE,
                ACCESS_READ_WRITE,
                FILE_NON_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_ATTRIBUTE_NORMAL,
            )?;
            Ok(File::from(file))
        }

        pub fn open_existing(&self, parent: &OwnedHandle, name: &OsStr) -> io::Result<File> {
            let name = units(name)?;
            let file = nt_open(
                parent,
                &name,
                FILE_OPEN,
                ACCESS_READ,
                FILE_NON_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
                0,
            )?;
            let attrs = attributes(file.as_raw_handle() as HANDLE)?;
            if attrs & WinFs::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(denied(
                    "refusing Windows sync path: the final name is a junction/symlink (reparse point)",
                ));
            }
            if attrs & WinFs::FILE_ATTRIBUTE_DIRECTORY != 0 {
                return Err(denied("Windows sync destination is a directory, not a file"));
            }
            Ok(File::from(file))
        }

        /// Rename the open staging HANDLE into the SAME pinned parent. There is
        /// deliberately no path parameter: the parent cannot be re-resolved.
        pub fn rename_staged(
            &self,
            parent: &OwnedHandle,
            from_name: &OsStr,
            to_name: &OsStr,
            source: &File,
        ) -> io::Result<()> {
            let from = units(from_name)?;
            let to = units(to_name)?;
            let named = nt_open(
                parent,
                &from,
                FILE_OPEN,
                WinFs::FILE_READ_ATTRIBUTES | WinFs::SYNCHRONIZE,
                FILE_NON_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
                0,
            )?;
            let named_id = stable_id(named.as_raw_handle() as HANDLE)?;
            let source_id = stable_id(source.as_raw_handle() as HANDLE)?;
            if named_id != source_id {
                return Err(denied(
                    "staging name no longer identifies this transfer's open file; refusing rename",
                ));
            }
            drop(named);
            rename_handle(parent, &to, source)
        }
    }

    fn check_dir(child: OwnedHandle) -> io::Result<OwnedHandle> {
        let attrs = attributes(child.as_raw_handle() as HANDLE)?;
        if attrs & WinFs::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(denied(
                "refusing Windows sync path: a parent is a junction/symlink (reparse point)",
            ));
        }
        if attrs & WinFs::FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(denied("Windows sync path parent is not a directory"));
        }
        Ok(child)
    }

    fn open_or_create_dir(parent: &OwnedHandle, name: &[u16]) -> io::Result<OwnedHandle> {
        match nt_open(
            parent,
            name,
            FILE_OPEN,
            DIR_ACCESS,
            FILE_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
            0,
        ) {
            Ok(child) => check_dir(child),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match nt_open(
                    parent,
                    name,
                    FILE_CREATE,
                    DIR_ACCESS,
                    FILE_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
                    WinFs::FILE_ATTRIBUTE_DIRECTORY,
                ) {
                    Ok(child) => check_dir(child),
                    Err(create) if create.kind() == io::ErrorKind::AlreadyExists => {
                        let child = nt_open(
                            parent,
                            name,
                            FILE_OPEN,
                            DIR_ACCESS,
                            FILE_DIRECTORY_FILE | OPEN_REPARSE | FILE_SYNCHRONOUS_IO_NONALERT,
                            0,
                        )?;
                        check_dir(child)
                    }
                    Err(create) => Err(create),
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn unsupported(error: io::Error) -> io::Error {
        let code = error.raw_os_error().unwrap_or(0);
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED,
        // ERROR_INVALID_PARAMETER: the filesystem cannot express the
        // handle-relative replace. Everything else keeps its real error.
        if matches!(code, 1 | 17 | 50 | 87) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Windows sync finalization is not supported on this filesystem: {error}"),
            )
        } else {
            error
        }
    }

    fn rename_handle(
        parent: &OwnedHandle,
        to_name: &[u16],
        source: &File,
    ) -> io::Result<()> {
        let name_bytes = to_name.len() * 2;
        let offset = std::mem::offset_of!(FileRenameInfo, file_name);
        let size = offset + name_bytes;
        // u64 words keep the buffer aligned for the HANDLE in the struct; a
        // Vec<u8> only promises byte alignment.
        let mut buffer = vec![0u64; size.div_ceil(std::mem::size_of::<u64>())];
        let info = buffer.as_mut_ptr() as *mut FileRenameInfo;
        unsafe {
            (*info).replace_if_exists = 1;
            (*info).root_directory = parent.as_raw_handle() as HANDLE;
            (*info).file_name_length = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                to_name.as_ptr(),
                std::ptr::addr_of_mut!((*info).file_name) as *mut u16,
                to_name.len(),
            );
        }
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle() as HANDLE,
                &mut iosb,
                buffer.as_mut_ptr() as *mut c_void,
                size as u32,
                FILE_RENAME_INFORMATION,
            )
        };
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(unsupported(io::Error::from_raw_os_error(code as i32)));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn windows_ensure_stable_id(id: (u32, u32, u32)) -> std::io::Result<()> {
    win_at::ensure_stable_id(id).map(|_| ())
}

#[cfg(windows)]
pub(crate) fn windows_unsupported_error(code: i32) -> std::io::Error {
    win_at::unsupported(std::io::Error::from_raw_os_error(code))
}

#[cfg(not(any(unix, windows)))]
pub fn safe_open_beneath(root: &std::path::Path, rel_path: &std::path::Path, flags: i32, deny_symlinks: bool, create_mode: u32) -> std::io::Result<std::fs::File> {
    canonical_open_beneath(root, rel_path, flags, deny_symlinks, create_mode)
}

#[cfg(windows)]
pub(crate) use win_at::WinRoot;

#[cfg(windows)]
pub fn safe_open_beneath(root: &std::path::Path, rel_path: &std::path::Path, flags: i32, deny_symlinks: bool, create_mode: u32) -> std::io::Result<std::fs::File> {
    // A deny_symlinks caller (the receive `.part` writers) needs the HANDLE
    // pinned across the whole operation; there is no such path-based form, so
    // refuse rather than silently using a weaker fallback. The mount surface
    // keeps its historical canonicalize arm (WinFsp is the live mount path).
    if deny_symlinks {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows receive requires the pinned root adapter; path-based deny-symlink opens are refused",
        ));
    }
    canonical_open_beneath(root, rel_path, flags, deny_symlinks, create_mode)
}

#[cfg(not(unix))]
fn canonical_open_beneath(root: &std::path::Path, rel_path: &std::path::Path, flags: i32, deny_symlinks: bool, create_mode: u32) -> std::io::Result<std::fs::File> {
    // There are no POSIX modes here; the file takes the directory's ACL.
    let _ = create_mode;
    let full = root.join(rel_path);
    // deny_symlinks callers (the .part writers) bypass this fallback on their
    // native arms, but refuse a reparse point here too so the property holds
    // even if the path is ever routed through this arm.
    if deny_symlinks && std::fs::symlink_metadata(&full)?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path is a symlink and symlinks are refused",
        ));
    }
    let canonical = full.canonicalize()?;
    let root_canonical = root.canonicalize()?;
    if !canonical.starts_with(&root_canonical) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path escapes share root",
        ));
    }
    open_file(&canonical, flags)
}

// -------------------------------------------------------- beneath mutations --
//
// The five mutating handlers (#148): resolve() is lexical and cannot see a
// symlink, so the old code ran std::fs on the resolved absolute path and a
// pre-existing symlink inside the share was followed outside it. The fix:
//
//   - unlink/mkdir/rmdir/rename act on a NAME; the final component is never
//     followed, so containment is entirely a parent question. Resolve the
//     parent to a dirfd the kernel guarantees is inside root, then act on the
//     bare name relative to it.
//   - truncate FOLLOWS its target, so it is an open: it reuses safe_open_beneath.
//
// ONE containment decision per platform, five callers. The platform split
// mirrors safe_open_beneath (Linux openat2 RESOLVE_BENEATH / other-Unix walk /
// non-Unix canonicalize) and is never re-derived per call site.

/// Resolve the parent of `rel` beneath `root`, returning the parent plus the
/// final component. Empty `rel` (the share root itself) and non-plain final
/// names are refused.
#[cfg(unix)]
fn resolve_parent_beneath(root: &std::path::Path, rel: &std::path::Path) -> std::io::Result<(std::os::fd::OwnedFd, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut comps = rel.components();
    let last = match comps.next_back() {
        Some(Component::Normal(n)) => n,
        _ => return Err(std::io::Error::from_raw_os_error(EINVAL)),
    };
    if last == std::ffi::OsStr::new(".") || last == std::ffi::OsStr::new("..") {
        return Err(std::io::Error::from_raw_os_error(EINVAL));
    }
    let last_c = std::ffi::CString::new(last.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "final component contains an interior NUL byte")
    })?;
    let parent: std::path::PathBuf = comps.collect();
    let parent_fd = open_parent_beneath(root, &parent)?;
    Ok((parent_fd, last_c))
}

/// Open the directory `dir_rel` (a relative path beneath `root`) to a dirfd,
/// refusing any resolution that escapes. Empty relative path = root itself.
#[cfg(unix)]
fn open_parent_beneath(root: &std::path::Path, dir_rel: &std::path::Path) -> std::io::Result<std::os::fd::OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        let root_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(root)?;

        // Values per include/uapi/linux/openat2.h, same as safe_open_beneath.
        const RESOLVE_BENEATH: u64 = 0x08;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_DIRECTORY as u64) | libc::O_CLOEXEC as u64;
        how.mode = 0;
        // Mount semantics: in-share symlinks resolve (deny_symlinks=false in
        // safe_open_beneath); only ESCAPE is refused, by RESOLVE_BENEATH.
        how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

        let rel_os = if dir_rel.as_os_str().as_bytes().is_empty() {
            std::ffi::OsStr::new(".")
        } else {
            dir_rel.as_os_str()
        };
        let rel_c = std::ffi::CString::new(rel_os.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains an interior NUL byte")
        })?;

        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd.as_raw_fd(),
                rel_c.as_ptr(),
                &how as *const _,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    #[cfg(not(target_os = "linux"))]
    {
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::Component;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let mut current = unsafe { OwnedFd::from_raw_fd(root_file.into_raw_fd()) };

        for comp in dir_rel.components() {
            match comp {
                Component::Normal(name) => {
                    let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path component contains an interior NUL byte")
                    })?;
                    // O_NOFOLLOW on every step: this arm refuses ALL symlinks
                    // (stricter than Linux, never the reverse), matching
                    // safe_open_beneath's non-Linux arm.
                    let fd = unsafe {
                        libc::openat(current.as_raw_fd(), name_c.as_ptr(), libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    current = unsafe { OwnedFd::from_raw_fd(fd) };
                }
                // Lexically impossible after resolve(); refuse rather than guess.
                Component::ParentDir | Component::CurDir => {
                    return Err(std::io::Error::from_raw_os_error(EACCES));
                }
                _ => {
                    return Err(std::io::Error::from_raw_os_error(EACCES));
                }
            }
        }
        Ok(current)
    }
}

#[cfg(not(unix))]
fn resolve_parent_beneath(root: &std::path::Path, rel: &std::path::Path) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    use std::path::Component;

    let mut comps = rel.components();
    let last = match comps.next_back() {
        Some(Component::Normal(n)) => n.to_os_string(),
        _ => return Err(std::io::Error::from_raw_os_error(EINVAL)),
    };
    if last == std::ffi::OsString::from(".") || last == std::ffi::OsString::from("..") {
        return Err(std::io::Error::from_raw_os_error(EINVAL));
    }
    let parent_rel: std::path::PathBuf = comps.collect();
    // Canonicalize the PARENT (not the full path): the final name is never
    // followed by the std::fs mutation calls, so only the parent needs the
    // beneath check. TOCTOU caveat, same as safe_open_beneath's non-Unix arm;
    // on Windows the live mount surface is WinFsp, so this is defense in depth.
    let canonical_parent = root.join(&parent_rel).canonicalize()?;
    let root_canonical = root.canonicalize()?;
    if !canonical_parent.starts_with(&root_canonical) {
        return Err(std::io::Error::from_raw_os_error(EACCES));
    }
    Ok((canonical_parent, std::path::PathBuf::from(last)))
}

#[cfg(unix)]
fn beneath_unlink(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(unix))]
fn beneath_unlink(parent: &std::path::Path, name: &std::path::Path) -> std::io::Result<()> {
    std::fs::remove_file(parent.join(name))
}

#[cfg(unix)]
fn beneath_rmdir(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(unix))]
fn beneath_rmdir(parent: &std::path::Path, name: &std::path::Path) -> std::io::Result<()> {
    std::fs::remove_dir(parent.join(name))
}

#[cfg(unix)]
fn beneath_mkdir(parent: &std::os::fd::OwnedFd, name: &std::ffi::CStr, mode: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // mode_t is a platform alias (u32 on Linux, u16 on Darwin), so cast at the
    // syscall boundary. The caller masks to 0o7777, so the narrowing never
    // truncates a meaningful bit.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // fchmodat is not subject to umask (mkdirat is), so applying the mode here
    // gives the peer exactly what it asked for. AT_SYMLINK_NOFOLLOW means a
    // symlink swapped in for the entry cannot be chmodded instead; the
    // freshly-created entry cannot be a symlink, so it never rejects a
    // legitimate directory.
    if unsafe { libc::fchmodat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(unix))]
fn beneath_mkdir(parent: &std::path::Path, name: &std::path::Path, _mode: u32) -> std::io::Result<()> {
    std::fs::create_dir(parent.join(name))
}

#[cfg(unix)]
fn beneath_rename(
    from_parent: &std::os::fd::OwnedFd,
    from_name: &std::ffi::CStr,
    to_parent: &std::os::fd::OwnedFd,
    to_name: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe {
        libc::renameat(
            from_parent.as_raw_fd(),
            from_name.as_ptr(),
            to_parent.as_raw_fd(),
            to_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(unix))]
fn beneath_rename(
    from_parent: &std::path::Path,
    from_name: &std::path::Path,
    to_parent: &std::path::Path,
    to_name: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::rename(from_parent.join(from_name), to_parent.join(to_name))
}

/// Atomically rename one path to another while keeping both parents beneath
/// `root`. Unix performs the rename relative to stable parent directory
/// handles. Windows resolves both parents to pinned directory HANDLEs (every
/// component opened with FILE_OPEN_REPARSE_POINT and refused if it is a
/// reparse point), verifies the staging name still identifies `source_file`,
/// and renames that HANDLE with SetFileInformationByHandle(FileRenameInfo,
/// RootDirectory=parent), replacing the destination entry without following
/// it. Both names must share one parent (sync's staging contract); anything
/// else is an explicit Unsupported error, never a path fallback. Other
/// non-Unix targets retain the canonical-parent fallback, which cannot resist
/// concurrent parent replacement.
#[cfg(unix)]
pub fn safe_rename_beneath(
    root: &std::path::Path,
    from_rel: &std::path::Path,
    to_rel: &std::path::Path,
    _source_file: &std::fs::File,
) -> std::io::Result<()> {
    let (from_parent, from_name) = resolve_parent_beneath(root, from_rel)?;
    let (to_parent, to_name) = resolve_parent_beneath(root, to_rel)?;
    beneath_rename(&from_parent, &from_name, &to_parent, &to_name)
}

#[cfg(windows)]
pub fn safe_rename_beneath(
    _root: &std::path::Path,
    _from_rel: &std::path::Path,
    _to_rel: &std::path::Path,
    _source_file: &std::fs::File,
) -> std::io::Result<()> {
    // Sync finalization goes through the retained staging-parent HANDLE
    // (`WinRoot::rename_staged`); a path-rooted rename would reopen the root
    // and is refused.
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows sync finalization requires the pinned staging parent; path-based rename is refused",
    ))
}

#[cfg(not(any(unix, windows)))]
pub fn safe_rename_beneath(
    root: &std::path::Path,
    from_rel: &std::path::Path,
    to_rel: &std::path::Path,
    _source_file: &std::fs::File,
) -> std::io::Result<()> {
    let (from_parent, from_name) = resolve_parent_beneath(root, from_rel)?;
    let (to_parent, to_name) = resolve_parent_beneath(root, to_rel)?;
    beneath_rename(&from_parent, &from_name, &to_parent, &to_name)
}

/// Remove a name beneath `root` without following its final component. Unix
/// unlinks relative to a stable parent handle; non-Unix uses the same
/// canonical-parent fallback as `safe_rename_beneath`.
#[cfg(unix)]
pub fn safe_unlink_beneath(root: &std::path::Path, rel: &std::path::Path) -> std::io::Result<()> {
    let (parent, name) = resolve_parent_beneath(root, rel)?;
    beneath_unlink(&parent, &name)
}

/// Remove the staging file represented by an already-open handle. Windows
/// marks that exact handle for deletion. Unix resolves a stable beneath-root
/// parent fd, compares the named entry to the open file with `fstatat` and
/// `AT_SYMLINK_NOFOLLOW`, then unlinks relative to that fd. A non-matching
/// entry (including a planted symlink) is left untouched. Unix has no portable
/// unlink-by-file-handle primitive, so a same-name replacement in the narrow
/// interval between identity check and `unlinkat` cannot be excluded against a
/// concurrent local filesystem attacker.
#[cfg(unix)]
pub fn safe_unlink_staged_beneath(
    root: &std::path::Path,
    rel: &std::path::Path,
    file: &std::fs::File,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let (parent, name) = resolve_parent_beneath(root, rel)?;
    let opened = file.metadata()?;
    let mut named: libc::stat = unsafe { std::mem::zeroed() };
    let stat_result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut named,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error);
    }
    if named.st_dev as u64 != opened.dev() || named.st_ino as u64 != opened.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "staging name no longer identifies this transfer's open file; refusing cleanup",
        ));
    }
    beneath_unlink(&parent, &name)
}

#[cfg(windows)]
pub(crate) fn safe_delete_open_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information_class: i32,
            information: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    let disposition = FileDispositionInfo { delete_file: 1 };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as *mut _,
            4, // FileDispositionInfo
            (&disposition as *const FileDispositionInfo).cast(),
            std::mem::size_of::<FileDispositionInfo>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub fn safe_unlink_staged_beneath(
    _root: &std::path::Path,
    _rel: &std::path::Path,
    file: &std::fs::File,
) -> std::io::Result<()> {
    safe_delete_open_file(file)
}

#[cfg(not(any(unix, windows)))]
pub fn safe_unlink_staged_beneath(
    root: &std::path::Path,
    rel: &std::path::Path,
    _file: &std::fs::File,
) -> std::io::Result<()> {
    safe_unlink_beneath(root, rel)
}

#[cfg(not(unix))]
pub fn safe_unlink_beneath(root: &std::path::Path, rel: &std::path::Path) -> std::io::Result<()> {
    let (parent, name) = resolve_parent_beneath(root, rel)?;
    beneath_unlink(&parent, &name)
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
    fn local_read_only_classification_covers_every_mutation() {
        let path = String::new();
        assert!(!mount_op_writes(&MountOp::GetAttr { path: path.clone() }));
        assert!(!mount_op_writes(&MountOp::Open { path: path.clone(), flags: O_RDONLY }));
        assert!(mount_op_writes(&MountOp::Open { path: path.clone(), flags: O_RDWR }));
        assert!(mount_op_writes(&MountOp::Write { fh: 1, offset: 0, size: 1 }));
        assert!(mount_op_writes(&MountOp::Create { path: path.clone(), mode: 0, flags: 0 }));
        assert!(mount_op_writes(&MountOp::Unlink { path: path.clone() }));
        assert!(mount_op_writes(&MountOp::MkDir { path: path.clone(), mode: 0 }));
        assert!(mount_op_writes(&MountOp::RmDir { path: path.clone() }));
        assert!(mount_op_writes(&MountOp::Rename { from: path.clone(), to: path.clone() }));
        assert!(mount_op_writes(&MountOp::Truncate { path, size: 0 }));
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

    // ------------------------------------------- #148 mutation containment
    //
    // The five mutating handlers once ran std::fs on a lexically-resolved path,
    // so a pre-existing symlink inside the share pointing outside it was
    // followed and the mutation landed outside the root. Each test plants that
    // symlink and asserts BOTH that the op is refused AND that the outside
    // state is byte-for-byte unchanged. The outside-state assertion is the one
    // that separates refusal-that-prevents from refusal-that-merely-reports.
    // read_only=false is deliberate: the EROFS gate would refuse these ops for
    // an unrelated reason, and a test that failed on the gate would prove
    // nothing about the containment primitive.

    #[cfg(unix)]
    struct EscapeFixture {
        share: std::path::PathBuf,
        outside: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl EscapeFixture {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("fil-mount-esc-{name}-{}", std::process::id()));
            let share = base.join("share");
            let outside = base.join("outside");
            std::fs::create_dir_all(&share).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            // share/evil -> outside : the pre-existing symlink inside the share.
            std::os::unix::fs::symlink(&outside, share.join("evil")).unwrap();
            EscapeFixture { share, outside }
        }
        fn enc(&self, rel: &str) -> String {
            path_encode(std::path::Path::new(rel))
        }
        fn cleanup(&self) {
            let _ = std::fs::remove_dir_all(self.share.parent().unwrap());
        }
    }

    #[cfg(unix)]
    async fn call_mount(root: &std::path::PathBuf, op: MountOp) -> MountResult {
        let mut open_files = HashMap::new();
        let mut next_fh = 1u64;
        let req = MountRequest { id: 1, bin: None, op };
        let (resp, _) =
            handle_mount_request(root, &mut open_files, &mut next_fh, &req, None, true, false).await;
        resp.result
    }

    /// M4/M5: the METADATA ops had the same lexical-resolve hole the five
    /// mutations had (#148). getattr and readlink through `evil -> outside`
    /// must be refused, the link itself still stats as a link, the root still
    /// stats, and a created file never keeps setuid/setgid/sticky.
    #[cfg(unix)]
    #[tokio::test]
    async fn metadata_ops_refuse_escape_and_create_masks_mode() {
        let f = EscapeFixture::new("meta");
        std::fs::write(f.outside.join("secret"), b"top secret").unwrap();
        std::os::unix::fs::symlink("/somewhere", f.outside.join("lnk")).unwrap();
        let res = call_mount(&f.share, MountOp::GetAttr { path: f.enc("evil/secret") }).await;
        assert!(matches!(res, MountResult::Err(_)), "getattr through escaping symlink must be refused: {res:?}");
        let res = call_mount(&f.share, MountOp::ReadLink { path: f.enc("evil/lnk") }).await;
        assert!(matches!(res, MountResult::Err(_)), "readlink through escaping symlink must be refused: {res:?}");
        match call_mount(&f.share, MountOp::GetAttr { path: f.enc("evil") }).await {
            MountResult::Ok(v) => {
                let st: FileStat = serde_json::from_value(v).unwrap();
                assert!(matches!(st.kind, Some(FileKind::Symlink)), "the in-share link stats as a link (lstat)");
            }
            other => panic!("getattr of the link itself must succeed: {other:?}"),
        }
        assert!(matches!(call_mount(&f.share, MountOp::GetAttr { path: f.enc("") }).await, MountResult::Ok(_)), "the root stats");

        let res = call_mount(&f.share, MountOp::Create { path: f.enc("made"), mode: 0o6755, flags: O_WRONLY }).await;
        assert!(matches!(res, MountResult::Ok(_)), "create: {res:?}");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(f.share.join("made")).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755, "setuid/setgid stripped, permission bits kept");
        f.cleanup();
    }

    /// A read-only share must refuse every Open that modifies data, not only a
    /// writable access mode: O_RDONLY|O_TRUNC truncates on Linux.
    #[cfg(unix)]
    #[tokio::test]
    async fn read_only_share_refuses_modifying_open_flags() {
        let f = EscapeFixture::new("ro");
        std::fs::write(f.share.join("keep"), b"data").unwrap();
        for flags in [libc::O_RDONLY | libc::O_TRUNC, libc::O_RDONLY | libc::O_CREAT, libc::O_RDONLY | libc::O_APPEND, libc::O_WRONLY] {
            let mut open_files = HashMap::new();
            let mut next_fh = 1u64;
            let req = MountRequest { id: 1, bin: None, op: MountOp::Open { path: f.enc("keep"), flags } };
            let (resp, _) = handle_mount_request(&f.share, &mut open_files, &mut next_fh, &req, None, true, true).await;
            assert!(matches!(&resp.result, MountResult::Err(e) if e.code == EROFS), "flags {flags:#o} must be EROFS: {:?}", resp.result);
            assert!(mount_op_writes(&MountOp::Open { path: String::new(), flags }), "client side agrees for {flags:#o}");
        }
        assert_eq!(std::fs::read(f.share.join("keep")).unwrap(), b"data", "nothing was truncated");
        f.cleanup();
    }

    /// M3: a read allocates what the server advertises, not what the peer asks.
    #[test]
    fn read_size_is_clamped_to_the_advertised_max() {
        let dir = std::env::temp_dir().join(format!("fil-mount-clamp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("big");
        std::fs::write(&p, vec![1u8; DEFAULT_MOUNT_MAX_SIZE as usize * 3]).unwrap();
        let mut open_files = HashMap::new();
        open_files.insert(1u64, (std::fs::File::open(&p).unwrap(), p.clone()));
        let (_, bytes) = do_read(&open_files, 1, 0, u32::MAX).unwrap();
        assert_eq!(bytes.len(), DEFAULT_MOUNT_MAX_SIZE as usize);
        drop(open_files);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M3: one stream cannot hold an unbounded number of daemon fds.
    #[test]
    fn open_handles_are_capped_per_stream() {
        let dir = std::env::temp_dir().join(format!("fil-mount-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"x").unwrap();
        let root = dir.clone();
        let enc = path_encode(std::path::Path::new("f"));
        let mut open_files = HashMap::new();
        let mut next_fh = 1u64;
        for _ in 0..MAX_OPEN_FILES_PER_STREAM {
            do_open(&root, &enc, O_RDONLY, &mut open_files, &mut next_fh).expect("under the cap");
        }
        let err = do_open(&root, &enc, O_RDONLY, &mut open_files, &mut next_fh).unwrap_err();
        assert_eq!(err.code, EMFILE);
        open_files.remove(&1);
        assert!(do_open(&root, &enc, O_RDONLY, &mut open_files, &mut next_fh).is_ok(), "a release frees a slot");
        drop(open_files);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unlink_refuses_escape_and_leaves_outside_unchanged() {
        let f = EscapeFixture::new("unlink");
        let victim = f.outside.join("victim.txt");
        std::fs::write(&victim, b"AAAA").unwrap();
        let res = call_mount(&f.share, MountOp::Unlink { path: f.enc("evil/victim.txt") }).await;
        // Outside-state assertion first: in the RED run this is the arm that
        // proves the pre-fix code actually reached outside the share.
        assert!(victim.exists(), "outside victim must survive the refused unlink");
        assert!(
            matches!(res, MountResult::Err(_)),
            "unlink through escaping symlink must be refused: {res:?}"
        );
        f.cleanup();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mkdir_refuses_escape_and_leaves_outside_unchanged() {
        let f = EscapeFixture::new("mkdir");
        let res = call_mount(&f.share, MountOp::MkDir { path: f.enc("evil/newdir"), mode: 0o755 }).await;
        assert!(
            !f.outside.join("newdir").exists(),
            "outside dir must NOT be created by the refused mkdir"
        );
        assert!(
            matches!(res, MountResult::Err(_)),
            "mkdir through escaping symlink must be refused: {res:?}"
        );
        f.cleanup();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rmdir_refuses_escape_and_leaves_outside_unchanged() {
        let f = EscapeFixture::new("rmdir");
        let outside_dir = f.outside.join("emptydir");
        std::fs::create_dir(&outside_dir).unwrap();
        let res = call_mount(&f.share, MountOp::RmDir { path: f.enc("evil/emptydir") }).await;
        assert!(outside_dir.exists(), "outside dir must survive the refused rmdir");
        assert!(
            matches!(res, MountResult::Err(_)),
            "rmdir through escaping symlink must be refused: {res:?}"
        );
        f.cleanup();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rename_refuses_escape_and_leaves_outside_unchanged() {
        let f = EscapeFixture::new("rename");
        let a = f.outside.join("a.txt");
        std::fs::write(&a, b"AAA").unwrap();
        let res = call_mount(&f.share, MountOp::Rename {
            from: f.enc("evil/a.txt"),
            to: f.enc("renamed.txt"),
        }).await;
        assert!(a.exists(), "outside source must survive the refused rename");
        assert!(
            !f.share.join("renamed.txt").exists(),
            "refused rename must not create the destination inside the share either"
        );
        assert!(
            matches!(res, MountResult::Err(_)),
            "rename out of the share must be refused: {res:?}"
        );
        f.cleanup();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn truncate_refuses_escape_and_leaves_outside_unchanged() {
        let f = EscapeFixture::new("truncate");
        let victim = f.outside.join("victim.txt");
        std::fs::write(&victim, b"AAAA").unwrap();
        let res = call_mount(&f.share, MountOp::Truncate { path: f.enc("evil/victim.txt"), size: 0 }).await;
        assert_eq!(
            std::fs::metadata(&victim).unwrap().len(),
            4,
            "outside victim length must stay 4 after the refused truncate"
        );
        assert!(
            matches!(res, MountResult::Err(_)),
            "truncate through escaping symlink must be refused: {res:?}"
        );
        f.cleanup();
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


    // ------------------------------------------------ moved host/log seam
    //
    // The live-session recheck moved with the server, but its verdict and
    // cadence are the injected host's. A cut must still answer the in-flight
    // request as a DENIAL (a FUSE client parks forever otherwise), then close
    // with the host's reason.

    #[derive(Default)]
    struct CutTransport {
        controls: std::sync::Mutex<Vec<Value>>,
        frames: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Transport for CutTransport {
        async fn send_control(&self, msg: &Value) -> anyhow::Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, payload: &[u8]) -> anyhow::Result<()> {
            self.frames.lock().unwrap().push(payload.to_vec());
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            64 * 1024
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn is_dead(&self) -> bool {
            false
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A host that cuts every check, immediately.
    struct CutHost;

    #[async_trait::async_trait]
    impl crate::host::HostServices for CutHost {
        fn settings_get_str(&self, key: &str) -> Option<String> {
            crate::host::NoHost.settings_get_str(key)
        }
        fn devices_load(&self) -> Vec<(String, String)> {
            crate::host::NoHost.devices_load()
        }
        fn is_self_uid(&self, a: &str, b: Option<&str>) -> bool {
            crate::host::NoHost.is_self_uid(a, b)
        }
        fn rejoin_unwarned(&self) -> std::time::Duration {
            crate::host::NoHost.rejoin_unwarned()
        }
        fn relay_banner(&self) -> String {
            crate::host::NoHost.relay_banner()
        }
        fn relay_forbidden(&self) -> bool {
            crate::host::NoHost.relay_forbidden()
        }
        fn channel_of(&self, secret: &str) -> String {
            crate::host::NoHost.channel_of(secret)
        }
        fn roster_snapshot_json(&self) -> Option<String> {
            crate::host::NoHost.roster_snapshot_json()
        }
        fn fleet_rv_present(&self) -> bool {
            false
        }
        fn revoke_recheck_interval(&self) -> std::time::Duration {
            std::time::Duration::ZERO
        }
        fn live_session_cut(&self, _idev: Option<&[u8; 32]>) -> Option<crate::host::LiveCut> {
            Some(crate::host::LiveCut {
                cause: crate::host::LiveCutCause::Revoked,
                expires_at: None,
                reason: "device revoked".into(),
            })
        }
    }

    #[tokio::test]
    async fn a_live_cut_answers_eacces_then_closes_with_the_host_reason() {
        let transport = Arc::new(CutTransport::default());
        let (tx, rx) = mpsc::channel(4);
        let handle = spawn_mount_server(MountServerConfig {
            root: PathBuf::from("."),
            transport: transport.clone(),
            sid: 9,
            stream: rx,
            protocol_version: 2,
            read_only: false,
            device_pub: Some([7; 32]),
            host: Arc::new(CutHost),
            log: Arc::new(crate::host::NoLog),
        });
        let req = MountRequest {
            id: 5,
            bin: None,
            op: MountOp::GetAttr { path: path_encode(std::path::Path::new("")) },
        };
        let mut payload = serde_json::to_vec(&req).unwrap();
        payload.push(b'\n');
        tx.send(Some(Bytes::from(payload))).await.unwrap();
        handle.await.unwrap();

        let frames = transport.frames.lock().unwrap();
        let (header, _) = decode_frame(&frames[0]);
        let resp: Value = serde_json::from_slice(header).unwrap();
        assert_eq!(resp["id"].as_u64(), Some(5));
        assert_eq!(resp["status"].as_str(), Some("err"));
        assert_eq!(resp["value"]["code"].as_i64(), Some(EACCES as i64));
        assert_eq!(
            *transport.controls.lock().unwrap(),
            vec![serde_json::json!({"type": "l2-close", "sid": 9, "err": "device revoked"})]
        );
    }


    #[cfg(windows)]
    fn win_tmp() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "tunlion-win-at-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[cfg(windows)]
    fn win_junction(target: &std::path::Path, link: &std::path::Path) -> bool {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::process::Command::new("cmd")
            .creation_flags(CREATE_NO_WINDOW)
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    fn win_symlink_file(target: &std::path::Path, link: &std::path::Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    /// Required adversarial coverage must not silently skip. These helpers
    /// panic with the exact capability that is missing, so the Windows job is
    /// red rather than green-but-uncovered.
    #[cfg(windows)]
    fn require_junction(target: &std::path::Path, link: &std::path::Path) {
        assert!(
            win_junction(target, link),
            "required Windows coverage: mklink /J (junction creation) is unavailable on this runner"
        );
    }

    #[cfg(windows)]
    fn require_symlink(target: &std::path::Path, link: &std::path::Path) {
        assert!(
            win_symlink_file(target, link),
            "required Windows coverage: file symlink creation is unavailable on this runner"
        );
    }

    #[cfg(windows)]
    fn win_root(path: &std::path::Path) -> WinRoot {
        WinRoot::open(path).expect("pin the admitted root")
    }

    #[cfg(windows)]
    #[test]
    fn windows_pinned_root_stage_and_rename_are_handle_relative() {
        use std::ffi::OsStr;
        use std::io::Write;
        let root = win_tmp();
        let win = win_root(&root);
        let parent = win
            .ensure_parent(std::path::Path::new("nested"))
            .expect("create the missing parent relative to the pinned root");
        let mut part = win
            .create_staging(&parent, OsStr::new("file.txt.part"))
            .expect("exclusive create beneath the pinned parent");
        part.write_all(b"payload").unwrap();
        part.sync_all().unwrap();
        win.rename_staged(
            &parent,
            OsStr::new("file.txt.part"),
            OsStr::new("file.txt"),
            &part,
        )
        .expect("same-parent handle-relative rename");
        assert_eq!(
            std::fs::read(root.join("nested/file.txt")).unwrap(),
            b"payload"
        );
        assert!(!root.join("nested/file.txt.part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_pinned_root_refuses_a_reparse_root() {
        let root = win_tmp();
        let outside = win_tmp();
        require_junction(&outside, &root.join("link"));
        let error = WinRoot::open(&root.join("link")).expect_err("a reparse root is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "refusing Windows sync root: the admitted root is a junction/symlink (reparse point)"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn windows_staging_refuses_a_junction_parent() {
        let root = win_tmp();
        let outside = win_tmp();
        require_junction(&outside, &root.join("nested"));
        let win = win_root(&root);
        let error = win
            .ensure_parent(std::path::Path::new("nested"))
            .expect_err("a junction parent must never be traversed");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "refusing Windows sync path: a parent is a junction/symlink (reparse point)"
        );
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing was created through the junction"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn windows_rename_replaces_a_destination_link_without_following_it() {
        use std::ffi::OsStr;
        use std::io::Write;
        let root = win_tmp();
        let outside = win_tmp();
        let outside_file = outside.join("outside.txt");
        std::fs::write(&outside_file, b"outside remains").unwrap();
        require_symlink(&outside_file, &root.join("file.txt"));
        let win = win_root(&root);
        let parent = win.ensure_parent(std::path::Path::new("")).unwrap();
        let mut part = win
            .create_staging(&parent, OsStr::new("file.txt.part"))
            .expect("create staging file");
        part.write_all(b"new content").unwrap();
        win.rename_staged(
            &parent,
            OsStr::new("file.txt.part"),
            OsStr::new("file.txt"),
            &part,
        )
        .expect("replace the destination entry");

        assert_eq!(std::fs::read(root.join("file.txt")).unwrap(), b"new content");
        assert!(
            !std::fs::symlink_metadata(root.join("file.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the rename replaced the link entry itself"
        );
        assert_eq!(
            std::fs::read(&outside_file).unwrap(),
            b"outside remains",
            "the rename replaced the entry, never the link target"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(windows)]
    #[test]
    fn windows_staging_identity_mismatch_is_refused() {
        use std::ffi::OsStr;
        use std::io::Write;
        let root = win_tmp();
        let win = win_root(&root);
        let parent = win.ensure_parent(std::path::Path::new("")).unwrap();
        let mut a = win
            .create_staging(&parent, OsStr::new("a.part"))
            .expect("create a");
        a.write_all(b"verified content").unwrap();
        let mut b = win
            .create_staging(&parent, OsStr::new("b.part"))
            .expect("create b");
        b.write_all(b"other content").unwrap();
        let error = win
            .rename_staged(&parent, OsStr::new("a.part"), OsStr::new("a"), &b)
            .expect_err("a different open file must not be renamed under this name");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "staging name no longer identifies this transfer's open file; refusing rename"
        );
        assert!(!root.join("a").exists());
        assert!(root.join("a.part").exists());
        assert!(root.join("b.part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_rooted_staging_and_rename_are_refused() {
        let root = win_tmp();
        std::fs::write(root.join("x.part"), b"x").unwrap();
        let source = std::fs::File::open(root.join("x.part")).unwrap();
        let rename = safe_rename_beneath(
            &root,
            std::path::Path::new("x.part"),
            std::path::Path::new("x"),
            &source,
        )
        .expect_err("a path-rooted rename has no pinned root");
        assert_eq!(rename.kind(), std::io::ErrorKind::Unsupported);
        assert!(rename.to_string().contains("pinned staging parent"));

        let open = safe_open_beneath(
            &root,
            std::path::Path::new("x.part"),
            0,
            true,
            0,
        )
        .expect_err("a path-rooted deny-symlink open has no pinned root");
        assert_eq!(open.kind(), std::io::ErrorKind::Unsupported);
        assert!(open.to_string().contains("pinned root adapter"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_unsupported_filesystem_errors_are_named_and_zero_ids_are_refused() {
        for code in [1, 17, 50, 87] {
            let error = windows_unsupported_error(code);
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported, "code {code}");
            assert!(
                error
                    .to_string()
                    .contains("not supported on this filesystem"),
                "code {code}: {error}"
            );
        }
        for id in [(0, 0, 0), (0, 1, 1), (7, 0, 0)] {
            let error = windows_ensure_stable_id(id).expect_err("zero/absent identity is unsupported");
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            assert!(error.to_string().contains("stable file identity"));
        }
        windows_ensure_stable_id((7, 1, 2)).expect("a real identity is accepted");
    }

}
