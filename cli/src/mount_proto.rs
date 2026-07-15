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
    Write { fh: u64, offset: u64, data: String },
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

// ----------------------------------------------------------- protocol transport --

/// A client-end handle for talking to the mount server over the mux stream.
pub struct MountClient {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Bytes>,
    buf: Vec<u8>,
    next_id: u64,
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
        MountClient { tx: tx_bytes, rx: rx_in, buf: Vec::new(), next_id: 1 }
    }

    /// Send a request and await its response (async).
    pub async fn call(&mut self, op: MountOp) -> Result<MountResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = MountRequest { id, op };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        self.tx.send(payload).ok();
        loop {
            if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                let line = self.buf.drain(..nl).collect::<Vec<_>>();
                if !self.buf.is_empty() && self.buf[0] == b'\n' {
                    self.buf.remove(0);
                }
                let resp: MountResponse = serde_json::from_slice(&line)?;
                if resp.id == id {
                    return Ok(resp);
                }
                // Not our response (pipelined responses can arrive out of order).
                // This function blocks until matching id; store others? No, they're
                // not ours since we do one-at-a-time calls. Re-enqueue and continue.
                self.buf.splice(0..0, line);
                continue;
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
        let id = self.next_id;
        self.next_id += 1;
        let req = MountRequest { id, op };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');
        self.tx.send(payload).ok();
        loop {
            if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                let line = self.buf.drain(..nl).collect::<Vec<_>>();
                if !self.buf.is_empty() && self.buf[0] == b'\n' { self.buf.remove(0); }
                let resp: MountResponse = serde_json::from_slice(&line)?;
                if resp.id == id { return Ok(resp); }
                self.buf.splice(0..0, line);
                continue;
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
/// when a `mount-open` control message arrives. Reads JSON requests from
/// `rx` (mux inbound pipe) and writes responses via `transport.send_frame`.
pub fn spawn_mount_server(
    root: PathBuf,
    transport: Arc<dyn Transport>,
    sid: u32,
    mut rx: mpsc::Receiver<PipeItem>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut open_files: HashMap<u64, (std::fs::File, PathBuf)> = HashMap::new();
        let mut next_fh: u64 = 1;
        let mut buf = Vec::new();

        loop {
            // Extract complete lines from buf and handle them
            while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..nl).collect();
                if !buf.is_empty() && buf[0] == b'\n' {
                    buf.remove(0);
                }
                let req: MountRequest = match serde_json::from_slice(&line) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = MountResponse { id: 0, result: MountResult::Err(MountError { code: EINVAL, msg: format!("parse: {e}") }) };
                        let mut p = serde_json::to_vec(&resp).unwrap_or_default();
                        p.push(b'\n');
                        let _ = transport.send_frame(sid, 0, &p).await;
                        continue;
                    }
                };
                let resp = handle_mount_request(&root, &mut open_files, &mut next_fh, &req).await;
                let mut p = serde_json::to_vec(&resp).unwrap_or_default();
                p.push(b'\n');
                if transport.send_frame(sid, 0, &p).await.is_err() { return; }
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

async fn handle_mount_request(
    root: &PathBuf,
    open_files: &mut HashMap<u64, (std::fs::File, PathBuf)>,
    next_fh: &mut u64,
    req: &MountRequest,
) -> MountResponse {
    let result = match &req.op {
        MountOp::GetAttr { path } => do_getattr(root, path),
        MountOp::Open { path, flags } => do_open(root, path, *flags, open_files, next_fh),
        MountOp::Read { fh, offset, size } => do_read(open_files, *fh, *offset, *size),
        MountOp::Write { fh, offset, data } => do_write(open_files, *fh, *offset, data),
        MountOp::ReadDir { fh, offset } => do_readdir(root, open_files, *fh, *offset),
        MountOp::Release { fh } => { open_files.remove(fh); Ok(Value::Null) }
        MountOp::Create { path, mode, flags } => do_create(root, path, *mode, *flags, open_files, next_fh),
        MountOp::Unlink { path } => do_unlink(root, path),
        MountOp::MkDir { path, mode } => do_mkdir(root, path, *mode),
        MountOp::RmDir { path } => do_rmdir(root, path),
        MountOp::Rename { from, to } => do_rename(root, from, to),
        MountOp::Truncate { path, size } => do_truncate(root, path, *size),
        MountOp::FSync { fh, .. } => do_fsync(open_files, *fh),
        MountOp::ReadLink { path } => do_readlink(root, path),
    };

    match result {
        Ok(v) => MountResponse { id: req.id, result: MountResult::Ok(v) },
        Err(e) => MountResponse { id: req.id, result: MountResult::Err(e) },
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
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read((flags & O_RDONLY as i32) == 0)
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

fn do_read(open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, offset: u64, size: u32) -> Result<Value, MountError> {
    use std::io::{Read, Seek, SeekFrom};
    let (file, _) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    let mut file = file.try_clone().map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    file.seek(SeekFrom::Start(offset)).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    let mut buf = vec![0u8; size as usize];
    let n = file.read(&mut buf).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    buf.truncate(n);
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
    Ok(serde_json::json!({ "data": encoded }))
}

fn do_write(open_files: &HashMap<u64, (std::fs::File, PathBuf)>, fh: u64, offset: u64, data: &str) -> Result<Value, MountError> {
    use std::io::{Seek, SeekFrom, Write};
    use base64::Engine;
    let (file, _) = open_files.get(&fh).ok_or_else(|| MountError { code: EBADF, msg: "bad fh".into() })?;
    let mut file = file.try_clone().map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    let buf = base64::engine::general_purpose::STANDARD.decode(data).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    file.seek(SeekFrom::Start(offset)).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
    let n = file.write(&buf).map_err(|e| MountError { code: EIO, msg: e.to_string() })?;
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
    let rd = (flags & O_RDONLY as i32) != 0 || (flags & O_RDWR as i32) != 0;
    let wr = (flags & O_WRONLY as i32) != 0 || (flags & O_RDWR as i32) != 0;
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
