//! Windows mount client adapter: present the mesh-native mount protocol as a real
//! local filesystem via WinFsp (FUSE-analog for Windows). Mirrors mount_fuse.rs.
//!
//! WinFsp is a kernel driver + userspace library; `choco install winfsp` provides
//! both. The adapter runs on WinFsp's own thread pool; MountClient call_sync/
//! call_sync_binary block the calling thread, matching the sync trait.
//!
//! MountClient is wrapped in a Mutex — call_sync is inherently single-caller
//! (sequential request ids, shared internal buffer).

#![cfg(all(target_os = "windows", feature = "mount-windows"))]

use std::ffi::c_void;
use std::path::Path;
use std::sync::Mutex;

use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::FileSystemHost;
use winfsp::host::VolumeParams;
use winfsp::{FspError, Result as FspResult, U16CStr, U16CString};
use winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES;

use crate::mount_proto::{self, DirEntry, FileKind, FileStat, MountClient, MountOp};

// Windows FILE_ATTRIBUTE constants (casted from winfsp_sys newtypes)
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;

// NTSTATUS constants
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC0000034;
const STATUS_IO_DEVICE_ERROR: u32 = 0xC0000185;

// ----------------------------------------------------------- name escaping ---

/// Escaper applied at the WinFsp<->protocol boundary. Windows NT names are
/// valid UTF-16 but forbid a set of characters and reserved names. The
/// protocol layer (mount_proto.rs) advertises `forbidden_bytes` and
/// `forbidden_names` in caps.
///
/// Reversibility + injectivity guarantee: for all protocol-valid strings x,
/// decode(encode(x)) == x. The scheme is:
///   - `%` (0x25) encodes to `%25` (escaped first, before any other %hh)
///   - each other forbidden byte b encodes to `%hh`
///   - reserved names encode with a `%ff` sentinel prefix on the base name stem
///   - decode reverses: `%25` -> `%`, `%ff` prefix -> strip (only at a path
///     component boundary), other `%hh` -> corresponding byte
///
/// The sentinel `%ff` is injective because 0xFF is itself a forbidden byte
/// (percent-encoded to `%ff` normally), and `%` is always escaped to `%25`.
struct NameEscaper {
    escape_map: Vec<(u8, String)>,
    reserved_names: Vec<String>,
}

impl NameEscaper {
    fn from_caps(caps: &crate::mount_proto::MountCaps) -> Self {
        let mut escape_map: Vec<(u8, String)> = Vec::new();
        escape_map.push((b'%', "%25".into()));
        for &b in &caps.forbidden_bytes {
            if b == b'%' { continue; }
            let need = match b {
                b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*' => true,
                0..=0x1F => true,
                _ => false,
            };
            if need {
                escape_map.push((b, format!("%{:02x}", b)));
            }
        }
        let reserved_names: Vec<String> = caps
            .forbidden_names.iter().map(|n| n.to_ascii_uppercase()).collect();
        NameEscaper { escape_map, reserved_names }
    }

    fn encode_byte(b: u8, map: &[(u8, String)], out: &mut String) {
        if let Some((_, esc)) = map.iter().find(|(fb, _)| *fb == b) {
            out.push_str(esc);
        } else {
            out.push(b as char);
        }
    }

    fn encode(&self, proto_name: &str) -> String {
        let mut out = String::with_capacity(proto_name.len());
        for b in proto_name.bytes() {
            Self::encode_byte(b, &self.escape_map, &mut out);
        }
        if let Some(base_start) = out.rfind('\\').map(|i| i + 1) {
            let base = &out[base_start..];
            let upper = base.to_ascii_uppercase();
            let stem_end = upper.rfind('.').unwrap_or(upper.len());
            let stem = &upper[..stem_end];
            if self.reserved_names.iter().any(|r| r == stem) {
                out.insert_str(base_start, "%ff");
            }
        } else {
            let upper = out.to_ascii_uppercase();
            let stem_end = upper.rfind('.').unwrap_or(upper.len());
            let stem = &upper[..stem_end];
            if self.reserved_names.iter().any(|r| r == stem) {
                out.insert_str(0, "%ff");
            }
        }
        out
    }

    fn decode(&self, win_name: &str) -> String {
        let mut out = String::with_capacity(win_name.len());
        let bytes = win_name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                if let Ok(b) = u8::from_str_radix(
                    &String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16,
                ) {
                    if b == 0xff {
                        i += 3;
                        continue;
                    }
                    out.push(b as char);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    fn test_caps() -> crate::mount_proto::MountCaps {
        crate::mount_proto::MountCaps {
            protocol_version: 1, case_sensitive: false,
            max_path_len: 4096, max_component_len: 255,
            max_read_size: 65536, max_write_size: 65536,
            forbidden_bytes: vec![b'<', b'>', b':', b'"', b'/', b'\\', b'|', b'?', b'*'],
            forbidden_names: vec!["AUX".into(), "CON".into(), "NUL".into(), "PRN".into()],
            supports_symlinks: false, supports_hardlinks: false, supports_fifo: false,
            metadata_fields: vec![],
        }
    }

    fn assert_roundtrip(e: &NameEscaper, input: &str) {
        let enc = e.encode(input);
        let dec = e.decode(&enc);
        assert_eq!(dec, input, "roundtrip failed: {input:?} -> {enc:?} -> {dec:?}");
    }

    fn assert_injective(e: &NameEscaper, a: &str, b: &str) {
        let ea = e.encode(a);
        let eb = e.encode(b);
        assert_ne!(ea, eb, "encode not injective: {a:?} -> {ea:?}, {b:?} -> {eb:?}");
    }

    #[test]
    fn roundtrip_simple() {
        let e = NameEscaper::from_caps(&test_caps());
        for name in &["file.txt", "hello world", "foo-bar", "test"] {
            assert_roundtrip(&e, name);
        }
    }

    #[test]
    fn roundtrip_colon() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_eq!(e.encode("foo:bar"), "foo%3abar");
        assert_roundtrip(&e, "foo:bar");
    }

    #[test]
    fn roundtrip_reserved() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_eq!(e.encode("AUX"), "%ffAUX");
        assert_roundtrip(&e, "AUX");
    }

    #[test]
    fn roundtrip_reserved_subdir() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_roundtrip(&e, "dir\\CON");
    }

    #[test]
    fn roundtrip_percent() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_roundtrip(&e, "100%20done");
    }

    #[test]
    fn roundtrip_percent_escape_collision() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_eq!(e.encode("foo%3abar"), "foo%253abar");
        assert_roundtrip(&e, "foo%3abar");
        assert_injective(&e, "foo:bar", "foo%3abar");
    }

    #[test]
    fn roundtrip_trailing_dot() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_roundtrip(&e, "file.");
    }

    #[test]
    fn adversarial_roundtrip() {
        let e = NameEscaper::from_caps(&test_caps());
        for name in &["%3a", "%25", "AUX", "_AUX", "%ffAUX", "foo:bar", "file.",
                       "dir\\CON", "foo%3abar", "100%", "%%", "file.<>:\"/\\|?*"] {
            assert_roundtrip(&e, name);
        }
    }

    #[test]
    fn adversarial_injective() {
        let e = NameEscaper::from_caps(&test_caps());
        assert_injective(&e, "AUX", "_AUX");
        assert_injective(&e, "AUX", "%ffAUX");
        assert_injective(&e, "foo:bar", "foo%3abar");
        assert_injective(&e, "CON", "%ffCON");
        assert_injective(&e, "NUL", "NUL.txt");
    }
}

// -------------------------------------------------------- file system struct ---

pub struct WinFspContext {
    filename: String,
    fh: u64,
    dir_buffer: Option<DirBuffer>,
}

pub struct FilamentWinFs {
    client: Mutex<MountClient>,
    escaper: NameEscaper,
}

impl FilamentWinFs {
    pub fn new(client: MountClient) -> Self {
        let escaper = NameEscaper::from_caps(&client.caps);
        FilamentWinFs { client: Mutex::new(client), escaper }
    }

    fn call(&self, op: MountOp) -> FspResult<serde_json::Value> {
        let mut c = self.client.lock().unwrap();
        match c.call_sync(op) {
            Ok(resp) => match resp.result {
                mount_proto::MountResult::Ok(v) => Ok(v),
                mount_proto::MountResult::Err(_) => {
                    Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND as i32))
                }
            },
            Err(_) => Err(FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR as i32)),
        }
    }

    fn file_stat_from_value(v: &serde_json::Value) -> FileStat {
        FileStat {
            ino: v["ino"].as_u64().unwrap_or(0),
            size: v["size"].as_u64().unwrap_or(0),
            mode: v["mode"].as_u64().unwrap_or(0) as u32,
            uid: v["uid"].as_u64().unwrap_or(0) as u32,
            gid: v["gid"].as_u64().unwrap_or(0) as u32,
            mtime: v["mtime"].as_u64().unwrap_or(0),
            nlink: v["nlink"].as_u64().unwrap_or(1) as u32,
            blksize: v["blksize"].as_u64().unwrap_or(4096) as u32,
            blocks: v["blocks"].as_u64().unwrap_or(0),
            kind: match v["kind"].as_str() {
                Some("dir") => Some(FileKind::Dir),
                Some("symlink") => Some(FileKind::Symlink),
                _ => Some(FileKind::File),
            },
        }
    }

    fn file_attributes_from_stat(st: &FileStat) -> u32 {
        let mut attrs = 0u32;
        if matches!(st.kind, Some(FileKind::Dir)) {
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
        }
        if st.mode & 0o222 == 0 {
            attrs |= FILE_ATTRIBUTE_READONLY;
        }
        attrs
    }

    fn fill_file_info(stat: &FileStat, info: &mut FileInfo) {
        info.file_attributes = Self::file_attributes_from_stat(stat);
        info.file_size = stat.size;
        info.allocation_size = (stat.size + 511) / 512 * 512;
        info.creation_time = stat.mtime;
        info.last_access_time = stat.mtime;
        info.last_write_time = stat.mtime;
        info.change_time = stat.mtime;
        info.index_number = stat.ino;
        info.hard_links = stat.nlink.max(1);
    }
}

// ------------------------------------------------------ FileSystemContext ---

impl FileSystemContext for FilamentWinFs {
    type FileContext = WinFspContext;

    fn get_volume_info(&self, volume_info: &mut VolumeInfo) -> FspResult<()> {
        volume_info.total_size = 1024 * 1024 * 1024 * 1024;
        volume_info.free_size = 1024 * 1024 * 1024 * 1024;
        volume_info.set_volume_label("Filament");
        Ok(())
    }

    fn get_security_by_name(
        &self, file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FspResult<FileSecurity> {
        let raw_name = file_name.to_string_lossy();
        let proto_path = self.escaper.decode(raw_name.trim_start_matches('\\'));
        let proto_enc = mount_proto::path_encode(Path::new(&proto_path));
        if proto_enc == mount_proto::path_encode(Path::new(".")) {
            return Ok(FileSecurity {
                attributes: FILE_ATTRIBUTE_DIRECTORY, reparse: false, sz_security_descriptor: 0,
            });
        }
        match self.call(MountOp::GetAttr { path: proto_enc }) {
            Ok(v) => {
                let stat = Self::file_stat_from_value(&v);
                Ok(FileSecurity {
                    attributes: Self::file_attributes_from_stat(&stat),
                    reparse: false, sz_security_descriptor: 0,
                })
            }
            Err(e) => Err(e),
        }
    }

    fn open(
        &self, file_name: &U16CStr, _create_options: u32, _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let raw_name = file_name.to_string_lossy();
        let proto_path = self.escaper.decode(raw_name.trim_start_matches('\\'));
        let proto_enc = mount_proto::path_encode(Path::new(&proto_path));

        if proto_enc == mount_proto::path_encode(Path::new(".")) {
            let info: &mut FileInfo = file_info.as_mut();
            let stat = FileStat {
                ino: 1, size: 0, mode: 0o755, uid: 0, gid: 0, mtime: 0, nlink: 1,
                blksize: 4096, blocks: 0, kind: Some(FileKind::Dir),
            };
            Self::fill_file_info(&stat, info);
            return Ok(WinFspContext {
                filename: proto_path, fh: 0, dir_buffer: Some(DirBuffer::new()),
            });
        }

        match self.call(MountOp::Open { path: proto_enc.clone(), flags: 0 }) {
            Ok(v) => {
                let fh = v["fh"].as_u64().unwrap_or(0);
                let stat = Self::file_stat_from_value(&v);
                let info: &mut FileInfo = file_info.as_mut();
                Self::fill_file_info(&stat, info);
                let dir_buffer = if matches!(stat.kind, Some(FileKind::Dir)) {
                    Some(DirBuffer::new())
                } else { None };
                Ok(WinFspContext { filename: proto_path, fh, dir_buffer })
            }
            Err(e) => Err(e),
        }
    }

    fn close(&self, context: Self::FileContext) {
        if context.fh != 0 {
            let mut c = self.client.lock().unwrap();
            let _ = c.call_sync(MountOp::Release { fh: context.fh });
        }
    }

    fn get_file_info(
        &self, context: &Self::FileContext, file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let proto_enc = mount_proto::path_encode(Path::new(&context.filename));
        match self.call(MountOp::GetAttr { path: proto_enc }) {
            Ok(v) => { Self::fill_file_info(&Self::file_stat_from_value(&v), file_info); Ok(()) }
            Err(e) => Err(e),
        }
    }

    fn read(
        &self, context: &Self::FileContext, buffer: &mut [u8], offset: u64,
    ) -> FspResult<u32> {
        let max_read = self.client.lock().unwrap().caps.max_read_size;
        let size = (buffer.len() as u32).min(max_read);
        let mut c = self.client.lock().unwrap();
        match c.call_sync_binary(MountOp::Read { fh: context.fh, offset, size }, None) {
            Ok((resp, data)) => match resp.result {
                mount_proto::MountResult::Ok(_) => {
                    if let Some(bytes) = data {
                        let n = bytes.len().min(buffer.len());
                        buffer[..n].copy_from_slice(&bytes[..n]);
                        return Ok(n as u32);
                    }
                    Ok(0)
                }
                mount_proto::MountResult::Err(_) => {
                    Err(FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR as i32))
                }
            },
            Err(_) => Err(FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR as i32)),
        }
    }

    fn write(
        &self, context: &Self::FileContext, buffer: &[u8], offset: u64,
        _write_to_eof: bool, _constrained_io: bool, file_info: &mut FileInfo,
    ) -> FspResult<u32> {
        let max_write = self.client.lock().unwrap().caps.max_write_size;
        let mut written: u32 = 0;
        let mut off = offset;
        for chunk in buffer.chunks(max_write as usize) {
            let mut c = self.client.lock().unwrap();
            let op = MountOp::Write { fh: context.fh, offset: off, size: chunk.len() as u32 };
            match c.call_sync_binary(op, Some(chunk)) {
                Ok((resp, _)) => match resp.result {
                    mount_proto::MountResult::Ok(ref v) => {
                        written += v["written"].as_u64().unwrap_or(chunk.len() as u64) as u32;
                        off += chunk.len() as u64;
                    }
                    mount_proto::MountResult::Err(_) => break,
                },
                Err(_) => break,
            }
        }
        if let Ok(v) = self.call(MountOp::GetAttr {
            path: mount_proto::path_encode(Path::new(&context.filename)),
        }) {
            Self::fill_file_info(&Self::file_stat_from_value(&v), file_info);
        }
        Ok(written)
    }

    fn read_directory(
        &self, context: &Self::FileContext, _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>, buffer: &mut [u8],
    ) -> FspResult<u32> {
        let dir_buffer = match &context.dir_buffer {
            Some(b) => b,
            None => return Err(FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR as i32)),
        };
        if let Ok(dir_buffer_lock) = dir_buffer.acquire(false, None) {
            match self.call(MountOp::ReadDir { fh: context.fh, offset: 0 }) {
                Ok(v) => {
                    let entries: Vec<DirEntry> = serde_json::from_value(v).unwrap_or_default();
                    let mut dir_info = DirInfo::<255>::new();
                    for entry in &entries {
                        dir_info.reset();
                        let encoded = self.escaper.encode(&entry.name);
                        let file_name_u16 = match U16CString::from_str(&encoded) {
                            Ok(n) => n,
                            Err(_) => continue,
                        };
                        if dir_info.set_name_cstr(&file_name_u16).is_err() {
                            continue;
                        }
                        let mut fi = FileInfo::default();
                        Self::fill_file_info(&entry.stat, &mut fi);
                        *dir_info.file_info_mut() = fi;
                        if dir_buffer_lock.write(&mut dir_info).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => {}
            }
        }
        Ok(dir_buffer.read(marker, buffer))
    }

    fn create(
        &self, file_name: &U16CStr, _create_options: u32, _granted_access: u32,
        _file_attributes: FILE_FLAGS_AND_ATTRIBUTES, _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64, _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool, file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let raw_name = file_name.to_string_lossy();
        let proto_path = self.escaper.decode(raw_name.trim_start_matches('\\'));
        let proto_enc = mount_proto::path_encode(Path::new(&proto_path));
        match self.call(MountOp::Create { path: proto_enc.clone(), mode: 0o644, flags: 0 }) {
            Ok(v) => {
                let fh = v["fh"].as_u64().unwrap_or(0);
                let info: &mut FileInfo = file_info.as_mut();
                Self::fill_file_info(&Self::file_stat_from_value(&v), info);
                Ok(WinFspContext { filename: proto_path, fh, dir_buffer: None })
            }
            Err(e) => Err(e),
        }
    }

    fn set_file_size(
        &self, context: &Self::FileContext, new_size: u64, _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let proto_enc = mount_proto::path_encode(Path::new(&context.filename));
        self.call(MountOp::Truncate { path: proto_enc.clone(), size: new_size })?;
        if let Ok(v) = self.call(MountOp::GetAttr { path: proto_enc }) {
            Self::fill_file_info(&Self::file_stat_from_value(&v), file_info);
        }
        Ok(())
    }

    fn rename(
        &self, context: &Self::FileContext, file_name: &U16CStr,
        new_file_name: &U16CStr, _replace_if_exists: bool,
    ) -> FspResult<()> {
        let from = self.escaper.decode(file_name.to_string_lossy().trim_start_matches('\\'));
        let to = self.escaper.decode(new_file_name.to_string_lossy().trim_start_matches('\\'));
        self.call(MountOp::Rename {
            from: mount_proto::path_encode(Path::new(&from)),
            to: mount_proto::path_encode(Path::new(&to)),
        })?;
        Ok(())
    }

    fn set_delete(
        &self, _context: &Self::FileContext, file_name: &U16CStr, _delete_file: bool,
    ) -> FspResult<()> {
        let path = self.escaper.decode(file_name.to_string_lossy().trim_start_matches('\\'));
        let proto_enc = mount_proto::path_encode(Path::new(&path));
        let _ = self.call(MountOp::Unlink { path: proto_enc.clone() });
        let _ = self.call(MountOp::RmDir { path: proto_enc });
        Ok(())
    }

    fn cleanup(
        &self, _context: &Self::FileContext, _file_name: Option<&U16CStr>, _flags: u32,
    ) {}

    fn flush(
        &self, context: Option<&Self::FileContext>, _file_info: &mut FileInfo,
    ) -> FspResult<()> {
        if let Some(ctx) = context {
            if ctx.fh != 0 {
                let mut c = self.client.lock().unwrap();
                let _ = c.call_sync(MountOp::FSync { fh: ctx.fh, datasync: false });
            }
        }
        Ok(())
    }

    fn overwrite(
        &self, context: &Self::FileContext, _file_attributes: u32,
        _replace_file_attributes: bool, _allocation_size: u64,
        _extra_buffer: Option<&[u8]>, file_info: &mut FileInfo,
    ) -> FspResult<()> {
        let proto_enc = mount_proto::path_encode(Path::new(&context.filename));
        self.call(MountOp::Truncate { path: proto_enc.clone(), size: 0 })?;
        if let Ok(v) = self.call(MountOp::GetAttr { path: proto_enc }) {
            Self::fill_file_info(&Self::file_stat_from_value(&v), file_info);
        }
        Ok(())
    }
}

// ----------------------------------------------------------- public API ---

/// Mount a mesh-native mount protocol connection at `mountpoint` using WinFsp.
/// Blocks the calling thread until unmounted.
pub fn run_mount(client: MountClient, mountpoint: &Path) -> anyhow::Result<()> {
    let _ = detect_winfsp()?;
    let fs = FilamentWinFs::new(client);
    let mountpoint_str = mountpoint.to_str()
        .ok_or_else(|| anyhow::anyhow!("mountpoint is not valid UTF-8"))?;
    let mut vol_params = VolumeParams::new();
    vol_params.filesystem_name("Filament");
    vol_params.prefix("\\");
    let mut host = FileSystemHost::new(vol_params, fs)
        .map_err(|e| anyhow::anyhow!("WinFsp mount failed: {e}"))?;
    host.mount(mountpoint_str)
        .map_err(|e| anyhow::anyhow!("WinFsp mount failed: {e}"))?;
    host.start()
        .map_err(|e| anyhow::anyhow!("WinFsp dispatcher failed: {e}"))?;
    Ok(())
}

fn detect_winfsp() -> anyhow::Result<()> {
    let candidates = [
        r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll",
        r"C:\Program Files\WinFsp\bin\winfsp-x64.dll",
    ];
    if !candidates.iter().any(|p| std::path::Path::new(p).exists()) {
        return Err(anyhow::anyhow!(
            "WinFsp is not installed. Install it from https://github.com/winfsp/winfsp/releases or:\n\
             winget install WinFsp.WinFsp\n\
             choco install winfsp"
        ));
    }
    Ok(())
}
