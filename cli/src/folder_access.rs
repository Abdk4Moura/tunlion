//! Recipient folder UI and bounded previews over the shared mount protocol.
//! No OS mount, DNS integration, or download publication is implied by a label.
use anyhow::{Result, anyhow, bail};
use crate::ui;
use bytes::Bytes;
use filament_peerloop::access::{AgreementSnapshot, FolderAccess};
use filament_peerloop::driver::Cancellation;
use filament_peerloop::mount_proto::{self, DirEntry, FileKind, FileStat, MountClient, MountOp, MountResult};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

const MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) enum Operation { Browse, Read, Download { directory: PathBuf, name: String } }
#[derive(Debug)]
pub(crate) enum Output {
    Listing(Vec<DirEntry>), Preview { bytes: Bytes, size: u64 },
    Downloaded(filament_peerloop::download_output::PublishedDownload), DurabilityUnknown(PathBuf),
}
pub(crate) struct Request {
    pub(crate) folder: FolderAccess,
    pub(crate) relative: PathBuf,
    pub(crate) operation: Operation,
    pub(crate) reply: std::sync::mpsc::SyncSender<std::result::Result<Output, String>>,
}

/// One recipient-side request from the blocking terminal menu. Folder work is
/// bounded reads over the scoped endpoint; a terminal request hands stdin to
/// the async PTY bridge and does not read the keyboard itself while it runs.
pub(crate) enum Control {
    Folder(Request),
    Terminal { reply: std::sync::mpsc::SyncSender<std::result::Result<(), String>> },
}

pub(crate) struct Controls {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    requests: tokio::sync::mpsc::Receiver<Control>,
}
impl Controls {
    pub(crate) fn start(snapshot: &AgreementSnapshot, shell: bool) -> Self {
        let folders = snapshot.spec.folders.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (tx, requests) = tokio::sync::mpsc::channel(4);
        let thread = std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                while !stopped.load(Ordering::Acquire) {
                    let mut labels = folders.iter().map(|folder| format!("{} · {}", folder.id,
                        if folder.mode == filament_peerloop::access::FolderMode::ReadOnly { "read-only" } else { "read/write" })).collect::<Vec<_>>();
                    let shell_row = if shell {
                        labels.push("Open shared terminal".into());
                        Some(labels.len() - 1)
                    } else { None };
                    labels.push("Close browser".into());
                    let prompt = if folders.is_empty() && shell { "SHELL · shared terminal" } else { "FOLDERS · endpoint checked on use" };
                    let Some(selected) = crate::access_ui::live_pick(prompt, &labels, &stopped)? else { return Ok(()); };
                    if shell_row == Some(selected) {
                        let (reply, response) = std::sync::mpsc::sync_channel(1);
                        if tx.blocking_send(Control::Terminal { reply }).is_err() { return Ok(()); }
                        loop {
                            if stopped.load(Ordering::Acquire) { return Ok(()); }
                            match response.recv_timeout(Duration::from_millis(100)) {
                                Ok(Ok(())) => break,
                                Ok(Err(error)) => { ui::say(&format!("  Shared terminal unavailable: {}", crate::access_ui::terminal_label(&error))); break; }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                                Err(_) => return Ok(()),
                            }
                        }
                        continue;
                    }
                    if selected >= labels.len() - 1 { return Ok(()); } // Close browser.
                    let Some(folder) = folders.get(selected) else { return Ok(()); };
                    let mut actions = vec!["Browse folder".into(), "Read file preview".into()];
                    if crate::platform::folder_download_supported() {
                        actions.push("Download file (up to 1 GiB)".into());
                    }
                    actions.push("Back".into());
                    let Some(action) = crate::access_ui::live_pick("FOLDER ACTION", &actions, &stopped)? else { continue; };
                    if action == actions.len() - 1 { continue; }
                    let Some(input) = crate::access_ui::live_line("relative path [. for folder root]: ", &stopped)? else { continue; };
                    let relative = match relative_path(if input.trim().is_empty() { "." } else { &input }) {
                        Ok(path) => path,
                        Err(error) => { ui::say(&format!("  {error}")); continue; }
                    };
                    let operation = match action {
                        0 => Operation::Browse,
                        1 => Operation::Read,
                        _ => {
                            let Some(directory) = crate::access_ui::live_line("existing local destination directory [.]: ", &stopped)? else { continue; };
                            let directory = PathBuf::from(if directory.trim().is_empty() { "." } else { directory.trim() });
                            let Some(default_name) = relative.file_name().and_then(|name| name.to_str()) else {
                                ui::say("  Choose one regular file to download."); continue;
                            };
                            let Some(name) = crate::access_ui::live_line(&format!("local filename [{default_name}]: "), &stopped)? else { continue; };
                            Operation::Download { directory, name: if name.trim().is_empty() { default_name.to_string() } else { name.trim().to_string() } }
                        }
                    };
                    let (reply, response) = std::sync::mpsc::sync_channel(1);
                    if tx.blocking_send(Control::Folder(Request { folder: folder.clone(), relative, operation, reply })).is_err() { break; }
                    loop {
                        if stopped.load(Ordering::Acquire) { return Ok(()); }
                        match response.recv_timeout(Duration::from_millis(100)) {
                            Ok(Ok(output)) => { show(folder, output)?; break; }
                            Ok(Err(error)) => { ui::say(&format!("  Folder unavailable: {}", crate::access_ui::terminal_label(&error))); break; }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                            Err(_) => return Ok(()),
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result { ui::critical(&format!("  Folder/terminal controls unavailable: {}", crate::access_ui::terminal_label(&error.to_string()))); }
        });
        Self { stop, thread: Some(thread), requests }
    }
    pub(crate) fn try_request(&mut self) -> Option<Control> { self.requests.try_recv().ok() }
}
impl Drop for Controls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn relative_path(input: &str) -> Result<PathBuf> {
    if input.len() > 4096 || input.chars().any(char::is_control) || input.contains(['\\', ':']) { bail!("choose a relative folder path without control characters"); }
    let path = Path::new(input.trim());
    if path.components().any(|component| !matches!(component, Component::Normal(_) | Component::CurDir)) { bail!("path must stay inside the offered folder"); }
    Ok(path.to_path_buf())
}

fn show(folder: &FolderAccess, output: Output) -> Result<()> {
    if let Output::DurabilityUnknown(path) = &output {
        ui::critical(&format!("  Download durability unknown: {} may exist; not reported complete.", crate::access_ui::terminal_label(&path.display().to_string())));
        return Ok(());
    }
    let name = folder.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| folder.id.clone());
    ui::say(&format!("  \u{2713} Folder {} \u{b7} {}", crate::access_ui::terminal_label(&name),
        if folder.mode == filament_peerloop::access::FolderMode::ReadOnly { "read-only" } else { "read & write" }));
    match output {
        Output::Listing(entries) => {
            ui::say(&format!("  Folder entries ({}):", entries.len()));
            for entry in entries {
                let name = mount_proto::path_decode(&entry.name).map_err(|_| anyhow!("invalid folder entry name"))?;
                ui::say(&format!("    {} · {} bytes", crate::access_ui::terminal_label(&name.to_string_lossy()), entry.stat.size));
            }
        }
        Output::Preview { bytes, size } => {
            use sha2::Digest;
            ui::say(&format!("  Read preview: {} of {size} bytes · SHA-256 {}", bytes.len(), hex::encode(sha2::Sha256::digest(&bytes))));
            let escaped = bytes.iter().flat_map(|byte| std::ascii::escape_default(*byte)).map(char::from).collect::<String>();
            ui::say(&format!("  {escaped}"));
        }
        Output::Downloaded(published) => {
            ui::say(&format!("  Download complete: {} · {} bytes · local SHA-256 {}", crate::access_ui::terminal_label(&published.path.display().to_string()), published.bytes, hex::encode(published.sha256)));
        }
        Output::DurabilityUnknown(_) => unreachable!(),
    }
    ui::say("  OS mount and .mesh DNS integration are unavailable; this is not a mounted folder.");
    Ok(())
}

async fn call(client: &mut MountClient, operation: MountOp, cancel: &Cancellation) -> Result<serde_json::Value> {
    let (response, _) = client.call_binary_with_cancel(operation, None, Duration::from_secs(10), cancel).await?;
    match response.result {
        MountResult::Ok(value) => Ok(value),
        MountResult::Err(error) => bail!("folder operation refused ({}): {}", error.code, crate::access_ui::terminal_label(&error.msg)),
    }
}

pub(crate) async fn perform(client: &mut MountClient, request: &Request, cancel: &Cancellation, read_limit: u32) -> Result<Output> {
    let path = mount_proto::path_encode(&request.relative);
    let stat: FileStat = serde_json::from_value(call(client, MountOp::GetAttr { path: path.clone() }, cancel).await?)?;
    let directory = matches!(stat.kind.as_ref(), Some(FileKind::Dir)) || stat.mode & 0o170000 == 0o040000;
    let file = matches!(stat.kind.as_ref(), Some(FileKind::File)) || stat.mode & 0o170000 == 0o100000;
    match &request.operation {
        Operation::Browse if !directory => bail!("choose a directory to browse"),
        Operation::Read | Operation::Download { .. } if !file => bail!("choose a regular file; symlinks and special files are not read"),
        _ => {},
    }
    let opened = call(client, MountOp::Open { path, flags: 0 }, cancel).await?;
    let fh = opened["fh"].as_u64().ok_or_else(|| anyhow!("folder endpoint omitted file handle"))?;
    if let Operation::Download { directory, name } = &request.operation {
        use filament_peerloop::download_output::{OwnedDownload, OutputError};
        let mut output = OwnedDownload::create(directory, name, stat.size, MAX_DOWNLOAD_BYTES, None).await?;
        let mut offset = 0u64;
        while offset < stat.size {
            let amount = (stat.size - offset).min(u64::from(read_limit)) as u32;
            let bytes = client.read_binary(fh, offset, amount, Duration::from_secs(10), cancel).await?;
            if bytes.is_empty() { bail!("file ended before its advertised size; no download was published"); }
            output.write_chunk(&bytes, cancel).await?;
            offset = offset.checked_add(bytes.len() as u64).ok_or_else(|| anyhow!("file byte count overflow"))?;
        }
        // Finish the remote operation before committing local publication. A
        // revoked/failed Release must leave only removable private staging.
        call(client, MountOp::Release { fh }, cancel).await?;
        return match output.finish(cancel).await {
            Ok(published) => Ok(Output::Downloaded(published)),
            Err(OutputError::DurabilityUnknown(path)) => Ok(Output::DurabilityUnknown(path)),
            Err(error) => Err(error.into()),
        };
    }
    let result = match &request.operation {
        Operation::Browse => {
            let value = call(client, MountOp::ReadDir { fh, offset: 0 }, cancel).await?;
            if value.as_array().is_none_or(|entries| entries.len() > 256) { bail!("folder listing exceeds 256 entries; choose a smaller subfolder"); }
            Output::Listing(serde_json::from_value(value)?)
        }
        Operation::Read => {
            let amount = stat.size.min(4096).min(u64::from(read_limit)) as u32;
            let bytes = client.read_binary(fh, 0, amount, Duration::from_secs(10), cancel).await?;
            Output::Preview { bytes, size: stat.size }
        }
        Operation::Download { .. } => unreachable!(),
    };
    call(client, MountOp::Release { fh }, cancel).await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_resource_paths_never_escape_or_become_credentials() {
        for path in ["../secret", "/etc/passwd", "a/../../secret", "C:\\secret", "bad\nname", "file:token"] { assert!(relative_path(path).is_err(), "{path}"); }
        for path in [".", "sub/file.bin", "unicode-文件.txt"] { assert!(relative_path(path).is_ok(), "{path}"); }
    }
}

// Deterministic protocol-level coverage for the recipient operations. A fake
// Transport stands in for the authenticated L2 stream, so these tests exercise
// the exact request sequence, byte counts, publication point and private
// staging without a network, a mount, or a peer.
#[cfg(all(test, feature = "mount-server"))]
mod protocol_tests {
    use super::*;
    use filament_peerloop::access::FolderMode;
    use filament_peerloop::mount_proto::{
        decode_frame, encode_frame, DirEntry, FileStat, MountCaps, MountRequest, MountResponse,
        MountResult, PipeItem, DEFAULT_MOUNT_MAX_SIZE,
    };
    use filament_transport::net::Transport;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use tokio::sync::mpsc;

    struct Requests(mpsc::UnboundedSender<Vec<u8>>);

    #[async_trait::async_trait]
    impl Transport for Requests {
        async fn send_control(&self, _: &Value) -> anyhow::Result<()> { Ok(()) }
        async fn send_frame(&self, _: u32, _: u64, payload: &[u8]) -> anyhow::Result<()> {
            self.0.send(payload.to_vec()).map_err(|_| anyhow!("request receiver closed"))
        }
        async fn flush(&self) -> anyhow::Result<()> { Ok(()) }
        fn max_payload(&self) -> usize { 65536 }
        fn is_dead(&self) -> bool { false }
        fn is_alive(&self) -> bool { true }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!("tunlion-folder-ui-{}-{}",
                std::process::id(), NEXT.fetch_add(1, AtomicOrdering::Relaxed)));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

    fn folder(root: &Path) -> FolderAccess {
        FolderAccess { id: "folder-0".into(), path: root.to_path_buf(), mode: FolderMode::ReadOnly }
    }

    fn start(root: &Path, relative: &str, operation: Operation, cancel: Cancellation)
        -> (tokio::task::JoinHandle<anyhow::Result<Output>>, mpsc::UnboundedReceiver<Vec<u8>>, mpsc::Sender<PipeItem>) {
        let (requests, rx) = mpsc::unbounded_channel();
        let (incoming, stream) = mpsc::channel(64);
        let caps = MountCaps { protocol_version: 2, max_read_size: DEFAULT_MOUNT_MAX_SIZE,
            max_write_size: DEFAULT_MOUNT_MAX_SIZE, ..MountCaps::default() };
        let mut client = MountClient::from_mux_v2_with_mode(Arc::new(Requests(requests)), 7, stream, caps, FolderMode::ReadOnly);
        let request = Request { folder: folder(root), relative: PathBuf::from(relative), operation,
            reply: std::sync::mpsc::sync_channel(1).0 };
        let task = tokio::spawn(async move { perform(&mut client, &request, &cancel, DEFAULT_MOUNT_MAX_SIZE).await });
        (task, rx, incoming)
    }

    async fn next(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> (MountRequest, Option<Bytes>) {
        let frame = rx.recv().await.expect("client sent no request");
        let (header, data) = decode_frame(&frame);
        (serde_json::from_slice(header).expect("request header"), data.map(Bytes::copy_from_slice))
    }

    fn response(id: u64, value: Value, data: Option<&[u8]>) -> Bytes {
        let message = MountResponse { id, bin: data.map(|_| true), result: MountResult::Ok(value) };
        let mut header = serde_json::to_vec(&message).unwrap();
        header.push(b'\n');
        Bytes::from(encode_frame(&header, data))
    }

    fn stat(kind: FileKind, size: u64) -> Value {
        let mode: u32 = match &kind { FileKind::Dir => 0o040755, FileKind::Symlink => 0o120777, _ => 0o100644 };
        serde_json::to_value(FileStat { ino: 1, size, mode, uid: 0, gid: 0, mtime: 0,
            nlink: 1, blocks: 0, blksize: 4096, kind: Some(kind) }).unwrap()
    }

    async fn get_attr(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, tx: &mpsc::Sender<PipeItem>, encoded: &str, value: Value) {
        let (request, _) = next(rx).await;
        assert!(matches!(&request.op, MountOp::GetAttr { path } if path.as_str() == encoded), "unexpected {:?}", request.op);
        tx.send(Some(response(request.id, value, None))).await.unwrap();
    }

    async fn open(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, tx: &mpsc::Sender<PipeItem>, encoded: &str, fh: u64) {
        let (request, _) = next(rx).await;
        assert!(matches!(&request.op, MountOp::Open { path, flags: 0 } if path.as_str() == encoded), "unexpected {:?}", request.op);
        tx.send(Some(response(request.id, json!({"fh": fh}), None))).await.unwrap();
    }

    async fn read(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, tx: &mpsc::Sender<PipeItem>, fh: u64, offset: u64, size: u32, data: &[u8]) {
        let (request, _) = next(rx).await;
        assert!(matches!(&request.op, MountOp::Read { fh: got, offset: got_offset, size: got_size }
            if *got == fh && *got_offset == offset && *got_size == size), "unexpected {:?}", request.op);
        tx.send(Some(response(request.id, json!({"n": data.len()}), Some(data)))).await.unwrap();
    }

    async fn release(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, tx: &mpsc::Sender<PipeItem>, fh: u64) {
        let (request, _) = next(rx).await;
        assert!(matches!(&request.op, MountOp::Release { fh: got } if *got == fh), "unexpected {:?}", request.op);
        tx.send(Some(response(request.id, Value::Null, None))).await.unwrap();
    }

    fn encoded(relative: &str) -> String { mount_proto::path_encode(Path::new(relative)) }

    fn staging_entries(directory: &Path) -> usize {
        std::fs::read_dir(directory).unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().starts_with(".tunlion-download-"))
            .count()
    }

    #[tokio::test]
    async fn browse_binary_empty_preview_download_round_trip_and_no_clobber() {
        if !crate::platform::folder_download_supported() { return; }
        use sha2::Digest;
        let scratch = Scratch::new();
        let destination = scratch.0.join("downloads");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("binary.bin"), b"preserve-existing").unwrap();
        let binary: Vec<u8> = (0..65549).map(|n| (n % 251) as u8).collect();
        let expected = sha2::Sha256::digest(&binary);

        // Browse the exact tree.
        let (task, mut rx, tx) = start(&scratch.0, ".", Operation::Browse, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("."), stat(FileKind::Dir, 0)).await;
        open(&mut rx, &tx, &encoded("."), 1).await;
        let (request, _) = next(&mut rx).await;
        assert!(matches!(&request.op, MountOp::ReadDir { fh: 1, offset: 0 }), "unexpected {:?}", request.op);
        let entries = vec![
            DirEntry { name: encoded("binary.bin"), stat: serde_json::from_value(stat(FileKind::File, binary.len() as u64)).unwrap() },
            DirEntry { name: encoded("empty.bin"), stat: serde_json::from_value(stat(FileKind::File, 0)).unwrap() },
            DirEntry { name: encoded("evil-link"), stat: serde_json::from_value(stat(FileKind::Symlink, 0)).unwrap() },
        ];
        tx.send(Some(response(request.id, serde_json::to_value(&entries).unwrap(), None))).await.unwrap();
        release(&mut rx, &tx, 1).await;
        let Output::Listing(listed) = task.await.unwrap().unwrap() else { panic!("browse did not return a listing") };
        assert_eq!(listed.len(), 3);
        assert_eq!(mount_proto::path_decode(&listed[0].name).unwrap(), PathBuf::from("binary.bin"));

        // Binary preview keeps every byte, including NUL and newline.
        let (task, mut rx, tx) = start(&scratch.0, "binary.bin", Operation::Read, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("binary.bin"), stat(FileKind::File, binary.len() as u64)).await;
        open(&mut rx, &tx, &encoded("binary.bin"), 2).await;
        read(&mut rx, &tx, 2, 0, 4096, &binary[..4096]).await;
        release(&mut rx, &tx, 2).await;
        let Output::Preview { bytes, size } = task.await.unwrap().unwrap() else { panic!("read did not return a preview") };
        assert_eq!(bytes.as_ref(), &binary[..4096]);
        assert_eq!(size, binary.len() as u64);

        // Empty preview is a real zero-byte read, not a fabricated success.
        let (task, mut rx, tx) = start(&scratch.0, "empty.bin", Operation::Read, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("empty.bin"), stat(FileKind::File, 0)).await;
        open(&mut rx, &tx, &encoded("empty.bin"), 3).await;
        read(&mut rx, &tx, 3, 0, 0, &[]).await;
        release(&mut rx, &tx, 3).await;
        let Output::Preview { bytes, size } = task.await.unwrap().unwrap() else { panic!("empty read did not return a preview") };
        assert!(bytes.is_empty());
        assert_eq!(size, 0);

        // Download round-trip: exact bytes and hash, existing name preserved,
        // and nothing is linked under the destination name before the remote
        // Release succeeds.
        let (task, mut rx, tx) = start(&scratch.0, "binary.bin",
            Operation::Download { directory: destination.clone(), name: "binary.bin".into() }, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("binary.bin"), stat(FileKind::File, binary.len() as u64)).await;
        open(&mut rx, &tx, &encoded("binary.bin"), 4).await;
        let mut offset = 0usize;
        while offset < binary.len() {
            let end = (offset + DEFAULT_MOUNT_MAX_SIZE as usize).min(binary.len());
            read(&mut rx, &tx, 4, offset as u64, (end - offset) as u32, &binary[offset..end]).await;
            offset = end;
        }
        let (request, _) = next(&mut rx).await;
        assert!(matches!(&request.op, MountOp::Release { fh: 4 }), "unexpected {:?}", request.op);
        assert!(!destination.join("binary.bin-1").exists(), "published before the remote Release");
        assert_eq!(staging_entries(&destination), 1, "expected exactly one private staging file");
        tx.send(Some(response(request.id, Value::Null, None))).await.unwrap();
        let Output::Downloaded(published) = task.await.unwrap().unwrap() else { panic!("download did not publish") };
        // Windows reports the canonical Win32 spelling of the same file (the
        // publisher strips the verbatim prefix); assert the published NAME and
        // the no-clobber result rather than one platform's path rendering.
        assert_eq!(published.path.file_name().and_then(|n| n.to_str()), Some("binary.bin-1"));
        assert!(destination.join("binary.bin-1").exists());
        assert_eq!(published.bytes, binary.len() as u64);
        assert_eq!(published.sha256.as_slice(), expected.as_slice());
        assert_eq!(std::fs::read(&published.path).unwrap(), binary);
        assert_eq!(std::fs::read(destination.join("binary.bin")).unwrap(), b"preserve-existing");
        // Owner-only staging is asserted by download_output's core test; the
        // portable metadata API here cannot express POSIX mode bits.
        assert_eq!(staging_entries(&destination), 0, "successful publish left private staging");

        // Empty download publishes an exact zero-byte file.
        let (task, mut rx, tx) = start(&scratch.0, "empty.bin",
            Operation::Download { directory: destination.clone(), name: "empty.bin".into() }, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("empty.bin"), stat(FileKind::File, 0)).await;
        open(&mut rx, &tx, &encoded("empty.bin"), 5).await;
        release(&mut rx, &tx, 5).await;
        let Output::Downloaded(published) = task.await.unwrap().unwrap() else { panic!("empty download did not publish") };
        assert_eq!(published.path.file_name().and_then(|n| n.to_str()), Some("empty.bin"));
        assert!(destination.join("empty.bin").exists());
        assert_eq!(published.bytes, 0);
        assert_eq!(std::fs::metadata(&published.path).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn symlink_and_short_reads_are_refused_before_any_local_publication() {
        if !crate::platform::folder_download_supported() { return; }
        let scratch = Scratch::new();
        let destination = scratch.0.join("downloads");
        std::fs::create_dir(&destination).unwrap();

        let (task, mut rx, tx) = start(&scratch.0, "evil-link", Operation::Read, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("evil-link"), stat(FileKind::Symlink, 4)).await;
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("symlinks"), "{error}");
        assert!(rx.recv().await.is_none(), "a symlink was opened after the kind check");
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);

        // The peer claims five bytes but ends after three: no local file.
        let (task, mut rx, tx) = start(&scratch.0, "short.bin",
            Operation::Download { directory: destination.clone(), name: "short.bin".into() }, Cancellation::default());
        get_attr(&mut rx, &tx, &encoded("short.bin"), stat(FileKind::File, 5)).await;
        open(&mut rx, &tx, &encoded("short.bin"), 6).await;
        read(&mut rx, &tx, 6, 0, 5, b"abc").await;
        read(&mut rx, &tx, 6, 3, 2, b"").await;
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("advertised size"), "{error}");
        // Name what is left, so a platform-specific leftover is diagnosable
        // from the failure line alone (a Windows run could not say which).
        let left: Vec<String> = std::fs::read_dir(&destination).unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                format!("{} ({len} bytes)", entry.file_name().to_string_lossy())
            })
            .collect();
        assert!(left.is_empty(), "short read left a local name or staging file: {left:?}");
    }

    #[tokio::test]
    async fn cancellation_during_read_leaves_no_name_or_private_staging() {
        if !crate::platform::folder_download_supported() { return; }
        let scratch = Scratch::new();
        let destination = scratch.0.join("downloads");
        std::fs::create_dir(&destination).unwrap();
        let cancel = Cancellation::default();
        let (task, mut rx, tx) = start(&scratch.0, "big.bin",
            Operation::Download { directory: destination.clone(), name: "big.bin".into() }, cancel.clone());
        get_attr(&mut rx, &tx, &encoded("big.bin"), stat(FileKind::File, 4096)).await;
        open(&mut rx, &tx, &encoded("big.bin"), 7).await;
        // The read is outstanding when the scope is revoked/cancelled.
        let (request, _) = next(&mut rx).await;
        assert!(matches!(&request.op, MountOp::Read { fh: 7, .. }));
        cancel.cancel();
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("cancelled"), "{error}");
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
        assert!(!destination.join("big.bin").exists());
    }

    /// Windows-specific recipient contract: the validated publisher exists, so
    /// the CLI advertises Download, and no peer-facing relative path can turn
    /// into a drive, UNC or backslash path.
    #[cfg(all(target_os = "windows", feature = "mount-server"))]
    #[test]
    fn windows_download_is_offered_and_peer_paths_cannot_become_local_paths() {
        assert!(crate::platform::folder_download_supported());
        for path in [r"C:\secret", r"\\server\share", r"sub\file.bin", "C:/secret", "file:stream"] {
            assert!(relative_path(path).is_err(), "accepted Windows-looking path {path:?}");
        }
        assert!(relative_path("sub/file.bin").is_ok());
    }
}
