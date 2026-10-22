//! Recipient folder UI and bounded previews over the shared mount protocol.
//! No OS mount, DNS integration, or download publication is implied by a label.
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use filament_peerloop::access::{AgreementSnapshot, FolderAccess};
use filament_peerloop::driver::Cancellation;
use filament_peerloop::mount_proto::{self, DirEntry, FileKind, FileStat, MountClient, MountOp, MountResult};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

const MAX_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) enum Operation { Browse, Read, Download { directory: PathBuf, name: String } }
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

pub(crate) struct Controls {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    requests: tokio::sync::mpsc::Receiver<Request>,
}
impl Controls {
    pub(crate) fn start(snapshot: &AgreementSnapshot) -> Self {
        let folders = snapshot.spec.folders.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (tx, requests) = tokio::sync::mpsc::channel(4);
        let thread = std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                while !stopped.load(Ordering::Acquire) {
                    let mut labels = folders.iter().map(|folder| format!("{} · {}", folder.id,
                        if folder.mode == filament_peerloop::access::FolderMode::ReadOnly { "read-only" } else { "read/write" })).collect::<Vec<_>>();
                    labels.push("Close folder browser".into());
                    let Some(selected) = crate::access_ui::live_pick("FOLDERS · endpoint checked on use", &labels, &stopped)? else { break; };
                    let Some(folder) = folders.get(selected) else { break; };
                    let mut actions = vec!["Browse folder".into(), "Read file preview".into()];
                    #[cfg(all(target_os = "linux", feature = "mount-server"))]
                    actions.push("Download file (up to 1 GiB)".into());
                    actions.push("Back".into());
                    let Some(action) = crate::access_ui::live_pick("FOLDER ACTION", &actions, &stopped)? else { continue; };
                    if action == actions.len() - 1 { continue; }
                    let Some(input) = crate::access_ui::live_line("relative path [. for folder root]: ", &stopped)? else { continue; };
                    let relative = match relative_path(if input.trim().is_empty() { "." } else { &input }) {
                        Ok(path) => path,
                        Err(error) => { eprintln!("  {error}"); continue; }
                    };
                    let operation = match action {
                        0 => Operation::Browse,
                        1 => Operation::Read,
                        _ => {
                            let Some(directory) = crate::access_ui::live_line("existing local destination directory [.]: ", &stopped)? else { continue; };
                            let directory = PathBuf::from(if directory.trim().is_empty() { "." } else { directory.trim() });
                            let Some(default_name) = relative.file_name().and_then(|name| name.to_str()) else {
                                eprintln!("  Choose one regular file to download."); continue;
                            };
                            let Some(name) = crate::access_ui::live_line(&format!("local filename [{default_name}]: "), &stopped)? else { continue; };
                            Operation::Download { directory, name: if name.trim().is_empty() { default_name.to_string() } else { name.trim().to_string() } }
                        }
                    };
                    let (reply, response) = std::sync::mpsc::sync_channel(1);
                    if tx.blocking_send(Request { folder: folder.clone(), relative, operation, reply }).is_err() { break; }
                    loop {
                        if stopped.load(Ordering::Acquire) { return Ok(()); }
                        match response.recv_timeout(Duration::from_millis(100)) {
                            Ok(Ok(output)) => { show(folder, output)?; break; }
                            Ok(Err(error)) => { eprintln!("  Folder unavailable: {}", crate::access_ui::terminal_label(&error)); break; }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                            Err(_) => return Ok(()),
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result { eprintln!("  Folder browser unavailable: {}", crate::access_ui::terminal_label(&error.to_string())); }
        });
        Self { stop, thread: Some(thread), requests }
    }
    pub(crate) fn try_request(&mut self) -> Option<Request> { self.requests.try_recv().ok() }
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
    if let Output::DurabilityUnknown(path) = output {
        eprintln!("  Download durability unknown: {} may exist; not reported complete.", crate::access_ui::terminal_label(&path.display().to_string()));
        return Ok(());
    }
    eprintln!("  Folder endpoint ready · {} · {}", crate::access_ui::terminal_label(&folder.id),
        if folder.mode == filament_peerloop::access::FolderMode::ReadOnly { "read-only" } else { "read/write" });
    match output {
        Output::Listing(entries) => {
            eprintln!("  Folder entries ({}):", entries.len());
            for entry in entries {
                let name = mount_proto::path_decode(&entry.name).map_err(|_| anyhow!("invalid folder entry name"))?;
                eprintln!("    {} · {} bytes", crate::access_ui::terminal_label(&name.to_string_lossy()), entry.stat.size);
            }
        }
        Output::Preview { bytes, size } => {
            use sha2::Digest;
            eprintln!("  Read preview: {} of {size} bytes · SHA-256 {}", bytes.len(), hex::encode(sha2::Sha256::digest(&bytes)));
            let escaped = bytes.iter().flat_map(|byte| std::ascii::escape_default(*byte)).map(char::from).collect::<String>();
            eprintln!("  {escaped}");
        }
        Output::Downloaded(published) => {
            eprintln!("  Download complete: {} · {} bytes · local SHA-256 {}", crate::access_ui::terminal_label(&published.path.display().to_string()), published.bytes, hex::encode(published.sha256));
        }
        Output::DurabilityUnknown(_) => unreachable!(),
    }
    eprintln!("  OS mount and .mesh DNS integration are unavailable; this is not a mounted folder.");
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
