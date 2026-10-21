//! Durable file offers beside the access-consent queue.
//!
//! This adapter is deliberately separate from the consent queue and from the
//! access-request store in `main.rs`: the two queues use different files (see
//! `store_dir`), different id spaces, and different actions. `approve`/`deny`
//! remain access consent; `accept`/`decline` act only on this store.
//!
//! The store is file-backed and cross-process locked, so a CLI process can read
//! and write it without a running daemon. Everything that decides whether a
//! sender may still act (certificate, revocation, delegated scope) is asked of
//! the shared engine adapter, never re-derived here.

use crate::ui::{self, Tone};
use anyhow::{anyhow, bail, Context, Result};
use filament_peerloop::host::HostServices;
use filament_peerloop::recv::request_delivery;
use filament_peerloop::recv::requests::{
    ManifestEntry, RequestError, RequestEvent, RequestRecord, RequestState, RequestStore,
    SenderIdentity, Snapshot, REQUESTS_FILE,
};
use std::path::{Component, Path, PathBuf};

/// The store's own directory under the config root. It must never be the config
/// root itself: the access-consent queue already owns `requests.json` there, in
/// a different JSON shape (`Vec<PendingRequest>` vs `DiskState`).
pub(crate) fn store_dir() -> PathBuf {
    crate::settings::config_dir().join(request_delivery::DIRECTORY)
}

/// The exact file the durable store writes.
pub(crate) fn store_path() -> PathBuf {
    store_dir().join(REQUESTS_FILE)
}

fn store_exists() -> Result<bool> {
    // `exists`, not `is_file`: a directory left at this path is damage that must
    // be reported by the store reader, not hidden as "no offers".
    match std::fs::metadata(store_path()) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow!(
            "cannot read transfer request store at {}: {error}",
            store_path().display()
        )),
    }
}

fn open_store() -> Result<RequestStore> {
    let host = crate::host_impl::CliHost;
    request_delivery::store(&host)
        .with_context(|| format!("cannot open transfer request store at {}", store_dir().display()))
}

fn now_secs() -> u64 {
    crate::capability::now_secs()
}

fn store_error(error: RequestError, path: &Path) -> anyhow::Error {
    match error {
        RequestError::Corrupt(message) => anyhow!(
            "transfer request store at {} is corrupt: {message}. Nothing was read as empty and nothing was overwritten; fix it or move it aside.",
            path.display()
        ),
        RequestError::Storage(message) => anyhow!(
            "transfer request store at {}: {message}",
            path.display()
        ),
        other => anyhow!(other),
    }
}

fn read_snapshot(
    store: &RequestStore,
    expire_now: Option<u64>,
) -> Result<(Snapshot, Vec<RequestEvent>)> {
    let path = store.store_path();
    let mut events = Vec::new();
    if let Some(now) = expire_now {
        events = store
            .expire(now)
            .map_err(|error| store_error(error, &path))?;
    }
    let snapshot = store
        .snapshot(None)
        .map_err(|error| store_error(error, &path))?;
    Ok((snapshot, events))
}

fn notify_events(events: &[RequestEvent]) {
    let host = crate::host_impl::CliHost;
    for event in events {
        host.transfer_request_event(event);
    }
}

fn find_record(store: &RequestStore, id: u64) -> Result<RequestRecord> {
    read_snapshot(store, None)?
        .0
        .requests
        .into_iter()
        .find(|record| record.id == id)
        .ok_or_else(|| {
            anyhow!("no transfer offer {id}; `tunlion requests` lists the file offers")
        })
}

fn is_active(state: RequestState) -> bool {
    matches!(
        state,
        RequestState::Pending | RequestState::Approved | RequestState::Delivering
    )
}

fn state_label(state: RequestState) -> &'static str {
    match state {
        RequestState::Pending => "pending",
        RequestState::Approved => "approved",
        RequestState::Delivering => "delivering",
        RequestState::Denied => "denied",
        RequestState::Expired => "expired",
        RequestState::Fulfilled => "fulfilled",
        RequestState::Failed => "failed",
        RequestState::Withdrawn => "withdrawn",
    }
}

/// The wire currently offers one file. Reject wider manifests here rather than
/// binding a destination this command cannot honestly describe.
fn single_entry(record: &RequestRecord) -> Result<&ManifestEntry> {
    if record.manifest.count != 1 || record.manifest.entries.len() != 1 {
        bail!(
            "this offer has {} files; offers with more than one file are not supported yet",
            record.manifest.count
        );
    }
    let entry = &record.manifest.entries[0];
    let path = Path::new(entry.path.as_str());
    if path.is_absolute()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        bail!("this offer's path is not a plain file name; nested paths are not supported yet");
    }
    Ok(entry)
}

/// `--to` is a file NAME under the configured drop directory, never a path.
fn file_name_arg(to: &Path) -> Result<String> {
    if to.as_os_str().is_empty() {
        bail!("--to needs a file name");
    }
    if to.is_absolute() || to.components().count() != 1 {
        bail!(
            "--to takes a file name, not a path; the file always lands in the configured drop directory"
        );
    }
    let name = to
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("--to must be a plain UTF-8 file name"))?;
    if name.is_empty() || name == "." || name == ".." {
        bail!("--to needs a file name");
    }
    let clean = filament_transfer::safe_incoming_name(name);
    if clean != name {
        bail!("--to must be a plain file name; {name:?} is normalized to {clean:?}");
    }
    Ok(name.to_string())
}

/// Resolve the exact final file path. Default: the first free name in the drop
/// directory derived from the offer's single path. `--to`: that exact name.
fn destination_for(root: &Path, record: &RequestRecord, to: Option<&Path>) -> Result<PathBuf> {
    let entry = single_entry(record)?;
    // A re-run of accept on an already-approved offer must keep the destination
    // it bound, not pick a new free name because the file now exists.
    if record.state == RequestState::Approved {
        if let Some(existing) = record.destination.as_deref() {
            let existing = request_delivery::confined_destination(root, Path::new(existing))?;
            match to {
                None => return Ok(existing),
                Some(to) => {
                    let name = file_name_arg(to)?;
                    if existing.file_name().and_then(|file_name| file_name.to_str())
                        == Some(name.as_str())
                    {
                        return Ok(existing);
                    }
                    bail!(
                        "transfer offer is already accepted at {}; decline it first to choose a different destination",
                        existing.display()
                    );
                }
            }
        }
    }
    let candidate = match to {
        Some(name) => {
            let name = file_name_arg(name)?;
            let candidate = root.join(name);
            if candidate.exists() {
                bail!(
                    "destination {} already exists; choose another name with --to",
                    candidate.display()
                );
            }
            candidate
        }
        None => filament_peerloop::recv::unique_path(root, entry.path.as_str()),
    };
    request_delivery::confined_destination(root, &candidate)
}

fn action_error(error: RequestError, id: u64, path: &Path) -> anyhow::Error {
    match error {
        RequestError::NotFound(_) => {
            anyhow!("no transfer offer {id}; `tunlion requests` lists the file offers")
        }
        RequestError::RevisionConflict { .. } => anyhow!(
            "transfer offer {id} changed since it was listed; run `tunlion requests` again"
        ),
        RequestError::InvalidState { state, .. } => anyhow!(
            "transfer offer {id} is {state}; there is nothing to accept or decline"
        ),
        RequestError::OfferExpired(_) => {
            anyhow!("transfer offer {id} expired; ask the sender to send it again")
        }
        RequestError::SenderRefused(reason) => {
            anyhow!("cannot accept transfer offer {id}: {reason}")
        }
        RequestError::InvalidDestination => anyhow!(
            "that destination is not usable; the file must land directly in the configured drop directory and must not already be used by another offer"
        ),
        other => store_error(other, path),
    }
}

fn files_word(count: usize) -> &'static str {
    if count == 1 {
        "file"
    } else {
        "files"
    }
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if value < KIB * KIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else {
        format!("{:.1} GiB", value / (KIB * KIB * KIB))
    }
}

fn sender_label(sender: &SenderIdentity) -> String {
    if let Ok(bytes) = hex::decode(&sender.device_id) {
        if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
            if let Some(name) = crate::device_name_for_pub(&key) {
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    let short: String = sender.device_id.chars().take(8).collect();
    if short.is_empty() {
        "unknown sender".to_string()
    } else {
        format!("device {short}…")
    }
}

fn summary(record: &RequestRecord) -> String {
    format!(
        "{} {} · {}",
        record.manifest.count,
        files_word(record.manifest.count),
        human_bytes(record.manifest.total_bytes)
    )
}

fn accept_text(record: &RequestRecord, destination: &Path) -> String {
    format!(
        "  {} accepted transfer offer {} from {}: {}\n    destination: {}\n    waiting for the sender to send it again; nothing has been received yet",
        ui::paint(Tone::Ok, ui::glyph_ok()),
        record.id,
        sender_label(&record.sender),
        summary(record),
        destination.display()
    )
}

fn decline_text(record: &RequestRecord, already: bool) -> String {
    format!(
        "  {} {} transfer offer {} from {}; the offer is recorded as declined and will not be accepted",
        ui::paint(Tone::Ok, ui::glyph_ok()),
        if already { "already declined" } else { "declined" },
        record.id,
        sender_label(&record.sender)
    )
}

/// One row in the durable file-offer section.
struct TransferEntry {
    id: u64,
    state: RequestState,
    sender: String,
    age: String,
    files: usize,
    bytes: u64,
    digest: String,
    names: Vec<String>,
    destination: Option<String>,
    rev: u64,
}

fn entry(record: &RequestRecord) -> TransferEntry {
    TransferEntry {
        id: record.id,
        state: record.state,
        sender: sender_label(&record.sender),
        age: crate::request_ago(record.created_at),
        files: record.manifest.count,
        bytes: record.manifest.total_bytes,
        digest: record.manifest.digest.clone(),
        names: record
            .manifest
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect(),
        destination: record.destination.clone(),
        rev: record.rev,
    }
}

fn render(entries: &[TransferEntry]) -> String {
    let count = entries.len();
    let mut lines = vec![
        format!(
            "  {}",
            ui::paint(
                Tone::Bold,
                &format!("{count} file offer{}", if count == 1 { "" } else { "s" })
            )
        ),
        format!(
            "  {}",
            ui::paint(Tone::Dim, "durable transfer offers (not access grants)")
        ),
        String::new(),
    ];

    for entry in entries {
        lines.push(format!(
            "  {}  {}  {}",
            ui::paint(Tone::Bold, &format!("#{}", entry.id)),
            ui::paint(Tone::Warn, &entry.sender),
            ui::paint(Tone::Dim, state_label(entry.state))
        ));
        lines.push(format!(
            "     asked {} · {} {} · {}",
            entry.age,
            entry.files,
            files_word(entry.files),
            human_bytes(entry.bytes)
        ));
        lines.push(format!("     sha256 {}", entry.digest));
        lines.push(format!(
            "     {}: {}",
            files_word(entry.files),
            entry.names.join(", ")
        ));
        if let Some(destination) = entry.destination.as_deref() {
            lines.push(format!("     destination: {destination}"));
        }
        match entry.state {
            RequestState::Pending => lines.push(format!(
                "     [ {} ]   [ {} ]",
                ui::paint(
                    Tone::Bold,
                    &format!("tunlion requests accept {} --rev {}", entry.id, entry.rev)
                ),
                ui::paint(
                    Tone::Dim,
                    &format!("tunlion requests decline {} --rev {}", entry.id, entry.rev)
                )
            )),
            RequestState::Approved => lines.push(format!(
                "     {}",
                ui::paint(
                    Tone::Dim,
                    "accepted; waiting for the sender to send it again. Nothing has been received yet."
                )
            )),
            RequestState::Delivering => {
                lines.push(format!("     {}", ui::paint(Tone::Dim, "receiving now")))
            }
            _ => {}
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Append the durable file-offer section. No store file (or no identity and no
/// store) means "nothing to add", which keeps the existing access list working.
/// A store that exists but cannot be read is an error, never an empty list.
pub(crate) fn say_section(all: bool) -> Result<()> {
    if !store_exists()? {
        return Ok(());
    }
    let store = open_store()?;
    let (snapshot, events) = read_snapshot(&store, Some(now_secs()))?;
    notify_events(&events);
    let entries: Vec<TransferEntry> = snapshot
        .requests
        .iter()
        .filter(|record| all || is_active(record.state))
        .map(entry)
        .collect();
    if entries.is_empty() {
        return Ok(());
    }
    ui::say(&render(&entries));
    Ok(())
}

/// The inbox the running daemon actually serves. `up --dir` records its root in
/// `up.inbox`; the configured drop dir is only the fallback when no daemon has
/// ever recorded one. Approving under the configured dir while the daemon served
/// another root made every sender retry fail the receive-root confinement check.
fn receiver_root() -> PathBuf {
    if let Ok(raw) = std::fs::read_to_string(crate::recv_files::daemon_inbox_marker()) {
        let recorded = PathBuf::from(raw.trim());
        if !recorded.as_os_str().is_empty() {
            return recorded;
        }
    }
    crate::drop_dir(None)
}

/// Accept one durable offer. The sender's current authority is re-observed by
/// the shared adapter; nothing from the stored snapshot is treated as a grant.
pub(crate) fn accept(id: u64, to: Option<&Path>, rev: Option<u64>) -> Result<()> {
    if !store_exists()? {
        bail!("no transfer offer {id}; `tunlion requests` lists the file offers");
    }
    let store = open_store()?;
    let record = find_record(&store, id)?;
    if !matches!(record.state, RequestState::Pending | RequestState::Approved) {
        bail!(
            "transfer offer {id} is {}; there is nothing to accept",
            state_label(record.state)
        );
    }
    let destination = destination_for(&receiver_root(), &record, to)?;
    let destination_text = destination
        .to_str()
        .ok_or_else(|| anyhow!("destination path is not valid UTF-8"))?;
    let host = crate::host_impl::CliHost;
    let sender = request_delivery::current_sender(&host, &record.sender.device_id)
        .with_context(|| format!("cannot verify the sender of transfer offer {id}"))?;
    let expected = rev.unwrap_or(record.rev);
    let (accepted, event) = store
        .accept(id, expected, destination_text, &sender, now_secs())
        .map_err(|error| action_error(error, id, &store.store_path()))?;
    if let Some(event) = event {
        host.transfer_request_event(&event);
    }
    ui::say(&accept_text(&accepted, &destination));
    Ok(())
}

/// Decline one durable offer. This is a local owner action, so no sender
/// observation is needed; the store retains the terminal record.
pub(crate) fn decline(id: u64, rev: Option<u64>) -> Result<()> {
    if !store_exists()? {
        bail!("no transfer offer {id}; `tunlion requests` lists the file offers");
    }
    let store = open_store()?;
    let record = find_record(&store, id)?;
    let already = record.state == RequestState::Denied;
    if !already && !matches!(record.state, RequestState::Pending | RequestState::Approved) {
        bail!(
            "transfer offer {id} is {}; there is nothing to decline",
            state_label(record.state)
        );
    }
    let expected = rev.unwrap_or(record.rev);
    let (declined, event) = store
        .decline(id, expected, now_secs())
        .map_err(|error| action_error(error, id, &store.store_path()))?;
    if let Some(event) = event {
        let host = crate::host_impl::CliHost;
        host.transfer_request_event(&event);
    }
    ui::say(&decline_text(&declined, already));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_peerloop::recv::requests::{
        canonical_manifest, CanonicalManifest, Limits, SenderRelation,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "tunlion-transfer-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn with_config_dir<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        let _guard = crate::tests::lock_test_config();
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                // SAFETY: the shared config lock is held for this scope.
                unsafe { std::env::remove_var("TUNLION_CONFIG_DIR") };
            }
        }
        // SAFETY: the shared config lock is held for this scope.
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", dir) };
        let _restore = Restore;
        f()
    }

    fn manifest(entries: &[(&str, u64)]) -> CanonicalManifest {
        let entries: Vec<ManifestEntry> = entries
            .iter()
            .map(|(path, size)| ManifestEntry {
                path: (*path).to_string(),
                size: *size,
                sha256: "a".repeat(64),
                mtime: 0,
            })
            .collect();
        canonical_manifest(&entries, &Limits::default()).unwrap()
    }

    fn record(
        entries: &[(&str, u64)],
        state: RequestState,
        destination: Option<&str>,
    ) -> RequestRecord {
        RequestRecord {
            id: 7,
            offer_id: "offer-7".to_string(),
            kind: "transfer".to_string(),
            sender: SenderIdentity {
                device_id: "aa".repeat(32),
                user_id: "bb".repeat(32),
                relation: SenderRelation::PairedExternal,
                verified: true,
                known: true,
                revoked: false,
                expires_at: None,
                is_primary: false,
            },
            manifest: manifest(entries),
            state,
            destination: destination.map(str::to_string),
            created_at: 1_000,
            updated_at: 1_010,
            expires_at: 2_000,
            rev: 3,
        }
    }

    fn root(tag: &str) -> (TempDir, PathBuf) {
        let dir = temp_dir(tag);
        let root = std::fs::canonicalize(&dir.0).unwrap();
        (dir, root)
    }

    fn row(state: RequestState, destination: Option<&str>) -> TransferEntry {
        TransferEntry {
            id: 7,
            state,
            sender: "carol".to_string(),
            age: "1m ago".to_string(),
            files: 1,
            bytes: 1536,
            digest: "a".repeat(64),
            names: vec!["report.pdf".to_string()],
            destination: destination.map(str::to_string),
            rev: 3,
        }
    }

    #[test]
    fn the_transfer_store_is_not_the_access_request_file() {
        let dir = temp_dir("paths");
        with_config_dir(&dir.0, || {
            assert_eq!(store_dir(), dir.0.join(request_delivery::DIRECTORY));
            assert_eq!(
                store_path(),
                dir.0
                    .join(request_delivery::DIRECTORY)
                    .join(REQUESTS_FILE)
            );
            assert_ne!(store_path(), dir.0.join("requests.json"));
            assert!(!store_exists().unwrap());
        });
    }

    #[test]
    fn an_empty_or_missing_store_keeps_the_access_list_working_without_an_owner() {
        let dir = temp_dir("empty");
        with_config_dir(&dir.0, || {
            assert_ne!(store_path(), dir.0.join("requests.json"));
            assert!(say_section(false).is_ok());
        });
    }

    #[test]
    fn accept_and_decline_do_not_create_state_when_no_offer_exists() {
        let dir = temp_dir("no-store");
        with_config_dir(&dir.0, || {
            let accept_error = accept(7, None, None).unwrap_err();
            assert!(
                format!("{accept_error}").contains("no transfer offer 7"),
                "{accept_error}"
            );
            let decline_error = decline(7, None).unwrap_err();
            assert!(
                format!("{decline_error}").contains("no transfer offer 7"),
                "{decline_error}"
            );
            assert!(
                !store_dir().exists(),
                "a failed action created the transfer store directory"
            );
        });
    }

    #[test]
    fn reset_removes_the_transfer_request_directory() {
        let dir = temp_dir("reset");
        let transfer = dir.0.join(request_delivery::DIRECTORY);
        std::fs::create_dir_all(&transfer).unwrap();
        std::fs::write(transfer.join(REQUESTS_FILE), b"{}").unwrap();

        let outcome = crate::mount_cmd::reset_state_in(&dir.0, &crate::reset_remove);
        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
        assert!(!transfer.exists(), "transfer-requests survived reset");
    }

    #[test]
    fn default_destination_is_a_unique_final_file_under_the_drop_root() {
        let (_dir, root) = root("default");
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        let record = record(&[("a.txt", 3)], RequestState::Pending, None);

        let destination = destination_for(&root, &record, None).unwrap();
        assert_eq!(destination.parent(), Some(root.as_path()));
        assert_eq!(
            destination.file_name().unwrap().to_string_lossy(),
            "a (1).txt"
        );
    }

    #[test]
    fn explicit_destination_is_exactly_one_name_under_the_root() {
        let (_dir, root) = root("explicit");
        let record = record(&[("a.txt", 3)], RequestState::Pending, None);

        let destination =
            destination_for(&root, &record, Some(Path::new("chosen.bin"))).unwrap();
        assert_eq!(destination, root.join("chosen.bin"));

        std::fs::write(root.join("chosen.bin"), b"x").unwrap();
        assert!(destination_for(&root, &record, Some(Path::new("chosen.bin"))).is_err());
        assert!(
            destination_for(&root, &record, Some(Path::new("sub/chosen.bin"))).is_err(),
            "a path is not a file name"
        );
        assert!(
            destination_for(&root, &record, Some(Path::new("../escape"))).is_err(),
            "traversal must be refused"
        );
    }

    #[test]
    fn approved_accept_keeps_the_destination_it_bound() {
        let (_dir, root) = root("approved");
        let bound = root.join("report.pdf");
        let record = record(
            &[("report.pdf", 3)],
            RequestState::Approved,
            Some(bound.to_str().unwrap()),
        );

        let destination = destination_for(&root, &record, None).unwrap();
        assert_eq!(destination, bound);
    }

    #[test]
    fn approved_accept_with_the_same_name_is_idempotent_and_a_different_one_is_refused() {
        let (_dir, root) = root("approved-to");
        let bound = root.join("report.pdf");
        let record = record(
            &[("report.pdf", 3)],
            RequestState::Approved,
            Some(bound.to_str().unwrap()),
        );

        assert_eq!(
            destination_for(&root, &record, Some(Path::new("report.pdf"))).unwrap(),
            bound
        );
        assert!(
            destination_for(&root, &record, Some(Path::new("other.pdf"))).is_err(),
            "an approved offer keeps the destination it bound"
        );
    }

    #[test]
    fn one_file_only_and_plain_names_only_for_now() {
        let (_dir, root) = root("shape");
        let wide = record(
            &[("a.txt", 3), ("b.txt", 4)],
            RequestState::Pending,
            None,
        );
        assert!(destination_for(&root, &wide, None).is_err());

        let nested = record(&[("sub/a.txt", 3)], RequestState::Pending, None);
        assert!(destination_for(&root, &nested, None).is_err());
    }

    #[test]
    fn pending_section_shows_the_exact_facts_and_both_hints() {
        let text = render(&[row(RequestState::Pending, None)]);
        for needle in [
            "#7",
            "carol",
            "pending",
            "1 file",
            "1.5 KiB",
            "sha256",
            "report.pdf",
            "requests accept 7 --rev 3",
            "requests decline 7 --rev 3",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
    }

    #[test]
    fn approved_section_says_waiting_and_offers_no_accept_hint() {
        let text = render(&[row(RequestState::Approved, Some("/inbox/report.pdf"))]);
        assert!(text.contains("waiting for the sender"), "{text}");
        assert!(text.contains("destination: /inbox/report.pdf"), "{text}");
        assert!(!text.contains("requests accept"), "{text}");
    }

    #[test]
    fn only_active_rows_show_without_all() {
        assert!(is_active(RequestState::Pending));
        assert!(is_active(RequestState::Approved));
        assert!(is_active(RequestState::Delivering));
        assert!(!is_active(RequestState::Denied));
        assert!(!is_active(RequestState::Expired));
        assert!(!is_active(RequestState::Fulfilled));
        assert!(!is_active(RequestState::Failed));
        assert!(!is_active(RequestState::Withdrawn));
    }

    #[test]
    fn a_corrupt_transfer_store_is_reported_with_its_path() {
        let dir = temp_dir("corrupt");
        let store = RequestStore::open(dir.0.clone(), "owner", Limits::default()).unwrap();
        std::fs::write(store.store_path(), b"{not json").unwrap();

        let error = read_snapshot(&store, None).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("corrupt"), "{text}");
        assert!(text.contains("requests.json"), "{text}");
    }

    #[test]
    fn human_bytes_is_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MiB");
    }
}
