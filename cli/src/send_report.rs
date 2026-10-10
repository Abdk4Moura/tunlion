//! `tunlion send --json`: one result object on stdout.
//!
//! `send_cmd` is a long event loop with many exits, so rather than thread a
//! report through every one of them it records what it is sending here, once
//! when the list is built and again when every transfer reached a terminal
//! state, and the dispatch arm turns that into the result object after the
//! verb returns, success or failure.
//!
//! The shape (one object, always):
//!
//! ```json
//! {"ok": true, "verb": "send", "peer": "laptop",
//!  "file": "a.txt", "bytes": 12, "sha256": "…",
//!  "files": [{"file": "a.txt", "bytes": 12, "sha256": "…", "delivered": true, "declined": false}]}
//! ```
//!
//! `file` and `sha256` are top-level when exactly one file was sent; `bytes`
//! is always the total; `files` always lists every one. `sha256` is the
//! whole-file digest the receiver verified before acknowledging. On failure
//! `ok` is false and `error` carries `{code, exit, message}` (exit_codes.rs).
//! `stored_name` is the name the receiver stored the file under, carried by
//! its delivery-ack (an additive field: an older receiver omits it, and then
//! `stored_name` is null).

use crate::exit_codes::{self, ExitKind};
use crate::ui;
use anyhow::Result;
use filament_transfer::Outgoing;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FileReport {
    pub(crate) file: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: Option<String>,
    pub(crate) delivered: bool,
    pub(crate) declined: bool,
    /// The receiver's final name for it, when its ack said so.
    pub(crate) stored_name: Option<String>,
}

static LAST: Mutex<Vec<FileReport>> = Mutex::new(Vec::new());
/// Transfer id -> the name the receiver stored it under.
static STORED: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// The receiver reported the name it stored transfer `id` under. Only the
/// final path component is kept: a name, never a path on the other machine.
pub(crate) fn note_stored(id: &str, stored: &str) {
    let name = std::path::Path::new(stored)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.is_empty() {
        return;
    }
    if let Ok(mut m) = STORED.lock() {
        m.get_or_insert_with(HashMap::new).insert(id.to_string(), name);
    }
}

fn stored_for(id: &str) -> Option<String> {
    STORED.lock().ok()?.as_ref()?.get(id).cloned()
}

/// Remember the current state of every outgoing file.
pub(crate) fn record(out: &[Outgoing]) {
    let files = out
        .iter()
        .map(|o| FileReport {
            file: o.name.clone(),
            bytes: o.size,
            sha256: o.full.clone(),
            delivered: o.done && !o.declined,
            declined: o.declined,
            stored_name: stored_for(&o.id),
        })
        .collect();
    if let Ok(mut last) = LAST.lock() {
        *last = files;
    }
}

fn take() -> Vec<FileReport> {
    LAST.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default()
}

/// The sender's half of the transfer history: one record per file this send
/// offered, `ok` when the receiver acknowledged it whole. Called once the verb
/// returns, success or failure; the report stays for `emit`.
pub(crate) fn persist_history(peer: Option<&str>) {
    let files = LAST.lock().map(|l| l.clone()).unwrap_or_default();
    crate::transfer_history::append(&history_records(&files, peer));
}

/// History records for these files. Pure.
pub(crate) fn history_records(
    files: &[FileReport],
    peer: Option<&str>,
) -> Vec<crate::transfer_history::Record> {
    let now = crate::transfer_history::now_secs();
    files
        .iter()
        .map(|f| crate::transfer_history::Record {
            time: now,
            direction: "out",
            peer: peer.map(str::to_string),
            file: f.file.clone(),
            stored: f.stored_name.clone(),
            bytes: f.bytes,
            sha256: f.sha256.clone(),
            ok: f.delivered,
        })
        .collect()
}

/// The error for a send that finished with some files declined: refused by the
/// peer when nothing landed, partial when some did.
pub(crate) fn incomplete(completed: usize, declined: usize) -> anyhow::Error {
    let kind = if completed == 0 {
        ExitKind::Denied
    } else {
        ExitKind::Partial
    };
    exit_codes::err(kind, format!("send incomplete: {completed} delivered, {declined} declined"))
}

/// The result object for these files and this outcome. Pure.
pub(crate) fn result_object(files: &[FileReport], peer: Option<&str>, res: &Result<()>) -> Value {
    let total: u64 = files.iter().map(|f| f.bytes).sum();
    let mut v = json!({
        "ok": res.is_ok(),
        "verb": "send",
        "peer": peer,
        "bytes": total,
        "files": files.iter().map(|f| json!({
            "file": f.file,
            "bytes": f.bytes,
            "sha256": f.sha256,
            "delivered": f.delivered,
            "declined": f.declined,
            "stored_name": f.stored_name,
        })).collect::<Vec<_>>(),
    });
    if let [only] = files {
        v["file"] = json!(only.file);
        v["sha256"] = json!(only.sha256);
        v["stored_name"] = json!(only.stored_name);
    }
    if let Err(e) = res {
        let kind = exit_codes::classify(e);
        v["error"] = json!({
            "code": kind.token(),
            "exit": kind.code(),
            "message": exit_codes::human_message(e),
        });
    }
    v
}

/// Print the result object for a finished `send --json` and turn the outcome
/// into the process result: success stays success, a failure exits with its
/// classified code without printing anything more.
pub(crate) fn emit(res: Result<()>, peer: Option<&str>) -> Result<()> {
    let files = take();
    ui::json_out(&result_object(&files, peer, &res));
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            // The envelope above is the answer on stdout; the reason still goes
            // to stderr for a log, in the usual form.
            let kind = exit_codes::classify(&e);
            ui::critical(&format!("Error: {}", exit_codes::human_message(&e)));
            Err(exit_codes::reported(kind))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(name: &str, bytes: u64) -> FileReport {
        FileReport {
            file: name.into(),
            bytes,
            sha256: Some("ab".repeat(32)),
            delivered: true,
            declined: false,
            stored_name: None,
        }
    }

    #[test]
    fn the_receivers_stored_name_reaches_the_result_as_a_name_only() {
        note_stored("t-stored-1", "/home/x/Tunlion/a (1).txt");
        assert_eq!(stored_for("t-stored-1").as_deref(), Some("a (1).txt"));
        let mut f = one("a.txt", 3);
        f.stored_name = stored_for("t-stored-1");
        let v = result_object(&[f.clone()], Some("laptop"), &Ok(()));
        assert_eq!(v["stored_name"], json!("a (1).txt"));
        assert_eq!(v["files"][0]["stored_name"], json!("a (1).txt"));
        // An older receiver says nothing: the field is present and null.
        let v = result_object(&[one("b", 1)], None, &Ok(()));
        assert_eq!(v["stored_name"], Value::Null);
    }

    #[test]
    fn the_sender_records_one_history_entry_per_file() {
        let mut declined = one("b", 2);
        declined.delivered = false;
        declined.declined = true;
        let recs = history_records(&[one("a", 1), declined], Some("laptop"));
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.direction == "out" && r.peer.as_deref() == Some("laptop")));
        assert!(recs[0].ok && !recs[1].ok);
        assert_eq!(recs[0].sha256, Some("ab".repeat(32)));
    }

    #[test]
    fn offline_unconfirmed_and_missing_input_have_their_codes() {
        let off = exit_codes::err(ExitKind::Unreachable, crate::send_cmd::offline_message("laptop", std::time::Duration::from_secs(10)));
        let v = result_object(&[], Some("laptop"), &Err(off));
        assert_eq!(v["error"]["exit"], json!(6));
        assert!(v["error"]["message"].as_str().unwrap().contains("offline"));
        let e = crate::send_cmd::missing_input(
            "nope.txt",
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(exit_codes::classify(&e), ExitKind::Usage);
        let msg = e.to_string();
        assert!(msg.contains("nope.txt") && msg.contains("no such file"), "{msg}");
        assert!(!msg.to_lowercase().contains("peer"), "a local problem must not blame the peer: {msg}");
    }

    #[test]
    fn send_timeout_flag_wins_and_offline_is_bounded() {
        use crate::send_cmd::{establish_window, offline_window};
        use std::time::Duration;
        assert_eq!(establish_window(None, None), Duration::from_secs(60));
        assert_eq!(establish_window(None, Some("20")), Duration::from_secs(20));
        assert_eq!(establish_window(Some(5), Some("20")), Duration::from_secs(5), "--timeout beats the env");
        assert_eq!(offline_window(Duration::from_secs(60), None), Some(Duration::from_secs(10)));
        assert_eq!(offline_window(Duration::from_secs(4), None), Some(Duration::from_secs(4)), "never past the timeout");
        assert_eq!(offline_window(Duration::ZERO, None), None, "0 waits without limit");
        assert_eq!(offline_window(Duration::from_secs(60), Some("3")), Some(Duration::from_secs(3)));
    }

    #[test]
    fn a_single_file_carries_file_bytes_and_sha256_at_the_top() {
        let v = result_object(&[one("a.txt", 12)], Some("laptop"), &Ok(()));
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["verb"], json!("send"));
        assert_eq!(v["peer"], json!("laptop"));
        assert_eq!(v["file"], json!("a.txt"));
        assert_eq!(v["bytes"], json!(12));
        assert_eq!(v["sha256"], json!("ab".repeat(32)));
        assert_eq!(v["files"][0]["delivered"], json!(true));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn several_files_sum_bytes_and_list_each() {
        let v = result_object(&[one("a", 1), one("b", 2)], None, &Ok(()));
        assert_eq!(v["bytes"], json!(3));
        assert_eq!(v["files"].as_array().map(Vec::len), Some(2));
        assert!(v.get("file").is_none(), "no single file to name");
    }

    #[test]
    fn a_failure_is_ok_false_with_a_classified_error() {
        let res: Result<()> = Err(incomplete(0, 1));
        let v = result_object(&[one("a", 1)], Some("laptop"), &res);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"]["code"], json!("denied"));
        assert_eq!(v["error"]["exit"], json!(4));
        let partial: Result<()> = Err(incomplete(1, 1));
        let v = result_object(&[one("a", 1), one("b", 1)], None, &partial);
        assert_eq!(v["error"]["code"], json!("partial"));
        assert_eq!(v["error"]["exit"], json!(8));
    }
}
