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
//! There is no `stored_name`: no receiver reports the name it stored under.

use crate::exit_codes::{self, ExitKind};
use crate::ui;
use anyhow::Result;
use filament_transfer::Outgoing;
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FileReport {
    pub(crate) file: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: Option<String>,
    pub(crate) delivered: bool,
    pub(crate) declined: bool,
}

static LAST: Mutex<Vec<FileReport>> = Mutex::new(Vec::new());

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
        })
        .collect();
    if let Ok(mut last) = LAST.lock() {
        *last = files;
    }
}

fn take() -> Vec<FileReport> {
    LAST.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default()
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
        })).collect::<Vec<_>>(),
    });
    if let [only] = files {
        v["file"] = json!(only.file);
        v["sha256"] = json!(only.sha256);
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
        }
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
