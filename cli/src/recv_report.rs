//! What a one-shot `tunlion receive` did with each offer, and how it ends.
//!
//! A receive that refused or declined every file it was offered used to hold
//! the line for the sender to come back and then say "the sender is
//! unreachable ... Nothing was received", exit 6: a receiver out of disk space
//! was reported as a network problem. The receive loop now records each
//! outcome here (a stored file, or a refusal with its kind), ends as soon as
//! nothing is left in flight, and fails with the receiver's own reason and its
//! code:
//!
//! - this machine's disk is full: 12 (`local_resource`), reason `no_space`
//! - no tty to ask on and no `-y`: 2 (`usage`), reason `no_tty`
//! - a person said no, or a capability refused the sender: 4 (`denied`)
//! - any other local storage failure (read-only folder, a name the
//!   filesystem refuses, no permission): 2 (`usage`, a local file problem)
//!
//! Some files stored and some refused is 8 (`partial`).
//!
//! `receive --json` prints one result object, the same contract as `send`:
//!
//! ```json
//! {"ok": false, "verb": "receive", "dir": "/home/me/Downloads", "bytes": 0,
//!  "files": [{"file": "p.bin", "bytes": 3000000, "sha256": null, "received": false,
//!             "stored_name": null,
//!             "refusal": {"reason": "no_space", "message": "receiver is out of disk space ..."}}],
//!  "error": {"code": "local_resource", "exit": 12, "reason": "no_space", "message": "..."}}
//! ```
//!
//! `ok` is true exactly when the exit is 0.

use crate::exit_codes::{self, ExitKind};
use crate::ui;
use anyhow::Result;
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecvFile {
    /// The name the sender offered.
    pub(crate) file: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: Option<String>,
    /// The name it was stored under (None when it was not stored).
    pub(crate) stored_name: Option<String>,
    /// Why it was not stored: (reason token, sentence, kind).
    pub(crate) refusal: Option<(String, String, ExitKind)>,
}

static FILES: Mutex<Vec<RecvFile>> = Mutex::new(Vec::new());
static LAST_REFUSAL: Mutex<Option<std::time::Instant>> = Mutex::new(None);

fn push(f: RecvFile) {
    if let Ok(mut v) = FILES.lock() {
        v.push(f);
    }
}

/// A file was stored as `stored_name`.
pub(crate) fn note_stored(file: &str, bytes: u64, sha256: Option<&str>, stored_name: &str) {
    push(RecvFile {
        file: file.to_string(),
        bytes,
        sha256: sha256.map(str::to_string),
        stored_name: Some(stored_name.to_string()),
        refusal: None,
    });
}

/// This receiver refused (or declined) `file`: `token` is the typed reason,
/// `message` the sentence it printed, `kind` the exit kind it ends in.
pub(crate) fn note_refused(file: &str, bytes: u64, token: &str, message: &str, kind: ExitKind) {
    push(RecvFile {
        file: file.to_string(),
        bytes,
        sha256: None,
        stored_name: None,
        refusal: Some((token.to_string(), message.to_string(), kind)),
    });
    if let Ok(mut t) = LAST_REFUSAL.lock() {
        *t = Some(std::time::Instant::now());
    }
}

/// The exit kind of a storage refusal token from `recv_files::storage_refusal`
/// or `inbox_refusal`: a full disk is this machine's resource (12), anything
/// else is a local file problem (2). Pure.
pub(crate) fn storage_kind(token: &str) -> ExitKind {
    if token == "no_space" { ExitKind::LocalResource } else { ExitKind::Usage }
}

fn snapshot() -> Vec<RecvFile> {
    FILES.lock().map(|v| v.clone()).unwrap_or_default()
}

/// How long ago the last refusal was, if there was one.
pub(crate) fn since_last_refusal() -> Option<std::time::Duration> {
    LAST_REFUSAL.lock().ok()?.map(|t| t.elapsed())
}

/// The failure for a receive that stored nothing and refused `files`, or None
/// when nothing was refused. Pure.
pub(crate) fn refused_error(files: &[RecvFile]) -> Option<anyhow::Error> {
    let refused: Vec<&(String, String, ExitKind)> =
        files.iter().filter_map(|f| f.refusal.as_ref()).collect();
    if refused.is_empty() {
        return None;
    }
    let stored = files.iter().filter(|f| f.stored_name.is_some()).count();
    let kind = if stored > 0 {
        ExitKind::Partial
    } else if refused.iter().any(|r| r.2 == ExitKind::LocalResource) {
        ExitKind::LocalResource
    } else if refused.iter().all(|r| r.2 == ExitKind::Usage) {
        ExitKind::Usage
    } else {
        ExitKind::Denied
    };
    let mut why: Vec<String> = refused.iter().map(|r| r.1.clone()).collect();
    why.dedup();
    let mut msg = if stored > 0 {
        format!("received {stored} file(s), refused {}: {}", refused.len(), why.join("; "))
    } else {
        format!("nothing was received: {}", why.join("; "))
    };
    if refused.iter().any(|r| r.0 == "no_tty") {
        msg.push_str(". Re-run with -y (--yes) to accept offers without a prompt");
    }
    Some(exit_codes::err(kind, msg))
}

/// The failure for what this receive has refused so far (see `refused_error`).
pub(crate) fn refused_outcome() -> Option<anyhow::Error> {
    refused_error(&snapshot())
}

/// The receive's outcome with its refusals applied: a receive that returned
/// Ok but refused some files is partial, and one whose error came from the
/// sender leaving after every file was refused reports the refusal instead.
pub(crate) fn finish(res: Result<()>) -> Result<()> {
    let files = snapshot();
    match (res, refused_error(&files)) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some(e)) => Err(e),
        (Err(e), Some(r)) if exit_codes::classify(&e) == ExitKind::Unreachable => Err(r),
        (Err(e), _) => Err(e),
    }
}

/// The result object. Pure.
pub(crate) fn result_object(files: &[RecvFile], dir: &str, res: &Result<()>) -> Value {
    let stored_bytes: u64 = files.iter().filter(|f| f.stored_name.is_some()).map(|f| f.bytes).sum();
    let mut v = json!({
        "ok": res.is_ok(),
        "verb": "receive",
        "dir": dir,
        "bytes": stored_bytes,
        "files": files.iter().map(|f| json!({
            "file": f.file,
            "bytes": f.bytes,
            "sha256": f.sha256,
            "received": f.stored_name.is_some(),
            "stored_name": f.stored_name,
            "refusal": refusal_json(f),
        })).collect::<Vec<_>>(),
    });
    if let Err(e) = res {
        let kind = exit_codes::classify(e);
        let mut error = json!({
            "code": kind.token(),
            "exit": kind.code(),
            "message": exit_codes::human_message(e),
        });
        let mut reasons: Vec<&str> =
            files.iter().filter_map(|f| f.refusal.as_ref().map(|r| r.0.as_str())).collect();
        reasons.sort_unstable();
        reasons.dedup();
        if let [one] = reasons.as_slice() {
            error["reason"] = json!(one);
        }
        v["error"] = error;
    }
    v
}

fn refusal_json(f: &RecvFile) -> Value {
    match &f.refusal {
        Some((reason, message, _)) => json!({ "reason": reason, "message": message }),
        None => Value::Null,
    }
}

/// Print the result object for a finished `receive --json` and turn the
/// outcome into the process result, like `send_report::emit`.
pub(crate) fn emit(res: Result<()>, dir: &str) -> Result<()> {
    let files = snapshot();
    ui::json_out(&result_object(&files, dir, &res));
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            let kind = exit_codes::classify(&e);
            ui::critical(&format!("{} {}", ui::error_label(), exit_codes::human_message(&e)));
            Err(exit_codes::reported(kind))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(token: &str, kind: ExitKind) -> RecvFile {
        RecvFile {
            file: "p.bin".into(),
            bytes: 3_000_000,
            sha256: None,
            stored_name: None,
            refusal: Some((token.into(), format!("refused for {token}"), kind)),
        }
    }

    fn stored() -> RecvFile {
        RecvFile {
            file: "a.txt".into(),
            bytes: 5,
            sha256: Some("ab".into()),
            stored_name: Some("a.txt".into()),
            refusal: None,
        }
    }

    #[test]
    fn a_full_disk_on_this_machine_is_local_resource() {
        let e = refused_error(&[refused("no_space", storage_kind("no_space"))]).unwrap();
        assert_eq!(exit_codes::classify(&e), ExitKind::LocalResource);
        assert!(e.to_string().contains("nothing was received"), "{e}");
    }

    #[test]
    fn no_tty_is_usage_and_names_the_flag() {
        let e = refused_error(&[refused("no_tty", ExitKind::Usage)]).unwrap();
        assert_eq!(exit_codes::classify(&e), ExitKind::Usage);
        assert!(e.to_string().contains("-y"), "{e}");
    }

    #[test]
    fn a_decline_is_denied_and_mixed_is_partial() {
        let e = refused_error(&[refused("declined", ExitKind::Denied)]).unwrap();
        assert_eq!(exit_codes::classify(&e), ExitKind::Denied);
        let e = refused_error(&[stored(), refused("declined", ExitKind::Denied)]).unwrap();
        assert_eq!(exit_codes::classify(&e), ExitKind::Partial);
        assert!(refused_error(&[stored()]).is_none());
    }

    #[test]
    fn the_result_object_has_the_send_contract() {
        let files = [refused("no_space", ExitKind::LocalResource)];
        let res: Result<()> = Err(refused_error(&files).unwrap());
        let v = result_object(&files, "/tmp/in", &res);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["verb"], json!("receive"));
        assert_eq!(v["error"]["code"], json!("local_resource"));
        assert_eq!(v["error"]["exit"], json!(12));
        assert_eq!(v["error"]["reason"], json!("no_space"));
        assert_eq!(v["files"][0]["received"], json!(false));
        assert_eq!(v["files"][0]["refusal"]["reason"], json!("no_space"));
        let ok = result_object(&[stored()], "/tmp/in", &Ok(()));
        assert_eq!(ok["ok"], json!(true));
        assert!(ok.get("error").is_none());
        assert_eq!(ok["files"][0]["stored_name"], json!("a.txt"));
        assert_eq!(ok["files"][0]["sha256"], json!("ab"));
        assert_eq!(ok["bytes"], json!(5));
    }
}
