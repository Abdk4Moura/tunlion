//! What one receive invocation did with each offer.
//!
//! The receiver records a value per file (stored under a name, or refused with
//! a typed reason) and the time of the last refusal. That record decides the
//! invocation's outcome: a full disk is this machine's resource, no tty or a
//! local file problem is usage, a person/capability saying no is denied, and
//! some stored plus some refused is partial. It also builds the `--json`
//! result object.
//!
//! The state used to live in two process-wide `Mutex`es in the CLI's
//! `recv_report`. Two receives in one process (a daemon and an embedded
//! invocation, or concurrent library callers) therefore shared files and the
//! refusal clock: one session could report another's file, and a refusal in one
//! reset another's sender-gone grace period. [`RecvReport`] is the
//! invocation-owned replacement: each instance owns its files and last-refusal
//! stamp. Cloning it clones a handle to that same instance (the receive engine
//! needs an owned handle), never a new shared/global one.
//!
//! This module is host-free. It never reads settings or the environment, never
//! writes to a terminal, and has no CLI dependency. The CLI keeps the exit-code
//! and UI mapping: [`RefusalClass`] is the small library vocabulary, and the
//! caller turns it into its own exit kind and renders the message.

use serde_json::{json, Value};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// A refusal's local cause, in the library's own vocabulary.
///
/// The CLI maps these to its exit kinds (12 for `LocalResource`, 2 for
/// `Usage`, 4 for `Denied`); the library does not know about processes or exit
/// codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalClass {
    /// This machine ran out of a local resource (disk full, quota).
    LocalResource,
    /// The caller's input/local setup cannot do it (no tty, a bad file name,
    /// a read-only or unwritable folder).
    Usage,
    /// A person or a capability said no.
    Denied,
}

/// Why one offered file was not stored: the stable reason token, the sentence
/// shown to both ends, and the local cause it ends in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub message: String,
    pub class: RefusalClass,
}

/// What an invocation did with one offered file.
#[derive(Clone, Debug, PartialEq)]
pub struct RecvFile {
    /// The name the sender offered.
    pub file: String,
    pub bytes: u64,
    pub sha256: Option<String>,
    /// The name it was stored under (None when it was not stored).
    pub stored_name: Option<String>,
    /// Why it was not stored, when it was refused or declined.
    pub refusal: Option<Refusal>,
}

/// The outcome a set of refusals decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Some files were stored and some refused.
    Partial,
    /// Nothing was stored and this machine ran out of a local resource.
    LocalResource,
    /// Nothing was stored and every refusal was a usage/local-file problem.
    Usage,
    /// Nothing was stored and at least one refusal was a person/capability
    /// saying no (with no local-resource refusal).
    Denied,
}

/// A failed receive, described without any exit-code or terminal knowledge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedOutcome {
    pub kind: OutcomeKind,
    pub message: String,
}

/// The `error` object's data for a `--json` result. The caller supplies its
/// own code/exit/message mapping; this is pure data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportError {
    pub code: String,
    pub exit: i32,
    pub message: String,
}

#[derive(Debug, Default)]
struct ReportState {
    files: Vec<RecvFile>,
    last_refusal: Option<Instant>,
}

/// The report for ONE receive invocation: its files and its last-refusal stamp.
///
/// No process-global state. Two reports created independently can never see or
/// overwrite each other's files, stamps or results. Clones share the same
/// instance's state (the engine closure takes an owned handle); create a new
/// report for each invocation.
#[derive(Clone, Debug, Default)]
pub struct RecvReport {
    state: Arc<Mutex<ReportState>>,
}

impl RecvReport {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, ReportState> {
        // A panic while holding the lock must not silently drop a session's
        // report: recover the data instead of losing it.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A file was stored as `stored_name`.
    pub fn note_stored(&self, file: &str, bytes: u64, sha256: Option<&str>, stored_name: &str) {
        self.state().files.push(RecvFile {
            file: file.to_string(),
            bytes,
            sha256: sha256.map(str::to_string),
            stored_name: Some(stored_name.to_string()),
            refusal: None,
        });
    }

    /// This receiver refused (or declined) `file`: `reason` is the typed token,
    /// `message` the sentence both ends show, `class` the local cause.
    pub fn note_refused(
        &self,
        file: &str,
        bytes: u64,
        reason: &str,
        message: &str,
        class: RefusalClass,
    ) {
        let mut state = self.state();
        state.files.push(RecvFile {
            file: file.to_string(),
            bytes,
            sha256: None,
            stored_name: None,
            refusal: Some(Refusal {
                reason: reason.to_string(),
                message: message.to_string(),
                class,
            }),
        });
        state.last_refusal = Some(Instant::now());
    }

    /// A copy of the files recorded so far, in arrival order.
    pub fn files(&self) -> Vec<RecvFile> {
        self.state().files.clone()
    }

    /// When the last refusal happened, if there was one.
    pub fn last_refusal_at(&self) -> Option<Instant> {
        self.state().last_refusal
    }

    /// How long ago the last refusal was, if there was one.
    pub fn since_last_refusal(&self) -> Option<Duration> {
        self.last_refusal_at().map(|t| t.elapsed())
    }

    /// The failure for what this receive has refused so far.
    pub fn refused_outcome(&self) -> Option<RefusedOutcome> {
        refused_error(&self.files())
    }

    /// The `--json` result object for this report. `error` is the caller's
    /// mapped failure, or `None` when the invocation succeeded.
    pub fn result_object(&self, dir: &str, error: Option<&ReportError>) -> Value {
        result_object(&self.files(), dir, error)
    }
}

/// The exit class of a storage refusal token from the CLI's `storage_refusal`
/// or `inbox_refusal`: a full disk is this machine's resource, anything else is
/// a local file problem. Pure.
pub fn storage_kind(token: &str) -> RefusalClass {
    if token == "no_space" {
        RefusalClass::LocalResource
    } else {
        RefusalClass::Usage
    }
}

/// The failure for a receive that stored nothing and refused `files`, or None
/// when nothing was refused. Pure.
pub fn refused_error(files: &[RecvFile]) -> Option<RefusedOutcome> {
    let refused: Vec<&Refusal> = files.iter().filter_map(|f| f.refusal.as_ref()).collect();
    if refused.is_empty() {
        return None;
    }
    let stored = files.iter().filter(|f| f.stored_name.is_some()).count();
    let kind = if stored > 0 {
        OutcomeKind::Partial
    } else if refused
        .iter()
        .any(|r| r.class == RefusalClass::LocalResource)
    {
        OutcomeKind::LocalResource
    } else if refused.iter().all(|r| r.class == RefusalClass::Usage) {
        OutcomeKind::Usage
    } else {
        OutcomeKind::Denied
    };
    let mut why: Vec<String> = refused.iter().map(|r| r.message.clone()).collect();
    why.dedup();
    let mut msg = if stored > 0 {
        format!(
            "received {stored} file(s), refused {}: {}",
            refused.len(),
            why.join("; ")
        )
    } else {
        format!("nothing was received: {}", why.join("; "))
    };
    if refused.iter().any(|r| r.reason == "no_tty") {
        msg.push_str(". Re-run with -y (--yes) to accept offers without a prompt");
    }
    Some(RefusedOutcome { kind, message: msg })
}

/// The result object. Pure: the caller passes its mapped error data.
pub fn result_object(files: &[RecvFile], dir: &str, error: Option<&ReportError>) -> Value {
    let stored_bytes: u64 = files
        .iter()
        .filter(|f| f.stored_name.is_some())
        .map(|f| f.bytes)
        .sum();
    let mut v = json!({
        "ok": error.is_none(),
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
    if let Some(e) = error {
        let mut error = json!({
            "code": e.code.clone(),
            "exit": e.exit,
            "message": e.message.clone(),
        });
        let mut reasons: Vec<&str> = files
            .iter()
            .filter_map(|f| f.refusal.as_ref().map(|r| r.reason.as_str()))
            .collect();
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
        Some(r) => json!({ "reason": r.reason, "message": r.message }),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(token: &str, class: RefusalClass) -> RecvFile {
        RecvFile {
            file: "p.bin".into(),
            bytes: 3_000_000,
            sha256: None,
            stored_name: None,
            refusal: Some(Refusal {
                reason: token.into(),
                message: format!("refused for {token}"),
                class,
            }),
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
        let outcome = refused_error(&[refused("no_space", storage_kind("no_space"))]).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::LocalResource);
        assert!(
            outcome.message.contains("nothing was received"),
            "{}",
            outcome.message
        );
    }

    #[test]
    fn no_tty_is_usage_and_names_the_flag() {
        let outcome = refused_error(&[refused("no_tty", RefusalClass::Usage)]).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Usage);
        assert!(outcome.message.contains("-y"), "{}", outcome.message);
    }

    #[test]
    fn a_decline_is_denied_and_mixed_is_partial() {
        let outcome = refused_error(&[refused("declined", RefusalClass::Denied)]).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Denied);
        let outcome =
            refused_error(&[stored(), refused("declined", RefusalClass::Denied)]).unwrap();
        assert_eq!(outcome.kind, OutcomeKind::Partial);
        assert!(refused_error(&[stored()]).is_none());
    }

    #[test]
    fn the_result_object_has_the_send_contract() {
        let files = [refused("no_space", RefusalClass::LocalResource)];
        let outcome = refused_error(&files).unwrap();
        let error = ReportError {
            code: "local_resource".into(),
            exit: 12,
            message: outcome.message,
        };
        let v = result_object(&files, "/tmp/in", Some(&error));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["verb"], json!("receive"));
        assert_eq!(v["error"]["code"], json!("local_resource"));
        assert_eq!(v["error"]["exit"], json!(12));
        assert_eq!(v["error"]["reason"], json!("no_space"));
        assert_eq!(v["files"][0]["received"], json!(false));
        assert_eq!(v["files"][0]["refusal"]["reason"], json!("no_space"));
        let ok = result_object(&[stored()], "/tmp/in", None);
        assert_eq!(ok["ok"], json!(true));
        assert!(ok.get("error").is_none());
        assert_eq!(ok["files"][0]["stored_name"], json!("a.txt"));
        assert_eq!(ok["files"][0]["sha256"], json!("ab"));
        assert_eq!(ok["bytes"], json!(5));
    }

    /// Two independent reports own disjoint state. One cannot see the other's
    /// files, outcome, or last-refusal stamp, and a refusal in one leaves the
    /// other's stamp untouched.
    #[test]
    fn independent_reports_cannot_see_or_overwrite_each_other() {
        let first = RecvReport::new();
        let second = RecvReport::new();

        first.note_stored("a.txt", 5, Some("ab"), "a.txt");
        first.note_refused(
            "p.bin",
            3_000_000,
            "no_space",
            "receiver is out of disk space",
            RefusalClass::LocalResource,
        );
        let first_stamp = first.last_refusal_at().expect("first refused");

        assert_eq!(
            second.files(),
            Vec::new(),
            "second saw the first report's files"
        );
        assert!(
            second.last_refusal_at().is_none(),
            "second saw the first report's stamp"
        );
        assert!(second.refused_outcome().is_none());
        assert_eq!(second.result_object("/tmp/in", None)["files"], json!([]));
        assert_eq!(second.result_object("/tmp/in", None)["ok"], json!(true));

        second.note_refused(
            "q.bin",
            7,
            "declined",
            "declined q.bin",
            RefusalClass::Denied,
        );
        assert_eq!(
            first.last_refusal_at(),
            Some(first_stamp),
            "the second refusal overwrote the first report's stamp"
        );
        assert_eq!(
            first.files().len(),
            2,
            "the second report added to the first"
        );
        assert_eq!(
            second.files().len(),
            1,
            "the first report added to the second"
        );

        let first_outcome = first.refused_outcome().unwrap();
        assert_eq!(first_outcome.kind, OutcomeKind::Partial);
        assert!(
            first_outcome.message.contains("received 1 file(s)"),
            "{}",
            first_outcome.message
        );
        let second_outcome = second.refused_outcome().unwrap();
        assert_eq!(second_outcome.kind, OutcomeKind::Denied);
        assert!(
            second_outcome.message.contains("q.bin"),
            "{}",
            second_outcome.message
        );
        assert!(
            !second_outcome
                .message
                .contains("receiver is out of disk space"),
            "the second report saw the first report's refusal"
        );

        // Each result object lists exactly its own files, in its own order.
        let first_object = first.result_object("/tmp/in", None);
        assert_eq!(first_object["files"].as_array().unwrap().len(), 2);
        assert_eq!(first_object["files"][0]["file"], json!("a.txt"));
        assert_eq!(first_object["files"][1]["file"], json!("p.bin"));
        let second_object = second.result_object("/tmp/in", None);
        assert_eq!(second_object["files"].as_array().unwrap().len(), 1);
        assert_eq!(second_object["files"][0]["file"], json!("q.bin"));
        assert_eq!(second_object["files"][0]["refusal"]["reason"], json!("declined"));
    }

    /// A clone is a handle to the same invocation's report, not a fresh or
    /// shared global: the receive engine records through a clone and the
    /// caller reads the same state.
    #[test]
    fn a_clone_is_the_same_instances_state() {
        let report = RecvReport::new();
        let engine_handle = report.clone();
        engine_handle.note_stored("a.txt", 5, None, "a.txt");
        assert_eq!(report.files().len(), 1);
        let other = RecvReport::new();
        assert!(other.files().is_empty());
    }
}
