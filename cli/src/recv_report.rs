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
//!
//! The data, the per-file record, the outcome aggregation and the result
//! object live in `filament_peerloop::recv::report`, one [`RecvReport`] per
//! receive invocation. This module is the thin process adapter: it maps the
//! library's [`RefusalClass`] to the CLI's [`ExitKind`], the library outcome to
//! `anyhow` errors, and the result object to `ui::json_out`. There is no
//! process-global list or refusal clock here.

use crate::exit_codes::{self, ExitKind};
use crate::ui;
use anyhow::Result;
use serde_json::Value;

// The invocation-owned report and its pure pieces, single-sourced in the peer
// loop crate. Re-exported so the CLI's call sites keep resolving here.
#[cfg(test)]
pub(crate) use filament_peerloop::recv::report::{refused_error, RecvFile, Refusal};
pub(crate) use filament_peerloop::recv::report::{
    storage_kind, OutcomeKind, RecvReport, RefusalClass, RefusedOutcome, ReportError,
};

/// The CLI exit kind for an outcome the library decided. This is the only
/// place the two vocabularies meet.
fn exit_kind(kind: OutcomeKind) -> ExitKind {
    match kind {
        OutcomeKind::Partial => ExitKind::Partial,
        OutcomeKind::LocalResource => ExitKind::LocalResource,
        OutcomeKind::Usage => ExitKind::Usage,
        OutcomeKind::Denied => ExitKind::Denied,
    }
}

pub(crate) fn as_error(outcome: RefusedOutcome) -> anyhow::Error {
    exit_codes::err(exit_kind(outcome.kind), outcome.message)
}

/// The failure for what this receive has refused so far.
pub(crate) fn refused_outcome(report: &RecvReport) -> Option<anyhow::Error> {
    report.refused_outcome().map(as_error)
}

/// The receive's outcome with its refusals applied: a receive that returned
/// Ok but refused some files is partial, and one whose error came from the
/// sender leaving after every file was refused reports the refusal instead.
pub(crate) fn finish(report: &RecvReport, res: Result<()>) -> Result<()> {
    match (res, refused_outcome(report)) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some(e)) => Err(e),
        (Err(e), Some(r)) if exit_codes::classify(&e) == ExitKind::Unreachable => Err(r),
        (Err(e), _) => Err(e),
    }
}

/// The `--json` error data for `res`, or None on success. The library owns the
/// object shape; the CLI supplies its classified code, exit and sentence.
fn error_report(res: &Result<()>) -> Option<ReportError> {
    res.as_ref().err().map(|e| {
        let kind = exit_codes::classify(e);
        ReportError {
            code: kind.token().to_string(),
            exit: kind.code(),
            message: exit_codes::human_message(e),
        }
    })
}

/// The result object. Pure (the CLI supplies the error mapping).
pub(crate) fn result_object(report: &RecvReport, dir: &str, res: &Result<()>) -> Value {
    report.result_object(dir, error_report(res).as_ref())
}

/// Print the result object for a finished `receive --json` and turn the
/// outcome into the process result, like `send_report::emit`.
pub(crate) fn emit(report: &RecvReport, res: Result<()>, dir: &str) -> Result<()> {
    ui::json_out(&result_object(report, dir, &res));
    match res {
        Ok(()) => Ok(()),
        Err(e) => {
            let kind = exit_codes::classify(&e);
            ui::critical(&format!(
                "{} {}",
                ui::error_label(),
                exit_codes::human_message(&e)
            ));
            Err(exit_codes::reported(kind))
        }
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
        let e = as_error(outcome);
        assert_eq!(exit_codes::classify(&e), ExitKind::LocalResource);
        assert!(e.to_string().contains("nothing was received"), "{e}");
    }

    #[test]
    fn no_tty_is_usage_and_names_the_flag() {
        let outcome = refused_error(&[refused("no_tty", RefusalClass::Usage)]).unwrap();
        let e = as_error(outcome);
        assert_eq!(exit_codes::classify(&e), ExitKind::Usage);
        assert!(e.to_string().contains("-y"), "{e}");
    }

    #[test]
    fn a_decline_is_denied_and_mixed_is_partial() {
        let e = as_error(refused_error(&[refused("declined", RefusalClass::Denied)]).unwrap());
        assert_eq!(exit_codes::classify(&e), ExitKind::Denied);
        let e = as_error(
            refused_error(&[stored(), refused("declined", RefusalClass::Denied)]).unwrap(),
        );
        assert_eq!(exit_codes::classify(&e), ExitKind::Partial);
        assert!(refused_error(&[stored()]).is_none());
    }

    #[test]
    fn the_result_object_has_the_send_contract() {
        let files = [refused("no_space", RefusalClass::LocalResource)];
        let outcome = refused_error(&files).unwrap();
        let res: Result<()> = Err(as_error(outcome));
        let report = RecvReport::new();
        // Feed the same files through the instance so the adapter sees them.
        feed(&report, &files);
        let v = result_object(&report, "/tmp/in", &res);
        assert_eq!(v["ok"], serde_json::json!(false));
        assert_eq!(v["verb"], serde_json::json!("receive"));
        assert_eq!(v["error"]["code"], serde_json::json!("local_resource"));
        assert_eq!(v["error"]["exit"], serde_json::json!(12));
        assert_eq!(v["error"]["reason"], serde_json::json!("no_space"));
        assert_eq!(v["files"][0]["received"], serde_json::json!(false));
        assert_eq!(
            v["files"][0]["refusal"]["reason"],
            serde_json::json!("no_space")
        );

        let ok_report = RecvReport::new();
        ok_report.note_stored("a.txt", 5, Some("ab"), "a.txt");
        let ok = result_object(&ok_report, "/tmp/in", &Ok(()));
        assert_eq!(ok["ok"], serde_json::json!(true));
        assert!(ok.get("error").is_none());
        assert_eq!(ok["files"][0]["stored_name"], serde_json::json!("a.txt"));
        assert_eq!(ok["files"][0]["sha256"], serde_json::json!("ab"));
        assert_eq!(ok["bytes"], serde_json::json!(5));
    }

    /// The report instance is the source of truth: the adapter maps the
    /// library outcome to the CLI's exit kind without reading any global.
    #[test]
    fn the_adapter_maps_the_instance_outcome() {
        let report = RecvReport::new();
        report.note_refused(
            "p.bin",
            3_000_000,
            "no_space",
            "receiver is out of disk space",
            storage_kind("no_space"),
        );
        let e = refused_outcome(&report).expect("refusal outcome");
        assert_eq!(exit_codes::classify(&e), ExitKind::LocalResource);

        let other = RecvReport::new();
        assert!(refused_outcome(&other).is_none());
        assert_eq!(other.files(), Vec::new());
    }

    /// Copy test fixtures into an instance without touching a global.
    fn feed(report: &RecvReport, files: &[RecvFile]) {
        for f in files {
            match &f.refusal {
                Some(r) => report.note_refused(&f.file, f.bytes, &r.reason, &r.message, r.class),
                None => report.note_stored(
                    &f.file,
                    f.bytes,
                    f.sha256.as_deref(),
                    f.stored_name.as_deref().unwrap_or_default(),
                ),
            }
        }
    }
}
