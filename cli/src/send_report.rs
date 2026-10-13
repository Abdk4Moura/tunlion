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
//!
//! `refusal` is why a file was not delivered, null for one that was:
//! `{"reason": <token>, "message": <the receiver's sentence>}`. The token is
//! the receiver's typed reason (`no_space`, `name_too_long`, `read_only`,
//! `permission`, `io`, `inbox_missing`, ...; see filament-proto `refuse_msg`)
//! or `declined` when a person (or an older receiver) said no without one.
//! When the send failed because of refusals, `error.message` carries their
//! sentences too, so a script reading only the top level still learns why.

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
    /// Why it was not delivered: (reason token, sentence). Set for a declined
    /// file; `None` for a delivered one.
    pub(crate) refusal: Option<(String, String)>,
}

static LAST: Mutex<Vec<FileReport>> = Mutex::new(Vec::new());
/// Transfer id -> the name the receiver stored it under.
static STORED: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
/// Transfer id -> (reason token, sentence) of the receiver's refusal.
static REFUSED: Mutex<Option<HashMap<String, (String, String)>>> = Mutex::new(None);

/// The reason token a script matches, from a peer-supplied string: lowercase
/// ASCII letters, digits, `_` and `-` only, bounded. Anything else (an empty
/// or hostile token) becomes `io`, the generic "could not store it".
pub(crate) fn reason_token(raw: &str) -> String {
    let t: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(40)
        .collect();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        "io".to_string()
    } else {
        t
    }
}

/// The receiver refused transfer `id`: remember its reason for the result.
/// `reason` is the wire token (None for a plain decline, which becomes
/// `declined`); `message` the sentence shown to the person.
pub(crate) fn note_refused(id: &str, reason: Option<&str>, message: &str) {
    let token = reason.map(reason_token).unwrap_or_else(|| "declined".to_string());
    if let Ok(mut m) = REFUSED.lock() {
        m.get_or_insert_with(HashMap::new)
            .insert(id.to_string(), (token, message.to_string()));
    }
}

fn refused_for(id: &str) -> Option<(String, String)> {
    REFUSED.lock().ok()?.as_ref()?.get(id).cloned()
}

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

/// The name the receiver stored a file under, when it differs from the name
/// offered: only the final path component, never a path on the other
/// machine. None when they match or the receiver did not say (an older one).
pub(crate) fn delivered_as(offered: &str, stored: Option<&str>) -> Option<String> {
    let name = std::path::Path::new(stored?)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())?;
    (name != offered).then_some(name)
}

/// Above this many characters the offered name is described, not printed, in
/// a status line. It is never cut with "...": a shortened name in "sent as
/// xxx...xxx.txt" reads as the name the file was sent under, which it is not.
const LONG_NAME_CHARS: usize = 80;

/// How the line refers to the name that was offered, next to the stored one.
fn sent_as(offered: &str, stored: &str) -> String {
    let n = offered.chars().count();
    if n <= LONG_NAME_CHARS {
        return format!("sent as {offered}");
    }
    if stored.chars().count() < n {
        format!("sent with a {n}-character name, shortened to fit there")
    } else {
        format!("sent with a {n}-character name")
    }
}

/// The label of the per-file "ok" line: the stored name when it differs,
/// followed by what was offered, so the line names a file that exists.
pub(crate) fn summary_label(offered: &str, renamed: Option<&str>) -> String {
    match renamed {
        Some(stored) => format!("{stored} ({})", sent_as(offered, stored)),
        None => offered.to_string(),
    }
}

/// The per-file confirmation line, naming the stored name whenever it differs.
pub(crate) fn delivered_line(offered: &str, renamed: Option<&str>) -> String {
    match renamed {
        Some(stored) => format!(
            "    delivered as {stored} ({}) + verified (whole-file sha256 matched)",
            sent_as(offered, stored)
        ),
        None => format!("    {offered} delivered + verified (whole-file sha256 matched)"),
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
            refusal: o.declined.then(|| {
                refused_for(&o.id).unwrap_or_else(|| {
                    ("declined".to_string(), "the receiver declined it".to_string())
                })
            }),
        })
        .collect();
    if let Ok(mut last) = LAST.lock() {
        *last = files;
    }
}

/// The peer this send targets, for an interrupt's result object.
static PEER: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn set_peer(peer: Option<&str>) {
    if let Ok(mut p) = PEER.lock() {
        *p = peer.map(str::to_string);
    }
}

/// An interrupted `send --json` answers with the same object as every other
/// send failure (`peer`, `bytes`, `files`), carrying the interrupt's `error`.
/// It used to be a bare `{ok, verb, error}`, a different shape for one kind
/// of failure.
pub(crate) fn interrupted_object(envelope: Value) -> Value {
    let files = LAST.lock().map(|l| l.clone()).unwrap_or_default();
    let peer = PEER.lock().ok().and_then(|p| p.clone());
    let mut v = result_object(&files, peer.as_deref(), &Ok(()));
    v["ok"] = json!(false);
    v["error"] = envelope["error"].clone();
    v
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

/// What the history calls each source a send was given: `-` is stdin (under
/// `--name` when given), anything else its file name. Pure.
pub(crate) fn source_labels(paths: &[String], name: Option<&str>) -> Vec<String> {
    paths
        .iter()
        .map(|p| {
            if p == "-" {
                name.unwrap_or("stdin").to_string()
            } else {
                std::path::Path::new(p)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| p.clone())
            }
        })
        .collect()
}

/// A send that failed before it offered any file (nothing reached
/// `record`) still belongs in the history: one failed record per source,
/// with the reason. Called after `persist_history`, only on failure.
pub(crate) fn persist_unoffered(peer: Option<&str>, sources: &[String], err: &anyhow::Error) {
    let offered = LAST.lock().map(|l| !l.is_empty()).unwrap_or(true);
    if offered {
        return;
    }
    crate::transfer_history::append_unoffered(peer, sources, &format!("{err:#}"));
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
            "refusal": refusal_json(f),
        })).collect::<Vec<_>>(),
    });
    if let [only] = files {
        v["file"] = json!(only.file);
        v["sha256"] = json!(only.sha256);
        v["stored_name"] = json!(only.stored_name);
        v["refusal"] = refusal_json(only);
    }
    if let Err(e) = res {
        let kind = exit_codes::classify(e);
        let mut error = json!({
            "code": kind.token(),
            "exit": kind.code(),
            "message": error_message(files, e),
        });
        // The typed reason at the top level too, when exactly one kind of
        // refusal is why the send failed: `error.reason == "no_space"` is the
        // one-field check a script wants.
        let mut reasons: Vec<&str> = files
            .iter()
            .filter_map(|f| f.refusal.as_ref().map(|(r, _)| r.as_str()))
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

fn refusal_json(f: &FileReport) -> Value {
    match &f.refusal {
        Some((reason, message)) => json!({ "reason": reason, "message": message }),
        None => Value::Null,
    }
}

/// The top-level failure sentence. A send that failed because the receiver
/// refused files names each refusal in the receiver's words; it used to say
/// "failed (denied)" while the human block said "receiver is out of disk
/// space ... needs 2.9 MiB, has 980.0 KiB".
fn error_message(files: &[FileReport], e: &anyhow::Error) -> String {
    let message = exit_codes::human_message(e);
    let refusals: Vec<String> = files
        .iter()
        .filter_map(|f| {
            let (reason, why) = f.refusal.as_ref()?;
            (reason != "declined").then(|| why.clone())
        })
        .collect();
    if refusals.is_empty() || refusals.iter().all(|r| message.contains(r.as_str())) {
        return message;
    }
    let generic = message.starts_with("failed (") || message.starts_with("send incomplete");
    if generic {
        refusals.join("; ")
    } else {
        format!("{message}: {}", refusals.join("; "))
    }
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

    /// An interrupted send has the shape of every other send failure.
    #[test]
    fn an_interrupt_is_the_send_result_object_with_its_error() {
        let env = json!({"ok": false, "error": {"code": "interrupted", "exit": 130, "signal": "SIGINT"}});
        let v = interrupted_object(env);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["verb"], json!("send"));
        assert_eq!(v["error"]["code"], json!("interrupted"));
        assert_eq!(v["error"]["exit"], json!(130));
        assert!(v["files"].is_array() && v.get("bytes").is_some() && v.get("peer").is_some(), "{v}");
    }

    #[test]
    fn a_failed_sends_sources_are_named_for_the_history() {
        let paths = vec!["-".to_string(), "/tmp/dir/a.txt".to_string()];
        assert_eq!(source_labels(&paths, None), ["stdin", "a.txt"]);
        assert_eq!(source_labels(&paths, Some("log.txt")), ["log.txt", "a.txt"]);
    }

    fn one(name: &str, bytes: u64) -> FileReport {
        FileReport {
            file: name.into(),
            bytes,
            sha256: Some("ab".repeat(32)),
            delivered: true,
            declined: false,
            stored_name: None,
            refusal: None,
        }
    }

    /// J5: on a full disk the human text named the reason and both sizes and
    /// the JSON said `{"code":"denied","message":"failed (denied)"}` with
    /// `declined: true` and no reason. Each file carries its typed reason and
    /// sentence, and the top-level error names them.
    #[test]
    fn a_refused_file_carries_its_typed_reason_into_json() {
        let why = "receiver is out of disk space for big.bin (needs 2.9 MiB, has 980.0 KiB)";
        note_refused("t-refused-1", Some("no_space"), why);
        let mut f = one("big.bin", 3_000_000);
        f.delivered = false;
        f.declined = true;
        f.refusal = refused_for("t-refused-1");
        let res: Result<()> = Err(exit_codes::reported(ExitKind::Denied));
        let v = result_object(&[f.clone()], Some("beta"), &res);
        assert_eq!(v["files"][0]["refusal"]["reason"], json!("no_space"));
        assert_eq!(v["files"][0]["refusal"]["message"], json!(why));
        assert_eq!(v["refusal"]["reason"], json!("no_space"), "single file: at the top too");
        assert_eq!(v["error"]["code"], json!("denied"));
        assert_eq!(v["error"]["exit"], json!(4));
        assert_eq!(v["error"]["reason"], json!("no_space"));
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("out of disk space") && msg.contains("needs 2.9 MiB"), "{msg}");
        assert!(!msg.contains("failed (denied)"), "{msg}");
        // A reported sentence that already names it is not repeated.
        let res: Result<()> = Err(exit_codes::reported_because(ExitKind::Denied, why));
        let v = result_object(&[f], Some("beta"), &res);
        assert_eq!(v["error"]["message"], json!(why));
    }

    #[test]
    fn a_plain_decline_and_a_hostile_token_have_safe_reasons() {
        note_refused("t-refused-2", None, "the receiver declined it");
        assert_eq!(refused_for("t-refused-2").unwrap().0, "declined");
        assert_eq!(reason_token("NAME_TOO_LONG"), "name_too_long");
        assert_eq!(reason_token("inbox_missing"), "inbox_missing");
        assert_eq!(reason_token("\u{1b}[31mx"), "io");
        assert_eq!(reason_token(""), "io");
        // Two different reasons: per file, and no single top-level reason.
        let mut a = one("a", 1);
        a.declined = true;
        a.delivered = false;
        a.refusal = Some(("no_space".into(), "no room for a".into()));
        let mut b = one("b", 1);
        b.declined = true;
        b.delivered = false;
        b.refusal = Some(("name_too_long".into(), "bad name b".into()));
        let v = result_object(&[a, b], None, &Err(incomplete(0, 2)));
        assert!(v["error"].get("reason").is_none());
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("no room for a") && msg.contains("bad name b"), "{msg}");
        // A delivered file has no refusal.
        let v = result_object(&[one("c", 1)], None, &Ok(()));
        assert_eq!(v["files"][0]["refusal"], Value::Null);
    }

    #[test]
    fn a_renamed_delivery_names_what_landed() {
        // `--name ../../escape.txt` was stored as escape.txt and reported as
        // "ok ../../escape.txt".
        let r = delivered_as("../../escape.txt", Some("escape.txt"));
        assert_eq!(r.as_deref(), Some("escape.txt"));
        assert!(delivered_line("../../escape.txt", r.as_deref()).contains("delivered as escape.txt"));
        assert!(summary_label("../../escape.txt", r.as_deref()).starts_with("escape.txt (sent as"));
        // A 300-byte name stored as 240 bytes.
        let long = "y".repeat(300);
        let stored = format!("/home/b/Tunlion/{}", "y".repeat(240));
        let r = delivered_as(&long, Some(&stored)).unwrap();
        assert_eq!(r.len(), 240);
        let line = delivered_line(&long, Some(&r));
        assert!(line.contains(&format!("delivered as {r}")), "{line}");
        assert!(line.len() < 400, "the offered name is described, not repeated: {}", line.len());
        // The tester's case: a long name, shortened by the receiver. Neither
        // line may print a cut-down "xxx...xxx" name, which reads as the name
        // the file was sent under; the line says what happened instead.
        let label = summary_label(&long, Some(&r));
        for l in [&line, &label] {
            assert!(!l.contains("..."), "no ellipsized name: {l}");
            assert!(l.contains("300-character name, shortened to fit there"), "{l}");
        }
        // A short name that differs is printed in full, never cut.
        assert_eq!(summary_label("a.txt", Some("a (1).txt")), "a (1).txt (sent as a.txt)");
        // A collision on the far side.
        assert_eq!(delivered_as("a.txt", Some("a (1).txt")).as_deref(), Some("a (1).txt"));
        // Same name, or an older receiver that does not say: unchanged lines.
        assert_eq!(delivered_as("a.txt", Some("/x/a.txt")), None);
        assert_eq!(delivered_as("a.txt", None), None);
        assert_eq!(delivered_line("a.txt", None), "    a.txt delivered + verified (whole-file sha256 matched)");
        assert_eq!(summary_label("a.txt", None), "a.txt");
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
