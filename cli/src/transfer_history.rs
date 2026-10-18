//! Structured transfer history, kept on both ends.
//!
//! Before this the sender kept nothing (`status --json` showed an empty
//! `recent` on the device that sent), and the receiver's `recent` was the raw
//! lines of its human log. Each finished transfer is now one record, written by
//! the side that saw it: time, direction, peer, file, the stored name (the
//! receiver's, when known), bytes, sha256 and whether it landed. The file is a
//! JSON array in the config dir, owner-only, and bounded to the newest
//! [`MAX_RECORDS`], so it never grows without limit.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Mutex;

/// How many records are kept. Old ones fall off the front.
pub(crate) const MAX_RECORDS: usize = 200;

/// Serializes writers in one process (the daemon finalizes files from one
/// loop, but a `send` and a test may race).
static LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Record {
    /// Unix seconds.
    pub(crate) time: u64,
    /// "in" (received here) or "out" (sent from here).
    pub(crate) direction: &'static str,
    pub(crate) peer: Option<String>,
    /// The name the file was offered under.
    pub(crate) file: String,
    /// Where it was stored: the full path on the receiver; on the sender, the
    /// name the receiver reported storing it under, when it did.
    pub(crate) stored: Option<String>,
    pub(crate) bytes: u64,
    pub(crate) sha256: Option<String>,
    pub(crate) ok: bool,
}

impl Record {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "time": self.time,
            "direction": self.direction,
            "peer": self.peer,
            "file": self.file,
            "stored": self.stored,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "ok": self.ok,
        })
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path() -> PathBuf {
    crate::settings::config_dir().join("transfers.json")
}

/// Append `records` to `existing` and keep the newest `MAX_RECORDS`. Pure.
pub(crate) fn appended(mut existing: Vec<Value>, records: &[Record]) -> Vec<Value> {
    existing.extend(records.iter().map(Record::to_json));
    if existing.len() > MAX_RECORDS {
        let drop = existing.len() - MAX_RECORDS;
        existing.drain(..drop);
    }
    existing
}

fn load_from(p: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

// The data file is atomically replaced, so lock a stable sidecar rather than
// its inode. The in-process mutex alone cannot coordinate separate senders.
fn writer_lock(p: &std::path::Path) -> anyhow::Result<crate::platform::DevicesFileLock> {
    if let Some(parent) = p.parent() {
        crate::platform::create_private_dir_all(parent)?;
    }
    crate::platform::DevicesFileLock::acquire_at(&p.with_extension("json.lock"))
}

/// Every stored record, oldest first.
pub(crate) fn load() -> Vec<Value> {
    load_from(&path())
}

/// Record finished transfers. Best-effort: history never fails a transfer.
pub(crate) fn append(records: &[Record]) {
    if records.is_empty() {
        return;
    }
    let _g = LOCK.lock();
    let p = path();
    let Ok(_writer_lock) = writer_lock(&p) else { return };
    let all = appended(load_from(&p), records);
    if let Ok(body) = serde_json::to_string(&Value::Array(all)) {
        let _ = crate::platform::SecretFile::write_str(&p, &body);
    }
}

/// Append already-shaped records, keeping the newest [`MAX_RECORDS`].
pub(crate) fn append_values(values: Vec<Value>) {
    if values.is_empty() {
        return;
    }
    let _g = LOCK.lock();
    let p = path();
    let Ok(_writer_lock) = writer_lock(&p) else { return };
    let mut all = load_from(&p);
    all.extend(values);
    if all.len() > MAX_RECORDS {
        let drop = all.len() - MAX_RECORDS;
        all.drain(..drop);
    }
    if let Ok(body) = serde_json::to_string(&Value::Array(all)) {
        let _ = crate::platform::SecretFile::write_str(&p, &body);
    }
}

/// Records for a send that failed before any file was offered (its source
/// could not be read, or `send -` ran out of spool space): one `ok: false`
/// record per named source, carrying the reason as `error`. Pure. Such a send
/// used to leave no trace in the history at all.
pub(crate) fn unoffered_records(peer: Option<&str>, sources: &[String], reason: &str, now: u64) -> Vec<Value> {
    sources
        .iter()
        .map(|s| {
            let mut v = Record {
                time: now,
                direction: "out",
                peer: peer.map(str::to_string),
                file: s.clone(),
                stored: None,
                bytes: 0,
                sha256: None,
                ok: false,
            }
            .to_json();
            v["error"] = json!(reason);
            v
        })
        .collect()
}

/// Record a send that failed before any file was offered (see
/// [`unoffered_records`]).
pub(crate) fn append_unoffered(peer: Option<&str>, sources: &[String], reason: &str) {
    append_values(unoffered_records(peer, sources, reason, now_secs()));
}

/// The newest `n` records, oldest first, as `status --json` reports them.
pub(crate) fn recent(n: usize) -> Vec<Value> {
    let all = load();
    let skip = all.len().saturating_sub(n);
    all.into_iter().skip(skip).collect()
}

/// One human line for a record, for `status` in text mode.
pub(crate) fn human_line(v: &Value) -> String {
    let arrow = if v["direction"] == "out" { "sent" } else { "received" };
    let prep = if v["direction"] == "out" { "to" } else { "from" };
    let peer = v["peer"].as_str().unwrap_or("?");
    let file = v["file"].as_str().unwrap_or("?");
    let bytes = crate::human(v["bytes"].as_u64().unwrap_or(0));
    let state = match (v["ok"].as_bool(), v["error"].as_str()) {
        (Some(true), _) => String::new(),
        (_, Some(why)) => format!("  (failed: {why})"),
        _ => "  (not delivered)".to_string(),
    };
    let stored = match v["stored"].as_str() {
        Some(s) if v["direction"] == "in" || s != file => format!(" -> {s}"),
        _ => String::new(),
    };
    format!("{arrow} {file}{stored}  {bytes}  {prep} {peer}{state}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: u64) -> Record {
        Record {
            time: i,
            direction: "out",
            peer: Some("laptop".into()),
            file: format!("f{i}"),
            stored: None,
            bytes: i,
            sha256: Some("ab".repeat(32)),
            ok: true,
        }
    }

    #[test]
    fn a_record_is_an_object_with_every_field() {
        let v = rec(7).to_json();
        for k in ["time", "direction", "peer", "file", "stored", "bytes", "sha256", "ok"] {
            assert!(v.get(k).is_some(), "missing {k}: {v}");
        }
        assert_eq!(v["direction"], json!("out"));
        assert_eq!(v["ok"], json!(true));
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest() {
        let mut all = Vec::new();
        for i in 0..(MAX_RECORDS as u64 + 25) {
            all = appended(all, &[rec(i)]);
        }
        assert_eq!(all.len(), MAX_RECORDS);
        assert_eq!(all[0]["time"], json!(25));
        assert_eq!(all[MAX_RECORDS - 1]["time"], json!(MAX_RECORDS as u64 + 24));
    }

    #[test]
    fn human_lines_name_direction_peer_and_stored_name() {
        let mut r = rec(1);
        r.file = "a.txt".into();
        r.stored = Some("a (1).txt".into());
        let line = human_line(&r.to_json());
        assert!(line.starts_with("sent a.txt -> a (1).txt"), "{line}");
        assert!(line.contains("to laptop"), "{line}");
        r.direction = "in";
        r.ok = false;
        let line = human_line(&r.to_json());
        assert!(line.starts_with("received a.txt"), "{line}");
        assert!(line.contains("from laptop") && line.contains("not delivered"), "{line}");
    }

    /// E4: `send -` that ran out of spool space failed before offering
    /// anything, and the history had no trace of it. A failed send is
    /// recorded too, `ok: false`, with its reason.
    #[test]
    fn a_send_that_failed_before_offering_is_recorded_with_its_reason() {
        let recs = unoffered_records(
            Some("laptop"),
            &["stdin".to_string()],
            "no space left for the stdin spool in /tmp",
            42,
        );
        assert_eq!(recs.len(), 1);
        let v = &recs[0];
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["direction"], json!("out"));
        assert_eq!(v["file"], json!("stdin"));
        assert_eq!(v["time"], json!(42));
        assert!(v["error"].as_str().unwrap().contains("no space"), "{v}");
        let line = human_line(v);
        assert!(line.contains("failed: no space left"), "{line}");
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Writer(std::process::Child);
    impl Drop for Writer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // A separate process is essential: the existing Mutex already serializes
    // threads, but concurrent `send --code` processes share transfers.json.
    #[test]
    #[ignore = "subprocess helper invoked by concurrent_process_append_preserves_both_outcomes"]
    fn history_writer_child() {
        let dir = PathBuf::from(std::env::var_os("TUNLION_HISTORY_TEST_DIR").unwrap());
        std::fs::write(dir.join("writer-ready"), b"ready").unwrap();
        match std::env::var("TUNLION_HISTORY_TEST_MODE").unwrap().as_str() {
            "records" => append(&[rec(2)]),
            "values" => append_values(vec![rec(2).to_json()]),
            other => panic!("unknown writer mode: {other}"),
        }
    }

    #[test]
    fn concurrent_process_append_preserves_both_outcomes() {
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        for mode in ["records", "values"] {
            let dir = Fixture(std::env::temp_dir().join(format!(
                "tunlion-history-lock-{}-{}-{mode}",
                std::process::id(),
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            )));
            std::fs::create_dir(&dir.0).unwrap();
            let history = dir.0.join("transfers.json");
            crate::platform::SecretFile::write_str(&history, "[]").unwrap();
            // Hold the same stable sidecar used by a cooperating writer. The
            // worker must wait BEFORE loading history. While it waits, publish
            // our outcome; its subsequent append must preserve both records.
            let lock = crate::platform::DevicesFileLock::acquire_at(
                &dir.0.join("transfers.json.lock"),
            ).unwrap();
            let mut writer = Writer(crate::platform::command(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "transfer_history::tests::history_writer_child"])
                .env("TUNLION_CONFIG_DIR", &dir.0)
                .env("TUNLION_HISTORY_TEST_DIR", &dir.0)
                .env("TUNLION_HISTORY_TEST_MODE", mode)
                .spawn().unwrap());
            let ready_deadline = Instant::now() + Duration::from_secs(10);
            while !dir.0.join("writer-ready").exists() {
                assert!(writer.0.try_wait().unwrap().is_none(), "writer exited before readiness");
                assert!(Instant::now() < ready_deadline, "writer never became ready");
                std::thread::sleep(Duration::from_millis(10));
            }
            // This is a controlled lock-contention test, not a probabilistic
            // burst of writes. On the unfixed path the child completes while we
            // hold the sidecar, then our ordered replace loses its outcome.
            let blocked_deadline = Instant::now() + Duration::from_secs(2);
            let premature = loop {
                if let Some(status) = writer.0.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= blocked_deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            crate::platform::SecretFile::write_str(
                &history, &serde_json::to_string(&vec![rec(1).to_json()]).unwrap(),
            ).unwrap();
            drop(lock);
            let finish_deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = writer.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < finish_deadline, "writer did not finish after unlock");
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success(), "{mode} writer failed: {status}");
            assert_eq!(
                load_from(&history), vec![rec(1).to_json(), rec(2).to_json()],
                "{mode}: writer completed while sidecar held: {premature:?}; lost an outcome",
            );
            assert!(premature.is_none(), "{mode}: writer bypassed the process lock");
        }
    }
}
