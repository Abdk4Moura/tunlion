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
    let all = appended(load_from(&p), records);
    if let Ok(body) = serde_json::to_string(&Value::Array(all)) {
        let _ = crate::platform::SecretFile::write_str(&p, &body);
    }
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
    let state = if v["ok"].as_bool() == Some(true) { "" } else { "  (not delivered)" };
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
}
