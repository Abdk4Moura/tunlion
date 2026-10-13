//! The state files every command trusts, and what happens when one is corrupt.
//!
//! `echo "{garbage" > ~/.config/filament/devices.json` used to become "no
//! devices": `devices` exited 0 with an empty list, `devices --json` said
//! `ok: true`, and `send --to alpha` said there was no such device (3). A
//! reader that treats an unparseable store as empty hides the damage, and the
//! next write would have replaced it with an empty one for good.
//!
//! Now:
//! - every command except the ones that repair or stop (`reset`, `down`,
//!   `logs`, `config`, `completions`, `man`, `update`) checks these files first
//!   and refuses with the file's path and the parse error, exit 2 (a local
//!   file problem);
//! - a write over one that does not parse is refused (`before_write`), so the
//!   damaged file stays for a person to inspect or repair;
//! - every write first copies the current, valid file to `<name>.bak`, and the
//!   refusal names that copy, so recovery is one `cp`.

use crate::exit_codes::{self, ExitKind};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// How a state file is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    JsonArray,
    JsonObject,
    /// `key value` lines (`config`).
    KeyValue,
}

/// The files checked, relative to the config directory.
pub(crate) const FILES: [(&str, Shape); 5] = [
    ("devices.json", Shape::JsonArray),
    ("revoked-keys.json", Shape::JsonArray),
    ("used-invitations.json", Shape::JsonArray),
    ("peerconf", Shape::JsonObject),
    ("config", Shape::KeyValue),
];

fn shape_of(path: &Path) -> Option<Shape> {
    let name = path.file_name()?.to_str()?;
    FILES.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

/// Why `raw` is not a valid file of this shape, or None when it is. An empty
/// file is valid (it holds nothing). Pure.
pub(crate) fn parse_problem(raw: &[u8], shape: Shape) -> Option<String> {
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(e) => return Some(format!("not UTF-8 text ({e})")),
    };
    if text.trim().is_empty() {
        return None;
    }
    match shape {
        Shape::JsonArray => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) if v.is_array() => None,
            Ok(_) => Some("expected a JSON array".to_string()),
            Err(e) => Some(e.to_string()),
        },
        Shape::JsonObject => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) if v.is_object() => None,
            Ok(_) => Some("expected a JSON object".to_string()),
            Err(e) => Some(e.to_string()),
        },
        Shape::KeyValue => text.lines().enumerate().find_map(|(i, l)| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let key = l.split_whitespace().next().unwrap_or_default();
            let ok = key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            (!ok).then(|| format!("line {}: expected `key value`, found {l:?}", i + 1))
        }),
    }
}

/// Where the last good copy of `path` is kept.
pub(crate) fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".bak");
    path.with_file_name(name)
}

/// The error for a corrupt state file: its path, the parse error, and how to
/// recover. Exit 2.
pub(crate) fn corrupt_error(path: &Path, why: &str) -> anyhow::Error {
    let bak = backup_path(path);
    let recover = if bak.exists() {
        format!(
            "Fix it, or restore the last good copy: cp {} {}",
            bak.display(),
            path.display()
        )
    } else {
        "Fix it, or move it aside to start with an empty one (that forgets what it held)".to_string()
    };
    exit_codes::err(
        ExitKind::Usage,
        format!(
            "{} cannot be parsed ({why}). tunlion will not read it as empty or write over it. {recover}",
            path.display()
        ),
    )
}

/// Ok when `path` is absent or parses; the corrupt-file error otherwise.
pub(crate) fn check_file(path: &Path, shape: Shape) -> Result<()> {
    match std::fs::read(path) {
        Ok(raw) => match parse_problem(&raw, shape) {
            None => Ok(()),
            Some(why) => Err(corrupt_error(path, &why)),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // Unreadable (permissions): the command that needs it says so.
        Err(_) => Ok(()),
    }
}

/// Check every state file in this config directory.
pub(crate) fn check_all() -> Result<()> {
    let dir = crate::platform::Paths::config_dir();
    for (name, shape) in FILES {
        check_file(&dir.join(name), shape)?;
    }
    Ok(())
}

/// Copy the current `path` to its `.bak`, when it exists. Best effort: a
/// failed copy never blocks the write it protects.
pub(crate) fn keep_backup(path: &Path) {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if !raw.trim().is_empty() {
            let _ = crate::platform::SecretFile::write_str(&backup_path(path), &raw);
        }
    }
}

/// Call before overwriting a state file: refuses when the file on disk does
/// not parse (it stays for a person to repair), else keeps a `.bak` of it.
pub(crate) fn before_write(path: &Path) -> Result<()> {
    if let Some(shape) = shape_of(path) {
        check_file(path, shape)?;
    }
    keep_backup(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_a_problem_and_valid_or_empty_is_not() {
        assert!(parse_problem(b"{garbage", Shape::JsonArray).is_some());
        assert!(parse_problem(b"{}", Shape::JsonArray).is_some());
        assert!(parse_problem(b"[]", Shape::JsonArray).is_none());
        assert!(parse_problem(b"", Shape::JsonArray).is_none());
        assert!(parse_problem(b"{\"a\":{}}", Shape::JsonObject).is_none());
        assert!(parse_problem(b"[1]", Shape::JsonObject).is_some());
        assert!(parse_problem(b"server http://x\nname box\n", Shape::KeyValue).is_none());
        assert!(parse_problem(b"{garbage\n", Shape::KeyValue).is_some());
        assert!(parse_problem(&[0xff, 0xfe], Shape::KeyValue).is_some());
    }

    #[test]
    fn a_corrupt_file_is_refused_by_name_and_never_written_over() {
        let d = std::env::temp_dir().join(format!("tunlion-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("devices.json");
        std::fs::write(&p, "[]").unwrap();
        before_write(&p).unwrap();
        assert!(backup_path(&p).exists(), "a write keeps the last good copy");
        std::fs::write(&p, "{garbage").unwrap();
        let e = before_write(&p).unwrap_err();
        let m = e.to_string();
        assert!(m.contains("devices.json") && m.contains("cp "), "{m}");
        assert_eq!(exit_codes::classify(&e), ExitKind::Usage);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{garbage");
        assert_eq!(std::fs::read_to_string(backup_path(&p)).unwrap(), "[]");
        let _ = std::fs::remove_dir_all(&d);
    }
}
