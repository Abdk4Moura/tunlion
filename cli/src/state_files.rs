//! The state files every command trusts, and what happens when one is corrupt.
//!
//! `echo "{garbage" > ~/.config/tunlion/devices.json` used to become "no
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
//!   refusal names that copy, so recovery is one `cp`;
//! - a file that exists but is empty (zero bytes, or only whitespace) is
//!   corrupt too. tunlion never writes one (an empty store is `[]`, an empty
//!   `config` is removed), so a truncated `devices.json` or
//!   `revoked-keys.json` is damage, and reading it as "nothing" would forget
//!   every device or silently drop every revocation;
//! - in `--json` the refusal's `error.code` is `corrupt_state` (exit 2).

use crate::exit_codes;
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
pub(crate) const FILES: [(&str, Shape); 6] = [
    ("devices.json", Shape::JsonArray),
    ("revoked-keys.json", Shape::JsonArray),
    ("used-invitations.json", Shape::JsonArray),
    // The signed capability store: grants and their revocations.
    ("caps.json", Shape::JsonArray),
    ("peerconf", Shape::JsonObject),
    ("config", Shape::KeyValue),
];

fn shape_of(path: &Path) -> Option<Shape> {
    let name = path.file_name()?.to_str()?;
    FILES.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

/// Why `raw` is not a valid file of this shape, or None when it is. An empty
/// (or whitespace-only) file is NOT valid: tunlion never writes one, so it is
/// a truncation, and reading it as empty would drop what it held. Pure.
pub(crate) fn parse_problem(raw: &[u8], shape: Shape) -> Option<String> {
    let text = match std::str::from_utf8(raw) {
        Ok(t) => t,
        Err(e) => return Some(format!("not UTF-8 text ({e})")),
    };
    if text.trim().is_empty() {
        return Some("the file is empty, and no command writes an empty one, so it was truncated".to_string());
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
    exit_codes::CorruptState(format!(
        "{} cannot be parsed ({why}). It is not read as empty, and nothing writes over it until it is fixed. {recover}",
        path.display()
    ))
    .into()
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
        // Empty is a truncation, not "nothing": for every shape.
        for shape in [Shape::JsonArray, Shape::JsonObject, Shape::KeyValue] {
            assert!(parse_problem(b"", shape).is_some(), "{shape:?}");
            assert!(parse_problem(b" \n\t\n", shape).is_some(), "{shape:?}");
        }
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
        assert_eq!(exit_codes::classify(&e), exit_codes::ExitKind::Usage);
        assert_eq!(exit_codes::json_code(&e), "corrupt_state");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{garbage");
        assert_eq!(std::fs::read_to_string(backup_path(&p)).unwrap(), "[]");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A: `: > devices.json` listed "No devices yet." with exit 0, and an
    /// empty revoked-keys.json dropped the revocation list. Both are refused
    /// by name now, as is a corrupt caps.json, and none is written over.
    #[test]
    fn an_empty_or_truncated_store_is_corrupt_and_left_alone() {
        let d = std::env::temp_dir().join(format!("tunlion-state-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(FILES.iter().any(|(n, _)| *n == "caps.json"), "caps.json is checked");
        for (name, body) in [
            ("devices.json", ""),
            ("revoked-keys.json", ""),
            ("used-invitations.json", "  \n"),
            ("caps.json", "[{"),
            ("peerconf", ""),
        ] {
            let p = d.join(name);
            std::fs::write(&p, body).unwrap();
            let e = before_write(&p).unwrap_err();
            assert!(e.to_string().contains(name), "{name}: {e}");
            assert_eq!(exit_codes::classify(&e).code(), 2, "{name}");
            assert_eq!(exit_codes::json_code(&e), "corrupt_state", "{name}");
            assert_eq!(std::fs::read_to_string(&p).unwrap(), body, "{name} untouched");
            let shape = shape_of(&p).unwrap();
            assert!(check_file(&p, shape).is_err(), "{name}");
        }
        // `[]` is legitimately empty.
        let p = d.join("devices.json");
        std::fs::write(&p, "[]").unwrap();
        assert!(before_write(&p).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}
