//! The pure `exec-open` frame parser.
//!
//! Moved verbatim out of `cli::exec_recv` so exec admission can validate the
//! frame before the sid and the shell gate without the CLI. There is no
//! process fact here: `argv` is kept exactly as the initiator sent it, and the
//! caller resolves PATH, cwd, the environment and the spawn plan later.

use crate::l2::is_l2_sid;
use serde_json::Value;
use std::path::PathBuf;

/// Bounds that keep a hostile or buggy initiator from turning an open frame
/// into unbounded allocation. Generous on purpose: real commands (long rsync
/// lines, big --env blobs) must fit comfortably; only absurd frames refuse.
const MAX_ARGV: usize = 128;
const MAX_ARG_LEN: usize = 32 * 1024;
const MAX_ENV_PAIRS: usize = 64;
const MAX_ENV_VAL_LEN: usize = 32 * 1024;
const MAX_NAME_LEN: usize = 128;

/// A validated `exec-open` request: argv[] verbatim plus the execution context.
pub struct ExecOpen {
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub tty: bool,
    /// Initiator-allocated stderr sid, announced in the open so BOTH ends use
    /// one value (same discipline as `sid` itself -- the initiator registers
    /// the pipe before the open goes out, so stderr racing the ack finds it).
    pub err_sid: u32,
    /// The initiator's heartbeat interval (`alive_ms`), when it promises one:
    /// the session then ends if it stops hearing them. None for an initiator
    /// that predates heartbeats, which is held to its link alone.
    pub alive_ms: Option<u64>,
}

/// Parse and validate an `exec-open` frame. Returns None (caller ignores the
/// frame, like every other malformed open) when argv[] is missing, not an
/// array, empty, over-long, or holds a non-string -- never defaulting or
/// truncating into something executable. Malformed env entries are DROPPED
/// individually (an odd entry must not kill an otherwise good open); a
/// missing/invalid cwd or tty falls back to the default.
pub fn parse_exec_open(v: &Value) -> Option<ExecOpen> {
    let arr = v.get("argv")?.as_array()?;
    if arr.is_empty() || arr.len() > MAX_ARGV {
        return None;
    }
    let mut argv = Vec::with_capacity(arr.len());
    for a in arr {
        let s = a.as_str()?;
        if s.len() > MAX_ARG_LEN {
            return None;
        }
        argv.push(s.to_string());
    }
    let cwd = v
        .get("cwd")
        .and_then(|c| c.as_str())
        .filter(|c| !c.is_empty() && c.len() <= 4096)
        .map(PathBuf::from);
    let mut env = Vec::new();
    if let Some(obj) = v.get("env").and_then(|e| e.as_array()) {
        for pair in obj.iter().take(MAX_ENV_PAIRS + 1) {
            let Some(s) = pair.as_str() else { continue };
            let Some((k, val)) = s.split_once('=') else {
                continue;
            };
            if k.is_empty()
                || k.len() > MAX_NAME_LEN
                || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || val.len() > MAX_ENV_VAL_LEN
            {
                continue;
            }
            env.push((k.to_string(), val.to_string()));
            if env.len() >= MAX_ENV_PAIRS {
                break;
            }
        }
    }
    let tty = v.get("tty").and_then(|t| t.as_bool()).unwrap_or(false);
    // Fail closed on a missing/forged stderr sid: defaulting to 0 would alias
    // a live stream, and allocating a second value the initiator never
    // listens on silently drops stderr (both observed live). Same
    // no-truncation discipline as `wire_sid`, plus the L2-half check.
    let err_sid = u32::try_from(v.get("err_sid")?.as_u64()?).ok()?;
    if !is_l2_sid(err_sid) {
        return None;
    }
    let alive_ms = v
        .get("alive_ms")
        .and_then(|a| a.as_u64())
        .filter(|a| *a > 0);
    Some(ExecOpen {
        argv,
        cwd,
        env,
        tty,
        err_sid,
        alive_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_keeps_argv_exact() {
        let v = json!({
            "type": "exec-open", "sid": 1, "err_sid": 2147483649u64,
            "argv": ["rsync", "-a", "my dir/with spaces", "--exclude='*.tmp'", "*.log"],
            "cwd": "/tmp", "env": ["FOO=bar"], "tty": false,
        });
        let req = parse_exec_open(&v).expect("valid frame parses");
        assert_eq!(
            req.argv,
            vec![
                "rsync",
                "-a",
                "my dir/with spaces",
                "--exclude='*.tmp'",
                "*.log"
            ]
        );
        assert_eq!(req.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(req.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert!(!req.tty);
        assert_eq!(req.err_sid, 2147483649);
    }

    #[test]
    fn parse_rejects_missing_or_forged_err_sid() {
        let base = json!({"type": "exec-open", "sid": 1, "argv": ["true"]});
        assert!(parse_exec_open(&base).is_none());
        let mut low = base.clone();
        low["err_sid"] = json!(7u64);
        assert!(parse_exec_open(&low).is_none());
        let mut big = base.clone();
        big["err_sid"] = json!(0x1_8000_0000u64);
        assert!(parse_exec_open(&big).is_none());
        let mut ok = base.clone();
        ok["err_sid"] = json!(2147483649u64);
        assert!(parse_exec_open(&ok).is_some());
    }

    #[test]
    fn parse_rejects_bad_argv() {
        for bad in [
            json!({"type": "exec-open", "sid": 1}),
            json!({"type": "exec-open", "sid": 1, "argv": []}),
            json!({"type": "exec-open", "sid": 1, "argv": "ls -la"}),
            json!({"type": "exec-open", "sid": 1, "argv": [42]}),
        ] {
            assert!(parse_exec_open(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_drops_malformed_env_and_applies_defaults() {
        let v = json!({
            "type": "exec-open", "sid": 1, "err_sid": 2147483649u64,
            "argv": ["true"],
            "env": ["OK=1", "NOEQUALS", "=nokey", "BAD KEY=x"],
        });
        let req = parse_exec_open(&v).expect("parses");
        assert_eq!(req.env, vec![("OK".to_string(), "1".to_string())]);
        assert!(req.cwd.is_none());
        assert!(!req.tty);
    }

    #[test]
    fn parse_rejects_absurd_frames() {
        // All companion fields are valid: rejection must come from the bound
        // under test, not (for example) a missing required stderr sid.
        let mut frame = json!({
            "type": "exec-open", "sid": crate::l2::L2_SID_BASE,
            "err_sid": crate::l2::L2_SID_BASE + 1,
            "cwd": "/tmp", "env": ["OK=1"], "tty": false,
            "argv": vec!["arg"; MAX_ARGV],
        });
        let req = parse_exec_open(&frame).expect("MAX_ARGV arguments are accepted");
        assert_eq!(req.argv.len(), MAX_ARGV);
        frame["argv"] = json!(vec!["arg"; MAX_ARGV + 1]);
        assert!(parse_exec_open(&frame).is_none(), "MAX_ARGV + 1 must refuse");

        frame["argv"] = json!(["ok", "x".repeat(MAX_ARG_LEN)]);
        let req = parse_exec_open(&frame).expect("MAX_ARG_LEN bytes are accepted");
        assert_eq!(req.argv[1].len(), MAX_ARG_LEN);
        frame["argv"] = json!(["ok", "x".repeat(MAX_ARG_LEN + 1)]);
        assert!(parse_exec_open(&frame).is_none(), "MAX_ARG_LEN + 1 must refuse");
    }

    /// An open that promises heartbeats carries `alive_ms`; one that does not
    /// (an older initiator) is held to its link alone, never to a default.
    #[test]
    fn parse_reads_the_heartbeat_promise() {
        let base =
            json!({"type": "exec-open", "sid": 1, "err_sid": 2147483649u64, "argv": ["true"]});
        assert_eq!(parse_exec_open(&base).unwrap().alive_ms, None);
        let mut with = base.clone();
        with["alive_ms"] = json!(2000u64);
        assert_eq!(parse_exec_open(&with).unwrap().alive_ms, Some(2000));
        let mut zero = base.clone();
        zero["alive_ms"] = json!(0u64);
        assert_eq!(parse_exec_open(&zero).unwrap().alive_ms, None);
    }
}
