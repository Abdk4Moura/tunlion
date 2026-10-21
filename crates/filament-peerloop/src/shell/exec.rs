//! The pure `exec-open` frame parser and the process-effect seam.
//!
//! The parser moved verbatim out of `cli::exec_recv` so exec admission can
//! validate the frame before the sid and the shell gate without the CLI. There
//! is no process fact in [`parse_exec_open`]: `argv` is kept exactly as the
//! initiator sent it, and the serve loop resolves PATH, cwd, the environment
//! and the spawn plan later.
//!
//! [`ExecProcess`] is that later seam. It is deliberately a process primitive,
//! not a handler callback: the CLI supplies how to resolve a program on the
//! daemon's PATH, the daemon's environment facts, the account-drop argv, and
//! how to spawn and then observe/kill an owned child. The protocol state
//! machine in `super::exec_server` owns every frame, stream and cancellation
//! decision around it.

use crate::l2::is_l2_sid;
use crate::l2::mux::TreeSignal;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

/// How often an initiator says it is still there (`exec-alive`), announced in
/// its open as `alive_ms`.
pub const EXEC_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a served exec waits without a heartbeat before it decides the
/// initiator is gone: six missed beats, never under 10 s (a busy relay can
/// delay a few), never over a minute (a hostile `alive_ms` cannot buy an
/// orphan a long life).
pub fn alive_deadline(alive_ms: u64) -> std::time::Duration {
    let beat = std::time::Duration::from_millis(alive_ms.clamp(250, 10_000));
    (beat * 6).clamp(
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(60),
    )
}

/// A child's terminal state, carried without `std::process::ExitStatus` so a
/// deterministic test child and the real adapter speak the same vocabulary.
/// A clean exit keeps its raw code; signal death becomes 128+signal (the shell
/// convention: 137 SIGKILL, 143 SIGTERM); no information is `None`, and the
/// close then OMITS status rather than inventing success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl ExecExit {
    /// Map a real waited child, keeping the host's signal fact on unix.
    pub fn from_std(status: std::process::ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
            }
        }
    }

    /// The reportable status, exactly [`status_code`].
    pub fn wire_code(self) -> Option<i32> {
        status_code(self.code, self.signal)
    }
}

/// Pure exit-status mapping, split out so it is unit-testable without spawning.
pub fn status_code(code: Option<i32>, signal: Option<i32>) -> Option<i32> {
    match (code, signal) {
        (Some(c), _) => Some(c),
        (None, Some(s)) => Some(128 + s),
        (None, None) => None,
    }
}

/// One fully-resolved spawn request. The library decided argv exactness, the
/// working directory and the child environment; the host applies the platform
/// effects (process group, parent-death containment, bookkeeping).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecSpawnSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// Already filtered: `env_clear` plus the user-like platform baseline
    /// (`HOME`/`USER`/`SHELL`/XDG and `TERM`/`LANG`/`LC_*` on Unix; the
    /// non-secret Windows machine/profile list on Windows) and explicit
    /// `--env` pairs. The host must not add the daemon environment.
    pub env: Vec<(String, String)>,
}

/// The account an exec will run as. The host resolves this before the child
/// environment is built so `HOME`/`USER`/`SHELL` and the default cwd all name
/// the same account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecUserContext {
    /// Login name (`USER`/`LOGNAME`, or `USERNAME` on Windows).
    pub name: String,
    /// The account's home. Also the default cwd unless the initiator named one.
    pub home: PathBuf,
    /// The account's login shell, when the platform knows it.
    pub shell: Option<String>,
    /// Unix uid, used only to derive a target account's `XDG_RUNTIME_DIR`.
    pub uid: Option<u32>,
}

/// The host's process effects for served exec.
///
/// A host answers only machine facts and applies only process effects. Every
/// protocol decision (ack/close ordering, stdout/stderr sids, collision and
/// capacity rules, heartbeat and revocation cancellation) stays in
/// `super::exec_server`. Implementations must not run a second serve loop.
pub trait ExecProcess: Send + Sync {
    /// Resolve `argv[0]` the way the daemon's own PATH would. Absolute or
    /// relative paths containing a separator are returned as-is; a bare name
    /// is looked up. `None` refuses before any fork.
    fn resolve_program(&self, program: &str) -> Option<PathBuf>;

    /// The daemon's own environment as string pairs. The library applies the
    /// allowlist; this method supplies the ambient fact.
    fn daemon_environment(&self) -> Vec<(String, String)>;

    /// Resolve the account this exec runs as (`None` = the daemon user,
    /// `Some` = `--shell-user`). `Err` refuses the exec before any fork; it
    /// must never fall back to the daemon's identity when a drop was asked
    /// for. On Unix a dropped account comes from the password database, not
    /// from the daemon's environment.
    fn user_context(&self, user: Option<&str>) -> Result<ExecUserContext, String>;

    /// The platform's account-drop argv (`runuser -l <user> -- ...` on unix),
    /// or a reason that names the missing capability. The library checks that
    /// the wrapper resolves on the daemon PATH and refuses rather than running
    /// as the daemon user.
    fn user_drop_argv(
        &self,
        program: &Path,
        args: &[String],
        user: &str,
    ) -> Result<Vec<String>, String>;

    /// Spawn exactly this command with piped stdio, in its own process group,
    /// contained/best-effort tied to the daemon, with the host's own leftover
    /// bookkeeping attached to the returned child's lifetime.
    fn spawn(&self, spec: ExecSpawnSpec) -> Result<Box<dyn ExecChild>, String>;

    /// Test-hook seam for the expiry close-order gate. Production hosts return
    /// false; the CLI reads its compiled-in `test-hooks` environment here so no
    /// ambient variable enters this crate.
    fn test_expiry_close_first(&self) -> bool {
        false
    }
}

/// An owned child plus the host's cleanup bookkeeping.
///
/// `wait` must be cancel-safe (it is polled inside `tokio::select!`); dropping
/// the child must end it or leave it to the host's recorded sweep, exactly as
/// the CLI adapter promises. `signal_group`/`group_alive` name the process-tree
/// effects the ladder uses; `start_kill` is the leader-only fallback.
#[async_trait::async_trait]
pub trait ExecChild: Send {
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send>>;
    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>>;
    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>>;
    async fn wait(&mut self) -> std::io::Result<ExecExit>;
    fn try_wait(&mut self) -> std::io::Result<Option<ExecExit>>;
    fn start_kill(&mut self);
    /// Signal the whole process tree; true when the host delivered it.
    fn signal_group(&self, sig: TreeSignal) -> bool;
    /// Is any member of the child's process group still alive?
    fn group_alive(&self) -> bool;
}

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
        assert!(
            parse_exec_open(&frame).is_none(),
            "MAX_ARGV + 1 must refuse"
        );

        frame["argv"] = json!(["ok", "x".repeat(MAX_ARG_LEN)]);
        let req = parse_exec_open(&frame).expect("MAX_ARG_LEN bytes are accepted");
        assert_eq!(req.argv[1].len(), MAX_ARG_LEN);
        frame["argv"] = json!(["ok", "x".repeat(MAX_ARG_LEN + 1)]);
        assert!(
            parse_exec_open(&frame).is_none(),
            "MAX_ARG_LEN + 1 must refuse"
        );
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

    /// The silence an acceptor tolerates is bounded on both sides: a beat it
    /// can miss a few of, and never long enough for a hostile `alive_ms` to
    /// buy an orphan a long life.
    #[test]
    fn heartbeat_deadline_is_bounded() {
        use std::time::Duration;
        let ours = EXEC_ALIVE_INTERVAL.as_millis() as u64;
        let d = alive_deadline(ours);
        assert!(
            d >= Duration::from_secs(10) && d <= Duration::from_secs(15),
            "{d:?}"
        );
        assert_eq!(alive_deadline(1), Duration::from_secs(10));
        assert_eq!(alive_deadline(u64::MAX), Duration::from_secs(60));
    }

    #[test]
    fn status_mapping_is_shell_convention() {
        assert_eq!(status_code(Some(0), None), Some(0));
        assert_eq!(status_code(Some(1), None), Some(1));
        assert_eq!(status_code(None, Some(9)), Some(137));
        assert_eq!(status_code(None, Some(15)), Some(143));
        assert_eq!(status_code(None, None), None);
        assert_eq!(
            ExecExit {
                code: None,
                signal: Some(6)
            }
            .wire_code(),
            Some(134)
        );
    }

    #[test]
    fn exec_control_frames_parse_and_unknowns_are_ignored() {
        use crate::l2::mux::ExecCtl;
        use crate::l2::mux::TreeSignal;
        assert_eq!(
            ExecCtl::from_frame(&json!({"type": "exec-alive", "sid": 1})),
            Some(ExecCtl::Alive)
        );
        assert_eq!(
            ExecCtl::from_frame(&json!({"type": "exec-signal", "sid": 1, "signal": "INT"})),
            Some(ExecCtl::Signal(TreeSignal::Interrupt))
        );
        assert_eq!(
            ExecCtl::from_frame(&json!({"type": "exec-signal", "sid": 1, "signal": "STOP"})),
            None
        );
        assert_eq!(
            ExecCtl::from_frame(&json!({"type": "exec-signal", "sid": 1})),
            None
        );
        assert_eq!(
            ExecCtl::from_frame(&json!({"type": "exec-open", "sid": 1})),
            None
        );
    }
}
