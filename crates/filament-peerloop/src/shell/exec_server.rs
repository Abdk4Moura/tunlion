//! The `exec-open` protocol state machine.
//!
//! This is the single implementation of the acceptor side of exec: admission,
//! capacity/collision registration, the ack, the detached serve loop, its
//! stdout/stderr pumps, and every cancellation path. The CLI supplies only the
//! process primitive in [`crate::shell::exec::ExecProcess`]; it must not run a
//! second serve loop.
//!
//! The contract is preserved from `cli::exec_recv` verbatim:
//!
//! * admission is [`admit_exec_open`] (serving close, transport, frame parse,
//!   sid, shared shell gate), then the per-link mux is created, the stream cap
//!   is checked BEFORE spawning, and the sid is registered collision-safe;
//! * `argv[]` is spawned DIRECTLY -- no shell, no login shell, no re-parse;
//! * cwd/env/user-drop policy is decided here, with the host supplying only its
//!   process facts;
//! * stdout and stderr travel on SEPARATE sids (`sid` and the initiator's
//!   `err_sid`), announced in `exec-open-ack`;
//! * stdin EOF is non-terminal; channel death ends the tree;
//! * exit is the raw code, or 128+signal, and a lost close is followed by both
//!   stream-end sentinels and named `l2-close`s;
//! * initiator heartbeats/link death, forwarded signals, and live
//!   revocation/expiry/ceiling narrowing all end the same process tree through
//!   one escalation ladder.
//!
//! The `SERVED_GROUPS` file and platform process tokens stay in the CLI
//! adapter: the library never reads a settings path, an environment variable,
//! a process id or a clock for those facts.

use crate::conn::Conn;
use crate::host::{HostServices, LogSink};
use crate::l2;
use crate::l2::mux::{ExecCtl, TreeSignal};
use crate::recv::dispatch::{park_on_deny, ParkKind, ParkedOpen};
use crate::refusal::{expired_at_from_reason, Code, Refusal};
use crate::shell::admit::{admit_exec_open, ShellAdmission, ShellAdmissionConfig};
use crate::shell::exec::{
    alive_deadline, ExecChild, ExecOpen, ExecProcess, ExecSpawnSpec, ExecUserContext,
};
use crate::shell_gate::ShellPolicy;
use filament_cap::capability::CAP_SHELL;
use filament_transport::net::Transport;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Grace each gentler signal gets before the next, harder one.
const TREE_GRACE: std::time::Duration = std::time::Duration::from_millis(1500);

/// How often the serve loop checks initiator liveness.
const LIVENESS_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// How one exec is spawned: the resolved program, its args, and the account it
/// runs as (None = the daemon user, only when no `--shell-user` is set).
#[derive(Debug)]
struct ExecSpawnPlan {
    program: PathBuf,
    args: Vec<String>,
    run_as: Option<String>,
}

/// Decide how to spawn an exec. With `--shell-user` set, the command runs as
/// that account through the PTY path's own drop (`Paths::exec_as_user_argv`,
/// runuser on Unix); where that drop does not exist, or its tool cannot be
/// found, the exec is REFUSED with the reason rather than run as the daemon
/// user. `program` is argv[0] already resolved on the daemon PATH.
fn exec_spawn_plan(
    process: &dyn ExecProcess,
    program: &Path,
    args: &[String],
    shell_user: Option<&str>,
) -> Result<ExecSpawnPlan, String> {
    let Some(user) = shell_user else {
        return Ok(ExecSpawnPlan {
            program: program.to_path_buf(),
            args: args.to_vec(),
            run_as: None,
        });
    };
    let argv = process.user_drop_argv(program, args, user)?;
    let (head, rest) = argv
        .split_first()
        .ok_or_else(|| "exec refused: empty spawn argv".to_string())?;
    // The drop tool resolves on the daemon PATH like argv[0] does: the child
    // env is cleared, so a bare name would otherwise search no PATH at all.
    let wrapper = process.resolve_program(head).ok_or_else(|| {
        format!(
            "exec refused: --shell-user {user} is set but `{head}` was not found on the daemon PATH, and running the command as the daemon user would ignore that setting"
        )
    })?;
    Ok(ExecSpawnPlan {
        program: wrapper,
        args: rest.to_vec(),
        run_as: Some(user.to_string()),
    })
}

/// Starting directory when the initiator names none: the account's home, or
/// `/` when a dropped account has no usable home (the same fallback a login
/// shell documents for an account whose passwd home is missing). `HOME` still
/// names the account's passwd home, so the exception is named here rather than
/// silently substituting the daemon's identity.
fn default_exec_cwd(user: &ExecUserContext) -> PathBuf {
    user.home
        .is_dir()
        .then(|| user.home.clone())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// The non-secret Windows variables that make a child a normal Windows
/// process rather than a bare `CreateProcess`. Only these NAMES cross from the
/// daemon's environment; every value still comes from the daemon locally and
/// is never carried on the link.
///
/// `SystemRoot`/`WINDIR`/`SYSTEMDRIVE` are what Win32 itself assumes: the
/// loader, side-by-side resolution, registry views, and the system DLLs and
/// RNG providers Windows and Node reach for. A child without them is not a
/// normal Windows process; the reported failures were Node's `ncrypto::CSPRNG`
/// abort and WSL refusing to launch, and handing over the full environment was
/// the workaround this baseline replaces.
/// `PATH`/`PATHEXT`/`COMSPEC` are how the child and the shells or Node
/// process-spawn paths it starts find programs (`cmd.exe` included).
/// `TEMP`/`TMP` are `GetTempPath` and the staging npm, node-gyp and ordinary
/// tools do. The profile and program roots are where Node, npm and
/// toolchains look for config, caches, global prefixes and installed tools.
/// `PSModulePath`, the account name/domain and the processor identity are the
/// same kind of non-secret machine fact and are routinely read by toolchains.
///
/// This list is only ever used for the daemon's own account on Windows:
/// `--shell-user` is refused there because running as another account needs
/// its token/credentials. If that changes, the target's environment must come
/// from `CreateEnvironmentBlock` on the target token (then be filtered through
/// this list), never from the daemon's `USERPROFILE`/`APPDATA`/`HOMEDRIVE`.
/// Deliberately absent: proxy settings, credentials/tokens, `NODE_OPTIONS`,
/// `SSH_AUTH_SOCK`, session-bus addresses, and every other variable that can
/// carry a secret or change how a command resolves.
const WINDOWS_PLATFORM_ENV: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "SYSTEMDRIVE",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "PSModulePath",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE",
];

/// The Unix half of the same policy. Identity values are replaced from the
/// resolved account (passwd for `--shell-user`, the daemon's own login facts
/// otherwise); `PATH` remains the daemon's search path because argv[0] was
/// already resolved against it and a login-shell PATH would require re-running
/// a shell. `TMPDIR` and XDG roots are target-home based for a dropped account.
const UNIX_PLATFORM_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PATH",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
];

/// The Unix default when the daemon has no usable PATH. It is the conventional
/// system path, not a copy of any account's private bin directories.
const UNIX_DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Environment names are case-insensitive on Windows and case-sensitive
/// everywhere else. Keeping the rule explicit makes both behaviours testable
/// on any host.
fn env_names_equal(a: &str, b: &str, windows: bool) -> bool {
    if windows {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// `TERM`, `LANG` and `LC_*` are locale/terminal facts, not credentials, and
/// pass through from the daemon on every platform. Everything else comes from
/// the platform allowlists above.
fn env_name_is_allowed(k: &str, windows: bool) -> bool {
    let names = if windows {
        WINDOWS_PLATFORM_ENV
    } else {
        UNIX_PLATFORM_ENV
    };
    names.iter().any(|name| env_names_equal(name, k, windows))
        || if windows {
            k.eq_ignore_ascii_case("TERM")
                || k.eq_ignore_ascii_case("LANG")
                || k.get(..3)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("LC_"))
        } else {
            k == "TERM" || k == "LANG" || k.starts_with("LC_")
        }
}

/// Set one pair, replacing an existing name (case-insensitively on Windows) so
/// the child never receives duplicates the OS would collapse unpredictably.
fn set_env(out: &mut Vec<(String, String)>, k: &str, v: &str, windows: bool) {
    if let Some(slot) = out
        .iter_mut()
        .find(|(existing, _)| env_names_equal(existing, k, windows))
    {
        slot.0 = k.to_string();
        slot.1 = v.to_string();
    } else {
        out.push((k.to_string(), v.to_string()));
    }
}

fn remove_env(out: &mut Vec<(String, String)>, k: &str, windows: bool) {
    out.retain(|(existing, _)| !env_names_equal(existing, k, windows));
}

fn has_env(out: &[(String, String)], k: &str, windows: bool) -> bool {
    out.iter()
        .any(|(existing, _)| env_names_equal(existing, k, windows))
}

fn ensure_env(out: &mut Vec<(String, String)>, k: &str, v: &str, windows: bool) {
    if !has_env(out, k, windows) {
        out.push((k.to_string(), v.to_string()));
    }
}

/// Split a `C:\Users\name` home into `(C:, \Users\name)` for the legacy
/// HOMEDRIVE/HOMEPATH pair Windows tools still read. UNC and drive-relative
/// homes are left alone: inventing a drive for them would be worse than
/// omitting the pair.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_home_parts(home: &Path) -> Option<(String, String)> {
    let text = home.to_str()?;
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let rest = &text[2..];
    if !rest.starts_with('\\') {
        return None;
    }
    let rest = if rest.is_empty() { "\\" } else { rest };
    Some((text[..2].to_string(), rest.to_string()))
}

/// Build the child's environment: `env_clear` PLUS a user-like baseline.
/// Explicit `--env` pairs are layered on top and win on collision
/// (case-insensitively on Windows). `dropped` means `--shell-user`; on Unix
/// the identity and XDG values come from the passwd record for that account,
/// never from the daemon's environment. On Windows a dropped child is refused:
/// without the target token there is no safe way to derive its profile, and
/// copying the daemon's profile is exactly the identity leak this policy
/// forbids.
fn build_env_for(
    daemon: Vec<(String, String)>,
    explicit: &[(String, String)],
    windows: bool,
    user: &ExecUserContext,
    dropped: bool,
) -> Result<Vec<(String, String)>, String> {
    if windows && dropped {
        return Err(format!(
            "exec refused: --shell-user {} needs the target account's token environment; refusing to copy the daemon's Windows profile",
            user.name
        ));
    }

    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in daemon {
        if windows {
            if let Some(canonical) = WINDOWS_PLATFORM_ENV
                .iter()
                .copied()
                .find(|name| name.eq_ignore_ascii_case(&k))
            {
                set_env(&mut out, canonical, &v, true);
            } else if env_name_is_allowed(&k, true) {
                set_env(&mut out, &k, &v, true);
            }
        } else if env_name_is_allowed(&k, false) {
            out.push((k, v));
        }
    }

    if windows {
        // Same account only (the target case returned above). Fill gaps from
        // the resolved daemon account, never synthesize a different profile.
        if !user.name.is_empty() {
            ensure_env(&mut out, "USERNAME", &user.name, true);
        }
        if user.home.is_absolute() {
            ensure_env(&mut out, "USERPROFILE", &user.home.to_string_lossy(), true);
            if let Some((drive, path)) = windows_home_parts(&user.home) {
                ensure_env(&mut out, "HOMEDRIVE", &drive, true);
                ensure_env(&mut out, "HOMEPATH", &path, true);
            }
            ensure_env(
                &mut out,
                "APPDATA",
                &user.home.join("AppData").join("Roaming").to_string_lossy(),
                true,
            );
            ensure_env(
                &mut out,
                "LOCALAPPDATA",
                &user.home.join("AppData").join("Local").to_string_lossy(),
                true,
            );
        }
    } else {
        // Identity always names the account the child actually runs as. For
        // the daemon user this is the same login fact the host resolved for
        // the default cwd; for --shell-user it is the passwd record, not the
        // daemon's HOME/USER/SHELL.
        set_env(&mut out, "HOME", &user.home.to_string_lossy(), false);
        set_env(&mut out, "USER", &user.name, false);
        set_env(&mut out, "LOGNAME", &user.name, false);
        set_env(
            &mut out,
            "SHELL",
            user.shell.as_deref().unwrap_or("/bin/sh"),
            false,
        );
        ensure_env(&mut out, "PATH", UNIX_DEFAULT_PATH, false);

        let home = user.home.as_path();
        if dropped {
            // A target account must not inherit the daemon's private temp or
            // session XDG roots. /tmp is the shared, documented fallback.
            remove_env(&mut out, "TMPDIR", false);
            set_env(&mut out, "TMPDIR", "/tmp", false);
            for (name, suffix) in [
                ("XDG_CONFIG_HOME", ".config"),
                ("XDG_CACHE_HOME", ".cache"),
                ("XDG_DATA_HOME", ".local/share"),
                ("XDG_STATE_HOME", ".local/state"),
            ] {
                remove_env(&mut out, name, false);
                set_env(&mut out, name, &home.join(suffix).to_string_lossy(), false);
            }
            remove_env(&mut out, "XDG_RUNTIME_DIR", false);
            if let Some(uid) = user.uid {
                let runtime = PathBuf::from(format!("/run/user/{uid}"));
                if runtime.is_dir() {
                    set_env(
                        &mut out,
                        "XDG_RUNTIME_DIR",
                        &runtime.to_string_lossy(),
                        false,
                    );
                }
            }
        } else {
            ensure_env(&mut out, "TMPDIR", "/tmp", false);
            for (name, suffix) in [
                ("XDG_CONFIG_HOME", ".config"),
                ("XDG_CACHE_HOME", ".cache"),
                ("XDG_DATA_HOME", ".local/share"),
                ("XDG_STATE_HOME", ".local/state"),
            ] {
                let default = home.join(suffix);
                ensure_env(&mut out, name, &default.to_string_lossy(), false);
            }
        }
    }

    for (k, v) in explicit {
        set_env(&mut out, k, v, windows);
    }
    Ok(out)
}

fn build_env(
    daemon: Vec<(String, String)>,
    explicit: &[(String, String)],
    user: &ExecUserContext,
    dropped: bool,
) -> Result<Vec<(String, String)>, String> {
    build_env_for(daemon, explicit, cfg!(windows), user, dropped)
}

async fn send_frames_chunked(t: &Arc<dyn Transport>, sid: u32, data: &[u8]) -> anyhow::Result<()> {
    let cap = t.max_payload().max(1);
    for chunk in data.chunks(cap) {
        t.send_frame(sid, 0, chunk)
            .await
            .map_err(|_| anyhow::anyhow!("send frame failed"))?;
    }
    Ok(())
}

/// Send `sig` to the session's whole tree (its own process group), or to the
/// leader alone where there are no groups.
fn deliver_signal(child: &mut dyn ExecChild, sig: TreeSignal) {
    let sent = child.signal_group(sig);
    if !sent && sig == TreeSignal::Kill {
        child.start_kill();
    }
}

/// Has the whole tree exited? Reaps the leader as it goes (a zombie leader
/// still counts as a member of its group), then asks about the group.
async fn tree_gone_within(child: &mut dyn ExecChild, within: std::time::Duration) -> bool {
    let end = tokio::time::Instant::now() + within;
    loop {
        let leader_done = matches!(child.try_wait(), Ok(Some(_)));
        if leader_done && !child.group_alive() {
            return true;
        }
        if tokio::time::Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The escalation ladder, starting at `first`: each step signals the whole
/// tree and waits up to [`TREE_GRACE`] for it to go; `Kill` always ends it.
fn ladder(first: TreeSignal) -> &'static [TreeSignal] {
    match first {
        TreeSignal::Kill => &[TreeSignal::Kill],
        TreeSignal::Terminate => &[TreeSignal::Terminate, TreeSignal::Kill],
        TreeSignal::Interrupt => &[
            TreeSignal::Interrupt,
            TreeSignal::Terminate,
            TreeSignal::Kill,
        ],
        TreeSignal::Hangup => &[TreeSignal::Hangup, TreeSignal::Terminate, TreeSignal::Kill],
    }
}

/// End a served exec whose initiator is gone (or whose access was revoked):
/// close the output read ends first, so a writer gets EPIPE/SIGPIPE at once
/// the way it would under a closed local pipe, then walk the signal ladder
/// over the whole process group until nothing of it is left.
async fn end_session_tree(
    child: &mut dyn ExecChild,
    readers: [&tokio::task::JoinHandle<u64>; 2],
    first: TreeSignal,
    first_already_sent: bool,
    why: &str,
    log: &dyn LogSink,
) -> Option<i32> {
    for r in readers {
        r.abort();
    }
    let mut gone = false;
    for (step, &sig) in ladder(first).iter().enumerate() {
        // A signal the initiator forwarded moments ago is not sent twice: the
        // ladder only gives it its grace before the next, harder one. Sending
        // SIGHUP straight after a forwarded SIGINT killed a shell before its
        // INT trap could run.
        if !(step == 0 && first_already_sent) {
            deliver_signal(child, sig);
        }
        let wait = if sig == TreeSignal::Kill {
            std::time::Duration::from_secs(5)
        } else {
            TREE_GRACE
        };
        if tree_gone_within(child, wait).await {
            gone = true;
            break;
        }
    }
    let group = child
        .group_alive()
        .then(|| " (process group is still present)".to_string())
        .unwrap_or_default();
    if gone {
        log.say(&format!(
            "l2: exec ended: {why}; the remote command{group} was stopped"
        ));
    } else {
        log.critical(&format!(
            "l2: exec ended: {why}; the remote command{group} did not exit after SIGKILL"
        ));
    }
    match child.try_wait() {
        Ok(Some(exit)) => exit.wire_code(),
        _ => None,
    }
}

/// Session-scoped authz snapshot for mid-session revoke re-checks: the
/// verified device name (None when unverified, meaning nothing store-bound
/// to re-check), its identity device key for cert-revoke checks, and whether
/// the serving policy auto-allows it (static for the session). Resolved once
/// in [`handle_exec_open`]; the ticker below re-reads the STORE each tick.
#[derive(Clone)]
pub struct ExecSessionAuthz {
    pub dev_name: Option<String>,
    pub idev: Option<[u8; 32]>,
    pub policy_allows: bool,
    /// True when this session was admitted via its enrolment ceiling rather
    /// than an explicit grant: a narrowed ceiling must end it on the next
    /// tick, exactly like a revocation.
    pub admitted_via_ceiling: bool,
    /// Admitted only as the owner's own device: ends when this device stops
    /// accepting owned shells, and is not judged by the per-device grant.
    pub admitted_via_owned_shell: bool,
}

/// Serve one accepted exec open: spawn argv[] directly (NO shell, NO login
/// shell -- that path does not exist here), pump stdout and stderr to their
/// separate stream channels, feed stdin from the registered pipe, and on child
/// exit send the exec-close payload and clean up. One-shot by design: unlike a
/// PTY session there is nothing persistent, so there is nothing to reattach.
#[allow(clippy::too_many_arguments)]
pub async fn serve_exec(
    t: Arc<dyn Transport>,
    mux: Arc<l2::Mux>,
    sid: u32,
    req: ExecOpen,
    stdin_rx: mpsc::Receiver<Option<bytes::Bytes>>,
    exec_ctl: mpsc::Receiver<ExecCtl>,
    authz: ExecSessionAuthz,
    shell_user: Option<String>,
    process: Arc<dyn ExecProcess>,
    host: Arc<dyn HostServices>,
    log: Arc<dyn LogSink>,
) {
    // stderr rides the initiator-allocated `err_sid` from the open frame
    // (same value the initiator registered before sending): allocating a
    // second sid here would name a stream nobody listens on.
    let err_sid = req.err_sid;
    let program = match process.resolve_program(&req.argv[0]) {
        Some(p) => p,
        None => {
            let _ = t
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": "argv[0] not found on daemon PATH" }),
                )
                .await;
            return;
        }
    };
    // tty/pty is a later slice: refuse loudly rather than silently serving
    // pipes to an initiator that is showing a terminal (wrong rendering, and
    // the user would blame the remote command, not the missing pty).
    if req.tty {
        let _ = t
            .send_control(
                &json!({ "type": "l2-close", "sid": sid, "err": "tty not supported in this build" }),
            )
            .await;
        return;
    }
    // --shell-user: the same account drop the PTY gets, or no exec at all.
    // Never the daemon user when an operator configured a lesser one.
    let plan = match exec_spawn_plan(
        process.as_ref(),
        &program,
        &req.argv[1..],
        shell_user.as_deref(),
    ) {
        Ok(p) => p,
        Err(reason) => {
            log.say(&format!("l2: {reason}"));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": reason }))
                .await;
            return;
        }
    };
    let dropped = plan.run_as.is_some();
    let user = match process.user_context(plan.run_as.as_deref()) {
        Ok(user) => user,
        Err(reason) => {
            log.say(&format!("l2: {reason}"));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": reason }))
                .await;
            return;
        }
    };
    let cwd = req.cwd.clone().unwrap_or_else(|| default_exec_cwd(&user));
    if !cwd.is_dir() {
        // Fail closed: a requested directory that does not exist refuses
        // rather than silently running somewhere else.
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "cwd does not exist" }))
            .await;
        return;
    }
    let env = match build_env(process.daemon_environment(), &req.env, &user, dropped) {
        Ok(env) => env,
        Err(reason) => {
            log.say(&format!("l2: {reason}"));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": reason }))
                .await;
            return;
        }
    };
    let spec = ExecSpawnSpec {
        program: plan.program,
        args: plan.args,
        cwd,
        env,
    };
    let mut child = match process.spawn(spec) {
        Ok(child) => child,
        Err(e) => {
            let _ = t
                .send_control(
                    &json!({ "type": "l2-close", "sid": sid, "err": format!("spawn failed: {e}") }),
                )
                .await;
            return;
        }
    };
    let _ = t
        .send_control(&json!({ "type": "exec-open-ack", "sid": sid, "out": sid, "err": err_sid }))
        .await;
    let stdout = match child.take_stdout() {
        Some(s) => s,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stdout pipe" }))
                .await;
            return;
        }
    };
    let stderr = match child.take_stderr() {
        Some(s) => s,
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stderr pipe" }))
                .await;
            return;
        }
    };
    let mut stdin = match child.take_stdin() {
        Some(s) => Some(s),
        None => {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "no stdin pipe" }))
                .await;
            return;
        }
    };
    let mut stdin_rx = stdin_rx;
    // Pump tasks report bytes SENT: the close carries both counts so the
    // initiator can drain stragglers deterministically (a fast-exiting child
    // can beat its own tail frames -- close travels control, bytes travel
    // frames -- and breaking on close would truncate output, observed live
    // as a missing 8 KiB tail with rc=0).
    let t_out = t.clone();
    let out_task = tokio::spawn(pump_output(stdout, t_out, sid));
    let t_err = t.clone();
    let err_task = tokio::spawn(pump_output(stderr, t_err, err_sid));
    // Revoke re-check (pty precedent): a dedicated ticker at the shared
    // interval re-asks the gate while the child runs. A peer revoked
    // mid-session -- certificate OR shell grant -- loses the live exec.
    let mut revoke_ticker = tokio::time::interval(host.revoke_recheck_interval());
    revoke_ticker.tick().await; // consume the immediate first tick
                                // Liveness of the INITIATOR, not only of the link. A client killed with
                                // SIGKILL, or one whose host vanished, sends no close, and its link can
                                // look alive for a long time after (the transport's own idle timeout, or
                                // never, when the link is shared). Observed: `exec beta -- sleep 300`
                                // killed locally left the sleep running for the full five minutes. An
                                // initiator that announces heartbeats (`alive_ms` in its open) is held to
                                // them; any initiator is held to its link.
    let heartbeat_deadline = req.alive_ms.map(alive_deadline);
    let mut last_heard = tokio::time::Instant::now();
    let mut liveness = tokio::time::interval(LIVENESS_TICK);
    liveness.tick().await;
    let mut exec_ctl = exec_ctl;
    let mut exec_ctl_open = true;
    // The last signal the initiator forwarded, so the close that follows it
    // gives that signal its grace instead of sending SIGHUP on top of it.
    let mut forwarded: Option<TreeSignal> = None;
    // stdin: chunks in, EOF shuts the child's write-half (it may still produce
    // output -- EOF is non-terminal, same rule as the pty pumps). Channel
    // death (link gone) kills the child: nobody is left to report to, and an
    // orphaned child outliving its link is a resource leak with a trust tail.
    loop {
        tokio::select! {
            status = child.wait() => {
                let out_bytes = out_task.await.unwrap_or(0);
                let err_bytes = err_task.await.unwrap_or(0);
                let mut close = json!({ "type": "exec-close", "sid": sid, "out_bytes": out_bytes, "err_bytes": err_bytes });
                if let Ok(exit) = status {
                    if let Some(code) = exit.wire_code() {
                        close["status"] = json!(code);
                    }
                }
                if let Err(e) = t.send_control(&close).await {
                    // The close is the only other way the initiator learns the session finished,
                    // so when it cannot be delivered the streams have to END on the wire instead.
                    // An EMPTY payload is the mux's pipe-end sentinel (`on_frame` maps it to
                    // None), which is the same mechanism stdin EOF uses, and the initiator's
                    // closed-pipe arm reads it as a terminal end without an exit status rather
                    // than waiting forever for a frame that will never be actioned.
                    // A close that never arrives leaves the initiator in a select with nothing
                    // left to select: this file already documents that hazard class a few lines
                    // above, for a different early break ("hanging the initiator"). The old
                    // `let _ =` made a LOST close indistinguishable from a delivered one, so the
                    // acceptor believed it had reported the exit while the initiator never heard
                    // it and the only artifact was silence. Say so instead.
                    log.say(&format!(
                        "tunlion: could not deliver exec-close for sid {sid}: {e}; the initiator will not learn the exit status"
                    ));
                }
                // THE END OF THE STREAM IS SIGNALLED UNCONDITIONALLY, and that is the correction
                // this fix carries: the sentinel was inside the error branch, so it fired only
                // when the close send FAILED. The observed run is the case where the send
                // returns Ok and the frame is still not acted on downstream, which left the
                // initiator waiting with nothing to observe -- the `fs.out`/`fs.done` evidence
                // from the gate, and the reason commit 5 did not remove the hang.
                //
                // An EMPTY payload is the mux's pipe-end convention (`on_frame` maps it to
                // None, and `exec_send` already uses it for stdin EOF), so these two frames are
                // how a stream's end reaches its reader whether or not the status frame made
                // it. Sent after the close attempt so the normal path still exits on the STATUS.
                // AND THE SEND'S OUTCOME IS OBSERVED, because the previous attempt discarded it
                // and therefore could not tell whether the end was emitted at all -- the same
                // discarded-error shape this file's close path already carries a fix for. If
                // these fail, the initiator cannot have observed an end, and the next run says so
                // instead of leaving "emitted but unseen" and "never emitted" indistinguishable.
                if let Err(e) = t.send_frame(sid, 0, &[]).await {
                    log.say(&format!(
                        "tunlion: could not signal the end of exec stream sid {sid}: {e}"
                    ));
                }
                if let Err(e) = t.send_frame(err_sid, 0, &[]).await {
                    log.say(&format!(
                        "tunlion: could not signal the end of exec stream sid {err_sid}: {e}"
                    ));
                }
                // THE CONTROL CHANNEL CARRIES THE END TOO, because the data-frame sentinel does
                // not reach the peer -- an empty frame is not forwarded, which is its own claim
                // and filed separately. `l2-close` demonstrably delivers: the peer's `on_close`
                // records the reason and calls `drop_stream`, whose own comment says that
                // dropping the pipe's sender is what closes it, so the consumer's `recv()`
                // returns None and its select bails with a name instead of waiting. Sent AFTER
                // the close attempt and on the SAME ordered control channel, so the normal path
                // still exits on the STATUS and this is only what the wedged path sees.
                for s in [sid, err_sid] {
                    let _ = t.send_control(&json!({
                        "type": "l2-close",
                        "sid": s,
                        "err": "exec session ended without a delivered exit status",
                    }))
                    .await;
                }
                mux.drop_stream(sid).await;
                mux.drop_stream(err_sid).await;
                return;
            }
            chunk = stdin_rx.recv() => {
                // on_frame maps a real empty payload to inner None (stdin
                // EOF) and reserves Some(empty) as a liveness marker, so:
                // inner None shuts the child's write-half but keeps waiting
                // for its output and exit -- EOF is non-terminal, same rule
                // as the pty pumps. Outer None is channel death (link gone):
                // kill the child rather than orphaning it with a trust tail
                // past its link's death.
                match chunk {
                    Some(Some(bytes)) => {
                        if let Some(s) = stdin.as_mut() {
                            if s.write_all(&bytes).await.is_err() {
                                // Write error (child gone or pipe broken): treat
                                // as EOF -- drop the write end and CONTINUE.
                                // break here would skip child.wait() AND the
                                // exec-close, hanging the initiator (yes |
                                // exec -- head -1). Only child.wait() (exit)
                                // or channel death (link gone) ends the loop.
                                stdin.take();
                            }
                        }
                    }
                    Some(None) => {
                        // EOF: CLOSE (drop) the write end. shutdown() is a
                        // socket operation and silently no-ops on a pipe --
                        // observed live: the daemon still held the write fd
                        // open after shutdown(), the child starved forever
                        // in pipe_wait_readable. EOF stays non-terminal: the
                        // loop keeps waiting for output and exit.
                        stdin.take();
                    }
                    None => {
                        // The initiator closed the session (its l2-close: it
                        // was interrupted, its output went away, or it quit),
                        // or the link carrying it was torn down. Nobody is
                        // left to report to: end the whole tree, gently first.
                        // A Ctrl-C the initiator forwarded just before its
                        // close may still be queued: it goes first, so the
                        // command sees the signal its user sent.
                        let (mut first, mut already_sent) = match forwarded {
                            Some(sig) => (sig, true),
                            None => (TreeSignal::Hangup, false),
                        };
                        while let Ok(m) = exec_ctl.try_recv() {
                            if let ExecCtl::Signal(sig) = m {
                                first = sig;
                                already_sent = false;
                            }
                        }
                        let status = end_session_tree(
                            &mut *child,
                            [&out_task, &err_task],
                            first,
                            already_sent,
                            "the initiator closed the session",
                            log.as_ref(),
                        )
                        .await;
                        // An initiator that closed on purpose may still be
                        // listening for a moment: tell it the tree is gone,
                        // with the status it ended on (128+signal).
                        let mut close = json!({ "type": "exec-close", "sid": sid, "ended": "initiator-closed" });
                        if let Some(code) = status {
                            close["status"] = json!(code);
                        }
                        let _ = t.send_control(&close).await;
                        mux.drop_stream(sid).await;
                        mux.drop_stream(err_sid).await;
                        return;
                    }
                }
            }
            ctl = exec_ctl.recv(), if exec_ctl_open => match ctl {
                Some(ExecCtl::Alive) => last_heard = tokio::time::Instant::now(),
                Some(ExecCtl::Signal(sig)) => {
                    // The initiator's user pressed Ctrl-C (or it was asked to
                    // stop): the remote tree gets the same signal, now. Its
                    // l2-close follows and ends whatever ignores it.
                    last_heard = tokio::time::Instant::now();
                    deliver_signal(&mut *child, sig);
                    forwarded = Some(sig);
                }
                // The stream was dropped; the stdin arm sees it too and ends
                // the session, so stop polling a closed channel.
                None => exec_ctl_open = false,
            },
            _ = liveness.tick() => {
                let silent = heartbeat_deadline.is_some_and(|d| last_heard.elapsed() >= d);
                let link_gone = t.is_dead() || !t.is_alive();
                if silent || link_gone {
                    let why = if link_gone {
                        "the link to the initiator died"
                    } else {
                        "the initiator stopped answering"
                    };
                    end_session_tree(
                        &mut *child,
                        [&out_task, &err_task],
                        TreeSignal::Hangup,
                        false,
                        why,
                        log.as_ref(),
                    )
                    .await;
                    mux.drop_stream(sid).await;
                    mux.drop_stream(err_sid).await;
                    return;
                }
            }
            _ = revoke_ticker.tick() => {
                // Re-ask the gate. Cert revoke is re-read from the store
                // each tick; the shell grant is re-read the same way (the
                // policy half is static per session). Either way the peer
                // loses the live exec: kill the child and close with the
                // revoked reason, so the initiator surfaces nonzero with a
                // reason instead of hanging or rendering a clean exit.
                // Revocation and the delegated deadline, from the one live
                // re-check every serving loop shares.
                let cut = host.live_session_cut(authz.idev.as_ref());
                let grant_gone = match authz.dev_name.as_deref() {
                    // An explicit deny always ends it. An owned-device session
                    // was never resting on a per-device grant, so a missing one
                    // is not a withdrawal; its own condition is below.
                    Some(n) => {
                        host.device_capability_denied(n, "shell")
                            || (!authz.admitted_via_owned_shell
                                && !(authz.policy_allows || host.device_allows(n, "shell")))
                    }
                    None => false,
                };
                // This device stopped accepting owned shells (switched off, or
                // a primary withdrew its opt-in): owned-admitted sessions end.
                let owned_gone = authz.admitted_via_owned_shell
                    && (!host.owned_shell_accepted()
                        || !host.ceiling_covers_action(authz.idev.as_ref(), CAP_SHELL));
                // A ceiling narrowed under a ceiling-admitted session ends
                // it (re-read fresh; grant-admitted sessions ignore this).
                let ceiling_gone = authz.admitted_via_ceiling
                    && !host.ceiling_covers_action(authz.idev.as_ref(), CAP_SHELL);
                // A lapsed deadline (cert expiry, absolute stop, offline
                // budget) ends it too; unresolvable identity is no opinion.
                let lapsed = matches!(host.peer_liveness_alive(authz.idev.as_ref()), Some(false));
                if cut.is_some() || grant_gone || ceiling_gone || owned_gone || lapsed {
                    // The close names the cause: an expiry must read as one
                    // (the initiator exits 4 and prints the re-invite), not as
                    // a revocation the owner never made.
                    let reason = match &cut {
                        Some(c) => c.reason.clone(),
                        None => filament_cap::capability::REVOKED_REASON.to_string(),
                    };
                    if matches!(&cut, Some(c) if c.cause == crate::host::LiveCutCause::Expired) {
                        log.critical("exec: peer access expired, closing live session");
                    } else {
                        log.critical("exec: peer access revoked, closing live session");
                    }
                    // Revocation is immediate: the whole tree, no grace.
                    end_session_tree(
                        &mut *child,
                        [&out_task, &err_task],
                        TreeSignal::Kill,
                        false,
                        "peer access revoked",
                        log.as_ref(),
                    )
                    .await;
                    // Test hook (gate proof, compiled out of release builds): close
                    // the link BEFORE the cut message, the order a racing close
                    // produces, so the initiator's handling of that order is gated
                    // deterministically (cli/tests/expiry-race-gates.sh).
                    if process.test_expiry_close_first()
                        && matches!(&cut, Some(c) if c.cause == crate::host::LiveCutCause::Expired)
                    {
                        log.critical("test hook: expiry closes the link before the cut message");
                        t.force_close();
                        mux.drop_stream(sid).await;
                        mux.drop_stream(err_sid).await;
                        return;
                    }
                    let mut close = json!({
                        "type": "l2-close",
                        "sid": sid,
                        "err": reason,
                    });
                    if matches!(&cut, Some(c) if c.cause == crate::host::LiveCutCause::Expired) {
                        // The host carries the invitation end as a typed fact;
                        // parsing the reason is only the compatibility fallback
                        // for an older host that did not fill `expires_at`.
                        let at = cut
                            .as_ref()
                            .and_then(|c| c.expires_at)
                            .or_else(|| expired_at_from_reason(&reason));
                        let r = match at {
                            Some(at) => Refusal::expired(
                                at,
                                authz.dev_name.clone(),
                                authz.idev.as_ref().and_then(|p| host.reinvite_for(p)),
                            ),
                            None => Refusal::new(Code::Expired, authz.dev_name.clone()),
                        };
                        r.annotate(&mut close);
                    }
                    let _ = t.send_control(&close).await;
                    mux.drop_stream(sid).await;
                    mux.drop_stream(err_sid).await;
                    return;
                }
            }
        }
    }
}

async fn pump_output(
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    t: Arc<dyn Transport>,
    sid: u32,
) -> u64 {
    let mut buf = vec![0u8; 8192];
    let mut sent: u64 = 0;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if send_frames_chunked(&t, sid, &buf[..n]).await.is_err() {
                    break;
                }
                sent += n as u64;
            }
        }
    }
    sent
}

/// Handle one `exec-open` frame: admission, then register, ack, serve. Sends
/// its own replies (ack/close/deny) and returns. The admission endpoint owns
/// the serving guard, frame validation and the gate; this function owns the
/// caller's mux, capacity/collision rules and the detached [`serve_exec`].
#[allow(clippy::too_many_arguments)]
pub async fn handle_exec_open(
    conn: &mut Conn,
    pid: &str,
    v: &Value,
    shell_policy: &ShellPolicy,
    shell_user: &Option<String>,
    l2_muxes: &mut HashMap<String, Arc<l2::Mux>>,
    serving: bool,
    parked: &mut Vec<ParkedOpen>,
    process: Arc<dyn ExecProcess>,
) {
    let admission = admit_exec_open(
        conn,
        pid,
        v,
        &ShellAdmissionConfig {
            policy: shell_policy,
            serving,
        },
    )
    .await;
    let (t, sid, device, device_pub, admitted_via_ceiling, admitted_via_owned_shell, req) = match admission {
        ShellAdmission::Admitted {
            transport,
            sid,
            device,
            device_pub,
            admitted_via_ceiling,
            admitted_via_owned_shell,
            plan,
        } => (
            transport,
            sid,
            device,
            device_pub,
            admitted_via_ceiling,
            admitted_via_owned_shell,
            plan,
        ),
        ShellAdmission::Ignored => return,
        ShellAdmission::Denied(d) => {
            let reason = d.reason.clone();
            let host = conn.host.clone();
            // Settle-then-evaluate: the verdict may rest on stale (unproven)
            // identity. Park for re-drive on proof when the deny is
            // attributable to it; otherwise the live verdict stands.
            let known = |p: &[u8; 32]| host.device_key_known(p);
            let revoked = |p: &[u8; 32]| host.cert_revoked_for(Some(p));
            let delegated = |p: &[u8; 32]| {
                host.delegated_access_for(p)
                    .is_some_and(|a| a.expired(filament_id::now_secs()))
            };
            let denied = |n: &str, c: &str| host.device_capability_denied(n, c);
            if park_on_deny(
                &known,
                &revoked,
                &delegated,
                &denied,
                host.gate_settle_ms(),
                parked,
                conn,
                pid,
                ParkKind::Exec,
                &d.transport,
                d.sid,
                v,
                &reason,
            )
            .await
            {
                return;
            }
            conn.log.say(&format!("l2: exec refused: {reason}"));
            // Enqueue under the verified petname (like pty-open's `who`), never
            // the raw pid: the queue is keyed by name, and "<unverified>" is a
            // no-op by design.
            let who = d.device.clone();
            conn.host
                .enqueue_request_if_requestable(who.as_deref().unwrap_or("<unverified>"), "shell");
            let refusal = match d.refusal.code {
                Code::Expired => {
                    let mut r = d.refusal;
                    if r.reinvite.is_none() {
                        r.reinvite = d.device_pub.as_ref().and_then(|p| host.reinvite_for(p));
                    }
                    r
                }
                _ => d.refusal,
            };
            let _ = d.transport.send_control(&refusal.close_frame(d.sid)).await;
            return;
        }
    };
    // The shared mux is created only AFTER admission, so a refused exec no
    // longer leaves an empty per-peer entry behind.
    let mux = l2_muxes
        .entry(pid.to_owned())
        .or_insert_with(|| l2::Mux::new(t.clone(), conn.host.clone()))
        .clone();
    // H-1 (DoS): refuse over the per-link stream cap BEFORE spawning, same as
    // pty-open -- a hostile paired device must not flood exec opens.
    if mux.at_stream_cap().await {
        conn.log
            .say("l2: exec refused: too many streams on this link");
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "too many streams" }))
            .await;
        return;
    }
    // Collision-safe: refuse (don't displace) an already-live sid.
    let Some(stdin_rx) = mux.register_stream(sid).await else {
        conn.log
            .say(&format!("l2: exec refused: sid {sid:#x} in use"));
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "sid in use" }))
            .await;
        return;
    };
    // Heartbeats and forwarded signals from the initiator, for this sid only.
    let exec_ctl = mux.register_exec_ctl(sid).await;
    // Serve DETACHED: awaiting the session inline would park the daemon's
    // single recv loop for its whole lifetime, so no inbound data frame
    // could ever be dispatched while a session runs (stdin starves, the
    // child never exits, every later open hangs behind the parked loop --
    // observed live as hung stdin sessions wedging the acceptor). The pty
    // path spawns its session pumps for exactly this reason; validation,
    // gating and registration above already ran in-hook, so the detached
    // task owns only owned values from here. The revoke ticker needs the
    // same authz context, resolved once here (re-reads the store per tick).
    let dev_name = device;
    let policy_allows = dev_name
        .as_deref()
        .map(|n| shell_policy.auto_allows(n))
        .unwrap_or(false);
    let idev = device_pub;
    let authz = ExecSessionAuthz {
        dev_name,
        idev,
        policy_allows,
        admitted_via_ceiling,
        admitted_via_owned_shell,
    };
    let host = conn.host.clone();
    let log = conn.log.clone();
    tokio::spawn(serve_exec(
        t,
        mux,
        sid,
        req,
        stdin_rx,
        exec_ctl,
        authz,
        shell_user.clone(),
        process,
        host,
        log,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::VecLog;
    use crate::l2::L2_SID_BASE;
    use crate::shell::exec::ExecExit;
    use serde_json::json;
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    const SID: u32 = L2_SID_BASE + 1;
    const ERR_SID: u32 = L2_SID_BASE + 2;

    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    // The Windows acceptance test is a console process too; keep its child
    // from flashing a window when a developer runs the suite interactively.
    #[cfg(windows)]
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn env_value<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
        env.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn env_value_exact<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn env_name_count(env: &[(String, String)], name: &str) -> usize {
        env.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }

    // A transport that records control messages and stream frames in order.
    #[derive(Default)]
    struct FakeTransport {
        controls: Mutex<Vec<Value>>,
        frames: Mutex<Vec<(u32, Vec<u8>)>>,
        dead: std::sync::atomic::AtomicBool,
    }

    impl FakeTransport {
        fn controls(&self) -> Vec<Value> {
            self.controls.lock().unwrap().clone()
        }
        fn frames(&self) -> Vec<(u32, Vec<u8>)> {
            self.frames.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Transport for FakeTransport {
        async fn send_control(&self, msg: &Value) -> anyhow::Result<()> {
            self.controls.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn send_frame(&self, sid: u32, _offset: u64, payload: &[u8]) -> anyhow::Result<()> {
            self.frames.lock().unwrap().push((sid, payload.to_vec()));
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            4
        }
        fn is_alive(&self) -> bool {
            !self.dead.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn is_dead(&self) -> bool {
            self.dead.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct BytesReader {
        bytes: Vec<u8>,
        at: usize,
    }

    impl AsyncRead for BytesReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.at >= self.bytes.len() {
                return Poll::Ready(Ok(()));
            }
            let n = (self.bytes.len() - self.at).min(buf.remaining());
            let start = self.at;
            let end = start + n;
            buf.put_slice(&self.bytes[start..end]);
            self.at = end;
            Poll::Ready(Ok(()))
        }
    }

    /// A deterministic child: scripted streams, one exit, recorded signals.
    struct FakeChild {
        stdin: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
        stdout: Option<Box<dyn AsyncRead + Unpin + Send>>,
        stderr: Option<Box<dyn AsyncRead + Unpin + Send>>,
        exit: ExecExit,
        alive: bool,
        signals: Arc<Mutex<Vec<TreeSignal>>>,
    }

    impl FakeChild {
        fn new(stdout: &[u8], stderr: &[u8], exit: ExecExit) -> Self {
            Self {
                stdin: Some(Box::new(tokio::io::sink())),
                stdout: Some(Box::new(BytesReader {
                    bytes: stdout.to_vec(),
                    at: 0,
                })),
                stderr: Some(Box::new(BytesReader {
                    bytes: stderr.to_vec(),
                    at: 0,
                })),
                exit,
                alive: true,
                signals: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl ExecChild for FakeChild {
        fn take_stdin(&mut self) -> Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>> {
            self.stdin.take()
        }
        fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>> {
            self.stdout.take()
        }
        fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>> {
            self.stderr.take()
        }
        async fn wait(&mut self) -> io::Result<ExecExit> {
            Ok(self.exit)
        }
        fn try_wait(&mut self) -> io::Result<Option<ExecExit>> {
            Ok(Some(self.exit))
        }
        fn start_kill(&mut self) {
            self.alive = false;
        }
        fn signal_group(&self, sig: TreeSignal) -> bool {
            self.signals.lock().unwrap().push(sig);
            true
        }
        fn group_alive(&self) -> bool {
            self.alive
        }
    }

    /// A process primitive with scripted facts and a captured spawn request.
    struct FakeProcess {
        program: Option<PathBuf>,
        daemon_env: Vec<(String, String)>,
        context: ExecUserContext,
        target_context: Result<ExecUserContext, String>,
        user_drop: Result<Vec<String>, String>,
        child: Mutex<Option<FakeChild>>,
        spawned: Mutex<Option<ExecSpawnSpec>>,
    }

    impl FakeProcess {
        fn new(child: FakeChild) -> Self {
            let home = std::env::temp_dir();
            Self {
                program: Some(PathBuf::from("/bin/echo")),
                daemon_env: vec![
                    ("TERM".into(), "xterm".into()),
                    ("LC_ALL".into(), "C".into()),
                    ("SECRET".into(), "nope".into()),
                ],
                context: ExecUserContext {
                    name: "daemon".into(),
                    home: home.clone(),
                    shell: Some("/bin/sh".into()),
                    uid: Some(1000),
                },
                target_context: Ok(ExecUserContext {
                    name: "target".into(),
                    home,
                    shell: Some("/bin/sh".into()),
                    uid: Some(1001),
                }),
                user_drop: Err("no drop here".into()),
                child: Mutex::new(Some(child)),
                spawned: Mutex::new(None),
            }
        }
        fn spawned(&self) -> Option<ExecSpawnSpec> {
            self.spawned.lock().unwrap().clone()
        }
    }

    impl ExecProcess for FakeProcess {
        fn resolve_program(&self, _program: &str) -> Option<PathBuf> {
            self.program.clone()
        }
        fn daemon_environment(&self) -> Vec<(String, String)> {
            self.daemon_env.clone()
        }
        fn user_context(&self, user: Option<&str>) -> Result<ExecUserContext, String> {
            match user {
                None => Ok(self.context.clone()),
                Some(_) => self.target_context.clone(),
            }
        }
        fn user_drop_argv(
            &self,
            _program: &Path,
            _args: &[String],
            _user: &str,
        ) -> Result<Vec<String>, String> {
            self.user_drop.clone()
        }
        fn spawn(&self, spec: ExecSpawnSpec) -> Result<Box<dyn ExecChild>, String> {
            *self.spawned.lock().unwrap() = Some(spec);
            self.child
                .lock()
                .unwrap()
                .take()
                .map(|c| Box::new(c) as Box<dyn ExecChild>)
                .ok_or_else(|| "spawned twice".into())
        }
    }

    fn request() -> ExecOpen {
        ExecOpen {
            argv: vec!["echo".into(), "my dir/with spaces".into(), "*.log".into()],
            cwd: Some(std::env::temp_dir()),
            env: vec![
                ("FOO".into(), "bar".into()),
                ("TERM".into(), "explicit".into()),
            ],
            tty: false,
            err_sid: ERR_SID,
            alive_ms: None,
        }
    }

    fn host() -> Arc<dyn HostServices> {
        Arc::new(crate::host::NoHost)
    }

    async fn serve(
        process: Arc<FakeProcess>,
        t: Arc<FakeTransport>,
        req: ExecOpen,
    ) -> Result<(), tokio::time::error::Elapsed> {
        serve_with_user(process, t, req, None).await
    }

    async fn serve_with_user(
        process: Arc<FakeProcess>,
        t: Arc<FakeTransport>,
        req: ExecOpen,
        shell_user: Option<&str>,
    ) -> Result<(), tokio::time::error::Elapsed> {
        let mux = l2::Mux::new(t.clone(), host());
        let (_stdin_tx, stdin_rx) = mpsc::channel(1);
        let (_ctl_tx, ctl_rx) = mpsc::channel(1);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            serve_exec(
                t,
                mux,
                SID,
                req,
                stdin_rx,
                ctl_rx,
                ExecSessionAuthz {
                    dev_name: Some("phone".into()),
                    idev: None,
                    policy_allows: true,
                    admitted_via_ceiling: false,
                    admitted_via_owned_shell: false,
                },
                shell_user.map(str::to_string),
                process,
                host(),
                Arc::new(VecLog::new()),
            ),
        )
        .await
    }

    #[tokio::test]
    async fn serve_spawns_argv_exactly_and_keeps_streams_separate() {
        let process = Arc::new(FakeProcess::new(FakeChild::new(
            b"hello out",
            b"hello err",
            ExecExit {
                code: Some(7),
                signal: None,
            },
        )));
        let t = Arc::new(FakeTransport::default());
        serve(process.clone(), t.clone(), request())
            .await
            .expect("serve finishes");

        let spec = process.spawned().expect("spawn happened");
        assert_eq!(
            spec.args,
            vec!["my dir/with spaces".to_string(), "*.log".to_string()],
            "argv stays exact; no shell re-parse"
        );
        assert_eq!(spec.cwd, std::env::temp_dir());
        assert_eq!(
            env_value(&spec.env, "TERM"),
            Some("explicit"),
            "explicit wins over the daemon's TERM"
        );
        assert_eq!(env_name_count(&spec.env, "TERM"), 1);
        assert_eq!(env_value(&spec.env, "LC_ALL"), Some("C"));
        assert_eq!(env_value(&spec.env, "FOO"), Some("bar"));
        assert_eq!(
            env_value(&spec.env, "SECRET"),
            None,
            "secrets stay on the daemon side"
        );

        let controls = t.controls();
        assert_eq!(
            controls[0],
            json!({"type": "exec-open-ack", "sid": SID, "out": SID, "err": ERR_SID}),
            "ack first, with both separate stream sids"
        );
        let close = controls
            .iter()
            .find(|c| c["type"] == "exec-close")
            .expect("exit close");
        assert_eq!(close["status"], 7);
        assert_eq!(close["out_bytes"], 9);
        assert_eq!(close["err_bytes"], 9);

        let frames = t.frames();
        let out: Vec<u8> = frames
            .iter()
            .filter(|(sid, _)| *sid == SID)
            .flat_map(|(_, b)| b.clone())
            .collect();
        let err: Vec<u8> = frames
            .iter()
            .filter(|(sid, _)| *sid == ERR_SID)
            .flat_map(|(_, b)| b.clone())
            .collect();
        assert_eq!(out, b"hello out");
        assert_eq!(err, b"hello err");
        assert!(
            frames.iter().all(|(sid, _)| *sid == SID || *sid == ERR_SID),
            "stdout and stderr never share a channel"
        );
    }

    #[test]
    fn windows_baseline_is_forwarded_but_secrets_stay_home() {
        let daemon = vec![
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("windir".into(), r"C:\Windows".into()),
            ("SYSTEMDRIVE".into(), "C:".into()),
            (
                "Path".into(),
                r"C:\Windows\System32;C:\Program Files\nodejs".into(),
            ),
            ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
            ("ComSpec".into(), r"C:\Windows\System32\cmd.exe".into()),
            ("TEMP".into(), r"C:\Users\me\AppData\Local\Temp".into()),
            ("TMP".into(), r"C:\Users\me\AppData\Local\Temp".into()),
            ("USERPROFILE".into(), r"C:\Users\me".into()),
            ("HOMEDRIVE".into(), "C:".into()),
            ("HOMEPATH".into(), r"\Users\me".into()),
            ("APPDATA".into(), r"C:\Users\me\AppData\Roaming".into()),
            ("LOCALAPPDATA".into(), r"C:\Users\me\AppData\Local".into()),
            ("PROGRAMDATA".into(), r"C:\ProgramData".into()),
            ("PROGRAMFILES".into(), r"C:\Program Files".into()),
            ("PROGRAMFILES(X86)".into(), r"C:\Program Files (x86)".into()),
            (
                "PSModulePath".into(),
                r"C:\Users\me\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules"
                    .into(),
            ),
            ("USERNAME".into(), "me".into()),
            ("USERDOMAIN".into(), "CORP".into()),
            ("COMPUTERNAME".into(), "BOX".into()),
            ("PROCESSOR_ARCHITECTURE".into(), "AMD64".into()),
            ("TERM".into(), "xterm".into()),
            ("lc_all".into(), "C".into()),
            ("HTTP_PROXY".into(), "http://proxy.example".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "secret".into()),
            ("NODE_OPTIONS".into(), "--require ./hook.js".into()),
            ("SSH_AUTH_SOCK".into(), r"\\.\pipe\ssh".into()),
            (
                "DBUS_SESSION_BUS_ADDRESS".into(),
                "unix:path=/run/user/1000/bus".into(),
            ),
        ];
        let user = ExecUserContext {
            name: "me".into(),
            home: PathBuf::from(r"C:\Users\me"),
            shell: None,
            uid: None,
        };

        let env = build_env_for(daemon, &[], true, &user, false).expect("windows env");

        assert_eq!(env_value(&env, "SystemRoot"), Some(r"C:\Windows"));
        assert_eq!(env_value(&env, "WINDIR"), Some(r"C:\Windows"));
        assert_eq!(env_value(&env, "SYSTEMDRIVE"), Some("C:"));
        assert_eq!(
            env_value(&env, "PATH"),
            Some(r"C:\Windows\System32;C:\Program Files\nodejs")
        );
        assert_eq!(env_value(&env, "PATHEXT"), Some(".COM;.EXE;.BAT;.CMD"));
        assert_eq!(
            env_value(&env, "COMSPEC"),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            env_value(&env, "TEMP"),
            Some(r"C:\Users\me\AppData\Local\Temp")
        );
        assert_eq!(
            env_value(&env, "TMP"),
            Some(r"C:\Users\me\AppData\Local\Temp")
        );
        assert_eq!(env_value(&env, "USERPROFILE"), Some(r"C:\Users\me"));
        assert_eq!(env_value(&env, "HOMEDRIVE"), Some("C:"));
        assert_eq!(env_value(&env, "HOMEPATH"), Some(r"\Users\me"));
        assert_eq!(
            env_value(&env, "APPDATA"),
            Some(r"C:\Users\me\AppData\Roaming")
        );
        assert_eq!(
            env_value(&env, "LOCALAPPDATA"),
            Some(r"C:\Users\me\AppData\Local")
        );
        assert_eq!(env_value(&env, "PROGRAMDATA"), Some(r"C:\ProgramData"));
        assert_eq!(env_value(&env, "PROGRAMFILES"), Some(r"C:\Program Files"));
        assert_eq!(
            env_value(&env, "PROGRAMFILES(X86)"),
            Some(r"C:\Program Files (x86)")
        );
        assert_eq!(
            env_value(&env, "PSMODULEPATH"),
            Some(r"C:\Users\me\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules")
        );
        assert_eq!(env_value(&env, "USERNAME"), Some("me"));
        assert_eq!(env_value(&env, "USERDOMAIN"), Some("CORP"));
        assert_eq!(env_value(&env, "COMPUTERNAME"), Some("BOX"));
        assert_eq!(env_value(&env, "PROCESSOR_ARCHITECTURE"), Some("AMD64"));
        assert_eq!(env_value(&env, "TERM"), Some("xterm"));
        assert_eq!(env_value(&env, "LC_ALL"), Some("C"));
        assert_eq!(env_name_count(&env, "PATH"), 1, "no case-duplicate PATH");
        assert_eq!(env_name_count(&env, "SystemRoot"), 1);

        for secret in [
            "HTTP_PROXY",
            "AWS_SECRET_ACCESS_KEY",
            "NODE_OPTIONS",
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
        ] {
            assert_eq!(
                env_value(&env, secret),
                None,
                "{secret} must not cross to the child"
            );
        }
    }

    #[test]
    fn windows_explicit_env_overrides_baseline_case_insensitively() {
        let daemon = vec![
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("Path".into(), r"C:\daemon\bin".into()),
            ("TERM".into(), "xterm".into()),
        ];
        let explicit = vec![
            ("systemroot".into(), r"D:\Win".into()),
            ("PATH".into(), r"C:\explicit\bin".into()),
            ("term".into(), "screen".into()),
            ("FOO".into(), "bar".into()),
        ];
        let user = ExecUserContext {
            name: "me".into(),
            home: PathBuf::from(r"C:\Users\me"),
            shell: None,
            uid: None,
        };

        let env = build_env_for(daemon, &explicit, true, &user, false).expect("windows env");

        assert_eq!(env_value(&env, "SystemRoot"), Some(r"D:\Win"));
        assert_eq!(env_name_count(&env, "SystemRoot"), 1);
        assert_eq!(env_value(&env, "PATH"), Some(r"C:\explicit\bin"));
        assert_eq!(env_name_count(&env, "PATH"), 1);
        assert_eq!(env_value(&env, "TERM"), Some("screen"));
        assert_eq!(env_name_count(&env, "TERM"), 1);
        assert_eq!(env_value(&env, "FOO"), Some("bar"));
    }

    #[test]
    fn windows_target_user_env_is_refused_not_copied_from_the_daemon() {
        let target = ExecUserContext {
            name: "guest".into(),
            home: PathBuf::from(r"D:\Users\guest"),
            shell: None,
            uid: None,
        };
        let err = build_env_for(
            vec![
                ("USERPROFILE".into(), r"C:\Users\owner".into()),
                ("APPDATA".into(), r"C:\Users\owner\AppData\Roaming".into()),
            ],
            &[],
            true,
            &target,
            true,
        )
        .expect_err("a Windows target account needs its own token environment");
        assert!(err.contains("--shell-user guest"), "{err}");
        assert!(err.contains("token environment"), "{err}");
    }

    #[test]
    fn unix_target_user_env_uses_passwd_identity_not_the_daemon_profile() {
        let daemon = vec![
            ("HOME".into(), "/home/daemon".into()),
            ("USER".into(), "daemon".into()),
            ("LOGNAME".into(), "daemon".into()),
            ("SHELL".into(), "/bin/daemon-shell".into()),
            ("PATH".into(), "/daemon/bin:/usr/bin".into()),
            ("TMPDIR".into(), "/home/daemon/tmp".into()),
            ("XDG_CONFIG_HOME".into(), "/home/daemon/.config".into()),
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
            ("TERM".into(), "xterm".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("SSH_AUTH_SOCK".into(), "/tmp/daemon-agent.sock".into()),
            ("NODE_OPTIONS".into(), "--require ./hook.js".into()),
            ("HTTP_PROXY".into(), "http://proxy.example".into()),
            (
                "DBUS_SESSION_BUS_ADDRESS".into(),
                "unix:path=/run/user/1000/bus".into(),
            ),
            ("AWS_SECRET_ACCESS_KEY".into(), "secret".into()),
        ];
        let target = ExecUserContext {
            name: "guest".into(),
            home: PathBuf::from("/home/guest"),
            shell: Some("/bin/zsh".into()),
            uid: Some(1001),
        };

        let env = build_env_for(daemon, &[], false, &target, true).expect("unix env");

        assert_eq!(env_value(&env, "HOME"), Some("/home/guest"));
        assert_eq!(env_value(&env, "USER"), Some("guest"));
        assert_eq!(env_value(&env, "LOGNAME"), Some("guest"));
        assert_eq!(env_value(&env, "SHELL"), Some("/bin/zsh"));
        assert_eq!(env_value(&env, "PATH"), Some("/daemon/bin:/usr/bin"));
        assert_eq!(env_value(&env, "TERM"), Some("xterm"));
        assert_eq!(env_value(&env, "LANG"), Some("en_US.UTF-8"));
        assert_eq!(env_value(&env, "TMPDIR"), Some("/tmp"));
        let target_home = PathBuf::from("/home/guest");
        for (name, suffix) in [
            ("XDG_CONFIG_HOME", ".config"),
            ("XDG_CACHE_HOME", ".cache"),
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
        ] {
            let expected = target_home.join(suffix);
            assert_eq!(
                env_value(&env, name),
                Some(expected.to_string_lossy().as_ref()),
                "{name} follows the target home"
            );
        }
        assert_ne!(
            env_value(&env, "XDG_RUNTIME_DIR"),
            Some("/run/user/1000"),
            "the daemon session's runtime dir must not follow the target account"
        );

        for secret in [
            "SSH_AUTH_SOCK",
            "NODE_OPTIONS",
            "HTTP_PROXY",
            "DBUS_SESSION_BUS_ADDRESS",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert_eq!(
                env_value(&env, secret),
                None,
                "{secret} must not cross to the child"
            );
        }
    }

    #[test]
    fn unix_env_stays_case_sensitive_and_has_no_windows_baseline() {
        let daemon = vec![
            ("TERM".into(), "xterm".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("Path".into(), r"C:\daemon\bin".into()),
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("SSH_AUTH_SOCK".into(), "/tmp/agent".into()),
        ];
        let explicit = vec![
            ("term".into(), "screen".into()),
            ("Path".into(), r"C:\explicit\bin".into()),
            ("HOME".into(), "/explicit/home".into()),
        ];
        let user = ExecUserContext {
            name: "me".into(),
            home: PathBuf::from("/home/me"),
            shell: Some("/bin/bash".into()),
            uid: Some(1000),
        };

        let env = build_env_for(daemon, &explicit, false, &user, false).expect("unix env");

        assert_eq!(env_value(&env, "TERM"), Some("xterm"));
        assert_eq!(
            env_value_exact(&env, "term"),
            Some("screen"),
            "Unix names stay case-sensitive, so lower-case term is its own key"
        );
        assert_eq!(env_value_exact(&env, "Path"), Some(r"C:\explicit\bin"));
        assert_eq!(env_value(&env, "HOME"), Some("/explicit/home"));
        assert_eq!(env_value(&env, "USER"), Some("me"));
        assert_eq!(env_value(&env, "SHELL"), Some("/bin/bash"));
        assert_eq!(env_value(&env, "SystemRoot"), None);
        assert_eq!(env_value(&env, "SSH_AUTH_SOCK"), None);
    }

    #[cfg(unix)]
    #[test]
    fn unix_child_sees_resolved_home_user_shell_and_cwd() {
        let home = std::env::temp_dir().join(format!(
            "tunlion-exec-child-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&home).expect("create test home");
        let user = ExecUserContext {
            name: "tunlion-exec-user".into(),
            home: home.clone(),
            shell: Some("/bin/sh".into()),
            uid: Some(4242),
        };
        let env = build_env_for(Vec::new(), &[], false, &user, true).expect("unix env");

        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"printf '%s|%s|%s|%s|%s' "$HOME" "$USER" "$LOGNAME" "$SHELL" "$PWD""#)
            .current_dir(&home)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .output()
            .expect("spawn /bin/sh");
        let _ = std::fs::remove_dir_all(&home);

        assert!(
            output.status.success(),
            "sh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!(
                "{}|tunlion-exec-user|tunlion-exec-user|/bin/sh|{}",
                home.display(),
                home.display()
            )
        );
    }

    #[cfg(windows)]
    fn program_on_path(env: &[(String, String)], name: &str) -> Option<std::path::PathBuf> {
        let path = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))?
            .1
            .as_str();
        std::env::split_paths(path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    }

    /// Decode a Windows console child's bytes: `wsl.exe` writes UTF-16LE,
    /// ordinary tools write UTF-8.
    #[cfg(windows)]
    fn windows_text(bytes: &[u8]) -> String {
        let nul = bytes.iter().filter(|b| **b == 0).count();
        if bytes.len() >= 2 && nul * 4 > bytes.len() {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    #[cfg(windows)]
    fn windows_current_user() -> ExecUserContext {
        ExecUserContext {
            name: std::env::var("USERNAME").unwrap_or_default(),
            home: std::env::var("USERPROFILE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| std::env::temp_dir()),
            shell: None,
            uid: None,
        }
    }

    #[cfg(windows)]
    fn windows_filtered_env() -> Vec<(String, String)> {
        let daemon: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        build_env_for(daemon, &[], true, &windows_current_user(), false).expect("windows env")
    }

    /// Acceptance on a real Windows child: the filtered environment must let
    /// Node's CSPRNG work and let Node resolve `node` again through PATH.
    #[cfg(windows)]
    #[test]
    fn windows_child_prng_and_nested_node_run_with_the_filtered_env() {
        let env = windows_filtered_env();
        assert!(
            env_value(&env, "SystemRoot").is_some(),
            "the daemon's own SystemRoot is the source of the baseline"
        );
        assert!(env_value(&env, "PATH").is_some());

        let Some(node) = program_on_path(&env, "node.exe") else {
            if std::env::var_os("CI").is_some() {
                panic!("node.exe is not on the daemon PATH; Windows Node acceptance cannot run");
            }
            eprintln!("skipping Windows Node acceptance: node.exe is not on PATH");
            return;
        };

        let mut command = std::process::Command::new(&node);
        command
            .args(["-e", NODE_ACCEPTANCE])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .creation_flags(CREATE_NO_WINDOW);
        let output = command
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", node.display()));
        assert!(
            output.status.success(),
            "node with the filtered env failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
    }

    /// Values are not shell-expanded or normalized on the way to the child:
    /// an empty value stays present, `%VAR%` stays literal, CRLF survives, and
    /// non-ASCII Windows UTF-16 text survives the wide-character environment.
    #[cfg(windows)]
    #[test]
    fn windows_child_env_preserves_literal_values() {
        let daemon: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let explicit = vec![
            ("TUNLION_TEST_EMPTY".into(), String::new()),
            ("TUNLION_TEST_PERCENT".into(), r"%SystemRoot%;%PATH%".into()),
            ("TUNLION_TEST_CRLF".into(), "line1\r\nline2".into()),
            ("TUNLION_TEST_UNICODE".into(), "Grüße-世界-🚀".into()),
        ];
        let env = build_env_for(daemon, &explicit, true, &windows_current_user(), false)
            .expect("windows env");
        assert_eq!(env_value_exact(&env, "TUNLION_TEST_EMPTY"), Some(""));
        assert_eq!(
            env_value_exact(&env, "TUNLION_TEST_PERCENT"),
            Some(r"%SystemRoot%;%PATH%")
        );
        assert_eq!(
            env_value_exact(&env, "TUNLION_TEST_CRLF"),
            Some("line1\r\nline2")
        );

        let Some(node) = program_on_path(&env, "node.exe") else {
            panic!("node.exe is not on the daemon PATH; literal-value acceptance cannot run");
        };
        let mut command = std::process::Command::new(&node);
        command
            .args(["-e", LITERAL_ENV_ACCEPTANCE])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .creation_flags(CREATE_NO_WINDOW);
        let output = command
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", node.display()));
        assert!(
            output.status.success(),
            "node literal-value probe failed ({}): stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let got: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("node emitted JSON");
        assert_eq!(got["empty"], "");
        assert_eq!(got["percent"], r"%SystemRoot%;%PATH%");
        assert_eq!(got["crlf"], "line1\r\nline2");
        assert_eq!(got["unicode"], "Grüße-世界-🚀");
    }

    /// A WSL-style launch: `wsl.exe` is a Windows child that needs the same
    /// baseline. `--help` does not require an installed distribution, so this
    /// proves the executable starts without turning a missing distro into a
    /// skip.
    #[cfg(windows)]
    #[test]
    fn windows_wsl_executable_starts_with_the_filtered_env() {
        let env = windows_filtered_env();
        let system_root =
            env_value(&env, "SystemRoot").expect("SystemRoot is in the filtered baseline");
        let wsl = std::path::Path::new(system_root)
            .join("System32")
            .join("wsl.exe");
        assert!(
            wsl.is_file(),
            "{} is missing from the Windows image",
            wsl.display()
        );

        let mut command = std::process::Command::new(&wsl);
        command
            .arg("--help")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .creation_flags(CREATE_NO_WINDOW);
        let output = command
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", wsl.display()));
        // Hosted Windows images have WSL installed but no distribution, so
        // `wsl.exe --help` prints its usage and exits with 0xffffffff. The
        // launch itself is the assertion here; no distro execution is claimed.
        let text = windows_text(&output.stdout);
        assert!(
            text.contains("Usage:") || text.contains("wsl.exe"),
            "wsl.exe did not print its usage ({}): stdout={:?} stderr={:?}",
            output.status,
            text,
            windows_text(&output.stderr)
        );
    }

    #[cfg(windows)]
    const LITERAL_ENV_ACCEPTANCE: &str = r#"
process.stdout.write(JSON.stringify({
  empty: process.env.TUNLION_TEST_EMPTY,
  percent: process.env.TUNLION_TEST_PERCENT,
  crlf: process.env.TUNLION_TEST_CRLF,
  unicode: process.env.TUNLION_TEST_UNICODE
}));
"#;

    #[cfg(windows)]
    const NODE_ACCEPTANCE: &str = r#"
const crypto = require('crypto');
const missing = ['SystemRoot', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'TEMP', 'TMP', 'USERPROFILE', 'USERNAME']
  .filter((name) => !process.env[name]);
if (missing.length) {
  console.error('missing baseline: ' + missing.join(','));
  process.exit(2);
}
crypto.randomBytes(32);
crypto.getRandomValues(new Uint8Array(16));
const { execFileSync } = require('child_process');
const cmdRoot = execFileSync(process.env.COMSPEC, ['/C', 'echo %SystemRoot%'], { encoding: 'utf8' }).trim();
if (cmdRoot.toLowerCase() !== process.env.SystemRoot.toLowerCase()) {
  console.error('cmd.exe saw SystemRoot=' + JSON.stringify(cmdRoot));
  process.exit(3);
}
const nested = execFileSync('node', ['-e', 'process.stdout.write("nested-ok")'], { encoding: 'utf8' });
if (nested !== 'nested-ok') {
  console.error('nested node output: ' + JSON.stringify(nested));
  process.exit(4);
}
process.stdout.write('ok\n');
"#;

    #[tokio::test]
    async fn serve_refuses_tty_and_missing_program_before_spawning() {
        let process = Arc::new(FakeProcess::new(FakeChild::new(
            b"",
            b"",
            ExecExit {
                code: Some(0),
                signal: None,
            },
        )));
        let mut req = request();
        req.tty = true;
        let t = Arc::new(FakeTransport::default());
        serve(process.clone(), t.clone(), req)
            .await
            .expect("serve finishes");
        assert!(process.spawned().is_none());
        assert_eq!(
            t.controls(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": "tty not supported in this build",
            })]
        );

        let process = Arc::new(FakeProcess {
            program: None,
            ..FakeProcess::new(FakeChild::new(
                b"",
                b"",
                ExecExit {
                    code: Some(0),
                    signal: None,
                },
            ))
        });
        let t = Arc::new(FakeTransport::default());
        serve(process.clone(), t.clone(), request())
            .await
            .expect("serve finishes");
        assert!(process.spawned().is_none());
        assert_eq!(
            t.controls(),
            vec![json!({
                "type": "l2-close",
                "sid": SID,
                "err": "argv[0] not found on daemon PATH",
            })]
        );
    }

    #[tokio::test]
    async fn missing_cwd_refuses_before_spawning() {
        let process = Arc::new(FakeProcess::new(FakeChild::new(
            b"",
            b"",
            ExecExit {
                code: Some(0),
                signal: None,
            },
        )));
        let mut req = request();
        req.cwd = Some(PathBuf::from("/definitely/not/here/xyz"));
        let t = Arc::new(FakeTransport::default());
        serve(process.clone(), t.clone(), req)
            .await
            .expect("serve finishes");
        assert!(process.spawned().is_none());
        assert_eq!(t.controls()[0]["err"], "cwd does not exist");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_user_env_and_cwd_come_from_the_target_not_the_daemon() {
        let mut process = FakeProcess::new(FakeChild::new(
            b"",
            b"",
            ExecExit {
                code: Some(0),
                signal: None,
            },
        ));
        process.daemon_env = vec![
            ("HOME".into(), "/home/daemon".into()),
            ("USER".into(), "daemon".into()),
            ("LOGNAME".into(), "daemon".into()),
            ("SHELL".into(), "/bin/daemon-shell".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("SECRET".into(), "nope".into()),
        ];
        process.user_drop = Ok(vec![
            "/usr/sbin/runuser".into(),
            "-p".into(),
            "-u".into(),
            "guest".into(),
            "--".into(),
        ]);
        process.program = Some(PathBuf::from("/usr/sbin/runuser"));
        let target_home = std::env::temp_dir();
        process.target_context = Ok(ExecUserContext {
            name: "guest".into(),
            home: target_home.clone(),
            shell: Some("/bin/zsh".into()),
            uid: Some(1001),
        });
        let mut req = request();
        req.cwd = None;
        let process = Arc::new(process);

        let t = Arc::new(FakeTransport::default());
        serve_with_user(process.clone(), t.clone(), req, Some("guest"))
            .await
            .expect("serve finishes");

        let spec = process.spawned().expect("spawn happened");
        assert_eq!(spec.cwd, target_home, "default cwd is the target home");
        assert_eq!(env_value(&spec.env, "HOME"), target_home.to_str());
        assert_eq!(env_value(&spec.env, "USER"), Some("guest"));
        assert_eq!(env_value(&spec.env, "LOGNAME"), Some("guest"));
        assert_eq!(env_value(&spec.env, "SHELL"), Some("/bin/zsh"));
        assert_ne!(env_value(&spec.env, "HOME"), Some("/home/daemon"));
        assert_ne!(env_value(&spec.env, "SHELL"), Some("/bin/daemon-shell"));
        assert_eq!(env_value(&spec.env, "SECRET"), None);
    }

    #[tokio::test]
    async fn unresolved_shell_user_refuses_before_spawn() {
        let mut process = FakeProcess::new(FakeChild::new(
            b"",
            b"",
            ExecExit {
                code: Some(0),
                signal: None,
            },
        ));
        process.user_drop = Ok(vec![
            "/usr/sbin/runuser".into(),
            "-p".into(),
            "-u".into(),
            "ghost".into(),
            "--".into(),
        ]);
        process.program = Some(PathBuf::from("/usr/sbin/runuser"));
        process.target_context =
            Err("exec refused: --shell-user ghost is not a resolvable local account".into());
        let process = Arc::new(process);
        let t = Arc::new(FakeTransport::default());
        serve_with_user(process.clone(), t.clone(), request(), Some("ghost"))
            .await
            .expect("serve finishes");

        assert!(
            process.spawned().is_none(),
            "an unknown account must not run"
        );
        assert_eq!(
            t.controls()[0]["err"],
            "exec refused: --shell-user ghost is not a resolvable local account"
        );
    }

    #[test]
    fn user_drop_is_all_or_refused_never_silently_dropped() {
        let mut process = FakeProcess::new(FakeChild::new(
            b"",
            b"",
            ExecExit {
                code: Some(0),
                signal: None,
            },
        ));
        let direct = exec_spawn_plan(
            &process,
            std::path::Path::new("/usr/bin/id"),
            &["-un".into()],
            None,
        )
        .expect("no user: direct");
        assert_eq!(direct.program, PathBuf::from("/usr/bin/id"));
        assert_eq!(direct.args, vec!["-un".to_string()]);
        assert_eq!(direct.run_as, None);

        // The drop's wrapper resolves through the same daemon PATH.
        process.user_drop = Ok(vec![
            "/usr/sbin/runuser".into(),
            "-l".into(),
            "nobody".into(),
            "-c".into(),
        ]);
        process.program = Some(PathBuf::from("/usr/sbin/runuser"));
        let dropped = exec_spawn_plan(
            &process,
            std::path::Path::new("/usr/bin/id"),
            &["-un".into()],
            Some("nobody"),
        )
        .expect("drop resolves");
        assert_eq!(dropped.program, PathBuf::from("/usr/sbin/runuser"));
        assert_eq!(dropped.run_as.as_deref(), Some("nobody"));
        assert_eq!(dropped.args, vec!["-l", "nobody", "-c"]);

        // An unresolvable drop refuses with the setting named, rather than
        // running as the daemon user.
        process.program = None;
        let err = exec_spawn_plan(
            &process,
            std::path::Path::new("/usr/bin/id"),
            &["-un".into()],
            Some("nobody"),
        )
        .expect_err("must refuse");
        assert!(err.contains("--shell-user nobody"), "{err}");

        // A platform without a drop says so and is refused.
        process.program = Some(PathBuf::from("/usr/sbin/runuser"));
        process.user_drop = Err("no account drop on this platform".into());
        assert_eq!(
            exec_spawn_plan(
                &process,
                std::path::Path::new("/usr/bin/id"),
                &["-un".into()],
                Some("nobody"),
            )
            .expect_err("must refuse"),
            "no account drop on this platform"
        );
    }

    #[test]
    fn default_cwd_uses_the_account_home_and_a_documented_root_fallback() {
        let home = std::env::temp_dir();
        let user = ExecUserContext {
            name: "somebody".into(),
            home: home.clone(),
            shell: Some("/bin/sh".into()),
            uid: Some(1000),
        };
        assert_eq!(default_exec_cwd(&user), home);

        let missing = ExecUserContext {
            name: "nobody".into(),
            home: PathBuf::from("/definitely/not/here/xyz"),
            shell: None,
            uid: None,
        };
        assert_eq!(
            default_exec_cwd(&missing),
            PathBuf::from("/"),
            "a passwd home that is not a directory falls back to / explicitly"
        );
    }

    #[test]
    fn every_ladder_ends_in_kill() {
        for first in [
            TreeSignal::Hangup,
            TreeSignal::Interrupt,
            TreeSignal::Terminate,
            TreeSignal::Kill,
        ] {
            let steps = ladder(first);
            assert_eq!(steps.first(), Some(&first), "{first:?}");
            assert_eq!(steps.last(), Some(&TreeSignal::Kill), "{first:?}");
        }
    }
}
