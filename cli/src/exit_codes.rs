//! The exit-code taxonomy, and the one place a failed command is reported.
//!
//! Before this every failure was exit 1, so a script could not tell "no such
//! device" from "the peer is offline" from "no internet" without parsing prose.
//! The codes below are documented in `tunlion --help` (EXIT CODES) and in
//! docs/ui/OUTPUT.md. They were chosen around the codes that already existed
//! and that gates assert, so none of those changed meaning:
//!
//!   3  unknown device      `sync`, `devices --caps` (sync-gates.sh gate F)
//!   4  denied              `sync` (sync-gates.sh gates D1/D2/I)
//!   5  still on a relay    `reach --until-direct` (its --help says so)
//!  10  daemon conflict     `up` over a running daemon with other settings
//!                          ([`DAEMON_CONFLICT`], shell-gates.sh gates F/F3)
//!
//! `1` stays the catch-all, so the change is additive: a script that only tests
//! `!= 0` is unaffected.
//!
//! Most failures arrive here as an ordinary `anyhow::Error` from a `bail!`. A
//! call site that knows its kind says so with [`err`]; everything else is
//! classified from its text by [`classify_text`], which is deliberately
//! conservative: anything it does not recognise is `1`.

use crate::ui;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// `up` found a daemon already running with settings other than the ones it
/// was given: nothing was applied, and the message names the restart. Not an
/// [`ExitKind`]: it is never a failure of the command's own work, and `up`
/// exits with it directly. #392 introduced this case (it used 3, which is
/// "unknown device" here) and carries the literal 10 with a pointer to this
/// constant, because it predates this file; once both are on main, `up` uses
/// this constant instead of the literal.
#[allow(dead_code)] // `up` (#392) is the user once both have merged
pub(crate) const DAEMON_CONFLICT: i32 = 10;

/// `status`: no daemon serves this config dir. Not an [`ExitKind`] either:
/// `status` did its job (it looked), so this is its answer, not its failure.
/// It exited 0 here, so a script had to parse "not running" out of prose.
/// A daemon that runs but does not answer in time is `status`'s 6
/// ([`ExitKind::Unreachable`]: "did not answer in time"). `--json` keeps exit
/// 0 and reports both in its `running`/`responding` fields.
pub(crate) const STATUS_NOT_RUNNING: i32 = 11;

/// What kind of failure a command ended in. `code()` is the process exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExitKind {
    /// Anything not classified below.
    Other,
    /// Bad arguments, a missing value, flags that cannot go together, or a
    /// missing local prerequisite the user has to set up first (`mount`
    /// without FUSE): input or environment, never the peer.
    Usage,
    /// No such device, or it is not paired with this one.
    UnknownDevice,
    /// The peer, a capability, a ceiling or the local system refused it.
    Denied,
    /// `reach --until-direct`: the link is up but still on a relay at the timeout.
    StillRelayed,
    /// The peer is offline, unreachable, or did not answer in time.
    Unreachable,
    /// The tunlion server cannot be reached (no internet, DNS, captive portal).
    Network,
    /// Some of the work landed and some did not.
    Partial,
    /// This device has no identity yet (`tunlion init` or `tunlion join`).
    NoIdentity,
    /// A resource on THIS machine ran out: its disk (or quota) is full, it
    /// has no file descriptors or memory left. Distinct from 2 (the input was
    /// wrong) and from 4 (a receiver's full disk is the peer refusing, with
    /// reason `no_space`): the fix is on this machine, and retrying after
    /// freeing space works with the same command line.
    LocalResource,
}

impl ExitKind {
    #[cfg(test)]
    pub(crate) const ALL: [ExitKind; 10] = [
        ExitKind::Other,
        ExitKind::Usage,
        ExitKind::UnknownDevice,
        ExitKind::Denied,
        ExitKind::StillRelayed,
        ExitKind::Unreachable,
        ExitKind::Network,
        ExitKind::Partial,
        ExitKind::NoIdentity,
        ExitKind::LocalResource,
    ];

    pub(crate) fn code(self) -> i32 {
        match self {
            ExitKind::Other => 1,
            ExitKind::Usage => 2,
            ExitKind::UnknownDevice => 3,
            ExitKind::Denied => 4,
            ExitKind::StillRelayed => 5,
            ExitKind::Unreachable => 6,
            ExitKind::Network => 7,
            ExitKind::Partial => 8,
            ExitKind::NoIdentity => 9,
            ExitKind::LocalResource => 12,
        }
    }

    /// The stable token a script matches in a `--json` error (`error.code`).
    pub(crate) fn token(self) -> &'static str {
        match self {
            ExitKind::Other => "error",
            ExitKind::Usage => "usage",
            ExitKind::UnknownDevice => "unknown_device",
            ExitKind::Denied => "denied",
            ExitKind::StillRelayed => "still_relayed",
            ExitKind::Unreachable => "unreachable",
            ExitKind::Network => "network",
            ExitKind::Partial => "partial",
            ExitKind::NoIdentity => "no_identity",
            ExitKind::LocalResource => "local_resource",
        }
    }
}

/// An error that already knows its exit kind. Its text is the message.
#[derive(Debug)]
pub(crate) struct Classified {
    pub(crate) kind: ExitKind,
    pub(crate) msg: String,
}

impl std::fmt::Display for Classified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}
impl std::error::Error for Classified {}

/// The failure was already reported in full (a `--json` envelope, or a block
/// the command printed itself). `main` exits with its code and prints nothing.
///
/// The second field is the one-sentence reason, when the command has one. A
/// printed block is for a person; a `--json` result built afterwards still
/// needs the reason as text, and "failed (denied)" was all it got for a
/// receiver out of disk space whose human block named both sizes.
#[derive(Debug)]
pub(crate) struct Reported(pub(crate) ExitKind, pub(crate) Option<String>);

impl std::fmt::Display for Reported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.1 {
            Some(m) => f.write_str(m),
            None => write!(f, "failed ({})", self.0.token()),
        }
    }
}
impl std::error::Error for Reported {}

/// A state file (devices.json, caps.json, ...) that exists and does not
/// parse, or is empty. Exit 2 like any local file problem; in `--json` its
/// `error.code` is `corrupt_state`, so a script can tell "fix this file"
/// from a bad flag.
#[derive(Debug)]
pub(crate) struct CorruptState(pub(crate) String);

impl std::fmt::Display for CorruptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CorruptState {}

/// The JSON token for a corrupt state file (exit 2).
pub(crate) const CORRUPT_STATE: &str = "corrupt_state";

/// The `error.code` a `--json` reader gets for `e`: its kind's token, or
/// `corrupt_state` for a corrupt state file.
pub(crate) fn json_code(e: &anyhow::Error) -> &'static str {
    if e.chain().any(|c| c.downcast_ref::<CorruptState>().is_some()) {
        CORRUPT_STATE
    } else {
        classify(e).token()
    }
}

/// An error of a known kind.
pub(crate) fn err(kind: ExitKind, msg: impl Into<String>) -> anyhow::Error {
    Classified { kind, msg: msg.into() }.into()
}

/// "Already said; exit with this kind." See [`Reported`].
pub(crate) fn reported(kind: ExitKind) -> anyhow::Error {
    Reported(kind, None).into()
}

/// "Already said; exit with this kind", carrying the sentence that was said,
/// so a `--json` result built from this error has the reason and not only
/// its code.
pub(crate) fn reported_because(kind: ExitKind, why: impl Into<String>) -> anyhow::Error {
    Reported(kind, Some(why.into())).into()
}

/// The kind of an error: an explicit classification anywhere in the chain
/// wins, otherwise the text decides.
pub(crate) fn classify(e: &anyhow::Error) -> ExitKind {
    for cause in e.chain() {
        if let Some(c) = cause.downcast_ref::<Classified>() {
            return c.kind;
        }
        if let Some(r) = cause.downcast_ref::<Reported>() {
            return r.0;
        }
        if cause.downcast_ref::<CorruptState>().is_some() {
            return ExitKind::Usage;
        }
    }
    classify_text(&format!("{e:#}"))
}

/// The text of a failure that means "the tunlion server is unreachable from
/// here": DNS, no route, a refused or timed-out connect to signaling. Matched on
/// the whole chain, lowercased.
pub(crate) fn is_network_text(s: &str) -> bool {
    let s = s.to_lowercase();
    const PATTERNS: [&str; 14] = [
        "signaling connect to",
        "websocket connect to",
        "failed to lookup address",
        "temporary failure in name resolution",
        "name or service not known",
        "nodename nor servname",
        "no such host is known",
        "dns error",
        "network is unreachable",
        "error sending request for url",
        "signaling connection lost",
        "signaling channel closed",
        "signaling closed",
        "can't reach the tunlion server",
    ];
    PATTERNS.iter().any(|p| s.contains(p))
}

/// Classify a failure from its text. Order matters: a network failure often
/// also says "timed out", and it is the network a person has to fix.
pub(crate) fn classify_text(s: &str) -> ExitKind {
    if is_network_text(s) {
        return ExitKind::Network;
    }
    let s = s.to_lowercase();
    let any = |ps: &[&str]| ps.iter().any(|p| s.contains(p));
    if any(&["no identity yet", "no identity. run"]) {
        return ExitKind::NoIdentity;
    }
    // A confirmation a script did not pre-answer (UiCapability::confirm): the
    // command line is missing -y/--yes, which is a usage error, not a failure
    // of the work. It was 1, the catch-all.
    if s.contains("without --yes") {
        return ExitKind::Usage;
    }
    if is_local_resource_text(&s) {
        return ExitKind::LocalResource;
    }
    if any(&[
        "no device named",
        "no known device",
        "not a known device",
        "is not paired",
        "not paired with",
    ]) {
        return ExitKind::UnknownDevice;
    }
    // "connection refused" is a socket that was not listening, not a decision
    // anyone made, so it is not a refusal in this sense.
    let refused = s.contains("refused") && !s.contains("connection refused");
    if refused
        || any(&[
            "denied",
            "declined",
            "not accepted",
            "not authorized",
            "outside the device's invitation ceiling",
            // A policy close mid-session: the device's access ended or was
            // revoked. Either is a decision, never a broken link.
            "access expired",
            "access revoked",
            "already been used",
            "invitation has expired",
        ])
    {
        return ExitKind::Denied;
    }
    if any(&[
        "timed out",
        "connect timeout",
        "couldn't reach",
        "could not reach",
        "unreachable",
        "no answer from",
        "is offline",
        "may be offline",
        "lost the receiving peer",
        "died during",
        "died mid",
        "disconnected before",
        "no usable path",
        "connection refused",
    ]) {
        return ExitKind::Unreachable;
    }
    ExitKind::Other
}

/// A resource on this machine ran out (see [`ExitKind::LocalResource`]).
/// Matched on the OS's own error text, lowercased. A receiver's refusal is
/// not this, even when its sentence quotes the receiver's ENOSPC: that says
/// "receiver", and it is the peer's disk.
pub(crate) fn is_local_resource_text(s: &str) -> bool {
    let s = s.to_lowercase();
    if s.contains("receiver") {
        return false;
    }
    const PATTERNS: [&str; 8] = [
        "no space left on device",
        "os error 28)",
        "disk quota exceeded",
        "os error 122)",
        "too many open files",
        "os error 24)",
        "cannot allocate memory",
        "out of memory",
    ];
    PATTERNS.iter().any(|p| s.contains(p))
}

// ------------------------------------------------------- per-verb help ---
//
// `send --help` documented 0/1/4/6 while send returned 2, 3 and 130 too. Each
// verb's --help now ends with the codes THAT verb can return, generated from
// one table, and a unit test cross-checks the table against every `ExitKind`
// the verb's own source names (`every_verbs_error_paths_are_in_its_help`).

/// `exec` passes these through from the remote side (see the help text).
pub(crate) const EXEC_NOT_FOUND: i32 = 127;
pub(crate) const EXEC_CANNOT_RUN: i32 = 126;
/// 128 + SIGPIPE: this side's output closed before the work finished, which is
/// what a shell reports for a process killed by SIGPIPE (`set -o pipefail`).
pub(crate) const OUTPUT_CLOSED: i32 = 141;

const SEND_CODES: &[i32] = &[0, 1, 2, 3, 4, 6, 7, 8, 9, 12, 130, 141, 143];
const RECEIVE_CODES: &[i32] = &[0, 1, 2, 3, 4, 6, 7, 8, 9, 12, 130, 141, 143];
const SYNC_CODES: &[i32] = &[0, 1, 2, 3, 4, 6, 7, 8, 9, 12, 130, 141, 143];
const EXEC_CODES: &[i32] = &[1, 2, 3, 4, 6, 7, 9, 126, 127, 130, 141, 143];
const REACH_CODES: &[i32] = &[0, 1, 2, 3, 5, 6, 7, 9, 130, 143];
const STATUS_CODES: &[i32] = &[0, 1, 2, 6, 9, 11, 130, 143];
const DEVICES_CODES: &[i32] = &[0, 1, 2, 3, 9, 12];
const DOCTOR_CODES: &[i32] = &[0, 1, 2, 3, 6, 7, 9, 130, 143];
const UP_CODES: &[i32] = &[0, 1, 2, 4, 7, 9, 10, 12, 130, 143];
const LOGS_CODES: &[i32] = &[0, 1, 2, 130, 143];
const DOWN_CODES: &[i32] = &[0, 1, 2, 6];
const PAIRING_CODES: &[i32] = &[0, 1, 2, 3, 4, 6, 7, 9, 12, 130, 143];
const LOCAL_CODES: &[i32] = &[0, 1, 2, 3, 9, 12];
/// `skill`: a refused or unresolvable target is 2, a full disk 12.
const SKILL_CODES: &[i32] = &[0, 1, 2, 12];
/// Verbs not listed above: the codes any command can produce.
const DEFAULT_CODES: &[i32] = &[0, 1, 2, 3, 4, 6, 7, 9, 12, 130, 143];

/// The exit codes `verb` can return.
pub(crate) fn verb_exit_codes(verb: &str) -> &'static [i32] {
    match verb {
        "send" => SEND_CODES,
        "receive" => RECEIVE_CODES,
        "sync" | "backup" => SYNC_CODES,
        "exec" => EXEC_CODES,
        "reach" => REACH_CODES,
        "status" => STATUS_CODES,
        "devices" => DEVICES_CODES,
        "doctor" => DOCTOR_CODES,
        "up" => UP_CODES,
        "logs" => LOGS_CODES,
        "down" => DOWN_CODES,
        "init" | "add" | "join" | "pair" | "depart" | "enroll" | "grant" | "revoke" => PAIRING_CODES,
        "set" | "addr" | "id" | "config" | "completions" | "man" => LOCAL_CODES,
        "skill" => SKILL_CODES,
        _ => DEFAULT_CODES,
    }
}

/// One line of the per-verb EXIT CODES block.
fn code_meaning(verb: &str, code: i32) -> &'static str {
    match (verb, code) {
        ("status", 0) => "the daemon for this config directory runs, answers, and has an identity",
        ("status", 6) => "a daemon runs but did not answer in time",
        ("status", 9) => "the daemon answers but this device has no identity yet",
        ("reach", 0) => "the peer answered (warm link, or a cold probe that connected)",
        ("send", 0) => "every file was delivered and verified by the receiver",
        ("send", 4) => "the receiver refused (its reason is printed, and in --json `error.reason`)",
        ("send", 8) => "some files were delivered and some were not",
        ("sync", 8) => "some files moved and some did not",
        (_, 0) => "success",
        (_, 1) => "any other error",
        (_, 2) => "usage: bad arguments or flags, a local file problem, or a missing prerequisite",
        (_, 3) => "unknown device, or not paired with this one",
        (_, 4) => "denied: refused by the peer, a capability, or the system",
        (_, 5) => "--until-direct: the link is up but still on a relay",
        (_, 6) => "the peer is offline, unreachable, or did not answer in time",
        (_, 7) => "can't reach the tunlion server (no internet or DNS)",
        (_, 8) => "partial: some of the work landed and some did not",
        (_, 9) => "this device has no identity yet (init, or join an invitation)",
        (_, 10) => "a daemon is already running with different settings (not applied)",
        (_, 11) => "no daemon is running for this config directory",
        (_, 12) => "a resource on this machine ran out (disk full, quota, open files, memory)",
        (_, EXEC_CANNOT_RUN) => "the remote command was found but cannot be executed there",
        (_, EXEC_NOT_FOUND) => "the remote command is not on the remote daemon's PATH",
        (_, INTERRUPTED) => "interrupted (SIGINT); with --json the failure object is still printed",
        (_, OUTPUT_CLOSED) => "this side's output was closed before the work finished (`| head`)",
        (_, TERMINATED) => "terminated (SIGTERM); with --json the failure object is still printed",
        _ => "",
    }
}

/// The EXIT CODES block appended to `verb`'s --help.
pub(crate) fn exit_codes_help(verb: &str) -> String {
    let mut s = String::from("EXIT CODES\n");
    if verb == "exec" {
        s.push_str("  N    the remote command's own exit status, passed through (0 included)\n");
    }
    for &c in verb_exit_codes(verb) {
        s.push_str(&format!("  {c:<4} {}\n", code_meaning(verb, c)));
    }
    if verb == "exec" {
        s.push_str("  A remote status that equals one of tunlion's own codes is indistinguishable\n");
        s.push_str("  from it; the reason line on stderr says which it was.\n");
    }
    s.push_str("  Full table: tunlion --help. Under --json, ok is true exactly when the exit is 0.");
    s
}

/// `cmd` with every subcommand's --help ending in its EXIT CODES block.
pub(crate) fn with_exit_code_help(cmd: clap::Command) -> clap::Command {
    let names: Vec<String> = cmd.get_subcommands().map(|s| s.get_name().to_string()).collect();
    let mut cmd = cmd;
    for name in names {
        cmd = cmd.mut_subcommand(&name, |sc| {
            let mut text = sc.get_after_help().map(|h| format!("{h}\n\n")).unwrap_or_default();
            text.push_str(&exit_codes_help(&name));
            sc.after_help(text)
        });
    }
    cmd
}

/// What a person sees for a network failure instead of the raw error chain.
pub(crate) const NETWORK_LINE: &str =
    "Can't reach the tunlion server (no internet or DNS?). Run `tunlion doctor` for details.";

// ------------------------------------------------------------- json mode ---

static JSON_MODE: AtomicBool = AtomicBool::new(false);
static VERB: Mutex<Option<String>> = Mutex::new(None);

/// Record, once the command line is parsed, whether failures must be reported
/// as JSON on stdout and which verb they belong to.
pub(crate) fn set_json_mode(on: bool, verb: Option<&str>) {
    JSON_MODE.store(on, Ordering::Relaxed);
    if let Ok(mut v) = VERB.lock() {
        *v = verb.map(str::to_string);
    }
    if on {
        arm_json_interrupt();
    }
}

// ------------------------------------------------------- interruption ---
//
// `tunlion --help` promises "With --json, a failure is one JSON object on
// stdout", and an interrupted command is a failure: `send --json` killed with
// SIGINT exited 130 with nothing on stdout, so a script read an empty document.
// Every interrupt exit under --json now prints the failure object first, once:
//
//   {"ok":false,"verb":"send","error":{"code":"interrupted","exit":130,
//    "signal":"SIGINT","message":"interrupted (SIGINT) before it finished"}}
//
// SIGINT exits 130 and SIGTERM 143 (128 + the signal number), as a shell
// reports a process killed by them.

/// Exit code for an interrupt (SIGINT, Ctrl-C).
pub(crate) const INTERRUPTED: i32 = 130;
/// Exit code for a termination request (SIGTERM).
pub(crate) const TERMINATED: i32 = 143;

/// A result object (success or failure) already went to stdout; an interrupt
/// after that must not add a second document.
static JSON_ANSWERED: AtomicBool = AtomicBool::new(false);
static INTERRUPT_ARMED: AtomicBool = AtomicBool::new(false);

/// Record that this command's one JSON document has been written.
pub(crate) fn note_json_answered() {
    JSON_ANSWERED.store(true, Ordering::SeqCst);
}

fn signal_name(code: i32) -> &'static str {
    if code == TERMINATED { "SIGTERM" } else { "SIGINT" }
}

/// The `--json` failure object for an interrupted command. Pure but for the
/// recorded verb.
pub(crate) fn interrupted_envelope(code: i32) -> Value {
    let sig = signal_name(code);
    let mut error = json!({
        "code": "interrupted",
        "exit": code,
        "signal": sig,
        "message": format!("interrupted ({sig}) before it finished"),
    });
    if code != INTERRUPTED && code != TERMINATED {
        error["signal"] = Value::Null;
        error["message"] = json!("interrupted before it finished");
    }
    let mut v = json!({ "ok": false, "error": error });
    if let Some(verb) = verb() {
        if verb == "send" {
            return crate::send_report::interrupted_object(v);
        }
        v["verb"] = json!(verb);
    }
    v
}

/// Under `--json`, print the interrupted failure object unless this command
/// already printed its answer. Idempotent: the first caller prints.
pub(crate) fn report_interrupted(code: i32) {
    if json_mode() && !JSON_ANSWERED.swap(true, Ordering::SeqCst) {
        ui::json_out(&interrupted_envelope(code));
    }
}

/// Exit for an interrupt: the `--json` failure object first, then the code.
/// Every interrupt exit goes through here so none of them leaves stdout empty.
pub(crate) fn interrupted_exit(code: i32) -> ! {
    report_interrupted(code);
    std::process::exit(code)
}

/// Under `--json`, catch SIGINT and SIGTERM for every verb: print the failure
/// object at once, then exit with 130 or 143. A verb with its own Ctrl-C
/// handling (send, receive) runs its graceful teardown in parallel and exits
/// through [`interrupted_exit`] itself; this one only exits after the same
/// bounded grace, so it never cuts that teardown short, and it is what makes
/// a verb with no handler of its own still answer and still exit on Ctrl-C.
fn arm_json_interrupt() {
    if INTERRUPT_ARMED.swap(true, Ordering::SeqCst) {
        return;
    }
    // Only on the multi-thread runtime. A light command runs on a
    // current-thread runtime and may block in plain code, where a spawned
    // task never runs: installing a handler there would trade "dies on
    // Ctrl-C without JSON" for "ignores Ctrl-C", which is worse. Light
    // commands are local and finish at once.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        INTERRUPT_ARMED.store(false, Ordering::SeqCst);
        return;
    };
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        INTERRUPT_ARMED.store(false, Ordering::SeqCst);
        return;
    }
    handle.spawn(async {
        let _ = tokio::signal::ctrl_c().await;
        report_interrupted(INTERRUPTED);
        tokio::time::sleep(crate::shutdown::grace()).await;
        std::process::exit(INTERRUPTED);
    });
    handle.spawn(async {
        crate::platform::terminate_requested().await;
        // SIGTERM's default action is to die at once; with a handler
        // installed that is now this task's job.
        interrupted_exit(TERMINATED);
    });
}

pub(crate) fn json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

fn verb() -> Option<String> {
    VERB.lock().ok().and_then(|v| v.clone())
}

/// The `--json` failure envelope: `{"ok":false,"verb":..,"error":{code,exit,message}}`.
/// `detail` carries the raw error chain when it differs from the message.
pub(crate) fn json_error(kind: ExitKind, message: &str, detail: Option<&str>) -> Value {
    let mut error = json!({ "code": kind.token(), "exit": kind.code(), "message": message });
    if let Some(d) = detail.filter(|d| *d != message) {
        error["detail"] = json!(d);
    }
    let mut v = json!({ "ok": false, "error": error });
    if let Some(verb) = verb() {
        v["verb"] = json!(verb);
    }
    v
}

/// The message a person (or a `--json` reader) gets for this error: the one
/// human line for a network failure, the error's own text otherwise.
pub(crate) fn human_message(e: &anyhow::Error) -> String {
    if classify(e) == ExitKind::Network && is_network_text(&format!("{e:#}")) {
        NETWORK_LINE.to_string()
    } else {
        e.to_string()
    }
}

/// The message and its cause chain in the shape `{e:?}` prints, WITHOUT the
/// stack backtrace `{e:?}` appends whenever RUST_BACKTRACE or
/// RUST_LIB_BACKTRACE is set. A Rust developer usually has one of those
/// exported, and every ordinary refusal (`send --to` an unknown device, a bad
/// flag) then ended in a page of `<unknown>` frames that read as a crash; the
/// gate logs, which tail the last lines, showed only the frames and never the
/// reason. A real panic still prints its backtrace through the panic hook.
pub(crate) fn error_with_causes(e: &anyhow::Error) -> String {
    let mut out = e.to_string();
    let causes: Vec<String> = e.chain().skip(1).map(|c| c.to_string()).collect();
    match causes.as_slice() {
        [] => {}
        [only] => out.push_str(&format!("\n\nCaused by:\n    {only}")),
        many => {
            out.push_str("\n\nCaused by:");
            for (i, c) in many.iter().enumerate() {
                out.push_str(&format!("\n    {i}: {c}"));
            }
        }
    }
    out
}

/// `main`'s failure path: report the error once, in the form the caller asked
/// for, and return the exit code.
///
/// Human output keeps the exact shape Rust's default `main -> Result` printed
/// (`Error: <message>` plus the cause chain) for everything except a network
/// failure, which becomes one plain line; its raw chain is shown under `-v`.
/// Under `--json` the envelope goes to stdout as well, so stdout is always one
/// JSON document and stderr still carries the reason for a log.
pub(crate) fn report(e: &anyhow::Error) -> i32 {
    let kind = classify(e);
    if e.chain().any(|c| c.downcast_ref::<Reported>().is_some()) {
        return kind.code();
    }
    let raw = format!("{e:#}");
    let network = kind == ExitKind::Network && is_network_text(&raw);
    let message = human_message(e);
    if json_mode() && !JSON_ANSWERED.swap(true, Ordering::SeqCst) {
        let mut v = json_error(kind, &message, Some(&raw));
        v["error"]["code"] = json!(json_code(e));
        ui::json_out(&v);
    }
    if network {
        ui::critical(&format!("Error: {NETWORK_LINE}"));
        ui::debug(&format!("  cause: {raw}"));
    } else {
        ui::critical(&format!("Error: {}", error_with_causes(e)));
    }
    kind.code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_report_carries_the_cause_chain_and_never_a_backtrace() {
        let one = anyhow::anyhow!("root cause").context("what failed");
        assert_eq!(error_with_causes(&one), "what failed\n\nCaused by:\n    root cause");
        let two = anyhow::anyhow!("deepest").context("middle").context("top");
        assert_eq!(
            error_with_causes(&two),
            "top\n\nCaused by:\n    0: middle\n    1: deepest"
        );
        assert_eq!(error_with_causes(&anyhow::anyhow!("alone")), "alone");
        // The Debug form it replaces matches it exactly when no backtrace was
        // captured, so the human output keeps its shape.
        if one.backtrace().status() != std::backtrace::BacktraceStatus::Captured {
            assert_eq!(format!("{one:?}"), error_with_causes(&one));
            assert_eq!(format!("{two:?}"), error_with_causes(&two));
        }
    }

    #[test]
    fn codes_are_distinct_and_keep_the_existing_meanings() {
        let mut seen = std::collections::HashSet::new();
        for k in ExitKind::ALL {
            assert!(seen.insert(k.code()), "{k:?} reuses exit code {}", k.code());
            assert!(k.code() != 0 && k.code() != 130, "{k:?} collides with success or SIGINT");
        }
        // Asserted by gates before this module existed; never renumber them.
        assert_eq!(ExitKind::UnknownDevice.code(), 3, "sync-gates.sh gate F");
        assert_eq!(ExitKind::Denied.code(), 4, "sync-gates.sh gates D1/D2/I");
        assert_eq!(ExitKind::StillRelayed.code(), 5, "reach --until-direct --help");
        assert_eq!(ExitKind::Usage.code(), 2, "clap and fleet_ui EXIT_BAD_ARG");
        assert_eq!(ExitKind::Other.code(), 1);
    }

    #[test]
    fn the_reported_dns_failure_is_a_network_failure() {
        let raw = "signaling connect to https://tunlion.autumated.com: failed to lookup address information: Try again";
        assert_eq!(classify_text(raw), ExitKind::Network);
        let e = anyhow::anyhow!("failed to lookup address information: Try again")
            .context("signaling connect to https://tunlion.autumated.com");
        assert_eq!(classify(&e), ExitKind::Network);
        assert_eq!(human_message(&e), NETWORK_LINE);
        assert!(!human_message(&e).contains("lookup"), "the raw chain is for -v only");
    }

    #[test]
    fn text_classification_covers_the_verbs_failure_sentences() {
        let cases = [
            ("no device named 'nope'. Known devices: a, b", ExitKind::UnknownDevice),
            ("exec denied by box: this device's invitation ceiling (send) does not include shell", ExitKind::Denied),
            ("'box' refused exec: shell not granted", ExitKind::Denied),
            ("send incomplete: 0 delivered, 1 declined", ExitKind::Denied),
            ("connect timeout: couldn't reach 'box' in 45s", ExitKind::Unreachable),
            ("lost the receiving peer after 3 attempts", ExitKind::Unreachable),
            ("tcp connect to 127.0.0.1:22: Connection refused (os error 111)", ExitKind::Unreachable),
            ("this invitation has expired", ExitKind::Denied),
            ("something else entirely", ExitKind::Other),
        ];
        for (text, want) in cases {
            assert_eq!(classify_text(text), want, "{text}");
        }
    }

    #[test]
    fn an_explicit_kind_beats_the_text() {
        let e = err(ExitKind::Usage, "no device named this, but it is a usage error");
        assert_eq!(classify(&e), ExitKind::Usage);
        let wrapped = e.context("while doing a thing");
        assert_eq!(classify(&wrapped), ExitKind::Usage, "the kind survives context");
        assert_eq!(classify(&reported(ExitKind::Unreachable)), ExitKind::Unreachable);
    }

    /// J5: an already-printed refusal kept only its code for `--json`, so a
    /// full disk read `{"message": "failed (denied)"}`. The sentence rides
    /// along, and a reason-less report keeps the old text.
    #[test]
    fn a_reported_failure_keeps_its_sentence_for_json() {
        let e = reported_because(
            ExitKind::Denied,
            "receiver is out of disk space for a.bin (needs 2.9 MiB, has 980.0 KiB)",
        );
        assert_eq!(classify(&e), ExitKind::Denied);
        assert!(human_message(&e).contains("out of disk space"), "{}", human_message(&e));
        assert_eq!(human_message(&reported(ExitKind::Denied)), "failed (denied)");
    }

    /// The blind automation run: these were exit 1. Each is a usage error,
    /// classified where it is raised rather than from its text.
    #[test]
    fn usage_errors_from_the_blind_run_exit_2() {
        let unknown_cap = crate::capability::canonical_capability("port")
            .map_err(crate::dispatch::grant_usage)
            .unwrap_err();
        assert_eq!(classify(&unknown_cap), ExitKind::Usage);
        assert_eq!(classify(&unknown_cap).code(), 2);
        let route = crate::capability::parse_grant_spec("route", &[0u8; 32])
            .map_err(crate::dispatch::grant_usage)
            .err()
            .expect("route without a prefix must not parse");
        assert_eq!(classify(&route), ExitKind::Usage);
        let missing = crate::send_cmd::missing_input(
            "nope.txt",
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(classify(&missing).code(), 2);
    }

    /// Offline and unconfirmed sends carry their kinds explicitly, so the
    /// exit code does not depend on the wording.
    #[test]
    fn offline_is_6_and_unconfirmed_delivery_is_8() {
        let off = err(ExitKind::Unreachable, crate::send_cmd::offline_message("laptop", std::time::Duration::from_secs(10)));
        assert_eq!(classify(&off).code(), 6);
        let unconfirmed = err(
            ExitKind::Partial,
            "delivery not confirmed: 1 file(s) sent but never delivery-acked by the receiver",
        );
        assert_eq!(classify(&unconfirmed).code(), 8);
        // And with no explicit kind the old sentence would have been 1: the
        // classification must come from the source, not the text.
        assert_eq!(
            classify_text("delivery not confirmed: 1 file(s) sent but never delivery-acked"),
            ExitKind::Other
        );
    }

    /// J3: `send --json` interrupted with SIGINT exited 130 and printed no
    /// JSON. The interrupted object has the failure envelope's shape, names
    /// the signal, and carries the exit code the process uses.
    #[test]
    fn an_interrupt_has_a_json_failure_object() {
        let v = interrupted_envelope(INTERRUPTED);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"]["code"], json!("interrupted"));
        assert_eq!(v["error"]["exit"], json!(130));
        assert_eq!(v["error"]["signal"], json!("SIGINT"));
        let t = interrupted_envelope(TERMINATED);
        assert_eq!(t["error"]["exit"], json!(143));
        assert_eq!(t["error"]["signal"], json!("SIGTERM"));
        assert!(t["error"]["message"].as_str().unwrap().contains("SIGTERM"));
        // The codes are 128 + the signal number, and no kind reuses them.
        assert_eq!(INTERRUPTED, 128 + 2);
        assert_eq!(TERMINATED, 128 + 15);
        for k in ExitKind::ALL {
            assert!(k.code() != INTERRUPTED && k.code() != TERMINATED);
        }
    }

    /// J6: local file problems were 2, a full stdin spool 1 and `add --out`
    /// onto a full disk 1. Local resource exhaustion is one code, 12, and a
    /// receiver's full disk stays the peer's refusal.
    #[test]
    fn local_resource_exhaustion_is_one_code() {
        assert_eq!(ExitKind::LocalResource.code(), 12);
        let cases = [
            "spooling stdin: No space left on device (os error 28)",
            "could not write /mnt/full/inv.txt: No space left on device (os error 28)",
            "writing config: Disk quota exceeded (os error 122)",
            "open: Too many open files (os error 24)",
        ];
        for c in cases {
            assert_eq!(classify_text(c), ExitKind::LocalResource, "{c}");
        }
        assert_eq!(
            classify_text("receiver is out of disk space for a.bin (No space left on device (os error 28))"),
            ExitKind::Other,
            "the receiver's disk is not this machine's"
        );
        assert_eq!(classify_text("permission denied (os error 13)"), ExitKind::Denied);
    }

    /// E2: `add --for beta --allow shell` from a script failed "refusing to
    /// include deliberate remote authority ... without --yes" with exit 1. A
    /// missing flag is usage: 2.
    #[test]
    fn a_missing_yes_is_a_usage_error() {
        for c in [
            "refusing to include deliberate remote authority in this invitation ceiling without --yes (non-interactive)",
            "refusing to shut down the daemon without --yes (non-interactive)",
        ] {
            assert_eq!(classify_text(c), ExitKind::Usage, "{c}");
            assert_eq!(classify_text(c).code(), 2, "{c}");
        }
    }

    /// J6: every verb's --help lists what it can return. Cross-checked
    /// against the source: every `ExitKind::X` a verb's own files name must be
    /// in that verb's table, so a new error path cannot add a code its help
    /// does not mention. Text-classified errors are covered by the shared
    /// codes every networked verb lists (3, 4, 6, 7, 9, 12).
    #[test]
    fn every_verbs_error_paths_are_in_its_help() {
        let kinds = [
            ("Other", 1), ("Usage", 2), ("UnknownDevice", 3), ("Denied", 4),
            ("StillRelayed", 5), ("Unreachable", 6), ("Network", 7), ("Partial", 8),
            ("NoIdentity", 9), ("LocalResource", 12),
        ];
        assert_eq!(kinds.len(), ExitKind::ALL.len(), "a new kind needs a row here");
        // status_cmd.rs is not scanned: it also holds `up --detach`'s helpers
        // (the network verdict for a daemon that died starting), which are
        // up's codes. status's own codes are decided in one function,
        // status_exit_code, and asserted below.
        let sources: [(&str, &str); 6] = [
            ("send", concat!(include_str!("send_cmd.rs"), include_str!("send_report.rs"), include_str!("send_source.rs"))),
            ("sync", include_str!("sync_cmd.rs")),
            ("exec", include_str!("exec_send.rs")),
            ("reach", include_str!("ping.rs")),
            ("receive", include_str!("recv_cmd.rs")),
            ("skill", include_str!("skill.rs")),
        ];
        for (verb, src) in sources {
            let allowed = verb_exit_codes(verb);
            for (name, code) in kinds {
                if src.contains(&format!("ExitKind::{name}")) {
                    assert!(allowed.contains(&code), "{verb} can return {code} (ExitKind::{name}) but its --help does not list it");
                }
            }
            if src.contains("STATUS_NOT_RUNNING") {
                assert!(allowed.contains(&STATUS_NOT_RUNNING), "{verb}");
            }
            if src.contains("interrupted_exit") || src.contains("ctrl_c") {
                assert!(allowed.contains(&INTERRUPTED), "{verb} handles Ctrl-C");
            }
            for c in [EXEC_NOT_FOUND, EXEC_CANNOT_RUN, OUTPUT_CLOSED] {
                let named = match c {
                    EXEC_NOT_FOUND => "EXEC_NOT_FOUND",
                    EXEC_CANNOT_RUN => "EXEC_CANNOT_RUN",
                    _ => "OUTPUT_CLOSED",
                };
                if src.contains(&format!("exit_codes::{named}")) {
                    assert!(allowed.contains(&c), "{verb} returns {c}");
                }
            }
        }
        for c in [0, STATUS_NOT_RUNNING, 6, 9] {
            assert!(verb_exit_codes("status").contains(&c), "status returns {c}");
        }
        assert!(verb_exit_codes("up").contains(&7), "up --detach: the daemon said the network");
        // The reported case: send's help named 0/1/4/6 only.
        let help = exit_codes_help("send");
        for c in [0, 1, 2, 3, 4, 6, 7, 8, 130] {
            assert!(help.lines().any(|l| l.trim_start().starts_with(&format!("{c} "))), "send --help lacks {c}:\n{help}");
        }
        // Every listed code has a meaning, for every verb.
        let cmd = with_exit_code_help(<crate::Cli as clap::CommandFactory>::command());
        for sc in cmd.get_subcommands() {
            let after = sc.get_after_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(after.contains("EXIT CODES"), "{} --help has no EXIT CODES", sc.get_name());
            for &c in verb_exit_codes(sc.get_name()) {
                assert!(!code_meaning(sc.get_name(), c).is_empty(), "{} {c} has no meaning", sc.get_name());
            }
        }
    }

    #[test]
    fn the_json_error_envelope_has_the_documented_shape() {
        let v = json_error(ExitKind::UnknownDevice, "no device named 'x'", None);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"]["code"], json!("unknown_device"));
        assert_eq!(v["error"]["exit"], json!(3));
        assert_eq!(v["error"]["message"], json!("no device named 'x'"));
        assert!(v["error"].get("detail").is_none(), "no detail when it adds nothing");
    }

    /// The help footer is the documentation a script author reads; every kind
    /// must be in it with its number, or the table and the code have drifted.
    #[test]
    fn every_code_is_documented_in_the_help_footer() {
        let footer = crate::cli_def::EXAMPLES
            .split("EXIT CODES")
            .nth(1)
            .expect("tunlion --help must carry an EXIT CODES section");
        for k in ExitKind::ALL {
            let n = format!("{} ", k.code());
            assert!(
                footer.lines().any(|l| l.trim_start().starts_with(&n) || l.contains(&format!("  {n}"))),
                "{k:?} (exit {}) is missing from the EXIT CODES help section",
                k.code()
            );
        }
        assert!(
            footer.lines().any(|l| l.trim_start().starts_with(&format!("{DAEMON_CONFLICT} "))),
            "DAEMON_CONFLICT (exit {DAEMON_CONFLICT}) is missing from the EXIT CODES help section"
        );
        let kinds: Vec<i32> = ExitKind::ALL.iter().map(|k| k.code()).collect();
        assert!(!kinds.contains(&DAEMON_CONFLICT), "DAEMON_CONFLICT must not reuse a kind's code");
        assert!(
            footer.lines().any(|l| l.trim_start().starts_with(&format!("{STATUS_NOT_RUNNING} "))),
            "STATUS_NOT_RUNNING (exit {STATUS_NOT_RUNNING}) is missing from the EXIT CODES help section"
        );
        assert!(
            !kinds.contains(&STATUS_NOT_RUNNING) && STATUS_NOT_RUNNING != DAEMON_CONFLICT,
            "STATUS_NOT_RUNNING must not reuse another code"
        );
    }
}
