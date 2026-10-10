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
}

impl ExitKind {
    #[cfg(test)]
    pub(crate) const ALL: [ExitKind; 9] = [
        ExitKind::Other,
        ExitKind::Usage,
        ExitKind::UnknownDevice,
        ExitKind::Denied,
        ExitKind::StillRelayed,
        ExitKind::Unreachable,
        ExitKind::Network,
        ExitKind::Partial,
        ExitKind::NoIdentity,
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
#[derive(Debug)]
pub(crate) struct Reported(pub(crate) ExitKind);

impl std::fmt::Display for Reported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed ({})", self.0.token())
    }
}
impl std::error::Error for Reported {}

/// An error of a known kind.
pub(crate) fn err(kind: ExitKind, msg: impl Into<String>) -> anyhow::Error {
    Classified { kind, msg: msg.into() }.into()
}

/// "Already said; exit with this kind." See [`Reported`].
pub(crate) fn reported(kind: ExitKind) -> anyhow::Error {
    Reported(kind).into()
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
    if json_mode() {
        ui::json_out(&json_error(kind, &message, Some(&raw)));
    }
    if network {
        ui::critical(&format!("Error: {NETWORK_LINE}"));
        ui::debug(&format!("  cause: {raw}"));
    } else {
        ui::critical(&format!("Error: {e:?}"));
    }
    kind.code()
}

#[cfg(test)]
mod tests {
    use super::*;

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
