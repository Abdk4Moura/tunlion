//! Why a peer said no to a shell-class open, and what to do about it.
//!
//! The acceptor knows the precise cause of a refusal (serving is off, this
//! device holds no grant there, the grant was revoked, the certificate was
//! revoked, the invitation ceiling excludes it, the configured user drop cannot
//! run), and it knows the name it has filed the initiator under. The initiator
//! knows neither, and before this module it guessed: a device with no shell
//! grant on a peer that WAS serving shells read "shell serving is off there;
//! run `tunlion up --shell`", which sent the user to fix the one thing that was
//! already right.
//!
//! So the refusal now carries a reason CODE (`code`) and the acceptor's name for
//! the initiator (`as`) next to the human `err`, and the initiator maps the code
//! to exactly one remedy. Older peers send only `err`; for those the code is
//! recovered from the canonical reason strings below, which are the only
//! strings an acceptor of this build produces for these causes.
//!
//! Wire: additive fields on `l2-close` and `shell-bootstrap-deny`. An older
//! initiator ignores them and still prints `err`.

use serde_json::{Value, json};

/// The precise cause of a shell-class refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    /// Shell serving is off on the acceptor (no `--shell`, no grant at all).
    ShellOff,
    /// The tunnel acceptor is off (forward/netcat/ssh have nothing to open).
    TunnelOff,
    /// Serving is on, but this device holds no shell grant there.
    NotGranted,
    /// The acceptor's owner revoked shell for this device.
    Revoked,
    /// The acceptor revoked this device's certificate.
    CertRevoked,
    /// The enrolment ceiling excludes shell; a grant cannot widen it.
    Ceiling,
    /// The acceptor is configured to drop shells to another account
    /// (`--shell-user`) and cannot do so (it is not running as root).
    UserDropUnavailable,
}

impl Code {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Code::ShellOff => "shell-off",
            Code::TunnelOff => "tunnel-off",
            Code::NotGranted => "not-granted",
            Code::Revoked => "revoked",
            Code::CertRevoked => "cert-revoked",
            Code::Ceiling => "ceiling",
            Code::UserDropUnavailable => "user-drop-unavailable",
        }
    }

    pub(crate) fn from_wire(s: &str) -> Option<Code> {
        Some(match s {
            "shell-off" => Code::ShellOff,
            "tunnel-off" => Code::TunnelOff,
            "not-granted" => Code::NotGranted,
            "revoked" => Code::Revoked,
            "cert-revoked" => Code::CertRevoked,
            "ceiling" => Code::Ceiling,
            "user-drop-unavailable" => Code::UserDropUnavailable,
            _ => return None,
        })
    }
}

/// Canonical human reason for a device with no grant, naming the acceptor's
/// petname for it when known. Keeps the words "not granted" (gates and older
/// tooling match on them).
pub(crate) fn not_granted_reason(as_name: Option<&str>) -> String {
    match as_name {
        Some(n) => format!("shell not granted to '{n}' here"),
        None => "shell capability not granted".to_string(),
    }
}

/// Canonical human reason for an owner-revoked shell grant.
pub(crate) fn revoked_reason(as_name: Option<&str>) -> String {
    match as_name {
        Some(n) => format!("shell revoked for '{n}' here"),
        None => "shell revoked for this device here".to_string(),
    }
}

/// Canonical human reason for a user drop the acceptor cannot perform.
pub(crate) const USER_DROP_REASON: &str =
    "this device is set to run shells as another account (--shell-user) but is not running as root, so it cannot switch to it";

/// A refusal as the acceptor decided it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Refusal {
    pub(crate) code: Code,
    pub(crate) reason: String,
    /// The acceptor's petname for the initiator, when proven.
    pub(crate) as_name: Option<String>,
}

impl Refusal {
    pub(crate) fn new(code: Code, as_name: Option<String>) -> Refusal {
        let reason = match code {
            Code::ShellOff => crate::capability::SHELL_OFF_REASON.to_string(),
            Code::TunnelOff => crate::capability::TUNNEL_OFF_REASON.to_string(),
            Code::NotGranted => not_granted_reason(as_name.as_deref()),
            Code::Revoked => revoked_reason(as_name.as_deref()),
            Code::CertRevoked => "device revoked".to_string(),
            Code::Ceiling => crate::capability::CEILING_REASON.to_string(),
            Code::UserDropUnavailable => USER_DROP_REASON.to_string(),
        };
        Refusal {
            code,
            reason,
            as_name,
        }
    }

    /// Classify a shell-gate denial. `cap_reason` is the engine's reason when
    /// it named one; `cert_revoked`/`denied` are the gate inputs.
    pub(crate) fn from_shell_gate(
        cert_revoked: bool,
        denied: bool,
        cap_reason: Option<&str>,
        as_name: Option<String>,
    ) -> Refusal {
        let code = if cert_revoked || cap_reason == Some("device revoked") {
            Code::CertRevoked
        } else if cap_reason == Some(crate::capability::CEILING_REASON) {
            Code::Ceiling
        } else if denied {
            Code::Revoked
        } else {
            Code::NotGranted
        };
        let mut r = Refusal::new(code, as_name);
        // Keep a specific engine reason the code does not already spell (e.g.
        // an expiry): it is more precise than the canonical sentence.
        if code == Code::NotGranted {
            if let Some(c) = cap_reason.filter(|c| !c.is_empty()) {
                r.reason = format!("{}: {c}", r.reason);
            }
        }
        r
    }

    /// Add the code and name to an outgoing refusal frame.
    pub(crate) fn annotate(&self, frame: &mut Value) {
        frame["code"] = json!(self.code.as_wire());
        if let Some(n) = &self.as_name {
            frame["as"] = json!(n);
        }
    }

    /// The `l2-close` that carries this refusal.
    pub(crate) fn close_frame(&self, sid: u32) -> Value {
        let mut f = json!({ "type": "l2-close", "sid": sid, "err": self.reason });
        self.annotate(&mut f);
        f
    }
}

/// Recover the code from a reason string alone (older peers, and paths whose
/// plumbing carries only the string).
pub(crate) fn code_from_reason(reason: &str) -> Option<Code> {
    let r = reason.trim();
    if r == crate::capability::SHELL_OFF_REASON {
        return Some(Code::ShellOff);
    }
    if r == crate::capability::TUNNEL_OFF_REASON {
        return Some(Code::TunnelOff);
    }
    if r == crate::capability::CEILING_REASON {
        return Some(Code::Ceiling);
    }
    if r.starts_with("shell revoked for") {
        return Some(Code::Revoked);
    }
    // REVOKED_REASON is the mid-session close, sent for a revoked certificate
    // as well as a withdrawn grant; the restore remedy is the one the shell
    // path has always given for it.
    if r == "device revoked" || r == crate::capability::REVOKED_REASON {
        return Some(Code::CertRevoked);
    }
    if r == USER_DROP_REASON {
        return Some(Code::UserDropUnavailable);
    }
    if r.starts_with("shell not granted to")
        || r.starts_with("shell capability not granted")
        || r.starts_with("not authorized: device lacks shell grant")
    {
        return Some(Code::NotGranted);
    }
    None
}

/// The quoted name inside a canonical reason (`... to 'NAME' here`).
pub(crate) fn name_from_reason(reason: &str) -> Option<String> {
    let start = reason.find('\'')? + 1;
    let len = reason[start..].find('\'')?;
    let n = &reason[start..start + len];
    (!n.is_empty()).then(|| n.to_string())
}

/// The code and name from a refusal frame, falling back to its reason string.
pub(crate) fn from_frame(v: &Value, reason_key: &str) -> (Option<Code>, Option<String>) {
    let reason = v[reason_key].as_str().unwrap_or("");
    let code = v["code"]
        .as_str()
        .and_then(Code::from_wire)
        .or_else(|| code_from_reason(reason));
    let as_name = v["as"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| name_from_reason(reason));
    (code, as_name)
}

/// Quote a device name for a copy-pasteable command when it needs it.
pub(crate) fn word(s: &str) -> String {
    if s.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"') {
        format!("'{}'", s.replace('\'', ""))
    } else {
        s.to_string()
    }
}

/// The remedy for a refusal by `peer`: (what to do, the exact command, if any).
/// The command is always one the CLI accepts (see the parse test below).
/// `me` is the name `peer` knows this device by (the acceptor's `as`), else
/// this device's own display name, which is what a pairing files it under.
pub(crate) fn remedy(code: Code, peer: &str, me: &str) -> (String, Option<String>) {
    let me_w = word(me);
    match code {
        Code::ShellOff => {
            let cmd = format!("tunlion grant {me_w} shell");
            (
                format!("'{peer}' is not serving shells. On '{peer}', grant this device:"),
                Some(cmd),
            )
        }
        Code::TunnelOff => {
            let cmd = format!("tunlion grant {me_w} shell");
            (
                format!(
                    "'{peer}' is not accepting tunnels. On '{peer}', grant this device (forwarding rides the shell grant):"
                ),
                Some(cmd),
            )
        }
        Code::NotGranted => {
            let cmd = format!("tunlion grant {me_w} shell");
            (
                format!(
                    "'{peer}' serves shells, but this device has no shell grant there. On '{peer}', run:"
                ),
                Some(cmd),
            )
        }
        Code::Revoked => {
            let cmd = format!("tunlion grant {me_w} shell");
            (
                format!(
                    "shell for this device was revoked on '{peer}'. Only its owner can restore it, on '{peer}':"
                ),
                Some(cmd),
            )
        }
        Code::CertRevoked => {
            let cmd = format!("tunlion devices restore {me_w}");
            (
                format!(
                    "'{peer}' revoked this device's certificate. Its owner can restore it, on '{peer}':"
                ),
                Some(cmd),
            )
        }
        Code::Ceiling => {
            let cmd = format!("tunlion add --for {me_w} --allow shell");
            (
                format!(
                    "shell is outside this device's invitation ceiling, and a grant cannot widen one. Re-invite it with shell, on '{peer}':"
                ),
                Some(cmd),
            )
        }
        Code::UserDropUnavailable => (
            format!(
                "'{peer}' is set to run shells as a separate account (--shell-user), which needs it to run as root. On '{peer}', restart `tunlion up` as root, or drop --shell-user and accept the risk with --i-know."
            ),
            None,
        ),
    }
}

/// One user-facing explanation: "<verb> refused by 'peer': reason" plus the
/// matching remedy. `as_name` falls back to this device's display name.
pub(crate) fn explain(verb: &str, peer: &str, reason: &str, code: Option<Code>, as_name: Option<&str>) -> String {
    let head = format!("'{peer}' refused {verb}: {reason}");
    let Some(code) = code.or_else(|| code_from_reason(reason)) else {
        return head;
    };
    let fallback = crate::display_name();
    let me = as_name
        .map(str::to_string)
        .or_else(|| name_from_reason(reason))
        .unwrap_or(fallback);
    match remedy(code, peer, &me) {
        (text, Some(cmd)) => format!("{head}\n  {text}\n    {cmd}"),
        (text, None) => format!("{head}\n  {text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Code; 7] = [
        Code::ShellOff,
        Code::TunnelOff,
        Code::NotGranted,
        Code::Revoked,
        Code::CertRevoked,
        Code::Ceiling,
        Code::UserDropUnavailable,
    ];

    #[test]
    fn wire_codes_round_trip() {
        for c in ALL {
            assert_eq!(Code::from_wire(c.as_wire()), Some(c), "{c:?}");
        }
        assert_eq!(Code::from_wire("nonsense"), None);
    }

    /// Every canonical reason maps back to its own code, so a peer whose
    /// plumbing carries only the string still gets the right remedy.
    #[test]
    fn canonical_reasons_map_back_to_their_code() {
        for c in ALL {
            for n in [None, Some("p1-b".to_string())] {
                let r = Refusal::new(c, n.clone());
                assert_eq!(code_from_reason(&r.reason), Some(c), "{c:?} {:?}", r.reason);
                if matches!(c, Code::NotGranted | Code::Revoked) {
                    assert_eq!(name_from_reason(&r.reason), n, "{c:?}");
                }
            }
        }
    }

    /// The bug this module exists for: a device with no grant on a peer that
    /// IS serving must never be told serving is off.
    #[test]
    fn a_missing_grant_is_not_reported_as_serving_off() {
        let r = Refusal::from_shell_gate(false, false, None, Some("p1-b".into()));
        assert_eq!(r.code, Code::NotGranted);
        assert!(!r.reason.contains("serving is off"), "{}", r.reason);
        assert!(r.reason.contains("not granted"), "{}", r.reason);
        let msg = explain("exec", "p1-a", &r.reason, Some(r.code), r.as_name.as_deref());
        assert!(msg.contains("tunlion grant p1-b shell"), "{msg}");
        assert!(!msg.contains("up --shell"), "{msg}");
    }

    #[test]
    fn gate_inputs_classify_precisely() {
        assert_eq!(Refusal::from_shell_gate(true, false, None, None).code, Code::CertRevoked);
        assert_eq!(
            Refusal::from_shell_gate(false, false, Some("device revoked"), None).code,
            Code::CertRevoked
        );
        assert_eq!(
            Refusal::from_shell_gate(false, false, Some(crate::capability::CEILING_REASON), None).code,
            Code::Ceiling
        );
        assert_eq!(Refusal::from_shell_gate(false, true, None, None).code, Code::Revoked);
        assert_eq!(Refusal::from_shell_gate(false, false, None, None).code, Code::NotGranted);
    }

    #[test]
    fn frame_carries_code_and_name_and_reads_back() {
        let r = Refusal::new(Code::NotGranted, Some("laptop".into()));
        let f = r.close_frame(7);
        assert_eq!(f["code"], "not-granted");
        assert_eq!(f["as"], "laptop");
        assert_eq!(from_frame(&f, "err"), (Some(Code::NotGranted), Some("laptop".into())));
        // An older acceptor: only the string. Still classified.
        let old = json!({"type": "l2-close", "sid": 7, "err": crate::capability::SHELL_OFF_REASON});
        assert_eq!(from_frame(&old, "err").0, Some(Code::ShellOff));
    }

    /// Every suggested command is one the CLI ACCEPTS, not merely one with the
    /// right words in it (the `a_suggested_forward_command_parses` precedent).
    #[test]
    fn every_remedy_command_parses() {
        use clap::Parser;
        for c in ALL {
            for me in ["p1-b", "user@p1-b"] {
                if let (_, Some(cmd)) = remedy(c, "p1-a", me) {
                    let argv: Vec<&str> = cmd.split_whitespace().collect();
                    assert!(
                        crate::Cli::try_parse_from(&argv).is_ok(),
                        "remedy for {c:?} does not parse: {cmd}"
                    );
                    assert!(cmd.contains(me), "remedy must name this device as the peer knows it: {cmd}");
                }
            }
        }
    }
}
