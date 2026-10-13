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
    /// The acceptor does not know this device at all: it claimed a pairing
    /// the acceptor no longer holds (forgotten there) or never held. Decided
    /// before any capability question, so it is never reported as a missing
    /// grant or as serving being off.
    Unrecognized,
    /// The invitation that admitted this device carried an end time, and it
    /// has passed. The capability may be inside the ceiling; it simply ended.
    /// The fix is a fresh invitation from the owner, never a grant or a wider
    /// ceiling.
    Expired,
}

/// What the acceptor knows about the invitation that ended, so the initiator
/// can print a re-invite that restores exactly what the device had: its
/// original capabilities and its original lifetime. Carried as additive
/// fields on the refusal frame (`ceiling`, `lifetime`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reinvite {
    pub(crate) ceiling: Vec<String>,
    pub(crate) lifetime: u64,
}

/// A lifetime as an `--expires` value, rounded UP to one unit (an invitation
/// joined a few seconds after it was minted still reads as the "4m" it was
/// minted with) and never above the 30-day maximum `add` accepts. Pure.
pub(crate) fn expires_text(secs: u64) -> String {
    let secs = secs.clamp(1, 30 * 86400);
    if secs >= 86400 {
        format!("{}d", secs.div_ceil(86400))
    } else if secs >= 3600 {
        format!("{}h", secs.div_ceil(3600))
    } else if secs >= 60 {
        format!("{}m", secs.div_ceil(60))
    } else {
        format!("{secs}s")
    }
}

/// The re-invite from a refusal frame, when the acceptor sent one. Pure.
pub(crate) fn reinvite_from_frame(v: &Value) -> Option<Reinvite> {
    let ceiling: Vec<String> = v["ceiling"]
        .as_array()?
        .iter()
        .filter_map(|c| c.as_str())
        // Peer-supplied and printed as a command: capability words only.
        .filter(|c| !c.is_empty() && c.len() <= 32 && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == ':' || ch == '.' || ch == '/'))
        .map(str::to_string)
        .collect();
    let lifetime = v["lifetime"].as_u64()?;
    (!ceiling.is_empty()).then_some(Reinvite { ceiling, lifetime })
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
            Code::Unrecognized => "not-recognized",
            Code::Expired => "expired",
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
            "not-recognized" => Code::Unrecognized,
            "expired" => Code::Expired,
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

/// Canonical human reason for a device the acceptor does not recognize.
pub(crate) const UNRECOGNIZED_REASON: &str =
    "this device is not recognized here: it was forgotten, or was never paired";

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
    /// For an expiry: what to re-invite with.
    pub(crate) reinvite: Option<Reinvite>,
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
            Code::Unrecognized => UNRECOGNIZED_REASON.to_string(),
            // Without the time; `Refusal::expired` names it.
            Code::Expired => format!(
                "{}: the invitation that admitted this device has ended",
                crate::capability::EXPIRED_PREFIX
            ),
        };
        Refusal {
            code,
            reason,
            as_name,
            reinvite: None,
        }
    }

    /// The refusal for a device whose invitation ended at `at`.
    pub(crate) fn expired(at: u64, as_name: Option<String>, reinvite: Option<Reinvite>) -> Refusal {
        Refusal {
            code: Code::Expired,
            reason: crate::capability::expired_reason(at),
            as_name,
            reinvite,
        }
    }

    /// Classify any gate reason (exec, pty, ssh-sign, forward, mount): the
    /// expiry and revocation causes get their own codes, everything else is
    /// left to the caller. Pure.
    pub(crate) fn final_cause(cap_reason: Option<&str>, as_name: Option<String>) -> Option<Refusal> {
        let r = cap_reason?.trim();
        if r.starts_with(crate::capability::EXPIRED_PREFIX) {
            let mut out = match crate::capability::expired_at_from_reason(r) {
                Some(at) => Refusal::expired(at, as_name, None),
                None => Refusal::new(Code::Expired, as_name),
            };
            out.reason = r.to_string();
            return Some(out);
        }
        if r == "device revoked" {
            return Some(Refusal::new(Code::CertRevoked, as_name));
        }
        None
    }

    /// Classify a shell-gate denial. `cap_reason` is the engine's reason when
    /// it named one; `cert_revoked`/`denied` are the gate inputs.
    pub(crate) fn from_shell_gate(
        cert_revoked: bool,
        denied: bool,
        cap_reason: Option<&str>,
        as_name: Option<String>,
    ) -> Refusal {
        if !cert_revoked {
            if let Some(r) = Refusal::final_cause(cap_reason, as_name.clone()) {
                return r;
            }
        }
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

    /// For an expiry, attach the re-invite the owner can run (read from this
    /// device's record of the peer). A no-op for every other cause.
    pub(crate) fn with_reinvite_for(mut self, idev: Option<&[u8; 32]>) -> Refusal {
        if self.code == Code::Expired && self.reinvite.is_none() {
            self.reinvite = idev.and_then(crate::identity_state::reinvite_for);
        }
        self
    }

    /// Add the code and name to an outgoing refusal frame.
    pub(crate) fn annotate(&self, frame: &mut Value) {
        frame["code"] = json!(self.code.as_wire());
        if let Some(n) = &self.as_name {
            frame["as"] = json!(n);
        }
        if let Some(r) = &self.reinvite {
            frame["ceiling"] = json!(r.ceiling);
            frame["lifetime"] = json!(r.lifetime);
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
    // By prefix: older peers send the same cause with a different tail (the
    // retired "run `tunlion up --shell`" advice), and it is the same cause.
    if r.starts_with(crate::capability::SHELL_OFF_PREFIX) {
        return Some(Code::ShellOff);
    }
    if r.starts_with(crate::capability::TUNNEL_OFF_PREFIX) {
        return Some(Code::TunnelOff);
    }
    if r == crate::capability::CEILING_REASON {
        return Some(Code::Ceiling);
    }
    if r.starts_with(crate::capability::EXPIRED_PREFIX) {
        return Some(Code::Expired);
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
    if r == UNRECOGNIZED_REASON {
        return Some(Code::Unrecognized);
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
    remedy_with(code, peer, me, None)
}

/// [`remedy`], with what the acceptor said about an ended invitation.
pub(crate) fn remedy_with(
    code: Code,
    peer: &str,
    me: &str,
    reinvite: Option<&Reinvite>,
) -> (String, Option<String>) {
    let me_w = word(me);
    match code {
        // Not a grant (nothing to grant to an ended principal) and not the
        // ceiling re-enrolment (the ceiling was fine): the same invitation
        // again, with the same capabilities and the same lifetime.
        // ONE remedy for an expiry, whichever verb met it: exec knew the
        // re-invite (ceiling + lifetime) and printed the steps, forward only
        // had the reason string and said "with a fresh invitation". The steps
        // are the same either way; only the add line's --allow/--expires need
        // the acceptor's record, and are left at their defaults without it.
        Code::Expired => (
            format!(
                "the invitation that admitted this device has ended, so '{peer}' refuses everything from it. Only its owner can admit it again:\n    {}",
                reinvite_steps(peer, &me_w, reinvite).join("\n    ")
            ),
            None,
        ),
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
        // Not one command: a grant cannot widen a ceiling, and a joined device
        // refuses a second invitation while it holds the first, so
        // `add --for <me> --allow shell` alone dead-ended on this device. The
        // steps that work are the full re-enrolment, each on the machine that
        // runs it (cli/tests/reenrol-advice-gates.sh follows them).
        Code::Ceiling => (
            format!(
                "shell is outside this device's invitation ceiling, and a grant cannot widen one. \
                 To give it shell, enrol it again with shell in its invitation:\n    \
                 {}",
                ceiling_steps(peer, &me_w).join("\n    ")
            ),
            None,
        ),
        Code::UserDropUnavailable => (
            format!(
                "'{peer}' is set to run shells as a separate account (--shell-user), which needs it to run as root. On '{peer}', restart `tunlion up` as root, or drop --shell-user and accept the risk with --i-know."
            ),
            None,
        ),
        // No grant can fix this and no command run here can either: the
        // acceptor holds no record of this device, so only its owner can let
        // it back in, by pairing or enrolling it again.
        Code::Unrecognized => (
            format!(
                "'{peer}' holds no record of this device (it was forgotten there), so no grant applies. Only the owner of '{peer}' can let it back in, by pairing or enrolling it again."
            ),
            None,
        ),
    }
}

/// The re-enrolment that widens this device's ceiling, as `on X:  command`
/// lines in the order they must run. `--allow` replaces the default ceiling,
/// so the defaults (transfer, mount) are carried over.
///
/// Every command runs EXACTLY as printed from a script: the confirmations
/// carry `-y`/`--yes` (a pipe has no terminal to answer them, and the old
/// `add` and `down` lines failed there), and the last step starts the daemon
/// again, without which the next `exec` waited 45 s for a device that was
/// not listening. The one line that is not a command (moving the invitation)
/// is in parentheses. cli/tests/reenrol-advice-gates.sh runs these lines.
pub(crate) fn ceiling_steps(peer: &str, me: &str) -> Vec<String> {
    let invite = format!("{me}-invite.txt");
    let owner = format!("on '{peer}':");
    let here = "on this device:".to_string();
    let w = owner.len().max(here.len());
    let pad = " ".repeat(w);
    vec![
        format!("{owner:<w$}  tunlion devices forget {me} -y"),
        format!("{pad}  tunlion add --for {me} --allow transfer,mount,shell --out {invite} --yes"),
        format!("{pad}  (copy {invite} to this device)"),
        format!("{here:<w$}  tunlion down -y"),
        format!("{pad}  tunlion reset -y"),
        format!("{pad}  tunlion join --invite-file {invite} --name {me}"),
        format!("{pad}  tunlion up --detach"),
    ]
}

/// The steps that admit an expired device again, each on the machine that
/// runs it, preserving its capabilities and its lifetime. The forget frees the
/// name; the device must reset, because a joined device refuses a second
/// invitation while it holds the first.
/// Why the reset: `join` refuses on a device that still holds a device
/// certificate (identity_flow::join_cmd), and an expired guest still holds
/// its old one. Without the acceptor's record of the invitation (`r` None)
/// the add line keeps its defaults rather than guessing the capabilities.
pub(crate) fn reinvite_steps(peer: &str, me: &str, r: Option<&Reinvite>) -> Vec<String> {
    let invite = format!("{me}-invite.txt");
    let owner = format!("on '{peer}':");
    let here = "on this device:".to_string();
    let w = owner.len().max(here.len());
    let pad = " ".repeat(w);
    let same = r
        .map(|r| format!(" --allow {} --expires {}", r.ceiling.join(","), expires_text(r.lifetime)))
        .unwrap_or_default();
    vec![
        format!("{owner:<w$}  tunlion devices forget {me} -y"),
        format!("{pad}  tunlion add --for {me}{same} --out {invite} --yes"),
        format!("{pad}  (copy {invite} to this device)"),
        format!("{here:<w$}  tunlion down -y"),
        format!("{pad}  tunlion reset -y"),
        format!("{pad}  tunlion join --invite-file {invite} --name {me}"),
        format!("{pad}  tunlion up --detach"),
    ]
}

/// [`explain`] from a whole refusal frame: the code, the acceptor's name for
/// us, and (for an expiry) the re-invite it sent.
pub(crate) fn explain_frame(verb: &str, peer: &str, v: &Value, reason_key: &str) -> String {
    let reason = v[reason_key].as_str().unwrap_or("closed");
    let (code, as_name) = from_frame(v, reason_key);
    explain_with(verb, peer, reason, code, as_name.as_deref(), reinvite_from_frame(v).as_ref())
}

/// One user-facing explanation: "<verb> refused by 'peer': reason" plus the
/// matching remedy. `as_name` falls back to this device's display name.
pub(crate) fn explain(verb: &str, peer: &str, reason: &str, code: Option<Code>, as_name: Option<&str>) -> String {
    explain_with(verb, peer, reason, code, as_name, None)
}

pub(crate) fn explain_with(
    verb: &str,
    peer: &str,
    reason: &str,
    code: Option<Code>,
    as_name: Option<&str>,
    reinvite: Option<&Reinvite>,
) -> String {
    let Some(code) = code.or_else(|| code_from_reason(reason)) else {
        return format!("'{peer}' refused {verb}: {reason}");
    };
    // An older peer's "serving is off" carried its own (wrong) command, which
    // would sit above the right one; say the cause in this build's words.
    let reason = match code {
        Code::ShellOff | Code::TunnelOff => Refusal::new(code, None).reason,
        _ => reason.to_string(),
    };
    let head = format!("'{peer}' refused {verb}: {reason}");
    let fallback = crate::display_name();
    let me = as_name
        .map(str::to_string)
        .or_else(|| name_from_reason(&reason))
        .unwrap_or(fallback);
    match remedy_with(code, peer, &me, reinvite) {
        (text, Some(cmd)) => format!("{head}\n  {text}\n    {cmd}"),
        (text, None) => format!("{head}\n  {text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Code; 9] = [
        Code::ShellOff,
        Code::TunnelOff,
        Code::NotGranted,
        Code::Revoked,
        Code::CertRevoked,
        Code::Ceiling,
        Code::UserDropUnavailable,
        Code::Unrecognized,
        Code::Expired,
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

    /// E3: "refused exec: shell serving is off there; run `tunlion up --shell`
    /// on that device" followed by "grant this device: tunlion grant alpha
    /// shell" was two contradictory fixes, and the first one refuses without
    /// --i-know. Serving is off exactly when no device holds a grant, so the
    /// grant is the one fix, and the reason says why rather than prescribing
    /// a different command.
    #[test]
    fn serving_off_says_why_and_gives_only_the_grant() {
        for (code, reason) in [
            (Code::ShellOff, crate::capability::SHELL_OFF_REASON),
            (Code::TunnelOff, crate::capability::TUNNEL_OFF_REASON),
        ] {
            assert!(!reason.contains("up --shell"), "{reason}");
            assert!(!reason.contains("TUNLION_L2"), "{reason}");
            let msg = explain("exec", "beta", reason, Some(code), Some("alpha"));
            assert!(!msg.contains("up --shell"), "{msg}");
            assert_eq!(msg.matches("tunlion ").count(), 1, "{msg}");
            assert!(msg.contains("tunlion grant alpha shell"), "{msg}");
        }
        // What older peers send is still the same cause.
        for legacy in [
            "shell serving is off there; run `tunlion up --shell` on that device",
            "tunnelling is off there; run `tunlion up --shell` (or set TUNLION_L2=1) on that device",
        ] {
            assert!(code_from_reason(legacy).is_some(), "{legacy}");
            let msg = explain("exec", "beta", legacy, None, Some("alpha"));
            assert!(msg.contains("tunlion grant alpha shell"), "{msg}");
            assert!(!msg.contains("up --shell"), "{msg}");
        }
    }

    /// The ceiling remedy is a sequence, and every step in it is a command the
    /// CLI accepts, in the order that works: the old single step (`add --for
    /// <me> --allow shell`) produced an invitation the joined device refused.
    #[test]
    fn the_ceiling_remedy_is_the_full_reenrolment_and_every_step_parses() {
        use clap::Parser;
        let steps = ceiling_steps("p1-a", "p1-b");
        let cmds: Vec<String> = steps
            .iter()
            .filter_map(|l| l.find("tunlion ").map(|i| l[i..].to_string()))
            .collect();
        assert_eq!(
            cmds,
            [
                "tunlion devices forget p1-b -y",
                "tunlion add --for p1-b --allow transfer,mount,shell --out p1-b-invite.txt --yes",
                "tunlion down -y",
                "tunlion reset -y",
                "tunlion join --invite-file p1-b-invite.txt --name p1-b",
                "tunlion up --detach",
            ]
        );
        // Every line is a command or a parenthesised instruction: nothing a
        // script would run by mistake.
        for l in &steps {
            assert!(l.contains("tunlion ") || l.trim_start().starts_with('(') || l.contains("  ("), "{l}");
        }
        for cmd in &cmds {
            let argv: Vec<&str> = cmd.split_whitespace().collect();
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "step does not parse: {cmd}");
        }
        assert!(steps[0].contains("on 'p1-a':") && steps[3].contains("on this device:"));
        let msg = explain("exec", "p1-a", crate::capability::CEILING_REASON, Some(Code::Ceiling), Some("p1-b"));
        for cmd in &cmds {
            assert!(msg.contains(cmd.as_str()), "{msg}");
        }
    }

    /// An expired device is told it EXPIRED and when, never that the
    /// capability is outside its ceiling, and its remedy is the same
    /// invitation again: the original caps (no mount added) and --expires.
    #[test]
    fn an_expiry_names_the_time_and_reinvites_with_the_same_caps() {
        use clap::Parser;
        let at = 1_760_384_363; // 2025-10-13 19:39:23 UTC
        let r = Refusal::from_shell_gate(
            false,
            false,
            Some(&crate::capability::expired_reason(at)),
            Some("guest-b".into()),
        );
        assert_eq!(r.code, Code::Expired);
        assert!(r.reason.starts_with("access expired at 2025-10-13 19:39:23 UTC"), "{}", r.reason);
        assert!(!r.reason.contains("ceiling"), "{}", r.reason);
        assert_eq!(crate::capability::expired_at_from_reason(&r.reason), Some(at));
        let inv = Reinvite { ceiling: vec!["transfer".into(), "shell".into()], lifetime: 240 };
        let mut f = Refusal { reinvite: Some(inv.clone()), ..r }.close_frame(9);
        assert_eq!(f["code"], "expired");
        assert_eq!(reinvite_from_frame(&f), Some(inv));
        let msg = explain_frame("exec", "owner-a", &f, "err");
        assert!(msg.contains("expired at"), "{msg}");
        assert!(msg.contains("--allow transfer,shell --expires 4m"), "{msg}");
        assert!(!msg.contains("mount"), "the re-invite must not add mount: {msg}");
        for cmd in msg.lines().filter_map(|l| l.find("tunlion ").map(|i| l[i..].to_string())) {
            let argv: Vec<&str> = cmd.split_whitespace().collect();
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "step does not parse: {cmd}");
        }
        // A hostile ceiling never reaches the printed command.
        f["ceiling"] = serde_json::json!(["shell; rm -rf /"]);
        assert_eq!(reinvite_from_frame(&f), None);
    }

    /// RC lab item 9: the same expiry read "forget + add + reset" from exec and
    /// "with a fresh invitation" from forward (which carries no re-invite).
    /// Both now give the same steps; only the add line's flags differ.
    #[test]
    fn an_expiry_has_one_remedy_with_or_without_the_reinvite() {
        use clap::Parser;
        let reason = crate::capability::expired_reason(1_760_384_363);
        let with = explain_with("exec", "owner-a", &reason, None, Some("guest-b"),
            Some(&Reinvite { ceiling: vec!["transfer".into()], lifetime: 240 }));
        let without = explain("forward", "owner-a", &reason, None, Some("guest-b"));
        let cmds = |m: &str| -> Vec<String> {
            m.lines().filter_map(|l| l.find("tunlion ").map(|i| l[i..].to_string())).collect()
        };
        let (a, b) = (cmds(&with), cmds(&without));
        assert_eq!(a.len(), 6, "{with}");
        assert_eq!(b.len(), 6, "{without}");
        for (x, y) in a.iter().zip(&b) {
            if x.starts_with("tunlion add ") {
                assert!(x.contains("--allow transfer --expires 4m"), "{x}");
                assert_eq!(y, "tunlion add --for guest-b --out guest-b-invite.txt --yes");
            } else {
                assert_eq!(x, y);
            }
            let argv: Vec<&str> = y.split_whitespace().collect();
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "step does not parse: {y}");
        }
        assert!(!without.contains("fresh invitation."), "{without}");
    }

    #[test]
    fn expires_text_rounds_up_and_caps_at_thirty_days() {
        assert_eq!(expires_text(20), "20s");
        assert_eq!(expires_text(223), "4m");
        assert_eq!(expires_text(3600), "1h");
        assert_eq!(expires_text(30 * 86400 - 5), "30d");
        assert_eq!(expires_text(90 * 86400), "30d");
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
