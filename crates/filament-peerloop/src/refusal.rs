//! Why a peer said no to a shell-class open: the wire vocabulary.
//!
//! An acceptor knows the precise cause of a refusal (serving is off, this device
//! holds no grant there, the grant was revoked, the certificate was revoked, the
//! invitation ceiling excludes it, the configured user drop cannot run), and it
//! knows the name it has filed the initiator under. The initiator knows neither,
//! so the refusal carries a reason CODE (`code`) and the acceptor's name for the
//! initiator (`as`) next to the human `err`, and the initiator maps the code to
//! exactly one remedy. Older peers send only `err`; for those the code is
//! recovered from the canonical reason strings below, which are the only strings
//! an acceptor of this build produces for these causes.
//!
//! Wire: additive fields on `l2-close` and `shell-bootstrap-deny`. An older
//! initiator ignores them and still prints `err`.
//!
//! The moved part is the WIRE vocabulary and the pure reason strings/parsers:
//! that is what the mount endpoint and the other serving loops need to build a
//! refusal without naming a terminal. What a PERSON should do about it (the
//! `tunlion grant ...` remedy text, the re-enrolment steps, the clap parse
//! tests) stays in the CLI, where the commands live.

use filament_cap::capability::REVOKED_REASON;
use serde_json::{Value, json};

// ------------------------------------------------------- canonical reasons --

/// Shell serving is OFF on the acceptor: it was started without `--shell` and
/// no device holds a shell grant there. The fix is the grant (serving turns on
/// live when the first one lands); the old wording sent people to
/// `tunlion up --shell`, which refuses without `--i-know` and was never needed.
/// Older peers still send that wording, so recognise the stable prefix
/// ([`SHELL_OFF_PREFIX`]), never the whole sentence.
pub const SHELL_OFF_REASON: &str =
    "shell serving is off there (no device holds a shell grant on it)";
/// The part of [`SHELL_OFF_REASON`] every build has sent.
pub const SHELL_OFF_PREFIX: &str = "shell serving is off there";

/// The L2 tunnel acceptor is OFF on the peer entirely, so `forward`, `netcat`
/// and the ssh bootstrap have nothing to open against. Like SHELL_OFF_REASON
/// this is not a capability problem and a grant does not help.
pub const TUNNEL_OFF_REASON: &str =
    "tunnelling is off there (no device holds a shell grant on it, and forwarding rides that grant)";
/// The part of [`TUNNEL_OFF_REASON`] every build has sent.
pub const TUNNEL_OFF_PREFIX: &str = "tunnelling is off there";

/// The peer's ENROLMENT CEILING excludes this capability. A grant cannot widen a
/// ceiling, so any hint built on this reason must not prescribe one: the fix is a
/// fresh invitation that includes the capability.
pub const CEILING_REASON: &str = "this capability is outside the device's invitation ceiling";

/// The device's access ENDED: the invitation that admitted it carried an end
/// time and that time has passed. Distinct from the ceiling on purpose: the
/// capability may well be inside the ceiling, it simply expired, and the fix
/// is a fresh invitation, not a wider one. Every reason built on this starts
/// with [`EXPIRED_PREFIX`], which is what an initiator recognises.
pub const EXPIRED_PREFIX: &str = "access expired";

/// The canonical expiry reason, naming WHEN in UTC to the second.
pub fn expired_reason(at: u64) -> String {
    let when = chrono::DateTime::from_timestamp(at as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| at.to_string());
    format!("{EXPIRED_PREFIX} at {when}: the invitation that admitted this device has ended")
}

/// The expiry time named in an [`expired_reason`], when it parses. Pure.
pub fn expired_at_from_reason(reason: &str) -> Option<u64> {
    let rest = reason.trim().strip_prefix(EXPIRED_PREFIX)?.trim_start().strip_prefix("at ")?;
    let stamp = rest.get(..23)?; // "YYYY-MM-DD HH:MM:SS UTC"
    chrono::NaiveDateTime::parse_from_str(stamp.trim_end_matches(" UTC"), "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc().timestamp().max(0) as u64)
}

// ------------------------------------------------------------ wire types --

/// The precise cause of a shell-class refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
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
pub struct Reinvite {
    pub ceiling: Vec<String>,
    pub lifetime: u64,
}

/// A lifetime as an `--expires` value, rounded UP to one unit (an invitation
/// joined a few seconds after it was minted still reads as the "4m" it was
/// minted with) and never above the 30-day maximum `add` accepts. Pure.
///
/// Never in seconds: an invitation's expiry is carried in whole minutes
/// (`expires_min` in the token), and the lifetime here is measured from when
/// the device JOINED, so anything under a minute is the join delay eating into
/// a "1m" invitation. It used to be suggested back as `--expires 51s`.
pub fn expires_text(secs: u64) -> String {
    let secs = secs.clamp(1, 30 * 86400);
    if secs >= 86400 {
        format!("{}d", secs.div_ceil(86400))
    } else if secs >= 3600 {
        format!("{}h", secs.div_ceil(3600))
    } else {
        format!("{}m", secs.div_ceil(60))
    }
}

/// What an expiry reason carries about the invitation, appended by the
/// acceptor (`capability::expired_reason_for`): ` (it allowed transfer,shell
/// for 4m)`. Read back by [`reinvite_from_reason`]. Pure.
pub fn reinvite_suffix(r: &Reinvite) -> String {
    format!(" (it allowed {} for {})", r.ceiling.join(","), expires_text(r.lifetime))
}

/// A capability word that may be printed inside a command. Peer-supplied.
fn cap_word_ok(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 32
        && c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == ':' || ch == '.' || ch == '/')
}

/// An [`expires_text`] value back to seconds. Pure.
fn expires_secs(t: &str) -> Option<u64> {
    let unit = t.chars().last()?;
    let n: u64 = t[..t.len() - unit.len_utf8()].parse().ok()?;
    let mul = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    (n > 0).then(|| n.saturating_mul(mul))
}

/// The re-invite an expiry REASON carries ([`reinvite_suffix`]), so a path
/// that only has the reason string (a warm-link refusal, a mount error, a
/// file-decline) builds the same remedy as one that got the frame fields.
/// Pure; anything malformed is no re-invite, never a command fragment.
pub fn reinvite_from_reason(reason: &str) -> Option<Reinvite> {
    let start = reason.rfind(" (it allowed ")? + " (it allowed ".len();
    let body = reason[start..].strip_suffix(')')?;
    let (caps, life) = body.rsplit_once(" for ")?;
    let ceiling: Vec<String> = caps.split(',').map(str::to_string).collect();
    if ceiling.iter().any(|c| !cap_word_ok(c)) {
        return None;
    }
    Some(Reinvite { ceiling, lifetime: expires_secs(life)? })
}

/// The re-invite from a refusal frame, when the acceptor sent one. Pure.
pub fn reinvite_from_frame(v: &Value) -> Option<Reinvite> {
    let ceiling: Vec<String> = v["ceiling"]
        .as_array()?
        .iter()
        .filter_map(|c| c.as_str())
        // Peer-supplied and printed as a command: capability words only.
        .filter(|c| cap_word_ok(c))
        .map(str::to_string)
        .collect();
    let lifetime = v["lifetime"].as_u64()?;
    (!ceiling.is_empty()).then_some(Reinvite { ceiling, lifetime })
}

impl Code {
    pub fn as_wire(self) -> &'static str {
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

    pub fn from_wire(s: &str) -> Option<Code> {
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
pub fn not_granted_reason(as_name: Option<&str>) -> String {
    match as_name {
        Some(n) => format!("shell not granted to '{n}' here"),
        None => "shell capability not granted".to_string(),
    }
}

/// Canonical human reason for an owner-revoked shell grant.
pub fn revoked_reason(as_name: Option<&str>) -> String {
    match as_name {
        Some(n) => format!("shell revoked for '{n}' here"),
        None => "shell revoked for this device here".to_string(),
    }
}

/// Canonical human reason for a device the acceptor does not recognize.
pub const UNRECOGNIZED_REASON: &str =
    "this device is not recognized here: it was forgotten, or was never paired";

/// Canonical human reason for a user drop the acceptor cannot perform.
pub const USER_DROP_REASON: &str =
    "this device is set to run shells as another account (--shell-user) but is not running as root, so it cannot switch to it";

/// A refusal as the acceptor decided it.
#[derive(Clone, Debug, PartialEq)]
pub struct Refusal {
    pub code: Code,
    pub reason: String,
    /// The acceptor's petname for the initiator, when proven.
    pub as_name: Option<String>,
    /// For an expiry: what to re-invite with.
    pub reinvite: Option<Reinvite>,
}

impl Refusal {
    pub fn new(code: Code, as_name: Option<String>) -> Refusal {
        let reason = match code {
            Code::ShellOff => SHELL_OFF_REASON.to_string(),
            Code::TunnelOff => TUNNEL_OFF_REASON.to_string(),
            Code::NotGranted => not_granted_reason(as_name.as_deref()),
            Code::Revoked => revoked_reason(as_name.as_deref()),
            Code::CertRevoked => "device revoked".to_string(),
            Code::Ceiling => CEILING_REASON.to_string(),
            Code::UserDropUnavailable => USER_DROP_REASON.to_string(),
            Code::Unrecognized => UNRECOGNIZED_REASON.to_string(),
            // Without the time; `Refusal::expired` names it.
            Code::Expired => format!(
                "{}: the invitation that admitted this device has ended",
                EXPIRED_PREFIX
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
    pub fn expired(at: u64, as_name: Option<String>, reinvite: Option<Reinvite>) -> Refusal {
        Refusal {
            code: Code::Expired,
            reason: expired_reason(at),
            as_name,
            reinvite,
        }
    }

    /// Classify any gate reason (exec, pty, ssh-sign, forward, mount): the
    /// expiry and revocation causes get their own codes, everything else is
    /// left to the caller. Pure.
    pub fn final_cause(cap_reason: Option<&str>, as_name: Option<String>) -> Option<Refusal> {
        let r = cap_reason?.trim();
        if r.starts_with(EXPIRED_PREFIX) {
            let mut out = match expired_at_from_reason(r) {
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
    pub fn from_shell_gate(
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
        } else if cap_reason == Some(CEILING_REASON) {
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
    pub fn annotate(&self, frame: &mut Value) {
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
    pub fn close_frame(&self, sid: u32) -> Value {
        let mut f = json!({ "type": "l2-close", "sid": sid, "err": self.reason });
        self.annotate(&mut f);
        f
    }
}

/// Recover the code from a reason string alone (older peers, and paths whose
/// plumbing carries only the string).
pub fn code_from_reason(reason: &str) -> Option<Code> {
    let r = reason.trim();
    // By prefix: older peers send the same cause with a different tail (the
    // retired "run `tunlion up --shell`" advice), and it is the same cause.
    if r.starts_with(SHELL_OFF_PREFIX) {
        return Some(Code::ShellOff);
    }
    if r.starts_with(TUNNEL_OFF_PREFIX) {
        return Some(Code::TunnelOff);
    }
    if r == CEILING_REASON {
        return Some(Code::Ceiling);
    }
    if r.starts_with(EXPIRED_PREFIX) {
        return Some(Code::Expired);
    }
    if r.starts_with("shell revoked for") {
        return Some(Code::Revoked);
    }
    // REVOKED_REASON is the mid-session close, sent for a revoked certificate
    // as well as a withdrawn grant; the restore remedy is the one the shell
    // path has always given for it.
    if r == "device revoked" || r == REVOKED_REASON {
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
pub fn name_from_reason(reason: &str) -> Option<String> {
    let start = reason.find('\'')? + 1;
    let len = reason[start..].find('\'')?;
    let n = &reason[start..start + len];
    (!n.is_empty()).then(|| n.to_string())
}

/// The code and name from a refusal frame, falling back to its reason string.
pub fn from_frame(v: &Value, reason_key: &str) -> (Option<Code>, Option<String>) {
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

    #[test]
    fn frame_carries_code_and_name_and_reads_back() {
        let r = Refusal::new(Code::NotGranted, Some("laptop".into()));
        let f = r.close_frame(7);
        assert_eq!(f["code"], "not-granted");
        assert_eq!(f["as"], "laptop");
        assert_eq!(from_frame(&f, "err"), (Some(Code::NotGranted), Some("laptop".into())));
        // An older acceptor: only the string. Still classified.
        let old = json!({"type": "l2-close", "sid": 7, "err": SHELL_OFF_REASON});
        assert_eq!(from_frame(&old, "err").0, Some(Code::ShellOff));
    }

    #[test]
    fn expires_text_rounds_up_and_caps_at_thirty_days() {
        // A "1m" invitation joined 9 s after it was minted is suggested as 1m,
        // not 51s: invitation expiry is whole minutes.
        assert_eq!(expires_text(51), "1m");
        assert_eq!(expires_text(20), "1m");
        assert_eq!(expires_text(223), "4m");
        assert_eq!(expires_text(3600), "1h");
        assert_eq!(expires_text(30 * 86400 - 5), "30d");
        assert_eq!(expires_text(90 * 86400), "30d");
    }

    /// An expired device is told it EXPIRED and when, never that the
    /// capability is outside its ceiling.
    #[test]
    fn an_expiry_names_the_time_and_reinvite_round_trips() {
        let at = 1_760_384_363; // 2025-10-13 19:39:23 UTC
        let r = Refusal::from_shell_gate(
            false,
            false,
            Some(&expired_reason(at)),
            Some("guest-b".into()),
        );
        assert_eq!(r.code, Code::Expired);
        assert!(r.reason.starts_with("access expired at 2025-10-13 19:39:23 UTC"), "{}", r.reason);
        assert!(!r.reason.contains("ceiling"), "{}", r.reason);
        assert_eq!(expired_at_from_reason(&r.reason), Some(at));
        let inv = Reinvite { ceiling: vec!["transfer".into(), "shell".into()], lifetime: 240 };
        let mut f = Refusal { reinvite: Some(inv.clone()), ..r }.close_frame(9);
        assert_eq!(f["code"], "expired");
        assert_eq!(reinvite_from_frame(&f), Some(inv));
        // A hostile ceiling never survives the parse.
        f["ceiling"] = serde_json::json!(["shell; rm -rf /"]);
        assert_eq!(reinvite_from_frame(&f), None);
    }
}
