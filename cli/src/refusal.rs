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

use serde_json::Value;

// The WIRE vocabulary moved to `filament_peerloop::refusal` with the mount
// endpoint that builds refusals from the library. Every CLI call site keeps its
// old path through this re-export; the remedy/explain text below stays here,
// because it names commands only the CLI accepts.
pub(crate) use filament_peerloop::refusal::{
    Code, Refusal, Reinvite, UNRECOGNIZED_REASON, code_from_reason, expires_text, from_frame,
    name_from_reason, reinvite_from_frame, reinvite_from_reason, reinvite_suffix,
};

/// For an expiry, attach the re-invite the owner can run (read from this
/// device's record of the peer). A no-op for every other cause. This stayed in
/// the CLI because it reads `identity_state::reinvite_for`, a host store.
pub(crate) fn with_reinvite_for(mut r: Refusal, idev: Option<&[u8; 32]>) -> Refusal {
    if r.code == Code::Expired && r.reinvite.is_none() {
        r.reinvite = idev.and_then(crate::identity_state::reinvite_for);
    }
    r
}

/// Quote a device name for a copy-pasteable command when it needs it.
/// A name as one command word. Moved to `filament-peerloop::consent`; every
/// caller in this module keeps the same rule.
pub(crate) use filament_peerloop::consent::word;

/// The remedy for a refusal by `peer`: (what to do, the exact command, if any).
/// The command is always one the CLI accepts (see the parse test below).
/// `me` is the name `peer` knows this device by (the acceptor's `as`), else
/// this device's own display name, which is what a pairing files it under.
#[cfg(test)]
pub(crate) fn remedy(code: Code, peer: &str, me: &str) -> (String, Option<String>) {
    remedy_with(code, peer, me, None)
}

/// [`remedy`], with the re-invite read from the refusal's reason string: the
/// one form every path has, so every path gives the same remedy.
pub(crate) fn remedy_from_reason(code: Code, peer: &str, me: &str, reason: &str) -> (String, Option<String>) {
    remedy_with(code, peer, me, reinvite_from_reason(reason).as_ref())
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
            let cmd = format!("tunlion promote {me_w}");
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
    let (mw, iw) = (word(me), word(&invite));
    let owner = format!("on '{peer}':");
    let here = "on this device:".to_string();
    let w = owner.len().max(here.len());
    let pad = " ".repeat(w);
    vec![
        format!("{owner:<w$}  tunlion devices forget {mw} -y"),
        format!("{pad}  tunlion add --for {mw} --allow transfer,mount,shell --out {iw} --yes"),
        format!("{pad}  (copy {invite} to this device)"),
        format!("{here:<w$}  tunlion down -y"),
        format!("{pad}  tunlion reset -y"),
        format!("{pad}  tunlion join --invite-file {iw} --name {mw}"),
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
    let (mw, iw) = (word(me), word(&invite));
    let owner = format!("on '{peer}':");
    let here = "on this device:".to_string();
    let w = owner.len().max(here.len());
    let pad = " ".repeat(w);
    let same = r
        .map(|r| format!(" --allow {} --expires {}", r.ceiling.join(","), expires_text(r.lifetime)))
        .unwrap_or_default();
    vec![
        format!("{owner:<w$}  tunlion devices forget {mw} -y"),
        format!("{pad}  tunlion add --for {mw}{same} --out {iw} --yes"),
        format!("{pad}  (copy {invite} to this device)"),
        format!("{here:<w$}  tunlion down -y"),
        format!("{pad}  tunlion reset -y"),
        format!("{pad}  tunlion join --invite-file {iw} --name {mw}"),
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
    // The frame's fields when it had them, else what the reason carries:
    // the same acceptor record either way.
    let reinvite = reinvite.cloned().or_else(|| reinvite_from_reason(&reason));
    match remedy_with(code, peer, &me, reinvite.as_ref()) {
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
    fn a_missing_grant_is_not_reported_as_serving_off() {
        let r = Refusal::from_shell_gate(false, false, false, None, Some("p1-b".into()));
        assert_eq!(r.code, Code::NotGranted);
        assert!(!r.reason.contains("serving is off"), "{}", r.reason);
        assert!(r.reason.contains("not granted"), "{}", r.reason);
        let msg = explain("exec", "p1-a", &r.reason, Some(r.code), r.as_name.as_deref());
        assert!(msg.contains("tunlion grant p1-b shell"), "{msg}");
        assert!(!msg.contains("up --shell"), "{msg}");
    }

    #[test]
    fn gate_inputs_classify_precisely() {
        assert_eq!(Refusal::from_shell_gate(false, true, false, None, None).code, Code::CertRevoked);
        assert_eq!(
            Refusal::from_shell_gate(false, false, false, Some("device revoked"), None).code,
            Code::CertRevoked
        );
        assert_eq!(
            Refusal::from_shell_gate(false, false, false, Some(crate::capability::CEILING_REASON), None).code,
            Code::Ceiling
        );
        assert_eq!(Refusal::from_shell_gate(false, false, true, None, None).code, Code::Revoked);
        assert_eq!(Refusal::from_shell_gate(false, false, false, None, None).code, Code::NotGranted);
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

    /// Lab pass: exec's expiry refusal said `add --for guest --allow
    /// transfer,shell --expires 2m ...` while send's said `add --for guest
    /// --out guest-invite.txt --yes`. The reason string now carries the
    /// re-invite, so a path holding only the reason (send's file-decline,
    /// forward, mount) prints exactly what exec prints from the frame.
    #[test]
    fn every_expiry_path_builds_the_same_remedy_from_the_reason() {
        let inv = Reinvite { ceiling: vec!["transfer".into(), "shell".into()], lifetime: 120 };
        let reason = format!("{}{}", crate::capability::expired_reason(1_760_384_363), reinvite_suffix(&inv));
        assert_eq!(reinvite_from_reason(&reason), Some(inv.clone()));
        assert_eq!(code_from_reason(&reason), Some(Code::Expired));
        assert_eq!(crate::capability::expired_at_from_reason(&reason), Some(1_760_384_363));
        // exec: the frame's fields. send/forward/mount: the reason alone.
        let mut f = Refusal::expired(1_760_384_363, Some("guest".into()), Some(inv.clone())).close_frame(3);
        f["err"] = serde_json::json!(reason.clone());
        let by_frame = explain_frame("exec", "owner", &f, "err");
        let by_reason = explain("send", "owner", &reason, None, Some("guest"));
        let adds = |m: &str| m.lines().find(|l| l.contains("tunlion add ")).map(|l| l.trim().to_string());
        assert_eq!(adds(&by_frame), adds(&by_reason), "{by_frame}\n---\n{by_reason}");
        assert!(adds(&by_reason).unwrap().contains("--allow transfer,shell --expires 2m"), "{by_reason}");
        let (text, _) = remedy_from_reason(Code::Expired, "owner", "guest", &reason);
        assert!(text.contains("--allow transfer,shell --expires 2m"), "{text}");
        // Hostile or malformed suffixes are no re-invite, never a fragment.
        assert_eq!(reinvite_from_reason("access expired at x (it allowed shell; rm -rf / for 2m)"), None);
        assert_eq!(reinvite_from_reason("access expired at x (it allowed shell for soon)"), None);
        assert_eq!(reinvite_from_reason(&crate::capability::expired_reason(1)), None);
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
