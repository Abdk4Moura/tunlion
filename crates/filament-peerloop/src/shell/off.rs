//! The refusal for a shell-class open while serving is OFF here.
//!
//! Moved out of `cli::recv_cmd` so the admission endpoint can own the first
//! branch of every open without the CLI. `off` is [`Code::ShellOff`] or
//! [`Code::TunnelOff`]; [`Code::ShellOff`] asks the owner once for a proven
//! device, a tunnel-off and a ceiling refusal do not.
//!
//! Nothing here reads a setting, a file, the clock or the environment: the
//! ceiling and the consent queue are host methods, the verified name is the
//! link's, and the refusal vocabulary is [`crate::refusal`].

use crate::conn::Conn;
use crate::refusal::{Code, Refusal};
use filament_cap::capability::CAP_SHELL;

/// Does an enrolment ceiling EXCLUDE `capability`?
///
/// A `None` ceiling means the device is not delegated (or not known), so it
/// has no ceiling to exclude anything and this answers false. This is the
/// one-line containment the CLI's `pair_cmd::grant_vs_ceiling` expresses as
/// `OutsideCeiling`; `cli/src/pair_cmd.rs` pins the two together over `None`,
/// covered and outside ceilings so they cannot drift.
pub fn ceiling_excludes(ceiling: Option<&[String]>, capability: &str) -> bool {
    ceiling.is_some_and(|c| !c.iter().any(|x| x == capability))
}

/// The refusal for a shell-class open while serving is OFF here (`off` is
/// ShellOff or TunnelOff). Its remedy is a grant, which is wrong for a
/// delegated device whose invitation ceiling excludes shell: `grant` refuses
/// exactly that, so the device was handed a command that would fail. Such a
/// device gets the ceiling refusal instead, whose remedy is the re-enrolment.
pub fn serving_off_refusal(conn: &Conn, pid: &str, off: Code) -> Refusal {
    let who = conn.link(pid).and_then(|l| l.verified_name.clone());
    let outside = who
        .as_deref()
        .and_then(|n| conn.host.principal_ceiling_for(n))
        .is_some_and(|c| ceiling_excludes(Some(c.as_slice()), CAP_SHELL));
    let code = if outside { Code::Ceiling } else { off };
    // A proven device asking for a shell on a machine that serves none is
    // exactly what the owner's Asks list is for. Only the gate path used to
    // record it, and that path is not reached while serving is off (plain
    // `tunlion up`, the default), so the ask was refused and forgotten: the
    // owner never saw it (launch matrix D06).
    if let Some(peer) = serving_off_ask(&code, who.as_deref()) {
        conn.host.enqueue_request_if_requestable(peer, "shell");
    }
    Refusal::new(code, who)
}

/// The device whose refused shell open becomes an ask, if any. Pure. Only a
/// proven device, and only when granting could change the answer: a ceiling
/// refusal cannot be lifted by a grant, so it asks nothing.
pub fn serving_off_ask<'a>(code: &Code, who: Option<&'a str>) -> Option<&'a str> {
    match code {
        Code::ShellOff => who.filter(|w| !w.is_empty()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ceiling_excludes, serving_off_ask};
    use crate::refusal::Code;

    #[test]
    fn a_proven_device_refused_while_serving_is_off_becomes_an_ask() {
        assert_eq!(
            serving_off_ask(&Code::ShellOff, Some("dcode")),
            Some("dcode")
        );
        // Unproven: nobody to ask on behalf of.
        assert_eq!(serving_off_ask(&Code::ShellOff, None), None);
        // A ceiling refusal cannot be granted away, so it is not an ask.
        assert_eq!(serving_off_ask(&Code::Ceiling, Some("dinv")), None);
        assert_eq!(serving_off_ask(&Code::ShellOff, Some("")), None);
    }

    #[test]
    fn ceil_excludes_only_a_delegated_ceiling_without_the_capability() {
        // Not delegated: no ceiling, nothing to exclude.
        assert!(!ceiling_excludes(None, "shell"));
        // Covered.
        assert!(!ceiling_excludes(
            Some(&["shell".to_string(), "transfer".to_string()]),
            "shell"
        ));
        // Outside.
        assert!(ceiling_excludes(Some(&["transfer".to_string()]), "shell"));
        assert!(ceiling_excludes(Some(&[]), "shell"));
    }
}
