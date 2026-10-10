//! What `status` and `doctor` say about the RUNNING daemon, beyond "its pid is
//! alive".
//!
//! WHY THIS EXISTS. A daemon stuck re-dialing the signaling server about 2.5
//! times a second still answered on its control socket, so `status` printed "up"
//! and exited 0, and `doctor` reported every check healthy because it only tested
//! a fresh connection from the CLI, never the daemon's own link. Peers meanwhile
//! could not reach it. The daemon now reports its signaling state in its
//! `cap-status` reply (`signaling`: connected, reconnecting or flapping), and
//! both commands read it: a daemon that is not connected, or keeps dropping, is
//! reported degraded with the reason, not "up".

use crate::ui::Tone;
use serde_json::{Value, json};
use std::time::Duration;

/// How long `doctor` waits for the daemon to answer.
const PROBE: Duration = Duration::from_millis(1500);

/// The daemon's `signaling` object, or None when no daemon answered or it is
/// too old to report one.
pub(crate) async fn signaling() -> Option<Value> {
    let reply = crate::ctl::try_cap_status().await?;
    let sig = reply.get("signaling")?.clone();
    (!sig.is_null()).then_some(sig)
}

/// One line for a person from a `signaling` object: None when the link is
/// healthy (or the daemon is too old to say), else what is wrong. Pure.
pub(crate) fn degraded_reason(sig: &Value) -> Option<String> {
    let secs = sig["for_secs"].as_u64().unwrap_or(0);
    match sig["state"].as_str()? {
        "reconnecting" => Some(format!(
            "not connected to the tunlion server (for {secs}s{}); it keeps retrying with backoff, and peers cannot reach it until it reconnects",
            sig["last_reason"].as_str().map(|r| format!(", last: {r}")).unwrap_or_default()
        )),
        "flapping" => Some(format!(
            "its link to the tunlion server keeps dropping ({} reconnects in the last {}s), so peers may fail to reach it",
            sig["redials"].as_u64().unwrap_or(0),
            sig["redials_window_secs"].as_u64().unwrap_or(120)
        )),
        _ => None,
    }
}

/// The daemon as `doctor` sees it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Daemon {
    NotRunning,
    /// Suspended (SIGSTOP): its pid is alive and it serves nothing.
    Suspended(u32),
    /// Alive but silent on its control socket.
    NotResponding(u32),
    /// Answers, but its signaling link is down or flapping.
    Degraded(u32, String),
    /// Answers, and its link is up (or it is too old to say otherwise).
    Serving(u32, Option<u64>),
}

/// Pure classification, so every branch is testable without a daemon.
pub(crate) fn classify(
    pid: Option<u32>,
    suspended: bool,
    responding: bool,
    sig: Option<&Value>,
) -> Daemon {
    let Some(pid) = pid else { return Daemon::NotRunning };
    if suspended {
        return Daemon::Suspended(pid);
    }
    if !responding {
        return Daemon::NotResponding(pid);
    }
    match sig.and_then(degraded_reason) {
        Some(why) => Daemon::Degraded(pid, why),
        None => Daemon::Serving(pid, sig.and_then(|s| s["for_secs"].as_u64())),
    }
}

/// Look at the running daemon.
pub(crate) async fn inspect() -> Daemon {
    let pid = crate::daemon_alive();
    let suspended = pid.is_some_and(|p| crate::platform::process_stopped(p) == Some(true));
    let responding = match pid {
        Some(_) if !suspended => crate::ctl::daemon_responds(PROBE).await == Some(true),
        _ => false,
    };
    let sig = if responding { signaling().await } else { None };
    classify(pid, suspended, responding, sig.as_ref())
}

impl Daemon {
    /// The tone, short word and detail for doctor's `daemon` row.
    pub(crate) fn row(&self) -> (Tone, &'static str, String) {
        match self {
            Daemon::NotRunning => (Tone::Dim, "not running", "start it with: tunlion up".into()),
            Daemon::Suspended(p) => (
                Tone::Err,
                "SUSPENDED",
                format!("pid {p} is stopped (SIGSTOP) and serves nothing; `tunlion down` then `tunlion up` restarts it"),
            ),
            Daemon::NotResponding(p) => (
                Tone::Err,
                "NOT RESPONDING",
                format!("pid {p} did not answer on its control socket within {}s", PROBE.as_secs_f32()),
            ),
            Daemon::Degraded(p, why) => (Tone::Warn, "DEGRADED", format!("pid {p}: {why}")),
            Daemon::Serving(p, Some(s)) => {
                (Tone::Ok, "serving", format!("pid {p}, connected to the server for {s}s"))
            }
            Daemon::Serving(p, None) => (Tone::Ok, "serving", format!("pid {p}")),
        }
    }

    /// Healthy enough that nothing needs doing.
    pub(crate) fn healthy(&self) -> bool {
        matches!(self, Daemon::NotRunning | Daemon::Serving(..))
    }

    pub(crate) fn to_json(&self) -> Value {
        let (_, word, detail) = self.row();
        json!({
            "state": word.to_ascii_lowercase(),
            "healthy": self.healthy(),
            "detail": detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degraded_reasons_are_said_and_healthy_is_silent() {
        assert!(degraded_reason(&json!({"state": "connected", "for_secs": 9})).is_none());
        assert!(degraded_reason(&json!({})).is_none(), "an older daemon says nothing, not degraded");
        let r = degraded_reason(&json!({"state": "reconnecting", "for_secs": 12, "last_reason": "closed (close)"})).unwrap();
        assert!(r.contains("not connected") && r.contains("12s") && r.contains("closed (close)"), "{r}");
        let f = degraded_reason(&json!({"state": "flapping", "redials": 7, "redials_window_secs": 120})).unwrap();
        assert!(f.contains("7 reconnects") && f.contains("120s"), "{f}");
    }

    /// The defect: a daemon in a reconnect storm answered its control socket,
    /// so it was "up". It must be degraded.
    #[test]
    fn a_flapping_daemon_that_answers_is_degraded_not_serving() {
        let sig = json!({"state": "flapping", "redials": 40, "redials_window_secs": 120});
        let d = classify(Some(5), false, true, Some(&sig));
        assert!(matches!(d, Daemon::Degraded(5, _)), "{d:?}");
        assert!(!d.healthy());
        assert_eq!(d.to_json()["state"], "degraded");
    }

    #[test]
    fn every_branch() {
        assert_eq!(classify(None, false, false, None), Daemon::NotRunning);
        assert_eq!(classify(Some(5), true, true, None), Daemon::Suspended(5));
        assert_eq!(classify(Some(5), false, false, None), Daemon::NotResponding(5));
        let ok = json!({"state": "connected", "for_secs": 30});
        assert_eq!(classify(Some(5), false, true, Some(&ok)), Daemon::Serving(5, Some(30)));
        assert_eq!(classify(Some(5), false, true, None), Daemon::Serving(5, None));
        assert!(!Daemon::Suspended(5).healthy());
        assert!(!Daemon::NotResponding(5).healthy());
    }
}
