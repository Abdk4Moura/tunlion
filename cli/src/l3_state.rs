//! Machine-readable L3 state, shared with siblings.
//!
//! A derived overlay address is an IDENTITY, not evidence that a packet
//! endpoint exists. `addr` used to print one while the daemon had no TUN and no
//! netstack, so an adapter dialed it and got ENETUNREACH. This module publishes
//! the daemon's live state next to the config and reads it back for `addr`,
//! `devices --json` and `expose`.
//!
//! The daemon owns the endpoint, so only the daemon writes `ready`. The record
//! carries its PID: a state file left by a dead daemon is never trusted, the
//! same rule `expose-bound.json` already uses.

use serde_json::{Value, json};
use std::path::PathBuf;

use filament_peerloop::mesh::L3Status;

/// `{config_dir}/l3-state.json`.
pub fn state_path() -> PathBuf {
    crate::settings::config_dir().join("l3-state.json")
}

/// Write the daemon's live state. Stamps the PID so a stale record from a
/// previous daemon can be recognised and ignored.
pub fn write(status: &L3Status) {
    let mut v = match serde_json::to_value(status) {
        Ok(Value::Object(m)) => m,
        _ => return,
    };
    v.insert("pid".into(), json!(std::process::id()));
    if let Err(e) =
        crate::platform::SecretFile::write_str(&state_path(), &Value::Object(v).to_string())
    {
        crate::ui::debug(&format!("tunlion: could not record the L3 state: {e}"));
    }
}

/// What to report when no daemon is running at all.
pub fn no_daemon() -> Value {
    serde_json::to_value(L3Status::down(
        "none",
        "no running tunlion daemon (start it with: tunlion up; use `tunlion up --userspace` when no TUN is available)",
    ))
    .unwrap_or_else(|_| json!({"state":"down","mode":"none","reason":"no running tunlion daemon"}))
}

/// Read the daemon's published state, verifying the PID still belongs to THIS
/// config's daemon. Missing/mismatched/corrupt is `down`, never `ready`.
pub fn read_file_for(daemon: Option<u32>) -> Value {
    let Some(pid) = daemon else {
        return no_daemon();
    };
    let Some(v) = std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    else {
        return serde_json::to_value(L3Status::down(
            "none",
            "the daemon has not reported an L3 endpoint yet",
        ))
        .unwrap_or_else(
            |_| json!({"state":"down","mode":"none","reason":"no L3 endpoint reported"}),
        );
    };
    if v["pid"].as_u64() != Some(u64::from(pid)) {
        return serde_json::to_value(L3Status::down(
            "none",
            "the daemon has not reported an L3 endpoint yet",
        ))
        .unwrap_or_else(
            |_| json!({"state":"down","mode":"none","reason":"no L3 endpoint reported"}),
        );
    }
    json!({
        "state": v["state"].as_str().unwrap_or("down"),
        "mode": v["mode"].as_str().unwrap_or("none"),
        "reason": v.get("reason").cloned().unwrap_or(Value::Null),
    })
}

/// The live state: ask the daemon on a platform with a control socket, else
/// read the PID-checked record. Never blocks on a missing daemon for long.
pub async fn current() -> Value {
    if let Some(l3) = crate::platform::l3_state_over_control().await {
        if l3.is_object() {
            return l3;
        }
    }
    read_file_for(crate::daemon_alive())
}

/// Is this state live enough to bind/dial?
pub fn is_ready(state: &Value) -> bool {
    state["state"].as_str() == Some("ready")
}

/// The one-line text warning for a non-ready state, or `None` when ready.
/// Pure so `addr`'s honesty is testable without a daemon.
pub fn not_ready_note(state: &Value) -> Option<String> {
    if is_ready(state) {
        return None;
    }
    let mode = state["mode"].as_str().unwrap_or("none");
    let reason = state["reason"].as_str().unwrap_or("no live L3 endpoint");
    Some(format!(
        "no live overlay endpoint (mode={mode}): {reason}. The overlay address above is \
         identity-only: it is not routed, cannot be dialed, and `expose` will not bind it"
    ))
}

/// Warnings for a READY endpoint that still is not what a person expects from
/// "native" overlay access (incident: dgmfa). Pure, testable without a daemon.
/// - userspace mode: tunlion's own commands reach the overlay, but other apps on
///   this machine (a browser, curl) cannot, because no adapter carries it;
/// - kernel mode with native IPv4 missing: the v4 address prints but is not
///   installed, so IPv4 overlay traffic cannot use the adapter.
pub fn native_notes(state: &Value) -> Vec<String> {
    let mut notes = Vec::new();
    if !is_ready(state) {
        return notes;
    }
    match state["mode"].as_str() {
        Some("userspace") => notes.push(
            "overlay is userspace-only here: tunlion's own commands reach it, but other apps on \
             this machine cannot (no network adapter carries it). For native access, run the \
             daemon elevated with l3-mode kernel."
                .to_string(),
        ),
        Some("kernel") => {
            if let Some(problem) = state["v4Problem"].as_str() {
                notes.push(format!(
                    "native IPv4 is NOT installed on the overlay adapter ({problem}). IPv6 overlay \
                     works; the v4 address above is not reachable from other apps here."
                ));
            }
        }
        _ => {}
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_notes_distinguish_userspace_and_missing_native_v4() {
        let kernel_ok = serde_json::to_value(L3Status::ready("kernel")).unwrap();
        assert!(native_notes(&kernel_ok).is_empty(), "a healthy kernel endpoint says nothing extra");
        let user = serde_json::to_value(L3Status::ready("userspace")).unwrap();
        let notes = native_notes(&user);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("userspace-only") && notes[0].contains("other apps"), "{notes:?}");
        let v4_missing = serde_json::to_value(
            L3Status::ready("kernel").with_v4_problem(Some("IPv4 198.18.194.149 not installed on tunlion0: x".into())),
        )
        .unwrap();
        assert_eq!(v4_missing["v4Problem"], "IPv4 198.18.194.149 not installed on tunlion0: x");
        let notes = native_notes(&v4_missing);
        assert!(notes.iter().any(|n| n.contains("NOT installed") && n.contains("198.18.194.149")), "{notes:?}");
        // not ready: the existing not_ready_note speaks, native_notes stays quiet
        let down = serde_json::to_value(L3Status::down("none", "no tun")).unwrap();
        assert!(native_notes(&down).is_empty());
    }

    #[test]
    fn ready_is_ready_and_says_nothing_extra() {
        let v = serde_json::to_value(L3Status::ready("userspace")).unwrap();
        assert!(is_ready(&v));
        assert_eq!(not_ready_note(&v), None);
        assert_eq!(v["state"], "ready");
        assert_eq!(v["mode"], "userspace");
    }

    #[test]
    fn down_and_starting_are_never_ready_and_name_their_reason() {
        for st in [
            L3Status::down("none", "/dev/net/tun does not exist"),
            L3Status::starting("kernel"),
        ] {
            let v = serde_json::to_value(st).unwrap();
            assert!(!is_ready(&v), "{v}");
            let note = not_ready_note(&v).expect("a note");
            assert!(note.contains("identity-only"), "{note}");
        }
        let down = serde_json::to_value(L3Status::down("none", "boom")).unwrap();
        assert_eq!(down["reason"], "boom");
        assert!(not_ready_note(&down).unwrap().contains("boom"));
    }

    #[test]
    fn a_missing_state_file_is_down_not_ready() {
        let v = read_file_for(None);
        assert_eq!(v["state"], "down");
        assert_eq!(v["mode"], "none");
        assert!(
            v["reason"]
                .as_str()
                .unwrap()
                .contains("no running tunlion daemon")
        );
    }
}
