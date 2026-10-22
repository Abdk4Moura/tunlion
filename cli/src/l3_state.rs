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

use serde_json::{json, Value};
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
    if let Err(e) = crate::platform::SecretFile::write_str(&state_path(), &Value::Object(v).to_string())
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
    let Some(pid) = daemon else { return no_daemon() };
    let Some(v) = std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
    else {
        return serde_json::to_value(L3Status::down(
            "none",
            "the daemon has not reported an L3 endpoint yet",
        ))
        .unwrap_or_else(|_| json!({"state":"down","mode":"none","reason":"no L3 endpoint reported"}));
    };
    if v["pid"].as_u64() != Some(u64::from(pid)) {
        return serde_json::to_value(L3Status::down(
            "none",
            "the daemon has not reported an L3 endpoint yet",
        ))
        .unwrap_or_else(|_| json!({"state":"down","mode":"none","reason":"no L3 endpoint reported"}));
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(v["reason"].as_str().unwrap().contains("no running tunlion daemon"));
    }
}
