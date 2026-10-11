//! Forget and revoke, in effect in the RUNNING daemon.
//!
//! `devices forget` writes the store (the record goes, and a live certificate's
//! key goes onto `revoked-keys.json`), but the daemon that is already up was
//! deciding with what it loaded at start. Measured on the launch candidate: the
//! owner forgot `beta`, was told the key "is refused here", and a minute later
//! beta's `send` was delivered and alpha's log read "known device 'beta'
//! appeared, connecting". Only `down` + `up` made the forget real. Three things
//! held the old answer:
//!
//!   * the daemon's `(name, pair secret)` list, loaded once at start, which the
//!     known-peer dial, the channel-digest re-adopt and the WebRTC `pair-proof`
//!     all matched against, so a forgotten secret kept proving;
//!   * the links already up, which nothing ever re-examined;
//!   * brokered meeting places a fleet sibling opened before it was revoked.
//!
//! This module is the pure half of the fix: what the store says now, which held
//! secrets it no longer holds, and which links must close because of it. The
//! daemon loop runs the sweep whenever the store changes (checked every ~2 s)
//! and at once when `devices forget` / `revoke` asks over the control socket,
//! and the decision sites prune the held list against the store before using
//! it. A daemon that cannot be asked still sees the store change on its next
//! scan, which is why the CLI can only promise "within a few seconds" when no
//! daemon answered.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

/// The store as raw text: devices.json and revoked-keys.json. The daemon keeps
/// the last one it acted on and sweeps when this differs. `None` when either
/// exists but cannot be read, or devices.json is not a JSON array: a half
/// written or corrupt store must never read as "every secret was removed" and
/// drop every paired link (the per-open gate already fails closed on it).
pub(crate) fn store_snapshot() -> Option<(String, String)> {
    snapshot_at(
        &crate::devices_store::devices_path(),
        &crate::platform::Paths::config_path(crate::fleet_support::KEY_REVOCATIONS_FILE),
    )
}

pub(crate) fn snapshot_at(devices: &Path, revoked: &Path) -> Option<(String, String)> {
    let d = read_or_empty(devices)?;
    if !d.trim().is_empty() && !matches!(serde_json::from_str::<Value>(&d), Ok(Value::Array(_))) {
        return None;
    }
    let r = read_or_empty(revoked)?;
    Some((d, r))
}

fn read_or_empty(p: &Path) -> Option<String> {
    match std::fs::read_to_string(p) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    }
}

/// Remove from `held` every pair whose secret `on_disk` no longer holds, and
/// return the removed SECRETS. A secret still held under another name (a
/// rename) stays, under its new name: matching is on the secret, the thing that
/// proves, never on the name. Pure.
pub(crate) fn prune_held(
    held: &mut Vec<(String, String)>,
    on_disk: &[(String, String)],
) -> HashSet<String> {
    let mut removed = HashSet::new();
    held.retain_mut(|pair| match on_disk.iter().find(|(_, s)| *s == pair.1) {
        Some((now, _)) => {
            if pair.0 != *now {
                pair.0 = now.clone();
            }
            true
        }
        None => {
            removed.insert(pair.1.clone());
            false
        }
    });
    removed
}

/// `prune_held` against the store on disk, at a decision site. Leaves `held`
/// untouched when the store cannot be read cleanly (see `store_snapshot`).
pub(crate) fn prune_to_store(held: &mut Vec<(String, String)>) -> HashSet<String> {
    if store_snapshot().is_none() {
        return HashSet::new();
    }
    prune_held(held, &crate::devices_load())
}

/// What the sweep needs to know about one link. Built from `conn::Link`.
pub(crate) struct LinkFacts<'a> {
    /// The secret this link was dialed or proved with (pair or brokered).
    pub secret: Option<&'a str>,
    /// The device key the link proved or resolved, if any.
    pub device_pub: Option<[u8; 32]>,
}

/// Must this link close now? Pure.
///
/// Closes a link whose secret the store no longer holds (a forgotten paired or
/// enrolled device, or a meeting place brokered by a now revoked sibling), and
/// one whose proven key is on the key revocation list (a forgotten live
/// certificate, which has no record left for any other check to find).
///
/// Deliberately NOT here: a device revoked IN PLACE (`revoke --certificate`,
/// `devices revoke`), whose record stays. Every open on its link meets the
/// capability gate, which refuses it with the reason ("device revoked"), and
/// that reason reaching the device is worth keeping. Its overlay route is
/// withdrawn separately (`route_must_withdraw`).
pub(crate) fn link_must_close(
    f: &LinkFacts<'_>,
    removed_secrets: &HashSet<String>,
    key_listed: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    if f.secret.is_some_and(|s| removed_secrets.contains(s)) {
        return true;
    }
    f.device_pub.as_ref().is_some_and(|k| key_listed(k))
}

/// Must this link lose its overlay route? Any revocation of its key, in place
/// or by forget. Pure.
pub(crate) fn route_must_withdraw(
    device_pub: Option<&[u8; 32]>,
    revoked: &dyn Fn(&[u8; 32]) -> bool,
) -> bool {
    device_pub.is_some_and(|k| revoked(k))
}

/// Is this device key on the key revocation list now?
pub(crate) fn key_listed(device_pub: &[u8; 32]) -> bool {
    crate::fleet_support::device_key_revoked(device_pub, crate::identity::now_secs())
}

/// What a running daemon said when asked to apply a revocation now.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DaemonAnswer {
    /// It swept: `closed` links ended, and it refuses the device from here on.
    Applied { closed: u64 },
    /// No daemon answered and none is running here (or this platform has no
    /// control socket to ask with).
    NoDaemon,
    /// A daemon is running but did not confirm (an older binary, or a busy
    /// loop). Until it does, nothing proves the revocation is live.
    Unconfirmed,
}

/// Ask the running daemon to apply the store now.
pub(crate) async fn tell_daemon() -> DaemonAnswer {
    match crate::ctl::try_revocation_sync().await {
        Some(v) if v["ok"].as_bool() == Some(true) => DaemonAnswer::Applied {
            closed: v["closed"].as_u64().unwrap_or(0),
        },
        _ if crate::ctl::daemon_present().await => DaemonAnswer::Unconfirmed,
        _ => DaemonAnswer::NoDaemon,
    }
}

/// The line `forget` / `revoke` prints about the running daemon. Err for
/// `Unconfirmed`: the store is written, but the claim "refused here" is not yet
/// true in the daemon that is accepting connections, so the command must not
/// exit 0 as if it were. `forgotten` is a forget (the device is no longer
/// answered at all, so it sees this machine as offline) rather than a revoke in
/// place (its opens are refused with the reason). Pure.
pub(crate) fn daemon_line(
    name: &str,
    answer: &DaemonAnswer,
    forgotten: bool,
) -> Result<String, String> {
    let untold = if forgotten {
        format!(" '{name}' is not told: from its side this machine looks offline.")
    } else {
        String::new()
    };
    match answer {
        DaemonAnswer::Applied { closed } => Ok(format!(
            "in effect now: the running daemon closed {closed} link(s) to '{name}' and refuses it from here on.{untold}"
        )),
        DaemonAnswer::NoDaemon => Ok(format!(
            "no running daemon answered: if `tunlion up` is running here it applies this within a few seconds, otherwise from its next start.{untold}"
        )),
        DaemonAnswer::Unconfirmed => Err(format!(
            "recorded, but the running daemon did not confirm it, so '{name}' may still be connected.\n  Restart it to apply now: tunlion down -y && tunlion up --detach"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: &str, s: &str) -> (String, String) {
        (n.to_string(), s.to_string())
    }

    #[test]
    fn a_forgotten_secret_is_pruned_and_reported() {
        let mut held = vec![p("beta", "s1"), p("gamma", "s2")];
        let removed = prune_held(&mut held, &[p("gamma", "s2")]);
        assert_eq!(held, vec![p("gamma", "s2")]);
        assert_eq!(removed, HashSet::from(["s1".to_string()]));
    }

    #[test]
    fn a_rename_is_not_a_removal() {
        let mut held = vec![p("beta", "s1")];
        let removed = prune_held(&mut held, &[p("b2", "s1")]);
        assert!(removed.is_empty(), "the secret is still held under a new name");
        assert_eq!(held, vec![p("b2", "s1")], "held under the name the store uses now");
    }

    #[test]
    fn nothing_changes_when_nothing_was_removed() {
        let mut held = vec![p("beta", "s1")];
        let removed = prune_held(&mut held, &[p("beta", "s1"), p("new", "s9")]);
        assert!(removed.is_empty());
        assert_eq!(held, vec![p("beta", "s1")]);
    }

    #[test]
    fn a_link_on_a_removed_secret_closes() {
        let removed = HashSet::from(["s1".to_string()]);
        let none = |_: &[u8; 32]| false;
        assert!(link_must_close(&LinkFacts { secret: Some("s1"), device_pub: None }, &removed, &none));
        assert!(!link_must_close(&LinkFacts { secret: Some("s2"), device_pub: None }, &removed, &none));
        assert!(!link_must_close(&LinkFacts { secret: None, device_pub: None }, &removed, &none));
    }

    #[test]
    fn a_link_proven_as_a_listed_key_closes_even_with_no_secret() {
        let listed = |k: &[u8; 32]| k == &[7u8; 32];
        let removed = HashSet::new();
        assert!(link_must_close(&LinkFacts { secret: None, device_pub: Some([7u8; 32]) }, &removed, &listed));
        assert!(!link_must_close(&LinkFacts { secret: None, device_pub: Some([8u8; 32]) }, &removed, &listed));
    }

    #[test]
    fn any_revoked_key_loses_its_route() {
        let revoked = |k: &[u8; 32]| k == &[7u8; 32];
        assert!(route_must_withdraw(Some(&[7u8; 32]), &revoked));
        assert!(!route_must_withdraw(Some(&[8u8; 32]), &revoked));
        assert!(!route_must_withdraw(None, &revoked));
    }

    #[test]
    fn a_corrupt_store_is_no_snapshot() {
        let dir = std::env::temp_dir().join(format!("tunlion-revlive-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.join("devices.json");
        let r = dir.join("revoked-keys.json");
        assert_eq!(snapshot_at(&d, &r), Some((String::new(), String::new())), "absent is empty");
        std::fs::write(&d, "[{\"name\":\"a\",\"secret\":\"s\"}]").unwrap();
        assert!(snapshot_at(&d, &r).is_some());
        std::fs::write(&d, "[{\"name\":").unwrap();
        assert_eq!(snapshot_at(&d, &r), None, "a torn store must not read as every secret removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_daemon_line_never_claims_what_it_cannot_know() {
        let applied = daemon_line("beta", &DaemonAnswer::Applied { closed: 2 }, true).unwrap();
        assert!(applied.contains("in effect now") && applied.contains("closed 2 link(s)"));
        assert!(applied.contains("looks offline"), "a forget says what the device sees: {applied}");
        let none = daemon_line("beta", &DaemonAnswer::NoDaemon, true).unwrap();
        assert!(!none.contains("in effect now"), "{none}");
        assert!(none.contains("next start"), "{none}");
        assert!(!none.contains("never met you"), "the forgotten side is not told: {none}");
        let in_place = daemon_line("beta", &DaemonAnswer::Applied { closed: 0 }, false).unwrap();
        assert!(!in_place.contains("offline"), "a revoked device is refused with a reason: {in_place}");
        let unconfirmed = daemon_line("beta", &DaemonAnswer::Unconfirmed, true).unwrap_err();
        assert!(unconfirmed.contains("tunlion down -y && tunlion up --detach"), "{unconfirmed}");
    }
}
