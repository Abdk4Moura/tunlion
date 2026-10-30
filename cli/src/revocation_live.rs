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

use crate::fleet_support::ForgetOutcome;
use crate::ui;

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
/// Deliberately NOT here: a device revoked IN PLACE (`demote --to cut`), whose record stays. Every open on its link meets the
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

/// Who brokered a meeting place: the PROVEN identity of the certificate
/// verified fleet link the `fleet-rendezvous` arrived on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokeredBy {
    pub device_pub: [u8; 32],
    pub owner_pub: [u8; 32],
    pub expires: u64,
    /// The local petname for `device_pub`, if we hold a record for that key.
    pub name: Option<String>,
}

/// The name a link on a brokered meeting place is dialed under, which every
/// adoption path copies into `verified_name` (the capability-store key). Pure.
///
/// It comes from the BROKER's proven key, never from the name the arriving peer
/// announces. The old code used the announced name, so a fleet sibling's
/// one-shot calling itself after a device that holds grants was filed under
/// that device: `verified_name` was the claimed name, `resolve_peer_identity`
/// then resolved the CLAIMED device's certificate, and the link was born
/// trusted as an owner device. With no record for the broker's key the link
/// gets `BROKERED_NO_RECORD`, which no device record can be named (it holds a
/// control character, which every stored name has stripped), so it keys no
/// grant on any path that copies it.
pub(crate) fn brokered_dial_name(broker: &BrokeredBy) -> String {
    broker
        .name
        .clone()
        .unwrap_or_else(|| BROKERED_NO_RECORD.to_string())
}

/// See `brokered_dial_name`. Not `FLEET_LINK_NAME`: that one is printable, so
/// `devices rename x 'fleet: unverified'` could make it a record's name.
pub(crate) const BROKERED_NO_RECORD: &str = "\u{7f}fleet: brokered, no record";

/// Bind a link that arrived on a brokered meeting place to its broker: the
/// same shape as a fleet-hello admission (proven key, fleet principal, not
/// legacy-trusted), because the only thing the peer proved is possession of a
/// one-time secret the broker handed over its own verified link.
pub(crate) fn bind_brokered_link(link: &mut crate::conn::Link, broker: &BrokeredBy) {
    link.trusted = false;
    link.verified_name = broker.name.clone();
    link.admit_fleet(broker.owner_pub, broker.device_pub, broker.expires);
}

/// What a running daemon said when asked to apply a revocation now.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DaemonAnswer {
    /// It swept: `closed` links ended, `refused` live links stay up to a device
    /// revoked IN PLACE (every open on them is refused with the reason, and
    /// their open sessions are cut by the live re-check), and it refuses the
    /// device from here on.
    Applied { closed: u64, refused: u64 },
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
            refused: v["refused"].as_u64().unwrap_or(0),
        },
        _ if crate::ctl::daemon_present().await => DaemonAnswer::Unconfirmed,
        _ => DaemonAnswer::NoDaemon,
    }
}

/// One result line: the success glyph, the past-tense verb, the name, then any
/// short retained facts. Pure, but for paint.
fn result_line(verb: &str, name: &str, details: &[String]) -> String {
    let mut line = format!(
        "{} {} {}",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        verb,
        ui::paint(ui::Tone::Bold, name),
    );
    if !details.is_empty() {
        line.push_str(&ui::paint(
            ui::Tone::Dim,
            &format!(" \u{b7} {}", details.join(" \u{b7} ")),
        ));
    }
    line
}

/// `1 link` / `2 links`, so counted facts read correctly.
fn links(n: u64) -> String {
    if n == 1 { "1 link".to_string() } else { format!("{n} links") }
}

/// The one line `devices forget` prints after the daemon answered. The store is
/// already written; this says what is true now, and nothing it cannot know.
/// `Unconfirmed` is an error: the command must not exit 0 while the daemon that
/// is accepting connections has not applied it. Pure.
pub(crate) fn forget_line(
    outcome: &ForgetOutcome,
    answer: &DaemonAnswer,
) -> Result<String, String> {
    let mut details = Vec::new();
    match answer {
        DaemonAnswer::Applied { closed, .. } => {
            if *closed > 0 {
                details.push(format!("closed {}", links(*closed)));
            }
        }
        DaemonAnswer::NoDaemon => {
            details.push("applies when `tunlion up` next starts".to_string());
        }
        DaemonAnswer::Unconfirmed => {
            return Err(unconfirmed("Forgot", &outcome.name));
        }
    }
    if let Some(detail) = outcome.verdict.detail() {
        details.push(detail);
    }
    Ok(result_line("Forgot", &outcome.name, &details))
}

/// The one line a durable revoke prints (`demote --to cut`). Unlike a forget,
/// a revoke in place keeps live links up on purpose so the device is told why
/// it is refused; the count is a fact, not a "closed 0 links" success. Pure.
pub(crate) fn revoke_line(name: &str, answer: &DaemonAnswer) -> Result<String, String> {
    let mut details = Vec::new();
    match answer {
        DaemonAnswer::Applied { closed, refused } => {
            if *closed > 0 {
                details.push(format!("closed {}", links(*closed)));
            }
            if *refused > 0 {
                details.push(format!(
                    "{} kept for the refusal",
                    links(*refused)
                ));
            }
        }
        DaemonAnswer::NoDaemon => {
            details.push("applies when `tunlion up` next starts".to_string());
        }
        DaemonAnswer::Unconfirmed => {
            return Err(unconfirmed("Revoked", name));
        }
    }
    Ok(result_line("Revoked", name, &details))
}

/// `revoke <device> <capability>` uses the same success shape as the ladder's
/// cut off. `shell_key_removed` is the fact the old sentence carried.
pub(crate) fn capability_revoke_line(
    name: &str,
    capability: &str,
    shell_key_removed: bool,
) -> String {
    let mut details = Vec::new();
    if shell_key_removed {
        details.push("removed its managed shell key".to_string());
    }
    let verb = format!("Revoked {capability} from");
    result_line(&verb, name, &details)
}

/// The single red outcome for an unconfirmed daemon, with the command that
/// applies it now. The caller returns it as an error so the exit stays nonzero
/// and nothing success-shaped was printed first.
fn unconfirmed(verb: &str, name: &str) -> String {
    format!(
        "{verb} {name}, but the running service didn't confirm \u{b7} restart it: tunlion down -y && tunlion up --detach"
    )
}

/// Print an unconfirmed outcome as the command's only feedback and return the
/// existing nonzero error for it. `reported_because` keeps `main` from printing
/// the same sentence a second time.
pub(crate) fn unconfirmed_exit(message: String) -> anyhow::Error {
    ui::critical(&format!(
        "{} {message}",
        ui::paint(ui::Tone::Err, ui::glyph_err())
    ));
    crate::exit_codes::reported_because(crate::exit_codes::ExitKind::Other, message)
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
    fn a_brokered_link_never_takes_the_name_its_peer_asserts() {
        // The broker proved key [7;32], which we hold as "phone". Whatever the
        // arriving one-shot calls itself ("laptop", the device with grants),
        // the link is dialed, and so filed, as the broker.
        let by = BrokeredBy {
            device_pub: [7u8; 32],
            owner_pub: [1u8; 32],
            expires: 99,
            name: Some("phone".into()),
        };
        assert_eq!(brokered_dial_name(&by), "phone");
        // No record for the broker's key: the placeholder, which can never be
        // a device record's name, so it keys no grant.
        let unknown = BrokeredBy { name: None, ..by.clone() };
        let n = brokered_dial_name(&unknown);
        assert_eq!(n, BROKERED_NO_RECORD);
        assert_ne!(crate::sanitize_device_name(&n), n, "the placeholder is not a storable device name");
        assert_ne!(n, "laptop");
    }

    #[test]
    fn a_forget_line_keeps_only_facts_it_can_stand_behind() {
        use crate::fleet_support::ForgetVerdict;

        let outcome = |verdict| ForgetOutcome { name: "beta".to_string(), verdict };
        let revoked = outcome(ForgetVerdict::RevokeThenRemove { days_left: 21 });

        let applied = forget_line(&revoked, &DaemonAnswer::Applied { closed: 1, refused: 0 })
            .unwrap();
        assert!(applied.contains("Forgot beta"), "{applied}");
        assert!(applied.contains("closed 1 link"), "{applied}");
        assert!(applied.contains("key refused for 21 days"), "{applied}");
        assert!(!applied.contains("is free now"), "{applied}");
        assert!(!applied.contains("looks offline"), "{applied}");
        assert!(!applied.contains("valid for"), "{applied}");

        let none = forget_line(&revoked, &DaemonAnswer::NoDaemon).unwrap();
        assert!(none.contains("applies when `tunlion up` next starts"), "{none}");
        assert!(none.contains("key refused for 21 days"), "{none}");
        assert!(!none.contains("in effect now"), "{none}");
        assert!(!none.contains("never met you"), "{none}");

        let plain = ForgetOutcome { name: "beta".to_string(), verdict: ForgetVerdict::Remove };
        assert_eq!(
            forget_line(&plain, &DaemonAnswer::Applied { closed: 0, refused: 0 }).unwrap(),
            format!("{} Forgot beta", ui::paint(ui::Tone::Ok, ui::glyph_ok()))
        );
        assert!(!forget_line(&plain, &DaemonAnswer::Applied { closed: 0, refused: 0 })
            .unwrap()
            .contains("key refused"));

        // Counting is part of the line, in the plural the count calls for.
        let one_day = outcome(ForgetVerdict::KeepRevocationThenRemove { days_left: 1 });
        let one = forget_line(&one_day, &DaemonAnswer::Applied { closed: 2, refused: 0 })
            .unwrap();
        assert!(one.contains("closed 2 links") && one.contains("key refused for 1 day"), "{one}");

        let unconfirmed =
            forget_line(&revoked, &DaemonAnswer::Unconfirmed).unwrap_err();
        assert!(unconfirmed.starts_with("Forgot beta, but the running service didn't confirm"), "{unconfirmed}");
        assert!(unconfirmed.contains("tunlion down -y && tunlion up --detach"), "{unconfirmed}");
        assert_eq!(
            crate::exit_codes::classify(&unconfirmed_exit(unconfirmed)).code(),
            1,
            "an unconfirmed daemon must keep the nonzero exit"
        );
    }

    #[test]
    fn a_revoke_line_counts_closed_and_kept_links() {
        let applied = revoke_line("beta", &DaemonAnswer::Applied { closed: 2, refused: 0 }).unwrap();
        assert!(applied.contains("Revoked beta") && applied.contains("closed 2 links"), "{applied}");

        // A revoke in place keeps live links up to carry the refusal; that is a
        // count, never reported as "closed 0 links".
        let live = revoke_line("beta", &DaemonAnswer::Applied { closed: 0, refused: 2 }).unwrap();
        assert!(live.contains("2 links kept for the refusal") && !live.contains("closed 0"), "{live}");
        assert!(!live.contains("offline"), "{live}");

        let none = revoke_line("beta", &DaemonAnswer::NoDaemon).unwrap();
        assert!(none.contains("applies when `tunlion up` next starts"), "{none}");

        let unconfirmed = revoke_line("beta", &DaemonAnswer::Unconfirmed).unwrap_err();
        assert!(unconfirmed.starts_with("Revoked beta, but the running service didn't confirm"), "{unconfirmed}");
        assert!(unconfirmed.contains("tunlion down -y && tunlion up --detach"), "{unconfirmed}");

        let shell = capability_revoke_line("beta", "shell", true);
        assert!(shell.contains("Revoked shell from beta") && shell.contains("managed shell key"), "{shell}");
        let mount = capability_revoke_line("beta", "mount", false);
        assert!(mount.contains("Revoked mount from beta") && !mount.contains("shell key"), "{mount}");
    }
}
