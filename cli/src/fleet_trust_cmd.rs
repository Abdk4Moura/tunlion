//! `tunlion grant <subject> <cap> --on <device>` and its `revoke` twin.
//!
//! The owner device authors a grant ABOUT another of its devices. It is kept
//! here as plain local state; the daemon signs the current set about each
//! target with the owner key and delivers it over the link to that target only
//! (`Conn::fleet_grants_maintenance`). The target judges it with
//! `filament_cap::fleet_grants::judge_grant_set` and keeps it outside its
//! capability store.
//!
//! Scope, deliberately narrow: subject and target must both be devices this
//! owner certified (fleet devices), and the capability one of the plain
//! per-device ones. A route, a tag or a user-wide grant is not something one
//! device can be told about another.

use crate::exit_codes::{ExitKind, err};
use anyhow::Result;

const DISTRIBUTABLE: &[&str] = &["transfer", "shell", "mount"];

fn fleet_device_pub(name: &str, owner: &[u8; 32]) -> Result<[u8; 32]> {
    let Some(cert) = crate::device_view::device_cert_for(name) else {
        return Err(err(
            ExitKind::UnknownDevice,
            format!("no device of yours named '{name}' (it must be one you added with `tunlion add`)"),
        ));
    };
    if cert.user_pub != *owner {
        return Err(err(
            ExitKind::Usage,
            format!("'{name}' is not certified by your owner key, so it is not one of your devices"),
        ));
    }
    Ok(cert.device_pub)
}

fn operands(subject: &str, cap: &str, target: &str) -> Result<([u8; 32], [u8; 32], String)> {
    let Some(owner) = crate::load_owner_key() else {
        crate::bail_usage!(
            "`--on` is for the owner device (the one you ran `tunlion init` on): only the owner key can grant on another device"
        );
    };
    let cap = cap.trim().to_ascii_lowercase();
    if !DISTRIBUTABLE.contains(&cap.as_str()) {
        crate::bail_usage!(
            "`--on` grants one of: {}. '{cap}' is not something one device can be told about another",
            DISTRIBUTABLE.join(", ")
        );
    }
    let owner_pub = owner.public_key_bytes();
    let subject_pub = fleet_device_pub(subject, &owner_pub)?;
    let target_pub = fleet_device_pub(target, &owner_pub)?;
    if subject_pub == target_pub {
        crate::bail_usage!("'{subject}' and '{target}' are the same device");
    }
    Ok((subject_pub, target_pub, cap))
}

pub(crate) fn grant_on(subject: &str, cap: &str, target: &str) -> Result<()> {
    let (subject_pub, target_pub, cap) = operands(subject, cap, target)?;
    crate::devices_store::store().fleet_grant_add(&target_pub, &subject_pub, &cap, 0)?;
    let weight = if cap == "shell" {
        " OWNER-EQUIVALENT on that device: they can act as you there."
    } else {
        ""
    };
    crate::outln!("granted '{cap}' to '{subject}' on '{target}'.{weight}");
    crate::ui::say(&format!(
        "  signed with your owner key and delivered to '{target}' while this device's `tunlion up` is linked to it; a deny recorded on '{target}' still wins"
    ));
    // This device cannot know the target's own fleet.owner_grants, so say what
    // it takes there rather than claim the grant is in force.
    crate::ui::say(&format!("  {}", takes_effect_note(&cap, target)));
    Ok(())
}

/// The one line `grant --on` prints about the target's `fleet.owner_grants`.
pub(crate) fn takes_effect_note(cap: &str, target: &str) -> String {
    if cap == "shell" {
        format!(
            "takes effect only if '{target}' allows owner shell grants: on '{target}', `tunlion set fleet.owner_grants all` (default: files)"
        )
    } else {
        format!(
            "takes effect only if '{target}' allows owner {cap} grants (its default, fleet.owner_grants=files, does; off refuses them)"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::takes_effect_note;

    #[test]
    fn grant_on_says_the_target_decides_without_claiming_it_applies() {
        let shell = takes_effect_note("shell", "charlie");
        assert!(shell.contains("takes effect only if 'charlie' allows"));
        assert!(shell.contains("fleet.owner_grants all"));
        for cap in ["transfer", "mount"] {
            let n = takes_effect_note(cap, "charlie");
            assert!(n.contains(&format!("allows owner {cap} grants")), "{n}");
            assert!(n.contains("fleet.owner_grants=files"));
        }
        for n in [shell, takes_effect_note("mount", "x")] {
            assert!(!n.contains('\u{2014}') && !n.contains('\u{2013}'), "no dashes: {n}");
        }
    }
}

pub(crate) fn revoke_on(subject: &str, cap: &str, target: &str) -> Result<()> {
    let (subject_pub, target_pub, cap) = operands(subject, cap, target)?;
    let removed = crate::devices_store::store().fleet_grant_remove(&target_pub, &subject_pub, &cap)?;
    if !removed {
        return Err(err(
            ExitKind::Usage,
            format!("'{subject}' holds no '{cap}' grant on '{target}' from this device"),
        ));
    }
    crate::outln!("revoked '{cap}' from '{subject}' on '{target}'.");
    crate::ui::say(&format!(
        "  '{target}' drops it on the next delivery from this device's `tunlion up`; if they cannot reach each other, it lapses when the last delivered set expires (at most {} minutes)",
        crate::roster::roster_ttl_secs().div_ceil(60)
    ));
    Ok(())
}
