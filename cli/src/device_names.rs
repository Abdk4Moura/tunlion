//! Device names: one spelling rule, and a forgiving lookup.
//!
//! The hostname default already goes through `short_host_label` (lowercase,
//! `[a-z0-9-]`, everything else to `-`, dashes collapsed and trimmed), so it
//! works as a `<name>.mesh` label. A name the person TYPES (`add "pop os"`,
//! `--name`, `devices rename`) used to keep its spaces, which made a name that
//! could never be a mesh label and could only be typed back with quotes. Every
//! user-supplied name now takes the same rule, and the person is told the final
//! name when it changed.
//!
//! Lookups are forgiving the other way round: an exact match first, else a
//! match after normalizing and ignoring dashes and case (`popos`, `PopOS` and
//! `"pop os"` all find `pop-os`), but only when exactly ONE device matches. Two
//! candidates is a question for the person, never a guess, so it is refused
//! with the list and the unknown-device exit code. Stored names are never
//! renamed: a record saved as `pop os` before this rule still resolves, both
//! exactly and by the forgiving match.

use crate::cli_def::{Cmd, DevicesAction};
use crate::ui;
use anyhow::Result;

/// The label rule for a name a person typed. Same character rule as the
/// hostname default (`short_host_label`), applied to the whole input: a typed
/// name is not a hostname, so `pop.os` means `pop-os`, not the first DNS label
/// `pop`. None when nothing usable is left (`"!!!"`), which the caller refuses
/// rather than silently storing `device`. Pure.
pub(crate) fn user_label(input: &str) -> Option<String> {
    let mut label = String::new();
    for c in input.trim().chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' };
        if c == '-' && (label.is_empty() || label.ends_with('-')) {
            continue;
        }
        label.push(c);
    }
    let label: String = label.trim_end_matches('-').chars().take(63).collect();
    let label = label.trim_end_matches('-').to_string();
    (!label.is_empty()).then_some(label)
}

/// The comparison key for the forgiving lookup: the label with its dashes
/// dropped, so `pop-os`, `popos`, `PopOS` and `pop os` share one key. Pure.
pub(crate) fn match_key(name: &str) -> String {
    user_label(name).unwrap_or_default().replace('-', "")
}

/// What a typed device name resolves to among the known names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// Typed exactly as stored.
    Exact(String),
    /// Not exact, but exactly one known name has the same key.
    Unique(String),
    /// Several known names share the key: the person must say which.
    Ambiguous(Vec<String>),
    /// Nothing matches; the verb's own unknown-device answer applies.
    NoMatch,
}

/// Resolve `input` against `known`. Pure.
pub(crate) fn resolve(input: &str, known: &[String]) -> Resolution {
    if let Some(n) = known.iter().find(|n| n.as_str() == input) {
        return Resolution::Exact(n.clone());
    }
    let key = match_key(input);
    if key.is_empty() {
        return Resolution::NoMatch;
    }
    let mut hits: Vec<String> = Vec::new();
    for n in known {
        if match_key(n) == key && !hits.contains(n) {
            hits.push(n.clone());
        }
    }
    match hits.len() {
        0 => Resolution::NoMatch,
        1 => Resolution::Unique(hits.remove(0)),
        _ => Resolution::Ambiguous(hits),
    }
}

/// The refusal for an ambiguous name. Pure.
pub(crate) fn ambiguous_msg(input: &str, hits: &[String]) -> String {
    format!(
        "no device named '{input}' exactly, and several devices match it: {}. Use the exact name\n  tunlion devices   to see them",
        hits.join(", ")
    )
}

/// Every device name this machine knows: each stored record (with or without
/// a pair secret) and each sibling on the owner-signed roster.
pub(crate) fn known_device_names() -> Vec<String> {
    let mut known: Vec<String> = std::fs::read_to_string(crate::devices_store::devices_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<serde_json::Value>>(&raw).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["name"].as_str().map(str::to_string))
        .collect();
    for (n, _) in crate::devices_load() {
        if !known.contains(&n) {
            known.push(n);
        }
    }
    for n in crate::roster::roster_device_names() {
        if !known.contains(&n) {
            known.push(n);
        }
    }
    known
}

/// Resolve one device argument against `known`: the canonical name for an
/// exact or unique match, the input unchanged when nothing matches (so each
/// verb keeps its own unknown-device answer), and exit 3 when it is ambiguous.
pub(crate) fn resolve_arg_in(input: &str, known: &[String]) -> Result<String> {
    match resolve(input, known) {
        Resolution::Exact(n) => Ok(n),
        Resolution::Unique(n) => {
            ui::say(&ui::paint(ui::Tone::Dim, &format!("  {input} \u{2192} {n}")));
            Ok(n)
        }
        Resolution::Ambiguous(hits) => Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::UnknownDevice,
            ambiguous_msg(input, &hits),
        )),
        Resolution::NoMatch => Ok(input.to_string()),
    }
}

/// Normalize a name the person is GIVING a device. Says the final name when it
/// changed; refuses a name with nothing usable in it (exit 2).
pub(crate) fn normalize_new_name(input: &str) -> Result<String> {
    // Blank keeps its existing meaning at each verb ("not given").
    if input.trim().is_empty() {
        return Ok(input.to_string());
    }
    let Some(label) = user_label(input) else {
        crate::bail_usage!(
            "'{input}' has no letters or digits to name a device with; use letters, digits and dashes, e.g. pop-os"
        );
    };
    if label != input {
        ui::say(&ui::paint(ui::Tone::Dim, &format!("  named {label}")));
    }
    Ok(label)
}

/// `device:rest` targets (`forward laptop:5432`, `sync dir laptop:dir`):
/// resolve the device part, keep the rest byte for byte.
fn resolve_prefixed(target: &str, known: &[String], split_last: bool) -> Result<String> {
    let at = if split_last { target.rfind(':') } else { target.find(':') };
    match at {
        Some(i) if i > 0 => {
            let (dev, rest) = target.split_at(i);
            Ok(format!("{}{rest}", resolve_arg_in(dev, known)?))
        }
        _ => Ok(target.to_string()),
    }
}

/// The words `add` reads as WHO KIND rather than a device name.
fn is_add_kind(who: &str) -> bool {
    matches!(who.trim().to_ascii_lowercase().as_str(), "" | "device" | "person" | "runner")
}

/// Apply both rules to a parsed command, once, before it runs: names the
/// person gives a device are normalized, and names that select an existing
/// device are resolved to the stored spelling.
pub(crate) fn canonicalize_cmd(cmd: Cmd) -> Result<Cmd> {
    // Read the store lazily: most verbs name no device.
    let mut cache: Option<Vec<String>> = None;
    let mut known = || -> Vec<String> { cache.get_or_insert_with(known_device_names).clone() };
    let opt = |v: Option<String>, known: &mut dyn FnMut() -> Vec<String>| -> Result<Option<String>> {
        v.map(|d| resolve_arg_in(&d, &known())).transpose()
    };
    Ok(match cmd {
        Cmd::Shell { peer, ssh, args } => Cmd::Shell { peer: opt(peer, &mut known)?, ssh, args },
        Cmd::Exec { peer, shell, tty, cwd, env, argv } => {
            Cmd::Exec { peer: opt(peer, &mut known)?, shell, tty, cwd, env, argv }
        }
        Cmd::Reach { dev, until_direct, timeout, json, socks } => {
            // `reach dev:port` is refused by the verb itself with a pointer to
            // `forward`; leave that spelling alone so the message is unchanged.
            let dev = match dev {
                Some(d) if !d.contains(':') => Some(resolve_arg_in(&d, &known())?),
                other => other,
            };
            Cmd::Reach { dev, until_direct, timeout, json, socks }
        }
        Cmd::Forward { target, lport, stdio, socks, port, bind, http_port, allow_remote } => Cmd::Forward {
            target: resolve_prefixed(&target, &known(), true)?,
            lport,
            stdio,
            socks,
            port,
            bind,
            http_port,
            allow_remote,
        },
        Cmd::Netcat { peer, rport } => Cmd::Netcat { peer: resolve_arg_in(&peer, &known())?, rport },
        Cmd::Doctor { device, watch, repeat, timeout, json } => {
            Cmd::Doctor { device: opt(device, &mut known)?, watch, repeat, timeout, json }
        }
        Cmd::Grant { device, capability, tag, user, on } => {
            // With --tag the single positional is the capability, not a device.
            let device = if tag.is_some() { device } else { opt(device, &mut known)? };
            // `--on <target>` names a device too (the owner grants ON it).
            let on = opt(on, &mut known)?;
            Cmd::Grant { device, capability, tag, user, on }
        }
        Cmd::Revoke { device, capability, user, on } => {
            let on = opt(on, &mut known)?;
            Cmd::Revoke { device: resolve_arg_in(&device, &known())?, capability, user, on }
        }
        Cmd::Promote { device, to, json } => Cmd::Promote { device: opt(device, &mut known)?, to, json },
        Cmd::Demote { device, to, json } => Cmd::Demote { device: opt(device, &mut known)?, to, json },
        Cmd::Backup { peer, source, dest, exclude, dry_run, delete, options } => {
            let peer = resolve_arg_in(&peer, &known())?;
            Cmd::Backup { peer, source, dest, exclude, dry_run, delete, options }
        }
        Cmd::Sync { local, dest, delete, dry_run, json_lines } => {
            Cmd::Sync { local, dest: resolve_prefixed(&dest, &known(), false)?, delete, dry_run, json_lines }
        }
        Cmd::Addr { device, v4 } => Cmd::Addr { device: opt(device, &mut known)?, v4 },
        Cmd::Expose { port, to, peer, list, off } => {
            let peer = peer.into_iter().map(|p| resolve_arg_in(&p, &known())).collect::<Result<Vec<_>>>()?;
            Cmd::Expose { port, to, peer, list, off }
        }
        Cmd::Devices { action, json, caps } => {
            let caps = match caps {
                Some(c) if !c.is_empty() => Some(resolve_arg_in(&c, &known())?),
                other => other,
            };
            let action = match action {
                Some(DevicesAction::Forget { name }) => {
                    Some(DevicesAction::Forget { name: resolve_arg_in(&name, &known())? })
                }
                Some(DevicesAction::Rename { old, new }) => Some(DevicesAction::Rename {
                    old: resolve_arg_in(&old, &known())?,
                    new: normalize_new_name(&new)?,
                }),
                Some(DevicesAction::Vouch { a, b }) => Some(DevicesAction::Vouch {
                    a: resolve_arg_in(&a, &known())?,
                    b: resolve_arg_in(&b, &known())?,
                }),
                None => None,
            };
            Cmd::Devices { action, json, caps }
        }
        Cmd::Set { key, value, peer, dry_run, reset, unset, hard, soft } => {
            let peer = peer.into_iter().map(|p| resolve_arg_in(&p, &known())).collect::<Result<Vec<_>>>()?;
            // This device's own name is the name every peer files it under by
            // default, so it takes the same rule.
            let value = match (key.as_deref(), value) {
                (Some("name"), Some(v)) => Some(normalize_new_name(&v)?),
                (_, v) => v,
            };
            Cmd::Set { key, value, peer, dry_run, reset, unset, hard, soft }
        }
        Cmd::Init { name, inbox, recovery_file, recovery_fd, background, no_background } => Cmd::Init {
            name: name.map(|n| normalize_new_name(&n)).transpose()?,
            inbox,
            recovery_file,
            recovery_fd,
            background,
            no_background,
        },
        Cmd::Send { paths, code, word, remember, room, to, name, timeout, auth_key } => {
            let to = opt(to, &mut known)?;
            let remember = remember.map(|r| normalize_new_name(&r)).transpose()?;
            Cmd::Send { paths, code, word, remember, room, to, name, timeout, auth_key }
        }
        Cmd::Add { who, name, word, for_, allow, expires, reuse, out, via, withdraw } => {
            // `add <who>` names a device of yours, or is a kind word. A name is
            // normalized, then matched to an existing device so `add popos`
            // re-adds the `pop-os` you already have instead of a second row.
            let norm_select = |v: String, known: &[String]| -> Result<String> {
                if is_add_kind(&v) {
                    return Ok(v);
                }
                match resolve(&v, known) {
                    Resolution::Exact(n) => Ok(n),
                    Resolution::Unique(n) => {
                        ui::say(&ui::paint(ui::Tone::Dim, &format!("  {v} \u{2192} {n}")));
                        Ok(n)
                    }
                    Resolution::Ambiguous(hits) => Err(crate::exit_codes::err(
                        crate::exit_codes::ExitKind::UnknownDevice,
                        ambiguous_msg(&v, &hits),
                    )),
                    Resolution::NoMatch => normalize_new_name(&v),
                }
            };
            let who = who.map(|w| norm_select(w, &known())).transpose()?;
            let for_ = for_.map(|f| norm_select(f, &known())).transpose()?;
            let name = name.map(|n| norm_select(n, &known())).transpose()?;
            // `--withdraw` names an INVITATION, not a device: it is matched
            // against the outstanding invitations, never resolved to a device
            // record (a joined device often carries the same name).
            Cmd::Add { who, name, word, for_, allow, expires, reuse, out, via, withdraw }
        }
        Cmd::Join { code, invite_file, invite_fd, name, to } => {
            let name = name.map(|n| normalize_new_name(&n)).transpose()?;
            Cmd::Join { code, invite_file, invite_fd, name, to }
        }
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_typed_name_takes_the_hostname_rule() {
        assert_eq!(user_label("pop os").as_deref(), Some("pop-os"));
        assert_eq!(user_label("Pop OS").as_deref(), Some("pop-os"));
        assert_eq!(user_label("  Kabir's  MacBook!! ").as_deref(), Some("kabir-s-macbook"));
        assert_eq!(user_label("pop.os").as_deref(), Some("pop-os"));
        assert_eq!(user_label("--a__b--").as_deref(), Some("a-b"));
        assert_eq!(user_label("pop-os").as_deref(), Some("pop-os"));
        assert_eq!(user_label("!!!"), None);
        assert_eq!(user_label(""), None);
        // Same characters as the hostname default for a single label.
        for h in ["pop-os", "Kabir-MacBook", "desk_1", "Ünïcode box"] {
            assert_eq!(user_label(h).unwrap(), crate::short_host_label(h), "{h}");
        }
        // A mesh label is at most 63 characters.
        assert!(user_label(&"a".repeat(80)).unwrap().len() <= 63);
    }

    #[test]
    fn exact_match_wins_even_when_a_fuzzy_one_exists() {
        let known = names(&["pop-os", "popos"]);
        assert_eq!(resolve("popos", &known), Resolution::Exact("popos".into()));
        assert_eq!(resolve("pop-os", &known), Resolution::Exact("pop-os".into()));
    }

    #[test]
    fn forgiving_lookup_finds_the_one_device() {
        let known = names(&["pop-os", "desk", "pixel-7"]);
        for typed in ["popos", "PopOS", "pop os", "POP-OS", "pop_os"] {
            assert_eq!(resolve(typed, &known), Resolution::Unique("pop-os".into()), "{typed}");
        }
        assert_eq!(resolve("Pixel 7", &known), Resolution::Unique("pixel-7".into()));
        assert_eq!(resolve("laptop", &known), Resolution::NoMatch);
        assert_eq!(resolve("!!!", &known), Resolution::NoMatch);
    }

    #[test]
    fn two_candidates_are_never_guessed() {
        let known = names(&["pop-os", "popos-2", "pop-o-s"]);
        match resolve("PopOS", &known) {
            Resolution::Ambiguous(hits) => {
                assert_eq!(hits, names(&["pop-os", "pop-o-s"]));
                let msg = ambiguous_msg("PopOS", &hits);
                assert!(msg.contains("pop-os") && msg.contains("pop-o-s"), "{msg}");
                // Classified as an unknown device (exit 3) by its text too.
                assert!(msg.starts_with("no device named"), "{msg}");
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        let err = resolve_arg_in("PopOS", &known).unwrap_err();
        assert_eq!(crate::exit_codes::classify(&err), crate::exit_codes::ExitKind::UnknownDevice);
    }

    #[test]
    fn a_legacy_name_with_a_space_still_resolves() {
        // Saved before the rule; never renamed behind the person's back.
        let known = names(&["pop os", "desk"]);
        assert_eq!(resolve("pop os", &known), Resolution::Exact("pop os".into()));
        assert_eq!(resolve("pop-os", &known), Resolution::Unique("pop os".into()));
        assert_eq!(resolve("popos", &known), Resolution::Unique("pop os".into()));
    }

    #[test]
    fn device_prefixed_targets_keep_their_tail() {
        let known = names(&["pop-os"]);
        assert_eq!(resolve_prefixed("PopOS:5432", &known, true).unwrap(), "pop-os:5432");
        assert_eq!(resolve_prefixed("popos:dir/a:b", &known, false).unwrap(), "pop-os:dir/a:b");
        assert_eq!(resolve_prefixed("nobody:22", &known, true).unwrap(), "nobody:22");
        assert_eq!(resolve_prefixed("5432", &known, true).unwrap(), "5432");
    }

    #[test]
    fn a_name_with_nothing_usable_is_refused() {
        let err = normalize_new_name("!!!").unwrap_err();
        assert_eq!(crate::exit_codes::classify(&err), crate::exit_codes::ExitKind::Usage);
        assert_eq!(normalize_new_name("Pop OS").unwrap(), "pop-os");
    }

    #[test]
    fn add_kind_words_are_not_names() {
        for k in ["device", "person", "runner", "", "Device"] {
            assert!(is_add_kind(k), "{k}");
        }
        assert!(!is_add_kind("pop-os"));
    }
}
