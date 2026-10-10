//! What to say when a paired device was reset and came back under a new key.
//!
//! WHY THIS EXISTS. A blind tester wiped a paired device (`reset --yes`), ran
//! `init` and `up` on it, and sent to it from the owner. The owner said "bravo
//! is offline: it did not appear on the tunlion server within 10s. Is `tunlion
//! up` running there?", which was true of the old key and useless: `up` WAS
//! running, as a new identity the old record can never find. After re-pairing
//! with `join --name bravo` the owner stored the new device as `bravo-2` (a new
//! key never takes over another key's name; the invitation authorizes an
//! enrolment, not a rename) and kept the stale `bravo` forever, with nothing
//! saying the two were the same machine or how to tidy up.
//!
//! These are the sentences for both moments. They only ever suggest commands;
//! replacing a record stays the owner's explicit act.

/// The newest record that looks like `peer` re-paired under a taken name: the
/// enrolment suffixes a new key's name as `<name>-2`, `<name>-3`, ... Pure.
pub(crate) fn successor_of<'a>(peer: &str, names: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let prefix = format!("{peer}-");
    names
        .into_iter()
        .filter_map(|n| {
            let rest = n.strip_prefix(&prefix)?;
            let k: u32 = rest.parse().ok()?;
            (k >= 2 && rest == k.to_string()).then(|| (k, n.to_string()))
        })
        .max_by_key(|(k, _)| *k)
        .map(|(_, n)| n)
}

/// The sentence a `send` to an offline known device ends with, before "Nothing
/// was sent". Pure.
pub(crate) fn offline_hint(peer: &str, successor: Option<&str>) -> String {
    match successor {
        Some(s) => format!(
            "{s} is also paired here, under a newer key: if {peer} was reset and joined again, that is the same machine. Send to {s}, and replace the stale record with `tunlion devices forget {peer}` then `tunlion devices rename {s} {peer}`."
        ),
        None => format!(
            "If {peer} was reset (its identity wiped), this key will never come back: pair it again (`tunlion add {peer}` here, `tunlion join` there), then drop the old record with `tunlion devices forget {peer}`."
        ),
    }
}

/// What `add <name>` says when `name` already belongs to a paired device:
/// the invitation it mints cannot reuse the name for a new key. Pure.
pub(crate) fn name_taken_note(name: &str, last_seen: Option<&str>) -> String {
    format!(
        "{name} is already paired here{}. If this invitation is for the same machine after a reset, forget the old record first (`tunlion devices forget {name}`); otherwise the new device is stored as {name}-2.",
        last_seen.map(|s| format!(" (last seen {s})")).unwrap_or_default()
    )
}

/// "just now", "5m ago", "3h ago", "2d ago" for an age in seconds. Pure.
pub(crate) fn ago(secs: u64) -> String {
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_read_like_devices() {
        assert_eq!(ago(5), "just now");
        assert_eq!(ago(300), "5m ago");
        assert_eq!(ago(3 * 3600), "3h ago");
        assert_eq!(ago(2 * 86_400 + 5), "2d ago");
    }

    #[test]
    fn the_newest_suffixed_record_is_the_successor() {
        let names = ["bravo", "bravo-2", "bravo-3", "bravo-x", "bravo-03", "bravo-1", "alpha-2"];
        assert_eq!(successor_of("bravo", names).as_deref(), Some("bravo-3"));
        assert_eq!(successor_of("alpha", names).as_deref(), Some("alpha-2"));
        assert_eq!(successor_of("charlie", names), None);
        // Not a suffix the enrolment writes: "-1", leading zeros, words.
        assert_eq!(successor_of("bravo", ["bravo-1", "bravo-02", "bravo-new"]), None);
    }

    #[test]
    fn the_hints_name_the_commands_that_fix_it() {
        let reset = offline_hint("bravo", None);
        assert!(reset.contains("reset") && reset.contains("tunlion devices forget bravo"), "{reset}");
        assert!(reset.contains("tunlion add bravo") && reset.contains("tunlion join"), "{reset}");
        let repaired = offline_hint("bravo", Some("bravo-2"));
        assert!(repaired.contains("Send to bravo-2"), "{repaired}");
        assert!(repaired.contains("tunlion devices rename bravo-2 bravo"), "{repaired}");
        let taken = name_taken_note("bravo", Some("3h ago"));
        assert!(taken.contains("last seen 3h ago") && taken.contains("bravo-2"), "{taken}");
        assert!(taken.contains("tunlion devices forget bravo"), "{taken}");
    }
}
