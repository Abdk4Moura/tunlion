// Surface 3a-3e: `devices` — full/empty/degraded/falling-out/promote.
//
// Pure render functions for the device listing surfaces.

use crate::ui::{self, Tone};

/// A device entry for rendering.
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub name: String,
    pub tier: DeviceTier,
    /// A warm link is held open RIGHT NOW. `None` = the warm-link data is
    /// unavailable on this platform/daemon (no control channel), so the row
    /// omits the status rather than asserting a falsehood (#217).
    pub online: Option<bool>,
    /// The held link's route word when it is not the ordinary one: `lan` for
    /// a link met by local discovery with no server.
    pub route: Option<String>,
    pub caps_summary: String,    // e.g. "OWNER-EQUIVALENT shell reach:8080 inbox"
    pub countdown: String,       // e.g. "expires in 4m" or "expired 2026-05-01"
                                 // Not "renews in ...": nothing renews (#236).
    pub last_seen: Option<String>, // e.g. "2h ago"
}

/// Device tier (fleet / external / needs-review / mesh-roster).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTier {
    Fleet,
    External,
    NeedsReview,
    /// A sibling learned from the owner-signed mesh roster: known by name and
    /// key, but no direct channel yet (sibling-to-sibling is not in v1). Liveness
    /// is unknown (#217), so the row must not assert online/idle/offline.
    MeshRoster,
    /// This device has no identity of its own (it paired by code and never
    /// joined anyone), so "other people" and "needs review" mean nothing here:
    /// the honest word is paired.
    Paired,
    /// Enrolled with a runner invitation (a CI lease, a borrowed box): listed
    /// while it exists and removed when its lease or offline budget ends or it
    /// departs. Never a fleet member, so it is kept out of FLEET.
    Ephemeral,
}

/// `render_devices_for` on the owner device.
#[cfg(test)]
pub fn render_devices(devices: &[DeviceEntry], pending_requests: usize, roster_heading: Option<String>) -> String {
    render_devices_for(devices, pending_requests, roster_heading, true)
}

/// Render the full device list. `roster_heading` is the already-honest heading
/// for the mesh-roster section (epoch + when received, or the expired note);
/// `Some` renders the section, `None` omits it.
/// The one-line resolution under a NEEDS REVIEW row. `owner_here`: this
/// device holds the owner key, so `add` here is the step that certifies.
/// Pure.
pub fn review_hint(name: &str, owner_here: bool) -> String {
    let n = crate::refusal::word(name);
    let add = if owner_here {
        format!("`tunlion add {n}`")
    } else {
        format!("`tunlion add {n}` on your owner device")
    };
    format!("\u{21b3} yours? {add}, then `tunlion join <code>` on {n} \u{b7} not yours? keep it, or `tunlion devices forget {n}`")
}

/// Render the full device list. `owner_here` picks where the NEEDS REVIEW
/// hint sends you (see `review_hint`).
pub fn render_devices_for(
    devices: &[DeviceEntry],
    pending_requests: usize,
    roster_heading: Option<String>,
    owner_here: bool,
) -> String {
    if devices.is_empty() && pending_requests == 0 && roster_heading.is_none() {
        return render_empty();
    }

    let mut lines = vec![];

    if devices.is_empty() && roster_heading.is_none() {
        lines.push(ui::paint(Tone::Dim, "  No devices yet."));
        lines.push(String::new());
    }

    // Fleet section
    let fleet: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::Fleet).collect();
    if !fleet.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Brand, ui::glyph_fleet()),
            ui::header(Tone::Brand, Tone::Dim, "FLEET  /  your devices, permissive within scope")
        ));
        for d in &fleet {
            lines.push(render_device_row(d));
        }
        lines.push(String::new());
    }

    // Ephemeral section: CI leases and borrowed boxes, apart from the fleet.
    let ephemeral: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::Ephemeral).collect();
    if !ephemeral.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Dim, ui::glyph_extern()),
            ui::header(Tone::Bold, Tone::Dim, "EPHEMERAL  /  CI and borrowed boxes, removed when they end")
        ));
        for d in &ephemeral {
            lines.push(render_device_row(d));
        }
        lines.push(String::new());
    }

    // External section
    let externs: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::External).collect();
    if !externs.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Dim, ui::glyph_extern()),
            ui::header(Tone::Bold, Tone::Dim, "EXTERNAL  /  other people, time-boxed, deny-by-default")
        ));
        for d in &externs {
            lines.push(render_device_row(d));
        }
        lines.push(String::new());
    }

    // Mesh-roster section: siblings learned from the owner's signed roster.
    // Rendered whenever a roster was received (fresh OR expired), so "no other
    // devices in the mesh" and "roster expired" read differently from "no
    // roster yet" (which omits the section entirely).
    let roster: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::MeshRoster).collect();
    if let Some(heading) = roster_heading {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Brand, ui::glyph_mesh()),
            ui::header(Tone::Brand, Tone::Dim, &heading)
        ));
        if roster.is_empty() {
            lines.push(ui::paint(Tone::Dim, "     (no other devices listed)"));
        } else {
            for d in &roster {
                lines.push(render_device_row(d));
            }
        }
        lines.push(String::new());
    }

    // Paired section: a device with no identity of its own.
    let paired: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::Paired).collect();
    if !paired.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Brand, ui::glyph_extern()),
            ui::header(Tone::Bold, Tone::Dim, "PAIRED  /  you can send each other files")
        ));
        for d in &paired {
            lines.push(render_device_row(d));
        }
        lines.push(String::new());
    }

    // Needs-review section
    let review: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::NeedsReview).collect();
    if !review.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Warn, ui::glyph_review()),
            ui::header(Tone::Warn, Tone::Dim, "NEEDS REVIEW  /  paired, not yet one of your devices")
        ));
        for d in &review {
            lines.push(render_device_row(d));
            // One line per device, both answers to "whose is it", each an exact
            // command (#240: never a verb that does not exist; eval item 7:
            // never "re-pair" with no command).
            lines.push(ui::paint(Tone::Dim, &format!("       {}", review_hint(&d.name, owner_here))));
        }
        lines.push(String::new());
    }

    // Pending requests
    if pending_requests > 0 {
        lines.push(format!(
            "  {} {} · tunlion requests",
            ui::paint(Tone::Bold, &format!("{pending_requests}")),
            ui::paint(Tone::Dim, "requests waiting")
        ));
    }

    // Authoritative note
    lines.push(ui::paint(Tone::Dim, "  This is a local index; each device's own capability list is authoritative."));

    lines.join("\n")
}

fn render_device_row(d: &DeviceEntry) -> String {
    let glyph = match d.tier {
        DeviceTier::Fleet => ui::paint(Tone::Brand, ui::glyph_fleet()),
        DeviceTier::External => ui::paint(Tone::Dim, ui::glyph_extern()),
        DeviceTier::NeedsReview => ui::paint(Tone::Warn, ui::glyph_review()),
        DeviceTier::MeshRoster => ui::paint(Tone::Brand, ui::glyph_mesh()),
        DeviceTier::Paired => ui::paint(Tone::Brand, ui::glyph_extern()),
        DeviceTier::Ephemeral => ui::paint(Tone::Dim, ui::glyph_extern()),
    };
    // #217 for the mesh: a sibling we have never contacted has UNKNOWN liveness,
    // never "idle"/"offline". The roster carries name + key only, so the row says
    // what is true (known via the owner, no direct channel yet) and nothing else.
    let status = match d.online {
        Some(true) => match d.route.as_deref() {
            Some(r) => ui::paint(Tone::Ok, &format!("online {r}")),
            None => ui::paint(Tone::Ok, "online"),
        },
        Some(false) if d.tier == DeviceTier::MeshRoster => ui::paint(Tone::Dim, "via owner"),
        // #217: "a warm link is NOT held open right now" is the normal, healthy
        // idle state, not an absence. "offline" promised far more than the value
        // supports and read as a failure next to "last seen just now".
        Some(false) => ui::paint(Tone::Dim, "idle"),
        None => "".to_string(),
    };
    let mut line = format!(
        "     {glyph} {:<16} {:<8} {:<24} {}",
        d.name, status, d.caps_summary, d.countdown
    );
    if let Some(ref seen) = d.last_seen {
        line.push_str(&format!("  {}", ui::paint(Tone::Dim, &format!("(last seen {seen})"))));
    }
    line
}

/// What an invitation was made for, in the words `add` uses. Pure.
pub fn invitation_kind_word(kind: Option<&str>) -> &'static str {
    match kind {
        Some("device") => "your device",
        Some("person") => "a person",
        Some("runner") => "runner, temporary",
        _ => "invitation",
    }
}

/// One INVITATIONS row: name, kind, ceiling, uses left, expiry, age. Pure but
/// for paint.
pub fn render_invitation_row(o: &crate::armed::Outstanding, now: u64) -> String {
    format!(
        "     {} {}",
        ui::paint(Tone::Warn, ui::glyph_echo()),
        invitation_row_text(o, now)
    )
}

/// The row's text without its indent and glyph, for a picker. Pure but for
/// paint.
pub fn invitation_row_text(o: &crate::armed::Outstanding, now: u64) -> String {
    let allow = match &o.allow {
        Some(a) if a.is_empty() => "nothing".to_string(),
        Some(a) => a
            .iter()
            .map(|c| if c == "shell" { "OWNER-EQUIVALENT shell".to_string() } else { c.clone() })
            .collect::<Vec<_>>()
            .join(" "),
        None => "ceiling not recorded".to_string(),
    };
    let ends = format!(
        "expires in {}",
        crate::device_view::remaining_span(o.expires.saturating_sub(now))
    );
    let mut line = format!(
        "{:<16} {:<18} {:<22} {:<22} {}",
        o.label(),
        invitation_kind_word(o.kind.as_deref()),
        allow,
        o.uses_phrase(),
        ends
    );
    if let Some(made) = o.created {
        line.push_str(&format!(
            "  {}",
            ui::paint(Tone::Dim, &format!("(made {})", crate::reset_hints::ago(now.saturating_sub(made))))
        ));
    }
    line
}

/// The INVITATIONS section of `devices`: every invitation that can still be
/// claimed, and the one command that withdraws one. `None` when there are
/// none, so the section is omitted rather than shown empty. Pure but for
/// paint.
pub fn render_invitations(list: &[crate::armed::Outstanding], now: u64) -> Option<String> {
    if list.is_empty() {
        return None;
    }
    let mut lines = vec![format!(
        "  {} {}",
        ui::paint(Tone::Warn, ui::glyph_echo()),
        ui::header(
            Tone::Warn,
            Tone::Dim,
            "INVITATIONS  /  not used up yet: anyone holding the file can still join"
        )
    )];
    for o in list {
        lines.push(render_invitation_row(o, now));
    }
    lines.push(ui::paint(
        Tone::Dim,
        "       withdraw one so it can never be claimed: tunlion add --withdraw <name>",
    ));
    lines.push(String::new());
    Some(lines.join("\n"))
}

/// Put the INVITATIONS block into a rendered device list: above the closing
/// "local index" note when the list has one, after it otherwise. Pure.
pub fn with_invitations(rendered: &str, block: &str) -> String {
    match rendered.rsplit_once('\n') {
        Some((body, last)) if last.contains("This is a local index") => {
            format!("{body}\n{block}\n{last}")
        }
        _ => format!("{rendered}\n\n{block}"),
    }
}

/// Render the empty devices list.
pub fn render_empty() -> String {
    format!(
        "No devices yet.\n\
         Add in person:        tunlion add\n\
         Invite securely:      tunlion add --for person"
    )
}

/// Render the degraded / no-primary-online message.
pub fn render_degraded(offline_primaries: &[(&str, &str)], expiry: &str) -> String {
    let primaries_str = offline_primaries.iter()
        .map(|(name, last_seen)| format!("{name} (offline {last_seen})"))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "{warn} No primary online. Existing grants keep working until their certificate expires.\n\
         {until} Bring a primary online before then to issue a fresh invitation.\n\
         {primaries}",
        warn = ui::paint(Tone::Warn, ui::glyph_extern()),
        until = format!("     until {expiry}"),
        primaries = ui::paint(Tone::Dim, &format!("     Primaries: {primaries_str}")),
    )
}

/// Render a device falling out (cert past renewal).
pub fn render_falling_out(name: &str, expiry: &str) -> String {
    format!(
        "     {} {:<16} {}",
        ui::paint(Tone::Warn, ui::glyph_fleet()),
        name,
        ui::paint(Tone::Warn, &format!("⚠ expires {expiry}, not renewing (no signer)"))
    )
}

/// Render a lapsed device (dimmed "left" line).
pub fn render_lapsed(name: &str, expiry: &str) -> String {
    format!(
        "     . {name:<16} -        -        {}",
        ui::paint(Tone::Dim, &format!("left: cert expired {expiry} / add again to restore"))
    )
}

/// Render the promote dialog.
pub fn render_promote(device_name: &str) -> String {
    format!(
        "{warn} {name} was paired before scoped trust. Sort it in:\n\
         {fleet}\n\
         {external}\n\
            {promote}   {cancel}",
        warn = ui::paint(Tone::Warn, ui::glyph_review()),
        name = device_name,
        fleet = format!("     {} fleet / my own device, permissive within scope", ui::paint(Tone::Dim, "(o)")),
        external = format!("     {} external / someone else, pick caps + an expiry", ui::paint(Tone::Dim, "( )")),
        promote = ui::paint(Tone::Bold, "[ Promote ]"),
        cancel = ui::paint(Tone::Dim, "[ Cancel ]"),
    )
}

/// Render the promote success.
pub fn render_promote_success(device_name: &str) -> String {
    format!(
        "{ok} {name} is now a fleet device. Its certificate remains time-bounded.",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        name = device_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_devices() {
        let s = render_empty();
        assert!(s.contains("No devices yet"), "must show empty message");
        assert!(s.contains("tunlion add"), "must suggest add");
        assert!(s.contains("tunlion add --for person"), "must suggest the bounded invite");
    }

    #[test]
    fn full_device_list() {
        let devices = vec![
            DeviceEntry {
                name: "pixel-7".into(),
                tier: DeviceTier::Fleet,
                online: Some(true),
                route: None,
                caps_summary: "OWNER-EQUIVALENT shell reach:8080 inbox".into(),
                countdown: "expires in 9m".into(),
                last_seen: None,
            },
            DeviceEntry {
                name: "carol".into(),
                tier: DeviceTier::External,
                online: Some(true),
                route: None,
                caps_summary: "send→you".into(),
                countdown: "expires in 4m".into(),
                last_seen: None,
            },
        ];
        let s = render_devices(&devices, 0, None);
        assert!(s.contains("FLEET"), "must show fleet section");
        assert!(s.contains("EXTERNAL"), "must show external section");
        assert!(s.contains("pixel-7"), "must show fleet device");
        assert!(s.contains("carol"), "must show external device");
    }

    #[test]
    fn an_ephemeral_device_is_listed_apart_from_the_fleet() {
        let devices = vec![
            DeviceEntry {
                name: "laptop".into(),
                tier: DeviceTier::Fleet,
                online: Some(true),
                caps_summary: "inbox mount".into(),
                countdown: "cert expires in 80d".into(),
                last_seen: None,
            },
            DeviceEntry {
                name: "ci-worker-3".into(),
                tier: DeviceTier::Ephemeral,
                online: Some(true),
                caps_summary: "inbox OWNER-EQUIVALENT shell".into(),
                countdown: "cert expires in 2h".into(),
                last_seen: Some("just now".into()),
            },
        ];
        let s = crate::ui::strip_ansi(&render_devices(&devices, 0, None));
        let fleet = s.find("FLEET").expect("fleet section");
        let eph = s.find("EPHEMERAL").expect("ephemeral section");
        let worker = s.find("ci-worker-3").expect("worker row");
        let laptop = s.find("laptop").expect("laptop row");
        assert!(fleet < laptop && laptop < eph && eph < worker, "{s}");
    }

    #[test]
    fn needs_review_section() {
        let devices = vec![
            DeviceEntry {
                name: "old-laptop".into(),
                tier: DeviceTier::NeedsReview,
                online: Some(false),
                route: None,
                caps_summary: "uncertified \u{b7} transfer".into(),
                countdown: "no certificate".into(),
                last_seen: None,
            },
        ];
        let s = render_devices(&devices, 0, None);
        assert!(s.contains("NEEDS REVIEW"), "must show review section");
        assert!(s.contains("old-laptop"), "must show review device");
        // #240: this used to assert the row said "promote to continue" and
        // printed `tunlion devices promote <name>`. The verb does not exist,
        // clap rejects it, and the owner hit exactly that on his own machines.
        // The test pinned the defect, so it is inverted: the row must state the
        // condition and prescribe no action it cannot deliver.
        assert!(!s.contains("promote"), "must not prescribe a verb that does not exist: {s}");
        assert!(!s.contains("legacy trust"), "must not leak internal jargon: {s}");
        // Eval item 7: the hint names the exact command that resolves it.
        assert!(s.contains("tunlion add old-laptop"), "must give the exact command: {s}");
        assert!(!s.contains("trusted in full"), "must not claim full trust: {s}");
        assert!(!s.contains("re-pair to scope it"), "a hint with no command: {s}");
        // Owner report: two hint lines per device was a wall. One line, both answers.
        let after_row: Vec<&str> = s.lines().skip_while(|l| !l.contains("old-laptop")).collect();
        assert!(after_row[1].contains("yours?") && after_row[1].contains("not yours?"), "{s}");
        assert!(after_row[1].contains("tunlion devices forget old-laptop"), "{s}");
        assert!(!after_row.get(2).is_some_and(|l| l.contains("\u{21b3}")), "a second hint line: {s}");
        // On a device without the owner key, `add` is sent to the owner device.
        let member = render_devices_for(&devices, 0, None, false);
        assert!(member.contains("on your owner device"), "{member}");
        assert!(!s.contains("on your owner device"), "{s}");
    }

    /// Owner report: on a device with no identity, the owner that paired it
    /// was filed under "EXTERNAL / other people, time-boxed, deny-by-default".
    #[test]
    fn a_device_with_no_identity_says_paired() {
        let devices = vec![DeviceEntry {
            name: "dovm".into(),
            tier: DeviceTier::Paired,
            online: Some(true),
            route: None,
            caps_summary: "files".into(),
            countdown: String::new(),
            last_seen: Some("just now".into()),
        }];
        let s = ui::strip_ansi(&render_devices(&devices, 0, None));
        assert!(s.contains("PAIRED  /  you can send each other files"), "{s}");
        assert!(!s.contains("EXTERNAL") && !s.contains("other people"), "{s}");
        assert!(s.contains("dovm"), "{s}");
    }

    fn invitation(name: Option<&str>, kind: &str, total: Option<Option<u64>>, uses: u64) -> crate::armed::Outstanding {
        crate::armed::Outstanding {
            key_id: "0123456789abcdef".repeat(4),
            name: name.map(str::to_string),
            kind: Some(kind.to_string()),
            allow: Some(vec!["transfer".into(), "shell".into()]),
            uses,
            total,
            expires: 10_000 + 30 * 86_400,
            created: Some(10_000 - 3_600),
        }
    }

    /// "We need to see all our invites": every outstanding invitation gets a
    /// row naming who it was for, what it allows, uses left, expiry and age,
    /// with the one command that takes it back.
    #[test]
    fn outstanding_invitations_are_listed_with_the_way_to_withdraw_them() {
        let list = vec![
            invitation(Some("ci"), "device", Some(Some(20)), 1),
            invitation(Some("alice"), "person", Some(None), 0),
            invitation(None, "runner", None, 2),
        ];
        let s = ui::strip_ansi(&render_invitations(&list, 10_000).unwrap());
        assert!(s.contains("INVITATIONS"), "{s}");
        let ci = s.lines().find(|l| l.contains(" ci ")).expect("ci row");
        assert!(ci.contains("your device") && ci.contains("19 of 20 left"), "{ci}");
        assert!(ci.contains("transfer") && ci.contains("OWNER-EQUIVALENT shell"), "{ci}");
        assert!(ci.contains("expires in 30d") && ci.contains("made 1h ago"), "{ci}");
        assert!(s.contains("alice") && s.contains("any number, not used yet"), "{s}");
        // Unnamed: listed by its id, which `add --withdraw` accepts.
        assert!(s.contains("(0123456789ab)") && s.contains("2 used"), "{s}");
        assert!(s.contains("tunlion add --withdraw <name>"), "{s}");
        assert!(!s.contains('\u{2014}') && !s.contains('\u{2013}'), "no em or en dash: {s}");
        assert_eq!(render_invitations(&[], 1_000), None, "no section when there are none");
    }

    #[test]
    fn the_invitations_block_sits_above_the_closing_note() {
        let devices = vec![DeviceEntry {
            name: "laptop".into(),
            tier: DeviceTier::Fleet,
            online: Some(true),
            route: None,
            caps_summary: "files".into(),
            countdown: String::new(),
            last_seen: None,
        }];
        let list = render_devices(&devices, 0, None);
        let out = with_invitations(&list, "BLOCK");
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.last().unwrap().contains("This is a local index"), "{out}");
        assert_eq!(lines[lines.len() - 2], "BLOCK", "{out}");
        // The empty list has no closing note: the block follows it.
        let empty = with_invitations(&render_empty(), "BLOCK");
        assert!(empty.starts_with("No devices yet.") && empty.ends_with("BLOCK"), "{empty}");
    }

    #[test]
    fn pending_requests_count() {
        let s = render_devices(&[], 2, None);
        assert!(s.contains("2"), "must show request count");
        assert!(s.contains("tunlion requests"), "must suggest tunlion requests");
    }

    #[test]
    fn degraded_no_primary() {
        let s = render_degraded(&[("pixel-7", "5d"), ("studio-mac", "2d")], "Aug 3 (in 5 days)");
        assert!(s.contains("No primary online"), "must show no-primary message");
        assert!(s.contains("pixel-7"), "must show offline primary");
        assert!(s.contains("Aug 3"), "must show expiry date");
    }

    #[test]
    fn falling_out_warning() {
        let s = render_falling_out("ci-box", "Aug 3");
        assert!(s.contains("ci-box"), "must show device name");
        assert!(s.contains("expires"), "must show expires");
        assert!(s.contains("not renewing"), "must show not-renewing");
    }

    #[test]
    fn lapsed_device() {
        let s = render_lapsed("ci-box", "Aug 3");
        assert!(s.contains("left: cert expired"), "must show lapsed reason");
        assert!(s.contains("add again to restore"), "must show restore hint");
    }

    #[test]
    fn promote_dialog() {
        let s = render_promote("old-laptop");
        assert!(s.contains("old-laptop"), "must show device name");
        assert!(s.contains("fleet"), "must show fleet option");
        assert!(s.contains("external"), "must show external option");
    }

    #[test]
    fn promote_success() {
        let s = render_promote_success("old-laptop");
        assert!(s.contains("old-laptop"), "must show device name");
        assert!(s.contains("fleet device"), "must confirm fleet status");
    }
}
