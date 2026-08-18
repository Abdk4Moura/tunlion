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
    pub caps_summary: String,    // e.g. "OWNER-EQUIVALENT shell reach:8080 inbox"
    pub countdown: String,       // e.g. "expires in 4m" or "expired 2026-05-01"
                                 // Not "renews in ...": nothing renews (#236).
    pub last_seen: Option<String>, // e.g. "2h ago"
    pub needs_promote: bool,
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
}

/// Render the full device list. `roster_heading` is the already-honest heading
/// for the mesh-roster section (epoch + when received, or the expired note);
/// `Some` renders the section, `None` omits it.
pub fn render_devices(devices: &[DeviceEntry], pending_requests: usize, roster_heading: Option<String>) -> String {
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
            ui::paint(Tone::Brand, "FLEET  /  your devices, permissive within scope")
        ));
        for d in &fleet {
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
            ui::paint(Tone::Dim, "EXTERNAL  /  other people, time-boxed, deny-by-default")
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
            ui::paint(Tone::Brand, &heading)
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

    // Needs-review section
    let review: Vec<_> = devices.iter().filter(|d| d.tier == DeviceTier::NeedsReview).collect();
    if !review.is_empty() {
        lines.push(format!(
            "  {} {}",
            ui::paint(Tone::Warn, ui::glyph_review()),
            ui::paint(Tone::Warn, "NEEDS REVIEW  /  paired without a certified identity, so trusted in full")
        ));
        for d in &review {
            lines.push(render_device_row(d));
            // #240: was `↳ filament devices promote <name>`, a verb that does
            // not exist, rendered as the prescribed next step.
            lines.push(ui::paint(Tone::Dim, "       ↳ its identity was never certified; re-pair to scope it"));
        }
        lines.push(String::new());
    }

    // Pending requests
    if pending_requests > 0 {
        lines.push(format!(
            "  {} {} · filament requests",
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
    };
    // #217 for the mesh: a sibling we have never contacted has UNKNOWN liveness,
    // never "idle"/"offline". The roster carries name + key only, so the row says
    // what is true (known via the owner, no direct channel yet) and nothing else.
    let status = match d.online {
        Some(true) => ui::paint(Tone::Ok, "online"),
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
    if d.needs_promote {
        line.push_str(&format!("  {}", ui::paint(Tone::Warn, "promote to continue")));
    }
    line
}

/// Render the empty devices list.
pub fn render_empty() -> String {
    format!(
        "No devices yet.\n\
         Add in person:        filament add\n\
         Invite securely:      filament add --for person"
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
        assert!(s.contains("filament add"), "must suggest add");
        assert!(s.contains("filament add --for person"), "must suggest the bounded invite");
    }

    #[test]
    fn full_device_list() {
        let devices = vec![
            DeviceEntry {
                name: "pixel-7".into(),
                tier: DeviceTier::Fleet,
                online: Some(true),
                caps_summary: "OWNER-EQUIVALENT shell reach:8080 inbox".into(),
                countdown: "expires in 9m".into(),
                last_seen: None,
                needs_promote: false,
            },
            DeviceEntry {
                name: "carol".into(),
                tier: DeviceTier::External,
                online: Some(true),
                caps_summary: "send→you".into(),
                countdown: "expires in 4m".into(),
                last_seen: None,
                needs_promote: false,
            },
        ];
        let s = render_devices(&devices, 0, None);
        assert!(s.contains("FLEET"), "must show fleet section");
        assert!(s.contains("EXTERNAL"), "must show external section");
        assert!(s.contains("pixel-7"), "must show fleet device");
        assert!(s.contains("carol"), "must show external device");
    }

    #[test]
    fn needs_review_section() {
        let devices = vec![
            DeviceEntry {
                name: "old-laptop".into(),
                tier: DeviceTier::NeedsReview,
                online: Some(false),
                caps_summary: "(full legacy trust)".into(),
                countdown: "promote to continue".into(),
                last_seen: None,
                needs_promote: true,
            },
        ];
        let s = render_devices(&devices, 0, None);
        assert!(s.contains("NEEDS REVIEW"), "must show review section");
        assert!(s.contains("old-laptop"), "must show review device");
        assert!(s.contains("promote to continue"), "must show promote nudge");
    }

    #[test]
    fn pending_requests_count() {
        let s = render_devices(&[], 2, None);
        assert!(s.contains("2"), "must show request count");
        assert!(s.contains("filament requests"), "must suggest filament requests");
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
