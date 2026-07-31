// Surface 4: Recovery: `init` phrase + `restore` loss-vs-theft + guardians.
//
// Pure render functions for the recovery flow: init with forced-ack,
// restore with loss-vs-theft posture choice, guardian install/act/remove,
// duress SILENT (no on-screen string).

use crate::ui::{self, Tone};
use super::{echo_cmd, meta, rule};

/// Render the init recovery-phrase screen with forced ack.
pub fn render_init_phrase(words: &[&str]) -> String {
    assert_eq!(words.len(), 12, "recovery phrase must be 12 words");

    let word_grid: Vec<String> = words
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .map(|(i, w)| format!("{:>2}  {:<10}", i + 1 + (words.len() / 3) * (chunk.as_ptr() as usize / 4), w))
                .collect::<Vec<_>>()
                .join("    ")
        })
        .collect();

    format!(
        "{ok} Identity created. This is you — devices come and go, this is what they trust.\n\n\
         {prompt}\n\
         {warn}\n\n\
         {words}\n\n\
         {ack}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        prompt = ui::paint(Tone::Bold, "  Write these 12 words down. This is the only way back if you LOSE every device."),
        warn = ui::paint(Tone::Warn, "  We will not show them again."),
        words = word_grid.join("\n"),
        ack = format!(
            "   {}",
            ui::paint(Tone::Bold, "[ I've written them down ]   ← required to continue")
        ),
    )
}

/// Render the skip / Ctrl-C attempt warning.
pub fn render_skip_warning() -> String {
    format!(
        "{} Without the phrase, a lost device is a lost identity. Skip anyway? [y/N]",
        ui::paint(Tone::Warn, ui::glyph_warn())
    )
}

/// Render the post-ack primary nudge.
pub fn render_post_ack_nudge() -> String {
    format!(
        "{ok} Saved. Now make sure you're never one dead device from lockout:\n\
         {this}\n\
         {add}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        this = format!("     {} this device (primary)", ui::paint(Tone::Ok, ui::glyph_ok())),
        add = format!(
            "     {} {}  (strongly recommended)",
            ui::paint(Tone::Warn, ui::glyph_extern()),
            ui::paint(Tone::Dim, "add a second primary:  filament pair --fleet")
        ),
    )
}

/// Render the restore header.
pub fn render_restore_header() -> String {
    format!(
        "{}",
        ui::paint(Tone::Brand, "  filament restore — recover your identity from your 12 words")
    )
}

/// Render the loss-vs-theft posture choice.
pub fn render_loss_vs_theft() -> String {
    format!(
        "{ok} Words verified. Before we finish, which happened?\n\n\
         {lost}\n\
         {stolen}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        lost = format!(
            "     {} {}",
            ui::paint(Tone::Dim, "(o)"),
            ui::paint(Tone::Bold, "I LOST my devices")
        ),
        stolen = format!(
            "     {} {}",
            ui::paint(Tone::Dim, "( )"),
            ui::paint(Tone::Err, "A device was STOLEN")
        ),
    )
}

/// Render the LOST posture response.
pub fn render_lost_response() -> String {
    format!(
        "{ok} Recovering. Your new device is now a primary.\n\
         {pending}\n\
         {rotate}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        pending = ui::paint(Tone::Dim, "  7-day pending window: if an old device is still out there, it can object."),
        rotate = ui::paint(Tone::Dim, "  Bring any old primary online to confirm instantly.\n  ↳ filament identity rotate   (optional — replaces the old key sooner)"),
    )
}

/// Render the STOLEN posture response — the honest truth.
/// This is the load-bearing copy: "The phrase recovers you from LOSS, not from THEFT."
pub fn render_stolen_response() -> String {
    format!(
        "{warn} Read this. The phrase recovers you from LOSS, not from THEFT.\n\n\
         {line1}\n\
         {line2}\n\n\
         {what_do}\n\
         {revoke}\n\
         {rotate}\n\n\
         {guardians}",
        warn = ui::paint(Tone::Warn, ui::glyph_warn()),
        line1 = "    Your 12 words rebuild your identity — but they do NOT disable a key a thief",
        line2 = "    already holds. There is no server to phone; no global kill-switch exists (by design).",
        what_do = ui::paint(Tone::Bold, "    What you CAN do right now:"),
        revoke = format!(
            "      • filament revoke <device>   tell your OTHER devices to stop trusting the stolen one\n\
             {}",
            ui::paint(Tone::Dim, "                                   (takes effect as each one is reached; bounded by cert expiry)")
        ),
        rotate = "      • filament identity rotate   move to a new key; devices re-verify on next contact".to_string(),
        guardians = format!(
            "{}",
            ui::paint(Tone::Dim, "    What actually closes the door: guardians. If you'd set 3-of-5 guardians, they\n    could co-sign a revocation the thief can't stop. Without them, revoke + rotate\n    is best-effort and races the thief until the old certs expire.")
        ),
    )
}

/// Posture choice (user OWNS it).
pub fn render_posture_choice() -> String {
    format!(
        "  Choose your posture going forward:\n\
         {accept}\n\
         {guardian}",
        accept = format!(
            "     {} {}",
            ui::paint(Tone::Dim, "(o)"),
            ui::paint(Tone::Dim, "Accept the race     backup-only — simplest, and a stolen key races you until expiry")
        ),
        guardian = format!(
            "     {} {}",
            ui::paint(Tone::Dim, "( )"),
            ui::paint(Tone::Bold, "Add guardians       3-of-5 people co-sign recovery/revocation — wins the theft race")
        ),
    )
}

/// Render the guardians install header.
pub fn render_guardians_header() -> String {
    format!(
        "{}",
        ui::paint(Tone::Brand, "  filament identity guardians — people who can co-sign your recovery")
    )
}

/// Render the installed guardians list.
pub fn render_guardians_installed(guardians: &[(&str, &str)], threshold: &str) -> String {
    let count = guardians.len();
    let mut lines = vec![
        format!(
            "  {} Installed  ({} — tolerates {} offline)",
            ui::paint(Tone::Brand, ui::glyph_fleet()),
            threshold,
            count.saturating_sub(threshold.split('-').next().unwrap_or("3").parse::<usize>().unwrap_or(3))
        ),
    ];

    for (name, how) in guardians {
        lines.push(format!(
            "     {} {:<12} {}",
            ui::paint(Tone::Brand, ui::glyph_fleet()),
            name,
            ui::paint(Tone::Dim, how)
        ));
    }

    lines.push(String::new());
    lines.push(ui::paint(Tone::Dim, "  Installing a guardian: one confirm, reversible anytime — they hold no power"));
    lines.push(ui::paint(Tone::Dim, "  until 3 of them together co-sign a recovery. No single guardian can act alone."));

    lines.join("\n")
}

/// Render a guardian recovery request (acting).
pub fn render_guardian_recovery_requested(started: &str, activates: &str) -> String {
    format!(
        "{warn} A recovery for YOUR identity was requested from a new device.\n\
         Started: {started} · Activates: {activates} (7-day hold) unless you cancel.\n\
         Not you?  filament identity freeze   — stops it cold; the new device gets nothing.\n\
         It's you? Ask your guardians to co-sign, or bring an old primary online.",
        warn = ui::paint(Tone::Warn, ui::glyph_warn()),
    )
}

/// Render guardian removal.
pub fn render_guardian_removed(name: &str, new_threshold: &str) -> String {
    format!(
        "{ok} Removed {name} as a guardian. Your threshold is now {new_threshold}.\n\
         {warn} Below your target of 3-of-5 — add one to restore your margin.",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        warn = ui::paint(Tone::Warn, ui::glyph_warn()),
    )
}

/// Duress path: SILENT by design — NO on-screen string.
/// This function exists to document the contract; it returns NOTHING.
/// Entering the duress PIN at any recovery/rotate prompt SILENTLY aborts or delays.
/// It must look identical to success on screen. Never render a "duress detected" line.
pub fn duress_silent() -> &'static str {
    // This function intentionally returns nothing. The duress path is silent.
    // It must look identical to success on screen. Never render a "duress detected" line.
    ""
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_phrase_word_count() {
        let words: Vec<&str> = (1..=12).map(|i| match i {
            1 => "harbor", 2 => "velvet", 3 => "cinder", 4 => "meadow",
            5 => "quartz", 6 => "tunnel", 7 => "autumn", 8 => "silver",
            9 => "falcon", 10 => "breeze", 11 => "copper", 12 => "cobalt",
            _ => "word",
        }).collect();
        let s = render_init_phrase(&words);
        assert!(s.contains("harbor"), "must show first word");
        assert!(s.contains("cobalt"), "must show last word");
        assert!(s.contains("I've written them down"), "must show forced ack");
        assert!(s.contains("We will not show them again"), "must show warning");
    }

    #[test]
    fn stolen_posture_honesty_line() {
        let s = render_stolen_response();
        assert!(s.contains("recovers you from LOSS, not from THEFT"), "must contain the load-bearing honesty line");
        assert!(s.contains("no server to phone"), "must explain no central kill-switch");
        assert!(s.contains("filament revoke"), "must suggest revoke");
        assert!(s.contains("filament identity rotate"), "must suggest rotate");
        assert!(s.contains("guardians"), "must mention guardians");
    }

    #[test]
    fn lost_posture_simple() {
        let s = render_lost_response();
        assert!(s.contains("Recovering"), "must confirm recovery");
        assert!(s.contains("7-day pending window"), "must explain pending window");
        assert!(s.contains("filament identity rotate"), "must suggest rotate");
    }

    #[test]
    fn skip_warning() {
        let s = render_skip_warning();
        assert!(s.contains("lost device is a lost identity"), "must explain consequence");
        assert!(s.contains("[y/N]"), "must show y/N prompt");
    }

    #[test]
    fn posture_choice() {
        let s = render_loss_vs_theft();
        assert!(s.contains("I LOST"), "must show lost option");
        assert!(s.contains("STOLEN"), "must show stolen option");
    }

    #[test]
    fn guardians_installed() {
        let s = render_guardians_installed(&[("bff", "added in person"), ("sister", "added in person")], "2-of-3");
        assert!(s.contains("bff"), "must show guardian name");
        assert!(s.contains("sister"), "must show guardian name");
        assert!(s.contains("added in person"), "must show how added");
    }

    #[test]
    fn guardian_recovery() {
        let s = render_guardian_recovery_requested("Aug 3", "Aug 10");
        assert!(s.contains("recovery"), "must mention recovery");
        assert!(s.contains("7-day hold"), "must mention hold period");
        assert!(s.contains("filament identity freeze"), "must suggest freeze");
    }

    #[test]
    fn guardian_removed_below_target() {
        let s = render_guardian_removed("coworker", "3-of-4");
        assert!(s.contains("coworker"), "must show removed name");
        assert!(s.contains("3-of-4"), "must show new threshold");
        assert!(s.contains("Below your target"), "must warn about margin");
    }

    #[test]
    fn duress_is_silent() {
        let s = duress_silent();
        assert!(s.is_empty(), "duress must return empty string — silent by design");
    }

    #[test]
    fn restore_header() {
        let s = render_restore_header();
        assert!(s.contains("filament restore"), "must contain restore command");
        assert!(s.contains("12 words"), "must mention 12 words");
    }

    #[test]
    fn post_ack_nudge() {
        let s = render_post_ack_nudge();
        assert!(s.contains("primary"), "must mention primary");
        assert!(s.contains("filament pair --fleet"), "must suggest fleet pair");
    }
}
