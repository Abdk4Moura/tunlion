// Surface 2: `pair` same-vs-inter-user flows.
//
// Pure render functions for the pairing UX: same-person vs someone-else banners,
// PAKE spoken-words screen, inter-user per-cap/direction/expiry form, non-TTY refusal.

use crate::ui::{self, Tone};
use super::{double_rule, echo_cmd, meta};
use filament_pair::words::SpokenSas;

/// Render the same-person banner + fleet add.
pub fn render_same_person_banner(device_name: &str) -> String {
    format!(
        "{rule}\n{banner}\n{rule}\n\n{msg}\n\n{will}\n{wont}\n{meta}\n\n{btns}",
        rule = ui::paint(Tone::Brand, double_rule()),
        banner = format!("  {}  SAME PERSON  /  this is you", ui::paint(Tone::Brand, ui::glyph_fleet())),
        msg = format!("  \"{}\" is signed by your identity. Adding it to your fleet.", device_name),
        will = format!(
            "  This device will:  {}",
            ui::paint(Tone::Ok, "send/receive with your fleet / reach exposed ports / read the configured share root")
        ),
        wont = format!(
            "  It will not:       {}",
            ui::paint(Tone::Dim, "owner-equivalent shell / write to disk   (grant those later if you want)")
        ),
        meta = meta(&format!("{} fleet / cryptographically Proven", ui::glyph_fleet())),
        btns = format!(
            "        {}   {}",
            ui::paint(Tone::Bold, "[ Add to my fleet ]"),
            ui::paint(Tone::Dim, "[ Cancel ]")
        ),
    )
}

/// Render the same-person success message.
pub fn render_same_person_success(device_name: &str) -> String {
    format!(
        "{ok} {name} joined your fleet.\n{echo}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        name = device_name,
        echo = echo_cmd("filament add"),
    )
}

/// Render the someone-else banner.
pub fn render_someone_else_banner() -> String {
    format!(
        "{rule}\n{banner}\n{rule}\n\n{msg}",
        rule = ui::paint(Tone::Warn, double_rule()),
        banner = format!("  {}  SOMEONE ELSE  /  not your identity", ui::paint(Tone::Warn, ui::glyph_extern())),
        msg = ui::paint(Tone::Dim, "  This is not you. Nothing is shared yet; you decide exactly what, and for how long."),
    )
}

/// Render the PAKE spoken-words screen.
///
/// Takes a [`SpokenSas`], never a `&[&str]`, so the pairing code cannot be
/// passed here. That type has no constructor: the only legitimate one derives
/// from the completed transcript and has not been designed. So this function is
/// currently uncallable BY CONSTRUCTION, which is the intent. The screen must
/// not render until there is a real short authentication string behind it.
pub fn render_pake_words(sas: &SpokenSas) -> String {
    let words_str = sas.words().join(" · ");
    format!(
        "{prompt}\n\n     {words}\n\n{confirm}\n{fingerprint}",
        prompt = "  Say these three words out loud. They must hear the SAME three, in this order.",
        words = ui::paint(Tone::Bold, &words_str),
        confirm = format!(
            "   Do they hear exactly these?\n        {}        {}",
            ui::paint(Tone::Bold, "[ Yes, they match ]"),
            ui::paint(Tone::Err, "[ No / stop ]")
        ),
        fingerprint = ui::paint(Tone::Dim, "  Fingerprint 7f3a 9c21 4b...  [compare]  / informational; the words are the trust."),
    )
}

/// Render the PAKE mismatch (No / stop) message.
pub fn render_pake_mismatch() -> String {
    format!(
        "{err} Stopped. If the words didn't match, someone may be in the middle. Don't retry\n  on the same channel. Get a fresh code from them and try again.",
        err = ui::paint(Tone::Err, ui::glyph_err()),
    )
}

/// Render the inter-user per-cap + direction + expiry form (after "Yes, they match").
pub fn render_inter_user_form(peer_name: &str) -> String {
    format!(
        "{ok} Words matched. What may \"{peer_name}\" do, and for how long?\n\n\
         {send} {port}\n\
         {read} {shell}\n\
         Direction:  {dir_out}    {dir_both}\n\
         Ends in:    [ 1h ]  <---o----->   (max 24h)\n\n\
         {rule}\n\
         {can}\n\
         {cannot}\n\
         {meta}\n\n\
         {grant}   {cancel}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        send = "   [ ] send me files",
        port = "[ ] reach my port [ 8080 ]",
        read = "   [ ] read-only ~/share",
         shell = format!("[ ] OWNER-EQUIVALENT shell (can act as you) {}", ui::paint(Tone::Warn, ui::glyph_warn())),
        dir_out = ui::paint(Tone::Dim, "(o)"),
        dir_both = format!("{} both ways", ui::paint(Tone::Dim, "( )")),
        rule = super::rule(),
        can = format!("  {} {}: send files", ui::paint(Tone::Ok, ui::glyph_ok()), peer_name),
        cannot = format!(
            "  {} you -> {}: nothing / {} cannot shell, mount, or reach other ports",
            ui::paint(Tone::Err, ui::glyph_err()),
            peer_name,
            peer_name
        ),
        meta = meta(&format!("{} external / one-way / expires 14:41 (in 1h) / no auto-renew", ui::glyph_extern())),
        grant = ui::paint(Tone::Bold, "[ Grant ]"),
        cancel = ui::paint(Tone::Dim, "[ Cancel ]"),
    )
}

/// Render the inter-user success message.
pub fn render_inter_user_success(peer_name: &str, cap: &str, expiry: &str) -> String {
    let echo = match cap {
        "shell" | "transfer" | "mount" => {
            echo_cmd(&format!("filament grant {peer_name} {cap} --for {expiry}"))
        }
        _ => String::new(),
    };
    format!(
        "{ok} {peer_name} can {cap_label} until {expiry}. It ends on its own; no cleanup needed.\n{echo}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        cap_label = if cap == "shell" { "act as you through a shell (OWNER-EQUIVALENT)" } else { cap },
        echo = echo,
    )
}

/// Non-TTY refusal: add is interactive.
pub fn err_pair_interactive() -> (String, i32) {
    // Built from lines rather than one continued literal: a `\`-continuation
    // carries the source indentation into the output, which is how this message
    // came to be printed with fifteen leading spaces on some lines and two on
    // others. Text the user reads should be laid out where you can see it.
    let lines = [
        format!(
            "{} `add` with no arguments needs a person at both ends: it reads a code out for",
            ui::paint(Tone::Err, ui::glyph_err())
        ),
        "  someone to type. In a script, write an invitation they claim later instead:".to_string(),
        String::new(),
        // EVERY ONE OF THESE RUNS. This used to suggest `filament add --for
        // device`, which fails with this very message because --out is required
        // too, so the error told you to run the thing that produced it.
        format!("  {}      a device you own", ui::paint(Tone::Brand, "filament add laptop --out laptop.invite")),
        format!("  {}  someone else", ui::paint(Tone::Brand, "filament add --for person --out alice.invite")),
        format!("  {}        a CI runner", ui::paint(Tone::Brand, "filament add --for runner --out ci.key")),
        String::new(),
        format!(
            "  A bare name means a device you own. They claim it with:  {}",
            ui::paint(Tone::Brand, "filament join <file>")
        ),
    ];
    (lines.join("\n"), super::EXIT_BAD_ARG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_person_banner_fleet_glyph() {
        let s = render_same_person_banner("pixel-7");
        assert!(s.contains("SAME PERSON"), "must show SAME PERSON");
        assert!(s.contains("pixel-7"), "must show device name");
        assert!(s.contains("fleet") || s.contains("[fleet]"), "must show fleet glyph");
    }

    #[test]
    fn someone_else_banner_extern_glyph() {
        let s = render_someone_else_banner();
        assert!(s.contains("SOMEONE ELSE"), "must show SOMEONE ELSE");
        assert!(s.contains("[extern]") || s.contains("○"), "must show extern glyph");
        assert!(s.contains("not your identity"), "must show not-your-identity");
    }

    // The old `pake_words_render` test is deliberately gone rather than adapted.
    //
    // It built its input from a literal &[&str], which is precisely the shape
    // that let a pairing code be passed here. Keeping it would have required
    // either a public SpokenSas constructor, reopening the hole this change
    // closes, or a test-only constructor, which would then be one `pub` away
    // from the same hole.
    //
    // The property that replaced it is enforced by the compiler and asserted in
    // filament-pair: SpokenSas has no constructor, so render_pake_words cannot
    // be called at all. Restore a rendering test when the transcript derivation
    // lands, and build its input from that derivation, never from a literal.

    #[test]
    fn pake_mismatch_honest_copy() {
        let s = render_pake_mismatch();
        assert!(s.contains("someone may be in the middle"), "must explain the risk");
        assert!(s.to_lowercase().contains("don't retry"), "must advise against retry");
    }

    #[test]
    fn inter_user_form_deliberate_glyph() {
        let s = render_inter_user_form("carol");
        assert!(s.contains("carol"), "must show peer name");
        assert!(s.contains("shell") || s.contains("SHELL"), "must mention shell");
        // The shell row must carry a deliberate glyph
        assert!(s.contains("⚠") || s.contains("!"), "shell row must carry warn glyph");
    }

    #[test]
    fn inter_user_success() {
        let s = render_inter_user_success("carol", "send files", "14:41 (1h)");
        assert!(s.contains("carol"), "must show peer name");
        assert!(s.contains("send files"), "must show capability");
        assert!(s.contains("14:41"), "must show expiry");
    }

    #[test]
    fn err_pair_interactive_exit_code() {
        let (msg, code) = err_pair_interactive();
        assert!(msg.contains("both ends"), "must explain why a script cannot do this");
        assert!(msg.contains("join"), "must name the claim side, or the advice is half a ceremony");
        assert_eq!(code, 2, "bad-arg = exit 2");
    }

    /// EVERY SUGGESTED COMMAND MUST RUN.
    ///
    /// This message used to suggest `filament add --for device`, which fails
    /// with this very message because --out is required too: the error told you
    /// to run the thing that produced it. Nothing caught it, because no test
    /// read error text.
    ///
    /// So the assertion is not "mentions --for" (the old one, which the broken
    /// suggestion satisfied) but "clap accepts what this tells you to type".
    #[test]
    fn every_suggested_command_parses() {
        use clap::Parser;
        let (msg, _) = err_pair_interactive();
        let plain = strip_ansi(&msg);
        let mut checked = 0;
        for line in plain.lines() {
            let Some(start) = line.find("filament ") else { continue };
            // the command runs to the double-space that starts its description
            let rest = &line[start..];
            let cmd = rest.split("  ").next().unwrap_or(rest).trim();
            if cmd.contains('<') {
                continue; // a placeholder, not a literal command
            }
            let argv: Vec<&str> = cmd.split_whitespace().collect();
            assert!(
                crate::Cli::try_parse_from(&argv).is_ok(),
                "suggested command does not parse: {cmd}"
            );
            checked += 1;
        }
        assert!(checked >= 3, "expected the three concrete suggestions, saw {checked}");
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c2 in chars.by_ref() {
                    if c2 == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn same_person_success() {
        let s = render_same_person_success("pixel-7");
        assert!(s.contains("pixel-7"), "must show device name");
        assert!(s.contains("joined your fleet"), "must confirm fleet join");
    }
}
