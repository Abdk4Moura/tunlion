// Fleet-trust UX surfaces: self-contained render modules.
//
// These are RENDER + form-logic functions: pure-ish functions that take state
// (key type, toggled caps, ttl, peer name, device list, request list, recovery
// posture, etc.) and RETURN the rendered string (or a small enum of form
// outcomes). They do NOT call the capability/identity/signaling layers and do
// NOT wire into main.rs's Commands enum — that integration is a separate step.
//
// Design model: docs/design-pairing-ux.md; surface spec: docs/ux-spec-pairing.md;
// command surface: docs/design-command-surface.md.
// FINAL copy: docs/ux-copy-final.md (every string, glyph, token is drop-in).
//
// Reuses the token/glyph machinery from cli/src/ui.rs (Brand/Ok/Warn/Err/Dim/Bold
// styling, NO_COLOR, unicode->ascii fallback). Every glyph has its ascii fallback
// wired via the glyph_* functions.

pub mod devices;
pub mod mint;
pub mod pair_ui;
pub mod recovery;
pub mod requests;

use crate::ui::{self, Tone};

// ---- shared helpers ----

/// Render a horizontal rule (full-width, Dim).
pub fn rule() -> &'static str {
    "────────────────────────────────────────────────────────────────────────────────"
}

/// Render a double rule for section headers (full-width, Brand/Warn).
pub fn double_rule() -> &'static str {
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

/// Render a "This key can/cannot" line.
fn can_line(ok: bool, deliberate: bool, text: &str) -> String {
    if ok && deliberate {
        format!("  {} {}", ui::paint(Tone::Warn, ui::glyph_warn()), text)
    } else if ok {
        format!("  {} {}", ui::paint(Tone::Ok, ui::glyph_ok()), text)
    } else {
        format!("  {} {}", ui::paint(Tone::Err, ui::glyph_err()), text)
    }
}

/// Render a meta line (Dim).
fn meta(text: &str) -> String {
    ui::paint(Tone::Dim, &format!("  {text}"))
}

/// Render a confirm-token mistype warning.
pub fn confirm_mistype(token: &str) -> String {
    format!(
        "{} {}",
        ui::paint(Tone::Warn, ui::glyph_warn()),
        format!("didn't match \"{token}\" — left off.")
    )
}

/// Non-TTY error: exit code 2 (bad-arg/bad-flag).
pub fn err_bad_arg(msg: &str) -> String {
    format!("{} {msg}", ui::paint(Tone::Err, ui::glyph_err()))
}

/// Non-TTY error: exit code 1 (refused-by-model).
pub fn err_refused(msg: &str) -> String {
    format!("{} {msg}", ui::paint(Tone::Err, ui::glyph_err()))
}

/// Echo the equivalent command (Dim, arrow-prefixed).
pub fn echo_cmd(cmd: &str) -> String {
    format!("{} {cmd}", ui::paint(Tone::Dim, ui::glyph_echo()))
}

/// Confirmation tokens (exact, as specified).
pub const CONFIRM_SHELL: &str = "SHELL";
pub const CONFIRM_WRITE: &str = "WRITE";
pub const CONFIRM_REUSE: &str = "REUSE";

/// Capability names surfaced by the fleet UX. Keep this as a checked subset of
/// the enforcement vocabulary, never as a second source of valid names.
pub const UX_CAPABILITIES: &[&str] = &["shell", "transfer", "mount", "send", "inbox"];

/// Exit codes.
pub const EXIT_BAD_ARG: i32 = 2;
pub const EXIT_REFUSED: i32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_tokens_are_exact() {
        assert_eq!(CONFIRM_SHELL, "SHELL");
        assert_eq!(CONFIRM_WRITE, "WRITE");
        assert_eq!(CONFIRM_REUSE, "REUSE");
    }

    #[test]
    fn exit_codes() {
        assert_eq!(EXIT_BAD_ARG, 2);
        assert_eq!(EXIT_REFUSED, 1);
    }

    #[test]
    fn ux_capabilities_are_enforcement_subset() {
        for capability in UX_CAPABILITIES {
            assert!(
                crate::capability::CANONICAL_CAPABILITIES.contains(capability),
                "UX capability '{capability}' is missing from enforcement vocabulary"
            );
        }
    }
}
