// Surface 1: `filament mint` guided form + danger microcopy.
//
// Pure render functions: take state (key type, toggled caps, ttl, reuse)
// and return rendered strings. No capability/identity/signaling calls.

use crate::ui::{self, Tone};
use super::{can_line, echo_cmd, meta, rule};

/// Key types for the fleet-trust mint flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Fleet,
    External,
    CI,
}

/// Caps that can be toggled on a mint form.
#[derive(Debug, Clone, Default)]
pub struct MintCaps {
    pub shell: bool,
    pub write: bool,
    pub all_ports: bool,
}

/// Capability names emitted by the mint form, derived from its actual toggles.
pub fn emitted_capabilities(caps: &MintCaps) -> Vec<&'static str> {
    let mut names = vec!["transfer"];
    if caps.shell {
        names.push("shell");
    }
    if caps.write {
        names.push("mount");
    }
    names
}

/// Reuse policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reuse {
    Once,
    Times(u32),
    Reusable,
}

/// Lifetime parameters.
#[derive(Debug, Clone)]
pub struct Lifetime {
    pub ttl: String,     // e.g. "1h", "15m"
    pub reuse: Reuse,
    pub max_ttl: String, // e.g. "24h"
}

/// Render the header (all key types).
pub fn render_header() -> String {
    format!(
        "  {}",
        ui::paint(Tone::Brand, "filament mint — a key that lets a machine join, scoped and expiring")
    )
}

/// Render the key-type picker (first screen).
pub fn render_key_type_picker() -> String {
    let fleet = format!(
        " {} {}",
        ui::paint(Tone::Brand, ui::glyph_fleet()),
        ui::paint(Tone::Bold, "(o) A device in my fleet")
    );
    let fleet_desc = ui::paint(Tone::Dim, "       my own laptop / box / CI — permissive within scope");
    let external = format!(
        " {} {}",
        ui::paint(Tone::Warn, ui::glyph_extern()),
        ui::paint(Tone::Dim, "( ) An external share")
    );
    let external_desc = ui::paint(Tone::Dim, "          give someone else narrow, time-boxed access");
    let ci = format!(
        "   {}",
        ui::paint(Tone::Dim, "( ) A CI / automation runner")
    );
    let ci_desc = ui::paint(Tone::Dim, "   single-use, pinned to one machine, then forgotten");

    format!(
        "What is this key for?\n{fleet}\n{fleet_desc}\n{external}\n{external_desc}\n{ci}\n{ci_desc}"
    )
}

/// Render the "This key can / cannot" live summary.
pub fn render_summary(key_type: KeyType, caps: &MintCaps) -> String {
    let mut lines = vec![format!("  {}", ui::paint(Tone::Dim, "── This key can ──"))];

    match key_type {
        KeyType::Fleet => {
            lines.push(can_line(true, false, "drop files in your inbox · reach your exposed ports · read ~/share"));
            if caps.shell {
                lines.push(can_line(true, true, "open a shell — a real terminal on this machine, running as you"));
            } else {
                lines.push(can_line(false, false, "open a shell"));
            }
            if caps.write {
                lines.push(can_line(true, true, "write to mounted dirs — can change or delete your files"));
            } else if caps.all_ports {
                lines.push(can_line(false, false, "write to disk"));
            }
            if caps.all_ports {
                lines.push(can_line(true, true, "reach ALL ports — not just the ports you chose to expose"));
            } else if caps.write {
                lines.push(can_line(false, false, "join your mesh"));
            } else {
                lines.push(can_line(false, false, "write to disk · join your mesh"));
            }
            // Deliberately omit the fleet meta line: this currently mints a
            // delegated ephemeral principal, not a fleet certificate. Restore
            // that claim only when fleet-cert enrollment exists.
        }
        KeyType::External => {
            lines.push(can_line(true, false, "send you files"));
            lines.push(meta("  (the only thing on, until you add more)"));
            lines.push(can_line(false, false, "read your files · open a shell · reach any port · join your mesh"));
            lines.push(meta("  one-way (them → you) · expires in 1h · no auto-renew · not your fleet"));
        }
        KeyType::CI => {
            lines.push(can_line(true, false, "run one job on ci-box, then vanish"));
            lines.push(can_line(false, false, "persist · open a shell · reach other ports · join your mesh"));
            lines.push(meta("  single-use · pinned to ci-box · expires in 15m · ephemeral (no identity left behind)"));
        }
    }

    lines.push(format!("  {}", ui::paint(Tone::Dim, rule())));
    lines.join("\n")
}

/// Render the deliberate-access region.
pub fn render_deliberate_access(caps: &MintCaps, pending_token: Option<&str>) -> String {
    let border = format!(
        "  {} {} {}",
        ui::paint(Tone::Warn, ui::glyph_warn()),
        ui::paint(Tone::Warn, "DELIBERATE ACCESS — off unless you turn it on"),
        ui::paint(Tone::Dim, rule())
    );

    let shell_row = if caps.shell {
        format!(
            "  │  {} open a shell          type {} to keep it on:  [ {}▌ ]",
            ui::paint(Tone::Warn, "[x]"),
            ui::paint(Tone::Warn, "SHELL"),
            pending_token.unwrap_or("")
        )
    } else {
        "  │  [ ] open a shell          a real terminal on this machine, running as you".to_string()
    };

    let write_row = if caps.write {
        format!(
            "  │  {} write to mounted dirs type {} to keep it on:  [ {}▌ ]",
            ui::paint(Tone::Warn, "[x]"),
            ui::paint(Tone::Warn, "WRITE"),
            pending_token.unwrap_or("")
        )
    } else {
        "  │  [ ] write to mounted dirs can change or delete your files".to_string()
    };

    let footer = format!("  └{}", ui::paint(Tone::Dim, rule()));

    format!("{border}\n{shell_row}\n{write_row}\n{footer}")
}

/// Render the lifetime block.
pub fn render_lifetime(lifetime: &Lifetime) -> String {
    let reuse_label = match &lifetime.reuse {
        Reuse::Once => format!("{} once", ui::paint(Tone::Dim, "(o)")),
        Reuse::Times(n) => format!("{} {n} times", ui::paint(Tone::Dim, "( )")),
        Reuse::Reusable => format!(
            "{} reusable {}",
            ui::paint(Tone::Dim, "( )"),
            ui::paint(Tone::Warn, ui::glyph_warn())
        ),
    };

    let mut lines = vec![
        format!("  Expires in:  [ {} ]  ◀────●───────▶   (max {} for this key type)", lifetime.ttl, lifetime.max_ttl),
        format!("  Reuse:       {reuse_label}"),
    ];

    // Best-effort honesty for non-once reuse without audience pinned
    if lifetime.reuse != Reuse::Once {
        lines.push(format!(
            "  {}",
            ui::paint(Tone::Warn, "\"5 times\" is best-effort hygiene, not a guarantee — a copied key can be")
        ));
        lines.push(format!(
            "  {}",
            ui::paint(Tone::Warn, "claimed again at a peer that never saw the count.")
        ));
        lines.push(format!(
            "  {}",
            ui::paint(Tone::Dim, "To make single-use real, pin the machine:  --audience ci-box  → enforced there.")
        ));
    }

    lines.join("\n")
}

/// Render the completion / teach-the-flags screen.
pub fn render_completion(code: &str, key_type: KeyType, caps: &MintCaps, lifetime: &Lifetime) -> String {
    let type_label = match key_type {
        KeyType::Fleet => ui::paint(Tone::Brand, "fleet key"),
        KeyType::External => ui::paint(Tone::Warn, "external key"),
        KeyType::CI => ui::paint(Tone::Dim, "CI key"),
    };

    let caps_str = format!(" · {}", emitted_capabilities(caps).join(", "));

    let reuse_str = match &lifetime.reuse {
        Reuse::Once => "once",
        Reuse::Times(n) => match *n {
            5 => "5 times",
            _ => "N times",
        },
        Reuse::Reusable => "reusable",
    };

    let cmd = format!("filament mint --{} --ttl {} --reuse {}{}",
        match key_type { KeyType::Fleet => "fleet", KeyType::External => "external", KeyType::CI => "ci" },
        lifetime.ttl,
        reuse_str,
        if caps.shell { " --allow shell" } else { "" },
    );

    format!(
        "{ok} {minted}\n\n     {code}\n\n{meta}\n{echo}",
        ok = ui::paint(Tone::Ok, ui::glyph_ok()),
        minted = "Minted. Share this with the machine that's joining:",
        code = ui::paint(Tone::Bold, &format!("filament join {code}")),
        meta = meta(&format!("{type_label} · {reuse_str} · expires in {} · {caps_str}", lifetime.ttl)),
        echo = echo_cmd(&cmd),
    )
}

/// Non-TTY error: --shell is not a flag.
pub fn err_shell_not_flag() -> (String, i32) {
    (
        format!(
            "{err}\n  {fix}",
            err = ui::paint(Tone::Err, &format!("{} --shell is not a flag. Shell is deliberate access.", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "To grant it on purpose:  filament mint --fleet --ttl 1h --allow shell"),
        ),
        super::EXIT_BAD_ARG,
    )
}

/// Non-TTY error: mint needs a key type.
pub fn err_needs_key_type() -> (String, i32) {
    (
        format!(
            "{err}\n{fix}",
            err = ui::paint(Tone::Err, &format!("{} mint needs a key type in non-interactive mode.", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "filament mint --fleet | --external <peer> | --ci\n(add --ttl; for external, at least one --allow)"),
        ),
        super::EXIT_BAD_ARG,
    )
}

/// Non-TTY error: --yes will not enable deliberate options.
pub fn err_yes_no_deliberate() -> (String, i32) {
    (
        format!(
            "{err}\n{fix}",
            err = ui::paint(Tone::Err, &format!("{} --yes will not enable a deliberate option you didn't name.", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "Say it explicitly:  filament mint --fleet --ttl 1h --allow reuse --yes"),
        ),
        super::EXIT_BAD_ARG,
    )
}

/// Non-TTY error: external key over-TTL.
pub fn err_over_ttl() -> (String, i32) {
    (
        format!(
            "{err}\n{fix}",
            err = ui::paint(Tone::Err, &format!("{} external keys expire within 24h (this key type's ceiling).", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "Pick a shorter --ttl, or re-mint when it lapses. Long-lived trust is `pair`, not a key."),
        ),
        super::EXIT_REFUSED,
    )
}

/// Non-TTY error: mesh not grantable by a key.
pub fn err_mesh_not_grantable() -> (String, i32) {
    (
        format!(
            "{err}\n{fix}",
            err = ui::paint(Tone::Err, &format!("{} mesh is never grantable by a key — a runner or borrower can't join your L3 overlay.", ui::glyph_err())),
            fix = ui::paint(Tone::Dim, "(Refused at the verifier regardless of signature. Not a flag; there's no override.)"),
        ),
        super::EXIT_REFUSED,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_summary_defaults() {
        let caps = MintCaps::default();
        let summary = render_summary(KeyType::Fleet, &caps);
        assert!(summary.contains("── This key can ──"), "summary must label capabilities");
        assert!(summary.contains("drop files in your inbox"), "fleet default must show can-drop-files");
        assert!(summary.contains("open a shell"), "must mention shell");
        assert!(summary.contains("write to disk"), "must mention write");
        assert!(summary.contains("join your mesh"), "must mention mesh");
        // Deliberate caps are OFF by default, so should show ✗ for shell/write/mesh
        // (the can_line function renders Err glyph for ok=false)
    }

    #[test]
    fn fleet_summary_keeps_denials_on_one_row() {
        let summary = render_summary(KeyType::Fleet, &MintCaps::default());
        assert!(summary.contains("write to disk · join your mesh"), "denied capabilities should share a row");
    }

    #[test]
    fn lifetime_does_not_repeat_summary_rule() {
        let summary = render_summary(KeyType::Fleet, &MintCaps::default());
        let lifetime = render_lifetime(&Lifetime { ttl: "1h".into(), reuse: Reuse::Once, max_ttl: "24h".into() });
        let combined = format!("{summary}\n{lifetime}");
        let rule_line = format!("  {}", rule());
        assert_eq!(combined.matches(&rule_line).count(), 1, "stacked summary and lifetime must not duplicate rules");
    }

    #[test]
    fn fleet_summary_shell_on() {
        let caps = MintCaps { shell: true, write: false, all_ports: false };
        let summary = render_summary(KeyType::Fleet, &caps);
        // Shell is deliberate, so should show ⚠ glyph
        assert!(summary.contains("open a shell — a real terminal"), "shell-on must show deliberate description");
    }

    #[test]
    fn emitted_capabilities_are_enforcement_subset() {
        for caps in [MintCaps { shell: false, write: false, all_ports: false }, MintCaps { shell: true, write: true, all_ports: false }] {
            for capability in emitted_capabilities(&caps) {
                assert!(
                    crate::capability::CANONICAL_CAPABILITIES.contains(&capability),
                    "mint emitted capability '{capability}' is not enforced"
                );
            }
        }
    }

    #[test]
    fn external_summary() {
        let caps = MintCaps::default();
        let summary = render_summary(KeyType::External, &caps);
        assert!(summary.contains("send you files"), "external must show send");
        assert!(summary.contains("read your files"), "external must block read");
        assert!(summary.contains("no auto-renew"), "external must note no auto-renew");
    }

    #[test]
    fn ci_summary() {
        let caps = MintCaps::default();
        let summary = render_summary(KeyType::CI, &caps);
        assert!(summary.contains("run one job"), "CI must show run-one-job");
        assert!(summary.contains("single-use"), "CI must note single-use");
        assert!(summary.contains("ephemeral"), "CI must note ephemeral");
    }

    #[test]
    fn confirm_mistype_render() {
        let s = super::super::confirm_mistype("SHELL");
        assert!(s.contains("SHELL"), "mistype must reference the token");
        assert!(s.contains("left off"), "mistype must say left off");
    }

    #[test]
    fn err_shell_not_flag_exit_code() {
        let (msg, code) = err_shell_not_flag();
        assert!(msg.contains("--shell"), "must reference the flag");
        assert!(msg.contains("deliberate access"), "must explain why");
        assert_eq!(code, 2, "bad-flag = exit 2");
    }

    #[test]
    fn err_needs_key_type_exit_code() {
        let (msg, code) = err_needs_key_type();
        assert!(msg.contains("non-interactive"), "must mention non-interactive");
        assert_eq!(code, 2, "missing-arg = exit 2");
    }

    #[test]
    fn err_over_ttl_exit_code() {
        let (_, code) = err_over_ttl();
        assert_eq!(code, 1, "refused-by-model = exit 1");
    }

    #[test]
    fn err_mesh_not_grantable_exit_code() {
        let (msg, code) = err_mesh_not_grantable();
        assert!(msg.contains("mesh"), "must mention mesh");
        assert_eq!(code, 1, "refused-by-model = exit 1");
    }

    #[test]
    fn completion_render() {
        let caps = MintCaps { shell: true, write: false, all_ports: false };
        let lt = Lifetime { ttl: "1h".into(), reuse: Reuse::Once, max_ttl: "24h".into() };
        let s = render_completion("clever-lynx-63-brave-otter", KeyType::Fleet, &caps, &lt);
        assert!(s.contains("filament join clever-lynx-63-brave-otter"), "must show join command");
        assert!(s.contains("fleet key"), "must label as fleet");
        assert!(s.contains("once"), "must show reuse");
        assert!(s.contains("shell"), "must show granted caps");
    }

    #[test]
    fn header_is_brand() {
        let h = render_header();
        assert!(h.contains("filament mint"), "header must contain filament mint");
    }
}
