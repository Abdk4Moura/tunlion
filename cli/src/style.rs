//! The terminal palette and motion of the tunlion design, in one place.
//!
//! The browser app, the dashboard and the CLI share one look: ink on paper,
//! one warm accent (the cursor in the tunnel mark), green for done, red for
//! failed. This module turns those design tokens into terminal escape codes
//! and keeps the two motion motifs from the logo work:
//!
//! - **pulse**: the cursor squashes on a `|..||` rhythm. Something is waiting
//!   on the OTHER side (connecting, waiting for a code to be claimed).
//! - **knock**: the cursor hops three times. Something is waiting on YOU.
//!
//! Everything here is pure: the caller (`ui`) decides whether color and motion
//! are on at all (tty, NO_COLOR, TUNLION_COLOR, TERM=dumb), then asks this
//! module for the codes. Nothing here changes what a line SAYS, only how it is
//! drawn, so a pipe (no color) reads exactly as before.
//!
//! The terminal's own foreground and background are the ink and the paper: we
//! never paint a background and never force a foreground for body text, so the
//! output reads on a light or a dark terminal. Only the accent, ok, bad and
//! warn roles carry a color, and each has three tunings: for a light
//! background, for a dark one, and a middle one (the default, when the
//! background is unknown) chosen to stay readable on both.

/// What a span of text is FOR. The palette maps each role to a color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The warm accent: commands to type, codes, the active choice, progress.
    Accent,
    /// Done, verified, online.
    Ok,
    /// Failed, refused.
    Bad,
    /// Needs attention but did not fail.
    Warn,
    /// Secondary text: explanations, hints, metadata.
    Sub,
    /// Emphasis in the terminal's own ink.
    Strong,
}

/// How many colors the terminal can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Ansi16,
    Ansi256,
    True,
}

/// The terminal's background, when it can be known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bg {
    Light,
    Dark,
    Unknown,
}

/// Color depth from `COLORTERM` and `TERM`. Pure.
pub fn depth_from(colorterm: Option<&str>, term: &str) -> Depth {
    let ct = colorterm.unwrap_or("");
    if ct.contains("truecolor") || ct.contains("24bit") {
        Depth::True
    } else if term.contains("256color") || term.contains("256") {
        Depth::Ansi256
    } else {
        Depth::Ansi16
    }
}

/// The background, from `TUNLION_THEME` (light, dark, auto) and the
/// `COLORFGBG` convention some terminals export ("15;0" is light text on a
/// dark background). Pure. Unknown unless one of them says.
pub fn bg_from(theme: Option<&str>, colorfgbg: Option<&str>) -> Bg {
    match theme.map(|t| t.trim().to_ascii_lowercase()).as_deref() {
        Some("light") => return Bg::Light,
        Some("dark") => return Bg::Dark,
        _ => {}
    }
    let Some(bg) = colorfgbg.and_then(|v| v.rsplit(';').next()).and_then(|b| b.trim().parse::<u8>().ok()) else {
        return Bg::Unknown;
    };
    // 7 (white) and 9..=15 (the bright half) are light backgrounds; 0..=6 and
    // 8 (bright black) are dark ones.
    if bg == 7 || (9..=15).contains(&bg) {
        Bg::Light
    } else {
        Bg::Dark
    }
}

/// The design tokens, as (truecolor, 256-color index, 16-color SGR).
///
/// Derived from the design's oklch tokens: the light and dark tunings are the
/// design's own text colors for each theme (`accInk`, `ok`, `bad`), the middle
/// tuning sits between them so it keeps at least 3:1 contrast on the design's
/// light paper (#f7f6f2) and dark paper (#141412). The 16-color terminal has no
/// orange, so the accent falls back to yellow there.
struct Swatch {
    rgb: (u8, u8, u8),
    idx: u8,
    sgr16: &'static str,
}

const fn sw(r: u8, g: u8, b: u8, idx: u8, sgr16: &'static str) -> Swatch {
    Swatch { rgb: (r, g, b), idx, sgr16 }
}

fn swatch(role: Role, bg: Bg) -> Option<Swatch> {
    Some(match (role, bg) {
        (Role::Accent, Bg::Light) => sw(0xa5, 0x3e, 0x00, 130, "33"),
        (Role::Accent, Bg::Dark) => sw(0xf1, 0x92, 0x66, 209, "93"),
        (Role::Accent, Bg::Unknown) => sw(0xd8, 0x66, 0x2a, 166, "33"),
        (Role::Ok, Bg::Light) => sw(0x13, 0x77, 0x38, 29, "32"),
        (Role::Ok, Bg::Dark) => sw(0x73, 0xc3, 0x85, 72, "92"),
        (Role::Ok, Bg::Unknown) => sw(0x2f, 0x8f, 0x52, 29, "32"),
        (Role::Bad, Bg::Light) => sw(0xaf, 0x3b, 0x43, 131, "31"),
        (Role::Bad, Bg::Dark) => sw(0xf5, 0x8a, 0x8b, 210, "91"),
        (Role::Bad, Bg::Unknown) => sw(0xd5, 0x57, 0x59, 167, "31"),
        (Role::Warn, Bg::Light) => sw(0x8d, 0x5e, 0x00, 94, "33"),
        (Role::Warn, Bg::Dark) => sw(0xe9, 0xb4, 0x52, 179, "93"),
        (Role::Warn, Bg::Unknown) => sw(0xc0, 0x85, 0x1f, 136, "33"),
        (Role::Sub | Role::Strong, _) => return None,
    })
}

/// The SGR sequence that starts `role`, bold or not. Pure.
///
/// `Sub` is the terminal's faint attribute and `Strong` its bold, so both
/// follow whatever ink the terminal uses. The colored roles use the swatch at
/// the terminal's depth.
pub fn sgr(role: Role, bold: bool, depth: Depth, bg: Bg) -> String {
    let b = if bold { "1;" } else { "" };
    match role {
        Role::Sub => "\x1b[2m".to_string(),
        Role::Strong => "\x1b[1m".to_string(),
        _ => {
            let s = swatch(role, bg).expect("colored role has a swatch");
            match depth {
                Depth::True => format!("\x1b[{b}38;2;{};{};{}m", s.rgb.0, s.rgb.1, s.rgb.2),
                Depth::Ansi256 => format!("\x1b[{b}38;5;{}m", s.idx),
                Depth::Ansi16 => format!("\x1b[{b}{}m", s.sgr16),
            }
        }
    }
}

/// Whether motion is turned down: `TUNLION_REDUCED_MOTION` set to anything but
/// empty or `0`. Pure over the value.
pub fn reduced_motion_from(v: Option<&str>) -> bool {
    matches!(v.map(str::trim), Some(s) if !s.is_empty() && s != "0")
}

/// One loop of either motif, in milliseconds. The browser's CSS loop is 5 s;
/// a terminal redraws a few times a second, so the CLI keeps the same rhythm in
/// a 2 s loop, with each beat long enough (150 ms or more) to be seen.
const LOOP_MS: u128 = 2000;

/// The pulse frame at time `ms`: the cursor squashes on `|..||`. Pure.
///
/// Full block at rest, lower half while squashed (the CSS squashes toward the
/// bottom edge). ASCII: `|` at rest, `.` squashed. With reduced motion the
/// cursor stays at rest.
pub fn pulse_frame(ms: u128, unicode: bool, reduced: bool) -> char {
    let t = ms % LOOP_MS;
    let squashed = !reduced && matches!(t, 1000..=1199 | 1500..=1649 | 1750..=1899);
    match (unicode, squashed) {
        (true, false) => '█',
        (true, true) => '▄',
        (false, false) => '|',
        (false, true) => '.',
    }
}

/// The knock frame at time `ms`: three hops, then rest. Pure.
///
/// Lower half at rest, upper half mid-hop. ASCII: `.` at rest, `^` mid-hop.
/// With reduced motion the cursor stays at rest.
pub fn knock_frame(ms: u128, unicode: bool, reduced: bool) -> char {
    let t = ms % LOOP_MS;
    let up = !reduced && matches!(t, 1200..=1349 | 1450..=1599 | 1700..=1849);
    match (unicode, up) {
        (true, false) => '▄',
        (true, true) => '▀',
        (false, false) => '.',
        (false, true) => '^',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_reads_colorterm_then_term() {
        assert_eq!(depth_from(Some("truecolor"), "xterm"), Depth::True);
        assert_eq!(depth_from(Some("24bit"), "xterm"), Depth::True);
        assert_eq!(depth_from(None, "xterm-256color"), Depth::Ansi256);
        assert_eq!(depth_from(None, "xterm"), Depth::Ansi16);
        assert_eq!(depth_from(Some(""), "screen"), Depth::Ansi16);
    }

    #[test]
    fn background_from_theme_and_colorfgbg() {
        assert_eq!(bg_from(Some("light"), Some("15;0")), Bg::Light, "the explicit theme wins");
        assert_eq!(bg_from(Some("DARK"), None), Bg::Dark);
        assert_eq!(bg_from(None, Some("15;0")), Bg::Dark);
        assert_eq!(bg_from(None, Some("0;15")), Bg::Light);
        assert_eq!(bg_from(None, Some("0;default;7")), Bg::Light);
        assert_eq!(bg_from(Some("auto"), Some("12;8")), Bg::Dark);
        assert_eq!(bg_from(None, Some("garbage")), Bg::Unknown);
        assert_eq!(bg_from(None, None), Bg::Unknown);
    }

    #[test]
    fn sgr_by_depth() {
        assert_eq!(sgr(Role::Accent, false, Depth::True, Bg::Unknown), "\x1b[38;2;216;102;42m");
        assert_eq!(sgr(Role::Accent, true, Depth::Ansi256, Bg::Unknown), "\x1b[1;38;5;166m");
        assert_eq!(sgr(Role::Accent, false, Depth::Ansi16, Bg::Unknown), "\x1b[33m");
        assert_eq!(sgr(Role::Ok, false, Depth::Ansi16, Bg::Dark), "\x1b[92m");
        assert_eq!(sgr(Role::Sub, true, Depth::True, Bg::Light), "\x1b[2m", "faint follows the terminal ink");
        assert_eq!(sgr(Role::Strong, false, Depth::Ansi16, Bg::Dark), "\x1b[1m");
    }

    #[test]
    fn every_colored_role_has_every_tuning() {
        for role in [Role::Accent, Role::Ok, Role::Bad, Role::Warn] {
            for bg in [Bg::Light, Bg::Dark, Bg::Unknown] {
                assert!(swatch(role, bg).is_some(), "{role:?} on {bg:?}");
            }
        }
    }

    #[test]
    fn reduced_motion_values() {
        assert!(!reduced_motion_from(None));
        assert!(!reduced_motion_from(Some("")));
        assert!(!reduced_motion_from(Some("0")));
        assert!(reduced_motion_from(Some("1")));
        assert!(reduced_motion_from(Some("yes")));
    }

    #[test]
    fn pulse_rhythm_is_one_then_two() {
        let squashed: Vec<bool> = (0..LOOP_MS as u32 / 50)
            .map(|i| pulse_frame(i as u128 * 50, true, false) == '▄')
            .collect();
        // Count rising edges: one beat, a gap, then two beats close together.
        let beats = squashed.windows(2).filter(|w| !w[0] && w[1]).count()
            + usize::from(squashed[0] && !*squashed.last().unwrap());
        assert_eq!(beats, 3, "|..|| is three beats per loop");
        assert_eq!(pulse_frame(0, true, false), '█', "the loop starts at rest");
        assert_eq!(pulse_frame(1100, true, false), '▄');
        assert_eq!(pulse_frame(1100, false, false), '.');
        assert_eq!(pulse_frame(1100, true, true), '█', "reduced motion stays at rest");
        assert_eq!(pulse_frame(1100 + LOOP_MS, true, false), '▄', "it loops");
    }

    #[test]
    fn knock_is_three_hops() {
        let up: Vec<bool> = (0..LOOP_MS as u32 / 50)
            .map(|i| knock_frame(i as u128 * 50, true, false) == '▀')
            .collect();
        assert_eq!(up.windows(2).filter(|w| !w[0] && w[1]).count(), 3);
        assert_eq!(knock_frame(1250, false, false), '^');
        assert_eq!(knock_frame(1250, true, true), '▄', "reduced motion stays at rest");
    }

    #[test]
    fn beats_last_long_enough_to_see() {
        // At a 120 ms redraw, every beat must cover at least one redraw.
        for (a, b) in [(1000u128, 1199u128), (1500, 1649), (1750, 1899)] {
            assert!(b - a + 1 >= 150, "pulse beat {a}..{b} too short");
        }
        for (a, b) in [(1200u128, 1349u128), (1450, 1599), (1700, 1849)] {
            assert!(b - a + 1 >= 150, "knock hop {a}..{b} too short");
        }
    }
}
