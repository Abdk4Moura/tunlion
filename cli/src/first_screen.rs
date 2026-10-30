//! The bare-argument comfort router and the first-screen action list.
//!
//! `classify_bare_token` decides what a bare `tunlion <word>` means (help, a
//! path to send, a nameplate, `device:port`, `device.mesh`, a known device name,
//! or nothing it recognises), and `first_screen_actions` is the list the no-args
//! screen offers. They travel together because both decide what a bare launch
//! does.
use crate::BareTarget;
use crate::looks_like_pake_code;
use crate::regex_lite_code;

/// `add` was handed an invitation instead of a pairing code. One source for the
/// sentence so the test and the error cannot drift apart.
/// The ONE way in for someone holding something they were given. There used to
/// be two entries, "Pair with a code I was given" (which ran `add`, the OFFERING
/// side, so a typed code minted a second code) and "Join with an invitation"
/// (which refused a code as "unknown format"). `join` with nothing on the line
/// asks once and tells a code from an invitation from a file itself.
pub(crate) const ACCEPT_ENTRY: (&str, &str) = ("I have a code or an invitation", "join");

/// The verb of the home screen's "More…" entry: opens [`more_actions`] instead
/// of naming a command.
pub(crate) const MORE: &str = "more";

/// What the bare `tunlion` screen offers, given what this machine actually has.
///
/// Start from an action, in plain words, and keep it short: the everyday
/// actions on the screen, everything else one step away under "More…" (see
/// [`more_actions`]). Nothing that used to be offered became unreachable; it
/// moved. A nine-item list of verbs read as a command index, not a start.
///
/// Extracted so #194 can be pinned without driving a terminal: the bug was a
/// menu that contradicted the header printed directly above it.
pub(crate) fn first_screen_actions(
    owner: bool,
    joined: bool,
    device_count: usize,
) -> Vec<(&'static str, &'static str)> {
    if owner {
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("Connect a device or share access", "add"),
            ("More\u{2026}", MORE),
        ]
    } else if joined {
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("See my devices", "devices"),
            ("More\u{2026}", MORE),
        ]
    } else if device_count == 0 {
        vec![
            ("Connect a device or share access", "add"),
            // #209: there are TWO ways to be brought into an identity. `add`
            // mints a pairing code; `add --for` mints a bounded invitation
            // claimed with `join`. Someone holding either needs an entry here,
            // so the one accept entry takes both (see ACCEPT_ENTRY).
            ACCEPT_ENTRY,
            ("Receive a one-time transfer", "receive"),
        ]
    } else {
        // #194: this branch is about having no IDENTITY, not about being the
        // first device. A machine paired by code has peers in devices.json and
        // no identity of its own. Offer what already works: those peers are
        // reachable right now, so hiding `send` and `devices` behind a setup
        // step nobody needs is its own small lie.
        vec![
            ("Send something", "send"),
            ("Receive something", "receive"),
            ("See my devices", "devices"),
            ("Connect a device or share access", "add"),
            ACCEPT_ENTRY, // #209, as above
        ]
    }
}

/// The second page behind "More…": real, less frequent actions. Each one was on
/// the first screen before and stays reachable without knowing a flag (#209:
/// a path whose menu entry disappears is a path nobody finds).
pub(crate) fn more_actions(owner: bool) -> Vec<(&'static str, &'static str)> {
    if owner {
        vec![
            ("Open files on another device", "mount"),
            ("See my devices", "devices"),
            ("Change what a device can do", "promote"),
            ("Invite with a file they claim later", "add --for"),
            // An unattended runner is a THIRD thing, not pairing: nobody is there
            // to consent live, so it gets a temporary key.
            ("Key for a CI runner or borrowed machine", "add --for runner"),
            // The way back from the two entries above: an invitation file that
            // leaked stays claimable until it runs out, unless withdrawn.
            ("Withdraw an invitation", "add --withdraw"),
            ("Keep running in the background", "up --install"),
            ("Show this device's identity", "id"),
        ]
    } else {
        vec![
            ("Open files on another device", "mount"),
            ("Change what a device can do", "promote"),
            ("Show this device's identity", "id"),
        ]
    }
}

/// Pure classification for the bare-argument router. All environment access is
/// injected through the closures so tests can pass fakes. The function does NOT
/// touch capabilities, prompts, or authorizations: it is a router only.
pub(crate) fn classify_bare_token(
    token: &str,
    file_exists: &dyn Fn(&str) -> bool,
    is_known_device: &dyn Fn(&str) -> bool,
) -> BareTarget {
    if token == "help" {
        return BareTarget::Help;
    }
    // Preserve the existing path-first behavior, except when the same bare name
    // is also a known device. A code-shaped filename is still a filename here.
    let is_file = file_exists(token);
    let is_device = is_known_device(token);
    if is_file && is_device {
        return BareTarget::AmbiguousFileDevice;
    }
    if is_file {
        return BareTarget::Send;
    }
    // 4-digit nameplates are the pairing-code shape; keep routing them to `pair`
    // because that is the long-standing bare-code behavior.
    if looks_like_pake_code(token) {
        return BareTarget::Add;
    }
    // 2-3 digit nameplates are the legacy one-time transfer-code shape.
    if regex_lite_code(token) {
        return BareTarget::Receive;
    }
    // `device:port` -> forward (same port locally and remotely). The device part
    // must be a known petname and the port must parse as a u16. If either fails,
    // fall through to the did-you-mean path; do not guess.
    if let Some((dev, port_str)) = token.rsplit_once(':') {
        if !dev.is_empty() && port_str.parse::<u16>().is_ok() && is_known_device(dev) {
            let port = port_str.to_string();
            return BareTarget::Forward {
                lport: port.clone(),
                peer: dev.to_string(),
                rport: port,
            };
        }
    }
    // `device.mesh` or `device.mesh:port` -> reach. The reach command validates
    // the address and reports unknown peers, so do not require a local petname
    // here. Mesh addresses are not limited to the current device index.
    if token.ends_with(".mesh")
        || token
            .split_once(".mesh:")
            .is_some_and(|(dev, port)| !dev.is_empty() && !port.is_empty())
    {
        return BareTarget::Reach(token.to_string());
    }
    // A non-file known device opens a PTY. The router never escalates privilege,
    // so the command path remains responsible for capability checks.
    if is_device {
        return BareTarget::Shell;
    }
    BareTarget::Unknown
}

/// Set on the child a Start Menu launch runs, so the child shows the menu once
/// and the launcher can tell "closed the menu" from "finished an action".
pub(crate) const HOME_CHILD_ENV: &str = "TUNLION_HOME_CHILD";
/// Exit status of a home-menu child whose menu was closed (Esc/q) rather than
/// answered. Outside the documented taxonomy on purpose: only the launcher
/// below ever sees it.
pub(crate) const HOME_CLOSED: u8 = 100;

/// A Start Menu or Explorer launch gets a console window of its own, and that
/// window closes the moment the process exits. Running one action and exiting
/// therefore made the result vanish before it could be read, and dropped the
/// person back at the desktop. When this process owns its console and was
/// started with no arguments, act as a small launcher instead: run the menu in
/// a child, then offer "back to the menu" until the person closes it.
///
/// Never in a shell (the shell shares the console), never when stdin is not a
/// terminal, and `TUNLION_HOME_LOOP=0` turns it off. Returns `None` when this
/// process should just carry on as normal.
pub(crate) fn maybe_run_home_loop() -> Option<std::process::ExitCode> {
    use std::io::IsTerminal;
    if std::env::args_os().len() != 1
        || std::env::var_os(HOME_CHILD_ENV).is_some()
        || std::env::var("TUNLION_HOME_LOOP").is_ok_and(|v| v == "0")
        || !std::io::stdin().is_terminal()
        || !crate::platform::console_is_ours()
    {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    ignore_console_interrupts();
    loop {
        let status = match crate::platform::command(&exe).env(HOME_CHILD_ENV, "1").status() {
            Ok(status) => status,
            // Could not start the child: fall back to running in this process.
            Err(_) => return None,
        };
        if status.code() == Some(i32::from(HOME_CLOSED)) {
            return Some(std::process::ExitCode::SUCCESS);
        }
        let exit = std::process::ExitCode::from(status.code().and_then(|c| u8::try_from(c).ok()).unwrap_or(1));
        crate::ui::say("");
        crate::ui::say(&crate::ui::paint(crate::ui::Tone::Dim, "  Enter: back to the menu \u{b7} Esc: close"));
        if !wait_back_or_close() {
            return Some(exit);
        }
    }
}

/// True for Enter (back to the menu), false for Esc / q / Ctrl-C (close).
fn wait_back_or_close() -> bool {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    let Ok(_guard) = crate::codeentry::RawGuard::enable_inline() else { return false };
    loop {
        let Ok(Event::Key(key)) = event::read() else { return false };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Enter => return true,
            KeyCode::Esc | KeyCode::Char('q') => return false,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
            _ => {}
        }
    }
}

/// The launcher shares the console with the child it runs, so Ctrl-C reaches
/// both; see `platform::ignore_console_interrupts`.
fn ignore_console_interrupts() {
    crate::platform::ignore_console_interrupts();
}

/// Where the home screen's "recent" entry lives: one small file in the config
/// dir, a convenience only (losing it loses nothing but the shortcut).
fn recent_path() -> std::path::PathBuf {
    crate::settings::config_dir().join("recent.json")
}

/// Remember an interactive shell into `device`, for the home screen.
pub(crate) fn remember_shell(device: &str) {
    let body = serde_json::json!({ "shell": device }).to_string();
    let _ = std::fs::write(recent_path(), body);
}

/// The home screen's recent entry, as (label, argv), when the remembered device
/// is still one of `known`. Pure over its inputs apart from the one read.
pub(crate) fn recent_action(known: &[String]) -> Option<(String, String)> {
    let raw = std::fs::read_to_string(recent_path()).ok()?;
    recent_from(&raw, known)
}

/// The rule behind `recent_action`, pure: a forgotten or renamed device, or a
/// name that is not a single word, offers nothing.
pub(crate) fn recent_from(raw: &str, known: &[String]) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let device = value["shell"].as_str()?;
    if device.is_empty() || device.split_whitespace().count() != 1 || !known.iter().any(|k| k == device) {
        return None;
    }
    Some((format!("Shell on {device}"), format!("shell {device}")))
}

#[cfg(test)]
mod recent_tests {
    use super::recent_from;

    #[test]
    fn recent_shell_is_offered_only_for_a_still_known_device() {
        let known = vec!["desk".to_string(), "pixel".to_string()];
        assert_eq!(
            recent_from(r#"{"shell":"desk"}"#, &known),
            Some(("Shell on desk".to_string(), "shell desk".to_string()))
        );
        assert_eq!(recent_from(r#"{"shell":"gone"}"#, &known), None, "a forgotten device offers nothing");
        assert_eq!(recent_from(r#"{"shell":"desk; rm"}"#, &known), None);
        assert_eq!(recent_from("not json", &known), None);
        assert_eq!(recent_from(r#"{"shell":""}"#, &known), None);
    }
}

