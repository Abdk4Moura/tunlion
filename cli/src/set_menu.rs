//! `tunlion set` at a terminal: the settings registry as a short menu.
//!
//! Groups first (four short lists, so a digit answers any row), then one
//! setting, whose control follows its kind: a toggle for on/off, the values of
//! a fixed set, a checklist for interface and device lists, a pick order for
//! `prefer`, a validated line for text. Per-device values are one step further
//! where the registry allows them.
//!
//! Every change goes through `settings::run_set`, the call behind
//! `tunlion set <key> <value>`, so validation, the stored bytes, the receipt
//! and the live reconfigure of a running daemon are the scripted path's own.
//! Accepting a control without changing it writes nothing.
//!
//! The menu opens only with a terminal on both ends ([`opens_menu`]): a pipe,
//! `--json`, `--no-interactive`, `TUNLION_NONINTERACTIVE` or TERM=dumb keep
//! `set`'s table, TSV and JSON readout exactly as they were.

use anyhow::Result;

use crate::codeentry::{self, Collapse, PickOpts, Picked};
use crate::settings::{self, Kind, Origin, ScopeKind, Setting};
use crate::ui::{self, Tone};

/// The menu's first page. Every registry key sits in exactly one group (a test
/// holds this), so a new setting cannot be left out of the menu.
pub(crate) const GROUPS: &[(&str, &[&str])] = &[
    ("This device", &["name", "drop-dir", "auto-extract", "verbosity"]),
    (
        "Shell",
        &["shell", "shell-user", "shell-program", "sshd-overlay", "ssh.cert_ttl", "gate.settle_ms", "fleet.owner_grants"],
    ),
    ("Connections", &["relay", "server", "prefer", "avoid", "only", "auto-warm", "warm-max", "warm-peers"]),
    ("Network", &["tun-addr", "l3-mode", "wireguard", "auto-proxy", "advertise-routes", "accept-routes", "route-snat"]),
];

// ------------------------------------------------------------------ gate --

/// What the menu needs from the process to open.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Terminal {
    /// The interactivity gate: stdin is a terminal and nobody opted out.
    pub interactive: bool,
    /// stdout is a terminal (a captured stdout wants the readout).
    pub stdout: bool,
    /// stderr redraws in place (a tty that is not TERM=dumb).
    pub live: bool,
}

impl Terminal {
    pub(crate) fn now() -> Terminal {
        use std::io::IsTerminal;
        Terminal {
            interactive: crate::policy::interactive_allowed(),
            stdout: std::io::stdout().is_terminal(),
            live: ui::caps().live,
        }
    }
}

/// Whether `set` (or `set <key>`) opens the menu instead of printing. Pure.
/// `global_scope` is false when `--peer` was given: that form reads.
pub(crate) fn opens_menu(global_scope: bool, json: bool, t: Terminal) -> bool {
    global_scope && !json && t.interactive && t.stdout && t.live
}

// ------------------------------------------------------------- the words --

/// A value as the menu shows it.
pub(crate) fn shown(value: &str) -> &str {
    if value.is_empty() {
        "(none)"
    } else {
        value
    }
}

/// Where a value comes from, in the readout's own words.
pub(crate) fn origin_word(origin: &Origin) -> String {
    match origin {
        Origin::Peer(_) => "this device".to_string(),
        other => other.label(),
    }
}

/// The group a key belongs to.
pub(crate) fn group_of(key: &str) -> &'static str {
    GROUPS.iter().find(|(_, keys)| keys.contains(&key)).map(|(g, _)| *g).unwrap_or("Settings")
}

/// One row of a group's list: key, value, provenance, and how many devices
/// hold their own value. Pure.
pub(crate) fn setting_row(key_w: usize, key: &str, value: &str, origin: &Origin, overrides: usize) -> String {
    let mut row = format!("{key:<key_w$}  {} \u{b7} {}", shown(value), origin_word(origin));
    if overrides > 0 {
        row.push_str(&format!(" \u{b7} {overrides} {}", if overrides == 1 { "device" } else { "devices" }));
    }
    row
}

/// One row of the first page. Pure.
pub(crate) fn group_row(label_w: usize, label: &str, changed: usize) -> String {
    let summary = if changed == 0 { "defaults".to_string() } else { format!("{changed} changed") };
    format!("{label:<label_w$}  {summary}")
}

/// The fixed values a setting offers, when it has them.
pub(crate) fn choices(s: &Setting) -> Option<Vec<&'static str>> {
    match s.kind {
        Kind::Enum(vals) => Some(vals.to_vec()),
        _ if s.key == "verbosity" => Some(settings::VERBOSITY_WORDS[..4].to_vec()),
        _ => None,
    }
}

/// What one setting's screen offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Store this value (the toggle's other state, or one of the choices).
    Value(String),
    /// Open the setting's control: a checklist, an order, or a line.
    Edit,
    /// Remove the stored value: back to the default, or for a device, back to
    /// the value every device uses.
    Reset,
    /// Choose a device to give its own value.
    Devices,
}

/// The actions for a setting at one scope, in order. Pure.
pub(crate) fn actions(s: &Setting, value: &str, origin: &Origin, peer: Option<&str>, have_devices: bool) -> Vec<Action> {
    let mut out = Vec::new();
    if s.kind == Kind::Bool {
        let on = matches!(value, "on" | "true" | "yes" | "1");
        out.push(Action::Value((if on { "off" } else { "on" }).to_string()));
    } else if let Some(vals) = choices(s) {
        out.extend(vals.iter().map(|v| Action::Value(v.to_string())));
    } else {
        out.push(Action::Edit);
    }
    let stored_here = match peer {
        None => matches!(origin, Origin::Global),
        Some(_) => matches!(origin, Origin::Peer(_)),
    };
    if stored_here {
        out.push(Action::Reset);
    }
    if peer.is_none() && s.scope == ScopeKind::GlobalOrPeer && have_devices {
        out.push(Action::Devices);
    }
    out
}

/// The label of an action. `fallback` is the value a reset lands on. Pure.
pub(crate) fn action_label(a: &Action, s: &Setting, value: &str, peer: Option<&str>, fallback: &str) -> String {
    match a {
        Action::Value(v) if s.kind == Kind::Bool => (if v == "on" { "Turn on" } else { "Turn off" }).to_string(),
        Action::Value(v) if v == value => format!("{v} \u{b7} now"),
        Action::Value(v) => v.clone(),
        Action::Edit => "Change\u{2026}".to_string(),
        Action::Reset if peer.is_some() => format!("Use the value for all devices \u{b7} {}", shown(fallback)),
        Action::Reset => format!("Reset to default \u{b7} {}", shown(fallback)),
        Action::Devices => "For one device\u{2026}".to_string(),
    }
}

/// Which row starts selected: the current choice for a fixed set, else the
/// first row, so Enter on a toggle flips it. Pure.
pub(crate) fn initial_action(acts: &[Action], value: &str) -> usize {
    acts.iter().position(|a| *a == Action::Value(value.to_string())).unwrap_or(0)
}

/// Greedy word wrap to `width` columns. Pure.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// The lines above a setting's control: where you are, what it does, its
/// value and where that value comes from. Each fits the width, so the screen
/// can be erased by counting them.
fn context_lines(s: &Setting, crumb: &str, peer: Option<&str>, value: &str, origin: &Origin) -> Vec<String> {
    let width = codeentry::term_width().saturating_sub(4);
    let mut title = format!("SETTINGS  /  {crumb}  /  {}", s.key);
    if let Some(p) = peer {
        title.push_str(&format!("  /  {p}"));
    }
    let mut out = vec![ui::header(Tone::Brand, Tone::Bold, &codeentry::fit(&title, width))];
    for line in wrap(s.help, width.saturating_sub(2)) {
        out.push(format!("  {}", ui::paint(Tone::Dim, &codeentry::fit(&line, width))));
    }
    let now = codeentry::fit(shown(value), width.saturating_sub(20));
    out.push(format!("  {} {}", ui::paint(Tone::Bold, &now), ui::paint(Tone::Dim, &format!("\u{b7} {}", origin_word(origin)))));
    if let Origin::Env(var) = origin {
        out.push(ui::paint(Tone::Warn, &codeentry::fit(&format!("  {var} is set in the environment and wins over this"), width)));
    }
    out
}

// ------------------------------------------------------------- applying --

/// Store one value the way `tunlion set <key> <value> [--peer] [--hard]`
/// does, through the same call, so the menu and a script cannot differ.
pub(crate) async fn apply(s: &Setting, value: &str, peer: Option<&str>, hard: bool, dry_run: bool) -> Result<()> {
    let peers: Vec<String> = peer.map(str::to_string).into_iter().collect();
    let hard = hard && s.key == "prefer";
    settings::run_set(Some(s.key), Some(value), &peers, dry_run, false, false, hard, false, false, false).await
}

/// `tunlion set <key> --unset [--peer]`, through the same call.
async fn reset(s: &Setting, peer: Option<&str>, dry_run: bool) -> Result<()> {
    let peers: Vec<String> = peer.map(str::to_string).into_iter().collect();
    settings::run_set(Some(s.key), None, &peers, dry_run, false, true, false, false, false, false).await
}

fn report(result: Result<()>) {
    if let Err(e) = result {
        ui::say(&ui::paint(Tone::Err, &format!("  {} {e:#}", ui::glyph_err())));
    }
}

// ---------------------------------------------------------------- screens --

fn interrupted() -> ! {
    crate::exit_codes::interrupted_exit(crate::exit_codes::INTERRUPTED)
}

fn draw(lines: &[String]) -> usize {
    let frame: String = lines.iter().map(|l| format!("\r\x1b[2K{l}\r\n")).collect();
    codeentry::write_frame(&frame);
    lines.len()
}

/// Erase `n` lines drawn above the cursor, leaving it where they began.
fn erase(n: usize) {
    if n > 0 {
        codeentry::write_frame(&format!("\x1b[{n}A\r\x1b[J"));
    }
}

fn device_names() -> Vec<String> {
    let mut names: Vec<String> = crate::devices_load().into_iter().map(|(n, _)| n).collect();
    names.sort();
    names.dedup();
    names
}

fn changed_in(keys: &[&str]) -> usize {
    keys.iter()
        .filter_map(|k| settings::find(k))
        .filter(|s| !matches!(settings::resolve(s, None).1, Origin::Default) || !settings::overrides_of(s).is_empty())
        .count()
}

/// Bare `tunlion set` at a terminal. Esc leaves; Ctrl-C exits 130.
pub(crate) async fn run(dry_run: bool) -> Result<()> {
    let title = if dry_run { "SETTINGS  /  dry run" } else { "SETTINGS" };
    let label_w = GROUPS.iter().map(|(g, _)| g.len()).max().unwrap_or(0);
    let mut sel = 0;
    loop {
        let rows: Vec<String> = GROUPS.iter().map(|(g, keys)| group_row(label_w, g, changed_in(keys))).collect();
        match codeentry::pick_opts(title, &rows, PickOpts { collapse: Some(Collapse::Erase), initial: sel, ..Default::default() })? {
            Picked::Item(i) => {
                sel = i;
                group(i, dry_run).await?;
            }
            Picked::Interrupted => interrupted(),
            _ => return Ok(()),
        }
    }
}

async fn group(index: usize, dry_run: bool) -> Result<()> {
    let (label, keys) = GROUPS[index];
    let list: Vec<&'static Setting> = keys.iter().filter_map(|k| settings::find(k)).collect();
    let key_w = list.iter().map(|s| s.key.len()).max().unwrap_or(0);
    let mut sel = 0;
    loop {
        let rows: Vec<String> = list
            .iter()
            .map(|s| {
                let (value, origin) = settings::resolve(s, None);
                setting_row(key_w, s.key, &value, &origin, settings::overrides_of(s).len())
            })
            .collect();
        let title = format!("SETTINGS  /  {label}");
        match codeentry::pick_opts(&title, &rows, PickOpts { collapse: Some(Collapse::Erase), initial: sel, ..Default::default() })? {
            Picked::Item(i) => {
                sel = i;
                edit(list[i], label, dry_run).await?;
            }
            Picked::Interrupted => interrupted(),
            _ => return Ok(()),
        }
    }
}

/// `tunlion set <key>` at a terminal: that one setting's screen.
pub(crate) async fn edit_one(s: &'static Setting, dry_run: bool) -> Result<()> {
    edit(s, group_of(s.key), dry_run).await
}

async fn edit(s: &'static Setting, crumb: &str, dry_run: bool) -> Result<()> {
    loop {
        match scope_screen(s, crumb, None, dry_run).await? {
            Next::Devices => devices(s, crumb, dry_run).await?,
            Next::Done | Next::Back => return Ok(()),
        }
    }
}

async fn devices(s: &'static Setting, crumb: &str, dry_run: bool) -> Result<()> {
    let mut sel = 0;
    loop {
        let names = device_names();
        if names.is_empty() {
            return Ok(());
        }
        let w = names.iter().map(|n| n.chars().count()).max().unwrap_or(0);
        let rows: Vec<String> = names
            .iter()
            .map(|n| {
                let (value, origin) = settings::resolve(s, Some(n));
                format!("{n:<w$}  {} \u{b7} {}", shown(&value), origin_word(&origin))
            })
            .collect();
        let title = format!("SETTINGS  /  {crumb}  /  {}  /  devices", s.key);
        match codeentry::pick_opts(&title, &rows, PickOpts { collapse: Some(Collapse::Erase), initial: sel, ..Default::default() })? {
            Picked::Item(i) => {
                sel = i;
                scope_screen(s, crumb, Some(&names[i]), dry_run).await?;
            }
            Picked::Interrupted => interrupted(),
            _ => return Ok(()),
        }
    }
}

enum Next {
    /// Something was chosen and handled (a change, a reset, or "keep").
    Done,
    Back,
    Devices,
}

/// One setting at one scope (every device, or one named device).
async fn scope_screen(s: &'static Setting, crumb: &str, peer: Option<&str>, dry_run: bool) -> Result<Next> {
    loop {
        let (value, origin) = settings::resolve(s, peer);
        let acts = actions(s, &value, &origin, peer, !device_names().is_empty());
        let fallback = match peer {
            Some(_) => settings::resolve(s, None).0,
            None => settings::effective_default(s),
        };
        let shown_lines = draw(&context_lines(s, crumb, peer, &value, &origin));
        // A setting whose only action is its control opens the control.
        let direct = acts == [Action::Edit];
        let chosen = if direct {
            Action::Edit
        } else {
            let labels: Vec<String> = acts.iter().map(|a| action_label(a, s, &value, peer, &fallback)).collect();
            let opts = PickOpts { collapse: Some(Collapse::Erase), initial: initial_action(&acts, &value), ..Default::default() };
            match codeentry::pick_opts("", &labels, opts)? {
                Picked::Item(i) => acts[i].clone(),
                Picked::Interrupted => {
                    erase(shown_lines);
                    interrupted()
                }
                _ => {
                    erase(shown_lines);
                    return Ok(Next::Back);
                }
            }
        };
        match chosen {
            Action::Devices => {
                erase(shown_lines);
                return Ok(Next::Devices);
            }
            Action::Reset => {
                erase(shown_lines);
                report(reset(s, peer, dry_run).await);
                return Ok(Next::Done);
            }
            Action::Value(v) => {
                erase(shown_lines);
                if v != value {
                    report(apply(s, &v, peer, false, dry_run).await);
                }
                return Ok(Next::Done);
            }
            Action::Edit => {
                let edited = control(s, peer, &value)?;
                erase(shown_lines);
                match edited {
                    Edited::Value(v, hard) => {
                        report(apply(s, &v, peer, hard, dry_run).await);
                        return Ok(Next::Done);
                    }
                    Edited::Unchanged => return Ok(Next::Done),
                    Edited::Back if direct => return Ok(Next::Back),
                    // Back from the control returns to this setting's actions.
                    Edited::Back => continue,
                    Edited::Interrupted => interrupted(),
                }
            }
        }
    }
}

// --------------------------------------------------------------- controls --

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Edited {
    /// The new value, and for `prefer` whether it is hard.
    Value(String, bool),
    Unchanged,
    Back,
    Interrupted,
}

fn split_list(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|i| !i.is_empty()).map(str::to_string).collect()
}

/// The control for a setting's value: a checklist where there is a known set
/// to pick from, a line otherwise.
fn control(s: &Setting, peer: Option<&str>, value: &str) -> Result<Edited> {
    let offered: Vec<(String, String)> = match s.key {
        "prefer" | "avoid" | "only" => crate::interact::enumerate_interfaces()
            .into_iter()
            .map(|i| {
                let mut detail: Vec<String> = i.ips.iter().map(|ip| ip.to_string()).collect();
                if i.group != "other" {
                    detail.push(i.group.clone());
                }
                (i.name, detail.join(" \u{b7} "))
            })
            .collect(),
        "warm-peers" => device_names().into_iter().map(|n| (n, String::new())).collect(),
        _ => return ask_line(s, value),
    };
    let saved = split_list(value);
    if offered.is_empty() && saved.is_empty() {
        return ask_line(s, value);
    }
    let ordered = s.key == "prefer";
    let hard = ordered && settings::prefer_strength(peer) == "hard";
    run_checklist(Checklist::new(&saved, offered, ordered, hard))
}

/// A checklist's state, apart from the terminal. With `ordered`, the order
/// things are picked in is the value's order (`prefer`).
#[derive(Debug, Clone)]
pub(crate) struct Checklist {
    items: Vec<(String, String)>,
    picked: Vec<usize>,
    ordered: bool,
    hard: bool,
    cursor: usize,
    initial: (String, bool),
}

impl Checklist {
    /// Saved entries first, in their saved order, then what is offered and not
    /// saved. A saved entry that is not offered (a CIDR, a group, an interface
    /// that is down) stays, so opening and saving never drops it.
    pub(crate) fn new(saved: &[String], offered: Vec<(String, String)>, ordered: bool, hard: bool) -> Checklist {
        let mut items: Vec<(String, String)> = Vec::new();
        for name in saved {
            let detail = offered.iter().find(|(n, _)| n == name).map(|(_, d)| d.clone()).unwrap_or_default();
            if !items.iter().any(|(n, _)| n == name) {
                items.push((name.clone(), detail));
            }
        }
        for (name, detail) in offered {
            if !items.iter().any(|(n, _)| *n == name) {
                items.push((name, detail));
            }
        }
        let picked: Vec<usize> = (0..items.len()).filter(|i| saved.contains(&items[*i].0)).collect();
        let mut c = Checklist { items, picked, ordered, hard, cursor: 0, initial: (String::new(), hard) };
        c.initial = (c.value(), hard);
        c
    }

    pub(crate) fn toggle(&mut self) {
        if let Some(at) = self.picked.iter().position(|i| *i == self.cursor) {
            self.picked.remove(at);
        } else {
            self.picked.push(self.cursor);
        }
    }

    pub(crate) fn move_by(&mut self, up: bool) {
        let n = self.items.len();
        self.cursor = if up { (self.cursor + n - 1) % n } else { (self.cursor + 1) % n };
    }

    /// Strength applies to a non-empty order only.
    pub(crate) fn strength_applies(&self) -> bool {
        self.ordered && !self.picked.is_empty()
    }

    pub(crate) fn toggle_strength(&mut self) {
        if self.strength_applies() {
            self.hard = !self.hard;
        }
    }

    /// The value to store: pick order for an order, list order otherwise.
    pub(crate) fn value(&self) -> String {
        let mut idx = self.picked.clone();
        if !self.ordered {
            idx.sort_unstable();
        }
        idx.iter().map(|i| self.items[*i].0.as_str()).collect::<Vec<_>>().join(",")
    }

    pub(crate) fn outcome(&self) -> Edited {
        // Strength means nothing without an order, before or after.
        let hard = self.hard && !self.picked.is_empty();
        let was_hard = self.initial.1 && !self.initial.0.is_empty();
        if self.value() == self.initial.0 && hard == was_hard {
            Edited::Unchanged
        } else {
            Edited::Value(self.value(), hard)
        }
    }

    pub(crate) fn row(&self, i: usize) -> String {
        let mark = match self.picked.iter().position(|p| *p == i) {
            Some(rank) if self.ordered => format!("[{}]", rank + 1),
            Some(_) => "[x]".to_string(),
            None => "[ ]".to_string(),
        };
        let (name, detail) = &self.items[i];
        if detail.is_empty() {
            format!("{mark} {name}")
        } else {
            format!("{mark} {name}  {detail}")
        }
    }

    /// The hint line: only the keys that do something here.
    pub(crate) fn hints(&self) -> String {
        let mut line = String::new();
        if self.items.len() > 1 {
            line.push_str("\u{2191}\u{2193} move \u{b7} ");
        }
        line.push_str(if self.ordered { "space pick in order" } else { "space pick" });
        if self.strength_applies() {
            line.push_str(if self.hard { " \u{b7} h hard" } else { " \u{b7} h soft" });
        }
        let clearing = self.picked.is_empty() && !self.initial.0.is_empty();
        line.push_str(if clearing { " \u{b7} \u{23ce} clear" } else { " \u{b7} \u{23ce} save" });
        line.push_str(" \u{b7} esc back");
        line
    }
}

fn render_checklist(c: &Checklist, prev: usize) -> usize {
    let width = codeentry::term_width().saturating_sub(4);
    let (first, view, above, below) = codeentry::viewport_window(c.cursor, c.items.len(), codeentry::VIEWPORT);
    let dim = ui::tone_code(Tone::Dim);
    let accent = ui::tone_code(Tone::Brand);
    let reset = ui::tone_reset();
    let mut frame = String::new();
    if prev > 0 {
        frame.push_str(&format!("\x1b[{prev}A"));
    }
    let mut drawn = 0;
    if above > 0 {
        frame.push_str(&format!("\r\x1b[2K  {dim}\u{2191} {above} more{reset}\r\n"));
        drawn += 1;
    }
    for i in first..first + view {
        let text = codeentry::fit(&c.row(i), width.saturating_sub(4));
        if i == c.cursor {
            frame.push_str(&format!("\r\x1b[2K  {accent}\u{276f}{reset} {accent}{text}{reset}\r\n"));
        } else {
            frame.push_str(&format!("\r\x1b[2K    {text}\r\n"));
        }
        drawn += 1;
    }
    if below > 0 {
        frame.push_str(&format!("\r\x1b[2K  {dim}\u{2193} {below} more{reset}\r\n"));
        drawn += 1;
    }
    frame.push_str(&format!("\r\x1b[2K  {dim}{}{reset}\r\n", codeentry::fit(&c.hints(), width)));
    drawn += 1;
    // Rows above and below the viewport can appear or vanish as the cursor
    // moves; clear whatever the last frame left under this one.
    frame.push_str("\x1b[J");
    codeentry::write_frame(&frame);
    drawn
}

fn run_checklist(mut c: Checklist) -> Result<Edited> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    let guard = codeentry::RawGuard::enable_inline()?;
    let mut drawn = 0;
    let outcome = loop {
        drawn = render_checklist(&c, drawn);
        let Event::Key(k) = event::read()? else { continue };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        match k.code {
            KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break Edited::Interrupted,
            KeyCode::Char('\u{3}') => break Edited::Interrupted,
            KeyCode::Up | KeyCode::Char('k') => c.move_by(true),
            KeyCode::Down | KeyCode::Char('j') => c.move_by(false),
            KeyCode::Char(' ') => c.toggle(),
            KeyCode::Char('h') => c.toggle_strength(),
            KeyCode::Enter => break c.outcome(),
            KeyCode::Esc | KeyCode::Char('q') => break Edited::Back,
            _ => {}
        }
    };
    erase(drawn);
    drop(guard);
    Ok(outcome)
}

/// What a line's text means right now: refused (with why), unchanged, or
/// ready to save. Uses the same validation `set <key> <value>` does.
pub(crate) fn judge_line(s: &Setting, text: &str, current: &str) -> (Tone, String) {
    match settings::validate(s, text) {
        Err(e) => (Tone::Warn, e.to_string()),
        Ok(v) if v == current => (Tone::Dim, "\u{23ce} keep \u{b7} esc back".to_string()),
        Ok(_) => (Tone::Ok, "\u{23ce} save \u{b7} esc back".to_string()),
    }
}

fn render_line(prompt: &str, text: &str, tone: Tone, steer: &str) {
    let width = codeentry::term_width().saturating_sub(2);
    let room = width.saturating_sub(prompt.chars().count() + 4);
    // Show the tail of a long value: a wrapped line breaks the redraw.
    let n = text.chars().count();
    let keep = room.saturating_sub(24).max(8);
    let visible: String = if n > keep {
        let tail: String = text.chars().skip(n - keep + 1).collect();
        format!("\u{2026}{tail}")
    } else {
        text.to_string()
    };
    let left = room.saturating_sub(visible.chars().count() + 3);
    let steer = codeentry::fit(steer, left);
    let col = 2 + prompt.chars().count() + visible.chars().count();
    let frame = format!(
        "\r\x1b[2K  {}{visible}   {}\r\x1b[{col}C",
        ui::paint(Tone::Bold, prompt),
        if left >= 8 { ui::paint(tone, &steer) } else { String::new() }
    );
    codeentry::write_frame(&frame);
}

fn ask_line(s: &Setting, current: &str) -> Result<Edited> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    let prompt = format!("{}: ", s.key);
    let mut text = current.to_string();
    let guard = codeentry::RawGuard::enable_inline()?;
    let outcome = loop {
        let (tone, steer) = judge_line(s, &text, current);
        render_line(&prompt, &text, tone, &steer);
        let Event::Key(k) = event::read()? else { continue };
        if k.kind == KeyEventKind::Release {
            continue;
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Char('c') if ctrl => break Edited::Interrupted,
            KeyCode::Char('\u{3}') => break Edited::Interrupted,
            KeyCode::Char('u') if ctrl => text.clear(),
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Esc => break Edited::Back,
            KeyCode::Enter => match settings::validate(s, &text) {
                Ok(v) if v == current => break Edited::Unchanged,
                Ok(_) => break Edited::Value(text.trim().to_string(), false),
                Err(_) => {}
            },
            KeyCode::Char(c) if !c.is_control() && !ctrl && text.len() + c.len_utf8() <= 4096 => text.push(c),
            _ => {}
        }
    };
    codeentry::write_frame("\r\x1b[2K");
    drop(guard);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tty() -> Terminal {
        Terminal { interactive: true, stdout: true, live: true }
    }

    #[test]
    fn the_menu_opens_only_with_a_terminal_on_every_end() {
        assert!(opens_menu(true, false, tty()));
        // The scripted contract: any of these keeps the readout.
        assert!(!opens_menu(true, true, tty()), "--json never opens the menu");
        assert!(!opens_menu(false, false, tty()), "--peer reads, it does not open the menu");
        assert!(!opens_menu(true, false, Terminal { interactive: false, ..tty() }), "piped stdin or an opt-out");
        assert!(!opens_menu(true, false, Terminal { stdout: false, ..tty() }), "a captured stdout gets the TSV");
        assert!(!opens_menu(true, false, Terminal { live: false, ..tty() }), "TERM=dumb or redirected stderr");
    }

    #[test]
    fn every_setting_is_in_exactly_one_group() {
        for s in settings::registry() {
            let n = GROUPS.iter().filter(|(_, keys)| keys.contains(&s.key)).count();
            assert_eq!(n, 1, "{} is in {n} groups", s.key);
        }
        for (g, keys) in GROUPS {
            for k in *keys {
                assert!(settings::find(k).is_some_and(|s| s.key == *k), "{g} lists {k}, which is not a canonical key");
            }
            // One digit per row on the picker.
            assert!(keys.len() <= 9, "{g} has {} rows", keys.len());
        }
    }

    #[test]
    fn controls_follow_the_kind() {
        let toggle = settings::find("auto-extract").unwrap();
        assert_eq!(actions(toggle, "off", &Origin::Default, None, false), vec![Action::Value("on".into())]);
        assert_eq!(action_label(&Action::Value("on".into()), toggle, "off", None, "off"), "Turn on");
        let relay = settings::find("relay").unwrap();
        let acts = actions(relay, "never", &Origin::Global, None, true);
        assert_eq!(
            acts,
            vec![
                Action::Value("auto".into()),
                Action::Value("always".into()),
                Action::Value("never".into()),
                Action::Reset,
                Action::Devices
            ]
        );
        assert_eq!(initial_action(&acts, "never"), 2, "the current value starts selected");
        assert_eq!(action_label(&acts[2], relay, "never", None, "auto"), "never \u{b7} now");
        assert_eq!(action_label(&Action::Reset, relay, "never", None, "auto"), "Reset to default \u{b7} auto");
        let verbosity = settings::find("verbosity").unwrap();
        assert_eq!(actions(verbosity, "info", &Origin::Default, None, false).len(), 4, "verbosity is a choice, not text");
        let name = settings::find("name").unwrap();
        assert_eq!(actions(name, "me@box", &Origin::Default, None, true), vec![Action::Edit]);
    }

    #[test]
    fn reset_and_devices_appear_only_where_they_apply() {
        let relay = settings::find("relay").unwrap();
        assert!(!actions(relay, "auto", &Origin::Default, None, true).contains(&Action::Reset), "nothing stored, nothing to reset");
        assert!(!actions(relay, "auto", &Origin::Default, None, false).contains(&Action::Devices), "no devices to choose");
        let on_device = actions(relay, "never", &Origin::Peer("dovm".into()), Some("dovm"), true);
        assert!(on_device.contains(&Action::Reset));
        assert!(!on_device.contains(&Action::Devices), "a device's screen does not nest devices");
        assert!(!actions(relay, "auto", &Origin::Global, Some("dovm"), true).contains(&Action::Reset), "inherited, not its own");
        assert_eq!(
            action_label(&Action::Reset, relay, "never", Some("dovm"), "auto"),
            "Use the value for all devices \u{b7} auto"
        );
        let global_only = settings::find("wireguard").unwrap();
        assert!(!actions(global_only, "off", &Origin::Default, None, true).contains(&Action::Devices));
        let env = settings::find("server").unwrap();
        assert!(!actions(env, "https://x", &Origin::Env("TUNLION_SERVER"), None, true).contains(&Action::Reset));
    }

    #[test]
    fn rows_show_value_provenance_and_device_overrides() {
        assert_eq!(setting_row(6, "relay", "auto", &Origin::Default, 0), "relay   auto \u{b7} default");
        assert_eq!(setting_row(6, "relay", "never", &Origin::Global, 2), "relay   never \u{b7} config \u{b7} 2 devices");
        assert_eq!(setting_row(5, "only", "", &Origin::Default, 1), "only   (none) \u{b7} default \u{b7} 1 device");
        assert_eq!(group_row(11, "Shell", 0), "Shell        defaults");
        assert_eq!(group_row(11, "Shell", 2), "Shell        2 changed");
        for text in [
            setting_row(6, "relay", "auto", &Origin::Env("X"), 3),
            group_row(4, "Network", 1),
            Checklist::new(&[], vec![("a".into(), String::new()), ("b".into(), String::new())], true, false).hints(),
        ] {
            assert!(!text.contains('\u{2014}'), "no em dashes: {text}");
        }
    }

    fn ifaces() -> Vec<(String, String)> {
        vec![("eth0".into(), "10.0.0.2".into()), ("wl1".into(), "192.168.1.4 \u{b7} wifi".into())]
    }

    #[test]
    fn a_checklist_keeps_saved_entries_and_writes_nothing_untouched() {
        let saved = vec!["10.9.0.0/16".to_string(), "wl1".to_string()];
        let c = Checklist::new(&saved, ifaces(), false, false);
        assert_eq!(c.row(0), "[x] 10.9.0.0/16", "a saved CIDR is not dropped for not being an interface");
        assert_eq!(c.row(1), "[x] wl1  192.168.1.4 \u{b7} wifi");
        assert_eq!(c.row(2), "[ ] eth0  10.0.0.2");
        assert_eq!(c.outcome(), Edited::Unchanged, "opening and saving is not a change");
        let mut c2 = c.clone();
        c2.cursor = 2;
        c2.toggle();
        assert_eq!(c2.outcome(), Edited::Value("10.9.0.0/16,wl1,eth0".into(), false));
    }

    #[test]
    fn clearing_a_checklist_is_a_change_not_a_cancel() {
        let mut c = Checklist::new(&["wl1".to_string()], ifaces(), false, false);
        c.toggle();
        assert_eq!(c.outcome(), Edited::Value(String::new(), false));
        assert!(c.hints().contains("\u{23ce} clear"), "{}", c.hints());
    }

    #[test]
    fn an_order_is_the_pick_order_and_strength_shows_only_for_one() {
        let mut c = Checklist::new(&[], ifaces(), true, false);
        assert!(!c.hints().contains(" h "), "no strength for an empty order: {}", c.hints());
        c.cursor = 1;
        c.toggle();
        c.cursor = 0;
        c.toggle();
        assert_eq!(c.row(1), "[1] wl1  192.168.1.4 \u{b7} wifi");
        assert_eq!(c.row(0), "[2] eth0  10.0.0.2");
        assert!(c.hints().contains("h soft"), "{}", c.hints());
        c.toggle_strength();
        assert_eq!(c.outcome(), Edited::Value("wl1,eth0".into(), true));
        let unordered = Checklist::new(&[], ifaces(), false, false);
        assert!(!unordered.hints().contains(" h "), "strength is prefer's alone");
    }

    #[test]
    fn reopening_a_saved_order_keeps_it_and_its_strength() {
        let saved = vec!["wl1".to_string(), "eth0".to_string()];
        let c = Checklist::new(&saved, ifaces(), true, true);
        assert_eq!(c.value(), "wl1,eth0");
        assert_eq!(c.outcome(), Edited::Unchanged);
        let mut softer = c.clone();
        softer.toggle_strength();
        assert_eq!(softer.outcome(), Edited::Value("wl1,eth0".into(), false));
    }

    #[test]
    fn a_line_is_judged_by_the_same_validation_as_set() {
        let warm = settings::find("warm-max").unwrap();
        assert_eq!(judge_line(warm, "abc", "12").0, Tone::Warn);
        assert_eq!(judge_line(warm, "0", "12").0, Tone::Warn);
        assert_eq!(judge_line(warm, "12", "12").0, Tone::Dim, "unchanged reads as keep");
        assert_eq!(judge_line(warm, "8", "12").0, Tone::Ok);
        let server = settings::find("server").unwrap();
        assert!(judge_line(server, "ftp://x", "").1.contains("http(s)"));
        let routes = settings::find("advertise-routes").unwrap();
        assert_eq!(judge_line(routes, "192.168.1.0/24,10.0.0.0/8", "").0, Tone::Ok);
        assert_eq!(judge_line(routes, "192.168.1.0", "").0, Tone::Warn);
        assert_eq!(judge_line(routes, "", "10.0.0.0/8").0, Tone::Ok, "empty withdraws the routes");
        let addr = settings::find("tun-addr").unwrap();
        for ok in ["auto", "", "10.9.0.1/24", "fd00::1/64"] {
            assert_eq!(judge_line(addr, ok, "x").0, Tone::Ok, "{ok}");
        }
        assert_eq!(judge_line(addr, "10.9.0.1", "auto").0, Tone::Warn);
        let ttl = settings::find("ssh.cert_ttl").unwrap();
        assert_eq!(judge_line(ttl, "30m", "1h").0, Tone::Ok);
        assert_eq!(judge_line(ttl, "soon", "1h").0, Tone::Warn);
    }

    #[test]
    fn help_wraps_to_the_width() {
        let lines = wrap("one two three four five six seven eight nine ten", 20);
        assert!(lines.iter().all(|l| l.chars().count() <= 20), "{lines:?}");
        assert_eq!(lines.join(" "), "one two three four five six seven eight nine ten");
    }
}
