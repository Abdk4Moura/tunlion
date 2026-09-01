//! Interactivity contract: one Affordance, three renderers.

use std::io::Write;
use std::net::IpAddr;
use std::process::Command;

use crate::ui;

// ------------------------------------------------------ interface enumeration

pub struct InterfaceInfo {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub group: String,
}

fn classify_interface(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("wl") || lower.starts_with("wlan") { "wifi" }
    else if lower.starts_with("eth") || lower.starts_with("en") || lower.starts_with("ens") { "ethernet" }
    else if lower.contains("tailscale") || lower == "ts0" { "tailscale" }
    else if lower.contains("docker") || lower.starts_with("br-") { "docker" }
    else if lower == "lo" { "loopback" }
    else { "other" }
}

pub fn enumerate_interfaces() -> Vec<InterfaceInfo> {
    let mut out: Vec<InterfaceInfo> = Vec::new();
    if let Ok(raw) = Command::new("ip").args(["-o", "-4", "addr", "show"]).output() {
        let text = String::from_utf8_lossy(&raw.stdout);
        let mut seen: std::collections::HashMap<String, Vec<IpAddr>> = std::collections::HashMap::new();
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let name = parts.iter().skip(1).find(|s| !s.is_empty()).cloned().unwrap_or("");
            if name.is_empty() || name.contains(':') { continue; }
            if let Some(ip_pos) = parts.iter().position(|p| *p == "inet") {
                if let Some(ip_str) = parts.get(ip_pos + 1) {
                    if let Ok(ip) = ip_str.split('/').next().unwrap_or("").parse::<IpAddr>() {
                        seen.entry(name.to_string()).or_default().push(ip);
                    }
                }
            }
        }
        for (name, ips) in seen {
            let group = classify_interface(&name).to_string();
            out.push(InterfaceInfo { name, ips, group });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

// ----------------------------------------------------------- affordance --

pub struct Affordance {
    pub command: String,
    pub needs: String,
    pub example: String,
    pub options: Option<Vec<OptionEntry>>,
    pub options_label: String, // "interfaces" | "peers"
}

pub struct OptionEntry {
    pub label: String,
    pub detail: String,
    pub group: String,
    pub checked: bool,
}

// --------------------------------------------------------------- renderers --

pub fn render_steer(aff: &Affordance) -> ! {
    eprintln!("error: `{}` needs a value: {}", aff.command, aff.needs);
    if let Some(ref opts) = aff.options {
        if !opts.is_empty() {
            let names: Vec<&str> = opts.iter().map(|o| o.label.as_str()).collect();
            eprintln!("{} on this machine: {}", aff.options_label, names.join(", "));
            let mut groups: Vec<&str> = Vec::new();
            for o in opts { if !groups.contains(&o.group.as_str()) { groups.push(&o.group); } }
            groups.sort();
            eprintln!("groups: {}", groups.join(", "));
        }
    }
    eprintln!("example: {}", aff.example);
    std::process::exit(2);
}

pub fn render_json_steer(aff: &Affordance) -> ! {
    let mut obj = serde_json::json!({
        "error": "missing_value", "command": aff.command, "needs": aff.needs, "example": aff.example,
    });
    if let Some(ref opts) = aff.options {
        let interfaces: Vec<String> = opts.iter().map(|o| o.label.clone()).collect();
        let mut groups: Vec<String> = opts.iter().map(|o| o.group.clone()).collect();
        groups.sort(); groups.dedup();
        obj["valid"] = serde_json::json!({"interfaces": interfaces, "groups": groups});
    }
    eprintln!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    std::process::exit(2);
}

// ---------------------------------------------------- shared raw-mode guard --

struct RawGuard { active: bool }

impl RawGuard {
    fn enable() -> std::io::Result<RawGuard> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(RawGuard { active: true })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = crossterm::terminal::disable_raw_mode();
            let mut err = std::io::stderr();
            let _ = crossterm::execute!(err, crossterm::cursor::Show);
            let _ = write!(err, "\r\n");
            let _ = err.flush();
        }
    }
}

// -------------------------------------------------------- checklist widget --

pub fn interactive_checklist(title: &str, subtitle: &str, opts: &[OptionEntry]) -> Option<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    if opts.is_empty() { return None; }

    let _guard = RawGuard::enable().ok()?;
    let mut selected: Vec<bool> = opts.iter().map(|o| o.checked).collect();
    let mut cursor: usize = 0;
    let n = opts.len();
    let vis_lines = n + 2; // title + n items + help (subtitle not counted)

    paint_checklist(title, subtitle, opts, &selected, cursor, false, vis_lines);

    loop {
        let Ok(ev) = event::read() else { continue };
        let Event::Key(key) = ev else { continue };
        if key.kind == KeyEventKind::Release { continue; }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return None,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return None,
            KeyCode::Enter => {
                let chosen: Vec<String> = opts.iter().enumerate().filter(|(i,_)| selected[*i]).map(|(_,o)| o.label.clone()).collect();
                let mut err = std::io::stderr();
                if chosen.is_empty() { let _ = writeln!(err, "  {} (nothing selected)", title); }
                else { let _ = writeln!(err, "  {} {}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), chosen.join(", ")); }
                return Some(chosen.join(","));
            }
            KeyCode::Up | KeyCode::Char('k') => { cursor = if cursor == 0 { n-1 } else { cursor-1 }; }
            KeyCode::Down | KeyCode::Char('j') => { cursor = (cursor+1) % n; }
            KeyCode::Char(' ') => { selected[cursor] = !selected[cursor]; }
            _ => {}
        }
        paint_checklist(title, subtitle, opts, &selected, cursor, true, vis_lines);
    }
}

fn paint_checklist(title: &str, _subtitle: &str, opts: &[OptionEntry], selected: &[bool], cursor: usize, redraw: bool, vis_lines: usize) {
    let mut err = std::io::stderr();
    let color = ui::caps().color;

    if redraw { let _ = write!(err, "\x1b[{}A", vis_lines); }

    let _ = writeln!(err, "\r\x1b[2K  {}", if color { format!("\x1b[1m{title}\x1b[0m") } else { title.to_string() });

    for (i, opt) in opts.iter().enumerate() {
        let detail = if opt.detail.is_empty() { String::new() } else { format!("  {}", opt.detail) };
        let group_str = if opt.group.is_empty() || opt.group == "other" { String::new() } else { format!("  ({})", opt.group) };

        let (mark, cy, r) = if i == cursor {
            ("\u{276f}", if color { "\x1b[36m" } else { "" }, if color { "\x1b[0m" } else { "" })
        } else {
            (" ", "", "")
        };
        let check = if selected[i] { "[x]" } else { "[ ]" };
        let line = format!("{cy}{mark} {check} {:<20}{detail}{group_str}{r}", opt.label);
        let _ = writeln!(err, "\r\x1b[2K  {line}");
    }

    let _ = writeln!(err, "\r\x1b[2K{}", ui::paint_when(color, ui::Tone::Dim, "  Space=toggle  Enter=save  Esc=cancel"));
    let _ = err.flush();
}

// -------------------------------------------------------- reorder widget --

#[derive(Clone, Copy, PartialEq)]
pub enum Strength { Soft, Hard }

pub fn interactive_reorder(title: &str, _subtitle: &str, opts: &[OptionEntry], initial_strength: Strength) -> Option<(String, Strength)> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    if opts.is_empty() { return None; }

    let _guard = RawGuard::enable().ok()?;
    let mut order: Vec<usize> = (0..opts.len()).collect();
    let mut cursor: usize = 0;
    let mut strength = initial_strength;
    let n = order.len();
    let vis_lines = n + 2; // title + n items + help

    paint_reorder(title, opts, &order, cursor, strength, false, vis_lines);

    loop {
        let Ok(ev) = event::read() else { continue };
        let Event::Key(key) = ev else { continue };
        if key.kind == KeyEventKind::Release { continue; }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return None,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return None,
            KeyCode::Enter => {
                let ordered: Vec<String> = order.iter().map(|&i| opts[i].label.clone()).collect();
                let mut err = std::io::stderr();
                let s = if strength == Strength::Hard { " (hard)" } else { "" };
                let _ = writeln!(err, "  {} {}{}", ui::paint(ui::Tone::Ok, ui::glyph_ok()), ordered.join(", "), s);
                return Some((ordered.join(","), strength));
            }
            KeyCode::Char('h') => { strength = if strength == Strength::Soft { Strength::Hard } else { Strength::Soft }; }
            KeyCode::Char('j') | KeyCode::Down => {
                if cursor + 1 < n { order.swap(cursor, cursor + 1); cursor += 1; }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if cursor > 0 { order.swap(cursor, cursor - 1); cursor -= 1; }
            }
            _ => {}
        }
        paint_reorder(title, opts, &order, cursor, strength, true, vis_lines);
    }
}

fn paint_reorder(title: &str, opts: &[OptionEntry], order: &[usize], cursor: usize, strength: Strength, redraw: bool, vis_lines: usize) {
    let mut err = std::io::stderr();
    let color = ui::caps().color;

    if redraw { let _ = write!(err, "\x1b[{}A", vis_lines); }

    let _ = writeln!(err, "\r\x1b[2K  {}", if color { format!("\x1b[1m{title}\x1b[0m") } else { title.to_string() });

    for (pos, &idx) in order.iter().enumerate() {
        let opt = &opts[idx];
        let detail = if opt.detail.is_empty() { String::new() } else { format!("  {}", opt.detail) };
        let group_str = if opt.group.is_empty() || opt.group == "other" { String::new() } else { format!("  ({})", opt.group) };

        let (mark, cy, r) = if pos == cursor {
            ("\u{276f}", if color { "\x1b[36m" } else { "" }, if color { "\x1b[0m" } else { "" })
        } else {
            (" ", "", "")
        };

        let line = format!("{cy}{mark} {:<20}{detail}{group_str}{r}", opt.label);
        let _ = writeln!(err, "\r\x1b[2K  {line}");
    }

    let strength_label = match strength {
        Strength::Soft => "soft (prefer unless much faster)",
        Strength::Hard => "hard (always prefer, even if slower)",
    };
    let help = format!("  j/k=move  h=strength [{}]  Enter=save  Esc=cancel", strength_label);
    let _ = writeln!(err, "\r\x1b[2K{}", ui::paint_when(color, ui::Tone::Dim, &help));
    let _ = err.flush();
}
