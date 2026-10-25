//! Temporary-access terminal adapter. Drafting is local and side-effect free:
//! it never creates keys, contacts, grants, listeners, or sample invitations.
//!
//! Presentation follows the pairing prototype (/root/pairing-ux): one compact
//! screen that shows what is chosen, plain words, and pickers that collapse once
//! answered. Policy, validation and activation stay in the shared engine; nothing
//! here decides what is allowed, it only describes it.
use anyhow::{Result, bail};
use crate::codeentry::{Collapse, PickOpts, Picked};
use crate::ui;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use filament_peerloop::access::{AccessSpec, AgreementEngine, AgreementSnapshot, AgreementState, FolderAccess, FolderMode, Lifetime, ServiceAccess, ServiceProtocol};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

#[derive(Default, Debug, PartialEq, Eq)]
struct Draft {
    spec: AccessSpec,
    next_id: u64,
}

impl Draft {
    fn add_folder(&mut self, input: &str) -> Result<()> {
        if input.trim().is_empty() {
            bail!("enter a folder path");
        }
        let path = std::fs::canonicalize(expand_home(input.trim()))
            .map_err(|_| anyhow::anyhow!("that folder does not exist or cannot be opened"))?;
        if !path.is_dir() {
            bail!("that is a file; choose a folder");
        }
        if self.spec.folders.iter().any(|folder| folder.path == path) {
            bail!("that folder is already shared");
        }
        let mut spec = self.spec.clone();
        spec.folders.push(FolderAccess::canonical(format!("folder-{}", self.next_id), path, FolderMode::ReadOnly)?);
        spec.validate()?;
        self.spec = spec;
        self.next_id += 1;
        Ok(())
    }

    fn add_service(&mut self, input: &str) -> Result<()> {
        let address = parse_service(input)?;
        if self.spec.services.iter().any(|service| service.target == address) {
            bail!("that port is already shared");
        }
        let mut spec = self.spec.clone();
        spec.services.push(ServiceAccess { id: format!("service-{}", self.next_id), target: address, protocol: ServiceProtocol::Tcp });
        spec.validate()?;
        self.spec = spec;
        self.next_id += 1;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.spec.folders.is_empty() && self.spec.services.is_empty() && !self.spec.shell
    }

    fn review(&self) -> Result<Vec<String>> {
        self.review_with_lifetime(Lifetime::UntilEnded)
    }

    fn review_with_lifetime(&self, lifetime: Lifetime) -> Result<Vec<String>> {
        self.review_at(lifetime, crate::identity::now_secs())
    }

    /// What the HOST is about to share, in the words the prototype uses. Pure.
    fn review_at(&self, lifetime: Lifetime, now: u64) -> Result<Vec<String>> {
        self.spec.validate()?;
        if self.is_empty() {
            bail!("choose at least one folder, service, or shell");
        }
        let mut lines = vec![format!("Sharing {}", lifetime_label_at(lifetime, now))];
        lines.extend(self.spec.folders.iter().map(|folder| format!(
            "  \u{2713} Folder {} \u{b7} {}", short_path(&folder.path), mode_label(&folder.mode)
        )));
        lines.extend(self.spec.services.iter().map(|service| format!("  \u{2713} Service {}", service_label(&service.target))));
        if self.spec.shell {
            lines.push("  \u{2713} Shell on this device, as your account".into());
        }
        lines.push("Stops when you close this window. Nothing is remembered afterwards.".into());
        Ok(lines)
    }
}

fn mode_label(mode: &FolderMode) -> &'static str {
    if *mode == FolderMode::ReadWrite { "read & write" } else { "read-only" }
}

/// `3000` for the common loopback case, the full address otherwise. Pure.
pub(crate) fn service_label(target: &SocketAddr) -> String {
    if target.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) { format!("port {}", target.port()) } else { target.to_string() }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(std::path::PathBuf::from)
}

/// `~/x` -> `$HOME/x`, so a typed path works the way the shell would take it.
fn expand_home(input: &str) -> std::path::PathBuf {
    match (input.strip_prefix("~/").or_else(|| input.strip_prefix("~\\")).or(if input == "~" { Some("") } else { None }), home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => std::path::PathBuf::from(input),
    }
}

/// `$HOME/x` -> `~/x` for display only, and never a control character.
fn short_path(path: &std::path::Path) -> String {
    let shown = match home_dir() {
        Some(home) if path.starts_with(&home) && path != home => {
            format!("~{}{}", std::path::MAIN_SEPARATOR, path.strip_prefix(&home).map(|p| p.display().to_string()).unwrap_or_default())
        }
        _ => path.display().to_string(),
    };
    terminal_label(&shown)
}

/// `45 min`, `2 h`, `1 h 20 min`, `30 s`. Pure.
fn human_duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs.div_ceil(60)),
        _ => {
            let h = secs / 3600;
            let m = (secs % 3600) / 60;
            if m == 0 { format!("{h} h") } else { format!("{h} h {m} min") }
        }
    }
}

/// How long access lasts, relative to `now`, never a raw timestamp. Pure.
pub(crate) fn lifetime_label_at(lifetime: Lifetime, now: u64) -> String {
    match lifetime {
        Lifetime::UntilEnded => "until you end it".into(),
        Lifetime::ExpiresAt(at) if at <= now => "ending now (time limit reached)".into(),
        Lifetime::ExpiresAt(at) => format!("for {} more", human_duration(at - now)),
    }
}

pub(crate) fn lifetime_label(lifetime: Lifetime) -> String {
    lifetime_label_at(lifetime, crate::identity::now_secs())
}

/// The same, from the RECIPIENT's side: the host is the one who ends it. Pure.
pub(crate) fn lifetime_label_recipient_at(lifetime: Lifetime, now: u64) -> String {
    match lifetime {
        Lifetime::UntilEnded => "until they end it".into(),
        other => lifetime_label_at(other, now),
    }
}

pub(crate) fn lifetime_label_recipient(lifetime: Lifetime) -> String {
    lifetime_label_recipient_at(lifetime, crate::identity::now_secs())
}

/// What the JOINING side sees before accepting, in the prototype's "you can"
/// form. Pure, so tests pin the wording.
///
/// `snapshot.name` here is the name the HOST assigned to THIS device (labels are
/// allocated by the side that offers), so it is shown as "you'll appear as",
/// never as the host's name.
fn offer_lines(snapshot: &AgreementSnapshot, now: u64) -> Vec<String> {
    let host = "their device";
    let mut lines = vec![
        format!("You're being offered access {}", lifetime_label_recipient_at(snapshot.lifetime, now)),
        format!("You'll appear there as {}", terminal_label(&snapshot.name)),
        String::new(),
        "You can".into(),
    ];
    for folder in &snapshot.spec.folders {
        let name = folder.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| folder.path.display().to_string());
        let verb = if folder.mode == FolderMode::ReadWrite { "Browse, download and change files in" } else { "Browse and download files from" };
        lines.push(format!("  \u{2713} {verb} {}", terminal_label(&name)));
    }
    for service in &snapshot.spec.services {
        lines.push(format!("  \u{2713} Reach {} on {host}", service_label(&service.target)));
    }
    if snapshot.spec.shell {
        lines.push(format!("  \u{2713} Open a shell on {host}, as its owner's account"));
    }
    lines
}

/// Only a caller holding the shared engine's authenticated review may call this.
pub(crate) fn review_offer(snapshot: &AgreementSnapshot, stop: &AtomicBool) -> Result<()> {
    // Refuse BEFORE describing anything this build could not actually deliver.
    if snapshot.spec.shell {
        #[cfg(not(all(unix, feature = "pty-server")))]
        bail!("this build cannot open the offered shell, so the offer was not accepted");
    }
    if snapshot.spec.device_network {
        bail!("this build cannot activate the offered device networking, so the offer was not accepted");
    }
    ui::say("");
    for line in offer_lines(snapshot, crate::identity::now_secs()) {
        ui::say(&format!("  {line}"));
    }
    ui::say(&ui::paint(ui::Tone::Dim, "  Verified with the code. Nothing stays on this device after it ends."));
    let choice = crate::codeentry::pick_opts(
        "",
        &["Accept".into(), "Decline".into()],
        PickOpts { stop: Some(stop), ..PickOpts::default() },
    )?;
    match choice {
        Picked::Item(0) if !stop.load(Ordering::Acquire) => Ok(()),
        _ => Err(crate::cancelled()),
    }
}

/// Host controls run on a cancellable terminal thread while the existing peer
/// loop continues routing network frames. No blocking discovery or subprocesses.
pub(crate) fn spawn_host_controls(
    engine: Arc<AgreementEngine>,
    id: String,
    stop: Arc<AtomicBool>,
    updates: tokio::sync::mpsc::Sender<AgreementSnapshot>,
) {
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            // Print the status line only when it changes, so the screen stays
            // one line of state plus the menu instead of growing every loop.
            let mut shown: Option<(u64, Lifetime)> = None;
            while !stop.load(Ordering::Acquire) {
                let snapshot = engine.snapshot(&id, crate::identity::now_secs())?;
                if matches!(snapshot.state, AgreementState::Ended | AgreementState::Expired | AgreementState::Declined) { return Ok(()); }
                if shown != Some((snapshot.revision, snapshot.lifetime)) {
                    ui::say(&format!("  Sharing with {} \u{b7} {}", terminal_label(&snapshot.name), lifetime_label(snapshot.lifetime)));
                    shown = Some((snapshot.revision, snapshot.lifetime));
                }
                let choice = live_menu("", &["Change what's shared".into(), "Set a time limit".into(), "End sharing now".into()], &stop)?;
                let Some(choice) = choice else {
                    if !stop.load(Ordering::Acquire) {
                        let _ = updates.blocking_send(engine.end(&id, crate::identity::now_secs())?);
                    }
                    return Ok(());
                };
                let updated = match choice {
                    0 => {
                        let Some(spec) = edit_live(&snapshot.spec, &stop)? else { continue; };
                        engine.revise(&id, snapshot.revision, spec, snapshot.lifetime, crate::identity::now_secs())?
                    }
                    1 => {
                        let Some(lifetime) = choose_lifetime(&stop)? else { continue; };
                        engine.revise(&id, snapshot.revision, snapshot.spec, lifetime, crate::identity::now_secs())?
                    }
                    _ => engine.end(&id, crate::identity::now_secs())?,
                };
                let ended = updated.state == AgreementState::Ended;
                if updates.blocking_send(updated).is_err() || ended { return Ok(()); }
            }
            Ok(())
        })();
        if let Err(error) = result {
            ui::critical(&format!("  Sharing controls failed: {error}"));
            if let Ok(snapshot) = engine.end(&id, crate::identity::now_secs()) { let _ = updates.blocking_send(snapshot); }
        }
    });
}

/// Presets first; typing a duration is the exception, not the only way.
fn choose_lifetime(stop: &AtomicBool) -> Result<Option<Lifetime>> {
    let presets: [(&str, u64); 3] = [("30 minutes", 30 * 60), ("1 hour", 3600), ("2 hours", 2 * 3600)];
    let mut labels = vec!["Until I end it".to_string()];
    labels.extend(presets.iter().map(|(label, _)| (*label).to_string()));
    labels.push("Other\u{2026}".into());
    let Some(choice) = live_menu("TIME LIMIT", &labels, stop)? else { return Ok(None) };
    let now = crate::identity::now_secs();
    Ok(match choice {
        0 => Some(Lifetime::UntilEnded),
        i if i <= presets.len() => Some(Lifetime::ExpiresAt(now.saturating_add(presets[i - 1].1))),
        _ => {
            let Some(raw) = ask_line("time limit, e.g. 45m or 3h: ", stop)? else { return Ok(None) };
            match crate::file_io::parse_mint_ttl(raw.trim()) {
                Ok(ttl) if ttl > 0 => Some(Lifetime::ExpiresAt(now.saturating_add(ttl))),
                _ => { ui::say("  Not a time limit I understand. Nothing changed."); None }
            }
        }
    })
}

/// A choice in the shared picker style that a session ending can tear down.
/// One-shot: leaves `✓ <answer>` behind.
pub(crate) fn live_pick(title: &str, labels: &[String], stop: &AtomicBool) -> Result<Option<usize>> {
    live_pick_opts(title, labels, stop, Collapse::Summary)
}

/// Same, for menus a flow comes back to: erases itself completely.
fn live_menu(title: &str, labels: &[String], stop: &AtomicBool) -> Result<Option<usize>> {
    live_pick_opts(title, labels, stop, Collapse::Erase)
}

fn live_pick_opts(title: &str, labels: &[String], stop: &AtomicBool, collapse: Collapse) -> Result<Option<usize>> {
    let labels: Vec<String> = labels.iter().map(|label| terminal_label(label)).collect();
    match crate::codeentry::pick_opts(title, &labels, PickOpts { stop: Some(stop), collapse: Some(collapse), ..PickOpts::default() })? {
        Picked::Item(i) if !stop.load(Ordering::Acquire) => Ok(Some(i)),
        _ => Ok(None),
    }
}

/// A one-line answer that keeps what was typed on screen (folder browsing
/// prompts, where the echo is part of the record).
pub(crate) fn live_line(prompt: &str, stop: &AtomicBool) -> Result<Option<String>> {
    read_line(prompt, stop, true)
}

/// A one-line answer that clears itself: the screen it feeds shows the result.
fn ask_line(prompt: &str, stop: &AtomicBool) -> Result<Option<String>> {
    read_line(prompt, stop, false)
}

fn read_line(prompt: &str, stop: &AtomicBool, keep: bool) -> Result<Option<String>> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalGuard { keep };
    let mut input = String::new();
    loop {
        if stop.load(Ordering::Acquire) { return Ok(None); }
        eprint!("\r\x1b[2K  {prompt}{}", terminal_label(&input));
        std::io::stderr().flush()?;
        if !event::poll(std::time::Duration::from_millis(100))? { continue; }
        let Event::Key(key) = event::read()? else { continue; };
        if key.kind == KeyEventKind::Release { continue; }
        match key.code {
            KeyCode::Enter => return Ok(Some(input)),
            KeyCode::Esc => return Ok(None),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
            KeyCode::Backspace => { input.pop(); }
            KeyCode::Char(c) if !c.is_control() && input.len() + c.len_utf8() <= 4096 => input.push(c),
            _ => {}
        }
    }
}

fn edit_live(spec: &AccessSpec, stop: &AtomicBool) -> Result<Option<AccessSpec>> {
    let next_id = spec.folders.iter().map(|folder| &folder.id).chain(spec.services.iter().map(|service| &service.id))
        .filter_map(|id| id.rsplit_once('-')?.1.parse::<u64>().ok()).max().unwrap_or(0).saturating_add(1);
    let mut draft = Draft { spec: spec.clone(), next_id };
    // The recipient reviews and accepts the new revision, so this screen is the
    // host's only review: no second "apply?" confirmation.
    if compose(&mut draft, "CHANGE WHAT'S SHARED", "Apply changes", stop)? && draft.spec != *spec {
        return Ok(Some(draft.spec));
    }
    Ok(None)
}

fn parse_service(input: &str) -> Result<SocketAddr> {
    let input = input.trim();
    let address = if let Ok(port) = input.parse::<u16>() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    } else {
        input.parse::<SocketAddr>()
            .map_err(|_| anyhow::anyhow!("enter a port like 3000, or an address like 127.0.0.1:3000"))?
    };
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        bail!("choose a nonzero port on one specific address");
    }
    Ok(address)
}

struct TerminalGuard {
    keep: bool,
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut err = std::io::stderr();
        let _ = if self.keep { writeln!(err, "\r") } else { write!(err, "\r\x1b[2K") };
        let _ = err.flush();
    }
}

pub(crate) fn terminal_label(label: &str) -> String {
    label.chars().map(|c| if c.is_control() { '�' } else { c }).collect()
}

/// The composer rows, shown as they are now. Pure, so tests pin the wording.
fn composer_rows(draft: &Draft, finish: &str) -> Vec<String> {
    let folders = match draft.spec.folders.as_slice() {
        [] => "none".to_string(),
        [one] => format!("{} ({})", short_path(&one.path), mode_label(&one.mode)),
        [first, rest @ ..] => format!("{} ({}) +{}", short_path(&first.path), mode_label(&first.mode), rest.len()),
    };
    let services = if draft.spec.services.is_empty() {
        "none".to_string()
    } else {
        draft.spec.services.iter().map(|service| service_label(&service.target)).collect::<Vec<_>>().join(", ")
    };
    vec![
        format!("Folders  \u{b7} {folders}"),
        format!("Services \u{b7} {services}"),
        format!("Shell    \u{b7} {}", if draft.spec.shell { "on" } else { "off" }),
        finish.to_string(),
    ]
}

/// One screen: what is shared so far, each row opens its editor in place, and
/// the finish row is preselected as soon as something is chosen. Returns true
/// when finished, false when the person backed out.
fn compose(draft: &mut Draft, title: &str, finish: &str, stop: &AtomicBool) -> Result<bool> {
    loop {
        let rows = composer_rows(draft, finish);
        let initial = if draft.is_empty() { 0 } else { 3 };
        let picked = crate::codeentry::pick_opts(
            title,
            &rows,
            PickOpts { stop: Some(stop), collapse: Some(Collapse::Erase), initial, ..PickOpts::default() },
        )?;
        let Picked::Item(row) = picked else { return Ok(false) };
        match row {
            0 => edit_folders(draft, stop)?,
            1 => edit_services(draft, stop)?,
            2 => draft.spec.shell = !draft.spec.shell,
            _ => {
                if draft.is_empty() {
                    ui::say("  Choose a folder, a service, or the shell first.");
                    continue;
                }
                return Ok(true);
            }
        }
    }
}

fn edit_folders(draft: &mut Draft, stop: &AtomicBool) -> Result<()> {
    if draft.spec.folders.is_empty() {
        return add_folder_prompt(draft, stop);
    }
    loop {
        let mut labels: Vec<String> = draft.spec.folders.iter()
            .map(|folder| format!("{} \u{b7} {}", short_path(&folder.path), mode_label(&folder.mode))).collect();
        labels.extend(["Add another folder".into(), "Done".into()]);
        let Some(selected) = live_menu("FOLDERS", &labels, stop)? else { return Ok(()) };
        let n = draft.spec.folders.len();
        if selected == n { add_folder_prompt(draft, stop)?; continue; }
        if selected > n { return Ok(()); }
        match live_menu(&short_path(&draft.spec.folders[selected].path), &["Read-only".into(), "Read & write".into(), "Stop sharing this folder".into()], stop)? {
            Some(0) => draft.spec.folders[selected].mode = FolderMode::ReadOnly,
            Some(1) => draft.spec.folders[selected].mode = FolderMode::ReadWrite,
            Some(_) => { draft.spec.folders.remove(selected); }
            None => {}
        }
        if draft.spec.folders.is_empty() { return Ok(()); }
    }
}

/// Enter alone shares the folder you are in: the commonest answer costs one key.
fn add_folder_prompt(draft: &mut Draft, stop: &AtomicBool) -> Result<()> {
    let here = std::env::current_dir().ok();
    let shown = here.as_deref().map(short_path).unwrap_or_default();
    let prompt = if shown.is_empty() { "folder to share: ".to_string() } else { format!("folder to share [{shown}]: ") };
    let Some(input) = ask_line(&prompt, stop)? else { return Ok(()) };
    let input = if input.trim().is_empty() {
        match &here { Some(dir) => dir.display().to_string(), None => return Ok(()) }
    } else { input };
    if let Err(error) = draft.add_folder(&input) { ui::say(&format!("  {error}")); }
    Ok(())
}

fn edit_services(draft: &mut Draft, stop: &AtomicBool) -> Result<()> {
    // No scan and no fake detected service names. Only explicit local input.
    if draft.spec.services.is_empty() {
        return add_service_prompt(draft, stop);
    }
    loop {
        let mut labels: Vec<String> = draft.spec.services.iter().map(|service| service_label(&service.target)).collect();
        labels.extend(["Add another port".into(), "Done".into()]);
        let Some(selected) = live_menu("SERVICES", &labels, stop)? else { return Ok(()) };
        let n = draft.spec.services.len();
        if selected == n { add_service_prompt(draft, stop)?; continue; }
        if selected > n { return Ok(()); }
        if live_menu(&labels[selected], &["Keep".into(), "Stop sharing this port".into()], stop)? == Some(1) {
            draft.spec.services.remove(selected);
        }
        if draft.spec.services.is_empty() { return Ok(()); }
    }
}

fn add_service_prompt(draft: &mut Draft, stop: &AtomicBool) -> Result<()> {
    let Some(input) = ask_line("port to share, e.g. 3000: ", stop)? else { return Ok(()) };
    if input.trim().is_empty() { return Ok(()); }
    if let Err(error) = draft.add_service(&input) { ui::say(&format!("  {error}")); }
    Ok(())
}

/// Safe adapter until authenticated agreement dispatch and endpoint activation
/// are available. Do not route a temporary offer through permanent `pair_cmd`.
pub(crate) fn temporary_access() -> Result<AccessSpec> {
    let mut draft = Draft::default();
    let never = AtomicBool::new(false);
    ui::say(&ui::paint(ui::Tone::Dim, "  Choose what to share. Nothing is shared until you create a code."));
    // Unsupported device networking, expiry and background controls are not offered.
    if !compose(&mut draft, "TEMPORARY ACCESS", "Create code", &never)? {
        return Err(crate::cancelled());
    }
    // The composer is the host's review; show what was chosen once, plainly.
    for line in draft.review()? { ui::say(&format!("  {}", terminal_label(&line))); }
    // Only the confirmed mutation crosses into the shared ceremony, and only
    // when this build has a scoped endpoint for what was chosen: the forward
    // server serves every resource kind; a pty-only Unix build serves a scope
    // that includes the shell.
    let servable = cfg!(feature = "forward-server")
        || (cfg!(all(unix, feature = "pty-server")) && draft.spec.shell);
    if servable {
        return Ok(draft.spec);
    }
    bail!("this build cannot share those resources, so no code was created and nothing was shared");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_input_requires_an_exact_endpoint() {
        assert_eq!(parse_service("3000").unwrap().to_string(), "127.0.0.1:3000");
        assert_eq!(parse_service("[::1]:443").unwrap().port(), 443);
        for invalid in ["", "0", "65536", "localhost:80", "0.0.0.0:80", "[::]:80", "224.0.0.1:80", "80,443"] {
            assert!(parse_service(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn mixed_resources_review_is_pure_and_read_only_by_default() {
        let mut draft = Draft::default();
        assert!(draft.review().is_err());
        assert!(draft.add_folder("").is_err());
        assert!(draft.add_folder("/definitely-missing-tunlion-folder").is_err());
        draft.add_folder(".").unwrap();
        assert_eq!(draft.spec.folders[0].mode, FolderMode::ReadOnly);
        assert!(draft.add_folder(".").is_err());
        draft.add_service("3000").unwrap();
        draft.add_service("8080").unwrap();
        assert!(draft.add_service("3000").is_err());
        let before = draft.review_at(Lifetime::UntilEnded, 0).unwrap();
        assert!(before.iter().any(|line| line.contains("read-only")));
        assert!(before.iter().any(|line| line.contains("until you end it")));
        assert!(before.iter().any(|line| line.contains("Service port 3000")));
        assert!(!before.iter().any(|line| line.contains(".mesh")));
        assert_eq!(before, draft.review_at(Lifetime::UntilEnded, 0).unwrap());
    }

    #[test]
    fn filesystem_labels_cannot_inject_terminal_controls() {
        assert_eq!(terminal_label("a\x1b[2J\nb"), "a�[2J�b");
    }

    #[test]
    fn resource_capacity_and_ids_come_from_shared_spec_validation() {
        let mut draft = Draft::default();
        for port in 1..=64 { draft.add_service(&port.to_string()).unwrap(); }
        assert!(draft.add_service("65").is_err());
        assert_eq!(draft.spec.services.len(), 64);
        let removed = draft.spec.services.remove(0).id;
        draft.add_service("65").unwrap();
        assert!(draft.spec.services.iter().all(|service| service.id != removed));
        assert!(draft.spec.validate().is_ok());
    }

    #[test]
    fn expiry_is_relative_and_never_a_raw_timestamp() {
        let mut draft = Draft::default();
        draft.add_service("3000").unwrap();
        let review = draft.review_at(Lifetime::ExpiresAt(1_000 + 7_200), 1_000).unwrap();
        assert_eq!(review[0], "Sharing for 2 h more");
        assert!(!review[0].contains("until you end it"));
        assert!(!review.iter().any(|line| line.contains("8200")));
        assert_eq!(lifetime_label_at(Lifetime::ExpiresAt(1_000 + 4_800), 1_000), "for 1 h 20 min more");
        assert_eq!(lifetime_label_at(Lifetime::ExpiresAt(1_000 + 90), 1_000), "for 2 min more");
        assert_eq!(lifetime_label_at(Lifetime::ExpiresAt(900), 1_000), "ending now (time limit reached)");
    }

    #[test]
    fn shell_is_a_first_class_basket_entry_and_review_states_its_boundary() {
        let mut draft = Draft::default();
        assert!(draft.review().is_err(), "an empty basket has nothing to share");
        draft.spec.shell = true;
        let review = draft.review().unwrap();
        assert!(review.iter().any(|line| line.contains("Shell on this device, as your account")));
        assert!(review.iter().any(|line| line.contains("Stops when you close this window")));
        draft.spec.shell = false;
        assert!(draft.review().is_err(), "shell removed leaves no resource");
    }

    #[test]
    fn composer_rows_show_what_is_chosen_in_place() {
        let mut draft = Draft::default();
        assert_eq!(composer_rows(&draft, "Create code"), vec![
            "Folders  \u{b7} none".to_string(),
            "Services \u{b7} none".to_string(),
            "Shell    \u{b7} off".to_string(),
            "Create code".to_string(),
        ]);
        draft.add_service("3000").unwrap();
        draft.add_service("127.0.0.2:22").unwrap();
        draft.spec.shell = true;
        let rows = composer_rows(&draft, "Create code");
        assert_eq!(rows[1], "Services \u{b7} port 3000, 127.0.0.2:22");
        assert_eq!(rows[2], "Shell    \u{b7} on");
    }

    #[test]
    fn offer_reads_as_what_you_can_do_without_engine_jargon() {
        let mut draft = Draft::default();
        draft.add_folder(".").unwrap();
        draft.add_service("5432").unwrap();
        draft.spec.shell = true;
        let snapshot = AgreementSnapshot {
            id: "a".into(),
            revision: 3,
            peer: [7; 32],
            host_peer: [9; 32],
            name: "alex-laptop".into(),
            relationship: filament_peerloop::access::Relationship::Temporary,
            spec: draft.spec.clone(),
            lifetime: Lifetime::UntilEnded,
            claim_expires_at: 0,
            state: AgreementState::Offered,
            accepted_revision: None,
        };
        let lines = offer_lines(&snapshot, 0);
        assert_eq!(lines[0], "You're being offered access until they end it");
        assert_eq!(lines[1], "You'll appear there as alex-laptop");
        assert!(lines.iter().any(|line| line.starts_with("  \u{2713} Browse and download files from")));
        assert!(lines.iter().any(|line| line == "  \u{2713} Reach port 5432 on their device"));
        assert!(lines.iter().any(|line| line == "  \u{2713} Open a shell on their device, as its owner's account"));
        let all = lines.join("\n");
        for jargon in ["revision", "peer", "0909", "foreground", "endpoint", "reattach"] {
            assert!(!all.contains(jargon), "offer leaks {jargon}: {all}");
        }
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(30), "30 s");
        assert_eq!(human_duration(60), "1 min");
        assert_eq!(human_duration(61), "2 min");
        assert_eq!(human_duration(3600), "1 h");
        assert_eq!(human_duration(5400), "1 h 30 min");
    }
}
