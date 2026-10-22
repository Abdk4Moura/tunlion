//! Temporary-access terminal adapter. Drafting is local and side-effect free:
//! it never creates keys, contacts, grants, listeners, or sample invitations.
use anyhow::{Result, bail};
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
        let path = std::fs::canonicalize(input.trim())
            .map_err(|_| anyhow::anyhow!("folder is unavailable or does not exist"))?;
        if !path.is_dir() {
            bail!("choose a folder, not a file");
        }
        if self.spec.folders.iter().any(|folder| folder.path == path) {
            bail!("that folder is already selected");
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
            bail!("that service is already selected");
        }
        let mut spec = self.spec.clone();
        spec.services.push(ServiceAccess { id: format!("service-{}", self.next_id), target: address, protocol: ServiceProtocol::Tcp });
        spec.validate()?;
        self.spec = spec;
        self.next_id += 1;
        Ok(())
    }

    fn review(&self) -> Result<Vec<String>> {
        self.review_with_lifetime(Lifetime::UntilEnded)
    }

    fn review_with_lifetime(&self, lifetime: Lifetime) -> Result<Vec<String>> {
        self.spec.validate()?;
        if self.spec.folders.is_empty() && self.spec.services.is_empty() && !self.spec.shell {
            bail!("choose at least one folder, service, or shell");
        }
        let mut lines = vec![format!("Temporary access · {} · foreground only", lifetime_label(lifetime))];
        lines.extend(self.spec.folders.iter().map(|folder| format!(
            "Folder {} · {}", folder.path.display(),
            if folder.mode == FolderMode::ReadWrite { "read/write" } else { "read-only" }
        )));
        lines.extend(self.spec.services.iter().map(|service| format!("Service {} · TCP", service.target)));
        lines.push(if self.spec.shell {
            "Shell · interactive terminal on this machine's existing account · no resume/reattach".into()
        } else {
            "Shell off · device networking off · no subnet access".into()
        });
        lines.push("No permanent contact. Sharing stops when the host exits.".into());
        Ok(lines)
    }
}

pub(crate) fn lifetime_label(lifetime: Lifetime) -> String {
    match lifetime {
        Lifetime::UntilEnded => "until ended".into(),
        Lifetime::ExpiresAt(at) => format!("expires at {at}"),
    }
}

/// Only a caller holding the shared engine's authenticated review may call this.
pub(crate) fn review_offer(snapshot: &AgreementSnapshot, stop: &AtomicBool) -> Result<()> {
    ui::say(&format!("  Authenticated temporary offer · peer {}", hex::encode(&snapshot.host_peer[..6])));
    ui::say(&format!("  {} · revision {} · {}", terminal_label(&snapshot.name), snapshot.revision, lifetime_label(snapshot.lifetime)));
    let draft = Draft { spec: snapshot.spec.clone(), next_id: 0 };
    for line in draft.review_with_lifetime(snapshot.lifetime)? { ui::say(&format!("  {}", terminal_label(&line))); }
    if !snapshot.spec.folders.is_empty() {
        ui::say("  Folder browse/read checks the host endpoint; download support is platform-specific. No OS mount or DNS is implied.");
    }
    if snapshot.spec.shell {
        #[cfg(all(unix, feature = "pty-server"))]
        ui::say("  Shell opens a real interactive terminal on the host's existing nonroot account; one session, no resume.");
        #[cfg(not(all(unix, feature = "pty-server")))]
        bail!("this build cannot activate the offered interactive shell scope");
    }
    if snapshot.spec.device_network {
        bail!("this build cannot activate the offered device networking scope");
    }
    match live_pick("ACCEPT THIS SCOPE?", &["Accept temporary access".into(), "Decline".into()], stop)? {
        Some(0) if !stop.load(Ordering::Acquire) => Ok(()),
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
            while !stop.load(Ordering::Acquire) {
                let snapshot = engine.snapshot(&id, crate::identity::now_secs())?;
                if matches!(snapshot.state, AgreementState::Ended | AgreementState::Expired | AgreementState::Declined) { return Ok(()); }
                ui::say(&format!("  {} · revision {} · {}", terminal_label(&snapshot.name), snapshot.revision, lifetime_label(snapshot.lifetime)));
                let choice = live_pick("RUNNING ACCESS", &["Change access".into(), "Set expiry".into(), "End access".into()], &stop)?;
                let Some(choice) = choice else {
                    if !stop.load(Ordering::Acquire) {
                        let _ = updates.blocking_send(engine.end(&id, crate::identity::now_secs())?);
                    }
                    return Ok(());
                };
                let updated = match choice {
                    0 => {
                        let Some(spec) = edit_live(&snapshot.spec, snapshot.lifetime, &stop)? else { continue; };
                        engine.revise(&id, snapshot.revision, spec, snapshot.lifetime, crate::identity::now_secs())?
                    }
                    1 => {
                        let Some(raw) = live_line("expiry (30m / 2h; blank = until ended): ", &stop)? else { continue; };
                        let lifetime = if raw.trim().is_empty() { Lifetime::UntilEnded } else {
                            match crate::file_io::parse_mint_ttl(raw.trim()) {
                                Ok(ttl) if ttl > 0 => Lifetime::ExpiresAt(crate::identity::now_secs().saturating_add(ttl)),
                                _ => { ui::say("  Invalid expiry. Nothing changed."); continue; }
                            }
                        };
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
            ui::critical(&format!("  Access controls failed: {error}"));
            if let Ok(snapshot) = engine.end(&id, crate::identity::now_secs()) { let _ = updates.blocking_send(snapshot); }
        }
    });
}

pub(crate) fn live_pick(title: &str, labels: &[String], stop: &AtomicBool) -> Result<Option<usize>> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut cursor = 0;
    let mut redraw = false;
    loop {
        if stop.load(Ordering::Acquire) { return Ok(None); }
        let mut out = std::io::stderr();
        if redraw { write!(out, "\x1b[{}A", labels.len() + 2)?; }
        writeln!(out, "\r\x1b[2K  {title}")?;
        for (i, label) in labels.iter().enumerate() {
            writeln!(out, "\r\x1b[2K  {} {}", if i == cursor { ">" } else { " " }, terminal_label(label))?;
        }
        writeln!(out, "\r\x1b[2K  arrows move · Enter choose · Esc back")?;
        out.flush()?;
        redraw = true;
        // Poll only for keyboard input/cancellation, never for service discovery.
        loop {
            if stop.load(Ordering::Acquire) { return Ok(None); }
            if event::poll(std::time::Duration::from_millis(100))? { break; }
        }
        let Event::Key(key) = event::read()? else { continue; };
        if key.kind == KeyEventKind::Release { continue; }
        match key.code {
            KeyCode::Up => cursor = (cursor + labels.len() - 1) % labels.len(),
            KeyCode::Down => cursor = (cursor + 1) % labels.len(),
            KeyCode::Enter => return Ok(Some(cursor)),
            KeyCode::Esc => return Ok(None),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
            _ => {}
        }
    }
}

pub(crate) fn live_line(prompt: &str, stop: &AtomicBool) -> Result<Option<String>> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalGuard;
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

fn edit_live(spec: &AccessSpec, lifetime: Lifetime, stop: &AtomicBool) -> Result<Option<AccessSpec>> {
    let next_id = spec.folders.iter().map(|folder| &folder.id).chain(spec.services.iter().map(|service| &service.id))
        .filter_map(|id| id.rsplit_once('-')?.1.parse::<u64>().ok()).max().unwrap_or(0).saturating_add(1);
    let mut draft = Draft { spec: spec.clone(), next_id };
    loop {
        let mut labels = draft.spec.folders.iter().map(|folder| format!("Folder {} · {}",
            folder.path.display(), if folder.mode == FolderMode::ReadOnly { "read-only" } else { "read/write" })).collect::<Vec<_>>();
        labels.extend(draft.spec.services.iter().map(|service| format!("Service {}", service.target)));
        let resources = labels.len();
        labels.extend(["Add folder".into(), "Add port".into()]);
        labels.push(format!("Shell: {}", if draft.spec.shell { "on (interactive terminal)" } else { "off" }));
        labels.extend(["Review change".into(), "Cancel".into()]);
        let Some(selected) = live_pick("CHANGE ACCESS", &labels, stop)? else { return Ok(None); };
        if selected < draft.spec.folders.len() {
            match live_pick("FOLDER ACCESS", &["Read-only".into(), "Read/write".into(), "Remove".into()], stop)? {
                Some(0) => draft.spec.folders[selected].mode = FolderMode::ReadOnly,
                Some(1) => draft.spec.folders[selected].mode = FolderMode::ReadWrite,
                Some(_) => { draft.spec.folders.remove(selected); }
                None => {}
            }
            continue;
        }
        if selected < resources { draft.spec.services.remove(selected - draft.spec.folders.len()); continue; }
        match selected - resources {
            0 => if let Some(path) = live_line("folder path: ", stop)? {
                if let Err(error) = draft.add_folder(&path) { ui::say(&format!("  {error}")); }
            },
            1 => if let Some(port) = live_line("port or IP:port: ", stop)? {
                if let Err(error) = draft.add_service(&port) { ui::say(&format!("  {error}")); }
            },
            2 => draft.spec.shell = !draft.spec.shell,
            3 => {
                let lines = match draft.review_with_lifetime(lifetime) { Ok(lines) => lines, Err(error) => { ui::say(&format!("  {error}")); continue; } };
                for line in lines { ui::say(&format!("  {}", terminal_label(&line))); }
                if live_pick("APPLY CHANGE?", &["Apply".into(), "Keep editing".into()], stop)? == Some(0) { return Ok(Some(draft.spec)); }
            }
            _ => return Ok(None),
        }
    }
}

fn parse_service(input: &str) -> Result<SocketAddr> {
    let input = input.trim();
    let address = if let Ok(port) = input.parse::<u16>() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    } else {
        input.parse::<SocketAddr>()
            .map_err(|_| anyhow::anyhow!("enter a port or an explicit IP:port, e.g. 3000 or 127.0.0.1:3000"))?
    };
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        bail!("choose a nonzero port on one explicit unicast address");
    }
    Ok(address)
}

/// Indices, not comma-separated labels: paths and labels may contain commas.
#[derive(Debug, PartialEq, Eq)]
struct Selection {
    checked: Vec<bool>,
    cursor: usize,
}

impl Selection {
    fn new(checked: Vec<bool>) -> Self { Self { checked, cursor: 0 } }
    fn move_by(&mut self, down: bool) {
        if self.checked.is_empty() { return; }
        let n = self.checked.len();
        self.cursor = if down { (self.cursor + 1) % n } else { (self.cursor + n - 1) % n };
    }
    fn toggle(&mut self) {
        if let Some(value) = self.checked.get_mut(self.cursor) { *value = !*value; }
    }
    fn indices(&self) -> Vec<usize> {
        self.checked.iter().enumerate().filter_map(|(i, checked)| checked.then_some(i)).collect()
    }
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = writeln!(std::io::stderr(), "\r");
    }
}

fn checklist(title: &str, labels: &[String], checked: Vec<bool>) -> Result<Option<Vec<usize>>> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    if labels.len() != checked.len() { bail!("invalid checklist state"); }
    if labels.is_empty() { return Ok(Some(Vec::new())); }
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalGuard;
    let mut selection = Selection::new(checked);
    let mut redraw = false;
    loop {
        let mut out = std::io::stderr();
        if redraw { write!(out, "\x1b[{}A", labels.len() + 2)?; }
        writeln!(out, "\r\x1b[2K  {title}")?;
        for (i, label) in labels.iter().enumerate() {
            writeln!(out, "\r\x1b[2K  {} [{}] {}",
                if selection.cursor == i { ">" } else { " " },
                if selection.checked[i] { "x" } else { " " }, terminal_label(label))?;
        }
        writeln!(out, "\r\x1b[2K  arrows move · Space toggle · Enter continue · Esc cancel")?;
        out.flush()?;
        redraw = true;
        let Event::Key(key) = event::read()? else { continue; };
        if key.kind == KeyEventKind::Release { continue; }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
            KeyCode::Up => selection.move_by(false),
            KeyCode::Down => selection.move_by(true),
            KeyCode::Char(' ') => selection.toggle(),
            KeyCode::Enter => return Ok(Some(selection.indices())),
            _ => {}
        }
    }
}

pub(crate) fn terminal_label(label: &str) -> String {
    label.chars().map(|c| if c.is_control() { '�' } else { c }).collect()
}

fn pick(title: &str, labels: Vec<String>) -> Result<usize> {
    crate::codeentry::pick(title, &labels)?.ok_or_else(crate::cancelled)
}

fn edit_folders(draft: &mut Draft) -> Result<()> {
    loop {
        let mut labels: Vec<String> = draft.spec.folders.iter().map(|folder| format!("{} · {}",
            terminal_label(&folder.path.display().to_string()),
            if folder.mode == FolderMode::ReadWrite { "read/write" } else { "read-only" })).collect();
        labels.extend(["Add folder".into(), "Continue".into()]);
        let selected = pick("FOLDERS", labels)?;
        if selected == draft.spec.folders.len() {
            let input = crate::prompt_line("  folder path: ")?;
            if let Err(error) = draft.add_folder(&input) { ui::say(&format!("  {error}")); }
            continue;
        }
        if selected > draft.spec.folders.len() { return Ok(()); }
        match pick("FOLDER ACCESS", vec!["Read-only".into(), "Read/write".into(), "Remove folder".into()])? {
            0 => draft.spec.folders[selected].mode = FolderMode::ReadOnly,
            1 => draft.spec.folders[selected].mode = FolderMode::ReadWrite,
            _ => { draft.spec.folders.remove(selected); }
        }
    }
}

fn edit_services(draft: &mut Draft) -> Result<()> {
    loop {
        // No scan and no fake detected service names. Only explicit local input.
        let action = pick("SERVICES", vec![format!("Choose services ({})", draft.spec.services.len()),
            "Add port".into(), "Continue".into()])?;
        match action {
            0 => {
                if draft.spec.services.is_empty() { ui::say("  No services added. Choose Add port."); continue; }
                let labels = draft.spec.services.iter().map(|service| service.target.to_string()).collect::<Vec<_>>();
                if let Some(indices) = checklist("SERVICES", &labels, vec![true; labels.len()])? {
                    draft.spec.services = indices.into_iter().map(|i| draft.spec.services[i].clone()).collect();
                }
            }
            1 => {
                let input = crate::prompt_line("  port or IP:port: ")?;
                if let Err(error) = draft.add_service(&input) { ui::say(&format!("  {error}")); }
            }
            _ => return Ok(()),
        }
    }
}

/// Safe adapter until authenticated agreement dispatch and endpoint activation
/// are available. Do not route a temporary offer through permanent `pair_cmd`.
pub(crate) fn temporary_access() -> Result<AccessSpec> {
    let mut draft = Draft::default();
    ui::say("  Temporary access · until ended · foreground only.");
    ui::say("  TCP services, supported host folder browse/read, and an interactive shell · no OS mount or DNS setup.");
    loop {
        // Unsupported device networking, expiry and background controls are not offered.
        match pick("TEMPORARY ACCESS", vec![format!("Folders ({})", draft.spec.folders.len()),
            format!("Services ({})", draft.spec.services.len()), "Review / create code".into(),
            format!("Shell: {}", if draft.spec.shell { "on (interactive terminal)" } else { "off" }),
            "Cancel".into()])? {
            0 => edit_folders(&mut draft)?,
            1 => edit_services(&mut draft)?,
            2 => {
                let review = match draft.review() {
                    Ok(review) => review,
                    Err(error) => { ui::say(&format!("  {error}")); continue; }
                };
                for line in review { ui::say(&format!("  {}", terminal_label(&line))); }
                match pick("SHARE THIS SCOPE?", vec!["Create code".into(), "Change access".into(), "Cancel".into()])? {
                    1 => continue,
                    2 => return Err(crate::cancelled()),
                    _ => {}
                }
                // Only the confirmed mutation crosses into the shared ceremony.
                #[cfg(feature = "forward-server")]
                { return Ok(draft.spec); }
                #[cfg(all(not(feature = "forward-server"), unix, feature = "pty-server"))]
                { if draft.spec.shell { return Ok(draft.spec); } }
                #[cfg(not(any(feature = "forward-server", all(unix, feature = "pty-server"))))]
                { let _ = draft; }
                bail!("temporary access unavailable: this build has no scoped endpoint for the chosen resources; no code was created and no access was granted");
            }
            3 => draft.spec.shell = !draft.spec.shell,
            _ => return Err(crate::cancelled()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiselect_preserves_indices_and_wraps() {
        let mut selection = Selection::new(vec![false, true, false]);
        selection.toggle();
        selection.move_by(false);
        assert_eq!(selection.cursor, 2);
        selection.toggle();
        assert_eq!(selection.indices(), vec![0, 1, 2]);
        selection.move_by(true);
        selection.toggle();
        assert_eq!(selection.indices(), vec![1, 2]);
        let mut empty = Selection::new(vec![]);
        empty.move_by(false);
        empty.toggle();
        assert!(empty.indices().is_empty());
    }

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
        let before = draft.review().unwrap();
        assert!(before.iter().any(|line| line.contains("read-only")));
        assert!(before.iter().any(|line| line.contains("until ended")));
        assert!(!before.iter().any(|line| line.contains(".mesh")));
        assert_eq!(before, draft.review().unwrap());
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
    fn expiry_review_never_claims_until_ended_for_an_expiring_offer() {
        let mut draft = Draft::default();
        draft.add_service("3000").unwrap();
        let review = draft.review_with_lifetime(Lifetime::ExpiresAt(1234)).unwrap();
        assert!(review[0].contains("expires at 1234"));
        assert!(!review[0].contains("until ended"));
    }

    #[test]
    fn shell_is_a_first_class_basket_entry_and_review_states_its_boundary() {
        let mut draft = Draft::default();
        assert!(draft.review().is_err(), "an empty basket has nothing to share");
        draft.spec.shell = true;
        let review = draft.review().unwrap();
        assert!(review.iter().any(|line| line.contains("interactive terminal")));
        assert!(review.iter().any(|line| line.contains("no resume/reattach")));
        assert!(!review.iter().any(|line| line.contains("Shell off")));
        draft.spec.shell = false;
        assert!(draft.review().is_err(), "shell removed leaves no resource");
    }
}
