//! `tunlion promote` / `tunlion demote`: one ladder for what a device may do.
//!
//! For a device of yours (or a pairing that could become one):
//!
//!   cut off  <->  paired  <->  your device  <->  your device + shell
//!
//! For someone else's device there is no "your device" rung (only its own
//! owner can certify it), so the same verbs move through capability presets:
//!
//!   cut off  <->  files  <->  files + your shared folder  <->  + shell
//!
//! The moves reuse the one implementation of each thing: `devices forget`'s
//! sibling for cutting off, the restore logic, the code ceremony for "your
//! device" (the owner key signs only after the device takes part), and the
//! owner-signed `grant` / `revoke` paths for capabilities. Nothing here signs
//! or grants by itself.
//!
//! One move the ladder cannot make honestly yet: your device -> paired. The
//! gate refuses a revoked certificate absolutely (it is keyed by the device
//! key), so dropping the certificate also cuts the device off. Until the gate
//! can revoke one certificate and fall back to the pairing, that move is
//! refused with the move that does exist (`--to cut`).

use crate::codeentry::{self, PickOpts, Picked};
use crate::ui::{self, Tone};
use crate::UiCapability;
use anyhow::Result;
use serde_json::{json, Value};

/// A rung. The index orders the ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rung {
    Cut = 0,
    Paired = 1,
    Device = 2,
    Shell = 3,
}

impl Rung {
    pub(crate) const ALL: [Rung; 4] = [Rung::Cut, Rung::Paired, Rung::Device, Rung::Shell];

    fn up(self) -> Option<Rung> {
        Rung::ALL.get(self as usize + 1).copied()
    }

    fn down(self) -> Option<Rung> {
        (self as usize).checked_sub(1).map(|i| Rung::ALL[i])
    }

    /// The `--to` word. Pure.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Rung::Cut => "cut",
            Rung::Paired => "paired",
            Rung::Device => "device",
            Rung::Shell => "shell",
        }
    }

    /// Parse `--to`, with the presets' own words accepted too. Pure.
    pub(crate) fn parse(s: &str) -> Option<Rung> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cut" | "cut-off" | "off" => Some(Rung::Cut),
            "paired" | "pair" | "files" => Some(Rung::Paired),
            "device" | "mine" | "folder" => Some(Rung::Device),
            "shell" => Some(Rung::Shell),
            _ => None,
        }
    }
}

/// Whose ladder a device is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Yours, or a pairing that could become yours.
    Mine,
    /// Someone else's (another owner certified it, or it was invited as a person).
    Theirs,
}

/// The rung's name, in plain words. Pure.
pub(crate) fn label(kind: Kind, r: Rung) -> &'static str {
    match (kind, r) {
        (_, Rung::Cut) => "cut off",
        (Kind::Mine, Rung::Paired) => "paired",
        (Kind::Mine, Rung::Device) => "your device",
        (Kind::Mine, Rung::Shell) => "your device + shell",
        (Kind::Theirs, Rung::Paired) => "files",
        (Kind::Theirs, Rung::Device) => "files + your shared folder",
        (Kind::Theirs, Rung::Shell) => "files, folder + shell",
    }
}

/// One plain line of what the rung means. Pure.
pub(crate) fn meaning(kind: Kind, r: Rung) -> &'static str {
    match (kind, r) {
        (_, Rung::Cut) => "refused on every connection",
        (Kind::Mine, Rung::Paired) => "you can send each other files; not one of your devices",
        (Kind::Mine, Rung::Device) => "certified with your owner key: files and your shared folder",
        (Kind::Mine, Rung::Shell) => "can open a shell here: it can act as you",
        (Kind::Theirs, Rung::Paired) => "can send you files",
        (Kind::Theirs, Rung::Device) => "can send you files and read your shared folder",
        (Kind::Theirs, Rung::Shell) => "can also open a shell here: it can act as you",
    }
}

/// What the ladder knows about one device. Gathered once, judged purely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    pub name: String,
    pub kind: Kind,
    /// Revoked here (cut off).
    pub revoked: bool,
    /// Holds a certificate from THIS device's owner key.
    pub certified_mine: bool,
    /// What it may do here now.
    pub caps: Vec<String>,
    /// This device holds the owner key (only it can certify or sign grants).
    pub owner_here: bool,
    /// A delegated device's invitation ceiling (what no grant or revoke moves).
    pub ceiling: Vec<String>,
}

/// The rung a device is on now. Pure.
pub(crate) fn current(f: &Facts) -> Rung {
    if f.revoked {
        return Rung::Cut;
    }
    let has = |c: &str| f.caps.iter().any(|x| x == c);
    match f.kind {
        Kind::Mine if !f.certified_mine => Rung::Paired,
        Kind::Mine => {
            if has("shell") {
                Rung::Shell
            } else {
                Rung::Device
            }
        }
        Kind::Theirs => {
            if has("shell") {
                Rung::Shell
            } else if has("mount") {
                Rung::Device
            } else {
                Rung::Paired
            }
        }
    }
}

/// One change the ladder makes, each through the existing path for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Undo a cut off (the restore logic).
    Restore,
    /// Cut it off now (durable revoke; live sessions end).
    Cut,
    /// The code ceremony that makes it one of your devices.
    Enrol,
    GrantShell,
    RevokeShell,
    GrantMount,
    RevokeMount,
}

impl Step {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Step::Restore => "restore",
            Step::Cut => "cut",
            Step::Enrol => "enrol",
            Step::GrantShell => "grant-shell",
            Step::RevokeShell => "revoke-shell",
            Step::GrantMount => "grant-mount",
            Step::RevokeMount => "revoke-mount",
        }
    }

    /// What the step changes, in a sentence. Pure.
    fn says(self, name: &str) -> String {
        match self {
            Step::Restore => format!("{name} is recognized again, as it was before it was cut off"),
            Step::Cut => format!("{name} is refused on every connection; its open sessions end"),
            Step::Enrol => format!("{name} gets your owner key's certificate (it joins with a one-time code)"),
            Step::GrantShell => format!("{name} may open a shell here and run commands: it can act as you"),
            Step::RevokeShell => format!("{name} can no longer open a shell here"),
            Step::GrantMount => format!("{name} may read your shared folder"),
            Step::RevokeMount => format!("{name} can no longer read your shared folder"),
        }
    }
}

/// Why a move cannot be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Already on that rung.
    Already(Rung),
    /// No rung above / below.
    End,
    /// Certifying or signing needs the owner key, which is elsewhere.
    NotOwner,
    /// your device -> paired, see the module note.
    DropCertificate,
    /// The capability comes from the device's invitation ceiling, not a grant.
    Ceiling,
}

impl Refusal {
    pub(crate) fn exit(&self) -> crate::exit_codes::ExitKind {
        match self {
            Refusal::NotOwner => crate::exit_codes::ExitKind::Denied,
            _ => crate::exit_codes::ExitKind::Usage,
        }
    }

    /// The sentence, with the command that does work. Pure.
    pub(crate) fn message(&self, f: &Facts) -> String {
        let n = crate::refusal::word(&f.name);
        match self {
            Refusal::Already(r) => format!("{} is already {}; nothing to change", f.name, label(f.kind, *r)),
            Refusal::End => format!("{} is already {}; there is no further step that way", f.name, label(f.kind, current(f))),
            Refusal::NotOwner => format!(
                "only your owner device (the one that holds your owner key) can make {} one of your devices or sign a grant for it; run this there:  tunlion promote {n}",
                f.name
            ),
            Refusal::Ceiling => format!(
                "{} holds that from its invitation ceiling, which a revoke cannot narrow. Cut it off:  tunlion demote {n} --to cut  (or invite it again with less)",
                f.name
            ),
            Refusal::DropCertificate => format!(
                "{} stays one of your devices: dropping its certificate without cutting it off needs per-certificate revocation, which the device gate does not have yet. To cut it off:  tunlion demote {n} --to cut",
                f.name
            ),
        }
    }
}

/// The steps from the current rung to `target`. Pure.
pub(crate) fn plan(f: &Facts, target: Rung) -> Result<Vec<Step>, Refusal> {
    let mut at = current(f);
    if at == target {
        return Err(Refusal::Already(target));
    }
    let mut steps = Vec::new();
    let mut facts = f.clone();
    // Out of "cut off" first: a restore returns the device to where it was.
    if at == Rung::Cut {
        steps.push(Step::Restore);
        facts.revoked = false;
        at = current(&facts);
        if at == target {
            return Ok(steps);
        }
    }
    if target == Rung::Cut {
        // Cutting off changes nothing else: the record (and its grants) is
        // kept as evidence, and promote returns it exactly as it was.
        steps.push(Step::Cut);
        return Ok(steps);
    }
    while at != target {
        let (next, step) = if target > at {
            let next = at.up().ok_or(Refusal::End)?;
            let step = match (f.kind, next) {
                (Kind::Mine, Rung::Device) => Step::Enrol,
                (Kind::Theirs, Rung::Device) => Step::GrantMount,
                (_, Rung::Shell) => Step::GrantShell,
                _ => return Err(Refusal::End),
            };
            if f.kind == Kind::Mine && !f.owner_here {
                return Err(Refusal::NotOwner);
            }
            (next, step)
        } else {
            let next = at.down().ok_or(Refusal::End)?;
            let step = match (f.kind, at) {
                // A shell from an invitation ceiling is not a grant: revoking it
                // cannot bind (`revoke` refuses it). Say so before doing anything.
                (_, Rung::Shell) if f.ceiling.iter().any(|c| c == "shell") => return Err(Refusal::Ceiling),
                (_, Rung::Shell) => Step::RevokeShell,
                (Kind::Mine, Rung::Device) => return Err(Refusal::DropCertificate),
                (Kind::Theirs, Rung::Device) if f.ceiling.iter().any(|c| c == "mount") => return Err(Refusal::Ceiling),
                (Kind::Theirs, Rung::Device) => Step::RevokeMount,
                _ => return Err(Refusal::End),
            };
            (next, step)
        };
        steps.push(step);
        at = next;
    }
    Ok(steps)
}

/// One step up (promote) or down (demote), or `--to`. Pure.
pub(crate) fn target_for(f: &Facts, up: bool, to: Option<Rung>) -> Result<Rung, Refusal> {
    if let Some(t) = to {
        return Ok(t);
    }
    let at = current(f);
    // Up from cut off is back to where it was.
    if up && at == Rung::Cut {
        return Ok(current(&Facts { revoked: false, ..f.clone() }));
    }
    if up { at.up() } else { at.down() }.ok_or(Refusal::End)
}

/// The command that undoes a move from `from`. Pure.
pub(crate) fn undo_command(name: &str, from: Rung, to: Rung) -> String {
    let n = crate::refusal::word(name);
    let verb = if to > from { "demote" } else { "promote" };
    if (to as i32 - from as i32).abs() == 1 && !(from == Rung::Cut || to == Rung::Cut) {
        format!("tunlion {verb} {n}")
    } else {
        format!("tunlion {verb} {n} --to {}", from.word())
    }
}

/// Gather the facts for a stored device. None when there is no record.
pub(crate) fn facts_for(name: &str) -> Option<Facts> {
    let raw = std::fs::read_to_string(crate::devices_store::devices_path()).ok()?;
    let records: Vec<Value> = serde_json::from_str(&raw).ok()?;
    let record = records.iter().find(|r| r["name"].as_str() == Some(name))?;
    let cert = crate::identity::DeviceCert::from_json(&record["deviceCert"]);
    let same_owner = crate::device_view::same_owner_key();
    let person = record["invitedAs"].as_str() == Some("person");
    let certified_mine = cert.as_ref().is_some_and(|c| same_owner == Some(c.user_pub)) && !person;
    let kind = if person || (cert.is_some() && !certified_mine) { Kind::Theirs } else { Kind::Mine };
    Some(Facts {
        name: name.to_string(),
        kind,
        revoked: crate::device_view::record_is_revoked(record),
        certified_mine,
        caps: crate::device_caps::effective_device_caps(name),
        owner_here: crate::load_owner_key().is_some(),
        ceiling: crate::principal_ceiling_for(name).unwrap_or_default(),
    })
}

/// Every stored device with its facts, for the picker.
fn all_facts() -> Vec<Facts> {
    crate::device_names::known_device_names()
        .into_iter()
        .filter_map(|n| facts_for(&n))
        .collect()
}

// ----------------------------------------------------------- the moves --

/// Cut a device off: the durable revoke. Shared with the dashboard's "Cut off".
pub(crate) async fn cut_off(name: &str) -> Result<()> {
    crate::set_device_revoked(name, true)?;
    crate::withdraw_requests_for(name);
    let answer = crate::revocation_live::tell_daemon().await;
    match crate::revocation_live::revoke_line(name, &answer) {
        Ok(line) => crate::outln!("{line}"),
        Err(e) => return Err(crate::revocation_live::unconfirmed_exit(e)),
    }
    Ok(())
}

/// Undo a cut off, or lift the key block a `forget` left behind. Returns the
/// report line; exit 3 when there was nothing by that name at all.
pub(crate) async fn restore(name: &str) -> Result<String> {
    let record = crate::device_view::device_record_exists(name);
    let revoked = record && crate::device_view::device_record_revoked(name);
    if revoked {
        crate::set_device_revoked(name, false)?;
    }
    let lifted = crate::fleet_support::lift_key_revocations_named(name)?;
    let report = crate::fleet_support::restore_report(name, record, revoked, &lifted);
    if !record && lifted.is_empty() {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::UnknownDevice,
            format!("no device named '{name}', and no forgotten device by that name; see `tunlion devices`"),
        ));
    }
    if revoked || !lifted.is_empty() {
        let _ = crate::revocation_live::tell_daemon().await;
    }
    Ok(report)
}

/// Run one step through the existing implementation of it.
async fn run_step(step: Step, name: &str, server: &str, relay: bool) -> Result<()> {
    // The ladder already asked; the shared paths must not ask again.
    let yes = UiCapability { interactive: false, json: false, yes: true, color: false };
    match step {
        Step::Restore => {
            let report = restore(name).await?;
            ui::say(&ui::paint(Tone::Dim, &format!("  {report}")));
        }
        Step::Cut => cut_off(name).await?,
        Step::Enrol => {
            if !crate::interactive_allowed() {
                crate::bail_usage!(
                    "making {name} one of your devices needs it to take part, with a one-time code: run `tunlion promote {}` at a terminal, then `tunlion join <code>` on {name}",
                    crate::refusal::word(name)
                );
            }
            ui::say(&format!(
                "  {name} is paired. To make it one of your devices, it joins once with the code below."
            ));
            crate::pair_cmd::pair_cmd(server, None, Some(name.to_string()), None, relay, true, Vec::new(), None, true)
                .await?;
        }
        Step::GrantShell => crate::dispatch::grant_cmd(Some(name.into()), Some("shell".into()), None, false).await?,
        Step::GrantMount => crate::dispatch::grant_cmd(Some(name.into()), Some("mount".into()), None, false).await?,
        Step::RevokeShell => crate::dispatch::revoke_cmd(&yes, name.into(), Some("shell".into()), false, false).await?,
        Step::RevokeMount => crate::dispatch::revoke_cmd(&yes, name.into(), Some("mount".into()), false, false).await?,
    }
    Ok(())
}

/// The confirmation each move needs, if any: cutting off and anything that
/// grants a shell. Pure.
pub(crate) fn needs_confirm(steps: &[Step]) -> bool {
    steps.iter().any(|s| matches!(s, Step::Cut | Step::GrantShell))
}

/// The JSON result. Pure.
pub(crate) fn json_result(verb: &str, f: &Facts, from: Rung, to: Rung, steps: &[Step]) -> Value {
    json!({
        "ok": true,
        "verb": verb,
        "schema": 2,
        "data": {
            "device": f.name,
            "ladder": match f.kind { Kind::Mine => "mine", Kind::Theirs => "theirs" },
            "from": from.word(),
            "to": to.word(),
            "from_label": label(f.kind, from),
            "to_label": label(f.kind, to),
            "steps": steps.iter().map(|s| s.word()).collect::<Vec<_>>(),
            "undo": undo_command(&f.name, from, to),
        }
    })
}

/// The ladder drawn for one device, current rung marked. Pure but for paint.
pub(crate) fn render_ladder(f: &Facts, online: Option<bool>) -> String {
    let at = current(f);
    let state = match online {
        Some(true) => format!("  \u{b7}  {}", ui::paint(Tone::Ok, "online")),
        Some(false) => format!("  \u{b7}  {}", ui::paint(Tone::Dim, "idle")),
        None => String::new(),
    };
    let mut lines = vec![format!(
        "  {}  \u{b7}  {}{state}",
        ui::paint(Tone::Bold, &f.name),
        label(f.kind, at)
    )];
    if f.kind == Kind::Theirs {
        lines.push(ui::paint(
            Tone::Dim,
            "  someone else's device: there is no \"your device\" rung, these are what it may do here",
        ));
    }
    for r in Rung::ALL.iter().rev() {
        let mark = if *r == at { ui::paint(Tone::Brand, "\u{25cf}") } else { ui::paint(Tone::Dim, "\u{25cb}") };
        let name = if *r == at { ui::paint(Tone::Bold, label(f.kind, *r)) } else { label(f.kind, *r).to_string() };
        let pad = 28usize.saturating_sub(label(f.kind, *r).chars().count());
        let tone = if *r == Rung::Shell { Tone::Warn } else { Tone::Dim };
        lines.push(format!("    {mark} {name}{} {}", " ".repeat(pad), ui::paint(tone, meaning(f.kind, *r))));
    }
    lines.join("\n")
}

/// The moves offered for a device in the interactive ladder: every rung the
/// plan can reach, nearest first, up before down. Pure.
pub(crate) fn legal_moves(f: &Facts) -> Vec<(Rung, Vec<Step>)> {
    let at = current(f);
    let mut ordered: Vec<Rung> = Rung::ALL.iter().copied().filter(|r| *r != at).collect();
    ordered.sort_by_key(|r| ((*r as i32 - at as i32).abs(), if *r > at { 0 } else { 1 }));
    ordered.into_iter().filter_map(|r| plan(f, r).ok().map(|s| (r, s))).collect()
}

/// The ladder for every device, for the dashboard: the same rungs, words
/// and legal moves the terminal shows.
pub(crate) fn dashboard_ladder() -> Vec<Value> {
    all_facts().iter().map(ladder_json).collect()
}

/// One device's ladder as JSON. Pure.
pub(crate) fn ladder_json(f: &Facts) -> Value {
    let at = current(f);
    json!({
        "name": f.name,
        "kind": match f.kind { Kind::Mine => "mine", Kind::Theirs => "theirs" },
        "rung": at.word(),
        "label": label(f.kind, at),
        "rungs": Rung::ALL.iter().map(|r| json!({"rung": r.word(), "label": label(f.kind, *r), "meaning": meaning(f.kind, *r)})).collect::<Vec<_>>(),
        "moves": legal_moves(f).iter().map(|(r, steps)| json!({
            "to": r.word(),
            "label": label(f.kind, *r),
            "meaning": meaning(f.kind, *r),
            "dir": if *r > at { "promote" } else { "demote" },
            "confirm": needs_confirm(steps),
            "says": steps.iter().map(|s| s.says(&f.name)).collect::<Vec<_>>(),
            "needs_terminal": steps.contains(&Step::Enrol),
            "undo": undo_command(&f.name, at, *r),
        })).collect::<Vec<_>>(),
    })
}

// --------------------------------------------------------------- verbs --

/// `promote` (up = true) / `demote`.
pub(crate) async fn ladder_cmd(
    ui_caps: &UiCapability,
    up: bool,
    device: Option<String>,
    to: Option<String>,
    json_out: bool,
    server: &str,
    relay: bool,
) -> Result<()> {
    let verb = if up { "promote" } else { "demote" };
    let to = match to.as_deref() {
        Some(t) => Some(Rung::parse(t).ok_or_else(|| {
            crate::exit_codes::err(
                crate::exit_codes::ExitKind::Usage,
                format!("--to takes cut, paired, device or shell, not '{t}'"),
            )
        })?),
        None => None,
    };
    let Some(name) = device else {
        if json_out || ui_caps.json || !ui_caps.interactive {
            crate::bail_usage!(
                "{verb} needs a device when nobody is at a terminal: tunlion {verb} <device> [--to cut|paired|device|shell]"
            );
        }
        return interactive(ui_caps, server, relay).await;
    };
    let Some(f) = facts_for(&name) else {
        // A forgotten device has no record but may still have a key block to
        // lift: that is the one move up from nothing.
        if up && to.is_none_or(|t| t != Rung::Cut) {
            let report = restore(&name).await?;
            crate::outln!("{report}");
            return Ok(());
        }
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::UnknownDevice,
            format!("no device named '{name}', see `tunlion devices`"),
        ));
    };
    let from = current(&f);
    let target = target_for(&f, up, to).map_err(|r| crate::exit_codes::err(r.exit(), r.message(&f)))?;
    let steps = plan(&f, target).map_err(|r| crate::exit_codes::err(r.exit(), r.message(&f)))?;
    if needs_confirm(&steps) {
        let what = if steps.contains(&Step::Cut) {
            format!("cut off {name} (refused on every connection until you promote it)")
        } else {
            format!("let {name} open a shell here (it can act as you)")
        };
        ui_caps.confirm(&what)?;
    }
    if json_out || ui_caps.json {
        crate::exit_codes::set_json_mode(true, Some(verb));
        if steps.contains(&Step::Enrol) {
            crate::bail_usage!(
                "making {name} one of your devices needs it to take part with a one-time code, so it cannot run under --json: run `tunlion promote {}` at a terminal",
                crate::refusal::word(&name)
            );
        }
    }
    for s in &steps {
        run_step(*s, &name, server, relay).await?;
    }
    let after = facts_for(&name).map(|g| current(&g)).unwrap_or(target);
    if json_out || ui_caps.json {
        ui::json_out(&json_result(verb, &f, from, after, &steps));
    } else {
        say_result(&f, from, after);
    }
    Ok(())
}

fn say_result(f: &Facts, from: Rung, to: Rung) {
    let tone = if to == Rung::Shell { Tone::Warn } else { Tone::Ok };
    ui::say(&format!(
        "  {} {} is now {}  {}",
        ui::paint(tone, ui::glyph_ok()),
        ui::paint(Tone::Bold, &f.name),
        label(f.kind, to),
        ui::paint(Tone::Dim, &format!("(was {})", label(f.kind, from)))
    ));
    ui::say(&ui::paint(Tone::Dim, &format!("  undo: {}", undo_command(&f.name, from, to))));
}

/// The picker row for a device. Pure but for paint.
pub(crate) fn picker_row(f: &Facts, online: Option<bool>) -> String {
    let on = match online {
        Some(true) => " \u{b7} online",
        Some(false) => " \u{b7} idle",
        None => "",
    };
    format!("{:<18} {}{on}", f.name, label(f.kind, current(f)))
}

/// The picker row for an outstanding invitation. Pure.
pub(crate) fn invitation_picker_row(o: &crate::armed::Outstanding) -> String {
    format!("{:<18} invitation \u{b7} {}", o.label(), o.uses_phrase())
}

fn interrupted() -> ! {
    crate::exit_codes::interrupted_exit(crate::exit_codes::INTERRUPTED)
}

/// Bare `promote` / `demote` at a terminal: device, ladder, confirm, result.
/// Esc goes back one screen; Ctrl-C exits 130.
async fn interactive(ui_caps: &UiCapability, server: &str, relay: bool) -> Result<()> {
    let warm = crate::dispatch::answering_links_now().await;
    let online = |n: &str| -> Option<bool> {
        warm.as_ref().map(|w| crate::warm_device_names(Some(w)).iter().any(|x| x == n))
    };
    'device: loop {
        let all = all_facts();
        // Outstanding invitations are listed after the devices: what they can
        // do is fixed at mint, so their one move is to withdraw them.
        let invites = crate::armed::outstanding();
        if all.is_empty() && invites.is_empty() {
            ui::say("  No devices yet. Pair one with:  tunlion add");
            return Ok(());
        }
        let mut rows: Vec<String> = all.iter().map(|f| picker_row(f, online(&f.name))).collect();
        rows.extend(invites.iter().map(invitation_picker_row));
        let f = match codeentry::pick_opts("CHANGE WHAT A DEVICE CAN DO", &rows, PickOpts { collapse: Some(codeentry::Collapse::Erase), ..Default::default() })? {
            Picked::Item(i) if i < all.len() => all[i].clone(),
            Picked::Item(i) => {
                let o = &invites[i - all.len()];
                let confirm = ui::paint(
                    Tone::Dim,
                    &format!(
                        "  {}: invitation, {}. Withdrawn, its key is refused from now on; devices that already joined with it keep their access.",
                        ui::paint(Tone::Bold, &o.label()),
                        o.uses_phrase()
                    ),
                );
                ui::say(&confirm);
                let yes = format!("Yes, withdraw the invitation for {}", o.label());
                match codeentry::pick_opts("", &[yes, "No, go back".to_string()], PickOpts { collapse: Some(codeentry::Collapse::Erase), initial: 1, ..Default::default() })? {
                    Picked::Item(0) => {}
                    Picked::Interrupted => interrupted(),
                    _ => {
                        if ui::caps().live {
                            use std::io::Write as _;
                            let mut e = std::io::stderr();
                            let _ = write!(e, "\x1b[{}A\r\x1b[J", confirm.lines().count());
                            let _ = e.flush();
                        }
                        continue 'device;
                    }
                }
                crate::armed::withdraw(o)?;
                for line in crate::add_for::withdrawn_lines(o, &crate::add_for::joined_with(o.expires)) {
                    ui::say(&line);
                }
                return Ok(());
            }
            Picked::Interrupted => interrupted(),
            _ => return Ok(()),
        };
        'ladder: loop {
            let from = current(&f);
            let shown = render_ladder(&f, online(&f.name));
            ui::say(&shown);
            let moves = legal_moves(&f);
            let shown_lines = shown.lines().count();
            let erase = |n: usize| {
                if ui::caps().live {
                    use std::io::Write as _;
                    let mut e = std::io::stderr();
                    let _ = write!(e, "\x1b[{n}A\r\x1b[J");
                    let _ = e.flush();
                }
            };
            if moves.is_empty() {
                ui::say(&ui::paint(Tone::Dim, "  nothing to change from here"));
            }
            let items: Vec<String> = moves
                .iter()
                .map(|(r, _)| {
                    let dir = if *r > from { "Promote to" } else { "Demote to" };
                    format!("{dir} {} \u{b7} {}", label(f.kind, *r), meaning(f.kind, *r))
                })
                .collect();
            let picked = if items.is_empty() {
                Picked::Cancelled
            } else {
                codeentry::pick_opts("MOVE TO", &items, PickOpts { collapse: Some(codeentry::Collapse::Erase), ..Default::default() })?
            };
            let (target, steps) = match picked {
                Picked::Item(i) => moves[i].clone(),
                Picked::Interrupted => interrupted(),
                _ => {
                    erase(shown_lines + usize::from(items.is_empty()));
                    continue 'device;
                }
            };
            // Confirm: exactly what changes, and the undo.
            let mut confirm = vec![format!(
                "  {}: {} \u{2192} {}",
                ui::paint(Tone::Bold, &f.name),
                label(f.kind, from),
                ui::paint(if target == Rung::Shell { Tone::Warn } else { Tone::Bold }, label(f.kind, target))
            )];
            for s in &steps {
                let tone = if *s == Step::GrantShell { Tone::Warn } else { Tone::Dim };
                confirm.push(ui::paint(tone, &format!("    {}", s.says(&f.name))));
            }
            confirm.push(ui::paint(Tone::Dim, &format!("    undo: {}", undo_command(&f.name, from, target))));
            let confirm = confirm.join("\n");
            ui::say(&confirm);
            let yes = match target {
                Rung::Cut => format!("Yes, cut off {}", f.name),
                Rung::Shell => format!("Yes, {} may act as me", f.name),
                _ => "Yes, do it".to_string(),
            };
            match codeentry::pick_opts("", &[yes, "No, go back".to_string()], PickOpts { collapse: Some(codeentry::Collapse::Erase), initial: 1, ..Default::default() })? {
                Picked::Item(0) => {}
                Picked::Interrupted => interrupted(),
                _ => {
                    erase(shown_lines + confirm.lines().count());
                    continue 'ladder;
                }
            }
            for s in &steps {
                run_step(*s, &f.name, server, relay).await?;
            }
            let after = facts_for(&f.name).map(|g| current(&g)).unwrap_or(target);
            say_result(&f, from, after);
            let _ = ui_caps;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine(certified: bool, caps: &[&str]) -> Facts {
        Facts {
            name: "pop-os".into(),
            kind: Kind::Mine,
            revoked: false,
            certified_mine: certified,
            caps: caps.iter().map(|c| c.to_string()).collect(),
            owner_here: true,
            ceiling: vec![],
        }
    }

    fn theirs(caps: &[&str]) -> Facts {
        Facts { kind: Kind::Theirs, certified_mine: false, name: "carol".into(), ..mine(false, caps) }
    }

    #[test]
    fn the_rung_is_read_from_the_facts() {
        assert_eq!(current(&mine(false, &["transfer"])), Rung::Paired);
        assert_eq!(current(&mine(true, &["transfer", "mount"])), Rung::Device);
        assert_eq!(current(&mine(true, &["transfer", "shell"])), Rung::Shell);
        assert_eq!(current(&Facts { revoked: true, ..mine(true, &["shell"]) }), Rung::Cut);
        // An uncertified pairing holding a shell grant is still not your device.
        assert_eq!(current(&mine(false, &["shell"])), Rung::Paired);
        assert_eq!(current(&theirs(&["transfer"])), Rung::Paired);
        assert_eq!(current(&theirs(&["transfer", "mount"])), Rung::Device);
        assert_eq!(current(&theirs(&["shell"])), Rung::Shell);
    }

    #[test]
    fn one_step_each_way_uses_the_existing_paths() {
        assert_eq!(plan(&mine(false, &["transfer"]), Rung::Device), Ok(vec![Step::Enrol]));
        assert_eq!(plan(&mine(true, &["transfer"]), Rung::Shell), Ok(vec![Step::GrantShell]));
        assert_eq!(plan(&mine(true, &["shell"]), Rung::Device), Ok(vec![Step::RevokeShell]));
        assert_eq!(plan(&mine(false, &["transfer"]), Rung::Cut), Ok(vec![Step::Cut]));
        assert_eq!(plan(&Facts { revoked: true, ..mine(false, &[]) }, Rung::Paired), Ok(vec![Step::Restore]));
        assert_eq!(plan(&theirs(&["transfer"]), Rung::Device), Ok(vec![Step::GrantMount]));
        assert_eq!(plan(&theirs(&["transfer", "mount"]), Rung::Paired), Ok(vec![Step::RevokeMount]));
    }

    #[test]
    fn jumps_chain_steps_and_cutting_drops_shell_first() {
        assert_eq!(plan(&mine(false, &[]), Rung::Shell), Ok(vec![Step::Enrol, Step::GrantShell]));
        // Cutting off keeps the record as it is; promote brings it back whole.
        assert_eq!(plan(&mine(true, &["shell"]), Rung::Cut), Ok(vec![Step::Cut]));
        let cut = Facts { revoked: true, ..mine(true, &["shell"]) };
        assert_eq!(target_for(&cut, true, None), Ok(Rung::Shell));
        assert_eq!(plan(&cut, Rung::Shell), Ok(vec![Step::Restore]));
        // Out of cut off, to where it was, then on.
        assert_eq!(
            plan(&Facts { revoked: true, ..mine(true, &[]) }, Rung::Shell),
            Ok(vec![Step::Restore, Step::GrantShell])
        );
    }

    /// Security: the "your device" rung and any shell for a device of yours
    /// need the owner key HERE; a device without it is told where to go.
    #[test]
    fn only_the_owner_device_climbs_to_your_device_or_shell() {
        let member = Facts { owner_here: false, ..mine(false, &[]) };
        assert_eq!(plan(&member, Rung::Device), Err(Refusal::NotOwner));
        assert_eq!(plan(&Facts { owner_here: false, ..mine(true, &[]) }, Rung::Shell), Err(Refusal::NotOwner));
        assert_eq!(Refusal::NotOwner.exit(), crate::exit_codes::ExitKind::Denied);
        // Cutting off and restoring are local decisions any device may make.
        assert_eq!(plan(&member, Rung::Cut), Ok(vec![Step::Cut]));
    }

    /// Someone else's device never reaches "your device": its rungs are what
    /// it may do here, and none of its moves certifies it.
    #[test]
    fn someone_elses_device_has_no_your_device_rung() {
        for target in Rung::ALL {
            for s in plan(&theirs(&["transfer"]), target).unwrap_or_default() {
                assert_ne!(s, Step::Enrol, "{target:?}");
            }
        }
        assert_eq!(label(Kind::Theirs, Rung::Device), "files + your shared folder");
        assert!(!label(Kind::Theirs, Rung::Device).contains("your device"));
    }

    /// A delegated device's ceiling is not narrowed by a revoke: refused up
    /// front with the move that does work, before anything changes.
    #[test]
    fn a_ceiling_capability_is_not_demoted_by_a_revoke() {
        let f = Facts { ceiling: vec!["transfer".into(), "shell".into()], ..mine(true, &["transfer", "shell"]) };
        assert_eq!(plan(&f, Rung::Device), Err(Refusal::Ceiling));
        assert!(Refusal::Ceiling.message(&f).contains("tunlion demote pop-os --to cut"));
        assert_eq!(plan(&f, Rung::Cut), Ok(vec![Step::Cut]));
    }

    #[test]
    fn dropping_a_certificate_is_refused_with_the_move_that_works() {
        let f = mine(true, &["transfer"]);
        assert_eq!(plan(&f, Rung::Paired), Err(Refusal::DropCertificate));
        let msg = Refusal::DropCertificate.message(&f);
        assert!(msg.contains("tunlion demote pop-os --to cut"), "{msg}");
        assert_eq!(plan(&f, Rung::Device), Err(Refusal::Already(Rung::Device)));
        assert_eq!(target_for(&mine(true, &["shell"]), true, None), Err(Refusal::End));
        assert_eq!(target_for(&Facts { revoked: true, ..mine(false, &[]) }, false, None), Err(Refusal::End));
    }

    #[test]
    fn every_move_names_its_undo_and_the_undo_parses() {
        use clap::Parser;
        let cases = [
            (Rung::Paired, Rung::Device, "tunlion demote pop-os"),
            (Rung::Device, Rung::Shell, "tunlion demote pop-os"),
            (Rung::Shell, Rung::Device, "tunlion promote pop-os"),
            (Rung::Paired, Rung::Cut, "tunlion promote pop-os --to paired"),
            (Rung::Cut, Rung::Paired, "tunlion demote pop-os --to cut"),
            (Rung::Paired, Rung::Shell, "tunlion demote pop-os --to paired"),
        ];
        for (from, to, want) in cases {
            let u = undo_command("pop-os", from, to);
            assert_eq!(u, want);
            let argv: Vec<&str> = u.split_whitespace().collect();
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "does not parse: {u}");
        }
    }

    #[test]
    fn the_json_result_names_both_rungs_and_the_undo() {
        let f = mine(true, &["transfer"]);
        let v = json_result("promote", &f, Rung::Device, Rung::Shell, &[Step::GrantShell]);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["data"]["from"], json!("device"));
        assert_eq!(v["data"]["to"], json!("shell"));
        assert_eq!(v["data"]["steps"], json!(["grant-shell"]));
        assert_eq!(v["data"]["undo"], json!("tunlion demote pop-os"));
    }

    #[test]
    fn moves_are_offered_nearest_first_and_only_legal_ones() {
        let m = legal_moves(&mine(true, &["transfer"]));
        let rungs: Vec<Rung> = m.iter().map(|(r, _)| *r).collect();
        // From your device: up to shell, down only to cut (paired is refused).
        assert_eq!(rungs, vec![Rung::Shell, Rung::Cut]);
        assert!(needs_confirm(&m[0].1) && needs_confirm(&m[1].1));
        assert!(!needs_confirm(&[Step::RevokeShell]));
    }

    #[test]
    fn rung_words_parse_both_ways() {
        for r in Rung::ALL {
            assert_eq!(Rung::parse(r.word()), Some(r));
        }
        assert_eq!(Rung::parse("files"), Some(Rung::Paired));
        assert_eq!(Rung::parse("folder"), Some(Rung::Device));
        assert_eq!(Rung::parse("root"), None);
    }

    #[test]
    fn no_em_dashes_in_any_label() {
        for k in [Kind::Mine, Kind::Theirs] {
            for r in Rung::ALL {
                assert!(!label(k, r).contains('\u{2014}') && !meaning(k, r).contains('\u{2014}'));
            }
        }
    }
}
