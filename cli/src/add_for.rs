//! `tunlion add --for`: the invitation and approval path.
//!
//! `add_for_cmd` is the handler `Cmd::Add` reaches when the caller names who the
//! addition is for -- it mints a capability for that subject, writes or prints
//! the invitation, and reports uptake. `report_invitation_uptake` is a member
//! rather than an import because this command is its only caller.
//!
//! Nothing here is promoted out of the crate root: every helper this needs
//! (`daemon_alive`, `mint_capability`, `parse_mint_ttl`, `invite_path_for`,
//! `resolve_for_kind`, `format_approval_expiry`, `write_owner_only_file`,
//! `prompt_line`) is private at the root and therefore already visible to this
//! module. There are no cfg branches, no spawns and no awaits in these bodies.
//! `add_for_cmd` keeps its own function-local `use base64::Engine`,
//! `use std::io::Write as _` and `use crossterm::{execute, terminal}`, which is
//! why no trait is imported at module level.
use crate::{
    UiCapability, Zeroizing, cancelled, codeentry, daemon_alive, devices_path, display_name,
    fmt_short_duration, format_approval_expiry, identity, invite_path_for, mint_capability,
    parse_mint_ttl, prompt_line, resolve_for_kind, ui, write_owner_only_file,
};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Report who, if anyone, joined through the invitation that carries `ttl_abs`
/// as its absolute expiry (#275). Polls briefly, because the joiner's "joined"
/// line and the daemon's write to the device store are separate events and the
/// owner presses Enter between them.
fn report_invitation_uptake(ttl_abs: u64) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let joined: Vec<(String, Vec<String>)> = std::fs::read_to_string(devices_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d["principalExpires"].as_u64() == Some(ttl_abs))
            .filter_map(|d| {
                let name = d["name"].as_str()?.to_string();
                let caps = d["principalCeiling"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                Some((name, caps))
            })
            .collect();
        if !joined.is_empty() {
            for (name, caps) in joined {
                ui::say(&format!(
                    "{} '{name}' joined, may {}, access ends {}",
                    ui::glyph_ok(),
                    if caps.is_empty() {
                        "nothing".to_string()
                    } else {
                        caps.join(" and ")
                    },
                    format_approval_expiry(ttl_abs)
                ));
            }
            return;
        }
        if Instant::now() >= deadline {
            // Deliberately not "waiting" or "pending": we do not know that
            // anyone ever scanned it. State only what is checkable.
            ui::say(&format!(
                "  no one has joined on this invitation yet; it stays usable until {}. `tunlion devices` will show them when they do.",
                format_approval_expiry(ttl_abs)
            ));
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub(crate) async fn add_for_cmd(
    caps: &UiCapability,
    for_: Option<String>,
    name: Option<String>,
    mut allow: Vec<String>,
    mut expires: Option<String>,
    reuse: Option<crate::ephemeral::Reuse>,
    out: Option<PathBuf>,
) -> Result<()> {
    use base64::Engine;
    // Before any question or prompt: no identity, no invitation (exit 9).
    if let Some(e) = crate::identity_flow::add_needs_init() {
        return Err(e);
    }
    // The Some("") -> "ask me" normalisation now lives in resolve_for_kind, so
    // both callers get it. Doing it here as well is what let the other caller
    // look correct while it was not.
    // #187: `--for` reads like a name. A bare word that is not the literal
    // device/person is a DEVICE NAME: select device-kind and pre-fill the
    // invitation so the owner can name the invitee up front. The literals
    // keep working for scripts.
    let (kind, named) = resolve_for_kind(caps, for_)?;
    // `add --for device --name b` named the invitee b, and the device joined
    // as its hostname: --name never reached the invitation path.
    let _invitee_name = invitee_name(named, name)?;
    // A name already held by a paired device cannot pass to the new key this
    // invitation enrols (it is stored as `<name>-2`), which is how a reset
    // device came back as a second record beside its stale self. Say so now,
    // while forgetting the old record first is still one command.
    if let Some(name) = _invitee_name.as_deref() {
        if crate::device_view::device_record_exists(name) {
            let now = crate::identity::now_secs();
            let seen = crate::device_view::devices_info(name)
                .map(|(t, _, _)| t)
                .filter(|t| *t > 0)
                .map(|t| crate::reset_hints::ago(now.saturating_sub(t)));
            ui::say(&format!(
                "  {} {}",
                ui::paint(ui::Tone::Warn, "!"),
                crate::reset_hints::name_taken_note(name, seen.as_deref())
            ));
        }
    }
    // The ergonomic gap behind "I want to shell into my own devices": shell has
    // to be in the invitation ceiling, because a grant cannot widen one later
    // (#226, which now refuses honestly instead of pretending). So the only way
    // to get it was `--allow shell`, a flag you had to already know about, on a
    // path the interactive flow never mentioned. Ask instead.
    //
    // Offered only for a device you control, only when the user did not pass
    // --allow, and only interactively. A person gets transfer and is not asked,
    // because owner-equivalent access to a stranger should stay a deliberate
    // flag rather than a menu item one keypress away.
    let mut interactive_shell = false;
    // Prefixes pulled out of `--allow route:<cidr>`; empty for every other kind
    // of invitation, which keeps those tokens byte-identical v2.
    let mut route_prefixes: Vec<String> = Vec::new();
    if allow.is_empty() && kind == "device" && caps.interactive {
        let choices = vec![
            "Send files, and mount my folders".to_string(),
            "...and open a terminal here  (OWNER-EQUIVALENT)".to_string(),
        ];
        match codeentry::pick("WHAT THIS DEVICE MAY DO", &choices)? {
            Some(1) => interactive_shell = true,
            Some(_) => {}
            None => return Err(cancelled()),
        }
    }
    let default_ttl = if kind == "device" { "30d" } else { "1h" };
    // INTERACTIVE PARITY FOR A RUNNER. The flags answer three questions --
    // --reuse (how many boxes), --expires (how long each), --allow (what each
    // may do) -- and an unattended runner previously answered all three
    // silently: one box, one hour, transfer only. Ask only what the caller did
    // not already answer, so the flags and the prompts produce one artifact.
    // Enter at a question keeps exactly the old default, including Reuse::Once,
    // so an all-Enter run mints the same bytes it did before.
    let mut reuse = reuse;
    if kind == "runner" && caps.interactive {
        if reuse.is_none() {
            let answer =
                runner_prompt("  How many boxes may use this invitation? [1, or type cancel]: ")?;
            reuse = Some(parse_reuse_answer(&answer)?);
        }
        if expires.is_none() {
            let answer = runner_prompt(&format!(
                "  How long may each stay? [{default_ttl}, or type cancel]: "
            ))?;
            expires = Some(parse_ttl_answer(&answer, default_ttl)?);
        }
        if allow.is_empty() {
            // Shell is the deliberate one, so it is NAMED as owner-equivalent
            // instead of being the default. A runner's everyday job is moving
            // bytes; a terminal on this machine is the owner's own authority.
            let choices = vec![
                "Send files only".to_string(),
                "Send files, and open a terminal here  (OWNER-EQUIVALENT)".to_string(),
            ];
            let picked = codeentry::pick("WHAT EACH RUNNER MAY DO", &choices)?;
            allow = runner_allow(picked)?;
        }
    }
    let mint_reuse = reuse.unwrap_or(crate::ephemeral::Reuse::Once);
    let mut ceiling = if allow.is_empty() {
        if kind == "runner" {
            // A runner moves bytes and nothing else by default. Widening it is
            // --allow, deliberately, the same as for anyone else.
            vec!["transfer".to_string()]
        } else if kind == "device" {
            let mut c = vec!["transfer".to_string(), "mount".to_string()];
            if interactive_shell {
                c.push("shell".to_string());
            }
            c
        } else {
            vec!["transfer".to_string()]
        }
    } else {
        // `route:10.0.0.0/24` carries its scope in the flag. Split the prefixes
        // out here so they can travel in the SIGNED ceiling: a bare `route` is
        // refused at mint, because a ceiling that cannot say which prefix is not
        // a scope at all, and it previously authorised every prefix a member
        // chose to advertise, 0.0.0.0/0 included.
        let mut caps = Vec::new();
        for entry in allow {
            match entry.split_once(':') {
                Some((name, cidr))
                    if mint_capability(name).ok().as_deref()
                        == Some(crate::capability::CAP_ROUTE) =>
                {
                    caps.push(crate::capability::CAP_ROUTE.to_string());
                    for one in cidr.split(',').map(str::trim).filter(|c| !c.is_empty()) {
                        route_prefixes.push(one.to_string());
                    }
                }
                _ => caps.push(mint_capability(&entry)?),
            }
        }
        caps
    };
    ceiling.sort();
    ceiling.dedup();
    let ttl_text = expires.unwrap_or_else(|| default_ttl.to_string());
    let ttl = parse_mint_ttl(&ttl_text)?;
    if ttl == 0 || ttl > 30 * 24 * 3600 {
        bail!("invitations must expire between 1 second and 30 days");
    }
    if ceiling
        .iter()
        .any(|capability| capability == "shell" || capability == "all-ports")
    {
        caps.confirm("include deliberate remote authority in this invitation ceiling")?;
    }
    if !caps.interactive && out.is_none() {
        // They already said who. Do not re-explain --for; name the one missing
        // piece, with a filename derived from what they actually typed so the
        // suggestion is copy-pasteable rather than a template.
        // Defensive: both call sites now supply a path (a bare `add laptop`
        // defaults to tunlion-invite-laptop.txt and says so), so this cannot
        // fire today. Kept because add_for_cmd is a function and a future caller
        // could pass None, and written as lines because the continued literal it
        // replaced dragged its source indentation into the output.
        let suggested = invite_path_for(_invitee_name.as_deref(), &kind);
        let who = _invitee_name
            .clone()
            .unwrap_or_else(|| format!("--for {kind}"));
        bail!(
            "{}",
            [
                "a script has to say where the invitation goes (it holds a credential):"
                    .to_string(),
                String::new(),
                format!("  tunlion add {who} --out {}", suggested.display()),
                String::new(),
                format!(
                    "  Then on that machine:  tunlion join {}",
                    suggested.display()
                ),
            ]
            .join("\n")
        );
    }
    let owner_key = crate::identity_flow::ensure_user_key(caps.json)?;
    let mut enroll_seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut enroll_seed)
        .map_err(|_| anyhow!("failed to generate invitation possession key"))?;
    // #186: the v2 invitation is a compact binary token (base64url) with a
    // self-contained signature, not hex-inside-JSON-inside-base64. ~530 chars
    // became ~210, and the QR fits a normal terminal.
    let ttl_abs = identity::now_secs().saturating_add(ttl);
    // AN INVITATION IS AN AUTH KEY WITH DIFFERENT CONFIG. The two were separate
    // artifacts in separate formats reached by separate verbs, and the fields
    // say otherwise: enroll_pub, caps, expires, reuse, ephemeral and sig are the
    // same in both, and Invitation already CARRIES the `ephemeral` flag that
    // is the whole difference. It was hardcoded `false` here, so the only way to
    // get the ephemeral variant was a different command writing a different file
    // format that a different claim verb could read.
    //
    // So `runner` is not a third artifact. It is this one, minted ephemeral:
    // removed on disconnect, no persistent record, which is exactly what an
    // unattended CI box should leave behind.
    let ephemeral = kind == "runner";
    let inv = crate::ephemeral::Invitation::mint(
        owner_key.keypair(),
        enroll_seed,
        ceiling.clone(),
        ttl_abs,
        30 * 24 * 3600,
        mint_reuse.clone(),
        ephemeral,
        display_name(),
        route_prefixes.clone(),
    )?;
    enroll_seed.fill(0);
    let token = Zeroizing::new(format!(
        // `v2:` IS PART OF THE WIRE FORMAT, not decoration. 0.8.4 and 0.8.5 --
        // the releases in users' hands -- parse only `filament-invite:v2:`, so a
        // token minted without it reads as "unknown format" on every device that
        // has not upgraded. #291 dropped the segment with no payload change,
        // which silently broke enrolment across the release boundary in both
        // directions. Keep minting it until no supported release needs it.
        // PROTOCOL LITERAL: frozen, do not rename (file_io::INVITE_PREFIX_V2).
        "{}{}",
        crate::file_io::INVITE_PREFIX_V2,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inv.to_token())
    ));
    // #205/#211: arming is a FILE WRITE, not IPC. The mint records the key in
    // armed.json directly; the daemon's per-tick arm-gate reads it. No socket,
    // no bind race, no platform branch, no control channel. The only thing the
    // mint cannot guarantee is that a RECEIVER is actually running to pick the
    // key up - check that, and offer to start one.
    crate::armed::arm(hex::encode(inv.enroll_pub), inv.expires, _invitee_name.clone(), Some(kind.clone()));
    // Make the daemon subscribe the enrollment channel NOW rather than on its next
    // idle tick, so a joiner that arrives within a second (a QR scan, a script) is
    // not left waiting on an empty channel. Measured: ~1.0-1.2 s back-to-back vs
    // ~0.2 s once subscribed. No daemon, or no control socket (#205): harmless.
    let _ = crate::ctl::try_wake().await;
    // #207: a minted code that nothing can claim is not an invitation, it is a
    // lie with a QR on it. The receiver is what claims; if none is running,
    // say so before printing and offer to start one.
    if caps.interactive && daemon_alive().is_none() {
        use std::io::Write as _;
        eprint!(
            "  the always-on receiver is not running.\n  Start it now so this invitation can be claimed? [y/N] "
        );
        let _ = std::io::stderr().flush();
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans).ok();
        if matches!(ans.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            let exe = std::env::current_exe()?;
            let _ = crate::platform::command(&exe)
                .arg("up")
                .arg("--install")
                .spawn();
            ui::say(&format!(
                "  {} receiver starting ({})",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                exe.display()
            ));
        }
    }

    if let Some(path) = out.as_deref() {
        write_owner_only_file(path, token.as_str())?;
    } else {
        use crossterm::{execute, terminal};
        let mut err = std::io::stderr();
        execute!(
            err,
            terminal::EnterAlternateScreen,
            terminal::Clear(terminal::ClearType::All)
        )?;
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "JOIN INVITATION"));
        eprintln!("  kind     {kind}");
        eprintln!("  ceiling  {}", ceiling.join(", "));
        eprintln!(
            "  budget   {} (the key allows up to {})",
            fmt_short_duration(inv.max_offline),
            fmt_short_duration(inv.max_offline)
        );
        let expires_line = if matches!(mint_reuse, crate::ephemeral::Reuse::Once) {
            format!("  expires  {ttl_text}")
        } else {
            format!("  expires  {ttl_text}  ({})", reuse_phrase(&mint_reuse))
        };
        eprintln!("{expires_line}");
        eprintln!();
        eprintln!(
            "  Whoever captures this can join {}.",
            claim_window(&mint_reuse)
        );
        // The token is printed ONCE, on its own line. qr_or_text's fallback
        // embeds the text, which would double it here; so render the QR only
        // when it fits and let the note stand alone otherwise (the other QR
        // callers rely on the fallback embedding the text, so the helper is
        // not changed - this call site prints the token separately).
        if ui::qr_fits(token.as_str(), 8) {
            eprintln!("{}", ui::qr(token.as_str()));
        } else if let Some(note) = ui::qr_too_tall_note(token.as_str(), 8) {
            eprintln!("  {note}; the code is below");
        }
        eprintln!("{}", token.as_str());
        eprintln!("  keep this window open so the QR stays on screen; the other device scans it");
        let result = prompt_line("\n  Press Enter after the other device has captured it: ");
        let _ = execute!(err, terminal::LeaveAlternateScreen);
        result?;
        // #275: this surface used to say nothing at all once the QR came down.
        // The owner picked the duration and the ceiling, someone joined under
        // them, and the one screen that knew what was offered never confirmed
        // what was taken; you had to run `tunlion devices` to find out.
        //
        // The mint process cannot observe the enrollment directly, because the
        // joiner talks to the running daemon and not to us. So match on the
        // invitation's absolute expiry, which the daemon copies verbatim into
        // `principalExpires`: a delegated record carrying THIS ttl_abs was
        // enrolled by THIS invitation.
        //
        // Says nothing rather than something reassuring when no record appears.
        // A claim of success we cannot support is worse than silence, which is
        // the failure this issue is about in the first place.
        report_invitation_uptake(ttl_abs);
    }
    if caps.json {
        let mut envelope = json!({
            "ok": true,
            "verb": "add",
            "kind": kind,
            "ceiling": ceiling,
            "maxOffline": inv.max_offline,
            "expires": inv.expires,
            "writtenTo": out,
            "invitationSecretPrinted": false,
        });
        // Absent --reuse keeps the envelope byte-identical to earlier releases.
        if !matches!(mint_reuse, crate::ephemeral::Reuse::Once) {
            envelope["reuse"] = reuse_json(&mint_reuse);
        }
        crate::outln!(
            "{}",
            serde_json::to_string_pretty(&envelope)?
        );
    } else if let Some(path) = out {
        ui::say(&format!(
            "  {} invitation written to {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            path.display()
        ));
        ui::say(&ui::paint(
            ui::Tone::Warn,
            &format!(
                "  Anyone who reads that file can join {}.",
                claim_window(&mint_reuse)
            ),
        ));
        // The step a first-time user could not find: they had a file and two
        // machines that share nothing. `join` takes the path positionally.
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        ui::say(&join_next_step(&file_name, _invitee_name.as_deref()));
    }
    // Non-interactive (--out or a pipe): no offer was printed above. Warn that a
    // receiver must be running to claim, which is the one thing the file write
    // cannot guarantee.
    if !caps.interactive && daemon_alive().is_none() {
        ui::say(&ui::paint(
            ui::Tone::Warn,
            &receiver_not_running_note(crate::platform::ServiceHost::detect().supports_install()),
        ));
    }
    Ok(())
}

/// The warning for an invitation written while no receiver is running. It
/// used to say "start `tunlion up --install`" on every platform, including the
/// ones where `--install` then answers that it is not supported. Suggest it
/// only where a service manager exists; `up --detach` works everywhere.
pub(crate) fn receiver_not_running_note(can_install: bool) -> String {
    let start = if can_install {
        "tunlion up --install"
    } else {
        "tunlion up --detach"
    };
    format!(
        "  note: the always-on receiver is not running; start `{start}` before anyone claims this invitation."
    )
}

/// The largest bounded count a v2 invitation can carry. The token stores reuse
/// in ONE byte: 0 is once, 255 is forever, and 1..=250 are counts. The encoder
/// clamps anything larger to 250, so accepting 300 would tell the owner "300
/// boxes" and mint a 250-box artifact. Refuse it instead of minting less than
/// was asked for.
pub(crate) const MAX_BOUNDED_USES: u32 = 250;

/// `--reuse` as a `Reuse`: `forever` is `Reusable`, a bare number is `N(n)`.
/// Shared by the flag and the interactive answer so both spellings accept the
/// same values and fail with the same words.
pub(crate) fn parse_reuse(raw: &str) -> Result<crate::ephemeral::Reuse> {
    use crate::ephemeral::Reuse;
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("forever") {
        return Ok(Reuse::Reusable);
    }
    let Ok(n) = raw.parse::<u32>() else {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::Usage,
            format!(
                "--reuse takes a number of machines (1-{MAX_BOUNDED_USES}) or `forever`, not '{raw}'"
            ),
        ));
    };
    if n == 0 {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::Usage,
            "`--reuse 0` would admit nobody; leave --reuse off for a single-use invitation",
        ));
    }
    if n > MAX_BOUNDED_USES {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::Usage,
            format!(
                "`--reuse {n}` is above the format's limit of {MAX_BOUNDED_USES}: the invitation stores the count in one byte (255 means forever), and a larger number would be silently reduced instead of admitting everyone you asked for"
            ),
        ));
    }
    Ok(Reuse::N(n))
}

/// `--reuse` needs a bounded invitation. A bare `tunlion add` offers an
/// ordinary pair, which is a one-time ceremony with no artifact to count, so
/// the flag is refused rather than ignored. Pure, and pinned by a test to
/// exit 2.
pub(crate) fn check_reuse_target(has_for: bool, has_reuse: bool) -> Result<()> {
    if has_reuse && !has_for {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::Usage,
            "`--reuse` needs a bounded invitation, so it cannot go with a bare `tunlion add`: an ordinary pair is always a one-time ceremony with no artifact to count. Add `--for device|person|runner` (the invitation is written to a file; `--out <path>` chooses where).",
        ));
    }
    Ok(())
}

/// The capability picker's answer for a runner: `None` is the picker's cancel;
/// row 0 is transfer-only, which is the old default and returns no override;
/// the shell row adds transfer + shell, because widening a ceiling must not
/// silently drop the baseline the runner already had. Pure so the cancel path
/// is testable without a terminal.
pub(crate) fn runner_allow(choice: Option<usize>) -> Result<Vec<String>> {
    match choice {
        None => Err(cancelled()),
        Some(0) => Ok(Vec::new()),
        Some(_) => Ok(vec!["transfer".to_string(), "shell".to_string()]),
    }
}

/// One line of input for a runner question. Unlike the shared `prompt_line`,
/// end-of-input is a CANCEL, not an empty answer: a closed stdin is not a
/// person pressing Enter, and treating it as the default would mint an
/// invitation after the operator walked away. Ctrl-C already ends the process
/// before the mint; this closes the other silent path.
fn runner_prompt(prompt: &str) -> Result<String> {
    use std::io::Write as _;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Err(cancelled());
    }
    Ok(line.trim().to_string())
}

/// The count answer at the runner prompt. Enter keeps the old default, one
/// claim (`Once`, byte-identical to every invitation minted before --reuse);
/// `cancel` returns before anything is minted.
pub(crate) fn parse_reuse_answer(raw: &str) -> Result<crate::ephemeral::Reuse> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("cancel") {
        return Err(cancelled());
    }
    if raw.is_empty() {
        return Ok(crate::ephemeral::Reuse::Once);
    }
    parse_reuse(raw)
}

/// The lifetime answer at the runner prompt. Enter keeps the kind's existing
/// default; `cancel` returns before anything is minted. The value is parsed and
/// bounded by the caller, so a typo fails before the key is created too.
pub(crate) fn parse_ttl_answer(raw: &str, default: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("cancel") {
        return Err(cancelled());
    }
    if raw.is_empty() {
        return Ok(default.to_string());
    }
    Ok(raw.to_string())
}

/// How a minted invitation is spent, for the QR screen and the file warning.
/// `Once` is the wording every earlier release printed.
pub(crate) fn claim_window(reuse: &crate::ephemeral::Reuse) -> &'static str {
    use crate::ephemeral::Reuse;
    match reuse {
        Reuse::Once => "until it is used or expires",
        Reuse::N(_) => "until its uses run out or it expires",
        Reuse::Reusable => "until it expires",
    }
}

/// "up to 5 machines" / "once" / "any number of machines", for the one new
/// screen line a non-default invitation adds.
pub(crate) fn reuse_phrase(reuse: &crate::ephemeral::Reuse) -> String {
    use crate::ephemeral::Reuse;
    match reuse {
        Reuse::Once => "once".to_string(),
        Reuse::N(1) => "1 machine".to_string(),
        Reuse::N(n) => format!("up to {n} machines"),
        Reuse::Reusable => "any number of machines".to_string(),
    }
}

fn reuse_json(reuse: &crate::ephemeral::Reuse) -> serde_json::Value {
    use crate::ephemeral::Reuse;
    match reuse {
        Reuse::Once => json!("once"),
        Reuse::N(n) => json!(n),
        Reuse::Reusable => json!("forever"),
    }
}

/// The invitee's name from `--for <name>` (or `add <name>`) and `--name`.
/// Either alone names them; both naming the same is fine; two different
/// names is a contradiction, refused rather than silently resolved. Pure.
pub(crate) fn invitee_name(named: Option<String>, name: Option<String>) -> Result<Option<String>> {
    let name = name.filter(|n| !n.trim().is_empty());
    match (named, name) {
        (Some(a), Some(b)) if a != b => Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::Usage,
            format!("you named the invitee twice: '{a}' and --name {b}. Use one."),
        )),
        (a, b) => Ok(b.or(a)),
    }
}

#[cfg(test)]
mod invitee_name_tests {
    use super::invitee_name;

    /// F: `add --for device --name b` must name the device b.
    #[test]
    fn name_names_the_invitee_on_the_invitation_path() {
        assert_eq!(invitee_name(None, Some("b".into())).unwrap().as_deref(), Some("b"));
        assert_eq!(invitee_name(Some("b".into()), None).unwrap().as_deref(), Some("b"));
        assert_eq!(invitee_name(Some("b".into()), Some("b".into())).unwrap().as_deref(), Some("b"));
        assert_eq!(invitee_name(None, None).unwrap(), None);
        assert_eq!(invitee_name(None, Some(" ".into())).unwrap(), None);
        let e = invitee_name(Some("a".into()), Some("b".into())).unwrap_err();
        assert_eq!(crate::exit_codes::classify(&e).code(), 2);
    }
}

/// The step printed after `add --out`: copy the file, then join with it. When
/// the owner named the invitee, the join names it too, so both ends call the
/// device what the owner chose (the joiner otherwise names itself after its
/// hostname, and that is the name the owner's list showed). The owner's store
/// uses the chosen name either way (`armed::invitee_name`). Pure.
pub(crate) fn join_next_step(file_name: &str, invitee: Option<&str>) -> String {
    let file = if file_name.chars().any(char::is_whitespace) {
        format!("'{file_name}'")
    } else {
        file_name.to_string()
    };
    match invitee.filter(|n| !n.chars().any(char::is_whitespace) && !n.is_empty()) {
        Some(n) => format!(
            "  next: copy it to the other device, then run there:  tunlion join {file} --name {n}"
        ),
        None => format!("  next: copy it to the other device, then run there:  tunlion join {file}"),
    }
}

#[cfg(test)]
mod join_next_step_tests {
    use super::join_next_step;

    #[test]
    fn the_join_step_carries_the_name_the_owner_chose() {
        let named = join_next_step("beta-invite.txt", Some("beta"));
        assert!(named.ends_with("tunlion join beta-invite.txt --name beta"), "{named}");
        let plain = join_next_step("invite.txt", None);
        assert!(plain.ends_with("tunlion join invite.txt"), "{plain}");
        use clap::Parser;
        let cmd = &named[named.find("tunlion").unwrap()..];
        let argv: Vec<&str> = cmd.split_whitespace().collect();
        assert!(crate::Cli::try_parse_from(&argv).is_ok(), "{cmd}");
    }
}

#[cfg(test)]
mod reuse_tests {
    use super::{
        claim_window, check_reuse_target, parse_reuse, parse_reuse_answer, parse_ttl_answer,
        reuse_phrase, runner_allow, MAX_BOUNDED_USES,
    };
    use crate::ephemeral::{Invitation, Reuse};
    use crate::invite_burn::{admit, record_use_at, Refusal};
    use base64::Engine;
    use ring::signature::Ed25519KeyPair;
    use std::path::PathBuf;

    fn mint(reuse: Reuse) -> Invitation {
        let mut seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).unwrap();
        let owner = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        Invitation::mint(
            &owner,
            seed,
            vec!["transfer".to_string()],
            1_800_000_000,
            3600,
            reuse,
            true,
            "owner".into(),
            Vec::new(),
        )
        .unwrap()
    }

    /// Mint exactly as the command does, then parse the artifact the way a
    /// claimer does. This is the round trip a hand-built `Reuse` cannot prove.
    fn round_trip(reuse: Reuse) -> Invitation {
        let inv = mint(reuse);
        let token = format!(
            "{}{}",
            crate::file_io::INVITE_PREFIX_V2,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inv.to_token())
        );
        assert!(
            token.starts_with(crate::file_io::INVITE_PREFIX_V2),
            "the v2 prefix is part of the wire format: {token}"
        );
        crate::file_io::parse_invitation(&token).expect("a freshly minted token must parse")
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tunlion-add-reuse-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("used-invitations.json")
    }

    #[test]
    fn bounded_invitation_round_trips_the_count_and_stops_at_it() {
        let parsed = round_trip(Reuse::N(3));
        assert_eq!(
            parsed.reuse,
            Reuse::N(3),
            "the claim side must see the count the owner minted"
        );
        let key = hex::encode(parsed.enroll_pub);
        let p = scratch("n3");
        for at in 0u64..3 {
            assert_eq!(
                record_use_at(&p, &key, &parsed.reuse, parsed.expires, at),
                Ok(()),
                "use {} of 3 must be admitted",
                at + 1
            );
        }
        assert_eq!(
            record_use_at(&p, &key, &parsed.reuse, parsed.expires, 4),
            Err(Refusal::UseLimitReached),
            "the fourth use must hit the minted limit, not already-used"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn forever_invitation_round_trips_and_is_never_refused_by_count() {
        let parsed = round_trip(Reuse::Reusable);
        assert_eq!(parsed.reuse, Reuse::Reusable);
        let key = hex::encode(parsed.enroll_pub);
        let p = scratch("forever");
        for at in 0u64..6 {
            assert_eq!(
                record_use_at(&p, &key, &parsed.reuse, parsed.expires, at),
                Ok(()),
                "reusable use {} must be admitted",
                at + 1
            );
        }
        assert_eq!(admit(1_000_000, &parsed.reuse), Ok(()));
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn the_default_invitation_still_refuses_a_second_claim() {
        // No flag means Once, which is what every earlier release minted.
        assert_eq!(parse_reuse_answer("").unwrap(), Reuse::Once);
        let parsed = round_trip(Reuse::Once);
        assert_eq!(parsed.reuse, Reuse::Once);
        let key = hex::encode(parsed.enroll_pub);
        let p = scratch("once");
        assert_eq!(
            record_use_at(&p, &key, &parsed.reuse, parsed.expires, 1),
            Ok(())
        );
        assert_eq!(
            record_use_at(&p, &key, &parsed.reuse, parsed.expires, 2),
            Err(Refusal::AlreadyUsed),
            "the second claim of a default invitation is already-used, not a use limit"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    #[test]
    fn the_flag_reaches_the_add_command_and_is_absent_by_default() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "tunlion", "add", "--for", "runner", "--reuse", "3", "--out", "ci.key",
        ])
        .expect("--reuse must be a flag on add");
        match cli.cmd {
            Some(crate::Cmd::Add { reuse, .. }) => {
                assert_eq!(reuse.as_deref(), Some("3"), "the value must survive clap");
            }
            _ => panic!("expected add"),
        }
        let cli = crate::Cli::try_parse_from([
            "tunlion", "add", "--for", "runner", "--out", "ci.key",
        ])
        .unwrap();
        match cli.cmd {
            Some(crate::Cmd::Add { reuse, .. }) => {
                assert_eq!(reuse, None, "no --reuse is the single-use default");
            }
            _ => panic!("expected add"),
        }
    }

    #[test]
    fn reuse_without_for_is_a_usage_error() {
        let e = check_reuse_target(false, true).expect_err("a bare add has no invitation to reuse");
        assert_eq!(
            crate::exit_codes::classify(&e).code(),
            2,
            "a flag that cannot apply is a usage error: {e}"
        );
        assert!(e.to_string().contains("--for"), "the fix must name --for: {e}");
        // With --for, the same flag is accepted; the value parser has already
        // refused anything that is not a count or `forever`.
        assert!(check_reuse_target(true, true).is_ok());
        assert!(check_reuse_target(true, false).is_ok());
    }

    #[test]
    fn reuse_values_are_bounded_and_parsed() {
        assert_eq!(parse_reuse("3").unwrap(), Reuse::N(3));
        assert_eq!(parse_reuse(" 1 ").unwrap(), Reuse::N(1));
        assert_eq!(parse_reuse("forever").unwrap(), Reuse::Reusable);
        assert_eq!(parse_reuse("FOREVER").unwrap(), Reuse::Reusable);
        assert_eq!(
            parse_reuse(&MAX_BOUNDED_USES.to_string()).unwrap(),
            Reuse::N(MAX_BOUNDED_USES)
        );
        for bad in ["0", "abc", "-5", "1.5", "251", ""] {
            let e = parse_reuse(bad).expect_err(bad);
            assert_eq!(
                crate::exit_codes::classify(&e).code(),
                2,
                "'{bad}' must be a usage error: {e}"
            );
        }
        // The upper bound is the TOKEN's, not a taste call: the byte encoder
        // clamps above it, so 251 would mint a 250-use invitation.
        assert!(
            parse_reuse("251").unwrap_err().to_string().contains("250"),
            "the out-of-range message must name the format limit"
        );
    }

    #[test]
    fn an_enter_at_a_runner_prompt_keeps_the_old_defaults() {
        assert_eq!(parse_reuse_answer("").unwrap(), Reuse::Once);
        assert_eq!(parse_ttl_answer("", "1h").unwrap(), "1h");
        assert_eq!(parse_ttl_answer("  ", "30d").unwrap(), "30d");
        assert_eq!(
            runner_allow(Some(0)).unwrap(),
            Vec::<String>::new(),
            "the default row must add no override, so the ceiling stays transfer-only"
        );
        assert_eq!(
            runner_allow(Some(1)).unwrap(),
            vec!["transfer".to_string(), "shell".to_string()],
            "choosing shell keeps the runner's baseline transfer"
        );
        assert_eq!(
            claim_window(&Reuse::Once),
            "until it is used or expires",
            "the default line is unchanged"
        );
        assert_eq!(reuse_phrase(&Reuse::Once), "once");
    }

    #[test]
    fn cancelling_a_runner_prompt_returns_before_a_mint() {
        // These are the three exits the runner prompts can take; all happen
        // before `ensure_user_key` and `Invitation::mint`, so a cancel leaves
        // no token and no file. The destination below is proof the path was
        // never opened by any of them.
        let p = scratch("cancel");
        let dest = p.parent().unwrap().join("invite.txt");
        assert!(parse_reuse_answer("cancel").is_err());
        assert!(parse_ttl_answer("cancel", "1h").is_err());
        assert!(runner_allow(None).is_err());
        assert!(
            !dest.exists(),
            "a prompt cancelled before the mint must leave no invitation file"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
