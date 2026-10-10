//! Creating an identity, joining, and the certificate and principal state behind them.
//!
//! `init_experience` walks a new device through minting its identity and showing the
//! recovery phrase, `confirm_recovery_phrase` is the check inside that flow,
//! `join_cmd` claims a code, `local_device_cert` and `principal_from_records` read
//! the resulting local state, and `open_enrollment` is the fleet side of joining.
//!
//! Six scattered blocks. One member is definition-gated, `offer_l3_grant`, and its
//! only caller is the `#[cfg(l3)]` statement inside init_experience, which travels
//! with the body; and
//! dispatch.rs imports init_experience unconditionally. The only gate is on the `l3`
//! module import, because anyhow::{ Result, bail };
use crate::UiCapability;
use crate::capability_list_summary;
use crate::certify_local_device;
use crate::config_set;
use crate::conn::Conn;
use crate::default_drop_dir;
use crate::device_view::device_cert_for;
use crate::devices_store::devices_path;
use crate::display_name;
use crate::enrollment::enroll_cmd;
use crate::fleet_support::ensure_self_genesis_header;
use crate::fmt_short_duration;
use crate::format_approval_expiry;
use crate::identity;
#[cfg(l3)]
use crate::l3;
use crate::local_device_cert_path;
use crate::net::Transport;
use crate::parse_invitation;
use crate::prompt_line;
use crate::read_owner_only_fd;
use crate::read_owner_only_file;
use crate::settings;
use crate::ui;
use crate::up_logs::up_cmd;
use crate::write_owner_only_fd;
use crate::write_owner_only_file;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Resolve the persisted principal record for a device cert. Returns
/// `(kind, not_after, max_offline, last_seen)`. A missing or malformed record
/// FAILS CLOSED as a ceiling-less delegated principal (denies everything), so
/// a half-persisted record can never silently become an owner.
pub(crate) fn principal_from_records(
    records: &[Value],
    cert: &identity::DeviceCert,
    own_user_pub: Option<&[u8; 32]>,
) -> (
    crate::capability::PrincipalKind,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    let record = records.iter().find(|record| {
        identity::DeviceCert::from_json(&record["deviceCert"])
            .map(|stored| stored.device_pub == cert.device_pub)
            .unwrap_or(false)
    });
    if let Some(record) = record {
        if record["principalKind"].is_null() {
            return (
                crate::capability::PrincipalKind::OwnerDevice,
                None,
                None,
                None,
            );
        }
        if record["principalKind"].as_str() == Some("delegated") {
            let caps = record["principalCeiling"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let expires = record["principalExpires"].as_u64().unwrap_or(0);
            let max_offline = record["principalMaxOffline"].as_u64();
            let last_seen = record["lastSeen"].as_u64();
            return (
                crate::capability::PrincipalKind::Delegated { caps },
                Some(expires),
                max_offline,
                last_seen,
            );
        }
        return (
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    let is_same_owner = own_user_pub
        .map(|owner| *owner == cert.user_pub)
        .unwrap_or(false);
    if is_same_owner {
        return (
            crate::capability::PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    (
        crate::capability::PrincipalKind::OwnerDevice,
        None,
        None,
        None,
    )
}

pub(crate) fn local_device_cert() -> Option<identity::DeviceCert> {
    if let (Ok(raw), Ok(overlay_pub)) = (
        std::fs::read_to_string(local_device_cert_path()),
        crate::overlay::overlay_pubkey_bytes(),
    ) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            if let Some(cert) = identity::DeviceCert::from_json(&value["cert"]) {
                if cert.device_pub == overlay_pub && cert.verify(identity::now_secs()).is_ok() {
                    return Some(cert);
                }
            }
        }
    }
    // Try display name first
    if let Some(cert) = device_cert_for(&display_name()) {
        if cert.verify(identity::now_secs()).is_ok() {
            return Some(cert);
        }
    }
    // Fallback: find any cert whose device_pub matches overlay key
    if let Ok(overlay_pub) = crate::overlay::overlay_pubkey_bytes() {
        let p = devices_path();
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) {
                for d in arr {
                    if let Some(cert) = identity::DeviceCert::from_json(&d["deviceCert"]) {
                        if cert.device_pub == overlay_pub
                            && cert.verify(identity::now_secs()).is_ok()
                        {
                            return Some(cert);
                        }
                    }
                }
            }
        }
    }
    // Final fallback: MINT the self-cert on demand from the user key + overlay key.
    // `identity init` creates the user key but no stored self device-cert, so without
    // this local_device_cert() is None, pairing never runs identity-expose (it is gated
    // on this fn), the peer stays secret-only (binding Inferred), and under authoritative
    // the #21 proven-gate denies EVERY peer. Minting here (deterministic in user_pub and
    // device_pub; only the timestamps vary) makes the Proven-binding path reachable for
    // freshly-onboarded and already-onboarded identities alike, without a peer-store entry.
    if let (Ok(Some(uk)), Ok(overlay_pub)) = (
        identity::UserKey::load(&crate::platform::PlatformKeyStore),
        crate::overlay::overlay_pubkey_bytes(),
    ) {
        if let Ok(cert) = identity::DeviceCert::certify(
            &uk,
            overlay_pub,
            identity::now_secs(),
            identity::CERT_TTL_SECS,
        ) {
            return Some(cert);
        }
    }
    None
}

/// Restores the pre-U1 precondition for scripts that want to fail fast: with
/// this set (any value but empty or `0`), a verb that needs an identity bails
/// with the old "run `tunlion init` first" instead of minting one.
pub(crate) const NO_IMPLICIT_INIT_ENV: &str = "FILAMENT_NO_IMPLICIT_INIT";

/// Whether the opt-out above is set (any value except empty and `0`).
///
/// The INSPECT surfaces read this instead of calling the accessor and letting
/// it fail. `tunlion id` and the bare tour screen answered pre-U1 without an
/// identity and exited 0; if the opt-out turned either into an error, U1 would
/// have taken a working read-only answer away from exactly the scripts that
/// asked for the old behaviour, which is the opposite of what an opt-out is
/// for.
pub(crate) fn implicit_init_disabled() -> bool {
    std::env::var_os(NO_IMPLICIT_INIT_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// What every read-only command says on a device with no identity. The two
/// commands named are the only two ways to get one deliberately; `init` makes
/// this device the owner, `join` makes it a member of someone else's mesh.
pub(crate) const NO_IDENTITY_MSG: &str =
    "no identity yet; run `tunlion init` or `tunlion join <invitation>`";

/// Does this device have an identity: an owner key, or a joined certificate?
/// Reads only. `join` refuses a device for which this is true, which is why
/// nothing that merely LOOKS at the identity may make it true.
pub(crate) fn has_identity() -> bool {
    identity::UserKey::load(&crate::platform::PlatformKeyStore)
        .ok()
        .flatten()
        .is_some()
        || local_device_cert_path().exists()
}

/// The read-only answer on a device with no identity: say so, mint nothing,
/// and fail with `ExitKind::NoIdentity` (exit 9). Under `--json` the answer is
/// the failure envelope with `"identity": null` (and `"configured": false`,
/// the field `id --json` has always carried) on stdout.
pub(crate) fn no_identity(json: bool) -> anyhow::Error {
    use crate::exit_codes::{ExitKind, json_error, reported};
    if json {
        let mut v = json_error(ExitKind::NoIdentity, NO_IDENTITY_MSG, None);
        v["identity"] = Value::Null;
        v["configured"] = json!(false);
        ui::json_out(&v);
    } else {
        ui::critical(NO_IDENTITY_MSG);
    }
    reported(ExitKind::NoIdentity)
}

/// The identity, minted on first use (U1). A keypair is not a ceremony: the
/// bails that read "no identity. Run `tunlion init` first" route through here
/// and proceed instead. Prints one past-tense line the ONE time the key is
/// created, to stderr via `ui::say`, and nothing under `--json` (the envelope
/// that could carry it as a data field is audit ticket 1; until then a prose
/// line on a `--json` run is the defect `docs/agent-output-audit.md` names).
///
/// WHERE IT IS CALLED, and the rule behind the list: a verb mints only when it
/// needs the key to do the job it was asked to do. `add --for` and both `grant`
/// paths sign with it. `id` used to mint too, on the theory that the identity
/// is its whole subject; that made `tunlion id` on a fresh machine create a key
/// and then `tunlion join` refuse the machine for having one. A command that
/// only looks never mints: `id` answers `no_identity` (exit 9) instead.
/// The bare tour screen (`status_cmd::tour_cmd`) does NOT call this and must
/// not: it is an inspect screen that renders whatever state it finds, so
/// minting there would make `tunlion` with no arguments write a private key
/// as a side effect of being looked at, and would make the screen FAIL on the
/// two devices that cannot mint (a joined one, and one with the opt-out set).
///
/// What it deliberately does NOT do, because those ARE ceremonies and
/// `tunlion init` still owns them: name the device, choose the inbox, write
/// a stored device cert, install the service, or touch anything outside the
/// config dir. `local_device_cert()` mints the self-cert on demand, so an
/// implicit identity pairs the same as an `init`ed one.
pub(crate) fn ensure_user_key(json: bool) -> Result<identity::UserKey> {
    let (key, created) = ensure_user_key_inner()?;
    if created && !json {
        ui::say(&format!(
            "  created your identity at {}  (tunlion id to see it)",
            settings::config_dir().display()
        ));
    }
    Ok(key)
}

/// `(key, created)`: the bool is what the tests count. Two concurrent first
/// commands must yield ONE identity, so creation happens under an exclusive
/// lock on a sidecar in the config dir (the key file itself is written by
/// temp + rename, so a lock on its inode would be replaced out from under a
/// holder; same reasoning as `DevicesFileLock`), and the load is repeated
/// under the lock. The seed is written by `SecretFile` (0600, atomic).
pub(crate) fn ensure_user_key_inner() -> Result<(identity::UserKey, bool)> {
    let store = crate::platform::PlatformKeyStore;
    if let Some(key) = identity::UserKey::load(&store)? {
        return Ok((key, false));
    }
    // A joined device holds a certificate from another owner and, by design,
    // no owner signing key. Minting one here would turn it into a second
    // owner behind the user's back; `join` refuses a device that has a key
    // for the same reason from the other side.
    if local_device_cert_path().exists() {
        bail!(
            "this is a joined device: it holds no owner signing key, so it cannot sign this. \
             Run the command on the owner's machine."
        );
    }
    if implicit_init_disabled() {
        bail!("no identity. Run `tunlion init` first");
    }
    let dir = settings::config_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create config dir {}", dir.display()))?;
        crate::platform::tighten_new_dir(&dir);
    }
    let _lock = crate::platform::DevicesFileLock::acquire_at(&dir.join("identity.lock"))?;
    if let Some(key) = identity::UserKey::load(&store)? {
        return Ok((key, false));
    }
    // Recoverable form (seed + phrase), not a bare pkcs8: the phrase is not
    // shown now (nothing worth recovering yet) but must exist for the first
    // verb that creates something worth losing to show it.
    let key = identity::PendingIdentity::generate()?.commit(&store)?;
    Ok((key, true))
}

fn confirm_recovery_phrase(words: &[&str], phrase: &str) -> Result<()> {
    use crossterm::{execute, terminal};
    let mut err = std::io::stderr();
    execute!(
        err,
        terminal::EnterAlternateScreen,
        terminal::Clear(terminal::ClearType::All)
    )?;
    let result = (|| -> Result<()> {
        eprintln!(
            "{}",
            ui::paint(ui::Tone::Brand, "  TUNLION / YOUR WAY BACK")
        );
        eprintln!();
        eprintln!("  Anyone with these words can become you.");
        eprintln!("  Write them somewhere offline. Tunlion cannot reset them.");
        eprintln!();
        for (row, chunk) in words.chunks(4).enumerate() {
            let cells = chunk
                .iter()
                .enumerate()
                .map(|(column, word)| format!("{:>2}  {:<10}", row * 4 + column + 1, word))
                .collect::<Vec<_>>()
                .join("   ");
            eprintln!("     {cells}");
        }
        eprintln!();
        let qr = prompt_line("  Enter to check your copy, or type QR for a scannable export: ")?;
        if qr.eq_ignore_ascii_case("qr") {
            eprintln!();
            eprintln!("  Anyone who captures this QR can become you.");
            eprintln!(
                "{}",
                ui::qr_or_text(&format!("{RECOVERY_QR_PREFIX}{phrase}"), 2)
            );
            let _ = prompt_line("  Press Enter after saving it somewhere you control: ")?;
        }
        // The quiz checks the copy the person WROTE DOWN. With all twelve
        // words still on screen it checked whether they could read, and a
        // first-time-user test answered it by reading. Wipe the screen (the
        // alternate screen, so the scrollback never held the words) first.
        execute!(
            err,
            terminal::Clear(terminal::ClearType::All),
            crossterm::cursor::MoveTo(0, 0)
        )?;
        ui::critical(&ui::paint(ui::Tone::Brand, "  TUNLION / CHECK YOUR COPY"));
        ui::critical("");
        ui::critical("  The words are off the screen. Answer from what you wrote down.");
        ui::critical("");
        let fourth = prompt_line("  Word 4:  ")?;
        if fourth != words[3] {
            bail!("word 4 did not match; identity was not created");
        }
        let eleventh = prompt_line("  Word 11: ")?;
        if eleventh != words[10] {
            bail!("word 11 did not match; identity was not created");
        }
        Ok(())
    })();
    let _ = execute!(err, terminal::LeaveAlternateScreen);
    result
}

pub(crate) async fn init_experience(
    caps: &UiCapability,
    server: &str,
    relay: bool,
    name: Option<String>,
    inbox: Option<PathBuf>,
    recovery_file: Option<PathBuf>,
    recovery_fd: Option<i32>,
    background: bool,
    no_background: bool,
) -> Result<()> {
    let store = crate::platform::PlatformKeyStore;
    if caps.json && background {
        bail!(
            "init --json cannot install a service without mixing service output; run `tunlion up --install` separately"
        );
    }
    if let Some(existing) = identity::UserKey::load(&store)? {
        bail!(
            "this device already has identity {}; see `tunlion id`",
            existing.fingerprint()
        );
    }
    // Non-interactive init names EVERYTHING it needs in one message, so a
    // script learns the full contract in one round trip instead of two
    // (--recovery-file, then --yes, then --name).
    if !caps.interactive {
        let mut missing: Vec<&str> = Vec::new();
        if recovery_file.is_none() && recovery_fd.is_none() {
            missing.push("--recovery-file <path> (or --recovery-fd <fd>)");
        }
        if !caps.yes {
            missing.push("--yes");
        }
        if name.is_none() {
            missing.push("--name <device>");
        }
        if !missing.is_empty() {
            // A usage error (exit 2): the command line is incomplete.
            return Err(crate::exit_codes::err(
                crate::exit_codes::ExitKind::Usage,
                format!("non-interactive init needs: {}", missing.join(", ")),
            ));
        }
    }

    let device_name = match name {
        Some(name) => name,
        None if caps.interactive => {
            let suggested = l3::hostname();
            let entered = prompt_line(&format!("  Name this device [{suggested}]: "))?;
            if entered.is_empty() {
                suggested
            } else {
                entered
            }
        }
        None => bail!("non-interactive init requires --name <device>"),
    };
    let inbox = inbox.unwrap_or_else(default_drop_dir);
    let pending = identity::PendingIdentity::generate()?;
    let phrase = Zeroizing::new(pending.mnemonic().to_string());
    let words = pending.mnemonic().words().collect::<Vec<_>>();

    if let Some(path) = recovery_file.as_deref() {
        write_owner_only_file(path, phrase.as_str())?;
    } else if let Some(fd) = recovery_fd {
        write_owner_only_fd(fd, phrase.as_str())?;
    } else {
        confirm_recovery_phrase(&words, phrase.as_str())?;
    }

    let user_key = pending.commit(&store)?;
    config_set("name", &device_name)?;
    config_set("dir", &inbox.display().to_string())?;
    crate::platform::create_inbox_dir(&inbox)?;
    certify_local_device(&user_key, &device_name)?;
    ensure_self_genesis_header(&crate::settings::config_dir(), &user_key);
    // The identity is saved: say so now, and say it is DONE. Everything after
    // this line is optional, and a first-time user dropped into a password
    // prompt with no word that setup had finished could not tell which part of
    // init had failed. Nothing below can undo what is printed here.
    if !caps.json {
        ui::say(&format!(
            "  {} identity created",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        ui::say(&format!(
            "  {} this device: {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            ui::paint(ui::Tone::Bold, &device_name)
        ));
        ui::say(&format!(
            "  {} inbox: {}",
            ui::paint(ui::Tone::Ok, ui::glyph_ok()),
            inbox.display()
        ));
        ui::say("");
        ui::say("  Least privilege by default");
        ui::say("  + paired devices may send into this inbox");
        ui::say("  - remote shell is off");
        ui::say("  - remote writing is off");
        ui::say("  - local ports are private");
        ui::say("");
        // critical, not say: the one line `-q` must not swallow.
        ui::critical(&format!(
            "  {} Setup complete.",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
        ui::say("");
    }
    // Do not offer what this machine cannot do. Asking "stay available in the
    // background?" and then answering yes with "--install is not supported on
    // this platform" is the contradiction a first-time user hit on a box with
    // no service manager. Detect first; where nothing can start tunlion at boot,
    // point at the thing that does work instead.
    let host_can_install = crate::platform::ServiceHost::detect().supports_install();
    let start_background = if no_background {
        false
    } else if background && !host_can_install {
        ui::say(&format!(
            "  {} {}",
            ui::paint(ui::Tone::Warn, "!"),
            background_hint(false)
        ));
        false
    } else if background {
        true
    } else if caps.interactive && host_can_install {
        // `-y` means "answer this prompt with its default", and the default is Y.
        // Without it `tunlion init --yes` BLOCKED on a real terminal: the
        // identity was written, then it sat on "Stay available in the
        // background? [Y/n]:" forever, because this arm never consulted
        // `caps.yes`. Every other confirmation goes through
        // `UiCapability::confirm`, which starts `if self.yes { return Ok(()); }`.
        // This one called `prompt_line` directly and so escaped that contract.
        //
        // Invisible to every non-TTY check: piped, redirected and scripted runs
        // all take the `else` branch and exit 0, so a build, a pipe and CI all
        // said the first-run command was fine while it hung in a terminal.
        //
        // The check belongs INSIDE the interactive arm, not ahead of it. A
        // non-TTY never saw this prompt, so there is no default for `-y` to
        // supply and its answer must stay no. Hoisting it out flipped
        // `init --yes` from a pipe to "install a service", which is how the
        // capability harness (two piped `init --yes` at setup) started hanging
        // on macOS and Windows.
        caps.yes
            || !prompt_line("  Stay available in the background? [Y/n]: ")?
                .eq_ignore_ascii_case("n")
    } else {
        false
    };
    if start_background {
        // No daemon flags are forwarded: the inbox was just written to the
        // config (`dir` above), which the service reads on every start, so a
        // later `tunlion set drop-dir` still applies to it.
        up_cmd(
            server,
            crate::up_logs::UpMode {
                install: true,
                ..Default::default()
            },
            &crate::up_logs::DaemonOpts::default(),
            Some(inbox.clone()),
            relay,
            false,
            None,
            None,
            None,
            false,
            false,
        )
        .await
        .context("install always-on receive service")?;
    }

    if caps.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "verb": "init",
                "identity": user_key.fingerprint(),
                "role": "owner",
                "device": device_name,
                "inbox": inbox,
                "recoveryExported": true,
                "background": start_background,
            }))?
        );
        return Ok(());
    }
    if start_background {
        ui::say(&format!(
            "  {} available in the background",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        ));
    } else {
        ui::say(&ui::paint(
            ui::Tone::Dim,
            &format!("  {}", background_hint(host_can_install)),
        ));
    }
    // L3 is default-on (`tun-addr` defaults to "auto"), and a non-root daemon
    // needs a one-time privilege grant to open the tunnel device. This used to
    // run `sudo setcap` right here, unprompted, so the first thing a new user
    // met after creating an identity was a password prompt they had not asked
    // for. It is optional (the overlay falls back to the userspace netstack,
    // which needs no privilege), so it is now a question, default No, asked
    // only at a terminal, and a No prints the one command to run later.
    #[cfg(l3)]
    offer_l3_grant(caps);
    Ok(())
}

/// How to keep receiving after this command exits. `--install` only where a
/// service manager exists to honour it; elsewhere `up --detach`, which works on
/// every platform but does not survive a reboot.
pub(crate) fn background_hint(can_install: bool) -> String {
    if can_install {
        "Stay available: tunlion up --install".to_string()
    } else {
        "No service manager here, so nothing restarts the receiver at boot. To keep receiving in the background: tunlion up --detach".to_string()
    }
}

/// The optional kernel-overlay grant, asked for rather than taken. See the call
/// site in `init_experience` for why.
#[cfg(l3)]
fn offer_l3_grant(caps: &UiCapability) {
    let l3_on = !settings::get_str("tun-addr", None)
        .unwrap_or_default()
        .is_empty();
    let userspace = settings::get_str("l3-mode", None).as_deref() == Some("userspace")
        || std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1");
    if !l3_on || userspace {
        return;
    }
    // None: nothing is missing (already granted, or a platform where no
    // one-time grant applies), so there is nothing to ask.
    let Some(later) = crate::tun::l3_grant_pending() else {
        return;
    };
    let accepted = caps.interactive
        && !caps.yes
        && prompt_line(L3_GRANT_QUESTION)
            .map(|a| l3_grant_answer_is_yes(&a))
            .unwrap_or(false);
    if accepted {
        crate::tun::ensure_net_admin_for_l3();
    } else {
        ui::say(&ui::paint(
            ui::Tone::Dim,
            &format!("  Virtual network interface: off for now. To turn it on later, run:  {later}"),
        ));
    }
}

/// The optional-grant question. Plain words: what it gives, what it costs.
pub(crate) const L3_GRANT_QUESTION: &str = "  Optional: let tunlion create a virtual network interface so devices get addresses like laptop.mesh. Needs your password once. [y/N]: ";

/// Default No: only an explicit yes grants anything.
pub(crate) fn l3_grant_answer_is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub(crate) async fn join_cmd(
    caps: &UiCapability,
    server: &str,
    relay: bool,
    invite_file: Option<PathBuf>,
    invite_fd: Option<i32>,
    name: Option<String>,
    to: Option<String>,
) -> Result<()> {
    if identity::UserKey::load(&crate::platform::PlatformKeyStore)?.is_some() {
        bail!("this device already has an identity; join starts from a clean Tunlion identity");
    }
    if local_device_cert_path().exists() {
        bail!("this device has already joined an identity; reset it before joining another");
    }
    let invitation = Zeroizing::new(if let Some(path) = invite_file.as_deref() {
        read_owner_only_file(path)?
    } else if let Some(fd) = invite_fd {
        read_owner_only_fd(fd)?
    } else if caps.interactive {
        use crossterm::{execute, terminal};
        let mut err = std::io::stderr();
        execute!(
            err,
            terminal::EnterAlternateScreen,
            terminal::Clear(terminal::ClearType::All)
        )?;
        eprintln!("  Paste the invitation. It is cleared from this terminal after reading.");
        let result = prompt_line("\n  invitation: ");
        let _ = execute!(err, terminal::LeaveAlternateScreen);
        result?
    } else {
        bail!(
            "non-interactive join requires a code (`join <code>`), --invite-file <path>, or --invite-fd <fd>"
        );
    });
    let inv = parse_invitation(invitation.as_str())?;
    if inv.expires <= identity::now_secs() {
        bail!("this invitation has expired");
    }
    let owner_name = to.or_else(|| Some(inv.owner_name.clone()));
    let name_given = name.is_some();
    let mut proposed_name = name.unwrap_or_else(l3::hostname);
    if caps.interactive {
        // #183.3: join is the other first-run path; let the joined device name
        // itself the way init does. The review below shows the chosen name,
        // which is the name the owner sees in the device list.
        if !name_given {
            let answer = prompt_line(&format!("  name this device [{}]: ", proposed_name))?;
            let trimmed = answer.trim();
            if !trimmed.is_empty() {
                proposed_name = trimmed.to_string();
            }
        }
        eprintln!();
        eprintln!("  {}", ui::paint(ui::Tone::Brand, "JOIN"));
        eprintln!("  as       {proposed_name}");
        eprintln!(
            "  owner    {}",
            owner_name.as_deref().unwrap_or("invitation issuer")
        );
        eprintln!("  ceiling  {}", capability_list_summary(&inv.caps));
        eprintln!(
            "  budget   {} (key allows up to {})",
            fmt_short_duration(inv.max_offline),
            fmt_short_duration(inv.max_offline)
        );
        // #183.2: a raw epoch on the one screen where a person decides whether
        // to accept a grant is illegible; the mint side already formats it.
        eprintln!("  expires  {}", format_approval_expiry(inv.expires));
        eprintln!(
            "  proof    the ceiling and budget are persisted and reloaded before reconnect authorization"
        );
        let confirmation = prompt_line("\n  Press Enter to join, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    enroll_cmd(
        server,
        inv,
        owner_name,
        relay,
        Some(&proposed_name),
        caps.json,
    )
    .await
}

/// Register a pending enrollment and send the request over a freshly-ready link.
///
/// Both enrollment commands opened their `ChannelReady` arm with exactly this,
/// and differed only in whether they printed a line afterwards. Two copies of a
/// ceremony step is how the two halves drift apart: one gets a fix, the other
/// keeps the bug, which this file has already recorded happening between `mount`
/// and `pty`.
pub(crate) async fn open_enrollment(
    conn: &mut Conn,
    pid: &str,
    t: &Arc<dyn Transport>,
    enroll_seed: [u8; 32],
    device_pub: [u8; 32],
    ak: &filament_cap::ephemeral::Invitation,
) {
    // SAME THREE STEPS the invitation path already performs (mark ready,
    // register pending, send the request), and now the same credential on the
    // wire. This branch used to send `auth_key` (an AuthKey JSON) and register
    // through `register_enrollment_legacy`, purely because `ephemeral mint`
    // wrote a different artifact than `add --for` did. The daemon carried a
    // reader for each. One credential means one of everything.
    conn.mark_ready(pid, t, true);
    crate::ephemeral::register_enrollment(pid.to_string(), enroll_seed, device_pub, ak.clone());
    let payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ak.to_payload())
    };
    let _ = t
        .send_control(&json!({
            "type": "identity-auth-key-enroll-request",
            "auth_key_v2": payload,
            "device_pub": hex::encode(device_pub),
        }))
        .await;
}

/// PROTOCOL LITERAL: frozen, do not rename. The prefix of the recovery QR
/// export; released builds printed QRs with exactly this text, and restore
/// must keep reading them for as long as anyone holds one.
pub(crate) const RECOVERY_QR_PREFIX: &str = "filament-recovery:v1:";

/// The recovery words inside whatever the user supplied: the bare 12 words,
/// or the full text of the recovery QR (`filament-recovery:v1:<words>`), which
/// is what a phone's QR scanner hands back.
pub(crate) fn recovery_words(input: &str) -> &str {
    let t = input.trim();
    t.strip_prefix(RECOVERY_QR_PREFIX).map(str::trim).unwrap_or(t)
}

#[cfg(test)]
mod recovery_qr_tests {
    use super::*;

    const WORDS: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bare_words_pass_through() {
        assert_eq!(recovery_words(WORDS), WORDS);
        assert_eq!(recovery_words(&format!("  {WORDS}\n")), WORDS);
    }

    #[test]
    fn the_qr_export_text_restores() {
        let qr = format!("{RECOVERY_QR_PREFIX}{WORDS}");
        assert_eq!(recovery_words(&qr), WORDS);
        assert_eq!(recovery_words(&format!("{qr}\n")), WORDS);
        // And the stripped words really restore (same identity as the bare
        // phrase; the golden value lives in filament-id).
        let dir = std::env::temp_dir().join(format!("recovery-qr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        struct Store(std::path::PathBuf);
        impl crate::identity::KeyStore for Store {
            fn write_secret(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
                std::fs::write(path, data)
            }
            fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
                std::fs::read(path)
            }
            fn config_path(&self, relative: &str) -> std::path::PathBuf {
                self.0.join(relative)
            }
        }
        let key = crate::identity::UserKey::restore(&Store(dir.clone()), recovery_words(&qr)).unwrap();
        assert_eq!(
            key.public_key_hex(),
            "2562276a8902accb0bff0b4f09bc8014bf10639be6734fb4c2ceda9594964205"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pinned by the SHA-256 of the original prefix
    /// (`printf '%s' 'filament-recovery:v1:' | sha256sum`).
    #[test]
    fn recovery_qr_prefix_is_frozen() {
        use sha2::{Digest, Sha256};
        let got: String = Sha256::digest(RECOVERY_QR_PREFIX.as_bytes())
            .as_slice()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, "bf1a055f157070e84038dd122108ee8f7c68d621bd4118125f40fa1632e0495c");
    }
}

#[cfg(test)]
mod first_run_tests {
    use super::*;
    use clap::Parser;

    /// Every `tunlion ...` command in `text` (placeholders like `<x>` filled
    /// with a token) must be accepted by clap: a hint that does not parse is a
    /// hint that fails the person who follows it.
    fn assert_commands_parse(text: &str) -> usize {
        let mut n = 0;
        for (i, _) in text.match_indices("tunlion ") {
            let cmd: String = text[i..]
                .split(['`', ';', ',', '(', ')'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let argv: Vec<String> = cmd
                .split_whitespace()
                .take_while(|t| *t != "&&")
                .map(|t| if t.starts_with('<') { "x".to_string() } else { t.to_string() })
                .collect();
            if argv.len() < 2 {
                continue;
            }
            crate::Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("hint `{cmd}` does not parse: {e}"));
            n += 1;
        }
        n
    }

    #[test]
    fn the_kernel_overlay_grant_is_a_question_whose_default_is_no() {
        assert!(L3_GRANT_QUESTION.contains("[y/N]"), "default No, visibly");
        assert!(L3_GRANT_QUESTION.contains("Optional"));
        assert!(L3_GRANT_QUESTION.contains("password once"));
        for yes in ["y", "Y", "yes", " YES "] {
            assert!(l3_grant_answer_is_yes(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "N", "sure", "yeah"] {
            assert!(!l3_grant_answer_is_yes(no), "{no:?} must not grant");
        }
    }

    /// The question replaced an unprompted `sudo setcap`. Guard the shape at
    /// the source: init's body asks before it calls the granting function,
    /// and the granting call sits behind the answer, never on its own.
    #[test]
    fn init_never_runs_the_grant_without_asking() {
        let src = include_str!("identity_flow.rs");
        let body = src
            .split_once("fn offer_l3_grant")
            .expect("offer_l3_grant must exist")
            .1;
        let body = body.split("\n}").next().unwrap_or(body);
        let ask = body.find("prompt_line(L3_GRANT_QUESTION)").expect("it asks");
        let grant = body.find("ensure_net_admin_for_l3").expect("it can grant");
        assert!(ask < grant, "the grant must come after the question");
        assert!(body.contains("!caps.yes"), "--yes takes the default, which is No");
        assert!(body.contains("caps.interactive"), "never asked without a terminal");
        let init = src.split_once("pub(crate) async fn init_experience").unwrap().1;
        let init = init.split("\n}").next().unwrap();
        assert!(!init.contains("ensure_net_admin_for_l3"), "init itself must not grant");
        assert!(init.contains("Setup complete"), "init always says it is done");
    }

    #[test]
    fn background_hints_offer_only_what_works_and_parse() {
        let yes = background_hint(true);
        let no = background_hint(false);
        assert!(yes.contains("tunlion up --install"));
        assert!(no.contains("tunlion up --detach"), "{no}");
        assert!(!no.contains("--install"), "never offer --install where it cannot work: {no}");
        assert_eq!(assert_commands_parse(&yes), 1);
        assert_eq!(assert_commands_parse(&no), 1);
        let note = crate::add_for::receiver_not_running_note(false);
        assert!(note.contains("tunlion up --detach") && !note.contains("--install"), "{note}");
        let note = crate::add_for::receiver_not_running_note(true);
        assert!(note.contains("tunlion up --install"), "{note}");
        assert_eq!(assert_commands_parse(&note), 1);
    }

    #[test]
    fn the_no_identity_answer_names_two_commands_that_parse() {
        assert!(NO_IDENTITY_MSG.starts_with("no identity yet"));
        assert_eq!(assert_commands_parse(NO_IDENTITY_MSG), 2);
    }

    /// The recovery quiz must not be answerable by reading the screen.
    #[test]
    fn the_recovery_quiz_clears_the_words_first() {
        let src = include_str!("identity_flow.rs");
        let body = src
            .split_once("fn confirm_recovery_phrase")
            .expect("confirm_recovery_phrase must exist")
            .1;
        let words_shown = body.find("for (row, chunk) in words.chunks(4)").expect("words are shown");
        let cleared = body[words_shown..]
            .find("terminal::Clear(terminal::ClearType::All)")
            .map(|i| i + words_shown)
            .expect("the screen is cleared after the words are shown");
        let quiz = body.find("prompt_line(\"  Word 4:").expect("the quiz asks for word 4");
        assert!(words_shown < cleared && cleared < quiz, "clear between showing and asking");
    }

    /// `id` only looks. It used to mint, and `join` then refused the machine.
    #[test]
    fn id_never_mints_an_identity() {
        let src = include_str!("dispatch.rs");
        let arm = src
            .split_once("Cmd::Id { action }")
            .expect("the id arm must exist")
            .1;
        let arm = arm.split("\n        Cmd::").next().unwrap_or(arm);
        assert!(!arm.contains("ensure_user_key"), "`tunlion id` must not create an identity");
        assert!(arm.contains("no_identity("), "`tunlion id` answers no_identity instead");
    }
}
