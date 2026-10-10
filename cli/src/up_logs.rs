//! `tunlion up` / `tunlion logs`, lifted out of `main.rs`.
//!
//! `up_cmd` installs and starts the receiver (including the service-manager and
//! shell-policy paths, and the already-running case that follows the daemon's
//! log), and `logs_cmd` tails that log. Both spawn; `up_cmd` also carries one
//! in-body `#[cfg(target_os = "windows")]` and `logs_cmd` a function-local
//! `use tokio::io::{AsyncBufReadExt, AsyncSeekExt}` plus its own
//! `macro_rules! detached`, all of which travel with the bodies.
//!
//! Everything else here is imported from the crate root and stays where it was:
//! `daemon_alive` (fourteen call sites in thirteen functions), `recv_cmd`,
//! `detach_up`, the pidfile helpers and the shell-policy helpers. No item is
//! promoted for this move -- a private crate-root item is already visible to a
//! descendant module like this one.
use crate::{
    ServiceManager, ShellPolicy, daemon_alive, detach_up, direct, dlog, drop_dir,
    install_system_service, pidfile, platform, recv_cmd, require_shell_owner_ack,
    service_manager_for_pid, settings, shell_grant_names, shell_root_note, sshkeys, subnet_forward,
    ui, write_pidfile,
};
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

/// Every `up` option that changes what the DAEMON does, as the user typed it.
///
/// `up --install`, `up --install --system`, `up --detach` and the elevated
/// re-run all start a SECOND process, and that process only knows what is in
/// its argv. Each path used to build that argv by hand from whichever flags its
/// author thought of: `--install` carried the shell posture and nothing else,
/// `--detach` carried `--server`/`--dir` and nothing else. `up --install
/// --userspace --no-relay` installed a service that used the kernel overlay
/// and the relay, with no message. Now there is one list, built here, and
/// `up_flags_round_trip_through_the_daemon_argv` fails the build when an `up`
/// flag is neither forwarded nor named as launch-only.
///
/// Values are the RAW flags, not flags merged with settings: the daemon reads
/// the settings itself on every start, so baking `set shell on` into a unit
/// would make a later `set shell off` silently not apply to the service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DaemonOpts {
    /// `--server` (or FILAMENT_SERVER) when it is not the default. A service
    /// does not inherit this shell's environment, so an env value is forwarded
    /// as a flag.
    pub(crate) server: Option<String>,
    pub(crate) relay: bool,
    pub(crate) no_relay: bool,
    pub(crate) name_as: Option<String>,
    pub(crate) dir: Option<PathBuf>,
    pub(crate) userspace: bool,
    pub(crate) shell: bool,
    pub(crate) shell_only: Option<String>,
    pub(crate) shell_program: Option<String>,
    pub(crate) shell_user: Option<String>,
    pub(crate) i_know: bool,
    pub(crate) no_proxy_fallback: bool,
}

impl DaemonOpts {
    /// The daemon options of a parsed `up` invocation; `None` for any other
    /// command.
    pub(crate) fn from_cli(cli: &crate::Cli) -> Option<DaemonOpts> {
        let Some(crate::Cmd::Up {
            install: _,
            detach: _,
            system: _,
            install_system: _,
            userspace,
            dir,
            shell,
            shell_only,
            shell_program,
            shell_user,
            i_know,
            no_proxy_fallback,
        }) = &cli.cmd
        else {
            return None;
        };
        Some(DaemonOpts {
            server: (cli.server != crate::DEFAULT_SERVER).then(|| cli.server.clone()),
            relay: cli.relay,
            no_relay: cli.no_relay,
            name_as: cli.name_as.clone(),
            dir: dir.clone(),
            userspace: *userspace,
            shell: *shell,
            shell_only: shell_only.clone(),
            shell_program: shell_program.clone(),
            shell_user: shell_user.clone(),
            i_know: *i_know,
            no_proxy_fallback: *no_proxy_fallback,
        })
    }

    /// The argv (without the program) that starts a daemon with these
    /// options: `["up", "--flag", "--key=value", ...]`. Values use the
    /// `--key=value` form so one that starts with `-` cannot be read as a flag.
    pub(crate) fn daemon_argv(&self) -> Vec<String> {
        let mut a: Vec<String> = vec!["up".into()];
        let val = |a: &mut Vec<String>, k: &str, v: &Option<String>| {
            if let Some(v) = v {
                a.push(format!("--{k}={v}"));
            }
        };
        val(&mut a, "server", &self.server);
        if self.relay {
            a.push("--relay".into());
        }
        if self.no_relay {
            a.push("--no-relay".into());
        }
        val(&mut a, "name-as", &self.name_as);
        let dir = self.dir.as_ref().map(|d| d.to_string_lossy().into_owned());
        val(&mut a, "dir", &dir);
        if self.userspace {
            a.push("--userspace".into());
        }
        if self.shell {
            a.push("--shell".into());
        }
        val(&mut a, "shell-only", &self.shell_only);
        val(&mut a, "shell-program", &self.shell_program);
        val(&mut a, "shell-user", &self.shell_user);
        if self.i_know {
            a.push("--i-know".into());
        }
        if self.no_proxy_fallback {
            a.push("--no-proxy-fallback".into());
        }
        a
    }
}

/// How `up` was asked to run, as opposed to what the daemon does.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UpMode {
    pub(crate) install: bool,
    pub(crate) system: bool,
    pub(crate) detach: bool,
    /// Internal: this process IS the elevated re-run; install and exit.
    pub(crate) install_system: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn up_cmd(
    server: &str,
    mode: UpMode,
    daemon: &DaemonOpts,
    dir: Option<PathBuf>,
    relay: bool,
    shell: bool,
    shell_only: Option<String>,
    shell_program: Option<String>,
    shell_user: Option<String>,
    i_know: bool,
    no_proxy_fallback: bool,
) -> Result<()> {
    let UpMode {
        install,
        system,
        detach,
        install_system: install_system_flag,
    } = mode;
    let daemon_argv = daemon.daemon_argv();
    let shell_enabled = shell || shell_only.is_some();
    let shell_config = settings::get_str("shell-program", None);
    let can_use_user =
        platform::Paths::shell_argv(None, shell_config.as_deref(), shell_user.as_deref()).1;
    require_shell_owner_ack(shell_enabled, shell_user.as_deref(), can_use_user, i_know)?;
    // Internal: re-invoked after elevation (macOS's administrator prompt). Do
    // the system-level install directly and return. This process was started
    // with the same daemon flags, so its own argv is the one to install.
    if install_system_flag {
        let host = platform::ServiceHost::detect();
        let exe = std::env::current_exe()?;
        host.install_system(&exe, &daemon_argv)?;
        return Ok(());
    }
    // --shell-program -- persist it so the daemon picks it up (shell_argv reads
    // this from config). The env var FILAMENT_SHELL is also checked independently.
    if let Some(ref prog) = shell_program {
        settings::set("shell-program", prog, None).ok();
    }
    let shell_policy = match &shell_only {
        Some(csv) => ShellPolicy::Only(
            csv.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ),
        None if shell => ShellPolicy::All,
        None => ShellPolicy::Granted,
    };
    // --shell-user is Unix-only (uses runuser). Warn early on Windows.
    if shell_user.is_some() && cfg!(windows) {
        ui::say(&format!(
            "  {} --shell-user is not supported on Windows.\n\
             \n\
             Windows requires CreateProcessAsUser or CreateProcessWithLogonW to run\n\
             a process as another user. CreateProcessAsUser needs SE_INCREASE_QUOTA_NAME\n\
             and SE_ASSIGNPRIMARYTOKEN_NAME privileges (typically requires admin).\n\
             CreateProcessWithLogonW needs the target user's credentials (username +\n\
             password), which is a security risk if stored or passed via CLI.\n\
             \n\
             The PTY will run as the current user. To run as a different user,\n\
             start tunlion from that user's session, or use 'runas /user:<name> tunlion'.",
            ui::paint(ui::Tone::Warn, "WARNING:")
        ));
    }
    if install && system {
        return install_system_service(&daemon_argv);
    }
    if install {
        // `--install` is the USER service, everywhere, and only that. It used
        // to try a root system service first whenever elevation worked (and on
        // Linux that unit had no `User=`), so the help's "user service" was
        // true only on machines where asking for root failed. A system service
        // is `--install --system`, an explicit request.
        let host = platform::ServiceHost::detect();
        if !host.supports_install() {
            let hint = host.install_instructions();
            anyhow::bail!("--install is not supported on this platform. {hint}");
        }
        let exe = std::env::current_exe()?;
        // An Err here names the step that failed and the command to finish by
        // hand; nothing below claims success unless this returned Ok.
        host.install_user(&exe, &daemon_argv)?;
        // #173: on Windows the background receiver is per-user (HKCU Run, no
        // elevation), matching systemd --user and the LaunchAgent.
        if cfg!(windows) {
            // #182: HKCU Run only fires at logon. The user asked for the
            // inbox NOW (the other platforms' service managers do `enable
            // --now` / bootstrap). Start the receiver now, detached, and
            // confirm it is live before printing. The detach is the SAME
            // portable operation as `up --detach` (platform::spawn_detached),
            // so the receiver's console lands in daemon.log.
            let log_path = crate::platform::Paths::config_path("daemon.log");
            let args: Vec<&str> = daemon_argv.iter().map(String::as_str).collect();
            let started = match crate::platform::spawn_detached(&exe, &args, &log_path) {
                Ok(_) => {
                    // Give the receiver a moment to write its pidfile.
                    let mut live = false;
                    for _ in 0..40 {
                        if daemon_alive().is_some() {
                            live = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                    live
                }
                Err(_) => false,
            };
            if started {
                ui::say(&format!(
                    "  {} receiving now, and at every logon",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok())
                ));
            } else {
                ui::say(&format!(
                    "  {} autostart installed; starting the receiver now failed, run `tunlion up`",
                    ui::paint(ui::Tone::Warn, "!")
                ));
            }
        } else {
            ui::say(&format!(
                "  {} installed as a user service (starts at login)",
                ui::paint(ui::Tone::Ok, ui::glyph_ok())
            ));
            if host == platform::ServiceHost::Systemd {
                ui::say(&format!(
                    "  {} for a machine-wide service (starts at boot, CAP_NET_ADMIN from systemd): \
                     tunlion up --install --system",
                    ui::paint(ui::Tone::Dim, "note:")
                ));
            }
        }
        #[cfg(target_os = "windows")]
        platform::add_firewall_rule(&exe);
        return Ok(());
    }
    if let Some(pid) = daemon_alive() {
        dlog!(
            "[up] already-up: pidfile={:?} pid={pid} cmdline={:?}",
            pidfile(),
            std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default()
        );
        // Asked of the RUNNING daemon (like `revoke`'s #244 check): its shell
        // posture comes from launch flags that never touch the settings file,
        // so only the daemon can say what it is serving.
        let running = crate::ctl::try_cap_status().await;
        let verdict = already_up_verdict(
            &shell_policy,
            running.as_ref(),
            // Only flags that can come from the command line alone: relay and
            // shell-user also fold in from settings, which the running daemon
            // read too, so counting them would refuse every second `up`.
            dir.is_some() || no_proxy_fallback,
        );
        if verdict != AlreadyUp::Same {
            // Never follow the log here: that blocked forever and silently
            // dropped the flags, so `up --detach --shell` looked like it worked
            // while the daemon went on serving no shell.
            // The restart carries EVERY daemon flag this `up` was given (the
            // same argv `--detach` hands its child), not a hand-picked subset.
            let mut restart_flags = vec!["--detach".to_string()];
            restart_flags.extend(daemon_argv.iter().skip(1).cloned());
            let restart = restart_command(&restart_flags);
            let detail = match (&verdict, running.as_ref()) {
                (AlreadyUp::Differs, Some(st)) => format!(
                    "it is serving shells to {}, and this `up` asked for {}. Your flags were NOT applied.",
                    describe_running(st),
                    describe_policy(&shell_policy)
                ),
                _ => "it did not report its settings, so the flags you gave may not be in effect. Your flags were NOT applied.".to_string(),
            };
            ui::problem(
                &format!("a daemon is already running (pid {pid}) with different settings"),
                &detail,
                &[format!("to apply them, restart it:  {restart}")],
            );
            std::process::exit(ALREADY_UP_DIFFERENT_EXIT);
        }
        if detach {
            // --detach never blocks: the daemon already serves exactly this.
            ui::say(&format!(
                "  {} daemon already running (pid {pid}) with these settings; nothing to do",
                ui::paint(ui::Tone::Ok, ui::glyph_ok())
            ));
            return Ok(());
        }
        // #192: `up` twice should not dead-end. The daemon is already serving;
        // follow its log. Ctrl-c detaches and leaves it running.
        ui::say(&format!(
            "  daemon already running (pid {pid}); following its log (ctrl-c to detach)"
        ));
        return logs_cmd(true, 20).await;
    }
    if detach {
        // --detach: spawn the daemon in the background, redirect its console to
        // {config}/daemon.log, return to the shell. The child writes the pidfile
        // and serves detached (survives closing this terminal).
        return detach_up(&daemon_argv).await;
    }
    let dir = drop_dir(dir);
    std::fs::create_dir_all(&dir)?;
    write_pidfile()?;
    let granted_names = shell_grant_names();
    match &shell_policy {
        // M-2: --shell intentionally grants ALL proof-verified paired devices
        // (current AND any introduced later via pair-intro). This is a broad,
        // deliberate over-grant; --shell-only is the scoped, safer alternative.
        ShellPolicy::All => ui::say(&format!(
            "  {} seamless shell ON, ANY paired device (now or paired later) can `tunlion shell --ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
        )),
        ShellPolicy::Only(set) => {
            let mut names: Vec<&String> = set.iter().collect();
            names.sort();
            let list = names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            ui::say(&format!(
                "  {} seamless shell ON for: {list}, they can `tunlion shell --ssh` into this machine",
                ui::paint(ui::Tone::Warn, "!"),
            ));
        }
        ShellPolicy::Granted if !granted_names.is_empty() => ui::say(&format!(
            "  {} seamless shell ON for: {}, they can `tunlion shell --ssh` into this machine",
            ui::paint(ui::Tone::Warn, "!"),
            granted_names.join(", "),
        )),
        ShellPolicy::Granted => {}
    }
    // Shell without a dropped account is owner-equivalent at any uid. A dropped
    // account is only safer if it cannot read FILAMENT_CONFIG_DIR.
    if shell_policy.enables_l2() {
        let warning = match shell_user.as_deref() {
            Some(user) if can_use_user => {
                format!(
                    "  note: shell PTYs run as {user}; verify this account cannot read FILAMENT_CONFIG_DIR or the drop is cosmetic"
                )
            }
            Some(user) => {
                format!(
                    "  {} --shell-user {user} is unsupported on this platform; the PTY runs as this process's user and has the owner's authority.",
                    ui::paint(ui::Tone::Warn, "!")
                )
            }
            None => {
                format!(
                    "  {} serving shell without --shell-user grants the peer the owner's authority because the PTY runs as this process's user and can read the config directory.{}",
                    ui::paint(ui::Tone::Warn, "!"),
                    shell_root_note()
                )
            }
        };
        ui::say(&warning);
    }
    // Pre-resolve our public IP off the critical path so the FIRST incoming
    // connect answers the transport-offer without an inline `/api/whoami` round
    // trip (the acceptor's gather is what the initiator waits on during
    // establishing). Best-effort, backgrounded so it never delays daemon start.
    {
        let server = server.to_string();
        tokio::spawn(async move {
            direct::warm_public_ip(&server).await;
        });
    }
    // Startup shell-key reconciliation. GATED on authoritative: in shadow the cap
    // layer gates NOTHING, so only REPORT what would be removed (it becomes part of
    // the pre-flip sample). Never delete a working key while the cap store is not
    // yet the authority, else the first `grant` on any node wipes every device that
    // has no cap grant yet.
    {
        let config_dir = crate::settings::config_dir();
        let authoritative = crate::capability::cap_authoritative();
        let revoked = crate::capability::devices_with_shell_revoked(&config_dir);
        let ak_path = sshkeys::authorized_keys_path();
        let ak_content = std::fs::read_to_string(&ak_path).unwrap_or_default();
        // Emit per-device shadow logs for the WOULD-remove devices that
        // actually have a block (avoid noise for devices without one).
        for device in &revoked {
            if sshkeys::has_block(&ak_content, device) && !authoritative {
                ui::critical(&format!(
                    "CAP-SHADOW RECONCILE (startup): WOULD remove shell key for '{device}' (cap store denies shell); NOT removing in shadow"
                ));
            }
        }
        let new_ak = crate::capability::reconcile_shell_keys(&revoked, &ak_content, authoritative);
        if new_ak != ak_content {
            if let Err(e) = crate::platform::SecretFile::write_str(&ak_path, &new_ak) {
                eprintln!("shell-key reconcile (startup): failed to write authorized_keys: {e}");
            }
        }
    }
    let res = recv_cmd(
        server,
        None,
        dir,
        false,
        None,
        None,
        true,
        relay,
        None,
        true,
        None,
        shell_policy,
        shell_user,
        no_proxy_fallback,
    )
    .await;
    let _ = std::fs::remove_file(pidfile());
    res
}

/// Exit status when `up` finds a daemon already running with settings other
/// than the ones asked for: distinct from a plain failure (1) so a script can
/// tell "nothing changed, restart to apply" apart from "up broke".
pub(crate) const ALREADY_UP_DIFFERENT_EXIT: i32 = 3;

/// What `up` should do about a daemon that is already running.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AlreadyUp {
    /// It already serves what was asked: nothing to apply.
    Same,
    /// It reported a different shell posture.
    Differs,
    /// It did not report, and flags it cannot confirm were given.
    Unknown,
}

/// Compare the asked-for posture with what the running daemon reports via
/// `cap-status` (`shell_policy` label + `shell_auto` names). `other_flags`:
/// flags given that the daemon cannot report back (`--dir`,
/// `--no-proxy-fallback`); those cannot be confirmed, so they count as a change.
pub(crate) fn already_up_verdict(
    asked: &ShellPolicy,
    running: Option<&serde_json::Value>,
    other_flags: bool,
) -> AlreadyUp {
    let Some(st) = running else {
        return if asked.enables_l2() || other_flags {
            AlreadyUp::Unknown
        } else {
            AlreadyUp::Same
        };
    };
    let label = st["shell_policy"].as_str().unwrap_or("");
    let mut auto: Vec<String> = st["shell_auto"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    auto.sort();
    if label != asked.label() || (label == "only" && auto != asked.auto_names()) {
        return AlreadyUp::Differs;
    }
    if other_flags {
        AlreadyUp::Unknown
    } else {
        AlreadyUp::Same
    }
}

fn describe_policy(p: &ShellPolicy) -> String {
    match p {
        ShellPolicy::All => "every paired device (--shell)".to_string(),
        ShellPolicy::Only(_) => format!("only {} (--shell-only)", p.auto_names().join(", ")),
        ShellPolicy::Granted => "only devices you granted shell (no --shell)".to_string(),
    }
}

fn describe_running(st: &serde_json::Value) -> String {
    match st["shell_policy"].as_str().unwrap_or("") {
        "all" => "every paired device (--shell)".to_string(),
        "only" => format!(
            "only {} (--shell-only)",
            st["shell_auto"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default()
        ),
        _ => "only devices you granted shell (no --shell)".to_string(),
    }
}

/// `tunlion down --yes && tunlion up <flags>`, quoting any flag value that
/// needs it. The `up` half is pinned by a parse test.
pub(crate) fn restart_command(up_flags: &[String]) -> String {
    let words: Vec<String> = up_flags
        .iter()
        .map(|f| {
            if f.chars().any(|c| c.is_whitespace()) {
                format!("'{f}'")
            } else {
                f.clone()
            }
        })
        .collect();
    format!("tunlion down --yes && tunlion up {}", words.join(" "))
}

#[cfg(test)]
mod already_up_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_different_posture_is_reported_not_followed() {
        let running = json!({"shell_policy": "granted", "shell_auto": []});
        assert_eq!(
            already_up_verdict(&ShellPolicy::All, Some(&running), false),
            AlreadyUp::Differs
        );
        assert_eq!(
            already_up_verdict(&ShellPolicy::Granted, Some(&running), false),
            AlreadyUp::Same
        );
        let only = json!({"shell_policy": "only", "shell_auto": ["b", "a"]});
        let asked = ShellPolicy::Only(["a".to_string(), "b".to_string()].into_iter().collect());
        assert_eq!(already_up_verdict(&asked, Some(&only), false), AlreadyUp::Same);
        let other = ShellPolicy::Only(["a".to_string()].into_iter().collect());
        assert_eq!(already_up_verdict(&other, Some(&only), false), AlreadyUp::Differs);
    }

    #[test]
    fn unconfirmable_flags_are_never_silently_dropped() {
        let running = json!({"shell_policy": "granted", "shell_auto": []});
        assert_eq!(
            already_up_verdict(&ShellPolicy::Granted, Some(&running), true),
            AlreadyUp::Unknown
        );
        assert_eq!(already_up_verdict(&ShellPolicy::All, None, false), AlreadyUp::Unknown);
        assert_eq!(already_up_verdict(&ShellPolicy::Granted, None, false), AlreadyUp::Same);
    }

    /// Both halves of the suggested restart are commands the CLI accepts.
    #[test]
    fn the_restart_command_parses() {
        use clap::Parser;
        let flags: Vec<String> = ["--detach", "--shell-only", "laptop,phone", "--i-know"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cmd = restart_command(&flags);
        let (down, up) = cmd.split_once(" && ").expect("two commands");
        for half in [down, up] {
            let argv: Vec<&str> = half.split_whitespace().collect();
            assert!(crate::Cli::try_parse_from(&argv).is_ok(), "does not parse: {half}");
        }
        assert!(up.contains("--detach"), "{up}");
        let shell: Vec<String> = ["--detach", "--shell", "--i-know"].iter().map(|s| s.to_string()).collect();
        let cmd = restart_command(&shell);
        let up = cmd.split_once(" && ").unwrap().1;
        let argv: Vec<&str> = up.split_whitespace().collect();
        assert!(crate::Cli::try_parse_from(&argv).is_ok(), "does not parse: {up}");
    }
}

/// Where `tunlion logs` reads from. Pure, so the order is pinned by a test.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LogSource {
    /// The running daemon is under systemd: its output is in the journal.
    Journal,
    /// `{config}/daemon.log`, which `up --detach` (and the Windows autostart)
    /// redirect the daemon's console into.
    ConsoleLog,
    /// `{config}/diag.jsonl`, the structured connect timeline, as raw JSONL.
    DiagTimeline,
}

/// The source the RUNNING daemon actually writes wins. daemon.log used to win
/// whenever it existed, so a box that once ran `up --detach` and now runs as a
/// service showed that old, dead log forever while the journal had the live
/// one.
pub(crate) fn log_source(running_under_service_manager: bool, console_log_exists: bool) -> LogSource {
    if running_under_service_manager {
        LogSource::Journal
    } else if console_log_exists {
        LogSource::ConsoleLog
    } else {
        LogSource::DiagTimeline
    }
}

/// Show the daemon's output: the journal for a daemon running under systemd,
/// else `{config}/daemon.log` (written by `up --detach`), else the diagnostic
/// timeline `diag.jsonl`, printed as the raw JSON lines the daemon wrote. A
/// bounded backlog (default 20 lines, --tail 0 = live only), then follows live
/// with -f.
pub(crate) async fn logs_cmd(follow: bool, tail: usize) -> Result<()> {
    let console = crate::platform::Paths::config_path("daemon.log");
    let managed = daemon_alive().and_then(|pid| service_manager_for_pid(pid).map(|m| (pid, m)));
    let source = log_source(managed.is_some(), console.exists());

    // A daemon under a service manager writes to the journal, not to a file we
    // own. That is the DEFAULT path: first-run offers "Stay available in the
    // background?" and installs a service, after which `tunlion logs` said "no
    // log yet (the daemon writes it while it runs)" forever, on a daemon that
    // was running and was writing plenty. Hand the user the journal instead.
    if let (LogSource::Journal, Some((pid, mgr))) = (&source, managed) {
        let scope = match mgr {
            ServiceManager::SystemdSystem => "",
            ServiceManager::SystemdUser => "--user ",
        };
        let n = tail.max(1);
        let follow_flag = if follow { "-f " } else { "" };
        let unit = crate::platform::SYSTEMD_UNIT;
        let cmd = format!("journalctl {scope}-u {unit} {follow_flag}-n {n} --no-pager");
        ui::say(&format!(
            "  this daemon runs as a service (pid {pid}); its output goes to the journal"
        ));
        ui::say(&ui::paint(ui::Tone::Dim, &format!("    {cmd}")));
        let status = std::process::Command::new("journalctl")
            .args(scope.split_whitespace())
            .args(["-u", unit])
            .args(if follow { vec!["-f"] } else { vec![] })
            .args(["-n", &n.to_string(), "--no-pager"])
            .status();
        return match status {
            Ok(st) if st.success() => Ok(()),
            // Say which step failed. "no log yet" would be a third
            // wrong explanation for the same situation.
            _ => {
                ui::say("  could not read the journal here; run the command above directly");
                Ok(())
            }
        };
    }

    let path = if source == LogSource::ConsoleLog {
        console
    } else {
        crate::platform::Paths::config_path("diag.jsonl")
    };
    let read_tail = |count: usize| -> Result<()> {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // Say what is true now, not what will happen later: nothing has
            // been written yet. Whether it WILL appear depends on the daemon
            // actually running (and, on some platforms, having a place to
            // write), which this process cannot establish.
            ui::say("  no log yet (nothing written so far)");
            return Ok(());
        };
        let lines: Vec<&str> = raw.lines().collect();
        let start = lines.len().saturating_sub(count);
        for line in &lines[start..] {
            eprintln!("{line}");
        }
        Ok(())
    };
    if tail > 0 {
        read_tail(tail)?;
    }
    if !follow {
        return Ok(());
    }
    // Follow live: read new appended lines until ctrl-c. Ctrl-c must detach
    // cleanly, never stop the daemon. The file may not exist yet (the daemon
    // is still starting); poll for it instead of erroring.
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt};
    // #216: ONE interrupt registration, created before the loops and held for
    // the whole follow.
    //
    // The old shape built `tokio::signal::ctrl_c()` fresh inside each select and
    // awaited the idle sleep in the branch BODY, outside any select. A followed
    // log is idle almost all of the time, so almost every press landed in a
    // window where no ctrl_c future existed, and a signal delivered when nothing
    // is listening is not replayed to whatever listens next. The user saw
    // ^C^C^C^C do nothing while two banners promised ctrl-c detaches.
    //
    // `notify_one` (not `notify_waiters`) is the load-bearing choice: it stores a
    // permit when there is no waiter, so a press during a sleep is remembered and
    // consumed by the next `notified()`. `notify_waiters` would drop it and
    // reintroduce the bug in a subtler form.
    let interrupted = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let n = interrupted.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            // Read-only verb: `logs -f` installs no forwarding rules and
            // creates no WireGuard interface, so there is nothing to tear
            // down here (those cleanups belong to the daemon paths that
            // own the state). Just wake the loop to detach.
            n.notify_one();
        });
    }
    macro_rules! detached {
        () => {{
            ui::say("\n  detached (the daemon keeps running)");
            return Ok(());
        }};
    }
    loop {
        match tokio::fs::OpenOptions::new().read(true).open(&path).await {
            Ok(f) => {
                let mut file = f;
                file.seek(std::io::SeekFrom::End(0)).await?;
                let mut reader = tokio::io::BufReader::new(file);
                let mut line = String::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = interrupted.notified() => detached!(),
                        res = reader.read_line(&mut line) => {
                            if res? == 0 {
                                // The idle wait is a select ARM, not an awaited
                                // body, so the interrupt stays live through it.
                                tokio::select! {
                                    biased;
                                    _ = interrupted.notified() => detached!(),
                                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                                }
                                continue;
                            }
                            eprintln!("{}", line.trim_end());
                            line.clear();
                        }
                    }
                }
            }
            Err(_) => {
                // The same window while waiting for the file to appear: a daemon
                // that is slow to start must not make ctrl-c inert either.
                tokio::select! {
                    biased;
                    _ = interrupted.notified() => detached!(),
                    _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                }
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    /// `up` flags that choose HOW this invocation starts the daemon. They are
    /// the one thing the daemon argv must never carry.
    const LAUNCH_ONLY: &[&str] = &["install", "detach", "system", "install_system"];
    /// Global flags that shape this invocation's own terminal output and
    /// prompts. The daemon has no terminal to apply them to.
    const PER_INVOCATION: &[&str] = &[
        "verbose",
        "quiet",
        "no_interactive",
        "interactive",
        "color",
        "json",
        "yes",
        "help",
        "version",
    ];

    fn parse(argv: &[String]) -> crate::Cli {
        let mut full = vec!["tunlion".to_string()];
        full.extend(argv.iter().cloned());
        crate::Cli::try_parse_from(&full)
            .unwrap_or_else(|e| panic!("argv does not parse: {argv:?}\n{e}"))
    }

    fn opts_of(argv: &[&str]) -> DaemonOpts {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        DaemonOpts::from_cli(&parse(&argv)).expect("an `up` command")
    }

    /// Every `up` flag survives the trip into the daemon argv and back: parse
    /// the user's command, build the argv a service/detached daemon gets, parse
    /// THAT with the real clap surface, and the daemon options are identical.
    #[test]
    fn up_flags_round_trip_through_the_daemon_argv() {
        let everything: &[&str] = &[
            "--server",
            "https://sig.example",
            "--relay",
            "--name-as",
            "box one",
            "up",
            "--install",
            "--dir",
            "/srv/My Inbox",
            "--userspace",
            "--shell",
            "--shell-only",
            "a,b",
            "--shell-program",
            "bash -l",
            "--shell-user=-odd",
            "--i-know",
            "--no-proxy-fallback",
        ];
        let full = opts_of(everything);
        // The parse captured every flag (a field left at its default here
        // would make the round trip below vacuous for that field).
        assert_eq!(
            full,
            DaemonOpts {
                server: Some("https://sig.example".into()),
                relay: true,
                no_relay: false,
                name_as: Some("box one".into()),
                dir: Some(PathBuf::from("/srv/My Inbox")),
                userspace: true,
                shell: true,
                shell_only: Some("a,b".into()),
                shell_program: Some("bash -l".into()),
                shell_user: Some("-odd".into()),
                i_know: true,
                no_proxy_fallback: true,
            }
        );
        let cases: Vec<DaemonOpts> = vec![
            full,
            opts_of(&["up", "--detach", "--no-relay", "--i-know"]),
            opts_of(&["up", "--install", "--system"]),
            opts_of(&["up"]),
        ];
        assert!(cases[1].no_relay, "--no-relay must be captured");
        for opts in cases {
            let argv = opts.daemon_argv();
            assert_eq!(argv[0], "up");
            for launch in ["--install", "--detach", "--system", "--install-system"] {
                assert!(
                    !argv.iter().any(|a| a == launch),
                    "the daemon argv must not re-launch: {argv:?}"
                );
            }
            let back = DaemonOpts::from_cli(&parse(&argv)).expect("daemon argv is an `up` command");
            assert_eq!(back, opts, "daemon argv {argv:?} lost or changed a flag");
        }
    }

    /// The guard against the next flag: every argument `up` accepts (its own
    /// and the globals it inherits) is either forwarded to the daemon argv or
    /// named above as launch-only / per-invocation. A new flag fails here until
    /// someone decides which it is, instead of being dropped silently.
    #[test]
    fn every_up_flag_is_forwarded_or_deliberately_not() {
        let mut cmd = crate::Cli::command();
        cmd.build();
        let up = cmd.find_subcommand("up").expect("`up` exists");
        let all = DaemonOpts {
            server: Some("https://x".into()),
            relay: true,
            no_relay: true,
            name_as: Some("n".into()),
            dir: Some(PathBuf::from("/d")),
            userspace: true,
            shell: true,
            shell_only: Some("a".into()),
            shell_program: Some("sh".into()),
            shell_user: Some("u".into()),
            i_know: true,
            no_proxy_fallback: true,
        }
        .daemon_argv();
        let mut seen = 0;
        for arg in up.get_arguments() {
            let id = arg.get_id().as_str();
            if LAUNCH_ONLY.contains(&id) || PER_INVOCATION.contains(&id) {
                continue;
            }
            let long = arg
                .get_long()
                .unwrap_or_else(|| panic!("`up` argument {id} has no long name"));
            let flag = format!("--{long}");
            let prefix = format!("--{long}=");
            assert!(
                all.iter().any(|a| *a == flag || a.starts_with(&prefix)),
                "`up {flag}` is not forwarded to the daemon argv and not listed as \
                 launch-only or per-invocation: `up --install`/`--detach` would drop it"
            );
            seen += 1;
        }
        assert!(seen >= 12, "expected the globals to be visible on `up` after build(); saw {seen}");
    }

    #[test]
    fn logs_read_what_the_running_daemon_writes() {
        // A service-managed daemon writes the journal even if an old
        // daemon.log from a past `up --detach` is still on disk.
        assert_eq!(log_source(true, true), LogSource::Journal);
        assert_eq!(log_source(true, false), LogSource::Journal);
        assert_eq!(log_source(false, true), LogSource::ConsoleLog);
        assert_eq!(log_source(false, false), LogSource::DiagTimeline);
    }
}
