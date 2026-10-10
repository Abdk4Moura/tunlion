use anyhow::{bail, Result};
use std::path::Path;

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
// PROTOCOL LITERAL: frozen, do not rename. This line is written into
// /etc/ssh/sshd_config and is how this code later recognises its OWN block, so
// it is on-disk format, not prose: a renamed marker stops matching the blocks
// released builds wrote, and every upgraded daemon appends a duplicate.
const FILAMENT_MARKER: &str = "# Added by filament for L3 overlay access";
/// The text an unreleased build wrote for a short while after the rename.
/// Read only, never written: recognised so such a block is not duplicated.
const FILAMENT_MARKER_RENAMED: &str = "# Added by tunlion for L3 overlay access";

fn has_overlay_marker(text: &str) -> bool {
    text.contains(FILAMENT_MARKER) || text.contains(FILAMENT_MARKER_RENAMED)
}

/// Configure sshd to listen on the L3 overlay addresses AND localhost.
/// Appends ListenAddress entries for both IPv6 and IPv4 overlay addresses,
/// plus 127.0.0.1 and ::1 so `tunlion ssh` (which dials localhost via the
/// L2 tunnel) continues to work. Without the localhost entries, sshd's
/// default all-interfaces listen is REPLACED by the explicit overlay entries
/// and localhost becomes unreachable (a regression).
pub fn configure_sshd_overlay(v6: &str, v4: &str) -> Result<()> {
    let config_path = Path::new(SSHD_CONFIG);
    
    if !config_path.exists() {
        bail!("sshd_config not found at {SSHD_CONFIG}");
    }
    
    let content = std::fs::read_to_string(config_path)?;
    
    // Check if already configured (idempotent)
    if has_overlay_marker(&content) {
        crate::ui::say("sshd overlay addresses already configured");
        return Ok(());
    }
    
    // Build the entries to append — overlay addresses AND localhost.
    let entries = format!(
        "\n{FILAMENT_MARKER}\nListenAddress {v6}\nListenAddress {v4}\nListenAddress 127.0.0.1\nListenAddress ::1\n"
    );
    
    // Append to config
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(config_path)?;
    std::io::Write::write_all(&mut file, entries.as_bytes())?;
    
    crate::ui::say(&format!("added overlay addresses to sshd_config:"));
    crate::ui::say(&format!("  ListenAddress {v6}"));
    crate::ui::say(&format!("  ListenAddress {v4}"));
    
    // Reload sshd
    reload_sshd()?;
    
    Ok(())
}

/// Reload sshd to pick up configuration changes.
fn reload_sshd() -> Result<()> {
    // daemon-reload first to pick up unit file changes
    let _ = std::process::Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    
    // Then restart sshd
    let status = std::process::Command::new("sudo")
        .args(["systemctl", "restart", "ssh"])
        .status();
    
    match status {
        Ok(s) if s.success() => {
            crate::ui::say("restarted sshd");
            Ok(())
        }
        _ => {
            // Try SIGHUP fallback
            let status = std::process::Command::new("sudo")
                .args(["kill", "-HUP"])
                .arg(get_sshd_pid()?)
                .status();
            
            match status {
                Ok(s) if s.success() => {
                    crate::ui::say("reloaded sshd via SIGHUP");
                    Ok(())
                }
                _ => bail!("failed to restart sshd (try: sudo systemctl restart ssh)"),
            }
        }
    }
}

/// Get the sshd PID.
fn get_sshd_pid() -> Result<String> {
    let output = std::process::Command::new("pidof")
        .arg("sshd")
        .output()?;
    
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pid.is_empty() {
        bail!("sshd is not running");
    }
    
    // Take the first PID if multiple
    Ok(pid.split_whitespace().next().unwrap_or(&pid).to_string())
}

/// Check if sshd overlay addresses are configured.
pub fn is_configured() -> bool {
    let Ok(content) = std::fs::read_to_string(SSHD_CONFIG) else {
        return false;
    };
    has_overlay_marker(&content)
}

// PROTOCOL LITERAL: frozen, do not rename. Written into sshd_config and used
// to recognise this code's own Match block (see FILAMENT_MARKER above).
const SSHD_CA_MARKER: &str = "# Added by filament for SSH certificates (shell --ssh)";
/// The text an unreleased build wrote for a short while after the rename.
/// Read only, never written: recognised so such a block is not duplicated.
const SSHD_CA_MARKER_RENAMED: &str = "# Added by tunlion for SSH certificates (shell --ssh)";

fn has_our_marker(text: &str) -> bool {
    text.contains(SSHD_CA_MARKER) || text.contains(SSHD_CA_MARKER_RENAMED)
}
/// Default location of the CA public key the TrustedUserCAKeys line points at.
/// (The operator places the daemon's CA pub here out of band.)
pub const SSHD_CA_PUB_DEFAULT: &str = "/etc/ssh/filament_ca.pub";
const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";
const SSHD_PRINCIPALS_BASE_DEFAULT: &str = "/etc/ssh/filament_principals";

/// sshd_config path: env-overridable so e2e exercises the real writer
/// against temp files instead of the live config.
pub fn sshd_config_path() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_SSHD_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_CONFIG_DEFAULT))
}

/// Principals base dir (per-user files under it): env-overridable likewise.
pub fn principals_base_dir() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_PRINCIPALS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_PRINCIPALS_BASE_DEFAULT))
}

/// Trust-anchor path (where TrustedUserCAKeys points): env-overridable so
/// e2e asserts the product copy without touching /etc/ssh.
pub fn ca_pub_anchor_path() -> std::path::PathBuf {
    std::env::var("FILAMENT_SSH_CA_PUB_ANCHOR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(SSHD_CA_PUB_DEFAULT))
}

/// Install the daemon CA pub at the trust anchor (0644), creating parents.
/// Best-effort like everything here (loud error, Ok): the manual steps
/// cover the unwritable case.
pub fn install_ca_pub_anchor(src: &Path, anchor: &Path) -> Result<()> {
    let pub_text = std::fs::read_to_string(src)?;
    if let Some(parent) = anchor.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(anchor, pub_text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(anchor, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// Principals file for one login user under a base dir.
pub fn principals_file_for(base: &Path, user: &str) -> std::path::PathBuf {
    base.join(user)
}

/// Ensure the principals file lists exactly the daemon principal (single
/// line, idempotent): without it even a valid cert fails at sshd, so the
/// arming flows write it in the same breath. Best-effort (loud error,
/// Ok): up/grant must not newly require root.
pub fn ensure_principals_entry(base: &Path, user: &str) -> Result<()> {
    std::fs::create_dir_all(base)?;
    let path = principals_file_for(base, user);
    let want = format!("{user}\n");
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    if have != want {
        std::fs::write(&path, want)?;
    }
    Ok(())
}

/// Exact CA block: a Match-User scope (everything restricted to the daemon
/// user) with the trust anchor plus the principals line. Rendered pure so
/// the text is unit-tested byte-exact without touching a real sshd_config.
pub fn render_sshd_ca_block(
    ca_pub_path: &Path,
    daemon_user: &str,
    principals_file: &Path,
) -> String {
    format!(
        "\n{SSHD_CA_MARKER}\nMatch User {daemon_user}\n    TrustedUserCAKeys {}\n    AuthorizedPrincipalsFile {}\n",
        ca_pub_path.display(),
        principals_file.display(),
    )
}

/// Manual steps printed when the config is unwritable (operator applies them
/// with privilege instead), including the CA-pub copy. Pure for the same
/// reason as the renderer.
pub fn sshd_ca_manual_steps(
    ca_src: &Path,
    anchor: &Path,
    daemon_user: &str,
    principals_file: &Path,
) -> String {
    format!(
        "sshd_config is not writable; apply as root, then reload sshd:\n# cp {} {} && chmod 644 {}\n{}\n# then: sudo systemctl restart ssh (or: sudo kill -HUP $(pidof sshd))",
        ca_src.display(),
        anchor.display(),
        anchor.display(),
        render_sshd_ca_block(anchor, daemon_user, principals_file).trim(),
    )
}

/// Ensure the CA block is present (idempotent via marker). Writable: append
/// and optionally reload. Unwritable: print both lines plus the reload step
/// and succeed -- the operator applies them, nothing fails silently.
/// `reload` runs the real sudo reload; tests pass false.
pub fn ensure_sshd_ca(
    config_path: &Path,
    ca_pub_path: &Path,
    daemon_user: &str,
    principals_file: &Path,
    ca_src: &Path,
    reload: bool,
) -> Result<()> {
    let current = std::fs::read_to_string(config_path).map_err(|_| {
        anyhow::anyhow!("sshd_config not found at {}", config_path.display())
    })?;
    if has_our_marker(&current) {
        crate::ui::debug("sshd CA trust already configured");
        return Ok(());
    }
    let block = render_sshd_ca_block(ca_pub_path, daemon_user, principals_file);
    let mut file = match std::fs::OpenOptions::new().append(true).open(config_path) {
        Ok(f) => f,
        Err(_) => {
            crate::ui::say(&sshd_ca_manual_steps(ca_src, ca_pub_path, daemon_user, principals_file));
            return Ok(());
        }
    };
    std::io::Write::write_all(&mut file, block.as_bytes())?;
    drop(file);
    // Test BEFORE reload: a bad config must roll back, never ship behind a
    // restart. `sshd -t -f` validates without touching the live daemon.
    // (Unix OpenSSH path; on Windows there is no system sshd to reload --
    // the writer still renders correct lines for manual application, and
    // the unwritable branch above is how that surfaces.)
    let tested = std::process::Command::new("sshd")
        .args(["-t", "-f"])
        .arg(config_path)
        .stdin(std::process::Stdio::null())
        .output();
    match tested {
        Ok(out) if out.status.success() => {}
        tested => {
            let detail = match tested {
                Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
                Err(e) => format!("could not run sshd: {e}"),
            };
            if std::fs::write(config_path, &current).is_err() {
                anyhow::bail!(
                    "sshd rejected the new config AND rollback failed; {} may be left modified -- restore it by hand",
                    config_path.display()
                );
            }
            anyhow::bail!(
                "sshd rejected the new config ({detail}) (rolled back, daemon untouched); apply manually: {}",
                sshd_ca_manual_steps(ca_src, ca_pub_path, daemon_user, principals_file)
                    .replace('\n', " | ")
            );
        }
    }
    crate::ui::say("added SSH CA trust to sshd_config");
    if reload {
        reload_sshd()?;
    }
    Ok(())
}

/// Pure presence check over config text: (TrustedUserCAKeys ours, principals
/// line ours). Both must carry our marker block to count.
pub fn sshd_ca_status(config_text: &str) -> (bool, bool) {
    let ours = has_our_marker(config_text);
    (
        ours && config_text.contains("TrustedUserCAKeys"),
        ours && config_text.contains("AuthorizedPrincipalsFile"),
    )
}

/// Doctor check: both CA lines present in the live sshd_config.
pub fn check_sshd_ca() -> std::result::Result<(), String> {
    check_sshd_ca_at(Path::new(SSHD_CONFIG_DEFAULT))
}

/// Whether tunlion's ssh is in play on this host: its sshd config already
/// carries tunlion's CA lines (some earlier `shell --ssh` setup armed them, so
/// a failure to keep them current matters). A host merely HAVING sshd is not
/// enough: a first-time-user test ran `grant <dev> shell` on a stock box and
/// was told "ssh CA arming skipped (cannot determine serving user)" about a
/// feature it never asked for. The native `shell`/`exec` path needs none of
/// this, and `tunlion doctor` still reports the CA lines for anyone using ssh.
fn ssh_relevant() -> bool {
    std::fs::read_to_string(sshd_config_path())
        .map(|text| {
            let (ca, principals) = sshd_ca_status(&text);
            ca || principals
        })
        .unwrap_or(false)
}

/// An arming outcome: shown when ssh is relevant here, debug-only otherwise.
/// "ssh CA arming skipped" printed on every `up --shell` for people who never
/// use ssh, and named a fix for a feature they were not using.
fn arming_note(line: &str) {
    if ssh_relevant() {
        crate::ui::say(line);
    } else {
        crate::ui::debug(line);
    }
}

/// Best-effort arming for shell-serving flows (`up --shell`, `grant shell`):
/// ensure the CA block plus the daemon principals entry. Loud on any
/// failure but always Ok: serving must not newly require root. Paths honor
/// the test overrides, so e2e exercises the real writer, not a stub.
pub async fn arm_ssh_ca_for_serving() {
    let user = match crate::ssh_ca::valid_principal() {
        Ok(u) => u,
        Err(_) => {
            arming_note("ssh CA arming skipped (cannot determine serving user); cert logins will refuse until applied");
            return;
        }
    };
    let config_dir = crate::settings::config_dir();
    // CA key first: pre-existing installs never ran init, so mint here
    // (idempotent). A mint failure stops arming loudly -- without a CA
    // there is nothing to anchor or trust.
    if let Err(e) = crate::ssh_ca::ensure_ca_key(&config_dir).await {
        arming_note(&format!(
            "ssh CA arming skipped (no CA key: {e}); cert logins will refuse until applied"
        ));
        return;
    }
    // NO-ROOT TRUST FIRST. Everything below writes under /etc/ssh and so needs
    // root; a daemon running as a normal user failed there, printed "cert logins
    // will refuse until applied" into its own log, and stopped. Every `--ssh`
    // after that presented a valid certificate that sshd had no reason to
    // trust, and ssh fell back to asking for a PASSWORD -- for a tool whose
    // whole point is that you never type one.
    //
    // OpenSSH has a per-user equivalent that needs neither root nor an sshd
    // reload: a `cert-authority,principals="<user>"` line in that user's own
    // authorized_keys, re-read on every login. Proven on a throwaway sshd
    // before relying on it: without trust a valid cert is refused with
    // "Permission denied (publickey,password)"; with the line it logs in;
    // and a cert for a different principal is still refused.
    let per_user_trust = install_user_ca_trust(&config_dir, &user);
    match &per_user_trust {
        // PER-USER TRUST IS SUFFICIENT, SO DO NOT TOUCH /etc/ssh AT ALL.
        //
        // The system-wide route below copies THIS daemon's CA over the one
        // shared file sshd trusts, /etc/ssh/filament_ca.pub, unconditionally.
        // So any second daemon running as root -- a test, a second instance, a
        // reinstall with a fresh config -- silently took over root ssh trust
        // from the first, and broke the first one's --ssh. This happened on a
        // production box during development: a scratch test daemon replaced
        // the trusted CA, and sshd trusted a throwaway key for root until it
        // was found and quarantined. Shared system state written without an
        // ownership check is the defect; not writing it is the fix whenever
        // the per-user line, which is scoped to one user and one daemon's
        // HOME, already does the job.
        Ok(()) => return,
        Err(e) => crate::ui::say(&format!(
            "ssh CA: could not add the per-user trust line ({e}); falling back to the system-wide setup"
        )),
    }

    // Trust anchor next: copy the daemon CA pub where the Match block
    // points, so -t validates what sshd will actually read. Unwritable:
    // print the manual steps (including this copy) and stop -- the block
    // below would fail its own -t against a missing anchor.
    let anchor = ca_pub_anchor_path();
    let ca_src = crate::ssh_ca::ca_key_path(&config_dir).with_extension("pub");
    if let Err(e) = install_ca_pub_anchor(&ca_src, &anchor) {
        arming_note(&format!(
            "ssh CA arming skipped (anchor unwritable: {e}); cert logins will refuse until applied:\n{}",
            sshd_ca_manual_steps(
                &ca_src,
                &anchor,
                &user,
                &principals_file_for(&principals_base_dir(), &user)
            )
        ));
        return;
    }
    let principals = principals_file_for(&principals_base_dir(), &user);
    if let Err(e) = ensure_sshd_ca(
        &sshd_config_path(),
        &anchor,
        &user,
        &principals,
        &ca_src,
        true,
    ) {
        arming_note(&format!(
            "ssh CA arming skipped ({e}); cert logins will refuse until applied"
        ));
        return;
    }
    if let Err(e) = ensure_principals_entry(&principals_base_dir(), &user) {
        arming_note(&format!(
            "ssh principals entry skipped ({e}); cert logins will refuse until applied"
        ));
    }
}

/// The exact authorized_keys line that makes sshd trust this daemon's CA for
/// `user` only. Pure, so it is unit-tested byte-exact. The CA pubkey is
/// validated (single line, known type, base64) before it can reach the file,
/// and the principal is restricted to a conservative charset because it is
/// written inside a quoted option.
pub fn render_user_ca_trust_line(ca_pub: &str, user: &str) -> Result<String> {
    let key = authkeys_managed::validate_pubkey(ca_pub)?;
    if user.is_empty()
        || user.len() > 64
        || !user.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        anyhow::bail!("refusing to write a principal that is not a plain username: {user:?}");
    }
    Ok(format!("cert-authority,principals=\"{user}\" {key}"))
}

/// Install (idempotently) the per-user CA trust line into the serving user's
/// authorized_keys, inside tunlion's managed block.
fn install_user_ca_trust(config_dir: &Path, user: &str) -> Result<()> {
    let ca_pub_path = crate::ssh_ca::ca_key_path(config_dir).with_extension("pub");
    let ca_pub = std::fs::read_to_string(&ca_pub_path)
        .map_err(|e| anyhow::anyhow!("CA public key unreadable at {}: {e}", ca_pub_path.display()))?;
    let line = render_user_ca_trust_line(&ca_pub, user)?;
    // Its own markers, not a per-device block: see authkeys_managed::CA_BEGIN.
    authkeys_managed::install_ca_trust_line(&line)
}

/// Same against an explicit path (tests use temp files, never the live one).
pub fn check_sshd_ca_at(path: &Path) -> std::result::Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("sshd config unreadable at {}: {e}", path.display()))?;
    match sshd_ca_status(&text) {
        (true, true) => Ok(()),
        (false, _) => Err("TrustedUserCAKeys line missing (run the CA setup)".to_string()),
        (_, false) => Err("AuthorizedPrincipalsFile line missing (run the CA setup)".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_written_before_the_rename_is_recognised() {
        // The rebrand changed the marker; without this an upgraded root daemon
        // appended a second, identical Match block.
        let old = format!("{SSHD_CA_MARKER}\nMatch User root\n    TrustedUserCAKeys /etc/ssh/x.pub\n    AuthorizedPrincipalsFile /etc/ssh/p/root\n");
        assert!(has_our_marker(&old));
        assert_eq!(sshd_ca_status(&old), (true, true));
        assert!(!has_our_marker("Match User root\n    TrustedUserCAKeys /etc/ssh/someone-elses.pub\n"));
    }

    #[test]
    fn the_per_user_trust_line_is_scoped_to_one_plain_username() {
        let ca = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH2u7c8bP1RkQ0n1i3f5l0x9c4m2rWq6v8T7a3YkZpQ1 tunlion-ca";
        assert_eq!(
            render_user_ca_trust_line(ca, "kabir").unwrap(),
            format!("cert-authority,principals=\"kabir\" {ca}")
        );
        let too_long = "u".repeat(65);
        let bad_users: [&str; 5] = ["", "a b", "root\",command=\"x", "x/y", too_long.as_str()];
        for bad in bad_users {
            assert!(render_user_ca_trust_line(ca, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ca_block_is_a_daemon_user_match_with_both_lines() {
        let block = render_sshd_ca_block(
            Path::new("/etc/ssh/filament_ca.pub"),
            "filament",
            Path::new("/etc/ssh/filament_principals/%u"),
        );
        assert_eq!(
            block,
            "\n# Added by filament for SSH certificates (shell --ssh)\nMatch User filament\n    TrustedUserCAKeys /etc/ssh/filament_ca.pub\n    AuthorizedPrincipalsFile /etc/ssh/filament_principals/%u\n"
        );
    }

    #[test]
    fn anchor_copy_installs_0644_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("ssh_ca.pub");
        std::fs::write(&src, "ssh-ed25519 AAAAC3test\n").unwrap();
        let anchor = dir.join("sub").join("anchor.pub");
        install_ca_pub_anchor(&src, &anchor).unwrap();
        install_ca_pub_anchor(&src, &anchor).unwrap();
        assert_eq!(
            std::fs::read_to_string(&anchor).unwrap(),
            "ssh-ed25519 AAAAC3test\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&anchor).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        assert!(install_ca_pub_anchor(&dir.join("missing"), &anchor).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn principals_entry_lists_exactly_the_daemon_user() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-princ-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_principals_entry(&dir, "daemon").unwrap();
        ensure_principals_entry(&dir, "daemon").unwrap();
        assert_eq!(
            std::fs::read_to_string(principals_file_for(&dir, "daemon")).unwrap(),
            "daemon\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_steps_contain_both_lines_and_reload() {
        let steps = sshd_ca_manual_steps(
            Path::new("/ssh/ssh_ca.pub"),
            Path::new("/ca.pub"),
            "daemon",
            Path::new("/p/%u"),
        );
        assert!(steps.contains("TrustedUserCAKeys /ca.pub"), "{steps}");
        assert!(steps.contains("AuthorizedPrincipalsFile"), "{steps}");
        assert!(steps.contains("systemctl restart ssh"), "{steps}");
        assert!(steps.contains("/ssh/ssh_ca.pub"), "{steps}");
        assert!(steps.contains("/ca.pub"), "{steps}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_is_idempotent_and_refuses_missing_file() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // sshd -t needs real host keys, else every ensure rolls back.
        for name in ["hostkey", "ca"] {
            let st = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join(name))
                .args(["-N", ""])
                .status()
                .expect("ssh-keygen present");
            assert!(st.success());
        }
        // sshd -t refuses an unprotected host private key (umask-dependent
        // otherwise): tighten like production key material.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("hostkey"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let ca_pub = dir.join("ca.pub");
        let cfg = dir.join("sshd_config");
        std::fs::write(
            &cfg,
            format!("Port 22\nHostKey {}\n", dir.join("hostkey").display()),
        )
        .unwrap();
        ensure_sshd_ca(&cfg, &ca_pub, "daemon", Path::new("/p/%u"), &ca_pub, false).unwrap();
        ensure_sshd_ca(&cfg, &ca_pub, "daemon", Path::new("/p/%u"), &ca_pub, false).unwrap();
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(
            text.matches(SSHD_CA_MARKER).count(),
            1,
            "second ensure must not duplicate: {text}"
        );
        assert!(check_sshd_ca_at(&cfg).is_ok());
        assert!(ensure_sshd_ca(
            &dir.join("nope"),
            Path::new("/ca.pub"),
            "daemon",
            Path::new("/p/%u"),
            Path::new("/ssh/ssh_ca.pub"),
            false
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bad_config_rolls_back_and_refuses() {
        let dir = std::env::temp_dir().join(format!("fil-sshd-rb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-f"])
            .arg(dir.join("hostkey"))
            .args(["-N", ""])
            .status()
            .expect("ssh-keygen present");
        assert!(st.success());
        let before = format!(
            "Port 22\nHostKey {}\nBogusDirective yes\n",
            dir.join("hostkey").display()
        );
        let cfg = dir.join("sshd_config");
        std::fs::write(&cfg, &before).unwrap();
        let e = ensure_sshd_ca(&cfg, Path::new("/ca.pub"), "daemon", Path::new("/p/%u"), Path::new("/ssh/ssh_ca.pub"), false)
            .unwrap_err();
        assert!(e.to_string().contains("rolled back"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            before,
            "failed config must be restored byte-identical"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_distinguishes_missing_halves() {
        let (t, p) = sshd_ca_status("Port 22\n");
        assert!(!t && !p);
        let full = render_sshd_ca_block(Path::new("/ca.pub"), "d", Path::new("/p/%u"));
        let (t, p) = sshd_ca_status(&full);
        assert!(t && p);
        let mut partial = full.replace("AuthorizedPrincipalsFile", "AuthorizedKeysFile");
        let (t, p) = sshd_ca_status(&partial);
        assert!(t && !p, "wrong principals directive must not count");
        partial = full.replace(SSHD_CA_MARKER, "# foreign");
        let (t, p) = sshd_ca_status(&partial);
        assert!(!t && !p, "keys without our marker must not count");
    }

    /// The markers are on-disk format shared with every released build. These
    /// are the exact bytes 0.8.5 wrote; a rename must not change them.
    /// Pinned by SHA-256 of the original literal (`printf '%s' '<marker>' |
    /// sha256sum`), which a find-and-replace cannot keep in step.
    #[test]
    fn sshd_markers_are_the_released_on_disk_text() {
        use sha2::{Digest, Sha256};
        let hex = |s: &str| -> String {
            Sha256::digest(s.as_bytes()).as_slice().iter().map(|b| format!("{b:02x}")).collect()
        };
        assert_eq!(
            hex(FILAMENT_MARKER),
            "072be630f0cd7592c35bb3af561091a846108a2d39868b3d0a11708be91f5426",
            "the overlay marker is frozen on-disk text"
        );
        assert_eq!(
            hex(SSHD_CA_MARKER),
            "288b19dcd13e623275ac2b76145844d4e82fcba1af3cac6f61b43cf16e855416",
            "the CA marker is frozen on-disk text"
        );
    }

    #[test]
    fn blocks_written_under_either_marker_are_recognised() {
        // Released builds wrote the filament text; main briefly wrote the
        // tunlion text. Both must count as ours, or an upgraded daemon appends
        // a second identical block.
        for marker in [SSHD_CA_MARKER, SSHD_CA_MARKER_RENAMED] {
            let block = format!(
                "{marker}\nMatch User root\n    TrustedUserCAKeys /etc/ssh/x.pub\n    AuthorizedPrincipalsFile /etc/ssh/p/root\n"
            );
            assert!(has_our_marker(&block), "{marker}");
            assert_eq!(sshd_ca_status(&block), (true, true), "{marker}");
        }
        for marker in [FILAMENT_MARKER, FILAMENT_MARKER_RENAMED] {
            assert!(has_overlay_marker(&format!("{marker}\nListenAddress ::1\n")), "{marker}");
        }
        assert!(!has_our_marker("Match User root\n    TrustedUserCAKeys /etc/ssh/someone-elses.pub\n"));
        assert!(!has_overlay_marker("ListenAddress ::1\n"));
    }
}
