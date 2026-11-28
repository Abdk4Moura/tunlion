//! Managed-key / ephemeral-cert SSH bootstrap, transport proxy launch, and sshd health probes.

use super::{bring_up_to_known, recv_selected_event};
use crate::net::{self, Ev};
use anyhow::{Result, anyhow};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Seamless-shell bootstrap (initiator): over the already-authenticated tunlion
/// channel, hand the acceptor our managed pubkey and fetch its host keys, so a
/// user with ZERO ssh setup gets a no-prompt shell. The exchange is pure control
/// JSON over the transport `bring_up_to_known` returns (no mux needed).
///
/// Returns `Ok(hostkeys)` on grant (the acceptor installed our key); the caller
/// pins the host keys and spawns ssh. Returns `Err` if the acceptor DENIES (the
/// device lacks the `shell` cap) or times out, in which case the caller MUST NOT
/// fall through to a key-less ssh attempt (that would be a muddy auth failure
/// instead of a clear "zero shell" denial).
/// Result of installing our managed key on a peer (warm or cold path). `sshd` is
/// the peer's report of whether an sshd is listening on the port `tunlion shell --ssh`
/// will dial: `Some(true)` reachable, `Some(false)` nothing there (so ssh would
/// fail blindly - caller bails with a clear message), `None` when the peer is an
/// older build that didn't report it (caller proceeds, status unknown).
struct BootstrapInfo {
    hostkeys: Vec<String>,
    user: Option<String>,
    sshd: Option<bool>,
}

async fn shell_bootstrap(
    server: &str,
    peer: &str,
    relay: bool,
    ssh_port: u16,
    cert_only: bool,
) -> Result<BootstrapInfo> {
    // Managed keypair lives under the tunlion config dir, NEVER ~/.ssh. In
    // cert mode it is NOT generated and NOT offered: `shell --ssh` now
    // authenticates with an ephemeral certificate, so this exchange exists
    // only to learn the peer's host keys and sshd status (the acceptor
    // skips its authorized_keys write on the same flag).
    let pubkey = if cert_only {
        String::new()
    } else {
        crate::sshkeys::ensure_managed_key()?
    };

    // Bound the connect so an unreachable peer fails with a clear, actionable
    // message instead of looping forever (the heartbeat inside reports progress
    // meanwhile). Override with TUNLION_SSH_CONNECT_SECS.
    let connect_secs: u64 = std::env::var("TUNLION_SSH_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(45);
    let (t, mut rx, guard, mut diag) = match tokio::time::timeout(
        std::time::Duration::from_secs(connect_secs),
        bring_up_to_known(server, peer, relay, "bootstrap"),
    )
    .await
    {
        Ok(inner) => inner?,
        Err(_) => {
            crate::ui::problem(
                &format!("tunlion shell --ssh: can't reach '{peer}'"),
                &format!(
                    "couldn't establish a link to '{peer}' in {connect_secs}s - it may be offline or unreachable from here."
                ),
                &[
                    format!(
                        "check it's reachable: {}",
                        crate::ui::paint(crate::ui::Tone::Brand, &format!("tunlion reach {peer}"))
                    ),
                    format!(
                        "diagnose the connect: {}",
                        crate::ui::paint(
                            crate::ui::Tone::Brand,
                            &format!("tunlion doctor {peer}")
                        )
                    ),
                ],
            );
            std::process::exit(1);
        }
    };
    // The bootstrap rides the bring-up transport directly (pure control JSON, no
    // mux), so the link being usable IS the end of this span. Record `up`; the
    // ssh data link is a SEPARATE netcat span instrumented in its own right.
    diag.up("tunnel", "datachannel-or-direct");
    t.send_control(&json!({
        "type": "shell-bootstrap",
        "v": 1,
        "pubkey": pubkey,
        "ssh_port": ssh_port,
        "cert": cert_only
    }))
    .await?;

    // Await the verdict (bounded, a daemon without TUNLION_L2 / without the cap
    // must not hang us forever). Capture it, then ALWAYS tear this link down
    // BEFORE returning, so the ssh data link (netcat ProxyCommand) is the only
    // boxA peer the acceptor sees, no concurrent same-device supersede churn.
    // One identity service for this bootstrap flow: the acceptor may challenge
    // more than once, and a rebuilt service would forget what it already logged.
    let identity = crate::identity_lifecycle::service_with_log(std::sync::Arc::new(
        crate::host_impl::CliLog,
    ));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let verdict: Result<BootstrapInfo> = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break Err(anyhow!(
                "shell bootstrap timed out with no answer from '{peer}'. If it is running \
                 `tunlion up`, the shell acceptor may be off there (`tunlion up --shell`)."
            ));
        }
        match tokio::time::timeout(remaining, recv_selected_event(&mut rx, t.source_id())).await {
            Ok(Some(Ev::Control(_pid, v))) => match v["type"].as_str() {
                // #30: the acceptor challenges us to prove device-key possession
                // before it decides the shell gate. Answer it (shared responder)
                // so our binding is upgraded to Proven; otherwise the acceptor
                // refuses the bootstrap on Inferred ("identity not proven").
                Some("identity-nonce-challenge") => {
                    crate::respond_to_identity_challenge(&identity, &t, &v).await;
                    continue;
                }
                // The acceptor SAYS why it refused, in an l2-close `err`. This
                // arm used to fall through to `_ => continue`, so `--ssh` threw
                // that sentence away, spun for the full 20s, and then guessed
                // at a cause: "is '<peer>' running `tunlion up` with shell
                // access granted?" The plain `tunlion shell` path surfaces the
                // same message immediately. Same refusal, same wire, two very
                // different errors, and the useless one was on the path a user
                // reaches for when the first attempt fails.
                Some("l2-close") => {
                    if let Some(why) = v["err"].as_str() {
                        break Err(anyhow!("shell refused by '{peer}': {why}"));
                    }
                    continue;
                }
                Some("shell-bootstrap-ack") => {
                    let hostkeys: Vec<String> = v["hostkeys"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|k| k.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    // The acceptor reports the account it installed our key into,
                    // authoritative for the ssh login (see ssh_cmd).
                    let user = v["user"].as_str().map(String::from);
                    // Older acceptors omit `sshd` -> None (unknown, proceed).
                    let sshd = v["sshd"].as_bool();
                    break Ok(BootstrapInfo {
                        hostkeys,
                        user,
                        sshd,
                    });
                }
                Some("shell-bootstrap-deny") => {
                    let why = v["reason"]
                        .as_str()
                        .unwrap_or("shell capability not granted");
                    // A peer of this build says exactly why (`code`) and what it
                    // calls us (`as`); one remedy per cause, never two.
                    let (code, as_name) = crate::refusal::from_frame(&v, "reason");
                    if code.is_some() {
                        break Err(anyhow!(
                            "{}",
                            crate::refusal::explain("a shell", peer, why, code, as_name.as_deref())
                        ));
                    }
                    // Same trap as the non-ssh path: a grant cannot widen an
                    // enrolment ceiling, so do not prescribe one when the
                    // ceiling is the reason.
                    // One reason, one remedy. Appending a grant hint to every
                    // refusal produced "shell serving is off there; run
                    // `tunlion up --shell` on that device. Run `tunlion grant
                    // <this-device> shell`" — two instructions, the second
                    // irrelevant to the stated cause. A reason that already
                    // carries its own fix gets no second one bolted on.
                    let fix = if why == crate::capability::CEILING_REASON {
                        format!(
                            " shell is outside this device's invitation ceiling, and a grant cannot widen one. {}",
                            crate::identity_state::reenrol_steps(
                                &crate::display_name(),
                                &peer,
                                "shell",
                                &[]
                            )
                        )
                    } else if why == crate::capability::SHELL_OFF_REASON {
                        String::new()
                    } else {
                        format!(" Run `tunlion grant <this-device> shell` on '{peer}'.")
                    };
                    break Err(anyhow!("shell refused by '{peer}': {why}.{fix}"));
                }
                _ => continue,
            },
            Ok(Some(_)) => continue, // other events on this link, ignore
            Ok(None) => break Err(anyhow!("channel closed before shell bootstrap completed")),
            Err(_) => continue, // timeout sliver, loop re-checks the deadline
        }
    };

    // Tear down the bootstrap link before the caller opens the ssh data link.
    drop(t);
    guard.close().await;
    verdict
}

/// Install our managed key on `peer`, WARM-first: ask the local `up` daemon to
/// run the `shell-bootstrap` over its already-established link (instant, no cold
/// establish), and fall back to a fresh `shell_bootstrap` on a miss/deny/timeout,
/// under `--relay`, or off-unix. This is what closes the last gap that left
/// `tunlion shell --ssh` slow while `pty` was already warm: the bootstrap was the only
/// remaining cold establish in the ssh path.
async fn bootstrap_key(
    server: &str,
    peer: &str,
    relay: bool,
    ssh_port: u16,
    cert_only: bool,
) -> Result<BootstrapInfo> {
    #[cfg(unix)]
    if !relay && !cert_only {
        let pubkey = crate::sshkeys::ensure_managed_key()?;
        if let Some(v) = crate::ctl::try_bootstrap(peer, &pubkey, ssh_port).await {
            let hostkeys: Vec<String> = v["hostkeys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if !hostkeys.is_empty() {
                crate::ui::trace(&format!(
                    "tunlion: reusing warm link to '{peer}' for ssh bootstrap (no establish)"
                ));
                return Ok(BootstrapInfo {
                    hostkeys,
                    user: v["user"].as_str().map(String::from),
                    sshd: v["sshd"].as_bool(),
                });
            }
        }
    }
    shell_bootstrap(server, peer, relay, ssh_port, cert_only).await
}

/// The login account for the ssh destination: TUNLION_SSH_USER wins, else the
/// account the ACCEPTOR installed our key into (from the bootstrap-ack, or the
/// cache), else local $USER, else root. The acceptor's report is authoritative
/// over a local $USER guess, which is usually wrong cross-machine (agboola@laptop
/// vs root@server, the "Permission denied (publickey)" mismatch).
fn resolve_login(remote_user: Option<String>) -> String {
    std::env::var("TUNLION_SSH_USER")
        .ok()
        .or(remote_user)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into())
}

/// Spawn the real `ssh`, pointed EXCLUSIVELY at the ephemeral cert identity
/// (fresh key + B-signed cert) + known_hosts, with a `tunlion netcat`
/// ProxyCommand. Returns ssh's exit code. The cert is acquired FIRST over a
/// fresh L2 link and the flow fails CLOSED without it (clear error, never a
/// managed-key fallback: silently downgrading would make the CA decorative).
/// The destination is always `<login>@tunlion-<peer>`.
/// Run the ssh session, preferring the resilient L3 overlay. Both paths use
/// the SAME cert identity; L3 just connects to the stable overlay address
/// directly (no ProxyCommand), so the session survives a link repair.
/// Falls back to the L2 tunnel when L3 isn't viable or its connect fails (255).
/// The ephemeral tmpdir dies with the flow: explicit cleanup is belt, Drop
/// is suspenders, and a signal watchdog covers SIGINT/SIGTERM (process::exit
/// and signals both skip Drop).
async fn run_ssh(
    server: &str,
    peer: &str,
    relay: bool,
    host: &str,
    login: &str,
    rport: u16,
    extra: &[String],
    revive: bool,
) -> Result<i32> {
    // Cert identity first: fresh ephemeral key, B-signed cert over an L2
    // link. Fail closed (no managed-key fallback) when keygen, link, or
    // signing fails -- the error names the cause.
    let eph = crate::ssh_ca::EphemeralKey::generate()
        .await
        .map_err(|e| anyhow::anyhow!("ssh cert setup failed (no key fallback): {e}"))?;
    // Aborted on the normal path below (Drop + explicit cleanup already
    // covered everything else); left running only while ssh owns the session.
    let sigwatch = crate::ssh_ca::spawn_cleanup_on_signal(eph.dir().to_path_buf());
    // Abort the watchdog on early exits too (Drop already covers the dir;
    // leaving the task running would only matter in a long-lived caller).
    let ident = match crate::ssh_ca::acquire_ssh_cert(server, peer, relay, &eph).await {
        Ok(id) => id,
        Err(e) => {
            sigwatch.abort();
            return Err(anyhow::anyhow!(
                "ssh cert issuance failed (no key fallback): {e}"
            ));
        }
    };
    #[cfg(not(target_os = "linux"))]
    let _ = revive;
    #[cfg(target_os = "linux")]
    if std::env::var("TUNLION_NO_L3_SSH").as_deref() != Ok("1") {
        if let Some((mesh_host, addr)) = l3_mesh_addr(peer, rport) {
            // The peer IS on the overlay. PREFER L3 (survives link repairs); only
            // fall to L2 when the overlay genuinely can't carry ssh.
            if probe_sshd(addr, std::time::Duration::from_millis(600)) {
                crate::ui::debug(&format!(
                    "ssh over the L3 overlay ({mesh_host}) - survives link repairs"
                ));
                let code = spawn_ssh_direct(login, &mesh_host, extra, &ident)?;
                if code != 255 {
                    sigwatch.abort();
                    return Ok(code);
                }
                crate::ui::say("tunlion: L3 ssh failed, falling back to the tunnel");
            } else if revive {
                // The route exists but the overlay path looks dead (a lapsed/zombie
                // transport). Kick the revive nudge in the BACKGROUND and fall back to
                // L2 immediately. The user must never wait the revive ceiling for an
                // interactive ssh; the next ssh will find L3 up if the revive worked.
                crate::ui::say(&format!(
                    "tunlion: L3 overlay to '{peer}' down, falling back to the tunnel; reviving in background"
                ));
                let peer = peer.to_string();
                tokio::spawn(async move {
                    revive_l3(&peer, rport).await;
                });
            }
            // else (revive=false, e.g. the post-255 re-bootstrap retry): don't pay the
            // revive wait twice - go straight to the L2 tunnel below.
        }
    }
    let code = spawn_ssh(server, peer, relay, host, login, rport, extra, &ident)?;
    sigwatch.abort();
    if code == 255 {
        // 255 is ssh's own failure (connect or auth), never the remote command's.
        // Without password fallback the commonest cause is now a crisp
        // "Permission denied (publickey)", so say what it means and what to do.
        crate::ui::say(&format!(
            "tunlion: ssh to '{peer}' was refused before a session started. If ssh said \
             \"Permission denied (publickey)\", that device's sshd does not trust \
             tunlion's certificates for this user yet: restart `tunlion up` there \
             (it installs the trust for its own user, no root needed), or drop \
             --ssh to use the built-in shell, which needs no sshd at all."
        ));
    }
    Ok(code)
}

/// ssh directly to a stable overlay host (no ProxyCommand), reusing the managed
/// key + known_hosts the L2 path uses. The overlay address is cryptographically
/// bound to the peer, so accept-new pins the host key on first use.
#[cfg(target_os = "linux")]
fn spawn_ssh_direct(
    login: &str,
    mesh_host: &str,
    extra: &[String],
    ident: &crate::ssh_ca::CertIdentity,
) -> Result<i32> {
    let kh = crate::sshkeys::known_hosts_path();
    let dest_token = format!("{login}@{mesh_host}");
    let mut cmd = crate::platform::command("ssh");
    cmd.arg("-o")
        .arg(format!("IdentityFile={}", ident.key_path.display()))
        .arg("-o")
        .arg(format!("CertificateFile={}", ident.cert_path.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        // NEVER A PASSWORD. Auth is the certificate this daemon just signed, so
        // there is no legitimate password path; when the cert is not accepted,
        // ssh's default is to fall through to a password prompt, which is how
        // a missing CA trust on the device used to look -- a baffling prompt
        // nobody could answer. With these, the same failure is an immediate,
        // explainable "Permission denied (publickey)".
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=4");
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a);
    }
    cmd.arg(&dest_token);
    for a in &extra[split..] {
        cmd.arg(a);
    }
    Ok(cmd.status()?.code().unwrap_or(1))
}

fn spawn_ssh(
    server: &str,
    peer: &str,
    relay: bool,
    host: &str,
    login: &str,
    rport: u16,
    extra: &[String],
    ident: &crate::ssh_ca::CertIdentity,
) -> Result<i32> {
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" forward {peer}:{rport} --stdio"));

    let kh = crate::sshkeys::known_hosts_path();
    let dest_token = format!("{login}@{host}");
    let mut cmd = crate::platform::command("ssh");
    cmd.arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .arg("-o")
        .arg(format!("IdentityFile={}", ident.key_path.display()))
        .arg("-o")
        .arg(format!("CertificateFile={}", ident.cert_path.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        // NEVER A PASSWORD. Auth is the certificate this daemon just signed, so
        // there is no legitimate password path; when the cert is not accepted,
        // ssh's default is to fall through to a password prompt, which is how
        // a missing CA trust on the device used to look -- a baffling prompt
        // nobody could answer. With these, the same failure is an immediate,
        // explainable "Permission denied (publickey)".
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", kh.display()))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        // Bound the ssh-side connect and detect a dead session, so the data link
        // (the tunlion netcat ProxyCommand) can't hang ssh indefinitely either.
        .arg("-o")
        .arg("ConnectTimeout=25")
        .arg("-o")
        .arg("ServerAliveInterval=15")
        .arg("-o")
        .arg("ServerAliveCountMax=3");
    // Split passthrough args into ssh OPTIONS (leading flags) and the remote
    // COMMAND (from the first non-flag token on). The destination is ALWAYS our
    // managed token, inserted BETWEEN options and command, or ssh would mistake
    // the command (e.g. `hostname`) for the host.
    let mut split = extra.len();
    for (i, a) in extra.iter().enumerate() {
        if !a.starts_with('-') {
            split = i;
            break;
        }
    }
    for a in &extra[..split] {
        cmd.arg(a);
    }
    cmd.arg(&dest_token);
    for a in &extra[split..] {
        cmd.arg(a);
    }
    Ok(cmd.status()?.code().unwrap_or(1))
}

/// `tunlion shell --ssh <peer> [args...]`: seamless shell over the trusted channel.
///
/// With zero pre-existing ssh setup: bootstrap our managed key + the peer's host
/// key over the authenticated tunlion channel, pin them, then run ssh pointed
/// EXCLUSIVELY at tunlion-managed material (-o IdentityFile / IdentitiesOnly /
/// UserKnownHostsFile) with a `tunlion netcat` ProxyCommand. No prompts, no
/// ~/.ssh, no key copying. The bootstrap is the deny-by-default gate: if the
/// peer lacks the `shell` cap we abort HERE, before invoking ssh.
/// Resolve `<peer>.mesh` (the MagicDNS /etc/hosts entry) to its overlay socket
/// address. `Some` iff the peer is on the overlay (has a route); the address is the
/// crypto-derived, STABLE overlay IP (only the transport swaps under it on a
/// repair), so it's a valid target to probe/connect across repairs. `None` means
/// the peer isn't on the mesh at all -> the caller goes straight to the L2 tunnel.
/// (Note: unlike the old `l3_ssh_target`, this does NOT probe here - the caller
/// probes and, if the route is present but dead, REVIVES rather than dumping to L2.)
#[cfg(target_os = "linux")]
fn l3_mesh_addr(peer: &str, port: u16) -> Option<(String, std::net::SocketAddr)> {
    use std::net::ToSocketAddrs;
    let name = format!("{}.mesh", crate::l3::sanitize_host(peer));
    let addr = (name.as_str(), port).to_socket_addrs().ok()?.next()?;
    Some((name, addr))
}

/// Quick reachability probe of an sshd over the overlay: a bounded TCP connect.
#[cfg(target_os = "linux")]
fn probe_sshd(addr: std::net::SocketAddr, to: std::time::Duration) -> bool {
    std::net::TcpStream::connect_timeout(&addr, to).is_ok()
}

/// Nudge the daemon to revive the overlay link to `peer`: a warm-open over the
/// control socket triggers the daemon's verify-before-accept, which drops a zombie
/// link so its re-dial / 8s self-heal rebuilds it (add_peer re-installs the SAME
/// stable overlay IP). The opened stream is discarded - the open itself is the
/// nudge. Bounded (ctl's open has no internal timeout).
#[cfg(target_os = "linux")]
async fn revive_l3(peer: &str, rport: u16) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::ctl::try_open(peer, rport),
    )
    .await;
}

/// How long to wait for the overlay to come back after a revive nudge (default 15s;
/// override with TUNLION_L3_REVIVE_MS). This is a CEILING, not a fixed wait:
/// Info needed to connect to a peer over SSH (or sshfs/rsync). Returned by
/// `ensure_peer_bootstrap` after key installation + host key pinning.
pub(crate) struct PeerSshInfo {
    pub login: String,
    pub host: String,
    pub rport: u16,
    pub key_path: std::path::PathBuf,
    pub known_hosts_path: std::path::PathBuf,
    pub took_fast_path: bool,
}

/// Ensure our managed key is installed on the peer and host keys are pinned.
/// Returns `PeerSshInfo` with everything needed to spawn sshfs/rsync/ssh.
// `tunlion-<peer>` is the host alias written into the managed known_hosts /
// bootstrap pin store and looked up by exactly this spelling.
const SSH_HOST_ALIAS_PREFIX: &str = "tunlion-";

/// The host alias for `peer`.
fn ssh_host_alias(peer: &str) -> String {
    format!("{SSH_HOST_ALIAS_PREFIX}{peer}")
}

/// The peer name inside a host alias.
#[allow(dead_code)] // only the Linux L3 path reads it outside tests
fn peer_from_ssh_host_alias(host: &str) -> &str {
    host.strip_prefix(SSH_HOST_ALIAS_PREFIX).unwrap_or(host)
}

pub(crate) async fn ensure_peer_bootstrap(
    server: &str,
    peer: &str,
    relay: bool,
) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let _host = ssh_host_alias(peer);
    let rport: u16 = std::env::var("TUNLION_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    // sshfs/rsync still authenticate with the managed key.
    ensure_peer_bootstrap_port(server, peer, relay, rport, false).await
}

/// Ensure our managed key is installed on the peer with a specific port.
pub(crate) async fn ensure_peer_bootstrap_port(
    server: &str,
    peer: &str,
    relay: bool,
    rport: u16,
    cert_only: bool,
) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let host = ssh_host_alias(peer);

    let cached = if crate::sshkeys::host_pinned(&host) {
        crate::sshkeys::bootstrap_cache_get(peer)
    } else {
        None
    };

    let (login, took_fast_path) = match cached {
        Some(cached_user) => (resolve_login(cached_user), true),
        None => {
            let info = bootstrap_key(server, peer, relay, rport, cert_only).await?;
            ensure_sshd(peer, rport, info.sshd).await;
            crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
            crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());
            (resolve_login(info.user), false)
        }
    };

    Ok(PeerSshInfo {
        login,
        host,
        rport,
        key_path: crate::sshkeys::managed_key_path(),
        known_hosts_path: crate::sshkeys::known_hosts_path(),
        took_fast_path,
    })
}

/// Invalidate bootstrap cache and re-bootstrap a peer (for retry after exit 255).
pub(crate) async fn rebootstrap_peer(server: &str, peer: &str, relay: bool, cert_only: bool) -> Result<PeerSshInfo> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);
    let host = ssh_host_alias(peer);
    let rport: u16 = std::env::var("TUNLION_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);

    crate::sshkeys::bootstrap_cache_clear(peer);
    let info = shell_bootstrap(server, peer, relay, rport, cert_only).await?;
    ensure_sshd(peer, rport, info.sshd).await;
    crate::sshkeys::pin_host_keys(&host, &info.hostkeys)?;
    crate::sshkeys::bootstrap_cache_put(peer, info.user.as_deref());

    Ok(PeerSshInfo {
        login: resolve_login(info.user),
        host,
        rport,
        key_path: crate::sshkeys::managed_key_path(),
        known_hosts_path: crate::sshkeys::known_hosts_path(),
        took_fast_path: false,
    })
}

/// Build ssh option args for use with sshfs/rsync (identity, known_hosts, etc).
pub(crate) fn ssh_transport_args(
    info: &PeerSshInfo,
    server: &str,
    peer: &str,
    relay: bool,
) -> Vec<String> {
    let mut args = vec![
        "-o".into(),
        format!("IdentityFile={}", info.key_path.display()),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", info.known_hosts_path.display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=4".into(),
    ];
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_string_lossy();
    let mut proxy = format!("{exe} --server {server}");
    if relay {
        proxy.push_str(" --relay");
    }
    proxy.push_str(&format!(" forward {peer}:{} --stdio", info.rport));
    args.push("-o".into());
    args.push(format!("ProxyCommand={proxy}"));
    args
}

/// Build the L3 direct destination for sshfs/rsync (login@peer.mesh). The mesh
/// overlay (TUN) and its `.mesh` MagicDNS entries are Linux-only, so on other
/// platforms there is no L3 path: return `None` and let the caller fall back to
/// the L2 tunnel (same semantics as "peer isn't on the mesh").
#[cfg(not(target_os = "linux"))]
pub(crate) fn l3_dest(_info: &PeerSshInfo) -> Option<String> {
    None
}

/// Build the L3 direct destination for sshfs/rsync (login@peer.mesh).
#[cfg(target_os = "linux")]
pub(crate) fn l3_dest(info: &PeerSshInfo) -> Option<String> {
    let peer = peer_from_ssh_host_alias(&info.host);
    let (mesh_host, addr) = l3_mesh_addr(peer, info.rport)?;

    // Retry with increasing timeouts (like run_ssh does with revive+poll).
    // A single 600ms probe is too aggressive - overlay may be temporarily slow.
    for attempt in 0..3 {
        if probe_sshd(addr, std::time::Duration::from_millis(1000)) {
            return Some(format!("{}@{mesh_host}", info.login));
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    None
}

pub async fn ssh_cmd(server: &str, peer: &str, extra: &[String], relay: bool) -> Result<()> {
    let peer = peer.strip_suffix(".mesh").unwrap_or(peer);

    // CERT MODE: `shell --ssh` authenticates with an ephemeral certificate,
    // so this bootstrap fetches host keys + sshd status only and installs
    // NOTHING into the peer's authorized_keys.
    let rport: u16 = std::env::var("TUNLION_SSH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(22);
    let info = ensure_peer_bootstrap_port(server, peer, relay, rport, true).await?;

    let code = run_ssh(
        server,
        peer,
        relay,
        &info.host,
        &info.login,
        info.rport,
        extra,
        true,
    )
    .await?;

    // A cached skip that failed at the ssh layer (connect/auth, exit 255) may mean
    // the device rotated its key/host-key or revoked the cap. Invalidate, run a
    // real bootstrap, and retry ssh ONCE.
    if code == 255 && info.took_fast_path {
        crate::ui::say(&format!("tunlion: re-authenticating with '{peer}'..."));
        let retry = rebootstrap_peer(server, peer, relay, true).await?;
        // revive=false: don't pay the L3 revive-wait twice on the same invocation.
        let code = run_ssh(
            server,
            peer,
            relay,
            &retry.host,
            &retry.login,
            retry.rport,
            extra,
            false,
        )
        .await?;
        ssh_failed_hint(peer, code);
        std::process::exit(code);
    }
    ssh_failed_hint(peer, code);
    std::process::exit(code);
}

/// ssh exit 255 is ssh's own connect/session failure (no sshd reachable, timed
/// out, auth) - distinct from a remote command's non-zero exit. In that case point
/// the user at the tunlion-native shell, which needs no sshd and survives repairs.
fn ssh_failed_hint(peer: &str, code: i32) {
    if code == 255 {
        crate::ui::say(&crate::ui::paint(
            crate::ui::Tone::Dim,
            &format!(
                "  tip: `tunlion {peer}` opens a tunlion shell instead (no sshd needed, survives link repairs)"
            ),
        ));
    }
}

/// Confirm an sshd is reachable on `rport` before spawning ssh, so it fails fast
/// with a clear message instead of hanging on a refused/black-holed connection.
/// A beta.20+ peer already `reported` it in the bootstrap ack; for an older peer
/// (`None`) fall back to a quick client-side probe over the warm link, which works
/// regardless of the peer's version. Only a DEFINITE "no sshd" stops us; an
/// inconclusive probe proceeds (never make ssh worse than before).
async fn ensure_sshd(peer: &str, rport: u16, reported: Option<bool>) {
    let sshd = match reported {
        Some(b) => Some(b),
        #[cfg(unix)]
        None => probe_sshd_warm(peer, rport).await,
        #[cfg(not(unix))]
        None => None,
    };
    if sshd != Some(false) {
        return;
    }
    crate::ui::problem(
        &format!("tunlion shell --ssh: no sshd on '{peer}'"),
        &format!(
            "'{peer}' is reachable, but nothing is listening on localhost:{rport} for ssh. \
             (sshd may be bound to a non-localhost address like the mesh ULA; \
             `tunlion shell --ssh` connects to localhost:{rport} on the peer.)",
        ),
        &[
            format!("start an sshd on '{peer}' listening on localhost (or all interfaces)"),
            format!(
                "set {} to a different port",
                crate::ui::paint(crate::ui::Tone::Brand, "TUNLION_SSH_PORT")
            ),
            format!(
                "use {} for a shell that needs no sshd",
                crate::ui::paint(crate::ui::Tone::Brand, &format!("tunlion shell {peer}"))
            ),
        ],
    );
    std::process::exit(1);
}

/// Client-side "is there an sshd on `peer:rport`" probe over the daemon's WARM
/// link only (fast, never a cold establish, so it can't hang). Opens one L2
/// stream and reads: an immediate EOF means the acceptor's local dial was refused
/// (no listener); any bytes (the SSH banner) mean a listener is there. No warm
/// link or no banner in time -> `None` (unknown, caller proceeds). Works against
/// any peer version, since it relies only on the old l2-open/l2-close path.
#[cfg(unix)]
async fn probe_sshd_warm(peer: &str, rport: u16) -> Option<bool> {
    use tokio::io::AsyncReadExt;
    let mut s = crate::ctl::try_open(peer, rport).await?;
    let mut buf = [0u8; 8];
    match tokio::time::timeout(std::time::Duration::from_secs(3), s.read(&mut buf)).await {
        Ok(Ok(0)) => Some(false),  // refused: stream closed before any byte
        Ok(Ok(_)) => Some(true),   // a listener answered (sshd banner)
        Ok(Err(_)) => Some(false), // stream error: treat as unreachable
        Err(_) => None,            // no banner in time: inconclusive, don't block
    }
}

#[cfg(test)]
mod ssh_host_alias_tests {
    use super::*;

    /// The alias is on-disk format: pinned by the SHA-256 of the prefix
    /// (`printf '%s' '<prefix>' | sha256sum`), which a find-and-replace cannot
    /// keep in step.
    #[test]
    fn writer_uses_the_frozen_prefix() {
        use sha2::{Digest, Sha256};
        let got: String = Sha256::digest(SSH_HOST_ALIAS_PREFIX.as_bytes())
            .as_slice()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, "3968f8daf6d3c64a6f999b30e787260f3a254279af6cda2b611a1e31183d66be");
        assert_eq!(ssh_host_alias("laptop"), format!("{SSH_HOST_ALIAS_PREFIX}laptop"));
    }

    #[test]
    fn reader_maps_the_alias_back_to_its_peer() {
        assert_eq!(peer_from_ssh_host_alias(&ssh_host_alias("laptop")), "laptop");
        assert_eq!(peer_from_ssh_host_alias("tunlion-laptop"), "laptop");
        assert_eq!(peer_from_ssh_host_alias("laptop"), "laptop");
        // Any other prefix is not ours and is left as it is.
        assert_eq!(peer_from_ssh_host_alias("filament-laptop"), "filament-laptop");
    }
}

