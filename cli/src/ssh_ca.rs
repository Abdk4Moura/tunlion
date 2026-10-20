//! Client half of the SSH CA path (`tunlion shell --ssh`).
//!
//! The signer moved to `filament_peerloop::ssh_ca`: request validation, the
//! shared shell gate, the grant/ceiling/serial/ledger order, the pinned
//! `ssh-keygen` argv and the refusal/audit frames are library code now. This
//! file keeps the initiator: the ephemeral key, the link, `ssh-sign-request`
//! and writing the cert beside the key. The moved names are re-exported under
//! their old paths, and the three setting/user wrappers below bind the CLI's
//! host facts for the client half and the existing tests.

use anyhow::{bail, Result};

use filament_peerloop::ssh_ca::SshCaHost as _;

pub(crate) use filament_peerloop::ssh_ca::{
    build_sign_argv, ca_key_path, check_ca_key, check_ephemeral_pubkey, clamp_validity_secs,
    daemon_username_from, format_issuance, grant_expiry_secs as grant_expiry_secs_in,
    is_single_name, issued_path, load_issued, next_serial, parse_sign_request, parse_ttl_secs,
    read_serial, record_issuance, refuse_resign, secure_tempdir, serial_path,
    validity_interval, write_serial, IssuedCert, SignRequest, CERT_SKEW_SECS,
    CERT_TTL_DEFAULT_SECS, CERT_TTL_HARD_MAX_SECS,
};
#[cfg(feature = "ssh-sign")]
pub(crate) use filament_peerloop::ssh_ca::sign;

/// The CLI's host facts for the ssh-certificate signer: settings, the serving
/// user, the device record's legacy expiry and the capability store.
pub(crate) struct CliSshCaHost;

impl filament_peerloop::ssh_ca::SshCaHost for CliSshCaHost {
    fn config_dir(&self) -> std::path::PathBuf {
        crate::settings::config_dir()
    }
    fn cert_ttl_raw(&self) -> Option<String> {
        let setting = crate::settings::find("ssh.cert_ttl")?;
        let (raw, _) = crate::settings::resolve(setting, None);
        Some(raw)
    }
    fn shell_user(&self) -> Option<String> {
        crate::settings::get_str("shell-user", None)
    }
    fn serving_user(&self) -> Option<String> {
        crate::platform::current_username()
    }
    fn device_cap_expiry(&self, name: &str, capability: &str) -> Option<u64> {
        let raw =
            std::fs::read_to_string(crate::settings::config_dir().join("devices.json")).ok()?;
        let arr: Vec<serde_json::Value> = serde_json::from_str(&raw).ok()?;
        arr.iter()
            .find(|d| d["name"].as_str() == Some(name))
            .and_then(|d| d["capExpires"][capability].as_u64())
    }
    fn cap_store(&self) -> Vec<serde_json::Value> {
        crate::capability::load_cap_store(&crate::settings::config_dir())
    }
}

/// Resolve the configured ttl through the settings registry (default 1h).
pub(crate) fn resolve_cert_ttl_secs() -> Result<u64> {
    filament_peerloop::ssh_ca::resolve_cert_ttl_secs(
        crate::ssh_ca::CliSshCaHost.cert_ttl_raw().as_deref(),
    )
}

/// Resolve the serving user for signing (thin wrapper over the pure core).
pub(crate) fn daemon_username() -> Option<String> {
    let su = crate::settings::get_str("shell-user", None);
    // The password database, not $USER: a daemon started without a login
    // environment (cron, a container, `env -i`) has no $USER, and arming then
    // failed with "cannot determine serving user" on a machine that knew.
    daemon_username_from(su.as_deref(), crate::platform::current_username().as_deref())
}

/// The single validated principal used EVERYWHERE.
pub(crate) fn valid_principal() -> Result<String> {
    filament_peerloop::ssh_ca::valid_principal(&CliSshCaHost)
}

/// Test/caller compatibility: the old config-dir signature over a host bound to
/// that directory (the tests build fixtures there).
#[allow(dead_code)]
pub(crate) fn grant_expiry_secs(
    config_dir: &std::path::Path,
    device_name: &str,
    user_pub: Option<[u8; 32]>,
    device_pub: Option<[u8; 32]>,
    now_secs: u64,
) -> Option<u64> {
    struct DirHost<'a>(&'a std::path::Path);
    impl filament_peerloop::ssh_ca::SshCaHost for DirHost<'_> {
        fn config_dir(&self) -> std::path::PathBuf {
            self.0.to_path_buf()
        }
        fn cert_ttl_raw(&self) -> Option<String> {
            None
        }
        fn shell_user(&self) -> Option<String> {
            None
        }
        fn serving_user(&self) -> Option<String> {
            None
        }
        fn device_cap_expiry(&self, name: &str, capability: &str) -> Option<u64> {
            let raw = std::fs::read_to_string(self.0.join("devices.json")).ok()?;
            let arr: Vec<serde_json::Value> = serde_json::from_str(&raw).ok()?;
            arr.iter()
                .find(|d| d["name"].as_str() == Some(name))
                .and_then(|d| d["capExpires"][capability].as_u64())
        }
        fn cap_store(&self) -> Vec<serde_json::Value> {
            crate::capability::load_cap_store(self.0)
        }
    }
    grant_expiry_secs_in(&DirHost(config_dir), device_name, user_pub, device_pub, now_secs)
}

/// This device's asserted id for sign requests: the configured name (env
/// override wins, same resolution as everywhere else).
pub(crate) fn local_device_id() -> String {
    crate::settings::get_str("name", None).unwrap_or_else(|| "unknown".to_string())
}

/// Identity files for one cert-authenticated ssh invocation (both under the
/// ephemeral tmpdir, removed with it).
pub(crate) struct CertIdentity {
    pub key_path: std::path::PathBuf,
    pub cert_path: std::path::PathBuf,
}

/// Full client side: bring up a link, request the cert, write it next to
/// the ephemeral key. Fail closed (clear error, no managed-key fallback):
/// silently downgrading would make the CA a decoration an attacker defeats
/// by blocking sign responses.
pub(crate) async fn acquire_ssh_cert(
    server: &str,
    peer: &str,
    relay: bool,
    eph: &EphemeralKey,
) -> Result<CertIdentity> {
    let ttl = resolve_cert_ttl_secs()?;
    let device_id = local_device_id();
    let inner = crate::l2::bring_up_to_known(server, peer, relay, "ssh-sign");
    let (t, mut rx, guard, _diag) =
        match tokio::time::timeout(std::time::Duration::from_secs(45), inner).await {
            Ok(inner) => inner?,
            Err(_) => {
                anyhow::bail!("connect timeout: couldn't reach '{peer}' in 45s");
            }
        };
    guard.forget();
    let mux = crate::l2::Mux::new(t.clone(), crate::host_impl::cli_host());
    let sid = mux.alloc_sid();
    let cert = request_cert(&t, &mut rx, sid, &device_id, eph.pubkey_text(), ttl).await?;
    let cert_path = eph.dir().join("key-cert.pub");
    std::fs::write(&cert_path, format!("{cert}\n"))?;
    Ok(CertIdentity { key_path: eph.private_path(), cert_path })
}

/// Request a certificate over an established link: send the open, wait
/// bounded (10s, like exec's ack) for the cert, a refusal, or silence.
/// Pure control round trip (no stream registered); the sid only correlates.
pub(crate) async fn request_cert(
    t: &std::sync::Arc<dyn crate::net::Transport>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::net::Ev>,
    sid: u32,
    device_id: &str,
    pubkey: &str,
    ttl_secs: u64,
) -> Result<String> {
    t.send_control(&serde_json::json!({
        "type": "ssh-sign-request",
        "sid": sid,
        "device_id": device_id,
        "ephemeral_pubkey": pubkey,
        "ttl_secs": ttl_secs,
    }))
    .await?;
    let cert: Result<String, String> = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let ev = match rx.recv().await {
                Some(ev) => ev,
                None => break Err("peer closed the sign stream before answering".to_string()),
            };
            match ev {
                crate::net::Ev::Control(_pid, v) => {
                    let is_ours = v.get("sid").and_then(|s| s.as_u64()) == Some(sid as u64);
                    match v.get("type").and_then(|x| x.as_str()) {
                        Some("ssh-sign-response") if is_ours => {
                            match v.get("cert").and_then(|c| c.as_str()) {
                                Some(c) if !c.is_empty() => break Ok(c.to_string()),
                                _ => break Err("peer answered without a cert".to_string()),
                            }
                        }
                        Some("l2-close") if is_ours => {
                            break Err(v
                                .get("err")
                                .and_then(|e| e.as_str())
                                .unwrap_or("closed")
                                .to_string());
                        }
                        _ => {}
                    }
                }
                crate::net::Ev::Chunk(_pid, got, _offset, data) => {
                    // No streams in this exchange, but never let a frame sit
                    // unread: feed the mux like every other pump does.
                    let _ = (got, data);
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "no answer to ssh-sign-request - peer may run a build without SSH CA"
        )
    })?;
    cert.map_err(|reason| anyhow::anyhow!("ssh sign refused by peer: {reason}"))
}

/// Ephemeral client key: a fresh ed25519 keypair in a 0700 tmpdir, unique
/// per invocation. Removal is a scope guard with three triggers, because no
/// single one covers every exit: Drop covers returns/unwinds, an explicit
/// `cleanup()` covers `process::exit` (which skips Drop) on the normal
/// path, and `spawn_cleanup_on_signal` covers SIGINT/SIGTERM. All three are
/// idempotent (double remove is ignored), so overlap is harmless.
pub(crate) struct EphemeralKey {
    dir: std::path::PathBuf,
    pubkey: String,
}

impl EphemeralKey {
    /// Generate with the real ssh-keygen.
    pub(crate) async fn generate() -> Result<Self> {
        Self::generate_with(std::path::Path::new("ssh-keygen")).await
    }

    /// Generate with an injectable keygen binary (tests pass a stub).
    pub(crate) async fn generate_with(keygen_bin: &std::path::Path) -> Result<Self> {
        let dir = secure_tempdir("ssh-ephemeral")?;
        let cleanup_on_err = || {
            let _ = std::fs::remove_dir_all(&dir);
        };
        let key = dir.join("key");
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::platform::tokio_command(keygen_bin)
                .kill_on_drop(true)
                .args([
                    "-q",
                    "-t",
                    "ed25519",
                    "-f",
                    &key.to_string_lossy(),
                    "-N",
                    "",
                    "-C",
                    "tunlion-ephemeral",
                ])
                .stdin(std::process::Stdio::null())
                .status(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("ephemeral keygen timed out"))?
        .map_err(|e| anyhow::anyhow!("ephemeral keygen failed to run: {e}"));
        let status = match status {
            Ok(s) => s,
            Err(e) => {
                cleanup_on_err();
                return Err(e);
            }
        };
        if !status.success() {
            cleanup_on_err();
            bail!(
                "ephemeral keygen refused (exit {})",
                status.code().unwrap_or(-1)
            );
        }
        let pubkey = std::fs::read_to_string(dir.join("key.pub")).map_err(|_| {
            cleanup_on_err();
            anyhow::anyhow!("ephemeral keygen wrote no pubkey; refusing")
        })?;
        Ok(Self { dir, pubkey: pubkey.trim().to_string() })
    }

    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    pub(crate) fn private_path(&self) -> std::path::PathBuf {
        self.dir.join("key")
    }

    pub(crate) fn pubkey_text(&self) -> &str {
        &self.pubkey
    }

    /// Idempotent removal (all three guard triggers funnel here).
    pub(crate) fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Signal watchdog: remove the ephemeral dir on SIGINT/SIGTERM, then exit
/// with the conventional code. Subscribing replaces the default disposition
/// (the process would otherwise survive the signal), so exiting here is
/// required, not optional. The caller aborts the handle on the normal path.
/// Unix watches INT+TERM; other platforms watch Ctrl-C.
pub(crate) fn spawn_cleanup_on_signal(dir: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut interrupt = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut terminate = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let code = tokio::select! {
                _ = interrupt.recv() => 130,
                _ = terminate.recv() => 143,
            };
            let _ = std::fs::remove_dir_all(&dir);
            crate::exit_codes::interrupted_exit(code);
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = std::fs::remove_dir_all(&dir);
                crate::exit_codes::interrupted_exit(130);
            }
        }
    })
}

/// Mint the CA key idempotently (0700 dir, 0600 key, 0644 pub): exists →
/// return as-is (perm problems fail closed later at sign time); missing →
/// ssh-keygen, deleting a half-created key on failure. ssh-keygen itself
/// missing refuses (the caller warns and continues: init must not fail for an
/// SSH-CA nicety, and signing fails closed with a clear error).
pub(crate) async fn ensure_ca_key_with(
    config_dir: &std::path::Path,
    keygen_bin: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let key = ca_key_path(config_dir);
    if key.exists() {
        return Ok(key);
    }
    if let Some(dir) = key.parent() {
        crate::platform::create_private_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let created = !key.exists();
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::platform::tokio_command(keygen_bin)
            .kill_on_drop(true)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "tunlion-ca", "-f"])
            .arg(&key)
            .stdin(std::process::Stdio::null())
            .status(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("CA mint timed out running ssh-keygen"))?
    .map_err(|e| anyhow::anyhow!("CA mint failed to run ssh-keygen: {e}"))?;
    if !status.success() {
        if created {
            let _ = std::fs::remove_file(&key);
            let _ = std::fs::remove_file(key.with_extension("pub"));
        }
        bail!("ssh-keygen refused to mint the CA key");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
        // ssh-keygen creates the .pub under the umask, which made it 0666 under
        // `umask 0000`: anyone could swap the CA public key sshd is told to
        // trust. Only this user and root (sshd) need to read it.
        let _ = std::fs::set_permissions(
            key.with_extension("pub"),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(key)
}

/// Mint with the real ssh-keygen.
pub(crate) async fn ensure_ca_key(config_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    ensure_ca_key_with(config_dir, std::path::Path::new("ssh-keygen")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parses_seconds_and_durations_then_clamps() {
        assert_eq!(parse_ttl_secs("3600").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("30m").unwrap(), 1800);
        assert_eq!(parse_ttl_secs("1h").unwrap(), 3600);
        assert_eq!(parse_ttl_secs("48h").unwrap(), 86_400);
        assert!(parse_ttl_secs("0").is_err());
        assert!(parse_ttl_secs("soon").is_err());
        assert!(parse_ttl_secs("").is_err());
    }

    #[test]
    fn clamp_takes_min_and_rejects_zero() {
        assert_eq!(clamp_validity_secs(None, 60, 3600).unwrap(), 60);
        assert_eq!(clamp_validity_secs(Some(30), 3600, 3600).unwrap(), 30);
        assert_eq!(clamp_validity_secs(None, 99_999, 3600).unwrap(), 3600);
        assert!(clamp_validity_secs(None, 0, 3600).is_err());
    }

    #[test]
    fn validity_is_relative_with_skew() {
        // Pure relative form: no timestamps rendered, nothing TZ-dependent.
        assert_eq!(validity_interval(3600), "-5m:+3600s");
        assert_eq!(validity_interval(60), "-5m:+60s");
    }

    #[test]
    fn grant_expiry_reads_both_stores_most_restrictive_wins() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-exp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        // Absent everywhere: unexpiring.
        assert_eq!(grant_expiry_secs(&dir, "boxA", None, None, now), None);
        // Legacy device store: 10-minute shell grant.
        std::fs::write(
            dir.join("devices.json"),
            r#"[{"name":"boxA","secret":"x","caps":["shell"],"capExpires":{"shell":1800000600}}]"#,
        )
        .unwrap();
        let got = grant_expiry_secs(&dir, "boxA", None, None, now).expect("legacy expiry");
        assert!(got <= 600 && got >= 590, "10-min grant clamps ttl, got {got}");
        // Fleet cap store with a tighter 5-minute shell grant for the peer key.
        let upub = [0x77u8; 32];
        let grantor = "aa".repeat(32);
        let row = |version: u64, expires: u64| {
            format!(
                r#"{{"type":"cap_grant","grantor":"{grantor}","version":{version},"resource":"self","permissions":["shell"],"target":"{}","expires":{expires}}}"#,
                hex::encode(upub)
            )
        };
        std::fs::write(
            dir.join("caps.json"),
            format!("[{0},{1}]", row(1, now - 10), row(2, now + 300)),
        )
        .unwrap();
        // Expired v1 must NOT shadow live v2: highest version per grantor wins.
        let got = grant_expiry_secs(&dir, "boxA", Some(upub), None, now).expect("fleet expiry");
        assert!(got <= 300 && got >= 290, "v2 window wins over expired v1, got {got}");
        // A per-device grant names the DEVICE key (target kind 0x01). Its
        // window must bound the cert too, and only for that device key.
        let dpub = [0x55u8; 32];
        let dev_row = format!(
            r#"{{"type":"cap_grant","grantor":"{grantor}","version":3,"resource":"self","permissions":["shell"],"targetKind":1,"target":"{}","expires":{}}}"#,
            hex::encode(dpub),
            now + 120
        );
        std::fs::write(
            dir.join("caps.json"),
            format!("[{0},{1}]", row(2, now + 300), dev_row),
        )
        .unwrap();
        let got = grant_expiry_secs(&dir, "boxA", Some(upub), Some(dpub), now)
            .expect("device-targeted expiry");
        assert!(got <= 120 && got >= 110, "device grant window is read, got {got}");
        let other = grant_expiry_secs(&dir, "boxA", Some(upub), Some([0x56u8; 32]), now)
            .expect("user-wide expiry only");
        assert!(
            other <= 300 && other >= 290,
            "another device's grant must not bound this one, got {other}"
        );
        // Expired clamps to zero (the validity clamp then refuses).
        std::fs::write(
            dir.join("devices.json"),
            r#"[{"name":"boxA","secret":"x","caps":["shell"],"capExpires":{"shell":1799999999}}]"#,
        )
        .unwrap();
        let _ = std::fs::remove_file(dir.join("caps.json"));
        assert_eq!(grant_expiry_secs(&dir, "boxA", None, None, now), Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relative_validity_accepted_under_foreign_tz() {
        // ssh-keygen must accept the relative -V under a non-UTC zone (the
        // old absolute stamps shifted with TZ). Nothing in this tree reads
        // localtime, so the set_var window below cannot disturb other tests.
        let prior = std::env::var("TZ").ok();
        unsafe { std::env::set_var("TZ", "Asia/Lagos") };
        let dir =
            std::env::temp_dir().join(format!("fil-sshca-tz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = (|| -> anyhow::Result<()> {
            crate::platform::command("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join("ca"))
                .args(["-N", ""])
                .status()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            // ssh-keygen refuses a 0644 signing key (and so does the
            // product's own check_ca_key): tighten the fixture like the
            // real mint path does.
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    dir.join("ca"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            crate::platform::command("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-f"])
                .arg(dir.join("key"))
                .args(["-N", ""])
                .status()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let out = crate::platform::command("ssh-keygen")
                .args([
                    "-q", "-s", &dir.join("ca").to_string_lossy(), "-I", "t",
                    "-n", "root", "-V", &validity_interval(3600), "-z", "1",
                ])
                .arg(dir.join("key.pub"))
                .output()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            assert!(
                out.status.success(),
                "relative -V must be accepted: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let out = crate::platform::command("ssh-keygen")
                .args(["-L", "-f"])
                .arg(dir.join("key-cert.pub"))
                .output()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let text = String::from_utf8_lossy(&out.stdout);
            // Bounds, not just presence: parse the window endpoints as naive
            // datetimes and require width == ttl + skew (3900s). Both ends
            // render in the same zone, so the zone cancels out -- this holds
            // under ANY TZ, which is exactly the regression being pinned
            // (absolute stamps used to shift).
            let line = text
                .lines()
                .find(|l| l.trim_start().starts_with("Valid:"))
                .ok_or_else(|| anyhow::anyhow!("no Valid line: {text}"))?;
            let bounds: Vec<&str> = line.split_whitespace().collect();
            let from = bounds.iter().position(|w| *w == "from").and_then(|i| bounds.get(i + 1));
            let to = bounds.iter().position(|w| *w == "to").and_then(|i| bounds.get(i + 1));
            let (Some(from), Some(to)) = (from, to) else {
                anyhow::bail!("unparseable Valid line: {line}");
            };
            fn naive_epoch(s: &str) -> anyhow::Result<i64> {
                // "2026-09-14T15:57:40" (ssh-keygen renders no zone here).
                let (d, t) = s.split_once('T').ok_or_else(|| anyhow::anyhow!("no T in {s}"))?;
                let d: Vec<i64> =
                    d.split('-').map(|x| x.parse().map_err(|_| anyhow::anyhow!("bad date"))).collect::<Result<_, _>>()?;
                let t: Vec<i64> =
                    t.split(':').map(|x| x.parse().map_err(|_| anyhow::anyhow!("bad time"))).collect::<Result<_, _>>()?;
                if d.len() != 3 || t.len() != 3 {
                    anyhow::bail!("bad stamp {s}");
                }
                // Days-from-civil (Howard Hinnant), then seconds.
                let (y, m, day) = (d[0], d[1], d[2]);
                let y = if m <= 2 { y - 1 } else { y };
                let era = if y >= 0 { y } else { y - 399 } / 400;
                let yoe = y - era * 400;
                let mp = (m + 9) % 12;
                let doy = (153 * mp + 2) / 5 + day - 1;
                let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
                Ok((era * 146097 + doe - 719468) * 86400 + t[0] * 3600 + t[1] * 60 + t[2])
            }
            let width = naive_epoch(to)? - naive_epoch(from)?;
            assert_eq!(width, 3900, "window must be ttl(3600) + skew(300): {line}");
            Ok(())
        })();
        match prior {
            Some(v) => unsafe { std::env::set_var("TZ", v) },
            None => unsafe { std::env::remove_var("TZ") },
        }
        let _ = std::fs::remove_dir_all(&dir);
        r.unwrap();
    }

    #[test]
    fn sign_argv_pins_everything() {
        let argv = build_sign_argv(
            std::path::Path::new("/ca"),
            std::path::Path::new("/w/key.pub"),
            "boxA",
            "daemon",
            "20260914000000:20260914010000",
            7,
        );
        assert_eq!(
            argv,
            vec![
                "-s", "/ca", "-I", "boxA", "-n", "daemon", "-V",
                "20260914000000:20260914010000", "-z", "7", "-O", "clear",
                "-O", "permit-pty", "/w/key.pub"
            ]
        );
        assert!(!argv.iter().any(|a| a.contains(' ') && !a.contains('/')),
            "no joined/shell-quoted values: {argv:?}");
    }

    #[test]
    fn secure_tempdir_is_unique_and_private() {
        let a = secure_tempdir("probe").expect("creates");
        let b = secure_tempdir("probe").expect("creates again");
        assert_ne!(a, b, "same prefix must still yield distinct dirs");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [&a, &b] {
                let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "tmpdir must be 0700");
            }
        }
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn ephemeral_accepts_only_bare_ed25519() {
        // Real ed25519 body (decodes to the ssh-ed25519 wire prefix).
        let good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5 stunt";
        assert!(check_ephemeral_pubkey(good).is_ok());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5").is_ok());
        assert!(check_ephemeral_pubkey("ssh-rsa AAAAB3xyz box").is_err());
        assert!(check_ephemeral_pubkey("no-touch-cert-request ssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("").is_err());
        // Smuggling shapes: interior newline/CR, single field, four fields.
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz\nssh-ed25519 AAAAC3xyz").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAAC3xyz\r").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 AAAA b c d").is_err());
        // Valid prefix on non-key bytes, and non-base64 body.
        assert!(check_ephemeral_pubkey("ssh-ed25519 !!!not-base64!!!").is_err());
        assert!(check_ephemeral_pubkey("ssh-ed25519 c3NoLXJzYQ==").is_err());
    }

    #[test]
    fn serials_monotonic_and_resign_bound_to_device() {
        let recs = vec![
            IssuedCert { pubkey: "k1".into(), device_id: "a".into(), serial: 4, expires: 9_999_999_999 },
            IssuedCert { pubkey: "k2".into(), device_id: "b".into(), serial: 9, expires: 9_999_999_999 },
        ];
        assert_eq!(next_serial(&recs), 10);
        assert_eq!(next_serial(&[]), 1);
        assert!(refuse_resign(&recs, "k1", "a").is_ok());
        assert!(refuse_resign(&recs, "k3", "zzz").is_ok());
        assert!(refuse_resign(&recs, "k1", "EVIL").is_err());
    }

    #[test]
    fn issuance_line_carries_contract_fields() {
        let line = format_issuance("boxA", "daemon", 7, "20260914010000");
        for field in ["boxA", "daemon", "7", "20260914010000"] {
            assert!(line.contains(field), "missing {field}: {line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_requires_0600() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let strict = dir.join("ca");
        let loose = dir.join("ca-loose");
        let missing = dir.join("ca-missing");
        std::fs::write(&strict, "x").unwrap();
        std::fs::write(&loose, "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&strict, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_ca_key(&strict).is_ok());
        assert!(check_ca_key(&loose).is_err());
        assert!(check_ca_key(&missing).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_sign_request_accepts_shape_rejects_garbage() {
        let good = serde_json::json!({
            "type": "ssh-sign-request", "sid": 1,
            "device_id": "boxA",
            "ephemeral_pubkey": "ssh-ed25519 AAAAC3xyz",
            "ttl_secs": 3600u64,
        });
        let req = parse_sign_request(&good).expect("parses");
        assert_eq!(req.device_id, "boxA");
        assert_eq!(req.ttl_secs, 3600);
        for bad in [
            serde_json::json!({}),
            serde_json::json!({"device_id": "", "ephemeral_pubkey": "k", "ttl_secs": 1u64}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "", "ttl_secs": 1u64}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "k"}),
            serde_json::json!({"device_id": "a", "ephemeral_pubkey": "k", "ttl_secs": "soon"}),
        ] {
            assert!(parse_sign_request(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn single_name_rejects_compounds_and_paths() {
        assert!(is_single_name("daemon"));
        assert!(is_single_name("svc-1"));
        for bad in ["", "a,b", "a b", "a/b", "\tlead", "trail\n"] {
            assert!(!is_single_name(bad), "{bad:?} must not certify");
        }
    }

    #[test]
    fn daemon_username_prefers_setting_then_env() {
        assert_eq!(daemon_username_from(Some("svc"), Some("bob")), Some("svc".to_string()));
        assert_eq!(daemon_username_from(None, Some("bob")), Some("bob".to_string()));
        assert_eq!(daemon_username_from(Some(""), Some("bob")), Some("bob".to_string()));
        assert_eq!(daemon_username_from(None, None), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ca_mint_is_idempotent_and_needs_keygen() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-mint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Missing keygen binary refuses without creating anything.
        assert!(ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).await.is_err());
        assert!(!ca_key_path(&dir).exists());
        // Stub that behaves like ssh-keygen -f (writes key + pub).
        let stub = dir.join("stub-keygen");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &stub,
            "#!/bin/sh\nf=\"\";prev=\"\";for a in \"$@\";do if [ \"$prev\" = \"-f\" ];then f=\"$a\";fi;prev=\"$a\";done\necho PRIVATE > \"$f\"\necho PUBLIC > \"$f.pub\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = ensure_ca_key_with(&dir, &stub).await.expect("stub mints");
        assert_eq!(key, ca_key_path(&dir));
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "minted CA key must be 0600");
        let mode = std::fs::metadata(dir.join("ssh")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "ssh dir must be 0700");
        // Second run returns the same key without touching it.
        let again = ensure_ca_key_with(&dir, std::path::Path::new("/bin/false")).await.expect("idempotent");
        assert_eq!(again, key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ledger_persists_serial_prunes_dead_and_roundtrips() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        // Absent serial falls back to record max + 1 (fresh store: 1).
        assert_eq!(read_serial(&dir, &[]), 1);
        write_serial(&dir, 41).expect("serial persists");
        assert_eq!(read_serial(&dir, &[]), 41);
        // Garbage reads as absent (fail closed downstream, never zero).
        std::fs::write(serial_path(&dir), "bogus").unwrap();
        assert_eq!(read_serial(&dir, &[]), 1);
        // Record round trip; expired rows prune on load.
        record_issuance(
            &dir,
            &IssuedCert { pubkey: "k".into(), device_id: "a".into(), serial: 41, expires: now + 100 },
            now,
        )
        .expect("record persists");
        record_issuance(
            &dir,
            &IssuedCert { pubkey: "old".into(), device_id: "a".into(), serial: 40, expires: now - 1 },
            now,
        )
        .expect("record persists");
        let v = load_issued(&dir, now);
        assert_eq!(v.len(), 1, "expired rows prune");
        assert_eq!(v[0].serial, 41);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ephemeral_key_is_0700_fresh_and_cleaned() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-stub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-keygen");
        std::fs::write(
            &stub,
            "#!/bin/sh\nf=\"\";prev=\"\";for a in \"$@\";do if [ \"$prev\" = \"-f\" ];then f=\"$a\";fi;prev=\"$a\";done\necho PRIVATE > \"$f\"\necho 'ssh-ed25519 AAAAC3test stub' > \"$f.pub\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = EphemeralKey::generate_with(&stub).await.expect("stub keygen succeeds");
        assert_eq!(key.pubkey_text(), "ssh-ed25519 AAAAC3test stub");
        let mode = std::fs::metadata(key.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "ephemeral tmpdir must be 0700");
        assert!(key.private_path().is_file());
        let path = key.dir().to_path_buf();
        drop(key);
        assert!(!path.exists(), "scope guard removes the tmpdir on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ephemeral_keygen_failure_is_an_error() {
        assert!(EphemeralKey::generate_with(std::path::Path::new("/bin/false")).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sign_refuses_on_nonzero_and_missing_output() {
        let dir = std::env::temp_dir().join(format!("fil-sshca-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIILzAe0+efgsfT1oeQP5UeMfhXaoRd/jKUNU9Ol2oub5 stunt";
        // Nonzero exit refuses with the stderr attached.
        let e = sign(
            std::path::Path::new("/bin/false"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("refused to sign"), "{e}");
        // Zero exit but no cert file refuses too (never an empty cert).
        let e = sign(
            std::path::Path::new("/bin/true"),
            std::path::Path::new("/ca"),
            key, "boxA", "daemon", "V", 1, &dir,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("wrote no cert"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
