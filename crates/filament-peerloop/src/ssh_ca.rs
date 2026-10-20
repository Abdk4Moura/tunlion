//! B-side SSH certificate signer (`tunlion shell --ssh` via local CA).
//!
//! Moved out of `cli/src/ssh_ca.rs`: the request validation, the shared shell
//! gate, the grant/ceiling/serial/ledger order, the pinned `ssh-keygen` argv and
//! the refusal/audit frames are the same code. The CLI keeps only the client
//! half (ephemeral key, link, request) and implements [`SshCaHost`] over its
//! settings/user/store facts.
//!
//! The daemon holds a permanent CA key (0600 beside the identity key) and signs
//! initiators' ephemeral ed25519 keys with `ssh-keygen -s`, pinning every flag
//! the contract requires. Fail-closed throughout: no key, bad perms, nonzero
//! ssh-keygen, missing cert output, garbage ttl, or a pubkey already signed for
//! another device all refuse with a clear error -- never a cert, never an
//! authorized_keys fallback.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::conn::Conn;
use crate::recv::dispatch::{park_on_deny, ParkKind, ParkedOpen};
use crate::shell_gate::{gather_shell_gate_inputs, ssh_gate_decision, ShellPolicy};
use filament_cap::capability::CAP_SHELL;
use filament_transport::net::Transport;

/// Hard max certificate lifetime: 24h, per contract. The setting clamps here.
pub const CERT_TTL_HARD_MAX_SECS: u64 = 86_400;
/// Default lifetime when unset: 1h (mirrors the setting default).
pub const CERT_TTL_DEFAULT_SECS: u64 = 3_600;
/// Skew allowance subtracted from validity start (late clocks, slow links).
pub const CERT_SKEW_SECS: u64 = 300;

/// The host facts the signer reads, and nothing else: where its state lives,
/// what the operator configured, who serves here, and the two stores the
/// validity clamp consults. The signing op itself stays in this module.
pub trait SshCaHost: Send + Sync {
    fn config_dir(&self) -> PathBuf;
    /// The raw `ssh.cert_ttl` setting, or `None` when unset.
    fn cert_ttl_raw(&self) -> Option<String>;
    /// The `shell-user` setting, if configured.
    fn shell_user(&self) -> Option<String>;
    /// The process user (password database on unix), if resolvable.
    fn serving_user(&self) -> Option<String>;
    /// The legacy `capExpires.<capability>` deadline for a device.
    fn device_cap_expiry(&self, name: &str, capability: &str) -> Option<u64>;
    /// The capability store exactly as its loader returns it.
    fn cap_store(&self) -> Vec<Value>;
}

/// Parse a ttl value (plain seconds or `30m`/`1h`/`1d` durations) and clamp
/// to the hard max. Zero, negative (unparseable), and garbage refuse --
/// signing with a guessed lifetime would over-grant against operator intent.
pub fn parse_ttl_secs(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        if secs == 0 {
            bail!("ssh cert ttl must be greater than zero");
        }
        return Ok(secs.min(CERT_TTL_HARD_MAX_SECS));
    }
    let secs = parse_duration_secs(trimmed)?;
    Ok(secs.min(CERT_TTL_HARD_MAX_SECS))
}

/// The CLI's duration grammar, moved with its only caller in this path.
fn parse_duration_secs(input: &str) -> Result<u64> {
    let (number, unit) = input.trim().split_at(input.trim().len().saturating_sub(1));
    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid duration '{input}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid duration '{input}', use e.g. 30m, 1h, or 1d"),
    };
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("duration too large"))?;
    if seconds == 0 {
        bail!("duration must be greater than zero");
    }
    Ok(seconds)
}

/// Resolve a configured ttl through the setting value (default 1h).
/// Garbage refuses (fail closed); the hard max applies after parsing.
pub fn resolve_cert_ttl_secs(raw: Option<&str>) -> Result<u64> {
    match raw {
        Some(raw) => parse_ttl_secs(raw),
        None => Ok(CERT_TTL_DEFAULT_SECS),
    }
}

/// Effective validity: min(grant remaining if known, requested ttl, setting).
/// All three are durations-from-now, so they compare directly. Requested 0
/// refuses (meaningless); the setting side is already clamped.
pub fn clamp_validity_secs(
    grant_remaining_secs: Option<u64>,
    requested_secs: u64,
    setting_secs: u64,
) -> Result<u64> {
    if requested_secs == 0 {
        bail!("ssh cert ttl must be greater than zero");
    }
    let mut out = requested_secs.min(setting_secs);
    if let Some(g) = grant_remaining_secs {
        out = out.min(g);
    }
    if out == 0 {
        bail!("ssh cert expires immediately under the clamp; refusing");
    }
    Ok(out)
}

/// Relative `-V` interval for ssh-keygen from a ttl: `-5m:+<ttl>s`. Pure
/// relative form, so there is NOTHING timezone-dependent anywhere in the
/// path (no timestamps rendered, nothing to shift under TZ=Asia/Lagos).
/// Verified live against ssh-keygen (seconds suffix accepted, validity
/// window correct); the skew allowance absorbs clock drift and slow links.
pub fn validity_interval(ttl_secs: u64) -> String {
    format!("-{}m:+{}s", CERT_SKEW_SECS / 60, ttl_secs)
}

/// Grant-expiry bound (relative seconds) from both stores: the legacy
/// device capExpires.shell for the name, plus fleet cap_grant ops naming the
/// peer's user key (target kind 0x00) or its device key (0x01, what a
/// per-device `grant` now signs). Most restrictive wins; absent everywhere means
/// unexpiring (None). Expired clamps to 0 via saturating_sub, which the
/// validity clamp then refuses. `now_secs` is a parameter (not read) so
/// tests pin time instead of racing it.
pub fn grant_expiry_secs(
    host: &dyn SshCaHost,
    device_name: &str,
    user_pub: Option<[u8; 32]>,
    device_pub: Option<[u8; 32]>,
    now_secs: u64,
) -> Option<u64> {
    let mut best: Option<u64> = None;
    let mut consider = |exp: u64| {
        best = Some(best.map_or(exp, |b: u64| b.min(exp)));
    };
    if let Some(e) = host.device_cap_expiry(device_name, "shell") {
        consider(e);
    }
    let user_key = user_pub.map(hex::encode);
    let device_key = device_pub.map(hex::encode);
    if user_key.is_some() || device_key.is_some() {
        // Highest-version row per (grantor, target kind) (dispatch.rs:1624
        // pattern): newer ops supersede, so an expired v1 must not shadow a
        // live v2 (and a revoked-then-regranted pair resolves to the live row,
        // because a revoke leaves a tombstone, which is not a `cap_grant`).
        // Across grantors and target kinds the tightest wins.
        let mut latest: std::collections::HashMap<(&str, u64), &Value> =
            std::collections::HashMap::new();
        let store = host.cap_store();
        for e in store.iter().filter(|e| {
            let wanted = match e["targetKind"].as_u64().unwrap_or(0) {
                0x00 => user_key.as_deref(),
                0x01 => device_key.as_deref(),
                _ => None,
            };
            e["type"].as_str() == Some("cap_grant")
                && e["resource"].as_str() == Some("self")
                && e["permissions"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|c| c.as_str() == Some("shell")))
                && wanted.is_some()
                && e["target"].as_str() == wanted
        }) {
            let g = (
                e["grantor"].as_str().unwrap_or(""),
                e["targetKind"].as_u64().unwrap_or(0),
            );
            let v = e["version"].as_u64().unwrap_or(0);
            let cur = latest
                .get(&g)
                .and_then(|c| c["version"].as_u64())
                .unwrap_or(0);
            if v >= cur {
                latest.insert(g, e);
            }
        }
        for e in latest.values() {
            if let Some(x) = e["expires"].as_u64() {
                consider(x);
            }
        }
    }
    best.map(|e| e.saturating_sub(now_secs))
}

/// Check the CA key file: must exist and (unix) be exactly 0600. A group- or
/// world-readable CA key refuses -- fail closed, never sign anyway.
pub fn check_ca_key(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("ssh CA key not found at {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "ssh CA key at {} has permissions {:o}, need 0600",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Refuse anything but a bare ed25519 pubkey, strictly: no newlines/CR
/// (log injection + multi-key smuggling), exactly 2-3 whitespace fields
/// (type, base64, optional comment), and the base64 must decode to the
/// ssh-ed25519 wire prefix (4-byte length 11 + "ssh-ed25519"). A textual
/// prefix match alone would bless `ssh-ed25519AAA...` garbage or a valid
/// prefix on non-key bytes; ssh-keygen would happily sign either.
pub fn check_ephemeral_pubkey(text: &str) -> Result<()> {
    if text.bytes().any(|b| b == b'\n' || b == b'\r') {
        bail!("ephemeral pubkey must be a single line");
    }
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 2 || fields.len() > 3 {
        bail!("ephemeral pubkey must have 2-3 fields");
    }
    if fields[0] != "ssh-ed25519" {
        bail!("only bare ed25519 ephemeral keys are signed");
    }
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(fields[1])
        .map_err(|_| anyhow!("ephemeral pubkey is not valid base64"))?;
    if raw.len() < 15 || raw[0..4] != [0, 0, 0, 11] || &raw[4..15] != b"ssh-ed25519" {
        bail!("ephemeral pubkey does not decode to an ssh-ed25519 key");
    }
    Ok(())
}

/// Exact pinned ssh-keygen argv: `-I` device id only, `-n` daemon user only
/// (single principal: commas/whitespace would certify extra names, so they
/// refuse here at the tool boundary, not just at the caller), absolute `-V`
/// interval, monotonic `-z` serial, `-O clear` + `-O permit-pty` and nothing
/// else. No shell involved (direct spawn by the caller).
pub fn build_sign_argv(
    ca_path: &Path,
    pubkey_file: &Path,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
) -> Vec<String> {
    vec![
        "-s".to_string(),
        ca_path.to_string_lossy().into_owned(),
        "-I".to_string(),
        key_id.to_string(),
        "-n".to_string(),
        principal.to_string(),
        "-V".to_string(),
        validity.to_string(),
        "-z".to_string(),
        serial.to_string(),
        "-O".to_string(),
        "clear".to_string(),
        "-O".to_string(),
        "permit-pty".to_string(),
        pubkey_file.to_string_lossy().into_owned(),
    ]
}

/// One issued-cert record: binds a pubkey to the device it was signed for,
/// so the same key is never re-signed for someone else. Carries its expiry
/// so dead entries prune instead of accumulating forever.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuedCert {
    pub pubkey: String,
    pub device_id: String,
    pub serial: u64,
    pub expires: u64,
}

/// Next monotonic serial: one past the max on record (starts at 1). The
/// counter additionally persists in its own file (below); the record max is
/// the fallback when that file is absent.
pub fn next_serial(records: &[IssuedCert]) -> u64 {
    records.iter().map(|r| r.serial).max().unwrap_or(0) + 1
}

/// Serial counter path (separate small file, not the record).
pub fn serial_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ssh_ca_serial")
}

/// Read the persisted serial, falling back to the record max. Garbage reads
/// as absent (fail closed downstream: a lost counter restarts at record
/// max + 1, never at zero over live serials).
pub fn read_serial(config_dir: &Path, records: &[IssuedCert]) -> u64 {
    std::fs::read_to_string(serial_path(config_dir))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| next_serial(records))
}

fn write_private_atomic(path: &Path, data: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        "{}.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Persist the NEXT serial atomically (temp + rename). Errors fail closed:
/// a serial that cannot be persisted must not be issued (a crash between
/// issue and persist would otherwise repeat it). No lock needed: issuance
/// runs inline in the daemon's single recv loop, so two signs cannot
/// interleave the read-increment-write.
pub fn write_serial(config_dir: &Path, next: u64) -> Result<()> {
    write_private_atomic(&serial_path(config_dir), &next.to_string())
}

/// Refuse a pubkey already signed for a DIFFERENT device id (key sharing
/// across devices). Same device re-issue is allowed (new serial).
pub fn refuse_resign(records: &[IssuedCert], pubkey: &str, device_id: &str) -> Result<()> {
    if let Some(r) = records.iter().find(|r| r.pubkey == pubkey) {
        if r.device_id != device_id {
            bail!("ephemeral key already signed for a different device; refusing re-sign");
        }
    }
    Ok(())
}

/// Sidecar path for the issued-cert record (config dir).
pub fn issued_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ssh_ca_issued.json")
}

/// Load the record (missing file = no issuances yet, not an error),
/// pruning expired entries so the ledger does not accumulate dead rows.
/// `now_secs` is a parameter (not read) so tests pin time.
pub fn load_issued(config_dir: &Path, now_secs: u64) -> Vec<IssuedCert> {
    let p = issued_path(config_dir);
    let Ok(raw) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    let mut v: Vec<IssuedCert> = serde_json::from_str(&raw).unwrap_or_default();
    let before = v.len();
    v.retain(|r| r.expires > now_secs);
    if v.len() != before {
        // Atomic like every other ledger write: a torn prune must not eat
        // live rows (best-effort here -- a failed prune just retries next
        // load; issuance itself already landed). Owner-only, like issuance: a
        // plain write-and-rename here would replace the 0600 ledger with a
        // umask-default (0644) file.
        if let Ok(text) = serde_json::to_string(&v) {
            let _ = write_private_atomic(&p, &text);
        }
    }
    v
}

/// Append one issuance, atomically (temp + rename). Errors fail closed at
/// the call site: an unrecorded cert must not ship, or the re-sign check
/// would go blind for it.
pub fn record_issuance(config_dir: &Path, rec: &IssuedCert, now_secs: u64) -> Result<()> {
    let mut v = load_issued(config_dir, now_secs);
    v.push(rec.clone());
    let text = serde_json::to_string(&v)
        .map_err(|e| anyhow!("issuance record unserializable: {e}"))?;
    write_private_atomic(&issued_path(config_dir), &text)
}

/// Issuance log line fields (who, principal, serial, expiry), per contract.
pub fn format_issuance(
    device_id: &str,
    principal: &str,
    serial: u64,
    valid_before: &str,
) -> String {
    format!("ssh-ca: signed for '{device_id}' principal '{principal}' serial {serial} expiry {valid_before}")
}

/// Secure tempdir: random-suffixed, create_dir (fail-if-exists, NOT
/// create_dir_all), 0700 on unix. Retries on collision; a persistent
/// collision fails instead of reusing (reusing a predictable dir would let
/// another user pre-place symlinks). Used for both the client ephemeral dir
/// and the daemon staging dir.
pub fn secure_tempdir(prefix: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for attempt in 0..10u32 {
        let dir = base.join(format!(
            "fil-{prefix}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            attempt
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not create a fresh tempdir for {prefix}")
}

/// CA private-key path: beside the managed keys in the ssh dir (which is
/// 0700 by construction). Operator-provisioned or minted at init; never
/// temp-copied, always passed by path.
pub fn ca_key_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ssh").join("ssh_ca")
}

/// Pure core: the daemon serving user is the shell-user setting when set,
/// else the daemon process user. Never anything the initiator sent: the
/// principal is B's decision alone (contract pins `-n`). Deliberately NO
/// root fallback: certifying root when the serving user is undeterminable
/// would mint a root login out of confusion (resolve_login's root fallback
/// is for the initiator's login GUESS, a harmless hint; a principal is a
/// security boundary, so unknown means refuse, not root).
pub fn daemon_username_from(shell_user: Option<&str>, env_user: Option<&str>) -> Option<String> {
    shell_user
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| env_user.filter(|s| !s.is_empty()).map(str::to_string))
}

/// Single-name check shared by every place a name enters sshd config (Match
/// User, principals file) or a certificate (`-n`): slashes enable path
/// traversal through the principals file; whitespace and commas would
/// certify or match extra names.
pub fn is_single_name(s: &str) -> bool {
    !s.is_empty() && !s.bytes().any(|b| b == b',' || b == b'/' || b.is_ascii_whitespace())
}

/// The single validated principal used EVERYWHERE: resolved once, checked
/// once. Unknown stays unknown (refuse) rather than becoming root.
pub fn valid_principal(host: &dyn SshCaHost) -> Result<String> {
    let Some(name) = daemon_username_from(
        host.shell_user().as_deref(),
        host.serving_user().as_deref(),
    ) else {
        bail!("cannot determine serving user");
    };
    if !is_single_name(&name) {
        bail!("serving user is not a single name");
    }
    Ok(name)
}

/// A validated `ssh-sign-request`: asserted device id, ephemeral pubkey,
/// requested ttl. Semantic checks (ed25519 shape, ttl range) run in sign()
/// so every layer fails closed independently; parse only enforces shape.
pub struct SignRequest {
    pub device_id: String,
    pub ephemeral_pubkey: String,
    pub ttl_secs: u64,
}

pub fn parse_sign_request(v: &Value) -> Option<SignRequest> {
    let device_id = v.get("device_id")?.as_str()?;
    if device_id.is_empty() || device_id.len() > 128 {
        return None;
    }
    let ephemeral_pubkey = v.get("ephemeral_pubkey")?.as_str()?;
    if ephemeral_pubkey.is_empty() || ephemeral_pubkey.len() > 4096 {
        return None;
    }
    let ttl_secs = v.get("ttl_secs")?.as_u64()?;
    Some(SignRequest {
        device_id: device_id.to_string(),
        ephemeral_pubkey: ephemeral_pubkey.to_string(),
        ttl_secs,
    })
}

/// Sign: write the pubkey to the workdir, run ssh-keygen, read back the
/// `<pubkey>-cert.pub` it writes. Nonzero exit, missing output, or any IO
/// failure refuses with a clear error -- never a cert, never a fallback.
/// `keygen_bin` is injectable so tests pass a stub instead of the real tool.
#[cfg(feature = "ssh-sign")]
pub async fn sign(
    keygen_bin: &Path,
    ca_path: &Path,
    pubkey_text: &str,
    key_id: &str,
    principal: &str,
    validity: &str,
    serial: u64,
    workdir: &Path,
) -> Result<String> {
    check_ephemeral_pubkey(pubkey_text)?;
    if !is_single_name(principal) {
        bail!("principal must be a single name");
    }
    let pub_file = workdir.join("key.pub");
    std::fs::write(&pub_file, pubkey_text)?;
    let argv = build_sign_argv(ca_path, &pub_file, key_id, principal, validity, serial);
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(keygen_bin)
            .kill_on_drop(true)
            .args(&argv)
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| anyhow!("ssh-keygen timed out; refusing"))?
    .map_err(|e| anyhow!("ssh-keygen failed to run: {e}"))?;
    if !status.status.success() {
        bail!(
            "ssh-keygen refused to sign (exit {}): {}",
            status.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    let cert_file = workdir.join("key-cert.pub");
    let cert = std::fs::read_to_string(&cert_file)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow!("ssh-keygen exited 0 but wrote no cert; refusing"))?;
    // Certs are public material, but a multi-user box should not offer them
    // for harvesting: lock the file down, fail closed if that fails.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cert_file, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow!("cannot lock down cert file: {e}"))?;
    }
    Ok(cert)
}

/// Handle one `ssh-sign-request` past the l2_enabled guard: validate, gate
/// through the shared shell gate (third path), clamp, sign, reply. Sends
/// its own replies (cert or l2-close refusal) and returns; the hook arm
/// only looks up the transport and continues.
#[cfg(feature = "ssh-sign")]
pub async fn handle_ssh_sign(
    host: &dyn SshCaHost,
    conn: &mut Conn,
    pid: &str,
    t: Arc<dyn Transport>,
    v: &Value,
    shell_policy: &ShellPolicy,
    parked: &mut Vec<ParkedOpen>,
) {
    // Refusals are GENERIC on the wire: every deny looks identical out
    // there, so a refused peer cannot oracle which check failed. The detail
    // goes to the local log only (the malformed-frame case below is the
    // deliberate exception: it names itself so misconfigured peers can
    // tell a malformed request from a denied one).
    let log = conn.log.clone();
    let refuse = |t: &Arc<dyn Transport>, sid: u32, detail: String| {
        let t = t.clone();
        let log = log.clone();
        async move {
            log.say(&format!("l2: ssh-sign refused: {detail}"));
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "ssh-sign refused" }))
                .await;
        }
    };
    // Malformed requests are refused LOUDLY (not silently dropped): a peer
    // that cannot form the frame learns it immediately instead of timing
    // out. Only a missing sid stays silent (nothing to correlate the reply
    // to). Non-L2 sids are malformed here too: the exchange mints proper
    // L2 sids, so anything else is a foreign or forged frame.
    let Some(sid) = crate::l2::wire_sid(v) else {
        return;
    };
    let good_sid = crate::l2::is_l2_sid(sid);
    let Some(req) = parse_sign_request(v) else {
        if good_sid {
            let _ = t
                .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "malformed ssh-sign-request" }))
                .await;
        }
        return;
    };
    if !good_sid {
        let _ = t
            .send_control(&json!({ "type": "l2-close", "sid": sid, "err": "malformed ssh-sign-request" }))
            .await;
        return;
    }
    // Gate first (same function, same inputs as pty/exec): no grant, no cert.
    let (dev, inputs) = gather_shell_gate_inputs(conn, pid, shell_policy, CAP_SHELL);
    if let Err(cap_reason) = ssh_gate_decision(&inputs, conn.host.as_ref()) {
        // Settle-then-evaluate: the verdict above may rest on stale
        // (unproven) identity. Park for re-drive on proof when the deny
        // is attributable to it; otherwise the live verdict stands.
        // Note: unlike exec/pty/forward, a parked sign request that must
        // deny now goes through the generic settle refusal (with the
        // retryable reason) rather than the generic ssh-sign refusal, so
        // the initiator can distinguish "retry" from "refused".
        let known = |p: &[u8; 32]| conn.host.device_known(p);
        let revoked = |p: &[u8; 32]| conn.host.cert_revoked_for(Some(p));
        let delegated = |p: &[u8; 32]| {
            conn.host
                .delegated_access_for(p)
                .is_some_and(|a| a.expired(conn.host.now_secs()))
        };
        let denied = |n: &str, c: &str| conn.host.device_capability_denied(n, c);
        if park_on_deny(
            &known,
            &revoked,
            &delegated,
            &denied,
            conn.host.gate_settle_ms(),
            parked,
            conn,
            pid,
            ParkKind::SshSign,
            &t,
            sid,
            v,
            cap_reason.as_deref().unwrap_or("shell capability not granted"),
        )
        .await
        {
            return;
        }
        refuse(
            &t,
            sid,
            cap_reason.unwrap_or_else(|| "shell capability not granted".to_string()),
        )
        .await;
        return;
    }
    // -I always carries the LINK-verified name, never the asserted one: a
    // lying id would poison audit, so on mismatch the verified name wins
    // and the attempt is logged loudly (the spoof fails closed: the cert
    // labels the true peer, never the claimed one). Unverified links have
    // no name to certify, so they refuse.
    let verified = dev.clone().unwrap_or_default();
    if verified.is_empty() {
        refuse(&t, sid, "link peer is unverified".to_string()).await;
        return;
    }
    if verified != req.device_id {
        // {:?}-escaped: the asserted id is attacker-controlled (log
        // injection via newlines/ANSI), the verified name decides.
        conn.log.say(&format!(
            "l2: ssh-sign id mismatch (asserted {:?}, verified '{}'): certifying verified",
            req.device_id, verified
        ));
    }
    let config_dir = host.config_dir();
    let ca_path = ca_key_path(&config_dir);
    if let Err(e) = check_ca_key(&ca_path) {
        refuse(&t, sid, format!("CA key: {e}")).await;
        return;
    }
    let setting_ttl = match resolve_cert_ttl_secs(host.cert_ttl_raw().as_deref()) {
        Ok(s) => s,
        Err(e) => {
            refuse(&t, sid, format!("bad ssh.cert_ttl: {e}")).await;
            return;
        }
    };
    let (peer_device, peer_user) = {
        let az = crate::shell_gate::peer_authz(conn, pid);
        let (idev, iusr, _, _, _, _) = az.parts();
        (idev.copied(), iusr.copied())
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let grant_remaining = grant_expiry_secs(host, &verified, peer_user, peer_device, now);
    let ttl = match clamp_validity_secs(grant_remaining, req.ttl_secs, setting_ttl) {
        Ok(s) => s,
        Err(e) => {
            refuse(&t, sid, format!("validity: {e}")).await;
            return;
        }
    };
    let records = load_issued(&config_dir, now);
    if let Err(e) = refuse_resign(&records, &req.ephemeral_pubkey, &verified) {
        refuse(&t, sid, format!("re-sign check: {e}")).await;
        return;
    }
    // Persist the serial BEFORE signing (atomic, fail closed): a crash
    // between issue and persist must never repeat a serial.
    let serial = read_serial(&config_dir, &records);
    if let Err(e) = write_serial(&config_dir, serial.saturating_add(1)) {
        refuse(&t, sid, format!("serial ledger unwritable: {e}")).await;
        return;
    }
    let validity = validity_interval(ttl);
    let principal = match valid_principal(host) {
        Ok(p) => p,
        Err(e) => {
            refuse(&t, sid, format!("cannot determine serving user: {e}")).await;
            return;
        }
    };
    let workdir = match secure_tempdir("ssh-sign") {
        Ok(d) => d,
        Err(_) => {
            refuse(&t, sid, "cannot stage signing".to_string()).await;
            return;
        }
    };
    let cert = match sign(
        Path::new("ssh-keygen"),
        &ca_path,
        &req.ephemeral_pubkey,
        &verified,
        &principal,
        &validity,
        serial,
        &workdir,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&workdir);
            refuse(&t, sid, format!("signing failed: {e}")).await;
            return;
        }
    };
    let _ = std::fs::remove_dir_all(&workdir);
    // Record the issuance (fail closed: an unrecorded cert must not ship,
    // or the re-sign check would go blind for it).
    if record_issuance(
        &config_dir,
        &IssuedCert {
            pubkey: req.ephemeral_pubkey.clone(),
            device_id: verified.clone(),
            serial,
            expires: now.saturating_add(ttl),
        },
        now,
    )
    .is_err()
    {
        refuse(&t, sid, "issuance ledger unwritable".to_string()).await;
        return;
    }
    conn.log.say(&format!(
        "l2: {}",
        format_issuance(&verified, &principal, serial, &(now + ttl).to_string())
    ));
    let _ = t
        .send_control(&json!({ "type": "ssh-sign-response", "sid": sid, "cert": cert }))
        .await;
}
