//! Owner-only files, the pidfile, and the small duration/ttl/invitation parsers.
//!
//! The file half: reading and writing owner-only files (both the path and the
//! file-descriptor forms), and the daemon pidfile writers. The parser half: the
//! duration and ttl parsers and the invitation parser, which are small and pure.
//!
//! TEN blocks, because write_owner_only_fd and read_owner_only_fd are cfg PAIRS --
//! a unix implementation and a not(unix) counterpart each. Both halves travel
//! together, and since the pairs cover every target the names exist everywhere, so
//! their imports and re-exports are UNGATED. Only two crate-root names are needed
//! (devices_path and the ephemeral module); no dependency has a lone gate.
use crate::devices_store::devices_path;
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) fn pidfile() -> PathBuf {
    devices_path().with_file_name("up.pid")
}

/// Where the daemon records the executable it started from, beside `up.pid`.
pub(crate) fn pidfile_exe() -> PathBuf {
    devices_path().with_file_name("up.exe")
}

/// Written once the daemon is serving (connected to signaling, control socket
/// bound), holding its pid. `up --detach` waits on it: a pidfile alone exists
/// from the first instant of `up`, so it cannot tell "serving" from "about to
/// die".
pub(crate) fn ready_marker() -> PathBuf {
    devices_path().with_file_name("up.ready")
}

/// Record the daemon's identity beside its pid. A pid alone can be recycled and
/// a name substring can lie, so the executable path the daemon started from is
/// recorded too; `daemon_alive` confirms it against the live process.
///
/// `up.pid` holds the pid ALONE, so `kill $(cat up.pid)` works. The path used
/// to be its second line, which made that idiom expand to `kill <pid> <path>`
/// and fail; it lives in `up.exe` now. `daemon_alive` still reads a two-line
/// pidfile written by an older daemon that is running across an upgrade.
pub(crate) fn write_pidfile() -> Result<()> {
    let pid = std::process::id();
    let exe = std::env::current_exe()?;
    let _ = std::fs::remove_file(ready_marker());
    std::fs::write(pidfile_exe(), format!("{}\n", exe.display()))?;
    std::fs::write(pidfile(), format!("{pid}\n"))?;
    Ok(())
}

/// Remove what `write_pidfile` and `mark_daemon_ready` wrote.
pub(crate) fn remove_pidfile() {
    let _ = std::fs::remove_file(pidfile());
    let _ = std::fs::remove_file(pidfile_exe());
    let _ = std::fs::remove_file(ready_marker());
}

/// The daemon is serving. Best-effort: a missing marker only makes
/// `up --detach` report "not ready yet", never a false success.
pub(crate) fn mark_daemon_ready() {
    // Owner-only like the rest of the config dir: `fs::write` let `umask 0000`
    // make it 0666, and anyone could then point `up --detach` at another pid.
    let _ = crate::platform::SecretFile::write_str(
        &ready_marker(),
        &format!("{}\n", std::process::id()),
    );
}

/// The pid recorded in the ready marker, if any.
pub(crate) fn ready_marker_pid() -> Option<u32> {
    std::fs::read_to_string(ready_marker()).ok()?.trim().parse().ok()
}

/// Parse a pidfile: the pid on the first line, and (legacy format only) the
/// executable path on the second.
pub(crate) fn parse_pidfile(raw: &str) -> Option<(u32, Option<PathBuf>)> {
    let mut lines = raw.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let legacy_exe = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    Some((pid, legacy_exe))
}

pub(crate) fn write_owner_only_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create owner-only file {}", path.display()))?;
    writeln!(file, "{contents}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_owner_only_fd(fd: i32, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    if fd < 0 {
        bail!("secret file descriptor must be non-negative");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    writeln!(file, "{contents}")?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_owner_only_fd(_fd: i32, _contents: &str) -> Result<()> {
    bail!(
        "file-descriptor secret output is not yet implemented on this platform; use a new owner-only file"
    )
}

#[cfg(unix)]
pub(crate) fn read_owner_only_fd(fd: i32) -> Result<String> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    if fd < 0 {
        bail!("secret file descriptor must be non-negative");
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(not(unix))]
pub(crate) fn read_owner_only_fd(_fd: i32) -> Result<String> {
    bail!(
        "file-descriptor secret input is not yet implemented on this platform; use an owner-only file"
    )
}

pub(crate) fn parse_duration_secs(input: &str) -> Result<u64> {
    let (number, unit) = input.trim().split_at(input.trim().len().saturating_sub(1));
    let value: u64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{input}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid duration '{input}', use e.g. 30m, 1h, or 1d"),
    };
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration too large"))?;
    if seconds == 0 {
        bail!("duration must be greater than zero");
    }
    Ok(seconds)
}

/// CLI handler for `tunlion ephemeral`
pub(crate) fn parse_mint_ttl(raw: &str) -> Result<u64> {
    let raw = raw.trim().to_ascii_lowercase();
    let (number, unit) = raw.split_at(
        raw.trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .len(),
    );
    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid --ttl '{raw}'"))?;
    let multiplier = match unit {
        // A bare number is seconds. `ephemeral mint --ttl` was a raw u64 before
        // the mint verbs were collapsed, and its default is still "86400", so
        // dropping this arm would break every script that passes a number.
        "" => 1,
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("invalid --ttl '{raw}', use a duration such as 15m or 1h (or plain seconds)"),
    };
    Ok(value.saturating_mul(multiplier))
}

pub(crate) fn parse_invitation(raw: &str) -> Result<crate::ephemeral::Invitation> {
    use base64::Engine;
    let token = raw.trim();
    // Three forms exist in the wild, and they are the same v2 payload except v1:
    //
    //   filament-invite:v1:...    0.8.0-0.8.3, a JSON token replaced in 0.8.4.
    //                             Stale, not malformed: say so, as 0.8.5 does.
    //   filament-invite:v2:<b64>  0.8.4-0.8.5 and current. The canonical form.
    //   filament-invite:<b64>     minted by unreleased builds between #291 and
    //                             the fix that restored `v2:`. Same bytes.
    //
    // Before this, only the third was accepted, so an invitation from the
    // RELEASED 0.8.5 failed as "not valid base64url": the parser decoded
    // `v2:...` and choked on the colon.
    if token.starts_with("filament-invite:v1:") {
        bail!(
            "this invitation uses the pre-0.8.4 format; ask the owner to mint a new one with `tunlion add --for`"
        );
    }
    let encoded = token
        .strip_prefix("filament-invite:v2:")
        .or_else(|| token.strip_prefix("filament-invite:"))
        .ok_or_else(|| anyhow!("invitation has an unknown format"))?;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow!("invitation is not valid base64url"))?,
    );
    crate::ephemeral::Invitation::from_token(bytes.as_slice())
        .ok_or_else(|| anyhow!("invitation payload is not a valid v2 invitation"))
}

#[cfg(test)]
mod pidfile_tests {
    use super::parse_pidfile;
    use std::path::PathBuf;

    #[test]
    fn the_pidfile_is_the_pid_alone_and_the_legacy_form_still_reads() {
        // What write_pidfile writes now: `kill $(cat up.pid)` gets one word.
        assert_eq!(parse_pidfile("4242\n"), Some((4242, None)));
        let written = format!("{}\n", 4242);
        assert_eq!(written.split_whitespace().count(), 1, "one token for kill");
        // What an older daemon wrote: the pid, then its executable.
        assert_eq!(
            parse_pidfile("4242\n/usr/bin/tunlion\n"),
            Some((4242, Some(PathBuf::from("/usr/bin/tunlion"))))
        );
        assert_eq!(parse_pidfile(""), None);
        assert_eq!(parse_pidfile("not-a-pid\n"), None);
    }
}
