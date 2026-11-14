//! The local control channel's transport: where the daemon listens, how a
//! sibling process connects, and who is allowed to.
//!
//! The protocol (one JSON request line, one JSON reply line, then raw bytes or
//! exec frames) lives in `ctl.rs` and is written once against the streams this
//! module hands out. Only the transport differs:
//!
//! UNIX: a unix-domain socket at `control_sock_path` (under the config dir, or
//! a short private per-user directory when that path is too long). The
//! directory is checked private (0700, ours) before the bind, a stale socket
//! file is removed, and the socket is chmod 0600. Who may connect is decided by
//! those file permissions; there is no peer-credential check. A sandboxed
//! process of the same uid cannot reach the socket either way, because it
//! cannot write the private directory.
//!
//! WINDOWS (#205): a local named pipe, `\\.\pipe\tunlion-ctl-<hash>`. The hash
//! covers this user's SID, the canonical config dir, and a per-install random
//! salt kept in that config dir (`control-pipe.salt`, owner-only), so two
//! config dirs or two users never meet on one name, and another user cannot
//! predict the name to squat it. A same-user process is NOT automatically
//! trusted here, because Windows has a boundary inside one user that unix does
//! not: integrity levels. A Low-integrity process (a sandboxed app or plugin
//! host) runs as our SID, so an owner check alone would let it pose as the
//! daemon. The rules:
//!
//!   * every instance is created with `O:<me>D:P(A;;FA;;;<me>)S:(ML;;NWNR;;;ME)`:
//!     owned by this user, a protected DACL with one ACE for this user (none
//!     for Everyone, which the default pipe DACL grants read), and a Medium
//!     mandatory label with no-write-up and no-read-up, so a Low-integrity
//!     process of this user cannot open it at all;
//!   * remote clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`);
//!   * the first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, and an
//!     additional instance is only ever created while the daemon holds a live
//!     one of its own, so it never joins a pipe someone else created; each new
//!     instance's owner is checked after creation;
//!   * the DAEMON checks each client before reading its request: the client
//!     process's token must be this user at Medium integrity or above
//!     (`GetNamedPipeClientProcessId`);
//!   * a CLIENT checks the daemon before writing a byte: the pipe must be owned
//!     by this user and carry a label of Medium or above (a Low creator always
//!     gets a Low label and cannot raise it), and when the server process's
//!     token is readable, it must be this user at Medium or above AND at least
//!     the client's own integrity. Clients open with the default
//!     `SECURITY_IDENTIFICATION` quality of service, so a server can never
//!     impersonate them.
//!
//! What that allows, deliberately: an elevated (High) daemon, the norm when
//! it drives the TUN, serves a non-elevated client of the same user. An
//! elevated client refuses a non-elevated daemon and takes the cold path,
//! because it will not hand its requests to a lower-integrity process. A
//! daemon running as LocalSystem is unreachable by user clients (another SID,
//! so another name and another owner); that is no regression, since such a
//! daemon was never reachable before either.
//!
//! A named pipe has no write half-close: `shutdown()` only flushes. The raw
//! `open`/`dial` bridges therefore carry the client's EOF in-band on Windows
//! (`"eof":"frames"`, the exec framing's stdin and stdin-EOF frames; see
//! [`upstream`] and `filament_peerloop::control::decode_upstream`). Exec already
//! frames EOF. A piped one-shot pty keeps the cold path (see `l2.rs`).

use std::path::{Path, PathBuf};

/// Whether shutting down a client's write side reaches the daemon as EOF while
/// the read side stays open. True for a unix socket; a named pipe only flushes,
/// so the raw bridges ask for in-band EOF frames there, and a warm path that
/// cannot frame (a piped one-shot pty) does not ride the pipe.
pub(crate) const HALF_CLOSE: bool = cfg!(unix);

/// A client's end of one control connection.
#[cfg(unix)]
pub(crate) type ClientStream = tokio::net::UnixStream;
/// A client's end of one control connection.
#[cfg(windows)]
pub(crate) type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// The daemon's end of one control connection.
pub(crate) use filament_peerloop::control::CtlStream as ServerStream;

/// Read half of a split [`ClientStream`].
#[cfg(unix)]
pub(crate) type ClientReadHalf = tokio::net::unix::OwnedReadHalf;
/// Write half of a split [`ClientStream`].
#[cfg(unix)]
pub(crate) type ClientWriteHalf = tokio::net::unix::OwnedWriteHalf;
/// Read half of a split [`ClientStream`].
#[cfg(windows)]
pub(crate) type ClientReadHalf = tokio::io::ReadHalf<ClientStream>;
/// Write half of a split [`ClientStream`].
#[cfg(windows)]
pub(crate) type ClientWriteHalf = tokio::io::WriteHalf<ClientStream>;

/// Split a client connection into halves for separate tasks. Unix keeps
/// `into_split` (dropping the write half shuts the write direction); a pipe
/// has no half-close, so its halves share one handle.
#[cfg(unix)]
pub(crate) fn split_client(sock: ClientStream) -> (ClientReadHalf, ClientWriteHalf) {
    sock.into_split()
}
/// See the unix arm.
#[cfg(windows)]
pub(crate) fn split_client(sock: ClientStream) -> (ClientReadHalf, ClientWriteHalf) {
    tokio::io::split(sock)
}

/// A client's raw `open`/`dial` bridge once the daemon said ok.
#[cfg(unix)]
pub(crate) type WarmStream = ClientStream;
/// A client's raw `open`/`dial` bridge once the daemon said ok: reads come
/// straight off the pipe, writes are framed so `shutdown()` becomes an EOF
/// frame the daemon turns back into EOF.
#[cfg(windows)]
pub(crate) type WarmStream = tokio::io::Join<ClientReadHalf, tokio::io::DuplexStream>;

/// Wrap an accepted raw bridge. Unix: the socket itself, whose half-close
/// already carries EOF.
#[cfg(unix)]
pub(crate) fn upstream(sock: ClientStream) -> WarmStream {
    sock
}
/// Wrap an accepted raw bridge. Windows: the client asked for
/// `"eof":"frames"`, so everything written is sent as `FRAME_STDIN` and the
/// write side's shutdown (or drop) as `FRAME_STDIN_EOF`, the same frames exec
/// uses.
#[cfg(windows)]
pub(crate) fn upstream(sock: ClientStream) -> WarmStream {
    use filament_peerloop::exec_frame::{write_frame, FRAME_STDIN, FRAME_STDIN_EOF};
    use tokio::io::AsyncReadExt;
    let (rd, mut wr) = split_client(sock);
    let (user, mut drain) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match drain.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_frame(&mut wr, FRAME_STDIN, &buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = write_frame(&mut wr, FRAME_STDIN_EOF, &[]).await;
    });
    tokio::io::join(rd, user)
}

/// Where this config dir's daemon listens: the socket path on unix, the pipe
/// name on Windows. Daemon and clients both resolve it here.
#[cfg(unix)]
pub(crate) fn default_endpoint() -> PathBuf {
    super::control_socket_path(
        &super::Paths::config_path("control.sock"),
        &super::Paths::config_dir(),
    )
}
/// Where this config dir's daemon listens: the socket path on unix, the pipe
/// name on Windows. Daemon and clients both resolve it here.
#[cfg(windows)]
pub(crate) fn default_endpoint() -> PathBuf {
    PathBuf::from(win::pipe_name_for_dir(&super::Paths::config_dir()))
}

/// Bind the daemon's endpoint for this config dir and return where it is.
/// Unix: the socket path, bound as `Listener::bind` describes. Windows: makes
/// sure the per-install salt exists, and if the name is already held (a
/// squatter that read the salt, or anything else), writes a fresh salt and
/// tries a fresh name, up to three times, before giving up.
#[cfg(unix)]
pub(crate) fn bind_daemon_endpoint() -> anyhow::Result<(PathBuf, Listener)> {
    let path = default_endpoint();
    let listener = Listener::bind(&path)?;
    Ok((path, listener))
}
/// See the unix arm.
#[cfg(windows)]
pub(crate) fn bind_daemon_endpoint() -> anyhow::Result<(PathBuf, Listener)> {
    let dir = super::Paths::config_dir();
    if win::read_salt(&dir).is_empty() {
        win::write_fresh_salt(&dir)?;
    }
    let mut last = None;
    for _ in 0..3 {
        let path = default_endpoint();
        match Listener::bind(&path) {
            Ok(listener) => return Ok((path, listener)),
            Err(e) => {
                last = Some(e);
                win::write_fresh_salt(&dir)?;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("cannot create the control pipe")))
}

/// The pipe name for a config dir `key` (its canonical, lowercased path), a
/// user `sid` and the per-install `salt`. Pure so it is testable everywhere;
/// only Windows binds it. The salt is what keeps another user from computing
/// it; the DACL and the integrity checks are what keep everyone else out.
#[cfg(any(windows, test))]
pub(crate) fn pipe_name_for(key: &str, sid: &str, salt: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update([0u8]);
    h.update(key.as_bytes());
    h.update([0u8]);
    h.update(salt.as_bytes());
    let digest = h.finalize();
    format!(r"\\.\pipe\tunlion-ctl-{}", hex::encode(&digest.as_slice()[..16]))
}

/// Mandatory integrity RIDs (`SECURITY_MANDATORY_*_RID`).
#[cfg(any(windows, test))]
pub(crate) mod integrity {
    pub(crate) const LOW: u32 = 0x1000;
    pub(crate) const MEDIUM: u32 = 0x2000;
    pub(crate) const MEDIUM_PLUS: u32 = 0x2100;
    pub(crate) const HIGH: u32 = 0x3000;
    pub(crate) const SYSTEM: u32 = 0x4000;
}

/// The lowest integrity a mandatory label in `sddl` (the `S:` part of an SDDL
/// string, as `ConvertSecurityDescriptorToStringSecurityDescriptorW` prints it
/// for LABEL_SECURITY_INFORMATION) assigns. No label ACE at all is the implicit
/// Medium Windows applies. An unparseable label is `None`, which callers treat
/// as untrusted.
#[cfg(any(windows, test))]
pub(crate) fn label_rid_from_sddl(sddl: &str) -> Option<u32> {
    let Some(start) = sddl.find("S:") else {
        return Some(integrity::MEDIUM);
    };
    let mut lowest: Option<u32> = None;
    for ace in sddl[start..].split('(').skip(1) {
        let ace = ace.split(')').next().unwrap_or("");
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.first() != Some(&"ML") {
            continue;
        }
        let rid = match *fields.get(5)? {
            "LW" => integrity::LOW,
            "ME" => integrity::MEDIUM,
            "MP" => integrity::MEDIUM_PLUS,
            "HI" => integrity::HIGH,
            "SI" => integrity::SYSTEM,
            t => t.strip_prefix("S-1-16-")?.parse().ok()?,
        };
        lowest = Some(lowest.map_or(rid, |l: u32| l.min(rid)));
    }
    Some(lowest.unwrap_or(integrity::MEDIUM))
}

/// What a client learned about the pipe it opened, before writing anything.
#[cfg(any(windows, test))]
pub(crate) struct DaemonFacts {
    /// The pipe instance's owner SID is this user's.
    pub(crate) owner_is_me: bool,
    /// The pipe instance's mandatory label (see `label_rid_from_sddl`).
    pub(crate) label_rid: Option<u32>,
    /// The server process's token, when this client may read it: whether its
    /// user is this user, and its integrity RID.
    pub(crate) token: Option<(bool, u32)>,
}

/// May a client talk to this daemon? Owned by this user, labelled Medium or
/// above, and, when the server token is readable, this user at Medium or above
/// and no lower than the client itself.
///
/// An unreadable token is accepted on the owner and label alone. That is
/// sound: the label is the integrity proof (a Low process's objects always get
/// a Low label it cannot raise), and the token of a same-user process is only
/// unreadable from here when that process runs above us, which the rule would
/// accept anyway.
#[cfg(any(windows, test))]
pub(crate) fn daemon_trusted(f: &DaemonFacts, own_il: u32) -> bool {
    if !f.owner_is_me {
        return false;
    }
    match f.label_rid {
        Some(rid) if rid >= integrity::MEDIUM => {}
        _ => return false,
    }
    match f.token {
        Some((user_is_me, il)) => user_is_me && il >= integrity::MEDIUM && il >= own_il,
        None => true,
    }
}

/// May the daemon serve this client? Its token must be readable, this user,
/// and Medium or above. An elevated daemon serves a non-elevated client.
#[cfg(any(windows, test))]
pub(crate) fn client_trusted(token: Option<(bool, u32)>) -> bool {
    matches!(token, Some((true, il)) if il >= integrity::MEDIUM)
}

/// Which kind of pipe instance the listener may create next. An ADDITIONAL
/// instance joins whatever pipe holds the name, so it is only safe while we
/// hold a live instance of our own; otherwise only a FIRST instance is, which
/// fails rather than join a pipe someone else created.
#[cfg(any(windows, test))]
pub(crate) fn may_add_instance(holding_live_instance: bool) -> bool {
    holding_live_instance
}

/// Connect to a daemon listening at `path`. An error means there is no daemon
/// to ask (or, on Windows, one this client does not trust); callers treat
/// every error as "no warm path".
#[cfg(unix)]
pub(crate) async fn connect(path: &Path) -> std::io::Result<ClientStream> {
    tokio::net::UnixStream::connect(path).await
}
/// Connect to a daemon listening at `path`. An error means there is no daemon
/// to ask (or, on Windows, one this client does not trust); callers treat
/// every error as "no warm path".
#[cfg(windows)]
pub(crate) async fn connect(path: &Path) -> std::io::Result<ClientStream> {
    win::connect(path).await
}

/// The daemon's listener.
pub(crate) struct Listener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    inner: win::PipeListener,
}

impl Listener {
    /// Bind at `path`. Unix: private directory first, stale socket removed,
    /// mode 0600 (unchanged from the original `serve_at`). Windows: the first
    /// pipe instance, owner-only, Medium-labelled, local clients only.
    #[cfg(unix)]
    pub(crate) fn bind(path: &Path) -> anyhow::Result<Self> {
        use anyhow::anyhow;
        // A private directory (0700, ours, not writable by anyone else) before
        // anything is bound in it: the short fallback lives under /tmp.
        super::prepare_socket_dir(path)
            .map_err(|e| anyhow!("cannot prepare the control socket directory for {}: {e}", path.display()))?;
        let _ = std::fs::remove_file(path); // clear a stale leftover
        let inner = tokio::net::UnixListener::bind(path)
            .map_err(|e| anyhow!("cannot bind the control socket {} ({} bytes): {e}", path.display(), path.as_os_str().len()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self { inner })
    }
    /// Bind at `path`. Unix: private directory first, stale socket removed,
    /// mode 0600 (unchanged from the original `serve_at`). Windows: the first
    /// pipe instance, owner-only, Medium-labelled, local clients only.
    #[cfg(windows)]
    pub(crate) fn bind(path: &Path) -> anyhow::Result<Self> {
        let inner = win::PipeListener::bind(path)
            .map_err(|e| anyhow::anyhow!("cannot create the control pipe {}: {e}", path.display()))?;
        Ok(Self { inner })
    }

    /// The next client connection. On Windows only a client that passes
    /// `client_trusted` is returned; others are dropped unread.
    #[cfg(unix)]
    pub(crate) async fn accept(&mut self) -> std::io::Result<ServerStream> {
        self.inner.accept().await.map(|(sock, _)| sock)
    }
    /// The next client connection. On Windows only a client that passes
    /// `client_trusted` is returned; others are dropped unread.
    #[cfg(windows)]
    pub(crate) async fn accept(&mut self) -> std::io::Result<ServerStream> {
        self.inner.accept().await
    }
}

/// A hermetic endpoint for tests: a short /tmp socket path on unix, a unique
/// pipe name on Windows. Never the live daemon's.
#[cfg(all(test, unix))]
pub(crate) fn test_endpoint(tag: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/tl-ep-{tag}-{}-{}", std::process::id(), nanos()));
    dir.join("control.sock")
}
/// A hermetic endpoint for tests: a short /tmp socket path on unix, a unique
/// pipe name on Windows. Never the live daemon's.
#[cfg(all(test, windows))]
pub(crate) fn test_endpoint(tag: &str) -> PathBuf {
    PathBuf::from(format!(r"\\.\pipe\tunlion-test-{tag}-{}-{}", std::process::id(), nanos()))
}

#[cfg(test)]
fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Remove what a test endpoint left behind (the socket's directory on unix;
/// nothing on Windows, where the pipe dies with its last handle).
#[cfg(test)]
pub(crate) fn cleanup_test_endpoint(path: &Path) {
    if cfg!(unix) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(windows)]
mod win {
    use super::{integrity, DaemonFacts};
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_BUSY, ERROR_SUCCESS, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TokenUser, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// How long a client keeps retrying while every pipe instance is busy. A
    /// loaded CI runner can take a while to schedule the accept loop.
    const BUSY_BUDGET: Duration = Duration::from_secs(2);

    // ------------------------------------------------------------ naming --

    fn salt_path(config_dir: &Path) -> PathBuf {
        config_dir.join("control-pipe.salt")
    }

    /// The per-install salt, or empty when none was written yet (no daemon
    /// has ever served this config dir; the name then matches nothing).
    pub(super) fn read_salt(config_dir: &Path) -> String {
        std::fs::read_to_string(salt_path(config_dir))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    /// Write a fresh random salt, owner-only. Only the daemon writes it.
    pub(super) fn write_fresh_salt(config_dir: &Path) -> anyhow::Result<()> {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw)
            .map_err(|e| anyhow::anyhow!("no secure random for the control pipe salt: {e}"))?;
        crate::platform::SecretFile::write_str(salt_path(config_dir), &hex::encode(raw))?;
        Ok(())
    }

    /// The pipe name for `config_dir` and this process's user.
    pub(super) fn pipe_name_for_dir(config_dir: &Path) -> String {
        let canon = std::fs::canonicalize(config_dir).unwrap_or_else(|_| config_dir.to_path_buf());
        // Windows paths compare case-insensitively; so must the name.
        let key = canon.to_string_lossy().to_lowercase();
        let sid = current_user_sid().unwrap_or_default();
        super::pipe_name_for(&key, &sid, &read_salt(config_dir))
    }

    // ---------------------------------------------------- tokens and SIDs --

    /// This process's user SID in string form (`S-1-5-21-...`), read once.
    pub(super) fn current_user_sid() -> io::Result<String> {
        static SID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        SID.get_or_init(|| own_token_facts().map(|(sid, _)| sid))
            .clone()
            .ok_or_else(|| io::Error::other("cannot read this process's user SID"))
    }

    /// This process's integrity RID, read once. Unknown counts as Medium.
    fn own_integrity() -> u32 {
        static IL: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
        IL.get_or_init(|| own_token_facts().map(|(_, il)| il))
            .unwrap_or(integrity::MEDIUM)
    }

    fn own_token_facts() -> Option<(String, u32)> {
        // SAFETY: plain Win32 calls on this process's own token; the handle is
        // closed on every path.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let out = token_facts(token);
            CloseHandle(token);
            out
        }
    }

    /// The user SID and integrity RID of process `pid`, when this process may
    /// read its token.
    fn process_token_facts(pid: u32) -> Option<(String, u32)> {
        // SAFETY: both handles are checked and closed on every path.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let ok = OpenProcessToken(process, TOKEN_QUERY, &mut token);
            CloseHandle(process);
            if ok == 0 {
                return None;
            }
            let out = token_facts(token);
            CloseHandle(token);
            out
        }
    }

    /// SAFETY: `token` must be a valid token handle opened with TOKEN_QUERY.
    unsafe fn token_facts(token: HANDLE) -> Option<(String, u32)> {
        unsafe {
            let user = token_info(token, TokenUser).ok()?;
            let sid = sid_string((*(user.as_ptr() as *const TOKEN_USER)).User.Sid).ok()?;
            let label = token_info(token, TokenIntegrityLevel).ok()?;
            let il = sid_last_rid((*(label.as_ptr() as *const TOKEN_MANDATORY_LABEL)).Label.Sid)?;
            Some((sid, il))
        }
    }

    /// One `GetTokenInformation` class, in u64 storage so the struct read at
    /// its start is aligned. Every pointer inside points into the buffer.
    ///
    /// SAFETY: `token` must be a valid token handle opened with TOKEN_QUERY.
    unsafe fn token_info(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
        let mut len = 0u32;
        // The size probe fails with ERROR_INSUFFICIENT_BUFFER by design.
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    /// The last sub-authority of a SID: for an integrity SID, its RID.
    ///
    /// SAFETY: `sid` must point at a valid SID.
    unsafe fn sid_last_rid(sid: PSID) -> Option<u32> {
        unsafe {
            let count = *GetSidSubAuthorityCount(sid);
            if count == 0 {
                return None;
            }
            Some(*GetSidSubAuthority(sid, u32::from(count) - 1))
        }
    }

    /// SAFETY: `sid` must point at a valid SID.
    unsafe fn sid_string(sid: PSID) -> io::Result<String> {
        let mut wide: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the conversion returned a LocalAlloc'd NUL-terminated string.
        unsafe {
            let s = wide_to_string(wide);
            LocalFree(wide as HLOCAL);
            Ok(s)
        }
    }

    /// SAFETY: `p` must point at a NUL-terminated UTF-16 string.
    unsafe fn wide_to_string(p: *const u16) -> String {
        let mut n = 0usize;
        // SAFETY: the caller guarantees a NUL terminator, so every read up to
        // and including it is in bounds.
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    // ------------------------------------------------- pipe descriptors --

    /// The SDDL every instance of the control pipe is created with: owned by
    /// `sid`, a protected DACL whose only ACE gives `sid` full file access,
    /// and a Medium label refusing lower-integrity writers and readers.
    pub(super) fn owner_only_sddl(sid: &str) -> String {
        format!("O:{sid}D:P(A;;FA;;;{sid})S:(ML;;NWNR;;;ME)")
    }

    /// The owner SID of the pipe a handle refers to.
    pub(super) fn handle_owner_sid(pipe: &impl AsRawHandle) -> io::Result<String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a live handle; `owner` points into `sd`, which is freed
        // after the SID is copied out.
        unsafe {
            let rc = GetSecurityInfo(
                pipe.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            let out = sid_string(owner);
            LocalFree(sd as HLOCAL);
            out
        }
    }

    /// The parts `info` names of a handle's security descriptor, as SDDL.
    pub(super) fn handle_sddl(pipe: &impl AsRawHandle, info: u32) -> io::Result<String> {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a live handle; both returned blocks are freed.
        unsafe {
            let rc = GetSecurityInfo(
                pipe.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            let mut wide: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                info,
                &mut wide,
                std::ptr::null_mut(),
            );
            let out = if ok == 0 {
                Err(io::Error::last_os_error())
            } else {
                let s = wide_to_string(wide);
                LocalFree(wide as HLOCAL);
                Ok(s)
            };
            LocalFree(sd as HLOCAL);
            out
        }
    }

    /// An owned security descriptor (LocalAlloc'd by the SDDL conversion).
    pub(super) struct PipeSecurity {
        sd: PSECURITY_DESCRIPTOR,
    }

    // SAFETY: the descriptor is a private heap block, written once at creation
    // and only read (by CreateNamedPipe) afterwards; moving the owner between
    // threads moves nothing the OS holds a reference to.
    unsafe impl Send for PipeSecurity {}

    impl PipeSecurity {
        pub(super) fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: `wide` is NUL-terminated and outlives the call; `sd`
            // receives a LocalAlloc'd descriptor that Drop frees.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { sd })
        }

        fn owner_only() -> io::Result<Self> {
            Self::from_sddl(&owner_only_sddl(&current_user_sid()?))
        }

        /// Create one pipe instance at `name` with this descriptor.
        pub(super) fn create(&self, name: &std::ffi::OsStr, first: bool) -> io::Result<NamedPipeServer> {
            let mut attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.sd,
                bInheritHandle: 0,
            };
            // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the duration
            // of the call and points at a descriptor `self` keeps alive.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(
                        name,
                        (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
                    )
            }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: `sd` came from the SDDL conversion and is freed once.
            unsafe {
                LocalFree(self.sd as HLOCAL);
            }
        }
    }

    // ------------------------------------------------------------ daemon --

    /// The daemon side: one listening instance, replaced as each one is handed
    /// to a client, and only ever replaced while a live instance of ours is
    /// held (see `may_add_instance`).
    pub(super) struct PipeListener {
        pub(super) name: std::ffi::OsString,
        pub(super) security: PipeSecurity,
        pub(super) next: Option<NamedPipeServer>,
    }

    impl PipeListener {
        pub(super) fn bind(path: &Path) -> io::Result<Self> {
            let mut me = Self {
                name: path.as_os_str().to_os_string(),
                security: PipeSecurity::owner_only()?,
                next: None,
            };
            // The FIRST instance: fails if anyone already holds this name.
            me.refill()?;
            Ok(me)
        }

        /// Create an instance of OUR pipe and check that it is ours. `first`
        /// must be true unless the caller holds a live instance (an additional
        /// instance would otherwise join whoever holds the name); callers
        /// derive it from `may_add_instance`.
        fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
            let server = self.security.create(&self.name, first)?;
            if handle_owner_sid(&server)? != current_user_sid()? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the new control pipe instance is not owned by this user",
                ));
            }
            Ok(server)
        }

        /// Make sure a listening instance exists while holding none: only a
        /// FIRST instance is created here, so a name someone else took while we
        /// held nothing is a failure, never a pipe we join.
        pub(super) fn refill(&mut self) -> io::Result<()> {
            if self.next.is_none() {
                // Holding no instance: `may_add_instance(false)` is false, so
                // this is a FIRST instance.
                self.next = Some(self.create(!super::may_add_instance(false))?);
            }
            Ok(())
        }

        pub(super) async fn accept(&mut self) -> io::Result<NamedPipeServer> {
            loop {
                if self.refill().is_err() {
                    // Our earlier connections still hold the name (so a first
                    // instance is refused) or the name was taken: wait for them
                    // to close rather than add an instance while holding none.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                let Some(server) = self.next.take() else { continue };
                let connected = server.connect().await;
                // Replace it now, while `server` is still a live instance of
                // our own pipe, so the additional instance joins ours.
                self.next = self.create(!super::may_add_instance(true)).ok();
                match connected {
                    Ok(()) if client_ok(&server) => return Ok(server),
                    // A client that vanished before the connect completed, or
                    // one this daemon does not serve: drop it unread.
                    _ => continue,
                }
            }
        }
    }

    /// The daemon's check of a connected client, before reading a byte.
    fn client_ok(server: &NamedPipeServer) -> bool {
        let mut pid = 0u32;
        // SAFETY: a live, connected server handle.
        let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) };
        if ok == 0 {
            return false;
        }
        let Ok(me) = current_user_sid() else { return false };
        super::client_trusted(process_token_facts(pid).map(|(sid, il)| (sid == me, il)))
    }

    // ------------------------------------------------------------ client --

    /// Open the pipe at `path`, retrying briefly while every instance is busy,
    /// then refuse it unless `daemon_trusted` says so. Nothing is written
    /// before the check.
    pub(super) async fn connect(path: &Path) -> io::Result<NamedPipeClient> {
        let deadline = Instant::now() + BUSY_BUDGET;
        let client = loop {
            match ClientOptions::new().open(path) {
                Ok(c) => break c,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => return Err(e),
            }
        };
        let facts = daemon_facts(&client)?;
        if !super::daemon_trusted(&facts, own_integrity()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the control pipe {} is not this user's daemon", path.display()),
            ));
        }
        Ok(client)
    }

    /// What the client can learn about the pipe and its server process.
    fn daemon_facts(client: &NamedPipeClient) -> io::Result<DaemonFacts> {
        let me = current_user_sid()?;
        let owner_is_me = handle_owner_sid(client)? == me;
        let label_rid = super::label_rid_from_sddl(&handle_sddl(client, LABEL_SECURITY_INFORMATION)?);
        let mut pid = 0u32;
        // SAFETY: a live, connected client handle.
        let ok = unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) };
        let token = if ok == 0 {
            None
        } else {
            process_token_facts(pid).map(|(sid, il)| (sid == me, il))
        };
        Ok(DaemonFacts { owner_is_me, label_rid, token })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pipe name is a pure function of (config dir, user, salt): stable
    /// for the daemon and its clients, different for another dir, another
    /// user or another install, and a legal pipe name. Runs on every target;
    /// only Windows binds it.
    #[test]
    fn the_pipe_name_is_derived_per_config_dir_user_and_install() {
        let dir = r"c:\users\a\.config\tunlion";
        let sid = "S-1-5-21-1-2-3-1001";
        let a = pipe_name_for(dir, sid, "00ff");
        assert_eq!(a, pipe_name_for(dir, sid, "00ff"));
        assert_ne!(a, pipe_name_for(r"c:\users\a\other-tunlion", sid, "00ff"));
        assert_ne!(a, pipe_name_for(dir, "S-1-5-21-1-2-3-1002", "00ff"));
        assert_ne!(a, pipe_name_for(dir, sid, "11ee"), "the salt changes the name");
        assert!(a.starts_with(r"\\.\pipe\tunlion-ctl-"), "{a}");
        assert!(a.len() < 256, "{a}");
        assert!(!a["\\\\.\\pipe\\".len()..].contains('\\'), "{a}");
    }

    /// The default endpoint is the one name daemon and client both compute.
    #[test]
    fn the_default_endpoint_is_deterministic() {
        assert_eq!(default_endpoint(), default_endpoint());
        if cfg!(windows) {
            assert!(default_endpoint().to_string_lossy().starts_with(r"\\.\pipe\tunlion-ctl-"));
        }
    }

    #[test]
    fn a_pipe_label_is_read_as_its_lowest_integrity() {
        use integrity::*;
        assert_eq!(label_rid_from_sddl(""), Some(MEDIUM), "no label is implicit Medium");
        assert_eq!(label_rid_from_sddl("S:"), Some(MEDIUM));
        assert_eq!(label_rid_from_sddl("S:(ML;;NWNR;;;ME)"), Some(MEDIUM));
        assert_eq!(label_rid_from_sddl("S:(ML;;NW;;;LW)"), Some(LOW));
        assert_eq!(label_rid_from_sddl("S:(ML;;NW;;;HI)"), Some(HIGH));
        assert_eq!(label_rid_from_sddl("S:(ML;;NW;;;S-1-16-0)"), Some(0), "Untrusted");
        assert_eq!(label_rid_from_sddl("S:AI(ML;;NW;;;S-1-16-8448)"), Some(MEDIUM_PLUS));
        assert_eq!(label_rid_from_sddl("S:(ML;;NW;;;HI)(ML;;NW;;;LW)"), Some(LOW));
        assert_eq!(label_rid_from_sddl("S:(ML;;NW;;;XX)"), None, "unknown is untrusted");
        assert_eq!(label_rid_from_sddl("S:(AU;SA;FA;;;WD)"), Some(MEDIUM), "audit ACEs are not labels");
    }

    /// The client's decision, as a pure function over what it observed.
    #[test]
    fn a_client_trusts_only_its_own_user_at_its_own_integrity_or_above() {
        use integrity::*;
        let ok = DaemonFacts { owner_is_me: true, label_rid: Some(MEDIUM), token: Some((true, MEDIUM)) };
        assert!(daemon_trusted(&ok, MEDIUM));
        // A foreign owner (another user, or an admin that squatted the name).
        assert!(!daemon_trusted(&DaemonFacts { owner_is_me: false, ..ok }, MEDIUM));
        // A Low-integrity process of this user: Low label, Low token.
        assert!(!daemon_trusted(&DaemonFacts { label_rid: Some(LOW), token: None, ..ok }, MEDIUM));
        assert!(!daemon_trusted(&DaemonFacts { token: Some((true, LOW)), ..ok }, MEDIUM));
        assert!(!daemon_trusted(&DaemonFacts { label_rid: None, ..ok }, MEDIUM));
        // Another user's process behind our owner (cannot happen, still refused).
        assert!(!daemon_trusted(&DaemonFacts { token: Some((false, HIGH)), ..ok }, MEDIUM));
        // An elevated daemon serves a non-elevated client...
        assert!(daemon_trusted(&DaemonFacts { token: Some((true, HIGH)), ..ok }, MEDIUM));
        // ...even when its token is unreadable from below.
        assert!(daemon_trusted(&DaemonFacts { token: None, ..ok }, MEDIUM));
        // An elevated client does not hand requests to a lower daemon.
        assert!(!daemon_trusted(&ok, HIGH));
    }

    /// The daemon's decision about a client.
    #[test]
    fn a_daemon_serves_only_its_own_user_at_medium_or_above() {
        use integrity::*;
        assert!(client_trusted(Some((true, MEDIUM))));
        assert!(client_trusted(Some((true, HIGH))));
        assert!(!client_trusted(Some((true, LOW))));
        assert!(!client_trusted(Some((true, 0))), "Untrusted");
        assert!(!client_trusted(Some((false, HIGH))));
        assert!(!client_trusted(None), "an unreadable client is not served");
    }

    /// Holding nothing, the listener may only create a FIRST instance.
    #[test]
    fn an_additional_instance_needs_a_live_one_of_ours() {
        assert!(may_add_instance(true));
        assert!(!may_add_instance(false));
    }

    /// A raw connect/accept round trip through the listener: bytes both ways,
    /// then EOF on the far side once the client is gone.
    #[tokio::test]
    async fn connect_accept_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = test_endpoint("rt");
        let mut listener = Listener::bind(&path).expect("bind");
        let server = tokio::spawn(async move {
            let mut s = listener.accept().await.expect("accept");
            let mut got = [0u8; 4];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ping");
            s.write_all(b"pong").await.unwrap();
            s.flush().await.unwrap();
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "nothing after the client closed");
        });
        let mut c = connect(&path).await.expect("connect");
        c.write_all(b"ping").await.unwrap();
        c.flush().await.unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
        drop(c);
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server saw the close")
            .unwrap();
        cleanup_test_endpoint(&path);
    }

    /// Several clients at once each get their own instance (the listener
    /// keeps one listening while another is served).
    #[tokio::test]
    async fn concurrent_clients_each_get_a_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let path = test_endpoint("many");
        let mut listener = Listener::bind(&path).expect("bind");
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let mut s = listener.accept().await.expect("accept");
                tokio::spawn(async move {
                    let mut b = [0u8; 1];
                    s.read_exact(&mut b).await.unwrap();
                    s.write_all(&b).await.unwrap();
                    s.flush().await.unwrap();
                });
            }
        });
        let mut clients = Vec::new();
        for i in 0..4u8 {
            let p = path.clone();
            clients.push(tokio::spawn(async move {
                let mut c = connect(&p).await.expect("connect");
                c.write_all(&[i]).await.unwrap();
                c.flush().await.unwrap();
                let mut b = [0u8; 1];
                c.read_exact(&mut b).await.unwrap();
                assert_eq!(b[0], i);
            }));
        }
        for c in clients {
            tokio::time::timeout(std::time::Duration::from_secs(10), c)
                .await
                .expect("client finished")
                .unwrap();
        }
        server.await.unwrap();
        cleanup_test_endpoint(&path);
    }

    /// No daemon: connect fails at once, which every caller reads as "no
    /// warm path".
    #[tokio::test]
    async fn connect_without_a_listener_fails() {
        let path = test_endpoint("none");
        assert!(connect(&path).await.is_err());
        cleanup_test_endpoint(&path);
    }

    /// Squatting: a name already held is a bind failure, never a shared pipe.
    /// (Unix deliberately replaces a stale socket file instead; two live
    /// daemons are excluded by the pidfile lock there.)
    #[cfg(windows)]
    #[tokio::test]
    async fn a_second_bind_on_a_held_name_is_refused() {
        let path = test_endpoint("squat");
        let _first = Listener::bind(&path).expect("first bind");
        assert!(Listener::bind(&path).is_err(), "first_pipe_instance must refuse a held name");
        // A plain squatter instance without our descriptor is refused too.
        let squat = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path);
        assert!(squat.is_err(), "a held name cannot be taken over");
    }

    /// The zero-instance path: a listener holding no instance never joins a
    /// pipe someone else created (here one whose default DACL is open), it
    /// fails instead.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_listener_holding_nothing_never_joins_a_foreign_pipe() {
        let path = test_endpoint("foreign");
        let _foreign = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .expect("the foreign pipe");
        let mut listener = win::PipeListener {
            name: path.as_os_str().to_os_string(),
            security: win::PipeSecurity::from_sddl(&win::owner_only_sddl(
                &win::current_user_sid().unwrap(),
            ))
            .unwrap(),
            next: None,
        };
        assert!(listener.refill().is_err(), "must not add an instance to a foreign pipe");
        assert!(listener.next.is_none());
    }

    /// The descriptor: owned by this user, protected, exactly one ACE, an
    /// allow for this user, and a Medium label with no-write-up and
    /// no-read-up. A different user (or Everyone, which the default pipe DACL
    /// grants read) has no ACE and is denied; a Low process of this user is
    /// stopped by the label. Creating a second Windows account in CI is not
    /// possible here, so the denial is asserted on the descriptor rather than
    /// by a cross-user connect.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_pipe_descriptor_admits_only_this_user_at_medium_or_above() {
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        };
        let path = test_endpoint("dacl");
        let mut listener = Listener::bind(&path).expect("bind");
        let accept = tokio::spawn(async move {
            let accepted = listener.accept().await;
            accepted.map(|s| (s, listener))
        });
        let client = connect(&path).await.expect("this user may connect");
        let (_server, _listener) = accept.await.unwrap().expect("accepted");
        let me = win::current_user_sid().expect("sid");
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let sddl = win::handle_sddl(&client, info).unwrap();
        assert!(sddl.contains(&format!("O:{me}")), "owner is this user: {sddl}");
        let dacl = &sddl[sddl.find("D:").expect("a DACL")..];
        assert!(dacl.starts_with("D:P"), "protected DACL, nothing inherited: {sddl}");
        assert_eq!(dacl.matches('(').count(), 1, "exactly one ACE: {sddl}");
        assert!(dacl.contains("(A;"), "the ACE is an allow: {sddl}");
        assert!(dacl.contains(&format!(";;;{me})")), "for this user: {sddl}");
        for other in [";;;WD)", ";;;AN)", ";;;BU)", ";;;AU)"] {
            assert!(!dacl.contains(other), "no ACE for {other}: {sddl}");
        }
        let label = win::handle_sddl(&client, LABEL_SECURITY_INFORMATION).unwrap();
        assert_eq!(label_rid_from_sddl(&label), Some(integrity::MEDIUM), "{label}");
        assert!(label.contains("NWNR") || (label.contains("NW") && label.contains("NR")), "{label}");
        assert_eq!(
            win::owner_only_sddl("S-1-2-3"),
            "O:S-1-2-3D:P(A;;FA;;;S-1-2-3)S:(ML;;NWNR;;;ME)"
        );
    }

    /// A client refuses a pipe this user's daemon would never create: one
    /// labelled Low (what a sandboxed same-user process gets), and, where the
    /// runner is elevated and may assign it, one owned by Administrators.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_client_refuses_a_low_labelled_or_foreign_owned_pipe() {
        let me = win::current_user_sid().unwrap();
        let low = test_endpoint("low");
        let low_sd = win::PipeSecurity::from_sddl(&format!(
            "O:{me}D:P(A;;FA;;;{me})S:(ML;;NW;;;LW)"
        ))
        .unwrap();
        let _low_pipe = low_sd.create(low.as_os_str(), true).expect("a Low-labelled pipe");
        let err = connect(&low).await.expect_err("a Low-labelled pipe is not our daemon");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");

        let foreign = test_endpoint("ba");
        let Ok(ba_sd) = win::PipeSecurity::from_sddl("O:BAD:P(A;;FA;;;WD)") else { return };
        // Only an elevated runner may make Administrators the owner.
        let Ok(_ba_pipe) = ba_sd.create(foreign.as_os_str(), true) else {
            return; // not elevated: this runner cannot make that pipe
        };
        let err = connect(&foreign).await.expect_err("a foreign-owned pipe is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }
}
