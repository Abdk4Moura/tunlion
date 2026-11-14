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
//! those file permissions; there is no peer-credential check.
//!
//! WINDOWS (#205): a local named pipe, `\\.\pipe\tunlion-ctl-<hash>`, where the
//! hash covers this user's SID and the canonical config dir, so two config dirs
//! or two users never meet on one name. The security matches the unix socket:
//!
//!   * the pipe's security descriptor is `O:<me>D:P(A;;FA;;;<me>)`: owned by
//!     this user, a protected DACL with one ACE granting this user and nobody
//!     else (no Everyone/Anonymous read access, which the default pipe DACL
//!     gives). That is the 0600 equivalent, and as on unix it is the whole
//!     authorization: any process running as this user may connect, nobody
//!     else can open the pipe at all, so no per-client check is added;
//!   * remote clients are rejected (`PIPE_REJECT_REMOTE_CLIENTS`);
//!   * the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a
//!     name another process already holds is a bind failure, never a pipe we
//!     share with a squatter;
//!   * a CLIENT refuses any pipe whose owner is not this user, so a squatter
//!     that created the name first cannot collect requests (an exec's argv
//!     and env, an ssh pubkey). The unix analog is the private-directory check.
//!     Clients also open with the default `SECURITY_IDENTIFICATION` quality of
//!     service, so a server can never impersonate them.
//!
//! One behavioural difference is unavoidable: a named pipe has no write
//! half-close. `shutdown()` on a pipe only flushes, so a raw-stream client's
//! stdin EOF reaches the peer when the connection closes, not before. Exec
//! carries EOF as a frame and is unaffected; see `l2.rs` for the warm paths
//! that account for it.

use std::path::{Path, PathBuf};

/// Whether shutting down a client's write side reaches the daemon as EOF while
/// the read side stays open. True for a unix socket; a named pipe only flushes,
/// so a warm path that needs the peer to see stdin EOF mid-session (a piped
/// one-shot shell) must not ride it on Windows.
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

/// The pipe name for a config dir `key` (its canonical, lowercased path) and a
/// user `sid`. Pure so it is testable everywhere; only Windows binds it. The
/// SID is in the hash for uniqueness, not secrecy: the DACL is the boundary.
#[cfg(any(windows, test))]
pub(crate) fn pipe_name_for(key: &str, sid: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sid.as_bytes());
    h.update([0u8]);
    h.update(key.as_bytes());
    let digest = h.finalize();
    format!(r"\\.\pipe\tunlion-ctl-{}", hex::encode(&digest.as_slice()[..16]))
}

/// Connect to a daemon listening at `path`. An error means there is no daemon
/// to ask (or, on Windows, one this user does not own); callers treat every
/// error as "no warm path".
#[cfg(unix)]
pub(crate) async fn connect(path: &Path) -> std::io::Result<ClientStream> {
    tokio::net::UnixStream::connect(path).await
}
/// Connect to a daemon listening at `path`. An error means there is no daemon
/// to ask (or, on Windows, one this user does not own); callers treat every
/// error as "no warm path".
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
    /// pipe instance, owner-only, local clients only.
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
    /// pipe instance, owner-only, local clients only.
    #[cfg(windows)]
    pub(crate) fn bind(path: &Path) -> anyhow::Result<Self> {
        let inner = win::PipeListener::bind(path)
            .map_err(|e| anyhow::anyhow!("cannot create the control pipe {}: {e}", path.display()))?;
        Ok(Self { inner })
    }

    /// The next client connection.
    #[cfg(unix)]
    pub(crate) async fn accept(&mut self) -> std::io::Result<ServerStream> {
        self.inner.accept().await.map(|(sock, _)| sock)
    }
    /// The next client connection.
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
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_PIPE_BUSY, ERROR_SUCCESS, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// The pipe name for `config_dir` and this process's user.
    pub(super) fn pipe_name_for_dir(config_dir: &Path) -> String {
        let canon = std::fs::canonicalize(config_dir).unwrap_or_else(|_| config_dir.to_path_buf());
        // Windows paths compare case-insensitively; so must the name.
        let key = canon.to_string_lossy().to_lowercase();
        let sid = current_user_sid().unwrap_or_default();
        super::pipe_name_for(&key, &sid)
    }

    /// This process's user SID in string form (`S-1-5-21-...`), read once.
    pub(super) fn current_user_sid() -> io::Result<String> {
        static SID: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        SID.get_or_init(|| read_current_user_sid().ok())
            .clone()
            .ok_or_else(|| io::Error::other("cannot read this process's user SID"))
    }

    fn read_current_user_sid() -> io::Result<String> {
        // SAFETY: plain Win32 calls on this process's own token; the handle is
        // closed on every path and the buffer outlives every pointer into it.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let out = token_user_sid(token);
            CloseHandle(token);
            out
        }
    }

    /// SAFETY: `token` must be a valid token handle opened with TOKEN_QUERY.
    unsafe fn token_user_sid(token: HANDLE) -> io::Result<String> {
        let mut len = 0u32;
        // The size probe fails with ERROR_INSUFFICIENT_BUFFER by design.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 storage keeps the TOKEN_USER read aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = unsafe {
            GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call above filled `buf` with a TOKEN_USER whose SID
        // pointer points into `buf`, which is alive for the conversion.
        unsafe {
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_string(user.User.Sid)
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

    /// The SDDL every instance of the control pipe is created with: owned by
    /// `sid`, a protected DACL whose only ACE gives `sid` full file access.
    pub(super) fn owner_only_sddl(sid: &str) -> String {
        format!("O:{sid}D:P(A;;FA;;;{sid})")
    }

    /// An owned security descriptor (LocalAlloc'd by the SDDL conversion).
    struct PipeSecurity {
        sd: PSECURITY_DESCRIPTOR,
    }

    // SAFETY: the descriptor is a private heap block, written once at creation
    // and only read (by CreateNamedPipe) afterwards; moving the owner between
    // threads moves nothing the OS holds a reference to.
    unsafe impl Send for PipeSecurity {}

    impl PipeSecurity {
        fn owner_only() -> io::Result<Self> {
            let sid = current_user_sid()?;
            let wide: Vec<u16> = owner_only_sddl(&sid).encode_utf16().chain(Some(0)).collect();
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
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: `sd` came from the SDDL conversion and is freed once.
            unsafe {
                LocalFree(self.sd as HLOCAL);
            }
        }
    }

    /// The daemon side: always one listening instance, replaced as each one
    /// is handed to a client.
    pub(super) struct PipeListener {
        name: std::ffi::OsString,
        security: PipeSecurity,
        next: Option<NamedPipeServer>,
    }

    impl PipeListener {
        pub(super) fn bind(path: &Path) -> io::Result<Self> {
            let security = PipeSecurity::owner_only()?;
            let mut me = Self {
                name: path.as_os_str().to_os_string(),
                security,
                next: None,
            };
            // The FIRST instance: fails if anyone already holds this name.
            me.next = Some(me.create(true)?);
            Ok(me)
        }

        fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
            let mut attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.security.sd,
                bInheritHandle: 0,
            };
            // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the duration
            // of the call and points at a descriptor `self` keeps alive.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(
                        &self.name,
                        (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
                    )
            }
        }

        pub(super) async fn accept(&mut self) -> io::Result<NamedPipeServer> {
            loop {
                let server = match self.next.take() {
                    Some(s) => s,
                    None => match self.create(false) {
                        Ok(s) => s,
                        Err(_) => {
                            // Out of handles or similar: back off rather than
                            // spin, and keep serving once it clears.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    },
                };
                match server.connect().await {
                    Ok(()) => {
                        // Keep an instance listening while this one is served,
                        // so a concurrent client sees PIPE_BUSY at worst, never
                        // a missing pipe.
                        self.next = self.create(false).ok();
                        return Ok(server);
                    }
                    // The client vanished before the connect completed; this
                    // instance is spent, so make a fresh one.
                    Err(_) => continue,
                }
            }
        }
    }

    /// Open the pipe at `path`, retrying briefly while every instance is busy,
    /// then refuse it unless this user owns it.
    pub(super) async fn connect(path: &Path) -> io::Result<NamedPipeClient> {
        let deadline = Instant::now() + Duration::from_millis(500);
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
        let me = current_user_sid()?;
        let owner = handle_owner_sid(&client)?;
        if owner != me {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the control pipe {} is owned by {owner}, not this user", path.display()),
            ));
        }
        Ok(client)
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

    #[cfg(test)]
    pub(super) fn handle_sddl(pipe: &impl AsRawHandle) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: as in `handle_owner_sid`; both returned blocks are freed.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pipe name is a pure function of (config dir, user): stable for the
    /// daemon and its clients, different for another dir or another user, and
    /// a legal pipe name. Runs on every target; only Windows binds it.
    #[test]
    fn the_pipe_name_is_derived_per_config_dir_and_per_user() {
        let a = pipe_name_for(r"c:\users\a\.config\tunlion", "S-1-5-21-1-2-3-1001");
        assert_eq!(a, pipe_name_for(r"c:\users\a\.config\tunlion", "S-1-5-21-1-2-3-1001"));
        assert_ne!(a, pipe_name_for(r"c:\users\a\other-tunlion", "S-1-5-21-1-2-3-1001"));
        assert_ne!(a, pipe_name_for(r"c:\users\a\.config\tunlion", "S-1-5-21-1-2-3-1002"));
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
            tokio::time::timeout(std::time::Duration::from_secs(5), c)
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

    /// The DACL: owned by this user, protected, exactly one ACE, an allow for
    /// this user. A different user (or Everyone, which the default pipe DACL
    /// grants read) has no ACE and is denied. Creating a second Windows
    /// account in CI is not possible here, so the denial is asserted on the
    /// descriptor itself rather than by a cross-user connect.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_pipe_dacl_admits_only_this_user() {
        let path = test_endpoint("dacl");
        let mut listener = Listener::bind(&path).expect("bind");
        let accept = tokio::spawn(async move {
            let accepted = listener.accept().await;
            accepted.map(|s| (s, listener))
        });
        let client = connect(&path).await.expect("this user may connect");
        let (server, _listener) = accept.await.unwrap().expect("accepted");
        let me = win::current_user_sid().expect("sid");
        // The client's handle shows what every other process sees; the
        // server end stays open so the pipe is live while it is read.
        let _server = server;
        {
            let sddl = win::handle_sddl(&client).unwrap();
            assert!(sddl.contains(&format!("O:{me}")), "owner is this user: {sddl}");
            let dacl = &sddl[sddl.find("D:").expect("a DACL") ..];
            assert!(dacl.starts_with("D:P"), "protected DACL, nothing inherited: {sddl}");
            assert_eq!(dacl.matches('(').count(), 1, "exactly one ACE: {sddl}");
            assert!(dacl.contains("(A;"), "the ACE is an allow: {sddl}");
            assert!(dacl.contains(&format!(";;;{me})")), "for this user: {sddl}");
            for other in [";;;WD)", ";;;AN)", ";;;BU)", ";;;AU)"] {
                assert!(!dacl.contains(other), "no ACE for {other}: {sddl}");
            }
        }
        assert_eq!(win::owner_only_sddl("S-1-2-3"), "O:S-1-2-3D:P(A;;FA;;;S-1-2-3)");
    }
}
