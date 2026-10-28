//! Windows shell privilege plane.
//!
//! The daemon may need elevation for the kernel TUN. A shell child must not
//! inherit that elevation by accident. `portable-pty` hardcodes CreateProcessW,
//! so the parent launches this same executable as a hidden pseudoconsole relay:
//! the relay runs with the desired token, creates the ConPTY as that user, and
//! copies UTF-8/bytes between the ConPTY and its own stdio. The parent only sees
//! ordinary pipes and a resize pipe.
//!
//! First slice: an elevated user's linked medium token. A LocalSystem service
//! has no linked token; that path needs S4U and is refused, never silently run
//! as SYSTEM.

// The policy enum and the portable stubs exist for the Windows implementation
// and its tests. On other platforms they are intentionally unreferenced; mark
// that as expected instead of regressing the warning ratchet.
#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::{Result, bail};
#[cfg(not(windows))]
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::io::{FromRawHandle, RawHandle};

/// How much privilege the served shell may keep.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShellPrivilege {
    /// Linked medium token when the daemon is elevated; current token when not.
    #[default]
    Standard,
    /// Explicit owner-equivalent shell. Requires --i-know at startup.
    OwnerEquivalent,
}

impl ShellPrivilege {
    pub fn from_env() -> Self {
        match std::env::var("TUNLION_SHELL_PRIVILEGE").as_deref() {
            Ok("owner-equivalent") => Self::OwnerEquivalent,
            _ => Self::Standard,
        }
    }
}

/// Pure policy used by both the startup gate and the spawn path.
///
/// `privileged` is not just UAC elevation: a LocalSystem service reports no
/// TokenElevation but is strictly more powerful than an Administrator. The
/// caller passes `elevated || SYSTEM`.
pub fn check_spawn_policy(
    privilege: ShellPrivilege,
    i_know: bool,
    privileged: bool,
    linked_medium: bool,
) -> Result<()> {
    if privilege == ShellPrivilege::OwnerEquivalent {
        if !i_know {
            bail!("owner-equivalent shell needs the explicit --i-know acknowledgement");
        }
        return Ok(());
    }
    if privileged && !linked_medium {
        bail!(
            "this privileged Windows process (elevated or LocalSystem) has no linked medium \
             token; refusing to serve its Administrator/SYSTEM token. Run the daemon as the \
             normal user, or choose owner-equivalent shell explicitly with --i-know."
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn spawn(_argv: &[String], _cols: u16, _rows: u16) -> Result<WinPty> {
    bail!("the Windows pseudoconsole relay is only available on Windows")
}

#[cfg(not(windows))]
pub fn relay(_cols: u16, _rows: u16, _resize: &str, _argv: &[String]) -> Result<()> {
    bail!("the Windows pseudoconsole relay is only available on Windows")
}

#[cfg(not(windows))]
pub struct WinPty {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub resize: std::fs::File,
    pub child: WinChild,
}

#[cfg(not(windows))]
pub struct WinChild;

#[cfg(not(windows))]
impl WinChild {
    pub fn kill(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    pub fn wait(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::{ShellPrivilege, check_spawn_policy};
    use anyhow::{Context, Result, anyhow};
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        WAIT_FAILED,
    };
    #[cfg(feature = "test-hooks")]
    use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, DuplicateTokenEx, EqualSid, GetTokenInformation,
        SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN, TOKEN_QUERY,
        TOKEN_USER, TokenElevation, TokenLinkedToken, TokenPrimary, TokenUser, WinLocalSystemSid,
        SECURITY_MAX_SID_SIZE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    #[cfg(feature = "test-hooks")]
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        GetCurrentProcess, InitializeProcThreadAttributeList, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };

    struct OwnedHandle(HANDLE);
    impl OwnedHandle {
        fn into_raw(self) -> HANDLE {
            let raw = self.0;
            std::mem::forget(self);
            raw
        }
    }
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn last_error(what: &str) -> anyhow::Error {
        anyhow!("{what}: {}", std::io::Error::last_os_error())
    }

    /// `MAXIMUM_ALLOWED` is a generic access mask that lives behind
    /// `Win32_System_SystemServices` in windows-sys, a feature this crate does
    /// not enable. DuplicateTokenEx documents it as the way to ask for every
    /// right the caller can get, which is what a token passed to
    /// CreateProcessAsUserW needs (TOKEN_QUERY | TOKEN_DUPLICATE |
    /// TOKEN_ASSIGN_PRIMARY plus the adjust rights).
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    /// A LocalSystem token has no UAC elevation bit, so TokenElevation alone
    /// would classify it as an ordinary user and let the standard plane inherit
    /// SYSTEM. Compare the token user SID to the well-known LocalSystem SID.
    fn token_is_local_system(token: HANDLE) -> bool {
        let mut needed = 0u32;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return false;
        }
        // `TOKEN_USER` contains a pointer, so the buffer must be pointer-aligned.
        let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buf = vec![0usize; words];
        let mut used = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut c_void,
                needed,
                &mut used,
            )
        } == 0
        {
            return false;
        }
        if used as usize > buf.len() * std::mem::size_of::<usize>() {
            return false;
        }
        let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        if user.User.Sid.is_null() {
            return false;
        }
        let mut system_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut system_sid_len = SECURITY_MAX_SID_SIZE;
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                null_mut(),
                system_sid.as_mut_ptr() as *mut c_void,
                &mut system_sid_len,
            )
        } == 0
        {
            return false;
        }
        unsafe { EqualSid(user.User.Sid, system_sid.as_mut_ptr() as *mut c_void) != 0 }
    }

    /// Returns `(privileged, linked_medium_primary_token)`, where `privileged`
    /// includes LocalSystem even though a SYSTEM token reports no UAC elevation.
    ///
    /// `want_linked` is false for an owner-equivalent shell: that mode must use
    /// the daemon's own token, not silently downgrade to the linked medium one.
    fn process_token(want_linked: bool) -> Result<(bool, Option<OwnedHandle>)> {
        let mut raw: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
            == 0
        {
            return Err(last_error("OpenProcessToken"));
        }
        let token = OwnedHandle(raw);
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let mut used = 0u32;
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut used,
            )
        } == 0
        {
            return Err(last_error("GetTokenInformation(TokenElevation)"));
        }
        let elevated = elevation.TokenIsElevated != 0;
        let privileged = elevated || token_is_local_system(token.0);
        if !privileged || !want_linked {
            return Ok((privileged, None));
        }
        // A LocalSystem token has no linked token at all. The caller must turn
        // that into a refusal: S4U is deliberately not implemented here.
        let mut linked: TOKEN_LINKED_TOKEN = unsafe { std::mem::zeroed() };
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenLinkedToken,
                &mut linked as *mut _ as *mut c_void,
                std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
                &mut used,
            )
        } == 0
        {
            return Ok((true, None));
        }
        let linked = OwnedHandle(linked.LinkedToken);
        if linked.0.is_null() || linked.0 == INVALID_HANDLE_VALUE {
            return Ok((true, None));
        }
        let mut primary: HANDLE = null_mut();
        if unsafe {
            DuplicateTokenEx(
                linked.0,
                MAXIMUM_ALLOWED,
                null(),
                SecurityImpersonation,
                TokenPrimary,
                &mut primary,
            )
        } == 0
        {
            return Ok((true, None));
        }
        if primary.is_null() || primary == INVALID_HANDLE_VALUE {
            return Ok((true, None));
        }
        Ok((true, Some(OwnedHandle(primary))))
    }

    fn inherit_pipe() -> Result<(OwnedHandle, OwnedHandle)> {
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read: HANDLE = null_mut();
        let mut write: HANDLE = null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, &attrs, 0) } == 0 {
            return Err(last_error("CreatePipe"));
        }
        Ok((OwnedHandle(read), OwnedHandle(write)))
    }

    /// Parent-side ends must not be inherited: the child only ever sees the
    /// handle list, and keeping these private guards against a caller that
    /// (accidentally) falls back to a path where the attribute list is ignored.
    fn set_not_inheritable(handle: HANDLE) -> Result<()> {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(last_error("SetHandleInformation"));
        }
        Ok(())
    }

    fn nul_handle() -> Result<OwnedHandle> {
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let handle = unsafe {
            CreateFileW(
                wide("NUL").as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attrs,
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("open NUL"));
        }
        Ok(OwnedHandle(handle))
    }

    /// Create the kill-on-close job and put the suspended relay in it.
    ///
    /// Failing closed is deliberate: a relay outside the job would survive
    /// `WinChild::drop`, and so would the shell it spawns.
    /// Give the relay our stderr only for a diagnostic run. The normal child
    /// gets NUL so a portable-pty failure cannot corrupt the terminal stream.
    #[cfg(feature = "test-hooks")]
    fn inherited_stderr() -> Result<OwnedHandle> {
        let source = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return nul_handle();
        }
        let mut duplicate: HANDLE = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return nul_handle();
        }
        Ok(OwnedHandle(duplicate))
    }

    fn create_job(process: HANDLE) -> Result<HANDLE> {
        unsafe {
            let job = CreateJobObjectW(null(), null());
            if job.is_null() || job == INVALID_HANDLE_VALUE {
                return Err(last_error("CreateJobObjectW"));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let err = last_error("SetInformationJobObject");
                CloseHandle(job);
                return Err(err);
            }
            // CREATE_SUSPENDED means the relay cannot spawn the shell before
            // this succeeds. On systems where the daemon already sits in a
            // non-nestable job this fails; refuse rather than run uncontained.
            if AssignProcessToJobObject(job, process) == 0 {
                let err = last_error("AssignProcessToJobObject");
                CloseHandle(job);
                return Err(err);
            }
            Ok(job)
        }
    }

    pub struct WinChild {
        process: HANDLE,
        job: HANDLE,
    }
    unsafe impl Send for WinChild {}
    impl WinChild {
        pub fn kill(&mut self) -> std::io::Result<()> {
            unsafe {
                // The job is the containment boundary. Terminating only the
                // relay would leave the shell and its descendants alive until
                // Drop closes the job handle.
                if !self.job.is_null() && self.job != INVALID_HANDLE_VALUE {
                    if TerminateJobObject(self.job, 1) != 0 {
                        return Ok(());
                    }
                }
                if !self.process.is_null() && self.process != INVALID_HANDLE_VALUE {
                    TerminateProcess(self.process, 1);
                }
            }
            Ok(())
        }
        pub fn wait(&mut self) -> std::io::Result<()> {
            let rc = unsafe { WaitForSingleObject(self.process, u32::MAX) };
            if rc == WAIT_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl Drop for WinChild {
        fn drop(&mut self) {
            unsafe {
                if !self.job.is_null() && self.job != INVALID_HANDLE_VALUE {
                    // Kill-on-close takes the whole relay tree down.
                    CloseHandle(self.job);
                } else if !self.process.is_null() && self.process != INVALID_HANDLE_VALUE {
                    // Belt and braces: create_job failing is now a spawn error,
                    // but never leak a relay if that ever changes.
                    TerminateProcess(self.process, 1);
                }
                if !self.process.is_null() && self.process != INVALID_HANDLE_VALUE {
                    CloseHandle(self.process);
                }
            }
        }
    }

    pub struct WinPty {
        pub reader: Box<dyn Read + Send>,
        pub writer: Box<dyn Write + Send>,
        pub resize: std::fs::File,
        pub child: WinChild,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn spawn(argv: &[String], cols: u16, rows: u16) -> Result<WinPty> {
        let privilege = ShellPrivilege::from_env();
        // Owner-equivalent means the daemon's own token; only Standard may use
        // the linked medium token.
        let want_linked = privilege == ShellPrivilege::Standard;
        let (elevated, token) = process_token(want_linked)?;
        let owner_ack = std::env::var("TUNLION_SHELL_OWNER_ACK").as_deref() == Ok("1");
        #[cfg(feature = "test-hooks")]
        crate::ui::critical(&format!(
            "WIN-PTY-SPAWN privilege={privilege:?} privileged={elevated} linked={}",
            token.is_some()
        ));
        check_spawn_policy(privilege, owner_ack, elevated, token.is_some())?;
        let exe = std::env::current_exe().context("current executable")?;
        let exe_w = wide(&exe.to_string_lossy());
        let (in_read, in_write) = inherit_pipe()?;
        let (out_read, out_write) = inherit_pipe()?;
        let (resize_read, resize_write) = inherit_pipe()?;
        #[cfg(feature = "test-hooks")]
        let stderr = if std::env::var("TUNLION_WIN_PTY_DIAG").as_deref() == Ok("1") {
            inherited_stderr()?
        } else {
            nul_handle()?
        };
        #[cfg(not(feature = "test-hooks"))]
        let stderr = nul_handle()?;
        set_not_inheritable(in_write.0)?;
        set_not_inheritable(out_read.0)?;
        set_not_inheritable(resize_write.0)?;

        // ConPTY takes COORD (i16) dimensions; clamp before they cross the wire.
        let cols = cols.clamp(1, i16::MAX as u16);
        let rows = rows.clamp(1, i16::MAX as u16);
        let mut args = vec![
            "__win-pty-relay".to_string(),
            "--cols".into(),
            cols.to_string(),
            "--rows".into(),
            rows.to_string(),
            "--resize".into(),
            format!("0x{:x}", resize_read.0 as usize),
            "--".into(),
        ];
        args.extend(argv.iter().cloned());
        let cmdline = windows_command_line(&exe, &args);
        let mut cmd_w = wide(&cmdline);

        let handles = [in_read.0, out_write.0, resize_read.0, stderr.0];
        let mut attr_size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_size);
        }
        if attr_size == 0 {
            return Err(last_error("InitializeProcThreadAttributeList(size)"));
        }
        // The attribute list must be pointer-aligned; Vec<u8> only guarantees
        // alignment of 1, so back it with usize words.
        let words = attr_size.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        let list = storage.as_mut_ptr() as *mut c_void;
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut attr_size) } == 0 {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *const c_void,
                std::mem::size_of_val(&handles),
                null_mut(),
                null(),
            )
        } == 0
        {
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(last_error("UpdateProcThreadAttribute(HANDLE_LIST)"));
        }

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = in_read.0;
        si.StartupInfo.hStdOutput = out_write.0;
        si.StartupInfo.hStdError = stderr.0;
        si.lpAttributeList = list;
        // STARTUPINFOEXW starts with STARTUPINFOW, so the address is the same;
        // the cast states that we really do pass the extended structure.
        let si_ptr = &si as *const STARTUPINFOEXW as *const STARTUPINFOW;

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let flags = CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_NO_WINDOW
            // Start suspended so the relay cannot spawn the shell before it is
            // in the kill-on-close job.
            | CREATE_SUSPENDED;
        // CreateProcessWithTokenW is intentionally not a fallback: it rejects
        // EXTENDED_STARTUPINFO_PRESENT (ERROR_INVALID_PARAMETER), so it cannot
        // carry the handle list or a pseudoconsole. The linked token is a
        // restricted version of the caller's token, which is the case
        // CreateProcessAsUserW supports without SeAssignPrimaryToken.
        let created = unsafe {
            if let Some(token) = &token {
                CreateProcessAsUserW(
                    token.0,
                    exe_w.as_ptr(),
                    cmd_w.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    flags,
                    null(),
                    null(),
                    si_ptr,
                    &mut pi,
                )
            } else {
                CreateProcessW(
                    exe_w.as_ptr(),
                    cmd_w.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    flags,
                    null(),
                    null(),
                    si_ptr,
                    &mut pi,
                )
            }
        };
        let created_error = if created == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        unsafe { DeleteProcThreadAttributeList(list) };
        if let Some(err) = created_error {
            return Err(if token.is_some() {
                anyhow!(
                    "CreateProcessAsUserW failed: {err} (the elevated daemon could \
                     not launch the linked medium token; it needs \
                     SeIncreaseQuotaPrivilege)"
                )
            } else {
                anyhow!("CreateProcessW(relay) failed: {err}")
            });
        }
        let job = match create_job(pi.hProcess) {
            Ok(job) => job,
            Err(err) => {
                unsafe {
                    TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
                return Err(err.context("contain the relay in a kill-on-close job"));
            }
        };
        if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
            let err = std::io::Error::last_os_error();
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(job);
            }
            return Err(anyhow!("ResumeThread(relay) failed: {err}"));
        }
        unsafe { CloseHandle(pi.hThread) };
        // Only the child ends stay inherited; the OwnedHandles close the rest.
        drop(in_read);
        drop(out_write);
        drop(resize_read);
        drop(stderr);
        let reader = unsafe { std::fs::File::from_raw_handle(out_read.into_raw() as RawHandle) };
        let writer = unsafe { std::fs::File::from_raw_handle(in_write.into_raw() as RawHandle) };
        let resize =
            unsafe { std::fs::File::from_raw_handle(resize_write.into_raw() as RawHandle) };
        Ok(WinPty {
            reader: Box::new(reader),
            writer: Box::new(writer),
            resize,
            child: WinChild {
                process: pi.hProcess,
                job,
            },
        })
    }

    fn windows_command_line(exe: &Path, args: &[String]) -> String {
        fn quote(s: &str) -> String {
            if !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c == '"') {
                return s.to_string();
            }
            let mut out = String::from("\"");
            let mut backslashes = 0;
            for c in s.chars() {
                match c {
                    '\\' => backslashes += 1,
                    '"' => {
                        out.push_str(&"\\".repeat(backslashes * 2 + 1));
                        out.push('"');
                        backslashes = 0;
                    }
                    _ => {
                        if backslashes > 0 {
                            out.push_str(&"\\".repeat(backslashes));
                            backslashes = 0;
                        }
                        out.push(c);
                    }
                }
            }
            out.push_str(&"\\".repeat(backslashes * 2));
            out.push('"');
            out
        }
        let mut out = quote(&exe.to_string_lossy());
        for arg in args {
            out.push(' ');
            out.push_str(&quote(arg));
        }
        out
    }
}

#[cfg(windows)]
pub use windows_impl::{WinChild, WinPty, spawn};

/// Test-hooks-only end-to-end smoke: run the real relay under this process's
/// current token (owner-equivalent mode) or the standard plane, and require the
/// shell's marker to come back through the ConPTY and pipes.
#[cfg(all(windows, feature = "test-hooks"))]
pub fn smoke(mode: &str) -> Result<()> {
    use std::io::Read;

    crate::ui::critical(&format!("WIN-PTY-SMOKE begin mode={mode}"));
    unsafe { std::env::set_var("TUNLION_WIN_PTY_DIAG", "1") };
    // The devloop has no command timeout. A wedged spawn/read must fail the
    // smoke with a marker instead of consuming the lease.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(60));
        crate::ui::critical("WIN-PTY-SMOKE watchdog timeout");
        std::process::exit(99);
    });
    match mode {
        "owner-equivalent" => unsafe {
            std::env::set_var("TUNLION_SHELL_PRIVILEGE", "owner-equivalent");
            std::env::set_var("TUNLION_SHELL_OWNER_ACK", "1");
        },
        "standard" => unsafe {
            std::env::set_var("TUNLION_SHELL_PRIVILEGE", "standard");
            std::env::remove_var("TUNLION_SHELL_OWNER_ACK");
        },
        other => bail!("unknown smoke mode {other:?}; use owner-equivalent or standard"),
    }
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    crate::ui::critical("WIN-PTY-SMOKE before spawn");
    let mut pty = spawn(
        &[
            comspec,
            "/C".into(),
            "echo".into(),
            "tunlion-win-pty-ok".into(),
        ],
        80,
        24,
    )?;
    crate::ui::critical("WIN-PTY-SMOKE after spawn");
    // Bound the smoke. A relay that keeps its stdout open after the shell exits
    // must not wedge the whole devloop lease; a timeout is a test failure, not a
    // reason to wait forever.
    let (tx, rx) = std::sync::mpsc::channel();
    let mut reader = pty.reader;
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let result = reader.read_to_end(&mut out);
        let _ = tx.send((result, out));
    });
    let (read_result, out) = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(pair) => pair,
        Err(_) => {
            let _ = pty.child.kill();
            let _ = pty.child.wait();
            bail!("relay produced no EOF within 30s");
        }
    };
    read_result?;
    crate::ui::critical("WIN-PTY-SMOKE after read");
    let text = String::from_utf8_lossy(&out);
    let _ = pty.child.wait();
    crate::ui::critical("WIN-PTY-SMOKE after wait");
    if !text.contains("tunlion-win-pty-ok") {
        bail!("relay returned no marker: {text:?}");
    }
    crate::ui::critical(&format!("WIN-PTY-SMOKE {mode} ok: {}", text.trim()));
    Ok(())
}

#[cfg(windows)]
pub fn relay(cols: u16, rows: u16, resize: &str, argv: &[String]) -> Result<()> {
    use anyhow::{Context, anyhow};
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    // The parent writes `--` before the user command. Clap normally consumes
    // it as the escape, but tolerate it here so the relay is not coupled to
    // that parser detail.
    relay_diag("start");
    let argv = if argv.first().map(String::as_str) == Some("--") {
        &argv[1..]
    } else {
        argv
    };
    let Some(program) = argv.first() else {
        bail!("pseudoconsole relay needs a command to run");
    };
    let resize_hex = resize.strip_prefix("0x").unwrap_or(resize);
    let resize_handle =
        usize::from_str_radix(resize_hex, 16).context("resize handle is not hex")?;
    let mut resize_read = unsafe { std::fs::File::from_raw_handle(resize_handle as RawHandle) };
    let cols = cols.clamp(1, i16::MAX as u16);
    let rows = rows.clamp(1, i16::MAX as u16);
    let size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    relay_diag("opening pseudoconsole");
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|e| anyhow!("open pseudoconsole: {e}"))?;
    relay_diag("pseudoconsole open");
    let mut cmd = CommandBuilder::new(program);
    for arg in &argv[1..] {
        cmd.arg(arg);
    }
    // The same environment a served `exec` gets: the account's own default,
    // read now (fresh PATH, the user's variables), plus only the session's
    // terminal and locale facts and the config dir from this relay's
    // inherited (daemon) environment. portable-pty's default was the relay's
    // whole inherited environment with the registry merged over it, which
    // handed the shell every variable the daemon was started with. With no
    // account block (a service-account daemon, an API failure) the filtered
    // baseline `user_env` keeps for that case is used, and the reason goes to
    // the relay's stderr (visible as the daemon's log or WIN-PTY diag).
    let inherited: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let user = super::Paths::exec_user_context(None).map_err(|e| anyhow!(e))?;
    let account = super::account_environment();
    if let Err(why) = &account {
        eprintln!("tunlion: account environment unavailable ({why}); keeping the filtered Windows baseline");
    }
    let env = filament_peerloop::shell::user_env::child_env(
        true,
        &user,
        false,
        account,
        &inherited,
        &[],
    )
    .map_err(|e| anyhow!(e))?;
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    // The relay is the child of the daemon, whose working directory is not
    // necessarily the served user's home. Start the shell in the profile when
    // one is known, but never fail the relay over a missing USERPROFILE.
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|p| !p.is_empty()) {
        if std::path::Path::new(&profile).is_dir() {
            cmd.cwd(profile);
        }
    }
    relay_diag("spawning shell");
    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| anyhow!("spawn shell: {e}"))?;
    relay_diag("shell spawned");
    drop(pair.slave);
    let master = Arc::new(Mutex::new(pair.master));
    let mut reader = match master
        .lock()
        .map_err(|_| anyhow!("pseudoconsole master lock poisoned"))
        .and_then(|master| {
            master
                .try_clone_reader()
                .map_err(|e| anyhow!("clone pseudoconsole reader: {e}"))
        }) {
        Ok(reader) => reader,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    // Take the writer once, here. The stdin thread owns it from now on; a
    // second take_writer() inside the thread would fail on portable-pty.
    let mut writer = match master
        .lock()
        .map_err(|_| anyhow!("pseudoconsole master lock poisoned"))
        .and_then(|master| {
            master
                .take_writer()
                .map_err(|e| anyhow!("take pseudoconsole writer: {e}"))
        }) {
        Ok(writer) => writer,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };

    let resize_master = master.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4];
        loop {
            match resize_read.read_exact(&mut buf) {
                Ok(()) => {
                    let c = u16::from_le_bytes([buf[0], buf[1]]).clamp(1, i16::MAX as u16);
                    let r = u16::from_le_bytes([buf[2], buf[3]]).clamp(1, i16::MAX as u16);
                    // A poisoned lock only means a previous resize panicked;
                    // stop resizing rather than panicking this thread too.
                    let Ok(mut master) = resize_master.lock() else {
                        break;
                    };
                    let _ = master.resize(PtySize {
                        rows: r,
                        cols: c,
                        pixel_width: 0,
                        pixel_height: 0,
                    });
                }
                Err(_) => break,
            }
        }
    });

    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
            }
        }
    });

    relay_diag("reading pseudoconsole");
    // portable-pty's ConPTY read has been observed not to reach EOF after the
    // shell exits. Poll the child as well as the reader: output is forwarded
    // immediately, but the relay ends when the shell is gone even if the
    // pseudoconsole master stays readable.
    let (out_tx, out_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut reader = reader;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut out = std::io::stdout().lock();
    loop {
        match out_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(bytes) => {
                if out.write_all(&bytes).is_err() || out.flush().is_err() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(_status)) = child.try_wait() {
                    relay_diag("shell exited");
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                relay_diag("reader closed");
                break;
            }
        }
    }
    relay_diag("pseudoconsole loop done");
    let _ = child.kill();
    let _ = child.wait();
    relay_diag("relay done");
    Ok(())
}

#[cfg(all(windows, feature = "test-hooks"))]
fn relay_diag(message: &str) {
    if std::env::var("TUNLION_WIN_PTY_DIAG").as_deref() == Ok("1") {
        crate::ui::critical(&format!("WIN-PTY-RELAY {message}"));
    }
}

#[cfg(all(windows, not(feature = "test-hooks")))]
fn relay_diag(_message: &str) {}

#[cfg(test)]
mod tests {
    use super::{ShellPrivilege, check_spawn_policy};

    #[test]
    fn standard_non_elevated_is_allowed() {
        check_spawn_policy(ShellPrivilege::Standard, false, false, false)
            .expect("an ordinary user token needs no linked token");
        check_spawn_policy(ShellPrivilege::Standard, true, false, false)
            .expect("the acknowledgement is irrelevant without elevation");
    }

    #[test]
    fn standard_elevated_with_linked_token_is_allowed() {
        check_spawn_policy(ShellPrivilege::Standard, false, true, true)
            .expect("an elevated daemon may serve the linked medium token");
    }

    #[test]
    fn standard_elevated_without_linked_token_is_refused() {
        let err = check_spawn_policy(ShellPrivilege::Standard, false, true, false)
            .expect_err("no linked token must fail closed, never serve SYSTEM")
            .to_string();
        assert!(err.contains("linked medium token"), "{err}");
        assert!(err.contains("--i-know"), "{err}");
    }

    #[test]
    fn i_know_does_not_unlock_a_standard_elevated_shell() {
        check_spawn_policy(ShellPrivilege::Standard, true, true, false)
            .expect_err("--i-know only authorizes owner-equivalent, not a SYSTEM shell");
    }

    #[test]
    fn owner_equivalent_requires_the_acknowledgement() {
        let err = check_spawn_policy(ShellPrivilege::OwnerEquivalent, false, true, false)
            .expect_err("owner-equivalent must be explicit")
            .to_string();
        assert!(err.contains("--i-know"), "{err}");
    }

    #[test]
    fn owner_equivalent_with_acknowledgement_is_allowed() {
        check_spawn_policy(ShellPrivilege::OwnerEquivalent, true, true, false)
            .expect("an explicit owner-equivalent shell may use the daemon token");
        check_spawn_policy(ShellPrivilege::OwnerEquivalent, true, false, false)
            .expect("an ordinary owner-equivalent shell is allowed");
    }

    #[test]
    fn owner_equivalent_ignores_the_linked_token() {
        // The spawn path must use the daemon's own token in this mode; a
        // linked medium token existing (or not) must not change the verdict.
        check_spawn_policy(ShellPrivilege::OwnerEquivalent, true, true, true)
            .expect("owner-equivalent does not depend on a linked token");
        check_spawn_policy(ShellPrivilege::OwnerEquivalent, false, true, true)
            .expect_err("a linked token never substitutes for --i-know");
    }
}
