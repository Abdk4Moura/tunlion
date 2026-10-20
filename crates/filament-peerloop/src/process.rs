//! Process spawn helpers for library code.
//!
//! The CLI's `platform::command` / `platform::tokio_command` cannot be reached
//! from this crate, but the rule is the same: on Windows a daemon with no
//! console of its own must not give every child (ssh-keygen, sshfs, fusermount)
//! a flashing console window. `surface_spawn.rs` audits crate files for that.
//! Every spawn in this crate goes through these two functions.

/// A synchronous child command, no console window on Windows.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut c = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Some(flags) = no_console_flags() {
            c.creation_flags(flags);
        }
    }
    c
}

/// An async child command, no console window on Windows.
pub fn tokio_command(program: impl AsRef<std::ffi::OsStr>) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Some(flags) = no_console_flags() {
            c.creation_flags(flags);
        }
    }
    c
}

/// CREATE_NO_WINDOW when this process has no console window, else None.
#[cfg(windows)]
fn no_console_flags() -> Option<u32> {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    // SAFETY: GetConsoleWindow takes no arguments and only reads this
    // process's console attachment.
    let hwnd = unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() };
    hwnd.is_null().then_some(CREATE_NO_WINDOW)
}
