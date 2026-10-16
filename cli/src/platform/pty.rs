//! The PTY the shell server spawns into. Everywhere but Android this is
//! portable-pty. Android goes without: the crate pulls in `serial`/`termios`,
//! which do not build there, and a phone never serves shells
//! (docs/android-app-spec.md). The Android stand-in has the same surface and
//! refuses at `openpty`, so the caller's existing failure path sends the reason.

#[cfg(not(target_os = "android"))]
pub use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[cfg(target_os = "android")]
pub use android::{native_pty_system, CommandBuilder, PtySize};

#[cfg(target_os = "android")]
mod android {
    use std::ffi::OsStr;

    #[derive(Clone, Copy, Debug)]
    pub struct PtySize {
        pub rows: u16,
        pub cols: u16,
        pub pixel_width: u16,
        pub pixel_height: u16,
    }

    pub struct CommandBuilder;

    impl CommandBuilder {
        pub fn new<S: AsRef<OsStr>>(_program: S) -> Self {
            CommandBuilder
        }
        pub fn arg<S: AsRef<OsStr>>(&mut self, _arg: S) {}
        pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, _key: K, _val: V) {}
        pub fn cwd<D: AsRef<OsStr>>(&mut self, _dir: D) {}
    }

    /// Uninhabited: `openpty` never succeeds, so no master, slave or child exists.
    pub enum Never {}

    impl Never {
        pub fn spawn_command(&self, _cmd: CommandBuilder) -> anyhow::Result<Never> {
            match *self {}
        }
        pub fn try_clone_reader(&self) -> anyhow::Result<Box<dyn std::io::Read + Send>> {
            match *self {}
        }
        pub fn take_writer(&self) -> anyhow::Result<Box<dyn std::io::Write + Send>> {
            match *self {}
        }
        pub fn resize(&self, _size: PtySize) -> anyhow::Result<()> {
            match *self {}
        }
        pub fn kill(&mut self) -> std::io::Result<()> {
            match *self {}
        }
        pub fn wait(&mut self) -> std::io::Result<()> {
            match *self {}
        }
    }

    pub struct PtyPair {
        pub master: Never,
        pub slave: Never,
    }

    pub struct NoPty;

    impl NoPty {
        pub fn openpty(&self, _size: PtySize) -> anyhow::Result<PtyPair> {
            anyhow::bail!("this device runs Android and does not serve shells")
        }
    }

    pub fn native_pty_system() -> NoPty {
        NoPty
    }
}
