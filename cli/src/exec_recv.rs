//! CLI process adapter for the library's `exec-open` state machine.
//!
//! The protocol, admission and serve loop moved to
//! `filament_peerloop::shell::exec_server` (feature `exec-server`). What stays
//! here is exactly the machine-bound half: the daemon's PATH/env/home facts,
//! the platform account drop, the real spawn with its process group /
//! parent-death / job-object containment, and the served-group record that
//! lets the next daemon end a tree a SIGKILLed one left behind.
//!
//! Nothing in this file decides a frame, an ack, a sid, a pump or a
//! cancellation rule; those are the library's, single-sourced.

#[cfg(feature = "exec-server")]
use filament_peerloop::l2::mux::TreeSignal;
#[cfg(feature = "exec-server")]
use filament_peerloop::shell::exec::{ExecChild, ExecExit, ExecProcess, ExecSpawnSpec};
#[cfg(feature = "exec-server")]
use std::path::Path;
#[cfg(feature = "exec-server")]
use std::path::PathBuf;
#[cfg(feature = "exec-server")]
use tokio::io::{AsyncRead, AsyncWrite};

/// Where the daemon records the process groups it is serving for `exec`,
/// beside its pidfile. A daemon killed with SIGKILL (or one that crashed) runs
/// none of its own cleanup, so whatever a served command forked would live on
/// under init; the next daemon reads this at startup and ends what is left.
/// One line per group: `<pgid> <boot token> <leader start token or ->`.
pub(crate) const SERVED_GROUPS_FILE: &str = "exec.groups";

#[cfg(feature = "exec-server")]
fn served_groups_path() -> PathBuf {
    crate::settings::config_dir().join(SERVED_GROUPS_FILE)
}

/// The live record, keyed by group id. Rewritten whole (atomically) on every
/// change, so the file never holds a half line.
#[cfg(feature = "exec-server")]
static SERVED_GROUPS: std::sync::Mutex<std::collections::BTreeMap<u32, String>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

#[cfg(feature = "exec-server")]
fn persist_served_groups(groups: &std::collections::BTreeMap<u32, String>) {
    let path = served_groups_path();
    if groups.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let body: String = groups.values().map(|l| format!("{l}\n")).collect();
    if let Err(e) = crate::platform::SecretFile::write_str(&path, &body) {
        crate::ui::trace(&format!(
            "exec: could not record served process groups in {}: {e}",
            path.display()
        ));
    }
}

/// One served group's entry in the record, removed when the session ends by
/// any path (the guard drops with the served child).
#[cfg(feature = "exec-server")]
struct ServedGroup(u32);

#[cfg(feature = "exec-server")]
impl ServedGroup {
    fn record(pgid: u32) -> ServedGroup {
        // Without a boot token a recorded number could not be trusted at the
        // next start, so the sweep ignores it; recording it anyway is harmless.
        let boot = crate::platform::boot_token().unwrap_or_else(|| "-".into());
        let start = crate::platform::process_start_token(pgid).unwrap_or_else(|| "-".into());
        if let Ok(mut g) = SERVED_GROUPS.lock() {
            g.insert(pgid, format!("{pgid} {boot} {start}"));
            persist_served_groups(&g);
        }
        ServedGroup(pgid)
    }
}

#[cfg(feature = "exec-server")]
impl Drop for ServedGroup {
    fn drop(&mut self) {
        if let Ok(mut g) = SERVED_GROUPS.lock() {
            g.remove(&self.0);
            persist_served_groups(&g);
        }
    }
}

/// Should a recorded line be killed now? Only a group from THIS boot, and
/// only when its number cannot have been handed to someone else: a live
/// process holding the leader's pid with a different start time proves the
/// pid was reused, and a pid is reused only once its old group is empty.
#[cfg_attr(not(feature = "exec-server"), allow(dead_code))]
fn leftover_group(
    line: &str,
    boot: &str,
    start_now: impl Fn(u32) -> Option<String>,
) -> Option<u32> {
    let mut f = line.split_whitespace();
    let pgid: u32 = f.next()?.parse().ok()?;
    let rec_boot = f.next()?;
    let rec_start = f.next()?;
    if pgid <= 1 || rec_boot == "-" || rec_boot != boot {
        return None;
    }
    match start_now(pgid) {
        Some(now) if rec_start != "-" && now != rec_start => None,
        _ => Some(pgid),
    }
}

/// End every served group a previous daemon left behind, then clear the
/// record. Called once at startup, after the single-instance lock is held and
/// before anything is served, so nothing in the file can be a live session of
/// this daemon. Returns how many groups were still alive and were killed.
#[cfg(feature = "exec-server")]
pub(crate) fn kill_leftover_groups() -> usize {
    let path = served_groups_path();
    let Ok(body) = std::fs::read_to_string(&path) else {
        return 0;
    };
    let mut killed = 0;
    if let Some(boot) = crate::platform::boot_token() {
        for line in body.lines() {
            let Some(pgid) = leftover_group(line, &boot, crate::platform::process_start_token)
            else {
                continue;
            };
            if crate::platform::process_group_alive(pgid)
                && crate::platform::signal_process_group(pgid, TreeSignal::Kill).unwrap_or(false)
            {
                killed += 1;
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    killed
}

/// Reduced builds compile no exec backend, so there is never a record of a
/// group this process served. A file left by an older build is still swept by
/// `reset` through [`SERVED_GROUPS_FILE`], not by this daemon.
#[cfg(not(feature = "exec-server"))]
pub(crate) fn kill_leftover_groups() -> usize {
    0
}

/// Resolve `program` the way the DAEMON would: an absolute or relative path
/// (anything containing a separator) is used as-is; a bare name is looked up
/// in the daemon process's own PATH. Returns None when unresolvable, so the
/// caller refuses instead of spawning something surprising. Runs BEFORE the
/// child env is cleared, which removes PATH from the child's environment.
#[cfg(feature = "exec-server")]
pub(crate) fn resolve_in_path(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    if program.contains('/') || program.contains('\\') {
        return Some(PathBuf::from(program));
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if let Some(p) = resolve_bare_in(&dir, program) {
            return Some(p);
        }
    }
    None
}

/// Candidate spellings of a bare program name in one directory: the name
/// itself, plus (Windows only) each PATHEXT suffix in order. Pure so the
/// ordering is unit-testable on every platform; only used on Windows
/// (allowed dead elsewhere so the unix build stays warning-neutral).
#[cfg(feature = "exec-server")]
#[cfg_attr(not(windows), allow(dead_code))]
fn pathext_candidates(program: &str, exts: &str) -> Vec<String> {
    let mut out = vec![program.to_string()];
    for ext in exts.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        out.push(format!("{program}{ext}"));
    }
    out
}

/// Resolve a bare name inside one PATH directory. Unix: the name itself.
/// Windows: the name itself, then PATHEXT suffixes (.EXE etc.) so `rsync`
/// finds `rsync.exe` -- still a direct spawn of the resolved path, never a
/// shell lookup, so argv exactness is unaffected.
#[cfg(all(feature = "exec-server", windows))]
fn resolve_bare_in(dir: &std::path::Path, program: &str) -> Option<PathBuf> {
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    for name in pathext_candidates(program, &exts) {
        let candidate = dir.join(&name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolve a bare name inside one PATH directory (non-Windows): the name
/// itself, unchanged from the original loop.
#[cfg(all(feature = "exec-server", not(windows)))]
fn resolve_bare_in(dir: &std::path::Path, program: &str) -> Option<PathBuf> {
    let candidate = dir.join(program);
    if is_executable(&candidate) {
        return Some(candidate);
    }
    None
}

#[cfg(all(feature = "exec-server", unix))]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.is_file()
        && p.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(all(feature = "exec-server", not(unix)))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// The CLI's process primitive. Stateless: every process fact is read at the
/// moment the library asks, exactly where the old handler read it.
#[cfg(feature = "exec-server")]
pub(crate) struct CliExecProcess;

#[cfg(feature = "exec-server")]
impl ExecProcess for CliExecProcess {
    fn resolve_program(&self, program: &str) -> Option<PathBuf> {
        resolve_in_path(program)
    }

    fn daemon_environment(&self) -> Vec<(String, String)> {
        std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect()
    }

    fn home_dir(&self) -> PathBuf {
        crate::platform::Paths::home_dir()
    }

    fn home_of_user(&self, user: &str) -> Option<PathBuf> {
        crate::platform::Paths::home_of_user(user)
    }

    fn user_drop_argv(
        &self,
        program: &Path,
        args: &[String],
        user: &str,
    ) -> Result<Vec<String>, String> {
        crate::platform::Paths::exec_as_user_argv(&program.to_string_lossy(), args, Some(user))
    }

    fn spawn(&self, spec: ExecSpawnSpec) -> Result<Box<dyn ExecChild>, String> {
        let mut cmd = crate::platform::tokio_command(&spec.program);
        cmd.args(&spec.args)
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(spec.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // A group of its own, so ending the session ends everything the
        // command started (`sh -c 'a | b'`, a script's children), not only
        // its leader.
        crate::platform::own_process_group(&mut cmd);
        // And not one that outlives the daemon: a daemon killed with SIGKILL
        // runs none of the session cleanup, which left a remote `sleep`
        // running under init across a fresh `up`.
        crate::platform::die_with_daemon(&mut cmd);
        // Backstop for a task that ends abnormally (panic, abort): the leader
        // dies with it rather than outliving the daemon's record of it.
        cmd.kill_on_drop(true);
        // The leader's pid is its group id (own_process_group). Recorded
        // before the child can run any of the program and kept until the
        // child is dropped, so a daemon that dies at any point after the fork
        // has its leftovers ended by the next one (kill_leftover_groups).
        let (child, served) = crate::platform::spawn_recorded(&mut cmd, ServedGroup::record)
            .map_err(|e| e.to_string())?;
        crate::platform::contain_with_daemon(&child);
        Ok(Box::new(CliExecChild {
            pgid: child.id(),
            child,
            _served: served,
        }))
    }

    fn test_expiry_close_first(&self) -> bool {
        #[cfg(feature = "test-hooks")]
        {
            std::env::var("TUNLION_TEST_EXPIRY_CLOSE_FIRST").is_ok()
        }
        #[cfg(not(feature = "test-hooks"))]
        {
            false
        }
    }
}

#[cfg(feature = "exec-server")]
struct CliExecChild {
    child: tokio::process::Child,
    pgid: Option<u32>,
    _served: Option<ServedGroup>,
}

#[cfg(feature = "exec-server")]
#[async_trait::async_trait]
impl ExecChild for CliExecChild {
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send>> {
        self.child
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>> {
        self.child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>> {
        self.child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>)
    }

    async fn wait(&mut self) -> std::io::Result<ExecExit> {
        self.child.wait().await.map(ExecExit::from_std)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExecExit>> {
        self.child.try_wait().map(|s| s.map(ExecExit::from_std))
    }

    fn start_kill(&mut self) {
        let _ = self.child.start_kill();
    }

    fn signal_group(&self, sig: TreeSignal) -> bool {
        self.pgid
            .map(|g| crate::platform::signal_process_group(g, sig).unwrap_or(false))
            .unwrap_or(false)
    }

    fn group_alive(&self) -> bool {
        self.pgid.is_some_and(crate::platform::process_group_alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The startup sweep kills only a group it can still vouch for: this boot,
    /// and a leader pid that was not handed to someone else since.
    #[test]
    fn leftover_sweep_kills_only_what_is_still_ours() {
        let gone = |_: u32| None;
        let same = |_: u32| Some("777".to_string());
        let reused = |_: u32| Some("999".to_string());
        // Leader dead (PDEATHSIG), group survivors remain: kill.
        assert_eq!(
            leftover_group("4242 boot-a 777", "boot-a", gone),
            Some(4242)
        );
        // Leader still running (no PDEATHSIG, e.g. macOS): kill.
        assert_eq!(
            leftover_group("4242 boot-a 777", "boot-a", same),
            Some(4242)
        );
        // Pid reused by an unrelated process: its old group is empty, skip.
        assert_eq!(leftover_group("4242 boot-a 777", "boot-a", reused), None);
        // Another boot, or no boot token at all: never trusted.
        assert_eq!(leftover_group("4242 boot-a 777", "boot-b", gone), None);
        assert_eq!(leftover_group("4242 - 777", "-", gone), None);
        // init and malformed lines are never targets.
        assert_eq!(leftover_group("1 boot-a 777", "boot-a", gone), None);
        assert_eq!(leftover_group("0 boot-a -", "boot-a", gone), None);
        assert_eq!(leftover_group("x boot-a 777", "boot-a", gone), None);
        assert_eq!(leftover_group("4242 boot-a", "boot-a", gone), None);
        // No recorded start time: the boot match is all there is.
        assert_eq!(
            leftover_group("4242 boot-a -", "boot-a", reused),
            Some(4242)
        );
    }

    #[cfg(feature = "exec-server")]
    #[test]
    fn pathext_candidates_bare_first_then_suffixes_in_order() {
        assert_eq!(
            pathext_candidates("rsync", ".COM;.EXE;.BAT;.CMD"),
            vec!["rsync", "rsync.COM", "rsync.EXE", "rsync.BAT", "rsync.CMD"]
        );
        assert_eq!(pathext_candidates("rsync", ""), vec!["rsync"]);
        assert_eq!(
            pathext_candidates("run", " .EXE ; ; .BAT "),
            vec!["run", "run.EXE", "run.BAT"]
        );
    }

    #[cfg(feature = "exec-server")]
    #[test]
    fn resolve_absolute_passthrough_and_missing() {
        assert_eq!(
            resolve_in_path("/bin/true"),
            Some(PathBuf::from("/bin/true"))
        );
        assert_eq!(
            resolve_in_path("definitely-not-a-filament-binary-xyz"),
            None
        );
        assert_eq!(resolve_in_path(""), None);
    }

    #[cfg(all(unix, feature = "exec-server"))]
    #[test]
    fn live_spawn_reports_real_exit_code() {
        let Some(sh) = resolve_in_path("sh") else {
            return;
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let status = rt.block_on(async {
            crate::platform::tokio_command(&sh)
                .arg("-c")
                .arg("exit 41")
                .status()
                .await
                .unwrap()
        });
        assert_eq!(ExecExit::from_std(status).wire_code(), Some(41));
    }
}
