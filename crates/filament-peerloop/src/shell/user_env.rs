//! The environment a served `exec` or shell starts with: the one the OS gives
//! a new process of that account, as sshd does, never the daemon's.
//!
//! A remote command should feel like the user opening a terminal on that
//! machine. The daemon was started once, possibly long ago and possibly with
//! variables only it should have (`TUNLION_AUTHKEY`, a proxy or token it was
//! launched with), so its own environment is the wrong base: it went stale
//! (a PATH edit or a tool installed since was invisible until a restart) and
//! anything copied from it could leak. Instead the child inherits the
//! platform default, and the account's own startup files build the rest:
//!
//! - Windows: the account's environment block (`CreateEnvironmentBlock` on
//!   the daemon's own token, not inheriting the daemon's block), read fresh
//!   per spawn. Machine and user registry variables, a merged current PATH,
//!   the profile directories: what Explorer gives a new process. Without one
//!   (the daemon runs as a service account, the API failed) another account's
//!   profile is never handed out: the child keeps the filtered baseline this
//!   module replaced, and the caller says why in its debug log.
//! - Unix: what sshd builds before the shell runs. The system default
//!   variables (the pam_env files, `/etc/environment` and
//!   `/etc/default/locale`), then `HOME`, `USER`, `LOGNAME` and `SHELL` from
//!   the password database for the account the child runs as, and a standard
//!   PATH when the system defines none. An interactive shell is a login
//!   shell, so `/etc/profile`, `~/.profile` and `~/.bashrc` do the rest.
//!
//! Layered on top, and nothing else from the daemon: `TERM`/`COLORTERM`/`LANG`
//! and `LC_*` (the session's terminal and locale), the daemon's
//! `TUNLION_CONFIG_DIR` for a same-account child (#602: a `tunlion` it runs
//! finds the daemon that served it), and the explicit `--env` pairs, which win.
//! A daemon-only variable reaches the child only when the account's own
//! default environment also defines it, and then with that value.

use super::exec::ExecUserContext;
use std::path::Path;

/// The variable that moves tunlion's config dir off its platform default.
pub const CONFIG_DIR_ENV: &str = "TUNLION_CONFIG_DIR";

/// The PATH a Unix child gets when the system's default environment sets
/// none: OpenSSH's standard path with the local and sbin directories.
pub const UNIX_DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The session's terminal and locale facts: the only daemon variables a child
/// keeps. `LC_*` joins by prefix.
fn is_session_var(k: &str, windows: bool) -> bool {
    ["TERM", "COLORTERM", "LANG"]
        .iter()
        .any(|name| same_name(k, name, windows))
        || if windows {
            k.get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("LC_"))
        } else {
            k.starts_with("LC_")
        }
}

/// The non-secret Windows platform variables the pre-account-block builder
/// copied from the daemon, kept ONLY for the fallback below. Values are the
/// daemon's, but these names cannot carry a credential, and they are what a
/// normal Windows process needs (`SystemRoot` and friends for Win32 itself,
/// `PATH`/`PATHEXT`/`COMSPEC` for program lookup, the profile roots for
/// toolchains). Deliberately absent, as before: proxies, tokens, `NODE_OPTIONS`,
/// `SSH_AUTH_SOCK`, session-bus addresses and every variable that can carry a
/// secret.
const WINDOWS_PLATFORM_ENV: [&str; 23] = [
    "SystemRoot",
    "WINDIR",
    "SYSTEMDRIVE",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "PSModulePath",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE",
];

/// Split a `C:\Users\name` home into `(C:, \Users\name)` for the legacy
/// HOMEDRIVE/HOMEPATH pair Windows tools still read. UNC and drive-relative
/// homes are left alone: inventing a drive for them would be worse than
/// omitting the pair.
fn windows_home_parts(home: &Path) -> Option<(String, String)> {
    let text = home.to_str()?;
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let rest = &text[2..];
    if !rest.starts_with('\\') {
        return None;
    }
    let rest = if rest.is_empty() { "\\" } else { rest };
    Some((text[..2].to_string(), rest.to_string()))
}

/// Whether `home` is an absolute Windows path. Checked as text, not with
/// `Path::is_absolute`, so the Windows rule is testable on every host.
fn windows_absolute(home: &Path) -> bool {
    let Some(text) = home.to_str() else {
        return false;
    };
    let bytes = text.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || text.starts_with(r"\\")
}

/// The Windows environment this module replaced: the daemon's non-secret
/// platform variables, with the profile roots filled from the resolved
/// account. Used only when there is no account block to read, so a service
/// account's profile is never handed out in its place.
fn windows_daemon_baseline(
    daemon: &[(String, String)],
    user: &ExecUserContext,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in daemon {
        if let Some(canonical) = WINDOWS_PLATFORM_ENV
            .iter()
            .copied()
            .find(|name| name.eq_ignore_ascii_case(k))
        {
            set(&mut out, canonical, v, true);
        }
    }
    let ensure = |out: &mut Vec<(String, String)>, k: &str, v: &str| {
        if !out.iter().any(|(name, _)| name.eq_ignore_ascii_case(k)) {
            out.push((k.to_string(), v.to_string()));
        }
    };
    if !user.name.is_empty() {
        ensure(&mut out, "USERNAME", &user.name);
    }
    if windows_absolute(&user.home) {
        ensure(&mut out, "USERPROFILE", &user.home.to_string_lossy());
        if let Some((drive, path)) = windows_home_parts(&user.home) {
            ensure(&mut out, "HOMEDRIVE", &drive);
            ensure(&mut out, "HOMEPATH", &path);
        }
        ensure(
            &mut out,
            "APPDATA",
            &user.home.join("AppData").join("Roaming").to_string_lossy(),
        );
        ensure(
            &mut out,
            "LOCALAPPDATA",
            &user.home.join("AppData").join("Local").to_string_lossy(),
        );
    }
    out
}

fn same_name(a: &str, b: &str, windows: bool) -> bool {
    if windows {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Set `k`, replacing an existing name (case-insensitively on Windows, where
/// a duplicate would collapse unpredictably).
fn set(out: &mut Vec<(String, String)>, k: &str, v: &str, windows: bool) {
    if let Some(slot) = out.iter_mut().find(|(e, _)| same_name(e, k, windows)) {
        slot.0 = k.to_string();
        slot.1 = v.to_string();
    } else {
        out.push((k.to_string(), v.to_string()));
    }
}

/// The child's environment; see the module docs for the rule.
///
/// `account` is the platform default for a new process of the daemon's
/// account (Windows: its environment block; Unix: the pam_env defaults), or
/// why there is none. `dropped` means `--shell-user`: `user` is then the
/// target account (from the password database on Unix; refused on Windows).
pub fn child_env(
    windows: bool,
    user: &ExecUserContext,
    dropped: bool,
    account: Result<Vec<(String, String)>, String>,
    daemon: &[(String, String)],
    explicit: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    if windows && dropped {
        return Err(format!(
            "exec refused: --shell-user {} needs the target account's token environment; refusing to copy the daemon's Windows profile",
            user.name
        ));
    }
    let mut out: Vec<(String, String)> = Vec::new();
    match account {
        Ok(block) => {
            for (k, v) in &block {
                // `=C:=C:\dir` entries are per-drive cwd records, not variables.
                if !k.is_empty() && !k.starts_with('=') {
                    set(&mut out, k, v, windows);
                }
            }
        }
        Err(_) if windows => {
            // Owner's rule: never hand out a service account's (or another
            // account's) profile. This corner keeps the filtered baseline the
            // account block replaced; the caller logs why.
            out = windows_daemon_baseline(daemon, user);
        }
        // Unix: no system defaults readable; the identity and PATH below
        // are still the account's.
        Err(_) => {}
    }
    if !windows {
        set(&mut out, "HOME", &user.home.to_string_lossy(), false);
        set(&mut out, "USER", &user.name, false);
        set(&mut out, "LOGNAME", &user.name, false);
        set(&mut out, "SHELL", user.shell.as_deref().unwrap_or("/bin/sh"), false);
        if !out.iter().any(|(k, _)| k == "PATH") {
            set(&mut out, "PATH", UNIX_DEFAULT_PATH, false);
        }
    }
    for (k, v) in daemon {
        let session = is_session_var(k, windows);
        let config_dir = !dropped && same_name(k, CONFIG_DIR_ENV, windows);
        if session || config_dir {
            set(&mut out, k, v, windows);
        }
    }
    for (k, v) in explicit {
        set(&mut out, k, v, windows);
    }
    Ok(out)
}

/// Parse a Windows environment block (UTF-16, `NAME=value` entries separated
/// by NUL, ended by an empty entry) into pairs. A leading `=` belongs to the
/// name (`=C:`), so the split is on the first `=` after position 0.
pub fn parse_environment_block(block: &[u16]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in block.split(|c| *c == 0) {
        if entry.is_empty() {
            break;
        }
        let text = String::from_utf16_lossy(entry);
        if let Some((i, _)) = text.char_indices().skip(1).find(|(_, c)| *c == '=') {
            out.push((text[..i].to_string(), text[i + 1..].to_string()));
        }
    }
    out
}

/// Parse a pam_env style defaults file (`/etc/environment`,
/// `/etc/default/locale`): `NAME=value` lines, optional `export `, optional
/// matching quotes, `#` comments. Lines it cannot read are skipped, as
/// pam_env skips them.
pub fn parse_pam_env_file(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let v = v.trim();
        let v = ['"', '\'']
            .iter()
            .find_map(|q| v.strip_prefix(*q).and_then(|s| s.strip_suffix(*q)))
            .unwrap_or(v);
        out.push((k.to_string(), v.to_string()));
    }
    out
}

/// `PATH` in `env` (case-insensitively, which also covers Windows' `Path`).
pub fn path_of(env: &[(String, String)]) -> Option<&str> {
    env.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.as_str())
}

/// The OS default environment for a new process of the daemon's account,
/// read fresh now. Windows: `CreateEnvironmentBlock` on this process's token
/// with `bInherit = FALSE`; refused for SYSTEM, LocalService and
/// NetworkService, whose profile is not a user's. Unix: the pam_env default
/// files sshd's session reads (`/etc/environment`, `/etc/default/locale`).
pub fn os_account_environment() -> Result<Vec<(String, String)>, String> {
    #[cfg(windows)]
    {
        windows_account_block()
    }
    #[cfg(not(windows))]
    {
        let mut out = Vec::new();
        let mut read = false;
        for path in ["/etc/environment", "/etc/default/locale"] {
            if let Ok(text) = std::fs::read_to_string(path) {
                read = true;
                for (k, v) in parse_pam_env_file(&text) {
                    set(&mut out, &k, &v, false);
                }
            }
        }
        if read {
            Ok(out)
        } else {
            Err("no system default environment files".into())
        }
    }
}

#[cfg(windows)]
fn windows_account_block() -> Result<Vec<(String, String)>, String> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalServiceSid, WinLocalSystemSid,
        WinNetworkServiceSid, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let last = || std::io::Error::last_os_error();
    let mut raw: HANDLE = std::ptr::null_mut();
    let access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE;
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut raw) } == 0 {
        return Err(format!("OpenProcessToken: {}", last()));
    }
    let token = Token(raw);
    let mut len = 0u32;
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(format!("GetTokenInformation: {}", last()));
    }
    // TOKEN_USER holds a pointer: back the buffer with pointer-sized words.
    let mut words = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
    let buf = words.as_mut_ptr() as *mut c_void;
    if unsafe { GetTokenInformation(token.0, TokenUser, buf, len, &mut len) } == 0 {
        return Err(format!("GetTokenInformation: {}", last()));
    }
    let sid = unsafe { (*(words.as_ptr() as *const TOKEN_USER)).User.Sid };
    for (kind, name) in [
        (WinLocalSystemSid, "SYSTEM"),
        (WinLocalServiceSid, "LocalService"),
        (WinNetworkServiceSid, "NetworkService"),
    ] {
        if unsafe { IsWellKnownSid(sid, kind) } != 0 {
            return Err(format!("the daemon runs as {name}, whose profile is not a user's"));
        }
    }
    let mut block: *mut c_void = std::ptr::null_mut();
    if unsafe { CreateEnvironmentBlock(&mut block, token.0, 0) } == 0 || block.is_null() {
        return Err(format!("CreateEnvironmentBlock: {}", last()));
    }
    // The block ends with an empty entry (two NULs in a row).
    let start = block as *const u16;
    let mut n = 0usize;
    while unsafe { *start.add(n) != 0 || *start.add(n + 1) != 0 } {
        n += 1;
    }
    let units = unsafe { std::slice::from_raw_parts(start, n + 2) };
    let pairs = parse_environment_block(units);
    unsafe { DestroyEnvironmentBlock(block) };
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
        env.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }

    fn me(windows: bool) -> ExecUserContext {
        ExecUserContext {
            name: "me".into(),
            home: PathBuf::from(if windows { r"C:\Users\me" } else { "/home/me" }),
            shell: if windows { None } else { Some("/bin/zsh".into()) },
            uid: if windows { None } else { Some(1000) },
        }
    }

    /// What the daemon process happens to have: stale, and partly secret.
    fn daemon() -> Vec<(String, String)> {
        kv(&[
            ("PATH", "/stale/daemon/path"),
            ("HOME", "/daemon/home"),
            ("TUNLION_AUTHKEY", "filament-invite:secret"),
            ("HTTPS_PROXY", "http://token@proxy"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("TUNLION_CONFIG_DIR", "/srv/cfg"),
            ("TERM", "xterm-256color"),
            ("COLORTERM", "truecolor"),
            ("LANG", "daemon-locale"),
            ("LC_ALL", "daemon-lc"),
        ])
    }

    fn assert_nothing_else_of_the_daemon(env: &[(String, String)]) {
        for k in ["TUNLION_AUTHKEY", "HTTPS_PROXY", "SSH_AUTH_SOCK"] {
            assert_eq!(get(env, k), None, "{k} exists only in the daemon process");
        }
        assert_ne!(get(env, "PATH"), Some("/stale/daemon/path"));
    }

    #[test]
    fn windows_child_is_the_account_block_plus_the_session_and_config_dir() {
        let block = kv(&[
            ("Path", r"C:\Windows\system32;C:\Users\me\go\bin"),
            ("JAVA_HOME", r"C:\jdk"),
            ("NUMBER_OF_PROCESSORS", "4"),
            ("OS", "Windows_NT"),
            ("USERPROFILE", r"C:\Users\me"),
            ("=C:", r"C:\somewhere"),
        ]);
        let env = child_env(true, &me(true), false, Ok(block), &daemon(), &[]).unwrap();
        assert_eq!(get(&env, "PATH"), Some(r"C:\Windows\system32;C:\Users\me\go\bin"));
        assert_eq!(get(&env, "JAVA_HOME"), Some(r"C:\jdk"));
        assert_eq!(get(&env, "NUMBER_OF_PROCESSORS"), Some("4"));
        assert_eq!(get(&env, "OS"), Some("Windows_NT"));
        assert_eq!(get(&env, "TERM"), Some("xterm-256color"));
        assert_eq!(get(&env, "COLORTERM"), Some("truecolor"));
        assert_eq!(get(&env, "TUNLION_CONFIG_DIR"), Some("/srv/cfg"));
        assert_eq!(get(&env, "LANG"), Some("daemon-locale"), "locale is a session fact");
        assert_eq!(get(&env, "LC_ALL"), Some("daemon-lc"));
        assert_eq!(get(&env, "HOME"), None, "Windows identity is the block's");
        assert!(env.iter().all(|(k, _)| !k.starts_with('=')));
        assert_nothing_else_of_the_daemon(&env);
    }

    #[test]
    fn windows_without_a_block_keeps_the_filtered_baseline_not_the_whole_daemon_env() {
        let env = child_env(true, &me(true), false, Err("the daemon runs as SYSTEM".into()), &daemon(), &[])
            .unwrap();
        // The old baseline: the daemon's allowlisted platform variables...
        assert_eq!(get(&env, "PATH"), Some("/stale/daemon/path"));
        assert_eq!(get(&env, "HOME"), None, "HOME is not a Windows platform variable");
        assert_eq!(get(&env, "USERNAME"), Some("me"), "filled from the resolved account");
        assert_eq!(get(&env, "USERPROFILE"), Some(r"C:\Users\me"));
        assert_eq!(get(&env, "HOMEDRIVE"), Some("C:"));
        assert_eq!(get(&env, "HOMEPATH"), Some(r"\Users\me"));
        // ...the session facts, and nothing that could carry a secret.
        assert_eq!(get(&env, "TERM"), Some("xterm-256color"));
        assert_eq!(get(&env, "TUNLION_CONFIG_DIR"), Some("/srv/cfg"));
        for k in ["TUNLION_AUTHKEY", "HTTPS_PROXY", "SSH_AUTH_SOCK"] {
            assert_eq!(get(&env, k), None, "{k} exists only in the daemon process");
        }

        let guest = ExecUserContext { name: "guest".into(), ..me(true) };
        let err = child_env(true, &guest, true, Ok(vec![]), &daemon(), &[]).unwrap_err();
        assert!(err.contains("--shell-user guest") && err.contains("token environment"), "{err}");
    }

    #[test]
    fn unix_child_is_the_system_defaults_and_the_passwd_identity() {
        let pam = kv(&[("PATH", "/usr/local/bin:/usr/bin:/snap/bin"), ("LANG", "en_US.UTF-8")]);
        let env = child_env(false, &me(false), false, Ok(pam), &daemon(), &[]).unwrap();
        assert_eq!(get(&env, "HOME"), Some("/home/me"));
        assert_eq!(get(&env, "USER"), Some("me"));
        assert_eq!(get(&env, "LOGNAME"), Some("me"));
        assert_eq!(get(&env, "SHELL"), Some("/bin/zsh"));
        assert_eq!(get(&env, "PATH"), Some("/usr/local/bin:/usr/bin:/snap/bin"));
        assert_eq!(get(&env, "LANG"), Some("daemon-locale"), "the session's locale wins over the system default");
        assert_eq!(get(&env, "LC_ALL"), Some("daemon-lc"));
        assert_eq!(get(&env, "TERM"), Some("xterm-256color"));
        assert_eq!(get(&env, "TUNLION_CONFIG_DIR"), Some("/srv/cfg"));
        assert_nothing_else_of_the_daemon(&env);

        // No readable defaults: identity, a standard PATH and the session.
        let env = child_env(false, &me(false), false, Err("none".into()), &daemon(), &[]).unwrap();
        let mut names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["COLORTERM", "HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "SHELL", "TERM", "TUNLION_CONFIG_DIR", "USER"]
        );
        assert_eq!(get(&env, "PATH"), Some(UNIX_DEFAULT_PATH));
    }

    #[test]
    fn a_dropped_unix_account_gets_its_own_identity_and_never_the_config_dir() {
        let guest = ExecUserContext {
            name: "guest".into(),
            home: PathBuf::from("/home/guest"),
            shell: Some("/bin/bash".into()),
            uid: Some(1001),
        };
        let env = child_env(false, &guest, true, Ok(vec![]), &daemon(), &[]).unwrap();
        assert_eq!(get(&env, "HOME"), Some("/home/guest"));
        assert_eq!(get(&env, "USER"), Some("guest"));
        assert_eq!(get(&env, "SHELL"), Some("/bin/bash"));
        assert_eq!(get(&env, "TUNLION_CONFIG_DIR"), None);
        assert_nothing_else_of_the_daemon(&env);
    }

    #[test]
    fn explicit_env_wins_case_insensitively_only_on_windows() {
        let explicit = kv(&[("term", "screen"), ("PATH", "/explicit"), ("TUNLION_CONFIG_DIR", "/other")]);
        let env = child_env(true, &me(true), false, Ok(kv(&[("Path", r"C:\w")])), &daemon(), &explicit).unwrap();
        assert_eq!(get(&env, "TERM"), Some("screen"));
        assert_eq!(env.iter().filter(|(k, _)| k.eq_ignore_ascii_case("TERM")).count(), 1);
        assert_eq!(get(&env, "PATH"), Some("/explicit"));
        assert_eq!(env.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PATH")).count(), 1);
        assert_eq!(get(&env, "TUNLION_CONFIG_DIR"), Some("/other"));

        let env = child_env(false, &me(false), false, Ok(vec![]), &daemon(), &explicit).unwrap();
        assert!(env.iter().any(|(k, v)| k == "term" && v == "screen"), "Unix names stay case-sensitive");
        assert!(env.iter().any(|(k, v)| k == "TERM" && v == "xterm-256color"));
        assert!(env.iter().any(|(k, v)| k == "PATH" && v == "/explicit"));
    }

    #[test]
    fn an_environment_block_parses_into_pairs() {
        let text = "=C:=C:\\x\0Path=C:\\a;C:\\b\0EMPTY=\0EQ=a=b\0\0ignored=1\0";
        let block: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(
            parse_environment_block(&block),
            kv(&[("=C:", "C:\\x"), ("Path", "C:\\a;C:\\b"), ("EMPTY", ""), ("EQ", "a=b")])
        );
        assert_eq!(path_of(&parse_environment_block(&block)), Some("C:\\a;C:\\b"));
    }

    #[test]
    fn pam_env_files_parse_like_pam_env() {
        let text = "# comment\nPATH=\"/usr/local/bin:/usr/bin\"\nexport LANG='en_US.UTF-8'\nBAD LINE\n  LC_TIME=C\n=nope\n";
        assert_eq!(
            parse_pam_env_file(text),
            kv(&[("PATH", "/usr/local/bin:/usr/bin"), ("LANG", "en_US.UTF-8"), ("LC_TIME", "C")])
        );
    }
}
