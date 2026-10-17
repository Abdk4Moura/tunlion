//! SHELL INVOCATION: which flag runs a command, per shell family.
//!
//! This is process policy with no host opinion: it does not resolve a shell,
//! read a setting, or touch a file. The caller passes the argv it already
//! resolved (from `--shell-program`, the environment, config, `$SHELL` or the
//! platform default) and this decides how to invoke it. It moved here from
//! `cli::platform` so the receive loop can name it without the CLI, and so a
//! library consumer that serves a PTY asks the same rule.

use std::path::Path;

/// Shell invocation strategy: the correct flag for running a command depends
/// on the shell family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellKind {
    /// sh / bash / zsh / fish / dash: `-c 'cmd'`
    Posix,
    /// powershell.exe / pwsh.exe / pwsh: `-Command 'cmd'`
    PowerShell,
    /// cmd.exe: `/c cmd`
    Cmd,
}

/// Resolves the shell program and provides the correct invocation for
/// interactive (login PTY) and one-shot (`exec cmd`) modes.
pub struct ShellHost {
    argv: Vec<String>,
    kind: ShellKind,
}

impl ShellHost {
    /// Resolve the shell from the precedence chain. No external resolution
    /// is done here: callers pass the already-resolved argv (from
    /// --shell-program / TUNLION_SHELL / config / $SHELL / platform default).
    pub fn new(shell_argv: &[String]) -> Self {
        let binary = shell_argv.first().map(|s| s.as_str()).unwrap_or("");
        let name = Path::new(binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        let kind = if name.contains("pwsh") || name.contains("powershell") {
            ShellKind::PowerShell
        } else if name == "cmd.exe" || name == "cmd" {
            ShellKind::Cmd
        } else {
            ShellKind::Posix
        };
        ShellHost {
            argv: shell_argv.to_vec(),
            kind,
        }
    }

    /// True when the argv is the `--shell-user` drop built by `shell_argv`.
    fn is_user_drop(&self) -> bool {
        self.argv.len() >= 3
            && Path::new(&self.argv[0])
                .file_name()
                .and_then(|n| n.to_str())
                == Some("runuser")
    }

    /// Args for spawning an INTERACTIVE login shell (PTY session).
    pub fn interactive_args(&self) -> Vec<String> {
        let mut args = self.argv.clone();
        match self.kind {
            ShellKind::Posix => {
                if !args.iter().any(|a| a == "-l" || a == "--login") {
                    args.push("-l".into());
                }
                args
            }
            _ => args,
        }
    }

    /// Args for running a one-shot COMMAND (returns, no interactive shell).
    pub fn exec_cmd_args(&self, cmd: &str) -> Vec<String> {
        // A `--shell-user` argv is `runuser -l <user>`. Keeping only argv[0]
        // here would yield `runuser -c <cmd>`, and runuser with no user named
        // defaults to root: the one-shot command would run as root while the
        // operator asked for <user>. Keep the whole drop prefix instead.
        if self.is_user_drop() {
            let mut args = self.argv.clone();
            args.push("-c".into());
            args.push(cmd.to_string());
            return args;
        }
        let mut args = vec![self.argv[0].clone()];
        match self.kind {
            ShellKind::Posix => {
                args.push("-c".into());
                args.push(cmd.to_string());
            }
            ShellKind::PowerShell => {
                args.push("-Command".into());
                args.push(cmd.to_string());
            }
            ShellKind::Cmd => {
                args.push("/c".into());
                args.push(cmd.to_string());
            }
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::ShellHost;

    #[test]
    fn shell_host_interactive_posix_adds_login() {
        let sh = ShellHost::new(&["/bin/bash".into()]);
        assert!(sh.interactive_args().contains(&"-l".into()));
    }

    #[test]
    fn shell_host_exec_posix_uses_minus_c() {
        let sh = ShellHost::new(&["bash".into()]);
        let args = sh.exec_cmd_args("echo hi");
        assert_eq!(args[0], "bash");
        assert_eq!(args[1], "-c");
        assert_eq!(args[2], "echo hi");
    }

    #[test]
    fn shell_host_exec_powershell_uses_command_flag() {
        let sh = ShellHost::new(&["pwsh.exe".into()]);
        let args = sh.exec_cmd_args("Get-Date");
        assert_eq!(args[1], "-Command");
        assert_eq!(args[2], "Get-Date");
    }

    #[test]
    fn shell_host_exec_cmd_uses_slash_c() {
        let sh = ShellHost::new(&["cmd.exe".into()]);
        let args = sh.exec_cmd_args("dir");
        assert_eq!(args[1], "/c");
        assert_eq!(args[2], "dir");
    }

    // --shell-user one-shot PTY command: the drop prefix must survive, or
    // `runuser -c <cmd>` runs the command as root.
    #[test]
    fn shell_host_exec_keeps_the_shell_user_drop() {
        let sh = ShellHost::new(&["runuser".into(), "-l".into(), "nobody".into()]);
        assert_eq!(
            sh.exec_cmd_args("id -un"),
            vec!["runuser", "-l", "nobody", "-c", "id -un"]
        );
        assert_eq!(sh.interactive_args(), vec!["runuser", "-l", "nobody"]);
    }
}
