//! Every child process is built through `platform::command` /
//! `platform::tokio_command`, never with a bare `Command::new`.
//!
//! Why: on Windows a process without a console of its own (the daemon after
//! `up --detach`, or one started at logon) gives each console child (netsh,
//! icacls, whoami, reg, schtasks, ssh, ...) a new console window that flashes
//! on screen. The helpers add CREATE_NO_WINDOW in exactly that case. One bare
//! `Command::new` in a path the daemon reaches brings the flashing back, and
//! nobody notices on Linux, where CI and most of us run.
//!
//! The library crates under crates/ cannot reach the cli helper; a crate file
//! that spawns must set CREATE_NO_WINDOW itself.

use std::path::{Path, PathBuf};

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn spawn_lines(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.contains("Command::new(") && !l.trim_start().starts_with("//"))
        .map(|(i, l)| (i + 1, l.trim().to_string()))
        .collect()
}

#[test]
fn cli_spawns_only_through_the_platform_helper() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let helper = src.join("platform").join("mod.rs");
    let mut files = Vec::new();
    rs_files(&src, &mut files);
    let mut bad = Vec::new();
    let mut helpers = 0;
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        for (n, l) in spawn_lines(&text) {
            if *f == helper && l.contains("// spawn-helper") {
                helpers += 1;
            } else {
                bad.push(format!("{}:{n}: {l}", f.strip_prefix(&src).unwrap().display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "bare Command::new in cli/src; use crate::platform::command (or tokio_command) so a Windows \
         daemon does not flash a console window:\n  {}",
        bad.join("\n  ")
    );
    assert_eq!(helpers, 2, "platform::command and platform::tokio_command should be the only two spawn sites");
}

#[test]
fn crate_spawns_set_create_no_window() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("crates");
    let Ok(rd) = std::fs::read_dir(&crates) else { return };
    let mut bad = Vec::new();
    for c in rd.flatten() {
        let mut files = Vec::new();
        rs_files(&c.path().join("src"), &mut files);
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap();
            if !spawn_lines(&text).is_empty() && !text.contains("CREATE_NO_WINDOW") {
                bad.push(f.display().to_string());
            }
        }
    }
    assert!(
        bad.is_empty(),
        "these crate files spawn a process without CREATE_NO_WINDOW on Windows:\n  {}",
        bad.join("\n  ")
    );
}
