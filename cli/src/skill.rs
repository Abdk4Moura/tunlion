//! `tunlion skill`: the opt-in agent skill.
//!
//! The binary carries skills/tunlion/SKILL.md, so the skill it installs always
//! describes the commands this build accepts (`the_skill_names_only_real_commands_and_flags`
//! below keeps the file honest). Nothing else ever installs it: not `init`, not
//! `up`, not the install scripts. A person runs `tunlion skill install` or the
//! skill does not exist on their machine.
//!
//! Layout written, per target skills directory:
//!
//!   <skills>/tunlion/SKILL.md        the embedded file
//!   <skills>/tunlion/.tunlion-skill  this CLI's version; the ownership marker
//!
//! The marker is what makes a directory ours. Install replaces a marked
//! directory (an update) and refuses an unmarked one unless --force; uninstall
//! removes marked directories only.

use crate::cli_def::{SkillAction, SkillTargets};
use crate::exit_codes::{ExitKind, err, is_local_resource_text};
use anyhow::Result;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// The skill, as this build describes itself.
pub(crate) const SKILL_MD: &str = include_str!("../../skills/tunlion/SKILL.md");
/// The ownership marker inside an installed skill directory.
pub(crate) const MARKER: &str = ".tunlion-skill";
/// The skill's directory name under a skills directory.
const SKILL_DIR: &str = "tunlion";
/// What the marker holds.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The skills directories a command acts on. Explicit flags win and may be
/// combined. With none, install uses each of ~/.claude and ~/.agents that
/// exists; uninstall looks in both.
pub(crate) fn resolve_targets(home: &Path, t: &SkillTargets, for_install: bool) -> Result<Vec<PathBuf>> {
    fn push(out: &mut Vec<PathBuf>, p: PathBuf) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    let mut out: Vec<PathBuf> = Vec::new();
    if t.claude {
        push(&mut out, home.join(".claude").join("skills"));
    }
    if t.agents {
        push(&mut out, home.join(".agents").join("skills"));
    }
    if let Some(d) = &t.dir {
        push(&mut out, d.clone());
    }
    if t.claude || t.agents || t.dir.is_some() {
        return Ok(out);
    }
    for parent in [".claude", ".agents"] {
        let base = home.join(parent);
        if !for_install || base.is_dir() {
            push(&mut out, base.join("skills"));
        }
    }
    if out.is_empty() {
        return Err(err(
            ExitKind::Usage,
            format!(
                "no agent directory found: neither {} nor {} exists. Pass --claude (~/.claude/skills), \
                 --agents (~/.agents/skills) or --dir <path> to choose where the skill goes",
                home.join(".claude").display(),
                home.join(".agents").display()
            ),
        ));
    }
    Ok(out)
}

/// What is at `<skills>/tunlion` now.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Existing {
    Absent,
    /// A directory carrying our marker: ours to replace or remove.
    Ours,
    /// Anything else: someone else's, left alone unless --force.
    Foreign,
}

pub(crate) fn existing(skill_dir: &Path) -> Existing {
    if std::fs::symlink_metadata(skill_dir).is_err() {
        return Existing::Absent;
    }
    let marked = std::fs::symlink_metadata(skill_dir).map(|m| m.is_dir()).unwrap_or(false)
        && std::fs::symlink_metadata(skill_dir.join(MARKER))
            .map(|m| m.is_file())
            .unwrap_or(false);
    if marked { Existing::Ours } else { Existing::Foreign }
}

/// An I/O failure here: a full disk is 12, anything else 1. Classified
/// explicitly so a "permission denied" from the filesystem does not read as
/// a peer's refusal (4).
fn io_failure(what: &str, path: &Path, e: std::io::Error) -> anyhow::Error {
    let msg = format!("{what} {}: {e}", path.display());
    if is_local_resource_text(&msg) {
        err(ExitKind::LocalResource, msg)
    } else {
        err(ExitKind::Other, msg)
    }
}

/// Remove a file, a symlink or a directory tree (never following a link).
fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

/// The refusal for a directory that is not ours.
fn foreign_refusal(skill_dir: &Path) -> anyhow::Error {
    err(
        ExitKind::Usage,
        format!(
            "{} exists and was not installed by tunlion (it has no {MARKER} marker); \
             refusing to replace it. Move it away, or pass --force to overwrite it",
            skill_dir.display()
        ),
    )
}

/// Install into one skills directory. Returns the SKILL.md path written and
/// whether an earlier install was replaced.
///
/// Atomic: the new directory is built under a temporary name beside the
/// target and renamed into place, so a reader sees the old skill or the new
/// one, never half of either.
pub(crate) fn install_into(skills: &Path, force: bool) -> Result<(PathBuf, bool)> {
    let dest = skills.join(SKILL_DIR);
    let prior = existing(&dest);
    if prior == Existing::Foreign && !force {
        return Err(foreign_refusal(&dest));
    }
    std::fs::create_dir_all(skills).map_err(|e| io_failure("could not create", skills, e))?;
    let suffix = unique_suffix();
    let staging = skills.join(format!(".{SKILL_DIR}.new-{suffix}"));
    let build = || -> Result<()> {
        std::fs::create_dir(&staging).map_err(|e| io_failure("could not create", &staging, e))?;
        let md = staging.join("SKILL.md");
        std::fs::write(&md, SKILL_MD).map_err(|e| io_failure("could not write", &md, e))?;
        let marker = staging.join(MARKER);
        std::fs::write(&marker, format!("{VERSION}\n"))
            .map_err(|e| io_failure("could not write", &marker, e))?;
        Ok(())
    };
    if let Err(e) = build() {
        let _ = remove_any(&staging);
        return Err(e);
    }
    let replaced = prior != Existing::Absent;
    if replaced {
        // Move the old one aside first: a directory cannot be renamed onto a
        // non-empty one. Put back if the new one cannot take its place.
        let old = skills.join(format!(".{SKILL_DIR}.old-{suffix}"));
        if let Err(e) = std::fs::rename(&dest, &old) {
            let _ = remove_any(&staging);
            return Err(io_failure("could not move aside", &dest, e));
        }
        if let Err(e) = std::fs::rename(&staging, &dest) {
            let _ = std::fs::rename(&old, &dest);
            let _ = remove_any(&staging);
            return Err(io_failure("could not install", &dest, e));
        }
        let _ = remove_any(&old);
    } else if let Err(e) = std::fs::rename(&staging, &dest) {
        let _ = remove_any(&staging);
        return Err(io_failure("could not install", &dest, e));
    }
    Ok((dest.join("SKILL.md"), replaced))
}

/// What uninstall found in one skills directory.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed(PathBuf),
    /// Present but not ours: left exactly as it was.
    NotOurs(PathBuf),
    Absent,
}

/// Remove `<skills>/tunlion` if, and only if, it carries our marker.
pub(crate) fn uninstall_from(skills: &Path) -> Result<Removal> {
    let dest = skills.join(SKILL_DIR);
    match existing(&dest) {
        Existing::Absent => Ok(Removal::Absent),
        Existing::Foreign => Ok(Removal::NotOurs(dest)),
        Existing::Ours => {
            std::fs::remove_dir_all(&dest).map_err(|e| io_failure("could not remove", &dest, e))?;
            Ok(Removal::Removed(dest))
        }
    }
}

fn paths(v: &[PathBuf]) -> Vec<String> {
    v.iter().map(|p| p.display().to_string()).collect()
}

/// `tunlion skill install` against `home`. Every target is checked before any
/// is written, so a refusal leaves nothing half-installed.
pub(crate) fn install(home: &Path, targets: &SkillTargets, force: bool) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let dirs = resolve_targets(home, targets, true)?;
    if !force {
        for d in &dirs {
            let dest = d.join(SKILL_DIR);
            if existing(&dest) == Existing::Foreign {
                return Err(foreign_refusal(&dest));
            }
        }
    }
    let mut installed = Vec::new();
    let mut updated = Vec::new();
    for d in &dirs {
        let (md, replaced) = install_into(d, force)?;
        if replaced {
            updated.push(md.clone());
        }
        installed.push(md);
    }
    Ok((installed, updated))
}

/// `tunlion skill uninstall` against `home`.
pub(crate) fn uninstall(home: &Path, targets: &SkillTargets) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut removed = Vec::new();
    let mut skipped = Vec::new();
    for d in resolve_targets(home, targets, false)? {
        match uninstall_from(&d)? {
            Removal::Removed(p) => removed.push(p),
            Removal::NotOurs(p) => skipped.push(p),
            Removal::Absent => {}
        }
    }
    Ok((removed, skipped))
}

fn result(action: &str, extra: Value) -> Value {
    let mut v = json!({ "ok": true, "verb": "skill", "action": action });
    if let (Some(obj), Value::Object(more)) = (v.as_object_mut(), extra) {
        obj.extend(more);
    }
    v
}

/// The `tunlion skill` verb.
pub(crate) fn skill_cmd(action: SkillAction, json_out: bool) -> Result<()> {
    let home = crate::platform::Paths::home_dir();
    match action {
        SkillAction::Show => {
            if json_out {
                crate::ui::json_out(&result(
                    "show",
                    json!({ "version": VERSION, "content": SKILL_MD }),
                ));
            } else {
                print!("{SKILL_MD}");
            }
        }
        SkillAction::Install { target, force } => {
            let (installed, updated) = install(&home, &target, force)?;
            if json_out {
                crate::ui::json_out(&result(
                    "install",
                    json!({
                        "version": VERSION,
                        "installed": paths(&installed),
                        "updated": paths(&updated),
                    }),
                ));
            } else {
                for p in &installed {
                    let how = if updated.contains(p) { "updated" } else { "installed" };
                    println!("{how} {}", p.display());
                }
            }
        }
        SkillAction::Uninstall { target } => {
            let (removed, skipped) = uninstall(&home, &target)?;
            if json_out {
                crate::ui::json_out(&result(
                    "uninstall",
                    json!({ "removed": paths(&removed), "skipped": paths(&skipped) }),
                ));
            } else {
                for p in &removed {
                    println!("removed {}", p.display());
                }
                for p in &skipped {
                    crate::ui::say(&format!(
                        "left {} alone: it has no {MARKER} marker, so this CLI did not install it",
                        p.display()
                    ));
                }
                if removed.is_empty() {
                    crate::ui::say("nothing to remove: this CLI found no skill it had installed");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tl-skill-{tag}-{}", unique_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn targets(claude: bool, agents: bool, dir: Option<PathBuf>) -> SkillTargets {
        SkillTargets { claude, agents, dir }
    }

    #[test]
    fn no_flag_installs_into_each_agent_dir_that_exists() {
        let home = scratch("resolve");
        let none = targets(false, false, None);
        // Neither exists: a usage error naming the flags.
        let e = resolve_targets(&home, &none, true).unwrap_err();
        assert_eq!(crate::exit_codes::classify(&e).code(), 2);
        let msg = e.to_string();
        for flag in ["--claude", "--agents", "--dir"] {
            assert!(msg.contains(flag), "{msg}");
        }
        // Only ~/.claude exists.
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        assert_eq!(resolve_targets(&home, &none, true).unwrap(), vec![home.join(".claude/skills")]);
        // Both.
        std::fs::create_dir_all(home.join(".agents")).unwrap();
        assert_eq!(
            resolve_targets(&home, &none, true).unwrap(),
            vec![home.join(".claude/skills"), home.join(".agents/skills")]
        );
        // Explicit flags win and combine, whether or not the parent exists.
        let other = home.join("elsewhere");
        assert_eq!(
            resolve_targets(&home, &targets(false, true, Some(other.clone())), true).unwrap(),
            vec![home.join(".agents/skills"), other]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn uninstall_with_no_flag_looks_in_both_even_when_absent() {
        let home = scratch("resolve-un");
        assert_eq!(
            resolve_targets(&home, &targets(false, false, None), false).unwrap(),
            vec![home.join(".claude/skills"), home.join(".agents/skills")]
        );
        let (removed, skipped) = uninstall(&home, &targets(false, false, None)).unwrap();
        assert!(removed.is_empty() && skipped.is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_writes_the_skill_and_its_marker_then_updates_in_place() {
        let home = scratch("install");
        let skills = home.join("skills");
        let (md, replaced) = install_into(&skills, false).unwrap();
        assert!(!replaced);
        assert_eq!(md, skills.join("tunlion").join("SKILL.md"));
        assert_eq!(std::fs::read_to_string(&md).unwrap(), SKILL_MD);
        let marker = std::fs::read_to_string(skills.join("tunlion").join(MARKER)).unwrap();
        assert_eq!(marker.trim(), VERSION);
        // A stale copy of ours is replaced: that is an update, no --force.
        std::fs::write(&md, "old").unwrap();
        let (_, replaced) = install_into(&skills, false).unwrap();
        assert!(replaced, "a marked directory is an update");
        assert_eq!(std::fs::read_to_string(&md).unwrap(), SKILL_MD);
        // Nothing temporary is left beside it.
        let names: Vec<String> = std::fs::read_dir(&skills)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["tunlion".to_string()], "{names:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_unmarked_skill_is_refused_unless_forced() {
        let home = scratch("foreign");
        let skills = home.join("skills");
        let theirs = skills.join("tunlion");
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(theirs.join("SKILL.md"), "someone else's").unwrap();
        let e = install_into(&skills, false).unwrap_err();
        assert_eq!(crate::exit_codes::classify(&e).code(), 2);
        assert!(e.to_string().contains("--force"), "{e}");
        assert!(e.to_string().contains(MARKER), "says why: {e}");
        assert_eq!(std::fs::read_to_string(theirs.join("SKILL.md")).unwrap(), "someone else's");
        // The multi-target path refuses before writing anything anywhere:
        // ~/.agents/skills comes first and must not be written either.
        let e = install(&home, &targets(false, true, Some(skills.clone())), false).unwrap_err();
        assert_eq!(crate::exit_codes::classify(&e).code(), 2);
        assert!(!home.join(".agents").join("skills").join("tunlion").exists());
        // --force overwrites it, and the result is ours from then on.
        let (md, replaced) = install_into(&skills, true).unwrap();
        assert!(replaced);
        assert_eq!(std::fs::read_to_string(&md).unwrap(), SKILL_MD);
        assert_eq!(existing(&theirs), Existing::Ours);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_plain_file_in_the_way_is_foreign_too() {
        let home = scratch("file");
        let skills = home.join("skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(skills.join("tunlion"), "a file").unwrap();
        assert_eq!(existing(&skills.join("tunlion")), Existing::Foreign);
        assert!(install_into(&skills, false).is_err());
        let (md, _) = install_into(&skills, true).unwrap();
        assert_eq!(std::fs::read_to_string(md).unwrap(), SKILL_MD);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn uninstall_removes_only_marked_directories() {
        let home = scratch("uninstall");
        let ours = home.join("a");
        let theirs = home.join("b");
        install_into(&ours, false).unwrap();
        std::fs::create_dir_all(theirs.join("tunlion")).unwrap();
        std::fs::write(theirs.join("tunlion").join("SKILL.md"), "keep me").unwrap();
        assert_eq!(uninstall_from(&ours).unwrap(), Removal::Removed(ours.join("tunlion")));
        assert!(!ours.join("tunlion").exists());
        assert!(ours.exists(), "the skills directory itself stays");
        assert_eq!(uninstall_from(&theirs).unwrap(), Removal::NotOurs(theirs.join("tunlion")));
        assert_eq!(
            std::fs::read_to_string(theirs.join("tunlion").join("SKILL.md")).unwrap(),
            "keep me"
        );
        // Again: nothing to remove is not an error.
        assert_eq!(uninstall_from(&ours).unwrap(), Removal::Absent);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The real entry point resolves ~ from HOME (USERPROFILE on Windows).
    #[test]
    fn install_and_uninstall_follow_the_home_directory() {
        let home = scratch("home");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let _guard = crate::tests::lock_test_config();
        let old_home = std::env::var_os("HOME");
        let old_profile = std::env::var_os("USERPROFILE");
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("USERPROFILE", &home);
        }
        let none = || targets(false, false, None);
        let installed = skill_cmd(SkillAction::Install { target: none(), force: false }, false);
        let removed = skill_cmd(SkillAction::Uninstall { target: none() }, false);
        let restore = |k: &str, v: Option<std::ffi::OsString>| match v {
            Some(v) => unsafe { std::env::set_var(k, v) },
            None => unsafe { std::env::remove_var(k) },
        };
        restore("HOME", old_home);
        restore("USERPROFILE", old_profile);
        installed.unwrap();
        removed.unwrap();
        assert!(home.join(".claude/skills").is_dir(), "installed under the existing ~/.claude");
        assert!(!home.join(".claude/skills/tunlion").exists());
        assert!(!home.join(".agents").exists(), "never creates ~/.agents on its own");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The drift guard. Every `tunlion ...` line in a fenced bash block of
    /// SKILL.md must name a real verb (and subverb), and every `--flag` on it
    /// must exist on that command or globally. An agent follows the skill
    /// literally; a flag that does not exist is a usage error it cannot see
    /// coming. When this fails, fix SKILL.md, not this test.
    #[test]
    fn the_skill_names_only_real_commands_and_flags() {
        use clap::CommandFactory;
        let mut root = crate::Cli::command();
        root.build();
        let names = |c: &clap::Command| {
            let mut v = vec![c.get_name().to_string()];
            v.extend(c.get_all_aliases().map(str::to_string));
            v
        };
        let placeholder = |t: &str| t.starts_with('<') || t.starts_with('[') || t.starts_with('\'') || t.starts_with('"');

        let mut in_bash = false;
        let mut checked = 0usize;
        let mut bad = Vec::new();
        for (n, line) in SKILL_MD.lines().enumerate() {
            let t = line.trim();
            if let Some(fence) = t.strip_prefix("```") {
                in_bash = !in_bash && matches!(fence.trim(), "bash" | "sh");
                continue;
            }
            if !in_bash {
                continue;
            }
            // The command ends at a comment or a shell operator.
            let cmd = t.split(" #").next().unwrap_or(t);
            let mut toks: Vec<&str> = Vec::new();
            for tok in cmd.split_whitespace() {
                if matches!(tok, ">" | ">>" | "<" | "|" | "&" | "&&" | "||" | ";" | "--") || tok.starts_with('#') {
                    break;
                }
                toks.push(tok);
            }
            if toks.first() != Some(&"tunlion") {
                continue;
            }
            let Some(verb) = toks.get(1) else { continue };
            let Some(mut cur) = root.get_subcommands().find(|sc| names(sc).iter().any(|x| x == verb)).cloned() else {
                bad.push(format!("  SKILL.md:{}: no verb `{verb}`: {t}", n + 1));
                continue;
            };
            checked += 1;
            let mut skip_value = false;
            for tok in &toks[2..] {
                // `[--to <host:port>]` documents an optional flag: check it too.
                let tok = tok.trim_start_matches('[').trim_end_matches(']').trim_end_matches(',');
                if std::mem::take(&mut skip_value) {
                    continue; // the value of the flag before it
                }
                if let Some(long) = tok.strip_prefix("--") {
                    let long = long.split('=').next().unwrap_or(long);
                    let arg = cur
                        .get_arguments()
                        .find(|a| a.get_long() == Some(long))
                        .or_else(|| root.get_arguments().find(|a| a.is_global_set() && a.get_long() == Some(long)));
                    match arg {
                        Some(a) => {
                            skip_value = !tok.contains('=')
                                && a.get_num_args().map(|r| r.min_values() > 0).unwrap_or(false);
                        }
                        None => bad.push(format!(
                            "  SKILL.md:{}: `{}` has no flag `--{long}`: {t}",
                            n + 1,
                            cur.get_name()
                        )),
                    }
                    continue;
                }
                if tok.starts_with('-') || placeholder(tok) || tok.is_empty() {
                    continue;
                }
                // A bare word right after a verb with subcommands must be one.
                if cur.get_subcommands().next().is_some() {
                    let found = cur.get_subcommands().find(|ss| names(ss).iter().any(|x| x == tok)).cloned();
                    match found {
                        Some(next) => cur = next,
                        None if cur.is_subcommand_required_set() => {
                            bad.push(format!("  SKILL.md:{}: `{}` has no subcommand `{tok}`: {t}", n + 1, cur.get_name()));
                            break;
                        }
                        // An optional subcommand: the word is a positional.
                        None => {}
                    }
                }
            }
        }
        assert!(checked >= 15, "read only {checked} commands from SKILL.md; the fences moved and this guard proves nothing");
        assert!(bad.is_empty(), "SKILL.md names commands or flags this build does not accept:\n{}", bad.join("\n"));
    }

    /// Every exit code and `error.code` token in SKILL.md's table is one this
    /// build can produce.
    #[test]
    fn the_skills_exit_code_table_matches_exit_codes_rs() {
        use crate::exit_codes::*;
        // Every code some verb's table in exit_codes.rs lists (that is where
        // up's 10, status's 11 and exec's 126/127/141 live), plus the kinds.
        // Read from the tables, not by naming the constants: this file is
        // scanned as `skill`'s source by `every_verbs_error_paths_are_in_its_help`.
        let mut codes: std::collections::HashSet<i32> = ExitKind::ALL.iter().map(|k| k.code()).collect();
        let root = <crate::Cli as clap::CommandFactory>::command();
        for sc in root.get_subcommands() {
            codes.extend(verb_exit_codes(sc.get_name()).iter().copied());
        }
        let mut tokens: std::collections::HashSet<&str> = ExitKind::ALL.iter().map(|k| k.token()).collect();
        tokens.insert(CORRUPT_STATE);
        tokens.insert("interrupted");

        let table: Vec<&str> = SKILL_MD
            .lines()
            .skip_while(|l| !l.starts_with("## Exit codes"))
            .skip(1)
            .take_while(|l| !l.starts_with("## "))
            .filter(|l| l.starts_with('|') && !l.starts_with("|---") && !l.starts_with("| Exit"))
            .collect();
        assert!(table.len() >= 12, "parsed only {} table rows from SKILL.md", table.len());
        let mut bad = Vec::new();
        for row in &table {
            let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
            let (exit, token) = (cells[0], cells.get(1).copied().unwrap_or(""));
            for c in exit.split('/').map(str::trim) {
                match c.parse::<i32>() {
                    Ok(n) if codes.contains(&n) => {}
                    _ => bad.push(format!("  exit `{c}` is not a code tunlion returns: {row}")),
                }
            }
            for tok in token.split(',').map(|s| s.trim().trim_matches('`')).filter(|s| !s.is_empty()) {
                if !tokens.contains(tok) {
                    bad.push(format!("  error.code `{tok}` is not a token exit_codes.rs emits: {row}"));
                }
            }
            // A kind's token belongs on its own code's row.
            for k in ExitKind::ALL {
                if token.contains(&format!("`{}`", k.token())) {
                    assert!(
                        exit.split('/').any(|c| c.trim() == k.code().to_string()),
                        "SKILL.md puts `{}` on exit {exit}, but it is exit {}",
                        k.token(),
                        k.code()
                    );
                }
            }
        }
        assert!(bad.is_empty(), "SKILL.md's exit-code table drifted from exit_codes.rs:\n{}", bad.join("\n"));
        // And every kind is in the table, so an agent can act on each.
        for k in ExitKind::ALL {
            assert!(
                table.iter().any(|r| r.contains(&format!("`{}`", k.token()))),
                "SKILL.md's table has no row for `{}` (exit {})",
                k.token(),
                k.code()
            );
        }
    }

    /// The skill's `--json` list matches dispatch's.
    #[test]
    fn the_skills_json_list_is_the_supported_list() {
        let line = SKILL_MD
            .split("Always pass `--json` on commands that support it: `")
            .nth(1)
            .and_then(|r| r.split('`').next())
            .expect("SKILL.md rule 1 lists the --json commands");
        let listed: std::collections::BTreeSet<&str> = line.split_whitespace().collect();
        use clap::CommandFactory;
        let root = crate::Cli::command();
        for sc in root.get_subcommands() {
            let name = sc.get_name();
            let sample: Vec<&str> = match name {
                "sync" => vec!["sync", ".", "laptop:dir"],
                "skill" => vec!["skill", "show"],
                "exec" | "shell" | "mount" | "forward" | "netcat" | "backup" | "revoke" | "ephemeral"
                | "completions" => continue,
                other => vec![other],
            };
            let Ok(cli) = <crate::Cli as clap::Parser>::try_parse_from(std::iter::once("tunlion").chain(sample)) else {
                continue;
            };
            let Some(cmd) = cli.cmd else { continue };
            let supported = crate::dispatch::json_supported(&cmd);
            assert_eq!(
                supported,
                listed.contains(name),
                "SKILL.md rule 1 and dispatch::json_supported disagree about `{name}`"
            );
        }
    }
}
