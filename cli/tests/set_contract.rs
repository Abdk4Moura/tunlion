//! `tunlion set` without a terminal: the scripted contract the interactive
//! menu must never change. The menu opens only when stdin, stdout and stderr
//! are all a terminal; these run the real binary with pipes on every end, in
//! a hermetic config dir, and pin what a script sees.

use std::process::{Command, Stdio};

fn temp_config(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tunlion-set-contract-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tunlion"));
    cmd.args(args)
        .env("TUNLION_CONFIG_DIR", dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("TUNLION_NO_WARM_REUSE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Environment overrides would change the values read back.
    for var in [
        "TUNLION_NAME",
        "TUNLION_SERVER",
        "TUNLION_SHELL",
        "TUNLION_WARM_PEERS",
        "TUNLION_AUTO_WARM",
        "TUNLION_WARM_MAX",
        "TUNLION_AUTO_PROXY",
        "TUNLION_LOG",
        "TUNLION_GATE_SETTLE_MS",
        "TUNLION_SSH_CERT_TTL",
    ] {
        cmd.env_remove(var);
    }
    cmd.output().expect("run tunlion")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

#[test]
fn bare_set_from_a_pipe_prints_tab_separated_rows_and_never_a_menu() {
    let dir = temp_config("tsv");
    let out = run(&dir, &["set"]);
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stdout={stdout} stderr={stderr}");
    assert!(!stdout.contains("SETTINGS") && !stderr.contains("SETTINGS"), "the menu opened without a terminal");
    assert!(!stderr.contains('\u{1b}'), "a pipe got terminal control codes: {stderr:?}");
    let rows: Vec<&str> = stdout.lines().collect();
    assert!(rows.len() >= 20, "one row per setting: {stdout}");
    for row in &rows {
        assert_eq!(row.split('\t').count(), 4, "key<TAB>value<TAB>scope<TAB>help: {row:?}");
    }
    assert!(rows.iter().any(|r| r.starts_with("relay\tauto\tglobal\t")), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bare_set_json_is_the_structured_array() {
    let dir = temp_config("json");
    let out = run(&dir, &["set", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let rows: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON on stdout");
    let relay = rows.as_array().unwrap().iter().find(|r| r["key"] == "relay").expect("relay row");
    assert_eq!(relay["value"], "auto");
    assert_eq!(relay["origin"], "default");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn set_key_from_a_pipe_reads_the_bare_value() {
    let dir = temp_config("read");
    let out = run(&dir, &["set", "relay"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stdout), "auto\n");
    let set = run(&dir, &["set", "relay", "never"]);
    assert_eq!(set.status.code(), Some(0), "{}", text(&set.stderr));
    assert_eq!(text(&run(&dir, &["set", "relay"]).stdout), "never\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The menu checks text through the same validation as `set <key> <value>`,
/// so a value the reader would silently replace is refused here too, with the
/// exit code any other bad value gets, and nothing is written.
#[test]
fn a_bad_number_is_refused_like_any_bad_value() {
    let dir = temp_config("number");
    let bad_enum = run(&dir, &["set", "relay", "sometimes"]);
    assert!(!bad_enum.status.success());
    let bad_number = run(&dir, &["set", "warm-max", "lots"]);
    assert_eq!(bad_number.status.code(), bad_enum.status.code(), "{}", text(&bad_number.stderr));
    assert!(text(&bad_number.stderr).contains("whole number"), "{}", text(&bad_number.stderr));
    assert_eq!(text(&run(&dir, &["set", "warm-max"]).stdout), "12\n", "nothing was written");
    let ok = run(&dir, &["set", "warm-max", "4"]);
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stderr));
    assert_eq!(text(&run(&dir, &["set", "warm-max"]).stdout), "4\n");
    let _ = std::fs::remove_dir_all(&dir);
}
