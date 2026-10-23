//! `init` with an explicit config dir and NO HOME.
//!
//! Automation runs `TUNLION_CONFIG_DIR=<dir> env -u HOME tunlion init ...` on
//! hosts where HOME is not meaningful. Init used to refuse to choose an inbox
//! there even though the config dir was explicit. The inbox now defaults under
//! that dir, and the command completes non-interactively.

use std::process::Command;

#[test]
fn non_interactive_init_puts_the_inbox_under_an_explicit_config_dir_without_home() {
    let dir = std::env::temp_dir().join(format!(
        "tunlion-init-nohome-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let recovery = dir.join("recovery.txt");

    let out = Command::new(env!("CARGO_BIN_EXE_tunlion"))
        .args([
            "init",
            "--name",
            "repro",
            "--recovery-file",
            recovery.to_str().unwrap(),
            "--yes",
            "--no-background",
        ])
        .env("TUNLION_CONFIG_DIR", &dir)
        .env_remove("HOME")
        .env("NO_COLOR", "1")
        .output()
        .expect("run tunlion init");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "init must succeed with an explicit config dir and no HOME\nstdout={stdout}\nstderr={stderr}"
    );

    let config = std::fs::read_to_string(dir.join("config")).expect("config written");
    let inbox = dir.join("inbox");
    let expected = format!("dir {}", inbox.display());
    assert!(
        config.lines().any(|l| l == expected),
        "inbox must default under TUNLION_CONFIG_DIR ({expected}):\n{config}"
    );
    assert!(inbox.is_dir(), "inbox directory created");
    assert!(recovery.is_file(), "recovery phrase exported");

    // The optional CA warning must not leak into a non-interactive success.
    let both = format!("{stdout}\n{stderr}");
    assert!(
        !both.contains("ssh-keygen") && !both.contains("ssh CA not provisioned"),
        "non-interactive init must not print the optional CA warning:\n{both}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
