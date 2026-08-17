//! #224: the daemon's identity is its executable path, not a "filament"
//! substring in its command line.
//!
//! The old `daemon_alive` read `/proc/<pid>/cmdline` and asked "does this
//! string contain the word filament". A renamed binary (or a recycled pid
//! running some other program) defeats that, so `status` lied, `down` did
//! nothing and `up` started a second daemon. The fix records the daemon's
//! executable when the pidfile is written and confirms it against the live
//! process on read. This test spawns a REAL daemon under a name with no
//! "filament" in it, which the old check could never recognise, and asserts an
//! unrelated live pid is rejected.

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn real_bin() -> &'static str {
    env!("CARGO_BIN_EXE_filament")
}

/// A copy of the real binary under a path that deliberately contains no
/// "filament" substring anywhere (scratch dir AND file name). The old check
/// matched on the name, so this path is exactly the input it could not fail.
fn scratch_root() -> std::path::PathBuf {
    // No "filament" in any component of this path: the cmdline substring check
    // must not be able to match it by accident.
    std::env::temp_dir().join(format!("bg-{}", std::process::id()))
}

fn status_json(cfg: &std::path::Path) -> serde_json::Value {
    let out = Command::new(real_bin())
        .env("FILAMENT_CONFIG_DIR", cfg)
        .args(["status", "--json"])
        .output()
        .expect("run filament status");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| serde_json::Value::Null)
}

#[test]
fn daemon_is_found_by_executable_and_an_unrelated_pid_is_rejected() {
    let scratch = scratch_root();
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();

    // Copy the binary under a name with no "filament" substring.
    let renamed = scratch.join("bg-224");
    std::fs::copy(real_bin(), &renamed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&renamed, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Hold a listener open so the daemon's signaling connect blocks instead of
    // failing fast; the daemon writes its pidfile before it ever reaches the
    // network, and the held-open socket keeps it alive long enough to observe.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hold = std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let mut buf = [0u8; 8192];
            let _ = (&stream).read(&mut buf);
            // Hold the socket past the daemon's ~10s connect timeout.
            std::thread::sleep(Duration::from_secs(20));
        }
    });
    let server = format!("http://127.0.0.1:{port}");

    // Hermetic config dir: the pidfile lands here, nowhere near production.
    let cfg = scratch.join("cfg");
    std::fs::create_dir_all(&cfg).unwrap();

    // Spawn the real daemon under the renamed binary.
    let mut child = Command::new(&renamed)
        .env("FILAMENT_CONFIG_DIR", &cfg)
        .arg("up")
        .arg("--server")
        .arg(&server)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn renamed daemon");

    // The daemon must be FOUND: `status` reports it running under its own pid.
    let mut found = None;
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        let v = status_json(&cfg);
        if v["running"] == true {
            found = v["pid"].as_u64();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        found,
        Some(child.id() as u64),
        "a daemon running under a name with no 'filament' must still be found by status"
    );

    // An unrelated live pid must be REJECTED: point the pidfile at a live
    // `sleep` process while recording the daemon's executable. The executable
    // will not match, so `status` must report not running (the recycled-pid
    // case the pidfile alone cannot detect).
    let mut sleeper = Command::new("sleep")
        .arg("30")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleeper");
    std::fs::write(
        cfg.join("up.pid"),
        format!("{}\n{}\n", sleeper.id(), real_bin()),
    )
    .unwrap();
    let v = status_json(&cfg);
    assert_eq!(
        v["running"], false,
        "an unrelated live pid must not be reported as the daemon"
    );

    // Cleanup.
    let _ = child.kill();
    let _ = child.wait();
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    drop(hold);
    let _ = std::fs::remove_dir_all(&scratch);
}
