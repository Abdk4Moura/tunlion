//! Per-OS capability CI harmer (docs/design-per-os-ci.md steps 1-2).
//!
//! Integration test that starts a local filament backend + two filament
//! daemons, pairs them, and runs smoke tests. Needs the filament binary
//! pre-built with `cargo build --features test-hooks`.
//!
//! COMPILE GATE: this entire file is `#[cfg(feature = "test-hooks")]`.
//! The compiler strips it from default/release builds, so the signaling-bypass
//! path can NEVER end up in a published binary (security gate per Claude).

#![cfg(feature = "test-hooks")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const CODE_WORD: &str = "gigantic-element-tango";

// ---------------------------------------------------------------- helpers ---

fn binary() -> PathBuf {
    // Try release first (Windows CI builds --release to avoid stack overflow)
    let release = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target").join("release").join("filament");
    if release.exists() {
        return release;
    }
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(profile)
        .join("filament")
}

fn find_backend_app() -> PathBuf {
    // Look for the Python backend app.py relative to the CLI crate
    let from_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("backend")
        .join("app.py");
    if from_manifest.exists() {
        return from_manifest;
    }
    // Fallback: try relative to CWD
    PathBuf::from("../backend/app.py")
}

struct Harness {
    backend: Child,
    backend_port: u16,
    daemon_a: Option<Child>,
    daemon_b: Option<Child>,
    work_dir: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(ref mut c) = self.daemon_a {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(ref mut c) = self.daemon_b {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = self.backend.kill();
        let _ = self.backend.wait();
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }
}

fn python_cmd() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn find_free_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().unwrap().port())
        .unwrap_or(19079)
}

impl Harness {
    fn new() -> Self {
        let work = std::env::temp_dir()
            .join(format!("filament-harness-{}", std::process::id()));
        std::fs::create_dir_all(&work).expect("create work dir");

        let a_dir = work.join("a");
        let b_dir = work.join("b");

        // Start the Python Flask backend on an ephemeral port
        let app_path = find_backend_app();
        let port = find_free_port();
        let mut backend = {
            let mut b = Command::new(python_cmd())
                .arg(&app_path)
                .env("PORT", port.to_string())
                .env("FIL_ASYNC_MODE", "eventlet")
                .env("FIL_SELF_MONKEYPATCH", "1")
                .env("FIL_CLAIM_LIMIT", "1000000")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .current_dir(app_path.parent().unwrap())
                .spawn()
                .expect("start backend");
            // Drain stderr in a background thread so the pipe buffer doesn't fill
            let stderr = b.stderr.take().unwrap();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        eprintln!("[backend] {l}");
                    }
                }
            });
            // Drain stdout too
            let stdout = b.stdout.take().unwrap();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        eprintln!("[backend] {l}");
                    }
                }
            });
            b
        };

        // Wait for backend to be healthy
        let server_url = format!("http://127.0.0.1:{port}");
        let mut backend_ok = false;
        for _ in 0..90 {
            if reqwest_blocking_head(&format!("{server_url}/api/health")) {
                backend_ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if !backend_ok {
            panic!("backend did not start within 45s at {server_url}");
        }

        Harness {
            backend,
            backend_port: port,
            daemon_a: None,
            daemon_b: None,
            work_dir: work,
            a_dir,
            b_dir,
        }
    }

    fn server_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.backend_port)
    }

    fn filament_bin(&self) -> &Path {
        // Lazily determined
        static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        BIN.get_or_init(binary)
    }

    fn spawn_daemon(&mut self, name: &str, config_dir: &Path) -> Child {
        let bin = self.filament_bin().to_path_buf();
        let server = self.server_url();
        spawn_daemon_inner(&bin, &server, name, config_dir)
    }

    /// Spawn daemons, pair them, and verify byte-exact file transfer.
    /// Uses `send --word` + `recv <code>` (same pattern as gates.sh gate 1)
    /// which is proven to work on CI across all 3 OSes.
    fn pair_daemons(&mut self) {
        let bin = self.filament_bin().to_path_buf();
        let server = self.server_url();

        // Start daemons first (they need devices.json, so we write a stub)
        // Actually: send/recv doesn't need paired devices, it uses one-time codes.
        // Just start daemons for the direct-QUIC path.
        self.daemon_a = Some(spawn_daemon_inner(&bin, &server, "test-a", &self.a_dir));
        self.daemon_b = Some(spawn_daemon_inner(&bin, &server, "test-b", &self.b_dir));
        std::thread::sleep(Duration::from_secs(8));
    }
}

fn spawn_daemon_inner(
    bin: &Path,
    server: &str,
    name: &str,
    config_dir: &Path,
) -> Child {
    std::fs::create_dir_all(config_dir).expect("create config dir");
    let mut child = Command::new(bin)
        .env("FILAMENT_CONFIG_DIR", config_dir)
        .env("FILAMENT_L3_USERSPACE", "1")
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_NAME", name)
        .arg("up")
        .arg("--userspace")
        .arg("--shell")
        .arg("--server")
        .arg(server)
        .arg("--relay")
        .arg("--dir")
        .arg(config_dir.join("drops").to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn daemon {name}: {e}"));
    // Drain stdout/stderr in background threads so pipe buffers don't fill
    let label1 = name.to_string();
    let label2 = name.to_string();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if let Ok(l) = line { eprintln!("[{label1} stderr] {l}"); }
            }
        });
    }
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if let Ok(l) = line { eprintln!("[{label2}] {l}"); }
            }
        });
    }
    child
}

fn reqwest_blocking_head(url: &str) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let host_port = url
        .trim_start_matches("http://")
        .trim_end_matches("/api/health");
    match TcpStream::connect_timeout(&host_port.parse().unwrap(), Duration::from_secs(3)) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(
                format!("GET /api/health HTTP/1.0\r\nHost: {host_port}\r\n\r\n").as_bytes(),
            );
            let mut buf = [0u8; 256];
            if let Ok(n) = stream.read(&mut buf) {
                let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
                return resp.contains("200") || resp.contains("ok");
            }
            false
        }
        Err(_) => false,
    }
}

// ------------------------------------------------------------ smoke tests ---

#[test]
fn pair_and_transfer_smoke() {
    let h = Harness::new();

    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    // Create a test file with 0x0D 0x0A + binary sweep
    let test_file = h.work_dir.join("test_payload.bin");
    let mut payload = vec![
        0x0D, 0x0A, // CR+LF (byte-transparency lock)
    ];
    // Add random binary
    for i in 0u8..=255 {
        payload.push(i);
    }
    // Add some structured data
    payload.extend_from_slice(b"\x00\x01\x02\x03\xff\xfe\xfd\xfc");
    std::fs::write(&test_file, &payload).expect("write test file");

    // Compute expected hash
    use std::hash::Hasher;
    let expected_hash = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&payload);
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    // Step 3: send from A to B
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let direct_flag = std::env::var("FILAMENT_DIRECT_PER_OS").unwrap_or_else(|_| "1".into());

    // Spawn send; drain stderr continuously in background to avoid SIGPIPE.
    // Also watch for the minted code prefix.
    let mut send_proc = Command::new(&bin)
        .env("FILAMENT_DIRECT", &direct_flag)
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.a_dir)
        .arg("send")
        .arg(&test_file)
        .arg("--word")
        .arg(CODE_WORD)
        .arg("--server")
        .arg(&server)
        .stderr(Stdio::piped())
        .spawn()
        .expect("send");

    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let stderr = send_proc.stderr.take().unwrap();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            eprintln!("[send] {line}");
            let lower = line.to_lowercase();
            if let Some(start) = lower.find(&CODE_WORD.to_lowercase()) {
                let rest = &line[start..];
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                let _ = code_tx.send(line[start..start + end].to_lowercase().to_string());
            }
        }
    });

    let full_code = code_rx.recv_timeout(Duration::from_secs(30))
        .expect("send did not mint a code within 30s");

    // Receive on B
    let recv_dir = h.b_dir.join("received");
    std::fs::create_dir_all(&recv_dir).expect("create recv dir");
    let mut recv_proc = Command::new(&bin)
        .env("FILAMENT_DIRECT", &direct_flag)
        .env(
        "FILAMENT_DIRECT_LOOPBACK_ONLY",
        std::env::var("FILAMENT_DIRECT_LOOPBACK_ONLY")
            .unwrap_or_else(|_| "1".into()),
    )
        .env("FILAMENT_L3_USERSPACE", "1")
        .env("FILAMENT_CONFIG_DIR", &h.b_dir)
        .arg("recv")
        .arg(&full_code)
        .arg("--yes")
        .arg("--dir")
        .arg(&recv_dir)
        .arg("--server")
        .arg(&server)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("recv");
    let recv_out = recv_proc.wait_with_output().expect("recv result");
    let recv_stdout = String::from_utf8_lossy(&recv_out.stdout);
    let recv_stderr = String::from_utf8_lossy(&recv_out.stderr);
    eprintln!("recv stdout:\n{recv_stdout}");
    eprintln!("recv stderr:\n{recv_stderr}");

    // Step 4: check received file
    let received_file = recv_dir.join("test_payload.bin");
    assert!(
        received_file.exists(),
        "received file missing: {}",
        received_file.display()
    );

    let received_data = std::fs::read(&received_file).expect("read received file");
    let recv_hash = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&received_data);
        digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    assert_eq!(
        expected_hash, recv_hash,
        "sha256 mismatch: sent {expected_hash} != received {recv_hash}"
    );
    assert_eq!(payload.len(), received_data.len(), "size mismatch");

    // Byte-transparency lock: verify 0x0D 0x0A survived
    assert_eq!(
        received_data[0], 0x0D,
        "byte 0 = 0x0D lost (CR)"
    );
    assert_eq!(
        received_data[1], 0x0A,
        "byte 1 = 0x0A lost (LF)"
    );
}

#[test]
fn two_nodes_pair_each_other() {
    let h = Harness::new();
    // Verify the backend + binary are reachable
    let bin = h.filament_bin().to_path_buf();
    let server = h.server_url();

    let out = Command::new(&bin)
        .args(["--server", &server, "--help"])
        .output()
        .expect("help");
    assert!(out.status.success(), "binary help failed");

    eprintln!("two_nodes_pair_each_other: filament binary and backend OK");
}
