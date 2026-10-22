//! Action-first setup against isolated stores, never a user's daemon/config.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct Store(PathBuf);
impl Store {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("tunlion-access-bootstrap-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tunlion"))
            .args(args)
            .env("TUNLION_CONFIG_DIR", &self.0)
            .env("HOME", &self.0)
            .env("USERPROFILE", &self.0)
            .env("TUNLION_NONINTERACTIVE", "1")
            .env_remove("TUNLION_NO_IMPLICIT_INIT")
            .output().unwrap()
    }
}
impl Drop for Store {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn add_bootstraps_once_without_init_or_name_wizard() {
    let store = Store::new();
    let first = store.0.join("first.invite");
    let result = store.run(&["add", "--for", "device", "--out", first.to_str().unwrap(), "--json"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let identity = store.0.join("identity.ed25519");
    let original = std::fs::read(&identity).unwrap();
    assert!(first.is_file());
    let second = store.0.join("second.invite");
    let result = store.run(&["add", "--for", "device", "--out", second.to_str().unwrap(), "--json"]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(original, std::fs::read(&identity).unwrap(), "add replaced existing identity");
    assert!(!store.0.join("up.pid").exists(), "noninteractive add started a daemon");
    assert!(!store.0.join("devices.json").exists(), "issuing invitation remembered a device");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(identity).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn read_only_and_invalid_add_do_not_mint_identity() {
    let store = Store::new();
    for args in [vec!["id", "--json"], vec!["devices", "--json"],
        vec!["add", "--for", "device", "--expires", "invalid", "--out", "unused.invite"]] {
        let _ = store.run(&args);
        assert!(!store.0.join("identity.ed25519").exists(), "inspection or invalid input created keys: {args:?}");
    }
}

#[test]
fn joined_identity_is_not_replaced_by_bootstrap() {
    let store = Store::new();
    let cert = store.0.join("identity/device-cert.json");
    std::fs::create_dir(cert.parent().unwrap()).unwrap();
    // The key bootstrap guards even an unreadable/corrupt joined certificate:
    // it cannot turn a failed load into a fresh owner identity.
    std::fs::write(&cert, b"existing joined certificate").unwrap();
    let out = store.0.join("not-created.invite");
    let result = store.run(&["add", "--for", "device", "--out", out.to_str().unwrap(), "--json"]);
    assert!(!result.status.success());
    assert!(!store.0.join("identity.ed25519").exists());
    assert!(!out.exists());
    assert_eq!(std::fs::read(cert).unwrap(), b"existing joined certificate");
}

#[test]
fn concurrent_first_adds_share_one_atomic_identity() {
    use base64::Engine;
    let store = Store::new();
    let first = store.0.join("concurrent-first.invite");
    let second = store.0.join("concurrent-second.invite");
    std::thread::scope(|scope| {
        let a = scope.spawn(|| store.run(&["add", "--for", "device", "--out", first.to_str().unwrap(), "--json"]));
        let b = scope.spawn(|| store.run(&["add", "--for", "device", "--out", second.to_str().unwrap(), "--json"]));
        for result in [a.join().unwrap(), b.join().unwrap()] {
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        }
    });
    let issuer = |path: &std::path::Path| {
        let material = std::fs::read_to_string(path).unwrap();
        let token = material.trim().strip_prefix("filament-invite:v2:").unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token).unwrap();
        filament_cap::ephemeral::Invitation::from_token(&bytes).unwrap().issuer_fp
    };
    assert_eq!(issuer(&first), issuer(&second), "concurrent add minted competing owners");
}
