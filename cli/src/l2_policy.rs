//! CLI shim over `filament_peerloop::l2::policy`.
//!
//! The two pure forward rules moved with the sector slice: whether a peer may
//! open an L2 stream at all, and whether the operator's per-device allowlist
//! covers a non-loopback `host:port`. The allowlist PATH and loader stay here,
//! because `{config_dir}/l2-allow.json` is this machine's configuration; the
//! library takes the parsed document instead. The allowlist matcher keeps its
//! CLI name for the receive path; the open gate is called directly from the
//! library by forward admission and the gate matrix.

use crate::devices_store::devices_path;
use serde_json::Value;
use std::path::PathBuf;

pub(crate) use filament_peerloop::l2::policy::l2_target_allowed_in;

/// Opt-in non-loopback forward allowlist: `{config_dir}/l2-allow.json`. Absent or
/// malformed file => no entries => loopback-only (the default SSRF posture).
fn l2_allow_path() -> PathBuf {
    devices_path().with_file_name("l2-allow.json")
}

fn l2_allow_load() -> Value {
    std::fs::read_to_string(l2_allow_path())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .unwrap_or(Value::Null)
}

/// The loaded allowlist's answer for this device and target. The matching rule
/// itself lives in the library; only reading this machine's file stays here.
pub(crate) fn l2_target_allowed(device: &str, host: &str, port: u16) -> bool {
    l2_target_allowed_in(&l2_allow_load(), device, host, port)
}

#[cfg(test)]
mod tests {
    use super::l2_target_allowed_in;
    use filament_peerloop::l2::policy;
    use serde_json::json;

    /// The CLI allowlist name must resolve to the library rule, not a second
    /// copy that can drift. The open gate itself is called directly by the gate
    /// matrix now, and lives with its own tests in `l2::policy`.
    #[test]
    fn cli_allowlist_name_is_the_library_policy() {
        let allow = json!({
            "laptop": ["10.0.0.5:5432", "192.168.1.10:*"],
            "*": ["db.internal:5432"]
        });
        for (device, host, port) in [
            ("laptop", "10.0.0.5", 5432),
            ("laptop", "10.0.0.5", 22),
            ("laptop", "192.168.1.10", 65535),
            ("phone", "db.internal", 5432),
            ("phone", "10.0.0.5", 5432),
        ] {
            assert_eq!(
                l2_target_allowed_in(&allow, device, host, port),
                policy::l2_target_allowed_in(&allow, device, host, port)
            );
        }
        assert!(l2_target_allowed_in(
            &allow,
            "phone",
            "DB.INTERNAL",
            5432
        ));
        assert!(!l2_target_allowed_in(&allow, "phone", "db.internal", 5433));
    }
}
