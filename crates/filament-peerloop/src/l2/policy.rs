//! The `l2-open` (forward) policy that needs no live link.
//!
//! Whether an incoming open may proceed at all, and which non-loopback
//! `host:port` the operator's per-device allowlist permits. The receive handler
//! still owns the live inputs (link trust, the peer's verified name and grants,
//! the expose bound, parking and the wire refusal). This module is pure: it
//! takes the already-resolved booleans and the already-loaded allowlist
//! document, and reads no file, environment or clock.
//!
//! One home for these rules matters because this is the forward SSRF boundary:
//! a second copy is how loopback-only and the per-device grant drift apart.

use serde_json::Value;

/// Whether to serve an `l2-open` (TCP tunnel / ssh data link) from a peer.
/// Blanket modes (`--shell` / `--shell-only` / `TUNLION_L2`) keep their existing
/// trusted-gated behavior. But when L2 is on ONLY because some device was
/// `grant`ed shell, the OPENING peer must itself hold that grant: otherwise a
/// grant for ONE device would let EVERY trusted device open loopback tunnels.
/// `trusted` is still required upstream; this is the additional per-device gate.
/// An explicit deny outranks both blanket mode and the peer's own grant:
/// a shell-denied device opens no tunnels, period (#244 class).
pub fn l2_open_allowed(blanket: bool, peer_has_shell: bool, denied: bool) -> bool {
    !denied && (blanket || peer_has_shell)
}

/// True if `allow` lists `host:port` (or `host:*`) for `device` or for "*".
/// Pure, so the matching logic is unit-testable without the filesystem. Host
/// match is case-insensitive; the device key must match the proven
/// `verified_name` exactly (or be "*").
///
/// `port` is already a `u16`: the caller denies an out-of-range wire port
/// before asking, rather than truncating it into a different (possibly listed)
/// port. An entry whose port does not parse as `u16` matches nothing.
///
/// The document is the parsed `{config_dir}/l2-allow.json`, whose shape is:
///   { "laptop": ["10.0.0.5:5432", "192.168.1.10:*"], "*": ["db.internal:5432"] }
/// A "*" device key applies to any authorized device; "host:*" allows any port.
/// Absent or malformed input is `Value::Null`, which matches nothing, keeping
/// the default loopback-only posture.
///
/// Only NON-loopback targets are asked about here. Loopback stays always
/// allowed, as before; that check and the trusted-link requirement live in the
/// mux and the receive handler, not in this rule.
pub fn l2_target_allowed_in(allow: &Value, device: &str, host: &str, port: u16) -> bool {
    let matches = |list: &Value| -> bool {
        list.as_array()
            .map(|a| {
                a.iter().any(|e| {
                    let s = e.as_str().unwrap_or("");
                    match s.rsplit_once(':') {
                        Some((h, "*")) => h.eq_ignore_ascii_case(host),
                        Some((h, p)) => {
                            h.eq_ignore_ascii_case(host) && p.parse::<u16>().ok() == Some(port)
                        }
                        None => false,
                    }
                })
            })
            .unwrap_or(false)
    };
    allow.get(device).map(&matches).unwrap_or(false)
        || allow.get("*").map(&matches).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{l2_open_allowed, l2_target_allowed_in};
    use serde_json::{Value, json};

    #[test]
    fn l2_open_gate_scopes_grant_mode() {
        // Blanket mode (--shell / --shell-only / TUNLION_L2): any trusted peer
        // may open, regardless of its own per-device grant (unchanged behavior).
        assert!(l2_open_allowed(true, false, false));
        assert!(l2_open_allowed(true, true, false));
        // Grant-only mode (L2 on solely because SOME device has a shell grant):
        // the opening peer must itself hold the grant.
        assert!(
            l2_open_allowed(false, true, false),
            "granted device may open"
        );
        assert!(
            !l2_open_allowed(false, false, false),
            "ungranted device denied in grant mode"
        );
        // Explicit deny outranks everything, including blanket mode.
        assert!(
            !l2_open_allowed(true, true, true),
            "denied device opens nothing, even blanketed and granted"
        );
    }

    #[test]
    fn l2_open_gate_is_exactly_deny_and_blanket_or_grant() {
        for blanket in [false, true] {
            for peer_has_shell in [false, true] {
                for denied in [false, true] {
                    assert_eq!(
                        l2_open_allowed(blanket, peer_has_shell, denied),
                        !denied && (blanket || peer_has_shell),
                        "gate changed: blanket={blanket} shell={peer_has_shell} denied={denied}"
                    );
                }
            }
        }
    }

    #[test]
    fn l2_target_allowlist_matches() {
        let allow = json!({
            "laptop": ["10.0.0.5:5432", "192.168.1.10:*"],
            "*": ["db.internal:5432"]
        });
        // Exact host:port for the named device.
        assert!(l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 5432));
        // host:* allows any port for that host.
        assert!(l2_target_allowed_in(&allow, "laptop", "192.168.1.10", 9999));
        // "*" device entry applies to any device.
        assert!(l2_target_allowed_in(&allow, "phone", "db.internal", 5432));
        // The "*" entry is additive: a device with its own list still inherits
        // it, rather than its list replacing the wildcard.
        assert!(l2_target_allowed_in(&allow, "laptop", "db.internal", 5432));
        // Wrong port (no wildcard) is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.5", 22));
        // Host not listed is denied.
        assert!(!l2_target_allowed_in(&allow, "laptop", "10.0.0.9", 5432));
        // A device with no entry (and not matching "*") is denied.
        assert!(!l2_target_allowed_in(&allow, "phone", "10.0.0.5", 5432));
        // No allowlist at all (null) denies everything (loopback-only default).
        assert!(!l2_target_allowed_in(
            &Value::Null,
            "laptop",
            "10.0.0.5",
            5432
        ));
        // Host match is case-insensitive.
        assert!(l2_target_allowed_in(&allow, "phone", "DB.INTERNAL", 5432));
    }

    #[test]
    fn l2_target_allowlist_device_key_is_exact() {
        let allow = json!({ "laptop": ["10.0.0.5:5432"] });
        // The key is the proven name, not a name-shaped wildcard: a different
        // case is a different device and inherits no permission.
        assert!(!l2_target_allowed_in(&allow, "LAPTOP", "10.0.0.5", 5432));
        assert!(!l2_target_allowed_in(&allow, "laptop ", "10.0.0.5", 5432));
    }

    #[test]
    fn l2_target_allowlist_pins_u16_port_boundaries() {
        let allow = json!({
            "laptop": ["low:0", "high:65535", "wide:*"],
            "over": ["low:65536"],
            "negative": ["low:-1"],
            "blank": ["low:"],
            "no_colon": ["low"],
            "not_a_number": ["low:http"],
            "not_a_list": "low:80",
            "mixed": [80, "low:80"],
            "numbers_only": [80, 443]
        });

        // Both ends of u16 are addressable and match exactly.
        assert!(l2_target_allowed_in(&allow, "laptop", "low", 0));
        assert!(l2_target_allowed_in(&allow, "laptop", "high", 65535));
        assert!(!l2_target_allowed_in(&allow, "laptop", "high", 65534));
        // host:* covers both boundaries too.
        assert!(l2_target_allowed_in(&allow, "laptop", "wide", 0));
        assert!(l2_target_allowed_in(&allow, "laptop", "wide", 65535));

        // A wire port that cannot be a u16 is denied by the caller before this
        // rule; an entry outside u16 must never wrap into a listed port.
        assert!(!l2_target_allowed_in(&allow, "over", "low", 0));
        assert!(!l2_target_allowed_in(&allow, "negative", "low", 65535));
        assert!(!l2_target_allowed_in(&allow, "blank", "low", 0));
        assert!(!l2_target_allowed_in(&allow, "not_a_number", "low", 80));

        // Malformed list shapes and entries match nothing. A non-string entry
        // is skipped, but it does not poison a valid string beside it.
        assert!(!l2_target_allowed_in(&allow, "no_colon", "low", 80));
        assert!(!l2_target_allowed_in(&allow, "not_a_list", "low", 80));
        assert!(l2_target_allowed_in(&allow, "mixed", "low", 80));
        assert!(!l2_target_allowed_in(&allow, "numbers_only", "low", 80));
    }
}
