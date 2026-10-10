//! Where a running SOCKS proxy is, so `status`, `addr` and `expose` can say how
//! to use it.
//!
//! When kernel TUN is unavailable the daemon auto-starts a SOCKS5 proxy, and
//! before this the only record of it (its address, and how to authenticate)
//! was a few lines in daemon.log. The proxy now writes a small owner-only state
//! file when it binds: the address, the port, its pid and the PATH of the token
//! file. Never the token itself. Readers ignore a record whose process is gone,
//! so a crashed or stopped proxy is never reported as running.

use crate::l2::{PROXY_USER, proxy_token_path};
use serde_json::{Value, json};
use std::path::PathBuf;

/// The record of a proxy that is (or was) running.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProxyInfo {
    pub(crate) bind: String,
    pub(crate) port: u16,
    pub(crate) pid: u32,
}

fn state_path() -> PathBuf {
    crate::platform::Paths::config_path("proxy.json")
}

/// Record that this process now serves the proxy on `bind:port`. Owner-only.
/// Best-effort: a status line is not worth failing the proxy over.
pub(crate) fn record(bind: &str, port: u16) {
    let body = json!({ "bind": bind, "port": port, "pid": std::process::id() }).to_string();
    let _ = crate::platform::SecretFile::write_str(state_path(), &body);
}

/// Parse a state record. Pure.
pub(crate) fn parse(raw: &str) -> Option<ProxyInfo> {
    let v: Value = serde_json::from_str(raw).ok()?;
    Some(ProxyInfo {
        bind: v["bind"].as_str()?.to_string(),
        port: u16::try_from(v["port"].as_u64()?).ok()?,
        pid: u32::try_from(v["pid"].as_u64()?).ok()?,
    })
}

/// The proxy that is running now, if any: the record exists and its process is
/// still alive.
pub(crate) fn current() -> Option<ProxyInfo> {
    let info = parse(&std::fs::read_to_string(state_path()).ok()?)?;
    crate::platform::process_exe_path(info.pid).map(|_| info)
}

/// The address a client points at.
pub(crate) fn addr(info: &ProxyInfo) -> String {
    format!("{}:{}", info.bind, info.port)
}

/// The exact curl line, reading the password from its file at use time. Pure
/// apart from the token path; it never contains the token.
pub(crate) fn curl_line(info: &ProxyInfo) -> String {
    format!(
        "curl -x \"socks5h://{PROXY_USER}:$(cat '{}')@{}\" http://<peer>.mesh:8080/",
        proxy_token_path().display(),
        addr(info)
    )
}

/// The `status --json` object: `null` when no proxy runs.
pub(crate) fn to_json(info: Option<&ProxyInfo>) -> Value {
    match info {
        None => Value::Null,
        Some(i) => json!({
            "running": true,
            "addr": addr(i),
            "user": PROXY_USER,
            "token_path": proxy_token_path().display().to_string(),
            "curl": curl_line(i),
        }),
    }
}

/// Human lines for `status`: where the proxy is and how to use it.
pub(crate) fn status_lines(info: &ProxyInfo) -> Vec<String> {
    vec![
        format!("  SOCKS5 proxy on {} (reaches <peer>.mesh with no TUN)", addr(info)),
        format!(
            "    user `{PROXY_USER}`, password in {} (owner-only)",
            proxy_token_path().display()
        ),
        format!("    e.g. {}", curl_line(info)),
    ]
}

/// The hint `addr` and `expose` print when there is no kernel route to
/// `<peer>.mesh` and the proxy is the way in.
pub(crate) fn mesh_hint(info: &ProxyInfo) -> String {
    format!(
        "  no TUN here: reach <peer>.mesh names through the SOCKS5 proxy on {}, e.g.\n    {}",
        addr(info),
        curl_line(info)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ProxyInfo {
        ProxyInfo { bind: "127.0.0.1".into(), port: 1080, pid: 42 }
    }

    #[test]
    fn a_record_round_trips() {
        let raw = json!({ "bind": "127.0.0.1", "port": 1080, "pid": 42 }).to_string();
        assert_eq!(parse(&raw), Some(info()));
        assert_eq!(parse("{}"), None);
        assert_eq!(parse("not json"), None);
        assert_eq!(parse(&json!({ "bind": "x", "port": 70000, "pid": 1 }).to_string()), None);
    }

    #[test]
    fn the_curl_line_names_the_token_path_and_never_a_token() {
        let i = info();
        let line = curl_line(&i);
        assert!(line.starts_with("curl -x \"socks5h://tunlion:$(cat '"), "{line}");
        assert!(line.contains(&proxy_token_path().display().to_string()), "{line}");
        assert!(line.contains("@127.0.0.1:1080\""), "{line}");
        assert!(line.contains("<peer>.mesh"), "{line}");
        let v = to_json(Some(&i));
        assert_eq!(v["running"], json!(true));
        assert_eq!(v["addr"], json!("127.0.0.1:1080"));
        assert_eq!(v["user"], json!("tunlion"));
        assert_eq!(v["curl"], json!(line));
        // The record carries no secret field at all.
        assert!(v.get("token").is_none() && v.get("password").is_none());
        assert_eq!(to_json(None), Value::Null);
    }

    #[test]
    fn status_and_hint_lines_say_how_to_use_it() {
        let i = info();
        let lines = status_lines(&i).join("\n");
        assert!(lines.contains("127.0.0.1:1080"), "{lines}");
        assert!(lines.contains(&curl_line(&i)), "{lines}");
        let hint = mesh_hint(&i);
        assert!(hint.contains(".mesh") && hint.contains(&curl_line(&i)), "{hint}");
    }

    #[test]
    fn a_dead_process_is_not_a_running_proxy() {
        // A pid far above any platform's pid range is never a live process.
        let raw = json!({ "bind": "127.0.0.1", "port": 1080, "pid": 4_000_000_000u64 }).to_string();
        let i = parse(&raw).unwrap();
        assert!(crate::platform::process_exe_path(i.pid).is_none());
    }
}
