//! `tunlion dashboard`: one screen for this device's relationships.
//!
//! The dashboard is a convenience screen served BY this device, never a control
//! plane. Everything it changes is a local write on this machine, made under its
//! owner's click: the same verbs the CLI runs (`grant`, `revoke`, `devices
//! revoke|restore|forget`, `requests approve|deny`, `add --out`), so the gates
//! that guard those verbs guard the dashboard too.
//!
//! Who can reach it:
//! - It listens on 127.0.0.1 only, on a random port.
//! - The browser is opened with a one-time secret in the URL fragment (never
//!   sent to a server, never in a Referer). The page trades it once for a
//!   session cookie (HttpOnly, SameSite=Strict). A second use is refused.
//! - Every request must name this listener in Host (a DNS-rebinding page names
//!   its own host) and, when the browser sends one, in Origin. Writes require
//!   Origin.
//! - On Linux, a connection from a different local user is refused outright,
//!   whatever it carries.
//! - It closes when the background service it started beside stops.
//!
//! Actions run this same binary with a fixed argument vector (no shell): every
//! argument is checked against a closed set first (a device must be one this
//! machine stores, a capability and a duration must match their shapes), so a
//! request cannot smuggle a flag in.

use anyhow::Result;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const INDEX_HTML: &[u8] = include_bytes!("../dashboard-dist/dashboard.html");
const DASHBOARD_JS: &[u8] = include_bytes!("../dashboard-dist/dashboard.js");
const DASHBOARD_CSS: &[u8] = include_bytes!("../dashboard-dist/dashboard.css");

/// The cookie that carries a session after the secret was traded.
const COOKIE: &str = "tl_dash";
/// Wrong secrets tolerated before the listener stops accepting any.
const MAX_BAD_SECRETS: u32 = 5;
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

/// The signaling server this dashboard was started with. Its child commands
/// must use the same one: a code minted on another server cannot be claimed.
static SERVER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn self_command() -> std::io::Result<tokio::process::Command> {
    let mut c = tokio::process::Command::new(std::env::current_exe()?);
    if let Some(s) = SERVER.get() {
        c.env("TUNLION_SERVER", s);
    }
    c.env("TUNLION_NONINTERACTIVE", "1").env("TUNLION_COLOR", "never").env("NO_COLOR", "1");
    Ok(c)
}

/// What a request looks like to the gate: no sockets, so the rules are tested
/// directly.
#[derive(Debug, Default, Clone)]
pub(crate) struct Req {
    pub method: String,
    pub path: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        raw.split(';').find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Host names something other than this listener (DNS rebinding).
    BadHost,
    /// Origin names another site, or a write came without one.
    BadOrigin,
    /// No valid session.
    NoSession,
    /// The secret was wrong, already used, or too many were wrong.
    BadSecret(&'static str),
}

impl Refusal {
    fn status(&self) -> (u16, &'static str) {
        match self {
            Refusal::BadHost | Refusal::BadOrigin => (403, "Forbidden"),
            Refusal::NoSession | Refusal::BadSecret(_) => (401, "Unauthorized"),
        }
    }
    fn message(&self) -> &'static str {
        match self {
            Refusal::BadHost => "This dashboard only answers at its own address.",
            Refusal::BadOrigin => "Requests from other sites are refused.",
            Refusal::NoSession => "Not signed in. Run tunlion dashboard again to open a new link.",
            Refusal::BadSecret(m) => m,
        }
    }
}

/// The listener's secret and sessions.
pub(crate) struct Gate {
    port: u16,
    secret: String,
    secret_used: bool,
    bad_secrets: u32,
    sessions: Vec<String>,
}

impl Gate {
    pub(crate) fn new(port: u16, secret: String) -> Self {
        Gate { port, secret, secret_used: false, bad_secrets: 0, sessions: Vec::new() }
    }

    fn origins(&self) -> [String; 2] {
        [format!("http://127.0.0.1:{}", self.port), format!("http://localhost:{}", self.port)]
    }

    /// Host and Origin. Every request, static or API.
    pub(crate) fn check_site(&self, req: &Req) -> Result<(), Refusal> {
        let host = req.header("host").unwrap_or("");
        if host != format!("127.0.0.1:{}", self.port) && host != format!("localhost:{}", self.port) {
            return Err(Refusal::BadHost);
        }
        let ours = self.origins();
        match req.header("origin") {
            Some(o) if ours.iter().any(|x| x == o) => {}
            Some(_) => return Err(Refusal::BadOrigin),
            // A same-origin GET carries no Origin; a write always does.
            None if req.method != "GET" => return Err(Refusal::BadOrigin),
            None => {}
        }
        // Fetch metadata, when the browser sends it, must say same-origin for
        // the API (a navigation to a page is `none` or `same-origin`).
        if req.path.starts_with("/api/") {
            if let Some(site) = req.header("sec-fetch-site") {
                if site != "same-origin" {
                    return Err(Refusal::BadOrigin);
                }
            }
        }
        Ok(())
    }

    /// Trade the one-time secret for a session token.
    pub(crate) fn redeem(&mut self, offered: &str, token: String) -> Result<String, Refusal> {
        if self.bad_secrets >= MAX_BAD_SECRETS {
            return Err(Refusal::BadSecret("Too many wrong links. Run tunlion dashboard again."));
        }
        if self.secret_used {
            return Err(Refusal::BadSecret("This link was already used. Run tunlion dashboard again for a new one."));
        }
        if !ct_eq(offered.as_bytes(), self.secret.as_bytes()) {
            self.bad_secrets += 1;
            return Err(Refusal::BadSecret("That link is not this dashboard's. Run tunlion dashboard again."));
        }
        self.secret_used = true;
        self.sessions.push(token.clone());
        Ok(token)
    }

    pub(crate) fn has_session(&self, req: &Req) -> bool {
        match req.cookie(COOKIE) {
            Some(t) => self.sessions.iter().any(|s| ct_eq(s.as_bytes(), t.as_bytes())),
            None => false,
        }
    }
}

/// Constant-time equality for secrets of the same length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("system randomness");
    hex::encode(b)
}

// ---------------------------------------------------------------------------
// Input shapes. Anything that reaches an argument vector passes one of these.

fn valid_cap(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 64
        && c.as_bytes()[0].is_ascii_lowercase()
        && c.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":/._-".contains(&b))
}

fn valid_duration(d: &str) -> bool {
    let (num, unit) = d.split_at(d.len().saturating_sub(1));
    !num.is_empty()
        && num.len() <= 5
        && !num.starts_with('0')
        && num.bytes().all(|b| b.is_ascii_digit())
        && matches!(unit, "m" | "h" | "d")
}

fn valid_new_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.as_bytes()[0].is_ascii_alphanumeric()
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// A device name the request names must be one this machine stores, exactly.
fn known_device(name: &str) -> bool {
    !name.starts_with('-') && crate::devices_store::devices_load().iter().any(|(n, _)| n == name)
}

/// The argument vector for an action, or why it is refused. Pure, so the
/// whitelist is tested without running anything.
pub(crate) fn action_argv(verb: &str, a: &Value, is_known: &dyn Fn(&str) -> bool) -> Result<Vec<String>, String> {
    let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let device = || -> Result<String, String> {
        let d = s("device");
        if is_known(&d) { Ok(d) } else { Err(format!("No device named '{d}' here.")) }
    };
    let cap = || -> Result<String, String> {
        let c = s("cap");
        if valid_cap(&c) { Ok(c) } else { Err("That is not a capability name.".to_string()) }
    };
    let id = || -> Result<String, String> {
        a.get("id").and_then(Value::as_u64).map(|n| n.to_string()).ok_or_else(|| "A request id is a number.".to_string())
    };
    let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    Ok(match verb {
        "grant" => { let (d, c) = (device()?, cap()?); [v(&["grant"]), vec![d, c], v(&["-y"])].concat() }
        "revoke-cap" => { let (d, c) = (device()?, cap()?); [v(&["revoke"]), vec![d, c], v(&["-y"])].concat() }
        "cut" => [v(&["devices", "revoke"]), vec![device()?], v(&["-y"])].concat(),
        "restore" => [v(&["devices", "restore"]), vec![device()?], v(&["-y"])].concat(),
        "forget" => [v(&["devices", "forget"]), vec![device()?], v(&["-y"])].concat(),
        "approve" => {
            let (i, c, dur) = (id()?, cap()?, s("for"));
            if !valid_duration(&dur) {
                return Err("Pick how long: for example 1h, 1d or 7d.".to_string());
            }
            [v(&["requests", "approve"]), vec![i], v(&["--allow"]), vec![c], v(&["--for"]), vec![dur], v(&["-y"])].concat()
        }
        "deny" => [v(&["requests", "deny"]), vec![id()?], v(&["-y"])].concat(),
        other => return Err(format!("Unknown action '{other}'.")),
    })
}

/// `add --out` for an invitation. Returns the argv and the file it writes.
pub(crate) fn invite_argv(a: &Value, out: &std::path::Path) -> Result<Vec<String>, String> {
    let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let kind = s("kind");
    if !matches!(kind.as_str(), "person" | "device" | "runner") {
        return Err("Pick who it is for: a person, one of your devices, or a machine.".to_string());
    }
    let name = s("name");
    if !valid_new_name(&name) {
        return Err("Give it a short name: letters, digits, dot, dash.".to_string());
    }
    let expires = s("expires");
    if !valid_duration(&expires) {
        return Err("Pick when it ends: for example 1d or 7d.".to_string());
    }
    let caps: Vec<String> = a
        .get("allow")
        .and_then(Value::as_array)
        .map(|xs| xs.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if caps.iter().any(|c| !valid_cap(c)) {
        return Err("One of the capabilities is not a capability name.".to_string());
    }
    let mut argv = vec!["add".to_string(), "--for".into(), kind.clone(), "--name".into(), name];
    if !caps.is_empty() && kind != "runner" {
        argv.push("--allow".into());
        argv.push(caps.join(","));
    }
    argv.extend(["--expires".to_string(), expires, "--out".into(), out.display().to_string(), "-y".into()]);
    Ok(argv)
}

/// Run this binary with `argv`, no shell, no terminal. (exit code, what it said)
async fn run_self(argv: &[String]) -> (i32, String) {
    let mut cmd = match self_command() {
        Ok(c) => c,
        Err(e) => return (1, format!("cannot find the tunlion binary: {e}")),
    };
    let child = cmd
        .args(argv)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(Duration::from_secs(60), child).await {
        Ok(Ok(out)) => {
            let mut said = String::from_utf8_lossy(&out.stderr).to_string();
            said.push_str(&String::from_utf8_lossy(&out.stdout));
            (out.status.code().unwrap_or(1), clean_text(&said))
        }
        Ok(Err(e)) => (1, format!("could not run tunlion: {e}")),
        Err(_) => (1, "tunlion did not finish within 60 seconds".to_string()),
    }
}

/// Strip ANSI escapes and blank lines; keep it short.
fn clean_text(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    let lines: Vec<&str> = out.lines().map(str::trim_end).filter(|l| !l.trim().is_empty()).collect();
    lines.iter().take(24).cloned().collect::<Vec<_>>().join("\n")
}

// ---------------------------------------------------------------------------
// State the page shows. All read from this machine.

fn daemon_log_tail(max_lines: usize) -> Vec<String> {
    let path = crate::platform::Paths::config_path("daemon.log");
    let Ok(raw) = std::fs::read(&path) else { return Vec::new() };
    let start = raw.len().saturating_sub(96 * 1024);
    let text = clean_text_keep_all(&String::from_utf8_lossy(&raw[start..]));
    let mut lines: Vec<String> = text.lines().map(str::to_string).filter(|l| !l.trim().is_empty()).collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // a partial first line
    }
    let n = lines.len();
    lines.split_off(n.saturating_sub(max_lines))
}

fn clean_text_keep_all(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

async fn state_json() -> Value {
    let now = crate::capability::now_secs();
    let all = crate::devices_store::devices_load();
    let devices = crate::dispatch::devices_json_rows(&all).await;
    let perms: Vec<Value> = crate::device_perms::all_device_perms(now).iter().map(crate::device_perms::to_json).collect();
    let pending = crate::ctl::try_list_pending().await;
    let requests: Vec<Value> = pending
        .as_ref()
        .map(|v| {
            crate::request_entries(v, false)
                .into_iter()
                .map(|r| json!({ "id": r.id, "peer": r.peer, "capability": r.capability, "ago": r.ago }))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "ok": true,
        "now": now,
        "me": {
            "name": crate::display_name(),
            "owner": crate::load_owner_key().is_some(),
            "identity": crate::identity_flow::has_identity(),
        },
        "daemon": { "running": crate::shell_support::daemon_alive().is_some(), "answering": pending.is_some() },
        "devices": devices,
        "perms": perms,
        "requests": requests,
        "history": daemon_log_tail(300),
    })
}

// ---------------------------------------------------------------------------
// A spoken pairing code: `add --word <words>` run as a child that waits for the
// other side to claim it. One at a time; the page polls it.

#[derive(Default)]
pub(crate) struct CodeJob {
    name: String,
    kind: String,
    code: Option<String>,
    done: Option<(i32, String)>,
    pid: Option<u32>,
}

pub(crate) type Codes = Arc<Mutex<Option<CodeJob>>>;

/// argv for a pairing code (`person` pairs only; `device` enrols into your
/// devices and needs the owner key, as `add --for device` does).
pub(crate) fn code_argv(a: &Value, words: &str) -> Result<Vec<String>, String> {
    let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let kind = s("kind");
    if !matches!(kind.as_str(), "person" | "device") {
        return Err("Pick who it is for: a person or one of your devices.".to_string());
    }
    let name = s("name");
    if !valid_new_name(&name) {
        return Err("Give it a short name: letters, digits, dot, dash.".to_string());
    }
    Ok(vec!["add".into(), "--for".into(), kind, "--name".into(), name, "--word".into(), words.to_string()])
}

fn qr_cells(text: &str) -> Value {
    match qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M) {
        Ok(c) => {
            let w = c.width();
            let cells: String = (0..w * w).map(|i| if c[(i % w, i / w)] == qrcode::Color::Dark { '1' } else { '0' }).collect();
            json!({ "width": w, "cells": cells })
        }
        Err(_) => Value::Null,
    }
}

async fn start_code(codes: &Codes, a: &Value) -> Resp {
    {
        let g = codes.lock().unwrap();
        if let Some(j) = g.as_ref() {
            if j.done.is_none() {
                return Resp::json(400, json!({"ok": false, "error": format!("A code for {} is still open. Cancel it first.", j.name)}));
            }
        }
    }
    let words = filament_pair::words::mint_words();
    let argv = match code_argv(a, &words) {
        Ok(v) => v,
        Err(msg) => return Resp::json(400, json!({"ok": false, "error": msg})),
    };
    let mut cmd = match self_command() {
        Ok(c) => c,
        Err(e) => return Resp::json(200, json!({"ok": false, "message": format!("cannot find the tunlion binary: {e}")})),
    };
    let log = crate::settings::config_dir().join(format!("dashboard-code-{}.log", random_hex(6)));
    let Ok(out) = std::fs::File::create(&log) else {
        return Resp::json(200, json!({"ok": false, "message": "could not write in the config dir"}));
    };
    let err = match out.try_clone() { Ok(f) => f, Err(_) => return Resp::json(200, json!({"ok": false})) };
    let child = cmd
        .args(&argv)
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err)
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Resp::json(200, json!({"ok": false, "message": format!("could not run tunlion: {e}")})),
    };
    let name = argv[4].clone();
    let kind = argv[2].clone();
    *codes.lock().unwrap() = Some(CodeJob { name: name.clone(), kind, code: None, done: None, pid: child.id() });
    // The full code is the words plus a number the ceremony picks: read it
    // from what `add` prints.
    let mut code = None;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(i) = text.find(&format!("{words}-")) {
            let rest: String = text[i + words.len() + 1..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if rest.len() >= 3 {
                code = Some(format!("{words}-{rest}"));
                break;
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
    }
    let codes2 = codes.clone();
    if let Some(c) = &code {
        if let Some(j) = codes.lock().unwrap().as_mut() {
            j.code = Some(c.clone());
        }
    }
    tokio::spawn(async move {
        let status = tokio::time::timeout(Duration::from_secs(11 * 60), child.wait()).await;
        let rc = match status {
            Ok(Ok(s)) => s.code().unwrap_or(1),
            _ => {
                let _ = child.kill().await;
                1
            }
        };
        let said = clean_text(&std::fs::read_to_string(&log).unwrap_or_default());
        let _ = std::fs::remove_file(&log);
        if let Some(j) = codes2.lock().unwrap().as_mut() {
            if j.done.is_none() {
                j.done = Some((rc, said));
            }
        }
    });
    match code {
        Some(c) => Resp::json(200, json!({"ok": true, "code": c, "name": name, "qr": qr_cells(&c)})),
        None => Resp::json(200, json!({"ok": false, "message": "tunlion did not show a code"})),
    }
}

fn code_status(codes: &Codes) -> Value {
    match codes.lock().unwrap().as_ref() {
        None => json!({"ok": true, "active": false}),
        Some(j) => json!({
            "ok": true,
            "active": j.done.is_none(),
            "name": j.name,
            "kind": j.kind,
            "code": j.code,
            "qr": j.code.as_deref().map(qr_cells),
            "done": j.done.as_ref().map(|(rc, said)| json!({"ok": *rc == 0, "exit": rc, "message": said})),
        }),
    }
}

fn cancel_code(codes: &Codes) {
    let mut g = codes.lock().unwrap();
    if let Some(j) = g.as_mut() {
        if j.done.is_none() {
            #[cfg(unix)]
            if let Some(pid) = j.pid {
                unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            }
            j.done = Some((130, "Cancelled. The code no longer works.".to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP: one request per connection, small and bounded.

struct Resp {
    status: u16,
    reason: &'static str,
    ctype: &'static str,
    body: Vec<u8>,
    extra: Vec<(String, String)>,
}

impl Resp {
    fn json(status: u16, v: Value) -> Self {
        let reason = match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", _ => "Error" };
        Resp { status, reason, ctype: "application/json", body: v.to_string().into_bytes(), extra: Vec::new() }
    }
    fn refuse(r: Refusal) -> Self {
        let (status, reason) = r.status();
        Resp { status, reason, ctype: "application/json", body: json!({"ok": false, "error": r.message()}).to_string().into_bytes(), extra: Vec::new() }
    }
    fn asset(ctype: &'static str, body: &[u8]) -> Self {
        Resp { status: 200, reason: "OK", ctype, body: body.to_vec(), extra: Vec::new() }
    }
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

async fn write_resp(stream: &mut TcpStream, r: Resp) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         X-Frame-Options: DENY\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\n\
         Content-Security-Policy: {CSP}\r\n",
        r.status, r.reason, r.ctype, r.body.len()
    );
    for (k, v) in &r.extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&r.body).await;
    let _ = stream.flush().await;
}

/// Parse one request. None on anything malformed or too large.
pub(crate) fn parse_request(buf: &[u8]) -> Option<(Req, usize)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let mut headers = Vec::new();
    for l in lines {
        let (k, v) = l.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let req = Req { method, path, headers, body: Vec::new() };
    let len: usize = req.header("content-length").map(|v| v.parse().ok()).unwrap_or(Some(0))?;
    if len > MAX_BODY {
        return None;
    }
    Some((req, end + 4 + len))
}

async fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some((mut req, total)) = parse_request(&buf) {
            if buf.len() >= total {
                let start = total - req.header("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
                req.body = buf[start..total].to_vec();
                return Some(req);
            }
        } else if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            // A complete head that did not parse, or a body over the cap.
            return None;
        }
        if buf.len() > MAX_HEAD + MAX_BODY {
            return None;
        }
    }
}

/// Linux: the uid owning the client end of a loopback connection, from
/// /proc/net/tcp. None when it cannot be told.
#[cfg(target_os = "linux")]
fn peer_uid(peer: std::net::SocketAddr, local: std::net::SocketAddr) -> Option<u32> {
    let want_local = format!("{:08X}:{:04X}", u32::from_le_bytes(match peer.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => return None }), peer.port());
    let want_rem = format!("{:08X}:{:04X}", u32::from_le_bytes(match local.ip() { std::net::IpAddr::V4(v) => v.octets(), _ => return None }), local.port());
    let raw = std::fs::read_to_string("/proc/net/tcp").ok()?;
    for line in raw.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 7 && f[1] == want_local && f[2] == want_rem {
            return f[7].parse().ok();
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_peer: std::net::SocketAddr, _local: std::net::SocketAddr) -> Option<u32> {
    None
}

#[cfg(unix)]
fn my_uid() -> Option<u32> {
    Some(unsafe { libc::getuid() })
}
#[cfg(not(unix))]
fn my_uid() -> Option<u32> {
    None
}

async fn handle(mut stream: TcpStream, gate: Arc<Mutex<Gate>>, codes: Codes) {
    // Another local user is refused before anything is read.
    if let (Ok(peer), Ok(local), Some(me)) = (stream.peer_addr(), stream.local_addr(), my_uid()) {
        if let Some(uid) = peer_uid(peer, local) {
            if uid != me {
                write_resp(&mut stream, Resp::json(403, json!({"ok": false, "error": "This dashboard belongs to another user."}))).await;
                return;
            }
        }
    }
    let Some(req) = read_request(&mut stream).await else {
        write_resp(&mut stream, Resp::json(400, json!({"ok": false, "error": "bad request"}))).await;
        return;
    };
    let resp = route(req, &gate, &codes).await;
    write_resp(&mut stream, resp).await;
}

async fn route(req: Req, gate: &Arc<Mutex<Gate>>, codes: &Codes) -> Resp {
    if let Err(r) = gate.lock().unwrap().check_site(&req) {
        return Resp::refuse(r);
    }
    let path = req.path.split('?').next().unwrap_or("").to_string();
    match (req.method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => Resp::asset("text/html; charset=utf-8", INDEX_HTML),
        ("GET", "/dashboard.js") => Resp::asset("text/javascript; charset=utf-8", DASHBOARD_JS),
        ("GET", "/dashboard.css") => Resp::asset("text/css; charset=utf-8", DASHBOARD_CSS),
        ("POST", "/api/session") => {
            let offered = serde_json::from_slice::<Value>(&req.body)
                .ok()
                .and_then(|v| v.get("secret").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            match gate.lock().unwrap().redeem(&offered, random_hex(32)) {
                Ok(token) => {
                    let mut r = Resp::json(200, json!({"ok": true}));
                    r.extra.push(("Set-Cookie".into(), format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")));
                    r
                }
                Err(e) => Resp::refuse(e),
            }
        }
        (_, p) if p.starts_with("/api/") => {
            if !gate.lock().unwrap().has_session(&req) {
                return Resp::refuse(Refusal::NoSession);
            }
            api(&req, p, codes).await
        }
        _ => Resp::json(404, json!({"ok": false, "error": "not found"})),
    }
}

async fn api(req: &Req, path: &str, codes: &Codes) -> Resp {
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    match (req.method.as_str(), path) {
        ("GET", "/api/state") => Resp::json(200, state_json().await),
        ("POST", "/api/act") => {
            let verb = body.get("verb").and_then(Value::as_str).unwrap_or("");
            match action_argv(verb, &body, &known_device) {
                Ok(argv) => {
                    let (code, said) = run_self(&argv).await;
                    Resp::json(200, json!({"ok": code == 0, "exit": code, "message": said}))
                }
                Err(msg) => Resp::json(400, json!({"ok": false, "error": msg})),
            }
        }
        ("POST", "/api/code") => start_code(codes, &body).await,
        ("GET", "/api/code") => Resp::json(200, code_status(codes)),
        ("POST", "/api/code/cancel") => {
            cancel_code(codes);
            Resp::json(200, code_status(codes))
        }
        ("POST", "/api/invite") => {
            // A fresh owner-only path in the config dir: `add --out` refuses
            // to overwrite, and the file is removed once read.
            let out = crate::settings::config_dir().join(format!("dashboard-invite-{}.txt", random_hex(8)));
            match invite_argv(&body, &out) {
                Ok(argv) => {
                    let (code, said) = run_self(&argv).await;
                    let text = std::fs::read_to_string(&out).ok();
                    let _ = std::fs::remove_file(&out);
                    match (code, text) {
                        (0, Some(text)) => Resp::json(200, json!({"ok": true, "invitation": text, "message": said})),
                        _ => Resp::json(200, json!({"ok": false, "exit": code, "message": said})),
                    }
                }
                Err(msg) => Resp::json(400, json!({"ok": false, "error": msg})),
            }
        }
        _ => Resp::json(404, json!({"ok": false, "error": "not found"})),
    }
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "windows")]
    let r = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    };
    matches!(r, Ok(s) if s.success())
}

pub(crate) async fn dashboard_cmd(no_open: bool, port: Option<u16>, server: &str) -> Result<()> {
    let _ = SERVER.set(server.to_string());
    if !crate::identity_flow::has_identity() && crate::devices_store::devices_load().is_empty() {
        return Err(crate::exit_codes::err(
            crate::exit_codes::ExitKind::NoIdentity,
            "nothing to manage yet: run `tunlion init` (or `tunlion join <code-or-invitation>`) first, then `tunlion dashboard`",
        ));
    }
    let listener = TcpListener::bind(("127.0.0.1", port.unwrap_or(0))).await.map_err(|e| {
        crate::exit_codes::err(crate::exit_codes::ExitKind::LocalResource, format!("could not listen on 127.0.0.1: {e}"))
    })?;
    let port = listener.local_addr()?.port();
    let secret = random_hex(32);
    let gate = Arc::new(Mutex::new(Gate::new(port, secret.clone())));
    let codes: Codes = Arc::new(Mutex::new(None));
    let url = format!("http://127.0.0.1:{port}/#k={secret}");
    let opened = !no_open && open_browser(&url);
    crate::ui::say(&format!(
        "  dashboard for {} {}\n  {url}\n  the link works once and only from this user on this machine. Ctrl-C stops it.",
        crate::display_name(),
        if opened { "opened in your browser" } else { "is ready: open this link in a browser on this machine" },
    ));

    // Close when the background service this dashboard started beside stops.
    let started_with_daemon = crate::shell_support::daemon_alive().is_some();
    let watch = async move {
        if !started_with_daemon {
            return std::future::pending::<()>().await;
        }
        // Three misses in a row, not one: a single look can miss a running
        // daemon (measured in the lab: the dashboard closed while `status`
        // still showed the daemon up), and closing is not undoable.
        let mut misses = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if crate::shell_support::daemon_alive().is_none() {
                misses += 1;
                if misses >= 3 {
                    return;
                }
            } else {
                misses = 0;
            }
        }
    };
    let serve = async {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            tokio::spawn(handle(stream, gate.clone(), codes.clone()));
        }
    };
    tokio::select! {
        _ = serve => {}
        _ = watch => {
            crate::ui::say("  the background service stopped, so the dashboard closed. Run `tunlion up`, then `tunlion dashboard` again.");
        }
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Req {
        Req {
            method: method.into(),
            path: path.into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn host_must_name_this_listener() {
        let g = Gate::new(7420, "s".repeat(64));
        assert!(g.check_site(&req("GET", "/", &[("host", "127.0.0.1:7420")])).is_ok());
        assert!(g.check_site(&req("GET", "/", &[("host", "localhost:7420")])).is_ok());
        // DNS rebinding: the attacker's name resolves to 127.0.0.1.
        assert_eq!(g.check_site(&req("GET", "/api/state", &[("host", "evil.example:7420")])), Err(Refusal::BadHost));
        assert_eq!(g.check_site(&req("GET", "/", &[("host", "127.0.0.1:7421")])), Err(Refusal::BadHost));
        assert_eq!(g.check_site(&req("GET", "/", &[])), Err(Refusal::BadHost));
    }

    #[test]
    fn cross_origin_is_refused_and_writes_need_an_origin() {
        let g = Gate::new(7420, "s".repeat(64));
        let h = ("host", "127.0.0.1:7420");
        assert_eq!(
            g.check_site(&req("POST", "/api/act", &[h, ("origin", "https://evil.example")])),
            Err(Refusal::BadOrigin)
        );
        assert_eq!(g.check_site(&req("POST", "/api/act", &[h])), Err(Refusal::BadOrigin));
        assert!(g.check_site(&req("POST", "/api/act", &[h, ("origin", "http://127.0.0.1:7420")])).is_ok());
        assert_eq!(
            g.check_site(&req("GET", "/api/state", &[h, ("sec-fetch-site", "cross-site")])),
            Err(Refusal::BadOrigin)
        );
        assert!(g.check_site(&req("GET", "/api/state", &[h, ("sec-fetch-site", "same-origin")])).is_ok());
    }

    #[test]
    fn the_secret_works_once_and_a_wrong_one_never() {
        let secret = "a".repeat(64);
        let mut g = Gate::new(7420, secret.clone());
        assert!(matches!(g.redeem(&"b".repeat(64), "t0".into()), Err(Refusal::BadSecret(_))));
        assert!(matches!(g.redeem("", "t0".into()), Err(Refusal::BadSecret(_))));
        let tok = g.redeem(&secret, "tok1".into()).unwrap();
        assert_eq!(tok, "tok1");
        // Second use of the same secret is refused.
        assert!(matches!(g.redeem(&secret, "tok2".into()), Err(Refusal::BadSecret(_))));
        let with = req("GET", "/api/state", &[("cookie", "x=1; tl_dash=tok1")]);
        assert!(g.has_session(&with));
        assert!(!g.has_session(&req("GET", "/api/state", &[("cookie", "tl_dash=tok2")])));
        assert!(!g.has_session(&req("GET", "/api/state", &[])));
    }

    #[test]
    fn too_many_wrong_secrets_lock_it() {
        let secret = "a".repeat(64);
        let mut g = Gate::new(7420, secret.clone());
        for _ in 0..MAX_BAD_SECRETS {
            let _ = g.redeem(&"b".repeat(64), "t".into());
        }
        assert!(matches!(g.redeem(&secret, "t".into()), Err(Refusal::BadSecret(_))));
    }

    #[test]
    fn actions_take_only_known_devices_and_shaped_values() {
        let known = |n: &str| n == "laptop" || n == "web-vps";
        let a = action_argv("grant", &json!({"device": "laptop", "cap": "shell"}), &known).unwrap();
        assert_eq!(a, ["grant", "laptop", "shell", "-y"]);
        assert!(action_argv("grant", &json!({"device": "--all", "cap": "shell"}), &known).is_err());
        assert!(action_argv("grant", &json!({"device": "nobody", "cap": "shell"}), &known).is_err());
        assert!(action_argv("grant", &json!({"device": "laptop", "cap": "--yes"}), &known).is_err());
        assert!(action_argv("grant", &json!({"device": "laptop", "cap": "shell; rm -rf /"}), &known).is_err());
        assert!(action_argv("reset", &json!({}), &known).is_err());
        let a = action_argv("approve", &json!({"id": 3, "cap": "shell", "for": "1d"}), &known).unwrap();
        assert_eq!(a, ["requests", "approve", "3", "--allow", "shell", "--for", "1d", "-y"]);
        assert!(action_argv("approve", &json!({"id": 3, "cap": "shell", "for": "forever"}), &known).is_err());
        assert!(action_argv("approve", &json!({"id": "3", "cap": "shell", "for": "1d"}), &known).is_err());
        assert_eq!(action_argv("cut", &json!({"device": "web-vps"}), &known).unwrap(), ["devices", "revoke", "web-vps", "-y"]);
    }

    #[test]
    fn invitations_are_shaped() {
        let out = std::path::Path::new("/tmp/x.txt");
        let a = invite_argv(&json!({"kind": "person", "name": "dana", "expires": "3d", "allow": ["transfer", "shell"]}), out).unwrap();
        assert_eq!(a, ["add", "--for", "person", "--name", "dana", "--allow", "transfer,shell", "--expires", "3d", "--out", "/tmp/x.txt", "-y"]);
        assert!(invite_argv(&json!({"kind": "admin", "name": "dana", "expires": "3d"}), out).is_err());
        assert!(invite_argv(&json!({"kind": "person", "name": "-x", "expires": "3d"}), out).is_err());
        assert!(invite_argv(&json!({"kind": "person", "name": "dana", "expires": "0d"}), out).is_err());
        assert!(invite_argv(&json!({"kind": "person", "name": "dana", "expires": "3d", "allow": ["a,b"]}), out).is_err());
    }

    #[test]
    fn codes_are_shaped() {
        let a = code_argv(&json!({"kind": "person", "name": "dana"}), "brave-otter").unwrap();
        assert_eq!(a, ["add", "--for", "person", "--name", "dana", "--word", "brave-otter"]);
        assert!(code_argv(&json!({"kind": "runner", "name": "dana"}), "w").is_err());
        assert!(code_argv(&json!({"kind": "device", "name": "--yes"}), "w").is_err());
    }

    #[test]
    fn requests_parse_and_bodies_are_capped() {
        let raw = b"POST /api/act HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 2\r\n\r\n{}";
        let (r, total) = parse_request(raw).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(total, raw.len());
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert!(parse_request(big.as_bytes()).is_none());
    }
}
