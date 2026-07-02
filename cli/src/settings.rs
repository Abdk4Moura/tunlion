//! Typed, discoverable persistent settings: the backing for `filament set`,
//! `filament get`, and `filament unset`.
//!
//! Design follows the evidence on world-class CLI config surfaces (clig.dev,
//! the 12-factor CLI doc, and how git/gh/aws actually behave), chosen over the
//! Tailscale `set --flag` model after its own maintainers documented that the
//! flag model "tries to safely do a bad job" at being both declarative and
//! imperative (tailscale/tailscale#15460):
//!
//!  - `key value` is the canonical surface (git/gh/npm/aws lineage): it scales
//!    without flag explosion and stays compatible with the legacy
//!    `filament config <key> <value>` file (`key value` lines).
//!  - `set` is strictly imperative and PARTIAL: it touches only the key you
//!    name, never resetting anything you did not mention (the exact Tailscale
//!    bug, designed out here).
//!  - Resolution precedence is a fixed ladder, surfaced via provenance like
//!    git's `--show-origin` / aws's TYPE/LOCATION:
//!        env  >  per-peer override  >  global config  >  built-in default
//!  - Humans first, machines second: a TTY gets an aligned, colored table; a
//!    pipe gets tab-separated `key<TAB>value<TAB>scope` rows with no color and
//!    no borders; `--json` gives the complete structured view either way.
//!  - Values go to stdout, all messaging/confirmation to stderr, so
//!    `$(filament get drop-dir)` is exactly the value.
//!
//! Storage: global settings live in the existing `config` file (one `key value`
//! line each, so name/server/dir stay byte-compatible with the old `config`
//! command and its readers). Per-peer overrides live alongside in `peerconf`
//! (JSON: `{ "<device>": { "<key>": "<value>" } }`).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::ui;

// --------------------------------------------------------------- registry --

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Bool,
    Str,
    Path,
    Enum(&'static [&'static str]),
}

#[derive(Clone, Copy, PartialEq)]
pub enum ScopeKind {
    /// Global only (a single machine-wide value).
    GlobalOnly,
    /// Global default, optionally overridden per known device via `--peer`.
    GlobalOrPeer,
}

pub struct Setting {
    /// Canonical name (what the readout prints, what `--peer` keys on).
    pub key: &'static str,
    /// Accepted alternate spellings (for input + did-you-mean).
    pub aliases: &'static [&'static str],
    /// On-disk key (legacy-compatible: drop-dir stores as `dir`).
    pub store: &'static str,
    pub kind: Kind,
    /// Built-in default rendered value (some keys compute it; see `effective_default`).
    pub default: &'static str,
    pub scope: ScopeKind,
    /// Environment variable that overrides everything (highest precedence).
    pub env: Option<&'static str>,
    /// True when the running `up` daemon must restart to pick the change up.
    pub daemon: bool,
    pub help: &'static str,
}

const RELAY_VALS: &[&str] = &["auto", "always", "never"];

pub fn registry() -> &'static [Setting] {
    static R: &[Setting] = &[
        Setting {
            key: "name",
            aliases: &[],
            store: "name",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_NAME"),
            daemon: true,
            help: "Display name other devices see (default: user@host)",
        },
        Setting {
            key: "server",
            aliases: &["signaling"],
            store: "server",
            kind: Kind::Str,
            default: crate::DEFAULT_SERVER,
            scope: ScopeKind::GlobalOnly,
            env: Some("FILAMENT_SERVER"),
            daemon: true,
            help: "Signaling server URL",
        },
        Setting {
            key: "drop-dir",
            aliases: &["dir"],
            store: "dir",
            kind: Kind::Path,
            default: "~/Filament",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Where received files are saved",
        },
        Setting {
            key: "relay",
            aliases: &[],
            store: "relay",
            kind: Kind::Enum(RELAY_VALS),
            default: "auto",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Relay policy: auto (direct, fall back to relay), always (force TURN), never (direct-only)",
        },
        Setting {
            key: "auto-extract",
            aliases: &["extract", "unzip"],
            store: "auto-extract",
            kind: Kind::Bool,
            default: "off",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Unpack received .tar/.tar.gz archives into the drop dir (off by default)",
        },
        Setting {
            key: "shell",
            aliases: &[],
            store: "shell",
            kind: Kind::Bool,
            default: "off",
            scope: ScopeKind::GlobalOrPeer,
            env: None,
            daemon: true,
            help: "Accept seamless `filament ssh` from paired devices (per-peer with --peer)",
        },
        Setting {
            key: "shell-user",
            aliases: &[],
            store: "shell-user",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "Drop the ssh/web-shell PTY to this non-root account (runuser)",
        },
        Setting {
            key: "tun-addr",
            aliases: &["overlay"],
            store: "tun-addr",
            kind: Kind::Str,
            default: "",
            scope: ScopeKind::GlobalOnly,
            env: None,
            daemon: true,
            help: "L3 overlay address as IP/PREFIX (e.g. 10.9.0.1/24); empty = L3 off",
        },
    ];
    R
}

/// Resolve a key (canonical or alias) to its `Setting`.
pub fn find(name: &str) -> Option<&'static Setting> {
    let n = name.trim();
    registry()
        .iter()
        .find(|s| s.key == n || s.aliases.contains(&n))
}

/// Closest known key name (canonical or alias) within edit-distance 2.
pub fn did_you_mean(name: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for s in registry() {
        for cand in std::iter::once(s.key).chain(s.aliases.iter().copied()) {
            let d = levenshtein(name, cand);
            if d <= 2 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
                best = Some((s.key, d)); // suggest the canonical name
            }
        }
    }
    best.map(|(k, _)| k)
}

pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

// ------------------------------------------------------------------ store --

pub(crate) fn config_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config/filament")
}

fn global_path() -> PathBuf {
    config_dir().join("config")
}

fn peer_path() -> PathBuf {
    config_dir().join("peerconf")
}

fn global_get(store: &str) -> Option<String> {
    std::fs::read_to_string(global_path()).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(char::is_whitespace)?;
        (k == store && !v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

fn global_put(store: &str, value: &str) -> Result<()> {
    let p = global_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(store))
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{store} {value}"));
    std::fs::write(&p, lines.join("\n") + "\n")?;
    Ok(())
}

fn global_remove(store: &str) -> Result<bool> {
    let p = global_path();
    let Ok(raw) = std::fs::read_to_string(&p) else { return Ok(false) };
    let kept: Vec<&str> = raw
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(store))
        .collect();
    let removed = kept.len() != raw.lines().count();
    if removed {
        std::fs::write(&p, kept.join("\n") + if kept.is_empty() { "" } else { "\n" })?;
    }
    Ok(removed)
}

fn peer_load() -> serde_json::Map<String, Value> {
    std::fs::read_to_string(peer_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn peer_save(m: &serde_json::Map<String, Value>) -> Result<()> {
    let p = peer_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&p, serde_json::to_string_pretty(&Value::Object(m.clone()))?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn peer_get(device: &str, store: &str) -> Option<String> {
    peer_load()
        .get(device)?
        .get(store)?
        .as_str()
        .map(|s| s.to_string())
}

// ------------------------------------------------------------- resolution --

#[derive(Clone)]
pub enum Origin {
    Env(&'static str),
    Peer(String),
    Global,
    Default,
}

impl Origin {
    fn label(&self) -> String {
        match self {
            Origin::Env(v) => format!("env:{v}"),
            Origin::Peer(d) => format!("peer:{d}"),
            Origin::Global => "config".into(),
            Origin::Default => "default".into(),
        }
    }
}

fn effective_default(s: &Setting) -> String {
    match s.key {
        "name" => crate::default_display_name(),
        "drop-dir" => crate::default_drop_dir().display().to_string(),
        _ => s.default.to_string(),
    }
}

/// Resolve the effective value of a setting and where it came from.
/// `peer` is consulted only for `GlobalOrPeer` settings.
pub fn resolve(s: &Setting, peer: Option<&str>) -> (String, Origin) {
    if let Some(ev) = s.env {
        if let Ok(v) = std::env::var(ev) {
            if !v.is_empty() {
                return (v, Origin::Env(ev));
            }
        }
    }
    if let Some(p) = peer {
        if s.scope == ScopeKind::GlobalOrPeer {
            if let Some(v) = peer_get(p, s.store) {
                return (v, Origin::Peer(p.to_string()));
            }
        }
    }
    if let Some(v) = global_get(s.store) {
        return (v, Origin::Global);
    }
    (effective_default(s), Origin::Default)
}

// -- typed convenience for behavioral consumers (up/recv/relay wiring) ------

/// Effective boolean for a Bool key, peer-aware (peer override > global > default).
pub fn get_bool(key: &str, peer: Option<&str>) -> bool {
    let Some(s) = find(key) else { return false };
    truthy(&resolve(s, peer).0)
}

/// Effective string for a key, or None when it resolves to the empty default.
pub fn get_str(key: &str, peer: Option<&str>) -> Option<String> {
    let s = find(key)?;
    let (v, origin) = resolve(s, peer);
    match origin {
        Origin::Default if v.is_empty() => None,
        _ => Some(v),
    }
}

/// Devices that have a per-peer override of `key` set to a truthy/eq value.
/// For Bool keys, `want` is "on"; used to fold per-peer shell into shell-only.
pub fn peers_with(key: &str, want: &str) -> Vec<String> {
    let Some(s) = find(key) else { return Vec::new() };
    let mut out = Vec::new();
    for (dev, kv) in peer_load() {
        if let Some(v) = kv.get(s.store).and_then(|v| v.as_str()) {
            if v == want {
                out.push(dev);
            }
        }
    }
    out.sort();
    out
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1")
}

// ------------------------------------------------------ validate / canon --

/// Canonicalize + validate a raw input value for a setting; returns the form
/// to persist, or a human error explaining what was expected.
fn canonicalize(s: &Setting, raw: &str) -> Result<String> {
    let raw = raw.trim();
    match s.kind {
        Kind::Bool => match raw.to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Ok("on".into()),
            "off" | "false" | "no" | "0" => Ok("off".into()),
            _ => bail!("'{}' expects on/off (also true/false, yes/no, 1/0)", s.key),
        },
        Kind::Enum(vals) => {
            let lc = raw.to_ascii_lowercase();
            if vals.contains(&lc.as_str()) {
                Ok(lc)
            } else {
                bail!("'{}' expects one of: {}", s.key, vals.join(", "))
            }
        }
        Kind::Path => {
            if raw.is_empty() {
                bail!("'{}' needs a path", s.key);
            }
            let expanded = expand_tilde(raw);
            // Validate writability without surprising side effects: the dir
            // itself, or its nearest existing ancestor, must be writable.
            let probe = if expanded.exists() {
                expanded.clone()
            } else {
                expanded
                    .ancestors()
                    .find(|a| a.exists())
                    .map(|a| a.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("/"))
            };
            let writable = std::fs::metadata(&probe)
                .map(|m| !m.permissions().readonly())
                .unwrap_or(false);
            if !writable {
                bail!("{} is not writable (or its parent does not exist)", probe.display());
            }
            Ok(raw.to_string()) // store as given (keep ~ portable)
        }
        Kind::Str => {
            if s.key == "server" && !(raw.starts_with("http://") || raw.starts_with("https://")) {
                bail!("server must be an http(s) URL, e.g. https://api.example.com");
            }
            Ok(raw.to_string())
        }
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

// ------------------------------------------------------------- mutations --

pub struct Change {
    pub key: &'static str,
    pub old: String,
    pub new: String,
    pub scope: String, // "global" or "peer:<device>"
    pub daemon: bool,
}

fn require_peer_known(device: &str) -> Result<()> {
    if crate::devices_load().iter().any(|(n, _)| n == device) {
        Ok(())
    } else {
        bail!("no device named '{device}' (see `filament devices`)")
    }
}

/// Set one key (strictly imperative + partial: only this key changes).
pub fn set(key: &str, value: &str, peer: Option<&str>) -> Result<Change> {
    let s = lookup(key)?;
    if let Some(p) = peer {
        if s.scope == ScopeKind::GlobalOnly {
            bail!("'{}' is global-only; drop --peer", s.key);
        }
        require_peer_known(p)?;
    }
    let new = canonicalize(s, value)?;
    let scope_str = peer.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
    let old = resolve(s, peer).0;
    match peer {
        Some(p) => {
            let mut m = peer_load();
            let entry = m.entry(p.to_string()).or_insert_with(|| json!({}));
            if let Some(obj) = entry.as_object_mut() {
                obj.insert(s.store.to_string(), json!(new));
            }
            peer_save(&m)?;
        }
        None => global_put(s.store, &new)?,
    }
    Ok(Change { key: s.key, old, new, scope: scope_str, daemon: s.daemon })
}

/// Remove an override (revert to the next layer down: global, then default).
pub fn unset(key: &str, peer: Option<&str>) -> Result<Change> {
    let s = lookup(key)?;
    let before = resolve(s, peer).0;
    let scope_str = peer.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
    match peer {
        Some(p) => {
            let mut m = peer_load();
            if let Some(obj) = m.get_mut(p).and_then(|e| e.as_object_mut()) {
                obj.remove(s.store);
                if obj.is_empty() {
                    m.remove(p);
                }
            }
            peer_save(&m)?;
        }
        None => {
            global_remove(s.store)?;
        }
    }
    let after = resolve(s, peer).0;
    Ok(Change { key: s.key, old: before, new: after, scope: scope_str, daemon: s.daemon })
}

fn lookup(key: &str) -> Result<&'static Setting> {
    find(key).ok_or_else(|| match did_you_mean(key) {
        Some(s) => anyhow::anyhow!("unknown key '{key}' - did you mean '{s}'? (`filament set` lists all)"),
        None => anyhow::anyhow!("unknown key '{key}' (`filament set` lists all keys)"),
    })
}

// ----------------------------------------------------------- CLI handlers --

/// `filament get <key> [--show-origin] [--default <v>] [--json] [--peer <d>]`
pub fn run_get(
    key: &str,
    peer: Option<&str>,
    show_origin: bool,
    default: Option<&str>,
    json_out: bool,
) -> Result<()> {
    let s = lookup(key)?;
    if peer.is_some() && s.scope == ScopeKind::GlobalOnly {
        bail!("'{}' is global-only; drop --peer", s.key);
    }
    let (mut value, origin) = resolve(s, peer);
    if value.is_empty() {
        if let Some(d) = default {
            value = d.to_string();
        } else {
            // Empty effective value (e.g. unset name fallback failed) → exit 1.
            std::process::exit(1);
        }
    }
    if json_out {
        println!(
            "{}",
            json!({ "key": s.key, "value": value, "origin": origin.label(), "default": effective_default(s), "help": s.help })
        );
    } else if show_origin {
        let color = ui::stdout_color();
        println!(
            "{}  {}",
            value,
            ui::paint_when(color, ui::Tone::Dim, &format!("({})", origin.label()))
        );
    } else {
        // Bare value: $(filament get drop-dir) is exactly the value.
        println!("{value}");
    }
    Ok(())
}

/// Tell a running daemon a key changed and print whether it applied live. On a
/// daemon that doesn't answer (or a non-unix host), fall back to the restart hint.
async fn announce_to_daemon(key: &str, color: bool) {
    #[cfg(unix)]
    {
        match crate::ctl::try_reconfigure(key).await {
            Some(v) if v["live"].as_bool() == Some(true) => {
                eprintln!("  {}", ui::paint_when(color, ui::Tone::Ok, "applied to the running daemon"));
                return;
            }
            _ => {}
        }
    }
    eprintln!("  {}", ui::paint_when(color, ui::Tone::Dim, "takes effect on next `filament up`"));
}

/// `filament unset <key> [--peer a,b]`. `peers` empty = clear the global value;
/// one or more = remove each device's per-peer override.
pub async fn run_unset(key: &str, peers: &[String]) -> Result<()> {
    let s = lookup(key)?;
    let color = ui::stdout_color();
    let targets: Vec<Option<&str>> = if peers.is_empty() {
        vec![None]
    } else {
        peers.iter().map(|p| Some(p.as_str())).collect()
    };
    let mut touched_daemon = false;
    for tgt in targets {
        let c = unset(key, tgt)?;
        eprintln!(
            "{} {} reset to default: {} ({})",
            ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()),
            c.key,
            c.new,
            c.scope
        );
        touched_daemon = c.daemon;
    }
    if touched_daemon && crate::daemon_running() {
        announce_to_daemon(s.key, color).await;
    }
    Ok(())
}

/// `filament set` with key+value, or no args (readout), or --reset.
/// `peers` empty = global; one or more = a per-peer override applied to each.
#[allow(clippy::too_many_arguments)]
pub async fn run_set(
    key: Option<&str>,
    value: Option<&str>,
    peers: &[String],
    dry_run: bool,
    reset: bool,
    yes: bool,
    json_out: bool,
) -> Result<()> {
    if reset {
        return run_reset(dry_run, yes);
    }
    match (key, value) {
        (None, _) => readout(json_out),
        (Some(k), None) => {
            // `set <key>` with no value = read it (ergonomic shortcut to `get`).
            run_get(k, peers.first().map(|s| s.as_str()), false, None, json_out)
        }
        (Some(k), Some(v)) => {
            let s = lookup(k)?;
            if !peers.is_empty() && s.scope == ScopeKind::GlobalOnly {
                bail!("'{}' is global-only; drop --peer", s.key);
            }
            // Validate the value once (fail fast before writing anything), and
            // every target device, so a typo in peer 2 never half-applies peer 1.
            let new = canonicalize(s, v)?;
            for p in peers {
                require_peer_known(p)?;
            }
            // Targets: no --peer = the single global scope; else one per device.
            let targets: Vec<Option<&str>> = if peers.is_empty() {
                vec![None]
            } else {
                peers.iter().map(|p| Some(p.as_str())).collect()
            };
            let color = ui::stdout_color();
            let mut touched_daemon = false;
            for tgt in targets {
                if dry_run {
                    let old = resolve(s, tgt).0;
                    let scope_str = tgt.map(|p| format!("peer:{p}")).unwrap_or_else(|| "global".into());
                    eprintln!(
                        "would set {} {} {} ({}) {}",
                        s.key,
                        ui::paint_when(color, ui::Tone::Dim, &old),
                        ui::paint_when(color, ui::Tone::Dim, ui::glyph_arrow()),
                        scope_str,
                        new
                    );
                    continue;
                }
                let c = set(k, v, tgt)?;
                if c.old == c.new {
                    eprintln!("{} already {} ({})", c.key, c.new, c.scope);
                } else {
                    eprintln!(
                        "{} {}: {} {} {} ({})",
                        ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()),
                        c.key,
                        ui::paint_when(color, ui::Tone::Dim, &c.old),
                        ui::glyph_arrow(),
                        c.new,
                        c.scope
                    );
                }
                touched_daemon = c.daemon;
            }
            // One reconfigure ping covers all peers (it re-reads the whole key).
            if !dry_run && touched_daemon && crate::daemon_running() {
                announce_to_daemon(s.key, color).await;
            }
            // Enabling the L3 overlay needs CAP_NET_ADMIN for a non-root daemon;
            // grant it now (one sudo prompt) so `up` just works, no separate step.
            // BUT the userspace backend needs no privilege, so don't prompt for a
            // setcap the user explicitly opted out of (l3-mode=userspace or the env).
            #[cfg(l3)]
            if !dry_run && s.key == "tun-addr" && !new.is_empty() {
                let userspace = std::env::var("FILAMENT_L3_USERSPACE").as_deref() == Ok("1")
                    || get_str("l3-mode", None).as_deref() == Some("userspace");
                if !userspace {
                    crate::tun::ensure_net_admin_for_l3();
                }
            }
            Ok(())
        }
    }
}

fn run_reset(dry_run: bool, yes: bool) -> Result<()> {
    let color = ui::stdout_color();
    // Gather what would change so dry-run and the prompt are honest.
    let mut changes: Vec<String> = Vec::new();
    for s in registry() {
        let (cur, origin) = resolve(s, None);
        if !matches!(origin, Origin::Default) {
            changes.push(format!("  {} {} {} {}", s.key, cur, ui::glyph_arrow(), effective_default(s)));
        }
    }
    let peers = peer_load();
    if changes.is_empty() && peers.is_empty() {
        eprintln!("nothing to reset (all settings are at their defaults)");
        return Ok(());
    }
    if dry_run {
        eprintln!("would reset to defaults:");
        for c in &changes {
            eprintln!("{c}");
        }
        if !peers.is_empty() {
            eprintln!("  and clear per-peer overrides for: {}", peers.keys().cloned().collect::<Vec<_>>().join(", "));
        }
        return Ok(());
    }
    // Destructive: confirm at a TTY, require --yes in a pipe (never hang).
    if !yes {
        if std::io::stdin().is_terminal() {
            eprint!("reset ALL settings to defaults? this clears global + per-peer overrides [y/N] ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).ok();
            if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                eprintln!("aborted");
                return Ok(());
            }
        } else {
            bail!("refusing to reset without --yes (non-interactive)");
        }
    }
    for s in registry() {
        global_remove(s.store)?;
    }
    let _ = std::fs::remove_file(peer_path());
    eprintln!("{} reset all settings to defaults", ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok()));
    Ok(())
}

/// No-args readout. TTY: aligned colored table. Pipe: tab-separated rows.
/// `--json`: complete structured array (global rows + per-peer overrides).
fn readout(json_out: bool) -> Result<()> {
    let peers = peer_load();

    if json_out {
        let mut rows: Vec<Value> = Vec::new();
        for s in registry() {
            let (v, o) = resolve(s, None);
            rows.push(json!({
                "key": s.key, "value": v, "scope": "global",
                "origin": o.label(), "default": effective_default(s), "daemon": s.daemon, "help": s.help,
            }));
        }
        for (dev, kv) in &peers {
            if let Some(obj) = kv.as_object() {
                for (store, val) in obj {
                    if let Some(s) = registry().iter().find(|s| s.store == store) {
                        rows.push(json!({
                            "key": s.key, "value": val, "scope": format!("peer:{dev}"),
                            "origin": format!("peer:{dev}"), "default": effective_default(s), "daemon": s.daemon,
                        }));
                    }
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&json!(rows))?);
        return Ok(());
    }

    let tty = std::io::stdout().is_terminal();
    if !tty {
        // Machine surface: one entry per line, no header, no color, no borders.
        // Always 3 columns so `cut -f2` is stable.
        for s in registry() {
            let (v, _) = resolve(s, None);
            println!("{}\t{}\tglobal", s.key, v);
        }
        for (dev, kv) in &peers {
            if let Some(obj) = kv.as_object() {
                for (store, val) in obj {
                    if let Some(s) = registry().iter().find(|s| s.store == store) {
                        println!("{}\t{}\tpeer:{dev}", s.key, val.as_str().unwrap_or_default());
                    }
                }
            }
        }
        return Ok(());
    }

    // Human surface: aligned table with provenance, no borders.
    let color = ui::stdout_color();
    let mut rows: Vec<(String, String, String, String)> = Vec::new();
    for s in registry() {
        let (v, o) = resolve(s, None);
        rows.push((s.key.into(), v, "global".into(), o.label()));
    }
    for (dev, kv) in &peers {
        if let Some(obj) = kv.as_object() {
            for (store, val) in obj {
                if let Some(s) = registry().iter().find(|s| s.store == store) {
                    rows.push((s.key.into(), val.as_str().unwrap_or_default().into(), format!("peer:{dev}"), format!("peer:{dev}")));
                }
            }
        }
    }
    let w0 = rows.iter().map(|r| r.0.len()).max().unwrap_or(3).max(7);
    let w1 = rows.iter().map(|r| r.1.len()).max().unwrap_or(5).max(5);
    let w2 = rows.iter().map(|r| r.2.len()).max().unwrap_or(5).max(5);
    let header = format!(
        "{:w0$}  {:w1$}  {:w2$}  {}",
        "SETTING", "VALUE", "SCOPE", "ORIGIN",
        w0 = w0, w1 = w1, w2 = w2
    );
    println!("{}", ui::paint_when(color, ui::Tone::Dim, &header));
    for (k, v, sc, or) in &rows {
        let dim_default = or == "default";
        let line = format!("{k:w0$}  {v:w1$}  {sc:w2$}  {or}", w0 = w0, w1 = w1, w2 = w2);
        if dim_default {
            println!("{}", ui::paint_when(color, ui::Tone::Dim, &line));
        } else {
            println!("{line}");
        }
    }
    println!();
    println!(
        "{}",
        ui::paint_when(color, ui::Tone::Dim, "change: filament set <key> <value> [--peer <device>]   reset: filament unset <key>")
    );
    Ok(())
}

// --------------------------------------------------------------- extract --

/// Extract a received tar/tar.gz archive into `into`, hardened against zip-slip,
/// symlink/hardlink escapes, and tar bombs. Returns the number of files written.
/// Only ever called for recognized archive extensions, opt-in via `auto-extract`.
pub fn extract_archive(path: &Path, into: &Path) -> Result<usize> {
    let max_files: usize = std::env::var("FILAMENT_MAX_EXTRACT_FILES").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let max_bytes: u64 = std::env::var("FILAMENT_MAX_EXTRACT_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(20 * 1024 * 1024 * 1024);

    let f = std::fs::File::open(path)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let gz = name.ends_with(".tar.gz") || name.ends_with(".tgz");
    let reader: Box<dyn std::io::Read> = if gz {
        Box::new(flate2::read::GzDecoder::new(f))
    } else {
        Box::new(f)
    };
    let mut ar = tar::Archive::new(reader);
    ar.set_overwrite(false); // never clobber existing files
    ar.set_preserve_permissions(false);

    std::fs::create_dir_all(into)?;
    let mut written = 0usize;
    let mut total = 0u64;
    let mut skipped = 0usize;
    for entry in ar.entries()? {
        let mut e = entry?;
        let et = e.header().entry_type();
        // Strict: an auto-unpack never creates links (a link is the classic
        // escape vector). Users who need them can extract by hand.
        if et.is_symlink() || et.is_hard_link() {
            skipped += 1;
            continue;
        }
        total = total.saturating_add(e.header().size().unwrap_or(0));
        if written > max_files || total > max_bytes {
            bail!("archive exceeds extract limits ({written} files / {total} bytes); extract it manually");
        }
        // unpack_in refuses to write outside `into` (returns Ok(false) on a
        // crafted `..`/absolute path); that is our zip-slip guard.
        match e.unpack_in(into) {
            Ok(true) => written += 1,
            Ok(false) => skipped += 1,
            Err(_) => skipped += 1,
        }
    }
    let _ = skipped;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    // FILAMENT_CONFIG_DIR is process-global, so config-dir tests must not run
    // concurrently (cargo tests are multithreaded by default). Serialize them.
    static CFG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_tmp_cfg<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CFG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("fil-set-test-{}-{:x}", std::process::id(), rand_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: the lock above makes this the only thread touching the env/dir.
        unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
        let r = f();
        unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
    fn rand_tag() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn find_resolves_aliases_and_did_you_mean() {
        assert_eq!(find("dir").unwrap().key, "drop-dir");
        assert_eq!(find("unzip").unwrap().key, "auto-extract");
        assert_eq!(did_you_mean("rely"), Some("relay"));
        assert_eq!(did_you_mean("dropdir"), Some("drop-dir"));
        assert!(find("nonsense").is_none());
    }

    #[test]
    fn bool_canonicalization_is_forgiving_then_strict() {
        let s = find("auto-extract").unwrap();
        assert_eq!(canonicalize(s, "YES").unwrap(), "on");
        assert_eq!(canonicalize(s, "0").unwrap(), "off");
        assert!(canonicalize(s, "maybe").is_err());
    }

    #[test]
    fn enum_validates_against_allowed_set() {
        let s = find("relay").unwrap();
        assert_eq!(canonicalize(s, "Always").unwrap(), "always");
        assert!(canonicalize(s, "sometimes").is_err());
    }

    #[test]
    fn precedence_env_over_peer_over_global_over_default() {
        with_tmp_cfg(|| {
            let s = find("shell").unwrap();
            // default
            assert!(matches!(resolve(s, None).1, Origin::Default));
            assert_eq!(resolve(s, None).0, "off");
            // global wins over default
            global_put("shell", "on").unwrap();
            assert!(matches!(resolve(s, None).1, Origin::Global));
            assert_eq!(resolve(s, None).0, "on");
        });
    }

    #[test]
    fn peer_override_beats_global_and_is_scoped() {
        with_tmp_cfg(|| {
            // a known device is required for set --peer; write devices.json
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();
            global_put("auto-extract", "off").unwrap();
            set("auto-extract", "on", Some("laptop")).unwrap();
            assert!(get_bool("auto-extract", Some("laptop")));
            assert!(!get_bool("auto-extract", Some("phone"))); // falls to global off
            assert!(!get_bool("auto-extract", None));
            assert_eq!(peers_with("auto-extract", "on"), vec!["laptop".to_string()]);
        });
    }

    #[test]
    fn global_only_rejects_peer_scope() {
        with_tmp_cfg(|| {
            let devs = config_dir().join("devices.json");
            std::fs::write(&devs, r#"[{"name":"laptop","secret":"x"}]"#).unwrap();
            assert!(set("server", "https://x", Some("laptop")).is_err());
        });
    }

    #[test]
    fn unset_reverts_to_lower_layer() {
        with_tmp_cfg(|| {
            global_put("relay", "always").unwrap();
            assert_eq!(resolve(find("relay").unwrap(), None).0, "always");
            unset("relay", None).unwrap();
            let (v, o) = resolve(find("relay").unwrap(), None);
            assert_eq!(v, "auto");
            assert!(matches!(o, Origin::Default));
        });
    }

    // Hand-built USTAR record so the archive genuinely contains a `..` entry
    // (the tar crate's Builder refuses to write one, so it can't construct the
    // attack we must defend against).
    fn raw_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len()].copy_from_slice(nb);
        h[100..107].copy_from_slice(b"0000644"); // mode
        h[108..115].copy_from_slice(b"0000000"); // uid
        h[116..123].copy_from_slice(b"0000000"); // gid
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes()); // size
        h[136..147].copy_from_slice(b"00000000000"); // mtime
        h[156] = b'0'; // typeflag = regular
        h[257..262].copy_from_slice(b"ustar");
        h[263..265].copy_from_slice(b"00");
        for b in h.iter_mut().take(156).skip(148) {
            *b = b' '; // checksum field is spaces while summing
        }
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        h[154] = 0;
        h[155] = b' ';
        let mut out = h.to_vec();
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
        out
    }

    #[test]
    fn extract_blocks_traversal() {
        with_tmp_cfg(|| {
            let src = config_dir().join("payload.tar");
            let mut bytes = Vec::new();
            bytes.extend(raw_entry("bundle/ok.txt", b"hello")); // the dir-send shape
            bytes.extend(raw_entry("../escape.txt", b"pwned")); // zip-slip attempt
            bytes.extend(std::iter::repeat(0u8).take(1024)); // tar EOF
            std::fs::write(&src, &bytes).unwrap();

            let into = config_dir().join("out");
            let n = extract_archive(&src, &into).unwrap();
            assert_eq!(n, 1, "only the safe entry is written");
            assert!(into.join("bundle/ok.txt").exists());
            assert!(!config_dir().join("escape.txt").exists(), "traversal blocked");
        });
    }
}
