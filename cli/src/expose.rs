//! `filament expose <port>`: publish a local service on this device's L3 overlay
//! address so paired peers reach it at `<this-device>.mesh:<port>`, like a
//! Tailscale-served port. The daemon binds the overlay address (a ULA reachable
//! only over filament0) and splices each connection to a local target; nothing is
//! exposed on any public or LAN interface. Config lives in `expose.json` next to
//! the other settings and is applied to the running daemon over the control
//! socket (no restart), mirroring `filament set`.
//!
//! Access control: a connection can only arrive over filament0 from a paired,
//! verified peer, so mesh membership is the primary boundary; `--peer` narrows it
//! further to named devices. (A malicious paired peer could still forge an inner
//! source address, so the allowlist is a convenience layer, not a hard boundary
//! against peers you have already paired with.)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ui;

/// One exposed port: listen on the overlay `port`, forward to `target`
/// (`host:port`), optionally restricted to `peers` (petnames; `None`/empty = any
/// paired device).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub port: u16,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<String>>,
}

fn expose_path() -> PathBuf {
    crate::settings::config_dir().join("expose.json")
}

/// Read the persisted bindings; a missing or unparseable file is an empty set.
pub fn load() -> Vec<Binding> {
    std::fs::read_to_string(expose_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(bindings: &[Binding]) -> Result<()> {
    let p = expose_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    // Atomic replace so a concurrent daemon read never sees a half-written file.
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(bindings)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// `--to` resolves to a `host:port` target: absent => `127.0.0.1:<port>`; a bare
/// number => `127.0.0.1:<number>`; a bare host => `<host>:<port>`; otherwise the
/// verbatim `host:port`.
fn resolve_target(port: u16, to: &Option<String>) -> String {
    match to {
        None => format!("127.0.0.1:{port}"),
        Some(s) => {
            if let Ok(p) = s.parse::<u16>() {
                format!("127.0.0.1:{p}")
            } else if s.contains(':') {
                s.clone()
            } else {
                format!("{s}:{port}")
            }
        }
    }
}

fn scope_str(peers: &Option<Vec<String>>) -> String {
    match peers {
        Some(p) if !p.is_empty() => p.join(","),
        _ => "any paired device".into(),
    }
}

/// `filament expose [<port>] [--to <host:port>] [--peer a,b] [--list]`.
pub async fn expose_cmd(
    port: Option<u16>,
    to: Option<String>,
    peers: Vec<String>,
    list: bool,
) -> Result<()> {
    if list || port.is_none() {
        return print_list();
    }
    let port = port.unwrap();
    let target = resolve_target(port, &to);
    let peers = (!peers.is_empty()).then_some(peers);

    let mut cfg = load();
    cfg.retain(|b| b.port != port);
    cfg.push(Binding { port, target: target.clone(), peers: peers.clone() });
    cfg.sort_by_key(|b| b.port);
    save(&cfg)?;

    ui::say(&format!(
        "  {} expose :{port} {} {}  ({})",
        ui::paint(ui::Tone::Ok, ui::glyph_ok()),
        ui::glyph_arrow(),
        target,
        scope_str(&peers),
    ));
    notify_daemon().await;
    Ok(())
}

/// `filament unexpose <port>`.
pub async fn unexpose_cmd(port: u16) -> Result<()> {
    let mut cfg = load();
    let before = cfg.len();
    cfg.retain(|b| b.port != port);
    if cfg.len() == before {
        ui::say(&ui::paint(ui::Tone::Dim, &format!("  :{port} was not exposed")));
        return Ok(());
    }
    save(&cfg)?;
    ui::say(&format!("  {} stopped exposing :{port}", ui::paint(ui::Tone::Ok, ui::glyph_ok())));
    notify_daemon().await;
    Ok(())
}

fn print_list() -> Result<()> {
    let cfg = load();
    if cfg.is_empty() {
        ui::say(&ui::paint(ui::Tone::Dim, "  no ports exposed. try: filament expose 8080"));
        return Ok(());
    }
    ui::say("  exposed on this device's .mesh address:");
    for b in cfg {
        ui::say(&format!("    :{} {} {}  ({})", b.port, ui::glyph_arrow(), b.target, scope_str(&b.peers)));
    }
    Ok(())
}

/// Push the change to the running daemon; fall back to a clear "next up" note.
async fn notify_daemon() {
    #[cfg(unix)]
    {
        match crate::ctl::try_reload_expose().await {
            Some(v) if v["live"].as_bool() == Some(true) => {
                let n = v["count"].as_u64().unwrap_or(0);
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    &format!("  applied to the running daemon ({n} port(s) bound on the overlay)"),
                ));
                return;
            }
            Some(_) => {
                ui::say(&ui::paint(
                    ui::Tone::Dim,
                    "  saved; the daemon has no L3 overlay up (run: filament set tun-addr auto, then filament up)",
                ));
                return;
            }
            None => {}
        }
    }
    ui::say(&ui::paint(ui::Tone::Dim, "  saved; takes effect on next `filament up`"));
}

// -------------------------------------------------------------- daemon side --
// The actual listeners live in the daemon and bind the overlay address, so they
// need the L3 manager, which is Linux-only (the TUN overlay is Linux-only).

#[cfg(l3)]
pub use imp::Exposer;

#[cfg(l3)]
mod imp {
    use super::{load, Binding};
    use crate::l3::L3;
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    /// Owns the live overlay listeners (one per exposed port) and reconciles them
    /// against `expose.json` on demand. Keyed by port; each value pairs the binding
    /// that spawned the listener (to detect changes) with its task handle.
    pub struct Exposer {
        l3: Arc<L3>,
        active: Mutex<HashMap<u16, (Binding, JoinHandle<()>)>>,
    }

    impl Exposer {
        pub fn new(l3: Arc<L3>) -> Arc<Exposer> {
            Arc::new(Exposer { l3, active: Mutex::new(HashMap::new()) })
        }

        /// Differential reconcile against `expose.json`: leave unchanged ports
        /// serving untouched, drop removed/changed ones (awaiting each task's exit
        /// so its socket is released before any rebind on the same port), then bind
        /// the new/changed ones. In-flight proxied connections are separate tasks
        /// and survive. Returns the port count now bound.
        pub async fn reconcile(self: &Arc<Self>) -> usize {
            let want: HashMap<u16, Binding> = load().into_iter().map(|b| (b.port, b)).collect();
            let mut active = self.active.lock().await;
            // Drop listeners that are gone or whose binding changed. AWAIT the task
            // after abort so the listening socket is fully closed before we might
            // rebind the same overlay addr:port below (abort alone is async, so an
            // immediate rebind would race and fail with "address in use").
            let stale: Vec<u16> = active
                .iter()
                .filter(|(p, (b, _))| want.get(p) != Some(b))
                .map(|(p, _)| *p)
                .collect();
            for p in stale {
                if let Some((_, jh)) = active.remove(&p) {
                    jh.abort();
                    let _ = jh.await;
                }
            }
            // Bind the ports that are new or changed (unchanged ones are still in
            // `active` and were skipped above).
            for (port, b) in want {
                if active.contains_key(&port) {
                    continue;
                }
                match self.clone().spawn(b.clone()).await {
                    Ok(jh) => {
                        active.insert(port, (b, jh));
                    }
                    Err(e) => crate::ui::say(&crate::ui::paint(
                        crate::ui::Tone::Warn,
                        &format!("  expose :{port} failed: {e}"),
                    )),
                }
            }
            active.len()
        }

        async fn spawn(self: Arc<Self>, b: Binding) -> Result<JoinHandle<()>> {
            let addr = self.l3.my_addr().context("L3 overlay is not up")?;
            let bind = SocketAddr::new(IpAddr::V6(addr), b.port);
            let listener = TcpListener::bind(bind)
                .await
                .with_context(|| format!("bind [{addr}]:{}", b.port))?;
            let me = self.clone();
            let jh = tokio::spawn(async move {
                loop {
                    let (mut inbound, src) = match listener.accept().await {
                        Ok(x) => x,
                        // Transient accept error (fd pressure): back off, keep serving.
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                    };
                    if !me.allowed(&b, src.ip()).await {
                        continue; // not a permitted peer; drop
                    }
                    let target = b.target.clone();
                    tokio::spawn(async move {
                        if let Ok(mut up) = TcpStream::connect(&target).await {
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut up).await;
                        }
                        // target down => connection drops (clean refused to the peer)
                    });
                }
            });
            Ok(jh)
        }

        /// A connection is allowed iff its source is a verified overlay peer and,
        /// when an allowlist is set, that peer's petname is in it.
        async fn allowed(&self, b: &Binding, src: IpAddr) -> bool {
            if !self.l3.is_verified_peer(src).await {
                return false;
            }
            match &b.peers {
                None => true,
                Some(list) if list.is_empty() => true,
                Some(list) => match self.l3.petname_of(src).await {
                    Some(name) => list.iter().any(|p| p == &name),
                    None => false,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_resolution() {
        assert_eq!(resolve_target(8080, &None), "127.0.0.1:8080");
        assert_eq!(resolve_target(8080, &Some("9090".into())), "127.0.0.1:9090");
        assert_eq!(resolve_target(8080, &Some("100.95.104.36:8080".into())), "100.95.104.36:8080");
        assert_eq!(resolve_target(8080, &Some("myhost".into())), "myhost:8080");
        assert_eq!(resolve_target(22, &Some("[fdf1::1]:22".into())), "[fdf1::1]:22");
    }

    #[test]
    fn scope_rendering() {
        assert_eq!(scope_str(&None), "any paired device");
        assert_eq!(scope_str(&Some(vec![])), "any paired device");
        assert_eq!(scope_str(&Some(vec!["a".into(), "b".into()])), "a,b");
    }

    #[test]
    fn binding_roundtrips_json() {
        let b = Binding { port: 8080, target: "127.0.0.1:8080".into(), peers: Some(vec!["dovm".into()]) };
        let s = serde_json::to_string(&b).unwrap();
        let back: Binding = serde_json::from_str(&s).unwrap();
        assert_eq!(back.port, 8080);
        assert_eq!(back.target, "127.0.0.1:8080");
        assert_eq!(back.peers.as_deref(), Some(&["dovm".to_string()][..]));
    }
}
