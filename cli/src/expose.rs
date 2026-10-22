//! `tunlion expose <port>`: publish a local service on this device's L3 overlay
//! address so paired peers reach it at `<this-device>.mesh:<port>`, like a
//! Tailscale-served port. The daemon binds the overlay address (a ULA reachable
//! only over tunlion0) and splices each connection to a local target; nothing is
//! exposed on any public or LAN interface. Config lives in `expose.json` next to
//! the other settings and is applied to the running daemon over the control
//! socket (no restart), mirroring `tunlion set`.
//!
//! Access control: a connection can only arrive over tunlion0 from a paired,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Where the daemon records the exposed ports it actually BOUND, so `status`
/// reports what is served rather than what `expose.json` asks for. The two
/// differ whenever a bind failed or no overlay is up.
fn bound_path() -> PathBuf {
    crate::settings::config_dir().join("expose-bound.json")
}

/// What the daemon with pid `daemon` has recorded: the ports it actually BOUND
/// and, per port, why a bind failed. Empty/ignored when no daemon runs, or when
/// the record was written by another process (a daemon that is gone serves
/// nothing, whatever its last record says).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundState {
    pub ports: Vec<u16>,
    /// The exact Binding each bound port currently serves. The port alone is not
    /// enough: `expose 8080 --to newtarget` replaces an existing listener, and an
    /// old record for :8080 must never satisfy the new request.
    pub bindings: std::collections::HashMap<u16, Binding>,
    pub errors: std::collections::HashMap<u16, String>,
}

pub fn bound_state(daemon: Option<u32>) -> BoundState {
    let Some(pid) = daemon else { return BoundState::default() };
    let Some(v) = std::fs::read_to_string(bound_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    else {
        return BoundState::default();
    };
    if v["pid"].as_u64() != Some(u64::from(pid)) {
        return BoundState::default();
    }
    let ports = v["ports"]
        .as_array()
        .map(|a| a.iter().filter_map(|p| p.as_u64().and_then(|n| u16::try_from(n).ok())).collect())
        .unwrap_or_default();
    let bindings = v["bindings"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, b)| {
                    Some((k.parse::<u16>().ok()?, serde_json::from_value::<Binding>(b.clone()).ok()?))
                })
                .collect()
        })
        .unwrap_or_default();
    let errors = v["errors"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, why)| {
                    Some((k.parse::<u16>().ok()?, why.as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    BoundState { ports, bindings, errors }
}

/// The ports the daemon has recorded as bound.
pub fn bound_ports(daemon: Option<u32>) -> Vec<u16> {
    bound_state(daemon).ports
}

fn save(bindings: &[Binding]) -> Result<()> {
    let p = expose_path();
    // Atomic replace (SecretFile also creates the directory, owner-only) so a concurrent daemon read never sees a half-written file.
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(bindings)?)?;
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

/// `tunlion expose [<port>] [--to <host:port>] [--peer a,b] [--list]`.
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

    let binding = Binding { port, target: target.clone(), peers: peers.clone() };
    let mut cfg = load();
    cfg.retain(|b| b.port != port);
    cfg.push(binding.clone());
    cfg.sort_by_key(|b| b.port);
    save(&cfg)?;

    // Bind BEFORE saying success. `expose.json` is a REQUEST; only the daemon's
    // `expose-bound.json` is evidence that a listener exists. This command used
    // to print the success glyph right after writing the request, so an
    // automation saw "done" while `expose --list` (and every dial) had nothing.
    let Some(daemon) = crate::daemon_alive() else {
        return Err(anyhow::anyhow!(
            "expose :{port} was saved but NOT bound: there is no running tunlion daemon, so no \
             live L3 endpoint can bind it. Start one with `tunlion up` (or `tunlion up --userspace` \
             when this host has no usable TUN) and run `tunlion expose {port}` again."
        ));
    };

    // The unix control socket is a fast wake; the bound record is the truth on
    // every platform (Windows has no control socket).
    notify_daemon().await;
    let state = wait_for_bind(daemon, &binding, std::time::Duration::from_secs(6)).await;
    match state {
        BindOutcome::Bound => {
            ui::say(&format!(
                "  {} expose :{port} {} {}  ({}) {}",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                ui::glyph_arrow(),
                target,
                scope_str(&peers),
                ui::paint(ui::Tone::Dim, &format!("[bound on the overlay, daemon pid {daemon}]")),
            ));
            // Without a TUN, peers reach this port as <this-device>.mesh through
            // their SOCKS proxy, and this side reaches theirs the same way; say how.
            if let Some(p) = crate::proxy_state::current() {
                ui::say(&crate::proxy_state::mesh_hint(&p));
            }
            Ok(())
        }
        BindOutcome::Failed(why) => Err(anyhow::anyhow!(
            "expose :{port} failed to bind on the overlay: {why}. It was saved in expose.json and \
             will be retried when the daemon next reconciles; fix the cause and rerun `tunlion expose {port}`."
        )),
        BindOutcome::NoEndpoint => {
            let l3 = crate::l3_state::current().await;
            let reason = l3["reason"].as_str().unwrap_or("no live L3 endpoint");
            let mode = l3["mode"].as_str().unwrap_or("none");
            Err(anyhow::anyhow!(
                "expose :{port} was saved but NOT bound: the daemon has no live L3 endpoint \
                 (state={}, mode={mode}). {reason}. Start L3 with `tunlion set tun-addr auto` and \
                 `tunlion up` (or `tunlion up --userspace` when no TUN is available), then rerun \
                 `tunlion expose {port}`.",
                l3["state"].as_str().unwrap_or("down"),
            ))
        }
        BindOutcome::TimedOut => Err(anyhow::anyhow!(
            "expose :{port} was saved but NOT bound within 6s: the daemon (pid {daemon}) did not \
             report a listener. Check `tunlion expose --list` and the daemon log; an L3 endpoint \
             that is not ready cannot bind, and this command will not claim it did."
        )),
    }
}

/// The result of waiting for the daemon to bind one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    Bound,
    Failed(String),
    /// The daemon answered but has no live L3 endpoint at all.
    NoEndpoint,
    TimedOut,
}

/// Decide from the daemon's record. Pure, so every branch is testable without
/// a listener. The EXACT binding must be present: an old listener on the same
/// port (a replaced target) is not this request's proof.
pub fn classify_bind(state: &BoundState, want: &Binding, l3_ready: bool) -> BindOutcome {
    // LIVE ENDPOINT FIRST. A stale bound record (a previous daemon incarnation,
    // or a listener from before L3 went away) must never turn a saved-only
    // request into success. `ready` is the daemon's own proof that bind/dial can
    // work; the record alone is history.
    if !l3_ready {
        return BindOutcome::NoEndpoint;
    }
    if state.bindings.get(&want.port) == Some(want) {
        return BindOutcome::Bound;
    }
    if let Some(why) = state.errors.get(&want.port) {
        return BindOutcome::Failed(why.clone());
    }
    BindOutcome::TimedOut
}

/// Poll the daemon's bound record until THIS binding is bound or failed. The
/// daemon reconciles expose.json on a 1s tick (and immediately on the unix
/// control socket), so this is a short wait, not the source of truth.
pub async fn wait_for_bind(
    daemon: u32,
    want: &Binding,
    timeout: std::time::Duration,
) -> BindOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let state = bound_state(Some(daemon));
        let l3_ready = crate::l3_state::is_ready(&crate::l3_state::read_file_for(Some(daemon)));
        let outcome = classify_bind(&state, want, l3_ready);
        if outcome != BindOutcome::TimedOut || tokio::time::Instant::now() >= deadline {
            return outcome;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// `tunlion unexpose <port>`.
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
        ui::say(&ui::paint(ui::Tone::Dim, "  no ports exposed. try: tunlion expose 8080"));
        return Ok(());
    }
    let daemon = crate::daemon_alive();
    let state = bound_state(daemon);
    ui::say("  exposed on this device's .mesh address:");
    for b in cfg {
        // Distinguish REQUESTED from SERVED. Printing "exposed" for a port that
        // never bound is what let addr+expose look trustworthy with no endpoint.
        let mark = if state.bindings.get(&b.port) == Some(&b) {
            ui::paint(ui::Tone::Ok, "[bound]").to_string()
        } else if let Some(why) = state.errors.get(&b.port) {
            ui::paint(ui::Tone::Err, &format!("[NOT bound: {why}]")).to_string()
        } else if daemon.is_none() {
            ui::paint(ui::Tone::Warn, "[NOT bound: no running daemon]").to_string()
        } else if state.bindings.contains_key(&b.port) {
            ui::paint(ui::Tone::Warn, "[NOT bound: old target still serving]").to_string()
        } else {
            ui::paint(ui::Tone::Warn, "[NOT bound: no live L3 endpoint]").to_string()
        };
        ui::say(&format!(
            "    :{} {} {}  ({}) {mark}",
            b.port,
            ui::glyph_arrow(),
            b.target,
            scope_str(&b.peers)
        ));
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
                    "  saved; the daemon has no L3 overlay up (run: tunlion set tun-addr auto, then tunlion up)",
                ));
                return;
            }
            None => {}
        }
    }
    ui::say(&ui::paint(ui::Tone::Dim, "  saved; takes effect on next `tunlion up`"));
}

// -------------------------------------------------------------- daemon side --
// The actual listeners live in the daemon and bind the overlay address, so they
// need the L3 manager, which is Linux-only (the TUN overlay is Linux-only).

#[cfg(l3)]
pub use imp::Exposer;

#[cfg(l3)]
mod imp {
    use super::{load, Binding};
    use anyhow::Result;
    use filament_peerloop::mesh::{MeshListener, MeshTunnel};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    /// Record the ports THIS daemon has bound right now, plus why any requested
    /// port failed (see `bound_state`). An error is evidence, not a log line: the
    /// `expose` command reads it to fail loudly instead of claiming success.
    fn record_bound(ports: &[u16], bindings: &HashMap<u16, Binding>, errors: &HashMap<u16, String>) {
        let v = serde_json::json!({
            "pid": std::process::id(),
            "ports": ports,
            "bindings": bindings,
            "errors": errors,
        });
        if let Err(e) = crate::platform::SecretFile::write_str(&super::bound_path(), &v.to_string()) {
            crate::ui::debug(&format!("tunlion: could not record the bound expose ports: {e}"));
        }
    }

    /// Owns the live overlay listeners (one per exposed port) and reconciles them
    /// against `expose.json` on demand. Keyed by port; each value pairs the binding
    /// that spawned the listener (to detect changes) with its task handle.
    pub struct Exposer {
        l3: Arc<dyn MeshTunnel>,
        active: Mutex<HashMap<u16, (Binding, JoinHandle<()>)>>,
    }

    impl Exposer {
        pub fn new(l3: Arc<dyn MeshTunnel>) -> Arc<Exposer> {
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
            let mut errors: HashMap<u16, String> = HashMap::new();
            for (port, b) in want {
                if active.contains_key(&port) {
                    continue;
                }
                match self.clone().spawn(b.clone()).await {
                    Ok(jh) => {
                        active.insert(port, (b, jh));
                    }
                    Err(e) => {
                        let why = e.to_string();
                        crate::ui::say(&crate::ui::paint(
                            crate::ui::Tone::Warn,
                            &format!("  expose :{port} failed: {why}"),
                        ));
                        errors.insert(port, why);
                    }
                }
            }
            let mut ports: Vec<u16> = active.keys().copied().collect();
            ports.sort_unstable();
            let bindings: HashMap<u16, Binding> =
                active.iter().map(|(p, (b, _))| (*p, b.clone())).collect();
            record_bound(&ports, &bindings, &errors);
            active.len()
        }

        async fn spawn(self: Arc<Self>, b: Binding) -> Result<JoinHandle<()>> {
            // Mode-agnostic listen on the overlay: a kernel TcpListener bound on the
            // overlay IP, or the userspace smoltcp listener (TUN-free). The accept +
            // splice below is identical either way.
            let listener = self
                .l3
                .bind(b.port)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
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
                    if !me.allowed(&b, src).await {
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

    /// The bug this closes: a saved request with no endpoint used to print
    /// success. No bound port and no live L3 is an explicit no-endpoint, never
    /// "bound" and never a silent success.
    #[test]
    fn a_request_that_did_not_bind_is_never_reported_as_bound() {
        let want = Binding { port: 9110, target: "127.0.0.1:9110".into(), peers: None };
        let empty = BoundState::default();
        assert_eq!(classify_bind(&empty, &want, false), BindOutcome::NoEndpoint);
        assert_eq!(classify_bind(&empty, &want, true), BindOutcome::TimedOut);
        let bound = BoundState {
            ports: vec![9110],
            bindings: [(9110, want.clone())].into_iter().collect(),
            errors: Default::default(),
        };
        assert_eq!(classify_bind(&bound, &want, true), BindOutcome::Bound);
        // A bound RECORD is not enough when the endpoint is gone: this is the
        // Windows saved-but-NOT-bound case, and it must be a failure.
        assert_eq!(
            classify_bind(&bound, &want, false),
            BindOutcome::NoEndpoint,
            "a stale bind record must never mask a down L3 endpoint"
        );
        let refused = BoundState {
            ports: vec![],
            bindings: Default::default(),
            errors: [(
                9110,
                "address already in use (os error 98)".to_string(),
            )]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            classify_bind(&refused, &want, true),
            BindOutcome::Failed("address already in use (os error 98)".to_string())
        );
        // A different port's failure must not fail this one.
        let other = Binding { port: 9111, ..want.clone() };
        assert_eq!(classify_bind(&refused, &other, true), BindOutcome::TimedOut);
    }

    fn write_bound(pid: u32, bindings: &[Binding], errors: &[(u16, &str)]) {
        let bmap: std::collections::HashMap<String, Binding> =
            bindings.iter().map(|b| (b.port.to_string(), b.clone())).collect();
        let emap: std::collections::HashMap<String, String> = errors
            .iter()
            .map(|(p, e)| (p.to_string(), (*e).to_string()))
            .collect();
        let ports: Vec<u16> = bindings.iter().map(|b| b.port).collect();
        let v = serde_json::json!({
            "pid": pid,
            "ports": ports,
            "bindings": bmap,
            "errors": emap,
        });
        crate::platform::SecretFile::write_str(&super::bound_path(), &v.to_string()).unwrap();
    }

    struct Restore(Option<std::ffi::OsString>, std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                match self.0.take() {
                    Some(v) => std::env::set_var("TUNLION_CONFIG_DIR", v),
                    None => std::env::remove_var("TUNLION_CONFIG_DIR"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    /// Replacing an already-bound port must not be satisfied by the OLD binding.
    /// Both apply paths end in `wait_for_bind`: the control socket asks the
    /// daemon immediately, and Windows waits for the 1s tick. The record is the
    /// same, so the old (port,target) pair is never proof for the new one.
    #[tokio::test]
    async fn replacing_a_bound_port_ignores_the_old_binding_on_both_apply_paths() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!("tunlion-expose-rev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("TUNLION_CONFIG_DIR");
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
        let _restore = Restore(previous, dir);

        let pid = std::process::id();
        crate::l3_state::write(&filament_peerloop::mesh::L3Status::ready("userspace"));
        let old = Binding { port: 8080, target: "127.0.0.1:8080".into(), peers: None };
        let new = Binding { port: 8080, target: "127.0.0.1:9090".into(), peers: None };
        write_bound(pid, &[old.clone()], &[]);

        // Control-socket path: an immediate reply carrying only the old binding
        // is still not proof. This is the record a fast `reload-expose` sees
        // before the Exposer has swapped the listener.
        assert_eq!(
            classify_bind(&bound_state(Some(pid)), &new, true),
            BindOutcome::TimedOut,
            "the old target on :8080 must not report the new target as bound"
        );

        // Windows-tick path: the daemon swaps the listener and rewrites the
        // record on its next reconcile. Only then may the command say BOUND.
        let new_for_tick = new.clone();
        let updater = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            write_bound(pid, &[new_for_tick], &[]);
        });
        let started = tokio::time::Instant::now();
        let outcome = wait_for_bind(pid, &new, std::time::Duration::from_secs(2)).await;
        updater.await.unwrap();
        assert_eq!(outcome, BindOutcome::Bound);
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(150),
            "must wait for the new binding, not accept the old one"
        );
        assert_eq!(classify_bind(&bound_state(Some(pid)), &new, true), BindOutcome::Bound);
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
