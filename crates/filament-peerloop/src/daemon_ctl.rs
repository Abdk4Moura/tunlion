//! Daemon control-socket work that does not need the CLI's stream server.
//!
//! Part of `cli/src/daemon_ctl.rs` (issue #465 slice 3). What moved here is the
//! half of the control surface whose inputs are already crate-owned: the reach
//! liveness probes, `sshd_listening`, the warm `Ping` and `ListWarm` replies,
//! and the deferred `Bootstrap` reply sockets. Each takes the crate's `Conn`
//! and `control::Req` (the reach ping also takes the calling invocation's
//! `LivenessProbes`) and returns a control-worded answer; the terminal is
//! reached through `Conn::log`, which is the injected `LogSink`.
//!
//! What stayed in the CLI, and why: `handle_warm_req` and the `Open`/`Pty`/
//! `Resize` warm handlers carry `l2::Mux`, and the mount handlers carry the
//! CLI's persistent mount store and spawn sshfs. Neither `l2` nor `mount` is in
//! this crate, and neither is host-bound in the sense the host traits describe,
//! so the honest split is to leave those handlers next to the modules they use
//! rather than drag a 7,000-line tunnel implementation in behind them. The CLI
//! file keeps them and re-exports the items below, so every daemon call site
//! still resolves under `crate::daemon_ctl::`.

use crate::conn::{Conn, warm_link_for};
use crate::control;
use crate::link_manager::peer_present;
use filament_transport::net;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Is something listening on this host's own loopback `port` - i.e. an sshd a
/// `tunlion shell --ssh` initiator could actually reach? A fast connect probe: a
/// successful connect means a listener (we close it at once); refused/timeout
/// means nothing is there. Reported in the shell-bootstrap ack so the initiator
/// fails fast with a clear message instead of ssh hanging on a dead port.
pub async fn sshd_listening(port: u16) -> bool {
    // Probe localhost first (covers the common case: sshd bound to localhost or
    // all interfaces). Then also try ::1 for dual-stack daemons that only bind
    // IPv6 localhost.
    let addrs: [(&str, std::net::SocketAddr); 2] = [
        ("127.0.0.1", (std::net::Ipv4Addr::LOCALHOST, port).into()),
        ("[::1]", (std::net::Ipv6Addr::LOCALHOST, port).into()),
    ];
    let rt = tokio::runtime::Handle::current();
    for (_label, addr) in addrs {
        let ok = rt
            .spawn_blocking(move || {
                std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400))
                    .is_ok()
            })
            .await
            .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

/// Outstanding `reach` liveness probes owned by ONE daemon/control invocation.
///
/// A warm link is only reported once the PEER answers on it, because a link
/// whose far end was stopped or killed -9 stays "alive" locally until QUIC's
/// idle timeout (~22-29 s measured), and reach used to say ok, warm, verified,
/// exit 0 for that whole window.
///
/// This used to be a process-global map plus a process-global nonce counter.
/// Two engines in one process therefore shared waiter state: a `reach-pong`
/// delivered by either receive loop could wake the other engine's probe, and
/// neither engine's shutdown could reap the other's waiters. The registry is
/// now an ordinary value. The owner (the receive/control loop) creates one and
/// passes a `&LivenessProbes` to the ping handler and to the pong arm; clones
/// are cheap handles to the same table, so a spawned probe task can hold its
/// own copy while the loop keeps dispatching.
///
/// Nonces come from a process-wide counter, so a nonce is unique across every
/// registry in the process even though each registry keeps its own waiter
/// table. That is what makes cross-engine delivery safe: the same pong cannot
/// find a waiter in two registries. The woken probe is still narrowed to the
/// peer/link (`pid`) it was sent on, so a pong with a matching number on the
/// wrong link or from the wrong peer is ignored.
#[derive(Clone)]
pub struct LivenessProbes {
    state: std::sync::Arc<LivenessState>,
}

struct LivenessState {
    /// nonce -> the bound waiter. Guarded by `Arc` above: this map belongs to
    /// the invocation, never to the process.
    waiters: std::sync::Mutex<HashMap<u64, Waiter>>,
}

struct Waiter {
    peer: String,
    pid: String,
    tx: tokio::sync::oneshot::Sender<()>,
}

/// Allocate a nonce that no other registry in this process will hand out.
/// The waiter MAP stays invocation-owned; only the number space is shared, so
/// a pong for one engine's probe can never match another engine's waiter.
fn next_liveness_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl Default for LivenessProbes {
    fn default() -> Self {
        Self::new()
    }
}

impl LivenessProbes {
    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(LivenessState {
                waiters: std::sync::Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Register a probe bound to the peer and link pid it is sent on. The
    /// returned waiter owns the table entry: its receiver resolves when the
    /// matching pong arrives, and dropping it (timeout, cancellation, or an
    /// aborted task) removes the entry.
    pub fn register(&self, peer: &str, pid: &str) -> LivenessWait {
        let nonce = next_liveness_nonce();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.state
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                nonce,
                Waiter {
                    peer: peer.to_string(),
                    pid: pid.to_string(),
                    tx,
                },
            );
        LivenessWait {
            probes: self.clone(),
            nonce,
            rx,
        }
    }

    /// A `reach-pong` arrived on link `pid`. Wake its waiter only when the
    /// nonce, the link AND the peer the link names all match; an unknown,
    /// late, peer-mismatched or other-link pong - or one on a link that no
    /// longer names its peer - is ignored and leaves any waiter intact.
    /// Returns whether a live waiter was woken (a send that fails because its
    /// receiver is already gone returns `false`).
    pub fn answered(&self, peer: Option<&str>, pid: &str, pong: &Value) -> bool {
        let Some(nonce) = pong["n"].as_u64() else {
            return false;
        };
        let tx = {
            let mut waiters = self
                .state
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let matches = waiters.get(&nonce).is_some_and(|w| {
                w.pid == pid && peer.is_some_and(|p| w.peer.eq_ignore_ascii_case(p))
            });
            if matches {
                waiters.remove(&nonce).map(|w| w.tx)
            } else {
                None
            }
        };
        tx.is_some_and(|tx| tx.send(()).is_ok())
    }

    /// How many probes this invocation still has outstanding. Observability
    /// for tests and logs; it never reaches the control reply formats.
    pub fn outstanding(&self) -> usize {
        self.state
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    fn forget(&self, nonce: u64) {
        self.state
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&nonce);
    }
}

/// One outstanding probe. Not `Clone`: exactly one task awaits it, and dropping
/// the wait is what unregisters the nonce.
pub struct LivenessWait {
    probes: LivenessProbes,
    nonce: u64,
    rx: tokio::sync::oneshot::Receiver<()>,
}

impl LivenessWait {
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Resolve when the matching pong arrives. A closed channel (the registry
    /// dropped the sender) also returns `false`, never a false positive.
    pub async fn answered(&mut self) -> bool {
        (&mut self.rx).await.is_ok()
    }
}

impl Drop for LivenessWait {
    fn drop(&mut self) {
        self.probes.forget(self.nonce);
    }
}

/// The `reach-ping` a daemon sends on a held link; the peer answers with a
/// `reach-pong` carrying the same `n`. An older peer ignores the unknown type,
/// so its warm link simply does not confirm and reach falls back to the full
/// probe, which works with any version.
// Called only by the unix control socket's warm ping (no control socket
// elsewhere), so other targets see it unused.
#[allow(dead_code)]
pub fn liveness_ping(n: u64) -> Value {
    json!({ "type": "reach-ping", "n": n })
}

/// The answer to a `reach-ping`, echoing its nonce.
pub fn liveness_pong(ping: &Value) -> Value {
    json!({ "type": "reach-pong", "n": ping["n"].clone() })
}

/// How long a warm link has to answer `reach-ping` (TUNLION_REACH_PING_MS,
/// default 1500 ms) before reach treats it as unconfirmed.
// Called only by the unix control socket's warm ping (no control socket
// elsewhere), so other targets see it unused.
#[allow(dead_code)]
pub fn liveness_window() -> Duration {
    let ms = std::env::var("TUNLION_REACH_PING_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1500);
    Duration::from_millis(ms)
}

/// Answer a `tunlion reach`: report the daemon's warm link to `peer` (route,
/// remote address, RTT, verified name). Synchronous - every fact is local (quinn
/// already measured the RTT/addr; the route is the link's own label/ICE state), so
/// nothing is awaited from the peer and the F8 event-loop rule is not in play. A
/// miss `reject`s so the client falls back to a cold establish-probe.
///
/// `probes` is the calling invocation's registry; the pong is routed back to it
/// by the same receive loop, never through process-wide state.
#[cfg(unix)]
pub async fn handle_warm_ping(conn: &Conn, probes: &LivenessProbes, req: control::Req) {
    let control::ReqKind::Ping { peer } = &req.kind else {
        return;
    };
    let peer = peer.clone();
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        req.reject("no warm link").await;
        return;
    };
    // WARM-HOLD: ping succeeded, mark peer as warm (note: we can't call
    // note_warm_use here because conn is &Conn; the warm-hold tick will
    // connect to this peer on the next cycle if it drops)
    let link = conn.link(&pid);
    let direct = link.map(|l| l.direct).unwrap_or(false);
    let route = if direct {
        link.map(|l| l.direct_route.to_string())
            .unwrap_or_else(|| "direct".into())
    } else if let Some(p) = link.and_then(|l| l.peer.clone()) {
        p.route().await.unwrap_or_else(|| "relay".into())
    } else {
        "relay".to_string()
    };
    // Path detail: name the interface the link's local end sits on, classify the
    // remote address, and (for webrtc) report the candidate types + whether the
    // path is relayed. The daemon holds the link AND runs on the same box as the
    // ping client, so it resolves local-ip -> interface locally; ping.rs just
    // renders the fields. This is the data that answers "is it the tailnet?"
    // (e.g. local 100.x on a tailscale0 iface) instead of inferring it.
    let peer_ref = link.and_then(|l| l.peer.clone());
    let path = net::describe_path(t.as_ref(), peer_ref.as_deref())
        .await
        .to_json();
    let mut reply = json!({
        "ok": true,
        "warm": true,
        "direct": direct,
        "route": route,
        "remote_addr": t.remote_addr().map(|a| a.to_string()),
        "rtt_ms": t.rtt_ms(),
        "verified": link.and_then(|l| l.verified_name.clone()),
        "path": path,
    });
    // Confirm the far end is there before saying so: one reach-ping round
    // trip, bounded. Spawned, so the event loop never waits on the peer (F8).
    let mut probe = probes.register(&peer, &pid);
    let sent = t.send_control(&liveness_ping(probe.nonce())).await.is_ok();
    let window = liveness_window();
    let log = conn.log.clone();
    tokio::spawn(async move {
        let t0 = Instant::now();
        let ok = sent && matches!(tokio::time::timeout(window, probe.answered()).await, Ok(true));
        if ok {
            reply["alive_ms"] = json!(t0.elapsed().as_millis() as u64);
            req.reply(&reply).await;
        } else {
            // Drop the waiter before answering so a late pong cannot find it.
            drop(probe);
            log.debug(&format!(
                "reach: warm link to '{peer}' did not answer a liveness ping in {}ms",
                window.as_millis()
            ));
            req.reject("warm link did not answer").await;
        }
    });
}

/// Return only links the daemon already holds. This is deliberately passive:
/// devices listing must never establish, ping, or otherwise wake a peer.
#[cfg(unix)]
pub async fn handle_list_warm(conn: &Conn, req: control::Req) {
    let links: Vec<Value> = conn
        .links
        .iter()
        .filter_map(|(pid, link)| {
            let name = link.verified_name.as_deref()?;
            let transport = link.transport.as_ref()?;
            // `devices` renders "online" from this list, so a link is listed
            // only while its peer is demonstrably there (peer_present): a relay
            // link to a stopped or wiped peer stays `is_alive()` and kept being
            // shown "online, last seen just now".
            if !link.trusted
                || !peer_present(
                    transport.is_alive(),
                    link.direct,
                    transport.heard_ms(),
                    transport.idle_ms(),
                )
            {
                return None;
            }
            Some(json!({
                "name": name,
                "warm": true,
                "direct": link.direct,
                "route": if link.direct { link.direct_route } else { "relay" },
                "remote_addr": transport.remote_addr().map(|a| a.to_string()),
                "rtt_ms": transport.rtt_ms(),
                "verified": name,
                "path": Value::Null,
                "pid": pid,
            }))
        })
        .collect();
    req.reply(&json!({ "ok": true, "links": links })).await;
}

/// Deferred ssh-bootstrap replies, keyed by the peer's link pid. A `Bootstrap`
/// request can't be answered inline: the daemon sends `shell-bootstrap` over the
/// warm link and the peer's `shell-bootstrap-ack` arrives LATER via this same
/// event loop, so blocking here would deadlock. We stash the reply socket (with a
/// deadline) and complete it from the `shell-bootstrap-ack`/`-deny` control arms,
/// or reap it on timeout. A `Vec` per pid handles concurrent ssh to one peer (the
/// ack is identical, so every waiter gets the same answer).
#[cfg(unix)]
pub type PendingBootstraps =
    HashMap<String, Vec<(tokio::net::UnixStream, std::time::Instant)>>;

/// DEBUG: dump every link's warm-reuse eligibility so a miss-despite-a-live-link
/// is diagnosable (visible at `-v` / TUNLION_LOG=debug only).
#[cfg(unix)]
pub fn log_warm_miss(conn: &Conn, peer: &str) {
    for (p, l) in conn.links.iter() {
        conn.log.debug(&format!(
            "warm-miss '{peer}': pid={p} name={:?} verified={:?} trusted={} has_transport={} alive={} direct={}",
            l.name,
            l.verified_name,
            l.trusted,
            l.transport.is_some(),
            l.transport.as_ref().map(|t| t.is_alive()).unwrap_or(false),
            l.direct,
        ));
    }
}

/// Warm-reuse the ssh `shell-bootstrap`: install the client's managed `pubkey` on
/// `peer` over the daemon's EXISTING link instead of a fresh cold establish, the
/// big win for `tunlion shell --ssh` (pty already rode the warm link; the bootstrap was
/// the last cold-establish left). Sends `shell-bootstrap` and STASHES the reply
/// socket; the ack/deny handler completes it. A miss falls the client back to the
/// cold `shell_bootstrap`.
#[cfg(unix)]
pub async fn handle_warm_bootstrap(
    conn: &Conn,
    pending: &mut PendingBootstraps,
    req: control::Req,
) {
    let (peer, pubkey, ssh_port) = match &req.kind {
        control::ReqKind::Bootstrap {
            peer,
            pubkey,
            ssh_port,
        } => (peer.clone(), pubkey.clone(), *ssh_port),
        _ => return,
    };
    let Some((pid, t)) = warm_link_for(conn, &peer) else {
        log_warm_miss(conn, &peer);
        req.reject("no warm link to that peer").await;
        return;
    };
    if t.send_control(
        &json!({ "type": "shell-bootstrap", "v": 1, "pubkey": pubkey, "ssh_port": ssh_port }),
    )
    .await
    .is_err()
    {
        req.reject("warm link send failed").await;
        return;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    pending.entry(pid).or_default().push((req.sock, deadline));
}

/// Complete every stashed `Bootstrap` waiter for `pid` with `reply`. Called from
/// the `shell-bootstrap-ack`/`-deny` arms; a no-op if none are pending (e.g. the
/// peer re-acked, or the waiter was already reaped).
#[cfg(unix)]
pub async fn complete_warm_bootstrap(
    pending: &mut PendingBootstraps,
    pid: &str,
    reply: &Value,
) {
    if let Some(waiters) = pending.remove(pid) {
        for (mut sock, _) in waiters {
            control::send_reply(&mut sock, reply).await;
        }
    }
}

/// Drop expired bootstrap waiters (peer never answered): closing the socket gives
/// the client an EOF, which it reads as a miss and falls back to the cold path.
#[cfg(unix)]
pub fn reap_warm_bootstraps(pending: &mut PendingBootstraps) {
    if pending.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    for waiters in pending.values_mut() {
        waiters.retain(|(_, deadline)| *deadline > now);
    }
    pending.retain(|_, waiters| !waiters.is_empty());
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    fn pong_reply(nonce: u64) -> Value {
        json!({ "type": "reach-pong", "n": nonce })
    }

    /// A pong echoing the ping's nonce wakes exactly that probe; a stray or
    /// late pong wakes nothing.
    #[tokio::test]
    async fn a_pong_answers_its_own_ping_only() {
        let probes = LivenessProbes::new();
        let mut first = probes.register("alice", "pid-a");
        let mut second = probes.register("alice", "pid-a");
        let n = first.nonce();
        let ping = liveness_ping(n);
        assert_eq!(ping["type"], json!("reach-ping"));
        let pong = liveness_pong(&ping);
        assert_eq!(pong, json!({ "type": "reach-pong", "n": n }));
        assert!(probes.answered(Some("alice"), "pid-a", &pong));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), first.answered()).await,
            Ok(true)
        ));
        assert!(
            !probes.answered(Some("alice"), "pid-a", &pong),
            "a pong answers one waiter, never a second probe"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second.answered())
                .await
                .is_err(),
            "probe {} must still be waiting",
            second.nonce()
        );
        assert_eq!(probes.outstanding(), 1);
        assert!(!probes.answered(Some("alice"), "pid-a", &pong_reply(999_999_999)));
        assert!(!probes.answered(Some("alice"), "pid-a", &json!({ "type": "reach-pong" })));
        assert!(!probes.answered(Some("alice"), "pid-a", &pong_reply(0)));
        assert_eq!(probes.outstanding(), 1);
        assert!(liveness_window() >= Duration::from_millis(1));
    }

    /// A probe belongs to the peer and link it was sent on. A pong carrying the
    /// right nonce but delivered for another peer, another link, or a link with
    /// no peer identity left leaves the waiter intact.
    #[tokio::test]
    async fn a_pong_must_match_the_bound_peer_and_link() {
        let probes = LivenessProbes::new();
        let mut wait = probes.register("Alice", "pid-a");
        let pong = pong_reply(wait.nonce());
        assert!(
            !probes.answered(Some("bob"), "pid-a", &pong),
            "another peer's pong must not complete this probe"
        );
        assert!(
            !probes.answered(Some("alice"), "pid-b", &pong),
            "the same nonce on another link must not complete this probe"
        );
        assert!(
            !probes.answered(None, "pid-a", &pong),
            "a link that no longer names its peer cannot confirm a probe"
        );
        assert_eq!(probes.outstanding(), 1);
        assert!(
            probes.answered(Some("alice"), "pid-a", &pong),
            "peer names match case-insensitively, exactly as warm selection does"
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), wait.answered()).await,
            Ok(true)
        ));
        assert_eq!(probes.outstanding(), 0);
    }

    /// Two engines in one process each own a registry, and probe nonces are
    /// unique across both. A pong is therefore accepted by at most one
    /// registry; delivering it to the other one is rejected and leaves the
    /// first engine's probe outstanding.
    #[tokio::test]
    async fn same_process_registries_are_isolated() {
        let engine_a = LivenessProbes::new();
        let engine_b = LivenessProbes::new();
        let mut probe_a = engine_a.register("alice", "pid-a");
        let mut probe_b = engine_b.register("alice", "pid-a");
        assert_ne!(
            probe_a.nonce(),
            probe_b.nonce(),
            "nonces must be unique across registry instances"
        );
        let pong_a = pong_reply(probe_a.nonce());
        let pong_b = pong_reply(probe_b.nonce());

        // B's pong is foreign to A: it matches no waiter there.
        assert!(!engine_a.answered(Some("alice"), "pid-a", &pong_b));
        assert_eq!(engine_a.outstanding(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), probe_a.answered())
                .await
                .is_err(),
            "B's pong must not complete A's probe"
        );

        // B's own registry accepts it; A is still outstanding.
        assert!(engine_b.answered(Some("alice"), "pid-a", &pong_b));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), probe_b.answered()).await,
            Ok(true)
        ));
        assert_eq!(engine_b.outstanding(), 0);
        assert_eq!(engine_a.outstanding(), 1);

        // A's pong is foreign to B for the same reason.
        assert!(!engine_b.answered(Some("alice"), "pid-a", &pong_a));

        // A's own registry accepts it; only now does A wake.
        assert!(engine_a.answered(Some("alice"), "pid-a", &pong_a));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), probe_a.answered()).await,
            Ok(true)
        ));
        assert_eq!(engine_a.outstanding(), 0);
    }

    /// Dropping a waiter (timeout, cancellation, task teardown) unregisters it;
    /// a pong that arrives afterwards finds nothing.
    #[tokio::test]
    async fn dropping_a_waiter_forgets_the_probe() {
        let probes = LivenessProbes::new();
        let wait = probes.register("alice", "pid-a");
        let n = wait.nonce();
        drop(wait);
        assert_eq!(probes.outstanding(), 0);
        assert!(
            !probes.answered(Some("alice"), "pid-a", &pong_reply(n)),
            "a late pong cannot wake a dropped waiter"
        );
    }

    /// Letting the probe time out and dropping the wait leaves no entry behind.
    #[tokio::test]
    async fn a_timed_out_probe_leaves_no_waiter() {
        let probes = LivenessProbes::new();
        let mut wait = probes.register("alice", "pid-a");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wait.answered())
                .await
                .is_err(),
            "silence must never confirm a probe"
        );
        drop(wait);
        assert_eq!(probes.outstanding(), 0);
    }

    /// Cancelling the task that owns a probe drops its waiter too (the pattern
    /// `handle_warm_ping` relies on when its spawned task goes away).
    #[tokio::test]
    async fn cancelling_the_probe_task_forgets_the_probe() {
        let probes = LivenessProbes::new();
        let wait = probes.register("alice", "pid-a");
        let held = tokio::spawn(async move {
            let _wait = wait;
            std::future::pending::<()>().await;
        });
        assert_eq!(probes.outstanding(), 1);
        held.abort();
        let _ = held.await;
        assert_eq!(probes.outstanding(), 0);
    }
}
