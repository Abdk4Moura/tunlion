//! The receive dispatch: the one production event loop.
//!
//! This file is the moved body of the CLI's former `recv_run`. It is library
//! code now: the event match, the link/transfer state machine, consent,
//! completion, reconnect and cleanup are all owned here. The CLI adapter
//! (`cli/src/recv_cmd.rs`) resolves process policy, installs signals, builds a
//! [`RecvPorts`], starts the engine and maps the outcome to an exit code.
//!
//! The rule is the crate's rule: the loop never calls the CLI. Machine facts
//! arrive through [`HostServices`](crate::host::HostServices), terminal state
//! through [`Presentation`](crate::present::Presentation), lines through
//! [`LogSink`](crate::host::LogSink), and the remaining host-bound sectors
//! through the narrow traits in [`crate::recv::ports`].

use crate::adoption::AdoptSource;
use crate::conn::{Conn, DigestSurface, Presence, Promotion, Rung};
use crate::consent::REQUEST_WITHDRAWN;
use crate::control::{Req, ReqKind};
use crate::daemon_ctl::sshd_listening;
use crate::driver::DriverOutcome;
use crate::host::{CapGate, HostServices, Level, LogSink, StorageFailure, Tone};
use crate::l2::{self, Mux};
use crate::limits::MAX_ATTEMPTS;
#[cfg(feature = "mesh")]
use crate::mesh::{
    accept_advertised, advertised_prefixes, sanitize_host, L3Mode, RouteAcceptance, RoutePolicy,
    IFNAME,
};
use crate::present::{Ask, Presentation};
use crate::recv::ceremony::{Ceremony, Inbound as PakeInbound};
use crate::recv::ports::{RecvDaemon, RecvPorts, RecvServers};
use crate::recv::report::{RecvReport, RefusalClass};
use crate::recv::signaling_health;
use crate::recv::MeshTunnel;
use crate::recv::{IncomingFile, PartMeta, StdoutSink, WriteFailure};
use crate::refusal::Code as RefusalCode;
use crate::secret::fresh_secret;
use crate::session::Session;
use crate::shell::ShellHost;
use crate::shell_gate::PeerAuthz;
use crate::shell_gate::ShellPolicy;
use crate::{refusal, test_hooks};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use filament_cap::capability as cap;
#[cfg(feature = "fleet")]
use filament_fleet as fleet;
use filament_id as identity;
#[cfg(feature = "mesh")]
use filament_overlay::Announce;
#[cfg(feature = "mesh")]
use filament_overlay::{b64, unb64};
use filament_pair as pake;
use filament_proto as protocol;
use filament_signal::Client as SignalClient;
use filament_transfer::{chunk_fits_offer, MAX_RECV_RANGES};
use filament_transport::direct;
use filament_transport::net::{self, Ev, Transport};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// How long the event loop waits, after writing a delivery-ack, for the peer to
/// acknowledge it at the transport. Short on purpose: the ack is already queued
/// and is delivered without this wait; it only lets a live peer take it before
/// the loop moves on, and a peer that will never acknowledge must not hold the
/// receiver (and its exit) hostage.
/// Dev-debug lines, exactly the CLI's old gate: stripped unless `debug-logs`.
macro_rules! dlog {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        eprintln!($($arg)*);
    };
}

const ACK_FLUSH_BUDGET: Duration = Duration::from_secs(2);

/// Whole-file verify failures before the transfer fails clearly (P4/GAP-5).
pub const MAX_VERIFY_FAILS: u32 = 3;
/// How long a proven-identity challenge is held before re-issuing.
pub const PROVEN_CHALLENGE_DEADLINE: Duration = Duration::from_secs(3);

/// The `caps` message to re-send on live links when what this machine serves
/// changed (a grant, or the revoke of the last shell grant), else None. Pure.
fn caps_reannounce(was_serving_shell: bool, serving_shell: bool) -> Option<Value> {
    (was_serving_shell != serving_shell).then(|| json!({ "type": "caps", "shell": serving_shell }))
}

/// A shell-class open parked while its link's possession proof is in flight
/// (settle-then-evaluate). The link is identified by pid AND the device key
/// known at park time: only a proof for the same identity on the same link
/// releases it, so a re-keyed peer or another link's proof denies instead.
/// Re-drive calls the same handler the live path uses, which re-gathers
/// everything fresh -- a revoke during the hold therefore denies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParkKind {
    Exec,
    Pty,
    SshSign,
    Forward,
    /// A `sync-open`: transfer-class, so the durable-deny check below reads
    /// the transfer capability, not shell.
    Sync,
}

impl ParkKind {
    /// The capability an explicit per-device deny would name for this kind.
    pub(crate) fn denied_cap(self) -> &'static str {
        match self {
            ParkKind::Sync => cap::CAP_TRANSFER,
            _ => "shell",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ParkedOpen {
    pub pid: String,
    pub device_pub: [u8; 32],
    /// Link generation at park time (Conn::next_gen, bumped on every
    /// reconnect/repair). Release requires equality: a proof on a later
    /// link, or a binding carried over across a transport swap, denies
    /// instead of releasing into a stale transport.
    pub generation: u32,
    pub kind: ParkKind,
    pub v: Value,
    pub sid: u32,
    pub deadline: Instant,
    pub settle_ms: u64,
}

/// Pure budget check, unit-tested: at most 2 parked opens per link and 32
/// per daemon, so parking can never become a DoS surface. Counts CURRENTLY
/// parked opens.
pub fn park_budget_ok(per_link: usize, total: usize) -> bool {
    per_link < 2 && total < 32
}

/// What the settle sweep does with one parked open, as a PURE decision over
/// the live link state -- so every arm (fire, and the three ways a hold goes
/// stale) is unit-testable without a Conn or a clock.
pub(crate) enum SweepArm {
    /// Still waiting, deadline not reached.
    Keep,
    /// Same link generation, same device key, now Proven: re-drive.
    Fire,
    /// A different device key on the link: the peer re-keyed.
    IdentityChanged,
    /// Same key, newer link generation: the transport was swapped.
    Replaced,
    /// No link at all.
    Dropped,
    /// The settle bound passed.
    Expired,
}

pub fn sweep_arm(
    device_pub: [u8; 32],
    generation: u32,
    live: Option<(cap::BindingStrength, Option<[u8; 32]>, u32)>,
    now: Instant,
    deadline: Instant,
) -> SweepArm {
    use cap::BindingStrength;
    match live {
        Some((BindingStrength::Proven, Some(pub_), link_gen))
            if pub_ == device_pub && link_gen == generation =>
        {
            SweepArm::Fire
        }
        Some((_, Some(pub_), _)) if pub_ != device_pub => SweepArm::IdentityChanged,
        Some((_, _, link_gen)) if link_gen != generation => SweepArm::Replaced,
        None => SweepArm::Dropped,
        _ if now >= deadline => SweepArm::Expired,
        _ => SweepArm::Keep,
    }
}

/// A dispatch failure that carries the host's exit class without naming a
/// process exit code. The CLI adapter maps these onto its own taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchFailureKind {
    Usage,
    Unreachable,
}

#[derive(Debug)]
pub struct DispatchFailure {
    pub kind: DispatchFailureKind,
    pub message: String,
}

impl std::fmt::Display for DispatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for DispatchFailure {}

/// A possession challenge's hold is over at its deadline.
pub fn hold_expired(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

/// The fleet presence branch exists only when a verifier is compiled in.
/// Without it, an unsolicited presence must never start a direct dial/adopt.
pub fn fleet_presence_allowed(is_fleet_channel: bool) -> bool {
    cfg!(feature = "fleet") && is_fleet_channel
}

/// The settle timeout reason, shared by the expiry deny and the client.
pub fn settle_timeout_reason(ms: u64) -> String {
    format!("identity not proven within {ms} ms; retry")
}

/// Refusal send for unsettled opens (park-time fast denies and sweep
/// expiry): always an l2-close carrying the specific reason, so the
/// initiator can retry cheaply instead of timing out.
async fn deny_unsettled(
    t: &Arc<dyn filament_transport::net::Transport>,
    sid: u32,
    kind: ParkKind,
    reason: &str,
    log: &dyn LogSink,
) {
    log.say(&format!("l2: {kind:?} unsettled open denied: {reason}"));
    let _ = t
        .send_control(&serde_json::json!({ "type": "l2-close", "sid": sid, "err": reason }))
        .await;
}

/// Answer a dial from a device this daemon no longer recognizes (it was
/// forgotten here while we ran) with the refusal, over signaling: no link is
/// built for it, and its sender reports the reason at once instead of
/// waiting out its establishment window.
/// A named close for an open this build does not serve. Valid L2 sids get a
/// frame; malformed opens cannot be answered on a stream that does not exist.
fn unserved_open_close(v: &Value, reason: &str) -> Option<Value> {
    let sid = l2::wire_sid(v).filter(|sid| l2::is_l2_sid(*sid))?;
    Some(json!({
        "type": "l2-close",
        "sid": sid,
        "err": reason,
    }))
}

async fn refuse_unserved_open(conn: &Conn, pid: &str, v: &Value, reason: &str) {
    let Some(close) = unserved_open_close(v, reason) else {
        return;
    };
    if let Some(t) = conn.transport_of(pid) {
        let _ = t.send_control(&close).await;
    }
}

async fn refuse_unrecognized_dial(sio: &filament_signal::Client, pid: &str, log: &dyn LogSink) {
    let refusal = crate::refusal::Refusal::new(crate::refusal::Code::Unrecognized, None);
    let mut data = json!({ "type": "not-recognized", "reason": refusal.reason });
    refusal.annotate(&mut data);
    let _ = sio.emit("signal", json!({ "to": pid, "data": data })).await;
    log.debug(&format!(
        "refused a dial from {pid}: a device forgotten here"
    ));
}

/// The outcome of ONE peer's step (adopt, answer, a control reply) inside the
/// serving loop.
///
/// The daemon (`up`) serves every peer from this one loop, so a bare `?` on a
/// per-peer step ended the process for all of them. A two-machine run lost
/// its daemon 9 s after a restart to one peer's ICE-config timeout ("direct
/// fallback adoption failed ... no answer within 3s"). In the daemon the
/// failure is logged and the step is skipped (`Ok(None)`): the steps routed
/// here leave the peer's existing state intact on error (an establish builds
/// before it destroys), and the next roster push, warm-hold tick or retry
/// rung drives that peer again. A one-shot `receive` has exactly one sender,
/// so there the error still ends the run, unchanged, with its exit code.
fn peer_step<T>(
    daemon: bool,
    pid: &str,
    what: &str,
    r: Result<T>,
    log: &dyn LogSink,
) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if daemon => {
            log.debug(&format!(
                "tunlion: PEER-STEP-FAILED peer={pid} step={what}: {e:#}; the daemon keeps serving"
            ));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Front a waiting question on the sticky line. A presentation with no screen
/// can only report that (`Ask::Unshown`), so the question goes to the log sink
/// instead: a pending ask must never become a hang on a prompt nobody saw.
///
/// `announced` says the caller already printed the permanent copy of `q` (C25:
/// nothing is asked invisibly), so a screen-less host does not print it twice.
fn front_question(present: &dyn Presentation, log: &dyn LogSink, q: &str, announced: bool) {
    if present.sticky_ask(q) == Ask::Unshown && !announced {
        log.critical(q);
    }
}

fn log_ctl_rx<'a>(pid: &str, ty: Option<&'a str>, log: &dyn LogSink) -> Option<&'a str> {
    log.debug(&format!("ctl rx {} <- {pid}", ty.unwrap_or("?")));
    ty
}

/// May this overlay key hold a route here? Not when its device was revoked,
/// and not once the invitation that admitted it ended: a route is access too,
/// the one a device keeps without opening anything.
pub fn overlay_key_refused(ports: &RecvPorts, host: &dyn HostServices, pubkey: &[u8; 32]) -> bool {
    ports.identity.device_cert_revoked(pubkey)
        || host
            .delegated_access_for(pubkey)
            .is_some_and(|a| a.expired(filament_id::now_secs()))
}

/// The decline for an offer the gate refused. A refusal with a known cause
/// (access expired, device revoked, outside the ceiling) travels as a TYPED
/// refusal carrying the reason, so the sender prints why ("access expired at
/// ...") instead of a bare "declined" that reads as a person saying no. A
/// plain no stays a plain decline. Pure.
pub fn policy_decline_msg(id: &str, reason: Option<&str>) -> Value {
    match reason.and_then(|r| crate::refusal::code_from_reason(r).map(|c| (c, r))) {
        Some((code, r)) => protocol::refuse_msg(id, code.as_wire(), r),
        None => protocol::decline_msg(id),
    }
}

/// May a parked open's re-drive overturn this deny once the peer proves its
/// key? Only when the deny could be ABOUT the missing proof. Expiry, the
/// enrolment ceiling, revocation (of the device or of a grant), an explicit
/// owner deny and an unrecognized device are decisions no proof changes, so
/// their verdict is final at once. Pure, so the rule is unit-testable.
pub fn deny_is_proof_attributable(reason: &str) -> bool {
    let r = reason.trim();
    let final_prefixes = [
        crate::refusal::EXPIRED_PREFIX,
        crate::refusal::CEILING_REASON,
        cap::REVOKED_REASON,
        "device revoked",
        "shell revoked for",
        "explicitly denied",
        crate::refusal::UNRECOGNIZED_REASON,
    ];
    !final_prefixes.iter().any(|p| r.starts_with(p))
}

/// Settle-then-evaluate, called with an ALREADY-DENIED verdict: decide
/// first, park only when the deny is attributable to the unproven binding.
/// Allows proceed untouched (this fn never runs for them), so legacy
/// shadow allows -- including secret-paired granted peers with no resolved
/// cert -- behave exactly as before. Parks only when ALL hold: binding not
/// Proven, a known device key that can become Proven, neither revoked nor
/// explicitly denied (durable states keep their live verdict), and budget
/// remains. Returns true when the caller must return immediately, having
/// either parked or sent the fast deny itself.
pub async fn park_on_deny(
    known_device: &(dyn Fn(&[u8; 32]) -> bool + Send + Sync),
    revoked: &(dyn Fn(&[u8; 32]) -> bool + Send + Sync),
    delegated_expired: &(dyn Fn(&[u8; 32]) -> bool + Send + Sync),
    denied: &(dyn Fn(&str, &str) -> bool + Send + Sync),
    settle_ms: u64,
    parked: &mut Vec<ParkedOpen>,
    conn: &Conn,
    pid: &str,
    kind: ParkKind,
    t: &Arc<dyn filament_transport::net::Transport>,
    sid: u32,
    v: &Value,
    gate_reason: &str,
) -> bool {
    let (binding_proven, device_pub, generation, name) = match conn.link(pid) {
        Some(l) => (
            l.identity_binding == cap::BindingStrength::Proven,
            l.identity_device_pub,
            l.generation,
            l.verified_name.clone(),
        ),
        None => (false, None, 0, None),
    };
    // Settled, revoked, or explicitly denied: the live verdict stands,
    // whatever it was, and the caller emits it (with its enqueue tell).
    // Only an unproven, known, revocable identity parks.
    if binding_proven {
        return false;
    }
    // A proof can only ever supply PROOF. A deny whose reason is something a
    // proof cannot change (the access expired, the ceiling excludes it, the
    // device was revoked or explicitly denied) is final: parking it handed the
    // verdict to the re-drive, and the re-drive overturned an expiry it had
    // no business touching (the exec ran ~2.5 min past the invitation end).
    if !deny_is_proof_attributable(gate_reason) {
        return false;
    }
    // No resolved key: there is nothing for a hold to bind to, so the LIVE
    // verdict stands -- the caller sends its own reason and raises the
    // access request. Answering here would replace a real denial ("no shell
    // grant") with a retry hint and suppress the requestable tell.
    let Some(device_pub) = device_pub else {
        return false;
    };
    // "Known key" means it resolves to a device record: an unresolved key
    // cannot become Proven against a record, so it must not occupy hold
    // budget (a stream of unknown-key opens would otherwise fill the queue).
    if !known_device(&device_pub) {
        return false;
    }
    if revoked(&device_pub) {
        return false;
    }
    if delegated_expired(&device_pub) {
        return false;
    }
    if let Some(n) = name.as_deref() {
        if denied(n, kind.denied_cap()) {
            return false;
        }
    }
    let per_link = parked.iter().filter(|p| p.pid == pid).count();
    if !park_budget_ok(per_link, parked.len()) {
        deny_unsettled(t, sid, kind, "identity settling, retry", conn.log.as_ref()).await;
        return true;
    }
    let ms = settle_ms;
    parked.push(ParkedOpen {
        pid: pid.to_string(),
        device_pub,
        generation,
        kind,
        v: v.clone(),
        sid,
        deadline: Instant::now() + Duration::from_millis(ms),
        settle_ms: ms,
    });
    conn.log.say(&format!(
        "l2: {kind:?} open parked {ms}ms for identity proof (gate said: {gate_reason})"
    ));
    true
}

/// The refusal for a shell-class open while serving is OFF here (`off` is
/// ShellOff or TunnelOff). The ceiling-aware decision and the one consent ask
/// moved to `crate::shell::off` with the admission endpoint; this
/// keeps the old call-site name for `l2-open` and `shell-bootstrap`, and is not
/// a second rule.
fn serving_off_refusal(
    conn: &Conn,
    pid: &str,
    off: crate::refusal::Code,
) -> crate::refusal::Refusal {
    crate::shell::off::serving_off_refusal(conn, pid, off)
}

/// Whether an offer is accepted without asking, before the capability layer.
/// A daemon accepts only proven links. A foreground receive accepts on `-y`,
/// on a re-enqueued answer the person already gave, on a proven link, on the
/// resume of a partial it already accepted, and on the CODE: typing the code a
/// sender's ceremony was bound to is the consent (`receive --help`). Pure.
pub fn offer_has_consent(
    daemon: bool,
    yes: bool,
    consented: bool,
    link_trusted: bool,
    resuming_partial: bool,
    code_consent: bool,
) -> bool {
    if daemon {
        link_trusted
    } else {
        yes || consented || link_trusted || resuming_partial || code_consent
    }
}

/// Why a code receive ended with no sender authenticated. "Older version" was
/// said for every expiry, including when other codes' senders sharing the room
/// ran their (current) ceremonies at us. Say it only when no peer ran one. Pure.
pub fn recv_pake_expired_message(any_pake_heard: bool, budget_secs: u64) -> String {
    if any_pake_heard {
        format!(
            "no device in the sender's room completed the encrypted handshake for this code within {budget_secs}s: \
             the code may be mistyped, or its sender stopped waiting. Nothing was received; ask for a FRESH code."
        )
    } else {
        "the other device uses an older version and can't send securely over a code. Update it (or this CLI) so the transfer runs the encrypted handshake. Nothing was received.".to_string()
    }
}

/// Whether a receive that has finished its files may start its quiet exit, and
/// the line it prints. Pure. `idle` = nothing in flight and no question open.
/// A one-time CODE receive also ends while its sender is still connected: a
/// browser keeps its tab and link open after the files are acked, so waiting for
/// the link to go (the rule for everyone else) waited forever (launch matrix B03).
pub fn quiet_exit_reason(
    completed: usize,
    keep_open: bool,
    idle: bool,
    links_clear: bool,
    code_only: bool,
) -> Option<&'static str> {
    if completed == 0 || keep_open || !idle {
        return None;
    }
    if links_clear {
        Some("  (peer-left never arrived, exiting on quiet)")
    } else if code_only {
        Some("  (the sender is still connected but sent nothing more; a code receive ends here, add --keep-open to wait for more files)")
    } else {
        None
    }
}

/// Whether a one-shot receive has waited past its deadline with nothing kept.
/// Pure so the boundary is testable without a socket. No timeout (or 0) means
/// "wait without limit"; anything already received means the deadline no
/// longer applies, because the transfer happened.
pub fn receive_timed_out(elapsed: Duration, timeout: Option<Duration>, completed: usize) -> bool {
    completed == 0 && timeout.is_some_and(|d| !d.is_zero() && elapsed >= d)
}

/// The real producer of an invalid `--expect-sha256` failure.
pub fn validate_expect_sha256(value: Option<&str>) -> Result<()> {
    match value {
        Some(expected) if !valid_sha256(expected) => Err(anyhow::Error::new(DispatchFailure {
            kind: DispatchFailureKind::Usage,
            message: "--expect-sha256 must be exactly 64 hexadecimal characters".into(),
        })),
        _ => Ok(()),
    }
}

/// The real producer of the one-shot "nothing arrived" failure.
pub fn receive_timeout_failure(secs: u64) -> DispatchFailure {
    DispatchFailure {
        kind: DispatchFailureKind::Unreachable,
        message: format!("nothing arrived within {secs}s: no sender offered a transfer"),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && hex::decode(value).is_ok_and(|digest| digest.len() == 32)
}

fn sha256_matches(expected: &str, offered: Option<&str>) -> bool {
    let (Ok(expected), Some(offered)) = (hex::decode(expected), offered) else {
        return false;
    };
    expected.len() == 32
        && hex::decode(offered).is_ok_and(|offered| offered.len() == 32 && offered == expected)
}

/// CLI process adapter. The driver below returns after its owned cleanup;
/// only this adapter translates cancellation into the CLI signal exit policy.

// ---- moved from recv_driver/recv_run ----

pub async fn drive(
    server: &str,
    code: Option<String>,
    dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    timeout: Option<u64>,
    expect_sha256: Option<String>,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    shell_policy: ShellPolicy,
    shell_user: Option<String>,
    no_proxy_fallback: bool,
    transport_context: filament_transport::TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
    mut ports: RecvPorts,
    report: RecvReport,
    stop: &crate::driver::Cancellation,
    readiness: &crate::driver::Readiness,
    cleanup: &mut RecvCleanup,
) -> DriverOutcome<Result<()>> {
    let outcome = stop
        .run(recv_run(
            server,
            code,
            dir,
            yes,
            room,
            to,
            keep_open,
            timeout,
            expect_sha256,
            relay,
            remember,
            daemon,
            output,
            shell_policy,
            shell_user,
            no_proxy_fallback,
            transport_context,
            log.clone(),
            host,
            ports,
            report,
            stop,
            readiness,
            cleanup,
        ))
        .await;
    cleanup.finish(log.as_ref()).await;
    let stdin_outcome = cleanup.stdin_outcome;
    // A signal received during cleanup still has its signal-specific outcome.
    if stop.is_cancelled() {
        return DriverOutcome::Cancelled;
    }
    match (outcome, stdin_outcome) {
        (DriverOutcome::Returned(Ok(())), crate::recv::ports::StdinOutcome::Detached(reason)) => {
            DriverOutcome::Returned(Err(anyhow::anyhow!(
                "stdin reader detached during cleanup: {reason}"
            )))
        }
        (outcome, _) => outcome,
    }
}

/// Receive-transfer and consent state for one dispatch.
pub struct RecvState {
    pub by_sid: HashMap<(String, u32), IncomingFile>,
    pub verify_fails: HashMap<String, u32>,
    pub completed: usize,
    pub ever_received: bool,
    pub pending: std::collections::VecDeque<(String, Value)>,
    pub pending_proven: Arc<Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
    pub question_open: Arc<std::sync::atomic::AtomicBool>,
    pub question_shown: Instant,
    pub recv_pending_offers: HashMap<String, Value>,
    pub recv_cers: HashMap<String, Ceremony>,
    pub recv_deadlines: HashMap<String, Instant>,
}

/// Resources retained when the inline driver is cancelled at ANY yielding
/// await, including setup/maintenance (not just next_ev). This is deliberately
/// not an owner of all lower-layer tasks or a durable/no-thread stop promise.
/// `watchdog` owns one diagnostic OS thread plus its stop handle; it does not
/// own receive-driver work. `writers` owns the blocking writes admitted by
/// `Ev::Chunk` and joins (never aborts) them before `state` is flushed.
#[derive(Default)]
pub struct RecvCleanup {
    state: Option<RecvState>,
    conn: Option<Conn>,
    signaling: Option<filament_signal::Client>,
    tasks: crate::recv::lifecycle::Tasks,
    writers: WriterTasks,
    watchdog: crate::recv::lifecycle::LoopWatchdog,
    stdin: Option<Box<dyn crate::recv::ports::StdinOwner>>,
    stdin_outcome: crate::recv::ports::StdinOutcome,
    sync_tasks: SyncTasks,
    /// Test-only observation of the cleanup order (`finish` also records the
    /// static phases used by the older tests). A gated writer pushes into the
    /// same trace, so ordering is observable across the blocking-pool thread.
    #[cfg(test)]
    trace: Option<Arc<Mutex<Vec<&'static str>>>>,
}

/// One served sync task. In a reduced profile the type is inert so the loop's
/// ownership methods stay unconditional.
#[cfg(feature = "mount-server")]
pub(crate) struct SyncTask(pub(crate) crate::sync::serving::SyncServeTask);
#[cfg(not(feature = "mount-server"))]
pub(crate) struct SyncTask;

impl SyncTask {
    #[cfg(feature = "mount-server")]
    fn cancel(&self) {
        self.0.cancel();
    }
    #[cfg(not(feature = "mount-server"))]
    fn cancel(&self) {}

    #[cfg(feature = "mount-server")]
    async fn join(self) -> Result<(), String> {
        match self.0.join().await {
            Ok(result) => result,
            Err(error) => Err(error.to_string()),
        }
    }
    #[cfg(not(feature = "mount-server"))]
    async fn join(self) -> Result<(), String> {
        Ok(())
    }

    #[cfg(feature = "mount-server")]
    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
    #[cfg(not(feature = "mount-server"))]
    fn is_finished(&self) -> bool {
        true
    }
}

#[derive(Clone, Default)]
struct SyncTasks(Arc<Mutex<HashMap<(String, u32), SyncTask>>>);

/// Owns the blocking `pwrite_at`/stdout writers admitted by this invocation.
///
/// This is deliberately separate from [`crate::recv::lifecycle::Tasks`]: that
/// owner aborts on stop, and aborting a `spawn_blocking` task does not stop the
/// OS write it is running. A write admitted by `Ev::Chunk` must therefore be
/// joined, never aborted, before its `.part` is flushed or stdout is called
/// delivered. Completed handles are reaped during the event loop so a daemon
/// does not accumulate one handle per chunk for its whole life.
#[derive(Clone, Default)]
struct WriterTasks {
    next: Arc<AtomicU64>,
    tasks: Arc<Mutex<HashMap<u64, WriterTask>>>,
}

struct WriterTask {
    pid: String,
    sid: u32,
    handle: tokio::task::JoinHandle<()>,
}

impl WriterTasks {
    /// Register a write at spawn time. There is no await between the spawn and
    /// the registration, so a cancelled dispatch cannot drop the handle before
    /// the invocation's cleanup owns it.
    fn spawn<F>(&self, pid: String, sid: u32, write: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = tokio::task::spawn_blocking(write);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.tasks
            .lock()
            .unwrap()
            .insert(id, WriterTask { pid, sid, handle });
    }

    /// Join writers that already finished, releasing their handles. A running
    /// write stays owned; a panic is reported here instead of being lost with
    /// the detached handle.
    async fn reap(&self, log: &dyn LogSink) {
        let finished: Vec<u64> = self
            .tasks
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, task)| task.handle.is_finished())
            .map(|(id, _)| *id)
            .collect();
        for id in finished {
            // Drop the guard before the await: see SyncTasks::reap_sync_tasks.
            let task = self.tasks.lock().unwrap().remove(&id);
            if let Some(task) = task {
                report_writer_join(log, &task.pid, task.sid, task.handle.await);
            }
        }
    }

    /// Join this stream's writers before a verify re-request re-arms its
    /// completion gate. A post-decrement writer that has not yet reached its
    /// claim would otherwise be able to claim the next generation. At an
    /// inflight==0 retry point these writers have finished their bytes and are
    /// only returning, so this is bounded.
    async fn join_sid(&self, pid: &str, sid: u32, log: &dyn LogSink) {
        let ids: Vec<u64> = self
            .tasks
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, task)| task.pid == pid && task.sid == sid)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let task = self.tasks.lock().unwrap().remove(&id);
            if let Some(task) = task {
                report_writer_join(log, &task.pid, task.sid, task.handle.await);
            }
        }
    }

    /// Await every remaining write. Never aborts: the write was admitted and
    /// must finish (or panic) before the caller flushes or finalizes its state.
    async fn join_all(&self, log: &dyn LogSink) {
        let mut joining: Vec<WriterTask> = std::mem::take(&mut *self.tasks.lock().unwrap())
            .into_values()
            .collect();
        for task in joining.drain(..) {
            report_writer_join(log, &task.pid, task.sid, task.handle.await);
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.tasks.lock().unwrap().is_empty()
    }
}

fn report_writer_join(
    log: &dyn LogSink,
    pid: &str,
    sid: u32,
    result: std::result::Result<(), tokio::task::JoinError>,
) {
    if let Err(error) = result {
        log.say(&format!(
            "recv: {pid}/{sid} blocking write task failed: {error}"
        ));
    }
}

/// Publishes the end of one admitted write. It runs on the normal return path
/// and on panic, so a poisoned lock or a panicking sink cannot leave `inflight`
/// permanently above zero and strand the stream. `WriterTasks` joins the
/// handle and reports the join error separately.
struct InflightGuard {
    inflight: Arc<AtomicI64>,
    end_seen: Arc<AtomicBool>,
    completion: Arc<crate::recv::CompletionGate>,
    tx: mpsc::UnboundedSender<Ev>,
    write_err: Arc<Mutex<Option<crate::recv::WriteFailure>>>,
    pid: String,
    sid: u32,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // A panic is a failed write, not an acceptable hole: record it once so
        // the event loop refuses with a reason instead of finalizing (or
        // re-fetching forever). The lock is not unwrapped: the panic may have
        // poisoned it, and panicking again in a destructor would abort.
        if std::thread::panicking() {
            let mut slot = self.write_err.lock().unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                *slot = Some(crate::recv::WriteFailure {
                    kind: None,
                    detail: "the blocking write task panicked".to_string(),
                });
            }
        }
        // SeqCst pairs with CompletionGate::file_end's store/load order so the
        // file-end and this last writer cannot both miss the other.
        let prev = self.inflight.fetch_sub(1, Ordering::SeqCst);
        if self.completion.last_writer(prev, &self.end_seen) {
            let _ = self.tx.send(Ev::MaybeComplete(self.pid.clone(), self.sid));
        }
    }
}

/// Test-only observation of the production cleanup order. The no-op in normal
/// builds keeps `finish` honest: tests assert what it actually awaits.
#[cfg(test)]
thread_local! {
    static CLEANUP_PHASES: std::cell::RefCell<Vec<&'static str>> =
        std::cell::RefCell::new(Vec::new());
}

#[cfg(test)]
fn note_cleanup_phase(phase: &'static str) {
    CLEANUP_PHASES.with(|phases| phases.borrow_mut().push(phase));
}

#[cfg(not(test))]
fn note_cleanup_phase(_phase: &'static str) {}

impl SyncTasks {
    async fn track_sync_task(&self, pid: String, sid: u32, task: SyncTask, log: &dyn LogSink) {
        let key = (pid, sid);
        // A live SID collision is rejected during admission. A finished entry
        // can remain until the next reap tick; join it before replacing it.
        // Remove into a binding so the guard drops before the await: a guard
        // held across `join().await` would make the whole receive dispatch
        // non-`Send` and is no longer needed once the task is taken.
        let previous = self.0.lock().unwrap().remove(&key);
        if let Some(previous) = previous {
            previous.cancel();
            report_sync_join(log, &key.0, key.1, previous.join().await);
        }
        self.0.lock().unwrap().insert(key, task);
    }

    async fn reap_sync_tasks(&self, log: &dyn LogSink) {
        let finished: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, task)| task.is_finished())
            .map(|(key, _)| key.clone())
            .collect();
        for (pid, sid) in finished {
            // Take the task out first; drop the guard before the await.
            let removed = self.0.lock().unwrap().remove(&(pid.clone(), sid));
            if let Some(task) = removed {
                report_sync_join(log, &pid, sid, task.join().await);
            }
        }
    }

    async fn cancel_sync_for_pid(&self, pid: &str, log: &dyn LogSink) {
        let keys: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|(task_pid, _)| task_pid == pid)
            .cloned()
            .collect();
        let mut joining = Vec::with_capacity(keys.len());
        for key in keys {
            let removed = self.0.lock().unwrap().remove(&key);
            if let Some(task) = removed {
                task.cancel();
                joining.push((key, task));
            }
        }
        for ((task_pid, sid), task) in joining {
            report_sync_join(log, &task_pid, sid, task.join().await);
        }
    }

    async fn stop_sync_tasks(&self, log: &dyn LogSink) {
        let mut joining = std::mem::take(&mut *self.0.lock().unwrap())
            .into_iter()
            .collect::<Vec<_>>();
        for (_, task) in &joining {
            task.cancel();
        }
        for ((pid, sid), task) in joining.drain(..) {
            report_sync_join(log, &pid, sid, task.join().await);
        }
    }
}

impl RecvCleanup {
    fn note_phase(&self, phase: &'static str) {
        note_cleanup_phase(phase);
        #[cfg(test)]
        {
            if let Some(trace) = &self.trace {
                trace.lock().unwrap().push(phase);
            }
        }
    }

    async fn finish(&mut self, log: &dyn LogSink) {
        // The stdin reader is an owned CLI resource when the adapter could
        // join it. A platform that cannot do so returns false and says so.
        self.stdin_outcome = match self.stdin.take() {
            None => crate::recv::ports::StdinOutcome::NotStarted,
            Some(mut stdin) => {
                stdin.stop();
                let outcome = stdin.join();
                match outcome {
                    crate::recv::ports::StdinOutcome::Detached(reason) => log.critical(&format!(
                        "recv: stdin reader detached: {reason}; cleanup continues but the reader may still live"
                    )),
                    crate::recv::ports::StdinOutcome::External(reason) => log.debug(&format!(
                        "recv: stdin uses the CLI process-lifetime reader: {reason}"
                    )),
                    _ => {}
                }
                outcome
            }
        };
        // The loop is intentionally no longer turning. Ask its stall observer
        // to stop before the (possibly slow) flush, so cleanup cannot be
        // reported as a live-loop stall. This is a best-effort one-second
        // join: a `Detached` outcome leaves the observer and its blocking
        // waiter alive (still holding the log sink) until they finish.
        let _ = self.watchdog.stop().await;
        self.note_phase("watchdog");
        // Writers admitted by Ev::Chunk are blocking OS writes, not aborted
        // tasks: join them before any by_sid entry is synced or drained. A
        // dispatch must not return (or report Stopped) while one is running.
        self.writers.join_all(log).await;
        self.note_phase("writers");
        self.sync_tasks.stop_sync_tasks(log).await;
        self.note_phase("sync_tasks");
        // Stop accepting control work before closing links. Joining aborted
        // tasks ensures their listener futures are dropped before we return.
        self.tasks.stop().await;
        self.note_phase("tasks");
        let had_state = self.state.is_some();
        if let Some(st) = &mut self.state {
            crate::recv::files::flush_inflight(&mut st.by_sid).await;
        }
        if had_state {
            self.note_phase("flush");
        }
        if let Some(conn) = &mut self.conn {
            conn.close_links_for_exit();
        }
        tokio::task::yield_now().await;
        if let Some(sio) = self.signaling.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
        }
        self.conn.take();
        self.state.take();
    }
}

pub fn report_sync_join(log: &dyn LogSink, pid: &str, sid: u32, result: Result<(), String>) {
    match result {
        Ok(()) => {}
        Err(error) => log.say(&format!("sync: {pid}/{sid} ended: {error}")),
    }
}

async fn recv_run(
    server: &str,
    mut code: Option<String>,
    mut dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    // Wait at most this long for anything to arrive; None (or 0) waits without
    // limit. A deadline that passes with nothing received exits 6, so a script
    // can tell "nobody came" from "the transfer failed".
    timeout: Option<u64>,
    // Optional content pin for a one-shot CI receive. The sender's advertised
    // digest must match this before we accept; the normal receive path then
    // verifies the bytes against that digest before acknowledging completion.
    expect_sha256: Option<String>,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    mut shell_policy: ShellPolicy,
    // M-1: optional non-root account the web-shell/ssh PTY is dropped to. `None`
    // means the PTY runs as the up-process user (documented root risk).
    mut shell_user: Option<String>,
    no_proxy_fallback: bool,
    // Configuration and discovery state bound to this daemon's config root.
    // Every signaling/config/ICE path below uses this same instance.
    transport_context: filament_transport::TransportContext,
    // Where this loop says what it is doing. The CLI hands it the terminal
    // sink; a caller with no terminal hands it `NoLog` and every line below
    // still formats, but nothing is printed.
    log: Arc<dyn LogSink>,
    // The machine's own facts (settings, the config dir, the keystore, the
    // filesystem). The CLI hands it `CliHost`; a caller with no host hands it
    // `NoHost` and every read resolves to the inert default.
    host: Arc<dyn HostServices>,
    mut ports: RecvPorts,
    report: RecvReport,
    stop: &crate::driver::Cancellation,
    readiness: &crate::driver::Readiness,
    cleanup: &mut RecvCleanup,
) -> Result<()> {
    cleanup.watchdog = crate::recv::lifecycle::LoopWatchdog::with_stall(ports.env.loop_stall_secs);
    validate_expect_sha256(expect_sha256.as_deref())?;
    let opened_flow = !daemon
        && ports.env.interactive_allowed
        && (code.is_none() || ports.env.interactive_requested);
    let to_stdout = output.as_deref() == Some("-");
    // Daemon start: idempotently heal the owner's self genesis cap header.
    // Identities created before this seeding existed have no header; seeding
    // only at `identity init` would grandfather-trap them into permanent
    // Unprovisioned. Healing on every daemon start makes old identities correct
    // on next `up` and new ones born correct. Tautological; widens nothing.
    if daemon {
        if let Some(uk) = host.user_key() {
            if host.ensure_self_genesis_header(&uk) {
                log.debug("seeded owner self genesis capability header");
            }
        }
    }
    // INTERACTIVE GATE (CLI `recv` only, never the daemon/`up`). With no code,
    // offer: type a code to connect to a specific person, or press Enter on an
    // empty buffer to use the local network (today's default). When the gate is
    // closed we fall straight through to the auto-room default below.
    // An explicit --room (or --to) already says where to meet: asking for a
    // code there contradicted the flag the user typed.
    if !daemon && code.is_none() && room.is_none() && to.is_none() && ports.env.interactive_allowed
    {
        log.say(&log.paint(
            Tone::Dim,
            "  enter a code to connect to a specific person, or press enter to use the local network",
        ));
        match ports.prompt.ask_code("  receive / code  ") {
            Ok(Some(c)) => code = Some(c),
            Ok(None) => { /* fall through to the local-network auto room */ }
            // Ctrl-C is an interrupt, not a choice: the CLI adapter maps the
            // cancelled dispatch to its signal exit (130).
            Err(e) if e.to_string() == "interrupted" => {
                stop.cancel();
                return std::future::pending().await;
            }
            Err(e) => return Err(e),
        }
    }
    if opened_flow {
        log.say("");
        log.say(&format!("  {}", log.paint(Tone::Brand, "RECEIVE")));
        log.say(&format!(
            "  from     {}",
            to.as_deref().unwrap_or(if code.is_some() {
                "holder of this one-time code"
            } else {
                "nearby sender"
            })
        ));
        log.say(&format!(
            "  into     {}",
            if to_stdout {
                "stdout".to_string()
            } else {
                dir.display().to_string()
            }
        ));
        log.say("  verify   whole-file hash before final placement");
        log.say(&format!(
            "  consent  {}",
            if yes {
                "accept matching offers"
            } else {
                "ask before each offer"
            }
        ));
        let mut replay = vec!["tunlion".to_string(), "receive".to_string()];
        if let Some(code) = code.as_deref() {
            replay.push(command_arg(code));
        }
        replay.extend(["--dir".to_string(), command_arg(&dir.display().to_string())]);
        if yes {
            replay.push("--yes".to_string());
        }
        log.say(&format!("  command  {}", replay.join(" ")));
        let confirmation = ports
            .prompt
            .line("\n  Press Enter to wait, or type cancel: ")?;
        if confirmation.eq_ignore_ascii_case("cancel") {
            bail!("cancelled");
        }
    }
    // L1-a unification: a transfer code and a pairing code now have the SAME
    // shape (`words-NNNN`) and run the SAME ephemeral SPAKE2 ceremony, the verb
    // (`recv` vs `pair`) decides whether the agreed secret is discarded or kept.
    // So `recv` no longer redirects a 4-digit code away (the old width-based
    // hint is obsolete); any well-formed code is a valid claim here.
    // Owner-only: peers write here (the host's create_inbox_dir).
    host.create_inbox_dir(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    // Interrupted transfers' partials wait PARTIAL_TTL_SECS for a resume, then go.
    crate::recv::files::expire_partials_and_say(&dir, log.as_ref());
    let my_uid = ports.env.uid.clone();
    let (tx, mut rx) = mpsc::unbounded_channel::<Ev>();
    // P2 (GAP-2): `mut` so the long-lived acceptor's outer reconnect loop can
    // swap in a freshly-dialed signaling client after a drop (see below). The
    // short-lived `recv`/`send` paths never reconnect, they re-invoke fresh,
    // so this is only exercised by the daemon (`up`/`up --dir`).
    // The daemon waits for the network instead of exiting (see
    // `connect_signaling_patiently`); a one-shot receive still fails fast.
    let mut sio = if daemon {
        crate::recv::events::connect_signaling_patiently(
            &transport_context,
            server,
            tx.clone(),
            log.as_ref(),
        )
        .await?
    } else {
        net::connect_signaling(&transport_context, server, tx.clone()).await?
    };
    cleanup.signaling = Some(sio.clone());

    let mut paired = code.is_some();
    // Set when the sender cancels a transfer because it could not read its own
    // source (`file-cancel`). A one-shot receive then ends saying so, instead of
    // holding the line for a sender that has already given up.
    let mut sender_cancelled: Option<String> = None;
    // For the give-up message: a code works once, so "re-run with the code"
    // can never resume anything, and only the partials THIS receive started
    // are ours to report (or to clean up when they hold nothing).
    let code_claimed = code.is_some();
    let mut session_parts: Vec<crate::recv::transfer_truth::SessionPart> = Vec::new();
    // C24: at most one typed claim in flight, a second typed code while one
    // is pending was silently dropped in live use; now it queues a message.
    let mut claim_in_flight = false;
    // C29's in-session pairing ceremony (a code typed into, or minted by, the
    // interactive `up` console) is GONE. It claimed a v1 code (`pair-claim`
    // without `v:2`) and then handed a fresh pair secret over a DataChannel
    // whose DTLS fingerprints the signaling server chose, so a malicious
    // server could MITM it and keep the secret. Pairing from the console now
    // points at `tunlion add` / `tunlion join`, which run the SPAKE2 ceremony.
    // Receive-side transfer/consent state, grouped out of this function's locals
    // (still a plain local; no handler extraction yet). See `RecvState`.
    let sync_tasks = cleanup.sync_tasks.clone();
    // The invocation's writer handles live in RecvCleanup (so cancellation
    // cannot lose them); the loop reaps finished ones and `finish` joins the
    // rest before flushing by_sid.
    let writer_tasks = cleanup.writers.clone();
    let st = cleanup.state.insert(RecvState {
        by_sid: HashMap::new(),
        verify_fails: HashMap::new(),
        completed: 0usize,
        ever_received: false,
        pending: Default::default(),
        pending_proven: Arc::new(Mutex::new(HashMap::new())),
        question_open: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        question_shown: Instant::now(),
        recv_pending_offers: HashMap::new(),
        recv_cers: HashMap::new(),
        recv_deadlines: HashMap::new(),
    });
    let mut devices = host.devices_load(); // channel -> identity lookup for proofs
                                           // C30: the convergent session repairs whatever the one-shot emits below
                                           // lose, room membership, channel subscriptions, the lease. The emits
                                           // stay as the fast path (and old-server compat); the session is truth.
    let mut sess = Session::new(&ports.env.display_name, &my_uid);
    // A one-shot `receive <code>` meets exactly one peer: whoever holds the
    // code. Subscribing it to every known device's channel (and the fleet's)
    // dialed whichever of them was online: the lab saw "known device 'w2-a'
    // appeared, connecting" during a receive from the unrelated w1-a, and then
    // that second link on the roster line under its raw signaling id.
    let code_only = code.is_some() && !daemon;
    if !code_only {
        sess.channels = devices.iter().map(|(_, s)| host.channel_of(s)).collect();
        // Fleet auto-mesh: one more meeting point, where devices certified by the
        // SAME owner key find each other with no pairwise pairing. Presence there
        // authorizes NOTHING; admission runs on the certificate. See cli/src/fleet.rs
        // and docs/design-fleet-automesh.md.
        if cfg!(feature = "fleet") {
            if let Some(fc) = ports.identity.fleet_channel() {
                if !sess.channels.contains(&fc) {
                    sess.channels.push(fc);
                }
            }
        }
    }
    // L1-a: the ephemeral SPAKE2 ceremony for a `recv <code>` claim. The typed
    // code is split CLIENT-SIDE; only the numeric nameplate is sent (pair-claim
    // {nameplate, v:2}). The words feed SPAKE2 and never reach the server. After
    // mutual auth the agreed secret is DISCARDED (transfer never persists it).
    //
    // PER-PEER ceremonies (shared-auto-room fix): the receiver joins the sender's
    // room, which (for a `send --code`) is the sender's AUTO room, shared with any
    // other local peers sitting in it. We therefore CANNOT latch onto the first
    // peer that appears: an unrelated decoy must not be allowed to consume our one
    // ceremony, run it to the budget, and bail the whole receive. Instead we run
    // an INDEPENDENT ephemeral ceremony per candidate peer, each built from the
    // SAME claimed code (words + nameplate). The FIRST peer whose ceremony agrees
    // K and verifies the confirm MAC becomes the authenticated sender; from then
    // on we accept file-offers ONLY from that peer. A peer whose ceremony fails
    // (wrong words) or whose per-peer budget expires is dropped INDIVIDUALLY and
    // never bails the receive. Only an OVERALL deadline with NO peer authenticated
    // fails the whole `recv` (so a genuinely absent/old sender still fails loudly
    // rather than hanging). `recv_code_path` is the "this is a code claim" sentinel
    // (was `recv_cer.is_some()`); `recv_pake_template` mints each per-peer ceremony.
    let recv_code_path = code.is_some();
    let recv_pake_template: Option<(String, String)>; // (words, nameplate)
                                                      // Identity: receiver-generated nonce challenges for introduce path (0x02), single-use, session-scoped, erased after verification, distinct per concurrent session
                                                      // Map peer_id -> (nonce, timestamp, receiver_device_pub)
    let mut identity_nonces: HashMap<String, ([u8; 32], Instant, [u8; 32])> = HashMap::new();
    let mut recv_pending_direct: HashMap<
        String,
        (Vec<String>, Option<String>, Option<String>, u8),
    > = HashMap::new();
    // #161: first-offer hold start times per peer. On the typed-code path the
    // buffered offer is replayed at PAKE confirm, BEFORE DirectReady issues the
    // 0x02 identity challenge, so the first offer always arrives with identity
    // unresolved. The offer is held (re-injected) while identity resolution is
    // pending, bounded by RECV_IDENTITY_HOLD_DEADLINE from first sight so a
    // ceremony that never resolves cannot wedge the transfer.
    let mut recv_identity_hold: HashMap<String, std::time::Instant> = HashMap::new();
    // #161: how long the offer waits for identity to resolve before deciding.
    // Identity resolution normally settles in well under a second on a working
    // link; the window exists so a revoked device's cert (which resolves via
    // the challenge) reaches the gate's absolute Deny before the offer is
    // decided. A peer whose identity does not resolve within the window is
    // decided by the normal gate, which is the documented residual - see
    // PROVEN_CHALLENGE_DEADLINE, which must stay in lockstep with this so the
    // challenge's entry does not expire and let a re-issue clobber the nonce.
    const RECV_IDENTITY_HOLD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
    let mut recv_pake_done = code.is_none(); // only the code path runs the PAKE
    let recv_pake_budget = ports.env.pair_grace;
    // Overall bound: once we are matched into the sender's room, SOMEONE must
    // authenticate within this window or the whole `recv` fails loudly. Per-peer
    // budgets only drop individual mis-latch candidates; this is the backstop for
    // a genuinely absent / old sender. Armed on the first candidate channel.
    let mut recv_pake_overall_deadline: Option<Instant> = None;
    // Did ANY peer send PAKE traffic? A peer that runs a ceremony is a current
    // build, so the "older version" message is only true when none did.
    let mut recv_pake_heard = false;
    // Memory bound: a crowded room cannot blow us up. We mint at most this many
    // concurrent candidate ceremonies; further candidates are ignored (the real
    // sender is, in practice, among the first to share the room with the claimer).
    const RECV_MAX_CANDIDATES: usize = 8;
    // #211: the control socket must be ACCEPTING before "tunlion up" is printed.
    // A sibling `mint` can race the bind and silently fail to arm otherwise.
    // Create the control channel here (before the banner) and spawn the server
    // with a readiness signal the banner awaits. `ctl_tx` is held for the loop's
    // life so `ctl_rx` stays open (recv pends, never spins) even when we are not
    // the daemon and `serve` was not spawned.
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Req>();
    let mut ctl_ready: Option<tokio::sync::oneshot::Receiver<()>> = None;
    #[cfg(unix)]
    {
        if daemon && ports.daemon.daemon_alive() == Some(ports.env.pid) {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
            ctl_ready = Some(ready_rx);
            let ctl_tx = ctl_tx.clone();
            let log = log.clone();
            let host = host.clone();
            cleanup.tasks.push(tokio::spawn(async move {
                if let Err(e) = host.serve_control(ctl_tx, Some(ready_tx)).await {
                    // LOUD, not trace. Without the control socket every
                    // daemon-backed feature degrades silently -- warm links,
                    // `requests`, instant invitations -- and other commands then
                    // report things that are false, such as "daemon not running"
                    // while this daemon is plainly up. The common real cause is
                    // a socket path longer than the kernel allows (108 bytes on
                    // Linux, 104 on macOS), e.g. a deep TUNLION_CONFIG_DIR or a
                    // CI/macOS temp directory; found by a first-time-user test
                    // whose sandbox path was 110 bytes.
                    //
                    // FATAL now, not a log line: the startup below waits on the
                    // readiness signal this task drops, and stops the daemon with
                    // this reason. A daemon nobody can talk to is not "up".
                    log.critical(&format!(
                        "tunlion: control socket unavailable: {e}\n  \
                         without it, `status`, `set`, warm links, `tunlion requests` and \
                         instant invitations cannot reach this daemon, so it will not start"
                    ));
                }
            }));
        }
    }
    #[cfg(not(unix))]
    let _ = &ctl_tx;
    match &code {
        Some(c) => {
            // Split the typed code into (nameplate, words); send ONLY the
            // nameplate. The words become the SPAKE2 password held locally.
            let normalized = filament_pair::norm_code(c);
            let (np, pw) = filament_pair::split_code(&normalized);
            if pw.is_empty() || np.is_empty() {
                bail!("that code doesn't look right, expected something like brave-otter-371");
            }
            // Held to mint a fresh per-peer ceremony for each candidate. The words
            // live ONLY here and inside each Ceremony's SPAKE2 state; never sent.
            recv_pake_template = Some((pw.clone(), np.clone()));
            sio.emit("pair-claim", json!({ "nameplate": np, "v": 2 }))
                .await
                .ok();
        }
        None if daemon => {
            recv_pake_template = None; // no code claim, no ephemeral PAKE
                                       // C19: the daemon joins NO room. Presence-channel subscriptions
                                       // only, strangers can't see it, probe it, or offer to it.
                                       // Enrollment rendezvous: subscribe to enroll_channel(owner_pub)
                                       // when armed (outstanding non-expired auth key). Channel-based
                                       // (not room) because the server supports 1 room/socket and we
                                       // need the solo room for known-device discovery.
            let solo = format!("up-{}", fresh_secret());
            sess.room = Some(solo.clone());
            sess.emit(
                &sio,
                "join",
                json!({ "room": solo, "name": ports.env.display_name, "uid": my_uid }),
            )
            .await;
            // #211: the banner means SERVING, not "process started". Wait
            // (bounded) for the control socket to accept before announcing up;
            // a sibling `mint` that arms right after this line must not race a
            // socket that is not listening yet.
            if let Some(ready) = ctl_ready.take() {
                // Both a dropped sender and timeout fail startup. Neither is
                // evidence that the control socket is accepting requests.
                if let Err(reason) =
                    crate::recv::lifecycle::control_ready(ready, Duration::from_secs(5)).await
                {
                    bail!(
                        "the control socket {} could not be created ({reason:?}); the daemon is not starting",
                        host.control_sock_path()
                            .map_or_else(|| "<none>".to_string(), |p| p.display().to_string())
                    );
                }
            }
            if ports.identity.is_armed() {
                log.debug("enrollment armed: ephemeral devices may enroll");
            } else {
                log.debug("enrollment closed (no armed keys: mint or arm an auth-key to open)");
            }
            let chans: Vec<String> = devices.iter().map(|(_, s)| host.channel_of(s)).collect();
            let mut c = chans;
            if ports.identity.is_armed() {
                if let Some(uk) = host.user_key() {
                    let ek = ports.identity.enroll_channel(&uk.public_key_bytes());
                    if !c.contains(&ek) {
                        c.push(ek);
                    }
                }
            }
            // Fleet auto-mesh: the meeting point for same-owner devices goes in
            // the SAME list, because this is the subscribe the daemon actually
            // emits. (It rebuilds `c` from scratch and then overwrites
            // sess.channels, so anything pushed onto sess.channels before this
            // point is discarded.) Presence here authorizes nothing; admission
            // runs on the certificate. See cli/src/fleet.rs.
            if cfg!(feature = "fleet") {
                if let Some(fc) = ports.identity.fleet_channel() {
                    if !c.contains(&fc) {
                        c.push(fc);
                    }
                }
            }
            sess.emit(&sio, "subscribe", json!({ "channels": c })).await;
            sess.channels = c;
            log.say(&format!(
                "  {} tunlion up, {} known device{} {} {}",
                log.paint(Tone::Brand, "●"),
                devices.len(),
                if devices.len() == 1 { "" } else { "s" },
                log.glyph_arrow(),
                log.paint(Tone::Bold, &dir.display().to_string()),
            ));
            log.say(&log.paint(
                Tone::Dim,
                "  trusted devices only · invisible to strangers · Ctrl-C or `tunlion down` to stop",
            ));
            // C29: this is a SESSION, like a browser tab, pairing and petname
            // management happen right here.
            if ports.env.interactive_terminal {
                log.say(&log.paint(
                    Tone::Dim,
                    "  type a code to pair a new device · `pair` mints one · `devices` · `forget <name>`",
                ));
            }
        }
        None => {
            recv_pake_template = None; // local-network listen, no ephemeral PAKE
            let room = match &room {
                Some(r) => r.clone(),
                None => net::fetch_auto_room(&transport_context, server).await?,
            };
            // C22: proactive affordance, tell the user what they CAN do,
            // cargo-style gutter, before they have to guess.
            log.say(&format!(
                "  {} listening, same-network devices appear automatically  {}",
                log.paint(Tone::Brand, "●"),
                log.paint(Tone::Dim, &format!("(room {room} · dir {})", dir.display())),
            ));
            log.say(&log.paint(
                Tone::Dim,
                "  have a code? just type it here (like brave-otter-123) and press Enter",
            ));
            sess.room = Some(room.clone());
            sess.emit(
                &sio,
                "join",
                json!({ "room": room, "name": ports.env.display_name, "uid": my_uid }),
            )
            .await;
            // C12: announce on every known device's presence channel
            if !devices.is_empty() {
                let chans: Vec<String> = devices.iter().map(|(_, s)| host.channel_of(s)).collect();
                log.say(&format!("watching for {} known device(s)", devices.len()));
                sess.emit(&sio, "subscribe", json!({ "channels": chans }))
                    .await;
            }
        }
    }

    // L2 acceptor posture (computed here so it also gates the direct-QUIC path).
    // OFF unless TUNLION_L2=1 (opt-in) OR an active `up --shell` policy turns it
    // on (you can't ssh in without the acceptor). See its second use below.
    // L2/shell is ON when: an `--shell`/`--shell-only` policy turns it on, the
    // TUNLION_L2 opt-in is set, OR any known device has been `grant`ed shell (so
    // `tunlion grant <dev> shell` works on a plain `up` without restarting with a
    // flag, matching what the grant command tells the user). The per-device gate
    // below still denies every non-granted device, so this never widens access.
    // The launch posture (`--shell`/`--shell-only`, TUNLION_L2) is fixed for
    // the daemon's life: it is what `--i-know` was checked against, so a live
    // `set shell on` must not widen it past that gate. The GRANT half is not
    // fixed: it is recomputed at the top of every loop iteration below.
    let l2_launch = shell_policy.enables_l2() || ports.env.l2_forced;
    let mut l2_enabled = l2_launch || ports.store.any_shell_grant();

    let mut conn = cleanup.conn.insert(
        Conn::for_command(
            transport_context.clone(),
            server,
            sio.clone(),
            tx.clone(),
            my_uid.clone(),
            relay, // relay_only
            to,    // to_filter
            // P3 (GAP-3): the `up`/`up --shell` daemon acceptor is the canonical
            // long-lived / interactive session, so warm redundancy defaults ON for it
            // (a one-shot `recv` keeps daemon=false -> OFF).
            daemon, // warm_standby default
            // rung-1 direct-QUIC: take it when the env gate is set, when this is an
            // L2/ssh acceptor, OR when this is the long-lived `up` daemon. Any acceptor
            // MUST answer the initiator's transport-offer (direct-QUIC over the
            // reachable host candidate, e.g. Tailscale) rather than build a colliding
            // WebRTC peer (glare). For `up --shell` this kills the `tunlion shell --ssh`
            // "stuck while connecting" failure; for a plain `up` it kills the up<->up
            // glare/supersede churn (two known daemons each racing to be the WebRTC
            // initiator). See `direct_ok_for`. One-shot send/recv/pair (daemon=false)
            // are unaffected and keep their WebRTC default.
            ports.env.direct_ok,
            log.clone(),
            host.clone(),
        )
        // The CLI's terminal: sticky line, waiting questions, transfer bars, OSC 52
        // and the raw-mode echo. The loop drives them through `Presentation` so the
        // same body runs with no screen at all (a library consumer, a journal).
        .with_presentation(ports.present.clone()),
    );
    // WARM-HOLD: load configured warm-peers at daemon startup
    if daemon {
        conn.load_warm_peers_config();
    }
    // Signal listeners belong to the outer CLI adapter, active during startup
    // too. Cancellation is out of band from this invocation's event queue.
    // C29: the stdin owner also runs for an INTERACTIVE daemon (a terminal-
    // attached `tunlion up` is a session); `up --install` under systemd has
    // no tty, so headless daemons stay stdin-free.
    let interactive = !daemon || ports.env.interactive_terminal;
    let _tty_guard = if interactive && ports.env.interactive_terminal {
        ports.prompt.enter_raw_mode()
    } else {
        None
    };
    if interactive {
        cleanup.stdin =
            ports
                .prompt
                .spawn_stdin(tx.clone(), st.question_open.clone(), conn.present.clone());
    }
    // L3 (serve_tun mesh): the up daemon opens a TUN and routes IP packets across
    // its peer links when `tun-addr` is set. `auto` (recommended) derives a stable,
    // self-certifying overlay address from this device's Ed25519 overlay key; peers
    // learn+trust it via a signed `l3-announce` (below). A manual CIDR is the
    // advanced/PSK case (no announce). Off otherwise; Linux-only.
    // `l3_seen`: last announce received per pid, replayed once a datagram-capable
    // transport is installed, so a hello that races ahead of the link is not lost
    // (review fix #3).
    #[cfg(feature = "mesh")]
    let mut l3_seen: HashMap<String, Announce> = HashMap::new();
    #[cfg(not(feature = "mesh"))]
    let l3: Option<std::sync::Arc<dyn MeshTunnel>> = None;
    #[cfg(feature = "mesh")]
    let l3: Option<std::sync::Arc<dyn MeshTunnel>> = if daemon {
        match host.settings_get_str("tun-addr") {
            Some(setting) => {
                let (cidr, identity) = if setting == "auto" {
                    match host.overlay_identity() {
                        Ok(id) => (format!("{}/128", id.addr()), Some(id)),
                        Err(e) => {
                            log.say(&log.paint(Tone::Warn, &format!("  L3 disabled: {e}")));
                            (String::new(), None)
                        }
                    }
                } else {
                    (setting.clone(), None) // manual/PSK address, no crypto announce
                };
                if cidr.is_empty() {
                    None
                } else {
                    // Endpoint selection: `l3-mode` setting (kernel|userspace|auto),
                    // default Auto; TUNLION_L3_USERSPACE / `up --userspace` force
                    // userspace (handled inside L3::start via the env).
                    let mode = match host.settings_get_str("l3-mode").as_deref() {
                        Some("kernel") => L3Mode::Kernel,
                        Some("userspace") => L3Mode::Userspace,
                        _ => L3Mode::Auto,
                    };
                    match host.l3_start(&cidr, 1280, identity, mode) {
                        Ok(m) => {
                            let addr = m.my_addr().map(|a| a.to_string()).unwrap_or(cidr);

                            // Subnet router: if this machine offers prefixes, make
                            // the kernel actually carry them. Only in kernel-TUN
                            // mode, because userspace has no kernel route to
                            // forward FROM, and saying "routing" while forwarding
                            // nothing is the failure this whole module is written
                            // against.
                            // Same reader the announce paths use, so what the
                            // kernel is told to forward and what the wire
                            // advertises cannot diverge.
                            let advertised: Vec<String> = advertised_prefixes(
                                host.settings_get_str("advertise-routes").as_deref(),
                            );
                            if !advertised.is_empty() {
                                if m.is_userspace() {
                                    log.say(&log.paint(
                                        Tone::Warn,
                                        &format!(
                                            "  advertise-routes is set ({}) but L3 is in userspace mode; a subnet router needs the kernel TUN, so nothing is being carried",
                                            advertised.join(", ")
                                        ),
                                    ));
                                } else {
                                    let snat = host.settings_get_bool("route-snat");
                                    match ports.daemon.subnet_enable(IFNAME, &advertised, snat) {
                                        Ok(_applied) => log.say(&format!(
                                            "  {} carrying {} for peers{}",
                                            log.paint(Tone::Ok, log.glyph_ok()),
                                            advertised.join(", "),
                                            if snat { " (masqueraded)" } else { "" }
                                        )),
                                        // LOUD, not swallowed: a router that cannot
                                        // forward must not look like one that can.
                                        Err(e) => log.say(&log.paint(
                                            Tone::Err,
                                            &format!(
                                                "  cannot carry {}: {e}",
                                                advertised.join(", ")
                                            ),
                                        )),
                                    }
                                }
                            }
                            if m.is_userspace() {
                                log.say(&format!(
                                    "  {} L3 overlay {} (userspace, zero privilege)",
                                    log.paint(Tone::Brand, "●"),
                                    addr
                                ));
                                log.say(&log.paint(
                                    Tone::Warn,
                                    "    host firewall/nftables are NOT enforced here; only mesh membership + the expose allowlist gate access",
                                ));
                                log.say(
                                    "    native tools reach <peer>.mesh via `tunlion forward <peer>:<port> --socks` (no kernel route in userspace)",
                                );
                                // Auto-start SOCKS5 proxy when kernel TUN is unavailable.
                                // Opt-out via --no-proxy-fallback or `tunlion set auto-proxy off`.
                                let auto_proxy =
                                    host.settings_get_bool("auto-proxy") && !no_proxy_fallback;
                                if auto_proxy {
                                    // Bind FIRST, then say what is true. Another daemon
                                    // (another HOME on this machine) or a hand-started
                                    // proxy may hold 1080 already.
                                    match ports.daemon.start_proxy(&server, relay).await {
                                        Ok((port, lines)) => {
                                            let note = if port == 1080 {
                                                String::new()
                                            } else {
                                                " (1080 was taken)".to_string()
                                            };
                                            log.say(&format!(
                                                "  {} started SOCKS5 proxy on 127.0.0.1:{port}{note} (set your tools' proxy to this)",
                                                log.paint(Tone::Ok, log.glyph_ok())
                                            ));
                                            for line in lines {
                                                log.say(&format!("  {line}"));
                                            }
                                        }
                                        Err(why) => log.say(&log.paint(
                                            Tone::Warn,
                                            &format!(
                                                "  no SOCKS5 proxy: {why}. To run one on a free port: `tunlion forward <device>:<port> --socks --port <free port>`"
                                            ),
                                        )),
                                    }
                                }
                            } else {
                                // Kernel mode is dual-stack: show the v4 address too
                                // (userspace has no v4 endpoint yet, so it is omitted
                                // above to avoid implying a route that does not exist).
                                let v4 = m
                                    .my_addr_v4()
                                    .map(|a| format!(" / {a}"))
                                    .unwrap_or_default();
                                log.say(&format!(
                                    "  {} L3 overlay {}{} on tunlion0",
                                    log.paint(Tone::Brand, "●"),
                                    addr,
                                    v4
                                ));
                                // Show the .mesh name that resolves to this machine.
                                let my_name = host.hostname();
                                log.say(&format!(
                                    "    this machine resolves as {}{}",
                                    sanitize_host(&my_name),
                                    ".mesh"
                                ));
                            }
                            // Add this machine's own address to MagicDNS so
                            // `<name>.mesh` resolves locally (not just peers).
                            // Uses the tunlion device name (from `tunlion set name`
                            // or hostname if unset), sanitized for DNS.
                            if let Some((v6, v4_addr)) = m.identity_addrs() {
                                let my_name = ports
                                    .env
                                    .config_name
                                    .clone()
                                    .unwrap_or_else(|| host.hostname());
                                let v4 = Some(v4_addr);
                                m.names_insert("__self__", &sanitize_host(&my_name), v6, v4)
                                    .await;
                                if !m.is_userspace() {
                                    m.refresh_hosts().await;
                                }
                                // Configure sshd to listen on overlay addresses if enabled.
                                if host.settings_get_bool("sshd-overlay") {
                                    let v6_str = v6.to_string();
                                    let v4_str = v4_addr.to_string();
                                    if let Err(e) =
                                        ports.daemon.configure_sshd_overlay(&v6_str, &v4_str)
                                    {
                                        log.say(
                                            &log.paint(Tone::Warn, &format!("  sshd-overlay: {e}")),
                                        );
                                    }
                                }
                            }
                            Some(m)
                        }
                        Err(e) => {
                            log.say(&log.paint(Tone::Warn, &format!("  L3 disabled: {e}")));
                            None
                        }
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    // `tunlion expose`: once the overlay is up, bind the persisted ports on the
    // overlay address. The optional exposer lives in the host server; the loop
    // only asks it to reconcile.
    if let Some(m) = l3.as_ref() {
        let n = ports.servers.start_expose(m.clone()).await;
        if n > 0 {
            log.say(&format!(
                "  {} exposing {} port{} on the overlay",
                log.paint(Tone::Brand, "●"),
                n,
                if n == 1 { "" } else { "s" }
            ));
            if m.is_userspace() {
                log.say(&log.paint(
                    Tone::Dim,
                    "    (userspace overlay: paired peers reach these directly; the host firewall does not filter them)",
                ));
            }
        }
    }
    // overlay address and forward each to its local target. Reconciled live on a
    // ReloadExpose control request (expose/unexpose without a restart).
    // G-k: peer-left delivery is best-effort, a browser can close having
    // delivered every byte yet never emit its leave (observed under load,
    // gate 6). Tick the loop on a 2s timeout so a fallback quiet-check can
    // exit cleanly instead of idling to the connect-timeout.
    let mut last_quiet: Option<Instant> = None;
    let quiet_window = ports.env.quiet_window;
    // C30 phase 2: roster reconciliation from sync digests, a missed
    // peer-joined/left self-corrects. Absence must hold for TWO consecutive
    // digests before a drop (one digest can race a join in flight). The
    // per-surface counters and the liveness deferral live on `Conn` because
    // each link must be judged by exactly one surface (see `digest_note`).
    // A fresh signaling sid is not evidence of absence. The server applies our
    // re-subscribe as part of that same `sync`, while the PEER is still
    // re-subscribing on its own new sid, so the first digest on the new socket
    // can legitimately omit it. Skip the first digest after a Welcome or a
    // successful reconnect and start both windows over; otherwise a miss from
    // before the flap plus this one retires a live link.
    let mut digest_epoch_fresh = false;
    let mut digest_alone = false;
    // C30 phase 3: link mini-sync, state pings every ~10s per link.
    let mut last_state_ping = Instant::now();
    // L2 (ssh/TCP tunnel) acceptor: one mux per link, created on the first
    // l2-open seen on that link. `l2_enabled` is computed once above (it also
    // gates the direct-QUIC path); reused here for the mux/cap machinery.
    let mut l2_muxes: HashMap<String, Arc<l2::Mux>> = HashMap::new();
    // Shell-class opens parked while their link's possession proof is in
    // flight (settle-then-evaluate): re-driven on proof, denied at the
    // settle bound. Bounded (2 per link, 32 per daemon) at park time.
    let mut parked_opens: Vec<ParkedOpen> = Vec::new();
    // Sweep counter for the settle retry cadence: while an open is parked,
    // every third sweep (about 300ms at the parked tick) re-issues the
    // possession challenge even when a hold is nominally live.
    let mut settle_ticks: u32 = 0;
    // Warm-pty session -> (pid, sid), so a `pty-resize` op relays to the right stream.
    // Outstanding `reach` liveness probes for THIS loop. A pong is routed back
    // only into the registry owned by the loop that sent the ping, bound to the
    // link it arrived on and the peer that link names, so a pong for another
    // probe cannot complete this loop's waiter. The loop's handle is dropped on
    // exit; a probe still in flight holds its own handle and removes itself
    // when it answers or its bounded window expires.
    // Warm ssh-bootstrap reply sockets awaiting the peer's ack (see PendingBootstraps).
    // Warm-link reuse: ONLY the registered `up` daemon exposes the local control
    // socket (a short-lived `recv`/`send` must never bind it and steal the
    // daemon's path). When a sibling `tunlion shell --ssh`/`netcat`/`forward` asks to
    // reach a peer we already hold a link to, we open a new L2 stream over that
    // warm link instead of making the sibling establish a fresh one. `ctl_tx`
    // was created (and `serve` spawned, when we are the daemon) before the
    // banner, so a mint racing the bind cannot happen; `ctl_rx` is consumed
    // below.

    // Hold `ctl_tx` for the loop's life so `ctl_rx` stays open (recv pends, never
    // spins) even when `serve` was not spawned (non-unix, or not the daemon).
    // web-shell (#4): persistent PTY sessions, keyed by a stable browser-chosen
    // session id, OUTLIVE the link that opened them. A dropped data channel
    // DETACHES (does not kill) the shell; a reconnect with the same session id
    // reattaches and replays buffered output. Process-wide for the whole loop.
    // Per-link map of the PTY sids currently bound to a session on that link, so
    // a link drop can DETACH exactly those sessions (and a clean l2-close ends
    // the right one). pid -> (sid -> session_id).
    let mut pty_bindings: HashMap<String, HashMap<u32, String>> = HashMap::new();
    // web-shell: per-sid resize senders are now owned by each Mux (l2.rs) so they
    // are freed on every teardown path (H-1: closes the prior pty_resizers leak).
    // Bug 5: surface the single-host mDNS wedge hint once after repeated stuck.
    let mut stuck_while_connecting = 0u32;
    let mut wedge_hint_shown = false;
    let _saw_known_peer: HashSet<String> = HashSet::new();
    // C12 live-pairing: the roster (`devices`) is loaded ONCE at startup, and
    // KnownPeer events only fire for channels we've SUBSCRIBED. A device paired
    // into the shared store by a SEPARATE `tunlion pair` process AFTER the
    // daemon is up was therefore invisible until restart, it never got a
    // subscription, so its "appeared, connecting" flow never fired and it
    // could not connect (no transfer, no web-shell). We now re-scan the store
    // on a modest cadence and subscribe to any NEW device's channel live; the
    // session digest (which includes `sess.channels`) repairs a lost subscribe
    // on the next tick. Existing channels and live links are untouched.
    let mut known_channels: std::collections::HashSet<String> =
        devices.iter().map(|(_, s)| host.channel_of(s)).collect();
    if cfg!(feature = "fleet") {
        known_channels.extend(ports.identity.fleet_channel());
    }
    let mut last_devices_scan = Instant::now();
    // Fleet auto-mesh link state, keyed by peer sid.
    //   pending  dialed off the fleet channel, certificate NOT yet proven. Such a
    //            link is reachable but authorizes nothing, and in particular must
    //            not receive an L3 route (see the l3-announce arm below).
    //   verified fleet-hello checked out against our owner key.
    //   greeted  we already sent ours, so a mutual hello does not ping-pong.
    // L3/fleet binding on a transport with NO RFC-5705 exporter (the relay /
    // DataChannel path). `Announce::verify` and `fleet-hello` are bound to the
    // link so a captured message cannot be replayed onto another one, and
    // direct-QUIC supplies that binding for free. A DataChannel does not, and
    // webrtc-rs exposes no DTLS exporter, so the two ends establish one by
    // challenge instead: each side picks a random nonce and sends it, and the
    // PEER signs against it. Freshly generated per link, so a message captured
    // on one link is useless on the next, which is the property the exporter was
    // providing.
    //   ours[pid]   what WE chose: verify messages arriving from that peer.
    //   theirs[pid] what THEY chose: sign messages we send to them.
    let mut bind_ours: HashMap<String, Vec<u8>> = HashMap::new();
    let mut bind_theirs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut fleet_pending: std::collections::HashSet<String> = Default::default();
    let mut fleet_verified: std::collections::HashSet<String> = Default::default();
    // Offers that arrived while this link's `fleet-hello` was still in flight.
    // Verification is MUTUAL and the two directions are not synchronized: the
    // sender proves US, then offers, and its offer can beat our verification of
    // IT. Deciding then reads `binding=None` on a link that is about to be
    // Proven, and the gate declines a transfer it would have allowed a moment
    // later. Measured as a ~1-in-6 spurious decline between two siblings. The
    // answer is to wait for the identity to settle, not to widen the gate:
    // whether the peer is authorized is exactly what is still being computed.
    let mut fleet_deferred_offers: Vec<(String, serde_json::Value, Instant)> = Vec::new();
    // Brokered meeting places we have joined: channel -> its one-time secret.
    // Kept so a peer arriving on one is proved by that secret, exactly as a
    // paired peer is proved by a pair secret.
    // The value also carries the device key of the sibling that brokered it,
    // so revoking that key closes the meeting place it opened (revocation_live).
    let mut brokered: HashMap<String, (String, crate::recv::revocation::BrokeredBy)> =
        HashMap::new();
    // Links dialed on a brokered meeting place, by pid -> who brokered it. Each
    // adoption of such a link (first DirectReady and every repair) is re-bound
    // to the broker's proven identity, never to the name the peer announced.
    let mut brokered_pids: HashMap<String, crate::recv::revocation::BrokeredBy> = HashMap::new();
    // Forget / revoke, live (revocation_live.rs). `revocation_snap` is the store
    // the last sweep acted on; a different one, or a `revocation-sync` request
    // (`revocation_sweep_now`), runs the sweep on this iteration's scan.
    // `revoked_secrets` collects held secrets the store dropped, wherever they
    // were noticed, until the sweep closes the links that used them.
    let mut revocation_snap = ports.daemon.revocation_snapshot();
    let mut revocation_sweep_now = false;
    // Links whose device's invitation ended, already withdrawn (said once).
    let mut expired_unrouted: std::collections::HashSet<String> = Default::default();
    let mut revoked_secrets: std::collections::HashSet<String> = Default::default();
    // Meeting places of devices forgotten while this daemon ran. The server keeps
    // us listed on them, so the forgotten device still finds us there; a dial on
    // one is answered `not-recognized` (a refusal it reports at once, exit 4)
    // instead of being buffered until its sender times out.
    let mut forgotten_channels: std::collections::HashSet<String> = Default::default();
    // Links whose peer claimed a pairing this store does not hold (its
    // pair-proof failed: forgotten here, or never paired). Every shell-class
    // open on such a link is refused as unrecognized before any handler runs,
    // so a forgotten device hears who refused it and why, not "serving is off"
    // or "no grant", which named fixes that cannot apply.
    let mut unrecognized_pids: std::collections::HashSet<String> = Default::default();
    let mut revocation_waiters: Vec<Req> = Vec::new();
    // How long an offer may wait for its sender to prove itself before we decide
    // anyway. Bounded on purpose: waiting forever for a hello that never comes
    // would turn a clean decline into the 45s timeout it replaced.
    let fleet_offer_grace = ports.env.fleet_offer_grace;
    let mut fleet_greeted: std::collections::HashSet<String> = Default::default();

    // Daemon-managed mount state: the daemon holds the sshfs child processes and
    // monitors their health centrally instead of spawning per-mount threads.
    let mut last_mount_check = Instant::now();

    // WARM-HOLD: periodic check for warm peers that need connections
    let mut last_warm_hold_tick = Instant::now();

    // P2 (GAP-2): outer reconnect / re-announce loop state for the long-lived
    // acceptor. `reconnect(false)` means a severed signaling TCP leaves the
    // socket dead with NO further events, the acceptor zombies and the sender
    // can't rediscover it (the documented `no peer connected` failure that
    // up_supervisor.sh patched from outside the binary). We close it IN-CORE:
    //  - `last_signaling`  : monotonic time of the last inbound signaling event;
    //                        any inbound Ev that originates from the socket bumps
    //                        it (welcome/synced/peer-*/signal/known-peer/...).
    //  - silence watchdog  : if it goes silent past `signaling_silence_ms` (and
    //                        a forced `sync` emit doesn't restore it), the link
    //                        is dead, re-dial. This is the AUTHORITATIVE trigger
    //                        because a hard TCP sever fires no close callback.
    //  - Ev::SignalingDown : the socket.io close/error fast-path accelerant.
    // Only the daemon acceptor self-heals (`signaling_self_heal`); the one-shot
    // recv/send paths re-invoke fresh, so they keep failing fast (unchanged).
    // TUNLION_TEST_NO_SIGNALING_RECONNECT reverts to the OLD no-outer-loop path
    // so the signaling-drop gate's A/B baseline can prove the acceptor ZOMBIES
    // without the fix (the detector/loop is load-bearing, not incidental).
    let signaling_self_heal = daemon && !test_hooks::no_signaling_reconnect();
    let mut last_signaling = Instant::now();
    let mut signaling_down_since: Option<Instant> = None;
    let mut reconnect_attempt: u32 = 0;
    let mut last_reconnect_try = Instant::now();
    let mut reconnect_wait = Duration::ZERO;
    // When the current connection came up (None while down). The ladder only
    // restarts after a connection that stayed up signaling_health::STABLE_AFTER.
    let mut signaling_up_since: Option<Instant> = Some(Instant::now());
    let mut down_reason = String::new();
    // When the forced `sync` probe went out (None: no probe outstanding).
    let mut probed_silence: Option<Instant> = None;
    // Repeated reconnect lines are collapsed, not written once per cycle.
    let mut signaling_log = signaling_health::LogCollapse::default();
    let mut health = signaling_health::Health::default();
    if signaling_self_heal {
        health.note_serving();
        host.report_signaling(health.snapshot_json());
    }
    let mut last_watchdog = Instant::now();
    // Link self-heal cadence (the multi-minute-outage fix, #3). A transport that
    // died past the QUIC idle timeout lingers in `links` as a zombie and SUPPRESSES
    // the KnownPeer re-dial (start_direct early-returns when a link exists), so the
    // overlay never recovers. We DROP dead links here (so the next KnownPeer
    // re-push re-establishes, single-driver + glare-safe = the model's proven
    // disconnect->recover) but do NOT re-dial ourselves - a timer-based re-dial on
    // BOTH ends caused a supersede storm. The L3 route is intentionally KEPT
    // (continuity), so the re-establish's add_peer swaps the transport under the
    // same overlay IP and the session resumes.
    let mut last_link_health = Instant::now();
    // Periodic liveness observation: refreshes lastSeen for devices with a
    // live link, independent of traffic. Without this an idle-but-connected
    // device would decay against its offline budget and be reaped while alive.
    let mut last_liveness_observe = Instant::now();
    // Periodic sweep: marks lapsed delegated records (deadline passed, no
    // observation revived them). State-only; the gate already denies past the
    // deadline, the sweep is what makes LAPSED visible in `devices`.
    let mut last_sweep = Instant::now();
    let mut last_renewal_check = Instant::now();
    let mut last_route_reconcile = Instant::now();
    let mut last_wg_check = Instant::now();
    // Owner-only roster push: mint + push the mesh roster on membership change,
    // validity refresh, or a newly-established link.
    let mut last_roster_push = Instant::now();

    // The single linearized readiness edge: published exactly once, immediately
    // before dispatch, after every required initialization. It is deliberately
    // distinct from the console banner (printed before Conn/sector setup) and
    // from optional post-dispatch work. Nothing awaited and optional may sit
    // between this edge and entering the loop. The systemd notifier and the
    // `up --detach` ready marker consume this one edge, so they cannot disagree
    // about when the daemon was ready. No-op for a one-shot receive, which has
    // transfer-completion semantics instead of an "engine is serving" edge.
    if daemon {
        readiness.publish(|| {
            // systemd Type=notify: announce readiness once the serving loop is
            // about to run. No-op when not run under systemd.
            ports.daemon.sdnotify_ready();
            ports.daemon.sdnotify_status("up - serving");
            // The same edge for `up --detach`, which has no systemd to tell it.
            ports.daemon.mark_daemon_ready();
        });
    }

    // Optional mount restoration is NOT a readiness gate. It starts after the
    // ready edge and after dispatch, reports degraded status on failure, and is
    // owned by this invocation so `RecvCleanup::finish` cancels and joins it on
    // normal return. A slow or hung restore can no longer delay serving after
    // readiness was announced.
    {
        let host = host.clone();
        let log = log.clone();
        let server = server.to_string();
        cleanup.tasks.push(tokio::spawn(async move {
            if let Err(e) = host.restore_mounts(&server, relay).await {
                log.say(&format!("warning: failed to restore mounts: {e}"));
            }
        }));
    }

    // The deadline starts when the loop starts, not when the process did: the
    // caller asked "wait N seconds for a sender", not "be ready in N seconds".
    let receive_started = Instant::now();

    loop {
        sync_tasks.reap_sync_tasks(log.as_ref()).await;
        // Reap completed blocking writers every iteration: the handles are
        // owned until their write lands, but a long-lived daemon must not keep
        // one per chunk for its whole life.
        writer_tasks.reap(log.as_ref()).await;
        // Live posture: a `tunlion grant <dev> shell` (or the revoke of the last
        // shell grant) applies to the RUNNING daemon on the next open. Computed once at startup, it silently required a
        // restart and refused every granted device with "shell serving is off".
        let was_l2 = l2_enabled;
        l2_enabled = l2_launch || ports.store.any_shell_grant();
        // A grant (or the revoke of the last one) changed what this machine
        // serves: say so on the links that are already up. The `caps` message
        // went out only at ChannelReady, so a browser that was connected when
        // the owner ran `grant` showed no Shell button until it reconnected.
        // Spawned: a send must never block this loop on a dead peer.
        if let Some(caps) = caps_reannounce(was_l2, l2_enabled) {
            for l in conn.links.values() {
                if let Some(t) = l.transport.clone() {
                    let caps = caps.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(5), t.send_control(&caps))
                            .await;
                    });
                }
            }
        }
        // systemd liveness watchdog: ping on a throttle (well under WatchdogSec).
        // If this loop WEDGES on an await, the pings stop and systemd restarts us
        // - the backstop for the stall that also freezes the reconnect code.
        if daemon && last_watchdog.elapsed() >= Duration::from_secs(5) {
            ports.daemon.sdnotify_watchdog();
            last_watchdog = Instant::now();
        }
        // Shutdown-hang repro hook: once links are live, freeze the event loop
        // forever, faithfully simulating a peer transport whose inline write
        // never returns. The graceful Ev::Interrupted can no longer be processed;
        // only the signal-owned force-exit watchdog can still terminate us. No-op
        // unless TUNLION_TEST_WEDGE_LOOP is set (test-hooks builds only).
        if test_hooks::wedge_loop_on_shutdown() && !conn.links.is_empty() {
            std::future::pending::<()>().await;
        }
        if !daemon && !keep_open && st.by_sid.is_empty() {
            if let Some(what) = sender_cancelled.take() {
                conn.present.clear_sticky();
                let _ = tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
                bail!(
                    "the sender cancelled the transfer because it could not read its file ({what}); \
                     nothing of it was kept here{}",
                    if st.completed > 0 {
                        format!(" ({} other file(s) were received)", st.completed)
                    } else {
                        String::new()
                    }
                );
            }
        }
        // A one-shot receive that refused or declined everything it was offered
        // ends here, at once, with its own reason and code (recv_report). It
        // used to hold the line for the sender, which had already been told
        // no, and then blame it: "the sender is unreachable ... Nothing was
        // received", exit 6, for a receiver whose own disk was full. It waits
        // only for the sender to leave, or a few seconds for another offer.
        if !daemon
            && !keep_open
            && st.completed == 0
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && st.recv_pending_offers.is_empty()
        {
            if let Some(since) = report.since_last_refusal() {
                let sender_gone = conn.rejoin.waiting_rejoin.is_some() || conn.links.is_empty();
                if sender_gone || since >= Duration::from_secs(3) {
                    if let Some(e) = report.refused_outcome() {
                        conn.present.clear_sticky();
                        let _ =
                            tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
                        return Err(anyhow::Error::new(crate::recv::report::RefusedFailure {
                            kind: e.kind,
                            message: e.message,
                        }));
                    }
                }
            }
        }
        // A one-shot receive whose sender left and did not come back ends here,
        // saying what is actually on disk and how it can actually continue.
        // The shared rejoin expiry in `next_ev` said "partial state kept for
        // resume" whether or not anything was kept, and "re-run `receive
        // <code>`" for a code that already burned.
        if !daemon {
            if let Some(since) = conn.rejoin.waiting_rejoin {
                if since.elapsed() > conn.rejoin.rejoin_window {
                    conn.present.clear_sticky();
                    let why = format!(
                        "the sender is unreachable: it disconnected and did not come back within {}s",
                        conn.rejoin.rejoin_window.as_secs()
                    );
                    bail!(crate::recv::transfer_truth::sender_gone_message(
                        &why,
                        &crate::recv::transfer_truth::kept_partials(&session_parts),
                        &dir,
                        code_claimed,
                    ));
                }
            }
        }
        // A one-shot receive with a deadline ends here, before selecting again:
        // nothing has arrived, so there is nothing left to wait for. Exit 6 is
        // "nobody answered", which a script can tell apart from a failed
        // transfer (1) or a refused one (4).
        if receive_timed_out(
            receive_started.elapsed(),
            timeout.map(Duration::from_secs),
            st.completed,
        ) {
            conn.present.clear_sticky();
            let secs = timeout.unwrap_or(0);
            let _ = tokio::time::timeout(Duration::from_secs(1), sio.disconnect()).await;
            return Err(anyhow::Error::new(receive_timeout_failure(secs)));
        }
        if daemon {
            cleanup.watchdog.tick(log.clone());
        }
        cleanup.tasks.reap(log.as_ref()).await;
        let ev = tokio::select! {
            biased;
            // Warm-link reuse request from a sibling process. Handle it inline
            // (we own `conn`/`l2_muxes` here), then fall through like a tick. For
            // a non-daemon this branch pends forever (ctl_tx held, serve unspawned).
            req = ctl_rx.recv() => {
                if let Some(req) = req {
                    // Bootstrap defers its reply (awaits the peer's ack via this
                    // loop), so it can't go through the inline handle_warm_req; it
                    // stashes the socket in pending_bootstrap instead.
                    #[cfg(unix)]
                    {
                        // `tunlion set` live-reconfigure: re-read the changed key
                        // into this loop's live state, then report whether it took
                        // without a restart. Handled here (we own dir/policy/sess).
                        if let ReqKind::Reconfigure { key } = &req.kind {
                            let key = key.clone();
                            let live = ports.servers.apply_reconfigure(
                                &key, &mut dir, &mut shell_policy, &mut shell_user,
                                l2_enabled, &mut sess, &sio, &my_uid,
                            ).await;
                            req.reply(&json!({ "ok": true, "live": live })).await;
                        } else if matches!(&req.kind, ReqKind::RevocationSync) {
                            // `devices forget` / `revoke`: apply the store NOW.
                            // Parked, and answered by the sweep below on this
                            // same iteration, so the reply means it is done.
                            revocation_sweep_now = true;
                            revocation_waiters.push(req);
                        } else if matches!(&req.kind, ReqKind::Wake) {
                            // Nothing to do here: receiving this event IS the point.
                            // The loop now runs its top-level arm gate this same
                            // iteration, so a just-minted invitation's enrollment
                            // channel is subscribed before the joiner can arrive.
                            req.reply(&json!({ "ok": true })).await;
                        } else if matches!(&req.kind, ReqKind::ReloadExpose) {
                            // `tunlion expose`/`unexpose`: reconcile overlay
                            // listeners from expose.json. live:true only if L3 is up.
                            let (live, count): (bool, usize) = if l3.is_some() {
                                (true, ports.servers.reload_expose().await)
                            } else {
                                (false, 0)
                            };
                            req.reply(&json!({ "ok": true, "live": live, "count": count })).await;
                        } else if matches!(&req.kind, ReqKind::Reload) {
                            // `tunlion update` reload: only safe when a supervisor
                            // will bring us back (systemd sets INVOCATION_ID). Reply
                            // FIRST (the shutdown closes the ctl socket), then take the
                            // SAME graceful path SIGTERM does - which cleanly closes the
                            // QUIC links so peers re-establish and L3 recovers - by
                            // raising SIGTERM on ourselves. systemd's Restart=always
                            // then starts the new binary with fresh ambient caps: no
                            // manual restart, no sudo. Unsupervised, we decline (exiting
                            // would just leave the node down).
                            let supervised = ports.env.supervised;
                            req.reply(&json!({ "ok": true, "reloading": supervised })).await;
                            if supervised {
                                log.say("tunlion: reloading onto the updated binary (graceful restart)");
                                ports.daemon.request_reload();
                            }
                        } else if matches!(&req.kind, ReqKind::Dial { .. }) {
                            // Overlay dial (proxy `.mesh` fallback): resolve the peer
                            // to its VERIFIED overlay address ourselves, dial it over
                            // L3, and bridge the ctl socket to it. Spawned so the
                            // long-lived splice never blocks the event loop.
                            #[cfg(feature = "mesh")]
                            if let ReqKind::Dial { peer, port } = &req.kind {
                                let (peer, port) = (peer.clone(), *port);
                                match l3.as_ref() {
                                    Some(m) => {
                                        let m = m.clone();
                                        tokio::spawn(async move {
                                            let Some(addr) = m.addr_of(&peer).await else {
                                                req.reject("unknown overlay peer").await;
                                                return;
                                            };
                                            // BOUNDED. A port the peer did not expose can
                                            // black-hole the SYN, and an unbounded dial held
                                            // the proxy's client with no reply at all.
                                            let t0 = std::time::Instant::now();
                                            match tokio::time::timeout(OVERLAY_DIAL_BOUND, m.dial(addr, port)).await {
                                                Ok(Ok(mut stream)) => {
                                                    // An exposed port's overlay listener completes
                                                    // the handshake before `expose` dials what is
                                                    // behind it, so a connect is not an answer.
                                                    // Settle first: the peer closing at once means
                                                    // nothing listens there (SOCKS 0x05), and the
                                                    // proxy must not say "granted" and then hold.
                                                    let window = overlay_settle_window(t0.elapsed());
                                                    let mut first = vec![0u8; 16 * 1024];
                                                    let got = match tokio::time::timeout(window, tokio::io::AsyncReadExt::read(&mut stream, &mut first)).await {
                                                        Ok(Ok(0)) | Ok(Err(_)) => {
                                                            req.reject(OVERLAY_TARGET_CLOSED).await;
                                                            return;
                                                        }
                                                        Ok(Ok(n)) => n,
                                                        Err(_) => 0,
                                                    };
                                                    let mut sock = req.accept().await;
                                                    if got > 0 && tokio::io::AsyncWriteExt::write_all(&mut sock, &first[..got]).await.is_err() {
                                                        return;
                                                    }
                                                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
                                                }
                                                Ok(Err(e)) => req.reject(&format!("overlay dial failed: {e}")).await,
                                                Err(_) => req.reject(OVERLAY_DIAL_TIMED_OUT).await,
                                            }
                                        });
                                    }
                                    None => req.reject("L3 overlay is not up").await,
                                }
                            }
                            #[cfg(not(feature = "mesh"))]
                            req.reject("L3 overlay not supported on this build").await;
                        } else if matches!(&req.kind, ReqKind::Bootstrap { .. }) {
                            ports.daemon.warm_bootstrap(&conn, &tx, req).await;
                        } else if matches!(&req.kind, ReqKind::Mount { .. }) {
                            ports.daemon.mount(req, &server, relay).await;
                        } else if matches!(&req.kind, ReqKind::Unmount { .. }) {
                            ports.daemon.unmount(req).await;
                        } else if matches!(&req.kind, ReqKind::ListMounts) {
                            ports.daemon.list_mounts(req).await;
                        } else if matches!(&req.kind, ReqKind::MountHealth { .. }) {
                            ports.daemon.mount_health(req).await;
                        } else if matches!(&req.kind, ReqKind::CapStatus) {
                            let counts = host.cap_shadow_counts();
                            let action_counts = host.cap_action_counts();
                            req.reply(&json!({
                                "ok": true,
                                "counts": {
                                    "la_authorized": counts.la_authorized,
                                    "la_denied": counts.la_denied,
                                    "la_narrowed": counts.la_narrowed,
                                    "la_no_header": counts.la_no_header,
                                    "ld_authorized": counts.ld_authorized,
                                    "ld_denied": counts.ld_denied,
                                    "ld_no_header": counts.ld_no_header,
                                    "ceiling_denied": counts.ceiling_denied,
                                    "ceiling_admitted": counts.ceiling_admitted,
                                },
                                "by_action": action_counts,
                                "flip_ready": counts.flip_ready(),
                                // The signaling link as the serving loop sees it, so
                                // `status` and `doctor` can tell a daemon that answers
                                // here but is off the server (or keeps dropping) from a
                                // healthy one. The host reports it; null means it has
                                // no signaling link to describe.
                                "signaling": host.signaling_snapshot(),
                                "summary": counts.summary(),
                                // #244: the LIVE shell posture. `revoke <dev> shell`
                                // reads this so it can say when the shell it just
                                // revoked is still being handed out by the policy.
                                "shell_policy": shell_policy.label(),
                                "shell_auto": shell_policy.auto_names(),
                                // Every other daemon flag, so `up` over this
                                // daemon can tell whether the flags it was
                                // given are already in effect.
                                "launch": host.launch_report(
                                    server,
                                    &dir,
                                    relay,
                                    shell_user.as_deref(),
                                    no_proxy_fallback,
                                ),
                            })).await;
                        } else if matches!(&req.kind, ReqKind::ListWarm) {
                            ports.daemon.list_warm(req, &conn).await;
                        } else if let ReqKind::FleetRendezvous { name } =
                            req.kind.clone()
                        {
                            // Broker a PRIVATE meeting place for a one-shot.
                            //
                            // The reliability problem this solves: a one-shot
                            // `send` joins the fleet channel, where every sibling
                            // is, and has to work out which of them is the target
                            // while they all answer. The daemon does not have that
                            // problem, because it already holds a
                            // certificate-verified link to the peer. So it mints a
                            // single-use secret, hands it over THAT link, and both
                            // ends meet on channel_of(secret) where exactly two
                            // parties exist.
                            //
                            // The secret doubles as the proof, which is why this
                            // reuses the most-tested path in the product rather
                            // than adding one: `send --to` already knows how to
                            // meet a known device on a shared secret. Its
                            // authenticity is inherited from the link it travelled
                            // over, which was verified by certificate.
                            match crate::conn::warm_link_for(&conn, &name) {
                                Some((pid, t)) => {
                                    let secret = fresh_secret();
                                    let sent = t
                                        .send_control(&json!({
                                            "type": "fleet-rendezvous",
                                            "secret": secret,
                                        }))
                                        .await
                                        .is_ok();
                                    if sent {
                                        log.debug(&format!(
                                            "fleet-rendezvous: brokered for '{name}' over pid={pid}"
                                        ));
                                        req.reply(&json!({ "ok": true, "secret": secret })).await;
                                    } else {
                                        req.reject("could not reach that peer over the warm link").await;
                                    }
                                }
                                None => {
                                    req.reject(&format!("no verified link to '{name}'")).await;
                                }
                            }
                        } else if matches!(&req.kind, ReqKind::ListPending) {
                            let mut requests = host.requests_load();
                            host.requests_expire(&mut requests);
                            req.reply(&json!({
                                "ok": true,
                                "requests": requests,
                            })).await;
                        } else if let ReqKind::ApproveRequest { id, allow, expires } = &req.kind {
                            let id = *id;
                            let allow = allow.clone();
                            let expires = *expires;
                            let mut requests = host.requests_load();
                            host.requests_expire(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                let peer = r.peer.clone();
                                let cap = r.capability.clone();
                                if let Some(bar) = host.request_bar(&peer) {
                                    // The gate refuses this device whatever is
                                    // granted; never record an approval for it.
                                    r.status = REQUEST_WITHDRAWN.to_string();
                                    host.requests_save(&requests);
                                    req.reject(&crate::consent::request_bar_refusal(id, &peer, bar)).await;
                                } else if cap != allow {
                                    req.reject(&format!("request {id} is for '{cap}', not '{allow}'")).await;
                                } else if !cap::grant_active(expires, cap::now_secs()) {
                                    req.reject("grant expiry must be in the future").await;
                                } else if let Err(e) = host.device_set_cap(&peer, &cap, true, Some(expires)) {
                                    req.reject(&format!("grant failed: {e}")).await;
                                } else if let Err(e) = host.issue_signed_bounded_grant(&peer, &cap, expires).and_then(|signed| {
                                    if signed { ports.store.mark_bounded_cap_source(&peer, &cap, "signed").map_err(|e| e.to_string()) } else { Ok(()) }
                                }) {
                                    req.reject(&format!("signed grant failed: {e}")).await;
                                } else {
                                    r.status = "approved".to_string();
                                    r.granted_at = Some(cap::now_secs());
                                    host.requests_save(&requests);
                                    req.reply(&json!({ "ok": true, "id": id, "peer": peer, "capability": cap, "expires": expires })).await;
                                }
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else if let ReqKind::DenyRequest { id } = &req.kind {
                            let id = *id;
                            let mut requests = host.requests_load();
                            host.requests_expire(&mut requests);
                            if let Some(r) = requests.iter_mut().find(|r| r.id == id && r.status == "pending") {
                                r.status = "denied".to_string();
                                host.requests_save(&requests);
                                req.reply(&json!({ "ok": true, "id": id })).await;
                            } else {
                                req.reject(&format!("request {id} not found or not pending")).await;
                            }
                        } else {
                            // Auto-warm: feed LRU for pty sessions (bounded, no leak).
                            if let ReqKind::Pty { peer, .. } = &req.kind {
                                conn.note_warm_use(peer);
                            }
                            ports.daemon.warm_req(&conn, &mut l2_muxes, &tx, req).await;
                        }
                    }
                    #[cfg(not(unix))]
                    ports.daemon.warm_req(&conn, &mut l2_muxes, &tx, req).await;
                }
                None
            }
            res = tokio::time::timeout(
                // While opens are parked the loop ticks fast, so a proof
                // dispatched this iteration is acted on promptly instead of
                // up to a full 2s later (a settled release must not miss its
                // own bound). Idle cost is unchanged when nothing is parked.
                if parked_opens.is_empty() {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(100)
                },
                crate::recv::events::next_ev(&mut rx, &conn, !st.pending.is_empty()),
            ) => match res {
                Ok(Ok(ev)) => ev,
                // A daemon is not one sender's receiver: a peer that left
                // mid-transfer and outlived its rejoin window closes that
                // window, and the daemon keeps serving everyone else (its
                // .part stays for a later resume). A one-shot ends here.
                Ok(Err(e)) if daemon && conn.rejoin.waiting_rejoin.is_some() => {
                    log.debug(&format!(
                        "tunlion: rejoin window closed ({e:#}); the daemon keeps serving"
                    ));
                    conn.rejoin.waiting_rejoin = None;
                    None
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => None, // tick: run the settle sweep + quiet-check below
            },
        };

        // Settle sweep: re-drive parked shell-class opens whose link proved
        // since parking (same link AND same device key, else the proof is
        // for someone else), deny those past their settle bound. Zero cost
        // when nothing is parked. Re-drive calls the same handler the live
        // path uses, which re-gathers everything fresh -- a revoke during
        // the hold therefore denies. Never blocks: releases and denies are
        // ordinary handler calls in this loop's turn, not spawned tasks
        // awaiting anything (the loop must stay live; see serve_exec).
        if !parked_opens.is_empty() {
            let now = Instant::now();
            let mut fire = Vec::new();
            let mut expire = Vec::new();
            let mut stale = Vec::new();
            parked_opens.retain(|p| {
                let live = conn
                    .link(&p.pid)
                    .map(|l| (l.identity_binding, l.identity_device_pub, l.generation));
                match sweep_arm(p.device_pub, p.generation, live, now, p.deadline) {
                    // The re-driven handler re-gathers everything fresh, so
                    // a revoke during the hold denies there.
                    SweepArm::Fire => {
                        fire.push(p.clone());
                        false
                    }
                    SweepArm::IdentityChanged => {
                        stale.push((p.clone(), "peer identity changed during hold"));
                        false
                    }
                    // The parked open belongs to the dead transport; deny
                    // rather than serving it there or lingering to expiry.
                    SweepArm::Replaced => {
                        stale.push((p.clone(), "link replaced during hold"));
                        false
                    }
                    SweepArm::Dropped => {
                        stale.push((p.clone(), "link dropped during hold"));
                        false
                    }
                    SweepArm::Expired => {
                        expire.push(p.clone());
                        false
                    }
                    SweepArm::Keep => true,
                }
            });
            // A close may only ride the SAME link generation the open was
            // parked on. sids are per-Mux and start at 0, so after a
            // reconnect the parked sid can name an unrelated live stream on
            // the new link -- sending there would kill someone else's
            // stream. When the generation moved, the denial is local-only
            // (the peer's own stream died with its old link anyway).

            for p in expire {
                // Name the link AND the fact that no proof arrived. A bare
                // "timed out settling" hid the single most important fact about
                // this failure for hours: the peer answered no challenge at all
                // (it is usually still re-establishing), as opposed to answering
                // with something we rejected.
                log.say(&format!(
                    "l2: {:?} open timed out settling ({}ms); denying -- {} answered no possession challenge",
                    p.kind, p.settle_ms, p.pid,
                ));
                if conn.link(&p.pid).map(|l| l.generation) == Some(p.generation) {
                    if let Some(t) = conn.transport_of(&p.pid) {
                        let _ = t
                            .send_control(&serde_json::json!({
                                "type": "l2-close",
                                "sid": p.sid,
                                "err": settle_timeout_reason(p.settle_ms),
                            }))
                            .await;
                    }
                } else {
                    log.say(&format!(
                        "l2: {:?} open expired on a replaced link; not answering",
                        p.kind
                    ));
                }
                // The link just failed its own identity probe for the whole
                // window, which is the strongest evidence we get that it is
                // stale (a live peer answers in milliseconds; observed live:
                // the peer answers, the frame never arrives, because the
                // connection it answers on is not the one we hold). Dropping
                // it stops `warm_link_for` from selecting it again, so the
                // caller's retry -- we send a RETRYABLE reason -- establishes
                // a fresh link instead of parking on the same corpse.
                sync_tasks.cancel_sync_for_pid(&p.pid, log.as_ref()).await;
                conn.drop_link(&p.pid);
            }
            for (p, reason) in stale {
                log.say(&format!("l2: {:?} open dropped: {reason}", p.kind));
                if conn.link(&p.pid).map(|l| l.generation) == Some(p.generation) {
                    if let Some(t) = conn.transport_of(&p.pid) {
                        let _ = t
                            .send_control(&serde_json::json!({
                                "type": "l2-close",
                                "sid": p.sid,
                                "err": reason,
                            }))
                            .await;
                    }
                }
            }
            // An open can outlive the challenge issued for it: the link may
            // have churned (re-adopted pid, replaced transport) between the
            // challenge and the park, and a proof nobody solicited never
            // arrives. Re-issue while it waits; the issuer dedupes on a LIVE
            // hold, so this cannot clobber an in-flight nonce.
            settle_ticks = settle_ticks.wrapping_add(1);
            let retry_due = settle_ticks % 3 == 0;
            for p in &parked_opens {
                let Some(t) = conn.transport_of(&p.pid) else {
                    continue;
                };
                // A live hold for THIS transport normally means "already
                // challenged, do not clobber the nonce". Two exceptions,
                // both needed for a park to terminate in a proof:
                //   - the hold belongs to a REPLACED transport (the peer's
                //     answer can never arrive on the link we have now), and
                //   - the retry cadence fires: a challenge whose answer was
                //     lost in flight -- observed live, the peer logs
                //     "identity challenge answered" while the owner's frame
                //     dispatch never sees it -- must be retried on the SAME
                //     link, or the open waits out its whole window on a
                //     proof that no longer exists anywhere. Each retry puts
                //     a fresh nonce in the map and the peer answers the
                //     latest one, so a match is guaranteed once a frame
                //     survives.
                let held_same_link = st
                    .pending_proven
                    .lock()
                    .unwrap()
                    .get(&p.pid)
                    .map(|(held_t, deadline)| {
                        !ports.identity.hold_expired(*deadline) && Arc::ptr_eq(held_t, &t)
                    })
                    .unwrap_or(false);
                // A held nonce is still usable: RE-SEND the same challenge
                // (idempotent for the peer, and it cannot race the reply the
                // way a fresh nonce would). A fresh nonce is minted only when
                // the hold is absent, expired, or belonged to another
                // transport, which is exactly when the old nonce is dead.
                let nonce_alive = identity_nonces
                    .get(&p.pid)
                    .map(|(_, issued, _)| now.duration_since(*issued) < PROVEN_CHALLENGE_DEADLINE)
                    .unwrap_or(false);
                if held_same_link && nonce_alive {
                    if retry_due {
                        if ports
                            .identity
                            .resend_identity_challenge(&conn, &p.pid, &mut identity_nonces)
                            .await
                        {
                            log.debug(&format!(
                                "settle: re-sent the held identity challenge to {}",
                                p.pid
                            ));
                        }
                    }
                    continue;
                }
                ports
                    .identity
                    .issue_proven_challenge_and_hold(
                        &conn,
                        &p.pid,
                        &t,
                        &st.pending_proven,
                        &mut identity_nonces,
                    )
                    .await;
                // The hold must not outlive its own deadline: the readiness
                // sites spawn this timer, and the settle re-drive has to as
                // well, or an expired hold lingers and suppresses later
                // challenges for the same link. Remove only if the deadline
                // we just installed is the one still there (a newer hold for
                // the same link must survive our timer).
                let pending = st.pending_proven.clone();
                let hold_pid = p.pid.clone();
                let installed = st
                    .pending_proven
                    .lock()
                    .unwrap()
                    .get(&hold_pid)
                    .map(|(_, d)| *d)
                    .unwrap_or_else(Instant::now);
                tokio::spawn(async move {
                    tokio::time::sleep(PROVEN_CHALLENGE_DEADLINE).await;
                    let mut m = pending.lock().unwrap();
                    if m.get(&hold_pid).map(|(_, d)| *d) == Some(installed) {
                        m.remove(&hold_pid);
                    }
                });
            }
            for p in fire {
                log.say(&format!("l2: {:?} open proven; re-driving", p.kind));
                let Some(t) = conn.transport_of(&p.pid) else {
                    crate::conn::dropped_no_transport(
                        log.as_ref(),
                        &p.pid,
                        &format!("parked {:?} open", p.kind),
                    );
                    continue;
                };
                match p.kind {
                    ParkKind::Exec => {
                        ports
                            .servers
                            .open_exec(
                                &mut conn,
                                p.pid.clone(),
                                &p.v,
                                &shell_policy,
                                &shell_user,
                                &mut l2_muxes,
                                l2_enabled,
                                &mut parked_opens,
                            )
                            .await;
                    }
                    ParkKind::Pty => {
                        crate::recv::servers::shell::open_pty(
                            &ports,
                            &mut conn,
                            p.pid.clone(),
                            &p.v,
                            &shell_policy,
                            &shell_user,
                            &mut l2_muxes,
                            &mut pty_bindings,
                            l2_enabled,
                            &mut parked_opens,
                        )
                        .await;
                    }
                    ParkKind::SshSign => {
                        ports
                            .servers
                            .ssh_sign(
                                &mut conn,
                                &p.pid,
                                t.clone(),
                                &p.v,
                                &shell_policy,
                                &mut parked_opens,
                            )
                            .await;
                    }
                    ParkKind::Sync => {
                        // The re-drive re-checks transport under its own label;
                        // admission then resolves it again from the same link.
                        if stop.is_cancelled() {
                            continue;
                        }
                        if conn.transport_of(&p.pid).is_none() {
                            crate::conn::dropped_no_transport(
                                log.as_ref(),
                                &p.pid,
                                &format!("parked {:?} open", p.kind),
                            );
                            continue;
                        }
                        if let Some((sid, task)) = crate::recv::servers::dispatch_open_sync(
                            &ports,
                            host.as_ref(),
                            &mut conn,
                            &p.pid,
                            &p.v,
                            &mut l2_muxes,
                            &dir,
                            &mut parked_opens,
                        )
                        .await
                        {
                            sync_tasks
                                .track_sync_task(p.pid.clone(), sid, task, log.as_ref())
                                .await;
                        }
                    }
                    ParkKind::Forward => {
                        if let Some(task) = crate::recv::servers::open_forward(
                            &ports,
                            host.as_ref(),
                            &mut conn,
                            p.pid.clone(),
                            &p.v,
                            &shell_policy,
                            &mut l2_muxes,
                            l2_enabled,
                            &mut parked_opens,
                        )
                        .await
                        {
                            cleanup.tasks.push(task);
                        }
                    }
                }
            }
        }

        // C30: converge session state (no-op unless diverged/stale/unconfirmed).
        sess.tick(&sio).await;

        // L1-a ephemeral PAKE progression (recv code path), PER CANDIDATE PEER.
        // For each candidate's ceremony whose link is up: send our SPAKE2 element,
        // then (once K + both DTLS fingerprints exist) the key-confirmation MAC.
        // Each ceremony is independent, so a decoy peer that never replies just
        // sits until ITS budget expires (dropped below), never blocking the real
        // sender's ceremony. The agreed secret is DISCARDED after auth, never
        // stored. Once one peer authenticates (`recv_pake_done`) we stop driving
        // candidates: the sender is settled.
        if recv_code_path && !recv_pake_done {
            let pids: Vec<String> = st.recv_cers.keys().cloned().collect();
            for pid in pids {
                let send_msg = st
                    .recv_cers
                    .get_mut(&pid)
                    .and_then(|c| c.take_msg_payload());
                if let Some(data) = send_msg {
                    sio.emit("signal", json!({ "to": pid, "data": data }))
                        .await
                        .ok();
                }
                let has_k = st.recv_cers.get(&pid).map(|c| c.has_k()).unwrap_or(false);
                if has_k {
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    if let Some((my_fp, their_fp)) = fps {
                        let conf = st
                            .recv_cers
                            .get_mut(&pid)
                            .and_then(|c| c.take_confirm_payload(&my_fp, &their_fp));
                        if let Some(data) = conf {
                            sio.emit("signal", json!({ "to": pid, "data": data }))
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        // Per-peer budgets: a candidate whose ceremony never completes within its
        // own budget is dropped INDIVIDUALLY (an unrelated decoy, or an old peer
        // that won't run v2). Dropping it never bails the receive; the real sender
        // keeps its own live budget. Only relevant before someone authenticates.
        if recv_code_path && !recv_pake_done {
            let now = Instant::now();
            let expired: Vec<String> = st
                .recv_deadlines
                .iter()
                .filter(|(_, dl)| now > **dl)
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in expired {
                st.recv_deadlines.remove(&pid);
                st.recv_cers.remove(&pid);
                st.recv_pending_offers.remove(&pid);
                log.debug(&format!(
                    "recv: candidate {pid} did not authenticate in budget, dropped"
                ));
            }
        }
        // Overall deadline: the backstop. Once we are matched into the sender's
        // room a candidate channel arms this; if NO peer authenticates within it,
        // fail the whole `recv` loudly (a genuinely absent / old sender, mirroring
        // the previous single-budget intent and TUNLION_PAIR_GRACE_SECS) rather
        // than hanging forever.
        if recv_code_path && !recv_pake_done {
            if let Some(dl) = recv_pake_overall_deadline {
                if Instant::now() > dl {
                    bail!(recv_pake_expired_message(
                        recv_pake_heard,
                        recv_pake_budget.as_secs()
                    ));
                }
            }
        }

        // P2 (GAP-2): the OUTER RECONNECT / RE-ANNOUNCE loop for the long-lived
        // acceptor. Runs only in the daemon path; the one-shot recv/send paths
        // re-invoke fresh on failure and so never need it.
        if signaling_self_heal {
            // (1) Liveness accounting. Any inbound signaling event proves the
            // socket is alive; a successful `sync` ack (Ev::Synced) is the
            // strongest signal (the server answered). The fast-path close/error
            // callback marks the link down immediately, but ONLY for the
            // current connection: a close of one this loop already replaced is
            // history (see signaling_health, defect 1). Acting on it is what
            // turned one late close into an endless reconnect storm.
            //
            // An inbound event no longer resets the backoff ladder: the new
            // connection's own `welcome` did, so the ladder could never climb
            // (defect 2). Only a connection that stays up STABLE_AFTER does.
            let mut saw_down = false;
            match &ev {
                Some(Ev::SignalingDown(reason, closed)) => {
                    if signaling_health::close_is_current(*closed, sio.id()) {
                        saw_down = true;
                        down_reason = reason.clone();
                    } else {
                        log.debug(&format!(
                            "  signaling: ignoring the close of replaced connection {closed} ({reason}); current is {}",
                            sio.id()
                        ));
                    }
                }
                Some(
                    Ev::Welcome(_)
                    | Ev::Synced(_)
                    | Ev::SignalingAlive
                    | Ev::PeerJoined(_)
                    | Ev::PeerLeft(_)
                    | Ev::Signal(_)
                    | Ev::KnownPeer(_)
                    | Ev::KnownPeerLeft(_)
                    | Ev::PairMatched(_)
                    | Ev::PairOk(_)
                    | Ev::PairCode(_)
                    | Ev::PairUsed(_)
                    | Ev::PairError(_),
                ) => {
                    last_signaling = Instant::now();
                    probed_silence = None;
                }
                _ => {}
            }

            // (2) Silence watchdog, the AUTHORITATIVE trigger. A hard TCP sever
            // fires no close callback, so we watch the inbound gap. Once it
            // exceeds the threshold, fire ONE forced `sync` (the heartbeat); if
            // the socket is alive the server's `synced` ack lands within a tick
            // and resets the gap. If the probe then goes unanswered for its own
            // window, the socket is dead, declare it down.
            //
            // The probe's window is measured from when it was SENT. It used to
            // be judged on the inbound gap alone, so after a freeze longer than
            // twice the threshold the very next loop iteration declared the link
            // dead before the probe could be answered, and re-dialed while the
            // old socket's close was still in flight (the storm's seed).
            let silence = net::signaling_silence_ms();
            let silent_ms = last_signaling.elapsed().as_millis() as u64;
            if signaling_down_since.is_none() {
                let mut declare: Option<String> = None;
                if saw_down {
                    declare = Some(format!("closed ({down_reason})"));
                } else if silent_ms >= silence {
                    match probed_silence {
                        None => {
                            // Heartbeat probe: an ACK'd `sync` round-trip, the only
                            // liveness signal that works for a room-less idle
                            // acceptor. `sess.tick()` can't serve here: it returns
                            // early when there is no room (the `up` case) AND when
                            // the session is already confirmed-fresh, so on a quiet
                            // link it emitted nothing and the watchdog falsely
                            // reconnected every ~30 s, churning presence. The server
                            // acks `sync` unconditionally; the ack wakes the loop as
                            // Ev::SignalingAlive, which resets the gap below.
                            probed_silence = Some(Instant::now());
                            net::heartbeat(&sio, sess.heartbeat_payload(), tx.clone()).await;
                        }
                        Some(sent)
                            if silent_ms >= silence.saturating_mul(2)
                                && sent.elapsed() >= signaling_health::PROBE_WINDOW =>
                        {
                            declare = Some(format!("silent for {}s", silent_ms / 1000));
                        }
                        Some(_) => {}
                    }
                }
                if let Some(why) = declare {
                    let now = Instant::now();
                    signaling_down_since = Some(now);
                    // The ladder restarts only if the link that just went down
                    // had been up long enough to count as stable.
                    reconnect_attempt = signaling_health::attempt_after_close(
                        reconnect_attempt,
                        signaling_up_since.map(|t| now.saturating_duration_since(t)),
                    );
                    signaling_up_since = None;
                    reconnect_wait = signaling_health::reconnect_delay(
                        reconnect_attempt,
                        signaling_health::jitter_unit(),
                    );
                    last_reconnect_try = now;
                    health.note_down(&why);
                    host.report_signaling(health.snapshot_json());
                    // Visible (not just debug): a node dropping off signaling was
                    // previously silent until it bit someone. Collapsed, so a
                    // link that keeps dropping cannot fill the disk with it.
                    if let Some(line) = signaling_log.admit(
                        "down",
                        &format!("signaling link {why}, reconnecting..."),
                        now,
                    ) {
                        log.say(&log.paint(Tone::Warn, &line));
                    }
                    ports
                        .daemon
                        .sdnotify_status("signaling down - reconnecting");
                }
            }

            // (3) Re-dial with bounded, jittered backoff. Idempotent: a fresh
            // `welcome` re-asserts room + channel subscriptions through the C30
            // session (sess.invalidate forces it next tick). Live DATA links are
            // NOT torn down, they ride independent WebRTC/QUIC transports and
            // keep flowing across the cosmetic signaling reconnect (the #28
            // contract).
            if signaling_down_since.is_some() && last_reconnect_try.elapsed() >= reconnect_wait {
                last_reconnect_try = Instant::now();
                reconnect_attempt = reconnect_attempt.saturating_add(1);
                reconnect_wait = signaling_health::reconnect_delay(
                    reconnect_attempt,
                    signaling_health::jitter_unit(),
                );
                // Drop the old client (no-op if already gone). Its close, when
                // it lands, carries the old id and is ignored above.
                let _ = sio.disconnect().await;
                match net::reconnect_signaling(&transport_context, server, tx.clone()).await {
                    Ok(new_sio) => {
                        sio = new_sio;
                        cleanup.signaling = Some(sio.clone());
                        conn.sio = sio.clone();
                        // C30: a fresh sid voids everything the server held,
                        // re-assert room + channels on the next tick. Re-fire
                        // the fast-path join/subscribe immediately too.
                        sess.invalidate();
                        // The re-subscribe below (and the `sync` emitted by
                        // `sess.tick`) puts every known-device channel back on
                        // the new socket BEFORE any digest is acted on. The
                        // first digest is still skipped as an absence signal:
                        // the peer's own new sid may not have resubscribed yet.
                        digest_epoch_fresh = true;
                        conn.reset_digest_reconcile();
                        if let Some(room) = sess.room.clone() {
                            sess.emit(
                                &sio,
                                "join",
                                json!({ "room": room, "name": ports.env.display_name, "uid": my_uid }),
                            )
                            .await;
                        }
                        if !sess.channels.is_empty() {
                            let chans = sess.channels.clone();
                            sess.emit(&sio, "subscribe", json!({ "channels": chans }))
                                .await;
                        }
                        sess.tick(&sio).await;
                        // optimistic: a clean connect proves reachability.
                        last_signaling = Instant::now();
                        signaling_down_since = None;
                        signaling_up_since = Some(Instant::now());
                        probed_silence = None;
                        health.note_redialed();
                        host.report_signaling(health.snapshot_json());
                        // Visible: pairs with the "reconnecting..." line so the
                        // recovery is observable end to end. Collapsed with it.
                        if let Some(line) = signaling_log.admit(
                            "up",
                            "signaling reconnected, re-announcing presence",
                            Instant::now(),
                        ) {
                            log.say(&log.paint(Tone::Ok, &line));
                        }
                        ports.daemon.sdnotify_status("up - serving");
                    }
                    Err(e) => {
                        // DEBUG, resilience internal (signaling reconnect retry).
                        log.debug(&log.paint(
                            Tone::Dim,
                            &format!(
                                "  signaling reconnect failed ({e}), retrying in {}ms",
                                reconnect_wait.as_millis()
                            ),
                        ));
                    }
                }
            }
        }

        // Arm-gate: toggle enrollment-channel subscription EVERY loop iteration
        // based on the armed set. Channel-based (not room) because the server
        // supports 1 room/socket. This MUST run at loop top-level, not nested in
        // the signaling-reconnect Ok arm: a stable daemon (signaling never down)
        // would otherwise never subscribe and no ephemeral device could enroll.
        if let Some(uk) = host.user_key() {
            let ek = ports.identity.enroll_channel(&uk.public_key_bytes());
            let armed = ports.identity.is_armed();
            let subscribed = sess.channels.contains(&ek);
            if armed && !subscribed {
                sess.channels.push(ek.clone());
                let _ = sio.emit("subscribe", json!({ "channels": [ek] })).await;
            } else if !armed && subscribed {
                sess.channels.retain(|c| c != &ek);
                let _ = sio
                    .emit("channel-goodbye", json!({ "channels": [ek] }))
                    .await;
            }
        }

        // Link self-heal (#3): drop links whose transport has DIED so the KnownPeer
        // re-dial (re-pushed on signaling reconnect + periodic sync) can rebuild
        // them. Same action as the on-demand DropLink handler, just proactive; the
        // L3 route is intentionally NOT retracted (continuity), so the re-establish's
        // add_peer swaps the fresh transport under the same overlay IP. We do NOT
        // re-dial here on purpose (single-driver = the model's proven, churn-free
        // recovery; a both-ends timer re-dial storms).
        if daemon && last_link_health.elapsed() >= Duration::from_secs(8) {
            last_link_health = Instant::now();
            let dead: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| !t.is_alive()))
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in dead {
                log.debug(&format!(
                    "tunlion: link to '{pid}' died, dropping so it can re-connect"
                ));
                sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                conn.drop_link(&pid);
                // Removing the mux is not ending its streams: every served
                // session holds its own Arc, so a bare remove left a remote
                // exec's stdin pipe open and its command running for as long
                // as the command liked (observed: five minutes of `sleep`
                // after the initiator was gone). End them, and detach the
                // shells this link carried so their idle reaper runs.
                crate::recv::servers::shell::retire_link(
                    &ports,
                    &pid,
                    &mut l2_muxes,
                    &mut pty_bindings,
                )
                .await;
            }
        }

        // LIVENESS OBSERVATION: a device with a live link is alive regardless of
        // traffic. Refresh lastSeen periodically for linked devices so an idle
        // but connected device never decays against its offline budget. This is
        // a PERIODIC OBSERVATION of link-up state, deliberately not an event
        // fired by message receipt (a traffic-driven refresh would reap healthy
        // quiet devices exactly the way xats reaped chief-ux).
        if daemon && last_liveness_observe.elapsed() >= Duration::from_secs(8) {
            last_liveness_observe = Instant::now();
            let live: Vec<String> = conn
                .links
                .iter()
                // Present, not merely open: a relay link to a stopped or wiped
                // peer stays `is_alive()` while our own keepalive writes keep
                // succeeding, and touching it here kept that device "last seen
                // just now" forever. See daemon_ctl::peer_present.
                .filter(|(_, l)| {
                    l.transport.as_ref().is_some_and(|t| {
                        ports
                            .daemon
                            .peer_present(t.is_alive(), l.direct, t.heard_ms(), t.idle_ms())
                    })
                })
                .map(|(_, l)| l.shown().to_string())
                .collect();
            for who in live {
                ports.store.devices_touch(&who, None, None);
            }
        }

        // SWEEP: mark lapsed delegated records whose effective deadline has
        // passed and which no observation revived. Runs every 30s; keeps the
        // record as evidence (option b, decided deliberately).
        if daemon && last_sweep.elapsed() >= Duration::from_secs(30) {
            last_sweep = Instant::now();
            let lapsed = ports.store.devices_sweep_lapsed(filament_id::now_secs());
            if lapsed > 0 {
                log.say(&format!(
                    "{} {lapsed} device(s) lapsed (offline past their budget)",
                    log.paint(Tone::Warn, log.glyph_warn())
                ));
            }
        }

        // WIREGUARD RECONCILE. On a timer, and deliberately NOT on an event.
        //
        // The first version hooked the moment a peer joined the L3 plane, which
        // is when its ANNOUNCE arrives. A link that starts relayed and upgrades
        // to direct upgrades AFTER that, so the hook saw the relay transport and
        // declined forever: the rig showed "DIRECT-CONNECT ok (route:
        // direct-quic)" in the same log as "WireGuard skipped". Reconciling on a
        // tick is order-independent, picks up a link that goes direct later, and
        // is idempotent, which an event hook can only approximate.
        //
        // Each attempt is spawned rather than awaited: the two ends rendezvous
        // on a QUIC bi-stream, so whichever side ticks first waits for the
        // other, and blocking the daemon loop on that would stall everything.
        if daemon
            && last_wg_check.elapsed() >= Duration::from_secs(10)
            && host
                .settings_get_str("wireguard")
                .map(|v| v == "on" || v == "true")
                .unwrap_or(false)
        {
            last_wg_check = Instant::now();
            if let Some(l3) = l3.as_ref() {
                if ports.daemon.wg_usable() {
                    let ours = l3.my_addr().map(|a| a.to_string()).unwrap_or_default();
                    for (who, addr, t) in l3.peers_with_transport().await {
                        // Direct links only: WireGuard needs a real UDP endpoint
                        // to send to, and a relay link has none to name.
                        let Some(sa) = t.remote_addr() else { continue };
                        if t.quic_connection().is_none() {
                            continue;
                        }
                        if !ports.daemon.wg_claim_attempt(&addr.to_string()) {
                            continue; // already announced to this peer
                        }
                        let (pubkey, port) = match ports.daemon.wg_local_offer() {
                            Ok(v) => v,
                            Err(e) => {
                                ports.daemon.wg_release_attempt(&addr.to_string());
                                log.debug(&format!("  wg: cannot bring up the interface ({e})"));
                                continue;
                            }
                        };
                        let _ = sa;
                        // Straight down the peer's own transport: the control
                        // channel every other tunlion message uses.
                        let _ = t
                            .send_control(&json!({
                                "type": "wg-key",
                                "pubkey": pubkey,
                                "port": port,
                            }))
                            .await;
                        log.debug(&format!("  wg: announced our key to {who}"));
                    }
                }
            }
        }

        // ROUTE RECONCILE: re-evaluate installed routes on a timer, not only on
        // an inbound announce. The case that matters most is a peer going
        // SILENT, and a silent peer sends no announce, so an announce-driven
        // reconciler is deaf to exactly the event it most needs to hear. For an
        // exit node that gap is the difference between a stale entry and a
        // machine holding a default route into a tunnel nobody is carrying.
        if daemon && last_route_reconcile.elapsed() >= Duration::from_secs(15) {
            last_route_reconcile = Instant::now();
            if let Some(l3) = l3.as_ref() {
                l3.reconcile_routes().await;
            }
        }

        // RENEWAL: ask a primary to re-sign this device's certificate before it
        // expires. ON A TIMER, not only when a link comes up: a device that
        // stays connected for its whole certificate lifetime would otherwise
        // never re-check and would expire while online, which is exactly the
        // silent death renewal exists to prevent. Found by running it, not by
        // reading it: the link-up trigger alone left a live device dying.
        //
        // Cheap: `maybe_request_cert_renewal` returns immediately unless this
        // device is a fleet member whose certificate is in its last third, so
        // the common case is a few comparisons. It asks every live peer because
        // only a primary can answer and we do not know which one that is.
        if daemon && last_renewal_check.elapsed() >= Duration::from_secs(30) {
            last_renewal_check = Instant::now();
            let live: Vec<String> = conn
                .links
                .iter()
                .filter(|(_, l)| l.transport.as_ref().is_some_and(|t| t.is_alive()))
                .map(|(pid, _)| pid.clone())
                .collect();
            for pid in live {
                ports.identity.maybe_request_cert_renewal(&conn, &pid).await;
            }
        }

        // ROSTER (v1, owner-only): push the mesh roster over live links on a
        // membership change, a validity refresh, or a newly-established link.
        // Runs faster than the sweep so a new link gets the roster promptly.
        if daemon && last_roster_push.elapsed() >= Duration::from_secs(5) {
            last_roster_push = Instant::now();
            conn.roster_maintenance().await;
        }

        // Daemon-managed mount health check: the host server owns the mount
        // table and the child processes; the loop only paces it.
        if daemon && last_mount_check.elapsed() >= Duration::from_secs(30) {
            last_mount_check = Instant::now();
            ports.daemon.mount_health_tick(host.as_ref()).await;
        }

        // WARM-HOLD: periodically check for warm peers that need connections.
        // This keeps recently-used and explicitly configured peers connected
        // so `tunlion reach`/`ssh` is instant. Runs every 10s, daemon-only.
        if daemon && last_warm_hold_tick.elapsed() >= Duration::from_secs(10) {
            last_warm_hold_tick = Instant::now();
            // Warm-all is the DEFAULT (auto-warm setting, opt-out). L3 forces it on:
            // the overlay routes over these links, opting out must not break L3.
            let auto_warm = l3.is_some() || host.settings_get_bool("auto-warm");
            let _ = conn.warm_hold_tick(auto_warm).await;
        }

        // C12 live-pairing: pick up devices paired AFTER we started (a separate
        // `tunlion pair` writes them into the shared store atomically). Re-read
        // every ~2s, subscribe to any channel we don't already watch, and feed
        // them into `devices` so the KnownPeer handler recognizes them. We never
        // re-subscribe existing channels or touch live links. Daemon-only: a
        // one-shot `recv`/`send` has a fixed roster for its short lifetime.
        if daemon && (revocation_sweep_now || last_devices_scan.elapsed() >= Duration::from_secs(2))
        {
            last_devices_scan = Instant::now();
            // Forget / revoke, live. Runs FIRST so a forgotten secret is out of
            // `devices` before anything below can re-add or dial it.
            let snap = ports.daemon.revocation_snapshot();
            if revocation_sweep_now || (snap.is_some() && snap != revocation_snap) {
                revocation_sweep_now = false;
                if snap.is_none() {
                    // A store that cannot be read is never "everything was
                    // forgotten"; the per-open gate fails closed on it anyway.
                    for req in revocation_waiters.drain(..) {
                        req.reply(&json!({ "ok": false, "error": "device store unreadable" }))
                            .await;
                    }
                } else {
                    revocation_snap = snap;
                    revoked_secrets.extend(ports.daemon.prune_to_store(&mut devices));
                    // Meeting places a now-revoked sibling brokered.
                    brokered.retain(|_, (sec, broker)| {
                        let keep = !ports.identity.device_cert_revoked(&broker.device_pub);
                        if !keep {
                            revoked_secrets.insert(sec.clone());
                        }
                        keep
                    });
                    if !revoked_secrets.is_empty() {
                        let gone: std::collections::HashSet<String> =
                            revoked_secrets.iter().map(|s| host.channel_of(s)).collect();
                        known_channels.retain(|c| !gone.contains(c));
                        let before = sess.channels.len();
                        sess.channels.retain(|c| !gone.contains(c));
                        if sess.channels.len() != before {
                            sess.invalidate();
                        }
                    }
                    let mut doomed: Vec<(String, String)> = Vec::new();
                    // Doomed links whose device KEY is revoked in place (its
                    // pair secret still held): told "device revoked", not
                    // "not recognized".
                    let mut key_revoked: std::collections::HashSet<String> = Default::default();
                    let mut unrouted: Vec<String> = Vec::new();
                    for (pid, l) in &conn.links {
                        let facts = crate::recv::revocation::LinkFacts {
                            secret: l.expected_secret.as_ref().map(|(_, s)| s.as_str()),
                            device_pub: l.identity_device_pub,
                        };
                        if crate::recv::revocation::link_must_close(
                            &facts,
                            &revoked_secrets,
                            &|p: &[u8; 32]| ports.daemon.key_listed(p),
                        ) {
                            // Forgotten (its secret removed) reads "not
                            // recognized", as every later open is answered;
                            // "device revoked" only for a key revoked in place.
                            let secret_gone =
                                facts.secret.is_some_and(|s| revoked_secrets.contains(s));
                            if !secret_gone
                                && l.identity_device_pub
                                    .as_ref()
                                    .is_some_and(|p| ports.daemon.key_listed(p))
                            {
                                key_revoked.insert(pid.clone());
                            }
                            doomed.push((pid.clone(), l.shown().to_string()));
                        } else if crate::recv::revocation::route_must_withdraw(
                            l.identity_device_pub.as_ref(),
                            &|p: &[u8; 32]| ports.identity.device_cert_revoked(p),
                        ) {
                            unrouted.push(pid.clone());
                        }
                    }
                    forgotten_channels.extend(revoked_secrets.iter().map(|s| host.channel_of(s)));
                    revoked_secrets.clear();
                    brokered_pids.retain(|p, by| {
                        (conn.links.contains_key(p) || conn.direct_pending.contains_key(p))
                            && !ports.identity.device_cert_revoked(&by.device_pub)
                    });
                    // Tell each doomed peer WHY before the link goes: a peer
                    // mid-exec or mid-send otherwise sees only a dead link and
                    // reports "link died" (exit 6) for what is a refusal.
                    // drop_link closes the transport only after a grace, so
                    // this frame leaves first.
                    for (pid, _) in &doomed {
                        if let Some(t) = conn.transport_of(pid) {
                            let code = if key_revoked.contains(pid) {
                                crate::refusal::Code::CertRevoked
                            } else {
                                crate::refusal::Code::Unrecognized
                            };
                            let refusal = crate::refusal::Refusal::new(code, None);
                            let mut f = json!({ "type": "link-revoked", "reason": refusal.reason });
                            refusal.annotate(&mut f);
                            let _ = t.send_control(&f).await;
                        }
                    }
                    for (pid, label) in &doomed {
                        sync_tasks.cancel_sync_for_pid(pid, log.as_ref()).await;
                        conn.drop_link(pid);
                        l2_muxes.remove(pid);
                        fleet_pending.remove(pid);
                        fleet_verified.remove(pid);
                        fleet_greeted.remove(pid);
                        fleet_deferred_offers.retain(|(p, _, _)| p != pid);
                        unrouted.push(pid.clone());
                        log.say(&format!(
                            "closed the link to '{label}': it was forgotten or revoked here"
                        ));
                    }
                    // An overlay route is the one thing a revoked device keeps
                    // without opening anything, so it goes with the revocation
                    // (this is the explicit forget path `remove_by_pid` is for).
                    #[cfg(feature = "mesh")]
                    for pid in &unrouted {
                        l3_seen.remove(pid);
                        if let Some(m) = l3.as_ref() {
                            m.remove_by_pid(pid).await;
                        }
                    }
                    let _ = &unrouted;
                    let closed = doomed.len();
                    // Links to a device revoked IN PLACE stay up to carry the
                    // refusal; count them so `devices revoke` can say so.
                    let refused = conn
                        .links
                        .values()
                        .filter(|l| {
                            crate::recv::revocation::route_must_withdraw(
                                l.identity_device_pub.as_ref(),
                                &|p: &[u8; 32]| ports.identity.device_cert_revoked(p),
                            )
                        })
                        .count();
                    for req in revocation_waiters.drain(..) {
                        req.reply(&json!({ "ok": true, "closed": closed, "refused": refused }))
                            .await;
                    }
                }
            }
            // Invitation ends are TIME, not store changes, so they are checked on
            // every scan rather than on a snapshot change: a link whose device's
            // invitation has ended loses its overlay route here (opens on it are
            // refused by the gate, and its open sessions are cut by the live
            // re-check in each serving loop).
            {
                let now = identity::now_secs();
                let ended: Vec<(String, String)> = conn
                    .links
                    .iter()
                    .filter(|(pid, _)| !expired_unrouted.contains(*pid))
                    .filter_map(|(pid, l)| {
                        let d = l.identity_device_pub?;
                        host.delegated_access_for(&d)
                            .filter(|a| a.expired(now))
                            .map(|_| (pid.clone(), l.shown().to_string()))
                    })
                    .collect();
                for (pid, label) in ended {
                    expired_unrouted.insert(pid.clone());
                    log.say(&format!(
                        "access for '{label}' ended (its invitation expired): refusing it from here on"
                    ));
                    #[cfg(feature = "mesh")]
                    {
                        l3_seen.remove(&pid);
                        if let Some(m) = l3.as_ref() {
                            m.remove_by_pid(&pid).await;
                        }
                    }
                }
                expired_unrouted.retain(|p| conn.links.contains_key(p));
            }
            let mut new_chans: Vec<String> = Vec::new();
            for (n, s) in host.devices_load() {
                let ch = host.channel_of(&s);
                if known_channels.insert(ch.clone()) {
                    log.say(&format!("new device '{n}' paired, now reachable"));
                    devices.push((n, s));
                    new_chans.push(ch);
                }
            }
            if !new_chans.is_empty() {
                // Fast-path emit now; the session digest carries the durable
                // subscription so a dropped emit self-repairs on the next tick.
                for ch in &new_chans {
                    if !sess.channels.contains(ch) {
                        sess.channels.push(ch.clone());
                    }
                }
                sess.emit(&sio, "subscribe", json!({ "channels": new_chans }))
                    .await;
            }
        }
        // #28: discharge any deferred peer-left whose channel has gone idle/dead.
        conn.reap_deferred();
        // Grace expired: decide these offers normally rather than hold them.
        // Re-injected with `__fleet_waited` so the deferral above does not catch
        // them a second time and park them forever.
        {
            let now = Instant::now();
            let due: Vec<_> = fleet_deferred_offers
                .iter()
                .filter(|(_, _, dl)| now > *dl)
                .cloned()
                .collect();
            fleet_deferred_offers.retain(|(_, _, dl)| now <= *dl);
            for (p, mut ov, _) in due {
                log.debug(&format!(
                    "fleet: offer from {p} waited out its grace unverified; deciding it"
                ));
                ov["__fleet_waited"] = serde_json::Value::Bool(true);
                let _ = tx.send(Ev::Control(p, ov));
            }
        }
        // Drop warm-bootstrap waiters whose peer never acked; the client's read
        // hits EOF and falls back to the cold establish.
        #[cfg(unix)]
        ports.daemon.reap_warm_bootstraps();
        // rung-1: direct attempt timed out → fall back to WebRTC (unchanged).
        // Unlike the sender call above, this receiver-side fallback routes
        // through maybe_adopt, so its ESTABLISH caller is indistinguishable
        // from ordinary adoption. Correlate DIRECT-FALLBACK with the following
        // ADOPT for the same peer; that sequence is not sound if peers recover
        // concurrently, so caller attribution alone is insufficient here.
        for (pid, info, (n, sec)) in conn.expired_direct() {
            let adopted = conn.maybe_adopt(&info, true).await.with_context(|| {
                format!("direct fallback adoption failed for peer {pid} on receive path")
            });
            peer_step(
                daemon,
                &pid,
                "direct fallback adoption",
                adopted,
                log.as_ref(),
            )?;
            if let Some(l) = conn.link_mut(&pid) {
                l.expected_secret = Some((n, sec));
            }
        }

        // C30 phase 3: state pings, each open link hears our transfer/away
        // truth every ~10s, so one-sided beliefs between PEERS can't persist.
        if last_state_ping.elapsed() >= Duration::from_secs(10) {
            last_state_ping = Instant::now();
            for (pid, l) in &conn.links {
                if let Some(t) = &l.transport {
                    let mut transfers = serde_json::Map::new();
                    for ((p0, _), inc) in &st.by_sid {
                        if p0 == pid {
                            transfers.insert(
                                inc.id.clone(),
                                json!(inc.received.load(Ordering::Relaxed)),
                            );
                        }
                    }
                    // BOUNDED: this runs inline in the event loop for EVERY link.
                    // A WebRTC data-channel write against a frozen / half-open peer
                    // can block (write_data_channel().await never returns), which
                    // would starve the whole loop, including the signal-driven
                    // Interrupted handler, the multi-link shutdown hang. The state
                    // ping is best-effort, so cap it and move on.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        t.send_control(&json!({
                            "type": "state", "v": 1,
                            "transfers": Value::Object(transfers),
                            "trusted": l.trusted,
                            "away": false,
                        })),
                    )
                    .await;
                }
            }
        }

        // G-k completion sweep (top-of-loop): see sweep_completed_streams.
        crate::recv::files::sweep_completed_streams(
            host.as_ref(),
            log.as_ref(),
            &mut st.by_sid,
            &conn,
            &dir,
            &output,
            to_stdout,
            daemon,
            &report,
            &mut st.completed,
            &ports.env.delivery,
        )
        .await?;

        // Gate-18 Mode B: recompute the completion flag AFTER the sweep, every
        // tick (never sticky). When true, a stuck/lost link is DROPPED in
        // on_stuck instead of re-established, see Conn::recv_done. Refreshing it
        // here, where `completed`/`by_sid` were just settled, makes the gate-2/
        // gate-11c fence exact: a mid-transfer link (by_sid non-empty) sees
        // recv_done=false and reconnects unchanged.
        conn.recv_done =
            protocol::recv_transfer_done(st.completed, keep_open, st.by_sid.is_empty());
        // WARM-HOLD: when a transfer completes, mark the peer as warm so we
        // proactively reconnect if the link drops.
        if st.completed > 0 {
            let warm_peers: Vec<String> = st
                .by_sid
                .keys()
                .filter_map(|(pid, _)| conn.links.get(pid)?.verified_name.clone())
                .collect();
            for name in &warm_peers {
                conn.note_warm_use(name);
            }
        }
        if st.completed > 0 || !st.by_sid.is_empty() {
            st.ever_received = true; // a channel was up; Bug-5 wedge hint no longer applies
        }

        // P0 (GAP-1): bytes-moved STALL watchdog (RECEIVE side). The receiver is
        // the peer that visibly hangs at 0%: when an inbound transfer is in
        // flight (`by_sid` non-empty for a link) but no data byte has arrived
        // past the stall threshold, its transport's idle_ms() climbs. The
        // RECEIVER must also act so a direct-QUIC repair is SYMMETRIC, a fresh
        // authenticated QUIC connection needs both ends to re-dial. We emit
        // Ev::TransferStalled for each such link (liveness-gated), whose handler
        // re-arms this side's direct dial (rung c). The on-disk `.part` is kept,
        // so the resumed stream continues from the saved offset.
        {
            // Per-link: in_flight = this peer has an inbound file mid-transfer
            // (a by_sid entry) OR a stall episode is already open for it (the
            // .part was flushed to disk mid-repair, so by_sid is momentarily
            // empty, detect_stall keeps the episode alive until fresh progress).
            let all_pids: Vec<String> = conn.links.keys().cloned().collect();
            for pid in all_pids {
                let in_flight = st.by_sid.keys().any(|(p, _)| *p == pid);
                if let Some(idle) = conn.detect_stall(&pid, in_flight) {
                    let transport_dead = conn
                        .transport_of(&pid)
                        .map(|t| t.is_dead())
                        .unwrap_or(false);
                    if transport_dead || conn.link_alive(&pid).await {
                        let _ = tx.send(Ev::TransferStalled(pid, idle));
                    } else {
                        conn.note_progress(&pid);
                    }
                }
            }
        }

        // P5 (GAP-6): relay->direct upgrade prober (receive side). The `up` daemon
        // acceptor is the canonical long-lived session, so the prober defaults ON
        // here. Probe for a direct path while serving on relay; verify-before-
        // upgrade cuts over only on a confirmed-stable direct standby.
        conn.tick_upgrade_prober().await;

        // Gate-18 Mode B DETERMINISTIC repro hook: simulate the post-completion
        // FLAP that contention triggers in the wild (the sender's departure puts
        // the receiver's link into the C4 reconnect loop). Once everything is on
        // disk, force each surviving link to go stuck repeatedly, reset its
        // attempts (mirroring the real flap's attempts-reset, so MAX_ATTEMPTS
        // can never cap it) and re-inject Ev::Stuck. On the BASELINE (no fix)
        // on_stuck re-establishes → link persists → conn.links never empties →
        // hang to timeout (RC=124). WITH the fix on_stuck drops on recv_done →
        // links empties → no link to churn next tick → quiet-exit fires. Driven
        // at LOOP level (not inside on_stuck) so the A/B tests the fix, not
        // itself.
        if conn.recv_done && test_hooks::churn_after_complete() {
            let churn: Vec<(String, u32)> = conn
                .links
                .iter()
                .map(|(pid, l)| (pid.clone(), l.generation))
                .collect();
            for (pid, generation) in churn {
                if let Some(l) = conn.links.get_mut(&pid) {
                    l.attempts = 0; // mirror the real flap: cap never accumulates
                                    // Tear the data channel down so on_stuck's is_connected()
                                    // guard sees a dead link and the Stuck isn't swallowed.
                    if let Some(p) = &l.peer {
                        p.close().await;
                    }
                }
                let _ = conn.tx.send(Ev::Stuck(pid, generation));
            }
        }

        // #28 exit reconciliation: once everything is received and the only links
        // left are ones held open purely for their deferred-drop reap (their
        // sender's signaling left AFTER the transfer finished), there is nothing
        // in flight to protect, exit promptly instead of paying the full
        // TUNLION_ADOPT_ACTIVE_MS deferral. Restores the pre-#28 prompt exit; an
        // in-progress reconnect keeps `by_sid` non-empty and so is unaffected.
        if st.completed > 0
            && !keep_open
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && !conn.links.is_empty()
            && conn.only_deferred_links()
        {
            log.say(&format!(
                "done ({} file{}).",
                st.completed,
                if st.completed == 1 { "" } else { "s" }
            ));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // Bug 2: the transfer is COMPLETE and the sender's link is fully GONE
        // (dropped via peer-left, or via the grace/Mode-B path when peer-left
        // was lost). With no live link and nothing left to fetch there is
        // nothing to wait for, exit at once instead of holding out the full
        // rejoin window (peer-left case) or the quiet-exit window (lost-peer-left
        // case). Fenced exactly like the exits above: by_sid empty + no pending
        // questions, so a mid-transfer reconnect (which keeps `by_sid`
        // non-empty) is untouched, and --keep-open still lingers by design.
        if st.completed > 0
            && !keep_open
            && st.by_sid.is_empty()
            && st.pending.is_empty()
            && conn.links.is_empty()
        {
            conn.rejoin.waiting_rejoin = None;
            conn.present.clear_sticky();
            log.say(&format!(
                "done ({} file{}).",
                st.completed,
                if st.completed == 1 { "" } else { "s" }
            ));
            let _ = sio.disconnect().await;
            return Ok(());
        }

        // G-k fallback: everything done, nobody attached, no questions
        // outstanding, if that holds quietly for the quiet-exit window (10s
        // default, TUNLION_QUIET_EXIT_SECS overrides), the peer-left we were
        // counting on for a clean exit never arrived; exit anyway. C30 ph2:
        // ALSO satisfied when the server's digest says the room is empty and
        // no room-independent (channel) link remains, lingering dead links
        // can't block the exit when the server knows nobody's there.
        // A fleet link is room-INDEPENDENT, exactly like a pair-channel link, so
        // it must count here too. It can lack a pair secret (WebRTC fallback), and
        // without this a daemon holding only fleet links would read as "alone" and
        // take the quiet-exit path while peers are connected.
        let digest_says_alone = digest_alone
            && conn.links.keys().all(|pid| {
                conn.links
                    .get(pid)
                    .map(|l| l.expected_secret.is_none())
                    .unwrap_or(true)
                    && !fleet_pending.contains(pid)
                    && !fleet_verified.contains(pid)
            });
        // #28 Mode B: a dead link that keeps FLAPPING, on_stuck reconnect, or a
        // roster/session reconcile re-adopting the gone sender and re-arming
        // `expected_secret` so `digest_says_alone` never holds, must NOT block
        // this fallback once everything is received; `conn.links` may never
        // empty under churn (the RC=124 hang). Surgical: discriminate on link
        // HEALTH, not existence, a churning/reconnecting/dead link (never
        // `Ready`) does not block exit, but a healthy `Ready` link (e.g. a
        // bystander between two human-paced sends, gate 6) STILL does. So this is
        // a no-op for healthy peers, not a behaviour change, only a peer we've
        // lost contact with stops blocking. TUNLION_TEST_DISABLE_MODEB_DROP
        // restores the old links-gated behaviour so gate 18b proves the A/B
        // (baseline hangs, fix exits) with one binary.
        // A link whose transport is DEAD is not healthy whatever its presence
        // says. A direct QUIC link stays `Ready` after its peer is gone: the
        // sender ends its send half once the file is acked (the primary is then
        // `is_dead`), and nothing moves presence off `Ready` for a link that
        // simply stops. Gated on presence alone, a receiver whose sender vanished
        // over QUIC with its peer-left lost never quiet-exited (gate 18, RC=124
        // at 120 s, once same-host transfers stopped falling back to WebRTC).
        let no_healthy_link = conn.links.values().all(|l| {
            !matches!(l.presence, Presence::Ready)
                || l.transport.as_ref().is_none_or(|t| t.is_dead())
        });
        let links_clear = if !test_hooks::disable_modeb_drop() {
            no_healthy_link
        } else {
            conn.links.is_empty() || digest_says_alone
        };
        // A one-time CODE receive has exactly one sender, and the code is spent.
        // A CLI sender leaves when its files are acked, which ends us above; a
        // BROWSER sender keeps its tab (and link) open, so `links_clear` never
        // held and `tunlion receive <code>` sat after "verified, acked" until
        // someone pressed Ctrl-C (launch matrix B03). Once everything offered is
        // received and the link has been idle for the quiet window, the session
        // is over: the same quiet exit, with a line that says why.
        if let Some(why) = quiet_exit_reason(
            st.completed,
            keep_open,
            st.by_sid.is_empty() && st.pending.is_empty(),
            links_clear,
            // The Mode B test hook restores the old links-gated exit wholesale,
            // so gate 18b's baseline still proves the drop matters.
            code_only && !test_hooks::disable_modeb_drop(),
        ) {
            match last_quiet {
                None => last_quiet = Some(Instant::now()),
                Some(since) if since.elapsed() > quiet_window => {
                    log.say(&log.paint(Tone::Dim, why));
                    log.say(&format!(
                        "done ({} file{}).",
                        st.completed,
                        if st.completed == 1 { "" } else { "s" }
                    ));
                    let _ = sio.disconnect().await;
                    return Ok(());
                }
                Some(_) => {}
            }
        } else {
            last_quiet = None;
        }

        let Some(ev) = ev else { continue };

        // C23: questions from links that died (supersede/peer-left) are
        // moot, the sender re-offers on its new link. Purge them so a 'y'
        // can never accept a ghost (the duplicate-stream ENOENT crash).
        if !st.pending.is_empty() {
            let front_id = st.pending.front().map(|(_, v)| v["id"].clone());
            st.pending.retain(|(p, _)| conn.links.contains_key(p));
            if st.pending.front().map(|(_, v)| v["id"].clone()) != front_id {
                conn.present.clear_sticky();
                if let Some((qpid, qv)) = st.pending.front() {
                    let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                    {
                        let q = offer_question(
                            log.as_ref(),
                            &s,
                            qv["name"].as_str().unwrap_or("file"),
                            qv["size"].as_u64().unwrap_or(0),
                            paired,
                        );
                        log.say(&q); // permanent: a new question fronted (C25)
                        front_question(conn.present.as_ref(), log.as_ref(), &q, true);
                        st.question_shown = Instant::now();
                    }
                } else {
                    st.question_open
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        match ev {
            // A sid left a channel we watch: forget it from the roster so
            // warm-hold never dials a departed instance (see on_known_peer_left).
            Ev::KnownPeerLeft(v) => {
                conn.on_known_peer_left(&v);
            }
            // A warm-reuse open found this held link black-holing new streams
            // (zombie: alive at QUIC, dead for data). Drop it so the proactive
            // re-connect forms a fresh, healthy held link and warm-reuse goes
            // back to instant. Live DATA links are untouched (each ssh/pty op
            // rides its own stream; the dropped link had no working stream).
            Ev::DropLink(pid) => {
                if conn.links.contains_key(&pid) {
                    log.debug(&format!(
                        "tunlion: dropping zombie warm link to '{pid}' (black-holed a stream)"
                    ));
                    sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                    conn.drop_link(&pid);
                    crate::recv::servers::shell::retire_link(
                        &ports,
                        &pid,
                        &mut l2_muxes,
                        &mut pty_bindings,
                    )
                    .await;
                    // CONTINUITY: do NOT retract the L3 route here. A dropped link
                    // is almost always followed by a repair (a fresh transport for
                    // the same peer), whose add_peer atomically swaps the route. If
                    // we retracted now, the overlay IP would be briefly unroutable
                    // and a live ssh/L3 session could reset across the repair. The
                    // stale route just drops datagrams (the inner TCP pauses) until
                    // the swap. The cached announce is dropped so the peer's next
                    // announce is treated fresh.
                    #[cfg(feature = "mesh")]
                    l3_seen.remove(&pid);
                    // Fleet auto-mesh: forget this peer's verification too. A
                    // reconnect gets a NEW sid and must re-prove its certificate
                    // on the new link's binding, so carrying the old sid's verdict
                    // forward would be exactly the stale-trust bug the channel
                    // binding exists to prevent.
                    fleet_pending.remove(&pid);
                    fleet_verified.remove(&pid);
                    fleet_greeted.remove(&pid);
                    // Deferred offers die with the link that carried them. A new
                    // link must re-prove on a NEW binding, so replaying an offer
                    // buffered under the old one is precisely the stale-trust bug
                    // the channel binding exists to prevent.
                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                    // A new link gets a NEW challenge. Carrying the old nonce
                    // forward would let a message captured on the previous link
                    // verify on this one, which is the whole thing the binding
                    // exists to stop.
                    bind_ours.remove(&pid);
                    bind_theirs.remove(&pid);
                }
            }
            Ev::PairMatched(v) => {
                claim_in_flight = false;
                let room = v["room"].as_str().unwrap_or_default().to_string();
                log.say(&format!(
                    "  {} code accepted, joining sender",
                    log.paint(Tone::Ok, log.glyph_ok())
                ));
                sess.room = Some(room.clone()); // C30: desire moves; session repairs if the join dies
                sess.touch();
                sess.emit(
                    &sio,
                    "join",
                    json!({ "room": room, "name": ports.env.display_name, "uid": my_uid }),
                )
                .await;
            }
            // C30: server confirmed our session digest. Phase 2: reconcile
            // the roster it carries, missed peer-joined/left self-correct.
            Ev::Synced(v) => {
                if let Some(roster) = sess.on_synced(&v) {
                    // Take the flag before any reconcile work: exactly the first
                    // digest on a fresh signaling sid is exempt from absence
                    // counting (adoption below still runs, so a new sid is
                    // picked up immediately).
                    let digest_fresh = std::mem::take(&mut digest_epoch_fresh);
                    let channel_peers = roster.channel_peers;
                    let channel_present: std::collections::HashSet<String> = channel_peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // Channel subscriptions are independent of room membership.
                    // Re-adopt missed known-peer pushes and reap known links that
                    // remain absent from two consecutive channel rosters.
                    // Re-adopting dials on a held secret: check it against the
                    // store first, as the known-peer arm does.
                    let gone = ports.daemon.prune_to_store(&mut devices);
                    if !gone.is_empty() {
                        revoked_secrets.extend(gone);
                        revocation_sweep_now = true;
                    }
                    for p in &channel_peers {
                        if host.is_self_uid(&conn.my_uid, p["uid"].as_str()) {
                            continue;
                        }
                        if let Some((name, secret)) = devices.iter().find(|(_, s)| {
                            host.channel_of(s) == p["channel"].as_str().unwrap_or_default()
                        }) {
                            let pid = p["id"].as_str().unwrap_or_default().to_string();
                            let (name, secret) = (name.clone(), secret.clone());
                            conn.start_direct(&pid, &name, &secret).await;
                            // Channel-digest recovery remains intentionally outside
                            // the room give-up suppression scope.
                            let r = conn.maybe_adopt(p, true).await;
                            peer_step(daemon, &pid, "channel-digest adoption", r, log.as_ref())?;
                            if let Some(l) = conn.link_mut(&pid) {
                                l.expected_secret = Some((name, secret));
                            }
                        } else if let Some(uk) = host.user_key() {
                            let enroll_channel =
                                ports.identity.enroll_channel(&uk.public_key_bytes());
                            if p["channel"].as_str() == Some(enroll_channel.as_str()) {
                                let r = conn.maybe_adopt(p, true).await;
                                let pid = p["id"].as_str().unwrap_or_default();
                                peer_step(
                                    daemon,
                                    pid,
                                    "enrollment-digest adoption",
                                    r,
                                    log.as_ref(),
                                )?;
                            }
                        }
                    }
                    // The channel surface speaks only about channel-owned
                    // links. A room-sourced link is legitimately absent from
                    // `channel_peers`; passing it here (and calling
                    // `digest_present`) cleared its room clock every digest and
                    // made its bounded grace eternal.
                    let channel_links: Vec<(String, Option<bool>)> = conn
                        .links
                        .iter()
                        .map(|(pid, link)| {
                            let channel_link = link
                                .expected_secret
                                .as_ref()
                                .map(|(_, secret)| {
                                    sess.channels
                                        .iter()
                                        .any(|ch| ch == &host.channel_of(secret))
                                })
                                .unwrap_or(false);
                            let present = channel_link.then(|| channel_present.contains(pid));
                            (pid.clone(), present)
                        })
                        .collect();
                    let mut channel_gone = Vec::new();
                    for (pid, present) in channel_links {
                        let Some(present) = present else {
                            // Not channel-owned: clear only a stale channel miss
                            // count. Its room clock belongs to the room loop and
                            // must survive this pass.
                            conn.channel_digest_absent.remove(&pid);
                            continue;
                        };
                        if conn.digest_note(
                            &pid,
                            crate::conn::DigestSurface::Channel,
                            present,
                            digest_fresh,
                        ) {
                            channel_gone.push(pid);
                        } else if !present && !digest_fresh {
                            log.debug(&format!(
                                "tunlion: '{}' missing from channel digest, link still live; deferring drop",
                                conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default()
                            ));
                        }
                    }
                    for pid in channel_gone {
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                        conn.drop_link(&pid);
                        // A stale duplicate of a peer that is still linked is
                        // housekeeping, not a departure: it printed "ok alpha
                        // ○ alpha left (channel digest reconcile), still listening", one
                        // peer both present and gone, with an internal reason.
                        if crate::conn::departure_is_news(
                            &name,
                            conn.links.values().map(|l| l.name.as_str()),
                        ) {
                            log.say(&conn.roster(
                                &pid,
                                "○",
                                Tone::Dim,
                                "left, still listening",
                                &name,
                            ));
                        } else {
                            log.debug(&format!("dropped a stale duplicate link to '{name}' (channel digest reconcile)"));
                        }
                    }
                    let peers = roster.peers;
                    digest_alone = peers.is_empty();
                    let present: std::collections::HashSet<String> = peers
                        .iter()
                        .filter_map(|p| p["id"].as_str().map(String::from))
                        .collect();
                    // unknown in digest → a peer-joined we never received
                    for p in &peers {
                        let id = p["id"].as_str().unwrap_or_default();
                        if !id.is_empty() && !conn.links.contains_key(id) {
                            log.debug(&log.paint(
                                Tone::Dim,
                                "  (digest: adopting a peer we never heard join)",
                            ));
                            let r = conn.maybe_adopt_from(p, true, AdoptSource::Digest).await;
                            peer_step(daemon, id, "digest adoption", r, log.as_ref())?;
                        }
                    }
                    // known room-sourced link absent ×2 → a peer-left we
                    // never received (channel-introduced links are exempt:
                    // room-independent by design)
                    // Room surface: only room-sourced links. Channel-introduced
                    // links (pair/fleet) are room-independent and are judged by
                    // the channel loop above.
                    let room_links: Vec<(String, Option<bool>)> = conn
                        .links
                        .iter()
                        .map(|(pid, l)| {
                            // "Channel-introduced" is the property that matters
                            // here, and `expected_secret.is_some()` was only ever
                            // a PROXY for it: true while every channel link
                            // carried a pair secret. A fleet link is
                            // channel-introduced and secretless, so the proxy
                            // reads it as room-sourced, finds it absent from the
                            // room roster, and reaps it after two digest ticks.
                            // Test the property directly instead of the proxy.
                            let channel_introduced = l.expected_secret.is_some()
                                || fleet_pending.contains(pid)
                                || fleet_verified.contains(pid);
                            let present = (!channel_introduced).then(|| present.contains(pid));
                            (pid.clone(), present)
                        })
                        .collect();
                    let mut gone: Vec<String> = Vec::new();
                    for (pid, present) in room_links {
                        let Some(present) = present else {
                            // Not room-owned: only a stale room count may be
                            // cleared, never the channel surface's clock.
                            conn.room_digest_absent.remove(&pid);
                            continue;
                        };
                        if conn.digest_note(
                            &pid,
                            crate::conn::DigestSurface::Room,
                            present,
                            digest_fresh,
                        ) {
                            gone.push(pid);
                        } else if !present && !digest_fresh {
                            log.debug(&format!(
                                "tunlion: '{}' missing from room digest, link still live; deferring drop",
                                conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default()
                            ));
                        }
                    }
                    for pid in gone {
                        let name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                        conn.drop_link(&pid);
                        // A stale duplicate of a peer that is still linked is
                        // housekeeping, not a departure: it printed "ok alpha
                        // ○ alpha left (digest reconcile), still listening", one
                        // peer both present and gone, with an internal reason.
                        if crate::conn::departure_is_news(
                            &name,
                            conn.links.values().map(|l| l.name.as_str()),
                        ) {
                            log.say(&conn.roster(
                                &pid,
                                "○",
                                Tone::Dim,
                                "left, still listening",
                                &name,
                            ));
                        } else {
                            log.debug(&format!(
                                "dropped a stale duplicate link to '{name}' (digest reconcile)"
                            ));
                        }
                    }
                    // The roster itself: a sid absent from two digests is gone
                    // even when its known-peer-left was lost.
                    conn.prune_roster_absent(&channel_present, &present);
                }
            }
            // C29: a code minted in-session (`pair` typed into up).
            Ev::PairCode(v) => {
                let c = v["code"].as_str().unwrap_or("?");
                conn.present.clipboard(c);
                log.say("");
                log.say(&format!(
                    "      {}",
                    log.paint(Tone::Brand, &c.to_uppercase())
                ));
                log.say("");
                log.say(&log.paint(
                    Tone::Dim,
                    "  say it aloud; they type it in the web app or `tunlion join <code>` / one claim / 10 min",
                ));
            }
            Ev::PairUsed(_) => {
                log.say(&log.paint(Tone::Dim, "  code claimed, connecting..."));
            }
            Ev::PairError(v) => {
                let why = v["error"].as_str().unwrap_or("?").to_string();
                // The server distinguishes (additively) a dead creator from a
                // typo'd/expired code, say the actionable thing for each.
                let hint = match v["why"].as_str() {
                    Some("sender-gone") => {
                        "the sender who made that code already left, ask them for a fresh one"
                            .to_string()
                    }
                    _ => format!("{why}, codes burn after one use and expire after 10 min"),
                };
                if code.is_some() && conn.links.is_empty() && st.completed == 0 {
                    // started WITH a code that failed: nothing else to do
                    bail!("code rejected: {hint}");
                }
                // a TYPED claim failing must not kill a listening session
                paired = false;
                claim_in_flight = false;
                log.say(&format!(
                    "  {} code rejected: {hint}; still listening",
                    log.paint(Tone::Err, log.glyph_err()),
                ));
            }
            Ev::Welcome(v) => {
                if let Some(id) = v["id"].as_str() {
                    conn.my_id = id.to_string();
                }
                // P5 (GAP-6): a fresh welcome (signaling reconnect) may mean the
                // network just changed under us, re-probe relay-committed peers for
                // a direct path immediately instead of waiting out the backoff.
                conn.reprobe_on_network_event();
                if let Some(peers) = v["peers"].as_array() {
                    for p in peers {
                        let r = conn.maybe_adopt(p, true).await;
                        let pid = p["id"].as_str().unwrap_or_default();
                        peer_step(daemon, pid, "welcome adoption", r, log.as_ref())?;
                    }
                }
                // C30 (dissolves the C28 belt): a welcome means a fresh sid,
                // everything sid-keyed (subscriptions, lease) died with the
                // old one. Invalidate; the next tick re-asserts everything.
                // The digest window also restarts: the first Synced on this
                // sid cannot prove absence while the peer re-subscribes.
                sess.invalidate();
                digest_epoch_fresh = true;
                conn.reset_digest_reconcile();
            }
            Ev::KnownPeer(v) => {
                if host.is_self_uid(&conn.my_uid, v["uid"].as_str()) {
                    continue; // our own sender/daemon shares these channels
                }
                // A code receive dials only the code's holder (see code_only).
                if code_only {
                    continue;
                }
                // Dialing on a held secret is admitting it (a direct link is born
                // trusted on that MAC), so match against the store as it is NOW,
                // not as it was at start: a forgotten device must not be dialed.
                let gone = ports.daemon.prune_to_store(&mut devices);
                if !gone.is_empty() {
                    revoked_secrets.extend(gone);
                    revocation_sweep_now = true;
                }
                if let Some((n, sec)) = devices
                    .iter()
                    .find(|(_, s)| host.channel_of(s) == v["channel"].as_str().unwrap_or(""))
                {
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    // WARM-HOLD: a known peer just came online. Under auto-warm, adopt it
                    // into the auto tier NOW (don't wait up to 10s for the tick) and clear
                    // any dormancy/backoff so the reconnect loop owns it from t=0. The
                    // start_direct/maybe_adopt below already dial immediately; this makes
                    // warm-hold RETRY if that first dial fails or the link later drops.
                    // Do NOT add to recent-LRU (that's for ACTUAL use only).
                    let auto_warm = l3.is_some() || host.settings_get_bool("auto-warm");
                    if auto_warm {
                        conn.warm_hold.auto.insert(n.clone());
                    }
                    if conn.warm_hold.should_connect(n) {
                        conn.warm_hold.resume(n);
                        // Pull the next warm tick forward: the event loop wakes at least every
                        // 2s (next_ev timeout, :8957-8960), so a failed eager dial is retried
                        // within ~2s instead of ~10s.
                        last_warm_hold_tick = Instant::now()
                            .checked_sub(Duration::from_secs(10))
                            .unwrap_or_else(Instant::now);
                    }
                    // Only announce a FRESH connect. The server re-pushes the
                    // known-peer roster on every (re)subscribe and C30 sync tick, so
                    // a peer we already hold a link to (or are already dialing) would
                    // otherwise reprint "appeared, connecting" on a loop, reading
                    // like a flap even though `start_direct` below no-ops for an
                    // existing link (start_direct_inner early-return). A real
                    // reconnect removes the link first, so it still announces.
                    let fresh =
                        !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid);
                    // Also re-announce if the existing link's transport is dead
                    let link_dead = conn
                        .links
                        .get(&pid)
                        .and_then(|l| l.transport.as_ref())
                        .map(|t| t.is_dead())
                        .unwrap_or(false);
                    if fresh || link_dead {
                        log.say_folded(&format!("known device '{n}' appeared, connecting"));
                        // NOT a sighting. This is the server's roster, which it
                        // re-pushes on every (re)subscribe and sync tick, and
                        // which can still carry a session the device no longer
                        // has (a reset device, a killed daemon not yet timed
                        // out). Touching lastSeen here kept a wiped device at
                        // "last seen just now" while `add`, reading the same
                        // record a minute later, said "1m ago". lastSeen moves
                        // only on a link whose peer is demonstrably present
                        // (daemon_ctl::peer_present, the liveness observation).
                    } else {
                        log.trace(&format!(
                            "known device '{n}' re-announced (link already up)"
                        ));
                    }
                    // rung-1: known device = both CLIs; try direct QUIC first.
                    let (n, sec) = (n.clone(), sec.clone());
                    conn.start_direct(&pid, &n, &sec).await;
                    let r = conn.maybe_adopt(&v, true).await;
                    peer_step(daemon, &pid, "known-device adoption", r, log.as_ref())?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((n.clone(), sec.clone()));
                    }
                } else if v["channel"].as_str().is_some_and(|c| {
                    forgotten_channels.contains(c)
                        || revoked_secrets.iter().any(|s| host.channel_of(s) == c)
                }) {
                    // A device forgotten here, dialing the meeting place it still
                    // finds us on: tell it, rather than leave it waiting.
                    if let Some(pid) = v["id"].as_str().filter(|p| !p.is_empty()) {
                        if !conn.links.contains_key(pid) {
                            refuse_unrecognized_dial(&sio, pid, log.as_ref()).await;
                        }
                    }
                } else if let Some((sec, broker)) =
                    brokered.get(v["channel"].as_str().unwrap_or("")).cloned()
                {
                    // A meeting place opened by a sibling revoked since is closed,
                    // not honoured (the sweep also drops it from `brokered`).
                    if ports.identity.device_cert_revoked(&broker.device_pub) {
                        log.debug("brokered meeting place refused: its broker is revoked");
                        revocation_sweep_now = true;
                        continue;
                    }
                    // A peer arrived on a meeting place we were TOLD about over a
                    // certificate-verified link. Exactly one other party is
                    // expected here, and the brokered secret proves it the same
                    // way a pair secret proves a paired device, so this joins the
                    // ordinary known-device path rather than the fleet one.
                    //
                    // That is the whole point of brokering: the one-shot never has
                    // to work out which of several siblings is the target, because
                    // only the target was ever given the address.
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if pid.is_empty() {
                        continue;
                    }
                    // Dialed (and so filed) under the BROKER's proven name, never
                    // the name this peer announces: a one-shot that called itself
                    // after a device holding grants used to be filed as that
                    // device (revocation_live::brokered_dial_name).
                    let name = crate::recv::revocation::brokered_dial_name(&broker);
                    brokered_pids.insert(pid.clone(), broker.clone());
                    conn.start_direct(&pid, &name, &sec).await;
                    let r = conn.maybe_adopt(&v, true).await;
                    peer_step(daemon, &pid, "brokered adoption", r, log.as_ref())?;
                    if let Some(l) = conn.link_mut(&pid) {
                        l.expected_secret = Some((name, sec));
                        if l.transport.is_some() {
                            crate::recv::revocation::bind_brokered_link(l, &broker);
                        }
                    }
                } else if fleet_presence_allowed(
                    ports
                        .identity
                        .is_fleet_channel(v["channel"].as_str().unwrap_or("")),
                ) {
                    // Fleet auto-mesh: a device is present on our fleet meeting
                    // point. We hold NO pair secret for it, so this is the
                    // secretless presence path (same shape as the enrollment
                    // channel below): dial now, prove identity with the
                    // certificate once the link is up. Until `fleet-hello`
                    // verifies, the link is in `fleet_pending` and authorizes
                    // nothing.
                    let pid = v["id"].as_str().unwrap_or_default().to_string();
                    if !pid.is_empty() && !fleet_verified.contains(&pid) {
                        fleet_pending.insert(pid.clone());
                    }
                    // Dial direct-QUIC keyed by the fleet secret. It must be
                    // direct, not the WebRTC fallback: only a direct link exposes
                    // an RFC-5705 channel binding, and fleet-hello is bound to it
                    // (net.rs channel_binding() returns None). And both ends are
                    // daemons, so without an explicit dial nobody connects at all
                    // (maybe_adopt only prepares to ACCEPT).
                    // GLARE: both ends see each other on the fleet channel, so
                    // both would dial, collide, and supersede each other forever.
                    // Measured before this guard: 1 verify, 10 drops, never
                    // settling, which reads downstream as "peer unreachable" while
                    // a link is visibly present. Pick ONE dialer deterministically;
                    // both sides run the same comparison and get opposite answers,
                    // so exactly one dials and the other accepts.
                    if conn.my_id < pid {
                        if let Some(rv) = ports.identity.fleet_rv() {
                            conn.start_direct_fleet(&pid, &rv).await;
                        }
                    }
                    let r = conn.maybe_adopt(&v, true).await;
                    peer_step(daemon, &pid, "fleet adoption", r, log.as_ref())?;
                } else if let Some(uk) = host.user_key() {
                    // Enrollment channel: an ephemeral device appeared on
                    // enroll_channel(own_owner_pub). Dial it (channel-presence
                    // path, no room-join) so the auth-key handshake can run.
                    let ek = ports.identity.enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid)
                        {
                            log.debug("enrollment peer appeared on channel, dialing");
                        }
                        let r = conn.maybe_adopt(&v, true).await;
                        peer_step(daemon, &pid, "enrollment adoption", r, log.as_ref())?;
                    }
                }
            }
            Ev::PeerJoined(v) => {
                let had_partials = !st.by_sid.is_empty();
                let r = conn.maybe_adopt(&v, true).await;
                let pid = v["id"].as_str().unwrap_or_default();
                let now_active = peer_step(daemon, pid, "peer-joined adoption", r, log.as_ref())?;
                if now_active.unwrap_or(false) && had_partials {
                    // Stale per-link sid routing dies with the old link; the
                    // .part files live on and the sender's resume re-offers.
                    crate::recv::files::flush_inflight(&mut st.by_sid).await;
                }
            }
            Ev::Signal(v) => {
                let from = v["from"].as_str().unwrap_or_default().to_string();
                let data = v["data"].clone();
                // rung-1: a relayed transport-offer carries the peer's direct
                // candidates, start the simultaneous-open + auth race.
                if data["type"].as_str() == Some("transport-offer") {
                    let cands: Vec<String> = data["addrs"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let srflx = data["srflx"].as_str().map(String::from);
                    // #237: peer's server-asserted candidate + protocol version
                    // (see the send-side handler; absent `proto` means older build).
                    let peer_server_public = data["server_public"].as_str().map(String::from);
                    let peer_proto = data["proto"].as_u64().unwrap_or(1).clamp(1, 255) as u8;
                    // If we're on the code path and this peer hasn't authenticated yet,
                    // buffer the transport-offer until PAKE completes. Otherwise
                    // on_transport_offer would find no DirectPending (no secret) and
                    // silently drop the offer, causing the QUIC race to fail.
                    if recv_code_path && !recv_pake_done {
                        recv_pending_direct
                            .insert(from.clone(), (cands, srflx, peer_server_public, peer_proto));
                        log.debug(&format!("buffering pre-auth transport-offer from {from}"));
                        continue;
                    }
                    if data["probe"].as_bool() == Some(true) {
                        conn.answer_upgrade_probe(&from).await;
                    }
                    // A dial on the meeting place of a device forgotten here: it
                    // can never be matched, so refuse it now, by name.
                    if !conn.direct_pending.contains_key(&from)
                        && !conn.links.contains_key(&from)
                        && data["ch"].as_str().is_some_and(|c| {
                            forgotten_channels.contains(c)
                                || revoked_secrets.iter().any(|s| host.channel_of(s) == c)
                        })
                    {
                        refuse_unrecognized_dial(&sio, &from, log.as_ref()).await;
                        continue;
                    }
                    // Bug 2: the sender re-dialed after mid-transfer death.
                    // If we don't have a DirectPending, buffer the offer and
                    // replay it once start_direct creates one (same pattern as
                    // Bug 1's pre-PAKE buffer). Without this, on_transport_offer
                    // finds no pending and silently drops the offer.
                    if conn.direct_pending.contains_key(&from) {
                        conn.on_transport_offer(
                            &from,
                            cands,
                            srflx,
                            peer_server_public,
                            peer_proto,
                        );
                    } else {
                        // Also try to re-arm direct proactively: if we still
                        // know this peer's (name,secret), create the pending
                        // now so the buffered offer is replayed immediately.
                        let known = host.devices_load().into_iter().find(|(n, _)| {
                            conn.links.get(&from).map(|l| l.name == *n).unwrap_or(false)
                        });
                        if let Some((name, secret)) = known {
                            conn.start_direct(&from, &name, &secret).await;
                        }
                        if conn.direct_pending.contains_key(&from) {
                            // Re-arm succeeded — process the offer now.
                            conn.on_transport_offer(
                                &from,
                                cands,
                                srflx,
                                peer_server_public,
                                peer_proto,
                            );
                        } else {
                            conn.buffered_offers.insert(
                                from.clone(),
                                (cands, srflx, peer_server_public, peer_proto),
                            );
                            log.debug(&format!(
                                "buffering re-dial transport-offer from {from} (no pending yet)"
                            ));
                        }
                    }
                    continue;
                }
                // L1-a: PAKE messages ride the opaque `signal` relay. Route them
                // into THAT `from` peer's own ephemeral ceremony (recv code path).
                // On confirm the secret is agreed; that peer becomes the
                // authenticated sender and we DISCARD the secret. A failed/aborted
                // ceremony drops ONLY that candidate (a decoy / wrong-words peer),
                // it never bails the receive: the real sender's ceremony is
                // independent and still live.
                if recv_code_path
                    && matches!(
                        data["type"].as_str(),
                        Some("pake-msg") | Some("pake-confirm")
                    )
                {
                    // Already authenticated a sender? Ignore stray PAKE traffic
                    // from anyone else, including a late decoy.
                    if recv_pake_done {
                        continue;
                    }
                    // A sender of ANOTHER code on the same device shares this
                    // room and may run its ceremony at us. It names its own
                    // nameplate: not ours to run, and not a reason to fail.
                    // Any PAKE traffic still proves that peer is a current build.
                    recv_pake_heard = true;
                    let ours_np = recv_pake_template
                        .as_ref()
                        .map(|(_, np)| np.as_str())
                        .unwrap_or("");
                    if crate::recv::ceremony::addressed_to(&data, ours_np) == Some(false) {
                        st.recv_cers.remove(&from);
                        st.recv_deadlines.remove(&from);
                        st.recv_pending_offers.remove(&from);
                        recv_pending_direct.remove(&from);
                        log.debug(&format!(
                            "recv: {from} runs another code's ceremony; not our sender"
                        ));
                        continue;
                    }
                    // Mint this peer's ceremony on first sight (bounded), or route
                    // into its existing one. If the peer was already dropped (budget
                    // expired) or we are at the candidate cap, ignore its traffic.
                    if !st.recv_cers.contains_key(&from) {
                        if st.recv_cers.len() >= RECV_MAX_CANDIDATES {
                            log.debug("recv: candidate cap reached, ignoring extra peer's PAKE");
                            continue;
                        }
                        if let Some((pw, np)) = &recv_pake_template {
                            st.recv_cers.insert(
                                from.clone(),
                                Ceremony::new(
                                    pw,
                                    np,
                                    crate::recv::ceremony::pair_v2_caps(),
                                    filament_id::IntroScope::Device.to_byte(),
                                ),
                            );
                            st.recv_deadlines
                                .entry(from.clone())
                                .or_insert_with(|| Instant::now() + recv_pake_budget);
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                        }
                    }
                    let fps = match conn.link(&from) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let fp_ref = fps.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
                    // Extract secret first to avoid borrow checker issues with clear() and start_direct
                    let mut secret_opt: Option<String> = None;
                    let mut is_abort = false;
                    let mut abort_why = String::new();
                    let mut peer_direct = false;
                    if let Some(cer) = st.recv_cers.get_mut(&from) {
                        match cer.on_signal(&data, fp_ref) {
                            PakeInbound::Consumed => {
                                secret_opt = cer.secret().cloned();
                                peer_direct = cer.peer_supports_direct();
                            }
                            PakeInbound::Abort(why) => {
                                is_abort = true;
                                abort_why = why;
                            }
                            PakeInbound::Ignored => {}
                        }
                    }
                    if let Some(sec) = secret_opt {
                        // This peer authenticated. Record it as THE sender
                        recv_pake_done = true;
                        st.recv_cers.clear();
                        st.recv_deadlines.clear();
                        log.say(&log.paint(Tone::Dim, "  authenticated, receiving"));
                        // Option A: start the direct-QUIC race. start_direct owns
                        // replacement after all fallible setup and pending registration.
                        // A browser sender cannot take direct QUIC:
                        // promoting it would drop the WebRTC link it is on.
                        let promo = if peer_direct {
                            conn.start_direct_promote(&from, &from, &sec).await
                        } else {
                            crate::conn::Promotion::Retained
                        };
                        conn.bind_active(&from);
                        // A retained link is unannounced here too, and this loop's
                        // ChannelReady arm sends `caps` and the signed L3 announce,
                        // which a peer on a retained link would otherwise never get.
                        conn.rearm_channel_ready(&from, promo);
                        // #161 (WebRTC/relay path): issue the possession challenge
                        // now that this peer authenticated. The direct path resolves
                        // identity at DirectReady (start_direct_promote above); the
                        // WebRTC path has no pair-proof for a fresh code peer (no
                        // stored secret) and no DirectReady, so without this its
                        // identity never resolves and revocation cannot bind. The
                        // helper is idempotent with the DirectReady site.
                        if recv_code_path {
                            if let Some(l) = conn.link_mut(&from) {
                                crate::identity::resolve_peer_identity(l);
                            }
                            let (idev_known, proven) = conn
                                .link(&from)
                                .map(|l| {
                                    (
                                        l.identity_device_pub.is_some(),
                                        l.identity_binding == cap::BindingStrength::Proven,
                                    )
                                })
                                .unwrap_or((false, false));
                            if !proven && !idev_known {
                                if let Some(t) = conn.transport_of(&from) {
                                    ports
                                        .identity
                                        .issue_proven_challenge_and_hold(
                                            &conn,
                                            &from,
                                            &t,
                                            &st.pending_proven,
                                            &mut identity_nonces,
                                        )
                                        .await;
                                }
                            }
                        }
                        // Replay any buffered transport-offer that arrived before PAKE
                        // (now that start_direct created a DirectPending with the secret)
                        if let Some((cands, srflx, server_public, proto)) =
                            recv_pending_direct.remove(&from)
                        {
                            conn.on_transport_offer(&from, cands, srflx, server_public, proto);
                        }
                        recv_pending_direct.clear();
                        // Replay any buffered file offers from this peer
                        let buffered = st.recv_pending_offers.remove(&from);
                        st.recv_pending_offers.clear();
                        if let Some(offer) = buffered {
                            let _ = tx.send(Ev::Control(from.clone(), offer));
                        }
                        continue;
                    }
                    if is_abort {
                        st.recv_cers.remove(&from);
                        st.recv_deadlines.remove(&from);
                        st.recv_pending_offers.remove(&from);
                        recv_pending_direct.remove(&from);
                        log.debug(&format!(
                            "recv: candidate {from} refused ({abort_why}), dropped"
                        ));
                    }
                    continue;
                }
                // C18: an offer from an unlinked roster peer creates a polite
                // responder link (browsers mesh-dial everyone, fix #7 rules).
                // A responder that could not be built (or a peer announcing a
                // malformed uid) gets no signal applied; the daemon carries on.
                let r = conn.ensure_responder(&from, &data).await;
                if peer_step(daemon, &from, "responder", r, log.as_ref())?.is_none() {
                    continue;
                }
                conn.apply_signal(&from, data).await;
            }
            // rung-1: authenticated direct-QUIC won the race, adopt as a
            // pre-trusted Link, then funnel into the normal ChannelReady handler.
            Ev::DirectReady(pid, t, route) => {
                let tkey = conn
                    .direct_pending
                    .get(&pid)
                    .map(|p| direct::transport_key(&p.secret.1));
                let named_before = conn.link(&pid).and_then(|l| l.verified_name.clone());
                conn.adopt_direct(&pid, t.clone(), route);
                // A direct link to a REMEMBERED device was authenticated by its
                // pair secret (the QUIC keying-material MAC), the proof a
                // WebRTC link gets from `pair-proof`. Only the pair-proof path
                // ever said so, so a daemon receiving from a known device over
                // QUIC (the usual case) never confirmed whose identity it had
                // verified. Said once, when the link first gains the name.
                if named_before.is_none() {
                    if let Some(n) = conn.link(&pid).and_then(|l| l.verified_name.clone()) {
                        if host.devices_load().iter().any(|(d, _)| *d == n) {
                            log.say(&format!("identity verified: '{n}' (auto-accepting)"));
                        }
                    }
                }
                if let Some(k) = tkey {
                    conn.spawn_direct_workers(&pid, &t, k);
                }
                // A link on a brokered meeting place: adoption just copied the
                // dial name into verified_name and marked it trusted. Re-bind it
                // to the broker's proven identity, on every (re)adoption.
                if let Some(by) = brokered_pids.get(&pid) {
                    if let Some(l) = conn.link_mut(&pid) {
                        crate::recv::revocation::bind_brokered_link(l, by);
                    }
                }
                // #30: Send nonce challenge at link adoption so Proven settles
                // before any gated open. Under authoritative, HOLD ChannelReady
                // until the possession-sig round-trip completes or 3s timeout,
                // so short-session gates never decide on Inferred while a
                // challenge is in flight.
                // Resolve identity from the stored cert first so device_pub is
                // populated at adopt time; otherwise needs_proven is always false
                // and the possession-sig challenge never fires.
                if let Some(l) = conn.link_mut(&pid) {
                    crate::identity::resolve_peer_identity(l);
                }
                let (idev_known, proven) = conn
                    .link(&pid)
                    .map(|l| {
                        (
                            l.identity_device_pub.is_some(),
                            l.identity_binding == cap::BindingStrength::Proven,
                        )
                    })
                    .unwrap_or((false, false));
                // #161: in shadow mode, a typed-code link with NO identity still
                // needs the challenge so revocation can bind: shadow mode never
                // resolves a fresh code peer's identity otherwise (the old code
                // issued the challenge under authoritative only), and the gate
                // would then decide a legacy-trusted offer with
                // cert_revoked_for(None)=false, letting a revoked device push a
                // transfer before its revoked cert resolves.
                let needs_challenge = if host.cap_authoritative() {
                    idev_known && !proven
                } else {
                    recv_code_path && !idev_known
                };
                if needs_challenge {
                    // Shared issue-and-hold (hold-then-await; see the helper). This
                    // registers the pending_proven hold BEFORE sending, identically to
                    // the ChannelReady site, so the two sites cannot diverge on order.
                    ports
                        .identity
                        .issue_proven_challenge_and_hold(
                            &conn,
                            &pid,
                            &t,
                            &st.pending_proven,
                            &mut identity_nonces,
                        )
                        .await;
                    if host.cap_authoritative() {
                        log.say(&format!(
                            "  identity challenge sent to {pid}, holding until Proven or timeout"
                        ));
                        // DirectReady-specific release policy: HOLD ChannelReady (do not
                        // emit it here) and RE-EMIT it when the 3s hold expires, so a
                        // direct link's gates never observe Inferred at all.
                        let hold_t = t.clone();
                        let hold_tx = tx.clone();
                        let hold_pending = st.pending_proven.clone();
                        let hold_pid = pid.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(PROVEN_CHALLENGE_DEADLINE).await;
                            if hold_pending.lock().unwrap().contains_key(&hold_pid) {
                                hold_pending.lock().unwrap().remove(&hold_pid);
                                let _ = hold_tx.send(Ev::ChannelReady(hold_pid, hold_t));
                            }
                        });
                    } else {
                        // #161 shadow mode: the typed-code path already rearmed
                        // ChannelReady at PAKE confirm. Issue the challenge for
                        // identity but do NOT hold the channel; the file-offer
                        // hold re-injects the first offer until identity settles.
                        let _ = tx.send(Ev::ChannelReady(pid, t));
                    }
                } else {
                    let _ = tx.send(Ev::ChannelReady(pid, t));
                }
            }
            Ev::DirectWorkersReady(pid, workers) => {
                if let Some(link) = conn.link_mut(&pid) {
                    link.workers = workers;
                    log.debug(&format!(
                        "worker transports ready: {pid} {} workers",
                        link.workers.len()
                    ));
                }
            }
            // P5 (GAP-6): relay->direct upgrade standby connected (receiver side).
            // Stash + VERIFY rather than adopt, see the send-loop twin.
            Ev::DirectUpgradeReady(pid, t, route) => {
                conn.stash_upgrade_standby(&pid, t, route);
            }
            Ev::ChannelReady(pid, t) => {
                // #39 (fleet-trust): the WebRTC/relay path's possession challenge is
                // NOT issued here. At ChannelReady on the WebRTC path, verified_name is
                // not set yet (the pair-proof round-trip sets it AFTER the channel opens),
                // so resolve_peer_identity finds no identity, needs_proven is false, and
                // the challenge would be skipped — the live rig caught exactly this. The
                // challenge for the WebRTC/relay path is issued from the pair-proof
                // handler, where verified_name is set and identity first RESOLVES on that
                // path; the DirectReady path issues at adoption (identity already resolved
                // by then). Both go through the now-idempotent issue_proven_challenge_and_hold,
                // which dedupes by a live pending_proven entry so the two sites are
                // order-independent and cannot clobber each other's nonce.
                //
                // #161 EXCEPTION (typed-code path): a fresh code peer has NO stored pair
                // secret, so pair-proof never fires and the #39 rule above would leave its
                // identity permanently unresolved on the WebRTC transport - the direct
                // path resolves it at DirectReady, the WebRTC path would never. Without
                // the challenge its cert never reaches the gate, so revocation cannot
                // bind and a revoked device's first transfer lands. The challenge is
                // issued at PAKE confirm (the peer is authenticated and its responder
                // loop is live), not here: at ChannelReady the sender is not yet ready
                // to answer, and the 3s hold would expire before it is.
                // #161 EXCEPTION (typed-code path, transport-up re-issue): a
                // fresh code peer has NO stored pair secret, so pair-proof never
                // fires and the #39 rule above would leave its identity
                // permanently unresolved on the WebRTC transport. The direct
                // path resolves it at DirectReady; the WebRTC path issues the
                // challenge at PAKE confirm. When that PAKE-confirm challenge
                // was LOST because the WebRTC transport was not yet up (the
                // direct-blocked fallback establishes the data channel AFTER
                // PAKE), this ChannelReady re-issue delivers it now that the
                // transport is genuinely ready. Gated on recv_pake_done so the
                // normal WebRTC path (ChannelReady BEFORE PAKE) never gets an
                // early challenge the sender cannot answer - only the case
                // where the channel arrived after the ceremony.
                if recv_code_path && recv_pake_done {
                    if let Some(l) = conn.link_mut(&pid) {
                        crate::identity::resolve_peer_identity(l);
                    }
                    let (idev_known, proven) = conn
                        .link(&pid)
                        .map(|l| {
                            (
                                l.identity_device_pub.is_some(),
                                l.identity_binding
                                    == filament_cap::capability::BindingStrength::Proven,
                            )
                        })
                        .unwrap_or((false, false));
                    if !proven && !idev_known {
                        ports
                            .identity
                            .issue_proven_challenge_and_hold(
                                &conn,
                                &pid,
                                &t,
                                &st.pending_proven,
                                &mut identity_nonces,
                            )
                            .await;
                    }
                }
                // web-shell discovery: tell the peer whether this receiver offers a
                // terminal (l2_enabled = `up --shell` / TUNLION_L2). The browser
                // shows its per-device shell button ONLY when this is true; the
                // actual pty-open is still gated server-side by the cap/policy.
                let _ = t
                    .send_control(&json!({ "type": "caps", "shell": l2_enabled }))
                    .await;
                // L3 (serve_tun mesh): on a datagram-capable (direct) link, send a
                // SIGNED announce of our overlay address, bound to THIS link's
                // channel binding so it can't be replayed elsewhere. Both ends
                // announce on their own ChannelReady, so each learns the other.
                // Also replay any announce that arrived BEFORE this transport was
                // installed (fix #3), now that the link can carry datagrams.
                // Fleet auto-mesh: this link came off the fleet channel, so there
                // is no pair secret to prove. Present the owner-signed certificate
                // bound to THIS link instead.
                // No exporter on this transport: open the challenge. Our nonce
                // goes out now; anything we SEND waits until theirs arrives.
                if t.channel_binding().is_none() {
                    // Generate ONCE per link, not per ChannelReady. This fires
                    // again on every re-establish and re-announce, and a fresh
                    // nonce here would invalidate the one the peer is already
                    // signing against, which shows up as a permanent
                    // "signature or channel-binding mismatch". The nonce is
                    // dropped with the link, so a genuinely new link still gets a
                    // new one. Re-send the stored value every time, so a peer
                    // that missed the first copy still gets it.
                    let nonce = bind_ours
                        .entry(pid.clone())
                        .or_insert_with(link_nonce)
                        .clone();
                    let _ = t
                        .send_control(&json!({
                            "type": "l3-nonce",
                            "nonce": base64::engine::general_purpose::STANDARD.encode(&nonce),
                        }))
                        .await;
                }
                // Only for a node that is actually IN a fleet: this fires on every
                // ChannelReady, and a user with no fleet has nothing to diagnose
                // here. It is what made the dial-glare visible, so it stays.
                if ports.identity.fleet_rv().is_some() {
                    log.debug(&format!(
                        "fleet-hello decision pid={pid}: rv={} pending={} shaped={} verified={} cb={} secret={:?}",
                        ports.identity.fleet_rv().is_some(),
                        fleet_pending.contains(&pid),
                        crate::recv::fleet::shaped_link(&conn, &pid, ports.identity.fleet_rv().as_deref()),
                        fleet_verified.contains(&pid),
                        t.channel_binding().is_some(),
                        conn.link(&pid)
                            .and_then(|l| l.expected_secret.as_ref().map(|(n, _)| n.clone())),
                    ));
                }
                // H1: a DataChannel's binding folds in its DTLS fingerprints.
                let link_fps = link_fingerprints(&conn, &pid).await;
                if cfg!(feature = "fleet")
                    && !fleet_verified.contains(&pid)
                    && ports.identity.fleet_rv().is_some()
                    && (fleet_pending.contains(&pid)
                        || crate::recv::fleet::shaped_link(
                            &conn,
                            &pid,
                            ports.identity.fleet_rv().as_deref(),
                        ))
                {
                    // Mark it, so the L3 gate and the drop-cleanup track this link
                    // even when it arrived via warm-hold rather than presence.
                    if cfg!(feature = "fleet") {
                        fleet_pending.insert(pid.clone());
                    }
                    if let Some(cb) = out_binding(&t, &pid, &bind_theirs, link_fps.as_ref()) {
                        match ports
                            .identity
                            .make_fleet_hello(&cb, &ports.env.display_name)
                        {
                            Ok(hello) => {
                                fleet_greeted.insert(pid.clone());
                                let _ = t.send_control(&hello).await;
                            }
                            Err(e) => log.debug(&format!("fleet-hello not sent to {pid}: {e}")),
                        }
                    }
                }
                #[cfg(feature = "mesh")]
                if let Some(l3) = l3.as_ref() {
                    if let Some(cb) = out_binding(&t, &pid, &bind_theirs, link_fps.as_ref()) {
                        if let Some(ann) = l3.make_announce(&cb) {
                            let _ = t.send_control(&ann.to_json()).await;
                        }
                    }
                    if let Some(cb) = in_binding(&t, &pid, &bind_ours, link_fps.as_ref()) {
                        if let Some(pending) = l3_seen.get(&pid) {
                            if let Ok(ip) = pending.verify(&cb) {
                                // Seq check AFTER verify, never before, so an
                                // unauthenticated message cannot poison the
                                // last-seen map. verify() proves the key, the
                                // channel binding and possession; none of those
                                // stop a genuine announce being replayed onto
                                // the SAME channel later.
                                if !crate::recv::fleet::route_ok(
                                    &conn,
                                    &pid,
                                    pending.relay_datagrams,
                                ) {
                                    log.debug(&format!(
                                        "  l3-announce from {pid} ignored: relayed link and peer does not advertise relay datagrams"
                                    ));
                                } else if overlay_key_refused(
                                    &ports,
                                    host.as_ref(),
                                    &pending.pubkey,
                                ) {
                                    // The overlay key IS the device key: a
                                    // revoked or forgotten device gets no route.
                                    log.debug(&format!(
                                        "  l3-announce from {pid} ignored: its key is revoked here"
                                    ));
                                } else if l3.accept_seq(&pending.pubkey, pending.seq).await {
                                    let who =
                                        conn.link(&pid).map(|l| l.shown()).unwrap_or_default();
                                    let v4 = pending.addr_v4();
                                    l3.add_peer(&pid, &who, ip.into(), Some(v4.into()), t.clone())
                                        .await;
                                    // Store overlay addresses for `tunlion addr <device>`
                                    ports.store.devices_touch(&who, Some(ip), Some(v4));
                                } else {
                                    log.debug(&format!(
                                        "  l3-announce from {pid} ignored: stale sequence {}",
                                        pending.seq
                                    ));
                                }
                            }
                        }
                    }
                }
                // Name the peer once, and only by a name. A second link to the
                // same sender (a candidate or a re-dial) announced itself again,
                // and a link not yet named by proof announced its raw signaling
                // id: the lab read "ok w1-a" then "ok DrUEPIADYWGghg6rAAVO".
                let announce = conn.link(&pid).and_then(|l| {
                    let label = l.label().to_string();
                    let raw = crate::conn::label_is_raw_id(&label, &pid, l.uid.as_deref())
                        || conn.links.keys().any(|k| k == &label);
                    let dup = conn.links.iter().any(|(k, o)| {
                        k != &pid && o.presence == Presence::Ready && o.label() == label
                    });
                    if (raw && !log.enabled(Level::Debug)) || dup {
                        log.debug(&format!("link ready: {label} (pid {pid}), not announced"));
                        None
                    } else {
                        Some(label)
                    }
                });
                if let Some(l) = conn.link_mut(&pid) {
                    if let Some(label) = &announce {
                        log.say(&format!(
                            "  {} {}",
                            log.paint(Tone::Ok, log.glyph_ok()),
                            log.paint(Tone::Bold, label)
                        ));
                    }
                    l.transport = Some(t.clone());
                    l.presence = Presence::Ready;
                    let is_direct = l.direct;
                    let direct_route = l.direct_route;
                    if let Some(p) = l.peer.clone() {
                        let log = log.clone();
                        let host = host.clone();
                        tokio::spawn(async move {
                            // ICE may renominate; retry briefly (mirrors the
                            // browser's _detectRoute attempts) so fast transfers
                            // still get a route line before the process exits.
                            for _ in 0..6 {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                                if let Some(r) = p.route().await {
                                    // CRITICAL: the route label is the value-prop,
                                    // direct vs relayed. Always shown, even under -q.
                                    log.debug(&format!(
                                        "    {}",
                                        log.paint(Tone::Dim, &format!("route: {r}"))
                                    ));
                                    // Relay honesty (§3.3): the quiet `route:` line
                                    // is legible but not loud. When the route is
                                    // actually the TURN relay, print the honest
                                    // one-line banner so the user is never unaware
                                    // they're on a middleman path. CRITICAL.
                                    if r == filament_transport::net::ROUTE_RELAY {
                                        log.critical(&format!("    {}", host.relay_banner()));
                                    }
                                    break;
                                }
                            }
                        });
                    } else if is_direct {
                        log.debug(&format!(
                            "    {}",
                            log.paint(
                                Tone::Dim,
                                &format!(
                                    "route: {}",
                                    crate::conn::shown_direct_route(direct_route, &t)
                                )
                            )
                        ));
                    }
                }
                // Warm-reuse readiness: proactively prove our identity to a KNOWN
                // peer on a RELAY/WebRTC link (a DIRECT link is born-verified at
                // adoption, so it skips this). `send_cmd` already does this on its
                // active transfer link (the ChannelReady proof ~5205); the daemon
                // must too, otherwise a passively-held link reaches `✓` but neither
                // end ever sets `verified_name`, so `warm_link_for` rejects it and
                // the FIRST ssh/pty/netcat to an idle paired peer eats a full cold
                // establish. Symmetric by construction: both daemons send, both
                // verify (the `pair-proof` handler below), both can then warm-reuse.
                // No guard, mirroring send_cmd: re-proving on a reconnect is
                // harmless and just refreshes trust.
                let proof_creds = conn.link(&pid).and_then(|l| {
                    if l.direct {
                        return None;
                    }
                    let (_n, sec) = l.expected_secret.clone()?;
                    Some((sec, l.uid.clone().unwrap_or_default(), l.peer.clone()))
                });
                if let Some((sec, uid, peer)) = proof_creds {
                    if let Some((my_fp, their_fp)) = match peer {
                        Some(p) => p.fingerprints().await,
                        None => None,
                    } {
                        let mac =
                            proof_for(&sec, &conn.my_uid, &conn.my_uid, &uid, &my_fp, &their_fp);
                        let _ = t
                            .send_control(&json!({ "type": "pair-proof", "mac": mac }))
                            .await;
                    }
                }
                // L1-a: on the `recv <code>` path, this peer is a CANDIDATE sender.
                // Mint its own ephemeral ceremony (bounded) and arm its per-peer
                // budget plus the overall backstop. The progression block (top of
                // loop) drives every candidate independently; file-offers are not
                // accepted until ONE peer's ceremony confirms (`recv_pake_done`),
                // and then only from that authenticated peer. A stored pairing
                // secret authenticates that known device, but does not prove it
                // minted this one-time code, so every candidate still runs PAKE.
                if recv_code_path && !recv_pake_done {
                    if st.recv_cers.contains_key(&pid) {
                        // Ceremony already minted (its PAKE traffic arrived first);
                        // just make sure its budgets are armed.
                        st.recv_deadlines
                            .entry(pid.clone())
                            .or_insert_with(|| Instant::now() + recv_pake_budget);
                        recv_pake_overall_deadline
                            .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                    } else if st.recv_cers.len() < RECV_MAX_CANDIDATES {
                        if let Some((pw, np)) = &recv_pake_template {
                            st.recv_cers.insert(
                                pid.clone(),
                                Ceremony::new(
                                    pw,
                                    np,
                                    crate::recv::ceremony::pair_v2_caps(),
                                    filament_id::IntroScope::Device.to_byte(),
                                ),
                            );
                            st.recv_deadlines
                                .insert(pid.clone(), Instant::now() + recv_pake_budget);
                            // Once per receive, not once per candidate in the room.
                            if recv_pake_overall_deadline.is_none() {
                                log.say(&log.paint(Tone::Dim, "  authenticating..."));
                            }
                            recv_pake_overall_deadline
                                .get_or_insert_with(|| Instant::now() + recv_pake_budget);
                        }
                    }
                }
            }
            Ev::Control(pid, v) => match log_ctl_rx(&pid, v["type"].as_str(), log.as_ref()) {
                // L3 (serve_tun): the peer announced its overlay IP. Route that IP
                // to this link and start pumping its datagrams into our TUN. Only
                // when we run an overlay ourselves; ignored otherwise.
                // Check BEFORE the catch-all guard so announces that race ahead of
                // link creation are cached in l3_seen for replay on ChannelReady.
                // The peer's half of the link challenge (transports with no
                // RFC-5705 exporter). Store it, then send everything that was
                // waiting on a binding: our announce, and our fleet-hello.
                // Fleet policy relayed by a sibling. Only ops the OWNER signed
                // survive `merge_owner_cap_ops`, so a peer can relay policy but
                // never author it.
                Some("fleet-policy") => {
                    if let Some(ops) = v["ops"].as_array() {
                        let n = ports.store.merge_owner_cap_ops(ops);
                        if n > 0 {
                            log.debug(&format!("fleet policy from {pid}: {n} new op(s)"));
                        }
                    }
                }
                #[cfg(feature = "mesh")]
                Some("l3-nonce") => {
                    match v["nonce"].as_str().map(unb64) {
                        Some(Ok(nonce)) if nonce.len() >= 16 => {
                            bind_theirs.insert(pid.clone(), nonce);
                            if let Some(t) = conn.transport_of(&pid) {
                                let link_fps = link_fingerprints(&conn, &pid).await;
                                if let Some(cb) =
                                    out_binding(&t, &pid, &bind_theirs, link_fps.as_ref())
                                {
                                    #[cfg(feature = "mesh")]
                                    if let Some(l3) = l3.as_ref() {
                                        if let Some(ann) = l3.make_announce(&cb) {
                                            let _ = t.send_control(&ann.to_json()).await;
                                        }
                                    }
                                    // Answer EVERY nonce with a fresh hello, even
                                    // one we have already greeted. A repeat nonce
                                    // means the peer could not verify what we sent
                                    // (its challenge had not reached us when we
                                    // signed) and is asking again. Honouring
                                    // `fleet_greeted` here would leave it waiting
                                    // forever for a proof we refuse to re-send.
                                    if cfg!(feature = "fleet") && !fleet_verified.contains(&pid) {
                                        if let Ok(hello) = ports
                                            .identity
                                            .make_fleet_hello(&cb, &ports.env.display_name)
                                        {
                                            fleet_greeted.insert(pid.clone());
                                            let _ = t.send_control(&hello).await;
                                        }
                                    }
                                }
                            }
                        }
                        // A short or malformed nonce is refused rather than used:
                        // a peer that picks a weak challenge would weaken OUR
                        // replay protection, not theirs.
                        _ => log.debug(&format!(
                            "l3-nonce from {pid} ignored: missing or too short"
                        )),
                    }
                }
                // Fleet auto-mesh: a same-owner device is presenting its
                // certificate. Three things must hold together (fleet.rs): live
                // possession bound to THIS link, a certificate chaining to OUR
                // owner key, and both naming the same device key. Anything less
                // and the link stays unverified, so it never gains a route.
                #[cfg(feature = "fleet")]
                Some(fleet::HELLO) => {
                    let link_fps = link_fingerprints(&conn, &pid).await;
                    let cb = conn
                        .transport_of(&pid)
                        .and_then(|t| in_binding(&t, &pid, &bind_ours, link_fps.as_ref()));
                    let owner = ports.identity.fleet_owner_pub();
                    match (cb, owner) {
                        (Some(cb), Some(owner)) => {
                            match fleet::verify_hello(&v, &cb, &owner, identity::now_secs()) {
                                Ok(ok) if ports.identity.device_cert_revoked(&ok.device_pub) => {
                                    log.debug(&format!(
                                        "fleet-hello from {pid} refused: device revoked"
                                    ));
                                    fleet_pending.remove(&pid);
                                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                    sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                                    conn.drop_link(&pid);
                                }
                                Ok(ok) => {
                                    let fresh = fleet_verified.insert(pid.clone());
                                    // Identity has settled: replay whatever arrived
                                    // while it had not. This belongs HERE, beside
                                    // the insert, not in the `fresh` branch below:
                                    // the deferral waits on "verified", and a link
                                    // that re-verifies is verified just the same.
                                    {
                                        let replay: Vec<_> = fleet_deferred_offers
                                            .iter()
                                            .filter(|(p, _, _)| p == &pid)
                                            .cloned()
                                            .collect();
                                        fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                        for (p, ov, _) in replay {
                                            log.debug(&format!(
                                                "fleet: replaying offer deferred while {p} was unverified"
                                            ));
                                            let _ = tx.send(Ev::Control(p, ov));
                                        }
                                    }
                                    // Reachability, NOT capability: an empty
                                    // ceiling. The link forms, warm-hold keeps it
                                    // and L3 routes to it, while transfer, shell
                                    // and mount still need their own grant.
                                    // verified_name is the CAP-STORE KEY, so it is
                                    // resolved from the PROVEN certificate key, never
                                    // from the name the peer sent. A peer that could
                                    // name itself could name itself after a device
                                    // that holds grants.
                                    let proven_name =
                                        ports.identity.device_name_for_pub(&ok.device_pub);
                                    // The ceiling comes from the RECORD, which is
                                    // what `tunlion grant` edits. Hardcoding it
                                    // empty made auto-mesh peers ungrantable: the
                                    // grant landed in devices.json and the live
                                    // link kept refusing, so `grant` silently did
                                    // nothing for exactly the devices this feature
                                    // adds. A sibling we hold no record for still
                                    // gets nothing, which is the intended
                                    // reachability-without-capability default.
                                    if let Some(l) = conn.link_mut(&pid) {
                                        l.verified_name = proven_name.clone();
                                        l.admit_fleet(ok.owner_pub, ok.device_pub, ok.cert_expires);
                                    }
                                    // Answer once, so a mutual hello terminates.
                                    if fleet_greeted.insert(pid.clone()) {
                                        if let Some(t) = conn.transport_of(&pid) {
                                            if let Ok(hello) = ports
                                                .identity
                                                .make_fleet_hello(&cb, &ports.env.display_name)
                                            {
                                                let _ = t.send_control(&hello).await;
                                            }
                                        }
                                    }
                                    // Re-announce our overlay address: an announce
                                    // that arrived while this link was unverified
                                    // was DROPPED (below), so without this the
                                    // route would never form.
                                    #[cfg(feature = "mesh")]
                                    if let Some(l3) = l3.as_ref() {
                                        if let Some(t) = conn.transport_of(&pid) {
                                            if let Some(ann) = l3.make_announce(&cb) {
                                                let _ = t.send_control(&ann.to_json()).await;
                                            }
                                        }
                                    }
                                    // Fleet policy push. Enrollment seeds a device
                                    // once; grants made LATER would never reach it,
                                    // so re-push on every verified hello. The peer
                                    // verifies each op against the owner key it
                                    // already holds, and merging is idempotent, so
                                    // repeating this is cheap and self-healing.
                                    {
                                        let ops = ports.store.owner_signed_cap_ops();
                                        if !ops.is_empty() {
                                            if let Some(t) = conn.transport_of(&pid) {
                                                let _ = t
                                                    .send_control(&json!({
                                                        "type": "fleet-policy",
                                                        "ops": ops,
                                                    }))
                                                    .await;
                                            }
                                        }
                                    }
                                    if fresh {
                                        // Proven petname when we have one; otherwise
                                        // the claimed display name, presentation only.
                                        let shown =
                                            proven_name.clone().unwrap_or(ok.claimed_name.clone());
                                        // Record the sibling so `tunlion devices`
                                        // can show the fleet. Deliberately with NO
                                        // pair secret: host.devices_load() filter-maps on
                                        // `secret`, so this record can never become a
                                        // channel subscription or a dial target. It is
                                        // an INDEX ENTRY, not an authorization, and the
                                        // empty ceiling it carries matches the link's.
                                        if proven_name.is_none() {
                                            // Transplant refusal: compare the SANITIZED
                                            // name -- the store keys on the sanitized
                                            // form, so "laptop " or control-char variants
                                            // must match "laptop" here, not slip past to
                                            // land on it in the write below. Bounded to
                                            // the same length the other network-supplied
                                            // strings get: the name is peer-controlled, and
                                            // an unbounded one would be a log/record flood.
                                            let shown: String = ports
                                                .store
                                                .sanitize_device_name(&shown)
                                                .chars()
                                                .take(64)
                                                .collect();
                                            // A claimed name matching an EXISTING record
                                            // is never indexed under. The store pin
                                            // below would refuse the write anyway; this
                                            // refuses before attempting it and never
                                            // binds the link to the name.
                                            let name_taken =
                                                std::fs::read_to_string(ports.store.devices_path())
                                                    .ok()
                                                    .and_then(|raw| {
                                                        serde_json::from_str::<Value>(&raw).ok()
                                                    })
                                                    .and_then(|v| v.as_array().cloned())
                                                    .map(|arr| {
                                                        arr.iter().any(|d| {
                                                            d["name"].as_str()
                                                                == Some(shown.as_str())
                                                        })
                                                    })
                                                    .unwrap_or(false);
                                            if name_taken {
                                                // A REFUSAL, not chatter: a peer tried to
                                                // take over another device's identity. Emitted
                                                // at Critical so `-q` cannot hide it, with a
                                                // STABLE TOKEN first so gates and log
                                                // pipelines match on structure rather than on
                                                // prose that a later edit may reword.
                                                log.critical(&format!(
                                                    "l2: refuse reason=name-taken claimed='{shown}' existing='{shown}' (this is not the device paired under that name)"
                                                ));
                                            } else if let Some(cert) =
                                                identity::DeviceCert::from_json(&v["cert"])
                                            {
                                                // Strict: a peer-asserted name may never
                                                // take over a pinned identity (F1).
                                                match ports.store.devices_upsert_atomic(
                                                    &shown,
                                                    None,
                                                    Some(&cert),
                                                    Some(&[]),
                                                    Some(identity::IntroScope::Device.to_byte()),
                                                    None,
                                                    None,
                                                    false,
                                                ) {
                                                    Ok(stored) => {
                                                        // Bind the link to the record we
                                                        // just created. Without this the
                                                        // FIRST contact leaves
                                                        // verified_name unset (there was
                                                        // no record when we looked it up),
                                                        // so the daemon cannot resolve
                                                        // this peer by name until some
                                                        // later reconnect happens to
                                                        // re-run the lookup. The name is
                                                        // still the PROVEN one: it came
                                                        // from the certificate we just
                                                        // verified.
                                                        if let Some(l) = conn.link_mut(&pid) {
                                                            l.verified_name = Some(stored.clone());
                                                        }
                                                        log.debug(&format!(
                                                            "fleet peer indexed as '{stored}'"
                                                        ));
                                                    }
                                                    Err(e) => log.debug(&format!(
                                                        "fleet peer not indexed: {e}"
                                                    )),
                                                }
                                            }
                                        }
                                        // The overlay route was installed at announce
                                        // time, when this link had no name yet, so its
                                        // MagicDNS entry still reads as the placeholder.
                                        // Correct it now that the certificate has named
                                        // the device.
                                        #[cfg(feature = "mesh")]
                                        if let Some(l3) = l3.as_ref() {
                                            if l3.rename_peer(&pid, &sanitize_host(&shown)).await {
                                                l3.refresh_hosts().await;
                                            }
                                        }
                                        log.say(&format!("fleet device '{shown}' joined the mesh"));
                                        // A link to a fleet peer is the only
                                        // chance a joined device gets to reach a
                                        // primary. Ask here rather than on a
                                        // timer: a device that is only
                                        // occasionally connected would otherwise
                                        // tick past its own expiry while offline.
                                        ports
                                            .identity
                                            .maybe_request_cert_renewal(&conn, &pid)
                                            .await;
                                    }
                                }
                                Err(e) => {
                                    log.debug(&format!("fleet-hello from {pid} rejected: {e}"));
                                    fleet_pending.remove(&pid);
                                    fleet_deferred_offers.retain(|(p, _, _)| p != &pid);
                                    sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                                    conn.drop_link(&pid);
                                }
                            }
                        }
                        _ => log.debug(&format!(
                            "fleet-hello from {pid} ignored: no channel binding or no owner key"
                        )),
                    }
                }
                // A sibling's daemon brokered a private meeting place for one of
                // its one-shots. Join it, so the one-shot meets exactly us.
                //
                // ONLY from a link whose certificate we already verified. The
                // secret grants a meeting place and, on that place, the ordinary
                // known-device proof, so accepting one from an unverified link
                // would let mere presence on the fleet channel manufacture a
                // trusted-looking peering, which is the one thing this design says
                // presence must never buy.
                #[cfg(feature = "fleet")]
                Some("fleet-rendezvous") if fleet_verified.contains(&pid) => {
                    match v["secret"].as_str() {
                        Some(sec) if hex::decode(sec).map(|b| b.len()).ok() == Some(32) => {
                            let ch = host.channel_of(sec);
                            // Who brokered it, as PROVEN on this link by its
                            // fleet-hello. A link verified but missing any of
                            // these is not one to accept a meeting place from.
                            let broker = conn.link(&pid).and_then(|l| {
                                Some(crate::recv::revocation::BrokeredBy {
                                    device_pub: l.identity_device_pub?,
                                    owner_pub: l.identity_user_pub?,
                                    expires: l.identity_cert_expires?,
                                    name: l.verified_name.clone(),
                                })
                            });
                            match broker {
                                None => log.debug(&format!(
                                    "fleet-rendezvous from {pid} ignored: no proven identity on the link"
                                )),
                                Some(broker) if !sess.channels.contains(&ch) => {
                                    sess.channels.push(ch.clone());
                                    let _ = sio
                                        .emit("subscribe", json!({ "channels": [ch.clone()] }))
                                        .await;
                                    brokered.insert(ch, (sec.to_string(), broker));
                                    log.debug(&format!(
                                        "fleet-rendezvous: joined a brokered channel for {pid}"
                                    ));
                                }
                                Some(_) => {}
                            }
                        }
                        _ => log.debug("fleet-rendezvous: ignored a malformed secret"),
                    }
                }
                #[cfg(feature = "mesh")]
                Some("l3-announce") if l3.is_some() => {
                    // A fleet link that has not proven its certificate gets NO
                    // overlay route, and its announce is not even cached for
                    // replay. Otherwise mere presence on the meeting point would
                    // buy an IP route, which is the one thing the design says
                    // presence must never buy.
                    if crate::recv::fleet::identity_pending(
                        &conn,
                        &pid,
                        fleet_pending.contains(&pid),
                        fleet_verified.contains(&pid),
                    ) {
                        log.debug(&format!(
                            "l3-announce from unverified fleet link {pid} ignored"
                        ));
                        continue;
                    }
                    match Announce::from_json(&v) {
                        Ok(ann) => {
                            l3_seen.insert(pid.clone(), ann.clone());
                            // Try to process immediately if transport is available.
                            if let Some(l3) = l3.as_ref() {
                                let link_fps = link_fingerprints(&conn, &pid).await;
                                match conn.transport_of(&pid).and_then(|t| {
                                    in_binding(&t, &pid, &bind_ours, link_fps.as_ref())
                                        .map(|cb| (t, cb))
                                }) {
                                    Some((t, cb)) => match ann.verify(&cb) {
                                        Ok(ip) => {
                                            // The overlay key IS the device key: a
                                            // revoked or forgotten device gets no route.
                                            if overlay_key_refused(
                                                &ports,
                                                host.as_ref(),
                                                &ann.pubkey,
                                            ) {
                                                log.debug(&format!(
                                                    "  l3-announce from {pid} ignored: its key is revoked here"
                                                ));
                                                continue;
                                            }
                                            // Seq check AFTER verify, never before, so an
                                            // unauthenticated message cannot poison the
                                            // last-seen map. verify() proves address-is-key,
                                            // channel binding and possession; none of those
                                            // stop a GENUINE announce captured on this
                                            // channel from being replayed onto it later,
                                            // which is an address rollback (see accept_seq).
                                            if !l3.accept_seq(&ann.pubkey, ann.seq).await {
                                                log.debug(&format!(
                                                    "  l3-announce from {pid} ignored: stale sequence {}",
                                                    ann.seq
                                                ));
                                                continue;
                                            }
                                            let who = conn
                                                .link(&pid)
                                                .map(|l| l.shown())
                                                .unwrap_or_default();
                                            // Verify-order fix: overlay key vs pinned cert check happens HERE at overlay establishment,
                                            // not at expose time. Possession-proven key already committed at expose time (provisional).
                                            // On mismatch, tear down with named error, never overwrite anchor.
                                            // Durable trust is written ONLY after this check passes.
                                            {
                                                let p = ports.store.devices_path();
                                                if let Ok(raw) = std::fs::read_to_string(&p) {
                                                    if let Ok(arr) =
                                                        serde_json::from_str::<Vec<Value>>(&raw)
                                                    {
                                                        if let Err(e) = identity::check_overlay_against_pinned_cert(&arr, &who, &ann.pubkey) {
                                                            log.say(&log.paint(Tone::Warn, &format!("  {}", e)));
                                                            // Tear down: do not add peer, do not overwrite anchor, clear provisional
                                                            ports.identity.clear_provisional_identity(&who);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            // Promote provisional identity to durable if present and matches overlay key
                                            if let Some(prov_cert) =
                                                ports.identity.load_provisional_identity(&who)
                                            {
                                                if let Err(e) = identity::provisional_promote_ok(
                                                    &prov_cert,
                                                    &ann.pubkey,
                                                ) {
                                                    log.say(&log.paint(
                                                        Tone::Warn,
                                                        &format!(
                                                            "  {} for device {} - clearing provisional, no anchor written",
                                                            e, who
                                                        ),
                                                    ));
                                                    ports.identity.clear_provisional_identity(&who);
                                                    // Do not add peer, no durable write
                                                    continue;
                                                }
                                                // Check takeover guard and scope-aware anchor before promoting
                                                {
                                                    // For promote, use Device-scope as fixed convention for pair
                                                    let scope =
                                                        filament_id::IntroScope::Device.to_byte();
                                                    match ports.store.promote_provisional_identity(
                                                        &who, &prov_cert, scope,
                                                    ) {
                                                        Ok(_) => {
                                                            // Write durable anchor only after overlay assertion passes
                                                            ports
                                                                .identity
                                                                .clear_provisional_identity(&who);
                                                        }
                                                        Err(e) => {
                                                            log.say(&log.paint(
                                                                Tone::Warn,
                                                                &format!(
                                                                    "  takeover guard at overlay establishment: {}",
                                                                    e
                                                                ),
                                                            ));
                                                            ports
                                                                .identity
                                                                .clear_provisional_identity(&who);
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            let v4 = ann.addr_v4();
                                            if !crate::recv::fleet::route_ok(
                                                &conn,
                                                &pid,
                                                ann.relay_datagrams,
                                            ) {
                                                log.debug(&format!(
                                                    "  L3 route for {who} withheld: relayed link and peer does not advertise relay datagrams"
                                                ));
                                                l3.set_peer_subnets(&pid, &t, &[]).await;
                                                continue;
                                            }
                                            l3.add_peer(
                                                &pid,
                                                &who,
                                                ip.into(),
                                                Some(v4.into()),
                                                t.clone(),
                                            )
                                            .await;
                                            log.say_folded(&format!(
                                                "  {} L3 peer {who}.mesh ({ip} / {v4})",
                                                log.paint(Tone::Ok, log.glyph_ok())
                                            ));
                                            ports.store.devices_touch(&who, Some(ip), Some(v4));

                                            // Subnet routes, after the peer is on
                                            // the overlay. Three conditions, in
                                            // increasing cost: the advertisement
                                            // must be SIGNED (verify_routes, which
                                            // also covers seq so a withdrawn prefix
                                            // cannot be resurrected), this machine
                                            // must ACCEPT routes from this device,
                                            // and the owner must have GRANTED each
                                            // prefix by name.
                                            let advertised = ann.verify_routes(&cb);
                                            // NO EMPTY-SET SHORTCUT. An announce
                                            // carrying no routes is not "nothing
                                            // to do", it is a WITHDRAWAL, and
                                            // set_peer_subnets is a full
                                            // restatement of what this peer
                                            // carries. Skipping the block left a
                                            // withdrawn route installed forever:
                                            // the operator cleared
                                            // advertise-routes, the peer stopped
                                            // advertising, and the receiver kept
                                            // routing through it. For an exit
                                            // node that is not a stale entry, it
                                            // is a default route pointing into a
                                            // tunnel nobody is carrying, which
                                            // is indistinguishable from the
                                            // machine losing the internet.
                                            {
                                                let accept = host
                                                    .settings_get_str_for(
                                                        "accept-routes",
                                                        Some(&who),
                                                    )
                                                    .map(|v| v == "on" || v == "true")
                                                    .unwrap_or(false);
                                                // The OWNER's public key, which is
                                                // not the same as holding the
                                                // owner's signing key.
                                                //
                                                // FOUND BY RUNNING IT, not by a
                                                // test: `UserKey::load` returns
                                                // None on a JOINED device, because
                                                // a fleet member has no user
                                                // signing key. Deriving the
                                                // resource from it therefore made
                                                // every fleet member refuse every
                                                // route, which is precisely the
                                                // population subnet routes exist
                                                // for. The owner's PUBLIC key is
                                                // carried in the device's own
                                                // certificate, which the owner
                                                // signed, so a joined device knows
                                                // it without holding anything
                                                // secret.
                                                let owner_pk =
                                                    ports.identity.owner_pub_for_resources();
                                                let idev = conn
                                                    .link(&pid)
                                                    .and_then(|l| l.identity_device_pub);
                                                let iusr = conn
                                                    .link(&pid)
                                                    .and_then(|l| l.identity_user_pub);
                                                // A DELEGATED principal's authority
                                                // is its enrollment ceiling, which
                                                // the owner signed inside the
                                                // invitation and enrollment
                                                // verified. That is the same source
                                                // transfer and mount are authorized
                                                // from, so route reads it too.
                                                //
                                                // Why it is needed at all: no grant
                                                // can bind to a fleet member (a
                                                // CapOp targets the owner user key
                                                // that every member presents, so it
                                                // cannot name one device), which is
                                                // why `grant` refuses outright. With
                                                // only the cap-store path, a router
                                                // that is a fleet member could never
                                                // be authorized by any route at all.
                                                //
                                                // Read the ceiling from the PERSISTED
                                                // record, not from the link's
                                                // principal. Which admission path ran
                                                // decides what the link says: a peer
                                                // that reconnects through fleet-hello
                                                // is admitted by admit_fleet as
                                                // FleetDevice, which carries no caps
                                                // at all, while only a fresh
                                                // enrollment produces Delegated{caps}.
                                                // Matching on Delegated therefore
                                                // worked exactly once per join and
                                                // silently stopped after the first
                                                // reconnect. The stored ceiling is the
                                                // same source `devices` renders and
                                                // `grant` consults, so all three agree
                                                // by construction.
                                                //
                                                // SCOPED, not a bare yes. The ceiling
                                                // entries are `route:<cidr>`, taken
                                                // from the signed invitation, so this
                                                // asks whether the advertised prefix
                                                // is INSIDE one the owner allowed. A
                                                // bare `route` used to authorise every
                                                // prefix a member cared to advertise,
                                                // 0.0.0.0/0 included, which is an exit
                                                // node the owner never agreed to.
                                                let ceiling = host
                                                    .principal_ceiling_for(&who)
                                                    .unwrap_or_default();
                                                let cap_entries = host.cap_store();
                                                let cap_now = host.now_secs();
                                                let RouteAcceptance {
                                                    accepted: ok,
                                                    declined,
                                                } = accept_advertised(
                                                    &advertised,
                                                    RoutePolicy {
                                                        accept_routes: accept,
                                                        ceiling: &ceiling,
                                                        owner_pub: owner_pk,
                                                        cap_store: &cap_entries,
                                                        device_pub: idev,
                                                        user_pub: iusr,
                                                        now: cap_now,
                                                    },
                                                );
                                                if declined > 0 {
                                                    // Say so rather than silently
                                                    // dropping: an advertisement
                                                    // that vanishes without a word
                                                    // is indistinguishable from one
                                                    // that was never sent.
                                                    log.debug(&format!(
                                                        "  {declined} of {} route(s) from {who} not installed (accept-routes={accept}, or not granted)",
                                                        advertised.len()
                                                    ));
                                                }
                                                // ALWAYS restate, including the
                                                // empty case. set_peer_subnets is
                                                // a full restatement of what this
                                                // peer carries, so an empty list
                                                // is how a WITHDRAWAL is applied.
                                                // Skipping it left a withdrawn
                                                // route installed forever: the
                                                // operator ran
                                                // `set advertise-routes ''`, the
                                                // peer stopped advertising, and
                                                // the receiver kept routing
                                                // through it. With an exit node
                                                // that is not a stale route, it
                                                // is a machine with a default
                                                // route pointing into a tunnel
                                                // nobody is carrying.
                                                l3.set_peer_subnets(&pid, &t, &ok).await;
                                                if !ok.is_empty() {
                                                    log.say(&format!(
                                                        "  {} routes via {who}: {}",
                                                        log.paint(Tone::Ok, log.glyph_ok()),
                                                        ok.join(", ")
                                                    ));
                                                }
                                            }
                                        }
                                        Err(e) => log.debug(&log.paint(
                                            Tone::Warn,
                                            &format!("  L3 announce rejected: {e}"),
                                        )),
                                    },
                                    // Transport not installed yet: kept in l3_seen, replayed on ChannelReady.
                                    None => {}
                                }
                            }
                        }
                        Err(e) => log.debug(&format!("  L3 malformed announce: {e}")),
                    }
                }
                // The peer cannot answer our identity challenge (it holds no
                // certificate for its own key, or the challenge named its own
                // key). Identity will not resolve on this link, so the offer
                // hold that waits for it ends now and the offer goes to the
                // normal gate, the same decision the hold reaches on expiry.
                // Without this every code transfer from a device with no
                // identity sat 20 s (RECV_IDENTITY_HOLD_DEADLINE) before its
                // first byte. Only an answer to OUR outstanding nonce counts.
                Some("identity-unavailable") => {
                    let ours = identity_nonces
                        .get(&pid)
                        .map(|(n, _, _)| hex::encode(n))
                        .is_some_and(|n| Some(n.as_str()) == v["nonce"].as_str());
                    if ours {
                        identity_nonces.remove(&pid);
                        st.pending_proven.lock().unwrap().remove(&pid);
                        if let Some(expired) =
                            Instant::now().checked_sub(RECV_IDENTITY_HOLD_DEADLINE)
                        {
                            recv_identity_hold.insert(pid.clone(), expired);
                        }
                        log.debug(&format!(
                            "  {pid} cannot prove an identity; deciding its offers without waiting"
                        ));
                    }
                }
                // #30: respond to identity nonce challenge by producing a
                // possession_sig (0x02) over the peer-provided nonce. The
                // challenger verifies and upgrades our binding to Proven.
                #[cfg(feature = "mesh")]
                Some("identity-nonce-challenge") => {
                    // #30: shared responder (also used by send_cmd) proves
                    // device-key possession so the challenger upgrades us to Proven.
                    // A challenge that cannot be answered because the link has no
                    // transport is a DROP, and it used to be silent: the challenger
                    // then times out while we look idle, which is exactly the
                    // asymmetry that made an unprovable link invisible.
                    match conn.transport_of(&pid) {
                        Some(t) => ports.identity.respond_to_identity_challenge(&t, &v).await,
                        None => log.say(&format!(
                            "l2: identity challenge received for {pid} but that link has no transport; not answered"
                        )),
                    }
                }
                // #30: received possession-sig from peer after our challenge.
                // Verify, upgrade binding to Proven so capability gates pass.
                #[cfg(feature = "mesh")]
                Some("identity-expose") => {
                    log.debug(&format!("identity-expose received on {pid}"));
                    if ports.identity.handle_identity_expose(
                        &mut conn,
                        &pid,
                        &v,
                        &mut identity_nonces,
                    ) {
                        // Release held ChannelReady — Proven settled before timeout.
                        if let Some((held_t, _deadline)) =
                            st.pending_proven.lock().unwrap().remove(&pid)
                        {
                            let _ = tx.send(Ev::ChannelReady(pid, held_t));
                        }
                    }
                }
                Some("worker-ports") => {
                    let pid = v["for"].as_str().unwrap_or_default();
                    log.trace(&format!(
                        "[T:CLI] worker-ports handler: looking up key={pid}"
                    ));
                    if let Some(tx) = conn.worker_port_tx.remove(pid) {
                        log.trace(&format!("[T:CLI] worker-ports handler: FOUND key={pid}"));
                        let ports: Vec<u16> = v["ports"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|p| p.as_u64().map(|x| x as u16))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let _ = tx.send(ports);
                    }
                }
                // WireGuard key announcement. Symmetric: whoever hears one
                // configures that peer and answers with its own if it has not
                // already, so two messages converge and neither end waits for
                // the other to move first. This rides the control channel
                // because an out-of-band QUIC stream races with tunlion's own
                // stream acceptor: the first version opened one and both ends
                // hung after creating their interface.
                Some("wg-key") => {
                    let enabled = host
                        .settings_get_str("wireguard")
                        .map(|x| x == "on" || x == "true")
                        .unwrap_or(false);
                    if enabled && ports.daemon.wg_usable() {
                        let peer_pub = v["pubkey"].as_str().unwrap_or_default().to_string();
                        let peer_port = v["port"].as_u64().unwrap_or(0) as u16;
                        let underlay = conn.transport_of(&pid).and_then(|t| t.remote_addr());
                        let peer_overlay = match l3.as_ref() {
                            Some(l) => l.peer_overlay_of(&pid).await,
                            None => None,
                        };
                        let ours = l3
                            .as_ref()
                            .and_then(|l| l.my_addr())
                            .map(|a| a.to_string())
                            .unwrap_or_default();
                        match (underlay, peer_overlay) {
                            (Some(sa), Some(po)) if !peer_pub.is_empty() && peer_port != 0 => {
                                match ports.daemon.wg_local_offer() {
                                    Ok((our_pub, our_port)) => {
                                        // The peer's real endpoint and port are
                                        // no longer needed: WireGuard talks to a
                                        // loopback stand-in and tunlion carries
                                        // the frames, so NAT never sees a
                                        // WireGuard packet.
                                        if let Err(e) = ports.daemon.wg_adopt_peer(
                                            &peer_pub,
                                            &po.to_string(),
                                            &ours,
                                            1380,
                                            sa.ip(),
                                            peer_port,
                                        )
                                        .await
                                        {
                                            log.debug(&format!("  wg: could not adopt peer ({e})"));
                                        } else {
                                            log.say(&format!(
                                                "  {} WireGuard tunnel to {}",
                                                log.paint(Tone::Ok, log.glyph_ok()),
                                                conn.link(&pid)
                                                    .map(|l| l.shown())
                                                    .unwrap_or_default()
                                            ));
                                        }
                                        // Answer once, so the other end can
                                        // adopt us too. claim_attempt makes this
                                        // idempotent across repeats.
                                        if ports.daemon.wg_claim_attempt(&po.to_string()) {
                                            if let Some(t) = conn.transport_of(&pid) {
                                                let _ = t
                                                    .send_control(&json!({
                                                        "type": "wg-key",
                                                        "pubkey": our_pub,
                                                        "port": our_port,
                                                    }))
                                                    .await;
                                            }
                                        }
                                    }
                                    Err(e) => log.debug(&format!("  wg: no local interface ({e})")),
                                }
                            }
                            _ => log.debug(
                                "  wg: key announcement ignored (no direct endpoint or overlay address yet)",
                            ),
                        }
                    }
                }
                // Certificate renewal. Expiry is the only bound this system has,
                // so renewal is also how removal works: an owner that stops
                // renewing evicts a device without needing to reach it.
                Some("identity-cert-renew-request") => {
                    ports
                        .identity
                        .respond_to_cert_renew_request(&mut conn, pid.clone())
                        .await;
                }
                Some("identity-cert-renew-ack") => {
                    ports.identity.handle_cert_renew_ack(&v).await;
                }
                Some("identity-cert-renew-error") => {
                    // Deliberately quiet and deliberately not fatal. A refusal
                    // may mean "removed", but it may equally mean the peer we
                    // asked is not a primary. Falling out at expiry is the
                    // correct failure direction either way, so we simply keep
                    // the certificate we have and ask again on the next link.
                    log.debug("  peer declined to renew our certificate");
                }
                // Auth key enrollment (challenge/response flow)
                Some("identity-auth-key-enroll-request") => {
                    ports
                        .identity
                        .respond_to_auth_key_enroll_request(&mut conn, pid.clone(), v.clone())
                        .await;
                }
                Some("identity-auth-key-enroll-response") => {
                    // Daemon receives the enrollment response with possession proofs.
                    // Must have a pending challenge nonce for this peer.
                    ports
                        .identity
                        .handle_auth_key_enroll_response(&mut conn, pid.clone(), v.clone())
                        .await;
                    // A successful join adds a reconnect secret. Refresh the
                    // daemon's live channel set immediately; waiting for restart
                    // would make the persisted ceiling correct but unreachable.
                    devices = host.devices_load();
                    sess.channels = devices
                        .iter()
                        .map(|(_, secret)| host.channel_of(secret))
                        .collect();
                    if let Some(fc) = ports.identity.fleet_channel() {
                        if !sess.channels.contains(&fc) {
                            sess.channels.push(fc);
                        }
                    }
                    sess.invalidate();
                }
                Some("depart") => {
                    // Advisory goodbye: a joined device asks to free its slot NOW.
                    // Verify possession of the claimed device_pub, then mark the
                    // record lapsed immediately. Never load-bearing: if this
                    // message never arrives, the offline budget lapses it anyway.
                    let dpub_hex = v["device_pub"].as_str().unwrap_or_default();
                    let msg = v["msg"].as_str().unwrap_or_default();
                    let sig_hex = v["sig"].as_str().unwrap_or_default();
                    if let (Ok(dpub), Ok(sig)) = (hex::decode(dpub_hex), hex::decode(sig_hex)) {
                        if let (Ok(dpub_arr), Ok(sig_arr)) = (
                            dpub.as_slice().try_into().map(|a: &[u8; 32]| *a),
                            sig.as_slice().try_into().map(|a: &[u8; 64]| *a),
                        ) {
                            // The message must be EXACTLY the depart text for
                            // this key (rebuilt here, never trusted from the
                            // wire); a valid signature over anything else is a
                            // different statement and must not lapse the device.
                            if let Err(why) = ports.identity.verify_depart(&dpub_arr, msg, &sig_arr)
                            {
                                log.say(&format!(
                                    "{} refused a depart request from {pid}: {why}",
                                    log.paint(Tone::Warn, "!")
                                ));
                            } else {
                                if let Some(name) = ports.store.mark_lapsed_now(&dpub_arr) {
                                    log.say(&format!(
                                        "{} {name} departed; slot freed immediately",
                                        log.paint(Tone::Dim, "·")
                                    ));
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(
                                                &json!({"type": "depart-ack", "name": name}),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
                // Owner-signed mesh roster push (v1, display-only). Verify
                // against the owner key held in OUR device certificate (the
                // issuer), accept only a newer (epoch, valid_until), store for
                // `devices` to render. The roster NEVER feeds an authorization
                // decision, so a failed receipt (bad sig / wrong owner / replay /
                // expired) is a silent no-op, logged at debug only.
                Some("roster") => {
                    if let Some(cert) = ports.identity.local_device_cert() {
                        match ports.identity.verify_and_store_roster(
                            &v,
                            &cert.user_pub,
                            identity::now_secs(),
                        ) {
                            Ok(true) => log.debug(&format!(
                                "roster: accepted epoch {} from owner",
                                v["epoch"].as_u64().unwrap_or(0)
                            )),
                            Ok(false) => {}
                            Err(e) => log.debug(&format!("roster: rejected: {e}")),
                        }
                    }
                }
                _ if !conn.links.contains_key(&pid) => {}
                // A peer whose pair-proof FAILED here (forgotten, or never
                // paired) and that has proven no other identity since: refuse
                // every shell-class open with that fact, ahead of the serving
                // and capability arms below. Those would answer "serving is off"
                // or "no grant", and either sends the user to a fix that cannot
                // apply to a device this machine does not know.
                Some(
                    ty @ ("exec-open" | "pty-open" | "l2-open" | "mount-open" | "ssh-sign-request"
                    | "shell-bootstrap"),
                ) if unrecognized_pids.contains(&pid)
                    && conn.link(&pid).is_some_and(|l| l.verified_name.is_none()) =>
                {
                    log.say(&format!(
                        "l2: {ty} refused: the peer is not a device recognized here"
                    ));
                    if let Some(t) = conn.transport_of(&pid) {
                        let refusal =
                            crate::refusal::Refusal::new(crate::refusal::Code::Unrecognized, None);
                        if ty == "shell-bootstrap" {
                            let mut f = json!({
                                "type": "shell-bootstrap-deny",
                                "reason": refusal.reason,
                            });
                            refusal.annotate(&mut f);
                            let _ = t.send_control(&f).await;
                        } else if let Some(sid) = v["sid"].as_u64() {
                            let mut f =
                                json!({ "type": "l2-close", "sid": sid, "err": refusal.reason });
                            refusal.annotate(&mut f);
                            let _ = t.send_control(&f).await;
                        }
                    }
                    continue;
                }
                // Warm-reuse liveness: the acceptor confirmed a stream WE initiated
                // (a warm `open`) is connected end to end. Route it to the mux so
                // verify_first_frame passes even for a client-speaks-first service
                // (HTTP, DB clients) that sends no bytes until we do, instead of the
                // verify window expiring and a HEALTHY link being dropped as a zombie
                // (which made every warm `forward` fall to a cold link). See
                // l2::Mux::on_open_ack.
                // NOT gated on `l2_enabled`, for the reason spelled out on the
                // `l2-close` arm just below: `l2_enabled` answers "will I ACCEPT
                // inbound opens", and an ack is the peer ANSWERING an open WE sent.
                // The gate was applied here anyway, so on a delegate daemon (L2 off
                // unless it serves shells) a warm `forward` to a client-speaks-first
                // service never heard its ack, the verify window expired, and a
                // healthy link was dropped as a zombie and replaced by a cold one.
                // Same defect as the `l2-close` guard in handle_forward_open, one
                // arm away; the mux only acts on an ack for a sid it opened.
                // `reach` liveness: answer a peer's ping on this link, and wake
                // our own waiting probe when its pong comes back. Not gated on
                // L2: it opens nothing and only proves this end is here.
                Some("reach-ping") => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let _ = t.send_control(&crate::daemon_ctl::liveness_pong(&v)).await;
                    }
                }
                Some("reach-pong") => {
                    // Only THIS loop's registry, bound to the link the pong
                    // actually arrived on and the peer that link names. A pong
                    // on another engine's link cannot complete this probe.
                    ports.daemon.reach_pong(&conn, &pid, &v).await;
                }
                Some("l2-open-ack") => {
                    if let Some(sid) = l2::wire_sid(&v) {
                        if let Some(mux) = l2_muxes.get(&pid) {
                            mux.on_open_ack(sid).await;
                        }
                    }
                }
                // L2 (ssh/TCP tunnel) acceptor. Opt-in (TUNLION_L2=1). The
                // capability gate is the proof-verified `trusted` flag on this
                // link (placeholder for L1-a caps); localhost-only is enforced in
                // accept_control. A non-trusted or non-loopback open is refused.
                // `l2_enabled` answers "will I ACCEPT inbound stream opens", which
                // is the right gate for `l2-open` and the WRONG one for
                // `l2-close`. A close is the peer answering a stream WE opened, and
                // a node that accepts no inbound opens still opens outbound ones.
                // Gating both on it meant a refusal ("shell capability not
                // granted") was silently discarded by the very client that asked,
                // which then waited out its 2500ms verify window, declared the link
                // a zombie, and fell through to a 45s cold establish that reported
                // "can't reach". The answer had arrived in milliseconds.
                // `l2-open` stays gated; the body already no-ops the authorization
                // check for a close.
                Some("l2-close") | Some("l2-open")
                    if l2_enabled || v["type"].as_str() == Some("l2-close") =>
                {
                    if let Some(task) = crate::recv::servers::open_forward(
                        &ports,
                        host.as_ref(),
                        &mut conn,
                        pid.clone(),
                        &v,
                        &shell_policy,
                        &mut l2_muxes,
                        l2_enabled,
                        &mut parked_opens,
                    )
                    .await
                    {
                        cleanup.tasks.push(task);
                    }
                }
                // Seamless-shell bootstrap (acceptor). Opt-in (TUNLION_L2=1).
                // DENY-BY-DEFAULT: install the initiator's managed pubkey ONLY
                // when the link is proof-verified (`trusted`) AND the proven
                // device holds the NEW `shell` capability, distinct from
                // `transfer`, so pairing for file transfer never yields a shell.
                // The write happens only here (over the authenticated channel)
                // into a clearly-marked, removable authorized_keys block.
                // Warm-bootstrap (INITIATOR side): the peer answered a
                // `shell-bootstrap` we relayed over its warm link for a `tunlion
                // ssh`. Complete the stashed reply socket(s) for this pid; the
                // client then pins these host keys and skips the cold establish.
                #[cfg(unix)]
                Some("shell-bootstrap-ack") => {
                    let reply = json!({
                        "ok": true,
                        "hostkeys": v["hostkeys"].clone(),
                        "user": v["user"].clone(),
                        "sshd": v["sshd"].clone(),
                    });
                    ports
                        .daemon
                        .complete_warm_bootstrap(&conn, &pid, &reply)
                        .await;
                }
                #[cfg(unix)]
                Some("shell-bootstrap-deny") => {
                    let reply = json!({
                        "ok": false,
                        "err": v["reason"].as_str().unwrap_or("shell bootstrap denied"),
                    });
                    ports
                        .daemon
                        .complete_warm_bootstrap(&conn, &pid, &reply)
                        .await;
                }
                // #268: an `l2-open` arriving while L2 is OFF used to fall
                // through and be IGNORED. The initiator has already committed a
                // client to that stream, so it waits for an answer that is never
                // coming: measured cross-machine, curl hung for its full 25s
                // timeout while tunlion printed nothing at either end.
                //
                // `shell-bootstrap` directly below already refuses explicitly in
                // this exact state. The tunnel open, which is the more common
                // path (`forward`, `netcat`, ssh), did not, so the two disagreed
                // about whether "off" is something you say or something you
                // silently do.
                //
                // `on_close` turns this into OpenOutcome::Refused with the reason
                // (#206), so the client gets a clean, immediate, explained close
                // instead of a hang.
                Some("l2-open") if !l2_enabled => {
                    if let (Some(t), Some(sid)) = (conn.transport_of(&pid), l2::wire_sid(&v)) {
                        let refusal =
                            serving_off_refusal(&conn, &pid, crate::refusal::Code::TunnelOff);
                        let _ = t.send_control(&refusal.close_frame(sid)).await;
                    }
                    continue;
                }
                // NOTE: keep this arm ABOVE the `#[cfg(unix)]` comment block
                // below. That attribute belongs to `shell-bootstrap`, and an
                // outer attribute binds to the NEXT arm regardless of any
                // comments in between: inserting here originally compiled this
                // refusal out on Windows AND silently made the shell-bootstrap
                // deny unconditional there. Found in review, not by the compiler,
                // because both outcomes still build.
                // Shell serving is OFF here. Without this arm the message falls
                // through the match and the acceptor says NOTHING, so the caller
                // can only time out: `tunlion shell X --ssh` burned its full
                // bootstrap deadline and then guessed, while plain
                // `tunlion shell X` printed the reason immediately. The refusal
                // exists; only this path failed to send it. Measured across three
                // machines, not inferred.
                #[cfg(unix)]
                Some("shell-bootstrap") if !l2_enabled => {
                    if let Some(t) = conn.transport_of(&pid) {
                        let refusal =
                            serving_off_refusal(&conn, &pid, crate::refusal::Code::ShellOff);
                        let mut f = json!({
                            "type": "shell-bootstrap-deny",
                            "reason": refusal.reason,
                        });
                        refusal.annotate(&mut f);
                        let _ = t.send_control(&f).await;
                    }
                    continue;
                }
                Some("shell-bootstrap") if l2_enabled => {
                    let Some(t) = conn.transport_of(&pid) else {
                        crate::conn::dropped_no_transport(log.as_ref(), &pid, "shell-bootstrap");
                        continue;
                    };
                    // #30 GAP 2 (shell): honor the pending_proven hold. If a
                    // possession-sig challenge is still in flight for this peer
                    // and the binding is not yet Proven, do NOT refuse on
                    // Inferred: the identity-expose that flips us to Proven is a
                    // SEPARATE event this single-consumer loop must process, so
                    // blocking inline would deadlock. Re-inject the bootstrap
                    // shortly and let the loop drain. The hold entry clears on
                    // Proven OR at the 3s deadline, so this self-terminates and
                    // the re-injected bootstrap is then decided for real.
                    if host.cap_authoritative() {
                        let challenge_in_flight =
                            st.pending_proven.lock().unwrap().contains_key(&pid);
                        let proven = conn
                            .link(&pid)
                            .map(|l| l.identity_binding == cap::BindingStrength::Proven)
                            .unwrap_or(false);
                        if challenge_in_flight && !proven {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                    }
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    // Cap lookup keys on the PROVEN petname, not the presence name.
                    let dev = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    // Granted if the device was explicitly `grant`ed shell OR an
                    // active `up --shell[-only]` policy auto-allows it. Trust
                    // (pair-proof) is still required either way.
                    let legacy_ok = trusted
                        && dev
                            .as_deref()
                            .map(|n| {
                                !host.device_capability_denied(n, "shell")
                                    && (shell_policy.auto_allows(n)
                                        || host.device_allows(n, "shell"))
                            })
                            .unwrap_or(false);
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under TUNLION_CAP_AUTHORITATIVE.
                    let granted = {
                        let az = crate::shell_gate::peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let store = host.cap_store();
                        let now = host.now_secs();
                        let outcome = cap::authorize_in(
                            &store,
                            "self",
                            cap::CAP_SHELL,
                            idev,
                            iusr,
                            ak_caps,
                            now,
                        );
                        {
                            let (own_user, has_grant) = cap::fleet_inputs_in(
                                &store,
                                "self",
                                cap::CAP_SHELL,
                                idev,
                                iusr,
                                ak_caps,
                                now,
                            );
                            // Deliberate tier: `shell` is never a scoped default, so a
                            // same-owner device gets it ONLY via an explicit grant
                            // (has_grant), never fleet auto-trust (scoped_in_bounds=false).
                            // The explicit deny travels too: denied short-circuits
                            // fleet auto-trust, matching the legacy fold above.
                            let denied = dev
                                .as_deref()
                                .map(|n| host.device_capability_denied(n, "shell"))
                                .unwrap_or(false);
                            host.cap_gate_effective(CapGate {
                                legacy_allowed: legacy_ok,
                                outcome: &outcome,
                                action: cap::CAP_SHELL,
                                resource: "self",
                                device_pub: idev,
                                user_pub: iusr,
                                binding,
                                cert_expires: expires,
                                auth_key_caps: ak_caps,
                                own_user_pub: own_user.as_ref(),
                                scoped_in_bounds: false,
                                has_explicit_grant: has_grant,
                                cert_revoked,
                                denied,
                                ceiling_authorizes: false,
                            })
                        }
                    };
                    if !granted.allowed() {
                        let who = dev.as_deref().unwrap_or("<unverified>");
                        log.say(&format!(
                            "l2: shell bootstrap refused: {who}: {}",
                            granted.deny_reason("no shell cap / untrusted")
                        ));
                        host.enqueue_request_if_requestable(who, "shell");
                        let cap_reason = granted.deny_reason("");
                        let refusal = crate::refusal::Refusal::from_shell_gate(
                            false,
                            dev.as_deref()
                                .map(|n| host.device_capability_denied(n, "shell"))
                                .unwrap_or(false),
                            (!cap_reason.is_empty()).then_some(cap_reason),
                            dev.clone(),
                        );
                        let mut f = json!({
                            "type": "shell-bootstrap-deny",
                            "reason": refusal.reason,
                        });
                        refusal.annotate(&mut f);
                        let _ = t.send_control(&f).await;
                        continue;
                    }
                    let device = dev.unwrap();
                    // CERT MODE: `shell --ssh` with the local CA authenticates with
                    // a short-lived certificate, so the requesting side asks for
                    // HOST KEYS ONLY and nothing is written to authorized_keys. The
                    // capability gate above is unchanged (a cert request is still a
                    // shell-class request); only the permanent key install is
                    // skipped. Absent flag = the historical install path, so older
                    // initiators keep working byte-for-byte.
                    let cert_only = v.get("cert").and_then(|c| c.as_bool()).unwrap_or(false);
                    let pubkey = v["pubkey"].as_str().unwrap_or_default().to_string();
                    // M-3 (authorized_keys injection): a single, well-formed key
                    // line ONLY. validate_pubkey rejects interior newlines / CR /
                    // control chars and multi-line payloads, so a trusted+shell
                    // peer can't inject extra authorized_keys lines. Enforced here
                    // AND again inside install_authorized_key (defense in depth).
                    if cert_only {
                        let hostkeys = host.ssh_host_pubkeys();
                        let login = host.serving_user().unwrap_or_else(|| "root".into());
                        let ssh_port = v["ssh_port"]
                            .as_u64()
                            .and_then(|n| u16::try_from(n).ok())
                            .unwrap_or(22);
                        let sshd = sshd_listening(ssh_port).await;
                        log.say(&format!(
                            "l2: shell (cert) granted to '{device}', no key installed"
                        ));
                        let _ = t
                            .send_control(&json!({
                                "type": "shell-bootstrap-ack",
                                "hostkeys": hostkeys,
                                "user": login,
                                "sshd": sshd,
                                "ssh_port": ssh_port,
                                "cert": true
                            }))
                            .await;
                        continue;
                    }
                    let pubkey = match authkeys_managed::validate_pubkey(&pubkey) {
                        Ok(k) => k,
                        Err(e) => {
                            log.say(&format!(
                                "l2: shell bootstrap refused: malformed pubkey from '{device}': {e}"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "malformed pubkey"
                                }))
                                .await;
                            continue;
                        }
                    };
                    match host.install_authorized_key(&device, &pubkey) {
                        Ok(()) => {
                            let hostkeys = host.ssh_host_pubkeys();
                            let login = host.serving_user().unwrap_or_else(|| "root".into());
                            // Tell the initiator whether an sshd is actually
                            // listening on the port `tunlion shell --ssh` will dial here,
                            // so it can fail fast with a clear message instead of
                            // spawning ssh into a refused/black-holed connection.
                            let ssh_port = v["ssh_port"]
                                .as_u64()
                                .and_then(|n| u16::try_from(n).ok())
                                .unwrap_or(22);
                            let sshd = sshd_listening(ssh_port).await;
                            log.say(&format!(
                                "l2: shell granted to '{device}', installed managed key (tunlion-managed block)"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-ack",
                                    "hostkeys": hostkeys,
                                    "user": login,
                                    "sshd": sshd,
                                    "ssh_port": ssh_port
                                }))
                                .await;
                        }
                        Err(e) => {
                            log.say(&format!(
                                "l2: shell bootstrap install failed for '{device}': {e}"
                            ));
                            let _ = t
                                .send_control(&json!({
                                    "type": "shell-bootstrap-deny",
                                    "reason": "install failed"
                                }))
                                .await;
                        }
                    }
                }
                // web-shell (browser terminal): spawn a login shell in a PTY and
                // bridge it to a sid stream. Same deny-by-default gate as
                // shell-bootstrap, a PTY is a superset of ssh-key access, so it
                // reuses the `shell` cap / --shell policy and requires `trusted`.
                Some("pty-open") => {
                    crate::recv::servers::shell::open_pty(
                        &ports,
                        &mut conn,
                        pid.clone(),
                        &v,
                        &shell_policy,
                        &shell_user,
                        &mut l2_muxes,
                        &mut pty_bindings,
                        l2_enabled,
                        &mut parked_opens,
                    )
                    .await;
                }
                // Remote command execution: parse, shell-gate, direct-spawn
                // and serve. The module sends its own ack/close/refusal
                // replies; the arm only resolves the transport and the mux.
                // The initiator of a served exec: still there (`exec-alive`),
                // or forwarding its user's Ctrl-C (`exec-signal`). Routed only
                // through THIS peer's mux, by sid, so it can reach nothing but
                // a session this same peer opened.
                Some("exec-alive") | Some("exec-signal") => {
                    if let (Some(mux), Some(sid), Some(msg)) = (
                        l2_muxes.get(&pid),
                        l2::wire_sid(&v),
                        crate::l2::mux::ExecCtl::from_frame(&v),
                    ) {
                        // Answer a heartbeat on the link it came in on: the
                        // initiator holds the session to these answers, so a
                        // daemon killed outright is noticed within seconds
                        // instead of when the transport finally times out.
                        let live = mux.exec_control(sid, msg).await;
                        if live && msg == crate::l2::mux::ExecCtl::Alive {
                            if let Some(t) = conn.transport_of(&pid) {
                                let _ = t
                                    .send_control(&json!({ "type": "exec-alive-ack", "sid": sid }))
                                    .await;
                            }
                        }
                    }
                    continue;
                }
                Some("exec-open") => {
                    ports
                        .servers
                        .open_exec(
                            &mut conn,
                            pid.clone(),
                            &v,
                            &shell_policy,
                            &shell_user,
                            &mut l2_muxes,
                            l2_enabled,
                            &mut parked_opens,
                        )
                        .await;
                    continue;
                }
                // Directory sync: admission (bounds + transfer gate) is the
                // peerloop endpoint; the CLI still parks a deny and serves the
                // stateful protocol. Not gated on l2_enabled: it is a transfer,
                // admitted by the same capability a file-offer from this peer
                // would be, and parked on an unproven-identity deny like the
                // shell-class opens.
                Some("sync-open") => {
                    if stop.is_cancelled() {
                        continue;
                    }
                    if conn.transport_of(&pid).is_none() {
                        crate::conn::dropped_no_transport(log.as_ref(), &pid, "sync-open");
                        continue;
                    }
                    if let Some((sid, task)) = crate::recv::servers::dispatch_open_sync(
                        &ports,
                        host.as_ref(),
                        &mut conn,
                        &pid,
                        &v,
                        &mut l2_muxes,
                        &dir,
                        &mut parked_opens,
                    )
                    .await
                    {
                        sync_tasks
                            .track_sync_task(pid.clone(), sid, task, log.as_ref())
                            .await;
                    }
                    continue;
                }
                Some("ssh-sign-request") if !l2_enabled => {
                    if let (Some(t), Some(sid)) = (conn.transport_of(&pid), v["sid"].as_u64()) {
                        let _ = t
                            .send_control(&json!({
                                "type": "l2-close",
                                "sid": sid,
                                "err": crate::refusal::SHELL_OFF_REASON,
                            }))
                            .await;
                    }
                    continue;
                }
                // SSH certificate signing: parse, shell-gate (third path),
                // clamp, sign, reply. Pure control round trip (no stream);
                // the handler sends its own cert/refusal replies.
                Some("ssh-sign-request") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        crate::conn::dropped_no_transport(log.as_ref(), &pid, "ssh-sign-request");
                        continue;
                    };
                    ports
                        .servers
                        .ssh_sign(&mut conn, &pid, t, &v, &shell_policy, &mut parked_opens)
                        .await;
                    continue;
                }
                // `mount-open` is an OPEN, not a capability question. It must
                // be answered even when the L2 acceptor is off; otherwise the
                // initiator waits for a close that never arrives. This arm is
                // deliberately not gated on `l2_enabled`.
                Some("mount-open") if !l2_enabled => {
                    refuse_unserved_open(
                        &conn,
                        &pid,
                        &v,
                        "mount serving is off in this core profile",
                    )
                    .await;
                    continue;
                }
                #[cfg(not(feature = "mount-server"))]
                Some("mount-open") => {
                    // The frame vocabulary stays in the common receive loop,
                    // but a reduced build has no mount endpoint to admit it.
                    refuse_unserved_open(
                        &conn,
                        &pid,
                        &v,
                        "mount server is not available in this build",
                    )
                    .await;
                    continue;
                }
                #[cfg(feature = "mount-server")]
                Some("mount-open") if l2_enabled => {
                    // The endpoint returns the serving task so a future driver
                    // can join it; binding and dropping it here is today's
                    // detached behaviour, unchanged.
                    if let Some(task) = crate::mount::handle_mount_open(
                        &mut conn,
                        &pid,
                        &v,
                        &mut l2_muxes,
                        &ports.daemon.fleet_share_root(),
                    )
                    .await
                    {
                        cleanup.tasks.push(task);
                    }
                    continue;
                }
                Some("pty-resize") if l2_enabled => {
                    let Some(sid) = l2::wire_sid(&v) else {
                        continue;
                    };
                    let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                    let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                    // #4: resize the persistent session bound to this sid (not a
                    // link-local serve_pty). Falls back to the mux resizer if the
                    // sid isn't a known session binding (defensive).
                    crate::recv::servers::shell::pty_resize(
                        &ports,
                        &pid,
                        &v,
                        &mut l2_muxes,
                        &mut pty_bindings,
                    )
                    .await;
                }
                // #4: explicit end of a persistent PTY session (the ✕ / unmount).
                // Distinct from a bare channel drop, which only DETACHES. Kills the
                // shell and removes the session so a later open spawns fresh.
                Some("pty-close") if l2_enabled => {
                    crate::recv::servers::shell::pty_close(&ports, &pid, &v, &mut pty_bindings)
                        .await;
                }
                // Client confirmed the protocol version advertised in mount-open-ack.
                // The server is already running in that version; this control is
                // received and consumed here to prevent it from hitting the catch-all.
                Some("mount-cap-ack") if l2_enabled => {}
                Some("brb") => {
                    // C21: the peer announces a benign absence (mobile file
                    // picker suspends the tab). Hold the line that long.
                    let ttl = v["ttl"].as_u64().unwrap_or(120).min(300);
                    conn.rejoin.away =
                        Some((pid.clone(), Instant::now() + Duration::from_secs(ttl)));
                    let n = conn.link_presence(&pid, Presence::Away);
                    log.say(&conn.roster(
                        &pid,
                        "●",
                        Tone::Warn,
                        "away, choosing a file · holding the line",
                        &n,
                    ));
                }
                Some("back") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        log.say(&conn.roster(&pid, log.glyph_ok(), Tone::Ok, "back", &n));
                    }
                }
                // C30 phase 3: a state ping proves the peer is alive, clear
                // any away-mark (the receiver side has no sender corrections).
                Some("state") => {
                    let was_away = conn.is_away(&pid);
                    conn.note_alive(&pid);
                    if was_away {
                        let n = conn.link_presence(&pid, Presence::Ready);
                        log.say(&conn.roster(&pid, log.glyph_ok(), Tone::Ok, "back", &n));
                    }
                }
                Some("pair-keep") => {
                    let sec = v["secret"].as_str().unwrap_or_default().to_string();
                    if sec.len() == 64 {
                        // A secret is remembered ONLY from the peer whose code
                        // ceremony confirmed on this receive: `--remember` means
                        // "remember the device I typed the code from", so the
                        // SPAKE2-bound peer is the only one it can name. Any other
                        // link (a room peer, a second candidate, a link whose DTLS
                        // the signaling server chose) is refused. And the secret
                        // always lands in a NEW record: a peer can never re-key
                        // an existing device by naming it.
                        let ceremony_peer =
                            recv_code_path && recv_pake_done && conn.is_bound_active_peer(&pid);
                        let kept = match (&remember, ceremony_peer) {
                            (Some(name), true) => match ports.store.devices_store(name, &sec) {
                                Ok(stored) => {
                                    ports
                                        .env
                                        .remember_stored
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                    log.say(&format!(
                                        "remembered this device as '{stored}', future sends auto-accept after proof"
                                    ));
                                    true
                                }
                                Err(e) => {
                                    log.say(
                                        &log.paint(Tone::Warn, &format!("  not remembered: {e}")),
                                    );
                                    false
                                }
                            },
                            (Some(_), false) => {
                                log.critical(&log.paint(
                                    Tone::Warn,
                                    "ignored a remember offer from a peer that is not this code's sender",
                                ));
                                false
                            }
                            (None, _) => {
                                log.say(
                                    "(sender offered to be remembered; re-run with --remember <name> to keep it)",
                                );
                                false
                            }
                        };
                        // C27: answer either way, a declined sender discards
                        // its half instead of waving at a dead meeting point.
                        if let Some(t) = conn.transport_of(&pid) {
                            t.send_control(&json!({ "type": "pair-keep-ack", "ok": kept }))
                                .await
                                .ok();
                        }
                    }
                }
                Some("pair-proof") => {
                    // The proof is matched against the store as it is NOW: a
                    // secret `devices forget` removed must stop proving at once,
                    // not at the next daemon start.
                    let gone = ports.daemon.prune_to_store(&mut devices);
                    if !gone.is_empty() {
                        revoked_secrets.extend(gone);
                        revocation_sweep_now = true;
                    }
                    let mac = v["mac"].as_str().unwrap_or_default();
                    let peer_uid = conn
                        .link(&pid)
                        .and_then(|l| l.uid.clone())
                        .unwrap_or_default();
                    let fps = match conn.link(&pid) {
                        Some(l) => match &l.peer {
                            Some(p) => p.fingerprints().await,
                            None => None,
                        },
                        None => None,
                    };
                    let Some((my_fp, their_fp)) = fps else {
                        log.debug("pair-proof received before fingerprints known, ignoring");
                        continue;
                    };
                    // #9: pair secrets are symmetric, our own install holds
                    // every secret we do, so a same-host process could prove
                    // "pop2" and tunnel callers into the WRONG machine. Refuse.
                    let hit = if host.is_self_uid(&conn.my_uid, Some(peer_uid.as_str())) {
                        log.debug("pair-proof from our own install, refusing (self-connect)");
                        None
                    } else {
                        devices.iter().find(|(_, s)| {
                            proof_for(s, &peer_uid, &peer_uid, &conn.my_uid, &my_fp, &their_fp)
                                == mac
                        })
                    };
                    let ok = if let Some((n, _)) = hit {
                        if let Some(l) = conn.link_mut(&pid) {
                            l.trusted = true;
                            l.verified_name = Some(n.clone());
                            crate::identity::resolve_peer_identity(l);
                        }
                        // #39: identity just RESOLVED on the WebRTC/relay path — verified_name
                        // is set above and resolve_peer_identity populated device_pub. This is
                        // the resolution point for NON-direct links (ChannelReady fired before
                        // this); the direct path resolves at DirectReady adoption instead. Issue
                        // the possession challenge here so the link reaches Proven (fleet
                        // auto-trust is Proven-gated), authoritative only. The helper is
                        // idempotent — if DirectReady already challenged this pid the call is a
                        // no-op and does not clobber the in-flight nonce. The transport exists by
                        // construction (this handler was reached by a control message on it).
                        if host.cap_authoritative() {
                            let needs_proven = conn
                                .link(&pid)
                                .map(|l| {
                                    l.identity_device_pub.is_some()
                                        && l.identity_binding != cap::BindingStrength::Proven
                                })
                                .unwrap_or(false);
                            if needs_proven {
                                if let Some(t) = conn.transport_of(&pid) {
                                    ports
                                        .identity
                                        .issue_proven_challenge_and_hold(
                                            &conn,
                                            &pid,
                                            &t,
                                            &st.pending_proven,
                                            &mut identity_nonces,
                                        )
                                        .await;
                                    log.debug(&format!(
                                        "  identity challenge sent to {pid} at pair-proof (universal expose, WebRTC/relay path)"
                                    ));
                                    let hold_pending = st.pending_proven.clone();
                                    let hold_pid = pid.clone();
                                    tokio::spawn(async move {
                                        tokio::time::sleep(PROVEN_CHALLENGE_DEADLINE).await;
                                        hold_pending.lock().unwrap().remove(&hold_pid);
                                    });
                                }
                            }
                        }
                        log.say(&format!("identity verified: '{n}' (auto-accepting)"));
                        unrecognized_pids.remove(&pid);
                        true
                    } else {
                        // Remembered for the open guard above; links gone since
                        // are dropped from the set here so it cannot grow.
                        unrecognized_pids.retain(|p| conn.links.contains_key(p));
                        unrecognized_pids.insert(pid.clone());
                        // CRITICAL, a security verdict the user must see (-q too).
                        log.critical(&log.paint(
                            Tone::Warn,
                            "pair-proof FAILED verification, treating peer as untrusted",
                        ));
                        false
                    };
                    // C27: tell the prover the verdict, a rejected prover
                    // learns we never met and stops claiming acquaintance.
                    if let Some(t) = conn.transport_of(&pid) {
                        t.send_control(&json!({ "type": "pair-proof-ack", "ok": ok }))
                            .await
                            .ok();
                    }
                }
                Some("pair-intro") => {
                    // C19/C20: only a fingerprint-verified known device may
                    // vouch new trust into this store. "Verified" means the
                    // link resolved to one of OUR records by its pair secret
                    // (`verified_name`), and that record was paired directly:
                    // a device that was itself introduced cannot introduce in
                    // turn, so a vouch is always one hop from a device the
                    // owner paired. The vouched secret always becomes a NEW
                    // record (suffixed on a name clash, refused if any record
                    // already holds that secret): a hub can never re-key an
                    // existing device and inherit its grants by naming it.
                    let trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let iname = v["name"].as_str().unwrap_or_default().to_string();
                    let isec = v["secret"].as_str().unwrap_or_default().to_string();
                    let hub = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let hub_record = conn.link(&pid).and_then(|l| l.verified_name.clone());
                    let may_vouch = trusted
                        && hub_record
                            .as_deref()
                            .is_some_and(|h| !ports.store.device_was_introduced(h));
                    let stored = if may_vouch && isec.len() == 64 && !iname.is_empty() {
                        match ports
                            .store
                            .devices_store_new(&iname, &isec, hub_record.as_deref())
                        {
                            Ok(stored) => Some(stored),
                            Err(e) => {
                                log.say(&log.paint(
                                    Tone::Warn,
                                    &format!("  ignored pair-intro from {hub}: {e}"),
                                ));
                                None
                            }
                        }
                    } else {
                        if !may_vouch {
                            log.say(&log.paint(
                                Tone::Warn,
                                &format!("  ignored pair-intro from unverified peer {hub}"),
                            ));
                        }
                        None
                    };
                    if let Some(iname) = stored {
                        devices.push((iname.clone(), isec.clone()));
                        sess.channels.push(host.channel_of(&isec)); // C30
                        sess.touch();
                        sio.emit("subscribe", json!({ "channels": [host.channel_of(&isec)] }))
                            .await
                            .ok();
                        log.say(&format!(
                            "  {} introduced to '{}' by {}, now a known device",
                            log.paint(Tone::Ok, log.glyph_ok()),
                            iname,
                            hub
                        ));
                        // For identity layer, after introduction, generate nonce challenge to learn peer's identity (0x02 path)
                        // Challenge carries ONLY {nonce, receiver_device_pub} per correction A
                        // Receiver_device_pub is our own overlay key (always exists, not cert-or-zeros)
                        #[cfg(feature = "mesh")]
                        if let Ok(own_dpub) = host.overlay_pubkey() {
                            if let Some(t) = conn.transport_of(&pid) {
                                use ring::rand::{SecureRandom, SystemRandom};
                                let rng = SystemRandom::new();
                                let mut nonce = [0u8; 32];
                                let _ = rng.fill(&mut nonce);
                                // Store pending nonce for this peer, single-use, session-scoped, distinct per concurrent session
                                identity_nonces
                                    .insert(iname.clone(), (nonce, Instant::now(), own_dpub));
                                let challenge = json!({
                                    "type": "identity-nonce-challenge",
                                    "nonce": hex::encode(nonce),
                                    "receiver_device_pub": hex::encode(own_dpub)
                                });
                                let _ = t.send_control(&challenge).await;
                            }
                        }
                    }
                }
                #[cfg(feature = "mesh")]
                Some("identity-nonce-challenge") => {
                    // Received challenge as sender: peer wants to learn our identity, we must respond with sealed cert + possession sig
                    // Challenge carries ONLY {nonce, receiver_device_pub} per correction A, no scope/caps/user data
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    let recv_dpub_hex = v["receiver_device_pub"].as_str().unwrap_or_default();
                    if let (Ok(nonce_bytes), Ok(recv_dpub_bytes)) =
                        (hex::decode(nonce_hex), hex::decode(recv_dpub_hex))
                    {
                        if nonce_bytes.len() == 32 && recv_dpub_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            let mut recv_dpub_arr = [0u8; 32];
                            recv_dpub_arr.copy_from_slice(&recv_dpub_bytes);
                            // Build possession_msg with 0x02 binding_type, binding_value=nonce, scope own, caps_digest own, cert_hash own, sender=own, receiver=challenger's
                            // For minimal, try to get local device cert for this machine
                            if let Some(local_cert) = ports.identity.local_device_cert() {
                                let scope = filament_id::IntroScope::User.to_byte(); // User-scope for introduce, from own token
                                let caps = "transfer";
                                let caps_d = filament_id::caps_digest(caps);
                                let chash = filament_id::cert_hash(&local_cert);
                                let sender_dpub = local_cert.device_pub;
                                // Possession_msg 8-field: tag, type 0x02, nonce, scope, caps_digest, cert_hash, sender, receiver
                                let msg = filament_id::possession_msg(
                                    0x02,
                                    &nonce_arr,
                                    scope,
                                    &caps_d,
                                    &chash,
                                    &sender_dpub,
                                    &recv_dpub_arr,
                                );
                                if let Ok(sig) = host.overlay_sign_possession(&msg) {
                                    // For introduce path, identity-expose goes over DIRECT A-B DTLS data channel (the introduced pair's OWN transport,
                                    // whose DTLS keys the introducer/hub does NOT know). This is E2E encrypted, so unsealed is actually FINE and BETTER than
                                    // sealing with HKDF(fresh_secret) (which introducer CAN open, since it minted fresh_secret). DTLS gives true A-B E2E,
                                    // introducer is BLIND (cannot read cert), which is stronger. No sealing needed for introduce when sent over direct A-B transport.
                                    // For pair path (0x01), we DO seal via signal path with HKDF(K) because signal goes via server.
                                    let _inner = json!({
                                        "cert": local_cert.to_json(),
                                        "possession_sig": hex::encode(sig)
                                    });
                                    if let Some(t) = conn.transport_of(&pid) {
                                        let payload = json!({
                                            "type": "identity-expose",
                                            "v": 2,
                                            "binding_type": 0x02,
                                            "nonce": hex::encode(nonce_arr),
                                            "cert": local_cert.to_json(),
                                            "possession_sig": hex::encode(sig)
                                        });
                                        let _ = t.send_control(&payload).await;
                                    }
                                }
                            }
                        }
                    }
                }
                #[cfg(feature = "mesh")]
                Some("identity-expose") => {
                    // Received sealed or unsealed identity-expose for introduce path (0x02)
                    // For PAKE path we already handle sealed with possession in pair_cmd, this is for introduce path
                    // Verify against held nonce, own scope/caps, cert_hash locally rebuilt, etc.
                    // For minimal, if we have pending nonce for this peer, verify and store
                    // This is the receiver side (we generated nonce, now receiving expose)
                    let nonce_hex = v["nonce"].as_str().unwrap_or_default();
                    if let Ok(nonce_bytes) = hex::decode(nonce_hex) {
                        if nonce_bytes.len() == 32 {
                            let mut nonce_arr = [0u8; 32];
                            nonce_arr.copy_from_slice(&nonce_bytes);
                            // Check held nonce matches and is single-use
                            if let Some((held_nonce, _ts, _held_recv_dpub)) =
                                identity_nonces.get(&pid)
                            {
                                if held_nonce == &nonce_arr {
                                    // Nonce matches, now verify cert and possession sig
                                    if let Some(cert_json) = v.get("cert") {
                                        if let Some(cert) =
                                            identity::DeviceCert::from_json(cert_json)
                                        {
                                            if cert.verify(identity::now_secs()).is_ok() {
                                                // Verify possession sig
                                                if let Some(sig_hex) =
                                                    v.get("possession_sig").and_then(|x| x.as_str())
                                                {
                                                    if let Ok(sig_bytes) = hex::decode(sig_hex) {
                                                        if sig_bytes.len() == 64 {
                                                            let mut sig_arr = [0u8; 64];
                                                            sig_arr.copy_from_slice(&sig_bytes);
                                                            // Recompute possession_msg with held nonce, own scope/caps, etc.
                                                            let scope =
                                                                filament_id::IntroScope::User
                                                                    .to_byte(); // from own token, not echoed
                                                            let caps_d = filament_id::caps_digest(
                                                                "transfer",
                                                            ); // own caps
                                                            let chash =
                                                                filament_id::cert_hash(&cert);
                                                            if let Ok(own_dpub) =
                                                                host.overlay_pubkey()
                                                            {
                                                                let sender_dpub = cert.device_pub;
                                                                let receiver_dpub = own_dpub; // our own device_pub as receiver
                                                                let msg =
                                                                    filament_id::possession_msg(
                                                                        0x02,
                                                                        &nonce_arr,
                                                                        scope,
                                                                        &caps_d,
                                                                        &chash,
                                                                        &sender_dpub,
                                                                        &receiver_dpub,
                                                                    );
                                                                if filament_id::verify_possession_sig(&cert.device_pub, &msg, &sig_arr).is_ok() {
                                                                    // Anti-reflection, narrowed to device_pub (#41). The outer `if let` is kept
                                                                    // only to preserve the if/else-if chain with the enrollment branch below;
                                                                    // the reflection test itself now compares cert.device_pub against own_dpub
                                                                    // (this machine's LOCAL device pubkey, from the enclosing
                                                                    // overlay_pubkey_bytes()), so a same-owner fleet device (different device_pub,
                                                                    // same user key) is admitted instead of refused. This 0x02 path also binds
                                                                    // receiver_dpub in the possession_msg, so device_pub here is defense-in-depth.
                                                                    if host.user_key().is_some() {
                                                                        if cert.device_pub == own_dpub {
                                                                            // self, refuse
                                                                        } else {
                                                                            // Store as provisional, then promote at overlay after check
                                                                            let _ = ports.identity.store_provisional_identity(&format!("peer-{}", pid), &cert);
                                                                            // Store identity on the link for capability authorization
                                                                            if let Some(l) = conn.link_mut(&pid) {
                                                                                l.identity_device_pub = Some(cert.device_pub);
                                                                                l.identity_user_pub = Some(cert.user_pub);
                                                                                l.identity_binding = cap::BindingStrength::Proven;
                                                                                l.identity_cert_expires = Some(cert.expires);
                                                                            }
                                                                            // The peer by name, not its raw signaling id.
                                                                            let who = conn.link(&pid).map(|l| l.label().to_string()).unwrap_or_else(|| pid.to_string());
                                                                            let line = format!("  {} identity verified for peer {}", log.paint(Tone::Ok, log.glyph_ok()), who);
                                                                            // A raw id is an internal: -v only.
                                                                            if who.as_str() == &pid[..] { log.debug(&line) } else { log.say(&line) }
                                                                            // Erase held nonce single-use
                                                                            identity_nonces.remove(&pid);
                    }
                } else if let Some(uk) = host.user_key() {
                    // Enrollment channel: an ephemeral device is trying to enroll.
                    // Recognize peers on enroll_channel(own_owner_pub) and dial them.
                    let ek = ports.identity.enroll_channel(&uk.public_key_bytes());
                    if v["channel"].as_str() == Some(&ek) {
                        let pid = v["id"].as_str().unwrap_or_default().to_string();
                        if !conn.links.contains_key(&pid) && !conn.direct_pending.contains_key(&pid) {
                            log.debug(&format!("enrollment peer appeared on channel, dialing"));
                        }
                        let r = conn.maybe_adopt(&v, true).await;
                        peer_step(daemon, &pid, "enrollment adoption", r, log.as_ref())?;
                    }
                }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Some("file-offer") => {
                    let Some(t) = conn.transport_of(&pid) else {
                        crate::conn::dropped_no_transport(log.as_ref(), &pid, "file-offer");
                        continue;
                    };
                    // L1-a (shared-room hardened): on the code path, accept bytes
                    // ONLY from the peer whose ephemeral SPAKE2 ceremony confirmed
                    // (the authenticated sender). Anything else, a pre-auth offer, a
                    // decoy / unrelated room peer, or an offer from a DIFFERENT peer
                    // than the one that authenticated, is refused. (Previously this
                    // only gated the single latched peer, so a decoy could slip an
                    // offer past while we were still authenticating; now it cannot.)
                    // If no peer has authenticated yet, the overall watchdog still
                    // fails loudly should the real sender never confirm.
                    if recv_code_path && (!recv_pake_done || !conn.is_bound_active_peer(&pid)) {
                        // A pre-auth offer from a peer we are STILL authenticating
                        // (it has a live ceremony) is buffered, not lost: the offer
                        // and the sender's confirm crossed on the wire. If that peer
                        // wins auth we replay it; if its ceremony is dropped, the
                        // buffered offer dies with it. A confirmed-but-different peer
                        // (a decoy that authenticated nothing) is simply ignored.
                        if !recv_pake_done && st.recv_cers.contains_key(&pid) {
                            st.recv_pending_offers.insert(pid.clone(), v.clone());
                            log.debug(
                                "buffering a pre-auth file-offer until its ceremony confirms",
                            );
                        } else {
                            log.debug(
                                "ignoring file-offer from a peer that has not authenticated via ephemeral PAKE",
                            );
                        }
                        continue;
                    }
                    // Same race, one layer over: this peer's `fleet-hello` has
                    // not landed yet, so its link still reads binding=None and
                    // the gate below would decline a peer that is seconds from
                    // being Proven. Buffer rather than decide. Bounded by the
                    // link: `fleet-hello` either verifies (we replay) or is
                    // rejected and the link is dropped (the entry goes with it),
                    // so a peer cannot park offers here indefinitely.
                    // "Could this link still prove itself?" is the question, and
                    // `fleet_pending` alone answers a NARROWER one: "have we already
                    // classified it?". The offer can arrive before ChannelReady has
                    // run for that pid, so the set is still empty and the gate
                    // decides against a peer that is seconds from being Proven,
                    // declining with "not in auth key caps" against the empty
                    // ceiling an unverified fleet link is born with. Measured as the
                    // dominant failure once the active-slot bug was fixed: 3 of 4
                    // remaining failures were this decline, not a timeout.
                    //
                    // `__fleet_waited` marks an offer that has already served its
                    // grace, so a peer that never proves itself is decided normally
                    // instead of deferred forever.
                    // MEASURED, and the wider condition was WORSE. Broadening this
                    // to "any untrusted fleet-shaped link could still verify" took
                    // sibling sends from 11/15 to 3/15: `fleet_shaped_link` is true
                    // for nearly every such link, so offers whose hello had ALREADY
                    // been handled were parked too, waited out the full grace, and
                    // were then declined anyway. `fleet_pending` is the honest
                    // predicate because it means "a hello is actually coming".
                    let already_waited = v["__fleet_waited"].as_bool() == Some(true);
                    if !already_waited
                        && crate::recv::fleet::identity_pending(
                            &conn,
                            &pid,
                            fleet_pending.contains(&pid),
                            fleet_verified.contains(&pid),
                        )
                    {
                        log.debug(&format!(
                            "deferring file-offer from {pid}: fleet identity still verifying"
                        ));
                        if cfg!(feature = "fleet") {
                            fleet_deferred_offers.push((
                                pid.clone(),
                                v.clone(),
                                Instant::now() + fleet_offer_grace,
                            ));
                        }
                        continue;
                    }
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Never trust a remote name: reduce it to a safe single path
                    // component (basename only, no path separators, no control
                    // bytes). See safe_incoming_name.
                    let raw = v["name"].as_str().unwrap_or("file.bin");
                    let name = filament_transfer::safe_incoming_name(raw);
                    let size = v["size"].as_u64().unwrap_or(0);
                    let offer_head = v["head"].as_str().map(|s| s.to_string());
                    // P4 (GAP-5): the sender's whole-file sha256 (absent for an old
                    // peer). Used to verify-on-completion + drive the delivery-ack.
                    let offer_full = v["full"].as_str().map(|s| s.to_string());
                    let is_resume = v["resume"].as_bool().unwrap_or(false);

                    // A pinned receive refuses unverifiable legacy offers and
                    // content with a different advertised digest before writing
                    // any bytes. For a match, the ordinary completion path still
                    // hashes the received file and checks it against `offer_full`.
                    if let Some(expected) = expect_sha256.as_deref() {
                        if !sha256_matches(expected, offer_full.as_deref()) {
                            let reason = if offer_full.is_some() {
                                "offered file SHA-256 does not match --expect-sha256"
                            } else {
                                "sender did not provide a whole-file SHA-256 required by --expect-sha256"
                            };
                            log.critical(&log.paint(
                                Tone::Err,
                                &format!(
                                    "  refused {name} from {}: {reason}",
                                    conn.link(&pid).map(|l| l.name.as_str()).unwrap_or_default()
                                ),
                            ));
                            note_refusal(
                                &report,
                                daemon,
                                &name,
                                size,
                                "sha256_mismatch",
                                reason,
                                RefusalClass::Denied,
                            );
                            let r = t.send_control(&protocol::decline_msg(&id)).await;
                            peer_step(daemon, &pid, "digest refusal", r, log.as_ref())?;
                            continue;
                        }
                    }

                    let part_path = dir.join(format!("{name}.part"));
                    let meta_path = dir.join(format!("{name}.part.meta"));
                    // C7: a partial counts only if size matches AND the
                    // content head matches (when both sides have one).
                    let mut offset = 0u64;
                    // P4: the whole-file digest persisted with the partial, so a
                    // resume after a process restart can still verify-on-completion
                    // even if this particular re-offer omits `full`.
                    let mut prior_full: Option<String> = None;
                    if part_path.is_file() {
                        let prior = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
                        match PartMeta::load(&meta_path) {
                            Some(m) if m.size == size && prior <= size => {
                                let head_ok = match (&m.head, &offer_head) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => true, // legacy peer, size-only fallback
                                };
                                if head_ok {
                                    offset = prior;
                                    prior_full = m.full;
                                } else {
                                    // DEBUG, resilience internal (resume mismatch, restart).
                                    log.debug(&format!(
                                        "{name}: same name+size but different content, restarting from 0"
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }

                    // #30 GAP 2 / #161: hold the offer while identity resolution
                    // is pending. Do NOT decide the offer with an un-resolved
                    // sender.
                    //
                    // #30 (authoritative): if a possession-sig challenge is still
                    // in flight and the binding is not yet Proven, do NOT decide
                    // on Inferred now: the identity-expose that flips us to
                    // Proven is a SEPARATE event this single-consumer loop must
                    // be free to process, so blocking inline would deadlock.
                    //
                    // #161 (both modes, typed-code path): the buffered offer is
                    // replayed at PAKE confirm BEFORE DirectReady issues the 0x02
                    // identity challenge, so the first offer always arrives with
                    // identity unresolved. Revocation is mode-independent (the
                    // #158 absolute Deny fires in both modes), so accepting a
                    // legacy-trusted offer with cert_revoked_for(None)=false lets
                    // a revoked device push a transfer before its stored revoked
                    // cert resolves. Hold the offer while identity is unresolved,
                    // bounded by RECV_IDENTITY_HOLD_DEADLINE from first sight.
                    //
                    // Both self-terminate: the pending_proven entry is removed on
                    // Proven OR its 3s deadline; the #161 hold clears at its own
                    // deadline and the offer below is then decided.
                    //
                    // #161 FAIL-CLOSED EXPIRY: if the hold clears with identity
                    // STILL unresolved on the typed-code path, DENY rather than
                    // proceed. Deciding a legacy-trusted offer with
                    // cert_revoked_for(None)=false would admit a device whose
                    // revocation cannot bind - #156 makes unidentified read as
                    // not-revoked by design, and #161's hold was the only thing
                    // standing between them. The operator is present by
                    // construction (they typed the code), so the cost of denial
                    // is a retry at the terminal, not a lost unattended
                    // transfer. A peer whose ceremony cannot resolve within the
                    // hold is either revoked or on a link the ceremony does not
                    // complete on; both must be refused, not admitted.
                    {
                        let (proven, idev_known, link_ready) = conn
                            .link(&pid)
                            .map(|l| {
                                (
                                    l.identity_binding == cap::BindingStrength::Proven,
                                    l.identity_device_pub.is_some(),
                                    l.presence == Presence::Ready,
                                )
                            })
                            .unwrap_or((false, false, false));
                        let challenge_in_flight =
                            st.pending_proven.lock().unwrap().contains_key(&pid);
                        let code_hold = recv_code_path && !proven && !idev_known;
                        let hold = if code_hold {
                            if !link_ready {
                                // Transport still establishing (the direct-blocked
                                // fallback brings WebRTC up AFTER PAKE, and the
                                // ChannelReady re-issue delivers the challenge when
                                // it does). Hold without starting the clock.
                                true
                            } else {
                                let deadline = *recv_identity_hold
                                    .entry(pid.clone())
                                    .or_insert_with(std::time::Instant::now);
                                deadline.elapsed() < RECV_IDENTITY_HOLD_DEADLINE
                            }
                        } else {
                            host.cap_authoritative() && challenge_in_flight && !proven
                        };
                        if hold {
                            let rtx = tx.clone();
                            let rpid = pid.clone();
                            let rv = v.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(80)).await;
                                let _ = rtx.send(Ev::Control(rpid, rv));
                            });
                            continue;
                        }
                        // #161: the hold expires into a DECISION, not a denial.
                        // Revocation binds wherever identity resolves: a revoked
                        // device's cert resolves via the challenge and the gate's
                        // absolute Deny fires. A peer whose identity does NOT
                        // resolve within the hold (a slow fallback link, or a
                        // lost challenge on a transport that came up late) is
                        // decided by the normal gate - consent and grants in
                        // shadow, the capability layer under authoritative. The
                        // residual (a revoked device whose identity ceremony does
                        // not complete on a given path being admitted) is
                        // precondition-bounded and documented in the changelog;
                        // the terminal-outcome model that closes it entirely is
                        // the next iteration, not a 0.8.0 change.
                    }

                    // C14/C22: consent. -y accepts everything; a resume of a
                    // partial we already said yes to auto-accepts; a verified
                    // device auto-accepts; otherwise the question joins the
                    // pending queue and the answer arrives via StdinLine, a
                    // per-process token marks re-enqueued offers so a remote
                    // peer can't forge "already consented".
                    let sender_name = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                    let link_trusted = conn.link(&pid).map(|l| l.trusted).unwrap_or(false);
                    let consented =
                        v["__consent"].as_str() == Some(ports.env.consent_token.as_str());
                    // Legacy (pre-capability) decision, per mode.
                    // A code is consent: the person typed the code this
                    // sender's ceremony was bound to, which is what `receive
                    // --help` promises ("`receive <code>` never asks"). It
                    // asked `accept? [y/N]` anyway at a terminal. Only the
                    // ceremony peer carries that consent, never a bystander.
                    let code_consent =
                        recv_code_path && recv_pake_done && conn.is_bound_active_peer(&pid);
                    let legacy_ok = offer_has_consent(
                        daemon,
                        yes,
                        consented,
                        link_trusted,
                        is_resume && offset > 0,
                        code_consent,
                    );
                    // Capability layer evaluated unconditionally (shadow samples the
                    // legacy-allowed population); legacy stands in shadow, cap gates
                    // under TUNLION_CAP_AUTHORITATIVE.
                    let authoritative = host.cap_authoritative();
                    let (ok, xfer_deny_reason, xfer_gate) = {
                        let az = crate::shell_gate::peer_authz(&mut conn, &pid);
                        let (idev, iusr, binding, expires, cert_revoked, ak_caps) = az.parts();
                        let store = host.cap_store();
                        let now = host.now_secs();
                        let outcome = cap::authorize_in(
                            &store,
                            "self",
                            cap::CAP_TRANSFER,
                            idev,
                            iusr,
                            ak_caps,
                            now,
                        );
                        // Trust floor: under authoritative, an untrusted link
                        // must never authorize transfer (pair-proof vs device-key).
                        let outcome =
                            cap::cap_trust_floor(&outcome, link_trusted, binding, authoritative);
                        // Fleet transfer scope, enforced by construction and VERIFIED
                        // here (not hardcoded `true`, which asserted a bound nothing
                        // checked). The offered name is basename-only (see ~14095:
                        // `Path::new(raw).file_name()`, "never trust a remote name with
                        // path separators") and lands in the receiver's OWN drop dir
                        // `dir`, which the sender cannot redirect. Assert the landing
                        // path is within `dir` so a future regression in the sanitizer
                        // or in how `dir` is derived TRIPS the gate (fails closed to
                        // grant-only) instead of silently widening scope. NOTE: this is
                        // a LEXICAL check; a symlink planted at the final `.part` create
                        // could still redirect the write — closed separately by the
                        // plain-file-only (O_NOFOLLOW/O_EXCL) write hardening tracked as
                        // a fleet-trust follow-up.
                        let landing = dir.join(&name);
                        let scoped_in_bounds =
                            filament_transfer::path_bounds::path_within(&dir, &landing);
                        let (own_user, has_grant) = cap::fleet_inputs_in(
                            &store,
                            "self",
                            cap::CAP_TRANSFER,
                            idev,
                            iusr,
                            ak_caps,
                            now,
                        );
                        // No deny list is consulted on the transfer path today;
                        // false preserves that exactly.
                        let d = host.cap_gate_effective(CapGate {
                            legacy_allowed: legacy_ok,
                            outcome: &outcome,
                            action: cap::CAP_TRANSFER,
                            resource: "self",
                            device_pub: idev,
                            user_pub: iusr,
                            binding,
                            cert_expires: expires,
                            auth_key_caps: ak_caps,
                            own_user_pub: own_user.as_ref(),
                            scoped_in_bounds,
                            has_explicit_grant: has_grant,
                            cert_revoked,
                            denied: false,
                            ceiling_authorizes: false,
                        });
                        let reason = if let cap::GateDecision::Deny { cap_reason } = &d {
                            cap_reason.clone()
                        } else {
                            None
                        };
                        log.debug(&format!(
                            "transfer-gate: from={sender_name} allowed={} legacy_ok={legacy_ok} trusted={link_trusted} binding={binding:?} own_user={} has_grant={has_grant} in_bounds={scoped_in_bounds} revoked={cert_revoked} authoritative={} reason={:?}",
                            d.allowed(),
                            own_user.is_some(),
                            authoritative,
                            reason
                        ));
                        (d.allowed(), reason, d)
                    };
                    // Under authoritative, a capability Deny hard-declines
                    // immediately: no prompt, skip the accept path entirely.
                    if let Some(reason) = cap::transfer_gate_decision(&xfer_gate, authoritative) {
                        log.say(&log.paint(
                            Tone::Dim,
                            &format!("  declined {name} from {sender_name} ({reason})",),
                        ));
                        if daemon {
                            host.enqueue_request_if_requestable(&sender_name, "transfer");
                        }
                        note_refusal(
                            &report,
                            daemon,
                            &name,
                            size,
                            "denied",
                            &format!("declined {name} from {sender_name} ({reason})"),
                            RefusalClass::Denied,
                        );
                        let r = t
                            .send_control(&policy_decline_msg(&id, Some(reason.as_str())))
                            .await;
                        peer_step(daemon, &pid, "decline", r, log.as_ref())?;
                        continue;
                    }
                    if !ok {
                        if !daemon && ports.env.interactive_terminal && xfer_deny_reason.is_none() {
                            st.pending.push_back((pid.clone(), v.clone()));
                            // The sender's no-answer timeout must not fire on a
                            // person who is still deciding; tell it so.
                            let _ = t.send_control(&protocol::pending_msg(&id)).await;
                            st.question_open
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            if st.pending.len() == 1 {
                                // C25: the question is a PERMANENT line first
                                // (nothing can be asked invisibly), with the
                                // sticky as the live answer tail.
                                let q =
                                    offer_question(log.as_ref(), &sender_name, &name, size, paired);
                                log.say(&q);
                                front_question(conn.present.as_ref(), log.as_ref(), &q, true);
                                st.question_shown = Instant::now();
                            }
                            continue; // decision arrives later via StdinLine
                        }
                        // #213: surface the REAL gate reason. In shadow mode a
                        // consent denial returns cap_reason None, so xfer_deny_reason
                        // is Some exactly when the gate refused for a real reason
                        // (revocation, ceiling, authoritative) - surface it. The tty
                        // hint is ONLY for the None case: an unanswered consent
                        // prompt on a non-tty, where passing -y genuinely changes the
                        // outcome. Telling a user to pass a flag they already passed,
                        // for a decision no flag can change, is how a green security
                        // property turns unmeasurable.
                        log.say(&log.paint(
                            Tone::Dim,
                            &format!(
                                "  declined {name} from {sender_name} ({})",
                                if daemon {
                                    xfer_deny_reason.as_deref().unwrap_or("unverified peer")
                                } else if let Some(reason) = xfer_deny_reason.as_deref() {
                                    reason
                                } else {
                                    "no tty, use -y to auto-accept"
                                }
                            ),
                        ));
                        match xfer_deny_reason.as_deref() {
                            Some(reason) => note_refusal(
                                &report,
                                daemon,
                                &name,
                                size,
                                "denied",
                                &format!("declined {name} from {sender_name} ({reason})"),
                                RefusalClass::Denied,
                            ),
                            None => note_refusal(
                                &report,
                                daemon,
                                &name,
                                size,
                                "no_tty",
                                &format!(
                                    "declined {name} from {sender_name}: no tty to ask on and no -y"
                                ),
                                RefusalClass::Usage,
                            ),
                        }
                        let r = t
                            .send_control(&policy_decline_msg(&id, xfer_deny_reason.as_deref()))
                            .await;
                        peer_step(daemon, &pid, "decline", r, log.as_ref())?;
                        continue;
                    }

                    // C23: never run two streams into one .part, a rejoin
                    // can re-offer a file whose first stream is still live;
                    // accepting both corrupted the path and crashed on the
                    // second rename. First stream wins.
                    //
                    // P0 (GAP-1) exception: a STALL repair re-offers the same file
                    // (resume:true) on a FRESH transport while the OLD stream's
                    // by_sid entry may still linger (its data path went dark). If
                    // the existing stream's transport is itself STALLED past the
                    // threshold, the "first stream" is the wedged one, flush it to
                    // its .part and accept the resume on the live link instead of
                    // declining (a decline would mark the SENDER's transfer done
                    // and abort the recovery). A genuinely FLOWING duplicate still
                    // wins as before.
                    let want_part = dir.join(format!("{name}.part"));
                    if !to_stdout {
                        let dup_keys: Vec<(String, u32)> = st
                            .by_sid
                            .iter()
                            .filter(|(_, inc)| inc.part_path == want_part)
                            .map(|(k, _)| k.clone())
                            .collect();
                        if !dup_keys.is_empty() {
                            // Is ANY existing stream for this file still flowing?
                            let any_flowing = dup_keys.iter().any(|(p, _)| {
                                conn.transport_of(p)
                                    .map(|t| t.idle_ms() < net::stall_ms())
                                    .unwrap_or(false)
                            });
                            if any_flowing {
                                // A real concurrent duplicate, first (flowing)
                                // stream wins. Ignore WITHOUT marking the sender
                                // done (a benign skip, not a user decline).
                                log.say(&log.paint(
                                    Tone::Dim,
                                    &format!(
                                        "  (duplicate offer for {name} ignored, already receiving it)"
                                    ),
                                ));
                                continue;
                            }
                            // The lingering stream(s) are STALLED, flush their
                            // partials to disk and drop them so the resume below
                            // re-opens the .part from its saved offset.
                            for k in dup_keys {
                                if let Some(inc) = st.by_sid.remove(&k) {
                                    let f = inc.file.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        let _ = f.sync_all();
                                    })
                                    .await;
                                }
                            }
                        }
                    }

                    if to_stdout {
                        // Pipe mode: no part files, no resume, pure stream.
                        // Write through a dup'd stdout fd so dropping the
                        // writer never closes the process's real fd 1; the
                        // /dev/stdout open is the portable-unix way to dup.
                        // (Windows: -o - is not supported yet; see G-e.)
                        #[cfg(unix)]
                        let out = tokio::fs::OpenOptions::new()
                            .write(true)
                            .open("/dev/stdout")
                            .await?;
                        #[cfg(not(unix))]
                        {
                            bail!("-o - (stdout streaming) is not supported on this platform yet");
                        }
                        #[cfg(unix)]
                        {
                            let out = out.into_std().await;
                            // A pipe cannot seek, so stdout gets an in-order
                            // writer (StdoutSink) instead of positional writes,
                            // which failed every `-o - | reader` with ESPIPE. It
                            // hashes what it writes, so the stream is verified
                            // against the offered digest and acked like a file.
                            let sink = Arc::new(std::sync::Mutex::new(
                                crate::recv::StdoutSink::new(out.try_clone()?),
                            ));
                            st.by_sid.insert(
                                (pid.clone(), sid),
                                IncomingFile {
                                    id: id.clone(),
                                    name,
                                    size,
                                    received: Arc::new(AtomicU64::new(0)),
                                    ranges: Arc::new(std::sync::Mutex::new(vec![])),
                                    file: Arc::new(out),
                                    part_path: PathBuf::new(),
                                    full: offer_full.clone(),
                                    inflight: Arc::new(AtomicI64::new(0)),
                                    end_seen: Arc::new(AtomicBool::new(false)),
                                    completion: Arc::new(crate::recv::CompletionGate::default()),
                                    ack_sid: 0,
                                    last_tick: 0,
                                    bar: conn.present.progress("(stdout)", size),
                                    write_err: Arc::new(std::sync::Mutex::new(None)),
                                    stdout: Some(sink),
                                },
                            );
                            // Ask for ONE in-order stream: split across parallel
                            // links, the second half would have to be held in
                            // memory until the first had been written. An older
                            // sender ignores this and the sink holds a bounded
                            // amount instead. Stdout cannot resume, so offset 0.
                            let mut accept = protocol::accept_msg(&id, 0);
                            accept["sequential"] = json!(true);
                            t.send_control(&accept).await?;
                            continue;
                        }
                    }
                    // The inbox may have been deleted while this ran: recreate it,
                    // or refuse with that reason (not "No such file or directory").
                    match crate::recv::files::ensure_inbox(host.as_ref(), &dir) {
                        Ok(true) => log.say(&log.paint(
                            Tone::Warn,
                            &format!("  the inbox {} was missing; recreated it", dir.display()),
                        )),
                        Ok(false) => {}
                        Err(e) => {
                            let (token, msg) = crate::recv::files::inbox_refusal(&dir, &name, &e);
                            log.critical(&log.paint(
                                Tone::Err,
                                &format!("  refused {name} from {sender_name}: {msg}"),
                            ));
                            note_refusal(
                                &report,
                                daemon,
                                &name,
                                size,
                                token,
                                &msg,
                                crate::recv::report::storage_kind(token),
                            );
                            let r = t
                                .send_control(&protocol::refuse_msg(&id, token, &msg))
                                .await;
                            peer_step(daemon, &pid, "refusal", r, log.as_ref())?;
                            continue;
                        }
                    }
                    // Refuse up front what cannot fit. Discovering ENOSPC half way
                    // through used to read as a CORRUPT file ("checksum still wrong
                    // after 3 re-fetches") on this side and "the receiver may have
                    // gotten nothing" on the sender's, when the truth was one line:
                    // the disk is full. Unknown free space (a platform that cannot
                    // say) accepts, and a write that then fails is caught below.
                    let need = size.saturating_sub(offset);
                    if let Some(free) = host.free_space(&dir) {
                        if free < need {
                            let (token, msg) = crate::recv::files::storage_refusal(
                                Some(StorageFailure::NoSpace),
                                &name,
                                "",
                                Some(need),
                                Some(free),
                            );
                            log.critical(&log.paint(
                                Tone::Err,
                                &format!("  refused {name} from {sender_name}: {msg}"),
                            ));
                            note_refusal(
                                &report,
                                daemon,
                                &name,
                                size,
                                token,
                                &msg,
                                crate::recv::report::storage_kind(token),
                            );
                            let r = t
                                .send_control(&protocol::refuse_msg(&id, token, &msg))
                                .await;
                            peer_step(daemon, &pid, "refusal", r, log.as_ref())?;
                            continue;
                        }
                    }
                    // P4: the digest to verify against on completion, the current
                    // offer's, else the one persisted with the partial (resume).
                    let effective_full = offer_full.clone().or(prior_full);
                    // A per-file open failure DECLINES this one file (continue),
                    // matching the other offer-accept declines. It must never unwind
                    // the receive loop: that would kill every other in-flight transfer.
                    let file = if offset > 0 {
                        // DEBUG, resilience internal (receiver resuming from offset).
                        log.debug(&format!(
                            "{name}: resuming at {} ({:.0}%)",
                            crate::present::human(offset),
                            offset as f64 / size.max(1) as f64 * 100.0
                        ));
                        // Open with write mode (not append) so we can seek to any
                        // position for multi-stream out-of-order writes.
                        // safe_resume_part: RESOLVE_BENEATH on Linux, O_NOFOLLOW +
                        // fstat regular-file check on other Unix. NO O_EXCL (resume).
                        match crate::recv::safe_resume_part(&part_path).await {
                            Ok(f) => f,
                            Err(e) => {
                                // Typed refusal, never silence: a decline the sender
                                // never hears about is a sender that waits forever.
                                let (token, msg) = crate::recv::files::storage_refusal(
                                    host.storage_failure(&e),
                                    &name,
                                    &e.to_string(),
                                    None,
                                    None,
                                );
                                log.critical(&log.paint(
                                    Tone::Err,
                                    &format!("  refused {name} from {sender_name}: {msg}"),
                                ));
                                note_refusal(
                                    &report,
                                    daemon,
                                    &name,
                                    size,
                                    token,
                                    &msg,
                                    crate::recv::report::storage_kind(token),
                                );
                                let r = t
                                    .send_control(&protocol::refuse_msg(&id, token, &msg))
                                    .await;
                                peer_step(daemon, &pid, "refusal", r, log.as_ref())?;
                                continue;
                            }
                        }
                    } else {
                        // Restart-from-0: a leftover .part of different content/size
                        // (interrupted transfer, or a common filename from another
                        // peer) must not block the fresh create. safe_create_part uses
                        // O_EXCL to refuse a planted symlink, which EEXISTs on any
                        // leftover .part; that Err used to unwind the whole loop. Remove
                        // the stale partial first (unlinking a symlink drops the link,
                        // not its target); a symlink planted in the gap still trips
                        // O_EXCL and is declined below, not followed.
                        let _ = std::fs::remove_file(&part_path);
                        let created = match (PartMeta {
                            size,
                            head: offer_head,
                            full: effective_full.clone(),
                        }
                        .store(&meta_path))
                        {
                            Ok(()) => crate::recv::safe_create_part(&part_path).await,
                            Err(e) => Err(e),
                        };
                        match created {
                            Ok(f) => f,
                            Err(e) => {
                                // The create failed (disk full, a name the filesystem
                                // refuses, a read-only or unwritable folder). This used
                                // to be a debug line and a silent `continue`, so the
                                // sender re-offered forever. Say why, to both ends.
                                crate::recv::discard_partial(&part_path);
                                let (token, msg) = crate::recv::files::storage_refusal(
                                    host.storage_failure(&e),
                                    &name,
                                    &e.to_string(),
                                    None,
                                    None,
                                );
                                log.critical(&log.paint(
                                    Tone::Err,
                                    &format!("  refused {name} from {sender_name}: {msg}"),
                                ));
                                note_refusal(
                                    &report,
                                    daemon,
                                    &name,
                                    size,
                                    token,
                                    &msg,
                                    crate::recv::report::storage_kind(token),
                                );
                                let r = t
                                    .send_control(&protocol::refuse_msg(&id, token, &msg))
                                    .await;
                                peer_step(daemon, &pid, "refusal", r, log.as_ref())?;
                                continue;
                            }
                        }
                    };
                    let bar = conn.present.progress(&name, size);
                    crate::recv::transfer_truth::note_part(
                        &mut session_parts,
                        &name,
                        &part_path,
                        size,
                    );
                    let file = Arc::new(file.into_std().await);
                    let received = Arc::new(AtomicU64::new(offset));
                    let ranges = Arc::new(std::sync::Mutex::new(if offset > 0 {
                        vec![(0, offset)]
                    } else {
                        vec![]
                    }));
                    st.by_sid.insert(
                        (pid.clone(), sid),
                        IncomingFile {
                            id: id.clone(),
                            name,
                            size,
                            received,
                            ranges,
                            file,
                            part_path,
                            full: effective_full,
                            inflight: Arc::new(AtomicI64::new(0)),
                            end_seen: Arc::new(AtomicBool::new(false)),
                            completion: Arc::new(crate::recv::CompletionGate::default()),
                            ack_sid: 0,
                            last_tick: 0,
                            bar,
                            write_err: Arc::new(std::sync::Mutex::new(None)),
                            stdout: None,
                        },
                    );
                    // The accept could not be sent (the link died under us): drop
                    // the stream just registered. Its .part stays for the
                    // sender's resume on the next link.
                    let r = t.send_control(&protocol::accept_msg(&id, offset)).await;
                    if peer_step(daemon, &pid, "accept", r, log.as_ref())?.is_none() {
                        st.by_sid.remove(&(pid.clone(), sid));
                    }
                }
                // The sender could not read its own source part way through: the
                // partial here can never be completed from it, so it is removed,
                // never kept as junk (`unread`, `unread.part`, `unread.part.meta`
                // were left behind before this message existed).
                Some("file-cancel") => {
                    let id = v["id"].as_str().unwrap_or_default().to_string();
                    let reason: String = v["reason"]
                        .as_str()
                        .unwrap_or("the sender cancelled it")
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(300)
                        .collect();
                    let keys: Vec<(String, u32)> = st
                        .by_sid
                        .iter()
                        .filter(|((p, _), inc)| *p == pid && inc.id == id)
                        .map(|(k, _)| k.clone())
                        .collect();
                    let remove_part = |part: &Path| {
                        let _ = std::fs::remove_file(part);
                        let mut meta = part.as_os_str().to_owned();
                        meta.push(".meta");
                        let _ = std::fs::remove_file(PathBuf::from(meta));
                    };
                    // The stream may already be parked (the sender's leave can
                    // land first and flush it out of the table), so the partial
                    // is also found by the name it was offered under.
                    let mut names: Vec<String> = Vec::new();
                    for k in keys {
                        if let Some(inc) = st.by_sid.remove(&k) {
                            if !to_stdout {
                                remove_part(inc.part_path.as_path());
                            }
                            names.push(inc.name.clone());
                        }
                    }
                    if names.is_empty() && !to_stdout {
                        if let Some(raw) = v["name"].as_str() {
                            let name = filament_transfer::safe_incoming_name(raw);
                            let part = dir.join(format!("{name}.part"));
                            if part.is_file() {
                                remove_part(part.as_path());
                                names.push(name);
                            }
                        }
                    }
                    for name in names {
                        log.critical(&log.paint(
                            Tone::Warn,
                            &format!("  {name}: the sender cancelled it ({reason}); its partial was removed"),
                        ));
                        sender_cancelled = Some(format!("{name}: {reason}"));
                    }
                }
                Some("file-end") => {
                    // Test hook (gate 18 standalone repro): drop the file-end
                    // control frame so a fully-received stream is stranded in
                    // by_sid, mirrors a sender whose PC tears down before the
                    // best-effort file-end is delivered.
                    if test_hooks::drop_file_end() {
                        continue;
                    }
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    // Exactly-once completion: the gate records end_seen and
                    // then checks inflight under SeqCst. If a writer drained
                    // the stream between those steps, this side claims the
                    // completion instead of both sides deferring forever.
                    let process_now = {
                        match st.by_sid.get_mut(&(pid.clone(), sid)) {
                            None => false, // unknown stream
                            Some(inc) => {
                                inc.ack_sid = sid;
                                inc.completion.file_end(&inc.inflight, &inc.end_seen)
                            }
                        }
                    };
                    if !process_now {
                        continue;
                    }
                    // No inflight writes — process inline (fast path).
                    let sid = v["sid"].as_u64().unwrap_or(0) as u32;
                    let mut inc = match st.by_sid.remove(&(pid.clone(), sid)) {
                        Some(i) => i,
                        None => continue,
                    };
                    let f = inc.file.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = f.sync_all();
                    })
                    .await;
                    if to_stdout {
                        stdout_delivered(&inc, &conn, &pid, sid, &report).await?;
                        st.completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    // A write already failed (disk full, read-only): that is the
                    // answer, not a checksum mismatch to re-fetch three times.
                    let failed = inc.write_err.lock().unwrap().clone();
                    if let Some(wf) = failed {
                        st.verify_fails.remove(&id);
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        let (fid, token, msg) = refuse_failed_write(
                            inc,
                            &dir,
                            &wf,
                            &from,
                            daemon,
                            &report,
                            log.as_ref(),
                            host.as_ref(),
                        );
                        if let Some(t) = conn.transport_of(&pid) {
                            let _ = t
                                .send_control(&protocol::refuse_msg(&fid, token, &msg))
                                .await;
                        }
                        continue;
                    }
                    if inc.full.is_some() {
                        let verdict = crate::recv::verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                st.verify_fails.remove(&id);
                                let rename_to = if st.completed == 0 {
                                    output.clone()
                                } else {
                                    None
                                };
                                let from =
                                    conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if crate::recv::files::finalize_incoming(
                                    host.as_ref(),
                                    log.as_ref(),
                                    inc,
                                    &dir,
                                    rename_to.as_deref(),
                                    daemon,
                                    &from,
                                    &report,
                                    &ports.env.delivery,
                                )
                                .await?
                                {
                                    st.completed += 1;
                                    // BUG-ACKLOSS reproducer: tear the link DOWN at the
                                    // instant the ack is due, so the sender never sees it and
                                    // its transport observes ApplicationClosed(0,""). In
                                    // `=once` mode this fires only the FIRST time, so a daemon
                                    // receiver recovers (delivers) on the re-dial.
                                    //
                                    // RESTORED 2026-08-30. This arm was wired in 12a8db82 and
                                    // was gone by the next commit, with no commit deleting it;
                                    // the else-if chain survived MINUS its first arm, which is
                                    // what a botched conflict resolution looks like. For ~620
                                    // commits `cli/tests/ack-loss-repro.sh` set
                                    // TUNLION_TEST_PREMATURE_CLOSE=1 and NOTHING READ IT, so
                                    // its "premature" round ran an ordinary transfer and the
                                    // promptness verdict measured the happy path.
                                    // `hooks_that_nothing_calls` now fails if any hook loses
                                    // its last call site again.
                                    if test_hooks::premature_close_after_ack()
                                        && !(test_hooks::premature_close_once()
                                            && test_hooks::premature_already_fired())
                                    {
                                        if test_hooks::premature_close_once() {
                                            test_hooks::premature_mark_fired();
                                        }
                                        log.say(&log.paint(
                                            Tone::Warn,
                                            &format!(
                                                "    [test] {nm} PREMATURE-CLOSE at ack (reproducing ack-loss / corpse)"
                                            ),
                                        ));
                                        sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                                        conn.drop_link(&pid);
                                    } else if test_hooks::suppress_delivery_ack() {
                                        log.say(&log.paint(
                                            Tone::Warn,
                                            &format!(
                                                "    [test] {nm} verified but SUPPRESSING delivery-ack"
                                            ),
                                        ));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(&crate::recv::files::delivery_ack(
                                                &id,
                                                sid,
                                                &ports.env.delivery,
                                            ))
                                            .await;
                                        // BOUNDED: this runs inline in the event
                                        // loop. The ack is already queued and goes
                                        // out on its own; the flush only waits for
                                        // the peer to acknowledge it, and a sender
                                        // that reads the ack and exits never does.
                                        // Unbounded, that parked the whole loop, so
                                        // the receiver never saw the peer-left that
                                        // ends it and held the finished file until
                                        // its timeout (gate 11c, G-k).
                                        let _ =
                                            tokio::time::timeout(ACK_FLUSH_BUDGET, t.flush()).await;
                                        log.say(&log.paint(
                                            Tone::Dim,
                                            &format!(
                                                "    {nm} verified (whole-file sha256 matched), acked"
                                            ),
                                        ));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = st.verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    log.critical(&log.paint(
                                        Tone::Err,
                                        &format!(
                                            "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                            inc.name
                                        ),
                                    ));
                                    st.verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = crate::recv::safe_create_part(&inc.part_path).await;
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    log.debug(&log.paint(
                                        Tone::Warn,
                                        &format!(
                                            "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                            inc.name, *fails
                                        ),
                                    ));
                                } else {
                                    log.debug(&log.paint(
                                        Tone::Warn,
                                        &format!(
                                            "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                            inc.name,
                                            crate::present::human(req_offset),
                                            crate::present::human(inc.size),
                                            *fails
                                        ),
                                    ));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = f.sync_all();
                                })
                                .await;
                                if req_offset == 0 {
                                    if let Ok(f) =
                                        crate::recv::safe_resume_part(&inc.part_path).await
                                    {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                }
                                writer_tasks.join_sid(&pid, sid, log.as_ref()).await;
                                inc.completion.reset(&inc.end_seen);
                                st.by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t
                                        .send_control(&protocol::accept_msg(&id, req_offset))
                                        .await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if st.completed == 0 {
                            output.clone()
                        } else {
                            None
                        };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if crate::recv::files::finalize_incoming(
                            host.as_ref(),
                            log.as_ref(),
                            inc,
                            &dir,
                            rename_to.as_deref(),
                            daemon,
                            &from,
                            &report,
                            &ports.env.delivery,
                        )
                        .await?
                        {
                            st.completed += 1;
                        }
                    }
                }
                _ => {}
            },
            Ev::MaybeComplete(pid, sid) => {
                // A background writer task finished and was the last inflight,
                // and end_seen was already set. Finalize (verify + delv ack).
                let ack_sid = {
                    st.by_sid
                        .get(&(pid.clone(), sid))
                        .map(|inc| inc.ack_sid)
                        .unwrap_or(0)
                };
                if let Some(mut inc) = st.by_sid.remove(&(pid.clone(), sid)) {
                    if to_stdout {
                        stdout_delivered(&inc, &conn, &pid, ack_sid, &report).await?;
                        st.completed += 1;
                        continue;
                    }
                    let id = inc.id.clone();
                    // A write already failed (disk full, read-only): that is the
                    // answer, not a checksum mismatch to re-fetch three times.
                    let failed = inc.write_err.lock().unwrap().clone();
                    if let Some(wf) = failed {
                        st.verify_fails.remove(&id);
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        let (fid, token, msg) = refuse_failed_write(
                            inc,
                            &dir,
                            &wf,
                            &from,
                            daemon,
                            &report,
                            log.as_ref(),
                            host.as_ref(),
                        );
                        if let Some(t) = conn.transport_of(&pid) {
                            let _ = t
                                .send_control(&protocol::refuse_msg(&fid, token, &msg))
                                .await;
                        }
                        continue;
                    }
                    if inc.full.is_some() {
                        let verdict = crate::recv::verify_incoming(&inc).await;
                        match verdict {
                            protocol::VerifyResult::Match => {
                                st.verify_fails.remove(&id);
                                let rename_to = if st.completed == 0 {
                                    output.clone()
                                } else {
                                    None
                                };
                                let from =
                                    conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                                let nm = inc.name.clone();
                                if crate::recv::files::finalize_incoming(
                                    host.as_ref(),
                                    log.as_ref(),
                                    inc,
                                    &dir,
                                    rename_to.as_deref(),
                                    daemon,
                                    &from,
                                    &report,
                                    &ports.env.delivery,
                                )
                                .await?
                                {
                                    st.completed += 1;
                                    // BUG-ACKLOSS reproducer: tear the link DOWN at the
                                    // instant the ack is due, so the sender never sees it and
                                    // its transport observes ApplicationClosed(0,""). In
                                    // `=once` mode this fires only the FIRST time, so a daemon
                                    // receiver recovers (delivers) on the re-dial.
                                    //
                                    // RESTORED 2026-08-30. This arm was wired in 12a8db82 and
                                    // was gone by the next commit, with no commit deleting it;
                                    // the else-if chain survived MINUS its first arm, which is
                                    // what a botched conflict resolution looks like. For ~620
                                    // commits `cli/tests/ack-loss-repro.sh` set
                                    // TUNLION_TEST_PREMATURE_CLOSE=1 and NOTHING READ IT, so
                                    // its "premature" round ran an ordinary transfer and the
                                    // promptness verdict measured the happy path.
                                    // `hooks_that_nothing_calls` now fails if any hook loses
                                    // its last call site again.
                                    if test_hooks::premature_close_after_ack()
                                        && !(test_hooks::premature_close_once()
                                            && test_hooks::premature_already_fired())
                                    {
                                        if test_hooks::premature_close_once() {
                                            test_hooks::premature_mark_fired();
                                        }
                                        log.say(&log.paint(
                                            Tone::Warn,
                                            &format!(
                                                "    [test] {nm} PREMATURE-CLOSE at ack (reproducing ack-loss / corpse)"
                                            ),
                                        ));
                                        sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                                        conn.drop_link(&pid);
                                    } else if test_hooks::suppress_delivery_ack() {
                                        log.say(&log.paint(
                                            Tone::Warn,
                                            &format!(
                                                "    [test] {nm} verified but SUPPRESSING delivery-ack"
                                            ),
                                        ));
                                    } else if let Some(t) = conn.transport_of(&pid) {
                                        let _ = t
                                            .send_control(&crate::recv::files::delivery_ack(
                                                &id,
                                                ack_sid,
                                                &ports.env.delivery,
                                            ))
                                            .await;
                                        log.say(&log.paint(
                                            Tone::Dim,
                                            &format!(
                                                "    {nm} verified (whole-file sha256 matched), acked"
                                            ),
                                        ));
                                    }
                                }
                            }
                            protocol::VerifyResult::Mismatch { restart_from_zero } => {
                                let fails = st.verify_fails.entry(id.clone()).or_insert(0);
                                *fails += 1;
                                if *fails > MAX_VERIFY_FAILS {
                                    log.critical(&log.paint(
                                        Tone::Err,
                                        &format!(
                                            "  {}: whole-file checksum still wrong after {MAX_VERIFY_FAILS} re-fetches, refusing to accept a corrupt file (partial kept)",
                                            inc.name
                                        ),
                                    ));
                                    st.verify_fails.remove(&id);
                                    continue;
                                }
                                let mut req_offset = inc.received.load(Ordering::Relaxed);
                                if restart_from_zero {
                                    let _ = crate::recv::safe_create_part(&inc.part_path).await;
                                    if let Ok(f) =
                                        crate::recv::safe_resume_part(&inc.part_path).await
                                    {
                                        inc.file = Arc::new(f.into_std().await);
                                    }
                                    inc.received.store(0, Ordering::Relaxed);
                                    inc.ranges.lock().unwrap().clear();
                                    req_offset = 0;
                                    log.debug(&log.paint(
                                        Tone::Warn,
                                        &format!(
                                            "  {}: received all bytes but whole-file checksum FAILED (corrupt), re-fetching from 0 (attempt {})",
                                            inc.name, *fails
                                        ),
                                    ));
                                } else {
                                    log.debug(&log.paint(
                                        Tone::Warn,
                                        &format!(
                                            "  {}: TRUNCATED ({}/{}), checksum can't match yet; re-requesting the rest (attempt {})",
                                            inc.name,
                                            crate::present::human(req_offset),
                                            crate::present::human(inc.size),
                                            *fails
                                        ),
                                    ));
                                }
                                let f = inc.file.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = f.sync_all();
                                })
                                .await;
                                writer_tasks.join_sid(&pid, sid, log.as_ref()).await;
                                inc.completion.reset(&inc.end_seen);
                                st.by_sid.insert((pid.clone(), sid), inc);
                                if let Some(t) = conn.transport_of(&pid) {
                                    let _ = t
                                        .send_control(&protocol::accept_msg(&id, req_offset))
                                        .await;
                                }
                            }
                        }
                    } else {
                        let rename_to = if st.completed == 0 {
                            output.clone()
                        } else {
                            None
                        };
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        if crate::recv::files::finalize_incoming(
                            host.as_ref(),
                            log.as_ref(),
                            inc,
                            &dir,
                            rename_to.as_deref(),
                            daemon,
                            &from,
                            &report,
                            &ports.env.delivery,
                        )
                        .await?
                        {
                            st.completed += 1;
                        }
                    }
                }
            }
            Ev::Chunk(pid, sid, offset, data) => {
                // L2 streams live in the HIGH half of the sid space, route them
                // to the tunnel mux, never the file-transfer table (the pure
                // high-bit prefix check keeps file send/recv byte-identical).
                // No serving-posture gate here: l2_enabled says whether WE
                // serve L2 opens, but inbound frames also carry replies to
                // streams WE opened (a plain-`up` daemon's warm pty open gets
                // its output dropped as "unknown sid" otherwise, and the
                // verify then misreports a granted session as refused). The
                // mux-map miss below still drops anything truly unknown.
                // A write to this file already failed: stop taking its bytes and
                // tell the sender why, now, instead of letting it stream the rest
                // into a disk that cannot hold it.
                let failed = if l2::is_l2_sid(sid) {
                    None
                } else {
                    st.by_sid
                        .get(&(pid.clone(), sid))
                        .and_then(|inc| inc.write_err.lock().unwrap().clone())
                };
                if let Some(wf) = failed {
                    if let Some(inc) = st.by_sid.remove(&(pid.clone(), sid)) {
                        let from = conn.link(&pid).map(|l| l.name.clone()).unwrap_or_default();
                        st.verify_fails.remove(&inc.id);
                        let (fid, token, msg) = refuse_failed_write(
                            inc,
                            &dir,
                            &wf,
                            &from,
                            daemon,
                            &report,
                            log.as_ref(),
                            host.as_ref(),
                        );
                        if let Some(t) = conn.transport_of(&pid) {
                            let _ = t
                                .send_control(&protocol::refuse_msg(&fid, token, &msg))
                                .await;
                        }
                    }
                    continue;
                }
                if l2::is_l2_sid(sid) {
                    if let Some(mux) = l2_muxes.get(&pid) {
                        mux.on_frame(sid, data).await;
                    }
                } else if let Some(inc) = st.by_sid.get_mut(&(pid.clone(), sid)) {
                    // --- TRACE recv path ---
                    let trace = cfg!(feature = "debug-logs") && ports.env.trace_throughput;
                    let t_recv_start = if trace {
                        Some(std::time::Instant::now())
                    } else {
                        None
                    };
                    // Determine the write position: absolute offset from the
                    // sender. Both QUIC and DataChannel now frame the offset.
                    // An offsetless frame is impossible under the new scheme.
                    let pos: u64 = match offset {
                        Some(off) => off,
                        None => {
                            dlog!(
                                "[recv] REFUSING offsetless chunk sid={sid}: transport must frame offset"
                            );
                            continue;
                        }
                    };
                    // The peer chose both the offset and the length. Nothing it
                    // writes may land past the size it offered (a sparse file of
                    // any size is otherwise one frame away), and the coverage
                    // list must stay bounded (every disjoint chunk adds a range).
                    if !chunk_fits_offer(pos, data.len(), inc.size)
                        || inc.ranges.lock().map(|r| r.len()).unwrap_or(usize::MAX)
                            >= MAX_RECV_RANGES
                    {
                        log.debug(&format!(
                            "  refusing chunk for sid {sid} from {pid}: {} bytes at {pos} is outside the offered {} bytes or too fragmented",
                            data.len(),
                            inc.size
                        ));
                        continue;
                    }
                    inc.inflight.fetch_add(1, Ordering::SeqCst);
                    let file = Arc::clone(&inc.file);
                    let stdout_sink = inc.stdout.clone();
                    let inflight = Arc::clone(&inc.inflight);
                    let end_seen = Arc::clone(&inc.end_seen);
                    let completion = Arc::clone(&inc.completion);
                    let ranges = Arc::clone(&inc.ranges);
                    let received = Arc::clone(&inc.received);
                    let write_err = Arc::clone(&inc.write_err);
                    let tx = tx.clone();
                    let pid_c = pid.clone();
                    let data_len = data.len();
                    let trace_inner = trace;
                    writer_tasks.spawn(pid.clone(), sid, move || {
                        // Own the inflight count before touching the sink: even
                        // a panic in the write path must decrement it, and, when
                        // this was the last writer, wake the event loop.
                        let _inflight = InflightGuard {
                            inflight,
                            end_seen,
                            completion,
                            tx,
                            write_err: Arc::clone(&write_err),
                            pid: pid_c,
                            sid,
                        };
                        let t_pwrite = if trace_inner {
                            Some(std::time::Instant::now())
                        } else {
                            None
                        };
                        // `pwrite_at` reports how many iterations the write took;
                        // more than one means a genuine short write. It used to
                        // print that itself, which put terminal output inside the
                        // byte-writing primitive. The primitive returns the fact
                        // now and the decision to report it lives out here.
                        // `-o -` writes in order instead: stdout may be a pipe.
                        let wrote = match &stdout_sink {
                            Some(sink) => crate::recv::stdout_put(sink, pos, &data),
                            None => filament_transfer::pwrite_at(&file, &data, pos),
                        };
                        if let Err(e) = &wrote {
                            // Write failed: do NOT record coverage (leaves the gap),
                            // and record WHY, once. A full disk or a filesystem gone
                            // read-only fails every later write too, and the event
                            // loop turns this into a typed refusal instead of three
                            // re-fetches and a false "corrupt file" verdict.
                            {
                                let mut slot = write_err.lock().unwrap();
                                if slot.is_none() {
                                    *slot = Some(crate::recv::WriteFailure::from_io(e));
                                }
                            }
                            dlog!("[recv] pwrite_at FAILED at pos={pos} len={data_len}: {e}");
                        } else {
                            if let Ok(iters) = &wrote {
                                if *iters > 1 {
                                    dlog!(
                                        "[recv] short write: {iters} iterations for {data_len} bytes at {pos}"
                                    );
                                }
                            }
                            // Write succeeded: record coverage AFTER bytes landed.
                            let mut r = ranges.lock().unwrap();
                            let (_delta, total) = filament_transfer::record_range(&mut *r, pos, data_len);
                            drop(r);
                            // fetch_max, not store: writer tasks run concurrently, so
                            // a task that locked earlier (lower union total) can reach
                            // this line AFTER one that locked later (higher total). The
                            // union total is monotonic, so max() keeps `received` from
                            // regressing to a stale value (which would spuriously trip
                            // the `recvd < size` gate in verify_incoming). Serialized in
                            // the old event-loop path; this race is new to the writer.
                            received.fetch_max(total, Ordering::Relaxed);
                        }
                        let pwrite_us = t_pwrite.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                        if trace_inner && pwrite_us > 1000 {
                            dlog!(
                                "[TRACE recv spawn_blocking] pos={} len={} pwrite={}us",
                                pos,
                                data_len,
                                pwrite_us
                            );
                        }
                    });
                    let recv_us = t_recv_start.map(|t| t.elapsed().as_micros()).unwrap_or(0);
                    if trace && recv_us > 500 {
                        dlog!(
                            "[TRACE recv Ev::Chunk] sid={} offset={:?} len={} dispatch={}us",
                            sid,
                            offset,
                            data_len,
                            recv_us
                        );
                    }
                    let r = inc.received.load(Ordering::Relaxed);
                    if r != inc.last_tick {
                        inc.bar.tick(r);
                        inc.last_tick = r;
                    }
                } else {
                    // Chunk arrived for unknown (pid, sid) - log instead of silently dropping.
                    // This happens during transport supersede or stall repair when old chunks
                    // arrive after the by_sid entry was removed.
                    log.debug(&format!(
                        "  dropping chunk for unknown sid {sid} from {pid} ({} bytes)",
                        data.len()
                    ));
                }
            }
            Ev::StdinLine(line) => {
                let ans = line.to_lowercase();
                if !st.pending.is_empty() {
                    // C22/C25: an open question owns stdin, but ONLY explicit
                    // answers count. An empty line (stray CR, idle Enter) used
                    // to default-decline an offer the user never saw; and any
                    // keypress within 300ms of the question appearing is a
                    // buffered stroke, not a decision.
                    if st.question_shown.elapsed() < Duration::from_millis(300) {
                        continue;
                    }
                    let mut answered = false;
                    if ans == "y" || ans == "yes" {
                        answered = true;
                        let (qpid, mut qv) = st.pending.pop_front().unwrap();
                        conn.present.clear_sticky();
                        qv["__consent"] = json!(ports.env.consent_token.clone());
                        let _ = tx.send(Ev::Control(qpid, qv)); // re-enter the offer path, consented
                    } else if ans == "n" || ans == "no" {
                        answered = true;
                        let (qpid, qv) = st.pending.pop_front().unwrap();
                        conn.present.clear_sticky();
                        let qname = filament_transfer::safe_incoming_name(
                            qv["name"].as_str().unwrap_or("file"),
                        );
                        note_refusal(
                            &report,
                            daemon,
                            &qname,
                            qv["size"].as_u64().unwrap_or(0),
                            "declined",
                            &format!("declined {qname}"),
                            RefusalClass::Denied,
                        );
                        log.say(&log.paint(
                            Tone::Dim,
                            &format!(
                                "  declined {}",
                                filament_transfer::safe_incoming_name(
                                    qv["name"].as_str().unwrap_or("file")
                                )
                            ),
                        ));
                        if let Some(t) = conn.transport_of(&qpid) {
                            let r = t
                                .send_control(&protocol::decline_msg(
                                    qv["id"].as_str().unwrap_or_default(),
                                ))
                                .await;
                            peer_step(daemon, &qpid, "decline", r, log.as_ref())?;
                        }
                    }
                    // show the next queued question (or re-show on gibberish)
                    if let Some((qpid, qv)) = st.pending.front() {
                        let s = conn.link(qpid).map(|l| l.name.clone()).unwrap_or_default();
                        let q = offer_question(
                            log.as_ref(),
                            &s,
                            qv["name"].as_str().unwrap_or("file"),
                            qv["size"].as_u64().unwrap_or(0),
                            paired,
                        );
                        if answered {
                            log.say(&q); // a NEW question fronted, permanent line (C25)
                            st.question_shown = Instant::now();
                        }
                        front_question(conn.present.as_ref(), log.as_ref(), &q, answered);
                    } else {
                        st.question_open
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if ans == "devices" {
                    // C29: session commands, `up` is a place you live in.
                    if devices.is_empty() {
                        log.say(&log.paint(
                            Tone::Dim,
                            "  no known devices yet, type a code or `pair` to add one",
                        ));
                    }
                    for (n, s) in &devices {
                        log.say(&format!(
                            "  {}  {}",
                            log.paint(Tone::Bold, n),
                            log.paint(
                                Tone::Dim,
                                &format!("(channel {})", &host.channel_of(s)[..12])
                            )
                        ));
                    }
                } else if let Some(n) = ans.strip_prefix("forget ") {
                    let n = n.trim();
                    if devices.iter().any(|(dn, _)| dn == n) {
                        // A typed command that fails is answered, never a
                        // reason to stop serving everyone else.
                        match ports.store.devices_remove(n) {
                            Ok(()) => {
                                devices.retain(|(dn, _)| dn != n);
                                log.say(&format!(
                                    "  {} forgot '{n}', it can no longer find this machine",
                                    log.paint(Tone::Ok, log.glyph_ok())
                                ));
                            }
                            Err(e) if daemon => log.say(&format!(
                                "  {} could not forget '{n}': {e:#}; still listening",
                                log.paint(Tone::Err, log.glyph_err())
                            )),
                            Err(e) => return Err(e),
                        }
                    } else {
                        log.say(&log.paint(
                            Tone::Dim,
                            &format!("  no device named '{n}' (try `devices`)"),
                        ));
                    }
                } else if daemon && (ans == "pair" || ans == "code" || regex_lite_code(&line)) {
                    // The console no longer pairs in-session: that ceremony
                    // was a v1 code plus a pair secret over a DataChannel the
                    // signaling server could MITM. `tunlion add` / `tunlion join` run the
                    // SPAKE2 ceremony, and the running daemon picks the new
                    // device up from the store.
                    log.say(&log.paint(
                        Tone::Dim,
                        "  to pair a device, run `tunlion add <device>` in another terminal (the other side runs `tunlion join <code>`)",
                    ));
                } else if ans == "pair" || ans == "code" {
                    sio.emit("pair-create", json!({})).await.ok();
                } else if regex_lite_code(&line) {
                    if claim_in_flight {
                        log.say(&log.paint(
                            Tone::Dim,
                            "  (a claim is already in flight, wait for it to resolve)",
                        ));
                    } else {
                        log.say(&format!("  claiming {}...", log.paint(Tone::Brand, &line)));
                        paired = true;
                        claim_in_flight = true;
                        sio.emit("pair-claim", json!({ "code": line.to_lowercase() }))
                            .await
                            .ok();
                    }
                } else if !line.is_empty() {
                    log.say(&log.paint(
                        Tone::Dim,
                        "  (type a code like brave-otter-123 to claim it · `pair` · `devices` · `forget <name>`)",
                    ));
                }
            }
            Ev::Interrupted => {
                stop.cancel();
                // Let the supervisor drop this future, then run the SAME
                // cleanup epilogue as ordinary return and setup failure.
                return std::future::pending().await;
            }
            // P0 (GAP-1): the inbound transfer stalled (zero bytes, link alive).
            // The receiver participates in the SYMMETRIC direct-QUIC repair: it
            // re-arms its own direct dial so the fresh authenticated connection
            // can form. The `.part` stays on disk; the sender re-offers
            // resume:true on the new transport, so the file continues from its
            // saved offset (no restart-from-zero). For a WebRTC link the repair
            // is the impolite-side ICE-restart inside correct_stall.
            Ev::TransferStalled(pid, idle_ms) => {
                // DEBUG, resilience internal (inbound stall detection).
                log.debug(&log.paint(
                    Tone::Warn,
                    &format!("  inbound stall: {idle_ms}ms with no data from peer, repairing link"),
                ));
                // P0 partial-preservation: flush THIS peer's in-flight partials
                // to their `.part` on disk and release the in-memory handles, so
                // the C23 "already receiving" guard doesn't reject the sender's
                // resume-offer on the FRESH repair link. The `.part` + `.meta`
                // stay on disk; the resume re-opens them from the saved offset
                // (no restart-from-zero). Only this peer's streams are dropped,
                // other links keep flowing.
                let stale: Vec<(String, u32)> = st
                    .by_sid
                    .keys()
                    .filter(|(p, _)| *p == pid)
                    .cloned()
                    .collect();
                for key in stale {
                    if let Some(inc) = st.by_sid.remove(&key) {
                        let f = inc.file.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            let _ = f.sync_all();
                        })
                        .await;
                        log.debug(&format!(
                            "{}: parked at {} for resume",
                            inc.name,
                            crate::present::human(inc.received.load(Ordering::Relaxed))
                        ));
                    }
                }
                match conn.correct_stall(&pid).await {
                    // Receiver has nothing to re-offer; the sender owns the offer.
                    // Rung (a) is a no-op here, wait for the sender's re-offer.
                    Rung::Resume => {}
                    Rung::Repaired => {}
                    // Rung (d) P1: the receiver re-established over the TURN relay
                    // (relay-only ICE), preserving its `.part`. The sender re-offers
                    // resume:true on the fresh relay link, the file continues from
                    // its saved offset. Nothing to do here.
                    Rung::Relayed => {}
                    // Direct rungs spent AND relay forbidden / already on relay:
                    // failed CLEANLY, partial kept on disk (message already shown).
                    Rung::Exhausted => {}
                }
            }
            // Losing the sender is only an ERROR when nothing completed,
            // after a successful transfer it's just closure (the quiet-exit
            // prints the same `done (N files).` the peer-left path would).
            Ev::Stuck(pid, generation) => {
                // Bug 5: repeated stuck before ANY byte arrived → hint at the
                // single-host mDNS wedge once.
                if !st.ever_received {
                    stuck_while_connecting += 1;
                    if stuck_while_connecting >= 2 {
                        ports.daemon.maybe_hint_local_wedge(&mut wedge_hint_shown);
                    }
                }
                if conn
                    .on_stuck(&pid, generation, "stuck while connecting")
                    .await?
                    && paired
                    && !keep_open
                {
                    // G-k: the dropped link may have delivered every byte but
                    // lost its file-end, finalize before deciding it's fatal.
                    crate::recv::files::sweep_completed_streams(
                        host.as_ref(),
                        log.as_ref(),
                        &mut st.by_sid,
                        &conn,
                        &dir,
                        &output,
                        to_stdout,
                        daemon,
                        &report,
                        &mut st.completed,
                        &ports.env.delivery,
                    )
                    .await?;
                    if st.completed == 0 {
                        bail!(crate::recv::transfer_truth::sender_gone_message(
                            &format!(
                                "the sender is unreachable: the connection to it failed {MAX_ATTEMPTS} times"
                            ),
                            &crate::recv::transfer_truth::kept_partials(&session_parts),
                            &dir,
                            code_claimed,
                        ));
                    }
                }
            }
            // RetryLink: the stuck-link ladder's scheduled retry came due (the
            // backoff runs on a timer task, never on this loop). Its exhausted
            // outcome is the same as a lost link's, so it shares the handling.
            ev @ (Ev::GraceExpired(..) | Ev::RetryLink(..)) => {
                let exhausted = match ev {
                    Ev::GraceExpired(pid, generation) => {
                        conn.on_stuck(&pid, generation, "lost").await?
                    }
                    Ev::RetryLink(pid, generation) => conn.on_retry_due(&pid, generation).await?,
                    _ => false,
                };
                if exhausted && paired && !keep_open {
                    crate::recv::files::sweep_completed_streams(
                        host.as_ref(),
                        log.as_ref(),
                        &mut st.by_sid,
                        &conn,
                        &dir,
                        &output,
                        to_stdout,
                        daemon,
                        &report,
                        &mut st.completed,
                        &ports.env.delivery,
                    )
                    .await?;
                    if st.completed == 0 {
                        bail!(crate::recv::transfer_truth::sender_gone_message(
                            &format!(
                                "the sender is unreachable: the connection to it failed {MAX_ATTEMPTS} times"
                            ),
                            &crate::recv::transfer_truth::kept_partials(&session_parts),
                            &dir,
                            code_claimed,
                        ));
                    }
                }
            }
            Ev::PcState(pid, s) => {
                // L2: a dead/closed link must abort every tunnel stream it
                // carried so no pump hangs on a peer that's gone (design §3.5).
                if l2_enabled && (s == "failed" || s == "closed" || s == "disconnected") {
                    // A peer id can have multiple racing candidates (direct
                    // QUIC and WebRTC). State from a losing candidate must not
                    // tear down the mux riding the selected, still-live path.
                    let selected_transport_dead = l2_muxes
                        .get(&pid)
                        .is_some_and(|mux| !mux.transport().is_alive());
                    if selected_transport_dead {
                        sync_tasks.cancel_sync_for_pid(&pid, log.as_ref()).await;
                        if let Some(mux) = l2_muxes.remove(&pid) {
                            mux.shutdown_all().await;
                        }
                    }
                    // #4: a genuinely DEAD link (failed/closed) DETACHES its PTY
                    // sessions, it does NOT kill them. The shell keeps running and
                    // buffering output; a reconnect with the same session id
                    // reattaches and replays. We deliberately skip `disconnected`:
                    // that is usually a transient ICE blip the SAME data channel
                    // rides out (no new pty-open follows), so detaching there would
                    // wedge a still-working session. The detached-idle / lifetime
                    // caps in the session task reap a session nobody returns to.
                    if selected_transport_dead
                        && (s == "failed" || s == "closed")
                        && !pty_bindings.is_empty()
                    {
                        crate::recv::servers::shell::detach_link_ptys(
                            &ports,
                            &pid,
                            &mut pty_bindings,
                        )
                        .await;
                    }
                }
                conn.on_pc_state(&pid, &s).await;
            }
            Ev::PeerLeft(v) => {
                // Test hook (gate 18): peer-left delivery is best-effort in the
                // real world; this simulates the loss deterministically so the
                // quiet-exit fallback (G-k) can be exercised. SIGSTOP can't do
                // it, engine.io's ping timeout reaps a frozen client in ~30s
                // and the legit peer-left wins the race.
                if test_hooks::drop_peer_left() {
                    continue;
                }
                let gone = v["id"]
                    .as_str()
                    .and_then(|p| conn.link(p))
                    .map(|l| l.name.clone());
                let left_pid = v["id"].as_str().unwrap_or_default().to_string();
                let left_mid_transfer = st.by_sid.keys().any(|(p, _)| *p == left_pid);
                if conn.on_peer_left(&v) {
                    let secs = conn.rejoin.rejoin_window.as_secs();
                    if !st.by_sid.is_empty() {
                        // Keep partials writable-but-parked; resume comes via
                        // rejoin (C6) or a later re-offer against the .part.
                        log.say(&log.paint(
                            Tone::Dim,
                            &format!("  sender disconnected mid-transfer, waiting up to {secs}s"),
                        ));
                        crate::recv::files::flush_inflight(&mut st.by_sid).await;
                    } else if st.completed > 0 && !keep_open {
                        log.say(&format!(
                            "done ({} file{}).",
                            st.completed,
                            if st.completed == 1 { "" } else { "s" }
                        ));
                        let _ = sio.disconnect().await;
                        return Ok(());
                    } else if paired && !keep_open {
                        // C21: NOT fatal, a phone opening its file picker
                        // suspends the whole tab and drops the socket. Hold
                        // the line; their client rejoins on refocus.
                        let gid = v["id"].as_str().unwrap_or_default();
                        let n = gone.unwrap_or_else(|| "sender".into());
                        log.say(&conn.roster(
                            gid,
                            "●",
                            Tone::Warn,
                            &format!(
                                "stepped away, holding the line up to {secs}s (Ctrl-C to stop)"
                            ),
                            &n,
                        ));
                    } else {
                        conn.rejoin.waiting_rejoin = None; // open listener: keep going
                        let gid = v["id"].as_str().unwrap_or_default();
                        match gone {
                            Some(n) => log.say(&conn.roster(
                                gid,
                                "○",
                                Tone::Dim,
                                "left, still listening",
                                &n,
                            )),
                            None => log.say(&log.paint(Tone::Dim, "  peer left, still listening")),
                        }
                    }
                }
                // The sender of a one-shot receive left mid-transfer and its link
                // is gone, but it was not the ACTIVE link, so no rejoin window
                // opened and nothing bounded the wait: the receive then sat
                // through the whole reconnect ladder against a dead process (a
                // SIGKILLed sender measured ~96 s) before giving up. Open the
                // same bounded window the active case gets.
                if !daemon
                    && paired
                    && !keep_open
                    && left_mid_transfer
                    && !conn.links.contains_key(&left_pid)
                    && conn.rejoin.waiting_rejoin.is_none()
                {
                    conn.rejoin.rejoin_window = host.rejoin_unwarned();
                    conn.rejoin.waiting_rejoin = Some(Instant::now());
                    log.say(&log.paint(
                        Tone::Dim,
                        &format!(
                            "  sender disconnected mid-transfer, waiting up to {}s",
                            conn.rejoin.rejoin_window.as_secs()
                        ),
                    ));
                    crate::recv::files::flush_inflight(&mut st.by_sid).await;
                }
            }
            _ => {}
        }
    }
}

/// The shared cancellation error.
pub fn cancelled() -> anyhow::Error {
    anyhow::anyhow!("cancelled")
}

fn link_nonce() -> Vec<u8> {
    hex::decode(fresh_secret()).unwrap_or_else(|_| fresh_secret().into_bytes())
}

const OVERLAY_DIAL_BOUND: Duration = Duration::from_secs(3);
const OVERLAY_DIAL_TIMED_OUT: &str = "overlay dial timed out";
const OVERLAY_TARGET_CLOSED: &str =
    "overlay dial refused: nothing is listening behind the exposed port there";
const OVERLAY_SETTLE_MAX: Duration = Duration::from_millis(1500);

fn overlay_settle_window(handshake: Duration) -> Duration {
    (handshake * 2 + Duration::from_millis(150))
        .clamp(Duration::from_millis(250), OVERLAY_SETTLE_MAX)
}

// ---- pure helpers moved with the loop ----

/// Quote a value for a replayed command line.
pub fn command_arg(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._/:".contains(character))
    {
        return value.to_string();
    }
    #[cfg(windows)]
    {
        return format!("\"{}\"", value.replace('"', "\\\""));
    }
    #[cfg(not(windows))]
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

async fn link_fingerprints(conn: &Conn, pid: &str) -> Option<(String, String)> {
    let peer = conn.link(pid)?.peer.clone()?;
    peer.fingerprints().await
}

fn nonce_binding(
    t: &Arc<dyn Transport>,
    fps: Option<&(String, String)>,
    nonce: &[u8],
) -> Option<Vec<u8>> {
    if t.as_any().is::<net::DataChannelTransport>() {
        let (a, b) = fps?;
        Some(dtls_channel_binding(a, b, nonce))
    } else {
        Some(nonce.to_vec())
    }
}

fn out_binding(
    t: &Arc<dyn Transport>,
    pid: &str,
    theirs: &HashMap<String, Vec<u8>>,
    fps: Option<&(String, String)>,
) -> Option<Vec<u8>> {
    t.channel_binding()
        .or_else(|| theirs.get(pid).and_then(|n| nonce_binding(t, fps, n)))
}

fn in_binding(
    t: &Arc<dyn Transport>,
    pid: &str,
    ours: &HashMap<String, Vec<u8>>,
    fps: Option<&(String, String)>,
) -> Option<Vec<u8>> {
    t.channel_binding()
        .or_else(|| ours.get(pid).and_then(|n| nonce_binding(t, fps, n)))
}

fn dtls_channel_binding(fp_a: &str, fp_b: &str, nonce: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    const LABEL: &[u8] = b"filament/dtls-link-binding/v1\0";
    let a = fp_a.trim().to_ascii_uppercase();
    let b = fp_b.trim().to_ascii_uppercase();
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update((lo.len() as u32).to_be_bytes());
    h.update(lo.as_bytes());
    h.update((hi.len() as u32).to_be_bytes());
    h.update(hi.as_bytes());
    h.update(nonce);
    h.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    hex::encode(outer.finalize())
}

pub fn proof_for(
    secret: &str,
    prover_uid: &str,
    a_uid: &str,
    b_uid: &str,
    fp1: &str,
    fp2: &str,
) -> String {
    let (lo, hi) = if a_uid < b_uid {
        (a_uid, b_uid)
    } else {
        (b_uid, a_uid)
    };
    let (f_lo, f_hi) = if fp1 < fp2 { (fp1, fp2) } else { (fp2, fp1) };
    hmac_sha256(
        secret.as_bytes(),
        format!("filament-proof2:{prover_uid}|{lo}|{hi}|{f_lo}|{f_hi}").as_bytes(),
    )
}

pub fn offer_question(
    log: &dyn LogSink,
    sender: &str,
    name: &str,
    size: u64,
    paired: bool,
) -> String {
    let sender = if sender.is_empty() {
        "unknown peer"
    } else {
        sender
    };
    let name = filament_transfer::safe_incoming_name(name);
    let hint = if paired { " [paired]" } else { "" };
    format!(
        "  {}{} offers {} ({}), accept? [y/N] ",
        log.paint(Tone::Bold, sender),
        hint,
        name,
        crate::present::human(size)
    )
}

fn regex_lite_code(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts[0].chars().all(|c| c.is_ascii_lowercase())
        && parts[1].chars().all(|c| c.is_ascii_lowercase())
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[2].len() >= 2
        && parts[2].chars().all(|c| c.is_ascii_digit())
}
/// `receive -o -`: the sender said the stream ended. Every byte written in
/// order and the digest of what was written matching the offered one is a
/// delivery like a file's, and is acked the same way, so the sender can report
/// it verified. Anything else ends the receive with the reason: the bytes are
/// already out and stdout cannot be rewound to re-fetch them.
async fn stdout_delivered(
    inc: &IncomingFile,
    conn: &Conn,
    pid: &str,
    sid: u32,
    report: &RecvReport,
) -> Result<()> {
    let Some(sink) = &inc.stdout else {
        return Ok(());
    };
    let (verdict, written) = {
        let s = sink
            .lock()
            .map_err(|_| anyhow::anyhow!("the stdout writer for {} failed", inc.name))?;
        (s.verdict(inc.size, inc.full.as_deref()), s.written())
    };
    if let Err(why) = verdict {
        bail!("{}: {why}", inc.name);
    }
    inc.bar.done(written);
    report.note_stored(&inc.name, written, inc.full.as_deref(), "-");
    if inc.full.is_some() {
        if let Some(t) = conn.transport_of(pid) {
            let _ = t
                .send_control(&protocol::delivery_ack_msg(&inc.id, sid))
                .await;
            let _ = t.flush().await;
        }
    }
    Ok(())
}

/// A write to an incoming file failed. Report it on this side (must-see), drop
/// the partial, and return the typed refusal (`id`, token, sentence) for the
/// sender. `need` is what was still to come and `free` what the disk has now,
/// so a full disk says by how much instead of calling the file corrupt.
fn refuse_failed_write(
    inc: IncomingFile,
    dir: &Path,
    wf: &crate::recv::WriteFailure,
    from: &str,
    daemon: bool,
    report: &RecvReport,
    log: &dyn LogSink,
    host: &dyn HostServices,
) -> (String, &'static str, String) {
    let need = inc
        .size
        .saturating_sub(inc.received.load(Ordering::Relaxed));
    let free = host.free_space(dir);
    let (token, msg) =
        crate::recv::files::storage_refusal(wf.kind, &inc.name, &wf.detail, Some(need), free);
    let from = if from.is_empty() { "the sender" } else { from };
    log.critical(&log.paint(
        Tone::Err,
        &format!("  refused {} from {from}: {msg}", inc.name),
    ));
    note_refusal(
        report,
        daemon,
        &inc.name,
        inc.size,
        token,
        &msg,
        crate::recv::report::storage_kind(token),
    );
    let id = inc.id.clone();
    let part = inc.part_path.clone();
    drop(inc);
    crate::recv::discard_partial(&part);
    (id, token, msg)
}

/// Record a refusal for a one-shot receive's outcome (`recv_report`). The
/// daemon serves many senders and ends with none of them, so it keeps no list.
fn note_refusal(
    report: &RecvReport,
    daemon: bool,
    name: &str,
    size: u64,
    token: &str,
    msg: &str,
    class: RefusalClass,
) {
    if !daemon {
        report.note_refused(name, size, token, msg, class);
    }
}
#[cfg(test)]
mod caps_reannounce_tests {
    use super::caps_reannounce;

    #[test]
    fn a_grant_or_last_revoke_is_announced_on_live_links() {
        assert_eq!(caps_reannounce(false, true).unwrap()["shell"], true);
        assert_eq!(caps_reannounce(true, false).unwrap()["shell"], false);
        assert_eq!(caps_reannounce(true, false).unwrap()["type"], "caps");
        assert!(caps_reannounce(true, true).is_none());
        assert!(caps_reannounce(false, false).is_none());
    }
}

#[cfg(test)]
mod pake_expired_tests {
    use super::recv_pake_expired_message;

    #[test]
    fn older_version_only_when_no_peer_ran_a_ceremony() {
        assert!(recv_pake_expired_message(false, 60).contains("older version"));
        let m = recv_pake_expired_message(true, 60);
        assert!(!m.contains("older version"), "{m}");
        assert!(m.contains("60s") && m.contains("FRESH code"), "{m}");
    }
}

#[cfg(test)]
mod offer_consent_tests {
    use super::offer_has_consent;

    /// Eval item 6: `receive <code>` asked `accept? [y/N]` at a terminal while
    /// its help says a code never asks. The code's own sender is accepted.
    #[test]
    fn a_code_is_consent_and_nothing_else_is() {
        assert!(offer_has_consent(false, false, false, false, false, true));
        // A room offer from an unproven stranger still asks.
        assert!(!offer_has_consent(false, false, false, false, false, false));
        // The daemon never treats a code as consent: it holds no code.
        assert!(!offer_has_consent(true, false, false, false, false, true));
        assert!(offer_has_consent(true, false, false, true, false, false));
    }

    #[test]
    fn the_receive_help_promises_what_the_code_path_does() {
        let help = include_str!("../../../../cli/src/cli_def.rs");
        assert!(help.contains("`receive <code>` never asks"));
    }
}

#[cfg(test)]
mod quiet_exit_tests {
    use super::quiet_exit_reason;

    #[test]
    fn a_code_receive_ends_after_its_files_even_while_the_browser_stays_connected() {
        // The B03 case: files done, idle, the browser's link still healthy.
        assert!(quiet_exit_reason(1, false, true, false, true).is_some());
        // Not before anything arrived, not mid-transfer, not with --keep-open.
        assert!(quiet_exit_reason(0, false, true, false, true).is_none());
        assert!(quiet_exit_reason(1, false, false, false, true).is_none());
        assert!(quiet_exit_reason(1, true, true, false, true).is_none());
        // A non-code receive keeps waiting while a healthy link is up (gate 6:
        // a bystander between two human-paced sends), and quiet-exits once clear.
        assert!(quiet_exit_reason(1, false, true, false, false).is_none());
        assert!(quiet_exit_reason(1, false, true, true, false).is_some());
    }
}

#[cfg(test)]
mod receive_timeout_tests {
    use super::receive_timed_out;
    use std::time::Duration;

    #[test]
    fn nothing_arrived_at_the_deadline_is_a_timeout() {
        assert!(receive_timed_out(
            Duration::from_secs(30),
            Some(Duration::from_secs(30)),
            0
        ));
        assert!(receive_timed_out(
            Duration::from_secs(31),
            Some(Duration::from_secs(30)),
            0
        ));
        assert!(!receive_timed_out(
            Duration::from_secs(29),
            Some(Duration::from_secs(30)),
            0
        ));
    }

    #[test]
    fn a_received_file_beats_the_deadline() {
        // The transfer happened; the clock must not turn a success into a
        // timeout because the sender stayed connected afterwards.
        assert!(!receive_timed_out(
            Duration::from_secs(99),
            Some(Duration::from_secs(30)),
            1
        ));
    }

    #[test]
    fn no_deadline_means_no_deadline() {
        assert!(!receive_timed_out(Duration::from_secs(86_400), None, 0));
        // 0 is the documented "wait without limit" value.
        assert!(!receive_timed_out(
            Duration::from_secs(86_400),
            Some(Duration::ZERO),
            0
        ));
    }
}

#[cfg(test)]
mod receive_expected_sha256_tests {
    use super::{sha256_matches, valid_sha256};

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_only_a_well_formed_sha256() {
        assert!(valid_sha256(HASH));
        assert!(valid_sha256(&HASH.to_uppercase()));
        assert!(!valid_sha256("abcd"));
        assert!(!valid_sha256(&format!("{HASH}00")));
        assert!(!valid_sha256(&"z".repeat(64)));
    }

    #[test]
    fn compares_digest_hex_case_insensitively_and_requires_a_digest() {
        assert!(sha256_matches(HASH, Some(HASH)));
        assert!(sha256_matches(HASH, Some(&HASH.to_uppercase())));
        assert!(!sha256_matches(HASH, None));
        assert!(!sha256_matches(HASH, Some(&"f".repeat(64))));
        assert!(!sha256_matches("invalid", Some(HASH)));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::driver::{Cancellation, DriverOutcome, Readiness};
    use crate::host::{NoHost, NoLog};
    use crate::recv::ports::RecvEnv;

    async fn invalid_receive_with(
        stop: &Cancellation,
        cleanup: &mut RecvCleanup,
    ) -> DriverOutcome<Result<()>> {
        // Validation precedes filesystem/network/UI setup, so this exercises
        // the actual return seam without a backend or process signal adapter.
        let (readiness, _watch) = Readiness::new();
        let mut env = RecvEnv::default();
        env.interactive_terminal = false;
        let ports = crate::recv::ports::test_support::ports(env);
        drive(
            "https://unused.invalid",
            None,
            PathBuf::new(),
            false,
            None,
            None,
            false,
            None,
            Some("invalid".into()),
            false,
            None,
            false,
            None,
            ShellPolicy::Granted,
            None,
            false,
            filament_transport::TransportContext::default(),
            Arc::new(NoLog),
            Arc::new(NoHost),
            ports,
            RecvReport::new(),
            stop,
            &readiness,
            cleanup,
        )
        .await
    }

    async fn invalid_receive(stop: &Cancellation) -> DriverOutcome<Result<()>> {
        let mut cleanup = RecvCleanup::default();
        invalid_receive_with(stop, &mut cleanup).await
    }

    #[tokio::test]
    async fn driver_setup_failure_returns_without_a_process_exit() {
        match invalid_receive(&Cancellation::default()).await {
            DriverOutcome::Returned(Err(error)) => {
                assert!(error.to_string().contains("--expect-sha256"));
            }
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_library_engine_drives_the_real_receive_dispatch() {
        use crate::driver::Engine;
        let stop = Cancellation::default();
        let engine = Engine::start(stop.clone(), |stop, _readiness| async move {
            let mut cleanup = RecvCleanup::default();
            invalid_receive_with(&stop, &mut cleanup).await
        });
        match engine.wait().await.expect("engine task") {
            DriverOutcome::Returned(Err(error)) => {
                assert!(error.to_string().contains("--expect-sha256"));
            }
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn driver_pre_cancel_is_local_and_returns_after_cleanup() {
        let first = Cancellation::default();
        first.cancel();
        assert!(matches!(
            invalid_receive(&first).await,
            DriverOutcome::Cancelled
        ));
        // Another invocation still runs validation, not cancellation.
        assert!(matches!(
            invalid_receive(&Cancellation::default()).await,
            DriverOutcome::Returned(Err(_))
        ));
    }

    fn empty_recv_state() -> RecvState {
        RecvState {
            by_sid: HashMap::new(),
            verify_fails: HashMap::new(),
            completed: 0,
            ever_received: false,
            pending: Default::default(),
            pending_proven: Arc::new(Mutex::new(HashMap::new())),
            question_open: Arc::new(AtomicBool::new(false)),
            question_shown: Instant::now(),
            recv_pending_offers: HashMap::new(),
            recv_cers: HashMap::new(),
            recv_deadlines: HashMap::new(),
        }
    }

    /// Records the task destructor inside the cleanup order vector.
    struct PhaseDrop;
    impl Drop for PhaseDrop {
        fn drop(&mut self) {
            super::note_cleanup_phase("task_drop");
        }
    }

    #[tokio::test]
    async fn cleanup_stops_a_started_watchdog_before_tasks_and_flush() {
        super::CLEANUP_PHASES.with(|phases| phases.borrow_mut().clear());
        let mut cleanup = RecvCleanup {
            watchdog: crate::recv::lifecycle::LoopWatchdog::for_test(),
            ..RecvCleanup::default()
        };
        cleanup.watchdog.tick(Arc::new(NoLog));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        cleanup.tasks.push(tokio::spawn(async move {
            let _guard = PhaseDrop;
            let _ = entered_tx.send(());
            std::future::pending::<()>().await;
        }));
        entered_rx.await.unwrap();
        // `Some` makes finish enter the flush stage (an empty map parks nothing).
        cleanup.state = Some(empty_recv_state());
        cleanup.finish(&NoLog).await;
        assert_eq!(
            super::CLEANUP_PHASES.with(|phases| phases.borrow().clone()),
            vec![
                "watchdog",
                "writers",
                "sync_tasks",
                "task_drop",
                "tasks",
                "flush",
            ]
        );
    }

    #[tokio::test]
    async fn cancellation_then_cleanup_stops_a_started_watchdog() {
        super::CLEANUP_PHASES.with(|phases| phases.borrow_mut().clear());
        let mut cleanup = RecvCleanup {
            watchdog: crate::recv::lifecycle::LoopWatchdog::for_test(),
            ..RecvCleanup::default()
        };
        let log = Arc::new(NoLog);
        let weak = Arc::downgrade(&log);
        cleanup.watchdog.tick(log);
        let stop = Cancellation::default();
        stop.cancel();
        // The real driver seam: cancellation resolves, then its cleanup runs.
        assert!(matches!(
            invalid_receive_with(&stop, &mut cleanup).await,
            DriverOutcome::Cancelled
        ));
        assert!(
            weak.upgrade().is_none(),
            "cleanup joined the started watchdog and released its sink"
        );
        assert_eq!(
            super::CLEANUP_PHASES.with(|phases| phases.borrow().clone()),
            vec!["watchdog", "writers", "sync_tasks", "tasks"]
        );
    }

    /// A blocking writer is admitted work, not an abortable task: cleanup must
    /// wait for it before flushing, and must not report a finished epilogue
    /// while it still runs.
    #[tokio::test]
    async fn cleanup_awaits_a_gated_blocking_writer_before_flush() {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let cleanup = RecvCleanup {
            state: Some(empty_recv_state()),
            trace: Some(Arc::clone(&trace)),
            ..RecvCleanup::default()
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let writer_trace = Arc::clone(&trace);
        let writers = cleanup.writers.clone();
        cleanup.writers.spawn("peer-gated".into(), 1, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            writer_trace.lock().unwrap().push("writer");
        });
        let (finished_tx, mut finished_rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn(async move {
            let mut cleanup = cleanup;
            cleanup.finish(&NoLog).await;
            let _ = finished_tx.send(());
            cleanup
        });
        started_rx.await.unwrap();
        // join_all takes every handle before awaiting, so an empty group while
        // the writer is still gated proves cleanup reached the writer join.
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writers.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup reached the writer join");
        // The writer is provably still inside its blocking call, and cleanup
        // has recorded only the pre-writer stage, never the flush.
        let phases = trace.lock().unwrap().clone();
        assert_eq!(
            phases,
            vec!["watchdog"],
            "cleanup advanced past the writer join"
        );
        assert!(
            finished_rx.try_recv().is_err(),
            "finish returned while an admitted write was still running"
        );
        release_tx.send(()).unwrap();
        let cleanup = running.await.expect("cleanup task");
        finished_rx.await.expect("cleanup completion");
        let phases = trace.lock().unwrap().clone();
        assert_eq!(
            phases,
            vec![
                "watchdog",
                "writer",
                "writers",
                "sync_tasks",
                "tasks",
                "flush",
            ],
            "the admitted write completed before the flush stage"
        );
        assert!(cleanup.writers.is_empty(), "cleanup drained every writer");
    }

    #[tokio::test]
    async fn writer_reaping_joins_finished_tasks_and_keeps_running_ones() {
        let writers = WriterTasks::default();
        let (running_started_tx, running_started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (running_done_tx, running_done_rx) = tokio::sync::oneshot::channel();
        writers.spawn("peer-running".into(), 7, move || {
            let _ = running_started_tx.send(());
            let _ = release_rx.recv();
            let _ = running_done_tx.send(());
        });
        running_started_rx.await.unwrap();

        let (quick_done_tx, quick_done_rx) = tokio::sync::oneshot::channel();
        writers.spawn("peer-quick".into(), 8, move || {
            let _ = quick_done_tx.send(());
        });
        quick_done_rx.await.unwrap();
        // Reap by observing completion, not by sleeping: the running writer
        // must survive, the finished one must be joined and released.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                writers.reap(&NoLog).await;
                let tasks = writers.tasks.lock().unwrap();
                if tasks.len() == 1 && tasks.values().all(|task| task.sid == 7) {
                    break;
                }
                drop(tasks);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finished writer handle is reaped");

        release_tx.send(()).unwrap();
        running_done_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writers.is_empty() {
                writers.reap(&NoLog).await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed running writer is reaped");
    }

    /// A verify re-request must join this stream's writers before re-arming
    /// its completion gate; otherwise a post-decrement writer could claim the
    /// next generation.
    #[tokio::test]
    async fn verify_retry_joins_stream_writers_before_reset() {
        let writers = WriterTasks::default();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        writers.spawn("peer".into(), 7, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx.await.unwrap();

        let joiner = {
            let writers = writers.clone();
            tokio::spawn(async move {
                writers.join_sid("peer", 7, &NoLog).await;
                writers
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writers.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("join_sid took the stream's writer handle");
        assert!(
            !joiner.is_finished(),
            "join_sid must wait for the stream's writer"
        );
        release_tx.send(()).unwrap();
        let writers = joiner.await.expect("join task");
        assert!(
            writers.is_empty(),
            "the stream's writer is joined and drained"
        );
    }

    fn completion_writer(
        inflight: &Arc<AtomicI64>,
        end_seen: &Arc<AtomicBool>,
        completion: &Arc<crate::recv::CompletionGate>,
        tx: mpsc::UnboundedSender<Ev>,
    ) -> InflightGuard {
        InflightGuard {
            inflight: Arc::clone(inflight),
            end_seen: Arc::clone(end_seen),
            completion: Arc::clone(completion),
            tx,
            write_err: Arc::new(Mutex::new(None)),
            pid: "peer".into(),
            sid: 7,
        }
    }

    /// Write-before-end: the last writer drains completely before file-end
    /// arrives. File-end must take the inline fast path and publish end_seen.
    /// (The old read-then-store window itself is forced inside
    /// `CompletionGate::file_end` by the library regression test.)
    #[test]
    fn file_end_claims_after_the_last_writer_drained_first() {
        let inflight = Arc::new(AtomicI64::new(1));
        let end_seen = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(crate::recv::CompletionGate::default());
        let (tx, mut rx) = mpsc::unbounded_channel();

        drop(completion_writer(&inflight, &end_seen, &completion, tx));
        assert!(rx.try_recv().is_err(), "writer saw no end yet");
        assert!(
            completion.file_end(&inflight, &end_seen),
            "file-end claims inline after the writer drained first"
        );
        assert!(end_seen.load(Ordering::SeqCst), "end_seen is published");
        assert!(
            rx.try_recv().is_err(),
            "an inline completion needs no MaybeComplete event"
        );
        assert!(
            !completion.last_writer(1, &end_seen),
            "the writer cannot claim a second completion"
        );
    }

    /// The ordinary deferred path: file-end arrives while a writer is still in
    /// flight, so the last writer emits the one MaybeComplete.
    #[test]
    fn file_end_defers_to_the_last_writer_and_it_emits_once() {
        let inflight = Arc::new(AtomicI64::new(1));
        let end_seen = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(crate::recv::CompletionGate::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(!completion.file_end(&inflight, &end_seen));
        drop(completion_writer(&inflight, &end_seen, &completion, tx));
        match rx.try_recv() {
            Ok(Ev::MaybeComplete(pid, sid)) => {
                assert_eq!((pid.as_str(), sid), ("peer", 7));
            }
            Ok(other) => panic!("unexpected event: {other:?}"),
            Err(error) => panic!("the last writer must emit MaybeComplete: {error}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one MaybeComplete");
    }

    /// A verify re-request re-inserts the stream: the gate must be re-armed so
    /// the next last writer can complete it again exactly once.
    #[test]
    fn completion_gate_rearms_after_a_verify_retry() {
        let inflight = Arc::new(AtomicI64::new(0));
        let end_seen = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(crate::recv::CompletionGate::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(completion.file_end(&inflight, &end_seen));
        completion.reset(&end_seen);
        assert!(!end_seen.load(Ordering::SeqCst));

        inflight.store(1, Ordering::SeqCst);
        assert!(!completion.file_end(&inflight, &end_seen));
        drop(completion_writer(&inflight, &end_seen, &completion, tx));
        match rx.try_recv() {
            Ok(Ev::MaybeComplete(pid, sid)) => {
                assert_eq!((pid.as_str(), sid), ("peer", 7));
            }
            Ok(other) => panic!("unexpected event: {other:?}"),
            Err(error) => panic!("the re-armed last writer must emit MaybeComplete: {error}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "exactly one MaybeComplete after reset"
        );
    }

    /// Both sides observe the completed state (file-end stored end_seen, then
    /// the last writer drained and read it, then file-end read zero inflight).
    /// Only the claim CAS may emit MaybeComplete.
    #[test]
    fn file_end_and_last_writer_emit_one_maybe_complete_when_both_see_zero() {
        let inflight = Arc::new(AtomicI64::new(1));
        let end_seen = Arc::new(AtomicBool::new(false));
        let completion = Arc::new(crate::recv::CompletionGate::default());
        let (tx, mut rx) = mpsc::unbounded_channel();

        // File-end's store half lands, but its inflight load has not run yet.
        end_seen.store(true, Ordering::SeqCst);
        // The last writer drains and sees end_seen: it claims the one event.
        drop(completion_writer(&inflight, &end_seen, &completion, tx));
        match rx.try_recv() {
            Ok(Ev::MaybeComplete(pid, sid)) => {
                assert_eq!((pid.as_str(), sid), ("peer", 7));
            }
            Ok(other) => panic!("unexpected event: {other:?}"),
            Err(error) => panic!("the last writer must emit MaybeComplete: {error}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one MaybeComplete");
        // File-end's load half now observes zero too; the claim CAS must make
        // it defer instead of processing a second completion.
        assert!(!completion.file_end(&inflight, &end_seen));
        assert!(rx.try_recv().is_err(), "the late file-end cannot duplicate");
    }

    #[derive(Default)]
    struct SyncTestTransport;

    #[async_trait::async_trait]
    impl filament_transport::net::Transport for SyncTestTransport {
        async fn send_control(&self, _msg: &Value) -> anyhow::Result<()> {
            Ok(())
        }
        async fn send_frame(&self, _sid: u32, _offset: u64, _payload: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        async fn flush(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn max_payload(&self) -> usize {
            64 * 1024
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[cfg(feature = "mount-server")]
    fn sync_server(
        stream: tokio::sync::mpsc::Receiver<Option<bytes::Bytes>>,
    ) -> crate::sync::serving::SyncServeTask {
        let transport: Arc<dyn filament_transport::net::Transport> = Arc::new(SyncTestTransport);
        let mux = crate::l2::Mux::new(transport.clone(), Arc::new(NoHost));
        crate::sync::serving::spawn_sync_server(crate::sync::serving::SyncServeConfig {
            transport,
            mux,
            sid: 0x8000_0101,
            root: std::env::temp_dir(),
            delete: false,
            dry_run: false,
            stream,
            max_record_bytes: crate::sync::MAX_SYNC_RECORD_BYTES,
            finalization_gate: None,
            staging_gate: None,
        })
    }

    #[tokio::test]
    async fn finished_per_open_tasks_are_reaped_while_live_ones_stay_owned() {
        let mut tasks = crate::recv::lifecycle::Tasks::default();
        for _ in 0..32 {
            tasks.push(tokio::spawn(async {}));
        }
        let (live_tx, live_rx) = tokio::sync::oneshot::channel::<()>();
        tasks.push(tokio::spawn(async move {
            let _ = live_rx.await;
        }));
        let _keep_live = live_tx;
        tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.len() > 1 {
                tasks.reap(&NoLog).await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finished tasks are reaped");
        assert_eq!(tasks.len(), 1);
        tasks.stop().await;
        assert_eq!(tasks.len(), 0);
    }

    struct FakeStdin {
        stopped: Arc<AtomicBool>,
        joined: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl crate::recv::ports::StdinOwner for FakeStdin {
        fn stop(&mut self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
        fn join(&mut self) -> crate::recv::ports::StdinOutcome {
            self.joined.store(true, Ordering::SeqCst);
            match self.handle.take().map(|h| h.join()) {
                Some(Ok(())) => crate::recv::ports::StdinOutcome::Joined,
                Some(Err(_)) => crate::recv::ports::StdinOutcome::Detached("fake panic"),
                None => crate::recv::ports::StdinOutcome::NotStarted,
            }
        }
    }

    #[tokio::test]
    async fn cleanup_stops_and_joins_an_active_stdin_sender() {
        let stopped = Arc::new(AtomicBool::new(false));
        let joined = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stop_thread = stopped.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                if tx.send(Ev::StdinLine("tick".into())).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        // The sender is provably active before cleanup starts.
        tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("active sender")
            .expect("an event");
        let mut cleanup = RecvCleanup {
            stdin: Some(Box::new(FakeStdin {
                stopped: stopped.clone(),
                joined: joined.clone(),
                handle: Some(handle),
            })),
            ..RecvCleanup::default()
        };
        cleanup.finish(&NoLog).await;
        assert!(stopped.load(Ordering::SeqCst), "stop before join");
        assert!(joined.load(Ordering::SeqCst), "join completed");
        assert_eq!(
            cleanup.stdin_outcome,
            crate::recv::ports::StdinOutcome::Joined
        );
        while rx.try_recv().is_ok() {}
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(rx.try_recv().is_err(), "no StdinLine after stop+join");
    }

    #[cfg(feature = "mount-server")]
    #[tokio::test]
    async fn sync_task_reaping_and_cleanup_join_owned_servers() {
        let (finished_tx, finished_rx) = tokio::sync::mpsc::channel(1);
        drop(finished_tx);
        let mut cleanup = RecvCleanup::default();
        let sync_tasks = cleanup.sync_tasks.clone();
        sync_tasks
            .track_sync_task(
                "peer-finished".into(),
                0x8000_0101,
                SyncTask(sync_server(finished_rx)),
                &NoLog,
            )
            .await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while !sync_tasks
                .0
                .lock()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closed sync stream completes its server");
        sync_tasks.reap_sync_tasks(&NoLog).await;
        assert!(
            sync_tasks.0.lock().unwrap().is_empty(),
            "completed owner is joined and removed"
        );

        let (_cancel_tx, cancel_rx) = tokio::sync::mpsc::channel(1);
        sync_tasks
            .track_sync_task(
                "peer-revoked".into(),
                0x8000_0102,
                SyncTask(sync_server(cancel_rx)),
                &NoLog,
            )
            .await;
        let (_survivor_tx, survivor_rx) = tokio::sync::mpsc::channel(1);
        sync_tasks
            .track_sync_task(
                "peer-live".into(),
                0x8000_0103,
                SyncTask(sync_server(survivor_rx)),
                &NoLog,
            )
            .await;
        sync_tasks.cancel_sync_for_pid("peer-revoked", &NoLog).await;
        assert!(
            sync_tasks
                .0
                .lock()
                .unwrap()
                .contains_key(&("peer-live".into(), 0x8000_0103)),
            "peer teardown must not cancel another peer's stream"
        );
        sync_tasks.stop_sync_tasks(&NoLog).await;
        assert!(
            sync_tasks.0.lock().unwrap().is_empty(),
            "shutdown cancels, joins, and drains owners"
        );
    }
}

#[cfg(test)]
mod peer_step_tests {
    use super::*;
    use crate::host::NoLog;

    /// The daemon survives a peer's failure: the step is skipped, not the loop.
    #[test]
    fn daemon_skips_a_failed_peer_step() {
        let r: Result<bool> = Err(anyhow::anyhow!("ICE config: no answer within 3s"));
        assert!(matches!(
            peer_step(true, "p1", "adoption", r, &NoLog),
            Ok(None)
        ));
    }

    /// A one-shot receive still fails, with the very error it met (no added
    /// context: the exit-code taxonomy classifies on that text).
    #[test]
    fn one_shot_keeps_the_error_unchanged() {
        let r: Result<bool> = Err(anyhow::anyhow!("ICE config: no answer within 3s"))
            .context("direct fallback adoption failed for peer p1 on receive path");
        let e = peer_step(false, "p1", "adoption", r, &NoLog).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "direct fallback adoption failed for peer p1 on receive path: ICE config: no answer within 3s"
        );
    }

    /// The daemon's skip line goes to the injected sink, not to a terminal.
    #[test]
    fn a_skipped_step_is_logged_to_the_sink() {
        let log = crate::host::VecLog::new();
        let r: Result<bool> = Err(anyhow::anyhow!("ICE config: no answer within 3s"));
        assert!(matches!(
            peer_step(true, "p1", "adoption", r, &log),
            Ok(None)
        ));
        let lines = log.take();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, crate::host::Level::Debug);
        assert!(
            lines[0]
                .1
                .contains("PEER-STEP-FAILED peer=p1 step=adoption"),
            "{:?}",
            lines[0].1
        );
    }

    /// Success passes the value through in both modes.
    #[test]
    fn success_passes_through() {
        assert!(matches!(
            peer_step(true, "p1", "adoption", Ok(true), &NoLog),
            Ok(Some(true))
        ));
        assert!(matches!(
            peer_step(false, "p1", "adoption", Ok(false), &NoLog),
            Ok(Some(false))
        ));
    }
}

#[cfg(test)]
mod front_question_tests {
    use super::*;
    use crate::host::{Level, VecLog};
    use crate::present::NoScreen;

    /// A presentation with no screen must not let a pending question vanish.
    /// Unless the caller already printed its permanent copy, the question goes
    /// to the sink; the ask path itself is untouched, so it still waits.
    #[test]
    fn an_unfronted_question_reaches_the_sink_once() {
        let log = VecLog::new();
        front_question(&NoScreen, &log, "keep x? [y/n]", false);
        assert_eq!(
            log.take(),
            vec![(Level::Critical, "keep x? [y/n]".to_string())]
        );

        front_question(&NoScreen, &log, "keep x? [y/n]", true);
        assert!(
            log.take().is_empty(),
            "the caller's permanent line already carried the question"
        );
    }
}

#[cfg(test)]
mod settle_tests {
    use super::*;

    #[test]
    fn park_budget_bounds() {
        // Empty: park.
        assert!(park_budget_ok(0, 0));
        // Room: park.
        assert!(park_budget_ok(1, 31));
        // Per-link cap (2): third concurrent open on the same link denies.
        assert!(!park_budget_ok(2, 2));
        // Per-daemon cap (32): the 33rd concurrent open denies.
        assert!(!park_budget_ok(0, 32));
        assert!(!park_budget_ok(1, 32));
    }

    /// Every sweep arm: the release condition, and each way a hold goes
    /// stale. Pure, so these are exhaustive and clock-free. The record is
    /// what stops a later edit from widening "fire" (e.g. dropping the
    /// generation check) without noticing.
    #[test]
    fn sweep_arms_cover_fire_and_each_stale_way() {
        use cap::BindingStrength as B;
        let now = Instant::now();
        let past = now + Duration::from_secs(3);
        let deadline = now + Duration::from_secs(2);
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        // Same link generation, same key, Proven -> release.
        assert!(matches!(
            sweep_arm(key_a, 7, Some((B::Proven, Some(key_a), 7)), now, deadline),
            SweepArm::Fire
        ));
        // Not proven yet, deadline ahead -> keep waiting.
        assert!(matches!(
            sweep_arm(key_a, 7, Some((B::Inferred, Some(key_a), 7)), now, deadline),
            SweepArm::Keep
        ));
        assert!(matches!(
            sweep_arm(key_a, 7, Some((B::None, None, 7)), now, deadline),
            SweepArm::Keep
        ));
        // Deadline passed -> expire (denied at the bound).
        assert!(matches!(
            sweep_arm(
                key_a,
                7,
                Some((B::Inferred, Some(key_a), 7)),
                past,
                deadline
            ),
            SweepArm::Expired
        ));
        // A different key on the link -> the peer re-keyed.
        assert!(matches!(
            sweep_arm(key_a, 7, Some((B::Proven, Some(key_b), 7)), now, deadline),
            SweepArm::IdentityChanged
        ));
        // Same key, NEWER generation -> replaced. This is the case a
        // pid+key-only hold got wrong: it would have fired into a transport
        // that never carried the challenge, or closed a stranger's sid.
        assert!(matches!(
            sweep_arm(key_a, 7, Some((B::Proven, Some(key_a), 8)), now, deadline),
            SweepArm::Replaced
        ));
        // No link -> dropped.
        assert!(matches!(
            sweep_arm(key_a, 7, None, now, deadline),
            SweepArm::Dropped
        ));
    }

    /// A hold must expire on its own deadline: the settle re-drive installs
    /// one and spawns a removal timer, and the pure rule behind both is this.
    #[test]
    fn challenge_hold_expires_at_its_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(20);
        assert!(!hold_expired(deadline, now));
        assert!(!hold_expired(deadline, now + Duration::from_secs(19)));
        assert!(hold_expired(deadline, deadline));
        assert!(hold_expired(deadline, deadline + Duration::from_secs(1)));
    }

    #[test]
    fn settle_timeout_reason_names_the_bound() {
        let r = settle_timeout_reason(2000);
        assert!(r.contains("2000"), "reason must name the bound: {r}");
        assert!(r.contains("retry"), "reason must offer the retry: {r}");
    }
}

#[cfg(test)]
mod expiry_redrive_tests {
    use super::{deny_is_proof_attributable, policy_decline_msg};
    use filament_cap::capability as cap;

    /// The lab defect: an exec denied because the guest's invitation had ended
    /// was parked "for identity proof", then RE-DRIVEN and run once the peer
    /// proved its key. A proof can only supply proof; a decision it cannot
    /// change must keep its verdict.
    #[test]
    fn the_redrive_never_overturns_a_final_deny() {
        for reason in [
            crate::refusal::expired_reason(1_760_000_000),
            crate::refusal::CEILING_REASON.to_string(),
            cap::REVOKED_REASON.to_string(),
            "device revoked".to_string(),
            "shell revoked for 'b' here".to_string(),
            "explicitly denied by owner (deniedCaps)".to_string(),
            crate::refusal::UNRECOGNIZED_REASON.to_string(),
        ] {
            assert!(
                !deny_is_proof_attributable(&reason),
                "parked a final deny: {reason}"
            );
        }
    }

    /// The settle path still exists for what it was built for: a deny that is
    /// about the binding not being proven yet.
    #[test]
    fn a_deny_about_missing_proof_still_parks() {
        for reason in [
            "identity not proven",
            "fleet device: action needs an explicit grant (deliberate tier or out of scope)",
            "device not granted shell",
            "no shell cap / untrusted",
        ] {
            assert!(
                deny_is_proof_attributable(reason),
                "refused to park: {reason}"
            );
        }
    }

    /// A send refused for a known cause carries it, so the sender can say
    /// "access expired at ..." instead of a bare "declined".
    #[test]
    fn a_policy_decline_carries_its_reason() {
        let r = crate::refusal::expired_reason(1_760_000_000);
        let m = policy_decline_msg("x", Some(&r));
        assert_eq!(m["type"], "file-decline");
        assert_eq!(m["reason"], "expired");
        assert!(m["error"]
            .as_str()
            .unwrap()
            .starts_with("access expired at"));
        let rv = policy_decline_msg("x", Some("device revoked"));
        assert_eq!(rv["reason"], "cert-revoked");
        // A person's plain no (or an unknown reason) stays a plain decline.
        assert!(policy_decline_msg("x", None).get("reason").is_none());
        assert!(policy_decline_msg("x", Some("unverified peer"))
            .get("reason")
            .is_none());
    }
}

#[cfg(test)]
mod inventory {
    use serde_json::json;

    /// The receive loop's regression suite moved with the loop. Names are part
    /// of the contract: a relocation that silently drops one (or a suite) must
    /// fail here, not be hidden by unrelated new tests elsewhere.
    const RECEIVE_LOOP_TESTS: &[&str] = &[
        "a_grant_or_last_revoke_is_announced_on_live_links",
        "older_version_only_when_no_peer_ran_a_ceremony",
        "a_code_is_consent_and_nothing_else_is",
        "the_receive_help_promises_what_the_code_path_does",
        "a_code_receive_ends_after_its_files_even_while_the_browser_stays_connected",
        "nothing_arrived_at_the_deadline_is_a_timeout",
        "a_received_file_beats_the_deadline",
        "no_deadline_means_no_deadline",
        "accepts_only_a_well_formed_sha256",
        "compares_digest_hex_case_insensitively_and_requires_a_digest",
        "driver_setup_failure_returns_without_a_process_exit",
        "the_library_engine_drives_the_real_receive_dispatch",
        "driver_pre_cancel_is_local_and_returns_after_cleanup",
        "cleanup_stops_a_started_watchdog_before_tasks_and_flush",
        "cancellation_then_cleanup_stops_a_started_watchdog",
        "cleanup_awaits_a_gated_blocking_writer_before_flush",
        "writer_reaping_joins_finished_tasks_and_keeps_running_ones",
        "verify_retry_joins_stream_writers_before_reset",
        "file_end_claims_after_the_last_writer_drained_first",
        "file_end_defers_to_the_last_writer_and_it_emits_once",
        "completion_gate_rearms_after_a_verify_retry",
        "file_end_and_last_writer_emit_one_maybe_complete_when_both_see_zero",
        "sync_task_reaping_and_cleanup_join_owned_servers",
        "daemon_skips_a_failed_peer_step",
        "one_shot_keeps_the_error_unchanged",
        "a_skipped_step_is_logged_to_the_sink",
        "success_passes_through",
        "an_unfronted_question_reaches_the_sink_once",
        "park_budget_bounds",
        "sweep_arms_cover_fire_and_each_stale_way",
        "challenge_hold_expires_at_its_deadline",
        "settle_timeout_reason_names_the_bound",
        "the_redrive_never_overturns_a_final_deny",
        "a_deny_about_missing_proof_still_parks",
        "a_policy_decline_carries_its_reason",
    ];

    #[test]
    fn unserved_forward_and_sync_opens_are_named_closes() {
        let forward = json!({ "type": "l2-open", "sid": 0x8000_0042u32 });
        let close = super::unserved_open_close(&forward, crate::refusal::TUNNEL_OFF_REASON)
            .expect("a valid forward sid must get a close");
        assert_eq!(close["type"], "l2-close");
        assert_eq!(close["sid"], 0x8000_0042u32);
        assert!(close["err"]
            .as_str()
            .is_some_and(|reason| reason.contains("tunnelling is off")));

        let sync = json!({ "type": "sync-open", "sid": 0x8000_0043u32 });
        let (sid, close) = crate::recv::servers::sync_unavailable_close(&sync)
            .expect("a valid sync sid must get a close");
        assert_eq!(sid, 0x8000_0043u32);
        assert_eq!(close["type"], "l2-close");
        assert!(close["err"]
            .as_str()
            .is_some_and(|reason| reason.contains("sync")));
    }

    #[test]
    fn unserved_mount_open_is_a_named_close_without_l2() {
        // A Core-like reduced host has l2_enabled=false. The mount-open arm
        // must still answer with a valid sid and a named reason.
        let open = json!({ "type": "mount-open", "sid": 0x8000_0041u32 });
        let close = super::unserved_open_close(&open, "mount serving is off in this core profile")
            .expect("a valid sid must get a close");
        assert_eq!(close["type"], "l2-close");
        assert_eq!(close["sid"], 0x8000_0041u32);
        assert!(close["err"]
            .as_str()
            .is_some_and(|reason| reason.contains("mount serving is off")));
        // A malformed open has no stream to close; it is not fabricated.
        assert!(super::unserved_open_close(&json!({ "type": "mount-open" }), "x").is_none());
    }

    #[test]
    fn fleet_presence_is_disabled_without_a_verifier() {
        #[cfg(not(feature = "fleet"))]
        assert!(!super::fleet_presence_allowed(true));
        #[cfg(feature = "fleet")]
        assert!(super::fleet_presence_allowed(true));
        assert!(!super::fleet_presence_allowed(false));
    }

    #[test]
    fn every_receive_loop_test_is_present_once() {
        let source = include_str!("dispatch.rs");
        assert_eq!(RECEIVE_LOOP_TESTS.len(), 35, "the base suite has 35 tests");
        let mut seen = std::collections::HashSet::new();
        for name in RECEIVE_LOOP_TESTS {
            assert!(seen.insert(*name), "duplicate inventory name {name}");
            let needle = format!("fn {name}(");
            assert!(
                source.matches(&needle).count() == 1,
                "receive-loop test {name} is missing or duplicated"
            );
        }
    }
}
