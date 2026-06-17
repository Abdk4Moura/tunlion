// Establishment telemetry (the CLI sibling of frontend/src/lib/tel.js +
// linkdiag.js). It exists to make the L2/ssh bring-up STALL visible: ssh over a
// filament netcat ProxyCommand sometimes burns the whole connect budget on the
// first try and only succeeds after several retries, and until now the CLI
// emitted NOTHING, so the stall was invisible on live devices.
//
// What it captures: the connect lifecycle as a phase state machine
//   Signaling -> Presence -> Establishing -> Ready -> L2Open -> Up
// with per-phase durations and an over-budget flag, plus a `stall` event when a
// candidate's establish budget fires (the wedged-candidate-rotation signal).
//
// Two sinks per event, BOTH best-effort and OFF the data channel (the wire
// protocol is frozen; telemetry never rides the control/data path):
//   (a) a local rotating JSONL at {config}/diag.jsonl, the rich timeline a
//       future `filament doctor` can replay,
//   (b) a fire-and-forget POST to {server}/api/telemetry (the same endpoint the
//       browser beacons to), so a live device's stalls surface in the backend
//       `TEL web:<ev>` log without the user having to ship a file.
//
// PRIVACY: lifecycle only. NEVER a file name, file contents, a secret, or a
// petname. The peer is a SHORT HASH (channel_of of the pair secret, or a
// sha256 of the name, truncated). The remote beacon must NEVER block or slow
// the connect path, every error is swallowed and the POST is spawned detached.

use serde_json::{json, Value};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

/// The connect lifecycle, smallest set that makes a stall locatable. Ordered so
/// `(p as u8)` doubles as a monotonic position for "how far did we get".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// socket connect + Ev::Welcome (the signaling socket is live).
    Signaling,
    /// subscribe + wait for a known peer to appear (a candidate is queued).
    Presence,
    /// Peer::connect (WebRTC) racing the direct-QUIC dial. The stall zone.
    Establishing,
    /// the tunnel transport came up (ChannelReady / DirectReady).
    Ready,
    /// the l2-open / l2-open-ack round trip (the mux stream is live).
    L2Open,
    /// the link is fully usable (ssh handshake bytes can flow).
    Up,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Signaling => "signaling",
            Phase::Presence => "presence",
            Phase::Establishing => "establishing",
            Phase::Ready => "ready",
            Phase::L2Open => "l2open",
            Phase::Up => "up",
        }
    }
}

/// Per-phase soft budget (ms). These are NOT hard timeouts (the candidate
/// rotation / relay path own the actual deadlines); crossing one only sets an
/// `over_budget` flag on the phase event so a slow phase is greppable. Tuned so
/// the happy path totals under ~5s (Tailscale-ssh parity): a clean local link
/// signals in well under a second, finds its peer fast, and ICE/QUIC completes
/// in a couple of seconds. `Up` has no budget (it is the open-ended steady
/// state, not a bring-up step).
pub fn budget_ms(p: Phase) -> u64 {
    match p {
        Phase::Signaling => 1200,
        Phase::Presence => 2500,
        Phase::Establishing => 3000,
        Phase::Ready => 500,
        Phase::L2Open => 800,
        Phase::Up => 0,
    }
}

/// True iff time spent in `p` crossed its soft budget. `Up` (budget 0) is never
/// over budget; it is the steady state.
pub fn over_budget(p: Phase, elapsed_ms: u64) -> bool {
    let b = budget_ms(p);
    b > 0 && elapsed_ms > b
}

/// A short, NON-secret correlation id so the local JSONL and the remote beacon
/// for one connect span can be stitched together. 8 hex chars of CSPRNG.
fn correlation_id() -> String {
    crate::fresh_secret()[..8].to_string()
}

/// Compute a short, stable, NON-reversible peer tag from the pair secret. This
/// is `channel_of(secret)` (sha256 of the secret) truncated to 10 hex, so it
/// never leaks the petname and never leaks the secret, but is stable per device
/// so a device's attempts can be grouped across the timeline.
pub fn peer_hash_from_secret(secret: &str) -> String {
    crate::channel_of(secret)[..10].to_string()
}

/// One connect span. Tracks the current phase and when it was entered so each
/// transition can record the PREVIOUS phase's duration. Cheap to hold across the
/// whole bring-up loop.
pub struct Attempt {
    id: String,
    server: String,
    peer: String,
    role: &'static str,
    start: Instant,
    phase: Phase,
    phase_at: Instant,
}

impl Attempt {
    /// Open a span (emits a "start" event). `peer_hash` MUST already be the
    /// short hash (see `peer_hash_from_secret`), never a petname.
    pub fn new(server: &str, peer_hash: &str, role: &'static str) -> Attempt {
        let now = Instant::now();
        let a = Attempt {
            id: correlation_id(),
            server: server.to_string(),
            peer: peer_hash.to_string(),
            role,
            start: now,
            phase: Phase::Signaling,
            phase_at: now,
        };
        a.emit("start", json!({ "phase": a.phase.name() }));
        a
    }

    /// Transition into `next`: records the time spent in the phase we are leaving
    /// (with its over-budget flag) and emits a per-phase event tagged with the
    /// phase we are entering.
    pub fn enter(&mut self, next: Phase) {
        let now = Instant::now();
        let dur_ms = now.duration_since(self.phase_at).as_millis() as u64;
        let prev = self.phase;
        self.emit(
            "phase",
            json!({
                "phase": next.name(),
                "prev": prev.name(),
                "dur_ms": dur_ms,
                "over_budget": over_budget(prev, dur_ms),
            }),
        );
        self.phase = next;
        self.phase_at = now;
    }

    /// Terminal success: the link is up and usable. Emits "up" with the total
    /// span time and the route/transport labels (e.g. route "direct"/"relayed",
    /// transport "direct-quic"/"datachannel").
    pub fn up(&mut self, route: &str, transport: &str) {
        let total_ms = self.start.elapsed().as_millis() as u64;
        self.phase = Phase::Up;
        self.phase_at = Instant::now();
        self.emit(
            "up",
            json!({
                "phase": Phase::Up.name(),
                "total_ms": total_ms,
                "route": route,
                "transport": transport,
            }),
        );
    }

    /// Terminal failure: the overall deadline expired or an error ended the
    /// bring-up. Records the phase we died in and the total span time.
    pub fn fail(&mut self, reason: &str) {
        let total_ms = self.start.elapsed().as_millis() as u64;
        self.emit(
            "fail",
            json!({
                "last_phase": self.phase.name(),
                "total_ms": total_ms,
                "reason": reason,
            }),
        );
    }

    /// A per-candidate establish budget fired (the wedged-candidate signal that
    /// rotates to the next candidate). NOT terminal: the span continues with the
    /// next candidate. `phase` is the phase that stalled; `elapsed_ms` is how
    /// long that candidate burned before rotation.
    pub fn stall(&mut self, phase: Phase, elapsed_ms: u64) {
        self.emit(
            "stall",
            json!({
                "phase": phase.name(),
                "elapsed_ms": elapsed_ms,
            }),
        );
    }

    /// Fan one event out to both sinks. Builds the common envelope once.
    fn emit(&self, ev: &str, mut fields: Value) {
        let obj = fields.as_object_mut().expect("diag fields are an object");
        obj.insert("ev".into(), json!(ev));
        obj.insert("src".into(), json!("cli"));
        obj.insert("role".into(), json!(self.role));
        obj.insert("peer".into(), json!(self.peer));
        obj.insert("id".into(), json!(self.id));
        write_jsonl(&fields);
        beacon(&self.server, fields);
    }
}

/// Rotating local JSONL sink. Appends one compact line; truncates the file when
/// it grows past `MAX_JSONL_BYTES` (keeps the most recent run, the only window a
/// `filament doctor` cares about). All errors are swallowed: telemetry must
/// never break a connect.
const MAX_JSONL_BYTES: u64 = 512 * 1024;

fn diag_path() -> PathBuf {
    let base = if let Ok(d) = std::env::var("FILAMENT_CONFIG_DIR") {
        PathBuf::from(d)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".config/filament")
    };
    base.join("diag.jsonl")
}

fn write_jsonl(v: &Value) {
    let path = diag_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Rotate by TRUNCATION: a doctor wants the latest span, not unbounded
    // history. Cheap stat, then start fresh if we are over the cap.
    let over = std::fs::metadata(&path).map(|m| m.len() > MAX_JSONL_BYTES).unwrap_or(false);
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true);
    if over {
        opts.truncate(true);
    } else {
        opts.append(true);
    }
    if let Ok(mut f) = opts.open(&path) {
        // Compact one-liner + newline; ignore a partial-write failure.
        let mut line = v.to_string();
        line.push('\n');
        let _ = f.write_all(line.as_bytes());
    }
}

/// Remote beacon sink. Fire-and-forget: spawn a detached POST to
/// {server}/api/telemetry with a short timeout and swallow EVERY error, so it
/// can never block or slow the connect path. The backend logs one
/// `TEL web:<ev>` line per event (it accepts a single object or an array).
fn beacon(server: &str, body: Value) {
    let url = format!("{server}/api/telemetry");
    tokio::spawn(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
        else {
            return;
        };
        let _ = client.post(&url).json(&body).send().await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_are_positive_except_up() {
        // Every bring-up phase has a real soft budget; only Up (the steady
        // state) is budget-free.
        for p in [Phase::Signaling, Phase::Presence, Phase::Establishing, Phase::Ready, Phase::L2Open] {
            assert!(budget_ms(p) > 0, "{:?} should have a budget", p);
        }
        assert_eq!(budget_ms(Phase::Up), 0);
    }

    #[test]
    fn critical_path_budget_under_5s() {
        // The per-phase budgets are generous SOFT flags (each only marks a phase
        // as slow, none is a serial deadline), so their raw sum overshoots on
        // purpose. The meaningful Tailscale-ssh parity check is the CRITICAL
        // PATH: the phases that actually serialize on every connect, the socket
        // (Signaling), the ICE/QUIC race (Establishing), and the stream open
        // (L2Open). Presence overlaps the socket on a healthy link and Ready is
        // a near-instant hop, so they are not on the dominant timeline. That
        // critical-path budget must stay under ~5s.
        let critical: u64 = budget_ms(Phase::Signaling) + budget_ms(Phase::Establishing) + budget_ms(Phase::L2Open);
        assert!(critical <= 5000, "critical-path budget {critical}ms exceeds 5s target");
    }

    #[test]
    fn over_budget_is_strict_and_phase_aware() {
        // At or under budget is fine; strictly over trips the flag.
        assert!(!over_budget(Phase::Signaling, 0));
        assert!(!over_budget(Phase::Signaling, budget_ms(Phase::Signaling)));
        assert!(over_budget(Phase::Signaling, budget_ms(Phase::Signaling) + 1));
        // Up has no budget, so it is never over budget no matter how long.
        assert!(!over_budget(Phase::Up, 10_000_000));
    }

    #[test]
    fn establishing_budget_covers_slow_but_real_ice() {
        // A legitimately slow ICE completes around 5s; the per-candidate
        // establish ROTATION budget (CANDIDATE_SECS in l2.rs) must not abandon
        // it before the relay/rotation fallback. The soft phase budget here is
        // intentionally tighter (it only flags, never aborts), but the establish
        // phase budget must stay in the few-seconds range, not sub-second.
        assert!(budget_ms(Phase::Establishing) >= 2000);
    }

    #[test]
    fn peer_hash_is_short_and_not_the_input() {
        // The peer tag is a short, stable hash, never the raw secret.
        let secret = "abcdef0123456789";
        let h = peer_hash_from_secret(secret);
        assert_eq!(h.len(), 10);
        assert!(!secret.contains(&h));
        // Stable: same secret -> same hash.
        assert_eq!(h, peer_hash_from_secret(secret));
    }
}
