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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
    /// Per-phase durations recorded as each phase is LEFT (via `enter`/`up`), so
    /// an in-process reader (the `doctor` probe) can read the same phase ladder
    /// the JSONL records, WITHOUT re-parsing the file. `doctor` is the consumer;
    /// the live connect paths simply never read it. Ordered by completion.
    timings: Vec<PhaseTiming>,
}

/// One completed phase of a connect span: which phase, how long it took, and
/// whether it crossed its soft budget. The unit the `doctor` phase ladder is
/// rendered from (it mirrors the `phase`/`up` JSONL events exactly).
#[derive(Clone, Copy, Debug)]
pub struct PhaseTiming {
    pub phase: Phase,
    pub dur_ms: u64,
    pub over_budget: bool,
}

impl Phase {
    /// Public, stable label for a phase (the ladder column + the JSONL `phase`
    /// field share this). Re-exposes the private `name` for `doctor`.
    pub fn label(self) -> &'static str {
        self.name()
    }
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
            timings: Vec::new(),
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
        let ob = over_budget(prev, dur_ms);
        self.timings.push(PhaseTiming { phase: prev, dur_ms, over_budget: ob });
        self.emit(
            "phase",
            json!({
                "phase": next.name(),
                "prev": prev.name(),
                "dur_ms": dur_ms,
                "over_budget": ob,
            }),
        );
        self.phase = next;
        self.phase_at = now;
    }

    /// Terminal success: the link is up and usable. Emits "up" with the total
    /// span time and the route/transport labels (e.g. route "direct"/"relayed",
    /// transport "direct-quic"/"datachannel").
    pub fn up(&mut self, route: &str, transport: &str) {
        let now = Instant::now();
        // Record the duration of the phase we are leaving (typically L2Open) so
        // the ladder has its final rung; Up itself is the steady state, no timing.
        let dur_ms = now.duration_since(self.phase_at).as_millis() as u64;
        let prev = self.phase;
        if prev != Phase::Up {
            self.timings.push(PhaseTiming { phase: prev, dur_ms, over_budget: over_budget(prev, dur_ms) });
        }
        let total_ms = self.start.elapsed().as_millis() as u64;
        self.phase = Phase::Up;
        self.phase_at = now;
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

    /// The per-phase ladder recorded so far (one entry per phase LEFT, in order).
    /// `doctor`'s probe reads this after the bring-up to render the phase ladder
    /// from the SAME timings/budgets a live connect records.
    pub fn timings(&self) -> &[PhaseTiming] {
        &self.timings
    }

    /// Total elapsed time on this span (start to now). Used as the probe's
    /// "healthy (total Xs)" figure.
    pub fn total_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
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

// ---------------------------------------------------------------- history ----
//
// `summarize` turns the passive JSONL telemetry into an instant local report:
// the last N connect spans, their median total time, the phase most often over
// budget, and the stall rate. This is what `filament doctor` (no device) prints
// under "history", the trail of what the live daemon's own connects looked like.

/// A digest of the recent connect spans in the local JSONL. All counts are over
/// the spans considered (`considered`), the most recent `limit` that reached a
/// terminal `up`/`fail` (a span with only a `start` and no terminal event is an
/// in-flight or crashed connect and is skipped).
#[derive(Debug, Default, Clone)]
pub struct Summary {
    /// How many terminal spans were folded in (<= the requested limit).
    pub considered: usize,
    /// How many of those ended in `up` (success).
    pub ups: usize,
    /// How many ended in `fail`.
    pub fails: usize,
    /// Median total_ms across the spans that recorded a total (up or fail).
    pub median_total_ms: Option<u64>,
    /// The phase seen over budget most often, with that count. `None` when no
    /// phase was ever over budget across the window.
    pub worst_phase: Option<(Phase, usize)>,
    /// How many spans recorded at least one `stall` event.
    pub spans_with_stall: usize,
}

/// Parse a phase label back to a `Phase` (the inverse of `Phase::label`). Used by
/// the history reader to fold JSONL `phase` fields into the worst-phase tally.
fn phase_from_label(s: &str) -> Option<Phase> {
    match s {
        "signaling" => Some(Phase::Signaling),
        "presence" => Some(Phase::Presence),
        "establishing" => Some(Phase::Establishing),
        "ready" => Some(Phase::Ready),
        "l2open" => Some(Phase::L2Open),
        "up" => Some(Phase::Up),
        _ => None,
    }
}

/// Read the local diag JSONL and digest the most recent `limit` terminal spans.
/// Reads from `{FILAMENT_CONFIG_DIR else ~/.config/filament}/diag.jsonl`. A
/// missing/empty file yields an all-zero `Summary` (a fresh install with no
/// history, not an error).
pub fn summarize(limit: usize) -> Summary {
    let path = diag_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    summarize_lines(&raw, limit)
}

/// The pure core of `summarize`: digest JSONL `text` (one event per line). Split
/// out so it is unit-testable without touching the filesystem.
pub fn summarize_lines(text: &str, limit: usize) -> Summary {
    // Group events by span id, preserving the order each span first appears so
    // "most recent" is by appearance in the file (the JSONL is append-ordered).
    let mut order: Vec<String> = Vec::new();
    let mut spans: std::collections::HashMap<String, SpanAcc> = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let id = match v["id"].as_str() {
            Some(i) => i.to_string(),
            None => continue,
        };
        let acc = spans.entry(id.clone()).or_insert_with(|| {
            order.push(id.clone());
            SpanAcc::default()
        });
        match v["ev"].as_str() {
            Some("phase") => {
                if v["over_budget"].as_bool().unwrap_or(false) {
                    if let Some(p) = v["prev"].as_str().and_then(phase_from_label) {
                        acc.over_budget_phases.push(p);
                    }
                }
            }
            Some("stall") => acc.had_stall = true,
            Some("up") => {
                acc.terminal = Some(Terminal::Up);
                acc.total_ms = v["total_ms"].as_u64();
            }
            Some("fail") => {
                acc.terminal = Some(Terminal::Fail);
                acc.total_ms = v["total_ms"].as_u64();
            }
            _ => {}
        }
    }

    // Keep only TERMINAL spans (reached up/fail), newest first, capped at `limit`.
    let mut terminal: Vec<&SpanAcc> = order
        .iter()
        .rev()
        .filter_map(|id| spans.get(id))
        .filter(|s| s.terminal.is_some())
        .take(limit)
        .collect();
    // `terminal` is newest-first; that ordering is all we need below.
    let considered = terminal.len();
    let ups = terminal.iter().filter(|s| matches!(s.terminal, Some(Terminal::Up))).count();
    let fails = terminal.iter().filter(|s| matches!(s.terminal, Some(Terminal::Fail))).count();
    let spans_with_stall = terminal.iter().filter(|s| s.had_stall).count();

    let mut totals: Vec<u64> = terminal.iter().filter_map(|s| s.total_ms).collect();
    totals.sort_unstable();
    let median_total_ms = median(&totals);

    // Tally which phase was over budget most often across the window.
    let mut tally: std::collections::HashMap<Phase, usize> = std::collections::HashMap::new();
    for s in terminal.iter_mut() {
        for p in &s.over_budget_phases {
            *tally.entry(*p).or_default() += 1;
        }
    }
    let worst_phase = tally
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(p, c)| (p, c));

    Summary { considered, ups, fails, median_total_ms, worst_phase, spans_with_stall }
}

/// Read back the MOST RECENT span's phase ladder + last phase from the JSONL.
/// The `doctor` probe uses this on a FAILED/timed-out establish (where the
/// `Attempt` was consumed by the erroring `bring_up_to_known`) to recover the
/// partial ladder it managed to record, so the verdict can name where it died.
/// Returns `(timings, last_phase)` for the latest span that has any events.
pub fn latest_span_ladder() -> Option<(Vec<PhaseTiming>, Phase)> {
    let raw = std::fs::read_to_string(diag_path()).ok()?;
    latest_span_ladder_lines(&raw)
}

/// Pure core of `latest_span_ladder` (testable without the filesystem).
pub fn latest_span_ladder_lines(text: &str) -> Option<(Vec<PhaseTiming>, Phase)> {
    // Find the id of the LAST span to appear (the most recent connect).
    let mut last_id: Option<String> = None;
    for line in text.lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
            if let Some(id) = v["id"].as_str() {
                if last_id.as_deref() != Some(id) {
                    last_id = Some(id.to_string());
                }
            }
        }
    }
    let id = last_id?;
    // Replay that span's phase events into a ladder + track the deepest phase.
    let mut timings = Vec::new();
    let mut last_phase = Phase::Signaling;
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        if v["id"].as_str() != Some(id.as_str()) {
            continue;
        }
        match v["ev"].as_str() {
            Some("phase") => {
                if let Some(prev) = v["prev"].as_str().and_then(phase_from_label) {
                    let dur_ms = v["dur_ms"].as_u64().unwrap_or(0);
                    timings.push(PhaseTiming { phase: prev, dur_ms, over_budget: over_budget(prev, dur_ms) });
                }
                if let Some(p) = v["phase"].as_str().and_then(phase_from_label) {
                    last_phase = p;
                }
            }
            Some("fail") => {
                if let Some(p) = v["last_phase"].as_str().and_then(phase_from_label) {
                    last_phase = p;
                }
            }
            Some("up") => last_phase = Phase::Up,
            _ => {}
        }
    }
    Some((timings, last_phase))
}

/// Median of a SORTED slice. Even-length takes the lower-middle (a stable,
/// integer-only choice, no averaging that would invent a non-observed value).
fn median(sorted: &[u64]) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    Some(sorted[(sorted.len() - 1) / 2])
}

#[derive(Default)]
struct SpanAcc {
    terminal: Option<Terminal>,
    total_ms: Option<u64>,
    over_budget_phases: Vec<Phase>,
    had_stall: bool,
}

enum Terminal {
    Up,
    Fail,
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

    fn line(id: &str, ev: &str, extra: &str) -> String {
        if extra.is_empty() {
            format!(r#"{{"id":"{id}","ev":"{ev}"}}"#)
        } else {
            format!(r#"{{"id":"{id}","ev":"{ev}",{extra}}}"#)
        }
    }

    #[test]
    fn summarize_empty_is_all_zero() {
        let s = summarize_lines("", 10);
        assert_eq!(s.considered, 0);
        assert_eq!(s.ups, 0);
        assert_eq!(s.fails, 0);
        assert!(s.median_total_ms.is_none());
        assert!(s.worst_phase.is_none());
        assert_eq!(s.spans_with_stall, 0);
    }

    #[test]
    fn summarize_counts_ups_fails_and_median() {
        // Three terminal spans: two up (1000ms, 3000ms), one fail (5000ms).
        let mut text = String::new();
        text += &line("a", "start", "");
        text.push('\n');
        text += &line("a", "up", r#""total_ms":1000"#);
        text.push('\n');
        text += &line("b", "up", r#""total_ms":3000"#);
        text.push('\n');
        text += &line("c", "fail", r#""total_ms":5000"#);
        text.push('\n');
        let s = summarize_lines(&text, 10);
        assert_eq!(s.considered, 3);
        assert_eq!(s.ups, 2);
        assert_eq!(s.fails, 1);
        // Sorted totals [1000,3000,5000] -> lower-middle median = 3000.
        assert_eq!(s.median_total_ms, Some(3000));
    }

    #[test]
    fn summarize_skips_in_flight_spans() {
        // A span with only a `start` (no up/fail) is in-flight, not counted.
        let text = format!("{}\n", line("x", "start", ""));
        let s = summarize_lines(&text, 10);
        assert_eq!(s.considered, 0);
    }

    #[test]
    fn summarize_finds_worst_phase_and_stall_rate() {
        // Two spans over budget on `establishing`, one on `presence`; one stall.
        let mut text = String::new();
        // span a: establishing over budget, has a stall, terminal up
        text += &line("a", "phase", r#""prev":"establishing","over_budget":true"#);
        text.push('\n');
        text += &line("a", "stall", r#""phase":"establishing""#);
        text.push('\n');
        text += &line("a", "up", r#""total_ms":4000"#);
        text.push('\n');
        // span b: establishing over budget, terminal up
        text += &line("b", "phase", r#""prev":"establishing","over_budget":true"#);
        text.push('\n');
        text += &line("b", "up", r#""total_ms":4200"#);
        text.push('\n');
        // span c: presence over budget, terminal fail
        text += &line("c", "phase", r#""prev":"presence","over_budget":true"#);
        text.push('\n');
        text += &line("c", "fail", r#""total_ms":9000"#);
        text.push('\n');
        let s = summarize_lines(&text, 10);
        assert_eq!(s.considered, 3);
        assert_eq!(s.spans_with_stall, 1);
        let (p, c) = s.worst_phase.expect("a worst phase");
        assert_eq!(p, Phase::Establishing);
        assert_eq!(c, 2);
    }

    #[test]
    fn summarize_limit_keeps_newest() {
        // Four terminal spans; limit 2 keeps the LAST two by file order (c,d).
        let mut text = String::new();
        for (id, t) in [("a", 100u64), ("b", 200), ("c", 300), ("d", 400)] {
            text += &line(id, "up", &format!(r#""total_ms":{t}"#));
            text.push('\n');
        }
        let s = summarize_lines(&text, 2);
        assert_eq!(s.considered, 2);
        // Newest two totals are [300,400]; lower-middle median = 300.
        assert_eq!(s.median_total_ms, Some(300));
    }

    #[test]
    fn median_handles_odd_even_empty() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[5]), Some(5));
        assert_eq!(median(&[1, 2, 3]), Some(2));
        assert_eq!(median(&[1, 2, 3, 4]), Some(2)); // lower-middle
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
