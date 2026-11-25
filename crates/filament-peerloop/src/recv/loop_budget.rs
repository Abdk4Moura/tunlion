//! Per-iteration busy budget for the daemon event loop (test-hooks builds).
//!
//! The loop watchdog (`lifecycle::observe`) only sees an iteration that never
//! ends: it warns at 20 s and exits at 120 s. The bug class it was built for,
//! an await parked in the loop on something the network decides (a webrtc-rs
//! lock held across an SCTP handshake, a signaling ack, a peer's flush), mostly
//! shows up shorter than that: the loop parks for 2, 5 or 30 s and then goes on.
//! Nothing noticed those unless a fault schedule made them long.
//!
//! This measures how long one iteration was BUSY: the time from the top of the
//! loop to the next top, minus the time spent waiting in the main `select!` for
//! the next event (idle is not a defect). Healthy handlers finish in
//! milliseconds (the `LOOP-BEAT` gate measures whole iterations, idle wait
//! included, in tens of ms on a loaded runner), so a busy iteration of a full
//! second means the loop was waiting on something it should not own. Each
//! busy stretch is labelled by phase and by the event or control request being
//! handled, so the report names the handler without per-await instrumentation.
//!
//! Every test-hooks build reports an over-budget iteration with one line that
//! starts with [`MARKER`]; `TUNLION_TEST_LOOP_BUDGET_PANIC=1` also panics, so
//! whatever test happens to exercise a parked await fails loudly. The dispatch
//! reaches this only through `test_hooks::LoopBudget`, which is an empty
//! zero-cost type in a build without the `test-hooks` feature.
//!
//! A permanently parked await never finishes its iteration, so it is never
//! reported here; that case stays with the loop watchdog.
//!
//! A whole-process pause (SIGSTOP, which several gates and the chaos fuzzer
//! inject on purpose; a VM freeze) is not a parked await, and the monotonic
//! clock keeps running through it. A [`PauseClock`] thread that beats every
//! 50 ms tells the two apart: an iteration during which that thread also
//! missed its beats by more than [`PAUSE_SLACK`] was frozen from outside and
//! is not judged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::host::LogSink;

/// The stable prefix of the report line. Log scanners (gate scripts, the chaos
/// fuzzer's oracles) match this exact string.
pub const MARKER: &str = "LOOP-BUDGET-EXCEEDED";

/// The busy budget of one loop iteration. Healthy handlers take milliseconds;
/// see the module docs. Not configurable: a trip is a finding, not a tuning
/// knob.
pub const BUDGET: Duration = Duration::from_secs(1);

/// Env var that turns a report into a panic (test-hooks builds only).
pub const PANIC_ENV: &str = "TUNLION_TEST_LOOP_BUDGET_PANIC";

/// Env var naming a file every report is also appended to, with the pid. CI
/// sets one per job and fails the job if it is not empty at the end, so a trip
/// counts even where a harness swallows the daemon's output or its panic.
pub const RECORD_ENV: &str = "TUNLION_TEST_LOOP_BUDGET_RECORD";

/// One over-budget iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exceeded {
    /// Busy time of the whole iteration.
    pub busy: Duration,
    /// The phase of the longest busy stretch (`handler`, `ctl`, `periodic`...).
    pub phase: &'static str,
    /// The event or control request being handled in that iteration.
    pub event: &'static str,
    /// Finer detail where cheap (a control message's `type`).
    pub detail: Option<String>,
    /// Length of the longest single busy stretch.
    pub slowest: Duration,
    pub budget: Duration,
}

impl Exceeded {
    /// `<phase>/<event>[:<detail>]`, the handler label.
    pub fn label(&self) -> String {
        match &self.detail {
            Some(d) => format!("{}/{}:{}", self.phase, self.event, d),
            None => format!("{}/{}", self.phase, self.event),
        }
    }

    /// `LOOP-BUDGET-EXCEEDED <busy_ms> <label> slowest_ms=<n> budget_ms=<n>`.
    pub fn line(&self) -> String {
        format!(
            "{MARKER} {} {} slowest_ms={} budget_ms={}",
            self.busy.as_millis(),
            self.label(),
            self.slowest.as_millis(),
            self.budget.as_millis()
        )
    }
}

const NO_EVENT: &str = "none";

/// How often the pause clock beats.
const BEAT: Duration = Duration::from_millis(50);
/// A beat this much later than scheduled means the whole process was paused.
pub const PAUSE_SLACK: Duration = Duration::from_millis(300);

/// Detects whole-process pauses: a thread that beats every [`BEAT`] and adds
/// up the time by which its beats came late beyond [`PAUSE_SLACK`].
#[derive(Debug)]
pub struct PauseClock {
    base: Instant,
    last_beat_ms: AtomicU64,
    paused_ms: AtomicU64,
}

impl PauseClock {
    /// A clock with no thread; `beat` drives it (tests).
    pub fn manual() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            last_beat_ms: AtomicU64::new(0),
            paused_ms: AtomicU64::new(0),
        })
    }

    /// The process-wide clock, its beating thread started on first use.
    pub fn global() -> Option<Arc<Self>> {
        static CLOCK: OnceLock<Option<Arc<PauseClock>>> = OnceLock::new();
        CLOCK
            .get_or_init(|| {
                let clock = Self::manual();
                let beating = Arc::clone(&clock);
                std::thread::Builder::new()
                    .name("loop-budget-pause".into())
                    .spawn(move || loop {
                        std::thread::sleep(BEAT);
                        beating.beat();
                    })
                    .ok()
                    .map(|_| clock)
            })
            .clone()
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// One beat: a gap past `BEAT + PAUSE_SLACK` since the last is a pause.
    pub fn beat(&self) {
        let now = self.now_ms();
        let last = self.last_beat_ms.swap(now, Ordering::Relaxed);
        let gap = now.saturating_sub(last);
        let late = (BEAT + PAUSE_SLACK).as_millis() as u64;
        if gap > late {
            self.paused_ms.fetch_add(gap - BEAT.as_millis() as u64, Ordering::Relaxed);
        }
    }

    /// Total paused time seen so far, for before/after comparison.
    fn paused_ms(&self) -> u64 {
        self.paused_ms.load(Ordering::Relaxed)
    }

    /// The beating thread has not run for longer than a pause would allow:
    /// the process has just resumed and the thread has not caught up yet.
    fn stale(&self) -> bool {
        let late = (BEAT + PAUSE_SLACK).as_millis() as u64;
        self.now_ms().saturating_sub(self.last_beat_ms.load(Ordering::Relaxed)) > late
    }
}

/// The measuring state for one loop. `enter` starts (or switches to) a busy
/// stretch, `idle` ends it (the loop is about to wait for an event), and
/// `finish` closes the iteration and judges it.
#[derive(Debug)]
pub struct IterationBudget {
    budget: Duration,
    panic: bool,
    record: Option<std::path::PathBuf>,
    open: Option<(Instant, &'static str, u64)>,
    clock: Option<Arc<PauseClock>>,
    /// The iteration overlapped a whole-process pause: not judged.
    paused: bool,
    busy: Duration,
    slowest: Duration,
    slowest_phase: &'static str,
    event: &'static str,
    detail: Option<String>,
}

impl IterationBudget {
    pub fn new(budget: Duration, panic: bool, clock: Option<Arc<PauseClock>>) -> Self {
        Self {
            budget,
            panic,
            record: None,
            open: None,
            clock,
            paused: false,
            busy: Duration::ZERO,
            slowest: Duration::ZERO,
            slowest_phase: NO_EVENT,
            event: NO_EVENT,
            detail: None,
        }
    }

    /// The daemon's budget: [`BUDGET`], fatal when [`PANIC_ENV`] is `1`.
    pub fn from_env() -> Self {
        let mut b = Self::new(
            BUDGET,
            std::env::var(PANIC_ENV).as_deref() == Ok("1"),
            PauseClock::global(),
        );
        b.record = std::env::var_os(RECORD_ENV)
            .filter(|p| !p.is_empty())
            .map(std::path::PathBuf::from);
        b
    }

    /// Also append every report to `path` (see [`RECORD_ENV`]).
    pub fn recording_to(mut self, path: std::path::PathBuf) -> Self {
        self.record = Some(path);
        self
    }

    /// Start a busy stretch labelled `phase`, closing the current one.
    pub fn enter(&mut self, phase: &'static str) {
        self.close_stretch();
        let paused_before = self.clock.as_ref().map_or(0, |c| c.paused_ms());
        self.open = Some((Instant::now(), phase, paused_before));
    }

    /// The loop is about to wait for its next event: stop counting.
    pub fn idle(&mut self) {
        self.close_stretch();
    }

    /// Name the event (or control request) this iteration is handling.
    pub fn event(&mut self, event: &'static str) {
        self.event = event;
    }

    /// Finer detail for the event, computed only in a measuring build.
    pub fn detail(&mut self, detail: Option<String>) {
        self.detail = detail;
    }

    fn close_stretch(&mut self) {
        if let Some((at, phase, paused_before)) = self.open.take() {
            let took = at.elapsed();
            if let Some(c) = &self.clock {
                if c.paused_ms() != paused_before || (took > PAUSE_SLACK && c.stale()) {
                    self.paused = true;
                }
            }
            self.busy += took;
            if took >= self.slowest {
                self.slowest = took;
                self.slowest_phase = phase;
            }
        }
    }

    /// Close the iteration: the verdict if it was over budget, then reset.
    pub fn finish(&mut self) -> Option<Exceeded> {
        self.close_stretch();
        let judged = !std::mem::take(&mut self.paused);
        let verdict = (judged && self.busy >= self.budget).then(|| Exceeded {
            busy: self.busy,
            phase: self.slowest_phase,
            event: self.event,
            detail: self.detail.take(),
            slowest: self.slowest,
            budget: self.budget,
        });
        self.busy = Duration::ZERO;
        self.slowest = Duration::ZERO;
        self.slowest_phase = NO_EVENT;
        self.event = NO_EVENT;
        self.detail = None;
        verdict
    }

    /// `finish`, reporting an over-budget iteration on `log` (and panicking
    /// when fatal). Returns the verdict for callers that also want it.
    pub fn finish_and_report(&mut self, log: &dyn LogSink) -> Option<Exceeded> {
        let verdict = self.finish()?;
        let line = verdict.line();
        log.critical(&line);
        if let Some(path) = &self.record {
            use std::io::Write;
            let appended = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "{line} pid={}", std::process::id()));
            if let Err(e) = appended {
                log.critical(&format!("{MARKER}: could not record to {}: {e}", path.display()));
            }
        }
        if self.panic {
            panic!("{line} ({PANIC_ENV}=1): an await parked the daemon event loop");
        }
        Some(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Capture(Mutex<Vec<String>>);

    impl LogSink for Capture {
        fn debug(&self, _line: &str) {}
        fn trace(&self, _line: &str) {}
        fn say(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
        fn critical(&self, line: &str) {
            self.0.lock().unwrap().push(line.to_string());
        }
        fn paint(&self, _tone: crate::host::Tone, s: &str) -> String {
            s.to_string()
        }
        fn glyph_ok(&self) -> &'static str {
            "ok"
        }
        fn glyph_warn(&self) -> &'static str {
            "!"
        }
        fn enabled(&self, _level: crate::host::Level) -> bool {
            true
        }
    }

    const SHORT: Duration = Duration::from_millis(100);

    #[test]
    fn a_handler_that_sleeps_past_the_budget_trips_it_with_its_label() {
        let log = Capture::default();
        let mut b = IterationBudget::new(SHORT, false, None);
        b.enter("prelude");
        b.idle();
        b.enter("periodic");
        b.event("PcState");
        b.enter("handler");
        std::thread::sleep(SHORT + Duration::from_millis(50));
        let v = b.finish_and_report(&log).expect("a slow handler must trip the budget");
        assert_eq!(v.phase, "handler");
        assert_eq!(v.event, "PcState");
        assert!(v.busy >= SHORT && v.slowest >= SHORT, "{v:?}");
        let lines = log.0.lock().unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("LOOP-BUDGET-EXCEEDED ")
                && lines[0].contains(" handler/PcState slowest_ms="),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn a_report_is_appended_to_the_record_file() {
        let dir = std::env::temp_dir().join(format!("loop-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("record.log");
        let _ = std::fs::remove_file(&path);
        let mut b = IterationBudget::new(Duration::ZERO, false, None).recording_to(path.clone());
        b.event("PcState");
        b.enter("handler");
        b.finish_and_report(&crate::host::NoLog);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            text.starts_with("LOOP-BUDGET-EXCEEDED ")
                && text.contains(" handler/PcState ")
                && text.contains(&format!(" pid={}", std::process::id())),
            "{text}"
        );
    }

    #[test]
    fn a_fast_handler_does_not_trip_it() {
        let log = Capture::default();
        let mut b = IterationBudget::new(SHORT, true, None);
        for _ in 0..3 {
            b.enter("prelude");
            b.idle();
            b.enter("periodic");
            b.event("Control");
            b.enter("handler");
            assert!(b.finish_and_report(&log).is_none());
        }
        assert!(log.0.lock().unwrap().is_empty());
    }

    #[test]
    fn time_waiting_for_the_next_event_is_not_counted() {
        let mut b = IterationBudget::new(SHORT, true, None);
        b.enter("prelude");
        b.idle();
        // The select! wait: idle, however long.
        std::thread::sleep(SHORT + Duration::from_millis(50));
        b.enter("periodic");
        assert!(b.finish().is_none());
    }

    #[test]
    fn busy_stretches_add_up_and_the_longest_names_the_phase() {
        let mut b = IterationBudget::new(SHORT, false, None);
        b.enter("ctl");
        b.event("Exec");
        std::thread::sleep(Duration::from_millis(70));
        b.idle();
        b.enter("periodic");
        std::thread::sleep(Duration::from_millis(40));
        let v = b.finish().expect("70 + 40 ms of busy time is over a 100 ms budget");
        assert_eq!((v.phase, v.event), ("ctl", "Exec"));
        assert!(v.slowest < v.busy, "{v:?}");
        // The next iteration starts clean.
        b.enter("prelude");
        assert!(b.finish().is_none());
    }

    #[test]
    fn detail_is_part_of_the_label() {
        let mut b = IterationBudget::new(Duration::ZERO, false, None);
        b.event("Control");
        b.detail(Some("file-offer".into()));
        b.enter("handler");
        let v = b.finish().unwrap();
        assert_eq!(v.label(), "handler/Control:file-offer");
        assert!(v.line().starts_with(&format!("{MARKER} ")));
    }

    #[test]
    fn an_iteration_frozen_from_outside_is_not_judged() {
        // The pause clock's thread was frozen with the loop (SIGSTOP): its
        // first beat after the resume comes late, and the iteration that
        // spanned the freeze is not a parked await.
        let clock = PauseClock::manual();
        clock.beat();
        let mut b = IterationBudget::new(SHORT, true, Some(clock.clone()));
        b.event("Signal");
        b.enter("handler");
        std::thread::sleep(SHORT + PAUSE_SLACK + Duration::from_millis(50));
        clock.beat();
        assert!(b.finish().is_none());

        // Same freeze, but the loop closes the iteration before the clock
        // thread has run again: the stale beat still marks it.
        clock.beat();
        b.enter("handler");
        std::thread::sleep(SHORT + PAUSE_SLACK + Duration::from_millis(50));
        assert!(b.finish().is_none());

        // A beating clock does not excuse a slow handler.
        let clock = PauseClock::manual();
        let beating = clock.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let t = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                beating.beat();
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let mut b = IterationBudget::new(SHORT, false, Some(clock));
        b.enter("handler");
        std::thread::sleep(SHORT + Duration::from_millis(50));
        let v = b.finish();
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        assert!(v.is_some(), "a slow handler with no pause must still trip");
    }

    #[test]
    #[should_panic(expected = "LOOP-BUDGET-EXCEEDED")]
    fn a_fatal_budget_panics_on_a_slow_handler() {
        let log = Capture::default();
        let mut b = IterationBudget::new(SHORT, true, None);
        b.event("Signal");
        b.enter("handler");
        std::thread::sleep(SHORT + Duration::from_millis(50));
        b.finish_and_report(&log);
    }
}
