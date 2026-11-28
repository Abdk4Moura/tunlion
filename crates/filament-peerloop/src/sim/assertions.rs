use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use filament_transport::clock;

use crate::sim::net::Fault;
use crate::sim::world::{SimConfig, SimOutcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlwaysFailure {
    pub tag: String,
    pub detail: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssertionReport {
    pub always_checks: u64,
    pub always_failures: Vec<AlwaysFailure>,
    pub sometimes_hits: BTreeMap<String, u64>,
    pub antecedents_seen: BTreeSet<String>,
}

thread_local! {
    static SIM_ASSERTIONS: RefCell<AssertionReport> = RefCell::new(AssertionReport::default());
}

pub fn reset_assertions() {
    SIM_ASSERTIONS.with(|cell| *cell.borrow_mut() = AssertionReport::default());
}

pub fn record_sometimes(tag: &'static str) {
    SIM_ASSERTIONS.with(|cell| {
        let mut r = cell.borrow_mut();
        *r.sometimes_hits.entry(tag.to_string()).or_insert(0) += 1;
    });
}

pub fn record_antecedent(tag: &'static str) {
    SIM_ASSERTIONS.with(|cell| {
        cell.borrow_mut().antecedents_seen.insert(tag.to_string());
    });
}

pub fn record_always(tag: &'static str, ok: bool, detail: impl FnOnce() -> String) {
    let at_ms = clock::now_ms();
    SIM_ASSERTIONS.with(|cell| {
        let mut r = cell.borrow_mut();
        r.always_checks = r.always_checks.saturating_add(1);
        if !ok {
            r.always_failures.push(AlwaysFailure {
                tag: tag.to_string(),
                detail: detail(),
                at_ms,
            });
        }
    });
}

pub fn take_assertions() -> AssertionReport {
    SIM_ASSERTIONS.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

#[macro_export]
macro_rules! sim_sometimes {
    ($tag:expr) => {
        $crate::sim::assertions::record_sometimes($tag)
    };
}

#[macro_export]
macro_rules! sim_always {
    ($tag:expr, $cond:expr, $($arg:tt)*) => {
        $crate::sim::assertions::record_always($tag, $cond, || format!($($arg)*))
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleKind {
    LoopBudgetExceeded,
    CapStatusFailed,
    AlwaysAssertionFailed,
    PostHealLivenessViolation,
    FormalInvariantViolation,
    /// A one-shot fleet dial of a live, reachable daemon was not answered with
    /// a direct link within the dialer's candidate bound.
    OneShotUnanswered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleViolation {
    pub kind: OracleKind,
    pub summary: String,
}

/// Fixed, guidance-independent correctness oracles.
/// Thresholds (1000 ms loop budget, 1000 ms status latency, Tier-1 post-heal
/// recovery window) never read or depend on any search guidance metric.
pub fn evaluate_oracles(outcome: &SimOutcome, config: &SimConfig) -> Vec<OracleViolation> {
    let mut violations = Vec::new();

    for v in &outcome.budget_violations {
        violations.push(OracleViolation {
            kind: OracleKind::LoopBudgetExceeded,
            summary: v.clone(),
        });
    }

    for st in &outcome.cap_status_results {
        if st.response["ok"] != true || st.latency_ms >= 1_000 {
            violations.push(OracleViolation {
                kind: OracleKind::CapStatusFailed,
                summary: format!(
                    "cap-status {}@{}ms latency={}ms ok={}",
                    st.node, st.at_ms, st.latency_ms, st.response["ok"]
                ),
            });
        }
    }

    for af in &outcome.assertions.always_failures {
        violations.push(OracleViolation {
            kind: OracleKind::AlwaysAssertionFailed,
            summary: format!("always({})@{}ms: {}", af.tag, af.at_ms, af.detail),
        });
    }

    // Derived from proofs/establishment_model.py Tier-1 self-heal invariant:
    // (a) if a node was restarted with >=10s remaining and is not blackholed
    // past restart+5s, it must re-establish signaling after restart;
    // (b) once all partitions/blackholes heal after a link-severing fault with
    // >=15s clean tail remaining, paired nodes must show post-heal connect progress;
    // (c) in clean non-faulted windows outside a 5s post-heal grace, signaling
    // reconnects remain bounded (no defect-1/defect-2 reconnect storm).
    if config.nodes.len() >= 2 && config.duration_ms >= 20_000 {
        let mut active_partitions: usize = 0;
        let mut active_blackholes: usize = 0;
        let mut last_heal_ms = config.restart_node.as_ref().map_or(0, |(_, _, r)| *r);
        let mut faulted_windows: Vec<(u64, u64)> = Vec::new();
        let mut part_start: Option<u64> = None;
        let mut bh_starts: BTreeMap<String, u64> = BTreeMap::new();
        let mut node_bh_intervals: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();

        if config.semantic_faults.is_empty() {
            for sf in &config.schedule {
                match &sf.fault {
                    Fault::Partition { .. } => {
                        if active_partitions == 0 {
                            part_start = Some(sf.at_ms);
                        }
                        active_partitions = active_partitions.saturating_add(1);
                    }
                    Fault::HealPartition { .. } => {
                        active_partitions = active_partitions.saturating_sub(1);
                        if active_partitions == 0 {
                            if let Some(s) = part_start.take() {
                                faulted_windows.push((s, sf.at_ms + 5_000));
                            }
                        }
                        last_heal_ms = last_heal_ms.max(sf.at_ms);
                    }
                    Fault::BlackholeSignaling { node, active: true } => {
                        bh_starts.entry(node.clone()).or_insert(sf.at_ms);
                        active_blackholes = active_blackholes.saturating_add(1);
                    }
                    Fault::BlackholeSignaling { node, active: false } => {
                        if let Some(s) = bh_starts.remove(node) {
                            faulted_windows.push((s, sf.at_ms + 5_000));
                            node_bh_intervals
                                .entry(node.clone())
                                .or_default()
                                .push((s, sf.at_ms));
                        }
                        active_blackholes = active_blackholes.saturating_sub(1);
                        last_heal_ms = last_heal_ms.max(sf.at_ms);
                    }
                    Fault::Impair { .. }
                    | Fault::ClearImpair { .. }
                    | Fault::Hang { .. }
                    | Fault::SetMessageChaos { .. }
                    | Fault::ClearMessageChaos
                    | Fault::SlowDisk { .. }
                    | Fault::ClearSlowDisk { .. } => {}
                }
            }
        } else {
            for ne in &outcome.net_events {
                if let Some(rest) = ne.event.strip_prefix("fault:partition:") {
                    let _ = rest;
                    if active_partitions == 0 {
                        part_start = Some(ne.at_ms);
                    }
                    active_partitions = active_partitions.saturating_add(1);
                } else if ne.event.starts_with("fault:heal:") {
                    active_partitions = active_partitions.saturating_sub(1);
                    if active_partitions == 0 {
                        if let Some(s) = part_start.take() {
                            faulted_windows.push((s, ne.at_ms + 5_000));
                        }
                    }
                    last_heal_ms = last_heal_ms.max(ne.at_ms);
                } else if let Some(rest) = ne.event.strip_prefix("fault:blackhole:") {
                    if let Some((node, active_str)) = rest.rsplit_once(':') {
                        if active_str == "true" {
                            bh_starts.entry(node.to_string()).or_insert(ne.at_ms);
                            active_blackholes = active_blackholes.saturating_add(1);
                        } else if active_str == "false" {
                            if let Some(s) = bh_starts.remove(node) {
                                faulted_windows.push((s, ne.at_ms + 5_000));
                                node_bh_intervals
                                    .entry(node.to_string())
                                    .or_default()
                                    .push((s, ne.at_ms));
                            }
                            active_blackholes = active_blackholes.saturating_sub(1);
                            last_heal_ms = last_heal_ms.max(ne.at_ms);
                        }
                    }
                }
            }
        }
        if let Some(s) = part_start {
            faulted_windows.push((s, config.duration_ms));
        }
        for (node, s) in bh_starts {
            faulted_windows.push((s, config.duration_ms));
            node_bh_intervals
                .entry(node)
                .or_default()
                .push((s, config.duration_ms));
        }
        if let Some((_, k, r)) = config.restart_node {
            faulted_windows.push((k, r + 5_000));
        }

        if let Some((ref rnode, _kill_ms, restart_ms)) = config.restart_node {
            let tail = config.duration_ms.saturating_sub(restart_ms);
            let bh_blocks_restart = node_bh_intervals.get(rnode).is_some_and(|ivs| {
                ivs.iter().any(|&(s, e)| {
                    (s <= restart_ms.saturating_add(5_000) && e >= restart_ms)
                        || e > config.duration_ms.saturating_sub(10_000)
                })
            });
            if tail >= 10_000 && !bh_blocks_restart {
                let reconnected = outcome.net_events.iter().any(|ne| {
                    ne.at_ms >= restart_ms && ne.event.starts_with(&format!("sig:connect:{rnode}:"))
                });
                if !reconnected {
                    violations.push(OracleViolation {
                        kind: OracleKind::PostHealLivenessViolation,
                        summary: format!(
                            "restarted node {rnode} at {restart_ms}ms never reconnected to signaling"
                        ),
                    });
                }
            }
        }

        let severed_before_heal = outcome
            .net_events
            .iter()
            .any(|ne| ne.event.starts_with("link:dropped_by_partition:"));
        let clean_tail_ms = config.duration_ms.saturating_sub(last_heal_ms);
        if severed_before_heal
            && active_partitions == 0
            && active_blackholes == 0
            && clean_tail_ms >= 15_000
        {
            let post_heal_progress = outcome.net_events.iter().any(|ne| {
                ne.at_ms > last_heal_ms
                    && (ne.event.starts_with("direct:pair:")
                        || ne.event.starts_with("sig:connect:"))
            });
            if !post_heal_progress {
                violations.push(OracleViolation {
                    kind: OracleKind::PostHealLivenessViolation,
                    summary: format!(
                        "no signaling/direct progress after severed link healed at {last_heal_ms}ms (tail={clean_tail_ms}ms)"
                    ),
                });
            }
        }

        record_antecedent("est_clean_window_checked");
        let mut clean_connects: BTreeMap<String, usize> = BTreeMap::new();
        for ne in &outcome.net_events {
            if let Some(rest) = ne.event.strip_prefix("sig:connect:") {
                let node = rest.split(':').next().unwrap_or("");
                let in_fault = faulted_windows
                    .iter()
                    .any(|(s, e)| ne.at_ms >= *s && ne.at_ms <= *e);
                if !in_fault && !node.is_empty() {
                    *clean_connects.entry(node.to_string()).or_insert(0) += 1;
                }
            }
        }
        for (node, cnt) in clean_connects {
            if cnt > 6 {
                violations.push(OracleViolation {
                    kind: OracleKind::FormalInvariantViolation,
                    summary: format!(
                        "est_no_clean_reconnect_storm: node {node} had {cnt} clean signaling connects"
                    ),
                });
            }
        }
    }

    violations.extend(one_shot_violations(outcome, config));
    violations
}

/// A one-shot dial of a reachable live peer is answered within the dialer's
/// candidate bound (`oneshot::CANDIDATE_BOUND`, the CLI's `WATCHDOG_SECS`).
///
/// "Reachable live peer" is judged from the trace, so semantic (event-driven)
/// faults count the same as scheduled ones. Around the dial (5 s before it to
/// 1 s past the bound) the target must stay connected to signaling (no
/// connect, disconnect or kill), and no fault may touch its reachability: a
/// signaling blackhole or an impairment on the target, a hang injected on the
/// target, or signaling message chaos. A partition or a slow disk does not
/// excuse it: neither stops the dialer reaching the target, so a dial they
/// break is a defect.
pub fn one_shot_violations(outcome: &SimOutcome, config: &SimConfig) -> Vec<OracleViolation> {
    let bound_ms = crate::sim::oneshot::CANDIDATE_BOUND.as_millis() as u64;
    let mut out = Vec::new();
    let ev = &outcome.net_events;
    for start in ev.iter().filter(|e| e.event.starts_with("oneshot:start:")) {
        let rest = &start.event["oneshot:start:".len()..];
        let Some((dialer, target)) = rest.split_once(':') else { continue };
        let (w0, w1) = (start.at_ms.saturating_sub(5_000), start.at_ms + bound_ms + 1_000);
        if w1 > config.duration_ms {
            continue;
        }
        record_antecedent("one_shot_dial_judged_window");
        // Target connected to signaling at w0 and steady through the window.
        let mut up = false;
        let mut steady = true;
        let conn_prefix = format!("sig:connect:{target}:");
        let disc_prefix = format!("sig:disconnect:{target}:");
        let kill = format!("node:disconnect:{target}");
        for e in ev {
            let is_conn = e.event.starts_with(&conn_prefix);
            let is_disc = e.event.starts_with(&disc_prefix) || e.event == kill;
            if !(is_conn || is_disc) {
                continue;
            }
            if e.at_ms < w0 {
                up = is_conn;
            } else if e.at_ms <= w1 {
                steady = false;
            }
        }
        if !up || !steady {
            continue;
        }
        // Faults that excuse a dial, as (start, end) intervals.
        let mut excused = false;
        let mut open: BTreeMap<&str, u64> = BTreeMap::new();
        let bh_on = format!("fault:blackhole:{target}:true");
        let bh_off = format!("fault:blackhole:{target}:false");
        let imp_on = format!("fault:impair:{target}:");
        let imp_off = format!("fault:clear_impair:{target}");
        let hang = format!("fault:hang:{target}:");
        let overlaps = |s: u64, e: u64| s <= w1 && e >= w0;
        for e in ev {
            let t = e.at_ms;
            if e.event == bh_on {
                open.insert("bh", t);
            } else if e.event == bh_off {
                if let Some(s) = open.remove("bh") {
                    excused |= overlaps(s, t);
                }
            } else if e.event.starts_with(&imp_on) {
                open.insert("imp", t);
            } else if e.event == imp_off {
                if let Some(s) = open.remove("imp") {
                    excused |= overlaps(s, t);
                }
            } else if e.event.starts_with("fault:msg_chaos:") {
                open.insert("chaos", t);
            } else if e.event == "fault:clear_msg_chaos" {
                if let Some(s) = open.remove("chaos") {
                    excused |= overlaps(s, t);
                }
            } else if e.event.starts_with(&hang) {
                // A hang fires at the next use of its site, which may be much
                // later: any hang injected before the window ends excuses it.
                excused |= t <= w1;
            }
        }
        for (_, s) in open {
            excused |= overlaps(s, config.duration_ms);
        }
        if excused {
            continue;
        }
        record_antecedent("one_shot_dial_clean_window");
        let answered = format!("oneshot:answered:{dialer}:{target}");
        if !ev.iter().any(|e| e.event == answered) {
            let why = ev
                .iter()
                .find_map(|e| {
                    e.event
                        .strip_prefix(&format!("oneshot:gaveup:{dialer}:{target}:"))
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "no outcome".to_string());
            out.push(OracleViolation {
                kind: OracleKind::OneShotUnanswered,
                summary: format!(
                    "one-shot {dialer} dialed live {target} at {}ms and was not answered within {}ms ({why})",
                    start.at_ms, bound_ms
                ),
            });
        }
    }
    out
}
