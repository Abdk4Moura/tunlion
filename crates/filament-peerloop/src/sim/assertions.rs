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
        let mut still_bh_nodes: BTreeSet<String> = BTreeSet::new();
        let mut active_partitions: usize = 0;
        let mut active_blackholes: usize = 0;
        let mut last_heal_ms = config.restart_node.as_ref().map_or(0, |(_, _, r)| *r);
        let mut faulted_windows: Vec<(u64, u64)> = Vec::new();
        let mut part_start: Option<u64> = None;
        let mut bh_starts: BTreeMap<String, u64> = BTreeMap::new();

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
                        still_bh_nodes.insert(node.clone());
                        bh_starts.entry(node.clone()).or_insert(sf.at_ms);
                        active_blackholes = active_blackholes.saturating_add(1);
                    }
                    Fault::BlackholeSignaling { node, active: false } => {
                        still_bh_nodes.remove(node);
                        if let Some(s) = bh_starts.remove(node) {
                            faulted_windows.push((s, sf.at_ms + 5_000));
                        }
                        active_blackholes = active_blackholes.saturating_sub(1);
                        last_heal_ms = last_heal_ms.max(sf.at_ms);
                    }
                    Fault::Impair { .. }
                    | Fault::ClearImpair { .. }
                    | Fault::Hang { .. }
                    | Fault::SetMessageChaos { .. }
                    | Fault::ClearMessageChaos => {}
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
                            still_bh_nodes.insert(node.to_string());
                            bh_starts.entry(node.to_string()).or_insert(ne.at_ms);
                            active_blackholes = active_blackholes.saturating_add(1);
                        } else if active_str == "false" {
                            still_bh_nodes.remove(node);
                            if let Some(s) = bh_starts.remove(node) {
                                faulted_windows.push((s, ne.at_ms + 5_000));
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
        for (_, s) in bh_starts {
            faulted_windows.push((s, config.duration_ms));
        }
        if let Some((_, k, r)) = config.restart_node {
            faulted_windows.push((k, r + 5_000));
        }

        if let Some((ref rnode, _kill_ms, restart_ms)) = config.restart_node {
            let tail = config.duration_ms.saturating_sub(restart_ms);
            let still_bh = still_bh_nodes.contains(rnode);
            if tail >= 10_000 && !still_bh {
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

    violations
}
