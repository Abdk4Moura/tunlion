use std::cell::RefCell;
use std::collections::BTreeMap;

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
    // >=15s clean tail remaining, paired nodes must show post-heal connect progress.
    if config.nodes.len() >= 2 && config.duration_ms >= 20_000 {
        if let Some((ref rnode, _kill_ms, restart_ms)) = config.restart_node {
            let tail = config.duration_ms.saturating_sub(restart_ms);
            let still_bh = config.schedule.iter().any(|sf| match &sf.fault {
                Fault::BlackholeSignaling { node, active: true } if node == rnode => {
                    !config.schedule.iter().any(|h| {
                        h.at_ms > sf.at_ms
                            && matches!(&h.fault, Fault::BlackholeSignaling { node: n2, active: false } if n2 == rnode && h.at_ms <= config.duration_ms.saturating_sub(10_000))
                    })
                }
                _ => false,
            });
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

        let mut active_partitions: usize = 0;
        let mut active_blackholes: usize = 0;
        let mut last_heal_ms = config.restart_node.as_ref().map_or(0, |(_, _, r)| *r);
        let severed_before_heal = outcome
            .net_events
            .iter()
            .any(|ne| ne.event.starts_with("link:dropped_by_partition:"));

        for sf in &config.schedule {
            match &sf.fault {
                Fault::Partition { .. } => {
                    active_partitions = active_partitions.saturating_add(1);
                }
                Fault::HealPartition { .. } => {
                    active_partitions = active_partitions.saturating_sub(1);
                    last_heal_ms = last_heal_ms.max(sf.at_ms);
                }
                Fault::BlackholeSignaling { active: true, .. } => {
                    active_blackholes = active_blackholes.saturating_add(1);
                }
                Fault::BlackholeSignaling { active: false, .. } => {
                    active_blackholes = active_blackholes.saturating_sub(1);
                    last_heal_ms = last_heal_ms.max(sf.at_ms);
                }
                Fault::Impair { .. } | Fault::ClearImpair { .. } | Fault::Hang { .. } => {}
            }
        }

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
    }

    violations
}
