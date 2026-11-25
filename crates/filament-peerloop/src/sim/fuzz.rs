use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use crate::sim::assertions::{evaluate_oracles, OracleKind, OracleViolation};
use crate::sim::net::{Fault, HangSite, Proto, SimRng};
use crate::sim::world::{NodeSpec, ScheduledFault, SimConfig, SimMutant, SimOutcome, SimWorld};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuideFlags {
    pub swarm: bool,
    pub timer_edges: bool,
    pub sometimes: bool,
    pub hill_climb: bool,
    pub target_phase: Option<String>,
}

impl GuideFlags {
    pub fn unguided() -> Self {
        Self::default()
    }

    pub fn swarm_only() -> Self {
        Self {
            swarm: true,
            ..Self::default()
        }
    }

    pub fn timer_edges_only() -> Self {
        Self {
            timer_edges: true,
            ..Self::default()
        }
    }

    pub fn sometimes_only() -> Self {
        Self {
            sometimes: true,
            ..Self::default()
        }
    }

    pub fn hill_climb_only() -> Self {
        Self {
            hill_climb: true,
            ..Self::default()
        }
    }

    pub fn married() -> Self {
        Self {
            swarm: true,
            timer_edges: true,
            sometimes: true,
            hill_climb: true,
            target_phase: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CampaignConfig {
    pub seed: u64,
    pub max_runs: usize,
    pub stop_on_first_finding: bool,
    pub flags: GuideFlags,
    pub mutant: SimMutant,
    pub allow_gather_hang: bool,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub label: &'static str,
    pub run_index: usize,
    pub wall_ms: u64,
    pub seed: u64,
    pub trace_hash: u64,
    pub replay_verified: bool,
    pub violations: Vec<OracleViolation>,
    pub schedule_summary: String,
}

#[derive(Debug, Clone)]
pub struct CampaignReport {
    pub runs_executed: usize,
    pub total_wall_ms: u64,
    pub findings: Vec<Finding>,
    pub milestone_counts: BTreeMap<String, usize>,
    pub max_iter_busy_ms_seen: u64,
    pub max_cap_status_latency_ms_seen: u64,
}

impl CampaignReport {
    pub fn first_detection_run(&self) -> Option<usize> {
        self.findings.first().map(|f| f.run_index)
    }

    pub fn first_detection_kind(&self) -> Option<&OracleKind> {
        self.findings
            .first()
            .and_then(|f| f.violations.first())
            .map(|v| &v.kind)
    }
}

#[derive(Debug, Clone)]
struct FuzzSchedule {
    sim_seed: u64,
    duration_ms: u64,
    impair_delay_ms: u64,
    impair_jitter_ms: u64,
    impair_loss_pct: u8,
    impair_range: Option<(usize, u64, u64)>,
    partition: Option<(usize, usize, bool, u64, u64)>,
    blackhole: Option<(usize, u64, u64)>,
    hang: Option<(usize, HangSite, u64, u64)>,
    restart: Option<(usize, u64, u64)>,
    status_query: Option<(usize, u64)>,
}

const NODE_NAMES: [&str; 3] = ["alpha", "bravo", "charlie"];

/// Protocol timer constants harvested from recv/loop_budget.rs, recv/dispatch.rs,
/// conn.rs, and transport/net.rs (budget, scan, gather, heartbeat, grace, health,
/// rejoin, silence/watchdog, and session bounds).
pub const TIMER_CONSTANTS_MS: &[u64] = &[
    1_000, 2_000, 3_000, 5_000, 6_000, 8_000, 10_000, 15_000, 20_000, 30_000, 45_000, 60_000,
];

fn pick_boundary_value(rng: &mut SimRng, min: u64, max: u64) -> u64 {
    if min >= max {
        return min;
    }
    let candidates: Vec<u64> = TIMER_CONSTANTS_MS
        .iter()
        .copied()
        .filter(|t| *t >= min && *t <= max)
        .collect();
    if candidates.is_empty() || !rng.chance_pct(80) {
        return min + rng.gen_range_u64(max - min + 1);
    }
    let base = candidates[rng.gen_range_u64(candidates.len() as u64) as usize];
    let deltas = [0u64, 50, 150, 300, 500, 750];
    let delta = deltas[rng.gen_range_u64(deltas.len() as u64) as usize];
    if rng.chance_pct(50) {
        base.saturating_add(delta).min(max)
    } else {
        base.saturating_sub(delta).max(min)
    }
}

impl FuzzSchedule {
    fn to_sim_config(&self, mutant: SimMutant) -> SimConfig {
        let sec_ab = "fuzz-sec-ab".to_string();
        let sec_ac = "fuzz-sec-ac".to_string();
        let sec_bc = "fuzz-sec-bc".to_string();
        let nodes = vec![
            NodeSpec {
                name: "alpha".to_string(),
                uid: "uid-alpha".to_string(),
                peers: vec![
                    ("bravo".to_string(), sec_ab.clone()),
                    ("charlie".to_string(), sec_ac.clone()),
                ],
            },
            NodeSpec {
                name: "bravo".to_string(),
                uid: "uid-bravo".to_string(),
                peers: vec![
                    ("alpha".to_string(), sec_ab),
                    ("charlie".to_string(), sec_bc.clone()),
                ],
            },
            NodeSpec {
                name: "charlie".to_string(),
                uid: "uid-charlie".to_string(),
                peers: vec![
                    ("alpha".to_string(), sec_ac),
                    ("bravo".to_string(), sec_bc),
                ],
            },
        ];

        let mut schedule = Vec::new();
        if let Some((n, start, end)) = self.impair_range {
            let node = NODE_NAMES[n % 3].to_string();
            schedule.push(ScheduledFault {
                at_ms: start,
                fault: Fault::Impair {
                    node: node.clone(),
                    delay_ms: self.impair_delay_ms,
                    jitter_ms: self.impair_jitter_ms,
                    loss_pct: self.impair_loss_pct,
                },
            });
            schedule.push(ScheduledFault {
                at_ms: end,
                fault: Fault::ClearImpair { node },
            });
        }
        if let Some((a_idx, b_idx, udp_only, start, end)) = self.partition {
            let a = NODE_NAMES[a_idx % 3].to_string();
            let b = NODE_NAMES[(b_idx + 1) % 3].to_string();
            let (a, b) = if a == b {
                ("alpha".to_string(), "charlie".to_string())
            } else {
                (a, b)
            };
            schedule.push(ScheduledFault {
                at_ms: start,
                fault: Fault::Partition {
                    a: a.clone(),
                    b: b.clone(),
                    proto: if udp_only { Proto::Udp } else { Proto::All },
                },
            });
            schedule.push(ScheduledFault {
                at_ms: end,
                fault: Fault::HealPartition { a, b },
            });
        }
        if let Some((n, start, end)) = self.blackhole {
            let node = NODE_NAMES[n % 3].to_string();
            schedule.push(ScheduledFault {
                at_ms: start,
                fault: Fault::BlackholeSignaling { node: node.clone(), active: true },
            });
            schedule.push(ScheduledFault {
                at_ms: end,
                fault: Fault::BlackholeSignaling { node, active: false },
            });
        }
        if let Some((n, site, at_ms, dur_ms)) = self.hang {
            schedule.push(ScheduledFault {
                at_ms,
                fault: Fault::Hang {
                    node: NODE_NAMES[n % 3].to_string(),
                    site,
                    duration_ms: dur_ms,
                },
            });
        }

        let restart_node = self
            .restart
            .map(|(n, k, r)| (NODE_NAMES[n % 3].to_string(), k, r));
        let cap_status_queries = self
            .status_query
            .map(|(n, at)| vec![(NODE_NAMES[n % 3].to_string(), at)])
            .unwrap_or_default();

        SimConfig {
            seed: self.sim_seed,
            duration_ms: self.duration_ms,
            nodes,
            schedule,
            restart_node,
            cap_status_queries,
            inline_stall_injection: None,
            mutant,
        }
    }

    fn summary(&self) -> String {
        format!(
            "seed={} impair={:?} part={:?} bh={:?} hang={:?} restart={:?} status={:?}",
            self.sim_seed,
            self.impair_range,
            self.partition,
            self.blackhole,
            self.hang,
            self.restart,
            self.status_query
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct SwarmMask {
    impair: bool,
    partition: bool,
    blackhole: bool,
    hang: bool,
    restart: bool,
    status_query: bool,
}

impl SwarmMask {
    fn all_default() -> Self {
        Self {
            impair: true,
            partition: true,
            blackhole: true,
            hang: true,
            restart: true,
            status_query: true,
        }
    }

    fn sample(rng: &mut SimRng) -> Self {
        // Focus tightly on 1 to 2 fault axes ~40% of runs so bugs masked by
        // background partition/impair noise get clean signal; otherwise coin-flip.
        if rng.chance_pct(40) {
            let mut m = Self {
                impair: false,
                partition: false,
                blackhole: false,
                hang: false,
                restart: false,
                status_query: rng.chance_pct(65),
            };
            let first = rng.gen_range_u64(5);
            let second = rng.gen_range_u64(5);
            for slot in [first, second] {
                match slot {
                    0 => m.impair = true,
                    1 => m.partition = true,
                    2 => m.blackhole = true,
                    3 => m.hang = true,
                    _ => m.restart = true,
                }
            }
            return m;
        }
        let mut m = Self {
            impair: rng.chance_pct(50),
            partition: rng.chance_pct(45),
            blackhole: rng.chance_pct(55),
            hang: rng.chance_pct(45),
            restart: rng.chance_pct(55),
            status_query: rng.chance_pct(70),
        };
        if !(m.impair || m.partition || m.blackhole || m.hang || m.restart) {
            m.blackhole = true;
        }
        m
    }
}

fn generate_schedule(
    rng: &mut SimRng,
    flags: &GuideFlags,
    allow_gather_hang: bool,
) -> FuzzSchedule {
    let duration_ms = 60_000;
    let mask = if flags.swarm {
        SwarmMask::sample(rng)
    } else {
        SwarmMask::all_default()
    };

    let pick_window = |rng: &mut SimRng, min_dur: u64, max_dur: u64| -> (u64, u64) {
        let start = if flags.timer_edges && rng.chance_pct(60) {
            pick_boundary_value(rng, 500, 32_500)
        } else {
            500 + rng.gen_range_u64(32_000)
        };
        let dur = if flags.timer_edges {
            pick_boundary_value(rng, min_dur, max_dur)
        } else {
            min_dur + rng.gen_range_u64(max_dur - min_dur + 1)
        };
        let end = (start + dur).min(duration_ms - 5_000);
        (start, end.max(start + 500))
    };

    let impair_prob = if flags.swarm { 90 } else { 55 };
    let part_prob = if flags.swarm { 90 } else { 65 };
    let bh_prob = if flags.swarm { 90 } else { 65 };
    let hang_prob = if flags.swarm { 90 } else { 50 };
    let restart_prob = if flags.swarm { 90 } else { 60 };
    let status_prob = if flags.swarm { 95 } else { 75 };

    let impair_range = (mask.impair && rng.chance_pct(impair_prob)).then(|| {
        let (s, e) = pick_window(rng, 2_000, 30_000);
        (rng.gen_range_u64(3) as usize, s, e)
    });
    let partition = (mask.partition && rng.chance_pct(part_prob)).then(|| {
        let (s, e) = pick_window(rng, 1_500, 18_000);
        let a = rng.gen_range_u64(3) as usize;
        let b = rng.gen_range_u64(2) as usize;
        (a, b, rng.chance_pct(60), s, e)
    });
    let blackhole = (mask.blackhole && rng.chance_pct(bh_prob)).then(|| {
        let (s, e) = pick_window(rng, 3_000, 40_000);
        (rng.gen_range_u64(3) as usize, s, e)
    });
    let hang = (mask.hang && rng.chance_pct(hang_prob)).then(|| {
        let site = if allow_gather_hang && rng.chance_pct(if flags.swarm { 50 } else { 35 }) {
            HangSite::GatherCandidates
        } else {
            match rng.gen_range_u64(3) {
                0 => HangSite::HttpGetJson,
                1 => HangSite::SignalingEmit,
                _ => HangSite::DirectRace,
            }
        };
        let at_ms = if flags.timer_edges {
            pick_boundary_value(rng, 500, 42_500)
        } else {
            500 + rng.gen_range_u64(42_000)
        };
        let dur = if flags.timer_edges {
            pick_boundary_value(rng, 1_100, 3_500)
        } else {
            1_100 + rng.gen_range_u64(2_400)
        };
        (rng.gen_range_u64(3) as usize, site, at_ms, dur)
    });
    let restart = (mask.restart && rng.chance_pct(restart_prob)).then(|| {
        let k = if flags.timer_edges {
            pick_boundary_value(rng, 2_000, 37_000)
        } else {
            2_000 + rng.gen_range_u64(35_000)
        };
        let gap = if flags.timer_edges {
            pick_boundary_value(rng, 1_000, 7_000)
        } else {
            1_000 + rng.gen_range_u64(6_000)
        };
        (rng.gen_range_u64(3) as usize, k, (k + gap).min(duration_ms - 5_000))
    });
    let status_query = (mask.status_query && rng.chance_pct(status_prob)).then(|| {
        let at = if flags.timer_edges {
            pick_boundary_value(rng, 4_000, 52_000)
        } else {
            4_000 + rng.gen_range_u64(48_000)
        };
        (rng.gen_range_u64(3) as usize, at)
    });

    FuzzSchedule {
        sim_seed: rng.next_u64(),
        duration_ms,
        impair_delay_ms: 40 + rng.gen_range_u64(80),
        impair_jitter_ms: rng.gen_range_u64(60),
        impair_loss_pct: (10 + rng.gen_range_u64(35)) as u8,
        impair_range,
        partition,
        blackhole,
        hang,
        restart,
        status_query,
    }
}

#[derive(Debug, Clone)]
struct CorpusEntry {
    sched: FuzzSchedule,
    milestones: BTreeSet<String>,
    score: u64,
}

fn mutate_schedule(
    base: &FuzzSchedule,
    rng: &mut SimRng,
    flags: &GuideFlags,
    allow_gather_hang: bool,
) -> FuzzSchedule {
    let mut s = base.clone();
    s.sim_seed = rng.next_u64();
    let fresh = generate_schedule(rng, flags, allow_gather_hang);

    // Pick 1 to 2 structural/timing mutations while preserving interesting fault combos.
    let mutations = 1 + rng.gen_range_u64(2);
    for _ in 0..mutations {
        match rng.gen_range_u64(6) {
            0 => s.impair_range = fresh.impair_range,
            1 => {
                if flags.swarm && rng.chance_pct(40) {
                    s.partition = None;
                } else {
                    s.partition = fresh.partition;
                }
            }
            2 => {
                if let Some((node, start, end)) = s.blackhole {
                    let dur = if flags.timer_edges {
                        pick_boundary_value(rng, 3_000, 40_000)
                    } else {
                        end.saturating_sub(start)
                            .saturating_add(rng.gen_range_u64(6_000))
                            .saturating_sub(3_000)
                            .clamp(3_000, 40_000)
                    };
                    let new_end = (start + dur).min(s.duration_ms - 5_000);
                    s.blackhole = Some((node, start, new_end.max(start + 500)));
                } else {
                    s.blackhole = fresh.blackhole;
                }
            }
            3 => s.hang = fresh.hang,
            4 => {
                if let Some((_n, k, r)) = s.restart {
                    let node = rng.gen_range_u64(3) as usize;
                    let shift = rng.gen_range_u64(4_000) as i64 - 2_000;
                    let nk = (k as i64 + shift).clamp(1_500, 45_000) as u64;
                    let gap = r.saturating_sub(k).clamp(1_000, 8_000);
                    s.restart = Some((node, nk, (nk + gap).min(s.duration_ms - 5_000)));
                } else {
                    s.restart = fresh.restart;
                }
            }
            _ => {
                let at = if flags.timer_edges {
                    pick_boundary_value(rng, 4_000, 52_000)
                } else {
                    4_000 + rng.gen_range_u64(48_000)
                };
                s.status_query = Some((rng.gen_range_u64(3) as usize, at));
            }
        }
    }
    s
}

fn select_parent_idx(
    corpus: &[CorpusEntry],
    milestone_counts: &BTreeMap<String, usize>,
    rng: &mut SimRng,
    flags: &GuideFlags,
) -> usize {
    if corpus.len() <= 1 {
        return 0;
    }
    let weights: Vec<u64> = corpus
        .iter()
        .map(|entry| {
            let mut w = 10u64;
            if flags.sometimes {
                let rarity: u64 = entry
                    .milestones
                    .iter()
                    .map(|m| {
                        let c = milestone_counts.get(m).copied().unwrap_or(1).max(1) as u64;
                        10_000 / c.saturating_mul(c).max(1)
                    })
                    .sum();
                w = w.saturating_add(rarity);
            }
            if flags.hill_climb {
                w = w.saturating_add(entry.score);
            }
            w.max(1)
        })
        .collect();
    let total: u64 = weights.iter().sum();
    let mut pick = rng.gen_range_u64(total);
    for (idx, w) in weights.iter().enumerate() {
        if pick < *w {
            return idx;
        }
        pick -= *w;
    }
    0
}

/// Purely non-oracle continuous guidance signal computed strictly from
/// telemetry (loop busy time capped below 1000 ms, control-status latency
/// capped below 1000 ms, phase/event variety, and optional target-phase hit).
/// Never reads `OracleViolation` or any pass/fail oracle threshold.
fn non_oracle_guidance_score(outcome: &SimOutcome, target_phase: Option<&str>) -> u64 {
    let busy_slope = outcome.telemetry.max_iter_busy_ms.min(999).saturating_mul(10);
    let status_slope = outcome
        .cap_status_results
        .iter()
        .map(|s| s.latency_ms.min(999))
        .max()
        .unwrap_or(0)
        .saturating_mul(4);
    let phase_div = (outcome.telemetry.phases_hit.len() as u64).saturating_mul(25);
    let event_div = (outcome.telemetry.events_hit.len() as u64).saturating_mul(10);
    let target_bonus = target_phase
        .and_then(|p| outcome.telemetry.phase_first_seen_ms.get(p))
        .map(|first_ms| 2_000u64.saturating_sub((*first_ms / 40).min(1_500)))
        .unwrap_or(0);
    busy_slope
        .saturating_add(status_slope)
        .saturating_add(phase_div)
        .saturating_add(event_div)
        .saturating_add(target_bonus)
}

pub struct Fuzzer;

impl Fuzzer {
    pub fn run(campaign: &CampaignConfig) -> CampaignReport {
        let t0 = Instant::now();
        let mut rng = SimRng::new(campaign.seed);
        let mut findings = Vec::new();
        let mut milestone_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut corpus: Vec<CorpusEntry> = Vec::new();
        let mut max_iter_busy_ms_seen = 0u64;
        let mut max_cap_status_latency_ms_seen = 0u64;
        let mut best_hill_score = 0u64;
        let mut best_busy_slope = 0u64;
        let mut runs_executed = 0usize;

        let corpus_active = campaign.flags.sometimes || campaign.flags.hill_climb;

        for run_idx in 0..campaign.max_runs {
            runs_executed = run_idx + 1;
            let sched = if corpus_active && !corpus.is_empty() && rng.chance_pct(65) {
                let idx = select_parent_idx(&corpus, &milestone_counts, &mut rng, &campaign.flags);
                mutate_schedule(
                    &corpus[idx].sched,
                    &mut rng,
                    &campaign.flags,
                    campaign.allow_gather_hang,
                )
            } else {
                generate_schedule(&mut rng, &campaign.flags, campaign.allow_gather_hang)
            };
            let cfg = sched.to_sim_config(campaign.mutant.clone());
            let outcome: SimOutcome = SimWorld::run(cfg.clone());

            let mut hit_rare_milestone = false;
            let mut hit_set = BTreeSet::new();
            for (k, v) in &outcome.assertions.sometimes_hits {
                if *v > 0 {
                    hit_set.insert(k.clone());
                    let prev = milestone_counts.get(k).copied().unwrap_or(0);
                    if prev < 3 {
                        hit_rare_milestone = true;
                    }
                    *milestone_counts.entry(k.clone()).or_insert(0) += 1;
                }
            }
            max_iter_busy_ms_seen = max_iter_busy_ms_seen.max(outcome.telemetry.max_iter_busy_ms);
            for st in &outcome.cap_status_results {
                max_cap_status_latency_ms_seen = max_cap_status_latency_ms_seen.max(st.latency_ms);
            }

            let hill_score = if campaign.flags.hill_climb {
                non_oracle_guidance_score(&outcome, campaign.flags.target_phase.as_deref())
            } else {
                0
            };
            let busy_slope = outcome.telemetry.max_iter_busy_ms.min(999);
            let improved_hill = campaign.flags.hill_climb
                && (hill_score > best_hill_score || busy_slope > best_busy_slope);
            if improved_hill {
                best_hill_score = best_hill_score.max(hill_score);
                best_busy_slope = best_busy_slope.max(busy_slope);
            }

            if (campaign.flags.sometimes && hit_rare_milestone) || improved_hill {
                if corpus.len() >= 64 {
                    corpus.remove(0);
                }
                corpus.push(CorpusEntry {
                    sched: sched.clone(),
                    milestones: hit_set,
                    score: hill_score,
                });
            }

            let violations = evaluate_oracles(&outcome, &cfg);
            if !violations.is_empty() {
                // Verify bit-exact deterministic replay before reporting any finding.
                let replay = SimWorld::run(cfg.clone());
                let replay_violations = evaluate_oracles(&replay, &cfg);
                let replay_verified = replay.trace_hash == outcome.trace_hash
                    && !replay_violations.is_empty();
                let finding_kinds: BTreeSet<_> =
                    violations.iter().map(|v| format!("{:?}", v.kind)).collect();
                assert!(
                    replay_verified,
                    "DST finding failed bit-exact replay! seed={} orig_hash={:#x} replay_hash={:#x} kinds={:?}",
                    cfg.seed, outcome.trace_hash, replay.trace_hash, finding_kinds
                );
                findings.push(Finding {
                    label: "sim-only",
                    run_index: run_idx + 1,
                    wall_ms: t0.elapsed().as_millis() as u64,
                    seed: cfg.seed,
                    trace_hash: outcome.trace_hash,
                    replay_verified,
                    violations,
                    schedule_summary: sched.summary(),
                });
                if campaign.stop_on_first_finding {
                    break;
                }
            }
        }

        CampaignReport {
            runs_executed,
            total_wall_ms: t0.elapsed().as_millis() as u64,
            findings,
            milestone_counts,
            max_iter_busy_ms_seen,
            max_cap_status_latency_ms_seen,
        }
    }
}
