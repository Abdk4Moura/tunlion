use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::sim::assertions::{evaluate_oracles, take_assertions, OracleKind, OracleViolation};
use crate::sim::corpus::{self, CorpusEntry};
use crate::sim::net::{Fault, HangSite, MessageChaosPolicy, Proto, SimRng};
use crate::sim::semantic::{ProtoEvent, SemanticAction, SemanticFault, SemanticTrigger, StateEdge};
use crate::sim::world::{
    NodeSpec, OneShotDial, ScheduledFault, SimConfig, SimMutant, SimOutcome, SimWorld,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuideFlags {
    pub swarm: bool,
    pub semantic: bool,
    pub message_chaos: bool,
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

    pub fn semantic_only() -> Self {
        Self {
            semantic: true,
            ..Self::default()
        }
    }

    pub fn swarm_semantic() -> Self {
        Self {
            swarm: true,
            semantic: true,
            ..Self::default()
        }
    }

    pub fn message_chaos_only() -> Self {
        Self {
            message_chaos: true,
            ..Self::default()
        }
    }

    pub fn full_semantic() -> Self {
        Self {
            swarm: true,
            semantic: true,
            message_chaos: true,
        }
    }

    /// PROVISIONAL: not shown to find real bugs faster than [`Self::unguided`].
    /// Chosen and judged on the same two bugs: #738 was not blind (its hang
    /// fault was placed at the bug site) and #729 is a tie (median 2 runs for
    /// both). With `CampaignConfig::reach` the sim reaches two held-out bugs,
    /// and on them (2026-11-28, 20 seeds, 40-run budget fixed in advance)
    /// married LOST to unguided on #757 (18/20, median 16 runs, against
    /// 20/20, median 3) and roughly tied on #768 (17/20, median 21, against
    /// 14/20, median 16; mean 19.4 against 21.2). Campaigns default to
    /// unguided (`CampaignConfig::default()`); keep it that way.
    pub fn married() -> Self {
        Self {
            swarm: true,
            semantic: false,
            message_chaos: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CampaignConfig {
    pub seed: u64,
    pub max_runs: usize,
    pub stop_on_first_finding: bool,
    pub flags: GuideFlags,
    pub mutant: SimMutant,
    pub allow_gather_hang: bool,
    pub quiet_logs: bool,
    pub corpus_dir: Option<PathBuf>,
    pub regressions_dir: Option<PathBuf>,
    /// The wider world: each schedule also draws, blindly, a fleet identity
    /// for the daemons, one-shot fleet dialers and a slow disk (see
    /// [`ReachDraw`]), and the network model gets random session ids, HTTP
    /// round trips and direct-link channel bindings. Off keeps every recorded
    /// result of the narrower sim bit-exact.
    pub reach: bool,
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
    pub state_edges: BTreeSet<StateEdge>,
    pub state_edges_discovered: usize,
    pub antecedents_seen: BTreeSet<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSchedule {
    pub sim_seed: u64,
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
    msg_chaos: Option<(MessageChaosPolicy, u64, u64)>,
    semantic_faults: Vec<SemanticFault>,
    #[serde(default)]
    reach: Option<ReachDraw>,
}

/// The wider-world part of a schedule. Every field is drawn blindly: which
/// node, when and how slow are uniform (latency log-uniform) and never look
/// at a call site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachDraw {
    /// All three daemons are members of one fleet.
    pub fleet: bool,
    /// One-shot fleet dials: (target node index, start ms).
    pub one_shots: Vec<(usize, u64)>,
    /// A slow disk: (node index, write latency ms, start ms, end ms).
    pub slow_disk: Option<(usize, u64, u64, u64)>,
}

/// Disk write latency, log-uniform over 10 ms .. 3 s: from a quiet SSD's fsync
/// to a disk saturated by writeback (the field saw 100 to 740 ms per write
/// with only the disk loaded, and over 1 s under the chaos fuzzer).
fn draw_write_ms(rng: &mut SimRng) -> u64 {
    let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    (10.0 * 300f64.powf(u)) as u64
}

fn draw_reach(rng: &mut SimRng, flags: &GuideFlags, duration_ms: u64) -> ReachDraw {
    // Swarm testing applies to these faults exactly as to the network ones:
    // a run either carries each feature or does not.
    let (fleet_p, dial_p, disk_p) = if flags.swarm {
        (
            if rng.chance_pct(50) { 95 } else { 0 },
            if rng.chance_pct(70) { 95 } else { 0 },
            if rng.chance_pct(60) { 95 } else { 0 },
        )
    } else {
        (60, 80, 50)
    };
    let fleet = rng.chance_pct(fleet_p);
    let mut one_shots = Vec::new();
    if fleet && rng.chance_pct(dial_p) {
        let n = 1 + rng.gen_range_u64(3) as usize;
        // A dial needs its whole candidate bound inside the run.
        let latest = duration_ms - 17_000;
        for _ in 0..n {
            let at = 3_000 + rng.gen_range_u64(latest - 3_000);
            one_shots.push((rng.gen_range_u64(3) as usize, at));
        }
        one_shots.sort_by_key(|(_, at)| *at);
    }
    let slow_disk = rng.chance_pct(disk_p).then(|| {
        let node = rng.gen_range_u64(3) as usize;
        let ms = draw_write_ms(rng);
        let start = 500 + rng.gen_range_u64(40_000);
        let end = (start + 5_000 + rng.gen_range_u64(40_001)).min(duration_ms - 2_000);
        (node, ms, start, end.max(start + 500))
    });
    ReachDraw {
        fleet,
        one_shots,
        slow_disk,
    }
}

const NODE_NAMES: [&str; 3] = ["alpha", "bravo", "charlie"];

impl FuzzSchedule {
    pub(crate) fn to_sim_config(&self, mutant: SimMutant) -> SimConfig {
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
        if let Some((policy, start, end)) = self.msg_chaos {
            schedule.push(ScheduledFault {
                at_ms: start,
                fault: Fault::SetMessageChaos { policy },
            });
            schedule.push(ScheduledFault {
                at_ms: end,
                fault: Fault::ClearMessageChaos,
            });
        }

        let restart_node = self
            .restart
            .map(|(n, k, r)| (NODE_NAMES[n % 3].to_string(), k, r));
        let cap_status_queries = self
            .status_query
            .map(|(n, at)| vec![(NODE_NAMES[n % 3].to_string(), at)])
            .unwrap_or_default();

        let mut one_shot_dials = Vec::new();
        let mut fleet = false;
        if let Some(r) = &self.reach {
            fleet = r.fleet;
            if r.fleet {
                for (t, at) in &r.one_shots {
                    one_shot_dials.push(OneShotDial {
                        at_ms: *at,
                        target: NODE_NAMES[t % 3].to_string(),
                    });
                }
            }
            if let Some((n, ms, start, end)) = r.slow_disk {
                let node = NODE_NAMES[n % 3].to_string();
                schedule.push(ScheduledFault {
                    at_ms: start,
                    fault: Fault::SlowDisk { node: node.clone(), write_ms: ms },
                });
                schedule.push(ScheduledFault {
                    at_ms: end,
                    fault: Fault::ClearSlowDisk { node },
                });
            }
        }

        SimConfig {
            seed: self.sim_seed,
            duration_ms: self.duration_ms,
            nodes,
            schedule,
            restart_node,
            cap_status_queries,
            inline_stall_injection: None,
            mutant,
            quiet_logs: false,
            semantic_faults: self.semantic_faults.clone(),
            reach: self.reach.is_some(),
            fleet,
            one_shot_dials,
            fleet_primary: None,
            renewal_due: Vec::new(),
        }
    }

    pub fn semantic_fault_count(&self) -> usize {
        self.semantic_faults.len()
    }

    pub fn summary(&self) -> String {
        format!(
            "seed={} impair={:?} part={:?} bh={:?} hang={:?} restart={:?} status={:?} sem={} reach={:?}",
            self.sim_seed,
            self.impair_range,
            self.partition,
            self.blackhole,
            self.hang,
            self.restart,
            self.status_query,
            self.semantic_faults.len(),
            self.reach
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
        // 35% of runs silence interfering background transport noise (partition/impair)
        // so clean blackhole/restart/hang interactions surface without masking.
        if rng.chance_pct(35) {
            return Self {
                impair: false,
                partition: false,
                blackhole: rng.chance_pct(80),
                hang: rng.chance_pct(75),
                restart: rng.chance_pct(80),
                status_query: rng.chance_pct(85),
            };
        }
        let mut m = Self {
            impair: rng.chance_pct(55),
            partition: rng.chance_pct(50),
            blackhole: rng.chance_pct(70),
            hang: rng.chance_pct(65),
            restart: rng.chance_pct(70),
            status_query: rng.chance_pct(85),
        };
        if !(m.impair || m.partition || m.blackhole || m.hang || m.restart) {
            m.blackhole = true;
            m.restart = true;
        }
        m
    }
}

fn generate_schedule(
    rng: &mut SimRng,
    flags: &GuideFlags,
    allow_gather_hang: bool,
    reach: bool,
) -> FuzzSchedule {
    let duration_ms = 60_000;
    let mask = if flags.swarm {
        SwarmMask::sample(rng)
    } else {
        SwarmMask::all_default()
    };

    let pick_window = |rng: &mut SimRng, min_dur: u64, max_dur: u64| -> (u64, u64) {
        let start = 500 + rng.gen_range_u64(32_000);
        let dur = min_dur + rng.gen_range_u64(max_dur - min_dur + 1);
        let end = (start + dur).min(duration_ms - 5_000);
        (start, end.max(start + 500))
    };

    let impair_prob = if flags.swarm { 95 } else { 55 };
    let part_prob = if flags.swarm { 95 } else { 65 };
    let bh_prob = if flags.swarm { 95 } else { 65 };
    let hang_prob = if flags.swarm { 95 } else { 50 };
    let restart_prob = if flags.swarm { 95 } else { 60 };
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
    let mut blackhole = (mask.blackhole && rng.chance_pct(bh_prob)).then(|| {
        let (s, e) = pick_window(rng, 3_000, 40_000);
        (rng.gen_range_u64(3) as usize, s, e)
    });
    let mut hang = (mask.hang && rng.chance_pct(hang_prob)).then(|| {
        let site = if allow_gather_hang && rng.chance_pct(35) {
            HangSite::GatherCandidates
        } else if rng.chance_pct(50) {
            HangSite::HttpGetJson
        } else {
            HangSite::DirectRace
        };
        let at_ms = 500 + rng.gen_range_u64(42_000);
        let dur = 1_100 + rng.gen_range_u64(2_400);
        (rng.gen_range_u64(3) as usize, site, at_ms, dur)
    });
    let mut restart = (mask.restart && rng.chance_pct(restart_prob)).then(|| {
        let k = 2_000 + rng.gen_range_u64(35_000);
        let gap = 1_000 + rng.gen_range_u64(6_000);
        (rng.gen_range_u64(3) as usize, k, (k + gap).min(duration_ms - 5_000))
    });
    let mut status_query = (mask.status_query && rng.chance_pct(status_prob)).then(|| {
        let node = rng.gen_range_u64(3) as usize;
        let mut at = 4_000 + rng.gen_range_u64(48_000);
        if let Some((rn, k, r)) = restart {
            if rn == node && at >= k.saturating_sub(200) && at <= r.saturating_add(500) {
                at = (r + 1_000).min(duration_ms - 2_000);
            }
        }
        (node, at)
    });

    let mut semantic_faults = Vec::new();
    if flags.semantic && rng.chance_pct(65) {
        if let Some((bh_idx, _, _)) = blackhole {
            let bh_node = NODE_NAMES[bh_idx % 3].to_string();
            blackhole = None;
            semantic_faults.push(SemanticFault {
                trigger: SemanticTrigger::OnEvent {
                    node: Some(bh_node.clone()),
                    event: ProtoEvent::SigConnected,
                    nth: 1,
                },
                delay_ms: 40 + rng.gen_range_u64(160),
                action: SemanticAction::ApplyFault(Fault::BlackholeSignaling {
                    node: bh_node.clone(),
                    active: true,
                }),
            });
            let boundary = if rng.chance_pct(60) { 15_000 } else { 30_000 };
            let jitter = (rng.gen_range_u64(801) as i64) - 400;
            semantic_faults.push(SemanticFault {
                trigger: SemanticTrigger::OnSilenceBoundary {
                    node: bh_node.clone(),
                    boundary_ms: boundary,
                    jitter_ms: jitter,
                },
                delay_ms: 0,
                action: SemanticAction::HealBlackhole {
                    node: bh_node.clone(),
                },
            });
            if status_query.is_some() {
                status_query = None;
                if rng.chance_pct(60) {
                    semantic_faults.push(SemanticFault {
                        trigger: SemanticTrigger::OnEvent {
                            node: Some(bh_node.clone()),
                            event: ProtoEvent::SigBlackholeHealed,
                            nth: 1,
                        },
                        delay_ms: 40 + rng.gen_range_u64(200),
                        action: SemanticAction::QueryCapStatus {
                            node: bh_node.clone(),
                        },
                    });
                } else {
                    semantic_faults.push(SemanticFault {
                        trigger: SemanticTrigger::OnEvent {
                            node: Some(bh_node.clone()),
                            event: ProtoEvent::SigHeartbeatUnderBlackhole,
                            nth: 1,
                        },
                        delay_ms: 40 + rng.gen_range_u64(200),
                        action: SemanticAction::QueryCapStatus {
                            node: bh_node.clone(),
                        },
                    });
                }
            }
            if restart.is_some() && rng.chance_pct(50) {
                restart = None;
                let rnode = NODE_NAMES[rng.gen_range_u64(3) as usize].to_string();
                let down_ms = 1_200 + rng.gen_range_u64(2_800);
                semantic_faults.push(SemanticFault {
                    trigger: SemanticTrigger::OnEvent {
                        node: None,
                        event: ProtoEvent::SigHeartbeatUnderBlackhole,
                        nth: 1,
                    },
                    delay_ms: 50 + rng.gen_range_u64(300),
                    action: SemanticAction::RestartPeer {
                        node: rnode,
                        down_ms,
                    },
                });
            }
        } else if allow_gather_hang {
            if let Some((hn, HangSite::GatherCandidates, _, dur)) = hang {
                let hnode = NODE_NAMES[hn % 3].to_string();
                hang = None;
                semantic_faults.push(SemanticFault {
                    trigger: SemanticTrigger::OnEvent {
                        node: Some(hnode.clone()),
                        event: ProtoEvent::SigConnected,
                        nth: 1,
                    },
                    delay_ms: 20,
                    action: SemanticAction::ApplyFault(Fault::Hang {
                        node: hnode,
                        site: HangSite::GatherCandidates,
                        duration_ms: dur,
                    }),
                });
            }
        }
    }

    let msg_chaos = (flags.message_chaos && rng.chance_pct(75)).then(|| {
        let policy = MessageChaosPolicy {
            drop_pct: (5 + rng.gen_range_u64(21)) as u8,
            duplicate_pct: (10 + rng.gen_range_u64(26)) as u8,
            reorder_max_delay_ms: 40 + rng.gen_range_u64(280),
        };
        let start = rng.gen_range_u64(4_000);
        let end = (start + 15_000 + rng.gen_range_u64(35_000)).min(duration_ms - 5_000);
        (policy, start, end.max(start + 1_000))
    });

    let mut sched = FuzzSchedule {
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
        msg_chaos,
        semantic_faults,
        reach: None,
    };
    if reach {
        // Its own stream, so the draws above are the same with or without it.
        let mut r = SimRng::new(rng.next_u64());
        sched.reach = Some(draw_reach(&mut r, flags, duration_ms));
    }
    sched
}

fn mutate_schedule(
    base: &FuzzSchedule,
    rng: &mut SimRng,
    flags: &GuideFlags,
    allow_gather_hang: bool,
    reach: bool,
) -> FuzzSchedule {
    let mut s = base.clone();
    s.sim_seed = rng.next_u64();
    let fresh = generate_schedule(rng, flags, allow_gather_hang, reach);
    if reach && rng.chance_pct(30) {
        s.reach = fresh.reach.clone();
    }

    // Perform 1 targeted structural/timing mutation per child.
    match rng.gen_range_u64(8) {
        0 => s.impair_range = fresh.impair_range,
        1 => {
            if flags.swarm && rng.chance_pct(45) {
                s.partition = None;
            } else {
                s.partition = fresh.partition;
            }
        }
        2 => {
            if let Some((node, start, end)) = s.blackhole {
                let dur = end
                    .saturating_sub(start)
                    .saturating_add(rng.gen_range_u64(6_000))
                    .saturating_sub(3_000)
                    .clamp(3_000, 40_000);
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
        5 => {
            let node = rng.gen_range_u64(3) as usize;
            let mut at = 4_000 + rng.gen_range_u64(48_000);
            if let Some((rn, k, r)) = s.restart {
                if rn == node && at >= k.saturating_sub(200) && at <= r.saturating_add(500) {
                    at = (r + 1_000).min(s.duration_ms - 2_000);
                }
            }
            s.status_query = Some((node, at));
        }
        6 => s.semantic_faults = fresh.semantic_faults,
        _ => s.msg_chaos = fresh.msg_chaos,
    }
    if flags.swarm && rng.chance_pct(35) {
        s.partition = None;
        s.impair_range = None;
    }
    s
}

fn select_parent_idx(
    corpus: &[CorpusEntry],
    edge_counts: &BTreeMap<StateEdge, usize>,
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
            if flags.semantic {
                let edge_rarity: u64 = entry
                    .edges
                    .iter()
                    .map(|e| {
                        let c = edge_counts.get(e).copied().unwrap_or(1).max(1) as u64;
                        5_000 / c.saturating_mul(c).max(1)
                    })
                    .sum();
                w = w.saturating_add(edge_rarity);
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

#[derive(Default)]
struct SharedFrontier {
    seen_edges: BTreeSet<StateEdge>,
    edge_counts: BTreeMap<StateEdge, usize>,
    corpus: Vec<CorpusEntry>,
}

impl SharedFrontier {
    fn warm_from_disk(campaign: &CampaignConfig) -> Arc<RwLock<Self>> {
        let mut f = Self::default();
        if let Some(ref dir) = campaign.corpus_dir {
            let (entries, seen, counts) =
                corpus::load_and_triage_corpus(dir, &campaign.mutant, campaign.quiet_logs);
            f.seen_edges = seen;
            f.edge_counts = counts;
            f.corpus = entries;
        }
        Arc::new(RwLock::new(f))
    }

    fn persist_if_configured(&self, dir: Option<&Path>) {
        if let Some(dir) = dir {
            let minimized = corpus::minimize_corpus(self.corpus.clone());
            let _ = corpus::save_minimized_corpus(dir, &minimized);
        }
    }
}

pub struct Fuzzer;

impl Fuzzer {
    pub fn run(campaign: &CampaignConfig) -> CampaignReport {
        let frontier = SharedFrontier::warm_from_disk(campaign);
        let mut rep = Self::run_with_stop(campaign, frontier.clone(), None);
        let guard = frontier.read().unwrap_or_else(|e| e.into_inner());
        guard.persist_if_configured(campaign.corpus_dir.as_deref());
        rep.state_edges = guard.seen_edges.clone();
        rep.state_edges_discovered = rep.state_edges.len();
        rep
    }

    pub fn run_parallel(campaign: &CampaignConfig, workers: usize) -> CampaignReport {
        let t0 = Instant::now();
        let workers = workers.max(1).min(campaign.max_runs.max(1));
        if workers == 1 {
            return Self::run(campaign);
        }
        let frontier = SharedFrontier::warm_from_disk(campaign);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let base_runs = campaign.max_runs / workers;
        let rem = campaign.max_runs % workers;

        let worker_reports: Vec<CampaignReport> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|w| {
                    let count = base_runs + usize::from(w < rem);
                    let mut sub = campaign.clone();
                    sub.seed = campaign.seed
                        ^ ((w as u64).wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                    sub.max_runs = count;
                    let stop = Arc::clone(&stop_flag);
                    let f_ref = Arc::clone(&frontier);
                    scope.spawn(move || Self::run_with_stop(&sub, f_ref, Some(&stop)))
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("fuzz worker panicked")).collect()
        });

        let mut merged = CampaignReport {
            runs_executed: 0,
            total_wall_ms: t0.elapsed().as_millis() as u64,
            findings: Vec::new(),
            milestone_counts: BTreeMap::new(),
            state_edges: BTreeSet::new(),
            state_edges_discovered: 0,
            antecedents_seen: BTreeSet::new(),
            max_iter_busy_ms_seen: 0,
            max_cap_status_latency_ms_seen: 0,
        };
        for rep in worker_reports {
            merged.runs_executed += rep.runs_executed;
            merged.max_iter_busy_ms_seen = merged.max_iter_busy_ms_seen.max(rep.max_iter_busy_ms_seen);
            merged.max_cap_status_latency_ms_seen = merged
                .max_cap_status_latency_ms_seen
                .max(rep.max_cap_status_latency_ms_seen);
            for (k, v) in rep.milestone_counts {
                *merged.milestone_counts.entry(k).or_insert(0) += v;
            }
            merged.antecedents_seen.extend(rep.antecedents_seen);
            if merged.findings.is_empty() || !campaign.stop_on_first_finding {
                merged.findings.extend(rep.findings);
            }
        }
        {
            let guard = frontier.read().unwrap_or_else(|e| e.into_inner());
            guard.persist_if_configured(campaign.corpus_dir.as_deref());
            merged.state_edges = guard.seen_edges.clone();
        }
        merged.state_edges_discovered = merged.state_edges.len();
        merged.total_wall_ms = t0.elapsed().as_millis() as u64;
        merged
    }

    pub fn replay_regressions(dir: &Path, mutant: SimMutant) -> Vec<Finding> {
        let t0 = Instant::now();
        let saved = corpus::load_regressions(dir);
        let mut findings = Vec::new();
        for (idx, (_path, doc)) in saved.into_iter().enumerate() {
            let mut cfg = doc.schedule.to_sim_config(mutant.clone());
            cfg.quiet_logs = false;
            let orig = SimWorld::run(cfg.clone());
            let violations = evaluate_oracles(&orig, &cfg);
            if !violations.is_empty() {
                let replay = SimWorld::run(cfg.clone());
                let replay_violations = evaluate_oracles(&replay, &cfg);
                let replay_verified =
                    replay.trace_hash == orig.trace_hash && !replay_violations.is_empty();
                assert!(
                    replay_verified,
                    "regression finding failed bit-exact replay! seed={} orig_hash={:#x} replay_hash={:#x}",
                    cfg.seed, orig.trace_hash, replay.trace_hash
                );
                findings.push(Finding {
                    label: "sim-only",
                    run_index: idx + 1,
                    wall_ms: t0.elapsed().as_millis() as u64,
                    seed: cfg.seed,
                    trace_hash: orig.trace_hash,
                    replay_verified,
                    violations,
                    schedule_summary: doc.schedule.summary(),
                });
            }
        }
        findings
    }

    fn run_with_stop(
        campaign: &CampaignConfig,
        frontier: Arc<RwLock<SharedFrontier>>,
        stop_flag: Option<&AtomicBool>,
    ) -> CampaignReport {
        let t0 = Instant::now();
        let mut rng = SimRng::new(campaign.seed);
        let mut findings = Vec::new();
        let mut milestone_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut antecedents_seen: BTreeSet<String> = BTreeSet::new();
        let mut max_iter_busy_ms_seen = 0u64;
        let mut max_cap_status_latency_ms_seen = 0u64;
        let mut runs_executed = 0usize;

        let corpus_active = campaign.flags.semantic;

        for run_idx in 0..campaign.max_runs {
            if stop_flag.is_some_and(|f| f.load(Ordering::Acquire)) {
                break;
            }
            runs_executed = run_idx + 1;
            let parent_sched = if corpus_active && rng.chance_pct(40) {
                let f = frontier.read().unwrap_or_else(|e| e.into_inner());
                if f.corpus.is_empty() {
                    None
                } else {
                    let idx = select_parent_idx(
                        &f.corpus,
                        &f.edge_counts,
                        &mut rng,
                        &campaign.flags,
                    );
                    Some(f.corpus[idx].sched.clone())
                }
            } else {
                None
            };
            let sched = match parent_sched {
                Some(ref base) => mutate_schedule(
                    base,
                    &mut rng,
                    &campaign.flags,
                    campaign.allow_gather_hang,
                    campaign.reach,
                ),
                None => generate_schedule(
                    &mut rng,
                    &campaign.flags,
                    campaign.allow_gather_hang,
                    campaign.reach,
                ),
            };
            let mut cfg = sched.to_sim_config(campaign.mutant.clone());
            cfg.quiet_logs = campaign.quiet_logs;
            let outcome: SimOutcome = SimWorld::run(cfg.clone());

            let mut hit_set = BTreeSet::new();
            for (k, v) in &outcome.assertions.sometimes_hits {
                if *v > 0 {
                    hit_set.insert(k.clone());
                    *milestone_counts.entry(k.clone()).or_insert(0) += 1;
                }
            }
            max_iter_busy_ms_seen = max_iter_busy_ms_seen.max(outcome.telemetry.max_iter_busy_ms);
            for st in &outcome.cap_status_results {
                max_cap_status_latency_ms_seen = max_cap_status_latency_ms_seen.max(st.latency_ms);
            }

            {
                let mut f = frontier.write().unwrap_or_else(|e| e.into_inner());
                let mut discovered_new_edge = false;
                for edge in &outcome.state_edges {
                    if f.seen_edges.insert(*edge) {
                        discovered_new_edge = true;
                    }
                    *f.edge_counts.entry(*edge).or_insert(0) += 1;
                }
                if (campaign.flags.semantic || campaign.corpus_dir.is_some())
                    && discovered_new_edge
                {
                    if f.corpus.len() >= 128 {
                        f.corpus.remove(0);
                    }
                    f.corpus.push(CorpusEntry {
                        sched: sched.clone(),
                        milestones: hit_set,
                        edges: outcome.state_edges.clone(),
                        score: 0,
                    });
                }
            }

            let violations = evaluate_oracles(&outcome, &cfg);
            let post_eval = take_assertions();
            antecedents_seen.extend(outcome.assertions.antecedents_seen.iter().cloned());
            antecedents_seen.extend(post_eval.antecedents_seen.iter().cloned());
            if !violations.is_empty() {
                // Verify bit-exact deterministic replay with full logging before reporting.
                let mut full_cfg = cfg.clone();
                full_cfg.quiet_logs = false;
                let full_orig = if cfg.quiet_logs {
                    SimWorld::run(full_cfg.clone())
                } else {
                    outcome.clone()
                };
                let replay = SimWorld::run(full_cfg.clone());
                let replay_violations = evaluate_oracles(&replay, &full_cfg);
                let replay_verified = replay.trace_hash == full_orig.trace_hash
                    && !replay_violations.is_empty();
                let finding_kinds: BTreeSet<_> =
                    violations.iter().map(|v| format!("{:?}", v.kind)).collect();
                if !replay_verified {
                    eprintln!(
                        "REPLAY_DIFF: orig_ev={} replay_ev={} orig_net={} replay_net={}",
                        full_orig.events.len(),
                        replay.events.len(),
                        full_orig.net_events.len(),
                        replay.net_events.len()
                    );
                    for i in 0..full_orig.events.len().min(replay.events.len()) {
                        if full_orig.events[i] != replay.events[i] {
                            eprintln!("FIRST_EV_DIFF[{i}]: orig={:?} replay={:?}", full_orig.events[i], replay.events[i]);
                            break;
                        }
                    }
                    for i in 0..full_orig.net_events.len().min(replay.net_events.len()) {
                        if full_orig.net_events[i].at_ms != replay.net_events[i].at_ms
                            || full_orig.net_events[i].event != replay.net_events[i].event
                        {
                            eprintln!("FIRST_NET_DIFF[{i}]: orig={:?} replay={:?}", full_orig.net_events[i], replay.net_events[i]);
                            break;
                        }
                    }
                }
                assert!(
                    replay_verified,
                    "DST finding failed bit-exact replay! seed={} orig_hash={:#x} replay_hash={:#x} kinds={:?}",
                    full_cfg.seed, full_orig.trace_hash, replay.trace_hash, finding_kinds
                );
                if let Some(ref rdir) = campaign.regressions_dir {
                    let _ = corpus::save_regression(rdir, "sim-only", full_orig.trace_hash, &sched);
                }
                findings.push(Finding {
                    label: "sim-only",
                    run_index: run_idx + 1,
                    wall_ms: t0.elapsed().as_millis() as u64,
                    seed: full_cfg.seed,
                    trace_hash: full_orig.trace_hash,
                    replay_verified,
                    violations,
                    schedule_summary: sched.summary(),
                });
                if campaign.stop_on_first_finding {
                    if let Some(f) = stop_flag {
                        f.store(true, Ordering::Release);
                    }
                    break;
                }
            }
        }

        let (state_edges, state_edges_discovered) = {
            let f = frontier.read().unwrap_or_else(|e| e.into_inner());
            (f.seen_edges.clone(), f.seen_edges.len())
        };
        CampaignReport {
            runs_executed,
            total_wall_ms: t0.elapsed().as_millis() as u64,
            findings,
            milestone_counts,
            state_edges,
            state_edges_discovered,
            antecedents_seen,
            max_iter_busy_ms_seen,
            max_cap_status_latency_ms_seen,
        }
    }
}
