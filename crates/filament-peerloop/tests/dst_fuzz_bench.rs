#![cfg(feature = "sim")]

use filament_peerloop::sim::{CampaignConfig, Fuzzer, GuideFlags, SimMutant};

const SEEDS: [u64; 5] = [101, 202, 303, 404, 505];
const BUDGET_RUNS: usize = 40;

#[test]
fn test_clean_build_zero_false_positives() {
    let report = Fuzzer::run(&CampaignConfig {
        seed: 2026_11_25,
        max_runs: 40,
        stop_on_first_finding: false,
        flags: GuideFlags::full_semantic(),
        mutant: SimMutant::None,
        allow_gather_hang: false,
        ..Default::default()
    });
    println!(
        "CLEAN_BUILD_40_RUNS: findings={} wall_ms={} state_edges={} max_busy_ms={} max_status_ms={} antecedents={:?} milestones={:?}",
        report.findings.len(),
        report.total_wall_ms,
        report.state_edges_discovered,
        report.max_iter_busy_ms_seen,
        report.max_cap_status_latency_ms_seen,
        report.antecedents_seen,
        report.milestone_counts
    );
    assert!(
        report.findings.is_empty(),
        "clean build reported unexpected findings: {:?}",
        report.findings
    );
    assert!(
        report.state_edges_discovered >= 6,
        "expected full_semantic campaign to discover diverse state edges, got {}",
        report.state_edges_discovered
    );
    assert!(
        !report.antecedents_seen.is_empty(),
        "formal invariants were vacuous (no antecedents triggered)"
    );
    assert!(
        report.milestone_counts.len() >= 4,
        "expected full_semantic campaign to hit diverse sometimes! milestones, got {:?}",
        report.milestone_counts
    );
}

#[test]
fn test_canary_planted_bug_found_and_replays_bit_exact() {
    let report = Fuzzer::run(&CampaignConfig {
        seed: 7777,
        max_runs: 40,
        stop_on_first_finding: true,
        flags: GuideFlags::married(),
        mutant: SimMutant::CanaryOnBlackholeStatus,
        allow_gather_hang: false,
        ..Default::default()
    });
    assert!(
        !report.findings.is_empty(),
        "canary bug was not found within 40 runs"
    );
    let f = &report.findings[0];
    assert_eq!(f.label, "sim-only");
    assert!(f.replay_verified);
    println!(
        "CANARY_FOUND: run={} wall_ms={} label={} replay_verified={} violations={:?}",
        f.run_index, f.wall_ms, f.label, f.replay_verified, f.violations
    );
}

#[test]
fn test_parallel_throughput_benchmark() {
    const RUNS: usize = 120;
    let cfg = CampaignConfig {
        seed: 42_4242,
        max_runs: RUNS,
        stop_on_first_finding: false,
        flags: GuideFlags::married(),
        mutant: SimMutant::None,
        allow_gather_hang: false,
        quiet_logs: true,
        ..Default::default()
    };

    let single = Fuzzer::run(&cfg);
    let single_sec = (single.total_wall_ms as f64 / 1000.0).max(0.001);
    let single_rps = single.runs_executed as f64 / single_sec;
    let single_hrs_per_sec = single_rps * 60.0 / 3600.0;
    println!(
        "PARALLEL_THROUGHPUT: mode=single workers=1 runs={} wall_ms={} runs_per_sec={:.2} sim_hours_per_sec={:.3}",
        single.runs_executed, single.total_wall_ms, single_rps, single_hrs_per_sec
    );

    let workers = std::thread::available_parallelism()
        .map_or(2, |n| n.get().clamp(2, 4));
    let parallel = Fuzzer::run_parallel(&cfg, workers);
    let par_sec = (parallel.total_wall_ms as f64 / 1000.0).max(0.001);
    let par_rps = parallel.runs_executed as f64 / par_sec;
    let par_hrs_per_sec = par_rps * 60.0 / 3600.0;
    println!(
        "PARALLEL_THROUGHPUT: mode=parallel workers={} runs={} wall_ms={} runs_per_sec={:.2} sim_hours_per_sec={:.3}",
        workers, parallel.runs_executed, parallel.total_wall_ms, par_rps, par_hrs_per_sec
    );

    assert_eq!(single.runs_executed, RUNS);
    assert_eq!(parallel.runs_executed, RUNS);
    assert!(single.findings.is_empty(), "single clean findings: {:?}", single.findings);
    assert!(parallel.findings.is_empty(), "parallel clean findings: {:?}", parallel.findings);
}

#[test]
fn test_disk_corpus_persistence_minimize_and_regression_replay() {
    let base = std::env::temp_dir().join(format!("tunlion-dst-corpus-test-{}", std::process::id()));
    let corpus_dir = base.join("corpus");
    let reg_dir = base.join("regressions");
    let _ = std::fs::remove_dir_all(&base);

    let dir_stats = |d: &std::path::Path| -> (usize, u64) {
        let mut count = 0usize;
        let mut bytes = 0u64;
        if let Ok(rd) = std::fs::read_dir(d) {
            for ent in rd.flatten() {
                if ent.path().extension().is_some_and(|e| e == "json") {
                    count += 1;
                    if let Ok(m) = ent.metadata() {
                        bytes += m.len();
                    }
                }
            }
        }
        (count, bytes)
    };

    let rep1 = Fuzzer::run(&CampaignConfig {
        seed: 55_001,
        max_runs: 20,
        stop_on_first_finding: false,
        flags: GuideFlags::married(),
        mutant: SimMutant::None,
        allow_gather_hang: false,
        quiet_logs: true,
        corpus_dir: Some(corpus_dir.clone()),
        regressions_dir: None,
    });
    assert!(rep1.findings.is_empty(), "clean run1 findings: {:?}", rep1.findings);
    let (files1, bytes1) = dir_stats(&corpus_dir);
    println!(
        "PERSISTENCE_RUN1: files={} total_bytes={} state_edges={}",
        files1, bytes1, rep1.state_edges_discovered
    );
    assert!(files1 > 0 && files1 <= rep1.state_edges_discovered);

    // Plant a redundant copy of an existing seed to confirm set-cover pruning.
    let first_seed = std::fs::read_dir(&corpus_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("at least one seed file");
    let dup_path = corpus_dir.join("seed-duplicate-obsolete.json");
    std::fs::copy(&first_seed, &dup_path).unwrap();

    let rep2 = Fuzzer::run_parallel(
        &CampaignConfig {
            seed: 55_002,
            max_runs: 10,
            stop_on_first_finding: false,
            flags: GuideFlags::married(),
            mutant: SimMutant::None,
            allow_gather_hang: false,
            quiet_logs: true,
            corpus_dir: Some(corpus_dir.clone()),
            regressions_dir: None,
        },
        2,
    );
    assert!(rep2.findings.is_empty(), "clean run2 findings: {:?}", rep2.findings);
    let (files2, bytes2) = dir_stats(&corpus_dir);
    println!(
        "PERSISTENCE_RUN2: files={} total_bytes={} state_edges={}",
        files2, bytes2, rep2.state_edges_discovered
    );
    assert!(
        !dup_path.exists(),
        "set-cover minimization should prune duplicate obsolete seed"
    );

    let bug_rep = Fuzzer::run(&CampaignConfig {
        seed: 7777,
        max_runs: 40,
        stop_on_first_finding: true,
        flags: GuideFlags::married(),
        mutant: SimMutant::CanaryOnBlackholeStatus,
        allow_gather_hang: false,
        quiet_logs: false,
        corpus_dir: None,
        regressions_dir: Some(reg_dir.clone()),
    });
    assert!(!bug_rep.findings.is_empty(), "canary should trigger regression save");
    let (reg_files, reg_bytes) = dir_stats(&reg_dir);
    assert_eq!(reg_files, 1, "expected 1 saved regression file");

    let mut_replays = Fuzzer::replay_regressions(&reg_dir, SimMutant::CanaryOnBlackholeStatus);
    assert!(!mut_replays.is_empty(), "regression bank failed to reproduce canary bug");
    let clean_replays = Fuzzer::replay_regressions(&reg_dir, SimMutant::None);
    assert!(clean_replays.is_empty(), "clean build failed persisted regression: {:?}", clean_replays);
    println!(
        "REGRESSION_BANK: files={} total_bytes={} canary_replays={} clean_replays={}",
        reg_files, reg_bytes, mut_replays.len(), clean_replays.len()
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[derive(Clone, Copy)]
struct BenchCell {
    detected: usize,
    mean_runs: f64,
    median_runs: f64,
    mean_ms: f64,
}

fn eval_cell_seeds(
    seeds: &[u64],
    flags: &GuideFlags,
    mutant: &SimMutant,
    allow_gather_hang: bool,
    max_runs: usize,
) -> BenchCell {
    let mut runs_vec = Vec::with_capacity(seeds.len());
    let mut ms_vec = Vec::with_capacity(seeds.len());
    let mut detected = 0usize;

    for &seed in seeds {
        let rep = Fuzzer::run(&CampaignConfig {
            seed,
            max_runs,
            stop_on_first_finding: true,
            flags: flags.clone(),
            mutant: mutant.clone(),
            allow_gather_hang,
            ..Default::default()
        });
        if let Some(first_run) = rep.first_detection_run() {
            detected += 1;
            runs_vec.push(first_run as f64);
        } else {
            runs_vec.push((max_runs + 1) as f64);
        }
        ms_vec.push(rep.total_wall_ms as f64);
    }

    let mut sorted = runs_vec.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_runs = runs_vec.iter().sum::<f64>() / seeds.len() as f64;
    let median_runs = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    };
    let mean_ms = ms_vec.iter().sum::<f64>() / seeds.len() as f64;
    BenchCell {
        detected,
        mean_runs,
        median_runs,
        mean_ms,
    }
}

fn eval_cell(flags: &GuideFlags, mutant: &SimMutant, allow_gather_hang: bool, max_runs: usize) -> BenchCell {
    eval_cell_seeds(&SEEDS, flags, mutant, allow_gather_hang, max_runs)
}

fn run_matrix(targets: &[(&str, SimMutant, bool)], max_runs: usize) {
    let guides: [(&str, GuideFlags); 7] = [
        ("unguided", GuideFlags::unguided()),
        ("swarm", GuideFlags::swarm_only()),
        ("semantic", GuideFlags::semantic_only()),
        ("swarm_semantic", GuideFlags::swarm_semantic()),
        ("message_chaos", GuideFlags::message_chaos_only()),
        ("married", GuideFlags::married()),
        ("full_semantic", GuideFlags::full_semantic()),
    ];

    println!("| target | guide | detected | mean_runs | median_runs | mean_ms | speedup_vs_unguided |");
    println!("|---|---|---:|---:|---:|---:|---:|");

    for (t_name, mutant, allow_gather) in targets {
        let mut base_mean_runs = None;
        for (g_name, flags) in &guides {
            let cell = eval_cell(flags, mutant, *allow_gather, max_runs);
            let base = *base_mean_runs.get_or_insert(cell.mean_runs);
            let speedup = base / cell.mean_runs.max(0.01);
            println!(
                "| {} | {} | {}/{} | {:.2} | {:.1} | {:.1} | {:.2}x |",
                t_name,
                g_name,
                cell.detected,
                SEEDS.len(),
                cell.mean_runs,
                cell.median_runs,
                cell.mean_ms,
                speedup
            );
        }
    }
}

#[test]
fn test_guidance_benchmark_matrix() {
    let targets = [
        ("pre729_heartbeat", SimMutant::Pre729InlineHeartbeat, false),
        (
            "noise_sensitive_restart",
            SimMutant::NoiseSensitiveRestartInBlackhole,
            false,
        ),
        (
            "timer_edge_silence",
            SimMutant::TimerEdgeSilenceBoundary,
            false,
        ),
        ("post_heal_liveness", SimMutant::PostHealDroppedReconnect, false),
        ("reorder_glare", SimMutant::ReorderGlareViolation, false),
    ];
    run_matrix(&targets, BUDGET_RUNS);
}

#[ignore]
#[test]
fn test_clean_main_1000_runs_married() {
    const RUNS: usize = 1_000;
    // DST_CLEAN_GUIDE picks the guide (default `married`), so the same seed and
    // budget can be compared across guides for coverage and findings.
    let guide = std::env::var("DST_CLEAN_GUIDE").unwrap_or_else(|_| "married".to_string());
    let flags = match guide.as_str() {
        "married" => GuideFlags::married(),
        "unguided" => GuideFlags::unguided(),
        "swarm" => GuideFlags::swarm_only(),
        "message_chaos" => GuideFlags::message_chaos_only(),
        "semantic" => GuideFlags::semantic_only(),
        other => panic!("unknown DST_CLEAN_GUIDE {other}"),
    };
    let workers = std::thread::available_parallelism()
        .map_or(2, |n| n.get().clamp(2, 4));
    let report = Fuzzer::run_parallel(
        &CampaignConfig {
            seed: 2026_11_27,
            max_runs: RUNS,
            stop_on_first_finding: false,
            flags,
            mutant: SimMutant::None,
            allow_gather_hang: true,
            quiet_logs: true,
            ..Default::default()
        },
        workers,
    );
    println!(
        "CLEAN_MAIN_1000: guide={} runs={} workers={} findings={} wall_ms={} state_edges={} max_busy_ms={} max_status_ms={}",
        guide,
        report.runs_executed,
        workers,
        report.findings.len(),
        report.total_wall_ms,
        report.state_edges_discovered,
        report.max_iter_busy_ms_seen,
        report.max_cap_status_latency_ms_seen,
    );
    assert_eq!(report.runs_executed, RUNS);
    assert!(
        report.findings.is_empty(),
        "clean main reported unexpected findings: {:?}",
        report.findings
    );
}

#[ignore]
#[test]
fn test_real_bug_benchmark_hook() {
    let name = std::env::var("DST_REAL_TARGET").unwrap_or_else(|_| "real_bug".to_string());
    let allow_gather = std::env::var("DST_ALLOW_GATHER_HANG").as_deref() == Ok("1");
    let max_runs: usize = std::env::var("DST_MAX_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(BUDGET_RUNS);
    let num_seeds: usize = std::env::var("DST_NUM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SEEDS.len())
        .max(1);
    let extra_combos = std::env::var("DST_EXTRA_COMBOS").as_deref() == Ok("1");
    let seeds: Vec<u64> = (1..=num_seeds as u64).map(|i| i * 101).collect();
    let mut guides: Vec<(&str, GuideFlags)> = vec![
        ("unguided", GuideFlags::unguided()),
        ("swarm", GuideFlags::swarm_only()),
        ("semantic", GuideFlags::semantic_only()),
        ("message_chaos", GuideFlags::message_chaos_only()),
        ("married", GuideFlags::married()),
    ];
    if extra_combos {
        guides.push(("swarm_semantic", GuideFlags::swarm_semantic()));
        guides.push((
            "semantic_msg_chaos",
            GuideFlags {
                swarm: false,
                semantic: true,
                message_chaos: true,
            },
        ));
        guides.push((
            "swarm_msg_chaos",
            GuideFlags {
                swarm: true,
                semantic: false,
                message_chaos: true,
            },
        ));
    }
    println!("| target | guide | detected | mean_runs | median_runs | mean_ms | speedup_vs_unguided |");
    println!("|---|---|---:|---:|---:|---:|---:|");
    let mut base_mean_runs = None;
    for (g_name, flags) in &guides {
        let cell = eval_cell_seeds(&seeds, flags, &SimMutant::None, allow_gather, max_runs);
        let base = *base_mean_runs.get_or_insert(cell.mean_runs);
        let speedup = base / cell.mean_runs.max(0.01);
        println!(
            "| {} | {} | {}/{} | {:.2} | {:.1} | {:.1} | {:.2}x |",
            name,
            g_name,
            cell.detected,
            seeds.len(),
            cell.mean_runs,
            cell.median_runs,
            cell.mean_ms,
            speedup
        );
    }
}
