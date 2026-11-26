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

#[derive(Clone, Copy)]
struct BenchCell {
    detected: usize,
    mean_runs: f64,
    median_runs: f64,
    mean_ms: f64,
}

fn eval_cell(flags: &GuideFlags, mutant: &SimMutant, allow_gather_hang: bool, max_runs: usize) -> BenchCell {
    let mut runs_vec = Vec::with_capacity(SEEDS.len());
    let mut ms_vec = Vec::with_capacity(SEEDS.len());
    let mut detected = 0usize;

    for &seed in &SEEDS {
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
    let mean_runs = runs_vec.iter().sum::<f64>() / SEEDS.len() as f64;
    let median_runs = sorted[SEEDS.len() / 2];
    let mean_ms = ms_vec.iter().sum::<f64>() / SEEDS.len() as f64;
    BenchCell {
        detected,
        mean_runs,
        median_runs,
        mean_ms,
    }
}

fn run_matrix(targets: &[(&str, SimMutant, bool)], max_runs: usize) {
    let guides: [(&str, GuideFlags); 7] = [
        ("unguided", GuideFlags::unguided()),
        ("swarm", GuideFlags::swarm_only()),
        ("semantic", GuideFlags::semantic_only()),
        ("swarm_semantic", GuideFlags::swarm_semantic()),
        ("message_chaos", GuideFlags::message_chaos_only()),
        ("full_semantic", GuideFlags::full_semantic()),
        ("married", GuideFlags::married()),
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
        ("gather_live_main", SimMutant::None, true),
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
fn test_real_pre729_campaign_hook() {
    let targets = [("real_pre729_source_revert", SimMutant::None, false)];
    run_matrix(&targets, 30);
}
