#![cfg(feature = "sim")]

use std::time::Instant;

use filament_peerloop::sim::{
    Fault, NodeSpec, Proto, ScheduledFault, SimConfig, SimMutant, SimWorld,
};

fn two_node_config(seed: u64, duration_ms: u64) -> SimConfig {
    let secret = "sim-shared-secret-alpha-bravo".to_string();
    SimConfig {
        seed,
        duration_ms,
        nodes: vec![
            NodeSpec {
                name: "alpha".to_string(),
                uid: "uid-alpha".to_string(),
                peers: vec![("bravo".to_string(), secret.clone())],
            },
            NodeSpec {
                name: "bravo".to_string(),
                uid: "uid-bravo".to_string(),
                peers: vec![("alpha".to_string(), secret)],
            },
        ],
        schedule: Vec::new(),
        restart_node: None,
        cap_status_queries: vec![("alpha".to_string(), 6_000)],
        inline_stall_injection: None,
        mutant: SimMutant::None,
        ..Default::default()
    }
}

#[test]
fn test_two_daemon_connect_and_determinism() {
    let cfg = two_node_config(42, 8_000);
    let run1 = SimWorld::run(cfg.clone());
    let run2 = SimWorld::run(cfg);

    assert!(
        run1.budget_violations.is_empty(),
        "unexpected budget violations: {:?}",
        run1.budget_violations
    );
    assert!(
        run1.events
            .iter()
            .any(|e| e.message.contains("known device") && e.message.contains("connecting")),
        "expected known-device connection attempt in trace, got {} events: {:?}",
        run1.events.len(),
        run1.events
    );
    assert!(
        run1.cap_status_results
            .iter()
            .any(|r| r.response["ok"] == true),
        "expected CapStatus ok:true, got {:?}",
        run1.cap_status_results
    );
    assert_eq!(
        run1.events, run2.events,
        "same seed must produce identical log events"
    );
    assert_eq!(
        run1.trace_hash, run2.trace_hash,
        "same seed must produce bit-exact trace hash"
    );
}

#[test]
fn test_replay_loop_stall_under_loss() {
    // Replays fuzz/chaos/corpus/loop-stall-under-loss-debug.json (seed 391743414)
    let mut cfg = two_node_config(391_743_414, 48_000);
    cfg.schedule = vec![
        ScheduledFault {
            at_ms: 0,
            fault: Fault::Impair {
                node: "bravo".to_string(),
                delay_ms: 80,
                jitter_ms: 50,
                loss_pct: 30,
            },
        },
        ScheduledFault {
            at_ms: 5_400,
            fault: Fault::Partition {
                a: "alpha".to_string(),
                b: "bravo".to_string(),
                proto: Proto::All,
            },
        },
        ScheduledFault {
            at_ms: 7_500,
            fault: Fault::HealPartition {
                a: "alpha".to_string(),
                b: "bravo".to_string(),
            },
        },
        ScheduledFault {
            at_ms: 45_000,
            fault: Fault::ClearImpair {
                node: "bravo".to_string(),
            },
        },
    ];
    cfg.cap_status_queries = vec![("bravo".to_string(), 10_000), ("alpha".to_string(), 20_000)];

    let outcome = SimWorld::run(cfg);
    assert!(
        outcome.budget_violations.is_empty(),
        "loop stall regression under loss: {:?}",
        outcome.budget_violations
    );
    assert_eq!(outcome.cap_status_results.len(), 2);
    for res in &outcome.cap_status_results {
        assert_eq!(res.response["ok"], true, "cap status failed: {res:?}");
        assert!(
            res.latency_ms < 1_000,
            "cap status stalled {}ms on {}",
            res.latency_ms,
            res.node
        );
    }
}

#[test]
fn test_replay_status_stall_blackhole_plus_peer_restart() {
    // Replays fuzz/chaos/corpus/status-stall-blackhole-plus-peer-restart.json (seed 950782088)
    let sec_ab = "sim-sec-alpha-bravo".to_string();
    let sec_ac = "sim-sec-alpha-charlie".to_string();
    let sec_bc = "sim-sec-bravo-charlie".to_string();
    let cfg = SimConfig {
        seed: 950_782_088,
        duration_ms: 60_000,
        nodes: vec![
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
        ],
        schedule: vec![
            ScheduledFault {
                at_ms: 900,
                fault: Fault::Partition {
                    a: "alpha".to_string(),
                    b: "charlie".to_string(),
                    proto: Proto::Udp,
                },
            },
            ScheduledFault {
                at_ms: 4_900,
                fault: Fault::BlackholeSignaling {
                    node: "charlie".to_string(),
                    active: true,
                },
            },
            ScheduledFault {
                at_ms: 8_700,
                fault: Fault::HealPartition {
                    a: "alpha".to_string(),
                    b: "charlie".to_string(),
                },
            },
            ScheduledFault {
                at_ms: 54_600,
                fault: Fault::BlackholeSignaling {
                    node: "charlie".to_string(),
                    active: false,
                },
            },
        ],
        restart_node: Some(("bravo".to_string(), 18_500, 21_800)),
        cap_status_queries: vec![("charlie".to_string(), 39_100)],
        inline_stall_injection: None,
        mutant: SimMutant::None,
        ..Default::default()
    };

    let outcome = SimWorld::run(cfg);
    assert!(
        outcome.budget_violations.is_empty(),
        "loop stall detected under blackhole+restart: {:?}",
        outcome.budget_violations
    );
    assert_eq!(outcome.cap_status_results.len(), 1);
    let st = &outcome.cap_status_results[0];
    assert_eq!(st.response["ok"], true, "status failed: {st:?}");
    assert!(
        st.latency_ms < 1_000,
        "status on blackholed charlie stalled {}ms",
        st.latency_ms
    );
}

#[test]
fn test_oracle_catches_injected_inline_stall() {
    let mut cfg = two_node_config(777, 10_000);
    cfg.inline_stall_injection = Some((2_000, 1_500));
    let outcome = SimWorld::run(cfg);
    assert!(
        !outcome.budget_violations.is_empty(),
        "expected LOOP-BUDGET-EXCEEDED oracle violation, got 0 violations; events={:?}",
        outcome.events
    );
    assert!(
        outcome
            .budget_violations
            .iter()
            .any(|v| v.contains("LOOP-BUDGET-EXCEEDED") && v.contains("budget_ms=1000")),
        "unexpected oracle format: {:?}",
        outcome.budget_violations
    );
}

#[test]
fn test_throughput_benchmark() {
    const RUNS: usize = 100;
    let t0 = Instant::now();
    for i in 0..RUNS {
        let cfg = two_node_config(10_000 + i as u64, 5_000);
        let outcome = SimWorld::run(cfg);
        assert!(
            outcome.budget_violations.is_empty(),
            "run {i} had violations: {:?}",
            outcome.budget_violations
        );
    }
    let elapsed = t0.elapsed();
    let runs_per_sec = RUNS as f64 / elapsed.as_secs_f64();
    println!(
        "DST_BENCHMARK: runs={} wall_ms={} runs_per_sec={:.2}",
        RUNS,
        elapsed.as_millis(),
        runs_per_sec
    );
    assert!(runs_per_sec > 5.0, "too slow: {runs_per_sec:.2} runs/sec");
}
