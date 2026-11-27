use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sim::fuzz::FuzzSchedule;
use crate::sim::semantic::StateEdge;
use crate::sim::world::{SimMutant, SimWorld};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSchedule {
    pub schema_version: u32,
    pub label: String,
    pub schedule: FuzzSchedule,
}

#[derive(Debug, Clone)]
pub struct CorpusEntry {
    pub sched: FuzzSchedule,
    pub milestones: BTreeSet<String>,
    pub edges: BTreeSet<StateEdge>,
    pub score: u64,
}

fn fnv1a64_bytes(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Greedy set-cover minimization over discovered `StateEdge`s.
/// Drops redundant or obsolete schedules that contribute zero uncovered edges.
pub fn minimize_corpus(mut entries: Vec<CorpusEntry>) -> Vec<CorpusEntry> {
    let mut uncovered: BTreeSet<StateEdge> = BTreeSet::new();
    for e in &entries {
        uncovered.extend(e.edges.iter().copied());
    }
    if uncovered.is_empty() {
        return Vec::new();
    }

    let mut selected = Vec::new();
    while !uncovered.is_empty() && !entries.is_empty() {
        let mut best_idx = None;
        let mut best_gain = 0usize;
        let mut best_key = (usize::MAX, u64::MAX);

        for (idx, entry) in entries.iter().enumerate() {
            let gain = entry.edges.iter().filter(|e| uncovered.contains(e)).count();
            let tie_key = (entry.sched.semantic_fault_count(), entry.sched.sim_seed);
            if gain > best_gain || (gain > 0 && gain == best_gain && tie_key < best_key) {
                best_gain = gain;
                best_key = tie_key;
                best_idx = Some(idx);
            }
        }

        let Some(idx) = best_idx else {
            break;
        };
        let chosen = entries.swap_remove(idx);
        for edge in &chosen.edges {
            uncovered.remove(edge);
        }
        selected.push(chosen);
    }
    selected
}

/// Loads persisted `seed-*.json` inputs, replays each against the current build
/// (never trusting stale coverage across code edits), and returns a minimized
/// active corpus plus fresh `seen_edges` and `edge_counts`.
pub fn load_and_triage_corpus(
    dir: &Path,
    mutant: &SimMutant,
    quiet_logs: bool,
) -> (Vec<CorpusEntry>, BTreeSet<StateEdge>, BTreeMap<StateEdge, usize>) {
    let mut seen_edges = BTreeSet::new();
    let mut edge_counts = BTreeMap::new();
    if !dir.exists() {
        return (Vec::new(), seen_edges, edge_counts);
    }

    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(_) => return (Vec::new(), seen_edges, edge_counts),
    };
    paths.sort();

    let mut loaded_entries = Vec::new();
    for path in paths {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(persisted) = serde_json::from_slice::<PersistedSchedule>(&bytes) else {
            continue;
        };
        if persisted.schema_version != SCHEMA_VERSION {
            continue;
        }
        let mut cfg = persisted.schedule.to_sim_config(mutant.clone());
        cfg.quiet_logs = quiet_logs;
        let outcome = SimWorld::run(cfg);
        for edge in &outcome.state_edges {
            seen_edges.insert(*edge);
            *edge_counts.entry(*edge).or_insert(0) += 1;
        }
        let mut milestones = BTreeSet::new();
        for (k, v) in outcome.assertions.sometimes_hits {
            if v > 0 {
                milestones.insert(k);
            }
        }
        loaded_entries.push(CorpusEntry {
            sched: persisted.schedule,
            milestones,
            edges: outcome.state_edges,
            score: 0,
        });
    }

    let minimized = minimize_corpus(loaded_entries);
    (minimized, seen_edges, edge_counts)
}

/// Persists the minimized corpus set as content-addressed `seed-<hash>.json`
/// files and prunes any redundant or obsolete `seed-*.json` files in `dir`.
pub fn save_minimized_corpus(dir: &Path, entries: &[CorpusEntry]) -> std::io::Result<usize> {
    fs::create_dir_all(dir)?;
    let mut keep_names = BTreeSet::new();
    for entry in entries {
        let doc = PersistedSchedule {
            schema_version: SCHEMA_VERSION,
            label: "corpus".to_string(),
            schedule: entry.sched.clone(),
        };
        let json = serde_json::to_vec_pretty(&doc)?;
        let hash = fnv1a64_bytes(&json);
        let name = format!("seed-{hash:016x}.json");
        let path = dir.join(&name);
        if !path.exists() {
            fs::write(&path, &json)?;
        }
        keep_names.insert(name);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("seed-") && !keep_names.contains(name) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    Ok(keep_names.len())
}

pub fn save_regression(
    dir: &Path,
    label: &str,
    trace_hash: u64,
    schedule: &FuzzSchedule,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let doc = PersistedSchedule {
        schema_version: SCHEMA_VERSION,
        label: label.to_string(),
        schedule: schedule.clone(),
    };
    let json = serde_json::to_vec_pretty(&doc)?;
    let path = dir.join(format!("finding-{trace_hash:016x}.json"));
    if !path.exists() {
        fs::write(&path, &json)?;
    }
    Ok(path)
}

pub fn load_regressions(dir: &Path) -> Vec<(PathBuf, PersistedSchedule)> {
    if !dir.exists() {
        return Vec::new();
    }
    let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(_) => return Vec::new(),
    };
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(persisted) = serde_json::from_slice::<PersistedSchedule>(&bytes) else {
            continue;
        };
        if persisted.schema_version == SCHEMA_VERSION {
            out.push((path, persisted));
        }
    }
    out
}
