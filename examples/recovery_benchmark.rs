use std::{
    fs,
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use telosieve::{
    actuator_store::LocalActuatorStore,
    protocol::{Scenario, verify},
};

const ITERATIONS: usize = 50;

#[derive(Serialize)]
struct OperationResult {
    iterations: usize,
    latency_micros_p50: u128,
    latency_micros_p95: u128,
}

#[derive(Serialize)]
struct BenchmarkResult {
    platform: String,
    architecture: String,
    state_bytes: u64,
    backup_bytes: u64,
    recover_consistent: OperationResult,
    backup_create: OperationResult,
    restore_latest: OperationResult,
}

fn summarize(mut timings: Vec<u128>) -> OperationResult {
    timings.sort_unstable();
    OperationResult {
        iterations: timings.len(),
        latency_micros_p50: timings[timings.len() / 2],
        latency_micros_p95: timings[timings.len() * 95 / 100],
    }
}

fn main() {
    let scenario_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "scenarios/benign.json".into());
    let scenario: Scenario =
        serde_json::from_slice(&fs::read(scenario_path).expect("scenario must be readable"))
            .expect("scenario must be valid JSON");
    let authorities = verify(&scenario).expect("scenario authorities must verify");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "telosieve-recovery-benchmark-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("benchmark directory must be creatable");
    let actuator_path = directory.join("actuator.json");
    let store = LocalActuatorStore::new(&actuator_path);
    store
        .initialize(&authorities.phenotype, &scenario.phenotype_history_anchor)
        .expect("actuator must initialize");

    let mut recover_timings = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        store.recover().expect("consistent recovery must pass");
        recover_timings.push(started.elapsed().as_micros());
    }

    let mut backup_timings = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let backup_path = directory.join(format!("backup-{index}.json"));
        let started = Instant::now();
        store.backup(&backup_path).expect("backup must succeed");
        backup_timings.push(started.elapsed().as_micros());
    }
    let restore_backup = directory.join("backup-0.json");
    let mut restore_timings = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        fs::remove_file(&actuator_path).expect("state removal must succeed");
        let started = Instant::now();
        store
            .restore(&restore_backup)
            .expect("latest restore must succeed");
        restore_timings.push(started.elapsed().as_micros());
    }

    let result = BenchmarkResult {
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        state_bytes: fs::metadata(&actuator_path).unwrap().len(),
        backup_bytes: fs::metadata(&restore_backup).unwrap().len(),
        recover_consistent: summarize(recover_timings),
        backup_create: summarize(backup_timings),
        restore_latest: summarize(restore_timings),
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    fs::remove_dir_all(Path::new(&directory)).expect("benchmark cleanup must succeed");
}
