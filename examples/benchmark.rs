use std::{env, fs, time::Instant};

use serde::Serialize;
use telosieve::{certificate::Decision, protocol::Scenario, run_scenario};

#[derive(Serialize)]
struct ResultRow {
    scenario: String,
    iterations: usize,
    latency_micros_p50: u128,
    latency_micros_p95: u128,
    hypothesis_count: usize,
    certificate_bytes: usize,
    decision: Decision,
    unsafe_approvals: usize,
    false_refusals: usize,
    baseline_unsafe_approvals: usize,
}

fn main() {
    let iterations = 20;
    let mut rows = Vec::new();
    for path in env::args().skip(1) {
        let scenario: Scenario = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut timings = Vec::with_capacity(iterations);
        let mut certificate = None;
        for _ in 0..iterations {
            let started = Instant::now();
            certificate = Some(run_scenario(&scenario).unwrap());
            timings.push(started.elapsed().as_micros());
        }
        timings.sort_unstable();
        let certificate = certificate.unwrap();
        rows.push(ResultRow {
            scenario: scenario.scenario_id,
            iterations,
            latency_micros_p50: timings[iterations / 2],
            latency_micros_p95: timings[iterations * 95 / 100],
            hypothesis_count: certificate.metrics.hypothesis_count,
            certificate_bytes: serde_json::to_vec(&certificate).unwrap().len(),
            decision: certificate.decision,
            unsafe_approvals: certificate.metrics.unsafe_approvals,
            false_refusals: certificate.metrics.false_refusals,
            baseline_unsafe_approvals: certificate
                .baselines
                .iter()
                .filter(|baseline| baseline.unsafe_approval)
                .count(),
        });
    }
    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
}
