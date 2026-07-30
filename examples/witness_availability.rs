use serde::Serialize;
use telosieve::witness_availability::{
    MAX_DISTRIBUTION_ATTEMPTS, MAX_DISTRIBUTION_BUDGET_MS, MAX_DISTRIBUTION_PROVIDERS,
    qualification_matrix,
};

#[derive(Serialize)]
struct ResultSet {
    schema_version: &'static str,
    model: &'static str,
    maximum_attempts: usize,
    maximum_providers: usize,
    maximum_budget_ms: u64,
    measurements: Vec<telosieve::witness_availability::AvailabilityMeasurement>,
}

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&ResultSet {
            schema_version: "telosieve.witness-availability/v1",
            model: "deterministic-scripted-distribution",
            maximum_attempts: MAX_DISTRIBUTION_ATTEMPTS,
            maximum_providers: MAX_DISTRIBUTION_PROVIDERS,
            maximum_budget_ms: MAX_DISTRIBUTION_BUDGET_MS,
            measurements: qualification_matrix(),
        })
        .expect("typed availability serialization cannot fail")
    );
}
