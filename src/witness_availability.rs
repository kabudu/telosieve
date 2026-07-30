use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAX_DISTRIBUTION_ATTEMPTS: usize = 3;
pub const MAX_DISTRIBUTION_PROVIDERS: usize = 2;
pub const MAX_DISTRIBUTION_BUDGET_MS: u64 = 250;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderResponse {
    Artifact {
        provider: String,
        digest: String,
        delay_ms: u64,
    },
    Unavailable {
        provider: String,
        delay_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityOutcome {
    Available,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityMeasurement {
    pub profile: String,
    pub outcome: AvailabilityOutcome,
    pub attempts: usize,
    pub elapsed_ms: u64,
    pub reason: String,
}

/// Evaluates a deterministic bounded distribution trace.
///
/// The trace models provider replies without sleeping or performing network I/O.
/// It is a reproducible availability experiment, not a production client.
#[must_use]
pub fn measure_distribution(
    profile: &str,
    expected_digest: &str,
    trace: &[ProviderResponse],
) -> AvailabilityMeasurement {
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return measurement(
            profile,
            AvailabilityOutcome::Refused,
            0,
            0,
            "invalid_expected_digest",
        );
    }
    let mut elapsed_ms = 0_u64;
    let mut providers = BTreeSet::new();
    for (index, response) in trace.iter().take(MAX_DISTRIBUTION_ATTEMPTS).enumerate() {
        let (provider, delay) = match response {
            ProviderResponse::Artifact {
                provider, delay_ms, ..
            }
            | ProviderResponse::Unavailable { provider, delay_ms } => (provider, *delay_ms),
        };
        providers.insert(provider);
        elapsed_ms = elapsed_ms.saturating_add(delay);
        let attempts = index + 1;
        if providers.len() > MAX_DISTRIBUTION_PROVIDERS {
            return measurement(
                profile,
                AvailabilityOutcome::Refused,
                attempts,
                elapsed_ms,
                "provider_bound_exceeded",
            );
        }
        if elapsed_ms > MAX_DISTRIBUTION_BUDGET_MS {
            return measurement(
                profile,
                AvailabilityOutcome::Refused,
                attempts,
                elapsed_ms,
                "budget_exhausted",
            );
        }
        if let ProviderResponse::Artifact { digest, .. } = response {
            return if digest == expected_digest {
                measurement(
                    profile,
                    AvailabilityOutcome::Available,
                    attempts,
                    elapsed_ms,
                    "exact_artifact",
                )
            } else {
                measurement(
                    profile,
                    AvailabilityOutcome::Refused,
                    attempts,
                    elapsed_ms,
                    "equivocation",
                )
            };
        }
    }
    measurement(
        profile,
        AvailabilityOutcome::Refused,
        trace.len().min(MAX_DISTRIBUTION_ATTEMPTS),
        elapsed_ms,
        "unavailable",
    )
}

#[must_use]
pub fn qualification_matrix() -> Vec<AvailabilityMeasurement> {
    let expected = "a".repeat(64);
    let other = "b".repeat(64);
    vec![
        measure_distribution(
            "nominal",
            &expected,
            &[ProviderResponse::Artifact {
                provider: "timestamp-a".into(),
                digest: expected.clone(),
                delay_ms: 10,
            }],
        ),
        measure_distribution(
            "bounded-delay",
            &expected,
            &[ProviderResponse::Artifact {
                provider: "timestamp-a".into(),
                digest: expected.clone(),
                delay_ms: 249,
            }],
        ),
        measure_distribution(
            "one-sided-partition",
            &expected,
            &[
                ProviderResponse::Unavailable {
                    provider: "timestamp-a".into(),
                    delay_ms: 50,
                },
                ProviderResponse::Artifact {
                    provider: "timestamp-b".into(),
                    digest: expected.clone(),
                    delay_ms: 50,
                },
            ],
        ),
        measure_distribution(
            "loss-exhaustion",
            &expected,
            &[
                ProviderResponse::Unavailable {
                    provider: "timestamp-a".into(),
                    delay_ms: 25,
                },
                ProviderResponse::Unavailable {
                    provider: "timestamp-b".into(),
                    delay_ms: 25,
                },
                ProviderResponse::Unavailable {
                    provider: "timestamp-a".into(),
                    delay_ms: 25,
                },
            ],
        ),
        measure_distribution(
            "authority-outage",
            &expected,
            &[
                ProviderResponse::Unavailable {
                    provider: "timestamp-a".into(),
                    delay_ms: 100,
                },
                ProviderResponse::Unavailable {
                    provider: "timestamp-b".into(),
                    delay_ms: 100,
                },
            ],
        ),
        measure_distribution(
            "over-budget-delay",
            &expected,
            &[ProviderResponse::Artifact {
                provider: "timestamp-a".into(),
                digest: expected.clone(),
                delay_ms: 251,
            }],
        ),
        measure_distribution(
            "equivocal-artifact",
            &expected,
            &[ProviderResponse::Artifact {
                provider: "timestamp-a".into(),
                digest: other,
                delay_ms: 10,
            }],
        ),
    ]
}

fn measurement(
    profile: &str,
    outcome: AvailabilityOutcome,
    attempts: usize,
    elapsed_ms: u64,
    reason: &str,
) -> AvailabilityMeasurement {
    AvailabilityMeasurement {
        profile: profile.into(),
        outcome,
        attempts,
        elapsed_ms,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_preserves_bounded_availability_and_fail_closed_outages() {
        let matrix = qualification_matrix();
        assert_eq!(matrix.len(), 7);
        assert_eq!(
            matrix
                .iter()
                .filter(|result| result.outcome == AvailabilityOutcome::Available)
                .count(),
            3
        );
        assert!(
            matrix
                .iter()
                .all(|result| result.attempts <= MAX_DISTRIBUTION_ATTEMPTS)
        );
        assert!(matrix.iter().all(|result| {
            result.outcome == AvailabilityOutcome::Refused
                || result.elapsed_ms <= MAX_DISTRIBUTION_BUDGET_MS
        }));
        assert_eq!(matrix[2].reason, "exact_artifact");
        assert_eq!(matrix[3].reason, "unavailable");
        assert_eq!(matrix[5].reason, "budget_exhausted");
        assert_eq!(matrix[6].reason, "equivocation");
        assert_eq!(
            measure_distribution(
                "invalid-anchor",
                "not-a-digest",
                &[ProviderResponse::Artifact {
                    provider: "timestamp-a".into(),
                    digest: "not-a-digest".into(),
                    delay_ms: 1,
                }],
            )
            .reason,
            "invalid_expected_digest"
        );
    }
}
