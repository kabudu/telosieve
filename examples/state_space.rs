use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Value, json};
use telosieve::{
    certificate::Decision,
    model::digest,
    protocol::{
        AuthorityKind, Envelope, ExpectedDecision, FaultDeclaration, HistoryAnchor, SCHEMA_VERSION,
        Scenario,
    },
    run_scenario,
};

const SEEDS: std::ops::Range<u64> = 0..8;

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    kind: AuthorityKind,
    subject: &'a str,
    schema_version: &'a str,
    issued_at: u64,
    expires_at: u64,
    issuer: &'a str,
    sequence: u64,
    content_digest: &'a str,
    parent_digests: &'a [String],
    content: &'a Value,
}

#[derive(Clone, Copy)]
enum SuspicionProfile {
    ViabilityOnly,
    GoalAndViability,
}

impl SuspicionProfile {
    const ALL: [Self; 2] = [Self::ViabilityOnly, Self::GoalAndViability];

    fn name(self) -> &'static str {
        match self {
            Self::ViabilityOnly => "viability_only",
            Self::GoalAndViability => "goal_and_viability",
        }
    }

    fn suspectable(self) -> BTreeSet<AuthorityKind> {
        match self {
            Self::ViabilityOnly => BTreeSet::from([AuthorityKind::Viability]),
            Self::GoalAndViability => {
                BTreeSet::from([AuthorityKind::Goal, AuthorityKind::Viability])
            }
        }
    }
}

#[derive(Default, Serialize)]
struct Counts {
    scenarios: usize,
    expected_apply: usize,
    expected_refuse: usize,
    applied: usize,
    refused: usize,
    unsafe_approvals: usize,
    false_refusals: usize,
}

#[derive(Serialize)]
struct Cell {
    suspicion_profile: &'static str,
    maximum_faults: usize,
    phenotype: &'static str,
    lab_domain: &'static str,
    review_domain: &'static str,
    counts: Counts,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    generator: &'static str,
    seeds: usize,
    dimensions: BTreeMap<&'static str, Vec<&'static str>>,
    total: Counts,
    cells: Vec<Cell>,
    conclusions: Vec<&'static str>,
}

fn envelope(
    key: &SigningKey,
    kind: AuthorityKind,
    issuer: &str,
    content: Value,
    sequence: u64,
    parent_digests: Vec<String>,
) -> Envelope {
    let mut envelope = Envelope {
        kind,
        subject: "kv/research".into(),
        schema_version: SCHEMA_VERSION.into(),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
        issuer: issuer.into(),
        sequence,
        content_digest: digest(&content),
        parent_digests,
        content,
        signature: String::new(),
    };
    let bytes = serde_json::to_vec(&UnsignedEnvelope {
        kind: envelope.kind,
        subject: &envelope.subject,
        schema_version: &envelope.schema_version,
        issued_at: envelope.issued_at,
        expires_at: envelope.expires_at,
        issuer: &envelope.issuer,
        sequence: envelope.sequence,
        content_digest: &envelope.content_digest,
        parent_digests: &envelope.parent_digests,
        content: &envelope.content,
    })
    .expect("typed envelope serialization");
    envelope.signature = hex::encode(key.sign(&bytes).to_bytes());
    envelope
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools
)]
fn scenario(
    seed: u64,
    safe_goal: bool,
    consensus: bool,
    lab_weak: bool,
    review_weak: bool,
    maximum_faults: usize,
    profile: SuspicionProfile,
) -> Scenario {
    let goal_key = SigningKey::from_bytes(&[11; 32]);
    let goal_review_key = SigningKey::from_bytes(&[66; 32]);
    let phenotype_key = SigningKey::from_bytes(&[22; 32]);
    let lab_key = SigningKey::from_bytes(&[33; 32]);
    let peer_key = SigningKey::from_bytes(&[55; 32]);
    let review_key = SigningKey::from_bytes(&[44; 32]);
    let public_keys = BTreeMap::from([
        (
            "goal-lab".into(),
            hex::encode(goal_key.verifying_key().to_bytes()),
        ),
        (
            "goal-review".into(),
            hex::encode(goal_review_key.verifying_key().to_bytes()),
        ),
        (
            "phenotype-lab".into(),
            hex::encode(phenotype_key.verifying_key().to_bytes()),
        ),
        (
            "viability-lab".into(),
            hex::encode(lab_key.verifying_key().to_bytes()),
        ),
        (
            "viability-peer".into(),
            hex::encode(peer_key.verifying_key().to_bytes()),
        ),
        (
            "viability-review".into(),
            hex::encode(review_key.verifying_key().to_bytes()),
        ),
    ]);
    let mut replicas = json!({
        "replica-a": {"cluster/epoch": "7", "user/message": "old"},
        "replica-b": {"cluster/epoch": "7", "user/message": "old"},
        "replica-c": {"cluster/epoch": "7", "user/message": "old"}
    });
    if !consensus {
        replicas["replica-c"]["user/message"] = json!("partition");
    }
    let phenotype = json!({"replicas": replicas});
    let history = envelope(
        &phenotype_key,
        AuthorityKind::Phenotype,
        "phenotype-lab",
        json!({"replicas": {
            "replica-a": {"cluster/epoch": "7", "user/message": "stable"},
            "replica-b": {"cluster/epoch": "7", "user/message": "stable"},
            "replica-c": {"cluster/epoch": "7", "user/message": "stable"}
        }}),
        1,
        Vec::new(),
    );
    let current = envelope(
        &phenotype_key,
        AuthorityKind::Phenotype,
        "phenotype-lab",
        phenotype,
        2,
        vec![digest(&history)],
    );
    let strict = json!({"replica_count": 3, "require_consensus": true, "required_keys": {"cluster/epoch": "7"}});
    let weak = json!({"replica_count": 3, "require_consensus": true, "required_keys": {}});
    let goal = if safe_goal {
        json!({"cluster/epoch": "7", "user/message": format!("new-{seed}")})
    } else {
        json!({"user/message": format!("poisoned-{seed}")})
    };
    let authorities = vec![
        envelope(
            &goal_key,
            AuthorityKind::Goal,
            "goal-lab",
            goal.clone(),
            1,
            Vec::new(),
        ),
        envelope(
            &goal_review_key,
            AuthorityKind::Goal,
            "goal-review",
            goal,
            1,
            Vec::new(),
        ),
        current.clone(),
        envelope(
            &lab_key,
            AuthorityKind::Viability,
            "viability-lab",
            if lab_weak {
                weak.clone()
            } else {
                strict.clone()
            },
            1,
            Vec::new(),
        ),
        envelope(
            &peer_key,
            AuthorityKind::Viability,
            "viability-peer",
            if lab_weak {
                weak.clone()
            } else {
                strict.clone()
            },
            1,
            Vec::new(),
        ),
        envelope(
            &review_key,
            AuthorityKind::Viability,
            "viability-review",
            if review_weak { weak } else { strict },
            1,
            Vec::new(),
        ),
    ];
    Scenario {
        scenario_id: format!(
            "generated-{seed}-{}-{}-{}-{}-f{maximum_faults}-{}",
            if safe_goal { "safe" } else { "poisoned" },
            if consensus { "consensus" } else { "partition" },
            if lab_weak { "lab-weak" } else { "lab-strict" },
            if review_weak {
                "review-weak"
            } else {
                "review-strict"
            },
            profile.name()
        ),
        seed,
        evaluation_time: 1_750_000_000,
        subject: "kv/research".into(),
        expected_decision: if safe_goal {
            ExpectedDecision::Apply
        } else {
            ExpectedDecision::Refuse
        },
        public_keys,
        fault_declaration: FaultDeclaration {
            maximum_faults,
            suspectable: profile.suspectable(),
            goal_fault_domains: match profile {
                SuspicionProfile::ViabilityOnly => BTreeMap::new(),
                SuspicionProfile::GoalAndViability => BTreeMap::from([
                    ("goal-lab".into(), "goal-lab-domain".into()),
                    ("goal-review".into(), "goal-review-domain".into()),
                ]),
            },
            viability_fault_domains: BTreeMap::from([
                ("viability-lab".into(), "lab-domain".into()),
                ("viability-peer".into(), "lab-domain".into()),
                ("viability-review".into(), "review-domain".into()),
            ]),
            deletion_fault_domains: BTreeMap::new(),
            maximum_hypotheses: 5,
        },
        phenotype_history_anchor: HistoryAnchor {
            issuer: current.issuer.clone(),
            sequence: current.sequence,
            tip_digest: digest(&current),
        },
        phenotype_history: vec![history],
        authorities,
    }
}

fn record(counts: &mut Counts, expected: ExpectedDecision, decision: &Decision) {
    counts.scenarios += 1;
    match expected {
        ExpectedDecision::Apply => counts.expected_apply += 1,
        ExpectedDecision::Refuse => counts.expected_refuse += 1,
    }
    match decision {
        Decision::Applied => counts.applied += 1,
        Decision::Refused => counts.refused += 1,
    }
    counts.unsafe_approvals +=
        usize::from(expected == ExpectedDecision::Refuse && *decision == Decision::Applied);
    counts.false_refusals +=
        usize::from(expected == ExpectedDecision::Apply && *decision == Decision::Refused);
}

fn generate() -> Report {
    let mut total = Counts::default();
    let mut cells = Vec::new();
    for profile in SuspicionProfile::ALL {
        for maximum_faults in 0..=1 {
            for consensus in [true, false] {
                for lab_weak in [false, true] {
                    for review_weak in [false, true] {
                        let mut counts = Counts::default();
                        for seed in SEEDS {
                            for safe_goal in [true, false] {
                                let input = scenario(
                                    seed,
                                    safe_goal,
                                    consensus,
                                    lab_weak,
                                    review_weak,
                                    maximum_faults,
                                    profile,
                                );
                                let expected = input.expected_decision;
                                let decision = run_scenario(&input)
                                    .expect("generated scenario must satisfy protocol")
                                    .decision;
                                record(&mut counts, expected, &decision);
                                record(&mut total, expected, &decision);
                            }
                        }
                        cells.push(Cell {
                            suspicion_profile: profile.name(),
                            maximum_faults,
                            phenotype: if consensus { "consensus" } else { "partition" },
                            lab_domain: if lab_weak { "weakened" } else { "strict" },
                            review_domain: if review_weak { "weakened" } else { "strict" },
                            counts,
                        });
                    }
                }
            }
        }
    }
    Report {
        schema_version: "telosieve.state-space/v2",
        generator: "exhaustive Cartesian product over declared finite dimensions",
        seeds: SEEDS.count(),
        dimensions: BTreeMap::from([
            ("goal", vec!["safe", "poisoned"]),
            (
                "goal_domains",
                vec!["goal-lab-domain", "goal-review-domain"],
            ),
            ("phenotype", vec!["consensus", "partition"]),
            ("lab_domain", vec!["strict", "weakened"]),
            ("review_domain", vec!["strict", "weakened"]),
            ("maximum_faults", vec!["0", "1"]),
            (
                "suspicion_profile",
                vec!["viability_only", "goal_and_viability"],
            ),
        ]),
        total,
        cells,
        conclusions: vec![
            "stable-key continuity retains zero unsafe approvals",
            "distinct agreeing goal domains remove the measured safe-goal false refusals",
            "organizational independence and divergent-goal availability remain unproven",
        ],
    }
}

fn main() {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "results/generated-state-space.json".into());
    let report = generate();
    fs::write(
        output,
        serde_json::to_vec_pretty(&report).expect("report serialization"),
    )
    .expect("write report");
}

#[cfg(test)]
mod tests {
    use super::generate;

    #[test]
    fn generated_frontier_has_no_unsafe_approval_or_false_refusal() {
        let report = generate();
        assert_eq!(report.total.scenarios, 512);
        assert_eq!(report.total.expected_apply, 256);
        assert_eq!(report.total.expected_refuse, 256);
        assert_eq!(report.total.unsafe_approvals, 0);
        assert_eq!(report.total.false_refusals, 0);
    }
}
