use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::{Value, json};
use telosieve::{
    model::digest,
    protocol::{
        AuthorityKind, Envelope, ExpectedDecision, FaultDeclaration, SCHEMA_VERSION, Scenario,
    },
};

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

fn envelope(key: &SigningKey, kind: AuthorityKind, issuer: &str, content: Value) -> Envelope {
    let mut envelope = Envelope {
        kind,
        subject: "kv/research".into(),
        schema_version: SCHEMA_VERSION.into(),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
        issuer: issuer.into(),
        sequence: 1,
        content_digest: digest(&content),
        parent_digests: Vec::new(),
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
    .unwrap();
    envelope.signature = hex::encode(key.sign(&bytes).to_bytes());
    envelope
}

fn write_scenario(name: &str, scenario: &Scenario) {
    fs::write(
        format!("scenarios/{name}.json"),
        serde_json::to_vec_pretty(scenario).unwrap(),
    )
    .unwrap();
}

#[allow(clippy::too_many_lines)]
fn main() {
    let goal_key = SigningKey::from_bytes(&[11; 32]);
    let phenotype_key = SigningKey::from_bytes(&[22; 32]);
    let viability_key = SigningKey::from_bytes(&[33; 32]);
    let public_keys = BTreeMap::from([
        (
            "goal-lab".into(),
            hex::encode(goal_key.verifying_key().to_bytes()),
        ),
        (
            "phenotype-lab".into(),
            hex::encode(phenotype_key.verifying_key().to_bytes()),
        ),
        (
            "viability-lab".into(),
            hex::encode(viability_key.verifying_key().to_bytes()),
        ),
    ]);
    let current = json!({
        "replicas": {
            "replica-a": {"cluster/epoch": "7", "user/message": "old"},
            "replica-b": {"cluster/epoch": "7", "user/message": "old"},
            "replica-c": {"cluster/epoch": "7", "user/message": "old"}
        }
    });
    let viability = json!({
        "replica_count": 3,
        "require_consensus": true,
        "required_keys": {"cluster/epoch": "7"}
    });
    let make = |scenario_id: &str,
                goal: Value,
                phenotype: Value,
                rules: Value,
                expected_decision,
                maximum_faults,
                suspectable|
     -> Scenario {
        Scenario {
            scenario_id: scenario_id.into(),
            seed: 7,
            evaluation_time: 1_750_000_000,
            subject: "kv/research".into(),
            expected_decision,
            public_keys: public_keys.clone(),
            fault_declaration: FaultDeclaration {
                maximum_faults,
                suspectable,
                maximum_hypotheses: 4,
            },
            authorities: vec![
                envelope(&goal_key, AuthorityKind::Goal, "goal-lab", goal),
                envelope(
                    &phenotype_key,
                    AuthorityKind::Phenotype,
                    "phenotype-lab",
                    phenotype,
                ),
                envelope(
                    &viability_key,
                    AuthorityKind::Viability,
                    "viability-lab",
                    rules,
                ),
            ],
        }
    };
    let benign = make(
        "benign-update",
        json!({"cluster/epoch": "7", "user/message": "new"}),
        current.clone(),
        viability.clone(),
        ExpectedDecision::Apply,
        0,
        BTreeSet::new(),
    );
    let poisoned = make(
        "poisoned-goal",
        json!({"user/message": "attacker-controlled"}),
        current.clone(),
        viability.clone(),
        ExpectedDecision::Refuse,
        1,
        BTreeSet::from([AuthorityKind::Goal]),
    );
    let weakened = make(
        "weakened-viability",
        json!({"user/message": "attacker-controlled"}),
        current.clone(),
        json!({"replica_count": 3, "require_consensus": true, "required_keys": {}}),
        ExpectedDecision::Apply,
        0,
        BTreeSet::new(),
    );
    let mut partition = current.clone();
    partition["replicas"]["replica-c"]["user/message"] = "partition".into();
    let partitioned = make(
        "partitioned-phenotype",
        json!({"cluster/epoch": "7", "user/message": "new"}),
        partition,
        viability.clone(),
        ExpectedDecision::Apply,
        1,
        BTreeSet::from([AuthorityKind::Phenotype]),
    );
    fs::create_dir_all("scenarios").unwrap();
    write_scenario("benign", &benign);
    write_scenario("poisoned-goal", &poisoned);
    write_scenario("weakened-viability", &weakened);
    write_scenario("partitioned-phenotype", &partitioned);
}
