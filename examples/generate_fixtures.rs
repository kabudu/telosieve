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
        AuthorityKind, DeletionAuthorization, Envelope, ExpectedDecision, FaultDeclaration,
        HistoryAnchor, KEY_LIFECYCLE_SCHEMA_VERSION, KeyLifecycleAction, KeyLifecycleAnchor,
        KeyLifecycleStatement, SCHEMA_VERSION, Scenario,
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

#[derive(Serialize)]
struct UnsignedKeyLifecycleStatement<'a> {
    schema_version: &'a str,
    subject: &'a str,
    issuer: &'a str,
    authority_kind: AuthorityKind,
    sequence: u64,
    effective_at: u64,
    parent_digest: &'a Option<String>,
    action: &'a KeyLifecycleAction,
}

fn envelope(key: &SigningKey, kind: AuthorityKind, issuer: &str, content: Value) -> Envelope {
    envelope_with_lineage(key, kind, issuer, content, 1, Vec::new())
}

fn envelope_with_lineage(
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
    .unwrap();
    envelope.signature = hex::encode(key.sign(&bytes).to_bytes());
    envelope
}

fn resign_envelope(envelope: &mut Envelope, key: &SigningKey) {
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
}

fn sign_lifecycle(statement: &mut KeyLifecycleStatement, root: &SigningKey) {
    let bytes = serde_json::to_vec(&UnsignedKeyLifecycleStatement {
        schema_version: &statement.schema_version,
        subject: &statement.subject,
        issuer: &statement.issuer,
        authority_kind: statement.authority_kind,
        sequence: statement.sequence,
        effective_at: statement.effective_at,
        parent_digest: &statement.parent_digest,
        action: &statement.action,
    })
    .unwrap();
    statement.signature = hex::encode(root.sign(&bytes).to_bytes());
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
    let goal_review_key = SigningKey::from_bytes(&[66; 32]);
    let deletion_key = SigningKey::from_bytes(&[77; 32]);
    let deletion_review_key = SigningKey::from_bytes(&[88; 32]);
    let phenotype_key = SigningKey::from_bytes(&[22; 32]);
    let viability_key = SigningKey::from_bytes(&[33; 32]);
    let viability_peer_key = SigningKey::from_bytes(&[55; 32]);
    let viability_backup_key = SigningKey::from_bytes(&[44; 32]);
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
            "deletion-lab".into(),
            hex::encode(deletion_key.verifying_key().to_bytes()),
        ),
        (
            "deletion-review".into(),
            hex::encode(deletion_review_key.verifying_key().to_bytes()),
        ),
        (
            "phenotype-lab".into(),
            hex::encode(phenotype_key.verifying_key().to_bytes()),
        ),
        (
            "viability-lab".into(),
            hex::encode(viability_key.verifying_key().to_bytes()),
        ),
        (
            "viability-review".into(),
            hex::encode(viability_backup_key.verifying_key().to_bytes()),
        ),
        (
            "viability-peer".into(),
            hex::encode(viability_peer_key.verifying_key().to_bytes()),
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
                review_rules: Value,
                expected_decision,
                maximum_faults,
                suspectable: BTreeSet<AuthorityKind>|
     -> Scenario {
        let history = envelope(
            &phenotype_key,
            AuthorityKind::Phenotype,
            "phenotype-lab",
            json!({
                "replicas": {
                    "replica-a": {"cluster/epoch": "7", "user/message": "stable"},
                    "replica-b": {"cluster/epoch": "7", "user/message": "stable"},
                    "replica-c": {"cluster/epoch": "7", "user/message": "stable"}
                }
            }),
        );
        let current_phenotype = envelope_with_lineage(
            &phenotype_key,
            AuthorityKind::Phenotype,
            "phenotype-lab",
            phenotype,
            2,
            vec![digest(&history)],
        );
        let phenotype_history_anchor = HistoryAnchor {
            issuer: current_phenotype.issuer.clone(),
            sequence: current_phenotype.sequence,
            tip_digest: digest(&current_phenotype),
        };
        let viability_fault_domains = if suspectable.contains(&AuthorityKind::Viability) {
            BTreeMap::from([
                ("viability-lab".into(), "lab-domain".into()),
                ("viability-peer".into(), "lab-domain".into()),
                ("viability-review".into(), "review-domain".into()),
            ])
        } else {
            BTreeMap::new()
        };
        let goal_fault_domains = if suspectable.contains(&AuthorityKind::Goal) {
            BTreeMap::from([
                ("goal-lab".into(), "goal-lab-domain".into()),
                ("goal-review".into(), "goal-review-domain".into()),
            ])
        } else {
            BTreeMap::new()
        };
        let maximum_hypotheses = 1
            + usize::from(suspectable.contains(&AuthorityKind::Goal)) * 2
            + usize::from(suspectable.contains(&AuthorityKind::Viability)) * 2
            + usize::from(suspectable.contains(&AuthorityKind::Phenotype));
        Scenario {
            scenario_id: scenario_id.into(),
            seed: 7,
            evaluation_time: 1_750_000_000,
            subject: "kv/research".into(),
            expected_decision,
            public_keys: public_keys.clone(),
            key_lifecycle_roots: BTreeMap::new(),
            key_lifecycle: Vec::new(),
            key_lifecycle_anchors: BTreeMap::new(),
            trusted_time: None,
            fault_declaration: FaultDeclaration {
                maximum_faults,
                suspectable,
                goal_fault_domains,
                viability_fault_domains,
                deletion_fault_domains: BTreeMap::new(),
                maximum_hypotheses,
            },
            phenotype_history_anchor,
            phenotype_history: vec![history],
            authorities: vec![
                envelope(&goal_key, AuthorityKind::Goal, "goal-lab", goal.clone()),
                envelope(&goal_review_key, AuthorityKind::Goal, "goal-review", goal),
                current_phenotype,
                envelope(
                    &viability_peer_key,
                    AuthorityKind::Viability,
                    "viability-peer",
                    rules.clone(),
                ),
                envelope(
                    &viability_key,
                    AuthorityKind::Viability,
                    "viability-lab",
                    rules,
                ),
                envelope(
                    &viability_backup_key,
                    AuthorityKind::Viability,
                    "viability-review",
                    review_rules,
                ),
            ],
        }
    };
    let benign = make(
        "benign-update",
        json!({"cluster/epoch": "7", "user/message": "new"}),
        current.clone(),
        viability.clone(),
        viability.clone(),
        ExpectedDecision::Apply,
        1,
        BTreeSet::from([AuthorityKind::Viability]),
    );
    let kubernetes_real_cluster = make(
        "kubernetes-real-cluster",
        json!({"cluster/epoch": "7", "user/message": "new"}),
        json!({
            "replicas": {
                "research-kv-0": {"cluster/epoch": "7", "user/message": "old"},
                "research-kv-1": {"cluster/epoch": "7", "user/message": "old"},
                "research-kv-2": {"cluster/epoch": "7", "user/message": "old"}
            }
        }),
        viability.clone(),
        viability.clone(),
        ExpectedDecision::Apply,
        1,
        BTreeSet::from([AuthorityKind::Viability]),
    );
    let lifecycle_root = SigningKey::from_bytes(&[90; 32]);
    let rotated_goal_key = SigningKey::from_bytes(&[91; 32]);
    let mut rotated_key = benign.clone();
    rotated_key.scenario_id = "rotated-goal-key".into();
    let mut activation = KeyLifecycleStatement {
        schema_version: KEY_LIFECYCLE_SCHEMA_VERSION.into(),
        subject: rotated_key.subject.clone(),
        issuer: "goal-lab".into(),
        authority_kind: AuthorityKind::Goal,
        sequence: 1,
        effective_at: 1_720_000_000,
        parent_digest: None,
        action: KeyLifecycleAction::Activate {
            public_key: hex::encode(rotated_goal_key.verifying_key().to_bytes()),
            expires_at: 1_790_000_000,
        },
        signature: String::new(),
    };
    sign_lifecycle(&mut activation, &lifecycle_root);
    rotated_key.key_lifecycle_roots.insert(
        "goal-lab".into(),
        hex::encode(lifecycle_root.verifying_key().to_bytes()),
    );
    rotated_key.key_lifecycle_anchors.insert(
        "goal-lab".into(),
        KeyLifecycleAnchor {
            sequence: 1,
            tip_digest: digest(&activation),
        },
    );
    rotated_key.key_lifecycle.push(activation);
    let rotated_goal = rotated_key
        .authorities
        .iter_mut()
        .find(|envelope| envelope.issuer == "goal-lab")
        .unwrap();
    rotated_goal.issued_at = 1_730_000_000;
    resign_envelope(rotated_goal, &rotated_goal_key);
    let poisoned = make(
        "poisoned-goal",
        json!({"user/message": "attacker-controlled"}),
        current.clone(),
        viability.clone(),
        viability.clone(),
        ExpectedDecision::Refuse,
        1,
        BTreeSet::from([AuthorityKind::Goal]),
    );
    let weakened_rules =
        json!({"replica_count": 3, "require_consensus": true, "required_keys": {}});
    let weakened = make(
        "weakened-viability",
        json!({"user/message": "attacker-controlled"}),
        current.clone(),
        weakened_rules.clone(),
        viability.clone(),
        ExpectedDecision::Refuse,
        1,
        BTreeSet::from([AuthorityKind::Goal, AuthorityKind::Viability]),
    );
    let mut partition = current.clone();
    partition["replicas"]["replica-c"]["user/message"] = "partition".into();
    let partitioned = make(
        "partitioned-phenotype",
        json!({"cluster/epoch": "7", "user/message": "new"}),
        partition,
        viability.clone(),
        viability.clone(),
        ExpectedDecision::Apply,
        1,
        BTreeSet::from([AuthorityKind::Phenotype]),
    );
    fs::create_dir_all("scenarios").unwrap();
    write_scenario("benign", &benign);
    write_scenario("kubernetes-real-cluster", &kubernetes_real_cluster);
    write_scenario("rotated-goal-key", &rotated_key);
    write_scenario("poisoned-goal", &poisoned);
    write_scenario("weakened-viability", &weakened);
    write_scenario("partitioned-phenotype", &partitioned);
    let deletion_goal = json!({"cluster/epoch": "7"});
    let mut unauthorized_deletion = benign.clone();
    unauthorized_deletion.scenario_id = "unauthorized-deletion".into();
    unauthorized_deletion.expected_decision = ExpectedDecision::Refuse;
    unauthorized_deletion
        .authorities
        .retain(|authority| authority.kind != AuthorityKind::Goal);
    unauthorized_deletion.authorities.extend([
        envelope(
            &goal_key,
            AuthorityKind::Goal,
            "goal-lab",
            deletion_goal.clone(),
        ),
        envelope(
            &goal_review_key,
            AuthorityKind::Goal,
            "goal-review",
            deletion_goal.clone(),
        ),
    ]);
    write_scenario("unauthorized-deletion", &unauthorized_deletion);

    let authorization = serde_json::to_value(DeletionAuthorization {
        keys: BTreeSet::from(["user/message".into()]),
        goal_digest: digest(&deletion_goal),
        phenotype_tip_digest: benign.phenotype_history_anchor.tip_digest.clone(),
    })
    .unwrap();
    let mut authorized_deletion = unauthorized_deletion;
    authorized_deletion.scenario_id = "authorized-deletion".into();
    authorized_deletion.expected_decision = ExpectedDecision::Apply;
    authorized_deletion
        .fault_declaration
        .suspectable
        .insert(AuthorityKind::Deletion);
    authorized_deletion.fault_declaration.deletion_fault_domains = BTreeMap::from([
        ("deletion-lab".into(), "deletion-lab-domain".into()),
        ("deletion-review".into(), "deletion-review-domain".into()),
    ]);
    authorized_deletion.fault_declaration.maximum_hypotheses = 5;
    authorized_deletion.authorities.extend([
        envelope(
            &deletion_key,
            AuthorityKind::Deletion,
            "deletion-lab",
            authorization.clone(),
        ),
        envelope(
            &deletion_review_key,
            AuthorityKind::Deletion,
            "deletion-review",
            authorization,
        ),
    ]);
    write_scenario("authorized-deletion", &authorized_deletion);
    let all_domains_weakened = make(
        "all-viability-domains-weakened",
        json!({"user/message": "attacker-controlled"}),
        current,
        weakened_rules.clone(),
        weakened_rules,
        ExpectedDecision::Refuse,
        1,
        BTreeSet::from([AuthorityKind::Viability]),
    );
    write_scenario("all-viability-domains-weakened", &all_domains_weakened);
}
