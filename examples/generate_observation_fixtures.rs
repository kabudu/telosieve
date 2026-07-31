//! Generates deterministic, non-production observation quorum examples.

use ed25519_dalek::SigningKey;
use sha2::Digest;
use telosieve::observation_quorum::{
    ObservationKey, ObservationQuorum, ObservationSigningRequest, ObservationTrust,
    QUORUM_SCHEMA_VERSION, TRUST_SCHEMA_VERSION, sign_observation,
};

fn main() {
    let input = include_bytes!("../snapshots/kubernetes-shadow-benign.json");
    let specifications = [
        (
            "fixture-exporter",
            "fixture-a",
            "cluster-export",
            [1_u8; 32],
        ),
        ("fixture-auditor", "fixture-b", "audit-mirror", [2_u8; 32]),
    ];
    let keys: Vec<_> = specifications
        .iter()
        .map(|(producer, key_id, domain, seed)| ObservationKey {
            producer: (*producer).into(),
            key_id: (*key_id).into(),
            fault_domain: (*domain).into(),
            public_key: hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes()),
            not_before: 1_788_000_000,
            not_after: 1_800_000_000,
        })
        .collect();
    let attestations = specifications
        .iter()
        .map(|(producer, key_id, domain, seed)| {
            sign_observation(
                input,
                &ObservationSigningRequest {
                    subject: "kv/research",
                    mode: "kubernetes-shadow",
                    producer,
                    key_id,
                    fault_domain: domain,
                    issued_at: 1_788_000_000,
                    expires_at: 1_788_000_300,
                },
                &SigningKey::from_bytes(seed),
            )
            .expect("fixed fixture is valid")
        })
        .collect();
    let trust = ObservationTrust {
        schema_version: TRUST_SCHEMA_VERSION.into(),
        evaluation_time: 1_788_000_100,
        required_distinct_domains: 2,
        keys,
    };
    let quorum = ObservationQuorum {
        schema_version: QUORUM_SCHEMA_VERSION.into(),
        subject: "kv/research".into(),
        mode: "kubernetes-shadow".into(),
        input_sha256: hex::encode(sha2::Sha256::digest(input)),
        attestations,
    };
    println!("{}", serde_json::to_string(&trust).unwrap());
    println!("{}", serde_json::to_string(&quorum).unwrap());
}
