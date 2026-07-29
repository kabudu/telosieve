use std::{collections::BTreeMap, fs, path::PathBuf, process};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use telosieve::{
    actuator_store::{ActuatorError, LocalActuatorStore},
    kubernetes_shadow::{KubernetesShadowSnapshot, ShadowError, validate},
    protocol::{Envelope, KeyLifecycleStatement, Scenario, verify},
};

const MAX_CASES_PER_CORPUS: usize = 16;
const MAX_CORPUS_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACTUATOR_STATE_BYTES: usize = 1024 * 1024;

fn fixture(path: &str) -> Vec<u8> {
    fs::read(path).unwrap()
}

fn assert_bounded(cases: &[Vec<u8>]) {
    assert!(cases.len() <= MAX_CASES_PER_CORPUS);
    assert!(cases.iter().map(Vec::len).sum::<usize>() <= MAX_CORPUS_BYTES);
}

fn truncations(bytes: &[u8]) -> Vec<Vec<u8>> {
    [0, 1, bytes.len() / 4, bytes.len() / 2, bytes.len() - 1]
        .into_iter()
        .map(|length| bytes[..length].to_vec())
        .collect()
}

fn assert_parse_rejections<T: DeserializeOwned>(cases: &[Vec<u8>]) {
    assert_bounded(cases);
    for case in cases {
        assert!(serde_json::from_slice::<T>(case).is_err());
    }
}

fn temporary_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("telosieve-{label}-{}", process::id()))
}

#[test]
fn authority_parser_corpus_is_bounded_and_fail_closed() {
    let scenario: Value = serde_json::from_slice(&fixture("scenarios/benign.json")).unwrap();
    let authority = scenario["authorities"][0].clone();
    let bytes = serde_json::to_vec(&authority).unwrap();
    let parsed: Envelope = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        authority,
        "valid authority round trip changed its representation"
    );

    let mut cases = truncations(&bytes);
    for (field, replacement) in [
        ("kind", json!(7)),
        ("issued_at", json!(-1)),
        ("parent_digests", json!({})),
        ("signature", Value::Null),
    ] {
        let mut candidate = authority.clone();
        candidate[field] = replacement;
        cases.push(serde_json::to_vec(&candidate).unwrap());
    }
    let mut unknown = authority.clone();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut missing = authority.clone();
    missing.as_object_mut().unwrap().remove("issuer");
    cases.push(serde_json::to_vec(&missing).unwrap());
    assert_parse_rejections::<Envelope>(&cases);

    assert!(
        serde_json::from_slice::<Envelope>(include_bytes!(
            "regressions/authority-negative-issued-at.json"
        ))
        .is_err()
    );
}

#[test]
fn lifecycle_parser_corpus_is_bounded_and_fail_closed() {
    let scenario: Value =
        serde_json::from_slice(&fixture("scenarios/rotated-goal-key.json")).unwrap();
    let statement = scenario["key_lifecycle"][0].clone();
    let bytes = serde_json::to_vec(&statement).unwrap();
    let parsed: KeyLifecycleStatement = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), statement);

    let mut cases = truncations(&bytes);
    for (field, replacement) in [
        ("authority_kind", json!("administrator")),
        ("sequence", json!("1")),
        ("parent_digest", json!([])),
        ("action", json!({"action":"activate","expires_at":2})),
    ] {
        let mut candidate = statement.clone();
        candidate[field] = replacement;
        cases.push(serde_json::to_vec(&candidate).unwrap());
    }
    let mut unknown = statement.clone();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    assert_parse_rejections::<KeyLifecycleStatement>(&cases);

    assert!(
        serde_json::from_slice::<KeyLifecycleStatement>(include_bytes!(
            "regressions/lifecycle-unknown-action-field.json"
        ))
        .is_err()
    );
}

#[test]
fn shadow_parser_corpus_is_bounded_and_structurally_bounded() {
    let fixture_bytes = fixture("snapshots/kubernetes-shadow-benign.json");
    let snapshot: KubernetesShadowSnapshot = serde_json::from_slice(&fixture_bytes).unwrap();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap(),
        serde_json::from_slice::<Value>(&fixture_bytes).unwrap()
    );

    let value = serde_json::to_value(&snapshot).unwrap();
    let mut cases = truncations(&bytes);
    for (pointer, replacement) in [
        ("/captured_at", json!("now")),
        ("/desired/metadata", json!([])),
        ("/observed/complete", json!("true")),
    ] {
        let mut candidate = value.clone();
        *candidate.pointer_mut(pointer).unwrap() = replacement;
        cases.push(serde_json::to_vec(&candidate).unwrap());
    }
    let mut unknown = value.clone();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut missing = value.clone();
    missing["desired"].as_object_mut().unwrap().remove("target");
    cases.push(serde_json::to_vec(&missing).unwrap());
    assert_parse_rejections::<KubernetesShadowSnapshot>(&cases);

    assert!(
        serde_json::from_slice::<KubernetesShadowSnapshot>(include_bytes!(
            "regressions/shadow-string-generation.json"
        ))
        .is_err()
    );

    let scenario: Scenario = serde_json::from_slice(&fixture("scenarios/benign.json")).unwrap();
    let authorities = verify(&scenario).unwrap();
    let mut oversized = snapshot;
    oversized.desired.data = BTreeMap::from([("key".into(), "x".repeat(4097))]);
    assert!(matches!(
        validate(&scenario, &authorities, &oversized),
        Err(ShadowError::ResourceBound(_))
    ));
}

#[test]
fn recovery_parser_corpus_is_bounded_and_fail_closed() {
    let directory = temporary_path("parser-corpus");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("actuator.json");
    let scenario: Scenario = serde_json::from_slice(&fixture("scenarios/benign.json")).unwrap();
    let authorities = verify(&scenario).unwrap();
    let store = LocalActuatorStore::new(&path);
    store
        .initialize(&authorities.phenotype, &scenario.phenotype_history_anchor)
        .unwrap();
    let valid =
        serde_json::to_vec(&serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap())
            .unwrap();
    assert!(store.current_snapshot().is_ok());

    let mut cases = truncations(&valid);
    let mut value: Value = serde_json::from_slice(&valid).unwrap();
    value["generation"] = json!("one");
    cases.push(serde_json::to_vec(&value).unwrap());
    let mut unknown: Value = serde_json::from_slice(&valid).unwrap();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut missing: Value = serde_json::from_slice(&valid).unwrap();
    missing.as_object_mut().unwrap().remove("history_anchor");
    cases.push(serde_json::to_vec(&missing).unwrap());
    cases.push(include_bytes!("regressions/recovery-string-generation.json").to_vec());
    assert_bounded(&cases);
    for case in cases {
        fs::write(&path, case).unwrap();
        assert!(store.current_snapshot().is_err());
    }

    fs::write(&path, vec![b' '; MAX_ACTUATOR_STATE_BYTES + 1]).unwrap();
    assert!(matches!(
        store.current_snapshot(),
        Err(ActuatorError::InvalidState(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}
