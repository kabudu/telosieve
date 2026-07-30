use std::{fs, process};

use serde_json::{Value, json};
use telosieve::{
    actuator_store::LocalActuatorStore,
    certificate::{
        CERTIFICATE_VERSION_V7, CERTIFICATE_VERSION_V8, CERTIFICATE_VERSION_V9,
        CertificateCompatibilityError, MAX_COMPATIBILITY_CERTIFICATE_BYTES,
        parse_supported_certificate,
    },
    engine::{run_scenario, run_scenario_actuated},
    protocol::{ProtocolError, Scenario, verify},
};

const MAX_COMPATIBILITY_CASES: usize = 16;
const MAX_COMPATIBILITY_CORPUS_BYTES: usize = 2 * 1024 * 1024;

fn fixture(path: &str) -> Vec<u8> {
    fs::read(path).unwrap()
}

fn scenario(path: &str) -> Scenario {
    serde_json::from_slice(&fixture(path)).unwrap()
}

fn assert_bounds(cases: &[Vec<u8>]) {
    assert!(cases.len() <= MAX_COMPATIBILITY_CASES);
    assert!(cases.iter().map(Vec::len).sum::<usize>() <= MAX_COMPATIBILITY_CORPUS_BYTES);
}

#[test]
fn scenario_migration_vectors_preserve_legacy_and_fail_closed() {
    let legacy_bytes = fixture("scenarios/benign.json");
    let legacy: Scenario = serde_json::from_slice(&legacy_bytes).unwrap();
    assert!(legacy.trusted_time.is_none());
    verify(&legacy).unwrap();

    let current_bytes = fixture("scenarios/rotated-goal-key.json");
    let current: Scenario = serde_json::from_slice(&current_bytes).unwrap();
    assert!(current.trusted_time.is_some());
    let verified = verify(&current).unwrap();
    assert!(verified.digests.contains_key("trusted-time"));

    let mut missing_time: Value = serde_json::from_slice(&current_bytes).unwrap();
    missing_time.as_object_mut().unwrap().remove("trusted_time");
    let missing_time_bytes = serde_json::to_vec(&missing_time).unwrap();
    let parsed_missing: Scenario = serde_json::from_slice(&missing_time_bytes).unwrap();
    assert!(matches!(
        verify(&parsed_missing),
        Err(ProtocolError::KeyLifecycle(_))
    ));

    let mut future_field: Value = serde_json::from_slice(&legacy_bytes).unwrap();
    future_field["future_trust_mode"] = json!("implicit");
    let future_field_bytes = serde_json::to_vec(&future_field).unwrap();
    assert!(serde_json::from_slice::<Scenario>(&future_field_bytes).is_err());

    let mut future_authority = legacy.clone();
    future_authority.authorities[0].schema_version = "telosieve.authority/v99".into();
    let future_authority_bytes = serde_json::to_vec(&future_authority).unwrap();
    assert!(matches!(
        verify(&future_authority),
        Err(ProtocolError::Invalid {
            field: "schema_version",
            ..
        })
    ));

    let mut future_lifecycle = current;
    future_lifecycle.key_lifecycle[0].schema_version = "telosieve.key-lifecycle/v99".into();
    let future_lifecycle_bytes = serde_json::to_vec(&future_lifecycle).unwrap();
    assert!(matches!(
        verify(&future_lifecycle),
        Err(ProtocolError::KeyLifecycle(_))
    ));

    assert_bounds(&[
        legacy_bytes,
        current_bytes,
        missing_time_bytes,
        future_field_bytes,
        future_authority_bytes,
        future_lifecycle_bytes,
    ]);
}

#[test]
fn certificate_vectors_accept_v7_to_v9_and_reject_future_or_confused_shapes() {
    let legacy = scenario("scenarios/benign.json");
    let certificate_v7 = run_scenario(&legacy).unwrap();
    assert_eq!(certificate_v7.certificate_version, CERTIFICATE_VERSION_V7);
    let bytes_v7 = serde_json::to_vec(&certificate_v7).unwrap();
    parse_supported_certificate(&bytes_v7).unwrap();

    let directory = std::env::temp_dir().join(format!("telosieve-compatibility-{}", process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("actuator.json");
    let authorities = verify(&legacy).unwrap();
    LocalActuatorStore::new(&path)
        .initialize(&authorities.phenotype, &legacy.phenotype_history_anchor)
        .unwrap();
    let certificate_v8 = run_scenario_actuated(&legacy, &path).unwrap();
    assert_eq!(certificate_v8.certificate_version, CERTIFICATE_VERSION_V8);
    let bytes_v8 = serde_json::to_vec(&certificate_v8).unwrap();
    parse_supported_certificate(&bytes_v8).unwrap();

    let bytes_v9 = fixture("results/kubernetes-shadow-certificate.json");
    let certificate_v9 = parse_supported_certificate(&bytes_v9).unwrap();
    assert_eq!(certificate_v9.certificate_version, CERTIFICATE_VERSION_V9);

    let mut future = serde_json::to_value(&certificate_v7).unwrap();
    future["certificate_version"] = json!("telosieve.certificate/v99");
    let future_bytes = serde_json::to_vec(&future).unwrap();
    assert!(matches!(
        parse_supported_certificate(&future_bytes),
        Err(CertificateCompatibilityError::UnsupportedVersion(_))
    ));

    let mut unknown_field = serde_json::to_value(&certificate_v7).unwrap();
    unknown_field["future_extension"] = json!({});
    let unknown_field_bytes = serde_json::to_vec(&unknown_field).unwrap();
    assert!(matches!(
        parse_supported_certificate(&unknown_field_bytes),
        Err(CertificateCompatibilityError::Malformed(_))
    ));

    let mut confused = certificate_v9;
    confused.certificate_version = CERTIFICATE_VERSION_V8.into();
    let confused_bytes = serde_json::to_vec(&confused).unwrap();
    assert!(matches!(
        parse_supported_certificate(&confused_bytes),
        Err(CertificateCompatibilityError::InvalidVersionShape(_))
    ));

    assert!(matches!(
        parse_supported_certificate(&vec![b' '; MAX_COMPATIBILITY_CERTIFICATE_BYTES + 1]),
        Err(CertificateCompatibilityError::ResourceBound)
    ));
    assert_bounds(&[
        bytes_v7,
        bytes_v8,
        bytes_v9,
        future_bytes,
        unknown_field_bytes,
        confused_bytes,
    ]);

    fs::remove_dir_all(directory).unwrap();
}
