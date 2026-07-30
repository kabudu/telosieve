use std::{
    fs,
    io::{Read, Write},
    process::{self, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

fn read_downstream(bytes: &[u8]) -> (std::process::Output, bool) {
    let mut child = Command::new("python3")
        .arg("scripts/certificate-reader.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let payload = bytes.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&payload));
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let _ = writer.join().unwrap();
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    (
        std::process::Output {
            status,
            stdout,
            stderr,
        },
        timed_out,
    )
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

#[test]
fn independent_reader_agrees_on_supported_versions_and_failure_matrix() {
    let legacy = scenario("scenarios/benign.json");
    let certificate_v7 = run_scenario(&legacy).unwrap();
    let bytes_v7 = serde_json::to_vec(&certificate_v7).unwrap();

    let directory =
        std::env::temp_dir().join(format!("telosieve-reader-qualification-{}", process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("actuator.json");
    let authorities = verify(&legacy).unwrap();
    LocalActuatorStore::new(&path)
        .initialize(&authorities.phenotype, &legacy.phenotype_history_anchor)
        .unwrap();
    let bytes_v8 = serde_json::to_vec(&run_scenario_actuated(&legacy, &path).unwrap()).unwrap();
    let bytes_v9 = fixture("results/kubernetes-shadow-certificate.json");

    for (version, bytes) in [
        (CERTIFICATE_VERSION_V7, &bytes_v7),
        (CERTIFICATE_VERSION_V8, &bytes_v8),
        (CERTIFICATE_VERSION_V9, &bytes_v9),
    ] {
        parse_supported_certificate(bytes).unwrap();
        let (output, timed_out) = read_downstream(bytes);
        assert!(!timed_out, "downstream reader timed out");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["certificate_version"], version);
        assert_eq!(
            summary["implementation"],
            "telosieve-python-certificate-reader/v1"
        );
        assert_eq!(summary["input_sha256"], hex::encode(Sha256::digest(bytes)));
    }

    let mut future = serde_json::to_value(&certificate_v7).unwrap();
    future["certificate_version"] = json!("telosieve.certificate/v99");
    let mut unknown = serde_json::to_value(&certificate_v7).unwrap();
    unknown["future_extension"] = json!({});
    let mut nested_unknown: Value = serde_json::from_slice(&bytes_v9).unwrap();
    nested_unknown["shadow"]["future_extension"] = json!(true);
    let mut missing = serde_json::to_value(&certificate_v7).unwrap();
    missing.as_object_mut().unwrap().remove("metrics");
    let mut wrong_type = serde_json::to_value(&certificate_v7).unwrap();
    wrong_type["seed"] = json!("7");
    let mut out_of_range = serde_json::to_value(&certificate_v7).unwrap();
    out_of_range["seed"] = serde_json::from_str("18446744073709551616").unwrap();
    let mut confused = serde_json::to_value(&certificate_v7).unwrap();
    confused["certificate_version"] = json!(CERTIFICATE_VERSION_V8);
    let duplicate = bytes_v7
        .strip_prefix(b"{")
        .map(|tail| {
            [
                br#"{"certificate_version":"telosieve.certificate/v7","#.as_slice(),
                tail,
            ]
            .concat()
        })
        .unwrap();
    let rejected = [
        serde_json::to_vec(&future).unwrap(),
        serde_json::to_vec(&unknown).unwrap(),
        serde_json::to_vec(&nested_unknown).unwrap(),
        serde_json::to_vec(&missing).unwrap(),
        serde_json::to_vec(&wrong_type).unwrap(),
        serde_json::to_vec(&out_of_range).unwrap(),
        serde_json::to_vec(&confused).unwrap(),
        duplicate,
        b"{".to_vec(),
    ];
    assert!(3 + rejected.len() <= MAX_COMPATIBILITY_CASES);
    assert!(
        bytes_v7.len()
            + bytes_v8.len()
            + bytes_v9.len()
            + rejected.iter().map(Vec::len).sum::<usize>()
            <= MAX_COMPATIBILITY_CORPUS_BYTES
    );
    for bytes in rejected {
        assert!(parse_supported_certificate(&bytes).is_err());
        let (output, timed_out) = read_downstream(&bytes);
        assert!(!timed_out, "downstream reader timed out");
        assert!(!output.status.success());
    }

    let oversized = vec![b' '; MAX_COMPATIBILITY_CERTIFICATE_BYTES + 1];
    assert!(parse_supported_certificate(&oversized).is_err());
    let (output, timed_out) = read_downstream(&oversized);
    assert!(!timed_out, "downstream reader timed out");
    assert!(!output.status.success());
    fs::remove_dir_all(directory).unwrap();
}
