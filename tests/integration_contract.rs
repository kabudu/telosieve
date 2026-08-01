use std::{fs, path::Path, process::Command};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use telosieve::observation_quorum::{
    ObservationKey, ObservationSigningRequest, ObservationTrust, sign_observation,
};

fn write(path: &Path, value: &[u8]) {
    fs::write(path, value).unwrap();
}

fn run(binary: &str, config: &Path) -> std::process::Output {
    Command::new(binary)
        .args(["evaluate", config.to_str().unwrap()])
        .output()
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn executable_contract_applies_and_refuses_untrusted_adapter_shapes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::temp_dir().join(format!(
        "telosieve-integration-contract-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let adapter = root
        .join("scripts/reference-integration-adapter.py")
        .canonicalize()
        .unwrap();
    let response_path = directory.join("response.json");
    let response = serde_json::to_vec(
        &serde_json::from_slice::<telosieve::integration::IntegrationResponse>(
            &fs::read(root.join("evaluation/integration-response.example.json")).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    write(&response_path, &response);

    let keys = [
        SigningKey::from_bytes(&[3; 32]),
        SigningKey::from_bytes(&[4; 32]),
    ];
    let trust = ObservationTrust {
        schema_version: "telosieve.observation-trust/v1".into(),
        evaluation_time: 1_750_000_000,
        required_distinct_domains: 2,
        keys: keys
            .iter()
            .enumerate()
            .map(|(index, key)| ObservationKey {
                producer: format!("producer-{}", index + 1),
                key_id: format!("key-{}", index + 1),
                fault_domain: format!("domain-{}", index + 1),
                public_key: hex::encode(key.verifying_key().to_bytes()),
                not_before: 1_749_999_900,
                not_after: 1_750_000_200,
            })
            .collect(),
    };
    let trust_path = directory.join("trust.json");
    write(&trust_path, &serde_json::to_vec(&trust).unwrap());
    let envelope_paths = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let producer = format!("producer-{}", index + 1);
            let key_id = format!("key-{}", index + 1);
            let fault_domain = format!("domain-{}", index + 1);
            let attestation = sign_observation(
                &response,
                &ObservationSigningRequest {
                    subject: "kv/research",
                    mode: "external-read-only",
                    producer: &producer,
                    key_id: &key_id,
                    fault_domain: &fault_domain,
                    issued_at: 1_750_000_000,
                    expires_at: 1_750_000_100,
                },
                key,
            )
            .unwrap();
            let path = directory.join(format!("envelope-{index}.json"));
            write(
                &path,
                &serde_json::to_vec(&json!({
                    "schema_version": "telosieve.observation-source/v1",
                    "input_hex": hex::encode(&response),
                    "attestation": attestation,
                }))
                .unwrap(),
            );
            path
        })
        .collect::<Vec<_>>();

    let config_path = directory.join("config.json");
    let certificate_path = directory.join("certificate.json");
    let ledger_path = directory.join("ledger.jsonl");
    let mut configuration = json!({
        "schema_version": "telosieve.evaluation-config/v7",
        "mode": "external-read-only",
        "scenario_path": root.join("scenarios/benign.json"),
        "certificate_path": certificate_path,
        "ledger_path": ledger_path,
        "observation_trust_path": trust_path,
        "observation_sources": envelope_paths.iter().map(|path| json!({
            "executable_path": "/bin/cat",
            "arguments": [path],
        })).collect::<Vec<_>>(),
        "adapter": {
            "executable_path": adapter,
            "arguments": ["--response", response_path],
            "integration_id": "example-service",
            "resource_kind": "replicated-key-value",
            "target_id": "example/service-a",
        },
    });
    write(&config_path, &serde_json::to_vec(&configuration).unwrap());
    let output = run(env!("CARGO_BIN_EXE_telosieve"), &config_path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mode"], "external-read-only");
    assert_eq!(report["target_mutated"], false);
    let certificate: Value = serde_json::from_slice(&fs::read(&certificate_path).unwrap()).unwrap();
    assert_eq!(
        certificate["certificate_version"],
        "telosieve.certificate/v11"
    );
    assert_eq!(
        certificate["integration"]["contract"],
        "telosieve.integration-contract/v1"
    );
    assert_eq!(certificate["integration"]["target_id"], "example/service-a");

    fs::remove_file(&certificate_path).unwrap();
    fs::remove_file(&ledger_path).unwrap();
    let original: Value = serde_json::from_slice(&response).unwrap();
    for (label, mutation) in [
        (
            "mutation-capability",
            json!({"capabilities":{"target_mutated":true}}),
        ),
        ("incomplete", json!({"complete":false})),
        ("context", json!({"target":{"id":"other"}})),
        ("authority", json!({"desired":{"user/message":"poisoned"}})),
    ] {
        let mut changed = original.clone();
        for (key, value) in mutation.as_object().unwrap() {
            if let (Some(existing), Some(fields)) = (changed.get_mut(key), value.as_object()) {
                for (field, item) in fields {
                    existing[field] = item.clone();
                }
            } else {
                changed[key] = value.clone();
            }
        }
        write(&response_path, &serde_json::to_vec(&changed).unwrap());
        for _ in 0..4 {
            let refused = run(env!("CARGO_BIN_EXE_telosieve"), &config_path);
            assert!(!refused.status.success(), "{label}");
            assert!(!certificate_path.exists(), "{label}");
            assert!(!ledger_path.exists(), "{label}");
        }
    }

    write(&response_path, &response);
    configuration["adapter"]["executable_path"] = json!("/bin/sleep");
    configuration["adapter"]["arguments"] = json!(["6"]);
    write(&config_path, &serde_json::to_vec(&configuration).unwrap());
    let started = std::time::Instant::now();
    let timed_out_adapter = run(env!("CARGO_BIN_EXE_telosieve"), &config_path);
    assert!(!timed_out_adapter.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    assert!(!certificate_path.exists());
    assert!(!ledger_path.exists());

    let oversized_path = directory.join("oversized-response");
    write(
        &oversized_path,
        &vec![b'x'; telosieve::integration::MAX_RESPONSE_BYTES + 1],
    );
    configuration["adapter"]["executable_path"] = json!("/bin/cat");
    configuration["adapter"]["arguments"] = json!([oversized_path]);
    write(&config_path, &serde_json::to_vec(&configuration).unwrap());
    let oversized = run(env!("CARGO_BIN_EXE_telosieve"), &config_path);
    assert!(!oversized.status.success());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("integration.resource_bound"));
    assert!(!certificate_path.exists());
    assert!(!ledger_path.exists());

    configuration["adapter"]["executable_path"] = json!(adapter);
    configuration["adapter"]["arguments"] = json!(["--response", response_path]);
    configuration["certificate_path"] = json!(adapter);
    write(&config_path, &serde_json::to_vec(&configuration).unwrap());
    let alias_refused = run(env!("CARGO_BIN_EXE_telosieve"), &config_path);
    assert!(!alias_refused.status.success());
    assert!(!ledger_path.exists());
    fs::remove_dir_all(directory).unwrap();
}
