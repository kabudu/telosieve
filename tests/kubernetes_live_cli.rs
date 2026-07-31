use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use telosieve::{
    evaluation::{LIVE_CONFIG_SCHEMA_VERSION, REPORT_SCHEMA_VERSION},
    kubernetes_shadow::KubernetesShadowSnapshot,
    observation_quorum::{
        ObservationKey, ObservationSigningRequest, ObservationTrust, TRUST_SCHEMA_VERSION,
        sign_observation,
    },
    observation_source::ENVELOPE_SCHEMA_VERSION,
};

struct Directory(PathBuf);
impl Directory {
    fn create() -> Self {
        let path = Path::new("target")
            .join("kubernetes-live-tests")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(kubectl: &Path, kubeconfig: &Path, trust: &Path, envelopes: &[PathBuf]) -> Value {
    json!({
        "schema_version": LIVE_CONFIG_SCHEMA_VERSION,
        "mode": "kubernetes-live",
        "scenario_path": fs::canonicalize("scenarios/benign.json").unwrap(),
        "certificate_path": "certificate.json",
        "ledger_path": "ledger.jsonl",
        "observation_trust_path": trust,
        "observation_sources": envelopes.iter().map(|path| json!({
            "executable_path": "/bin/cat",
            "arguments": [path]
        })).collect::<Vec<_>>(),
        "kubernetes": {
            "kubectl_path": kubectl,
            "kubeconfig_path": kubeconfig,
            "context": "evaluation",
            "namespace": "telosieve-research",
            "desired_config_map": "repair-goal",
            "observed_stateful_set": "research-kv"
        }
    })
}

#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: &'static str,
    snapshot: &'a KubernetesShadowSnapshot,
    attestation: telosieve::observation_quorum::ObservationAttestation,
}

fn observation_files(directory: &Path) -> (PathBuf, Vec<PathBuf>) {
    let snapshot: KubernetesShadowSnapshot =
        serde_json::from_slice(&fs::read("snapshots/kubernetes-shadow-benign.json").unwrap())
            .unwrap();
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
    let specifications = [
        ("producer-a", "key-a", "domain-a", [11_u8; 32]),
        ("producer-b", "key-b", "domain-b", [12_u8; 32]),
    ];
    let mut keys = Vec::new();
    let mut envelopes = Vec::new();
    for (index, (producer, key_id, domain, seed)) in specifications.iter().enumerate() {
        let key = SigningKey::from_bytes(seed);
        keys.push(ObservationKey {
            producer: (*producer).into(),
            key_id: (*key_id).into(),
            fault_domain: (*domain).into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            not_before: 1_788_000_000,
            not_after: 1_800_000_000,
        });
        let attestation = sign_observation(
            &snapshot_bytes,
            &ObservationSigningRequest {
                subject: &snapshot.subject,
                mode: "kubernetes-live",
                producer,
                key_id,
                fault_domain: domain,
                issued_at: 1_788_000_000,
                expires_at: 1_788_000_300,
            },
            &key,
        )
        .unwrap();
        let path = directory.join(format!("envelope-{index}.json"));
        fs::write(
            &path,
            serde_json::to_vec(&Envelope {
                schema_version: ENVELOPE_SCHEMA_VERSION,
                snapshot: &snapshot,
                attestation,
            })
            .unwrap(),
        )
        .unwrap();
        envelopes.push(fs::canonicalize(path).unwrap());
    }
    let trust = directory.join("trust.json");
    fs::write(
        &trust,
        serde_json::to_vec(&ObservationTrust {
            schema_version: TRUST_SCHEMA_VERSION.into(),
            evaluation_time: 1_788_000_100,
            required_distinct_domains: 2,
            keys,
        })
        .unwrap(),
    )
    .unwrap();
    (fs::canonicalize(trust).unwrap(), envelopes)
}

#[test]
#[allow(clippy::too_many_lines)]
fn live_collector_uses_four_reads_and_fails_closed_on_drift() {
    let directory = Directory::create();
    let kubectl = directory.0.join("kubectl");
    fs::copy("tests/fixtures/fake-kubectl", &kubectl).unwrap();
    let mut permissions = fs::metadata(&kubectl).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&kubectl, permissions).unwrap();
    let kubeconfig = directory.0.join("kubeconfig");
    fs::write(&kubeconfig, "trusted test credential boundary").unwrap();
    let config_path = directory.0.join("evaluation.json");
    let (trust, envelopes) = observation_files(&directory.0);
    fs::write(
        &config_path,
        serde_json::to_vec(&config(
            &fs::canonicalize(&kubectl).unwrap(),
            &fs::canonicalize(&kubeconfig).unwrap(),
            &trust,
            &envelopes,
        ))
        .unwrap(),
    )
    .unwrap();
    let log = directory.0.join("calls.jsonl");
    let counter = directory.0.join("counter");
    let run = |case: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_telosieve"));
        command
            .arg("evaluate")
            .arg(&config_path)
            .env("TELOSIEVE_KUBECTL_LOG", &log)
            .env("TELOSIEVE_KUBECTL_COUNTER", &counter);
        if let Some(case) = case {
            command.env("TELOSIEVE_KUBECTL_CASE", case);
        }
        command.output().unwrap()
    };
    let output = run(None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], REPORT_SCHEMA_VERSION);
    assert_eq!(report["configuration_schema"], LIVE_CONFIG_SCHEMA_VERSION);
    assert_eq!(report["mode"], "kubernetes-live");
    assert_eq!(report["target_mutated"], false);
    let certificate: Value =
        serde_json::from_slice(&fs::read(directory.0.join("certificate.json")).unwrap()).unwrap();
    assert!(certificate["shadow"]["observation_quorum_digest"].is_string());
    let calls: Vec<Value> = fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|call| {
        call.as_array()
            .unwrap()
            .contains(&Value::String("get".into()))
    }));
    assert!(
        calls
            .iter()
            .flat_map(|call| call.as_array().unwrap())
            .all(|arg| {
                !["apply", "create", "delete", "patch", "update"]
                    .contains(&arg.as_str().unwrap_or(""))
            })
    );

    for case in [
        "drift",
        "not-ready",
        "wrong-owner",
        "error",
        "oversized",
        "timeout",
        "selector-expression",
    ] {
        let _ = fs::remove_file(directory.0.join("certificate.json"));
        let _ = fs::remove_file(directory.0.join("ledger.jsonl"));
        let _ = fs::remove_file(&counter);
        let refusal = run(Some(case));
        assert!(!refusal.status.success(), "{case} was accepted");
        assert!(
            !directory.0.join("certificate.json").exists(),
            "{case} wrote a certificate"
        );
        assert!(
            !directory.0.join("ledger.jsonl").exists(),
            "{case} wrote a ledger"
        );
    }

    let original_envelope = fs::read(&envelopes[0]).unwrap();
    for source_case in ["forged", "disagreement"] {
        let mut envelope: Value = serde_json::from_slice(&original_envelope).unwrap();
        if source_case == "forged" {
            envelope["attestation"]["signature"] = "00".repeat(64).into();
        } else {
            envelope["snapshot"]["captured_at"] =
                (envelope["snapshot"]["captured_at"].as_u64().unwrap() + 1).into();
        }
        fs::write(&envelopes[0], serde_json::to_vec(&envelope).unwrap()).unwrap();
        let _ = fs::remove_file(directory.0.join("certificate.json"));
        let _ = fs::remove_file(directory.0.join("ledger.jsonl"));
        let _ = fs::remove_file(&counter);
        let refusal = run(None);
        assert!(
            !refusal.status.success(),
            "{source_case} source was accepted"
        );
        assert!(!directory.0.join("certificate.json").exists());
        assert!(!directory.0.join("ledger.jsonl").exists());
    }
    fs::write(&envelopes[0], original_envelope).unwrap();

    let original_config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    for (source_case, executable, arguments) in [
        ("malformed", "/bin/echo", json!(["not-json"])),
        ("oversized", "/usr/bin/yes", json!([])),
        ("timeout", "/bin/sleep", json!(["6"])),
    ] {
        let mut hostile = original_config.clone();
        hostile["observation_sources"][0]["executable_path"] = executable.into();
        hostile["observation_sources"][0]["arguments"] = arguments;
        fs::write(&config_path, serde_json::to_vec(&hostile).unwrap()).unwrap();
        let _ = fs::remove_file(directory.0.join("certificate.json"));
        let _ = fs::remove_file(directory.0.join("ledger.jsonl"));
        let _ = fs::remove_file(&counter);
        let refusal = run(None);
        assert!(
            !refusal.status.success(),
            "{source_case} source was accepted"
        );
        assert!(!directory.0.join("certificate.json").exists());
        assert!(!directory.0.join("ledger.jsonl").exists());
    }
    fs::write(&config_path, serde_json::to_vec(&original_config).unwrap()).unwrap();

    let executable_before = fs::read("/bin/cat").unwrap();
    let mut collision = original_config;
    collision["certificate_path"] = "/bin/cat".into();
    fs::write(&config_path, serde_json::to_vec(&collision).unwrap()).unwrap();
    let _ = fs::remove_file(directory.0.join("ledger.jsonl"));
    assert!(!run(None).status.success());
    assert_eq!(fs::read("/bin/cat").unwrap(), executable_before);
    assert!(!directory.0.join("ledger.jsonl").exists());
}
