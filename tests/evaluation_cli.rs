use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Value, json};
use telosieve::{
    certificate::{Certificate, Decision},
    evaluation::{
        CONFIG_SCHEMA_VERSION, MAX_CONFIG_BYTES, REPORT_SCHEMA_VERSION,
        SUPPORTED_EVALUATION_CAPABILITIES,
    },
    model::digest,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let path = Path::new("target")
            .join("evaluation-cli-tests")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

#[test]
fn compiled_capabilities_exactly_match_the_product_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_telosieve"))
        .arg("evaluation-capabilities")
        .output()
        .unwrap();
    assert!(output.status.success());
    let emitted: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        emitted["schema_version"],
        "telosieve.evaluation-capabilities/v2"
    );
    assert_eq!(
        emitted["capabilities"],
        serde_json::to_value(SUPPORTED_EVALUATION_CAPABILITIES).unwrap()
    );
    let contract: Value =
        serde_json::from_slice(include_bytes!("../evaluation/contract.json")).unwrap();
    assert_eq!(
        contract["schema_version"],
        "telosieve.evaluation-product-contract/v3"
    );
    assert_eq!(
        contract["evaluation_authority_boundary"],
        "read-only-no-target-mutation"
    );
    assert_eq!(
        contract["supported_evaluation_modes"],
        emitted["capabilities"]
    );
    assert!(
        emitted["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .all(|capability| capability["target_mutated"] == false)
    );
    assert!(
        emitted["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .all(|capability| {
                capability["observation_quorum_required"] == true
                    && capability["certificate_schema"]
                        .as_str()
                        .is_some_and(|schema| schema.starts_with("telosieve.certificate/v"))
            })
    );
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(config: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_telosieve"))
        .arg("evaluate")
        .arg(config)
        .output()
        .unwrap()
}

fn valid_config(certificate: &str, ledger: &str) -> Value {
    json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "mode": "kubernetes-shadow",
        "scenario_path": "../../../scenarios/benign.json",
        "snapshot_path": "../../../snapshots/kubernetes-shadow-benign.json",
        "observation_trust_path": "../../../evaluation/observation-trust.example.json",
        "observation_quorum_path": "../../../evaluation/observation-quorum.example.json",
        "certificate_path": certificate,
        "ledger_path": ledger
    })
}

#[test]
#[allow(clippy::too_many_lines)]
fn versioned_evaluation_cli_is_read_only_bounded_and_fail_closed() {
    let directory = TestDirectory::create();
    let config_path = directory.0.join("evaluation.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&valid_config("certificate.json", "ledger.jsonl")).unwrap(),
    )
    .unwrap();
    let scenario_before = fs::read("scenarios/benign.json").unwrap();
    let snapshot_before = fs::read("snapshots/kubernetes-shadow-benign.json").unwrap();

    let output = run(&config_path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], REPORT_SCHEMA_VERSION);
    assert_eq!(report["configuration_schema"], CONFIG_SCHEMA_VERSION);
    assert_eq!(report["mode"], "kubernetes-shadow");
    assert_eq!(report["scenario_id"], "benign-update");
    assert_eq!(report["decision"], "applied");
    assert_eq!(report["target_mutated"], false);

    let certificate: Certificate =
        serde_json::from_slice(&fs::read(directory.0.join("certificate.json")).unwrap()).unwrap();
    assert_eq!(certificate.decision, Decision::Applied);
    assert!(certificate.actuation.is_none());
    assert!(certificate.shadow.is_some());
    assert!(
        certificate
            .shadow
            .as_ref()
            .unwrap()
            .observation_quorum_digest
            .is_some()
    );
    assert_eq!(report["certificate_digest"], digest(&certificate));
    assert_eq!(
        fs::read_to_string(directory.0.join("ledger.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(fs::read("scenarios/benign.json").unwrap(), scenario_before);
    assert_eq!(
        fs::read("snapshots/kubernetes-shadow-benign.json").unwrap(),
        snapshot_before
    );

    let mut forged_quorum: Value =
        serde_json::from_slice(&fs::read("evaluation/observation-quorum.example.json").unwrap())
            .unwrap();
    forged_quorum["attestations"][0]["signature"] = "00".repeat(64).into();
    fs::write(
        directory.0.join("forged-quorum.json"),
        serde_json::to_vec(&forged_quorum).unwrap(),
    )
    .unwrap();
    let mut forged_config = valid_config("forged-certificate.json", "forged-ledger.jsonl");
    forged_config["observation_quorum_path"] = "forged-quorum.json".into();
    let forged_config_path = directory.0.join("forged-evaluation.json");
    fs::write(
        &forged_config_path,
        serde_json::to_vec(&forged_config).unwrap(),
    )
    .unwrap();
    assert!(!run(&forged_config_path).status.success());
    assert!(!directory.0.join("forged-certificate.json").exists());
    assert!(!directory.0.join("forged-ledger.jsonl").exists());

    let version = Command::new(env!("CARGO_BIN_EXE_telosieve"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("telosieve {}\n", env!("CARGO_PKG_VERSION"))
    );

    let invalid_cases = [
        (
            "unknown-field.json",
            json!({
                "schema_version": CONFIG_SCHEMA_VERSION,
                "mode": "kubernetes-shadow",
                "scenario_path": "absent",
                "snapshot_path": "absent",
                "observation_trust_path": "absent",
                "observation_quorum_path": "absent",
                "certificate_path": "unused-certificate.json",
                "ledger_path": "unused-ledger.jsonl",
                "unexpected": true
            }),
        ),
        (
            "future-schema.json",
            json!({
                "schema_version": "telosieve.evaluation-config/v5",
                "mode": "kubernetes-shadow",
                "scenario_path": "absent",
                "snapshot_path": "absent",
                "observation_trust_path": "absent",
                "observation_quorum_path": "absent",
                "certificate_path": "unused-certificate.json",
                "ledger_path": "unused-ledger.jsonl"
            }),
        ),
        (
            "missing-field.json",
            json!({
                "schema_version": CONFIG_SCHEMA_VERSION,
                "mode": "kubernetes-shadow",
                "scenario_path": "absent",
                "snapshot_path": "absent",
                "observation_trust_path": "absent",
                "observation_quorum_path": "absent",
                "certificate_path": "unused-certificate.json"
            }),
        ),
        (
            "mutation-mode.json",
            json!({
                "schema_version": CONFIG_SCHEMA_VERSION,
                "mode": "kubernetes-apply",
                "scenario_path": "absent",
                "snapshot_path": "absent",
                "certificate_path": "unused-certificate.json",
                "ledger_path": "unused-ledger.jsonl"
            }),
        ),
    ];
    for (name, value) in invalid_cases {
        let path = directory.0.join(name);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!run(&path).status.success(), "{name} was accepted");
    }

    let collision_path = directory.0.join("collision.json");
    fs::write(
        &collision_path,
        serde_json::to_vec(&valid_config("collision.json", "collision-ledger.jsonl")).unwrap(),
    )
    .unwrap();
    assert!(!run(&collision_path).status.success());

    let temporary_collision_config = directory.0.join("protected-config.json.tmp");
    fs::write(
        &temporary_collision_config,
        serde_json::to_vec(&valid_config("protected-config", "protected-ledger.jsonl")).unwrap(),
    )
    .unwrap();
    let protected_before = fs::read(&temporary_collision_config).unwrap();
    assert!(!run(&temporary_collision_config).status.success());
    assert_eq!(
        fs::read(&temporary_collision_config).unwrap(),
        protected_before
    );

    let long_path = directory.0.join("long-path.json");
    let mut long_config = valid_config("unused-certificate.json", "unused-ledger.jsonl");
    long_config["scenario_path"] = "x".repeat(4097).into();
    fs::write(&long_path, serde_json::to_vec(&long_config).unwrap()).unwrap();
    assert!(!run(&long_path).status.success());

    let oversized_config_path = directory.0.join("oversized-config.json");
    fs::write(
        &oversized_config_path,
        vec![b' '; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1],
    )
    .unwrap();
    assert!(!run(&oversized_config_path).status.success());

    let oversized_scenario = directory.0.join("oversized-scenario.json");
    fs::write(
        &oversized_scenario,
        vec![b' '; usize::try_from(telosieve::engine::MAX_SCENARIO_BYTES).unwrap() + 1],
    )
    .unwrap();
    let scenario_bound_path = directory.0.join("scenario-bound.json");
    let mut scenario_bound = valid_config("bound-certificate.json", "bound-ledger.jsonl");
    scenario_bound["scenario_path"] = "oversized-scenario.json".into();
    fs::write(
        &scenario_bound_path,
        serde_json::to_vec(&scenario_bound).unwrap(),
    )
    .unwrap();
    assert!(!run(&scenario_bound_path).status.success());
    assert!(!directory.0.join("bound-certificate.json").exists());
    assert!(!directory.0.join("bound-ledger.jsonl").exists());
}
