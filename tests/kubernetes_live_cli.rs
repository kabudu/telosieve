use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
use telosieve::evaluation::{LIVE_CONFIG_SCHEMA_VERSION, REPORT_SCHEMA_VERSION};

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

fn config(kubectl: &Path, kubeconfig: &Path) -> Value {
    json!({
        "schema_version": LIVE_CONFIG_SCHEMA_VERSION,
        "mode": "kubernetes-live",
        "scenario_path": fs::canonicalize("scenarios/benign.json").unwrap(),
        "certificate_path": "certificate.json",
        "ledger_path": "ledger.jsonl",
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

#[test]
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
    fs::write(
        &config_path,
        serde_json::to_vec(&config(
            &fs::canonicalize(&kubectl).unwrap(),
            &fs::canonicalize(&kubeconfig).unwrap(),
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
}
