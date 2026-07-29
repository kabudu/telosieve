use std::{fs, path::Path};

use telosieve::{
    certificate::Decision,
    engine::{RunError, run_scenario, run_scenario_file},
    protocol::Scenario,
};

fn load(name: &str) -> Scenario {
    serde_json::from_slice(
        &fs::read(Path::new("scenarios").join(name)).expect("fixture should exist"),
    )
    .expect("fixture should be valid")
}

#[test]
fn benign_goal_is_applied_and_rollback_restores_snapshot() {
    let scenario = load("benign.json");
    let certificate = run_scenario(&scenario).expect("benign scenario should run");

    assert_eq!(certificate.decision, Decision::Applied);
    assert_eq!(certificate.hypotheses.len(), 1);
    assert_eq!(
        certificate.final_state.consensus().unwrap()["user/message"],
        "new"
    );
    assert_eq!(
        certificate.rollback.as_ref().unwrap().after,
        serde_json::from_value(scenario.authorities[1].content.clone()).unwrap()
    );
}

#[test]
fn poisoned_goal_is_refused_and_state_is_unchanged() {
    let scenario = load("poisoned-goal.json");
    let certificate = run_scenario(&scenario).expect("poisoned scenario should run");

    assert_eq!(certificate.decision, Decision::Refused);
    assert_eq!(certificate.hypotheses.len(), 2);
    assert!(certificate.transition.is_none());
    assert_eq!(
        certificate.final_state,
        serde_json::from_value(scenario.authorities[1].content.clone()).unwrap()
    );
    assert!(certificate.hypotheses.iter().any(|hypothesis| {
        hypothesis
            .checker
            .as_ref()
            .is_some_and(|verdict| !verdict.safe)
    }));
    assert!(certificate.baseline.unsafe_approval);
    assert_eq!(certificate.metrics.unsafe_approvals, 0);
}

#[test]
fn replay_is_byte_deterministic() {
    let scenario = load("poisoned-goal.json");
    let first = serde_json::to_vec(&run_scenario(&scenario).unwrap()).unwrap();
    let second = serde_json::to_vec(&run_scenario(&scenario).unwrap()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn tampering_fails_closed() {
    let mut scenario = load("benign.json");
    scenario.authorities[0].content["user/message"] = "tampered".into();
    assert!(matches!(
        run_scenario(&scenario),
        Err(RunError::Protocol(_))
    ));
}

#[test]
fn configured_hypothesis_bound_is_enforced() {
    let mut scenario = load("poisoned-goal.json");
    scenario.fault_declaration.maximum_hypotheses = 1;
    assert!(matches!(
        run_scenario(&scenario),
        Err(RunError::FaultDeclaration(_))
    ));
}

#[test]
fn file_boundary_writes_certificate_and_append_only_ledger() {
    let test_dir = Path::new("target")
        .join("m0-tests")
        .join(std::process::id().to_string());
    fs::create_dir_all(&test_dir).unwrap();
    let certificate_path = test_dir.join("certificate.json");
    let ledger_path = test_dir.join("ledger.jsonl");
    let _ = fs::remove_file(&certificate_path);
    let _ = fs::remove_file(&ledger_path);
    let scenario_path = Path::new("scenarios/poisoned-goal.json");

    let expected = run_scenario_file(scenario_path, &certificate_path, &ledger_path).unwrap();
    run_scenario_file(scenario_path, &certificate_path, &ledger_path).unwrap();

    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(certificate_path).unwrap()).unwrap();
    assert_eq!(persisted["scenario_id"], expected.scenario_id);
    let ledger = fs::read_to_string(ledger_path).unwrap();
    assert_eq!(ledger.lines().count(), 2);
    assert!(
        ledger
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
    );
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn ledger_failure_does_not_publish_a_certificate() {
    let test_dir = Path::new("target")
        .join("m0-ledger-failure")
        .join(std::process::id().to_string());
    fs::create_dir_all(&test_dir).unwrap();
    let certificate_path = test_dir.join("certificate.json");

    let result = run_scenario_file(
        Path::new("scenarios/benign.json"),
        &certificate_path,
        &test_dir,
    );

    assert!(matches!(result, Err(RunError::Io(_))));
    assert!(!certificate_path.exists());
    fs::remove_dir_all(test_dir).unwrap();
}
