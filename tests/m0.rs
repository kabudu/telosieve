use std::{fs, path::Path};

use telosieve::{
    certificate::Decision,
    engine::{RunError, run_scenario, run_scenario_file},
    protocol::{AuthorityKind, Scenario},
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
    assert_eq!(certificate.hypotheses.len(), 3);
    assert_eq!(certificate.metrics.false_refusals, 0);
    assert_eq!(
        certificate
            .hypotheses
            .iter()
            .filter(|hypothesis| !hypothesis.suspected_issuers.is_empty())
            .count(),
        2
    );
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
    assert_eq!(certificate.baselines.len(), 3);
    assert!(certificate.baselines[0].unsafe_approval);
    assert_eq!(certificate.baselines[1].decision, Decision::Applied);
    assert_eq!(certificate.baselines[2].decision, Decision::Refused);
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
fn general_enumeration_is_complete_bounded_and_excludes_every_suspect() {
    let mut scenario = load("poisoned-goal.json");
    scenario.fault_declaration.maximum_faults = 2;
    scenario.fault_declaration.maximum_hypotheses = 11;
    scenario.fault_declaration.suspectable = [
        AuthorityKind::Goal,
        AuthorityKind::Phenotype,
        AuthorityKind::Viability,
    ]
    .into_iter()
    .collect();

    let certificate = run_scenario(&scenario).unwrap();

    assert_eq!(certificate.hypotheses.len(), 11);
    assert!(
        certificate
            .hypotheses
            .iter()
            .all(|hypothesis| hypothesis.suspected == hypothesis.excluded)
    );
    let no_evidence_plan = certificate.hypotheses.iter().find(|hypothesis| {
        hypothesis.suspected == vec![AuthorityKind::Goal, AuthorityKind::Phenotype]
    });
    assert!(no_evidence_plan.unwrap().proposed_transition.is_none());
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

#[test]
fn rust_and_python_checkers_agree_on_safe_and_unsafe_transitions() {
    let scenario = load("poisoned-goal.json");
    let certificate = run_scenario(&scenario).unwrap();
    for hypothesis in certificate.hypotheses {
        if let (Some(transition), Some(external)) =
            (hypothesis.proposed_transition, hypothesis.checker)
        {
            let current = serde_json::from_value(scenario.authorities[1].content.clone()).unwrap();
            let rust_safe = scenario
                .authorities
                .iter()
                .filter(|authority| authority.kind == AuthorityKind::Viability)
                .all(|authority| {
                    let rules = serde_json::from_value(authority.content.clone()).unwrap();
                    telosieve::checker::check(&current, &transition, &rules).safe
                });
            assert_eq!(rust_safe, external.safe);
        }
    }
}

#[test]
fn protocol_rejects_stale_unknown_schema_and_duplicate_authorities() {
    let mut stale = load("benign.json");
    stale.evaluation_time = stale.authorities[0].expires_at;
    assert!(matches!(run_scenario(&stale), Err(RunError::Protocol(_))));

    let mut schema = load("benign.json");
    schema.authorities[0].schema_version = "unknown/v9".into();
    assert!(matches!(run_scenario(&schema), Err(RunError::Protocol(_))));

    let mut duplicate = load("benign.json");
    duplicate.authorities.push(duplicate.authorities[0].clone());
    assert!(matches!(
        run_scenario(&duplicate),
        Err(RunError::Protocol(_))
    ));

    let mut duplicate_viability_issuer = load("benign.json");
    duplicate_viability_issuer
        .authorities
        .push(duplicate_viability_issuer.authorities[2].clone());
    assert!(matches!(
        run_scenario(&duplicate_viability_issuer),
        Err(RunError::Protocol(_))
    ));

    let mut missing_viability = load("benign.json");
    missing_viability
        .authorities
        .retain(|authority| authority.kind != AuthorityKind::Viability);
    assert!(matches!(
        run_scenario(&missing_viability),
        Err(RunError::Protocol(_))
    ));

    let mut broken_lineage = load("benign.json");
    broken_lineage.authorities[0].sequence = 2;
    assert!(matches!(
        run_scenario(&broken_lineage),
        Err(RunError::Protocol(_))
    ));
}

#[test]
fn public_replay_reports_all_baselines_and_protocol_evidence() {
    for fixture in ["benign.json", "poisoned-goal.json"] {
        let certificate = run_scenario(&load(fixture)).unwrap();
        let names: Vec<_> = certificate
            .baselines
            .iter()
            .map(|baseline| baseline.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "conventional-reconciler/v0",
                "signed-history-rollback/v0",
                "invariant-gated-reconciler/v0"
            ]
        );
        assert_eq!(certificate.authority_digests.len(), 4);
        assert!(certificate.hypotheses.iter().all(|hypothesis| {
            hypothesis.suspected == hypothesis.excluded
                && hypothesis.checker.as_ref().is_none_or(|verdict| {
                    verdict.implementation == "telosieve-multi-principal-checker/v1"
                        || !verdict.safe
                })
        }));
    }
}
