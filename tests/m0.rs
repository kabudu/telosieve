use std::{collections::BTreeMap, fs, path::Path, process::Command};

use telosieve::{
    certificate::Decision,
    engine::{
        RunError, initialize_actuator_file, initialize_anchor_file, read_actuator_state_file,
        run_scenario, run_scenario_file, run_scenario_file_actuated, run_scenario_file_anchored,
    },
    protocol::{AuthorityKind, Scenario},
};

fn load(name: &str) -> Scenario {
    serde_json::from_slice(
        &fs::read(Path::new("scenarios").join(name)).expect("fixture should exist"),
    )
    .expect("fixture should be valid")
}

fn content(scenario: &Scenario, kind: AuthorityKind) -> serde_json::Value {
    scenario
        .authorities
        .iter()
        .find(|authority| authority.kind == kind)
        .unwrap()
        .content
        .clone()
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
        serde_json::from_value(content(&scenario, AuthorityKind::Phenotype)).unwrap()
    );
}

#[test]
fn poisoned_goal_is_refused_and_state_is_unchanged() {
    let scenario = load("poisoned-goal.json");
    let certificate = run_scenario(&scenario).expect("poisoned scenario should run");

    assert_eq!(certificate.decision, Decision::Refused);
    assert_eq!(certificate.hypotheses.len(), 3);
    assert!(certificate.transition.is_none());
    assert_eq!(
        certificate.final_state,
        serde_json::from_value(content(&scenario, AuthorityKind::Phenotype)).unwrap()
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
fn authenticated_history_replays_predecessor_and_rejects_rollback() {
    let scenario = load("poisoned-goal.json");
    let certificate = run_scenario(&scenario).unwrap();
    let history = certificate
        .baselines
        .iter()
        .find(|baseline| baseline.name == "signed-history-replay/v1")
        .unwrap();
    assert_eq!(
        history
            .transition
            .as_ref()
            .unwrap()
            .after
            .consensus()
            .unwrap()["user/message"],
        "stable"
    );

    let mut omitted = scenario.clone();
    omitted.phenotype_history.clear();
    assert!(matches!(run_scenario(&omitted), Err(RunError::Protocol(_))));

    let mut replayed_tip = scenario.clone();
    replayed_tip.phenotype_history_anchor.sequence = 1;
    replayed_tip.phenotype_history_anchor.tip_digest =
        telosieve::model::digest(&replayed_tip.phenotype_history[0]);
    assert!(matches!(
        run_scenario(&replayed_tip),
        Err(RunError::Protocol(_))
    ));

    let mut forked = scenario;
    forked
        .phenotype_history
        .push(forked.phenotype_history[0].clone());
    assert!(matches!(run_scenario(&forked), Err(RunError::Protocol(_))));

    let mut over_bound = load("poisoned-goal.json");
    over_bound.phenotype_history = vec![over_bound.phenotype_history[0].clone(); 65];
    assert!(matches!(
        run_scenario(&over_bound),
        Err(RunError::Protocol(_))
    ));
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
    scenario.fault_declaration.maximum_hypotheses = 16;
    scenario.fault_declaration.suspectable = [
        AuthorityKind::Goal,
        AuthorityKind::Phenotype,
        AuthorityKind::Viability,
    ]
    .into_iter()
    .collect();
    scenario.fault_declaration.viability_fault_domains = BTreeMap::from([
        ("viability-lab".into(), "lab-domain".into()),
        ("viability-peer".into(), "lab-domain".into()),
        ("viability-review".into(), "review-domain".into()),
    ]);

    let certificate = run_scenario(&scenario).unwrap();

    assert_eq!(certificate.hypotheses.len(), 16);
    assert!(
        certificate
            .hypotheses
            .iter()
            .all(|hypothesis| hypothesis.suspected == hypothesis.excluded)
    );
    assert!(certificate.hypotheses.iter().all(|hypothesis| {
        hypothesis.suspected != vec![AuthorityKind::Goal]
            || hypothesis.proposed_transition.is_some()
    }));
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
fn durable_anchor_initialization_and_public_run_are_fail_closed() {
    let test_dir = Path::new("target")
        .join("durable-anchor-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/benign.json");
    let anchor = test_dir.join("anchor.json");
    let certificate = test_dir.join("certificate.json");
    let ledger = test_dir.join("ledger.jsonl");

    assert!(matches!(
        run_scenario_file_anchored(scenario, &certificate, &ledger, &anchor),
        Err(RunError::Anchor(_))
    ));
    assert!(!certificate.exists());
    assert!(!ledger.exists());

    initialize_anchor_file(scenario, &anchor).unwrap();
    let result = run_scenario_file_anchored(scenario, &certificate, &ledger, &anchor).unwrap();
    assert_eq!(result.decision, Decision::Applied);
    assert!(certificate.exists());
    assert_eq!(fs::read_to_string(ledger).unwrap().lines().count(), 1);

    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn anchored_authorized_deletion_is_consumed_once() {
    let test_dir = Path::new("target")
        .join("deletion-consumption-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/authorized-deletion.json");
    let anchor = test_dir.join("anchor.json");
    let certificate = test_dir.join("certificate.json");
    let ledger = test_dir.join("ledger.jsonl");

    initialize_anchor_file(scenario, &anchor).unwrap();
    let first = run_scenario_file_anchored(scenario, &certificate, &ledger, &anchor).unwrap();
    assert_eq!(first.decision, Decision::Applied);
    assert!(first.deletion_authorization_id.is_some());
    assert!(matches!(
        run_scenario_file_anchored(scenario, &certificate, &ledger, &anchor),
        Err(RunError::Anchor(
            telosieve::anchor_store::AnchorError::AuthorizationConsumed(_)
        ))
    ));
    assert_eq!(fs::read_to_string(&ledger).unwrap().lines().count(), 1);

    let replayable = run_scenario(&load("authorized-deletion.json")).unwrap();
    assert_eq!(
        replayable.deletion_authorization_id,
        first.deletion_authorization_id
    );
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn evidence_failure_burns_applied_deletion_authorization_safely() {
    let test_dir = Path::new("target")
        .join("deletion-evidence-failure-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/authorized-deletion.json");
    let anchor = test_dir.join("anchor.json");
    let certificate = test_dir.join("certificate.json");
    let invalid_ledger = test_dir.join("ledger-directory");
    fs::create_dir(&invalid_ledger).unwrap();

    initialize_anchor_file(scenario, &anchor).unwrap();
    assert!(matches!(
        run_scenario_file_anchored(scenario, &certificate, &invalid_ledger, &anchor),
        Err(RunError::Io(_))
    ));
    assert!(!certificate.exists());
    assert!(matches!(
        run_scenario_file_anchored(scenario, &certificate, &invalid_ledger, &anchor),
        Err(RunError::Anchor(
            telosieve::anchor_store::AnchorError::AuthorizationConsumed(_)
        ))
    ));
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn transactional_local_actuator_applies_once_and_exposes_committed_state() {
    let test_dir = Path::new("target")
        .join("local-actuator-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/benign.json");
    let actuator = test_dir.join("actuator.json");
    let certificate = test_dir.join("certificate.json");
    let ledger = test_dir.join("ledger.jsonl");

    initialize_actuator_file(scenario, &actuator).unwrap();
    let result = run_scenario_file_actuated(scenario, &certificate, &ledger, &actuator).unwrap();
    assert_eq!(result.certificate_version, "telosieve.certificate/v8");
    assert_eq!(result.decision, Decision::Applied);
    let receipt = result.actuation.unwrap();
    assert_ne!(receipt.before_digest, receipt.after_digest);
    assert_eq!(
        read_actuator_state_file(&actuator)
            .unwrap()
            .consensus()
            .unwrap()["user/message"],
        "new"
    );
    assert_eq!(fs::read_to_string(&ledger).unwrap().lines().count(), 1);

    assert!(matches!(
        run_scenario_file_actuated(scenario, &certificate, &ledger, &actuator),
        Err(RunError::Actuator(
            telosieve::actuator_store::ActuatorError::ObservedStateMismatch
        ))
    ));
    assert_eq!(fs::read_to_string(&ledger).unwrap().lines().count(), 1);
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn transactional_local_actuator_refusal_preserves_service_state() {
    let test_dir = Path::new("target")
        .join("local-actuator-refusal-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/poisoned-goal.json");
    let actuator = test_dir.join("actuator.json");
    let certificate = test_dir.join("certificate.json");
    let ledger = test_dir.join("ledger.jsonl");

    initialize_actuator_file(scenario, &actuator).unwrap();
    let before = read_actuator_state_file(&actuator).unwrap();
    let result = run_scenario_file_actuated(scenario, &certificate, &ledger, &actuator).unwrap();
    assert_eq!(result.decision, Decision::Refused);
    let receipt = result.actuation.unwrap();
    assert_eq!(receipt.before_digest, receipt.after_digest);
    assert_eq!(read_actuator_state_file(&actuator).unwrap(), before);
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn local_actuation_survives_post_commit_evidence_failure_without_retrying() {
    let test_dir = Path::new("target")
        .join("local-actuator-evidence-failure-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let scenario = Path::new("scenarios/authorized-deletion.json");
    let actuator = test_dir.join("actuator.json");
    let certificate = test_dir.join("certificate.json");
    let invalid_ledger = test_dir.join("ledger-directory");
    fs::create_dir(&invalid_ledger).unwrap();

    initialize_actuator_file(scenario, &actuator).unwrap();
    assert!(matches!(
        run_scenario_file_actuated(scenario, &certificate, &invalid_ledger, &actuator),
        Err(RunError::Io(_))
    ));
    assert!(!certificate.exists());
    assert!(
        read_actuator_state_file(&actuator)
            .unwrap()
            .replicas
            .values()
            .all(|values| !values.contains_key("user/message"))
    );
    assert!(
        telosieve::engine::read_actuator_snapshot_file(&actuator)
            .unwrap()
            .last_actuation
            .is_some()
    );
    assert!(matches!(
        run_scenario_file_actuated(scenario, &certificate, &invalid_ledger, &actuator),
        Err(RunError::Actuator(
            telosieve::actuator_store::ActuatorError::ObservedStateMismatch
        ))
    ));
    fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn local_actuator_cli_exercises_initialize_apply_and_read_lifecycle() {
    let test_dir = Path::new("target")
        .join("local-actuator-cli-tests")
        .join(std::process::id().to_string());
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();
    let binary = env!("CARGO_BIN_EXE_telosieve");
    let scenario = Path::new("scenarios/benign.json");
    let actuator = test_dir.join("actuator.json");
    let certificate = test_dir.join("certificate.json");
    let ledger = test_dir.join("ledger.jsonl");

    assert!(
        Command::new(binary)
            .args(["local-init"])
            .arg(scenario)
            .arg(&actuator)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        Command::new(binary)
            .args(["apply-local"])
            .arg(scenario)
            .arg(&certificate)
            .arg(&ledger)
            .arg(&actuator)
            .output()
            .unwrap()
            .status
            .success()
    );
    let output = Command::new(binary)
        .args(["local-show"])
        .arg(&actuator)
        .output()
        .unwrap();
    assert!(output.status.success());
    let snapshot: telosieve::actuator_store::ActuatorSnapshot =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        snapshot.service_state.consensus().unwrap()["user/message"],
        "new"
    );
    assert!(snapshot.last_actuation.is_some());
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
            let current =
                serde_json::from_value(content(&scenario, AuthorityKind::Phenotype)).unwrap();
            let rust_safe = scenario
                .authorities
                .iter()
                .filter(|authority| authority.kind == AuthorityKind::Viability)
                .all(|authority| {
                    let rules = serde_json::from_value(authority.content.clone()).unwrap();
                    telosieve::checker::check(
                        &current,
                        &transition,
                        &rules,
                        &std::collections::BTreeSet::new(),
                    )
                    .safe
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
    let viability = duplicate_viability_issuer
        .authorities
        .iter()
        .find(|authority| authority.kind == AuthorityKind::Viability)
        .unwrap()
        .clone();
    duplicate_viability_issuer.authorities.push(viability);
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
        assert_eq!(certificate.certificate_version, "telosieve.certificate/v7");
        let names: Vec<_> = certificate
            .baselines
            .iter()
            .map(|baseline| baseline.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "conventional-reconciler/v0",
                "signed-history-replay/v1",
                "invariant-gated-reconciler/v0"
            ]
        );
        assert_eq!(certificate.authority_digests.len(), 7);
        assert!(certificate.hypotheses.iter().all(|hypothesis| {
            hypothesis.suspected == hypothesis.excluded
                && hypothesis.checker.as_ref().is_none_or(|verdict| {
                    verdict.implementation == "telosieve-multi-principal-checker/v2"
                        || !verdict.safe
                })
        }));
    }
}
