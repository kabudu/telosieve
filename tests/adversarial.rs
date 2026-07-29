use std::{collections::BTreeSet, fs};

use telosieve::{
    certificate::Decision,
    engine::{RunError, run_scenario},
    protocol::{AuthorityKind, Scenario},
};

fn fixture(name: &str) -> Scenario {
    serde_json::from_slice(&fs::read(format!("scenarios/{name}")).unwrap()).unwrap()
}

#[test]
fn registered_adversarial_fault_classes_fail_closed_or_refuse() {
    let poisoned = run_scenario(&fixture("poisoned-goal.json")).unwrap();
    assert_eq!(poisoned.decision, Decision::Refused);

    let mut stale = fixture("benign.json");
    stale.evaluation_time = stale.authorities[0].expires_at;
    assert!(matches!(run_scenario(&stale), Err(RunError::Protocol(_))));

    let mut omitted = fixture("benign.json");
    omitted
        .authorities
        .retain(|envelope| envelope.kind != AuthorityKind::Phenotype);
    assert!(matches!(run_scenario(&omitted), Err(RunError::Protocol(_))));

    let mut forged = fixture("benign.json");
    forged.authorities[1].signature.replace_range(..2, "00");
    assert!(matches!(run_scenario(&forged), Err(RunError::Protocol(_))));

    let weakened = run_scenario(&fixture("weakened-viability.json")).unwrap();
    assert_eq!(weakened.decision, Decision::Refused);
    assert_eq!(weakened.metrics.unsafe_approvals, 0);
    assert_eq!(weakened.metrics.hypothesis_count, 4);
    assert!(weakened.hypotheses.iter().any(|hypothesis| {
        hypothesis.suspected == vec![AuthorityKind::Viability]
            && hypothesis.suspected_issuers == vec!["viability-lab"]
            && hypothesis.proposed_transition.is_some()
            && hypothesis
                .checker
                .as_ref()
                .is_some_and(|checker| !checker.safe)
    }));

    let partitioned = run_scenario(&fixture("partitioned-phenotype.json")).unwrap();
    assert_eq!(partitioned.decision, Decision::Applied);

    let mut equivocation = fixture("benign.json");
    equivocation
        .authorities
        .push(equivocation.authorities[0].clone());
    assert!(matches!(
        run_scenario(&equivocation),
        Err(RunError::Protocol(_))
    ));

    let mut correlated = fixture("poisoned-goal.json");
    correlated.fault_declaration.maximum_faults = 2;
    correlated.fault_declaration.maximum_hypotheses = 11;
    correlated.fault_declaration.suspectable = BTreeSet::from([
        AuthorityKind::Goal,
        AuthorityKind::Phenotype,
        AuthorityKind::Viability,
    ]);
    assert_eq!(
        run_scenario(&correlated).unwrap().decision,
        Decision::Refused
    );
}
