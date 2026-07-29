use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

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
    assert_eq!(weakened.metrics.hypothesis_count, 5);
    assert!(weakened.hypotheses.iter().any(|hypothesis| {
        hypothesis.suspected == vec![AuthorityKind::Viability]
            && hypothesis.suspected_fault_domains == vec!["lab-domain"]
            && hypothesis.suspected_issuers == vec!["viability-lab", "viability-peer"]
            && hypothesis.proposed_transition.is_some()
            && hypothesis
                .checker
                .as_ref()
                .is_some_and(|checker| !checker.safe)
    }));
    let benign_domains = run_scenario(&fixture("benign.json")).unwrap();
    assert_eq!(benign_domains.decision, Decision::Applied);
    assert_eq!(benign_domains.metrics.false_refusals, 0);
    assert!(benign_domains.hypotheses.iter().any(|hypothesis| {
        hypothesis.suspected_fault_domains == vec!["lab-domain"]
            && hypothesis.excluded_issuers == vec!["viability-lab", "viability-peer"]
    }));

    let cross_domain = run_scenario(&fixture("all-viability-domains-weakened.json")).unwrap();
    assert_eq!(cross_domain.decision, Decision::Refused);
    assert_eq!(cross_domain.metrics.unsafe_approvals, 0);
    assert!(cross_domain.hypotheses.iter().all(|hypothesis| {
        hypothesis.checker.as_ref().is_some_and(|checker| {
            !checker.safe
                && checker
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("stable key continuity failed: cluster/epoch"))
        })
    }));

    let mut missing_domain = fixture("benign.json");
    missing_domain
        .fault_declaration
        .viability_fault_domains
        .remove("viability-peer");
    assert!(matches!(
        run_scenario(&missing_domain),
        Err(RunError::FaultDeclaration(_))
    ));
    let mut unknown_domain = fixture("poisoned-goal.json");
    unknown_domain
        .fault_declaration
        .goal_fault_domains
        .insert("goal-ghost".into(), "goal-ghost-domain".into());
    assert!(matches!(
        run_scenario(&unknown_domain),
        Err(RunError::FaultDeclaration(_))
    ));

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
    correlated.fault_declaration.maximum_hypotheses = 16;
    correlated.fault_declaration.suspectable = BTreeSet::from([
        AuthorityKind::Goal,
        AuthorityKind::Phenotype,
        AuthorityKind::Viability,
    ]);
    correlated.fault_declaration.viability_fault_domains = BTreeMap::from([
        ("viability-lab".into(), "lab-domain".into()),
        ("viability-peer".into(), "lab-domain".into()),
        ("viability-review".into(), "review-domain".into()),
    ]);
    assert_eq!(
        run_scenario(&correlated).unwrap().decision,
        Decision::Refused
    );
}

#[test]
fn goal_domains_preserve_agreement_and_reject_invalid_or_divergent_evidence() {
    let poisoned = run_scenario(&fixture("poisoned-goal.json")).unwrap();
    assert_eq!(poisoned.metrics.hypothesis_count, 3);
    for (domain, issuer) in [
        ("goal-lab-domain", "goal-lab"),
        ("goal-review-domain", "goal-review"),
    ] {
        assert!(poisoned.hypotheses.iter().any(|hypothesis| {
            hypothesis.suspected == vec![AuthorityKind::Goal]
                && hypothesis.suspected_fault_domains == vec![domain]
                && hypothesis.suspected_issuers == vec![issuer]
                && hypothesis.proposed_transition.is_some()
        }));
    }

    let mut missing_domain = fixture("poisoned-goal.json");
    missing_domain
        .fault_declaration
        .goal_fault_domains
        .remove("goal-review");
    assert!(matches!(
        run_scenario(&missing_domain),
        Err(RunError::FaultDeclaration(_))
    ));

    let benign_review = fixture("benign.json")
        .authorities
        .into_iter()
        .find(|authority| authority.issuer == "goal-review")
        .unwrap();
    let mut divergent = fixture("poisoned-goal.json");
    *divergent
        .authorities
        .iter_mut()
        .find(|authority| authority.issuer == "goal-review")
        .unwrap() = benign_review;
    assert!(matches!(
        run_scenario(&divergent),
        Err(RunError::Protocol(_))
    ));

    let mut correlated = fixture("benign.json");
    correlated
        .fault_declaration
        .suspectable
        .insert(AuthorityKind::Goal);
    correlated.fault_declaration.goal_fault_domains = BTreeMap::from([
        ("goal-lab".into(), "shared-goal-domain".into()),
        ("goal-review".into(), "shared-goal-domain".into()),
    ]);
    correlated.fault_declaration.maximum_hypotheses = 4;
    let certificate = run_scenario(&correlated).unwrap();
    assert_eq!(certificate.decision, Decision::Refused);
    assert!(certificate.hypotheses.iter().any(|hypothesis| {
        hypothesis.suspected_fault_domains == vec!["shared-goal-domain"]
            && hypothesis.proposed_transition.is_none()
    }));
}

#[test]
fn deletion_requires_exact_bound_authorization_with_a_surviving_domain() {
    let authorized = run_scenario(&fixture("authorized-deletion.json")).unwrap();
    assert_eq!(authorized.decision, Decision::Applied);
    assert_eq!(authorized.metrics.unsafe_approvals, 0);
    assert!(authorized.final_state.replicas.values().all(|values| {
        values.contains_key("cluster/epoch") && !values.contains_key("user/message")
    }));
    assert!(
        authorized
            .hypotheses
            .iter()
            .all(|hypothesis| { hypothesis.authorized_deletions == vec!["user/message"] })
    );

    let unauthorized = run_scenario(&fixture("unauthorized-deletion.json")).unwrap();
    assert_eq!(unauthorized.decision, Decision::Refused);
    assert_eq!(unauthorized.metrics.unsafe_approvals, 0);

    let deletion_evidence: Vec<_> = fixture("authorized-deletion.json")
        .authorities
        .into_iter()
        .filter(|authority| authority.kind == AuthorityKind::Deletion)
        .collect();
    let mut replayed = fixture("benign.json");
    replayed
        .fault_declaration
        .suspectable
        .insert(AuthorityKind::Deletion);
    replayed.fault_declaration.deletion_fault_domains = BTreeMap::from([
        ("deletion-lab".into(), "deletion-lab-domain".into()),
        ("deletion-review".into(), "deletion-review-domain".into()),
    ]);
    replayed.fault_declaration.maximum_hypotheses = 5;
    replayed.authorities.extend(deletion_evidence);
    assert!(matches!(
        run_scenario(&replayed),
        Err(RunError::Protocol(_))
    ));

    let mut missing_domain = fixture("authorized-deletion.json");
    missing_domain
        .fault_declaration
        .deletion_fault_domains
        .remove("deletion-review");
    assert!(matches!(
        run_scenario(&missing_domain),
        Err(RunError::FaultDeclaration(_))
    ));

    let mut correlated = fixture("authorized-deletion.json");
    correlated.fault_declaration.deletion_fault_domains = BTreeMap::from([
        ("deletion-lab".into(), "shared-deletion-domain".into()),
        ("deletion-review".into(), "shared-deletion-domain".into()),
    ]);
    let certificate = run_scenario(&correlated).unwrap();
    assert_eq!(certificate.decision, Decision::Refused);
    assert_eq!(certificate.metrics.false_refusals, 1);
    assert!(certificate.hypotheses.iter().any(|hypothesis| {
        hypothesis.suspected_fault_domains == vec!["shared-deletion-domain"]
            && hypothesis.authorized_deletions.is_empty()
    }));
}
