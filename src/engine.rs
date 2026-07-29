use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use thiserror::Error;

use crate::{
    certificate::{BaselineRecord, Certificate, Decision, HypothesisRecord, Metrics},
    checker,
    model::{Transition, digest},
    protocol::{
        AuthorityKind, ExpectedDecision, ProtocolError, Scenario, VerifiedAuthorities, verify,
    },
};

#[derive(Debug, Error)]
pub enum RunError {
    #[error("scenario I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("scenario JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("authority verification failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("fault declaration invalid: {0}")]
    FaultDeclaration(String),
    #[error("independent checker failed: {0}")]
    Checker(#[from] crate::external_checker::ExternalCheckerError),
}

/// Runs a scenario through the public file boundary and persists its evidence.
///
/// # Errors
///
/// Returns [`RunError`] for input, protocol, configuration, or output failures.
pub fn run_scenario_file(
    path: &Path,
    certificate_path: &Path,
    ledger_path: &Path,
) -> Result<Certificate, RunError> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(path)?)?;
    let certificate = run_scenario(&scenario)?;
    let mut ledger = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)?;
    ledger.write_all(&serde_json::to_vec(&certificate)?)?;
    ledger.write_all(b"\n")?;
    ledger.sync_all()?;
    let bytes = serde_json::to_vec_pretty(&certificate)?;
    let temporary_path = certificate_path.with_extension("json.tmp");
    fs::write(&temporary_path, &bytes)?;
    fs::rename(temporary_path, certificate_path)?;
    Ok(certificate)
}

/// Evaluates one deterministic, bounded research scenario.
///
/// # Errors
///
/// Returns [`RunError`] when the fault declaration exceeds its configured bound or
/// when any authority fails verification.
pub fn run_scenario(scenario: &Scenario) -> Result<Certificate, RunError> {
    let authorities = verify(scenario)?;
    validate_declaration(scenario, &authorities)?;
    let mut checker_session = crate::external_checker::CheckerSession::start()?;
    let hypotheses = enumerate_hypotheses(scenario, &authorities, &mut checker_session)?;
    let safe_transitions: Vec<&Transition> = hypotheses
        .iter()
        .filter_map(
            |record| match (&record.proposed_transition, &record.checker) {
                (Some(transition), Some(verdict)) if verdict.safe => Some(transition),
                _ => None,
            },
        )
        .collect();
    let every_hypothesis_safe = safe_transitions.len() == hypotheses.len();
    let unique = safe_transitions.first().filter(|first| {
        safe_transitions
            .iter()
            .all(|item| item.after == first.after)
    });
    let transition = if every_hypothesis_safe {
        unique.copied().cloned()
    } else {
        None
    };
    let decision = if transition.is_some() {
        Decision::Applied
    } else {
        Decision::Refused
    };
    let final_state = transition
        .as_ref()
        .map_or_else(|| authorities.phenotype.clone(), |plan| plan.after.clone());
    let rollback = transition.as_ref().map(|_| Transition {
        before_digest: digest(&final_state),
        after: authorities.phenotype.clone(),
    });
    let refusal_reason = (decision == Decision::Refused).then(|| {
        if safe_transitions.len() == hypotheses.len() {
            "surviving hypotheses do not identify one common safe transition".into()
        } else {
            "at least one surviving hypothesis has no certified safe transition".into()
        }
    });
    let baselines = build_baselines(
        &authorities,
        scenario.expected_decision,
        &mut checker_session,
    )?;
    let false_refusal =
        decision == Decision::Refused && scenario.expected_decision == ExpectedDecision::Apply;
    let unsafe_approval =
        decision == Decision::Applied && scenario.expected_decision == ExpectedDecision::Refuse;
    let hypothesis_count = hypotheses.len();

    Ok(Certificate {
        certificate_version: "telosieve.certificate/v1".into(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        authority_digests: authorities.digests,
        hypotheses,
        decision,
        refusal_reason,
        transition,
        rollback,
        final_state,
        baselines,
        metrics: Metrics {
            hypothesis_count,
            unsafe_approvals: usize::from(unsafe_approval),
            false_refusals: usize::from(false_refusal),
        },
    })
}

fn build_baselines(
    authorities: &VerifiedAuthorities,
    expected: ExpectedDecision,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<Vec<BaselineRecord>, RunError> {
    let conventional_transition = authorities.phenotype.transition_to(&authorities.goal);
    let conventional_checker =
        check_all_viability_in_process(authorities, &conventional_transition);
    let signed_history_transition = authorities
        .phenotype
        .consensus()
        .map(|values| authorities.phenotype.transition_to(values));
    let signed_history_checker = signed_history_transition
        .as_ref()
        .map(|plan| check_all_viability(authorities, plan, checker_session))
        .transpose()?;
    let invariant_decision = if conventional_checker.safe {
        Decision::Applied
    } else {
        Decision::Refused
    };
    let baselines = vec![
        BaselineRecord {
            name: "conventional-reconciler/v0".into(),
            decision: Decision::Applied,
            unsafe_approval: expected == ExpectedDecision::Refuse,
            transition: Some(conventional_transition.clone()),
            checker: Some(conventional_checker.clone()),
        },
        BaselineRecord {
            name: "signed-history-rollback/v0".into(),
            decision: if signed_history_checker
                .as_ref()
                .is_some_and(|verdict| verdict.safe)
            {
                Decision::Applied
            } else {
                Decision::Refused
            },
            unsafe_approval: expected == ExpectedDecision::Refuse
                && signed_history_checker
                    .as_ref()
                    .is_some_and(|verdict| verdict.safe),
            transition: signed_history_transition,
            checker: signed_history_checker,
        },
        BaselineRecord {
            name: "invariant-gated-reconciler/v0".into(),
            decision: invariant_decision.clone(),
            unsafe_approval: expected == ExpectedDecision::Refuse
                && invariant_decision == Decision::Applied,
            transition: (invariant_decision == Decision::Applied)
                .then_some(conventional_transition),
            checker: Some(conventional_checker),
        },
    ];
    Ok(baselines)
}

fn validate_declaration(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
) -> Result<(), RunError> {
    let declaration = &scenario.fault_declaration;
    let target_count = declaration
        .suspectable
        .iter()
        .map(|kind| {
            if *kind == AuthorityKind::Viability {
                authorities.viability.len()
            } else {
                1
            }
        })
        .sum();
    if declaration.maximum_faults > target_count {
        return Err(RunError::FaultDeclaration(
            "maximum_faults exceeds the number of suspectable authorities".into(),
        ));
    }
    let required = bounded_hypothesis_count(
        target_count,
        declaration.maximum_faults,
        declaration.maximum_hypotheses,
    )?;
    if required > declaration.maximum_hypotheses {
        return Err(RunError::FaultDeclaration(format!(
            "{required} hypotheses exceed the configured bound of {}",
            declaration.maximum_hypotheses
        )));
    }
    Ok(())
}

fn bounded_hypothesis_count(n: usize, budget: usize, limit: usize) -> Result<usize, RunError> {
    let mut total = 1usize;
    let mut combinations = 1usize;
    for size in 1..=budget {
        combinations = combinations
            .checked_mul(n - size + 1)
            .and_then(|value| value.checked_div(size))
            .ok_or_else(|| RunError::FaultDeclaration("hypothesis count overflow".into()))?;
        total = total
            .checked_add(combinations)
            .ok_or_else(|| RunError::FaultDeclaration("hypothesis count overflow".into()))?;
        if total > limit {
            return Ok(total);
        }
    }
    Ok(total)
}

fn enumerate_hypotheses(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<Vec<HypothesisRecord>, RunError> {
    let targets: Vec<_> = scenario
        .fault_declaration
        .suspectable
        .iter()
        .flat_map(|kind| {
            if *kind == AuthorityKind::Viability {
                authorities
                    .viability
                    .iter()
                    .map(|authority| FaultTarget::ViabilityIssuer(authority.issuer.clone()))
                    .collect()
            } else {
                vec![FaultTarget::Authority(*kind)]
            }
        })
        .collect();
    let mut fault_sets = Vec::new();
    for size in 0..=scenario.fault_declaration.maximum_faults {
        combinations(&targets, size, 0, &mut Vec::new(), &mut fault_sets);
    }
    fault_sets
        .iter()
        .map(|suspected| evaluate_hypothesis(authorities, suspected, checker_session))
        .collect()
}

fn combinations(
    targets: &[FaultTarget],
    remaining: usize,
    start: usize,
    current: &mut Vec<FaultTarget>,
    output: &mut Vec<BTreeSet<FaultTarget>>,
) {
    if remaining == 0 {
        output.push(current.iter().cloned().collect());
        return;
    }
    for index in start..=targets.len() - remaining {
        current.push(targets[index].clone());
        combinations(targets, remaining - 1, index + 1, current, output);
        current.pop();
    }
}

fn evaluate_hypothesis(
    authorities: &VerifiedAuthorities,
    suspected: &BTreeSet<FaultTarget>,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<HypothesisRecord, RunError> {
    let suspects = |kind| suspected.contains(&FaultTarget::Authority(kind));
    let desired = if suspects(AuthorityKind::Goal) && suspects(AuthorityKind::Phenotype) {
        None
    } else if suspects(AuthorityKind::Goal) {
        authorities.phenotype.consensus().cloned()
    } else {
        Some(authorities.goal.clone())
    };
    let proposed_transition = desired.map(|values| authorities.phenotype.transition_to(&values));
    let checker = proposed_transition
        .as_ref()
        .map(|transition| -> Result<_, RunError> {
            let excluded: BTreeSet<_> = suspected
                .iter()
                .filter_map(|target| match target {
                    FaultTarget::ViabilityIssuer(issuer) => Some(issuer.as_str()),
                    FaultTarget::Authority(_) => None,
                })
                .collect();
            check_surviving_viability(authorities, transition, &excluded, checker_session)
        })
        .transpose()?;
    let suspected_kinds: Vec<_> = suspected
        .iter()
        .map(|target| match target {
            FaultTarget::Authority(kind) => *kind,
            FaultTarget::ViabilityIssuer(_) => AuthorityKind::Viability,
        })
        .collect();
    let suspected_issuers: Vec<_> = suspected
        .iter()
        .filter_map(|target| match target {
            FaultTarget::ViabilityIssuer(issuer) => Some(issuer.clone()),
            FaultTarget::Authority(_) => None,
        })
        .collect();
    Ok(HypothesisRecord {
        excluded: suspected_kinds.clone(),
        suspected: suspected_kinds,
        excluded_issuers: suspected_issuers.clone(),
        suspected_issuers,
        proposed_transition,
        checker,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FaultTarget {
    Authority(AuthorityKind),
    ViabilityIssuer(String),
}

fn check_all_viability(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<crate::checker::CheckerVerdict, RunError> {
    check_surviving_viability(authorities, transition, &BTreeSet::new(), checker_session)
}

fn check_all_viability_in_process(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
) -> crate::checker::CheckerVerdict {
    let mut reasons = Vec::new();
    for authority in &authorities.viability {
        let verdict = checker::check(&authorities.phenotype, transition, &authority.rules);
        reasons.extend(
            verdict
                .reasons
                .into_iter()
                .map(|reason| format!("{}: {reason}", authority.issuer)),
        );
    }
    crate::checker::CheckerVerdict {
        implementation: "telosieve-multi-principal-reference-checker/v1".into(),
        safe: reasons.is_empty(),
        reasons,
    }
}

fn check_surviving_viability(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
    excluded: &BTreeSet<&str>,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<crate::checker::CheckerVerdict, RunError> {
    let surviving: Vec<_> = authorities
        .viability
        .iter()
        .filter(|authority| !excluded.contains(authority.issuer.as_str()))
        .collect();
    if surviving.is_empty() {
        return Ok(crate::checker::CheckerVerdict {
            implementation: "telosieve-multi-principal-checker/v1".into(),
            safe: false,
            reasons: vec!["no independent viability rules survive".into()],
        });
    }
    let mut reasons = Vec::new();
    for authority in surviving {
        let verdict =
            checker_session.check(&authorities.phenotype, transition, &authority.rules)?;
        reasons.extend(
            verdict
                .reasons
                .into_iter()
                .map(|reason| format!("{}: {reason}", authority.issuer)),
        );
    }
    Ok(crate::checker::CheckerVerdict {
        implementation: "telosieve-multi-principal-checker/v1".into(),
        safe: reasons.is_empty(),
        reasons,
    })
}
