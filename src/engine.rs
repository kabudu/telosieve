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
    validate_declaration(scenario)?;
    let authorities = verify(scenario)?;
    let hypotheses = enumerate_hypotheses(scenario, &authorities);
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
    let baseline_transition = authorities.phenotype.transition_to(&authorities.goal);
    let baseline_checker = checker::check(
        &authorities.phenotype,
        &baseline_transition,
        &authorities.viability,
    );
    let baseline = BaselineRecord {
        name: "conventional-reconciler/v0".into(),
        unsafe_approval: !baseline_checker.safe,
        transition: baseline_transition,
        checker: baseline_checker,
    };
    let false_refusal =
        decision == Decision::Refused && scenario.expected_decision == ExpectedDecision::Apply;
    let hypothesis_count = hypotheses.len();

    Ok(Certificate {
        certificate_version: "telosieve.certificate/v0".into(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        authority_digests: authorities.digests,
        hypotheses,
        decision,
        refusal_reason,
        transition,
        rollback,
        final_state,
        baseline,
        metrics: Metrics {
            hypothesis_count,
            unsafe_approvals: 0,
            false_refusals: usize::from(false_refusal),
        },
    })
}

fn validate_declaration(scenario: &Scenario) -> Result<(), RunError> {
    let declaration = &scenario.fault_declaration;
    if declaration.maximum_faults > declaration.suspectable.len() {
        return Err(RunError::FaultDeclaration(
            "maximum_faults exceeds the number of suspectable authorities".into(),
        ));
    }
    let required = bounded_hypothesis_count(
        declaration.suspectable.len(),
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
) -> Vec<HypothesisRecord> {
    let kinds: Vec<_> = scenario
        .fault_declaration
        .suspectable
        .iter()
        .copied()
        .collect();
    let mut fault_sets = Vec::new();
    for size in 0..=scenario.fault_declaration.maximum_faults {
        combinations(&kinds, size, 0, &mut Vec::new(), &mut fault_sets);
    }
    fault_sets
        .into_iter()
        .map(|suspected| evaluate_hypothesis(authorities, suspected))
        .collect()
}

fn combinations(
    kinds: &[AuthorityKind],
    remaining: usize,
    start: usize,
    current: &mut Vec<AuthorityKind>,
    output: &mut Vec<BTreeSet<AuthorityKind>>,
) {
    if remaining == 0 {
        output.push(current.iter().copied().collect());
        return;
    }
    for index in start..=kinds.len() - remaining {
        current.push(kinds[index]);
        combinations(kinds, remaining - 1, index + 1, current, output);
        current.pop();
    }
}

fn evaluate_hypothesis(
    authorities: &VerifiedAuthorities,
    suspected: BTreeSet<AuthorityKind>,
) -> HypothesisRecord {
    let desired = if suspected.contains(&AuthorityKind::Goal)
        && suspected.contains(&AuthorityKind::Phenotype)
    {
        None
    } else if suspected.contains(&AuthorityKind::Goal) {
        authorities.phenotype.consensus().cloned()
    } else {
        Some(authorities.goal.clone())
    };
    let proposed_transition = desired.map(|values| authorities.phenotype.transition_to(&values));
    let checker = proposed_transition.as_ref().map(|transition| {
        if suspected.contains(&AuthorityKind::Viability) {
            crate::checker::CheckerVerdict {
                implementation: "telosieve-independent-checker/v0".into(),
                safe: false,
                reasons: vec![
                    "viability authority is suspected; no independent rules remain".into(),
                ],
            }
        } else {
            checker::check(&authorities.phenotype, transition, &authorities.viability)
        }
    });
    let suspected: Vec<_> = suspected.into_iter().collect();
    HypothesisRecord {
        excluded: suspected.clone(),
        suspected,
        proposed_transition,
        checker,
    }
}
