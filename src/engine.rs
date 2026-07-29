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
    #[error("durable history anchor failed: {0}")]
    Anchor(#[from] crate::anchor_store::AnchorError),
    #[error("transactional local actuator failed: {0}")]
    Actuator(#[from] crate::actuator_store::ActuatorError),
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
    persist_evidence(&certificate, certificate_path, ledger_path)?;
    Ok(certificate)
}

/// Runs a scenario through the durable-anchor and public file boundaries.
///
/// # Errors
///
/// Returns [`RunError`] for input, protocol, durable-anchor, checker, or output
/// failures.
pub fn run_scenario_file_anchored(
    path: &Path,
    certificate_path: &Path,
    ledger_path: &Path,
    anchor_path: &Path,
) -> Result<Certificate, RunError> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(path)?)?;
    let certificate = run_scenario_anchored(&scenario, anchor_path)?;
    persist_evidence(&certificate, certificate_path, ledger_path)?;
    Ok(certificate)
}

/// Explicitly initializes the durable anchor from a verified scenario.
///
/// # Errors
///
/// Returns [`RunError`] when the scenario is invalid, the store already exists,
/// or persistence fails.
pub fn initialize_anchor_file(scenario_path: &Path, anchor_path: &Path) -> Result<(), RunError> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(scenario_path)?)?;
    verify(&scenario)?;
    crate::anchor_store::AnchorStore::new(anchor_path)
        .initialize(&scenario.phenotype_history_anchor)?;
    Ok(())
}

/// Explicitly initializes the transactional local actuator from a verified
/// scenario.
///
/// # Errors
///
/// Returns [`RunError`] when verification, initialization, or persistence
/// fails.
pub fn initialize_actuator_file(
    scenario_path: &Path,
    actuator_path: &Path,
) -> Result<(), RunError> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(scenario_path)?)?;
    let authorities = verify(&scenario)?;
    crate::actuator_store::LocalActuatorStore::new(actuator_path)
        .initialize(&authorities.phenotype, &scenario.phenotype_history_anchor)?;
    Ok(())
}

/// Evaluates and transactionally applies one scenario to the local reference
/// actuator.
///
/// # Errors
///
/// Returns [`RunError`] on verification, checking, stale service state, replay,
/// contention, or persistence failure.
pub fn run_scenario_actuated(
    scenario: &Scenario,
    actuator_path: &Path,
) -> Result<Certificate, RunError> {
    let authorities = verify(scenario)?;
    let observed = authorities.phenotype.clone();
    let fault_targets = fault_targets(scenario, &authorities)?;
    validate_declaration(scenario, fault_targets.len())?;
    let mut certificate = evaluate_preflighted_scenario(scenario, authorities, &fault_targets)?;
    let consumed_identifier = (certificate.decision == Decision::Applied)
        .then_some(certificate.deletion_authorization_id.as_deref())
        .flatten();
    let actuation = crate::actuator_store::LocalActuatorStore::new(actuator_path)
        .compare_and_apply(
            &observed,
            &scenario.phenotype_history_anchor,
            certificate.transition.as_ref(),
            consumed_identifier,
        )?;
    certificate.certificate_version = "telosieve.certificate/v8".into();
    certificate.actuation = Some(actuation);
    Ok(certificate)
}

/// Runs the transactional local actuator through the public file boundary and
/// persists its evidence.
///
/// # Errors
///
/// Returns [`RunError`] on input, evaluation, actuation, or evidence failures.
pub fn run_scenario_file_actuated(
    scenario_path: &Path,
    certificate_path: &Path,
    ledger_path: &Path,
    actuator_path: &Path,
) -> Result<Certificate, RunError> {
    let scenario: Scenario = serde_json::from_slice(&fs::read(scenario_path)?)?;
    let certificate = run_scenario_actuated(&scenario, actuator_path)?;
    persist_evidence(&certificate, certificate_path, ledger_path)?;
    Ok(certificate)
}

/// Reads the current state from the transactional local actuator.
///
/// # Errors
///
/// Returns [`RunError`] when the store is missing, corrupt, oversized, or
/// incompatible.
pub fn read_actuator_state_file(
    actuator_path: &Path,
) -> Result<crate::model::ServiceState, RunError> {
    Ok(crate::actuator_store::LocalActuatorStore::new(actuator_path).current_service_state()?)
}

/// Reads the current state and durable last-actuation receipt from the local
/// actuator.
///
/// # Errors
///
/// Returns [`RunError`] when the store is missing, corrupt, oversized, or
/// incompatible.
pub fn read_actuator_snapshot_file(
    actuator_path: &Path,
) -> Result<crate::actuator_store::ActuatorSnapshot, RunError> {
    Ok(crate::actuator_store::LocalActuatorStore::new(actuator_path).current_snapshot()?)
}

fn persist_evidence(
    certificate: &Certificate,
    certificate_path: &Path,
    ledger_path: &Path,
) -> Result<(), RunError> {
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
    Ok(())
}

/// Evaluates one deterministic, bounded research scenario.
///
/// # Errors
///
/// Returns [`RunError`] when the fault declaration exceeds its configured bound or
/// when any authority fails verification.
pub fn run_scenario(scenario: &Scenario) -> Result<Certificate, RunError> {
    let authorities = verify(scenario)?;
    run_verified_scenario(scenario, authorities)
}

/// Evaluates a scenario after monotonically checking its durable history anchor.
///
/// # Errors
///
/// Returns [`RunError`] when authority verification, durable anchor comparison,
/// bounded evaluation, or independent checking fails.
pub fn run_scenario_anchored(
    scenario: &Scenario,
    anchor_path: &Path,
) -> Result<Certificate, RunError> {
    let authorities = verify(scenario)?;
    let fault_targets = fault_targets(scenario, &authorities)?;
    validate_declaration(scenario, fault_targets.len())?;
    let certificate = evaluate_preflighted_scenario(scenario, authorities, &fault_targets)?;
    let consumed_identifier = (certificate.decision == Decision::Applied)
        .then_some(certificate.deletion_authorization_id.as_deref())
        .flatten();
    crate::anchor_store::AnchorStore::new(anchor_path)
        .compare_advance_and_consume(&scenario.phenotype_history_anchor, consumed_identifier)?;
    Ok(certificate)
}

fn run_verified_scenario(
    scenario: &Scenario,
    authorities: VerifiedAuthorities,
) -> Result<Certificate, RunError> {
    let fault_targets = fault_targets(scenario, &authorities)?;
    validate_declaration(scenario, fault_targets.len())?;
    evaluate_preflighted_scenario(scenario, authorities, &fault_targets)
}

fn evaluate_preflighted_scenario(
    scenario: &Scenario,
    authorities: VerifiedAuthorities,
    fault_targets: &[FaultTarget],
) -> Result<Certificate, RunError> {
    let mut checker_session = crate::external_checker::CheckerSession::start()?;
    let hypotheses =
        enumerate_hypotheses(scenario, &authorities, fault_targets, &mut checker_session)?;
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
        certificate_version: "telosieve.certificate/v7".into(),
        scenario_id: scenario.scenario_id.clone(),
        seed: scenario.seed,
        authority_digests: authorities.digests,
        deletion_authorization_id: authorities.deletion_authorization_id,
        actuation: None,
        phenotype_history_anchor: scenario.phenotype_history_anchor.clone(),
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
        .phenotype_history
        .last()
        .and_then(|state| state.consensus())
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
            name: "signed-history-replay/v1".into(),
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

fn validate_declaration(scenario: &Scenario, target_count: usize) -> Result<(), RunError> {
    let declaration = &scenario.fault_declaration;
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

#[allow(clippy::too_many_lines)]
fn fault_targets(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
) -> Result<Vec<FaultTarget>, RunError> {
    let declaration = &scenario.fault_declaration;
    let goal_issuers: BTreeSet<_> = authorities
        .goal_issuers
        .iter()
        .map(String::as_str)
        .collect();
    let viability_issuers: BTreeSet<_> = authorities
        .viability
        .iter()
        .map(|authority| authority.issuer.as_str())
        .collect();
    let deletion_issuers: BTreeSet<_> = authorities
        .deletion_issuers
        .iter()
        .map(String::as_str)
        .collect();
    if declaration.suspectable.contains(&AuthorityKind::Goal) {
        for issuer in &goal_issuers {
            if declaration
                .goal_fault_domains
                .get(*issuer)
                .is_none_or(String::is_empty)
            {
                return Err(RunError::FaultDeclaration(format!(
                    "goal issuer {issuer} has no non-empty fault domain"
                )));
            }
        }
        if declaration
            .goal_fault_domains
            .keys()
            .any(|issuer| !goal_issuers.contains(issuer.as_str()))
        {
            return Err(RunError::FaultDeclaration(
                "fault-domain mapping contains an unknown goal issuer".into(),
            ));
        }
    } else if !declaration.goal_fault_domains.is_empty() {
        return Err(RunError::FaultDeclaration(
            "goal fault domains require goal to be suspectable".into(),
        ));
    }
    if authorities.deletion.is_some() != declaration.suspectable.contains(&AuthorityKind::Deletion)
    {
        return Err(RunError::FaultDeclaration(
            "deletion evidence and deletion suspectability must be configured together".into(),
        ));
    }
    if declaration.suspectable.contains(&AuthorityKind::Deletion) {
        for issuer in &deletion_issuers {
            if declaration
                .deletion_fault_domains
                .get(*issuer)
                .is_none_or(String::is_empty)
            {
                return Err(RunError::FaultDeclaration(format!(
                    "deletion issuer {issuer} has no non-empty fault domain"
                )));
            }
        }
        if declaration
            .deletion_fault_domains
            .keys()
            .any(|issuer| !deletion_issuers.contains(issuer.as_str()))
        {
            return Err(RunError::FaultDeclaration(
                "fault-domain mapping contains an unknown deletion issuer".into(),
            ));
        }
        let other_domains: BTreeSet<_> = declaration
            .goal_fault_domains
            .values()
            .chain(declaration.viability_fault_domains.values())
            .collect();
        if declaration
            .deletion_fault_domains
            .values()
            .any(|domain| other_domains.contains(domain))
        {
            return Err(RunError::FaultDeclaration(
                "deletion fault domains must be distinct from goal and viability domains".into(),
            ));
        }
    } else if !declaration.deletion_fault_domains.is_empty() {
        return Err(RunError::FaultDeclaration(
            "deletion fault domains require deletion to be suspectable".into(),
        ));
    }
    if declaration.suspectable.contains(&AuthorityKind::Viability) {
        for issuer in &viability_issuers {
            if declaration
                .viability_fault_domains
                .get(*issuer)
                .is_none_or(String::is_empty)
            {
                return Err(RunError::FaultDeclaration(format!(
                    "viability issuer {issuer} has no non-empty fault domain"
                )));
            }
        }
        if declaration
            .viability_fault_domains
            .keys()
            .any(|issuer| !viability_issuers.contains(issuer.as_str()))
        {
            return Err(RunError::FaultDeclaration(
                "fault-domain mapping contains an unknown viability issuer".into(),
            ));
        }
    } else if !declaration.viability_fault_domains.is_empty() {
        return Err(RunError::FaultDeclaration(
            "viability fault domains require viability to be suspectable".into(),
        ));
    }
    let mut targets = Vec::new();
    for kind in &declaration.suspectable {
        match kind {
            AuthorityKind::Goal => targets.extend(
                declaration
                    .goal_fault_domains
                    .values()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(FaultTarget::GoalDomain),
            ),
            AuthorityKind::Viability => targets.extend(
                declaration
                    .viability_fault_domains
                    .values()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(FaultTarget::ViabilityDomain),
            ),
            AuthorityKind::Phenotype => {
                targets.push(FaultTarget::Authority(AuthorityKind::Phenotype));
            }
            AuthorityKind::Deletion => targets.extend(
                declaration
                    .deletion_fault_domains
                    .values()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .map(FaultTarget::DeletionDomain),
            ),
        }
    }
    Ok(targets)
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
    targets: &[FaultTarget],
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<Vec<HypothesisRecord>, RunError> {
    let mut fault_sets = Vec::new();
    for size in 0..=scenario.fault_declaration.maximum_faults {
        combinations(targets, size, 0, &mut Vec::new(), &mut fault_sets);
    }
    fault_sets
        .iter()
        .map(|suspected| evaluate_hypothesis(scenario, authorities, suspected, checker_session))
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

#[allow(clippy::too_many_lines)]
fn evaluate_hypothesis(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
    suspected: &BTreeSet<FaultTarget>,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<HypothesisRecord, RunError> {
    let excluded_goal_issuers: BTreeSet<_> = suspected
        .iter()
        .flat_map(|target| match target {
            FaultTarget::GoalDomain(domain) => scenario
                .fault_declaration
                .goal_fault_domains
                .iter()
                .filter_map(|(issuer, candidate)| (candidate == domain).then_some(issuer.as_str()))
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    let desired = authorities
        .goal_issuers
        .iter()
        .any(|issuer| !excluded_goal_issuers.contains(issuer.as_str()))
        .then(|| authorities.goal.clone());
    let proposed_transition = desired.map(|values| authorities.phenotype.transition_to(&values));
    let excluded_deletion_issuers: BTreeSet<_> = suspected
        .iter()
        .flat_map(|target| match target {
            FaultTarget::DeletionDomain(domain) => scenario
                .fault_declaration
                .deletion_fault_domains
                .iter()
                .filter_map(|(issuer, candidate)| (candidate == domain).then_some(issuer.as_str()))
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    let authorized_deletions = authorities
        .deletion
        .as_ref()
        .map_or_else(BTreeSet::new, |auth| {
            if authorities
                .deletion_issuers
                .iter()
                .any(|issuer| !excluded_deletion_issuers.contains(issuer.as_str()))
            {
                auth.keys.clone()
            } else {
                BTreeSet::new()
            }
        });
    let checker = proposed_transition
        .as_ref()
        .map(|transition| -> Result<_, RunError> {
            let excluded: BTreeSet<_> = suspected
                .iter()
                .flat_map(|target| match target {
                    FaultTarget::ViabilityDomain(domain) => scenario
                        .fault_declaration
                        .viability_fault_domains
                        .iter()
                        .filter_map(|(issuer, candidate)| {
                            (candidate == domain).then_some(issuer.as_str())
                        })
                        .collect(),
                    FaultTarget::GoalDomain(_)
                    | FaultTarget::DeletionDomain(_)
                    | FaultTarget::Authority(_) => Vec::new(),
                })
                .collect();
            check_surviving_viability(
                authorities,
                transition,
                &excluded,
                &authorized_deletions,
                checker_session,
            )
        })
        .transpose()?;
    let suspected_kinds: Vec<_> = suspected
        .iter()
        .map(|target| match target {
            FaultTarget::Authority(kind) => *kind,
            FaultTarget::GoalDomain(_) => AuthorityKind::Goal,
            FaultTarget::ViabilityDomain(_) => AuthorityKind::Viability,
            FaultTarget::DeletionDomain(_) => AuthorityKind::Deletion,
        })
        .collect();
    let suspected_fault_domains: Vec<_> = suspected
        .iter()
        .filter_map(|target| match target {
            FaultTarget::GoalDomain(domain)
            | FaultTarget::ViabilityDomain(domain)
            | FaultTarget::DeletionDomain(domain) => Some(domain.clone()),
            FaultTarget::Authority(_) => None,
        })
        .collect();
    let suspected_issuers: Vec<_> = suspected
        .iter()
        .flat_map(|target| {
            let (domains, selected) = match target {
                FaultTarget::GoalDomain(domain) => {
                    (&scenario.fault_declaration.goal_fault_domains, domain)
                }
                FaultTarget::ViabilityDomain(domain) => {
                    (&scenario.fault_declaration.viability_fault_domains, domain)
                }
                FaultTarget::DeletionDomain(domain) => {
                    (&scenario.fault_declaration.deletion_fault_domains, domain)
                }
                FaultTarget::Authority(_) => return Vec::new(),
            };
            domains
                .iter()
                .filter_map(|(issuer, domain)| (domain == selected).then_some(issuer.clone()))
                .collect()
        })
        .collect();
    Ok(HypothesisRecord {
        excluded: suspected_kinds.clone(),
        suspected: suspected_kinds,
        excluded_issuers: suspected_issuers.clone(),
        suspected_issuers,
        excluded_fault_domains: suspected_fault_domains.clone(),
        suspected_fault_domains,
        authorized_deletions: authorized_deletions.into_iter().collect(),
        proposed_transition,
        checker,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FaultTarget {
    Authority(AuthorityKind),
    GoalDomain(String),
    ViabilityDomain(String),
    DeletionDomain(String),
}

fn check_all_viability(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<crate::checker::CheckerVerdict, RunError> {
    check_surviving_viability(
        authorities,
        transition,
        &BTreeSet::new(),
        &BTreeSet::new(),
        checker_session,
    )
}

fn check_all_viability_in_process(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
) -> crate::checker::CheckerVerdict {
    let mut reasons = Vec::new();
    for authority in &authorities.viability {
        let verdict = checker::check(
            &authorities.phenotype,
            transition,
            &authority.rules,
            &BTreeSet::new(),
        );
        reasons.extend(
            verdict
                .reasons
                .into_iter()
                .map(|reason| format!("{}: {reason}", authority.issuer)),
        );
    }
    crate::checker::CheckerVerdict {
        implementation: "telosieve-multi-principal-reference-checker/v2".into(),
        safe: reasons.is_empty(),
        reasons,
    }
}

fn check_surviving_viability(
    authorities: &VerifiedAuthorities,
    transition: &Transition,
    excluded: &BTreeSet<&str>,
    authorized_deletions: &BTreeSet<String>,
    checker_session: &mut crate::external_checker::CheckerSession,
) -> Result<crate::checker::CheckerVerdict, RunError> {
    let surviving: Vec<_> = authorities
        .viability
        .iter()
        .filter(|authority| !excluded.contains(authority.issuer.as_str()))
        .collect();
    if surviving.is_empty() {
        return Ok(crate::checker::CheckerVerdict {
            implementation: "telosieve-multi-principal-checker/v2".into(),
            safe: false,
            reasons: vec!["no independent viability rules survive".into()],
        });
    }
    let mut reasons = Vec::new();
    for authority in surviving {
        let verdict = checker_session.check(
            &authorities.phenotype,
            transition,
            &authority.rules,
            authorized_deletions,
        )?;
        reasons.extend(
            verdict
                .reasons
                .into_iter()
                .map(|reason| format!("{}: {reason}", authority.issuer)),
        );
    }
    Ok(crate::checker::CheckerVerdict {
        implementation: "telosieve-multi-principal-checker/v2".into(),
        safe: reasons.is_empty(),
        reasons,
    })
}
