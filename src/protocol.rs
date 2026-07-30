use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{ServiceState, Values, digest};

pub const SCHEMA_VERSION: &str = "telosieve.authority/v0";
pub const KEY_LIFECYCLE_SCHEMA_VERSION: &str = "telosieve.key-lifecycle/v1";
pub const MAX_TRUSTED_TIME_WINDOW_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    Goal,
    Phenotype,
    Viability,
    Deletion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub kind: AuthorityKind,
    pub subject: String,
    pub schema_version: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer: String,
    pub sequence: u64,
    pub content_digest: String,
    pub parent_digests: Vec<String>,
    pub content: Value,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    kind: AuthorityKind,
    subject: &'a str,
    schema_version: &'a str,
    issued_at: u64,
    expires_at: u64,
    issuer: &'a str,
    sequence: u64,
    content_digest: &'a str,
    parent_digests: &'a [String],
    content: &'a Value,
}

impl Envelope {
    fn signed_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&UnsignedEnvelope {
            kind: self.kind,
            subject: &self.subject,
            schema_version: &self.schema_version,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            issuer: &self.issuer,
            sequence: self.sequence,
            content_digest: &self.content_digest,
            parent_digests: &self.parent_digests,
            content: &self.content,
        })
        .expect("typed envelope serialization cannot fail")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViabilityRules {
    pub replica_count: usize,
    pub require_consensus: bool,
    pub required_keys: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionAuthorization {
    pub keys: BTreeSet<String>,
    pub goal_digest: String,
    pub phenotype_tip_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultDeclaration {
    pub maximum_faults: usize,
    pub suspectable: BTreeSet<AuthorityKind>,
    #[serde(default)]
    pub goal_fault_domains: BTreeMap<String, String>,
    #[serde(default)]
    pub viability_fault_domains: BTreeMap<String, String>,
    #[serde(default)]
    pub deletion_fault_domains: BTreeMap<String, String>,
    pub maximum_hypotheses: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryAnchor {
    pub issuer: String,
    pub sequence: u64,
    pub tip_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLifecycleAnchor {
    pub sequence: u64,
    pub tip_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTimeWindow {
    pub not_before: u64,
    pub not_after: u64,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyLifecycleAction {
    Activate { public_key: String, expires_at: u64 },
    Revoke { public_key_digest: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLifecycleStatement {
    pub schema_version: String,
    pub subject: String,
    pub issuer: String,
    pub authority_kind: AuthorityKind,
    pub sequence: u64,
    pub effective_at: u64,
    pub parent_digest: Option<String>,
    pub action: KeyLifecycleAction,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedKeyLifecycleStatement<'a> {
    schema_version: &'a str,
    subject: &'a str,
    issuer: &'a str,
    authority_kind: AuthorityKind,
    sequence: u64,
    effective_at: u64,
    parent_digest: &'a Option<String>,
    action: &'a KeyLifecycleAction,
}

impl KeyLifecycleStatement {
    fn signed_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&UnsignedKeyLifecycleStatement {
            schema_version: &self.schema_version,
            subject: &self.subject,
            issuer: &self.issuer,
            authority_kind: self.authority_kind,
            sequence: self.sequence,
            effective_at: self.effective_at,
            parent_digest: &self.parent_digest,
            action: &self.action,
        })
        .expect("typed key lifecycle serialization cannot fail")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDecision {
    Apply,
    Refuse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub scenario_id: String,
    pub seed: u64,
    pub evaluation_time: u64,
    pub subject: String,
    pub expected_decision: ExpectedDecision,
    pub public_keys: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_lifecycle_roots: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_lifecycle: Vec<KeyLifecycleStatement>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_lifecycle_anchors: BTreeMap<String, KeyLifecycleAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_time: Option<TrustedTimeWindow>,
    pub fault_declaration: FaultDeclaration,
    pub phenotype_history_anchor: HistoryAnchor,
    #[serde(default)]
    pub phenotype_history: Vec<Envelope>,
    pub authorities: Vec<Envelope>,
}

#[derive(Clone, Debug)]
pub struct VerifiedAuthorities {
    pub digests: BTreeMap<String, String>,
    pub goal: Values,
    pub goal_issuers: BTreeSet<String>,
    pub deletion: Option<DeletionAuthorization>,
    pub deletion_authorization_id: Option<String>,
    pub deletion_issuers: BTreeSet<String>,
    pub phenotype: ServiceState,
    pub phenotype_history: Vec<ServiceState>,
    pub viability: Vec<VerifiedViability>,
}

#[derive(Clone, Debug)]
pub struct VerifiedViability {
    pub issuer: String,
    pub rules: ViabilityRules,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("authority set must contain exactly one {0:?} envelope")]
    Cardinality(AuthorityKind),
    #[error("invalid {field} for {kind:?}: {reason}")]
    Invalid {
        kind: AuthorityKind,
        field: &'static str,
        reason: String,
    },
    #[error("invalid key lifecycle: {0}")]
    KeyLifecycle(String),
}

/// Authenticates, freshness-checks, and decodes the scenario authority set.
///
/// # Errors
///
/// Returns [`ProtocolError`] when an authority is missing, duplicated, stale,
/// malformed, digest-mismatched, or has an invalid signature.
#[allow(clippy::too_many_lines)]
pub fn verify(scenario: &Scenario) -> Result<VerifiedAuthorities, ProtocolError> {
    if scenario.phenotype_history.len() > 64 {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Phenotype,
            field: "phenotype_history",
            reason: "history exceeds the 64-record bound".into(),
        });
    }
    let key_lifecycle = verify_key_lifecycle(scenario)?;
    for envelope in &scenario.authorities {
        validate_envelope(scenario, envelope, true, &key_lifecycle)?;
    }
    for envelope in &scenario.phenotype_history {
        validate_envelope(scenario, envelope, false, &key_lifecycle)?;
    }
    let mut by_kind = BTreeMap::new();
    let mut goal_envelopes = Vec::new();
    let mut viability_envelopes = Vec::new();
    let mut deletion_envelopes = Vec::new();
    for envelope in &scenario.authorities {
        if matches!(
            envelope.kind,
            AuthorityKind::Goal | AuthorityKind::Viability | AuthorityKind::Deletion
        ) {
            let envelopes = match envelope.kind {
                AuthorityKind::Goal => &mut goal_envelopes,
                AuthorityKind::Viability => &mut viability_envelopes,
                AuthorityKind::Deletion => &mut deletion_envelopes,
                AuthorityKind::Phenotype => unreachable!(),
            };
            if envelopes
                .iter()
                .any(|existing: &&Envelope| existing.issuer == envelope.issuer)
            {
                return Err(ProtocolError::Invalid {
                    kind: envelope.kind,
                    field: "issuer",
                    reason: "duplicate authority issuer".into(),
                });
            }
            envelopes.push(envelope);
            continue;
        }
        if let Some(previous) = by_kind.insert(envelope.kind, envelope) {
            if previous.issuer == envelope.issuer
                && previous.sequence == envelope.sequence
                && previous.content_digest != envelope.content_digest
            {
                return Err(ProtocolError::Invalid {
                    kind: envelope.kind,
                    field: "sequence",
                    reason: "authenticated issuer equivocation".into(),
                });
            }
            return Err(ProtocolError::Cardinality(envelope.kind));
        }
    }

    let (goal, goal_issuers) = verify_goals(&goal_envelopes)?;
    let phenotype = parse_content::<ServiceState>(&by_kind, AuthorityKind::Phenotype)?;
    let current_phenotype = by_kind
        .get(&AuthorityKind::Phenotype)
        .ok_or(ProtocolError::Cardinality(AuthorityKind::Phenotype))?;
    if scenario.phenotype_history_anchor.issuer != current_phenotype.issuer
        || scenario.phenotype_history_anchor.sequence != current_phenotype.sequence
        || scenario.phenotype_history_anchor.tip_digest != digest(*current_phenotype)
    {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Phenotype,
            field: "phenotype_history_anchor",
            reason: "current phenotype does not match the trusted history anchor".into(),
        });
    }
    let phenotype_history = verify_history(scenario, current_phenotype)?;
    let (deletion, deletion_issuers) = verify_deletions(
        &deletion_envelopes,
        &goal,
        &scenario.phenotype_history_anchor.tip_digest,
    )?;
    if viability_envelopes.is_empty() {
        return Err(ProtocolError::Cardinality(AuthorityKind::Viability));
    }
    let viability = viability_envelopes
        .iter()
        .map(|envelope| {
            serde_json::from_value(envelope.content.clone())
                .map(|rules| VerifiedViability {
                    issuer: envelope.issuer.clone(),
                    rules,
                })
                .map_err(|error| ProtocolError::Invalid {
                    kind: AuthorityKind::Viability,
                    field: "content",
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if deletion_issuers.iter().any(|issuer| {
        goal_issuers.contains(issuer)
            || viability
                .iter()
                .any(|authority| authority.issuer == *issuer)
    }) {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Deletion,
            field: "issuer",
            reason: "deletion issuers must be distinct from goal and viability issuers".into(),
        });
    }
    let digests = authority_digests(scenario);
    let deletion_authorization_id = deletion.as_ref().map(|_| {
        let envelope_digests: BTreeSet<_> = deletion_envelopes
            .iter()
            .map(|envelope| digest(*envelope))
            .collect();
        digest(&("telosieve.deletion-authorization/v1", envelope_digests))
    });

    Ok(VerifiedAuthorities {
        digests,
        goal,
        goal_issuers,
        deletion,
        deletion_authorization_id,
        deletion_issuers,
        phenotype,
        phenotype_history,
        viability,
    })
}

fn verify_deletions(
    envelopes: &[&Envelope],
    goal: &Values,
    phenotype_tip_digest: &str,
) -> Result<(Option<DeletionAuthorization>, BTreeSet<String>), ProtocolError> {
    if envelopes.is_empty() {
        return Ok((None, BTreeSet::new()));
    }
    let authorizations = envelopes
        .iter()
        .map(|envelope| {
            serde_json::from_value::<DeletionAuthorization>(envelope.content.clone()).map_err(
                |error| ProtocolError::Invalid {
                    kind: AuthorityKind::Deletion,
                    field: "content",
                    reason: error.to_string(),
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authorization = authorizations[0].clone();
    if authorization.keys.is_empty()
        || authorizations
            .iter()
            .any(|candidate| candidate != &authorization)
        || authorization.goal_digest != digest(goal)
        || authorization.phenotype_tip_digest != phenotype_tip_digest
    {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Deletion,
            field: "content",
            reason: "deletion authorization is empty, divergent, or binding-mismatched".into(),
        });
    }
    let issuers = envelopes
        .iter()
        .map(|envelope| envelope.issuer.clone())
        .collect();
    Ok((Some(authorization), issuers))
}

fn verify_goals(envelopes: &[&Envelope]) -> Result<(Values, BTreeSet<String>), ProtocolError> {
    let first = envelopes
        .first()
        .ok_or(ProtocolError::Cardinality(AuthorityKind::Goal))?;
    let goal = serde_json::from_value::<Values>(first.content.clone()).map_err(|error| {
        ProtocolError::Invalid {
            kind: AuthorityKind::Goal,
            field: "content",
            reason: error.to_string(),
        }
    })?;
    for envelope in &envelopes[1..] {
        let candidate =
            serde_json::from_value::<Values>(envelope.content.clone()).map_err(|error| {
                ProtocolError::Invalid {
                    kind: AuthorityKind::Goal,
                    field: "content",
                    reason: error.to_string(),
                }
            })?;
        if candidate != goal {
            return Err(ProtocolError::Invalid {
                kind: AuthorityKind::Goal,
                field: "content",
                reason: "authenticated goal principals disagree".into(),
            });
        }
    }
    let issuers = envelopes
        .iter()
        .map(|envelope| envelope.issuer.clone())
        .collect();
    Ok((goal, issuers))
}

fn authority_digests(scenario: &Scenario) -> BTreeMap<String, String> {
    let mut digests: BTreeMap<_, _> = scenario
        .authorities
        .iter()
        .map(|envelope| ("current", envelope))
        .chain(
            scenario
                .phenotype_history
                .iter()
                .map(|envelope| ("history", envelope)),
        )
        .map(|(scope, envelope)| {
            (
                format!(
                    "{scope}:{:?}:{}:{}",
                    envelope.kind, envelope.issuer, envelope.sequence
                )
                .to_lowercase(),
                digest(envelope),
            )
        })
        .collect();
    for statement in &scenario.key_lifecycle {
        digests.insert(
            format!("lifecycle:{}:{}", statement.issuer, statement.sequence),
            digest(statement),
        );
    }
    for (issuer, anchor) in &scenario.key_lifecycle_anchors {
        digests.insert(format!("lifecycle-anchor:{issuer}"), digest(anchor));
    }
    for (issuer, root) in &scenario.key_lifecycle_roots {
        digests.insert(format!("lifecycle-root:{issuer}"), digest(root));
    }
    if let Some(trusted_time) = &scenario.trusted_time {
        digests.insert("trusted-time".into(), digest(trusted_time));
    }
    digests
}

fn verify_history(
    scenario: &Scenario,
    current: &Envelope,
) -> Result<Vec<ServiceState>, ProtocolError> {
    if scenario.phenotype_history.is_empty() {
        if current.sequence != 1 || !current.parent_digests.is_empty() {
            return Err(ProtocolError::Invalid {
                kind: AuthorityKind::Phenotype,
                field: "parent_digests",
                reason: "current phenotype does not have a retained history chain".into(),
            });
        }
        return Ok(Vec::new());
    }
    let mut expected_parent = None;
    let mut states = Vec::with_capacity(scenario.phenotype_history.len());
    for (index, envelope) in scenario.phenotype_history.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1).expect("history bound fits u64");
        if envelope.kind != AuthorityKind::Phenotype
            || envelope.issuer != current.issuer
            || envelope.sequence != expected_sequence
            || envelope.parent_digests != expected_parent.iter().cloned().collect::<Vec<_>>()
        {
            return Err(ProtocolError::Invalid {
                kind: AuthorityKind::Phenotype,
                field: "phenotype_history",
                reason: "history kind, issuer, sequence, or parent link is invalid".into(),
            });
        }
        states.push(
            serde_json::from_value(envelope.content.clone()).map_err(|error| {
                ProtocolError::Invalid {
                    kind: AuthorityKind::Phenotype,
                    field: "content",
                    reason: error.to_string(),
                }
            })?,
        );
        expected_parent = Some(digest(envelope));
    }
    let expected_sequence =
        u64::try_from(scenario.phenotype_history.len() + 1).expect("history bound fits u64");
    if current.sequence != expected_sequence
        || current.parent_digests != expected_parent.into_iter().collect::<Vec<_>>()
    {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Phenotype,
            field: "parent_digests",
            reason: "current phenotype does not extend the retained history tip".into(),
        });
    }
    Ok(states)
}

fn parse_content<T: for<'de> Deserialize<'de>>(
    envelopes: &BTreeMap<AuthorityKind, &Envelope>,
    kind: AuthorityKind,
) -> Result<T, ProtocolError> {
    let envelope = envelopes
        .get(&kind)
        .ok_or(ProtocolError::Cardinality(kind))?;
    serde_json::from_value(envelope.content.clone()).map_err(|error| ProtocolError::Invalid {
        kind,
        field: "content",
        reason: error.to_string(),
    })
}

#[allow(clippy::too_many_lines)]
fn verify_key_lifecycle(
    scenario: &Scenario,
) -> Result<BTreeMap<String, Vec<&KeyLifecycleStatement>>, ProtocolError> {
    if scenario.key_lifecycle.len() > 64 {
        return Err(ProtocolError::KeyLifecycle(
            "statements exceed the 64-record bound".into(),
        ));
    }
    let mut by_issuer: BTreeMap<String, Vec<&KeyLifecycleStatement>> = BTreeMap::new();
    for statement in &scenario.key_lifecycle {
        by_issuer
            .entry(statement.issuer.clone())
            .or_default()
            .push(statement);
    }
    let enrolled: BTreeSet<_> = by_issuer.keys().cloned().collect();
    if !enrolled.is_empty() {
        let trusted_time = scenario.trusted_time.as_ref().ok_or_else(|| {
            ProtocolError::KeyLifecycle("enrolled lifecycle requires a trusted-time window".into())
        })?;
        if trusted_time.source.is_empty()
            || trusted_time.source.len() > 128
            || trusted_time.source.chars().any(char::is_control)
            || trusted_time.not_before > scenario.evaluation_time
            || scenario.evaluation_time > trusted_time.not_after
            || trusted_time.not_after < trusted_time.not_before
            || trusted_time.not_after - trusted_time.not_before > MAX_TRUSTED_TIME_WINDOW_SECONDS
        {
            return Err(ProtocolError::KeyLifecycle(
                "trusted time is absent, unbounded, rolled back, or advanced".into(),
            ));
        }
    }
    if scenario
        .key_lifecycle_roots
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != enrolled
        || scenario
            .key_lifecycle_anchors
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != enrolled
    {
        return Err(ProtocolError::KeyLifecycle(
            "statement, recovery-root, and anchor issuer sets must match exactly".into(),
        ));
    }
    let recovery_roots: BTreeSet<_> = scenario.key_lifecycle_roots.values().collect();
    if recovery_roots.len() != scenario.key_lifecycle_roots.len() {
        return Err(ProtocolError::KeyLifecycle(
            "recovery roots must be unique across enrolled issuers".into(),
        ));
    }
    for root in &recovery_roots {
        decode_verifying_key(root).map_err(|reason| {
            ProtocolError::KeyLifecycle(format!("invalid recovery root: {reason}"))
        })?;
        if scenario.public_keys.values().any(|key| key == *root) {
            return Err(ProtocolError::KeyLifecycle(
                "a recovery root is also configured as an operational key".into(),
            ));
        }
    }

    for (issuer, statements) in &mut by_issuer {
        let bootstrap = scenario.public_keys.get(issuer).ok_or_else(|| {
            ProtocolError::KeyLifecycle(format!("enrolled issuer {issuer} has no bootstrap key"))
        })?;
        decode_verifying_key(bootstrap).map_err(|reason| {
            ProtocolError::KeyLifecycle(format!("invalid bootstrap key for {issuer}: {reason}"))
        })?;
        statements.sort_by_key(|statement| statement.sequence);
        let encoded_root = scenario
            .key_lifecycle_roots
            .get(issuer)
            .expect("enrolled issuer sets match");
        let root = decode_verifying_key(encoded_root).map_err(|reason| {
            ProtocolError::KeyLifecycle(format!("invalid recovery root for {issuer}: {reason}"))
        })?;
        let mut previous_digest = None;
        let mut previous_effective_at = None;
        let mut authority_kind = None;
        let mut active_key = bootstrap.clone();
        let mut is_active = true;
        let mut seen_key_digests = BTreeSet::from([digest(&active_key)]);

        for (index, statement) in statements.iter().enumerate() {
            let expected_sequence = u64::try_from(index + 1).expect("lifecycle bound fits u64");
            if statement.schema_version != KEY_LIFECYCLE_SCHEMA_VERSION
                || statement.subject != scenario.subject
                || statement.issuer != *issuer
                || statement.sequence != expected_sequence
                || statement.parent_digest.as_ref() != previous_digest.as_ref()
                || statement.effective_at > scenario.evaluation_time
                || previous_effective_at.is_some_and(|time| statement.effective_at <= time)
            {
                return Err(ProtocolError::KeyLifecycle(format!(
                    "invalid schema, subject, issuer, sequence, parent, or effective time for {issuer}"
                )));
            }
            if authority_kind
                .replace(statement.authority_kind)
                .is_some_and(|kind| kind != statement.authority_kind)
            {
                return Err(ProtocolError::KeyLifecycle(format!(
                    "authority kind changed for {issuer}"
                )));
            }
            verify_signature(&root, &statement.signed_bytes(), &statement.signature).map_err(
                |reason| {
                    ProtocolError::KeyLifecycle(format!(
                        "invalid recovery-root signature for {issuer}: {reason}"
                    ))
                },
            )?;
            match &statement.action {
                KeyLifecycleAction::Activate {
                    public_key,
                    expires_at,
                } => {
                    decode_verifying_key(public_key).map_err(|reason| {
                        ProtocolError::KeyLifecycle(format!(
                            "invalid activated key for {issuer}: {reason}"
                        ))
                    })?;
                    if recovery_roots.contains(public_key) {
                        return Err(ProtocolError::KeyLifecycle(format!(
                            "recovery root cannot be activated operationally for {issuer}"
                        )));
                    }
                    if *expires_at <= statement.effective_at {
                        return Err(ProtocolError::KeyLifecycle(format!(
                            "activated key for {issuer} has an empty validity interval"
                        )));
                    }
                    if !seen_key_digests.insert(digest(public_key)) {
                        return Err(ProtocolError::KeyLifecycle(format!(
                            "key reuse or rollback detected for {issuer}"
                        )));
                    }
                    active_key.clone_from(public_key);
                    is_active = true;
                }
                KeyLifecycleAction::Revoke { public_key_digest } => {
                    if !is_active || public_key_digest != &digest(&active_key) {
                        return Err(ProtocolError::KeyLifecycle(format!(
                            "revocation does not name the active key for {issuer}"
                        )));
                    }
                    is_active = false;
                }
            }
            previous_effective_at = Some(statement.effective_at);
            previous_digest = Some(digest(*statement));
        }
        let anchor = scenario
            .key_lifecycle_anchors
            .get(issuer)
            .expect("enrolled issuer sets match");
        if anchor.sequence != u64::try_from(statements.len()).expect("lifecycle bound fits u64")
            || Some(&anchor.tip_digest) != previous_digest.as_ref()
        {
            return Err(ProtocolError::KeyLifecycle(format!(
                "trusted lifecycle anchor mismatch for {issuer}"
            )));
        }
    }
    Ok(by_issuer)
}

fn key_for_envelope<'a>(
    scenario: &'a Scenario,
    envelope: &Envelope,
    require_current: bool,
    lifecycle: &'a BTreeMap<String, Vec<&KeyLifecycleStatement>>,
) -> Result<&'a str, String> {
    let bootstrap = scenario
        .public_keys
        .get(&envelope.issuer)
        .ok_or_else(|| "unknown issuer".to_string())?;
    let Some(statements) = lifecycle.get(&envelope.issuer) else {
        return Ok(bootstrap);
    };
    if statements[0].authority_kind != envelope.kind {
        return Err("issuer lifecycle is bound to another authority kind".into());
    }
    let issued = active_key_at(bootstrap, statements, envelope.issued_at)
        .ok_or_else(|| "no active issuer key at envelope issuance".to_string())?;
    if require_current {
        let current = active_key_at(bootstrap, statements, scenario.evaluation_time)
            .ok_or_else(|| "issuer key is revoked or expired".to_string())?;
        if current != issued {
            return Err("envelope was signed by a superseded issuer key".into());
        }
    }
    Ok(issued)
}

fn active_key_at<'a>(
    bootstrap: &'a str,
    statements: &'a [&KeyLifecycleStatement],
    at: u64,
) -> Option<&'a str> {
    let mut active = Some((bootstrap, u64::MAX));
    for statement in statements {
        if statement.effective_at > at {
            break;
        }
        match &statement.action {
            KeyLifecycleAction::Activate {
                public_key,
                expires_at,
            } => active = Some((public_key, *expires_at)),
            KeyLifecycleAction::Revoke { .. } => active = None,
        }
    }
    active.and_then(|(key, expires_at)| (at < expires_at).then_some(key))
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(encoded).map_err(|error| error.to_string())?;
    if hex::encode(&bytes) != encoded {
        return Err("public key must use canonical lowercase hex".into());
    }
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&array).map_err(|error| error.to_string())
}

fn verify_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> Result<(), String> {
    let bytes = hex::decode(encoded).map_err(|error| error.to_string())?;
    let signature = Signature::from_slice(&bytes).map_err(|error| error.to_string())?;
    key.verify(message, &signature)
        .map_err(|_| "verification failed".into())
}

fn validate_envelope(
    scenario: &Scenario,
    envelope: &Envelope,
    require_current: bool,
    lifecycle: &BTreeMap<String, Vec<&KeyLifecycleStatement>>,
) -> Result<(), ProtocolError> {
    let invalid = |field, reason: String| ProtocolError::Invalid {
        kind: envelope.kind,
        field,
        reason,
    };
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(invalid("schema_version", "unsupported schema".into()));
    }
    if envelope.sequence > 1 && envelope.parent_digests.is_empty() {
        return Err(invalid("parent_digests", "broken lineage".into()));
    }
    if envelope.subject != scenario.subject {
        return Err(invalid("subject", "subject mismatch".into()));
    }
    if envelope.issued_at >= envelope.expires_at
        || envelope.issued_at > scenario.evaluation_time
        || (require_current && scenario.evaluation_time >= envelope.expires_at)
    {
        return Err(invalid("validity", "envelope is not current".into()));
    }
    if digest(&envelope.content) != envelope.content_digest {
        return Err(invalid("content_digest", "digest mismatch".into()));
    }
    let encoded_key = key_for_envelope(scenario, envelope, require_current, lifecycle)
        .map_err(|reason| invalid("public_key", reason))?;
    let key_bytes =
        hex::decode(encoded_key).map_err(|error| invalid("public_key", error.to_string()))?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| invalid("public_key", "expected 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&key_array)
        .map_err(|error| invalid("public_key", error.to_string()))?;
    let signature_bytes = hex::decode(&envelope.signature)
        .map_err(|error| invalid("signature", error.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| invalid("signature", error.to_string()))?;
    key.verify(&envelope.signed_bytes(), &signature)
        .map_err(|_| invalid("signature", "verification failed".into()))
}

#[cfg(test)]
mod key_lifecycle_tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn scenario() -> Scenario {
        serde_json::from_slice(include_bytes!("../scenarios/benign.json")).unwrap()
    }

    fn encoded_key(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    fn sign_envelope(envelope: &mut Envelope, key: &SigningKey) {
        envelope.signature = hex::encode(key.sign(&envelope.signed_bytes()).to_bytes());
    }

    fn enroll(
        scenario: &mut Scenario,
        issuer: &str,
        kind: AuthorityKind,
        root: &SigningKey,
        actions: Vec<(u64, KeyLifecycleAction)>,
    ) {
        scenario.trusted_time = Some(TrustedTimeWindow {
            not_before: scenario.evaluation_time.saturating_sub(60),
            not_after: scenario.evaluation_time.saturating_add(60),
            source: "credential-free-test-clock".into(),
        });
        let mut parent_digest = None;
        for (index, (effective_at, action)) in actions.into_iter().enumerate() {
            let mut statement = KeyLifecycleStatement {
                schema_version: KEY_LIFECYCLE_SCHEMA_VERSION.into(),
                subject: scenario.subject.clone(),
                issuer: issuer.into(),
                authority_kind: kind,
                sequence: u64::try_from(index + 1).unwrap(),
                effective_at,
                parent_digest,
                action,
                signature: String::new(),
            };
            statement.signature = hex::encode(root.sign(&statement.signed_bytes()).to_bytes());
            parent_digest = Some(digest(&statement));
            scenario.key_lifecycle.push(statement);
        }
        scenario
            .key_lifecycle_roots
            .insert(issuer.into(), encoded_key(root));
        scenario.key_lifecycle_anchors.insert(
            issuer.into(),
            KeyLifecycleAnchor {
                sequence: u64::try_from(
                    scenario
                        .key_lifecycle
                        .iter()
                        .filter(|statement| statement.issuer == issuer)
                        .count(),
                )
                .unwrap(),
                tip_digest: parent_digest.unwrap(),
            },
        );
    }

    #[test]
    fn rotation_accepts_new_current_key_and_preserves_old_history() {
        let mut scenario = scenario();
        let root = SigningKey::from_bytes(&[90; 32]);
        let rotated = SigningKey::from_bytes(&[91; 32]);
        enroll(
            &mut scenario,
            "phenotype-lab",
            AuthorityKind::Phenotype,
            &root,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        let current = scenario
            .authorities
            .iter_mut()
            .find(|envelope| envelope.kind == AuthorityKind::Phenotype)
            .unwrap();
        current.issued_at = 1_730_000_000;
        sign_envelope(current, &rotated);
        scenario.phenotype_history_anchor.tip_digest = digest(current);

        let verified = verify(&scenario).unwrap();
        assert_eq!(verified.phenotype_history.len(), 1);
    }

    #[test]
    fn superseded_expired_and_revoked_keys_cannot_authorize_current_evidence() {
        let original = scenario();
        let root = SigningKey::from_bytes(&[90; 32]);
        let rotated = SigningKey::from_bytes(&[91; 32]);

        let mut superseded = original.clone();
        enroll(
            &mut superseded,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        assert!(matches!(
            verify(&superseded),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));

        let mut expired = original.clone();
        enroll(
            &mut expired,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_690_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_740_000_000,
                },
            )],
        );
        let goal = expired
            .authorities
            .iter_mut()
            .find(|envelope| envelope.issuer == "goal-lab")
            .unwrap();
        sign_envelope(goal, &rotated);
        assert!(matches!(
            verify(&expired),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));

        let mut revoked = original;
        enroll(
            &mut revoked,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![
                (
                    1_690_000_000,
                    KeyLifecycleAction::Activate {
                        public_key: encoded_key(&rotated),
                        expires_at: 1_790_000_000,
                    },
                ),
                (
                    1_740_000_000,
                    KeyLifecycleAction::Revoke {
                        public_key_digest: digest(&encoded_key(&rotated)),
                    },
                ),
            ],
        );
        let goal = revoked
            .authorities
            .iter_mut()
            .find(|envelope| envelope.issuer == "goal-lab")
            .unwrap();
        sign_envelope(goal, &rotated);
        assert!(matches!(
            verify(&revoked),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));
        revoked
            .authorities
            .retain(|envelope| envelope.issuer != "goal-lab");
        verify(&revoked).unwrap();
    }

    #[test]
    fn recovery_root_can_activate_a_fresh_key_after_revocation() {
        let mut scenario = scenario();
        let root = SigningKey::from_bytes(&[90; 32]);
        let compromised = SigningKey::from_bytes(&[91; 32]);
        let recovered = SigningKey::from_bytes(&[92; 32]);
        enroll(
            &mut scenario,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![
                (
                    1_690_000_000,
                    KeyLifecycleAction::Activate {
                        public_key: encoded_key(&compromised),
                        expires_at: 1_790_000_000,
                    },
                ),
                (
                    1_720_000_000,
                    KeyLifecycleAction::Revoke {
                        public_key_digest: digest(&encoded_key(&compromised)),
                    },
                ),
                (
                    1_730_000_000,
                    KeyLifecycleAction::Activate {
                        public_key: encoded_key(&recovered),
                        expires_at: 1_790_000_000,
                    },
                ),
            ],
        );
        let goal = scenario
            .authorities
            .iter_mut()
            .find(|envelope| envelope.issuer == "goal-lab")
            .unwrap();
        goal.issued_at = 1_735_000_000;
        sign_envelope(goal, &recovered);
        verify(&scenario).unwrap();
    }

    #[test]
    fn trusted_time_expiry_and_revocation_boundaries_fail_closed() {
        let root = SigningKey::from_bytes(&[90; 32]);
        let rotated = SigningKey::from_bytes(&[91; 32]);
        let mut candidate = scenario();
        enroll(
            &mut candidate,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_690_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        let goal = candidate
            .authorities
            .iter_mut()
            .find(|envelope| envelope.issuer == "goal-lab")
            .unwrap();
        sign_envelope(goal, &rotated);

        let set_time = |scenario: &mut Scenario, at| {
            scenario.evaluation_time = at;
            scenario.trusted_time = Some(TrustedTimeWindow {
                not_before: at,
                not_after: at,
                source: "credential-free-test-clock".into(),
            });
        };
        set_time(&mut candidate, 1_789_999_999);
        verify(&candidate).unwrap();
        set_time(&mut candidate, 1_790_000_000);
        assert!(matches!(
            verify(&candidate),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));

        let mut revoked = scenario();
        enroll(
            &mut revoked,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![
                (
                    1_690_000_000,
                    KeyLifecycleAction::Activate {
                        public_key: encoded_key(&rotated),
                        expires_at: 1_790_000_000,
                    },
                ),
                (
                    1_760_000_000,
                    KeyLifecycleAction::Revoke {
                        public_key_digest: digest(&encoded_key(&rotated)),
                    },
                ),
            ],
        );
        let goal = revoked
            .authorities
            .iter_mut()
            .find(|envelope| envelope.issuer == "goal-lab")
            .unwrap();
        sign_envelope(goal, &rotated);
        set_time(&mut revoked, 1_760_000_000);
        assert!(matches!(
            verify(&revoked),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));
    }

    #[test]
    fn trusted_time_rollback_forward_and_unbounded_windows_refuse() {
        let root = SigningKey::from_bytes(&[90; 32]);
        let rotated = SigningKey::from_bytes(&[91; 32]);
        let mut candidate = scenario();
        enroll(
            &mut candidate,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        let window = candidate.trusted_time.clone().unwrap();

        let mut absent = candidate.clone();
        absent.trusted_time = None;
        assert!(matches!(
            verify(&absent),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut rollback = candidate.clone();
        rollback.evaluation_time = window.not_before - 1;
        assert!(matches!(
            verify(&rollback),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut forward = candidate.clone();
        forward.evaluation_time = window.not_after + 1;
        assert!(matches!(
            verify(&forward),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        candidate.trusted_time.as_mut().unwrap().not_after =
            window.not_before + MAX_TRUSTED_TIME_WINDOW_SECONDS + 1;
        assert!(matches!(
            verify(&candidate),
            Err(ProtocolError::KeyLifecycle(_))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn lifecycle_rollback_equivocation_kind_mismatch_and_bounds_fail_closed() {
        let root = SigningKey::from_bytes(&[90; 32]);
        let rotated = SigningKey::from_bytes(&[91; 32]);
        let activation = KeyLifecycleAction::Activate {
            public_key: encoded_key(&rotated),
            expires_at: 1_790_000_000,
        };
        let mut anchored_rollback = scenario();
        enroll(
            &mut anchored_rollback,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(1_720_000_000, activation.clone())],
        );
        anchored_rollback
            .key_lifecycle_anchors
            .get_mut("goal-lab")
            .unwrap()
            .tip_digest = "00".repeat(32);
        assert!(matches!(
            verify(&anchored_rollback),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut kind_mismatch = scenario();
        enroll(
            &mut kind_mismatch,
            "goal-lab",
            AuthorityKind::Viability,
            &root,
            vec![(1_720_000_000, activation.clone())],
        );
        assert!(matches!(
            verify(&kind_mismatch),
            Err(ProtocolError::Invalid {
                field: "public_key",
                ..
            })
        ));

        let mut tampered = scenario();
        enroll(
            &mut tampered,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(1_720_000_000, activation)],
        );
        tampered.key_lifecycle[0].effective_at += 1;
        assert!(matches!(
            verify(&tampered),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut equivocation = scenario();
        let bootstrap_digest = digest(equivocation.public_keys.get("goal-lab").unwrap());
        enroll(
            &mut equivocation,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Revoke {
                    public_key_digest: bootstrap_digest,
                },
            )],
        );
        equivocation
            .key_lifecycle
            .push(equivocation.key_lifecycle[0].clone());
        assert!(matches!(
            verify(&equivocation),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut partial = scenario();
        partial
            .key_lifecycle_roots
            .insert("goal-lab".into(), encoded_key(&root));
        assert!(matches!(
            verify(&partial),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut oversized = scenario();
        oversized.key_lifecycle = vec![
            KeyLifecycleStatement {
                schema_version: KEY_LIFECYCLE_SCHEMA_VERSION.into(),
                subject: oversized.subject.clone(),
                issuer: "goal-lab".into(),
                authority_kind: AuthorityKind::Goal,
                sequence: 1,
                effective_at: 1,
                parent_digest: None,
                action: KeyLifecycleAction::Revoke {
                    public_key_digest: "00".repeat(32),
                },
                signature: "00".repeat(64),
            };
            65
        ];
        assert!(matches!(
            verify(&oversized),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut self_recovery = scenario();
        let operational = SigningKey::from_bytes(&[11; 32]);
        enroll(
            &mut self_recovery,
            "goal-lab",
            AuthorityKind::Goal,
            &operational,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        assert!(matches!(
            verify(&self_recovery),
            Err(ProtocolError::KeyLifecycle(_))
        ));

        let mut noncanonical = scenario();
        enroll(
            &mut noncanonical,
            "goal-lab",
            AuthorityKind::Goal,
            &root,
            vec![(
                1_720_000_000,
                KeyLifecycleAction::Activate {
                    public_key: encoded_key(&rotated).to_uppercase(),
                    expires_at: 1_790_000_000,
                },
            )],
        );
        assert!(matches!(
            verify(&noncanonical),
            Err(ProtocolError::KeyLifecycle(_))
        ));
    }
}
