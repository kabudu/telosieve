use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{ServiceState, Values, digest};

pub const SCHEMA_VERSION: &str = "telosieve.authority/v0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    Goal,
    Phenotype,
    Viability,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultDeclaration {
    pub maximum_faults: usize,
    pub suspectable: BTreeSet<AuthorityKind>,
    #[serde(default)]
    pub viability_fault_domains: BTreeMap<String, String>,
    pub maximum_hypotheses: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryAnchor {
    pub issuer: String,
    pub sequence: u64,
    pub tip_digest: String,
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
}

/// Authenticates, freshness-checks, and decodes the scenario authority set.
///
/// # Errors
///
/// Returns [`ProtocolError`] when an authority is missing, duplicated, stale,
/// malformed, digest-mismatched, or has an invalid signature.
pub fn verify(scenario: &Scenario) -> Result<VerifiedAuthorities, ProtocolError> {
    if scenario.phenotype_history.len() > 64 {
        return Err(ProtocolError::Invalid {
            kind: AuthorityKind::Phenotype,
            field: "phenotype_history",
            reason: "history exceeds the 64-record bound".into(),
        });
    }
    for envelope in &scenario.authorities {
        validate_envelope(scenario, envelope, true)?;
    }
    for envelope in &scenario.phenotype_history {
        validate_envelope(scenario, envelope, false)?;
    }
    let mut by_kind = BTreeMap::new();
    let mut viability_envelopes = Vec::new();
    for envelope in &scenario.authorities {
        if envelope.kind == AuthorityKind::Viability {
            if viability_envelopes
                .iter()
                .any(|existing: &&Envelope| existing.issuer == envelope.issuer)
            {
                return Err(ProtocolError::Invalid {
                    kind: AuthorityKind::Viability,
                    field: "issuer",
                    reason: "duplicate viability issuer".into(),
                });
            }
            viability_envelopes.push(envelope);
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

    let goal = parse_content::<Values>(&by_kind, AuthorityKind::Goal)?;
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
    let digests = authority_digests(scenario);

    Ok(VerifiedAuthorities {
        digests,
        goal,
        phenotype,
        phenotype_history,
        viability,
    })
}

fn authority_digests(scenario: &Scenario) -> BTreeMap<String, String> {
    scenario
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
        .collect()
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

fn validate_envelope(
    scenario: &Scenario,
    envelope: &Envelope,
    require_current: bool,
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
    let key_bytes = scenario
        .public_keys
        .get(&envelope.issuer)
        .ok_or_else(|| invalid("issuer", "unknown issuer".into()))
        .and_then(|encoded| {
            hex::decode(encoded).map_err(|error| invalid("public_key", error.to_string()))
        })?;
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
