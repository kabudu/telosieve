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
    pub maximum_hypotheses: usize,
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
    pub authorities: Vec<Envelope>,
}

#[derive(Clone, Debug)]
pub struct VerifiedAuthorities {
    pub digests: BTreeMap<AuthorityKind, String>,
    pub goal: Values,
    pub phenotype: ServiceState,
    pub viability: ViabilityRules,
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
    let mut by_kind = BTreeMap::new();
    for envelope in &scenario.authorities {
        if by_kind.insert(envelope.kind, envelope).is_some() {
            return Err(ProtocolError::Cardinality(envelope.kind));
        }
        validate_envelope(scenario, envelope)?;
    }

    let goal = parse_content::<Values>(&by_kind, AuthorityKind::Goal)?;
    let phenotype = parse_content::<ServiceState>(&by_kind, AuthorityKind::Phenotype)?;
    let viability = parse_content::<ViabilityRules>(&by_kind, AuthorityKind::Viability)?;
    let digests = by_kind
        .into_iter()
        .map(|(kind, envelope)| (kind, digest(envelope)))
        .collect();

    Ok(VerifiedAuthorities {
        digests,
        goal,
        phenotype,
        viability,
    })
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

fn validate_envelope(scenario: &Scenario, envelope: &Envelope) -> Result<(), ProtocolError> {
    let invalid = |field, reason: String| ProtocolError::Invalid {
        kind: envelope.kind,
        field,
        reason,
    };
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(invalid("schema_version", "unsupported schema".into()));
    }
    if envelope.subject != scenario.subject {
        return Err(invalid("subject", "subject mismatch".into()));
    }
    if !(envelope.issued_at <= scenario.evaluation_time
        && scenario.evaluation_time < envelope.expires_at)
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
