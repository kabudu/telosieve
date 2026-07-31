use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TRUST_SCHEMA_VERSION: &str = "telosieve.observation-trust/v1";
pub const QUORUM_SCHEMA_VERSION: &str = "telosieve.observation-quorum/v1";
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
pub const MAX_PARTICIPANTS: usize = 8;
pub const MAX_LIFETIME_SECONDS: u64 = 300;
const SUPPORTED_MODES: [&str; 3] = ["kubernetes-shadow", "kubernetes-live", "opentofu-plan"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationKey {
    pub producer: String,
    pub key_id: String,
    pub fault_domain: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationTrust {
    pub schema_version: String,
    pub evaluation_time: u64,
    pub required_distinct_domains: usize,
    pub keys: Vec<ObservationKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAttestation {
    pub producer: String,
    pub key_id: String,
    pub fault_domain: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationQuorum {
    pub schema_version: String,
    pub subject: String,
    pub mode: String,
    pub input_sha256: String,
    pub attestations: Vec<ObservationAttestation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationSigningRequest<'a> {
    pub subject: &'a str,
    pub mode: &'a str,
    pub producer: &'a str,
    pub key_id: &'a str,
    pub fault_domain: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Serialize)]
struct Unsigned<'a> {
    schema_version: &'a str,
    subject: &'a str,
    mode: &'a str,
    input_sha256: &'a str,
    producer: &'a str,
    key_id: &'a str,
    fault_domain: &'a str,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedObservationQuorum {
    pub evidence_digest: String,
    pub distinct_domains: usize,
    pub producers: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObservationQuorumError {
    #[error("observation input or document exceeds its resource bound")]
    ResourceBound,
    #[error("observation trust or quorum JSON is malformed or non-canonical")]
    Malformed,
    #[error("observation trust configuration is invalid")]
    InvalidTrust,
    #[error("observation quorum envelope is invalid")]
    InvalidQuorum,
    #[error("observation quorum does not match the exact input context")]
    InputMismatch,
    #[error("observation signer is unknown, ambiguous, or duplicated")]
    UnknownSigner,
    #[error("observation attestation is outside its trust or evaluation window")]
    InvalidTime,
    #[error("observation attestation signature is invalid")]
    InvalidSignature,
    #[error("observation quorum has insufficient distinct fault domains")]
    InsufficientDomains,
}

impl ObservationAttestation {
    fn signed_bytes(&self, quorum: &ObservationQuorum) -> Vec<u8> {
        let mut bytes = QUORUM_SCHEMA_VERSION.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(
            serde_json::to_vec(&Unsigned {
                schema_version: &quorum.schema_version,
                subject: &quorum.subject,
                mode: &quorum.mode,
                input_sha256: &quorum.input_sha256,
                producer: &self.producer,
                key_id: &self.key_id,
                fault_domain: &self.fault_domain,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
            .expect("typed observation attestation serialization cannot fail"),
        );
        bytes
    }
}

/// Creates one domain-separated signature over an exact observation context.
///
/// # Errors
///
/// Refuses oversized input, unsupported modes, unsafe identifiers, and invalid
/// or over-wide validity windows.
pub fn sign_observation(
    input: &[u8],
    request: &ObservationSigningRequest<'_>,
    key: &SigningKey,
) -> Result<ObservationAttestation, ObservationQuorumError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ObservationQuorumError::ResourceBound);
    }
    if !valid_text(request.subject)
        || !valid_mode(request.mode)
        || !valid_text(request.producer)
        || !valid_text(request.key_id)
        || !valid_text(request.fault_domain)
        || request.issued_at >= request.expires_at
        || request.expires_at - request.issued_at > MAX_LIFETIME_SECONDS
    {
        return Err(ObservationQuorumError::InvalidQuorum);
    }
    let quorum = ObservationQuorum {
        schema_version: QUORUM_SCHEMA_VERSION.into(),
        subject: request.subject.into(),
        mode: request.mode.into(),
        input_sha256: hex::encode(Sha256::digest(input)),
        attestations: Vec::new(),
    };
    let mut attestation = ObservationAttestation {
        producer: request.producer.into(),
        key_id: request.key_id.into(),
        fault_domain: request.fault_domain.into(),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        signature: String::new(),
    };
    attestation.signature = hex::encode(key.sign(&attestation.signed_bytes(&quorum)).to_bytes());
    Ok(attestation)
}

/// Verifies canonical trust and quorum documents against exact observation bytes.
///
/// # Errors
///
/// Refuses resource excess, non-canonical documents, invalid trust, context or
/// digest mismatch, ambiguous identities, invalid time, forgery, and insufficient
/// distinct fault domains.
pub fn verify_observation_quorum(
    input: &[u8],
    expected_subject: &str,
    expected_mode: &str,
    trust_bytes: &[u8],
    quorum_bytes: &[u8],
) -> Result<VerifiedObservationQuorum, ObservationQuorumError> {
    if input.len() > MAX_INPUT_BYTES
        || trust_bytes.len() > MAX_DOCUMENT_BYTES
        || quorum_bytes.len() > MAX_DOCUMENT_BYTES
    {
        return Err(ObservationQuorumError::ResourceBound);
    }
    let trust: ObservationTrust = canonical_document(trust_bytes)?;
    let quorum: ObservationQuorum = canonical_document(quorum_bytes)?;
    validate_trust(&trust)?;
    if quorum.schema_version != QUORUM_SCHEMA_VERSION
        || !valid_text(&quorum.subject)
        || !valid_mode(&quorum.mode)
        || !canonical_hex(&quorum.input_sha256, 32)
        || quorum.attestations.len() < trust.required_distinct_domains
        || quorum.attestations.len() > MAX_PARTICIPANTS
    {
        return Err(ObservationQuorumError::InvalidQuorum);
    }
    if quorum.subject != expected_subject
        || quorum.mode != expected_mode
        || quorum.input_sha256 != hex::encode(Sha256::digest(input))
    {
        return Err(ObservationQuorumError::InputMismatch);
    }
    let keys: BTreeMap<_, _> = trust
        .keys
        .iter()
        .map(|key| ((key.producer.as_str(), key.key_id.as_str()), key))
        .collect();
    let mut producers = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for attestation in &quorum.attestations {
        if !valid_text(&attestation.producer)
            || !valid_text(&attestation.key_id)
            || !valid_text(&attestation.fault_domain)
            || !canonical_hex(&attestation.signature, 64)
            || attestation.issued_at >= attestation.expires_at
            || attestation.expires_at - attestation.issued_at > MAX_LIFETIME_SECONDS
            || !producers.insert(attestation.producer.clone())
        {
            return Err(ObservationQuorumError::InvalidQuorum);
        }
        domains.insert(attestation.fault_domain.clone());
        let key = keys
            .get(&(attestation.producer.as_str(), attestation.key_id.as_str()))
            .ok_or(ObservationQuorumError::UnknownSigner)?;
        if key.fault_domain != attestation.fault_domain {
            return Err(ObservationQuorumError::UnknownSigner);
        }
        if attestation.issued_at < key.not_before
            || attestation.expires_at > key.not_after
            || trust.evaluation_time < attestation.issued_at
            || trust.evaluation_time > attestation.expires_at
        {
            return Err(ObservationQuorumError::InvalidTime);
        }
        let public: [u8; 32] = hex::decode(&key.public_key)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(ObservationQuorumError::InvalidTrust)?;
        let signature: [u8; 64] = hex::decode(&attestation.signature)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(ObservationQuorumError::InvalidSignature)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| ObservationQuorumError::InvalidTrust)?
            .verify_strict(
                &attestation.signed_bytes(&quorum),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ObservationQuorumError::InvalidSignature)?;
    }
    if domains.len() < trust.required_distinct_domains {
        return Err(ObservationQuorumError::InsufficientDomains);
    }
    let mut evidence = b"telosieve.observation-quorum-evidence/v1\0".to_vec();
    evidence.extend(trust_bytes);
    evidence.push(0);
    evidence.extend(quorum_bytes);
    Ok(VerifiedObservationQuorum {
        evidence_digest: hex::encode(Sha256::digest(evidence)),
        distinct_domains: domains.len(),
        producers: producers.into_iter().collect(),
    })
}

fn validate_trust(trust: &ObservationTrust) -> Result<(), ObservationQuorumError> {
    if trust.schema_version != TRUST_SCHEMA_VERSION
        || !(2..=MAX_PARTICIPANTS).contains(&trust.required_distinct_domains)
        || trust.keys.len() < trust.required_distinct_domains
        || trust.keys.len() > MAX_PARTICIPANTS
    {
        return Err(ObservationQuorumError::InvalidTrust);
    }
    let mut identities = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for key in &trust.keys {
        if !valid_text(&key.producer)
            || !valid_text(&key.key_id)
            || !valid_text(&key.fault_domain)
            || !canonical_hex(&key.public_key, 32)
            || key.not_before >= key.not_after
            || !identities.insert((key.producer.as_str(), key.key_id.as_str()))
            || !public_keys.insert(key.public_key.as_str())
        {
            return Err(ObservationQuorumError::InvalidTrust);
        }
        domains.insert(key.fault_domain.as_str());
    }
    if domains.len() < trust.required_distinct_domains {
        return Err(ObservationQuorumError::InvalidTrust);
    }
    Ok(())
}

fn canonical_document<T>(bytes: &[u8]) -> Result<T, ObservationQuorumError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ObservationQuorumError::Malformed)?;
    if serde_json::to_vec(&value).map_err(|_| ObservationQuorumError::Malformed)? != bytes {
        return Err(ObservationQuorumError::Malformed);
    }
    Ok(value)
}

fn valid_mode(value: &str) -> bool {
    SUPPORTED_MODES.contains(&value)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(mode: &str, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let keys = [
            SigningKey::from_bytes(&[31; 32]),
            SigningKey::from_bytes(&[47; 32]),
        ];
        let trust = ObservationTrust {
            schema_version: TRUST_SCHEMA_VERSION.into(),
            evaluation_time: 150,
            required_distinct_domains: 2,
            keys: vec![
                ObservationKey {
                    producer: "observer-a".into(),
                    key_id: "key-a".into(),
                    fault_domain: "domain-a".into(),
                    public_key: hex::encode(keys[0].verifying_key().to_bytes()),
                    not_before: 50,
                    not_after: 250,
                },
                ObservationKey {
                    producer: "observer-b".into(),
                    key_id: "key-b".into(),
                    fault_domain: "domain-b".into(),
                    public_key: hex::encode(keys[1].verifying_key().to_bytes()),
                    not_before: 50,
                    not_after: 250,
                },
            ],
        };
        let quorum = ObservationQuorum {
            schema_version: QUORUM_SCHEMA_VERSION.into(),
            subject: "research-kv".into(),
            mode: mode.into(),
            input_sha256: hex::encode(Sha256::digest(input)),
            attestations: vec![
                sign_observation(
                    input,
                    &ObservationSigningRequest {
                        subject: "research-kv",
                        mode,
                        producer: "observer-a",
                        key_id: "key-a",
                        fault_domain: "domain-a",
                        issued_at: 100,
                        expires_at: 200,
                    },
                    &keys[0],
                )
                .unwrap(),
                sign_observation(
                    input,
                    &ObservationSigningRequest {
                        subject: "research-kv",
                        mode,
                        producer: "observer-b",
                        key_id: "key-b",
                        fault_domain: "domain-b",
                        issued_at: 100,
                        expires_at: 200,
                    },
                    &keys[1],
                )
                .unwrap(),
            ],
        };
        (
            serde_json::to_vec(&trust).unwrap(),
            serde_json::to_vec(&quorum).unwrap(),
        )
    }

    #[test]
    fn distinct_authenticated_domains_corroborate_all_evaluation_modes() {
        for mode in SUPPORTED_MODES {
            let input = format!("exact-{mode}-observation");
            let (trust, quorum) = evidence(mode, input.as_bytes());
            let verified =
                verify_observation_quorum(input.as_bytes(), "research-kv", mode, &trust, &quorum)
                    .unwrap();
            assert_eq!(verified.distinct_domains, 2);
            assert_eq!(verified.producers, ["observer-a", "observer-b"]);
            assert_eq!(verified.evidence_digest.len(), 64);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn substitution_forgery_domain_time_identity_and_shape_fail_closed() {
        let input = b"exact-observation";
        let (trust_bytes, quorum_bytes) = evidence("kubernetes-live", input);
        assert_eq!(
            verify_observation_quorum(
                b"substituted",
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &quorum_bytes
            ),
            Err(ObservationQuorumError::InputMismatch),
        );
        assert_eq!(
            verify_observation_quorum(
                input,
                "other",
                "kubernetes-live",
                &trust_bytes,
                &quorum_bytes
            ),
            Err(ObservationQuorumError::InputMismatch),
        );

        let mut quorum: ObservationQuorum = serde_json::from_slice(&quorum_bytes).unwrap();
        quorum.attestations[0].signature.replace_range(..2, "00");
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &serde_json::to_vec(&quorum).unwrap()
            ),
            Err(ObservationQuorumError::InvalidSignature),
        );

        let (_, mut shared_bytes) = evidence("kubernetes-live", input);
        let mut shared: ObservationQuorum = serde_json::from_slice(&shared_bytes).unwrap();
        shared.attestations[1].fault_domain = "domain-a".into();
        shared_bytes = serde_json::to_vec(&shared).unwrap();
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &shared_bytes
            ),
            Err(ObservationQuorumError::UnknownSigner),
        );

        let mut stale_trust: ObservationTrust = serde_json::from_slice(&trust_bytes).unwrap();
        stale_trust.evaluation_time = 201;
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &serde_json::to_vec(&stale_trust).unwrap(),
                &quorum_bytes
            ),
            Err(ObservationQuorumError::InvalidTime),
        );

        let mut reused_key: ObservationTrust = serde_json::from_slice(&trust_bytes).unwrap();
        reused_key.keys[1].public_key = reused_key.keys[0].public_key.clone();
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &serde_json::to_vec(&reused_key).unwrap(),
                &quorum_bytes
            ),
            Err(ObservationQuorumError::InvalidTrust),
        );

        let mut shared_trust: ObservationTrust = serde_json::from_slice(&trust_bytes).unwrap();
        shared_trust.keys[1].fault_domain = "domain-a".into();
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &serde_json::to_vec(&shared_trust).unwrap(),
                &quorum_bytes
            ),
            Err(ObservationQuorumError::InvalidTrust),
        );

        let mut unknown: ObservationQuorum = serde_json::from_slice(&quorum_bytes).unwrap();
        unknown.attestations[0].key_id = "unknown".into();
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &serde_json::to_vec(&unknown).unwrap()
            ),
            Err(ObservationQuorumError::UnknownSigner),
        );

        let mut duplicate: ObservationQuorum = serde_json::from_slice(&quorum_bytes).unwrap();
        duplicate.attestations[1] = duplicate.attestations[0].clone();
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &serde_json::to_vec(&duplicate).unwrap()
            ),
            Err(ObservationQuorumError::InvalidQuorum),
        );

        let mut noncanonical = quorum_bytes.clone();
        noncanonical.push(b'\n');
        assert_eq!(
            verify_observation_quorum(
                input,
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &noncanonical
            ),
            Err(ObservationQuorumError::Malformed),
        );
        assert_eq!(
            verify_observation_quorum(
                &vec![0; MAX_INPUT_BYTES + 1],
                "research-kv",
                "kubernetes-live",
                &trust_bytes,
                &quorum_bytes
            ),
            Err(ObservationQuorumError::ResourceBound),
        );
    }
}
