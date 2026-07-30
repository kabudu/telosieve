use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::certificate_attestation::{CertificateAttestation, VerifiedAttestation};

pub const TIMESTAMP_SCHEMA: &str = "telosieve.attestation-timestamp/v1";
pub const REVOCATION_SCHEMA: &str = "telosieve.signer-revocations/v1";
pub const MAX_WITNESS_BYTES: usize = 64 * 1024;
pub const MAX_WITNESS_RECORDS: usize = 64;
pub const MAX_REVOCATIONS: usize = 64;
pub const MAX_REVOCATION_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampRecord {
    pub schema_version: String,
    pub context: String,
    pub sequence: u64,
    pub previous_digest: Option<String>,
    pub attestation_sha256: String,
    pub observed_at: u64,
    pub authority: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedTimestamp<'a> {
    schema_version: &'a str,
    context: &'a str,
    sequence: u64,
    previous_digest: &'a Option<String>,
    attestation_sha256: &'a str,
    observed_at: u64,
    authority: &'a str,
    key_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedSigner {
    pub signer: String,
    pub key_id: String,
    pub revoked_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSnapshot {
    pub schema_version: String,
    pub context: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub entries: Vec<RevokedSigner>,
    pub authority: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedRevocations<'a> {
    schema_version: &'a str,
    context: &'a str,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    entries: &'a [RevokedSigner],
    authority: &'a str,
    key_id: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessTrust {
    pub context: String,
    pub evaluation_time: u64,
    pub timestamp_authority: String,
    pub timestamp_key_id: String,
    pub timestamp_public_key: String,
    pub trusted_tip_sequence: u64,
    pub trusted_tip_digest: String,
    pub revocation_authority: String,
    pub revocation_key_id: String,
    pub revocation_public_key: String,
    pub trusted_revocation_sequence: u64,
    pub trusted_revocation_digest: String,
}

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("timestamp or revocation evidence exceeds its resource bound")]
    ResourceBound,
    #[error("timestamp or revocation JSON is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("timestamp chain is invalid, incomplete, rolled back, or equivocal")]
    InvalidChain,
    #[error("timestamp or revocation trust is invalid")]
    InvalidTrust,
    #[error("timestamp or revocation signature is invalid")]
    InvalidSignature,
    #[error("attestation was not witnessed inside its validity interval")]
    InvalidTime,
    #[error("attestation signer was revoked at or before observation")]
    Revoked,
}

impl TimestampRecord {
    fn signed_bytes(&self) -> Vec<u8> {
        domain_json(
            TIMESTAMP_SCHEMA,
            &UnsignedTimestamp {
                schema_version: &self.schema_version,
                context: &self.context,
                sequence: self.sequence,
                previous_digest: &self.previous_digest,
                attestation_sha256: &self.attestation_sha256,
                observed_at: self.observed_at,
                authority: &self.authority,
                key_id: &self.key_id,
            },
        )
    }

    #[must_use]
    /// Returns the canonical record digest used by the next record and trusted tip.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of this fully typed record unexpectedly fails.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("typed timestamp serialization cannot fail"),
        ))
    }
}

impl RevocationSnapshot {
    fn signed_bytes(&self) -> Vec<u8> {
        domain_json(
            REVOCATION_SCHEMA,
            &UnsignedRevocations {
                schema_version: &self.schema_version,
                context: &self.context,
                sequence: self.sequence,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                entries: &self.entries,
                authority: &self.authority,
                key_id: &self.key_id,
            },
        )
    }
}

/// Creates one signed append-only timestamp record.
///
/// # Errors
///
/// Refuses malformed or oversized attestation evidence, invalid chain fields,
/// context mismatch, and observation outside the attestation lifetime.
#[allow(clippy::too_many_arguments)]
pub fn witness_attestation(
    attestation_bytes: &[u8],
    context: &str,
    sequence: u64,
    previous_digest: Option<String>,
    observed_at: u64,
    authority: &str,
    key_id: &str,
    key: &SigningKey,
) -> Result<TimestampRecord, WitnessError> {
    if attestation_bytes.len() > MAX_WITNESS_BYTES
        || sequence == 0
        || (sequence == 1) != previous_digest.is_none()
        || previous_digest
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
        || !valid_text(context)
        || !valid_text(authority)
        || !valid_text(key_id)
    {
        return Err(if attestation_bytes.len() > MAX_WITNESS_BYTES {
            WitnessError::ResourceBound
        } else {
            WitnessError::InvalidChain
        });
    }
    let attestation: CertificateAttestation = serde_json::from_slice(attestation_bytes)?;
    if attestation.context != context
        || observed_at < attestation.issued_at
        || observed_at >= attestation.expires_at
    {
        return Err(WitnessError::InvalidTime);
    }
    let mut record = TimestampRecord {
        schema_version: TIMESTAMP_SCHEMA.into(),
        context: context.into(),
        sequence,
        previous_digest,
        attestation_sha256: hex::encode(Sha256::digest(attestation_bytes)),
        observed_at,
        authority: authority.into(),
        key_id: key_id.into(),
        signature: String::new(),
    };
    record.signature = hex::encode(key.sign(&record.signed_bytes()).to_bytes());
    Ok(record)
}

/// Creates a bounded, signed signer-revocation snapshot.
///
/// # Errors
///
/// Refuses invalid identifiers, duplicate or excessive entries, invalid
/// sequences, and unbounded validity intervals.
#[allow(clippy::too_many_arguments)]
pub fn sign_revocations(
    context: &str,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    entries: Vec<RevokedSigner>,
    authority: &str,
    key_id: &str,
    key: &SigningKey,
) -> Result<RevocationSnapshot, WitnessError> {
    let mut snapshot = RevocationSnapshot {
        schema_version: REVOCATION_SCHEMA.into(),
        context: context.into(),
        sequence,
        issued_at,
        expires_at,
        entries,
        authority: authority.into(),
        key_id: key_id.into(),
        signature: String::new(),
    };
    validate_revocations(&snapshot)?;
    snapshot.signature = hex::encode(key.sign(&snapshot.signed_bytes()).to_bytes());
    Ok(snapshot)
}

/// Verifies the complete anchored timestamp chain and exact revocation snapshot.
///
/// # Errors
///
/// Refuses malformed, oversized, rolled-back, equivocal, stale, incorrectly
/// signed, unwitnessed, or revoked evidence.
pub fn verify_witnessed_attestation(
    verified: &VerifiedAttestation,
    attestation_bytes: &[u8],
    timestamp_bytes: &[u8],
    revocation_bytes: &[u8],
    trust: &WitnessTrust,
) -> Result<TimestampRecord, WitnessError> {
    if attestation_bytes.len() > MAX_WITNESS_BYTES
        || timestamp_bytes.len() > MAX_WITNESS_BYTES
        || revocation_bytes.len() > MAX_WITNESS_BYTES
    {
        return Err(WitnessError::ResourceBound);
    }
    validate_trust(trust)?;
    let records: Vec<TimestampRecord> = serde_json::from_slice(timestamp_bytes)?;
    if records.is_empty() || records.len() > MAX_WITNESS_RECORDS {
        return Err(WitnessError::ResourceBound);
    }
    let timestamp_key = decode_key(&trust.timestamp_public_key)?;
    let mut predecessor = None;
    let mut previous_observed_at = None;
    let mut matched = None;
    for (index, record) in records.iter().enumerate() {
        let expected_sequence =
            u64::try_from(index + 1).map_err(|_| WitnessError::ResourceBound)?;
        if record.schema_version != TIMESTAMP_SCHEMA
            || record.context != trust.context
            || record.sequence != expected_sequence
            || record.previous_digest != predecessor
            || record.authority != trust.timestamp_authority
            || record.key_id != trust.timestamp_key_id
            || !valid_digest(&record.attestation_sha256)
            || previous_observed_at.is_some_and(|previous| record.observed_at < previous)
        {
            return Err(WitnessError::InvalidChain);
        }
        verify_signature(&timestamp_key, &record.signature, &record.signed_bytes())?;
        if record.attestation_sha256 == hex::encode(Sha256::digest(attestation_bytes))
            && matched.replace(record.clone()).is_some()
        {
            return Err(WitnessError::InvalidChain);
        }
        predecessor = Some(record.digest());
        previous_observed_at = Some(record.observed_at);
    }
    if records.last().map(|record| record.sequence) != Some(trust.trusted_tip_sequence)
        || predecessor.as_deref() != Some(&trust.trusted_tip_digest)
    {
        return Err(WitnessError::InvalidChain);
    }
    let record = matched.ok_or(WitnessError::InvalidChain)?;
    let attestation: CertificateAttestation = serde_json::from_slice(attestation_bytes)?;
    if attestation.signer != verified.signer
        || attestation.key_id != verified.key_id
        || attestation.certificate_sha256 != verified.certificate_sha256
    {
        return Err(WitnessError::InvalidTrust);
    }
    if record.observed_at < attestation.issued_at || record.observed_at >= attestation.expires_at {
        return Err(WitnessError::InvalidTime);
    }

    let snapshot: RevocationSnapshot = serde_json::from_slice(revocation_bytes)?;
    validate_revocations(&snapshot)?;
    let snapshot_digest = hex::encode(Sha256::digest(revocation_bytes));
    if snapshot.context != trust.context
        || snapshot.authority != trust.revocation_authority
        || snapshot.key_id != trust.revocation_key_id
        || snapshot.sequence != trust.trusted_revocation_sequence
        || snapshot_digest != trust.trusted_revocation_digest
        || trust.evaluation_time < snapshot.issued_at
        || trust.evaluation_time >= snapshot.expires_at
    {
        return Err(WitnessError::InvalidTrust);
    }
    verify_signature(
        &decode_key(&trust.revocation_public_key)?,
        &snapshot.signature,
        &snapshot.signed_bytes(),
    )?;
    if snapshot.entries.iter().any(|entry| {
        entry.signer == verified.signer
            && entry.key_id == verified.key_id
            && record.observed_at >= entry.revoked_at
    }) {
        return Err(WitnessError::Revoked);
    }
    Ok(record)
}

fn validate_revocations(snapshot: &RevocationSnapshot) -> Result<(), WitnessError> {
    if snapshot.schema_version != REVOCATION_SCHEMA
        || snapshot.sequence == 0
        || !valid_text(&snapshot.context)
        || !valid_text(&snapshot.authority)
        || !valid_text(&snapshot.key_id)
        || snapshot.issued_at >= snapshot.expires_at
        || snapshot.expires_at - snapshot.issued_at > MAX_REVOCATION_LIFETIME_SECONDS
        || snapshot.entries.len() > MAX_REVOCATIONS
    {
        return Err(WitnessError::InvalidTrust);
    }
    let mut identities = BTreeSet::new();
    for entry in &snapshot.entries {
        if !valid_text(&entry.signer)
            || !valid_text(&entry.key_id)
            || !identities.insert((&entry.signer, &entry.key_id))
        {
            return Err(WitnessError::InvalidTrust);
        }
    }
    Ok(())
}

fn validate_trust(trust: &WitnessTrust) -> Result<(), WitnessError> {
    if !valid_text(&trust.context)
        || !valid_text(&trust.timestamp_authority)
        || !valid_text(&trust.timestamp_key_id)
        || !valid_text(&trust.revocation_authority)
        || !valid_text(&trust.revocation_key_id)
        || trust.trusted_tip_sequence == 0
        || trust.trusted_revocation_sequence == 0
        || !valid_digest(&trust.trusted_tip_digest)
        || !valid_digest(&trust.trusted_revocation_digest)
    {
        return Err(WitnessError::InvalidTrust);
    }
    decode_key(&trust.timestamp_public_key)?;
    decode_key(&trust.revocation_public_key)?;
    Ok(())
}

fn domain_json<T: Serialize>(domain: &str, value: &T) -> Vec<u8> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(value).expect("typed witness serialization cannot fail"));
    bytes
}

fn verify_signature(key: &VerifyingKey, encoded: &str, message: &[u8]) -> Result<(), WitnessError> {
    if encoded.len() != 128 {
        return Err(WitnessError::InvalidSignature);
    }
    let signature =
        Signature::from_slice(&hex::decode(encoded).map_err(|_| WitnessError::InvalidSignature)?)
            .map_err(|_| WitnessError::InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| WitnessError::InvalidSignature)
}

fn decode_key(value: &str) -> Result<VerifyingKey, WitnessError> {
    if !valid_digest(value) {
        return Err(WitnessError::InvalidTrust);
    }
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| WitnessError::InvalidTrust)?
        .try_into()
        .map_err(|_| WitnessError::InvalidTrust)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| WitnessError::InvalidTrust)
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
