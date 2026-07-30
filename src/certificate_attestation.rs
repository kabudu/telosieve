use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::certificate::{MAX_COMPATIBILITY_CERTIFICATE_BYTES, parse_supported_certificate};

pub const ATTESTATION_SCHEMA_VERSION: &str = "telosieve.certificate-attestation/v1";
pub const MAX_ATTESTATION_BYTES: usize = 64 * 1024;
pub const MAX_ATTESTATION_KEYS: usize = 8;
pub const MAX_ATTESTATION_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateAttestation {
    pub schema_version: String,
    pub context: String,
    pub certificate_sha256: String,
    pub signer: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedAttestation<'a> {
    schema_version: &'a str,
    context: &'a str,
    certificate_sha256: &'a str,
    signer: &'a str,
    key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationKey {
    pub signer: String,
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationTrust {
    pub context: String,
    pub evaluation_time: u64,
    pub keys: Vec<AttestationKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedAttestation {
    pub signer: String,
    pub key_id: String,
    pub certificate_sha256: String,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("certificate or attestation exceeds its input bound")]
    ResourceBound,
    #[error("attestation JSON is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("certificate is not a supported compatibility artifact")]
    InvalidCertificate,
    #[error("attestation context, fields, or lifetime are invalid")]
    InvalidEnvelope,
    #[error("attestation certificate digest does not match")]
    CertificateMismatch,
    #[error("attestation trust set is invalid")]
    InvalidTrust,
    #[error("attestation signer key is unknown or ambiguous")]
    UnknownSigner,
    #[error("attestation is outside the signer or evaluation time window")]
    InvalidTime,
    #[error("attestation signature is invalid")]
    InvalidSignature,
}

impl CertificateAttestation {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = ATTESTATION_SCHEMA_VERSION.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(
            serde_json::to_vec(&UnsignedAttestation {
                schema_version: &self.schema_version,
                context: &self.context,
                certificate_sha256: &self.certificate_sha256,
                signer: &self.signer,
                key_id: &self.key_id,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
            .expect("typed attestation serialization cannot fail"),
        );
        bytes
    }
}

/// Creates a detached, domain-separated certificate attestation.
///
/// # Errors
///
/// Rejects oversized certificates, invalid identifiers, or an invalid lifetime.
pub fn attest_certificate(
    certificate_bytes: &[u8],
    context: &str,
    signer: &str,
    key_id: &str,
    issued_at: u64,
    expires_at: u64,
    signing_key: &SigningKey,
) -> Result<CertificateAttestation, AttestationError> {
    if certificate_bytes.len() > MAX_COMPATIBILITY_CERTIFICATE_BYTES
        || !valid_text(context)
        || !valid_text(signer)
        || !valid_text(key_id)
        || !valid_lifetime(issued_at, expires_at)
    {
        return Err(
            if certificate_bytes.len() > MAX_COMPATIBILITY_CERTIFICATE_BYTES {
                AttestationError::ResourceBound
            } else {
                AttestationError::InvalidEnvelope
            },
        );
    }
    parse_supported_certificate(certificate_bytes)
        .map_err(|_| AttestationError::InvalidCertificate)?;
    let mut attestation = CertificateAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION.into(),
        context: context.into(),
        certificate_sha256: hex::encode(Sha256::digest(certificate_bytes)),
        signer: signer.into(),
        key_id: key_id.into(),
        issued_at,
        expires_at,
        signature: String::new(),
    };
    attestation.signature = hex::encode(signing_key.sign(&attestation.signed_bytes()).to_bytes());
    Ok(attestation)
}

/// Verifies a detached certificate attestation against a bounded trust set.
///
/// # Errors
///
/// Rejects malformed, oversized, expired, replayed, unknown-key, or
/// cryptographically invalid evidence.
pub fn verify_attestation(
    certificate_bytes: &[u8],
    attestation_bytes: &[u8],
    trust: &AttestationTrust,
) -> Result<VerifiedAttestation, AttestationError> {
    if certificate_bytes.len() > MAX_COMPATIBILITY_CERTIFICATE_BYTES
        || attestation_bytes.len() > MAX_ATTESTATION_BYTES
    {
        return Err(AttestationError::ResourceBound);
    }
    parse_supported_certificate(certificate_bytes)
        .map_err(|_| AttestationError::InvalidCertificate)?;
    let attestation: CertificateAttestation = serde_json::from_slice(attestation_bytes)?;
    if attestation.schema_version != ATTESTATION_SCHEMA_VERSION
        || !valid_text(&attestation.context)
        || !valid_text(&attestation.signer)
        || !valid_text(&attestation.key_id)
        || !valid_digest(&attestation.certificate_sha256)
        || !valid_signature(&attestation.signature)
        || !valid_lifetime(attestation.issued_at, attestation.expires_at)
    {
        return Err(AttestationError::InvalidEnvelope);
    }
    if attestation.context != trust.context {
        return Err(AttestationError::InvalidEnvelope);
    }
    if attestation.certificate_sha256 != hex::encode(Sha256::digest(certificate_bytes)) {
        return Err(AttestationError::CertificateMismatch);
    }
    validate_trust(trust)?;
    let matches: Vec<_> = trust
        .keys
        .iter()
        .filter(|key| key.signer == attestation.signer && key.key_id == attestation.key_id)
        .collect();
    let [key] = matches.as_slice() else {
        return Err(AttestationError::UnknownSigner);
    };
    if attestation.issued_at < key.not_before
        || attestation.issued_at >= key.not_after
        || trust.evaluation_time < attestation.issued_at
        || trust.evaluation_time >= attestation.expires_at
    {
        return Err(AttestationError::InvalidTime);
    }
    let verifying_key = decode_key(&key.public_key).ok_or(AttestationError::InvalidTrust)?;
    let signature = Signature::from_slice(
        &hex::decode(&attestation.signature).map_err(|_| AttestationError::InvalidSignature)?,
    )
    .map_err(|_| AttestationError::InvalidSignature)?;
    verifying_key
        .verify_strict(&attestation.signed_bytes(), &signature)
        .map_err(|_| AttestationError::InvalidSignature)?;
    Ok(VerifiedAttestation {
        signer: attestation.signer,
        key_id: attestation.key_id,
        certificate_sha256: attestation.certificate_sha256,
    })
}

fn validate_trust(trust: &AttestationTrust) -> Result<(), AttestationError> {
    if !valid_text(&trust.context)
        || trust.keys.is_empty()
        || trust.keys.len() > MAX_ATTESTATION_KEYS
    {
        return Err(AttestationError::InvalidTrust);
    }
    let mut identities = BTreeSet::new();
    for key in &trust.keys {
        if !valid_text(&key.signer)
            || !valid_text(&key.key_id)
            || !identities.insert((&key.signer, &key.key_id))
            || key.not_before >= key.not_after
            || decode_key(&key.public_key).is_none()
        {
            return Err(AttestationError::InvalidTrust);
        }
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_lifetime(issued_at: u64, expires_at: u64) -> bool {
    issued_at < expires_at && expires_at - issued_at <= MAX_ATTESTATION_LIFETIME_SECONDS
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_signature(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_key(value: &str) -> Option<VerifyingKey> {
    if !valid_digest(value) {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(value).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_record(
        signer: &str,
        key_id: &str,
        key: &SigningKey,
        not_before: u64,
        not_after: u64,
    ) -> AttestationKey {
        AttestationKey {
            signer: signer.into(),
            key_id: key_id.into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            not_before,
            not_after,
        }
    }

    fn trust(keys: Vec<AttestationKey>, evaluation_time: u64) -> AttestationTrust {
        AttestationTrust {
            context: "telosieve/research".into(),
            evaluation_time,
            keys,
        }
    }

    #[test]
    fn rotated_signers_preserve_historical_attestations() {
        let old = SigningKey::from_bytes(&[31; 32]);
        let new = SigningKey::from_bytes(&[32; 32]);
        let keys = vec![
            key_record("evidence-lab", "2026-a", &old, 100, 300),
            key_record("evidence-lab", "2026-b", &new, 250, 900),
        ];
        let certificate = include_bytes!("../results/kubernetes-shadow-certificate.json");

        let old_attestation = attest_certificate(
            certificate,
            "telosieve/research",
            "evidence-lab",
            "2026-a",
            200,
            700,
            &old,
        )
        .unwrap();
        let old_bytes = serde_json::to_vec(&old_attestation).unwrap();
        assert_eq!(
            verify_attestation(certificate, &old_bytes, &trust(keys.clone(), 600))
                .unwrap()
                .key_id,
            "2026-a"
        );

        let new_attestation = attest_certificate(
            certificate,
            "telosieve/research",
            "evidence-lab",
            "2026-b",
            300,
            800,
            &new,
        )
        .unwrap();
        assert_eq!(
            verify_attestation(
                certificate,
                &serde_json::to_vec(&new_attestation).unwrap(),
                &trust(keys, 600),
            )
            .unwrap()
            .key_id,
            "2026-b"
        );
    }

    #[test]
    fn tamper_replay_expiry_signature_and_bounds_fail_closed() {
        let signing_key = SigningKey::from_bytes(&[33; 32]);
        let certificate = include_bytes!("../results/kubernetes-shadow-certificate.json");
        let attestation = attest_certificate(
            certificate,
            "telosieve/research",
            "evidence-lab",
            "2026-a",
            200,
            700,
            &signing_key,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&attestation).unwrap();
        let keys = vec![key_record("evidence-lab", "2026-a", &signing_key, 100, 300)];

        assert!(matches!(
            verify_attestation(b"tampered-certificate", &bytes, &trust(keys.clone(), 600)),
            Err(AttestationError::InvalidCertificate)
        ));
        let mut wrong_context = trust(keys.clone(), 600);
        wrong_context.context = "other/research".into();
        assert!(matches!(
            verify_attestation(certificate, &bytes, &wrong_context),
            Err(AttestationError::InvalidEnvelope)
        ));
        assert!(matches!(
            verify_attestation(certificate, &bytes, &trust(keys.clone(), 199)),
            Err(AttestationError::InvalidTime)
        ));
        assert!(matches!(
            verify_attestation(certificate, &bytes, &trust(keys.clone(), 700)),
            Err(AttestationError::InvalidTime)
        ));

        let mut tampered = attestation;
        let replacement = if tampered.signature.starts_with("00") {
            "01"
        } else {
            "00"
        };
        tampered.signature.replace_range(0..2, replacement);
        assert!(matches!(
            verify_attestation(
                certificate,
                &serde_json::to_vec(&tampered).unwrap(),
                &trust(keys.clone(), 600),
            ),
            Err(AttestationError::InvalidSignature)
        ));
        assert!(matches!(
            attest_certificate(
                certificate,
                "telosieve/research",
                "evidence-lab",
                "2026-a",
                0,
                MAX_ATTESTATION_LIFETIME_SECONDS + 1,
                &signing_key,
            ),
            Err(AttestationError::InvalidEnvelope)
        ));

        let mut duplicate_trust = trust(vec![keys[0].clone(), keys[0].clone()], 600);
        assert!(matches!(
            verify_attestation(certificate, &bytes, &duplicate_trust),
            Err(AttestationError::InvalidTrust)
        ));
        duplicate_trust.keys = (0..=MAX_ATTESTATION_KEYS)
            .map(|index| {
                key_record(
                    "evidence-lab",
                    &format!("key-{index}"),
                    &signing_key,
                    100,
                    300,
                )
            })
            .collect();
        assert!(matches!(
            verify_attestation(certificate, &bytes, &duplicate_trust),
            Err(AttestationError::InvalidTrust)
        ));
        assert!(matches!(
            verify_attestation(
                certificate,
                &vec![b' '; MAX_ATTESTATION_BYTES + 1],
                &trust(keys, 600),
            ),
            Err(AttestationError::ResourceBound)
        ));
    }
}
