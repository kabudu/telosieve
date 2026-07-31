use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "telosieve.private-bundle-signature/v1";
pub const MAX_BUNDLE_BYTES: usize = 160 * 1024 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
pub const MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub schema_version: String,
    pub context: String,
    pub bundle_sha256: String,
    pub signer: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Serialize)]
struct Unsigned<'a> {
    schema_version: &'a str,
    context: &'a str,
    bundle_sha256: &'a str,
    signer: &'a str,
    key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleKey {
    pub signer: String,
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleTrust {
    pub context: String,
    pub evaluation_time: u64,
    pub keys: Vec<BundleKey>,
}

#[derive(Debug, Error)]
pub enum BundleSignatureError {
    #[error("bundle or signature exceeds its input bound")]
    ResourceBound,
    #[error("bundle signature JSON is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("bundle signature envelope is invalid")]
    InvalidEnvelope,
    #[error("bundle digest does not match the signature")]
    BundleMismatch,
    #[error("bundle trust is invalid")]
    InvalidTrust,
    #[error("bundle signer key is unknown or ambiguous")]
    UnknownSigner,
    #[error("bundle signature is outside the signer or evaluation time window")]
    InvalidTime,
    #[error("bundle signature is invalid")]
    InvalidSignature,
}

impl BundleSignature {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = SCHEMA_VERSION.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(
            serde_json::to_vec(&Unsigned {
                schema_version: &self.schema_version,
                context: &self.context,
                bundle_sha256: &self.bundle_sha256,
                signer: &self.signer,
                key_id: &self.key_id,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            })
            .expect("typed bundle signature serialization cannot fail"),
        );
        bytes
    }
}

/// Signs the exact bundle bytes with a bounded, domain-separated envelope.
///
/// # Errors
///
/// Refuses oversized bundles, invalid identifiers, and invalid lifetimes.
pub fn sign_bundle(
    bundle: &[u8],
    context: &str,
    signer: &str,
    key_id: &str,
    issued_at: u64,
    expires_at: u64,
    key: &SigningKey,
) -> Result<BundleSignature, BundleSignatureError> {
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(BundleSignatureError::ResourceBound);
    }
    if !valid_text(context)
        || !valid_text(signer)
        || !valid_text(key_id)
        || issued_at >= expires_at
        || expires_at - issued_at > MAX_LIFETIME_SECONDS
    {
        return Err(BundleSignatureError::InvalidEnvelope);
    }
    let mut value = BundleSignature {
        schema_version: SCHEMA_VERSION.into(),
        context: context.into(),
        bundle_sha256: hex::encode(Sha256::digest(bundle)),
        signer: signer.into(),
        key_id: key_id.into(),
        issued_at,
        expires_at,
        signature: String::new(),
    };
    value.signature = hex::encode(key.sign(&value.signed_bytes()).to_bytes());
    Ok(value)
}

/// Verifies exact bundle bytes against independently supplied bounded trust.
///
/// # Errors
///
/// Refuses malformed, oversized, mismatched, untrusted, untimely, or invalid
/// signature evidence.
pub fn verify_bundle(
    bundle: &[u8],
    signature_bytes: &[u8],
    trust: &BundleTrust,
) -> Result<BundleSignature, BundleSignatureError> {
    if bundle.len() > MAX_BUNDLE_BYTES || signature_bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(BundleSignatureError::ResourceBound);
    }
    let value: BundleSignature = serde_json::from_slice(signature_bytes)?;
    if value.schema_version != SCHEMA_VERSION
        || !valid_text(&value.context)
        || !valid_text(&value.signer)
        || !valid_text(&value.key_id)
        || !canonical_hex(&value.bundle_sha256, 32)
        || !canonical_hex(&value.signature, 64)
        || value.issued_at >= value.expires_at
        || value.expires_at - value.issued_at > MAX_LIFETIME_SECONDS
    {
        return Err(BundleSignatureError::InvalidEnvelope);
    }
    if value.context != trust.context || value.bundle_sha256 != hex::encode(Sha256::digest(bundle))
    {
        return Err(BundleSignatureError::BundleMismatch);
    }
    if trust.keys.is_empty()
        || trust.keys.len() > 8
        || !valid_text(&trust.context)
        || trust.keys.iter().any(|key| {
            !valid_text(&key.signer)
                || !valid_text(&key.key_id)
                || key.not_before > key.not_after
                || !canonical_hex(&key.public_key, 32)
        })
    {
        return Err(BundleSignatureError::InvalidTrust);
    }
    let matches: Vec<_> = trust
        .keys
        .iter()
        .filter(|key| key.signer == value.signer && key.key_id == value.key_id)
        .collect();
    if matches.len() != 1 {
        return Err(BundleSignatureError::UnknownSigner);
    }
    let key = matches[0];
    if key.not_before > key.not_after
        || value.issued_at < key.not_before
        || value.expires_at > key.not_after
        || trust.evaluation_time < value.issued_at
        || trust.evaluation_time > value.expires_at
    {
        return Err(BundleSignatureError::InvalidTime);
    }
    let public: [u8; 32] = hex::decode(&key.public_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(BundleSignatureError::InvalidTrust)?;
    let verifying =
        VerifyingKey::from_bytes(&public).map_err(|_| BundleSignatureError::InvalidTrust)?;
    let signature: [u8; 64] = hex::decode(&value.signature)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(BundleSignatureError::InvalidSignature)?;
    verifying
        .verify_strict(&value.signed_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| BundleSignatureError::InvalidSignature)?;
    Ok(value)
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
    #[test]
    fn exact_signature_verifies_and_tamper_time_key_and_metadata_refuse() {
        let key = SigningKey::from_bytes(&[91; 32]);
        let bundle = b"exact private bundle";
        let signature = sign_bundle(
            bundle,
            "telosieve/private-evaluation",
            "release-lab",
            "key-a",
            100,
            200,
            &key,
        )
        .unwrap();
        let trust = BundleTrust {
            context: "telosieve/private-evaluation".into(),
            evaluation_time: 150,
            keys: vec![BundleKey {
                signer: "release-lab".into(),
                key_id: "key-a".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
                not_before: 50,
                not_after: 250,
            }],
        };
        let bytes = serde_json::to_vec(&signature).unwrap();
        assert_eq!(verify_bundle(bundle, &bytes, &trust).unwrap(), signature);
        assert!(verify_bundle(b"tampered", &bytes, &trust).is_err());
        let mut expired = trust.clone();
        expired.evaluation_time = 201;
        assert!(verify_bundle(bundle, &bytes, &expired).is_err());
        let mut wrong = trust.clone();
        wrong.keys[0].public_key = hex::encode([92; 32]);
        assert!(verify_bundle(bundle, &bytes, &wrong).is_err());
        let mut altered = signature;
        altered.context = "telosieve/other".into();
        assert!(verify_bundle(bundle, &serde_json::to_vec(&altered).unwrap(), &trust).is_err());

        let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        unknown["unknown"] = true.into();
        assert!(verify_bundle(bundle, &serde_json::to_vec(&unknown).unwrap(), &trust).is_err());
        let mut noncanonical = trust.clone();
        noncanonical.keys[0].public_key.make_ascii_uppercase();
        assert!(verify_bundle(bundle, &bytes, &noncanonical).is_err());
        let mut ambiguous = trust.clone();
        ambiguous.keys.push(ambiguous.keys[0].clone());
        assert!(verify_bundle(bundle, &bytes, &ambiguous).is_err());
        assert!(matches!(
            verify_bundle(bundle, &vec![b' '; MAX_SIGNATURE_BYTES + 1], &trust),
            Err(BundleSignatureError::ResourceBound)
        ));
    }
}
