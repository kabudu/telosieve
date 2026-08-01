use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    checker::CheckerVerdict,
    model::{ServiceState, Transition},
    protocol::{AuthorityKind, HistoryAnchor},
};

pub const CERTIFICATE_VERSION_V7: &str = "telosieve.certificate/v7";
pub const CERTIFICATE_VERSION_V8: &str = "telosieve.certificate/v8";
pub const CERTIFICATE_VERSION_V9: &str = "telosieve.certificate/v9";
pub const CERTIFICATE_VERSION_V10: &str = "telosieve.certificate/v10";
pub const CERTIFICATE_VERSION_V11: &str = "telosieve.certificate/v11";
pub const MAX_COMPATIBILITY_CERTIFICATE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CertificateCompatibilityError {
    #[error("certificate exceeds the compatibility input bound")]
    ResourceBound,
    #[error("certificate JSON is malformed or contains unknown fields: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported certificate version: {0}")]
    UnsupportedVersion(String),
    #[error("certificate extensions do not match {0}")]
    InvalidVersionShape(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Applied,
    Refused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HypothesisRecord {
    pub suspected: Vec<AuthorityKind>,
    pub excluded: Vec<AuthorityKind>,
    pub suspected_issuers: Vec<String>,
    pub excluded_issuers: Vec<String>,
    pub suspected_fault_domains: Vec<String>,
    pub excluded_fault_domains: Vec<String>,
    pub authorized_deletions: Vec<String>,
    pub proposed_transition: Option<Transition>,
    pub checker: Option<CheckerVerdict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub hypothesis_count: usize,
    pub unsafe_approvals: usize,
    pub false_refusals: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRecord {
    pub name: String,
    pub decision: Decision,
    pub transition: Option<Transition>,
    pub checker: Option<CheckerVerdict>,
    pub unsafe_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuationRecord {
    pub adapter: String,
    pub operation_digest: String,
    pub before_digest: String,
    pub after_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowRecord {
    pub adapter: String,
    pub snapshot_digest: String,
    pub target_uid: String,
    pub desired_resource_version: String,
    pub observed_resource_version: String,
    pub captured_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_quorum_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuRecord {
    pub adapter: String,
    pub plan_sha256: String,
    pub format_version: String,
    pub terraform_version: String,
    pub resource_change_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_quorum_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRecord {
    pub contract: String,
    pub integration_id: String,
    pub resource_kind: String,
    pub target_id: String,
    pub target_revision: String,
    pub response_sha256: String,
    pub observation_quorum_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub certificate_version: String,
    pub scenario_id: String,
    pub seed: u64,
    pub authority_digests: BTreeMap<String, String>,
    pub deletion_authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actuation: Option<ActuationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<ShadowRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opentofu: Option<OpenTofuRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration: Option<IntegrationRecord>,
    pub phenotype_history_anchor: HistoryAnchor,
    pub hypotheses: Vec<HypothesisRecord>,
    pub decision: Decision,
    pub refusal_reason: Option<String>,
    pub transition: Option<Transition>,
    pub rollback: Option<Transition>,
    pub final_state: ServiceState,
    pub baselines: Vec<BaselineRecord>,
    pub metrics: Metrics,
}

/// Parses a retained certificate through the supported compatibility boundary.
///
/// Versions 7–11 share one additive serialized shape. Their extension fields
/// remain version-specific so an artifact cannot be relabelled across execution
/// modes.
///
/// # Errors
///
/// Rejects oversized, malformed, unknown-version, or cross-version artifacts.
pub fn parse_supported_certificate(
    bytes: &[u8],
) -> Result<Certificate, CertificateCompatibilityError> {
    if bytes.len() > MAX_COMPATIBILITY_CERTIFICATE_BYTES {
        return Err(CertificateCompatibilityError::ResourceBound);
    }
    let certificate: Certificate = serde_json::from_slice(bytes)?;
    let valid_shape = match certificate.certificate_version.as_str() {
        CERTIFICATE_VERSION_V7 => {
            certificate.actuation.is_none()
                && certificate.shadow.is_none()
                && certificate.opentofu.is_none()
                && certificate.integration.is_none()
        }
        CERTIFICATE_VERSION_V8 => {
            certificate.actuation.is_some()
                && certificate.shadow.is_none()
                && certificate.opentofu.is_none()
                && certificate.integration.is_none()
        }
        CERTIFICATE_VERSION_V9 => {
            certificate.actuation.is_none()
                && certificate.shadow.as_ref().is_some_and(valid_shadow_record)
                && certificate.opentofu.is_none()
                && certificate.integration.is_none()
        }
        CERTIFICATE_VERSION_V10 => {
            certificate.actuation.is_none()
                && certificate.shadow.is_none()
                && certificate.integration.is_none()
                && certificate
                    .opentofu
                    .as_ref()
                    .is_some_and(valid_opentofu_record)
        }
        CERTIFICATE_VERSION_V11 => {
            certificate.actuation.is_none()
                && certificate.shadow.is_none()
                && certificate.opentofu.is_none()
                && certificate
                    .integration
                    .as_ref()
                    .is_some_and(valid_integration_record)
        }
        version => {
            return Err(CertificateCompatibilityError::UnsupportedVersion(
                version.into(),
            ));
        }
    };
    if !valid_shape {
        return Err(CertificateCompatibilityError::InvalidVersionShape(
            certificate.certificate_version.clone(),
        ));
    }
    Ok(certificate)
}

fn valid_integration_record(record: &IntegrationRecord) -> bool {
    record.contract == "telosieve.integration-contract/v1"
        && valid_integration_text(&record.integration_id)
        && valid_integration_text(&record.resource_kind)
        && valid_integration_text(&record.target_id)
        && valid_integration_text(&record.target_revision)
        && canonical_digest(&record.response_sha256)
        && canonical_digest(&record.observation_quorum_digest)
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_integration_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_shadow_record(record: &ShadowRecord) -> bool {
    record.adapter == "telosieve.kubernetes-shadow/v1"
        && record
            .observation_quorum_digest
            .as_ref()
            .is_none_or(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn valid_opentofu_record(record: &OpenTofuRecord) -> bool {
    record.adapter == "telosieve.opentofu-plan/v1"
        && record.plan_sha256.len() == 64
        && record
            .plan_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && record.format_version == "1.2"
        && valid_version_text(&record.terraform_version)
        && (1..=64).contains(&record.resource_change_count)
        && record
            .observation_quorum_digest
            .as_ref()
            .is_none_or(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn valid_version_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}
