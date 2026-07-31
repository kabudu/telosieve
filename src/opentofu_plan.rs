use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    certificate::OpenTofuRecord,
    model::{ServiceState, Values},
    protocol::VerifiedAuthorities,
};

pub const ADAPTER_VERSION: &str = "telosieve.opentofu-plan/v1";
pub const SUPPORTED_FORMAT_VERSION: &str = "1.2";
pub const MAX_PLAN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RESOURCE_CHANGES: usize = 64;
const MAX_VALUES: usize = 256;
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum OpenTofuError {
    #[error("OpenTofu plan I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("OpenTofu plan JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OpenTofu plan exceeds its byte or structural resource bound: {0}")]
    ResourceBound(String),
    #[error("OpenTofu plan contains unsupported, unknown, sensitive, or destructive changes")]
    UnsupportedChange,
    #[error("OpenTofu plan does not exactly match authenticated authority evidence")]
    AuthorityMismatch,
    #[error("OpenTofu evidence output aliases an input or another output")]
    OutputCollision,
}

#[derive(Deserialize)]
struct Plan {
    format_version: String,
    terraform_version: String,
    resource_changes: Vec<ResourceChange>,
}

#[derive(Deserialize)]
struct ResourceChange {
    address: String,
    mode: String,
    #[serde(rename = "type")]
    resource_type: String,
    change: Change,
}

#[derive(Deserialize)]
struct Change {
    actions: Vec<String>,
    before: serde_json::Value,
    after: serde_json::Value,
    #[serde(default)]
    before_sensitive: serde_json::Value,
    #[serde(default)]
    after_sensitive: serde_json::Value,
    #[serde(default)]
    after_unknown: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterInput {
    replica: String,
    values: Values,
}

/// Reads a bounded plan and maps its exact before/after inputs to authorities.
///
/// # Errors
///
/// Returns [`OpenTofuError`] for I/O, parsing, bounds, unsupported changes, or
/// authority mismatch.
pub fn read_and_validate(
    path: &Path,
    authorities: &VerifiedAuthorities,
) -> Result<OpenTofuRecord, OpenTofuError> {
    let bytes = read_bounded(path)?;
    validate_bytes(&bytes, authorities)
}

/// Reads an exact plan file within the adapter byte bound.
///
/// # Errors
///
/// Refuses I/O failure and plans exceeding the byte bound.
pub fn read_bounded(path: &Path) -> Result<Vec<u8>, OpenTofuError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len()
        > usize::try_from(MAX_PLAN_BYTES)
            .map_err(|_| OpenTofuError::ResourceBound("plan bound is unsupported".into()))?
    {
        return Err(OpenTofuError::ResourceBound(format!(
            "plan exceeds {MAX_PLAN_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Validates exact bounded plan bytes against authenticated authorities.
///
/// # Errors
///
/// Refuses excess, malformed, unsafe, unknown, sensitive, destructive, or
/// authority-mismatched plan content.
pub fn validate_bytes(
    bytes: &[u8],
    authorities: &VerifiedAuthorities,
) -> Result<OpenTofuRecord, OpenTofuError> {
    if bytes.len() > usize::try_from(MAX_PLAN_BYTES).unwrap_or(usize::MAX) {
        return Err(OpenTofuError::ResourceBound(
            "plan exceeds byte bound".into(),
        ));
    }
    let plan: Plan = serde_json::from_slice(bytes)?;
    validate_plan(&plan, authorities)?;
    Ok(OpenTofuRecord {
        adapter: ADAPTER_VERSION.into(),
        plan_sha256: hex::encode(Sha256::digest(bytes)),
        format_version: plan.format_version,
        terraform_version: plan.terraform_version,
        resource_change_count: plan.resource_changes.len(),
        observation_quorum_digest: None,
    })
}

fn validate_plan(plan: &Plan, authorities: &VerifiedAuthorities) -> Result<(), OpenTofuError> {
    if plan.format_version != SUPPORTED_FORMAT_VERSION
        || plan.terraform_version.is_empty()
        || plan.terraform_version.len() > 64
        || !plan
            .terraform_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        || plan.resource_changes.is_empty()
        || plan.resource_changes.len() > MAX_RESOURCE_CHANGES
    {
        return Err(OpenTofuError::ResourceBound(
            "invalid metadata or resource count".into(),
        ));
    }
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    for resource in &plan.resource_changes {
        if resource.address.is_empty()
            || resource.address.len() > 512
            || resource.address.chars().any(char::is_control)
            || resource.mode != "managed"
            || resource.resource_type != "terraform_data"
            || resource.change.actions != ["update"]
            || input_flagged(&resource.change.before_sensitive)
            || input_flagged(&resource.change.after_sensitive)
            || input_flagged(&resource.change.after_unknown)
        {
            return Err(OpenTofuError::UnsupportedChange);
        }
        let before_input = extract_input(&resource.change.before)?;
        let after_input = extract_input(&resource.change.after)?;
        if before_input.replica != after_input.replica
            || before
                .insert(before_input.replica, before_input.values)
                .is_some()
            || after
                .insert(after_input.replica, after_input.values)
                .is_some()
        {
            return Err(OpenTofuError::UnsupportedChange);
        }
    }
    if (ServiceState { replicas: before }) != authorities.phenotype
        || after.len() != authorities.phenotype.replicas.len()
        || after.values().any(|values| values != &authorities.goal)
    {
        return Err(OpenTofuError::AuthorityMismatch);
    }
    Ok(())
}

fn extract_input(value: &serde_json::Value) -> Result<AdapterInput, OpenTofuError> {
    let input = value.get("input").ok_or(OpenTofuError::UnsupportedChange)?;
    let input: AdapterInput =
        serde_json::from_value(input.clone()).map_err(|_| OpenTofuError::UnsupportedChange)?;
    if input.replica.is_empty()
        || input.replica.len() > 256
        || input.replica.chars().any(char::is_control)
        || input.values.len() > MAX_VALUES
        || input.values.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > MAX_TEXT_BYTES
                || value.len() > MAX_TEXT_BYTES
                || key.chars().any(char::is_control)
                || value.chars().any(char::is_control)
        })
    {
        return Err(OpenTofuError::ResourceBound(
            "adapter input exceeds structural bounds".into(),
        ));
    }
    Ok(input)
}

fn contains_true(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Array(values) => values.iter().any(contains_true),
        serde_json::Value::Object(values) => values.values().any(contains_true),
        _ => false,
    }
}

fn input_flagged(value: &serde_json::Value) -> bool {
    value.get("input").is_some_and(contains_true)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::protocol::{Scenario, verify};

    fn authorities() -> VerifiedAuthorities {
        let scenario: Scenario =
            serde_json::from_slice(include_bytes!("../scenarios/benign.json")).unwrap();
        verify(&scenario).unwrap()
    }

    fn plan_value() -> Value {
        let before = json!({"cluster/epoch": "7", "user/message": "old"});
        let after = json!({"cluster/epoch": "7", "user/message": "new"});
        let changes: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|suffix| json!({
                "address": format!("terraform_data.replica_{suffix}"),
                "mode": "managed",
                "type": "terraform_data",
                "change": {
                    "actions": ["update"],
                    "before": {"input": {"replica": format!("replica-{suffix}"), "values": before}},
                    "after": {"input": {"replica": format!("replica-{suffix}"), "values": after}},
                    "before_sensitive": {}, "after_sensitive": {}, "after_unknown": {}
                }
            }))
            .collect();
        json!({"format_version": "1.2", "terraform_version": "1.12.5", "resource_changes": changes})
    }

    fn validate(value: Value) -> Result<(), OpenTofuError> {
        validate_plan(&serde_json::from_value(value).unwrap(), &authorities())
    }

    #[test]
    fn exact_plan_maps_to_authenticated_authorities() {
        validate(plan_value()).unwrap();
    }

    #[test]
    fn unsupported_sensitive_unknown_duplicate_and_mismatched_plans_fail_closed() {
        let mut destructive = plan_value();
        destructive["resource_changes"][0]["change"]["actions"] = json!(["delete"]);
        assert!(matches!(
            validate(destructive),
            Err(OpenTofuError::UnsupportedChange)
        ));

        let mut sensitive = plan_value();
        sensitive["resource_changes"][0]["change"]["after_sensitive"] =
            json!({"input": {"values": true}});
        assert!(matches!(
            validate(sensitive),
            Err(OpenTofuError::UnsupportedChange)
        ));

        let mut unknown = plan_value();
        unknown["resource_changes"][0]["change"]["after_unknown"] =
            json!({"input": {"values": true}});
        assert!(matches!(
            validate(unknown),
            Err(OpenTofuError::UnsupportedChange)
        ));

        let mut duplicate = plan_value();
        duplicate["resource_changes"][1]["change"]["before"]["input"]["replica"] =
            json!("replica-a");
        duplicate["resource_changes"][1]["change"]["after"]["input"]["replica"] =
            json!("replica-a");
        assert!(matches!(
            validate(duplicate),
            Err(OpenTofuError::UnsupportedChange)
        ));

        let mut mismatch = plan_value();
        mismatch["resource_changes"][0]["change"]["after"]["input"]["values"]["user/message"] =
            json!("tampered");
        assert!(matches!(
            validate(mismatch),
            Err(OpenTofuError::AuthorityMismatch)
        ));

        let mut future = plan_value();
        future["format_version"] = json!("2.0");
        assert!(matches!(
            validate(future),
            Err(OpenTofuError::ResourceBound(_))
        ));
    }
}
