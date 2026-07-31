use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::ShadowRecord,
    model::{ServiceState, Values, digest},
    protocol::{Scenario, VerifiedAuthorities},
};

pub const SNAPSHOT_SCHEMA_VERSION: &str = "telosieve.kubernetes-shadow/v1";
pub const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;
const MAX_REPLICAS: usize = 64;
const MAX_VALUES_PER_REPLICA: usize = 256;
const MAX_METADATA_FIELD_BYTES: usize = 256;
const MAX_VALUE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredSnapshot {
    pub metadata: ObjectIdentity,
    pub target: ObjectIdentity,
    pub data: Values,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSnapshot {
    pub metadata: ObjectIdentity,
    pub generation: u64,
    pub observed_generation: u64,
    pub complete: bool,
    pub replicas: BTreeMap<String, Values>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesShadowSnapshot {
    pub schema_version: String,
    pub subject: String,
    pub captured_at: u64,
    pub desired: DesiredSnapshot,
    pub observed: ObservedSnapshot,
}

#[derive(Debug, Error)]
pub enum ShadowError {
    #[error("unsupported Kubernetes shadow snapshot schema")]
    Schema,
    #[error("shadow snapshot subject or capture time does not match the scenario")]
    Context,
    #[error("unsupported or invalid Kubernetes object metadata: {0}")]
    Metadata(String),
    #[error("desired target reference does not exactly match the observed object")]
    TargetMismatch,
    #[error("observed snapshot is partial or its controller generation is stale")]
    PartialOrStale,
    #[error("shadow snapshot exceeds a structural resource bound: {0}")]
    ResourceBound(String),
    #[error("exported desired or observed state does not match authenticated authority evidence")]
    AuthorityMismatch,
    #[error("shadow evidence output aliases an input or another output")]
    OutputCollision,
}

/// Validates a read-only Kubernetes export against authenticated Telosieve inputs.
///
/// # Errors
///
/// Returns [`ShadowError`] for schema, context, identity, freshness,
/// completeness, resource-bound, or authority mismatches.
pub fn validate(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
    snapshot: &KubernetesShadowSnapshot,
) -> Result<ShadowRecord, ShadowError> {
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(ShadowError::Schema);
    }
    if snapshot.subject != scenario.subject || snapshot.captured_at != scenario.evaluation_time {
        return Err(ShadowError::Context);
    }
    validate_identity(&snapshot.desired.metadata, "v1", "ConfigMap")?;
    validate_identity(&snapshot.observed.metadata, "apps/v1", "StatefulSet")?;
    validate_identity(&snapshot.desired.target, "apps/v1", "StatefulSet")?;
    if snapshot.desired.target != snapshot.observed.metadata {
        return Err(ShadowError::TargetMismatch);
    }
    if !snapshot.observed.complete
        || snapshot.observed.generation == 0
        || snapshot.observed.observed_generation != snapshot.observed.generation
    {
        return Err(ShadowError::PartialOrStale);
    }
    validate_values(&snapshot.desired.data)?;
    if snapshot.observed.replicas.is_empty() || snapshot.observed.replicas.len() > MAX_REPLICAS {
        return Err(ShadowError::ResourceBound(format!(
            "replicas must be between 1 and {MAX_REPLICAS}"
        )));
    }
    for (replica, values) in &snapshot.observed.replicas {
        validate_text(replica, "replica name")?;
        validate_values(values)?;
    }
    if snapshot.desired.data != authorities.goal
        || (ServiceState {
            replicas: snapshot.observed.replicas.clone(),
        }) != authorities.phenotype
    {
        return Err(ShadowError::AuthorityMismatch);
    }
    Ok(ShadowRecord {
        adapter: SNAPSHOT_SCHEMA_VERSION.into(),
        snapshot_digest: digest(snapshot),
        target_uid: snapshot.observed.metadata.uid.clone(),
        desired_resource_version: snapshot.desired.metadata.resource_version.clone(),
        observed_resource_version: snapshot.observed.metadata.resource_version.clone(),
        captured_at: snapshot.captured_at,
        observation_quorum_digest: None,
    })
}

fn validate_identity(
    identity: &ObjectIdentity,
    api_version: &str,
    kind: &str,
) -> Result<(), ShadowError> {
    if identity.api_version != api_version || identity.kind != kind {
        return Err(ShadowError::Metadata(format!(
            "expected {api_version} {kind}"
        )));
    }
    for (label, value) in [
        ("namespace", &identity.namespace),
        ("name", &identity.name),
        ("uid", &identity.uid),
        ("resourceVersion", &identity.resource_version),
    ] {
        validate_text(value, label)?;
    }
    Ok(())
}

fn validate_values(values: &Values) -> Result<(), ShadowError> {
    if values.len() > MAX_VALUES_PER_REPLICA {
        return Err(ShadowError::ResourceBound(format!(
            "value map exceeds {MAX_VALUES_PER_REPLICA} entries"
        )));
    }
    for (key, value) in values {
        validate_text(key, "data key")?;
        if value.is_empty() || value.len() > MAX_VALUE_BYTES {
            return Err(ShadowError::ResourceBound(format!(
                "data value must be 1..={MAX_VALUE_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), ShadowError> {
    if value.is_empty()
        || value.len() > MAX_METADATA_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ShadowError::ResourceBound(format!(
            "{label} must be 1..={MAX_METADATA_FIELD_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Scenario, verify};

    fn inputs() -> (Scenario, KubernetesShadowSnapshot) {
        (
            serde_json::from_slice(include_bytes!("../scenarios/benign.json")).unwrap(),
            serde_json::from_slice(include_bytes!("../snapshots/kubernetes-shadow-benign.json"))
                .unwrap(),
        )
    }

    #[test]
    fn exact_export_maps_to_authenticated_authorities() {
        let (scenario, snapshot) = inputs();
        let authorities = verify(&scenario).unwrap();
        let record = validate(&scenario, &authorities, &snapshot).unwrap();
        assert_eq!(record.adapter, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(record.snapshot_digest, digest(&snapshot));
        assert_eq!(record.observed_resource_version, "73");
    }

    #[test]
    fn drift_partial_stale_identity_schema_and_authority_mismatch_fail_closed() {
        let (scenario, original) = inputs();
        let authorities = verify(&scenario).unwrap();

        let mut drift = original.clone();
        drift.desired.target.resource_version = "72".into();
        assert!(matches!(
            validate(&scenario, &authorities, &drift),
            Err(ShadowError::TargetMismatch)
        ));

        let mut partial = original.clone();
        partial.observed.complete = false;
        assert!(matches!(
            validate(&scenario, &authorities, &partial),
            Err(ShadowError::PartialOrStale)
        ));

        let mut stale = original.clone();
        stale.observed.observed_generation -= 1;
        assert!(matches!(
            validate(&scenario, &authorities, &stale),
            Err(ShadowError::PartialOrStale)
        ));

        let mut identity = original.clone();
        identity.observed.metadata.uid = "replacement-uid".into();
        assert!(matches!(
            validate(&scenario, &authorities, &identity),
            Err(ShadowError::TargetMismatch)
        ));

        let mut schema = original.clone();
        schema.schema_version = "unknown/v9".into();
        assert!(matches!(
            validate(&scenario, &authorities, &schema),
            Err(ShadowError::Schema)
        ));

        let mut authority = original;
        authority
            .observed
            .replicas
            .get_mut("replica-a")
            .unwrap()
            .insert("user/message".into(), "untrusted".into());
        assert!(matches!(
            validate(&scenario, &authorities, &authority),
            Err(ShadowError::AuthorityMismatch)
        ));
    }

    #[test]
    fn capture_context_and_structural_bounds_fail_closed() {
        let (scenario, original) = inputs();
        let authorities = verify(&scenario).unwrap();

        let mut context = original.clone();
        context.captured_at -= 1;
        assert!(matches!(
            validate(&scenario, &authorities, &context),
            Err(ShadowError::Context)
        ));

        let mut empty_version = original.clone();
        empty_version.observed.metadata.resource_version.clear();
        assert!(matches!(
            validate(&scenario, &authorities, &empty_version),
            Err(ShadowError::ResourceBound(_))
        ));

        let mut replicas = original;
        for index in 0..=MAX_REPLICAS {
            replicas
                .observed
                .replicas
                .insert(format!("extra-{index}"), BTreeMap::new());
        }
        assert!(matches!(
            validate(&scenario, &authorities, &replicas),
            Err(ShadowError::ResourceBound(_))
        ));
    }
}
