use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    kubernetes_shadow::{
        DesiredSnapshot, KubernetesShadowSnapshot, ObjectIdentity, ObservedSnapshot,
        SNAPSHOT_SCHEMA_VERSION,
    },
    model::Values,
    protocol::Scenario,
};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const VALUES_ANNOTATION: &str = "telosieve.io/values";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveKubernetesConfig {
    pub kubectl_path: String,
    pub kubeconfig_path: String,
    pub context: String,
    pub namespace: String,
    pub desired_config_map: String,
    pub observed_stateful_set: String,
}

#[derive(Debug, Error)]
pub enum LiveError {
    #[error("live Kubernetes configuration is invalid: {0}")]
    Configuration(String),
    #[error("kubectl process failed: {0}")]
    Process(String),
    #[error("kubectl response JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("live Kubernetes observation is invalid: {0}")]
    Observation(String),
    #[error("live Kubernetes object changed during collection")]
    Drift,
    #[error("live Kubernetes I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    name: String,
    namespace: String,
    uid: String,
    resource_version: String,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
    #[serde(default)]
    owner_references: Vec<OwnerReference>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct OwnerReference {
    api_version: String,
    kind: String,
    name: String,
    uid: String,
    #[serde(default)]
    controller: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigMap {
    api_version: String,
    kind: String,
    metadata: Metadata,
    #[serde(default)]
    data: Values,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct StatefulSet {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: StatefulSetSpec,
    status: StatefulSetStatus,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct StatefulSetSpec {
    replicas: u64,
    selector: Selector,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Selector {
    match_labels: BTreeMap<String, String>,
    #[serde(default)]
    match_expressions: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct StatefulSetStatus {
    observed_generation: u64,
    ready_replicas: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodList {
    api_version: String,
    kind: String,
    items: Vec<Pod>,
}

#[derive(Debug, Deserialize)]
struct Pod {
    metadata: Metadata,
    status: PodStatus,
}

#[derive(Debug, Deserialize)]
struct PodStatus {
    #[serde(default)]
    conditions: Vec<PodCondition>,
}

#[derive(Debug, Deserialize)]
struct PodCondition {
    #[serde(rename = "type")]
    condition_type: String,
    status: String,
}

/// Collects one coherent, bounded read-only Kubernetes observation.
///
/// # Errors
///
/// Returns [`LiveError`] for invalid configuration, process failure or timeout,
/// malformed or oversized responses, incoherent reads, or unsafe object state.
pub fn collect(
    scenario: &Scenario,
    config: &LiveKubernetesConfig,
) -> Result<KubernetesShadowSnapshot, LiveError> {
    let kubectl = absolute_regular_file(&config.kubectl_path, "kubectl_path")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&kubectl)?.permissions().mode() & 0o111 == 0 {
            return Err(LiveError::Configuration(
                "kubectl_path is not executable".into(),
            ));
        }
    }
    let kubeconfig = absolute_regular_file(&config.kubeconfig_path, "kubeconfig_path")?;
    validate_name(&config.namespace, "namespace")?;
    validate_name(&config.desired_config_map, "desired_config_map")?;
    validate_name(&config.observed_stateful_set, "observed_stateful_set")?;
    validate_text(&config.context, "context")?;

    let common = [
        format!("--kubeconfig={}", kubeconfig.display()),
        format!("--context={}", config.context),
        format!("--namespace={}", config.namespace),
    ];
    let desired: ConfigMap = get(
        &kubectl,
        &common,
        &["get", "configmap", &config.desired_config_map, "-o", "json"],
    )?;
    let before: StatefulSet = get(
        &kubectl,
        &common,
        &[
            "get",
            "statefulset",
            &config.observed_stateful_set,
            "-o",
            "json",
        ],
    )?;
    validate_controller(&before, config)?;
    if !before.spec.selector.match_expressions.is_empty() {
        return Err(LiveError::Observation(
            "matchExpressions selectors are not supported".into(),
        ));
    }
    let selector = selector_argument(&before.spec.selector.match_labels)?;
    let pods: PodList = get(&kubectl, &common, &["get", "pods", &selector, "-o", "json"])?;
    let after: StatefulSet = get(
        &kubectl,
        &common,
        &[
            "get",
            "statefulset",
            &config.observed_stateful_set,
            "-o",
            "json",
        ],
    )?;
    if before != after {
        return Err(LiveError::Drift);
    }
    validate_desired(&desired, config)?;
    let desired_data = desired_values(&desired)?;
    validate_pods(&pods, &before)?;

    let mut replicas = BTreeMap::new();
    for pod in pods.items {
        let encoded = pod
            .metadata
            .annotations
            .get(VALUES_ANNOTATION)
            .ok_or_else(|| {
                LiveError::Observation(format!(
                    "pod {} lacks {VALUES_ANNOTATION}",
                    pod.metadata.name
                ))
            })?;
        replicas.insert(pod.metadata.name, serde_json::from_str(encoded)?);
    }
    Ok(KubernetesShadowSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION.into(),
        subject: scenario.subject.clone(),
        captured_at: scenario.evaluation_time,
        desired: DesiredSnapshot {
            metadata: identity(&desired.api_version, &desired.kind, &desired.metadata),
            target: identity(&before.api_version, &before.kind, &before.metadata),
            data: desired_data,
        },
        observed: ObservedSnapshot {
            metadata: identity(&before.api_version, &before.kind, &before.metadata),
            generation: before.metadata.generation.unwrap_or(0),
            observed_generation: before.status.observed_generation,
            complete: true,
            replicas,
        },
    })
}

fn get<T: for<'de> Deserialize<'de>>(
    executable: &Path,
    common: &[String; 3],
    operation: &[&str],
) -> Result<T, LiveError> {
    let mut child = Command::new(executable)
        .args(common)
        .args(operation)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| LiveError::Process("stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| LiveError::Process("stderr unavailable".into()))?;
    let out = thread::spawn(move || bounded_read(stdout, MAX_RESPONSE_BYTES));
    let err = thread::spawn(move || bounded_read(stderr, MAX_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            return Err(LiveError::Process("timed out after 5 seconds".into()));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = out
        .join()
        .map_err(|_| LiveError::Process("stdout reader failed".into()))??;
    let stderr = err
        .join()
        .map_err(|_| LiveError::Process("stderr reader failed".into()))??;
    if !status.success() {
        return Err(LiveError::Process(
            String::from_utf8_lossy(&stderr).into_owned(),
        ));
    }
    Ok(serde_json::from_slice(&stdout)?)
}

fn bounded_read(input: impl Read, maximum: usize) -> Result<Vec<u8>, LiveError> {
    let mut bytes = Vec::new();
    input
        .take(u64::try_from(maximum).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(LiveError::Process(format!(
            "response exceeds {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn absolute_regular_file(value: &str, field: &str) -> Result<PathBuf, LiveError> {
    let path = Path::new(value);
    if !path.is_absolute() || value.len() > 4096 || !fs::metadata(path).is_ok_and(|m| m.is_file()) {
        return Err(LiveError::Configuration(format!(
            "{field} must name an absolute regular file"
        )));
    }
    Ok(path.to_path_buf())
}

fn validate_controller(
    value: &StatefulSet,
    config: &LiveKubernetesConfig,
) -> Result<(), LiveError> {
    if value.api_version != "apps/v1"
        || value.kind != "StatefulSet"
        || value.metadata.namespace != config.namespace
        || value.metadata.name != config.observed_stateful_set
        || value.metadata.generation.unwrap_or(0) == 0
        || value.spec.replicas == 0
        || value.spec.replicas > 64
        || value.status.ready_replicas != value.spec.replicas
        || value.status.observed_generation != value.metadata.generation.unwrap_or(0)
    {
        return Err(LiveError::Observation(
            "StatefulSet identity, readiness, or generation is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_desired(value: &ConfigMap, config: &LiveKubernetesConfig) -> Result<(), LiveError> {
    if value.api_version != "v1"
        || value.kind != "ConfigMap"
        || value.metadata.namespace != config.namespace
        || value.metadata.name != config.desired_config_map
    {
        return Err(LiveError::Observation(
            "ConfigMap identity is invalid".into(),
        ));
    }
    Ok(())
}

fn desired_values(value: &ConfigMap) -> Result<Values, LiveError> {
    let Some(encoded) = value.metadata.annotations.get(VALUES_ANNOTATION) else {
        return Ok(value.data.clone());
    };
    let annotated: Values = serde_json::from_str(encoded)?;
    if !value.data.is_empty() && value.data != annotated {
        return Err(LiveError::Observation(
            "ConfigMap data and telosieve.io/values disagree".into(),
        ));
    }
    Ok(annotated)
}

fn validate_pods(value: &PodList, controller: &StatefulSet) -> Result<(), LiveError> {
    if value.api_version != "v1"
        || !matches!(value.kind.as_str(), "List" | "PodList")
        || value.items.len() != usize::try_from(controller.spec.replicas).unwrap_or(usize::MAX)
    {
        return Err(LiveError::Observation(format!(
            "pod list is incomplete: apiVersion={} kind={} items={} replicas={}",
            value.api_version,
            value.kind,
            value.items.len(),
            controller.spec.replicas
        )));
    }
    for pod in &value.items {
        let owner = pod.metadata.owner_references.iter().any(|owner| {
            owner.api_version == "apps/v1"
                && owner.kind == "StatefulSet"
                && owner.controller
                && owner.name == controller.metadata.name
                && owner.uid == controller.metadata.uid
        });
        let ready = pod
            .status
            .conditions
            .iter()
            .any(|condition| condition.condition_type == "Ready" && condition.status == "True");
        if pod.metadata.namespace != controller.metadata.namespace || !owner || !ready {
            return Err(LiveError::Observation(format!(
                "pod {} is not ready or owned by the target",
                pod.metadata.name
            )));
        }
    }
    Ok(())
}

fn selector_argument(labels: &BTreeMap<String, String>) -> Result<String, LiveError> {
    if labels.is_empty() || labels.len() > 16 {
        return Err(LiveError::Observation(
            "selector must contain 1..=16 labels".into(),
        ));
    }
    for (key, value) in labels {
        validate_text(key, "selector key")?;
        validate_text(value, "selector value")?;
        let safe_key = key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
            && key.matches('/').count() <= 1;
        let safe_value = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
        if !safe_key || !safe_value {
            return Err(LiveError::Observation(
                "selector contains unsupported characters".into(),
            ));
        }
    }
    Ok(format!(
        "--selector={}",
        labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",")
    ))
}

fn identity(api_version: &str, kind: &str, metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        api_version: api_version.into(),
        kind: kind.into(),
        namespace: metadata.namespace.clone(),
        name: metadata.name.clone(),
        uid: metadata.uid.clone(),
        resource_version: metadata.resource_version.clone(),
    }
}

fn validate_name(value: &str, field: &str) -> Result<(), LiveError> {
    validate_text(value, field)?;
    if value.len() > 253
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(LiveError::Configuration(format!(
            "{field} is not a bounded Kubernetes name"
        )));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), LiveError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(LiveError::Configuration(format!(
            "{field} must be 1..=256 non-control bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod desired_tests {
    use super::*;

    fn config_map(data: &Values, annotation: Option<&str>) -> ConfigMap {
        let annotations = annotation
            .map(|value| BTreeMap::from([(VALUES_ANNOTATION.to_string(), value.to_string())]))
            .unwrap_or_default();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {
                "name": "repair-goal", "namespace": "telosieve-research",
                "uid": "uid", "resourceVersion": "1",
                "annotations": annotations
            },
            "data": data
        }))
        .unwrap()
    }

    #[test]
    fn desired_annotation_supports_kubernetes_illegal_keys_and_refuses_ambiguity() {
        let values = BTreeMap::from([("user/message".into(), "new".into())]);
        let encoded = serde_json::to_string(&values).unwrap();
        assert_eq!(
            desired_values(&config_map(&Values::new(), Some(&encoded))).unwrap(),
            values
        );
        let legacy = BTreeMap::from([("message".into(), "new".into())]);
        assert_eq!(desired_values(&config_map(&legacy, None)).unwrap(), legacy);
        assert!(desired_values(&config_map(&legacy, Some(&encoded))).is_err());
    }
}
