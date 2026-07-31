use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::Decision,
    engine::{
        RunError, certificate_temporary_path, read_scenario,
        run_kubernetes_shadow_file_corroborated, run_kubernetes_shadow_snapshot_corroborated,
        run_opentofu_plan_file,
    },
    kubernetes_live::{LiveError, LiveKubernetesConfig},
    model::digest,
};

pub const CONFIG_SCHEMA_VERSION: &str = "telosieve.evaluation-config/v4";
pub const LIVE_CONFIG_SCHEMA_VERSION: &str = "telosieve.evaluation-config/v5";
pub const OPENTOFU_CONFIG_SCHEMA_VERSION: &str = "telosieve.evaluation-config/v3";
pub const REPORT_SCHEMA_VERSION: &str = "telosieve.evaluation-report/v1";
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const KUBERNETES_SHADOW_MODE: &str = "kubernetes-shadow";

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct EvaluationCapability {
    pub configuration_schema: &'static str,
    pub mode: &'static str,
    pub target_mutated: bool,
}

pub const SUPPORTED_EVALUATION_CAPABILITIES: &[EvaluationCapability] = &[
    EvaluationCapability {
        configuration_schema: OPENTOFU_CONFIG_SCHEMA_VERSION,
        mode: "opentofu-plan",
        target_mutated: false,
    },
    EvaluationCapability {
        configuration_schema: CONFIG_SCHEMA_VERSION,
        mode: KUBERNETES_SHADOW_MODE,
        target_mutated: false,
    },
    EvaluationCapability {
        configuration_schema: LIVE_CONFIG_SCHEMA_VERSION,
        mode: "kubernetes-live",
        target_mutated: false,
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationConfigV4 {
    schema_version: String,
    mode: String,
    scenario_path: String,
    snapshot_path: String,
    observation_trust_path: String,
    observation_quorum_path: String,
    certificate_path: String,
    ledger_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationConfigV5 {
    schema_version: String,
    mode: String,
    scenario_path: String,
    certificate_path: String,
    ledger_path: String,
    kubernetes: LiveKubernetesConfig,
    observation_trust_path: String,
    observation_sources: Vec<crate::observation_source::ObservationSourceConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationConfigV3 {
    schema_version: String,
    mode: String,
    scenario_path: String,
    plan_path: String,
    certificate_path: String,
    ledger_path: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct EvaluationReport {
    pub schema_version: &'static str,
    pub configuration_schema: &'static str,
    pub mode: &'static str,
    pub scenario_id: String,
    pub decision: Decision,
    pub certificate_digest: String,
    pub target_mutated: bool,
}

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("evaluation configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("evaluation configuration JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evaluation configuration exceeds {MAX_CONFIG_BYTES} bytes")]
    ConfigTooLarge,
    #[error("unsupported evaluation configuration schema")]
    Schema,
    #[error("unsupported evaluation mode")]
    Mode,
    #[error("evaluation configuration path is invalid: {0}")]
    Path(String),
    #[error("evaluation evidence output aliases the configuration")]
    ConfigOutputCollision,
    #[error("evaluation failed: {0}")]
    Run(#[from] RunError),
    #[error("live Kubernetes collection failed: {0}")]
    Live(#[from] LiveError),
    #[error("external observation source failed: {0}")]
    ObservationSource(#[from] crate::observation_source::ObservationSourceError),
}

/// Runs the stable read-only evaluation boundary from a bounded configuration.
///
/// Relative paths are resolved against the canonical configuration directory.
/// The target system is never mutated; only certificate and ledger evidence are
/// written.
///
/// # Errors
///
/// Returns [`EvaluationError`] before platform input reads when configuration
/// schema, mode, size, paths, or output separation are invalid. Evaluation,
/// verification, checker, and evidence-persistence errors also fail closed.
pub fn run_config_file(config_path: &Path) -> Result<EvaluationReport, EvaluationError> {
    let canonical_config = fs::canonicalize(config_path)?;
    let mut bytes = Vec::new();
    fs::File::open(&canonical_config)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len()
        > usize::try_from(MAX_CONFIG_BYTES)
            .map_err(|_| EvaluationError::Path("configuration bound is unsupported".into()))?
    {
        return Err(EvaluationError::ConfigTooLarge);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let schema = value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or(EvaluationError::Schema)?;
    let capability = SUPPORTED_EVALUATION_CAPABILITIES
        .iter()
        .find(|capability| capability.configuration_schema == schema)
        .ok_or(EvaluationError::Schema)?;
    if capability.target_mutated {
        return Err(EvaluationError::Mode);
    }
    let schema = capability.configuration_schema;
    let base = canonical_config
        .parent()
        .ok_or_else(|| EvaluationError::Path("configuration has no parent directory".into()))?;
    if schema == CONFIG_SCHEMA_VERSION {
        return run_shadow_config(value, base, &canonical_config, capability);
    }
    if schema == OPENTOFU_CONFIG_SCHEMA_VERSION {
        let config: EvaluationConfigV3 = serde_json::from_value(value)?;
        if config.schema_version != OPENTOFU_CONFIG_SCHEMA_VERSION {
            return Err(EvaluationError::Schema);
        }
        if config.mode != capability.mode {
            return Err(EvaluationError::Mode);
        }
        let scenario = resolve_path(base, &config.scenario_path, "scenario_path")?;
        let plan = resolve_path(base, &config.plan_path, "plan_path")?;
        let certificate = resolve_path(base, &config.certificate_path, "certificate_path")?;
        let ledger = resolve_path(base, &config.ledger_path, "ledger_path")?;
        reject_config_collision(&canonical_config, &certificate, &ledger)?;
        let certificate_value = run_opentofu_plan_file(&scenario, &plan, &certificate, &ledger)?;
        return Ok(report(
            capability.configuration_schema,
            capability.mode,
            &certificate_value,
        ));
    }
    if schema != LIVE_CONFIG_SCHEMA_VERSION {
        return Err(EvaluationError::Schema);
    }
    run_live_config(value, base, &canonical_config, capability)
}

fn run_live_config(
    value: serde_json::Value,
    base: &Path,
    canonical_config: &Path,
    capability: &EvaluationCapability,
) -> Result<EvaluationReport, EvaluationError> {
    let config: EvaluationConfigV5 = serde_json::from_value(value)?;
    if config.schema_version != LIVE_CONFIG_SCHEMA_VERSION {
        return Err(EvaluationError::Schema);
    }
    if config.mode != capability.mode {
        return Err(EvaluationError::Mode);
    }
    let scenario = resolve_path(base, &config.scenario_path, "scenario_path")?;
    let certificate = resolve_path(base, &config.certificate_path, "certificate_path")?;
    let ledger = resolve_path(base, &config.ledger_path, "ledger_path")?;
    let trust = resolve_path(
        base,
        &config.observation_trust_path,
        "observation_trust_path",
    )?;
    reject_config_collision(canonical_config, &certificate, &ledger)?;
    let source_executables = config
        .observation_sources
        .iter()
        .map(|source| Path::new(&source.executable_path))
        .collect::<Vec<_>>();
    reject_live_path_collisions(
        &scenario,
        Path::new(&config.kubernetes.kubectl_path),
        Path::new(&config.kubernetes.kubeconfig_path),
        &trust,
        &source_executables,
        &certificate,
        &ledger,
    )?;
    let scenario_value = read_scenario(&scenario)?;
    let snapshot = crate::kubernetes_live::collect(&scenario_value, &config.kubernetes)?;
    let trust_bytes = crate::observation_source::read_trust(&trust)?;
    let verified = crate::observation_source::corroborate(
        &snapshot,
        &scenario_value.subject,
        "kubernetes-live",
        &trust_bytes,
        &config.observation_sources,
    )?;
    let certificate_value = run_kubernetes_shadow_snapshot_corroborated(
        &scenario_value,
        &snapshot,
        verified.evidence_digest,
        &certificate,
        &ledger,
    )?;
    Ok(report(
        capability.configuration_schema,
        capability.mode,
        &certificate_value,
    ))
}

fn run_shadow_config(
    value: serde_json::Value,
    base: &Path,
    canonical_config: &Path,
    capability: &EvaluationCapability,
) -> Result<EvaluationReport, EvaluationError> {
    let config: EvaluationConfigV4 = serde_json::from_value(value)?;
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(EvaluationError::Schema);
    }
    if config.mode != capability.mode {
        return Err(EvaluationError::Mode);
    }
    let scenario = resolve_path(base, &config.scenario_path, "scenario_path")?;
    let snapshot = resolve_path(base, &config.snapshot_path, "snapshot_path")?;
    let trust = resolve_path(
        base,
        &config.observation_trust_path,
        "observation_trust_path",
    )?;
    let quorum = resolve_path(
        base,
        &config.observation_quorum_path,
        "observation_quorum_path",
    )?;
    let certificate = resolve_path(base, &config.certificate_path, "certificate_path")?;
    let ledger = resolve_path(base, &config.ledger_path, "ledger_path")?;
    reject_config_collision(canonical_config, &certificate, &ledger)?;
    let certificate_value = run_kubernetes_shadow_file_corroborated(
        &scenario,
        &snapshot,
        &trust,
        &quorum,
        &certificate,
        &ledger,
    )?;
    Ok(report(
        capability.configuration_schema,
        capability.mode,
        &certificate_value,
    ))
}

fn reject_live_path_collisions(
    scenario: &Path,
    kubectl: &Path,
    kubeconfig: &Path,
    trust: &Path,
    source_executables: &[&Path],
    certificate: &Path,
    ledger: &Path,
) -> Result<(), EvaluationError> {
    let mut inputs = vec![
        fs::canonicalize(scenario)?,
        fs::canonicalize(kubectl)?,
        fs::canonicalize(kubeconfig)?,
        fs::canonicalize(trust)?,
    ];
    inputs.extend(
        source_executables
            .iter()
            .map(fs::canonicalize)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let outputs = [
        canonical_output_path(certificate)?,
        canonical_output_path(&certificate_temporary_path(certificate))?,
        canonical_output_path(ledger)?,
    ];
    if outputs[0] == outputs[1]
        || outputs[0] == outputs[2]
        || outputs[1] == outputs[2]
        || outputs
            .iter()
            .any(|output| inputs.iter().any(|input| input == output))
    {
        return Err(EvaluationError::ConfigOutputCollision);
    }
    Ok(())
}

fn reject_config_collision(
    canonical_config: &Path,
    certificate: &Path,
    ledger: &Path,
) -> Result<(), EvaluationError> {
    let certificate_temporary = certificate_temporary_path(certificate);
    for output in [certificate, certificate_temporary.as_path(), ledger] {
        if canonical_output_path(output)? == canonical_config {
            return Err(EvaluationError::ConfigOutputCollision);
        }
    }
    Ok(())
}

fn report(
    configuration_schema: &'static str,
    mode: &'static str,
    certificate_value: &crate::certificate::Certificate,
) -> EvaluationReport {
    EvaluationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        configuration_schema,
        mode,
        scenario_id: certificate_value.scenario_id.clone(),
        decision: certificate_value.decision.clone(),
        certificate_digest: digest(&certificate_value),
        target_mutated: false,
    }
}

fn resolve_path(base: &Path, value: &str, field: &str) -> Result<PathBuf, EvaluationError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || value.chars().any(char::is_control) {
        return Err(EvaluationError::Path(format!(
            "{field} must be 1..={MAX_PATH_BYTES} non-control bytes"
        )));
    }
    let path = Path::new(value);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    })
}

fn canonical_output_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.exists() {
        return fs::canonicalize(path);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("evaluation output has no file name"))?;
    Ok(fs::canonicalize(parent)?.join(name))
}
