use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::Decision,
    engine::{RunError, certificate_temporary_path, run_kubernetes_shadow_file},
    model::digest,
};

pub const CONFIG_SCHEMA_VERSION: &str = "telosieve.evaluation-config/v1";
pub const REPORT_SCHEMA_VERSION: &str = "telosieve.evaluation-report/v1";
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const KUBERNETES_SHADOW_MODE: &str = "kubernetes-shadow";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationConfig {
    schema_version: String,
    mode: String,
    scenario_path: String,
    snapshot_path: String,
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
    let config: EvaluationConfig = serde_json::from_slice(&bytes)?;
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(EvaluationError::Schema);
    }
    if config.mode != KUBERNETES_SHADOW_MODE {
        return Err(EvaluationError::Mode);
    }
    let base = canonical_config
        .parent()
        .ok_or_else(|| EvaluationError::Path("configuration has no parent directory".into()))?;
    let scenario = resolve_path(base, &config.scenario_path, "scenario_path")?;
    let snapshot = resolve_path(base, &config.snapshot_path, "snapshot_path")?;
    let certificate = resolve_path(base, &config.certificate_path, "certificate_path")?;
    let ledger = resolve_path(base, &config.ledger_path, "ledger_path")?;
    let certificate_temporary = certificate_temporary_path(&certificate);
    for output in [&certificate, &certificate_temporary, &ledger] {
        if canonical_output_path(output)? == canonical_config {
            return Err(EvaluationError::ConfigOutputCollision);
        }
    }

    let certificate_value =
        run_kubernetes_shadow_file(&scenario, &snapshot, &certificate, &ledger)?;
    Ok(EvaluationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        configuration_schema: CONFIG_SCHEMA_VERSION,
        mode: KUBERNETES_SHADOW_MODE,
        scenario_id: certificate_value.scenario_id.clone(),
        decision: certificate_value.decision.clone(),
        certificate_digest: digest(&certificate_value),
        target_mutated: false,
    })
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
