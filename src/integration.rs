use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::IntegrationRecord,
    model::{ServiceState, Values},
    protocol::{Scenario, VerifiedAuthorities},
};

pub const CONTRACT_SCHEMA_VERSION: &str = "telosieve.integration-contract/v1";
pub const REQUEST_SCHEMA_VERSION: &str = "telosieve.integration-request/v1";
pub const RESPONSE_SCHEMA_VERSION: &str = "telosieve.integration-response/v1";
pub const MODE: &str = "external-read-only";
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 128;
const MAX_REPLICAS: usize = 64;
const MAX_VALUES: usize = 256;
const MAX_VALUE_BYTES: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationAdapterConfig {
    pub executable_path: String,
    pub arguments: Vec<String>,
    pub integration_id: String,
    pub resource_kind: String,
    pub target_id: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationRequest<'a> {
    schema_version: &'static str,
    contract: &'static str,
    operation: &'static str,
    integration_id: &'a str,
    resource_kind: &'a str,
    target_id: &'a str,
    subject: &'a str,
    evaluation_time: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCapabilities {
    pub contract: String,
    pub operation: String,
    pub credential_authority: String,
    pub target_mutated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationTarget {
    pub id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationResponse {
    pub schema_version: String,
    pub integration_id: String,
    pub resource_kind: String,
    pub subject: String,
    pub captured_at: u64,
    pub capabilities: IntegrationCapabilities,
    pub target: IntegrationTarget,
    pub complete: bool,
    pub desired: Values,
    pub observed: ServiceState,
}

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("integration.configuration: adapter configuration is invalid: {0}")]
    Configuration(String),
    #[error("integration.process: adapter process failed: {0}")]
    Process(String),
    #[error("integration.resource_bound: adapter input or output exceeds a bound")]
    ResourceBound,
    #[error("integration.malformed: adapter response is malformed or non-canonical: {0}")]
    Malformed(String),
    #[error("integration.capability: adapter does not declare the required read-only capability")]
    Capability,
    #[error("integration.context: adapter response does not match the requested context")]
    Context,
    #[error("integration.incomplete: adapter response is incomplete")]
    Incomplete,
    #[error(
        "integration.authority_mismatch: adapter state disagrees with authenticated authorities"
    )]
    AuthorityMismatch,
    #[error("integration.io: adapter I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Executes one bounded read-only integration adapter and validates its response.
///
/// # Errors
///
/// Refuses unsafe executable configuration, process failure or timeout,
/// oversized/non-canonical output, mutation authority, incomplete collection,
/// context mismatch, structural excess, and authority disagreement.
pub fn collect_and_validate(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
    config: &IntegrationAdapterConfig,
) -> Result<(IntegrationResponse, Vec<u8>, IntegrationRecord), IntegrationError> {
    validate_config(config)?;
    let request = serde_json::to_vec(&IntegrationRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        contract: CONTRACT_SCHEMA_VERSION,
        operation: "observe",
        integration_id: &config.integration_id,
        resource_kind: &config.resource_kind,
        target_id: &config.target_id,
        subject: &scenario.subject,
        evaluation_time: scenario.evaluation_time,
    })
    .map_err(|error| IntegrationError::Malformed(error.to_string()))?;
    let response_bytes = invoke(config, &request)?;
    let response: IntegrationResponse = serde_json::from_slice(&response_bytes)
        .map_err(|error| IntegrationError::Malformed(error.to_string()))?;
    let canonical = serde_json::to_vec(&response)
        .map_err(|error| IntegrationError::Malformed(error.to_string()))?;
    if canonical != response_bytes {
        return Err(IntegrationError::Malformed(
            "response must use canonical compact JSON with sorted maps".into(),
        ));
    }
    validate_response(scenario, authorities, config, &response)?;
    let record = IntegrationRecord {
        contract: CONTRACT_SCHEMA_VERSION.into(),
        integration_id: response.integration_id.clone(),
        resource_kind: response.resource_kind.clone(),
        target_id: response.target.id.clone(),
        target_revision: response.target.revision.clone(),
        response_sha256: digest_bytes(&response_bytes),
        observation_quorum_digest: String::new(),
    };
    Ok((response, response_bytes, record))
}

fn validate_config(config: &IntegrationAdapterConfig) -> Result<(), IntegrationError> {
    let executable = Path::new(&config.executable_path);
    if !executable.is_absolute() || executable.is_symlink() || !executable.is_file() {
        return Err(IntegrationError::Configuration(
            "executable_path must be an absolute regular file".into(),
        ));
    }
    #[cfg(unix)]
    let missing_execute_permission = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(executable)?.permissions().mode() & 0o111 == 0
    };
    #[cfg(unix)]
    if missing_execute_permission {
        return Err(IntegrationError::Configuration(
            "executable_path must be executable".into(),
        ));
    }
    if config.arguments.len() > MAX_ARGUMENTS
        || config.arguments.iter().any(|value| !valid_argument(value))
        || !valid_text(&config.integration_id)
        || !valid_text(&config.resource_kind)
        || !valid_text(&config.target_id)
    {
        return Err(IntegrationError::Configuration(
            "adapter arguments or identifiers exceed bounds".into(),
        ));
    }
    Ok(())
}

fn validate_response(
    scenario: &Scenario,
    authorities: &VerifiedAuthorities,
    config: &IntegrationAdapterConfig,
    response: &IntegrationResponse,
) -> Result<(), IntegrationError> {
    if response.schema_version != RESPONSE_SCHEMA_VERSION
        || response.integration_id != config.integration_id
        || response.resource_kind != config.resource_kind
        || response.subject != scenario.subject
        || response.captured_at != scenario.evaluation_time
        || response.target.id != config.target_id
        || !valid_text(&response.target.revision)
    {
        return Err(IntegrationError::Context);
    }
    if response.capabilities.contract != CONTRACT_SCHEMA_VERSION
        || response.capabilities.operation != "observe"
        || response.capabilities.credential_authority != "read_only"
        || response.capabilities.target_mutated
    {
        return Err(IntegrationError::Capability);
    }
    if !response.complete {
        return Err(IntegrationError::Incomplete);
    }
    validate_values(&response.desired)?;
    if response.observed.replicas.is_empty() || response.observed.replicas.len() > MAX_REPLICAS {
        return Err(IntegrationError::ResourceBound);
    }
    for (replica, values) in &response.observed.replicas {
        if !valid_text(replica) {
            return Err(IntegrationError::ResourceBound);
        }
        validate_values(values)?;
    }
    if response.desired != authorities.goal || response.observed != authorities.phenotype {
        return Err(IntegrationError::AuthorityMismatch);
    }
    Ok(())
}

fn validate_values(values: &Values) -> Result<(), IntegrationError> {
    if values.len() > MAX_VALUES {
        return Err(IntegrationError::ResourceBound);
    }
    for (key, value) in values {
        if !valid_text(key) || value.is_empty() || value.len() > MAX_VALUE_BYTES {
            return Err(IntegrationError::ResourceBound);
        }
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_argument(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ARGUMENT_BYTES && !value.chars().any(char::is_control)
}

fn invoke(config: &IntegrationAdapterConfig, request: &[u8]) -> Result<Vec<u8>, IntegrationError> {
    let mut child = Command::new(&config.executable_path)
        .args(&config.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| IntegrationError::Process("stdin unavailable".into()))?
        .write_all(request)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| IntegrationError::Process("stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| IntegrationError::Process("stderr unavailable".into()))?;
    let out = thread::spawn(move || bounded_read(stdout, MAX_RESPONSE_BYTES));
    let err = thread::spawn(move || bounded_read(stderr, MAX_STDERR_BYTES));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            return Err(IntegrationError::Process("timed out".into()));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = out
        .join()
        .map_err(|_| IntegrationError::Process("stdout reader panicked".into()))?
        .map_err(map_stream_error)?;
    let error = err
        .join()
        .map_err(|_| IntegrationError::Process("stderr reader panicked".into()))?
        .map_err(map_stream_error)?;
    if !status.success() {
        return Err(IntegrationError::Process(
            String::from_utf8_lossy(&error).into_owned(),
        ));
    }
    Ok(output)
}

fn bounded_read(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(u64::try_from(maximum).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "adapter stream exceeded bound",
        ));
    }
    Ok(bytes)
}

fn map_stream_error(error: std::io::Error) -> IntegrationError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        IntegrationError::ResourceBound
    } else {
        IntegrationError::Io(error)
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
