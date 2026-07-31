use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    kubernetes_shadow::KubernetesShadowSnapshot,
    observation_quorum::{
        MAX_DOCUMENT_BYTES, MAX_PARTICIPANTS, ObservationAttestation, ObservationQuorum,
        QUORUM_SCHEMA_VERSION, VerifiedObservationQuorum, verify_observation_quorum,
    },
};

pub const ENVELOPE_SCHEMA_VERSION: &str = "telosieve.observation-source/v1";
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSourceConfig {
    pub executable_path: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationSourceEnvelope {
    schema_version: String,
    snapshot: KubernetesShadowSnapshot,
    attestation: ObservationAttestation,
}

#[derive(Debug, Error)]
pub enum ObservationSourceError {
    #[error("observation source configuration is invalid: {0}")]
    Configuration(String),
    #[error("observation source process failed: {0}")]
    Process(String),
    #[error("observation source output is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("observation source disagrees with the primary live observation")]
    Disagreement,
    #[error("observation source quorum failed: {0}")]
    Quorum(#[from] crate::observation_quorum::ObservationQuorumError),
    #[error("observation source I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Collects bounded external observations and verifies their signed agreement.
///
/// # Errors
///
/// Refuses fewer than two or more than eight sources, unsafe command shape,
/// process failure/timeout, malformed or oversized output, observation
/// disagreement, and every observation-quorum verification failure.
pub fn corroborate(
    expected: &KubernetesShadowSnapshot,
    subject: &str,
    mode: &str,
    trust_bytes: &[u8],
    sources: &[ObservationSourceConfig],
) -> Result<VerifiedObservationQuorum, ObservationSourceError> {
    if !(2..=MAX_PARTICIPANTS).contains(&sources.len()) {
        return Err(ObservationSourceError::Configuration(
            "source count must be 2..=8".into(),
        ));
    }
    let expected_bytes = serde_json::to_vec(expected)?;
    let mut attestations = Vec::with_capacity(sources.len());
    for source in sources {
        validate_source(source)?;
        let output = invoke(source)?;
        let envelope: ObservationSourceEnvelope = serde_json::from_slice(&output)?;
        if envelope.schema_version != ENVELOPE_SCHEMA_VERSION
            || serde_json::to_vec(&envelope.snapshot)? != expected_bytes
        {
            return Err(ObservationSourceError::Disagreement);
        }
        attestations.push(envelope.attestation);
    }
    let quorum = ObservationQuorum {
        schema_version: QUORUM_SCHEMA_VERSION.into(),
        subject: subject.into(),
        mode: mode.into(),
        input_sha256: hex::encode(Sha256::digest(&expected_bytes)),
        attestations,
    };
    let quorum_bytes = serde_json::to_vec(&quorum)?;
    Ok(verify_observation_quorum(
        &expected_bytes,
        subject,
        mode,
        trust_bytes,
        &quorum_bytes,
    )?)
}

fn validate_source(source: &ObservationSourceConfig) -> Result<(), ObservationSourceError> {
    let executable = Path::new(&source.executable_path);
    if !executable.is_absolute() || executable.is_symlink() || !executable.is_file() {
        return Err(ObservationSourceError::Configuration(
            "executable_path must be an absolute regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(executable)?.permissions().mode() & 0o111 == 0 {
            return Err(ObservationSourceError::Configuration(
                "executable_path is not executable".into(),
            ));
        }
    }
    if source.arguments.len() > MAX_ARGUMENTS
        || source.arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > MAX_ARGUMENT_BYTES
                || argument.chars().any(char::is_control)
        })
    {
        return Err(ObservationSourceError::Configuration(
            "arguments exceed count or text bounds".into(),
        ));
    }
    Ok(())
}

fn invoke(source: &ObservationSourceConfig) -> Result<Vec<u8>, ObservationSourceError> {
    let mut child = Command::new(&source.executable_path)
        .args(&source.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ObservationSourceError::Process("stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ObservationSourceError::Process("stderr unavailable".into()))?;
    let out = thread::spawn(move || bounded_read(stdout, MAX_STDOUT_BYTES));
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
            return Err(ObservationSourceError::Process("timed out".into()));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = out
        .join()
        .map_err(|_| ObservationSourceError::Process("stdout reader panicked".into()))??;
    let error = err
        .join()
        .map_err(|_| ObservationSourceError::Process("stderr reader panicked".into()))??;
    if !status.success() {
        return Err(ObservationSourceError::Process(
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
        return Err(std::io::Error::other("process stream exceeded bound"));
    }
    Ok(bytes)
}

/// Reads a bounded observation trust document.
///
/// # Errors
///
/// Refuses I/O failure and documents exceeding the protocol bound.
pub fn read_trust(path: &Path) -> Result<Vec<u8>, ObservationSourceError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(u64::try_from(MAX_DOCUMENT_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(ObservationSourceError::Configuration(
            "trust document exceeds bound".into(),
        ));
    }
    Ok(bytes)
}
