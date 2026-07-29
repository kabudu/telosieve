use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    checker::CheckerVerdict,
    model::{ServiceState, Transition, digest},
    protocol::ViabilityRules,
};

#[derive(Serialize)]
struct Request<'a> {
    current: &'a ServiceState,
    current_digest: String,
    transition: &'a Transition,
    rules: &'a ViabilityRules,
}

#[derive(Debug, Error)]
pub enum ExternalCheckerError {
    #[error("checker process failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checker response was invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checker exited unsuccessfully: {0}")]
    Exit(String),
    #[error("checker process did not expose piped stdin")]
    MissingStdin,
    #[error("checker exceeded the two-second execution bound")]
    Timeout,
}

/// Evaluates a transition through the independently implemented Python checker.
///
/// # Errors
///
/// Returns an error when the checker cannot start, exchange valid JSON, or exits
/// unsuccessfully.
pub fn check(
    current: &ServiceState,
    transition: &Transition,
    rules: &ViabilityRules,
) -> Result<CheckerVerdict, ExternalCheckerError> {
    let mut child = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/checker.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    serde_json::to_writer(
        child
            .stdin
            .as_mut()
            .ok_or(ExternalCheckerError::MissingStdin)?,
        &Request {
            current,
            current_digest: digest(current),
            transition,
            rules,
        },
    )?;
    child
        .stdin
        .take()
        .ok_or(ExternalCheckerError::MissingStdin)?
        .flush()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            return Err(ExternalCheckerError::Timeout);
        }
        thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(ExternalCheckerError::Exit(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
