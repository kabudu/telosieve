use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
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
    authorized_deletions: &'a BTreeSet<String>,
}

#[derive(Debug, Error)]
pub enum ExternalCheckerError {
    #[error("checker process failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checker response was invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checker exited before returning a response")]
    Exit,
    #[error("checker process did not expose piped {0}")]
    MissingPipe(&'static str),
    #[error("checker exceeded the two-second response bound")]
    Timeout,
}

pub struct CheckerSession {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Result<String, std::io::Error>>,
    response_timeout: Duration,
}

impl CheckerSession {
    /// Starts one independently implemented checker process for a bounded run.
    ///
    /// # Errors
    ///
    /// Returns an error when Python cannot start or required pipes are absent.
    pub fn start() -> Result<Self, ExternalCheckerError> {
        let mut command = Command::new("python3");
        command.args(["-u", "-c", include_str!("../scripts/checker.py")]);
        Self::start_command(&mut command, Duration::from_secs(2))
    }

    fn start_command(
        command: &mut Command,
        response_timeout: Duration,
    ) -> Result<Self, ExternalCheckerError> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or(ExternalCheckerError::MissingPipe("stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ExternalCheckerError::MissingPipe("stdout"))?;
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            responses,
            response_timeout,
        })
    }

    /// Checks one bounded request using the scenario-owned process.
    ///
    /// # Errors
    ///
    /// Returns an error on write, timeout, process exit, or malformed output.
    pub fn check(
        &mut self,
        current: &ServiceState,
        transition: &Transition,
        rules: &ViabilityRules,
        authorized_deletions: &BTreeSet<String>,
    ) -> Result<CheckerVerdict, ExternalCheckerError> {
        serde_json::to_writer(
            &mut self.stdin,
            &Request {
                current,
                current_digest: digest(current),
                transition,
                rules,
                authorized_deletions,
            },
        )?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        match self.responses.recv_timeout(self.response_timeout) {
            Ok(Ok(line)) => Ok(serde_json::from_str(&line)?),
            Ok(Err(error)) => Err(error.into()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Err(ExternalCheckerError::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ExternalCheckerError::Exit),
        }
    }
}

impl Drop for CheckerSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ServiceState, Transition};
    use std::collections::BTreeMap;

    fn request() -> (ServiceState, Transition, ViabilityRules) {
        let current = ServiceState {
            replicas: BTreeMap::from([("replica-a".into(), BTreeMap::new())]),
        };
        let transition = Transition {
            before_digest: digest(&current),
            after: current.clone(),
        };
        let rules = ViabilityRules {
            replica_count: 1,
            require_consensus: true,
            required_keys: BTreeMap::new(),
        };
        (current, transition, rules)
    }

    #[test]
    fn malformed_response_fails_closed() {
        let mut command = Command::new("python3");
        command.args([
            "-u",
            "-c",
            "import sys\nfor line in sys.stdin:\n print('bad')",
        ]);
        let mut session =
            CheckerSession::start_command(&mut command, Duration::from_millis(200)).unwrap();
        let (current, transition, rules) = request();
        assert!(matches!(
            session.check(&current, &transition, &rules, &BTreeSet::new()),
            Err(ExternalCheckerError::Json(_))
        ));
    }

    #[test]
    fn response_timeout_fails_closed() {
        let mut command = Command::new("python3");
        command.args([
            "-u",
            "-c",
            "import sys,time\nfor line in sys.stdin:\n time.sleep(1)",
        ]);
        let mut session =
            CheckerSession::start_command(&mut command, Duration::from_millis(20)).unwrap();
        let (current, transition, rules) = request();
        assert!(matches!(
            session.check(&current, &transition, &rules, &BTreeSet::new()),
            Err(ExternalCheckerError::Timeout)
        ));
    }

    #[test]
    fn stable_key_continuity_matches_the_reference_checker() {
        let current = ServiceState {
            replicas: BTreeMap::from([(
                "replica-a".into(),
                BTreeMap::from([("cluster/epoch".into(), "7".into())]),
            )]),
        };
        let transition = Transition {
            before_digest: digest(&current),
            after: ServiceState {
                replicas: BTreeMap::from([("replica-a".into(), BTreeMap::new())]),
            },
        };
        let rules = ViabilityRules {
            replica_count: 1,
            require_consensus: true,
            required_keys: BTreeMap::new(),
        };
        let reference = crate::checker::check(&current, &transition, &rules, &BTreeSet::new());
        let external = CheckerSession::start()
            .unwrap()
            .check(&current, &transition, &rules, &BTreeSet::new())
            .unwrap();
        assert_eq!(external.safe, reference.safe);
        assert_eq!(external.reasons, reference.reasons);
        assert!(!external.safe);
    }
}
