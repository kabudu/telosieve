use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    certificate::ActuationRecord,
    model::{ServiceState, Transition, digest},
    protocol::HistoryAnchor,
};

pub const ACTUATOR_SCHEMA: &str = "telosieve.local-actuator/v1";
const MAX_STATE_BYTES: usize = 1024 * 1024;
const MAX_CONSUMED_DELETION_AUTHORIZATIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActuatorState {
    schema_version: String,
    service_state: ServiceState,
    history_anchor: HistoryAnchor,
    consumed_deletion_authorizations: BTreeSet<String>,
    last_actuation: Option<ActuationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuatorSnapshot {
    pub adapter: String,
    pub service_state: ServiceState,
    pub history_anchor: HistoryAnchor,
    pub last_actuation: Option<ActuationRecord>,
}

#[derive(Debug, Error)]
pub enum ActuatorError {
    #[error("local actuator I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("local actuator JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("local actuator is not initialized")]
    Uninitialized,
    #[error("local actuator is locked; explicit stale-lock recovery may be required")]
    Locked,
    #[error("local actuator already exists")]
    AlreadyInitialized,
    #[error("local actuator state is invalid: {0}")]
    InvalidState(String),
    #[error("authenticated phenotype does not match the current service state")]
    ObservedStateMismatch,
    #[error("transition precondition does not match the current service state")]
    TransitionPrecondition,
    #[error("history anchor issuer changed")]
    IssuerChanged,
    #[error("history anchor rollback from sequence {stored} to {candidate}")]
    Rollback { stored: u64, candidate: u64 },
    #[error("history anchor conflict at sequence {0}")]
    Conflict(u64),
    #[error("history anchor sequence gap from {stored} to {candidate}")]
    SequenceGap { stored: u64, candidate: u64 },
    #[error("deletion authorization has already been consumed: {0}")]
    AuthorizationConsumed(String),
    #[error(
        "deletion-consumption ledger reached its {MAX_CONSUMED_DELETION_AUTHORIZATIONS}-entry bound"
    )]
    ConsumptionLedgerFull,
}

pub struct LocalActuatorStore {
    path: PathBuf,
}

impl LocalActuatorStore {
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
        }
    }

    /// Initializes an absent local actuator from authenticated state.
    ///
    /// # Errors
    ///
    /// Fails if the store or lock exists, or durable persistence fails.
    pub fn initialize(
        &self,
        service_state: &ServiceState,
        history_anchor: &HistoryAnchor,
    ) -> Result<(), ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        if self.path.exists() {
            return Err(ActuatorError::AlreadyInitialized);
        }
        self.persist(&ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            service_state: service_state.clone(),
            history_anchor: history_anchor.clone(),
            consumed_deletion_authorizations: BTreeSet::new(),
            last_actuation: None,
        })
    }

    /// Atomically validates observed state, advances history, applies an
    /// optional certified transition, and consumes deletion evidence.
    ///
    /// # Errors
    ///
    /// Fails closed on stale observations, invalid transition preconditions,
    /// history errors, replay, contention, capacity, corruption, or persistence
    /// failure.
    pub fn compare_and_apply(
        &self,
        observed: &ServiceState,
        candidate_anchor: &HistoryAnchor,
        transition: Option<&Transition>,
        deletion_authorization_id: Option<&str>,
    ) -> Result<ActuationRecord, ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        let mut state = self.read()?;
        validate_anchor(&state.history_anchor, candidate_anchor)?;
        if state.service_state != *observed {
            return Err(ActuatorError::ObservedStateMismatch);
        }
        let before_digest = digest(&state.service_state);
        if transition.is_some_and(|candidate| candidate.before_digest != before_digest) {
            return Err(ActuatorError::TransitionPrecondition);
        }
        if transition.is_none() && deletion_authorization_id.is_some() {
            return Err(ActuatorError::InvalidState(
                "refused decisions cannot consume deletion authorization".into(),
            ));
        }
        if let Some(identifier) = deletion_authorization_id {
            validate_authorization_id(identifier)?;
            if state.consumed_deletion_authorizations.contains(identifier) {
                return Err(ActuatorError::AuthorizationConsumed(identifier.into()));
            }
            if state.consumed_deletion_authorizations.len() >= MAX_CONSUMED_DELETION_AUTHORIZATIONS
            {
                return Err(ActuatorError::ConsumptionLedgerFull);
            }
            state
                .consumed_deletion_authorizations
                .insert(identifier.into());
        }
        if let Some(candidate) = transition {
            state.service_state = candidate.after.clone();
        }
        state.history_anchor = candidate_anchor.clone();
        let after_digest = digest(&state.service_state);
        let operation_digest = digest(&(
            "telosieve.local-actuation-operation/v1",
            candidate_anchor,
            transition,
            deletion_authorization_id,
            &before_digest,
            &after_digest,
        ));
        let record = ActuationRecord {
            adapter: ACTUATOR_SCHEMA.into(),
            operation_digest,
            before_digest,
            after_digest,
        };
        state.last_actuation = Some(record.clone());
        self.persist(&state)?;
        Ok(record)
    }

    /// Reads the current service state through the operator-facing store
    /// boundary.
    ///
    /// # Errors
    ///
    /// Fails on missing, corrupt, oversized, or schema-incompatible state.
    pub fn current_service_state(&self) -> Result<ServiceState, ActuatorError> {
        Ok(self.read()?.service_state)
    }

    /// Reads the current operator-facing service and actuation status.
    ///
    /// # Errors
    ///
    /// Fails on missing, corrupt, oversized, or schema-incompatible state.
    pub fn current_snapshot(&self) -> Result<ActuatorSnapshot, ActuatorError> {
        let state = self.read()?;
        Ok(ActuatorSnapshot {
            adapter: state.schema_version,
            service_state: state.service_state,
            history_anchor: state.history_anchor,
            last_actuation: state.last_actuation,
        })
    }

    fn read(&self) -> Result<ActuatorState, ActuatorError> {
        if !self.path.exists() {
            return Err(ActuatorError::Uninitialized);
        }
        let length = fs::metadata(&self.path)?.len();
        if length > u64::try_from(MAX_STATE_BYTES).expect("bound fits in u64") {
            return Err(ActuatorError::InvalidState(format!(
                "state exceeds the {MAX_STATE_BYTES}-byte bound"
            )));
        }
        let state: ActuatorState = serde_json::from_slice(&fs::read(&self.path)?)?;
        if state.schema_version != ACTUATOR_SCHEMA
            || state.consumed_deletion_authorizations.len() > MAX_CONSUMED_DELETION_AUTHORIZATIONS
            || !state
                .consumed_deletion_authorizations
                .iter()
                .all(|identifier| valid_authorization_id(identifier))
            || state
                .last_actuation
                .as_ref()
                .is_some_and(|record| !valid_actuation_record(record))
        {
            return Err(ActuatorError::InvalidState(
                "unsupported schema or invalid consumption ledger".into(),
            ));
        }
        Ok(state)
    }

    fn persist(&self, state: &ActuatorState) -> Result<(), ActuatorError> {
        let mut bytes = serde_json::to_vec(state)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ActuatorError::InvalidState(format!(
                "state exceeds the {MAX_STATE_BYTES}-byte bound"
            )));
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("actuator.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| -> Result<(), ActuatorError> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn validate_anchor(stored: &HistoryAnchor, candidate: &HistoryAnchor) -> Result<(), ActuatorError> {
    if stored.issuer != candidate.issuer {
        return Err(ActuatorError::IssuerChanged);
    }
    if candidate.sequence < stored.sequence {
        return Err(ActuatorError::Rollback {
            stored: stored.sequence,
            candidate: candidate.sequence,
        });
    }
    if candidate.sequence == stored.sequence {
        if candidate.tip_digest != stored.tip_digest {
            return Err(ActuatorError::Conflict(candidate.sequence));
        }
    } else if candidate.sequence != stored.sequence + 1 {
        return Err(ActuatorError::SequenceGap {
            stored: stored.sequence,
            candidate: candidate.sequence,
        });
    }
    Ok(())
}

fn validate_authorization_id(identifier: &str) -> Result<(), ActuatorError> {
    if valid_authorization_id(identifier) {
        Ok(())
    } else {
        Err(ActuatorError::InvalidState(
            "deletion authorization identifier must be 64 lowercase hexadecimal bytes".into(),
        ))
    }
}

fn valid_authorization_id(identifier: &str) -> bool {
    identifier.len() == 64
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_actuation_record(record: &ActuationRecord) -> bool {
    record.adapter == ACTUATOR_SCHEMA
        && valid_authorization_id(&record.operation_digest)
        && valid_authorization_id(&record.before_digest)
        && valid_authorization_id(&record.after_digest)
}

struct StoreLock {
    path: PathBuf,
}

impl StoreLock {
    fn acquire(store_path: &Path) -> Result<Self, ActuatorError> {
        fs::create_dir_all(store_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let path = store_path.with_extension("actuator.lock");
        match fs::create_dir(&path) {
            Ok(()) => Ok(Self { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ActuatorError::Locked)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn service(value: &str) -> ServiceState {
        ServiceState {
            replicas: BTreeMap::from([(
                "replica-a".into(),
                BTreeMap::from([("user/message".into(), value.into())]),
            )]),
        }
    }

    fn anchor(sequence: u64, tip_digest: &str) -> HistoryAnchor {
        HistoryAnchor {
            issuer: "phenotype-lab".into(),
            sequence,
            tip_digest: tip_digest.into(),
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("telosieve-actuator-{name}-{}", std::process::id()))
    }

    #[test]
    fn transition_history_and_consumption_commit_together() {
        let directory = test_dir("apply");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let before = service("old");
        let after = service("new");
        let identifier = "a".repeat(64);
        store.initialize(&before, &anchor(1, "one")).unwrap();

        let receipt = store
            .compare_and_apply(
                &before,
                &anchor(2, "two"),
                Some(&Transition {
                    before_digest: digest(&before),
                    after: after.clone(),
                }),
                Some(&identifier),
            )
            .unwrap();
        assert_eq!(receipt.before_digest, digest(&before));
        assert_eq!(receipt.after_digest, digest(&after));
        assert_eq!(
            store
                .current_snapshot()
                .unwrap()
                .last_actuation
                .unwrap()
                .operation_digest,
            receipt.operation_digest
        );
        assert_eq!(store.current_service_state().unwrap(), after);

        let current = service("new");
        assert!(matches!(
            store.compare_and_apply(
                &current,
                &anchor(2, "two"),
                Some(&Transition {
                    before_digest: digest(&current),
                    after: service("newer"),
                }),
                Some(&identifier),
            ),
            Err(ActuatorError::AuthorizationConsumed(_))
        ));
        assert_eq!(store.current_service_state().unwrap(), current);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refusal_advances_history_without_mutating_service() {
        let directory = test_dir("refuse");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let initial = service("old");
        store.initialize(&initial, &anchor(1, "one")).unwrap();

        let receipt = store
            .compare_and_apply(&initial, &anchor(2, "two"), None, None)
            .unwrap();
        assert_eq!(receipt.before_digest, receipt.after_digest);
        assert_eq!(store.current_service_state().unwrap(), initial);
        assert_eq!(store.read().unwrap().history_anchor, anchor(2, "two"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn full_consumption_ledger_does_not_apply_or_advance() {
        let directory = test_dir("full");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let initial = service("old");
        store
            .persist(&ActuatorState {
                schema_version: ACTUATOR_SCHEMA.into(),
                service_state: initial.clone(),
                history_anchor: anchor(1, "one"),
                consumed_deletion_authorizations: (0..MAX_CONSUMED_DELETION_AUTHORIZATIONS)
                    .map(|index| format!("{index:064x}"))
                    .collect(),
                last_actuation: None,
            })
            .unwrap();
        let identifier = format!("{MAX_CONSUMED_DELETION_AUTHORIZATIONS:064x}");

        assert!(matches!(
            store.compare_and_apply(
                &initial,
                &anchor(2, "two"),
                Some(&Transition {
                    before_digest: digest(&initial),
                    after: service("new"),
                }),
                Some(&identifier),
            ),
            Err(ActuatorError::ConsumptionLedgerFull)
        ));
        let state = store.read().unwrap();
        assert_eq!(state.service_state, initial);
        assert_eq!(state.history_anchor, anchor(1, "one"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stale_corrupt_oversized_and_locked_state_fail_closed() {
        let directory = test_dir("failures");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let initial = service("old");
        assert!(matches!(
            store.current_service_state(),
            Err(ActuatorError::Uninitialized)
        ));
        store.initialize(&initial, &anchor(1, "one")).unwrap();
        assert!(matches!(
            store.compare_and_apply(&service("stale"), &anchor(1, "one"), None, None),
            Err(ActuatorError::ObservedStateMismatch)
        ));

        fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            store.current_service_state(),
            Err(ActuatorError::Json(_))
        ));
        fs::write(&path, vec![b' '; MAX_STATE_BYTES + 1]).unwrap();
        assert!(matches!(
            store.current_service_state(),
            Err(ActuatorError::InvalidState(_))
        ));
        fs::create_dir(path.with_extension("actuator.lock")).unwrap();
        assert!(matches!(
            store.compare_and_apply(&initial, &anchor(1, "one"), None, None),
            Err(ActuatorError::Locked)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
