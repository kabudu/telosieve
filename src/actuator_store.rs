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

pub const ACTUATOR_SCHEMA: &str = "telosieve.local-actuator/v2";
const LEGACY_ACTUATOR_SCHEMA: &str = "telosieve.local-actuator/v1";
const WITNESS_SCHEMA: &str = "telosieve.local-actuator-witness/v1";
const BACKUP_SCHEMA: &str = "telosieve.local-actuator-backup/v1";
const MAX_STATE_BYTES: usize = 1024 * 1024;
const MAX_WITNESS_BYTES: usize = 4096;
const MAX_BACKUP_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONSUMED_DELETION_AUTHORIZATIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActuatorState {
    schema_version: String,
    generation: u64,
    service_state: ServiceState,
    history_anchor: HistoryAnchor,
    consumed_deletion_authorizations: BTreeSet<String>,
    last_actuation: Option<ActuationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyActuatorState {
    schema_version: String,
    service_state: ServiceState,
    history_anchor: HistoryAnchor,
    consumed_deletion_authorizations: BTreeSet<String>,
    last_actuation: Option<ActuationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReference {
    generation: u64,
    state_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WitnessPosition {
    Committed {
        state: StateReference,
    },
    Pending {
        previous: Option<StateReference>,
        next: StateReference,
    },
    UpgradePending {
        legacy_digest: String,
        next: StateReference,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryWitness {
    schema_version: String,
    position: WitnessPosition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActuatorBackup {
    schema_version: String,
    state: ActuatorState,
    state_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActuatorSnapshot {
    pub adapter: String,
    pub generation: u64,
    pub service_state: ServiceState,
    pub history_anchor: HistoryAnchor,
    pub last_actuation: Option<ActuationRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    AlreadyConsistent,
    PreviousStateRetained,
    NextStateCommitted,
    IncompleteInitializationRemoved,
    IncompleteUpgradeRetained,
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
    #[error("local actuator recovery witness is missing")]
    MissingWitness,
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
    #[error("backup target already exists")]
    BackupExists,
    #[error("backup does not match the latest durable recovery witness")]
    StaleBackup,
    #[error("test interruption injected at {0}")]
    #[doc(hidden)]
    InjectedInterruption(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InterruptionPoint {
    None,
    AfterPendingWitness,
    AfterStateReplacement,
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
        if self.path.exists() || self.witness_path().exists() {
            return Err(ActuatorError::AlreadyInitialized);
        }
        let state = ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            generation: 0,
            service_state: service_state.clone(),
            history_anchor: history_anchor.clone(),
            consumed_deletion_authorizations: BTreeSet::new(),
            last_actuation: None,
        };
        let next = state_reference(&state);
        self.persist_witness(&RecoveryWitness {
            schema_version: WITNESS_SCHEMA.into(),
            position: WitnessPosition::Pending {
                previous: None,
                next: next.clone(),
            },
        })?;
        self.persist(&state)?;
        self.persist_witness(&committed_witness(next))
    }

    /// Explicitly upgrades a witness-less v1 actuator while preserving service
    /// state, history, deletion consumption, and the last receipt.
    ///
    /// # Errors
    ///
    /// Fails unless the primary file is a valid v1 state and no witness exists,
    /// or when durable persistence fails.
    pub fn upgrade_legacy(&self) -> Result<(), ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        if self.witness_path().exists() {
            return Err(ActuatorError::AlreadyInitialized);
        }
        let legacy = self.read_legacy()?;
        let legacy_digest = digest(&legacy);
        let state = ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            generation: 0,
            service_state: legacy.service_state,
            history_anchor: legacy.history_anchor,
            consumed_deletion_authorizations: legacy.consumed_deletion_authorizations,
            last_actuation: legacy.last_actuation,
        };
        let next = state_reference(&state);
        self.persist_witness(&RecoveryWitness {
            schema_version: WITNESS_SCHEMA.into(),
            position: WitnessPosition::UpgradePending {
                legacy_digest,
                next: next.clone(),
            },
        })?;
        self.persist(&state)?;
        self.persist_witness(&committed_witness(next))
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
        self.compare_and_apply_inner(
            observed,
            candidate_anchor,
            transition,
            deletion_authorization_id,
            InterruptionPoint::None,
        )
    }

    fn compare_and_apply_inner(
        &self,
        observed: &ServiceState,
        candidate_anchor: &HistoryAnchor,
        transition: Option<&Transition>,
        deletion_authorization_id: Option<&str>,
        interruption: InterruptionPoint,
    ) -> Result<ActuationRecord, ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()?;
        let mut state = self.read()?;
        let previous = state_reference(&state);
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
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| ActuatorError::InvalidState("generation overflow".into()))?;
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
        let next = state_reference(&state);
        self.persist_witness(&RecoveryWitness {
            schema_version: WITNESS_SCHEMA.into(),
            position: WitnessPosition::Pending {
                previous: Some(previous),
                next: next.clone(),
            },
        })?;
        if interruption == InterruptionPoint::AfterPendingWitness {
            return interrupted("after pending witness");
        }
        self.persist(&state)?;
        if interruption == InterruptionPoint::AfterStateReplacement {
            return interrupted("after state replacement");
        }
        self.persist_witness(&committed_witness(next))?;
        Ok(record)
    }

    /// Reads the current service state through the operator-facing store
    /// boundary.
    ///
    /// # Errors
    ///
    /// Fails on missing, corrupt, oversized, or schema-incompatible state.
    pub fn current_service_state(&self) -> Result<ServiceState, ActuatorError> {
        Ok(self.current_snapshot()?.service_state)
    }

    /// Reads the current operator-facing service and actuation status.
    ///
    /// # Errors
    ///
    /// Fails on missing, corrupt, oversized, or schema-incompatible state.
    pub fn current_snapshot(&self) -> Result<ActuatorSnapshot, ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()?;
        let state = self.read()?;
        Ok(ActuatorSnapshot {
            adapter: state.schema_version,
            generation: state.generation,
            service_state: state.service_state,
            history_anchor: state.history_anchor,
            last_actuation: state.last_actuation,
        })
    }

    /// Resolves an interrupted witness transaction without weakening its
    /// rollback checks.
    ///
    /// # Errors
    ///
    /// Fails on a live/stale lock, missing/corrupt state, or any state/witness
    /// combination other than the exact previous or next transaction state.
    pub fn recover(&self) -> Result<RecoveryOutcome, ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()
    }

    /// Creates a verified create-new backup of the latest committed state.
    ///
    /// # Errors
    ///
    /// Fails on recovery inconsistency, an existing target, size bounds, or
    /// persistence failure.
    pub fn backup(&self, backup_path: &Path) -> Result<(), ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()?;
        let state = self.read()?;
        let state_digest = digest(&state);
        let backup = ActuatorBackup {
            schema_version: BACKUP_SCHEMA.into(),
            state,
            state_digest,
        };
        let mut bytes = serde_json::to_vec(&backup)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_BACKUP_BYTES {
            return Err(ActuatorError::InvalidState(format!(
                "backup exceeds the {MAX_BACKUP_BYTES}-byte bound"
            )));
        }
        persist_create_new(backup_path, &bytes)
    }

    /// Restores only a verified backup that exactly matches the latest durable
    /// committed witness.
    ///
    /// # Errors
    ///
    /// Fails on stale/tampered backup, a pending transaction that cannot be
    /// recovered, contention, bounds, or persistence failure.
    pub fn restore(&self, backup_path: &Path) -> Result<(), ActuatorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        let mut witness = self.read_witness()?;
        self.cleanup_temporary_files()?;
        if !matches!(witness.position, WitnessPosition::Committed { .. }) {
            self.recover_locked()?;
            witness = self.read_witness()?;
        }
        let committed = match witness.position {
            WitnessPosition::Committed { state } => state,
            WitnessPosition::Pending { .. } | WitnessPosition::UpgradePending { .. } => {
                unreachable!("recovery resolves pending state")
            }
        };
        let bytes = read_bounded(backup_path, MAX_BACKUP_BYTES, "backup")?;
        let backup: ActuatorBackup = serde_json::from_slice(&bytes)?;
        validate_state(&backup.state)?;
        if backup.schema_version != BACKUP_SCHEMA
            || backup.state_digest != digest(&backup.state)
            || state_reference(&backup.state) != committed
        {
            return Err(ActuatorError::StaleBackup);
        }
        self.persist(&backup.state)
    }

    fn recover_locked(&self) -> Result<RecoveryOutcome, ActuatorError> {
        if !self.path.exists() && !self.witness_path().exists() {
            return Err(ActuatorError::Uninitialized);
        }
        let witness = self.read_witness()?;
        self.cleanup_temporary_files()?;
        let outcome = match witness.position {
            WitnessPosition::Committed { state: expected } => {
                let state = self.read()?;
                if state_reference(&state) != expected {
                    return Err(ActuatorError::InvalidState(
                        "state does not match committed recovery witness".into(),
                    ));
                }
                RecoveryOutcome::AlreadyConsistent
            }
            WitnessPosition::Pending { previous, next } => {
                let state = self.read_optional()?;
                if state
                    .as_ref()
                    .is_some_and(|candidate| state_reference(candidate) == next)
                {
                    self.persist_witness(&committed_witness(next))?;
                    RecoveryOutcome::NextStateCommitted
                } else if let Some(previous) = previous {
                    if state
                        .as_ref()
                        .is_some_and(|candidate| state_reference(candidate) == previous)
                    {
                        self.persist_witness(&committed_witness(previous))?;
                        RecoveryOutcome::PreviousStateRetained
                    } else {
                        return Err(ActuatorError::InvalidState(
                            "pending witness matches neither previous nor next state".into(),
                        ));
                    }
                } else if state.is_none() {
                    fs::remove_file(self.witness_path())?;
                    sync_parent(&self.path)?;
                    RecoveryOutcome::IncompleteInitializationRemoved
                } else {
                    return Err(ActuatorError::InvalidState(
                        "pending witness matches neither previous nor next state".into(),
                    ));
                }
            }
            WitnessPosition::UpgradePending {
                legacy_digest,
                next,
            } => {
                let bytes = read_bounded(&self.path, MAX_STATE_BYTES, "upgrade state")?;
                let next_matches = serde_json::from_slice::<ActuatorState>(&bytes)
                    .ok()
                    .filter(|state| validate_state(state).is_ok())
                    .is_some_and(|state| state_reference(&state) == next);
                let legacy_matches = serde_json::from_slice::<LegacyActuatorState>(&bytes)
                    .ok()
                    .filter(valid_legacy_state)
                    .is_some_and(|state| digest(&state) == legacy_digest);
                if next_matches {
                    self.persist_witness(&committed_witness(next))?;
                    RecoveryOutcome::NextStateCommitted
                } else if legacy_matches {
                    fs::remove_file(self.witness_path())?;
                    sync_parent(&self.path)?;
                    RecoveryOutcome::IncompleteUpgradeRetained
                } else {
                    return Err(ActuatorError::InvalidState(
                        "upgrade witness matches neither legacy nor next state".into(),
                    ));
                }
            }
        };
        Ok(outcome)
    }

    fn cleanup_temporary_files(&self) -> Result<(), ActuatorError> {
        let paths = [
            self.path.with_extension("actuator.tmp"),
            self.witness_path().with_extension("witness.tmp"),
        ];
        let mut removed = false;
        for path in paths {
            match fs::remove_file(path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if removed {
            sync_parent(&self.path)?;
        }
        Ok(())
    }

    fn read(&self) -> Result<ActuatorState, ActuatorError> {
        self.read_optional()?.ok_or(ActuatorError::Uninitialized)
    }

    fn read_optional(&self) -> Result<Option<ActuatorState>, ActuatorError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = read_bounded(&self.path, MAX_STATE_BYTES, "state")?;
        let state: ActuatorState = serde_json::from_slice(&bytes)?;
        validate_state(&state)?;
        Ok(Some(state))
    }

    fn read_witness(&self) -> Result<RecoveryWitness, ActuatorError> {
        let path = self.witness_path();
        if !path.exists() {
            return Err(ActuatorError::MissingWitness);
        }
        let bytes = read_bounded(&path, MAX_WITNESS_BYTES, "witness")?;
        let witness: RecoveryWitness = serde_json::from_slice(&bytes)?;
        validate_witness(&witness)?;
        Ok(witness)
    }

    fn read_legacy(&self) -> Result<LegacyActuatorState, ActuatorError> {
        if !self.path.exists() {
            return Err(ActuatorError::Uninitialized);
        }
        let bytes = read_bounded(&self.path, MAX_STATE_BYTES, "legacy state")?;
        let state: LegacyActuatorState = serde_json::from_slice(&bytes)?;
        if !valid_legacy_state(&state) {
            return Err(ActuatorError::InvalidState(
                "invalid legacy actuator state".into(),
            ));
        }
        Ok(state)
    }

    fn witness_path(&self) -> PathBuf {
        self.path.with_extension("witness.json")
    }

    fn persist_witness(&self, witness: &RecoveryWitness) -> Result<(), ActuatorError> {
        let mut bytes = serde_json::to_vec(witness)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(ActuatorError::InvalidState(format!(
                "witness exceeds the {MAX_WITNESS_BYTES}-byte bound"
            )));
        }
        persist_replace(&self.witness_path(), &bytes, "witness.tmp")
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

fn state_reference(state: &ActuatorState) -> StateReference {
    StateReference {
        generation: state.generation,
        state_digest: digest(state),
    }
}

fn committed_witness(state: StateReference) -> RecoveryWitness {
    RecoveryWitness {
        schema_version: WITNESS_SCHEMA.into(),
        position: WitnessPosition::Committed { state },
    }
}

fn validate_state(state: &ActuatorState) -> Result<(), ActuatorError> {
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
            "unsupported schema or invalid actuator state".into(),
        ));
    }
    Ok(())
}

fn valid_legacy_state(state: &LegacyActuatorState) -> bool {
    state.schema_version == LEGACY_ACTUATOR_SCHEMA
        && state.consumed_deletion_authorizations.len() <= MAX_CONSUMED_DELETION_AUTHORIZATIONS
        && state
            .consumed_deletion_authorizations
            .iter()
            .all(|identifier| valid_authorization_id(identifier))
        && state
            .last_actuation
            .as_ref()
            .is_none_or(valid_actuation_record)
}

fn validate_witness(witness: &RecoveryWitness) -> Result<(), ActuatorError> {
    let valid_reference =
        |reference: &StateReference| valid_authorization_id(&reference.state_digest);
    let valid_position = match &witness.position {
        WitnessPosition::Committed { state } => valid_reference(state),
        WitnessPosition::Pending { previous, next } => {
            valid_reference(next)
                && match previous {
                    None => next.generation == 0,
                    Some(previous) => {
                        valid_reference(previous)
                            && previous
                                .generation
                                .checked_add(1)
                                .is_some_and(|generation| generation == next.generation)
                    }
                }
        }
        WitnessPosition::UpgradePending {
            legacy_digest,
            next,
        } => valid_authorization_id(legacy_digest) && valid_reference(next) && next.generation == 0,
    };
    if witness.schema_version != WITNESS_SCHEMA || !valid_position {
        return Err(ActuatorError::InvalidState(
            "unsupported schema or invalid recovery witness".into(),
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum_bytes: usize, label: &str) -> Result<Vec<u8>, ActuatorError> {
    let length = fs::metadata(path)?.len();
    if length > u64::try_from(maximum_bytes).expect("bound fits in u64") {
        return Err(ActuatorError::InvalidState(format!(
            "{label} exceeds the {maximum_bytes}-byte bound"
        )));
    }
    Ok(fs::read(path)?)
}

fn persist_replace(
    path: &Path,
    bytes: &[u8],
    temporary_extension: &str,
) -> Result<(), ActuatorError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(temporary_extension);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| -> Result<(), ActuatorError> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn persist_create_new(path: &Path, bytes: &[u8]) -> Result<(), ActuatorError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ActuatorError::BackupExists);
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ActuatorError> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

fn interrupted<T>(point: &'static str) -> Result<T, ActuatorError> {
    Err(ActuatorError::InjectedInterruption(point))
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
    matches!(
        record.adapter.as_str(),
        ACTUATOR_SCHEMA | LEGACY_ACTUATOR_SCHEMA
    ) && valid_authorization_id(&record.operation_digest)
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
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
    };

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
    fn recovery_resolves_both_commit_interruption_boundaries() {
        let directory = test_dir("interruptions");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let before = service("old");
        let after = service("new");
        store.initialize(&before, &anchor(1, "one")).unwrap();
        let transition = Transition {
            before_digest: digest(&before),
            after: after.clone(),
        };

        assert!(matches!(
            store.compare_and_apply_inner(
                &before,
                &anchor(2, "two"),
                Some(&transition),
                None,
                InterruptionPoint::AfterPendingWitness,
            ),
            Err(ActuatorError::InjectedInterruption(_))
        ));
        assert_eq!(
            store.recover().unwrap(),
            RecoveryOutcome::PreviousStateRetained
        );
        assert_eq!(store.current_service_state().unwrap(), before);

        assert!(matches!(
            store.compare_and_apply_inner(
                &before,
                &anchor(2, "two"),
                Some(&transition),
                None,
                InterruptionPoint::AfterStateReplacement,
            ),
            Err(ActuatorError::InjectedInterruption(_))
        ));
        assert_eq!(
            store.recover().unwrap(),
            RecoveryOutcome::NextStateCommitted
        );
        let snapshot = store.current_snapshot().unwrap();
        assert_eq!(snapshot.service_state, after);
        assert_eq!(snapshot.generation, 1);
        assert!(snapshot.last_actuation.is_some());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn incomplete_initialization_recovery_removes_only_the_witness() {
        let directory = test_dir("initialize-interruption");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let state = ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            generation: 0,
            service_state: service("old"),
            history_anchor: anchor(1, "one"),
            consumed_deletion_authorizations: BTreeSet::new(),
            last_actuation: None,
        };
        store
            .persist_witness(&RecoveryWitness {
                schema_version: WITNESS_SCHEMA.into(),
                position: WitnessPosition::Pending {
                    previous: None,
                    next: state_reference(&state),
                },
            })
            .unwrap();

        assert_eq!(
            store.recover().unwrap(),
            RecoveryOutcome::IncompleteInitializationRemoved
        );
        assert!(!path.exists());
        assert!(!store.witness_path().exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_upgrade_preserves_consumption_and_is_recoverable() {
        let directory = test_dir("upgrade");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let identifier = "a".repeat(64);
        let legacy = LegacyActuatorState {
            schema_version: LEGACY_ACTUATOR_SCHEMA.into(),
            service_state: service("old"),
            history_anchor: anchor(1, "one"),
            consumed_deletion_authorizations: BTreeSet::from([identifier.clone()]),
            last_actuation: None,
        };
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(matches!(
            store.current_snapshot(),
            Err(ActuatorError::MissingWitness)
        ));
        store.upgrade_legacy().unwrap();
        assert_eq!(store.current_snapshot().unwrap().generation, 0);
        assert!(matches!(
            store.compare_and_apply(
                &service("old"),
                &anchor(1, "one"),
                Some(&Transition {
                    before_digest: digest(&service("old")),
                    after: service("new"),
                }),
                Some(&identifier),
            ),
            Err(ActuatorError::AuthorizationConsumed(_))
        ));

        fs::remove_file(store.witness_path()).unwrap();
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let upgraded = ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            generation: 0,
            service_state: legacy.service_state.clone(),
            history_anchor: legacy.history_anchor.clone(),
            consumed_deletion_authorizations: legacy.consumed_deletion_authorizations.clone(),
            last_actuation: None,
        };
        store
            .persist_witness(&RecoveryWitness {
                schema_version: WITNESS_SCHEMA.into(),
                position: WitnessPosition::UpgradePending {
                    legacy_digest: digest(&legacy),
                    next: state_reference(&upgraded),
                },
            })
            .unwrap();
        assert_eq!(
            store.recover().unwrap(),
            RecoveryOutcome::IncompleteUpgradeRetained
        );
        assert!(!store.witness_path().exists());
        assert_eq!(store.read_legacy().unwrap(), legacy);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn backup_restore_rejects_rollback_and_recovers_latest_state() {
        let directory = test_dir("backup");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let old_backup = directory.join("old.backup.json");
        let latest_backup = directory.join("latest.backup.json");
        let tampered_backup = directory.join("tampered.backup.json");
        let store = LocalActuatorStore::new(&path);
        let before = service("old");
        let after = service("new");
        store.initialize(&before, &anchor(1, "one")).unwrap();
        let old_state_bytes = fs::read(&path).unwrap();
        store.backup(&old_backup).unwrap();
        store
            .compare_and_apply(
                &before,
                &anchor(2, "two"),
                Some(&Transition {
                    before_digest: digest(&before),
                    after: after.clone(),
                }),
                None,
            )
            .unwrap();
        assert!(matches!(
            store.restore(&old_backup),
            Err(ActuatorError::StaleBackup)
        ));

        store.backup(&latest_backup).unwrap();
        assert!(matches!(
            store.backup(&latest_backup),
            Err(ActuatorError::BackupExists)
        ));
        fs::write(&path, &old_state_bytes).unwrap();
        assert!(matches!(
            store.current_snapshot(),
            Err(ActuatorError::InvalidState(_))
        ));
        store.restore(&latest_backup).unwrap();
        assert_eq!(store.current_service_state().unwrap(), after);

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fs::read(&latest_backup).unwrap()).unwrap();
        tampered["state"]["service_state"]["replicas"]["replica-a"]["user/message"] =
            "tampered".into();
        fs::write(&tampered_backup, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(matches!(
            store.restore(&tampered_backup),
            Err(ActuatorError::StaleBackup)
        ));

        fs::remove_file(&path).unwrap();
        store.restore(&latest_backup).unwrap();
        assert_eq!(store.current_service_state().unwrap(), after);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_writers_allow_at_most_one_commit() {
        let directory = test_dir("concurrent");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let before = service("old");
        LocalActuatorStore::new(&path)
            .initialize(&before, &anchor(1, "one"))
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = ["new-a", "new-b"]
            .into_iter()
            .map(|value| {
                let path = path.clone();
                let before = before.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let transition = Transition {
                        before_digest: digest(&before),
                        after: service(value),
                    };
                    barrier.wait();
                    LocalActuatorStore::new(&path).compare_and_apply(
                        &before,
                        &anchor(2, "two"),
                        Some(&transition),
                        None,
                    )
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter(|result| result.is_err())
                .all(|result| {
                    matches!(
                        result,
                        Err(ActuatorError::Locked | ActuatorError::ObservedStateMismatch)
                    )
                })
        );
        assert_eq!(
            LocalActuatorStore::new(&path)
                .current_snapshot()
                .unwrap()
                .generation,
            1
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn full_consumption_ledger_does_not_apply_or_advance() {
        let directory = test_dir("full");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        let initial = service("old");
        let state = ActuatorState {
            schema_version: ACTUATOR_SCHEMA.into(),
            generation: 1,
            service_state: initial.clone(),
            history_anchor: anchor(1, "one"),
            consumed_deletion_authorizations: (0..MAX_CONSUMED_DELETION_AUTHORIZATIONS)
                .map(|index| format!("{index:064x}"))
                .collect(),
            last_actuation: None,
        };
        store.persist(&state).unwrap();
        store
            .persist_witness(&committed_witness(state_reference(&state)))
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

    #[test]
    fn committed_witness_loss_fails_closed() {
        let directory = test_dir("witness-loss");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("actuator.json");
        let store = LocalActuatorStore::new(&path);
        store
            .initialize(&service("old"), &anchor(1, "one"))
            .unwrap();
        fs::remove_file(store.witness_path()).unwrap();
        assert!(matches!(
            store.current_snapshot(),
            Err(ActuatorError::MissingWitness)
        ));
        assert!(matches!(
            store.recover(),
            Err(ActuatorError::MissingWitness)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
