use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const STATE_SCHEMA: &str = "telosieve.witness-tip-state/v1";
const RECOVERY_SCHEMA: &str = "telosieve.witness-tip-recovery/v1";
const BACKUP_SCHEMA: &str = "telosieve.witness-tip-backup/v1";
const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedTips {
    pub schema_version: String,
    pub generation: u64,
    pub timestamp_sequence: u64,
    pub timestamp_digest: String,
    pub revocation_sequence: u64,
    pub revocation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateReference {
    generation: u64,
    digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryPosition {
    Pending {
        previous: StateReference,
        next: StateReference,
    },
    Committed {
        current: StateReference,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryWitness {
    schema_version: String,
    position: RecoveryPosition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TipBackup {
    schema_version: String,
    state: TrustedTips,
    state_digest: String,
}

#[derive(Debug, Error)]
pub enum TipStoreError {
    #[error("witness-tip store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("witness-tip store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("witness-tip store is missing, corrupt, or inconsistent")]
    InvalidState,
    #[error("witness-tip store is locked")]
    Locked,
    #[error("witness-tip rollback, conflict, or sequence gap")]
    InvalidAdvance,
    #[error("backup target already exists")]
    BackupExists,
    #[error("backup is not the exact latest committed generation")]
    InvalidBackup,
}

pub struct WitnessTipStore {
    path: PathBuf,
}

impl WitnessTipStore {
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
        }
    }

    /// Initializes an absent store and committed recovery witness.
    ///
    /// # Errors
    ///
    /// Refuses existing state, invalid tips, lock contention, or failed durable
    /// persistence.
    pub fn initialize(&self, mut tips: TrustedTips) -> Result<(), TipStoreError> {
        let _lock = StoreLock::acquire(&self.path)?;
        if self.path.exists() || self.witness_path().exists() {
            return Err(TipStoreError::InvalidState);
        }
        tips.schema_version = STATE_SCHEMA.into();
        validate_state(&tips)?;
        self.persist_state(&tips)?;
        self.persist_witness(&committed(reference(&tips)))
    }

    /// Atomically advances both trusted tips as one generation.
    ///
    /// # Errors
    ///
    /// Refuses rollback, same-sequence equivocation, gaps, invalid input,
    /// inconsistent recovery state, lock contention, or persistence failure.
    pub fn compare_and_advance(&self, mut next: TrustedTips) -> Result<(), TipStoreError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()?;
        let current = self.read_state()?;
        next.schema_version = STATE_SCHEMA.into();
        validate_state(&next)?;
        let timestamp_changed = next.timestamp_sequence != current.timestamp_sequence;
        let revocation_changed = next.revocation_sequence != current.revocation_sequence;
        if (!timestamp_changed && !revocation_changed)
            || current.generation.checked_add(1) != Some(next.generation)
            || !valid_tip_advance(
                current.timestamp_sequence,
                &current.timestamp_digest,
                next.timestamp_sequence,
                &next.timestamp_digest,
            )
            || !valid_tip_advance(
                current.revocation_sequence,
                &current.revocation_digest,
                next.revocation_sequence,
                &next.revocation_digest,
            )
        {
            return Err(TipStoreError::InvalidAdvance);
        }
        let previous = reference(&current);
        let next_reference = reference(&next);
        self.persist_witness(&RecoveryWitness {
            schema_version: RECOVERY_SCHEMA.into(),
            position: RecoveryPosition::Pending {
                previous,
                next: next_reference.clone(),
            },
        })?;
        self.persist_state(&next)?;
        self.persist_witness(&committed(next_reference))
    }

    /// Reads only a state exactly matching its committed recovery witness.
    ///
    /// # Errors
    ///
    /// Refuses missing, corrupt, pending, oversized, or inconsistent files.
    pub fn read(&self) -> Result<TrustedTips, TipStoreError> {
        let state = self.read_state()?;
        match self.read_witness()?.position {
            RecoveryPosition::Committed { current } if current == reference(&state) => Ok(state),
            RecoveryPosition::Pending { .. } | RecoveryPosition::Committed { .. } => {
                Err(TipStoreError::InvalidState)
            }
        }
    }

    /// Resolves an interrupted update without inventing a generation.
    ///
    /// # Errors
    ///
    /// Refuses state matching neither the witnessed previous nor next
    /// generation, malformed files, or lock contention.
    pub fn recover(&self) -> Result<TrustedTips, TipStoreError> {
        let _lock = StoreLock::acquire(&self.path)?;
        self.recover_locked()?;
        self.read()
    }

    /// Creates a content-addressed backup without overwriting a target.
    ///
    /// # Errors
    ///
    /// Refuses inconsistent state, existing targets, or persistence failure.
    pub fn backup(&self, backup_path: &Path) -> Result<(), TipStoreError> {
        let state = self.read()?;
        let backup = TipBackup {
            schema_version: BACKUP_SCHEMA.into(),
            state_digest: digest(&state),
            state,
        };
        persist_create_new(backup_path, &serde_json::to_vec(&backup)?)
    }

    /// Restores only a backup equal to the latest committed witness.
    ///
    /// # Errors
    ///
    /// Refuses stale, tampered, oversized, malformed, or non-latest backups.
    pub fn restore(&self, backup_path: &Path) -> Result<(), TipStoreError> {
        let _lock = StoreLock::acquire(&self.path)?;
        let witness = self.read_witness()?;
        let RecoveryPosition::Committed { current } = witness.position else {
            return Err(TipStoreError::InvalidState);
        };
        let bytes = read_bounded(backup_path)?;
        let backup: TipBackup = serde_json::from_slice(&bytes)?;
        validate_state(&backup.state)?;
        if backup.schema_version != BACKUP_SCHEMA
            || backup.state_digest != digest(&backup.state)
            || reference(&backup.state) != current
        {
            return Err(TipStoreError::InvalidBackup);
        }
        self.persist_state(&backup.state)
    }

    fn recover_locked(&self) -> Result<(), TipStoreError> {
        let state = self.read_state()?;
        let witness = self.read_witness()?;
        match witness.position {
            RecoveryPosition::Committed { current } if current == reference(&state) => Ok(()),
            RecoveryPosition::Pending { previous, next: _ } if reference(&state) == previous => {
                self.persist_witness(&committed(previous))
            }
            RecoveryPosition::Pending { previous: _, next } if reference(&state) == next => {
                self.persist_witness(&committed(next))
            }
            RecoveryPosition::Pending { .. } | RecoveryPosition::Committed { .. } => {
                Err(TipStoreError::InvalidState)
            }
        }
    }

    fn read_state(&self) -> Result<TrustedTips, TipStoreError> {
        let state: TrustedTips = serde_json::from_slice(&read_bounded(&self.path)?)?;
        validate_state(&state)?;
        Ok(state)
    }

    fn read_witness(&self) -> Result<RecoveryWitness, TipStoreError> {
        let witness: RecoveryWitness =
            serde_json::from_slice(&read_bounded(&self.witness_path())?)?;
        if witness.schema_version != RECOVERY_SCHEMA {
            return Err(TipStoreError::InvalidState);
        }
        Ok(witness)
    }

    fn witness_path(&self) -> PathBuf {
        self.path.with_extension("witness.json")
    }

    fn persist_state(&self, state: &TrustedTips) -> Result<(), TipStoreError> {
        persist_replace(&self.path, &serde_json::to_vec(state)?, "state.tmp")
    }

    fn persist_witness(&self, witness: &RecoveryWitness) -> Result<(), TipStoreError> {
        persist_replace(
            &self.witness_path(),
            &serde_json::to_vec(witness)?,
            "witness.tmp",
        )
    }
}

fn validate_state(state: &TrustedTips) -> Result<(), TipStoreError> {
    if state.schema_version != STATE_SCHEMA
        || state.generation == 0
        || state.timestamp_sequence == 0
        || state.revocation_sequence == 0
        || !valid_digest(&state.timestamp_digest)
        || !valid_digest(&state.revocation_digest)
    {
        return Err(TipStoreError::InvalidState);
    }
    Ok(())
}

fn valid_tip_advance(
    old_sequence: u64,
    old_digest: &str,
    new_sequence: u64,
    new_digest: &str,
) -> bool {
    (new_sequence == old_sequence && new_digest == old_digest)
        || (old_sequence.checked_add(1) == Some(new_sequence) && new_digest != old_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest<T: Serialize>(value: &T) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("typed state serialization cannot fail"),
    ))
}

fn reference(state: &TrustedTips) -> StateReference {
    StateReference {
        generation: state.generation,
        digest: digest(state),
    }
}

fn committed(current: StateReference) -> RecoveryWitness {
    RecoveryWitness {
        schema_version: RECOVERY_SCHEMA.into(),
        position: RecoveryPosition::Committed { current },
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, TipStoreError> {
    if fs::metadata(path)?.len() > MAX_FILE_BYTES {
        return Err(TipStoreError::InvalidState);
    }
    Ok(fs::read(path)?)
}

fn persist_replace(path: &Path, bytes: &[u8], suffix: &str) -> Result<(), TipStoreError> {
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_FILE_BYTES) {
        return Err(TipStoreError::InvalidState);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(suffix);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(Into::into)
}

fn persist_create_new(path: &Path, bytes: &[u8]) -> Result<(), TipStoreError> {
    if path.exists() {
        return Err(TipStoreError::BackupExists);
    }
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_FILE_BYTES) {
        return Err(TipStoreError::InvalidState);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

struct StoreLock {
    path: PathBuf,
}

impl StoreLock {
    fn acquire(store_path: &Path) -> Result<Self, TipStoreError> {
        fs::create_dir_all(store_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let path = store_path.with_extension("lock");
        match fs::create_dir(&path) {
            Ok(()) => Ok(Self { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(TipStoreError::Locked)
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
    use super::*;

    fn tips(generation: u64, timestamp: u64, revocation: u64) -> TrustedTips {
        TrustedTips {
            schema_version: STATE_SCHEMA.into(),
            generation,
            timestamp_sequence: timestamp,
            timestamp_digest: format!("{timestamp:064x}"),
            revocation_sequence: revocation,
            revocation_digest: format!("{revocation:064x}"),
        }
    }

    fn directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("telosieve-tip-{name}-{}", std::process::id()))
    }

    #[test]
    fn recovery_backup_restore_and_independent_path_preserve_exact_tips() {
        let directory = directory("lifecycle");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("tips.json");
        let backup = directory.join("tips.backup.json");
        let store = WitnessTipStore::new(&path);
        store.initialize(tips(1, 1, 1)).unwrap();
        store.backup(&backup).unwrap();
        store.compare_and_advance(tips(2, 2, 1)).unwrap();
        assert!(matches!(
            store.restore(&backup),
            Err(TipStoreError::InvalidBackup)
        ));

        let latest = directory.join("latest.backup.json");
        store.backup(&latest).unwrap();
        fs::remove_file(&path).unwrap();
        store.restore(&latest).unwrap();
        assert_eq!(store.read().unwrap(), tips(2, 2, 1));

        let remote = directory.join("independent");
        fs::create_dir_all(&remote).unwrap();
        fs::copy(&path, remote.join("tips.json")).unwrap();
        fs::copy(store.witness_path(), remote.join("tips.witness.json")).unwrap();
        assert_eq!(
            WitnessTipStore::new(&remote.join("tips.json"))
                .read()
                .unwrap(),
            tips(2, 2, 1)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn interrupted_updates_recover_only_previous_or_next_and_conflicts_refuse() {
        let directory = directory("recovery");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("tips.json");
        let store = WitnessTipStore::new(&path);
        let previous = tips(1, 1, 1);
        let next = tips(2, 2, 2);
        store.initialize(previous.clone()).unwrap();
        store
            .persist_witness(&RecoveryWitness {
                schema_version: RECOVERY_SCHEMA.into(),
                position: RecoveryPosition::Pending {
                    previous: reference(&previous),
                    next: reference(&next),
                },
            })
            .unwrap();
        assert_eq!(store.recover().unwrap(), previous);

        store
            .persist_witness(&RecoveryWitness {
                schema_version: RECOVERY_SCHEMA.into(),
                position: RecoveryPosition::Pending {
                    previous: reference(&tips(1, 1, 1)),
                    next: reference(&next),
                },
            })
            .unwrap();
        store.persist_state(&next).unwrap();
        assert_eq!(store.recover().unwrap(), next);
        assert!(matches!(
            store.compare_and_advance(tips(3, 2, 2)),
            Err(TipStoreError::InvalidAdvance)
        ));
        assert!(matches!(
            store.compare_and_advance(tips(3, 1, 2)),
            Err(TipStoreError::InvalidAdvance)
        ));
        let mut corrupt = tips(9, 9, 9);
        corrupt.timestamp_digest = "a".repeat(64);
        store.persist_state(&corrupt).unwrap();
        assert!(matches!(store.recover(), Err(TipStoreError::InvalidState)));

        let missing = directory.join("missing.json");
        let missing_store = WitnessTipStore::new(&missing);
        missing_store.initialize(tips(1, 1, 1)).unwrap();
        fs::remove_file(missing_store.witness_path()).unwrap();
        assert!(matches!(missing_store.read(), Err(TipStoreError::Io(_))));
        fs::write(
            &missing,
            vec![b' '; usize::try_from(MAX_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(matches!(
            missing_store.read(),
            Err(TipStoreError::InvalidState)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
