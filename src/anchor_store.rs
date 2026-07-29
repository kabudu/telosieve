use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::HistoryAnchor;

const STATE_SCHEMA: &str = "telosieve.anchor-state/v2";
const MAX_STATE_BYTES: u64 = 512 * 1024;
pub const MAX_CONSUMED_DELETION_AUTHORIZATIONS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorState {
    schema_version: String,
    history_anchor: HistoryAnchor,
    consumed_deletion_authorizations: BTreeSet<String>,
}

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("anchor store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("anchor store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("anchor store is not initialized")]
    Uninitialized,
    #[error(
        "legacy anchor state has no deletion-consumption ledger; retire it and explicitly initialize a new verified anchor"
    )]
    LegacyState,
    #[error("anchor store state is invalid: {0}")]
    InvalidState(String),
    #[error("anchor store is locked; explicit stale-lock recovery may be required")]
    Locked,
    #[error("anchor issuer changed")]
    IssuerChanged,
    #[error("anchor rollback from sequence {stored} to {candidate}")]
    Rollback { stored: u64, candidate: u64 },
    #[error("anchor conflict at sequence {0}")]
    Conflict(u64),
    #[error("anchor sequence gap from {stored} to {candidate}")]
    SequenceGap { stored: u64, candidate: u64 },
    #[error("deletion authorization has already been consumed: {0}")]
    AuthorizationConsumed(String),
    #[error(
        "deletion-consumption ledger reached its {MAX_CONSUMED_DELETION_AUTHORIZATIONS}-entry bound"
    )]
    ConsumptionLedgerFull,
}

pub struct AnchorStore {
    path: PathBuf,
}

impl AnchorStore {
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
        }
    }

    /// Explicitly initializes an absent durable trust anchor.
    ///
    /// # Errors
    ///
    /// Fails when the store or lock already exists or persistence cannot be
    /// completed.
    pub fn initialize(&self, anchor: &HistoryAnchor) -> Result<(), AnchorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        if self.path.exists() {
            return Err(AnchorError::Conflict(anchor.sequence));
        }
        self.persist(&AnchorState {
            schema_version: STATE_SCHEMA.into(),
            history_anchor: anchor.clone(),
            consumed_deletion_authorizations: BTreeSet::new(),
        })
    }

    /// Verifies and monotonically advances an existing durable anchor.
    ///
    /// # Errors
    ///
    /// Fails closed on missing/corrupt state, rollback, conflicts, sequence gaps,
    /// concurrent ownership, or persistence failure.
    pub fn compare_and_advance(&self, candidate: &HistoryAnchor) -> Result<(), AnchorError> {
        self.compare_advance_and_consume(candidate, None)
    }

    /// Atomically advances history and consumes an optional one-shot deletion
    /// authorization.
    ///
    /// # Errors
    ///
    /// Fails closed on any history error, replayed authorization, full ledger,
    /// incompatible state, concurrent ownership, or persistence failure.
    pub fn compare_advance_and_consume(
        &self,
        candidate: &HistoryAnchor,
        deletion_authorization_id: Option<&str>,
    ) -> Result<(), AnchorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        let mut state = self.read()?;
        let stored = &state.history_anchor;
        if stored.issuer != candidate.issuer {
            return Err(AnchorError::IssuerChanged);
        }
        if candidate.sequence < stored.sequence {
            return Err(AnchorError::Rollback {
                stored: stored.sequence,
                candidate: candidate.sequence,
            });
        }
        if candidate.sequence == stored.sequence {
            if candidate.tip_digest != stored.tip_digest {
                return Err(AnchorError::Conflict(candidate.sequence));
            }
        } else if candidate.sequence != stored.sequence + 1 {
            return Err(AnchorError::SequenceGap {
                stored: stored.sequence,
                candidate: candidate.sequence,
            });
        }
        if let Some(identifier) = deletion_authorization_id {
            if !valid_authorization_id(identifier) {
                return Err(AnchorError::InvalidState(
                    "deletion authorization identifier must be 64 lowercase hexadecimal bytes"
                        .into(),
                ));
            }
            if state.consumed_deletion_authorizations.contains(identifier) {
                return Err(AnchorError::AuthorizationConsumed(identifier.into()));
            }
            if state.consumed_deletion_authorizations.len() >= MAX_CONSUMED_DELETION_AUTHORIZATIONS
            {
                return Err(AnchorError::ConsumptionLedgerFull);
            }
            state
                .consumed_deletion_authorizations
                .insert(identifier.into());
        }
        state.history_anchor = candidate.clone();
        self.persist(&state)
    }

    fn read(&self) -> Result<AnchorState, AnchorError> {
        if !self.path.exists() {
            return Err(AnchorError::Uninitialized);
        }
        if fs::metadata(&self.path)?.len() > MAX_STATE_BYTES {
            return Err(AnchorError::InvalidState(format!(
                "state exceeds the {MAX_STATE_BYTES}-byte bound"
            )));
        }
        let bytes = fs::read(&self.path)?;
        match serde_json::from_slice::<AnchorState>(&bytes) {
            Ok(state)
                if state.schema_version == STATE_SCHEMA
                    && state.consumed_deletion_authorizations.len()
                        <= MAX_CONSUMED_DELETION_AUTHORIZATIONS
                    && state
                        .consumed_deletion_authorizations
                        .iter()
                        .all(|identifier| valid_authorization_id(identifier)) =>
            {
                Ok(state)
            }
            Ok(_) => Err(AnchorError::InvalidState(
                "unsupported schema or invalid consumption ledger".into(),
            )),
            Err(_error) if serde_json::from_slice::<HistoryAnchor>(&bytes).is_ok() => {
                Err(AnchorError::LegacyState)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn persist(&self, state: &AnchorState) -> Result<(), AnchorError> {
        let mut bytes = serde_json::to_vec(state)?;
        bytes.push(b'\n');
        if bytes.len() > usize::try_from(MAX_STATE_BYTES).expect("bound fits in usize") {
            return Err(AnchorError::InvalidState(format!(
                "state exceeds the {MAX_STATE_BYTES}-byte bound"
            )));
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("anchor.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| -> Result<(), AnchorError> {
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

fn valid_authorization_id(identifier: &str) -> bool {
    identifier.len() == 64
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct StoreLock {
    path: PathBuf,
}

impl StoreLock {
    fn acquire(store_path: &Path) -> Result<Self, AnchorError> {
        fs::create_dir_all(store_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let path = store_path.with_extension("anchor.lock");
        match fs::create_dir(&path) {
            Ok(()) => Ok(Self { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(AnchorError::Locked)
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

    fn anchor(sequence: u64, digest: &str) -> HistoryAnchor {
        HistoryAnchor {
            issuer: "phenotype-lab".into(),
            sequence,
            tip_digest: digest.into(),
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("telosieve-anchor-{name}-{}", std::process::id()))
    }

    #[test]
    fn initialization_idempotence_and_monotonic_advance_are_durable() {
        let directory = test_dir("advance");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("anchor.json");
        let store = AnchorStore::new(&path);

        store.initialize(&anchor(2, "two")).unwrap();
        assert!(matches!(
            store.initialize(&anchor(2, "two")),
            Err(AnchorError::Conflict(2))
        ));
        store.compare_and_advance(&anchor(2, "two")).unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::Rollback { .. })
        ));
        assert!(matches!(
            store.compare_and_advance(&anchor(2, "conflict")),
            Err(AnchorError::Conflict(2))
        ));
        assert!(matches!(
            store.compare_and_advance(&anchor(4, "gap")),
            Err(AnchorError::SequenceGap { .. })
        ));
        store.compare_and_advance(&anchor(3, "three")).unwrap();
        assert_eq!(store.read().unwrap().history_anchor, anchor(3, "three"));
        assert!(!path.with_extension("anchor.tmp").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn deletion_authorization_is_consumed_once_atomically() {
        let directory = test_dir("consume");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("anchor.json");
        let store = AnchorStore::new(&path);
        store.initialize(&anchor(2, "two")).unwrap();

        let authorization_a = "a".repeat(64);
        let authorization_b = "b".repeat(64);
        store
            .compare_advance_and_consume(&anchor(2, "two"), Some(&authorization_a))
            .unwrap();
        assert!(matches!(
            store.compare_advance_and_consume(&anchor(2, "two"), Some(&authorization_a)),
            Err(AnchorError::AuthorizationConsumed(_))
        ));
        store
            .compare_advance_and_consume(&anchor(3, "three"), Some(&authorization_b))
            .unwrap();
        let state = store.read().unwrap();
        assert_eq!(state.history_anchor, anchor(3, "three"));
        assert_eq!(
            state.consumed_deletion_authorizations,
            BTreeSet::from([authorization_a, authorization_b])
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn full_consumption_ledger_fails_closed_without_advancing_history() {
        let directory = test_dir("full");
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("anchor.json");
        let store = AnchorStore::new(&path);
        let consumed_deletion_authorizations = (0..MAX_CONSUMED_DELETION_AUTHORIZATIONS)
            .map(|index| format!("{index:064x}"))
            .collect();
        store
            .persist(&AnchorState {
                schema_version: STATE_SCHEMA.into(),
                history_anchor: anchor(2, "two"),
                consumed_deletion_authorizations,
            })
            .unwrap();
        let new_identifier = format!("{MAX_CONSUMED_DELETION_AUTHORIZATIONS:064x}");

        assert!(matches!(
            store.compare_advance_and_consume(&anchor(3, "three"), Some(&new_identifier)),
            Err(AnchorError::ConsumptionLedgerFull)
        ));
        assert_eq!(store.read().unwrap().history_anchor, anchor(2, "two"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_corrupt_and_locked_stores_fail_closed() {
        let directory = test_dir("failures");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("anchor.json");
        let store = AnchorStore::new(&path);
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::Uninitialized)
        ));

        fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::Json(_))
        ));

        fs::write(&path, serde_json::to_vec(&anchor(1, "one")).unwrap()).unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::LegacyState)
        ));

        let oversized_length = usize::try_from(MAX_STATE_BYTES).unwrap() + 1;
        fs::write(&path, vec![b' '; oversized_length]).unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::InvalidState(_))
        ));

        fs::create_dir(path.with_extension("anchor.lock")).unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::Locked)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
