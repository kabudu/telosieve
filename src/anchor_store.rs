use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::protocol::HistoryAnchor;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("anchor store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("anchor store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("anchor store is not initialized")]
    Uninitialized,
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
        self.persist(anchor)
    }

    /// Verifies and monotonically advances an existing durable anchor.
    ///
    /// # Errors
    ///
    /// Fails closed on missing/corrupt state, rollback, conflicts, sequence gaps,
    /// concurrent ownership, or persistence failure.
    pub fn compare_and_advance(&self, candidate: &HistoryAnchor) -> Result<(), AnchorError> {
        let _lock = StoreLock::acquire(&self.path)?;
        let stored = self.read()?;
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
            return if candidate.tip_digest == stored.tip_digest {
                Ok(())
            } else {
                Err(AnchorError::Conflict(candidate.sequence))
            };
        }
        if candidate.sequence != stored.sequence + 1 {
            return Err(AnchorError::SequenceGap {
                stored: stored.sequence,
                candidate: candidate.sequence,
            });
        }
        self.persist(candidate)
    }

    fn read(&self) -> Result<HistoryAnchor, AnchorError> {
        if !self.path.exists() {
            return Err(AnchorError::Uninitialized);
        }
        Ok(serde_json::from_slice(&fs::read(&self.path)?)?)
    }

    fn persist(&self, anchor: &HistoryAnchor) -> Result<(), AnchorError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("anchor.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| -> Result<(), AnchorError> {
            file.write_all(&serde_json::to_vec(anchor)?)?;
            file.write_all(b"\n")?;
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
        assert_eq!(store.read().unwrap(), anchor(3, "three"));
        assert!(!path.with_extension("anchor.tmp").exists());
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

        fs::create_dir(path.with_extension("anchor.lock")).unwrap();
        assert!(matches!(
            store.compare_and_advance(&anchor(1, "one")),
            Err(AnchorError::Locked)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
