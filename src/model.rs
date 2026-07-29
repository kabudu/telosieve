use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type Values = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceState {
    pub replicas: BTreeMap<String, Values>,
}

impl ServiceState {
    #[must_use]
    pub fn consensus(&self) -> Option<&Values> {
        let mut replicas = self.replicas.values();
        let first = replicas.next()?;
        replicas
            .all(|candidate| candidate == first)
            .then_some(first)
    }

    #[must_use]
    pub fn transition_to(&self, desired: &Values) -> Transition {
        Transition {
            before_digest: digest(self),
            after: ServiceState {
                replicas: self
                    .replicas
                    .keys()
                    .map(|name| (name.clone(), desired.clone()))
                    .collect(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub before_digest: String,
    pub after: ServiceState,
}

/// Returns a stable SHA-256 digest for typed, deterministically ordered values.
///
/// # Panics
///
/// Panics only if a caller supplies a custom [`Serialize`] implementation that
/// rejects serialization. All Telosieve protocol types serialize infallibly.
#[must_use]
pub fn digest<T: Serialize>(value: &T) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).expect("serializing a typed value cannot fail");
    hex::encode(Sha256::digest(bytes))
}
