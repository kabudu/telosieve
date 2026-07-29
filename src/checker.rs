use serde::{Deserialize, Serialize};

use crate::{
    model::{ServiceState, Transition},
    protocol::ViabilityRules,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckerVerdict {
    pub implementation: String,
    pub safe: bool,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn check(
    current: &ServiceState,
    transition: &Transition,
    rules: &ViabilityRules,
) -> CheckerVerdict {
    let mut reasons = Vec::new();
    if transition.before_digest != crate::model::digest(current) {
        reasons.push("transition is not bound to the current state".into());
    }
    if current.replicas.is_empty() {
        reasons.push("current state has no replicas".into());
    }
    if transition.after.replicas.len() != rules.replica_count {
        reasons.push("replica count invariant failed".into());
    }
    if rules.require_consensus && transition.after.consensus().is_none() {
        reasons.push("replica consensus invariant failed".into());
    }
    for (key, required_value) in &rules.required_keys {
        if transition
            .after
            .replicas
            .values()
            .any(|values| values.get(key) != Some(required_value))
        {
            reasons.push(format!("required key invariant failed: {key}"));
        }
    }
    if let Some(first) = current.replicas.values().next() {
        for key in first.keys().filter(|key| {
            current
                .replicas
                .values()
                .all(|values| values.contains_key(*key))
        }) {
            if transition
                .after
                .replicas
                .values()
                .any(|values| !values.contains_key(key))
            {
                reasons.push(format!("stable key continuity failed: {key}"));
            }
        }
    }
    CheckerVerdict {
        implementation: "telosieve-independent-checker/v1".into(),
        safe: reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::digest;

    fn state(values: BTreeMap<String, String>) -> ServiceState {
        ServiceState {
            replicas: BTreeMap::from([
                ("replica-a".into(), values.clone()),
                ("replica-b".into(), values),
            ]),
        }
    }

    fn rules() -> ViabilityRules {
        ViabilityRules {
            replica_count: 2,
            require_consensus: true,
            required_keys: BTreeMap::new(),
        }
    }

    #[test]
    fn stable_keys_cannot_be_deleted_even_when_viability_is_empty() {
        let current = state(BTreeMap::from([
            ("cluster/epoch".into(), "7".into()),
            ("message".into(), "old".into()),
        ]));
        let after = state(BTreeMap::from([("message".into(), "new".into())]));
        let verdict = check(
            &current,
            &Transition {
                before_digest: digest(&current),
                after,
            },
            &rules(),
        );
        assert!(!verdict.safe);
        assert_eq!(
            verdict.reasons,
            ["stable key continuity failed: cluster/epoch"]
        );
    }

    #[test]
    fn stable_key_updates_and_additions_remain_available() {
        let current = state(BTreeMap::from([("message".into(), "old".into())]));
        let after = state(BTreeMap::from([
            ("message".into(), "new".into()),
            ("new-key".into(), "value".into()),
        ]));
        let verdict = check(
            &current,
            &Transition {
                before_digest: digest(&current),
                after,
            },
            &rules(),
        );
        assert!(verdict.safe, "{:?}", verdict.reasons);
    }
}
